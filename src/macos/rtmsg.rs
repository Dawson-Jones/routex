use std::{io, net::IpAddr};

use libc::{
    AF_INET, AF_INET6, AF_LINK, RTM_VERSION, in_addr, in6_addr, rt_msghdr, sockaddr_dl,
    sockaddr_in, sockaddr_in6,
};

#[repr(C)]
#[derive(Clone, Copy)]
#[allow(non_camel_case_types)]
pub(super) struct m_rtmsg {
    pub hdr: rt_msghdr,
    pub attr: [i8; 2048],
    pub attr_len: usize,
}

impl Default for m_rtmsg {
    fn default() -> Self {
        let mut rtmsg = unsafe { std::mem::zeroed::<m_rtmsg>() };
        rtmsg.hdr.rtm_version = RTM_VERSION as u8;

        rtmsg
    }
}

macro_rules! roundup {
    ($a:expr) => {{
        let size = std::mem::size_of::<u32>();
        let val = if $a > 0 {
            1 + (($a - 1) | (size - 1))
        } else {
            size
        };
        val
    }};
}

impl m_rtmsg {
    pub fn new_buf() -> [u8; std::mem::size_of::<m_rtmsg>()] {
        [0u8; std::mem::size_of::<m_rtmsg>()]
    }

    pub fn len(&self) -> usize {
        std::mem::size_of::<rt_msghdr>() + self.attr_len
    }

    pub fn parse(bytes: &[u8]) -> io::Result<Self> {
        let header_len = std::mem::size_of::<rt_msghdr>();
        if bytes.len() < header_len {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated routing message header",
            ));
        }

        // Routing sockets return byte buffers with no Rust alignment
        // guarantee. Copy the wire header into an owned, aligned value before
        // inspecting any fields.
        let hdr = unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast::<rt_msghdr>()) };
        let message_len = hdr.rtm_msglen as usize;
        if message_len < header_len || message_len > bytes.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "invalid routing message length {message_len} for {} received bytes",
                    bytes.len()
                ),
            ));
        }

        let attr_len = message_len - header_len;
        if attr_len > 2048 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("routing message attributes exceed capacity: {attr_len}"),
            ));
        }

        let mut message = Self {
            hdr,
            ..Self::default()
        };
        message.attr[..attr_len].copy_from_slice(unsafe {
            std::slice::from_raw_parts(bytes[header_len..message_len].as_ptr().cast(), attr_len)
        });
        Ok(message)
    }

    fn put_addr(&mut self, addr: &IpAddr) {
        match addr {
            IpAddr::V4(addr) => {
                let sa_len = std::mem::size_of::<sockaddr_in>();
                let sa_in = sockaddr_in {
                    sin_len: sa_len as u8,
                    sin_family: AF_INET as u8,
                    sin_port: 0,
                    sin_addr: in_addr {
                        s_addr: u32::from_ne_bytes(addr.octets()),
                    },
                    sin_zero: [0; 8],
                };
                self.write_value(sa_in);
            }
            IpAddr::V6(addr) => {
                let sa_len = std::mem::size_of::<sockaddr_in6>();
                let sa_in6 = sockaddr_in6 {
                    sin6_len: sa_len as u8,
                    sin6_family: AF_INET6 as u8,
                    sin6_port: 0,
                    sin6_flowinfo: 0,
                    sin6_addr: in6_addr {
                        s6_addr: addr.octets(),
                    },
                    sin6_scope_id: 0,
                };
                self.write_value(sa_in6);
            }
        }
    }

    fn write_value<T: Copy>(&mut self, value: T) {
        let len = std::mem::size_of::<T>();
        assert!(self.attr_len + len <= self.attr.len());
        unsafe {
            std::ptr::write_unaligned(self.attr[self.attr_len..].as_mut_ptr().cast::<T>(), value);
        }
        self.attr_len += len;
    }

    pub fn put_destination(&mut self, dest: &IpAddr) {
        self.put_addr(dest);
    }

    pub fn put_gateway(&mut self, gateway: &IpAddr) {
        self.put_addr(gateway)
    }

    pub fn put_index(&mut self, ifindex: u32) {
        let sdl_len = std::mem::size_of::<sockaddr_dl>();
        let mut sa_dl = unsafe { std::mem::zeroed::<sockaddr_dl>() };
        sa_dl.sdl_len = sdl_len as u8;
        sa_dl.sdl_family = AF_LINK as u8;
        sa_dl.sdl_index = ifindex as u16;
        self.write_value(sa_dl);
    }

    pub fn put_netmask(&mut self, mask: &IpAddr) {
        let start = self.attr_len;

        if is_zero_mask(mask) {
            self.attr_len += roundup!(0);
            return;
        }

        self.put_addr(mask);

        let compact_len = compact_sockaddr_len(&self.attr[start..self.attr_len]);
        self.attr[start] = compact_len as i8;
        self.attr_len = start + roundup!(compact_len);
    }

    fn next_sockaddr(&mut self) -> io::Result<[u8; 128]> {
        let header_len = std::mem::size_of::<rt_msghdr>();
        let attributes_len = (self.hdr.rtm_msglen as usize)
            .checked_sub(header_len)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid message length"))?;
        if self.attr_len >= attributes_len {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "missing routing sockaddr",
            ));
        }

        let sockaddr_len = self.attr[self.attr_len] as u8 as usize;
        if sockaddr_len > 128 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported sockaddr length {sockaddr_len}"),
            ));
        }
        let slot_len = roundup!(sockaddr_len);
        let end = self
            .attr_len
            .checked_add(slot_len)
            .filter(|end| *end <= attributes_len)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::UnexpectedEof, "truncated routing sockaddr")
            })?;

        let mut bytes = [0; 128];
        bytes[..sockaddr_len].copy_from_slice(unsafe {
            std::slice::from_raw_parts(self.attr[self.attr_len..].as_ptr().cast(), sockaddr_len)
        });
        self.attr_len = end;
        Ok(bytes)
    }

    fn get_addr(&mut self, family: Option<u8>) -> io::Result<IpAddr> {
        let mut bytes = self.next_sockaddr()?;
        if let Some(family) = family {
            bytes[1] = family;
        }

        match bytes[1] {
            family if family == AF_INET as u8 => {
                let addr =
                    unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast::<sockaddr_in>()) };
                Ok(IpAddr::from(addr.sin_addr.s_addr.to_ne_bytes()))
            }
            family if family == AF_INET6 as u8 => {
                let addr =
                    unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast::<sockaddr_in6>()) };
                Ok(IpAddr::from(addr.sin6_addr.s6_addr))
            }
            family => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported sockaddr family {family}"),
            )),
        }
    }

    pub fn get_destination(&mut self) -> io::Result<IpAddr> {
        self.get_addr(None)
    }

    pub fn get_gateway(&mut self) -> io::Result<IpAddr> {
        self.get_addr(None)
    }

    pub fn get_netmask(&mut self, family: u8) -> io::Result<IpAddr> {
        self.get_addr(Some(family))
    }

    pub fn get_index(&mut self) -> io::Result<u32> {
        let bytes = self.next_sockaddr()?;
        if bytes[1] != AF_LINK as u8 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("expected link sockaddr, found family {}", bytes[1]),
            ));
        }
        let addr = unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast::<sockaddr_dl>()) };

        Ok(addr.sdl_index as u32)
    }

    pub fn skip_addr(&mut self) -> io::Result<()> {
        self.next_sockaddr().map(|_| ())
    }
}

fn compact_sockaddr_len(bytes: &[i8]) -> usize {
    bytes
        .iter()
        .rposition(|byte| *byte != 0)
        .map_or(0, |pos| pos + 1)
}

fn is_zero_mask(mask: &IpAddr) -> bool {
    match mask {
        IpAddr::V4(addr) => addr.octets() == [0; 4],
        IpAddr::V6(addr) => addr.octets() == [0; 16],
    }
}
