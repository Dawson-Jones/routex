use std::net::IpAddr;

use libc::{
    AF_INET, AF_INET6, AF_LINK, RTM_VERSION, in_addr, in6_addr, rt_msghdr, sockaddr, sockaddr_dl,
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

    fn put_addr(&mut self, addr: &IpAddr) {
        match addr {
            IpAddr::V4(addr) => {
                let sa_len = std::mem::size_of::<sockaddr_in>();
                let sa_in =
                    unsafe { &mut *(self.attr[self.attr_len..].as_mut_ptr() as *mut sockaddr_in) };
                sa_in.sin_len = sa_len as u8;
                sa_in.sin_family = AF_INET as u8;
                sa_in.sin_port = 0;
                sa_in.sin_addr = in_addr {
                    s_addr: u32::from_ne_bytes(addr.octets()),
                };

                self.attr_len += sa_len;
            }
            IpAddr::V6(addr) => {
                let sa_len = std::mem::size_of::<sockaddr_in6>();
                let sa_in6 =
                    unsafe { &mut *(self.attr[self.attr_len..].as_mut_ptr() as *mut sockaddr_in6) };
                sa_in6.sin6_len = sa_len as u8;
                sa_in6.sin6_family = AF_INET6 as u8;
                sa_in6.sin6_port = 0;
                sa_in6.sin6_flowinfo = 0;
                sa_in6.sin6_addr = in6_addr {
                    s6_addr: addr.octets(),
                };
                sa_in6.sin6_scope_id = 0;

                self.attr_len += sa_len;
            }
        }
    }

    pub fn put_destination(&mut self, dest: &IpAddr) {
        self.put_addr(dest);
    }

    pub fn put_gateway(&mut self, gateway: &IpAddr) {
        self.put_addr(gateway)
    }

    pub fn put_index(&mut self, ifindex: u32) {
        let sdl_len = std::mem::size_of::<sockaddr_dl>();
        let sa_dl = unsafe { &mut *(self.attr[self.attr_len..].as_mut_ptr() as *mut sockaddr_dl) };
        sa_dl.sdl_len = sdl_len as u8;
        sa_dl.sdl_family = AF_LINK as u8;
        sa_dl.sdl_index = ifindex as u16;

        self.attr_len += sdl_len;
    }

    pub fn put_netmask(&mut self, mask: &IpAddr) {
        let start = self.attr_len;

        if is_zero_mask(mask) {
            self.attr_len += roundup!(0);
            return;
        }

        self.put_addr(mask);

        let compact_len = compact_sockaddr_len(&self.attr[start..self.attr_len]);
        let sa = unsafe { &mut *(self.attr[start..].as_mut_ptr() as *mut sockaddr) };
        sa.sa_len = compact_len as u8;
        self.attr_len = start + roundup!(compact_len);
    }

    pub fn get_addr(&mut self) -> IpAddr {
        let sa_ptr = self.attr[self.attr_len..].as_ptr() as *const sockaddr;

        unsafe {
            if (*sa_ptr).sa_family == AF_INET as u8 {
                let sa_in_ptr = sa_ptr as *const sockaddr_in;
                let sa_in = &*sa_in_ptr;

                self.attr_len += roundup!(sa_in.sin_len as usize);

                IpAddr::from(sa_in.sin_addr.s_addr.to_ne_bytes())
            } else {
                let sa_in6_ptr = sa_ptr as *const sockaddr_in6;
                let sa_in6 = &*sa_in6_ptr;

                self.attr_len += roundup!(sa_in6.sin6_len as usize);

                IpAddr::from(sa_in6.sin6_addr.s6_addr)
            }
        }
    }

    pub fn get_destination(&mut self) -> IpAddr {
        self.get_addr()
    }

    pub fn get_gateway(&mut self) -> IpAddr {
        self.get_addr()
    }

    pub fn get_netmask(&mut self, family: u8) -> IpAddr {
        let sa = unsafe { &mut *(self.attr[self.attr_len..].as_ptr() as *mut sockaddr) };
        sa.sa_family = family;

        self.get_addr()
    }

    pub fn get_index(&mut self) -> u32 {
        let sa_dl = unsafe { &mut *(self.attr[self.attr_len..].as_ptr() as *mut sockaddr_dl) };
        self.attr_len += roundup!(sa_dl.sdl_len as usize);

        sa_dl.sdl_index as u32
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
