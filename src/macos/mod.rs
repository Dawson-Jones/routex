mod rtmsg;

use std::{
    io::{self, Read, Write},
    os::fd::{AsRawFd, RawFd},
};

use crate::{macos::rtmsg::m_rtmsg, syscall, Route, RouteAction, RouteChange};
use libc::{
    rt_msghdr, AF_INET, AF_INET6, AF_ROUTE, AF_UNSPEC, RTAX_MAX, RTA_DST, RTA_GATEWAY, RTA_IFP,
    RTA_NETMASK, RTF_GATEWAY, RTF_STATIC, RTF_UP, RTM_ADD, RTM_DELETE, RTM_GET, RTM_VERSION,
    SOCK_RAW,
};

pub struct RouteSock(RawFd);

impl AsRawFd for RouteSock {
    fn as_raw_fd(&self) -> RawFd {
        self.0
    }
}

impl Write for RouteSock {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = syscall!(write(self.as_raw_fd(), buf.as_ptr() as *const _, buf.len()))?;

        Ok(n as usize)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Read for RouteSock {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = syscall!(read(
            self.as_raw_fd(),
            buf.as_mut_ptr() as *mut _,
            buf.len()
        ))?;

        Ok(n as usize)
    }
}

impl RouteAction for RouteSock {
    fn add(&mut self, route: &Route) -> io::Result<()> {
        route.validate()?;

        let mut rtm_flags = RTF_STATIC | RTF_UP;
        if route.gateway.is_some() {
            rtm_flags |= RTF_GATEWAY;
        };

        let mut rtmsg = write_route_addrs(route, RouteRequestKind::Add);
        rtmsg.hdr.rtm_type = RTM_ADD as u8;
        rtmsg.hdr.rtm_flags = rtm_flags;
        rtmsg.hdr.rtm_seq = 1;
        rtmsg.hdr.rtm_msglen = rtmsg.len() as u16;

        self.write_all(route_msg_bytes(&rtmsg))?;

        let mut buf = [0; std::mem::size_of::<m_rtmsg>()];
        let n = self.read(&mut buf)?;
        if n < std::mem::size_of::<rt_msghdr>() {
            return Err(io::Error::other("invalid response"));
        }

        let rt_hdr = unsafe { buf.as_ptr().cast::<rt_msghdr>().as_ref().unwrap() };

        validate_header(rt_hdr, Some(RTM_ADD as u8))?;
        if rt_hdr.rtm_errno != 0 {
            return Err(code2error(rt_hdr.rtm_errno));
        }

        Ok(())
    }

    fn delete(&mut self, route: &Route) -> io::Result<()> {
        route.validate()?;

        let rtm_flags = RTF_STATIC | RTF_UP | RTF_GATEWAY;
        let mut rtmsg = write_route_addrs(route, RouteRequestKind::Delete);
        rtmsg.hdr.rtm_type = RTM_DELETE as u8;
        rtmsg.hdr.rtm_flags = rtm_flags;
        rtmsg.hdr.rtm_seq = 1;
        rtmsg.hdr.rtm_msglen = rtmsg.len() as u16;

        self.write_all(route_msg_bytes(&rtmsg))?;

        let mut buf = [0; std::mem::size_of::<m_rtmsg>()];
        let n = self.read(&mut buf)?;
        if n < std::mem::size_of::<rt_msghdr>() {
            return Err(io::Error::other("invalid response"));
        }

        let rt_hdr = unsafe { buf.as_ptr().cast::<rt_msghdr>().as_ref().unwrap() };

        validate_header(rt_hdr, None)?;
        if rt_hdr.rtm_errno != 0 {
            return Err(code2error(rt_hdr.rtm_errno));
        }

        Ok(())
    }

    fn get(&mut self, route: &Route) -> io::Result<Route> {
        route.validate()?;

        let rtm_flags = RTF_STATIC | RTF_UP | RTF_GATEWAY;
        let mut rtmsg = write_route_addrs(route, RouteRequestKind::Query);
        rtmsg.hdr.rtm_type = RTM_GET as u8;
        rtmsg.hdr.rtm_flags = rtm_flags;
        rtmsg.hdr.rtm_seq = 1;
        rtmsg.hdr.rtm_msglen = rtmsg.len() as u16;

        self.write_all(route_msg_bytes(&rtmsg))?;

        let mut buf = [0; std::mem::size_of::<m_rtmsg>()];
        let n = self.read(&mut buf)?;
        if n < std::mem::size_of::<rt_msghdr>() {
            return Err(io::Error::other("invalid response"));
        }

        let rtmsg: &mut m_rtmsg = unsafe { &mut *(buf.as_mut_ptr() as *mut m_rtmsg) };
        validate_header(&rtmsg.hdr, None)?;
        if rtmsg.hdr.rtm_errno != 0 {
            return Err(code2error(rtmsg.hdr.rtm_errno));
        }
        if rtmsg.hdr.rtm_msglen > n as u16 {
            return Err(io::Error::other(format!(
                "message length mismatch, in packet {}, returned {}",
                rtmsg.hdr.rtm_msglen, n
            )));
        }

        read_route(rtmsg, n)
    }

    fn monitor(&mut self, buf: &mut [u8]) -> io::Result<(crate::RouteChange, Route)> {
        let n = self.read(buf)?;

        let rtmsg: &mut m_rtmsg = unsafe { &mut *(buf.as_mut_ptr() as *mut m_rtmsg) };
        if rtmsg.hdr.rtm_msglen > n as u16 {
            return Err(io::Error::other(format!(
                "message length mismatch, in packet {}, returned {}",
                rtmsg.hdr.rtm_msglen, n
            )));
        }
        validate_header(&rtmsg.hdr, None)?;

        let rtm_type: RouteChange = rtmsg.hdr.rtm_type.into();
        Ok((rtm_type, read_route(rtmsg, n)?))
    }
}

impl RouteSock {
    pub fn new() -> io::Result<Self> {
        let fd = syscall!(socket(AF_ROUTE, SOCK_RAW, AF_UNSPEC))?;

        Ok(Self(fd))
    }

    pub fn new_buf() -> [u8; std::mem::size_of::<m_rtmsg>()] {
        m_rtmsg::new_buf()
    }
}

impl Drop for RouteSock {
    fn drop(&mut self) {
        let _ = syscall!(close(self.as_raw_fd()));
    }
}

enum RouteRequestKind {
    Add,
    Delete,
    Query,
}

fn write_route_addrs(route: &Route, kind: RouteRequestKind) -> m_rtmsg {
    let mut rtmsg = m_rtmsg::default();
    rtmsg.hdr.rtm_addrs = RTA_DST | RTA_NETMASK;

    // macOS kernel matches deletes by destination and netmask only.
    // Darwin route may send gateway/ifp on delete, but empirical tests show the kernel ignores them.
    if matches!(kind, RouteRequestKind::Add) && route.gateway.is_some() {
        rtmsg.hdr.rtm_addrs |= RTA_GATEWAY;
    }
    if (matches!(kind, RouteRequestKind::Add) && route.ifindex.is_some())
        || matches!(kind, RouteRequestKind::Query)
    {
        rtmsg.hdr.rtm_addrs |= RTA_IFP;
    }

    for offset in 0..RTAX_MAX {
        let bit = 1 << offset;
        if rtmsg.hdr.rtm_addrs & bit == 0 {
            continue;
        }

        match bit {
            RTA_DST => rtmsg.put_destination(&route.destination),
            RTA_GATEWAY => {
                if let Some(gateway) = route.gateway {
                    rtmsg.put_gateway(&gateway);
                }
            }
            RTA_NETMASK => rtmsg.put_netmask(&route.mask()),
            RTA_IFP => rtmsg.put_index(route.ifindex.unwrap_or(0)),
            _ => {}
        }
    }

    rtmsg
}

fn read_route(rtmsg: &mut m_rtmsg, n: usize) -> io::Result<Route> {
    let mut ret = Route::default();
    rtmsg.attr_len = 0;

    for offset in 0..RTAX_MAX {
        if rtmsg.attr_len + std::mem::size_of::<rt_msghdr>() >= n {
            break;
        }
        let bit = 1 << offset;
        if rtmsg.hdr.rtm_addrs & bit == 0 {
            continue;
        }

        match bit {
            RTA_DST => ret.destination = rtmsg.get_destination(),
            RTA_GATEWAY => {
                let gateway = rtmsg.get_gateway();
                ret.gateway = if rtmsg.hdr.rtm_flags & RTF_GATEWAY != 0 {
                    Some(gateway)
                } else {
                    None
                };
            }
            RTA_NETMASK => ret.cidr(rtmsg.get_netmask(if ret.destination.is_ipv4() {
                AF_INET as u8
            } else {
                AF_INET6 as u8
            })),
            RTA_IFP => ret.ifindex = Some(rtmsg.get_index()),
            _ => {}
        }
    }

    rtmsg.attr_len = 0;
    Ok(ret)
}

fn route_msg_bytes(rtmsg: &m_rtmsg) -> &[u8] {
    let ptr = rtmsg as *const m_rtmsg as *const u8;
    let len = rtmsg.hdr.rtm_msglen as usize;

    unsafe { std::slice::from_raw_parts(ptr, len) }
}

fn validate_header(hdr: &rt_msghdr, expected_type: Option<u8>) -> io::Result<()> {
    if hdr.rtm_version != RTM_VERSION as u8 {
        return Err(io::Error::other(format!(
            "unexpected routing message version {}",
            hdr.rtm_version
        )));
    }

    if let Some(expected_type) = expected_type {
        if hdr.rtm_type != expected_type {
            return Err(io::Error::other(format!(
                "unexpected routing message type {}",
                hdr.rtm_type
            )));
        }
    }

    Ok(())
}

fn code2error(err: i32) -> io::Error {
    let kind = match err {
        17 => io::ErrorKind::AlreadyExists, // EEXIST
        3 => io::ErrorKind::NotFound,       // ESRCH
        3436 => io::ErrorKind::OutOfMemory, // ENOBUFS
        _ => io::ErrorKind::Other,
    };

    io::Error::new(kind, format!("rtm_errno {}", err))
}
