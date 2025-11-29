mod rtmsg;

use std::{
    io::{self, Read, Write}, 
    os::fd::{AsRawFd, RawFd}
};

use crate::{macos::rtmsg::m_rtmsg, syscall, Route, RouteAction, RouteChange};
use libc::{
    rt_msghdr, AF_INET, AF_INET6, AF_ROUTE, AF_UNSPEC, RTAX_MAX, RTA_DST, 
    RTA_GATEWAY, RTA_IFP, RTA_NETMASK, RTF_GATEWAY, RTF_STATIC, 
    RTF_UP, RTM_ADD, RTM_DELETE, RTM_GET, RTM_VERSION, SOCK_RAW
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
        let mut rtm_flags = (RTF_STATIC | RTF_UP) as i32;

        if route.gateway.is_some() {
            rtm_flags |= RTF_GATEWAY as i32;
        };

        let rtm_addrs = (RTA_DST | RTA_NETMASK | RTA_GATEWAY) as i32;

        let mut rtmsg: m_rtmsg = m_rtmsg::default();
        rtmsg.hdr.rtm_type = RTM_ADD as u8;
        rtmsg.hdr.rtm_flags = rtm_flags;
        rtmsg.hdr.rtm_addrs = rtm_addrs;
        rtmsg.hdr.rtm_seq = 1;

        rtmsg.put_destination(&route.destination);
        if let Some(gateway) = route.gateway {
            rtmsg.put_gateway(&gateway);
        }
        if let Some(ifindex) = route.ifindex {
            rtmsg.put_index(ifindex);
        }
        rtmsg.put_netmask(&route.mask());

        rtmsg.hdr.rtm_msglen = rtmsg.len() as u16;

        let slice = {
            let ptr = &rtmsg as *const m_rtmsg as *const u8;
            let len = rtmsg.hdr.rtm_msglen as usize;

            unsafe { std::slice::from_raw_parts(ptr, len) }
        };

        self.write(slice)?;

        let mut buf = [0; std::mem::size_of::<m_rtmsg>()];
        let n = self.read(&mut buf)?;
        if n < std::mem::size_of::<rt_msghdr>() {
            return Err(io::Error::new(io::ErrorKind::Other, "invalid response"));
        }

        let rt_hdr = unsafe { buf.as_ptr().cast::<rt_msghdr>().as_ref().unwrap() };

        assert_eq!(rt_hdr.rtm_type, RTM_ADD as u8);
        assert_eq!(rt_hdr.rtm_version, RTM_VERSION as u8);
        if rt_hdr.rtm_errno != 0 {
            return Err(code2error(rt_hdr.rtm_errno));
        }

        Ok(())
    }

    fn delete(&mut self, route: &Route) -> io::Result<()> {
        let rtm_flags = (RTF_STATIC | RTF_UP | RTF_GATEWAY) as i32;
        let rtm_addrs = (RTA_DST | RTA_NETMASK) as i32;

        let mut rtmsg = m_rtmsg::default();
        rtmsg.hdr.rtm_type = RTM_DELETE as u8;
        rtmsg.hdr.rtm_flags = rtm_flags;
        rtmsg.hdr.rtm_addrs = rtm_addrs;
        rtmsg.hdr.rtm_seq = 1;

        rtmsg.put_destination(&route.destination);
        rtmsg.put_netmask(&route.mask());

        rtmsg.hdr.rtm_msglen = rtmsg.len() as u16;

        let slice = {
            let ptr = &rtmsg as *const m_rtmsg as *const u8;
            let len = rtmsg.hdr.rtm_msglen as usize;

            unsafe { std::slice::from_raw_parts(ptr, len) }
        };

        self.write(slice)?;

        let mut buf = [0; std::mem::size_of::<m_rtmsg>()];
        let n = self.read(&mut buf)?;
        if n < std::mem::size_of::<rt_msghdr>() {
            return Err(io::Error::new(io::ErrorKind::Other, "invalid response"));
        }

        let rt_hdr = unsafe { buf.as_ptr().cast::<rt_msghdr>().as_ref().unwrap() };

        assert_eq!(rt_hdr.rtm_version, RTM_VERSION as u8);
        if rt_hdr.rtm_errno != 0 {
            return Err(code2error(rt_hdr.rtm_errno));
        }

        Ok(())
    }

    fn get(&mut self, route: &Route) -> io::Result<Route> {
        let mut ret = Route::default();
        let rtm_flags = (RTF_STATIC | RTF_UP | RTF_GATEWAY) as i32;
        let rtm_addrs = (RTA_DST | RTA_NETMASK | RTA_IFP) as i32;
        // if !route.destination.is_unspecified() {
        //     rtm_flags |= RTF_HOST as i32;
        // }
        let mut rtmsg = m_rtmsg::default();
        rtmsg.hdr.rtm_type = RTM_GET as u8;
        rtmsg.hdr.rtm_flags = rtm_flags;
        rtmsg.hdr.rtm_addrs = rtm_addrs;
        rtmsg.hdr.rtm_seq = 1;

        rtmsg.put_destination(&route.destination);
        rtmsg.put_netmask(&route.mask());
        rtmsg.put_index(0);

        rtmsg.hdr.rtm_msglen = rtmsg.len() as u16;

        let slice = {
            let ptr = &rtmsg as *const m_rtmsg as *const u8;
            let len = rtmsg.hdr.rtm_msglen as usize;

            unsafe { std::slice::from_raw_parts(ptr, len) }
        };

        self.write(slice)?;

        let mut buf = [0; std::mem::size_of::<m_rtmsg>()];
        let n = self.read(&mut buf)?;
        if n < std::mem::size_of::<rt_msghdr>() {
            return Err(io::Error::new(io::ErrorKind::Other, "invalid response"));
        }

        let rtmsg: &mut m_rtmsg = unsafe { &mut *(buf.as_mut_ptr() as *mut m_rtmsg) };
        assert_eq!(rtmsg.hdr.rtm_version, RTM_VERSION as u8);
        if rtmsg.hdr.rtm_errno != 0 {
            return Err(code2error(rtmsg.hdr.rtm_errno));
        }
        if rtmsg.hdr.rtm_msglen > n as u16 {
            return Err(io::Error::new(
                io::ErrorKind::Other, 
                format!("message length mismatch, in packet {}, returned {}", rtmsg.hdr.rtm_msglen, n)
            ));
        }
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
                RTA_DST => {
                    ret.destination = rtmsg.get_destination()
                },
                RTA_GATEWAY => ret.gateway = {
                    let gateway = rtmsg.get_gateway();
                    if rtmsg.hdr.rtm_flags & RTF_GATEWAY != 0 {
                        Some(gateway)
                    } else {
                        None
                    }
                },
                RTA_NETMASK => ret.cidr(
                    rtmsg.get_netmask(if ret.destination.is_ipv4() {
                        AF_INET as u8
                    } else {
                        AF_INET6 as u8
                    })
                ),
                RTA_IFP => ret.ifindex = Some(rtmsg.get_index()),
                _ => (),
            }
        }

        Ok(ret)
    }

    fn monitor(&mut self, buf: &mut [u8]) -> io::Result<(crate::RouteChange, Route)> {
        let mut ret = Route::default();
        let n = self.read(buf)?;

        let rtmsg: &mut m_rtmsg = unsafe { &mut *(buf.as_mut_ptr() as *mut m_rtmsg) };
        if rtmsg.hdr.rtm_msglen > n as u16 {
            return Err(io::Error::new(
                io::ErrorKind::Other, 
                format!("message length mismatch, in packet {}, returned {}", rtmsg.hdr.rtm_msglen, n)
            ));
        }
        assert_eq!(rtmsg.hdr.rtm_version, RTM_VERSION as u8);
        rtmsg.attr_len = 0;

        let rtm_type: RouteChange = rtmsg.hdr.rtm_type.into();

        for offset in 0..RTAX_MAX {
            if rtmsg.attr_len + std::mem::size_of::<rt_msghdr>() >= n {
                break;
            }
            let bit = 1 << offset;
            if rtmsg.hdr.rtm_addrs & bit == 0 {
                continue;
            }

            match bit {
                RTA_DST => {
                    ret.destination = rtmsg.get_destination()
                },
                RTA_GATEWAY => ret.gateway = {
                    let gateway = rtmsg.get_gateway();
                    if rtmsg.hdr.rtm_flags & RTF_GATEWAY != 0 {
                        Some(gateway)
                    } else {
                        None
                    }
                },
                RTA_NETMASK => ret.cidr(
                    rtmsg.get_netmask(if ret.destination.is_ipv4() {
                        AF_INET as u8
                    } else {
                        AF_INET6 as u8
                    })
                ),
                RTA_IFP => ret.ifindex = Some(rtmsg.get_index()),
                _ => (),
            }
        }

        rtmsg.attr_len = 0;
        Ok((rtm_type, ret))
    }
}

impl RouteSock {
    pub fn new() -> io::Result<Self> {
        let fd = syscall!(
            socket(AF_ROUTE as i32, SOCK_RAW as i32, AF_UNSPEC as i32)
        )?;

        Ok(Self(fd))
    }

    pub fn new_buf() -> [u8; std::mem::size_of::<m_rtmsg>()] {
        m_rtmsg::new_buf()
    }
}

impl Drop for RouteSock {
    fn drop(&mut self) {
        syscall!(close(self.as_raw_fd())).unwrap();
    }
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
