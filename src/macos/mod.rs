mod rtmsg;

use std::{
    io::{self, Read, Write},
    os::fd::{AsRawFd, RawFd},
    time::{Duration, Instant},
};

use crate::{Route, RouteAction, RouteChange, macos::rtmsg::m_rtmsg, syscall};
use libc::{
    AF_INET, AF_INET6, AF_ROUTE, AF_UNSPEC, POLLIN, RTA_DST, RTA_GATEWAY, RTA_IFP, RTA_NETMASK,
    RTAX_MAX, RTF_GATEWAY, RTF_HOST, RTF_STATIC, RTF_UP, RTM_ADD, RTM_DELETE, RTM_GET, RTM_VERSION,
    SOCK_RAW, pollfd, rt_msghdr,
};

const ROUTE_RESPONSE_TIMEOUT: Duration = Duration::from_millis(500);

/// `RTF_IFSCOPE` is the XNU flag that ties a route to a specific interface
/// for use by `IP_BOUND_IF` scoped lookups. Not exposed by `libc`'s macOS
/// bindings, so define it locally from the XNU value (`net/route.h`).
const RTF_IFSCOPE: i32 = 0x1000000;

pub struct RouteSock {
    fd: RawFd,
    seq: i32,
}

impl AsRawFd for RouteSock {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
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

        let mut rtmsg = write_route_addrs(route, RouteRequestKind::Add);
        let seq = self.next_seq();
        rtmsg.hdr.rtm_type = RTM_ADD as u8;
        rtmsg.hdr.rtm_flags = route_flags(route, route.gateway.is_some());
        apply_ifscope(&mut rtmsg.hdr, route);
        rtmsg.hdr.rtm_seq = seq;
        rtmsg.hdr.rtm_pid = unsafe { libc::getpid() };
        rtmsg.hdr.rtm_msglen = rtmsg.len() as u16;

        self.write_all(route_msg_bytes(&rtmsg))?;

        let mut buf = [0; std::mem::size_of::<m_rtmsg>()];
        let rt_hdr = self.read_request_response(&mut buf, seq, RTM_ADD as u8)?;

        if rt_hdr.rtm_errno != 0 {
            return Err(code2error(rt_hdr.rtm_errno));
        }

        Ok(())
    }

    fn delete(&mut self, route: &Route) -> io::Result<()> {
        route.validate()?;

        let mut rtmsg = write_route_addrs(route, RouteRequestKind::Delete);
        let seq = self.next_seq();
        rtmsg.hdr.rtm_type = RTM_DELETE as u8;
        rtmsg.hdr.rtm_flags = route_flags(route, false);
        apply_ifscope(&mut rtmsg.hdr, route);
        rtmsg.hdr.rtm_seq = seq;
        rtmsg.hdr.rtm_pid = unsafe { libc::getpid() };
        rtmsg.hdr.rtm_msglen = rtmsg.len() as u16;

        self.write_all(route_msg_bytes(&rtmsg))?;

        let mut buf = [0; std::mem::size_of::<m_rtmsg>()];
        let rt_hdr = match self.read_request_response_timeout(
            &mut buf,
            seq,
            RTM_DELETE as u8,
            ROUTE_RESPONSE_TIMEOUT,
        ) {
            Ok(rt_hdr) => rt_hdr,
            Err(error) if error.kind() == io::ErrorKind::TimedOut => return Ok(()),
            Err(error) => return Err(error),
        };

        if rt_hdr.rtm_errno != 0 {
            return Err(code2error(rt_hdr.rtm_errno));
        }

        Ok(())
    }

    fn get(&mut self, route: &Route) -> io::Result<Route> {
        route.validate()?;

        let mut rtmsg = write_route_addrs(route, RouteRequestKind::Query);
        let seq = self.next_seq();
        rtmsg.hdr.rtm_type = RTM_GET as u8;
        rtmsg.hdr.rtm_flags = route_flags(route, true);
        apply_ifscope(&mut rtmsg.hdr, route);
        rtmsg.hdr.rtm_seq = seq;
        rtmsg.hdr.rtm_pid = unsafe { libc::getpid() };
        rtmsg.hdr.rtm_msglen = rtmsg.len() as u16;

        self.write_all(route_msg_bytes(&rtmsg))?;

        let mut buf = [0; std::mem::size_of::<m_rtmsg>()];
        let n = self.read_request_response_len(&mut buf, seq, RTM_GET as u8)?;
        let rtmsg: &mut m_rtmsg = unsafe { &mut *(buf.as_mut_ptr() as *mut m_rtmsg) };
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

        Ok(Self { fd, seq: 0 })
    }

    pub fn new_buf() -> [u8; std::mem::size_of::<m_rtmsg>()] {
        m_rtmsg::new_buf()
    }

    fn read_request_response<'a>(
        &mut self,
        buf: &'a mut [u8],
        seq: i32,
        expected_type: u8,
    ) -> io::Result<&'a rt_msghdr> {
        let _ = self.read_request_response_len(buf, seq, expected_type)?;
        Ok(unsafe { buf.as_ptr().cast::<rt_msghdr>().as_ref().unwrap() })
    }

    fn read_request_response_timeout<'a>(
        &mut self,
        buf: &'a mut [u8],
        seq: i32,
        expected_type: u8,
        timeout: Duration,
    ) -> io::Result<&'a rt_msghdr> {
        let _ = self.read_request_response_len_timeout(buf, seq, expected_type, timeout)?;
        Ok(unsafe { buf.as_ptr().cast::<rt_msghdr>().as_ref().unwrap() })
    }

    fn read_request_response_len(
        &mut self,
        buf: &mut [u8],
        seq: i32,
        expected_type: u8,
    ) -> io::Result<usize> {
        let pid = unsafe { libc::getpid() };
        loop {
            let n = self.read(buf)?;
            if !response_matches_ours(buf, n, pid, seq) {
                continue;
            }
            let hdr = unsafe { buf.as_ptr().cast::<rt_msghdr>().as_ref().unwrap() };
            validate_header(hdr, Some(expected_type))?;
            return Ok(n);
        }
    }

    fn read_request_response_len_timeout(
        &mut self,
        buf: &mut [u8],
        seq: i32,
        expected_type: u8,
        timeout: Duration,
    ) -> io::Result<usize> {
        let pid = unsafe { libc::getpid() };
        let deadline = Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "routing response timed out",
                ));
            }

            let mut pfd = pollfd {
                fd: self.as_raw_fd(),
                events: POLLIN,
                revents: 0,
            };
            let timeout_ms = remaining.as_millis().min(i32::MAX as u128) as i32;
            let ready = syscall!(poll(&mut pfd, 1, timeout_ms))?;
            if ready == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "routing response timed out",
                ));
            }

            let n = self.read(buf)?;
            if !response_matches_ours(buf, n, pid, seq) {
                continue;
            }
            let hdr = unsafe { buf.as_ptr().cast::<rt_msghdr>().as_ref().unwrap() };
            validate_header(hdr, Some(expected_type))?;
            return Ok(n);
        }
    }

    fn next_seq(&mut self) -> i32 {
        self.seq = self.seq.wrapping_add(1).max(1);
        self.seq
    }
}

/// True only when the message in `buf` is large enough to be a routing
/// header and carries OUR `(pid, seq)`. Short broadcasts and replies for
/// other route-socket listeners should make the caller keep reading, not
/// bail out. Once a message is ours, version/type validation is a real
/// protocol check and belongs in `validate_header`.
fn response_matches_ours(buf: &[u8], n: usize, pid: i32, seq: i32) -> bool {
    if n < std::mem::size_of::<rt_msghdr>() {
        return false;
    }
    let hdr = unsafe { &*(buf.as_ptr().cast::<rt_msghdr>()) };
    hdr.rtm_pid == pid && hdr.rtm_seq == seq
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
    rtmsg.hdr.rtm_addrs = RTA_DST;

    if matches!(kind, RouteRequestKind::Add | RouteRequestKind::Delete) {
        rtmsg.hdr.rtm_addrs |= RTA_NETMASK;
    }
    if matches!(kind, RouteRequestKind::Add) && route.gateway.is_some() {
        rtmsg.hdr.rtm_addrs |= RTA_GATEWAY;
    }
    if matches!(kind, RouteRequestKind::Add) && route.gateway.is_none() && route.ifindex.is_some() {
        // `route add ... -interface ifname` is encoded as a link-layer gateway.
        // The route CLI does not also send RTA_IFP for this path.
        rtmsg.hdr.rtm_addrs |= RTA_GATEWAY;
    }
    // Query asks the kernel to fill in IFP, so the slot must be reserved
    // even when the caller does not yet know the ifindex.
    if matches!(kind, RouteRequestKind::Query) {
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
                } else if let Some(ifindex) = route.ifindex {
                    rtmsg.put_index(ifindex);
                }
            }
            RTA_NETMASK => rtmsg.put_netmask(&route.mask()),
            RTA_IFP => rtmsg.put_index(route.ifindex.unwrap_or(0)),
            _ => {}
        }
    }

    rtmsg
}

fn route_flags(route: &Route, gateway: bool) -> i32 {
    let mut flags = RTF_STATIC | RTF_UP;

    if is_host_route(route) {
        flags |= RTF_HOST;
    }
    if gateway {
        flags |= RTF_GATEWAY;
    }

    flags
}

/// Apply `RTF_IFSCOPE` and `rtm_index` together for a scoped route. XNU
/// encodes interface-scope in two coupled fields — the flag in
/// `rtm_flags` and the ifindex in `rtm_msghdr.rtm_index` — so every
/// request kind (ADD / DELETE / GET) needs to touch both or the kernel
/// silently ignores the scope. Keep the coupling local to this helper
/// so the two halves cannot drift again.
fn apply_ifscope(hdr: &mut rt_msghdr, route: &Route) {
    if let Some(scope) = route.scope_ifindex {
        hdr.rtm_flags |= RTF_IFSCOPE;
        hdr.rtm_index = scope as u16;
    }
}

fn is_host_route(route: &Route) -> bool {
    match route.destination {
        std::net::IpAddr::V4(_) => route.prefix == 32,
        std::net::IpAddr::V6(_) => route.prefix == 128,
    }
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

    // Scope lives outside the sockaddr table: the flag is in `rtm_flags`
    // and the bound ifindex is in `rt_msghdr.rtm_index`. Reading them
    // back keeps round-trips (`add` -> `get`, `monitor` events) lossless.
    if rtmsg.hdr.rtm_flags & RTF_IFSCOPE != 0 {
        ret.scope_ifindex = Some(rtmsg.hdr.rtm_index as u32);
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

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use libc::sockaddr;

    use super::*;

    #[test]
    fn add_by_interface_uses_link_gateway_without_ifp() {
        let route = Route::new(IpAddr::V4(Ipv4Addr::new(1, 9, 4, 5)), 32).ifindex(4);

        let rtmsg = write_route_addrs(&route, RouteRequestKind::Add);

        assert_eq!(rtmsg.hdr.rtm_addrs, RTA_DST | RTA_GATEWAY | RTA_NETMASK);
    }

    #[test]
    fn query_reserves_ifp_slot() {
        let route = Route::new(IpAddr::V4(Ipv4Addr::new(1, 9, 4, 5)), 32);

        let rtmsg = write_route_addrs(&route, RouteRequestKind::Query);

        assert_eq!(rtmsg.hdr.rtm_addrs, RTA_DST | RTA_IFP);
    }

    #[test]
    fn host_route_sets_host_flag() {
        let route = Route::new(IpAddr::V4(Ipv4Addr::new(1, 9, 4, 5)), 32);

        assert_ne!(route_flags(&route, false) & RTF_HOST, 0);
    }

    #[test]
    fn netmask_sockaddr_is_compacted_like_route_cli() {
        let route = Route::new(IpAddr::V4(Ipv4Addr::new(1, 9, 4, 5)), 24);

        let rtmsg = write_route_addrs(&route, RouteRequestKind::Add);
        let netmask = unsafe { &*(rtmsg.attr[16..].as_ptr() as *const sockaddr) };

        assert_eq!(netmask.sa_len, 7);
    }

    #[test]
    fn default_route_netmask_uses_empty_sockaddr_slot() {
        let route = Route::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);

        let rtmsg = write_route_addrs(&route, RouteRequestKind::Add);
        let netmask = unsafe { &*(rtmsg.attr[16..].as_ptr() as *const sockaddr) };

        assert_eq!(netmask.sa_len, 0);
        assert_eq!(rtmsg.attr_len, 20);
    }

    #[test]
    fn apply_ifscope_sets_both_flag_and_index() {
        let route = Route::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
            .gateway(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)))
            .ifscope(7);

        let mut rtmsg = m_rtmsg::default();
        rtmsg.hdr.rtm_flags = route_flags(&route, true);
        apply_ifscope(&mut rtmsg.hdr, &route);

        assert_ne!(rtmsg.hdr.rtm_flags & RTF_IFSCOPE, 0);
        assert_eq!(rtmsg.hdr.rtm_index, 7);
    }

    #[test]
    fn apply_ifscope_no_scope_leaves_header_untouched() {
        let route = Route::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
            .gateway(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)));

        let mut rtmsg = m_rtmsg::default();
        rtmsg.hdr.rtm_flags = route_flags(&route, true);
        apply_ifscope(&mut rtmsg.hdr, &route);

        assert_eq!(rtmsg.hdr.rtm_flags & RTF_IFSCOPE, 0);
        assert_eq!(rtmsg.hdr.rtm_index, 0);
    }

    #[test]
    fn read_route_preserves_scope() {
        let mut rtmsg = m_rtmsg::default();
        rtmsg.hdr.rtm_flags = RTF_IFSCOPE;
        rtmsg.hdr.rtm_index = 11;
        // No sockaddr table — RTA bits are all zero, so read_route just
        // sees the scope metadata in the header.
        rtmsg.hdr.rtm_addrs = 0;

        let route = read_route(&mut rtmsg, std::mem::size_of::<rt_msghdr>()).unwrap();
        assert_eq!(route.scope_ifindex, Some(11));
    }

    #[test]
    fn read_route_without_scope_returns_none() {
        let mut rtmsg = m_rtmsg::default();
        rtmsg.hdr.rtm_flags = 0;
        rtmsg.hdr.rtm_index = 42;
        rtmsg.hdr.rtm_addrs = 0;

        let route = read_route(&mut rtmsg, std::mem::size_of::<rt_msghdr>()).unwrap();
        assert_eq!(route.scope_ifindex, None);
    }

    #[test]
    fn response_filter_rejects_short_read_and_mismatch_but_accepts_our_reply() {
        let mut rtmsg = m_rtmsg::default();
        rtmsg.hdr.rtm_pid = 42;
        rtmsg.hdr.rtm_seq = 7;
        let buf = unsafe {
            std::slice::from_raw_parts(
                &rtmsg as *const m_rtmsg as *const u8,
                std::mem::size_of::<m_rtmsg>(),
            )
        };

        // Short read: not enough bytes for a header — skip.
        assert!(!response_matches_ours(buf, 4, 42, 7));
        // Foreign reply (different pid): skip.
        assert!(!response_matches_ours(
            buf,
            std::mem::size_of::<rt_msghdr>(),
            99,
            7,
        ));
        // Bad version is still OUR reply. Accept it here so validate_header
        // reports the protocol error instead of looping forever.
        let mut bad_ver = m_rtmsg::default();
        bad_ver.hdr.rtm_version = (RTM_VERSION as u8).wrapping_add(1);
        bad_ver.hdr.rtm_pid = 42;
        bad_ver.hdr.rtm_seq = 7;
        let bad_buf = unsafe {
            std::slice::from_raw_parts(
                &bad_ver as *const m_rtmsg as *const u8,
                std::mem::size_of::<rt_msghdr>(),
            )
        };
        assert!(response_matches_ours(
            bad_buf,
            std::mem::size_of::<rt_msghdr>(),
            42,
            7,
        ));
        // Our reply: accept.
        assert!(response_matches_ours(
            buf,
            std::mem::size_of::<rt_msghdr>(),
            42,
            7,
        ));
    }
}
