use std::{
    io::{self, Read, Write},
    net::IpAddr,
    os::fd::{AsRawFd, RawFd},
};

use ipnetwork::IpNetwork;
use libc::{
    sockaddr_nl, AF_NETLINK, NETLINK_ROUTE, RTNLGRP_IPV4_ROUTE, RTNLGRP_IPV6_ROUTE,
    RTNLGRP_MPLS_ROUTE, SOCK_CLOEXEC, SOCK_RAW,
};
use netlink_packet_core::{
    NetlinkHeader, NetlinkMessage, NetlinkPayload, NLM_F_ACK, NLM_F_CREATE, NLM_F_DUMP, NLM_F_EXCL,
    NLM_F_REQUEST,
};
use netlink_packet_route::{
    route::{
        RouteAddress, RouteAttribute, RouteHeader, RouteMessage, RouteProtocol, RouteScope,
        RouteType,
    },
    AddressFamily, RouteNetlinkMessage,
};

use crate::{syscall, Route, RouteAction, RouteChange};

pub struct RouteSock(RawFd);

impl AsRawFd for RouteSock {
    fn as_raw_fd(&self) -> RawFd {
        self.0
    }
}

impl RouteSock {
    pub fn new() -> io::Result<Self> {
        let fd = syscall!(socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE))?;

        Ok(RouteSock(fd))
    }

    fn bind(&mut self, local: sockaddr_nl) -> io::Result<()> {
        syscall!(bind(
            self.as_raw_fd(),
            &local as *const sockaddr_nl as *const _,
            std::mem::size_of::<sockaddr_nl>() as _
        ))?;

        Ok(())
    }

    pub fn subscribe(&mut self) -> io::Result<()> {
        let mut local = unsafe { std::mem::zeroed::<sockaddr_nl>() };
        local.nl_family = AF_NETLINK as u16;
        local.nl_groups =
            nl_mgrp(RTNLGRP_IPV4_ROUTE) | nl_mgrp(RTNLGRP_IPV6_ROUTE) | nl_mgrp(RTNLGRP_MPLS_ROUTE);

        self.bind(local)
    }

    pub fn new_buf() -> [u8; 16384] {
        [0u8; 16384]
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

impl Drop for RouteSock {
    fn drop(&mut self) {
        let _ = syscall!(close(self.0));
    }
}

impl RouteAction for RouteSock {
    fn add(&mut self, route: &Route) -> io::Result<()> {
        route.validate()?;

        let mut nl_hdr = NetlinkHeader::default();
        nl_hdr.flags = NLM_F_REQUEST | NLM_F_EXCL | NLM_F_CREATE | NLM_F_ACK;
        // TODO: use a monotonically increasing sequence and validate response sequence numbers.
        nl_hdr.sequence_number = 1;

        let mut rt_msg = route_message(route);
        rt_msg.header.table = RouteHeader::RT_TABLE_MAIN;
        rt_msg.header.protocol = RouteProtocol::Boot;
        rt_msg.header.scope = RouteScope::Universe;
        rt_msg.header.kind = RouteType::Unicast;

        if let Some(gateway) = route.gateway {
            rt_msg
                .attributes
                .push(RouteAttribute::Gateway(route_address(gateway)));
        }

        if let Some(index) = route.ifindex {
            rt_msg.header.scope = RouteScope::Link;
            rt_msg.attributes.push(RouteAttribute::Oif(index));
        }

        let mut req = NetlinkMessage::new(
            nl_hdr,
            NetlinkPayload::from(RouteNetlinkMessage::NewRoute(rt_msg)),
        );
        req.finalize();

        let mut buf = [0u8; 4096];
        req.serialize(&mut buf[..req.buffer_len()]);
        self.write_all(&buf[..req.buffer_len()])?;
        self.recv_ack()
    }

    fn delete(&mut self, route: &Route) -> io::Result<()> {
        route.validate()?;

        let mut nl_hdr = NetlinkHeader::default();
        nl_hdr.flags = NLM_F_REQUEST | NLM_F_ACK;
        // TODO: use a monotonically increasing sequence and validate response sequence numbers.
        nl_hdr.sequence_number = 1;

        let mut rt_msg = route_message(route);
        rt_msg.header.table = RouteHeader::RT_TABLE_MAIN;
        rt_msg.header.scope = RouteScope::NoWhere;

        let mut req = NetlinkMessage::new(
            nl_hdr,
            NetlinkPayload::from(RouteNetlinkMessage::DelRoute(rt_msg)),
        );
        req.finalize();

        let mut buf = [0u8; 4096];
        req.serialize(&mut buf[..req.buffer_len()]);
        self.write_all(&buf[..req.buffer_len()])?;
        self.recv_ack()
    }

    fn get(&mut self, route: &Route) -> io::Result<Route> {
        route.validate()?;

        let mut nl_hdr = NetlinkHeader::default();
        nl_hdr.flags = NLM_F_DUMP | NLM_F_REQUEST;
        // TODO: use a monotonically increasing sequence and validate response sequence numbers.
        nl_hdr.sequence_number = 1;

        let mut rt_msg = RouteMessage::default();
        rt_msg.header.address_family = address_family(route.destination);
        rt_msg
            .attributes
            .push(RouteAttribute::Table(u32::from(RouteHeader::RT_TABLE_MAIN)));
        if let Some(index) = route.ifindex {
            rt_msg.attributes.push(RouteAttribute::Oif(index));
        }

        let mut req = NetlinkMessage::new(
            nl_hdr,
            NetlinkPayload::from(RouteNetlinkMessage::GetRoute(rt_msg)),
        );
        req.finalize();
        let mut buf = [0u8; 4096];
        req.serialize(&mut buf[..req.buffer_len()]);
        self.write_all(&buf[..req.buffer_len()])?;

        // TODO: return Option<Route> so callers can distinguish a miss from a real default route.
        let mut ret = Route::new(unspecified(address_family(route.destination)), 0);
        loop {
            let mut rbuf = [0u8; 16384];
            let n = self.read(&mut rbuf)?;
            let mut offset = 0;

            while offset < n {
                let nlmsg = parse_nlmsg(&rbuf[offset..n])?;
                let length = nlmsg.header.length as usize;
                if length == 0 {
                    return Err(io::Error::other("zero-length netlink message"));
                }

                match nlmsg.payload {
                    NetlinkPayload::Done(_) => return Ok(ret),
                    NetlinkPayload::Error(e) => {
                        if let Some(e) = e.code {
                            return Err(io::Error::other(format!("{e:?}")));
                        }
                        return Ok(ret);
                    }
                    NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewRoute(rt_msg)) => {
                        if rt_msg.header.destination_prefix_length <= route.prefix
                            && rt_msg.header.destination_prefix_length >= ret.prefix
                        {
                            if let Some(candidate) = route_from_message(&rt_msg)? {
                                if route_contains(&candidate, route.destination)? {
                                    ret = candidate;
                                }
                            }
                        }
                    }
                    _ => {}
                }

                offset += nlmsg_align(length);
            }
        }
    }

    fn monitor(&mut self, buf: &mut [u8]) -> io::Result<(RouteChange, Route)> {
        // TODO: the socket can return multiple route messages in one read; the current trait only returns one.
        let n = self.read(buf)?;
        let nlmsg = parse_nlmsg(&buf[..n])?;

        if let NetlinkPayload::InnerMessage(rtnl_msg) = nlmsg.payload {
            match rtnl_msg {
                RouteNetlinkMessage::NewRoute(rtmsg) => Ok((
                    RouteChange::ADD,
                    route_from_message(&rtmsg)?
                        .ok_or_else(|| io::Error::other("unsupported route address"))?,
                )),
                RouteNetlinkMessage::DelRoute(rtmsg) => Ok((
                    RouteChange::DELETE,
                    route_from_message(&rtmsg)?
                        .ok_or_else(|| io::Error::other("unsupported route address"))?,
                )),
                _ => Err(io::Error::other(format!(
                    "Unexpected rtnl message: {:?}",
                    rtnl_msg
                ))),
            }
        } else {
            Err(io::Error::other(format!("not rtnl message: {:?}", nlmsg)))
        }
    }
}

impl RouteSock {
    fn recv_ack(&mut self) -> io::Result<()> {
        // This is only for one request/ACK exchange, not dump or subscription responses.
        let mut rbuf = [0u8; 4096];
        let n = self.read(&mut rbuf)?;
        let nlmsg = parse_nlmsg(&rbuf[..n])?;

        if let NetlinkPayload::Error(e) = nlmsg.payload {
            if let Some(e) = e.code {
                return Err(io::Error::other(format!("{e:?}")));
            }
        }

        Ok(())
    }
}

fn route_message(route: &Route) -> RouteMessage {
    let mut rt_msg = RouteMessage::default();
    rt_msg.header.address_family = address_family(route.destination);
    rt_msg.header.destination_prefix_length = route.prefix;
    rt_msg
        .attributes
        .push(RouteAttribute::Destination(route_address(
            route.destination,
        )));
    rt_msg
}

fn route_from_message(rt_msg: &RouteMessage) -> io::Result<Option<Route>> {
    let mut route = Route::new(
        unspecified(rt_msg.header.address_family),
        rt_msg.header.destination_prefix_length,
    );

    for attr in &rt_msg.attributes {
        match attr {
            RouteAttribute::Destination(addr) => {
                let Some(destination) = ip_addr(addr) else {
                    return Ok(None);
                };
                route.destination = destination;
            }
            RouteAttribute::Gateway(addr) => {
                let Some(gateway) = ip_addr(addr) else {
                    return Ok(None);
                };
                route.gateway = Some(gateway);
            }
            RouteAttribute::Oif(index) => route.ifindex = Some(*index),
            _ => {}
        }
    }

    Ok(Some(route))
}

fn route_contains(route: &Route, target: IpAddr) -> io::Result<bool> {
    if address_family(route.destination) != address_family(target) {
        return Ok(false);
    }

    Ok(IpNetwork::new(route.destination, route.prefix)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?
        .contains(target))
}

fn parse_nlmsg(bytes: &[u8]) -> io::Result<NetlinkMessage<RouteNetlinkMessage>> {
    <NetlinkMessage<RouteNetlinkMessage>>::deserialize(bytes)
        .map_err(|e| io::Error::other(format!("{e:?}")))
}

fn nlmsg_align(len: usize) -> usize {
    (len + 3) & !3
}

fn address_family(addr: IpAddr) -> AddressFamily {
    match addr {
        IpAddr::V4(_) => AddressFamily::Inet,
        IpAddr::V6(_) => AddressFamily::Inet6,
    }
}

fn unspecified(family: AddressFamily) -> IpAddr {
    match family {
        AddressFamily::Inet6 => IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
        _ => IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
    }
}

fn route_address(addr: IpAddr) -> RouteAddress {
    match addr {
        IpAddr::V4(addr) => RouteAddress::Inet(addr),
        IpAddr::V6(addr) => RouteAddress::Inet6(addr),
    }
}

fn ip_addr(addr: &RouteAddress) -> Option<IpAddr> {
    match addr {
        RouteAddress::Inet(addr) => Some(IpAddr::V4(*addr)),
        RouteAddress::Inet6(addr) => Some(IpAddr::V6(*addr)),
        _ => None,
    }
}

const fn nl_mgrp(group: u32) -> u32 {
    if group > 31 {
        panic!("Use setsockopt NETLINK_ADD_MEMBERSHIP for this group");
    }

    if group == 0 {
        0
    } else {
        1 << (group - 1)
    }
}
