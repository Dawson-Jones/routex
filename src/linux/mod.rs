use std::{
    collections::VecDeque,
    io::{self, Read, Write},
    net::IpAddr,
    num::NonZeroI32,
    os::fd::{AsRawFd, RawFd},
    sync::atomic::{AtomicU32, Ordering},
};

use libc::{
    AF_NETLINK, NETLINK_ROUTE, RTNLGRP_IPV4_ROUTE, RTNLGRP_IPV6_ROUTE, SOCK_CLOEXEC, SOCK_RAW,
    sockaddr_nl,
};
use netlink_packet_core::{
    NLM_F_ACK, NLM_F_CREATE, NLM_F_EXCL, NLM_F_REQUEST, NetlinkHeader, NetlinkMessage,
    NetlinkPayload,
};
use netlink_packet_route::{
    AddressFamily, RouteNetlinkMessage,
    route::{
        RouteAddress, RouteAttribute, RouteHeader, RouteMessage, RouteProtocol, RouteScope,
        RouteType,
    },
};

use crate::{Route, RouteAction, RouteChange};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SocketMode {
    Fresh,
    Command(u32),
    Monitor,
}

pub struct RouteSock {
    fd: RawFd,
    sequence: AtomicU32,
    mode: SocketMode,
    pending_changes: VecDeque<(RouteChange, Route)>,
}

impl AsRawFd for RouteSock {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl RouteSock {
    pub fn new() -> io::Result<Self> {
        let fd = syscall!(socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE))?;

        Ok(Self {
            fd,
            sequence: AtomicU32::new(0),
            mode: SocketMode::Fresh,
            pending_changes: VecDeque::new(),
        })
    }

    fn bind(&mut self, local: sockaddr_nl) -> io::Result<()> {
        syscall!(bind(
            self.as_raw_fd(),
            &local as *const sockaddr_nl as *const _,
            std::mem::size_of::<sockaddr_nl>() as _
        ))?;

        Ok(())
    }

    fn bind_command(&mut self) -> io::Result<u32> {
        let mut local = unsafe { std::mem::zeroed::<sockaddr_nl>() };
        local.nl_family = AF_NETLINK as u16;
        self.bind(local)?;

        let mut assigned = unsafe { std::mem::zeroed::<sockaddr_nl>() };
        let mut assigned_len = std::mem::size_of::<sockaddr_nl>() as libc::socklen_t;
        syscall!(getsockname(
            self.as_raw_fd(),
            (&mut assigned as *mut sockaddr_nl).cast(),
            &mut assigned_len
        ))?;
        if assigned_len < std::mem::size_of::<sockaddr_nl>() as libc::socklen_t
            || assigned.nl_family != AF_NETLINK as u16
            || assigned.nl_pid == 0
        {
            return Err(io::Error::other(
                "kernel assigned an invalid netlink address",
            ));
        }

        Ok(assigned.nl_pid)
    }

    pub fn subscribe(&mut self) -> io::Result<()> {
        match self.mode {
            SocketMode::Fresh => {}
            SocketMode::Monitor => return Ok(()),
            SocketMode::Command(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "a command netlink socket cannot become a route monitor",
                ));
            }
        }

        let mut local = unsafe { std::mem::zeroed::<sockaddr_nl>() };
        local.nl_family = AF_NETLINK as u16;
        local.nl_groups = nl_mgrp(RTNLGRP_IPV4_ROUTE) | nl_mgrp(RTNLGRP_IPV6_ROUTE);

        self.bind(local)?;
        self.mode = SocketMode::Monitor;
        Ok(())
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
        let _ = syscall!(close(self.fd));
    }
}

impl RouteAction for RouteSock {
    fn add(&mut self, route: &Route) -> io::Result<()> {
        route.validate()?;

        let (sequence, port_id) = self.next_command_sequence()?;
        let mut nl_hdr = NetlinkHeader::default();
        nl_hdr.flags = NLM_F_REQUEST | NLM_F_EXCL | NLM_F_CREATE | NLM_F_ACK;
        nl_hdr.sequence_number = sequence;
        nl_hdr.port_number = port_id;

        let mut rt_msg = route_change_message(route);
        rt_msg.header.table = RouteHeader::RT_TABLE_MAIN;
        rt_msg.header.protocol = RouteProtocol::Boot;
        rt_msg.header.scope = RouteScope::Universe;
        rt_msg.header.kind = RouteType::Unicast;

        add_route_selectors(&mut rt_msg, route);
        if route.gateway.is_none() && route.ifindex.is_some() {
            rt_msg.header.scope = RouteScope::Link;
        }

        let mut req = NetlinkMessage::new(
            nl_hdr,
            NetlinkPayload::from(RouteNetlinkMessage::NewRoute(rt_msg)),
        );
        req.finalize();

        let mut buf = [0u8; 4096];
        req.serialize(&mut buf[..req.buffer_len()]);
        self.write_all(&buf[..req.buffer_len()])?;
        self.recv_ack(sequence, port_id)
    }

    fn delete(&mut self, route: &Route) -> io::Result<()> {
        route.validate()?;

        let (sequence, port_id) = self.next_command_sequence()?;
        let mut nl_hdr = NetlinkHeader::default();
        nl_hdr.flags = NLM_F_REQUEST | NLM_F_ACK;
        nl_hdr.sequence_number = sequence;
        nl_hdr.port_number = port_id;

        let mut rt_msg = route_change_message(route);
        rt_msg.header.table = RouteHeader::RT_TABLE_MAIN;
        rt_msg.header.scope = RouteScope::NoWhere;
        add_route_selectors(&mut rt_msg, route);

        let mut req = NetlinkMessage::new(
            nl_hdr,
            NetlinkPayload::from(RouteNetlinkMessage::DelRoute(rt_msg)),
        );
        req.finalize();

        let mut buf = [0u8; 4096];
        req.serialize(&mut buf[..req.buffer_len()]);
        self.write_all(&buf[..req.buffer_len()])?;
        self.recv_ack(sequence, port_id)
    }

    fn get(&mut self, route: &Route) -> io::Result<Route> {
        route.validate()?;

        let (sequence, port_id) = self.next_command_sequence()?;
        let mut nl_hdr = NetlinkHeader::default();
        nl_hdr.flags = NLM_F_REQUEST;
        nl_hdr.sequence_number = sequence;
        nl_hdr.port_number = port_id;

        let rt_msg = route_lookup_message(route);

        let mut req = NetlinkMessage::new(
            nl_hdr,
            NetlinkPayload::from(RouteNetlinkMessage::GetRoute(rt_msg)),
        );
        req.finalize();
        let mut buf = [0u8; 4096];
        req.serialize(&mut buf[..req.buffer_len()]);
        self.write_all(&buf[..req.buffer_len()])?;

        self.recv_route_response(sequence, port_id)
    }

    fn monitor(&mut self, buf: &mut [u8]) -> io::Result<(RouteChange, Route)> {
        if !matches!(self.mode, SocketMode::Monitor) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "call subscribe before monitoring route changes",
            ));
        }

        loop {
            if let Some(change) = self.pending_changes.pop_front() {
                return Ok(change);
            }

            let n = self.read(buf)?;
            enqueue_route_changes(parse_nlmsgs(&buf[..n])?, &mut self.pending_changes)?;
        }
    }
}

impl RouteSock {
    fn next_command_sequence(&mut self) -> io::Result<(u32, u32)> {
        let port_id = match self.mode {
            SocketMode::Fresh => {
                let port_id = self.bind_command()?;
                self.mode = SocketMode::Command(port_id);
                port_id
            }
            SocketMode::Command(port_id) => port_id,
            SocketMode::Monitor => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "route commands require a non-subscribed netlink socket",
                ));
            }
        };

        let previous = self
            .sequence
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |sequence| {
                Some(sequence.wrapping_add(1).max(1))
            })
            .expect("sequence update closure always returns Some");
        Ok((previous.wrapping_add(1).max(1), port_id))
    }

    fn recv_route_response(&mut self, sequence: u32, port_id: u32) -> io::Result<Route> {
        loop {
            let mut rbuf = [0u8; 16384];
            let n = self.read(&mut rbuf)?;
            for nlmsg in parse_nlmsgs(&rbuf[..n])? {
                if !response_matches(&nlmsg.header, sequence, port_id) {
                    continue;
                }

                match nlmsg.payload {
                    NetlinkPayload::Done(_) => {
                        return Err(io::Error::new(io::ErrorKind::NotFound, "route not found"));
                    }
                    NetlinkPayload::Error(e) => {
                        if let Some(e) = e.code {
                            return Err(netlink_error(e));
                        }
                        return Err(io::Error::other("received an ACK without a route response"));
                    }
                    NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewRoute(rt_msg)) => {
                        if let Some(candidate) = route_from_message(&rt_msg)? {
                            return Ok(candidate);
                        }
                    }
                    payload => {
                        return Err(io::Error::other(format!(
                            "unexpected netlink route response: {payload:?}"
                        )));
                    }
                }
            }
        }
    }

    fn recv_ack(&mut self, sequence: u32, port_id: u32) -> io::Result<()> {
        loop {
            let mut rbuf = [0u8; 4096];
            let n = self.read(&mut rbuf)?;
            if let Some(result) = ack_from_messages(&parse_nlmsgs(&rbuf[..n])?, sequence, port_id) {
                return result;
            }
        }
    }
}

fn netlink_error(code: NonZeroI32) -> io::Error {
    let raw = code.get();
    io::Error::from_raw_os_error(if raw < 0 { -raw } else { raw })
}

fn route_change_message(route: &Route) -> RouteMessage {
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

fn add_route_selectors(rt_msg: &mut RouteMessage, route: &Route) {
    if let Some(gateway) = route.gateway {
        rt_msg
            .attributes
            .push(RouteAttribute::Gateway(route_address(gateway)));
    }

    if let Some(index) = route.ifindex {
        rt_msg.attributes.push(RouteAttribute::Oif(index));
    }
}

fn route_lookup_message(route: &Route) -> RouteMessage {
    let mut rt_msg = RouteMessage::default();
    rt_msg.header.address_family = address_family(route.destination);
    rt_msg.header.destination_prefix_length = route.prefix;
    rt_msg
        .attributes
        .push(RouteAttribute::Destination(route_address(
            route.destination,
        )));

    if let Some(index) = route.ifindex {
        rt_msg.attributes.push(RouteAttribute::Oif(index));
    }

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

fn parse_nlmsgs(bytes: &[u8]) -> io::Result<Vec<NetlinkMessage<RouteNetlinkMessage>>> {
    const NETLINK_HEADER_LEN: usize = 16;

    let mut messages = Vec::new();
    let mut offset = 0;
    while offset < bytes.len() {
        let remaining = &bytes[offset..];
        if remaining.len() < NETLINK_HEADER_LEN {
            return Err(io::Error::other("truncated netlink header"));
        }

        let message = <NetlinkMessage<RouteNetlinkMessage>>::deserialize(remaining)
            .map_err(|error| io::Error::other(format!("{error:?}")))?;
        let length = message.header.length as usize;
        if length < NETLINK_HEADER_LEN || length > remaining.len() {
            return Err(io::Error::other(format!(
                "invalid netlink message length {length}"
            )));
        }

        messages.push(message);
        let message_end = offset
            .checked_add(length)
            .ok_or_else(|| io::Error::other("netlink message length overflow"))?;
        let aligned_end = offset
            .checked_add(nlmsg_align(length))
            .ok_or_else(|| io::Error::other("netlink message length overflow"))?;
        if aligned_end > bytes.len() {
            if message_end == bytes.len() {
                break;
            }
            return Err(io::Error::other("truncated netlink message padding"));
        }
        offset = aligned_end;
    }

    Ok(messages)
}

fn response_matches(header: &NetlinkHeader, sequence: u32, port_id: u32) -> bool {
    header.port_number == port_id && header.sequence_number == sequence
}

fn ack_from_messages(
    messages: &[NetlinkMessage<RouteNetlinkMessage>],
    sequence: u32,
    port_id: u32,
) -> Option<io::Result<()>> {
    messages
        .iter()
        .find(|message| response_matches(&message.header, sequence, port_id))
        .map(|message| match &message.payload {
            NetlinkPayload::Error(error) => match error.code {
                Some(code) => Err(netlink_error(code)),
                None => Ok(()),
            },
            payload => Err(io::Error::other(format!(
                "unexpected netlink ACK response: {payload:?}"
            ))),
        })
}

fn enqueue_route_changes(
    messages: Vec<NetlinkMessage<RouteNetlinkMessage>>,
    pending: &mut VecDeque<(RouteChange, Route)>,
) -> io::Result<()> {
    for message in messages {
        match message.payload {
            NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewRoute(route)) => {
                if let Some(route) = route_from_message(&route)? {
                    pending.push_back((RouteChange::ADD, route));
                }
            }
            NetlinkPayload::InnerMessage(RouteNetlinkMessage::DelRoute(route)) => {
                if let Some(route) = route_from_message(&route)? {
                    pending.push_back((RouteChange::DELETE, route));
                }
            }
            NetlinkPayload::Error(error) => {
                if let Some(code) = error.code {
                    return Err(netlink_error(code));
                }
            }
            NetlinkPayload::Overrun(_) => {
                return Err(io::Error::other("netlink route monitor overrun"));
            }
            _ => {}
        }
    }

    Ok(())
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

    if group == 0 { 0 } else { 1 << (group - 1) }
}

#[cfg(test)]
mod tests {
    use std::{collections::VecDeque, net::Ipv4Addr};

    use netlink_packet_core::ErrorMessage;

    use super::*;

    fn message(
        sequence: u32,
        port_number: u32,
        payload: NetlinkPayload<RouteNetlinkMessage>,
    ) -> NetlinkMessage<RouteNetlinkMessage> {
        let mut header = NetlinkHeader::default();
        header.sequence_number = sequence;
        header.port_number = port_number;
        let mut message = NetlinkMessage::new(header, payload);
        message.finalize();
        message
    }

    fn ack(
        sequence: u32,
        port_number: u32,
        error: Option<i32>,
    ) -> NetlinkMessage<RouteNetlinkMessage> {
        let mut ack = ErrorMessage::default();
        ack.code = error.and_then(NonZeroI32::new);
        message(sequence, port_number, NetlinkPayload::Error(ack))
    }

    fn route_message(destination: Ipv4Addr, deleted: bool) -> NetlinkMessage<RouteNetlinkMessage> {
        let route = Route::new(IpAddr::V4(destination), 32);
        let payload = if deleted {
            RouteNetlinkMessage::DelRoute(route_change_message(&route))
        } else {
            RouteNetlinkMessage::NewRoute(route_change_message(&route))
        };
        message(0, 0, NetlinkPayload::InnerMessage(payload))
    }

    fn serialize(messages: &[NetlinkMessage<RouteNetlinkMessage>]) -> Vec<u8> {
        let mut bytes = Vec::new();
        for message in messages {
            let start = bytes.len();
            let length = message.buffer_len();
            bytes.resize(start + nlmsg_align(length), 0);
            message.serialize(&mut bytes[start..start + length]);
        }
        bytes
    }

    #[test]
    fn response_matching_requires_local_port_and_expected_sequence() {
        let mut header = NetlinkHeader::default();
        header.sequence_number = 7;
        header.port_number = 42;
        assert!(!response_matches(&header, 7, 99));

        header.sequence_number = 6;
        assert!(!response_matches(&header, 7, 42));

        header.sequence_number = 7;
        assert!(response_matches(&header, 7, 42));
    }

    #[test]
    fn ack_filter_skips_foreign_messages_and_preserves_kernel_errors() {
        let messages = [ack(9, 123, None), ack(8, 777, None), ack(9, 777, None)];
        assert!(ack_from_messages(&messages, 9, 777).unwrap().is_ok());

        let messages = [ack(9, 777, Some(-libc::EPERM))];
        let error = ack_from_messages(&messages, 9, 777).unwrap().unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EPERM));
    }

    #[test]
    fn multi_message_datagram_queues_every_route_change() {
        let add = route_message(Ipv4Addr::new(10, 0, 0, 1), false);
        let delete = route_message(Ipv4Addr::new(10, 0, 0, 2), true);
        let parsed = parse_nlmsgs(&serialize(&[add, delete])).unwrap();
        assert_eq!(parsed.len(), 2);

        let mut pending = VecDeque::new();
        enqueue_route_changes(parsed, &mut pending).unwrap();

        let (change, route) = pending.pop_front().unwrap();
        assert!(matches!(change, RouteChange::ADD));
        assert_eq!(route.destination, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        let (change, route) = pending.pop_front().unwrap();
        assert!(matches!(change, RouteChange::DELETE));
        assert_eq!(route.destination, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
        assert!(pending.is_empty());
    }

    #[test]
    fn delete_message_keeps_nowhere_scope_and_includes_selectors() {
        let route = Route::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 24)
            .gateway(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
            .ifindex(7);
        let mut message = route_change_message(&route);
        message.header.scope = RouteScope::NoWhere;
        add_route_selectors(&mut message, &route);

        assert_eq!(message.header.scope, RouteScope::NoWhere);
        assert!(message.attributes.iter().any(|attribute| {
            matches!(attribute, RouteAttribute::Gateway(RouteAddress::Inet(address)) if *address == Ipv4Addr::new(10, 0, 0, 1))
        }));
        assert!(
            message
                .attributes
                .iter()
                .any(|attribute| matches!(attribute, RouteAttribute::Oif(7)))
        );
    }

    #[test]
    #[ignore = "black-box check against the live Linux routing table"]
    fn default_route_lookup_matches_the_bound_command_socket() {
        let mut socket = RouteSock::new().unwrap();

        let route = socket.get(&Route::default()).unwrap();

        assert!(matches!(socket.mode, SocketMode::Command(port_id) if port_id != 0));
        assert!(route.destination.is_ipv4());
    }
}
