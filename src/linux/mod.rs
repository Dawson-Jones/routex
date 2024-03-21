mod rtmsg;

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
        let fd = syscall!(
            socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE)
        )?;

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

    pub fn subscript(&mut self) -> io::Result<()> {
        let mut local = unsafe { std::mem::zeroed::<sockaddr_nl>() };
        local.nl_family = AF_NETLINK as u16;
        local.nl_groups = nl_mgrp(RTNLGRP_IPV4_ROUTE) | nl_mgrp(RTNLGRP_IPV6_ROUTE) | nl_mgrp(RTNLGRP_MPLS_ROUTE);

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
        syscall!(close(self.0)).unwrap();
    }
}

impl RouteAction for RouteSock {
    fn add(&mut self, route: &Route) -> io::Result<()> {
        let mut nl_hdr = NetlinkHeader::default();
        nl_hdr.flags = NLM_F_REQUEST | NLM_F_EXCL | NLM_F_CREATE | NLM_F_ACK;
        nl_hdr.sequence_number = 1;

        let mut rt_msg = RouteMessage::default();
        rt_msg.header.table = RouteHeader::RT_TABLE_MAIN;
        rt_msg.header.protocol = RouteProtocol::Boot;
        rt_msg.header.scope = RouteScope::Universe;
        rt_msg.header.kind = RouteType::Unicast;

        match route.destination {
            std::net::IpAddr::V4(addr) => {
                rt_msg.header.address_family = AddressFamily::Inet;
                rt_msg
                    .attributes
                    .push(RouteAttribute::Destination(RouteAddress::Inet(addr)));
            }
            std::net::IpAddr::V6(addr) => {
                rt_msg.header.address_family = AddressFamily::Inet6;
                rt_msg
                    .attributes
                    .push(RouteAttribute::Destination(RouteAddress::Inet6(addr)));
            }
        }
        rt_msg.header.destination_prefix_length = route.prefix;

        if let Some(gateway) = route.gateway {
            match gateway {
                std::net::IpAddr::V4(addr) => {
                    rt_msg.header.address_family = AddressFamily::Inet;
                    rt_msg
                        .attributes
                        .push(RouteAttribute::Gateway(RouteAddress::Inet(addr)));
                }
                std::net::IpAddr::V6(addr) => {
                    rt_msg.header.address_family = AddressFamily::Inet6;
                    rt_msg
                        .attributes
                        .push(RouteAttribute::Gateway(RouteAddress::Inet6(addr)));
                }
            }
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

        self.write(&buf[..req.buffer_len()])?;

        let mut rbuf = [0u8; 4096];
        let n = self.read(&mut rbuf)?;
        let nlmsg = <NetlinkMessage<RouteNetlinkMessage>>::deserialize(&rbuf[..n]);
        // println!("<<< {:?}", nlmsg);
        match nlmsg {
            Ok(nlmsg) => {
                if let NetlinkPayload::Error(e) = nlmsg.payload {
                    match e.code {
                        Some(e) => {
                            return Err(io::Error::new(io::ErrorKind::Other, format!("{e:?}")))
                        }
                        None => return Ok(()),
                    }
                }
            }
            Err(e) => return Err(io::Error::new(io::ErrorKind::Other, format!("{e:?}"))),
        }

        Ok(())
    }

    fn delete(&mut self, route: &Route) -> io::Result<()> {
        let mut nl_hdr = NetlinkHeader::default();
        nl_hdr.flags = NLM_F_REQUEST | NLM_F_ACK;
        nl_hdr.sequence_number = 1;

        let mut rt_msg = RouteMessage::default();
        rt_msg.header.table = RouteHeader::RT_TABLE_MAIN;
        rt_msg.header.scope = RouteScope::NoWhere;

        match route.destination {
            std::net::IpAddr::V4(addr) => {
                rt_msg.header.address_family = AddressFamily::Inet;
                rt_msg
                    .attributes
                    .push(RouteAttribute::Destination(RouteAddress::Inet(addr)));
            }
            std::net::IpAddr::V6(addr) => {
                rt_msg.header.address_family = AddressFamily::Inet6;
                rt_msg
                    .attributes
                    .push(RouteAttribute::Destination(RouteAddress::Inet6(addr)));
            }
        }
        rt_msg.header.destination_prefix_length = route.prefix;

        let mut req = NetlinkMessage::new(
            nl_hdr,
            NetlinkPayload::from(RouteNetlinkMessage::DelRoute(rt_msg)),
        );
        req.finalize();

        let mut buf = [0u8; 4096];
        req.serialize(&mut buf[..req.buffer_len()]);
        self.write(&buf[..req.buffer_len()])?;

        let mut rbuf = [0u8; 4096];
        let n = self.read(&mut rbuf)?;
        let nlmsg = <NetlinkMessage<RouteNetlinkMessage>>::deserialize(&rbuf[..n]);
        // println!("<<< {:?}", nlmsg);
        match nlmsg {
            Ok(nlmsg) => {
                if let NetlinkPayload::Error(e) = nlmsg.payload {
                    match e.code {
                        Some(e) => {
                            return Err(io::Error::new(io::ErrorKind::Other, format!("{e:?}")))
                        }
                        None => return Ok(()),
                    }
                }
            }
            Err(e) => return Err(io::Error::new(io::ErrorKind::Other, format!("{e:?}"))),
        }

        Ok(())
    }

    fn get(&mut self, route: &Route) -> io::Result<Route> {
        let mut nl_hdr = NetlinkHeader::default();
        nl_hdr.flags = NLM_F_DUMP | NLM_F_REQUEST;
        nl_hdr.sequence_number = 1;

        let mut rt_msg = RouteMessage::default();
        rt_msg.header.address_family = AddressFamily::Inet;
        rt_msg
            .attributes
            .push(RouteAttribute::Table(254 /*table main*/));
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
        // println!(">>> {:?}", &buf[..req.buffer_len()]);
        self.write(&buf[..req.buffer_len()])?;

        let mut ret = Route::default();
        let mut offset = 0;
        let mut rbuf = [0u8; 4096];
        let n = self.read(&mut rbuf)?;
        loop {
            let bytes = &rbuf[offset..];

            let nlmsg = match <NetlinkMessage<RouteNetlinkMessage>>::deserialize(bytes) {
                Ok(nlmsg) => {
                    nlmsg
                }
                Err(e) => {
                    return Err(io::Error::new(io::ErrorKind::Other, format!("{e:?}")));
                }
            };

            if matches!(nlmsg.payload, NetlinkPayload::Done(_)) {
                // println!("Done!");
                break;
            }

            if let NetlinkPayload::InnerMessage(rtnl_msg) = nlmsg.payload {
                if let RouteNetlinkMessage::NewRoute(rt_msg) = rtnl_msg {
                    if rt_msg.header.destination_prefix_length <= route.prefix
                        && rt_msg.header.destination_prefix_length >= ret.prefix
                    {
                        let mut t_route = Route::default();
                        t_route.prefix = rt_msg.header.destination_prefix_length;

                        let mut travel_over_nomal = true;
                        for attr in &rt_msg.attributes {
                            match attr {
                                RouteAttribute::Destination(dst) => {
                                    if let RouteAddress::Inet(dst) = dst {
                                        if let IpAddr::V4(target) = route.destination {
                                            let contained = IpNetwork::new(
                                                IpAddr::V4(*dst),
                                                rt_msg.header.destination_prefix_length,
                                            )
                                            .unwrap()
                                            .contains(IpAddr::V4(target));

                                            if !contained {
                                                travel_over_nomal = false;
                                                break;
                                            }

                                            t_route.destination = IpAddr::V4(*dst)
                                        }
                                    } else if let RouteAddress::Inet6(dst) = dst {
                                        if let IpAddr::V6(target) = route.destination {
                                            let contained = IpNetwork::new(
                                                IpAddr::V6(*dst),
                                                rt_msg.header.destination_prefix_length,
                                            )
                                            .unwrap()
                                            .contains(IpAddr::V6(target));

                                            if !contained {
                                                travel_over_nomal = false;
                                                break;
                                            }

                                            t_route.destination = IpAddr::V6(*dst)
                                        }
                                    }
                                }

                                RouteAttribute::Gateway(gw) => {
                                    if let RouteAddress::Inet(gw) = gw {
                                        t_route.gateway = Some(IpAddr::V4(*gw));
                                    } else if let RouteAddress::Inet6(gw) = gw {
                                        t_route.gateway = Some(IpAddr::V6(*gw));
                                    } else {
                                        return Err(io::Error::new(
                                            io::ErrorKind::Other,
                                            "Invalid gateway",
                                        ));
                                    }
                                }

                                RouteAttribute::Oif(index) => {
                                    t_route.ifindex = Some(*index);
                                }

                                _ => (),
                            }
                        }

                        if travel_over_nomal {
                            ret = t_route
                        }
                    }
                }
            }

            offset += nlmsg.header.length as usize;
            if offset == n || nlmsg.header.length == 0 {
                // println!("offset: {}, n: {}, nlmsg len: {}", offset, n, nlmsg.header.length);
                break;
            }
        }

        Ok(ret)
    }

    fn monitor(&mut self, buf: &mut [u8]) -> io::Result<(RouteChange, Route)> {
        // maybe have another netlink message on same buf. see `get`
        let n = self.read(buf)?;
        println!("read {n} bytes");

        let nlmsg = match <NetlinkMessage<RouteNetlinkMessage>>::deserialize(&buf[..n]) {
            Ok(nlmsg) => {
                nlmsg
            }
            Err(e) => {
                return Err(io::Error::new(io::ErrorKind::Other, format!("{e:?}")));
            }
        };

        let mut ret = Route::default();

        if let NetlinkPayload::InnerMessage(rtnl_msg) = nlmsg.payload {
            match rtnl_msg {
                RouteNetlinkMessage::NewRoute(rtmsg) => {
                    ret.prefix = rtmsg.header.destination_prefix_length;

                    for attr in &rtmsg.attributes {
                        match attr {
                            RouteAttribute::Destination(addr) => {
                                if let RouteAddress::Inet(addr) = addr {
                                    ret.destination = IpAddr::V4(*addr);
                                } else if let RouteAddress::Inet6(addr) = addr {
                                    ret.destination = IpAddr::V6(*addr);
                                }
                            },
                            RouteAttribute::Gateway(addr) => {
                                if let RouteAddress::Inet(addr) = addr {
                                    ret.gateway = Some(IpAddr::V4(*addr));
                                } else if let RouteAddress::Inet6(addr) = addr {
                                    ret.gateway = Some(IpAddr::V6(*addr));
                                }

                            },
                            RouteAttribute::Oif(ifindex) => {
                                ret.ifindex = Some(*ifindex);
                            },
                            _ => (),
                        }
                    }

                    return Ok((RouteChange::ADD, ret))
                },
                RouteNetlinkMessage::DelRoute(rtmsg) => {
                    ret.prefix = rtmsg.header.destination_prefix_length;

                    for attr in &rtmsg.attributes {
                        match attr {
                            RouteAttribute::Destination(addr) => {
                                if let RouteAddress::Inet(addr) = addr {
                                    ret.destination = IpAddr::V4(*addr);
                                } else if let RouteAddress::Inet6(addr) = addr {
                                    ret.destination = IpAddr::V6(*addr);
                                }
                            },
                            RouteAttribute::Gateway(addr) => {
                                if let RouteAddress::Inet(addr) = addr {
                                    ret.gateway = Some(IpAddr::V4(*addr));
                                } else if let RouteAddress::Inet6(addr) = addr {
                                    ret.gateway = Some(IpAddr::V6(*addr));
                                }

                            },
                            RouteAttribute::Oif(ifindex) => {
                                ret.ifindex = Some(*ifindex);
                            },
                            _ => (),
                        }
                    }

                    return Ok((RouteChange::DELETE, ret))
                },
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        format!("Unexpected rtnl message: {:?}", rtnl_msg),
                    ))
                },
            }
        } else {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("not rtnl message: {:?}", nlmsg),
            ))
        }

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