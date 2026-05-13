#![allow(clippy::macro_metavars_in_unsafe)]

use std::{
    ffi::CString,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "windows")]
mod windows;

#[cfg(target_os = "linux")]
pub use linux::RouteSock;
#[cfg(target_os = "macos")]
pub use macos::RouteSock;
#[cfg(target_os = "windows")]
pub use windows::RouteSock;

#[macro_export]
#[allow(clippy::macro_metavars_in_unsafe)]
macro_rules! syscall {
    ($fn: ident ( $($arg: expr),* ) ) => {{
        #[allow(unused_unsafe)]
        let res = unsafe { libc::$fn($( $arg), *) };
        if res < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(res)
        }
    }};
}

#[derive(Debug, Clone)]
pub struct Route {
    pub destination: IpAddr,
    pub prefix: u8,
    pub gateway: Option<IpAddr>,
    pub ifindex: Option<u32>,
}

impl Default for Route {
    fn default() -> Self {
        Route {
            destination: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            prefix: 0,
            gateway: None,
            ifindex: None,
        }
    }
}

impl Route {
    pub fn new(destination: IpAddr, prefix: u8) -> Route {
        Route {
            destination,
            prefix,
            gateway: None,
            ifindex: None,
        }
    }

    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub(crate) fn mask(&self) -> IpAddr {
        match self.destination {
            IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::from(
                u32::MAX.checked_shl(32 - self.prefix as u32).unwrap_or(0),
            )),
            IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::from(
                u128::MAX.checked_shl(128 - self.prefix as u32).unwrap_or(0),
            )),
        }
    }

    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub(crate) fn cidr(&mut self, netmask: IpAddr) {
        self.prefix = match netmask {
            IpAddr::V4(netmask) => <Ipv4Addr as Into<u32>>::into(netmask).leading_ones() as u8,
            IpAddr::V6(netmask) => <Ipv6Addr as Into<u128>>::into(netmask).leading_ones() as u8,
        }
    }

    pub(crate) fn validate(&self) -> io::Result<()> {
        let max_prefix = match self.destination {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };

        if self.prefix > max_prefix {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid prefix {} for {}", self.prefix, self.destination),
            ));
        }

        if let Some(gateway) = self.gateway {
            if std::mem::discriminant(&self.destination) != std::mem::discriminant(&gateway) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "gateway {gateway} does not match destination {}",
                        self.destination
                    ),
                ));
            }
        }

        Ok(())
    }

    #[cfg(target_os = "linux")]
    pub fn via(mut self, gateway: IpAddr) -> Route {
        self.gateway = Some(gateway);
        self
    }

    pub fn gateway(mut self, gateway: IpAddr) -> Route {
        self.gateway = Some(gateway);
        self
    }

    pub fn ifindex(mut self, ifindex: u32) -> Route {
        self.ifindex = Some(ifindex);
        self
    }

    #[cfg(any(target_os = "macos", target_os = "windows"))]
    pub fn interface(mut self, interface: &str) -> Route {
        self.ifindex = if_nametoindex(interface);
        self
    }

    #[cfg(target_os = "linux")]
    pub fn dev(mut self, interface: &str) -> Route {
        self.ifindex = if_nametoindex(interface);
        self
    }
}

#[derive(Debug)]
pub enum RouteChange {
    ADD,
    DELETE,
    CHANGE,
    OTHER(u8),
}

impl From<u8> for RouteChange {
    fn from(value: u8) -> Self {
        match value {
            1 => RouteChange::ADD,
            2 => RouteChange::DELETE,
            3 => RouteChange::CHANGE,
            _ => RouteChange::OTHER(value),
        }
    }
}

pub trait RouteAction {
    fn add(&mut self, route: &Route) -> io::Result<()>;
    fn delete(&mut self, route: &Route) -> io::Result<()>;
    fn get(&mut self, route: &Route) -> io::Result<Route>;
    fn monitor(&mut self, buf: &mut [u8]) -> io::Result<(RouteChange, Route)>;
}

pub fn if_nametoindex(name: &str) -> Option<u32> {
    let name = CString::new(name).ok()?;

    #[cfg(not(target_os = "windows"))]
    let ifindex = unsafe { libc::if_nametoindex(name.as_ptr()) };

    #[cfg(target_os = "windows")]
    let ifindex = unsafe {
        windows_sys::Win32::NetworkManagement::IpHelper::if_nametoindex(name.as_ptr().cast())
    };

    (ifindex != 0).then_some(ifindex)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_rejects_prefix_outside_address_family() {
        let route = Route::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 33);

        assert_eq!(
            route.validate().unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn validate_rejects_mismatched_gateway_family() {
        let route = Route::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
            .gateway(IpAddr::V6(Ipv6Addr::LOCALHOST));

        assert_eq!(
            route.validate().unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }
}
