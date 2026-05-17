use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    ptr,
};

use windows_sys::Win32::{
    Foundation::{
        ERROR_BUFFER_OVERFLOW, ERROR_FILE_NOT_FOUND, ERROR_NOT_FOUND, ERROR_OBJECT_ALREADY_EXISTS,
        ERROR_SUCCESS,
    },
    NetworkManagement::IpHelper::{
        CreateIpForwardEntry2, DeleteIpForwardEntry2, FreeMibTable,
        GAA_FLAG_INCLUDE_ALL_INTERFACES, GetAdaptersAddresses, GetBestRoute2, GetIpForwardTable2,
        IP_ADAPTER_ADDRESSES_LH, InitializeIpForwardEntry, MIB_IPFORWARD_ROW2,
        MIB_IPFORWARD_TABLE2,
    },
    Networking::WinSock::{
        ADDRESS_FAMILY, AF_INET, AF_INET6, AF_UNSPEC, IN_ADDR, IN_ADDR_0, IN6_ADDR,
        MIB_IPPROTO_NETMGMT, NlroManual, SOCKADDR_IN, SOCKADDR_IN6, SOCKADDR_INET,
    },
};

use crate::{Route, RouteAction, RouteChange};

pub struct RouteSock;

impl RouteSock {
    pub fn new() -> io::Result<Self> {
        Ok(Self)
    }

    pub fn new_buf() -> [u8; 0] {
        // TODO: replace this placeholder when monitor is backed by NotifyRouteChange2.
        []
    }
}

impl RouteAction for RouteSock {
    fn add(&mut self, route: &Route) -> io::Result<()> {
        route.validate()?;

        let mut row = route_row(route);
        row.InterfaceIndex = resolve_interface_index(route)?;
        win32_result(unsafe { CreateIpForwardEntry2(&row) })
    }

    fn delete(&mut self, route: &Route) -> io::Result<()> {
        route.validate()?;

        let row = find_route(route)?;
        win32_result(unsafe { DeleteIpForwardEntry2(&row) })
    }

    fn get(&mut self, route: &Route) -> io::Result<Route> {
        route.validate()?;

        // GetBestRoute2 treats an unspecified destination as a lookup target, not as "show default route".
        let row = if route.destination.is_unspecified() && route.prefix == 0 {
            find_route(route)?
        } else {
            best_route(route.destination, route.ifindex.unwrap_or(0))?
        };

        Ok(route_from_row(&row))
    }

    fn monitor(&mut self, _buf: &mut [u8]) -> io::Result<(RouteChange, Route)> {
        // TODO: implement this with NotifyRouteChange2 and an internal event queue.
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Windows route monitoring is not implemented",
        ))
    }
}

pub(crate) fn if_friendly_name_to_index(name: &str) -> Option<u32> {
    let table = AdapterAddressTable::new().ok()?;
    let target = name.to_lowercase();

    table.rows().find_map(|row| {
        let friendly_name = unsafe { wide_ptr_to_string(row.FriendlyName) }?;
        (friendly_name.to_lowercase() == target)
            .then(|| unsafe { row.Anonymous1.Anonymous.IfIndex })
    })
}

fn route_row(route: &Route) -> MIB_IPFORWARD_ROW2 {
    let mut row = MIB_IPFORWARD_ROW2::default();
    unsafe { InitializeIpForwardEntry(&mut row) };

    row.DestinationPrefix.Prefix = sockaddr(route.destination);
    row.DestinationPrefix.PrefixLength = route.prefix;
    row.NextHop = sockaddr(
        route
            .gateway
            .unwrap_or_else(|| unspecified(route.destination)),
    );
    row.Protocol = MIB_IPPROTO_NETMGMT;
    row.Origin = NlroManual;

    row
}

fn find_route(route: &Route) -> io::Result<MIB_IPFORWARD_ROW2> {
    let table = RouteTable::new(address_family(route.destination))?;

    // TODO: Windows deletes match the concrete row. Without gateway/ifindex this keeps the
    // current Route API semantics by taking the first prefix match, which can be ambiguous.
    table
        .rows()
        .iter()
        .copied()
        .find(|row| row_matches(row, route))
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "route not found"))
}

fn row_matches(row: &MIB_IPFORWARD_ROW2, route: &Route) -> bool {
    row.DestinationPrefix.PrefixLength == route.prefix
        && sockaddr_ip(row.DestinationPrefix.Prefix) == route.destination
        && route
            .gateway
            .is_none_or(|gateway| sockaddr_ip(row.NextHop) == gateway)
        && route
            .ifindex
            .is_none_or(|ifindex| row.InterfaceIndex == ifindex)
}

fn best_route(destination: IpAddr, interface_index: u32) -> io::Result<MIB_IPFORWARD_ROW2> {
    let destination = sockaddr(destination);
    let mut best_route = MIB_IPFORWARD_ROW2::default();
    let mut best_source = SOCKADDR_INET::default();

    win32_result(unsafe {
        GetBestRoute2(
            ptr::null(),
            interface_index,
            ptr::null(),
            &destination,
            0,
            &mut best_route,
            &mut best_source,
        )
    })?;

    Ok(best_route)
}

fn resolve_interface_index(route: &Route) -> io::Result<u32> {
    if let Some(ifindex) = route.ifindex {
        return Ok(ifindex);
    }

    let target = route.gateway.unwrap_or(route.destination);
    Ok(best_route(target, 0)?.InterfaceIndex)
}

fn route_from_row(row: &MIB_IPFORWARD_ROW2) -> Route {
    let mut route = Route::new(
        sockaddr_ip(row.DestinationPrefix.Prefix),
        row.DestinationPrefix.PrefixLength,
    );
    let gateway = sockaddr_ip(row.NextHop);
    if !gateway.is_unspecified() {
        route.gateway = Some(gateway);
    }
    route.ifindex = Some(row.InterfaceIndex);

    route
}

fn sockaddr(addr: IpAddr) -> SOCKADDR_INET {
    match addr {
        IpAddr::V4(addr) => SOCKADDR_INET {
            Ipv4: SOCKADDR_IN {
                sin_family: AF_INET,
                sin_port: 0,
                sin_addr: IN_ADDR {
                    S_un: IN_ADDR_0 {
                        S_addr: u32::from_ne_bytes(addr.octets()),
                    },
                },
                sin_zero: [0; 8],
            },
        },
        IpAddr::V6(addr) => SOCKADDR_INET {
            Ipv6: SOCKADDR_IN6 {
                sin6_family: AF_INET6,
                sin6_port: 0,
                sin6_flowinfo: 0,
                sin6_addr: IN6_ADDR {
                    u: windows_sys::Win32::Networking::WinSock::IN6_ADDR_0 {
                        Byte: addr.octets(),
                    },
                },
                Anonymous: Default::default(),
            },
        },
    }
}

fn sockaddr_ip(addr: SOCKADDR_INET) -> IpAddr {
    unsafe {
        match addr.si_family {
            AF_INET => IpAddr::V4(Ipv4Addr::from(addr.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes())),
            AF_INET6 => IpAddr::V6(Ipv6Addr::from(addr.Ipv6.sin6_addr.u.Byte)),
            family => unreachable!("unsupported SOCKADDR_INET family {family}"),
        }
    }
}

fn unspecified(addr: IpAddr) -> IpAddr {
    match addr {
        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    }
}

fn address_family(addr: IpAddr) -> ADDRESS_FAMILY {
    match addr {
        IpAddr::V4(_) => AF_INET,
        IpAddr::V6(_) => AF_INET6,
    }
}

fn win32_result(code: u32) -> io::Result<()> {
    match code {
        ERROR_SUCCESS => Ok(()),
        ERROR_OBJECT_ALREADY_EXISTS => Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!("Win32 error {code}"),
        )),
        ERROR_FILE_NOT_FOUND | ERROR_NOT_FOUND => Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("Win32 error {code}"),
        )),
        _ => Err(io::Error::from_raw_os_error(code as i32)),
    }
}

struct RouteTable {
    ptr: *mut MIB_IPFORWARD_TABLE2,
}

impl RouteTable {
    fn new(family: ADDRESS_FAMILY) -> io::Result<Self> {
        let mut ptr = ptr::null_mut();
        win32_result(unsafe { GetIpForwardTable2(family, &mut ptr) })?;

        Ok(Self { ptr })
    }

    fn rows(&self) -> &[MIB_IPFORWARD_ROW2] {
        unsafe {
            let table = &*self.ptr;
            std::slice::from_raw_parts(table.Table.as_ptr(), table.NumEntries as usize)
        }
    }
}

impl Drop for RouteTable {
    fn drop(&mut self) {
        unsafe { FreeMibTable(self.ptr.cast()) };
    }
}

struct AdapterAddressTable {
    buf: Vec<u8>,
}

impl AdapterAddressTable {
    fn new() -> io::Result<Self> {
        let mut len = 15_000u32;
        loop {
            let mut buf = vec![0u8; len as usize];
            let code = unsafe {
                GetAdaptersAddresses(
                    AF_UNSPEC as u32,
                    GAA_FLAG_INCLUDE_ALL_INTERFACES,
                    ptr::null(),
                    buf.as_mut_ptr().cast(),
                    &mut len,
                )
            };
            match code {
                ERROR_SUCCESS => return Ok(Self { buf }),
                ERROR_BUFFER_OVERFLOW => continue,
                _ => return Err(io::Error::from_raw_os_error(code as i32)),
            }
        }
    }

    fn rows(&self) -> AdapterAddressRows<'_> {
        AdapterAddressRows {
            next: self.buf.as_ptr().cast(),
            _table: self,
        }
    }
}

struct AdapterAddressRows<'a> {
    next: *const IP_ADAPTER_ADDRESSES_LH,
    _table: &'a AdapterAddressTable,
}

impl<'a> Iterator for AdapterAddressRows<'a> {
    type Item = &'a IP_ADAPTER_ADDRESSES_LH;

    fn next(&mut self) -> Option<Self::Item> {
        let row = unsafe { self.next.as_ref()? };
        self.next = row.Next;
        Some(row)
    }
}

unsafe fn wide_ptr_to_string(ptr: windows_sys::core::PWSTR) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    let mut len = 0usize;
    while unsafe { *ptr.add(len) } != 0 {
        len += 1;
    }
    Some(String::from_utf16_lossy(unsafe {
        std::slice::from_raw_parts(ptr, len)
    }))
}
