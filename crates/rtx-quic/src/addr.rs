//! Address conversions at the adapter boundary.
//!
//! `rtx-core` owns the portable address model (`ARCHITECTURE.md` §9);
//! `quinn-proto` uses `std::net::SocketAddr`. The conversion happens here and
//! nowhere else.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr as StdSocketAddr, SocketAddrV4, SocketAddrV6};

use rtx_core::{IpAddr, SocketAddr};

pub(crate) fn to_std_addr(addr: SocketAddr) -> StdSocketAddr {
    match addr.ip {
        IpAddr::V4(octets) => {
            StdSocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(octets), addr.port))
        }
        IpAddr::V6(octets) => {
            StdSocketAddr::V6(SocketAddrV6::new(Ipv6Addr::from(octets), addr.port, 0, 0))
        }
    }
}

pub(crate) fn from_std_addr(addr: StdSocketAddr) -> SocketAddr {
    match addr {
        StdSocketAddr::V4(v4) => SocketAddr::new(IpAddr::V4(v4.ip().octets()), v4.port()),
        StdSocketAddr::V6(v6) => SocketAddr::new(IpAddr::V6(v6.ip().octets()), v6.port()),
    }
}

pub(crate) fn to_std_ip(ip: IpAddr) -> std::net::IpAddr {
    match ip {
        IpAddr::V4(octets) => std::net::IpAddr::V4(Ipv4Addr::from(octets)),
        IpAddr::V6(octets) => std::net::IpAddr::V6(Ipv6Addr::from(octets)),
    }
}
