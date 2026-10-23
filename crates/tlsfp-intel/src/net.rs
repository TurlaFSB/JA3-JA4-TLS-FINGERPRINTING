// ©AngelaMos | 2026
// net.rs

//! CIDR matching for operator-declared shared networks.
//!
//! A NAT gateway, jump host or proxy presents many unrelated clients from one
//! address, which is exactly what the rotation rule is built to find in an
//! evading client. Only the operator knows which addresses are shared, so the
//! engine takes them as configuration instead of guessing. The type is a few
//! lines of integer masking rather than a dependency.

use std::net::IpAddr;
use std::str::FromStr;

/// An IPv4 or IPv6 network in CIDR form, or a single address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Network {
    addr: IpAddr,
    prefix: u8,
}

impl Network {
    /// Whether `ip` falls inside this network. An address of the other family
    /// never matches.
    #[must_use]
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let mask = u32::MAX
                    .checked_shl(32 - u32::from(self.prefix))
                    .unwrap_or(0);
                u32::from(net) & mask == u32::from(ip) & mask
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let mask = u128::MAX
                    .checked_shl(128 - u32::from(self.prefix))
                    .unwrap_or(0);
                u128::from(net) & mask == u128::from(ip) & mask
            }
            _ => false,
        }
    }
}

impl FromStr for Network {
    type Err = String;

    /// Parses `10.0.0.0/8`, `2001:db8::/32`, or a bare address, which means a
    /// single host.
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let text = text.trim();
        let (addr_text, prefix_text) = match text.split_once('/') {
            Some((addr, prefix)) => (addr, Some(prefix)),
            None => (text, None),
        };
        let addr: IpAddr = addr_text
            .parse()
            .map_err(|_| format!("'{text}' is not an IP address or CIDR network"))?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix_text {
            None => max,
            Some(prefix) => prefix
                .parse::<u8>()
                .ok()
                .filter(|prefix| *prefix <= max)
                .ok_or_else(|| format!("'{text}' has an invalid prefix length (0 to {max})"))?,
        };
        Ok(Self { addr, prefix })
    }
}

#[cfg(test)]
mod tests {
    use super::Network;

    fn net(text: &str) -> Network {
        text.parse().unwrap()
    }

    fn ip(text: &str) -> std::net::IpAddr {
        text.parse().unwrap()
    }

    #[test]
    fn ipv4_prefix_matches_inside_and_not_outside() {
        let lan = net("192.168.1.0/24");
        assert!(lan.contains(ip("192.168.1.1")));
        assert!(lan.contains(ip("192.168.1.255")));
        assert!(!lan.contains(ip("192.168.2.1")));
        assert!(!lan.contains(ip("10.0.0.1")));
    }

    #[test]
    fn a_bare_address_is_one_host() {
        let host = net("203.0.113.7");
        assert!(host.contains(ip("203.0.113.7")));
        assert!(!host.contains(ip("203.0.113.8")));
    }

    #[test]
    fn zero_prefix_matches_every_address_of_its_family() {
        assert!(net("0.0.0.0/0").contains(ip("8.8.8.8")));
        assert!(!net("0.0.0.0/0").contains(ip("2001:db8::1")));
        assert!(net("::/0").contains(ip("2001:db8::1")));
    }

    #[test]
    fn ipv6_prefix_matches() {
        let net = net("2001:db8::/32");
        assert!(net.contains(ip("2001:db8:ffff::1")));
        assert!(!net.contains(ip("2001:db9::1")));
    }

    #[test]
    fn malformed_input_is_rejected_with_a_reason() {
        for bad in [
            "",
            "not-an-ip",
            "10.0.0.0/33",
            "10.0.0.0/-1",
            "::/129",
            "10.0.0.0/",
        ] {
            assert!(bad.parse::<Network>().is_err(), "{bad:?}");
        }
    }
}
