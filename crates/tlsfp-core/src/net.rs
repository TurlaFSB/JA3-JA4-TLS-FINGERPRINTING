// © Pranav Verma | 2026
// net.rs

//! CIDR matching, for the networks an operator declares and the ones a capture
//! interface sits on.
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
    /// A network from an address and a prefix length, or `None` when the
    /// prefix is longer than the address family allows.
    #[must_use]
    pub fn new(addr: IpAddr, prefix: u8) -> Option<Self> {
        let max = if addr.is_ipv4() { 32 } else { 128 };
        (prefix <= max).then_some(Self { addr, prefix })
    }

    /// The network an interface address sits on, from its netmask. A mask of
    /// the other family, or one that is not a run of ones, gives `None`.
    #[must_use]
    pub fn from_mask(addr: IpAddr, mask: IpAddr) -> Option<Self> {
        let (bits, width) = match (addr, mask) {
            (IpAddr::V4(_), IpAddr::V4(mask)) => (u128::from(u32::from(mask)), 32_u32),
            (IpAddr::V6(_), IpAddr::V6(mask)) => (u128::from(mask), 128_u32),
            _ => return None,
        };
        let ones = (bits << (128 - width)).leading_ones();
        // A valid mask is all ones then all zeros: shifting back must agree.
        let rebuilt = if ones == 0 {
            0
        } else {
            u128::MAX << (128 - ones)
        };
        (bits << (128 - width) == rebuilt)
            .then(|| Self::new(addr, u8::try_from(ones).ok()?))
            .flatten()
    }

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

impl std::fmt::Display for Network {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
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

    #[test]
    fn a_netmask_becomes_a_prefix() {
        let lan = Network::from_mask(ip("192.168.1.10"), ip("255.255.255.0")).unwrap();
        assert!(lan.contains(ip("192.168.1.99")));
        assert!(!lan.contains(ip("192.168.2.1")));
        let v6 =
            Network::from_mask(ip("2409:40f4:40d1:a0f6::5"), ip("ffff:ffff:ffff:ffff::")).unwrap();
        assert!(v6.contains(ip("2409:40f4:40d1:a0f6:1:2:3:4")));
        assert!(!v6.contains(ip("2409:40f4:40d1:a0f7::1")));
        assert!(Network::from_mask(ip("10.0.0.1"), ip("255.0.255.0")).is_none());
        assert!(Network::from_mask(ip("10.0.0.1"), ip("ffff::")).is_none());
    }

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
