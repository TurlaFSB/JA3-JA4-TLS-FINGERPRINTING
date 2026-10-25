// © Pranav Verma | 2026
// dns.rs

//! Passive DNS: the question and answers of a plain UDP DNS message.
//!
//! DNS is the one place a name and an address meet before a connection starts,
//! so reading it lets the sensor name a server even when the TLS handshake
//! hides its name (Encrypted Client Hello) or the connection is not TLS at all.
//! It sees only cleartext DNS on UDP port 53. DNS over HTTPS or TLS is
//! encrypted and invisible here, and a resolver on the same machine over a
//! loopback address is seen only if the capture includes loopback.
//!
//! The parser treats the datagram as hostile: every read is bounds checked,
//! compression pointers may jump only a few times, names are capped, and
//! at most [`MAX_ANSWERS`] records are read.

use std::fmt::Write as _;
use std::net::{Ipv4Addr, Ipv6Addr};

use serde::Serialize;

/// Most answer records read from one message.
pub const MAX_ANSWERS: usize = 32;

/// Longest name accepted, per RFC 1035.
const MAX_NAME_LEN: usize = 255;

/// Compression pointers followed per name before the name is rejected.
const MAX_POINTER_JUMPS: usize = 8;

const HEADER_LEN: usize = 12;

/// One answer record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DnsAnswer {
    /// Record type: `A`, `AAAA`, `CNAME` or `TYPEnnn` for anything else.
    pub rtype: String,
    /// Address or target name; empty for a type this build does not decode.
    pub data: String,
    pub ttl: u32,
}

/// A parsed DNS message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DnsMessage {
    pub id: u16,
    /// True for a response, false for a query.
    pub response: bool,
    /// The name asked about, lower case, without a trailing dot.
    pub name: String,
    /// The type asked about, as [`DnsAnswer::rtype`].
    pub qtype: String,
    /// Response code (`NOERROR`, `NXDOMAIN`, `SERVFAIL`, ...); empty for a query.
    pub rcode: String,
    pub answers: Vec<DnsAnswer>,
    /// For a reverse lookup (a name under `in-addr.arpa` or `ip6.arpa`), the
    /// address it asks about, so a person reads an address, not 64 nibbles.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reverse_of: Option<String>,
}

/// Turns a reverse-lookup name back into the address it asks about:
/// `34.216.184.93.in-addr.arpa` is 93.184.216.34, and a 32-nibble `ip6.arpa`
/// name is the IPv6 address. Anything else (or a malformed name) is `None`.
#[must_use]
pub fn reverse_to_address(name: &str) -> Option<String> {
    let lower = name.to_ascii_lowercase();
    if let Some(rest) = lower.strip_suffix(".in-addr.arpa") {
        let octets: Vec<u8> = rest
            .split('.')
            .map(str::parse)
            .collect::<Result<_, _>>()
            .ok()?;
        let octets: [u8; 4] = octets.try_into().ok()?;
        let [d, c, b, a] = octets;
        return Some(Ipv4Addr::new(a, b, c, d).to_string());
    }
    let rest = lower.strip_suffix(".ip6.arpa")?;
    let nibbles: Vec<u8> = rest
        .split('.')
        .map(|n| {
            let mut chars = n.chars();
            match (chars.next(), chars.next()) {
                (Some(c), None) => c.to_digit(16).and_then(|d| u8::try_from(d).ok()),
                _ => None,
            }
        })
        .collect::<Option<_>>()?;
    if nibbles.len() != 32 {
        return None;
    }
    // The name lists the address's last nibble first.
    let mut bytes = [0u8; 16];
    for (i, byte) in bytes.iter_mut().enumerate() {
        let high = nibbles[31 - 2 * i];
        let low = nibbles[30 - 2 * i];
        *byte = (high << 4) | low;
    }
    Some(Ipv6Addr::from(bytes).to_string())
}

#[must_use]
pub fn type_name(code: u16) -> String {
    match code {
        1 => "A".to_owned(),
        2 => "NS".to_owned(),
        5 => "CNAME".to_owned(),
        6 => "SOA".to_owned(),
        12 => "PTR".to_owned(),
        15 => "MX".to_owned(),
        16 => "TXT".to_owned(),
        28 => "AAAA".to_owned(),
        33 => "SRV".to_owned(),
        64 => "SVCB".to_owned(),
        65 => "HTTPS".to_owned(),
        255 => "ANY".to_owned(),
        other => format!("TYPE{other}"),
    }
}

fn rcode_name(code: u8) -> String {
    match code {
        0 => "NOERROR".to_owned(),
        1 => "FORMERR".to_owned(),
        2 => "SERVFAIL".to_owned(),
        3 => "NXDOMAIN".to_owned(),
        4 => "NOTIMP".to_owned(),
        5 => "REFUSED".to_owned(),
        other => format!("RCODE{other}"),
    }
}

/// Reads a possibly compressed name starting at `start`, returning it and the
/// offset just past the name in the original position (not past a pointer's
/// target).
fn read_name(msg: &[u8], start: usize) -> Option<(String, usize)> {
    let mut out = String::new();
    let mut pos = start;
    let mut resume: Option<usize> = None;
    let mut jumps = 0usize;
    loop {
        let len = usize::from(*msg.get(pos)?);
        if len == 0 {
            let end = resume.unwrap_or(pos + 1);
            return Some((out.to_ascii_lowercase(), end));
        }
        match len & 0xC0 {
            0xC0 => {
                let low = usize::from(*msg.get(pos + 1)?);
                let target = ((len & 0x3F) << 8) | low;
                resume.get_or_insert(pos + 2);
                jumps += 1;
                if jumps > MAX_POINTER_JUMPS || target >= msg.len() {
                    return None;
                }
                pos = target;
            }
            0x00 => {
                let label = msg.get(pos + 1..pos + 1 + len)?;
                if !out.is_empty() {
                    out.push('.');
                }
                for &b in label {
                    // Names are shown to people; keep the printable ones and
                    // escape the rest so a hostile label cannot inject text.
                    if b.is_ascii_graphic() && b != b'\\' {
                        out.push(char::from(b));
                    } else {
                        let _ = write!(out, "\\x{b:02x}");
                    }
                }
                if out.len() > MAX_NAME_LEN {
                    return None;
                }
                pos += 1 + len;
            }
            _ => return None,
        }
    }
}

fn be16(msg: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*msg.get(at)?, *msg.get(at + 1)?]))
}

fn be32(msg: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes([
        *msg.get(at)?,
        *msg.get(at + 1)?,
        *msg.get(at + 2)?,
        *msg.get(at + 3)?,
    ]))
}

/// Parses one DNS message. Returns `None` for anything that is not a
/// well-formed standard query or response with exactly the shape this reads:
/// at least one question, opcode 0.
#[must_use]
pub fn parse(msg: &[u8]) -> Option<DnsMessage> {
    if msg.len() < HEADER_LEN {
        return None;
    }
    let id = be16(msg, 0)?;
    let flags = be16(msg, 2)?;
    let response = flags & 0x8000 != 0;
    let opcode = (flags >> 11) & 0x0F;
    if opcode != 0 {
        return None;
    }
    let questions = be16(msg, 4)?;
    let answers = usize::from(be16(msg, 6)?);
    if questions == 0 || questions > 8 {
        return None;
    }

    let (name, mut pos) = read_name(msg, HEADER_LEN)?;
    let qtype = be16(msg, pos)?;
    pos += 4;
    // Further questions are rare and add nothing here; step over them.
    for _ in 1..questions {
        let (_, next) = read_name(msg, pos)?;
        pos = next + 4;
    }
    if name.is_empty() {
        return None;
    }

    let mut records = Vec::new();
    if response {
        for _ in 0..answers.min(MAX_ANSWERS) {
            let Some((_, after_name)) = read_name(msg, pos) else {
                break;
            };
            let (Some(rtype), Some(ttl), Some(rdlen)) = (
                be16(msg, after_name),
                be32(msg, after_name + 4),
                be16(msg, after_name + 8),
            ) else {
                break;
            };
            let rdata = after_name + 10;
            let rdlen = usize::from(rdlen);
            let Some(bytes) = msg.get(rdata..rdata + rdlen) else {
                break;
            };
            let data = match (rtype, bytes.len()) {
                (1, 4) => Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]).to_string(),
                (28, 16) => {
                    let mut octets = [0u8; 16];
                    octets.copy_from_slice(bytes);
                    Ipv6Addr::from(octets).to_string()
                }
                (5 | 12, _) => read_name(msg, rdata).map(|(n, _)| n).unwrap_or_default(),
                _ => String::new(),
            };
            records.push(DnsAnswer {
                rtype: type_name(rtype),
                data,
                ttl,
            });
            pos = rdata + rdlen;
        }
    }

    let reverse_of = reverse_to_address(&name);
    Some(DnsMessage {
        id,
        response,
        name,
        qtype: type_name(qtype),
        rcode: if response {
            rcode_name(u8::try_from(flags & 0x000F).unwrap_or(0))
        } else {
            String::new()
        },
        answers: records,
        reverse_of,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn question(name: &str, qtype: u16) -> Vec<u8> {
        let mut out = Vec::new();
        for label in name.split('.') {
            out.push(u8::try_from(label.len()).unwrap());
            out.extend(label.as_bytes());
        }
        out.push(0);
        out.extend(qtype.to_be_bytes());
        out.extend(1u16.to_be_bytes());
        out
    }

    fn query(name: &str, qtype: u16) -> Vec<u8> {
        let mut m = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        m.extend(question(name, qtype));
        m
    }

    #[test]
    fn a_query_names_what_was_asked() {
        let parsed = parse(&query("Example.COM", 1)).unwrap();
        assert!(!parsed.response);
        assert_eq!(parsed.name, "example.com");
        assert_eq!(parsed.qtype, "A");
        assert_eq!(parsed.id, 0x1234);
        assert_eq!(parsed.answers, Vec::new());
    }

    #[test]
    fn a_response_yields_addresses_through_a_cname_with_compression() {
        let mut m = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, 2, 0, 0, 0, 0];
        m.extend(question("www.example.com", 1));
        // CNAME www.example.com -> edge.example.net (pointer to the question name)
        m.extend([0xC0, 0x0C, 0, 5, 0, 1, 0, 0, 0, 60]);
        let target = [
            4, b'e', b'd', b'g', b'e', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'n', b'e',
            b't', 0,
        ];
        m.extend(u16::try_from(target.len()).unwrap().to_be_bytes());
        m.extend(target);
        // A record owned by the CNAME target would normally be named by pointer; a
        // pointer back to the question name is enough to exercise compression.
        m.extend([0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 1, 44, 0, 4, 93, 184, 216, 34]);
        let parsed = parse(&m).unwrap();
        assert!(parsed.response);
        assert_eq!(parsed.rcode, "NOERROR");
        assert_eq!(parsed.answers[0].rtype, "CNAME");
        assert_eq!(parsed.answers[0].data, "edge.example.net");
        assert_eq!(parsed.answers[1].data, "93.184.216.34");
        assert_eq!(parsed.answers[1].ttl, 300);
    }

    #[test]
    fn an_nxdomain_is_reported() {
        let mut m = vec![0, 1, 0x81, 0x83, 0, 1, 0, 0, 0, 0, 0, 0];
        m.extend(question("nope.invalid", 28));
        let parsed = parse(&m).unwrap();
        assert_eq!(parsed.rcode, "NXDOMAIN");
        assert_eq!(parsed.qtype, "AAAA");
    }

    #[test]
    fn a_pointer_loop_is_rejected_not_followed_forever() {
        let mut m = vec![0, 1, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        m.extend([0xC0, 0x0C, 0, 1, 0, 1]);
        assert_eq!(parse(&m), None);
    }

    #[test]
    fn truncation_and_nonsense_are_not_panics() {
        let full = query("example.com", 1);
        for cut in 0..full.len() {
            let _ = parse(&full[..cut]);
        }
        assert_eq!(parse(&[]), None);
        assert_eq!(parse(&[0xFF; 40]), None);
    }

    #[test]
    fn hostile_label_bytes_are_escaped() {
        let mut m = vec![0, 1, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        m.extend([3, b'a', 0x07, b'<', 0, 0, 1, 0, 1]);
        let parsed = parse(&m).unwrap();
        assert_eq!(parsed.name, "a\\x07<");
    }
}

#[cfg(test)]
mod reverse_tests {
    use super::*;

    #[test]
    fn an_ipv4_reverse_name_is_read_back_as_the_address() {
        assert_eq!(
            reverse_to_address("34.216.184.93.in-addr.arpa").as_deref(),
            Some("93.184.216.34")
        );
        assert_eq!(reverse_to_address("1.2.3.in-addr.arpa"), None);
        assert_eq!(reverse_to_address("300.1.1.1.in-addr.arpa"), None);
    }

    #[test]
    fn an_ipv6_reverse_name_is_read_back_as_the_address() {
        // 2001:db8::1
        let name = "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa";
        assert_eq!(reverse_to_address(name).as_deref(), Some("2001:db8::1"));
        assert_eq!(reverse_to_address("1.0.ip6.arpa"), None);
        assert_eq!(reverse_to_address("example.com"), None);
    }

    #[test]
    fn a_ptr_answer_carries_the_host_name() {
        let mut m = vec![0, 1, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
        m.extend(b"\x0234\x03216\x03184\x0293\x07in-addr\x04arpa\x00\x00\x0c\x00\x01");
        m.extend([0xC0, 0x0C, 0, 12, 0, 1, 0, 0, 0, 60]);
        let target = b"\x03www\x07example\x03com\x00";
        m.extend(u16::try_from(target.len()).unwrap().to_be_bytes());
        m.extend(target);
        let parsed = parse(&m).unwrap();
        assert_eq!(parsed.reverse_of.as_deref(), Some("93.184.216.34"));
        assert_eq!(parsed.answers[0].rtype, "PTR");
        assert_eq!(parsed.answers[0].data, "www.example.com");
    }
}
