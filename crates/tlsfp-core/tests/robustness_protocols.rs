// © Pranav Verma | 2026
// robustness_protocols.rs

//! The arbitrary-input contract for the DNS and SSH readers.
//!
//! The claim is the project's usual one: hostile bytes yield `None`, an error or
//! a counted drop, never a panic, and what is returned stays within its stated
//! bounds. Random bytes rarely get past the first length check, so each group
//! also mutates and truncates a well-formed message, which is what reaches the
//! deep branches (compression pointers, name lists, padding arithmetic).

use proptest::prelude::*;
use tlsfp_core::dns::{self, MAX_ANSWERS};
use tlsfp_core::ssh::{self, Ssh};
use tlsfp_core::{Pipeline, PipelineConfig, RawFrame};

fn question(name: &str, qtype: u16) -> Vec<u8> {
    let mut out = Vec::new();
    for label in name.split('.') {
        out.push(u8::try_from(label.len()).unwrap_or(0));
        out.extend(label.as_bytes());
    }
    out.push(0);
    out.extend(qtype.to_be_bytes());
    out.extend(1u16.to_be_bytes());
    out
}

fn valid_response() -> Vec<u8> {
    let mut m = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, 3, 0, 0, 0, 0];
    m.extend(question("www.example.com", 1));
    m.extend([0xC0, 0x0C, 0, 5, 0, 1, 0, 0, 0, 60, 0, 2, 0xC0, 0x10]);
    m.extend([0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 1, 44, 0, 4, 93, 184, 216, 34]);
    m.extend([0xC0, 0x0C, 0, 28, 0, 1, 0, 0, 0, 60, 0, 16]);
    m.extend([0x20, 0x01, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    m
}

fn valid_ssh() -> Vec<u8> {
    let mut payload = vec![20u8];
    payload.extend([1u8; 16]);
    for list in [
        "curve25519-sha256",
        "ssh-ed25519",
        "aes128-ctr",
        "aes128-ctr",
        "hmac-sha2-256",
        "hmac-sha2-256",
        "none",
        "none",
        "",
        "",
    ] {
        payload.extend(u32::try_from(list.len()).unwrap().to_be_bytes());
        payload.extend(list.as_bytes());
    }
    payload.push(0);
    payload.extend([0u8; 4]);
    let padding = 8 - (payload.len() + 1) % 8;
    let mut body = vec![u8::try_from(padding).unwrap()];
    body.extend(&payload);
    body.extend(vec![0u8; padding]);
    let mut out = b"SSH-2.0-OpenSSH_9.6\r\n".to_vec();
    out.extend(u32::try_from(body.len()).unwrap().to_be_bytes());
    out.extend(body);
    out
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2_000))]

    #[test]
    fn dns_never_panics_on_arbitrary_bytes(bytes in proptest::collection::vec(any::<u8>(), 0..600)) {
        let _ = dns::parse(&bytes);
    }

    #[test]
    fn dns_survives_mutation_and_stays_bounded(
        flips in proptest::collection::vec((0usize..200, any::<u8>()), 0..12),
        cut in 0usize..200,
    ) {
        let mut message = valid_response();
        for (at, value) in flips {
            if let Some(byte) = message.get_mut(at) {
                *byte = value;
            }
        }
        message.truncate(message.len().saturating_sub(cut % 40));
        if let Some(parsed) = dns::parse(&message) {
            prop_assert!(parsed.name.len() <= 255 * 4, "name stays bounded after escaping");
            prop_assert!(parsed.answers.len() <= MAX_ANSWERS);
        }
    }

    #[test]
    fn a_reverse_name_never_panics_and_round_trips_for_any_ipv4(
        text in ".{0,120}",
        octets in any::<[u8; 4]>(),
    ) {
        let _ = dns::reverse_to_address(&text);
        let [a, b, c, d] = octets;
        let name = format!("{d}.{c}.{b}.{a}.in-addr.arpa");
        let expected = std::net::Ipv4Addr::from(octets).to_string();
        prop_assert_eq!(dns::reverse_to_address(&name), Some(expected));
    }

    #[test]
    fn a_reverse_name_round_trips_for_any_ipv6(octets in any::<[u8; 16]>()) {
        let nibbles: Vec<String> = octets
            .iter()
            .rev()
            .flat_map(|byte| [format!("{:x}", byte & 0x0f), format!("{:x}", byte >> 4)])
            .collect();
        let name = format!("{}.ip6.arpa", nibbles.join("."));
        prop_assert_eq!(
            dns::reverse_to_address(&name),
            Some(std::net::Ipv6Addr::from(octets).to_string())
        );
    }

    #[test]
    fn ssh_never_panics_on_arbitrary_bytes(bytes in proptest::collection::vec(any::<u8>(), 0..400)) {
        let _ = ssh::parse(&bytes);
    }

    #[test]
    fn ssh_survives_mutation_and_a_prefix_is_never_a_hello(
        flips in proptest::collection::vec((0usize..160, any::<u8>()), 0..10),
        keep in 0usize..200,
    ) {
        let mut message = valid_ssh();
        let whole = message.len();
        for (at, value) in flips.iter().copied() {
            if let Some(byte) = message.get_mut(at) {
                *byte = value;
            }
        }
        let _ = ssh::parse(&message);
        // A strict prefix of an unmodified message waits for more bytes.
        let original = valid_ssh();
        let prefix = &original[..keep.min(whole.saturating_sub(1))];
        prop_assert!(!matches!(ssh::parse(prefix), Ssh::Hello(_)));
    }

    #[test]
    fn port_53_datagrams_of_any_content_never_crash_the_pipeline(
        payload in proptest::collection::vec(any::<u8>(), 0..300),
    ) {
        let mut frame = Vec::new();
        etherparse::PacketBuilder::ethernet2([1; 6], [2; 6])
            .ipv4([10, 0, 0, 5], [10, 0, 0, 1], 64)
            .udp(40000, 53)
            .write(&mut frame, &payload)
            .unwrap();
        let mut pipeline = Pipeline::new(PipelineConfig::default());
        pipeline.feed(
            &RawFrame { ts_nanos: 1, link_type: 1, data: &frame },
            &mut |_| {},
        );
        let counters = pipeline.counters();
        prop_assert_eq!(counters.dns_messages + counters.dns_unparsed, 1);
    }
}
