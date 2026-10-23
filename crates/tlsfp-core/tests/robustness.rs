// © Pranav Verma | 2026
// robustness.rs

//! Arbitrary-input contract for the parsers that face attacker-controlled bytes.
//!
//! The TLS hello parser, the stream reassembler, and the JA4X certificate walk
//! each have their own property tests next to their unit tests. This file covers
//! the remaining entry points a passive sensor exposes to the network: the QUIC
//! Initial header, frame walk, and CRYPTO assembler, the cleartext HTTP request
//! reader behind JA4H, the SSLv2 hello, the certificate list, and the whole
//! pipeline fed raw frames under each link type it accepts. Random bytes seldom
//! get past the first length check, so every group also mutates a well-formed
//! input, which is what actually reaches the deep branches.
//!
//! The only claim is the one the project makes for itself: hostile bytes yield
//! an error or a counted drop, never a panic, and memory use stays bounded.

mod common;

use common::ClientHelloBuilder;
use std::fmt::Write as _;

use proptest::prelude::*;
use tlsfp_core::parse::{
    certificate_der_list, handshake_bytes, is_sslv2_client_hello, parse_sslv2_client_hello,
};
use tlsfp_core::quic::{CryptoAssembler, InitialPacket, walk_crypto_frames};
use tlsfp_core::{Pipeline, PipelineConfig, RawFrame, ja4h, parse_http_request};

const ETHERNET: i32 = 1;
const RAW_IP: i32 = 101;
const LINUX_SLL: i32 = 113;

fn bytes(max: usize) -> impl Strategy<Value = Vec<u8>> {
    proptest::collection::vec(any::<u8>(), 0..max)
}

/// A valid ClientHello record with a few random byte flips applied.
fn mutated_client_hello() -> impl Strategy<Value = Vec<u8>> {
    let record = ClientHelloBuilder::new()
        .ciphers(&[0x1301, 0x1302, 0xc02b])
        .sni("example.com")
        .supported_groups(&[0x001d, 0x0017])
        .alpn(&[b"h2", b"http/1.1"])
        .supported_versions(&[0x0304, 0x0303])
        .build_record();
    let len = record.len();
    proptest::collection::vec((0..len, any::<u8>()), 0..8).prop_map(move |flips| {
        let mut out = record.clone();
        for (at, value) in flips {
            out[at] = value;
        }
        out
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2048))]

    #[test]
    fn quic_initial_parse_and_open_never_panic(data in bytes(1500), start in 0usize..64) {
        if let Ok(packet) = InitialPacket::parse(&data, start) {
            let keys = packet.client_keys();
            let _ = packet.open(&keys, None);
            let _ = packet.open(&keys, Some(u64::MAX));
        }
    }

    #[test]
    fn quic_initial_with_long_header_prefix_never_panics(tail in bytes(1400)) {
        // Long header, Initial type, QUIC v1: forces the parser past the cheap rejects.
        let mut datagram = vec![0xc3, 0x00, 0x00, 0x00, 0x01];
        datagram.extend_from_slice(&tail);
        if let Ok(packet) = InitialPacket::parse(&datagram, 0) {
            let keys = packet.client_keys();
            let _ = packet.open(&keys, None);
        }
    }

    #[test]
    fn quic_frame_walk_never_panics(frames in bytes(2048)) {
        let mut seen = 0usize;
        let _ = walk_crypto_frames(&frames, |_, data| seen += data.len());
        prop_assert!(seen <= frames.len());
    }

    #[test]
    fn crypto_assembler_stays_bounded_under_arbitrary_pushes(
        pushes in proptest::collection::vec((any::<u64>(), bytes(300)), 0..64),
    ) {
        let mut assembler = CryptoAssembler::new(4096);
        for (offset, data) in &pushes {
            assembler.push(*offset, data);
        }
        prop_assert!(assembler.data().len() <= 4096);
        let _ = assembler.client_hello();
    }

    #[test]
    fn http_request_reader_never_panics(data in bytes(2048)) {
        if let Some(request) = parse_http_request(&data) {
            let _ = ja4h(&request);
        }
    }

    #[test]
    fn http_request_reader_never_panics_on_request_like_text(
        method in "[A-Z]{0,8}",
        path in "[ -~]{0,64}",
        headers in proptest::collection::vec(("[A-Za-z-]{0,16}", "[ -~]{0,64}"), 0..16),
    ) {
        let mut text = format!("{method} {path} HTTP/1.1\r\n");
        for (name, value) in &headers {
            let _ = write!(text, "{name}: {value}\r\n");
        }
        text.push_str("\r\n");
        if let Some(request) = parse_http_request(text.as_bytes()) {
            let _ = ja4h(&request);
        }
    }

    #[test]
    fn sslv2_hello_never_panics(data in bytes(512)) {
        if is_sslv2_client_hello(&data) {
            let _ = parse_sslv2_client_hello(&data);
        }
        let mut forced = vec![0x80, 0x2e, 0x01, 0x00, 0x02];
        forced.extend_from_slice(&data);
        let _ = parse_sslv2_client_hello(&forced);
    }

    #[test]
    fn certificate_list_never_panics(body in bytes(1024)) {
        let _ = certificate_der_list(&body);
    }

    #[test]
    fn mutated_client_hello_record_never_panics(record in mutated_client_hello()) {
        if let Ok(handshake) = handshake_bytes(&record) {
            let _ = tlsfp_core::parse::first_handshake_message(&handshake, 1)
                .and_then(tlsfp_core::parse::parse_client_hello);
        }
    }

    #[test]
    fn pipeline_survives_arbitrary_frames_on_every_link_type(
        frames in proptest::collection::vec((bytes(256), 0usize..3), 0..32),
    ) {
        let mut pipeline = Pipeline::new(PipelineConfig::default());
        let mut sink = |_| {};
        for (data, link) in &frames {
            let link_type = [ETHERNET, RAW_IP, LINUX_SLL][*link];
            pipeline.feed(&RawFrame { ts_nanos: 0, link_type, data }, &mut sink);
        }
        pipeline.finish();
        prop_assert_eq!(pipeline.counters().frames, frames.len() as u64);
    }

    #[test]
    fn pipeline_survives_ipv4_tcp_headers_with_hostile_payloads(
        payload in bytes(512),
        flags in any::<u8>(),
        seq in any::<u32>(),
        options in proptest::collection::vec(any::<u8>(), 0..40),
    ) {
        let mut frame = Vec::new();
        frame.extend_from_slice(&[0u8; 12]);
        frame.extend_from_slice(&[0x08, 0x00]);
        let tcp_len = 20 + (options.len() & !3);
        let total = 20 + tcp_len + payload.len();
        frame.extend_from_slice(&[0x45, 0x00]);
        frame.extend_from_slice(&u16::try_from(total).unwrap_or(u16::MAX).to_be_bytes());
        frame.extend_from_slice(&[0, 0, 0, 0, 64, 6, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2]);
        frame.extend_from_slice(&[0xc0, 0x00, 0x01, 0xbb]);
        frame.extend_from_slice(&seq.to_be_bytes());
        frame.extend_from_slice(&[0, 0, 0, 0]);
        frame.push(u8::try_from(tcp_len / 4).unwrap_or(15) << 4);
        frame.push(flags);
        frame.extend_from_slice(&[0xff, 0xff, 0, 0, 0, 0]);
        frame.extend_from_slice(&options[..options.len() & !3]);
        frame.extend_from_slice(&payload);
        let mut pipeline = Pipeline::new(PipelineConfig::default());
        let mut sink = |_| {};
        pipeline.feed(&RawFrame { ts_nanos: 0, link_type: ETHERNET, data: &frame }, &mut sink);
        pipeline.finish();
    }
}
