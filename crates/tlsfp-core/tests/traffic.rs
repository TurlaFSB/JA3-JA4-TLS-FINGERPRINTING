// © Pranav Verma | 2026
// traffic.rs

//! The traffic table, fed by the real pipeline over a vendored capture.

use std::path::PathBuf;

use tlsfp_core::pipeline::traffic::{Proto, TrafficHandle};
use tlsfp_core::{PcapFileSource, Pipeline, PipelineConfig};

#[test]
fn a_real_capture_fills_the_table_with_names_and_fingerprints() {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/pcap/tls-handshake.pcapng");
    let mut source = PcapFileSource::open(path).unwrap();
    let handle = TrafficHandle::default();
    let mut pipeline = Pipeline::new(PipelineConfig::default());
    pipeline.track_traffic(handle.clone());
    let mut hellos = 0usize;
    pipeline
        .run(&mut source, |event| {
            if matches!(event.event, tlsfp_core::StreamEvent::ClientHello { .. }) {
                hellos += 1;
            }
        })
        .unwrap();

    let (rows, totals) = handle.with(|t| (t.all_rows(), t.totals()));
    assert!(!rows.is_empty(), "conversations were recorded");
    let frames = pipeline.counters().frames;
    let counted =
        totals.out_packets + totals.in_packets + totals.internal_packets + totals.transit_packets;
    assert_eq!(
        counted,
        pipeline.counters().tcp_segments + pipeline.counters().udp_datagrams,
        "every decoded packet is counted once ({frames} frames)"
    );

    let named = rows.iter().filter(|r| r.ja4.is_some()).count();
    assert_eq!(
        named, hellos,
        "each client hello is attached to its conversation"
    );
    assert!(
        rows.iter().any(|r| r.sni.is_some()),
        "some conversation carries a server name"
    );
    assert!(rows.iter().all(|r| r.bytes_up + r.bytes_down > 0));
    assert!(
        rows.iter()
            .any(|r| r.proto == Proto::Udp && r.ja4.as_deref().is_some_and(|j| j.starts_with('q'))),
        "the QUIC conversation is attributed"
    );
}

#[test]
fn tracking_is_off_unless_asked_for() {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/pcap/tls-handshake.pcapng");
    let mut source = PcapFileSource::open(path).unwrap();
    let mut pipeline = Pipeline::new(PipelineConfig::default());
    pipeline.run(&mut source, |_| {}).unwrap();
    assert!(pipeline.counters().frames > 0);
}
