// © Pranav Verma | 2026
// protocols.rs

//! SSH and DNS through the whole pipeline, from Ethernet frames.

use etherparse::PacketBuilder;
use tlsfp_core::pipeline::event::StreamEvent;
use tlsfp_core::pipeline::traffic::TrafficHandle;
use tlsfp_core::{FingerprintEvent, Pipeline, PipelineConfig, RawFrame};

const CLIENT: [u8; 4] = [10, 0, 0, 5];
const SERVER: [u8; 4] = [192, 0, 2, 22];
const RESOLVER: [u8; 4] = [10, 0, 0, 1];

fn feed(pipeline: &mut Pipeline, ts: u64, data: &[u8], out: &mut Vec<FingerprintEvent>) {
    let frame = RawFrame {
        ts_nanos: ts,
        link_type: 1,
        data,
    };
    pipeline.feed(&frame, &mut |event| out.push(event));
}

fn tcp(from: ([u8; 4], u16), to: ([u8; 4], u16), seq: u32, flags: &str, payload: &[u8]) -> Vec<u8> {
    let mut builder = PacketBuilder::ethernet2([1; 6], [2; 6])
        .ipv4(from.0, to.0, 64)
        .tcp(from.1, to.1, seq, 64240);
    if flags.contains('S') {
        builder = builder.syn();
    }
    if flags.contains('A') {
        builder = builder.ack(1);
    }
    let mut out = Vec::new();
    builder.write(&mut out, payload).unwrap();
    out
}

fn udp(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    PacketBuilder::ethernet2([1; 6], [2; 6])
        .ipv4(src, dst, 64)
        .udp(sport, dport)
        .write(&mut out, payload)
        .unwrap();
    out
}

fn name_list(items: &[&str]) -> Vec<u8> {
    let joined = items.join(",");
    let mut out = u32::try_from(joined.len()).unwrap().to_be_bytes().to_vec();
    out.extend(joined.as_bytes());
    out
}

fn ssh_hello(banner: &str, kex: &str, enc: &str, mac: &str) -> Vec<u8> {
    let mut payload = vec![20u8];
    payload.extend([9u8; 16]);
    for l in [
        vec![kex],
        vec!["ssh-ed25519"],
        vec![enc],
        vec![enc],
        vec![mac],
        vec![mac],
        vec!["none"],
        vec!["none"],
        vec![],
        vec![],
    ] {
        payload.extend(name_list(&l));
    }
    payload.push(0);
    payload.extend([0u8; 4]);
    let padding = 8 - (payload.len() + 1) % 8;
    let mut body = vec![u8::try_from(padding).unwrap()];
    body.extend(&payload);
    body.extend(vec![0u8; padding]);
    let mut out = format!("{banner}\r\n").into_bytes();
    out.extend(u32::try_from(body.len()).unwrap().to_be_bytes());
    out.extend(body);
    out
}

#[test]
fn ssh_client_and_server_are_told_apart_by_who_opened_the_connection() {
    let mut pipeline = Pipeline::new(PipelineConfig::default());
    let mut events = Vec::new();
    let client_hello = ssh_hello(
        "SSH-2.0-OpenSSH_9.6",
        "curve25519-sha256",
        "aes128-ctr",
        "hmac-sha2-256",
    );
    let server_hello = ssh_hello(
        "SSH-2.0-dropbear_2022.83",
        "curve25519-sha256",
        "chacha20-poly1305@openssh.com",
        "hmac-sha2-256",
    );

    // A nonstandard port, so only the SYN can say who is the client.
    feed(
        &mut pipeline,
        1,
        &tcp((CLIENT, 50000), (SERVER, 2222), 100, "S", b""),
        &mut events,
    );
    feed(
        &mut pipeline,
        2,
        &tcp((SERVER, 2222), (CLIENT, 50000), 900, "SA", b""),
        &mut events,
    );
    feed(
        &mut pipeline,
        3,
        &tcp((SERVER, 2222), (CLIENT, 50000), 901, "A", &server_hello),
        &mut events,
    );
    feed(
        &mut pipeline,
        4,
        &tcp((CLIENT, 50000), (SERVER, 2222), 101, "A", &client_hello),
        &mut events,
    );

    let hellos: Vec<_> = events
        .iter()
        .filter_map(|e| match &e.event {
            StreamEvent::Ssh(h) => Some((e.src.port(), h)),
            _ => None,
        })
        .collect();
    assert_eq!(hellos.len(), 2, "{events:?}");
    let (_, server) = hellos.iter().find(|(port, _)| *port == 2222).unwrap();
    let (_, client) = hellos.iter().find(|(port, _)| *port == 50000).unwrap();
    assert_eq!(client.banner, "SSH-2.0-OpenSSH_9.6");
    assert!(client.hassh.is_some() && client.hassh_server.is_none());
    assert!(server.hassh_server.is_some() && server.hassh.is_none());
    assert_eq!(pipeline.counters().ssh_hellos, 2);
}

#[test]
fn a_dns_response_names_the_server_of_a_later_connection() {
    let traffic = TrafficHandle::default();
    let mut pipeline = Pipeline::new(PipelineConfig::default());
    pipeline.track_traffic(traffic.clone());
    let mut events = Vec::new();

    let mut query = vec![0xAB, 0xCD, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    let question = b"\x07example\x03org\x00\x00\x01\x00\x01";
    query.extend(question);
    let mut response = vec![0xAB, 0xCD, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
    response.extend(question);
    response.extend([0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 192, 0, 2, 22]);

    feed(
        &mut pipeline,
        1,
        &udp(CLIENT, RESOLVER, 40000, 53, &query),
        &mut events,
    );
    feed(
        &mut pipeline,
        2,
        &udp(RESOLVER, CLIENT, 53, 40000, &response),
        &mut events,
    );
    // A TCP connection to the answered address that carries no name of its own.
    feed(
        &mut pipeline,
        3,
        &tcp((CLIENT, 50001), (SERVER, 8443), 5, "S", b""),
        &mut events,
    );

    let dns: Vec<_> = events
        .iter()
        .filter_map(|e| match &e.event {
            StreamEvent::Dns(m) => Some(m),
            _ => None,
        })
        .collect();
    assert_eq!(dns.len(), 2);
    assert!(!dns[0].response && dns[0].name == "example.org");
    assert!(dns[1].response && dns[1].answers[0].data == "192.0.2.22");

    let rows = traffic.with(|t| t.all_rows());
    let row = rows
        .iter()
        .find(|r| r.server.port() == 8443)
        .expect("the TCP conversation");
    assert_eq!(row.dns_name.as_deref(), Some("example.org"));
    assert_eq!(pipeline.counters().dns_messages, 2);
}

#[test]
fn port_53_noise_is_counted_not_fatal() {
    let mut pipeline = Pipeline::new(PipelineConfig::default());
    let mut events = Vec::new();
    feed(
        &mut pipeline,
        1,
        &udp(CLIENT, RESOLVER, 40000, 53, b"not dns at all"),
        &mut events,
    );
    assert!(events.is_empty());
    assert_eq!(pipeline.counters().dns_unparsed, 1);
}
