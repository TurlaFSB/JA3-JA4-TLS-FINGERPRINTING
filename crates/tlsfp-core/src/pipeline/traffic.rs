// © Pranav Verma | 2026
// traffic.rs

//! Per-connection accounting: who talked to whom, how much, and which way.
//!
//! The fingerprint pipeline throws away everything but handshakes. This table
//! keeps the other half of the picture a person watching a link wants: every
//! TCP and UDP conversation with packet and byte counts in each direction,
//! when it started and last spoke, whether it ended, and the server name and
//! client fingerprint the handshake carried. It is bounded, and it counts what
//! it sheds. It records bytes the capture saw on the wire (frame lengths), not
//! payload.
//!
//! "Local" means a private, loopback, link-local or unique-local address. That
//! is a heuristic, stated as one: a sensor on a public segment will call
//! everything remote.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};

use crate::net::Network;
use std::sync::{Arc, Mutex, PoisonError};

use serde::Serialize;

/// The most conversations kept at once.
pub const DEFAULT_MAX_FLOWS: usize = 20_000;

/// A conversation with no packet for this long (capture time) is idle.
const IDLE_NANOS: u64 = 120 * 1_000_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Proto {
    Tcp,
    Udp,
}

/// Which way a conversation crosses the boundary of the local networks, judged
/// by who opened it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    /// A local host opened it to a remote one.
    Outbound,
    /// A remote host opened it to a local one.
    Inbound,
    /// Both ends are local.
    Internal,
    /// Neither end is local: traffic passing through.
    Transit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowState {
    Open,
    Closed,
    Reset,
}

/// Whether an address is in a range that is private by definition: RFC 1918,
/// loopback, link-local and IPv6 unique-local. A sensor can also be told its
/// own networks (see [`TrafficTable::set_local_networks`]), which is what makes
/// a host with a public address count as local.
#[must_use]
pub fn is_local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private() || v4.is_loopback() || v4.is_link_local(),
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || (v6.segments()[0] & 0xfe00) == 0xfc00 // unique local fc00::/7
                || (v6.segments()[0] & 0xffc0) == 0xfe80 // link local fe80::/10
        }
    }
}

/// A name for the service on a well-known port, or `None`.
#[must_use]
pub fn service_name(proto: Proto, port: u16) -> Option<&'static str> {
    Some(match (proto, port) {
        (Proto::Tcp, 443) => "https",
        (Proto::Udp, 443) => "quic",
        (Proto::Tcp, 80) => "http",
        (_, 53) => "dns",
        (Proto::Tcp, 853) => "dns-over-tls",
        (Proto::Tcp, 22) => "ssh",
        (Proto::Tcp, 25 | 465 | 587) => "smtp",
        (Proto::Tcp, 993) => "imaps",
        (Proto::Tcp, 143) => "imap",
        (Proto::Tcp, 110 | 995) => "pop3",
        (Proto::Tcp, 445) => "smb",
        (Proto::Tcp, 3389) => "rdp",
        (Proto::Tcp, 8080 | 8000 | 8008) => "http-alt",
        (Proto::Tcp, 8443) => "https-alt",
        (Proto::Udp, 123) => "ntp",
        (Proto::Udp, 5353) => "mdns",
        (Proto::Udp, 1900) => "ssdp",
        (Proto::Udp, 67 | 68) => "dhcp",
        (Proto::Udp, 137 | 138) => "netbios",
        (Proto::Udp, 51820) => "wireguard",
        _ => return None,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct Key {
    proto: Proto,
    a: SocketAddr,
    b: SocketAddr,
}

impl Key {
    fn new(proto: Proto, x: SocketAddr, y: SocketAddr) -> Self {
        if x <= y {
            Self { proto, a: x, b: y }
        } else {
            Self { proto, a: y, b: x }
        }
    }
}

struct Entry {
    /// The endpoint that sent the first packet seen.
    initiator: SocketAddr,
    first_ns: u64,
    last_ns: u64,
    /// Index 0: initiator to responder. Index 1: responder to initiator.
    packets: [u64; 2],
    bytes: [u64; 2],
    state: FlowState,
    fin_seen: [bool; 2],
    sni: Option<String>,
    alpn: Option<String>,
    ja4: Option<String>,
    ja4_raw: Option<String>,
}

/// The TCP flag bits the table cares about.
#[derive(Debug, Clone, Copy)]
pub struct TcpBits {
    /// A SYN without ACK: the opening packet of a connection.
    pub opens: bool,
    pub fin: bool,
    pub rst: bool,
}

/// Running totals by direction across the boundary of the local networks.
/// Counted per packet, never reset, so a reader can take rates from successive
/// samples.
#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct Totals {
    pub out_bytes: u64,
    pub out_packets: u64,
    pub in_bytes: u64,
    pub in_packets: u64,
    pub internal_bytes: u64,
    pub internal_packets: u64,
    pub transit_bytes: u64,
    pub transit_packets: u64,
    /// Conversations shed because the table was full.
    pub flows_shed: u64,
}

/// One conversation as it is reported.
#[derive(Debug, Clone, Serialize)]
pub struct FlowRow {
    pub proto: Proto,
    pub client: SocketAddr,
    pub server: SocketAddr,
    pub direction: Direction,
    pub service: Option<&'static str>,
    pub state: FlowState,
    pub first_ns: u64,
    pub last_ns: u64,
    /// Client to server.
    pub bytes_up: u64,
    /// Server to client.
    pub bytes_down: u64,
    pub packets_up: u64,
    pub packets_down: u64,
    pub sni: Option<String>,
    pub alpn: Option<String>,
    pub ja4: Option<String>,
    pub ja4_raw: Option<String>,
}

/// What a client hello reveals about the conversation that carried it.
#[derive(Debug, Clone)]
pub struct HelloNote {
    pub proto: Proto,
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub sni: Option<String>,
    pub alpn: Option<String>,
    pub ja4: String,
    pub ja4_raw: String,
}

/// The table itself.
pub struct TrafficTable {
    max: usize,
    flows: HashMap<Key, Entry>,
    totals: Totals,
    /// Networks the operator or the capture interface says are ours, beyond
    /// the private ranges.
    local: Vec<Network>,
}

impl Default for TrafficTable {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_FLOWS)
    }
}

impl TrafficTable {
    #[must_use]
    pub fn new(max: usize) -> Self {
        Self {
            max: max.max(1),
            flows: HashMap::new(),
            totals: Totals::default(),
            local: Vec::new(),
        }
    }

    /// Declares the networks this sensor sits on. Without them only private
    /// ranges are local, so a machine with a public IPv6 or IPv4 address would
    /// see all its own traffic as transit between two strangers.
    pub fn set_local_networks(&mut self, networks: Vec<Network>) {
        self.local = networks;
    }

    fn is_ours(&self, ip: IpAddr) -> bool {
        is_local(ip) || self.local.iter().any(|net| net.contains(ip))
    }

    /// Counts one packet. `wire_len` is the captured frame length.
    pub fn record(
        &mut self,
        proto: Proto,
        src: SocketAddr,
        dst: SocketAddr,
        wire_len: usize,
        ts_ns: u64,
        tcp: Option<TcpBits>,
    ) {
        let len = wire_len as u64;
        match (self.is_ours(src.ip()), self.is_ours(dst.ip())) {
            (true, false) => {
                self.totals.out_bytes += len;
                self.totals.out_packets += 1;
            }
            (false, true) => {
                self.totals.in_bytes += len;
                self.totals.in_packets += 1;
            }
            (true, true) => {
                self.totals.internal_bytes += len;
                self.totals.internal_packets += 1;
            }
            (false, false) => {
                self.totals.transit_bytes += len;
                self.totals.transit_packets += 1;
            }
        }

        let key = Key::new(proto, src, dst);
        // A new SYN on an address pair whose last connection already got an
        // answer or ended is a client reusing its source port: count it as a
        // new conversation. A retransmitted or duplicated SYN, which arrives
        // before any reply, is not.
        if tcp.is_some_and(|bits| bits.opens)
            && self
                .flows
                .get(&key)
                .is_some_and(|e| e.state != FlowState::Open || e.packets[1] > 0)
        {
            self.flows.remove(&key);
        }
        if !self.flows.contains_key(&key) && self.flows.len() >= self.max {
            self.shed(ts_ns);
        }
        let entry = self.flows.entry(key).or_insert_with(|| Entry {
            initiator: src,
            first_ns: ts_ns,
            last_ns: ts_ns,
            packets: [0; 2],
            bytes: [0; 2],
            state: FlowState::Open,
            fin_seen: [false; 2],
            sni: None,
            alpn: None,
            ja4: None,
            ja4_raw: None,
        });
        let side = usize::from(src != entry.initiator);
        entry.packets[side] += 1;
        entry.bytes[side] += len;
        entry.first_ns = entry.first_ns.min(ts_ns);
        entry.last_ns = entry.last_ns.max(ts_ns);
        if let Some(TcpBits { fin, rst, .. }) = tcp {
            if rst {
                entry.state = FlowState::Reset;
            } else if fin {
                entry.fin_seen[side] = true;
                if entry.fin_seen[0] && entry.fin_seen[1] && entry.state == FlowState::Open {
                    entry.state = FlowState::Closed;
                }
            }
        }
    }

    /// Attaches what a handshake revealed to its conversation.
    pub fn annotate(&mut self, note: &HelloNote) {
        if let Some(entry) = self
            .flows
            .get_mut(&Key::new(note.proto, note.src, note.dst))
        {
            entry.sni.clone_from(&note.sni);
            entry.alpn.clone_from(&note.alpn);
            entry.ja4 = Some(note.ja4.clone());
            entry.ja4_raw = Some(note.ja4_raw.clone());
        }
    }

    /// Drops the idle conversations, or if none are idle the stalest eighth,
    /// and counts them.
    fn shed(&mut self, now_ns: u64) {
        let before = self.flows.len();
        self.flows
            .retain(|_, e| now_ns.saturating_sub(e.last_ns) <= IDLE_NANOS);
        if self.flows.len() == before {
            let mut times: Vec<u64> = self.flows.values().map(|e| e.last_ns).collect();
            let cut = times.len() / 8;
            times.select_nth_unstable(cut);
            let threshold = times[cut];
            self.flows.retain(|_, e| e.last_ns > threshold);
        }
        self.totals.flows_shed += (before - self.flows.len()) as u64;
    }

    /// Forgets the conversations but keeps the totals, so a replayed capture
    /// can start over without the byte counters running backwards.
    pub fn clear_flows(&mut self) {
        self.flows.clear();
    }

    #[must_use]
    pub fn totals(&self) -> Totals {
        self.totals
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.flows.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.flows.is_empty()
    }

    /// Every conversation, most recently active first, at most `limit`.
    #[must_use]
    pub fn rows(&self, limit: usize) -> Vec<FlowRow> {
        let mut rows: Vec<FlowRow> = self.flows.iter().map(|(k, e)| self.row(k, e)).collect();
        rows.sort_by(|a, b| {
            b.last_ns
                .cmp(&a.last_ns)
                .then_with(|| a.client.cmp(&b.client))
        });
        rows.truncate(limit);
        rows
    }

    /// Every conversation, for aggregation.
    #[must_use]
    pub fn all_rows(&self) -> Vec<FlowRow> {
        self.flows.iter().map(|(k, e)| self.row(k, e)).collect()
    }

    fn row(&self, key: &Key, e: &Entry) -> FlowRow {
        row(key, e, |ip| self.is_ours(ip))
    }
}

fn row(key: &Key, e: &Entry, local: impl Fn(IpAddr) -> bool) -> FlowRow {
    let responder = if e.initiator == key.a { key.b } else { key.a };
    let direction = match (local(e.initiator.ip()), local(responder.ip())) {
        (true, false) => Direction::Outbound,
        (false, true) => Direction::Inbound,
        (true, true) => Direction::Internal,
        (false, false) => Direction::Transit,
    };
    let service = service_name(key.proto, responder.port())
        .or_else(|| service_name(key.proto, e.initiator.port()));
    FlowRow {
        proto: key.proto,
        client: e.initiator,
        server: responder,
        direction,
        service,
        state: e.state,
        first_ns: e.first_ns,
        last_ns: e.last_ns,
        bytes_up: e.bytes[0],
        bytes_down: e.bytes[1],
        packets_up: e.packets[0],
        packets_down: e.packets[1],
        sni: e.sni.clone(),
        alpn: e.alpn.clone(),
        ja4: e.ja4.clone(),
        ja4_raw: e.ja4_raw.clone(),
    }
}

/// A shareable handle to a table, so a server thread can read it while the
/// capture thread writes it.
#[derive(Clone, Default)]
pub struct TrafficHandle(Arc<Mutex<TrafficTable>>);

impl TrafficHandle {
    pub fn with<R>(&self, f: impl FnOnce(&mut TrafficTable) -> R) -> R {
        f(&mut self.0.lock().unwrap_or_else(PoisonError::into_inner))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn a_public_address_on_a_declared_network_is_local() {
        let mut t = TrafficTable::default();
        // A host with a global IPv6 address talking to a CDN: with no declared
        // network this is "transit"; once the sensor knows its own prefix it
        // is outbound.
        let (me, cdn) = (
            addr("[2409:40f4:40d1:a0f6::5]:50000"),
            addr("[2606:4700::1]:443"),
        );
        let go = |t: &mut TrafficTable| {
            t.record(Proto::Tcp, me, cdn, 100, 1, None);
            t.record(Proto::Tcp, cdn, me, 400, 2, None);
        };
        go(&mut t);
        assert_eq!(t.totals().transit_bytes, 500);
        assert_eq!(t.totals().out_bytes, 0);

        let mut t = TrafficTable::default();
        t.set_local_networks(vec!["2409:40f4:40d1:a0f6::/64".parse().unwrap()]);
        go(&mut t);
        assert_eq!(t.totals().out_bytes, 100);
        assert_eq!(t.totals().in_bytes, 400);
        assert_eq!(t.totals().transit_bytes, 0);
        assert_eq!(t.rows(1)[0].direction, Direction::Outbound);
    }

    #[test]
    fn counts_both_directions_and_names_the_initiator() {
        let mut t = TrafficTable::default();
        let (c, s) = (addr("192.168.1.5:50000"), addr("93.184.216.34:443"));
        t.record(
            Proto::Tcp,
            c,
            s,
            100,
            1,
            Some(TcpBits {
                opens: false,
                fin: false,
                rst: false,
            }),
        );
        t.record(
            Proto::Tcp,
            s,
            c,
            1500,
            2,
            Some(TcpBits {
                opens: false,
                fin: false,
                rst: false,
            }),
        );
        t.record(
            Proto::Tcp,
            c,
            s,
            60,
            3,
            Some(TcpBits {
                opens: false,
                fin: false,
                rst: false,
            }),
        );
        let rows = t.rows(10);
        assert_eq!(rows.len(), 1, "one conversation");
        let r = &rows[0];
        assert_eq!((r.client, r.server), (c, s));
        assert_eq!((r.bytes_up, r.bytes_down), (160, 1500));
        assert_eq!((r.packets_up, r.packets_down), (2, 1));
        assert_eq!(r.direction, Direction::Outbound);
        assert_eq!(r.service, Some("https"));
        let totals = t.totals();
        assert_eq!((totals.out_bytes, totals.in_bytes), (160, 1500));
    }

    #[test]
    fn a_remote_initiator_is_inbound() {
        let mut t = TrafficTable::default();
        t.record(
            Proto::Tcp,
            addr("203.0.113.9:40000"),
            addr("10.0.0.2:22"),
            74,
            1,
            None,
        );
        assert_eq!(t.rows(1)[0].direction, Direction::Inbound);
        assert_eq!(t.rows(1)[0].service, Some("ssh"));
    }

    #[test]
    fn fin_from_both_sides_closes_and_rst_resets() {
        let mut t = TrafficTable::default();
        let (c, s) = (addr("10.0.0.1:1111"), addr("10.0.0.2:80"));
        t.record(
            Proto::Tcp,
            c,
            s,
            60,
            1,
            Some(TcpBits {
                opens: false,
                fin: true,
                rst: false,
            }),
        );
        assert_eq!(t.rows(1)[0].state, FlowState::Open);
        t.record(
            Proto::Tcp,
            s,
            c,
            60,
            2,
            Some(TcpBits {
                opens: false,
                fin: true,
                rst: false,
            }),
        );
        assert_eq!(t.rows(1)[0].state, FlowState::Closed);
        let (c2, s2) = (addr("10.0.0.1:2222"), addr("10.0.0.2:80"));
        t.record(
            Proto::Tcp,
            c2,
            s2,
            60,
            3,
            Some(TcpBits {
                opens: false,
                fin: false,
                rst: true,
            }),
        );
        let reset = t.rows(10).into_iter().find(|r| r.client == c2).unwrap();
        assert_eq!(reset.state, FlowState::Reset);
    }

    #[test]
    fn a_reused_port_is_a_new_conversation_but_a_duplicate_syn_is_not() {
        let mut t = TrafficTable::default();
        let (c, s) = (addr("10.0.0.1:1111"), addr("1.1.1.1:443"));
        let syn = Some(TcpBits {
            opens: true,
            fin: false,
            rst: false,
        });
        let plain = Some(TcpBits {
            opens: false,
            fin: false,
            rst: false,
        });
        t.record(Proto::Tcp, c, s, 60, 1, syn);
        t.record(Proto::Tcp, c, s, 60, 1, syn); // duplicate before any reply
        assert_eq!(t.rows(10)[0].packets_up, 2);
        t.record(Proto::Tcp, s, c, 60, 2, plain);
        t.record(Proto::Tcp, c, s, 60, 3, syn); // a new connection, same ports
        let rows = t.rows(10);
        assert_eq!(rows.len(), 1);
        assert_eq!(
            (rows[0].packets_up, rows[0].packets_down),
            (1, 0),
            "counted afresh"
        );
    }

    #[test]
    fn annotation_reaches_the_conversation() {
        let mut t = TrafficTable::default();
        let (c, s) = (addr("10.0.0.1:1111"), addr("1.1.1.1:443"));
        t.record(Proto::Tcp, c, s, 60, 1, None);
        t.annotate(&HelloNote {
            proto: Proto::Tcp,
            src: c,
            dst: s,
            sni: Some("one.one.one.one".into()),
            alpn: Some("h2".into()),
            ja4: "t13d".into(),
            ja4_raw: "raw".into(),
        });
        let r = &t.rows(1)[0];
        assert_eq!(r.sni.as_deref(), Some("one.one.one.one"));
        assert_eq!(r.ja4.as_deref(), Some("t13d"));
    }

    #[test]
    fn the_table_stays_bounded_and_counts_what_it_sheds() {
        let mut t = TrafficTable::new(64);
        for i in 0..1000u16 {
            let c = addr(&format!("10.0.0.1:{}", 2000 + i));
            t.record(Proto::Udp, c, addr("8.8.8.8:53"), 80, u64::from(i), None);
        }
        assert!(t.len() <= 64, "len {}", t.len());
        assert!(t.totals().flows_shed > 900);
    }

    #[test]
    fn local_address_ranges() {
        for local in [
            "10.1.2.3",
            "172.16.0.1",
            "192.168.0.9",
            "127.0.0.1",
            "169.254.1.1",
            "fd00::1",
            "fe80::1",
            "::1",
        ] {
            assert!(is_local(local.parse().unwrap()), "{local}");
        }
        for remote in ["8.8.8.8", "93.184.216.34", "2606:4700::1111"] {
            assert!(!is_local(remote.parse().unwrap()), "{remote}");
        }
    }
}
