// © Pranav Verma | 2026
// dnsbook.rs

//! What the sensor has heard of DNS: which names are asked for, by whom, and
//! how often they fail.
//!
//! DNS is far chattier than TLS, so it does not go through the event stream
//! (it would push the handshakes out of its history). It is summarised here
//! instead, in memory and bounded: a fixed number of names, clients and recent
//! lookups, with the least recently seen names dropped when full. It is reset
//! when the server restarts, and it sees only cleartext DNS on UDP 53; DNS over
//! HTTPS or TLS is encrypted and does not appear.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;

use serde::Serialize;
use tlsfp_core::dns::DnsMessage;
use tlsfp_intel::{Alert, AlertSeverity, Rule};

use crate::dnsfind::{self, ClientFacts, Finding, NameFacts, ParentFacts};

const MAX_NAMES: usize = 20_000;
const MAX_CLIENTS: usize = 5_000;
const MAX_RECENT: usize = 500;
/// Clients remembered per name, enough to say "several machines ask for this".
const MAX_CLIENTS_PER_NAME: usize = 16;
const MAX_PENDING: usize = 4_096;
const MAX_RESOLVERS: usize = 256;
const MAX_PARENTS: usize = 5_000;
const MAX_CHILDREN: usize = 256;
/// Query times kept per name.
const MAX_TIMES: usize = 24;
/// How often the findings are re-examined for new alerts. They are computed
/// over every name, so this is throttled rather than run per message.
const EXAMINE_EVERY_NANOS: u64 = 30_000_000_000;
const MAX_ALERTED: usize = 2_000;

#[derive(Default)]
struct NameStat {
    queries: u64,
    answered: u64,
    nxdomain: u64,
    failures: u64,
    first_ts: u64,
    last_ts: u64,
    clients: HashSet<IpAddr>,
    resolvers: Vec<String>,
    qtypes: Vec<String>,
    /// What the name resolved to, most recent last.
    addresses: Vec<String>,
    reverse_of: Option<String>,
    latency_total_ms: f64,
    latency_count: u64,
    ttl: Option<u32>,
    /// When the most recent questions were asked, for judging rhythm.
    times: VecDeque<u64>,
}

/// What is known about a domain's subdomains, for spotting generated names.
#[derive(Default)]
struct ParentStat {
    children: HashSet<String>,
    random: HashSet<String>,
    queries: u64,
}

/// One answer record as shown.
#[derive(Debug, Clone, Serialize)]
pub struct AnswerRow {
    pub rtype: String,
    pub data: String,
    pub ttl: u32,
}

/// One lookup as shown in the recent list.
#[derive(Debug, Clone, Serialize)]
pub struct Lookup {
    pub ts_nanos: u64,
    pub client: String,
    pub resolver: String,
    pub name: String,
    pub qtype: String,
    /// Empty for a query that has no response yet.
    pub rcode: String,
    pub answers: Vec<AnswerRow>,
    /// For a reverse lookup, the address it asks about.
    pub reverse_of: Option<String>,
    /// Milliseconds from the query to this response, when both were seen.
    pub latency_ms: Option<f64>,
}

#[derive(Debug, Serialize)]
pub struct NameRow {
    pub name: String,
    /// `internet`, `local` (a name that only makes sense inside a network:
    /// `.local`, `.lan`, a single label) or `reverse` (an address looked up).
    pub kind: &'static str,
    pub reverse_of: Option<String>,
    pub queries: u64,
    pub answered: u64,
    pub nxdomain: u64,
    pub failures: u64,
    pub clients: usize,
    pub first_ts: u64,
    pub last_ts: u64,
    /// The record types asked for.
    pub qtypes: Vec<String>,
    /// The DNS servers that were asked.
    pub resolvers: Vec<String>,
    /// Addresses the name resolved to, most recent last.
    pub addresses: Vec<String>,
    /// Average milliseconds to answer.
    pub latency_ms: Option<f64>,
    pub ttl: Option<u32>,
    /// The resolver answered with an unroutable address (0.0.0.0 or ::), the
    /// way a blocklist does.
    pub blocked: bool,
    /// The first label is long and looks random. A hint, not a verdict: content
    /// networks and trackers generate such names legitimately.
    pub random_looking: bool,
}

#[derive(Debug, Serialize)]
pub struct ClientRow {
    pub client: String,
    pub queries: u64,
    pub nxdomain: u64,
    /// The DNS servers this host asked.
    pub resolvers: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct ResolverRow {
    pub resolver: String,
    pub queries: u64,
    pub nxdomain: u64,
    pub latency_ms: Option<f64>,
    pub clients: usize,
}

#[derive(Debug, Default, Serialize, Clone, Copy)]
pub struct DnsTotals {
    pub queries: u64,
    pub responses: u64,
    pub nxdomain: u64,
    pub failures: u64,
    /// When the first message was seen, so "so far" has a start.
    pub since_ts: u64,
    pub last_ts: u64,
}

#[derive(Debug, Serialize)]
pub struct DnsView {
    pub totals: DnsTotals,
    pub top_names: Vec<NameRow>,
    pub top_failing: Vec<NameRow>,
    pub top_clients: Vec<ClientRow>,
    pub resolvers: Vec<ResolverRow>,
    pub recent: Vec<Lookup>,
    /// Things in the traffic worth a look, with evidence.
    pub findings: Vec<Finding>,
}

#[derive(Default)]
struct ClientStat {
    queries: u64,
    nxdomain: u64,
    resolvers: Vec<String>,
}

#[derive(Default)]
struct ResolverStat {
    queries: u64,
    nxdomain: u64,
    latency_total_ms: f64,
    latency_count: u64,
    clients: HashSet<IpAddr>,
}

#[derive(Default)]
pub struct DnsBook {
    names: HashMap<String, NameStat>,
    clients: HashMap<IpAddr, ClientStat>,
    resolvers: HashMap<String, ResolverStat>,
    parents: HashMap<String, ParentStat>,
    /// Findings already turned into alerts, so each is raised once.
    alerted: HashSet<String>,
    /// When the findings were last examined (nanoseconds of capture time).
    examined_ts: u64,
    /// Queries waiting for their response, to time the answer.
    pending: HashMap<(IpAddr, u16, String), u64>,
    recent: VecDeque<Lookup>,
    totals: DnsTotals,
}

/// Names that only mean something inside a network.
const LOCAL_SUFFIXES: [&str; 9] = [
    ".local",
    ".localdomain",
    ".lan",
    ".home",
    ".internal",
    ".corp",
    ".intranet",
    ".home.arpa",
    ".localhost",
];

fn kind_of(name: &str, reverse_of: Option<&String>) -> &'static str {
    if reverse_of.is_some() || name.rsplit('.').next() == Some("arpa") {
        "reverse"
    } else if !name.contains('.') || LOCAL_SUFFIXES.iter().any(|s| name.ends_with(s)) {
        "local"
    } else {
        "internet"
    }
}

fn push_unique(list: &mut Vec<String>, value: &str, cap: usize) {
    if !value.is_empty() && !list.iter().any(|v| v == value) {
        if list.len() >= cap {
            list.remove(0);
        }
        list.push(value.to_owned());
    }
}

/// Shannon entropy of the characters, in bits each.
#[allow(clippy::cast_precision_loss)]
fn entropy(text: &str) -> f64 {
    let mut counts = [0u32; 256];
    for b in text.bytes() {
        counts[usize::from(b)] += 1;
    }
    let len = text.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = f64::from(c) / len;
            -p * p.log2()
        })
        .sum()
}

/// A long first label with high character entropy and no separators.
#[must_use]
pub fn looks_random(name: &str) -> bool {
    let label = name.split('.').next().unwrap_or("");
    label.len() >= 16 && label.bytes().all(|b| b.is_ascii_alphanumeric()) && entropy(label) >= 3.5
}

impl DnsBook {
    pub fn record(
        &mut self,
        ts_nanos: u64,
        src: std::net::SocketAddr,
        dst: std::net::SocketAddr,
        message: &DnsMessage,
    ) {
        // The client is whoever asked: the sender of a query, the receiver of
        // a response.
        let (client, resolver) = if message.response {
            (dst, src)
        } else {
            (src, dst)
        };
        let resolver_text = resolver.ip().to_string();
        if self.totals.since_ts == 0 || ts_nanos < self.totals.since_ts {
            self.totals.since_ts = ts_nanos;
        }
        self.totals.last_ts = self.totals.last_ts.max(ts_nanos);
        if message.response {
            self.totals.responses += 1;
        } else {
            self.totals.queries += 1;
        }
        let nx = message.response && message.rcode == "NXDOMAIN";
        let failed = message.response && matches!(message.rcode.as_str(), "SERVFAIL" | "REFUSED");
        if nx {
            self.totals.nxdomain += 1;
        }
        if failed {
            self.totals.failures += 1;
        }

        // Time the answer: a response closes the query with the same id, name
        // and asking host.
        let pending_key = (client.ip(), message.id, message.name.clone());
        let latency_ms = if message.response {
            self.pending.remove(&pending_key).map(|asked| {
                #[allow(clippy::cast_precision_loss)]
                let ms = ts_nanos.saturating_sub(asked) as f64 / 1e6;
                ms
            })
        } else {
            if self.pending.len() >= MAX_PENDING {
                self.pending.clear();
            }
            self.pending.insert(pending_key, ts_nanos);
            None
        };

        let seen = Seen {
            ts_nanos,
            client: client.ip(),
            resolver: resolver_text.clone(),
            nx,
            failed,
            latency_ms,
        };
        self.update_name(message, &seen);
        self.update_client_and_resolver(message, &seen);

        if self.recent.len() >= MAX_RECENT {
            self.recent.pop_front();
        }
        self.recent.push_back(Lookup {
            ts_nanos,
            client: client.ip().to_string(),
            resolver: resolver_text,
            name: message.name.clone(),
            qtype: message.qtype.clone(),
            rcode: message.rcode.clone(),
            answers: message
                .answers
                .iter()
                .map(|a| AnswerRow {
                    rtype: a.rtype.clone(),
                    data: a.data.clone(),
                    ttl: a.ttl,
                })
                .collect(),
            reverse_of: message.reverse_of.clone(),
            latency_ms,
        });
    }

    fn drop_stalest_names(&mut self) {
        let mut times: Vec<u64> = self.names.values().map(|s| s.last_ts).collect();
        let cut = times.len() / 8;
        times.select_nth_unstable(cut);
        let threshold = times[cut];
        self.names.retain(|_, s| s.last_ts > threshold);
    }

    /// Alerts for findings that are new since the last time, at most every 30
    /// seconds of capture time. Only the "worth a look" findings alert; the
    /// informational ones stay on the page. Each subject (a host, a domain, a
    /// name) alerts once until the sensor restarts.
    pub fn new_alerts(&mut self, now_ts: u64) -> Vec<Alert> {
        if now_ts.saturating_sub(self.examined_ts) < EXAMINE_EVERY_NANOS {
            return Vec::new();
        }
        self.examined_ts = now_ts;
        let mut out = Vec::new();
        for finding in self.findings() {
            if finding.severity != dnsfind::Severity::Notice {
                continue;
            }
            for line in &finding.evidence {
                let subject = line.split(" (").next().unwrap_or(line).to_owned();
                let key = format!("{}|{subject}", finding.id);
                if self.alerted.len() >= MAX_ALERTED {
                    self.alerted.clear();
                }
                if !self.alerted.insert(key) {
                    continue;
                }
                out.push(Alert {
                    ts_nanos: i64::try_from(now_ts).unwrap_or(i64::MAX),
                    rule: Rule::DnsPattern,
                    severity: AlertSeverity::Low,
                    // A host's own failures belong to that host.
                    ip: (finding.id == "many_failures").then(|| subject.clone()),
                    fp_kind: None,
                    fp_value: None,
                    title: finding.title.clone(),
                    detail: format!(
                        "{line}. {} Could also be: {}",
                        finding.detail, finding.innocent
                    ),
                    score: None,
                });
            }
        }
        out
    }

    #[must_use]
    pub fn totals(&self) -> DnsTotals {
        self.totals
    }

    #[must_use]
    pub fn view(&self, top: usize) -> DnsView {
        let row = |(name, s): (&String, &NameStat)| NameRow {
            name: name.clone(),
            kind: kind_of(name, s.reverse_of.as_ref()),
            reverse_of: s.reverse_of.clone(),
            queries: s.queries.max(s.answered),
            answered: s.answered,
            nxdomain: s.nxdomain,
            failures: s.failures,
            clients: s.clients.len(),
            first_ts: s.first_ts,
            last_ts: s.last_ts,
            qtypes: s.qtypes.clone(),
            resolvers: s.resolvers.clone(),
            addresses: s.addresses.clone(),
            latency_ms: average(s.latency_total_ms, s.latency_count),
            ttl: s.ttl,
            blocked: s.addresses.iter().any(|a| a == "0.0.0.0" || a == "::"),
            random_looking: looks_random(name),
        };
        let mut names: Vec<NameRow> = self.names.iter().map(row).collect();
        names.sort_by(|a, b| b.queries.cmp(&a.queries).then_with(|| a.name.cmp(&b.name)));
        let mut failing: Vec<NameRow> = self
            .names
            .iter()
            .filter(|(_, s)| s.nxdomain + s.failures > 0)
            .map(row)
            .collect();
        failing.sort_by(|a, b| {
            (b.nxdomain + b.failures)
                .cmp(&(a.nxdomain + a.failures))
                .then_with(|| a.name.cmp(&b.name))
        });
        failing.truncate(top);
        names.truncate(top);

        let mut clients: Vec<ClientRow> = self
            .clients
            .iter()
            .map(|(ip, s)| ClientRow {
                client: ip.to_string(),
                queries: s.queries,
                nxdomain: s.nxdomain,
                resolvers: s.resolvers.clone(),
            })
            .collect();
        clients.sort_by(|a, b| {
            b.queries
                .cmp(&a.queries)
                .then_with(|| a.client.cmp(&b.client))
        });
        clients.truncate(top);

        let mut resolvers: Vec<ResolverRow> = self
            .resolvers
            .iter()
            .map(|(resolver, s)| ResolverRow {
                resolver: resolver.clone(),
                queries: s.queries,
                nxdomain: s.nxdomain,
                latency_ms: average(s.latency_total_ms, s.latency_count),
                clients: s.clients.len(),
            })
            .collect();
        resolvers.sort_by(|a, b| {
            b.queries
                .cmp(&a.queries)
                .then_with(|| a.resolver.cmp(&b.resolver))
        });

        let findings = self.findings();
        DnsView {
            totals: self.totals,
            top_names: names,
            top_failing: failing,
            top_clients: clients,
            resolvers,
            recent: self
                .recent
                .iter()
                .rev()
                .take(top.max(50))
                .cloned()
                .collect(),
            findings,
        }
    }

    fn findings(&self) -> Vec<Finding> {
        let rows: Vec<(&String, &NameStat, Vec<u64>)> = self
            .names
            .iter()
            .map(|(name, s)| (name, s, s.times.iter().copied().collect()))
            .collect();
        let names: Vec<NameFacts<'_>> = rows
            .iter()
            .map(|(name, s, times)| NameFacts {
                name,
                reverse: s.reverse_of.is_some(),
                queries: s.queries,
                ttl: s.ttl,
                addresses: &s.addresses,
                times,
                blocked: s.addresses.iter().any(|a| a == "0.0.0.0" || a == "::"),
            })
            .collect();
        let client_keys: Vec<(String, &ClientStat)> = self
            .clients
            .iter()
            .map(|(ip, s)| (ip.to_string(), s))
            .collect();
        let clients: Vec<ClientFacts<'_>> = client_keys
            .iter()
            .map(|(ip, s)| ClientFacts {
                client: ip,
                queries: s.queries,
                nxdomain: s.nxdomain,
            })
            .collect();
        let parents: Vec<ParentFacts<'_>> = self
            .parents
            .iter()
            .map(|(parent, s)| ParentFacts {
                parent,
                children: s.children.len(),
                random_children: s.random.len(),
                queries: s.queries,
            })
            .collect();
        dnsfind::analyze(&names, &clients, &parents)
    }
}

/// What one DNS message adds to the books, beyond the message itself.
struct Seen {
    ts_nanos: u64,
    client: IpAddr,
    resolver: String,
    nx: bool,
    failed: bool,
    latency_ms: Option<f64>,
}

impl DnsBook {
    fn update_name(&mut self, message: &DnsMessage, seen: &Seen) {
        if self.names.len() >= MAX_NAMES && !self.names.contains_key(&message.name) {
            self.drop_stalest_names();
        }
        let stat = self.names.entry(message.name.clone()).or_default();
        if stat.first_ts == 0 {
            stat.first_ts = seen.ts_nanos;
        }
        stat.first_ts = stat.first_ts.min(seen.ts_nanos);
        stat.last_ts = stat.last_ts.max(seen.ts_nanos);
        if stat.clients.len() < MAX_CLIENTS_PER_NAME {
            stat.clients.insert(seen.client);
        }
        push_unique(&mut stat.resolvers, &seen.resolver, 8);
        push_unique(&mut stat.qtypes, &message.qtype, 8);
        if stat.reverse_of.is_none() {
            stat.reverse_of.clone_from(&message.reverse_of);
        }
        if message.response {
            stat.answered += 1;
            stat.nxdomain += u64::from(seen.nx);
            stat.failures += u64::from(seen.failed);
            for answer in &message.answers {
                if answer.rtype == "A" || answer.rtype == "AAAA" || answer.rtype == "PTR" {
                    push_unique(&mut stat.addresses, &answer.data, 8);
                }
                stat.ttl = Some(answer.ttl);
            }
            if let Some(ms) = seen.latency_ms {
                stat.latency_total_ms += ms;
                stat.latency_count += 1;
            }
        } else {
            stat.queries += 1;
            if stat.times.len() >= MAX_TIMES {
                stat.times.pop_front();
            }
            stat.times.push_back(seen.ts_nanos);
        }
        if !message.response && message.reverse_of.is_none() {
            self.note_parent(&message.name);
        }
    }

    fn note_parent(&mut self, name: &str) {
        let parent = dnsfind::parent_domain(name);
        if parent == name {
            return;
        }
        if self.parents.len() >= MAX_PARENTS && !self.parents.contains_key(parent) {
            self.parents.clear();
        }
        let stat = self.parents.entry(parent.to_owned()).or_default();
        stat.queries += 1;
        if stat.children.len() < MAX_CHILDREN {
            stat.children.insert(name.to_owned());
        }
        if looks_random(name) && stat.random.len() < MAX_CHILDREN {
            stat.random.insert(name.to_owned());
        }
    }

    fn update_client_and_resolver(&mut self, message: &DnsMessage, seen: &Seen) {
        if self.clients.len() >= MAX_CLIENTS && !self.clients.contains_key(&seen.client) {
            self.clients.clear();
        }
        let who = self.clients.entry(seen.client).or_default();
        if !message.response {
            who.queries += 1;
        }
        who.nxdomain += u64::from(seen.nx);
        push_unique(&mut who.resolvers, &seen.resolver, 4);

        if self.resolvers.len() >= MAX_RESOLVERS && !self.resolvers.contains_key(&seen.resolver) {
            self.resolvers.clear();
        }
        let server = self.resolvers.entry(seen.resolver.clone()).or_default();
        if !message.response {
            server.queries += 1;
        }
        server.nxdomain += u64::from(seen.nx);
        if let Some(ms) = seen.latency_ms {
            server.latency_total_ms += ms;
            server.latency_count += 1;
        }
        if server.clients.len() < MAX_CLIENTS_PER_NAME {
            server.clients.insert(seen.client);
        }
    }
}

#[allow(clippy::cast_precision_loss)]
fn average(total_ms: f64, count: u64) -> Option<f64> {
    (count > 0).then(|| total_ms / count as f64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tlsfp_core::dns::{DnsAnswer, DnsMessage};

    fn msg(name: &str, response: bool, rcode: &str, answers: &[&str]) -> DnsMessage {
        DnsMessage {
            reverse_of: None,
            id: 1,
            response,
            name: name.to_owned(),
            qtype: "A".to_owned(),
            rcode: rcode.to_owned(),
            answers: answers
                .iter()
                .map(|a| DnsAnswer {
                    rtype: "A".to_owned(),
                    data: (*a).to_owned(),
                    ttl: 60,
                })
                .collect(),
        }
    }

    fn addr(s: &str) -> std::net::SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn queries_and_failures_are_counted_against_the_asking_client() {
        let mut book = DnsBook::default();
        let (client, resolver) = (addr("10.0.0.5:40000"), addr("10.0.0.1:53"));
        book.record(1, client, resolver, &msg("a.example", false, "", &[]));
        book.record(
            2,
            resolver,
            client,
            &msg("a.example", true, "NOERROR", &["192.0.2.1"]),
        );
        book.record(3, client, resolver, &msg("gone.example", false, "", &[]));
        book.record(
            4,
            resolver,
            client,
            &msg("gone.example", true, "NXDOMAIN", &[]),
        );
        let view = book.view(10);
        assert_eq!(view.totals.queries, 2);
        assert_eq!(view.totals.nxdomain, 1);
        assert_eq!(view.top_clients[0].client, "10.0.0.5");
        assert_eq!(view.top_clients[0].nxdomain, 1);
        assert_eq!(view.top_failing[0].name, "gone.example");
        let a = view
            .top_names
            .iter()
            .find(|n| n.name == "a.example")
            .unwrap();
        assert_eq!(a.addresses, ["192.0.2.1"]);
    }

    #[test]
    fn memory_is_bounded_when_names_keep_changing() {
        let mut book = DnsBook::default();
        let (client, resolver) = (addr("10.0.0.5:40000"), addr("10.0.0.1:53"));
        for i in 0..(MAX_NAMES as u64 + 500) {
            book.record(
                i,
                client,
                resolver,
                &msg(&format!("n{i}.example"), false, "", &[]),
            );
        }
        assert!(book.names.len() <= MAX_NAMES);
        assert_eq!(book.recent.len(), MAX_RECENT);
    }

    #[test]
    fn random_looking_names_are_flagged_and_ordinary_ones_are_not() {
        assert!(looks_random("x7f3k9q2m8z1v5b4n6.example.com"));
        assert!(!looks_random("www.example.com"));
        assert!(!looks_random("mail-server-01.example.com"));
        assert!(!looks_random("aaaaaaaaaaaaaaaaaaaa.example.com"));
    }

    #[test]
    fn findings_surface_from_the_books() {
        let mut book = DnsBook::default();
        let (client, resolver) = (addr("10.0.0.5:40000"), addr("10.0.0.1:53"));
        // Many random-looking subdomains of one domain.
        for i in 0..8u64 {
            let name = format!("x7f3k9q2m8z1v5b{i}n6.tunnel.example");
            book.record(i, client, resolver, &msg(&name, false, "", &[]));
        }
        // A name asked for every 30 seconds.
        for i in 0..10u64 {
            book.record(
                i * 30_000_000_000,
                client,
                resolver,
                &msg("poll.example.com", false, "", &[]),
            );
        }
        let ids: Vec<&str> = book.view(10).findings.iter().map(|f| f.id).collect();
        assert!(ids.contains(&"generated_subdomains"), "{ids:?}");
        assert!(ids.contains(&"regular_polling"), "{ids:?}");
    }

    #[test]
    fn a_quiet_network_has_no_findings() {
        let mut book = DnsBook::default();
        let (client, resolver) = (addr("10.0.0.5:40000"), addr("10.0.0.1:53"));
        book.record(1, client, resolver, &msg("www.example.com", false, "", &[]));
        book.record(
            2,
            resolver,
            client,
            &msg("www.example.com", true, "NOERROR", &["192.0.2.1"]),
        );
        assert_eq!(book.view(10).findings, Vec::new());
    }

    #[test]
    fn a_finding_raises_one_alert_per_subject_and_not_again() {
        let mut book = DnsBook::default();
        let (client, resolver) = (addr("10.0.0.5:40000"), addr("10.0.0.1:53"));
        for i in 0..8u64 {
            let name = format!("x7f3k9q2m8z1v5b{i}n6.tunnel.example");
            book.record(i, client, resolver, &msg(&name, false, "", &[]));
        }
        // Too soon after the start of capture time: nothing is examined yet.
        assert_eq!(book.new_alerts(1).len(), 0);
        let first = book.new_alerts(EXAMINE_EVERY_NANOS);
        assert_eq!(first.len(), 1, "{first:?}");
        assert_eq!(first[0].rule, Rule::DnsPattern);
        assert_eq!(first[0].severity, AlertSeverity::Low);
        assert!(first[0].detail.contains("tunnel.example"));
        assert!(first[0].detail.contains("Could also be"));
        // Examined again later: the same subject is not alerted twice.
        assert_eq!(book.new_alerts(EXAMINE_EVERY_NANOS * 3).len(), 0);
    }

    #[test]
    fn informational_findings_do_not_alert() {
        let mut book = DnsBook::default();
        let (client, resolver) = (addr("10.0.0.5:40000"), addr("10.0.0.1:53"));
        // A steady rhythm is only informational.
        for i in 0..10u64 {
            book.record(
                i * 30_000_000_000,
                client,
                resolver,
                &msg("poll.example.com", false, "", &[]),
            );
        }
        assert!(
            book.view(5)
                .findings
                .iter()
                .any(|f| f.id == "regular_polling")
        );
        assert_eq!(book.new_alerts(EXAMINE_EVERY_NANOS * 20).len(), 0);
    }

    #[test]
    fn a_hosts_failures_alert_against_that_host() {
        let mut book = DnsBook::default();
        let (client, resolver) = (addr("10.0.0.9:40000"), addr("10.0.0.1:53"));
        for i in 0..30u64 {
            let name = format!("gone{i}.example");
            book.record(i, client, resolver, &msg(&name, false, "", &[]));
            book.record(i, resolver, client, &msg(&name, true, "NXDOMAIN", &[]));
        }
        let alerts = book.new_alerts(EXAMINE_EVERY_NANOS);
        let failures: Vec<_> = alerts
            .iter()
            .filter(|a| a.title.contains("no such name"))
            .collect();
        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0].ip.as_deref(), Some("10.0.0.9"));
    }
}
