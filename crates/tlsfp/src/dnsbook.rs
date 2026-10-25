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

const MAX_NAMES: usize = 20_000;
const MAX_CLIENTS: usize = 5_000;
const MAX_RECENT: usize = 500;
/// Clients remembered per name, enough to say "several machines ask for this".
const MAX_CLIENTS_PER_NAME: usize = 16;

#[derive(Default)]
struct NameStat {
    queries: u64,
    answered: u64,
    nxdomain: u64,
    failures: u64,
    last_ts: u64,
    clients: HashSet<IpAddr>,
    addresses: Vec<String>,
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
    pub answers: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct NameRow {
    pub name: String,
    pub queries: u64,
    pub answered: u64,
    pub nxdomain: u64,
    pub failures: u64,
    pub clients: usize,
    pub last_ts: u64,
    /// Addresses the name resolved to, most recent last.
    pub addresses: Vec<String>,
    /// The first label is long and looks random. A hint, not a verdict: content
    /// networks and trackers generate such names legitimately.
    pub random_looking: bool,
}

#[derive(Debug, Serialize)]
pub struct ClientRow {
    pub client: String,
    pub queries: u64,
    pub nxdomain: u64,
}

#[derive(Debug, Default, Serialize, Clone, Copy)]
pub struct DnsTotals {
    pub queries: u64,
    pub responses: u64,
    pub nxdomain: u64,
    pub failures: u64,
}

#[derive(Debug, Serialize)]
pub struct DnsView {
    pub totals: DnsTotals,
    pub top_names: Vec<NameRow>,
    pub top_failing: Vec<NameRow>,
    pub top_clients: Vec<ClientRow>,
    pub recent: Vec<Lookup>,
}

#[derive(Default)]
pub struct DnsBook {
    names: HashMap<String, NameStat>,
    clients: HashMap<IpAddr, (u64, u64)>,
    recent: VecDeque<Lookup>,
    totals: DnsTotals,
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

        if self.names.len() >= MAX_NAMES && !self.names.contains_key(&message.name) {
            self.drop_stalest_names();
        }
        let stat = self.names.entry(message.name.clone()).or_default();
        stat.last_ts = stat.last_ts.max(ts_nanos);
        if stat.clients.len() < MAX_CLIENTS_PER_NAME {
            stat.clients.insert(client.ip());
        }
        if message.response {
            stat.answered += 1;
            stat.nxdomain += u64::from(nx);
            stat.failures += u64::from(failed);
            for answer in &message.answers {
                let is_address = answer.rtype == "A" || answer.rtype == "AAAA";
                if is_address && !stat.addresses.contains(&answer.data) {
                    if stat.addresses.len() >= 8 {
                        stat.addresses.remove(0);
                    }
                    stat.addresses.push(answer.data.clone());
                }
            }
        } else {
            stat.queries += 1;
        }

        if self.clients.len() >= MAX_CLIENTS && !self.clients.contains_key(&client.ip()) {
            self.clients.clear();
        }
        let who = self.clients.entry(client.ip()).or_default();
        if !message.response {
            who.0 += 1;
        }
        who.1 += u64::from(nx);

        if self.recent.len() >= MAX_RECENT {
            self.recent.pop_front();
        }
        self.recent.push_back(Lookup {
            ts_nanos,
            client: client.ip().to_string(),
            resolver: resolver.ip().to_string(),
            name: message.name.clone(),
            qtype: message.qtype.clone(),
            rcode: message.rcode.clone(),
            answers: message
                .answers
                .iter()
                .filter(|a| !a.data.is_empty())
                .map(|a| a.data.clone())
                .collect(),
        });
    }

    fn drop_stalest_names(&mut self) {
        let mut times: Vec<u64> = self.names.values().map(|s| s.last_ts).collect();
        let cut = times.len() / 8;
        times.select_nth_unstable(cut);
        let threshold = times[cut];
        self.names.retain(|_, s| s.last_ts > threshold);
    }

    #[must_use]
    pub fn totals(&self) -> DnsTotals {
        self.totals
    }

    #[must_use]
    pub fn view(&self, top: usize) -> DnsView {
        let row = |(name, s): (&String, &NameStat)| NameRow {
            name: name.clone(),
            queries: s.queries.max(s.answered),
            answered: s.answered,
            nxdomain: s.nxdomain,
            failures: s.failures,
            clients: s.clients.len(),
            last_ts: s.last_ts,
            addresses: s.addresses.clone(),
            random_looking: looks_random(name),
        };
        let mut names: Vec<NameRow> = self.names.iter().map(row).collect();
        names.sort_by(|a, b| b.queries.cmp(&a.queries).then_with(|| a.name.cmp(&b.name)));
        let mut failing: Vec<NameRow> = names
            .iter()
            .filter(|n| n.nxdomain + n.failures > 0)
            .map(|n| NameRow {
                name: n.name.clone(),
                addresses: Vec::new(),
                ..*n
            })
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
            .map(|(ip, (queries, nxdomain))| ClientRow {
                client: ip.to_string(),
                queries: *queries,
                nxdomain: *nxdomain,
            })
            .collect();
        clients.sort_by(|a, b| {
            b.queries
                .cmp(&a.queries)
                .then_with(|| a.client.cmp(&b.client))
        });
        clients.truncate(top);

        DnsView {
            totals: self.totals,
            top_names: names,
            top_failing: failing,
            top_clients: clients,
            recent: self
                .recent
                .iter()
                .rev()
                .take(top.max(50))
                .cloned()
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tlsfp_core::dns::{DnsAnswer, DnsMessage};

    fn msg(name: &str, response: bool, rcode: &str, answers: &[&str]) -> DnsMessage {
        DnsMessage {
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
}
