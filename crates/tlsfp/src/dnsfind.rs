// © Pranav Verma | 2026
// dnsfind.rs

//! Things in the DNS traffic worth a person's attention, with the evidence.
//!
//! These are heuristics over what has been heard, not verdicts. Every finding
//! says what was observed, why it can matter, and what else could explain it,
//! because each pattern has innocent causes (software that polls, content
//! networks with generated names, a mistyped setting). Thresholds are named
//! constants so they are easy to read and to tune, and each is covered by a
//! test. Nothing here sends an alert: findings are shown, not acted on.

use serde::Serialize;

/// Distinct generated-looking subdomains under one domain before it is flagged.
pub const RANDOM_CHILDREN: usize = 5;
/// Names this long (in characters) are unusual outside tunnelling and tracking.
pub const LONG_NAME: usize = 80;
/// "No such name" answers for one host before it is flagged, and the share.
pub const NX_HOST_MIN: u64 = 20;
pub const NX_HOST_SHARE: f64 = 0.3;
/// Queries for one name needed to judge its timing, and the largest spread of
/// the gaps between them (as a share of their average) that counts as regular.
pub const BEACON_MIN_QUERIES: usize = 8;
pub const BEACON_MAX_SPREAD: f64 = 0.15;
/// A regular gap shorter than this is ordinary chatter, not polling.
pub const BEACON_MIN_GAP_SECS: f64 = 2.0;
/// Distinct addresses and the longest cache time that suggest fast-changing hosting.
pub const FLUX_ADDRESSES: usize = 6;
pub const FLUX_MAX_TTL: u32 = 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// Worth knowing; usually benign.
    Info,
    /// Worth a look.
    Notice,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Finding {
    /// A stable id for the kind of finding, for filtering.
    pub id: &'static str,
    pub severity: Severity,
    pub title: String,
    /// What was seen and why it can matter, in plain words.
    pub detail: String,
    /// What else could explain it.
    pub innocent: &'static str,
    /// The names, hosts or domains involved, strongest first.
    pub evidence: Vec<String>,
}

pub struct NameFacts<'a> {
    pub name: &'a str,
    pub reverse: bool,
    pub queries: u64,
    pub ttl: Option<u32>,
    pub addresses: &'a [String],
    /// Timestamps of the most recent queries, oldest first (nanoseconds).
    pub times: &'a [u64],
    pub blocked: bool,
}

pub struct ClientFacts<'a> {
    pub client: &'a str,
    pub queries: u64,
    pub nxdomain: u64,
}

pub struct ParentFacts<'a> {
    pub parent: &'a str,
    pub children: usize,
    pub random_children: usize,
    pub queries: u64,
}

/// The mean gap in seconds and how irregular the gaps are (their standard
/// deviation as a share of the mean), or `None` with too few queries.
#[must_use]
#[allow(clippy::cast_precision_loss)]
pub fn regularity(times: &[u64]) -> Option<(f64, f64)> {
    if times.len() < BEACON_MIN_QUERIES {
        return None;
    }
    let gaps: Vec<f64> = times
        .windows(2)
        .map(|w| w[1].saturating_sub(w[0]) as f64 / 1e9)
        .collect();
    let mean = gaps.iter().sum::<f64>() / gaps.len() as f64;
    if mean <= 0.0 {
        return None;
    }
    let variance = gaps.iter().map(|g| (g - mean).powi(2)).sum::<f64>() / gaps.len() as f64;
    Some((mean, variance.sqrt() / mean))
}

fn top(mut items: Vec<(String, u64)>, n: usize) -> Vec<String> {
    items.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    items.into_iter().take(n).map(|(text, _)| text).collect()
}

#[must_use]
pub fn analyze(
    names: &[NameFacts<'_>],
    clients: &[ClientFacts<'_>],
    parents: &[ParentFacts<'_>],
) -> Vec<Finding> {
    let mut out: Vec<Finding> = [
        many_failures(clients),
        generated_subdomains(parents),
        long_names(names),
        regular_polling(names),
        changing_addresses(names),
        blocked_names(names),
    ]
    .into_iter()
    .flatten()
    .collect();
    out.sort_by(|a, b| b.severity.cmp(&a.severity).then_with(|| a.id.cmp(b.id)));
    out
}

#[allow(clippy::cast_precision_loss)]
fn many_failures(clients: &[ClientFacts<'_>]) -> Option<Finding> {
    let busy: Vec<(String, u64)> = clients
        .iter()
        .filter(|c| {
            c.nxdomain >= NX_HOST_MIN
                && c.nxdomain as f64 / c.queries.max(1) as f64 >= NX_HOST_SHARE
        })
        .map(|c| {
            (
                format!(
                    "{} ({} of {} lookups failed)",
                    c.client, c.nxdomain, c.queries
                ),
                c.nxdomain,
            )
        })
        .collect();
    (!busy.is_empty()).then(|| Finding {
        id: "many_failures",
        severity: Severity::Notice,
        title: "A host gets many \"no such name\" answers".to_owned(),
        detail: "Most of this host's lookups are for names that do not exist. That is what software looks like when it is misconfigured, probing for hosts, or generating names it hopes will resolve.".to_owned(),
        innocent: "A stale configuration, a retired service, or a search-domain suffix being tried first.",
        evidence: top(busy, 5),
    })
}

fn generated_subdomains(parents: &[ParentFacts<'_>]) -> Option<Finding> {
    let generated: Vec<(String, u64)> = parents
        .iter()
        .filter(|p| p.random_children >= RANDOM_CHILDREN)
        .map(|p| {
            (
                format!(
                    "{} ({} of {} subdomains seen look random)",
                    p.parent, p.random_children, p.children
                ),
                p.queries,
            )
        })
        .collect();
    (!generated.is_empty()).then(|| Finding {
        id: "generated_subdomains",
        severity: Severity::Notice,
        title: "Many random-looking subdomains under one domain".to_owned(),
        detail: "A domain is being asked for many different long, random-looking names. Malware that generates domains, and tools that smuggle data inside DNS names, look like this.".to_owned(),
        innocent: "Content delivery networks, cloud storage and tracking services generate such names routinely.",
        evidence: top(generated, 5),
    })
}

fn long_names(names: &[NameFacts<'_>]) -> Option<Finding> {
    let long: Vec<(String, u64)> = names
        .iter()
        .filter(|n| !n.reverse && n.name.len() >= LONG_NAME)
        .map(|n| (n.name.to_owned(), n.queries))
        .collect();
    (!long.is_empty()).then(|| Finding {
        id: "long_names",
        severity: Severity::Notice,
        title: "Unusually long DNS names".to_owned(),
        detail: format!("Names of {LONG_NAME} characters or more are rare in ordinary use. Data tunnelled through DNS is carried in names like these."),
        innocent: "Some tracking and anti-abuse services use long encoded names.",
        evidence: top(long, 5),
    })
}

fn regular_polling(names: &[NameFacts<'_>]) -> Option<Finding> {
    let regular: Vec<(String, u64)> = names
        .iter()
        .filter(|n| !n.reverse)
        .filter_map(|n| {
            let (mean, spread) = regularity(n.times)?;
            (mean >= BEACON_MIN_GAP_SECS && spread <= BEACON_MAX_SPREAD).then(|| {
                (
                    format!("{} (about every {})", n.name, every(mean)),
                    n.queries,
                )
            })
        })
        .collect();
    (!regular.is_empty()).then(|| Finding {
        id: "regular_polling",
        severity: Severity::Info,
        title: "A name is looked up at a steady rhythm".to_owned(),
        detail: "These names are asked for at nearly equal intervals. People do not behave that way; software that polls does, and so does malware checking in with its controller.".to_owned(),
        innocent: "Update checks, mail and chat clients, monitoring agents and time sync all poll.",
        evidence: top(regular, 5),
    })
}

fn changing_addresses(names: &[NameFacts<'_>]) -> Option<Finding> {
    let flux: Vec<(String, u64)> = names
        .iter()
        .filter(|n| {
            !n.reverse
                && n.addresses.len() >= FLUX_ADDRESSES
                && n.ttl.is_some_and(|t| t <= FLUX_MAX_TTL)
        })
        .map(|n| {
            (
                format!(
                    "{} ({} addresses, cached {} s)",
                    n.name,
                    n.addresses.len(),
                    n.ttl.unwrap_or(0)
                ),
                n.addresses.len() as u64,
            )
        })
        .collect();
    (!flux.is_empty()).then(|| Finding {
        id: "changing_addresses",
        severity: Severity::Info,
        title: "A name keeps changing address".to_owned(),
        detail: "These names resolved to many different addresses with a short cache time. Hosting that moves between machines, sometimes to evade blocking, looks like this.".to_owned(),
        innocent: "Load balancers and large content networks do exactly this.",
        evidence: top(flux, 5),
    })
}

fn blocked_names(names: &[NameFacts<'_>]) -> Option<Finding> {
    let blocked: Vec<(String, u64)> = names
        .iter()
        .filter(|n| n.blocked)
        .map(|n| (n.name.to_owned(), n.queries))
        .collect();
    (!blocked.is_empty()).then(|| Finding {
        id: "blocked_names",
        severity: Severity::Info,
        title: "The DNS server is blocking names".to_owned(),
        detail: format!("{} names were answered with an empty address (0.0.0.0), the way an ad or tracker blocklist answers.", blocked.len()),
        innocent: "A filtering resolver doing its job.",
        evidence: top(blocked, 5),
    })
}

fn every(seconds: f64) -> String {
    if seconds < 90.0 {
        format!("{seconds:.0} s")
    } else if seconds < 5400.0 {
        format!("{:.0} min", seconds / 60.0)
    } else {
        format!("{:.1} h", seconds / 3600.0)
    }
}

/// Two-label public suffixes common enough to matter: a name under
/// `example.co.uk` belongs to `example.co.uk`, not to `co.uk`.
const TWO_LEVEL_SUFFIXES: [&str; 14] = [
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.jp", "co.in", "co.nz",
    "com.br", "com.cn", "co.za", "com.mx",
];

/// The domain a name belongs to, approximately: its last two labels, or three
/// under a common two-label suffix. Without the full public suffix list this
/// is a heuristic, which is acceptable for grouping and is never shown as fact.
#[must_use]
pub fn parent_domain(name: &str) -> &str {
    let labels: Vec<&str> = name.split('.').collect();
    if labels.len() <= 2 {
        return name;
    }
    let last_two =
        &name[name.len() - (labels[labels.len() - 1].len() + 1 + labels[labels.len() - 2].len())..];
    let keep = if TWO_LEVEL_SUFFIXES.contains(&last_two) {
        3
    } else {
        2
    };
    let skip: usize = labels[..labels.len() - keep]
        .iter()
        .map(|l| l.len() + 1)
        .sum();
    &name[skip..]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name<'a>(n: &'a str, times: &'a [u64], addresses: &'a [String]) -> NameFacts<'a> {
        NameFacts {
            name: n,
            reverse: false,
            queries: times.len() as u64,
            ttl: Some(300),
            addresses,
            times,
            blocked: false,
        }
    }

    const SEC: u64 = 1_000_000_000;

    #[test]
    fn a_steady_rhythm_is_found_and_a_human_one_is_not() {
        let steady: Vec<u64> = (0..10).map(|i| i * 30 * SEC).collect();
        let (mean, spread) = regularity(&steady).unwrap();
        assert!((mean - 30.0).abs() < 1e-9 && spread < 1e-9);
        let ragged: Vec<u64> = [0, 4, 31, 33, 90, 95, 200, 203, 410, 460]
            .iter()
            .map(|s| s * SEC)
            .collect();
        assert!(regularity(&ragged).unwrap().1 > BEACON_MAX_SPREAD);
        assert_eq!(regularity(&steady[..4]), None);

        let found = analyze(&[name("poll.example.com", &steady, &[])], &[], &[]);
        assert_eq!(found[0].id, "regular_polling");
        assert!(found[0].evidence[0].contains("every 30 s"));
        let none = analyze(&[name("human.example.com", &ragged, &[])], &[], &[]);
        assert_eq!(none, Vec::new());
    }

    #[test]
    fn rapid_repeats_are_chatter_not_polling() {
        let fast: Vec<u64> = (0..12).map(|i| i * SEC / 2).collect();
        assert_eq!(
            analyze(&[name("a.example.com", &fast, &[])], &[], &[]),
            Vec::new()
        );
    }

    #[test]
    fn a_host_with_many_failures_is_flagged_only_past_both_thresholds() {
        let bad = ClientFacts {
            client: "10.0.0.5",
            queries: 50,
            nxdomain: 30,
        };
        let found = analyze(&[], &[bad], &[]);
        assert_eq!(found[0].id, "many_failures");
        assert!(found[0].evidence[0].contains("30 of 50"));
        let few = ClientFacts {
            client: "10.0.0.6",
            queries: 10,
            nxdomain: 9,
        };
        let mostly_fine = ClientFacts {
            client: "10.0.0.7",
            queries: 1000,
            nxdomain: 40,
        };
        assert_eq!(analyze(&[], &[few, mostly_fine], &[]), Vec::new());
    }

    #[test]
    fn generated_subdomains_and_long_names_are_flagged() {
        let parent = ParentFacts {
            parent: "tunnel.example",
            children: 30,
            random_children: 12,
            queries: 60,
        };
        let long_name = "a".repeat(LONG_NAME) + ".example.com";
        let found = analyze(&[name(&long_name, &[], &[])], &[], &[parent]);
        let ids: Vec<&str> = found.iter().map(|f| f.id).collect();
        assert!(ids.contains(&"generated_subdomains") && ids.contains(&"long_names"));
        let calm = ParentFacts {
            parent: "cdn.example",
            children: 40,
            random_children: 2,
            queries: 80,
        };
        assert_eq!(analyze(&[], &[], &[calm]), Vec::new());
    }

    #[test]
    fn many_addresses_with_a_short_cache_time_are_flagged() {
        let addrs: Vec<String> = (1..=7).map(|i| format!("192.0.2.{i}")).collect();
        let mut n = name("flux.example.com", &[], &addrs);
        n.ttl = Some(30);
        assert_eq!(analyze(&[n], &[], &[])[0].id, "changing_addresses");
        let mut slow = name("stable.example.com", &[], &addrs);
        slow.ttl = Some(3600);
        assert_eq!(analyze(&[slow], &[], &[]), Vec::new());
    }

    #[test]
    fn findings_are_ordered_by_importance_and_say_what_else_it_could_be() {
        let bad = ClientFacts {
            client: "10.0.0.5",
            queries: 50,
            nxdomain: 30,
        };
        let mut blocked = name("ads.example.com", &[], &[]);
        blocked.blocked = true;
        let found = analyze(&[blocked], &[bad], &[]);
        assert_eq!(found[0].severity, Severity::Notice);
        assert_eq!(found[1].id, "blocked_names");
        assert!(found.iter().all(|f| !f.innocent.is_empty()));
    }

    #[test]
    fn the_parent_domain_handles_common_two_label_suffixes() {
        assert_eq!(parent_domain("a.b.example.com"), "example.com");
        assert_eq!(parent_domain("example.com"), "example.com");
        assert_eq!(parent_domain("localhost"), "localhost");
        assert_eq!(parent_domain("www.shop.example.co.uk"), "example.co.uk");
        assert_eq!(parent_domain("x.y.z.tunnel.example"), "tunnel.example");
    }
}
