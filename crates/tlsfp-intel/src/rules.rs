// © Pranav Verma | 2026
// rules.rs

//! Detection rules written by the operator, in a TOML file.
//!
//! The built-in rules encode what the project's author thought worth catching.
//! An operator knows things the project cannot: which server names are
//! forbidden on this network, which client families should never reach the
//! payment hosts, which subnet must not speak TLS 1.0. A rule says so:
//!
//! ```toml
//! [[rule]]
//! name = "dynamic-dns"
//! description = "TLS to a dynamic DNS provider"
//! severity = "medium"
//! once_per = "address"
//!
//! [rule.when]
//! event = ["client_hello"]
//! sni_glob = ["*.duckdns.org", "*.ddns.net"]
//!
//! [rule.unless]
//! src_network = ["10.9.0.0/16"]
//! ```
//!
//! Within a condition, the list is any-of; across conditions, all must hold.
//! `unless` has the same fields and vetoes the rule. A file with an unknown
//! key, an unknown value or a rule with no condition is refused whole, with
//! the rule's name in the message, so a typo can never become a rule that
//! silently never fires.
//!
//! Alerts from this file carry the rule name in the title and the rule `custom`.
//! The `once_per` setting keeps a beacon from raising one alert per flow.

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Mutex;

use serde::Deserialize;
use tlsfp_core::FingerprintEvent;
use tlsfp_core::pipeline::event::StreamEvent;

use crate::detect::{Alert, AlertSeverity, Rule};
use crate::infer::{ClientFamily, infer_client};
use crate::model::{FpKind, MatchReport, Verdict};
use crate::net::Network;

/// How many distinct firing keys are remembered before the set is reset, a
/// guard against unbounded memory on a very long run.
const MAX_REMEMBERED: usize = 200_000;

const EVENTS: &[&str] = &[
    "client_hello",
    "server_hello",
    "certificate",
    "http_request",
    "tcp_syn",
    "tcp_syn_ack",
];

const FAMILIES: &[&str] = &[
    "chromium",
    "firefox",
    "safari_like",
    "open_ssl",
    "library",
    "unknown",
];

const VERDICTS: &[&str] = &["malicious", "suspicious", "benign", "unknown"];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileDef {
    #[serde(default)]
    rule: Vec<RuleDef>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleDef {
    name: String,
    description: Option<String>,
    severity: Option<String>,
    once_per: Option<String>,
    when: Conditions,
    #[serde(default)]
    unless: Conditions,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
struct Conditions {
    event: Vec<String>,
    sni_glob: Vec<String>,
    sni_present: Option<bool>,
    host_glob: Vec<String>,
    user_agent_contains: Vec<String>,
    ja3: Vec<String>,
    ja4: Vec<String>,
    ja4_prefix: Vec<String>,
    ja3s: Vec<String>,
    ja4s: Vec<String>,
    ja4h: Vec<String>,
    ja4x: Vec<String>,
    ja4t: Vec<String>,
    ja4ts: Vec<String>,
    family: Vec<String>,
    verdict: Vec<String>,
    alpn: Vec<String>,
    transport: Vec<String>,
    tls_version: Vec<String>,
    has_extension: Vec<String>,
    lacks_extension: Vec<String>,
    src_network: Vec<String>,
    dst_network: Vec<String>,
    dst_port: Vec<u16>,
}

impl Conditions {
    fn is_empty(&self) -> bool {
        self.event.is_empty()
            && self.sni_glob.is_empty()
            && self.sni_present.is_none()
            && self.host_glob.is_empty()
            && self.user_agent_contains.is_empty()
            && self.ja3.is_empty()
            && self.ja4.is_empty()
            && self.ja4_prefix.is_empty()
            && self.ja3s.is_empty()
            && self.ja4s.is_empty()
            && self.ja4h.is_empty()
            && self.ja4x.is_empty()
            && self.ja4t.is_empty()
            && self.ja4ts.is_empty()
            && self.family.is_empty()
            && self.verdict.is_empty()
            && self.alpn.is_empty()
            && self.transport.is_empty()
            && self.tls_version.is_empty()
            && self.has_extension.is_empty()
            && self.lacks_extension.is_empty()
            && self.src_network.is_empty()
            && self.dst_network.is_empty()
            && self.dst_port.is_empty()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OncePer {
    Event,
    Address,
    Fingerprint,
    AddressAndFingerprint,
    Rule,
}

/// A validated rule.
#[derive(Debug)]
struct CustomRule {
    name: String,
    description: Option<String>,
    severity: AlertSeverity,
    once_per: OncePer,
    when: Compiled,
    unless: Compiled,
}

/// Conditions with their values lower-cased and their networks parsed.
#[derive(Debug, Default)]
struct Compiled {
    raw: Conditions,
    src: Vec<Network>,
    dst: Vec<Network>,
}

/// What a rule can see of one event.
struct View<'a> {
    event: &'static str,
    src: IpAddr,
    dst: IpAddr,
    dst_port: u16,
    sni: Option<&'a str>,
    alpn: Option<&'a str>,
    host: Option<&'a str>,
    user_agent: Option<&'a str>,
    fingerprints: Vec<(&'static str, String)>,
    ja4_raw: Option<&'a str>,
    family: Option<&'static str>,
    verdict: &'static str,
}

fn family_token(family: ClientFamily) -> &'static str {
    match family {
        ClientFamily::Chromium => "chromium",
        ClientFamily::Firefox => "firefox",
        ClientFamily::SafariLike => "safari_like",
        ClientFamily::OpenSsl => "open_ssl",
        ClientFamily::Library => "library",
        ClientFamily::Unknown => "unknown",
    }
}

fn view<'a>(event: &'a FingerprintEvent, reports: &[MatchReport]) -> View<'a> {
    let mut v = View {
        event: "",
        src: event.src.ip(),
        dst: event.dst.ip(),
        dst_port: event.dst.port(),
        sni: None,
        alpn: None,
        host: None,
        user_agent: None,
        fingerprints: Vec::new(),
        ja4_raw: None,
        family: None,
        verdict: worst_verdict(reports),
    };
    match &event.event {
        StreamEvent::ClientHello {
            ja3,
            ja4,
            sni,
            alpn,
            ..
        } => {
            v.event = "client_hello";
            v.sni = sni.as_deref();
            v.alpn = alpn.as_deref();
            v.fingerprints = vec![("ja3", ja3.to_string()), ("ja4", ja4.hash.clone())];
            v.ja4_raw = Some(ja4.raw.as_str());
            v.family = Some(family_token(infer_client(&ja4.raw).family));
        }
        StreamEvent::ServerHello { ja3s, ja4s, .. } => {
            v.event = "server_hello";
            v.fingerprints = vec![("ja3s", ja3s.to_string()), ("ja4s", ja4s.hash.clone())];
        }
        StreamEvent::Certificate { ja4x } => {
            v.event = "certificate";
            v.fingerprints = vec![("ja4x", ja4x.clone())];
        }
        StreamEvent::HttpRequest {
            ja4h,
            host,
            user_agent,
            ..
        } => {
            v.event = "http_request";
            v.host = host.as_deref();
            v.user_agent = user_agent.as_deref();
            v.fingerprints = vec![("ja4h", ja4h.hash.clone())];
        }
        StreamEvent::TcpSyn { ja4t } => {
            v.event = "tcp_syn";
            v.fingerprints = vec![("ja4t", ja4t.clone())];
        }
        StreamEvent::TcpSynAck { ja4ts } => {
            v.event = "tcp_syn_ack";
            v.fingerprints = vec![("ja4ts", ja4ts.clone())];
        }
    }
    v
}

fn worst_verdict(reports: &[MatchReport]) -> &'static str {
    let rank = |v: Verdict| match v {
        Verdict::Malicious => 3,
        Verdict::Suspicious => 2,
        Verdict::Benign => 1,
        Verdict::Unknown => 0,
    };
    reports
        .iter()
        .map(|r| r.verdict)
        .max_by_key(|v| rank(*v))
        .map_or("unknown", Verdict::as_str)
}

/// Case-insensitive match of `text` against a pattern whose only wildcard is
/// `*`, which stands for any run of characters, including none.
fn glob(pattern: &str, text: &str) -> bool {
    let pattern = pattern.to_ascii_lowercase();
    let text = text.to_ascii_lowercase();
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() == 1 {
        return pattern == text;
    }
    let (first, rest) = parts.split_first().unwrap_or((&"", &[]));
    let Some(mut remaining) = text.strip_prefix(first) else {
        return false;
    };
    let Some((last, middle)) = rest.split_last() else {
        return true;
    };
    for part in middle {
        match remaining.find(part) {
            Some(at) => remaining = &remaining[at + part.len()..],
            None => return false,
        }
    }
    remaining.ends_with(last)
}

fn any_eq(list: &[String], value: Option<&str>) -> bool {
    value.is_some_and(|v| list.iter().any(|item| item.eq_ignore_ascii_case(v)))
}

impl Compiled {
    /// Whether every stated condition holds. Records what matched, for the
    /// alert's explanation.
    fn matches(&self, v: &View<'_>, why: &mut Vec<String>) -> bool {
        let c = &self.raw;
        let mut note = |text: String| why.push(text);

        if !c.event.is_empty() {
            if !c.event.iter().any(|e| e == v.event) {
                return false;
            }
            note(format!("event={}", v.event));
        }
        if !c.sni_glob.is_empty() {
            let Some(sni) = v.sni else { return false };
            if !c.sni_glob.iter().any(|p| glob(p, sni)) {
                return false;
            }
            note(format!("sni={sni}"));
        }
        if let Some(want) = c.sni_present {
            if want != v.sni.is_some() {
                return false;
            }
            note(format!("sni_present={want}"));
        }
        if !c.host_glob.is_empty() {
            let Some(host) = v.host else { return false };
            if !c.host_glob.iter().any(|p| glob(p, host)) {
                return false;
            }
            note(format!("host={host}"));
        }
        if !c.user_agent_contains.is_empty() {
            let Some(agent) = v.user_agent else {
                return false;
            };
            let lower = agent.to_ascii_lowercase();
            if !c
                .user_agent_contains
                .iter()
                .any(|needle| lower.contains(&needle.to_ascii_lowercase()))
            {
                return false;
            }
            note("user_agent matched".to_owned());
        }
        if !self.matches_identity(v, &mut note) {
            return false;
        }
        if !self.matches_ja4_shape(v, &mut note) {
            return false;
        }
        self.matches_network(v, &mut note)
    }

    /// The conditions on who is talking to whom.
    fn matches_network(&self, v: &View<'_>, note: &mut impl FnMut(String)) -> bool {
        let c = &self.raw;
        if !c.src_network.is_empty() {
            if !self.src.iter().any(|n| n.contains(v.src)) {
                return false;
            }
            note(format!("src={}", v.src));
        }
        if !c.dst_network.is_empty() {
            if !self.dst.iter().any(|n| n.contains(v.dst)) {
                return false;
            }
            note(format!("dst={}", v.dst));
        }
        if !c.dst_port.is_empty() {
            if !c.dst_port.contains(&v.dst_port) {
                return false;
            }
            note(format!("dst_port={}", v.dst_port));
        }
        true
    }

    /// The conditions on which fingerprint, family and verdict the event carries.
    fn matches_identity(&self, v: &View<'_>, note: &mut impl FnMut(String)) -> bool {
        let c = &self.raw;
        for (kind, list) in [
            ("ja3", &c.ja3),
            ("ja4", &c.ja4),
            ("ja3s", &c.ja3s),
            ("ja4s", &c.ja4s),
            ("ja4h", &c.ja4h),
            ("ja4x", &c.ja4x),
            ("ja4t", &c.ja4t),
            ("ja4ts", &c.ja4ts),
        ] {
            if list.is_empty() {
                continue;
            }
            let value = v
                .fingerprints
                .iter()
                .find(|(k, _)| *k == kind)
                .map(|(_, value)| value.as_str());
            if !any_eq(list, value) {
                return false;
            }
            note(format!("{kind}={}", value.unwrap_or_default()));
        }
        if !c.ja4_prefix.is_empty() {
            let Some(ja4) = v.fingerprints.iter().find(|(k, _)| *k == "ja4") else {
                return false;
            };
            if !c.ja4_prefix.iter().any(|p| ja4.1.starts_with(p.as_str())) {
                return false;
            }
            note(format!("ja4={}", ja4.1));
        }
        if !c.family.is_empty() {
            if !any_eq(&c.family, v.family) {
                return false;
            }
            note(format!("family={}", v.family.unwrap_or_default()));
        }
        if !c.verdict.is_empty() {
            if !any_eq(&c.verdict, Some(v.verdict)) {
                return false;
            }
            note(format!("verdict={}", v.verdict));
        }
        if !c.alpn.is_empty() {
            if !any_eq(&c.alpn, v.alpn) {
                return false;
            }
            note(format!("alpn={}", v.alpn.unwrap_or_default()));
        }
        true
    }

    /// The conditions that read the JA4 string: transport, TLS version and
    /// the extensions offered.
    fn matches_ja4_shape(&self, v: &View<'_>, note: &mut impl FnMut(String)) -> bool {
        let c = &self.raw;
        if c.transport.is_empty()
            && c.tls_version.is_empty()
            && c.has_extension.is_empty()
            && c.lacks_extension.is_empty()
        {
            return true;
        }
        let Some(ja4) = v
            .fingerprints
            .iter()
            .find(|(k, _)| *k == "ja4")
            .map(|f| f.1.as_str())
        else {
            return false;
        };
        if !c.transport.is_empty() {
            let transport = match ja4.chars().next() {
                Some('q') => "quic",
                Some('d') => "dtls",
                _ => "tcp",
            };
            if !any_eq(&c.transport, Some(transport)) {
                return false;
            }
            note(format!("transport={transport}"));
        }
        if !c.tls_version.is_empty() {
            let version = ja4.get(1..3);
            if !any_eq(&c.tls_version, version) {
                return false;
            }
            note(format!("tls_version={}", version.unwrap_or_default()));
        }
        let extensions: Vec<&str> = v
            .ja4_raw
            .and_then(|raw| raw.split('_').nth(2))
            .map(|list| list.split(',').collect())
            .unwrap_or_default();
        for want in &c.has_extension {
            if !extensions.iter().any(|e| e.eq_ignore_ascii_case(want)) {
                return false;
            }
            note(format!("has_extension={want}"));
        }
        for avoid in &c.lacks_extension {
            if extensions.iter().any(|e| e.eq_ignore_ascii_case(avoid)) {
                return false;
            }
            note(format!("lacks_extension={avoid}"));
        }
        true
    }
}

fn lower_all(list: &mut [String]) {
    for item in list {
        *item = item.trim().to_ascii_lowercase();
    }
}

fn compile(name: &str, section: &str, mut c: Conditions) -> Result<Compiled, String> {
    let err = |msg: String| format!("rule '{name}' ({section}): {msg}");
    for list in [
        &mut c.event,
        &mut c.family,
        &mut c.verdict,
        &mut c.transport,
        &mut c.tls_version,
        &mut c.has_extension,
        &mut c.lacks_extension,
    ] {
        lower_all(list);
    }
    for (field, list, allowed) in [
        ("event", &c.event, EVENTS),
        ("family", &c.family, FAMILIES),
        ("verdict", &c.verdict, VERDICTS),
        ("transport", &c.transport, &["tcp", "quic", "dtls"][..]),
    ] {
        if let Some(bad) = list.iter().find(|v| !allowed.contains(&v.as_str())) {
            return Err(err(format!(
                "'{bad}' is not a valid {field}; use one of {}",
                allowed.join(", ")
            )));
        }
    }
    let parse = |list: &[String], field: &str| -> Result<Vec<Network>, String> {
        list.iter()
            .map(|text| {
                text.parse::<Network>()
                    .map_err(|e| err(format!("{field}: {e}")))
            })
            .collect()
    };
    let src = parse(&c.src_network, "src_network")?;
    let dst = parse(&c.dst_network, "dst_network")?;
    for pattern in c.sni_glob.iter().chain(&c.host_glob) {
        if pattern.is_empty() {
            return Err(err("an empty glob pattern".into()));
        }
    }
    Ok(Compiled { raw: c, src, dst })
}

/// The rules loaded from a file, with the memory `once_per` needs.
#[derive(Debug)]
pub struct RuleSet {
    rules: Vec<CustomRule>,
    fired: Mutex<HashSet<String>>,
}

impl RuleSet {
    /// Parses and validates a rules file's text.
    pub fn parse(text: &str) -> Result<Self, String> {
        let file: FileDef = toml::from_str(text).map_err(|e| e.to_string())?;
        let mut names = HashSet::new();
        let mut rules = Vec::new();
        for def in file.rule {
            let name = def.name.trim().to_owned();
            if name.is_empty() {
                return Err("a rule has an empty name".into());
            }
            if !names.insert(name.clone()) {
                return Err(format!("two rules are named '{name}'"));
            }
            if def.when.is_empty() {
                return Err(format!(
                    "rule '{name}' has no condition under [rule.when]; a rule that matches everything is almost certainly a mistake"
                ));
            }
            let severity = match def.severity.as_deref().unwrap_or("medium") {
                "info" => AlertSeverity::Info,
                "low" => AlertSeverity::Low,
                "medium" => AlertSeverity::Medium,
                "high" => AlertSeverity::High,
                "critical" => AlertSeverity::Critical,
                other => {
                    return Err(format!(
                        "rule '{name}': '{other}' is not a severity; use info, low, medium, high or critical"
                    ));
                }
            };
            let once_per = match def.once_per.as_deref().unwrap_or("address_and_fingerprint") {
                "event" => OncePer::Event,
                "address" => OncePer::Address,
                "fingerprint" => OncePer::Fingerprint,
                "address_and_fingerprint" => OncePer::AddressAndFingerprint,
                "rule" => OncePer::Rule,
                other => {
                    return Err(format!(
                        "rule '{name}': '{other}' is not a once_per value; use event, address, fingerprint, address_and_fingerprint or rule"
                    ));
                }
            };
            let when = compile(&name, "when", def.when)?;
            let unless = compile(&name, "unless", def.unless)?;
            rules.push(CustomRule {
                name,
                description: def.description,
                severity,
                once_per,
                when,
                unless,
            });
        }
        Ok(Self {
            rules,
            fired: Mutex::new(HashSet::new()),
        })
    }

    /// Reads and validates a rules file.
    pub fn load(path: &std::path::Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("reading {}: {e}", path.display()))?;
        Self::parse(&text).map_err(|e| format!("{}: {e}", path.display()))
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Names and severities, for a summary line.
    #[must_use]
    pub fn names(&self) -> Vec<(String, AlertSeverity)> {
        self.rules
            .iter()
            .map(|r| (r.name.clone(), r.severity))
            .collect()
    }

    /// The alerts this event raises under the loaded rules.
    pub(crate) fn evaluate(
        &self,
        event: &FingerprintEvent,
        reports: &[MatchReport],
        kind: FpKind,
        value: &str,
    ) -> Vec<Alert> {
        let v = view(event, reports);
        let mut alerts = Vec::new();
        for rule in &self.rules {
            let mut why = Vec::new();
            if !rule.when.matches(&v, &mut why) {
                continue;
            }
            if !rule.unless.raw_is_empty() && rule.unless.matches(&v, &mut Vec::new()) {
                continue;
            }
            let ip = v.src.to_string();
            let key = match rule.once_per {
                OncePer::Event => None,
                OncePer::Rule => Some(rule.name.clone()),
                OncePer::Address => Some(format!("{}|{ip}", rule.name)),
                OncePer::Fingerprint => Some(format!("{}|{value}", rule.name)),
                OncePer::AddressAndFingerprint => Some(format!("{}|{ip}|{value}", rule.name)),
            };
            if let Some(key) = key {
                let mut fired = self
                    .fired
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if fired.len() >= MAX_REMEMBERED {
                    fired.clear();
                }
                if !fired.insert(key) {
                    continue;
                }
            }
            let mut detail = rule.description.clone().unwrap_or_default();
            if !detail.is_empty() {
                detail.push(' ');
            }
            detail.push_str("[matched: ");
            detail.push_str(&why.join(", "));
            detail.push(']');
            alerts.push(Alert {
                ts_nanos: 0,
                rule: Rule::Custom,
                severity: rule.severity,
                ip: Some(ip),
                fp_kind: Some(kind),
                fp_value: Some(value.to_owned()),
                title: rule.name.clone(),
                detail,
                score: None,
            });
        }
        alerts
    }
}

impl Compiled {
    fn raw_is_empty(&self) -> bool {
        self.raw.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob_handles_prefix_suffix_and_middle_wildcards() {
        assert!(glob("*.duckdns.org", "evil.DuckDNS.org"));
        assert!(!glob("*.duckdns.org", "duckdns.org"));
        assert!(glob("login.*", "login.example.com"));
        assert!(glob("a*c*e", "abcde"));
        assert!(!glob("a*c*e", "abde"));
        assert!(glob("*", "anything"));
        assert!(glob("exact.test", "EXACT.test"));
        assert!(!glob("exact.test", "exact.test.evil"));
    }

    #[test]
    fn a_valid_file_loads() {
        let rules = RuleSet::parse(
            r#"
            [[rule]]
            name = "ddns"
            severity = "high"
            once_per = "address"
            [rule.when]
            event = ["client_hello"]
            sni_glob = ["*.duckdns.org"]
            [rule.unless]
            src_network = ["10.9.0.0/16"]
            "#,
        )
        .unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules.names()[0].1, AlertSeverity::High);
    }

    fn refuses(text: &str, needle: &str) {
        let error = RuleSet::parse(text).unwrap_err();
        assert!(
            error.contains(needle),
            "'{error}' should mention '{needle}'"
        );
    }

    #[test]
    fn mistakes_are_refused_with_the_rule_named() {
        refuses(
            "[[rule]]\nname='x'\n[rule.when]\nsni_glob=['a']\nbogus=1",
            "bogus",
        );
        refuses(
            "[[rule]]\nname='x'\n[rule.when]\nevent=['hello']",
            "'hello' is not a valid event",
        );
        refuses(
            "[[rule]]\nname='x'\n[rule.when]\nfamily=['browser']",
            "not a valid family",
        );
        refuses(
            "[[rule]]\nname='x'\nseverity='urgent'\n[rule.when]\nevent=['client_hello']",
            "not a severity",
        );
        refuses(
            "[[rule]]\nname='x'\n[rule.when]\nsrc_network=['not-a-net']",
            "src_network",
        );
        refuses("[[rule]]\nname='x'\n[rule.when]\n", "no condition");
        refuses(
            "[[rule]]\nname='x'\n[rule.when]\nevent=['client_hello']\n[[rule]]\nname='x'\n[rule.when]\nevent=['client_hello']",
            "two rules are named 'x'",
        );
    }

    #[test]
    fn once_per_keeps_a_repeat_from_alerting_twice() {
        use std::net::SocketAddr;
        use tlsfp_core::{Ja3, Ja4Family};
        let rules = RuleSet::parse(
            "[[rule]]\nname='r'\nonce_per='address'\n[rule.when]\nsni_glob=['*.bad.test']",
        )
        .unwrap();
        let event = |sni: &str| FingerprintEvent {
            ts_nanos: 1,
            src: "10.0.0.5:5000".parse::<SocketAddr>().unwrap(),
            dst: "1.2.3.4:443".parse::<SocketAddr>().unwrap(),
            event: StreamEvent::ClientHello {
                ja3: Ja3::from_digest([7; 16]),
                ja3_raw: String::new(),
                ja4: Ja4Family::new(
                    "t13d1516h2_aaaaaaaaaaaa_bbbbbbbbbbbb".into(),
                    "t13d1516h2_1301_0005,44cd_0403".into(),
                ),
                sni: Some(sni.to_owned()),
                alpn: Some("h2".into()),
            },
        };
        let first = rules.evaluate(
            &event("x.bad.test"),
            &[],
            FpKind::Ja4,
            "t13d1516h2_aaaaaaaaaaaa_bbbbbbbbbbbb",
        );
        assert_eq!(first.len(), 1);
        assert!(first[0].detail.contains("sni=x.bad.test"));
        let again = rules.evaluate(
            &event("y.bad.test"),
            &[],
            FpKind::Ja4,
            "t13d1516h2_aaaaaaaaaaaa_bbbbbbbbbbbb",
        );
        assert_eq!(again.len(), 0, "same address, same rule: once");
        let other = rules.evaluate(
            &event("fine.test"),
            &[],
            FpKind::Ja4,
            "t13d1516h2_aaaaaaaaaaaa_bbbbbbbbbbbb",
        );
        assert_eq!(other.len(), 0, "no match, no alert");
    }
}
