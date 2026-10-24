// © Pranav Verma | 2026
// observed.rs

//! What this sensor has actually seen, set against what the feed knows.
//!
//! The intelligence feed is a catalogue; on its own it says nothing about the
//! traffic in front of you. This reads the client fingerprints the sensor has
//! observed, asks the feed about each one now (so a label added a minute ago
//! counts), and reports how much of the traffic the feed can name. The
//! fingerprints it cannot name are the ones an operator is most likely to want
//! to label: a new browser build, an internal tool, a client the feed predates.

use anyhow::Result;
use rusqlite::{Connection, params};
use serde::Serialize;

use crate::infer::{ClientGuess, infer_client};
use crate::matcher::match_one;
use crate::model::{FpKind, MatchStrength, Verdict};

/// The most distinct client fingerprints one report covers.
const MAX_FINGERPRINTS: i64 = 500;

/// How much the feed knows about a fingerprint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Knowledge {
    /// An identical fingerprint is in the feed.
    Exact,
    /// Only a similar one is: the same cipher list, say, with other extensions.
    Partial,
    /// Nothing in the feed resembles it.
    Unknown,
}

/// One client fingerprint the sensor has seen.
#[derive(Debug, Clone, Serialize)]
pub struct ObservedClient {
    pub ja4: String,
    pub connections: i64,
    pub hosts: i64,
    pub first_ts: i64,
    pub last_ts: i64,
    /// The server names it was most often used to reach.
    pub sites: Vec<String>,
    pub knowledge: Knowledge,
    /// What the feed calls it (the exact hit, else the closest).
    pub label: Option<String>,
    pub source: Option<String>,
    pub verdict: Option<Verdict>,
    /// A family read from the handshake's shape, when the raw JA4 was kept.
    pub guess: Option<ClientGuess>,
}

/// How much of what was seen the feed can name.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Coverage {
    pub fingerprints: i64,
    pub exact: i64,
    pub partial: i64,
    pub unknown: i64,
    pub connections: i64,
    pub exact_connections: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct Observed {
    pub coverage: Coverage,
    pub clients: Vec<ObservedClient>,
}

pub(crate) fn report(conn: &Connection) -> Result<Observed> {
    let mut statement = conn.prepare(
        "SELECT fp_value, count(*), count(DISTINCT ip), min(ts), max(ts), max(fp_raw)
         FROM observation WHERE fp_kind = 'ja4'
         GROUP BY fp_value ORDER BY count(*) DESC LIMIT ?1",
    )?;
    let rows = statement
        .query_map(params![MAX_FINGERPRINTS], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, Option<String>>(5)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;

    let mut sites = conn.prepare(
        "SELECT sni FROM observation
         WHERE fp_kind = 'ja4' AND fp_value = ?1 AND sni IS NOT NULL
         GROUP BY sni ORDER BY count(*) DESC, sni LIMIT 3",
    )?;
    let mut coverage = Coverage::default();
    let mut clients = Vec::with_capacity(rows.len());
    for (ja4, connections, hosts, first_ts, last_ts, raw) in rows {
        let report = match_one(conn, FpKind::Ja4, &ja4)?;
        let exact = report
            .hits
            .iter()
            .find(|hit| hit.strength == MatchStrength::Exact);
        let knowledge = if exact.is_some() {
            Knowledge::Exact
        } else if report.has_hits() {
            Knowledge::Partial
        } else {
            Knowledge::Unknown
        };
        let named = exact.or_else(|| report.hits.first());
        coverage.fingerprints += 1;
        coverage.connections += connections;
        match knowledge {
            Knowledge::Exact => {
                coverage.exact += 1;
                coverage.exact_connections += connections;
            }
            Knowledge::Partial => coverage.partial += 1,
            Knowledge::Unknown => coverage.unknown += 1,
        }
        clients.push(ObservedClient {
            sites: sites
                .query_map(params![ja4], |row| row.get::<_, String>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?,
            knowledge,
            label: named.map(|hit| hit.label.clone()),
            source: named.map(|hit| hit.source.clone()),
            verdict: report.has_hits().then_some(report.verdict),
            guess: raw.as_deref().map(infer_client),
            ja4,
            connections,
            hosts,
            first_ts,
            last_ts,
        });
    }
    Ok(Observed { coverage, clients })
}

#[cfg(test)]
mod tests {
    use super::Knowledge;
    use crate::IntelStore;
    use crate::model::{Category, FpKind};
    use std::net::SocketAddr;
    use tlsfp_core::pipeline::event::StreamEvent;
    use tlsfp_core::{FingerprintEvent, Ja3, Ja4Family};

    fn hello(ja4: &str, raw: &str, sni: &str) -> FingerprintEvent {
        FingerprintEvent {
            ts_nanos: 1_000_000_000,
            src: "10.0.0.5:5000".parse::<SocketAddr>().unwrap(),
            dst: "1.2.3.4:443".parse::<SocketAddr>().unwrap(),
            event: StreamEvent::ClientHello {
                detail: None,
                ja3: Ja3::from_digest([1; 16]),
                ja3_raw: String::new(),
                ja4: Ja4Family::new(ja4.to_owned(), raw.to_owned()),
                sni: Some(sni.to_owned()),
                alpn: None,
            },
        }
    }

    #[test]
    fn unknown_fingerprints_are_listed_and_a_label_makes_them_known() {
        let mut store = IntelStore::open_in_memory().unwrap();
        let ja4 = "t13d1516h2_8daaf6152771_aaaaaaaaaaaa";
        let raw = "t13d1516h2_1301_0005,4469,000d_0403";
        store.detect(&hello(ja4, raw, "a.test")).unwrap();
        store.detect(&hello(ja4, raw, "a.test")).unwrap();

        let before = store.observed().unwrap();
        assert_eq!(before.coverage.fingerprints, 1);
        assert_eq!(before.coverage.unknown, 1);
        assert_eq!(before.clients[0].knowledge, Knowledge::Unknown);
        assert_eq!(before.clients[0].connections, 2);
        assert_eq!(before.clients[0].sites, vec!["a.test".to_owned()]);
        let guess = before.clients[0].guess.as_ref().expect("raw JA4 was kept");
        assert_eq!(guess.family, crate::ClientFamily::Chromium);

        store
            .add_label(FpKind::Ja4, ja4, "Brave on Windows", Category::Benign, None)
            .unwrap();
        let after = store.observed().unwrap();
        assert_eq!(after.coverage.exact, 1);
        assert_eq!(after.coverage.exact_connections, 2);
        assert_eq!(after.clients[0].label.as_deref(), Some("Brave on Windows"));
        assert_eq!(after.clients[0].source.as_deref(), Some("local labels"));
    }
}
