// © Pranav Verma | 2026
// hosts.rs

//! What the sensor has learned about each address over time.
//!
//! Detection records an observation for every fingerprint an address presents.
//! Read back by address, that history answers the questions a list of alerts
//! cannot: which clients does this host run, when did each first appear, did a
//! new one show up after weeks of quiet, which servers does it talk to. A host
//! whose fingerprint set changes (a new browser, a new tool) is the thing worth
//! looking at, and the profile makes the change visible without a rule having
//! to fire.
//!
//! Observations exist only where detection ran (`--detect`, or `serve` with a
//! live or replay feed). Addresses are the source addresses of the handshakes,
//! so a NAT gateway is one host here, with many clients.

use anyhow::Result;
use rusqlite::{Connection, params};
use serde::Serialize;

use crate::detect::{Alert, for_address};
use crate::model::Verdict;

/// How many ClientHello observations a profile reads, newest kept, a guard
/// against an address that has handshaken millions of times.
const MAX_ROWS: i64 = 50_000;

/// One line of the host list.
#[derive(Debug, Clone, Serialize)]
pub struct HostSummary {
    pub ip: String,
    pub first_ts: i64,
    pub last_ts: i64,
    pub observations: i64,
    /// Distinct client fingerprints (JA4).
    pub clients: i64,
    /// Distinct server names asked for.
    pub servers: i64,
    pub alerts: i64,
    /// The worst verdict among the client fingerprints.
    pub verdict: Option<Verdict>,
    /// The label of the busiest client fingerprint that has one.
    pub top_label: Option<String>,
}

/// One client fingerprint's life on a host.
#[derive(Debug, Clone, Serialize)]
pub struct ClientSpan {
    pub ja4: String,
    pub label: Option<String>,
    pub verdict: Option<Verdict>,
    pub first_ts: i64,
    pub last_ts: i64,
    pub count: i64,
    pub servers: Vec<String>,
}

/// A name and how often it was seen.
#[derive(Debug, Clone, Serialize)]
pub struct Counted {
    pub value: String,
    pub count: i64,
}

/// Everything known about one address.
#[derive(Debug, Clone, Serialize)]
pub struct HostProfile {
    pub summary: HostSummary,
    /// Client fingerprints, in the order they first appeared.
    pub clients: Vec<ClientSpan>,
    pub servers: Vec<Counted>,
    pub user_agents: Vec<Counted>,
    pub os_claims: Vec<Counted>,
    pub alerts: Vec<Alert>,
}

fn verdict_rank(token: Option<&str>) -> u8 {
    match token {
        Some("malicious") => 3,
        Some("suspicious") => 2,
        Some("benign") => 1,
        _ => 0,
    }
}

fn verdict_of(token: Option<&str>) -> Option<Verdict> {
    match token? {
        "malicious" => Some(Verdict::Malicious),
        "suspicious" => Some(Verdict::Suspicious),
        "benign" => Some(Verdict::Benign),
        "unknown" => Some(Verdict::Unknown),
        _ => None,
    }
}

/// Which addresses a host list covers.
///
/// A ServerHello is observed from the server's address, so without this every
/// site a client talked to would appear as a "host" with no clients of its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HostRole {
    /// Addresses that originated handshakes or requests: the machines whose
    /// behaviour is being watched. The default.
    #[default]
    Clients,
    /// Addresses seen only answering.
    Servers,
    All,
}

impl HostRole {
    /// Parses `clients`, `servers` or `all`; anything else is the default.
    #[must_use]
    pub fn from_token(token: &str) -> Self {
        match token {
            "servers" => Self::Servers,
            "all" => Self::All,
            _ => Self::Clients,
        }
    }
}

/// The hosts seen, most recently active first, at most `limit`.
pub(crate) fn list(conn: &Connection, limit: i64, role: HostRole) -> Result<Vec<HostSummary>> {
    // Client-side fingerprints are made by the sender of a request; server-side
    // ones by the sender of an answer.
    let filter = match role {
        HostRole::All => "",
        HostRole::Clients => "HAVING sum(fp_kind IN ('ja4', 'ja3', 'ja4h', 'ja4t')) > 0",
        HostRole::Servers => "HAVING sum(fp_kind IN ('ja4', 'ja3', 'ja4h', 'ja4t')) = 0",
    };
    let mut statement = conn.prepare(&format!(
        "SELECT ip, min(ts), max(ts), count(*),
                count(DISTINCT CASE WHEN fp_kind = 'ja4' THEN fp_value END),
                count(DISTINCT sni)
         FROM observation GROUP BY ip {filter} ORDER BY max(ts) DESC LIMIT ?1"
    ))?;
    let base = statement
        .query_map(params![limit], |row| {
            Ok(HostSummary {
                ip: row.get(0)?,
                first_ts: row.get(1)?,
                last_ts: row.get(2)?,
                observations: row.get(3)?,
                clients: row.get(4)?,
                servers: row.get(5)?,
                alerts: 0,
                verdict: None,
                top_label: None,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;

    let mut alerts = conn.prepare("SELECT count(*) FROM alert WHERE ip = ?1")?;
    let mut clients = conn.prepare(
        "SELECT verdict, label, count(*) FROM observation
         WHERE ip = ?1 AND fp_kind = 'ja4' GROUP BY fp_value ORDER BY count(*) DESC",
    )?;
    let mut out = Vec::with_capacity(base.len());
    for mut host in base {
        host.alerts = alerts.query_row(params![host.ip], |row| row.get(0))?;
        let rows = clients
            .query_map(params![host.ip], |row| {
                Ok((
                    row.get::<_, Option<String>>(0)?,
                    row.get::<_, Option<String>>(1)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let worst = rows
            .iter()
            .map(|(verdict, _)| verdict.as_deref())
            .max_by_key(|v| verdict_rank(*v));
        host.verdict = verdict_of(worst.flatten());
        host.top_label = rows.into_iter().find_map(|(_, label)| label);
        out.push(host);
    }
    Ok(out)
}

fn counted(conn: &Connection, sql: &str, ip: &str) -> Result<Vec<Counted>> {
    let mut statement = conn.prepare(sql)?;
    let rows = statement
        .query_map(params![ip], |row| {
            Ok(Counted {
                value: row.get(0)?,
                count: row.get(1)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

/// The profile of one address, or `None` when nothing was observed from it.
pub(crate) fn profile(conn: &Connection, ip: &str) -> Result<Option<HostProfile>> {
    let Some(mut summary) = list_one(conn, ip)? else {
        return Ok(None);
    };

    let mut statement = conn.prepare(
        "SELECT fp_value, max(label), max(verdict), count(*), min(ts), max(ts)
         FROM (SELECT * FROM observation WHERE ip = ?1 AND fp_kind = 'ja4'
               ORDER BY ts DESC LIMIT ?2)
         GROUP BY fp_value ORDER BY min(ts)",
    )?;
    let mut clients = statement
        .query_map(params![ip, MAX_ROWS], |row| {
            let verdict: Option<String> = row.get(2)?;
            Ok(ClientSpan {
                ja4: row.get(0)?,
                label: row.get(1)?,
                verdict: verdict_of(verdict.as_deref()),
                count: row.get(3)?,
                first_ts: row.get(4)?,
                last_ts: row.get(5)?,
                servers: Vec::new(),
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;

    let mut names = conn.prepare(
        "SELECT sni FROM observation WHERE ip = ?1 AND fp_kind = 'ja4' AND fp_value = ?2
           AND sni IS NOT NULL GROUP BY sni ORDER BY count(*) DESC LIMIT 4",
    )?;
    for client in &mut clients {
        client.servers = names
            .query_map(params![ip, client.ja4], |row| row.get(0))?
            .collect::<rusqlite::Result<Vec<String>>>()?;
    }

    summary.alerts = i64::try_from(for_address(conn, ip, 10_000)?.len()).unwrap_or(0);
    Ok(Some(HostProfile {
        servers: counted(
            conn,
            "SELECT sni, count(*) FROM observation WHERE ip = ?1 AND sni IS NOT NULL
             GROUP BY sni ORDER BY count(*) DESC LIMIT 25",
            ip,
        )?,
        user_agents: counted(
            conn,
            "SELECT user_agent, count(*) FROM observation WHERE ip = ?1 AND user_agent IS NOT NULL
             GROUP BY user_agent ORDER BY count(*) DESC LIMIT 10",
            ip,
        )?,
        os_claims: counted(
            conn,
            "SELECT os_claim, count(*) FROM observation WHERE ip = ?1 AND os_claim IS NOT NULL
             GROUP BY os_claim ORDER BY count(*) DESC LIMIT 10",
            ip,
        )?,
        alerts: for_address(conn, ip, 100)?,
        summary,
        clients,
    }))
}

fn list_one(conn: &Connection, ip: &str) -> Result<Option<HostSummary>> {
    // The list query ordered by recency is the same shape; reuse it on one row.
    let mut statement = conn.prepare(
        "SELECT min(ts), max(ts), count(*),
                count(DISTINCT CASE WHEN fp_kind = 'ja4' THEN fp_value END),
                count(DISTINCT sni)
         FROM observation WHERE ip = ?1",
    )?;
    let row = statement.query_row(params![ip], |row| {
        Ok((
            row.get::<_, Option<i64>>(0)?,
            row.get::<_, Option<i64>>(1)?,
            row.get::<_, i64>(2)?,
            row.get::<_, i64>(3)?,
            row.get::<_, i64>(4)?,
        ))
    })?;
    let (Some(first_ts), Some(last_ts)) = (row.0, row.1) else {
        return Ok(None);
    };
    let mut verdicts = conn.prepare(
        "SELECT verdict, label FROM observation WHERE ip = ?1 AND fp_kind = 'ja4'
         GROUP BY fp_value ORDER BY count(*) DESC",
    )?;
    let rows = verdicts
        .query_map(params![ip], |row| {
            Ok((
                row.get::<_, Option<String>>(0)?,
                row.get::<_, Option<String>>(1)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let worst = rows
        .iter()
        .map(|(verdict, _)| verdict.as_deref())
        .max_by_key(|v| verdict_rank(*v))
        .flatten();
    Ok(Some(HostSummary {
        ip: ip.to_owned(),
        first_ts,
        last_ts,
        observations: row.2,
        clients: row.3,
        servers: row.4,
        alerts: 0,
        verdict: verdict_of(worst),
        top_label: rows.into_iter().find_map(|(_, label)| label),
    }))
}

#[cfg(test)]
mod tests {
    use super::HostRole;
    use crate::IntelStore;
    use std::net::SocketAddr;
    use tlsfp_core::pipeline::event::StreamEvent;
    use tlsfp_core::{FingerprintEvent, Ja3, Ja4Family};

    fn hello(ts: u64, src: &str, ja4: &str, sni: &str) -> FingerprintEvent {
        FingerprintEvent {
            ts_nanos: ts,
            src: src.parse::<SocketAddr>().unwrap(),
            dst: "1.2.3.4:443".parse::<SocketAddr>().unwrap(),
            event: StreamEvent::ClientHello {
                ja3: Ja3::from_digest([1; 16]),
                ja3_raw: String::new(),
                ja4: Ja4Family::new(ja4.to_owned(), "x".to_owned()),
                sni: Some(sni.to_owned()),
                alpn: None,
            },
        }
    }

    #[test]
    fn a_host_profile_shows_when_each_client_first_appeared() {
        let mut store = IntelStore::open_in_memory().unwrap();
        let a = "t13d1516h2_aaaaaaaaaaaa_111111111111";
        let b = "t13d1713h2_bbbbbbbbbbbb_222222222222";
        for (ts, ja4, sni) in [
            (1_000_000_000, a, "one.test"),
            (2_000_000_000, a, "two.test"),
            (9_000_000_000, b, "one.test"),
            (9_500_000_000, a, "one.test"),
        ] {
            store.detect(&hello(ts, "10.0.0.5:5000", ja4, sni)).unwrap();
        }
        store
            .detect(&hello(3_000_000_000, "10.0.0.6:5000", a, "other.test"))
            .unwrap();

        let hosts = store.hosts(10, HostRole::Clients).unwrap();
        assert_eq!(hosts.len(), 2);
        assert_eq!(hosts[0].ip, "10.0.0.5", "most recent first");
        assert_eq!(hosts[0].clients, 2);
        assert_eq!(hosts[0].servers, 2);

        let profile = store.host_profile("10.0.0.5").unwrap().unwrap();
        assert_eq!(profile.clients.len(), 2);
        assert_eq!(profile.clients[0].ja4, a, "ordered by first appearance");
        assert_eq!(profile.clients[0].count, 3);
        assert_eq!(profile.clients[1].ja4, b);
        assert_eq!(profile.clients[1].first_ts, 9_000_000_000);
        assert!(profile.servers.iter().any(|s| s.value == "one.test"));
        assert!(
            !profile.alerts.is_empty(),
            "first_seen alerts belong to the host"
        );
        assert!(
            profile
                .alerts
                .iter()
                .all(|alert| alert.ip.as_deref() == Some("10.0.0.5"))
        );
    }

    #[test]
    fn a_server_that_only_answered_is_not_listed_as_a_client_host() {
        let mut store = IntelStore::open_in_memory().unwrap();
        store
            .detect(&hello(
                1_000_000_000,
                "10.0.0.5:5000",
                "t13d1516h2_aaaaaaaaaaaa_111111111111",
                "a.test",
            ))
            .unwrap();
        // The same connection's ServerHello is observed from the server.
        store
            .detect(&FingerprintEvent {
                ts_nanos: 1_000_000_500,
                src: "1.2.3.4:443".parse::<SocketAddr>().unwrap(),
                dst: "10.0.0.5:5000".parse::<SocketAddr>().unwrap(),
                event: StreamEvent::ServerHello {
                    ja3s: Ja3::from_digest([2; 16]),
                    ja3s_raw: String::new(),
                    ja4s: Ja4Family::new("t130200_1301_aaaaaaaaaaaa".to_owned(), "r".to_owned()),
                },
            })
            .unwrap();

        let clients = store.hosts(10, HostRole::Clients).unwrap();
        assert_eq!(clients.len(), 1);
        assert_eq!(clients[0].ip, "10.0.0.5");
        let servers = store.hosts(10, HostRole::Servers).unwrap();
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].ip, "1.2.3.4");
        assert_eq!(store.hosts(10, HostRole::All).unwrap().len(), 2);
    }

    #[test]
    fn an_unknown_address_has_no_profile() {
        let store = IntelStore::open_in_memory().unwrap();
        assert!(store.host_profile("192.0.2.1").unwrap().is_none());
        assert!(store.hosts(10, HostRole::Clients).unwrap().is_empty());
    }
}
