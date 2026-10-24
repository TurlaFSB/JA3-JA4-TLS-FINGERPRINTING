// © Pranav Verma | 2026
// retention.rs

//! Keeping the database from growing without end.
//!
//! Every handshake the sensor sees becomes an observation row, and every alert
//! a row of its own. On a busy link that is gigabytes a month, which an
//! operator will not notice until the disk is full. Retention deletes the old
//! ones, oldest first, in small batches so a writer is never blocked for long.
//!
//! Ages are measured from the newest record, not from the wall clock: a replay
//! of a capture from last year must not be wiped the moment it is loaded. A
//! limit of zero means unlimited.
//!
//! The one thing pruning changes is memory: a fingerprint last seen longer ago
//! than the window is "first seen" again when it returns, and a host's history
//! starts at the oldest row kept.

use anyhow::Result;
use rusqlite::{Connection, params};
use serde::Serialize;

const NANOS_PER_DAY: i64 = 86_400 * 1_000_000_000;
/// Rows deleted per statement.
const BATCH: i64 = 20_000;

/// How much history to keep.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Retention {
    /// Days of observations to keep, counted back from the newest. 0 = all.
    pub observation_days: u32,
    /// Days of alerts to keep. 0 = all.
    pub alert_days: u32,
    /// The most observation rows kept, newest first. 0 = unlimited.
    pub max_observations: u64,
}

impl Default for Retention {
    fn default() -> Self {
        Self {
            observation_days: 90,
            alert_days: 365,
            max_observations: 5_000_000,
        }
    }
}

/// What a pruning pass removed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct Pruned {
    pub observations: u64,
    pub alerts: u64,
}

fn delete_in_batches(conn: &Connection, sql: &str, bound: i64) -> Result<u64> {
    let mut total = 0_u64;
    loop {
        let removed = conn.execute(sql, params![bound, BATCH])?;
        total += removed as u64;
        if removed == 0 {
            return Ok(total);
        }
    }
}

pub(crate) fn prune(conn: &Connection, policy: Retention) -> Result<Pruned> {
    let mut pruned = Pruned::default();

    if policy.observation_days > 0 {
        let newest: Option<i64> =
            conn.query_row("SELECT max(ts) FROM observation", [], |row| row.get(0))?;
        if let Some(newest) = newest {
            let cutoff = newest.saturating_sub(i64::from(policy.observation_days) * NANOS_PER_DAY);
            pruned.observations += delete_in_batches(
                conn,
                "DELETE FROM observation WHERE id IN
                   (SELECT id FROM observation WHERE ts < ?1 ORDER BY id LIMIT ?2)",
                cutoff,
            )?;
        }
    }

    if policy.max_observations > 0 {
        let keep = i64::try_from(policy.max_observations).unwrap_or(i64::MAX);
        // The id of the newest row that is one too many; it and everything
        // older go.
        let over: Option<i64> = conn
            .query_row(
                "SELECT id FROM observation ORDER BY id DESC LIMIT 1 OFFSET ?1",
                params![keep],
                |row| row.get(0),
            )
            .ok();
        if let Some(limit) = over {
            pruned.observations += delete_in_batches(
                conn,
                "DELETE FROM observation WHERE id IN
                   (SELECT id FROM observation WHERE id <= ?1 ORDER BY id LIMIT ?2)",
                limit,
            )?;
        }
    }

    if policy.alert_days > 0 {
        let newest: Option<i64> =
            conn.query_row("SELECT max(ts) FROM alert", [], |row| row.get(0))?;
        if let Some(newest) = newest {
            let cutoff = newest.saturating_sub(i64::from(policy.alert_days) * NANOS_PER_DAY);
            pruned.alerts += delete_in_batches(
                conn,
                "DELETE FROM alert WHERE id IN
                   (SELECT id FROM alert WHERE ts < ?1 ORDER BY id LIMIT ?2)",
                cutoff,
            )?;
        }
    }
    Ok(pruned)
}

#[cfg(test)]
mod tests {
    use super::{NANOS_PER_DAY, Pruned, Retention};
    use crate::IntelStore;
    use std::net::SocketAddr;
    use tlsfp_core::pipeline::event::StreamEvent;
    use tlsfp_core::{FingerprintEvent, Ja3, Ja4Family};

    fn hello(ts: i64, n: u32) -> FingerprintEvent {
        FingerprintEvent {
            ts_nanos: u64::try_from(ts).unwrap(),
            src: "10.0.0.5:5000".parse::<SocketAddr>().unwrap(),
            dst: "1.2.3.4:443".parse::<SocketAddr>().unwrap(),
            event: StreamEvent::ClientHello {
                detail: None,
                ja3: Ja3::from_digest([1; 16]),
                ja3_raw: String::new(),
                ja4: Ja4Family::new(format!("t13d1516h2_aaaaaaaaaaaa_{n:012}"), "r".to_owned()),
                sni: Some("a.test".to_owned()),
                alpn: None,
            },
        }
    }

    fn count(store: &IntelStore, table: &str) -> i64 {
        store
            .conn
            .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .unwrap()
    }

    #[test]
    fn old_observations_go_measured_from_the_newest_not_from_today() {
        let mut store = IntelStore::open_in_memory().unwrap();
        // A capture from long ago: only its own spread matters.
        let base = 1_600_000_000 * 1_000_000_000_i64;
        store.detect(&hello(base, 1)).unwrap();
        store.detect(&hello(base + 40 * NANOS_PER_DAY, 2)).unwrap();
        store.detect(&hello(base + 100 * NANOS_PER_DAY, 3)).unwrap();
        assert_eq!(count(&store, "observation"), 3);

        let pruned = store
            .prune(Retention {
                observation_days: 30,
                alert_days: 0,
                max_observations: 0,
            })
            .unwrap();
        assert_eq!(
            pruned,
            Pruned {
                observations: 2,
                alerts: 0
            }
        );
        assert_eq!(count(&store, "observation"), 1, "the newest is always kept");
    }

    #[test]
    fn the_row_cap_keeps_the_newest_and_zero_means_unlimited() {
        let mut store = IntelStore::open_in_memory().unwrap();
        for n in 0..10 {
            store
                .detect(&hello(1_000_000_000 + i64::from(n), n))
                .unwrap();
        }
        let none = store
            .prune(Retention {
                observation_days: 0,
                alert_days: 0,
                max_observations: 0,
            })
            .unwrap();
        assert_eq!(none, Pruned::default());
        assert_eq!(count(&store, "observation"), 10);

        let pruned = store
            .prune(Retention {
                observation_days: 0,
                alert_days: 0,
                max_observations: 4,
            })
            .unwrap();
        assert_eq!(pruned.observations, 6);
        assert_eq!(count(&store, "observation"), 4);
        let oldest_kept: i64 = store
            .conn
            .query_row("SELECT min(ts) FROM observation", [], |row| row.get(0))
            .unwrap();
        assert_eq!(oldest_kept, 1_000_000_006, "the four newest remain");
    }

    #[test]
    fn old_alerts_are_dropped_and_an_empty_store_is_fine() {
        let mut store = IntelStore::open_in_memory().unwrap();
        assert_eq!(
            store.prune(Retention::default()).unwrap(),
            Pruned::default()
        );
        let base = 1_600_000_000 * 1_000_000_000_i64;
        store.detect(&hello(base, 1)).unwrap();
        store.detect(&hello(base + 500 * NANOS_PER_DAY, 2)).unwrap();
        assert_eq!(count(&store, "alert"), 2, "first_seen alert each");
        let pruned = store
            .prune(Retention {
                observation_days: 0,
                alert_days: 365,
                max_observations: 0,
            })
            .unwrap();
        assert_eq!(pruned.alerts, 1);
        assert_eq!(count(&store, "alert"), 1);
    }
}
