// © Pranav Verma | 2026
// labels.rs

//! The operator's own labels.
//!
//! No public feed knows every client: a browser released last week, a build of
//! your own software, an appliance. The operator does, so a fingerprint can be
//! named locally. Labels live in their own feed ("local labels", licence
//! "operator") so they are never mixed up with, or overwritten by, a bundled or
//! imported source, and are matched exactly like any other.

use anyhow::{Result, bail};
use rusqlite::{Connection, params};

use crate::model::{Category, FpKind};
use crate::{get_or_create_source, ja4_parts, refresh_source_count};

/// The name of the feed the operator's labels are stored in.
pub const LOCAL_SOURCE: &str = "local labels";

const MAX_LABEL_CHARS: usize = 120;
const MAX_VALUE_CHARS: usize = 400;

/// A label the operator wrote.
#[derive(Debug, Clone, serde::Serialize)]
pub struct LocalLabel {
    pub kind: String,
    pub value: String,
    pub label: String,
    pub category: String,
    pub note: Option<String>,
}

fn check(kind: FpKind, value: &str, label: &str) -> Result<()> {
    if value.is_empty() || value.chars().count() > MAX_VALUE_CHARS {
        bail!("the fingerprint is empty or too long");
    }
    if !value.chars().all(|c| c.is_ascii_graphic()) {
        bail!("a fingerprint is plain printable characters, with no spaces");
    }
    match kind {
        FpKind::Ja3 | FpKind::Ja3s => {
            if value.len() != 32 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
                bail!("a JA3 value is 32 hexadecimal characters");
            }
        }
        FpKind::Ja4 | FpKind::Ja4s | FpKind::Ja4h | FpKind::Ja4x => {
            if ja4_parts(value).is_none() && kind != FpKind::Ja4h {
                bail!(
                    "a {} value looks like three parts joined by underscores",
                    kind.as_str()
                );
            }
        }
        FpKind::Ja4t | FpKind::Ja4ts => {}
    }
    let label = label.trim();
    if label.is_empty() || label.chars().count() > MAX_LABEL_CHARS {
        bail!("the label must be 1 to {MAX_LABEL_CHARS} characters");
    }
    if label.chars().any(char::is_control) {
        bail!("the label must not contain control characters");
    }
    Ok(())
}

/// Adds or replaces a label. Returns whether it is new.
pub(crate) fn add(
    conn: &mut Connection,
    kind: FpKind,
    value: &str,
    label: &str,
    category: Category,
    note: Option<&str>,
) -> Result<bool> {
    let value = value.trim().to_ascii_lowercase();
    check(kind, &value, label)?;
    let tx = conn.transaction()?;
    let source = get_or_create_source(&tx, LOCAL_SOURCE, None, Some("operator"), "local")?;
    let (part_a, part_b) = if kind.supports_partial() {
        ja4_parts(&value).map_or((None, None), |(a, b)| (Some(a), Some(b)))
    } else {
        (None, None)
    };
    let existed: bool = tx
        .query_row(
            "SELECT 1 FROM intel_fingerprint WHERE fp_kind = ?1 AND value = ?2 AND source_id = ?3",
            params![kind.as_str(), value, source],
            |_| Ok(true),
        )
        .unwrap_or(false);
    tx.execute(
        "INSERT INTO intel_fingerprint
             (fp_kind, value, part_a, part_b, label, category, reference, first_seen, source_id)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, NULL, ?8)
         ON CONFLICT(fp_kind, value, source_id) DO UPDATE SET
             label = excluded.label,
             category = excluded.category,
             reference = excluded.reference",
        params![
            kind.as_str(),
            value,
            part_a,
            part_b,
            label.trim(),
            category.as_str(),
            note.map(str::trim).filter(|n| !n.is_empty()),
            source,
        ],
    )?;
    refresh_source_count(&tx, source)?;
    tx.commit()?;
    Ok(!existed)
}

/// Removes a label; returns whether one existed.
pub(crate) fn remove(conn: &mut Connection, kind: FpKind, value: &str) -> Result<bool> {
    let tx = conn.transaction()?;
    let removed = tx.execute(
        "DELETE FROM intel_fingerprint WHERE fp_kind = ?1 AND value = ?2
           AND source_id = (SELECT id FROM intel_source WHERE name = ?3)",
        params![
            kind.as_str(),
            value.trim().to_ascii_lowercase(),
            LOCAL_SOURCE
        ],
    )?;
    if let Ok(id) = tx.query_row(
        "SELECT id FROM intel_source WHERE name = ?1",
        params![LOCAL_SOURCE],
        |row| row.get::<_, i64>(0),
    ) {
        refresh_source_count(&tx, id)?;
    }
    tx.commit()?;
    Ok(removed > 0)
}

/// Every label the operator has written.
pub(crate) fn list(conn: &Connection) -> Result<Vec<LocalLabel>> {
    let mut statement = conn.prepare(
        "SELECT f.fp_kind, f.value, f.label, f.category, f.reference
         FROM intel_fingerprint f JOIN intel_source s ON s.id = f.source_id
         WHERE s.name = ?1 ORDER BY f.fp_kind, f.label",
    )?;
    let rows = statement
        .query_map(params![LOCAL_SOURCE], |row| {
            Ok(LocalLabel {
                kind: row.get(0)?,
                value: row.get(1)?,
                label: row.get(2)?,
                category: row.get(3)?,
                note: row.get(4)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use crate::IntelStore;
    use crate::model::{Category, FpKind};

    const JA4: &str = "t13d1516h2_8daaf6152771_e5627efa2ab1";

    #[test]
    fn a_label_is_matched_replaced_and_removed() {
        let mut store = IntelStore::open_in_memory().unwrap();
        assert!(
            store
                .add_label(FpKind::Ja4, JA4, "My build", Category::Tool, Some("ci"))
                .unwrap()
        );
        let report = store.match_fingerprint(FpKind::Ja4, JA4).unwrap();
        assert_eq!(report.hits[0].label, "My build");
        assert_eq!(report.hits[0].source, "local labels");

        assert!(
            !store
                .add_label(FpKind::Ja4, JA4, "My build 2", Category::Benign, None)
                .unwrap(),
            "replacing is not new"
        );
        assert_eq!(store.labels().unwrap().len(), 1);
        assert_eq!(store.labels().unwrap()[0].label, "My build 2");

        assert!(store.remove_label(FpKind::Ja4, JA4).unwrap());
        assert!(
            !store
                .match_fingerprint(FpKind::Ja4, JA4)
                .unwrap()
                .has_hits()
        );
        assert!(!store.remove_label(FpKind::Ja4, JA4).unwrap());
    }

    #[test]
    fn nonsense_is_refused_with_a_reason() {
        let mut store = IntelStore::open_in_memory().unwrap();
        for (kind, value, label) in [
            (FpKind::Ja4, "nounderscores", "x"),
            (FpKind::Ja3, "not-hex", "x"),
            (FpKind::Ja4, JA4, "   "),
            (FpKind::Ja4, JA4, "bad\nlabel"),
            (FpKind::Ja4, "has space_a_b", "x"),
        ] {
            assert!(
                store
                    .add_label(kind, value, label, Category::Benign, None)
                    .is_err(),
                "{value} / {label}"
            );
        }
        assert!(store.labels().unwrap().is_empty());
    }
}
