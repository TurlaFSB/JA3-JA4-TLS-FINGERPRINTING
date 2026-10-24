// © Pranav Verma | 2026
// case_report.rs

//! A self-contained HTML report for one or more capture files: what is in the
//! capture, who the clients appear to be, which detection rules fired, and the
//! limits of every one of those statements, with the SHA-256 of the file so the
//! report can be tied to its evidence.
//!
//! The page has no script, no external request and no font to download, so it
//! can be emailed, attached to a ticket or printed. Every value that came from
//! a capture is escaped: a hostile server name cannot inject markup.

use std::fmt::Write as _;
use std::io::Read;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use tlsfp_core::{PcapFileSource, Pipeline};
use tlsfp_intel::{Alert, DetectConfig, IntelStore, Rule};

use crate::deliver::rfc3339;
use crate::library::{CaptureSummary, FileStatus, analyse};

/// The most alerts listed per capture; the count above the cap is stated.
const MAX_ALERTS: usize = 200;

/// Everything the report says about one capture.
pub struct Case {
    pub summary: CaptureSummary,
    pub sha256: String,
    pub alerts: Vec<Alert>,
    /// Alerts beyond [`MAX_ALERTS`], counted but not listed.
    pub alerts_omitted: usize,
}

/// Reads and analyses one capture. Detection runs against a private copy of
/// the intelligence database, so the operator's own database is untouched.
pub fn build(path: &Path, name: String, db: &Path, scratch: &Path) -> Result<Case> {
    let store = IntelStore::open(db).context("opening the intelligence database")?;
    let summary = analyse(path, name, &store);
    let sha256 = sha256_file(path).context("hashing the capture")?;
    let (alerts, alerts_omitted) = if matches!(summary.status, FileStatus::Ready) {
        detect(path, db, scratch)?
    } else {
        (Vec::new(), 0)
    };
    Ok(Case {
        summary,
        sha256,
        alerts,
        alerts_omitted,
    })
}

fn detect(path: &Path, db: &Path, scratch: &Path) -> Result<(Vec<Alert>, usize)> {
    // Unique per call: two reports may be built in one process.
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let copy = scratch.join(format!(
        "tlsfp-case-{}-{}.db",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let _ = std::fs::remove_file(&copy);
    let mut store = if db.exists() {
        std::fs::copy(db, &copy).context("copying the intelligence database")?;
        IntelStore::open(&copy)?
    } else {
        let mut fresh = IntelStore::open(&copy)?;
        fresh.seed_bundled()?;
        fresh
    };
    store.set_detect_config(DetectConfig {
        custom: crate::extras::rules(),
        ..DetectConfig::default()
    });
    let mut source = PcapFileSource::open(path).context("opening the capture")?;
    let mut pipeline = Pipeline::new(crate::engine::config());
    let mut alerts = Vec::new();
    let run = pipeline.run(&mut source, |event| {
        if let Ok(found) = store.detect(&event) {
            alerts.extend(found);
        }
    });
    drop(store);
    for suffix in ["", "-wal", "-shm"] {
        let mut file = copy.clone().into_os_string();
        file.push(suffix);
        let _ = std::fs::remove_file(file);
    }
    run.context("reading the capture")?;
    let omitted = alerts.len().saturating_sub(MAX_ALERTS);
    alerts.truncate(MAX_ALERTS);
    Ok((alerts, omitted))
}

fn sha256_file(path: &Path) -> std::io::Result<String> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1 << 16];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher
        .finalize()
        .iter()
        .fold(String::with_capacity(64), |mut out, byte| {
            let _ = write!(out, "{byte:02x}");
            out
        }))
}

/// Escapes text for an HTML body or a double-quoted attribute.
fn esc(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c if c.is_control() && c != '\n' => out.push(' '),
            c => out.push(c),
        }
    }
    out
}

fn bytes_text(bytes: u64) -> String {
    #[allow(clippy::cast_precision_loss)]
    let value = bytes as f64;
    if bytes >= 1 << 20 {
        format!("{:.1} MiB", value / f64::from(1 << 20))
    } else if bytes >= 1 << 10 {
        format!("{:.1} KiB", value / 1024.0)
    } else {
        format!("{bytes} B")
    }
}

fn nanos_text(nanos: Option<u64>) -> String {
    nanos.map_or_else(
        || "none".to_owned(),
        |n| rfc3339(i64::try_from(n).unwrap_or(i64::MAX)),
    )
}

const STYLE: &str = "
:root{color-scheme:light;--ink:#1b1f24;--dim:#57606a;--line:#d0d7de;--bg:#fff;--soft:#f6f8fa;--accent:#0b5cad}
*{box-sizing:border-box}
body{margin:0;padding:32px 20px;background:var(--bg);color:var(--ink);font:15px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
main{max-width:980px;margin:0 auto}
h1{font-size:24px;margin:0 0 4px}h2{font-size:18px;margin:32px 0 8px;border-bottom:1px solid var(--line);padding-bottom:4px}
h3{font-size:15px;margin:20px 0 6px}
.dim{color:var(--dim)}.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:13px;word-break:break-all}
table{width:100%;border-collapse:collapse;margin:8px 0;font-size:14px}
th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{background:var(--soft);font-weight:600}
.facts{display:grid;grid-template-columns:max-content 1fr;gap:4px 16px;margin:8px 0}
.facts dt{color:var(--dim)}.facts dd{margin:0}
.head{background:var(--soft);border:1px solid var(--line);border-left:4px solid var(--accent);padding:10px 14px;margin:12px 0}
.sev{display:inline-block;padding:0 6px;border-radius:3px;font-size:12px;font-weight:600;border:1px solid var(--line)}
.sev-critical,.sev-high{background:#ffebe9;border-color:#ff8182}.sev-medium{background:#fff8c5;border-color:#d4a72c}
.limits li{margin:4px 0}
footer{margin-top:40px;padding-top:12px;border-top:1px solid var(--line);font-size:13px;color:var(--dim)}
@media print{body{padding:0}h2{break-after:avoid}table{break-inside:auto}tr{break-inside:avoid}}
";

fn rule_explanation(rule: Rule) -> &'static str {
    match rule {
        Rule::KnownBad => {
            "The fingerprint matches an entry the intelligence feed marks as malicious."
        }
        Rule::UaMismatch => {
            "The cleartext User-Agent names one client but the handshake looks like another."
        }
        Rule::OsMismatch => {
            "The operating system the User-Agent claims disagrees with the one the TCP/IP stack suggests."
        }
        Rule::FpRotation => {
            "One address presented several different client fingerprints in a short window."
        }
        Rule::Monoculture => "Many addresses presented the identical, unusual fingerprint.",
        Rule::HeaderAnomaly => {
            "The HTTP request headers are ordered or shaped unlike the client they claim to be."
        }
        Rule::FirstSeen => "This fingerprint had not been seen before in this database.",
        Rule::Custom => "A rule written by the operator matched.",
    }
}

/// Renders the report page.
pub fn render(cases: &[Case], intel_fingerprints: i64) -> String {
    let mut out = String::with_capacity(16 * 1024);
    let generated = rfc3339(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| i64::try_from(d.as_nanos()).unwrap_or(i64::MAX)),
    );
    let title = if let [only] = cases {
        format!("tlsfp report: {}", only.summary.name)
    } else {
        format!("tlsfp report: {} captures", cases.len())
    };
    let _ = write!(
        out,
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>{}</title><style>{STYLE}</style></head><body><main>",
        esc(&title)
    );
    let _ = write!(
        out,
        "<h1>{}</h1><p class=\"dim\">Passive TLS fingerprint analysis. Generated {} by tlsfp {}.</p>",
        esc(&title),
        esc(&generated),
        env!("CARGO_PKG_VERSION")
    );
    for case in cases {
        render_case(&mut out, case);
    }
    out.push_str("<h2>Limits of this report</h2><ul class=\"limits\">");
    for line in [
        "A fingerprint describes how a client builds its TLS handshake, not who is using it. A tool that copies a browser's handshake is indistinguishable here from that browser.",
        "\"Inferred\" client names come from the shape of the ClientHello and are guesses with the confidence shown. Only an exact match in the intelligence feed is a named identification, and the feed is a snapshot that cannot know every build.",
        "Encrypted ClientHello hides the server name; those connections appear without one. Content of encrypted traffic is never visible to this tool.",
        "Detection rules are heuristics. A rule firing is a lead to check, not a verdict; a rule silent is not proof of innocence.",
        "Times come from the packet timestamps in the capture file, shown in UTC.",
    ] {
        let _ = write!(out, "<li>{}</li>", esc(line));
    }
    let _ = write!(
        out,
        "</ul><footer>tlsfp {} (AGPL-3.0-only). Intelligence feed: {} fingerprints. This page contains no script and makes no network request.</footer></main></body></html>",
        env!("CARGO_PKG_VERSION"),
        intel_fingerprints
    );
    out
}

fn render_case(out: &mut String, case: &Case) {
    let s = &case.summary;
    let _ = write!(out, "<h2>{}</h2><dl class=\"facts\">", esc(&s.name));
    let facts = [
        (
            "SHA-256",
            format!("<span class=\"mono\">{}</span>", esc(&case.sha256)),
        ),
        ("Size", esc(&bytes_text(s.size))),
        ("First packet", esc(&nanos_text(s.first_ts_nanos))),
        ("Last packet", esc(&nanos_text(s.last_ts_nanos))),
        ("Frames read", s.frames.to_string()),
        ("TLS handshakes", s.tls_handshakes.to_string()),
        ("QUIC Initials", s.quic_initials.to_string()),
    ];
    for (key, value) in facts {
        let _ = write!(out, "<dt>{key}</dt><dd>{value}</dd>");
    }
    out.push_str("</dl>");
    if let Some(error) = &s.error {
        let _ = write!(out, "<p><strong>Not analysed:</strong> {}</p>", esc(error));
        return;
    }
    match &s.headline {
        Some(head) => {
            let _ = write!(
                out,
                "<div class=\"head\"><strong>Most likely client: {}</strong><br><span class=\"dim\">{} identification, {:?} confidence.{}</span></div>",
                esc(&head.text),
                esc(head.basis),
                head.confidence,
                head.caveat
                    .map(|c| format!(" {}", esc(c)))
                    .unwrap_or_default()
            );
        }
        None => out.push_str("<p class=\"dim\">No TLS ClientHello was found in this capture.</p>"),
    }
    if !s.clients.is_empty() {
        out.push_str("<h3>Clients</h3><table><tr><th>JA4</th><th>Transport</th><th>Connections</th><th>Named as</th><th>Servers contacted</th></tr>");
        for c in &s.clients {
            let named = c.known_as.as_deref().map_or_else(
                || format!("{} (inferred)", c.guess.family.display()),
                str::to_owned,
            );
            let _ = write!(
                out,
                "<tr><td class=\"mono\">{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                esc(&c.ja4),
                c.transport,
                c.connections,
                esc(&named),
                esc(&c.servers.join(", "))
            );
        }
        out.push_str("</table>");
    }
    out.push_str("<h3>Detection findings</h3>");
    if case.alerts.is_empty() {
        out.push_str("<p>No detection rule fired on this capture.</p>");
        return;
    }
    out.push_str("<table><tr><th>Severity</th><th>Rule</th><th>Source</th><th>Finding</th></tr>");
    for a in &case.alerts {
        let _ = write!(
            out,
            "<tr><td><span class=\"sev sev-{sev}\">{sev}</span></td><td>{}<br><span class=\"dim\">{}</span></td><td class=\"mono\">{}</td><td><strong>{}</strong><br>{}</td></tr>",
            esc(a.rule.as_str()),
            esc(rule_explanation(a.rule)),
            esc(a.ip.as_deref().unwrap_or("")),
            esc(&a.title),
            esc(&a.detail),
            sev = a.severity.as_str()
        );
    }
    out.push_str("</table>");
    if case.alerts_omitted > 0 {
        let _ = write!(
            out,
            "<p class=\"dim\">{} further alerts are not listed.</p>",
            case.alerts_omitted
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn testdata(name: &str) -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../testdata/pcap")
            .join(name)
    }

    #[test]
    fn escaping_neutralises_markup_and_quotes() {
        assert_eq!(
            esc("<script>\"x\"&'y'</script>"),
            "&lt;script&gt;&quot;x&quot;&amp;&#39;y&#39;&lt;/script&gt;"
        );
        assert_eq!(esc("a\u{7}b"), "a b");
    }

    #[test]
    fn a_hostile_server_name_cannot_inject_markup() {
        let mut case = fake_case();
        case.summary.clients[0].servers = vec!["<img src=x onerror=alert(1)>".into()];
        case.summary.name = "\"><script>alert(1)</script>.pcap".into();
        let html = render(&[case], 10);
        assert!(!html.contains("<script>alert"));
        assert!(!html.contains("<img src=x"));
        assert!(html.contains("&lt;img src=x onerror=alert(1)&gt;"));
    }

    fn fake_case() -> Case {
        let store = IntelStore::open(Path::new(":memory:")).unwrap();
        let mut summary = analyse(&testdata("tls-handshake.pcapng"), "t.pcapng".into(), &store);
        summary.clients.truncate(1);
        Case {
            summary,
            sha256: "0".repeat(64),
            alerts: Vec::new(),
            alerts_omitted: 0,
        }
    }

    #[test]
    fn a_real_capture_produces_a_report_with_its_hash_and_no_script() {
        let dir = std::env::temp_dir().join(format!("tlsfp-case-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("intel.db");
        let _ = std::fs::remove_file(&db);
        IntelStore::open(&db).unwrap().seed_bundled().unwrap();
        let path = testdata("tls-handshake.pcapng");
        let case = build(&path, "tls-handshake.pcapng".into(), &db, &dir).unwrap();
        assert_eq!(case.sha256.len(), 64);
        let html = render(&[case], 1);
        assert!(html.contains("tls-handshake.pcapng"));
        assert!(html.contains("Most likely client"));
        assert!(!html.contains("<script"));
        assert!(!html.contains("http://") && !html.contains("https://"));
    }
}
