// © Pranav Verma | 2026
// library.rs

//! A library of capture files: find them, read each once, say what is in them.
//!
//! `tlsfp serve --library DIR` scans the directory (and subdirectories to a
//! small depth) for `.pcap` and `.pcapng` files, fingerprints every handshake
//! in each, and names the clients it finds, from an exact intelligence match
//! when there is one and from the ClientHello's shape when there is not.
//! `tlsfp identify FILE...` does the same from the command line.
//!
//! The scan is analysis only. It never writes to the intelligence database and
//! never raises alerts, so pointing it at a folder cannot change what the
//! detection rules have recorded. A file is read once and read again only when
//! its size or modification time changes. Files are untrusted input: they go
//! through the same fuzzed parsers as any capture, and a file that fails to
//! parse is reported with its error rather than skipped silently.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Serialize;
use tlsfp_core::{PcapFileSource, Pipeline, PipelineConfig, StreamEvent};
use tlsfp_intel::{
    ClientFamily, ClientGuess, Confidence, IntelStore, MatchStrength, Verdict, infer_client,
};

/// How deep below a library directory the scan descends.
const MAX_DEPTH: usize = 3;

/// The most capture files kept from one library, a guard against a directory
/// of thousands.
const MAX_FILES: usize = 500;

/// Files larger than this are listed but not read.
const MAX_BYTES: u64 = 1 << 30;

/// How many distinct clients are kept per file.
const MAX_CLIENTS: usize = 12;

/// How many server names are kept per client.
const MAX_SNIS: usize = 5;

/// The state of one file in the library.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FileStatus {
    Ready,
    Error,
    TooLarge,
}

/// One distinct client found in a capture, grouped by ClientHello JA4.
#[derive(Debug, Clone, Serialize)]
pub struct ClientSummary {
    pub ja4: String,
    /// `tcp` or `quic`, from the first character of the JA4.
    pub transport: &'static str,
    pub connections: usize,
    pub ja3_variants: usize,
    pub alpn: Option<String>,
    pub servers: Vec<String>,
    /// The label of an exact intelligence match, when one exists.
    pub known_as: Option<String>,
    pub verdict: Option<Verdict>,
    pub guess: ClientGuess,
}

/// What one capture file holds.
#[derive(Debug, Clone, Serialize)]
pub struct CaptureSummary {
    pub id: String,
    /// Path relative to the library directory; never an absolute path.
    pub name: String,
    pub size: u64,
    pub modified_unix: u64,
    pub status: FileStatus,
    pub error: Option<String>,
    pub frames: u64,
    pub tls_handshakes: u64,
    pub quic_initials: u64,
    pub first_ts_nanos: Option<u64>,
    pub last_ts_nanos: Option<u64>,
    pub clients: Vec<ClientSummary>,
    /// The client that best describes the file: the busiest browser-like or
    /// exactly-identified one, else the busiest of all.
    pub headline: Option<Headline>,
}

/// The one-line answer to "which browser is this capture?".
#[derive(Debug, Clone, Serialize)]
pub struct Headline {
    pub ja4: String,
    pub text: String,
    /// `exact` when the intelligence feed names it, `inferred` when the
    /// ClientHello's shape does.
    pub basis: &'static str,
    pub confidence: Confidence,
    pub caveat: Option<&'static str>,
}

#[derive(Default)]
struct ClientAcc {
    connections: usize,
    ja3: std::collections::HashSet<String>,
    alpn: Option<String>,
    servers: HashMap<String, usize>,
    raw: String,
    known_as: Option<String>,
    verdict: Option<Verdict>,
}

/// Reads one capture file and summarises it. `store` supplies intelligence
/// matches and is only read.
pub fn analyse(path: &Path, name: String, store: &IntelStore) -> CaptureSummary {
    let (size, modified_unix) = file_stamp(path);

    let mut summary = CaptureSummary {
        id: file_id(&name),
        name,
        size,
        modified_unix,
        status: FileStatus::Ready,
        error: None,
        frames: 0,
        tls_handshakes: 0,
        quic_initials: 0,
        first_ts_nanos: None,
        last_ts_nanos: None,
        clients: Vec::new(),
        headline: None,
    };
    if size > MAX_BYTES {
        summary.status = FileStatus::TooLarge;
        summary.error = Some(format!("larger than {} MiB; not read", MAX_BYTES >> 20));
        return summary;
    }

    let mut source = match PcapFileSource::open(path) {
        Ok(source) => source,
        Err(error) => {
            summary.status = FileStatus::Error;
            summary.error = Some(error.to_string());
            return summary;
        }
    };
    let mut pipeline = Pipeline::new(PipelineConfig::default());
    let mut clients: HashMap<String, ClientAcc> = HashMap::new();
    let run = pipeline.run(&mut source, |event| {
        summary.first_ts_nanos = Some(
            summary
                .first_ts_nanos
                .map_or(event.ts_nanos, |t| t.min(event.ts_nanos)),
        );
        summary.last_ts_nanos = Some(
            summary
                .last_ts_nanos
                .map_or(event.ts_nanos, |t| t.max(event.ts_nanos)),
        );
        let StreamEvent::ClientHello {
            ja3,
            ja4,
            sni,
            alpn,
            ..
        } = &event.event
        else {
            return;
        };
        let acc = clients.entry(ja4.hash.clone()).or_default();
        if acc.connections == 0 {
            acc.raw.clone_from(&ja4.raw);
            if let Ok(reports) = store.match_event(&event) {
                for report in reports.iter().filter(|r| r.observed == ja4.hash) {
                    acc.verdict = Some(report.verdict);
                    acc.known_as = report
                        .hits
                        .iter()
                        .find(|hit| hit.strength == MatchStrength::Exact)
                        .map(|hit| hit.label.clone());
                }
            }
        }
        acc.connections += 1;
        acc.ja3.insert(ja3.to_string());
        if acc.alpn.is_none() {
            acc.alpn.clone_from(alpn);
        }
        if let Some(sni) = sni {
            *acc.servers.entry(sni.clone()).or_default() += 1;
        }
    });
    if let Err(error) = run {
        summary.status = FileStatus::Error;
        summary.error = Some(error.to_string());
    }
    let counters = pipeline.counters();
    summary.frames = counters.frames;
    summary.tls_handshakes = counters.tls_handshakes_fingerprinted;
    summary.quic_initials = counters.quic_decrypted;

    let list = finish_clients(clients);
    summary.headline = headline(&list);
    summary.clients = list;
    summary
}

/// Size and modification time (seconds since the epoch) of a file; zeros when
/// it cannot be read.
fn file_stamp(path: &Path) -> (u64, u64) {
    std::fs::metadata(path).map_or((0, 0), |m| {
        (
            m.len(),
            m.modified()
                .ok()
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .map_or(0, |d| d.as_secs()),
        )
    })
}

/// Turns the per-JA4 accumulators into the busiest-first, bounded client list.
fn finish_clients(clients: HashMap<String, ClientAcc>) -> Vec<ClientSummary> {
    let mut list: Vec<ClientSummary> = clients
        .into_iter()
        .map(|(ja4, acc)| {
            let mut servers: Vec<_> = acc.servers.into_iter().collect();
            servers.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
            ClientSummary {
                transport: if ja4.starts_with('q') { "quic" } else { "tcp" },
                guess: infer_client(&acc.raw),
                ja4,
                connections: acc.connections,
                ja3_variants: acc.ja3.len(),
                alpn: acc.alpn,
                servers: servers.into_iter().take(MAX_SNIS).map(|(n, _)| n).collect(),
                known_as: acc.known_as,
                verdict: acc.verdict,
            }
        })
        .collect();
    list.sort_by(|a, b| {
        b.connections
            .cmp(&a.connections)
            .then_with(|| a.ja4.cmp(&b.ja4))
    });
    list.truncate(MAX_CLIENTS);
    list
}

/// Chooses the client that best answers "which browser is this?". An exact
/// intelligence match outranks a guess; among guesses, browser families
/// outrank libraries; busiest wins ties.
fn headline(clients: &[ClientSummary]) -> Option<Headline> {
    let rank = |c: &ClientSummary| -> (u8, usize) {
        let tier = if c.known_as.is_some() {
            3
        } else if c.guess.family.is_browser_like() {
            2
        } else {
            u8::from(c.guess.family != ClientFamily::Unknown)
        };
        (tier, c.connections)
    };
    let best = clients.iter().max_by_key(|c| rank(c))?;
    let (text, basis) = match &best.known_as {
        Some(label) => (label.clone(), "exact"),
        None => (best.guess.family.display().to_string(), "inferred"),
    };
    Some(Headline {
        ja4: best.ja4.clone(),
        text,
        basis,
        confidence: if basis == "exact" {
            Confidence::High
        } else {
            best.guess.confidence
        },
        caveat: best.guess.caveat,
    })
}

/// A stable short identifier for a file name, for use in URLs and React keys.
fn file_id(name: &str) -> String {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    name.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

fn is_capture(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("pcap") || e.eq_ignore_ascii_case("pcapng"))
}

/// Capture files under `root`, as (absolute path, name relative to root).
/// Symbolic links are not followed, so a library cannot point the scan at
/// files outside the directory it was given.
pub fn discover(root: &Path) -> Vec<(PathBuf, String)> {
    fn walk(dir: &Path, root: &Path, depth: usize, out: &mut Vec<(PathBuf, String)>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        let mut entries: Vec<_> = entries.filter_map(Result::ok).collect();
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for entry in entries {
            if out.len() >= MAX_FILES {
                return;
            }
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            let path = entry.path();
            if kind.is_dir() && depth < MAX_DEPTH {
                walk(&path, root, depth + 1, out);
            } else if kind.is_file() && is_capture(&path) {
                let name = path
                    .strip_prefix(root)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .replace('\\', "/");
                out.push((path, name));
            }
        }
    }
    let mut out = Vec::new();
    walk(root, root, 0, &mut out);
    out
}

/// What the dashboard shows about the library.
#[derive(Debug, Clone, Default, Serialize)]
pub struct LibraryView {
    pub directories: usize,
    pub scanning: bool,
    pub scanned_unix: Option<u64>,
    pub files: Vec<CaptureSummary>,
    /// Where each listed file is on disk, by id. Never sent to a browser.
    #[serde(skip)]
    pub paths: HashMap<String, PathBuf>,
}

/// The shared, always-current result of scanning the library directories.
#[derive(Clone, Default)]
pub struct Library {
    inner: Arc<Mutex<LibraryView>>,
}

impl Library {
    pub fn view(&self) -> LibraryView {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    fn update(&self, edit: impl FnOnce(&mut LibraryView)) {
        edit(
            &mut self
                .inner
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
    }

    /// Scans `dirs` now and then every `interval`, until `stop` is set. Runs
    /// on the calling thread; spawn it. Only new or changed files are read.
    pub fn watch(
        &self,
        dirs: &[PathBuf],
        db: &Path,
        interval: Duration,
        stop: &std::sync::atomic::AtomicBool,
    ) {
        let store = match IntelStore::open(db) {
            Ok(store) => store,
            Err(error) => {
                tracing::error!(%error, "library: cannot open the intelligence database");
                return;
            }
        };
        self.update(|v| v.directories = dirs.len());
        let mut seen: HashMap<(usize, String), (u64, u64)> = HashMap::new();
        let mut cache: HashMap<(usize, String), CaptureSummary> = HashMap::new();
        while !stop.load(std::sync::atomic::Ordering::Relaxed) {
            self.update(|v| v.scanning = true);
            let mut files = Vec::new();
            let mut paths = HashMap::new();
            let mut present = std::collections::HashSet::new();
            for (index, dir) in dirs.iter().enumerate() {
                for (path, name) in discover(dir) {
                    let label = if dirs.len() > 1 {
                        format!(
                            "{}/{}",
                            dir.file_name().map_or_else(
                                || index.to_string(),
                                |n| n.to_string_lossy().into_owned()
                            ),
                            name
                        )
                    } else {
                        name.clone()
                    };
                    let key = (index, name);
                    present.insert(key.clone());
                    let stamp = file_stamp(&path);
                    if seen.get(&key) != Some(&stamp) || !cache.contains_key(&key) {
                        if stop.load(std::sync::atomic::Ordering::Relaxed) {
                            return;
                        }
                        tracing::info!(file = %label, "library: reading capture");
                        let result = analyse(&path, label, &store);
                        seen.insert(key.clone(), stamp);
                        cache.insert(key.clone(), result);
                    }
                    if let Some(result) = cache.get(&key) {
                        paths.insert(result.id.clone(), path.clone());
                        files.push(result.clone());
                    }
                }
            }
            seen.retain(|k, _| present.contains(k));
            cache.retain(|k, _| present.contains(k));
            files.sort_by(|a, b| {
                b.modified_unix
                    .cmp(&a.modified_unix)
                    .then_with(|| a.name.cmp(&b.name))
            });
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.as_secs());
            self.update(|v| {
                v.files = files;
                v.paths = paths;
                v.scanning = false;
                v.scanned_unix = Some(now);
            });
            let mut waited = Duration::ZERO;
            while waited < interval && !stop.load(std::sync::atomic::Ordering::Relaxed) {
                std::thread::sleep(Duration::from_millis(250));
                waited += Duration::from_millis(250);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn testdata(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../testdata/pcap")
            .join(name)
    }

    #[test]
    fn names_the_clients_in_a_real_capture() {
        let store = IntelStore::open_in_memory().unwrap();
        let summary = analyse(
            &testdata("browsers-x509.pcapng"),
            "browsers-x509.pcapng".into(),
            &store,
        );
        assert!(
            matches!(summary.status, FileStatus::Ready),
            "{:?}",
            summary.error
        );
        assert!(!summary.clients.is_empty(), "client hellos found");
        assert!(summary.headline.is_some());
        assert!(summary.clients.len() <= MAX_CLIENTS);
    }

    #[test]
    fn a_file_that_is_not_a_capture_is_an_error_not_a_crash() {
        let dir = tempfile_dir("notpcap");
        let path = dir.join("junk.pcap");
        std::fs::write(&path, b"this is not a packet capture").unwrap();
        let store = IntelStore::open_in_memory().unwrap();
        let summary = analyse(&path, "junk.pcap".into(), &store);
        assert!(matches!(summary.status, FileStatus::Error));
        assert!(summary.error.is_some());
        assert!(summary.clients.is_empty());
    }

    #[test]
    fn discovery_finds_captures_in_subdirectories_with_relative_names() {
        let dir = tempfile_dir("discover");
        std::fs::create_dir_all(dir.join("a/b")).unwrap();
        std::fs::write(dir.join("one.pcap"), b"x").unwrap();
        std::fs::write(dir.join("a/b/two.PCAPNG"), b"x").unwrap();
        std::fs::write(dir.join("a/notes.txt"), b"x").unwrap();
        let names: Vec<String> = discover(&dir).into_iter().map(|(_, n)| n).collect();
        assert_eq!(
            names,
            vec!["a/b/two.PCAPNG".to_string(), "one.pcap".to_string()]
        );
    }

    #[cfg(unix)]
    #[test]
    fn discovery_does_not_follow_symbolic_links_out_of_the_directory() {
        let dir = tempfile_dir("symlink");
        let outside = tempfile_dir("outside");
        std::fs::write(outside.join("secret.pcap"), b"x").unwrap();
        std::os::unix::fs::symlink(&outside, dir.join("link")).unwrap();
        std::os::unix::fs::symlink(outside.join("secret.pcap"), dir.join("file.pcap")).unwrap();
        let found = discover(&dir);
        assert_eq!(
            found.len(),
            0,
            "a link must not lead the scan outside: {found:?}"
        );
    }

    fn tempfile_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("tlsfp-library-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }
}
