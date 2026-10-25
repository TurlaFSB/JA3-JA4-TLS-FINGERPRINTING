// ©AngelaMos | 2026
// serve.rs

//! The web dashboard and HTTP API.
//!
//! This is the one place in the tool that needs concurrent access to the
//! intelligence store, and the one place the store's deliberate synchrony has
//! to be reconciled with an async runtime. The reconciliation is small on
//! purpose: the store stays a plain blocking handle, and every request that
//! touches it does so inside [`tokio::task::spawn_blocking`], so a slow query
//! parks a blocking thread rather than stalling the reactor. A single
//! `Mutex` serialises access, which is the right shape for a dashboard whose
//! queries are short and whose writers, when present, are one capture loop.
//!
//! The live stream is a `broadcast` channel. Whatever feeds the dashboard, a
//! replayed capture, a live interface, or new alerts tailed from the database,
//! publishes a pre-serialised line onto the channel, and every connected
//! browser's Server-Sent Events response subscribes to it. The stream route is
//! kept off the compression layer on purpose: a compressor buffers to find
//! runs worth packing, and buffering is the one thing a live event stream
//! cannot tolerate.

use std::collections::HashMap;
use std::convert::Infallible;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::Duration;

use anyhow::{Context, Result};
use axum::Json;
use axum::Router;
use axum::extract::{Query, State};
use axum::http::{StatusCode, header};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;
use tokio_stream::StreamExt;
use tokio_stream::wrappers::BroadcastStream;
use tower_http::compression::CompressionLayer;
use tower_http::services::ServeDir;
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::trace::TraceLayer;

use tlsfp_core::pipeline::traffic::{Direction, FlowRow, Totals, TrafficHandle};
use tlsfp_core::{FingerprintEvent, PcapFileSource, Pipeline, StreamEvent};
use tlsfp_intel::{
    Alert, CatalogEntry, DetectConfig, FpKind, IntelStore, MatchReport, MatchStrength, Network,
    Rule, Stats, infer_client,
};

use crate::library::Library;
use crate::live::{LiveConfig, LiveSource, StopHandle};

/// How many serialised live lines the broadcast channel holds before the
/// slowest subscriber starts missing the oldest. A browser that lags past this
/// skips the gap rather than stalling every other client.
const STREAM_BUFFER: usize = 1024;

/// How many recent live lines the server remembers and hands to a dashboard
/// the moment it connects, so a fresh page shows what already happened instead
/// of replaying it one event at a time.
const HISTORY_LINES: usize = 500;

/// How often the library directories are scanned again for new or changed files.
const LIBRARY_RESCAN_SECS: u64 = 20;

/// How often the keep-alive comment is sent on an idle stream, below the
/// common sixty second proxy idle timeout so a quiet link stays open.
const KEEPALIVE_SECS: u64 = 15;

/// How often the database tail poller checks for alerts raised by an external
/// sensor writing to the same store.
const TAIL_POLL_MILLIS: u64 = 1000;

/// The largest export or alert page served in one response, a guard against a
/// query string asking the store for everything at once.
const MAX_PAGE: i64 = 100_000;

/// The default alert page when a request does not ask for a size.
const DEFAULT_PAGE: i64 = 200;

/// The largest batch the database tail drains per poll. It carries the last id
/// forward between ticks, so a backlog catches up over several polls rather
/// than blocking one task on a single huge read.
const TAIL_PAGE: i64 = 256;

/// Where the live events shown on the dashboard come from.
pub enum Source {
    /// Nothing in process; the stream tails the database for alerts an external
    /// `tlsfp live --detect` writes to the same store.
    Tail,
    /// Replay a capture file as a synthetic live feed, optionally looping, with
    /// a pause between events so the stream is watchable.
    Replay {
        path: PathBuf,
        looping: bool,
        interval: Duration,
    },
    /// Capture live from an interface in process, detecting and broadcasting as
    /// it goes.
    Live {
        interface: String,
        filter: String,
        promiscuous: bool,
        buffer_mib: Option<u32>,
    },
}

/// Everything the server needs to start.
pub struct ServeConfig {
    pub bind: String,
    pub db: PathBuf,
    pub web: PathBuf,
    pub source: Source,
    /// A free-text label for where this sensor is deployed, shown in the
    /// dashboard header. Never derived from the network; absent unless the
    /// operator sets it.
    pub location: Option<String>,
    /// Addresses fronting many clients; the rotation and monoculture rules skip them.
    pub shared_networks: Vec<Network>,
    /// Networks that count as this sensor's own, besides the private ranges and
    /// the capture interface's networks.
    pub local_networks: Vec<Network>,
    /// Directories of capture files to find and identify.
    pub library: Vec<PathBuf>,
    /// Host names the dashboard answers to, besides loopback, when it is bound
    /// to a loopback address (see [`host_guard`]).
    pub allowed_hosts: Vec<String>,
    /// How long observations and alerts are kept.
    pub retention: tlsfp_intel::Retention,
}

/// The live channel plus a bounded memory of what has crossed it. Publishing
/// and subscribing take the same lock, so a client that joins gets the backlog
/// followed by exactly the lines published afterwards, with no gap or repeat.
#[derive(Clone)]
struct Feed {
    tx: broadcast::Sender<Arc<str>>,
    history: Arc<Mutex<std::collections::VecDeque<Arc<str>>>>,
    /// The conversation table the capture thread fills and `/api/traffic` reads.
    traffic: TrafficHandle,
    /// The engine's counters, published by the capture thread.
    counters: tlsfp_core::CountersHandle,
    /// How the capture was set up, filled in once it starts.
    capture: Arc<std::sync::OnceLock<CaptureSetup>>,
    /// DNS seen on the wire, summarised (see `dnsbook`).
    dns: Arc<Mutex<crate::dnsbook::DnsBook>>,
}

/// How the feed is captured, for the capture health panel.
struct CaptureSetup {
    mode: &'static str,
    interface: Option<String>,
    filter: Option<String>,
    promiscuous: Option<bool>,
    buffer_mib: Option<i32>,
    kernel: Option<crate::live::KernelStats>,
}

impl Feed {
    fn new() -> Self {
        let (tx, _) = broadcast::channel::<Arc<str>>(STREAM_BUFFER);
        Self {
            tx,
            history: Arc::new(Mutex::new(std::collections::VecDeque::with_capacity(
                HISTORY_LINES,
            ))),
            traffic: TrafficHandle::default(),
            counters: tlsfp_core::CountersHandle::default(),
            capture: Arc::new(std::sync::OnceLock::new()),
            dns: Arc::new(Mutex::new(crate::dnsbook::DnsBook::default())),
        }
    }

    fn publish(&self, line: String) {
        let line: Arc<str> = Arc::from(line);
        let mut history = self
            .history
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if history.len() == HISTORY_LINES {
            history.pop_front();
        }
        history.push_back(Arc::clone(&line));
        let _ = self.tx.send(line);
    }

    /// The remembered lines, oldest first, and a receiver for everything after.
    fn join(&self) -> (Vec<Arc<str>>, broadcast::Receiver<Arc<str>>) {
        let history = self
            .history
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        (history.iter().cloned().collect(), self.tx.subscribe())
    }
}

/// Shared state every handler reads through. The store is the read side of the
/// database behind a mutex; the sender is the live channel handlers subscribe
/// to.
struct AppState {
    store: Mutex<IntelStore>,
    feed: Feed,
    library: Library,
    db: PathBuf,
    /// Open event streams, capped at [`MAX_STREAMS`].
    streams: std::sync::atomic::AtomicUsize,
    /// One report is built at a time: each reads a whole capture file.
    report_gate: tokio::sync::Semaphore,
    /// Throughput per second for the last [`RATE_POINTS`] seconds, kept here
    /// rather than in each browser so the chart is full when a page opens.
    rates: Mutex<std::collections::VecDeque<RatePoint>>,
    /// What the intelligence feed and the family rules say about each client
    /// fingerprint seen in a conversation, looked up once per fingerprint.
    client_cache: Mutex<HashMap<String, ClientInfo>>,
    meta: Meta,
}

/// The longest sensor location label the header will carry.
const MAX_LOCATION_CHARS: usize = 80;

/// What this sensor is doing, as the dashboard header shows it. Every field is
/// real runtime state or an operator-supplied label; nothing is guessed from
/// the network, and no filesystem path is exposed.
#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
struct Meta {
    version: &'static str,
    source: SourceMeta,
    started_unix_ms: u64,
    location: Option<String>,
    /// The name of the computer this server runs on.
    hostname: Option<String>,
}

#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
struct SourceMeta {
    /// `tail`, `replay` or `live`.
    kind: &'static str,
    /// The interface for `live`, the capture file name (not its path) for
    /// `replay`, nothing for `tail`.
    detail: Option<String>,
    looping: bool,
}

impl Meta {
    fn new(config: &ServeConfig, started_unix_ms: u64) -> Self {
        let source = match &config.source {
            Source::Tail => SourceMeta {
                kind: "tail",
                detail: None,
                looping: false,
            },
            Source::Replay { path, looping, .. } => SourceMeta {
                kind: "replay",
                detail: path
                    .file_name()
                    .map(|name| name.to_string_lossy().into_owned()),
                looping: *looping,
            },
            Source::Live { interface, .. } => SourceMeta {
                kind: "live",
                detail: Some(interface.clone()),
                looping: false,
            },
        };
        let location = config
            .location
            .as_deref()
            .map(str::trim)
            .filter(|label| !label.is_empty())
            .map(|label| label.chars().take(MAX_LOCATION_CHARS).collect());
        Self {
            version: env!("CARGO_PKG_VERSION"),
            source,
            started_unix_ms,
            location,
            hostname: crate::live::local_hostname(),
        }
    }
}

impl AppState {
    /// Locks the store, recovering the guard if a previous handler panicked
    /// while holding it, since a poisoned read connection is still usable.
    fn store(&self) -> MutexGuard<'_, IntelStore> {
        self.store
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

type Shared = Arc<AppState>;

/// One message on the live stream: either a freshly fingerprinted flow with its
/// intelligence and any alerts it raised, or a standalone alert the database
/// tail surfaced. Serialised once by the producer and sent as an opaque line,
/// so a thousand subscribers cost one serialisation, not a thousand.
#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum LiveMessage {
    Flow {
        event: FingerprintEvent,
        #[serde(skip_serializing_if = "Vec::is_empty")]
        intel: Vec<MatchReport>,
        #[serde(skip_serializing_if = "Vec::is_empty")]
        alerts: Vec<Alert>,
        /// Who the client appears to be, for a ClientHello only.
        #[serde(skip_serializing_if = "Option::is_none")]
        client: Option<Box<ClientRead>>,
    },
    Alert {
        alert: Alert,
    },
}

fn new_state(store: IntelStore, feed: Feed, config: &ServeConfig, started_unix_ms: u64) -> Shared {
    Arc::new(AppState {
        store: Mutex::new(store),
        feed,
        library: Library::default(),
        db: config.db.clone(),
        streams: std::sync::atomic::AtomicUsize::new(0),
        report_gate: tokio::sync::Semaphore::new(1),
        rates: Mutex::new(std::collections::VecDeque::with_capacity(RATE_POINTS)),
        client_cache: Mutex::new(HashMap::new()),
        meta: Meta::new(config, started_unix_ms),
    })
}

/// What a ClientHello says about its sender: an exact intelligence match when
/// there is one, otherwise the family its shape suggests, with the evidence and
/// the limit of the claim, so the dashboard can show more than a hash.
#[derive(Serialize)]
struct ClientRead {
    /// The label of an exact intelligence match, if any.
    known_as: Option<String>,
    family: &'static str,
    /// Human name of the family.
    family_name: &'static str,
    confidence: tlsfp_intel::Confidence,
    reasons: Vec<String>,
    caveat: Option<&'static str>,
}

fn read_client(raw: &str, intel: &[MatchReport]) -> ClientRead {
    let guess = infer_client(raw);
    let known_as = intel
        .iter()
        .flat_map(|report| report.hits.iter())
        .find(|hit| hit.strength == MatchStrength::Exact)
        .map(|hit| hit.label.clone());
    ClientRead {
        known_as,
        family: family_token(guess.family),
        family_name: guess.family.display(),
        confidence: guess.confidence,
        reasons: guess.reasons,
        caveat: guess.caveat,
    }
}

/// Runs the dashboard until interrupted. Builds its own runtime so the rest of
/// the program stays a synchronous command line tool, the same split the live
/// capture path uses.
pub fn run(config: ServeConfig) -> Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("building the async runtime")?;
    runtime.block_on(serve(config))
}

async fn serve(config: ServeConfig) -> Result<()> {
    let store = IntelStore::open(&config.db)
        .with_context(|| format!("opening intelligence database {}", config.db.display()))?;
    if store.latest_alert_id().unwrap_or(0) == 0 {
        tracing::info!(
            "the store holds no alerts yet; run a capture with --detect, or start serve with --replay or --live to populate the stream"
        );
    }

    let feed = Feed::new();
    let started_unix_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        });
    let state = new_state(store, feed.clone(), &config, started_unix_ms);

    let shutdown = Arc::new(AtomicBool::new(false));
    let scanner = (!config.library.is_empty()).then(|| {
        let library = state.library.clone();
        let dirs = config.library.clone();
        let db = config.db.clone();
        let stop = Arc::clone(&shutdown);
        std::thread::Builder::new()
            .name("library".into())
            .spawn(move || {
                library.watch(&dirs, &db, Duration::from_secs(LIBRARY_RESCAN_SECS), &stop);
            })
    });
    if let Some(Err(error)) = &scanner {
        tracing::error!(%error, "could not start the library scanner");
    }
    let sampler = {
        let state = Arc::clone(&state);
        let stop = Arc::clone(&shutdown);
        std::thread::Builder::new()
            .name("rates".into())
            .spawn(move || sample_rates(&state, &stop))
    };
    if let Err(error) = &sampler {
        tracing::error!(%error, "could not start the throughput sampler");
    }
    let pruner = {
        let db = config.db.clone();
        let policy = config.retention;
        let stop = Arc::clone(&shutdown);
        std::thread::Builder::new()
            .name("retention".into())
            .spawn(move || prune_loop(&db, policy, &stop))
    };
    if let Err(error) = &pruner {
        tracing::error!(%error, "could not start the retention task");
    }
    let mut capture = spawn_source(&config, feed, Arc::clone(&shutdown), Arc::clone(&state))?;

    let app = router(&config.web, Arc::clone(&state), &allowed_hosts(&config));
    let listener = tokio::net::TcpListener::bind(&config.bind)
        .await
        .with_context(|| format!("binding {}", config.bind))?;
    let addr = listener.local_addr().context("reading the bound address")?;
    tracing::info!(%addr, web = %config.web.display(), "dashboard listening on http://{addr}");

    let result = axum::serve(listener, app.into_make_service())
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("serving the dashboard");

    shutdown.store(true, Ordering::Relaxed);
    capture.stop();
    result
}

/// Builds the route table. The data API and the static files are compressed;
/// the event stream is merged in afterwards so the compression layer never
/// touches it.
fn router(web: &std::path::Path, state: Shared, allowed: &[String]) -> Router {
    let data_api = Router::new()
        .route("/stats", get(stats))
        .route("/alerts", get(alerts))
        .route("/search", get(search))
        .route("/export", get(export))
        .route("/health", get(health))
        .route("/meta", get(meta))
        .route("/library", get(library))
        .route("/library/{id}/report", get(library_report))
        .route("/traffic", get(traffic))
        .route("/observed", get(observed))
        .route("/hosts", get(hosts))
        .route("/hosts/{ip}", get(host_profile))
        .layer(CompressionLayer::new());

    let stream_api = Router::new().route("/stream", get(stream));

    let state_for_metrics = Arc::clone(&state);
    let api = data_api.merge(stream_api).with_state(state);

    // A missing file is a 404. Only a page navigation (a path with no file
    // extension) falls back to index.html, so a request for a stale script
    // gets an honest 404 rather than HTML with a 200 that the browser then
    // fails to run as a module.
    let static_files = ServeDir::new(web).append_index_html_on_directories(true);
    let web_root = Arc::new(web.to_path_buf());

    let ops = Router::new()
        .route("/api/capture", get(capture_health))
        .route("/api/dns", get(dns_view))
        .route("/api/interfaces", get(interfaces))
        .route("/metrics", get(metrics))
        .with_state(Arc::clone(&state_for_metrics));

    Router::new()
        .nest("/api", api)
        .merge(ops)
        .fallback_service(static_files)
        .layer(axum::middleware::from_fn_with_state(
            web_root,
            static_policy,
        ))
        .layer(axum::middleware::from_fn_with_state(
            Arc::new(allowed.to_vec()),
            host_guard,
        ))
        .layer(security_header(
            axum::http::header::CONTENT_SECURITY_POLICY,
            CONTENT_SECURITY_POLICY,
        ))
        .layer(security_header(
            axum::http::header::X_CONTENT_TYPE_OPTIONS,
            "nosniff",
        ))
        .layer(security_header(axum::http::header::X_FRAME_OPTIONS, "DENY"))
        .layer(security_header(
            axum::http::header::REFERRER_POLICY,
            "no-referrer",
        ))
        .layer(TraceLayer::new_for_http())
}

/// The host names a loopback-bound dashboard answers to. Empty (no check) when
/// it is bound to a network address, where the operator's own proxy and
/// authentication are in charge and the names are theirs to choose.
fn allowed_hosts(config: &ServeConfig) -> Vec<String> {
    let loopback = config
        .bind
        .rsplit_once(':')
        .map(|(host, _)| host.trim_matches(['[', ']']))
        .is_some_and(|host| {
            host == "localhost"
                || host
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback())
        });
    if !loopback {
        return Vec::new();
    }
    let mut hosts: Vec<String> = ["localhost", "127.0.0.1", "::1"]
        .iter()
        .map(|h| (*h).to_owned())
        .collect();
    hosts.extend(config.allowed_hosts.iter().map(|h| h.to_ascii_lowercase()));
    hosts
}

/// Refuses a request whose `Host` is not one the dashboard expects.
///
/// A dashboard on `127.0.0.1` shows who your machine talks to. Without this, a
/// web page on any site could point its own domain at `127.0.0.1` (DNS
/// rebinding) and read the API as if it were the same origin. A rebinding page
/// still sends its own domain as the Host, so checking it closes that route.
async fn host_guard(
    State(allowed): State<Arc<Vec<String>>>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    if allowed.is_empty() {
        return next.run(request).await;
    }
    let host = request
        .headers()
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .map(host_without_port)
        .unwrap_or_default();
    if allowed.contains(&host) {
        return next.run(request).await;
    }
    tracing::warn!(
        host,
        "refused a request for an unexpected Host; use --allowed-host to permit it"
    );
    (
        StatusCode::MISDIRECTED_REQUEST,
        Json(serde_json::json!({
            "error": "this dashboard answers only to localhost; start it with --allowed-host NAME to use another name"
        })),
    )
        .into_response()
}

/// `example.com:8080` to `example.com`, `[::1]:8080` to `::1`.
fn host_without_port(value: &str) -> String {
    let value = value.trim().to_ascii_lowercase();
    if let Some(rest) = value.strip_prefix('[') {
        return rest.split(']').next().unwrap_or_default().to_owned();
    }
    value
        .rsplit_once(':')
        .map_or(value.clone(), |(host, port)| {
            if port.bytes().all(|b| b.is_ascii_digit()) {
                host.to_owned()
            } else {
                value.clone()
            }
        })
}

/// Serves the single-page app and sets the caching that keeps a new build from
/// being masked by an old one: the page and unhashed files are revalidated on
/// every load, hashed bundles are cached for good, and data is never cached.
async fn static_policy(
    State(web): State<Arc<std::path::PathBuf>>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let path = request.uri().path().to_owned();
    let mut response = next.run(request).await;
    if response.status() == StatusCode::NOT_FOUND && is_navigation(&path) {
        if let Ok(page) = tokio::fs::read(web.join("index.html")).await {
            response = (
                StatusCode::OK,
                [(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")],
                page,
            )
                .into_response();
        }
    }
    let policy = cache_policy(&path, response.status());
    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static(policy),
    );
    response
}

/// A browser asking for a page, as opposed to a file or the API.
fn is_navigation(path: &str) -> bool {
    !path.starts_with("/api/")
        && path != "/metrics"
        && !path
            .rsplit('/')
            .next()
            .is_some_and(|last| last.contains('.'))
}

fn cache_policy(path: &str, status: StatusCode) -> &'static str {
    if path.starts_with("/api/") || path == "/metrics" {
        "no-store"
    } else if status.is_success() && is_hashed_bundle(path) {
        "public, max-age=31536000, immutable"
    } else {
        "no-cache"
    }
}

/// `/assets/name-HASH.js` or `.css`: the build names these by content, so a
/// changed file always has a new name.
fn is_hashed_bundle(path: &str) -> bool {
    let Some(file) = path.strip_prefix("/assets/") else {
        return false;
    };
    let Some(stem) = file
        .strip_suffix(".js")
        .or_else(|| file.strip_suffix(".css"))
    else {
        return false;
    };
    !file.contains('/')
        && stem
            .rsplit_once('-')
            .is_some_and(|(_, hash)| hash.len() >= 6)
}

/// The dashboard loads its own script, style and data and nothing else, so the
/// policy says exactly that. A hostile server name or User-Agent that somehow
/// reached the page as markup could not run script or load anything remote.
const CONTENT_SECURITY_POLICY: &str = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";

fn security_header(
    name: axum::http::HeaderName,
    value: &'static str,
) -> SetResponseHeaderLayer<axum::http::HeaderValue> {
    SetResponseHeaderLayer::if_not_present(name, axum::http::HeaderValue::from_static(value))
}

/// A count of alerts attributed to one rule, the shape the distribution chart
/// reads.
#[derive(Serialize)]
struct RuleCount {
    rule: Rule,
    count: i64,
}

/// The summary the dashboard header and distribution chart draw from: what the
/// intelligence store holds, and how the alerts raised so far break down by
/// rule.
#[derive(Serialize)]
struct StatsResponse {
    intel: Stats,
    alerts_by_rule: Vec<RuleCount>,
    alert_total: i64,
    /// Alerts above informational severity, what the menu badge counts.
    alert_attention: i64,
}

/// Prometheus text exposition: totals a monitoring system can scrape and
/// graph. Only what the server itself holds is reported (conversation byte and
/// packet counts, alerts per rule, the size of the intelligence feed); capture
/// drops are printed in the log when a capture ends and are not exported here.
async fn metrics(State(state): State<Shared>) -> Result<impl IntoResponse, ApiError> {
    let body = tokio::task::spawn_blocking(move || -> Result<String> {
        use std::fmt::Write as _;
        let (totals, active) = state.feed.traffic.with(|t| (t.totals(), t.len()));
        let (intel, counts) = {
            let store = state.store();
            (store.stats()?, store.alert_counts()?)
        };
        let mut out = String::new();
        let _ = writeln!(out, "# HELP tlsfp_info Build information.\n# TYPE tlsfp_info gauge");
        let _ = writeln!(out, "tlsfp_info{{version=\"{}\"}} 1", state.meta.version);
        let _ = writeln!(out, "# HELP tlsfp_traffic_bytes_total Bytes seen on the wire by direction across the local network boundary.\n# TYPE tlsfp_traffic_bytes_total counter");
        for (direction, value) in [
            ("out", totals.out_bytes),
            ("in", totals.in_bytes),
            ("internal", totals.internal_bytes),
            ("transit", totals.transit_bytes),
        ] {
            let _ = writeln!(out, "tlsfp_traffic_bytes_total{{direction=\"{direction}\"}} {value}");
        }
        let _ = writeln!(out, "# HELP tlsfp_traffic_packets_total Packets seen by direction.\n# TYPE tlsfp_traffic_packets_total counter");
        for (direction, value) in [
            ("out", totals.out_packets),
            ("in", totals.in_packets),
            ("internal", totals.internal_packets),
            ("transit", totals.transit_packets),
        ] {
            let _ = writeln!(out, "tlsfp_traffic_packets_total{{direction=\"{direction}\"}} {value}");
        }
        let _ = writeln!(out, "# HELP tlsfp_conversations Conversations currently tracked.\n# TYPE tlsfp_conversations gauge\ntlsfp_conversations {active}");
        let _ = writeln!(out, "# HELP tlsfp_conversations_shed_total Conversations dropped because the table was full.\n# TYPE tlsfp_conversations_shed_total counter\ntlsfp_conversations_shed_total {}", totals.flows_shed);
        {
            let view = build_capture_view(&state);
            let c = &view.counters;
            for (name, help, value) in [
                ("tlsfp_frames_total", "Frames read by the engine.", c.frames),
                ("tlsfp_handshakes_fingerprinted_total", "TLS handshake messages fully read.", c.tls_handshakes_fingerprinted),
                ("tlsfp_tls_streams_unfinished_total", "TLS streams that ended before a full handshake was read.", c.unfinished_tls_streams),
                ("tlsfp_flows_evicted_pressure_total", "Conversations shed because the table was full.", c.flows_evicted_pressure),
                ("tlsfp_streams_capped_total", "Streams clipped at the per-stream limit.", c.streams_capped),
                ("tlsfp_frames_malformed_total", "Frames skipped as malformed.", c.skipped_malformed),
                ("tlsfp_quic_initials_total", "QUIC Initial packets seen.", c.quic_initials),
                ("tlsfp_quic_decrypted_total", "QUIC client Initials decrypted.", c.quic_decrypted),
            ] {
                let _ = writeln!(out, "# HELP {name} {help}\n# TYPE {name} counter\n{name} {value}");
            }
            let dns = state
                .feed
                .dns
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .totals();
            for (name, help, value) in [
                ("tlsfp_dns_queries_total", "DNS queries seen on UDP 53.", dns.queries),
                ("tlsfp_dns_nxdomain_total", "DNS responses reporting a name that does not exist.", dns.nxdomain),
            ] {
                let _ = writeln!(out, "# HELP {name} {help}\n# TYPE {name} counter\n{name} {value}");
            }
            if let Some(kernel) = &view.kernel {
                let _ = writeln!(out, "# HELP tlsfp_kernel_received_total Frames the capture socket accepted.\n# TYPE tlsfp_kernel_received_total counter\ntlsfp_kernel_received_total {}", kernel.received);
                let _ = writeln!(out, "# HELP tlsfp_kernel_dropped_total Frames the kernel dropped because the reader fell behind.\n# TYPE tlsfp_kernel_dropped_total counter\ntlsfp_kernel_dropped_total {}", kernel.dropped + kernel.interface_dropped);
            }
        }
        let _ = writeln!(out, "# HELP tlsfp_alerts_total Alerts recorded, by rule.\n# TYPE tlsfp_alerts_total counter");
        for (rule, count) in counts {
            let _ = writeln!(out, "tlsfp_alerts_total{{rule=\"{}\"}} {count}", rule.as_str());
        }
        if let Some(stats) = crate::deliver::stats() {
            let _ = writeln!(out, "# HELP tlsfp_alert_delivery_total Alerts forwarded to the configured destinations, by outcome.\n# TYPE tlsfp_alert_delivery_total counter");
            for (outcome, value) in [
                ("delivered", &stats.delivered),
                ("failed", &stats.failed),
                ("dropped", &stats.dropped),
            ] {
                let _ = writeln!(out, "tlsfp_alert_delivery_total{{outcome=\"{outcome}\"}} {}", value.load(std::sync::atomic::Ordering::Relaxed));
            }
        }
        let _ = writeln!(out, "# HELP tlsfp_intel_fingerprints Fingerprints in the intelligence feed.\n# TYPE tlsfp_intel_fingerprints gauge\ntlsfp_intel_fingerprints {}", intel.total);
        Ok(out)
    })
    .await??;
    Ok((
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        body,
    ))
}

async fn stats(State(state): State<Shared>) -> Result<Json<StatsResponse>, ApiError> {
    let response = tokio::task::spawn_blocking(move || -> Result<StatsResponse> {
        let store = state.store();
        let intel = store.stats()?;
        let counts = store.alert_counts()?;
        let alert_total = counts.iter().map(|(_, count)| count).sum();
        let alert_attention = store.actionable_alert_count()?;
        let alerts_by_rule = counts
            .into_iter()
            .map(|(rule, count)| RuleCount { rule, count })
            .collect();
        Ok(StatsResponse {
            intel,
            alerts_by_rule,
            alert_total,
            alert_attention,
        })
    })
    .await??;
    Ok(Json(response))
}

#[derive(Deserialize)]
struct AlertsQuery {
    limit: Option<i64>,
}

async fn alerts(
    State(state): State<Shared>,
    Query(query): Query<AlertsQuery>,
) -> Result<Json<Vec<Alert>>, ApiError> {
    let limit = page_size(query.limit);
    let alerts = tokio::task::spawn_blocking(move || state.store().recent_alerts(limit)).await??;
    Ok(Json(alerts))
}

#[derive(Deserialize)]
struct SearchQuery {
    q: Option<String>,
    kind: Option<String>,
    limit: Option<i64>,
}

async fn search(
    State(state): State<Shared>,
    Query(query): Query<SearchQuery>,
) -> Result<Json<Vec<CatalogEntry>>, ApiError> {
    let kind = match query.kind.as_deref().filter(|token| !token.is_empty()) {
        Some(token) => Some(FpKind::from_token(&token.to_ascii_lowercase()).ok_or_else(|| {
            ApiError::bad_request(format!(
                "unknown fingerprint kind '{token}'; expected ja3, ja3s, ja4, ja4s, ja4h, ja4x, ja4t, or ja4ts"
            ))
        })?),
        None => None,
    };
    let needle = query.q.unwrap_or_default();
    let limit = page_size(query.limit);
    let entries =
        tokio::task::spawn_blocking(move || state.store().search(&needle, kind, limit)).await??;
    Ok(Json(entries))
}

#[derive(Deserialize)]
struct ExportQuery {
    format: Option<String>,
    limit: Option<i64>,
}

async fn export(
    State(state): State<Shared>,
    Query(query): Query<ExportQuery>,
) -> Result<Response, ApiError> {
    let limit = query.limit.unwrap_or(MAX_PAGE).clamp(1, MAX_PAGE);
    let csv = matches!(query.format.as_deref(), Some("csv"));
    let alerts = tokio::task::spawn_blocking(move || state.store().recent_alerts(limit)).await??;

    if csv {
        let body = alerts_to_csv(&alerts)?;
        Ok((
            [
                (header::CONTENT_TYPE, "text/csv; charset=utf-8"),
                (
                    header::CONTENT_DISPOSITION,
                    "attachment; filename=\"tlsfp-alerts.csv\"",
                ),
            ],
            body,
        )
            .into_response())
    } else {
        let body = serde_json::to_vec_pretty(&alerts).context("serialising alerts as JSON")?;
        Ok((
            [
                (header::CONTENT_TYPE, "application/json"),
                (
                    header::CONTENT_DISPOSITION,
                    "attachment; filename=\"tlsfp-alerts.json\"",
                ),
            ],
            body,
        )
            .into_response())
    }
}

async fn meta(State(state): State<Shared>) -> Json<Meta> {
    Json(state.meta.clone())
}

/// What is known about a client fingerprint seen in a conversation.
#[derive(Clone, Serialize)]
struct ClientInfo {
    /// The label of an exact intelligence match, if any.
    known_as: Option<String>,
    /// The family read from the ClientHello's shape.
    family: &'static str,
}

#[derive(Serialize)]
struct TrafficFlow {
    #[serde(flatten)]
    flow: FlowRow,
    client_info: Option<ClientInfo>,
}

#[derive(Serialize)]
struct Talker {
    host: String,
    flows: usize,
    bytes_up: u64,
    bytes_down: u64,
    names: Vec<String>,
}

#[derive(Serialize)]
struct ServiceShare {
    service: String,
    flows: usize,
    bytes: u64,
}

/// How often old records are removed while the server runs.
const PRUNE_EVERY: Duration = Duration::from_secs(15 * 60);

/// Applies the retention policy on its own connection, so the shared store is
/// never held while rows are deleted.
fn prune_loop(db: &std::path::Path, policy: tlsfp_intel::Retention, stop: &AtomicBool) {
    let mut waited = PRUNE_EVERY; // once soon after start, then every interval
    waited = waited.saturating_sub(Duration::from_secs(30));
    while !stop.load(std::sync::atomic::Ordering::Relaxed) {
        if waited >= PRUNE_EVERY {
            waited = Duration::ZERO;
            match IntelStore::open(db).and_then(|mut store| store.prune(policy)) {
                Ok(pruned) if pruned.observations + pruned.alerts > 0 => {
                    tracing::info!(
                        observations = pruned.observations,
                        alerts = pruned.alerts,
                        "retention removed old records"
                    );
                }
                Ok(_) => {}
                Err(error) => tracing::warn!(%error, "retention could not run"),
            }
        }
        std::thread::sleep(Duration::from_secs(1));
        waited += Duration::from_secs(1);
    }
}

/// How many one-second throughput points are kept: fifteen minutes.
const RATE_POINTS: usize = 900;

/// Bytes moved in one second, by direction. "other" is internal and transit,
/// which a sensor on a gateway can see a lot of.
#[derive(Clone, Serialize)]
struct RatePoint {
    t_ms: u64,
    out_bytes: u64,
    in_bytes: u64,
    other_bytes: u64,
    packets: u64,
}

/// Every second, turns the monotonic traffic counters into a throughput point.
fn sample_rates(state: &Shared, stop: &AtomicBool) {
    let mut last = state.feed.traffic.with(|t| t.totals());
    while !stop.load(std::sync::atomic::Ordering::Relaxed) {
        std::thread::sleep(Duration::from_secs(1));
        let now = state.feed.traffic.with(|t| t.totals());
        let t_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
        let point = RatePoint {
            t_ms,
            out_bytes: now.out_bytes.saturating_sub(last.out_bytes),
            in_bytes: now.in_bytes.saturating_sub(last.in_bytes),
            other_bytes: (now.internal_bytes + now.transit_bytes)
                .saturating_sub(last.internal_bytes + last.transit_bytes),
            packets: (now.out_packets
                + now.in_packets
                + now.internal_packets
                + now.transit_packets)
                .saturating_sub(
                    last.out_packets
                        + last.in_packets
                        + last.internal_packets
                        + last.transit_packets,
                ),
        };
        last = now;
        let mut rates = state
            .rates
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if rates.len() == RATE_POINTS {
            rates.pop_front();
        }
        rates.push_back(point);
    }
}

#[derive(Serialize)]
struct TrafficView {
    /// False when the server has no packet source of its own (database tail).
    enabled: bool,
    totals: Totals,
    active_flows: usize,
    /// Capture time of the newest packet, so a reader can age conversations
    /// relative to the capture, which for a replay is not the wall clock.
    latest_ns: u64,
    talkers: Vec<Talker>,
    services: Vec<ServiceShare>,
    flows: Vec<TrafficFlow>,
    /// One point per second, oldest first.
    history: Vec<RatePoint>,
}

/// How many conversations one response carries at most.
const MAX_TRAFFIC_FLOWS: usize = 1000;
const DEFAULT_TRAFFIC_FLOWS: usize = 300;

#[derive(Deserialize)]
struct TrafficQuery {
    limit: Option<usize>,
}

/// One thing the operator should know about how well the capture is reading.
#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
struct HealthNote {
    /// `warn` when results are being lost, `info` when they are only limited.
    level: &'static str,
    text: String,
}

#[derive(Serialize)]
struct KernelView {
    received: u64,
    dropped: u64,
    interface_dropped: u64,
}

#[derive(Serialize)]
struct LimitsView {
    max_flows: usize,
    idle_timeout_secs: u64,
    stream_limit_kib: usize,
}

/// How the capture is set up and how well it is reading: the numbers that
/// tell an operator whether an absence of fingerprints means an absence of
/// handshakes.
#[derive(Serialize)]
struct CaptureView {
    mode: String,
    interface: Option<String>,
    filter: Option<String>,
    promiscuous: Option<bool>,
    buffer_mib: Option<i32>,
    limits: LimitsView,
    counters: tlsfp_core::Counters,
    kernel: Option<KernelView>,
    /// Share of recognised TLS streams that ended before a full handshake
    /// message was read.
    tls_miss_rate: f64,
    /// `ok`, `degraded` (limits hit) or `lossy` (frames lost).
    status: &'static str,
    notes: Vec<HealthNote>,
}

/// How much a finding matters to the results.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Weight {
    Info,
    /// Results are limited (clipped streams, partial handshakes).
    Limit,
    /// Frames or conversations were lost.
    Loss,
}

/// Turns raw counters into plain statements about what may have been missed.
/// Pure so every threshold is tested.
fn assess(
    counters: &tlsfp_core::Counters,
    kernel: Option<&KernelView>,
    limits: &LimitsView,
) -> (&'static str, Vec<HealthNote>) {
    let mut found: Vec<(Weight, String)> = Vec::new();
    if let Some(kernel) = kernel {
        let lost = kernel.dropped + kernel.interface_dropped;
        if lost > 0 {
            #[allow(clippy::cast_precision_loss)]
            let share = lost as f64 / (kernel.received + lost).max(1) as f64 * 100.0;
            found.push((
                Weight::Loss,
                format!(
                    "The kernel dropped {lost} frames ({share:.2}% of those offered) because the \
                     reader fell behind. Some handshakes were not seen. Raise --buffer-mib or \
                     narrow --filter."
                ),
            ));
        }
    }
    if counters.flows_evicted_pressure > 0 {
        found.push((
            Weight::Loss,
            format!(
                "The conversation table filled {} times and shed live conversations (limit {}). \
                 Raise --max-flows.",
                counters.flows_evicted_pressure, limits.max_flows
            ),
        ));
    }
    let recognised = counters.tls_handshakes_fingerprinted + counters.unfinished_tls_streams;
    if counters.tls_miss_rate() > 0.05 && recognised >= 20 {
        found.push((
            Weight::Limit,
            format!(
                "{:.1}% of TLS streams ended before a full handshake was read (packet loss, \
                 asymmetric routing or a clipped capture).",
                counters.tls_miss_rate() * 100.0
            ),
        ));
    }
    if counters.streams_capped > 0 {
        found.push((
            Weight::Limit,
            format!(
                "{} streams exceeded the per-stream limit ({} KiB) and were clipped. Raise \
                 --stream-limit-kib to read larger certificate chains.",
                counters.streams_capped, limits.stream_limit_kib
            ),
        ));
    }
    if counters.segments_dropped > 0 {
        found.push((
            Weight::Info,
            format!(
                "{} out-of-order or overlapping segments were discarded by the reassembler.",
                counters.segments_dropped
            ),
        ));
    }
    if counters.skipped_malformed > 0 {
        found.push((
            Weight::Info,
            format!(
                "{} frames were malformed and skipped.",
                counters.skipped_malformed
            ),
        ));
    }
    if counters.quic_version_unsupported > 0 {
        found.push((
            Weight::Info,
            format!(
                "{} QUIC Initials used a version this build cannot open.",
                counters.quic_version_unsupported
            ),
        ));
    }
    let worst = found.iter().map(|(weight, _)| *weight).max();
    let status = match worst {
        Some(Weight::Loss) => "lossy",
        Some(Weight::Limit) => "degraded",
        _ => "ok",
    };
    let notes = found
        .into_iter()
        .map(|(weight, text)| HealthNote {
            level: if weight == Weight::Info {
                "info"
            } else {
                "warn"
            },
            text,
        })
        .collect();
    (status, notes)
}

#[derive(Deserialize)]
struct DnsQuery {
    limit: Option<usize>,
}

async fn dns_view(
    State(state): State<Shared>,
    Query(query): Query<DnsQuery>,
) -> Json<crate::dnsbook::DnsView> {
    let top = query.limit.unwrap_or(25).clamp(1, 200);
    Json(
        state
            .feed
            .dns
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .view(top),
    )
}

#[derive(Serialize)]
struct InterfacesView {
    /// False when the capture library is not usable (for example Npcap is not
    /// installed); `reason` says why.
    available: bool,
    reason: Option<String>,
    /// The interface this server is capturing from, when it is capturing.
    current: Option<String>,
    interfaces: Vec<crate::live::InterfaceInfo>,
}

async fn interfaces(State(state): State<Shared>) -> Result<Json<InterfacesView>, ApiError> {
    let listed = tokio::task::spawn_blocking(crate::live::list_interfaces).await?;
    let current = state.feed.capture.get().and_then(|c| c.interface.clone());
    Ok(Json(match listed {
        Ok(interfaces) => InterfacesView {
            available: true,
            reason: None,
            current,
            interfaces,
        },
        Err(reason) => InterfacesView {
            available: false,
            reason: Some(reason),
            current,
            interfaces: Vec::new(),
        },
    }))
}

async fn capture_health(State(state): State<Shared>) -> Json<CaptureView> {
    Json(build_capture_view(&state))
}

fn build_capture_view(state: &Shared) -> CaptureView {
    let config = crate::engine::config();
    let limits = LimitsView {
        max_flows: config.max_flows,
        idle_timeout_secs: config.idle_timeout_nanos / 1_000_000_000,
        stream_limit_kib: config.max_assembled_bytes / 1024,
    };
    let counters = state.feed.counters.get();
    let setup = state.feed.capture.get();
    let kernel = setup.and_then(|s| s.kernel.as_ref()).map(|k| {
        let counts = k.get();
        KernelView {
            received: counts.received,
            dropped: counts.kernel_dropped,
            interface_dropped: counts.interface_dropped,
        }
    });
    let (status, notes) = assess(&counters, kernel.as_ref(), &limits);
    CaptureView {
        mode: setup.map_or_else(|| state.meta.source.kind.to_owned(), |s| s.mode.to_owned()),
        interface: setup.and_then(|s| s.interface.clone()),
        filter: setup.and_then(|s| s.filter.clone()),
        promiscuous: setup.and_then(|s| s.promiscuous),
        buffer_mib: setup.and_then(|s| s.buffer_mib),
        limits,
        tls_miss_rate: counters.tls_miss_rate(),
        counters,
        kernel,
        status,
        notes,
    }
}

async fn traffic(
    State(state): State<Shared>,
    Query(query): Query<TrafficQuery>,
) -> Result<Json<TrafficView>, ApiError> {
    let limit = query
        .limit
        .unwrap_or(DEFAULT_TRAFFIC_FLOWS)
        .clamp(1, MAX_TRAFFIC_FLOWS);
    let view = tokio::task::spawn_blocking(move || build_traffic_view(&state, limit)).await?;
    Ok(Json(view))
}

fn build_traffic_view(state: &Shared, limit: usize) -> TrafficView {
    let (totals, active, rows) = state
        .feed
        .traffic
        .with(|t| (t.totals(), t.len(), t.all_rows()));
    let latest_ns = rows.iter().map(|r| r.last_ns).max().unwrap_or(0);

    let mut hosts: HashMap<String, Talker> = HashMap::new();
    let mut services: HashMap<String, ServiceShare> = HashMap::new();
    for row in &rows {
        let remote = match row.direction {
            Direction::Inbound => row.client,
            _ => row.server,
        };
        let talker = hosts
            .entry(remote.ip().to_string())
            .or_insert_with(|| Talker {
                host: remote.ip().to_string(),
                flows: 0,
                bytes_up: 0,
                bytes_down: 0,
                names: Vec::new(),
            });
        talker.flows += 1;
        talker.bytes_up += row.bytes_up;
        talker.bytes_down += row.bytes_down;
        if let Some(name) = &row.sni {
            if talker.names.len() < 3 && !talker.names.contains(name) {
                talker.names.push(name.clone());
            }
        }
        let label = row.service.map_or_else(
            || format!("{:?}/{}", row.proto, row.server.port()).to_lowercase(),
            str::to_owned,
        );
        let share = services
            .entry(label.clone())
            .or_insert_with(|| ServiceShare {
                service: label,
                flows: 0,
                bytes: 0,
            });
        share.flows += 1;
        share.bytes += row.bytes_up + row.bytes_down;
    }
    let mut talkers: Vec<Talker> = hosts.into_values().collect();
    talkers.sort_by(|a, b| {
        (b.bytes_up + b.bytes_down)
            .cmp(&(a.bytes_up + a.bytes_down))
            .then_with(|| a.host.cmp(&b.host))
    });
    talkers.truncate(15);
    let mut services: Vec<ServiceShare> = services.into_values().collect();
    services.sort_by(|a, b| {
        b.bytes
            .cmp(&a.bytes)
            .then_with(|| a.service.cmp(&b.service))
    });
    services.truncate(10);

    let mut recent = rows;
    recent.sort_by(|a, b| {
        b.last_ns
            .cmp(&a.last_ns)
            .then_with(|| a.client.cmp(&b.client))
    });
    recent.truncate(limit);
    let flows = recent
        .into_iter()
        .map(|flow| {
            let client_info = flow
                .ja4
                .as_deref()
                .zip(flow.ja4_raw.as_deref())
                .map(|(hash, raw)| client_info(state, hash, raw));
            TrafficFlow { flow, client_info }
        })
        .collect();

    TrafficView {
        enabled: !matches!(state.meta.source.kind, "tail"),
        totals,
        active_flows: active,
        latest_ns,
        talkers,
        services,
        flows,
        history: state
            .rates
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .cloned()
            .collect(),
    }
}

/// Looks a client fingerprint up once and remembers the answer.
fn client_info(state: &Shared, hash: &str, raw: &str) -> ClientInfo {
    if let Some(found) = state
        .client_cache
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(hash)
    {
        return found.clone();
    }
    let known_as = state
        .store()
        .match_fingerprint(FpKind::Ja4, hash)
        .ok()
        .and_then(|report| {
            report
                .hits
                .into_iter()
                .find(|hit| hit.strength == MatchStrength::Exact)
                .map(|hit| hit.label)
        });
    let info = ClientInfo {
        known_as,
        family: family_token(infer_client(raw).family),
    };
    let mut cache = state
        .client_cache
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if cache.len() < 4096 {
        cache.insert(hash.to_owned(), info.clone());
    }
    info
}

fn family_token(family: tlsfp_intel::ClientFamily) -> &'static str {
    use tlsfp_intel::ClientFamily as F;
    match family {
        F::Chromium => "chromium",
        F::Firefox => "firefox",
        F::SafariLike => "safari-like",
        F::OpenSsl => "openssl",
        F::Library => "library",
        F::Unknown => "unknown",
    }
}

#[derive(Deserialize)]
struct HostsQuery {
    limit: Option<i64>,
    /// `clients` (the default), `servers` or `all`.
    role: Option<String>,
}

/// How many hosts the list carries at most.
const MAX_HOSTS: i64 = 1000;

async fn hosts(
    State(state): State<Shared>,
    Query(query): Query<HostsQuery>,
) -> Result<Json<Vec<tlsfp_intel::HostSummary>>, ApiError> {
    let limit = query.limit.unwrap_or(200).clamp(1, MAX_HOSTS);
    let role = tlsfp_intel::HostRole::from_token(query.role.as_deref().unwrap_or("clients"));
    let list = tokio::task::spawn_blocking(move || state.store().hosts(limit, role)).await??;
    Ok(Json(list))
}

async fn host_profile(
    State(state): State<Shared>,
    axum::extract::Path(ip): axum::extract::Path<String>,
) -> Result<Json<tlsfp_intel::HostProfile>, ApiError> {
    // Only an address is a valid key; refusing anything else keeps free text
    // out of the query path altogether.
    if ip.parse::<std::net::IpAddr>().is_err() {
        return Err(ApiError::not_found());
    }
    let found = tokio::task::spawn_blocking(move || state.store().host_profile(&ip)).await??;
    found.map(Json).ok_or(ApiError::not_found())
}

/// The client fingerprints this sensor has seen and how much of it the feed can
/// name.
async fn observed(State(state): State<Shared>) -> Result<Json<tlsfp_intel::Observed>, ApiError> {
    let report = tokio::task::spawn_blocking(move || state.store().observed()).await??;
    Ok(Json(report))
}

async fn library(State(state): State<Shared>) -> impl IntoResponse {
    Json(state.library.view())
}

/// A downloadable HTML report for one library file, found by the id the
/// listing gave it. An id that is not in the listing is a 404, so a request
/// can never name a path.
async fn library_report(
    State(state): State<Shared>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let view = state.library.view();
    let (Some(path), Some(summary)) = (
        view.paths.get(&id).cloned(),
        view.files.iter().find(|f| f.id == id),
    ) else {
        return Err(ApiError::not_found());
    };
    let name = summary.name.clone();
    let db = state.db.clone();
    // Each report reads a whole capture file; build one at a time.
    let Ok(_permit) = state.report_gate.try_acquire() else {
        return Err(ApiError::busy(
            "a report is already being built; try again in a moment",
        ));
    };
    let html = tokio::task::spawn_blocking(move || -> anyhow::Result<String> {
        let case = crate::case_report::build(&path, name, &db, &std::env::temp_dir())?;
        let total = IntelStore::open(&db)?.stats()?.total;
        Ok(crate::case_report::render(&[case], total))
    })
    .await?
    .map_err(|error| {
        tracing::warn!(%error, "building a report failed");
        ApiError::not_found()
    })?;
    Ok((
        [
            (axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (
                axum::http::header::CONTENT_DISPOSITION,
                "attachment; filename=\"tlsfp-report.html\"",
            ),
            (axum::http::header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        ],
        html,
    ))
}

async fn health() -> impl IntoResponse {
    Json(serde_json::json!({ "status": "ok" }))
}

/// The Server-Sent Events stream. Subscribes to the broadcast channel and
/// forwards every line as an event, dropping the gap when a lagging client
/// falls behind rather than tearing its connection down.
async fn stream(
    State(state): State<Shared>,
) -> Result<Sse<impl tokio_stream::Stream<Item = Result<Event, Infallible>>>, ApiError> {
    let guard = StreamGuard::acquire(&state)?;
    let (backlog, receiver) = state.feed.join();
    // One event carrying the whole backlog as a JSON array, so the page fills
    // at once instead of rendering hundreds of single updates.
    let first = if backlog.is_empty() {
        None
    } else {
        let body = format!(
            "[{}]",
            backlog
                .iter()
                .map(AsRef::as_ref)
                .collect::<Vec<&str>>()
                .join(",")
        );
        Some(Ok(Event::default().event("backlog").data(body)))
    };
    let live = BroadcastStream::new(receiver).filter_map(|item| match item {
        Ok(line) => Some(Ok(Event::default().data(line.as_ref()))),
        Err(_lagged) => None,
    });
    // The guard rides along with the stream and releases its slot when the
    // client goes away and the stream is dropped.
    let events = tokio_stream::iter(first).chain(live).map(move |item| {
        let _held = &guard;
        item
    });
    Ok(Sse::new(events).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(KEEPALIVE_SECS))
            .text("keep-alive"),
    ))
}

/// How many event streams may be open at once. A person uses one or two tabs;
/// a runaway page or a hostile client opening thousands would otherwise cost a
/// subscriber each.
const MAX_STREAMS: usize = 64;

struct StreamGuard(Shared);

impl StreamGuard {
    fn acquire(state: &Shared) -> Result<Self, ApiError> {
        use std::sync::atomic::Ordering;
        if state.streams.fetch_add(1, Ordering::AcqRel) >= MAX_STREAMS {
            state.streams.fetch_sub(1, Ordering::AcqRel);
            return Err(ApiError::busy("too many open event streams"));
        }
        Ok(Self(Arc::clone(state)))
    }
}

impl Drop for StreamGuard {
    fn drop(&mut self) {
        self.0
            .streams
            .fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
    }
}

/// Clamps a requested page size into a sane range, defaulting an absent or
/// non-positive request to a readable page.
fn page_size(requested: Option<i64>) -> i64 {
    match requested {
        Some(value) if value > 0 => value.min(MAX_PAGE),
        _ => DEFAULT_PAGE,
    }
}

/// Renders alerts as CSV, quoting through the csv writer so a comma or newline
/// inside a detail string can never break the row structure.
fn alerts_to_csv(alerts: &[Alert]) -> Result<Vec<u8>> {
    let mut writer = csv::Writer::from_writer(Vec::new());
    writer.write_record([
        "ts_nanos", "rule", "severity", "ip", "fp_kind", "fp_value", "title", "detail", "score",
    ])?;
    for alert in alerts {
        writer.write_record([
            alert.ts_nanos.to_string(),
            alert.rule.as_str().to_string(),
            alert.severity.as_str().to_string(),
            alert.ip.clone().unwrap_or_default(),
            alert
                .fp_kind
                .map(|kind| kind.as_str().to_string())
                .unwrap_or_default(),
            alert.fp_value.clone().unwrap_or_default(),
            alert.title.clone(),
            alert.detail.clone(),
            alert.score.map(|s| format!("{s:.4}")).unwrap_or_default(),
        ])?;
    }
    writer.into_inner().context("finishing the CSV export")
}

/// A handle to whatever is feeding the live stream, so the server can stop it
/// on shutdown. A replay or tail loop watches the shared flag; a live capture
/// also needs its blocking read woken, which is what the stop handle does.
struct Capture {
    shutdown: Arc<AtomicBool>,
    live_stop: Option<StopHandle>,
    handle: Option<JoinHandle<()>>,
}

impl Capture {
    fn stop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        if let Some(stop) = &self.live_stop {
            stop.stop();
        }
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// Starts whatever produces the live stream for this run and returns a handle
/// to stop it. The replay and live producers each own a private write
/// connection to the same database, so detection persists while the API reads
/// through its own connection; SQLite's write-ahead log lets the two coexist.
fn spawn_source(
    config: &ServeConfig,
    feed: Feed,
    shutdown: Arc<AtomicBool>,
    state: Shared,
) -> Result<Capture> {
    // What counts as "ours" for the traffic page: what the operator declared,
    // plus (for a live capture, below) the networks the interface sits on.
    feed.traffic
        .with(|table| table.set_local_networks(config.local_networks.clone()));
    match &config.source {
        Source::Tail => {
            spawn_tail(state, feed, Arc::clone(&shutdown));
            Ok(Capture {
                shutdown,
                live_stop: None,
                handle: None,
            })
        }
        Source::Replay {
            path,
            looping,
            interval,
        } => {
            let _ = feed.capture.set(CaptureSetup {
                mode: "replay",
                interface: None,
                filter: None,
                promiscuous: None,
                buffer_mib: None,
                kernel: None,
            });
            let path = path.clone();
            let db = config.db.clone();
            let looping = *looping;
            let interval = *interval;
            let stop = Arc::clone(&shutdown);
            let detect = detect_config(config);
            let handle = std::thread::Builder::new()
                .name("tlsfp-replay".to_owned())
                .spawn(move || {
                    replay_loop(&path, &db, &feed, &stop, looping, interval, detect);
                })
                .context("starting the replay thread")?;
            Ok(Capture {
                shutdown,
                live_stop: None,
                handle: Some(handle),
            })
        }
        Source::Live {
            interface,
            filter,
            promiscuous,
            buffer_mib,
        } => {
            let live_config = LiveConfig {
                filter: filter.clone(),
                promiscuous: *promiscuous,
                buffer_mib: *buffer_mib,
            };
            let source = LiveSource::open(interface, &live_config)
                .with_context(|| format!("opening live capture on {interface}"))?;
            let live_stop = source.stop_handle();
            let _ = feed.capture.set(CaptureSetup {
                mode: "live",
                interface: Some(interface.clone()),
                filter: Some(filter.clone()),
                promiscuous: Some(*promiscuous),
                buffer_mib: Some(crate::live::effective_buffer_mib(&live_config)),
                kernel: Some(source.kernel_stats()),
            });
            let mut local = config.local_networks.clone();
            local.extend(source.local_networks());
            tracing::info!(
                networks = %local.iter().map(ToString::to_string).collect::<Vec<_>>().join(", "),
                "treating these networks as this sensor's own, besides the private ranges"
            );
            feed.traffic.with(|table| table.set_local_networks(local));
            if let Some(name) = crate::live::local_hostname() {
                let own = source.own_addresses();
                feed.traffic.with(|table| table.set_own(name, own));
            }
            let db = config.db.clone();
            let stop = Arc::clone(&shutdown);
            let interface = interface.clone();
            let detect = detect_config(config);
            tracing::info!(interface, filter = %live_config.filter, "serving live capture");
            let handle = std::thread::Builder::new()
                .name("tlsfp-live".to_owned())
                .spawn(move || live_loop(source, &db, &feed, &stop, detect))
                .context("starting the live capture thread")?;
            Ok(Capture {
                shutdown,
                live_stop: Some(live_stop),
                handle: Some(handle),
            })
        }
    }
}

/// The detection settings for a producer thread: the defaults plus the
/// operator's shared networks.
fn detect_config(config: &ServeConfig) -> DetectConfig {
    DetectConfig {
        shared_networks: config.shared_networks.clone(),
        custom: crate::extras::rules(),
        sink: crate::deliver::sink(),
        ..DetectConfig::default()
    }
}

/// Replays a capture file as a synthetic live feed, pausing between events so
/// the stream reads at a human pace and looping when asked.
fn replay_loop(
    path: &std::path::Path,
    db: &std::path::Path,
    feed: &Feed,
    shutdown: &AtomicBool,
    looping: bool,
    interval: Duration,
    detect: DetectConfig,
) {
    let mut store = match IntelStore::open(db) {
        Ok(store) => store,
        Err(error) => {
            tracing::error!(%error, "replay: cannot open the intelligence database");
            return;
        }
    };
    store.set_detect_config(detect);
    tracing::info!(path = %path.display(), looping, "serving replayed capture");
    // The first pass runs at full speed so the dashboard opens already
    // populated; later passes are paced to read like a live link.
    let mut warm = true;
    loop {
        let mut source = match PcapFileSource::open(path) {
            Ok(source) => source,
            Err(error) => {
                tracing::error!(%error, path = %path.display(), "replay: cannot open the capture");
                return;
            }
        };
        let mut pipeline = Pipeline::new(crate::engine::config());
        // Each pass starts with an empty conversation table; the byte totals
        // keep counting so rates never run backwards.
        feed.traffic
            .with(tlsfp_core::pipeline::traffic::TrafficTable::clear_flows);
        pipeline.track_traffic(feed.traffic.clone());
        pipeline.publish_counters(feed.counters.clone());
        let run = pipeline.run(&mut source, |event| {
            if shutdown.load(Ordering::Relaxed) {
                return;
            }
            broadcast_flow(&mut store, feed, event);
            if !warm && !interval.is_zero() {
                std::thread::sleep(interval);
            }
        });
        warm = false;
        if let Err(error) = run {
            tracing::error!(%error, "replay: reading the capture failed");
            return;
        }
        if shutdown.load(Ordering::Relaxed) || !looping {
            return;
        }
    }
}

/// Drives a live capture through the same pipeline the file path uses, on this
/// dedicated thread, detecting and broadcasting until the stop handle wakes the
/// blocking read.
fn live_loop(
    mut source: LiveSource,
    db: &std::path::Path,
    feed: &Feed,
    shutdown: &AtomicBool,
    detect: DetectConfig,
) {
    let mut store = match IntelStore::open(db) {
        Ok(store) => store,
        Err(error) => {
            tracing::error!(%error, "live: cannot open the intelligence database");
            return;
        }
    };
    store.set_detect_config(detect);
    let mut pipeline = Pipeline::new(crate::engine::config());
    pipeline.track_traffic(feed.traffic.clone());
    pipeline.publish_counters(feed.counters.clone());
    let run = pipeline.run(&mut source, |event| {
        if shutdown.load(Ordering::Relaxed) {
            return;
        }
        broadcast_flow(&mut store, feed, event);
    });
    if let Err(error) = run {
        tracing::warn!(%error, "live capture ended");
    }
}

/// Tails the database for alerts written by an external sensor and broadcasts
/// each new one. Used when nothing is captured in process: a `tlsfp live
/// --detect` writing to the same store shows up on the dashboard without the
/// server holding a capture socket of its own.
fn spawn_tail(state: Shared, feed: Feed, shutdown: Arc<AtomicBool>) {
    tokio::spawn(async move {
        let start = Arc::clone(&state);
        let mut last_id =
            tokio::task::spawn_blocking(move || start.store().latest_alert_id().unwrap_or(0))
                .await
                .unwrap_or(0);
        let mut ticker = tokio::time::interval(Duration::from_millis(TAIL_POLL_MILLIS));
        loop {
            ticker.tick().await;
            if shutdown.load(Ordering::Relaxed) {
                return;
            }
            let reader = Arc::clone(&state);
            let since = last_id;
            let fresh = tokio::task::spawn_blocking(move || {
                reader
                    .store()
                    .alerts_since(since, TAIL_PAGE)
                    .unwrap_or_default()
            })
            .await
            .unwrap_or_default();
            for (id, alert) in fresh {
                last_id = last_id.max(id);
                let message = LiveMessage::Alert { alert };
                if let Ok(line) = serde_json::to_string(&message) {
                    feed.publish(line);
                }
            }
        }
    });
}

/// Enriches one event, runs the detection rules over it, and broadcasts the
/// result as a single line. A serialisation failure is dropped rather than
/// allowed to end the capture, since one bad line is not worth a dark stream.
fn broadcast_flow(store: &mut IntelStore, feed: &Feed, event: FingerprintEvent) {
    // DNS is summarised, not streamed: it would drown the handshakes.
    if let StreamEvent::Dns(message) = &event.event {
        feed.dns
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .record(event.ts_nanos, event.src, event.dst, message);
        return;
    }
    let intel = store.match_event(&event).unwrap_or_default();
    let alerts = store.detect(&event).unwrap_or_default();
    let client = match &event.event {
        StreamEvent::ClientHello { ja4, .. } => Some(Box::new(read_client(&ja4.raw, &intel))),
        _ => None,
    };
    let message = LiveMessage::Flow {
        event,
        intel,
        alerts,
        client,
    };
    if let Ok(line) = serde_json::to_string(&message) {
        feed.publish(line);
    }
}

/// Resolves when the process is asked to stop, the trigger for axum's graceful
/// shutdown.
async fn shutdown_signal() {
    if let Err(error) = tokio::signal::ctrl_c().await {
        tracing::error!(%error, "failed to listen for ctrl-c; serving until killed");
        std::future::pending::<()>().await;
    }
    tracing::info!("shutting down the dashboard");
}

/// The error type every handler returns. Failures become a 500 with a JSON
/// body; a bad request is the one client-caused case that is reported as a 400.
#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn not_found() -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            message: "not found".to_owned(),
        }
    }

    fn busy(message: &str) -> Self {
        Self {
            status: StatusCode::SERVICE_UNAVAILABLE,
            message: message.to_owned(),
        }
    }

    fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.into(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        if self.status.is_server_error() {
            tracing::error!(error = %self.message, "request failed");
        }
        (
            self.status,
            Json(serde_json::json!({ "error": self.message })),
        )
            .into_response()
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(error: anyhow::Error) -> Self {
        // The detail (a path, a query) is for the log, not for the browser.
        tracing::error!(error = %format!("{error:#}"), "request failed");
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: "internal error; the details are in the server log".to_owned(),
        }
    }
}

impl From<tokio::task::JoinError> for ApiError {
    fn from(error: tokio::task::JoinError) -> Self {
        tracing::error!(%error, "a request task failed");
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: "internal error; the details are in the server log".to_owned(),
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_joining_client_gets_the_backlog_then_only_newer_lines() {
        let feed = super::Feed::new();
        for n in 0..(super::HISTORY_LINES + 3) {
            feed.publish(format!("{{\"n\":{n}}}"));
        }
        let (backlog, mut receiver) = feed.join();
        assert_eq!(backlog.len(), super::HISTORY_LINES, "history is bounded");
        assert_eq!(&*backlog[0], "{\"n\":3}", "the oldest lines were dropped");
        assert!(receiver.try_recv().is_err(), "nothing is replayed live");
        feed.publish("{\"n\":\"next\"}".to_string());
        assert_eq!(&*receiver.try_recv().unwrap(), "{\"n\":\"next\"}");
    }

    use super::*;

    fn config(source: Source, location: Option<&str>) -> ServeConfig {
        ServeConfig {
            bind: "127.0.0.1:0".to_owned(),
            db: PathBuf::from("/var/lib/tlsfp/intel.db"),
            web: PathBuf::from("frontend/dist"),
            source,
            location: location.map(str::to_owned),
            shared_networks: Vec::new(),
            local_networks: Vec::new(),
            allowed_hosts: Vec::new(),
            retention: tlsfp_intel::Retention::default(),
            library: Vec::new(),
        }
    }

    #[test]
    fn replay_reports_the_file_name_never_the_path() {
        let source = Source::Replay {
            path: PathBuf::from("/secret/captures/demo.pcap"),
            looping: true,
            interval: Duration::ZERO,
        };
        let meta = Meta::new(&config(source, None), 7);
        assert_eq!(meta.source.kind, "replay");
        assert_eq!(meta.source.detail.as_deref(), Some("demo.pcap"));
        assert!(meta.source.looping);
        assert_eq!(meta.started_unix_ms, 7);
        let json = serde_json::to_string(&meta).unwrap();
        assert!(!json.contains("secret"), "{json}");
        assert!(!json.contains("intel.db"), "{json}");
    }

    // --- the HTTP surface, through the real router ---

    fn build(bind: &str, allowed: &[&str]) -> (axum::Router, super::Shared) {
        let mut cfg = config(Source::Tail, None);
        cfg.bind = bind.to_owned();
        cfg.allowed_hosts = allowed.iter().map(|h| (*h).to_owned()).collect();
        let web = std::env::temp_dir().join(format!("tlsfp-web-{}-{bind}", std::process::id()));
        std::fs::create_dir_all(web.join("assets")).unwrap();
        std::fs::write(web.join("index.html"), "<!doctype html><title>app</title>").unwrap();
        std::fs::write(web.join("assets/app-ABCDEF12.js"), "export{}").unwrap();
        let state = super::new_state(
            tlsfp_intel::IntelStore::open_in_memory().unwrap(),
            super::Feed::new(),
            &cfg,
            0,
        );
        let hosts = super::allowed_hosts(&cfg);
        (
            super::router(&web, std::sync::Arc::clone(&state), &hosts),
            state,
        )
    }

    async fn get(
        app: &axum::Router,
        path: &str,
        host: &str,
    ) -> (axum::http::StatusCode, axum::http::HeaderMap, String) {
        use tower::ServiceExt;
        let request = axum::http::Request::builder()
            .uri(path)
            .header("host", host)
            .body(axum::body::Body::empty())
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        let (parts, body) = response.into_parts();
        let bytes = axum::body::to_bytes(body, 1 << 20).await.unwrap();
        (
            parts.status,
            parts.headers,
            String::from_utf8_lossy(&bytes).into_owned(),
        )
    }

    fn limits() -> super::LimitsView {
        super::LimitsView {
            max_flows: 65_536,
            idle_timeout_secs: 60,
            stream_limit_kib: 256,
        }
    }

    #[test]
    fn a_clean_capture_is_ok_and_says_nothing() {
        let (status, notes) = super::assess(&tlsfp_core::Counters::default(), None, &limits());
        assert_eq!(status, "ok");
        assert_eq!(notes, Vec::new());
    }

    #[test]
    fn kernel_drops_make_the_capture_lossy_and_name_the_remedy() {
        let kernel = super::KernelView {
            received: 900,
            dropped: 100,
            interface_dropped: 0,
        };
        let (status, notes) =
            super::assess(&tlsfp_core::Counters::default(), Some(&kernel), &limits());
        assert_eq!(status, "lossy");
        assert!(notes[0].text.contains("10.00%"), "{}", notes[0].text);
        assert!(notes[0].text.contains("--buffer-mib"));
    }

    #[test]
    fn a_full_flow_table_is_lossy_and_clipped_streams_are_only_degraded() {
        let full = tlsfp_core::Counters {
            flows_evicted_pressure: 3,
            ..tlsfp_core::Counters::default()
        };
        assert_eq!(super::assess(&full, None, &limits()).0, "lossy");
        let clipped = tlsfp_core::Counters {
            streams_capped: 2,
            ..tlsfp_core::Counters::default()
        };
        let (status, notes) = super::assess(&clipped, None, &limits());
        assert_eq!(status, "degraded");
        assert!(notes[0].text.contains("--stream-limit-kib"));
    }

    #[test]
    fn a_high_miss_rate_needs_enough_streams_to_mean_anything() {
        let few = tlsfp_core::Counters {
            tls_handshakes_fingerprinted: 1,
            unfinished_tls_streams: 3,
            ..tlsfp_core::Counters::default()
        };
        assert_eq!(super::assess(&few, None, &limits()).0, "ok");
        let many = tlsfp_core::Counters {
            tls_handshakes_fingerprinted: 80,
            unfinished_tls_streams: 20,
            ..tlsfp_core::Counters::default()
        };
        let (status, notes) = super::assess(&many, None, &limits());
        assert_eq!(status, "degraded");
        assert!(notes[0].text.contains("20.0%"));
    }

    #[tokio::test]
    async fn the_capture_endpoint_reports_limits_and_mode() {
        let (app, _s) = build("127.0.0.1:8090", &[]);
        let (status, _, body) = get(&app, "/api/capture", "localhost").await;
        assert_eq!(status, axum::http::StatusCode::OK);
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(json["status"], "ok");
        assert_eq!(json["limits"]["max_flows"], 65_536);
        assert!(json["counters"]["frames"].is_u64());
        let (_, _, metrics) = get(&app, "/metrics", "localhost").await;
        assert!(metrics.contains("tlsfp_frames_total"));
    }

    #[tokio::test]
    async fn a_loopback_dashboard_refuses_a_foreign_host_header() {
        let (app, _state) = build("127.0.0.1:8080", &[]);
        for ok in [
            "localhost:8080",
            "127.0.0.1:8080",
            "[::1]:8080",
            "LOCALHOST",
        ] {
            let (status, _, _) = get(&app, "/api/health", ok).await;
            assert_eq!(status, axum::http::StatusCode::OK, "{ok}");
        }
        // A DNS-rebinding page arrives under its own name.
        let (status, _, body) = get(&app, "/api/stats", "evil.example:8080").await;
        assert_eq!(status, axum::http::StatusCode::MISDIRECTED_REQUEST);
        assert!(body.contains("--allowed-host"));
    }

    #[tokio::test]
    async fn an_allowed_host_is_accepted_and_a_network_bind_skips_the_check() {
        let (app, _s) = build("127.0.0.1:8081", &["dash.lan"]);
        assert_eq!(
            get(&app, "/api/health", "dash.lan:8081").await.0,
            axum::http::StatusCode::OK
        );
        let (open, _s) = build("0.0.0.0:8082", &[]);
        assert_eq!(
            get(&open, "/api/health", "anything.example").await.0,
            axum::http::StatusCode::OK
        );
    }

    #[tokio::test]
    async fn pages_fall_back_to_the_app_and_missing_files_are_404() {
        let (app, _s) = build("127.0.0.1:8083", &[]);
        let (status, headers, body) = get(&app, "/hosts", "localhost").await;
        assert_eq!(status, axum::http::StatusCode::OK);
        assert!(body.contains("<title>app</title>"));
        assert_eq!(headers["cache-control"], "no-cache");

        let (status, _, body) = get(&app, "/assets/app-OLDOLD99.js", "localhost").await;
        assert_eq!(status, axum::http::StatusCode::NOT_FOUND);
        assert!(!body.contains("<title>"), "never HTML in place of a script");

        let (status, headers, _) = get(&app, "/assets/app-ABCDEF12.js", "localhost").await;
        assert_eq!(status, axum::http::StatusCode::OK);
        assert_eq!(
            headers["cache-control"],
            "public, max-age=31536000, immutable"
        );
        let (_, headers, _) = get(&app, "/api/health", "localhost").await;
        assert_eq!(headers["cache-control"], "no-store");
    }

    #[tokio::test]
    async fn every_response_carries_the_security_headers() {
        let (app, _s) = build("127.0.0.1:8084", &[]);
        let (_, headers, _) = get(&app, "/", "localhost").await;
        assert!(
            headers["content-security-policy"]
                .to_str()
                .unwrap()
                .contains("script-src 'self'")
        );
        assert_eq!(headers["x-frame-options"], "DENY");
        assert_eq!(headers["x-content-type-options"], "nosniff");
        assert_eq!(headers["referrer-policy"], "no-referrer");
    }

    #[tokio::test]
    async fn an_unknown_report_or_host_is_a_plain_404_and_a_bad_query_a_400_not_a_leak() {
        let (app, _s) = build("127.0.0.1:8085", &[]);
        assert_eq!(
            get(&app, "/api/library/deadbeef/report", "localhost")
                .await
                .0,
            axum::http::StatusCode::NOT_FOUND
        );
        assert_eq!(
            get(&app, "/api/hosts/not-an-ip", "localhost").await.0,
            axum::http::StatusCode::NOT_FOUND
        );
        let (status, _, body) = get(&app, "/api/observed", "localhost").await;
        assert_eq!(status, axum::http::StatusCode::OK);
        assert!(body.contains("coverage"));
    }

    #[tokio::test]
    async fn event_streams_are_capped() {
        let (_app, state) = build("127.0.0.1:8086", &[]);
        let mut held = Vec::new();
        for _ in 0..super::MAX_STREAMS {
            held.push(super::StreamGuard::acquire(&state).unwrap());
        }
        assert!(
            super::StreamGuard::acquire(&state).is_err(),
            "one past the cap is refused"
        );
        held.pop();
        assert!(
            super::StreamGuard::acquire(&state).is_ok(),
            "a closed stream frees its slot"
        );
    }

    #[test]
    fn caching_never_masks_a_new_build() {
        assert_eq!(cache_policy("/api/traffic", StatusCode::OK), "no-store");
        assert_eq!(cache_policy("/metrics", StatusCode::OK), "no-store");
        assert_eq!(cache_policy("/", StatusCode::OK), "no-cache");
        assert_eq!(cache_policy("/scope", StatusCode::OK), "no-cache");
        assert_eq!(cache_policy("/theme-init.js", StatusCode::OK), "no-cache");
        assert_eq!(
            cache_policy("/assets/objects/xray-butterfly.png", StatusCode::OK),
            "no-cache",
            "unhashed artwork is revalidated"
        );
        assert_eq!(
            cache_policy("/assets/traffic-CWOdAE8G.js", StatusCode::OK),
            "public, max-age=31536000, immutable"
        );
        assert_eq!(
            cache_policy("/assets/traffic-CWOdAE8G.js", StatusCode::NOT_FOUND),
            "no-cache",
            "a 404 is never cached for a year"
        );
    }

    #[test]
    fn only_page_navigations_fall_back_to_the_app() {
        assert!(is_navigation("/"));
        assert!(is_navigation("/hosts"));
        assert!(!is_navigation("/assets/traffic-CWOdAE8G.js"));
        assert!(!is_navigation("/api/nothing"));
        assert!(!is_navigation("/favicon.ico"));
    }

    #[test]
    fn a_client_hello_is_read_as_a_family_with_its_evidence() {
        let raw = "t13d1516h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0015,0017,001b,0023,002b,002d,0033,4469,ff01_0403,0804,0401,0503,0805,0501,0806,0601";
        let read = read_client(raw, &[]);
        assert_eq!(read.family, "chromium");
        assert!(read.known_as.is_none());
        assert!(read.reasons.iter().any(|reason| reason.contains("ALPS")));
        assert!(
            read.caveat.is_some(),
            "an impersonable family carries its caveat"
        );
    }

    #[test]
    fn live_reports_the_interface_and_tail_reports_nothing() {
        let live = Source::Live {
            interface: "eth0".to_owned(),
            filter: String::new(),
            promiscuous: true,
            buffer_mib: None,
        };
        let meta = Meta::new(&config(live, None), 0);
        assert_eq!(meta.source.kind, "live");
        assert_eq!(meta.source.detail.as_deref(), Some("eth0"));

        let tail = Meta::new(&config(Source::Tail, None), 0);
        assert_eq!(tail.source.kind, "tail");
        assert_eq!(tail.source.detail, None);
    }

    #[test]
    fn location_is_operator_supplied_trimmed_and_bounded() {
        let none = Meta::new(&config(Source::Tail, None), 0);
        assert_eq!(none.location, None);

        let blank = Meta::new(&config(Source::Tail, Some("   ")), 0);
        assert_eq!(blank.location, None);

        let named = Meta::new(&config(Source::Tail, Some("  DC-2 rack 14 ")), 0);
        assert_eq!(named.location.as_deref(), Some("DC-2 rack 14"));

        let long = "x".repeat(500);
        let capped = Meta::new(&config(Source::Tail, Some(&long)), 0);
        assert_eq!(capped.location.unwrap().chars().count(), MAX_LOCATION_CHARS);
    }
}
