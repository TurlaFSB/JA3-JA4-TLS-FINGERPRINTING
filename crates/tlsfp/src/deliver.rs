// © Pranav Verma | 2026
// deliver.rs

//! Alert delivery: forwards every alert, once it is stored, to the places an
//! operator already watches. A JSON-lines file for a log shipper, syslog
//! (RFC 5424) over UDP or TCP for a collector, and an HTTP or HTTPS webhook
//! for a chat channel or a SIEM's HTTP intake.
//!
//! Alerts are handed to one worker thread through a bounded queue, so a slow
//! or dead destination never stalls packet processing. When the queue is full
//! the alert is dropped and counted, and the drop count is reported on
//! `/metrics` and in the log. The alert is still in the database either way.

use std::fmt::Write as _;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::net::{TcpStream, ToSocketAddrs, UdpSocket};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use tlsfp_intel::{Alert, AlertSeverity, AlertSink};

/// Alerts waiting for the worker. Past this, new alerts are dropped.
const QUEUE_DEPTH: usize = 1024;
/// Attempts per webhook delivery, with a doubling pause between them.
const WEBHOOK_ATTEMPTS: u32 = 3;
const WEBHOOK_TIMEOUT: Duration = Duration::from_secs(5);
const SOCKET_TIMEOUT: Duration = Duration::from_secs(5);
/// Syslog UDP messages above this risk fragmentation, so the detail is cut.
const SYSLOG_UDP_MAX: usize = 1_200;
/// RFC 5424 facility local0, the conventional home for an application.
const SYSLOG_FACILITY: u8 = 16;

/// How a webhook body is shaped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum WebhookFormat {
    /// The alert as JSON, for a SIEM or your own receiver.
    Generic,
    /// `{"text": "..."}` for a Slack incoming webhook.
    Slack,
    /// `{"content": "..."}` for a Discord webhook.
    Discord,
}

/// Where a syslog message goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyslogTarget {
    Udp(String),
    Tcp(String),
}

/// What the operator asked for. All parts are optional; with none set, nothing
/// is delivered and no worker is started.
#[derive(Debug, Clone, Default)]
pub struct DeliveryConfig {
    pub file: Option<PathBuf>,
    pub syslog: Option<SyslogTarget>,
    pub webhook: Option<String>,
    pub webhook_format: Option<WebhookFormat>,
    pub min_severity: Option<AlertSeverity>,
}

impl DeliveryConfig {
    fn is_empty(&self) -> bool {
        self.file.is_none() && self.syslog.is_none() && self.webhook.is_none()
    }
}

/// Parses `udp://host:port` or `tcp://host:port`.
pub fn parse_syslog(text: &str) -> Result<SyslogTarget> {
    let (scheme, rest) = text
        .split_once("://")
        .context("a syslog target looks like udp://host:514 or tcp://host:514")?;
    if rest.is_empty() || !rest.contains(':') {
        bail!("a syslog target needs a port, like udp://host:514");
    }
    match scheme {
        "udp" => Ok(SyslogTarget::Udp(rest.to_owned())),
        "tcp" => Ok(SyslogTarget::Tcp(rest.to_owned())),
        other => bail!("syslog scheme `{other}` is not supported; use udp or tcp"),
    }
}

/// Parses a severity name for `--alert-min-severity`.
pub fn parse_severity(text: &str) -> Result<AlertSeverity, String> {
    match text {
        "info" | "low" | "medium" | "high" | "critical" => Ok(AlertSeverity::from_token(text)),
        _ => Err("expected info, low, medium, high or critical".to_owned()),
    }
}

/// Counters for `/metrics`.
#[derive(Default)]
pub struct Stats {
    pub delivered: AtomicU64,
    pub failed: AtomicU64,
    pub dropped: AtomicU64,
}

static STATS: OnceLock<Arc<Stats>> = OnceLock::new();
static SINK: OnceLock<Option<AlertSink>> = OnceLock::new();
static QUEUE: OnceLock<flume::Sender<Message>> = OnceLock::new();

/// What travels to the worker: an alert, or a request to say when everything
/// before it has been handled.
enum Message {
    Alert(Box<Alert>),
    Flush(flume::Sender<()>),
}

/// Waits (up to ten seconds) for queued alerts to be delivered. A one-shot
/// command calls this before it exits, or its last alerts would die in the
/// queue.
pub fn flush() {
    let Some(queue) = QUEUE.get() else {
        return;
    };
    let (done_tx, done_rx) = flume::bounded(1);
    if queue
        .send_timeout(Message::Flush(done_tx), Duration::from_secs(2))
        .is_ok()
    {
        let _ = done_rx.recv_timeout(Duration::from_secs(10));
    }
}

/// Delivery counters, or `None` when no destination is configured.
pub fn stats() -> Option<Arc<Stats>> {
    STATS.get().cloned()
}

/// The callback to put in the detection config, or `None` when nothing is
/// configured.
pub fn sink() -> Option<AlertSink> {
    SINK.get().cloned().flatten()
}

/// Validates the destinations, starts the worker and records the sink. Called
/// once at start-up; a destination that cannot work stops the program.
pub fn init(config: &DeliveryConfig) -> Result<()> {
    if config.is_empty() {
        let _ = SINK.set(None);
        return Ok(());
    }
    if let Some(url) = &config.webhook {
        if !(url.starts_with("http://") || url.starts_with("https://")) {
            bail!("the webhook must be an http:// or https:// URL");
        }
    }
    let file = match &config.file {
        Some(path) => Some(
            OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .with_context(|| format!("opening the alert file {}", path.display()))?,
        ),
        None => None,
    };
    let stats = Arc::new(Stats::default());
    let (tx, rx) = flume::bounded::<Message>(QUEUE_DEPTH);
    let mut worker = Worker {
        file,
        syslog: config.syslog.clone(),
        syslog_udp: None,
        syslog_tcp: None,
        webhook: config.webhook.clone(),
        format: config.webhook_format.unwrap_or(WebhookFormat::Generic),
        stats: Arc::clone(&stats),
    };
    thread::Builder::new()
        .name("alert-delivery".into())
        .spawn(move || {
            while let Ok(message) = rx.recv() {
                match message {
                    Message::Alert(alert) => worker.deliver(&alert),
                    Message::Flush(done) => {
                        let _ = done.send(());
                    }
                }
            }
        })
        .context("starting the alert delivery thread")?;

    let floor = config.min_severity.unwrap_or(AlertSeverity::Info);
    let counters = Arc::clone(&stats);
    let _ = QUEUE.set(tx.clone());
    let sink = AlertSink(Arc::new(move |alert: &Alert| {
        if alert.severity < floor {
            return;
        }
        if tx
            .try_send(Message::Alert(Box::new(alert.clone())))
            .is_err()
        {
            let dropped = counters.dropped.fetch_add(1, Ordering::Relaxed) + 1;
            if dropped == 1 || dropped.is_power_of_two() {
                tracing::warn!(
                    dropped,
                    "alert delivery is behind; alerts dropped from the queue"
                );
            }
        }
    }));
    let _ = STATS.set(stats);
    let _ = SINK.set(Some(sink));
    tracing::info!(
        file = config.file.is_some(),
        syslog = config.syslog.is_some(),
        webhook = config.webhook.is_some(),
        "alert delivery enabled"
    );
    Ok(())
}

struct Worker {
    file: Option<File>,
    syslog: Option<SyslogTarget>,
    syslog_udp: Option<UdpSocket>,
    syslog_tcp: Option<TcpStream>,
    webhook: Option<String>,
    format: WebhookFormat,
    stats: Arc<Stats>,
}

impl Worker {
    fn deliver(&mut self, alert: &Alert) {
        let mut ok = true;
        if self.file.is_some() {
            ok &= self.write_file(alert);
        }
        if self.syslog.is_some() {
            ok &= self.send_syslog(alert);
        }
        if self.webhook.is_some() {
            ok &= self.post_webhook(alert);
        }
        let counter = if ok {
            &self.stats.delivered
        } else {
            &self.stats.failed
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    fn write_file(&mut self, alert: &Alert) -> bool {
        let Some(file) = self.file.as_mut() else {
            return true;
        };
        let mut line = json_line(alert);
        line.push('\n');
        match file.write_all(line.as_bytes()).and_then(|()| file.flush()) {
            Ok(()) => true,
            Err(error) => {
                tracing::warn!(%error, "writing the alert file failed");
                false
            }
        }
    }

    fn send_syslog(&mut self, alert: &Alert) -> bool {
        let Some(target) = self.syslog.clone() else {
            return true;
        };
        let result = match target {
            SyslogTarget::Udp(addr) => self.syslog_udp_send(&addr, alert),
            SyslogTarget::Tcp(addr) => self.syslog_tcp_send(&addr, alert),
        };
        if let Err(error) = &result {
            tracing::warn!(%error, "sending the syslog message failed");
        }
        result.is_ok()
    }

    fn syslog_udp_send(&mut self, addr: &str, alert: &Alert) -> Result<()> {
        if self.syslog_udp.is_none() {
            let peer = addr
                .to_socket_addrs()?
                .next()
                .context("the syslog address did not resolve")?;
            let bind = if peer.is_ipv4() {
                "0.0.0.0:0"
            } else {
                "[::]:0"
            };
            let socket = UdpSocket::bind(bind)?;
            socket.connect(peer)?;
            self.syslog_udp = Some(socket);
        }
        let mut message = syslog_message(alert);
        truncate_utf8(&mut message, SYSLOG_UDP_MAX);
        self.syslog_udp
            .as_ref()
            .context("no syslog socket")?
            .send(message.as_bytes())?;
        Ok(())
    }

    fn syslog_tcp_send(&mut self, addr: &str, alert: &Alert) -> Result<()> {
        // RFC 6587 octet counting, so a newline inside a field cannot split a message.
        let message = syslog_message(alert);
        let framed = format!("{} {message}", message.len());
        for attempt in 0..2 {
            if self.syslog_tcp.is_none() {
                let peer = addr
                    .to_socket_addrs()?
                    .next()
                    .context("the syslog address did not resolve")?;
                let stream = TcpStream::connect_timeout(&peer, SOCKET_TIMEOUT)?;
                stream.set_write_timeout(Some(SOCKET_TIMEOUT))?;
                self.syslog_tcp = Some(stream);
            }
            let stream = self.syslog_tcp.as_mut().context("no syslog connection")?;
            match stream.write_all(framed.as_bytes()) {
                Ok(()) => return Ok(()),
                Err(error) => {
                    // A connection the collector closed: reconnect once.
                    self.syslog_tcp = None;
                    if attempt == 1 {
                        return Err(error.into());
                    }
                }
            }
        }
        Ok(())
    }

    fn post_webhook(&self, alert: &Alert) -> bool {
        let Some(url) = &self.webhook else {
            return true;
        };
        let body = webhook_body(alert, self.format).to_string();
        let agent = ureq::AgentBuilder::new()
            .timeout(WEBHOOK_TIMEOUT)
            .redirects(0)
            .build();
        let mut pause = Duration::from_secs(1);
        for attempt in 1..=WEBHOOK_ATTEMPTS {
            let response = agent
                .post(url)
                .set("Content-Type", "application/json")
                .set("User-Agent", concat!("tlsfp/", env!("CARGO_PKG_VERSION")))
                .send_string(&body);
            match response {
                Ok(_) => return true,
                // A 4xx will not improve by asking again.
                Err(ureq::Error::Status(code, _)) if (400..500).contains(&code) && code != 429 => {
                    tracing::warn!(code, "the webhook refused the alert");
                    return false;
                }
                Err(error) => {
                    // ureq's own message carries the whole URL, and a webhook
                    // URL is usually a secret. Say which host and what kind of
                    // failure, never the path.
                    let reason = match &error {
                        ureq::Error::Status(code, _) => format!("status {code}"),
                        ureq::Error::Transport(transport) => transport.kind().to_string(),
                    };
                    tracing::warn!(
                        attempt,
                        host = webhook_host(url),
                        reason,
                        "the webhook did not accept the alert"
                    );
                    if attempt < WEBHOOK_ATTEMPTS {
                        thread::sleep(pause);
                        pause *= 2;
                    }
                }
            }
        }
        false
    }
}

/// The host part of a URL, for logging in place of the URL itself.
fn webhook_host(url: &str) -> &str {
    url.split_once("://")
        .map_or(url, |(_, rest)| rest)
        .split(['/', '?', '#'])
        .next()
        .and_then(|authority| authority.rsplit('@').next())
        .unwrap_or("?")
}

/// The alert as one line of JSON with a readable time and a sensor tag.
pub fn json_line(alert: &Alert) -> String {
    let mut value = serde_json::to_value(alert).unwrap_or(Value::Null);
    if let Value::Object(map) = &mut value {
        map.insert("time".into(), Value::String(rfc3339(alert.ts_nanos)));
        map.insert("sensor".into(), Value::String("tlsfp".into()));
    }
    value.to_string()
}

/// The body to POST for a given destination style.
pub fn webhook_body(alert: &Alert, format: WebhookFormat) -> Value {
    match format {
        WebhookFormat::Generic => serde_json::from_str(&json_line(alert)).unwrap_or(Value::Null),
        WebhookFormat::Slack => json!({ "text": chat_text(alert) }),
        WebhookFormat::Discord => json!({ "content": chat_text(alert) }),
    }
}

fn chat_text(alert: &Alert) -> String {
    let mut text = format!(
        "[{}] {} ({})",
        alert.severity.as_str().to_uppercase(),
        alert.title,
        alert.rule.as_str()
    );
    if let Some(ip) = &alert.ip {
        let _ = write!(text, " from {ip}");
    }
    text.push('\n');
    text.push_str(&alert.detail);
    // Chat services cap a message; Discord's limit is 2000.
    truncate_utf8(&mut text, 1_900);
    text
}

/// One RFC 5424 message: priority, version, time, no hostname, the app name,
/// the rule as the message id, structured data, then the human message.
pub fn syslog_message(alert: &Alert) -> String {
    let severity = match alert.severity {
        AlertSeverity::Critical => 2,
        AlertSeverity::High => 3,
        AlertSeverity::Medium => 4,
        AlertSeverity::Low => 5,
        AlertSeverity::Info => 6,
    };
    let priority = SYSLOG_FACILITY * 8 + severity;
    let mut data = String::from("[tlsfp@32473");
    let mut param = |name: &str, value: &str| {
        let _ = write!(data, " {name}=\"{}\"", sd_escape(value));
    };
    param("rule", alert.rule.as_str());
    param("severity", alert.severity.as_str());
    if let Some(ip) = &alert.ip {
        param("src", ip);
    }
    if let Some(value) = &alert.fp_value {
        param("fp", value);
    }
    data.push(']');
    let text: String = format!("{}: {}", alert.title, alert.detail)
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    format!(
        "<{priority}>1 {} - tlsfp - {} {data} {text}",
        rfc3339(alert.ts_nanos),
        alert.rule.as_str()
    )
}

// RFC 5424 section 6.3.3: escape the quote, the backslash and the closing bracket.
fn sd_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '"' | '\\' | ']' => {
                out.push('\\');
                out.push(c);
            }
            c if c.is_control() => out.push(' '),
            c => out.push(c),
        }
    }
    out
}

fn truncate_utf8(text: &mut String, max: usize) {
    if text.len() <= max {
        return;
    }
    let mut end = max;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text.truncate(end);
}

/// Nanoseconds since the Unix epoch as an RFC 3339 UTC time.
pub fn rfc3339(nanos: i64) -> String {
    let secs = nanos.div_euclid(1_000_000_000);
    let millis = nanos.rem_euclid(1_000_000_000) / 1_000_000;
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    // Civil date from a day count (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{millis:03}Z",
        rem / 3_600,
        rem % 3_600 / 60,
        rem % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use tlsfp_intel::Rule;

    fn sample() -> Alert {
        Alert {
            ts_nanos: 1_700_000_000_123_000_000,
            rule: Rule::UaMismatch,
            severity: AlertSeverity::High,
            ip: Some("10.0.0.5".into()),
            fp_kind: None,
            fp_value: Some("t13d1516h2_x".into()),
            title: "Chrome claimed, curl seen".into(),
            detail: "User-Agent says \"Chrome\"]\nbut the handshake is curl".into(),
            score: None,
        }
    }

    #[test]
    fn times_are_rfc3339_utc() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(
            rfc3339(1_700_000_000_123_000_000),
            "2023-11-14T22:13:20.123Z"
        );
        assert_eq!(rfc3339(951_782_400_000_000_000), "2000-02-29T00:00:00.000Z");
    }

    #[test]
    fn json_line_is_one_line_with_time_and_sensor() {
        let line = json_line(&sample());
        assert!(!line.contains('\n'));
        let value: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(value["rule"], "ua_mismatch");
        assert_eq!(value["sensor"], "tlsfp");
        assert_eq!(value["time"], "2023-11-14T22:13:20.123Z");
    }

    #[test]
    fn syslog_follows_rfc5424_and_escapes() {
        let message = syslog_message(&sample());
        // local0 (16) * 8 + error-class severity 3 for high.
        assert!(message.starts_with("<131>1 2023-11-14T22:13:20.123Z - tlsfp - ua_mismatch ["));
        assert!(message.contains("src=\"10.0.0.5\""));
        assert!(!message.contains('\n'));
        assert_eq!(sd_escape("a\"b]c\\d"), "a\\\"b\\]c\\\\d");
    }

    #[test]
    fn chat_bodies_carry_the_severity_and_stay_short() {
        let slack = webhook_body(&sample(), WebhookFormat::Slack);
        assert!(
            slack["text"]
                .as_str()
                .unwrap()
                .starts_with("[HIGH] Chrome claimed")
        );
        let mut long = sample();
        long.detail = "x".repeat(5_000);
        let discord = webhook_body(&long, WebhookFormat::Discord);
        assert!(discord["content"].as_str().unwrap().len() <= 1_900);
    }

    #[test]
    fn only_the_host_of_a_webhook_is_ever_logged() {
        assert_eq!(
            webhook_host("https://hooks.slack.com/services/T000/B000/SECRETSECRET"),
            "hooks.slack.com"
        );
        assert_eq!(
            webhook_host("http://user:pw@siem.local:8088/x?token=1"),
            "siem.local:8088"
        );
        assert_eq!(webhook_host("https://example.com"), "example.com");
    }

    #[test]
    fn syslog_targets_are_parsed() {
        assert_eq!(
            parse_syslog("udp://10.0.0.1:514").unwrap(),
            SyslogTarget::Udp("10.0.0.1:514".into())
        );
        assert!(parse_syslog("10.0.0.1:514").is_err());
        assert!(parse_syslog("http://x:1").is_err());
        assert!(parse_syslog("udp://nohost").is_err());
    }

    #[test]
    fn a_webhook_receives_the_alert_as_json() {
        use std::io::Read;
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/hook", listener.local_addr().unwrap());
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = vec![0u8; 8192];
            let mut got = Vec::new();
            // Read until the JSON body is complete.
            loop {
                let n = stream.read(&mut buf).unwrap();
                got.extend_from_slice(&buf[..n]);
                let text = String::from_utf8_lossy(&got);
                if let Some((head, body)) = text.split_once("\r\n\r\n") {
                    let length = head
                        .lines()
                        .find_map(|l| {
                            l.to_lowercase()
                                .strip_prefix("content-length: ")
                                .map(str::to_owned)
                        })
                        .and_then(|v| v.trim().parse::<usize>().ok())
                        .unwrap_or(0);
                    if body.len() >= length {
                        break;
                    }
                }
                if n == 0 {
                    break;
                }
            }
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .unwrap();
            String::from_utf8_lossy(&got).into_owned()
        });
        let worker = Worker {
            file: None,
            syslog: None,
            syslog_udp: None,
            syslog_tcp: None,
            webhook: Some(url),
            format: WebhookFormat::Generic,
            stats: Arc::new(Stats::default()),
        };
        assert!(worker.post_webhook(&sample()));
        let request = handle.join().unwrap();
        assert!(request.starts_with("POST /hook"));
        assert!(request.contains("\"rule\":\"ua_mismatch\""));
    }
}
