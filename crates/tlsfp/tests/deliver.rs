// © Pranav Verma | 2026
// deliver.rs

//! Alert delivery, driven through the real binary on a real capture.

use std::net::UdpSocket;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

fn capture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/pcap/tls-handshake.pcapng")
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("tlsfp-deliver-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir.join(name)
}

#[test]
fn alerts_reach_the_file_and_syslog_before_the_command_exits() {
    let db = scratch("d.db");
    let _ = std::fs::remove_file(&db);
    let file = scratch("alerts.jsonl");
    let _ = std::fs::remove_file(&file);
    let seeded = Command::new(env!("CARGO_BIN_EXE_tlsfp"))
        .args(["intel", "seed", "--db", db.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(seeded.status.success());

    let listener = UdpSocket::bind("127.0.0.1:0").unwrap();
    listener
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let target = format!("udp://{}", listener.local_addr().unwrap());

    let out = Command::new(env!("CARGO_BIN_EXE_tlsfp"))
        .args([
            "pcap",
            capture().to_str().unwrap(),
            "--detect",
            "--json",
            "--db",
            db.to_str().unwrap(),
            "--alert-file",
            file.to_str().unwrap(),
            "--alert-syslog",
            &target,
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let stored = Command::new(env!("CARGO_BIN_EXE_tlsfp"))
        .args([
            "intel",
            "alerts",
            "--json",
            "--limit",
            "500",
            "--db",
            db.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    let stored: Vec<serde_json::Value> = serde_json::from_slice(&stored.stdout).unwrap();
    assert!(!stored.is_empty(), "the capture raises alerts");

    let text = std::fs::read_to_string(&file).unwrap();
    let lines: Vec<serde_json::Value> = text
        .lines()
        .map(|l| serde_json::from_str(l).expect("each line is JSON"))
        .collect();
    assert_eq!(
        lines.len(),
        stored.len(),
        "every stored alert was delivered"
    );
    assert!(
        lines
            .iter()
            .all(|l| l["sensor"] == "tlsfp" && l["time"].is_string())
    );

    let mut buf = [0u8; 4096];
    let n = listener.recv(&mut buf).expect("a syslog datagram arrived");
    let message = String::from_utf8_lossy(&buf[..n]);
    assert!(message.starts_with("<1"), "{message}");
    assert!(message.contains(" tlsfp - "), "{message}");
}

#[test]
fn the_severity_floor_filters_what_is_delivered() {
    let db = scratch("f.db");
    let _ = std::fs::remove_file(&db);
    let file = scratch("high.jsonl");
    let _ = std::fs::remove_file(&file);
    Command::new(env!("CARGO_BIN_EXE_tlsfp"))
        .args(["intel", "seed", "--db", db.to_str().unwrap()])
        .output()
        .unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_tlsfp"))
        .args([
            "pcap",
            capture().to_str().unwrap(),
            "--detect",
            "--db",
            db.to_str().unwrap(),
            "--alert-file",
            file.to_str().unwrap(),
            "--alert-min-severity",
            "critical",
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    let text = std::fs::read_to_string(&file).unwrap_or_default();
    assert!(
        text.lines()
            .all(|l| l.contains("\"severity\":\"critical\"")),
        "only critical alerts: {text}"
    );
}

#[test]
fn a_bad_destination_stops_the_program_with_the_reason() {
    let out = Command::new(env!("CARGO_BIN_EXE_tlsfp"))
        .args(["--alert-webhook", "ftp://x", "rules", "check", "x"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("http"));
}
