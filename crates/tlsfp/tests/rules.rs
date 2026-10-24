// © Pranav Verma | 2026
// rules.rs

//! The operator's rules file, driven through the real binary.

use std::path::PathBuf;
use std::process::Command;

fn capture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/pcap/tls-handshake.pcapng")
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("tlsfp-rules-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir.join(name)
}

fn tlsfp(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_tlsfp"))
        .args(args)
        .output()
        .expect("running tlsfp")
}

#[test]
fn the_shipped_example_file_is_valid() {
    let example =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/rules.example.toml");
    let out = tlsfp(&["rules", "check", example.to_str().unwrap()]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("5 rule(s) valid"));
}

#[test]
fn a_mistake_in_the_file_fails_the_check_and_names_the_rule() {
    let file = scratch("bad.toml");
    std::fs::write(
        &file,
        "[[rule]]\nname = \"typo\"\n[rule.when]\nsni_glob = [\"a\"]\nsnigloob = [\"b\"]\n",
    )
    .unwrap();
    let out = tlsfp(&["rules", "check", file.to_str().unwrap()]);
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("snigloob"),
        "names the bad key"
    );
}

#[test]
fn a_rule_fires_once_per_address_on_a_real_capture_and_is_stored() {
    let rules = scratch("fires.toml");
    std::fs::write(
        &rules,
        "[[rule]]\nname = \"google-from-chromium\"\nseverity = \"high\"\nonce_per = \"address\"\n[rule.when]\nevent = [\"client_hello\"]\nfamily = [\"chromium\"]\nsni_glob = [\"*.google.com\"]\n",
    )
    .unwrap();
    let db = scratch("fires.db");
    let _ = std::fs::remove_file(&db);
    let seeded = tlsfp(&["intel", "seed", "--db", db.to_str().unwrap()]);
    assert!(seeded.status.success());
    let out = tlsfp(&[
        "pcap",
        capture().to_str().unwrap(),
        "--detect",
        "--json",
        "--db",
        db.to_str().unwrap(),
        "--rules",
        rules.to_str().unwrap(),
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let fired = String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|l| l.contains("\"rule\":\"custom\"") && l.contains("google-from-chromium"))
        .count();
    assert_eq!(fired, 1, "once per address, not once per handshake");

    let alerts = tlsfp(&["intel", "alerts", "--json", "--db", db.to_str().unwrap()]);
    assert!(
        String::from_utf8_lossy(&alerts.stdout).contains("google-from-chromium"),
        "persisted"
    );
}

#[test]
fn without_a_rules_file_nothing_custom_fires() {
    let db = scratch("plain.db");
    let _ = std::fs::remove_file(&db);
    tlsfp(&["intel", "seed", "--db", db.to_str().unwrap()]);
    let out = tlsfp(&[
        "pcap",
        capture().to_str().unwrap(),
        "--detect",
        "--json",
        "--db",
        db.to_str().unwrap(),
    ]);
    assert!(!String::from_utf8_lossy(&out.stdout).contains("\"rule\":\"custom\""));
}
