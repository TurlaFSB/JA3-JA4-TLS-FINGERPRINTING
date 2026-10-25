// © Pranav Verma | 2026
// ssh.rs

//! SSH client and server fingerprints (HASSH and HASSHServer).
//!
//! The first thing each SSH side sends, in the clear, is a version banner and
//! then a key exchange init message (`SSH_MSG_KEXINIT`) listing the algorithms
//! it supports in preference order. Like a TLS ClientHello, that list is
//! characteristic of the SSH library and its configuration. HASSH, by
//! Salesforce (BSD-3-Clause), hashes it:
//!
//! - client: `md5(kex ; encryption c2s ; mac c2s ; compression c2s)`
//! - server: `md5(kex ; encryption s2c ; mac s2c ; compression s2c)`
//!
//! each field being the algorithm name list exactly as sent (comma separated).
//! Everything after the key exchange is encrypted, so this reads only the
//! first packet of each direction.

use md5::{Digest, Md5};
use serde::Serialize;

/// Longest banner line accepted (RFC 4253 allows 255 bytes including CRLF).
const MAX_BANNER: usize = 255;

/// Largest first packet accepted. RFC 4253 requires implementations to handle
/// 35000 bytes; a KEXINIT is a few hundred.
const MAX_PACKET: usize = 35_000;

/// Name lists in a KEXINIT.
const NAME_LISTS: usize = 10;

/// Which side of the connection an SSH hello came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SshRole {
    Client,
    Server,
    /// The capture did not show who opened the connection, and the ports gave
    /// no hint. Both hashes are then reported.
    Unknown,
}

/// The algorithm lists a side offered, in order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SshAlgorithms {
    pub kex: Vec<String>,
    pub host_key: Vec<String>,
    pub encryption_c2s: Vec<String>,
    pub encryption_s2c: Vec<String>,
    pub mac_c2s: Vec<String>,
    pub mac_s2c: Vec<String>,
    pub compression_c2s: Vec<String>,
    pub compression_s2c: Vec<String>,
}

/// One side's SSH hello.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SshHello {
    pub role: SshRole,
    /// The version banner, for example `SSH-2.0-OpenSSH_9.6`.
    pub banner: String,
    /// HASSH, when this is a client (or the role is unknown).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hassh: Option<String>,
    /// The string `hassh` was computed from.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hassh_raw: Option<String>,
    /// HASSHServer, when this is a server (or the role is unknown).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hassh_server: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hassh_server_raw: Option<String>,
    pub algorithms: SshAlgorithms,
}

fn md5_hex(text: &str) -> String {
    hex::encode(Md5::digest(text.as_bytes()))
}

impl SshHello {
    /// Fixes the role and computes the hash that role calls for. `initiator`
    /// says whether the side that sent this hello opened the connection, when
    /// the capture saw the opening SYN; otherwise the ports decide, and failing
    /// that the role stays unknown and both hashes are given.
    pub fn resolve(&mut self, initiator: Option<bool>, src_port: u16, dst_port: u16) {
        let role = match initiator {
            Some(true) => SshRole::Client,
            Some(false) => SshRole::Server,
            None if dst_port == 22 => SshRole::Client,
            None if src_port == 22 => SshRole::Server,
            None => SshRole::Unknown,
        };
        self.role = role;
        let a = &self.algorithms;
        let client = format!(
            "{};{};{};{}",
            a.kex.join(","),
            a.encryption_c2s.join(","),
            a.mac_c2s.join(","),
            a.compression_c2s.join(",")
        );
        let server = format!(
            "{};{};{};{}",
            a.kex.join(","),
            a.encryption_s2c.join(","),
            a.mac_s2c.join(","),
            a.compression_s2c.join(",")
        );
        let (want_client, want_server) = match role {
            SshRole::Client => (true, false),
            SshRole::Server => (false, true),
            SshRole::Unknown => (true, true),
        };
        self.hassh = want_client.then(|| md5_hex(&client));
        self.hassh_raw = want_client.then_some(client);
        self.hassh_server = want_server.then(|| md5_hex(&server));
        self.hassh_server_raw = want_server.then_some(server);
    }
}

/// Outcome of looking at the start of a stream.
#[derive(Debug, PartialEq, Eq)]
pub enum Ssh {
    /// More bytes are needed.
    Incomplete,
    /// Not SSH, or an SSH this does not read (version 1, or a malformed packet).
    Rejected,
    /// A banner and a complete KEXINIT.
    Hello(Box<SshHello>),
}

fn be32(bytes: &[u8], at: usize) -> Option<usize> {
    let raw: [u8; 4] = bytes.get(at..at + 4)?.try_into().ok()?;
    usize::try_from(u32::from_be_bytes(raw)).ok()
}

/// Reads the banner and first packet from the start of one direction's bytes.
/// The role is left [`SshRole::Unknown`] with no hashes; call
/// [`SshHello::resolve`].
#[must_use]
pub fn parse(stream: &[u8]) -> Ssh {
    if !stream.starts_with(b"SSH-") && stream.len() >= 4 {
        return Ssh::Rejected;
    }
    let Some(line_end) = stream.iter().position(|&b| b == b'\n') else {
        return if stream.len() > MAX_BANNER {
            Ssh::Rejected
        } else {
            Ssh::Incomplete
        };
    };
    if line_end + 1 > MAX_BANNER {
        return Ssh::Rejected;
    }
    let banner = String::from_utf8_lossy(&stream[..line_end])
        .trim_end_matches('\r')
        .chars()
        .filter(|c| !c.is_control())
        .collect::<String>();
    // Only the 2.0 protocol (and the 1.99 compatibility banner) has a KEXINIT.
    if !(banner.starts_with("SSH-2.0-") || banner.starts_with("SSH-1.99-")) {
        return Ssh::Rejected;
    }

    let packet = &stream[line_end + 1..];
    let Some(length) = be32(packet, 0) else {
        return Ssh::Incomplete;
    };
    if !(6..=MAX_PACKET).contains(&length) {
        return Ssh::Rejected;
    }
    if packet.len() < 4 + length {
        return Ssh::Incomplete;
    }
    let body = &packet[4..4 + length];
    let padding = usize::from(body[0]);
    // body: padding_length, payload (msg type 20, cookie 16, lists), padding
    let Some(payload_len) = length.checked_sub(1 + padding) else {
        return Ssh::Rejected;
    };
    let payload = &body[1..=payload_len];
    if payload.first() != Some(&20) || payload.len() < 17 {
        return Ssh::Rejected;
    }
    let mut at = 17;
    let mut lists: Vec<Vec<String>> = Vec::with_capacity(NAME_LISTS);
    for _ in 0..NAME_LISTS {
        let Some(len) = be32(payload, at) else {
            return Ssh::Rejected;
        };
        at += 4;
        let Some(raw) = payload.get(at..at + len) else {
            return Ssh::Rejected;
        };
        at += len;
        let text = String::from_utf8_lossy(raw);
        lists.push(
            text.split(',')
                .filter(|s| !s.is_empty())
                .map(|s| s.chars().filter(|c| !c.is_control()).collect())
                .collect(),
        );
    }
    let mut it = lists.into_iter();
    let mut next = || it.next().unwrap_or_default();
    let algorithms = SshAlgorithms {
        kex: next(),
        host_key: next(),
        encryption_c2s: next(),
        encryption_s2c: next(),
        mac_c2s: next(),
        mac_s2c: next(),
        compression_c2s: next(),
        compression_s2c: next(),
    };
    Ssh::Hello(Box::new(SshHello {
        role: SshRole::Unknown,
        banner,
        hassh: None,
        hassh_raw: None,
        hassh_server: None,
        hassh_server_raw: None,
        algorithms,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list(items: &[&str]) -> Vec<u8> {
        let joined = items.join(",");
        let mut out = u32::try_from(joined.len()).unwrap().to_be_bytes().to_vec();
        out.extend(joined.as_bytes());
        out
    }

    fn stream(banner: &str, lists: [&[&str]; 10]) -> Vec<u8> {
        let mut payload = vec![20u8];
        payload.extend([7u8; 16]);
        for l in lists {
            payload.extend(list(l));
        }
        payload.push(0);
        payload.extend([0u8; 4]);
        let padding = 8 - (payload.len() + 1) % 8;
        let mut body = vec![u8::try_from(padding).unwrap()];
        body.extend(&payload);
        body.extend(vec![0u8; padding]);
        let mut out = format!("{banner}\r\n").into_bytes();
        out.extend(u32::try_from(body.len()).unwrap().to_be_bytes());
        out.extend(body);
        out
    }

    fn sample() -> Vec<u8> {
        stream(
            "SSH-2.0-OpenSSH_9.6",
            [
                &["curve25519-sha256", "ecdh-sha2-nistp256"],
                &["ssh-ed25519"],
                &["chacha20-poly1305@openssh.com", "aes128-ctr"],
                &["aes256-ctr"],
                &["umac-64-etm@openssh.com"],
                &["hmac-sha2-256"],
                &["none", "zlib@openssh.com"],
                &["none"],
                &[],
                &[],
            ],
        )
    }

    #[test]
    fn a_client_hello_is_read_and_hashed() {
        let Ssh::Hello(mut hello) = parse(&sample()) else {
            panic!("expected a hello");
        };
        assert_eq!(hello.banner, "SSH-2.0-OpenSSH_9.6");
        hello.resolve(Some(true), 50000, 22);
        assert_eq!(hello.role, SshRole::Client);
        let raw = "curve25519-sha256,ecdh-sha2-nistp256;chacha20-poly1305@openssh.com,aes128-ctr;umac-64-etm@openssh.com;none,zlib@openssh.com";
        assert_eq!(hello.hassh_raw.as_deref(), Some(raw));
        assert_eq!(hello.hassh.as_deref(), Some(md5_hex(raw).as_str()));
        assert_eq!(hello.hassh_server, None);
    }

    #[test]
    fn the_server_hash_uses_the_other_direction() {
        let Ssh::Hello(mut hello) = parse(&sample()) else {
            panic!("expected a hello");
        };
        hello.resolve(Some(false), 22, 50000);
        assert_eq!(hello.role, SshRole::Server);
        assert_eq!(
            hello.hassh_server_raw.as_deref(),
            Some("curve25519-sha256,ecdh-sha2-nistp256;aes256-ctr;hmac-sha2-256;none")
        );
        assert_eq!(hello.hassh, None);
    }

    #[test]
    fn ports_decide_when_the_open_was_not_seen_and_otherwise_both_are_given() {
        let Ssh::Hello(mut hello) = parse(&sample()) else {
            panic!("expected a hello");
        };
        hello.resolve(None, 50000, 22);
        assert_eq!(hello.role, SshRole::Client);
        hello.resolve(None, 50000, 2222);
        assert_eq!(hello.role, SshRole::Unknown);
        assert!(hello.hassh.is_some() && hello.hassh_server.is_some());
    }

    #[test]
    fn a_partial_stream_waits_and_a_non_ssh_stream_is_rejected() {
        let full = sample();
        assert_eq!(parse(&full[..10]), Ssh::Incomplete);
        assert_eq!(parse(&full[..full.len() - 3]), Ssh::Incomplete);
        assert_eq!(parse(b"GET / HTTP/1.1\r\n"), Ssh::Rejected);
        assert_eq!(parse(b"SSH-1.5-old\r\n\0\0\0\x10"), Ssh::Rejected);
    }

    #[test]
    fn truncation_and_garbage_are_not_panics() {
        let full = sample();
        for cut in 0..full.len() {
            let _ = parse(&full[..cut]);
        }
        let mut bad = b"SSH-2.0-x\r\n".to_vec();
        bad.extend([0xFF; 64]);
        assert_eq!(parse(&bad), Ssh::Rejected);
    }
}
