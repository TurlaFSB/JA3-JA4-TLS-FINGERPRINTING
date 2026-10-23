// © Pranav Verma | 2026
// infer.rs

//! Guessing the client family from the shape of a ClientHello.
//!
//! The intelligence feed names a client only when its fingerprint matches an
//! entry exactly, which a browser version the feed has never seen will not.
//! The extensions a client offers say more than the hash does: Chromium sends
//! ALPS, Firefox's NSS sends `record_size_limit` and `delegated_credentials`,
//! OpenSSL sends `encrypt_then_mac`. This module reads those markers from the
//! JA4 raw string and returns a family, a confidence, and the reasons, so a
//! person can see why the guess was made.
//!
//! It is a heuristic with a stated blind spot. A tool that reproduces a
//! browser's ClientHello (curl-impersonate, uTLS) carries the same markers, so
//! every browser-family guess says so. The rules were checked against the
//! labelled lab captures in `eval/identify.py`, which reports where they are
//! wrong.

use serde::Serialize;

/// How far a guess can be trusted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    High,
    Medium,
    Low,
}

/// The client family a ClientHello looks like.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientFamily {
    Chromium,
    Firefox,
    SafariLike,
    OpenSsl,
    Library,
    Unknown,
}

impl ClientFamily {
    pub const fn display(self) -> &'static str {
        match self {
            ClientFamily::Chromium => "Chromium family (Chrome, Edge, Brave, Opera)",
            ClientFamily::Firefox => "Firefox family (Firefox, Tor Browser)",
            ClientFamily::SafariLike => "Safari-like (Apple TLS)",
            ClientFamily::OpenSsl => "OpenSSL-based client (curl, Python, many tools)",
            ClientFamily::Library => "Script or library TLS stack",
            ClientFamily::Unknown => "Unrecognised client",
        }
    }

    pub const fn is_browser_like(self) -> bool {
        matches!(
            self,
            ClientFamily::Chromium | ClientFamily::Firefox | ClientFamily::SafariLike
        )
    }
}

/// A guess with its evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ClientGuess {
    pub family: ClientFamily,
    pub confidence: Confidence,
    pub reasons: Vec<String>,
    /// Present when the family is one that an impersonation tool can copy.
    pub caveat: Option<&'static str>,
}

const IMPERSONATION_CAVEAT: &str = "Tools such as curl-impersonate and uTLS reproduce these markers, so this does not prove a real browser.";

/// Extension codes (lower-case hex, as JA4 writes them) this module reads.
mod ext {
    pub const COMPRESS_CERTIFICATE: &str = "001b";
    pub const RECORD_SIZE_LIMIT: &str = "001c";
    pub const DELEGATED_CREDENTIALS: &str = "0022";
    pub const ENCRYPT_THEN_MAC: &str = "0016";
    pub const ALPS_LEGACY: &str = "4469";
    pub const ALPS: &str = "44cd";
    pub const ECH: &str = "fe0d";
    pub const TRUST_ANCHORS: &str = "ca34";
    pub const PADDING: &str = "0015";
}

/// Splits a JA4 raw string into its sorted extension codes. A string that is
/// not four underscore-separated fields yields none.
fn extensions(raw: &str) -> Vec<&str> {
    let mut parts = raw.split('_');
    match (parts.next(), parts.next(), parts.next()) {
        (Some(_), Some(_), Some(exts)) => exts.split(',').filter(|e| !e.is_empty()).collect(),
        _ => Vec::new(),
    }
}

/// Infers the client family from a JA4 raw string (`a_ciphers_extensions_sigs`).
pub fn infer_client(ja4_raw: &str) -> ClientGuess {
    let exts = extensions(ja4_raw);
    let has = |code: &str| exts.contains(&code);
    let mut reasons = Vec::new();

    if exts.is_empty() {
        return ClientGuess {
            family: ClientFamily::Unknown,
            confidence: Confidence::Low,
            reasons: vec!["no extension list to read".into()],
            caveat: None,
        };
    }

    if has(ext::ALPS) || has(ext::ALPS_LEGACY) {
        reasons.push(
            if has(ext::ALPS) {
                "offers ALPS (application_settings, codepoint 0x44cd), sent only by Chromium"
            } else {
                "offers ALPS (legacy codepoint 0x4469), sent only by Chromium"
            }
            .to_string(),
        );
        if has(ext::ECH) {
            reasons.push("offers Encrypted Client Hello".into());
        }
        if has(ext::TRUST_ANCHORS) {
            reasons.push("offers trust_anchors (a headless or very recent build)".into());
        }
        return ClientGuess {
            family: ClientFamily::Chromium,
            confidence: Confidence::High,
            reasons,
            caveat: Some(IMPERSONATION_CAVEAT),
        };
    }

    if has(ext::RECORD_SIZE_LIMIT) && has(ext::DELEGATED_CREDENTIALS) {
        reasons.push(
            "offers record_size_limit and delegated_credentials, the pair sent by Firefox's NSS stack"
                .into(),
        );
        if has(ext::ECH) {
            reasons.push("offers Encrypted Client Hello".into());
        }
        return ClientGuess {
            family: ClientFamily::Firefox,
            confidence: Confidence::High,
            reasons,
            caveat: Some(IMPERSONATION_CAVEAT),
        };
    }

    if has(ext::ENCRYPT_THEN_MAC) {
        return ClientGuess {
            family: ClientFamily::OpenSsl,
            confidence: Confidence::Medium,
            reasons: vec![
                "offers encrypt_then_mac, which OpenSSL sends by default and browsers do not"
                    .into(),
            ],
            caveat: None,
        };
    }

    if has(ext::COMPRESS_CERTIFICATE) {
        reasons.push(
            "offers certificate compression without ALPS or Firefox's markers, as Apple's TLS does"
                .into(),
        );
        if has(ext::PADDING) {
            reasons.push("pads the ClientHello".into());
        }
        return ClientGuess {
            family: ClientFamily::SafariLike,
            confidence: Confidence::Low,
            reasons,
            caveat: Some(IMPERSONATION_CAVEAT),
        };
    }

    ClientGuess {
        family: if exts.len() <= 12 {
            ClientFamily::Library
        } else {
            ClientFamily::Unknown
        },
        confidence: Confidence::Low,
        reasons: vec![format!(
            "{} extensions and none of the browser markers (ALPS, record_size_limit with delegated_credentials, certificate compression)",
            exts.len()
        )],
        caveat: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw(exts: &str) -> String {
        format!("t13d0000h2_aaaa_{exts}_bbbb")
    }

    #[test]
    fn alps_means_chromium() {
        let guess = infer_client(&raw(
            "0005,000a,000b,000d,0012,0017,001b,0023,002b,002d,0033,44cd,fe0d,ff01",
        ));
        assert_eq!(guess.family, ClientFamily::Chromium);
        assert_eq!(guess.confidence, Confidence::High);
        assert!(
            guess.caveat.is_some(),
            "a browser guess always carries the caveat"
        );
    }

    #[test]
    fn legacy_alps_is_chromium_too() {
        let guess = infer_client(&raw(
            "0005,000a,000b,000d,0012,0015,0017,001b,0023,002b,002d,0033,4469,ff01",
        ));
        assert_eq!(guess.family, ClientFamily::Chromium);
    }

    #[test]
    fn nss_pair_means_firefox() {
        let guess = infer_client(&raw(
            "0005,000a,000b,000d,0012,0017,001b,001c,0022,0023,002b,002d,0033,fe0d,ff01",
        ));
        assert_eq!(guess.family, ClientFamily::Firefox);
    }

    #[test]
    fn openssl_is_not_a_browser() {
        let guess = infer_client(&raw("000a,000b,000d,0015,0016,0017,002b,002d,0031,0033"));
        assert_eq!(guess.family, ClientFamily::OpenSsl);
        assert!(guess.caveat.is_none());
        assert!(!guess.family.is_browser_like());
    }

    #[test]
    fn a_short_plain_hello_is_a_library() {
        let guess = infer_client(&raw("0005,000a,000b,000d,0012,0017,002b,0033,ff01"));
        assert_eq!(guess.family, ClientFamily::Library);
    }

    #[test]
    fn garbage_is_unknown_not_a_guess() {
        assert_eq!(infer_client("").family, ClientFamily::Unknown);
        assert_eq!(infer_client("not-a-ja4").family, ClientFamily::Unknown);
    }
}
