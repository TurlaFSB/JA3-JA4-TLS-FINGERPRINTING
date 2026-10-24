// © Pranav Verma | 2026
// detail.rs

//! The readable contents of a hello: what was offered or chosen, in wire
//! order, with registry names where this build knows them.
//!
//! Fingerprints say two clients differ; this says how. Names come from a
//! small table of the values seen in practice. A value the table does not
//! know is kept as its number, never dropped, because an unfamiliar value is
//! often exactly what sets a client apart.

use serde::Serialize;

use crate::grease::is_grease;
use crate::parse::{ClientHello, ServerHello};
use crate::registry::version;

/// A registry value with its name when known.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Named {
    pub id: u16,
    pub name: String,
}

/// What a ClientHello offered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ClientDetail {
    /// The version word in the record, which TLS 1.3 clients pin to 1.2.
    pub legacy_version: String,
    /// Versions offered in the supported_versions extension, highest first.
    pub versions: Vec<String>,
    pub ciphers: Vec<Named>,
    pub extensions: Vec<Named>,
    pub groups: Vec<Named>,
    pub signature_algorithms: Vec<Named>,
    pub ec_point_formats: Vec<u8>,
    pub alpn: Vec<String>,
    /// Capabilities the client signalled, as short readable tags.
    pub features: Vec<&'static str>,
    /// Whether the client inserted GREASE values (RFC 8701), as modern
    /// browsers and many libraries do.
    pub grease: bool,
}

/// What a ServerHello chose.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ServerDetail {
    pub version: String,
    pub cipher: Named,
    pub extensions: Vec<Named>,
    pub alpn: Option<String>,
}

/// The detail of either hello, as carried on an event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum HelloDetail {
    Client(ClientDetail),
    Server(ServerDetail),
}

#[must_use]
pub fn version_name(word: u16) -> String {
    match word {
        version::TLS_1_3 => "TLS 1.3".to_owned(),
        version::TLS_1_2 => "TLS 1.2".to_owned(),
        version::TLS_1_1 => "TLS 1.1".to_owned(),
        version::TLS_1_0 => "TLS 1.0".to_owned(),
        version::SSL_3_0 => "SSL 3.0".to_owned(),
        version::SSL_2_0 => "SSL 2.0".to_owned(),
        version::DTLS_1_0 => "DTLS 1.0".to_owned(),
        version::DTLS_1_2 => "DTLS 1.2".to_owned(),
        version::DTLS_1_3 => "DTLS 1.3".to_owned(),
        w if is_grease(w) => "GREASE".to_owned(),
        w => format!("unknown (0x{w:04x})"),
    }
}

fn named(id: u16, lookup: fn(u16) -> Option<&'static str>) -> Named {
    let name = if is_grease(id) {
        "GREASE".to_owned()
    } else {
        lookup(id).map_or_else(|| format!("unknown (0x{id:04x})"), str::to_owned)
    };
    Named { id, name }
}

fn cipher_name(id: u16) -> Option<&'static str> {
    Some(match id {
        0x1301 => "TLS_AES_128_GCM_SHA256",
        0x1302 => "TLS_AES_256_GCM_SHA384",
        0x1303 => "TLS_CHACHA20_POLY1305_SHA256",
        0x1304 => "TLS_AES_128_CCM_SHA256",
        0x1305 => "TLS_AES_128_CCM_8_SHA256",
        0xc02b => "ECDHE_ECDSA_AES_128_GCM_SHA256",
        0xc02c => "ECDHE_ECDSA_AES_256_GCM_SHA384",
        0xc02f => "ECDHE_RSA_AES_128_GCM_SHA256",
        0xc030 => "ECDHE_RSA_AES_256_GCM_SHA384",
        0xcca8 => "ECDHE_RSA_CHACHA20_POLY1305",
        0xcca9 => "ECDHE_ECDSA_CHACHA20_POLY1305",
        0xccaa => "DHE_RSA_CHACHA20_POLY1305",
        0xc009 => "ECDHE_ECDSA_AES_128_CBC_SHA",
        0xc00a => "ECDHE_ECDSA_AES_256_CBC_SHA",
        0xc013 => "ECDHE_RSA_AES_128_CBC_SHA",
        0xc014 => "ECDHE_RSA_AES_256_CBC_SHA",
        0xc023 => "ECDHE_ECDSA_AES_128_CBC_SHA256",
        0xc024 => "ECDHE_ECDSA_AES_256_CBC_SHA384",
        0xc027 => "ECDHE_RSA_AES_128_CBC_SHA256",
        0xc028 => "ECDHE_RSA_AES_256_CBC_SHA384",
        0x009c => "RSA_AES_128_GCM_SHA256",
        0x009d => "RSA_AES_256_GCM_SHA384",
        0x003c => "RSA_AES_128_CBC_SHA256",
        0x003d => "RSA_AES_256_CBC_SHA256",
        0x002f => "RSA_AES_128_CBC_SHA",
        0x0035 => "RSA_AES_256_CBC_SHA",
        0x000a => "RSA_3DES_EDE_CBC_SHA",
        0x0005 => "RSA_RC4_128_SHA",
        0x0004 => "RSA_RC4_128_MD5",
        0x009e => "DHE_RSA_AES_128_GCM_SHA256",
        0x009f => "DHE_RSA_AES_256_GCM_SHA384",
        0x0033 => "DHE_RSA_AES_128_CBC_SHA",
        0x0039 => "DHE_RSA_AES_256_CBC_SHA",
        0x0067 => "DHE_RSA_AES_128_CBC_SHA256",
        0x006b => "DHE_RSA_AES_256_CBC_SHA256",
        0x00ff => "EMPTY_RENEGOTIATION_INFO_SCSV",
        0x5600 => "FALLBACK_SCSV",
        0xc02d => "ECDH_ECDSA_AES_128_GCM_SHA256",
        0xc031 => "ECDH_RSA_AES_128_GCM_SHA256",
        0xc012 => "ECDHE_RSA_3DES_EDE_CBC_SHA",
        0xc008 => "ECDHE_ECDSA_3DES_EDE_CBC_SHA",
        _ => return None,
    })
}

fn extension_name(id: u16) -> Option<&'static str> {
    Some(match id {
        0x0000 => "server_name",
        0x0001 => "max_fragment_length",
        0x0005 => "status_request",
        0x000a => "supported_groups",
        0x000b => "ec_point_formats",
        0x000d => "signature_algorithms",
        0x000e => "use_srtp",
        0x000f => "heartbeat",
        0x0010 => "application_layer_protocol_negotiation",
        0x0012 => "signed_certificate_timestamp",
        0x0015 => "padding",
        0x0016 => "encrypt_then_mac",
        0x0017 => "extended_master_secret",
        0x001b => "compress_certificate",
        0x001c => "record_size_limit",
        0x0022 => "delegated_credentials",
        0x0023 => "session_ticket",
        0x0029 => "pre_shared_key",
        0x002a => "early_data",
        0x002b => "supported_versions",
        0x002c => "cookie",
        0x002d => "psk_key_exchange_modes",
        0x002f => "certificate_authorities",
        0x0031 => "post_handshake_auth",
        0x0032 => "signature_algorithms_cert",
        0x0033 => "key_share",
        0x0039 => "quic_transport_parameters",
        0x3374 => "next_protocol_negotiation",
        0x4469 => "application_settings (old)",
        0x44cd => "application_settings",
        0xfe0d => "encrypted_client_hello",
        0xff01 => "renegotiation_info",
        _ => return None,
    })
}

fn group_name(id: u16) -> Option<&'static str> {
    Some(match id {
        0x0017 => "secp256r1",
        0x0018 => "secp384r1",
        0x0019 => "secp521r1",
        0x001d => "x25519",
        0x001e => "x448",
        0x0100 => "ffdhe2048",
        0x0101 => "ffdhe3072",
        0x0102 => "ffdhe4096",
        0x0103 => "ffdhe6144",
        0x0104 => "ffdhe8192",
        0x001a => "brainpoolP256r1",
        0x001b => "brainpoolP384r1",
        0x001c => "brainpoolP512r1",
        0x6399 => "X25519Kyber768Draft00",
        0x11eb => "SecP256r1Kyber768Draft00",
        0x11ec => "X25519MLKEM768",
        0x11ed => "SecP256r1MLKEM768",
        0x0200 => "MLKEM512",
        0x0201 => "MLKEM768",
        0x0202 => "MLKEM1024",
        _ => return None,
    })
}

fn sigalg_name(id: u16) -> Option<&'static str> {
    Some(match id {
        0x0401 => "rsa_pkcs1_sha256",
        0x0501 => "rsa_pkcs1_sha384",
        0x0601 => "rsa_pkcs1_sha512",
        0x0201 => "rsa_pkcs1_sha1",
        0x0403 => "ecdsa_secp256r1_sha256",
        0x0503 => "ecdsa_secp384r1_sha384",
        0x0603 => "ecdsa_secp521r1_sha512",
        0x0203 => "ecdsa_sha1",
        0x0804 => "rsa_pss_rsae_sha256",
        0x0805 => "rsa_pss_rsae_sha384",
        0x0806 => "rsa_pss_rsae_sha512",
        0x0809 => "rsa_pss_pss_sha256",
        0x080a => "rsa_pss_pss_sha384",
        0x080b => "rsa_pss_pss_sha512",
        0x0807 => "ed25519",
        0x0808 => "ed448",
        0x0402 => "dsa_sha256",
        0x0301 => "rsa_pkcs1_sha224",
        0x0303 => "ecdsa_sha224",
        0x0101 => "rsa_pkcs1_md5",
        _ => return None,
    })
}

/// The features worth naming, from the extensions a client sent.
fn features(extensions: &[Named]) -> Vec<&'static str> {
    let has = |id: u16| extensions.iter().any(|e| e.id == id);
    let mut out = Vec::new();
    for (id, tag) in [
        (0xfe0d, "ECH"),
        (0x0029, "PSK resumption"),
        (0x0023, "session tickets"),
        (0x0005, "OCSP stapling"),
        (0x0012, "SCT"),
        (0x0017, "extended master secret"),
        (0x001b, "certificate compression"),
        (0x0022, "delegated credentials"),
        (0x002a, "early data"),
        (0x0031, "post-handshake auth"),
        (0x44cd, "ALPS"),
        (0x4469, "ALPS"),
        (0x0039, "QUIC transport parameters"),
        (0x3374, "NPN (legacy)"),
        (0xff01, "secure renegotiation"),
    ] {
        if has(id) && !out.contains(&tag) {
            out.push(tag);
        }
    }
    out
}

/// Reads the offered contents of a ClientHello.
#[must_use]
pub fn client_detail(hello: &ClientHello<'_>) -> ClientDetail {
    let ciphers: Vec<Named> = hello
        .cipher_suites
        .iter()
        .map(|&c| named(c, cipher_name))
        .collect();
    let extensions: Vec<Named> = hello
        .extensions
        .iter()
        .map(|e| named(e.ext_type, extension_name))
        .collect();
    let mut offered: Vec<u16> = hello
        .supported_versions()
        .into_iter()
        .filter(|&v| !is_grease(v))
        .collect();
    offered.sort_unstable_by(|a, b| b.cmp(a));
    let grease = hello.cipher_suites.iter().any(|&c| is_grease(c))
        || hello.extensions.iter().any(|e| is_grease(e.ext_type))
        || hello.supported_groups().iter().any(|&g| is_grease(g));
    ClientDetail {
        legacy_version: version_name(hello.legacy_version),
        versions: offered.into_iter().map(version_name).collect(),
        features: features(&extensions),
        ciphers,
        extensions,
        groups: hello
            .supported_groups()
            .iter()
            .map(|&g| named(g, group_name))
            .collect(),
        signature_algorithms: hello
            .signature_algorithms()
            .iter()
            .map(|&s| named(s, sigalg_name))
            .collect(),
        ec_point_formats: hello.ec_point_formats().to_vec(),
        alpn: hello
            .alpn_protocols()
            .iter()
            .map(|p| String::from_utf8_lossy(p).into_owned())
            .collect(),
        grease,
    }
}

/// Reads the chosen contents of a ServerHello.
#[must_use]
pub fn server_detail(hello: &ServerHello<'_>) -> ServerDetail {
    ServerDetail {
        version: version_name(hello.selected_version()),
        cipher: named(hello.cipher_suite, cipher_name),
        extensions: hello
            .extensions
            .iter()
            .map(|e| named(e.ext_type, extension_name))
            .collect(),
        alpn: hello
            .alpn_protocol()
            .map(|p| String::from_utf8_lossy(p).into_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::parse_client_hello;

    /// A TLS 1.3 style hello: GREASE cipher, two real ciphers, SNI, supported
    /// versions (GREASE, 1.3, 1.2), ALPN h2.
    fn hello_bytes() -> Vec<u8> {
        let mut b = vec![0x03, 0x03];
        b.extend([0u8; 32]);
        b.push(0);
        b.extend([0x00, 0x06, 0x0a, 0x0a, 0x13, 0x01, 0xc0, 0x2f]);
        b.extend([0x01, 0x00]);
        let mut ext = Vec::new();
        // server_name example.com
        ext.extend([0x00, 0x00, 0x00, 0x10, 0x00, 0x0e, 0x00, 0x00, 0x0b]);
        ext.extend(b"example.com");
        // supported_versions: GREASE, 1.3, 1.2
        ext.extend([
            0x00, 0x2b, 0x00, 0x07, 0x06, 0x1a, 0x1a, 0x03, 0x04, 0x03, 0x03,
        ]);
        // alpn: h2
        ext.extend([0x00, 0x10, 0x00, 0x05, 0x00, 0x03, 0x02, b'h', b'2']);
        // supported_groups: x25519, X25519MLKEM768
        ext.extend([0x00, 0x0a, 0x00, 0x06, 0x00, 0x04, 0x00, 0x1d, 0x11, 0xec]);
        // ech
        ext.extend([0xfe, 0x0d, 0x00, 0x00]);
        b.extend(u16::try_from(ext.len()).unwrap().to_be_bytes());
        b.extend(ext);
        b
    }

    #[test]
    fn a_hello_is_described_in_words() {
        let bytes = hello_bytes();
        let hello = parse_client_hello(&bytes).unwrap();
        let detail = client_detail(&hello);
        assert_eq!(detail.legacy_version, "TLS 1.2");
        assert_eq!(detail.versions, ["TLS 1.3", "TLS 1.2"]);
        assert!(detail.grease);
        assert_eq!(detail.ciphers[0].name, "GREASE");
        assert_eq!(detail.ciphers[1].name, "TLS_AES_128_GCM_SHA256");
        assert_eq!(detail.ciphers[2].name, "ECDHE_RSA_AES_128_GCM_SHA256");
        assert_eq!(detail.alpn, ["h2"]);
        assert_eq!(detail.groups[1].name, "X25519MLKEM768");
        assert!(detail.features.contains(&"ECH"));
        assert_eq!(detail.extensions[0].name, "server_name");
    }

    #[test]
    fn an_unfamiliar_value_is_kept_as_its_number() {
        let named = named(0x1234, cipher_name);
        assert_eq!(named.id, 0x1234);
        assert_eq!(named.name, "unknown (0x1234)");
    }
}
