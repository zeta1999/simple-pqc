//! Shared helpers for the **fully post-quantum** Rust mTLS endpoints (Track 5).
//!
//! Unlike `../rust` (PQC KEM + classical Ed25519 auth), these endpoints prove
//! BOTH PQC properties at once:
//!
//! * **KEM** — hybrid `X25519MLKEM768`, the only group we offer.
//! * **PKI / auth** — ML-DSA-65 (FIPS 204) X.509 certificates, signature
//!   scheme `0x0905`, verified mutually.
//!
//! EXPERIMENTAL: ML-DSA signing comes from `rustls-post-quantum`'s
//! `aws-lc-rs-unstable` feature. `rustls` itself knows the codepoints but its
//! stock provider cannot sign or verify with them, so swapping in this
//! provider is what makes the whole thing work.

use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;

use rustls::crypto::{aws_lc_rs, CryptoProvider};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

/// The hybrid post-quantum KEM group we require (IANA 0x11EC).
pub const WANT_GROUP: &str = "X25519MLKEM768";

/// DER encoding of the `id-ml-dsa-65` OID, 2.16.840.1.101.3.4.3.18 (RFC 9881),
/// including the tag and length bytes so it cannot match by accident.
const ML_DSA_65_OID_DER: &[u8] = &[
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12,
];

/// Provider that requires post-quantum crypto on *both* axes: ML-DSA signing
/// and verification, and only the hybrid PQC key-exchange group.
///
/// `rustls_post_quantum::provider()` replaces the stock aws-lc-rs
/// `key_provider` and `signature_verification_algorithms`; we then narrow
/// `kx_groups` so a classical-only peer cannot negotiate at all.
pub fn mldsa_provider() -> Arc<CryptoProvider> {
    let mut p = rustls_post_quantum::provider();
    p.kx_groups = vec![aws_lc_rs::kx_group::X25519MLKEM768];
    Arc::new(p)
}

pub fn load_certs(path: &str) -> anyhow::Result<Vec<CertificateDer<'static>>> {
    let mut r = BufReader::new(File::open(path)?);
    Ok(rustls_pemfile::certs(&mut r).collect::<Result<Vec<_>, _>>()?)
}

pub fn load_key(path: &str) -> anyhow::Result<PrivateKeyDer<'static>> {
    let mut r = BufReader::new(File::open(path)?);
    rustls_pemfile::private_key(&mut r)?.ok_or_else(|| anyhow::anyhow!("no private key in {path}"))
}

pub fn root_store(ca: &str) -> anyhow::Result<rustls::RootCertStore> {
    let mut roots = rustls::RootCertStore::empty();
    for c in load_certs(ca)? {
        roots.add(c)?;
    }
    Ok(roots)
}

/// Render the negotiated key-exchange group of a live connection.
pub fn group_name(conn: &rustls::CommonState) -> String {
    match conn.negotiated_key_exchange_group() {
        Some(g) => format!("{:?}", g.name()),
        None => "none".to_string(),
    }
}

/// Whether the peer's end-entity certificate is an ML-DSA-65 certificate.
///
/// In this PKI the OID appears twice — as the subject public key algorithm and
/// as the certificate's signature algorithm — so a presence check is
/// sufficient to say "this peer authenticated with ML-DSA-65". Note the
/// handshake itself is the stronger proof: rustls only gets here after
/// verifying an ML-DSA signature, since that is the only scheme on offer.
pub fn peer_is_mldsa65(conn: &rustls::CommonState) -> bool {
    conn.peer_certificates()
        .and_then(|c| c.first())
        .is_some_and(|leaf| {
            leaf.as_ref()
                .windows(ML_DSA_65_OID_DER.len())
                .any(|w| w == ML_DSA_65_OID_DER)
        })
}

/// Assert both PQC properties on a completed handshake, or explain which failed.
pub fn assert_fully_pqc(conn: &rustls::CommonState) -> anyhow::Result<String> {
    let kex = group_name(conn);
    if kex != WANT_GROUP {
        anyhow::bail!("refused: non-PQC KEX {kex}");
    }
    if !peer_is_mldsa65(conn) {
        anyhow::bail!("refused: peer did not authenticate with an ML-DSA-65 certificate");
    }
    Ok(kex)
}
