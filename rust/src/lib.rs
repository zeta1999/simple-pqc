//! Shared PQC mTLS helpers for the Rust demo endpoints.
//!
//! PQC property demonstrated: post-quantum KEY EXCHANGE via the hybrid
//! `X25519MLKEM768` group. We build a crypto provider that offers ONLY that
//! group, so a classical-only peer cannot handshake. Authentication stays
//! classical (Ed25519 certs) -- the interoperable, demoable-today posture.

use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;

use rustls::crypto::{aws_lc_rs, CryptoProvider};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

/// The hybrid post-quantum KEM group we require (IANA 0x11EC).
pub const WANT_GROUP: &str = "X25519MLKEM768";

/// aws-lc-rs provider restricted to the PQC hybrid key exchange group.
pub fn pqc_provider() -> Arc<CryptoProvider> {
    let mut p = aws_lc_rs::default_provider();
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
