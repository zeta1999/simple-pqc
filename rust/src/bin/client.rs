//! PQC mTLS client (Track 2 / Track 3).
//!
//! Connects with a client cert, offers only the hybrid PQC KEM, and asserts
//! the negotiated group is post-quantum (exit non-zero otherwise). Speaks
//! minimal HTTP/1.0 so it interoperates with the Go and Rust servers.
//!
//! env: HOST (default 127.0.0.1), PORT (default 9443), CERT_DIR (default ../certs)

use std::sync::Arc;

use anyhow::Context;
use rustls::pki_types::ServerName;
use simple_pqc_demo::{group_name, load_certs, load_key, pqc_provider, root_store, WANT_GROUP};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cert_dir = std::env::var("CERT_DIR").unwrap_or_else(|_| "../certs".into());
    let host = std::env::var("HOST").unwrap_or_else(|_| "127.0.0.1".into());
    let port = std::env::var("PORT").unwrap_or_else(|_| "9443".into());
    let provider = pqc_provider();

    let roots = root_store(&format!("{cert_dir}/ca.crt"))?;
    let certs = load_certs(&format!("{cert_dir}/client.crt"))?;
    let key = load_key(&format!("{cert_dir}/client.key"))?;

    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_client_auth_cert(certs, key)?;

    let connector = TlsConnector::from(Arc::new(config));
    let sock = TcpStream::connect(format!("{host}:{port}")).await
        .with_context(|| format!("connect {host}:{port}"))?;
    let server_name = ServerName::try_from("localhost".to_string())?;
    let mut tls = connector.connect(server_name, sock).await.context("tls connect")?;

    let kex = {
        let (_io, conn) = tls.get_ref();
        group_name(conn)
    };
    if kex != WANT_GROUP {
        anyhow::bail!("FAIL: negotiated non-PQC KEX ({kex}), wanted {WANT_GROUP}");
    }

    tls.write_all(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n").await?;
    tls.flush().await?;
    let mut resp = String::new();
    tls.read_to_string(&mut resp).await?;

    let body = resp.split("\r\n\r\n").nth(1).unwrap_or("");
    eprintln!("OK  kex={kex}");
    print!("{body}");
    Ok(())
}
