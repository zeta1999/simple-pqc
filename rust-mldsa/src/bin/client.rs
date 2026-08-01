//! Fully post-quantum mTLS client (Track 5, EXPERIMENTAL).
//!
//! Presents an ML-DSA-65 client certificate, offers only the hybrid PQC KEM,
//! and asserts BOTH properties on the completed handshake: the negotiated
//! group is X25519MLKEM768 *and* the server authenticated with an ML-DSA-65
//! certificate. Exits non-zero otherwise, so it is usable as a test.
//!
//! env: HOST (default 127.0.0.1), PORT (default 10443), CERT_DIR (default ../certs-mldsa)

use std::sync::Arc;

use anyhow::Context;
use rustls::pki_types::ServerName;
use simple_pqc_mldsa::{assert_fully_pqc, load_certs, load_key, mldsa_provider, root_store};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cert_dir = std::env::var("CERT_DIR").unwrap_or_else(|_| "../certs-mldsa".into());
    let host = std::env::var("HOST").unwrap_or_else(|_| "127.0.0.1".into());
    let port = std::env::var("PORT").unwrap_or_else(|_| "10443".into());
    let provider = mldsa_provider();

    let roots = root_store(&format!("{cert_dir}/ca.crt"))?;
    let certs = load_certs(&format!("{cert_dir}/client.crt"))?;
    let key = load_key(&format!("{cert_dir}/client.key"))
        .context("load ML-DSA-65 client key (must be PKCS#8)")?;

    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_client_auth_cert(certs, key)
        .context("ML-DSA-65 client cert/key rejected by the provider")?;

    let connector = TlsConnector::from(Arc::new(config));
    let sock = TcpStream::connect(format!("{host}:{port}"))
        .await
        .with_context(|| format!("connect {host}:{port}"))?;
    let server_name = ServerName::try_from("localhost".to_string())?;
    let mut tls = connector
        .connect(server_name, sock)
        .await
        .context("tls connect")?;

    let kex = {
        let (_io, conn) = tls.get_ref();
        assert_fully_pqc(conn).context("FAIL: handshake was not fully post-quantum")?
    };

    tls.write_all(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
        .await?;
    tls.flush().await?;
    let mut resp = String::new();
    tls.read_to_string(&mut resp).await?;

    let body = resp.split("\r\n\r\n").nth(1).unwrap_or("");
    eprintln!("OK  kex={kex}  auth=ML-DSA-65 (server cert verified)");
    print!("{body}");
    Ok(())
}
