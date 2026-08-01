//! Fully post-quantum mTLS server (Track 5, EXPERIMENTAL).
//!
//! TLS 1.3, hybrid PQC KEM only (X25519MLKEM768), mutual auth against an
//! **ML-DSA-65** CA. Speaks minimal HTTP/1.0 so `openssl s_client` and the
//! sibling Rust client can both drive it. Refuses a non-PQC KEX *and* a peer
//! that did not authenticate with an ML-DSA-65 certificate.
//!
//! env: ADDR (default 127.0.0.1:10443), CERT_DIR (default ../certs-mldsa)

use std::sync::Arc;

use anyhow::Context;
use simple_pqc_mldsa::{assert_fully_pqc, load_certs, load_key, mldsa_provider, root_store, WANT_GROUP};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cert_dir = std::env::var("CERT_DIR").unwrap_or_else(|_| "../certs-mldsa".into());
    let addr = std::env::var("ADDR").unwrap_or_else(|_| "127.0.0.1:10443".into());
    let provider = mldsa_provider();

    let roots = Arc::new(root_store(&format!("{cert_dir}/ca.crt"))?);
    let verifier =
        rustls::server::WebPkiClientVerifier::builder_with_provider(roots, provider.clone())
            .build()
            .context("build ML-DSA client verifier")?;

    let certs = load_certs(&format!("{cert_dir}/server.crt"))?;
    let key = load_key(&format!("{cert_dir}/server.key"))
        .context("load ML-DSA-65 server key (must be PKCS#8)")?;

    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)
        .context("ML-DSA-65 cert/key rejected by the provider")?;

    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind(&addr).await?;
    eprintln!("rust fully-PQC mTLS server on {addr}  (require {WANT_GROUP} + ML-DSA-65 auth)");

    loop {
        let (sock, peer) = listener.accept().await?;
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            if let Err(e) = handle(sock, acceptor).await {
                eprintln!("conn {peer} error: {e:#}");
            }
        });
    }
}

async fn handle(sock: TcpStream, acceptor: TlsAcceptor) -> anyhow::Result<()> {
    let mut tls = acceptor.accept(sock).await.context("tls accept")?;

    let kex = {
        let (_io, conn) = tls.get_ref();
        assert_fully_pqc(conn)?
    };

    // Drain the request head -- we don't route on it.
    let mut buf = [0u8; 2048];
    let _ = tls.read(&mut buf).await;

    let body = format!(
        "{{\"ok\":true,\"impl\":\"rust-mldsa\",\"kex\":\"{kex}\",\"tls\":\"1.3\",\"auth\":\"ML-DSA-65\",\"peer\":\"verified\"}}\n"
    );
    let resp = format!(
        "HTTP/1.0 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    tls.write_all(resp.as_bytes()).await?;
    tls.flush().await?;
    tls.shutdown().await?; // close_notify, so the peer sees a clean EOF
    eprintln!("served  kex={kex}  auth=ML-DSA-65  peer=verified");
    Ok(())
}
