//! PQC mTLS server (Track 2 / Track 3).
//!
//! TLS 1.3, hybrid PQC KEM only (X25519MLKEM768), mutual auth against the demo
//! CA. Speaks minimal HTTP/1.0 so it interoperates with the Go client, curl,
//! and `openssl s_client`. Refuses any non-PQC key exchange.
//!
//! env: ADDR (default 127.0.0.1:9443), CERT_DIR (default ../certs)

use std::sync::Arc;

use anyhow::Context;
use simple_pqc_demo::{group_name, load_certs, load_key, pqc_provider, root_store, WANT_GROUP};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cert_dir = std::env::var("CERT_DIR").unwrap_or_else(|_| "../certs".into());
    let addr = std::env::var("ADDR").unwrap_or_else(|_| "127.0.0.1:9443".into());
    let provider = pqc_provider();

    let roots = Arc::new(root_store(&format!("{cert_dir}/ca.crt"))?);
    let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(roots, provider.clone())
        .build()
        .context("build client verifier")?;

    let certs = load_certs(&format!("{cert_dir}/server.crt"))?;
    let key = load_key(&format!("{cert_dir}/server.key"))?;

    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)?;

    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind(&addr).await?;
    eprintln!("rust PQC mTLS server on {addr}  (require {WANT_GROUP})");

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

    let (kex, has_peer) = {
        let (_io, conn) = tls.get_ref();
        (group_name(conn), conn.peer_certificates().map_or(0, |c| c.len()) > 0)
    };
    if kex != WANT_GROUP {
        anyhow::bail!("refused: non-PQC KEX {kex}");
    }

    // Drain the request head (up to the blank line) -- we don't route on it.
    let mut buf = [0u8; 2048];
    let _ = tls.read(&mut buf).await;

    let body = format!(
        "{{\"ok\":true,\"impl\":\"rust\",\"kex\":\"{kex}\",\"tls\":\"1.3\",\"peer\":\"{}\"}}\n",
        if has_peer { "verified" } else { "none" }
    );
    let resp = format!(
        "HTTP/1.0 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    tls.write_all(resp.as_bytes()).await?;
    tls.flush().await?;
    tls.shutdown().await?; // send TLS close_notify so the peer sees a clean EOF
    eprintln!("served  kex={kex}  peer={}", if has_peer { "verified" } else { "none" });
    Ok(())
}
