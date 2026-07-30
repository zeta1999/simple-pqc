//! Track 4: PQC secure channel over real TCP, using `simple_network::security::pqc`.
//!
//! This is the PQC *authentication* story that works TODAY and interoperably
//! with our own tooling, ahead of X.509 ML-DSA in TLS (Go: 2027):
//!   - KEM:  hybrid ML-KEM-768 + X25519   (post-quantum key agreement)
//!   - AUTH: ML-DSA-65 signatures over the handshake, each side verifying the
//!           other against a PINNED verifying key (set at pairing)
//!   - RECORDS: XChaCha20-Poly1305 seal/open
//!
//! We run it end to end over a loopback TCP socket, then prove that a client
//! with the WRONG pinned server key is rejected (MITM / impersonation defense).

use anyhow::Result;
use simple_network::security::pqc::{Identity, Initiator, Responder};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

async fn write_frame<W: AsyncWriteExt + Unpin>(w: &mut W, data: &[u8]) -> Result<()> {
    w.write_u32(data.len() as u32).await?;
    w.write_all(data).await?;
    w.flush().await?;
    Ok(())
}

async fn read_frame<R: AsyncReadExt + Unpin>(r: &mut R) -> Result<Vec<u8>> {
    let n = r.read_u32().await? as usize;
    let mut buf = vec![0u8; n];
    r.read_exact(&mut buf).await?;
    Ok(buf)
}

/// Server: verify client against `client_pin`, establish session, echo one record.
async fn run_server(listener: TcpListener, id: Identity, client_pin: Vec<u8>) -> Result<()> {
    let (mut sock, _) = listener.accept().await?;
    let hello = read_frame(&mut sock).await?;
    let responder = Responder::new(id, client_pin);
    let (resp, mut session) = responder.respond(&hello)?; // errors if client pin/sig bad
    write_frame(&mut sock, &resp).await?;

    let ct = read_frame(&mut sock).await?;
    let pt = session.open(&ct)?;
    eprintln!("  [server] opened record: {:?}", String::from_utf8_lossy(&pt));
    let reply = session.seal(b"pong: authenticated with ML-DSA-65")?;
    write_frame(&mut sock, &reply).await?;
    Ok(())
}

/// Client: pin the server as `server_pin`, handshake, exchange one record.
async fn run_client(addr: std::net::SocketAddr, id: Identity, server_pin: Vec<u8>) -> Result<String> {
    let mut sock = TcpStream::connect(addr).await?;
    let initiator = Initiator::new(id, server_pin)?;
    write_frame(&mut sock, &initiator.hello()?).await?;

    let resp = read_frame(&mut sock).await?;
    let mut session = initiator.finish(&resp)?; // errors if server pin/sig bad
    write_frame(&mut sock, &session.seal(b"ping: hello over PQC channel")?).await?;

    let reply = read_frame(&mut sock).await?;
    Ok(String::from_utf8_lossy(&session.open(&reply)?).into_owned())
}

#[tokio::main]
async fn main() -> Result<()> {
    // ---- positive: matched pins -----------------------------------------
    let server_id = Identity::generate()?;
    let client_id = Identity::generate()?;
    let server_vk = server_id.verifying_key();
    let client_vk = client_id.verifying_key();
    println!(
        "ML-DSA-65 identities generated: server_vk={} B, client_vk={} B",
        server_vk.len(),
        client_vk.len()
    );

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let srv = tokio::spawn(run_server(listener, server_id, client_vk));
    let reply = run_client(addr, client_id, server_vk).await?;
    srv.await??;
    println!("PASS positive: mutual ML-DSA-65 auth + ML-KEM-768 channel; client opened {reply:?}");

    // ---- negative: client pins the WRONG server key ---------------------
    let server_id2 = Identity::generate()?;
    let client_id2 = Identity::generate()?;
    let client_vk2 = client_id2.verifying_key();
    let wrong_pin = Identity::generate()?.verifying_key(); // not the real server
    let listener2 = TcpListener::bind("127.0.0.1:0").await?;
    let addr2 = listener2.local_addr()?;
    let srv2 = tokio::spawn(run_server(listener2, server_id2, client_vk2));
    let res = run_client(addr2, client_id2, wrong_pin).await;
    let _ = srv2.await; // server side may see an EOF; ignore

    match res {
        Err(e) => {
            println!("PASS negative: wrong server pin rejected -> {e}");
            Ok(())
        }
        Ok(_) => {
            eprintln!("FAIL negative: a wrong pinned key was accepted!");
            std::process::exit(1);
        }
    }
}
