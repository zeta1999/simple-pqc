# Experiments — verified PQC results

Each experiment is **runnable** and was executed on the machine below; the
output shown is the real captured output, not illustrative. Re-run any of them
with the `make` target listed. Every experiment states **which PQC property** it
proves — *KEM* (post-quantum key exchange, beats harvest-now-decrypt-later) vs
*PKI/auth* (post-quantum signatures, beats quantum MITM/forgery).

## Environment

| | |
|---|---|
| Date run | 2026-07-30 |
| Host | macOS 26 (Tahoe), Apple Silicon (arm64) |
| OpenSSL | 3.6.3 (`/opt/homebrew/bin/openssl`) — PATH `openssl` is miniconda 3.0.17 (no PQC), `/usr/bin/openssl` is LibreSSL |
| Go | 1.26.2 |
| Rust | 1.95.0 · rustls 0.23 + aws-lc-rs · tokio-rustls 0.26 |
| OpenSSH | client 10.2p1 (system) · sshd 10.4p1 (Homebrew) |

---

## E1 — mini-CA (Ed25519) · `make certs`

**Proves:** test-fixture setup (classical PKI, the hybrid-ECC/PQC baseline auth).

```
$ ./scripts/gen-ca.sh
openssl: /opt/homebrew/bin/openssl (OpenSSL 3.6.3 9 Jun 2026 ...)
Verify chain:
server.crt: OK
client.crt: OK
```

---

## E2 — Go↔Go PQC mTLS · `make run-go`

**Proves:** KEM = post-quantum (`X25519MLKEM768`), auth = classical Ed25519,
mutual. Both ends **assert** the group and refuse a non-PQC KEX.

```
$ CERT_DIR=./certs go run ./server &   # then the client:
2026/07/30 13:18:37 OK  status=200 OK  kex=X25519MLKEM768 (0x11ec)
{"ok":true,"impl":"go","kex":"X25519MLKEM768 (0x11ec)","tls":"1.3","peer_cn":"demo-client"}
# server log:
served 127.0.0.1:54631  kex=X25519MLKEM768 (0x11ec)  peer_cn=demo-client
```

## E3 — Rust↔Rust PQC mTLS · `make run-rust`

**Proves:** same as E2, on rustls/aws-lc-rs. The provider offers **only** the
PQC hybrid group (`ring` provider has no PQC at all).

```
$ ./target/debug/pqc-client
OK  kex=X25519MLKEM768
{"ok":true,"impl":"rust","kex":"X25519MLKEM768","tls":"1.3","peer":"verified"}
```

---

## E4 — proof harness, positive & negative · `make prove` / `make prove-neg`

**Proves:** KEM negotiation is real (openssl as an independent third client), and
that the strict server **rejects** a classical-only client (no silent downgrade).

Positive:
```
== POSITIVE: PQC client (X25519MLKEM768) against 127.0.0.1:8443 ==
Negotiated TLS1.3 group: X25519MLKEM768
Protocol: TLSv1.3
Verify return code: 0 (ok)
PASS: post-quantum KEM negotiated (X25519MLKEM768).
```
Negative (classical-only `-groups X25519`):
```
== NEGATIVE: classical-only client (X25519) against 127.0.0.1:8443 ==
PASS: classical-only client was REFUSED (strict PQC-only server).
...ssl/tls alert handshake failure...SSL alert number 40
```

---

## E5 — cross-language interop matrix · `make interop`

**Proves:** KEM = post-quantum across **every** (client × server) pair of
{Go, Rust, OpenSSL}. This is the headline result.

```
client \ server  | go (:8443)         | rust (:9443)
-----------------+--------------------+-------------------
go               | X25519MLKEM768     | X25519MLKEM768
rust             | X25519MLKEM768     | X25519MLKEM768
openssl          | X25519MLKEM768     | X25519MLKEM768

PASS: all pairs negotiated X25519MLKEM768 (PQC KEM).
```

---

## E6 — PQC SSH to a non-root sshd · `make ssh`

**Proves:** KEM = post-quantum SSH KEX (`mlkem768x25519-sha256`) to a sshd run as
the current user (no root), pinned so a classical KEX cannot be used. Auth is
classical ed25519 (SSH PQC auth is still experimental — see notes).

```
$ ./scripts/ssh-pqc-demo.sh
ssh:  OpenSSH_10.2p1, OpenSSL 3.6.3 9 Jun 2026
== client output ==
REMOTE_OK
Darwin arm64
== negotiated KEX (client) ==
debug1: kex: algorithm: mlkem768x25519-sha256
PASS: authenticated over post-quantum SSH KEX (mlkem768x25519-sha256).
```

**Secretive variant (interactive, not automated):** add a Secure-Enclave
ECDSA-P-256 key from Secretive to `authorized_keys` and connect without `-i`;
Touch ID gates the signature. Result: PQC KEX + hardware-held classical auth.
See the recipe printed by the script. (Frontier: Secretive on Tahoe can hold
Enclave **ML-DSA-65** keys, but its wire format is draft-sfluhrer while OpenSSH
implements the composite draft — no interoperable server yet.)

**Gotcha proven in testing:** `StrictModes` silently fails auth if the demo dir
or `authorized_keys` perms are loose; the script sets `chmod 700`/`600`.

---

## E7 — fully post-quantum mTLS: ML-DSA-65 certs · `make mldsa` *(EXPERIMENTAL)*

**Proves BOTH properties at once:** KEM = `X25519MLKEM768` **and** auth = ML-DSA-65
(FIPS 204) X.509 certificates, mutually verified. OpenSSL 3.6.3 both ends.

```
$ ./scripts/gen-ca-mldsa.sh
  ca.crt  -> Signature Algorithm: ML-DSA-65
  server.crt -> Signature Algorithm: ML-DSA-65
  client.crt -> Signature Algorithm: ML-DSA-65
Verify chain:  server.crt: OK   client.crt: OK

$ ./scripts/mldsa-tls-demo.sh
== handshake facts ==
Peer signature type: mldsa65
Negotiated TLS1.3 group: X25519MLKEM768
Protocol: TLSv1.3
Verify return code: 0 (ok)
== server cert signature algorithm ==
Signature Algorithm: ML-DSA-65
PASS KEM : X25519MLKEM768 negotiated
PASS AUTH: server authenticated with ML-DSA
PASS: fully post-quantum mTLS (PQC KEM + PQC PKI).
```

**Scope/limits:** interop today is OpenSSL↔OpenSSL and OpenSSL↔rustls(unstable);
**Go cannot do ML-DSA certs until 1.27** (~Aug/Sep 2026). ML-DSA certs are large
and no public trust store has ML-DSA roots → private PKI only. This is why the
default posture (E2–E5) is **hybrid**: PQC KEM + classical auth.

---

## E8 — simple-network PQC channel · `cd channel && cargo run` *(PQC auth, today)*

**Proves BOTH properties, interoperably with our own tooling, TODAY:** an
app-layer channel (`simple_network::security::pqc`) over real TCP with hybrid
ML-KEM-768 + X25519 KEM and **ML-DSA-65 mutual authentication** against pinned
identities — the PQC-auth story that X.509 can't broadly give until 2027. Also
proves a wrong pinned key is rejected (MITM / impersonation defense).

```
$ cd channel && cargo run
ML-DSA-65 identities generated: server_vk=1952 B, client_vk=1952 B
  [server] opened record: "ping: hello over PQC channel"
PASS positive: mutual ML-DSA-65 auth + ML-KEM-768 channel; client opened "pong: authenticated with ML-DSA-65"
PASS negative: wrong server pin rejected -> peer identity does not match pinned key
```

The 1952-byte verifying key is the expected ML-DSA-65 public-key size (FIPS 204).

## Aggregate · `make test`

Runs E5–E8 with a pass/fail summary (all self-asserting):
```
PASS  E5 cross-language interop (Go/Rust/openssl, PQC KEM)
PASS  E6 PQC SSH to non-root sshd (mlkem768x25519)
PASS  E7 fully-PQC mTLS (ML-DSA-65 certs)
PASS  E8 simple-network PQC channel (ML-DSA-65 auth)
TOTAL: 4 passed, 0 failed
```

## Not yet run (need external infra)

- **E9 — multi-arch containers** (`scripts/docker-build.sh`, `go/Dockerfile`,
  `rust/Dockerfile`): the **Docker daemon was down** during development. Files
  are written and reviewed but unbuilt.
- **E10 — k3s PQC probe** (`scripts/k3s-probe.sh`, `docs/k3s-pqc.md`): needs a
  k3s/RKE2 cluster. Script + support-level analysis are written; unrun here.

## Summary

| # | Experiment | PQC KEM | PQC auth | Status |
|---|---|:---:|:---:|---|
| E2 | Go↔Go mTLS | ✅ | classical | PASS |
| E3 | Rust↔Rust mTLS | ✅ | classical | PASS |
| E4 | openssl positive/negative | ✅ | — | PASS |
| E5 | Go/Rust/openssl interop | ✅ | classical | PASS |
| E6 | SSH to non-root sshd | ✅ | classical | PASS |
| E7 | ML-DSA-65 mTLS (openssl) | ✅ | ✅ | PASS (experimental) |
| E8 | simple-network channel | ✅ | ✅ | PASS (app-layer, today) |
| E9 | multi-arch containers | — | — | not run (no Docker daemon) |
| E10 | k3s PQC probe | ✅* | ❌ | not run (no cluster) |
