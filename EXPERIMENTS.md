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
| Linux | verified 2026-08-01 in containers on the same host (Debian 13 / Debian sid, arm64) — see E10–E12 and [`docs/linux-support.md`](docs/linux-support.md) |
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

---

## E10 — k3s control-plane PQC KEM · `scripts/docker-linux-verify.sh 2` *(Track K1)*

**Proves:** KEM = post-quantum on a **real kube-apiserver, with zero
configuration** — it rides the Go toolchain. Auth stays classical (the cluster
CA is ECDSA P-256; no orchestrator issues PQC certs yet).

```
### [2] k3s (rancher/k3s) apiserver PQC KEM probe
waiting for apiserver :6443 ...
kube-apiserver :6443 -> X25519MLKEM768
PASS [2] k3s apiserver negotiated X25519MLKEM768
```

`rancher/k3s:v1.36.2-k3s1`, single node in Docker, `--disable=traefik,servicelb,metrics-server`,
probed from the host with OpenSSL 3.6.3 `s_client -groups X25519MLKEM768`.
**Version matters:** an earlier pin of v1.31.5 (Go 1.22, pre-dating the Go 1.24
PQC default) would report a false negative. Traefik ingress and Linkerd
(Track K2) remain unrun.

---

## E11 — full suite on Linux · `scripts/docker-linux-verify.sh 1` *(task #12)*

**Proves:** E5–E8 reproduce on **Debian 13 (trixie), arm64** — i.e. none of the
macOS results depend on macOS. Debian 13 ships OpenSSL 3.5.6 and OpenSSH 10.0p2,
so the ML-DSA cert track and the mlkem SSH KEX work on **stock distro packages**.

```
-- versions --
OpenSSL 3.5.6 7 Apr 2026 (Library: OpenSSL 3.5.6 7 Apr 2026)
OpenSSH_10.0p2 Debian-7+deb13u4, OpenSSL 3.5.6 7 Apr 2026
go version go1.26.5 linux/arm64
rustc 1.97.1 (8bab26f4f 2026-07-14)
...
PASS  E5 cross-language interop (Go/Rust/openssl, PQC KEM)
PASS  E6 PQC SSH to non-root sshd (mlkem768x25519)
PASS  E7 fully-PQC mTLS (ML-DSA-65 certs)
PASS  E8 simple-network PQC channel (ML-DSA-65 auth)
TOTAL: 4 passed, 0 failed
```

**Toolchain caveat found here:** `go.mod` requires **Go ≥ 1.26**, but Debian 13
packages 1.24 — the harness installs the upstream Go tarball. Distro Go is *not*
sufficient for this repo even though 1.24 is enough for the PQC KEM itself.

---

## E12 — experimental ML-DSA SSH auth on Linux · `scripts/docker-linux-verify.sh 3` *(Track S4)*

**Proves BOTH properties for SSH:** KEM = `mlkem768x25519-sha256` **and** host +
user auth = **ML-DSA-44 composite** (`ssh-mldsa44-ed25519@openssh.com`) — the
classical-auth gap in SSH closing. Debian sid, OpenSSH 10.4p1.

```
OpenSSH_10.4p1 Debian-4, OpenSSL 3.6.3 9 Jun 2026
-- client output --
S4_OK
debug1: kex: algorithm: mlkem768x25519-sha256
debug1: Server host key: ssh-mldsa44-ed25519@openssh.com SHA256:RKvwcyfmuI6JwQIkTmNnRNyVRPJGvU9j3AdP4349dXE
PASS [3] sid mldsa44-ed25519 SSH (PQC KEX + PQC auth)
```

**Naming gotcha:** the algorithm is `ssh-mldsa44-ed25519@openssh.com`. The bare
`ssh-mldsa44-ed25519` is accepted by `ssh-keygen -t` but **rejected** by
`HostKeyAlgorithms` / `PubkeyAcceptedAlgorithms` (`Bad key types`) — and because
`sshd -E` diverts config errors into the logfile, that failure is silent unless
the log is dumped. Composite = hybrid: an ed25519 signature alongside the ML-DSA
one, so a break in the young primitive doesn't drop you below classical security.
**Experimental:** sid/10.4 only; no LTS ships this.

---

## E9 — containerized endpoints · `scripts/docker-build.sh` *(Track 6)*

**Proves:** the PQC mTLS endpoints keep both properties **inside containers** —
distroless Go (9.7 MB) and Debian-slim Rust (32 MB), certs mounted at runtime.
Not just "the image builds": every server was handshaked against.

Host `openssl s_client` (3.6.3) → each containerized server:
```
--- host openssl -> 127.0.0.1:18443 (go) ---     --- 127.0.0.1:19443 (rust) ---
Negotiated TLS1.3 group: X25519MLKEM768          Negotiated TLS1.3 group: X25519MLKEM768
Protocol: TLSv1.3                                Protocol: TLSv1.3
Verify return code: 0 (ok)                       Verify return code: 0 (ok)
```

Container→container, all four client/server pairs (clients run in a shared
network namespace so the `CN=localhost` cert still verifies):
```
go client  -> go server      "kex":"X25519MLKEM768 (0x11ec)"
rust client-> go server      "kex":"X25519MLKEM768 (0x11ec)"
go client  -> rust server    "kex":"X25519MLKEM768"
rust client-> rust server    "kex":"X25519MLKEM768"
```

Server-side, mutual auth confirmed (not just the KEM):
```
go PQC mTLS server on :8443  (require X25519MLKEM768 (0x11ec))
served [::1]:58266  kex=X25519MLKEM768 (0x11ec)  peer_cn=demo-client
rust PQC mTLS server on 0.0.0.0:9443  (require X25519MLKEM768)
served  kex=X25519MLKEM768  peer=verified
```

### Both architectures

`PLATFORMS=linux/amd64,linux/arm64 ./scripts/docker-build.sh` builds cleanly for
both. The **amd64** images also run here under emulation and negotiate PQC:

```
--- amd64 container on :28443 (go) ---     --- :29443 (rust) ---
Negotiated TLS1.3 group: X25519MLKEM768    Negotiated TLS1.3 group: X25519MLKEM768
Verify return code: 0 (ok)                 Verify return code: 0 (ok)
served  kex=X25519MLKEM768  peer=verified
```

| | arm64 | amd64 |
|---|---|---|
| go image | 9.7 MB (distroless) | 10.5 MB |
| rust image | 31.8 MB (debian-slim) | 32.1 MB |
| built | ✅ | ✅ |
| handshake verified | ✅ native | ✅ **emulated** |

Build notes: `docker buildx` cannot `--load` a multi-platform manifest, so each
arch was loaded separately (`--platform linux/amd64 --load`, instant from cache)
to run it. Go cross-compiles from the build platform (`--platform=$BUILDPLATFORM`
+ `GOARCH`); the Rust stage has no such pin, so the foreign arch compiles
aws-lc-rs under emulation — ~59 s here, the bulk of the build. **Caveat:** amd64
was exercised under emulation on an arm64 host, which is not the same as a real
amd64 machine.

---

## E13 — legacy-LTS reality check · `scripts/docker-linux-verify.sh 4` *(Track S3)*

**Proves the negative**, which matters as much as the positives: on the LTS
releases most fleets actually run, `mlkem` and ML-DSA are simply **not there** —
but the pre-standard `sntrup761x25519-sha512@openssh.com` still gives
harvest-now-decrypt-later resistance. Ubuntu 24.04 is supported to **2029**, so
this is the migration reality, not a historical footnote.

```
-- ubuntu:24.04 --
OpenSSH_9.6p1 Ubuntu-3ubuntu13.18, OpenSSL 3.0.13 30 Jan 2024
confirmed: no mlkem768x25519-sha256
confirmed: no X25519MLKEM768 in openssl
S3_OK
debug1: kex: algorithm: sntrup761x25519-sha512@openssh.com

-- debian:12 --
OpenSSH_9.2p1 Debian-2+deb12u10, OpenSSL 3.0.20 7 Apr 2026
confirmed: no mlkem768x25519-sha256
confirmed: no X25519MLKEM768 in openssl
S3_OK
debug1: kex: algorithm: sntrup761x25519-sha512@openssh.com
```

The check **fails loudly if a future image gains mlkem** ("docs need updating"),
so it doubles as a tripwire on the version matrix rather than silently passing.
Reproduce the fallback on such a host with:
```
KEX=sntrup761x25519-sha512@openssh.com ./scripts/ssh-pqc-demo.sh
```

---

## E14 — cross-platform SSH, both arches · `scripts/docker-linux-verify.sh 6` *(Track S2)*

**Proves:** this machine's **own** ssh client (OpenSSH 10.2p1, macOS) reaching a
Debian 13 sshd over PQC KEX — on **linux/arm64 and linux/amd64**. E6 was
mac→mac and E11 was linux→linux; this is the mac→linux leg that a real fleet
looks like.

```
### host ssh -> debian:13 sshd (linux/arm64)     ### (linux/amd64)
S2_OK                                            S2_OK
Linux aarch64                                    Linux x86_64
debug1: kex: algorithm: mlkem768x25519-sha256    debug1: kex: algorithm: mlkem768x25519-sha256
```

Auth is classical ed25519; the KEX is pinned so a classical fallback cannot
happen silently. The generated key is left in `ssh-demo-s2/` so the **Secretive**
variant (Track S1) can be run by hand: append `ssh-add -L` output to the
container's `authorized_keys` and connect without `-i`, and Touch ID gates the
signature inside the Secure Enclave. That step is interactive and stays manual.

**amd64 caveat:** emulated on an arm64 host, as with E9 — not real hardware.

## Not yet run (need external infra)

- **Track K2 (mesh)** — Linkerd/Istio on k3s, and Traefik PQC ingress
  termination: not attempted.
- **Native (non-container) Linux and amd64:** E10–E12 ran in containers on an
  arm64 macOS host. Kernel-independent by nature, but a real amd64 box is
  untested.

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
| E9 | multi-arch containers (arm64+amd64) | ✅ | classical | PASS |
| E10 | k3s apiserver probe (v1.36.2) | ✅ | ❌ | PASS (Track K1) |
| E11 | full suite on Debian 13 arm64 | ✅ | ✅ | PASS (task #12) |
| E12 | ML-DSA SSH auth, Debian sid | ✅ | ✅ | PASS (experimental, Track S4) |
| E13 | legacy LTS (Ubuntu 24.04, Debian 12) | ⚠️ sntrup761 only | ❌ | PASS (Track S3) |
| E14 | mac→linux SSH, arm64 + amd64 | ✅ | classical | PASS (Track S2) |
