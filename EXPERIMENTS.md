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
| amd64 | verified 2026-08-08 under emulation (E19) — no native amd64 silicon was tested |
| Cluster | k3s v1.36.2 (single container; two-node for E20) · Traefik 3.7.4 · Linkerd edge-26.8.1 · Istio 1.30.3 — see E16–E18 and [`docs/k3s-pqc.md`](docs/k3s-pqc.md) |
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

**Scope/limits:** interop today is OpenSSL↔OpenSSL and OpenSSL↔rustls(unstable)
— the rustls half is now demonstrated in **E15**. **Go cannot do ML-DSA certs
until 1.27** (~Aug/Sep 2026). ML-DSA certs are large and no public trust store
has ML-DSA roots → private PKI only. This is why the default posture (E2–E5) is
**hybrid**: PQC KEM + classical auth.

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

Runs E5–E8 + E15 with a pass/fail summary (all self-asserting):
```
PASS  E5 cross-language interop (Go/Rust/openssl, PQC KEM)
PASS  E6 PQC SSH to non-root sshd (mlkem768x25519)
PASS  E7 fully-PQC mTLS (ML-DSA-65 certs)
PASS  E8 simple-network PQC channel (ML-DSA-65 auth)
PASS  E15 fully-PQC mTLS in Rust + openssl interop
TOTAL: 5 passed, 0 failed
```

The container tracks (E10–E14) live in `scripts/docker-linux-verify.sh` —
`make linux-verify` — and need a Docker engine.

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

---

## E15 — fully post-quantum mTLS in **Rust** · `make mldsa-rust` *(Track 5, EXPERIMENTAL)*

**Proves BOTH properties in a second implementation.** E7 showed PQC PKI
openssl↔openssl, which is a single-implementation result; this adds rustls, so
ML-DSA-65 certificates are shown to be genuinely interoperable rather than one
library agreeing with itself. Hybrid `X25519MLKEM768` KEM **+** ML-DSA-65
mutual auth, TLS 1.3.

```
== [1] rust client -> rust server ==
OK  kex=X25519MLKEM768  auth=ML-DSA-65 (server cert verified)
{"ok":true,"impl":"rust-mldsa","kex":"X25519MLKEM768","tls":"1.3","auth":"ML-DSA-65","peer":"verified"}

== [2] openssl s_client -> rust server ==
Peer signature type: mldsa65
Negotiated TLS1.3 group: X25519MLKEM768
Verify return code: 0 (ok)

== [3] rust client -> openssl s_server ==
OK  kex=X25519MLKEM768  auth=ML-DSA-65 (server cert verified)

== [4] negative: classical-only client ==
  ...ssl/tls alert handshake failure...SSL alert number 40
== [4] negative: classical Ed25519 client cert (wrong PKI) ==
  conn 127.0.0.1:53073 error: tls accept: invalid peer certificate: UnknownIssuer

TOTAL: 5 passed, 0 failed
```

The same ML-DSA-65 certs from E7 (`certs-mldsa/`, generated by OpenSSL) are
loaded directly by rustls — the PKI is shared, only the TLS implementation
differs.

**How it works.** `rustls` 0.23 knows the ML-DSA codepoints (`0x0904`–`0x0906`)
but its stock aws-lc-rs provider can neither sign nor verify with them.
`rustls_post_quantum::provider()` (feature `aws-lc-rs-unstable`) swaps in a
`KeyProvider` backed by `aws_lc_rs::unstable::signature::PqdsaKeyPair` plus the
matching webpki verification algorithms. `rust-mldsa/src/lib.rs` then narrows
`kx_groups` to the hybrid PQC group, so **both** axes are mandatory.

**Why a separate crate:** `rust-mldsa/` is deliberately not part of `rust/`. The
unstable aws-lc-rs surface is expected to churn, and E2/E3/E5 must keep building
on stable rustls regardless.

**Assertion note:** the negative client-cert test reads the **server** log, not
the client's. Under TLS 1.3 the client finishes its side before the server
validates the client certificate, so `openssl s_client` exits reporting
`Verify return code: 0` (its own check of the *server* cert) and never sees the
rejection. Asserting client-side made a rejected connection look accepted.

**Limits:** unstable, pinned to `rustls-post-quantum` 0.2.4 (0.3.0-dev exists);
not FIPS-validated; Go still cannot participate until 1.27.

## E16 — Traefik ingress terminates PQC · `./scripts/k2-mesh-verify.sh 1` *(Track K2)*

**Proves:** KEM = post-quantum at the **cluster edge**, zero configuration. The
Ingress cert is a classical Ed25519 one — this is the KEM half only.

k3s v1.36.2 with its bundled Traefik **3.7.4**, a `whoami` backend behind a TLS
Ingress, reached over a real published port (servicelb binds `:443` on the node,
so this is not a `kubectl port-forward` tunnel).

```
$ ./scripts/k2-mesh-verify.sh 1
traefik image: rancher/mirrored-library-traefik:3.7.4
ingress :18443 -> X25519MLKEM768
backend response: HTTP/1.1 200 OK
PASS [1] traefik ingress terminated X25519MLKEM768, backend 200
```

The request is driven with `openssl s_client`, not `curl`: macOS system curl is
LibreSSL and has no PQC groups at all.

**Gotcha proven in testing:** Traefik answers **503** for a few seconds after
`kubectl rollout status` reports the backend rolled out — the Deployment is
ready before Traefik has observed its Endpoints. The script retries; asserting
on the first response makes this flake.

---

## E17 — Linkerd pod↔pod mTLS over a PQC KEM · `./scripts/k2-mesh-verify.sh 2` *(Track K2)*

**Proves:** KEM = post-quantum for **pod-to-pod mesh mTLS, on by default**.
Workload identity stays classical (Linkerd issues ECDSA P-256).

Linkerd `edge-26.8.1`. Two proofs, because they are different claims:

```
proxy tls_kx_groups : X25519MLKEM768,X25519,secp256r1,secp384r1,
proxy key provider  : AwsLcRs   (ring would mean no PQC at all)
outbound requests over mTLS: 34
ClientHello offered  : 0x11ec,0x001d,0x0017,0x0018
ServerHello selected : 4588  (want 4588 = 0x11EC = X25519MLKEM768)
PASS [2] linkerd pod<->pod mTLS negotiated X25519MLKEM768 (captured)
```

`rustls_info` reports what the proxy is **configured** to offer — PQC first, on
the aws-lc-rs provider. That is *not* the same claim as what the peers actually
**negotiated**, so the script also captures the handshake with `tcpdump` on the
proxy's port 4143 and reads the ServerHello's selected group. Per PLAN gotcha
\#1: assert the negotiated group, never assume it.

Note Linkerd **prefers** PQC but still offers X25519 and the NIST curves — a
classical-only peer would be accepted. Contrast E18.

**Gotcha proven in testing:** scraping `/metrics` right after the client pod
goes Ready reports `0` mTLS requests — `request_total` has no outbound series
until traffic has actually flowed. The metric is a lagging indicator, not a
readiness signal.

---

## E18 — Istio `COMPLIANCE_POLICY=pqc` enforces PQC · `./scripts/k2-mesh-verify.sh 3` *(Track K2)*

**Proves:** KEM = post-quantum **and enforced** — a classical-only peer cannot
connect at all. Istio 1.30.3, sidecar mode, `PeerAuthentication: STRICT`.
Istio calls this policy *experimental*.

```
istiod COMPLIANCE_POLICY=pqc
classical-only client (X25519)   -> REFUSED (alert 40)
PQC client (X25519MLKEM768)      -> X25519MLKEM768
mesh ClientHello offered  : 0x11ec   (pqc mode offers ONLY 0x11ec)
mesh ServerHello selected : 4588
PASS [3] istio pqc: mesh negotiated X25519MLKEM768, classical refused
```

**This is the sharp contrast with E17.** Linkerd offered four groups with PQC
first; Istio in `pqc` mode offers **exactly one**, so there is no classical
fallback to silently downgrade to. The negative test runs from an *unmeshed*
pod (`sidecar.istio.io/inject=false`) so it is a genuine outsider: a
classical-only `openssl s_client` gets `alert number 40`, and the same client
with `-groups X25519MLKEM768` completes the handshake. **The legacy client's
failure is the demo** — that is the whole point of the compliance policy.

**Two gotchas proven in testing:**
1. Istio redirects to the sidecar's `:15006` with iptables **inside** the
   destination pod, so on the wire the port is still the service port. Capturing
   `tcp port 15006` yields **zero packets**; capture port 80. (Linkerd differs —
   it uses an explicit `:4143` on the wire.)
2. tshark then dissects that traffic as HTTP and finds no TLS. It needs
   `-d tcp.port==80,tls` to decode it, or the handshake is invisible.

A cluster holds one mesh, so section [3] rebuilds the cluster rather than
layering Istio on top of Linkerd.

---

## E19 — the full suite on amd64 · `PLATFORM=linux/amd64 ./scripts/docker-linux-verify.sh 1`

**Proves:** every locally-verifiable experiment passes on **amd64**, not just
the arm64 the rest of this file was captured on.

```
-- versions --
OpenSSL 3.5.6 7 Apr 2026
OpenSSH_10.0p2 Debian-7+deb13u4
go version go1.26.5 linux/amd64
rustc 1.97.1 (8bab26f4f 2026-07-14)
...
PASS  E5 cross-language interop (Go/Rust/openssl, PQC KEM)
PASS  E6 PQC SSH to non-root sshd (mlkem768x25519)
PASS  E7 fully-PQC mTLS (ML-DSA-65 certs)
PASS  E8 simple-network PQC channel (ML-DSA-65 auth)
PASS  E15 fully-PQC mTLS in Rust + openssl interop
TOTAL: 5 passed, 0 failed
```

**Scope, stated plainly:** this is an amd64 *toolchain and binary* — `go1.26.5
linux/amd64`, an amd64 rustc, amd64 OpenSSL — executed under emulation on Apple
Silicon. It covers the architecture dimension of the **code**. It is **not**
native amd64 silicon, so anything hardware-specific (AES-NI/AVX2 paths inside
aws-lc-rs, real timing) is still untested. A physical amd64 box remains the one
genuinely untested axis.

---

## E20 — two-node k3s: cross-node control plane · `./scripts/k1-multinode-verify.sh` *(Track K1)*

**Proves:** KEM = post-quantum on **every control-plane endpoint of a real
two-node cluster**, including a kubelet on a *different* node from the
apiserver, and both etcd ports. Zero configuration. PKI stays classical.

Every other k3s result in this repo is a single container, which never puts
cross-node traffic on the wire. This runs `server` + `agent` on their own docker
network with **embedded etcd** (`--cluster-init`) and probes from a third
container:

```
$ ./scripts/k1-multinode-verify.sh
NAME      STATUS   ROLES                AGE   VERSION
agent0    Ready    <none>               6s    v1.36.2+k3s1
server0   Ready    control-plane,etcd   18s   v1.36.2+k3s1

probe openssl: OpenSSL 3.5.7 9 Jun 2026
pqc-k3s-server:6443        -> X25519MLKEM768     # kube-apiserver
pqc-k3s-server:10250       -> X25519MLKEM768     # kubelet, control-plane node
pqc-k3s-agent:10250        -> X25519MLKEM768     # kubelet, WORKER node
pqc-k3s-server:2379        -> X25519MLKEM768     # etcd client
pqc-k3s-server:2380        -> X25519MLKEM768     # etcd peer

PASS multi-node: all 5 endpoints negotiated X25519MLKEM768 (5/5)
```

`pqc-k3s-agent:10250` is the cross-node leg — a kubelet on a different node,
reached over the container network. This is the endpoint set PLAN Track K1 named.

**Worth knowing:** `:2379`/`:2380` exist **only because of `--cluster-init`**. A
default single-server k3s uses sqlite and has no etcd listener at all, so an
etcd probe against a stock k3s isn't a failure — there is nothing listening.

**Scope:** control plane only. Cross-node *pod* traffic is encapsulated in
flannel VXLAN, so proving mesh mTLS between pods on different nodes needs the
capture taken inside the tunnel — not done here.

---

## Not yet run

- **Native amd64 hardware** — E19 covers the amd64 toolchain under emulation;
  real silicon is untested (no such machine available here).
- **Cross-node pod-to-pod mesh traffic** — E20 covers the multi-node *control*
  plane; E17/E18 proved mesh mTLS but on a single node. Pod traffic between
  nodes rides flannel VXLAN and would need the capture taken inside the tunnel.
- **Track S1 (Secretive)** — needs an interactive Touch ID tap, so it cannot be
  scripted; the recipe is in E6.

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
| E15 | ML-DSA-65 mTLS in Rust + openssl interop | ✅ | ✅ | PASS (experimental, Track 5) |
| E16 | Traefik 3.7.4 PQC ingress termination | ✅ | ❌ | PASS (Track K2) |
| E17 | Linkerd pod↔pod mTLS (PQC preferred) | ✅ | ❌ | PASS (Track K2) |
| E18 | Istio `COMPLIANCE_POLICY=pqc` (PQC enforced) | ✅ | ❌ | PASS (experimental, Track K2) |
| E19 | full suite on amd64 (emulated) | ✅ | ✅ | PASS |
| E20 | two-node k3s control plane (5 endpoints) | ✅ | ❌ | PASS (Track K1) |
