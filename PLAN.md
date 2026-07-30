# simple-pqc — PQC Demo Roadmap

*Prepared 2026-07-29. Two Fable 5 research agents, web-verified against live sources
and smoke-tested on this Mac (macOS 26 Tahoe, Apple Silicon).*

Scope: demoable **HTTPS-with-PQC** and **SSH-with-PQC**, doing **mTLS + PQC**, with
**hybrid PQC/ECC** as the default posture. Rust + Go client/servers, plus SSH/sshd
run as a local user, across linux arm64 / amd64 (Ubuntu/Debian) and mac silicon.
Plus a support-level verdict for k3s / Rancher / RKE2.

---

## 0. The one distinction that governs everything: **KEM vs PKI**

Every "PQC" claim is one of two things. Each demo track below **names which it gives you.**

| Property | What it is | What it protects against | 2026 status |
|---|---|---|---|
| **PQC KEM / KEX** | Hybrid **X25519 + ML-KEM-768** key exchange (TLS group `0x11EC` / SSH `mlkem768x25519-sha256`) | **Harvest-now-decrypt-later** — recorded traffic can't be decrypted by a future quantum computer | **On by default nearly everywhere.** The demo's job is to *prove* it, not enable it. |
| **PQC auth / PKI** | **ML-DSA** (Dilithium) signatures in the X.509 chain, or SSH host/user keys | **Quantum MITM / identity forgery** — a quantum attacker can't forge a signature to impersonate a peer | **Mostly experimental / 2027.** Real today only in: OpenSSL 3.5+, rustls-unstable, OpenSSH 10.4 (composite), Secretive Enclave (non-interoperable), and **simple-network's app-layer ML-DSA-65 channel**. |

**Hybrid PQC/ECC** = the correct default for both: hybrid KEM (X25519+ML-KEM) and,
where PQC auth is used, hybrid signatures (e.g. `mldsa44-ed25519`) so a flaw in the
young PQC primitive doesn't sink you below classical security.

> ⚠️ **Local toolchain correction:** your PATH `openssl` (3.0.17) is **miniconda's** and
> `/usr/bin/openssl` is **LibreSSL**. The real PQC-capable one is Homebrew's
> **`/opt/homebrew/bin/openssl` = 3.6.3** (full ML-KEM + ML-DSA, verified). Pin the
> absolute path in every script.

---

## 1. Unified support-level matrix (verified July 2026)

### TLS / HTTPS / mTLS stack

| Component | PQC **KEM** (X25519MLKEM768) | PQC **auth** (ML-DSA certs) | Verdict | How |
|---|---|---|---|---|
| **Go crypto/tls** (you have 1.26.2) | ✅ default since 1.24; 1.26 adds SecP256r1MLKEM768 | ❌ `crypto/mldsa` + x509/TLS **accepted for Go 1.27** (~Feb 2027) | **KEM today** | `CurvePreferences: []tls.CurveID{tls.X25519MLKEM768}`; verify `ConnectionState.CurveID == 4588` (1.25+) |
| **rustls 0.23.42** (aws-lc-rs) | ✅ default + preferred since 0.23.27 | ⚠️ **experimental** ML-DSA-44/65/87 via `aws-lc-rs-unstable` + rustls-post-quantum 0.2.4 | **KEM today; auth experimental** | default features already include `prefer-post-quantum`; **`ring` provider = zero PQC** |
| **OpenSSL 3.5 LTS / 3.6.3** | ✅ default+preferred since 3.5.0 | ✅ **native** ML-DSA keygen/req/x509/TLS (verified locally) | **Both today** | `/opt/homebrew/bin/openssl genpkey -algorithm ML-DSA-65`; `s_client -groups X25519MLKEM768` |
| **BoringSSL / Chrome** | ✅ default since Chrome 131 (>30% of TLS1.3 handshakes) | ⚠️ codepoints only; no browser negotiates ML-DSA certs | interop target | — |

### SSH stack

| Component | PQC **KEM/KEX** | PQC **auth** | Verdict | How |
|---|---|---|---|---|
| **OpenSSH 10.x** (this Mac: 10.2p1 system) | ✅ `mlkem768x25519-sha256`, **default since 10.0** | ⚠️ `mldsa44-ed25519` composite host+user keys, **experimental, OpenSSH 10.4** (off by default) | **KEM today; auth experimental (10.4)** | `-o KexAlgorithms=mlkem768x25519-sha256`; `ssh-keygen -t mldsa44-ed25519` (10.4) |
| **OpenSSH ≤9.6** (Ubuntu 24.04 LTS, Debian 12) | ⚠️ `sntrup761x25519-sha512@openssh.com` only (pre-standard PQC) | ❌ | KEM (legacy PQC) | pin `sntrup761...`; `mlkem` will fail to negotiate |
| **Secretive 3.0.x** (installed) | n/a (KEX is ssh's) | ⚠️ Enclave **ECDSA P-256** (interoperable) **or** Enclave **ML-DSA-65/87** on Tahoe (draft-sfluhrer wire format → **no OpenSSH server accepts it**) | **classical auth today; PQC-auth = frontier/non-interop** | `ssh-add -L`; P-256 key composes with PQC KEX |

### k3s / Rancher / RKE2 / mesh

| Layer | PQC **KEM** | PQC **auth** | Verdict |
|---|---|---|---|
| **Kubernetes core ≥1.33** (apiserver↔kubelet↔etcd↔kubectl) | ✅ default via Go 1.24+ | ❌ | **Works today, for free** (k8s blog 2025-07-18) |
| **k3s / RKE2 v1.36.2** (Go 1.25/1.26) | ✅ default, zero config | ❌ dynamiclistener CA = ECDSA P-256, no PQC plans | **KEM today, zero config** |
| **etcd** (current 3.5/3.6 patches) | ✅ (Go 1.25.x) | ❌ | KEM on current patches (3.6.0 was Go 1.23 = draft only) |
| **Traefik ≥3.5** (k3s bundles 3.6.10) | ✅ default | ❌ | **Works today** — k3s default ingress terminates PQC out of the box |
| **Caddy ≥2.10** | ✅ default | ❌ | Works today |
| **ingress-nginx** | ✅ (last v1.15.1) | ❌ | **DEAD — retired 2026-03-24, no CVE fixes.** Don't build on it |
| **cert-manager** | n/a | ❌ RSA/ECDSA/Ed25519 only (ML-DSA = issue #8929, blocked on Go 1.27) | **Not yet** |
| **Linkerd 2.19** (rustls/aws-lc) | ✅ **default on** for all pod↔pod mTLS | ❌ | **Works today, on by default** — only mesh with default PQC; provable via `rustls_info` metrics |
| **Istio 1.27 / Envoy** | ⚠️ opt-in `COMPLIANCE_POLICY=pqc` (set in pilot **and** ztunnel) | ❌ (Envoy ML-DSA cert bump: not-planned) | Works, needs config; failure of legacy client = the demo |
| **Cilium / WireGuard** | ❌ Curve25519 (Rosenpass unintegrated) | ❌ | Skip |

**Two headline verdicts:**
1. **PQC KEM is a today-thing across the entire stack** — TLS, SSH, and k3s control+data plane. The work is *proving/asserting* it, defending against silent classical downgrade.
2. **PQC auth (PKI) is demoable today only in OpenSSL + rustls-unstable + OpenSSH-10.4-experimental.** For a *genuinely PQC-authenticated, interoperable-with-our-own-tooling* story **now**, **simple-network's ML-DSA-65 pinned-identity channel is the answer** — it does what X.509 PQC auth won't broadly do until 2027.

---

## 2. HTTPS / mTLS + PQC — demo tracks (Rust, Go, interop)

**Track 0 — Toolchain + proof harness** (~0.5 day) · *proves: KEM*
Fix the openssl PATH shadowing. Build `scripts/prove-pqc.sh`:
(1) `/opt/homebrew/bin/openssl s_client -groups X25519MLKEM768` → grep `Negotiated TLS1.3 group`;
(2) `SSLKEYLOGFILE` + tshark filter on `supported_groups` containing `0x11EC` (4588);
(3) negative test `-groups X25519` to demonstrate downgrade detection.
Reused by every later track.

**Track 1 — Go ↔ Go PQC mTLS** (~0.5–1 day) · *proves: KEM (hybrid ECC/PQC), classical auth*
Classical Ed25519 mini-CA + client/server certs; `tls.Config` pins `CurvePreferences =
[X25519MLKEM768]` + `RequireAndVerifyClientCert`; both sides log `ConnectionState.CurveID`
and **refuse** if it isn't 4588. Villain demo: `GODEBUG=tlsmlkem=0` = the silent downgrade.

**Track 2 — Rust ↔ Rust PQC mTLS** (~1 day) · *proves: KEM (hybrid ECC/PQC), classical auth*
rustls 0.23.42 + aws-lc-rs (X25519MLKEM768 preferred by default) + tokio-rustls 0.26.
Reuse `simple-network/src/transport/tls.rs` shape (configs are injected → drops in). rcgen
≥0.14.8 for the classical CA. Log `negotiated_key_exchange_group()`, hard-fail if non-PQ.
Gotcha to encode: `ring` provider = zero PQC.

**Track 3 — Cross-language interop matrix** (~0.5 day) · *proves: KEM, the money slide*
Rust-server↔Go-client, Go-server↔Rust-client, + `openssl s_client` (3.6.3) against both.
One `interop.sh` printing a 3×3 matrix of negotiated groups.

**Track 5 — Experimental ML-DSA-65 mTLS** (~2–3 days) · *proves: **PQC PKI auth** (Rust + OpenSSL only)*
CA recipe (verified locally): `openssl genpkey -algorithm ML-DSA-65` → self-signed root →
issue server/client certs. Rust endpoints with `aws-lc-rs-unstable` + rustls-post-quantum
0.2.4 (sig schemes 0x0904–0x0906, RFC 9881 certs); interop vs `openssl s_client/s_server`.
Label **EXPERIMENTAL**. Go participates only as a KEM-side observer (auth waits for 1.27).

---

## 3. SSH + PQC — demo tracks

**Track S0 — "PQC by default"** (5 min, zero setup) · *proves: KEM, classical auth*
System ssh (10.2p1) ↔ a non-root sshd on :2222. Show `ssh -Q kex`, pin
`mlkem768x25519-sha256`, and the OpenSSH 10.1+ weak-crypto warning on a classical KEX.
*Smoke-tested end-to-end on this Mac today.*

Non-root sshd recipe (verified working):
```bash
D=~/pqc-sshd-demo && mkdir -p $D && chmod 700 $D && cd $D
ssh-keygen -q -t ed25519 -N '' -f host_ed25519
cat > sshd_config <<EOF
Port 2222
ListenAddress 127.0.0.1
HostKey $D/host_ed25519
PidFile $D/sshd.pid
AuthorizedKeysFile $D/authorized_keys
KexAlgorithms mlkem768x25519-sha256
PasswordAuthentication no
UsePAM no
LogLevel VERBOSE
EOF
/usr/sbin/sshd -f $D/sshd_config -E $D/sshd.log     # linux: $(which sshd)
ssh -p 2222 -o KexAlgorithms=mlkem768x25519-sha256 -vv 127.0.0.1 true 2>&1 | grep 'kex: algorithm'
# → debug1: kex: algorithm: mlkem768x25519-sha256
```
Gotchas: absolute paths for binary+config; non-root = pubkey-only; **StrictModes** silently
fails auth on loose perms; high ports only.

**Track S1 — Secretive Enclave auth + PQC KEX (mac→mac)** (headline) · *proves: KEM (PQC) + hardware-gated classical auth*
Secretive P-256 key (Secure Enclave, Touch-ID) authenticates over `mlkem768x25519` KEX to
the local sshd. `ssh-add -L` → append to `authorized_keys` → connect. Proof: Touch ID fires
(sign inside Enclave) + client log shows the PQC KEX + `Authenticated ... publickey`.
mac→linux is identical (Secretive is agent-side only).

**Track S2 — Cross-platform matrix** (~0.5 day) · *proves: KEM*
mac client (Secretive) → Docker `ubuntu:26.04` arm64 **and** `--platform linux/amd64`
sshd, PQC-only KEX + Enclave auth. Covers both linux targets from the laptop.

**Track S3 — Legacy reality check** · *proves: KEM (legacy PQC)*
Same client → `ubuntu:24.04` / `debian:12`: `mlkem` negotiation **fails**, fall back to
`sntrup761x25519-sha512@openssh.com`. The migration story (Ubuntu 24.04 LTS is supported to 2029).

**Track S4 — Experimental full-PQC SSH (KEX + auth)** (~1 day) · *proves: KEM + **PQC PKI auth***
`brew install openssh` (10.4p1) both ends. `ssh-keygen -t mldsa44-ed25519` host+user keys;
`HostKeyAlgorithms/PubkeyAcceptedAlgorithms +mldsa44-ed25519`. File-key based, no Enclave.
Linux end: Debian unstable 10.4p1 or build from source. "The classical-auth gap is closing."

**Track S5 — Frontier (show, can't interop)** · *proves: **PQC PKI auth** in hardware*
Create an ML-DSA-65 key in Secretive on Tahoe → `ssh-add -L` shows `ssh-mldsa-65` from the
**Secure Enclave** → explain the draft split (sfluhrer *pure* vs OpenSSH's *composite*) means
no server accepts it yet. Closing slide: Enclave PQ auth is hardware-ready, waiting on IETF.

---

## 4. k3s / Rancher / RKE2 PQC-ization

**Track K1 — k3s PQC demo** (~1–2 days) · *proves: KEM across control + data plane, zero config*
Current **k3s v1.36.2** on a linux arm64 + amd64 VM pair. With **zero configuration**, use the
Track-0 harness to show apiserver (6443), kubelet (10250), etcd (2379/2380, `--cluster-init`)
all negotiating X25519MLKEM768; then bundled **Traefik 3.6.10** terminating PQC for an Ingress
(classical cert); deploy Track-6 images as in-cluster PQC mTLS workloads.
Verdict slide: *"control-plane + data-plane KEX is PQC by toolchain; certs remain ECDSA P-256."*

**Track K2 — Service mesh add-on** (~1–2 days, optional) · *proves: KEM (default vs enforced)*
**Linkerd 2.19** on k3s: PQC pod↔pod mTLS **by default**, proven via its TLS-algorithm
Prometheus metrics (no packet capture). Stretch: **Istio 1.27** `COMPLIANCE_POLICY=pqc` where a
legacy client's handshake *failure* is the demo.

**Rancher-level note:** Rancher/RKE2 inherit the same Go-toolchain KEM story. **RKE2
FIPS/BoringCrypto** builds offering X25519MLKEM768 is **unverified** — don't promise PQC on
FIPS RKE2 without testing. No orchestrator issues PQC certs yet (cert-manager blocked on Go 1.27).

---

## 5. App-layer PQC-auth that works **today**: simple-network + simple-remote

**Track 4 — Package the simple-network PQC channel** (~0.5–1 day) · *proves: **KEM + PQC ML-DSA-65 mutual auth** — the real thing, today*
`simple-network/src/security/pqc.rs` already does: ML-KEM-768+X25519 KEM, **ML-DSA-65 mutual
auth** (which TLS PKI can't broadly do until 2027), pinned-identity pairing
(`src/security/pairing.rs`), and `simple-remote` capability-scoped exec on top.
Position explicitly: *"X.509 PQC auth is 2027; pinned PQC identity is now."*

**SSH vs simple-remote:** complementary, not competing. SSH = interoperable industry baseline
(PQC KEX, classical auth, full shell). simple-remote = opinionated alternative (PQC channel +
ML-DSA identity + capability scoping SSH lacks natively). Demo angles: (a) side-by-side PQC-SSH
vs `simple-remote client exec` contrasting all-or-nothing-shell vs capability-scoped; (b) run
simple-remote over an SSH tunnel = double PQC / defense-in-depth.

---

## 6. Cross-cutting: containers + platforms

**Track 6 — Multi-arch containers** (~1 day)
`docker buildx` linux/arm64 + amd64. Go: trivial static builds. Rust: aws-lc-rs needs
cmake/clang in the builder stage per arch (cross-compile friction). Debian bookworm/trixie
runtime; ship an `openssl-pqc` verifier sidecar on **Alpine 3.22+** (OpenSSL 3.5.7) so the
proof harness runs in-cluster. arm64 native on the Mac; amd64 via `--platform` (Rosetta) or a
real VPS for the stretch leg.

---

## 7. Gotchas (encode these into demos, don't hand-wave)

1. **Silent classical downgrade is THE failure mode.** Every demo must *assert* the negotiated
   group/KEX, never assume it. Mixed Go 1.23/1.24 fleets share no PQC group at all.
2. **ClientHello fragmentation** (~1.2 KB ML-KEM keyshare) breaks some middleboxes and Traefik
   TCP `HostSNI` routers — test through real network paths, not just localhost.
3. **PATH hazards (Mac):** miniconda openssl 3.0.17 shadows Homebrew 3.6.3; `/usr/bin/openssl`
   is LibreSSL. Absolute paths only.
4. **rustls PQC is aws-lc-rs only** (`ring` = none); ML-DSA needs `aws-lc-rs-unstable` (API may
   churn); rcgen <0.14.8 emitted wrong ML-DSA OIDs.
5. **simple-network's `ml-dsa` crate is 0.0.4** — pre-1.0, unaudited, not FIPS-validated. Fine
   for demos; flag for production.
6. **ML-DSA certs are ~12× larger / slower**; no public trust store has ML-DSA roots →
   private-PKI only.
7. **SSH KEX ≠ auth.** Today's deployable PQC property in default SSH is HNDL-resistance in the
   KEX; host + user auth stays classical everywhere by default. Say it explicitly.
8. **StrictModes / non-root sshd** perms silently fail auth (hit + fixed in testing).
9. **Ubuntu 24.04 LTS can't do mlkem** (only sntrup761) — expect this in real fleets to 2029.
10. **Secretive ML-DSA is non-interoperable** (draft-sfluhrer vs OpenSSH composite) — it's real
    Enclave PQC auth with no server to talk to yet.

---

## 8. Sequencing & effort

| Phase | Tracks | Property proven | Effort |
|---|---|---|---|
| **Core mTLS matrix** (fastest win) | 0, 1, 2, 3 | PQC **KEM**, hybrid ECC/PQC, classical auth | **~2–3 days** |
| **SSH, today** | S0, S1 (headline), S2, S3 | PQC **KEM** + Enclave-gated classical auth | ~1–1.5 days |
| **App-layer PQC auth, today** | 4 | **KEM + ML-DSA-65 mutual auth** | ~0.5–1 day |
| **k3s / Rancher** | 6, K1 (+ K2 optional) | PQC **KEM** across cluster | ~2–4 days |
| **Experimental PQC PKI** | 5 (TLS), S4 (SSH), S5 (frontier) | **PQC auth / PKI** | ~3–5 days |

**Recommended demo order:** 0 → 1 → 2 → 3 (the matrix) → S0 → S1 → 4 → K1, then the
experimental PQC-PKI tracks (5, S4, S5) as the "where it's going" finale.

Rough total: **~7–10 focused days** for the core through k3s; experimental PQC-auth adds
~3–5 more.

---

## Sources (checked 2026-07-29)
- OpenSSH PQ: openssh.org/pq.html · release notes 9.9 (mlkem intro), 10.0 (mlkem default), 10.1 (WarnWeakCrypto), **10.4 (mldsa44-ed25519, 2026-07-06)**
- TLS hybrid KEX: draft-ietf-tls-ecdhe-mlkem-05 (RFC-Ed queue); ML-DSA-in-X.509 = **RFC 9881** (Oct 2025); TLS ML-DSA sig codepoints 0x0904–0x0906
- Go: X25519MLKEM768 default since 1.24; `crypto/mldsa` accepted for **1.27** (golang/go#77626, #78888)
- rustls: PQC default+preferred since 0.23.27; ML-DSA via aws-lc-rs-unstable + rustls-post-quantum 0.2.4; latest 0.23.42
- OpenSSL 3.5.0 LTS (2025-04-08) native ML-KEM/ML-DSA; Homebrew `openssl@3` = 3.6.3
- k8s PQC: kubernetes.io/blog/2025/07/18/pqc-in-k8s/ · k3s v1.36.2 · Traefik ≥3.5 · Linkerd 2.19 · Istio 1.27 `COMPLIANCE_POLICY=pqc` · ingress-nginx EOL 2026-03-24 · cert-manager #8929
- Secretive 3.0.x (Enclave ML-DSA-65/87 on Tahoe, draft-sfluhrer wire format)
