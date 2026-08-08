# simple-pqc

Runnable demos of **post-quantum cryptography** in transport security: HTTPS /
mTLS with a post-quantum KEM, in Rust and Go, plus PQC SSH. See
[`PLAN.md`](PLAN.md) for the full roadmap and support-level analysis.

## The one distinction that matters

Every "PQC" claim is one of two things — each demo says which:

| Property | Mechanism | Protects against | Status (2026) |
|---|---|---|---|
| **PQC KEM / KEX** | hybrid **X25519 + ML-KEM-768** (`0x11EC`) | harvest-now-decrypt-later | **default nearly everywhere** |
| **PQC auth / PKI** | **ML-DSA** signatures in certs / SSH keys | quantum MITM / forgery | mostly experimental → 2027 |

**Hybrid PQC/ECC** = the correct posture: PQC KEM for confidentiality, classical
(Ed25519/ECDSA) auth for interoperable identity today.

## What's implemented (Tracks 0–3): HTTPS/mTLS with a PQC KEM

- **KEM: post-quantum** — TLS 1.3 pinned to `X25519MLKEM768`; endpoints **refuse**
  any classical key exchange (no silent downgrade).
- **Auth: classical** — Ed25519 mutual-TLS against a demo CA (the interoperable
  "hybrid ECC/PQC" baseline). PQC *PKI* (ML-DSA certs) is a later track.

```
make interop      # build all, run the cross-language matrix, assert PQC everywhere
```
Expected:
```
client \ server  | go (:8443)         | rust (:9443)
-----------------+--------------------+-------------------
go               | X25519MLKEM768     | X25519MLKEM768
rust             | X25519MLKEM768     | X25519MLKEM768
openssl          | X25519MLKEM768     | X25519MLKEM768
PASS: all pairs negotiated X25519MLKEM768 (PQC KEM).
```

### Other targets
```
make certs        # Track 0: Ed25519 mini-CA + server/client certs
make run-go       # Go server + Go client, one round trip
make run-rust     # Rust server + Rust client, one round trip
make prove PORT=8443       # openssl proves PQC KEM is negotiated
make prove-neg PORT=8443   # openssl proves a classical-only client is refused
make ssh          # Track S: PQC SSH KEX to a non-root sshd (+ Secretive recipe)
make mldsa        # Track 5 (experimental): fully-PQC mTLS with ML-DSA-65 certs
make mldsa-rust   # Track 5 (experimental): the same in Rust, + openssl interop
make channel      # Track 4: simple-network PQC channel, ML-DSA-65 mutual auth
make test         # run every locally-verifiable experiment (E5-E8, E15)
make docker       # Track 6: multi-arch images (needs a Docker daemon)
make k3s-probe HOST=<node>   # Track K1: probe k3s for PQC KEM (needs a cluster)
make mesh         # Track K2: Traefik ingress + Linkerd + Istio (Docker + kubectl)
make multinode    # Track K1: two-node k3s, PQC on apiserver/kubelet/etcd

./scripts/docker-linux-verify.sh        # Linux verification, all six steps
./scripts/docker-linux-verify.sh 2      # just the k3s apiserver probe
PLATFORM=linux/amd64 ./scripts/docker-linux-verify.sh 1   # the suite on amd64

./scripts/k2-mesh-verify.sh             # Track K2, all three steps
./scripts/k2-mesh-verify.sh 3           # just Istio (rebuilds the cluster)
./scripts/k1-multinode-verify.sh        # two-node k3s: control + data plane
./scripts/k1-multinode-verify.sh 1      # control plane only (skips Linkerd)
```

### Running with a partial toolchain

Several experiments need things this repo does not vendor — a sibling checkout,
an OpenSSL ≥ 3.5, a recent OpenSSH, or a Linkerd/Istio install that pulls a CLI
and applies a lot of manifests. Any of those can be missing or flaky, so a
component that **cannot be set up is SKIPPED with a reason, not failed**. Only a
real PQC assertion failure produces a non-zero exit, so a partial toolchain
still gives you every result it can:

```
TOTAL: 2 passed, 0 failed, 3 skipped
```

Detection is automatic — no sibling checkout means E8 skips itself rather than
dying on a missing `Cargo.toml`. You can also force it, or demand the opposite:

```
SKIP_CHANNEL=1 make test      # E8 needs ../simple-network + ../rust-secure-memory
SKIP_MLDSA=1   make test      # E7/E15 need OpenSSL >= 3.5
SKIP_SSH=1     make test      # E6 needs sshd + OpenSSH >= 9.9
SKIP_LINKERD=1 make mesh      # keep Traefik + Istio
SKIP_ISTIO=1   make mesh      # keep Traefik + Linkerd
STRICT=1       make test      # CI: treat any SKIP as a failure
```

`STRICT=1` is the flag to use in CI — it turns "quietly skipped" back into a
hard error, so a machine that silently lost its PQC OpenSSL cannot report green.

All experiments, with their **real captured output**, are documented in
[`EXPERIMENTS.md`](EXPERIMENTS.md).

## Requirements

- **OpenSSL ≥ 3.5** with `X25519MLKEM768`. On macOS the PATH `openssl` is often
  miniconda's 3.0.17 (no PQC) and `/usr/bin/openssl` is LibreSSL — install
  Homebrew's (`brew install openssl@3`); the scripts auto-select it.
- **Go ≥ 1.26** to build this repo (`go.mod` says `go 1.26`). X25519MLKEM768
  itself is default since **1.24** — but no distro packages 1.26 yet (Debian 13
  ships 1.24), so install upstream Go, not `golang-go`.
- **Rust** with the **aws-lc-rs** rustls provider (the `ring` provider has **no**
  PQC). Uses rustls 0.23 + tokio-rustls 0.26.

## Layout

```
scripts/  gen-ca.sh · prove-pqc.sh · interop.sh · openssl-env.sh
go/       common/ · server/ · client/            (net/http over TLS 1.3)
rust/     src/lib.rs · src/bin/{server,client}.rs (tokio-rustls, stable)
rust-mldsa/  same shape, ML-DSA-65 certs      (rustls-post-quantum, UNSTABLE)
PLAN.md   full roadmap: TLS, SSH (incl. Secretive), k3s/Rancher
```

## Status by track

| Track | What | PQC KEM | PQC auth | Verified here |
|---|---|:--:|:--:|:--:|
| 0–3 | Rust/Go/openssl mTLS + interop | ✅ | classical | ✅ |
| S | PQC SSH → non-root sshd (+ Secretive recipe) | ✅ | classical | ✅ |
| 4 | simple-network channel (ML-DSA-65 mutual auth) | ✅ | ✅ | ✅ |
| 5 | Fully-PQC mTLS, ML-DSA-65 certs — openssl | ✅ | ✅ | ✅ |
| 5 | Fully-PQC mTLS, ML-DSA-65 certs — Rust + interop | ✅ | ✅ | ✅ |
| 6 | Multi-arch containers (arm64 + amd64) | ✅ | classical | ✅ (amd64 emulated) |
| K1 | k3s PQC probe + analysis (`docs/k3s-pqc.md`) | ✅ | ❌ | ✅ (v1.36.2, apiserver) |
| K1 | two-node k3s: apiserver + both kubelets + etcd | ✅ | ❌ | ✅ (5/5 endpoints) |
| K1 | cross-node pod mTLS through flannel VXLAN | ✅ | ❌ | ✅ (captured in-tunnel) |
| S2 | mac → linux sshd, arm64 + amd64 | ✅ | classical | ✅ |
| S3 | Legacy LTS: no mlkem, `sntrup761` fallback | ⚠️ | ❌ | ✅ |
| S4 | Experimental ML-DSA SSH auth (OpenSSH 10.4) | ✅ | ✅ | ✅ (Debian sid) |
| K2 | Traefik 3.7.4 PQC ingress termination | ✅ | ❌ | ✅ |
| K2 | Linkerd pod↔pod mTLS — PQC **preferred** | ✅ | ❌ | ✅ (handshake captured) |
| K2 | Istio `COMPLIANCE_POLICY=pqc` — PQC **enforced** | ✅ | ❌ | ✅ (experimental) |
| S1 | Secretive Enclave auth + PQC KEX | ✅ | classical (hardware) | ✅ E23 — [walkthrough](docs/secretive-pqc-ssh.md) |
| S5 | Enclave **ML-DSA-87** → OpenSSH 10.4 | ✅ | ❌ **non-interop** | ✅ measured negative (E22) |
| — | Linux: full suite on Debian 13 arm64 | ✅ | ✅ | ✅ |
| — | Linux: full suite on amd64 | ✅ | ✅ | ✅ (emulated) |

Everything above was verified on macOS arm64; the Linux, k3s and mesh rows were
verified in containers on that same host (`scripts/docker-linux-verify.sh`,
`scripts/k2-mesh-verify.sh`), and the amd64 legs ran under emulation. **No
native amd64 machine was tested** — that is now the only untested axis. The
multi-node cluster is verified on both the control plane and the data plane,
the latter captured inside the flannel VXLAN tunnel.

The two meshes prove *different* things, which is the K2 headline: Linkerd
offers `0x11ec,0x001d,0x0017,0x0018` — PQC first, classical still available.
Istio in `pqc` mode offers **only** `0x11ec`, so a classical-only client is
refused outright. Default-on vs. enforced.

**On a Mac, start with [`README.quick.mac.md`](README.quick.mac.md)** — install,
the three silent PATH traps, and the gotchas that waste an afternoon.

See [`EXPERIMENTS.md`](EXPERIMENTS.md) for captured output,
[`docs/linux-support.md`](docs/linux-support.md) for the per-Debian/Ubuntu
matrix, [`docs/k3s-pqc.md`](docs/k3s-pqc.md) for the orchestrator analysis, and
[`docs/secretive-pqc-ssh.md`](docs/secretive-pqc-ssh.md) for the Secure-Enclave
SSH walkthrough — which also documents **what to upgrade on a Mac** and what
each upgrade actually unlocks.
