# Linux support & expected results (Debian / Ubuntu)

Everything in `EXPERIMENTS.md` was verified on macOS. This is the **per-distro
expectation matrix** for native Linux (arm64 + amd64), so a run on a Linux host
can be checked against known-good values. Nothing here has been executed yet —
these are *expected* results with their reasoning; the actual run is task #12.

## The key insight: what depends on distro packages, and what doesn't

| Track | Uses distro OpenSSL? | Uses distro OpenSSH? | Portable? |
|---|:--:|:--:|---|
| E2/E3 Go & Rust mTLS | ❌ | ❌ | **Yes** — Go's own `crypto/tls`, Rust's bundled aws-lc-rs |
| E5 interop (Go/Rust cells) | ❌ | ❌ | **Yes** |
| E5 interop (openssl cell), E4 prove | ✅ needs ≥3.5 | ❌ | version-sensitive |
| E7 ML-DSA-65 certs | ✅ needs ≥3.5 | ❌ | version-sensitive |
| E6 PQC SSH | ❌ | ✅ needs ≥9.9 for mlkem | version-sensitive |
| E8 simple-network channel | ❌ | ❌ | **Yes** (pure Rust) |

**So:** with a recent **Go (≥1.24)** and **Rust** toolchain installed, the
Go/Rust/channel tracks (E2, E3, E8, and the Go/Rust cells of E5) pass on **any**
of the distros below regardless of their system OpenSSL. Only the `openssl`-CLI
proof, the ML-DSA cert track, and the SSH KEX track care about distro versions.

## Per-distro versions & verdicts

Toolchain (packaged): **OpenSSH** needs ≥ 9.9 for `mlkem768x25519-sha256`
(older ships only `sntrup761x25519-sha512@openssh.com` — still PQC, pre-standard).
**OpenSSL** needs ≥ 3.5 for `X25519MLKEM768` and ML-DSA.

| Distro | OpenSSH | mlkem KEX | OpenSSL | X25519MLKEM768 / ML-DSA | SSH track (E6) | openssl+ML-DSA (E4/E7) |
|---|---|:--:|---|:--:|---|---|
| **Ubuntu 24.04 LTS** (noble) | 9.6p1 | ❌ | 3.0.13 | ❌ | `sntrup761` fallback | ✗ (use container/build) |
| **Ubuntu 25.04** (plucky) | 9.9 | ✅ (not default) | ~3.4 | ❌ | pin `mlkem…` | ✗ |
| **Ubuntu 25.10** (questing) | 10.0p1 | ✅ default | ~3.5 | ✅ (verify) | ✅ | ✅ (verify) |
| **Ubuntu 26.04 LTS** (resolute) | 10.2p1 | ✅ default | 3.5.5 | ✅ | ✅ | ✅ |
| **Debian 12** (bookworm) | 9.2p1 | ❌ | 3.0.x | ❌ | `sntrup761` fallback | ✗ (use container/build) |
| **Debian 13** (trixie) | 10.0p1 | ✅ default | 3.5.6 | ✅ | ✅ | ✅ |
| **Debian sid** (unstable) | 10.4p1 | ✅ default | 4.0.1 | ✅ | ✅ (+ experimental `mldsa44-ed25519` auth) | ✅ |

OpenSSH per-distro from upstream research (2026-07); OpenSSL LTS/stable rows
verified against packages.debian.org / launchpad. Intermediate non-LTS Ubuntu
OpenSSL versions (24.10≈3.3, 25.04≈3.4, 25.10≈3.5) are approximate — **always
confirm on the box**:
```
openssl version            # need >= 3.5 for X25519MLKEM768 + ML-DSA
ssh -V                     # need >= 9.9 for mlkem768x25519
ssh -Q kex | grep -E 'mlkem|sntrup'
go version                 # need >= 1.24
```

## Expected results per track (native Linux)

- **E2 / E3 / E8 / E5(Go,Rust cells)** — PASS on every distro above once Go 1.24+
  and Rust are installed. Distro OpenSSL/OpenSSH irrelevant. The interop matrix's
  `openssl` row will show `<no handshake>`/blank on distros with OpenSSL < 3.5.
- **E4 / E5(openssl cell) / E7 (ML-DSA)** — PASS on Ubuntu ≥25.10, Ubuntu 26.04,
  Debian ≥13, sid. On Ubuntu 24.04 / Debian 12 the scripts abort with the
  "need >= 3.5" hint. Workarounds: run the proof from a container
  (`alpine:3.22` ships OpenSSL 3.5.x) or a statically-built openssl, or simply
  rely on the Go/Rust cells to prove the KEM.
- **E6 PQC SSH** — On Ubuntu ≥25.10 / Debian ≥13 the demo negotiates
  `mlkem768x25519-sha256` as written. On **Ubuntu 24.04 / Debian 12**, override
  the KEX to the pre-standard PQC one:
  ```
  KEX=sntrup761x25519-sha512@openssh.com PORT=2222 ./scripts/ssh-pqc-demo.sh
  ```
  (the script pins `KexAlgorithms`; edit it or export `KEX` — still post-quantum,
  just the older construction). To get mlkem on an old LTS, build OpenSSH ≥10
  from source; no official PPA/backport exists.

## Linux-specific gotchas (vs the macOS run)

- **sshd binary path:** on Debian/Ubuntu it's `/usr/sbin/sshd` (not in a normal
  user's PATH); `ssh-pqc-demo.sh` already falls back to it. Install with
  `apt-get install -y openssh-server`.
- **Non-root sshd:** runs fine as a user on a high port; if it complains about a
  missing privilege-separation dir, that only applies to root/privsep — the
  user-run config here (`UsePAM no`, pubkey only) does not need `/run/sshd`.
- **StrictModes:** same as macOS — the demo dir (700) and `authorized_keys`
  (600) perms must be tight or auth silently fails (the script sets these).
- **aws-lc-rs build deps** (Rust track / container): `apt-get install -y cmake
  clang` on the builder.
- **arm64 vs amd64:** all tracks are arch-neutral; run the same steps on both.
  The `rust/Dockerfile` builds each arch under QEMU emulation via buildx.

## Fastest portable path on a bare Linux box

```
apt-get update && apt-get install -y openssh-server cmake clang make git
# install Go >=1.24 and rustup, then:
git clone <this repo> && cd simple-pqc
make test        # E5 (Go/Rust cells) + E6 + E8 will pass everywhere;
                 # E7 + the openssl cell need OpenSSL >=3.5 (see table)
```
