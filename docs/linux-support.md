# Linux support & expected results (Debian / Ubuntu)

E1–E8 in `EXPERIMENTS.md` were verified on macOS. This is the **per-distro
matrix** for Linux (arm64 + amd64), so a run on a Linux host can be checked
against known-good values.

**Status (task #12, 2026-08-01):** all versions in the table below are now
**measured** in arm64 containers via `scripts/docker-linux-verify.sh`. Full
handshakes ran on Debian 13 (E11), Debian sid ML-DSA SSH auth (E12), and the
Ubuntu 24.04 / Debian 12 legacy fallback (E13); the Ubuntu 25.04–26.04 rows were
capability-probed only (step 5), not handshaked.

## The key insight: what depends on distro packages, and what doesn't

| Track | Uses distro OpenSSL? | Uses distro OpenSSH? | Portable? |
|---|:--:|:--:|---|
| E2/E3 Go & Rust mTLS | ❌ | ❌ | **Yes** — Go's own `crypto/tls`, Rust's bundled aws-lc-rs |
| E5 interop (Go/Rust cells) | ❌ | ❌ | **Yes** |
| E5 interop (openssl cell), E4 prove | ✅ needs ≥3.5 | ❌ | version-sensitive |
| E7 ML-DSA-65 certs | ✅ needs ≥3.5 | ❌ | version-sensitive |
| E6 PQC SSH | ❌ | ✅ needs ≥9.9 for mlkem | version-sensitive |
| E8 simple-network channel | ❌ | ❌ | **Yes** (pure Rust) |

**So:** with a recent **Go** and **Rust** toolchain installed, the
Go/Rust/channel tracks (E2, E3, E8, and the Go/Rust cells of E5) pass on **any**
of the distros below regardless of their system OpenSSL. Only the `openssl`-CLI
proof, the ML-DSA cert track, and the SSH KEX track care about distro versions.

**But mind the Go version twice over.** PQC KEM in `crypto/tls` needs only Go
**≥1.24**; *this repo's* `go.mod` declares **`go 1.26`**, so an older toolchain
refuses to build it at all. No distro packages 1.26 yet — Debian 13 ships 1.24 —
so install upstream Go rather than `apt install golang-go` (this bit the E11 run).

## Per-distro versions & verdicts

Toolchain (packaged): **OpenSSH** needs ≥ 9.9 for `mlkem768x25519-sha256`
(older ships only `sntrup761x25519-sha512@openssh.com` — still PQC, pre-standard).
**OpenSSL** needs ≥ 3.5 for `X25519MLKEM768` and ML-DSA.

Every version below is **measured**, not looked up — run
`./scripts/docker-linux-verify.sh 5` to regenerate the sweep.

| Distro | OpenSSH | mlkem KEX | OpenSSL | X25519MLKEM768 / ML-DSA | SSH track (E6) | openssl+ML-DSA (E4/E7) |
|---|---|:--:|---|:--:|---|---|
| **Ubuntu 24.04 LTS** (noble) | 9.6p1 | ❌ | 3.0.13 | ❌ | `sntrup761` fallback — **verified (E13)** | ✗ (use container/build) |
| **Ubuntu 25.04** (plucky) | 9.9p1 | ✅ present, not default | 3.4.1 | ❌ | pin `mlkem…` | ✗ |
| **Ubuntu 25.10** (questing) | 10.0p2 | ✅ default | 3.5.3 | ✅ | ✅ | ✅ |
| **Ubuntu 26.04 LTS** (resolute) | 10.2p1 | ✅ default | 3.5.5 | ✅ | ✅ | ✅ |
| **Debian 12** (bookworm) | 9.2p1 | ❌ | 3.0.20 | ❌ | `sntrup761` fallback — **verified (E13)** | ✗ (use container/build) |
| **Debian 13** (trixie) | 10.0p2 | ✅ default | 3.5.6 | ✅ | ✅ **verified (E11)** | ✅ **verified (E11)** |
| **Debian sid** (unstable) | 10.4p1 | ✅ default | 3.6.3 | ✅ | ✅ **verified (E12)**, incl. experimental `mldsa44-ed25519` auth | ✅ |

**mlkem / X25519MLKEM768 columns are probed capability** (`ssh -Q kex`,
`openssl list -tls-groups`), so they say *available*, not *default* — that
distinction is why the 25.04 row is called out separately. The **verified**
labels mark rows where a full handshake actually ran; the rest were only
capability-probed.

Two earlier entries in this table were wrong and are corrected above: sid's
OpenSSL is **3.6.3**, not 4.0.1, and Debian 13 / Ubuntu 25.10 ship OpenSSH
**10.0p2**, not 10.0p1.

Versions drift with point releases, so **confirm on the box**:
```
openssl version            # need >= 3.5 for X25519MLKEM768 + ML-DSA
ssh -V                     # need >= 9.9 for mlkem768x25519
ssh -Q kex | grep -E 'mlkem|sntrup'
go version                 # >= 1.24 for PQC KEM; >= 1.26 to build this repo
```

## Expected results per track (native Linux)

- **E2 / E3 / E8 / E5(Go,Rust cells)** — PASS on every distro above once Go 1.26+
  and Rust are installed (measured on Debian 13, E11). Distro OpenSSL/OpenSSH irrelevant. The interop matrix's
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
- **Non-root sshd:** runs fine as a user on a high port; the user-run config here
  (`UsePAM no`, pubkey only) does not need `/run/sshd`. **In a container you are
  usually root**, which *does* engage privsep — and Debian creates `/run/sshd`
  via systemd-tmpfiles, which containers never run. `mkdir -p /run/sshd` first,
  or sshd exits with `Missing privilege separation directory` (hit in E11/E12).
- **`sshd -E logfile` hides startup failures.** Config errors go to the logfile,
  not stderr, so a bad `sshd_config` looks like silence. Always `cat` the log on
  a non-zero exit.
- **ML-DSA SSH algorithm naming (OpenSSH 10.4):** the wire name is
  `ssh-mldsa44-ed25519@openssh.com`. `ssh-keygen -t mldsa44-ed25519` takes the
  short form, but `HostKeyAlgorithms` / `PubkeyAcceptedAlgorithms` reject it with
  `Bad key types` — use the full `@openssh.com` name in config and `-o` flags.
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
