# PQC on a Mac — the practical bits

Everything here was measured on macOS 26.5.2 (Tahoe), Apple Silicon, 2026-08-09.
No theory; just what to install, what to type, and what will bite you.

For the reasoning see [`PLAN.md`](PLAN.md); for captured results,
[`EXPERIMENTS.md`](EXPERIMENTS.md).

---

## 1. Install

```
brew install openssh openssl@3 go
```

| Tool | Floor | Why |
|---|---|---|
| **OpenSSL ≥ 3.5** | 3.5 | `X25519MLKEM768` + ML-DSA. Homebrew ships 3.6.3 |
| **OpenSSH ≥ 9.9** | 9.9 | PQC key exchange (`mlkem768x25519-sha256`) |
| **OpenSSH ≥ 10.4** | 10.4 | PQC **authentication** (`mldsa44-ed25519`) — a separate jump |
| **Go ≥ 1.24** | 1.24 | `X25519MLKEM768` on by default in `crypto/tls` |
| Rust | any | PQC comes from the **aws-lc-rs** provider, not the compiler |

Check you actually got them:

```
ssh -V                                              # want >= 10.4 for PQC auth
ssh -Q kex     | grep mlkem768x25519-sha256         # PQC key exchange
ssh -Q key-sig | grep mldsa                         # PQC auth (10.4+ only)
openssl list -tls-groups | grep X25519MLKEM768
go version
```

---

## 2. The three PATH traps

These cost more time than anything else. **All three are silent** — you get a
working-looking tool that simply has no PQC.

| You type | You may get | You want |
|---|---|---|
| `openssl` | miniconda's **3.0.17** — no PQC | `/opt/homebrew/bin/openssl` |
| `/usr/bin/openssl` | **LibreSSL** — no PQC, ever | same |
| `ssh` | Apple's **10.2p1** — no ML-DSA | `/opt/homebrew/bin/ssh` |

`brew upgrade openssh` **never replaces `/usr/bin/ssh`.** macOS keeps its own
copy forever. Put Homebrew first on `PATH` or use absolute paths:

```
which -a openssl ssh        # first line wins
```

In scripts, pin the absolute path. This repo's `scripts/openssl-env.sh` picks a
PQC-capable openssl for you and errors out loudly if there isn't one.

---

## 3. What you get for free (do nothing)

**Post-quantum secrecy is already on.** Any Go ≥1.24, Rust+aws-lc-rs, OpenSSL
≥3.5, or OpenSSH ≥9.9 negotiates a hybrid PQC key exchange by default. Same for
Kubernetes ≥1.33, k3s, Traefik ≥3.5, and Linkerd.

This is the one that matters most day to day: it defeats *harvest-now,
decrypt-later*. You do not have to configure it. You should **verify** it:

```
openssl s_client -connect example.com:443 -groups X25519MLKEM768 </dev/null 2>&1 \
  | grep 'Negotiated TLS1.3 group'
```

If that fails, the far end has no PQC — the risk is a silent downgrade to
classical, which is why every demo in this repo *asserts* the group.

---

## 4. What needs work (identity)

Secrecy is solved; proving **who you are** is not. Three options, honestly ranked:

**① Enclave key + PQC key exchange — use this today.**
Unstealable hardware identity, post-quantum secrecy, works with every server.
Identity is classical (P-256), and that is fine. See
[`docs/secretive-pqc-ssh.md`](docs/secretive-pqc-ssh.md).

**② `mldsa44-ed25519` — if you control both ends.**
Genuinely hybrid: ML-DSA-44 **and** Ed25519, both verified (measured: key
1312+32 B, signature 2420+64 B). Needs OpenSSH **10.4 on both sides**.

```
make mldsa-ssh          # runs it locally, asserts all three properties
```

**③ Secure-Enclave ML-DSA — don't bother yet.**
Secretive can make the key, but no server accepts it: Apple uses the *pure*
draft, OpenSSH the *composite* one. Tested with a real key; it fails **silently**
(see §5). Waiting on the IETF, not on any version bump.

**TLS certificates:** there is no hybrid option at all. OpenSSL has only *pure*
ML-DSA — `openssl list -signature-algorithms | grep -ic composite` → `0`.

**This is not a Mac thing.** Measured identical on `ubuntu:26.04` (3.5.5),
`debian:13` (3.5.6) and `debian:sid` (3.6.3): three pure ML-DSA algorithms, zero
composite, keygen rejected. It is upstream OpenSSL, so a newer distro will not
help.

So for anything public-facing: classical certs + hybrid KEM. A pure-ML-DSA cert
has no classical signature to fall back on.

---

## 5. Gotchas that waste an afternoon

**PQC auth ships switched OFF.** Upgrading to OpenSSH 10.4 is not enough — a
stock 10.4 server advertises *no* ML-DSA. You must say so explicitly:

```
HostKeyAlgorithms        ssh-mldsa44-ed25519@openssh.com
PubkeyAcceptedAlgorithms ssh-mldsa44-ed25519@openssh.com
```

Note the **`@openssh.com` suffix** — the bare `mldsa44-ed25519` is only the
`ssh-keygen -t` name and is rejected in config with `Bad key types`.

**`StrictModes` checks every parent directory.** A demo dir under `/tmp` fails
because `/tmp` is world-writable — even with perfect `700`/`600` on your own
files. The client shows only `Permission denied (publickey)`; the real reason is
server-side:

```
Authentication refused: bad ownership or modes for directory /private/tmp
```

Keep SSH demo dirs under `$HOME`. No `chmod` can fix `/tmp`.

**`Too many authentication failures`** is usually exhaustion, not rejection.
Default `MaxAuthTries` is **6**; a full agent plus `~/.ssh` keys blows through it
before reaching the key you meant. Use `-o IdentitiesOnly=yes`.

**A key the server can't parse is ignored *silently*.** No error at startup, none
in the log, `sshd -t` passes. You get a generic auth failure. If a key "does
nothing," suspect an unsupported type.

**Touch ID can't fire in a script.** With a Secretive key, this:

```
sign_and_send_pubkey: signing failed ... agent refused operation
Permission denied (publickey)
```

is a **presence** problem, not an auth problem. The Enclave wants a fingerprint
and nothing can show the prompt. It hits `git push` from any non-interactive
context. Run it in the foreground and tap. If it degrades to
`communication with agent failed`, kill stale `ssh`/`git` processes first — a
wedged agent socket looks identical to a rejected key.

---

## 6. Verify the whole thing

```
make test           # every locally-runnable experiment, self-asserting
make mldsa-ssh      # fully-PQC SSH (needs OpenSSH 10.4)
```

Missing pieces are **skipped with a reason**, not failed, so a partial toolchain
still gives you every result it can:

```
TOTAL: 2 passed, 0 failed, 3 skipped
```

Force-skip with `SKIP_MLDSA=1`, `SKIP_SSH=1`, `SKIP_CHANNEL=1`. In CI use
`STRICT=1`, which turns any skip into a failure — otherwise a machine that
quietly lost its PQC OpenSSL reports green.

---

## TL;DR

1. `brew install openssh openssl@3 go` — then check `which -a` before anything else.
2. **Secrecy is already post-quantum and free.** Verify it; don't assume it.
3. **Identity: use a Secure Enclave key** with a classical signature. That is the strongest thing that actually interoperates.
4. Want PQC identity too? `mldsa44-ed25519`, both ends on 10.4, and **turn it on explicitly**.
5. Public-facing TLS: classical certs, hybrid KEM. Hybrid PQC certificates do not exist yet.
