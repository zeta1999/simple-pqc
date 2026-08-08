# Track S1 — Secure Enclave SSH auth over a post-quantum KEX

**What it proves:** both halves of the demo at once, on real hardware —

| Half | Mechanism | Where the secret lives |
|---|---|---|
| **KEM: post-quantum** | `mlkem768x25519-sha256` SSH key exchange | ephemeral, per-connection |
| **Auth: classical, hardware-gated** | ECDSA P-256 signature | **inside the Secure Enclave**, gated by Touch ID |

This is the interoperable posture, in its strongest form: the session key
resists harvest-now-decrypt-later, and the identity key is a P-256 key that
**cannot be exported** — not by you, not by malware, not by anyone with your
disk. Every use requires a fingerprint.

> **Why this one is not in `make test`.** Every other experiment in this repo
> is self-asserting and runs unattended. This one deliberately cannot be: the
> whole point is that the Enclave refuses to sign without a **live human
> fingerprint**. A scripted version would have to disable the thing being
> demonstrated. So it is a hands-on walkthrough — about two minutes.

---

## 0. Prerequisites (all verified on this machine, 2026-08-08, post-upgrade)

```
$ ssh -V
OpenSSH_10.4p1, OpenSSL 3.6.3          # Homebrew's, first on PATH
$ /usr/bin/ssh -V
OpenSSH_10.2p1, LibreSSL 3.3.6         # Apple's system one -- still 10.2

$ ssh -Q kex | grep mlkem
mlkem768x25519-sha256                  # needs OpenSSH >= 9.9

$ defaults read /Applications/Secretive.app/Contents/Info.plist CFBundleShortVersionString
3.0.2

$ echo $SSH_AUTH_SOCK
/Users/<you>/Library/Containers/com.maxgoedjen.Secretive.SecretAgent/Data/socket.ssh
```

`SSH_AUTH_SOCK` pointing at that container path is what makes this work — it
means `ssh` asks **Secretive's agent** for signatures instead of reading a key
file. Secretive sets this up when you install it; if it is unset or points
somewhere else, see [Troubleshooting](#troubleshooting).

Either `ssh` works. Both know `mlkem768x25519-sha256`, so the PQC KEX is
available regardless of which one you use.

---

## 1. Create an Enclave-backed key

In **Secretive.app**:

1. **New Secret**
2. Type: **ECDSA-256**
3. Tick **Require Authentication** — this is the Touch ID gate. Without it the
   Enclave still holds the key, but it will sign silently and you lose the
   demo's punchline.
4. Name it something you will recognise in `ssh-add -L`, e.g. `pqc-demo`.

Confirm the agent is serving it:

```
$ ssh-add -L
ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTIt... pqc-demo
```

The comment field is the key's name in Secretive. Keys already in the agent on
this machine look like `GITHUB@secretive.phoenix.local` — same mechanism, used
for real: that GitHub key is an Enclave key, which is why `git push` prompts for
a fingerprint.

**Note the key type.** It is `ecdsa-sha2-nistp256`, a *classical* signature.
That is deliberate and it is the interoperable choice — see
[The ML-DSA frontier](#the-ml-dsa-frontier-track-s5) for why the PQC option
does not work yet.

---

## 2. Start the throwaway sshd

```
./scripts/ssh-pqc-demo.sh
```

That runs the automated E6 demo (file-key auth) and leaves a working
non-root sshd config in `ssh-demo/` listening on `127.0.0.1:2222`, with
`KexAlgorithms` pinned to `mlkem768x25519-sha256`. It also prints this recipe at
the end.

The sshd exits with the script. To keep it running for the manual walkthrough,
start it yourself from the same config:

```
$(command -v sshd || echo /usr/sbin/sshd) -f ssh-demo/sshd_config -E ssh-demo/sshd.log
```

---

## 3. Authorize the Enclave key

```
ssh-add -L | grep pqc-demo >> ssh-demo/authorized_keys
chmod 600 ssh-demo/authorized_keys
```

Grep for *your* key's name — appending all of `ssh-add -L` authorizes every key
in your agent, including your real GitHub key. Harmless against a throwaway
local sshd, but a bad habit.

The `chmod` is not optional; see [Troubleshooting](#troubleshooting).

---

## 4. Connect — no `-i`, no key file

```
ssh -F /dev/null -p 2222 \
    -o KexAlgorithms=mlkem768x25519-sha256 \
    -o UserKnownHostsFile=ssh-demo/known_hosts \
    -o StrictHostKeyChecking=no \
    -vv 127.0.0.1 'echo enclave+pqc OK'
```

**There is no `-i` flag.** No private key exists on disk to point at — the
signature happens inside the Enclave, and `ssh` reaches it through
`SSH_AUTH_SOCK`.

**Touch ID fires here.** That prompt *is* the proof: the Enclave is being asked
to sign the SSH authentication challenge and is refusing until it sees a
fingerprint.

### What success looks like

Real captured output (2026-08-09, recorded as **E23**):

```
debug1: kex: algorithm: mlkem768x25519-sha256                       <- PQC KEM
debug1: get_agent_identities: agent returned 4 keys
debug1: Offering public key: renaudb1999@gmail.com ECDSA ... agent  <- from the Enclave
debug1: Server accepts key:  renaudb1999@gmail.com ECDSA ... agent
Authenticated to 127.0.0.1 ([127.0.0.1]:2225) using "publickey".
Darwin arm64
```

and server-side:

```
Accepted key ECDSA SHA256:xFjDeZr0Zpo... found at .../authorized_keys:1
Accepted publickey for bechaderenaud from 127.0.0.1 ... ECDSA SHA256:xFjDeZr0Zpo...
```

Three things worth reading carefully:

- `kex: algorithm: mlkem768x25519-sha256` — the session key is hybrid
  post-quantum. Recorded traffic is not decryptable by a future quantum computer.
- `Server accepts key: pqc-demo` — the identity came from the agent, and the
  private half never left the Enclave.
- You touched the sensor. Nothing here is a stored credential a thief could reuse.

To prove the KEX is genuinely pinned rather than merely preferred, ask for a
classical one and watch it fail:

```
$ ssh -F /dev/null -p 2222 -o KexAlgorithms=curve25519-sha256 127.0.0.1 true
Unable to negotiate with 127.0.0.1 port 2222: no matching key exchange method found.
```

---

## The ML-DSA frontier (Track S5)

The obvious next question: why classical P-256 auth, when the KEX is
post-quantum? Because **the PQC option has no server to talk to.**

Secretive 3.x on macOS Tahoe can generate **ML-DSA-65/87 keys in the Secure
Enclave** — genuine hardware-held post-quantum identity. But it emits them in
the **draft-sfluhrer** *pure* ML-DSA wire format, while OpenSSH implements the
**composite** draft (`ssh-mldsa44-ed25519@openssh.com`). The two are not
interoperable, and no OpenSSH server accepts the Secretive format.

**This has been measured, not just read off the drafts — see E22.** A real
Enclave `ssh-mldsa-87` key was placed in a demo server's `authorized_keys` and
the connection attempted through Secretive's agent. It fails for *two*
independent reasons:

1. **The agent never offers it.** `ssh-add -L` and the agent handshake both
   return only the ECDSA P-256 keys. The ML-DSA secret is in Secretive, but the
   SSH agent protocol does not surface it, so the client has nothing to present.
2. **Neither end knows the name.** The client never lists it under
   `Will attempt key`, and **sshd silently ignores the `authorized_keys` line** —
   the server log never mentions ML-DSA at all.

That second point is worth internalising: a key the server cannot parse produces
**no error anywhere**. `sshd -t` passes, startup is clean, and all you get is a
generic `Permission denied`. If you are debugging this, that silence is the
signal.

Apple's bundled `ssh` knows nothing about ML-DSA at all:

```
$ /usr/bin/ssh -Q key-sig | grep -c mldsa
0
```

That is Apple's `/usr/bin/ssh` (10.2p1). Homebrew's is now **10.4p1** and does
list `ssh-mldsa44-ed25519@openssh.com` — but that is the *composite* algorithm,
which still cannot talk to Secretive's *pure* format. Upgrading gave this Mac
two PQC SSH implementations that cannot talk to each other.

And even the composite one is **off by default**: a stock 10.4p1 sshd advertises
`server-sig-algs` with no ML-DSA in it. It has to be enabled explicitly with
`PubkeyAcceptedAlgorithms` (E21 does this). Upgrading alone changes nothing.

So the honest closing statement is: **Enclave PQC authentication is hardware-
ready and waiting on the IETF**, not on Apple. Until the drafts converge, the
deployable posture is exactly what Step 4 demonstrates — PQC KEX plus
hardware-gated classical auth.

---

## Upgrading this Mac

Measured 2026-08-08 on macOS 26.5.2 (Tahoe), Apple Silicon. Everything in this
repo passed *before* these upgrades too — the only one that unlocked new
capability is OpenSSH.

**These upgrades have since been applied on this machine.** The table records what it
changed, and the reasoning stands for any other Mac.

| Tool | Was | Now | Did it matter? |
|---|---|---|---|
| **OpenSSH** (brew) | 10.0p2_3 | **10.4p1** | **Yes** — unlocked ML-DSA SSH auth (E21) |
| OpenSSL (brew `openssl@3`) | 3.6.2 | 3.6.3 | No — 3.6.2 already had ML-KEM + ML-DSA |
| Go (brew) | 1.25.6 | 1.26.5 | No — see the note below |
| rustup | 1.28.2 | 1.29.0_2 | No; `rustc` is 1.95.0 |
| macOS | 26.5.2 | — | Already Tahoe, which is what Enclave ML-DSA needs |

### The upgrade that actually buys you something

```
brew upgrade openssh          # 10.0p2_3 -> 10.4p1
```

**OpenSSH 10.4 is where the composite PQC signature lands.** After upgrading:

```
$ ssh -Q key-sig | grep mldsa
ssh-mldsa44-ed25519@openssh.com
ssh-mldsa44-ed25519-cert-v01@openssh.com
```

That turned **Track S4** from a container-only result (E12) into one that runs
natively here — hardware-free, file-based **post-quantum SSH authentication** on
both ends. It is now **E21**, `make mldsa-ssh`, and it passes:

```
PASS AUTH: host AND user authenticated with ML-DSA (ssh-mldsa44-ed25519@openssh.com)
PASS: fully post-quantum SSH (PQC KEX + PQC auth), no classical fallback.
```

Before the upgrade, `ssh -Q key-sig | grep -c mldsa` returned `0` on both the
Homebrew and the Apple ssh — which is why E12 had to run in Debian sid.

Two caveats, both real:

- It does **not** rescue Track S5. Secretive's Enclave ML-DSA is the
  *draft-sfluhrer pure* format; OpenSSH 10.4 implements the *composite* one.
  Upgrading gives you two PQC SSH implementations that still cannot talk to each
  other. That gap is an IETF question, not a version question.
- `brew upgrade openssh` changes only `/opt/homebrew/bin/ssh`. **Apple's
  `/usr/bin/ssh` stays at 10.2p1** — macOS ships its own and Homebrew never
  replaces it. Make sure the Homebrew one is first on `PATH`, or call it by
  absolute path, or you will get 10.2p1 and wonder where ML-DSA went.

### The other three

```
brew upgrade openssl@3        # 3.6.2 -> 3.6.3, patch only
brew upgrade go               # 1.25.6 -> 1.26.5
brew upgrade rustup && rustup update stable
```

**None of these unlock anything.** Specifically:

- **OpenSSL 3.6.2 already does everything this repo needs** — `X25519MLKEM768`
  and ML-DSA-65 both work; E7 and E15 pass on it. The floor is **3.5**, and you
  are well past it.
- **Go 1.25.6 is fine even though `go/go.mod` says `go 1.26`.** `GOTOOLCHAIN` is
  `auto`, so the 1.25.6 driver downloads and runs a 1.26 toolchain on demand —
  that is the `go: downloading go1.26.0` line in the build logs. Upgrading just
  saves that download. The PQC-relevant floor is **1.24**, where
  `X25519MLKEM768` became the default.
- **Rust 1.95.0 is fine.** PQC comes from the `aws-lc-rs` rustls provider, not
  the compiler. The thing to never do is switch to the `ring` provider, which
  has **no** PQC at any Rust version.

### Verifying an upgrade did what you wanted

```
ssh -V                                        # want OpenSSH_10.4p1
ssh -Q kex     | grep mlkem768x25519-sha256   # PQC KEX  (already present at 10.0)
ssh -Q key-sig | grep mldsa                   # PQC AUTH (only from 10.4)
/opt/homebrew/bin/openssl list -tls-groups | grep X25519MLKEM768
go version                                    # >= 1.24 for the TLS default
```

Then re-run the suite — it self-asserts, so a regression shows up as a FAIL
rather than silently downgrading to classical crypto:

```
make test
```

---

## Troubleshooting

**Touch ID never appears; auth just fails.**
The key was created without **Require Authentication**. Secretive signs it
silently, so if nothing prompts and login still succeeds, the gate is off.
Recreate the secret with the box ticked.

**`Permission denied (publickey)` with no prompt at all.**
Almost always `StrictModes`. sshd silently refuses keys when the directory or
`authorized_keys` are group/world-writable, and logs nothing useful at default
verbosity:

```
chmod 700 ssh-demo
chmod 600 ssh-demo/authorized_keys
```

This bit us during development, which is why `ssh-pqc-demo.sh` sets both.

**`sign_and_send_pubkey: signing failed ... agent refused operation`**
The Enclave was asked to sign in a context that cannot show a prompt — a
non-interactive script, a background job, CI. This is not a broken key; it is
the gate working. Re-run it in the foreground and tap.

This is the single most confusing failure in practice, because it also hits
`git push` when your GitHub key lives in Secretive. It looks like an auth
problem (`Permission denied (publickey)`) but it is a *presence* problem — the
fix is to run the command where you can see and answer the prompt.

**`ssh-add -L` prints "The agent has no identities".**
`SSH_AUTH_SOCK` is not pointing at Secretive. Check it against §0. Secretive's
Setup window will re-print the correct value, or set it in your shell profile.

**`Too many authentication failures` before your key is reached.**
A populated agent plus `~/.ssh` file keys can exceed the server's `MaxAuthTries`
(default **6**) before the right key comes up — and the client is dropped, which
looks like rejection rather than exhaustion. Measured: 4 agent keys + 5 file
keys hit the limit. Restrict it to the one you want:

```
ssh ... -o IdentityAgent="$SSH_AUTH_SOCK" -o IdentitiesOnly=yes -i ssh-demo/pqc-demo.pub
```

Passing a **`.pub`** file with `IdentitiesOnly` selects which agent key to use —
`ssh` matches the public half and asks the agent to sign. There is still no
private key on disk.

---

## See also

- **E6** in [`EXPERIMENTS.md`](../EXPERIMENTS.md) — the automated file-key
  version of this demo, with captured output.
- **E12** — ML-DSA SSH auth (`ssh-mldsa44-ed25519@openssh.com`) working
  end to end on OpenSSH 10.4, in a container.
- `scripts/ssh-pqc-demo.sh` — the sshd config used here, and the short form of
  this recipe printed on exit.
