#!/usr/bin/env bash
# Track S4: fully post-quantum SSH -- PQC key exchange AND PQC authentication.
#
# Stands up a throwaway non-root sshd whose HOST key and the USER key are both
# composite ML-DSA (ssh-mldsa44-ed25519@openssh.com), with the KEX pinned to
# mlkem768x25519-sha256. Nothing classical survives the handshake:
#
#   KEM  : mlkem768x25519-sha256              (harvest-now-decrypt-later)
#   AUTH : ssh-mldsa44-ed25519@openssh.com    (quantum MITM / forgery)
#
# Needs OpenSSH >= 10.4 on BOTH ends. Earlier releases have the PQC KEX but no
# ML-DSA signatures at all, so they fail the capability check below rather than
# silently negotiating classical auth.
#
# EXPERIMENTAL: mldsa44-ed25519 is a draft composite scheme, off by default
# upstream, and the wire format may still change. Private/lab use only.
#
#   ./scripts/mldsa-ssh-demo.sh
#   PORT=2223 ./scripts/mldsa-ssh-demo.sh
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
PORT="${PORT:-2223}"
ALG=ssh-mldsa44-ed25519@openssh.com
KEX=mlkem768x25519-sha256

# StrictModes walks EVERY parent directory, and /tmp is world-writable (1777),
# so a demo dir under TMPDIR is refused with "bad ownership or modes for
# directory /private/tmp". Keep it inside the repo, i.e. under $HOME.
D="${SSH_S4_DIR:-$ROOT/ssh-demo-s4}"

# Prefer a Homebrew/self-built sshd: macOS ships 10.2p1, which has no ML-DSA.
SSHD="${SSHD_BIN:-}"
if [ -z "$SSHD" ]; then
  for c in /opt/homebrew/sbin/sshd /usr/local/sbin/sshd "$(command -v sshd 2>/dev/null)" /usr/sbin/sshd; do
    [ -x "${c:-}" ] || continue
    "$c" -V 2>&1 | grep -qE 'OpenSSH_(1[1-9]|10\.([4-9]|[1-9][0-9]))' && { SSHD="$c"; break; }
    [ -z "$SSHD" ] && SSHD="$c"
  done
fi
SSH="$(command -v ssh)"

stop() { [ -f "$D/sshd.pid" ] && kill "$(cat "$D/sshd.pid")" 2>/dev/null; }
trap stop EXIT

echo "ssh : $("$SSH" -V 2>&1)"
echo "sshd: $SSHD -> $("$SSHD" -V 2>&1 | head -1)"

# Capability gate: say exactly what is missing rather than failing in a handshake.
if ! "$SSH" -Q key-sig 2>/dev/null | grep -qx "$ALG"; then
  echo
  echo "SKIP: this ssh has no $ALG (needs OpenSSH >= 10.4)."
  echo "      macOS: brew upgrade openssh   (Apple's /usr/bin/ssh stays at 10.2p1;"
  echo "             make sure Homebrew's is first on PATH)."
  echo "      Debian: sid ships 10.4p1. The container run is E12:"
  echo "             ./scripts/docker-linux-verify.sh 3"
  exit 0
fi
"$SSH" -Q kex 2>/dev/null | grep -qx "$KEX" || { echo "ERROR: this ssh has no $KEX"; exit 1; }

rm -rf "$D"; mkdir -p "$D"; chmod 700 "$D"; cd "$D"
ssh-keygen -q -t mldsa44-ed25519 -N '' -f hostkey
ssh-keygen -q -t mldsa44-ed25519 -N '' -f userkey
cat userkey.pub > authorized_keys
chmod 600 authorized_keys hostkey

cat > sshd_config <<EOF
Port $PORT
ListenAddress 127.0.0.1
HostKey $D/hostkey
PidFile $D/sshd.pid
AuthorizedKeysFile $D/authorized_keys
KexAlgorithms $KEX
HostKeyAlgorithms $ALG
PubkeyAcceptedAlgorithms $ALG
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
UsePAM no
StrictModes yes
LogLevel VERBOSE
EOF

"$SSHD" -f "$D/sshd_config" -E "$D/sshd.log" || { echo "sshd failed to start:"; cat "$D/sshd.log"; exit 1; }
sleep 1

set +e
"$SSH" -F /dev/null -p "$PORT" -i "$D/userkey" \
  -o KexAlgorithms="$KEX" \
  -o HostKeyAlgorithms="$ALG" \
  -o PubkeyAcceptedAlgorithms="$ALG" \
  -o IdentitiesOnly=yes \
  -o UserKnownHostsFile="$D/known_hosts" \
  -o StrictHostKeyChecking=no \
  -vv 127.0.0.1 'echo S4_OK; uname -sm' >"$D/out" 2>"$D/log"
rc=$?
set -e

echo; echo "== client output =="; cat "$D/out"
echo; echo "== handshake facts =="
grep -m1 'kex: algorithm:'    "$D/log" || true
grep -m1 'Server host key:'   "$D/log" || true
grep -m1 'Server accepts key:' "$D/log" || true
grep -m1 'Authenticated to'   "$D/log" || true

echo
ok=1
grep -q S4_OK "$D/out"                    || { echo "FAIL: remote command did not run"; ok=0; }
grep -q "kex: algorithm: $KEX" "$D/log"   || { echo "FAIL KEM : $KEX was not negotiated"; ok=0; }
grep -q "Server host key: $ALG" "$D/log"  || { echo "FAIL AUTH: host key was not ML-DSA"; ok=0; }
grep -qi "Server accepts key:.*MLDSA" "$D/log" || { echo "FAIL AUTH: user key was not ML-DSA"; ok=0; }
if [ $ok -eq 1 ] && [ $rc -eq 0 ]; then
  echo "PASS KEM : $KEX negotiated"
  echo "PASS AUTH: host AND user authenticated with ML-DSA ($ALG)"
  echo "PASS: fully post-quantum SSH (PQC KEX + PQC auth), no classical fallback."
else
  echo "FAIL: rc=$rc (see $D/log and $D/sshd.log)"; exit 1
fi

cat <<'NOTE'

Scope: EXPERIMENTAL. mldsa44-ed25519 is a composite draft, off by default in
OpenSSH, and only 10.4+ has it -- so both ends must be upgraded together. It is
a *file*-key scheme: the Secure Enclave cannot hold these (see
docs/secretive-pqc-ssh.md for why Secretive's ML-DSA does not interoperate).
NOTE
