#!/usr/bin/env bash
# Track S0/S1: PQC SSH against a non-root sshd.
#
# Stands up a throwaway sshd as the current user on 127.0.0.1:2222 with the
# key exchange PINNED to the hybrid post-quantum KEM `mlkem768x25519-sha256`,
# connects with a generated key, and asserts the negotiated KEX is PQC.
#
# PQC property: post-quantum KEY EXCHANGE (harvest-now-decrypt-later). SSH host
# and user AUTH stay classical (ed25519) -- this is the interoperable posture.
# For hardware-gated auth see the Secretive recipe printed at the end.
#
#   ssh-pqc-demo.sh            # run the demo (leaves artifacts for inspection)
#   PORT=2222 ssh-pqc-demo.sh  # override port
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
D="${SSH_DEMO_DIR:-$HERE/../ssh-demo}"
PORT="${PORT:-2222}"
KEX="mlkem768x25519-sha256"
SSHD="$(command -v sshd || echo /usr/sbin/sshd)"
SSH="$(command -v ssh)"

stop() { [ -f "$D/sshd.pid" ] && kill "$(cat "$D/sshd.pid")" 2>/dev/null || true; }
trap stop EXIT

echo "ssh:  $("$SSH" -V 2>&1)"
echo "sshd: $SSHD"
"$SSH" -Q kex | grep -q "^$KEX\$" || { echo "ERROR: local ssh has no $KEX (need OpenSSH >= 9.9)"; exit 1; }

# --- fresh demo dir (StrictModes: perms MUST be tight or auth silently fails) --
rm -rf "$D"; mkdir -p "$D"; chmod 700 "$D"; cd "$D"
ssh-keygen -q -t ed25519 -N '' -f host_ed25519
ssh-keygen -q -t ed25519 -N '' -f id_ed25519
cat id_ed25519.pub > authorized_keys; chmod 600 authorized_keys host_ed25519

cat > sshd_config <<EOF
Port $PORT
ListenAddress 127.0.0.1
HostKey $D/host_ed25519
PidFile $D/sshd.pid
AuthorizedKeysFile $D/authorized_keys
KexAlgorithms $KEX
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
UsePAM no
StrictModes yes
LogLevel VERBOSE
EOF

# --- start the user-run sshd (absolute paths required) ------------------
"$SSHD" -f "$D/sshd_config" -E "$D/sshd.log"
sleep 1

# --- connect, forcing the PQC KEX; capture verbose negotiation ----------
set +e
"$SSH" -F /dev/null -p "$PORT" -i "$D/id_ed25519" \
  -o KexAlgorithms="$KEX" \
  -o IdentitiesOnly=yes \
  -o UserKnownHostsFile="$D/known_hosts" \
  -o StrictHostKeyChecking=no \
  -vv 127.0.0.1 'echo REMOTE_OK; uname -sm' >"$D/client.out" 2>"$D/client.log"
rc=$?
set -e

echo; echo "== client output =="; cat "$D/client.out"
echo; echo "== negotiated KEX (client) =="
grep -m1 'kex: algorithm:' "$D/client.log" || true
echo "== negotiated KEX (server log) =="
grep -m1 'kex: algorithm:' "$D/sshd.log" || true

echo
if [ $rc -eq 0 ] && grep -q "kex: algorithm: $KEX" "$D/client.log" && grep -q REMOTE_OK "$D/client.out"; then
  echo "PASS: authenticated over post-quantum SSH KEX ($KEX)."
else
  echo "FAIL: rc=$rc (see $D/client.log and $D/sshd.log)"; exit 1
fi

cat <<'NOTE'

--- Secretive (Secure Enclave) variant, macOS, interactive -----------------
Auth from a hardware key instead of the file key above:
  1. Secretive.app -> New Secret -> ECDSA-256, "Require Authentication" (Touch ID)
  2. ssh-add -L | grep ecdsa-sha2-nistp256   >> ssh-demo/authorized_keys
  3. SSH_AUTH_SOCK is already set to Secretive's socket; connect WITHOUT -i:
       ssh -F /dev/null -p 2222 -o KexAlgorithms=mlkem768x25519-sha256 \
           -o UserKnownHostsFile=ssh-demo/known_hosts -o StrictHostKeyChecking=no \
           127.0.0.1 'echo enclave+pqc OK'
  -> Touch ID prompt fires (signature happens inside the Enclave);
     KEX is post-quantum, auth is Enclave-held P-256. Both properties, no root.
NOTE
