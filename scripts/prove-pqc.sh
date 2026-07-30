#!/usr/bin/env bash
# Track 0 proof harness: prove a TLS endpoint negotiates the post-quantum
# hybrid KEM (X25519MLKEM768, IANA 0x11EC / 4588), and prove the negative.
#
#   prove-pqc.sh HOST PORT            # assert PQC group is negotiated
#   prove-pqc.sh HOST PORT --negative # assert a classical-only client CANNOT
#
# Uses the real PQC-capable openssl (see openssl-env.sh). mTLS endpoints need
# a client cert; pass CLIENT_CERT/CLIENT_KEY env to authenticate.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$HERE/openssl-env.sh"

HOST="${1:?usage: prove-pqc.sh HOST PORT [--negative]}"
PORT="${2:?usage: prove-pqc.sh HOST PORT [--negative]}"
MODE="${3:-positive}"
PQC_GROUP="X25519MLKEM768"
CERTDIR="${CERTDIR:-$HERE/../certs}"
CLIENT_CERT="${CLIENT_CERT:-$CERTDIR/client.crt}"
CLIENT_KEY="${CLIENT_KEY:-$CERTDIR/client.key}"
CAFILE="${CAFILE:-$CERTDIR/ca.crt}"

mtls_args=()
[ -f "$CLIENT_CERT" ] && [ -f "$CLIENT_KEY" ] && \
  mtls_args=(-cert "$CLIENT_CERT" -key "$CLIENT_KEY")
[ -f "$CAFILE" ] && mtls_args+=(-CAfile "$CAFILE")

handshake() { # groups
  echo Q | "$OPENSSL_BIN" s_client -connect "$HOST:$PORT" \
    -servername localhost -tls1_3 -groups "$1" "${mtls_args[@]}" 2>&1
}

if [ "$MODE" = "--negative" ] || [ "$MODE" = "negative" ]; then
  echo "== NEGATIVE: classical-only client (X25519) against $HOST:$PORT =="
  out="$(handshake X25519 || true)"
  if grep -q 'Negotiated TLS1.3 group: X25519MLKEM768' <<<"$out"; then
    echo "FAIL: server accepted a classical-only client as PQC?!"; exit 1
  fi
  # A real, completed handshake shows a concrete cipher (not "(NONE)").
  if grep -qE 'Cipher is TLS_' <<<"$out" && ! grep -q 'Cipher is (NONE)' <<<"$out"; then
    echo "NOTE: handshake succeeded with a classical group -> server ALLOWS downgrade."
    grep -E 'Negotiated TLS1.3 group' <<<"$out" || true
    echo "(A strict PQC-only server should have refused this.)"
    exit 1
  fi
  echo "PASS: classical-only client was REFUSED (strict PQC-only server)."
  grep -E 'handshake failure|no shared cipher|alert|sslv3' <<<"$out" | head -1 || true
  exit 0
fi

echo "== POSITIVE: PQC client ($PQC_GROUP) against $HOST:$PORT =="
out="$(handshake "$PQC_GROUP")"
line="$(grep -E 'Negotiated TLS1.3 group' <<<"$out" || true)"
echo "${line:-<no group line>}"
grep -E 'Protocol|Cipher is|Verify return code' <<<"$out" || true
if grep -q "Negotiated TLS1.3 group: $PQC_GROUP" <<<"$out"; then
  echo "PASS: post-quantum KEM negotiated ($PQC_GROUP)."
else
  echo "FAIL: $PQC_GROUP was not negotiated."; exit 1
fi
