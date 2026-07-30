#!/usr/bin/env bash
# Track 5 (EXPERIMENTAL): fully post-quantum mTLS -- BOTH properties at once.
#   - KEM:  X25519MLKEM768   (post-quantum key exchange)
#   - AUTH: ML-DSA-65 certs  (post-quantum PKI / signatures)
# Runs an OpenSSL s_server requiring a client cert and an s_client against it,
# then proves the negotiated group AND the peer signature type are both PQC.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$HERE/openssl-env.sh"
CERTS="${CERTS:-$HERE/../certs-mldsa}"
PORT="${PORT:-4443}"
[ -f "$CERTS/ca.crt" ] || "$HERE/gen-ca-mldsa.sh" "$CERTS" >/dev/null

srv_pid=""
cleanup() { [ -n "$srv_pid" ] && kill "$srv_pid" 2>/dev/null || true; }
trap cleanup EXIT

"$OPENSSL_BIN" s_server -accept "$PORT" -naccept 1 \
  -cert "$CERTS/server.crt" -key "$CERTS/server.key" \
  -CAfile "$CERTS/ca.crt" -Verify 1 \
  -tls1_3 -groups X25519MLKEM768 -quiet >/dev/null 2>&1 &
srv_pid=$!
sleep 1

out="$(echo Q | "$OPENSSL_BIN" s_client -connect "127.0.0.1:$PORT" -servername localhost \
        -cert "$CERTS/client.crt" -key "$CERTS/client.key" -CAfile "$CERTS/ca.crt" \
        -tls1_3 -groups X25519MLKEM768 2>&1)"

echo "== handshake facts =="
grep -E 'Negotiated TLS1.3 group|Peer signature type|Protocol|Cipher is|Verify return code' <<<"$out" || true
echo
echo "== server cert signature algorithm =="
"$OPENSSL_BIN" x509 -in "$CERTS/server.crt" -noout -text | grep -m1 'Signature Algorithm' | sed 's/^ *//'

kem_ok=false; auth_ok=false
grep -q 'Negotiated TLS1.3 group: X25519MLKEM768' <<<"$out" && kem_ok=true
grep -qiE 'Peer signature type: *(ML-?DSA|mldsa)' <<<"$out" && auth_ok=true

echo
$kem_ok  && echo "PASS KEM : X25519MLKEM768 negotiated"       || echo "FAIL KEM"
$auth_ok && echo "PASS AUTH: server authenticated with ML-DSA" || echo "FAIL AUTH"
{ $kem_ok && $auth_ok; } && echo "PASS: fully post-quantum mTLS (PQC KEM + PQC PKI)." || { echo "FAIL"; exit 1; }
