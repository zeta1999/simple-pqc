#!/usr/bin/env bash
# Track 5 (EXPERIMENTAL): fully post-quantum mTLS in **Rust**, and its interop
# with OpenSSL. Proves BOTH properties on every leg:
#   - KEM:  X25519MLKEM768   (post-quantum key exchange)
#   - AUTH: ML-DSA-65 certs  (post-quantum PKI / signatures, RFC 9881)
#
# E7 (mldsa-tls-demo.sh) showed openssl<->openssl. This adds the Rust side, so
# PQC PKI is no longer a single-implementation result:
#   [1] rust client   -> rust server
#   [2] openssl client-> rust server
#   [3] rust client   -> openssl s_server
#
# Rust ML-DSA comes from rustls-post-quantum's `aws-lc-rs-unstable` feature --
# experimental, and the reason this lives in its own crate (../rust-mldsa).
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
source "$HERE/openssl-env.sh"
CERTS="${CERTS:-$ROOT/certs-mldsa}"
RPORT="${RPORT:-10443}"   # rust server
OPORT="${OPORT:-10444}"   # openssl s_server
BIN="$ROOT/rust-mldsa/target/debug"
SRVLOG="$ROOT/rust-mldsa-srv.log"

rust_pid=""; ossl_pid=""
cleanup() {
  [ -n "$rust_pid" ] && kill "$rust_pid" 2>/dev/null
  [ -n "$ossl_pid" ] && kill "$ossl_pid" 2>/dev/null
  wait 2>/dev/null
  return 0
}
trap cleanup EXIT

[ -f "$CERTS/ca.crt" ] || "$HERE/gen-ca-mldsa.sh" "$CERTS" >/dev/null
echo "building rust-mldsa (unstable aws-lc-rs) ..."
( cd "$ROOT/rust-mldsa" && cargo build -q ) || { echo "FAIL: rust-mldsa build"; exit 1; }

pass=0; fail=0
note() { if [ "$1" = 0 ]; then echo "PASS  $2"; pass=$((pass+1)); else echo "FAIL  $2"; fail=$((fail+1)); fi; }

# --- servers ---------------------------------------------------------------
: > "$SRVLOG"
CERT_DIR="$CERTS" ADDR="127.0.0.1:$RPORT" "$BIN/mldsa-server" >/dev/null 2>"$SRVLOG" &
rust_pid=$!
sleep 2
if grep -q "Address already in use" "$SRVLOG" 2>/dev/null; then
  echo "FAIL: port $RPORT already in use -- a stray mldsa-server is running."
  echo "      (pkill -f mldsa-server, or set RPORT=<other>)"
  exit 1
fi
"$OPENSSL_BIN" s_server -accept "$OPORT" -naccept 1 \
  -cert "$CERTS/server.crt" -key "$CERTS/server.key" \
  -CAfile "$CERTS/ca.crt" -Verify 1 \
  -tls1_3 -groups X25519MLKEM768 -quiet >/dev/null 2>&1 &
ossl_pid=$!
sleep 2

# --- [1] rust client -> rust server ----------------------------------------
echo; echo "== [1] rust client -> rust server =="
if out="$(CERT_DIR="$CERTS" HOST=127.0.0.1 PORT="$RPORT" "$BIN/mldsa-client" 2>&1)"; then
  echo "$out"
  grep -q '"auth":"ML-DSA-65"' <<<"$out" && note 0 "rust<->rust: PQC KEM + ML-DSA-65 mutual auth" \
                                         || note 1 "rust<->rust: no ML-DSA-65 in response"
else
  echo "$out"; note 1 "rust<->rust handshake"
fi

# --- [2] openssl client -> rust server -------------------------------------
# Independent implementation checking the Rust server's ML-DSA signature.
echo; echo "== [2] openssl s_client -> rust server =="
out="$(echo Q | "$OPENSSL_BIN" s_client -connect "127.0.0.1:$RPORT" -servername localhost \
        -cert "$CERTS/client.crt" -key "$CERTS/client.key" -CAfile "$CERTS/ca.crt" \
        -tls1_3 -groups X25519MLKEM768 2>&1)"
grep -E 'Negotiated TLS1.3 group|Peer signature type|Verify return code' <<<"$out" || true
kem_ok=false; auth_ok=false
grep -q 'Negotiated TLS1.3 group: X25519MLKEM768' <<<"$out" && kem_ok=true
grep -qiE 'Peer signature type: *(ML-?DSA|mldsa)' <<<"$out" && auth_ok=true
{ $kem_ok && $auth_ok; } && note 0 "openssl->rust: PQC KEM + rust signed with ML-DSA" \
                         || note 1 "openssl->rust (kem=$kem_ok auth=$auth_ok)"

# --- [3] rust client -> openssl s_server ------------------------------------
echo; echo "== [3] rust client -> openssl s_server =="
if out="$(CERT_DIR="$CERTS" HOST=127.0.0.1 PORT="$OPORT" "$BIN/mldsa-client" 2>&1)"; then
  grep -E '^OK' <<<"$out" || true
  note 0 "rust->openssl: rust verified an ML-DSA-65 server over PQC KEM"
else
  echo "$out"; note 1 "rust->openssl handshake"
fi

# --- [4] negatives: the Rust server must REFUSE weaker peers ----------------
# Restart it (the earlier probes consumed connections, but it loops) and check
# it rejects (a) a classical-only KEX and (b) a classical Ed25519 client cert
# from the *other* CA. Without these the PASSes above could be vacuous.
echo; echo "== [4] negative: classical-only client against the rust server =="
out="$(echo Q | "$OPENSSL_BIN" s_client -connect "127.0.0.1:$RPORT" -servername localhost \
        -cert "$CERTS/client.crt" -key "$CERTS/client.key" -CAfile "$CERTS/ca.crt" \
        -tls1_3 -groups X25519 2>&1)"
if grep -qE 'alert|failure|error' <<<"$out" && ! grep -q 'Negotiated TLS1.3 group: X25519MLKEM768' <<<"$out"; then
  grep -m1 -E 'alert|failure' <<<"$out" | sed 's/^/  /'
  note 0 "classical-only KEX refused by the rust ML-DSA server"
else
  note 1 "classical-only KEX was NOT refused"
fi

echo; echo "== [4] negative: classical Ed25519 client cert (wrong PKI) =="
# Assert on the SERVER log, not the client's. Under TLS 1.3 the client finishes
# its side before the server validates the client certificate, so `s_client`
# exits reporting success ("Verify return code: 0" refers to *its* check of the
# server cert) and the rejection alert never shows up in its output.
if [ -f "$ROOT/certs/client.crt" ]; then
  before="$(wc -l < "$SRVLOG" 2>/dev/null || echo 0)"
  echo Q | "$OPENSSL_BIN" s_client -connect "127.0.0.1:$RPORT" -servername localhost \
          -cert "$ROOT/certs/client.crt" -key "$ROOT/certs/client.key" -CAfile "$CERTS/ca.crt" \
          -tls1_3 -groups X25519MLKEM768 >/dev/null 2>&1
  sleep 1
  new="$(tail -n "+$((before+1))" "$SRVLOG" 2>/dev/null)"
  echo "$new" | sed 's/^/  /'
  if grep -qE 'invalid peer certificate|UnknownIssuer|BadSignature' <<<"$new"; then
    note 0 "classical Ed25519 client cert rejected (ML-DSA PKI enforced)"
  else
    note 1 "classical Ed25519 client cert was ACCEPTED by the server"
  fi
else
  echo "  (skipped: run scripts/gen-ca.sh first for the classical CA)"
fi

echo; echo "----------------------------------------------------------------------"
echo "TOTAL: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
