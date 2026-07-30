#!/usr/bin/env bash
# Track 0 mini-CA: a classical Ed25519 CA + server/client leaf certs.
#
# Auth is CLASSICAL (Ed25519) on purpose: this is the "hybrid ECC/PQC" posture
# where the KEM is post-quantum (X25519MLKEM768, negotiated at the TLS layer)
# but the PKI stays classical -- the interoperable, demoable-today baseline.
# For PQC *PKI* (ML-DSA certs) see scripts/gen-ca-mldsa.sh (Track 5, later).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$HERE/openssl-env.sh"

OUT="${1:-$HERE/../certs}"
mkdir -p "$OUT"
cd "$OUT"

echo "openssl: $OPENSSL_BIN ($("$OPENSSL_BIN" version))"
echo "out:     $OUT"

gen_key()  { "$OPENSSL_BIN" genpkey -algorithm ed25519 -out "$1"; }

# --- CA -----------------------------------------------------------------
gen_key ca.key
"$OPENSSL_BIN" req -x509 -new -key ca.key -days 3650 \
  -subj "/CN=simple-pqc-demo-ca/O=simple-pqc" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -out ca.crt

# --- leaf issuance helper ----------------------------------------------
issue() { # name  CN  extfile-contents
  local name="$1" cn="$2" exts="$3"
  gen_key "$name.key"
  "$OPENSSL_BIN" req -new -key "$name.key" -subj "/CN=$cn/O=simple-pqc" -out "$name.csr"
  "$OPENSSL_BIN" x509 -req -in "$name.csr" -CA ca.crt -CAkey ca.key -CAcreateserial \
    -days 825 -extfile <(printf '%s\n' "$exts") -out "$name.crt"
  rm -f "$name.csr"
}

issue server localhost \
  "subjectAltName=DNS:localhost,IP:127.0.0.1
extendedKeyUsage=serverAuth
keyUsage=critical,digitalSignature"

issue client demo-client \
  "extendedKeyUsage=clientAuth
keyUsage=critical,digitalSignature"

rm -f ca.srl
echo
echo "Generated:"
ls -1 "$OUT"/*.crt "$OUT"/*.key
echo
echo "Verify chain:"
"$OPENSSL_BIN" verify -CAfile ca.crt server.crt client.crt
