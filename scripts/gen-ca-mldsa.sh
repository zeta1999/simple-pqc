#!/usr/bin/env bash
# Track 5 (EXPERIMENTAL): a fully post-quantum PKI -- ML-DSA-65 CA + leaf certs.
#
# This is PQC *authentication* (the cert signatures are ML-DSA-65 / FIPS 204),
# not just a PQC KEM. Requires OpenSSL >= 3.5. Note: ML-DSA certs are large and
# no public trust store has ML-DSA roots -> private PKI only. Interop today is
# OpenSSL <-> OpenSSL and OpenSSL <-> rustls(unstable); Go waits for 1.27.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$HERE/openssl-env.sh"
ALG="${MLDSA_ALG:-ML-DSA-65}"
OUT="${1:-$HERE/../certs-mldsa}"
mkdir -p "$OUT"; cd "$OUT"

echo "openssl: $OPENSSL_BIN ($("$OPENSSL_BIN" version))"
echo "alg:     $ALG"

gen_key() { "$OPENSSL_BIN" genpkey -algorithm "$ALG" -out "$1"; }

gen_key ca.key
"$OPENSSL_BIN" req -x509 -new -key ca.key -days 3650 \
  -subj "/CN=simple-pqc-mldsa-ca/O=simple-pqc" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -out ca.crt

issue() { # name CN exts
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

echo; echo "Signature algorithm in each cert:"
for c in ca server client; do
  printf '  %-7s -> ' "$c.crt"
  "$OPENSSL_BIN" x509 -in "$c.crt" -noout -text | grep -m1 'Signature Algorithm' | sed 's/^ *//'
done
echo; echo "Verify chain:"; "$OPENSSL_BIN" verify -CAfile ca.crt server.crt client.crt
