#!/usr/bin/env bash
# Track 3: cross-language PQC mTLS interop matrix.
#
# Starts the Go and Rust servers, then probes each with the Go client, the Rust
# client, and `openssl s_client` -- printing the negotiated key-exchange group
# for every (client x server) pair. Every cell should read X25519MLKEM768.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
source "$HERE/openssl-env.sh"
SCRATCH="$(mktemp -d)"
CERTS="$ROOT/certs"

cleanup() { kill "${GOSRV:-}" "${RUSTSRV:-}" 2>/dev/null; wait 2>/dev/null; rm -rf "$SCRATCH"; }
trap cleanup EXIT

# --- prerequisites ------------------------------------------------------
[ -f "$CERTS/ca.crt" ] || "$HERE/gen-ca.sh" >/dev/null
echo "building go + rust ..."
( cd "$ROOT/go" && go build -o ./bin/pqc-server ./server && go build -o ./bin/pqc-client ./client )
( cd "$ROOT/rust" && cargo build -q )
GO="$ROOT/go/bin"; RS="$ROOT/rust/target/debug"

# --- servers ------------------------------------------------------------
CERT_DIR="$CERTS" ADDR=127.0.0.1:8443 "$GO/pqc-server" >"$SCRATCH/go-srv.log" 2>&1 & GOSRV=$!
CERT_DIR="$CERTS" ADDR=127.0.0.1:9443 "$RS/pqc-server" >"$SCRATCH/rust-srv.log" 2>&1 & RUSTSRV=$!
sleep 2

norm() { sed -E 's/^([A-Za-z0-9]+).*/\1/'; }   # keep first token (drop "(0x..)" suffix)

probe() { # client host port  ->  negotiated group or FAIL
  local client="$1" host="$2" port="$3" out kex=""
  case "$client" in
    go)   out="$(CERT_DIR="$CERTS" URL="https://$host:$port/" "$GO/pqc-client" 2>&1)";;
    rust) out="$(CERT_DIR="$CERTS" HOST="$host" PORT="$port" "$RS/pqc-client" 2>&1)";;
    openssl)
      out="$(echo Q | "$OPENSSL_BIN" s_client -connect "$host:$port" -servername localhost \
              -tls1_3 -groups X25519MLKEM768 -cert "$CERTS/client.crt" -key "$CERTS/client.key" \
              -CAfile "$CERTS/ca.crt" 2>&1)"
      kex="$(grep -oE 'Negotiated TLS1.3 group: [A-Za-z0-9]+' <<<"$out" | awk '{print $NF}' | head -1)"
      ;;
  esac
  if [ -z "$kex" ]; then
    kex="$(grep -oE '"kex":"[^"]*"' <<<"$out" | head -1 | sed -E 's/"kex":"//; s/".*//' | norm)"
  fi
  echo "${kex:-FAIL}"
}

# --- matrix -------------------------------------------------------------
echo
printf '%-16s | %-18s | %-18s\n' 'client \ server' 'go (:8443)' 'rust (:9443)'
printf '%-16s-+-%-18s-+-%-18s\n' '----------------' '------------------' '------------------'
rc=0
for client in go rust openssl; do
  g="$(probe "$client" 127.0.0.1 8443)"
  r="$(probe "$client" 127.0.0.1 9443)"
  printf '%-16s | %-18s | %-18s\n' "$client" "$g" "$r"
  [ "$g" = X25519MLKEM768 ] && [ "$r" = X25519MLKEM768 ] || rc=1
done
echo
if [ "$rc" = 0 ]; then echo "PASS: all pairs negotiated X25519MLKEM768 (PQC KEM)."
else echo "FAIL: at least one pair did not negotiate the PQC group."; fi
exit "$rc"
