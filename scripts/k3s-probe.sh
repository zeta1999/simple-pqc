#!/usr/bin/env bash
# Track K1: probe a k3s / RKE2 node's TLS endpoints for post-quantum KEM.
#
# On current k3s/RKE2 (Go 1.24+ toolchain) the control- and data-plane TLS
# negotiate X25519MLKEM768 with ZERO configuration. This just proves it.
#
#   ./scripts/k3s-probe.sh [HOST]        # default 127.0.0.1
#
# Notes:
#  - These endpoints use mTLS; without a client cert the HTTP layer will reject
#    us, but the TLS ServerHello still selects the KEM group, which is what we
#    read. Endpoints that abort on missing client cert show "<no handshake>";
#    the KEM verdict then comes from the ones that do complete.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$HERE/openssl-env.sh"
HOST="${1:-127.0.0.1}"

probe() { # port name
  local port="$1" name="$2" out grp
  out="$(echo Q | "$OPENSSL_BIN" s_client -connect "$HOST:$port" \
          -tls1_3 -groups X25519MLKEM768 2>&1)"
  grp="$(grep -oE 'Negotiated TLS1.3 group: [A-Za-z0-9]+' <<<"$out" | awk '{print $NF}' | head -1)"
  printf '  %-16s :%-6s -> %s\n' "$name" "$port" "${grp:-<no handshake>}"
}

echo "Probing k3s TLS endpoints on $HOST for PQC KEM (X25519MLKEM768):"
probe 6443  kube-apiserver
probe 10250 kubelet
probe 2379  etcd-client
probe 2380  etcd-peer
echo
echo "Expected on current k3s/RKE2: X25519MLKEM768 on endpoints that complete a"
echo "TLS handshake. Certificates remain classical (ECDSA P-256) -- PQC PKI is"
echo "not yet available upstream (see docs/k3s-pqc.md)."
