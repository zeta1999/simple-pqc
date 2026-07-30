#!/usr/bin/env bash
# Resolves a PQC-capable openssl (>= 3.5, supports X25519MLKEM768 + ML-DSA).
# On this Mac the PATH openssl is miniconda's 3.0.17 and /usr/bin/openssl is
# LibreSSL -- neither does PQC. Prefer Homebrew's 3.6.3.
set -euo pipefail

pick_openssl() {
  local candidates=(
    "${OPENSSL:-}"
    /opt/homebrew/bin/openssl
    /opt/homebrew/opt/openssl@3/bin/openssl
    /usr/local/opt/openssl@3/bin/openssl
    openssl
  )
  for c in "${candidates[@]}"; do
    [ -z "$c" ] && continue
    command -v "$c" >/dev/null 2>&1 || continue
    # Must know the hybrid PQC group (OpenSSL >= 3.5).
    if "$c" list -tls-groups 2>/dev/null | grep -qi 'X25519MLKEM768'; then
      echo "$c"; return 0
    fi
    if "$c" list -kem-algorithms 2>/dev/null | grep -qi 'X25519MLKEM768'; then
      echo "$c"; return 0
    fi
  done
  echo "ERROR: no PQC-capable openssl found (need >=3.5 with X25519MLKEM768)." >&2
  echo "       Install with: brew install openssl@3" >&2
  return 1
}

OPENSSL_BIN="$(pick_openssl)"
export OPENSSL_BIN
