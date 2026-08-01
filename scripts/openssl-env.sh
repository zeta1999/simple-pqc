#!/usr/bin/env bash
# Resolves a PQC-capable openssl (>= 3.5, supports X25519MLKEM768 + ML-DSA).
# On this Mac the PATH openssl is miniconda's 3.0.17 and /usr/bin/openssl is
# LibreSSL -- neither does PQC. Prefer Homebrew's 3.6.3.
#
# NB: this file is *sourced*, so it must not change the caller's shell options.
# It used to `set -euo pipefail`, which forced -e onto every caller -- scripts
# that deliberately run failing commands (negative tests) then died silently on
# the first expected failure instead of reporting it.

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
  echo "       macOS: brew install openssl@3   (Homebrew's is 3.6.x)" >&2
  echo "       Linux: needs a distro with OpenSSL >=3.5 (Ubuntu >=25.10 / Debian >=13);" >&2
  echo "              older LTS ship 3.0.x -- use a container (alpine:3.22) or set OPENSSL=/path." >&2
  return 1
}

# Abort the caller if no PQC-capable openssl exists (previously a side effect
# of the leaked `set -e`); `return` when sourced, `exit` if run directly.
if ! OPENSSL_BIN="$(pick_openssl)"; then
  return 1 2>/dev/null || exit 1
fi
export OPENSSL_BIN
