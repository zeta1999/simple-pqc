#!/usr/bin/env bash
# Run every locally-verifiable PQC experiment and print a pass/fail summary.
# (Container + k3s tracks need a Docker daemon / cluster and are not included.)
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
pass=0; fail=0; results=()

step() { # label  command...
  local label="$1"; shift
  echo "======================================================================"
  echo "### $label"
  echo "======================================================================"
  if "$@"; then results+=("PASS  $label"); pass=$((pass+1))
  else          results+=("FAIL  $label"); fail=$((fail+1)); fi
  echo
}

step "E5 cross-language interop (Go/Rust/openssl, PQC KEM)" "$HERE/interop.sh"
step "E6 PQC SSH to non-root sshd (mlkem768x25519)"         "$HERE/ssh-pqc-demo.sh"
step "E7 fully-PQC mTLS (ML-DSA-65 certs)"                  "$HERE/mldsa-tls-demo.sh"
step "E8 simple-network PQC channel (ML-DSA-65 auth)"       bash -c "cd '$ROOT/channel' && cargo run -q"
step "E15 fully-PQC mTLS in Rust + openssl interop"        "$HERE/mldsa-rust-demo.sh"

echo "======================================================================"
printf '%s\n' "${results[@]}"
echo "----------------------------------------------------------------------"
echo "TOTAL: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
