#!/usr/bin/env bash
# Run every locally-verifiable PQC experiment and print a pass/fail summary.
# (Container + k3s tracks need a Docker daemon / cluster and are not included.)
#
# Optional modules: some experiments need things this repo does not vendor -- a
# sibling checkout, a Homebrew OpenSSH, a PQC-capable openssl. Those are SKIPPED
# with a reason rather than failed, so a partial toolchain still gives a useful
# run. Only a real assertion failure sets a non-zero exit.
#
#   ./scripts/run-all.sh                 # run what this machine can
#   SKIP_CHANNEL=1 ./scripts/run-all.sh  # force-skip E8 (sibling repos)
#   SKIP_MLDSA=1   ./scripts/run-all.sh  # force-skip the ML-DSA tracks (E7/E15)
#   STRICT=1       ./scripts/run-all.sh  # treat any SKIP as a failure (CI)
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
source "$HERE/openssl-env.sh" 2>/dev/null || true
pass=0; fail=0; skip=0; results=()

step() { # label  command...
  local label="$1"; shift
  echo "======================================================================"
  echo "### $label"
  echo "======================================================================"
  if "$@"; then results+=("PASS  $label"); pass=$((pass+1))
  else          results+=("FAIL  $label"); fail=$((fail+1)); fi
  echo
}

skip_step() { # label  reason
  echo "======================================================================"
  echo "### $1"
  echo "SKIP: $2"
  echo "======================================================================"
  results+=("SKIP  $1")
  echo "      reason: $2"
  skip=$((skip+1))
  echo
}

# --- what can this machine actually do? --------------------------------------
# E8's channel crate resolves cargo path deps to sibling checkouts; without them
# `cargo run` fails on a missing Cargo.toml, which is a setup problem and not a
# PQC result. Detect it up front instead of reporting a red FAIL.
channel_reason=""
[ -n "${SKIP_CHANNEL:-}" ] && channel_reason="SKIP_CHANNEL set"
if [ -z "$channel_reason" ]; then
  for repo in simple-network rust-secure-memory; do
    [ -f "$ROOT/../$repo/Cargo.toml" ] || channel_reason="../$repo not checked out"
  done
fi
command -v cargo >/dev/null 2>&1 || channel_reason="${channel_reason:-cargo not installed}"

# E7/E15 need an OpenSSL >= 3.5 that actually has the PQC group.
mldsa_reason=""
[ -n "${SKIP_MLDSA:-}" ] && mldsa_reason="SKIP_MLDSA set"
if [ -z "$mldsa_reason" ]; then
  "${OPENSSL_BIN:-openssl}" list -tls-groups 2>/dev/null | grep -qi X25519MLKEM768 \
    || mldsa_reason="${OPENSSL_BIN:-openssl} has no X25519MLKEM768 (need >= 3.5)"
fi

# E6 needs an sshd binary and an OpenSSH that knows the standardized PQC KEX.
ssh_reason=""
[ -n "${SKIP_SSH:-}" ] && ssh_reason="SKIP_SSH set"
if [ -z "$ssh_reason" ]; then
  command -v sshd >/dev/null 2>&1 || [ -x /usr/sbin/sshd ] || ssh_reason="no sshd binary found"
  [ -z "$ssh_reason" ] && { ssh -Q kex 2>/dev/null | grep -qx mlkem768x25519-sha256 \
    || ssh_reason="this OpenSSH has no mlkem768x25519-sha256 (need >= 9.9)"; }
fi

step "E5 cross-language interop (Go/Rust/openssl, PQC KEM)" "$HERE/interop.sh"

if [ -n "$ssh_reason" ]; then
  skip_step "E6 PQC SSH to non-root sshd (mlkem768x25519)" "$ssh_reason"
else
  step "E6 PQC SSH to non-root sshd (mlkem768x25519)" "$HERE/ssh-pqc-demo.sh"
fi

if [ -n "$mldsa_reason" ]; then
  skip_step "E7 fully-PQC mTLS (ML-DSA-65 certs)" "$mldsa_reason"
else
  step "E7 fully-PQC mTLS (ML-DSA-65 certs)" "$HERE/mldsa-tls-demo.sh"
fi

if [ -n "$channel_reason" ]; then
  skip_step "E8 simple-network PQC channel (ML-DSA-65 auth)" "$channel_reason"
else
  step "E8 simple-network PQC channel (ML-DSA-65 auth)" bash -c "cd '$ROOT/channel' && cargo run -q"
fi

if [ -n "$mldsa_reason" ]; then
  skip_step "E15 fully-PQC mTLS in Rust + openssl interop" "$mldsa_reason"
else
  step "E15 fully-PQC mTLS in Rust + openssl interop" "$HERE/mldsa-rust-demo.sh"
fi

echo "======================================================================"
printf '%s\n' ${results[@]+"${results[@]}"}
echo "----------------------------------------------------------------------"
echo "TOTAL: $pass passed, $fail failed, $skip skipped"
if [ "$skip" -gt 0 ] && [ -n "${STRICT:-}" ]; then
  echo "STRICT=1: treating $skip skipped experiment(s) as failure"
  exit 1
fi
[ "$fail" -eq 0 ]
