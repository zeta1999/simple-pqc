#!/usr/bin/env bash
# Container-based PQC verification (needs a working Docker engine).
# Covers the tracks that can't run on macOS:
#   [1] task #12  linux<->linux: the full suite inside Debian 13 (trixie)
#   [2] Track K1  k3s control-plane PQC KEM probe (rancher/k3s in Docker)
#   [3] Track S4  experimental ML-DSA SSH auth (Debian sid, OpenSSH 10.4)
#
# Usage: ./scripts/docker-linux-verify.sh [1|2|3 ...]   (default: all)
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
source "$HERE/openssl-env.sh" 2>/dev/null || true
sel="${*:-1 2 3}"

docker info >/dev/null 2>&1 || { echo "ERROR: Docker engine not reachable. Start Docker Desktop and retry."; exit 1; }
echo "docker: $(docker version --format '{{.Server.Version}}')  host-arch: $(docker info --format '{{.Architecture}}')"

pass=0; fail=0; note=()

# E8 builds against sibling checkouts via cargo path dependencies:
#   channel -> ../../simple-network -> ../rust-secure-memory/crates/secure-memory
# Mount each at the absolute path the chain resolves to inside the container
# (/work/channel/../../simple-network = /simple-network, and from there
# ../rust-secure-memory = /rust-secure-memory).
sib_mount=()
for repo in simple-network rust-secure-memory; do
  p="$(cd "$ROOT/../$repo" 2>/dev/null && pwd || true)"
  if [ -n "$p" ]; then sib_mount+=(-v "$p":"/$repo":ro)
  else echo "NOTE: $repo checkout not found -> E8 will fail in [1]"; fi
done

# --- [1] linux<->linux full suite in Debian 13 -------------------------------
if [[ " $sel " == *" 1 "* ]]; then
  echo; echo "### [1] Debian 13 (trixie): full suite (E5/E6/E7/E8)"
  if docker run --rm -v "$ROOT":/src:ro "${sib_mount[@]}" debian:13 bash -euc '
      export DEBIAN_FRONTEND=noninteractive
      apt-get update -qq
      apt-get install -y -qq openssh-server openssh-client openssl \
        cmake clang curl ca-certificates build-essential >/dev/null
      # sshd runs as root here, so the privsep dir must exist (Debian ships it
      # via systemd-tmpfiles, which containers do not run).
      mkdir -p /run/sshd
      # go.mod requires go >= 1.26; trixie ships 1.24, so fetch upstream.
      GOVER="$(curl -sSf https://go.dev/VERSION?m=text | head -1)"
      ARCH="$(dpkg --print-architecture)"
      curl -sSfL "https://go.dev/dl/${GOVER}.linux-${ARCH}.tar.gz" | tar -C /usr/local -xzf -
      export PATH=/usr/local/go/bin:$PATH
      curl -sSf https://sh.rustup.rs | sh -s -- -y -q >/dev/null; . "$HOME/.cargo/env"
      echo "-- versions --"; openssl version; ssh -V; go version; rustc --version
      cp -r /src /work && cd /work
      # drop macOS build artifacts copied in from the host tree
      rm -rf rust/target channel/target go/bin certs certs-mldsa ssh-demo
      ./scripts/run-all.sh
  '; then note+=("PASS [1] debian:13 full suite"); pass=$((pass+1)); else note+=("FAIL [1] debian:13 full suite"); fail=$((fail+1)); fi
fi

# --- [2] k3s control-plane PQC KEM probe -------------------------------------
if [[ " $sel " == *" 2 "* ]]; then
  echo; echo "### [2] k3s (rancher/k3s) apiserver PQC KEM probe"
  docker rm -f pqc-k3s >/dev/null 2>&1 || true
  if docker run -d --name pqc-k3s --privileged -p 6443:6443 \
       rancher/k3s:v1.36.2-k3s1 server --disable=traefik,servicelb,metrics-server >/dev/null 2>&1; then
    echo "waiting for apiserver :6443 ..."
    up=0; for i in $(seq 1 30); do
      ( echo Q | "${OPENSSL_BIN:-openssl}" s_client -connect 127.0.0.1:6443 -tls1_3 -groups X25519MLKEM768 >/dev/null 2>&1 ) && { up=1; break; }
      sleep 3
    done
    if [ $up -eq 1 ]; then
      grp="$(echo Q | "${OPENSSL_BIN:-openssl}" s_client -connect 127.0.0.1:6443 -tls1_3 -groups X25519MLKEM768 2>&1 | grep -oE 'Negotiated TLS1.3 group: [A-Za-z0-9]+' | awk '{print $NF}' | head -1)"
      echo "kube-apiserver :6443 -> ${grp:-<none>}"
      if [ "$grp" = X25519MLKEM768 ]; then note+=("PASS [2] k3s apiserver negotiated X25519MLKEM768"); pass=$((pass+1))
      else note+=("FAIL [2] k3s apiserver group=${grp:-none}"); fail=$((fail+1)); fi
    else note+=("FAIL [2] k3s apiserver did not come up"); fail=$((fail+1)); fi
    docker rm -f pqc-k3s >/dev/null 2>&1 || true
  else note+=("FAIL [2] could not start k3s container"); fail=$((fail+1)); fi
fi

# --- [3] Track S4: experimental ML-DSA SSH auth in Debian sid -----------------
if [[ " $sel " == *" 3 "* ]]; then
  echo; echo "### [3] Debian sid: mldsa44-ed25519 SSH (PQC KEX + PQC auth)"
  if docker run --rm debian:sid bash -euc '
      export DEBIAN_FRONTEND=noninteractive
      apt-get update -qq; apt-get install -y -qq openssh-server openssh-client >/dev/null
      mkdir -p /run/sshd   # privsep dir: sshd runs as root in this container
      ssh -V
      # OpenSSH 10.4 names the composite algorithm ssh-mldsa44-ed25519@openssh.com;
      # the bare name is rejected by *Algorithms options ("Bad key types").
      ALG=ssh-mldsa44-ed25519@openssh.com
      ssh -Q key-sig | grep -qx "$ALG" || { echo "no $ALG in this openssh"; exit 1; }
      D=/root/s4; mkdir -p $D; chmod 700 $D; cd $D
      ssh-keygen -q -t mldsa44-ed25519 -N "" -f hostkey
      ssh-keygen -q -t mldsa44-ed25519 -N "" -f userkey
      cat userkey.pub > authorized_keys; chmod 600 authorized_keys hostkey
      cat > sshd_config <<EOF
Port 2222
ListenAddress 127.0.0.1
HostKey $D/hostkey
PidFile $D/sshd.pid
AuthorizedKeysFile $D/authorized_keys
KexAlgorithms mlkem768x25519-sha256
HostKeyAlgorithms $ALG
PubkeyAcceptedAlgorithms $ALG
PubkeyAuthentication yes
PasswordAuthentication no
UsePAM no
StrictModes yes
LogLevel VERBOSE
EOF
      # -E sends startup/config errors to the logfile, so surface it on failure
      /usr/sbin/sshd -f $D/sshd_config -E $D/sshd.log || { cat $D/sshd.log; exit 1; }
      sleep 1
      ssh -F /dev/null -p 2222 -i $D/userkey \
        -o KexAlgorithms=mlkem768x25519-sha256 \
        -o HostKeyAlgorithms=$ALG \
        -o PubkeyAcceptedAlgorithms=$ALG \
        -o IdentitiesOnly=yes -o UserKnownHostsFile=$D/known_hosts \
        -o StrictHostKeyChecking=no -vv 127.0.0.1 "echo S4_OK" >$D/out 2>$D/log
      echo "-- client output --"; cat $D/out
      grep -m1 "kex: algorithm:" $D/log
      grep -m1 -E "Server host key: ssh-mldsa44-ed25519|Host key algorithm: ssh-mldsa44-ed25519" $D/log || true
      grep -q S4_OK $D/out && grep -q "kex: algorithm: mlkem768x25519-sha256" $D/log
  '; then note+=("PASS [3] sid mldsa44-ed25519 SSH (PQC KEX + PQC auth)"); pass=$((pass+1)); else note+=("FAIL [3] sid mldsa44-ed25519 SSH"); fail=$((fail+1)); fi
fi

echo; echo "======================================================================"
printf '%s\n' "${note[@]}"
echo "TOTAL: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
