#!/usr/bin/env bash
# Container-based PQC verification (needs a working Docker engine).
# Covers the tracks that can't run on macOS:
#   [1] task #12  linux<->linux: the full suite inside Debian 13 (trixie)
#   [2] Track K1  k3s control-plane PQC KEM probe (rancher/k3s in Docker)
#   [3] Track S4  experimental ML-DSA SSH auth (Debian sid, OpenSSH 10.4)
#   [4] Track S3  legacy LTS: Ubuntu 24.04 / Debian 12 have no mlkem or ML-DSA,
#                 only the pre-standard sntrup761 KEX
#
# Usage: ./scripts/docker-linux-verify.sh [1|2|3|4 ...]   (default: all)
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
source "$HERE/openssl-env.sh" 2>/dev/null || true
sel="${*:-1 2 3 4 5 6}"

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
# PLATFORM=linux/amd64 runs the same suite under emulation on an arm64 host.
# That covers the ARCH dimension of the code, not real amd64 silicon -- Rosetta
# still executes amd64 instructions, so a genuine amd64 box remains untested.
if [[ " $sel " == *" 1 "* ]]; then
  plat_args=()
  [ -n "${PLATFORM:-}" ] && plat_args=(--platform "$PLATFORM")
  echo; echo "### [1] Debian 13 (trixie): full suite (E5/E6/E7/E8/E15)${PLATFORM:+ [$PLATFORM]}"
  if docker run --rm -v "$ROOT":/src:ro "${sib_mount[@]}" ${plat_args[@]+"${plat_args[@]}"} debian:13 bash -euc '
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
  '; then note+=("PASS [1] debian:13 full suite${PLATFORM:+ [$PLATFORM]}"); pass=$((pass+1)); else note+=("FAIL [1] debian:13 full suite${PLATFORM:+ [$PLATFORM]}"); fail=$((fail+1)); fi
fi

# --- [2] k3s control-plane PQC KEM probe -------------------------------------
if [[ " $sel " == *" 2 "* ]]; then
  echo; echo "### [2] k3s (rancher/k3s) apiserver PQC KEM probe"
  # k8s inherits PQC KEM from Go >= 1.24, which first ships in k8s >= 1.33.
  # Liveness and the PQC assertion are probed SEPARATELY: an older k3s boots
  # fine but offers no PQC group, and a combined probe reports that misleadingly
  # as "apiserver did not come up" (measured: v1.31.5-k3s1 boots, no PQC group).
  K3S_TAG="${K3S_TAG:-v1.36.2-k3s1}"
  docker rm -f pqc-k3s >/dev/null 2>&1 || true
  if docker run -d --name pqc-k3s --privileged -p 6443:6443 \
       "rancher/k3s:$K3S_TAG" server --disable=traefik,servicelb,metrics-server >/dev/null 2>&1; then
    echo "waiting for apiserver :6443 (rancher/k3s:$K3S_TAG) ..."
    up=0; for i in $(seq 1 60); do
      ( echo Q | "${OPENSSL_BIN:-openssl}" s_client -connect 127.0.0.1:6443 -tls1_3 >/dev/null 2>&1 ) && { up=1; break; }
      sleep 3
    done
    if [ $up -eq 1 ]; then
      echo "apiserver is up; asserting PQC KEM"
      grp="$(echo Q | "${OPENSSL_BIN:-openssl}" s_client -connect 127.0.0.1:6443 -tls1_3 -groups X25519MLKEM768 2>&1 | grep -oE 'Negotiated TLS1.3 group: [A-Za-z0-9]+' | awk '{print $NF}' | head -1)"
      echo "kube-apiserver :6443 -> ${grp:-<none: PQC-only client was refused>}"
      if [ "$grp" = X25519MLKEM768 ]; then note+=("PASS [2] k3s $K3S_TAG apiserver negotiated X25519MLKEM768"); pass=$((pass+1))
      else note+=("FAIL [2] k3s $K3S_TAG offers no PQC group (needs k8s >= 1.33 / Go >= 1.24)"); fail=$((fail+1)); fi
    else
      echo "-- last container logs --"; docker logs pqc-k3s 2>&1 | tail -15
      note+=("FAIL [2] k3s $K3S_TAG apiserver did not come up"); fail=$((fail+1))
    fi
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

# --- [4] Track S3: legacy-LTS reality check ----------------------------------
# Ubuntu 24.04 (supported to 2029) and Debian 12 ship OpenSSH < 9.9 and
# OpenSSL < 3.5: no mlkem, no ML-DSA. Assert the *absence*, then show the
# pre-standard sntrup761 PQC KEX still gives HNDL resistance.
if [[ " $sel " == *" 4 "* ]]; then
  for img in ubuntu:24.04 debian:12; do
    echo; echo "### [4] $img: legacy fallback (expect no mlkem, sntrup761 works)"
    if docker run --rm -e IMG="$img" "$img" bash -euc '
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq; apt-get install -y -qq openssh-server openssh-client openssl >/dev/null
        mkdir -p /run/sshd
        echo "-- versions --"; ssh -V; openssl version
        # 1. mlkem must be ABSENT (that is the whole point of this track)
        if ssh -Q kex | grep -q "^mlkem768x25519-sha256$"; then
          echo "UNEXPECTED: $IMG has mlkem768x25519-sha256 -- docs need updating"; exit 1; fi
        echo "confirmed: no mlkem768x25519-sha256"
        # 2. OpenSSL must lack the hybrid TLS group
        if openssl list -tls-groups 2>/dev/null | grep -qi X25519MLKEM768; then
          echo "UNEXPECTED: $IMG openssl has X25519MLKEM768 -- docs need updating"; exit 1; fi
        echo "confirmed: no X25519MLKEM768 in openssl"
        # 3. the pre-standard PQC KEX must still work end to end
        KEX=sntrup761x25519-sha512@openssh.com
        ssh -Q kex | grep -qx "$KEX" || { echo "no $KEX either -- not PQC at all"; exit 1; }
        D=/root/s3; mkdir -p $D; chmod 700 $D; cd $D
        ssh-keygen -q -t ed25519 -N "" -f hostkey; ssh-keygen -q -t ed25519 -N "" -f userkey
        cat userkey.pub > authorized_keys; chmod 600 authorized_keys hostkey
        printf "%s\n" "Port 2222" "ListenAddress 127.0.0.1" "HostKey $D/hostkey" \
          "PidFile $D/sshd.pid" "AuthorizedKeysFile $D/authorized_keys" \
          "KexAlgorithms $KEX" "PasswordAuthentication no" "UsePAM no" \
          "StrictModes yes" "LogLevel VERBOSE" > sshd_config
        /usr/sbin/sshd -f $D/sshd_config -E $D/sshd.log || { cat $D/sshd.log; exit 1; }
        sleep 1
        ssh -F /dev/null -p 2222 -i $D/userkey -o KexAlgorithms=$KEX \
          -o IdentitiesOnly=yes -o UserKnownHostsFile=$D/known_hosts \
          -o StrictHostKeyChecking=no -vv 127.0.0.1 "echo S3_OK" >$D/out 2>$D/log
        cat $D/out; grep -m1 "kex: algorithm:" $D/log
        grep -q S3_OK $D/out && grep -q "kex: algorithm: $KEX" $D/log
    '; then note+=("PASS [4] $img legacy: no mlkem/ML-DSA, sntrup761 works"); pass=$((pass+1))
    else note+=("FAIL [4] $img legacy check"); fail=$((fail+1)); fi
  done
fi

# --- [5] capability probe across the distro matrix ---------------------------
# Cheap versions-and-capabilities sweep (no builds) to keep the table in
# docs/linux-support.md honest. Prints what each image actually ships.
if [[ " $sel " == *" 5 "* ]]; then
  echo; echo "### [5] distro capability matrix"
  printf '%-18s %-34s %-14s %-7s %-7s\n' IMAGE OPENSSH OPENSSL mlkem X25519MLKEM768
  for img in ubuntu:24.04 ubuntu:25.04 ubuntu:25.10 ubuntu:26.04 debian:12 debian:13 debian:sid; do
    row="$(docker run --rm "$img" bash -euc '
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq >/dev/null 2>&1
        apt-get install -y -qq openssh-client openssl >/dev/null 2>&1
        s="$(ssh -V 2>&1 | cut -d, -f1)"; o="$(openssl version | cut -d" " -f2)"
        ssh -Q kex 2>/dev/null | grep -qx mlkem768x25519-sha256 && k=yes || k=no
        openssl list -tls-groups 2>/dev/null | grep -qi X25519MLKEM768 && g=yes || g=no
        echo "$s|$o|$k|$g"' 2>/dev/null)" || row="|(pull/install failed)||"
    IFS='|' read -r s o k g <<<"$row"
    printf '%-18s %-34s %-14s %-7s %-7s\n' "$img" "${s:-?}" "${o:-?}" "${k:-?}" "${g:-?}"
  done
  note+=("INFO [5] capability matrix printed above (informational, no assertions)")
fi

# --- [6] Track S2: host ssh client -> linux container sshd, both arches -------
# The real cross-platform leg: this machine's own ssh client against a Debian 13
# sshd, PQC KEX pinned, on linux/arm64 AND linux/amd64 (the latter emulated).
if [[ " $sel " == *" 6 "* ]]; then
  S2D="$ROOT/ssh-demo-s2"
  rm -rf "$S2D"; mkdir -p "$S2D"; chmod 700 "$S2D"
  ssh-keygen -q -t ed25519 -N '' -f "$S2D/id_ed25519"
  for arch in arm64 amd64; do
    echo; echo "### [6] host ssh -> debian:13 sshd (linux/$arch), mlkem768x25519-sha256"
    docker rm -f "pqc-sshd-$arch" >/dev/null 2>&1 || true
    if ! docker run -d --name "pqc-sshd-$arch" --platform "linux/$arch" \
         -p 12222:22 -v "$S2D/id_ed25519.pub":/tmp/authk:ro debian:13 bash -c '
           export DEBIAN_FRONTEND=noninteractive
           apt-get update -qq >/dev/null 2>&1
           apt-get install -y -qq openssh-server >/dev/null 2>&1
           mkdir -p /run/sshd /root/.ssh && chmod 700 /root/.ssh
           cp /tmp/authk /root/.ssh/authorized_keys && chmod 600 /root/.ssh/authorized_keys
           printf "%s\n" "Port 22" "PermitRootLogin prohibit-password" \
             "KexAlgorithms mlkem768x25519-sha256" "PasswordAuthentication no" \
             "UsePAM no" "LogLevel VERBOSE" >> /etc/ssh/sshd_config
           exec /usr/sbin/sshd -D -e' >/dev/null 2>&1; then
      note+=("FAIL [6] linux/$arch sshd container did not start"); fail=$((fail+1)); continue
    fi
    # Wait for sshd to finish apt + bind. Probe the SSH banner, not a login:
    # a login attempt fails auth and would never report ready.
    up=0; for i in $(seq 1 60); do
      if banner="$( (exec 3<>/dev/tcp/127.0.0.1/12222 && head -c 8 <&3) 2>/dev/null )" \
         && [[ "$banner" == SSH-2.0* ]]; then up=1; break; fi
      sleep 3
    done
    if [ $up -eq 0 ]; then
      note+=("FAIL [6] linux/$arch sshd never became reachable"); fail=$((fail+1))
      docker rm -f "pqc-sshd-$arch" >/dev/null 2>&1; continue
    fi
    out="$(ssh -F /dev/null -p 12222 -i "$S2D/id_ed25519" \
        -o KexAlgorithms=mlkem768x25519-sha256 -o IdentitiesOnly=yes \
        -o UserKnownHostsFile="$S2D/known_hosts_$arch" -o StrictHostKeyChecking=no \
        -vv root@127.0.0.1 'echo S2_OK; uname -sm' 2>&1)"
    echo "$out" | grep -E '^(S2_OK|Linux)' || true
    echo "$out" | grep -m1 'kex: algorithm:' || true
    if grep -q S2_OK <<<"$out" && grep -q 'kex: algorithm: mlkem768x25519-sha256' <<<"$out"; then
      note+=("PASS [6] host ssh -> linux/$arch sshd over mlkem768x25519-sha256"); pass=$((pass+1))
    else
      note+=("FAIL [6] host ssh -> linux/$arch sshd"); fail=$((fail+1))
    fi
    docker rm -f "pqc-sshd-$arch" >/dev/null 2>&1 || true
  done
  echo "(key material left in $S2D for the Secretive variant; see PLAN.md Track S1)"
fi

echo; echo "======================================================================"
printf '%s\n' ${note[@]+"${note[@]}"}
echo "TOTAL: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
