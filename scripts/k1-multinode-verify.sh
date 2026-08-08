#!/usr/bin/env bash
# Track K1, multi-node: PQC KEM across a REAL two-node k3s cluster.
#
# Every other k3s result in this repo is a single privileged container, which
# never exercises cross-node traffic. This brings up server + agent on their own
# docker network with EMBEDDED ETCD (--cluster-init) and proves two things:
#
#   [1] CONTROL plane -- probe each endpoint from a third container:
#         :6443  kube-apiserver        :10250 kubelet (BOTH nodes)
#         :2379  etcd client           :2380  etcd peer
#   [2] DATA plane -- Linkerd mesh mTLS between pods pinned to DIFFERENT nodes,
#       captured inside the flannel VXLAN tunnel they are encapsulated in.
#
# PQC property: post-quantum KEY EXCHANGE, zero configuration -- it rides the Go
# 1.24+ toolchain that k8s >= 1.33 is built with. Cluster PKI stays classical
# (ECDSA P-256); nothing here issues ML-DSA certs.
#
# [2] needs a Linkerd install (CLI download + Gateway API CRDs + manifests),
# which is the flaky part. If any of that cannot be set up the section is
# SKIPPED with a reason rather than failed, so [1] still reports. Section [1]
# needs nothing but Docker.
#
#   ./scripts/k1-multinode-verify.sh          # both
#   ./scripts/k1-multinode-verify.sh 1        # control plane only (no Linkerd)
#   SKIP_LINKERD=1 ./scripts/k1-multinode-verify.sh   # same, via env
#   STRICT=1 ./scripts/k1-multinode-verify.sh # treat any SKIP as a failure (CI)
#   KEEP=1 ./scripts/k1-multinode-verify.sh   # leave the cluster up
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
sel="${*:-1 2}"
K3S_TAG="${K3S_TAG:-v1.36.2-k3s1}"
NET="${NET:-pqc-net}"
TOKEN="${TOKEN:-pqcdemotoken123}"
LINKERD_VER="${LINKERD_VER:-edge-26.8.1}"
GATEWAY_API_VER="${GATEWAY_API_VER:-v1.2.1}"
WORK="${WORK:-${TMPDIR:-/tmp}/pqc-mn}"
PQC_GROUP_DEC=4588
# alpine 3.22 ships OpenSSL 3.5.x, which is the minimum for X25519MLKEM768.
PROBE_IMAGE="${PROBE_IMAGE:-alpine:3.22}"

docker info >/dev/null 2>&1 || { echo "ERROR: Docker engine not reachable."; exit 1; }
mkdir -p "$WORK"
export KUBECONFIG="$WORK/kubeconfig.yaml"
pass=0; fail=0; skip=0; note=()

cleanup() {
  [ -n "${KEEP:-}" ] && { echo; echo "KEEP=1: cluster left up. export KUBECONFIG=$KUBECONFIG"; return; }
  docker rm -f pqc-k3s-server pqc-k3s-agent pqc-vxlan-cap >/dev/null 2>&1
  docker network rm "$NET" >/dev/null 2>&1
}
trap cleanup EXIT

echo "### two-node k3s $K3S_TAG (server + agent, embedded etcd)"
docker rm -f pqc-k3s-server pqc-k3s-agent pqc-vxlan-cap >/dev/null 2>&1
docker network rm "$NET" >/dev/null 2>&1
rm -f "$KUBECONFIG"
docker network create "$NET" >/dev/null 2>&1 || { echo "ERROR: could not create network"; exit 1; }

# --cluster-init selects embedded etcd instead of sqlite, which is what puts
# :2379/:2380 on the wire at all -- a default single-server k3s has no etcd.
# :6443 is published because the linkerd CLI in [2] renders its manifests against
# a LIVE cluster -- without a reachable kubeconfig it emits nothing and the
# apply fails with the misleading "no objects passed to apply".
docker run -d --name pqc-k3s-server --privileged --network "$NET" \
  --hostname pqc-k3s-server -p 6443:6443 -e K3S_TOKEN="$TOKEN" \
  -v "$WORK":/output \
  "rancher/k3s:$K3S_TAG" server --cluster-init \
  --write-kubeconfig /output/kubeconfig.yaml --write-kubeconfig-mode 644 \
  --disable=traefik,servicelb,metrics-server --node-name server0 >/dev/null 2>&1 \
  || { echo "ERROR: could not start the server node"; exit 1; }

echo -n "waiting for the server node ..."
for i in $(seq 1 60); do
  [ "$(docker exec pqc-k3s-server kubectl get nodes --no-headers 2>/dev/null | grep -c ' Ready ')" -ge 1 ] && break
  sleep 5
done; echo

docker run -d --name pqc-k3s-agent --privileged --network "$NET" \
  --hostname pqc-k3s-agent -e K3S_TOKEN="$TOKEN" \
  -e K3S_URL=https://pqc-k3s-server:6443 \
  "rancher/k3s:$K3S_TAG" agent --node-name agent0 >/dev/null 2>&1 \
  || { echo "ERROR: could not start the agent node"; exit 1; }

echo -n "waiting for the agent to join ..."
for i in $(seq 1 60); do
  [ "$(docker exec pqc-k3s-server kubectl get nodes --no-headers 2>/dev/null | grep -c ' Ready ')" -ge 2 ] && break
  sleep 5
done; echo
docker exec pqc-k3s-server kubectl get nodes 2>&1 | tail -3

nodes="$(docker exec pqc-k3s-server kubectl get nodes --no-headers 2>/dev/null | grep -c ' Ready ')"
if [ "${nodes:-0}" -lt 2 ]; then
  echo "ERROR: only ${nodes:-0} node(s) Ready -- cannot test the cross-node leg"
  echo "-- agent logs --"; docker logs pqc-k3s-agent 2>&1 | tail -15
  exit 1
fi

if [[ " $sel " != *" 1 "* ]]; then out=""; else
echo
echo "### [1] probing each endpoint with a PQC-only client (from a third container)"
out="$(docker run --rm --network "$NET" "$PROBE_IMAGE" sh -c '
  apk add --no-cache openssl >/dev/null 2>&1
  echo "probe openssl: $(openssl version)"
  for ep in pqc-k3s-server:6443 pqc-k3s-server:10250 pqc-k3s-agent:10250 \
            pqc-k3s-server:2379 pqc-k3s-server:2380; do
    printf "%-26s -> " "$ep"
    g=$(echo Q | openssl s_client -connect $ep -tls1_3 -groups X25519MLKEM768 2>&1 \
        | grep -oE "Negotiated TLS1.3 group: [A-Za-z0-9]+" | awk "{print \$NF}" | head -1)
    echo "${g:-<no handshake>}"
  done' 2>&1)"
echo "$out"

# every probed endpoint must have selected the PQC group
total="$(echo "$out" | grep -c ' -> ')"
ok="$(echo "$out" | grep -c 'X25519MLKEM768')"
if [ "${total:-0}" -eq 5 ] && [ "${ok:-0}" -eq 5 ]; then
  note+=("PASS [1] control plane: 5/5 endpoints negotiated X25519MLKEM768"); pass=$((pass+1))
else
  note+=("FAIL [1] control plane: only ${ok:-0}/${total:-0} endpoints negotiated the PQC group"); fail=$((fail+1))
fi
fi

# --- [2] cross-node POD traffic, inside the flannel VXLAN tunnel -------------
if [[ " $sel " == *" 2 "* ]]; then
  echo; echo "### [2] cross-node pod mTLS (Linkerd $LINKERD_VER) through flannel VXLAN"
  case "$(uname -s)-$(uname -m)" in
    Darwin-arm64) LD_ARCH=darwin-arm64 ;;  Darwin-x86_64) LD_ARCH=darwin-amd64 ;;
    Linux-aarch64) LD_ARCH=linux-arm64 ;;  Linux-x86_64) LD_ARCH=linux-amd64 ;;
    *) LD_ARCH="" ;;
  esac
  LD="$WORK/linkerd"
  if [ -n "$LD_ARCH" ] && [ ! -x "$LD" ]; then
    curl -sSfL "https://github.com/linkerd/linkerd2/releases/download/$LINKERD_VER/linkerd2-cli-$LINKERD_VER-$LD_ARCH" -o "$LD" && chmod +x "$LD"
  fi

  if [ -n "${SKIP_LINKERD:-}" ]; then
    echo "SKIP: SKIP_LINKERD set"
    note+=("SKIP [2] cross-node pod mTLS -- SKIP_LINKERD set"); skip=$((skip+1))
  elif [ ! -x "$LD" ]; then
    echo "SKIP: could not download the linkerd CLI ($LINKERD_VER/$LD_ARCH)"
    note+=("SKIP [2] cross-node pod mTLS -- CLI download failed"); skip=$((skip+1))
  else
    # Linkerd requires the Gateway API CRDs. k3s normally gets them from its
    # bundled Traefik -- which is disabled here, so install them explicitly or
    # `linkerd install` refuses to render anything.
    kubectl apply --server-side -f \
      "https://github.com/kubernetes-sigs/gateway-api/releases/download/$GATEWAY_API_VER/standard-install.yaml" >/dev/null 2>&1
    "$LD" install --crds 2>/dev/null | kubectl apply -f - >/dev/null 2>&1
    "$LD" install 2>/dev/null | kubectl apply -f - >/dev/null 2>&1
    kubectl -n linkerd rollout status deploy/linkerd-destination --timeout=420s 2>&1 | tail -1
    kubectl -n linkerd rollout status deploy/linkerd-proxy-injector --timeout=420s 2>&1 | tail -1
  fi

  # A failed render leaves no namespace at all -- distinguish "could not install"
  # from "installed and the PQC assertion failed", which are very different results.
  if [ "${skip:-0}" -eq 0 ] && ! kubectl -n linkerd get deploy linkerd-proxy-injector >/dev/null 2>&1; then
    echo "SKIP: linkerd control plane did not come up (render or apply failed)"
    "$LD" install --crds >/dev/null 2>"$WORK/linkerd.err" || true
    [ -s "$WORK/linkerd.err" ] && { echo "-- linkerd said --"; head -4 "$WORK/linkerd.err"; }
    note+=("SKIP [2] cross-node pod mTLS -- linkerd control plane unavailable"); skip=$((skip+1))
  elif [ "${skip:-0}" -eq 0 ]; then

    kubectl create namespace xnode >/dev/null 2>&1
    kubectl annotate namespace xnode linkerd.io/inject=enabled --overwrite >/dev/null 2>&1
    # nodeSelector pins the two ends to DIFFERENT nodes; without this the
    # scheduler may co-locate them and the traffic never enters the tunnel.
    kubectl apply -f - >/dev/null 2>&1 <<'YAML'
apiVersion: apps/v1
kind: Deployment
metadata: {name: whoami, namespace: xnode}
spec:
  replicas: 1
  selector: {matchLabels: {app: whoami}}
  template:
    metadata: {labels: {app: whoami}}
    spec:
      nodeSelector: {kubernetes.io/hostname: agent0}
      containers:
        - name: whoami
          image: traefik/whoami:v1.10
          ports: [{containerPort: 80}]
---
apiVersion: v1
kind: Service
metadata: {name: whoami, namespace: xnode}
spec:
  selector: {app: whoami}
  ports: [{port: 80, targetPort: 80}]
YAML
    kubectl -n xnode rollout status deploy/whoami --timeout=420s 2>&1 | tail -1

    docker rm -f pqc-vxlan-cap >/dev/null 2>&1
    docker run -d --name pqc-vxlan-cap --net=container:pqc-k3s-server --privileged \
      -v "$WORK":/out nicolaka/netshoot:latest \
      timeout 100 tcpdump -i any -s 0 -w /out/vxlan.pcap 'udp port 8472' >/dev/null 2>&1
    sleep 5
    kubectl -n xnode delete pod xclient --force --grace-period=0 >/dev/null 2>&1
    kubectl -n xnode run xclient --image=curlimages/curl:8.11.1 --restart=Never \
      --overrides='{"spec":{"nodeSelector":{"kubernetes.io/hostname":"server0"}}}' \
      --command -- sh -c 'sleep 5; for i in $(seq 1 60); do curl -s http://whoami/ >/dev/null; sleep 1; done' >/dev/null 2>&1
    kubectl -n xnode wait --for=condition=Ready pod/xclient --timeout=420s >/dev/null 2>&1
    kubectl -n xnode get pods -o wide --no-headers 2>/dev/null | awk '{printf "  %-26s %-12s %s\n",$1,$6,$7}'

    docker wait pqc-vxlan-cap >/dev/null 2>&1
    docker rm -f pqc-vxlan-cap >/dev/null 2>&1

    # tshark decapsulates VXLAN on its own -- the ip.src/ip.dst fields come back
    # as "outer,inner". It does NOT know 4143 is TLS, hence the -d.
    xsel="$(docker run --rm -v "$WORK":/out nicolaka/netshoot:latest \
      tshark -r /out/vxlan.pcap -d tcp.port==4143,tls -Y 'tls.handshake.type==2' \
      -T fields -e ip.src -e ip.dst -e tls.handshake.extensions_key_share_group 2>/dev/null | head -1)"
    xoff="$(docker run --rm -v "$WORK":/out nicolaka/netshoot:latest \
      tshark -r /out/vxlan.pcap -d tcp.port==4143,tls -Y 'tls.handshake.type==1' \
      -T fields -e tls.handshake.extensions_supported_group 2>/dev/null | head -1)"
    grp="$(echo "$xsel" | awk '{print $NF}')"
    echo "  ClientHello offered      : ${xoff:-<none>}"
    echo "  ServerHello (outer,inner): ${xsel:-<none>}"

    if [ "$grp" = "$PQC_GROUP_DEC" ]; then
      note+=("PASS [2] cross-node pod mTLS negotiated X25519MLKEM768 inside VXLAN"); pass=$((pass+1))
    else
      note+=("FAIL [2] cross-node pod mTLS selected=${grp:-none}"); fail=$((fail+1))
    fi
  fi
fi

echo
echo "======================================================================"
printf '%s\n' ${note[@]+"${note[@]}"}
echo "TOTAL: $pass passed, $fail failed, $skip skipped"
cat <<'NOTE'

The control-plane cross-node leg is pqc-k3s-agent:10250 -- a kubelet on a
DIFFERENT node from the apiserver. etcd :2379/:2380 only exist because of
--cluster-init; a default single-server k3s uses sqlite and has no etcd
listener at all.

In [2] the ServerHello's address field reads "outer,inner": the outer pair is
the two NODE addresses and the inner pair is the two POD addresses. That is the
encapsulation itself, and it is what proves the handshake genuinely crossed the
node boundary rather than being served by a co-located pod.

Identity stays classical throughout -- Linkerd issues ECDSA P-256 workload certs.
NOTE
if [ "$skip" -gt 0 ] && [ -n "${STRICT:-}" ]; then
  echo "STRICT=1: treating $skip skipped section(s) as failure"
  exit 1
fi
[ "$fail" -eq 0 ]
