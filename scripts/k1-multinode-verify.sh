#!/usr/bin/env bash
# Track K1, multi-node: PQC KEM across a REAL two-node k3s cluster.
#
# Every other k3s result in this repo is a single privileged container, which
# never exercises cross-node traffic. This brings up server + agent on their own
# docker network with EMBEDDED ETCD (--cluster-init) and probes each control
# plane endpoint from a third container on that network:
#
#   :6443  kube-apiserver          :10250 kubelet (BOTH nodes -- the cross-node leg)
#   :2379  etcd client             :2380  etcd peer
#
# PQC property: post-quantum KEY EXCHANGE, zero configuration -- it rides the Go
# 1.24+ toolchain that k8s >= 1.33 is built with. Cluster PKI stays classical
# (ECDSA P-256); nothing here issues ML-DSA certs.
#
#   ./scripts/k1-multinode-verify.sh
#   KEEP=1 ./scripts/k1-multinode-verify.sh   # leave the cluster up
set -uo pipefail
K3S_TAG="${K3S_TAG:-v1.36.2-k3s1}"
NET="${NET:-pqc-net}"
TOKEN="${TOKEN:-pqcdemotoken123}"
# alpine 3.22 ships OpenSSL 3.5.x, which is the minimum for X25519MLKEM768.
PROBE_IMAGE="${PROBE_IMAGE:-alpine:3.22}"

docker info >/dev/null 2>&1 || { echo "ERROR: Docker engine not reachable."; exit 1; }

cleanup() {
  [ -n "${KEEP:-}" ] && { echo; echo "KEEP=1: cluster left up (docker network $NET)"; return; }
  docker rm -f pqc-k3s-server pqc-k3s-agent >/dev/null 2>&1
  docker network rm "$NET" >/dev/null 2>&1
}
trap cleanup EXIT

echo "### two-node k3s $K3S_TAG (server + agent, embedded etcd)"
docker rm -f pqc-k3s-server pqc-k3s-agent >/dev/null 2>&1
docker network rm "$NET" >/dev/null 2>&1
docker network create "$NET" >/dev/null 2>&1 || { echo "ERROR: could not create network"; exit 1; }

# --cluster-init selects embedded etcd instead of sqlite, which is what puts
# :2379/:2380 on the wire at all -- a default single-server k3s has no etcd.
docker run -d --name pqc-k3s-server --privileged --network "$NET" \
  --hostname pqc-k3s-server -e K3S_TOKEN="$TOKEN" \
  "rancher/k3s:$K3S_TAG" server --cluster-init \
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

echo
echo "### probing each endpoint with a PQC-only client (from a third container)"
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
echo
echo "======================================================================"
if [ "${total:-0}" -eq 5 ] && [ "${ok:-0}" -eq 5 ]; then
  echo "PASS multi-node: all 5 endpoints negotiated X25519MLKEM768 ($ok/$total)"
  echo "TOTAL: 1 passed, 0 failed"
else
  echo "FAIL multi-node: only $ok/${total:-0} endpoints negotiated the PQC group"
  echo "TOTAL: 0 passed, 1 failed"
  exit 1
fi
cat <<'NOTE'

The cross-node leg is pqc-k3s-agent:10250 -- a kubelet on a DIFFERENT node from
the apiserver, reached over the container network. etcd :2379/:2380 only exist
because of --cluster-init; a default single-server k3s uses sqlite and has no
etcd listener at all.

Scope: control plane only. Cross-node POD traffic is encapsulated in flannel
VXLAN, so proving mesh mTLS between pods on different nodes needs the capture to
be taken inside the tunnel -- not done here. Identity stays classical throughout.
NOTE
