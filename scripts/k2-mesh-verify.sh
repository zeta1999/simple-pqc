#!/usr/bin/env bash
# Track K2: PQC in the k3s data plane (needs a working Docker engine + kubectl).
#
#   [1] Traefik ingress terminates TLS with a post-quantum KEM, out of the box
#   [2] Linkerd pod<->pod mTLS negotiates the same PQC KEM, by default
#   [3] Istio COMPLIANCE_POLICY=pqc ENFORCES it -- classical peers cannot connect
#
# PQC property: post-quantum KEY EXCHANGE (harvest-now-decrypt-later) across the
# cluster DATA plane. Workload identity stays classical -- Linkerd issues ECDSA
# P-256 certs and no mesh does ML-DSA yet, so this is the KEM half only. (For the
# CONTROL plane see docker-linux-verify.sh section [2].)
#
# The [2] proof is a packet capture, not a config read: rustls_info reports which
# groups the proxy is *configured* to offer, which is not the same claim as which
# group the peers actually *negotiated*. We assert the ServerHello selection.
#
#   ./scripts/k2-mesh-verify.sh          # all three
#   ./scripts/k2-mesh-verify.sh 1        # ingress only (skips the mesh installs)
#   ./scripts/k2-mesh-verify.sh 3        # istio only -- it rebuilds the cluster,
#                                        #   since a cluster holds one mesh
#   KEEP=1 ./scripts/k2-mesh-verify.sh   # leave the cluster up for poking at
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
source "$HERE/openssl-env.sh" 2>/dev/null || true
OS="${OPENSSL_BIN:-openssl}"
sel="${*:-1 2 3}"

K3S_TAG="${K3S_TAG:-v1.36.2-k3s1}"
LINKERD_VER="${LINKERD_VER:-edge-26.8.1}"
ISTIO_VER="${ISTIO_VER:-1.30.3}"
WORK="${WORK:-${TMPDIR:-/tmp}/pqc-k2}"
HTTPS_PORT="${HTTPS_PORT:-18443}"
# 0x11EC. tshark prints the ServerHello key_share group in decimal.
PQC_GROUP_DEC=4588

docker info >/dev/null 2>&1 || { echo "ERROR: Docker engine not reachable."; exit 1; }
command -v kubectl >/dev/null 2>&1 || { echo "ERROR: kubectl not found."; exit 1; }

mkdir -p "$WORK"
export KUBECONFIG="$WORK/kubeconfig.yaml"
pass=0; fail=0; note=()

cleanup() {
  [ -n "${KEEP:-}" ] && { echo; echo "KEEP=1: cluster left up. export KUBECONFIG=$KUBECONFIG"; return; }
  docker rm -f pqc-k3s pqc-k2-cap >/dev/null 2>&1
}
trap cleanup EXIT

# --- cluster -----------------------------------------------------------------
# $1 = extra --disable list. Linkerd and Istio cannot share a cluster, so [3]
# calls this again to get a clean one rather than layering two meshes.
start_cluster() {
  echo "### bringing up k3s $K3S_TAG ${1:+(disabled: $1)}"
  docker rm -f pqc-k3s >/dev/null 2>&1
  rm -f "$KUBECONFIG"
  # servicelb must stay enabled for [1]: it is what binds :443 on the node, so
  # the published port reaches Traefik over a real network path rather than a
  # kubectl port-forward tunnel.
  docker run -d --name pqc-k3s --privileged \
    -p 6443:6443 -p "$HTTPS_PORT":443 \
    -v "$WORK":/output \
    "rancher/k3s:$K3S_TAG" server \
    --write-kubeconfig /output/kubeconfig.yaml --write-kubeconfig-mode 644 \
    --disable="metrics-server${1:+,$1}" >/dev/null 2>&1 || { echo "ERROR: could not start k3s"; return 1; }

  echo -n "waiting for node ..."
  for i in $(seq 1 90); do
    [ "$(kubectl get nodes --no-headers 2>/dev/null | grep -c ' Ready ')" -ge 1 ] && break
    sleep 5
  done
  kubectl get nodes 2>&1 | tail -1
}

if [[ " $sel " == *" 1 "* ]] || [[ " $sel " == *" 2 "* ]]; then
  start_cluster || exit 1
fi

# --- [1] Traefik PQC ingress termination -------------------------------------
if [[ " $sel " == *" 1 "* ]]; then
  echo; echo "### [1] Traefik ingress: PQC KEM termination"
  # The node reports Ready before the bundled helm-install job has created the
  # traefik Deployment, so wait for the object to EXIST before rollout status --
  # otherwise this races and dies on "deployments.apps not found".
  echo -n "waiting for the traefik deployment to appear ..."
  for i in $(seq 1 90); do
    kubectl -n kube-system get deploy traefik >/dev/null 2>&1 && break
    sleep 5
  done; echo
  kubectl -n kube-system rollout status deploy/traefik --timeout=420s 2>&1 | tail -1
  echo "traefik image: $(kubectl -n kube-system get deploy traefik -o jsonpath='{.spec.template.spec.containers[0].image}')"

  "$OS" req -x509 -newkey ed25519 -keyout "$WORK/tls.key" -out "$WORK/tls.crt" \
    -days 30 -nodes -subj "/CN=pqc.demo/O=simple-pqc" \
    -addext "subjectAltName=DNS:pqc.demo" >/dev/null 2>&1

  kubectl apply -f - >/dev/null 2>&1 <<'YAML'
apiVersion: v1
kind: Namespace
metadata: {name: pqc-demo}
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: whoami, namespace: pqc-demo}
spec:
  replicas: 1
  selector: {matchLabels: {app: whoami}}
  template:
    metadata: {labels: {app: whoami}}
    spec:
      containers:
        - name: whoami
          image: traefik/whoami:v1.10
          ports: [{containerPort: 80}]
---
apiVersion: v1
kind: Service
metadata: {name: whoami, namespace: pqc-demo}
spec:
  selector: {app: whoami}
  ports: [{port: 80, targetPort: 80}]
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata: {name: whoami, namespace: pqc-demo}
spec:
  ingressClassName: traefik
  tls: [{hosts: [pqc.demo], secretName: pqc-demo-tls}]
  rules:
    - host: pqc.demo
      http:
        paths:
          - path: /
            pathType: Prefix
            backend: {service: {name: whoami, port: {number: 80}}}
YAML
  kubectl -n pqc-demo create secret tls pqc-demo-tls \
    --cert="$WORK/tls.crt" --key="$WORK/tls.key" >/dev/null 2>&1
  kubectl -n pqc-demo rollout status deploy/whoami --timeout=300s 2>&1 | tail -1

  # PQC-only client: if Traefik lacked the group this handshake would fail.
  grp="$(echo Q | "$OS" s_client -connect "127.0.0.1:$HTTPS_PORT" -servername pqc.demo \
        -groups X25519MLKEM768 -tls1_3 2>&1 \
        | grep -oE 'Negotiated TLS1.3 group: [A-Za-z0-9]+' | awk '{print $NF}' | head -1)"
  echo "ingress :$HTTPS_PORT -> ${grp:-<none: PQC-only client refused>}"

  # ... and drive real HTTP through it, so this is an end-to-end ingress path
  # and not just a handshake against a listener. Traefik answers 503 until it
  # has observed the backend's Endpoints, which lands after the Deployment
  # reports rolled out -- so retry rather than asserting on the first try.
  code=""
  for i in $(seq 1 30); do
    code="$(printf 'GET / HTTP/1.1\r\nHost: pqc.demo\r\nConnection: close\r\n\r\n' \
          | "$OS" s_client -connect "127.0.0.1:$HTTPS_PORT" -servername pqc.demo \
            -groups X25519MLKEM768 -tls1_3 -quiet 2>/dev/null | head -1)"
    echo "$code" | grep -q "200 OK" && break
    sleep 3
  done
  echo "backend response: $code"

  if [ "$grp" = X25519MLKEM768 ] && echo "$code" | grep -q "200 OK"; then
    note+=("PASS [1] traefik ingress terminated X25519MLKEM768, backend 200"); pass=$((pass+1))
  else
    note+=("FAIL [1] traefik ingress group=${grp:-none} resp=${code:-none}"); fail=$((fail+1))
  fi
fi

# --- [2] Linkerd pod<->pod PQC mTLS ------------------------------------------
if [[ " $sel " == *" 2 "* ]]; then
  echo; echo "### [2] Linkerd $LINKERD_VER: pod<->pod mTLS over a PQC KEM"

  # host-local CLI download; nothing is installed system-wide
  case "$(uname -s)-$(uname -m)" in
    Darwin-arm64) LD_ARCH=darwin-arm64 ;;
    Darwin-x86_64) LD_ARCH=darwin-amd64 ;;
    Linux-aarch64) LD_ARCH=linux-arm64 ;;
    Linux-x86_64) LD_ARCH=linux-amd64 ;;
    *) echo "unsupported host for the linkerd CLI"; LD_ARCH="" ;;
  esac
  LD="$WORK/linkerd"
  if [ -n "$LD_ARCH" ] && [ ! -x "$LD" ]; then
    curl -sSfL "https://github.com/linkerd/linkerd2/releases/download/$LINKERD_VER/linkerd2-cli-$LINKERD_VER-$LD_ARCH" -o "$LD" && chmod +x "$LD"
  fi

  if [ ! -x "$LD" ]; then
    note+=("FAIL [2] could not obtain the linkerd CLI"); fail=$((fail+1))
  else
    "$LD" install --crds 2>/dev/null | kubectl apply -f - >/dev/null 2>&1
    "$LD" install 2>/dev/null | kubectl apply -f - >/dev/null 2>&1
    if "$LD" check >/dev/null 2>&1; then echo "linkerd check: healthy"
    else echo "linkerd check reported problems:"; "$LD" check 2>&1 | grep -E '^(×|‼)' | head -5; fi

    # mesh the namespace; existing pods need a restart to get a sidecar
    kubectl annotate namespace pqc-demo linkerd.io/inject=enabled --overwrite >/dev/null 2>&1
    kubectl -n pqc-demo rollout restart deploy/whoami >/dev/null 2>&1
    kubectl -n pqc-demo rollout status deploy/whoami --timeout=300s 2>&1 | tail -1

    # capture BEFORE the client exists, so we catch its first handshake
    docker rm -f pqc-k2-cap >/dev/null 2>&1
    docker run -d --name pqc-k2-cap --net=container:pqc-k3s --privileged -v "$WORK":/out \
      nicolaka/netshoot:latest \
      timeout 75 tcpdump -i any -s 0 -w /out/mesh.pcap 'tcp port 4143' >/dev/null 2>&1
    sleep 4

    kubectl -n pqc-demo delete pod client --force --grace-period=0 >/dev/null 2>&1
    kubectl -n pqc-demo run client --image=curlimages/curl:8.11.1 --restart=Never \
      --command -- sh -c 'sleep 3; for i in $(seq 1 40); do curl -s http://whoami/ >/dev/null; sleep 1; done' >/dev/null 2>&1
    kubectl -n pqc-demo wait --for=condition=Ready pod/client --timeout=300s >/dev/null 2>&1

    # Let traffic actually flow before reading anything. request_total only
    # gains an outbound series once the client has sent something, so scraping
    # straight after the pod goes Ready reports 0 mTLS requests on a healthy mesh.
    sleep 30

    # (a) what the proxy is CONFIGURED to offer
    kubectl -n pqc-demo exec client -c client -- curl -s localhost:4191/metrics 2>/dev/null > "$WORK/proxy-metrics.txt"
    rustls_line="$(grep '^rustls_info' "$WORK/proxy-metrics.txt" | head -1)"
    kx="$(echo "$rustls_line" | grep -oE 'tls_kx_groups="[^"]*"' | cut -d'"' -f2)"
    prov="$(echo "$rustls_line" | grep -oE 'tls_key_provider="[^"]*"' | cut -d'"' -f2)"
    echo "proxy tls_kx_groups : ${kx:-<none>}"
    echo "proxy key provider  : ${prov:-<none>}   (ring would mean no PQC at all)"
    # mutual TLS actually in use between the pods?
    mtls="$(grep -c 'direction="outbound".*tls="true"' "$WORK/proxy-metrics.txt")"
    echo "outbound requests over mTLS: $mtls"

    # (b) what the peers actually NEGOTIATED
    docker wait pqc-k2-cap >/dev/null 2>&1
    docker rm -f pqc-k2-cap >/dev/null 2>&1
    sel_grp="$(docker run --rm -v "$WORK":/out nicolaka/netshoot:latest \
      tshark -r /out/mesh.pcap -Y 'tls.handshake.type==2' \
      -T fields -e tls.handshake.extensions_key_share_group 2>/dev/null | head -1 | tr -d '\r')"
    offered="$(docker run --rm -v "$WORK":/out nicolaka/netshoot:latest \
      tshark -r /out/mesh.pcap -Y 'tls.handshake.type==1' \
      -T fields -e tls.handshake.extensions_supported_group 2>/dev/null | head -1 | tr -d '\r')"
    echo "ClientHello offered  : ${offered:-<none>}"
    echo "ServerHello selected : ${sel_grp:-<none>}  (want $PQC_GROUP_DEC = 0x11EC = X25519MLKEM768)"

    if [ "$sel_grp" = "$PQC_GROUP_DEC" ] && [ "${mtls:-0}" -gt 0 ]; then
      note+=("PASS [2] linkerd pod<->pod mTLS negotiated X25519MLKEM768 (captured)"); pass=$((pass+1))
    else
      note+=("FAIL [2] linkerd selected=${sel_grp:-none} mtls_requests=${mtls:-0}"); fail=$((fail+1))
    fi
  fi
fi

# --- [3] Istio COMPLIANCE_POLICY=pqc -----------------------------------------
# Unlike Linkerd (PQC-preferred, classical still offered), this mode ENFORCES:
# the sidecar offers X25519MLKEM768 and nothing else, so a classical-only peer
# cannot negotiate at all. The legacy client's failure is the demo.
if [[ " $sel " == *" 3 "* ]]; then
  echo; echo "### [3] Istio $ISTIO_VER: COMPLIANCE_POLICY=pqc (enforced, experimental)"
  case "$(uname -s)-$(uname -m)" in
    Darwin-arm64) IS_ARCH=osx-arm64 ;;  Darwin-x86_64) IS_ARCH=osx-amd64 ;;
    Linux-aarch64) IS_ARCH=linux-arm64 ;; Linux-x86_64) IS_ARCH=linux-amd64 ;;
    *) IS_ARCH="" ;;
  esac
  ISTIO_DIR="$WORK/istio-$ISTIO_VER"
  if [ -n "$IS_ARCH" ] && [ ! -x "$ISTIO_DIR/bin/istioctl" ]; then
    curl -sSfL "https://github.com/istio/istio/releases/download/$ISTIO_VER/istio-$ISTIO_VER-$IS_ARCH.tar.gz" \
      -o "$WORK/istio.tgz" && tar -xzf "$WORK/istio.tgz" -C "$WORK"
  fi
  ISTIOCTL="$ISTIO_DIR/bin/istioctl"

  if [ ! -x "$ISTIOCTL" ]; then
    note+=("FAIL [3] could not obtain istioctl"); fail=$((fail+1))
  else
    # a mesh per cluster: tear down whatever [1]/[2] built
    start_cluster "traefik,servicelb" || exit 1
    "$ISTIOCTL" install -y --set profile=minimal \
      --set values.pilot.env.COMPLIANCE_POLICY=pqc \
      --set meshConfig.defaultConfig.proxyMetadata.COMPLIANCE_POLICY=pqc 2>&1 | tail -2
    pol="$(kubectl -n istio-system get deploy istiod \
      -o jsonpath='{range .spec.template.spec.containers[0].env[?(@.name=="COMPLIANCE_POLICY")]}{.value}{end}' 2>/dev/null)"
    echo "istiod COMPLIANCE_POLICY=${pol:-<unset>}"

    kubectl create namespace istio-demo >/dev/null 2>&1
    kubectl label namespace istio-demo istio-injection=enabled --overwrite >/dev/null 2>&1
    kubectl -n istio-demo apply -f - >/dev/null 2>&1 <<'YAML'
apiVersion: apps/v1
kind: Deployment
metadata: {name: whoami, namespace: istio-demo}
spec:
  replicas: 1
  selector: {matchLabels: {app: whoami}}
  template:
    metadata: {labels: {app: whoami}}
    spec:
      containers:
        - name: whoami
          image: traefik/whoami:v1.10
          ports: [{containerPort: 80}]
---
apiVersion: v1
kind: Service
metadata: {name: whoami, namespace: istio-demo}
spec:
  selector: {app: whoami}
  ports: [{port: 80, targetPort: 80, name: http}]
---
apiVersion: security.istio.io/v1
kind: PeerAuthentication
metadata: {name: default, namespace: istio-demo}
spec:
  mtls: {mode: STRICT}
YAML
    kubectl -n istio-demo rollout status deploy/whoami --timeout=420s 2>&1 | tail -1

    # Istio redirects to :15006 with iptables INSIDE the destination pod, so on
    # the wire the port is still the service port -- capture 80, not 15006, and
    # tell tshark to dissect it as TLS (it assumes HTTP on 80 otherwise).
    docker rm -f pqc-k2-cap >/dev/null 2>&1
    docker run -d --name pqc-k2-cap --net=container:pqc-k3s --privileged -v "$WORK":/out \
      nicolaka/netshoot:latest \
      timeout 80 tcpdump -i any -s 0 -w /out/istio.pcap 'tcp port 80 and net 10.42.0.0/16' >/dev/null 2>&1
    sleep 4
    kubectl -n istio-demo delete pod istio-client --force --grace-period=0 >/dev/null 2>&1
    kubectl -n istio-demo run istio-client --image=curlimages/curl:8.11.1 --restart=Never \
      --command -- sh -c 'sleep 5; for i in $(seq 1 60); do curl -s http://whoami/ >/dev/null; sleep 1; done' >/dev/null 2>&1
    kubectl -n istio-demo wait --for=condition=Ready pod/istio-client --timeout=420s >/dev/null 2>&1

    # negative/positive from an UNMESHED pod while the capture runs
    podip="$(kubectl -n istio-demo get pod -l app=whoami -o jsonpath='{.items[0].status.podIP}')"
    kubectl -n istio-demo delete pod probe --force --grace-period=0 >/dev/null 2>&1
    kubectl -n istio-demo run probe --image=alpine:3.22 --restart=Never \
      --labels=sidecar.istio.io/inject=false --command -- sleep 600 >/dev/null 2>&1
    kubectl -n istio-demo wait --for=condition=Ready pod/probe --timeout=300s >/dev/null 2>&1
    kubectl -n istio-demo exec probe -- apk add --no-cache openssl >/dev/null 2>&1
    neg="$(kubectl -n istio-demo exec probe -- sh -c "echo Q | openssl s_client -connect $podip:80 -tls1_3 -groups X25519 2>&1 | grep -cE 'handshake failure|alert number 40'" 2>/dev/null | tr -d '\r')"
    posg="$(kubectl -n istio-demo exec probe -- sh -c "echo Q | openssl s_client -connect $podip:80 -tls1_3 -groups X25519MLKEM768 2>&1 | grep -oE 'Negotiated TLS1.3 group: [A-Za-z0-9]+'" 2>/dev/null | awk '{print $NF}' | tr -d '\r')"
    echo "classical-only client (X25519)   -> $([ "${neg:-0}" -gt 0 ] && echo 'REFUSED (alert 40)' || echo 'accepted -- NOT enforced')"
    echo "PQC client (X25519MLKEM768)      -> ${posg:-<none>}"

    docker wait pqc-k2-cap >/dev/null 2>&1
    docker rm -f pqc-k2-cap >/dev/null 2>&1
    isel="$(docker run --rm -v "$WORK":/out nicolaka/netshoot:latest \
      tshark -r /out/istio.pcap -d tcp.port==80,tls -Y 'tls.handshake.type==2' \
      -T fields -e tls.handshake.extensions_key_share_group 2>/dev/null | head -1 | tr -d '\r')"
    ioff="$(docker run --rm -v "$WORK":/out nicolaka/netshoot:latest \
      tshark -r /out/istio.pcap -d tcp.port==80,tls -Y 'tls.handshake.type==1' \
      -T fields -e tls.handshake.extensions_supported_group 2>/dev/null | head -1 | tr -d '\r')"
    echo "mesh ClientHello offered  : ${ioff:-<none>}   (pqc mode offers ONLY 0x11ec)"
    echo "mesh ServerHello selected : ${isel:-<none>}"

    if [ "$isel" = "$PQC_GROUP_DEC" ] && [ "$ioff" = "0x11ec" ] && [ "${neg:-0}" -gt 0 ]; then
      note+=("PASS [3] istio pqc: mesh negotiated X25519MLKEM768, classical refused"); pass=$((pass+1))
    else
      note+=("FAIL [3] istio selected=${isel:-none} offered=${ioff:-none} classical_refused=${neg:-0}"); fail=$((fail+1))
    fi
  fi
fi

echo; echo "======================================================================"
printf '%s\n' "${note[@]}"
echo "TOTAL: $pass passed, $fail failed"
cat <<'NOTE'

Scope: this is the KEM half only. Linkerd's workload identity is ECDSA P-256 and
Traefik served a classical Ed25519 cert -- no mesh or ingress issues ML-DSA yet
(cert-manager #8929 is blocked on Go 1.27). So cluster traffic resists
harvest-now-decrypt-later today, while identity stays classical.
NOTE
[ "$fail" -eq 0 ]
