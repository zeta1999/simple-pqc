# PQC-izing k3s / Rancher / RKE2

Status as of 2026-07 (see `PLAN.md` for the full stack table and sources).

## The split: KEM is free today, PKI is not

| Layer | PQC KEM (X25519MLKEM768) | PQC PKI (ML-DSA certs) |
|---|---|---|
| kube-apiserver ↔ kubelet ↔ etcd ↔ kubectl | ✅ **default, zero-config** via the Go 1.24+ toolchain | ❌ CAs are ECDSA P-256 |
| k3s / RKE2 v1.36.2 (Go 1.25/1.26) | ✅ default | ❌ `dynamiclistener` CA has no PQC plans |
| Traefik ≥3.5 (k3s bundles 3.6.10) | ✅ terminates PQC ingress out of the box | ❌ |
| Caddy ≥2.10 | ✅ | ❌ |
| Linkerd 2.19 (rustls/aws-lc) | ✅ **default** pod↔pod mTLS; provable via `rustls_info` metrics | ❌ |
| Istio 1.27 / Envoy | ⚠️ opt-in `COMPLIANCE_POLICY=pqc` (set in pilot **and** ztunnel) | ❌ |
| ingress-nginx | (last v1.15.1) | ❌ **retired 2026-03-24 — don't use** |
| cert-manager | n/a | ❌ ML-DSA blocked on **Go 1.27** (~Aug/Sep 2026); issue #8929 |

**Bottom line:** the *key exchange* across a current k3s cluster is post-quantum
with no action required — it rides the Go toolchain. The *PKI* (all the cluster
certs) stays classical, and there is **no upstream plan** for PQC certs in
k3s/RKE2/Rancher; the earliest realistic path is cert-manager after Go 1.27, i.e.
2027-ish. Rancher's issue tracker has **zero** PQC/ML-DSA entries.

## Demo path

1. Bring up current k3s on a linux arm64 + amd64 pair (or `k3d` if a Docker
   daemon is available):
   ```
   curl -sfL https://get.k3s.io | sh -
   ```
2. Prove the KEM with the probe (reuses the OpenSSL 3.6.3 harness):
   ```
   ./scripts/k3s-probe.sh 127.0.0.1
   ```
   Expect `X25519MLKEM768` on endpoints that complete a handshake.
3. Deploy the Track-6 images as in-cluster PQC mTLS workloads; expose one via the
   bundled Traefik and prove PQC termination with `scripts/prove-pqc.sh`.
4. (Optional) Install Linkerd 2.19 → pod-to-pod mTLS is PQC by default; read its
   TLS-algorithm Prometheus metrics instead of capturing packets.

## Verified (2026-08-01)

`scripts/docker-linux-verify.sh 2` brings up **`rancher/k3s:v1.36.2-k3s1`** as a
single privileged container and probes `:6443` from the host:

```
kube-apiserver :6443 -> X25519MLKEM768
```

**PQC KEM on the control plane, with zero configuration** — exactly as predicted
above. See `EXPERIMENTS.md` E10.

**Pin a current k3s.** The probe originally used v1.31.5, built with Go 1.22 —
before the Go 1.24 PQC default — which would have shown a false negative. The
KEM story here is a property of the *toolchain the release was built with*, so
always check the k3s version's Go version before drawing conclusions.

## Track K2 verified (2026-08-08)

`scripts/k2-mesh-verify.sh` covers the **data plane** on the same k3s v1.36.2:

| # | What | Result |
|---|---|---|
| [1] | Traefik **3.7.4** ingress, zero config | `ingress -> X25519MLKEM768`, backend `200 OK` |
| [2] | **Linkerd** `edge-26.8.1` pod↔pod mTLS | ServerHello selected `4588` (0x11EC) |
| [3] | **Istio 1.30.3** `COMPLIANCE_POLICY=pqc` | ClientHello offers **only** `0x11ec`; classical client refused |

**The two meshes differ in kind, and it matters for the pitch:**

- **Linkerd is PQC-*preferred*.** Its ClientHello offered
  `0x11ec,0x001d,0x0017,0x0018` — PQC first, but X25519 and the NIST curves are
  still on the table. You get HNDL resistance by default with zero config, and a
  classical-only peer still connects. Good default, no enforcement.
- **Istio with `COMPLIANCE_POLICY=pqc` is PQC-*enforced*.** Its ClientHello
  offered `0x11ec` and nothing else, and a classical-only `openssl s_client`
  from an unmeshed pod got `alert number 40`. There is no group left to
  downgrade to. Istio labels the policy **experimental**, and it must be set on
  pilot **and** ztunnel (ambient) to be effective.

So: *Linkerd for "PQC by default, nothing to do"; Istio for "PQC or you don't
connect."* Neither does PQC **identity** — Linkerd's workload certs are ECDSA
P-256, and cert-manager's ML-DSA support is blocked on Go 1.27.

**Correction to the table above:** k3s v1.36.2 bundles Traefik **3.7.4**, not
3.6.10, and Istio's `pqc` policy is present in **1.30.3** (documented in-binary
as enforcing X25519MLKEM768 + TLS 1.3 + AES-GCM suites).

## Multi-node cluster verified (2026-08-08)

`scripts/k1-multinode-verify.sh` (`make multinode`) brings up a **real two-node
cluster** — `server` + `agent` on their own docker network, with **embedded
etcd** via `--cluster-init` — and covers both planes.

### Control plane, probed from a third container

```
agent0    Ready    <none>               v1.36.2+k3s1
server0   Ready    control-plane,etcd   v1.36.2+k3s1

pqc-k3s-server:6443        -> X25519MLKEM768     # kube-apiserver
pqc-k3s-server:10250       -> X25519MLKEM768     # kubelet, control-plane node
pqc-k3s-agent:10250        -> X25519MLKEM768     # kubelet, WORKER node
pqc-k3s-server:2379        -> X25519MLKEM768     # etcd client
pqc-k3s-server:2380        -> X25519MLKEM768     # etcd peer
```

That is the full endpoint set PLAN Track K1 named, and `pqc-k3s-agent:10250` is
the genuinely cross-node leg. **Still zero configuration.**

**`--cluster-init` is load-bearing.** A default single-server k3s uses sqlite and
has **no etcd listener at all**, so probing `:2379` against a stock k3s finds
nothing listening — that is not a PQC failure, there is simply no etcd.

### Cross-node pod traffic, captured inside the tunnel

Section [2] of the same script installs Linkerd and pins the two ends to
**different nodes**, forcing mesh mTLS through flannel's VXLAN encapsulation:

```
  whoami   10.42.1.4  agent0
  xclient  10.42.0.5  server0
  ServerHello (outer,inner): 172.20.0.2,10.42.0.4  172.20.0.3,10.42.1.3  4588
```

The `outer,inner` addresses are the proof: `172.20.0.x` are the two **nodes**,
wrapping the two **pod** addresses. The handshake genuinely crossed the node
boundary, and inside the tunnel the selected group is `4588` (X25519MLKEM768).

**Gotcha:** Linkerd needs the Gateway API CRDs, which k3s installs *via its
bundled Traefik*. Disabling Traefik removes them and `linkerd install` then
renders nothing, failing with the misleading `no objects passed to apply`.

## Still not verified here

Native amd64 silicon. Everything else in Tracks K1/K2 is now measured.
