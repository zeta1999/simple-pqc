#!/usr/bin/env bash
# Track 6: build multi-arch (arm64 + amd64) images for the Go and Rust endpoints.
#
# Multi-platform manifests cannot be --load'ed into the local daemon; either
# --push to a registry, or build a single platform with --load for local runs:
#   PLATFORMS=linux/arm64 ./scripts/docker-build.sh --load
#   PLATFORMS=linux/amd64,linux/arm64 ./scripts/docker-build.sh --push
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
PLATFORMS="${PLATFORMS:-linux/amd64,linux/arm64}"
REG="${REG:-simple-pqc}"

docker buildx inspect pqc-builder >/dev/null 2>&1 || docker buildx create --name pqc-builder >/dev/null
docker buildx use pqc-builder

echo "building $REG/go and $REG/rust for [$PLATFORMS]"
docker buildx build --platform "$PLATFORMS" -f "$ROOT/go/Dockerfile"   -t "$REG/go:latest"   "$ROOT" "$@"
docker buildx build --platform "$PLATFORMS" -f "$ROOT/rust/Dockerfile" -t "$REG/rust:latest" "$ROOT" "$@"
echo "done. Run e.g.:"
echo "  docker run --rm -p 8443:8443 -v \$PWD/certs:/certs $REG/go:latest"
