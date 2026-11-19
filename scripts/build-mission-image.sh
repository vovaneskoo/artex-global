#!/usr/bin/env bash
# Build an ARTEX mission image inside the isolated bench VM.
#
# The VM does not mount the host FS, so the context is packed on the host and
# streamed to `docker build -` over limactl copy. The binary is cross-compiled
# for the VM architecture; only apt layers run under emulation.
#
# Usage:
#   scripts/build-mission-image.sh            # offsec image (Dockerfile.offsec)
#   scripts/build-mission-image.sh --base     # lean base image (Dockerfile)
# Env:
#   ARTEX_MISSION_VM    lima instance (default artex-bench)
#   ARTEX_IMAGE        target tag (default artex-offsec:latest / artex-bench:latest)
#   ARTEX_IMAGE_ARCH   linux arch (default: VM arch)
set -euo pipefail

cd "$(cd "$(dirname "$0")/.." && pwd)"

MODE=offsec
[ "${1:-}" = "--base" ] && MODE=base

VM="${ARTEX_MISSION_VM:-artex-bench}"
ARCH="${ARTEX_IMAGE_ARCH:-$(limactl shell "$VM" -- uname -m)}"
case "$ARCH" in
  aarch64|arm64) ARCH=arm64 ;;
  x86_64|amd64) ARCH=amd64 ;;
  *) echo "unsupported arch: $ARCH" >&2; exit 1 ;;
esac
if [ "$MODE" = base ]; then
  DOCKERFILE=Dockerfile
  TAG="${ARTEX_IMAGE:-artex-bench:latest}"
else
  DOCKERFILE=Dockerfile.offsec
  TAG="${ARTEX_IMAGE:-artex-offsec:latest}"
fi

command -v go >/dev/null || { echo "go not found" >&2; exit 1; }
[ -n "$(ls -A server/webui/dist 2>/dev/null)" ] || {
  command -v npm >/dev/null || { echo "npm not found and server/webui/dist is empty" >&2; exit 1; }
  (cd web && npm ci && npm run build:static)
  mkdir -p server/webui/dist
  rsync -a --delete web/out/ server/webui/dist/
}

echo "[*] cross-compiling linux/$ARCH"
mkdir -p "dist/$ARCH"
CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" GOFLAGS=-buildvcs=false \
  go build -tags embedui -trimpath -o "dist/$ARCH/artex" ./cmd/artex

CTX="$(mktemp -d "${TMPDIR:-/tmp}/artex-img.XXXXXX")"
trap 'rm -rf "$CTX"' EXIT
cp "$DOCKERFILE" start.sh "$CTX/"
mkdir -p "$CTX/dist/$ARCH" "$CTX/skills" "$CTX/scripts"
cp "dist/$ARCH/artex" "$CTX/dist/$ARCH/artex"
rsync -a skills/ "$CTX/skills/"
cp scripts/tool-versions.sh "$CTX/scripts/"
tar -C "$CTX" -cf "$CTX/ctx.tar" .

echo "[*] building $TAG in $VM"
limactl shell "$VM" -- sudo docker build -f "$DOCKERFILE" --build-arg "TARGETARCH=$ARCH" -t "$TAG" - < "$CTX/ctx.tar"

echo "[+] built $TAG"
