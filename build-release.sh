#!/usr/bin/env bash
# build-release.sh — one-click build of the versioned release artifacts into dist/.
#
# Reproduces exactly what .github/workflows/release.yml packages so you can
# produce the same tarballs, install scripts and checksums locally without a
# CI run or a tag push:
#
#   - oh-my-acme-server_linux_amd64.tar.gz / linux_arm64.tar.gz
#   - oh-my-acme-agent_linux_amd64.tar.gz  / linux_arm64.tar.gz
#   - install-server.sh, install-agent.sh
#   - checksums.txt
#
# Usage:
#   ./build-release.sh              # uses the latest git tag (e.g. v0.2.3)
#   ./build-release.sh v0.2.3       # explicit version
#
# Version is baked into the binaries via -ldflags so the built server/agent
# report it on /health and the agent updater.

set -euo pipefail

cd "$(dirname "$0")"

VERSION="${1:-$(git describe --tags --abbrev=0 2>/dev/null || echo dev)}"
SERVER_PKG="github.com/Flyinsky2004/oh-my-acme/internal/server"
AGENT_PKG="github.com/Flyinsky2004/oh-my-acme/internal/agent"

# shasum -a 256 on macOS, sha256sum on Linux. Both emit "<hash>  <file>".
if command -v shasum >/dev/null 2>&1; then
  SHA256="shasum -a 256"
elif command -v sha256sum >/dev/null 2>&1; then
  SHA256="sha256sum"
else
  echo "error: need either shasum or sha256sum" >&2
  exit 1
fi

mkdir -p dist
# Remove only this script's own outputs so a stale version never ships.
rm -f dist/oh-my-acme-server dist/oh-my-acme-agent dist/*.tar.gz dist/checksums.txt

echo "Building release ${VERSION} ..."
for goarch in amd64 arm64; do
  echo "- linux/${goarch}: server + agent"
  GOOS=linux GOARCH="$goarch" CGO_ENABLED=0 go build -trimpath \
    -ldflags="-s -w -X ${SERVER_PKG}.Version=${VERSION}" \
    -o dist/oh-my-acme-server ./cmd/server
  GOOS=linux GOARCH="$goarch" CGO_ENABLED=0 go build -trimpath \
    -ldflags="-s -w -X ${AGENT_PKG}.Version=${VERSION}" \
    -o dist/oh-my-acme-agent ./cmd/agent
  (
    cd dist
    tar -czf "oh-my-acme-server_linux_${goarch}.tar.gz" oh-my-acme-server
    tar -czf "oh-my-acme-agent_linux_${goarch}.tar.gz" oh-my-acme-agent
  )
done

# Only the versioned tarballs, install scripts and checksums ship; the raw
# binaries are build intermediaries.
rm -f dist/oh-my-acme-server dist/oh-my-acme-agent

cp server/install.sh dist/install-server.sh
cp agent/install.sh dist/install-agent.sh
chmod 0755 dist/install-server.sh dist/install-agent.sh

(cd dist && $SHA256 *.tar.gz install-*.sh > checksums.txt)

echo "Done. Version ${VERSION} artifacts in dist/:"
ls -l dist/
