#!/usr/bin/env bash
#
# oh-my-acme server install script.
#
# Downloads the oh-my-acme-server binary from a GitHub Release, verifies its
# SHA-256 checksum, installs it under /opt/oh-my-acme-server, writes config.json
# and a hardened systemd unit, then enables and starts the service.
#
# Usage:
#   sudo ./install.sh                       # latest
#   sudo ./install.sh -version v1.2.3       # specific version
#   sudo ./install.sh -port 8080            # web UI port
#   sudo ./install.sh -agent-port 9444      # agent control port
#
set -euo pipefail

REPO="Flyinsky2004/oh-my-acme"
VERSION="latest"
WEB_PORT=8080
CONTROL_PORT=9444
INSTALL_DIR="/opt/oh-my-acme-server"

# Accept -flag and --flag.
while [ $# -gt 0 ]; do
  case "$1" in
    -version|--version) VERSION="$2"; shift 2 ;;
    -repo|--repo)       REPO="$2"; shift 2 ;;
    -port|--port)       WEB_PORT="$2"; shift 2 ;;
    -agent-port|--agent-port|--control-port) CONTROL_PORT="$2"; shift 2 ;;
    -config|--config)   INSTALL_DIR="$(dirname "$2")"; shift 2 ;;
    -h|--help)
      echo "usage: $0 [-version vX.Y.Z] [-repo OWNER/REPO] [-port N] [-agent-port N]"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 1 ;;
  esac
done

if [ "$(id -u)" -ne 0 ]; then echo "must run as root" >&2; exit 1; fi

# Detect architecture.
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|amd64) GOARCH="amd64" ;;
  aarch64|arm64) GOARCH="arm64" ;;
  *) echo "unsupported arch: $ARCH" >&2; exit 1 ;;
esac
[ "$(uname -s)" = "Linux" ] || { echo "only Linux is supported" >&2; exit 1; }

if [ "$VERSION" = "latest" ]; then
  RELEASE_BASE="https://github.com/${REPO}/releases/latest/download"
else
  RELEASE_BASE="https://github.com/${REPO}/releases/download/${VERSION}"
fi
DOWNLOAD_URL="${RELEASE_BASE}/oh-my-acme-server_linux_${GOARCH}.tar.gz"
CHECKSUM_URL="${RELEASE_BASE}/checksums.txt"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

log() { printf '\033[1;32m[oh-my-acme]\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31m[oh-my-acme]\033[0m %s\n' "$*" >&2; exit 1; }

log "downloading ${DOWNLOAD_URL}"
CURL="$(command -v curl || true)"
WGET="$(command -v wget || true)"
if [ -n "$CURL" ]; then
  curl -fsSL -o "$TMP/archive.tar.gz" "$DOWNLOAD_URL" || fail "download failed"
  curl -fsSL -o "$TMP/checksums.txt" "$CHECKSUM_URL" || fail "checksums download failed"
elif [ -n "$WGET" ]; then
  wget -q -O "$TMP/archive.tar.gz" "$DOWNLOAD_URL" || fail "download failed"
  wget -q -O "$TMP/checksums.txt" "$CHECKSUM_URL" || fail "checksums download failed"
else
  fail "neither curl nor wget is installed"
fi

# Verify checksum.
EXPECTED="$(awk -v b="oh-my-acme-server_linux_${GOARCH}.tar.gz" '$2==b {print $1}' "$TMP/checksums.txt")"
ACTUAL="$(sha256sum "$TMP/archive.tar.gz" | awk '{print $1}')"
if [ -z "$EXPECTED" ] || [ "$EXPECTED" != "$ACTUAL" ]; then
  fail "checksum mismatch (expected := ${EXPECTED})"
fi

log "extracting"
tar -xzf "$TMP/archive.tar.gz" -C "$TMP"
BIN="$TMP/oh-my-acme-server"
[ -x "$BIN" ] || fail "binary not found in archive"

# Persist existing config on upgrade.
BIN_TARGET="${INSTALL_DIR}/oh-my-acme-server"
mkdir -p "$INSTALL_DIR" "$INSTALL_DIR/data" "$INSTALL_DIR/pki" "$INSTALL_DIR/logs"
IF_EXISTS=0; [ -f "${INSTALL_DIR}/config.json" ] && IF_EXISTS=1

if [ "$IF_EXISTS" -eq 0 ]; then
  cat > "${INSTALL_DIR}/config.json" <<JSON
{
  "web_listen": "127.0.0.1",
  "web_port": ${WEB_PORT},
  "control_listen": "0.0.0.0",
  "control_port": ${CONTROL_PORT},
  "data_dir": "${INSTALL_DIR}/data",
  "pki_dir": "${INSTALL_DIR}/pki",
  "log_dir": "${INSTALL_DIR}/logs",
  "log_level": "info"
}
JSON
  chmod 600 "${INSTALL_DIR}/config.json"
  log "wrote ${INSTALL_DIR}/config.json"
else
  log "preserving existing config.json"
fi

# Stop service before replacing binary.
SVC="oh-my-acme-server"
systemctl -q stop "$SVC" 2>/dev/null || true
install -m 0755 "$BIN" "$BIN_TARGET"

# systemd unit with hardening.
cat > "/etc/systemd/system/${SVC}.service" <<UNIT
[Unit]
Description=oh-my-acme server
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=${BIN_TARGET} -config ${INSTALL_DIR}/config.json
Restart=on-failure
RestartSec=3
User=root
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=full
ReadWritePaths=${INSTALL_DIR}/data ${INSTALL_DIR}/pki ${INSTALL_DIR}/logs
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable "$SVC" >/dev/null 2>&1 || true
systemctl restart "$SVC"
sleep 1
systemctl -q is-active "$SVC" >/dev/null || fail "service failed to start"

log "server installed. Web UI: http://127.0.0.1:${WEB_PORT}"
log "check status: systemctl status ${SVC}"
