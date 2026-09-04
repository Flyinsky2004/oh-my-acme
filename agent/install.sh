#!/usr/bin/env bash
#
# oh-my-acme agent install script.
#
# Downloads the oh-my-acme-agent binary from a GitHub Release, verifies its
# SHA-256 checksum, installs it under /opt/oh-my-acme-agent, writes config.json
# (server URL, one-time token, pinned CA fingerprint) and a hardened systemd
# unit, then enables and starts the service. On first start the agent generates
# a private key + CSR and registers with the server control port over a pinned
# CA fingerprint. The connected Server IP is recorded as an inbound API
# allowlist, and the one-time token is then cleared from config.json.
#
# Usage:
#   sudo ./install.sh -server https://SRV:9444 -token XXX -ca-fingerprint SHA256:XXX
#   sudo ./install.sh -port 9123
#
set -euo pipefail

REPO="Flyinsky2004/oh-my-acme"
VERSION="latest"
PORT=9123
SERVER_URL=""
TOKEN=""
CA_FINGERPRINT=""
NAME=""
INSTALL_DIR="/opt/oh-my-acme-agent"

while [ $# -gt 0 ]; do
  case "$1" in
    -version|--version)    VERSION="$2"; shift 2 ;;
    -repo|--repo)          REPO="$2"; shift 2 ;;
    -port|--port)          PORT="$2"; shift 2 ;;
    -server|--server)      SERVER_URL="$2"; shift 2 ;;
    -token|--token)        TOKEN="$2"; shift 2 ;;
    -ca-fingerprint|--ca-fingerprint) CA_FINGERPRINT="$2"; shift 2 ;;
    -name|--name)          NAME="$2"; shift 2 ;;
    -config|--config)      INSTALL_DIR="$(dirname "$2")"; shift 2 ;;
    -h|--help)
      echo "usage: $0 [-version vX.Y.Z] [-repo OWNER/REPO] [-port N] -server URL -token T -ca-fingerprint FP"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 1 ;;
  esac
done

if [ "$(id -u)" -ne 0 ]; then echo "must run as root" >&2; exit 1; fi
[ "$(uname -s)" = "Linux" ] || { echo "only Linux is supported" >&2; exit 1; }

# A fresh installation needs registration material. An existing installation
# keeps config.json and may be upgraded with only -version.
if [ ! -f "${INSTALL_DIR}/config.json" ]; then
  [ -n "$SERVER_URL" ] || { echo "-server is required for first install" >&2; exit 1; }
  [ -n "$TOKEN" ] || { echo "-token is required for first install" >&2; exit 1; }
  [ -n "$CA_FINGERPRINT" ] || { echo "-ca-fingerprint is required for first install" >&2; exit 1; }
fi

ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|amd64) GOARCH="amd64" ;;
  aarch64|arm64) GOARCH="arm64" ;;
  *) echo "unsupported arch: $ARCH" >&2; exit 1 ;;
esac

if [ "$VERSION" = "latest" ]; then
  RELEASE_BASE="https://github.com/${REPO}/releases/latest/download"
else
  RELEASE_BASE="https://github.com/${REPO}/releases/download/${VERSION}"
fi
DOWNLOAD_URL="${RELEASE_BASE}/oh-my-acme-agent_linux_${GOARCH}.tar.gz"
CHECKSUM_URL="${RELEASE_BASE}/checksums.txt"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

CURL="$(command -v curl || true)"
WGET="$(command -v wget || true)"
if [ -n "$CURL" ]; then
  curl -fsSL -o "$TMP/archive.tar.gz" "$DOWNLOAD_URL" || { echo "download failed" >&2; exit 1; }
  curl -fsSL -o "$TMP/checksums.txt" "$CHECKSUM_URL"   || { echo "checksums download failed" >&2; exit 1; }
elif [ -n "$WGET" ]; then
  wget -q -O "$TMP/archive.tar.gz" "$DOWNLOAD_URL" || exit 1
  wget -q -O "$TMP/checksums.txt" "$CHECKSUM_URL"   || exit 1
else
  echo "neither curl nor wget is installed" >&2; exit 1
fi

EXPECTED="$(awk -v b="oh-my-acme-agent_linux_${GOARCH}.tar.gz" '$2==b {print $1}' "$TMP/checksums.txt")"
ACTUAL="$(sha256sum "$TMP/archive.tar.gz" | awk '{print $1}')"
[ -n "$EXPECTED" ] && [ "$EXPECTED" = "$ACTUAL" ] || { echo "checksum mismatch" >&2; exit 1; }

tar -xzf "$TMP/archive.tar.gz" -C "$TMP"
BIN="$TMP/oh-my-acme-agent"
[ -x "$BIN" ] || { echo "binary not found in archive" >&2; exit 1; }

BIN_TARGET="${INSTALL_DIR}/oh-my-acme-agent"
mkdir -p "$INSTALL_DIR" "$INSTALL_DIR/certs" "$INSTALL_DIR/logs"

if [ ! -f "${INSTALL_DIR}/config.json" ]; then
  [ -n "$NAME" ] || NAME="$(hostname)"
  cat > "${INSTALL_DIR}/config.json" <<JSON
{
  "listen": "0.0.0.0",
  "port": ${PORT},
  "cert_dir": "${INSTALL_DIR}/certs",
  "log_dir": "${INSTALL_DIR}/logs",
  "server_url": "${SERVER_URL}",
  "allowed_server_cidrs": [],
  "name": "${NAME}",
  "token": "${TOKEN}",
  "ca_fingerprint": "${CA_FINGERPRINT}"
}
JSON
  chmod 600 "${INSTALL_DIR}/config.json"
  echo "wrote ${INSTALL_DIR}/config.json"
else
  echo "preserving existing config.json"
fi

SVC="oh-my-acme-agent"
systemctl -q stop "$SVC" 2>/dev/null || true
install -m 0755 "$BIN" "$BIN_TARGET"

cat > "/etc/systemd/system/${SVC}.service" <<UNIT
[Unit]
Description=oh-my-acme agent
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
ReadWritePaths=${INSTALL_DIR}
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable "$SVC" >/dev/null 2>&1 || true
systemctl restart "$SVC"
sleep 1

echo "agent installed. Listening on :${PORT}; registration auto-ran if token was supplied."
echo "check status: systemctl status ${SVC}"
