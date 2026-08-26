export function installScript(origin: string): Response {
  const safeOrigin = origin.replace(/[^A-Za-z0-9:/.\-_]/g, "");
  const script = `#!/bin/sh
set -eu

SERVER_URL=${safeOrigin}
SING_BOX_VERSION=1.13.12
CODE=""
NAME=""

while [ "$#" -gt 0 ]; do
  case "$1" in
    --code) CODE="\${2:-}"; shift 2 ;;
    --name) NAME="\${2:-}"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

[ "$(id -u)" -eq 0 ] || { echo "run this installer as root" >&2; exit 1; }
[ -n "$CODE" ] || { echo "--code is required" >&2; exit 2; }
command -v curl >/dev/null 2>&1 || { echo "curl is required" >&2; exit 1; }
command -v tar >/dev/null 2>&1 || { echo "tar is required" >&2; exit 1; }
command -v sha256sum >/dev/null 2>&1 || { echo "sha256sum is required" >&2; exit 1; }

case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) echo "unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

[ -n "$NAME" ] || NAME="$(hostname)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT INT TERM

curl -fL --retry 3 --connect-timeout 10 "$SERVER_URL/downloads/nodemanage-agent-linux-$ARCH" -o "$TMP_DIR/nodemanage-agent"
curl -fL --retry 3 --connect-timeout 10 "$SERVER_URL/downloads/SHA256SUMS" -o "$TMP_DIR/agent-checksums.txt"
AGENT_FILE="nodemanage-agent-linux-$ARCH"
AGENT_EXPECTED="$(awk -v f="$AGENT_FILE" '$2 == f {print $1}' "$TMP_DIR/agent-checksums.txt")"
[ -n "$AGENT_EXPECTED" ] || { echo "Agent checksum not found" >&2; exit 1; }
AGENT_ACTUAL="$(sha256sum "$TMP_DIR/nodemanage-agent" | awk '{print $1}')"
[ "$AGENT_EXPECTED" = "$AGENT_ACTUAL" ] || { echo "Agent checksum mismatch" >&2; exit 1; }
chmod 0755 "$TMP_DIR/nodemanage-agent"
install -m 0755 "$TMP_DIR/nodemanage-agent" /usr/local/bin/nodemanage-agent

if ! command -v sing-box >/dev/null 2>&1; then
  BASE="sing-box-$SING_BOX_VERSION-linux-$ARCH"
  curl -fL --retry 3 --connect-timeout 10 "https://github.com/SagerNet/sing-box/releases/download/v$SING_BOX_VERSION/$BASE.tar.gz" -o "$TMP_DIR/sing-box.tar.gz"
  curl -fL --retry 3 --connect-timeout 10 "https://github.com/SagerNet/sing-box/releases/download/v$SING_BOX_VERSION/sing-box-$SING_BOX_VERSION-checksums.txt" -o "$TMP_DIR/checksums.txt"
  EXPECTED="$(awk -v f="$BASE.tar.gz" '$2 == f {print $1}' "$TMP_DIR/checksums.txt")"
  [ -n "$EXPECTED" ] || { echo "sing-box checksum not found" >&2; exit 1; }
  ACTUAL="$(sha256sum "$TMP_DIR/sing-box.tar.gz" | awk '{print $1}')"
  [ "$EXPECTED" = "$ACTUAL" ] || { echo "sing-box checksum mismatch" >&2; exit 1; }
  tar -xzf "$TMP_DIR/sing-box.tar.gz" -C "$TMP_DIR"
  install -m 0755 "$TMP_DIR/$BASE/sing-box" /usr/local/bin/sing-box
fi

install -d -m 0700 /etc/nodemanage
install -d -m 0755 /etc/sing-box
[ -f /etc/sing-box/config.json ] || printf '%s\n' '{"inbounds":[],"outbounds":[{"type":"direct"}]}' >/etc/sing-box/config.json
chmod 0600 /etc/sing-box/config.json

cat >/etc/systemd/system/sing-box.service <<'UNIT'
[Unit]
Description=sing-box proxy service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/sing-box run -c /etc/sing-box/config.json
Restart=on-failure
RestartSec=5s
LimitNOFILE=1048576
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
UNIT

if [ ! -s /etc/nodemanage/agent.json ]; then
  /usr/local/bin/nodemanage-agent register --server "$SERVER_URL" --code "$CODE" --name "$NAME"
fi

cat >/etc/systemd/system/nodemanage-agent.service <<'UNIT'
[Unit]
Description=NodeManage Agent
After=network-online.target sing-box.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/nodemanage-agent run
Restart=always
RestartSec=10s
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now sing-box.service nodemanage-agent.service
echo "NodeManage Agent installed successfully"
`;
  return new Response(script, {
    headers: {
      "content-type": "text/x-shellscript; charset=utf-8",
      "content-disposition": "inline; filename=install.sh",
      "cache-control": "public, max-age=300",
      "x-content-type-options": "nosniff",
    },
  });
}
