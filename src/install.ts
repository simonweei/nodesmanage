import { AGENT_VERSION, RELEASE_DIGESTS } from "./generated-releases";

export function installScript(origin: string): Response {
  const safeOrigin = origin.replace(/[^A-Za-z0-9:/.\-_]/g, "");
  const script = `#!/bin/sh
set -eu

SERVER_URL='${safeOrigin}'
TICKET=''
NAME=''
MODE='auto'
INGRESS_MODE='direct'
TUNNEL_KIND='none'
TUNNEL_HOSTNAME=''
TUNNEL_TOKEN=''
CONNECT_PORT='443'
ORIGIN_PORT='0'
while [ "$#" -gt 0 ]; do
  case "$1" in
    --ticket) TICKET="\${2:-}"; shift 2 ;;
    --name) NAME="\${2:-}"; shift 2 ;;
    --mode) MODE="\${2:-}"; shift 2 ;;
    --ingress-mode) INGRESS_MODE="\${2:-}"; shift 2 ;;
    --tunnel-kind) TUNNEL_KIND="\${2:-}"; shift 2 ;;
    --tunnel-hostname) TUNNEL_HOSTNAME="\${2:-}"; shift 2 ;;
    --tunnel-token) TUNNEL_TOKEN="\${2:-}"; shift 2 ;;
    --connect-port) CONNECT_PORT="\${2:-}"; shift 2 ;;
    --origin-port) ORIGIN_PORT="\${2:-}"; shift 2 ;;
    *) echo "[NM-E101] unknown argument: $1" >&2; exit 2 ;;
  esac
done

case "$MODE" in
  auto) if [ "$(id -u)" -eq 0 ]; then MODE=system; else MODE=user; fi ;;
  system) [ "$(id -u)" -eq 0 ] || { echo "[NM-E102] system mode requires root" >&2; exit 1; } ;;
  user) [ "$(id -u)" -ne 0 ] || { echo "[NM-E102] user mode must run without sudo" >&2; exit 1; } ;;
  *) echo "[NM-E102] --mode must be auto, system or user" >&2; exit 2 ;;
esac
[ -n "$TICKET" ] || { echo "[NM-E103] --ticket is required" >&2; exit 2; }
case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64; EXPECTED='${RELEASE_DIGESTS.amd64.agentSha256}' ;;
  aarch64|arm64) ARCH=arm64; EXPECTED='${RELEASE_DIGESTS.arm64.agentSha256}' ;;
  *) echo "[NM-E104] unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

[ -n "$NAME" ] || NAME="$(hostname 2>/dev/null || uname -n)"
TMP_DIR="$(mktemp -d 2>/dev/null || mktemp -d -t nodemanage)"
trap 'rm -rf "$TMP_DIR"' EXIT INT TERM

download() {
  source_url="$1" destination="$2"
  if command -v curl >/dev/null 2>&1; then curl -fL --retry 3 --connect-timeout 10 "$source_url" -o "$destination"
  elif command -v wget >/dev/null 2>&1; then wget -O "$destination" "$source_url"
  elif command -v busybox >/dev/null 2>&1; then busybox wget -O "$destination" "$source_url"
  else echo "[NM-E105] curl, wget or busybox is required" >&2; exit 1
  fi
}

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
  elif command -v busybox >/dev/null 2>&1 && busybox sha256sum "$1" >/dev/null 2>&1; then busybox sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | awk '{print $1}'
  elif command -v openssl >/dev/null 2>&1; then openssl dgst -sha256 "$1" | awk '{print $NF}'
  else echo "[NM-E106] no SHA-256 tool is available" >&2; exit 1
  fi
}

MANIFEST_URL="$SERVER_URL/api/install/manifest?os=linux&arch=$ARCH"
download "$SERVER_URL/downloads/v${AGENT_VERSION}/nodemanage-agent-linux-$ARCH" "$TMP_DIR/nodemanage-agent"
ACTUAL="$(sha256_file "$TMP_DIR/nodemanage-agent")"
[ "$EXPECTED" = "$ACTUAL" ] || { echo "[NM-E108] Agent checksum mismatch" >&2; exit 1; }
chmod 0755 "$TMP_DIR/nodemanage-agent"
"$TMP_DIR/nodemanage-agent" install --server "$SERVER_URL" --ticket "$TICKET" --name "$NAME" --mode "$MODE" --manifest "$MANIFEST_URL" --ingress-mode "$INGRESS_MODE" --tunnel-kind "$TUNNEL_KIND" --tunnel-hostname "$TUNNEL_HOSTNAME" --tunnel-token "$TUNNEL_TOKEN" --connect-port "$CONNECT_PORT" --origin-port "$ORIGIN_PORT"
`;
  return new Response(script, { headers: {
    "content-type": "text/x-shellscript; charset=utf-8",
    "content-disposition": "inline; filename=install.sh",
    "cache-control": "public, max-age=300",
    "x-content-type-options": "nosniff",
  } });
}
