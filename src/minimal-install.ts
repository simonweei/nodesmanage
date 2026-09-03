import { RELEASE_DIGESTS, SING_BOX_VERSION } from "./generated-releases";
import type { ProfileSettings } from "./domain";

export interface MinimalInstallInput {
  origin: string;
  ticket: string;
  settings: ProfileSettings;
}

function shellSingleQuote(value: string): string {
  return `'${value.replaceAll("'", `'"'"'`)}'`;
}

export function minimalInstallScript(input: MinimalInstallInput): Response {
  const origin = input.origin.replace(/[^A-Za-z0-9:/._-]/g, "");
  const config = JSON.stringify({
    log: { level: "warn", timestamp: true },
    inbounds: [{
      type: "vless", tag: "vless-reality-vision-in", listen: "::", listen_port: input.settings.listen_port,
      users: [{ name: "shared", uuid: input.settings.shared_uuid, flow: "xtls-rprx-vision" }],
      tls: { enabled: true, server_name: input.settings.server_name, reality: {
        enabled: true,
        handshake: { server: input.settings.reality_handshake_server, server_port: input.settings.reality_handshake_port },
        private_key: input.settings.reality_private_key,
        short_id: [input.settings.reality_short_id],
      } },
    }],
    outbounds: [{ type: "direct", tag: "direct" }],
  }, null, 2);
  const root = `sing-box-${SING_BOX_VERSION}-linux`;
  const script = `#!/bin/sh
set -eu

SERVER_URL=${shellSingleQuote(origin)}
TICKET=${shellSingleQuote(input.ticket)}
SING_BOX_VERSION=${shellSingleQuote(SING_BOX_VERSION)}
LISTEN_PORT=${shellSingleQuote(String(input.settings.listen_port))}

case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64; EXPECTED=${shellSingleQuote(RELEASE_DIGESTS.amd64.singBoxSha256)} ;;
  aarch64|arm64) ARCH=arm64; EXPECTED=${shellSingleQuote(RELEASE_DIGESTS.arm64.singBoxSha256)} ;;
  *) echo "[NM-M101] unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

if [ "$(id -u)" -eq 0 ]; then
  INSTALL_MODE=system
  BIN_DIR=/usr/local/bin
  CONFIG_DIR=/etc/sing-box
  STATE_DIR=/var/lib/nodemanage-minimal
else
  INSTALL_MODE=user
  BIN_DIR="$HOME/.local/bin"
  CONFIG_DIR="\${XDG_CONFIG_HOME:-$HOME/.config}/sing-box"
  STATE_DIR="\${XDG_STATE_HOME:-$HOME/.local/state}/nodemanage-minimal"
  if [ "$LISTEN_PORT" -le 1024 ]; then
    echo "[NM-M102] port $LISTEN_PORT requires root; rerun this command through sudo sh" >&2
    exit 1
  fi
fi

command -v tar >/dev/null 2>&1 || { echo "[NM-M103] tar is required" >&2; exit 1; }
mkdir -p "$BIN_DIR" "$CONFIG_DIR" "$STATE_DIR"
WORK_DIR="$STATE_DIR/install.$$"
mkdir -p "$WORK_DIR"
trap 'rm -rf "$WORK_DIR"' EXIT INT TERM
ARCHIVE="$WORK_DIR/sing-box.tar.gz"

download() {
  source_url="$1" destination="$2"
  if command -v curl >/dev/null 2>&1; then curl -fL --retry 3 --connect-timeout 10 "$source_url" -o "$destination"
  elif command -v wget >/dev/null 2>&1; then wget -O "$destination" "$source_url"
  elif command -v busybox >/dev/null 2>&1; then busybox wget -O "$destination" "$source_url"
  else echo "[NM-M104] curl, wget or busybox is required" >&2; exit 1
  fi
}

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
  elif command -v busybox >/dev/null 2>&1 && busybox sha256sum "$1" >/dev/null 2>&1; then busybox sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | awk '{print $1}'
  elif command -v openssl >/dev/null 2>&1; then openssl dgst -sha256 "$1" | awk '{print $NF}'
  else echo "[NM-M105] no SHA-256 tool is available" >&2; exit 1
  fi
}

FILE="sing-box-$SING_BOX_VERSION-linux-$ARCH.tar.gz"
download "$SERVER_URL/downloads/v$SING_BOX_VERSION/$FILE" "$ARCHIVE"
[ "$(sha256_file "$ARCHIVE")" = "$EXPECTED" ] || { echo "[NM-M106] sing-box checksum mismatch" >&2; exit 1; }
tar -xzf "$ARCHIVE" -C "$WORK_DIR" "${root}-$ARCH/sing-box"
EXTRACTED="$WORK_DIR/${root}-$ARCH/sing-box"
[ -x "$EXTRACTED" ] || { echo "[NM-M107] sing-box binary missing from archive" >&2; exit 1; }
cp "$EXTRACTED" "$BIN_DIR/sing-box.new"
chmod 0755 "$BIN_DIR/sing-box.new"
mv -f "$BIN_DIR/sing-box.new" "$BIN_DIR/sing-box"

cat > "$CONFIG_DIR/config.json.new" <<'NODEMANAGE_MINIMAL_CONFIG'
${config}
NODEMANAGE_MINIMAL_CONFIG
chmod 0600 "$CONFIG_DIR/config.json.new"
"$BIN_DIR/sing-box" check -c "$CONFIG_DIR/config.json.new"
mv -f "$CONFIG_DIR/config.json.new" "$CONFIG_DIR/config.json"

start_standalone() {
  if [ -f "$STATE_DIR/sing-box.pid" ]; then
    old_pid="$(cat "$STATE_DIR/sing-box.pid" 2>/dev/null || true)"
    [ -n "$old_pid" ] && kill "$old_pid" 2>/dev/null || true
  fi
  GOMEMLIMIT=64MiB nohup "$BIN_DIR/sing-box" run -c "$CONFIG_DIR/config.json" >>"$STATE_DIR/sing-box.log" 2>&1 &
  echo $! > "$STATE_DIR/sing-box.pid"
  sleep 1
  kill -0 "$(cat "$STATE_DIR/sing-box.pid")" 2>/dev/null || { echo "[NM-M108] sing-box failed to start" >&2; exit 1; }
  echo "Warning: no supported service manager found; automatic restart after reboot is not guaranteed." >&2
}

if [ "$INSTALL_MODE" = system ] && [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
  cat > /etc/systemd/system/nodemanage-minimal.service <<EOF
[Unit]
Description=NodeManage Minimal sing-box
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
Environment=GOMEMLIMIT=64MiB
ExecStart=$BIN_DIR/sing-box run -c $CONFIG_DIR/config.json
Restart=on-failure
RestartSec=5s
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable nodemanage-minimal.service >/dev/null
  systemctl restart nodemanage-minimal.service
  systemctl is-active --quiet nodemanage-minimal.service
elif [ "$INSTALL_MODE" = user ] && command -v systemctl >/dev/null 2>&1 && systemctl --user show-environment >/dev/null 2>&1; then
  USER_UNIT_DIR="\${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
  mkdir -p "$USER_UNIT_DIR"
  cat > "$USER_UNIT_DIR/nodemanage-minimal.service" <<EOF
[Unit]
Description=NodeManage Minimal sing-box
After=network-online.target

[Service]
Type=simple
Environment=GOMEMLIMIT=64MiB
ExecStart=$BIN_DIR/sing-box run -c $CONFIG_DIR/config.json
Restart=on-failure
RestartSec=5s
NoNewPrivileges=true

[Install]
WantedBy=default.target
EOF
  systemctl --user daemon-reload
  systemctl --user enable nodemanage-minimal.service >/dev/null
  systemctl --user restart nodemanage-minimal.service
  systemctl --user is-active --quiet nodemanage-minimal.service
elif [ "$INSTALL_MODE" = system ] && command -v rc-service >/dev/null 2>&1 && [ -d /etc/init.d ]; then
  cat > /etc/init.d/nodemanage-minimal <<EOF
#!/sbin/openrc-run
command="$BIN_DIR/sing-box"
command_args="run -c $CONFIG_DIR/config.json"
command_background=true
pidfile="$STATE_DIR/sing-box.pid"
output_log="$STATE_DIR/sing-box.log"
error_log="$STATE_DIR/sing-box.log"
export GOMEMLIMIT=64MiB
depend() { need net; }
EOF
  chmod 0755 /etc/init.d/nodemanage-minimal
  rc-update add nodemanage-minimal default >/dev/null
  rc-service nodemanage-minimal restart
else
  start_standalone
fi

REPORT='{"ticket":"'"$TICKET"'","install_mode":"'"$INSTALL_MODE"'"}'
if command -v curl >/dev/null 2>&1; then
  curl -fsS --retry 3 -H 'content-type: application/json' --data "$REPORT" "$SERVER_URL/api/minimal/complete" >/dev/null
elif command -v wget >/dev/null 2>&1; then
  wget -qO- --header='content-type: application/json' --post-data="$REPORT" "$SERVER_URL/api/minimal/complete" >/dev/null
else
  busybox wget -qO- --header='content-type: application/json' --post-data="$REPORT" "$SERVER_URL/api/minimal/complete" >/dev/null
fi
echo "NodeManage minimal VPS installed successfully ($INSTALL_MODE mode)."
`;
  return new Response(script.replace(/\r\n/g, "\n"), { headers: {
    "content-type": "text/x-shellscript; charset=utf-8",
    "content-disposition": "inline; filename=nodemanage-minimal-install.sh",
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
  } });
}
