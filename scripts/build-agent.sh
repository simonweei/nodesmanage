#!/bin/sh
set -eu
cd "$(dirname "$0")/../agent"
AGENT_VERSION="$(sed -n 's/.*version[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' main.go | head -n 1)"
[ -n "$AGENT_VERSION" ] || { echo "Cannot read Agent version" >&2; exit 1; }
OUTPUT="../public/downloads/v$AGENT_VERSION"
mkdir -p "$OUTPUT"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o "$OUTPUT/nodemanage-agent-linux-amd64" .
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o "$OUTPUT/nodemanage-agent-linux-arm64" .
cd ..
sha256sum "public/downloads/v$AGENT_VERSION"/nodemanage-agent-linux-* > "public/downloads/v$AGENT_VERSION/SHA256SUMS"
node scripts/generate-release-manifest.mjs
