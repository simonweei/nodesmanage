#!/bin/sh
set -eu
cd "$(dirname "$0")/../agent"
mkdir -p ../public/downloads
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o ../public/downloads/nodemanage-agent-linux-amd64 .
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o ../public/downloads/nodemanage-agent-linux-arm64 .
cd ..
sha256sum public/downloads/nodemanage-agent-linux-* > public/downloads/SHA256SUMS
