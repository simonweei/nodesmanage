#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROJECT_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
DATABASE_NAME=${1:-nodemanage}
OUTPUT_DIR=${2:-"$PROJECT_ROOT/backups"}
mkdir -p "$OUTPUT_DIR"
TIMESTAMP=$(date -u +%Y%m%d-%H%M%S)
OUTPUT_FILE="$OUTPUT_DIR/$DATABASE_NAME-$TIMESTAMP.sql"

npx wrangler d1 export "$DATABASE_NAME" --remote --skip-confirmation --output "$OUTPUT_FILE"
printf 'D1 backup created: %s\n' "$OUTPUT_FILE"
