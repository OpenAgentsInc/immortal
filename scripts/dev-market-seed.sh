#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

if ! test -x target/debug/immortal; then
  cargo build --locked -p immortal-relay --bin immortal
fi

IMMORTAL_DEV_RELAY_URL="${IMMORTAL_DEV_RELAY_URL:-ws://127.0.0.1:18080}" \
IMMORTAL_DEV_RELAY_AUTH_URL="${IMMORTAL_DEV_RELAY_AUTH_URL:-${IMMORTAL_DEV_RELAY_URL:-ws://127.0.0.1:18080}}" \
  exec target/debug/immortal dev-market-seed
