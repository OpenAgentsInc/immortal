#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

provider_identity_secret="${IMMORTAL_PROVIDER_IDENTITY_SECRET:-${IMMORTAL_DEV_PROVIDER_SECRET:-}}"
provider_relay_url="${IMMORTAL_PROVIDER_RELAY_URL:-${IMMORTAL_DEV_RELAY_URL:-ws://127.0.0.1:18080}}"

if [[ -z "${provider_identity_secret}" ]]; then
  echo "IMMORTAL_PROVIDER_IDENTITY_SECRET is required" >&2
  exit 1
fi

if ! test -x target/debug/immortal-provider; then
  cargo build --locked -p immortal-provider --bin immortal-provider
fi

IMMORTAL_PROVIDER_IDENTITY_SECRET="${provider_identity_secret}" \
  IMMORTAL_PROVIDER_RELAY_URL="${provider_relay_url}" \
  exec target/debug/immortal-provider --no-spend
