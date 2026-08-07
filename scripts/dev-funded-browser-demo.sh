#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

IMMORTAL_PROVIDER_FUNDED_BROWSER_DEMO=1 \
  IMMORTAL_PROVIDER_FUNDED_BROWSER_DEMO_CLIENT=external \
  IMMORTAL_PROVIDER_FUNDED_RESTART_AT= \
  scripts/test-provider-funded.sh
