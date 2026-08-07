#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

IMMORTAL_LAB_DYNAMIC_TOPOLOGY=1 scripts/test-lab-topology-funded.sh
