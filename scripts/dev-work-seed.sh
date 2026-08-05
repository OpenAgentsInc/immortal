#!/usr/bin/env bash
# Dev work-item seed for NIP-WK / NIP-PI (immortal#33).
#
#   scripts/dev-work-seed.sh                      publish to the local dev relay
#   scripts/dev-work-seed.sh --emit               print signed events without publishing
#   scripts/dev-work-seed.sh --publish-openagents publish to wss://relay.openagents.com
#
# The local mode targets the scripts/dev-relay.sh quickstart relay
# (IMMORTAL_DEV_RELAY_URL overrides the URL). The --publish-openagents mode
# is explicit and requires the pinned dev authority secret in
# IMMORTAL_DEV_WORK_AUTHORITY_SECRET; the corresponding pubkey is recorded
# in scripts/dev-work-authority.md. Without that variable the seeder signs
# with a fresh throwaway key per the dev-seed key conventions.
set -euo pipefail
cd "$(dirname "$0")/.."

mode="local"
for argument in "$@"; do
  case "${argument}" in
    --emit) mode="emit" ;;
    --publish-openagents) mode="openagents" ;;
    *)
      echo "usage: scripts/dev-work-seed.sh [--emit | --publish-openagents]" >&2
      exit 2
      ;;
  esac
done

if ! test -x target/debug/immortal; then
  cargo build --locked -p immortal-relay --bin immortal
fi

case "${mode}" in
  local)
    IMMORTAL_DEV_RELAY_URL="${IMMORTAL_DEV_RELAY_URL:-ws://127.0.0.1:18080}" \
      exec target/debug/immortal dev-work-seed
    ;;
  emit)
    IMMORTAL_DEV_WORK_EMIT=1 exec target/debug/immortal dev-work-seed
    ;;
  openagents)
    if test -z "${IMMORTAL_DEV_WORK_AUTHORITY_SECRET:-}"; then
      echo "dev-work-seed: --publish-openagents requires IMMORTAL_DEV_WORK_AUTHORITY_SECRET" >&2
      echo "dev-work-seed: the pinned dev authority pubkey is recorded in scripts/dev-work-authority.md" >&2
      exit 1
    fi
    IMMORTAL_DEV_WORK_EMIT=1 target/debug/immortal dev-work-seed \
      | python3 scripts/dev-work-publish.py "${IMMORTAL_DEV_WORK_RELAY_URL:-wss://relay.openagents.com}"
    ;;
esac
