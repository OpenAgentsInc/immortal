#!/bin/sh
set -eu

export LC_ALL=C

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
mode=${1:-write}
if [ "$mode" != "write" ] && [ "$mode" != "--check" ]; then
    echo "usage: scripts/export-provider-contract.sh [--check]" >&2
    exit 2
fi

temporary=$(mktemp -d "${TMPDIR:-/tmp}/immortal-provider-contract.XXXXXX")
trap 'rm -rf "$temporary"' EXIT HUP INT TERM

cd "$root"
export IMMORTAL_PROVIDER_CONTRACT_DESTINATION="$temporary/contract-one.json"
cargo test --locked -p immortal-provider --test provider_contract \
    export_provider_contract -- --ignored --exact >/dev/null
export IMMORTAL_PROVIDER_CONTRACT_DESTINATION="$temporary/contract-two.json"
cargo test --locked -p immortal-provider --test provider_contract \
    export_provider_contract -- --ignored --exact >/dev/null
unset IMMORTAL_PROVIDER_CONTRACT_DESTINATION

cmp "$temporary/contract-one.json" "$temporary/contract-two.json"

destination="$root/tests/fixtures/provider/provider-contract-v1.json"
if [ "$mode" = "--check" ]; then
    cmp "$temporary/contract-one.json" "$destination"
    exit 0
fi

mv "$temporary/contract-one.json" "$destination"
