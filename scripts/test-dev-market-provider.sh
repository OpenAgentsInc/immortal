#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

relay_port="${IMMORTAL_PROVIDER_LIVE_RELAY_PORT:-18080}"
relay_url="ws://127.0.0.1:${relay_port}"
relay_pid=""

cleanup() {
  trap - EXIT INT TERM
  if test -n "${relay_pid}" && kill -0 "${relay_pid}" 2>/dev/null; then
    kill -TERM "${relay_pid}"
    wait "${relay_pid}" || true
  fi
}
trap cleanup EXIT INT TERM

IMMORTAL_DEV_RELAY_PORT="${relay_port}" scripts/dev-relay.sh &
relay_pid=$!

for _ in $(seq 1 300); do
  if curl -fsS "http://127.0.0.1:${relay_port}/health" >/dev/null 2>&1; then
    break
  fi
  if ! kill -0 "${relay_pid}" 2>/dev/null; then
    wait "${relay_pid}"
    echo "test-dev-market-provider: local relay exited before readiness" >&2
    exit 1
  fi
  sleep 0.1
done
if ! curl -fsS "http://127.0.0.1:${relay_port}/health" >/dev/null 2>&1; then
  echo "test-dev-market-provider: local relay did not become ready" >&2
  exit 1
fi

cargo build --locked -p immortal-provider --bin immortal-provider
IMMORTAL_PROVIDER_LIVE_RELAY_URL="${relay_url}" \
  cargo test --locked -p immortal-provider --test no_spend_live \
    separate_no_spend_daemon_recovers_and_completes_all_swap_shapes -- --ignored --exact --nocapture
