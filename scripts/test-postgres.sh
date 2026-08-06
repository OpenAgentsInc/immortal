#!/usr/bin/env bash
# Run the live M2–M4 and binary deployment suites against disposable databases.
set -euo pipefail
cd "$(dirname "$0")/.."

for command_name in initdb pg_ctl createdb cargo curl python3 sed; do
  command -v "${command_name}" >/dev/null || {
    echo "test-postgres: missing ${command_name}" >&2
    exit 1
  }
done

cluster_dir="$(mktemp -d /tmp/immortal-postgres.XXXXXX)"
socket_dir="${cluster_dir}/socket"
data_dir="${cluster_dir}/data"
mkdir -p "${socket_dir}"
relay_pid=""
relay_two_pid=""

cleanup() {
  if test -n "${relay_pid}" && kill -0 "${relay_pid}" 2>/dev/null; then
    kill -TERM "${relay_pid}"
    wait "${relay_pid}" || true
  fi
  if test -n "${relay_two_pid}" && kill -0 "${relay_two_pid}" 2>/dev/null; then
    kill -TERM "${relay_two_pid}"
    wait "${relay_two_pid}" || true
  fi
  if test -f "${data_dir}/postmaster.pid"; then
    pg_ctl -D "${data_dir}" -m immediate -w stop >/dev/null
  fi
  rm -rf "${cluster_dir}"
}
trap cleanup EXIT INT TERM

initdb -D "${data_dir}" -A trust --no-locale -E UTF8 >/dev/null
pg_ctl -D "${data_dir}" \
  -o "-c listen_addresses='' -c unix_socket_directories='${socket_dir}'" \
  -w start >/dev/null

database_user="$(id -un)"
createdb -h "${socket_dir}" -U "${database_user}" immortal_test
IMMORTAL_TEST_DATABASE_URL="host=${socket_dir} user=${database_user} dbname=immortal_test" \
  IMMORTAL_TEST_ALLOW_DESTRUCTIVE=1 \
  cargo test --locked -p immortal-relay --test store_postgres -- --nocapture

createdb -h "${socket_dir}" -U "${database_user}" immortal_gateway_test
IMMORTAL_TEST_DATABASE_URL="host=${socket_dir} user=${database_user} dbname=immortal_gateway_test" \
  IMMORTAL_TEST_ALLOW_DESTRUCTIVE=1 \
  cargo test --locked -p immortal-relay --test gateway_postgres -- --nocapture

createdb -h "${socket_dir}" -U "${database_user}" immortal_conformance_test
IMMORTAL_TEST_DATABASE_URL="host=${socket_dir} user=${database_user} dbname=immortal_conformance_test" \
  IMMORTAL_TEST_ALLOW_DESTRUCTIVE=1 \
  cargo test --locked -p immortal-relay --test multiprocess_postgres -- --nocapture

createdb -h "${socket_dir}" -U "${database_user}" immortal_import_test
IMMORTAL_TEST_DATABASE_URL="host=${socket_dir} user=${database_user} dbname=immortal_import_test" \
  IMMORTAL_TEST_ALLOW_DESTRUCTIVE=1 \
  cargo test --locked -p immortal-relay --test bulk_import_postgres -- --nocapture

createdb -h "${socket_dir}" -U "${database_user}" immortal_load_test
IMMORTAL_TEST_DATABASE_URL="host=${socket_dir} user=${database_user} dbname=immortal_load_test" \
  IMMORTAL_TEST_ALLOW_DESTRUCTIVE=1 \
  cargo test --locked --release -p immortal-relay --test load_postgres -- --ignored --nocapture

createdb -h "${socket_dir}" -U "${database_user}" immortal_deploy_test
cargo build --locked -p immortal-relay --bin immortal
relay_log="${cluster_dir}/relay.log"
DATABASE_URL="host=${socket_dir} user=${database_user} dbname=immortal_deploy_test" \
  IMMORTAL_PORT=0 \
  IMMORTAL_RELAY_URL=ws://relay.test \
  IMMORTAL_SUPPORTED_NIPS=11,1,50 \
  target/debug/immortal >"${relay_log}" 2>&1 &
relay_pid=$!

relay_port=""
for _ in $(seq 1 100); do
  relay_port="$(sed -n 's/.*"address":"127.0.0.1:\([0-9][0-9]*\)".*/\1/p' "${relay_log}" | tail -1)"
  if test -n "${relay_port}"; then
    break
  fi
  if ! kill -0 "${relay_pid}" 2>/dev/null; then
    sed -n '1,120p' "${relay_log}" >&2
    exit 1
  fi
  sleep 0.05
done
test -n "${relay_port}"
curl -fsS "http://127.0.0.1:${relay_port}/health" | grep -q '"status":"ok"'
curl -fsS -H 'Accept: application/nostr+json' \
  "http://127.0.0.1:${relay_port}/" | grep -q '"supported_nips":\[11,1,50\]'
IMMORTAL_ACCEPTANCE_PORT="${relay_port}" python3 scripts/debian-acceptance-client.py

relay_two_log="${cluster_dir}/relay-two.log"
DATABASE_URL="host=${socket_dir} user=${database_user} dbname=immortal_deploy_test" \
  IMMORTAL_PORT=0 \
  target/debug/immortal >"${relay_two_log}" 2>&1 &
relay_two_pid=$!
relay_two_port=""
for _ in $(seq 1 100); do
  relay_two_port="$(sed -n 's/.*"address":"127.0.0.1:\([0-9][0-9]*\)".*/\1/p' "${relay_two_log}" | tail -1)"
  if test -n "${relay_two_port}"; then
    break
  fi
  if ! kill -0 "${relay_two_pid}" 2>/dev/null; then
    sed -n '1,120p' "${relay_two_log}" >&2
    exit 1
  fi
  sleep 0.05
done
test -n "${relay_two_port}"
shadow_output="${cluster_dir}/relay-shadow.json"
python3 scripts/relay-readonly-shadow.py \
  --incumbent "ws://127.0.0.1:${relay_port}/" \
  --candidate "ws://127.0.0.1:${relay_two_port}/" \
  --workload tests/fixtures/migration/relay-shadow-v1.json \
  --output "${shadow_output}" >/dev/null
grep -q '"matched": true' "${shadow_output}"
grep -q '"event_count": 1' "${shadow_output}"
kill -TERM "${relay_two_pid}"
wait "${relay_two_pid}"
relay_two_pid=""
kill -TERM "${relay_pid}"
wait "${relay_pid}"
relay_pid=""
