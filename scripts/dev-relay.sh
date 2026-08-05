#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

relay_port="${IMMORTAL_DEV_RELAY_PORT:-18080}"
relay_url="ws://127.0.0.1:${relay_port}"
cluster_dir=""
container_name=""
container_id=""
container_runtime=""
relay_pid=""

cleanup() {
  local exit_status=$?
  trap - EXIT INT TERM
  if test -n "${relay_pid}" && kill -0 "${relay_pid}" 2>/dev/null; then
    kill -TERM "${relay_pid}"
    wait "${relay_pid}" || true
  fi
  if test -n "${container_id}"; then
    current_container_id="$(
      "${container_runtime}" container inspect --format '{{.Id}}' \
        "${container_name}" 2>/dev/null || true
    )"
    if test -n "${current_container_id}" && test "${current_container_id}" != "${container_id}"; then
      echo "dev-relay: ${container_name} no longer matches the created container; refusing teardown" >&2
      exit_status=1
    elif test -n "${current_container_id}" \
      && ! "${container_runtime}" rm -f "${container_name}" >/dev/null; then
      echo "dev-relay: could not remove its disposable Postgres container" >&2
      exit_status=1
    fi
  fi
  if test -n "${cluster_dir}"; then
    if test -f "${cluster_dir}/data/postmaster.pid"; then
      pg_ctl -D "${cluster_dir}/data" -m immediate -w stop >/dev/null 2>&1 || true
    fi
    rm -rf "${cluster_dir}"
  fi
  exit "${exit_status}"
}
trap cleanup EXIT INT TERM

if test -n "${IMMORTAL_DEV_DATABASE_URL:-}"; then
  database_url="${IMMORTAL_DEV_DATABASE_URL}"
else
  if command -v brew >/dev/null; then
    for formula in postgresql@17 postgresql@16 postgresql@15 postgresql; do
      formula_prefix="$(brew --prefix "${formula}" 2>/dev/null || true)"
      if test -x "${formula_prefix}/bin/initdb"; then
        PATH="${formula_prefix}/bin:${PATH}"
        break
      fi
    done
  fi
  if command -v initdb >/dev/null && command -v pg_ctl >/dev/null && command -v createdb >/dev/null; then
    cluster_dir="$(mktemp -d /tmp/immortal-dev-postgres.XXXXXX)"
    mkdir -p "${cluster_dir}/socket"
    initdb -D "${cluster_dir}/data" -A trust --no-locale -E UTF8 >/dev/null
    pg_ctl -D "${cluster_dir}/data" \
      -o "-c listen_addresses='' -c unix_socket_directories='${cluster_dir}/socket'" \
      -w start >/dev/null
    database_user="$(id -un)"
    createdb -h "${cluster_dir}/socket" -U "${database_user}" immortal_dev
    database_url="host=${cluster_dir}/socket user=${database_user} dbname=immortal_dev"
  else
    for candidate in docker podman; do
      if command -v "${candidate}" >/dev/null; then
        container_runtime="${candidate}"
        break
      fi
    done
    if test -z "${container_runtime}"; then
      echo "dev-relay: install local Postgres tools or Docker/Podman" >&2
      exit 1
    fi
    container_name="immortal-dev-postgres-$PPID-$$"
    if ! created_container_id="$(
      "${container_runtime}" run --rm -d \
        --name "${container_name}" \
        -e POSTGRES_HOST_AUTH_METHOD=trust \
        -e POSTGRES_DB=immortal_dev \
        -p 127.0.0.1::5432 \
        postgres:17-alpine
    )"; then
      echo "dev-relay: could not start its disposable Postgres container" >&2
      exit 1
    fi
    if test -z "${created_container_id}"; then
      echo "dev-relay: container runtime returned no Postgres container id" >&2
      exit 1
    fi
    container_id="${created_container_id}"
    for _ in $(seq 1 100); do
      if "${container_runtime}" exec "${container_name}" pg_isready -U postgres -d immortal_dev >/dev/null 2>&1; then
        break
      fi
      sleep 0.1
    done
    if ! "${container_runtime}" exec "${container_name}" pg_isready -U postgres -d immortal_dev >/dev/null 2>&1; then
      echo "dev-relay: disposable Postgres did not become ready" >&2
      exit 1
    fi
    postgres_port="$("${container_runtime}" port "${container_name}" 5432/tcp | sed -n 's/.*:\([0-9][0-9]*\)$/\1/p' | head -1)"
    if test -z "${postgres_port}"; then
      echo "dev-relay: could not resolve disposable Postgres port" >&2
      exit 1
    fi
    database_url="postgres://postgres@127.0.0.1:${postgres_port}/immortal_dev"
  fi
fi

cargo build --locked -p immortal-relay --bin immortal
echo "dev-relay: relay ${relay_url} (Ctrl-C removes disposable state)"
echo "dev-relay: curl -fsS http://127.0.0.1:${relay_port}/health"
echo "dev-relay: curl -fsS -H 'Accept: application/nostr+json' http://127.0.0.1:${relay_port}/"
DATABASE_URL="${database_url}" \
  IMMORTAL_BIND_ADDR=127.0.0.1 \
  IMMORTAL_PORT="${relay_port}" \
  IMMORTAL_RELAY_URL="${relay_url}" \
  IMMORTAL_AUTH_REQUIRED=false \
  target/debug/immortal &
relay_pid=$!
wait "${relay_pid}"
relay_pid=""
