#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
umask 077

command_name="${1:-}"
state_dir=""
backup_path=""
compose_file="deploy/join/compose.yaml"

usage() {
  cat <<'USAGE'
usage: scripts/operate-joined-relay.sh <status|backup|restore-test> --state-dir /absolute/dir [--backup /absolute/file.dump]

Runs bounded health, Postgres backup, and disposable restore verification for
state created by `scripts/join-regtest.sh relay`. Backup files remain private
under STATE/backups and the newest 14 are retained.
USAGE
}

fail() { echo "operate-joined-relay: $1" >&2; exit 1; }

while test "$#" -gt 0; do
  case "$1" in
    status|backup|restore-test) command_name="$1"; shift ;;
    --state-dir) test "$#" -ge 2 || fail "--state-dir requires a value"; state_dir="$2"; shift 2 ;;
    --backup) test "$#" -ge 2 || fail "--backup requires a value"; backup_path="$2"; shift 2 ;;
    help|-h|--help) usage; exit 0 ;;
    *) usage >&2; fail "unknown argument $1" ;;
  esac
done

case "${command_name}" in status|backup|restore-test) ;; *) usage >&2; exit 2 ;; esac
test -n "${state_dir}" || fail "--state-dir is required"
case "${state_dir}" in /*) ;; *) fail "state directory must be absolute" ;; esac
test ! -L "${state_dir}" || fail "state directory must not be a symlink"
test -f "${state_dir}/ownership.json" || fail "ownership marker is absent"
test ! -L "${state_dir}/ownership.json" || fail "ownership marker must not be a symlink"

readarray_compat() {
  python3 - "${state_dir}/ownership.json" "$(pwd -P)" <<'PY'
import json, pathlib, sys
path = pathlib.Path(sys.argv[1])
if path.stat().st_size > 4096:
    raise SystemExit("ownership marker exceeds its bound")
value = json.loads(path.read_text(encoding="utf-8"))
if value.get("schema") != "openagents.immortal.join-owner.v1":
    raise SystemExit("ownership marker has another schema")
if value.get("repository") != sys.argv[2] or value.get("mode") != "relay":
    raise SystemExit("ownership marker does not belong to this relay checkout")
project = value.get("compose_project")
port = value.get("relay_port")
url = value.get("relay_public_url")
if not isinstance(project, str) or not project.startswith("immortal-join-") or len(project) > 63:
    raise SystemExit("invalid Compose project")
if not isinstance(port, str) or not port.isdecimal() or not 1024 <= int(port) <= 65535:
    raise SystemExit("invalid relay port")
if not isinstance(url, str) or len(url) > 512:
    raise SystemExit("invalid relay URL")
print(project)
print(port)
print(url)
PY
}

marker_values="$(readarray_compat)" || fail "owned relay state is invalid"
project="$(printf '%s\n' "${marker_values}" | sed -n '1p')"
relay_port="$(printf '%s\n' "${marker_values}" | sed -n '2p')"
relay_url="$(printf '%s\n' "${marker_values}" | sed -n '3p')"

compose() {
  docker compose --project-directory . --project-name "${project}" \
    --env-file "${state_dir}/compose.env" --profile relay -f "${compose_file}" "$@"
}

status() {
  docker info >/dev/null 2>&1 || fail "Docker is unavailable"
  compose ps --status running --services | grep -qx relay-postgres || fail "relay Postgres is not running"
  compose ps --status running --services | grep -qx relay || fail "relay is not running"
  compose exec -T relay-postgres psql -U immortal_relay -d immortal_relay -Atqc 'SELECT 1' | grep -qx 1 ||
    fail "relay Postgres query failed"
  local nip11
  nip11="$(curl --fail --silent --max-time 10 -H 'Accept: application/nostr+json' "http://127.0.0.1:${relay_port}/")" ||
    fail "relay NIP-11 check failed"
  jq -e '
    (.pubkey | type == "string" and test("^[0-9a-f]{64}$")) and
    (["nip-mkt", "mkt-swp:1", "mkt-swp-coordination:1"] - .supported_extensions == [])
  ' <<<"${nip11}" >/dev/null || fail "relay NIP-11 market identity or extensions are incomplete"
  jq -nc --arg url "${relay_url}" --arg pubkey "$(jq -r .pubkey <<<"${nip11}")" \
    --argjson extensions "$(jq -c .supported_extensions <<<"${nip11}")" \
    '{schema:"openagents.immortal.join-relay-health.v1",health:"ready",relay_url:$url,relay_pubkey:$pubkey,supported_extensions:$extensions,database:"ready"}'
}

backup() {
  status >/dev/null
  local backup_dir stamp temporary final
  backup_dir="${state_dir}/backups"
  install -d -m 0700 "${backup_dir}"
  stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  temporary="${backup_dir}/.relay-${stamp}-$$.dump"
  final="${backup_dir}/relay-${stamp}.dump"
  trap 'test -z "${temporary:-}" || test ! -e "${temporary}" || unlink "${temporary}"' EXIT
  compose exec -T relay-postgres pg_dump -U immortal_relay -d immortal_relay -Fc >"${temporary}"
  test -s "${temporary}" || fail "Postgres backup is empty"
  compose exec -T relay-postgres pg_restore --list <"${temporary}" >/dev/null || fail "Postgres backup inventory is invalid"
  chmod 0600 "${temporary}"
  mv "${temporary}" "${final}"
  trap - EXIT
  python3 - "${backup_dir}" <<'PY'
import os, pathlib, re, sys
directory = pathlib.Path(sys.argv[1])
pattern = re.compile(r"relay-[0-9]{8}T[0-9]{6}Z\.dump")
files = sorted((path for path in directory.iterdir() if path.is_file() and not path.is_symlink() and pattern.fullmatch(path.name)), reverse=True)
for path in files[14:]:
    os.unlink(path)
PY
  printf '%s\n' "${final}"
}

restore_test() {
  status >/dev/null
  local backup_dir database events migrations digest
  backup_dir="${state_dir}/backups"
  if test -z "${backup_path}"; then
    backup_path="$(find "${backup_dir}" -maxdepth 1 -type f -name 'relay-????????T??????Z.dump' -print | LC_ALL=C sort | tail -1)"
  fi
  test -n "${backup_path}" && test -f "${backup_path}" && test ! -L "${backup_path}" || fail "verified backup is absent"
  local backup_parent backup_name
  backup_parent="$(cd "$(dirname "${backup_path}")" && pwd -P)"
  backup_name="$(basename "${backup_path}")"
  case "${backup_parent}/${backup_name}" in "$(cd "${backup_dir}" && pwd -P)"/relay-????????T??????Z.dump) ;; *) fail "backup must be an owned relay dump" ;; esac
  database="immortal_relay_restore_$(od -An -N 6 -tx1 /dev/urandom | tr -d ' \n')"
  trap 'test -z "${database:-}" || compose exec -T relay-postgres dropdb -U immortal_relay --if-exists "${database}" >/dev/null 2>&1 || true' EXIT
  compose exec -T relay-postgres createdb -U immortal_relay "${database}"
  compose exec -T relay-postgres pg_restore -U immortal_relay -d "${database}" --exit-on-error <"${backup_path}"
  migrations="$(compose exec -T relay-postgres psql -U immortal_relay -d "${database}" -Atqc 'SELECT count(*) FROM schema_migrations')"
  events="$(compose exec -T relay-postgres psql -U immortal_relay -d "${database}" -Atqc 'SELECT count(*) FROM nostr_event')"
  digest="$(shasum -a 256 "${backup_path}" | awk '{print $1}')"
  jq -nc --arg backup "$(basename "${backup_path}")" --arg digest "${digest}" \
    --argjson migrations "${migrations}" --argjson events "${events}" \
    '{schema:"openagents.immortal.join-relay-restore.v1",result:"passed",backup:$backup,sha256:$digest,schema_migrations:$migrations,nostr_events:$events}'
  compose exec -T relay-postgres dropdb -U immortal_relay --if-exists "${database}" >/dev/null
  trap - EXIT
}

case "${command_name}" in
  status) status ;;
  backup) backup ;;
  restore-test) restore_test ;;
esac
