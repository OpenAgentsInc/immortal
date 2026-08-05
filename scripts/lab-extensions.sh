#!/usr/bin/env bash
# Registry-backed extension boundary for the adversarial lab. The owning
# issues provide executable hooks; this wrapper allocates an isolated state
# directory and records enough ownership to tear down only a successful hook
# invocation.
set -euo pipefail
cd "$(dirname "$0")/.."

manifest_file="tests/fixtures/lab/provisioning-v1.json"
lab_dir="${IMMORTAL_LAB_DIR:-${TMPDIR:-/tmp}/immortal-lab}"

usage() {
  cat <<'USAGE'
usage: scripts/lab-extensions.sh <command> [extension]

commands:
  manifest [elementsd|arkd]  print the pinned extension registry
  up <elementsd|arkd>        invoke the configured extension hook
  status <elementsd|arkd>    report hook and ownership state
  down <elementsd|arkd>      tear down a wrapper-created extension

Each hook is an executable configured by the manifest's hook_environment
field. It receives up, status, or down as argv[1] and these non-secret values:
  IMMORTAL_LAB_EXTENSION_ID
  IMMORTAL_LAB_EXTENSION_ISSUE
  IMMORTAL_LAB_EXTENSION_RUN_ID
  IMMORTAL_LAB_EXTENSION_STATE_DIR
  IMMORTAL_LAB_EXTENSION_PORTS_JSON

Hooks must bind loopback only, keep credentials in their assigned state
directory with mode 0600, and remove only resources bearing that directory's
run identifier. The wrapper passes no wallet, macaroon, seed, or node secret.
USAGE
}

extension_json() {
  local extension="$1"
  jq -ec --arg extension "${extension}" \
    '.extensions[] | select(.id == $extension)' "${manifest_file}"
}

require_extension() {
  local extension="${1:-}"
  if test -z "${extension}" || ! extension_json "${extension}" >/dev/null; then
    echo "lab-extensions: extension must be elementsd or arkd" >&2
    exit 1
  fi
  echo "${extension}"
}

extension_dir() {
  echo "${lab_dir}/extensions/$1"
}

hook_path() {
  local extension="$1" hook_environment
  hook_environment="$(extension_json "${extension}" | jq -er '.hook_environment')"
  printf '%s' "${!hook_environment:-}"
}

invoke_hook() {
  local extension="$1" hook="$2" command="$3" directory issue ports run_id
  directory="$(extension_dir "${extension}")"
  issue="$(extension_json "${extension}" | jq -er '.issue')"
  ports="$(extension_json "${extension}" | jq -c '.ports')"
  run_id="$(cat "${directory}/run-id")"
  IMMORTAL_LAB_EXTENSION_ID="${extension}" \
    IMMORTAL_LAB_EXTENSION_ISSUE="${issue}" \
    IMMORTAL_LAB_EXTENSION_RUN_ID="${run_id}" \
    IMMORTAL_LAB_EXTENSION_STATE_DIR="${directory}" \
    IMMORTAL_LAB_EXTENSION_PORTS_JSON="${ports}" \
    "${hook}" "${command}"
}

cmd_manifest() {
  local extension="${1:-}"
  if test -z "${extension}"; then
    jq '{schema, loopback_only, extensions, custody_boundary, teardown}' "${manifest_file}"
  else
    extension="$(require_extension "${extension}")"
    extension_json "${extension}" | jq .
  fi
}

cmd_up() {
  local extension directory hook
  extension="$(require_extension "${1:-}")"
  directory="$(extension_dir "${extension}")"
  if test -e "${directory}"; then
    echo "lab-extensions: refusing to reuse ${directory}; run down if it is recorded" >&2
    exit 1
  fi
  hook="$(hook_path "${extension}")"
  if test -z "${hook}" || ! test -x "${hook}"; then
    echo "lab-extensions: ${extension} is hook-only until issue #$(extension_json "${extension}" | jq -r .issue); configure $(extension_json "${extension}" | jq -r .hook_environment) with an executable" >&2
    exit 2
  fi
  mkdir -p "${directory}"
  chmod 700 "${directory}"
  printf '%s\n' "${hook}" >"${directory}/hook"
  printf 'immortal-lab-%s-%s-%s\n' "${extension}" "$$" "$(date +%s)" >"${directory}/run-id"
  chmod 600 "${directory}/hook" "${directory}/run-id"
  touch "${directory}/wrapper-created"
  if ! invoke_hook "${extension}" "${hook}" up; then
    invoke_hook "${extension}" "${hook}" down >/dev/null 2>&1 || true
    rm -rf "${directory}"
    echo "lab-extensions: ${extension} hook failed; wrapper-owned state was removed" >&2
    exit 1
  fi
  touch "${directory}/active"
  echo "lab-extensions: ${extension} active under ${directory}"
}

cmd_status() {
  local extension directory hook
  extension="$(require_extension "${1:-}")"
  directory="$(extension_dir "${extension}")"
  if ! test -f "${directory}/wrapper-created" || ! test -f "${directory}/active"; then
    if test -n "$(hook_path "${extension}")"; then
      echo "lab-extensions: ${extension} inactive (hook configured)"
    else
      echo "lab-extensions: ${extension} inactive (hook not configured; owned by issue #$(extension_json "${extension}" | jq -r .issue))"
    fi
    return 0
  fi
  hook="$(cat "${directory}/hook")"
  if ! test -x "${hook}"; then
    echo "lab-extensions: ${extension} is recorded active but its hook is unavailable" >&2
    exit 1
  fi
  invoke_hook "${extension}" "${hook}" status
}

cmd_down() {
  local extension directory hook
  extension="$(require_extension "${1:-}")"
  directory="$(extension_dir "${extension}")"
  if ! test -e "${directory}"; then
    echo "lab-extensions: ${extension} has no wrapper-owned state"
    return 0
  fi
  if ! test -f "${directory}/wrapper-created" || ! test -f "${directory}/active"; then
    echo "lab-extensions: ${directory} has no active ownership record; refusing teardown" >&2
    exit 1
  fi
  hook="$(cat "${directory}/hook")"
  if ! test -x "${hook}"; then
    echo "lab-extensions: ${extension} hook is unavailable; refusing an incomplete teardown" >&2
    exit 1
  fi
  invoke_hook "${extension}" "${hook}" down
  rm -rf "${directory}"
  echo "lab-extensions: ${extension} stopped and wrapper-owned state removed"
}

command="${1:-}"
shift || true
case "${command}" in
manifest) cmd_manifest "$@" ;;
up) cmd_up "$@" ;;
status) cmd_status "$@" ;;
down) cmd_down "$@" ;;
help | --help | -h | "") usage ;;
*)
  echo "lab-extensions: unknown command '${command}'" >&2
  usage >&2
  exit 1
  ;;
esac
