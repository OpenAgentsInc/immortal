#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
umask 077

test_root="$(mktemp -d)"
cleanup() {
  find "${test_root}" -depth -type f -exec unlink {} \; 2>/dev/null || true
  find "${test_root}" -depth -type d -exec rmdir {} \; 2>/dev/null || true
}
trap cleanup EXIT
mkdir "${test_root}/bin"
state_dir="${test_root}/state"

cat >"${test_root}/bin/docker" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
joined="$*"
case "${joined}" in
  info|"compose version") exit 0 ;;
  *" ps --status running --services") printf 'relay\nrelay-postgres\n' ;;
  *"exec -T relay-postgres psql"*)
    case "${joined}" in *schema_migrations*) printf '14\n' ;; *nostr_event*) printf '9\n' ;; *) printf '1\n' ;; esac
    ;;
  *"exec -T relay-postgres pg_dump"*) printf 'bounded-test-dump\n' ;;
  *"exec -T relay-postgres pg_restore"*|*"exec -T relay-postgres createdb"*|*"exec -T relay-postgres dropdb"*) exit 0 ;;
  *"config --quiet"*|*"build relay"*|*"up --detach relay-postgres relay"*) exit 0 ;;
  *) echo "unexpected docker invocation: ${joined}" >&2; exit 1 ;;
esac
SH
cat >"${test_root}/bin/curl" <<'SH'
#!/usr/bin/env bash
printf '%s\n' '{"name":"immortal","pubkey":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","supported_extensions":["mkt-swp-coordination:1","mkt-swp:1","nip-mkt"]}'
SH
chmod +x "${test_root}/bin/docker" "${test_root}/bin/curl"

PATH="${test_root}/bin:${PATH}" scripts/join-regtest.sh relay \
  --state-dir "${state_dir}" --port 18082 \
  --url wss://relay-independent.example:8443 >/dev/null

test "$(stat -f '%Lp' "${state_dir}/relay.env" 2>/dev/null || stat -c '%a' "${state_dir}/relay.env")" = 600
grep -Eq '^IMMORTAL_RELAY_SECRET_KEY=[0-9a-f]{64}$' "${state_dir}/relay.env"
digest="$(jq -r '.mkt.mkt_swp.coordination.conformance_sha256' contract/immortal-contract.json)"
grep -qx "IMMORTAL_MKT_SWP_COORDINATION_CONFORMANCE_SHA256=${digest}" "${state_dir}/relay.env"
! grep -q 'IMMORTAL_MKT_SWP_COORDINATION_ENABLED' "${state_dir}/relay.env"
project="$(jq -r .compose_project "${state_dir}/ownership.json")"
/usr/local/bin/docker compose --project-directory . --project-name "${project}" \
  --env-file "${state_dir}/compose.env" --profile relay -f deploy/join/compose.yaml \
  config --format json |
  jq -e --arg root "$(pwd -P)" '.services.relay.build.context == $root' >/dev/null
grep -Fqx 'COPY deploy/join/tls_egress.py /usr/local/libexec/immortal-join-tls-egress' \
  deploy/join/Dockerfile.tls-egress
grep -Fqx '!deploy/join/tls_egress.py' .dockerignore

PATH="${test_root}/bin:${PATH}" scripts/operate-joined-relay.sh status --state-dir "${state_dir}" |
  jq -e '.health == "ready" and .relay_pubkey == ("a" * 64)' >/dev/null
backup="$(PATH="${test_root}/bin:${PATH}" scripts/operate-joined-relay.sh backup --state-dir "${state_dir}")"
test -s "${backup}"
test "$(stat -f '%Lp' "${backup}" 2>/dev/null || stat -c '%a' "${backup}")" = 600
PATH="${test_root}/bin:${PATH}" scripts/operate-joined-relay.sh restore-test \
  --state-dir "${state_dir}" --backup "${backup}" |
  jq -e '.result == "passed" and .schema_migrations == 14 and .nostr_events == 9' >/dev/null

outside="${test_root}/outside.dump"
printf 'not owned\n' >"${outside}"
if PATH="${test_root}/bin:${PATH}" scripts/operate-joined-relay.sh restore-test \
  --state-dir "${state_dir}" --backup "${outside}" >/dev/null 2>&1; then
  echo "joined-relay-operations: accepted an outside backup" >&2
  exit 1
fi

echo "joined-relay-operations: passed"
