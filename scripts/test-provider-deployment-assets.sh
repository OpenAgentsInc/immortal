#!/bin/sh
set -eu

cd "$(dirname "$0")/.."

service=deploy/systemd/immortal-provider.service
environment=deploy/immortal-provider.env.example
backup=deploy/backup/immortal-provider-backup
backup_service=deploy/backup/immortal-provider-backup.service
backup_timer=deploy/backup/immortal-provider-backup.timer

for path in "${service}" "${environment}" "${backup}" "${backup_service}" "${backup_timer}"; do
    test -f "${path}"
done
test -x "${backup}"
sh -n "${backup}"

grep -Fqx 'KillSignal=SIGTERM' "${service}"
grep -Fqx 'TimeoutStopSec=infinity' "${service}"
grep -Fqx 'SendSIGKILL=no' "${service}"
grep -Fqx 'Requires=postgresql.service bitcoind.service lightningd.service' "${service}"
if grep -E '^(Requires|BindsTo)=.*immortal\.service' "${service}" >/dev/null; then
    echo 'test-provider-deployment-assets: provider must recover independently of the relay unit' >&2
    exit 1
fi

grep -Fqx 'IMMORTAL_PROVIDER_WALLET_SEED_FILE=/var/lib/immortal-provider/wallet.seed' "${environment}"
grep -Fqx 'IMMORTAL_PROVIDER_RELAY_URL=ws://127.0.0.1:8080' "${environment}"
grep -Fqx '# IMMORTAL_PROVIDER_LIQUID_ENABLED=true' "${environment}"
grep -Fqx '# IMMORTAL_PROVIDER_ELEMENTSD_HOST=127.0.0.1' "${environment}"
if grep -Eq '^IMMORTAL_PROVIDER_(LIQUID|ELEMENTSD)' "${environment}"; then
    echo 'test-provider-deployment-assets: Liquid must remain off by default' >&2
    exit 1
fi
if grep -Ev '^(#.*|$|[A-Z0-9_]+=.*(<[^>]+>|127\.0\.0\.1|/|mainnet|cln|hard|[0-9]+|true).*)$' "${environment}" >/dev/null; then
    echo 'test-provider-deployment-assets: provider environment example contains an unexpected value' >&2
    exit 1
fi

if grep -Ei 'wallet|seed|preimage|macaroon|claim.key|refund.key|rpc.password' "${backup}" "${backup_service}" "${backup_timer}" >/dev/null; then
    echo 'test-provider-deployment-assets: provider database backup touches custody material' >&2
    exit 1
fi
grep -Fqx 'pg_dump --dbname=immortal_provider --format=custom --no-owner --no-acl \' "${backup}"
grep -Fqx 'RestrictAddressFamilies=AF_UNIX' "${backup_service}"

grep -Fq 'reverse_proxy 127.0.0.1:9093' deploy/caddy/immortal-provider.Caddyfile
grep -Fq 'proxy_pass http://127.0.0.1:9093;' deploy/nginx/immortal-provider.conf
grep -Fq 'proxy_set_header Upgrade $http_upgrade;' deploy/nginx/immortal-provider.conf

jq -e '.cases[] | select(.name == "provider-v1-bounded-drain")
    | .mode == "funded"
    and .new_native_sessions == false
    and .new_boltz_compatibility_sessions == false
    and .existing_sessions_continue == true
    and .watchtower_continues == true
    and .exit_when_active_sessions_reach_zero == true' \
    tests/fixtures/provider/provider-runtime-v1.json >/dev/null
jq -e '."$defs".swap_client_config.properties.provider_route."$ref" == "#/$defs/provider_route_pin"' \
    tests/fixtures/nipmkt/swp-requester-api-v2.json >/dev/null
jq -e '.provider_drain.provider_mode == "funded"
    and .provider_drain.relay_unit_dependency == false
    and .client_selection.mid_session_failover == false' \
    tests/fixtures/nipmkt/swap-network-migration-v1.json >/dev/null

echo 'test-provider-deployment-assets: provider drain, install, backup, TLS, and route-pin assets passed'
