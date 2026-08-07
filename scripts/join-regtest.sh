#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
umask 077

compose_file="deploy/join/compose.yaml"
mode=""
state_dir="/var/lib/immortal-join"
relay_urls=""
addnode=""
gateway_origin=""
relay_port="18080"
relay_public_url=""
faucet_amount_sat="${IMMORTAL_JOIN_FAUCET_AMOUNT_SAT:-1000000}"

usage() {
  cat <<'USAGE'
usage: scripts/join-regtest.sh <provider|relay> [options]

provider options:
  --relays wss://a.example[,wss://b.example]   public relays (required once)
  --addnode host:port                          public bitcoind peer endpoint
  --gateway https://gateway.example            public-regtest gateway origin
                                               for faucet funding (optional)
  --state-dir /absolute/dir                    owned private state directory
                                               (default /var/lib/immortal-join)

relay options:
  --state-dir /absolute/dir                    owned private state directory
  --port N                                     host loopback port (default 18080)
  --url wss://relay.example                    the public URL your TLS proxy
                                               will serve (optional; defaults
                                               to ws://127.0.0.1:PORT)

Keys, seeds, and rail credentials are generated fresh into the owned state
directory and never leave this machine. Re-running with the same state
directory is idempotent.
USAGE
}

fail() { echo "join-regtest: $1" >&2; exit 1; }

[[ "${faucet_amount_sat}" =~ ^[0-9]+$ ]] &&
  test "${faucet_amount_sat}" -ge 10000 && test "${faucet_amount_sat}" -le 1000000 ||
  fail "IMMORTAL_JOIN_FAUCET_AMOUNT_SAT must be an integer in 10000..1000000"

require_commands() {
  local command_name
  for command_name in "$@"; do
    command -v "${command_name}" >/dev/null 2>&1 || fail "required command ${command_name} is unavailable"
  done
}

validate_state_path() {
  case "${state_dir}" in
    /*) ;;
    *) fail "state directory must be absolute" ;;
  esac
  case "${state_dir}" in
    /|/Users|/home|/var|/tmp|"$(pwd -P)"|"$(pwd -P)"/*)
      fail "state directory is too broad or inside the repository"
      ;;
  esac
  if test -L "${state_dir}"; then
    fail "state directory must not be a symlink"
  fi
}

validate_provider_inputs() {
  python3 - "${relay_urls}" "${addnode}" "${gateway_origin}" <<'PY'
import sys
import urllib.parse

relays = [value for value in sys.argv[1].split(",") if value]
if not 1 <= len(relays) <= 4 or len(relays) != len(set(relays)):
    raise SystemExit("provider requires one to four distinct wss relay URLs")
for value in relays:
    parsed = urllib.parse.urlsplit(value)
    if (
        parsed.scheme != "wss"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
    ):
        raise SystemExit("public relay URL must be an exact wss authority")
addnode = sys.argv[2]
if addnode:
    host, separator, port = addnode.rpartition(":")
    if not separator or not host or not port.isdecimal() or not 1 <= int(port) <= 65535:
        raise SystemExit("addnode must have host:port form")
gateway = sys.argv[3]
if gateway:
    parsed = urllib.parse.urlsplit(gateway)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
    ):
        raise SystemExit("gateway must be one exact https origin")
PY
}

random_hex() {
  LC_ALL=C od -An -N "$1" -tx1 /dev/urandom | tr -d ' \n'
}

write_secret() {
  local path="$1" value="$2"
  (umask 077; printf '%s\n' "${value}" >"${path}")
  chmod 0600 "${path}"
}

marker_field() {
  python3 - "${state_dir}/ownership.json" "$1" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
field = value.get(sys.argv[2], "")
print(",".join(field) if isinstance(field, list) else field)
PY
}

require_owned_state() {
  validate_state_path
  test -f "${state_dir}/ownership.json" || fail "owned state is absent"
  test ! -L "${state_dir}/ownership.json" || fail "ownership marker must not be a symlink"
  python3 - "${state_dir}/ownership.json" "$(pwd -P)" "${mode}" <<'PY'
import json, pathlib, sys
path = pathlib.Path(sys.argv[1])
if path.stat().st_size > 4096:
    raise SystemExit("ownership marker exceeds its bound")
value = json.loads(path.read_text(encoding="utf-8"))
if value.get("schema") != "openagents.immortal.join-owner.v1":
    raise SystemExit("ownership marker has another schema")
if value.get("repository") != sys.argv[2]:
    raise SystemExit("ownership marker belongs to another checkout")
if value.get("mode") != sys.argv[3]:
    raise SystemExit("ownership marker was initialized for another mode; use a fresh --state-dir")
project = value.get("compose_project")
if not isinstance(project, str) or not project.startswith("immortal-join-") or len(project) > 63:
    raise SystemExit("ownership marker has an invalid Compose project")
PY
}

write_marker() {
  python3 - "${state_dir}/ownership.json" "$(pwd -P)" "$1" "$2" "${mode}" \
    "${relay_urls}" "${addnode}" "${gateway_origin}" "${relay_port}" "${relay_public_url}" <<'PY'
import json, os, sys, time
value = {
    "schema": "openagents.immortal.join-owner.v1",
    "repository": sys.argv[2],
    "compose_project": sys.argv[3],
    "source_revision": sys.argv[4],
    "mode": sys.argv[5],
    "relay_urls": [item for item in sys.argv[6].split(",") if item],
    "addnode": sys.argv[7],
    "gateway_origin": sys.argv[8],
    "relay_port": sys.argv[9],
    "relay_public_url": sys.argv[10],
    "created_at": int(time.time()),
}
descriptor = os.open(sys.argv[1], os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(descriptor, "w", encoding="utf-8") as output:
    json.dump(value, output, indent=2, sort_keys=True)
    output.write("\n")
PY
}

project_name() { marker_field compose_project; }

compose() {
  docker compose --project-directory . --project-name "$(project_name)" \
    --env-file "${state_dir}/compose.env" --profile "${mode}" \
    -f "${compose_file}" "$@"
}

wait_for() {
  local description="$1" attempts="$2"
  shift 2
  local attempt
  for attempt in $(seq 1 "${attempts}"); do
    if "$@" >/dev/null 2>&1; then return 0; fi
    sleep 2
  done
  fail "${description} did not become ready within $((attempts * 2)) seconds"
}

primary_relay() { relay_urls_list=(${relay_urls//,/ }); printf '%s' "${relay_urls_list[0]}"; }

relay_authority() {
  python3 - "$(primary_relay)" <<'PY'
import sys, urllib.parse
parsed = urllib.parse.urlsplit(sys.argv[1])
print(f"{parsed.hostname}:{parsed.port or 443}")
PY
}

initialize_provider() {
  if test -e "${state_dir}/ownership.json"; then
    require_owned_state
    if test -z "${relay_urls}"; then relay_urls="$(marker_field relay_urls)"; fi
    if test -z "${addnode}"; then addnode="$(marker_field addnode)"; fi
    if test -z "${gateway_origin}"; then gateway_origin="$(marker_field gateway_origin)"; fi
    test "${relay_urls}" = "$(marker_field relay_urls)" || fail "relays differ from the owned state; use a fresh --state-dir"
    validate_provider_inputs
    echo "join-regtest: owned provider state already initialized at ${state_dir}"
    return
  fi
  test -n "${relay_urls}" || { usage >&2; fail "provider requires --relays"; }
  validate_provider_inputs
  install -d -m 0700 "${state_dir}"

  local project revision rpc_password postgres_password wallet_seed identity
  project="immortal-join-$(random_hex 5)"
  revision="$(git rev-parse HEAD)"
  rpc_password="$(random_hex 32)"
  postgres_password="$(random_hex 32)"
  wallet_seed="$(random_hex 32)"
  # A fresh provider identity secret is generated on this machine and never
  # printed, uploaded, or reused from any demo or fixture material.
  identity="$(python3 <<'PY'
import secrets
order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
value = 0
while not value:
    value = secrets.randbelow(order)
print(f"{value:064x}")
PY
  )"
  write_marker "${project}" "${revision}"
  write_secret "${state_dir}/provider-postgres-password" "${postgres_password}"
  write_secret "${state_dir}/provider-wallet-seed" "${wallet_seed}"

  cat >"${state_dir}/bitcoin.conf" <<EOF
regtest=1
server=1
txindex=1
fallbackfee=0.0002
listen=1
dnsseed=0
listenonion=0
[regtest]
bind=0.0.0.0:18444
$( test -n "${addnode}" && printf 'addnode=%s\n' "${addnode}" )
rpcbind=127.0.0.1
rpcallowip=127.0.0.1
rpcport=18443
rpcuser=immortal-join
rpcpassword=${rpc_password}
EOF
  cat >"${state_dir}/cln.conf" <<EOF
network=regtest
lightning-dir=/root/.lightning
rpc-file=/rail-rpc/lightning-rpc
rpc-file-mode=0660
bitcoin-rpcconnect=127.0.0.1
bitcoin-rpcport=18443
bitcoin-rpcuser=immortal-join
bitcoin-rpcpassword=${rpc_password}
bind-addr=0.0.0.0:19846
log-level=info
plugin=/usr/local/bin/hold
hold-grpc-port=-1
hold-expiry-deadline=30
EOF
  cat >"${state_dir}/provider.env" <<EOF
IMMORTAL_PROVIDER_DATABASE_URL=postgres://immortal_provider:${postgres_password}@provider-postgres:5432/immortal_provider
IMMORTAL_PROVIDER_RELAY_URL=ws://127.0.0.1:18080
IMMORTAL_PROVIDER_RELAY_AUTH_URL=$(primary_relay)
IMMORTAL_PROVIDER_IDENTITY_SECRET=${identity}
IMMORTAL_PROVIDER_BITCOIN_NETWORK=regtest
IMMORTAL_PROVIDER_BITCOIND_HOST=127.0.0.1
IMMORTAL_PROVIDER_BITCOIND_PORT=18443
IMMORTAL_PROVIDER_BITCOIND_RPC_USER=immortal-join
IMMORTAL_PROVIDER_BITCOIND_RPC_PASSWORD=${rpc_password}
IMMORTAL_PROVIDER_CLN_RPC_PATH=/rail/cln/lightning-rpc
IMMORTAL_PROVIDER_WALLET_SEED_FILE=/run/immortal-private/provider-wallet-seed
IMMORTAL_PROVIDER_HEALTH_BIND=127.0.0.1:9091
IMMORTAL_PROVIDER_CHAIN_POLL_SECONDS=1
IMMORTAL_PROVIDER_CHAIN_STALE_SECONDS=30
IMMORTAL_PROVIDER_MINIMUM_CONFIRMATIONS=1
IMMORTAL_PROVIDER_REORG_SAFETY_BLOCKS=2
IMMORTAL_PROVIDER_SPREAD_BPS=100
IMMORTAL_PROVIDER_FALLBACK_FEERATE_SAT_PER_VB=2
IMMORTAL_PROVIDER_QUOTE_MIN_SAT=10000
IMMORTAL_PROVIDER_QUOTE_MAX_SAT=1000000
IMMORTAL_PROVIDER_QUOTE_EXPIRY_SECONDS=300
IMMORTAL_PROVIDER_RESERVATION_TIER=hard
IMMORTAL_PROVIDER_LN_ROUTING_FEE_PPM=2900
EOF
  cat >"${state_dir}/compose.env" <<EOF
IMMORTAL_JOIN_PRIVATE_DIR=${state_dir}
IMMORTAL_JOIN_RELAY_EGRESS=$(relay_authority)
IMMORTAL_JOIN_RELAY_PORT=${relay_port}
EOF
  chmod 0600 "${state_dir}"/*.env "${state_dir}"/*.conf
  echo "join-regtest: initialized owned provider state at ${state_dir}"
}

initialize_relay() {
  if test -e "${state_dir}/ownership.json"; then
    require_owned_state
    relay_port="$(marker_field relay_port)"
    relay_public_url="$(marker_field relay_public_url)"
    echo "join-regtest: owned relay state already initialized at ${state_dir}"
    return
  fi
  [[ "${relay_port}" =~ ^[0-9]+$ ]] && test "${relay_port}" -ge 1024 && test "${relay_port}" -le 65535 ||
    fail "relay port must be in 1024..65535"
  install -d -m 0700 "${state_dir}"
  local project revision postgres_password relay_url
  project="immortal-join-$(random_hex 5)"
  revision="$(git rev-parse HEAD)"
  postgres_password="$(random_hex 32)"
  relay_url="${relay_public_url:-ws://127.0.0.1:${relay_port}}"
  write_marker "${project}" "${revision}"
  write_secret "${state_dir}/relay-postgres-password" "${postgres_password}"
  cat >"${state_dir}/relay.env" <<EOF
DATABASE_URL=postgres://immortal_relay:${postgres_password}@relay-postgres:5432/immortal_relay
IMMORTAL_BIND_ADDR=0.0.0.0
IMMORTAL_PORT=8080
IMMORTAL_RELAY_URL=${relay_url}
IMMORTAL_AUTH_REQUIRED=true
IMMORTAL_MKT_SWP_COORDINATION_ENABLED=true
EOF
  cat >"${state_dir}/compose.env" <<EOF
IMMORTAL_JOIN_PRIVATE_DIR=${state_dir}
IMMORTAL_JOIN_RELAY_EGRESS=unused:443
IMMORTAL_JOIN_RELAY_PORT=${relay_port}
EOF
  chmod 0600 "${state_dir}"/*.env
  echo "join-regtest: initialized owned relay state at ${state_dir}"
}

bitcoin_cli() {
  compose exec -T bitcoin bitcoin-cli \
    -conf=/run/immortal-private/bitcoin.conf -datadir=/var/lib/bitcoin "$@"
}

cln_cli() {
  compose exec -T cln lightning-cli --network=regtest \
    --lightning-dir=/root/.lightning --rpc-file=/rail-rpc/lightning-rpc "$@"
}

bitcoin_peered() { test "$(bitcoin_cli getconnectioncount)" -ge 1; }

chain_synced() {
  local info
  info="$(bitcoin_cli getblockchaininfo)"
  test "$(jq -er .blocks <<<"${info}")" -gt 0 &&
    test "$(jq -er .blocks <<<"${info}")" -eq "$(jq -er .headers <<<"${info}")"
}

cln_ready() {
  cln_cli getinfo | jq -e \
    '.network == "regtest" and .warning_bitcoind_sync == null and .warning_lightningd_sync == null'
}

provider_healthy() {
  compose exec -T provider /usr/bin/curl --fail --silent http://127.0.0.1:9091/healthz
}

provider_pubkey() {
  compose logs --no-color provider 2>/dev/null | sed -n \
    's/.*ready relay=.* pubkey=\([0-9a-f]\{64\}\).*/\1/p' | tail -1
}

provider_announced() { test -n "$(provider_pubkey)"; }

address_funded() {
  bitcoin_cli scantxoutset start "[\"addr($1)\"]" |
    jq -e '.success == true and .total_amount > 0'
}

request_faucet() {
  local address="$1" body request_id status
  body="$(jq -nc --arg address "${address}" --argjson amount "${faucet_amount_sat}" \
    '{"schema":"openagents.immortal.public-regtest-faucet-request.v1","address":$address,"amount_sat":$amount}')"
  request_id="$(curl --fail --silent --show-error --max-time 30 \
    -H 'Content-Type: application/json' \
    --data "${body}" "${gateway_origin}/v1/public-regtest/faucet" | jq -er .request_id)" ||
    fail "faucet request for ${address} was refused by ${gateway_origin}"
  [[ "${request_id}" =~ ^[0-9a-f]{64}$ ]] || fail "faucet returned an invalid request ID"
  local attempt
  for attempt in $(seq 1 60); do
    status="$(curl --fail --silent --max-time 30 \
      "${gateway_origin}/v1/public-regtest/faucet/${request_id}" | jq -er .status || true)"
    if test "${status}" = "paid"; then
      printf '%s' "${request_id}"
      return 0
    fi
    sleep 5
  done
  fail "faucet request ${request_id} was not paid within 300 seconds"
}

print_listing_request() {
  local pubkey="$1" health="$2"
  python3 - "${pubkey}" "${relay_urls}" "${health}" <<'PY'
import sys, urllib.parse
pubkey, relays, health = sys.argv[1], sys.argv[2], sys.argv[3]
coordinate = f"39601:{pubkey}:immortal-funded-btc-lightning"
title = f"Listing request: provider {pubkey[:16]}… on public regtest"
body = "\n".join([
    "## Listing request (discovered -> pinned)",
    "",
    f"- provider pubkey: `{pubkey}`",
    f"- offering coordinate: `{coordinate}`",
    f"- relays: {', '.join(relays.split(','))}",
    "",
    "### Health output",
    "",
    "```json",
    health,
    "```",
    "",
    "Pinning stays a signed human decision; no automation signs the launch manifest.",
])
query = urllib.parse.urlencode({"title": title, "body": body})
print("join-regtest: request a listing by opening:")
print(f"https://github.com/OpenAgentsInc/immortal/issues/new?{query}")
PY
}

run_provider() {
  require_commands docker git jq python3 curl od
  initialize_provider
  require_owned_state
  docker info >/dev/null 2>&1 || fail "Docker is unavailable"
  docker compose version >/dev/null 2>&1 || fail "Docker Compose is unavailable"
  compose config --quiet
  compose build bitcoin cln provider relay-egress
  compose up --detach bitcoin provider-postgres
  wait_for "Bitcoin node" 60 bitcoin_cli getblockchaininfo
  if test -n "${addnode}"; then
    wait_for "Bitcoin peering with ${addnode}" 60 bitcoin_peered
    wait_for "chain sync against the public network" 300 chain_synced
  fi
  compose up --detach cln relay-egress
  wait_for "Core Lightning" 120 cln_ready

  local provider_address cln_address faucet_ids="" faucet_state="skipped"
  provider_address="$(compose run --rm --no-deps provider address | tail -1)"
  [[ "${provider_address}" =~ ^bcrt1[0-9a-z]{6,85}$ ]] || fail "provider wallet address is invalid"
  cln_address="$(cln_cli newaddr bech32 | jq -er .bech32)"
  [[ "${cln_address}" =~ ^bcrt1[0-9a-z]{6,85}$ ]] || fail "Lightning wallet address is invalid"

  if test -n "${gateway_origin}"; then
    faucet_state="paid"
    faucet_ids="$(request_faucet "${provider_address}"),$(request_faucet "${cln_address}")"
    wait_for "provider wallet funding confirmation" 150 address_funded "${provider_address}"
    wait_for "Lightning wallet funding confirmation" 150 address_funded "${cln_address}"
  else
    echo "join-regtest: no --gateway given; skipping faucet funding" >&2
  fi

  compose up --detach provider
  wait_for "provider health" 120 provider_healthy
  wait_for "provider relay announcement" 120 provider_announced
  local pubkey health
  pubkey="$(provider_pubkey)"

  health="$(python3 - "${pubkey}" "${relay_urls}" "$(bitcoin_cli getblockcount)" \
    "$(bitcoin_cli getbestblockhash)" "$(bitcoin_cli getconnectioncount)" \
    "${faucet_state}" "${faucet_ids}" <<'PY'
import json, sys
pubkey, relays, height, best, peers, faucet_state, faucet_ids = sys.argv[1:8]
value = {
    "schema": "openagents.immortal.join-health.v1",
    "mode": "provider",
    "network": "bip122:0f9188f13cb7b2c9e5c72a6b65eeada4",
    "provider_pubkey": pubkey,
    "offering_coordinate": f"39601:{pubkey}:immortal-funded-btc-lightning",
    "relays": [item for item in relays.split(",") if item],
    "chain": {"height": int(height), "best_block_hash": best, "peers": int(peers)},
    "faucet": {"state": faucet_state, "request_ids": [item for item in faucet_ids.split(",") if item]},
    "health": "ready",
}
encoded = json.dumps(value, indent=2, sort_keys=True)
if len(encoded) > 8192:
    raise SystemExit("join health summary exceeds its bound")
print(encoded)
PY
  )"
  echo "${health}"
  print_listing_request "${pubkey}" "${health}"
  echo "join-regtest: custody note: the provider identity secret, wallet seed, and rail credentials live only in ${state_dir} on this machine"
}

run_relay() {
  require_commands docker git jq python3 curl od
  initialize_relay
  require_owned_state
  docker info >/dev/null 2>&1 || fail "Docker is unavailable"
  docker compose version >/dev/null 2>&1 || fail "Docker Compose is unavailable"
  compose config --quiet
  compose build relay
  compose up --detach relay-postgres relay
  local self_check=(curl --fail --silent -H 'Accept: application/nostr+json' "http://127.0.0.1:${relay_port}/")
  wait_for "relay NIP-11 document" 60 "${self_check[@]}"
  echo "join-regtest: NIP-11 self-check:"
  printf '  %s\n' "${self_check[*]}"
  "${self_check[@]}" | jq .
  echo "join-regtest: front this loopback port with your own TLS proxy before announcing a public wss URL"
}

command="${1:-}"
case "${command}" in
  provider|relay) mode="${command}"; shift ;;
  help|-h|--help) usage; exit 0 ;;
  *) usage >&2; exit 2 ;;
esac

while test "$#" -gt 0; do
  case "$1" in
    --relays) test "$#" -ge 2 || fail "--relays requires a value"; relay_urls="$2"; shift 2 ;;
    --addnode) test "$#" -ge 2 || fail "--addnode requires a value"; addnode="$2"; shift 2 ;;
    --gateway) test "$#" -ge 2 || fail "--gateway requires a value"; gateway_origin="${2%/}"; shift 2 ;;
    --state-dir) test "$#" -ge 2 || fail "--state-dir requires a value"; state_dir="$2"; shift 2 ;;
    --port) test "$#" -ge 2 || fail "--port requires a value"; relay_port="$2"; shift 2 ;;
    --url) test "$#" -ge 2 || fail "--url requires a value"; relay_public_url="$2"; shift 2 ;;
    *) usage >&2; fail "unknown option $1" ;;
  esac
done

case "${mode}" in
  provider) run_provider ;;
  relay) run_relay ;;
esac
