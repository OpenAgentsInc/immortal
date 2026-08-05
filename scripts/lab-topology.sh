#!/usr/bin/env bash
# Adversarial-lab topology manifest (immortal#32/#18): the ports, datadirs,
# and identities that let two relays, two providers, the harness, one
# bitcoind, two provider CLN nodes, and one wallet CLN node coexist on one
# machine. Print-only; this
# script starts and stops nothing. Topology shape per
# docs/inspiration/satora.md (regtest-devenv): product binaries from this
# repo, everything else operator-shaped fixture infrastructure beside them.
set -euo pipefail
cd "$(dirname "$0")/.."

lab_dir="${IMMORTAL_LAB_DIR:-${TMPDIR:-/tmp}/immortal-lab}"
btc_dir="${lab_dir}/bitcoind"
relay_a_port="${IMMORTAL_LAB_RELAY_A_PORT:-18080}"
relay_b_port="${IMMORTAL_LAB_RELAY_B_PORT:-18081}"
rpc_port="${IMMORTAL_LAB_BITCOIND_RPC_PORT:-18543}"
p2p_port="${IMMORTAL_LAB_BITCOIND_P2P_PORT:-18544}"
cln1_port="${IMMORTAL_LAB_CLN1_PORT:-19846}"
cln2_port="${IMMORTAL_LAB_CLN2_PORT:-19847}"
cln3_port="${IMMORTAL_LAB_CLN3_PORT:-19848}"
state_dir="${IMMORTAL_LAB_STATE_DIR:-target/lab-state}"

live_bitcoind() {
  if test -f "${btc_dir}/runtime"; then
    echo "up ($(cat "${btc_dir}/runtime"), height $(scripts/lab-bitcoind.sh cli getblockcount 2>/dev/null || echo '?'))"
  else
    echo "down"
  fi
}

live_cln() {
  local node="$1"
  if test -f "${lab_dir}/cln-runtime"; then
    local id
    id="$(scripts/lab-cln.sh cli "${node}" getinfo 2>/dev/null | jq -r .id 2>/dev/null || echo '?')"
    echo "up (id ${id})"
  else
    echo "down"
  fi
}

extension_status() {
  scripts/lab-extensions.sh status "$1" 2>/dev/null || echo "invalid ownership record"
}

harness_identity() {
  local identity="${state_dir}/identity.json"
  if test -f "${identity}"; then
    jq -r .pubkey "${identity}" 2>/dev/null || echo "?"
  else
    echo "none yet (created by 'immortal-lab rfq')"
  fi
}

cat <<MANIFEST
immortal adversarial-lab topology (one machine)
===============================================
lab fixture root:   ${lab_dir}
harness state dir:  ${state_dir}

component            port(s) on 127.0.0.1        datadir / identity
-------------------  --------------------------  ------------------------------------------
relay A              ws ${relay_a_port}                    disposable Postgres per scripts/dev-relay.sh
                                                 (IMMORTAL_DEV_RELAY_PORT=${relay_a_port})
relay B              ws ${relay_b_port}                    second dev-relay instance
                                                 (IMMORTAL_DEV_RELAY_PORT=${relay_b_port})
bitcoind (regtest)   rpc ${rpc_port}, p2p ${p2p_port}        ${btc_dir}
                                                 wallet "lab"; status: $(live_bitcoind)
provider-a CLN       p2p ${cln1_port}                    ${lab_dir}/cln1
                                                 status: $(live_cln 1)
provider-b CLN       p2p ${cln2_port}                    ${lab_dir}/cln2
                                                 status: $(live_cln 2)
wallet CLN           p2p ${cln3_port}                    ${lab_dir}/cln3
                                                 status: $(live_cln 3)
provider A           none (outbound only)        identity via IMMORTAL_PROVIDER_IDENTITY_SECRET
                                                 relay via IMMORTAL_PROVIDER_RELAY_URL=ws://127.0.0.1:${relay_a_port}
                                                 CLN socket owned by provider-a CLN; own Postgres
provider B           none (outbound only)        second immortal-provider process, distinct
                                                 identity secret, relay ws://127.0.0.1:${relay_b_port}
                                                 CLN socket owned by provider-b CLN; own Postgres
wallet harness       none (outbound only)        crates/immortal-lab; identity at
                                                 ${state_dir}/identity.json
                                                 pubkey: $(harness_identity)
                                                 CLN socket owned by wallet CLN

provider rail variants
----------------------
LND (#29):       implemented behind provider feature lnd; gate with IMMORTAL_PROVIDER_FUNDED_LIGHTNING_RAIL=lnd scripts/test-provider-funded.sh

extension hooks (inactive until their owning issues land)
----------------------------------------------------------
elementsd (#27): $(extension_status elementsd)
arkd (#20):      $(extension_status arkd)

notes
-----
- Every listener binds 127.0.0.1 only; nothing in this lab is reachable
  off-machine. All identities are throwaway dev keys, never funded mainnet
  material.
- Port allocations avoid the regtest defaults (18443/18444) and each other,
  so a developer's own bitcoind or relay does not collide with the lab.
- Providers and the harness hold no listen ports: they speak outbound
  WebSocket to their relays. Each provider speaks only to bitcoind
  (127.0.0.1:${rpc_port}) and its own CLN socket; the wallet CLN data and
  socket are never mounted into either provider.
- Provider-a, provider-b, and wallet CLN form a balanced three-edge topology.
  The hold plugin and all four hold RPCs are mandatory and probed on both
  provider nodes. The wallet node does not receive the plugin.
- The pinned machine-readable allocation and custody assertions live at
  tests/fixtures/lab/provisioning-v1.json. Extension hooks receive only their
  loopback ports, issue number, run id, and isolated state directory.
- jq is a lab-script prerequisite (macOS: brew install jq; Debian:
  apt-get install jq).
- Bring-up order: lab-bitcoind.sh up -> lab-cln.sh up ->
  lab-cln.sh fund -> lab-cln.sh channel -> dev-relay.sh (per relay) ->
  dev-market-provider.sh (per provider) -> immortal-lab.
- The owned discovery/Quote process proof is scripts/test-lab-topology-quotes.sh;
  its provider actors use --no-spend and its retained record makes no funded
  two-provider claim.
- The owned funded process proof is scripts/test-lab-topology-funded.sh; it
  uses the same public role graph with provider-owned CLN socket/seed mounts,
  two provider databases, rank-two cancellation, and rank-one settlement. This
  #32 gate shares bitcoind; #18 still requires separate bitcoind namespaces.
MANIFEST
