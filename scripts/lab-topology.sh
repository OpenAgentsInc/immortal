#!/usr/bin/env bash
# Adversarial-lab topology manifest (immortal#32/#18): the ports, datadirs,
# and identities that let two relays, two providers, the harness, one
# bitcoind, and two CLN nodes coexist on one machine. Print-only; this
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
cln1                 p2p ${cln1_port}                    ${lab_dir}/cln1
                                                 status: $(live_cln 1)
cln2                 p2p ${cln2_port}                    ${lab_dir}/cln2
                                                 status: $(live_cln 2)
provider A           none (outbound only)        identity via IMMORTAL_PROVIDER_IDENTITY_SECRET
                                                 relay via IMMORTAL_PROVIDER_RELAY_URL=ws://127.0.0.1:${relay_a_port}
provider B           none (outbound only)        second immortal-provider process, distinct
                                                 identity secret, relay ws://127.0.0.1:${relay_b_port}
wallet harness       none (outbound only)        crates/immortal-lab; identity at
                                                 ${state_dir}/identity.json
                                                 pubkey: $(harness_identity)

notes
-----
- Every listener binds 127.0.0.1 only; nothing in this lab is reachable
  off-machine. All identities are throwaway dev keys, never funded mainnet
  material.
- Port allocations avoid the regtest defaults (18443/18444) and each other,
  so a developer's own bitcoind or relay does not collide with the lab.
- Providers and the harness hold no listen ports: both speak outbound
  WebSocket to their relays, and the provider (post-#25) speaks outbound
  RPC to bitcoind (127.0.0.1:${rpc_port}) and its CLN node.
- jq is a lab-script prerequisite (macOS: brew install jq; Debian:
  apt-get install jq).
- Bring-up order: lab-bitcoind.sh up -> lab-cln.sh up [--with-hold] ->
  lab-cln.sh fund -> lab-cln.sh channel -> dev-relay.sh (per relay) ->
  dev-market-provider.sh (per provider) -> immortal-lab.
MANIFEST
