#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
WORK_ROOT=$(cd "$ROOT/.." && pwd)
IMMORTAL_COMMIT=$(git -C "$ROOT" rev-parse HEAD)
ARKD_SOURCE=${ARKD_SOURCE:-$WORK_ROOT/projects/arkade/repos/arkd}
ARKADE_SDK_SOURCE=${ARKADE_SDK_SOURCE:-$WORK_ROOT/projects/arkade/repos/ts-sdk}
ARKADE_EXIT_SOURCE=${ARKADE_EXIT_SOURCE:-$WORK_ROOT/projects/arkade/repos/arkade-unilateral-exit}
EXPECTED_ARKD=8b34e352859595cc03ba22ffa35088ab88b87fd9
EXPECTED_SDK=dfa1af44274bae97bd184b499d7697ea5f5e4cd3
EXPECTED_EXIT=d9c949d3be7cc6eaab7551bc52cc502b90647b2d
EXPECTED_REGTEST=15354f994dbba032f856e9a8e02f33b69b8c0e8a
ARKD_IMAGE=immortal-lab-arkd:8b34e352
ARKD_WALLET_IMAGE=immortal-lab-arkd-wallet:8b34e352
MEMPOOL_WEB_PORT=${ARK_LAB_MEMPOOL_WEB_PORT:-43000}
ARKD_PORT=${ARK_LAB_ARKD_PORT:-47070}
ARKD_ADMIN_PORT=${ARK_LAB_ARKD_ADMIN_PORT:-47071}
ARKD_WALLET_PORT=${ARK_LAB_ARKD_WALLET_PORT:-46060}
LAB_DIR=$(mktemp -d "${TMPDIR:-/tmp}/immortal-ark-operator-removal.XXXXXX")
PACKAGE=$LAB_DIR/exit-package.json
PREPARATION=$LAB_DIR/preparation.json
RECEIPT=$LAB_DIR/receipt.json
RECORD_PATH=${IMMORTAL_ARK_LAB_RECORD_PATH:-$ROOT/target/lab-evidence/ark-operator-removal-v1.json}
REGTEST=$ARKADE_SDK_SOURCE/regtest/regtest.mjs
TOPOLOGY_OWNED=false

cleanup() {
  local exit_status=$?
  trap - EXIT INT TERM
  if [[ "$TOPOLOGY_OWNED" == true && -f "$REGTEST" ]]; then
    MEMPOOL_WEB_PORT=$MEMPOOL_WEB_PORT \
      ARKD_PORT=$ARKD_PORT \
      ARKD_ADMIN_PORT=$ARKD_ADMIN_PORT \
      ARKD_WALLET_PORT=$ARKD_WALLET_PORT \
      node "$REGTEST" clean >/dev/null 2>&1 || exit_status=1
  fi
  case "$(basename "$LAB_DIR")" in
    immortal-ark-operator-removal.*) rm -rf -- "$LAB_DIR" || exit_status=1 ;;
    *) echo "Ark lab refused unexpected private directory $LAB_DIR" >&2; exit_status=1 ;;
  esac
  exit "$exit_status"
}
trap cleanup EXIT INT TERM

for command_name in docker git node pnpm; do
  command -v "$command_name" >/dev/null 2>&1 || {
    echo "Ark lab requires $command_name" >&2
    exit 1
  }
done
docker info >/dev/null 2>&1 || {
  echo "Ark lab requires a running Docker daemon" >&2
  exit 1
}

require_revision() {
  local source=$1
  local expected=$2
  local subject=$3
  [[ -d "$source/.git" ]] || { echo "$subject source is missing: $source" >&2; exit 1; }
  local observed
  observed=$(git -C "$source" rev-parse HEAD)
  [[ "$observed" == "$expected" ]] || {
    echo "$subject revision mismatch: expected $expected, observed $observed" >&2
    exit 1
  }
  [[ -z "$(git -C "$source" status --short)" ]] || {
    echo "$subject source must be clean: $source" >&2
    exit 1
  }
}

require_revision "$ARKD_SOURCE" "$EXPECTED_ARKD" arkd
require_revision "$ARKADE_SDK_SOURCE" "$EXPECTED_SDK" arkade-ts-sdk
require_revision "$ARKADE_EXIT_SOURCE" "$EXPECTED_EXIT" arkade-unilateral-exit
git -C "$ARKADE_SDK_SOURCE" submodule update --init --recursive
[[ "$(git -C "$ARKADE_SDK_SOURCE/regtest" rev-parse HEAD)" == "$EXPECTED_REGTEST" ]] || {
  echo "arkade regtest fixture revision mismatch" >&2
  exit 1
}

for name in bitcoin bitcoin-miner postgres nbxplorer fulcrum mempool_mariadb mempool_api \
  mempool_web lnd arkd arkd-wallet arkade-wallet arkade-explorer; do
  if docker container inspect "$name" >/dev/null 2>&1; then
    echo "Ark lab refuses to replace existing container $name" >&2
    exit 1
  fi
done
for volume in arkade-regtest_postgres_datadir arkade-regtest_mempool_mariadb \
  arkade-regtest_mempool_api_datadir arkade-regtest_lnd_datadir \
  arkade-regtest_fulcrum_datadir arkade-regtest_bitcoin_datadir \
  arkade-regtest_nbxplorer_datadir arkade-regtest_ark_datadir \
  arkade-regtest_ark_wallet_datadir; do
  if docker volume inspect "$volume" >/dev/null 2>&1; then
    echo "Ark lab refuses to reuse existing volume $volume" >&2
    exit 1
  fi
done
if docker network inspect arkade-regtest_default >/dev/null 2>&1; then
  echo "Ark lab refuses to reuse existing network arkade-regtest_default" >&2
  exit 1
fi

docker build --quiet --tag "$ARKD_IMAGE" --file "$ARKD_SOURCE/Dockerfile" "$ARKD_SOURCE" >/dev/null
docker build --quiet --tag "$ARKD_WALLET_IMAGE" --file "$ARKD_SOURCE/arkdwallet.Dockerfile" "$ARKD_SOURCE" >/dev/null
(cd "$ARKADE_SDK_SOURCE" && pnpm install --frozen-lockfile >/dev/null)
(cd "$ARKADE_SDK_SOURCE/packages/ts-sdk" && pnpm build >/dev/null)
(cd "$ARKADE_EXIT_SOURCE" && pnpm install --frozen-lockfile >/dev/null)

TOPOLOGY_OWNED=true
if ! ARKD_IMAGE=$ARKD_IMAGE \
  ARKD_WALLET_IMAGE=$ARKD_WALLET_IMAGE \
  MEMPOOL_WEB_PORT=$MEMPOOL_WEB_PORT \
  MEMPOOL_API_PORT=48999 \
  BITCOIN_RPC_PORT=48443 \
  BITCOIN_P2P_PORT=48444 \
  NBXPLORER_PORT=42838 \
  POSTGRES_PORT=49372 \
  FULCRUM_TCP_PORT=45001 \
  FULCRUM_SSL_PORT=45003 \
  LND_P2P_PORT=49735 \
  LND_RPC_PORT=50009 \
  ARKD_PORT=$ARKD_PORT \
  ARKD_ADMIN_PORT=$ARKD_ADMIN_PORT \
  ARKD_WALLET_PORT=$ARKD_WALLET_PORT \
  WALLET_PORT=43003 \
  EXPLORER_PORT=47080 \
  node "$REGTEST" start \
    --env "$ARKADE_SDK_SOURCE/packages/ts-sdk/.env.regtest" \
    --profile ark >"$LAB_DIR/regtest-start.log" 2>&1; then
  echo "Ark regtest topology failed to start; private diagnostics were removed" >&2
  exit 1
fi

node "$ROOT/scripts/support/ark-operator-removal/prepare.mjs" \
  --sdk-entry "$ARKADE_SDK_SOURCE/packages/ts-sdk/dist/index.js" \
  --regtest "$REGTEST" \
  --arkd-url "http://127.0.0.1:$ARKD_PORT" \
  --esplora-url "http://127.0.0.1:$MEMPOOL_WEB_PORT/api" \
  --package "$PACKAGE" \
  --metadata "$PREPARATION" \
  --arkd-container arkd

for name in arkade-explorer arkade-wallet arkd arkd-wallet nbxplorer postgres; do
  project=$(docker inspect --format '{{ index .Config.Labels "com.docker.compose.project" }}' "$name")
  [[ "$project" == "arkade-regtest" ]] || {
    echo "refusing to remove $name outside the Ark lab project" >&2
    exit 1
  }
  docker rm --force "$name" >/dev/null
done
for volume in arkade-regtest_ark_datadir arkade-regtest_ark_wallet_datadir \
  arkade-regtest_nbxplorer_datadir arkade-regtest_postgres_datadir; do
  project=$(docker volume inspect --format '{{ index .Labels "com.docker.compose.project" }}' "$volume")
  [[ "$project" == "arkade-regtest" ]] || {
    echo "refusing to remove $volume outside the Ark lab project" >&2
    exit 1
  }
  docker volume rm "$volume" >/dev/null
done

for name in arkade-explorer arkade-wallet arkd arkd-wallet nbxplorer postgres; do
  if docker container inspect "$name" >/dev/null 2>&1; then
    echo "operator component survived permanent removal: $name" >&2
    exit 1
  fi
done

node "$ROOT/scripts/support/ark-operator-removal/execute.mjs" \
  --sdk-entry "$ARKADE_EXIT_SOURCE/node_modules/@arkade-os/sdk/dist/index.js" \
  --regtest "$REGTEST" \
  --package "$PACKAGE" \
  --receipt "$RECEIPT" \
  --esplora-url "http://127.0.0.1:$MEMPOOL_WEB_PORT/api" \
  --arkd-url "http://127.0.0.1:$ARKD_PORT/v1/info" \
  --arkd-admin-url "http://127.0.0.1:$ARKD_ADMIN_PORT/v1/admin/wallet/status" \
  --arkd-wallet-url "http://127.0.0.1:$ARKD_WALLET_PORT"

node -e '
  const fs = require("node:fs");
  const preparation = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
  const receipt = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
  if (preparation.package_sha256 !== receipt.package_sha256) throw new Error("package digest changed");
  if (preparation.recovered_amount_sat !== receipt.confirmed_recovered_sat) throw new Error("recovered amount changed");
  if (!receipt.operator_endpoints_removed || receipt.execution_authority !== "keyless_esplora") throw new Error("operator removal was not proven");
' "$PREPARATION" "$RECEIPT"

node - "$PREPARATION" "$RECEIPT" "$RECORD_PATH" \
  "$IMMORTAL_COMMIT" "$EXPECTED_ARKD" "$EXPECTED_SDK" "$EXPECTED_EXIT" "$EXPECTED_REGTEST" <<'NODE'
const fs = require("node:fs");
const path = require("node:path");
const [preparationPath, receiptPath, recordPath, immortal, arkd, sdk, exit, regtest] = process.argv.slice(2);
const preparation = JSON.parse(fs.readFileSync(preparationPath, "utf8"));
const receipt = JSON.parse(fs.readFileSync(receiptPath, "utf8"));
const record = {
  schema: "openagents.immortal.ark-operator-removal-lab.v1",
  sources: {
    immortal,
    arkd,
    arkade_ts_sdk: sdk,
    arkade_unilateral_exit: exit,
    arkade_regtest: regtest,
  },
  preparation,
  recovery: receipt,
  claims: {
    actual_arkd_process: true,
    actual_vtxo_transfer: true,
    funded_presigned_exit: true,
    operator_indexer_wallet_permanently_removed_before_recovery: true,
    keyless_bitcoin_recovery: true,
    live_deployment: false,
    public_replacement: false,
  },
};
const encoded = `${JSON.stringify(record)}\n`;
if (encoded.length > 32768) throw new Error("Ark lab record exceeds its bound");
fs.mkdirSync(path.dirname(recordPath), { recursive: true, mode: 0o700 });
fs.writeFileSync(recordPath, encoded, { mode: 0o600 });
fs.chmodSync(recordPath, 0o600);
NODE

echo "Ark operator-removal lab passed: exact VTXO transfer, funded package, permanent operator removal, keyless Bitcoin recovery; record $RECORD_PATH"
