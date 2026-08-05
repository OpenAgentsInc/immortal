#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../../.."

support_dir="scripts/support/provider-funded"
compose_file="${support_dir}/adversarial-compose.yaml"
private_root="$(mktemp -d "${TMPDIR:-/tmp}/immortal-adversarial-compose.XXXXXX")"

cleanup() {
  local exit_status=$?
  trap - EXIT INT TERM
  case "$(basename "${private_root}")" in
  immortal-adversarial-compose.*)
    if test -f "${private_root}/owned"; then
      rm -rf -- "${private_root}"
    else
      echo "test-adversarial-compose: private root lost ownership marker" >&2
      exit_status=1
    fi
    ;;
  *)
    echo "test-adversarial-compose: refused unexpected private root" >&2
    exit_status=1
    ;;
  esac
  exit "${exit_status}"
}
trap cleanup EXIT INT TERM

umask 077
touch "${private_root}/owned"
mkdir -m 0700 "${private_root}/evidence" "${private_root}/state"
for name in \
  bitcoin-a.conf bitcoin-b.conf \
  cln-provider-a.conf cln-provider-b.conf cln-wallet.conf \
  relay-a.env relay-b.env provider-a.env provider-b.env wallet-driver.env esplora.env \
  relay-a-postgres-password relay-b-postgres-password \
  provider-a-postgres-password provider-b-postgres-password \
  provider-a-wallet-seed provider-b-wallet-seed client-wallet-seed; do
  touch "${private_root}/${name}"
done

python3 -m unittest "${support_dir}/test_tcp_forward.py"
bash -n scripts/test-lab-adversarial.sh

python3 - scripts/test-lab-adversarial.sh <<'PY'
import pathlib
import sys

runner = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
for phase in (
    "channel-provider-a-wallet",
    "channel-provider-b-wallet",
    "channel-connect-provider-a-provider-b",
    "channel-fund-provider-a-provider-b",
    "channel-readiness",
):
    if f"current_phase={phase}" not in runner:
        raise SystemExit(f"adversarial runner lacks granular {phase} receipt")
for case_id, injection, checkpoint, target in (
    ("relay-a-partition", "relay_loss", "submarine:funding_execution_ready", "relay-a"),
    ("relay-b-partition", "relay_loss", "submarine:funding_execution_ready", "relay-b"),
    ("provider-a-crash-restart", "provider_crash", "submarine:funding_effect_recorded", "provider-a"),
    ("provider-b-crash-restart", "provider_crash", "submarine:funding_effect_recorded", "provider-b"),
    ("wallet-crash-restart", "wallet_crash", "submarine:funding_effect_recorded", "wallet-driver"),
):
    case_start = runner.find(f"{case_id})")
    case_end = runner.find(";;", case_start)
    case = runner[case_start:case_end]
    if case_start < 0 or not all(value in case for value in (injection, checkpoint, target)):
        raise SystemExit(f"{case_id} lacks an exact external control mapping")
for member in ("before_pid", "after_pid", "process_replaced_and_ready"):
    if member not in runner:
        raise SystemExit(f"adversarial acknowledgement lacks {member}")
for container in ("wallet-driver-initial", "wallet-driver-replacement"):
    if container not in runner:
        raise SystemExit(f"wallet restart lacks deterministic {container} ownership")
if "provider-funding chain height" not in runner:
    raise SystemExit("provider startup lacks an all-CLN chain-height barrier")
wallet_environment_start = runner.index('cat >"${private_root}/wallet-driver.env"')
wallet_environment_end = runner.index("\nEOF", wallet_environment_start)
wallet_environment = runner[wallet_environment_start:wallet_environment_end]
if "IMMORTAL_PROVIDER_IDENTITY_SECRET" in wallet_environment:
    raise SystemExit("wallet driver has provider signing authority")
for predicate in (
    "event_id = :'refused_rfq' AND kind = 39604",
    "session_id = :'refused_session' AND kind = 39605",
    "event_id = :'active_quote' AND kind = 39605",
):
    if predicate not in runner:
        raise SystemExit("double-reservation audit uses another MKT kind mapping")
PY

if ! docker compose version >/dev/null 2>&1; then
  echo "test-adversarial-compose: Docker Compose is required" >&2
  exit 1
fi

rendered="${private_root}/compose.json"
IMMORTAL_ADVERSARIAL_PRIVATE_DIR="${private_root}" \
  IMMORTAL_ADVERSARIAL_PROVIDER_IMAGE=immortal-adversarial-provider-test:local \
  docker compose --file "${compose_file}" config --format json >"${rendered}"

python3 - "${rendered}" <<'PY'
import json
import pathlib
import sys

document = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
services = document.get("services", {})
expected = {
    "alert-sink-a", "alert-sink-b", "bitcoin-a", "bitcoin-b",
    "cln-provider-a", "cln-provider-b", "cln-wallet",
    "esplora-broadcast", "keyless-executor",
    "provider-a", "provider-a-egress", "provider-a-postgres",
    "provider-b", "provider-b-egress", "provider-b-postgres",
    "relay-a", "relay-a-postgres", "relay-b", "relay-b-postgres",
    "wallet-driver", "wallet-gateway",
}
if set(services) != expected:
    raise SystemExit("adversarial Compose service closure changed")
if any(service.get("ports") for service in services.values()):
    raise SystemExit("adversarial Compose publishes a host port")
namespace = {
    "relay-a": "service:bitcoin-a",
    "provider-a": "service:bitcoin-a",
    "alert-sink-a": "service:bitcoin-a",
    "provider-a-egress": "service:bitcoin-a",
    "esplora-broadcast": "service:bitcoin-a",
    "relay-b": "service:bitcoin-b",
    "provider-b": "service:bitcoin-b",
    "alert-sink-b": "service:bitcoin-b",
    "provider-b-egress": "service:bitcoin-b",
    "cln-provider-a": "service:bitcoin-a",
    "cln-provider-b": "service:bitcoin-b",
    "cln-wallet": "service:wallet-gateway",
    "wallet-driver": "service:wallet-gateway",
    "keyless-executor": "service:wallet-gateway",
}
for service, expected_mode in namespace.items():
    if services[service].get("network_mode") != expected_mode:
        raise SystemExit(f"{service} has another network namespace")
for service in ("cln-provider-a", "cln-provider-b", "cln-wallet"):
    if services[service].get("environment", {}).get("LIGHTNINGD_NETWORK") != "regtest":
        raise SystemExit(f"{service} does not force the pinned image entrypoint to regtest")
provider_cln_dockerfile = "scripts/support/provider-funded/Dockerfile.cln-hold-adversarial"
for service in ("cln-provider-a", "cln-provider-b"):
    if services[service].get("build", {}).get("dockerfile") != provider_cln_dockerfile:
        raise SystemExit(f"{service} does not use the adversarial hold-plugin image")
wallet_cln_dockerfile = "scripts/support/provider-funded/Dockerfile.cln-hold"
if services["cln-wallet"].get("build", {}).get("dockerfile") != wallet_cln_dockerfile:
    raise SystemExit("wallet CLN does not retain the stock hold-plugin image")
for provider, own_rpc, own_seed, other_rpc, other_seed in (
    ("provider-a", "cln-provider-a-rpc", "provider-a-wallet-seed", "cln-provider-b-rpc", "provider-b-wallet-seed"),
    ("provider-b", "cln-provider-b-rpc", "provider-b-wallet-seed", "cln-provider-a-rpc", "provider-a-wallet-seed"),
):
    encoded = json.dumps(services[provider].get("volumes", []), sort_keys=True)
    if own_rpc not in encoded or own_seed not in encoded:
        raise SystemExit(f"{provider} lacks its own custody mounts")
    if other_rpc in encoded or other_seed in encoded or "cln-wallet-rpc" in encoded:
        raise SystemExit(f"{provider} has a cross-party custody mount")
    if services[provider].get("build", {}).get("target") != "provider":
        raise SystemExit(f"{provider} does not build the shipped provider target")
    if services[provider].get("command") != ["run"]:
        raise SystemExit(f"{provider} does not run the shipped funded mode")
if services["provider-a"].get("image") != services["provider-b"].get("image"):
    raise SystemExit("providers do not bind one shipped image reference")
def volume_source(service, target):
    matches = [
        volume.get("source")
        for volume in services[service].get("volumes", [])
        if volume.get("type") == "volume" and volume.get("target") == target
    ]
    if len(matches) != 1 or not matches[0]:
        raise SystemExit(f"{service} lacks one owned volume at {target}")
    return matches[0]

isolated_volumes = [
    volume_source("bitcoin-a", "/var/lib/bitcoin"),
    volume_source("bitcoin-b", "/var/lib/bitcoin"),
    volume_source("relay-a-postgres", "/var/lib/postgresql/data"),
    volume_source("relay-b-postgres", "/var/lib/postgresql/data"),
    volume_source("provider-a-postgres", "/var/lib/postgresql/data"),
    volume_source("provider-b-postgres", "/var/lib/postgresql/data"),
]
for service in ("cln-provider-a", "cln-provider-b", "cln-wallet"):
    isolated_volumes.append(volume_source(service, "/root/.lightning"))
    isolated_volumes.append(volume_source(service, "/rail-rpc"))
if len(set(isolated_volumes)) != len(isolated_volumes):
    raise SystemExit("adversarial parties share a data or rail-RPC volume")
gateway_command = services["wallet-gateway"].get("command", [])
for endpoint in (
    "127.0.0.1:18080=bitcoin-a:28080",
    "127.0.0.1:18081=bitcoin-b:28081",
    "127.0.0.1:9091=bitcoin-a:29091",
    "127.0.0.1:9092=bitcoin-b:29092",
    "127.0.0.1:9191=bitcoin-a:29191",
    "127.0.0.1:9192=bitcoin-b:29192",
    "127.0.0.1:3002=bitcoin-a:23002",
    "127.0.0.1:18443=bitcoin-a:28443",
    "127.0.0.1:18444=bitcoin-b:28443",
):
    if endpoint not in gateway_command:
        raise SystemExit(f"wallet gateway lacks {endpoint}")
if "0.0.0.0:28443=127.0.0.1:18443" not in services["provider-a-egress"].get("command", []):
    raise SystemExit("wallet bitcoind access bypasses the provider-A namespace egress")
if "0.0.0.0:28443=127.0.0.1:18443" not in services["provider-b-egress"].get("command", []):
    raise SystemExit("wallet bitcoind access bypasses the provider-B namespace egress")
keyless = services["keyless-executor"]
keyless_environment = keyless.get("environment", {})
if set(keyless_environment) != {
    "IMMORTAL_LAB_KEYLESS_REQUEST_FILE", "IMMORTAL_LAB_KEYLESS_RESULT_FILE"
}:
    raise SystemExit("keyless executor environment gained another input")
encoded_keyless = json.dumps(keyless.get("volumes", []), sort_keys=True).lower()
for forbidden in ("wallet", "seed", "rpc", "macaroon", "state", "rail"):
    if forbidden in encoded_keyless:
        raise SystemExit(f"keyless executor gained forbidden mount term {forbidden}")
if "/keyless" not in encoded_keyless or keyless.get("command") != ["doomsday-keyless-executor"]:
    raise SystemExit("keyless executor does not expose its exact bounded command volume")
if services["esplora-broadcast"].get("entrypoint") != [
    "python3", "/usr/local/libexec/immortal-lab-esplora-broadcast"
]:
    raise SystemExit("Esplora-compatible broadcaster has another entrypoint")
if document.get("networks", {}).get("adversarial", {}).get("internal") is not True:
    raise SystemExit("adversarial bridge is not internal")
PY

echo "test-adversarial-compose: isolated topology and loopback gateway passed"
