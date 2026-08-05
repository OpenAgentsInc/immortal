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
  relay-a.env relay-b.env provider-a.env provider-b.env wallet-driver.env \
  relay-a-postgres-password relay-b-postgres-password \
  provider-a-postgres-password provider-b-postgres-password \
  provider-a-wallet-seed provider-b-wallet-seed client-wallet-seed; do
  touch "${private_root}/${name}"
done

python3 -m unittest "${support_dir}/test_tcp_forward.py"

if ! docker compose version >/dev/null 2>&1; then
  echo "test-adversarial-compose: Docker Compose is required" >&2
  exit 1
fi

rendered="${private_root}/compose.json"
IMMORTAL_ADVERSARIAL_PRIVATE_DIR="${private_root}" \
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
    "relay-b": "service:bitcoin-b",
    "provider-b": "service:bitcoin-b",
    "alert-sink-b": "service:bitcoin-b",
    "provider-b-egress": "service:bitcoin-b",
    "cln-provider-a": "service:bitcoin-a",
    "cln-provider-b": "service:bitcoin-b",
    "cln-wallet": "service:wallet-gateway",
    "wallet-driver": "service:wallet-gateway",
}
for service, expected_mode in namespace.items():
    if services[service].get("network_mode") != expected_mode:
        raise SystemExit(f"{service} has another network namespace")
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
    "127.0.0.1:18443=bitcoin-a:28443",
    "127.0.0.1:18444=bitcoin-b:28443",
):
    if endpoint not in gateway_command:
        raise SystemExit(f"wallet gateway lacks {endpoint}")
if "0.0.0.0:28443=127.0.0.1:18443" not in services["provider-a-egress"].get("command", []):
    raise SystemExit("wallet bitcoind access bypasses the provider-A namespace egress")
if "0.0.0.0:28443=127.0.0.1:18443" not in services["provider-b-egress"].get("command", []):
    raise SystemExit("wallet bitcoind access bypasses the provider-B namespace egress")
if document.get("networks", {}).get("adversarial", {}).get("internal") is not True:
    raise SystemExit("adversarial bridge is not internal")
PY

echo "test-adversarial-compose: isolated topology and loopback gateway passed"
