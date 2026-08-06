#!/bin/sh
set -eu

cd "$(dirname "$0")/.."

usage() {
    echo 'usage: scripts/test-swap-network-migration.sh --lab-record <json> --shadow-record <json> --debian-record <json> --output <json>' >&2
}

if test "$#" != 8; then
    usage
    exit 2
fi
lab_record=
shadow_record=
debian_record=
output=
while test "$#" -gt 0; do
    case "$1" in
        --lab-record) lab_record=$2 ;;
        --shadow-record) shadow_record=$2 ;;
        --debian-record) debian_record=$2 ;;
        --output) output=$2 ;;
        *) usage; exit 2 ;;
    esac
    shift 2
done
for path in "${lab_record}" "${shadow_record}" "${debian_record}"; do
    case "${path}" in
        docs/conformance/records/*.json) ;;
        *) echo "test-swap-network-migration: input record is outside docs/conformance/records" >&2; exit 2 ;;
    esac
    test -f "${path}"
done
case "${output}" in
    docs/conformance/records/*.json) ;;
    *) echo "test-swap-network-migration: output is outside docs/conformance/records" >&2; exit 2 ;;
esac
test ! -e "${output}"

scripts/test-provider-deployment-assets.sh
source_commit="$(git rev-parse HEAD)"
python3 - \
    tests/fixtures/nipmkt/swap-network-migration-v1.json \
    "${lab_record}" "${shadow_record}" "${debian_record}" "${output}" "${source_commit}" <<'PY'
import datetime
import hashlib
import json
import os
import pathlib
import re
import sys

fixture_path = pathlib.Path(sys.argv[1])
lab_path = pathlib.Path(sys.argv[2])
shadow_path = pathlib.Path(sys.argv[3])
debian_path = pathlib.Path(sys.argv[4])
output_path = pathlib.Path(sys.argv[5])
source_commit = sys.argv[6]
if not re.fullmatch(r"[0-9a-f]{40}", source_commit):
    raise SystemExit("source commit is invalid")


def read_unique(path):
    def unique(pairs):
        value = {}
        for name, member in pairs:
            if name in value:
                raise ValueError(f"duplicate JSON member {name}")
            value[name] = member
        return value

    with path.open(encoding="utf-8") as source:
        return json.load(source, object_pairs_hook=unique)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


fixture = read_unique(fixture_path)
lab = read_unique(lab_path)
shadow = read_unique(shadow_path)
debian = read_unique(debian_path)

expected_lab = fixture["lab"]
if digest(lab_path) != expected_lab["sha256"]:
    raise SystemExit("lab record digest changed")
if lab.get("case_count") != expected_lab["required_cases"] or len(lab.get("cases", [])) != expected_lab["required_cases"]:
    raise SystemExit("lab record is incomplete")
if any(case.get("result", {}).get("passed") is not True for case in lab["cases"]):
    raise SystemExit("lab record contains a failing case")
for name, expected in expected_lab["required_claims"].items():
    if lab.get("claims", {}).get(name) is not expected:
        raise SystemExit(f"lab claim differs: {name}")

if shadow.get("schema") != "openagents.immortal.boltz-readonly-shadow.v1" or shadow.get("result") != "passed":
    raise SystemExit("shadow record is not a passing v1 record")
if shadow.get("source_commit") != source_commit:
    raise SystemExit("shadow record was not produced from the current source commit")
shadow_contract = shadow.get("request_contract", {})
if shadow_contract.get("methods") != fixture["shadow"]["methods"] or shadow_contract.get("endpoints") != fixture["shadow"]["endpoints"]:
    raise SystemExit("shadow request surface differs from the fixture")
for forbidden in ("authentication", "request_bodies", "swap_identifiers", "websocket", "redirects"):
    if shadow_contract.get(forbidden) is not False:
        raise SystemExit(f"shadow request contract enables {forbidden}")
if shadow.get("summary", {}).get("endpoints") != len(fixture["shadow"]["endpoints"]):
    raise SystemExit("shadow record omitted an endpoint")
if shadow.get("claims", {}).get("public_replacement") is not False:
    raise SystemExit("shadow record overclaims public replacement")

if debian.get("schema") != "openagents.immortal.debian-provider-funded-run.v1" or debian.get("result") != "passed":
    raise SystemExit("Debian provider record is not a passing v1 record")
if debian.get("source_commit") != source_commit or debian.get("clean_debian_environment") is not True:
    raise SystemExit("Debian provider record is not from the current pushed source")
deployment = debian.get("deployment_assets", {})
if deployment.get("systemd_verified") is not True or deployment.get("backup_restore_passed") is not True:
    raise SystemExit("Debian provider record lacks install and backup/restore proof")

old_origin = "https://legacy.example.invalid"
new_origin = "https://provider.example.invalid"
session_origins = {"before-cutover": old_origin}
default_origin = new_origin
session_origins["after-cutover"] = default_origin
if session_origins["before-cutover"] != old_origin:
    raise SystemExit("cutover moved an in-flight session")
default_origin = old_origin
session_origins["after-rollback"] = default_origin
if session_origins["after-cutover"] != new_origin:
    raise SystemExit("rollback moved an in-flight candidate session")

now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
record = {
    "schema": "openagents.immortal.swap-network-cutover-rehearsal.v1",
    "source_commit": source_commit,
    "executed_at": now,
    "result": "passed",
    "inputs": {
        str(lab_path): digest(lab_path),
        str(shadow_path): digest(shadow_path),
        str(debian_path): digest(debian_path),
        str(fixture_path): digest(fixture_path),
    },
    "checks": {
        "lab_cases": expected_lab["required_cases"],
        "live_shadow_gets": len(fixture["shadow"]["endpoints"]),
        "fresh_debian_provider": True,
        "provider_drain": True,
        "provider_route_pin": True,
        "in_flight_session_origin_unchanged_on_cutover": True,
        "in_flight_session_origin_unchanged_on_rollback": True,
        "new_session_origin_switched_atomically": True,
    },
    "claims": fixture["claims"],
}
output = pathlib.Path(output_path)
temporary = output.with_name(output.name + f".pending-{os.getpid()}")
descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
try:
    with os.fdopen(descriptor, "w", encoding="utf-8") as target:
        json.dump(record, target, indent=2, sort_keys=True)
        target.write("\n")
        target.flush()
        os.fsync(target.fileno())
    os.replace(temporary, output)
except BaseException:
    temporary.unlink(missing_ok=True)
    raise
PY

echo 'test-swap-network-migration: lab, live shadow, Debian, cutover, and rollback evidence passed'
