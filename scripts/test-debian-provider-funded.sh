#!/bin/sh
set -eu

cd "$(dirname "$0")/.."

if test "${IMMORTAL_DEBIAN_PROVIDER_FUNDED_ACCEPTANCE:-}" != 1; then
    echo "test-debian-provider-funded: set IMMORTAL_DEBIAN_PROVIDER_FUNDED_ACCEPTANCE=1" >&2
    exit 1
fi
if test "${IMMORTAL_DISPOSABLE_CONTAINER:-}" != immortal-debian-provider-funded; then
    echo "test-debian-provider-funded: refusing to run outside its disposable container" >&2
    exit 1
fi
. /etc/os-release
if test "${ID}" != debian || test "${VERSION_ID}" != 13; then
    echo "test-debian-provider-funded: requires Debian 13" >&2
    exit 1
fi
if test "$(id -u)" != 0; then
    echo "test-debian-provider-funded: requires root inside the disposable container" >&2
    exit 1
fi
if ! printf '%s' "${IMMORTAL_DEBIAN_PROVIDER_SOURCE_COMMIT:-}" | grep -Eq '^[0-9a-f]{40}$'; then
    echo "test-debian-provider-funded: source commit is invalid" >&2
    exit 1
fi
receipt_directory="${IMMORTAL_DEBIAN_PROVIDER_RECEIPT_DIRECTORY:-}"
case "${receipt_directory}" in
    /tmp/immortal-debian-provider-receipt.*) ;;
    *)
        echo "test-debian-provider-funded: receipt directory is invalid" >&2
        exit 1
        ;;
esac
if test ! -d "${receipt_directory}" || test ! -w "${receipt_directory}"; then
    echo "test-debian-provider-funded: receipt directory is unavailable" >&2
    exit 1
fi
if ! grep -Fqx 'wait_for "Boltz provider compatibility listener inside the smoke network" \' scripts/test-provider-funded.sh \
    || ! grep -Fqx 'wait_for "Boltz provider compatibility published endpoint" \' scripts/test-provider-funded.sh \
    || ! grep -Fqx '  node --experimental-websocket --test adapters/boltz-web-app/provider-process.test.mjs; then' scripts/test-provider-funded.sh; then
    echo "test-debian-provider-funded: funded process gate must retain both readiness probes and Node WebSocket support" >&2
    exit 1
fi
if grep -F -- '--env TMPDIR=' scripts/run-debian-provider-funded.sh >/dev/null; then
    echo "test-debian-provider-funded: receipt mount must not become the private runtime directory" >&2
    exit 1
fi
if ! grep -Fqx 'controller_log="${controller_directory}/container.log"' scripts/run-debian-provider-funded.sh \
    || ! grep -Fqx '    --cidfile "${controller_cidfile}" \' scripts/run-debian-provider-funded.sh \
    || ! grep -Fqx '                if ! head -c 65536 "${controller_log}" >"${controller_excerpt}"; then' scripts/run-debian-provider-funded.sh \
    || ! grep -Fqx "                    && ! sed -n '1,200p' \"\${controller_excerpt}\" >\"\${failure_log}\"; then" scripts/run-debian-provider-funded.sh \
    || ! grep -Fqx '    set +e' scripts/run-debian-provider-funded.sh \
    || ! grep -Fqx 'trap cleanup 0' scripts/run-debian-provider-funded.sh \
    || ! grep -Fqx 'trap handle_signal HUP INT TERM' scripts/run-debian-provider-funded.sh \
    || ! grep -Fqx 'if ! docker start --attach "${outer_container_id}" >>"${controller_log}" 2>&1; then' scripts/run-debian-provider-funded.sh \
    || ! grep -Fqx 'if ! docker rm "${outer_container_id}" >>"${controller_log}" 2>&1; then' scripts/run-debian-provider-funded.sh \
    || ! grep -F -- 'docker ps -a --no-trunc --filter "id=${outer_container_id}"' scripts/run-debian-provider-funded.sh >/dev/null \
    || ! grep -Fqx 'if ! mv "${receipt_result}" "${receipt_pending_path}"; then' scripts/run-debian-provider-funded.sh \
    || ! grep -Fqx 'if ! rmdir "${receipt_directory}"; then' scripts/run-debian-provider-funded.sh \
    || ! grep -Fqx 'if ! rm -f "${controller_cidfile}"; then' scripts/run-debian-provider-funded.sh \
    || ! grep -Fqx 'if ! rm -f "${controller_excerpt}"; then' scripts/run-debian-provider-funded.sh \
    || ! grep -Fqx 'if ! rm -f "${controller_log}"; then' scripts/run-debian-provider-funded.sh \
    || ! grep -Fqx 'if ! rmdir "${controller_directory}"; then' scripts/run-debian-provider-funded.sh \
    || ! grep -Fqx "trap '' HUP INT TERM" scripts/run-debian-provider-funded.sh \
    || ! tail -n 1 scripts/run-debian-provider-funded.sh | grep -Fqx 'mv "${receipt_pending_path}" "${receipt_path}"'; then
    echo "test-debian-provider-funded: failure retention must be bounded and signal-cleaned" >&2
    exit 1
fi

started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
scripts/test-provider-funded.sh
if docker ps --all --format '{{.Names}}' | grep -q '^immortal-provider-funded-'; then
    echo "test-debian-provider-funded: funded container cleanup is incomplete" >&2
    exit 1
fi
finished_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

IMMORTAL_DEBIAN_PROVIDER_STARTED_AT="${started_at}" \
IMMORTAL_DEBIAN_PROVIDER_FINISHED_AT="${finished_at}" \
IMMORTAL_DEBIAN_PROVIDER_ARCHITECTURE="$(uname -m)" \
IMMORTAL_DEBIAN_PROVIDER_CARGO="$(cargo --version)" \
IMMORTAL_DEBIAN_PROVIDER_DOCKER_CLIENT="$(docker version --format '{{.Client.Version}}')" \
IMMORTAL_DEBIAN_PROVIDER_DOCKER_SERVER="$(docker version --format '{{.Server.Version}}')" \
IMMORTAL_DEBIAN_PROVIDER_GO="$(go version)" \
IMMORTAL_DEBIAN_PROVIDER_NODE="$(node --version)" \
IMMORTAL_DEBIAN_PROVIDER_RUSTC="$(rustc --version)" \
python3 - "${receipt_directory}/result.json" <<'PY'
import hashlib
import json
import os
import pathlib
import sys

output = pathlib.Path(sys.argv[1])
if output.name != "result.json" or output.parent.name.startswith("immortal-debian-provider-receipt.") is False:
    raise SystemExit("receipt output path is invalid")

root = pathlib.Path.cwd()
paths = (
    "scripts/test-provider-funded.sh",
    "tests/fixtures/provider/funded-smoke-v1.json",
    "tests/fixtures/lab/funded-checkpoints-v1.json",
    "tests/fixtures/lab/funded-matrix-v1.json",
)
digests = {}
for relative in paths:
    source = root / relative
    digests[relative] = hashlib.sha256(source.read_bytes()).hexdigest()

record = {
    "schema": "openagents.immortal.debian-provider-funded-run.v1",
    "source_commit": os.environ["IMMORTAL_DEBIAN_PROVIDER_SOURCE_COMMIT"],
    "command": "scripts/run-debian-provider-funded.sh --receipt <record>",
    "started_at": os.environ["IMMORTAL_DEBIAN_PROVIDER_STARTED_AT"],
    "finished_at": os.environ["IMMORTAL_DEBIAN_PROVIDER_FINISHED_AT"],
    "result": "passed",
    "scope": "fresh-debian-13-disposable-container",
    "clean_debian_environment": True,
    "platform": {
        "operating_system": "Debian 13",
        "architecture": os.environ["IMMORTAL_DEBIAN_PROVIDER_ARCHITECTURE"],
        "cargo": os.environ["IMMORTAL_DEBIAN_PROVIDER_CARGO"],
        "docker_client": os.environ["IMMORTAL_DEBIAN_PROVIDER_DOCKER_CLIENT"],
        "docker_server": os.environ["IMMORTAL_DEBIAN_PROVIDER_DOCKER_SERVER"],
        "go": os.environ["IMMORTAL_DEBIAN_PROVIDER_GO"],
        "node": os.environ["IMMORTAL_DEBIAN_PROVIDER_NODE"],
        "rustc": os.environ["IMMORTAL_DEBIAN_PROVIDER_RUSTC"],
    },
    "funded_smoke": {
        "journeys": ["submarine", "reverse", "noncooperative_refund"],
        "forced_restart": "submarine:funding_authorized",
        "passed": True,
    },
    "manifests": digests,
    "cleanup": {
        "matching_provider_containers_after_run": 0,
        "private_runtime_artifacts_retained": False,
    },
    "environment_boundary": (
        "The Debian process and Docker daemon are fresh and disposable. "
        "The privileged outer container starts a new dockerd with an empty "
        "data root and removes it after the gate."
    ),
    "limitations": [
        "This does not establish live deployment or a public replacement claim.",
        "This runs the single-provider funded smoke; the separate #32 topology gate covers two providers.",
    ],
}
serialized = json.dumps(record, indent=2, sort_keys=True) + "\n"
if any(term in serialized.lower() for term in ("wallet_seed", "spend_key", "claim_key", "refund_key", "preimage", "macaroon", "rpc_password")):
    raise SystemExit("receipt contains a custody-bearing field name")
output.write_text(serialized, encoding="utf-8")
PY

echo "test-debian-provider-funded: fresh Debian 13 funded smoke passed"
