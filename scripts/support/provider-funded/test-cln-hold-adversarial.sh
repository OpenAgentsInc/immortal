#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/../../.." && pwd)
fixture="$root/tests/fixtures/provider/cln-adversarial-hold-v1.json"

python3 - "$root" "$fixture" <<'PY'
import hashlib
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
fixture = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))
if fixture.get("schema") != "openagents.immortal.cln-adversarial-hold.v1":
    raise SystemExit("CLN adversarial hold fixture has another schema")
if fixture.get("profile") != "regtest_adversarial" or fixture.get("network") != "regtest":
    raise SystemExit("CLN adversarial hold fixture is not structurally regtest-only")

source = fixture["source"]
production = fixture["production"]
for path_member, digest_member in (
    ("patch", "patch_sha256"),
    ("dockerfile", "dockerfile_sha256"),
):
    path = root / source[path_member]
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if digest != source[digest_member]:
        raise SystemExit(f"{path_member} digest changed")
stock = root / production["dockerfile"]
if hashlib.sha256(stock.read_bytes()).hexdigest() != production["dockerfile_sha256"]:
    raise SystemExit("stock CLN hold Dockerfile changed")
dockerignore = (root / ".dockerignore").read_text(encoding="utf-8").splitlines()
if source["docker_context_include"] not in dockerignore:
    raise SystemExit("adversarial hold patch is absent from the Docker build context")

rpc = fixture["rpc"]
request = rpc["request"]
if rpc["method"] != "holdinvoiceimmortalregtest" or rpc["stock_method"] != "holdinvoice":
    raise SystemExit("CLN hold RPC method contract changed")
if request["expiry_seconds"] != 30 or request["min_final_cltv_expiry_delta"] != 80:
    raise SystemExit("CLN adversarial hold policy changed")

patch = (root / source["patch"]).read_text(encoding="utf-8")
for required in (
    'plugin.configuration().network != "regtest"',
    'params.expiry_seconds != 30',
    'params.min_final_cltv_expiry_delta != 80',
    'i32::try_from(params.min_final_cltv_expiry_delta)',
    '"holdinvoiceimmortalregtest"',
    '.expiry(params.expiry_seconds)',
    '.min_final_cltv_expiry_delta(params.min_final_cltv_expiry_delta)',
    'min_cltv: Some(minimum_final_cltv_expiry_delta)',
):
    if required not in patch:
        raise SystemExit(f"reviewed hold patch lost {required}")
if "holdinvoiceimmortalregtest" in stock.read_text(encoding="utf-8"):
    raise SystemExit("stock CLN hold image acquired the adversarial method")

dockerfile = (root / source["dockerfile"]).read_text(encoding="utf-8")
for required in (
    source["archive_sha256"],
    source["archive"],
    "patch --batch --fuzz=0 --strip=1",
    "cargo build --locked --release --no-default-features",
    "elementsproject/lightningd:v26.06.6@sha256:094be3630f865c795649d6063a8796afa0f78e82a0c311bb34f2b0bd570c819a",
):
    if required not in dockerfile:
        raise SystemExit(f"adversarial CLN Dockerfile lost {required}")
PY

temporary=$(mktemp -d "${TMPDIR:-/tmp}/immortal-hold-adversarial.XXXXXX")
case "$(basename "$temporary")" in
    immortal-hold-adversarial.*) ;;
    *) echo "refusing unexpected temporary directory: $temporary" >&2; exit 1 ;;
esac
touch "$temporary/.immortal-owned"
cleanup() {
    case "$temporary" in
        "${TMPDIR:-/tmp}"/immortal-hold-adversarial.*)
            if [ -f "$temporary/.immortal-owned" ]; then
                rm -rf -- "$temporary"
            fi
            ;;
    esac
}
trap cleanup EXIT HUP INT TERM
archive="$temporary/hold-v0.3.3.tar.gz"
curl --fail --location --silent --show-error \
    https://github.com/BoltzExchange/hold/archive/refs/tags/v0.3.3.tar.gz \
    --output "$archive"
python3 - "$archive" <<'PY'
import hashlib
import pathlib
import sys

expected = "2a5631e6766b06d9af18ca4ca352d410bf78f79ccb7eb17f5d6030f0aca5177e"
observed = hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest()
if observed != expected:
    raise SystemExit("hold v0.3.3 archive digest changed")
PY
tar --extract --gzip --file "$archive" --directory "$temporary"
patch --dry-run --batch --fuzz=0 --strip=1 \
    --directory="$temporary/hold-0.3.3" \
    --input="$root/scripts/support/provider-funded/hold-v0.3.3-immortal-regtest.patch"

echo "test-cln-hold-adversarial: source, patch, image, and stock boundary passed"
