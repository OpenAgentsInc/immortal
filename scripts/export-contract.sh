#!/bin/sh
set -eu

export LC_ALL=C

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
mode=${1:-write}
if [ "$mode" != "write" ] && [ "$mode" != "--check" ]; then
    echo "usage: scripts/export-contract.sh [--check]" >&2
    exit 2
fi

temporary=$(mktemp -d "${TMPDIR:-/tmp}/immortal-contract.XXXXXX")
trap 'rm -rf "$temporary"' EXIT HUP INT TERM

cd "$root"
cargo build --locked --bin immortal >/dev/null

write_manifest() {
    destination=$1
    contract_file=$2
    python3 - "$root" "$destination" "$contract_file" <<'PY'
import hashlib
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1]).resolve()
destination = pathlib.Path(sys.argv[2])
contract = json.loads(pathlib.Path(sys.argv[3]).read_text(encoding="utf-8"))
fixture_root = root / "tests" / "fixtures"
entries = []
for path in sorted(fixture_root.rglob("*.json"), key=lambda item: item.relative_to(root).as_posix()):
    if path.is_symlink() or not path.is_file():
        raise SystemExit(f"fixture must be a regular non-symlink file: {path}")
    resolved = path.resolve()
    try:
        relative = resolved.relative_to(root).as_posix()
    except ValueError as error:
        raise SystemExit(f"fixture escapes repository root: {path}") from error
    data = path.read_bytes()
    if (
        relative.endswith("nipmkt/client-only-cases.json")
        or relative.endswith("nipmkt/client-transport.json")
        or relative.endswith("nip44/market-client.json")
    ):
        scope = "client"
    elif (
        relative.endswith("nipmkt/common-grammar.json")
        or relative.endswith("nipmkt/relay-closing.json")
        or relative.endswith("nipmkt/swp-profile-v1.json")
        or relative.endswith("nipmkt/swp-verification.json")
    ):
        scope = "relay_and_client"
    else:
        scope = "relay"
    entries.append({
        "path": relative,
        "sha256": hashlib.sha256(data).hexdigest(),
        "bytes": len(data),
        "scope": scope,
    })

manifest = {
    "schema": "openagents.immortal.fixture-manifest.v1",
    "manifest_version": 1,
    "algorithm": "sha256",
    "contract_identity": contract["identity"],
    "fixtures": entries,
}
destination.write_text(
    json.dumps(manifest, ensure_ascii=False, indent=2, separators=(",", ": ")) + "\n",
    encoding="utf-8",
)
PY
}

"$root/target/debug/immortal" contract >"$temporary/contract-one.json"
"$root/target/debug/immortal" contract >"$temporary/contract-two.json"
cmp "$temporary/contract-one.json" "$temporary/contract-two.json"

write_manifest "$temporary/fixtures-one.json" "$temporary/contract-one.json"
write_manifest "$temporary/fixtures-two.json" "$temporary/contract-two.json"
cmp "$temporary/fixtures-one.json" "$temporary/fixtures-two.json"

if [ "$mode" = "--check" ]; then
    cmp "$temporary/contract-one.json" "$root/contract/immortal-contract.json"
    cmp "$temporary/fixtures-one.json" "$root/contract/immortal-fixtures.json"
    exit 0
fi

mkdir -p "$root/contract"
mv "$temporary/contract-one.json" "$root/contract/immortal-contract.json"
mv "$temporary/fixtures-one.json" "$root/contract/immortal-fixtures.json"
