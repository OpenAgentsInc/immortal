#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

fixture="tests/fixtures/lab/no-spend-demo-v1.json"
relay_port="${IMMORTAL_DEMO_TEST_RELAY_PORT:-18142}"
state_dir="$(mktemp -d "${TMPDIR:-/tmp}/immortal-no-spend-demo-test.XXXXXX")"
launcher_log="$(mktemp "${TMPDIR:-/tmp}/immortal-no-spend-demo-launcher.XXXXXX")"
smoke_log="$(mktemp "${TMPDIR:-/tmp}/immortal-no-spend-demo-smoke.XXXXXX")"
record_path="${IMMORTAL_DEMO_TEST_RECORD:-target/lab-evidence/no-spend-demo-v1.json}"
launcher_pid=""

cleanup() {
  local exit_status=$?
  trap - EXIT INT TERM
  if test -e "${state_dir}/owner.json"; then
    IMMORTAL_DEMO_STATE_DIR="${state_dir}" scripts/dev-no-spend-demo.sh down \
      >/dev/null 2>&1 || exit_status=1
  fi
  if test -n "${launcher_pid}" && kill -0 "${launcher_pid}" 2>/dev/null; then
    kill -TERM "${launcher_pid}" 2>/dev/null || true
  fi
  if test -n "${launcher_pid}"; then
    wait "${launcher_pid}" 2>/dev/null || true
  fi
  rm -f -- "${launcher_log}" "${smoke_log}"
  if test -e "${state_dir}"; then
    echo "test-dev-no-spend-demo: launcher did not remove its owned state" >&2
    exit_status=1
  fi
  exit "${exit_status}"
}
trap cleanup EXIT INT TERM

# The launcher requires ownership of a nonexistent directory.
rmdir "${state_dir}"
IMMORTAL_DEMO_STATE_DIR="${state_dir}" \
  IMMORTAL_DEMO_RELAY_PORT="${relay_port}" \
  scripts/dev-no-spend-demo.sh >"${launcher_log}" 2>&1 &
launcher_pid=$!

for _ in $(seq 1 900); do
  if test -f "${state_dir}/manifest.json" \
    && python3 - "${state_dir}/manifest.json" <<'PY'
import json
import sys
x = json.load(open(sys.argv[1], encoding="utf-8"))
raise SystemExit(0 if x.get("relay", {}).get("health", {}).get("state") == "ready" and all(
    p.get("health", {}).get("state") == "ready" for p in x.get("providers", [])
) and len(x.get("providers", [])) == 2 else 1)
PY
  then
    break
  fi
  if ! kill -0 "${launcher_pid}" 2>/dev/null; then
    wait "${launcher_pid}" || true
    sed -n '1,260p' "${launcher_log}" >&2
    echo "test-dev-no-spend-demo: launcher exited before readiness" >&2
    exit 1
  fi
  sleep 0.1
done

python3 - "${fixture}" "${state_dir}/manifest.json" "${relay_port}" \
  "tests/fixtures/nipmkt/swp-full-sessions-v1.json" <<'PY'
import json
import os
import pathlib
import re
import stat
import sys

fixture = json.load(open(sys.argv[1], encoding="utf-8"))
path = pathlib.Path(sys.argv[2])
raw = path.read_bytes()
manifest = json.loads(raw)
if manifest.get("schema") != fixture["manifest_schema"]:
    raise SystemExit("demo manifest has another schema")
if len(raw) > fixture["manifest"]["maximum_bytes"]:
    raise SystemExit("demo manifest exceeds its bound")
if stat.S_IMODE(path.stat().st_mode) != 0o644:
    raise SystemExit("demo manifest is not public-readable mode 0644")
if manifest.get("relay", {}).get("websocket_url") != f"ws://127.0.0.1:{sys.argv[3]}":
    raise SystemExit("demo manifest relay URL is not the owned loopback target")
providers = manifest.get("providers")
if not isinstance(providers, list) or len(providers) != 2:
    raise SystemExit("demo manifest does not contain exactly two providers")
if {p.get("role") for p in providers} != {"provider-a", "provider-b"}:
    raise SystemExit("demo provider roles are invalid")
if len({p.get("pubkey") for p in providers}) != 2 or not all(
    re.fullmatch(r"[0-9a-f]{64}", p.get("pubkey", "")) for p in providers
):
    raise SystemExit("demo provider public keys are not distinct lower hex")
expected = {row["role"]: row for row in fixture["quote_policies"]}
for provider in providers:
    policy = provider.get("policy", {})
    row = expected[provider["role"]]
    for member in ["variant", "quote_lifetime_seconds", "completion_discount_seconds", "quote_class", "reservation_class"]:
        if policy.get(member) != row[member]:
            raise SystemExit(f"{provider['role']} policy {member} differs from the fixture")

sessions = json.load(open(sys.argv[4], encoding="utf-8"))
expected_templates = []
for swap_type in ["submarine", "reverse", "chain"]:
    records = sessions["flows"][swap_type]["snapshot"]["signed_records"]
    quotes = [record for record in records if record.get("kind") == 39605]
    if len(quotes) != 1:
        raise SystemExit(f"full-session fixture has another {swap_type} Quote count")
    terms = json.loads(quotes[0]["content"])["mkt_swp"]["terms"]
    invoice_sha256 = None
    if swap_type == "submarine":
        lightning = [
            verifier for verifier in terms["verifier_inputs"]
            if verifier.get("leg_id") == "lightning"
        ]
        if len(lightning) != 1:
            raise SystemExit("full-session fixture has another submarine Lightning verifier count")
        invoice_sha256 = lightning[0]["invoice_sha256"]
    requester_public_keys = []
    for verifier in terms["verifier_inputs"]:
        for leaf in verifier.get("taproot_tree", []):
            if leaf.get("participant_role") == "requester":
                requester_public_keys.append({
                    "leg_id": verifier["leg_id"],
                    "path": leaf["path"],
                    "public_key": leaf["signing_pubkey"],
                })
    requester_public_keys.sort(
        key=lambda item: json.dumps(item, sort_keys=True, separators=(",", ":"))
    )
    expected_templates.append({
        "swap_type": swap_type,
        "input_asset_id": terms["asset_pair"][0],
        "output_asset_id": terms["asset_pair"][1],
        "input_amount": terms["input_amount"],
        "payment_hash": terms["payment_hash"],
        "invoice_sha256": invoice_sha256,
        "requester_public_keys": requester_public_keys,
    })
request_contract = manifest.get("request_contract")
expected_contract = {
    "schema": fixture["request_contract"]["schema"],
    "templates": expected_templates,
}
if request_contract != expected_contract:
    raise SystemExit("demo request contract differs from the pinned Quote fixtures")
lower = raw.lower()
for forbidden in [b"identity_secret", b"provider-a.secret", b"provider-b.secret", b"private_key", b"preimage", b"macaroon"]:
    if forbidden in lower:
        raise SystemExit(f"public manifest contains {forbidden.decode()}")
PY

IMMORTAL_DEMO_MANIFEST="${state_dir}/manifest.json" \
  IMMORTAL_DEMO_CONTROL_DIR="${state_dir}/control" \
  cargo test --locked -p immortal-provider --test no_spend_live \
    two_provider_demo_manifest_quotes_restart_and_close_are_live \
    -- --ignored --exact --nocapture | tee "${smoke_log}"

python3 - "${fixture}" "${smoke_log}" "${record_path}" <<'PY'
import json
import os
import pathlib
import sys

fixture = json.load(open(sys.argv[1], encoding="utf-8"))
lines = pathlib.Path(sys.argv[2]).read_text(encoding="utf-8").splitlines()
records = []
for line in lines:
    try:
        value = json.loads(line)
    except json.JSONDecodeError:
        continue
    if value.get("schema") == fixture["smoke_schema"]:
        records.append(value)
if len(records) != 1:
    raise SystemExit("demo smoke did not emit exactly one machine receipt")
record = records[0]
providers = record.get("providers")
if not isinstance(providers, list) or len(providers) != 2:
    raise SystemExit("demo smoke receipt omits provider results")
if not isinstance(record.get("requester_pubkey"), str) or len(record["requester_pubkey"]) != 64:
    raise SystemExit("demo smoke receipt omits its single requester identity")
if providers[0].get("restart_count", 0) < 1 or providers[1].get("restart_count") != 0:
    raise SystemExit("demo smoke did not isolate the in-flight provider restart")
if record.get("external_spend_effects") != fixture["lifecycle"]["external_spend_effects"]:
    raise SystemExit("demo smoke made an external spend claim")
encoded = (json.dumps(record, indent=2, sort_keys=True) + "\n").encode()
path = pathlib.Path(sys.argv[3])
path.parent.mkdir(parents=True, exist_ok=True)
os.chmod(path.parent, 0o700)
temporary = path.with_suffix(".json.tmp")
descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(descriptor, "wb") as output:
    output.write(encoded)
    output.flush()
    os.fsync(output.fileno())
os.replace(temporary, path)
os.chmod(path, 0o600)
PY

IMMORTAL_DEMO_STATE_DIR="${state_dir}" scripts/dev-no-spend-demo.sh down
wait "${launcher_pid}"
launcher_pid=""
test ! -e "${state_dir}"
echo "test-dev-no-spend-demo: two signed providers, distinct Quotes, isolated restart, and zero-spend Close passed"
