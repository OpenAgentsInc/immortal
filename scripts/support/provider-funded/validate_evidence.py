#!/usr/bin/env python3

import argparse
import json
import pathlib
import re
import stat
import sys


HEX_32 = re.compile(r"^[0-9a-f]{64}$")
MAX_MANIFEST_BYTES = 256 * 1024
MAX_PRIVATE_JSON_BYTES = 4 * 1024 * 1024
EVIDENCE_SCHEMA = "openagents.immortal.provider-funded-smoke-evidence.v1"
DURABLE_EVIDENCE_SCHEMA = (
    "openagents.immortal.provider-funded-smoke-durable-evidence.v1"
)
EXPECTED_FORBIDDEN_FIELDS = {
    "claim_key",
    "macaroon",
    "password",
    "preimage",
    "private_key",
    "raw_transaction",
    "refund_key",
    "seed",
    "secret",
}
EXPECTED_CONFIRMATION_POLICY = {
    "minimum_confirmations": 1,
    "reorg_safety_blocks": 2,
    "terminal_confirmations": 3,
}
EXPECTED_JOURNEYS = {
    "submarine": {
        "chain_terminal_field": "claim_txid",
        "result": "claimed",
        "lightning_owner": "peer",
        "lightning_kind": "ordinary",
        "lightning_terminal_state": "paid",
    },
    "reverse": {
        "chain_terminal_field": "claim_txid",
        "result": "claimed",
        "lightning_owner": "provider",
        "lightning_kind": "hold",
        "lightning_terminal_state": "paid",
    },
    "reverse_refund": {
        "chain_terminal_field": "refund_txid",
        "result": "refunded",
        "lightning_owner": "provider",
        "lightning_kind": "hold",
        "lightning_terminal_state": "cancelled",
        "lightning_payment_succeeded": False,
    },
}
EXPECTED_DURABLE_STATE = {
    "session_dispositions": {
        "submarine": "provider_close_completed",
        "reverse": "provider_close_completed",
        "reverse_refund": "provider_close_refunded",
    },
    "reservation": {
        "count_per_journey": 1,
        "state": "released",
        "release_cause": "terminal_close",
    },
    "effect": {
        "minimum_count_per_journey": 1,
        "state": "applied",
    },
    "watches": {
        "reverse": {
            "job_kind": "refund_broadcast",
            "state": "completed",
            "disposition": "claim_settled",
            "minimum_confirmations": 0,
        },
        "reverse_refund": {
            "job_kind": "refund_broadcast",
            "state": "confirmed",
            "disposition": "confirmation",
            "minimum_confirmations": 3,
        },
    },
}


class EvidenceError(RuntimeError):
    pass


def unique_object(pairs):
    value = {}
    for name, child in pairs:
        if name in value:
            raise EvidenceError("JSON object repeats a member")
        value[name] = child
    return value


def load_private_json(path):
    try:
        file_stat = path.lstat()
    except OSError as error:
        raise EvidenceError(f"{path.name} is not readable") from error
    if not stat.S_ISREG(file_stat.st_mode):
        raise EvidenceError(f"{path.name} is not a regular file")
    if file_stat.st_mode & 0o077:
        raise EvidenceError(f"{path.name} is readable outside its owner")
    if file_stat.st_size > MAX_PRIVATE_JSON_BYTES:
        raise EvidenceError(f"{path.name} exceeds the funded-smoke evidence bound")
    try:
        with path.open(encoding="utf-8") as source:
            return json.load(source, object_pairs_hook=unique_object)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise EvidenceError(f"{path.name} is not valid JSON") from error


def load_manifest(path):
    try:
        if path.stat().st_size > MAX_MANIFEST_BYTES:
            raise EvidenceError("the committed funded-smoke manifest exceeds its bound")
        with path.open(encoding="utf-8") as source:
            return json.load(source, object_pairs_hook=unique_object)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise EvidenceError("the committed funded-smoke manifest is invalid") from error


def reject_forbidden_fields(value, forbidden_fields):
    if isinstance(value, dict):
        for name, child in value.items():
            if str(name).lower() in forbidden_fields:
                raise EvidenceError("public evidence contains a custody field")
            reject_forbidden_fields(child, forbidden_fields)
    elif isinstance(value, list):
        for child in value:
            reject_forbidden_fields(child, forbidden_fields)


def require_exact_keys(value, expected, context):
    if not isinstance(value, dict) or set(value) != set(expected):
        raise EvidenceError(f"{context} fields do not match the manifest")


def require_hex_32(value, context):
    if not isinstance(value, str) or HEX_32.fullmatch(value) is None:
        raise EvidenceError(f"{context} is not lowercase 32-byte hex")


def require_count(value, context):
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise EvidenceError(f"{context} is not a nonnegative integer")
    return value


def validate_terminal_counts(value, context, expected_total=None, minimum_total=None):
    require_exact_keys(value, {"total", "terminal", "pending", "unresolved"}, context)
    total = require_count(value["total"], f"{context} total")
    terminal = require_count(value["terminal"], f"{context} terminal count")
    pending = require_count(value["pending"], f"{context} pending count")
    unresolved = require_count(value["unresolved"], f"{context} unresolved count")
    if expected_total is not None and total != expected_total:
        raise EvidenceError(f"{context} has the wrong row count")
    if minimum_total is not None and total < minimum_total:
        raise EvidenceError(f"{context} has no durable terminal row")
    if terminal != total or pending != 0 or unresolved != 0:
        raise EvidenceError(f"{context} is not durably terminal")


def validate_durable_evidence(durable, durable_manifest, confirmation_policy):
    require_exact_keys(
        durable,
        {
            "schema",
            "terminal_confirmations",
            "session_summary",
            "journeys",
            "watches",
        },
        "durable evidence",
    )
    if durable["schema"] != DURABLE_EVIDENCE_SCHEMA:
        raise EvidenceError("the durable evidence has the wrong schema")
    if durable["terminal_confirmations"] != confirmation_policy["terminal_confirmations"]:
        raise EvidenceError("the durable evidence used another confirmation policy")

    session_summary = durable["session_summary"]
    require_exact_keys(
        session_summary,
        {"selected", "distinct", "terminal", "pending", "unresolved"},
        "durable session summary",
    )
    for field_name in ("selected", "distinct", "terminal", "pending", "unresolved"):
        require_count(
            session_summary[field_name], f"durable session summary {field_name}"
        )
    if session_summary != {
        "selected": 3,
        "distinct": 3,
        "terminal": 3,
        "pending": 0,
        "unresolved": 0,
    }:
        raise EvidenceError("the three funded-smoke sessions are not durably terminal")

    dispositions = durable_manifest["session_dispositions"]
    journeys = durable["journeys"]
    require_exact_keys(journeys, dispositions, "durable journey evidence")
    reservation_manifest = durable_manifest["reservation"]
    effect_manifest = durable_manifest["effect"]
    for journey_name, disposition in dispositions.items():
        journey = journeys[journey_name]
        require_exact_keys(
            journey,
            {
                "matched_session_count",
                "session_disposition",
                "reservations",
                "effects",
            },
            f"{journey_name} durable evidence",
        )
        require_count(
            journey["matched_session_count"],
            f"{journey_name} matched session count",
        )
        if journey["matched_session_count"] != 1:
            raise EvidenceError(f"{journey_name} did not resolve to one provider session")
        if journey["session_disposition"] != disposition:
            raise EvidenceError(f"{journey_name} has the wrong durable disposition")
        validate_terminal_counts(
            journey["reservations"],
            f"{journey_name} reservation evidence",
            expected_total=reservation_manifest["count_per_journey"],
        )
        validate_terminal_counts(
            journey["effects"],
            f"{journey_name} effect evidence",
            minimum_total=effect_manifest["minimum_count_per_journey"],
        )

    watch_manifest = durable_manifest["watches"]
    watches = durable["watches"]
    require_exact_keys(watches, watch_manifest, "durable watch evidence")
    watch_fields = {
        "job_kind",
        "total",
        "completed",
        "confirmed",
        "pending",
        "unresolved",
        "disposition",
        "confirmations",
    }
    for journey_name, expected in watch_manifest.items():
        watch = watches[journey_name]
        require_exact_keys(watch, watch_fields, f"{journey_name} watch evidence")
        for field_name in (
            "total",
            "completed",
            "confirmed",
            "pending",
            "unresolved",
            "confirmations",
        ):
            require_count(watch[field_name], f"{journey_name} watch {field_name}")
        if watch["job_kind"] != expected["job_kind"] or watch["total"] != 1:
            raise EvidenceError(f"{journey_name} refund watch is not unique")
        expected_completed = 1 if expected["state"] == "completed" else 0
        expected_confirmed = 1 if expected["state"] == "confirmed" else 0
        if (
            watch["completed"] != expected_completed
            or watch["confirmed"] != expected_confirmed
            or watch["pending"] != 0
            or watch["unresolved"] != 0
        ):
            raise EvidenceError(f"{journey_name} refund watch is not durably terminal")
        if watch["disposition"] != expected["disposition"]:
            raise EvidenceError(f"{journey_name} refund watch has the wrong disposition")
        if watch["confirmations"] < expected["minimum_confirmations"]:
            raise EvidenceError(
                f"{journey_name} refund watch is below the confirmation policy"
            )


def validate_chain_transaction(
    transaction, expected_txid, required_confirmations, context
):
    if not isinstance(transaction, dict):
        raise EvidenceError(f"{context} chain response is not an object")
    if transaction.get("txid") != expected_txid:
        raise EvidenceError(f"{context} chain response has the wrong transaction ID")
    confirmations = transaction.get("confirmations")
    if (
        not isinstance(confirmations, int)
        or isinstance(confirmations, bool)
        or confirmations < required_confirmations
    ):
        raise EvidenceError(
            f"{context} chain transaction is below the confirmation policy"
        )
    if not isinstance(transaction.get("blockhash"), str):
        raise EvidenceError(f"{context} chain transaction has no block hash")


def validate_spend(
    chain_directory, journey_name, journey, terminal_field, confirmation_policy
):
    lockup = load_private_json(chain_directory / f"{journey_name}-lockup.json")
    terminal = load_private_json(chain_directory / f"{journey_name}-terminal.json")
    validate_chain_transaction(
        lockup,
        journey["lockup_txid"],
        confirmation_policy["minimum_confirmations"],
        f"{journey_name} lockup",
    )
    validate_chain_transaction(
        terminal,
        journey[terminal_field],
        confirmation_policy["terminal_confirmations"],
        f"{journey_name} terminal spend",
    )
    inputs = terminal.get("vin")
    if not isinstance(inputs, list) or not any(
        isinstance(transaction_input, dict)
        and transaction_input.get("txid") == journey["lockup_txid"]
        and transaction_input.get("vout") == journey["lockup_vout"]
        for transaction_input in inputs
    ):
        raise EvidenceError(
            f"{journey_name} terminal transaction does not spend its lockup outpoint"
        )


def validate_lightning(lightning_directory, journey_name, journey, journey_manifest):
    response = load_private_json(lightning_directory / f"{journey_name}.json")
    collection_name = (
        "invoices" if journey_manifest["lightning_kind"] == "ordinary" else "holdinvoices"
    )
    invoices = response.get(collection_name) if isinstance(response, dict) else None
    if not isinstance(invoices, list):
        raise EvidenceError(f"{journey_name} Lightning response has no invoice collection")
    matching = [
        invoice
        for invoice in invoices
        if isinstance(invoice, dict) and invoice.get("payment_hash") == journey["payment_hash"]
    ]
    if len(matching) != 1:
        raise EvidenceError(f"{journey_name} Lightning payment hash is not unique")
    if matching[0].get("state", matching[0].get("status")) != journey_manifest[
        "lightning_terminal_state"
    ]:
        raise EvidenceError(f"{journey_name} Lightning invoice has the wrong terminal state")


def validate(arguments):
    manifest = load_manifest(arguments.manifest)
    evidence = load_private_json(arguments.evidence)
    durable = load_private_json(arguments.durable_evidence)
    require_exact_keys(
        manifest,
        {
            "schema",
            "evidence_schema",
            "durable_evidence_schema",
            "confirmation_policy",
            "forbidden_evidence_fields",
            "durable_state",
            "journeys",
        },
        "funded-smoke manifest",
    )
    if manifest.get("schema") != "openagents.immortal.provider-funded-smoke-manifest.v1":
        raise EvidenceError("the funded-smoke manifest has the wrong schema")
    if manifest.get("evidence_schema") != EVIDENCE_SCHEMA:
        raise EvidenceError("the funded-smoke manifest has the wrong evidence schema")
    if manifest.get("durable_evidence_schema") != DURABLE_EVIDENCE_SCHEMA:
        raise EvidenceError("the funded-smoke manifest has the wrong durable evidence schema")
    confirmation_policy = manifest.get("confirmation_policy")
    if confirmation_policy != EXPECTED_CONFIRMATION_POLICY:
        raise EvidenceError("the funded-smoke manifest has the wrong confirmation policy")
    forbidden_values = manifest.get("forbidden_evidence_fields")
    if (
        not isinstance(forbidden_values, list)
        or len(forbidden_values) != len(EXPECTED_FORBIDDEN_FIELDS)
        or set(forbidden_values) != EXPECTED_FORBIDDEN_FIELDS
    ):
        raise EvidenceError("the funded-smoke manifest has the wrong custody-field denylist")
    if manifest.get("journeys") != EXPECTED_JOURNEYS:
        raise EvidenceError("the funded-smoke manifest does not define the v1 journeys")
    if manifest.get("durable_state") != EXPECTED_DURABLE_STATE:
        raise EvidenceError("the funded-smoke manifest has the wrong durable-state gate")
    if (
        manifest["durable_state"]["watches"]["reverse_refund"][
            "minimum_confirmations"
        ]
        != confirmation_policy["terminal_confirmations"]
    ):
        raise EvidenceError("the durable refund watch policy is inconsistent")
    forbidden_fields = set(forbidden_values)
    reject_forbidden_fields(evidence, forbidden_fields)
    reject_forbidden_fields(durable, forbidden_fields)
    require_exact_keys(evidence, {"schema", "daemon", "journeys"}, "evidence")
    if evidence["schema"] != manifest.get("evidence_schema"):
        raise EvidenceError("the funded-smoke evidence has the wrong schema")
    require_exact_keys(
        evidence["daemon"],
        {"health_ready", "provider_pubkey"},
        "daemon evidence",
    )
    if evidence["daemon"]["health_ready"] is not True:
        raise EvidenceError("the provider daemon never became ready")
    require_hex_32(evidence["daemon"]["provider_pubkey"], "provider pubkey")

    journeys = evidence["journeys"]
    journey_manifests = manifest.get("journeys")
    require_exact_keys(journeys, journey_manifests, "journey evidence")
    seen_transaction_ids = set()
    seen_order_ids = set()
    seen_payment_hashes = set()
    for journey_name, journey_manifest in journey_manifests.items():
        terminal_field = journey_manifest["chain_terminal_field"]
        expected_fields = {
            "order_id",
            "lockup_txid",
            "lockup_vout",
            terminal_field,
            "payment_hash",
            "result",
        }
        if "lightning_payment_succeeded" in journey_manifest:
            expected_fields.add("lightning_payment_succeeded")
        journey = journeys[journey_name]
        require_exact_keys(journey, expected_fields, f"{journey_name} evidence")
        for field_name in ("order_id", "lockup_txid", terminal_field, "payment_hash"):
            require_hex_32(journey[field_name], f"{journey_name} {field_name}")
        if (
            not isinstance(journey["lockup_vout"], int)
            or isinstance(journey["lockup_vout"], bool)
            or not 0 <= journey["lockup_vout"] <= 0xFFFFFFFF
        ):
            raise EvidenceError(f"{journey_name} lockup output index is invalid")
        if journey["result"] != journey_manifest["result"]:
            raise EvidenceError(f"{journey_name} has the wrong terminal result")
        if (
            "lightning_payment_succeeded" in journey_manifest
            and journey["lightning_payment_succeeded"] is not False
        ):
            raise EvidenceError("the refund journey released its preimage")
        if journey["order_id"] in seen_order_ids:
            raise EvidenceError("journeys reused an order ID")
        if journey["payment_hash"] in seen_payment_hashes:
            raise EvidenceError("journeys reused a payment hash")
        transaction_ids = {journey["lockup_txid"], journey[terminal_field]}
        if seen_transaction_ids.intersection(transaction_ids):
            raise EvidenceError("journeys reused a chain transaction")
        seen_order_ids.add(journey["order_id"])
        seen_payment_hashes.add(journey["payment_hash"])
        seen_transaction_ids.update(transaction_ids)
        validate_spend(
            arguments.chain_directory,
            journey_name,
            journey,
            terminal_field,
            confirmation_policy,
        )
        validate_lightning(
            arguments.lightning_directory, journey_name, journey, journey_manifest
        )
    validate_durable_evidence(
        durable, manifest["durable_state"], confirmation_policy
    )


def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=pathlib.Path, required=True)
    parser.add_argument("--evidence", type=pathlib.Path, required=True)
    parser.add_argument("--durable-evidence", type=pathlib.Path, required=True)
    parser.add_argument("--chain-directory", type=pathlib.Path, required=True)
    parser.add_argument("--lightning-directory", type=pathlib.Path, required=True)
    return parser.parse_args()


def main():
    try:
        validate(parse_arguments())
    except (EvidenceError, KeyError, TypeError) as error:
        print(f"provider funded smoke evidence rejected: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
