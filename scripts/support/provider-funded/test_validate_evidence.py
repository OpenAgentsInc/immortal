#!/usr/bin/env python3

import copy
import json
import pathlib
import sys
import unittest


SUPPORT_DIRECTORY = pathlib.Path(__file__).resolve().parent
REPOSITORY_ROOT = SUPPORT_DIRECTORY.parents[2]
sys.path.insert(0, str(SUPPORT_DIRECTORY))

import validate_evidence


def terminal_counts(total):
    return {"total": total, "terminal": total, "pending": 0, "unresolved": 0}


def valid_durable_evidence():
    return {
        "schema": validate_evidence.DURABLE_EVIDENCE_SCHEMA,
        "terminal_confirmations": 3,
        "session_summary": {
            "selected": 3,
            "distinct": 3,
            "terminal": 3,
            "pending": 0,
            "unresolved": 0,
        },
        "journeys": {
            "submarine": {
                "matched_session_count": 1,
                "session_disposition": "provider_close_completed",
                "reservations": terminal_counts(1),
                "effects": terminal_counts(2),
            },
            "reverse": {
                "matched_session_count": 1,
                "session_disposition": "provider_close_completed",
                "reservations": terminal_counts(1),
                "effects": terminal_counts(3),
            },
            "reverse_refund": {
                "matched_session_count": 1,
                "session_disposition": "provider_close_refunded",
                "reservations": terminal_counts(1),
                "effects": terminal_counts(3),
            },
        },
        "watches": {
            "reverse": {
                "job_kind": "refund_broadcast",
                "total": 1,
                "completed": 1,
                "confirmed": 0,
                "pending": 0,
                "unresolved": 0,
                "disposition": "claim_settled",
                "confirmations": 0,
            },
            "reverse_refund": {
                "job_kind": "refund_broadcast",
                "total": 1,
                "completed": 0,
                "confirmed": 1,
                "pending": 0,
                "unresolved": 0,
                "disposition": "confirmation",
                "confirmations": 3,
            },
        },
    }


class DurableEvidenceTests(unittest.TestCase):
    def test_manifest_and_static_query_pin_the_durable_gate(self):
        manifest_path = (
            REPOSITORY_ROOT / "tests/fixtures/provider/funded-smoke-v1.json"
        )
        with manifest_path.open(encoding="utf-8") as source:
            manifest = json.load(source)
        self.assertEqual(
            manifest["durable_evidence_schema"],
            validate_evidence.DURABLE_EVIDENCE_SCHEMA,
        )
        self.assertEqual(
            manifest["durable_state"], validate_evidence.EXPECTED_DURABLE_STATE
        )

        query = (SUPPORT_DIRECTORY / "durable_evidence.sql").read_text(encoding="utf-8")
        self.assertIn("PREPARE funded_smoke_durable_evidence", query)
        self.assertIn("EXECUTE funded_smoke_durable_evidence", query)
        self.assertIn("provider_session_record", query)
        self.assertIn("provider_session_disposition", query)
        self.assertIn("provider_reservation", query)
        self.assertIn("provider_effect", query)
        self.assertIn("provider_watch_job", query)
        for fragment in (
            "record.kind = 39606",
            "reservation.state = 'released'",
            "reservation.release_cause = 'terminal_close'",
            "effect.state = 'applied'",
            "watch.state = 'completed'",
            "watch.state = 'confirmed'",
        ):
            self.assertIn(fragment, query)

    def test_harness_keeps_durable_rows_private_and_validates_the_aggregate(self):
        harness = (REPOSITORY_ROOT / "scripts/test-provider-funded.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn('<"${support_dir}/durable_evidence.sql"', harness)
        self.assertIn('>"${durable_evidence_file}"', harness)
        self.assertIn(
            '2>"${private_root}/evidence/provider-postgres-error.log"', harness
        )
        self.assertIn('--durable-evidence "${durable_evidence_file}"', harness)
        self.assertNotIn("provider-postgres.json\" >&1", harness)

    def test_accepts_three_terminal_journeys_and_expected_watches(self):
        validate_evidence.validate_durable_evidence(
            valid_durable_evidence(),
            validate_evidence.EXPECTED_DURABLE_STATE,
            validate_evidence.EXPECTED_CONFIRMATION_POLICY,
        )

    def test_rejects_nonterminal_effect(self):
        durable = valid_durable_evidence()
        durable["journeys"]["submarine"]["effects"] = {
            "total": 2,
            "terminal": 1,
            "pending": 1,
            "unresolved": 0,
        }
        with self.assertRaises(validate_evidence.EvidenceError):
            validate_evidence.validate_durable_evidence(
                durable,
                validate_evidence.EXPECTED_DURABLE_STATE,
                validate_evidence.EXPECTED_CONFIRMATION_POLICY,
            )

    def test_rejects_cooperative_watch_without_claim_settled(self):
        durable = valid_durable_evidence()
        durable["watches"]["reverse"]["disposition"] = "confirmation"
        with self.assertRaises(validate_evidence.EvidenceError):
            validate_evidence.validate_durable_evidence(
                durable,
                validate_evidence.EXPECTED_DURABLE_STATE,
                validate_evidence.EXPECTED_CONFIRMATION_POLICY,
            )

    def test_rejects_refund_watch_below_terminal_depth(self):
        durable = valid_durable_evidence()
        durable["watches"]["reverse_refund"]["confirmations"] = 2
        with self.assertRaises(validate_evidence.EvidenceError):
            validate_evidence.validate_durable_evidence(
                durable,
                validate_evidence.EXPECTED_DURABLE_STATE,
                validate_evidence.EXPECTED_CONFIRMATION_POLICY,
            )

    def test_rejects_private_field_names_in_durable_evidence(self):
        durable = copy.deepcopy(valid_durable_evidence())
        durable["seed"] = "forbidden"
        with self.assertRaises(validate_evidence.EvidenceError):
            validate_evidence.reject_forbidden_fields(
                durable, validate_evidence.EXPECTED_FORBIDDEN_FIELDS
            )


if __name__ == "__main__":
    unittest.main()
