"""Offline checks for the read-only Take on Debt quote proof boundary."""
from __future__ import annotations

import copy
import unittest

from bridge.debt_quote_query import (
    ACTION_ID,
    BASIS,
    QUERY_CAPABILITY,
    normalize_request,
    project_event,
    query_only_descriptor,
    validate_event,
)
from bridge.diplomacy_catalog import ACTIONS
from bridge.information.loan_interest_quote_math import quote_total


AS_OF = 56556984
MXCSR_RNE_MASKED = 0x1F80


def _loan_rows(count: int = 1) -> list[dict[str, int]]:
    rows = [{
        "principal_i32": 1500,
        "stored_rate_i32": 0,
        "expiry_raw_i32": AS_OF,
        "interest_raw_i32": 0,
    } for _ in range(count)]
    model = quote_total(
        loans=[{key: row[key] for key in (
            "principal_i32", "stored_rate_i32", "expiry_raw_i32")}
            for row in rows],
        as_of_raw_i32=AS_OF,
    )
    for row, modeled in zip(rows, model["loans"]):
        row["interest_raw_i32"] = modeled["interest"]["amount_i32"]
    return rows


def _event(*, visible: bool = True, complete: bool = True,
           count: int = 1) -> dict:
    rows = _loan_rows(count) if visible and complete else []
    total = None
    if visible and complete:
        total = quote_total(
            loans=[{key: row[key] for key in (
                "principal_i32", "stored_rate_i32", "expiry_raw_i32")}
                for row in rows],
            as_of_raw_i32=AS_OF,
        )["quote_i32"]
    mxcsr_values = ([MXCSR_RNE_MASKED, MXCSR_RNE_MASKED,
                     MXCSR_RNE_MASKED, MXCSR_RNE_MASKED]
                    if visible and complete else
                    [MXCSR_RNE_MASKED, None, None, MXCSR_RNE_MASKED]
                    if visible else [None] * 4)
    mxcsr_flags = ({
        "mxcsr_model_compatible": True,
        "mxcsr_controls_stable": True,
        "mxcsr_daz_enabled": False,
        "mxcsr_ftz_enabled": False,
    } if visible else {
        "mxcsr_model_compatible": False,
        "mxcsr_controls_stable": False,
        "mxcsr_daz_enabled": False,
        "mxcsr_ftz_enabled": False,
    })
    quote = {
        "schema": "native.debt_quote.v1",
        "read_only": True,
        "complete": complete if visible else False,
        "context_stable": True,
        "guards_verified": True,
        "financial_inputs_read": visible,
        "mxcsr_before": mxcsr_values[0],
        "mxcsr_after_helpers": mxcsr_values[1],
        "mxcsr_before_description": mxcsr_values[2],
        "mxcsr_after": mxcsr_values[3],
        **mxcsr_flags,
        "total_raw_i32": total,
        "scale": 1000,
        "basis": BASIS,
        "loans": rows,
        "description_readable": visible and complete,
        "description_truncated": False,
        "description_encoding_known": False,
        "description_hex": "44656274205b3939395d" if visible and complete else "",
        "description_cleanup_performed": visible and complete,
        "description_cleanup_skipped": False,
        "action_cleanup_performed": visible,
    }
    return {
        "event": "native_alliance_inspection",
        "action_id": ACTION_ID,
        "family": "debt_quote",
        "query_id": "inspect_" + "a" * 32,
        "session_id": "observer-session-quote-test",
        "actor": "FRA",
        "recipient": "ENG",
        "phase": "initiate",
        "date_raw": AS_OF,
        "ui_selection_checked": True,
        "native_visibility": visible,
        "reason_code": ("NATIVE_VISIBILITY_FALSE" if not visible else
                        "NATIVE_DEBT_QUOTE_READY" if complete else
                        "NATIVE_DEBT_QUOTE_INCOMPLETE"),
        "validity_called": False,
        "full_rules_complete": False,
        "complete": complete if visible else False,
        "submitted": False,
        "native_debt_quote": quote,
    }


def _all_keys(value: object) -> set[str]:
    found: set[str] = set()
    if type(value) is dict:
        for key, item in value.items():
            if isinstance(key, str):
                found.add(key)
            found.update(_all_keys(item))
    elif type(value) is list:
        for item in value:
            found.update(_all_keys(item))
    return found


class DebtQuoteQueryTests(unittest.TestCase):
    def test_request_scope_and_empty_parameters_are_strict(self):
        self.assertEqual({}, normalize_request("FRA", "ENG", "initiate", {}))
        self.assertEqual({}, normalize_request("POR", "ENG", "initiate", {}))
        self.assertEqual({}, normalize_request("FRA", "POR", "initiate", {}))
        self.assertEqual({}, normalize_request("K00", "SAV", "initiate", {}))
        invalid = (
            ("por", "ENG", "initiate", {}),
            ("FRA", "FRA", "initiate", {}),
            ("FRA", "eng", "initiate", {}),
            ("FRA", "EN1G", "initiate", {}),
            ("FRA", "ENG", "accept", {}),
            ("FRA", "ENG", "initiate", None),
            ("FRA", "ENG", "initiate", {"amount": 1}),
        )
        for request in invalid:
            with self.subTest(request=request), self.assertRaises(ValueError):
                normalize_request(*request)

    def test_complete_event_recomputes_total_and_decodes_only_safe_text(self):
        event = _event()
        self.assertTrue(validate_event(
            event, "FRA", "ENG", "initiate", AS_OF,
            event["query_id"], event["session_id"]))

        public = project_event(event)
        expected = quote_total(
            loans=[{key: row[key] for key in (
                "principal_i32", "stored_rate_i32", "expiry_raw_i32")}
                for row in event["native_debt_quote"]["loans"]],
            as_of_raw_i32=AS_OF,
        )
        self.assertEqual("known", public["debt_quote"]["status"])
        self.assertEqual(expected["quote_i32"], public["debt_quote"]["total_raw_i32"])
        self.assertEqual(expected["quote_value"], public["debt_quote"]["value"])
        self.assertEqual(1000, public["debt_quote"]["scale"])
        self.assertEqual("ducats", public["debt_quote"]["unit"])
        self.assertEqual(AS_OF, public["debt_quote"]["as_of_raw"])
        self.assertEqual("Debt [999]", public["native_description"]["text"])
        self.assertFalse(public["validity_called"])
        self.assertFalse(public["full_rules_complete"])
        self.assertFalse(public["submitted"])
        self.assertFalse(_all_keys(public) & {
            "loans", "description_hex", "principal_i32", "stored_rate_i32",
            "expiry_raw_i32", "interest_raw_i32", "mxcsr_before",
            "module_base", "country_pointer", "native_record",
        })

    def test_scope_identity_date_and_optional_bindings_are_checked(self):
        event = _event()
        self.assertFalse(validate_event(event, "ENG", "ENG", "initiate", AS_OF))
        self.assertFalse(validate_event(event, "FRA", "SWE", "initiate", AS_OF))
        self.assertFalse(validate_event(event, "FRA", "ENG", "accept", AS_OF))
        self.assertFalse(validate_event(event, "FRA", "ENG", "initiate", AS_OF + 1))
        self.assertFalse(validate_event(event, "FRA", "ENG", "initiate", True))
        self.assertFalse(validate_event(
            event, "FRA", "ENG", "initiate", AS_OF, "inspect_other"))
        self.assertFalse(validate_event(
            event, "FRA", "ENG", "initiate", AS_OF,
            session_id="other-session"))

    def test_invisible_event_has_no_financial_reads_or_public_quote(self):
        event = _event(visible=False)
        self.assertTrue(validate_event(event, "FRA", "ENG", "initiate", AS_OF))
        public = project_event(event)
        self.assertFalse(public["native_visibility"])
        self.assertEqual("invisible", public["debt_quote"]["status"])
        self.assertIsNone(public["debt_quote"]["total_raw_i32"])
        self.assertIsNone(public["debt_quote"]["value"])
        self.assertNotIn("native_description", public)
        self.assertFalse(_all_keys(public) & {
            "loans", "description_hex", "principal_i32", "interest_raw_i32",
        })

    def test_visibility_requires_verified_guards_and_stable_context(self):
        # These mirror native exits after the selector returned a bool, where
        # the post-selector actor/target/date check failed. Neither bool is a
        # publishable visibility result in that case.
        for visible in (False, True):
            event = _event(visible=visible, complete=visible)
            event["native_debt_quote"]["context_stable"] = False
            with self.subTest(visible=visible, cause="context_changed"):
                self.assertFalse(validate_event(
                    event, "FRA", "ENG", "initiate", AS_OF))
                public = project_event(event)
                self.assertIsNone(public["native_visibility"])
                self.assertEqual("unknown", public["debt_quote"]["status"])

        for visible in (False, True):
            event = _event(visible=visible, complete=visible)
            event["native_debt_quote"]["guards_verified"] = False
            with self.subTest(visible=visible, cause="guard_failed"):
                self.assertFalse(validate_event(
                    event, "FRA", "ENG", "initiate", AS_OF))
                public = project_event(event)
                self.assertIsNone(public["native_visibility"])
                self.assertEqual("unknown", public["debt_quote"]["status"])

        mismatched_reason = _event(visible=False)
        mismatched_reason["reason_code"] = "CONTEXT_CHANGED_DURING_VISIBILITY"
        self.assertFalse(validate_event(
            mismatched_reason, "FRA", "ENG", "initiate", AS_OF))

    def test_visible_incomplete_event_is_unknown_and_hides_private_values(self):
        event = _event(complete=False)
        self.assertTrue(validate_event(event, "FRA", "ENG", "initiate", AS_OF))
        quote = event["native_debt_quote"]
        self.assertIsNotNone(quote["mxcsr_before"])
        self.assertIsNone(quote["mxcsr_after_helpers"])
        self.assertIsNone(quote["mxcsr_before_description"])
        self.assertIsNotNone(quote["mxcsr_after"])
        public = project_event(event)
        self.assertTrue(public["native_visibility"])
        self.assertEqual("unknown", public["debt_quote"]["status"])
        self.assertIsNone(public["debt_quote"]["total_raw_i32"])
        self.assertIsNone(public["debt_quote"]["value"])
        self.assertNotIn("native_description", public)
        self.assertFalse(_all_keys(public) & {
            "loans", "description_hex", "principal_i32", "interest_raw_i32",
        })
        self.assertNotIn("floating_point", public["debt_quote"])

    def test_native_total_and_per_loan_interest_must_match_model(self):
        event = _event()
        event["native_debt_quote"]["total_raw_i32"] += 1
        self.assertFalse(validate_event(event, "FRA", "ENG", "initiate", AS_OF))

        event = _event()
        event["native_debt_quote"]["loans"][0]["interest_raw_i32"] += 1
        self.assertFalse(validate_event(event, "FRA", "ENG", "initiate", AS_OF))

    def test_complete_requires_stable_context_guards_and_cleanup(self):
        mutations = (
            ("context_stable", False),
            ("guards_verified", False),
            ("description_cleanup_performed", False),
            ("action_cleanup_performed", False),
        )
        for field, value in mutations:
            event = _event()
            event["native_debt_quote"][field] = value
            with self.subTest(field=field):
                self.assertFalse(validate_event(event, "FRA", "ENG", "initiate", AS_OF))

    def test_fp_controls_are_recomputed_and_daz_ftz_are_allowed(self):
        event = _event()
        event["native_debt_quote"]["mxcsr_after"] = 0x3F80
        self.assertFalse(validate_event(event, "FRA", "ENG", "initiate", AS_OF))

        event = _event()
        for field in ("mxcsr_before", "mxcsr_after_helpers",
                      "mxcsr_before_description", "mxcsr_after"):
            event["native_debt_quote"][field] = 0x9FC0
        event["native_debt_quote"]["mxcsr_daz_enabled"] = True
        event["native_debt_quote"]["mxcsr_ftz_enabled"] = True
        self.assertTrue(validate_event(event, "FRA", "ENG", "initiate", AS_OF))
        public = project_event(event)
        self.assertTrue(public["debt_quote"]["floating_point"]["model_compatible"])
        self.assertTrue(public["debt_quote"]["floating_point"]["daz_enabled"])
        self.assertTrue(public["debt_quote"]["floating_point"]["ftz_enabled"])
        self.assertNotIn("mxcsr_before", _all_keys(public))

    def test_invisible_with_contradictory_private_payload_is_rejected_and_hidden(self):
        event = _event(visible=False)
        event["native_debt_quote"]["loans"] = _loan_rows()
        event["native_debt_quote"]["total_raw_i32"] = 1500000
        self.assertFalse(validate_event(event, "FRA", "ENG", "initiate", AS_OF))
        public = project_event(event)
        self.assertIsNone(public["native_visibility"])
        self.assertIsNone(public["ui_selection_checked"])
        self.assertEqual("unknown", public["debt_quote"]["status"])
        self.assertIsNone(public["debt_quote"]["total_raw_i32"])
        self.assertNotIn("native_description", public)
        self.assertFalse(_all_keys(public) & {"loans", "principal_i32", "description_hex"})

    def test_rows_use_strict_int32_and_have_a_64_record_limit(self):
        event = _event(count=64)
        self.assertTrue(validate_event(event, "FRA", "ENG", "initiate", AS_OF))
        oversized = _event(count=64)
        oversized["native_debt_quote"]["loans"].append(
            copy.deepcopy(oversized["native_debt_quote"]["loans"][0]))
        self.assertFalse(validate_event(oversized, "FRA", "ENG", "initiate", AS_OF))

        malformed = _event()
        malformed["native_debt_quote"]["loans"][0]["principal_i32"] = True
        self.assertFalse(validate_event(malformed, "FRA", "ENG", "initiate", AS_OF))
        malformed = _event()
        malformed["native_debt_quote"]["total_raw_i32"] = True
        self.assertFalse(validate_event(malformed, "FRA", "ENG", "initiate", AS_OF))

    def test_description_payload_is_bounded_to_512_bytes(self):
        boundary = _event()
        boundary["native_debt_quote"]["description_hex"] = "41" * 512
        self.assertTrue(validate_event(boundary, "FRA", "ENG", "initiate", AS_OF))

        oversized = _event()
        oversized["native_debt_quote"]["description_hex"] = "41" * 513
        self.assertFalse(validate_event(oversized, "FRA", "ENG", "initiate", AS_OF))

    def test_descriptor_is_query_only_and_not_registered_for_execution(self):
        available = query_only_descriptor(True)
        unavailable = query_only_descriptor(False)
        self.assertNotIn(ACTION_ID, ACTIONS)
        self.assertTrue(available["query_only"])
        self.assertEqual({}, available["parameter_definitions"])
        self.assertEqual(QUERY_CAPABILITY, available["phases"]["initiate"]["query"])
        self.assertEqual("unimplemented", available["phases"]["initiate"]["execute"])
        self.assertEqual("unimplemented", unavailable["phases"]["initiate"]["query"])
        self.assertEqual("unimplemented", unavailable["phases"]["initiate"]["execute"])
        with self.assertRaises(ValueError):
            query_only_descriptor(1)

    def test_malformed_event_projects_only_an_unknown_shell(self):
        event = _event()
        event["native_debt_quote"]["schema"] = "native.other.v1"
        public = project_event(event)
        self.assertEqual("unknown", public["debt_quote"]["status"])
        self.assertIsNone(public["debt_quote"]["total_raw_i32"])
        self.assertNotIn("native_description", public)
        self.assertFalse(_all_keys(public) & {
            "loans", "description_hex", "principal_i32", "interest_raw_i32",
        })


if __name__ == "__main__":
    unittest.main()
