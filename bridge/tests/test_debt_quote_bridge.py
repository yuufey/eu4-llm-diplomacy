"""Exercise the read-only facade and its publication boundary without EU4."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from bridge.diplomacy import DiplomacyTools, ObserverSession
from bridge.diplomacy_catalog import ACTIONS
from bridge.diplomacy_journal import DurableJournal
from bridge.debt_quote_query import ACTION_ID, QUERY_CAPABILITY, BASIS


class DebtQuoteBridgeTests(unittest.TestCase):
    def test_catalog_preserves_actions_and_lists_quote_as_query_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            journal = DurableJournal(Path(tmp) / "catalog.sqlite3",
                                     experiment_id="offline-quote", session_id="offline")
            try:
                tools = DiplomacyTools(journal)
                catalog = tools.list_diplomatic_actions()
                self.assertEqual({row["action_id"] for row in catalog["actions"]}, set(ACTIONS))
                self.assertNotIn(ACTION_ID, {row["action_id"] for row in catalog["actions"]})
                self.assertEqual(len(catalog["query_only_actions"]), 1)
                quote = catalog["query_only_actions"][0]
                self.assertEqual(quote["action_id"], ACTION_ID)
                self.assertTrue(quote["query_only"])
                self.assertFalse(quote["submission_supported"])
                self.assertEqual(quote["phases"]["initiate"]["execute"], "unimplemented")
                self.assertEqual(tools.list_diplomatic_actions(category="peace_term")["query_only_actions"], [])
            finally:
                journal.close()

    def test_execution_rejected_before_journal_or_native_query(self):
        journal, session = Mock(), Mock()
        tools = DiplomacyTools(journal, session)
        with self.assertRaisesRegex(ValueError, "DEBT_QUOTE_IS_READ_ONLY"):
            tools.execute_diplomatic_action("quote_1", ACTION_ID, "FRA", "ENG")
        journal.register.assert_not_called()
        session.inspect_take_on_debt.assert_not_called()
        self.assertNotIn(ACTION_ID, ACTIONS)

    @staticmethod
    def _ack():
        return {"version": 34, QUERY_CAPABILITY: True,
                "native_debt_quote_query_wire": 1,
                "native_debt_quote_read_only": True,
                "native_debt_quote_fp_context": True}

    def test_capability_requires_literal_v34_contract(self):
        session = object.__new__(ObserverSession)
        session.record = {}
        ack = self._ack()
        with patch.object(session, "_installation_ack", return_value=ack):
            self.assertIn(QUERY_CAPABILITY, session.installation_capabilities())
        for key in ack:
            malformed = dict(ack)
            malformed.pop(key)
            with self.subTest(missing=key), patch.object(
                    session, "_installation_ack", return_value=malformed):
                self.assertNotIn(QUERY_CAPABILITY, session.installation_capabilities())
        for key, value in (("version", 33), ("native_debt_quote_query_wire", True),
                           ("native_debt_quote_read_only", 1),
                           ("native_debt_quote_fp_context", 1)):
            malformed = dict(ack, **{key: value})
            with self.subTest(key=key), patch.object(
                    session, "_installation_ack", return_value=malformed):
                self.assertNotIn(QUERY_CAPABILITY, session.installation_capabilities())

    def test_copied_caps_cannot_grant_quote(self):
        session = object.__new__(ObserverSession)
        session.record = {}
        for payload in ({"caps": [QUERY_CAPABILITY]},
                        {"capabilities": {QUERY_CAPABILITY: True}}):
            with self.subTest(payload=payload), patch.object(
                    session, "_installation_ack", return_value=payload):
                self.assertNotIn(QUERY_CAPABILITY, session.installation_capabilities())

    @staticmethod
    def _session(capabilities=()):
        session = Mock()
        session.health.return_value = {"status": "ready", "date_raw": 56556984}
        session.installation_capabilities.return_value = frozenset(capabilities)
        return session

    def test_missing_capability_performs_no_native_query(self):
        session = self._session()
        result = DiplomacyTools(Mock(), session).inspect_diplomatic_action(
            ACTION_ID, "FRA", "ENG")
        self.assertFalse(result["debt_quote"]["complete"])
        self.assertEqual(result["authorization"]["status"], "unavailable")
        session.inspect_take_on_debt.assert_not_called()

    def test_raw_capability_container_cannot_enable_public_query(self):
        session = self._session()
        for advertised in ([QUERY_CAPABILITY], {QUERY_CAPABILITY: True}):
            session.installation_capabilities.return_value = advertised
            with self.subTest(advertised=advertised):
                result = DiplomacyTools(Mock(), session).inspect_diplomatic_action(
                    ACTION_ID, "FRA", "ENG")
                self.assertFalse(result["debt_quote"]["complete"])
        session.inspect_take_on_debt.assert_not_called()

    def test_query_failure_never_grants_execution_or_financial_value(self):
        session = self._session([QUERY_CAPABILITY])
        session.inspect_take_on_debt.return_value = {"error_code": "QUERY_FAILED"}
        result = DiplomacyTools(Mock(), session).inspect_diplomatic_action(
            ACTION_ID, "FRA", "ENG")
        self.assertEqual(result["interface_support"]["execute"], "unimplemented")
        self.assertFalse(result["debt_quote"]["complete"])
        self.assertEqual(result["costs"]["items"], [])

    def test_invisible_quote_has_no_cost(self):
        session = self._session([QUERY_CAPABILITY])
        session.inspect_take_on_debt.return_value = {
            "native_visibility": False,
            "debt_quote": {"status": "invisible", "complete": False}}
        result = DiplomacyTools(Mock(), session).inspect_diplomatic_action(
            ACTION_ID, "FRA", "ENG")
        self.assertEqual(result["visibility"]["status"], "invisible")
        self.assertEqual(result["costs"]["items"], [])
        self.assertNotIn("native_description", result)

    def test_facade_drops_nonpublic_fields_from_normalized_session(self):
        session = self._session([QUERY_CAPABILITY])
        session.inspect_take_on_debt.return_value = {
            "native_visibility": True,
            "debt_quote": {"status": "known", "complete": True, "total_raw_i32": 1234,
                "value": 999, "scale": 1000, "unit": "ducats", "basis": BASIS,
                "as_of_raw": 56556984, "loans": ["secret"], "pointer": "secret",
                "floating_point": {"model_compatible": True, "controls_stable": True,
                                   "register": "secret"}},
            "native_description": {"text": "native quote", "readable": True,
                                   "truncated": False, "pointer": "secret"}}
        result = DiplomacyTools(Mock(), session).inspect_diplomatic_action(
            ACTION_ID, "FRA", "ENG")
        self.assertTrue(result["debt_quote"]["complete"])
        self.assertEqual(result["debt_quote"]["value"], 1.234)
        self.assertNotIn("secret", json.dumps(result))
        self.assertEqual(result["native_description"]["text"], "native quote")

    def test_query22_wire_uses_existing_read_channel(self):
        session = object.__new__(ObserverSession)
        session.record = {"creation_filetime": 1234, "controlled_countries": ["FRA"]}
        session.session_id = "offline-session"
        session.native_text_codec = "eu4_escape"
        captured = []
        with tempfile.TemporaryDirectory() as tmp:
            session.directory = Path(tmp)
            log = session.directory / "control-probe.jsonl"
            log.write_bytes(b"")

            def publish(pending, request):
                wire = Path(pending).read_text(encoding="ascii")
                captured.append(wire)
                parts = wire.split()
                log.write_text(json.dumps({
                    "event": "native_alliance_inspection_failed",
                    "session_id": session.session_id, "query_id": parts[2],
                    "reason_code": "OFFLINE_TEST_FAILURE", "submitted": False}) + "\n")

            with patch.object(session, "health", return_value={
                    "status": "ready", "date_raw": 56556984}), patch.object(
                    session, "installation_capabilities", return_value=frozenset({
                        QUERY_CAPABILITY})), patch("bridge.diplomacy.os.link", side_effect=publish):
                result = session.inspect_take_on_debt("FRA", "ENG")
            self.assertEqual(result, {"error_code": "OFFLINE_TEST_FAILURE"})
            self.assertEqual(len(captured), 1)
            self.assertTrue(captured[0].startswith("EU4DIP_QUERY22 4d2 inspect_"))
            self.assertIn(" take_on_debt FRA ENG 56556984 ", captured[0])
            self.assertTrue(captured[0].endswith("\n"))
            self.assertFalse(list(session.directory.glob("*.pending")))

    def test_quote_rejects_player_or_foreign_actor_before_channel(self):
        session = object.__new__(ObserverSession)
        for actor, recipient in (("POR", "ENG"), ("FRA", "POR"), ("FRA", "FRA")):
            with self.subTest(actor=actor, recipient=recipient), patch.object(
                    session, "inspect_alliance") as read_channel:
                with self.assertRaises(ValueError):
                    session.inspect_take_on_debt(actor, recipient)
                read_channel.assert_not_called()
