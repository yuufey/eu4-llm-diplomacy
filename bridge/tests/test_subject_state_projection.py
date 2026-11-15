from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from bridge.diplomacy import DiplomacyTools, ObserverSession
from bridge.diplomacy_journal import DurableJournal


FIXTURE = (Path(__file__).parent / "fixtures" /
           "vassalization_r35_native_inspections.json")


class SubjectStateProjectionTests(unittest.TestCase):
    @staticmethod
    def _event() -> dict:
        return json.loads(FIXTURE.read_text(encoding="utf-8"))["events"][
            "offer_vassalization"]

    def setUp(self) -> None:
        self.journal = DurableJournal(":memory:", "subject-state", "subject-session")

    def tearDown(self) -> None:
        self.journal.close()

    def _public_query(self, native: dict) -> dict:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            session_id = "subject-session"
            installation = root / "installation.json"
            installation.write_text(json.dumps({
                "experiment_id": "subject-state", "session_id": session_id,
                "pid": 1, "creation_filetime": 2, "dll_sha256": "dll",
                "controlled_countries": ["FRA"], "installation_returncode": 0,
            }), encoding="utf-8")
            log = root / "control-probe.jsonl"
            log.write_text(json.dumps({"event": "diplomacy_observer_installed",
                                       "session_id": session_id,
                                       "native_vassalization_query": True}) + "\n",
                           encoding="utf-8")
            session = ObserverSession(installation, root / "eu4.exe")
            ready = {"status": "ready", "state_id": "ready", "date_raw": 1,
                     "reasons": [], "complete": True}
            with patch.object(session, "health", return_value=ready), \
                 patch.object(session, "inspect_vassalization", return_value=native), \
                 patch("bridge.diplomacy.probe_identity",
                       return_value={"session_id": session_id}):
                result = DiplomacyTools(self.journal, session).inspect_diplomatic_action(
                    "offer_vassalization", "FRA", "SAV")
            return result

    def test_verified_subject_state_is_normalized(self):
        value = {"verified": True, "is_subject": True, "overlord": "FRA",
                 "subject_type": "vassal", "liberty_desire_raw": 72500,
                 "scale": 1000}
        self.assertEqual(value, ObserverSession._subject_state_value(value))

    def test_verified_non_subject_has_no_subject_only_values(self):
        value = {"verified": True, "is_subject": False}
        self.assertEqual({"verified": True, "is_subject": False, "overlord": None,
                          "subject_type": None, "liberty_desire_raw": None,
                          "scale": 1000}, ObserverSession._subject_state_value(value))

    def test_bad_shape_and_boolean_raw_are_rejected(self):
        valid = {"verified": True, "is_subject": True, "overlord": "FRA",
                 "subject_type": "vassal", "liberty_desire_raw": 50000,
                 "scale": 1000}
        for value in ([], {**valid, "liberty_desire_raw": True},
                      {**valid, "is_subject": 1}, {**valid, "scale": True}):
            with self.subTest(value=value):
                self.assertIsNone(ObserverSession._subject_state_value(value))

    def test_integration_keeps_false_zero_and_decodes_native_conditions(self):
        integration = {'verified': True, 'applicable': True, 'can_start': False,
                       'total_diplomatic_power': 0, 'conditions_readable': True,
                       'conditions_hex': b'Need 50 years'.hex(), 'conditions_truncated': False}
        self.assertEqual({'verified': True, 'applicable': True, 'can_start': False,
                          'total_diplomatic_power': 0, 'conditions': 'Need 50 years',
                          'conditions_truncated': False},
                         ObserverSession._subject_integration_value(integration, 'eu4_escape'))
        for bad in ({**integration, 'total_diplomatic_power': True},
                    {**integration, 'can_start': 1}, {**integration, 'total_diplomatic_power': -1}):
            with self.subTest(bad=bad):
                self.assertIsNone(ObserverSession._subject_integration_value(bad))

    def test_bad_optional_integration_preserves_existing_subject_state(self):
        value = {'verified': True, 'is_subject': True, 'overlord': 'DAN',
                 'subject_type': 'personal_union', 'liberty_desire_raw': 0, 'scale': 1000,
                 'integration': {'verified': False}}
        expected = {key: item for key, item in value.items() if key != 'integration'}
        self.assertEqual(expected, ObserverSession._subject_state_value(value))

    def test_integration_survives_semantic_and_public_projection(self):
        native = {'verified': True, 'applicable': True, 'can_start': False,
                  'total_diplomatic_power': 144, 'conditions_readable': True,
                  'conditions_hex': b'Need 50 years'.hex(), 'conditions_truncated': False}
        event = self._event()
        event['recipient_subject_state'] = {
            'verified': True, 'is_subject': True, 'overlord': 'FRA', 'subject_type': 'vassal',
            'liberty_desire_raw': 0, 'scale': 1000, 'integration': native}
        semantic = ObserverSession._semantic_inspection(event, {}, 'eu4_escape', False)
        result = self._public_query(semantic)
        self.assertEqual({'verified': True, 'applicable': True, 'can_start': False,
                          'total_diplomatic_power': 144, 'conditions': 'Need 50 years',
                          'conditions_truncated': False}, result['recipient_subject_state']['integration'])

    def test_semantic_and_public_projection_passes_states_and_keeps_legacy_event(self):
        event = self._event()
        recipient = {"verified": True, "is_subject": True, "overlord": "FRA",
                     "subject_type": "vassal", "liberty_desire_raw": 72500,
                     "scale": 1000}
        event["actor_subject_state"] = {"verified": True, "is_subject": False}
        event["recipient_subject_state"] = recipient
        self.assertTrue(ObserverSession._valid_native_inspection(
            event, "offer_vassalization", "FRA", "SAV", "initiate", 1))
        semantic = ObserverSession._semantic_inspection(event, {}, "eu4_escape", False)
        self.assertEqual(recipient, semantic["recipient_subject_state"])
        public = self._public_query(semantic)
        self.assertEqual(recipient, public["recipient_subject_state"])
        self.assertEqual({"verified": True, "is_subject": False, "overlord": None,
                          "subject_type": None, "liberty_desire_raw": None,
                          "scale": 1000}, public["actor_subject_state"])
        legacy_semantic = ObserverSession._semantic_inspection(
            self._event(), {}, "eu4_escape", False)
        legacy = self._public_query(legacy_semantic)
        self.assertNotIn("actor_subject_state", legacy)
        self.assertNotIn("recipient_subject_state", legacy)


if __name__ == "__main__":
    unittest.main()
