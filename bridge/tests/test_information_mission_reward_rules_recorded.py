"""Offline recorded acceptance tests for the M04 literal rule projection.

The JSON fixture is a saved FRA mission-slot capture plus the selected static
definition AST.  Its expected occurrences and condition contexts were made by
an independent bounded AST walk; these tests deliberately compare the source
adapter/projector against those values instead of deriving expected values from
the implementation under test.
"""

from collections import Counter
from copy import deepcopy
import hashlib
import json
from pathlib import Path

from bridge.information import InformationService
from bridge.information.catalog import list_topics
from bridge.information.composite import CompositeSource
from bridge.information.missions import MissionInformationSource


FIXTURE_PATH = Path(__file__).with_name("fixtures") / (
    "information_mission_reward_rules_recorded_1374.json"
)
RULE_FIELDS = ("claims", "casus_belli", "trade_modifiers")
M04_FIELDS = ("rewards", *RULE_FIELDS)


def _load_fixture():
    return json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


class _RecordedPrimary:
    """Small source seam with a saved context and no native/game session."""

    event_types = ()

    def __init__(self, fixture):
        self._context = deepcopy(fixture["recorded_context"])

    def context(self):
        return deepcopy(self._context)

    def catalog(self):
        return list_topics()

    def read(self, query, context):
        raise AssertionError("M04 should be routed to MissionInformationSource")

    def poll_events(self, context, cursor):
        return {"events": [], "cursor": deepcopy(cursor or {}), "complete": True, "gaps": []}


class _RecordedDefinitions:
    def __init__(self, fixture):
        self._fixture = fixture
        self._roots = {
            root["root_id"]: deepcopy(root)
            for root in fixture["selected_roots"]
        }

    def context(self):
        return deepcopy(self._fixture["definition_context"])

    def root(self, root_id):
        return deepcopy(self._roots[root_id])

    def roots(self, root_ids):
        return [self.root(root_id) for root_id in root_ids]


class _RecordedMissionReader:
    """Replay only the recorded slot vector, intentionally omitting loaded_tasks."""

    supported_countries = ("FRA",)

    def __init__(self, fixture):
        self._fixture = fixture

    def __call__(self, country):
        assert country == "FRA"
        save = self._fixture["save"]
        missions = self._fixture["country_missions"]
        return {
            "complete": True,
            "country": country,
            "mode": "recorded",
            "game_date": save["date"],
            "session_id": None,
            "state_kind": "saved_country_mission_slots",
            "mission_slots": [
                {"slot": slot["index"], "roots": list(slot["root_ids"])}
                for slot in missions["mission_slots"]
            ],
            "completed_missions": {
                "status": "unknown",
                "reason": "COMPLETION_FIELD_ABSENT_IN_SAVE",
            },
            "provenance": {
                "file_sha256": save["sha256"],
                "save_date": save["date"],
                "save_version": save["version"],
                "recorded": True,
            },
        }


def _service(tmp_path, fixture=None):
    fixture = fixture or _load_fixture()
    primary = _RecordedPrimary(fixture)
    definitions = _RecordedDefinitions(fixture)
    reader = _RecordedMissionReader(fixture)
    adapter = MissionInformationSource(
        primary, definitions, reader, scheduling=False
    )
    source = CompositeSource(primary, [adapter])
    service = InformationService(source, tmp_path / "recorded-m04.sqlite3")
    return service, source


def _query(fields=M04_FIELDS, **parameters):
    return {
        "topic": "M04",
        "object": {"type": "country", "country": "FRA"},
        "fields": list(fields),
        "parameters": parameters,
    }


def _single_item(service, request_id, query):
    result = service.query(request_id, queries=[query])
    assert len(result["items"]) == 1
    return result, result["items"][0]


def _occurrence_key(row):
    return (
        row["command"],
        row["root_id"],
        row["task_id"],
        row["source"]["line"],
        row["source"]["path"],
    )


def _context_key(row):
    return (
        row["root_id"],
        row["task_id"],
        tuple(row["path"]),
        row["key"],
        row["line"],
        row["end_line"],
        row["path_name"],
    )


def _actual_occurrences(value):
    rows = []
    for task in value["rules"]:
        for rule in task.get("rules", []):
            rows.append(
                {
                    "command": rule["command"],
                    "root_id": task["root_id"],
                    "task_id": task["task_id"],
                    "source": {
                        "line": rule["source"]["line"],
                        "path": rule["source"]["path"],
                    },
                }
            )
    return rows


def _actual_condition_contexts(value):
    rows = []
    for task in value["rules"]:
        for context in task.get("context_table", []):
            if context.get("kind") != "condition":
                continue
            header = context["header"]
            rows.append(
                {
                    "root_id": task["root_id"],
                    "task_id": task["task_id"],
                    "path": list(context["path"]),
                    "key": context["key"],
                    "line": header["line"],
                    "end_line": header["end_line"],
                    "path_name": context["source"]["path"],
                }
            )
    return rows


def _assert_projection(item, fixture, query_name):
    expected_occurrences = fixture["expected_occurrence_tuples"][query_name]
    expected_contexts = fixture["expected_condition_contexts"][query_name]
    report_expected = fixture["expected"][query_name]
    for field in RULE_FIELDS:
        field_result = item["fields"][field]
        assert field_result["status"] == "known"
        assert field_result["complete"] is False
        value = field_result["value"]
        expected = expected_occurrences[field]
        assert value["task_count"] == report_expected[field]["selected_task_count"]
        assert value["context_table_count"] == 689 if query_name == "full" else (
            value["context_table_count"] >= len(expected_contexts[field])
        )
        assert value["evaluated"] is False
        assert value["applied"] == "unknown"
        assert field_result["provenance"]["mode"] == "static_rules"

        actual_rows = _actual_occurrences(value)
        actual_counter = Counter(_occurrence_key(row) for row in actual_rows)
        expected_counter = Counter(tuple(row) for row in expected)
        assert actual_counter == expected_counter
        assert len(actual_rows) == report_expected[field]["occurrence_count"]

        actual_contexts = Counter(
            _context_key(row) for row in _actual_condition_contexts(value)
        )
        expected_context_counter = Counter(
            (
                row["root_id"],
                row["task_id"],
                tuple(row["ast_path"]),
                row["key"],
                row["line"],
                row["end_line"],
                row["path"],
            )
            for row in expected_contexts[field]
        )
        assert actual_contexts == expected_context_counter
        assert len(_actual_condition_contexts(value)) == report_expected[field]["condition_context_count"]


def test_recorded_fixture_is_explicit_and_self_contained():
    fixture = _load_fixture()
    assert fixture["schema"] == "information_mission_reward_rules_recorded_fixture_v2"
    assert fixture["fixture_kind"] == "recorded_current_definition_rule_inventory"
    assert fixture["mode"] == "recorded"
    assert fixture["live_state"] is False
    assert fixture["not_a_live_state_fallback"] is True
    assert fixture["native_query_invoked"] is False
    assert fixture["task_membership_source"] == "current_definitions_for_captured_roots"
    assert fixture["loaded_task_membership_verified"] is False
    assert fixture["definition_rules_previously_loaded_verified"] is False
    assert fixture["recorded_context"]["session_id"] is None
    assert fixture["recorded_context"]["game_day"] is None
    assert fixture["save"]["country"] == "FRA"
    assert fixture["save"]["mode"] == "recorded"
    assert fixture["save"]["sha256"] == "ffa91dbd2a2d544b18d586a895bb9b0c2b90e94ece47b2c74507555b8f58c2e0"
    assert len(fixture["selected_roots"]) == 18
    assert sum(len(root["tasks"]) for root in fixture["selected_roots"]) == 61
    assert len(fixture["source"]["recorded_mcp_report_sha256"]) == 64
    assert len(fixture["source"]["fixture_inputs_sha256"]) == 64
    assert fixture["source"]["save_is_recorded"] is True
    assert fixture["source"]["native_query_invoked"] is False
    assert set(fixture["unsupported_fields"]) == {"unlocks", "duration"}


def test_recorded_full_projection_matches_independent_expected(tmp_path):
    fixture = _load_fixture()
    service, source = _service(tmp_path, fixture)
    try:
        result, item = _single_item(service, "recorded-full", _query())
    finally:
        service.close()

    assert result["status"] == "partial"
    assert item["complete"] is False
    assert item["source"]["mode"] == "recorded"
    assert item["source"]["session_id"] is None
    assert item["source"]["observer"] == "FRA"
    assert item["source"]["provenance"]["state"]["file_sha256"] == fixture["save"]["sha256"]
    provenance = item["source"]["provenance"]["reward_rule_projection"]
    assert provenance == {
        "selected_captured_roots_only": True,
        "task_membership_source": "current_definitions_for_captured_roots",
        "loaded_task_membership_verified": False,
        "definition_rules_previously_loaded_verified": False,
        "declared_literal_effect_rules": True,
        "runtime_conditions_evaluated": False,
        "actual_reward_status": "unknown",
    }
    rewards = item["fields"]["rewards"]
    assert rewards["status"] == "known"
    assert rewards["value"]["evaluated"] is False
    assert rewards["value"]["applied"] == "unknown"
    assert len(rewards["value"]["tasks"]) == 61
    _assert_projection(item, fixture, "full")


def test_historical_fixture_supports_new_declared_unlock_and_duration_views(tmp_path):
    fixture = _load_fixture()
    service, _source = _service(tmp_path, fixture)
    try:
        result, item = _single_item(
            service,
            "recorded-mixed-unsupported",
            _query((*M04_FIELDS, "unlocks", "duration")),
        )
    finally:
        service.close()

    assert result["status"] == "partial"
    for field in RULE_FIELDS:
        assert item["fields"][field]["status"] == "known"
    # Preserve the fixture's historical unsupported result. Current projection
    # can expose written requests while still withholding actual unlock state.
    unlocks = item["fields"]["unlocks"]
    assert unlocks["status"] == "known" and unlocks["complete"] is False
    assert unlocks["value"]["task_count"] == 61
    assert unlocks["value"]["evaluated"] is False
    assert unlocks["value"]["actual_unlocks"] == "unknown"
    assert unlocks["value"]["literal_rule_count"] > 0
    duration = item["fields"]["duration"]
    assert duration["status"] == "known"
    assert duration["complete"] is False
    assert duration["value"]["task_count"] == 61
    assert duration["value"]["known_numeric_term_count"] > 0
    assert duration["value"]["evaluated"] is False
    assert duration["value"]["applied"] == "unknown"
    assert duration["value"]["start_time"] == "unknown"
    assert duration["value"]["expiry_time"] == "unknown"
    assert item["source"]["mode"] == "recorded"
    assert item["source"]["session_id"] is None
    _assert_projection(item, fixture, "full")


def test_recorded_root_selector_matches_independent_root_expected(tmp_path):
    fixture = _load_fixture()
    service, _source = _service(tmp_path, fixture)
    try:
        result, item = _single_item(
            service,
            "recorded-root-selector",
            _query(root_id="french_missions_5_normal"),
        )
    finally:
        service.close()

    assert result["status"] == "partial"
    assert item["source"]["provenance"]["selector"] == {
        "root_id": "french_missions_5_normal"
    }
    _assert_projection(item, fixture, "single_root")


def test_recorded_task_selectors_keep_casus_and_trade_scopes_separate(tmp_path):
    fixture = _load_fixture()
    service, _source = _service(tmp_path, fixture)
    try:
        _result_casus, casus = _single_item(
            service,
            "recorded-task-casus",
            _query(
                root_id="french_missions_5_normal",
                task_id="fra_ducal_lands_avignon",
            ),
        )
        _result_trade, trade = _single_item(
            service,
            "recorded-task-trade",
            _query(
                root_id="french_missions_5_continuation_normal_1",
                task_id="fra_restore_signoria",
            ),
        )
    finally:
        service.close()

    _assert_projection(casus, fixture, "single_task_casus")
    _assert_projection(trade, fixture, "single_task_trade")
    assert len(_actual_occurrences(casus["fields"]["casus_belli"]["value"])) == 2
    assert len(_actual_occurrences(trade["fields"]["trade_modifiers"]["value"])) == 2
    assert _actual_occurrences(casus["fields"]["trade_modifiers"]["value"]) == []
    assert _actual_occurrences(trade["fields"]["casus_belli"]["value"]) == []


def test_recorded_discovery_is_query_only_and_has_no_fake_session(tmp_path):
    fixture = _load_fixture()
    service, source = _service(tmp_path, fixture)
    try:
        discovery = service.discover()
    finally:
        service.close()

    assert discovery["context"]["mode"] == "recorded"
    assert discovery["context"]["session_id"] is None
    assert discovery["context"]["game_day"] is None
    m04 = next(topic for topic in discovery["topics"] if topic["topic_id"] == "M04")
    assert m04["triggers"] == ["query"]
    assert discovery["event_types"] == []
    assert source.context()["session_id"] is None

