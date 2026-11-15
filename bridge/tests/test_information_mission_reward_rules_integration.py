"""M04 literal reward-rule projection and source-boundary tests.

The projector is deliberately supplied as a seam in these tests.  This keeps
the tests independent of the native/source implementation while asserting the
adapter contract: selected loaded definitions are passed through, malformed or
stale inputs remain explicit gaps, and the existing raw ``rewards`` field is
kept separate from the new partial projections.
"""

from copy import deepcopy

import pytest

from bridge.information import InformationService
from bridge.information.catalog import list_topics
from bridge.information.composite import CompositeSource
from bridge.information.missions import MissionInformationSource
from bridge.information.model import InformationError


RULE_FIELDS = ("claims", "casus_belli", "trade_modifiers")


def _ast_node(key, line, *, value=None, children=()):
    """Small structural node accepted by the bounded reward projector."""
    children = list(children)
    return {
        "key": key,
        "line": line,
        "end_line": line,
        "value": value,
        "children": children,
        "ast_semantics": "structural",
        "kind": "block" if children else "scalar",
        "assignment": "=" if value is not None or children else None,
        "raw_key": key,
        "raw_value": value if value is not None else "{" if children else None,
    }


class _State:
    event_types = ()

    def __init__(self, *, mode="live"):
        self.current = {
            "status": "ready",
            "mode": mode,
            "observer": "FRA",
            "game_version": "1.37.4",
            "session_id": "mission-session" if mode == "live" else None,
            "game_date": 24 if mode == "live" else "1455.11.13",
            "game_day": 24 if mode == "live" else None,
            "world_id": "world-a" if mode == "live" else None,
        }
        self.sample = {
            "complete": True,
            "country": "FRA",
            "mode": mode,
            "session_id": self.current["session_id"],
            "game_date": self.current["game_date"],
            "state_kind": "captured_country_mission_slots",
            "mission_slots": [{"slot": 1, "roots": ["loaded"]}],
            "loaded_tasks": {"status": "known", "roots": [
                {"root_id": "loaded", "task_ids": ["first", "second"]},
            ]},
            "completed_missions": {"status": "known", "task_ids": ["first"]},
            "provenance": {
                "capture": "fake-native",
                "guard": {"status": "observed", "sha256": "state-sha"},
            },
        }

    def context(self):
        return deepcopy(self.current)

    def catalog(self):
        return list_topics()

    def read(self, query, context):
        raise AssertionError("M04 must route to MissionInformationSource")

    def capture(self, country):
        assert country == "FRA"
        return deepcopy(self.sample)

    def poll_events(self, context, cursor):
        return {"events": [], "cursor": deepcopy(cursor or {}), "complete": True, "gaps": []}


class _Definitions:
    def __init__(self):
        self.ready = True
        self.revision = "definitions-1"
        self.flip_after_roots = False
        self.values = {
            "loaded": {
                "root_id": "loaded",
                "slot": 1,
                "potential": {"tag": "FRA"},
                "potential_on_load": {"has_dlc": "Domination"},
                "source": {"path": "missions/fake.txt", "sha256": "a" * 64},
                "tasks": [
                    {"task_id": "first", "required_missions": [],
                     "trigger": {"stability": 1},
                     "effect": _ast_node("effect", 20, children=(
                         _ast_node("add_claim", 20, value="1"),
                         _ast_node("add_casus_belli", 21, value="cb_claim"),
                     )),
                     "source": {"path": "missions/fake.txt", "sha256": "a" * 64, "line": 20}},
                    {"task_id": "second", "required_missions": ["first"],
                     "trigger": {"owns": 1},
                     "effect": _ast_node("effect", 30, children=(
                         _ast_node("if", 30, children=(
                             _ast_node("limit", 31, children=(
                                 _ast_node("tag", 31, value="FRA"),
                             )),
                             _ast_node("add_trade_modifier", 32, value="trade_bonus"),
                         )),
                     )),
                     "source": {"path": "missions/fake.txt", "sha256": "a" * 64, "line": 30}},
                ],
            },
        }

    def context(self):
        return {
            "status": "ready" if self.ready else "unready",
            "game_version": "1.37.4",
            "configuration_sha256": "config-sha",
            "definitions_sha256": self.revision,
            "reasons": [],
        }

    def root(self, root_id):
        if root_id not in self.values:
            raise KeyError(root_id)
        return deepcopy(self.values[root_id])

    def roots(self, ids):
        result = [self.root(root_id) for root_id in ids]
        if self.flip_after_roots:
            self.revision = "definitions-2"
        return result


def _query(fields, **parameters):
    return {
        "topic": "M04",
        "object": {"type": "country", "country": "FRA"},
        "fields": list(fields),
        "parameters": parameters,
    }


def _adapter(*, mode="live", scheduling=True):
    state = _State(mode=mode)
    definitions = _Definitions()
    adapter = MissionInformationSource(state, definitions, state.capture, scheduling=scheduling)
    return state, definitions, adapter


def _install_projector(monkeypatch, calls, *, failing=()):
    def project(tasks, field):
        calls.append((field, [(task["root_id"], task["task_id"]) for task in tasks]))
        if field in failing:
            raise InformationError("BAD_REWARD_RULES", f"malformed {field}")
        return {
            "status": "known",
            "value": {
                "declared_literal_effect_rules": True,
                "runtime_conditions_evaluated": False,
                "actual_reward_status": "unknown",
                "field": field,
                "tasks": [{"root_id": task["root_id"], "task_id": task["task_id"]}
                          for task in tasks],
            },
            "complete": False,
            "provenance": {"projector": "fake", "definitions_scope": "selected"},
        }

    monkeypatch.setattr("bridge.information.missions._project_reward_rules", project)


def test_catalog_advertises_three_partial_literal_rule_fields():
    _state, _definitions, adapter = _adapter()
    topic = next(entry for entry in adapter.catalog() if entry["topic_id"] == "M04")

    assert topic["status"] == "available"
    assert topic["triggers"] == ["query", "periodic", "change"]
    assert set(topic["fields"]) == {"rewards", *RULE_FIELDS, "duration", "unlocks"}
    for field in RULE_FIELDS:
        metadata = topic["fields"][field]
        assert metadata["coverage"] == "partial"
        assert metadata["declared_literal_effect_rules"] is True
        assert metadata["runtime_conditions_evaluated"] is False
        assert metadata["actual_reward_status"] == "unknown"

    duration = topic["fields"]["duration"]
    assert duration["coverage"] == "partial"
    assert duration["declared_literal_effect_rules"] is True
    assert duration["runtime_conditions_evaluated"] is False
    assert duration["actual_reward_status"] == "unknown"
    assert duration["actual_expiry_evaluated"] is False
    assert duration["complete"] is False
    assert duration["period"] == "static_rules"
    assert duration["units"] == "per_term"
    assert duration["value_origin"] == "declared_effect_timing_parameters"

    # The configured source adds a partial unlock-declaration view;
    # the unconfigured global catalog still describes it as planned.
    assert topic["fields"]["unlocks"]["coverage"] == "partial"
    base_m04 = next(entry for entry in list_topics() if entry["topic_id"] == "M04")
    assert base_m04["fields"]["unlocks"]["coverage"] == "planned"


def test_duration_query_keeps_missing_terms_unknown_and_preserves_raw_rewards(tmp_path):
    state, _definitions, adapter = _adapter()
    service = InformationService(CompositeSource(state, [adapter]), tmp_path / "m04-duration.db")
    try:
        result = service.query(
            "duration-m04",
            queries=[_query(("rewards", "duration"))],
        )
    finally:
        service.close()

    assert result["status"] == "partial"
    item = result["items"][0]
    assert item["complete"] is False
    rewards = item["fields"]["rewards"]
    assert rewards["status"] == "known"
    assert rewards["value"]["evaluated"] is False
    assert rewards["value"]["applied"] == "unknown"

    duration = item["fields"]["duration"]
    assert duration["schema"] == "information.mission_reward_duration.v1"
    assert duration["status"] == "unknown"
    assert duration["reason"] == "NO_KNOWN_DURATION_TERM"
    assert duration["complete"] is False
    assert "value" not in duration
    assert duration["provenance"]["mode"] == "static_rules"
    assert duration["provenance"]["runtime_conditions_evaluated"] is False
    assert duration["provenance"]["actual_reward_status"] == "unknown"

    evidence = duration["evidence"]
    assert evidence["kind"] == "bounded_static_duration_rule_evidence"
    assert evidence["complete"] is False
    by_command = {row["command"]: row for row in evidence["rules"]}
    assert set(by_command) == {"add_claim", "add_casus_belli", "add_trade_modifier"}
    assert by_command["add_claim"]["terms"][0]["reason"] == "CWT_DURATION_NOT_DECLARED"
    assert by_command["add_casus_belli"]["terms"][0]["reason"] == "PARAMETER_MISSING"
    trade_rule = by_command["add_trade_modifier"]
    assert trade_rule["terms"][0]["reason"] == "PARAMETER_MISSING"
    assert trade_rule["context_status"] == "unresolved"


def test_mixed_query_routes_and_preserves_raw_rewards(monkeypatch, tmp_path):
    state, definitions, adapter = _adapter()
    calls = []
    _install_projector(monkeypatch, calls)
    service = InformationService(CompositeSource(state, [adapter]), tmp_path / "m04.db")
    try:
        result = service.query("mixed-m04", queries=[_query(("rewards", *RULE_FIELDS))])
    finally:
        service.close()

    item = result["items"][0]
    assert result["status"] == "partial"
    assert item["complete"] is False
    assert item["fields"]["rewards"]["status"] == "known"
    assert item["fields"]["rewards"]["value"]["evaluated"] is False
    assert item["fields"]["rewards"]["value"]["applied"] == "unknown"
    assert item["fields"]["rewards"]["value"]["tasks"][0]["effect"]["children"][0]["key"] == "add_claim"
    for field in RULE_FIELDS:
        projected = item["fields"][field]
        assert projected["status"] == "known"
        assert projected["complete"] is False
        assert projected["value"]["runtime_conditions_evaluated"] is False
    projection = item["source"]["provenance"]["reward_rule_projection"]
    assert projection["selected_captured_roots_only"] is True
    assert projection["task_membership_source"] == "captured_loaded_task_objects"
    assert projection["loaded_task_membership_verified"] is True
    assert projection["definition_rules_previously_loaded_verified"] is False
    assert calls == [
        ("claims", [("loaded", "first"), ("loaded", "second")]),
        ("casus_belli", [("loaded", "first"), ("loaded", "second")]),
        ("trade_modifiers", [("loaded", "first"), ("loaded", "second")]),
    ]


def test_root_and_task_selectors_limit_projection_and_bad_fields_are_rejected(monkeypatch):
    _state, _definitions, adapter = _adapter()
    calls = []
    _install_projector(monkeypatch, calls)
    context = adapter.context()

    selected = adapter.read(_query(("claims",), root_id="loaded", task_id="second"), context)
    assert selected["fields"]["claims"]["status"] == "known"
    assert calls == [("claims", [("loaded", "second")])]

    with pytest.raises(InformationError) as error:
        adapter.validate_query(_query(("claims", "unlock_conditions")), context)
    assert error.value.code == "invalid_fields"

    calls.clear()
    state = _State()
    state.sample["mission_slots"][0]["roots"].append("other")
    state.sample["loaded_tasks"]["roots"].append({"root_id": "other", "task_ids": []})
    definitions = _Definitions()
    definitions.values["other"] = {
        "root_id": "other", "slot": 1, "tasks": [{"task_id": "not_selected", "effect": {}}],
    }
    adapter = MissionInformationSource(state, definitions, state.capture)
    result = adapter.read(_query(("claims",), root_id="other"), adapter.context())
    assert result["fields"]["claims"] == {"status": "unknown", "reason": "NO_SELECTED_MISSION_TASKS"}
    assert calls == []


def test_unavailable_definitions_do_not_call_projector(monkeypatch):
    _state, definitions, adapter = _adapter()
    definitions.ready = False
    calls = []
    _install_projector(monkeypatch, calls)

    result = adapter.read(_query(("claims", "rewards")), adapter.context())
    assert result["fields"]["claims"]["status"] == "unavailable"
    assert result["fields"]["claims"]["reason"] == "MISSION_DEFINITIONS_UNAVAILABLE"
    assert result["fields"]["rewards"]["status"] == "unavailable"
    assert calls == []


def test_stale_definitions_invalidates_projection_after_capture(monkeypatch):
    _state, definitions, adapter = _adapter()
    definitions.flip_after_roots = True
    calls = []
    _install_projector(monkeypatch, calls)

    result = adapter.read(_query(("claims", "rewards")), adapter.context())
    assert calls == [("claims", [("loaded", "first"), ("loaded", "second")])]
    assert result["fields"]["claims"] == {
        "status": "stale", "reason": "MISSION_DEFINITIONS_CHANGED_DURING_COLLECTION",
    }
    assert result["fields"]["rewards"]["status"] == "stale"
    assert result["source"]["provenance"]["definitions"]["definitions_sha256"] == "definitions-1"
    assert result["source"]["provenance"]["definitions_after"]["definitions_sha256"] == "definitions-2"
    assert result["source"]["provenance"]["selector"] == {}


def test_bad_one_field_or_task_does_not_erase_siblings(monkeypatch):
    _state, _definitions, adapter = _adapter()
    calls = []
    def project(tasks, field):
        calls.append((field, [(task["root_id"], task["task_id"]) for task in tasks]))
        if field == "casus_belli":
            return {"status": "unavailable", "reason": "BAD_REWARD_RULES"}
        return {
            "status": "known", "value": {"field": field}, "complete": False,
        }
    monkeypatch.setattr("bridge.information.missions._project_reward_rules", project)
    result = adapter.read(_query(("claims", "casus_belli", "trade_modifiers", "rewards")), adapter.context())
    fields = result["fields"]
    assert fields["claims"]["status"] == "known"
    assert fields["trade_modifiers"]["status"] == "known"
    assert fields["casus_belli"] == {"status": "unavailable", "reason": "BAD_REWARD_RULES"}
    assert fields["rewards"]["status"] == "known"

    calls.clear()
    def per_task_project(tasks, field):
        calls.append(field)
        return {
            "status": "known",
            "value": {"tasks": [
                {"task_id": task["task_id"],
                 "status": "unknown" if task["task_id"] == "second" else "known",
                 "reason": "MALFORMED_EFFECT" if task["task_id"] == "second" else None}
                for task in tasks],
            },
            "complete": False,
        }
    monkeypatch.setattr("bridge.information.missions._project_reward_rules", per_task_project)
    result = adapter.read(_query(("claims", "rewards")), adapter.context())
    entries = result["fields"]["claims"]["value"]["tasks"]
    assert [entry["status"] for entry in entries] == ["known", "unknown"]
    assert result["fields"]["rewards"]["status"] == "known"
    assert calls == ["claims"]


def test_unverified_loaded_membership_does_not_project_rules(monkeypatch):
    state, _definitions, adapter = _adapter()
    state.sample["loaded_tasks"] = {"status": "unknown", "reason": "LOADED_TASKS_NOT_CAPTURED"}
    calls = []
    _install_projector(monkeypatch, calls)

    result = adapter.read(_query(("claims", "rewards")), adapter.context())
    assert result["fields"]["claims"] == {"status": "unknown", "reason": "LOADED_TASKS_NOT_CAPTURED"}
    assert calls == []


def test_recorded_source_is_query_only_and_keeps_partial_projection(monkeypatch):
    state, _definitions, adapter = _adapter(mode="recorded", scheduling=False)
    # Archived captures expose captured roots but no runtime loaded-task
    # vector; current definitions are therefore the explicit rule scope.
    state.sample.pop("loaded_tasks")
    calls = []
    _install_projector(monkeypatch, calls)
    topic = next(entry for entry in adapter.catalog() if entry["topic_id"] == "M04")
    assert topic["triggers"] == ["query"]

    result = adapter.read(_query(("claims",)), adapter.context())
    assert result["source"]["mode"] == "recorded"
    assert result["fields"]["claims"]["status"] == "known"
    assert result["fields"]["claims"]["complete"] is False
    projection = result["source"]["provenance"]["reward_rule_projection"]
    assert projection["selected_captured_roots_only"] is True
    assert projection["task_membership_source"] == "current_definitions_for_captured_roots"
    assert projection["loaded_task_membership_verified"] is False
    assert projection["definition_rules_previously_loaded_verified"] is False
    assert calls == [("claims", [("loaded", "first"), ("loaded", "second")])]


def test_projector_envelope_is_validated_at_module_boundary(monkeypatch):
    """Malformed source output is quarantined without affecting raw M04."""
    import sys
    import types

    fake_module = types.ModuleType("bridge.information.mission_reward_rules")
    fake_module.project_reward_rules = lambda tasks, field: {
        "status": "known", "value": {"field": field}, "complete": True,
    }
    monkeypatch.setitem(sys.modules, "bridge.information.mission_reward_rules", fake_module)
    state, _definitions, adapter = _adapter()
    result = adapter.read(_query(("claims", "rewards")), adapter.context())
    assert result["fields"]["claims"] == {
        "status": "unavailable", "reason": "MISSION_REWARD_RULES_INVALID_RESULT",
    }
    assert result["fields"]["rewards"]["status"] == "known"


def test_real_projector_projects_literal_occurrences_and_isolates_bad_task_ast():
    state, definitions, adapter = _adapter()
    result = adapter.read(_query(RULE_FIELDS), adapter.context())
    for field in RULE_FIELDS:
        value = result["fields"][field]
        assert value["status"] == "known"
        assert value["complete"] is False
        assert value["value"]["semantics"] == "declared_literal_effect_rules"
        assert value["value"]["evaluated"] is False
        assert value["value"]["task_count"] == 2

    # A malformed second effect is represented as one unknown task in the
    # partial envelope; the first task and the raw rewards field survive.
    definitions.values["loaded"]["tasks"][1]["effect"] = {"broken": True}
    result = adapter.read(_query(("claims", "rewards")), state.context())
    claims = result["fields"]["claims"]
    assert claims["status"] == "known" and claims["complete"] is False
    assert claims["value"]["known_task_count"] == 1
    assert claims["value"]["unknown_task_count"] == 1
    assert claims["value"]["rules"][1]["status"] == "unknown"
    assert claims["value"]["rules"][1]["reason"]["code"] == "INVALID_IDENTIFIER"
    assert result["fields"]["rewards"]["status"] == "known"


def test_real_projector_excludes_limit_commands_but_keeps_effect_commands():
    state, definitions, adapter = _adapter()
    definitions.values["loaded"]["tasks"][0]["effect"] = _ast_node(
        "effect", 40, children=(
            _ast_node("if", 40, children=(
                _ast_node("limit", 41, children=(
                    _ast_node("add_claim", 41, value="must-not-be-counted"),
                )),
                _ast_node("add_claim", 42, value="effect-claim"),
            )),
        ),
    )
    result = adapter.read(_query(("claims",)), state.context())
    value = result["fields"]["claims"]["value"]
    first = value["rules"][0]
    assert first["status"] == "known"
    assert len(first["rules"]) == 1
    assert first["rules"][0]["raw_node"]["value"] == "effect-claim"
    assert [entry["key"] for entry in first["context_table"]] == ["if", "limit"]
    assert [entry["key"] for entry in first["rules"][0]["condition_context"]] == ["if", "limit"]

