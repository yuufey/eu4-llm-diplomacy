"""G01 task targets preserve M05 rule, task-role, and static-map evidence."""
from __future__ import annotations

from copy import deepcopy

import pytest

from bridge.information.mission_analysis import MissionAnalysisSource
from bridge.information.model import InformationError
from bridge.information.province_interest_parameters import parameters_schema
from bridge.information.province_task_targets import ProvinceTaskTargetsSource
from bridge.tests import test_information_mission_chain_targets as chain_fixture


_CONFIG = "a" * 64
_FILE_HASH = "b" * 64
_ROOT = "C:/eu4"
_USER_DATA = "C:/eu4-user"


def _scope_source(filename: str) -> dict:
    return {
        "configuration_sha256": _CONFIG,
        "files": [{"relative": filename, "bytes": 42, "sha256": _FILE_HASH,
                   "source_kind": "base_game"}],
    }


class _ScopeIndex:
    def context(self):
        return {
            "status": "ready", "complete": True, "game_version": "1.37.4",
            "game_root": _ROOT, "user_data": _USER_DATA, "enabled_mods": [],
            "configuration_sha256": _CONFIG, "definitions_sha256": "c" * 64,
            "component_statuses": {}, "script_parser": {"status": "ready"},
            "reasons": [],
        }

    def lookup_scopes(self, names):
        rows = {
            "183": {"status": "known", "kind": "province_id", "name": "183",
                    "value": 183, "members": None,
                    "source": _scope_source("map/definition.csv")},
            "186": {"status": "known", "kind": "province_id", "name": "186",
                    "value": 186, "members": None,
                    "source": _scope_source("map/definition.csv")},
            "france_region": {"status": "known", "kind": "regions",
                              "name": "france_region", "value": "france_region",
                              "members": [200, 201],
                              "source": _scope_source("map/regions.txt")},
            "FRA": {"status": "known", "kind": "country_tag", "name": "FRA",
                    "value": "FRA", "members": None,
                    "source": _scope_source("common/country_tags/00_countries.txt")},
        }
        return {name: deepcopy(rows.get(name, {
            "status": "unknown", "name": name, "reason": "SCOPE_NOT_INDEXED",
        })) for name in names}


class _FakeAnalysis:
    def __init__(self, linked_field=None):
        self._context = {"status": "ready", "mode": "live", "observer": "FRA",
                         "game_version": "1.37.4", "session_id": "fake-session",
                         "game_date": 56556984}
        self.linked_field = deepcopy(linked_field)
        self.calls = []

    def context(self):
        return deepcopy(self._context)

    def catalog(self):
        return [{"topic_id": "M05", "triggers": ["query"],
                 "supported_versions": ["1.37.4"],
                 "supported_observers": ["FRA"], "supported_countries": ["FRA"]}]

    def read(self, query, context):
        self.calls.append((deepcopy(query), deepcopy(context)))
        return {"topic": "M05", "fields": {"linked_targets": deepcopy(self.linked_field)},
                "complete": False, "source": {"name": "FakeMissionAnalysisSource",
                    "status": "observed", "provenance": {"single_captured_state": True}}}


def _query(*, country="FRA", parameters=None, fields=None, object_value=None):
    return {
        "topic": "G01",
        "object": deepcopy(object_value or {"type": "country", "country": country}),
        "fields": list(fields or ["task_targets"]),
        "parameters": deepcopy(parameters if parameters is not None else {
            "root_id": "root_main", "task_id": "task_owned",
        }),
    }


def _static_scope(kind, name, members, filename):
    return {"kind": kind, "index_kind": kind, "name": name,
            "value": name, "members": members, "source": _scope_source(filename)}


def _rule(task_id, reference_kind, reference, *, static_scope=None, target_resolution=None):
    row = {
        "kind": "literal_reference",
        "semantics": "declared_static_condition_reference",
        "requiredness": "not_inferred",
        "evaluated": False,
        "scope_targets_resolved": False,
        "field_classifications": ["provinces"],
        "command_key": "owns",
        "assignment": "=",
        "literal_value": reference,
        "reference_kind": reference_kind,
        "root_id": "root_main",
        "task_id": task_id,
        "path": [0, 0],
        "path_text": "trigger[0].owns",
        "trigger_context_id": "ctx-owner" if task_id == "task_owned" else "ctx-core",
        "source": {"path": "missions/example.txt", "sha256": "d" * 64,
                   "line": 2, "end_line": 2},
    }
    if static_scope is not None:
        row["static_scope"] = deepcopy(static_scope)
    if target_resolution is not None:
        row["target_resolution"] = deepcopy(target_resolution)
    return row


def _linked_field(target_rules):
    tasks = [
        {"root_id": "root_main", "task_id": task_id,
         "source": {"path": "missions/example.txt", "sha256": "d" * 64},
         "context_ids": [context_id]}
        for task_id, context_id in (("task_owned", "ctx-owner"), ("task_core", "ctx-core"))
    ]
    contexts = [
        {"root_id": "root_main", "task_id": task_id, "context_id": context_id,
         "trigger_ast": {"key": "trigger", "kind": "block", "children": []},
         "trigger_ast_bytes": 52, "ast_semantics": "preserved_structural_condition; no evaluation",
         "source": {"path": "missions/example.txt", "sha256": "d" * 64},
         "trigger_source": {"path": "missions/example.txt", "line": 1}}
        for task_id, context_id in (("task_owned", "ctx-owner"), ("task_core", "ctx-core"))
    ]
    for envelope in target_rules.values():
        if isinstance(envelope, dict) and envelope.get("status") == "known" and isinstance(envelope.get("value"), dict):
            envelope["value"].setdefault("tasks", deepcopy(tasks))
            envelope["value"].setdefault("trigger_contexts", deepcopy(contexts))
    return {
        "status": "known", "partial": True, "complete": False,
        "value": {
            "selected": [{"root_id": "root_main", "task_id": "task_owned"}],
            "prerequisite": [],
            "follow_up": [{"root_id": "root_main", "task_id": "task_core"}],
            "supporting_prerequisite": [],
            "tasks": deepcopy(tasks),
            "trigger_contexts": deepcopy(contexts),
            "target_rules": target_rules,
            "unknowns": [{"code": "MISSION_CONDITIONS_NOT_EVALUATED"}],
            "evaluated": False,
            "complete": False,
        },
    }


def _synthetic_rules():
    province = _rule("task_owned", "province_id", "183",
                     static_scope=_static_scope("province", "183", [183], "map/definition.csv"))
    region = _rule("task_core", "region", "france_region",
                   static_scope=_static_scope("region", "france_region", [200, 201],
                                              "map/regions.txt"))
    unvalidated_number = _rule("task_owned", "province_id", "184")
    dynamic = _rule("task_owned", "dynamic_scope_symbol", "ROOT",
                    target_resolution={"status": "unknown",
                                       "reason": "DYNAMIC_SCOPE_SYMBOL_UNRESOLVED"})
    country = _rule("task_owned", "country_tag", "FRA",
                    static_scope=_static_scope("country_tag", "FRA", None,
                                               "common/country_tags/00_countries.txt"))
    target_rules = {name: {"status": "unknown", "reason": "NO_RULES", "complete": False}
                    for name in ("provinces", "regions", "countries", "ownership",
                                 "control", "cores", "subjects")}
    target_rules["provinces"] = {"status": "known", "complete": False,
                                  "value": {"rules": [province, unvalidated_number, dynamic]}}
    target_rules["regions"] = {"status": "known", "complete": False,
                                "value": {"rules": [region]}}
    target_rules["control"] = {"status": "known", "complete": False,
                               "value": {"rules": [country]}}
    return target_rules


def _real_source(*, with_scope=True):
    _chain, missions, primary, state, definitions = chain_fixture.setup_source()
    if with_scope:
        original_context = definitions.context

        def bound_context():
            result = original_context()
            result.update(game_root=_ROOT, user_data=_USER_DATA, enabled_mods=[])
            return result

        definitions.context = bound_context
        missions.scope_index = _ScopeIndex()
    analysis = MissionAnalysisSource(missions)
    return ProvinceTaskTargetsSource(analysis), analysis, missions, primary, state, definitions


def test_real_m05_chain_associates_explicit_and_region_members_and_preserves_roles():
    source, analysis, _missions, primary, state, _definitions = _real_source()
    original_read = analysis.read
    read_requests = []

    def record_request(query, context):
        read_requests.append(deepcopy(query))
        return original_read(query, context)

    analysis.read = record_request
    result = source.read(_query(), primary.context())

    assert state.calls == 1
    assert len(read_requests) == 1
    assert read_requests[0]["topic"] == "M05"
    assert read_requests[0]["fields"] == ["linked_targets"]
    assert read_requests[0]["parameters"] == _query()["parameters"]
    field = result["fields"]["task_targets"]
    assert field["status"] == "known"
    assert field["complete"] is False and field["partial"] is True
    assert field["runtime_conditions_evaluated"] is False
    assert field["full_target_set_resolved"] is False
    assert field["actual_target_set"] == "unknown"
    value = field["value"]
    assert value["runtime_conditions_evaluated"] is False
    assert value["full_target_set_resolved"] is False
    assert value["actual_target_set"] == "unknown"
    assert value["selected"] == [{"root_id": "root_main", "task_id": "task_owned"}]
    assert {row["task_id"] for row in value["follow_up"]} == {"task_core", "task_region"}
    assert {(row["task_id"], row["mission_role"], row["target_field"], tuple(row["province_ids"]))
            for row in value["rules"]} >= {
                ("task_owned", "selected", "provinces", (183,)),
                ("task_region", "follow_up", "regions", (200, 201)),
            }
    direct = next(row for row in value["rules"] if row["task_id"] == "task_owned"
                  and row["target_field"] == "provinces")
    assert direct["rule"]["source"]["path"] == "missions/example.txt"
    assert direct["static_scope"]["source"]["configuration_sha256"] == _CONFIG
    assert direct["static_scope"]["source"]["files"][0]["sha256"] == _FILE_HASH
    trigger_context = next(context for context in value["trigger_contexts"]
                           if context["root_id"] == direct["root_id"]
                           and context["task_id"] == direct["task_id"]
                           and context["context_id"] == direct["rule"]["trigger_context_id"])
    assert trigger_context["trigger_ast"]["key"] == "trigger"
    assert result["source"]["provenance"]["mission_analysis"]["provenance"]["single_captured_state"] is True


def test_unvalidated_numeric_symbolic_and_country_rules_never_expand_to_provinces():
    analysis = _FakeAnalysis(_linked_field(_synthetic_rules()))
    source = ProvinceTaskTargetsSource(analysis)
    result = source.read(_query())
    field = result["fields"]["task_targets"]

    assert field["status"] == "known"  # the separate province and region pins are validated
    value = field["value"]
    assert [row["province_ids"] for row in value["rules"]] == [[183], [200, 201]]
    unresolved = value["unresolved_rules"]
    assert any(row["rule"].get("literal_value") == "184"
               and row["reason"] == "STATIC_SCOPE_MEMBERSHIP_UNAVAILABLE" for row in unresolved)
    assert any(row["rule"].get("literal_value") == "ROOT"
               and row["reason"] == "DYNAMIC_SCOPE_SYMBOL_UNRESOLVED" for row in unresolved)
    assert any(row["rule"].get("literal_value") == "FRA"
               and row["reason"] == "STATIC_SCOPE_KIND_NOT_PROVINCE_COMPATIBLE" for row in unresolved)
    assert all("province_ids" not in row for row in unresolved)


def test_no_validated_members_is_unknown_not_a_known_empty_target_set():
    source, _analysis, _missions, primary, state, _definitions = _real_source(with_scope=False)
    result = source.read(_query(), primary.context())
    field = result["fields"]["task_targets"]

    assert state.calls == 1
    assert field["status"] == "unknown"
    assert field["reason"] == "NO_VALIDATED_STATIC_PROVINCE_ASSOCIATIONS"
    assert "value" not in field
    assert any(row.get("rule", {}).get("literal_value") == 183
               for row in field["unresolved_rules"])


@pytest.mark.parametrize("failure", ["missing_loaded_membership", "definition_drift"])
def test_m05_membership_and_definition_guards_remain_authoritative(failure):
    source, _analysis, _missions, primary, state, definitions = _real_source()
    if failure == "missing_loaded_membership":
        state.sample.pop("loaded_tasks")
    else:
        definitions.mutate_after_first_context = True

    result = source.read(_query(), primary.context())
    field = result["fields"]["task_targets"]
    assert state.calls == 1
    assert field["status"] == "unknown"
    assert field.get("reason")
    assert "value" not in field


@pytest.mark.parametrize("status,reason", [
    ("unknown", "M05_TASK_NOT_VERIFIED"),
    ("unavailable", "MISSION_CONTEXT_UNAVAILABLE"),
])
def test_m05_unknown_and_unavailable_statuses_and_reasons_are_passed_through(status, reason):
    analysis = _FakeAnalysis({"status": status, "reason": reason, "complete": False})
    source = ProvinceTaskTargetsSource(analysis)
    result = source.read(_query())

    assert result["fields"]["task_targets"]["status"] == status
    assert result["fields"]["task_targets"]["reason"] == reason
    assert analysis.calls[0][0]["fields"] == ["linked_targets"]


def test_province_object_is_not_applicable_without_calling_m05():
    analysis = _FakeAnalysis(_linked_field(_synthetic_rules()))
    source = ProvinceTaskTargetsSource(analysis)
    result = source.read(_query(object_value={"type": "province", "province_id": 183}))

    assert result["fields"]["task_targets"]["status"] == "not_applicable"
    assert result["fields"]["task_targets"]["reason"] == "TASK_TARGETS_REQUIRES_COUNTRY_OBJECT"
    assert analysis.calls == []


def test_selector_pair_country_scope_and_owned_field_validation_precede_capture():
    source, _analysis, _missions, primary, state, _definitions = _real_source()
    context = primary.context()
    for parameters in ({}, {"root_id": "root_main"}, {"task_id": "task_owned"},
                       {"root_id": "root/main", "task_id": "task_owned"}):
        with pytest.raises(InformationError):
            source.read(_query(parameters=parameters), context)
    with pytest.raises(InformationError) as mismatch:
        source.read(_query(country="ENG"), context)
    assert mismatch.value.code == "observer_scope_mismatch"
    with pytest.raises(InformationError):
        source.validate_query(_query(fields=["cores"], parameters={
            "root_id": "root_main", "task_id": "task_owned"}), context)
    with pytest.raises(InformationError):
        source.validate_query(_query(object_value={"type": "province", "province_id": 0},
                                     parameters={"root_id": "root_main", "task_id": "task_owned"}), context)
    assert state.calls == 0


def test_catalog_uses_shared_optional_schema_and_only_owns_task_targets():
    source, _analysis, _missions, _primary, _state, _definitions = _real_source()
    topic = source.catalog()[0]
    assert set(topic["fields"]) == {"task_targets"}
    assert topic["parameters"] == parameters_schema()
    assert topic["parameters"].get("required", []) == []
    assert topic["context_scope"] == "country_scope"
    assert topic["observer_roles"] == ["country"]
    assert topic["object_types"] == ["country"]
    assert topic["fields"]["task_targets"]["coverage"] == "partial"
    assert topic["fields"]["task_targets"]["complete"] is False
