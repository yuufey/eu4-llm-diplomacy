"""Mission source integration tests for bound static scope definitions."""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest

from bridge.information.model import InformationError
from bridge.tests.test_information_mission_targets_source import (
    block, make_source, query, scalar, target_rows,
)


GAME_ROOT = r"C:\EU4"
USER_DATA = r"C:\EU4User"
MODS = [
    {"descriptor": r"C:\EU4User\mod\a.mod", "descriptor_sha256": "a" * 64,
     "root": r"C:\EU4User\mod\a"},
    {"descriptor": r"C:\EU4User\mod\b.mod", "descriptor_sha256": "b" * 64,
     "root": r"C:\EU4User\mod\b"},
]
COMPONENTS = (
    "province_ids", "areas", "regions", "superregions", "continents",
    "province_groups", "country_tags",
)


def _configure_definitions(definitions, *, game_root=GAME_ROOT, user_data=USER_DATA,
                           enabled_mods=MODS):
    original = definitions.context

    def context():
        value = original()
        value.update(game_root=game_root, user_data=user_data,
                     enabled_mods=deepcopy(enabled_mods))
        return value

    definitions.context = context


def _source_pin(relative: str) -> dict:
    return {
        "files": [{"relative": relative, "bytes": 32, "sha256": "c" * 64,
                   "source_kind": "base_game", "source": "base_game"}],
        "configuration_sha256": "config-v1",
    }


class FakeScopeIndex:
    def __init__(self, *, game_root=GAME_ROOT, user_data=USER_DATA, game_version="1.37.4",
                 enabled_mods=MODS, configuration_sha256="config-v1",
                 definitions_sha256="definitions-v1", unavailable_components=(),
                 change_context_at=None):
        self.game_root = game_root
        self.user_data = user_data
        self.game_version = game_version
        self.enabled_mods = deepcopy(enabled_mods)
        self.configuration_sha256 = configuration_sha256
        self.definitions_sha256 = definitions_sha256
        self.unavailable_components = set(unavailable_components)
        self.change_context_at = change_context_at
        self.context_calls = 0
        self.lookup_calls = 0
        self.lookup_batches = []

    def context(self):
        self.context_calls += 1
        configuration_sha256 = self.configuration_sha256
        definitions_sha256 = self.definitions_sha256
        if self.change_context_at is not None and self.context_calls >= self.change_context_at:
            configuration_sha256 = "config-v2"
            definitions_sha256 = "definitions-v2"
        components = {
            name: {"status": "unavailable" if name in self.unavailable_components else "ready",
                   "complete": name not in self.unavailable_components,
                   "reasons": ([{"code": "TEST_COMPONENT_UNAVAILABLE"}]
                               if name in self.unavailable_components else [])}
            for name in COMPONENTS
        }
        return {
            "schema": "information.mission_scope_index_context.v1",
            "status": "ready", "complete": not self.unavailable_components,
            "mode": "static", "context_scope": "static_rules",
            "game_root": self.game_root, "user_data": self.user_data,
            "game_version": self.game_version,
            "configuration_sha256": configuration_sha256,
            "definitions_sha256": definitions_sha256,
            "enabled_mods": deepcopy(self.enabled_mods),
            "component_statuses": components,
            "scope_count_by_kind": {"province_id": 3, "regions": 1},
            "reasons": [],
        }

    def lookup_scopes(self, names):
        self.lookup_calls += 1
        names = list(names)
        self.lookup_batches.append(names)
        result = {}
        for name in names:
            if name == "france_region":
                if "regions" in self.unavailable_components:
                    result[name] = {"status": "unknown", "name": name, "kind": "regions",
                                    "reason": "SCOPE_COMPONENT_UNAVAILABLE"}
                else:
                    result[name] = {"status": "known", "kind": "regions", "name": name,
                                    "value": name, "members": [184],
                                    "source": _source_pin("map/region.txt")}
            elif name in {"183", "184", "186"}:
                province_id = int(name)
                result[name] = {"status": "known", "kind": "province_id", "name": name,
                                "value": province_id,
                                "source": _source_pin("map/definition.csv")}
            elif name == "FRA":
                result[name] = {"status": "known", "kind": "country_tag", "name": name,
                                "value": name,
                                "source": _source_pin("common/country_tags/00_countries.txt")}
            else:
                result[name] = {"status": "unknown", "name": name,
                                "reason": "SCOPE_NOT_FOUND"}
        return result


def _attach_scope_head(definitions, *, task_id="task_owned"):
    for root in definitions.values.values():
        for item in root["tasks"]:
            if item["task_id"] == task_id:
                item["trigger"]["children"].append(
                    block("france_region", [], 4))
                item["trigger"]["children"].append(
                    block("183", [], 5))
                item["trigger"]["end_line"] = 5
                item["source"]["end_line"] = 5
                return
    raise AssertionError(f"fixture task not found: {task_id}")


def _replace_trigger(definitions, task_id, children):
    for root in definitions.values.values():
        for item in root["tasks"]:
            if item["task_id"] == task_id:
                item["trigger"] = block("trigger", list(children), 1)
                item["source"]["end_line"] = item["trigger"]["end_line"]
                return
    raise AssertionError(f"fixture task not found: {task_id}")


def _scope_source(*, mismatch=None, unavailable_components=(), change_context_at=None):
    source, state, definitions = make_source()
    _attach_scope_head(definitions)
    _configure_definitions(definitions)
    index_kwargs = {}
    mods = deepcopy(MODS)
    if mismatch == "game_root":
        index_kwargs["game_root"] = r"C:\EU4-other"
    elif mismatch == "user_data":
        index_kwargs["user_data"] = r"C:\EU4User-other"
    elif mismatch == "game_version":
        index_kwargs["game_version"] = "1.37.3"
    elif mismatch == "mod_descriptor":
        mods[0]["descriptor"] = r"C:\EU4User\mod\a-other.mod"
        index_kwargs["enabled_mods"] = mods
    elif mismatch == "mod_descriptor_sha":
        mods[0]["descriptor_sha256"] = "d" * 64
        index_kwargs["enabled_mods"] = mods
    elif mismatch == "mod_root":
        mods[0]["root"] = r"C:\EU4User\mod\a-other"
        index_kwargs["enabled_mods"] = mods
    elif mismatch == "mod_order":
        index_kwargs["enabled_mods"] = list(reversed(mods))
    index = FakeScopeIndex(unavailable_components=unavailable_components,
                           change_context_at=change_context_at, **index_kwargs)
    source.scope_index = index
    return source, state, definitions, index


def test_source_binds_matching_scope_index_and_prepares_once_for_requested_fields():
    source, state, _definitions, index = _scope_source()
    result = source.read(query("M03", ["provinces", "regions", "countries", "ownership"],
                              task_id="task_owned"), state.context())

    assert state.calls == 1
    assert index.lookup_calls == 1
    assert result["source"]["provenance"]["scope_definitions"]["configuration_binding_verified"] is True
    assert result["source"]["provenance"]["scope_definitions_after"]["configuration_binding_verified"] is True
    province_rules = target_rows(result["fields"]["provinces"])
    literal_rules = [row for row in province_rules if row["kind"] == "literal_reference"]
    scope_heads = [row for row in province_rules if row["kind"] == "scope_head_reference"]
    assert [(row["command_key"], row["literal_value"]) for row in literal_rules] == [("owns", 183)]
    assert len(scope_heads) == 1
    assert scope_heads[0]["command_key"] == "183"
    assert scope_heads[0]["literal_value"] == "183"
    assert scope_heads[0]["reference_kind"] == "province_id"
    assert all(isinstance(row.get("static_scope"), dict) for row in province_rules)
    region_rules = target_rows(result["fields"]["regions"])
    head = next(row for row in region_rules if row["kind"] == "scope_head_reference")
    assert head["static_scope"]["name"] == "france_region"
    assert head["static_scope"]["members"] == [184]
    assert result["fields"]["countries"]["status"] == "known"
    assert result["fields"]["ownership"]["status"] == "known"


@pytest.mark.parametrize("mismatch", [
    "game_root", "user_data", "game_version", "mod_descriptor",
    "mod_descriptor_sha", "mod_root", "mod_order",
])
def test_scope_binding_mismatch_withholds_map_extensions_but_keeps_literals(mismatch):
    source, state, _definitions, index = _scope_source(mismatch=mismatch)
    result = source.read(query("M03", ["provinces", "regions"], task_id="task_owned"),
                         state.context())

    assert result["source"]["provenance"]["scope_definitions"]["configuration_binding_verified"] is False
    assert index.lookup_calls == 0
    province_rules = target_rows(result["fields"]["provinces"])
    assert [(row["command_key"], row["literal_value"]) for row in province_rules] == [("owns", 183)]
    assert all("static_scope" not in row for row in province_rules)
    assert all(row["kind"] != "scope_head_reference" for row in province_rules)
    assert result["fields"]["regions"]["status"] == "unknown"
    assert "value" not in result["fields"]["regions"]


def test_unavailable_map_component_does_not_create_scope_head_value():
    source, state, _definitions, index = _scope_source(unavailable_components=("regions",))
    result = source.read(query("M03", ["provinces", "regions"], task_id="task_owned"),
                         state.context())

    assert result["source"]["provenance"]["scope_definitions"]["configuration_binding_verified"] is True
    assert index.lookup_calls == 1
    province_rules = target_rows(result["fields"]["provinces"])
    assert [(row["kind"], row["literal_value"]) for row in province_rules] == [
        ("literal_reference", 183), ("scope_head_reference", "183"),
    ]
    regions = result["fields"]["regions"]
    assert regions["status"] == "unknown"
    assert "value" not in regions
    assert {gap["reason"] for gap in regions["gaps"]} == {"SCOPE_COMPONENT_UNAVAILABLE"}


def test_scope_context_change_withdraws_only_extensions_and_retains_v1_literals():
    source, state, _definitions, index = _scope_source(change_context_at=3)
    result = source.read(query("M03", ["provinces", "regions"], task_id="task_owned"),
                         state.context())

    assert index.lookup_calls == 1
    assert result["source"]["provenance"]["static_scope_extensions_withdrawn"] == (
        "MISSION_SCOPE_INPUT_CHANGED_DURING_COLLECTION")
    province_rules = target_rows(result["fields"]["provinces"])
    assert [(row["command_key"], row["literal_value"]) for row in province_rules] == [("owns", 183)]
    assert all("static_scope" not in row for row in province_rules)
    assert all(row["kind"] != "scope_head_reference" for row in province_rules)
    assert result["fields"]["regions"]["status"] == "unknown"
    assert "value" not in result["fields"]["regions"]


def test_root_symbol_stays_unresolved_instead_of_becoming_observer_tag():
    source, state, definitions, index = _scope_source()
    _replace_trigger(definitions, "task_owned", [scalar("owns", "ROOT", 2)])
    result = source.read(query("M03", ["ownership"], task_id="task_owned"), state.context())

    assert index.lookup_calls == 1
    rule = target_rows(result["fields"]["ownership"])[0]
    assert rule["kind"] == "symbolic_condition_reference"
    assert rule["symbolic_value"] == "ROOT"
    assert "literal_value" not in rule
    assert rule["target_resolution"] == {
        "status": "unknown", "reason": "DYNAMIC_SCOPE_SYMBOL_UNRESOLVED",
    }
    assert rule["symbolic_value"] != "FRA"


def test_scope_integration_preserves_task_selectors_and_other_mission_topics():
    source, state, _definitions, index = _scope_source()
    scoped_root = source.read(query("M03", ["regions"], root_id="root_extra"), state.context())
    assert {row["task_id"] for row in target_rows(scoped_root["fields"]["regions"])} == {"task_region"}

    scoped_task = source.read(query("M03", ["provinces"], task_id="task_core"), state.context())
    assert [(row["task_id"], row["literal_value"])
            for row in target_rows(scoped_task["fields"]["provinces"])] == [("task_core", 186)]
    assert source.read(query("M03", ["provinces"], task_id="not_loaded"), state.context())["fields"]["provinces"]["reason"] == (
        "TASK_NOT_IN_CAPTURED_LOADED_TASKS")
    assert source.read(query("M03", ["provinces"], root_id="not_captured_root"), state.context())["fields"]["provinces"]["reason"] == (
        "ROOT_NOT_IN_CAPTURED_MISSION_SLOTS")

    state.current["observer"] = "ENG"
    with pytest.raises(InformationError) as error:
        source.read(query("M03", ["provinces"]), state.context())
    assert error.value.code == "observer_scope_mismatch"
    state.current["observer"] = "FRA"

    baseline, baseline_state, _ = make_source()
    for topic, fields in (("M01", ["task_id", "branches"]),
                          ("M02", ["completion_status"]),
                          ("M04", ["rewards"])):
        assert source.read(query(topic, fields), state.context())["fields"] == (
            baseline.read(query(topic, fields), baseline_state.context())["fields"])
    assert index.lookup_calls == 2


def test_mission_factory_shares_one_script_parser_between_both_indexes(monkeypatch, tmp_path):
    from tools import serve_information
    from bridge.information import composite, cwtools_script, mission_definitions
    from bridge.information import mission_scope_index, missions, saved_missions, service

    instances = {}
    class ParserStub:
        def __init__(self, manifest):
            instances["parser_manifest"] = manifest
            instances["parser"] = self

    class DefinitionsStub:
        def __init__(self, *, game_root, user_data, script_parser):
            instances["definition_parser"] = script_parser

    class ScopeIndexStub:
        def __init__(self, *, game_root, user_data, script_parser):
            instances["scope_parser"] = script_parser
            instances["scope_index"] = self

    class SnapshotStub:
        def __init__(self, save_path, observer):
            instances["save"] = save_path
            instances["observer"] = observer

    class SavedContextSourceStub:
        def __init__(self, snapshot):
            self.snapshot = snapshot

        def capture(self, country):
            return {"country": country}

        def context(self):
            return {"status": "ready", "observer": "FRA", "game_version": "1.37.4"}

    class MissionSourceStub:
        def __init__(self, base_source, definitions, reader, *, scheduling, scope_index=None):
            instances["mission_scope_index"] = scope_index
            instances["mission_definitions"] = definitions
            self.scope_index = scope_index

    class CompositeStub:
        def __init__(self, base_source, adapters):
            self.base_source = base_source
            self.adapters = list(adapters)

    class ServiceStub:
        def __init__(self, source, database, *, owner):
            self.source = source

    monkeypatch.setattr(cwtools_script, "CwtoolsScriptParser", ParserStub)
    monkeypatch.setattr(mission_definitions, "MissionDefinitionIndex", DefinitionsStub)
    monkeypatch.setattr(mission_scope_index, "StaticMissionScopeIndex", ScopeIndexStub)
    monkeypatch.setattr(saved_missions, "SavedMissionSnapshot", SnapshotStub)
    monkeypatch.setattr(missions, "SavedMissionContextSource", SavedContextSourceStub)
    monkeypatch.setattr(missions, "MissionInformationSource", MissionSourceStub)
    monkeypatch.setattr(composite, "CompositeSource", CompositeStub)
    monkeypatch.setattr(service, "InformationService", ServiceStub)

    args = serve_information.build_parser().parse_args([
        "--mission-game-data", "--mission-save", str(tmp_path / "save.eu4"),
        "--mission-parser-manifest", str(tmp_path / "parser.json"),
        "--observer", "FRA", "--database", ":memory:",
    ])
    built, journal = serve_information._build_runtime(args)

    assert journal is None
    assert instances["parser_manifest"] == Path(tmp_path / "parser.json")
    assert instances["definition_parser"] is instances["parser"]
    assert instances["scope_parser"] is instances["parser"]
    assert built.source.adapters[0].scope_index is instances["scope_index"]
