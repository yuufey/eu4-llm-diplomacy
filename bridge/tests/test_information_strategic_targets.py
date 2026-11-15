from __future__ import annotations

from copy import deepcopy

import pytest

from bridge.information.model import InformationError
from bridge.information.strategic_targets import StrategicTargetsSource


_CONFIG = "a" * 64
_FILE_HASH = "b" * 64


class _BaseSource:
    def __init__(self, *, changes_on_call: int | None = None):
        self.calls = 0
        self.changes_on_call = changes_on_call

    def context(self):
        self.calls += 1
        value = {
            "schema": "information.test_context.v1",
            "status": "ready",
            "mode": "live",
            "observer": "FRA",
            "session_id": "session-1",
            "game_sha256": "c" * 64,
            "game_date": "1456.1.1",
            "game_version": "1.37.4",
        }
        if self.changes_on_call == self.calls:
            value["session_id"] = "session-2"
        return value


def _index_file():
    return {
        "relative": "map/default.map",
        "bytes": 128,
        "sha256": _FILE_HASH,
        "source_kind": "game_definition",
        "source": "base_game",
    }


def _scope_context(*, config: str = _CONFIG, version: str = "1.37.4"):
    return {
        "schema": "information.mission_scope_index_context.v1",
        "status": "ready",
        "game_version": version,
        "configuration_sha256": config,
        "definition_files": [_index_file()],
        "component_statuses": {
            "province_ids": {"status": "ready", "complete": True},
            "areas": {"status": "ready", "complete": True},
            "regions": {"status": "ready", "complete": True},
            "country_tags": {"status": "ready", "complete": True},
        },
    }


def _row(kind, name, value, *, members=None):
    result = {
        "status": "known",
        "kind": kind,
        "name": name,
        "value": value,
        "source": {"configuration_sha256": _CONFIG, "files": [_index_file()]},
    }
    if members is not None:
        result["members"] = members
    return result


class _ScopeIndex:
    def __init__(self, rows=None, *, contexts=None):
        self.rows = rows or {}
        self.contexts = contexts or [_scope_context()]
        self.context_calls = 0
        self.lookup_calls = []

    def context(self):
        index = min(self.context_calls, len(self.contexts) - 1)
        self.context_calls += 1
        return deepcopy(self.contexts[index])

    def lookup_scopes(self, names):
        names = list(names)
        self.lookup_calls.append(names)
        return {name: deepcopy(self.rows.get(name, {
            "status": "unknown", "name": name, "reason": "SCOPE_NOT_FOUND"}))
                for name in names}


def _query(object_value=None, parameters=None):
    return {
        "topic": "G01",
        "object": object_value or {"type": "country", "country": "FRA"},
        "fields": ["strategic_targets"],
        **({"parameters": parameters} if parameters is not None else {}),
    }


def _declaration(identifier, target, *, intent="acquire", description=None):
    item = {"id": identifier, "intent": intent, "target": target}
    if description is not None:
        item["description"] = description
    return item


def test_country_view_preserves_caller_input_and_does_not_claim_game_fact():
    item = _declaration("goal-a", {"type": "country", "country": "ENG"},
                        intent="weaken_country", description="Reduce English influence")
    index = _ScopeIndex({"ENG": _row("country_tag", "ENG", "ENG")})
    source = StrategicTargetsSource(_BaseSource(), index)

    result = source.read(_query(parameters={"root_id": "root-1", "strategic_targets": [item]}))

    field = result["fields"]["strategic_targets"]
    declaration = field["value"]["declarations"][0]
    assert field["status"] == "known"
    assert field["game_fact"] is False
    assert declaration["source_kind"] == "caller_input"
    assert declaration["game_fact"] is False
    assert {key: declaration[key] for key in item} == item
    assert declaration["resolution"]["status"] == "known"
    assert declaration["resolution"]["basis"] == "static_country_tag_declaration"
    assert "province_ids" not in declaration["resolution"]
    assert result["source"]["provenance"]["selectors"] == {"root_id": "root-1"}
    assert index.lookup_calls == [["ENG"]]


def test_static_province_area_and_country_targets_keep_distinct_resolution_semantics():
    declarations = [
        _declaration("province", {"type": "province", "province_id": 12}),
        _declaration("area", {"type": "area", "name": "western_area"}),
        _declaration("country", {"type": "country", "country": "ENG"}),
    ]
    index = _ScopeIndex({
        "12": _row("province_id", "12", 12),
        "western_area": _row("areas", "western_area", "western_area", members=[10, 11]),
        "ENG": _row("country_tag", "ENG", "ENG"),
    })
    source = StrategicTargetsSource(_BaseSource(), index)

    result = source.read(_query(parameters={"strategic_targets": declarations}))

    rows = result["fields"]["strategic_targets"]["value"]["declarations"]
    by_id = {row["id"]: row["resolution"] for row in rows}
    assert by_id["province"]["province_ids"] == [12]
    assert by_id["area"]["province_ids"] == [10, 11]
    assert by_id["country"]["province_membership"]["status"] == "unknown"
    assert "province_ids" not in by_id["country"]
    assert index.lookup_calls == [["12", "western_area", "ENG"]]


def test_missing_declarations_are_unknown_but_explicit_empty_is_known_empty():
    source = StrategicTargetsSource(_BaseSource())

    missing = source.read(_query())["fields"]["strategic_targets"]
    empty = source.read(_query(parameters={"strategic_targets": []}))["fields"]["strategic_targets"]

    assert (missing["status"], missing["reason"]) == ("unknown", "NOT_DECLARED")
    assert missing["value"]["declarations"] == []
    assert empty["status"] == "known"
    assert empty["value"]["declarations"] == []
    assert empty["value"]["unresolved"] == []
    assert "DOES NOT PROVE" in empty["value"]["empty_semantics"]
    assert empty["game_fact"] is False


def test_province_object_filters_static_members_and_keeps_unresolved_unknown():
    area = _declaration("area-goal", {"type": "area", "name": "western_area"})
    index = _ScopeIndex({
        "western_area": _row("areas", "western_area", "western_area", members=[10, 11]),
    })
    source = StrategicTargetsSource(_BaseSource(), index)

    member = source.read(_query({"type": "province", "province_id": 11},
                                {"strategic_targets": [area]}))["fields"]["strategic_targets"]
    nonmember = source.read(_query({"type": "province", "province_id": 19},
                                   {"strategic_targets": [area]}))["fields"]["strategic_targets"]

    assert member["status"] == "known"
    assert [row["id"] for row in member["value"]["declarations"]] == ["area-goal"]
    assert nonmember["status"] == "known"
    assert nonmember["value"]["declarations"] == []

    unresolved = StrategicTargetsSource(_BaseSource()).read(
        _query({"type": "province", "province_id": 19}, {"strategic_targets": [area]}))[
            "fields"]["strategic_targets"]
    assert unresolved["status"] == "unknown"
    assert unresolved["value"]["declarations"] == []
    assert unresolved["value"]["unresolved"][0]["id"] == "area-goal"


def test_country_target_tag_does_not_resolve_province_membership():
    item = _declaration("country-goal", {"type": "country", "country": "ENG"})
    index = _ScopeIndex({"ENG": _row("country_tag", "ENG", "ENG")})
    source = StrategicTargetsSource(_BaseSource(), index)

    result = source.read(_query({"type": "province", "province_id": 55},
                                {"strategic_targets": [item]}))["fields"]["strategic_targets"]

    assert result["status"] == "unknown"
    assert result["value"]["unresolved"][0]["reason"] == "COUNTRY_DYNAMIC_PROVINCES_NOT_RESOLVED"
    assert result["value"]["unresolved"][0]["resolution"]["status"] == "known"


def test_static_scope_drift_withdraws_resolution_but_preserves_declaration():
    item = _declaration("area-goal", {"type": "area", "name": "western_area"})
    changed = _scope_context(config="d" * 64)
    index = _ScopeIndex(
        {"western_area": _row("areas", "western_area", "western_area", members=[10])},
        contexts=[_scope_context(), changed],
    )
    source = StrategicTargetsSource(_BaseSource(), index)

    field = source.read(_query(parameters={"strategic_targets": [item]}))["fields"]["strategic_targets"]

    assert field["status"] == "known"
    row = field["value"]["declarations"][0]
    assert {key: row[key] for key in item} == item
    assert row["resolution"]["status"] == "unknown"
    assert row["resolution"]["reason"] == "STATIC_SCOPE_CONTEXT_CHANGED_DURING_LOOKUP"
    assert field["value"]["unresolved"][0]["id"] == "area-goal"


def test_live_context_change_withdraws_whole_read():
    item = _declaration("province", {"type": "province", "province_id": 12})
    index = _ScopeIndex({"12": _row("province_id", "12", 12)})
    source = StrategicTargetsSource(_BaseSource(changes_on_call=2), index)

    field = source.read(_query(parameters={"strategic_targets": [item]}))["fields"]["strategic_targets"]

    assert field["status"] == "unavailable"
    assert field["reason"] == "STRATEGIC_TARGETS_CONTEXT_CHANGED_DURING_READ"
    assert "value" not in field


@pytest.mark.parametrize("items", [
    [_declaration("same", {"type": "province", "province_id": 1}),
     _declaration("same", {"type": "province", "province_id": 2})],
    [_declaration("bool-id", {"type": "province", "province_id": True})],
    [{"id": "extra", "intent": "acquire", "target": {"type": "country", "country": "ENG"},
      "unknown": True}],
    [_declaration("intent", {"type": "country", "country": "ENG"}, intent="conquer")],
    [_declaration("type", {"type": "province_group", "name": "west"})],
    [_declaration(f"g{i}", {"type": "province", "province_id": 1}, description="x" * 2048)
     for i in range(64)],
])
def test_invalid_structured_parameters_rejected_before_static_lookup(items):
    index = _ScopeIndex()
    source = StrategicTargetsSource(_BaseSource(), index)

    with pytest.raises(InformationError):
        source.read(_query(parameters={"strategic_targets": items}))

    assert index.lookup_calls == []


def test_country_object_must_be_the_logical_observer():
    source = StrategicTargetsSource(_BaseSource())

    with pytest.raises(InformationError) as error:
        source.read(_query({"type": "country", "country": "ENG"},
                           {"strategic_targets": []}))

    assert error.value.code == "observer_scope_mismatch"

