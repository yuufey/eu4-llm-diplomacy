"""Offline source tests for static HRE reform definitions (not current reforms)."""
from __future__ import annotations

from copy import deepcopy

import pytest

from bridge.information import InformationService
from bridge.information.catalog import list_topics
from bridge.information.composite import CompositeSource
from bridge.information.empire_live import NativeEmpireSource
from bridge.information import imperial_reform_rules as reform_rules
from bridge.information.imperial_reform_rules import StaticImperialReformRulesSource


def _node(key, *, line=1, column=0, assignment="=", kind="scalar", value="yes", children=None):
    return {
        "key": key,
        "assignment": assignment,
        "kind": kind,
        "value": value,
        "children": list(children or []),
        "line": line,
        "column": column,
    }


def _definitions():
    # Unknown syntax and duplicate declarations are deliberately retained as
    # source structure. Nothing here is evaluated as a trigger or effect.
    repeated = _node("future_rule", line=8, value="opaque_value")
    return [{
        "reform_id": "reform_one",
        "empire": "hre",
        "relative_file": "common/imperial_reforms/00_fixture.txt",
        "line": 4,
        "declarations": [
            _node("potential", line=4, kind="block", value=None, children=[
                deepcopy(repeated), deepcopy(repeated),
                _node("owns", line=9, value="183"),
            ]),
            _node("future_effect", line=15, kind="block", value=None, children=[
                _node("unknown_command", line=16, value="preserve_me"),
            ]),
        ],
        # Index-only metadata must never be projected.
        "absolute_path": "C:/private/mods/secret.txt",
        "source_sha256": "private-source-hash",
        "raw_parser_state": {"pointer": "0x12345678"},
    }]


class _FakeIndex:
    def __init__(self, definitions=None, *, game_version="1.37.4", ready=True):
        self.rows = deepcopy(_definitions() if definitions is None else definitions)
        self.current = {
            "status": "ready" if ready else "unready",
            "complete": False,
            "game_version": game_version,
            "configuration_sha256": "a" * 64,
            "definitions_sha256": "b" * 64,
            "script_parser": {"name": "CWTools", "version": "0.6.0-alpha"},
            "reasons": [],
        }
        self.calls = []
        self.error = None
        self.definitions_error = None
        self.change_after_definitions = False
        self.change_config_after_definitions = False

    def context(self):
        self.calls.append("context")
        if self.error:
            raise self.error
        return deepcopy(self.current)

    def definitions(self, empire="hre"):
        self.calls.append(("definitions", empire))
        if self.definitions_error:
            raise self.definitions_error
        if self.error:
            raise self.error
        if self.change_after_definitions:
            self.current["definitions_sha256"] = "c" * 64
        if self.change_config_after_definitions:
            self.current["configuration_sha256"] = "d" * 64
        return deepcopy(self.rows)


class _FakeBase:
    event_types = ()

    def __init__(self, *, context=None, contexts=None):
        self.current = deepcopy(context or {
            "status": "ready", "mode": "live", "observer": "FRA",
            "game_version": "1.37.4", "session_id": "hre-session",
            "world_id": "world-a", "game_date": "1456.1.1", "game_day": 10,
        })
        self.contexts = list(contexts or [])
        self.context_calls = 0

    def context(self):
        self.context_calls += 1
        if self.contexts:
            value = self.contexts.pop(0)
            if isinstance(value, Exception):
                raise value
            return deepcopy(value)
        return deepcopy(self.current)

    def catalog(self):
        return list_topics()

    def validate_query(self, query, context=None):
        return deepcopy(query)

    def read(self, query, context):
        raise AssertionError("S01.reforms must route to the static rules source")

    def poll_events(self, context, cursor):
        return {"events": [], "cursor": deepcopy(cursor or {}), "complete": True, "gaps": []}


def _query(*, object_type="country", country="FRA", fields=("reforms",)):
    obj = {"type": object_type}
    if object_type == "country":
        obj["country"] = country
    return {"topic": "S01", "object": obj, "fields": list(fields), "parameters": {}}


def _field(result):
    return result["fields"]["reforms"]


def _assert_static_contract(field):
    assert field["status"] == "known"
    assert field["unit"] == "imperial_reform_definition"
    assert field["period"] == "static_definition"
    assert field["complete"] is False
    assert field["conditions_evaluated"] is False
    assert field["effects_applied"] is False
    assert field["current_passed_reforms_observed"] is False
    assert field["loaded_definition_set_verified"] is False
    assert field["scale"] == 1
    assert field["basis"] == "cwtools_effective_imperial_reform_declarations"


def test_catalog_and_query_contract_are_global_static_rules_with_empty_parameters():
    source = StaticImperialReformRulesSource(_FakeBase(), _FakeIndex())
    topic = next(item for item in source.catalog() if item["topic_id"] == "S01")

    assert set(topic["fields"]) == {"reforms"}
    assert topic["fields"]["reforms"]["coverage"] == "partial"
    assert topic["fields"]["reforms"]["complete"] is False
    assert topic["fields"]["reforms"]["unit"] == "imperial_reform_definition"
    assert topic["fields"]["reforms"]["period"] == "static_definition"
    assert topic["fields"]["reforms"]["supported_object_types"] == ["country", "session"]
    assert source.validate_query(_query()) == _query()
    assert source.validate_query(_query(object_type="session")) == _query(object_type="session")
    index = _FakeIndex()
    source = StaticImperialReformRulesSource(_FakeBase(), index)
    france = _field(source.read(_query(country="FRA"), None))
    england = _field(source.read(_query(country="ENG"), None))
    session = _field(source.read(_query(object_type="session"), None))
    assert france["value"] == england["value"] == session["value"]


def test_static_definitions_preserve_unknown_and_duplicate_ast_without_private_metadata():
    index = _FakeIndex()
    source = StaticImperialReformRulesSource(_FakeBase(), index)
    result = source.read(_query(), None)
    field = _field(result)

    _assert_static_contract(field)
    reform = field["value"][0]
    assert reform["reform_id"] == "reform_one"
    assert reform["empire"] == "hre"
    assert reform["relative_file"] == "common/imperial_reforms/00_fixture.txt"
    assert reform["line"] == 4
    declarations = reform["declarations"]
    assert [node["key"] for node in declarations] == ["potential", "future_effect"]
    assert [node["key"] for node in declarations[0]["children"]] == [
        "future_rule", "future_rule", "owns"
    ]
    assert declarations[1]["children"][0]["key"] == "unknown_command"
    assert "private-source-hash" not in str(result)
    assert "secret.txt" not in str(result)
    assert "0x12345678" not in str(result)
    for key in ("absolute_path", "source_sha256", "raw_parser_state"):
        assert key not in reform


def test_unbound_static_rules_are_available_but_mismatched_explicit_version_is_not():
    unbound = _FakeBase(context={"status": "unready", "mode": "unbound", "game_version": None})
    source = StaticImperialReformRulesSource(unbound, _FakeIndex())
    result = source.read(_query(), None)
    _assert_static_contract(_field(result))

    mismatch = StaticImperialReformRulesSource(
        _FakeBase(), _FakeIndex(game_version="1.37.5")
    )
    field = _field(mismatch.read(_query(), None))
    assert field["status"] in {"unavailable", "unknown"}
    assert "value" not in field


def test_index_unready_or_exception_does_not_become_an_empty_definition_list():
    unready = StaticImperialReformRulesSource(_FakeBase(), _FakeIndex(ready=False))
    field = _field(unready.read(_query(), None))
    assert field["status"] in {"unavailable", "unknown"}
    assert "value" not in field

    broken_index = _FakeIndex()
    broken_index.error = RuntimeError("C:/private/mods/secret.txt 0x12345678")
    broken = StaticImperialReformRulesSource(_FakeBase(), broken_index)
    broken_field = _field(broken.read(_query(), None))
    assert broken_field["status"] in {"unavailable", "unknown"}
    assert "value" not in broken_field
    assert "secret.txt" not in str(broken_field)
    assert "0x12345678" not in str(broken_field)

    failed_definitions = _FakeIndex()
    failed_definitions.definitions_error = RuntimeError("C:/private/mods/secret.txt 0x12345678")
    definition_failure = StaticImperialReformRulesSource(_FakeBase(), failed_definitions)
    failed_field = _field(definition_failure.read(_query(), None))
    assert failed_field["status"] == "unavailable"
    assert "value" not in failed_field
    assert "secret.txt" not in str(failed_field)
    assert "0x12345678" not in str(failed_field)


def test_base_context_drift_retracts_definition_result():
    before = _FakeBase().context()
    after = deepcopy(before)
    after["world_id"] = "world-b"
    # After the first base-context observation, every later observation sees
    # the changed world, regardless of harmless extra context reads.
    base = _FakeBase(context=after, contexts=[before])
    source = StaticImperialReformRulesSource(base, _FakeIndex())
    field = _field(source.read(_query(), None))

    assert field["status"] in {"unavailable", "unknown"}
    assert "value" not in field


@pytest.mark.parametrize("changed", ("definitions", "configuration"))
def test_index_identity_or_input_hash_drift_retracts_definition_result(changed):
    index = _FakeIndex()
    setattr(index, f"change_{'config_after' if changed == 'configuration' else 'after'}_definitions",
            True)
    source = StaticImperialReformRulesSource(_FakeBase(), index)
    field = _field(source.read(_query(), None))

    assert field["status"] in {"unavailable", "unknown"}
    assert "value" not in field


def test_bad_relative_source_path_is_not_projected_as_a_public_absolute_path():
    rows = _definitions()
    rows[0]["relative_file"] = "../outside/secret.txt"
    source = StaticImperialReformRulesSource(_FakeBase(), _FakeIndex(rows))
    field = _field(source.read(_query(), None))

    assert field["status"] in {"unknown", "unavailable"}
    assert "value" not in field


@pytest.mark.parametrize("limit_name,limit", [
    ("MAX_DEFINITIONS", 0),
    ("MAX_AST_NODES", 2),
    ("MAX_AST_DEPTH", 1),
    ("MAX_OUTPUT_BYTES", 1),
])
def test_definition_and_ast_budgets_fail_closed(monkeypatch, limit_name, limit):
    monkeypatch.setattr(reform_rules, limit_name, limit)
    source = StaticImperialReformRulesSource(_FakeBase(), _FakeIndex())
    field = _field(source.read(_query(), None))

    assert field["status"] in {"unknown", "unavailable"}
    assert "value" not in field


class _Clock:
    def __init__(self, now=100.0):
        self.now = float(now)

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += float(seconds)


def test_composite_keeps_live_identity_and_static_rules_disjoint_and_schedules_reported_values(tmp_path):
    base = _FakeBase()
    native = NativeEmpireSource(base, capture=lambda *_args, **_kwargs: {})
    static = StaticImperialReformRulesSource(base, _FakeIndex())
    composite = CompositeSource(base, [native, static])
    topic = next(item for item in composite.catalog() if item["topic_id"] == "S01")

    base_s01 = next(item for item in list_topics() if item["topic_id"] == "S01")
    assert set(topic["fields"]) == set(base_s01["fields"])
    assert {"emperor", "electors", "reforms"} <= set(topic["fields"])
    assert topic["fields"]["reforms"]["coverage"] == "partial"
    service = InformationService(composite, tmp_path / "reforms.sqlite3", clock=_Clock(), owner="reforms-test")
    query = _query()
    try:
        direct = service.query("reforms-direct", queries=[query])["items"][0]
        _assert_static_contract(_field(direct))
        report = service.manage_report("reforms-report-create", "create", config={
            "name": "static HRE reform definitions", "detail": "raw", "queries": [query],
        })["report"]
        reported = service.query("reforms-report-run", report_id=report["id"])["items"][0]
        assert _field(reported) == _field(direct)

        binding = {key: base.context()[key] for key in ("session_id", "observer", "game_version", "world_id")}
        subscriptions = []
        for request_id, every in (("reforms-2s-create", 2), ("reforms-5s-create", 5)):
            sub = service.manage_subscription(request_id, "create", config={
                "name": f"static-reforms-{every}s", "kind": "periodic", "report_id": report["id"],
                "enabled": True, "binding": binding,
                "schedule": {"basis": "real", "every": every, "unit": "seconds", "missed": "coalesce"},
            })["subscription"]
            subscriptions.append(sub)

        clock = service.clock
        clock.advance(2)
        at_two = service.tick()["results"]
        assert len(at_two) == 1
        assert at_two[0]["subscription_id"] == subscriptions[0]["id"]
        assert _field(at_two[0]["items"][0]) == _field(direct)
        cancelled_two = service.manage_subscription(
            "reforms-sub-2-cancel", "cancel", subscription_id=subscriptions[0]["id"],
            expected_version=subscriptions[0]["version"],
        )["subscription"]
        assert cancelled_two["state"] == "cancelled"

        clock.advance(3)
        at_five = service.tick()["results"]
        assert len(at_five) == 1
        assert at_five[0]["subscription_id"] == subscriptions[1]["id"]
        assert _field(at_five[0]["items"][0]) == _field(direct)

        cancelled_five = service.manage_subscription(
            "reforms-sub-5-cancel", "cancel", subscription_id=subscriptions[1]["id"],
            expected_version=subscriptions[1]["version"],
        )["subscription"]
        assert cancelled_five["state"] == "cancelled"
    finally:
        service.close()
