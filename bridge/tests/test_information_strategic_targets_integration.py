"""G01 operator targets through CompositeSource and InformationService."""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest

from bridge.information import InformationError
from bridge.information.composite import CompositeSource
from bridge.information.province_task_targets import ProvinceTaskTargetsSource
from bridge.information.service import InformationService
from bridge.information.strategic_targets import StrategicTargetsSource
from bridge.tests.test_information_g01_task_targets_integration import (
    _make_service as _make_task_target_service,
)
from bridge.tests.test_information_mission_target_rules_v2 import area_scope


PROVINCE_ID = 186
TASK_SELECTOR = {"root_id": "root_main", "task_id": "task_core"}


def _query(fields, *, parameters=None, object_=None):
    return {
        "topic": "G01",
        "object": deepcopy(object_ or {"type": "country", "country": "FRA"}),
        "fields": list(fields),
        "parameters": deepcopy(parameters or {}),
    }


def _target(id_, intent, target, *, description=None):
    item = {"id": id_, "intent": intent, "target": deepcopy(target)}
    if description is not None:
        item["description"] = description
    return item


def _make_service(tmp_path, monkeypatch, *, clock=None, with_scope_index=False):
    """Extend the proven 192 G01 fixture with only the fourth owner."""
    old_service, old_composite, primary, mission_state, captures = _make_task_target_service(
        tmp_path, monkeypatch, clock=clock,
    )
    task_owner = next(
        owner for owner in old_composite.adapters
        if isinstance(owner, ProvinceTaskTargetsSource)
    )
    scope_index = task_owner.mission_analysis.missions.scope_index
    if with_scope_index:
        area = area_scope("normandy_area", [186, 187])
        scope_index.rows["normandy_area"] = area
        original_context = scope_index.context
        definition_files = deepcopy(area["source"]["files"])

        def context_with_definition_files():
            value = original_context()
            value["definition_files"] = deepcopy(definition_files)
            return value

        scope_index.context = context_with_definition_files
        strategy_index = scope_index
    else:
        strategy_index = None

    # The legacy service is only a fixture factory here. Recompose its existing
    # three owners with the new adapter, then run all assertions through one
    # actual CompositeSource + InformationService pair.
    old_service.close()
    strategic_owner = StrategicTargetsSource(primary, scope_index=strategy_index)
    composite = CompositeSource(primary, [*old_composite.adapters, strategic_owner])
    service = InformationService(
        composite,
        Path(tmp_path) / "g01-strategic-targets.sqlite3",
        clock=clock,
    )
    return service, composite, mission_state, captures


def _field(result, name="strategic_targets"):
    return result["items"][0]["fields"][name]


def test_four_g01_owners_share_typed_targets_and_keep_legacy_empty_parameters(
        tmp_path, monkeypatch):
    service, composite, mission_state, captures = _make_service(tmp_path, monkeypatch)
    try:
        owners = composite.adapters
        assert len(owners) == 4
        schemas = [owner.catalog()[0]["parameters"] for owner in owners]
        assert all(schema == schemas[0] for schema in schemas[1:])

        schema = schemas[0]
        assert set(schema["properties"]) == {"root_id", "task_id", "strategic_targets"}
        assert schema["additionalProperties"] is False
        assert not schema.get("required")
        declarations = schema["properties"]["strategic_targets"]
        assert declarations["type"] == "array"
        assert declarations["maxItems"] == 64
        assert {"id", "intent", "target"} <= set(declarations["items"]["required"])
        assert declarations["items"]["additionalProperties"] is False
        target_kinds = {
            variant["properties"]["type"].get("const")
            or tuple(variant["properties"]["type"].get("enum", ()))
            for variant in declarations["items"]["properties"]["target"]["oneOf"]
        }
        assert target_kinds == {"province", ("area", "region"), "country"}

        # Existing province fields continue to work with omitted/empty
        # parameters under the larger shared G01 schema.
        legacy = service.query(
            "strategic-targets-legacy-empty-parameters",
            queries=[_query(
                ["cores", "claims", "permanent_claims"],
                object_={"type": "province", "province_id": PROVINCE_ID},
            )],
        )
        fields = legacy["items"][0]["fields"]
        assert {name: value["status"] for name, value in fields.items()} == {
            "cores": "known",
            "claims": "known",
            "permanent_claims": "known",
        }
        assert legacy["items"][0]["query"]["parameters"] == {}
        assert captures["analysis"] == []
        assert mission_state.calls == 0
    finally:
        service.close()


def test_structured_targets_are_caller_input_and_dynamic_province_membership_stays_unknown(
        tmp_path, monkeypatch):
    declarations = [
        _target("province-goal", "acquire", {"type": "province", "province_id": 186}),
        _target("area-goal", "return_core", {"type": "area", "name": "normandy_area"}),
        _target("region-goal", "protect_subject", {"type": "region", "name": "north_france"}),
        _target("country-goal", "weaken_country", {"type": "country", "country": "ENG"}),
        _target("other-goal", "other", {"type": "province", "province_id": 187},
                description="caller supplied label"),
    ]
    params = {"strategic_targets": declarations}
    service, composite, mission_state, captures = _make_service(tmp_path, monkeypatch)
    try:
        field_catalog = next(
            row["fields"]["strategic_targets"]
            for row in composite.catalog() if row["topic_id"] == "G01"
        )
        assert field_catalog["game_fact"] is False
        assert field_catalog["complete"] is False

        absent = service.query(
            "strategic-targets-missing-declaration-parameter",
            queries=[_query(["strategic_targets"])],
        )
        assert _field(absent)["status"] == "unknown"
        assert _field(absent)["reason"] == "NOT_DECLARED"
        assert "value" not in _field(absent)

        explicit_empty = service.query(
            "strategic-targets-explicit-empty-declaration",
            queries=[_query(["strategic_targets"], parameters={"strategic_targets": []})],
        )
        empty_field = _field(explicit_empty)
        assert empty_field["status"] == "known"
        assert empty_field["value"]["declarations"] == []
        assert empty_field["value"]["game_fact"] is False
        assert empty_field["value"]["complete"] is False

        country = service.query(
            "strategic-targets-explicit-country-input",
            queries=[_query(["strategic_targets"], parameters=params)],
        )
        country_field = _field(country)
        assert country_field["status"] == "known"
        assert country_field["value"]["game_fact"] is False
        assert country_field["value"]["complete"] is False
        assert country_field["value"]["partial"] is True
        assert [row["id"] for row in country_field["value"]["declarations"]] == [
            "province-goal", "area-goal", "region-goal", "country-goal", "other-goal",
        ]
        area_declaration = next(
            row for row in country_field["value"]["declarations"] if row["id"] == "area-goal"
        )
        assert area_declaration["resolution"]["status"] == "unknown"
        assert country["items"][0]["query"]["parameters"] == params

        # An explicitly declared country does not let the province query infer
        # current, dynamic country ownership when no static map index exists.
        dynamic_country = service.query(
            "strategic-targets-province-no-dynamic-country-expansion",
            queries=[_query(
                ["strategic_targets"],
                parameters={"strategic_targets": [
                    _target("country-only", "other", {"type": "country", "country": "FRA"}),
                ]},
                object_={"type": "province", "province_id": PROVINCE_ID},
            )],
        )
        assert _field(dynamic_country)["status"] == "unknown"

        # Country queries are scoped to the active logical observer.
        wrong_observer = service.query(
            "strategic-targets-wrong-logical-observer",
            queries=[_query(
                ["strategic_targets"], parameters=params,
                object_={"type": "country", "country": "ENG"},
            )],
        )
        assert _field(wrong_observer)["status"] == "unavailable"
        assert _field(wrong_observer)["reason"] == "observer_scope_mismatch"

        assert captures["analysis"] == []
        assert mission_state.calls == 0
    finally:
        service.close()


def test_static_area_membership_filters_province_queries_without_dynamic_expansion(
        tmp_path, monkeypatch):
    service, _composite, mission_state, captures = _make_service(
        tmp_path, monkeypatch, with_scope_index=True,
    )
    params = {"strategic_targets": [
        _target("area", "acquire", {"type": "area", "name": "normandy_area"}),
    ]}
    try:
        member = service.query(
            "strategic-targets-static-province-member",
            queries=[_query(
                ["strategic_targets"], parameters=params,
                object_={"type": "province", "province_id": 186},
            )],
        )
        assert _field(member)["status"] == "known"
        assert _field(member)["value"]["game_fact"] is False
        assert [row["id"] for row in _field(member)["value"]["declarations"]] == ["area"]

        nonmember = service.query(
            "strategic-targets-static-province-nonmember",
            queries=[_query(
                ["strategic_targets"], parameters=params,
                object_={"type": "province", "province_id": 999},
            )],
        )
        assert _field(nonmember)["status"] == "known"
        assert _field(nonmember)["value"]["game_fact"] is False
        assert _field(nonmember)["value"]["declarations"] == []
        assert captures["analysis"] == []
        assert mission_state.calls == 0
    finally:
        service.close()


def test_mixed_task_and_operator_targets_preserve_parameters_but_m05_gets_only_selector(
        tmp_path, monkeypatch):
    targets = [_target("explicit-goal", "acquire", {"type": "province", "province_id": 186})]
    parameters = dict(TASK_SELECTOR, strategic_targets=targets)
    service, _composite, mission_state, captures = _make_service(tmp_path, monkeypatch)
    try:
        result = service.query(
            "strategic-targets-mixed-task-query",
            queries=[_query(
                ["cores", "claims", "permanent_claims", "task_targets", "strategic_targets"],
                parameters=parameters,
            )],
        )
        item = result["items"][0]
        assert item["query"]["parameters"] == parameters
        assert item["fields"]["task_targets"]["status"] == "known"
        assert item["fields"]["strategic_targets"]["status"] == "known"
        assert item["fields"]["strategic_targets"]["value"]["game_fact"] is False
        assert captures["analysis"] == [{
            "topic": "M05",
            "object": {"type": "country", "country": "FRA"},
            "fields": ["linked_targets"],
            "parameters": TASK_SELECTOR,
        }]
        assert mission_state.calls == 1
    finally:
        service.close()


def test_report_update_persists_targets_periodic_reuses_them_and_invalid_update_is_atomic(
        tmp_path, monkeypatch):
    now = [100.0]
    service, _composite, mission_state, captures = _make_service(
        tmp_path, monkeypatch, clock=lambda: now[0],
    )
    first = {"strategic_targets": [
        _target("goal-one", "acquire", {"type": "province", "province_id": 186}),
    ]}
    second = {"strategic_targets": [
        _target("goal-two", "return_core", {"type": "area", "name": "normandy_area"}),
    ]}
    try:
        first_query = _query(["strategic_targets"], parameters=first)
        report = service.manage_report(
            "strategic-targets-report-create",
            "create",
            config={"name": "Strategic targets", "queries": [first_query], "detail": "full"},
        )["report"]
        report_b = service.manage_report(
            "strategic-targets-unrelated-report-create",
            "create",
            config={"name": "Legacy province", "queries": [
                _query(["cores"], object_={"type": "province", "province_id": PROVINCE_ID}),
            ]},
        )["report"]
        subscription = service.manage_subscription(
            "strategic-targets-periodic-create",
            "create",
            config={
                "name": "Strategic target polling",
                "kind": "periodic",
                "report_id": report["id"],
                "enabled": True,
                "schedule": {"basis": "real", "every": 1, "unit": "seconds", "missed": "coalesce"},
            },
        )["subscription"]
        subscription_b = service.manage_subscription(
            "strategic-targets-unrelated-subscription-create",
            "create",
            config={
                "name": "Legacy polling",
                "kind": "periodic",
                "report_id": report_b["id"],
                "enabled": True,
                "schedule": {"basis": "real", "every": 1, "unit": "seconds", "missed": "coalesce"},
            },
        )["subscription"]
        global_config = service.configure("strategic-targets-global-config-before", "get")["config"]

        updated = service.manage_report(
            "strategic-targets-report-update",
            "update",
            report_id=report["id"],
            expected_version=report["version"],
            config={
                "name": "Strategic targets revised",
                "queries": [_query(["strategic_targets"], parameters=second)],
                "detail": "full",
            },
        )["report"]
        assert updated["version"] == report["version"] + 1
        assert updated["queries"][0]["parameters"] == second
        assert service.manage_report("strategic-targets-report-get", "get",
                                     report_id=report_b["id"])["report"] == report_b
        assert service.manage_subscription("strategic-targets-sub-get", "get",
                                           subscription_id=subscription["id"])["subscription"] == subscription
        assert service.manage_subscription("strategic-targets-sub-b-get", "get",
                                           subscription_id=subscription_b["id"])["subscription"] == subscription_b
        assert service.configure("strategic-targets-global-config-after-update", "get")["config"] == global_config

        report_read = service.query("strategic-targets-report-read", report_id=report["id"])
        assert report_read["items"][0]["query"]["parameters"] == second
        assert _field(report_read)["status"] == "known"
        assert _field(report_read)["value"]["game_fact"] is False

        assert service.tick()["results"] == []
        now[0] += 1.0
        periodic = service.tick()["results"]
        strategic_result = next(
            row for row in periodic if row["subscription_id"] == subscription["id"]
        )
        assert strategic_result["items"][0]["query"]["parameters"] == second
        assert _field(strategic_result)["status"] == "known"
        assert _field(strategic_result)["value"]["game_fact"] is False

        invalid = deepcopy(second)
        invalid["strategic_targets"][0]["target"]["country"] = "fra"
        with pytest.raises(InformationError):
            service.manage_report(
                "strategic-targets-report-update-rejected",
                "update",
                report_id=report["id"],
                expected_version=updated["version"],
                config={"name": "Must not commit", "queries": [
                    _query(["strategic_targets"], parameters=invalid),
                ]},
            )

        assert service.manage_report("strategic-targets-report-after-reject", "get",
                                     report_id=report["id"])["report"] == updated
        assert service.manage_report("strategic-targets-report-b-after-reject", "get",
                                     report_id=report_b["id"])["report"] == report_b
        assert service.manage_subscription("strategic-targets-sub-after-reject", "get",
                                           subscription_id=subscription["id"])["subscription"] == subscription
        assert service.manage_subscription("strategic-targets-sub-b-after-reject", "get",
                                           subscription_id=subscription_b["id"])["subscription"] == subscription_b
        assert service.configure("strategic-targets-global-config-after-reject", "get")["config"] == global_config
        assert captures["analysis"] == []
        assert mission_state.calls == 0
    finally:
        service.close()
