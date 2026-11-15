"""Caller-associated trade scenarios reuse current read-only action previews."""
from copy import deepcopy
import json

import pytest

from bridge.information import InformationError, InformationService
from bridge.information.composite import CompositeSource
from bridge.information.trade_scenario_costs import TradeScenarioCostReader
from bridge.information.trade_scenarios import FIELDS, TradeScenarioSource
from bridge.tests import test_information_mission_candidate_costs as action_fixtures
from bridge.tests import test_information_trade_scenarios_integration as trade_fixtures


NODE_ID = trade_fixtures.NODE_ID
DATE_RAW = trade_fixtures.live_context()["game_date"]


def _scenario(identifier, *, actions=None, **changes):
    row = trade_fixtures.scenario(identifier, **changes)
    if actions is not None:
        row["actions"] = deepcopy(actions)
    return row


def _query(scenarios, *, fields=None):
    return trade_fixtures.scenario_query(
        scenarios,
        fields=fields or ["costs"],
    )


def _service_with_costs(tmp_path, inspector, *, reader=None, clock=None, observer="FRA"):
    reader = reader or trade_fixtures.FakeTradeBaseline(
        context=trade_fixtures.live_context(observer=observer),
    )
    primary = trade_fixtures.FakePrimary(trade_fixtures.live_context(observer=observer))
    adapter = TradeScenarioSource(reader, TradeScenarioCostReader(inspector))
    composite = CompositeSource(primary, [adapter])
    service = InformationService(
        composite,
        tmp_path / "trade-scenario-costs.sqlite3",
        clock=clock,
    )
    return service, composite, reader, adapter


def _preview(action_id, actor, recipient, phase, parameters, *, date_raw=DATE_RAW):
    assert phase == "initiate"
    action = {
        "action_id": action_id,
        "recipient": recipient,
        "parameters": deepcopy(parameters),
    }
    if action_id == "declare_war":
        return action_fixtures._public_war_inspection(
            action, actor=actor, date_raw=date_raw,
        )
    return action_fixtures._public_peace_inspection(action, date_raw=date_raw)


def _field(result, name):
    return result["items"][0]["fields"][name]


def test_war_and_peace_costs_keep_exact_current_projection_and_t06_schema(tmp_path):
    calls = []

    def inspector(action_id, actor, recipient, phase, parameters):
        calls.append((action_id, actor, recipient, phase, deepcopy(parameters)))
        return _preview(action_id, actor, recipient, phase, parameters)

    war = action_fixtures._war_action("war-action")
    peace = action_fixtures._peace_action("peace-action")
    scenarios = [_scenario("caller-scenario", actions=[war, peace])]
    service, _composite, reader, _adapter = _service_with_costs(tmp_path, inspector)
    try:
        result = service.query(
            "trade-cost-war-and-peace",
            queries=[_query(scenarios, fields=["costs"])],
        )

        costs = _field(result, "costs")
        assert costs["status"] == "known"
        assert costs["partial"] is True
        assert costs["complete"] is False
        assert costs["game_fact"] is False
        value = costs["value"]
        assert value["schema"] == "information.trade_scenario_costs.v1"
        assert value["association"] == "caller_scenario_id"
        assert value["submitted"] is False
        assert value["sequencing"] == "independent_previews_at_current_state"
        assert value["game_fact"] is False
        assert value["complete"] is False
        assert [row["id"] for row in value["scenarios"]] == ["caller-scenario"]

        row = value["scenarios"][0]
        assert row["total_cost"] == {
            "status": "unknown",
            "reason": "CROSS_ACTION_TOTAL_NOT_EVALUATED",
            "complete": False,
        }
        assert row["combined_future_state_evaluated"] is False
        war_result, peace_result = row["actions"]
        assert [(action["action_id"], action["actor"], action["recipient"], action["phase"])
                for action in row["actions"]] == [
            ("declare_war", "FRA", "ENG", "initiate"),
            ("cede_province", "FRA", "ENG", "initiate"),
        ]
        assert war_result["costs"]["status"] == "known"
        assert war_result["costs"]["submitted"] is False
        assert [(item["resource"], item["amount_raw"], item["scale"], item["unit"],
                 item["amount"], item["amount_decimal"]) for item in war_result["costs"]["items"]] == [
            ("stability_loss", 0, 1000, "stability_loss", 0.0, "0.000"),
            ("war_exhaustion", 1500, 1000, "war_exhaustion", 1.5, "1.500"),
        ]
        assert peace_result["costs"]["status"] == "known"
        assert peace_result["costs"]["submitted"] is False
        assert peace_result["costs"]["items"] == []
        assert peace_result["costs"]["preview_fields"]["P02"]["war_score_cost"]["status"] == "unknown"
        assert peace_result["phase"] == "initiate"

        assert calls == [
            ("declare_war", "FRA", "ENG", "initiate", war["parameters"]),
            ("cede_province", "FRA", "ENG", "initiate", peace["parameters"]),
        ]
        assert len(reader.read_calls) == 1
        assert value["inspection_collection"] == {
            "scope": "one_t06_read",
            "inspector_calls": 2,
            "shared_result_hits": 0,
            "cross_request_cache": False,
        }
        # T06 exposes caller association and action projections without M05 selectors.
        assert "selector" not in value
        assert "task_association" not in value
        assert "root_id" not in json.dumps(value)
        assert "task_id" not in json.dumps(value)
    finally:
        service.close()


def test_duplicate_actions_share_successes_per_read_and_long_scenario_ids_stay_valid(tmp_path):
    calls = []

    def inspector(action_id, actor, recipient, phase, parameters):
        calls.append((action_id, actor, recipient, phase, deepcopy(parameters)))
        return _preview(action_id, actor, recipient, phase, parameters)

    long_id = "s" + "x" * 127
    rows = [
        _scenario("first", actions=[action_fixtures._war_action("first-action")]),
        _scenario(long_id, actions=[action_fixtures._war_action("second-action")]),
    ]
    service, _composite, reader, _adapter = _service_with_costs(tmp_path, inspector)
    try:
        for index in range(2):
            result = service.query(
                f"trade-cost-shared-actions-{index}",
                queries=[_query(rows)],
            )
            value = _field(result, "costs")["value"]
            assert [row["id"] for row in value["scenarios"]] == ["first", long_id]
            assert value["inspection_collection"]["inspector_calls"] == 1
            assert value["inspection_collection"]["shared_result_hits"] == 1
            assert all(row["actions"][0]["costs"]["status"] == "known"
                       for row in value["scenarios"])

        assert len(calls) == 2
        assert len(reader.read_calls) == 2
    finally:
        service.close()


def test_failed_action_is_cached_and_isolated_while_baseline_cost_and_other_action_survive(tmp_path):
    calls = []

    def inspector(action_id, actor, recipient, phase, parameters):
        calls.append((action_id, actor, recipient, phase, deepcopy(parameters)))
        if action_id == "declare_war":
            raise RuntimeError("read-only inspector unavailable")
        return _preview(action_id, actor, recipient, phase, parameters)

    rows = [
        _scenario("broken-one", actions=[action_fixtures._war_action("war-one")]),
        _scenario("broken-two", actions=[action_fixtures._war_action("war-two")]),
        _scenario("still-readable", actions=[action_fixtures._peace_action("peace-one")]),
    ]
    service, _composite, reader, _adapter = _service_with_costs(tmp_path, inspector)
    try:
        result = service.query(
            "trade-cost-isolated-inspection-failure",
            queries=[_query(rows, fields=["expected_trade", "costs"])],
        )

        expected = _field(result, "expected_trade")
        costs = _field(result, "costs")
        assert expected["status"] == "known"
        assert expected["game_fact"] is False
        assert len(reader.read_calls) == 1
        assert costs["status"] == "known"
        projections = costs["value"]["scenarios"]
        assert [row["actions"][0]["costs"]["reason"] for row in projections[:2]] == [
            "CANDIDATE_INSPECTION_FAILED",
            "CANDIDATE_INSPECTION_FAILED",
        ]
        assert projections[2]["actions"][0]["costs"]["status"] == "known"
        assert costs["value"]["inspection_collection"]["inspector_calls"] == 2
        assert costs["value"]["inspection_collection"]["shared_result_hits"] == 1

        again = service.query(
            "trade-cost-isolated-inspection-failure-again",
            queries=[_query(rows, fields=["costs"])],
        )
        assert _field(again, "costs")["value"]["inspection_collection"]["inspector_calls"] == 2
        assert len(calls) == 4
        assert len(reader.read_calls) == 2
    finally:
        service.close()


def _invalid_cost_scenarios():
    war = action_fixtures._war_action
    return [
        ("missing-actions", [_scenario("missing")]),
        ("empty-actions", [_scenario("empty", actions=[])]),
        ("duplicate-scenario-id", [
            _scenario("duplicate", actions=[war("one")]),
            _scenario("duplicate", actions=[war("two")]),
        ]),
        ("duplicate-action-id", [_scenario("duplicate-action", actions=[war("same"), war("same")])]),
        ("per-scenario-action-limit", [
            _scenario("too-many", actions=[war(f"action-{index}") for index in range(17)])
        ]),
        ("aggregate-action-limit", [
            _scenario("nine-one", actions=[war(f"one-{index}") for index in range(9)]),
            _scenario("nine-two", actions=[war(f"two-{index}") for index in range(9)]),
        ]),
        ("input-byte-limit", [
            _scenario("oversized", actions=[war("large", parameters={
                **action_fixtures.WAR_PARAMETERS,
                "large_payload": "x" * 65536,
            })]),
        ]),
        ("self-recipient", [_scenario("self", actions=[war("self", recipient="FRA")])]),
    ]


def test_bad_action_inputs_reject_before_baseline_or_inspection(tmp_path):
    inspector_calls = []

    def inspector(*args):
        inspector_calls.append(args)
        return {}

    service, _composite, reader, _adapter = _service_with_costs(tmp_path, inspector)
    try:
        for index, (label, scenarios) in enumerate(_invalid_cost_scenarios()):
            with pytest.raises(InformationError) as error:
                service.query(
                    f"trade-cost-invalid-{index}-{label}",
                    queries=[_query(scenarios, fields=["costs"])],
                )
            assert error.value.code == "invalid_parameters"
            assert reader.read_calls == []
            assert inspector_calls == []
    finally:
        service.close()


def test_catalog_binds_costs_only_with_reader_and_preserves_legacy_queries(tmp_path):
    baseline = trade_fixtures.FakeTradeBaseline()
    legacy_adapter = TradeScenarioSource(baseline)
    legacy_composite = CompositeSource(
        trade_fixtures.FakePrimary(trade_fixtures.live_context()),
        [legacy_adapter],
    )
    legacy_service = InformationService(legacy_composite, tmp_path / "legacy.sqlite3")
    inspector_calls = []

    def inspector(*args):
        inspector_calls.append(args)
        return {}

    service, composite, reader, adapter = _service_with_costs(tmp_path, inspector)
    try:
        assert FIELDS == ("expected_trade", "assumptions")
        legacy_entry = legacy_adapter.catalog()[0]
        legacy_topic = next(item for item in legacy_composite.catalog() if item["topic_id"] == "T06")
        assert set(legacy_entry["fields"]) == set(FIELDS)
        assert legacy_topic["fields"]["costs"]["coverage"] == "planned"
        assert "actions" not in legacy_entry["parameters"]["properties"]["scenarios"]["items"]["properties"]
        legacy_result = legacy_service.query(
            "trade-cost-legacy-no-actions",
            queries=[trade_fixtures.scenario_query([trade_fixtures.scenario("legacy")])],
        )
        assert _field(legacy_result, "expected_trade")["status"] == "known"
        assert len(baseline.read_calls) == 1

        bound_topic = next(item for item in composite.catalog() if item["topic_id"] == "T06")
        assert bound_topic["fields"]["costs"]["coverage"] == "partial"
        assert bound_topic["fields"]["costs"]["complete"] is False
        assert bound_topic["fields"]["costs"]["game_fact"] is False
        action_schema = bound_topic["parameters"]["properties"]["scenarios"]["items"]["properties"]["actions"]
        assert (action_schema["minItems"], action_schema["maxItems"]) == (1, 16)
        assert "actions" not in bound_topic["parameters"]["properties"]["scenarios"]["items"]["required"]

        # Cost-only selection still reads one baseline, but the cost reader is not called
        # when costs are not among the requested fields.
        no_actions = service.query(
            "trade-cost-bound-legacy-fields",
            queries=[trade_fixtures.scenario_query([trade_fixtures.scenario("without-actions")])],
        )
        assert _field(no_actions, "expected_trade")["status"] == "known"
        assert _field(no_actions, "assumptions")["status"] == "known"
        assert reader.read_calls == [{"node_id": NODE_ID, "context": trade_fixtures.live_context()}]
        assert inspector_calls == []

        unsupported = legacy_service.query(
            "trade-cost-unbound-field",
            queries=[trade_fixtures.scenario_query(
                [trade_fixtures.scenario("no-costs")], fields=["costs"],
            )],
        )
        assert _field(unsupported, "costs")["status"] == "unsupported"
        assert len(baseline.read_calls) == 1
    finally:
        legacy_service.close()
        service.close()


def test_date_drift_after_cost_preview_withdraws_all_requested_fields(tmp_path):
    reader = trade_fixtures.FakeTradeBaseline()

    def inspector(action_id, actor, recipient, phase, parameters):
        result = _preview(action_id, actor, recipient, phase, parameters)
        reader._context["game_date"] += 1
        reader._context["game_day"] += 1
        return result

    service, _composite, reader, _adapter = _service_with_costs(
        tmp_path, inspector, reader=reader,
    )
    try:
        result = service.query(
            "trade-cost-date-drift",
            queries=[_query(
                [_scenario("drift", actions=[action_fixtures._war_action("war")])],
                fields=["expected_trade", "costs"],
            )],
        )

        assert len(reader.read_calls) == 1
        for name in ("expected_trade", "costs"):
            field = _field(result, name)
            assert field["status"] == "unavailable"
            assert field["reason"] == "TRADE_SCENARIO_CONTEXT_CHANGED"
            assert "value" not in field
    finally:
        service.close()


def test_information_service_report_periodic_delivery_and_independent_cancel(tmp_path):
    now = [100.0]
    inspector_calls = []

    def inspector(action_id, actor, recipient, phase, parameters):
        inspector_calls.append((action_id, actor, recipient, phase, deepcopy(parameters)))
        return _preview(action_id, actor, recipient, phase, parameters)

    service, _composite, reader, _adapter = _service_with_costs(
        tmp_path, inspector, clock=lambda: now[0],
    )
    query = _query([
        _scenario("report-scenario", actions=[action_fixtures._war_action("report-war")]),
    ])
    subscriptions = []
    try:
        direct = service.query("trade-cost-report-direct", queries=[query])
        report = service.manage_report(
            "trade-cost-report-create",
            "create",
            config={"name": "Trade action costs", "queries": [query], "detail": "full"},
        )["report"]
        saved = service.query("trade-cost-report-read", report_id=report["id"])
        assert saved["items"][0]["query"] == query
        assert _field(direct, "costs") == _field(saved, "costs")

        for seconds in (2, 5):
            subscriptions.append(service.manage_subscription(
                f"trade-cost-subscription-{seconds}",
                "create",
                config={
                    "name": f"{seconds}s trade costs",
                    "kind": "periodic",
                    "report_id": report["id"],
                    "enabled": True,
                    "schedule": {"basis": "real", "every": seconds, "unit": "seconds", "missed": "coalesce"},
                },
            )["subscription"])

        assert service.tick()["results"] == []
        now[0] = 102.0
        fast_result = service.tick()["results"]
        assert len(fast_result) == 1
        fast = next(item for item in subscriptions if item["schedule"]["every"] == 2)
        slow = next(item for item in subscriptions if item["schedule"]["every"] == 5)
        assert fast_result[0]["subscription_id"] == fast["id"]
        assert _field(fast_result[0], "costs") == _field(saved, "costs")

        now[0] = 105.0
        due = service.tick()["results"]
        assert {item["subscription_id"] for item in due} == {fast["id"], slow["id"]}
        assert all(_field(item, "costs") == _field(saved, "costs") for item in due)

        cancelled = service.manage_subscription(
            "trade-cost-cancel-fast",
            "cancel",
            subscription_id=fast["id"],
            expected_version=fast["version"],
        )["subscription"]
        assert cancelled["state"] == "cancelled"
        assert service.manage_subscription(None, "get", subscription_id=slow["id"])["subscription"]["state"] == "active"

        now[0] = 110.0
        remaining = service.tick()["results"]
        assert len(remaining) == 1
        assert remaining[0]["subscription_id"] == slow["id"]
        assert _field(remaining[0], "costs") == _field(saved, "costs")
        assert len(reader.read_calls) == 6
        assert len(inspector_calls) == 6
    finally:
        for index, subscription in enumerate(subscriptions):
            current = service.manage_subscription(None, "get", subscription_id=subscription["id"])["subscription"]
            if current["state"] != "cancelled":
                service.manage_subscription(
                    f"trade-cost-cleanup-{index}",
                    "cancel",
                    subscription_id=current["id"],
                    expected_version=current["version"],
                )
        service.close()


def test_malformed_inspection_identity_withholds_action_cost_but_keeps_baseline(tmp_path):
    mode = ["submitted"]
    inspector_calls = []

    def inspector(action_id, actor, recipient, phase, parameters):
        inspector_calls.append((action_id, actor, recipient, phase, deepcopy(parameters)))
        inspected = _preview(action_id, actor, recipient, phase, parameters)
        if mode[0] == "submitted":
            inspected["submitted"] = True
        else:
            inspected["session"]["date_raw"] += 1
        return inspected

    service, _composite, reader, _adapter = _service_with_costs(tmp_path, inspector)
    try:
        for index, case in enumerate(("submitted", "date-mismatch")):
            mode[0] = "submitted" if case == "submitted" else "date-mismatch"
            result = service.query(
                f"trade-cost-invalid-inspection-identity-{index}",
                queries=[_query(
                    [_scenario("caller", actions=[action_fixtures._war_action("war")])],
                    fields=["expected_trade", "costs"],
                )],
            )

            assert _field(result, "expected_trade")["status"] == "known"
            costs = _field(result, "costs")
            assert costs["status"] == "known"
            action_costs = costs["value"]["scenarios"][0]["actions"][0]["costs"]
            assert action_costs == {
                "status": "unknown",
                "reason": "CANDIDATE_INSPECTION_IDENTITY_MISMATCH",
                "complete": False,
            }

        assert len(reader.read_calls) == 2
        assert len(inspector_calls) == 2
    finally:
        service.close()


def test_non_date_context_identity_drift_withdraws_all_requested_fields(tmp_path):
    drift_values = {
        "session_id": "replacement-session",
        "world_id": "replacement-world",
        "observer": "ENG",
        "game_sha256": "a" * 64,
    }

    for index, (key, changed_value) in enumerate(drift_values.items()):
        reader = trade_fixtures.FakeTradeBaseline()

        def inspector(action_id, actor, recipient, phase, parameters, *, key=key,
                      changed_value=changed_value, baseline_reader=reader):
            inspected = _preview(action_id, actor, recipient, phase, parameters)
            baseline_reader._context[key] = changed_value
            return inspected

        case_dir = tmp_path / f"context-drift-{index}"
        case_dir.mkdir()
        service, _composite, reader, _adapter = _service_with_costs(
            case_dir, inspector, reader=reader,
        )
        try:
            result = service.query(
                f"trade-cost-context-drift-{key}",
                queries=[_query(
                    [_scenario("drift", actions=[action_fixtures._war_action("war")])],
                    fields=["expected_trade", "costs"],
                )],
            )

            assert len(reader.read_calls) == 1
            for field_name in ("expected_trade", "costs"):
                field = _field(result, field_name)
                assert field["status"] == "unavailable"
                assert field["reason"] == "TRADE_SCENARIO_CONTEXT_CHANGED"
                assert "value" not in field
        finally:
            service.close()
