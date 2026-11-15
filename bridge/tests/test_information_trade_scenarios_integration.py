"""T06 trade scenarios through the real composite and information service."""
from copy import deepcopy
from fractions import Fraction

import pytest

from bridge.information import InformationError, InformationService
from bridge.information.catalog import get_topic
from bridge.information.composite import CompositeSource
from bridge.information.trade_scenarios import TradeScenarioSource


NODE_ID = "english_channel"
SESSION_ID = "trade-scenario-session"
GAME_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"


def live_context(**overrides):
    context = {
        "status": "ready",
        "mode": "live",
        "observer": "FRA",
        "game_version": "1.37.4",
        "game_sha256": GAME_SHA256,
        "session_id": SESSION_ID,
        "world_id": "trade-world",
        "game_date": 56560344,
        "game_day": 56560344,
    }
    context.update(overrides)
    return context


def _scalar(raw, unit):
    return {
        "status": "known",
        "raw": raw,
        "value": raw,
        "unit": unit,
        "scale": 1000,
    }


def baseline_result(*, income=1000, country_power=2000, total_power=4000,
                    eligible=True, collecting=True):
    fields = {
        "income": {**_scalar(income, "ducats"), "eligible": eligible},
        "collection": {"status": "known", "value": collecting},
        "country_power": _scalar(country_power, "trade_power"),
        "total_power": _scalar(total_power, "trade_power"),
    }
    return {
        "status": "known",
        "fields": fields,
        "source": {"name": "FakeTradeBaseline", "mode": "live", "observer": "FRA"},
        "complete": False,
    }


def scenario(identifier, country_delta=0, total_delta=0, **extra):
    return {
        "id": identifier,
        "country_power_delta_raw": country_delta,
        "total_power_delta_raw": total_delta,
        **extra,
    }


def scenario_query(scenarios, *, fields=None, object_=None):
    return {
        "topic": "T06",
        "object": deepcopy(object_ or {"type": "trade_node", "node_id": NODE_ID}),
        "fields": list(fields or ["expected_trade", "assumptions"]),
        "parameters": {"scenarios": deepcopy(scenarios)},
    }


class FakePrimary:
    event_types = ()

    def __init__(self, context):
        self._context = deepcopy(context)

    def context(self):
        return deepcopy(self._context)

    def catalog(self):
        return [get_topic("T06")]

    def read(self, query, context):
        raise AssertionError("T06 must be routed to TradeScenarioSource")

    def poll_events(self, context, cursor):
        return {"events": [], "cursor": cursor or {}, "complete": True, "gaps": []}


class FakeTradeBaseline:
    def __init__(self, context=None, result=None):
        self._context = deepcopy(context or live_context())
        self.result = deepcopy(result or baseline_result())
        self.read_calls = []

    def context(self):
        return deepcopy(self._context)

    def read(self, node_id, context):
        self.read_calls.append({"node_id": node_id, "context": deepcopy(context)})
        return deepcopy(self.result)


def make_service(tmp_path, *, reader=None, clock=None, observer="FRA"):
    reader = reader or FakeTradeBaseline(context=live_context(observer=observer))
    primary = FakePrimary(live_context(observer=observer))
    adapter = TradeScenarioSource(reader)
    composite = CompositeSource(primary, [adapter])
    service = InformationService(
        composite,
        tmp_path / "trade-scenarios.sqlite3",
        clock=clock,
    )
    return service, composite, reader


def _field(result, name):
    return result["items"][0]["fields"][name]


def _exact(money):
    exact = money["exact_raw"]
    return Fraction(int(exact["numerator"]), int(exact["denominator"]))


def test_mixed_t06_query_uses_one_baseline_and_keeps_partial_scenario_results(tmp_path):
    reader = FakeTradeBaseline()
    service, _composite, reader = make_service(tmp_path, reader=reader)
    scenarios = [
        scenario("gain", country_delta=1000),
        scenario("dilution", total_delta=2000),
        # The input is well-formed, but P' would exceed T'.
        scenario("outside-domain", country_delta=3000),
    ]
    try:
        result = service.query(
            "trade-scenario-mixed-query",
            queries=[scenario_query(scenarios)],
        )

        assert len(reader.read_calls) == 1
        assert reader.read_calls[0]["node_id"] == NODE_ID
        fields = result["items"][0]["fields"]
        expected = fields["expected_trade"]
        assumptions = fields["assumptions"]
        assert expected["status"] == "known"
        assert expected["complete"] is False
        assert expected["game_fact"] is False
        value = expected["value"]
        assert value["schema"] == "information.trade_power_scenarios.v1"
        assert value["baseline"] == baseline_result()["fields"]
        assert value["actual_future_income"] == "unknown"
        assert value["game_fact"] is False
        assert value["complete"] is False

        rows = {row["id"]: row for row in value["scenarios"]}
        assert [rows[item["id"]]["status"] for item in scenarios] == [
            "known", "known", "unknown",
        ]
        assert _exact(rows["gain"]["expected_income"]) == Fraction(1500)
        assert rows["gain"]["expected_income"]["decimal"] == "1.500000"
        assert rows["gain"]["expected_income"]["unit"] == "ducats"
        assert rows["gain"]["expected_income"]["scale"] == 1000
        assert _exact(rows["gain"]["income_delta"]) == Fraction(500)
        assert _exact(rows["dilution"]["expected_income"]) == Fraction(2000, 3)
        assert _exact(rows["dilution"]["income_delta"]) == Fraction(-1000, 3)
        assert rows["dilution"]["expected_income"]["decimal"] == "0.666667"
        assert "expected_income" not in rows["outside-domain"]
        assert "income_delta" not in rows["outside-domain"]

        assert assumptions["status"] == "known"
        assert assumptions["game_fact"] is False
        modeled = assumptions["value"]
        assert modeled["baseline"] == baseline_result()["fields"]
        assert modeled["caller_scenarios"] == scenarios
        assert modeled["collection_policy"] == baseline_result()["fields"]["collection"]
        factor = modeled["calibrated_income_factor_raw"]
        assert factor["status"] == "known"
        assert factor["exact_raw"] == {"numerator": "2000", "denominator": "1"}
        assert factor["unit"] == "ducats"
        assert factor["scale"] == 1000
        assert factor["native_node_value_or_efficiency"] is False
        components = {item["component"]: item for item in modeled["unmeasured_fixed_components"]}
        assert set(components) == {"node_value", "inflows_outflows", "trade_efficiency"}
        assert all(item["status"] == "unknown" for item in components.values())
        assert all(item["model_treatment"] == "held_fixed_not_measured" for item in components.values())
        assert all("value" not in item for item in components.values())
    finally:
        service.close()


@pytest.mark.parametrize(
    "baseline",
    [
        {"status": "unknown", "reason": "NO_TRADE_BASELINE", "fields": {}, "complete": False},
        baseline_result(eligible=False),
        baseline_result(collecting=False),
        baseline_result(country_power=0),
    ],
    ids=["missing", "ineligible", "not-collecting", "zero-country-power"],
)
def test_missing_or_uncalibratable_baseline_never_fabricates_income(tmp_path, baseline):
    reader = FakeTradeBaseline(result=baseline)
    service, _composite, reader = make_service(tmp_path, reader=reader)
    try:
        result = service.query(
            "trade-scenario-unknown-baseline",
            queries=[scenario_query([scenario("try-growth", country_delta=500)])],
        )
        expected = _field(result, "expected_trade")
        assert len(reader.read_calls) == 1
        assert expected["status"] == "unknown"
        assert "value" not in expected
        assert "actual_future_income" not in expected
    finally:
        service.close()


def test_report_update_is_atomic_and_two_periodic_subscriptions_share_updated_query(tmp_path):
    now = [100.0]
    service, _composite, reader = make_service(tmp_path, clock=lambda: now[0])
    original_query = scenario_query([scenario("original", country_delta=1000)])
    updated_scenarios = [scenario("updated-competitor-growth", total_delta=1000)]
    updated_query = scenario_query(updated_scenarios)
    subscriptions = []
    try:
        direct = service.query(
            "trade-scenario-direct-reference",
            queries=[original_query],
        )
        assert len(reader.read_calls) == 1
        assert [row["id"] for row in _field(direct, "expected_trade")["value"]["scenarios"]] == [
            "original",
        ]

        created = service.manage_report(
            "trade-scenario-report-create",
            "create",
            config={"name": "Trade scenario", "queries": [original_query], "detail": "full"},
        )["report"]
        assert created["queries"] == [original_query]

        invalid_query = deepcopy(updated_query)
        invalid_query["parameters"]["scenarios"][0]["country_power_delta_raw"] = True
        invalid_config = {
            "name": "Invalid trade scenario",
            "queries": [invalid_query],
            "detail": "full",
        }
        with pytest.raises(InformationError) as invalid:
            service.manage_report(
                "trade-scenario-report-invalid-update",
                "update",
                report_id=created["id"],
                config=invalid_config,
                expected_version=created["version"],
            )
        assert invalid.value.code == "invalid_parameters"
        unchanged = service.manage_report(None, "get", report_id=created["id"])["report"]
        assert unchanged == created

        updated = service.manage_report(
            "trade-scenario-report-valid-update",
            "update",
            report_id=created["id"],
            config={"name": "Trade scenario updated", "queries": [updated_query], "detail": "full"},
            expected_version=created["version"],
        )["report"]
        assert updated["version"] == created["version"] + 1
        assert updated["queries"] == [updated_query]

        saved_read = service.query("trade-scenario-report-read", report_id=created["id"])
        assert saved_read["items"][0]["query"] == updated_query
        expected_reference = _field(saved_read, "expected_trade")
        assert [row["id"] for row in expected_reference["value"]["scenarios"]] == [
            "updated-competitor-growth",
        ]

        for seconds in (2, 5):
            subscriptions.append(service.manage_subscription(
                f"trade-scenario-subscription-{seconds}",
                "create",
                config={
                    "name": f"{seconds}s trade scenario",
                    "kind": "periodic",
                    "report_id": updated["id"],
                    "enabled": True,
                    "schedule": {"basis": "real", "every": seconds, "unit": "seconds", "missed": "coalesce"},
                },
            )["subscription"])

        assert service.tick()["results"] == []
        now[0] = 102.0
        two_second = service.tick()["results"]
        assert len(two_second) == 1
        fast = next(item for item in subscriptions if item["schedule"]["every"] == 2)
        slow = next(item for item in subscriptions if item["schedule"]["every"] == 5)
        assert two_second[0]["subscription_id"] == fast["id"]
        assert two_second[0]["items"][0]["fields"] == saved_read["items"][0]["fields"]

        now[0] = 105.0
        both_due = service.tick()["results"]
        assert {item["subscription_id"] for item in both_due} == {fast["id"], slow["id"]}
        assert all(item["items"][0]["fields"] == saved_read["items"][0]["fields"] for item in both_due)

        cancelled = service.manage_subscription(
            "trade-scenario-cancel-fast",
            "cancel",
            subscription_id=fast["id"],
            expected_version=fast["version"],
        )["subscription"]
        assert cancelled["state"] == "cancelled"
        active_slow = service.manage_subscription(None, "get", subscription_id=slow["id"])["subscription"]
        assert active_slow["state"] == "active"

        now[0] = 110.0
        remaining = service.tick()["results"]
        assert len(remaining) == 1
        assert remaining[0]["subscription_id"] == slow["id"]
        assert remaining[0]["items"][0]["fields"] == saved_read["items"][0]["fields"]
        # One baseline read per query result, although each result contains both T06 fields.
        assert len(reader.read_calls) == 6
    finally:
        for index, subscription in enumerate(subscriptions):
            current = service.manage_subscription(None, "get", subscription_id=subscription["id"])["subscription"]
            if current["state"] != "cancelled":
                service.manage_subscription(
                    f"trade-scenario-cleanup-{index}",
                    "cancel",
                    subscription_id=current["id"],
                    expected_version=current["version"],
                )
        service.close()


def test_catalog_keeps_unowned_t06_fields_planned_and_rejects_bad_scope_or_parameters(tmp_path):
    service, composite, reader = make_service(tmp_path)
    try:
        topic = next(item for item in composite.catalog() if item["topic_id"] == "T06")
        assert topic["fields"]["expected_trade"]["coverage"] == "partial"
        assert topic["fields"]["assumptions"]["coverage"] == "partial"
        assert topic["fields"]["targets"]["coverage"] == "planned"
        assert topic["fields"]["costs"]["coverage"] == "planned"
        assert topic["parameters"]["required"] == ["scenarios"]
        scenario_schema = topic["parameters"]["properties"]["scenarios"]
        assert (scenario_schema["minItems"], scenario_schema["maxItems"]) == (1, 8)
        item_schema = scenario_schema["items"]
        assert set(item_schema["required"]) == {"id"}
        assert [set(branch["required"]) for branch in item_schema["oneOf"]] == [
            {"country_power_delta_raw", "total_power_delta_raw"},
            {"power_input_model", "province_power_delta_raw", "total_power_delta_raw"},
            {"power_input_model", "province_power_delta_raw", "total_power_input_model"},
        ]
        assert item_schema["properties"]["power_input_model"] == {
            "type": "string",
            "const": "province_source_fixed_other_inputs",
            "enum": ["province_source_fixed_other_inputs"],
        }
        assert item_schema["properties"]["description"]["maxLength"] == 512

        valid_scenarios = [scenario("one")]
        for index, parameters in enumerate((
            {},
            {"scenarios": []},
            {"scenarios": [scenario("bool-is-not-int", country_delta=True)]},
            {"scenarios": [scenario(f"many-{i}") for i in range(9)]},
            {"scenarios": [scenario("long-description", description="x" * 513)]},
        )):
            with pytest.raises(InformationError) as invalid:
                service.query(
                    f"trade-scenario-invalid-parameters-{index}",
                    queries=[{
                        "topic": "T06",
                        "object": {"type": "trade_node", "node_id": NODE_ID},
                        "fields": ["expected_trade"],
                        "parameters": parameters,
                    }],
                )
            assert invalid.value.code == "invalid_parameters"

        with pytest.raises(InformationError) as bad_object:
            service.query(
                "trade-scenario-unsupported-object",
                queries=[scenario_query(valid_scenarios, object_={"type": "country", "country": "FRA"})],
            )
        assert bad_object.value.code == "invalid_object"

        unsupported = service.query(
            "trade-scenario-unowned-target-field",
            queries=[scenario_query(valid_scenarios, fields=["targets"])],
        )
        assert _field(unsupported, "targets")["status"] == "unsupported"
        assert reader.read_calls == []
    finally:
        service.close()

    wrong_observer_reader = FakeTradeBaseline(context=live_context(observer="ENG"))
    wrong_observer_service, _composite, wrong_observer_reader = make_service(
        tmp_path / "wrong-observer", reader=wrong_observer_reader, observer="ENG",
    )
    try:
        result = wrong_observer_service.query(
            "trade-scenario-wrong-observer",
            queries=[scenario_query([scenario("wrong-observer")])],
        )
        expected = _field(result, "expected_trade")
        assert expected["status"] == "unavailable"
        assert "value" not in expected
        assert wrong_observer_reader.read_calls == []
    finally:
        wrong_observer_service.close()
