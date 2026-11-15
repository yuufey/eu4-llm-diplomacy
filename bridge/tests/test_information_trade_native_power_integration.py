from __future__ import annotations

from copy import deepcopy
from fractions import Fraction

import pytest

from bridge.information import InformationError
from bridge.information.trade_scenarios import TradeScenarioSource
from bridge.tests import test_information_trade_scenarios_integration as fixtures


MODEL = "province_source_fixed_other_inputs"
COMPONENTS = {
    "multiplier_raw": 1000,
    "cap_raw": 1000,
    "base_raw": 1000,
    "subtract_raw": 0,
    "add_raw": 0,
}


def _scalar(raw: int, unit: str) -> dict:
    return {
        "status": "known",
        "raw": raw,
        "value": raw,
        "unit": unit,
        "scale": 1000,
        "period": "current",
    }


def _baseline(*, collecting: bool = True) -> dict:
    return {
        "status": "known",
        "node_id": fixtures.NODE_ID,
        "fields": {
            "income": {
                **_scalar(1000, "ducats"),
                "eligible": collecting,
            },
            "collection": {"status": "known", "value": collecting},
            "country_power": _scalar(1000, "trade_power"),
            "total_power": _scalar(4000, "trade_power"),
        },
        "native_power_components": {
            "status": "known",
            "value": deepcopy(COMPONENTS),
            "basis": "native_trade_node_power_caches",
            "scale": 1000,
            "period": "current",
            "complete": False,
        },
        "source": {"name": "FixtureBaseline", "mode": "live", "observer": "FRA"},
        "complete": False,
    }


class RichBaseline:
    supports_native_power_components = True

    def __init__(self, *, collecting: bool = True):
        self._context = fixtures.live_context()
        self.result = _baseline(collecting=collecting)
        self.read_calls = []

    def context(self):
        return deepcopy(self._context)

    def read(self, node_id, context, **kwargs):
        self.read_calls.append({"node_id": node_id, "kwargs": deepcopy(kwargs)})
        result = deepcopy(self.result)
        result["node_id"] = node_id
        if kwargs.get("with_power_components") is not True:
            result.pop("native_power_components", None)
        return result


class LegacyBaseline:
    """A custom reader whose exact signature must remain supported."""

    def __init__(self):
        self._context = fixtures.live_context()
        self.read_calls = []

    def context(self):
        return deepcopy(self._context)

    def read(self, node_id, context):
        self.read_calls.append((node_id, deepcopy(context)))
        result = _baseline()
        result.pop("native_power_components", None)
        return result


def _manual(identifier: str, delta: int = 0, total_delta: int = 0) -> dict:
    return {
        "id": identifier,
        "country_power_delta_raw": delta,
        "total_power_delta_raw": total_delta,
    }


def _native(identifier: str, delta: int = 0, total_delta: int = 0) -> dict:
    return {
        "id": identifier,
        "power_input_model": MODEL,
        "province_power_delta_raw": delta,
        "total_power_delta_raw": total_delta,
    }


def _query(scenarios, *, fields=None) -> dict:
    return {
        "topic": "T06",
        "object": {"type": "trade_node", "node_id": fixtures.NODE_ID},
        "fields": list(fields or ["expected_trade", "assumptions"]),
        "parameters": {"scenarios": deepcopy(scenarios)},
    }


def _exact(money: dict) -> Fraction:
    raw = money["exact_raw"]
    return Fraction(int(raw["numerator"]), int(raw["denominator"]))


def test_public_mixed_manual_and_native_query_preserves_order_and_local_unknown(tmp_path):
    baseline = RichBaseline()
    now = [100.0]
    service, _composite, baseline = fixtures.make_service(
        tmp_path, reader=baseline, clock=lambda: now[0],
    )
    subscription = None
    scenarios = [
        _manual("manual", delta=10),
        _native("native", delta=20),
        # The power transition is calculable; this caller supplied total delta
        # makes only the income row leave the model domain.
        _native("local-unknown", delta=30, total_delta=-4000),
    ]
    query = _query(scenarios)
    try:
        result = service.query("native-power-mixed-public-query", queries=[query])

        assert baseline.read_calls == [{
            "node_id": fixtures.NODE_ID,
            "kwargs": {"with_power_components": True},
        }]
        fields = result["items"][0]["fields"]
        expected = fields["expected_trade"]
        assert expected["status"] == "known"
        rows = expected["value"]["scenarios"]
        assert [row["id"] for row in rows] == [row["id"] for row in scenarios]
        assert [row["inputs"] for row in rows] == scenarios
        assert [row["status"] for row in rows] == ["known", "known", "unknown"]
        assert _exact(rows[0]["expected_income"]) == Fraction(1010)
        assert _exact(rows[1]["expected_income"]) == Fraction(1020)
        assert rows[2]["reason"] == "SCENARIO_POWER_OUTSIDE_MODEL_DOMAIN"

        transitions = expected["native_power_scenarios"]
        assert [row["id"] for row in transitions] == ["native", "local-unknown"]
        assert [row["inputs"] for row in transitions] == [scenarios[1], scenarios[2]]
        assert all(row["power_transition"]["status"] == "known" for row in transitions)
        assert transitions[0]["power_transition"]["value"]["country_power_delta_raw"] == 20
        assert transitions[0]["power_transition"]["value"]["total_power_delta_raw"] == 0
        assert expected["game_fact"] is False
        assert expected["complete"] is False

        # Reports and periodic execution validate and reuse the same native
        # scenario schema through the service's normal query path.
        report = service.manage_report(
            "native-power-report-create",
            "create",
            config={"name": "Native power scenario", "queries": [query], "detail": "full"},
        )["report"]
        saved = service.query("native-power-report-read", report_id=report["id"])
        assert saved["items"][0]["query"]["parameters"]["scenarios"] == scenarios
        assert [row["id"] for row in saved["items"][0]["fields"]["expected_trade"]["value"]["scenarios"]] == [
            "manual", "native", "local-unknown",
        ]

        subscription = service.manage_subscription(
            "native-power-periodic-create",
            "create",
            config={
                "name": "Native power scenario",
                "kind": "periodic",
                "report_id": report["id"],
                "enabled": True,
                "schedule": {"basis": "real", "every": 2, "unit": "seconds", "missed": "coalesce"},
            },
        )["subscription"]
        assert service.tick()["results"] == []
        now[0] = 102.0
        periodic = service.tick()["results"]
        assert len(periodic) == 1
        assert periodic[0]["subscription_id"] == subscription["id"]
        assert periodic[0]["items"][0]["fields"] == saved["items"][0]["fields"]
        assert len(baseline.read_calls) == 3
    finally:
        if subscription is not None:
            current = service.manage_subscription(
                None, "get", subscription_id=subscription["id"],
            )["subscription"]
            if current["state"] != "cancelled":
                service.manage_subscription(
                    "native-power-periodic-cancel",
                    "cancel",
                    subscription_id=current["id"],
                    expected_version=current["version"],
                )
        service.close()


def test_native_reader_option_is_opt_in_and_targets_only_skips_baseline():
    baseline = RichBaseline()
    source = TradeScenarioSource(baseline)

    manual_result = source.read(_query([_manual("manual")]), baseline.context())
    assert manual_result["fields"]["expected_trade"]["status"] == "known"
    assert baseline.read_calls[-1]["kwargs"] == {}

    native_result = source.read(_query([_native("native")]), baseline.context())
    assert baseline.read_calls[-1]["kwargs"] == {"with_power_components": True}
    assert native_result["fields"]["expected_trade"]["native_power_scenarios"][0]["power_transition"]["status"] == "known"

    class TargetReader:
        def __init__(self):
            self.read_calls = []

        def read(self, node_id, context, page):
            self.read_calls.append((node_id, deepcopy(page)))
            return {"status": "known", "value": {"rows": []}, "complete": False}

    target = TargetReader()
    target_source = TradeScenarioSource(baseline, target_reader=target)
    calls_before = len(baseline.read_calls)
    target_result = target_source.read({
        "topic": "T06",
        "object": {"type": "trade_node", "node_id": fixtures.NODE_ID},
        "fields": ["targets"],
        "parameters": {"target_page": {"offset": 0, "limit": 1}},
    }, baseline.context())
    assert target_result["fields"]["targets"]["status"] == "known"
    assert len(baseline.read_calls) == calls_before
    assert target.read_calls == [(fixtures.NODE_ID, {"offset": 0, "limit": 1})]


def test_legacy_custom_reader_gets_one_call_without_new_keyword():
    baseline = LegacyBaseline()
    source = TradeScenarioSource(baseline)

    result = source.read(_query([_native("native")]), baseline.context())

    assert len(baseline.read_calls) == 1
    expected = result["fields"]["expected_trade"]
    assert expected["status"] == "unknown"
    assert expected["native_power_scenarios"][0]["power_transition"]["status"] == "unknown"


def test_native_power_transition_survives_noncollecting_income_baseline():
    baseline = RichBaseline(collecting=False)
    source = TradeScenarioSource(baseline)

    result = source.read(_query([_native("still-known", delta=20)]), baseline.context())

    expected = result["fields"]["expected_trade"]
    assert expected["status"] == "unknown"
    assert "value" not in expected
    transition = expected["native_power_scenarios"][0]["power_transition"]
    assert transition["status"] == "known"
    assert transition["value"]["country_power_delta_raw"] == 20


def test_public_schema_accepts_both_forms_and_rejects_mixed_or_invalid_rows(tmp_path):
    baseline = RichBaseline()
    service, composite, baseline = fixtures.make_service(tmp_path, reader=baseline)
    try:
        topic = next(item for item in composite.catalog() if item["topic_id"] == "T06")
        item_schema = topic["parameters"]["properties"]["scenarios"]["items"]
        assert set(item_schema["required"]) == {"id"}
        assert [set(branch["required"]) for branch in item_schema["oneOf"]] == [
            {"country_power_delta_raw", "total_power_delta_raw"},
            {"power_input_model", "province_power_delta_raw", "total_power_delta_raw"},
            {"power_input_model", "province_power_delta_raw", "total_power_input_model"},
        ]
        assert item_schema["properties"]["power_input_model"]["type"] == "string"

        # Exercise the public InformationService schema validator as well as
        # TradeScenarioSource's stricter oneOf branch checks.
        for request_id, row in (
            ("native-schema-manual", _manual("manual")),
            ("native-schema-derived", _native("derived", delta=1)),
        ):
            service.query(request_id, queries=[_query([row], fields=["expected_trade"])])

        invalid_rows = [
            {
                "id": "mixed",
                "country_power_delta_raw": 1,
                "power_input_model": MODEL,
                "province_power_delta_raw": 1,
                "total_power_delta_raw": 0,
            },
            {"id": "bool", "power_input_model": MODEL,
             "province_power_delta_raw": True, "total_power_delta_raw": 0},
            {"id": "orphan", "province_power_delta_raw": 1,
             "total_power_delta_raw": 0},
            {"id": "unknown-model", "power_input_model": "other",
             "province_power_delta_raw": 1, "total_power_delta_raw": 0},
        ]
        for index, row in enumerate(invalid_rows):
            with pytest.raises(InformationError) as invalid:
                service.query(
                    f"native-schema-invalid-{index}",
                    queries=[_query([row], fields=["expected_trade"])],
                )
            assert invalid.value.code == "invalid_parameters"
        # Invalid selectors are rejected before either valid call reaches the
        # reader; the two accepted public queries each make exactly one read.
        assert len(baseline.read_calls) == 2
    finally:
        service.close()
