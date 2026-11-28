from __future__ import annotations

from copy import deepcopy
from fractions import Fraction

import pytest

from bridge.information import InformationError
from bridge.information.trade_scenarios import TradeScenarioSource
from bridge.tests import test_information_trade_scenarios_integration as fixtures


POWER_MODEL = "province_source_fixed_other_inputs"
TOTAL_MODEL = "fixed_other_country_power"
COMPONENTS = {
    "multiplier_raw": 1000,
    "cap_raw": 1000,
    "base_raw": 1000,
    "subtract_raw": 0,
    "add_raw": 0,
}
MEMBERSHIP = {
    "status": "known",
    "basis": "native_global_country_power_sum_membership",
    "period": "current",
    "complete": False,
    "value": {
        "observer": "FRA",
        "country_slot": 42,
        "member_count": 256,
        "observer_occurrences": 1,
        "fullref_occurrences": 1,
        "slot_occurrences": 1,
        "observer_nonplayer_verified": True,
        "canonical_observer_verified": True,
        "stable": True,
    },
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


def _baseline(*, membership=None) -> dict:
    result = {
        "status": "known",
        "node_id": fixtures.NODE_ID,
        "fields": {
            "income": {**_scalar(1000, "ducats"), "eligible": True},
            "collection": {"status": "known", "value": True},
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
        "source": {"name": "FakeValidatedBaseline", "mode": "live", "observer": "FRA"},
        "complete": False,
    }
    if membership is not None:
        result["native_power_sum_membership"] = deepcopy(membership)
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
        "power_input_model": POWER_MODEL,
        "province_power_delta_raw": delta,
        "total_power_delta_raw": total_delta,
    }


def _automatic(identifier: str, delta: int = 0) -> dict:
    return {
        "id": identifier,
        "power_input_model": POWER_MODEL,
        "province_power_delta_raw": delta,
        "total_power_input_model": TOTAL_MODEL,
    }


def _query(scenarios, *, fields=None) -> dict:
    return {
        "topic": "T06",
        "object": {"type": "trade_node", "node_id": fixtures.NODE_ID},
        "fields": list(fields or ["expected_trade", "assumptions"]),
        "parameters": {"scenarios": deepcopy(scenarios)},
    }


class RichAutoBaseline:
    supports_native_power_components = True
    supports_native_power_sum = True

    def __init__(self, *, membership=None, change_context_on_read=False):
        self._context = fixtures.live_context()
        self.result = _baseline(membership=membership)
        self.change_context_on_read = change_context_on_read
        self.read_calls = []

    def context(self):
        return deepcopy(self._context)

    def read(self, node_id, context, **kwargs):
        self.read_calls.append({"node_id": node_id, "kwargs": deepcopy(kwargs)})
        result = deepcopy(self.result)
        result["node_id"] = node_id
        if self.change_context_on_read:
            self._context["session_id"] = "changed-during-read"
        return result


def _direct(source: TradeScenarioSource, scenarios, *, context=None):
    return source.read(_query(scenarios), context or source.context())


def _exact(money: dict) -> Fraction:
    raw = money["exact_raw"]
    return Fraction(int(raw["numerator"]), int(raw["denominator"]))


def test_public_service_mixes_all_three_forms_and_keeps_local_income_unknown(tmp_path):
    baseline = RichAutoBaseline(membership=MEMBERSHIP)
    now = [100.0]
    service, _composite, baseline = fixtures.make_service(
        tmp_path, reader=baseline, clock=lambda: now[0],
    )
    subscription = None
    scenarios = [
        _manual("manual", delta=100),
        _native("explicit-native-total", delta=50, total_delta=20),
        _automatic("auto-total", delta=100),
        # The country transition is still calculable; only this income row
        # leaves the model domain when its explicit total becomes zero.
        _native("income-outside-domain", delta=50, total_delta=-4000),
    ]
    try:
        result = service.query(
            "auto-total-public-mixed-forms",
            queries=[_query(scenarios)],
        )
        assert len(baseline.read_calls) == 1
        assert baseline.read_calls[0] == {
            "node_id": fixtures.NODE_ID,
            "kwargs": {"with_power_components": True, "with_sum_membership": True},
        }

        fields = result["items"][0]["fields"]
        expected = fields["expected_trade"]
        assert expected["status"] == "known"
        assert expected["complete"] is False and expected["game_fact"] is False
        rows = expected["value"]["scenarios"]
        assert [row["id"] for row in rows] == [row["id"] for row in scenarios]
        assert [row["inputs"] for row in rows] == scenarios
        assert [row["status"] for row in rows] == ["known", "known", "known", "unknown"]
        assert _exact(rows[0]["expected_income"]) == Fraction(1100)

        transitions = expected["native_power_scenarios"]
        assert [row["id"] for row in transitions] == [
            "explicit-native-total", "auto-total", "income-outside-domain",
        ]
        assert all(row["power_transition"]["status"] == "known" for row in transitions)
        automatic_transition = transitions[1]["power_transition"]["value"]
        assert automatic_transition["total_power_input_model"] == TOTAL_MODEL
        assert automatic_transition["country_power_delta_raw"] == 100
        assert automatic_transition["total_power_before_raw"] == 4000
        assert automatic_transition["total_power_after_raw"] == 4100
        assert automatic_transition["total_power_delta_raw"] == 100
        assert transitions[2]["power_transition"]["value"]["country_power_delta_raw"] == 50

        assumptions = fields["assumptions"]["value"]
        assert assumptions["total_power_input_model"] == TOTAL_MODEL
        assert assumptions["native_power_sum_membership"] == MEMBERSHIP
        assert assumptions["caller_scenarios"] == scenarios
        assert expected["value"]["actual_future_income"] == "unknown"

        report = service.manage_report(
            "auto-total-report-create",
            "create",
            config={"name": "Auto total scenario", "queries": [_query(scenarios)], "detail": "full"},
        )["report"]
        saved = service.query("auto-total-report-read", report_id=report["id"])
        assert saved["items"][0]["query"]["parameters"]["scenarios"] == scenarios
        assert saved["items"][0]["fields"] == fields

        subscription = service.manage_subscription(
            "auto-total-periodic-create",
            "create",
            config={
                "name": "Auto total scenario",
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
                    "auto-total-periodic-cancel",
                    "cancel",
                    subscription_id=current["id"],
                    expected_version=current["version"],
                )
        service.close()


@pytest.mark.parametrize(
    "mutation",
    [
        "missing",
        "duplicate",
        "role_false",
    ],
    ids=["missing-membership", "duplicate-observer", "observer-role-not-verified"],
)
def test_invalid_sum_gate_blocks_auto_only(mutation):
    membership = deepcopy(MEMBERSHIP)
    if mutation == "missing":
        membership = None
    elif mutation == "duplicate":
        membership["value"]["observer_occurrences"] = 2
    else:
        membership["value"]["canonical_observer_verified"] = False
    baseline = RichAutoBaseline(membership=membership)
    source = TradeScenarioSource(baseline)
    rows = [_manual("manual", delta=10), _native("explicit", delta=20, total_delta=3), _automatic("auto", delta=30)]

    result = _direct(source, rows)

    expected = result["fields"]["expected_trade"]
    assert expected["status"] == "known"
    projected = expected["value"]["scenarios"]
    assert [row["status"] for row in projected] == ["known", "known", "unknown"]
    transitions = expected["native_power_scenarios"]
    assert transitions[0]["id"] == "explicit"
    assert transitions[0]["power_transition"]["status"] == "known"
    assert transitions[1]["id"] == "auto"
    assert transitions[1]["power_transition"]["status"] == "unknown"
    assert transitions[1]["power_transition"]["reason"] == "BASELINE_POWER_SUM_MEMBERSHIP_UNKNOWN"


def test_sum_read_option_is_automatic_mode_only_and_requires_reader_support():
    baseline = RichAutoBaseline(membership=MEMBERSHIP)
    source = TradeScenarioSource(baseline)

    _direct(source, [_manual("manual")])
    _direct(source, [_native("explicit", delta=1, total_delta=2)])
    _direct(source, [_automatic("automatic", delta=1)])

    assert [call["kwargs"] for call in baseline.read_calls] == [
        {},
        {"with_power_components": True},
        {"with_power_components": True, "with_sum_membership": True},
    ]

    class ComponentsOnlyBaseline(RichAutoBaseline):
        supports_native_power_sum = False

    no_sum_reader = ComponentsOnlyBaseline(membership=None)
    no_sum_source = TradeScenarioSource(no_sum_reader)
    result = _direct(no_sum_source, [_automatic("not-requested", delta=1)])
    assert no_sum_reader.read_calls[0]["kwargs"] == {"with_power_components": True}
    transition = result["fields"]["expected_trade"]["native_power_scenarios"][0]["power_transition"]
    assert transition["status"] == "unknown"
    assert transition["reason"] == "BASELINE_POWER_SUM_MEMBERSHIP_UNKNOWN"


def test_old_reader_signature_is_attempted_once_without_typeerror_retry():
    class LegacyReader:
        supports_native_power_components = True
        supports_native_power_sum = True

        def __init__(self):
            self._context = fixtures.live_context()
            self.read_lookups = 0
            self.read_bodies = 0

        def context(self):
            return deepcopy(self._context)

        def __getattribute__(self, name):
            if name == "read":
                object.__setattr__(self, "read_lookups", object.__getattribute__(self, "read_lookups") + 1)
                return object.__getattribute__(self, "_legacy_read")
            return object.__getattribute__(self, name)

        def _legacy_read(self, node_id, context):
            self.read_bodies += 1
            return _baseline(membership=MEMBERSHIP)

    baseline = LegacyReader()
    result = _direct(TradeScenarioSource(baseline), [_automatic("old-signature", delta=1)])
    assert baseline.read_lookups == 1
    assert baseline.read_bodies == 0
    assert result["fields"]["expected_trade"]["status"] == "unavailable"
    assert result["fields"]["expected_trade"]["reason"] == "TRADE_SCENARIO_READ_FAILED"


def test_context_drift_withdraws_auto_projection():
    baseline = RichAutoBaseline(membership=MEMBERSHIP, change_context_on_read=True)
    result = _direct(TradeScenarioSource(baseline), [_automatic("drifting", delta=10)])
    expected = result["fields"]["expected_trade"]
    assumptions = result["fields"]["assumptions"]
    assert len(baseline.read_calls) == 1
    assert expected["status"] == assumptions["status"] == "unavailable"
    assert expected["reason"] == assumptions["reason"] == "TRADE_SCENARIO_CONTEXT_CHANGED"
    assert "value" not in expected and "value" not in assumptions


def test_targets_only_ignores_valid_auto_scenario_and_skips_baseline():
    baseline = RichAutoBaseline(membership=MEMBERSHIP)

    class TargetReader:
        def __init__(self):
            self.calls = []

        def read(self, node_id, context, page):
            self.calls.append((node_id, deepcopy(page)))
            return {"status": "known", "value": {"rows": []}, "complete": False}

    target = TargetReader()
    source = TradeScenarioSource(baseline, target_reader=target)
    query = {
        "topic": "T06",
        "object": {"type": "trade_node", "node_id": fixtures.NODE_ID},
        "fields": ["targets"],
        "parameters": {
            "scenarios": [_automatic("valid-but-unused", delta=10)],
            "target_page": {"offset": 0, "limit": 1},
        },
    }

    result = source.read(query, baseline.context())

    assert result["fields"]["targets"]["status"] == "known"
    assert baseline.read_calls == []
    assert target.calls == [(fixtures.NODE_ID, {"offset": 0, "limit": 1})]
    assert result["source"]["provenance"]["baseline_reads"] == 0


def test_public_schema_accepts_three_forms_and_rejects_mixed_invalid_forms(tmp_path):
    baseline = RichAutoBaseline(membership=MEMBERSHIP)
    service, composite, baseline = fixtures.make_service(tmp_path, reader=baseline)
    valid_rows = [_manual("manual"), _native("native", delta=1, total_delta=2), _automatic("automatic", delta=3)]
    try:
        topic = next(item for item in composite.catalog() if item["topic_id"] == "T06")
        item_schema = topic["parameters"]["properties"]["scenarios"]["items"]
        assert set(item_schema["required"]) == {"id"}
        assert [set(branch["required"]) for branch in item_schema["oneOf"]] == [
            {"country_power_delta_raw", "total_power_delta_raw"},
            {"power_input_model", "province_power_delta_raw", "total_power_delta_raw"},
            {"power_input_model", "province_power_delta_raw", "total_power_input_model"},
        ]
        assert item_schema["properties"]["total_power_input_model"] == {
            "type": "string", "const": TOTAL_MODEL, "enum": [TOTAL_MODEL],
        }
        service.query("auto-total-schema-three-valid", queries=[_query(valid_rows)])

        invalid_rows = [
            {"id": "manual-auto", "country_power_delta_raw": 1,
             "total_power_delta_raw": 0, "total_power_input_model": TOTAL_MODEL},
            {"id": "mixed-total", "power_input_model": POWER_MODEL,
             "province_power_delta_raw": 1, "total_power_delta_raw": 0,
             "total_power_input_model": TOTAL_MODEL},
            {"id": "bool-delta", "power_input_model": POWER_MODEL,
             "province_power_delta_raw": True, "total_power_input_model": TOTAL_MODEL},
            {"id": "unknown-total-model", "power_input_model": POWER_MODEL,
             "province_power_delta_raw": 1, "total_power_input_model": "other"},
            {"id": "unknown-power-model", "power_input_model": "other",
             "province_power_delta_raw": 1, "total_power_delta_raw": 0},
            {"id": "orphan-native-delta", "province_power_delta_raw": 1,
             "total_power_delta_raw": 0},
        ]
        for index, row in enumerate(invalid_rows):
            with pytest.raises(InformationError) as invalid:
                service.query(
                    f"auto-total-schema-invalid-{index}",
                    queries=[_query([row], fields=["expected_trade"])],
                )
            assert invalid.value.code == "invalid_parameters"
        assert len(baseline.read_calls) == 1
    finally:
        service.close()
