"""Port classification integration at the trade-target page boundary."""
from copy import deepcopy

from bridge.information.trade_scenarios import TradeScenarioSource
from bridge.information.trade_targets import TradeTargetsReader
from bridge.tests import test_information_trade_scenarios_integration as trade_fixtures
from bridge.tests import test_information_trade_targets as target_fixtures


NODE_ID = target_fixtures.NODE_ID
LIVE_CONTEXT = target_fixtures.LIVE_CONTEXT


def _port_result(
    query,
    context,
    *,
    status="known",
    has_port=False,
    reason="NATIVE_PORT_PREDICATE_UNKNOWN",
    provenance_province_id=None,
    source_changes=None,
):
    province_id = query["object"]["province_id"]
    field = {"status": status, "complete": False}
    if status == "known":
        field["value"] = {"province_id": province_id, "has_port": has_port}
    else:
        field["reason"] = reason
    source = {
        "name": "FakeNativeHasPortSource",
        "mode": "live",
        "status": "observed",
        "observer": "FRA",
        "session_id": context["session_id"],
        "complete": False,
        "provenance": {
            "province_id": (
                province_id if provenance_province_id is None else provenance_province_id
            ),
            "read_only": True,
        },
    }
    source.update(deepcopy(source_changes or {}))
    return {
        "topic": "G04",
        "fields": {"ports": field},
        "source": source,
        "game_date": context["game_date"],
        "objects": [deepcopy(query["object"])],
        "complete": False,
    }


class FakePortSource:
    def __init__(self, results=None, *, after_read=None):
        self.results = deepcopy(results or {})
        self.after_read = after_read
        self.read_calls = []

    def read(self, query, context):
        self.read_calls.append((deepcopy(query), deepcopy(context)))
        province_id = query["object"]["province_id"]
        response = deepcopy(self.results.get(province_id, {"status": "known", "has_port": False}))
        result = _port_result(query, context, **response)
        if self.after_read is not None:
            self.after_read(query, context)
        return result


def _reader(graph, province_source=None, port_source=None):
    return TradeTargetsReader(
        graph,
        province_source or target_fixtures.FakeProvinceSource(),
        port_source,
    )


def test_true_and_false_port_values_are_explicit_and_independent_of_coastal_cot():
    rows = [
        target_fixtures._member(183, 0),
        target_fixtures._member(184, 1),
    ]
    graph = target_fixtures.FakeTradeGraph(rows)
    annotations = target_fixtures._annotation_fields()
    annotations["center_of_trade"] = {
        "status": "known",
        "value": {"present": True, "level": 2, "kind": "coastal"},
        "partial": True,
        "complete": False,
    }
    province_source = target_fixtures.FakeProvinceSource(fields=annotations)
    port_source = FakePortSource({
        183: {"status": "known", "has_port": True},
        184: {"status": "known", "has_port": False},
    })
    reader = _reader(graph, province_source, port_source)

    result = reader.read(NODE_ID, LIVE_CONTEXT, {"offset": 0, "limit": 2})

    assert result["status"] == "known"
    value = result["value"]
    assert value["port_reads"] == 2
    assert value["province_reads"] == 2
    assert [row["province_id"] for row in value["rows"]] == [183, 184]
    for row, expected in zip(value["rows"], (True, False)):
        cot = row["current_annotations"]["fields"]["center_of_trade"]
        assert cot["value"]["kind"] == "coastal"
        port = row["classification"]["port"]
        assert port["status"] == "known"
        assert port["value"] is expected
        assert port["source"]["name"] == "FakeNativeHasPortSource"
        assert port["source"]["provenance"]["province_id"] == row["province_id"]
        assert port["game_date"] == LIVE_CONTEXT["game_date"]
        assert port["basis"] == "native_has_port_scope_predicate"
        assert port["partial"] is True and port["complete"] is False
        assert row["classification"]["estuary"]["status"] == "unknown"
        assert row["classification"]["eligibility"]["status"] == "unknown"
        assert row["classification"]["expected_benefit"]["status"] == "unknown"
    assert [
        (query["topic"], query["object"], query["fields"], query["parameters"])
        for query, _context in port_source.read_calls
    ] == [
        ("G04", {"type": "province", "province_id": 183}, ["ports"], {}),
        ("G04", {"type": "province", "province_id": 184}, ["ports"], {}),
    ]


def test_bad_port_identity_and_unknown_port_keep_other_target_and_baseline_fields():
    graph = target_fixtures.FakeTradeGraph([
        target_fixtures._member(183, 0),
        target_fixtures._member(184, 1),
    ])
    province_source = target_fixtures.FakeProvinceSource()
    port_source = FakePortSource({
        183: {
            "status": "known",
            "has_port": True,
            "provenance_province_id": 184,
        },
        184: {
            "status": "unknown",
            "reason": "NATIVE_PORT_VALUE_NOT_AVAILABLE",
        },
    })
    baseline = trade_fixtures.FakeTradeBaseline()
    target_reader = _reader(graph, province_source, port_source)
    source = TradeScenarioSource(baseline, target_reader=target_reader)

    result = source.read(
        target_fixtures._mixed_query(),
        baseline.context(),
    )

    assert result["fields"]["expected_trade"]["status"] == "known"
    targets = result["fields"]["targets"]
    assert targets["status"] == "known"
    assert targets["partial"] is True
    assert targets["value"]["port_reads"] == 2
    ports = [row["classification"]["port"] for row in targets["value"]["rows"]]
    assert ports[0]["status"] == "unknown"
    assert ports[0]["reason"] == "TRADE_TARGET_PORT_BINDING_INVALID"
    assert ports[1]["status"] == "unknown"
    assert ports[1]["reason"] == "NATIVE_PORT_VALUE_NOT_AVAILABLE"
    assert len(baseline.read_calls) == 1


def test_duplicate_members_share_one_port_read_per_page_but_not_across_reads():
    graph = target_fixtures.FakeTradeGraph([
        target_fixtures._member(183, 0),
        target_fixtures._member(183, 1),
    ])
    port_source = FakePortSource({183: {"status": "known", "has_port": True}})
    reader = _reader(graph, port_source=port_source)
    page = {"offset": 0, "limit": 2}

    first = reader.read(NODE_ID, LIVE_CONTEXT, page)
    second = reader.read(NODE_ID, LIVE_CONTEXT, page)

    assert first["value"]["port_reads"] == 1
    assert second["value"]["port_reads"] == 1
    assert [row["classification"]["port"]["value"] for row in first["value"]["rows"]] == [
        True,
        True,
    ]
    assert [row["classification"]["port"]["value"] for row in second["value"]["rows"]] == [
        True,
        True,
    ]
    assert len(port_source.read_calls) == 2
    assert [call[0]["object"]["province_id"] for call in port_source.read_calls] == [183, 183]


def test_context_drift_after_port_read_withdraws_target_field():
    baseline = trade_fixtures.FakeTradeBaseline()

    def drift_after_port(_query, _context):
        baseline._context["game_date"] += 1
        baseline._context["game_day"] += 1

    graph = target_fixtures.FakeTradeGraph([target_fixtures._member(183, 0)])
    port_source = FakePortSource(
        {183: {"status": "known", "has_port": True}},
        after_read=drift_after_port,
    )
    source = TradeScenarioSource(
        baseline,
        target_reader=_reader(graph, port_source=port_source),
    )

    result = source.read(
        target_fixtures._target_query(),
        baseline.context(),
    )

    targets = result["fields"]["targets"]
    assert targets["status"] == "unavailable"
    assert targets["reason"] == "TRADE_SCENARIO_CONTEXT_CHANGED"
    assert "value" not in targets
    assert baseline.read_calls == []
    assert len(port_source.read_calls) == 1
