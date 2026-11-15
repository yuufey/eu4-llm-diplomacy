"""Paginated static trade-node members with separately qualified G02 notes."""
from copy import deepcopy

import pytest

from bridge.information import InformationError, InformationService
from bridge.information.composite import CompositeSource
from bridge.information.trade_scenarios import FIELDS, TradeScenarioSource
from bridge.information.trade_targets import TradeTargetsReader
from bridge.tests import test_information_trade_scenarios_integration as trade_fixtures


NODE_ID = trade_fixtures.NODE_ID
LIVE_CONTEXT = trade_fixtures.live_context()


def _static_context(**changes):
    context = {
        "status": "ready",
        "mode": "static",
        "context_scope": "static_rules",
        "game_version": "1.37.4",
        "game_sha256": trade_fixtures.GAME_SHA256,
        "definitions_sha256": "1" * 64,
        "trade_definitions_sha256": "2" * 64,
        "configuration_sha256": "3" * 64,
        "definition_files": ["common/tradenodes/00_tradenodes.txt"],
        "configuration_files": [],
        "enabled_mods": [],
        "trade_directory_members": {"common/tradenodes": ["00_tradenodes.txt"]},
    }
    context.update(changes)
    return context


def _member(province_id, ordinal):
    return {
        "node_id": NODE_ID,
        "province_id": province_id,
        "membership_kind": "member",
        "source_rule": f"member-{ordinal}",
        "ordinal": ordinal,
    }


def _graph_result(rows, *, node_id=NODE_ID):
    return {
        "status": "known",
        "rows": deepcopy(rows),
        "topology": {"node_id": node_id, "member_count": len(rows), "routes": []},
        "source": {
            "name": "FakeStaticTradeGraph",
            "mode": "static",
            "status": "observed",
            "context_scope": "static_rules",
            "game_version": "1.37.4",
            "game_sha256": trade_fixtures.GAME_SHA256,
            "trade_definitions_sha256": "2" * 64,
            "configuration_sha256": "3" * 64,
        },
        "complete": False,
    }


class FakeTradeGraph:
    def __init__(self, rows, *, context=None, result=None, error=None, after_read=None):
        self._context = deepcopy(context or _static_context())
        self.result = deepcopy(result or _graph_result(rows))
        self.error = error
        self.after_read = after_read
        self.read_calls = []

    def context(self):
        return deepcopy(self._context)

    def read(self, node_id, context):
        self.read_calls.append((node_id, deepcopy(context)))
        if self.error is not None:
            raise self.error
        result = deepcopy(self.result)
        if self.after_read is not None:
            self.after_read(self)
        return result


def _annotation_fields():
    return {
        "owner": {"status": "known", "value": "FRA", "partial": True, "complete": False},
        "controller": {"status": "unknown", "reason": "PROVINCE_CONTROLLER_UNKNOWN",
                        "partial": True, "complete": False},
        "center_of_trade": {"status": "known", "value": {"present": False, "level": 0},
                            "partial": True, "complete": False},
    }


class FakeProvinceSource:
    """Small public G02-shaped reader for paging and failure isolation cases."""

    def __init__(self, *, fields=None, error=None, after_read=None, identity_overrides=None):
        self.fields = deepcopy(fields or _annotation_fields())
        self.error = error
        self.after_read = after_read
        self.identity_overrides = deepcopy(identity_overrides or {})
        self.read_calls = []

    def read(self, query, context):
        self.read_calls.append((deepcopy(query), deepcopy(context)))
        if self.error is not None:
            raise self.error
        province_id = query["object"]["province_id"]
        result = {
            "topic": "G02",
            "fields": deepcopy(self.fields),
            "source": {
                "name": "FakeNativeProvinceStateSource",
                "mode": "live",
                "status": "observed",
                "observer": "FRA",
                "session_id": context["session_id"],
                "complete": False,
                "provenance": {
                    "province_id": province_id,
                    "observer": "FRA",
                    "read_only": True,
                },
            },
            "game_date": context["game_date"],
            "objects": [deepcopy(query["object"])],
            "complete": False,
        }
        result["source"].update(self.identity_overrides)
        if self.after_read is not None:
            self.after_read()
        return result


def _service(tmp_path, graph, province_source, *, baseline=None, clock=None):
    baseline = baseline or trade_fixtures.FakeTradeBaseline()
    target_reader = TradeTargetsReader(graph, province_source)
    adapter = TradeScenarioSource(baseline, target_reader=target_reader)
    composite = CompositeSource(trade_fixtures.FakePrimary(LIVE_CONTEXT), [adapter])
    service = InformationService(
        composite,
        tmp_path / "trade-targets.sqlite3",
        clock=clock,
    )
    return service, composite, baseline, adapter


def _target_query(parameters=None, *, fields=("targets",)):
    query = {
        "topic": "T06",
        "object": {"type": "trade_node", "node_id": NODE_ID},
        "fields": list(fields),
    }
    if parameters is not None:
        query["parameters"] = deepcopy(parameters)
    return query


def _mixed_query(*, fields=("expected_trade", "targets"), parameters=None):
    query = trade_fixtures.scenario_query(
        [trade_fixtures.scenario("mixed")],
        fields=list(fields),
    )
    if parameters:
        query["parameters"].update(deepcopy(parameters))
    return query


def _field(result, name):
    return result["items"][0]["fields"][name]


def test_target_only_query_uses_g02_annotation_and_keeps_unknown_classification(tmp_path):
    graph = FakeTradeGraph([_member(183, 0)])
    recording_g02 = FakeProvinceSource()
    baseline = trade_fixtures.FakeTradeBaseline()
    service, composite, baseline, _adapter = _service(
        tmp_path, graph, recording_g02, baseline=baseline,
    )
    try:
        topic = next(item for item in composite.catalog() if item["topic_id"] == "T06")
        assert topic["fields"]["targets"]["coverage"] == "partial"
        assert topic["fields"]["targets"]["complete"] is False
        assert topic["fields"]["targets"]["game_fact"] is False
        assert topic["parameters"]["required"] == []
        assert topic["parameters"]["properties"]["target_page"]["properties"]["offset"]["maximum"] == 4096
        assert topic["parameters"]["properties"]["target_page"]["properties"]["limit"]["maximum"] == 16

        result = service.query(
            "trade-target-only-default-page",
            queries=[_target_query()],
        )

        targets = _field(result, "targets")
        assert targets["status"] == "known"
        assert targets["partial"] is True
        assert targets["complete"] is False
        assert targets["game_fact"] is False
        value = targets["value"]
        assert value["schema"] == "information.trade_targets.v1"
        assert value["candidate_basis"] == "effective_disk_node_members_not_engine_loaded_membership"
        assert value["page"] == {"offset": 0, "limit": 4}
        assert value["candidate_count"] == 1
        assert value["next_offset"] is None
        assert value["province_reads"] == 1
        assert value["province_annotation_fields"] == ["owner", "controller", "center_of_trade"]
        assert value["game_fact"] is False
        assert value["complete"] is False
        assert value["rows"][0]["source_rule"] == "member-0"
        assert value["rows"][0]["current_annotations"]["fields"]["owner"]["value"] == "FRA"
        controller = value["rows"][0]["current_annotations"]["fields"]["controller"]
        assert controller["status"] == "unknown"
        assert controller["reason"] == "PROVINCE_CONTROLLER_UNKNOWN"
        assert "value" not in controller
        assert value["rows"][0]["current_annotations"]["source"]["name"] == "FakeNativeProvinceStateSource"
        assert value["rows"][0]["current_annotations"]["game_date"] == LIVE_CONTEXT["game_date"]
        cot = value["rows"][0]["current_annotations"]["fields"]["center_of_trade"]["value"]
        assert cot == {"present": False, "level": 0}
        classification = value["rows"][0]["classification"]
        assert {name: item["status"] for name, item in classification.items()} == {
            "key_center_of_trade": "unknown",
            "port": "unknown",
            "estuary": "unknown",
            "eligibility": "unknown",
            "expected_benefit": "unknown",
        }
        assert all("value" not in item for item in classification.values())

        assert baseline.read_calls == []
        assert graph.read_calls[0][0] == NODE_ID
        assert len(recording_g02.read_calls) == 1
        g02_query, g02_context = recording_g02.read_calls[0]
        assert g02_query == {
            "topic": "G02",
            "object": {"type": "province", "province_id": 183},
            "fields": ["owner", "controller", "center_of_trade"],
            "parameters": {},
        }
        assert g02_context["session_id"] == trade_fixtures.SESSION_ID
        assert g02_context["game_date"] == LIVE_CONTEXT["game_date"]
    finally:
        service.close()


def test_target_pages_preserve_membership_and_dedupe_only_within_each_read(tmp_path):
    rows = [_member(183, 0), _member(183, 1), _member(184, 2)]
    graph = FakeTradeGraph(rows)
    province_source = FakeProvinceSource()
    baseline = trade_fixtures.FakeTradeBaseline()
    service, _composite, baseline, _adapter = _service(
        tmp_path, graph, province_source, baseline=baseline,
    )
    try:
        first = service.query(
            "trade-target-page-first",
            queries=[_target_query({"target_page": {"offset": 0, "limit": 2}})],
        )
        first_value = _field(first, "targets")["value"]
        assert first_value["candidate_count"] == 3
        assert first_value["page"] == {"offset": 0, "limit": 2}
        assert first_value["next_offset"] == 2
        assert [row["province_id"] for row in first_value["rows"]] == [183, 183]
        assert [row["source_rule"] for row in first_value["rows"]] == ["member-0", "member-1"]
        assert first_value["province_reads"] == 1
        assert first_value["cross_request_cache"] is False

        second = service.query(
            "trade-target-page-second",
            queries=[_target_query({"target_page": {"offset": 1, "limit": 2}})],
        )
        second_value = _field(second, "targets")["value"]
        assert second_value["candidate_count"] == 3
        assert second_value["page"] == {"offset": 1, "limit": 2}
        assert second_value["next_offset"] is None
        assert [row["province_id"] for row in second_value["rows"]] == [183, 184]
        assert second_value["province_reads"] == 2
        assert len(graph.read_calls) == 2
        assert [call[0]["object"]["province_id"] for call in province_source.read_calls] == [183, 183, 184]
        assert len(baseline.read_calls) == 0
    finally:
        service.close()


def test_target_page_limits_and_income_scenario_requirement_reject_before_readers(tmp_path):
    graph = FakeTradeGraph([_member(183, 0)])
    province_source = FakeProvinceSource()
    baseline = trade_fixtures.FakeTradeBaseline()
    service, _composite, baseline, _adapter = _service(
        tmp_path, graph, province_source, baseline=baseline,
    )
    invalid_pages = [
        {"offset": -1, "limit": 1},
        {"offset": 4097, "limit": 1},
        {"offset": True, "limit": 1},
        {"offset": 0},
        {"offset": 0, "limit": 0},
        {"offset": 0, "limit": 17},
        {"offset": 0, "limit": 1, "extra": 1},
        [],
    ]
    try:
        for index, page in enumerate(invalid_pages):
            with pytest.raises(InformationError) as error:
                service.query(
                    f"trade-target-invalid-page-{index}",
                    queries=[_target_query({"target_page": page})],
                )
            assert error.value.code == "invalid_parameters"

        with pytest.raises(InformationError) as missing_scenarios:
            service.query(
                "trade-income-needs-scenarios",
                queries=[_target_query(fields=["expected_trade"])],
            )
        assert missing_scenarios.value.code == "invalid_parameters"
        assert graph.read_calls == []
        assert province_source.read_calls == []
        assert baseline.read_calls == []

        legacy = TradeScenarioSource(baseline)
        legacy_fields = legacy.catalog()[0]["fields"]
        assert set(legacy_fields) == set(FIELDS)
    finally:
        service.close()


def test_target_graph_failure_or_static_drift_does_not_withdraw_known_income(tmp_path):
    cases = [
        ("graph-error", FakeTradeGraph([_member(183, 0)], error=RuntimeError("graph unavailable")),
         "TRADE_TARGET_GRAPH_READ_FAILED"),
        ("static-drift", FakeTradeGraph(
            [_member(183, 0)],
            after_read=lambda graph: graph._context.update(configuration_sha256="4" * 64),
        ), "TRADE_TARGET_STATIC_CONTEXT_CHANGED"),
    ]
    for index, (label, graph, reason) in enumerate(cases):
        case_dir = tmp_path / f"target-failure-{index}"
        case_dir.mkdir()
        province_source = FakeProvinceSource()
        baseline = trade_fixtures.FakeTradeBaseline()
        service, _composite, baseline, _adapter = _service(
            case_dir, graph, province_source, baseline=baseline,
        )
        try:
            result = service.query(
                f"trade-target-failure-{label}",
                queries=[_mixed_query()],
            )
            assert _field(result, "expected_trade")["status"] == "known"
            target = _field(result, "targets")
            assert target["status"] == "unavailable"
            assert target["reason"] == reason
            assert len(baseline.read_calls) == 1
            assert len(graph.read_calls) == 1
        finally:
            service.close()


def test_live_context_drift_after_target_read_withdraws_all_mixed_fields(tmp_path):
    baseline = trade_fixtures.FakeTradeBaseline()

    def drift_live_context():
        baseline._context["game_date"] += 1
        baseline._context["game_day"] += 1

    graph = FakeTradeGraph([_member(183, 0)])
    province_source = FakeProvinceSource(after_read=drift_live_context)
    service, _composite, baseline, _adapter = _service(
        tmp_path, graph, province_source, baseline=baseline,
    )
    try:
        result = service.query(
            "trade-target-live-context-drift",
            queries=[_mixed_query()],
        )
        for name in ("expected_trade", "targets"):
            field = _field(result, name)
            assert field["status"] == "unavailable"
            assert field["reason"] == "TRADE_SCENARIO_CONTEXT_CHANGED"
            assert "value" not in field
        assert len(baseline.read_calls) == 1
        assert len(graph.read_calls) == 1
        assert len(province_source.read_calls) == 1
    finally:
        service.close()


def test_information_service_report_periodic_delivery_and_independent_cancel(tmp_path):
    now = [100.0]
    graph = FakeTradeGraph([_member(183, 0)])
    province_source = FakeProvinceSource()
    baseline = trade_fixtures.FakeTradeBaseline()
    service, _composite, baseline, _adapter = _service(
        tmp_path, graph, province_source, baseline=baseline, clock=lambda: now[0],
    )
    query = _target_query()
    subscriptions = []
    try:
        direct = service.query("trade-target-direct", queries=[query])
        report = service.manage_report(
            "trade-target-report-create",
            "create",
            config={"name": "Trade targets", "queries": [query], "detail": "full"},
        )["report"]
        saved = service.query("trade-target-report-read", report_id=report["id"])
        assert _field(direct, "targets") == _field(saved, "targets")

        for seconds in (2, 5):
            subscriptions.append(service.manage_subscription(
                f"trade-target-subscription-{seconds}",
                "create",
                config={
                    "name": f"{seconds}s trade targets",
                    "kind": "periodic",
                    "report_id": report["id"],
                    "enabled": True,
                    "schedule": {"basis": "real", "every": seconds, "unit": "seconds", "missed": "coalesce"},
                },
            )["subscription"])

        assert service.tick()["results"] == []
        now[0] = 102.0
        fast_results = service.tick()["results"]
        assert len(fast_results) == 1
        fast = next(item for item in subscriptions if item["schedule"]["every"] == 2)
        slow = next(item for item in subscriptions if item["schedule"]["every"] == 5)
        assert fast_results[0]["subscription_id"] == fast["id"]
        assert _field(fast_results[0], "targets") == _field(saved, "targets")

        now[0] = 105.0
        both_due = service.tick()["results"]
        assert {item["subscription_id"] for item in both_due} == {fast["id"], slow["id"]}
        assert all(_field(item, "targets") == _field(saved, "targets") for item in both_due)

        cancelled = service.manage_subscription(
            "trade-target-cancel-fast",
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
        assert _field(remaining[0], "targets") == _field(saved, "targets")
        assert baseline.read_calls == []
        assert len(graph.read_calls) == 6
        assert len(province_source.read_calls) == 6
    finally:
        for index, subscription in enumerate(subscriptions):
            current = service.manage_subscription(None, "get", subscription_id=subscription["id"])["subscription"]
            if current["state"] != "cancelled":
                service.manage_subscription(
                    f"trade-target-cleanup-{index}",
                    "cancel",
                    subscription_id=current["id"],
                    expected_version=current["version"],
                )
        service.close()
