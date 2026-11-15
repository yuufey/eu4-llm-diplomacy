"""Estuary classification integration at the trade-target page boundary."""
from copy import deepcopy

from bridge.information.trade_scenarios import TradeScenarioSource
from bridge.information.trade_targets import TradeTargetsReader
from bridge.tests import test_information_trade_scenarios_integration as trade_fixtures
from bridge.tests import test_information_trade_targets as target_fixtures


NODE_ID = target_fixtures.NODE_ID
LIVE_CONTEXT = target_fixtures.LIVE_CONTEXT

CONFIGURATION_FILES = [
    {
        "kind": "launcher_settings",
        "path": "C:/Users/Player/Documents/Paradox Interactive/Europa Universalis IV/launcher-settings.json",
        "sha256": "a" * 64,
    },
    {
        "kind": "enabled_mod_config",
        "path": "C:/Users/Player/Documents/Paradox Interactive/Europa Universalis IV/dlc_load.json",
        "sha256": "b" * 64,
    },
]


def _configured_graph(rows, *, configuration_files=None, after_read=None):
    files = deepcopy(configuration_files or CONFIGURATION_FILES)
    context = target_fixtures._static_context(
        configuration_files=deepcopy(files),
        enabled_mods=[],
    )
    result = target_fixtures._graph_result(rows)
    result["source"]["provenance"] = {
        "configuration_files": deepcopy(files),
        "enabled_mods": [],
    }
    return target_fixtures.FakeTradeGraph(
        rows,
        context=context,
        result=result,
        after_read=after_read,
    )


def _rule_binding(configuration_files=None, *, configuration_sha256="4" * 64):
    files = deepcopy(configuration_files or CONFIGURATION_FILES)
    return {
        "schema": "information.province_estuary_static_definition.v1",
        "status": "known",
        "complete": True,
        "game_fact": False,
        "context_scope": "static_rules",
        "rule_name": "has_river_estuary_trigger",
        "configuration_sha256": configuration_sha256,
        "configuration_files": files,
        "enabled_mods": [],
        "definitions_sha256": "5" * 64,
        "definition_files": [{
            "relative": "common/scripted_triggers/00_scripted_triggers.txt",
            "path": "C:/EU4/common/scripted_triggers/00_scripted_triggers.txt",
            "sha256": "6" * 64,
        }],
        "scriptedtrigger_ast": {
            "key": "has_river_estuary_trigger",
            "kind": "block",
            "children": [{
                "key": "OR",
                "kind": "block",
                "children": [{"key": "has_province_modifier", "value": "has_river_estuary"}],
            }],
        },
        "known_modifier_keys": ["has_river_estuary"],
    }


def _estuary_result(
    province_id,
    context,
    *,
    status="known",
    value=True,
    reason="PROVINCE_ESTUARY_PREDICATE_UNKNOWN",
    matched_modifier_keys=None,
    unknown_modifier_keys=None,
    configuration_files=None,
    source_changes=None,
    provenance_changes=None,
    rule_configuration_sha256="4" * 64,
):
    source = {
        "name": "FakeNativeProvinceEstuaryReader",
        "mode": "live",
        "status": "observed",
        "observer": "FRA",
        "session_id": context["session_id"],
        "game_date": context["game_date"],
        "provenance": {
            "observer": "FRA",
            "province_id": province_id,
            "read_only": True,
            "native_function_invoked": False,
            "capture_report_sha256": "c" * 64,
        },
    }
    source.update(deepcopy(source_changes or {}))
    source["provenance"].update(deepcopy(provenance_changes or {}))
    result = {
        "schema": "information.province_estuary.v1",
        "status": status,
        "province_id": province_id,
        "game_date": context["game_date"],
        "basis": "native_province_modifiers_under_effective_disk_estuary_rule",
        "partial": True,
        "complete": False,
        "game_fact": False,
        "engine_loaded_rule_verified": False,
        "matched_modifier_keys": deepcopy(matched_modifier_keys or []),
        "unknown_modifier_keys": deepcopy(unknown_modifier_keys or []),
        "rule_binding": _rule_binding(
            configuration_files,
            configuration_sha256=rule_configuration_sha256,
        ),
        "source": source,
    }
    if status == "known":
        result["value"] = value
    else:
        result["reason"] = reason
    return result


class FakeEstuaryReader:
    def __init__(self, results=None, *, after_read=None):
        self.results = deepcopy(results or {})
        self.after_read = after_read
        self.read_calls = []

    def read(self, province_id, context):
        self.read_calls.append((province_id, deepcopy(context)))
        result = deepcopy(self.results.get(
            province_id,
            _estuary_result(province_id, context),
        ))
        if self.after_read is not None:
            self.after_read(province_id, context)
        return result


def _reader(graph, estuary_reader, province_source=None):
    return TradeTargetsReader(
        graph,
        province_source or target_fixtures.FakeProvinceSource(),
        estuary_reader=estuary_reader,
    )


def _estuary_rows(result):
    return [row["classification"]["estuary"] for row in result["value"]["rows"]]


def test_true_and_false_estuaries_preserve_rule_binding_and_modifier_keys():
    graph = _configured_graph([
        target_fixtures._member(183, 0),
        target_fixtures._member(184, 1),
    ])
    province_source = target_fixtures.FakeProvinceSource()
    estuary_reader = FakeEstuaryReader({
        183: _estuary_result(
            183,
            LIVE_CONTEXT,
            value=True,
            matched_modifier_keys=["has_river_estuary"],
            unknown_modifier_keys=["has_special_river_estuary"],
        ),
        184: _estuary_result(
            184,
            LIVE_CONTEXT,
            value=False,
            matched_modifier_keys=[],
            unknown_modifier_keys=[],
        ),
    })

    result = _reader(graph, estuary_reader, province_source).read(
        NODE_ID,
        LIVE_CONTEXT,
        {"offset": 0, "limit": 2},
    )

    assert result["status"] == "known"
    assert result["value"]["estuary_reads"] == 2
    true_estuary, false_estuary = _estuary_rows(result)
    assert true_estuary["value"] is True
    assert true_estuary["matched_modifier_keys"] == ["has_river_estuary"]
    assert true_estuary["unknown_modifier_keys"] == ["has_special_river_estuary"]
    assert true_estuary["rule_binding"]["context_scope"] == "static_rules"
    assert true_estuary["rule_binding"]["scriptedtrigger_ast"]["key"] == "has_river_estuary_trigger"
    assert true_estuary["rule_binding"]["configuration_files"] == CONFIGURATION_FILES
    assert true_estuary["rule_binding"]["game_fact"] is False
    assert true_estuary["basis"] == "native_province_modifiers_under_effective_disk_estuary_rule"
    assert true_estuary["partial"] is True and true_estuary["complete"] is False
    assert true_estuary["game_fact"] is False
    assert true_estuary["engine_loaded_rule_verified"] is False
    assert true_estuary["source"]["provenance"]["native_function_invoked"] is False
    assert true_estuary["source"]["provenance"]["capture_report_sha256"] == "c" * 64

    assert false_estuary["value"] is False
    assert false_estuary["matched_modifier_keys"] == []
    assert false_estuary["unknown_modifier_keys"] == []
    assert false_estuary["rule_binding"] == estuary_reader.results[184]["rule_binding"]
    assert false_estuary["source"]["game_date"] == LIVE_CONTEXT["game_date"]
    assert false_estuary["source"]["provenance"]["province_id"] == 184
    assert len(province_source.read_calls) == 2


def test_unknown_and_invalid_source_identities_are_isolated_per_province():
    graph = _configured_graph([
        target_fixtures._member(183, 0),
        target_fixtures._member(184, 1),
        target_fixtures._member(185, 2),
    ])
    province_source = target_fixtures.FakeProvinceSource()
    estuary_reader = FakeEstuaryReader({
        183: _estuary_result(183, LIVE_CONTEXT, status="unknown"),
        184: _estuary_result(
            184,
            LIVE_CONTEXT,
            source_changes={"session_id": "different-session"},
        ),
        185: _estuary_result(
            185,
            LIVE_CONTEXT,
            provenance_changes={"province_id": 183},
        ),
    })

    result = _reader(graph, estuary_reader, province_source).read(
        NODE_ID,
        LIVE_CONTEXT,
        {"offset": 0, "limit": 3},
    )

    first, wrong_session, wrong_province = _estuary_rows(result)
    assert first["status"] == "unknown"
    assert first["reason"] == "PROVINCE_ESTUARY_PREDICATE_UNKNOWN"
    assert "value" not in first
    for invalid in (wrong_session, wrong_province):
        assert invalid["status"] == "unknown"
        assert invalid["reason"] == "TRADE_TARGET_ESTUARY_BINDING_INVALID"
        assert "source" not in invalid
    assert result["value"]["estuary_reads"] == 3
    assert all(row["current_annotations"]["fields"]["owner"]["value"] == "FRA"
               for row in result["value"]["rows"])


def test_rule_configuration_must_match_graph_configuration_manifest():
    graph = _configured_graph([target_fixtures._member(183, 0)])
    mismatched_files = deepcopy(CONFIGURATION_FILES)
    mismatched_files[1]["sha256"] = "d" * 64
    estuary_reader = FakeEstuaryReader({
        183: _estuary_result(
            183,
            LIVE_CONTEXT,
            configuration_files=mismatched_files,
            # The aggregate digest is deliberately the same; the file manifest is authoritative here.
            rule_configuration_sha256=graph.result["source"]["configuration_sha256"],
        ),
    })

    result = _reader(graph, estuary_reader).read(NODE_ID, LIVE_CONTEXT)

    estuary = _estuary_rows(result)[0]
    assert estuary["status"] == "unavailable"
    assert estuary["reason"] == "TRADE_TARGET_ESTUARY_CONFIGURATION_MISMATCH"
    assert "value" not in estuary
    assert result["value"]["estuary_reads"] == 1


def test_duplicate_members_share_estuary_read_per_page_but_not_across_reads():
    graph = _configured_graph([
        target_fixtures._member(183, 0),
        target_fixtures._member(183, 1),
    ])
    estuary_reader = FakeEstuaryReader({
        183: _estuary_result(
            183,
            LIVE_CONTEXT,
            value=True,
            matched_modifier_keys=["has_river_estuary"],
        ),
    })
    reader = _reader(graph, estuary_reader)
    page = {"offset": 0, "limit": 2}

    first = reader.read(NODE_ID, LIVE_CONTEXT, page)
    second = reader.read(NODE_ID, LIVE_CONTEXT, page)

    assert first["value"]["estuary_reads"] == 1
    assert second["value"]["estuary_reads"] == 1
    assert [item["value"] for item in _estuary_rows(first)] == [True, True]
    assert [item["value"] for item in _estuary_rows(second)] == [True, True]
    assert [call[0] for call in estuary_reader.read_calls] == [183, 183]


def test_static_graph_context_drift_after_estuary_read_withdraws_targets():
    graph = _configured_graph([target_fixtures._member(183, 0)])

    def drift_after_read(_province_id, _context):
        graph._context["configuration_sha256"] = "d" * 64

    estuary_reader = FakeEstuaryReader(
        {183: _estuary_result(183, LIVE_CONTEXT)},
        after_read=drift_after_read,
    )

    result = _reader(graph, estuary_reader).read(NODE_ID, LIVE_CONTEXT)

    assert result["status"] == "unavailable"
    assert result["reason"] == "TRADE_TARGET_STATIC_CONTEXT_CHANGED"
    assert "value" not in result
    assert len(estuary_reader.read_calls) == 1


def test_estuary_failure_does_not_break_existing_expected_trade_field():
    graph = _configured_graph([target_fixtures._member(183, 0)])
    estuary_reader = FakeEstuaryReader({
        183: _estuary_result(183, LIVE_CONTEXT, status="unknown"),
    })
    baseline = trade_fixtures.FakeTradeBaseline()
    target_reader = _reader(graph, estuary_reader)
    source = TradeScenarioSource(baseline, target_reader=target_reader)

    result = source.read(
        target_fixtures._mixed_query(fields=("expected_trade", "targets")),
        baseline.context(),
    )

    assert result["fields"]["expected_trade"]["status"] == "known"
    assert result["fields"]["targets"]["status"] == "known"
    assert _estuary_rows({"value": result["fields"]["targets"]["value"]})[0]["status"] == "unknown"
    assert result["fields"]["targets"]["value"]["estuary_reads"] == 1
    assert len(baseline.read_calls) == 1
