"""Strict public projection checks for reconstructed province modifier sources."""
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest

from bridge.information import province_goods_sources as goods_module
from bridge.information.composite import CompositeSource
from bridge.information.final_attributes import NativeFinalAttributesSource
from bridge.information.province_goods_sources import (
    BASIS_V2,
    FIELD_GOODS_SOURCE,
    INNER_SCHEMA_V2,
    MODIFIER_KEY,
    NativeProvinceGoodsSourceBreakdownSource,
    SCHEMA_V2,
    validate_public_breakdown,
)
from bridge.information.catalog import list_topics
from bridge.tests.test_information_province_state import Base, CREATION
from bridge.tests.test_information_war_exhaustion import _context


PROVINCE_ID = 187
PROFILE_SHA = "cd" * 32
DIRECT_KEYS = ("under_siege", "blockaded", "in_state", "prosperity")
DIRECT_BASIS = "current_native_condition_reconstruction"
PUBLIC_GAPS_V2 = [
    "OTHER_PROVINCE_MODIFIER_CALLBACKS_NOT_CAPTURED",
    "PROVINCE_MODIFIER_CACHE_PHASE_UNRESOLVED",
    "PROVINCE_ACQUISITION_DELTA_NOT_CAPTURED",
]


def _i32(value):
    value &= 0xFFFFFFFF
    return value - (1 << 32) if value & (1 << 31) else value


def _direct(key, *, enabled=False, definition_raw=0, applied_raw=None):
    if applied_raw is None:
        applied_raw = definition_raw if enabled else 0
    return {
        "status": "known",
        "source_key": key,
        "definition_raw": definition_raw,
        "enabled": enabled,
        "applied_raw": applied_raw,
        "scale": 1000,
        "basis": DIRECT_BASIS,
        "last_refresh_execution_observed": False,
    }


def _leaf_value(**updates):
    cached = [
        {"status": "known", "source_key": f"cached_{index}", "raw": 0, "scale": 1000}
        for index in range(23)
    ]
    # An empty native name is still a real slot and its observed nonzero value counts.
    cached[0] = {"status": "known", "source_key": "devastation", "raw": -18, "scale": 1000}
    cached[1] = {"status": "known", "source_key": "", "raw": 10, "scale": 1000}
    direct = [
        _direct("under_siege", enabled=True, definition_raw=-250),
        _direct("blockaded", enabled=False, definition_raw=330),
        _direct("in_state", enabled=False, definition_raw=310),
        _direct("prosperity", enabled=False, definition_raw=250),
    ]
    value = {
        "province_id": PROVINCE_ID,
        "modifier_index": 21,
        "modifier_key": MODIFIER_KEY,
        "aggregate_raw": -258,
        "cached_components": cached,
        "cached_sum_raw": -8,
        "direct_sources": direct,
        "direct_sum_raw": -250,
        "residual_raw": 0,
        "scale": 1000,
        "current_only": True,
        "full_source_coverage": False,
        "last_refresh_execution_observed": False,
        "descriptor_qualified": True,
    }
    value.update(updates)
    return value


def _report(*, value=None, field_status="known", consistency="stable", consistency_reason=None,
            province_id=PROVINCE_ID):
    gate = {
        "status": "known", "admitted": True,
        "observer_nonplayer_role": {"observer": "FRA", "verified": True},
    }
    discovery = {"status": "known", "value": True}
    field = {
        "status": field_status,
        "complete": False,
        "basis": BASIS_V2,
        "period": "current",
        "raw_inputs": {"private_pointer": "0x1234567890abcdef", "offset": "0x998"},
    }
    if field_status == "known":
        field["value"] = deepcopy(value if value is not None else _leaf_value())
    else:
        field["reason"] = "aggregate_unverified"
    consistency_value = {"status": consistency}
    if consistency_reason is not None:
        consistency_value["reason"] = consistency_reason
    target = {
        "province_id": province_id,
        "owner_tag": "POR",
        "admission_by_pass": {"pass1": deepcopy(gate), "pass2": deepcopy(gate)},
        "discovery_by_pass": {"pass1": deepcopy(discovery), "pass2": deepcopy(discovery)},
        "fields": {FIELD_GOODS_SOURCE: field},
        "field_consistency": {FIELD_GOODS_SOURCE: consistency_value},
    }
    game_date = _context()["game_date"]
    return {
        "schema": SCHEMA_V2,
        "observer": "FRA",
        "object": {"type": "province", "province_id": province_id},
        "capture": {
            "schema": INNER_SCHEMA_V2,
            "status": "observed",
            "completed": True,
            "observation": {
                "stable": True,
                "context_before": {"game_date": game_date},
                "context_after": {"game_date": game_date},
                "backend": {
                    "status": "observed",
                    "consistency": {"status": "stable"},
                    "observer": {"tag": "FRA"},
                    "targets": [target],
                },
            },
        },
    }


class _Quality:
    def __init__(self, context):
        self.current = deepcopy(context)
        self.calls = []

    def context(self):
        return deepcopy(self.current)

    def read(self, query, context):
        self.calls.append(deepcopy(query))
        raise AssertionError("province source projection must not call N03")


def _provider(tmp_path, monkeypatch, *, report=None, valid=True, version=2, after_capture=None):
    context = _context()
    base = Base(tmp_path, context)
    actual_report = deepcopy(report if report is not None else _report())
    captures = []
    validations = []

    def capture(installation, *, province_id, observer):
        captures.append((installation, province_id, observer))
        if after_capture is not None:
            after_capture(base)
        return deepcopy(actual_report)

    def validate_capture(report_arg, context_arg, creation, province_id):
        validations.append((deepcopy(report_arg), deepcopy(context_arg), creation, province_id))
        return valid

    module = SimpleNamespace(
        SCHEMA=SCHEMA_V2,
        INNER_SCHEMA=INNER_SCHEMA_V2,
        PROFILE_SHA256=PROFILE_SHA,
        validate_capture=validate_capture,
    )
    imported = []

    def import_capture(name, package):
        imported.append((name, package))
        return module

    monkeypatch.setattr(goods_module, "import_module", import_capture)
    source = NativeProvinceGoodsSourceBreakdownSource(
        base, capture=capture, projection_version=version,
    )
    return source, base, captures, validations, imported


def _query():
    return {
        "topic": "N09",
        "object": {"type": "province", "province_id": PROVINCE_ID},
        "fields": ["source_breakdown"],
        "parameters": {},
    }


def test_v2_projects_all_23_slots_and_four_direct_conditions_through_single_n09_owner(
        tmp_path, monkeypatch):
    quality = _Quality(_context())
    provider, base, captures, validations, imported = _provider(tmp_path, monkeypatch)
    source = NativeFinalAttributesSource(quality, province_breakdown_source=provider)

    result = source.read(_query(), quality.context())

    field = result["fields"]["source_breakdown"]
    assert field["status"] == "known"
    assert field["projection_version"] == 2
    assert field["basis"] == "native_cached_and_reconstructed_province_modifier_sources"
    value = field["value"][MODIFIER_KEY]
    assert len(value["cached_components"]) == 23
    assert value["cached_components"][1]["source_key"] == ""
    assert value["cached_components"][1]["raw"] == 10
    assert [row["source_key"] for row in value["direct_sources"]] == list(DIRECT_KEYS)
    assert value["cached_sum_raw"] == -8
    assert value["direct_sum_raw"] == -250
    assert value["residual_raw"] == _i32(-258 - -8 - -250) == 0
    assert value["full_source_coverage"] is False
    assert value["last_refresh_execution_observed"] is False
    assert set(value) == {
        "province_id", "modifier_index", "modifier_key", "aggregate_raw",
        "cached_components", "cached_sum_raw", "direct_sources", "direct_sum_raw",
        "residual_raw", "scale", "current_only", "full_source_coverage",
        "last_refresh_execution_observed", "descriptor_qualified",
    }
    assert validate_public_breakdown(field, PROVINCE_ID) == field
    assert "0x1234567890abcdef" not in repr(result)
    assert "0x998" not in repr(result)
    assert "raw_inputs" not in repr(result)
    assert quality.calls == []
    assert captures == [(tmp_path / "installation.json", PROVINCE_ID, "FRA")]
    assert validations[0][1]["observer"] == "FRA"
    assert validations[0][2:] == (CREATION, PROVINCE_ID)
    assert imported[0][0] == ".province_modifier_sources_capture"
    assert result["source"]["provenance"]["delegations"][FIELD_GOODS_SOURCE]["profile_sha256"] == PROFILE_SHA
    assert provider.catalog() == []


def test_v2_accepts_other_cached_sources_without_a_devastation_row(tmp_path, monkeypatch):
    value = _leaf_value()
    value["cached_components"][0]["source_key"] = "merchant_republic_bonus"
    source, base, *_ = _provider(tmp_path, monkeypatch, report=_report(value=value))

    field = source.read(_query(), base.context())["fields"]["source_breakdown"]

    assert field["status"] == "known"
    assert field["value"][MODIFIER_KEY]["cached_components"][0]["source_key"] == "merchant_republic_bonus"


def test_unknown_children_keep_the_field_known_and_withhold_derived_sums(tmp_path, monkeypatch):
    value = _leaf_value()
    value["cached_components"][4] = {
        "status": "unknown", "source_key": None, "reason": "slot_not_observed",
    }
    value["cached_sum_raw"] = None
    value["direct_sources"][3] = {
        "status": "unknown", "source_key": "prosperity", "definition_raw": 250,
        "enabled": None, "applied_raw": None, "scale": 1000,
        "basis": DIRECT_BASIS, "last_refresh_execution_observed": False,
        "reason": "threshold_not_met",
    }
    value["direct_sum_raw"] = None
    value["residual_raw"] = None
    source, base, _captures, _validations, _imported = _provider(
        tmp_path, monkeypatch, report=_report(value=value),
    )

    field = source.read(_query(), base.context())["fields"]["source_breakdown"]

    assert field["status"] == "known"
    projected = field["value"][MODIFIER_KEY]
    assert projected["cached_components"][4]["reason"] == "slot_not_observed"
    assert projected["cached_sum_raw"] is None
    assert projected["direct_sources"][3]["reason"] == "threshold_not_met"
    assert projected["direct_sum_raw"] is None
    assert projected["residual_raw"] is None
    assert validate_public_breakdown(field, PROVINCE_ID) == field


@pytest.mark.parametrize("kind", ("cached", "direct"))
def test_v2_rejects_empty_reason_for_unknown_child(tmp_path, monkeypatch, kind):
    value = _leaf_value()
    if kind == "cached":
        value["cached_components"][0] = {
            "status": "unknown", "source_key": None, "reason": "",
        }
        value["cached_sum_raw"] = None
    else:
        value["direct_sources"][0] = {
            "status": "unknown", "source_key": "under_siege", "definition_raw": -250,
            "enabled": None, "applied_raw": None, "scale": 1000,
            "basis": DIRECT_BASIS, "last_refresh_execution_observed": False,
            "reason": "",
        }
        value["direct_sum_raw"] = None
    value["residual_raw"] = None
    source, base, *_ = _provider(tmp_path, monkeypatch, report=_report(value=value))

    field = source.read(_query(), base.context())["fields"]["source_breakdown"]

    assert field["status"] == "unknown"
    assert "value" not in field


@pytest.mark.parametrize("corrupt", [
    lambda value: value.update(aggregate_raw=True),
    lambda value: value["cached_components"][0].update(raw=True),
    lambda value: value["direct_sources"][0].update(definition_raw=True),
    lambda value: value["direct_sources"][0].update(applied_raw=True),
    lambda value: value.update(cached_sum_raw=True),
])
def test_v2_rejects_boolean_values_where_signed_i32_is_required(tmp_path, monkeypatch, corrupt):
    value = _leaf_value()
    corrupt(value)
    source, base, _captures, _validations, _imported = _provider(
        tmp_path, monkeypatch, report=_report(value=value),
    )

    field = source.read(_query(), base.context())["fields"]["source_breakdown"]

    assert field["status"] == "unknown"
    assert "value" not in field


def test_v2_recomputes_residual_and_rejects_coverage_or_trace_claims(tmp_path, monkeypatch):
    bad_residual = _leaf_value(residual_raw=7)
    source, base, *_ = _provider(tmp_path, monkeypatch, report=_report(value=bad_residual))
    field = source.read(_query(), base.context())["fields"]["source_breakdown"]
    assert field["status"] == "unknown"

    for mutate in (
        lambda value: value.update(full_source_coverage=True),
        lambda value: value.update(last_refresh_execution_observed=True),
        lambda value: value.update(refresh_trace=True),
    ):
        value = _leaf_value()
        mutate(value)
        changed = Path(base.session.directory) / f"case-{id(mutate)}"
        changed.mkdir()
        source, base, *_ = _provider(changed, monkeypatch, report=_report(value=value))
        rejected = source.read(_query(), base.context())["fields"]["source_breakdown"]
        assert rejected["status"] == "unknown"
        assert "value" not in rejected

    complete_dir = Path(base.session.directory) / "complete"
    complete_dir.mkdir()
    valid_source, valid_base, *_ = _provider(complete_dir, monkeypatch)
    public = valid_source.read(_query(), valid_base.context())["fields"]["source_breakdown"]
    for invalid in (
        {**public, "complete": True},
        {**public, "full_source_coverage": True},
        {**public, "trace": {"executed": True}},
    ):
        with pytest.raises(ValueError):
            validate_public_breakdown(invalid, PROVINCE_ID)


def test_v2_capture_failure_and_context_drift_fail_closed(tmp_path, monkeypatch):
    source, base, _captures, validations, imported = _provider(
        tmp_path, monkeypatch, valid=False,
    )
    field = source.read(_query(), base.context())["fields"]["source_breakdown"]
    assert field["status"] == "unknown"
    assert len(validations) == 1
    assert imported[0][0] == ".province_modifier_sources_capture"

    drift_dir = Path(base.session.directory) / "drift"
    drift_dir.mkdir()

    def drift(base_source):
        base_source.current["game_date"] += 1

    source, base, _captures, validations, _imported = _provider(
        drift_dir, monkeypatch, after_capture=drift,
    )
    field = source.read(_query(), base.context())["fields"]["source_breakdown"]
    assert field["status"] == "unavailable"
    assert validations == []


def test_v2_catalog_describes_partial_sources_without_subscribing_to_them():
    context = _context()
    base = Base(Path("."), context)
    provider = NativeProvinceGoodsSourceBreakdownSource(
        base, capture=lambda *_a, **_k: None, projection_version=2,
    )
    source = NativeFinalAttributesSource(_Quality(context), province_breakdown_source=provider)

    topic = source.catalog()[0]
    breakdown = topic["fields"]["source_breakdown"]

    expected_fields = {item["topic_id"]: set(item["fields"]) for item in list_topics()}
    full_catalog = CompositeSource(base, [source]).catalog()
    assert len(full_catalog) == len(expected_fields)
    assert {item["topic_id"]: set(item["fields"]) for item in full_catalog} == expected_fields
    assert breakdown["basis_by_object_type"]["country"] == "existing_N03_validated_discipline_calculation_observation"
    assert breakdown["basis_by_object_type"]["province"] == BASIS_V2
    assert breakdown["projection_version"] == 2
    assert "23个贸易商品修正缓存槽与4个直接条件模型" in breakdown["description"]
    assert "繁荣只验证了必要门槛" in breakdown["description"]
    assert "部分分解" in breakdown["description"]
    assert topic["change_scope"]["fields"] == ["final_value"]


def test_public_validator_still_accepts_legacy_v1_breakdown_and_versions_are_exact(
        tmp_path, monkeypatch):
    legacy = {
        "status": "known",
        "value": {MODIFIER_KEY: {
            "province_id": PROVINCE_ID,
            "modifier_index": 21,
            "modifier_key": MODIFIER_KEY,
            "source_key": "devastation",
            "aggregate_raw": -18,
            "cached_component_raw": -18,
            "residual_raw": 0,
            "province_scale_input_raw": 1000,
            "scale": 1000,
            "current_only": True,
            "full_source_coverage": False,
            "descriptor_qualified": True,
        }},
        "unit": "attribute_breakdown_map", "scale": 1, "period": "current",
        "complete": False, "partial": True,
        "basis": "native_cached_province_modifier_component_candidate",
        "gaps": [
            "OTHER_PROVINCE_MODIFIER_CALLBACKS_NOT_CAPTURED",
            "PROVINCE_MODIFIER_CACHE_PHASE_UNRESOLVED",
            "PROVINCE_ACQUISITION_DELTA_NOT_CAPTURED",
            "SOURCE_KEY_NAMES_A_CACHED_DEFINITION_NOT_A_UNIQUE_RUNTIME_CAUSE",
        ],
    }
    assert validate_public_breakdown(legacy, PROVINCE_ID) == legacy

    context = _context()
    source = NativeProvinceGoodsSourceBreakdownSource(Base(tmp_path, context), capture=lambda *_a, **_k: None)
    assert source.projection_version == 1
    for invalid in (True, 0, 3, 1.0):
        with pytest.raises(ValueError, match="PROJECTION_VERSION_INVALID"):
            NativeProvinceGoodsSourceBreakdownSource(
                Base(tmp_path, context), projection_version=invalid,
            )
