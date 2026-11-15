"""N09 delegates one verified province goods component through its sole owner."""
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest

from bridge.information import province_goods_sources as goods_module
from bridge.information.catalog import list_topics
from bridge.information.composite import CompositeSource
from bridge.information.final_attributes import NativeFinalAttributesSource
from bridge.information.model import InformationError
from bridge.information.province_goods_sources import (
    BASIS,
    FIELD_GOODS_SOURCE,
    MODIFIER_KEY,
    NativeProvinceGoodsSourceBreakdownSource,
)
from bridge.tests.test_information_war_exhaustion import _context
from bridge.tests.test_information_province_state import Base, CREATION


PROVINCE_ID = 183
PROFILE_SHA = "ab" * 32


def _leaf_value(**updates):
    value = {
        "province_id": PROVINCE_ID,
        "modifier_index": 21,
        "modifier_key": MODIFIER_KEY,
        "source_key": "trade_goods_size_modifier",
        "aggregate_raw": 21,
        "cached_component_raw": 21,
        "residual_raw": 0,
        "province_scale_input_raw": 1000,
        "scale": 1000,
        "current_only": True,
        "full_source_coverage": False,
        "descriptor_qualified": True,
    }
    value.update(updates)
    return value


def _report(*, province_id=PROVINCE_ID, value=None, field_status="known",
            consistency="stable", consistency_reason=None, observer="FRA",
            owner_tag="POR"):
    gate = {
        "status": "known",
        "admitted": True,
        "observer_nonplayer_role": {"observer": "FRA", "verified": True},
    }
    discovery = {"status": "known", "value": True}
    field = {
        "status": field_status,
        "complete": False,
        "basis": BASIS,
        "period": "current",
        "value": deepcopy(value if value is not None else _leaf_value(province_id=province_id)),
        "raw_inputs": {"private_pointer": "0x1234567890abcdef"},
    }
    if field_status != "known":
        field["reason"] = "cache_phase_unresolved"
        field.pop("value")
    consistency_value = {"status": consistency}
    if consistency_reason is not None:
        consistency_value["reason"] = consistency_reason
    game_date = _context()["game_date"]
    target = {
        "province_id": province_id,
        "owner_tag": owner_tag,
        "admission_by_pass": {"pass1": deepcopy(gate), "pass2": deepcopy(gate)},
        "discovery_by_pass": {"pass1": deepcopy(discovery), "pass2": deepcopy(discovery)},
        "fields": {FIELD_GOODS_SOURCE: field},
        "field_consistency": {FIELD_GOODS_SOURCE: consistency_value},
    }
    return {
        "schema": goods_module.SCHEMA,
        "observer": observer,
        "object": {"type": "province", "province_id": province_id},
        "capture": {
            "schema": goods_module.INNER_SCHEMA,
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
        raise AssertionError("province breakdown must not call N03")


def _provider(tmp_path, monkeypatch, *, report=None, valid=True,
              capture_error=None, after_capture=None):
    context = _context()
    base = Base(tmp_path, context)
    actual_report = deepcopy(report if report is not None else _report())
    captures = []
    validations = []

    def capture(installation, *, province_id, observer):
        captures.append((installation, province_id, observer))
        if after_capture is not None:
            after_capture(base)
        if capture_error is not None:
            raise capture_error
        return deepcopy(actual_report)

    def validate_capture(report_arg, context_arg, creation, province_id):
        validations.append((deepcopy(report_arg), deepcopy(context_arg), creation, province_id))
        return valid

    module = SimpleNamespace(
        SCHEMA=goods_module.SCHEMA,
        INNER_SCHEMA=goods_module.INNER_SCHEMA,
        PROFILE_SHA256=PROFILE_SHA,
        validate_capture=validate_capture,
    )
    monkeypatch.setattr(goods_module, "import_module", lambda _name, _package: module)
    source = NativeProvinceGoodsSourceBreakdownSource(base, capture=capture)
    return source, base, captures, validations


def _query(*, province_id=PROVINCE_ID, fields=("source_breakdown",), parameters=None):
    return {
        "topic": "N09",
        "object": {"type": "province", "province_id": province_id},
        "fields": list(fields),
        "parameters": {} if parameters is None else parameters,
    }


def test_final_attributes_owns_single_n09_route_and_never_calls_n03_for_province(
        tmp_path, monkeypatch):
    context = _context()
    quality = _Quality(context)
    provider, base, captures, validations = _provider(tmp_path, monkeypatch)
    source = NativeFinalAttributesSource(
        quality, country_records_source=object(),
        province_breakdown_source=provider,
    )

    result = source.read(_query(fields=("source_breakdown", "final_value", "modifier_effects")), context)

    field = result["fields"]["source_breakdown"]
    assert field["status"] == "known"
    component = field["value"][MODIFIER_KEY]
    assert (component["aggregate_raw"], component["cached_component_raw"],
            component["residual_raw"]) == (21, 21, 0)
    assert component["province_scale_input_raw"] == 1000
    assert field["complete"] is False and field["partial"] is True
    assert field["basis"] == BASIS
    assert result["fields"]["final_value"]["status"] == "unsupported"
    assert result["fields"]["modifier_effects"]["status"] == "unsupported"
    assert quality.calls == []
    assert captures == [(tmp_path / "installation.json", PROVINCE_ID, "FRA")]
    assert validations[0][1]["observer"] == "FRA"
    assert validations[0][2:] == (CREATION, PROVINCE_ID)
    assert result["source"]["provenance"]["delegations"][FIELD_GOODS_SOURCE]["profile_sha256"] == PROFILE_SHA
    assert provider.catalog() == []
    assert "0x1234567890abcdef" not in repr(result)
    assert "owner_tag" not in repr(result)


def test_province_catalog_scope_is_explicit_and_preserves_field_set():
    quality = _Quality(_context())
    base = Base(Path("."), _context())
    provider = NativeProvinceGoodsSourceBreakdownSource(base, capture=lambda *_a, **_k: None)
    records = object()
    source = NativeFinalAttributesSource(
        quality, country_records_source=records, province_breakdown_source=provider,
    )
    topic = source.catalog()[0]
    expected_fields = {item["topic_id"]: set(item["fields"]) for item in list_topics()}
    full_catalog = CompositeSource(base, [source]).catalog()
    assert len(full_catalog) == len(expected_fields)
    assert {item["topic_id"]: set(item["fields"]) for item in full_catalog} == expected_fields
    assert topic["object_types"] == ["country", "province"]
    assert topic["parameters"]["properties"] == {}
    assert topic["visibility"] == topic["context_scope"] == "adapter_managed"
    assert topic["fields"]["final_value"]["supported_object_types"] == ["country"]
    assert topic["fields"]["final_value"]["context_scope"] == "country_scope"
    assert topic["fields"]["modifier_effects"]["supported_object_types"] == ["country"]
    assert topic["fields"]["modifier_effects"]["context_scope"] == "country_scope"
    breakdown = topic["fields"]["source_breakdown"]
    assert breakdown["supported_object_types"] == ["country", "province"]
    assert breakdown["scope_by_object_type"] == {
        "country": "country_scope", "province": "visible_scope",
    }
    assert "不按省份所有者过滤" in breakdown["scope_note"]
    assert MODIFIER_KEY in breakdown["supported_attributes"]
    assert "province_id" not in topic["parameters"]["properties"]


def test_unconfigured_or_invalid_province_selector_is_rejected():
    quality = _Quality(_context())
    unconfigured = NativeFinalAttributesSource(quality)
    with pytest.raises(InformationError, match="not configured"):
        unconfigured.validate_query(_query())

    provider = NativeProvinceGoodsSourceBreakdownSource(
        Base(Path("."), _context()), capture=lambda *_a, **_k: None,
    )
    source = NativeFinalAttributesSource(quality, province_breakdown_source=provider)
    for bad_id in (True, 0, 0x10000):
        with pytest.raises(InformationError):
            source.validate_query(_query(province_id=bad_id))
    with pytest.raises(InformationError, match="no extra parameters"):
        provider.validate_query(_query(parameters={"modifier_key": MODIFIER_KEY}))
    with pytest.raises(InformationError, match="logical FRA"):
        provider.validate_query(_query(), {**_context(), "observer": "POR"})


@pytest.mark.parametrize(("change", "expected"), [
    (lambda value: value.update(cached_component_raw=True), "PROVINCE_GOODS_SOURCES_ARITHMETIC_INVALID"),
    (lambda value: value.update(residual_raw=1), "PROVINCE_GOODS_SOURCES_RESIDUAL_MISMATCH"),
    (lambda value: value.update(province_scale_input_raw=0), "PROVINCE_GOODS_SOURCES_SCALE_INPUT_INVALID"),
    (lambda value: value.update(descriptor_qualified=False), "PROVINCE_GOODS_SOURCES_COMPONENT_INVALID"),
])
def test_bad_component_types_descriptor_or_i32_residual_fail_closed(
        tmp_path, monkeypatch, change, expected):
    value = _leaf_value()
    change(value)
    source, base, _captures, _validations = _provider(
        tmp_path, monkeypatch, report=_report(value=value),
    )

    result = source.read(_query(), base.context())

    field = result["fields"]["source_breakdown"]
    assert field["status"] == "unknown"
    assert field["reason"] == expected
    assert "value" not in field


def test_unknown_consistency_is_preserved_and_changed_capture_fails_closed(tmp_path, monkeypatch):
    source, base, _captures, _validations = _provider(
        tmp_path, monkeypatch,
        report=_report(consistency="unknown", consistency_reason="cache_phase_unresolved"),
    )
    field = source.read(_query(), base.context())["fields"]["source_breakdown"]
    assert field["status"] == "unknown"
    assert field["reason"] == "cache_phase_unresolved"

    changed_dir = tmp_path / "changed"
    changed_dir.mkdir()
    source, base, _captures, validations = _provider(
        changed_dir, monkeypatch, report=_report(consistency="changed"),
    )
    field = source.read(_query(), base.context())["fields"]["source_breakdown"]
    assert field["status"] == "unknown"
    assert field["reason"] == "PROVINCE_GOODS_SOURCES_FIELD_CHANGED_BETWEEN_PASSES"
    assert len(validations) == 1


def test_capture_validation_and_context_drift_do_not_publish_component(tmp_path, monkeypatch):
    source, base, _captures, validations = _provider(tmp_path, monkeypatch, valid=False)
    field = source.read(_query(), base.context())["fields"]["source_breakdown"]
    assert field["status"] == "unknown"
    assert field["reason"] == "PROVINCE_GOODS_SOURCES_CAPTURE_INVALID"
    assert len(validations) == 1

    drift_dir = tmp_path / "drift"
    drift_dir.mkdir()

    def drift(base_source):
        base_source.current["game_date"] += 1

    source, base, _captures, validations = _provider(
        drift_dir, monkeypatch, after_capture=drift,
    )
    field = source.read(_query(), base.context())["fields"]["source_breakdown"]
    assert field["status"] == "unavailable"
    assert field["reason"] == "PROVINCE_GOODS_SOURCES_CONTEXT_CHANGED_DURING_CAPTURE"
    assert validations == []

