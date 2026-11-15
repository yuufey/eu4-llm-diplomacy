"""Composition tests for the writer-gate leaf and the existing country capture."""
from __future__ import annotations

import struct

import pytest

from bridge.information import country_view_admission_memory as admission
from bridge.information import province_identity_memory as identity
from bridge.information import province_trade_power_calculation_memory as calculation
from bridge.information import province_trade_power_gates_memory as gates
from bridge.information import province_trade_power_inputs_memory as inputs
from bridge.tests import test_information_province_state_memory as fixture

BASE = fixture.BASES[0]
PROVINCE_ID = fixture.PROVINCE_ID
FRA_SLOT = fixture.FRA_SLOT
SWE_SLOT = fixture.SWE_SLOT
RECORD = fixture.RECORDS + PROVINCE_ID * identity.PROVINCE_RECORD_STRIDE
NODE = 0x5D00000000
VTABLE = BASE + 0x100000
METHOD = BASE + 0x200000
CONTROLLER_TYPE = 0x6200000000
CONTAINER = 0x6300000000


def _admit_swe(image) -> None:
    fra = fixture.COUNTRY_BASE + FRA_SLOT * 0x1000
    image.put_u64(fra + admission.RELATION_TABLE_OFFSET, fixture.RELATION_TABLE)
    row = fixture.RELATION_TABLE + SWE_SLOT * admission.RELATION_ROW_STRIDE
    image.put_u64(row + admission.RELATION_ROW_OWNER_OFFSET, fixture.RELATION_OWNER)
    image.put_u64(row + admission.RELATION_ROW_RECIPIENT_FULLREF_OFFSET,
                  fixture._fullref("SWE", SWE_SLOT))
    image.put_u64(fixture.RELATION_OWNER + admission.RELATION_OWNER_COUNTERS_OFFSET,
                  fixture.RELATION_COUNTERS)
    counter = (fixture.RELATION_COUNTERS + admission.RELATION_COUNTER_FIRST_OFFSET
               + SWE_SLOT * admission.RELATION_COUNTER_STRIDE)
    image.put_i32(counter, 1)


def _install_gate(image, *, node_enabled=True, controller_enabled=True,
                  flags=0, predicate=b"\xb0\x01\xc3"):
    image.put_u64(RECORD + 0xE8, NODE if node_enabled else 0)
    image.put(RECORD + 0x958, bytes([flags & 0xFF]))
    if not node_enabled:
        return
    image.put_u64(NODE, VTABLE)
    image.put_u64(VTABLE + 0x40, METHOD)
    image.put(METHOD, predicate)
    swe = fixture.COUNTRY_BASE + SWE_SLOT * 0x1000
    image.put_u64(swe + 0x2440, CONTROLLER_TYPE)
    image.put(CONTROLLER_TYPE + 0x79, bytes([int(controller_enabled)]))
    if flags & 4:
        image.put_u64(RECORD + 0x8A8, CONTAINER)
        image.put_u64(CONTAINER + 0x28, 0)
        image.put_u64(CONTAINER + 0x30, 0)


def _numeric_field(field):
    if field == inputs.FIELD_PROVINCE_TRADE_POWER:
        basis, unit, raw = "native_province_trade_power_trigger_cache", "trade_power", 1250
    elif field == inputs.FIELD_PROVINCE_TRADE_POWER_VALUE:
        basis, unit, raw = "native_province_numeric_modifier_processor_absent", "trade_power", 800
    else:
        basis, unit, raw = "native_province_numeric_modifier_processor_absent", "ratio", 200
    return {
        "status": "known", "complete": False, "period": "current", "basis": basis,
        "value": {"raw": raw, "scale": 1000, "unit": unit},
        "raw_inputs": {"synthetic": field},
    }


def _country_field(tag, field):
    return {
        "status": "known", "complete": False, "period": "current",
        "basis": "native_country_province_trade_power_modifier_processor_absent",
        "value": {"country": tag, "raw": 100 if tag == "FRA" else 200,
                  "scale": 1000, "unit": "ratio"},
        "raw_inputs": {"synthetic": field},
    }


def _run(monkeypatch, image):
    def parent_fields(_reader, _base, _binding, fields):
        return {field: _numeric_field(field) for field in fields}

    def country_fields(_reader, _base, binding, fields):
        return {field: _country_field(binding["tag"], field) for field in fields}

    monkeypatch.setattr(calculation._country._inputs, "read_fields", parent_fields)
    monkeypatch.setattr(calculation._country._country_leaf, "read_fields", country_fields)
    return calculation.read_two_pass(image, BASE, PROVINCE_ID)


def _target(result):
    return result["targets"][0]


def test_known_gates_reuse_parent_scan_and_fit_shared_512k_budget(monkeypatch):
    image = fixture.make_image()
    _admit_swe(image)
    _install_gate(image, flags=0)

    result = _run(monkeypatch, image)

    target = _target(result)
    assert result["status"] == "observed"
    assert result["consistency"]["status"] == "stable"
    assert target["fields"][inputs.FIELD_PROVINCE_TRADE_POWER]["status"] == "known"
    assert target["fields"][gates.FIELD]["status"] == "known"
    assert target["fields"][gates.FIELD]["value"] == {
        "province_node_enabled": True, "controller_type_enabled": True,
        "owner_bonus_active": False, "owner_bonus_raw": 0}
    assert target["field_consistency"][gates.FIELD]["status"] == "stable"
    assert "province_trade_gates.owner_ref" not in [label for _, _, label in image.reads]
    # The parent performs the two full scans; calculation rebinds are indexed.
    assert sum(label == "country_reference.database_global"
               for _, _, label in image.reads) == 2
    assert result["budget"]["bytes_requested"] == sum(size for _, size, _ in image.reads)
    assert result["budget"]["calls"] == len(image.reads)
    assert result["budget"]["bytes_requested"] <= 512 * 1024
    assert result["budget"]["limit_bytes"] == 512 * 1024


def test_controller_admission_denial_keeps_province_cache_and_does_not_read_gate_leaf(monkeypatch):
    image = fixture.make_image()
    _install_gate(image, flags=0)

    result = _run(monkeypatch, image)

    target = _target(result)
    assert result["status"] == "observed"
    assert target["fields"][inputs.FIELD_PROVINCE_TRADE_POWER]["status"] == "known"
    assert target["fields"][gates.FIELD]["status"] == "unknown"
    assert target["fields"][gates.FIELD]["reason"] == "CALCULATION_PARENT_UNVERIFIED"
    assert not any("province_trade_gates." in label for _, _, label in image.reads)


def test_unrecognized_gate_body_is_local_unknown_and_preserves_province_power(monkeypatch):
    image = fixture.make_image()
    _admit_swe(image)
    _install_gate(image, predicate=b"\x90\x90\xc3", flags=0)

    result = _run(monkeypatch, image)

    target = _target(result)
    assert result["status"] == "observed"
    assert target["fields"][inputs.FIELD_PROVINCE_TRADE_POWER]["status"] == "known"
    assert target["fields"][gates.FIELD]["status"] == "unknown"
    assert target["fields"][gates.FIELD]["reason"] == "NODE_PREDICATE_UNSUPPORTED"


def test_denied_owner_gate_is_local_unknown_after_shared_revalidation(monkeypatch):
    image = fixture.make_image()
    _admit_swe(image)
    _install_gate(image, flags=4)

    result = _run(monkeypatch, image)

    target = _target(result)
    assert result["status"] == "observed"
    assert target["fields"][inputs.FIELD_PROVINCE_TRADE_POWER]["status"] == "known"
    assert target["fields"][gates.FIELD]["status"] == "unknown"
    assert target["fields"][gates.FIELD]["reason"] == "OWNER_ADMISSION_NOT_ESTABLISHED"
    assert all(item["shared_valid"] for item in result["calculation_gate_evidence"].values())
    assert sum(label == "country_reference.database_global"
               for _, _, label in image.reads) == 2


def test_shared_province_drift_after_owner_denial_retracts_whole_capture(monkeypatch):
    image = fixture.make_image()
    _admit_swe(image)
    _install_gate(image, flags=4)
    original = calculation._country._admit
    changed = {"done": False}

    def denying_owner_after_mutation(limiter, base, scan, binding):
        gate = original(limiter, base, scan, binding)
        if binding.get("tag") == "ENG" and not changed["done"]:
            image.put_i32(RECORD + identity.PROVINCE_ID_OFFSET, PROVINCE_ID + 1)
            changed["done"] = True
        return gate

    monkeypatch.setattr(calculation._country, "_admit", denying_owner_after_mutation)
    result = _run(monkeypatch, image)

    assert changed["done"]
    assert result["status"] == "unknown"
    assert result["consistency"]["shared_mismatch_paths"] == ["calculation_gates"]
    target = _target(result)
    assert target["fields"][inputs.FIELD_PROVINCE_TRADE_POWER]["status"] == "unknown"
    assert target["fields"][gates.FIELD]["status"] == "unknown"


def test_observer_role_drift_during_gate_round_invalidates_shared_capture(monkeypatch):
    image = fixture.make_image()
    _admit_swe(image)
    _install_gate(image, flags=0)
    original = calculation._country._admit
    seen_swe = {"count": 0, "mutated": False}

    def drift_after_first_calculation_controller_gate(limiter, base, scan, binding):
        gate = original(limiter, base, scan, binding)
        if binding.get("tag") == "SWE":
            seen_swe["count"] += 1
            # Four SWE admissions belong to the two country-input rounds.
            if seen_swe["count"] == 5:
                image.put_i32(fixture.CONTROLLERS + FRA_SLOT * 4, 1)
                seen_swe["mutated"] = True
        return gate

    monkeypatch.setattr(calculation._country, "_admit", drift_after_first_calculation_controller_gate)
    result = _run(monkeypatch, image)

    assert seen_swe["mutated"]
    assert result["status"] == "unknown"
    assert result["consistency"]["shared_mismatch_paths"] == ["calculation_gates"]
    assert _target(result)["fields"][gates.FIELD]["status"] == "unknown"


def test_two_pass_gate_value_change_is_local_and_does_not_discard_power(monkeypatch):
    image = fixture.make_image()
    _admit_swe(image)
    _install_gate(image, flags=0)
    original = gates.read_fields
    calls = {"count": 0}

    def changed_result(*args, **kwargs):
        result = original(*args, **kwargs)
        calls["count"] += 1
        if calls["count"] > 1:
            result[gates.FIELD]["value"]["controller_type_enabled"] = False
        return result

    monkeypatch.setattr(calculation._gates, "read_fields", changed_result)
    result = _run(monkeypatch, image)

    target = _target(result)
    assert calls["count"] == 2
    assert result["status"] == "observed"
    assert target["fields"][inputs.FIELD_PROVINCE_TRADE_POWER]["status"] == "known"
    assert target["fields"][gates.FIELD]["status"] == "unknown"
    assert target["fields"][gates.FIELD]["reason"] == "CALCULATION_GATES_CHANGED_BETWEEN_PASSES"
    assert target["field_consistency"][gates.FIELD]["status"] == "changed"
