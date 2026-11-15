"""Offline composition tests for province and country trade-power inputs."""
from __future__ import annotations

from copy import deepcopy

import pytest

from bridge.information import country_reference_memory as country_memory
from bridge.information import country_view_admission_memory as admission
from bridge.information import province_reference_memory as province_memory
from bridge.information import province_trade_power_country_memory as memory
from bridge.information import province_trade_power_inputs_memory as inputs
from bridge.tests import test_information_province_state_memory as parent_fixture

BASE = parent_fixture.BASES[0]
PROVINCE_ID = parent_fixture.PROVINCE_ID
FRA_SLOT = parent_fixture.FRA_SLOT
SWE_SLOT = parent_fixture.SWE_SLOT
FRA_REF = parent_fixture._fullref("FRA", FRA_SLOT)
SWE_REF = parent_fixture._fullref("SWE", SWE_SLOT)
COUNTRY_BASIS = "native_country_province_trade_power_modifier_processor_absent"


def _parent_field(field: str, raw: int = 1250) -> dict:
    if field == inputs.FIELD_PROVINCE_TRADE_POWER:
        unit = "trade_power"
        basis = "native_province_trade_power_trigger_cache"
    elif field == inputs.FIELD_PROVINCE_TRADE_POWER_VALUE:
        unit = "trade_power"
        basis = "native_province_numeric_modifier_processor_absent"
    else:
        unit = "ratio"
        basis = "native_province_numeric_modifier_processor_absent"
    return {
        "status": "known", "complete": False, "period": "current", "basis": basis,
        "value": {"raw": raw, "scale": 1000, "unit": unit},
        "raw_inputs": {"synthetic_field": field, "trace": "private"},
    }


def _country_field(tag: str, raw: int = 300) -> dict:
    return {
        "status": "known", "complete": False, "period": "current",
        "basis": COUNTRY_BASIS,
        "value": {"country": tag, "raw": raw, "scale": 1000, "unit": "ratio"},
        "raw_inputs": {"country_pointer": "private", "raw_storage": "private"},
    }


def _admit_swe(image) -> None:
    """Give the synthetic FRA observer an explicit admitted SWE relation row."""
    fra = parent_fixture.COUNTRY_BASE + FRA_SLOT * 0x1000
    image.put_u64(fra + admission.RELATION_TABLE_OFFSET, parent_fixture.RELATION_TABLE)
    row = parent_fixture.RELATION_TABLE + SWE_SLOT * admission.RELATION_ROW_STRIDE
    image.put_u64(row + admission.RELATION_ROW_OWNER_OFFSET, parent_fixture.RELATION_OWNER)
    image.put_u64(row + admission.RELATION_ROW_RECIPIENT_FULLREF_OFFSET, SWE_REF)
    image.put_u64(parent_fixture.RELATION_OWNER + admission.RELATION_OWNER_COUNTERS_OFFSET,
                  parent_fixture.RELATION_COUNTERS)
    counter = (parent_fixture.RELATION_COUNTERS + admission.RELATION_COUNTER_FIRST_OFFSET
               + SWE_SLOT * admission.RELATION_COUNTER_STRIDE)
    image.put_i32(counter, 1)


def _run(monkeypatch, image, *, leaf=None):
    parent_reads = []
    leaf_reads = []

    def parent_reader(_reader, _base, _binding, fields):
        parent_reads.append(tuple(fields))
        return {field: _parent_field(field) for field in fields}

    def country_reader(_reader, _base, binding, fields):
        tag = binding["tag"]
        leaf_reads.append((tag, tuple(fields), deepcopy(dict(binding))))
        if leaf is not None:
            value = leaf(tag, len(leaf_reads))
        else:
            value = _country_field(tag, raw=100 if tag == "FRA" else 200)
        return {field: deepcopy(value) for field in fields}

    monkeypatch.setattr(memory._inputs, "read_fields", parent_reader)
    monkeypatch.setattr(memory._country_leaf, "read_fields", country_reader)
    result = memory.read_two_pass(image, BASE, PROVINCE_ID)
    return result, leaf_reads, parent_reads


def _target(result):
    return result["targets"][0]


def test_real_parent_scan_rebinds_both_countries_into_admission_without_rescanning(monkeypatch):
    image = parent_fixture.make_image()
    _admit_swe(image)
    admissions = []
    original = memory._owner._bound_admission

    def checked(read, base, bindings, observer, target):
        rows = bindings.get("rows")
        assert bindings.get("status") == "observed"
        assert isinstance(rows, list) and bindings.get("count") == len(rows)
        assert target in bindings.get("requested", {})
        selected = bindings["requested"][target]
        row = rows[selected["slot"]]
        assert selected["country_pointer"] == row["country_pointer"]
        assert selected["fullref"] == row["fullref"]
        admissions.append((observer, target, bindings["count"]))
        return original(read, base, bindings, observer, target)

    monkeypatch.setattr(memory._owner, "_bound_admission", checked)
    result, leaf_reads, _ = _run(monkeypatch, image)

    target = _target(result)
    assert result["status"] == "observed"
    assert result["consistency"]["status"] == "stable"
    assert target["fields"][memory.CONTROLLER_FIELD]["value"] == {
        "country": "SWE", "raw": 200, "scale": 1000, "unit": "ratio"}
    assert target["fields"][memory.OBSERVER_FIELD]["value"] == {
        "country": "FRA", "raw": 100, "scale": 1000, "unit": "ratio"}
    assert [item[0] for item in leaf_reads] == ["FRA", "SWE", "FRA", "SWE"]
    assert any(observer == "FRA" and country == "SWE" for observer, country, _ in admissions)
    # The parent performs one complete manager scan in each pass; child rebinds
    # use indexed fullrefs and preserve that scan for admission.
    assert sum(label == "country_reference.database_global"
               for _, _, label in image.reads) == 2
    assert result["budget"]["bytes_requested"] == sum(size for _, size, _ in image.reads)
    assert result["budget"]["calls"] == len(image.reads)
    assert result["budget"]["bytes_requested"] <= 512 * 1024
    assert result["budget"]["limit_bytes"] == 512 * 1024


def test_same_controller_and_observer_country_is_read_once_per_pass(monkeypatch):
    image = parent_fixture.make_image(controller_ref=FRA_REF)
    result, leaf_reads, _ = _run(monkeypatch, image)

    target = _target(result)
    assert result["status"] == "observed"
    assert target["fields"][memory.CONTROLLER_FIELD]["value"]["country"] == "FRA"
    assert target["fields"][memory.OBSERVER_FIELD]["value"]["country"] == "FRA"
    assert [item[0] for item in leaf_reads] == ["FRA", "FRA"]


@pytest.mark.parametrize("denial", ["discovery", "role"])
def test_parent_discovery_or_role_denial_performs_no_country_extension(monkeypatch, denial):
    image = parent_fixture.make_image(
        discovered=denial != "discovery", role_verified=denial != "role")
    result, leaf_reads, _ = _run(monkeypatch, image)

    assert leaf_reads == []
    assert "country_inputs_evidence" not in result
    assert not any("trade_country" in label for _, _, label in image.reads)
    assert result["status"] == "observed"
    assert _target(result)["fields"][memory.OBSERVER_FIELD]["status"] == "unknown"
    assert _target(result)["fields"][memory.CONTROLLER_FIELD]["status"] == "unknown"


def test_controller_admission_denial_is_local_to_controller_child(monkeypatch):
    image = parent_fixture.make_image()
    result, leaf_reads, _ = _run(monkeypatch, image)

    target = _target(result)
    assert result["status"] == "observed"
    assert target["fields"][memory.OBSERVER_FIELD]["status"] == "known"
    assert target["fields"][memory.CONTROLLER_FIELD]["status"] == "unknown"
    assert [item[0] for item in leaf_reads] == ["FRA", "FRA"]


def test_observer_role_drift_during_extension_invalidates_shared_capture(monkeypatch):
    image = parent_fixture.make_image()

    class RoleDrift:
        def __init__(self):
            self.seen = 0

        def read(self, address, size, label):
            if label == "foreign_tech.role.observer_controller":
                self.seen += 1
                if self.seen == 3:
                    image.put_i32(parent_fixture.CONTROLLERS + FRA_SLOT * 4, 1)
            return image.read(address, size, label)

    reader = RoleDrift()
    leaf_reads = []
    monkeypatch.setattr(memory._inputs, "read_fields",
                        lambda _r, _b, _binding, fields: {field: _parent_field(field) for field in fields})
    monkeypatch.setattr(memory._country_leaf, "read_fields",
                        lambda _r, _b, binding, fields: leaf_reads.append(binding["tag"])
                        or {field: _country_field(binding["tag"]) for field in fields})
    result = memory.read_two_pass(reader, BASE, PROVINCE_ID)

    assert reader.seen >= 3
    assert result["status"] == "unknown"
    assert result["consistency"]["shared_mismatch_paths"] == ["country_inputs"]
    assert leaf_reads == []


def test_observer_fullref_drift_against_retained_scan_invalidates_shared_capture(monkeypatch):
    image = parent_fixture.make_image()
    fra = parent_fixture.COUNTRY_BASE + FRA_SLOT * 0x1000
    changed = parent_fixture._fullref("FRA", FRA_SLOT, generation=0x1201)

    class RebindDrift:
        def __init__(self):
            self.changed = False

        def read(self, address, size, label):
            if label == "province_state.trade_country.observer.database_global" and not self.changed:
                image.put_u64(fra + country_memory.COUNTRY_FULLREF_OFFSET, changed)
                self.changed = True
            return image.read(address, size, label)

    reader = RebindDrift()
    result, leaf_reads, _ = _run(monkeypatch, reader)

    assert reader.changed
    assert result["status"] == "unknown"
    assert result["consistency"]["shared_mismatch_paths"] == ["country_inputs"]
    assert leaf_reads == []


def test_controller_pointer_change_with_same_fullref_is_not_stable(monkeypatch):
    image = parent_fixture.make_image()
    _admit_swe(image)
    new_pointer = parent_fixture.COUNTRY_BASE + 0x80000
    new_ref = SWE_REF.to_bytes(8, "little")

    class ControllerPointerDrift:
        def __init__(self):
            self.seen = 0

        def read(self, address, size, label):
            if label == "country_reference.database_global":
                self.seen += 1
                if self.seen == 2:
                    image.put_u64(parent_fixture.TABLE + SWE_SLOT * 8, new_pointer)
                    image.put(new_pointer + country_memory.COUNTRY_FULLREF_OFFSET, new_ref)
            return image.read(address, size, label)

    result, leaf_reads, _ = _run(monkeypatch, ControllerPointerDrift())

    target = _target(result)
    assert result["status"] == "observed"
    assert target["fields"][memory.OBSERVER_FIELD]["status"] == "known"
    assert target["fields"][memory.CONTROLLER_FIELD]["status"] == "unknown"
    assert target["fields"][memory.CONTROLLER_FIELD]["reason"] == "CONTROLLER_REFERENCE_CHANGED"
    assert [item[0] for item in leaf_reads].count("SWE") >= 1


def test_country_field_value_drift_between_passes_is_unknown_only_for_that_role(monkeypatch):
    image = parent_fixture.make_image()
    _admit_swe(image)

    def drifting_leaf(tag, call_number):
        if tag == "FRA":
            return _country_field(tag, 100 if call_number == 1 else 101)
        return _country_field(tag, 200)

    result, leaf_reads, _ = _run(monkeypatch, image, leaf=drifting_leaf)
    target = _target(result)

    assert result["status"] == "observed"
    assert target["fields"][memory.OBSERVER_FIELD]["status"] == "unknown"
    assert target["fields"][memory.OBSERVER_FIELD]["reason"] == "COUNTRY_INPUT_CHANGED_BETWEEN_PASSES"
    assert target["fields"][memory.CONTROLLER_FIELD]["status"] == "known"
    assert [item[0] for item in leaf_reads] == ["FRA", "SWE", "FRA", "SWE"]
