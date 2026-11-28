"""Offline tests for the shared province extension composition boundary."""
from __future__ import annotations

from copy import deepcopy

import pytest

from bridge.information import country_view_admission_memory as admission
from bridge.information import province_identity_memory as identity
from bridge.information import province_extension_memory as extension
from bridge.information import province_trade_power_country_memory as country
from bridge.information import province_trade_power_inputs_memory as inputs
from bridge.tests import test_information_province_state_memory as fixture


BASE = fixture.BASES[0]
PROVINCE_ID = fixture.PROVINCE_ID
FRA_SLOT = fixture.FRA_SLOT
SWE_SLOT = fixture.SWE_SLOT
FRA_REF = fixture._fullref("FRA", FRA_SLOT)
SWE_REF = fixture._fullref("SWE", SWE_SLOT)
ENG_REF = fixture._fullref("ENG", fixture.ENG_SLOT)
FIELD = "G02.province_node_allocation"
BASIS = "native_trade_node_province_component_reconstruction"
RECORD = fixture.RECORDS + PROVINCE_ID * identity.PROVINCE_RECORD_STRIDE


def _admit_swe(image) -> None:
    fra = fixture.COUNTRY_BASE + FRA_SLOT * 0x1000
    image.put_u64(fra + admission.RELATION_TABLE_OFFSET, fixture.RELATION_TABLE)
    row = fixture.RELATION_TABLE + SWE_SLOT * admission.RELATION_ROW_STRIDE
    image.put_u64(row + admission.RELATION_ROW_OWNER_OFFSET, fixture.RELATION_OWNER)
    image.put_u64(row + admission.RELATION_ROW_RECIPIENT_FULLREF_OFFSET, SWE_REF)
    image.put_u64(fixture.RELATION_OWNER + admission.RELATION_OWNER_COUNTERS_OFFSET,
                  fixture.RELATION_COUNTERS)
    counter = (fixture.RELATION_COUNTERS + admission.RELATION_COUNTER_FIRST_OFFSET
               + SWE_SLOT * admission.RELATION_COUNTER_STRIDE)
    image.put_i32(counter, 1)


def _parent_field(field: str) -> dict:
    unit = "ratio" if field.endswith("modifier") else "trade_power"
    basis = ("native_province_trade_power_trigger_cache" if field == inputs.FIELD_PROVINCE_TRADE_POWER
             else "native_province_numeric_modifier_processor_absent")
    return {
        "status": "known", "complete": False, "period": "current", "basis": basis,
        "value": {"raw": 1250, "scale": 1000, "unit": unit},
        "raw_inputs": {"synthetic_parent_field": field},
    }


def _country_field(tag: str, field: str) -> dict:
    return {
        "status": "known", "complete": False, "period": "current",
        "basis": "native_country_province_trade_power_modifier_processor_absent",
        "value": {"country": tag, "raw": 100 if tag == "FRA" else 200,
                  "scale": 1000, "unit": "ratio"},
        "raw_inputs": {"synthetic_country_field": field},
    }


def _allocation_field(*, raw: int = 1250) -> dict:
    return {
        "status": "known", "complete": False, "period": "current", "basis": BASIS,
        "value": {
            "node_id": "bordeaux",
            "center_province_id": 2,
            "province_id": PROVINCE_ID,
            "recipient_country": "SWE",
            "contribution_raw": raw,
            "observer_country": "FRA",
            "observer_contribution_raw": 0,
            "observer_node_province_power_cache_raw": 2200,
            "observed_observer_province_power_sum_raw": 0,
            "observer_sum_complete": False,
            "matches_observer_cache": None,
            "member_count": 5,
            "observed_member_count": 1,
            "owner_present": True,
            "scale": 1000,
            "unit": "trade_power",
        },
        "raw_inputs": {"private_pointer": "0x123456789abcdef0"},
    }


def _install_parent_leafs(monkeypatch) -> None:
    def parent_fields(_reader, _base, _binding, fields):
        return {field: _parent_field(field) for field in fields}

    def country_fields(_reader, _base, binding, fields):
        return {field: _country_field(binding["tag"], field) for field in fields}

    monkeypatch.setattr(country._inputs, "read_fields", parent_fields)
    monkeypatch.setattr(country._country_leaf, "read_fields", country_fields)


def _run(monkeypatch, image, read_fields, *, parent_reader=None):
    _install_parent_leafs(monkeypatch)
    return extension.extend(
        image, BASE, PROVINCE_ID, observer="FRA",
        parent_reader=parent_reader or country.read_two_pass,
        fields=(FIELD,), read_fields=read_fields,
    )


def _target(result):
    return result["targets"][0]


def test_extension_reuses_parent_scan_real_bindings_and_one_shared_budget(monkeypatch):
    image = fixture.make_image()
    _admit_swe(image)
    callback_inputs = []

    def read_allocation(_reader, base, binding, province_scan, observer, controller):
        callback_inputs.append((base, deepcopy(binding), deepcopy(province_scan),
                                deepcopy(observer), deepcopy(controller)))
        return {FIELD: _allocation_field()}

    result = _run(monkeypatch, image, read_allocation)

    target = _target(result)
    assert result["status"] == "observed"
    assert result["consistency"]["status"] == "stable"
    assert target["fields"][inputs.FIELD_PROVINCE_TRADE_POWER]["status"] == "known"
    assert target["fields"][FIELD]["status"] == "known"
    assert target["field_consistency"][FIELD]["status"] == "stable"
    assert len(callback_inputs) == 2
    for base, binding, scan, observer, controller in callback_inputs:
        assert base == BASE
        assert binding["province_id"] == PROVINCE_ID
        assert binding["record_pointer"] == hex(RECORD)
        assert scan["status"] == "observed"
        assert scan["requested"][str(PROVINCE_ID)]["record_pointer"] == hex(RECORD)
        assert observer["tag"] == "FRA"
        assert observer["fullref_raw_hex"] == FRA_REF.to_bytes(8, "little").hex()
        assert controller["tag"] == "SWE"
        assert controller["fullref_raw_hex"] == SWE_REF.to_bytes(8, "little").hex()

    # Two complete manager scans belong to the real 203 parent. Extension
    # rebinds use its retained rows and the same aggregate 512 KiB budget.
    assert sum(label == "country_reference.database_global"
               for _, _, label in image.reads) == 2
    assert result["budget"]["bytes_requested"] == sum(size for _, size, _ in image.reads)
    assert result["budget"]["calls"] == len(image.reads)
    assert result["budget"]["bytes_requested"] <= 512 * 1024
    assert result["budget"]["limit_bytes"] == 512 * 1024

    group = result["province_extension_evidence"][FIELD]
    assert set(group) == {"pass1", "pass2"}
    assert all(group[phase]["shared_valid"] for phase in ("pass1", "pass2"))
    assert all(group[phase]["before"] and group[phase]["after"]
               for phase in ("pass1", "pass2"))


@pytest.mark.parametrize("denial", ["discovery", "controller"])
def test_parent_discovery_or_controller_denial_never_calls_child(
        monkeypatch, denial):
    image = fixture.make_image(discovered=denial != "discovery")
    if denial != "controller":
        _admit_swe(image)
    calls = []

    def read_allocation(*args):
        calls.append(args)
        return {FIELD: _allocation_field()}

    result = _run(monkeypatch, image, read_allocation)

    assert calls == []
    assert result["status"] == "observed"
    expected_parent_status = "known" if denial == "controller" else "unknown"
    assert (_target(result)["fields"][inputs.FIELD_PROVINCE_TRADE_POWER]["status"]
            == expected_parent_status)
    assert _target(result)["fields"][FIELD]["status"] == "unknown"
    assert "province_extension_evidence" not in result


def test_human_observer_with_positive_discovery_can_use_extension(monkeypatch):
    image = fixture.make_image(role_verified=False)
    _admit_swe(image)
    calls = []
    def read_allocation(*args):
        calls.append(args)
        return {FIELD: _allocation_field()}
    result = _run(monkeypatch, image, read_allocation)
    assert calls
    assert result['status'] == 'observed'
    assert _target(result)['fields'][FIELD]['status'] == 'known'


@pytest.mark.parametrize("drift", ["controller_ref", "province", "observer_role"])
def test_shared_identity_drift_during_child_retracts_the_whole_snapshot(
        monkeypatch, drift):
    image = fixture.make_image()
    _admit_swe(image)
    calls = []

    def mutate_shared_state():
        if drift == "controller_ref":
            image.put_u64(RECORD + country._province.CONTROLLER_FULLREF_OFFSET, ENG_REF)
        elif drift == "province":
            image.put_i32(RECORD + identity.PROVINCE_ID_OFFSET, PROVINCE_ID + 1)
        else:
            image.put_i32(fixture.CONTROLLERS + FRA_SLOT * 4, 1)

    def read_allocation(*args):
        calls.append(args)
        if len(calls) == 1:
            mutate_shared_state()
        return {FIELD: _allocation_field()}

    result = _run(monkeypatch, image, read_allocation)

    assert calls
    assert result["status"] == "unknown"
    assert result["consistency"]["shared_mismatch_paths"] == ["province_extension"]
    assert all(value["status"] == "unknown" for value in _target(result)["fields"].values())


def test_child_exception_is_local_when_shared_revalidation_stays_stable(monkeypatch):
    image = fixture.make_image()
    _admit_swe(image)
    calls = []

    def read_allocation(*args):
        calls.append(args)
        if len(calls) == 1:
            raise RuntimeError("synthetic private leaf failure")
        return {FIELD: _allocation_field()}

    result = _run(monkeypatch, image, read_allocation)

    group = result["province_extension_evidence"][FIELD]
    assert len(calls) == 2
    assert all(group[phase]["shared_valid"] for phase in ("pass1", "pass2"))
    assert "after" in group["pass1"]
    assert result["status"] == "observed"
    assert _target(result)["fields"][inputs.FIELD_PROVINCE_TRADE_POWER]["status"] == "known"
    assert _target(result)["fields"][FIELD]["status"] == "unknown"
    assert _target(result)["fields"][FIELD]["reason"] == (
        "PROVINCE_EXTENSION_CHANGED_BETWEEN_PASSES")


def test_leaf_exception_does_not_skip_after_validation(monkeypatch):
    image = fixture.make_image()
    _admit_swe(image)
    calls = []

    def read_allocation(*args):
        calls.append(args)
        if len(calls) == 2:
            # The last leaf call fails after changing a shared binding. Without
            # the mandatory after-check this would look like a local field miss.
            image.put_u64(RECORD + country._province.CONTROLLER_FULLREF_OFFSET, ENG_REF)
            raise RuntimeError("synthetic private leaf failure")
        return {FIELD: _allocation_field()}

    result = _run(monkeypatch, image, read_allocation)

    assert len(calls) == 2
    assert result["status"] == "unknown"
    assert result["consistency"]["shared_mismatch_paths"] == ["province_extension"]
    assert _target(result)["fields"][inputs.FIELD_PROVINCE_TRADE_POWER]["status"] == "unknown"
    assert _target(result)["fields"][FIELD]["status"] == "unknown"


def test_child_value_drift_is_local_and_keeps_parent_fields(monkeypatch):
    image = fixture.make_image()
    _admit_swe(image)
    calls = []

    def read_allocation(*args):
        calls.append(args)
        return {FIELD: _allocation_field(raw=1250 if len(calls) == 1 else 1251)}

    result = _run(monkeypatch, image, read_allocation)

    assert result["status"] == "observed"
    assert _target(result)["fields"][inputs.FIELD_PROVINCE_TRADE_POWER]["status"] == "known"
    assert _target(result)["fields"][FIELD]["status"] == "unknown"
    assert _target(result)["fields"][FIELD]["reason"] == (
        "PROVINCE_EXTENSION_CHANGED_BETWEEN_PASSES")
    assert _target(result)["field_consistency"][FIELD]["status"] == "changed"


def test_extension_metadata_is_scoped_by_field_group(monkeypatch):
    image = fixture.make_image()
    _admit_swe(image)
    sentinel = {"pass1": {"kept": True}}

    def parent_with_prior_extension(read, base, province_id, *, observer):
        result = country.read_two_pass(read, base, province_id, observer=observer)
        result["province_extension_evidence"] = {"G02.future_extension": deepcopy(sentinel)}
        return result

    result = _run(monkeypatch, image,
        lambda *_args: {FIELD: _allocation_field()}, parent_reader=parent_with_prior_extension)

    evidence = result["province_extension_evidence"]
    assert evidence["G02.future_extension"] == sentinel
    assert set(evidence[FIELD]) == {"pass1", "pass2"}
