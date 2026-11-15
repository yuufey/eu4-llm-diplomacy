"""Bounded offline tests for the N06 governing-capacity cache projection."""
from __future__ import annotations

from copy import deepcopy

import pytest

from bridge.information import governance_capacity_memory as memory
from bridge.information import governance_capacity_values as values
from bridge.information import foreign_quality_memory as quality
from bridge.tests import test_information_country_scale_development_memory as scale_fixture


BASE = scale_fixture.BASE
TARGET_PTR = scale_fixture.TARGET_PTR
MANAGER = 0x70000000
VALUES = 0x71000000
BASE_OBJECT = 0x72000000
PROCESSOR = 0x73000000


def _qword(value: int) -> bytes:
    return int(value).to_bytes(8, "little", signed=False)


def _i32(value: int) -> bytes:
    return int(value).to_bytes(4, "little", signed=True)


def _processor_cell(modifier_id: int) -> int:
    return MANAGER + modifier_id * quality.MODIFIER_PROCESSOR_STRIDE + quality.MODIFIER_PROCESSOR_OFFSET


def _install(reader, *, used=2500, base=1000, additive=200, ratio=500, state=0,
             dense=True, sparse_entries=None, base_pointer=BASE_OBJECT,
             processor_409=0, processor_410=0):
    reader.put(TARGET_PTR + memory.GOVERNANCE_CAPACITY_USED_OFFSET, _i32(used))
    reader.put(TARGET_PTR + quality.COUNTRY_CACHE_STATE_OFFSET, _i32(state))
    reader.put(TARGET_PTR + memory.GOVERNANCE_CAPACITY_BASE_POINTER_OFFSET,
               _qword(base_pointer))
    if base_pointer == BASE_OBJECT:
        reader.put(BASE_OBJECT + memory.GOVERNANCE_CAPACITY_BASE_VALUE_OFFSET, _i32(base))

    reader.put(BASE + quality.MODIFIER_PROCESSOR_GLOBAL_RVA, _qword(MANAGER))
    reader.put(_processor_cell(memory.MODIFIER_ADD_ID), _qword(processor_409))
    reader.put(_processor_cell(memory.MODIFIER_RATIO_ID), _qword(processor_410))

    modifier = TARGET_PTR + quality.COUNTRY_MODIFIER_OBJECT_OFFSET
    entries = list(sparse_entries or [])
    reader.put(modifier + quality.MODIFIER_DENSE_FLAG_OFFSET, bytes([1 if dense else 0]))
    if dense:
        reader.put(modifier + quality.MODIFIER_VALUES_POINTER_OFFSET, _qword(VALUES))
        reader.put(modifier + quality.MODIFIER_SPARSE_COUNT_OFFSET, _i32(0))
        reader.put(VALUES + memory.MODIFIER_ADD_ID * 8 + 4, _i32(additive))
        reader.put(VALUES + memory.MODIFIER_RATIO_ID * 8 + 4, _i32(ratio))
    else:
        reader.put(modifier + quality.MODIFIER_VALUES_POINTER_OFFSET,
                   _qword(VALUES if entries else 0))
        reader.put(modifier + quality.MODIFIER_SPARSE_COUNT_OFFSET, _i32(len(entries)))
        for index, (modifier_id, value) in enumerate(entries):
            reader.put(VALUES + index * 8, _i32(modifier_id) + _i32(value))


def _environment(**kwargs):
    reader, binding, _ = scale_fixture.environment()
    _install(reader, **kwargs)
    return reader, binding


def _read(reader, binding, fields=memory.FIELDS):
    before = deepcopy(reader.bytes)
    result = memory.read_fields(reader, BASE, binding, fields)
    assert reader.bytes == before, "the governing-capacity reader must not write input memory"
    return result


def _dto(name, value):
    spec = values.NUMBER_SPECS[name]
    width = spec["width"]
    return {"status": "known", "value": value, "raw": value,
            "raw_hex": value.to_bytes(width, "little", signed=True).hex(),
            "unit": spec["unit"], "scale": spec["scale"], "period": "current",
            "partial": True, "complete": False, "basis": spec["basis"],
            "value_origin": spec["value_origin"]}


def _summary(*, used=2, limit=4, fraction=500, headroom=2):
    return {
        "status": "known",
        "value": {
            "used": _dto("used", used),
            "limit": _dto("limit", limit),
            "used_fraction": _dto("used_fraction", fraction),
            "headroom": _dto("headroom", headroom),
        },
        "unit": memory.UNIT, "scale": memory.SCALE, "period": "current",
        "partial": True, "complete": False, "basis": memory.BASIS,
        "value_origin": memory.VALUE_ORIGIN,
    }


def test_dense_components_build_signed_capacity_summary_and_keep_private_reads_out_of_numbers():
    reader, binding = _environment()

    field = _read(reader, binding)[memory.FIELD]

    assert field["status"] == "known"
    assert field["unit"] == memory.UNIT == "governing_capacity_summary"
    assert field["scale"] == memory.SCALE == 1
    assert field["period"] == "current" and field["partial"] is True and field["complete"] is False
    assert field["basis"] == memory.BASIS
    assert field["value_origin"] == memory.VALUE_ORIGIN
    assert field["value"] == {
        "used": _dto("used", 2500),
        "limit": _dto("limit", 1800),
        "used_fraction": _dto("used_fraction", 1388),
        "headroom": _dto("headroom", -700),
    }
    assert "raw" not in field and "raw_hex" not in field
    assert field["raw_inputs"]["modifier_409"]["raw_inputs"]["modifier_id"] == 409
    assert field["raw_inputs"]["modifier_410"]["raw_inputs"]["modifier_id"] == 410
    assert field["raw_inputs"]["modifier_409"]["raw_inputs"]["processor_pointer"] == "0x0"
    assert field["raw_inputs"]["modifier_410"]["raw_inputs"]["processor_pointer"] == "0x0"
    assert field["raw_inputs"]["used"]["raw"] == 2500
    assert all("address" not in nested and "processor_pointer" not in nested
               for nested in field["value"].values())
    assert field["raw_inputs"]["budget"]["calls"] == len(field["raw_inputs"]["reads"])


def test_sparse_modifiers_use_first_409_and_410_matches():
    reader, binding = _environment(
        dense=False,
        sparse_entries=[(133, 9000), (409, 200), (409, -500), (410, 500), (410, -900)],
    )

    field = _read(reader, binding)[memory.FIELD]

    assert field["status"] == "known"
    assert field["value"]["limit"]["raw"] == 1800
    assert field["value"]["used_fraction"]["raw"] == 1388
    assert field["raw_inputs"]["modifier_409"]["raw_inputs"]["first_match_index"] == 1
    assert field["raw_inputs"]["modifier_410"]["raw_inputs"]["first_match_index"] == 3


def test_calculating_cache_keeps_used_but_withdraws_limit_and_derived_numbers():
    reader, binding = _environment(state=1)

    field = _read(reader, binding)[memory.FIELD]

    assert field["status"] == "known"
    assert field["value"]["used"] == _dto("used", 2500)
    assert field["value"]["limit"] == {"status": "unknown", "reason": "MILITARY_CACHE_CALCULATING"}
    assert field["value"]["used_fraction"]["reason"] == "GOVERNANCE_CAPACITY_LIMIT_UNAVAILABLE"
    assert field["value"]["headroom"]["reason"] == "GOVERNANCE_CAPACITY_LIMIT_UNAVAILABLE"
    assert not any("modifier_processor_manager" in label for _, _, label in reader.calls)


@pytest.mark.parametrize("bad_pointer", (0x10, TARGET_PTR, MANAGER))
def test_bad_native_base_pointer_withdraws_limit_but_not_direct_used(bad_pointer):
    reader, binding = _environment(base_pointer=bad_pointer)

    field = _read(reader, binding)[memory.FIELD]

    assert field["status"] == "known"
    assert field["value"]["used"] == _dto("used", 2500)
    assert field["value"]["limit"]["status"] == "unknown"
    assert field["value"]["used_fraction"]["status"] == "unknown"
    assert field["value"]["headroom"]["status"] == "unknown"


@pytest.mark.parametrize("which", (409, 410))
def test_nonnull_modifier_processor_withdraws_limit_without_withdrawing_used(which):
    reader, binding = _environment(**({"processor_409": PROCESSOR} if which == 409
                                      else {"processor_410": PROCESSOR}))

    field = _read(reader, binding)[memory.FIELD]

    assert field["status"] == "known"
    assert field["value"]["used"]["raw"] == 2500
    assert field["value"]["limit"]["status"] == "unknown"
    assert field["value"]["used_fraction"]["status"] == "unknown"
    assert field["value"]["headroom"]["status"] == "unknown"
    assert field["raw_inputs"][f"modifier_{which}"]["reason"] == "MODIFIER_PROCESSOR_PRESENT"


def test_zero_limit_is_not_applicable_for_ratio_and_headroom_is_not_clamped():
    reader, binding = _environment(used=1500, base=0, additive=0, ratio=0)

    field = _read(reader, binding)[memory.FIELD]

    assert field["value"]["limit"] == _dto("limit", 0)
    assert field["value"]["used_fraction"] == {
        "status": "not_applicable", "reason": "GOVERNANCE_CAPACITY_LIMIT_ZERO"}
    assert field["value"]["headroom"] == _dto("headroom", -1500)


@pytest.mark.parametrize(("used", "expected_ratio", "expected_headroom"),
                         [(-125, -125, 1125), (0, 0, 1000)])
def test_leaf_preserves_negative_and_zero_used_values(used, expected_ratio, expected_headroom):
    reader, binding = _environment(used=used, base=1000, additive=0, ratio=0)

    field = _read(reader, binding)[memory.FIELD]

    assert field["value"]["used"] == _dto("used", used)
    assert field["value"]["limit"] == _dto("limit", 1000)
    assert field["value"]["used_fraction"] == _dto("used_fraction", expected_ratio)
    assert field["value"]["headroom"] == _dto("headroom", expected_headroom)


def test_used_read_failure_does_not_hide_a_known_limit():
    reader, binding = _environment()
    reader.error_labels.add("governance_capacity.used_i32")

    field = _read(reader, binding)[memory.FIELD]

    assert field["status"] == "known"
    assert field["value"]["used"]["status"] == "unknown"
    assert field["value"]["limit"] == _dto("limit", 1800)
    assert field["value"]["used_fraction"]["status"] == "unknown"
    assert field["value"]["headroom"]["status"] == "unknown"


def test_wrong_target_and_unsupported_field_do_not_read_memory():
    reader, binding = _environment()
    other = deepcopy(binding)
    other["tag"] = "ENG"
    fullref = scale_fixture.fullref(122, "ENG")
    other["fullref"] = hex(fullref)
    other["fullref_raw_hex"] = _qword(fullref).hex()

    field = _read(reader, other)[memory.FIELD]
    assert field["status"] == "unknown" and field["reason"] == "TARGET_COUNTRY_SCOPE"
    assert reader.calls == []

    reader, binding = _environment()
    assert _read(reader, binding, fields=("not_supported",)) == {
        "not_supported": {"status": "unknown", "reason": "FIELD_NOT_SUPPORTED"}}
    assert reader.calls == []


@pytest.mark.parametrize("function,arguments", [
    (values.capacity_limit, (True, 0, 0)),
    (values.capacity_limit, (1 << 31, 0, 0)),
    (values.used_ratio, (0, False)),
    (values.used_ratio, (0, 1 << 31)),
    (values.headroom_signed, (False, 0)),
    (values.headroom_signed, (0, -(1 << 31) - 1)),
])
def test_pure_arithmetic_rejects_bool_and_out_of_range_inputs(function, arguments):
    with pytest.raises(ValueError):
        function(*arguments)


def test_pure_arithmetic_uses_i32_wrap_truncation_zero_and_signed64_headroom():
    assert values.capacity_limit(1000, 200, 500) == 1800
    assert values.capacity_limit(-1, 0, 0) == -1
    assert values.capacity_limit(100, -200, -2000) == 0
    assert values.capacity_limit((1 << 31) - 1, 1, 0) == -(1 << 31)
    assert values.capacity_limit((1 << 31) - 1, 0, 1000) == -2
    assert values.used_ratio(1, 3) == 333
    assert values.used_ratio(-1, 3) == -333
    assert values.used_ratio(2, -3) == -666
    assert values.used_ratio(10, 0) is None
    assert values.headroom_signed(-(1 << 31), (1 << 31) - 1) == 0xFFFFFFFF
    assert values.headroom_signed((1 << 31) - 1, -(1 << 31)) == -0xFFFFFFFF


@pytest.mark.parametrize("name", tuple(values.NUMBER_SPECS))
def test_named_number_validator_accepts_exact_known_shape(name):
    width = values.NUMBER_SPECS[name]["width"]
    value = (1 << (width * 8 - 1)) - 1
    assert values.validate_number_field(name, _dto(name, value)) is True


@pytest.mark.parametrize("mutation", ("pointer", "bool", "unit", "scale", "hex", "extra"))
def test_named_number_validator_rejects_private_or_malformed_dto(mutation):
    field = _dto("used", 12)
    if mutation == "pointer":
        field["country_pointer"] = hex(TARGET_PTR)
    elif mutation == "bool":
        field["raw"] = True
        field["value"] = True
    elif mutation == "unit":
        field["unit"] = "ratio"
    elif mutation == "scale":
        field["scale"] = True
    elif mutation == "hex":
        field["raw_hex"] = "00000000"
    else:
        field["raw_inputs"] = {"base_pointer": hex(BASE_OBJECT)}
    assert values.validate_number_field("used", field) is False


def test_whole_summary_validator_accepts_exact_known_shape_and_safe_unknown():
    assert values.validate_public_field(_summary()) is True
    assert values.validate_public_field({"status": "unknown", "reason": "CACHE_MISSING"})
    assert not values.validate_public_field({"status": "unknown", "reason": "bad"})
    assert not values.validate_public_field({"status": "unknown", "reason": "X" * 129})
    assert not values.validate_public_field({"status": "unknown", "reason": "CACHE_MISSING",
                                             "address": hex(TARGET_PTR)})


@pytest.mark.parametrize("mutation", ("pointer", "unit", "scale", "extra"))
def test_whole_summary_validator_rejects_private_or_malformed_outer_dto(mutation):
    field = _summary()
    if mutation == "pointer":
        field["raw_inputs"] = {"base_pointer": hex(BASE_OBJECT)}
    elif mutation == "unit":
        field["unit"] = "ratio"
    elif mutation == "scale":
        field["scale"] = True
    else:
        field["address"] = hex(TARGET_PTR)
    assert values.validate_public_field(field) is False


def test_named_number_validator_rejects_used_and_limit_contract_swaps():
    assert not values.validate_number_field("used", _dto("limit", 4))
    assert not values.validate_number_field("limit", _dto("used", 2))

    swapped = _summary()
    swapped["value"]["used"] = _dto("limit", 4)
    swapped["value"]["limit"] = _dto("used", 2)
    assert not values.validate_public_field(swapped)


def test_whole_summary_validator_enforces_derived_values_and_zero_limit_status():
    zero = _summary(used=2, limit=0, fraction=0, headroom=-2)
    zero["value"]["used_fraction"] = {
        "status": "not_applicable", "reason": "GOVERNANCE_CAPACITY_LIMIT_ZERO"}
    assert values.validate_public_field(zero) is True

    wrong_zero = deepcopy(zero)
    wrong_zero["value"]["used_fraction"] = {
        "status": "unknown", "reason": "GOVERNANCE_CAPACITY_LIMIT_ZERO"}
    assert values.validate_public_field(wrong_zero) is False

    wrong_fraction = _summary()
    wrong_fraction["value"]["used_fraction"] = _dto("used_fraction", 499)
    assert values.validate_public_field(wrong_fraction) is False

    wrong_headroom = _summary()
    wrong_headroom["value"]["headroom"] = _dto("headroom", 3)
    assert values.validate_public_field(wrong_headroom) is False

    incomplete_inputs = _summary()
    incomplete_inputs["value"]["used"] = {"status": "unknown", "reason": "CACHE_MISSING"}
    assert values.validate_public_field(incomplete_inputs) is False


def test_shared_read_budget_failure_withdraws_the_entire_summary(monkeypatch):
    reader, binding = _environment()
    monkeypatch.setattr(quality, "MAX_TOTAL_READ_BYTES", 1)

    field = _read(reader, binding)[memory.FIELD]

    assert field["status"] == "unknown"
    assert field["reason"] == "GOVERNANCE_CAPACITY_READ_BUDGET_EXCEEDED"
    assert "value" not in field
    assert field["raw_inputs"]["budget"]["bytes_requested"] <= 1
