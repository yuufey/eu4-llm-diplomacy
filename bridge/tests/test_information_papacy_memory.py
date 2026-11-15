"""Fake-memory tests for the copied S02 papacy state leaf."""
from __future__ import annotations

import pytest

from bridge.information import papacy_memory as memory
from bridge.tests import test_information_religion_defender_memory as defender_fake


BASE = defender_fake.MODULE_BASE
DATABASE = defender_fake.DATABASE
TABLE = defender_fake.TABLE
RECORDS = defender_fake.RECORDS
RELIGION = defender_fake.RELIGION
TARGET = defender_fake.TARGET_COUNTRY
WORLD = defender_fake.WORLD
MANAGER = defender_fake.MANAGER
DEFINITION = 0x59000000
OWNER = 0x5A000000
PAPACY_STATE = 0x5B000000
OTHER = defender_fake.OTHER
COUNTRY_FULLREF_OFFSET = 0x20
COUNTRY_RELIGION_OFFSET = 0xF30
PAPAL_INFLUENCE_OFFSET = 0xF50
STATE_STRIDE = 0x50


def _qword(value):
    return value.to_bytes(8, "little", signed=False)


def _i32(value):
    return value.to_bytes(4, "little", signed=True)


def _fullref(tag, slot, generation=0xA5):
    return defender_fake._fullref(tag, slot, generation)


def _scenario(*, target_tag="FRA", controller_tag="FRA", papacy_used=True,
              owner_id=2, influence=537, treasury=123456, controller_reference=None,
              definition_pointer=None, owner_pointer=OWNER, owner_vtable=None,
              religion_vtable=None, owner_state_id=None, record_owner=None,
              record_state_pointer=PAPACY_STATE, database_count=20):
    reader, binding, layout = defender_fake._scenario(
        target_tag=target_tag, holder_tag=controller_tag)
    cells = reader.cells
    definition_pointer = (DEFINITION if papacy_used else 0) if definition_pointer is None else definition_pointer
    selected_religion = RELIGION
    controller_reference = (layout["holder_ref"] if controller_reference is None
                            else controller_reference)
    owner_state_id = owner_id if owner_state_id is None else owner_state_id
    owner_vtable = (BASE + memory.RELIGION_VTABLE_RVA
                    if owner_vtable is None else owner_vtable)
    religion_vtable = (BASE + memory.RELIGION_VTABLE_RVA
                       if religion_vtable is None else religion_vtable)
    record = RECORDS + (owner_id - 1) * STATE_STRIDE if 1 <= owner_id <= 4096 else RECORDS

    cells[TARGET + COUNTRY_RELIGION_OFFSET] = _qword(selected_religion)
    cells[RELIGION] = _qword(religion_vtable)
    cells[RELIGION + 0x578] = _qword(definition_pointer)
    cells[TARGET + PAPAL_INFLUENCE_OFFSET] = _i32(influence)
    cells[DEFINITION + 0x60] = _qword(owner_pointer)
    if owner_pointer:
        cells[owner_pointer] = _qword(owner_vtable)
        cells[owner_pointer + 0x70] = _i32(owner_state_id)
    if 1 <= owner_id <= 4096:
        if record_owner is None:
            record_owner = owner_pointer
        cells[record + 0x10] = _qword(record_owner)
        cells[record + 0x40] = _qword(record_state_pointer)
    cells[DATABASE + 0x124] = _i32(database_count)
    if record_state_pointer:
        cells[record_state_pointer + 0x24] = _qword(controller_reference)
        cells[record_state_pointer + 0x100] = _i32(treasury)

    layout.update({
        "definition": definition_pointer,
        "owner": owner_pointer,
        "state": record_state_pointer,
        "record": record,
        "influence_cell": TARGET + PAPAL_INFLUENCE_OFFSET,
        "definition_cell": RELIGION + 0x578,
        "owner_cell": DEFINITION + 0x60,
        "owner_id_cell": owner_pointer + 0x70 if owner_pointer else None,
        "record_owner_cell": record + 0x10,
        "record_state_cell": record + 0x40,
        "controller_cell": record_state_pointer + 0x24 if record_state_pointer else None,
        "treasury_cell": record_state_pointer + 0x100 if record_state_pointer else None,
        "controller_reference": controller_reference,
    })
    return reader, binding, layout


def _read(reader, binding, fields=None):
    requested = (memory.FIELD_ID,) if fields is None else fields
    return memory.read_fields(reader, BASE, binding, requested)


def _known(field):
    assert field["status"] == "known"
    assert field["complete"] is False
    assert field["basis"] == memory.BASIS
    return field["value"]


def _controller_unknown(field):
    value = _known(field)
    assert value["uses_papacy"] is True
    assert value["controller"] == {
        "status": "unknown", "reason": "PAPACY_CONTROLLER_UNRESOLVED"
    }
    assert value["papal_influence"]["status"] == "known"
    assert value["curia_treasury"]["status"] == "known"


@pytest.mark.parametrize(("target_tag", "controller_tag", "expected"), [
    ("FRA", "FRA", True), ("FRA", "ENG", False), ("PAP", "PAP", True),
])
def test_valid_controller_is_checked_by_full_country_reference(target_tag, controller_tag, expected):
    reader, binding, _ = _scenario(target_tag=target_tag, controller_tag=controller_tag)
    field = _read(reader, binding)[memory.FIELD_ID]
    value = _known(field)
    assert value["uses_papacy"] is True
    assert value["controller"] == {
        "status": "known", "country": controller_tag,
        "is_target_controller": expected,
    }


def test_negative_scalars_preserve_signed_raw_bytes_and_exact_dtos():
    influence, treasury = -712, -123456
    reader, binding, _ = _scenario(influence=influence, treasury=treasury)
    value = _known(_read(reader, binding)[memory.FIELD_ID])
    assert value["papal_influence"] == {
        "status": "known", "value": influence, "raw": influence,
        "raw_hex": _i32(influence).hex(), "unit": "papal_influence",
        "scale": 1000, "period": "current", "partial": True, "complete": False,
        "basis": "native_current_papal_influence_cache",
        "value_origin": "copied_native_papacy_state",
    }
    assert value["curia_treasury"] == {
        "status": "known", "value": treasury, "raw": treasury,
        "raw_hex": _i32(treasury).hex(), "unit": "ducats",
        "scale": 1000, "period": "current", "partial": True, "complete": False,
        "basis": "native_current_curia_treasury_cache",
        "value_origin": "copied_native_papacy_state",
    }


def test_null_definition_means_not_applicable_and_does_not_read_state():
    reader, binding, layout = _scenario(papacy_used=False)
    field = _read(reader, binding)[memory.FIELD_ID]
    value = _known(field)
    absent = {"status": "not_applicable", "reason": "PAPACY_NOT_USED"}
    assert value == {
        "uses_papacy": False, "papal_influence": absent,
        "curia_treasury": absent, "controller": absent,
    }
    forbidden = {layout["influence_cell"], layout["record_state_cell"],
                 layout["controller_cell"], layout["treasury_cell"]}
    assert not any(address in forbidden for address, _, _, _ in reader.calls)


@pytest.mark.parametrize("controller_reference", [
    0,
    (0xA5 << 56) | (11 << 32) | int.from_bytes(b"E!G", "little"),
    (0xA4 << 56) | (10 << 32) | int.from_bytes(b"FRA", "little"),
    (0xA4 << 56) | (11 << 32) | int.from_bytes(b"ENG", "little"),
])
def test_invalid_dangling_or_generation_mismatch_controller_is_unknown(controller_reference):
    reader, binding, _ = _scenario(controller_reference=controller_reference)
    _controller_unknown(_read(reader, binding)[memory.FIELD_ID])


@pytest.mark.parametrize("defect", ["missing_slot", "wrong_table_pointer", "wrong_country_fullref"])
def test_controller_database_failures_only_make_controller_unknown(defect):
    reader, binding, layout = _scenario(controller_tag="ENG")
    if defect == "missing_slot":
        reader.cells[DATABASE + 0x124] = _i32(11)
    elif defect == "wrong_table_pointer":
        reader.cells[TABLE + 11 * 8] = _qword(OTHER)
    else:
        reader.cells[defender_fake.HOLDER_COUNTRY + COUNTRY_FULLREF_OFFSET] = _qword(
            _fullref("ENG", 11, 0xA4))
    field = _read(reader, binding)[memory.FIELD_ID]
    _controller_unknown(field)


@pytest.mark.parametrize(("owner_id", "expected_known"), [
    (-1, False), (0, False), (4097, False), (4096, True),
])
def test_owner_state_id_bounds_and_maximum(owner_id, expected_known):
    reader, binding, _ = _scenario(owner_id=owner_id)
    field = _read(reader, binding)[memory.FIELD_ID]
    assert (field["status"] == "known") is expected_known
    if expected_known:
        assert _known(field)["uses_papacy"] is True


@pytest.mark.parametrize("defect", [
    "null_owner", "owner_vtable", "definition_used_as_owner", "record_owner",
    "null_state", "religion_vtable", "null_religion", "invalid_definition_pointer",
])
def test_owner_definition_record_and_pointer_identity_are_required(defect):
    kwargs = {}
    if defect == "null_owner":
        kwargs["owner_pointer"] = 0
    elif defect == "owner_vtable":
        kwargs["owner_vtable"] = BASE + memory.RELIGION_VTABLE_RVA + 8
    elif defect == "definition_used_as_owner":
        kwargs["owner_pointer"] = DEFINITION
        kwargs["owner_vtable"] = BASE + memory.RELIGION_VTABLE_RVA + 8
    elif defect == "record_owner":
        kwargs["record_owner"] = OTHER
    elif defect == "null_state":
        kwargs["record_state_pointer"] = 0
    elif defect == "religion_vtable":
        kwargs["religion_vtable"] = BASE + memory.RELIGION_VTABLE_RVA + 8
    elif defect == "null_religion":
        pass
    elif defect == "invalid_definition_pointer":
        kwargs["definition_pointer"] = 0x7FFFFFFFFFF8
    reader, binding, _ = _scenario(**kwargs)
    if defect == "null_religion":
        reader.cells[TARGET + COUNTRY_RELIGION_OFFSET] = _qword(0)
    field = _read(reader, binding)[memory.FIELD_ID]
    assert field["status"] == "unknown"
    assert "value" not in field


@pytest.mark.parametrize("dependency", [
    "country_religion", "definition", "owner_id", "record_owner", "state_pointer",
    "influence", "treasury", "controller",
])
def test_dependency_change_on_final_reread_retracts_field(dependency):
    reader, binding, layout = _scenario()
    address = {
        "country_religion": TARGET + COUNTRY_RELIGION_OFFSET,
        "definition": layout["definition_cell"],
        "owner_id": layout["owner_id_cell"],
        "record_owner": layout["record_owner_cell"],
        "state_pointer": layout["record_state_cell"],
        "influence": layout["influence_cell"],
        "treasury": layout["treasury_cell"],
        "controller": layout["controller_cell"],
    }[dependency]
    current = reader.cells[address]
    if dependency in ("country_religion", "definition", "record_owner", "state_pointer", "controller"):
        replacement = _qword(OTHER)
    else:
        replacement = _i32(int.from_bytes(current, "little", signed=True) + 1)
    reader.replacements[(address, 2)] = replacement
    field = _read(reader, binding)[memory.FIELD_ID]
    assert field["status"] == "unknown"
    assert "value" not in field


def test_short_read_is_unknown_without_partial_value():
    reader, binding, layout = _scenario()
    reader.replacements[(layout["influence_cell"], 1)] = b"\x01"
    field = _read(reader, binding)[memory.FIELD_ID]
    assert field["status"] == "unknown"
    assert "value" not in field


@pytest.mark.parametrize(("name", "message"), [
    ("MAX_READ_CALLS", "read_call_budget_exceeded"),
    ("MAX_READ_BYTES", "read_budget_exceeded"),
])
def test_leaf_read_budget_exhaustion_propagates(monkeypatch, name, message):
    reader, binding, _ = _scenario()
    monkeypatch.setattr(memory, name, 0)
    with pytest.raises(ValueError, match=message):
        _read(reader, binding)


def test_outer_reader_budget_exhaustion_propagates():
    reader, binding, layout = _scenario()
    reader.exceptions[(layout["selected_slot_cell"], 1)] = RuntimeError("read_budget_exceeded")
    with pytest.raises(RuntimeError, match="read_budget_exceeded"):
        _read(reader, binding)


def test_only_requested_field_is_read_and_unsupported_fields_stay_unknown():
    reader, binding, _ = _scenario()
    result = _read(reader, binding, fields=("S02.other",))
    assert result["S02.other"]["status"] == "unknown"
    assert reader.calls == []
