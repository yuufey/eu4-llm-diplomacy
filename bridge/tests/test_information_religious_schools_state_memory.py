from __future__ import annotations

import pytest

from bridge.information import religious_schools_state_memory as memory
from bridge.information import religious_schools_state_values as state_values
from bridge.tests.test_information_religious_schools_memory import (
    BASE, DEFINITION, GROUP, FakeMemory, _qword,
)


FIELD_ID = memory.FIELD_ID
ACTIVATION_DEF = 0xA00000
FALSE_VTABLE = BASE + 0x1C48550
REAL_VTABLE = BASE + 0x1D216F8
OTHER_VTABLE = BASE + 0x1D216F0
FALSE_METHOD = BASE + 0x8F450
REAL_METHOD = BASE + 0xDACBC0


class StateMemory(FakeMemory):
    """Reuse the real parent school/identity fixture and add native gate bytes."""

    def __init__(self, *, has_school=True, definition_pointer=None,
                 activation_type="real", flags=(1, 0), activation_count=None,
                 overrides=None):
        super().__init__(has_school=has_school, overrides=overrides)
        if definition_pointer is None:
            definition_pointer = DEFINITION if has_school else ACTIVATION_DEF
        self.regions[GROUP + 0xA0] = _qword(definition_pointer)
        self.regions[BASE + memory.FLAG1_RVA] = bytes([flags[0]])
        self.regions[BASE + memory.FLAG2_RVA] = bytes([flags[1]])

        if activation_type == "real":
            vtable, method = REAL_VTABLE, REAL_METHOD
        elif activation_type == "false":
            vtable, method = FALSE_VTABLE, FALSE_METHOD
        else:
            vtable, method = OTHER_VTABLE, REAL_METHOD

        self.regions[definition_pointer] = _qword(vtable)
        self.regions[vtable + 0x40] = _qword(method)
        self.regions[definition_pointer + 0x10] = _qword(GROUP)
        if activation_count is not None:
            self.regions[definition_pointer + 0x2C] = int(activation_count).to_bytes(
                4, "little", signed=True)


def _qword_for_test(value: int) -> bytes:
    return value.to_bytes(8, "little")


def _read(reader: StateMemory, fields=(FIELD_ID,)):
    return memory.read_fields(reader, BASE, reader.binding, fields)


def _known(field: dict) -> dict:
    assert field["status"] == "known"
    assert field["complete"] is False
    return field["value"]


def _unknown(field: dict, reason: str) -> None:
    assert field["status"] == "unknown"
    assert field["complete"] is False
    assert "value" not in field
    assert reason in field["reason"]


def _activation_read_labels(reader: StateMemory) -> list[str]:
    return [label for _, _, label in reader.calls if label.startswith("school_state.activation.")]


def test_default_definition_fallback_proves_false_without_reading_gate_or_count():
    reader = StateMemory(
        has_school=False, definition_pointer=0, activation_type="false")
    default_definition = ACTIVATION_DEF
    reader.regions[BASE + memory.DEFAULT_DEFINITION_RVA] = _qword(default_definition)
    reader.regions[default_definition] = _qword(FALSE_VTABLE)
    reader.regions[FALSE_VTABLE + 0x40] = _qword(FALSE_METHOD)

    value = _known(_read(reader)[FIELD_ID])

    assert value["has_school"] is False
    assert value["current_school"] == {"status": "none", "reason": "NATIVE_SCHOOL_SENTINEL"}
    assert value["uses_schools"] == {"status": "known", "value": False}
    labels = _activation_read_labels(reader)
    assert "school_state.activation.fallback_definition" in labels
    assert "school_state.activation.count" not in labels
    assert "school_state.activation.flag1" not in labels
    assert "school_state.activation.flag2" not in labels


def test_real_activation_gate_and_signed_nonzero_count_prove_true():
    reader = StateMemory(has_school=True, activation_type="real", flags=(1, 0))

    value = _known(_read(reader)[FIELD_ID])

    assert value["has_school"] is True
    assert value["current_school"] == {"status": "known", "key": "shafi"}
    assert value["uses_schools"] == {"status": "known", "value": True}
    assert "school_state.activation.count" in _activation_read_labels(reader)


@pytest.mark.parametrize("flags", [(0, 0), (1, 1)])
def test_unresolved_thread_gate_does_not_read_count_and_preserves_parent_school(flags):
    reader = StateMemory(has_school=True, activation_type="real", flags=flags)

    value = _known(_read(reader)[FIELD_ID])

    assert value["current_school"] == {"status": "known", "key": "shafi"}
    assert value["uses_schools"] == {
        "status": "unknown", "reason": "RELIGIOUS_SCHOOLS_THREAD_GATE_UNRESOLVED"}
    assert "school_state.activation.count" not in _activation_read_labels(reader)


def test_real_activation_with_zero_count_proves_false_for_native_no_school():
    reader = StateMemory(
        has_school=False, definition_pointer=ACTIVATION_DEF,
        activation_type="real", flags=(1, 0), activation_count=0)

    value = _known(_read(reader)[FIELD_ID])

    assert value["has_school"] is False
    assert value["uses_schools"] == {"status": "known", "value": False}


@pytest.mark.parametrize(
    ("activation_type", "overrides"),
    [
        ("unsupported", None),
        ("real", {"school_state.activation.flag1": [OSError("unreadable flag")]}),
    ],
)
def test_unrecognized_or_unreadable_activation_keeps_school_identity(
        activation_type, overrides):
    reader = StateMemory(
        has_school=True, activation_type=activation_type, overrides=overrides)

    value = _known(_read(reader)[FIELD_ID])

    assert value["has_school"] is True
    assert value["current_school"] == {"status": "known", "key": "shafi"}
    assert value["uses_schools"] == {
        "status": "unknown", "reason": "RELIGIOUS_SCHOOLS_ACTIVATION_UNAVAILABLE"}


def test_negative_signed_count_makes_activation_unknown_without_losing_school():
    reader = StateMemory(
        has_school=False, definition_pointer=ACTIVATION_DEF,
        activation_type="real", flags=(1, 0), activation_count=-1)

    value = _known(_read(reader)[FIELD_ID])

    assert value["has_school"] is False
    assert value["uses_schools"] == {
        "status": "unknown", "reason": "RELIGIOUS_SCHOOLS_ACTIVATION_UNAVAILABLE"}


def test_activation_dependency_drift_only_revokes_activation_child():
    reader = StateMemory(
        has_school=True,
        overrides={"school_state.activation.flag1_after": [b"\x00"]})

    value = _known(_read(reader)[FIELD_ID])

    assert value["current_school"] == {"status": "known", "key": "shafi"}
    assert value["uses_schools"] == {
        "status": "unknown", "reason": "RELIGIOUS_SCHOOLS_ACTIVATION_CHANGED"}


def test_parent_dependency_drift_revokes_the_entire_field():
    label = (
        "school_state.religious_schools.religion_identity."
        "primary_religion_pointer_before_state_after")
    reader = StateMemory(overrides={label: [_qword_for_test(0x300008)]})

    field = _read(reader)[FIELD_ID]

    _unknown(field, "school_state_parent_changed")


@pytest.mark.parametrize("budget_owner", ["state", "parent"])
def test_local_and_parent_budget_errors_propagate(monkeypatch, budget_owner):
    reader = StateMemory()
    if budget_owner == "state":
        monkeypatch.setattr(memory, "MAX_READ_BYTES", 0)
    else:
        monkeypatch.setattr(memory.parent, "MAX_READ_BYTES", 0)

    with pytest.raises(ValueError, match="budget_exceeded"):
        _read(reader)


def test_field_request_shape_and_unsupported_id_match_parent_contract():
    reader = StateMemory()

    assert _read(reader, [FIELD_ID])[FIELD_ID]["reason"] == "fields_shape_invalid"
    assert _read(reader, ("other",))["other"]["reason"] == "unsupported_field"
    assert _read(reader, (FIELD_ID, FIELD_ID))[FIELD_ID]["reason"] == "duplicate_field_requested"

