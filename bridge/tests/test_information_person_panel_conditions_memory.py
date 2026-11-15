from __future__ import annotations

import pytest

from bridge.information.person_panel_conditions_memory import (
    COUNTRY_FULLREF_OFFSET,
    COUNTRY_PANEL_ATTRIBUTES_POINTER_OFFSET,
    HEIR_PANEL_SLOT_OFFSET,
    HEIR_SPECIAL_NAME_SLOT_OFFSET,
    HEIR_TLS_GATE_FIRST_RVA,
    HEIR_TLS_GATE_SECOND_RVA,
    MONARCHISTS_SLOT_OFFSET,
    PANEL_ATTRIBUTES_BASE_OFFSET,
    PROPERTY_VALUE_OFFSET,
    read_person_panel_conditions,
)


_SLOTS = {
    "heir_panel": HEIR_PANEL_SLOT_OFFSET,
    "heir_special_name": HEIR_SPECIAL_NAME_SLOT_OFFSET,
    "monarchists": MONARCHISTS_SLOT_OFFSET,
}


def _u64(value: int) -> bytes:
    return value.to_bytes(8, "little", signed=False)


def _i32(value: int) -> bytes:
    return value.to_bytes(4, "little", signed=True)


def _fullref(tag: str = "POR", slot: int = 189) -> int:
    return (0xA5 << 56) | (slot << 32) | int.from_bytes(tag.encode("ascii"), "little")


class FakeLimiter:
    def __init__(self) -> None:
        self.memory: dict[int, int] = {}
        self.fail_labels: set[str] = set()
        self.short_labels: set[str] = set()
        self.calls: list[tuple[int, int, str]] = []

    def put(self, address: int, raw: bytes) -> None:
        for offset, value in enumerate(raw):
            self.memory[address + offset] = value

    def read(self, address: int, size: int, label: str) -> bytes:
        self.calls.append((address, size, label))
        if label in self.fail_labels:
            raise OSError("fixture read failure")
        raw = bytes(self.memory[address + offset]
                    for offset in range(size)
                    if address + offset in self.memory)
        if len(raw) != size:
            raise OSError("fixture address is unmapped")
        if label in self.short_labels:
            return raw[:-1]
        return raw


def _fixture(*, attributes_pointer: int | None = 0x300000,
             field_specs: dict[str, dict[str, int | None]] | None = None,
             first_gate: int = 1, second_gate: int = 0,
             memory_fullref: int | None = None) -> tuple[
                 FakeLimiter, int, dict[str, object], dict[str, int]]:
    reader = FakeLimiter()
    base = 0x140000000
    country = 0x200000
    attributes_owner = attributes_pointer
    attributes_base = (attributes_owner + PANEL_ATTRIBUTES_BASE_OFFSET
                       if attributes_owner is not None else None)
    expected_ref = _fullref()
    reader.put(country + COUNTRY_FULLREF_OFFSET,
               _u64(expected_ref if memory_fullref is None else memory_fullref))
    reader.put(country + COUNTRY_PANEL_ATTRIBUTES_POINTER_OFFSET,
               _u64(attributes_owner or 0))

    properties = {
        name: 0x400000 + index * 0x1000
        for index, name in enumerate(_SLOTS)
    }
    if field_specs is None:
        field_specs = {
            name: {"pointer": properties[name], "token": 0, "value": 0}
            for name in _SLOTS
        }
    if attributes_base is not None:
        for name, offset in _SLOTS.items():
            spec = field_specs[name]
            pointer = spec.get("pointer")
            reader.put(attributes_base + offset, _u64(pointer or 0))
            if pointer:
                token = spec.get("token", 0)
                value = spec.get("value", 0)
                assert token is not None and value is not None
                reader.put(pointer, _i32(token))
                reader.put(pointer + PROPERTY_VALUE_OFFSET, bytes([value & 0xFF]))
    reader.put(base + HEIR_TLS_GATE_FIRST_RVA, bytes([first_gate & 0xFF]))
    reader.put(base + HEIR_TLS_GATE_SECOND_RVA, bytes([second_gate & 0xFF]))
    binding: dict[str, object] = {
        "tag": "POR",
        "slot": 189,
        "fullref": hex(expected_ref),
        "country_pointer": hex(country),
        "fullref_raw_hex": expected_ref.to_bytes(8, "little").hex(),
    }
    return reader, base, binding, {
        "country": country,
        "attributes_owner": attributes_owner or 0,
        "attributes_base": attributes_base or 0,
        **properties,
    }


@pytest.mark.parametrize("field_name", sorted(_SLOTS))
def test_panel_bool_property_uses_one_value_byte_and_accepts_any_nonzero(field_name: str) -> None:
    reader, base, binding, addresses = _fixture(
        field_specs={
            name: {
                "pointer": addresses_pointer,
                "token": 0,
                "value": 0x80 if name == field_name else 0,
            }
            for name, addresses_pointer in {
                name: 0x400000 + index * 0x1000
                for index, name in enumerate(_SLOTS)
            }.items()
        },
    )

    result = read_person_panel_conditions(reader, base, binding)

    assert result[field_name] == {
        "status": "known",
        "value": True,
        "reason": (
            "bool_property_true_tls_bypass_gate"
            if field_name == "heir_special_name"
            else "projected_true_selects_heir_character_name_info_branch"
            if field_name == "heir_panel"
            else "bool_property_nonzero_byte"
        ),
    }
    assert result["raw_inputs"]["field_inputs"][field_name]["property_value_raw_hex"] == "80"
    assert "PROPERTY_VALUES_ARE_MEMORY_PROJECTIONS_NOT_NATIVE_CALL_RESULTS" in result["gaps"]


def test_null_property_slots_are_known_false_without_tls_or_global_fallback() -> None:
    field_specs = {
        name: {"pointer": None, "token": None, "value": None}
        for name in _SLOTS
    }
    reader, base, binding, _ = _fixture(field_specs=field_specs, first_gate=0, second_gate=1)

    result = read_person_panel_conditions(reader, base, binding)

    for field_name in _SLOTS:
        assert result[field_name]["status"] == "known"
        assert result[field_name]["value"] is False
    assert result["heir_panel"]["reason"] == (
        "projected_false_hides_monarch_heir_name_election_info_not_no_heir")
    assert result["raw_inputs"]["field_inputs"]["heir_panel"][
        "property_condition_reason"] == "null_property_default_false"
    assert result["heir_special_name"]["reason"].endswith("tls_gate_not_needed_for_false")
    assert not any("tls_gate_" in label for _, _, label in reader.calls)


def test_false_heir_panel_projects_hidden_info_branch_not_absent_heir() -> None:
    field_specs = {
        name: {"pointer": 0x400000 + index * 0x1000, "token": 0, "value": 0}
        for index, name in enumerate(_SLOTS)
    }
    reader, base, binding, _ = _fixture(field_specs=field_specs)

    result = read_person_panel_conditions(reader, base, binding)

    assert result["heir_panel"]["status"] == "known"
    assert result["heir_panel"]["value"] is False
    assert result["heir_panel"]["reason"] == (
        "projected_false_hides_monarch_heir_name_election_info_not_no_heir")
    inputs = result["raw_inputs"]["field_inputs"]["heir_panel"]
    assert inputs["property_condition_reason"] == "bool_property_zero_byte"
    assert inputs["property_value_raw_hex"] == "00"
    assert "HEIR_PANEL_FALSE_DOES_NOT_PROVE_THERE_IS_NO_HEIR" in result["gaps"]


@pytest.mark.parametrize(
    ("token", "expected_status", "expected_value", "normalized"),
    [
        (-1, "known", True, 0),
        (-2, "known", False, 1),
        (-10, "known", False, 9),
        (-11, "unknown", None, 10),
    ],
)
def test_signed_token_normalization_is_explicit(
    token: int, expected_status: str, expected_value: bool | None, normalized: int,
) -> None:
    field_specs = {
        name: {"pointer": 0x400000 + index * 0x1000, "token": 0, "value": 0}
        for index, name in enumerate(_SLOTS)
    }
    field_specs["heir_panel"] = {
        "pointer": 0x400000, "token": token, "value": 1,
    }
    reader, base, binding, _ = _fixture(field_specs=field_specs)

    result = read_person_panel_conditions(reader, base, binding)
    field_result = result["heir_panel"]
    assert field_result["status"] == expected_status
    if expected_status == "known":
        assert field_result["value"] is expected_value
    else:
        assert "value" not in field_result
    assert result["raw_inputs"]["field_inputs"]["heir_panel"][
        "property_token_normalized"] == normalized


@pytest.mark.parametrize("token", [1, 5, 9])
def test_non_boolean_property_tokens_project_false_without_reading_value(token: int) -> None:
    field_specs = {
        name: {"pointer": 0x400000 + index * 0x1000, "token": 0, "value": 1}
        for index, name in enumerate(_SLOTS)
    }
    field_specs["monarchists"] = {
        "pointer": 0x402000, "token": token, "value": 1,
    }
    reader, base, binding, _ = _fixture(field_specs=field_specs)

    result = read_person_panel_conditions(reader, base, binding)

    assert result["monarchists"] == {
        "status": "known",
        "value": False,
        "reason": "non_bool_property_type_projects_false",
    }
    assert "property_value_raw_hex" not in result["raw_inputs"]["field_inputs"]["monarchists"]
    assert result["raw_inputs"]["field_inputs"]["monarchists"][
        "property_type_outcome"] == "token_1_to_9_non_bool"


def test_token_ten_is_unknown_without_hiding_other_fields() -> None:
    field_specs = {
        name: {"pointer": 0x400000 + index * 0x1000, "token": 0, "value": 1}
        for index, name in enumerate(_SLOTS)
    }
    field_specs["heir_panel"] = {
        "pointer": 0x400000, "token": 10, "value": 1,
    }
    reader, base, binding, _ = _fixture(field_specs=field_specs)

    result = read_person_panel_conditions(reader, base, binding)

    assert result["heir_panel"] == {
        "status": "unknown",
        "reason": "property_type_token_unresolved_or_throwing",
    }
    assert result["heir_special_name"]["status"] == "known"
    assert result["monarchists"]["value"] is True


@pytest.mark.parametrize(("first_gate", "second_gate"), [(0, 0), (1, 1), (0, 1)])
def test_true_heir_property_requires_exact_fastpath_gate(
    first_gate: int, second_gate: int,
) -> None:
    field_specs = {
        name: {"pointer": 0x400000 + index * 0x1000, "token": 0, "value": 0}
        for index, name in enumerate(_SLOTS)
    }
    field_specs["heir_special_name"] = {
        "pointer": 0x401000, "token": 0, "value": 1,
    }
    reader, base, binding, _ = _fixture(
        field_specs=field_specs, first_gate=first_gate, second_gate=second_gate)

    result = read_person_panel_conditions(reader, base, binding)

    assert result["heir_special_name"] == {
        "status": "unknown",
        "reason": "tls_required_not_observed",
    }
    assert result["heir_panel"]["status"] == "known"
    assert result["monarchists"]["status"] == "known"


def test_missing_attributes_pointer_unknowns_all_fields_without_global_fallback() -> None:
    reader, base, binding, _ = _fixture(attributes_pointer=None)

    result = read_person_panel_conditions(reader, base, binding)

    for field_name in _SLOTS:
        assert result[field_name] == {
            "status": "unknown",
            "reason": "country_attributes_pointer_null_global_fallback_not_implemented",
        }
    assert result["raw_inputs"]["country_attributes_pointer_raw_hex"] == "0000000000000000"


def test_bad_binding_or_memory_ref_mismatch_rejects_all_fields() -> None:
    reader, base, binding, addresses = _fixture()
    bad_binding = dict(binding)
    bad_binding["slot"] = 188

    invalid = read_person_panel_conditions(reader, base, bad_binding)
    assert invalid["heir_panel"]["reason"] == "target_binding_fullref_slot_mismatch"
    assert invalid["raw_inputs"]["read_calls"] == 0

    reader.put(addresses["country"] + COUNTRY_FULLREF_OFFSET, _u64(_fullref(slot=188)))
    mismatch = read_person_panel_conditions(reader, base, binding)
    assert mismatch["heir_special_name"]["reason"] == "target_binding_fullref_memory_mismatch"
    assert "value" not in mismatch["monarchists"]


def test_one_field_read_failure_does_not_erase_sibling_results() -> None:
    reader, base, binding, _ = _fixture()
    reader.fail_labels.add("person_panel.heir_panel.property_token")

    result = read_person_panel_conditions(reader, base, binding)

    assert result["heir_panel"]["status"] == "unknown"
    assert result["heir_panel"]["reason"].startswith(
        "read_failed:person_panel.heir_panel.property_token")
    assert result["heir_special_name"]["status"] == "known"
    assert result["monarchists"]["status"] == "known"
    assert result["raw_inputs"]["reads"][-1]["status"] == "ok"
    assert any(row["status"] == "failed" and row["label"]
               == "person_panel.heir_panel.property_token"
               for row in result["raw_inputs"]["reads"])


def test_unaligned_property_pointer_only_makes_its_field_unknown() -> None:
    field_specs = {
        name: {"pointer": 0x400000 + index * 0x1000, "token": 0, "value": 1}
        for index, name in enumerate(_SLOTS)
    }
    field_specs["heir_panel"] = {
        "pointer": 0x400001, "token": 0, "value": 1,
    }
    reader, base, binding, _ = _fixture(field_specs=field_specs)

    result = read_person_panel_conditions(reader, base, binding)

    assert result["heir_panel"] == {
        "status": "unknown",
        "reason": "heir_panel_property_pointer_unaligned",
    }
    assert result["heir_special_name"]["value"] is True
    assert result["monarchists"]["value"] is True


def test_heir_global_gate_read_failure_is_unknown_and_keeps_other_fields() -> None:
    field_specs = {
        name: {"pointer": 0x400000 + index * 0x1000, "token": 0, "value": 0}
        for index, name in enumerate(_SLOTS)
    }
    field_specs["heir_special_name"] = {
        "pointer": 0x401000, "token": 0, "value": 1,
    }
    reader, base, binding, _ = _fixture(field_specs=field_specs)
    reader.fail_labels.add("person_panel.heir_special_name.tls_gate_second")

    result = read_person_panel_conditions(reader, base, binding)

    assert result["heir_special_name"]["status"] == "unknown"
    assert result["heir_special_name"]["reason"].startswith(
        "read_failed:person_panel.heir_special_name.tls_gate_second")
    assert result["heir_panel"]["status"] == "known"
    assert result["monarchists"]["status"] == "known"

