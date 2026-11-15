from __future__ import annotations

import hashlib
import re

import pytest

from bridge.information import religion_binding
from bridge.information.model import canonical


MODULE_BASE = 0x140000000
COUNTRY_POINTER = 0x200000
RELIGION_POINTER = 0x300000
GROUP_POINTER = 0x320000
TAG = "POR"
SLOT = 47
FULLREF = (1 << 56) | (SLOT << 32) | int.from_bytes(TAG.encode("ascii"), "little")


def _binding(*, tag=TAG, slot=SLOT, country_pointer=COUNTRY_POINTER,
             fullref=FULLREF):
    return {
        "tag": tag,
        "slot": slot,
        "country_pointer": hex(country_pointer),
        "fullref": hex(fullref),
        "fullref_raw_hex": fullref.to_bytes(8, "little").hex(),
        "country_fullref_address": hex(country_pointer + 0x20),
        "table_entry_address": hex(0x100000),
        "table_entry_raw_hex": country_pointer.to_bytes(8, "little").hex(),
    }


def _field(raw_inputs, *, status="known"):
    return {
        "status": status,
        "complete": False,
        "value": {"sample": "validated by caller"},
        "raw_inputs": raw_inputs,
    }


def _faith_shape(**overrides):
    raw = {
        "country_binding": _binding(),
        "country_pointer": hex(COUNTRY_POINTER),
        "module_base": hex(MODULE_BASE),
        "primary_religion_pointer": hex(RELIGION_POINTER),
        "primary_religion_pointer_raw_hex": RELIGION_POINTER.to_bytes(8, "little").hex(),
    }
    raw.update(overrides)
    return raw


def _group_shape(**overrides):
    raw = {
        "country_binding": _binding(),
        "country_pointer": hex(COUNTRY_POINTER),
        "module_base": hex(MODULE_BASE),
        "primary_religion_pointer": hex(RELIGION_POINTER),
        "primary_religion_pointer_before_raw_hex": RELIGION_POINTER.to_bytes(8, "little").hex(),
        "primary_religion_pointer_after_raw_hex": RELIGION_POINTER.to_bytes(8, "little").hex(),
        "religion_group_pointer": hex(GROUP_POINTER),
        "religion_group_pointer_before_raw_hex": GROUP_POINTER.to_bytes(8, "little").hex(),
        "religion_group_pointer_after_raw_hex": GROUP_POINTER.to_bytes(8, "little").hex(),
    }
    raw.update(overrides)
    return raw


def _identity_shape(**overrides):
    raw = _group_shape(**overrides)
    raw.update({
        "religion_key_String32_header_before_raw_hex": "catholic",
        "religion_group_key_String32_header_before_raw_hex": "christian",
        "primary_religion_name_raw_hex": "irrelevant-display-text",
    })
    return raw


@pytest.mark.parametrize("raw_shape", [_faith_shape, _group_shape, _identity_shape],
                         ids=["country-faith", "religion-group", "religion-identity"])
def test_three_real_leaf_raw_shapes_produce_the_same_no_pointer_digests(raw_shape):
    result = religion_binding.binding_digests(_field(raw_shape()), TAG)

    expected_keys = {"religion_binding_sha256"}
    if raw_shape is not _faith_shape:
        expected_keys.add("religion_group_binding_sha256")
    assert set(result) == expected_keys
    assert all(re.fullmatch(r"[0-9a-f]{64}", value) for value in result.values())
    assert set(result.values()).isdisjoint({hex(COUNTRY_POINTER), hex(RELIGION_POINTER),
                                            hex(GROUP_POINTER), hex(MODULE_BASE)})
    expected_religion = hashlib.sha256(canonical({
        "schema": "information.religion_binding.v1",
        "country": TAG,
        "module_base": hex(MODULE_BASE),
        "country_pointer": hex(COUNTRY_POINTER),
        "country_fullref": hex(FULLREF),
        "primary_religion_pointer": hex(RELIGION_POINTER),
    }).encode("utf-8")).hexdigest()
    expected_group = hashlib.sha256(canonical({
        "schema": "information.religion_group_binding.v1",
        "country": TAG,
        "module_base": hex(MODULE_BASE),
        "country_pointer": hex(COUNTRY_POINTER),
        "country_fullref": hex(FULLREF),
        "primary_religion_pointer": hex(RELIGION_POINTER),
        "religion_group_pointer": hex(GROUP_POINTER),
    }).encode("utf-8")).hexdigest()
    expected_result = {"religion_binding_sha256": expected_religion}
    if "religion_group_binding_sha256" in expected_keys:
        expected_result["religion_group_binding_sha256"] = expected_group
    assert result == expected_result


def test_older_leaf_without_pointer_raw_hex_remains_joinable():
    raw = _faith_shape()
    raw.pop("primary_religion_pointer_raw_hex")

    result = religion_binding.binding_digests(_field(raw), TAG)

    assert set(result) == {"religion_binding_sha256"}


def test_require_group_rejects_missing_group_and_optional_group_adds_digest_when_present():
    faith = _field(_faith_shape())

    without_group = religion_binding.binding_digests(faith, TAG)
    assert set(without_group) == {"religion_binding_sha256"}
    with pytest.raises(ValueError, match="religion_group_pointer_missing"):
        religion_binding.binding_digests(faith, TAG, require_group=True)

    with_group = religion_binding.binding_digests(_field(_group_shape()), TAG,
                                                   require_group=True)
    assert set(with_group) == {"religion_binding_sha256", "religion_group_binding_sha256"}


def test_religion_pointer_change_changes_religion_and_group_binding_digests():
    first = religion_binding.binding_digests(_field(_group_shape()), TAG)
    changed_pointer = RELIGION_POINTER + 0x1000
    changed = _group_shape(
        primary_religion_pointer=hex(changed_pointer),
        primary_religion_pointer_before_raw_hex=changed_pointer.to_bytes(8, "little").hex(),
        primary_religion_pointer_after_raw_hex=changed_pointer.to_bytes(8, "little").hex(),
    )

    second = religion_binding.binding_digests(_field(changed), TAG)

    assert second["religion_binding_sha256"] != first["religion_binding_sha256"]
    assert second["religion_group_binding_sha256"] != first["religion_group_binding_sha256"]


def test_country_fullref_generation_change_is_preserved_in_both_digests():
    first = religion_binding.binding_digests(_field(_group_shape()), TAG)
    changed_fullref = FULLREF ^ (1 << 48)
    changed_binding = _binding(fullref=changed_fullref)
    second = religion_binding.binding_digests(
        _field(_group_shape(country_binding=changed_binding)), TAG)

    assert second["religion_binding_sha256"] != first["religion_binding_sha256"]
    assert second["religion_group_binding_sha256"] != first["religion_group_binding_sha256"]


def test_country_pointer_change_is_preserved_when_binding_and_raw_pointer_agree():
    changed_pointer = COUNTRY_POINTER + 0x1000
    raw = _group_shape(
        country_binding=_binding(country_pointer=changed_pointer),
        country_pointer=hex(changed_pointer),
    )

    changed = religion_binding.binding_digests(_field(raw), TAG)
    original = religion_binding.binding_digests(_field(_group_shape()), TAG)

    assert changed["religion_binding_sha256"] != original["religion_binding_sha256"]
    assert changed["religion_group_binding_sha256"] != original["religion_group_binding_sha256"]


def test_group_pointer_change_preserves_religion_digest_and_changes_group_digest():
    first = religion_binding.binding_digests(_field(_group_shape()), TAG)
    changed_pointer = GROUP_POINTER + 0x1000
    changed = _group_shape(
        religion_group_pointer=hex(changed_pointer),
        religion_group_pointer_before_raw_hex=changed_pointer.to_bytes(8, "little").hex(),
        religion_group_pointer_after_raw_hex=changed_pointer.to_bytes(8, "little").hex(),
    )

    second = religion_binding.binding_digests(_field(changed), TAG)

    assert second["religion_binding_sha256"] == first["religion_binding_sha256"]
    assert second["religion_group_binding_sha256"] != first["religion_group_binding_sha256"]


@pytest.mark.parametrize("field,country,require_group", [
    ({"status": "unknown", "raw_inputs": {}}, TAG, False),
    (_field(None), TAG, False),
    (_field(_faith_shape()), "ENG", False),
    (_field(_faith_shape()), TAG, 1),
])
def test_invalid_field_country_or_require_group_arguments_raise(field, country, require_group):
    with pytest.raises(ValueError):
        religion_binding.binding_digests(field, country, require_group=require_group)


@pytest.mark.parametrize("raw,reason", [
    (_faith_shape(country_pointer=hex(COUNTRY_POINTER + 8)), "country_pointer_binding_mismatch"),
    (_faith_shape(primary_religion_pointer=hex(0)), "primary_religion_pointer"),
    (_faith_shape(primary_religion_pointer=True), "primary_religion_pointer"),
    (_faith_shape(module_base=True), "module_base"),
    (_faith_shape(country_binding=_binding(tag="ENG")), "country_binding_invalid"),
    (_faith_shape(country_binding=_binding(slot=SLOT + 1)), "country_binding_invalid"),
    (_faith_shape(country_binding={**_binding(), "fullref_raw_hex": "00" * 8}),
     "country_binding_invalid"),
    (_faith_shape(primary_religion_pointer_raw_hex="00" * 8),
     "primary_religion_pointer_raw_mismatch"),
    (_faith_shape(primary_religion_pointer_raw_hex="abc"),
     "primary_religion_pointer_raw_hex_invalid"),
])
def test_bad_tags_slots_pointers_booleans_or_supplied_raw_bytes_are_rejected(raw, reason):
    with pytest.raises(ValueError, match=reason):
        religion_binding.binding_digests(_field(raw), TAG)


def test_supplied_group_pointer_raw_bytes_are_checked_even_when_group_is_optional():
    raw = _group_shape(
        religion_group_pointer_after_raw_hex=(GROUP_POINTER + 8).to_bytes(8, "little").hex())

    with pytest.raises(ValueError, match="religion_group_pointer_raw_mismatch"):
        religion_binding.binding_digests(_field(raw), TAG)


def test_group_pointer_can_be_recovered_from_consistent_raw_copies_when_direct_value_is_absent():
    raw = _group_shape()
    raw.pop("religion_group_pointer")

    result = religion_binding.binding_digests(_field(raw), TAG, require_group=True)

    assert set(result) == {"religion_binding_sha256", "religion_group_binding_sha256"}


def test_group_raw_copies_must_agree_when_direct_pointer_is_absent():
    raw = _group_shape()
    raw.pop("religion_group_pointer")
    raw["religion_group_pointer_after_raw_hex"] = (GROUP_POINTER + 8).to_bytes(8, "little").hex()

    with pytest.raises(ValueError, match="religion_group_pointer_raw_mismatch"):
        religion_binding.binding_digests(_field(raw), TAG)
