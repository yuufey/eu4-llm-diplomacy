from __future__ import annotations

import pytest

from bridge.information import country_scale_flag_memory as memory


MODULE_BASE = 0x140000000
COUNTRY = 0x200000
TAG = "FRA"
SLOT = 122
COUNTRY_REGION_SIZE = 0x3000


def _fullref(tag: str = TAG, slot: int = SLOT, *, byte48: int = 0,
             high_byte: int = 1) -> int:
    return ((high_byte & 0xFF) << 56) | ((byte48 & 0xFF) << 48) | (slot << 32) | int.from_bytes(tag.encode("ascii"), "little")


def _binding(*, tag: str = TAG, slot: int = SLOT,
             pointer: int = COUNTRY, fullref: int | None = None,
             raw_hex: str | None = None) -> dict:
    if fullref is None:
        fullref = _fullref(tag, slot)
    if raw_hex is None:
        raw_hex = fullref.to_bytes(8, "little").hex()
    return {
        "tag": tag,
        "slot": slot,
        "country_pointer": hex(pointer),
        "fullref": hex(fullref),
        "fullref_raw_hex": raw_hex,
        "country_fullref_address": hex(pointer + 0x10),
        "table_entry_address": hex(0x500000 + slot * 8),
        "table_entry_raw_hex": pointer.to_bytes(8, "little", signed=False).hex()
        if type(pointer) is int and 0 <= pointer < 1 << 64 else "invalid",
    }


class FakeReader:
    def __init__(self, *, flag: int = 1, qualifier: int = 2,
                 overlord: int = 0x12345678,
                 global_a: int = 2, global_b: int = 0, global_c: int = 0,
                 fail_labels: set[str] | None = None,
                 short_labels: set[str] | None = None):
        self.regions: dict[int, bytes] = {}
        country = bytearray(COUNTRY_REGION_SIZE)
        country[memory.COUNTRY_GREAT_POWER_FLAG_OFFSET] = flag
        country[memory.COUNTRY_FEATURE_QUALIFIER_OFFSET:
                memory.COUNTRY_FEATURE_QUALIFIER_OFFSET + 4] = int(qualifier).to_bytes(
                    4, "little", signed=True)
        country[memory.COUNTRY_OVERLORD_FULLREF_OFFSET:
                memory.COUNTRY_OVERLORD_FULLREF_OFFSET + 8] = int(overlord).to_bytes(8, "little")
        self.regions[COUNTRY] = bytes(country)
        for rva, value in (
            (memory.FEATURE_GLOBAL_A_RVA, global_a),
            (memory.FEATURE_GLOBAL_B_RVA, global_b),
            (memory.FEATURE_GLOBAL_C_RVA, global_c),
        ):
            self.regions[MODULE_BASE + rva] = bytes((value,))
        self.fail_labels = set(fail_labels or ())
        self.short_labels = set(short_labels or ())
        self.reads: list[tuple[int, int, str]] = []

    def read(self, address: int, size: int, label: str) -> bytes:
        self.reads.append((address, size, label))
        if label in self.fail_labels:
            raise OSError(f"fixture failure at {label}")
        for start, content in self.regions.items():
            offset = address - start
            if 0 <= offset and offset + size <= len(content):
                data = content[offset:offset + size]
                return data[:-1] if label in self.short_labels else data
        raise OSError(f"fixture unmapped read at {label}")


def _read(reader: FakeReader, binding: dict | None = None, *, base=MODULE_BASE,
          fields=(memory.FIELD_ID,)):
    return memory.read_fields(reader, base, binding if binding is not None else _binding(), fields)


def _labels(reader: FakeReader) -> list[str]:
    return [label for _, _, label in reader.reads]


def test_positive_native_global_predicate_is_literal_bool_and_not_a_rank_claim():
    reader = FakeReader(global_a=2, global_b=0, global_c=0)
    result = _read(reader)[memory.FIELD_ID]
    assert result["status"] == "known"
    assert result["complete"] is False
    assert result["value"] is True
    assert result["ui_observed"] is False
    assert result["ranking_membership_observed"] is False
    assert result["raw_inputs"]["native_operands"]["bound_country_fullref"]["value_hex"] == (
        "0x0100007a00415246"
    )
    assert result["raw_inputs"]["native_operands"]["feature_global_A"]["raw_hex"] == "02"
    assert _labels(reader) == [
        "country_great_power_flag", "country_feature_qualifier",
        "country_overlord_fullref", "feature_global_A", "feature_global_B",
        "feature_global_C",
    ]


@pytest.mark.parametrize(
    ("global_a", "global_b", "global_c", "status", "value"),
    [
        (0, 0, 3, "known", True),
        (0, 0, 0, "unknown", None),
        (2, 1, 3, "unknown", None),
        (0, 1, 4, "unknown", None),
        (255, 0, 255, "known", True),
    ],
)
def test_global_truth_table_nonzero_bytes_and_tls_negative_are_distinguished(
        global_a, global_b, global_c, status, value):
    reader = FakeReader(global_a=global_a, global_b=global_b, global_c=global_c)
    result = _read(reader)[memory.FIELD_ID]
    assert result["status"] == status
    assert result.get("value") is value
    if status == "unknown":
        assert result["reason"] == "GREAT_POWER_TLS_PREDICATE_UNRESOLVED"
        assert "NEGATIVE_GLOBAL_BRANCH_DEPENDS_ON_UNRESOLVED_TLS" in result["gaps"]
    assert _labels(reader)[-3:] == [
        "feature_global_A", "feature_global_B", "feature_global_C"
    ]


def test_target_flag_zero_is_known_false_and_reads_nothing_else():
    reader = FakeReader(flag=0)
    result = _read(reader)[memory.FIELD_ID]
    assert result["status"] == "known"
    assert result["value"] is False
    assert result["complete"] is False
    assert _labels(reader) == ["country_great_power_flag"]


def test_zero_qualifier_is_known_false_without_reading_feature_globals():
    reader = FakeReader(qualifier=0, fail_labels={"country_overlord_fullref"})
    result = _read(reader)[memory.FIELD_ID]
    assert result["status"] == "known"
    assert result["value"] is False
    assert _labels(reader) == [
        "country_great_power_flag", "country_feature_qualifier",
    ]
    assert result["raw_inputs"]["read_failures"] == []


def test_any_nonzero_signed_qualifier_is_preserved_as_nonzero_without_extra_semantics():
    reader = FakeReader(qualifier=-7, global_a=0, global_b=0, global_c=2)
    result = _read(reader)[memory.FIELD_ID]
    assert result["status"] == "known"
    assert result["value"] is True
    assert result["raw_inputs"]["native_operands"]["country_feature_qualifier"]["signed_i32"] == -7


def test_overlord_high_byte_nonzero_is_known_false_without_global_reads():
    reader = FakeReader(overlord=(1 << 56) | 0x12345678)
    result = _read(reader)[memory.FIELD_ID]
    assert result["status"] == "known"
    assert result["value"] is False
    assert result["raw_inputs"]["native_operands"]["country_overlord_fullref"]["high_byte"] == 1
    assert _labels(reader) == [
        "country_great_power_flag", "country_feature_qualifier",
        "country_overlord_fullref",
    ]


@pytest.mark.parametrize(
    "binding",
    [
        _binding(tag="POR", fullref=_fullref(tag=TAG, slot=SLOT)),
        _binding(slot=123, fullref=_fullref(tag=TAG, slot=SLOT)),
        _binding(slot=True),
        _binding(fullref=True),
        _binding(raw_hex="00" * 8),
        _binding(pointer=True),
        _binding(pointer=0x7000),
        _binding(fullref=_fullref(byte48=7)),
        _binding(fullref=_fullref(high_byte=0)),
    ],
)
def test_wrong_tag_slot_raw_pointer_and_special_fullref_fail_closed_before_reads(binding):
    reader = FakeReader()
    result = _read(reader, binding)[memory.FIELD_ID]
    assert result["status"] == "unknown"
    assert "value" not in result
    assert reader.reads == []


def test_wrong_fullref_identity_and_boolean_field_shapes_are_rejected_before_reads():
    reader = FakeReader()
    bad_ref = _fullref(tag="POR", slot=SLOT)
    result = _read(reader, _binding(fullref=bad_ref))[memory.FIELD_ID]
    assert result["status"] == "unknown"
    assert reader.reads == []

    reader2 = FakeReader()
    result2 = memory.read_fields(reader2, MODULE_BASE, _binding(), (memory.FIELD_ID, memory.FIELD_ID))
    assert result2[memory.FIELD_ID]["reason"] == "duplicate_field_requested"
    assert reader2.reads == []

    reader3 = FakeReader()
    result3 = memory.read_fields(reader3, MODULE_BASE, _binding(), [memory.FIELD_ID])
    assert result3[memory.FIELD_ID]["reason"] == "fields_shape_invalid"
    assert reader3.reads == []


def test_unsupported_fields_and_invalid_base_do_not_read_memory():
    reader = FakeReader()
    result = memory.read_fields(reader, MODULE_BASE, {"not": "a binding"}, ("F01.wars",))
    assert result["F01.wars"]["reason"] == "unsupported_field"
    assert reader.reads == []

    reader2 = FakeReader()
    result2 = _read(reader2, base=True)[memory.FIELD_ID]
    assert result2["status"] == "unknown"
    assert reader2.reads == []

    reader3 = FakeReader()
    result3 = memory.read_fields(reader3, MODULE_BASE, None, (memory.FIELD_ID,))
    assert result3[memory.FIELD_ID]["status"] == "unknown"
    assert reader3.reads == []


@pytest.mark.parametrize(
    "label",
    [
        "country_great_power_flag", "country_feature_qualifier", "country_overlord_fullref",
        "feature_global_A", "feature_global_B", "feature_global_C",
    ],
)
def test_read_exception_retracts_the_value_and_records_failed_operand(label):
    reader = FakeReader(fail_labels={label})
    result = _read(reader)[memory.FIELD_ID]
    assert result["status"] == "unknown"
    assert "value" not in result
    assert result["raw_inputs"]["read_failures"][-1]["operand"] == label


@pytest.mark.parametrize(
    "label",
    [
        "country_great_power_flag", "country_feature_qualifier", "country_overlord_fullref",
        "feature_global_A", "feature_global_B", "feature_global_C",
    ],
)
def test_short_read_retracts_the_value(label):
    reader = FakeReader(short_labels={label})
    result = _read(reader)[memory.FIELD_ID]
    assert result["status"] == "unknown"
    assert "value" not in result
    assert result["raw_inputs"]["read_failures"][-1]["operand"] == label


def test_callable_reader_is_supported_and_public_result_contains_no_native_pointer():
    reader = FakeReader()
    result = memory.read_fields(reader.read, MODULE_BASE, _binding(), (memory.FIELD_ID,))[memory.FIELD_ID]
    assert result["status"] == "known"
    assert type(result["value"]) is bool
    assert isinstance(result["raw_inputs"]["country_binding"]["country_pointer"], str)
    assert result["value"] is True


def test_country_pointer_address_overflow_fails_before_any_native_read():
    reader = FakeReader()
    top = memory.MAX_USER_ADDRESS & ~7
    binding = _binding(pointer=top)
    result = _read(reader, binding)[memory.FIELD_ID]
    assert result["status"] == "unknown"
    assert "value" not in result
    assert reader.reads == []
