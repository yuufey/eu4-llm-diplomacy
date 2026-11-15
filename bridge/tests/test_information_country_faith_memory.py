from __future__ import annotations

import pytest

from bridge.information import country_faith_memory as faith


MODULE_BASE = 0x140000000
COUNTRY = 0x200000
RELIGION = 0x300000
HEAP = 0x400000
ICON_FRAME = 7
SLOT = 47
TAG = "POR"
FULLREF = (SLOT << 32) | int.from_bytes(TAG.encode("ascii"), "little")
BINDING = {
    "tag": TAG,
    "slot": SLOT,
    "country_pointer": hex(COUNTRY),
    "fullref": hex(FULLREF),
    "fullref_raw_hex": FULLREF.to_bytes(8, "little").hex(),
    "country_fullref_address": hex(COUNTRY + 0x10),
    "table_entry_address": hex(0x500000),
    "table_entry_raw_hex": COUNTRY.to_bytes(8, "little").hex(),
}


class FakeLimiter:
    def __init__(self, regions: dict[int, bytes] | None = None,
                 *, fail_labels: set[str] | None = None,
                 short_labels: set[str] | None = None):
        self.regions = dict(regions or {})
        self.fail_labels = set(fail_labels or ())
        self.short_labels = set(short_labels or ())
        self.reads: list[tuple[int, int, str]] = []

    def read(self, address: int, size: int, label: str) -> bytes:
        self.reads.append((address, size, label))
        if label in self.fail_labels:
            raise OSError(f"fixture read failure at {label}")
        for start, data in self.regions.items():
            offset = address - start
            if 0 <= offset and offset + size <= len(data):
                result = data[offset:offset + size]
                if label in self.short_labels:
                    return result[:-1]
                return result
        raise OSError(f"fixture unmapped read at {label}")


def _header_inline(value: bytes, *, capacity: int = 15,
                   terminator: int = 0) -> bytes:
    header = bytearray(32)
    header[:len(value)] = value
    if len(value) < 16:
        header[len(value)] = terminator
    header[0x10:0x18] = len(value).to_bytes(8, "little")
    header[0x18:0x20] = capacity.to_bytes(8, "little")
    return bytes(header)


def _header_heap(value: bytes, *, capacity: int = 31,
                 pointer: int = HEAP) -> bytes:
    header = bytearray(32)
    header[:8] = pointer.to_bytes(8, "little")
    header[0x10:0x18] = len(value).to_bytes(8, "little")
    header[0x18:0x20] = capacity.to_bytes(8, "little")
    return bytes(header)


def _reader(*, value: bytes = b"catholic", storage: str = "inline",
            pointer: int = RELIGION, capacity: int | None = None,
            icon: int = ICON_FRAME, terminator: int = 0,
            extra_regions: dict[int, bytes] | None = None,
            fail_labels: set[str] | None = None,
            short_labels: set[str] | None = None) -> FakeLimiter:
    if capacity is None:
        capacity = 15 if storage == "inline" else max(16, len(value))
    header = (_header_inline(value, capacity=capacity, terminator=terminator)
              if storage == "inline" else
              _header_heap(value, capacity=capacity, pointer=HEAP))
    regions = {
        COUNTRY + faith.COUNTRY_RELIGION_POINTER_OFFSET: pointer.to_bytes(8, "little"),
        pointer + faith.RELIGION_KEY_OFFSET: header,
        pointer + faith.RELIGION_ICON_FRAME_OFFSET: icon.to_bytes(4, "little"),
    }
    if storage == "heap":
        regions[HEAP] = value + b"\x00"
    regions.update(extra_regions or {})
    return FakeLimiter(regions, fail_labels=fail_labels, short_labels=short_labels)


def _read(reader: FakeLimiter, binding=BINDING, fields=(faith.FIELD_ID,)):
    return faith.read_fields(reader, MODULE_BASE, binding, fields)


def test_inline_ascii_primary_religion_name_and_icon_frame_are_copied_without_display_claim():
    reader = _reader(value=b"catholic", icon=7)
    result = _read(reader)[faith.FIELD_ID]
    assert result["status"] == "known"
    assert result["complete"] is False
    assert result["value"] == {
        "primary_religion_name": {
            "text": "catholic",
            "raw_hex": b"catholic".hex(),
            "encoding": "eu4_escape",
        },
        "icon_frame_request": 7,
    }
    assert result["raw_inputs"]["primary_religion_pointer"] == hex(RELIGION)
    assert result["raw_inputs"]["icon_frame_request_raw_hex"] == "07000000"
    assert result["raw_inputs"]["string32_payload_raw_hex"] == b"catholic\x00".hex()
    assert result["raw_inputs"]["native_text_decoder"]["status"] == "decoded"
    assert "ICON_FRAME_REQUEST_IS_NOT_PROOF_OF_DISPLAY" in result["gaps"]
    assert all("shown" not in key.lower() for key in result["value"])


def test_escape_encoded_runtime_display_name_decodes_strictly_and_excludes_nul_from_value_hex():
    encoded = bytes.fromhex("10295911494e105965")
    reader = _reader(value=encoded, icon=1)
    result = _read(reader)[faith.FIELD_ID]
    assert result["status"] == "known"
    assert result["value"] == {
        "primary_religion_name": {
            "text": "天主教",
            "raw_hex": "10295911494e105965",
            "encoding": "eu4_escape",
        },
        "icon_frame_request": 1,
    }
    assert result["raw_inputs"]["string32_payload_raw_hex"] == "10295911494e10596500"
    assert result["raw_inputs"]["native_text_decoder"] == {
        "status": "decoded",
        "codec": "eu4_escape",
        "gaps": ["TEXT_IS_COPIED_NOT_LOCALIZED"],
    }
    assert "PRIMARY_RELIGION_CONFIGURATION_KEY_AND_ID_NOT_READ" in result["gaps"]


def test_text_is_not_restricted_to_configuration_key_syntax():
    reader = _reader(value=b"catholic-name")
    result = _read(reader)[faith.FIELD_ID]
    assert result["status"] == "known"
    assert result["value"]["primary_religion_name"]["text"] == "catholic-name"


def test_heap_string32_reads_only_length_plus_terminator():
    reader = _reader(value=b"reformed", storage="heap", capacity=31)
    result = _read(reader)[faith.FIELD_ID]
    assert result["status"] == "known"
    assert result["value"]["primary_religion_name"]["text"] == "reformed"
    assert result["raw_inputs"]["string32_storage"] == "heap"
    assert result["raw_inputs"]["string32_heap_pointer"] == hex(HEAP)
    payload_reads = [row for row in reader.reads if row[2].endswith("String32_payload")]
    assert payload_reads == [(HEAP, len(b"reformed") + 1,
                              "country_faith.primary_religion.String32_payload")]


def test_callable_reader_is_supported():
    reader = _reader()
    result = faith.read_fields(reader.read, MODULE_BASE, BINDING, (faith.FIELD_ID,))
    assert result[faith.FIELD_ID]["status"] == "known"


@pytest.mark.parametrize(
    ("value", "reason"),
    [
        (b"cath\x00lic", "primary_religion_name_embedded_nul"),
        (b"\x10\x29", "primary_religion_name_decode_invalid"),
        (b"\x13\x0e\xcf", "primary_religion_name_decode_invalid"),
    ],
)
def test_embedded_nul_or_invalid_escape_is_unknown_not_truncated(value, reason):
    reader = _reader(value=value)
    result = _read(reader)[faith.FIELD_ID]
    assert result["status"] == "unknown"
    assert result["reason"] == reason
    assert "value" not in result
    assert "string32_header_raw_hex" in result["raw_inputs"]
    if reason.endswith("decode_invalid"):
        assert result["raw_inputs"]["native_text_decoder"]["status"] == "invalid"
        assert result["raw_inputs"]["native_text_decoder"]["error_type"] == "InvalidNativeText"


def test_empty_name_is_unknown_and_not_reported_as_absent():
    reader = _reader(value=b"")
    result = _read(reader)[faith.FIELD_ID]
    assert result["status"] == "unknown"
    assert result["reason"] == "primary_religion_name_empty"
    assert "absent" not in result["reason"]
    assert "value" not in result


def test_length_above_128_is_unknown_without_reading_payload():
    value = b"a" * 129
    reader = _reader(value=value, storage="heap", capacity=129)
    result = _read(reader)[faith.FIELD_ID]
    assert result["status"] == "unknown"
    assert result["reason"] == "primary_religion_name_length_out_of_bound"
    assert not any(row[2].endswith("String32_payload") for row in reader.reads)


@pytest.mark.parametrize(
    ("length", "capacity", "reason"),
    [
        (8, 7, "primary_religion_string32_capacity_below_length"),
        (8, 129, "primary_religion_string32_capacity_out_of_bound"),
    ],
)
def test_inconsistent_or_overbound_capacity_is_unknown(length, capacity, reason):
    reader = _reader(value=b"catholic", storage="heap", capacity=capacity)
    header_address = RELIGION + faith.RELIGION_KEY_OFFSET
    header = bytearray(reader.regions[header_address])
    header[0x10:0x18] = length.to_bytes(8, "little")
    reader.regions[header_address] = bytes(header)
    result = _read(reader)[faith.FIELD_ID]
    assert result["status"] == "unknown"
    assert result["reason"] == reason
    assert "string32_header_raw_hex" in result["raw_inputs"]


def test_missing_terminator_is_unknown():
    reader = _reader(value=b"catholic", terminator=ord("!"))
    result = _read(reader)[faith.FIELD_ID]
    assert result["status"] == "unknown"
    assert result["reason"] == "primary_religion_name_terminator_invalid"


@pytest.mark.parametrize(
    ("label", "reason"),
    [
        ("country_faith.primary_religion_pointer", "primary_religion_pointer_read_failed"),
        ("country_faith.primary_religion.String32_header", "primary_religion_string32_header_read_failed"),
        ("country_faith.primary_religion.icon_frame_request", "icon_frame_request_read_failed"),
        ("country_faith.primary_religion.String32_payload", "primary_religion_name_payload_read_failed"),
    ],
)
def test_each_read_failure_is_unknown_and_keeps_prior_raw_inputs(label, reason):
    reader = _reader(storage="heap", fail_labels={label})
    result = _read(reader)[faith.FIELD_ID]
    assert result["status"] == "unknown"
    assert result["reason"] == reason
    assert result["raw_inputs"]["country_binding"]["tag"] == TAG
    if label == "country_faith.primary_religion_pointer":
        assert "primary_religion_pointer" not in result["raw_inputs"]
    else:
        assert result["raw_inputs"]["primary_religion_pointer"] == hex(RELIGION)
    assert any(item["label"] == label for item in result["raw_inputs"]["read_failures"])


def test_short_header_read_is_unknown():
    label = "country_faith.primary_religion.String32_header"
    reader = _reader(short_labels={label})
    result = _read(reader)[faith.FIELD_ID]
    assert result["status"] == "unknown"
    assert result["reason"] == "primary_religion_string32_header_read_failed"
    assert result["raw_inputs"]["read_failures"][0]["error"].startswith("ValueError:short_read:")


def test_null_and_invalid_definition_pointers_are_unknown_not_absent():
    null_pointer = _reader(pointer=0)
    result = _read(null_pointer)[faith.FIELD_ID]
    assert result["status"] == "unknown"
    assert result["reason"] == "primary_religion_pointer_null"
    assert "absent" not in result["reason"]

    invalid_pointer = _reader(pointer=7)
    result = _read(invalid_pointer)[faith.FIELD_ID]
    assert result["status"] == "unknown"
    assert result["reason"] == "primary_religion_pointer_invalid"


def test_unknown_field_is_per_field_unknown_and_does_not_read_memory():
    reader = _reader()
    result = _read(reader, fields=("S02.religion_group", "S02.faith"))
    assert result["S02.religion_group"]["status"] == "unknown"
    assert result["S02.religion_group"]["reason"] == "unsupported_field"
    assert result["S02.faith"]["status"] == "known"
    assert result["S02.faith"]["value"]["primary_religion_name"]["text"] == "catholic"
    assert len(reader.reads) == 3


@pytest.mark.parametrize(
    ("binding", "reason"),
    [
        ({**BINDING, "tag": "POR1"}, "target_binding_tag_invalid"),
        ({**BINDING, "slot": SLOT + 1}, "target_binding_fullref_slot_mismatch"),
        ({**BINDING, "fullref": hex(FULLREF ^ 1)}, "target_binding_fullref_tag_mismatch"),
        ({**BINDING, "country_pointer": "0x7"}, "country_pointer_invalid"),
    ],
)
def test_invalid_country_binding_is_unknown_before_native_reads(binding, reason):
    reader = _reader()
    result = _read(reader, binding=binding)[faith.FIELD_ID]
    assert result["status"] == "unknown"
    assert result["reason"] == reason
    assert reader.reads == []


def test_invalid_base_is_unknown_before_native_reads():
    reader = _reader()
    result = faith.read_fields(reader, 0, BINDING, (faith.FIELD_ID,))[faith.FIELD_ID]
    assert result["status"] == "unknown"
    assert result["reason"] == "module_base_invalid"
    assert reader.reads == []


def test_non_tuple_fields_shape_is_unknown_without_reading():
    reader = _reader()
    result = faith.read_fields(reader, MODULE_BASE, BINDING, [faith.FIELD_ID])
    assert result[faith.FIELD_ID]["status"] == "unknown"
    assert result[faith.FIELD_ID]["reason"] == "fields_shape_invalid"
    assert reader.reads == []

