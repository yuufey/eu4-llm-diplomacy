from __future__ import annotations

import pytest

from bridge.information import religion_group_memory as memory


MODULE_BASE = 0x140000000
COUNTRY = 0x200000
TABLE_ENTRY = 0x100000
RELIGION = 0x300000
GROUP = 0x320000
HEAP = 0x400000
SLOT = 47
TAG = "POR"
FULLREF = (SLOT << 32) | int.from_bytes(TAG.encode("ascii"), "little")
BINDING = {
    "tag": TAG,
    "slot": SLOT,
    "country_pointer": hex(COUNTRY),
    "fullref": hex(FULLREF),
    "fullref_raw_hex": FULLREF.to_bytes(8, "little").hex(),
    "country_fullref_address": hex(COUNTRY + 0x20),
    "table_entry_address": hex(TABLE_ENTRY),
    "table_entry_raw_hex": COUNTRY.to_bytes(8, "little").hex(),
}


def _header(value: bytes, *, storage: str = "inline", capacity: int | None = None,
            pointer: int = HEAP, terminator: int = 0) -> bytes:
    if capacity is None:
        capacity = 15 if storage == "inline" else max(16, len(value))
    header = bytearray(memory.STRING32_SIZE)
    if storage == "inline":
        header[:len(value)] = value
        if len(value) < 16:
            header[len(value)] = terminator
    else:
        header[:8] = pointer.to_bytes(8, "little")
    header[memory.STRING32_LENGTH_OFFSET:0x18] = len(value).to_bytes(8, "little")
    header[memory.STRING32_CAPACITY_OFFSET:0x20] = capacity.to_bytes(8, "little")
    return bytes(header)


class FakeMemory:
    def __init__(self, *, value: bytes = b"catholic", storage: str = "inline",
                 capacity: int | None = None, terminator: int = 0,
                 religion_pointer: int = RELIGION, group_pointer: int = GROUP,
                 regions: dict[int, bytes] | None = None,
                 overrides: dict[str, list[bytes | BaseException]] | None = None,
                 short_labels: set[str] | None = None,
                 binding: dict | None = None):
        self.binding = dict(BINDING if binding is None else binding)
        self.reads: list[tuple[int, int, str]] = []
        self.overrides = {label: list(items) for label, items in (overrides or {}).items()}
        self.short_labels = set(short_labels or ())
        country = int(self.binding["country_pointer"], 0)
        table = int(self.binding["table_entry_address"], 0)
        fullref_address = int(self.binding["country_fullref_address"], 0)
        self.regions = {
            table: country.to_bytes(8, "little"),
            fullref_address: int(self.binding["fullref"], 0).to_bytes(8, "little"),
            country + memory.COUNTRY_RELIGION_POINTER_OFFSET: religion_pointer.to_bytes(8, "little"),
            religion_pointer + memory.RELIGION_GROUP_POINTER_OFFSET: group_pointer.to_bytes(8, "little"),
            group_pointer + memory.GROUP_NAME_OFFSET: _header(
                value, storage=storage, capacity=capacity, terminator=terminator),
        }
        if storage == "heap":
            self.regions[HEAP] = value + b"\x00"
        self.regions.update(regions or {})

    def read(self, address: int, size: int, label: str) -> bytes:
        self.reads.append((address, size, label))
        scripted = self.overrides.get(label)
        if scripted:
            item = scripted.pop(0)
            if isinstance(item, BaseException):
                raise item
            return item
        for start, data in self.regions.items():
            offset = address - start
            if 0 <= offset and offset + size <= len(data):
                result = data[offset:offset + size]
                if label in self.short_labels:
                    return result[:-1]
                return result
        raise OSError(f"unmapped read at {label}")


def _read(reader: FakeMemory, fields=(memory.FIELD_ID,), *, base=MODULE_BASE):
    return memory.read_fields(reader, base, reader.binding, fields)


def _unknown(field: dict) -> None:
    assert field["status"] == "unknown"
    assert field["complete"] is False
    assert "value" not in field


def test_inline_chinese_group_display_name_is_strictly_decoded_and_bounded():
    encoded = bytes.fromhex("10 fa 57 10 63 77 10 59 65")  # 基督教
    reader = FakeMemory(value=encoded, capacity=15)

    field = _read(reader)[memory.FIELD_ID]

    assert field["status"] == "known"
    assert field["complete"] is False
    assert field["basis"] == "bounded_primary_religion_group_display_name_string32"
    assert field["value"] == {
        "religion_group_name": {
            "text": "基督教",
            "raw_hex": encoded.hex(),
            "encoding": "eu4_escape",
        },
    }
    assert field["gaps"] == [
        "RELIGION_GROUP_CONFIGURATION_KEY_NOT_READ",
        "TOOLTIP_NOT_READ",
        "CALLER_ADMISSION_IS_PARENT_OWNED",
    ]
    assert "table_entry_before_raw_hex" not in field["value"]
    assert field["raw_inputs"]["string32_storage"] == "inline"
    assert (RELIGION + memory.GROUP_NAME_OFFSET) not in {
        address for address, _, _ in reader.reads
    }
    assert field["raw_inputs"]["budget"]["calls"] == len(reader.reads)
    assert field["raw_inputs"]["budget"]["calls"] <= memory.MAX_READ_CALLS
    assert field["raw_inputs"]["budget"]["bytes_requested"] <= memory.MAX_READ_BYTES


def test_heap_string32_with_max_capacity_is_read_and_rechecked():
    reader = FakeMemory(value=b"catholic", storage="heap", capacity=8192)

    field = _read(reader)[memory.FIELD_ID]

    assert field["status"] == "known"
    assert field["value"]["religion_group_name"] == {
        "text": "catholic", "raw_hex": b"catholic".hex(), "encoding": "eu4_escape",
    }
    labels = [label for _, _, label in reader.reads]
    assert labels.count("religion_group.String32_heap_payload_before") == 1
    assert labels.count("religion_group.String32_heap_payload_after") == 1
    assert labels.count("religion_group.String32_header_before") == 1
    assert labels.count("religion_group.String32_header_after") == 1


@pytest.mark.parametrize(
    ("value", "storage", "capacity", "terminator", "expected_reason"),
    [
        (b"", "inline", 15, 0, "religion_group_name_empty"),
        (b"a" * 129, "heap", 129, 0, "religion_group_name_length_out_of_bound"),
        (b"abc", "inline", 2, 0, "religion_group_string32_capacity_below_length"),
        (b"a", "heap", 8193, 0, "religion_group_string32_capacity_out_of_bound"),
        (b"abc", "inline", 15, 1, "religion_group_name_terminator_invalid"),
        (b"a\x00b", "inline", 15, 0, "religion_group_name_embedded_nul"),
        (b"\x10", "inline", 15, 0, "religion_group_name_decode_invalid"),
    ],
)
def test_invalid_string32_shapes_and_encoding_are_unknown(
        value, storage, capacity, terminator, expected_reason):
    reader = FakeMemory(value=value, storage=storage, capacity=capacity,
                        terminator=terminator)

    field = _read(reader)[memory.FIELD_ID]

    _unknown(field)
    assert expected_reason in field["reason"]
    assert field["raw_inputs"]["string32_length"] == len(value)


@pytest.mark.parametrize(
    ("label", "value"),
    [
        ("religion_group.String32_header_before", None),
        ("religion_group.String32_heap_payload_before", None),
    ],
)
def test_short_string32_reads_are_unknown(label, value):
    reader = FakeMemory(value=b"catholic", storage="heap",
                        short_labels={label})

    field = _read(reader)[memory.FIELD_ID]

    _unknown(field)
    assert field["raw_inputs"]["reads"][-1]["status"] == "failed"


@pytest.mark.parametrize(
    ("label", "response", "reason"),
    [
        ("religion_group.group_pointer_after", (0x330000).to_bytes(8, "little"),
         "religion_group_pointer_changed"),
        ("religion_group.primary_religion_pointer_after", (0x310000).to_bytes(8, "little"),
         "primary_religion_pointer_changed"),
        ("religion_group.country_table_entry_after", (0x210000).to_bytes(8, "little"),
         "country_table_entry_changed_during_read"),
        ("religion_group.country_fullref_after", (FULLREF + 1).to_bytes(8, "little"),
         "country_fullref_changed_during_read"),
    ],
)
def test_pointer_or_country_binding_drift_is_unknown(label, response, reason):
    reader = FakeMemory(overrides={label: [response]})

    field = _read(reader)[memory.FIELD_ID]

    _unknown(field)
    assert reason in field["reason"]


def test_country_binding_drift_before_read_is_unknown():
    reader = FakeMemory(overrides={
        "religion_group.country_table_entry_before": [(COUNTRY + 8).to_bytes(8, "little")],
    })

    field = _read(reader)[memory.FIELD_ID]

    _unknown(field)
    assert "country_table_entry_changed_before_read" in field["reason"]
    assert len(reader.reads) == 2


@pytest.mark.parametrize(
    ("label", "response", "reason"),
    [
        ("religion_group.String32_header_after",
         _header(b"romania", capacity=15), "religion_group_string32_header_changed"),
        ("religion_group.String32_heap_payload_after", b"romanish\x00",
         "religion_group_string32_heap_payload_changed"),
    ],
)
def test_string32_header_or_heap_payload_drift_is_unknown(label, response, reason):
    if "payload" in label:
        reader = FakeMemory(value=b"catholic", storage="heap", capacity=31,
                            overrides={label: [response]})
    else:
        reader = FakeMemory(value=b"catholic", capacity=15,
                            overrides={label: [response]})

    field = _read(reader)[memory.FIELD_ID]

    _unknown(field)
    assert reason in field["reason"]


@pytest.mark.parametrize("religion_pointer,group_pointer,reason", [
    (0, GROUP, "primary_religion_pointer_null"),
    (RELIGION, 0, "religion_group_pointer_null"),
])
def test_null_pointer_hops_are_unknown(religion_pointer, group_pointer, reason):
    reader = FakeMemory(religion_pointer=religion_pointer, group_pointer=group_pointer)

    field = _read(reader)[memory.FIELD_ID]

    _unknown(field)
    assert reason in field["reason"]


def test_pointer_addition_overflow_is_rejected_before_native_read():
    country = 0x7FFFFFFFFF00
    binding = dict(BINDING)
    binding["country_pointer"] = hex(country)
    binding["table_entry_raw_hex"] = country.to_bytes(8, "little").hex()
    binding["country_fullref_address"] = hex(country + 0x20)
    reader = FakeMemory(binding=binding)

    field = _read(reader)[memory.FIELD_ID]

    _unknown(field)
    assert "address_range_invalid:primary_religion_pointer" in field["raw_inputs"]["leaf_error"]["detail"]
    assert not any("primary_religion_pointer" in label for _, _, label in reader.reads)


def test_heap_payload_range_overflow_is_rejected_before_payload_read():
    reader = FakeMemory(value=b"catholic", storage="heap", capacity=31)
    heap_pointer = 0x7FFFFFFFFFFD
    reader.regions[GROUP + memory.GROUP_NAME_OFFSET] = _header(
        b"catholic", storage="heap", capacity=31, pointer=heap_pointer)

    field = _read(reader)[memory.FIELD_ID]

    _unknown(field)
    assert "address_range_invalid:religion_group_name_heap_payload" in field["raw_inputs"]["leaf_error"]["detail"]
    assert not any("heap_payload" in label for _, _, label in reader.reads)


def test_shared_outer_budget_error_is_not_hidden_as_leaf_unknown():
    reader = FakeMemory(overrides={
        "religion_group.String32_header_after": [ValueError("read_budget_exceeded")],
    })

    with pytest.raises(ValueError, match="read_budget_exceeded"):
        _read(reader)


def test_field_request_shape_duplicate_and_unsupported_semantics_match_faith_leaf():
    reader = FakeMemory()

    assert memory.read_fields(reader, MODULE_BASE, reader.binding, ()) == {}
    invalid = memory.read_fields(reader, MODULE_BASE, reader.binding, [memory.FIELD_ID])
    _unknown(invalid[memory.FIELD_ID])
    assert invalid[memory.FIELD_ID]["reason"] == "fields_shape_invalid"
    mixed = memory.read_fields(reader, MODULE_BASE, reader.binding,
                               (memory.FIELD_ID, 7))
    _unknown(mixed[memory.FIELD_ID])
    assert mixed[memory.FIELD_ID]["reason"] == "fields_shape_invalid"
    duplicate = memory.read_fields(reader, MODULE_BASE, reader.binding,
                                   (memory.FIELD_ID, memory.FIELD_ID))
    _unknown(duplicate[memory.FIELD_ID])
    assert duplicate[memory.FIELD_ID]["reason"] == "duplicate_field_requested"
    unsupported = memory.read_fields(reader, MODULE_BASE, reader.binding, ("S02.other",))
    _unknown(unsupported["S02.other"])
    assert unsupported["S02.other"]["reason"] == "unsupported_field"
    assert reader.reads == []


@pytest.mark.parametrize("base", [True, "0x140000000", 0, 0x7FFFFFFFFFFF + 1])
def test_module_base_requires_bounded_non_boolean_integer(base):
    reader = FakeMemory()

    field = _read(reader, base=base)[memory.FIELD_ID]

    _unknown(field)
    assert reader.reads == []


@pytest.mark.parametrize("key,value", [
    ("slot", True),
    ("fullref", True),
    ("country_pointer", True),
])
def test_binding_boolean_in_integer_fields_is_rejected(key, value):
    reader = FakeMemory()
    binding = dict(reader.binding)
    binding[key] = value

    field = memory.read_fields(reader, MODULE_BASE, binding,
                               (memory.FIELD_ID,))[memory.FIELD_ID]

    _unknown(field)
    assert reader.reads == []


def test_known_field_budget_and_raw_string_are_bounded():
    reader = FakeMemory(value=b"a" * 128, storage="heap", capacity=8192)

    field = _read(reader)[memory.FIELD_ID]

    assert field["status"] == "known"
    assert len(field["value"]["religion_group_name"]["raw_hex"]) == 256
    assert field["raw_inputs"]["budget"]["calls"] == len(reader.reads)
    assert field["raw_inputs"]["budget"]["calls"] <= 32
    assert field["raw_inputs"]["budget"]["bytes_requested"] <= 4096
