from __future__ import annotations

import pytest

from bridge.information import religion_identity_memory as memory


BASE = 0x140000000
COUNTRY = 0x200000
TABLE_ENTRY = 0x100000
RELIGION = 0x300000
GROUP = 0x320000
RELIGION_HEAP = 0x400000
GROUP_HEAP = 0x500000
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


def _string32(value: bytes, *, storage: str = "inline", capacity: int | None = None,
              pointer: int = RELIGION_HEAP, terminator: int = 0) -> bytes:
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
    def __init__(self, *, religion_key: bytes = b"catholic",
                 group_key: bytes = b"christian",
                 religion_storage: str = "inline", group_storage: str = "inline",
                 religion_capacity: int | None = None, group_capacity: int | None = None,
                 religion_terminator: int = 0, group_terminator: int = 0,
                 religion_pointer: int = RELIGION, group_pointer: int = GROUP,
                 binding: dict | None = None,
                 regions: dict[int, bytes] | None = None,
                 overrides: dict[str, list[bytes | BaseException]] | None = None,
                 short_labels: set[str] | None = None):
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
            country + memory.COUNTRY_RELIGION_POINTER_OFFSET:
                religion_pointer.to_bytes(8, "little"),
            religion_pointer + memory.RELIGION_GROUP_POINTER_OFFSET:
                group_pointer.to_bytes(8, "little"),
            religion_pointer + memory.RELIGION_KEY_STRING32_OFFSET:
                _string32(religion_key, storage=religion_storage,
                          capacity=religion_capacity, pointer=RELIGION_HEAP,
                          terminator=religion_terminator),
            group_pointer + memory.GROUP_KEY_STRING32_OFFSET:
                _string32(group_key, storage=group_storage,
                          capacity=group_capacity, pointer=GROUP_HEAP,
                          terminator=group_terminator),
        }
        if religion_storage == "heap":
            self.regions[RELIGION_HEAP] = religion_key + b"\x00"
        if group_storage == "heap":
            self.regions[GROUP_HEAP] = group_key + b"\x00"
        self.regions.update(regions or {})

    def read(self, address: int, size: int, label: str) -> bytes:
        self.reads.append((address, size, label))
        scripted = self.overrides.get(label)
        if scripted:
            result = scripted.pop(0)
            if isinstance(result, BaseException):
                raise result
            return result
        for start, data in self.regions.items():
            offset = address - start
            if 0 <= offset and offset + size <= len(data):
                result = data[offset:offset + size]
                if label in self.short_labels:
                    return result[:-1]
                return result
        raise OSError(f"unmapped read at {label}")


def _read(reader: FakeMemory, fields=(memory.FIELD_ID,), *, base=BASE):
    return memory.read_fields(reader, base, reader.binding, fields)


def _unknown(field: dict) -> None:
    assert field["status"] == "unknown"
    assert field["complete"] is False
    assert "value" not in field


def test_inline_religion_and_group_configuration_keys_are_read_as_ascii_identifiers():
    reader = FakeMemory()

    field = _read(reader)[memory.FIELD_ID]

    assert set(field) == {"status", "complete", "value", "basis", "gaps", "raw_inputs"}
    assert field["status"] == "known"
    assert field["complete"] is False
    assert field["value"] == {"religion_key": "catholic", "religion_group_key": "christian"}
    assert field["basis"] == "bounded_native_religion_and_group_configuration_keys"
    assert field["gaps"] == [
        "LOCALIZATION_TOOLTIP_AND_RELIGION_RULES_NOT_READ",
        "CALLER_ADMISSION_IS_PARENT_OWNED",
        "UI_RENDER_NOT_OBSERVED",
    ]
    assert field["raw_inputs"]["religion_key_String32_length"] == 8
    assert field["raw_inputs"]["religion_key_String32_capacity"] == 15
    assert field["raw_inputs"]["religion_group_key_String32_length"] == 9
    assert field["raw_inputs"]["religion_group_key_String32_capacity"] == 15
    assert field["raw_inputs"]["budget"]["calls"] == len(reader.reads)
    assert field["raw_inputs"]["budget"]["calls"] <= 32
    assert field["raw_inputs"]["budget"]["bytes_requested"] <= 4096
    assert all(key in field["raw_inputs"] for key in (
        "primary_religion_pointer", "religion_group_pointer",
        "religion_key_String32_header_before_raw_hex",
        "religion_group_key_String32_header_before_raw_hex"))


def test_heap_religion_and_group_keys_are_rechecked_and_exposed_without_metadata():
    reader = FakeMemory(religion_storage="heap", group_storage="heap",
                        religion_capacity=8192, group_capacity=8192)

    field = _read(reader)[memory.FIELD_ID]

    assert field["status"] == "known"
    assert field["value"] == {"religion_key": "catholic", "religion_group_key": "christian"}
    assert set(field["value"]) == {"religion_key", "religion_group_key"}
    labels = [label for _, _, label in reader.reads]
    for key in ("religion_key", "religion_group_key"):
        assert labels.count(f"religion_identity.{key}.String32_header_before") == 1
        assert labels.count(f"religion_identity.{key}.String32_header_after") == 1
        assert labels.count(f"religion_identity.{key}.String32_heap_payload_before") == 1
        assert labels.count(f"religion_identity.{key}.String32_heap_payload_after") == 1


@pytest.mark.parametrize(
    ("key", "value", "storage", "capacity", "terminator", "reason"),
    [
        ("religion_key", b"", "inline", 15, 0, "religion_key_length_out_of_bound"),
        ("religion_group_key", b"a" * 129, "heap", 129, 0,
         "religion_group_key_length_out_of_bound"),
        ("religion_key", b"abc", "inline", 2, 0,
         "religion_key_capacity_below_length"),
        ("religion_group_key", b"a", "heap", 8193, 0,
         "religion_group_key_capacity_out_of_bound"),
        ("religion_key", b"catholic", "inline", 15, 1,
         "religion_key_terminator_invalid"),
        ("religion_group_key", b"christian", "inline", 15, 1,
         "religion_group_key_terminator_invalid"),
        ("religion_key", b"cat\x00holic", "inline", 15, 0,
         "religion_key_embedded_nul"),
        ("religion_group_key", "基督教".encode("utf-8"), "heap", 16, 0,
         "religion_group_key_non_ascii"),
        ("religion_key", b"-catholic", "inline", 15, 0,
         "religion_key_identifier_invalid"),
    ],
)
def test_malformed_string32_shapes_and_identifiers_are_unknown(
        key, value, storage, capacity, terminator, reason):
    reader = FakeMemory()
    if key == "religion_key":
        reader = FakeMemory(religion_key=value, religion_storage=storage,
                            religion_capacity=capacity,
                            religion_terminator=terminator)
    else:
        reader = FakeMemory(group_key=value, group_storage=storage,
                            group_capacity=capacity, group_terminator=terminator)

    field = _read(reader)[memory.FIELD_ID]

    _unknown(field)
    assert reason in field["reason"]


@pytest.mark.parametrize(
    ("label", "reason"),
    [
        ("religion_identity.religion_key.String32_header_before",
         "religion_identity_read_failed"),
        ("religion_identity.religion_group_key.String32_header_before",
         "religion_identity_read_failed"),
        ("religion_identity.religion_key.String32_heap_payload_before",
         "religion_identity_read_failed"),
        ("religion_identity.religion_group_key.String32_heap_payload_before",
         "religion_identity_read_failed"),
    ],
)
def test_short_header_or_heap_payload_read_is_unknown(label, reason):
    reader = FakeMemory(religion_storage="heap", group_storage="heap",
                        short_labels={label})

    field = _read(reader)[memory.FIELD_ID]

    _unknown(field)
    assert reason in field["reason"]


@pytest.mark.parametrize("religion_pointer,group_pointer,reason", [
    (0, GROUP, "primary_religion_pointer_null"),
    (RELIGION, 0, "religion_group_pointer_null"),
    (RELIGION + 1, GROUP, "religion_identity_read_failed"),
    (RELIGION, GROUP + 1, "religion_identity_read_failed"),
])
def test_null_or_invalid_native_object_pointer_is_unknown(
        religion_pointer, group_pointer, reason):
    reader = FakeMemory(religion_pointer=religion_pointer, group_pointer=group_pointer)

    field = _read(reader)[memory.FIELD_ID]

    _unknown(field)
    assert reason in field["reason"]


@pytest.mark.parametrize(
    ("label", "response", "reason"),
    [
        ("religion_identity.group_pointer_after", (GROUP + 8).to_bytes(8, "little"),
         "religion_group_pointer_changed"),
        ("religion_identity.primary_religion_pointer_after", (RELIGION + 8).to_bytes(8, "little"),
         "primary_religion_pointer_changed"),
        ("religion_identity.country_table_entry_after", (COUNTRY + 8).to_bytes(8, "little"),
         "country_table_entry_changed_during_read"),
        ("religion_identity.country_fullref_after", (FULLREF + 1).to_bytes(8, "little"),
         "country_fullref_changed_during_read"),
        ("religion_identity.religion_key.String32_header_after",
         _string32(b"orthodox", capacity=15), "religion_identity_string32_changed"),
        ("religion_identity.religion_key.String32_heap_payload_after",
         b"orthodox\x00", "religion_identity_string32_changed"),
        ("religion_identity.religion_group_key.String32_heap_payload_after",
         b"reformist\x00", "religion_identity_string32_changed"),
    ],
)
def test_pointer_fullref_header_or_payload_drift_revokes_both_keys(label, response, reason):
    if "heap_payload" in label:
        reader = FakeMemory(religion_storage="heap", group_storage="heap",
                            overrides={label: [response]})
    else:
        reader = FakeMemory(overrides={label: [response]})

    field = _read(reader)[memory.FIELD_ID]

    _unknown(field)
    assert reason in field["reason"]


def test_shared_outer_read_budget_error_is_not_swallowed_as_leaf_unknown():
    reader = FakeMemory(overrides={
        "religion_identity.religion_key.String32_header_after":
            [ValueError("read_budget_exceeded")],
    })

    with pytest.raises(ValueError, match="read_budget_exceeded"):
        _read(reader)


def test_field_request_shape_duplicate_and_unsupported_semantics_match_group_leaf():
    reader = FakeMemory()

    assert memory.read_fields(reader, BASE, reader.binding, ()) == {}
    invalid = memory.read_fields(reader, BASE, reader.binding, [memory.FIELD_ID])
    _unknown(invalid[memory.FIELD_ID])
    assert invalid[memory.FIELD_ID]["reason"] == "fields_shape_invalid"
    mixed = memory.read_fields(reader, BASE, reader.binding, (memory.FIELD_ID, 7))
    _unknown(mixed[memory.FIELD_ID])
    assert mixed[memory.FIELD_ID]["reason"] == "fields_shape_invalid"
    duplicate = memory.read_fields(reader, BASE, reader.binding,
                                   (memory.FIELD_ID, memory.FIELD_ID))
    _unknown(duplicate[memory.FIELD_ID])
    assert duplicate[memory.FIELD_ID]["reason"] == "duplicate_field_requested"
    unsupported = memory.read_fields(reader, BASE, reader.binding, ("S02.other",))
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
def test_binding_boolean_integer_fields_are_rejected(key, value):
    reader = FakeMemory()
    binding = dict(reader.binding)
    binding[key] = value

    field = memory.read_fields(reader, BASE, binding, (memory.FIELD_ID,))[memory.FIELD_ID]

    _unknown(field)
    assert reader.reads == []


def test_maximum_key_length_and_capacity_remain_within_leaf_budget():
    reader = FakeMemory(religion_key=b"a" * 128, religion_storage="heap",
                        religion_capacity=8192,
                        group_key=b"b" * 128, group_storage="heap",
                        group_capacity=8192)

    field = _read(reader)[memory.FIELD_ID]

    assert field["status"] == "known"
    assert len(field["value"]["religion_key"]) == 128
    assert len(field["value"]["religion_group_key"]) == 128
    assert field["raw_inputs"]["budget"]["calls"] <= memory.MAX_READ_CALLS
    assert field["raw_inputs"]["budget"]["bytes_requested"] <= memory.MAX_READ_BYTES
