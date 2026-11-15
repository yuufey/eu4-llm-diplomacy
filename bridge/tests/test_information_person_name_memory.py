from __future__ import annotations

import pytest

from bridge.information import person_name_memory as person_names


BASE = 0x140000000
PERSON = 0x200000
DYNASTY = 0x300000
PERSON_VTABLE = 0x400000
DYNASTY_VTABLE = 0x410000
BASE_HEAP = 0x500000
DYN_HEAP = 0x510000
COUNTRY_REF = 0x0100007A00415246
OTHER_COUNTRY_REF = 0x0100002E00474E45

TRUE_METHOD = BASE + person_names.DYN_APPEND_TRUE_RVA
FALSE_METHOD = BASE + person_names.DYN_APPEND_FALSE_RVA
ACTUAL_FRA_PERSON_NAME = bytes.fromhex("10ef8d101366205849")
ACTUAL_FRA_DYNASTY_NAME = bytes.fromhex("12b7562010e67410625310e674")


def _string32(value: bytes, *, storage: str = "inline", capacity: int | None = None,
              pointer: int = BASE_HEAP, terminator: int = 0) -> tuple[bytes, bytes | None]:
    header = bytearray(0x20)
    if capacity is None:
        capacity = 15 if storage == "inline" else max(16, len(value))
    payload = value + bytes([terminator])
    if storage == "inline":
        if len(payload) <= 16:
            header[:len(payload)] = payload
    else:
        header[:8] = pointer.to_bytes(8, "little")
    header[0x10:0x18] = len(value).to_bytes(8, "little")
    header[0x18:0x20] = capacity.to_bytes(8, "little")
    return bytes(header), (payload if storage == "heap" else None)


class FakeLimiter:
    def __init__(self, regions: dict[int, bytes], *, fail_labels: set[str] | None = None,
                 short_labels: set[str] | None = None):
        self.regions = dict(regions)
        self.fail_labels = set(fail_labels or ())
        self.short_labels = set(short_labels or ())
        self.reads: list[tuple[int, int, str]] = []

    def read(self, address: int, size: int, label: str) -> bytes:
        self.reads.append((address, size, label))
        if label in self.fail_labels:
            raise OSError(f"fixture read failure: {label}")
        for start, data in self.regions.items():
            offset = address - start
            if offset >= 0 and offset + size <= len(data):
                result = data[offset:offset + size]
                if label in self.short_labels:
                    return result[:-1]
                return result
        raise OSError(f"fixture unmapped read: {label}")


def _fixture(*, base_name: bytes = b"Louis",
             dynasty_name: bytes = b"Valois",
             include_dynasty: bool = True,
             base_storage: str = "inline",
             dynasty_storage: str = "inline",
             method: int | None = None,
             country_ref: int = COUNTRY_REF,
             regency: int = 0,
             base_capacity: int | None = None,
             dynasty_capacity: int | None = None,
             base_terminator: int = 0,
             dynasty_terminator: int = 0,
             extra_regions: dict[int, bytes] | None = None,
             fail_labels: set[str] | None = None,
             short_labels: set[str] | None = None) -> FakeLimiter:
    person = bytearray(person_names.PERSON_HEADER_SIZE)
    person[:8] = PERSON_VTABLE.to_bytes(8, "little")
    person[person_names.PERSON_COUNTRY_FULLREF_OFFSET:
           person_names.PERSON_COUNTRY_FULLREF_OFFSET + 8] = country_ref.to_bytes(8, "little")
    base_header, base_payload = _string32(
        base_name, storage=base_storage, capacity=base_capacity,
        pointer=BASE_HEAP, terminator=base_terminator)
    person[person_names.PERSON_BASE_NAME_OFFSET:
           person_names.PERSON_BASE_NAME_OFFSET + 0x20] = base_header
    person[person_names.PERSON_DYNASTY_POINTER_OFFSET:
           person_names.PERSON_DYNASTY_POINTER_OFFSET + 8] = DYNASTY.to_bytes(8, "little")
    person[0x74] = 0x5A
    person[person_names.PERSON_REGENCY_POINTER_OFFSET:
           person_names.PERSON_REGENCY_POINTER_OFFSET + 8] = regency.to_bytes(8, "little")

    vtable = bytearray(0x10)
    method_address = method if method is not None else (TRUE_METHOD if include_dynasty else FALSE_METHOD)
    vtable[0x08:0x10] = method_address.to_bytes(8, "little")
    dynasty_vtable = bytearray(8)
    dynasty_vtable[:8] = DYNASTY_VTABLE.to_bytes(8, "little")
    dynasty_header, dynasty_payload = _string32(
        dynasty_name, storage=dynasty_storage, capacity=dynasty_capacity,
        pointer=DYN_HEAP, terminator=dynasty_terminator)
    regions = {
        PERSON: bytes(person),
        PERSON_VTABLE: b"\x00" * 8,
        DYNASTY: bytes(dynasty_vtable) + dynasty_header,
        DYNASTY_VTABLE: bytes(vtable),
    }
    if base_payload is not None:
        regions[BASE_HEAP] = base_payload
    if dynasty_payload is not None:
        regions[DYN_HEAP] = dynasty_payload
    regions.update(extra_regions or {})
    return FakeLimiter(regions, fail_labels=fail_labels, short_labels=short_labels)


def _read(reader: FakeLimiter, *, pointer: int = PERSON, base: int = BASE,
          expected_ref: int = COUNTRY_REF, name_layout: str = "vanilla"):
    return person_names.read_person_name(
        reader, base, pointer, expected_country_fullref=expected_ref,
        name_layout=name_layout)


def _read_dynasty(reader: FakeLimiter, *, pointer: int = PERSON, base: int = BASE,
                  expected_ref: int = COUNTRY_REF, name_layout: str = "vanilla"):
    return person_names.read_dynasty_component(
        reader, base, pointer, expected_country_fullref=expected_ref,
        name_layout=name_layout)


def test_actual_nine_byte_person_name_and_non_ascii_dynasty_are_projected_as_component():
    # Both byte sequences were observed in the FRA ruler capture; this fixture
    # checks only the leaf projection, not a live qualification claim.
    reader = _fixture(base_name=ACTUAL_FRA_PERSON_NAME,
                      dynasty_name=ACTUAL_FRA_DYNASTY_NAME)
    result = _read(reader)

    assert result["status"] == "known"
    assert result["value"] == {
        "text": "路易 XI 德 瓦卢瓦",
        "raw_hex": (ACTUAL_FRA_PERSON_NAME + b" " + ACTUAL_FRA_DYNASTY_NAME).hex(),
        "encoding": "eu4_escape",
    }
    assert result["base_name"] == {
        "text": "路易 XI",
        "raw_hex": ACTUAL_FRA_PERSON_NAME.hex(),
        "encoding": "eu4_escape",
    }
    assert result["dynasty"] == {
        "included_in_name": True,
        "name": {
            "text": "德 瓦卢瓦",
            "raw_hex": ACTUAL_FRA_DYNASTY_NAME.hex(),
            "encoding": "eu4_escape",
        },
    }
    assert result["basis"] == "projected_a4b130_normal_name_component"
    assert result["full_ui_label"] is False
    assert result["raw_inputs"]["person_country_fullref_matches_expected"] is True
    assert result["raw_inputs"]["dynasty_method_pointer"] == hex(TRUE_METHOD)


def test_false_dynasty_predicate_returns_base_without_reading_dynasty_string():
    reader = _fixture(base_name=b"Edward", dynasty_name=b"York", include_dynasty=False)
    result = _read(reader)

    assert result["status"] == "known"
    assert result["value"]["text"] == "Edward"
    assert result["dynasty"] == {"included_in_name": False, "name": None}
    assert result["raw_inputs"]["dynasty_name_read"] is False
    assert not any(label == "dynasty.String32_header" for _, _, label in reader.reads)


def test_heap_string32_for_both_components_reads_only_length_plus_terminator():
    base = b"A" * 20
    dynasty = b"B" * 19
    reader = _fixture(base_name=base, dynasty_name=dynasty,
                     base_storage="heap", dynasty_storage="heap")
    result = _read(reader)
    assert result["status"] == "known"
    assert result["value"]["text"] == base.decode() + " " + dynasty.decode()
    assert (BASE_HEAP, len(base) + 1, "person.base_name.payload") in reader.reads
    assert (DYN_HEAP, len(dynasty) + 1, "dynasty.name.payload") in reader.reads


def test_empty_string32_is_a_valid_observed_name_component():
    reader = _fixture(base_name=b"", dynasty_name=b"", include_dynasty=False)
    result = _read(reader)
    assert result["status"] == "known"
    assert result["value"] == {"text": "", "raw_hex": "", "encoding": "eu4_escape"}
    assert result["base_name"]["text"] == ""

    dynasty_reader = _fixture(base_name=b"Base", dynasty_name=b"", include_dynasty=True)
    dynasty_result = _read(dynasty_reader)
    assert dynasty_result["status"] == "known"
    assert dynasty_result["value"]["text"] == "Base "
    assert dynasty_result["value"]["raw_hex"] == b"Base ".hex()
    assert dynasty_result["dynasty"] == {
        "included_in_name": True,
        "name": {"text": "", "raw_hex": "", "encoding": "eu4_escape"},
    }


@pytest.mark.parametrize(
    ("kwargs", "reason"),
    [
        ({"method": 0x12345678}, "dynasty_method_unrecognized"),
        ({"country_ref": OTHER_COUNTRY_REF}, "person_country_fullref_mismatch"),
        ({"regency": 0x520000}, "regency_name_path_unsupported"),
        ({"base_name": b"A\x00B"}, "person.base_name_embedded_nul"),
        ({"base_name": b"\x10\x01"}, "person.base_name_decode_invalid"),
        ({"base_name": b"A", "base_terminator": ord("!")}, "person.base_name_terminator_invalid"),
    ],
)
def test_unknown_method_wrong_country_regency_and_invalid_string_fail_closed(kwargs, reason):
    reader = _fixture(**kwargs)
    result = _read(reader)
    assert result["status"] == "unknown"
    assert result["reason"] == reason
    assert "value" not in result
    assert result["raw_inputs"]
    assert result["full_ui_label"] is False


def test_nonzero_regency_is_not_followed_and_retains_raw_pointer():
    reader = _fixture(regency=0x520000)
    result = _read(reader)
    assert result["reason"] == "regency_name_path_unsupported"
    assert result["raw_inputs"]["regency_pointer"] == hex(0x520000)
    assert not any(label.startswith("regency") for _, _, label in reader.reads)


@pytest.mark.parametrize(
    ("label", "short"),
    [
        ("person.header", False),
        ("dynasty.vtable", True),
        ("dynasty.predicate", False),
        ("dynasty.String32_header", False),
        ("dynasty.name.payload", True),
    ],
)
def test_short_and_failed_reads_are_unknown_with_read_failure_evidence(label, short):
    reader = _fixture(dynasty_name=b"B" * 20, dynasty_storage="heap",
                      fail_labels=set() if short else {label},
                      short_labels={label} if short else set())
    result = _read(reader)
    assert result["status"] == "unknown"
    assert "_read_failed" in result["reason"]
    assert result["raw_inputs"]["read_failures"]
    assert result["raw_inputs"]["read_budget"]["bytes_requested"] <= 4096


def test_invalid_person_and_heap_pointers_are_unknown_without_unbounded_reads():
    invalid_person = _read(_fixture(), pointer=7)
    assert invalid_person["status"] == "unknown"
    assert invalid_person["reason"] == "person_pointer_invalid"

    reader = _fixture(base_name=b"A" * 20, base_storage="heap")
    header = bytearray(reader.regions[PERSON])
    header[person_names.PERSON_BASE_NAME_OFFSET:
           person_names.PERSON_BASE_NAME_OFFSET + 8] = (7).to_bytes(8, "little")
    reader.regions[PERSON] = bytes(header)
    invalid_heap = _read(reader)
    assert invalid_heap["status"] == "unknown"
    assert invalid_heap["reason"] == "person.base_name_heap_pointer_invalid"
    assert len(reader.reads) == 1


def test_read_budget_is_explicit_and_bounded():
    reader = _fixture()
    result = _read(reader)
    budget = result["raw_inputs"]["read_budget"]
    assert budget["calls"] == len(reader.reads)
    assert budget["bytes_requested"] == sum(size for _, size, _ in reader.reads)
    assert budget["max_single_read"] <= 257
    assert budget["calls"] <= 16
    assert budget["bytes_requested"] <= 4096


def test_dynasty_component_reads_only_owner_regency_dynasty_and_method_inputs():
    raw_dynasty = bytes.fromhex("12b7562010e67410625310e674")
    reader = _fixture(dynasty_name=raw_dynasty)
    result = _read_dynasty(reader)

    assert result["status"] == "known"
    assert result["value"] == {
        "included_in_name": True,
        "name": {
            "text": "德 瓦卢瓦",
            "raw_hex": raw_dynasty.hex(),
            "encoding": "eu4_escape",
        },
    }
    assert result["full_ui_label"] is False
    assert result["raw_inputs"]["person_country_fullref_matches_expected"] is True
    assert result["raw_inputs"]["dynasty_method_pointer"] == hex(TRUE_METHOD)
    assert not any(
        address < PERSON + 0x48 and address + size > PERSON + 0x28
        for address, size, _ in reader.reads
    )
    assert not any(label.startswith("person.base_name") for _, _, label in reader.reads)


def test_firstname_age_and_claim_changes_do_not_change_dynasty_component():
    raw_dynasty = bytes.fromhex("12b7562010e67410625310e674")
    first = _fixture(base_name=b"valid", dynasty_name=raw_dynasty,
                     extra_regions={PERSON + 0x148: b"\x01\x00\x00\x00"})
    second = _fixture(base_name=b"valid", dynasty_name=raw_dynasty,
                      extra_regions={PERSON + 0x148: b"\xff\xff\xff\x7f"})
    altered = bytearray(second.regions[PERSON])
    altered[0x28:0x48] = bytes.fromhex("1001" + "00" * 30)  # malformed/empty name bytes
    altered[0x74] = 0xE7  # independent raw age-like byte
    second.regions[PERSON] = bytes(altered)

    first_result = _read_dynasty(first)
    second_result = _read_dynasty(second)
    assert first_result == second_result
    assert first_result["status"] == "known"
    assert not any(address == PERSON + 0x148 for address, _, _ in second.reads)
    assert not any(address == PERSON + 0x74 for address, _, _ in second.reads)


def test_false_dynasty_component_does_not_read_string_and_reports_no_name():
    reader = _fixture(base_name=b"must not be read", dynasty_name=b"also not read",
                      include_dynasty=False)
    result = _read_dynasty(reader)
    assert result["status"] == "known"
    assert result["value"] == {"included_in_name": False, "name": None}
    assert result["raw_inputs"]["dynasty_string32_read"] is False
    assert not any(label == "dynasty.String32_header" for _, _, label in reader.reads)


def test_dynasty_only_heap_name_reads_exact_length_and_nul():
    value = b"a dynasty name longer than sso"
    reader = _fixture(dynasty_name=value, dynasty_storage="heap")
    result = _read_dynasty(reader)
    assert result["status"] == "known"
    assert result["value"]["name"]["text"] == value.decode("ascii")
    assert (DYNASTY + 0x08, 0x20, "dynasty.String32_header") in reader.reads
    assert (DYN_HEAP, len(value) + 1, "dynasty.name.payload") in reader.reads
    assert not any(label.startswith("person.base_name") for _, _, label in reader.reads)


@pytest.mark.parametrize(
    ("kwargs", "reason"),
    [
        ({"country_ref": OTHER_COUNTRY_REF}, "person_country_fullref_mismatch"),
        ({"method": 0x12345678}, "dynasty_method_unrecognized"),
        ({"regency": 0x520000}, "regency_name_path_unsupported"),
        ({"dynasty_name": b"A\x00B"}, "dynasty.name_embedded_nul"),
        ({"dynasty_name": b"\x10\x01"}, "dynasty.name_decode_invalid"),
    ],
)
def test_dynasty_only_invalid_binding_method_regency_or_text_is_unknown(kwargs, reason):
    reader = _fixture(**kwargs)
    result = _read_dynasty(reader)
    assert result["status"] == "unknown"
    assert result["reason"] == reason
    assert "value" not in result
    assert result["raw_inputs"]


def test_dynasty_only_unknown_method_and_regency_do_not_read_dynasty_string():
    wrong_method = _read_dynasty(_fixture(method=BASE + 0x123456))
    assert wrong_method["reason"] == "dynasty_method_unrecognized"
    assert not any(row["label"] == "dynasty.String32_header"
                   for row in wrong_method["raw_inputs"]["read_trace"])

    active_regency = _read_dynasty(_fixture(regency=0x520000))
    assert active_regency["reason"] == "regency_name_path_unsupported"
    assert not any(row["label"] == "person.dynasty_pointer"
                   for row in active_regency["raw_inputs"]["read_trace"])


@pytest.mark.parametrize(
    ("label", "short"),
    [
        ("person.country_fullref", False),
        ("person.regency_pointer", True),
        ("person.dynasty_pointer", False),
        ("dynasty.vtable", True),
        ("dynasty.predicate", False),
        ("dynasty.String32_header", True),
        ("dynasty.name.payload", False),
    ],
)
def test_dynasty_only_short_or_failed_read_is_unknown(label, short):
    reader = _fixture(dynasty_name=b"a dynasty name longer than sso",
                      dynasty_storage="heap",
                      fail_labels=set() if short else {label},
                      short_labels={label} if short else set())
    result = _read_dynasty(reader)
    assert result["status"] == "unknown"
    assert "_read_failed" in result["reason"]
    assert result["raw_inputs"]["read_failures"][-1]["label"] == label


def test_plugin64_bf_a_marker_reorders_dynasty_suffix_before_base_without_space():
    reader = _fixture(base_name=b"Louis", dynasty_name=b"\xbfA")
    result = _read(reader, name_layout="plugin64")

    assert result["status"] == "known"
    assert result["value"] == {
        "text": "ALouis", "raw_hex": b"ALouis".hex(), "encoding": "eu4_escape"}
    assert result["dynasty"] == {
        "included_in_name": True,
        "name": {"text": "A", "raw_hex": b"A".hex(), "encoding": "eu4_escape"},
    }
    raw = result["raw_inputs"]
    assert raw["name_layout"] == "plugin64"
    assert raw["plugin64_callback_right_raw_hex"] == b" \xbfA".hex()
    assert raw["plugin64_callback_right_length"] == 3
    assert raw["plugin64_marker_byte"] == "0xbf"
    assert raw["plugin64_marker_selected"] is True
    assert raw["plugin64_callback_path"] == "dynasty_suffix_then_base"
    assert raw["plugin64_dynasty_cached_raw_hex"] == b"\xbfA".hex()
    assert raw["plugin64_projected_dynasty_raw_hex"] == b"A".hex()
    assert result["basis"] == person_names.PLUGIN64_BASIS


def test_plugin64_single_bf_does_not_select_marker_and_vanilla_keeps_literal_byte():
    plugin_reader = _fixture(base_name=b"Base", dynasty_name=b"\xbf")
    plugin = _read(plugin_reader, name_layout="plugin64")
    assert plugin["status"] == "known"
    assert plugin["value"]["raw_hex"] == b"Base \xbf".hex()
    assert plugin["value"]["text"] == "Base \u00bf"
    assert plugin["raw_inputs"]["plugin64_callback_right_length"] == 2
    assert plugin["raw_inputs"]["plugin64_marker_byte"] == "0xbf"
    assert plugin["raw_inputs"]["plugin64_marker_selected"] is False
    assert plugin["raw_inputs"]["plugin64_callback_path"] == "base_then_space_dynasty"

    vanilla_reader = _fixture(base_name=b"Base", dynasty_name=b"\xbfA")
    vanilla = _read(vanilla_reader)
    assert vanilla["status"] == "known"
    assert vanilla["value"]["raw_hex"] == b"Base \xbfA".hex()
    assert vanilla["value"]["text"] == "Base \u00bfA"
    assert vanilla["dynasty"]["name"]["raw_hex"] == b"\xbfA".hex()
    assert "name_layout" not in vanilla["raw_inputs"]


def test_plugin64_marker_with_observed_eu4escape_dynasty_keeps_private_cached_bytes():
    cached = b"\xbf" + ACTUAL_FRA_DYNASTY_NAME
    result = _read(_fixture(base_name=ACTUAL_FRA_PERSON_NAME,
                            dynasty_name=cached), name_layout="plugin64")

    expected_raw = ACTUAL_FRA_DYNASTY_NAME + ACTUAL_FRA_PERSON_NAME
    assert result["status"] == "known"
    assert result["value"] == {
        "text": "德 瓦卢瓦路易 XI", "raw_hex": expected_raw.hex(),
        "encoding": "eu4_escape"}
    assert result["dynasty"]["name"] == {
        "text": "德 瓦卢瓦", "raw_hex": ACTUAL_FRA_DYNASTY_NAME.hex(),
        "encoding": "eu4_escape"}
    assert result["raw_inputs"]["plugin64_dynasty_cached_raw_hex"] == cached.hex()
    assert result["raw_inputs"]["plugin64_projected_dynasty_raw_hex"] == ACTUAL_FRA_DYNASTY_NAME.hex()


def test_plugin64_empty_and_heap_string32_components_remain_exact():
    empty = _read(_fixture(base_name=b"", dynasty_name=b"", include_dynasty=False),
                  name_layout="plugin64")
    assert empty["status"] == "known"
    assert empty["value"] == {"text": "", "raw_hex": "", "encoding": "eu4_escape"}

    reader = _fixture(base_name=b"A" * 20, dynasty_name=b"B" * 19,
                      base_storage="heap", dynasty_storage="heap")
    heap = _read(reader, name_layout="plugin64")
    assert heap["status"] == "known"
    assert heap["value"]["text"] == "A" * 20 + " " + "B" * 19
    assert (BASE_HEAP, 21, "person.base_name.payload") in reader.reads
    assert (DYN_HEAP, 20, "dynasty.name.payload") in reader.reads


@pytest.mark.parametrize("dynasty", [b"Valois", b"York", b"Tudor", ACTUAL_FRA_DYNASTY_NAME])
def test_plugin64_nonmarker_names_keep_base_space_dynasty_order(dynasty):
    result = _read(_fixture(base_name=b"Base", dynasty_name=dynasty),
                   name_layout="plugin64")
    assert result["status"] == "known"
    assert result["value"]["raw_hex"] == (b"Base " + dynasty).hex()
    assert result["raw_inputs"]["plugin64_marker_selected"] is False
    assert result["raw_inputs"]["plugin64_callback_path"] == "base_then_space_dynasty"


def test_plugin64_dynasty_component_strips_marker_but_preserves_original_private_raw():
    cached = b"\xbf" + ACTUAL_FRA_DYNASTY_NAME
    reader = _fixture(dynasty_name=cached)
    result = _read_dynasty(reader, name_layout="plugin64")
    assert result["status"] == "known"
    assert result["value"] == {
        "included_in_name": True,
        "name": {"text": "德 瓦卢瓦", "raw_hex": ACTUAL_FRA_DYNASTY_NAME.hex(),
                 "encoding": "eu4_escape"},
    }
    assert result["raw_inputs"]["dynasty_string32"]["value_raw_hex"] == cached.hex()
    assert result["raw_inputs"]["plugin64_callback_right_raw_hex"] == (b" " + cached).hex()
    assert result["raw_inputs"]["plugin64_marker_selected"] is True
    assert not any(label.startswith("person.base_name") for _, _, label in reader.reads)


def test_plugin64_false_dynasty_predicate_returns_none_without_marker_or_string_read():
    reader = _fixture(base_name=b"Base", dynasty_name=b"\xbfA", include_dynasty=False)
    result = _read_dynasty(reader, name_layout="plugin64")
    assert result["status"] == "known"
    assert result["value"] == {"included_in_name": False, "name": None}
    assert result["raw_inputs"]["plugin64_callback_right_raw_hex"] is None
    assert result["raw_inputs"]["plugin64_callback_path"] == "dynasty_not_appended"
    assert not any(label == "dynasty.String32_header" for _, _, label in reader.reads)


@pytest.mark.parametrize("name_layout", [None, "auto", [], "Plugin64"])
def test_unsupported_name_layout_is_unknown_without_exposing_name_components(name_layout):
    for read in (_read, _read_dynasty):
        reader = _fixture()
        result = read(reader, name_layout=name_layout)
        assert result["status"] == "unknown"
        assert result["reason"] == "name_layout_unsupported"
        assert "value" not in result
        assert "base_name" not in result
        assert "dynasty" not in result
        assert reader.reads == []


def test_plugin64_output_limit_accepts_254_bytes_and_rejects_255():
    boundary = _read(_fixture(base_name=b"B" * 127, dynasty_name=b"D" * 126,
                              base_storage="heap", dynasty_storage="heap"),
                     name_layout="plugin64")
    assert boundary["status"] == "known"
    assert len(bytes.fromhex(boundary["value"]["raw_hex"])) == 254
    assert boundary["raw_inputs"]["plugin64_output_max_bytes"] == 254

    too_long = _read(_fixture(base_name=b"B" * 127, dynasty_name=b"D" * 127,
                              base_storage="heap", dynasty_storage="heap"),
                     name_layout="plugin64")
    assert too_long["status"] == "unknown"
    assert too_long["reason"] == "NATIVE_PLUGIN_NAME_SIZE_UNSUPPORTED"
    assert "value" not in too_long
    assert too_long["raw_inputs"]["plugin64_output_length"] == 255


def test_plugin64_dynasty_component_uses_same_254_byte_limit():
    boundary = _read_dynasty(_fixture(dynasty_name=b"D" * 254,
                                     dynasty_storage="heap"), name_layout="plugin64")
    assert boundary["status"] == "known"
    assert len(bytes.fromhex(boundary["value"]["name"]["raw_hex"])) == 254

    too_long = _read_dynasty(_fixture(dynasty_name=b"D" * 255,
                                     dynasty_storage="heap"), name_layout="plugin64")
    assert too_long["status"] == "unknown"
    assert too_long["reason"] == "NATIVE_PLUGIN_NAME_SIZE_UNSUPPORTED"
    assert "value" not in too_long
