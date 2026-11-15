"""FRA's private country-knowledge predicate stays bounded to one capital."""
import pytest

from bridge.information import country_knowledge_memory as memory
from bridge.information import province_discovery_bitmap_memory as bitmap
from bridge.information import province_reference_memory as province


BASE = 0x140000000
RECORDS = 0x300000000
OBSERVER_PTR = 0x400000000
TARGET_PTR = 0x400001000
PROVINCE_COUNT = 5


def make_fullref(tag, slot, *, high=1, kind=0):
    return ((high & 0xFF) << 56) | ((kind & 0xFF) << 48) | (slot << 32) | int.from_bytes(tag.encode("ascii"), "little")


def binding(tag, slot, pointer, *, fullref=None, raw_hex=None):
    if fullref is None:
        fullref = make_fullref(tag, slot)
    raw = int(fullref).to_bytes(8, "little")
    return {"tag": tag, "slot": slot, "country_pointer": hex(pointer),
            "fullref": hex(fullref), "fullref_raw_hex": raw.hex() if raw_hex is None else raw_hex}


def header(*, records=RECORDS, count=PROVINCE_COUNT, records_range=None):
    if records_range is None:
        records_range = [hex(records), hex(records + count * province.RECORD_STRIDE)]
    return {"records_pointer": hex(records), "count": count, "records_range": records_range}


class MemoryImage:
    def __init__(self):
        self.bytes = {}
        self.reads = []
        self.short_addresses = set()

    def put(self, address, data):
        for offset, byte in enumerate(bytes(data)):
            self.bytes[address + offset] = byte

    def put_u8(self, address, value):
        self.put(address, int(value).to_bytes(1, "little"))

    def put_u32(self, address, value, *, signed=False):
        self.put(address, int(value).to_bytes(4, "little", signed=signed))

    def put_u64(self, address, value):
        self.put(address, int(value).to_bytes(8, "little"))

    def read(self, address, size, label):
        self.reads.append((address, size, label))
        if address in self.short_addresses:
            return bytes(max(0, size - 1))
        try:
            return bytes(self.bytes[address + offset] for offset in range(size))
        except KeyError as exc:
            raise KeyError(f"unmapped:{address:#x}:{size}:{label}") from exc


def configured_image(*, observer_slot=5, target_tag="ENG", target_slot=19,
                     capital_index=2, flags=0, bitmap_word=None, bitmap_length=1,
                     bitmap_capacity=1, bitmap_pointer=None):
    image = MemoryImage()
    target = binding(target_tag, target_slot, TARGET_PTR)
    observer = binding("FRA", observer_slot, OBSERVER_PTR)
    capital = RECORDS + capital_index * province.RECORD_STRIDE
    image.put_u64(TARGET_PTR + memory.TARGET_CAPITAL_OFFSET, capital)
    image.put_u32(capital + memory.CAPITAL_RECORD_ID_OFFSET, capital_index, signed=True)
    image.put_u8(capital + memory.CAPITAL_KNOWLEDGE_FLAGS_OFFSET, flags)
    if bitmap_word is not None:
        if bitmap_pointer is None:
            bitmap_pointer = capital + bitmap.INLINE_OFFSET
        raw_header = (int(BASE + bitmap.BITMAP_VTABLE_RVA).to_bytes(8, "little")
                      + int(bitmap_pointer).to_bytes(8, "little")
                      + int(bitmap_capacity).to_bytes(4, "little", signed=True)
                      + int(bitmap_length).to_bytes(4, "little", signed=True))
        image.put(capital + bitmap.BITMAP_OFFSET, raw_header)
        image.put_u32(bitmap_pointer + (observer_slot >> 5) * 4, bitmap_word)
    return image, observer, target, capital


def read(image, observer, target, province_header=None):
    return memory.read_knowledge(image, BASE, observer, target,
                                 header() if province_header is None else province_header)


def test_clear_capital_knowledge_flag_is_true_shortcut_without_bitmap_reads():
    image, observer, target, _ = configured_image(flags=0, bitmap_word=None)
    result = read(image, observer, target)
    assert result["status"] == "known" and result["value"] is True
    assert result["raw_inputs"]["bitmap"] == {"status": "not_read", "reason": "CAPITAL_SHORTCUT"}
    assert [label for _, _, label in image.reads] == [
        "country_knowledge.target.capital_pointer",
        "country_knowledge.capital.record_id",
        "country_knowledge.capital.flags",
    ]


def test_marked_capital_flag_uses_observer_bitmap_bit_and_keeps_target_distinct():
    image, observer, target, capital = configured_image(flags=memory.CAPITAL_KNOWLEDGE_BIT,
                                                        bitmap_word=1 << 5)
    result = read(image, observer, target)
    assert result["status"] == "known" and result["value"] is True
    assert target["tag"] == "ENG" and observer["tag"] == "FRA"
    assert image.reads[-2][2] == "province_bitmap.header"
    assert image.reads[-1][2] == "province_bitmap.word_u32"
    assert image.reads[-1][0] == capital + bitmap.INLINE_OFFSET


def test_bitmap_clear_bit_is_known_false_not_unknown():
    image, observer, target, _ = configured_image(flags=0x10, bitmap_word=0)
    result = read(image, observer, target)
    assert result["status"] == "known" and result["value"] is False
    assert result["raw_inputs"]["bitmap"]["word_raw_hex"] == "00000000"


def test_missing_bitmap_is_unknown_and_does_not_become_false():
    image, observer, target, _ = configured_image(flags=0x10, bitmap_word=None)
    result = read(image, observer, target)
    assert result["status"] == "unknown" and "value" not in result
    assert result["reason"] == "READ_FAILED:province_bitmap.header"


def test_observer_slot_outside_native_bitmap_length_is_unknown():
    image, observer, target, _ = configured_image(observer_slot=32, flags=0x10,
                                                   bitmap_word=0, bitmap_length=1,
                                                   bitmap_capacity=1)
    result = read(image, observer, target)
    assert result["status"] == "unknown" and "value" not in result
    assert result["reason"] == "OBSERVER_OUTSIDE_BITMAP_LENGTH"
    assert not any(label == "province_bitmap.word_u32" for _, _, label in image.reads)


def test_indexed_capital_id_zero_is_validated_without_assigning_zero_semantics():
    image, observer, target, capital = configured_image(capital_index=0, flags=0)
    result = read(image, observer, target)
    assert result["status"] == "known" and result["value"] is True
    assert result["raw_inputs"]["capital_record_index"] == 0
    assert result["raw_inputs"]["capital_record_id_i32"] == 0


@pytest.mark.parametrize("capital", [RECORDS - province.RECORD_STRIDE, RECORDS + 8,
                                      RECORDS + PROVINCE_COUNT * province.RECORD_STRIDE])
def test_nonindexed_capital_pointer_is_unknown_before_record_reads(capital):
    image, observer, target, _ = configured_image(flags=0)
    image.put_u64(TARGET_PTR + memory.TARGET_CAPITAL_OFFSET, capital)
    result = read(image, observer, target)
    assert result["status"] == "unknown" and "value" not in result
    assert result["reason"] in {"TARGET_CAPITAL_NOT_INDEXED_RECORD_START",
                                "TARGET_CAPITAL_OUTSIDE_PROVINCE_INDEX",
                                "TARGET_CAPITAL_POINTER_INVALID"}
    assert len(image.reads) == 1


def test_capital_record_id_mismatch_is_unknown_before_flags_or_bitmap():
    image, observer, target, capital = configured_image(flags=0x10, bitmap_word=1)
    image.put_u32(capital + memory.CAPITAL_RECORD_ID_OFFSET, 3, signed=True)
    result = read(image, observer, target)
    assert result["status"] == "unknown" and result["reason"] == "TARGET_CAPITAL_RECORD_ID_MISMATCH"
    assert [label for _, _, label in image.reads] == [
        "country_knowledge.target.capital_pointer", "country_knowledge.capital.record_id"]


def test_short_direct_flag_read_is_unknown_without_value():
    image, observer, target, capital = configured_image(flags=0)
    image.short_addresses.add(capital + memory.CAPITAL_KNOWLEDGE_FLAGS_OFFSET)
    result = read(image, observer, target)
    assert result["status"] == "unknown" and "value" not in result
    assert result["reason"] == "READ_SHORT_OR_INVALID:country_knowledge.capital.flags"


@pytest.mark.parametrize(
    "role,mutator,reason",
    [
        ("observer", lambda b: b.update(tag="ENG"), "OBSERVER_MUST_BE_FRA"),
        ("observer", lambda b: b.update(slot=True), "OBSERVER_SLOT_INVALID"),
        ("observer", lambda b: b.update(fullref=hex(make_fullref("FRA", 5, high=0)),
                                          fullref_raw_hex=make_fullref("FRA", 5, high=0).to_bytes(8, "little").hex()),
         "OBSERVER_FULLREF_HIGH_BYTE_ZERO"),
        ("observer", lambda b: b.update(fullref=hex(make_fullref("FRA", 5, kind=7)),
                                          fullref_raw_hex=make_fullref("FRA", 5, kind=7).to_bytes(8, "little").hex()),
         "OBSERVER_FULLREF_KIND_UNSUPPORTED"),
        ("observer", lambda b: b.update(fullref=hex(make_fullref("FRA", 6)),
                                          fullref_raw_hex=make_fullref("FRA", 6).to_bytes(8, "little").hex()),
         "OBSERVER_FULLREF_SLOT_MISMATCH"),
        ("observer", lambda b: b.update(fullref_raw_hex="00" * 8), "OBSERVER_FULLREF_RAW_MISMATCH"),
        ("target", lambda b: b.update(fullref=hex(make_fullref("POR", 19)),
                                        fullref_raw_hex=make_fullref("POR", 19).to_bytes(8, "little").hex()),
         "TARGET_FULLREF_TAG_MISMATCH"),
    ],
)
def test_invalid_country_fullref_bindings_fail_before_any_memory_read(role, mutator, reason):
    image, observer, target, _ = configured_image(flags=0)
    selected = observer if role == "observer" else target
    mutator(selected)
    result = read(image, observer, target)
    assert result["status"] == "unknown" and result["reason"] == reason
    assert "value" not in result and image.reads == []


@pytest.mark.parametrize("bad_header", [
    {"records_pointer": hex(RECORDS), "count": True,
     "records_range": [hex(RECORDS), hex(RECORDS + PROVINCE_COUNT * province.RECORD_STRIDE)]},
    {"records_pointer": hex(RECORDS), "count": PROVINCE_COUNT,
     "records_range": [hex(RECORDS), hex(RECORDS + 4 * province.RECORD_STRIDE)]},
])
def test_invalid_province_header_fails_closed(bad_header):
    image, observer, target, _ = configured_image(flags=0)
    result = read(image, observer, target, bad_header)
    assert result["status"] == "unknown" and "value" not in result
    assert result["reason"] in {"PROVINCE_COUNT_INVALID", "PROVINCE_RECORDS_RANGE_MISMATCH"}
    assert image.reads == []


def test_bitmap_header_type_or_pointer_failure_never_returns_false():
    image, observer, target, capital = configured_image(flags=0x10, bitmap_word=1)
    # Replace only the expected vtable with a wrong pointer while preserving an
    # otherwise valid inline bitmap header.
    image.put_u64(capital + bitmap.BITMAP_OFFSET, BASE + bitmap.BITMAP_VTABLE_RVA + 8)
    result = read(image, observer, target)
    assert result["status"] == "unknown" and "value" not in result
    assert result["reason"] == "BITMAP_TYPE_MISMATCH"
    assert not any(label == "province_bitmap.word_u32" for _, _, label in image.reads)


def test_result_contains_private_raw_trace_but_only_boolean_value():
    image, observer, target, _ = configured_image(flags=0)
    result = read(image, observer, target)
    assert set(result).issuperset({"schema", "status", "value", "basis", "raw_inputs", "read_budget"})
    assert result["value"] is True and type(result["value"]) is bool
    trace = result["raw_inputs"]["ordered_read_trace"]
    assert [(int(row["address"], 16), row["size"], row["label"])
            for row in trace] == image.reads
    assert all(row["raw_hex"] == bytes(image.bytes[address + offset]
                                      for offset in range(size)).hex()
               for row, (address, size, _) in zip(trace, image.reads))
    assert result["read_budget"]["calls"] == 3
    assert "owner" not in result["raw_inputs"] and "controller" not in result["raw_inputs"]
