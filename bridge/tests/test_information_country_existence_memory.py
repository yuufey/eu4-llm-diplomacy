"""The private country-existence leaf matches its bounded native predicate."""
import pytest

from bridge.information import country_existence_memory as memory


BASE = 0x140000000
TARGET_PTR = 0x400001000


def make_fullref(tag, slot, *, high=1, kind=0):
    return ((high & 0xFF) << 56) | ((kind & 0xFF) << 48) | (slot << 32) | int.from_bytes(
        tag.encode("ascii"), "little")


def binding(tag="ENG", slot=19, pointer=TARGET_PTR, *, kind=0):
    fullref = make_fullref(tag, slot, kind=kind)
    return {"tag": tag, "slot": slot, "country_pointer": hex(pointer),
            "fullref": hex(fullref),
            "fullref_raw_hex": fullref.to_bytes(8, "little").hex()}


class MemoryImage:
    def __init__(self):
        self.bytes = {}
        self.reads = []
        self.writes = []
        self.short_addresses = set()
        self.fail_addresses = set()

    def put(self, address, data):
        for offset, byte in enumerate(bytes(data)):
            self.bytes[address + offset] = byte

    def put_u8(self, address, value):
        self.put(address, int(value).to_bytes(1, "little"))

    def put_u32(self, address, value):
        self.put(address, int(value).to_bytes(4, "little", signed=False))

    def write(self, address, data, label):
        self.writes.append((address, bytes(data), label))

    def read(self, address, size, label):
        self.reads.append((address, size, label))
        if address in self.fail_addresses:
            raise OSError("injected read failure")
        if address in self.short_addresses:
            return bytes(max(0, size - 1))
        try:
            return bytes(self.bytes[address + offset] for offset in range(size))
        except KeyError as exc:
            raise KeyError(f"unmapped:{address:#x}:{size}:{label}") from exc


def configured_image(*, dword=0, bound_kind=0, memory_kind=None):
    image = MemoryImage()
    target = binding(kind=bound_kind)
    if memory_kind is None:
        memory_kind = bound_kind
    image.put_u32(TARGET_PTR + memory.EXISTENCE_DWORD_OFFSET, dword)
    image.put_u8(TARGET_PTR + memory.COUNTRY_KIND_OFFSET, memory_kind)
    return image, target


def read(image, target, module_base=BASE):
    return memory.read_existence(image, module_base, target)


@pytest.mark.parametrize("dword", [1, 0xFFFFFFFF])
def test_every_nonzero_raw_dword_is_true_and_short_circuits_kind_read(dword):
    image, target = configured_image(dword=dword, bound_kind=2, memory_kind=7)
    result = read(image, target)

    assert result["schema"] == memory.SCHEMA
    assert result["status"] == "known" and result["value"] is True
    assert result["raw_inputs"]["existence_dword_raw_hex"] == dword.to_bytes(4, "little").hex()
    assert result["raw_inputs"]["existence_dword_u32"] == dword
    assert result["raw_inputs"]["kind_check"] == {"status": "not_read", "reason": "NONZERO_DWORD"}
    assert [label for _, _, label in image.reads] == ["country_existence.dword_u32"]
    assert result["read_budget"]["calls"] == 1
    assert result["read_budget"]["bytes_requested"] == 4
    assert result["read_budget"]["limits"] == {"calls": 2, "bytes": 5,
                                                  "single_read_bytes": 4}
    assert image.writes == []


def test_zero_dword_with_matching_ordinary_kind_is_known_false():
    image, target = configured_image(dword=0, bound_kind=2)
    result = read(image, target)

    assert result["status"] == "known" and result["value"] is False
    assert result["raw_inputs"]["existence_dword_u32"] == 0
    assert result["raw_inputs"]["kind_check"]["matches_fullref"] is True
    assert result["raw_inputs"]["kind_check"]["country_kind_u8"] == 2
    assert [label for _, _, label in image.reads] == [
        "country_existence.dword_u32", "country_existence.kind_u8"]
    assert result["read_budget"]["calls"] == 2
    assert result["read_budget"]["bytes_requested"] == 5
    assert image.writes == []


def test_zero_dword_kind_7_mismatch_is_unknown_instead_of_false_or_true():
    image, target = configured_image(dword=0, bound_kind=2, memory_kind=7)
    result = read(image, target)

    assert result["status"] == "unknown"
    assert "value" not in result
    assert result["reason"] == "COUNTRY_KIND_FULLREF_MISMATCH"
    assert result["raw_inputs"]["kind_check"]["country_kind_u8"] == 7
    assert result["raw_inputs"]["kind_check"]["bound_fullref_kind_u8"] == 2
    assert len(result["raw_inputs"]["ordered_read_trace"]) == 2
    assert image.writes == []


@pytest.mark.parametrize(
    "failure_kind,expected_reason,failed_address",
    [
        ("raise_dword", "READ_FAILED:country_existence.dword_u32",
         TARGET_PTR + memory.EXISTENCE_DWORD_OFFSET),
        ("short_kind", "READ_SHORT_OR_INVALID:country_existence.kind_u8",
         TARGET_PTR + memory.COUNTRY_KIND_OFFSET),
    ],
)
def test_read_failures_are_unknown_and_never_emit_false(failure_kind, expected_reason,
                                                        failed_address):
    image, target = configured_image(dword=0)
    if failure_kind == "raise_dword":
        image.fail_addresses.add(failed_address)
    else:
        image.short_addresses.add(failed_address)

    result = read(image, target)

    assert result["status"] == "unknown" and "value" not in result
    assert result["reason"] == expected_reason
    assert result["raw_inputs"]["ordered_read_trace"][-1]["status"] == "failed"
    assert image.writes == []


def test_target_role_accepts_non_fra_tag_and_copies_binding_inputs_for_digest():
    image = MemoryImage()
    target = binding(tag="SWE", slot=31)
    image.put_u32(TARGET_PTR + memory.EXISTENCE_DWORD_OFFSET, 5)
    original = dict(target)

    result = read(image, target)
    target["tag"] = "POR"
    target["fullref_raw_hex"] = "00" * 8

    assert result["status"] == "known" and result["value"] is True
    assert result["raw_inputs"]["target_binding"]["tag"] == "SWE"
    assert result["raw_inputs"]["target_binding"]["fullref_raw_hex"] == original[
        "fullref_raw_hex"]
    assert result["raw_inputs"]["ordered_read_trace"] == [
        {"address": hex(TARGET_PTR + memory.EXISTENCE_DWORD_OFFSET), "size": 4,
         "label": "country_existence.dword_u32", "status": "ok", "raw_hex": "05000000"}]


def test_invalid_module_binding_or_reader_fails_before_memory_reads():
    image, target = configured_image(dword=1)
    invalid_target = dict(target, tag="POR")

    assert read(image, target, module_base=True)["reason"] == "MODULE_BASE_INVALID"
    assert read(image, invalid_target)["reason"] == "TARGET_FULLREF_TAG_MISMATCH"
    assert memory.read_existence(object(), BASE, target)["reason"] == "READER_INVALID"
    assert image.reads == []
    assert image.writes == []
