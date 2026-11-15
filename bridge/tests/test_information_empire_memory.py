from __future__ import annotations

import struct

import pytest

from bridge.information import country_reference_memory as countries
from bridge.information import empire_memory as memory


BASE = 0x140000000
WORLD = 0x50000000
DATABASE = 0x51000000
TABLE = 0x51001000
CONTROLLERS = 0x52000000
COUNTRY_BASE = 0x53000000
NODE1 = 0x60000000
NODE2 = 0x60000100


def _ref(slot: int, tag: str) -> int:
    return (slot << 32) | int.from_bytes(tag.encode("ascii"), "little")


class MemoryImage:
    def __init__(self):
        self.data: dict[int, int] = {}
        self.read_log = []

    def put(self, address: int, raw: bytes):
        for offset, value in enumerate(raw):
            self.data[address + offset] = value

    def read(self, address: int, size: int, label: str) -> bytes:
        try:
            raw = bytes(self.data[address + offset] for offset in range(size))
        except KeyError as exc:
            self.read_log.append({"address": hex(address), "size": size, "label": label,
                                  "status": "failed", "error_type": "missing_byte"})
            raise OSError("unmapped fake address") from exc
        self.read_log.append({"address": hex(address), "size": size, "label": label,
                              "status": "observed", "raw_hex": raw.hex()})
        return raw


def _u32(value: int, *, signed=False):
    return int(value).to_bytes(4, "little", signed=signed)


def _u64(value: int):
    return int(value).to_bytes(8, "little", signed=False)


def make_image(electors=("BOH", "BRA")) -> MemoryImage:
    image = MemoryImage()
    slots = [(1, "FRA"), (2, "POR"), (3, "HAB"), (4, "BOH"), (5, "BRA")]
    pointers = {tag: COUNTRY_BASE + slot * 0x100 for slot, tag in slots}
    refs = {tag: _ref(slot, tag) for slot, tag in slots}

    image.put(BASE + countries.DATABASE_GLOBAL_RVA, _u64(DATABASE))
    image.put(DATABASE + countries.DATABASE_TABLE_OFFSET, _u64(TABLE))
    image.put(DATABASE + countries.DATABASE_TABLE_COUNT_OFFSET, _u32(6, signed=True))
    image.put(TABLE, _u64(0))
    for slot, tag in slots:
        image.put(TABLE + slot * 8, _u64(pointers[tag]))
        image.put(pointers[tag] + countries.COUNTRY_FULLREF_OFFSET, _u64(refs[tag]))

    image.put(BASE + memory.WORLD_GLOBAL_RVA, _u64(WORLD))
    image.put(WORLD, _u64(BASE + memory.WORLD_VTABLE_RVA))
    image.put(WORLD + 0x1DD0, _u32(56556984, signed=True))
    image.put(WORLD + 0x1E66, b"\x00")
    image.put(WORLD + 0x1E6F, b"\x00")
    image.put(WORLD + 0x1E60, _u64(refs["POR"]))
    image.put(WORLD + 0xA60, _u32(1, signed=True))
    image.put(WORLD + 0x1D48, _u64(CONTROLLERS))
    for slot in range(6):
        image.put(CONTROLLERS + slot * 4, _u32(0 if slot == 1 else 1, signed=True))

    hre = WORLD + memory.HRE_OFFSET
    image.put(hre, _u64(BASE + memory.HRE_VTABLE_RVA))
    image.put(hre + 0x10, _u64(refs["HAB"]))
    header = bytearray(24)
    header[0:8] = _u64(NODE1 if electors else 0)
    header[8:16] = bytes.fromhex("aabbccddeeff0011")
    header[16:20] = _u32(len(electors))
    header[20:24] = bytes.fromhex("deadbeef")
    image.put(hre + 0x80, bytes(header))
    for index, tag in enumerate(electors):
        node = NODE1 if index == 0 else NODE2 + (index - 1) * 0x100
        following = (NODE2 if index == 0 else
                     (NODE2 + index * 0x100 if index + 1 < len(electors) else 0))
        image.put(node, _u64(refs[tag]))
        image.put(node + 8, bytes.fromhex("1122334455667788"))
        image.put(node + 0x10, _u64(following))
    return image


def _read(image):
    return memory.read_state(image, BASE)


def test_reads_only_bound_emperor_elector_references_and_terminates_chain():
    image = make_image()
    result = _read(image)

    assert result["status"] == "known"
    assert result["emperor"]["tag"] == "HAB"
    assert [row["tag"] for row in result["electors"]] == ["BOH", "BRA"]
    assert result["elector_container"]["count"] == 2
    assert result["observer_nonplayer"]["verified"] is True
    assert result["physical_client"]["tag"] == "POR"
    assert result["atomic_snapshot"] is False
    assert result["publication_admitted"] is False
    hre = WORLD + memory.HRE_OFFSET
    forbidden = {hre + 0x18, hre + 0x500, NODE1 + 8, NODE2 + 8}
    assert all(int(row["address"], 16) not in forbidden for row in image.read_log)


def test_empty_elector_container_is_known_only_when_head_is_null():
    image = make_image(electors=())
    result = _read(image)
    assert result["elector_container"]["count"] == 0
    assert result["electors"] == []

    image.put(WORLD + memory.HRE_OFFSET + 0x80, _u64(NODE1) + bytes(16))
    with pytest.raises(ValueError, match="HEAD_COUNT_MISMATCH"):
        _read(image)


def test_date_and_physical_player_are_bound_dynamically():
    image = make_image()
    image.put(WORLD + 0x1DD0, _u32(400, signed=True))
    image.put(WORLD + 0x1E60, _u64(_ref(3, "HAB")))
    result = _read(image)
    assert result["context_before"]["game_date"] == 400
    assert result["physical_client"]["tag"] == "HAB"


@pytest.mark.parametrize(
    ("address", "raw", "reason"),
    [
        (WORLD, _u64(BASE + memory.WORLD_VTABLE_RVA + 8), "WORLD_VTABLE_MISMATCH"),
        (WORLD + memory.HRE_OFFSET, _u64(BASE + memory.HRE_VTABLE_RVA + 8), "HRE_VTABLE_MISMATCH"),
        (WORLD + 0xA60, _u32(2, signed=True), "OBSERVER_NOT_NONPLAYER"),
        (CONTROLLERS + 4, _u32(3, signed=True), "OBSERVER_NOT_NONPLAYER"),
        (WORLD + 0x1E60, _u64(_ref(1, "FRA")), "OBSERVER_IS_PHYSICAL_PLAYER"),
    ],
)
def test_rejects_wrong_vtables_or_nonplayer_role(address, raw, reason):
    image = make_image()
    image.put(address, raw)
    with pytest.raises(ValueError, match=reason):
        _read(image)


def test_rejects_invalid_fullref_and_country_table_mismatch():
    image = make_image()
    image.put(WORLD + memory.HRE_OFFSET + 0x10, _u64(_ref(3, "HAB") & ~0xFFFFFF | 0x212121))
    with pytest.raises(ValueError, match="FULLREF_TAG_INVALID"):
        _read(image)

    image = make_image()
    image.put(TABLE + 4 * 8, _u64(COUNTRY_BASE + 4 * 0x100))
    image.put(COUNTRY_BASE + 4 * 0x100 + countries.COUNTRY_FULLREF_OFFSET,
              _u64(_ref(3, "BOH")))
    with pytest.raises(ValueError, match="slot_mismatch"):
        _read(image)


def test_rejects_count_overflow_short_long_cycle_and_duplicate_electors():
    image = make_image()
    header = bytearray(image.read(WORLD + memory.HRE_OFFSET + 0x80, 24, "fixture"))
    header[16:20] = _u32(memory.MAX_ELECTOR_NODES + 1)
    image.put(WORLD + memory.HRE_OFFSET + 0x80, bytes(header))
    with pytest.raises(ValueError, match="COUNT_OUT_OF_RANGE"):
        _read(image)

    image = make_image()
    image.put(NODE1 + 0x10, _u64(0))
    with pytest.raises(ValueError, match="CHAIN_SHORT"):
        _read(image)

    image = make_image(electors=("BOH",))
    image.put(NODE1 + 0x10, _u64(NODE2))
    with pytest.raises(ValueError, match="CHAIN_LONG"):
        _read(image)

    image = make_image()
    image.put(NODE2 + 0x10, _u64(NODE1))
    with pytest.raises(ValueError, match="CYCLE"):
        _read(image)

    image = make_image(electors=("BOH", "BOH"))
    with pytest.raises(ValueError, match="DUPLICATE_FULLREF"):
        _read(image)


def test_reader_short_read_and_budget_fail_closed():
    image = make_image()
    image.data.pop(WORLD + memory.HRE_OFFSET + 0x10)
    with pytest.raises(OSError, match="unmapped"):
        _read(image)

    reader = memory._BudgetReader(MemoryImage())
    with pytest.raises(ValueError, match="READ_RANGE_INVALID"):
        reader.read(WORLD, memory.MAX_SINGLE_READ + 1, "oversize")

