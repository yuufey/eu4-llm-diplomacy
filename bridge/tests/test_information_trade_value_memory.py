from __future__ import annotations

import struct

from bridge.information import trade_value_memory as memory


BASE = 0x140000000
MANAGER = 0x200000
VECTOR = 0x300000
DEF_A = 0x400000
DEF_B = 0x401000
VTABLE = 0x500000
WORLD = 0x600000
PROVINCE_BASE = 0x700000
RUNTIME_A = 0x800000
RUNTIME_B = 0x810000
INCOMING = 0x900000
ROUTES = 0x910000
RATIOS = 0x920000
PROVINCE_RECORD_A = PROVINCE_BASE + 5 * 0x2E10


def _q(value: int) -> bytes:
    return struct.pack("<Q", value)


def _i(value: int) -> bytes:
    return struct.pack("<i", value)


class FakeReader:
    def __init__(self):
        self.regions: list[tuple[int, bytes]] = []
        self.log: list[tuple[int, int, str]] = []

    def put(self, address: int, data: bytes) -> None:
        self.regions.append((address, bytes(data)))

    def read(self, address: int, size: int, label: str) -> bytes:
        self.log.append((address, size, label))
        for start, data in reversed(self.regions):
            offset = address - start
            if offset >= 0 and offset + size <= len(data):
                return data[offset:offset + size]
        raise OSError(f"unmapped:{address:#x}:{size}:{label}")


def _put_key(header: bytearray, node_id: str) -> None:
    key = node_id.encode("ascii")
    object_raw = bytearray(32)
    object_raw[:len(key) + 1] = key + b"\0"
    struct.pack_into("<Q", object_raw, 16, len(key))
    struct.pack_into("<Q", object_raw, 24, 15)
    header[0x10:0x30] = object_raw


def _province_binding(province_id: int, record: int) -> dict[str, object]:
    return {
        "province_id": province_id,
        "record_id": province_id,
        "record_pointer": hex(record),
        "id_address": hex(record + 0x20),
        "id_raw_hex": _i(province_id).hex(),
    }


def make_reader(*, bad_destination_echo: bool = False) -> tuple[FakeReader, dict[str, object]]:
    reader = FakeReader()
    for guard in memory.code_guards():
        reader.put(BASE + int(guard["rva"], 0), bytes.fromhex(guard["bytes"]))

    reader.put(BASE + 0x242BE28, _q(MANAGER))
    reader.put(MANAGER, _q(VECTOR) + _q(VECTOR + 16))
    reader.put(VECTOR, _q(DEF_A) + _q(DEF_B))
    reader.put(VTABLE + 0x40, _q(BASE + 0x8F440))

    def definition(address: int, name: str, center: int, route_begin: int = 0, route_end: int = 0) -> None:
        raw = bytearray(0xE0)
        raw[:8] = _q(VTABLE)
        _put_key(raw, name)
        struct.pack_into("<Q", raw, 0x98, route_begin)
        struct.pack_into("<Q", raw, 0xA0, route_end)
        struct.pack_into("<i", raw, 0xDC, center)
        reader.put(address, raw)

    definition(DEF_A, "node_a", 5, ROUTES, ROUTES + 0x78)
    definition(DEF_B, "node_b", 6)
    reader.put(BASE + 0x233FE58, _q(WORLD))
    reader.put(WORLD + 0x1CA8, _q(PROVINCE_BASE))
    reader.put(PROVINCE_BASE + 5 * 0x2E10 + 0xE8, _q(RUNTIME_A))
    reader.put(PROVINCE_BASE + 6 * 0x2E10 + 0xE8, _q(RUNTIME_B))

    runtime_a = bytearray(0x100)
    struct.pack_into("<Q", runtime_a, 0x88, RATIOS)
    struct.pack_into("<Q", runtime_a, 0xA8, DEF_A)
    struct.pack_into("<i", runtime_a, 0xB4, 100)
    struct.pack_into("<i", runtime_a, 0xBC, 25)
    struct.pack_into("<i", runtime_a, 0xC0, 1000)
    struct.pack_into("<Q", runtime_a, 0xF0, INCOMING)
    struct.pack_into("<Q", runtime_a, 0xF8, INCOMING + 64)
    reader.put(RUNTIME_A, runtime_a)
    reader.put(RUNTIME_B + 0xA8, _q(DEF_A if bad_destination_echo else DEF_B))
    incoming = bytearray(64)
    struct.pack_into("<i", incoming, 0x10, 30)
    struct.pack_into("<i", incoming, 32 + 0x10, 40)
    reader.put(INCOMING, incoming)

    route = bytearray(0x78)
    struct.pack_into("<Q", route, 0x30, DEF_B)
    reader.put(ROUTES, route)
    reader.put(RATIOS, _i(20))

    reader.put(PROVINCE_RECORD_A + 0x20, _i(5))
    return reader, _province_binding(5, PROVINCE_RECORD_A)


def test_profile_and_guard_windows_are_pinned_and_bounded():
    profile = memory.load_profile()
    guards = memory.code_guards()
    assert profile["profile_id"] == "trade-value-memory-1374"
    assert profile["semantics"]["collected_value"].startswith("unknown;")
    assert guards and all(len(bytes.fromhex(item["bytes"])) <= 1024 for item in guards)


def test_find_node_only_resolves_identity_and_does_not_read_value_offsets():
    reader, _binding = make_reader()
    result = memory.find_node(reader, BASE, "node_a")
    assert result["status"] == "known"
    assert result["center_province_id"] == 5
    assert result["definition_pointer"] == hex(DEF_A)
    assert result["runtime_pointer"] == hex(RUNTIME_A)
    assert not any(address in {
        RUNTIME_A + 0x88, RUNTIME_A + 0xB4, RUNTIME_A + 0xBC,
        RUNTIME_A + 0xC0, RUNTIME_A + 0xF0, DEF_A + 0x98,
    } for address, _size, _label in reader.log)


def test_four_selected_node_values_and_route_amount_are_independent_i32_sources():
    reader, binding = make_reader()
    result = memory.read_fields(
        reader, BASE, binding,
        ["T03.local_value", "T03.incoming_value", "T03.total_value", "T03.outgoing_value"],
        node_id="node_a",
    )
    assert result["T03.local_value"]["status"] == "known"
    assert result["T03.local_value"]["value"] == 100
    assert result["T03.incoming_value"]["value"] == 70
    assert result["T03.total_value"]["value"] == 145
    outgoing = result["T03.outgoing_value"]["value"]
    assert outgoing == {
        "total_raw": 25,
        "routes": [{"node_id": "node_b", "destination_center": 6, "raw": 20}],
    }
    assert sum(route["raw"] for route in outgoing["routes"]) != outgoing["total_raw"]


def test_incoming_and_total_apply_native_signed_i32_wrap():
    reader, binding = make_reader()
    incoming = bytearray(64)
    struct.pack_into("<i", incoming, 0x10, 0x7FFFFFFF)
    struct.pack_into("<i", incoming, 32 + 0x10, 1)
    reader.put(INCOMING, incoming)
    reader.put(RUNTIME_A + 0xB4, _i(-0x80000000) + bytes(4) + _i(-1))
    result = memory.read_fields(
        reader, BASE, binding,
        ["T03.local_value", "T03.incoming_value", "T03.total_value"],
        node_id="node_a",
    )
    assert result["T03.local_value"]["value"] == -0x80000000
    assert result["T03.incoming_value"]["value"] == -0x80000000
    assert result["T03.total_value"]["value"] == 1


def test_bad_outgoing_target_retracts_routes_but_keeps_other_independent_values():
    reader, binding = make_reader(bad_destination_echo=True)
    result = memory.read_fields(
        reader, BASE, binding,
        ["T03.local_value", "T03.total_value", "T03.outgoing_value"],
        node_id="node_a",
    )
    assert result["T03.local_value"]["status"] == "known"
    assert result["T03.total_value"]["status"] == "known"
    assert result["T03.total_value"]["value"] == 145
    assert result["T03.outgoing_value"]["status"] == "unknown"
    assert "value" not in result["T03.outgoing_value"]


def test_wrong_center_binding_stops_before_numeric_cache_reads():
    reader, binding = make_reader()
    binding = dict(binding)
    binding["province_id"] = 7
    binding["record_id"] = 7
    binding["id_raw_hex"] = _i(7).hex()
    result = memory.read_fields(reader, BASE, binding, ["T03.local_value"], node_id="node_a")
    assert result["T03.local_value"]["status"] == "unknown"
    assert not any(label == "trade_value.node.local_value_i32" for _a, _s, label in reader.log)


def test_other_record_with_matching_id_bytes_cannot_bind_selected_center():
    reader, binding = make_reader()
    spoofed = dict(binding)
    spoofed_record = PROVINCE_RECORD_A + 0x1000
    spoofed["record_pointer"] = hex(spoofed_record)
    spoofed["id_address"] = hex(spoofed_record + 0x20)
    reader.put(spoofed_record + 0x20, _i(5))
    result = memory.read_fields(reader, BASE, spoofed, ["T03.local_value"], node_id="node_a")
    assert result["T03.local_value"]["status"] == "unknown"
    assert not any(label == "trade_value.node.local_value_i32" for _a, _s, label in reader.log)


def test_collected_value_stays_unknown_without_any_numeric_read():
    reader, binding = make_reader()
    before = len(reader.log)
    result = memory.read_fields(reader, BASE, binding, ["T03.collected_value"], node_id="node_a")
    assert result["T03.collected_value"]["status"] == "unknown"
    assert "value" not in result["T03.collected_value"]
    assert result["T03.collected_value"]["reason"] == memory.COLLECTED_UNKNOWN
    assert len(reader.log) == before
