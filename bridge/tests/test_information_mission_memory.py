"""Bounded regression tests for the production mission-memory reader."""
from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from bridge.information import mission_memory as mm


class FakeReader:
    def __init__(self, module_base: int = 0x140000000):
        self.module_base = module_base
        self.memory: dict[int, int] = {}
        self.bytes_requested = 0
        self.calls = 0

    def put(self, address: int, data: bytes) -> None:
        for offset, value in enumerate(data):
            self.memory[address + offset] = value

    def qword_put(self, address: int, value: int) -> None:
        self.put(address, int(value).to_bytes(8, "little"))

    def dword_put(self, address: int, value: int, *, signed: bool = False) -> None:
        self.put(address, int(value).to_bytes(4, "little", signed=signed))

    def read(self, address: int, size: int, label: str) -> bytes:
        self.bytes_requested += size
        self.calls += 1
        return bytes(self.memory.get(address + offset, 0) for offset in range(size))

    def read_code(self, address: int, size: int, label: str) -> bytes:
        return self.read(address, size, label)

    def qword(self, address: int, label: str) -> tuple[int, bytes]:
        raw = self.read(address, 8, label)
        return int.from_bytes(raw, "little"), raw


def write_string32(reader: FakeReader, definition: int, text: str, *, heap: bool = False) -> None:
    payload = text.encode("ascii") + b"\x00"
    header = bytearray(32)
    length = len(text.encode("ascii"))
    capacity = 16 if heap else max(length, 1)
    if heap:
        heap_address = definition + 0x1000
        reader.qword_put(definition + mm.DEFINITION_NAME_OFFSET, heap_address)
        reader.put(heap_address, payload)
    else:
        header[:len(payload)] = payload
        reader.put(definition + mm.DEFINITION_NAME_OFFSET, header)
    reader.dword_put(definition + mm.DEFINITION_NAME_OFFSET + mm.STRING_LENGTH_OFFSET, length)
    reader.dword_put(definition + mm.DEFINITION_NAME_OFFSET + mm.STRING_CAPACITY_OFFSET, capacity)
    # String32 fields are 64-bit values; rewrite the complete values after
    # the byte-sized setup so fake memory mirrors the native layout exactly.
    reader.qword_put(definition + mm.DEFINITION_NAME_OFFSET + mm.STRING_LENGTH_OFFSET, length)
    reader.qword_put(definition + mm.DEFINITION_NAME_OFFSET + mm.STRING_CAPACITY_OFFSET, capacity)


def base_reader(*, slots: int = 0, completed: str = "empty") -> tuple[FakeReader, int, int]:
    module = 0x140000000
    game = 0x200000
    database = 0x300000
    table = 0x400000
    country = 0x500000
    reader = FakeReader(module)
    reader.qword_put(module + mm.GAME_RVA, game)
    reader.qword_put(module + mm.DATABASE_RVA, database)
    reader.dword_put(game + mm.GAME_DATE_OFFSET, 56553384, signed=True)
    reader.qword_put(database + mm.COUNTRY_TABLE_OFFSET, table)
    reader.qword_put(table + 122 * 8, country)
    reader.qword_put(country + mm.COUNTRY_HANDLE_OFFSET,
                     (122 << 32) | int.from_bytes(b"FRA", "little"))

    vtable = module + mm.EXPECTED_MISSION_VTABLE_RVA
    reader.qword_put(country + mm.COUNTRY_MISSIONS_OFFSET, vtable)
    reader.qword_put(vtable + 8, module + mm.EXPECTED_MISSION_THUNK_RVA)
    reader.qword_put(vtable + 0x10, module + mm.EXPECTED_MISSION_WRITER_RVA)
    mission = country + mm.COUNTRY_MISSIONS_OFFSET
    if slots:
        slot_array = 0x700000
        reader.qword_put(mission + mm.SLOT_ARRAY_OFFSET, slot_array)
        reader.dword_put(mission + mm.SLOT_COUNT_OFFSET, slots, signed=True)
        for index in range(slots):
            reader.qword_put(slot_array + index * mm.SLOT_STRIDE + mm.ROOT_ARRAY_OFFSET, 0)
            reader.dword_put(slot_array + index * mm.SLOT_STRIDE + mm.ROOT_COUNT_OFFSET, 0, signed=True)

    container = country + mm.COUNTRY_COMPLETED_OFFSET
    reader.qword_put(container, vtable)  # marker: this qword must never be followed
    sentinel = 0x600000
    reader.qword_put(container + 8, sentinel)
    if completed == "empty":
        reader.qword_put(sentinel, sentinel)
    elif completed == "nonempty":
        node = 0x610000
        definition = 0x620000
        reader.qword_put(sentinel, node)
        reader.qword_put(node, sentinel)
        reader.qword_put(node + 0x10, definition)
        write_string32(reader, definition, "done")
    elif completed == "cycle":
        node = 0x610000
        definition = 0x620000
        reader.qword_put(sentinel, node)
        reader.qword_put(node, node)
        reader.qword_put(node + 0x10, definition)
        write_string32(reader, definition, "cycle")
    else:
        raise ValueError(completed)
    return reader, module, country


def populate_code_guards(reader: FakeReader) -> None:
    for _name, rva, expected in mm._profile_code_guards():
        reader.put(reader.module_base + rva, expected)


class FakeCloseKernel:
    def __init__(self, result: bool | None = True, error: Exception | None = None):
        self.result = result
        self.error = error
        self.closed_handles: list[int] = []

    def CloseHandle(self, handle: int) -> bool:
        self.closed_handles.append(handle)
        if self.error is not None:
            raise self.error
        return bool(self.result)


class MissionMemoryTests(unittest.TestCase):
    def test_cleanup_close_failure_is_terminal_and_closes_once(self):
        report = mm._base_report(Path("missing.json"), "FRA", False)
        report["status"] = "observed"
        kernel = FakeCloseKernel(result=False)
        mm._apply_cleanup(report, kernel, 123)
        self.assertEqual(kernel.closed_handles, [123])
        self.assertEqual(report["cleanup"]["handle_close"]["status"], "error")
        self.assertFalse(report["cleanup"]["handle_close"]["success"])
        self.assertEqual(report["status"], "cleanup_error")
        self.assertNotEqual(report["status"], "observed")

        success = mm._base_report(Path("missing.json"), "FRA", False)
        success["status"] = "observed"
        ok_kernel = FakeCloseKernel(result=True)
        mm._apply_cleanup(success, ok_kernel, 456)
        self.assertEqual(ok_kernel.closed_handles, [456])
        self.assertEqual(success["cleanup"]["handle_close"]["status"], "closed")
        self.assertTrue(success["cleanup"]["handle_close"]["success"])
        self.assertEqual(success["status"], "observed")

        raised = mm._base_report(Path("missing.json"), "FRA", False)
        raised["status"] = "observed"
        raised_kernel = FakeCloseKernel(error=RuntimeError("close exploded"))
        mm._apply_cleanup(raised, raised_kernel, 789)
        self.assertEqual(raised_kernel.closed_handles, [789])
        self.assertEqual(raised["cleanup"]["handle_close"]["status"], "error")
        self.assertEqual(raised["status"], "cleanup_error")

        unopened = mm._base_report(Path("missing.json"), "FRA", False)
        unopened["status"] = "unsupported_country"
        mm._apply_cleanup(unopened, None, None)
        self.assertEqual(unopened["cleanup"]["handle_close"]["status"], "not_opened")
        self.assertEqual(unopened["status"], "unsupported_country")

    def test_profile_contract_and_runtime_code_guard(self):
        guard = mm._static_contract_guard()
        self.assertEqual(guard["status"], "observed")
        self.assertTrue(all(guard["checks"].values()))
        reader, module, _country = base_reader()
        populate_code_guards(reader)
        runtime = mm._runtime_code_guard(reader, module)
        self.assertEqual(runtime["status"], "observed")
        first = mm._profile_code_guards()[0]
        reader.memory[module + first[1]] ^= 0x01
        tampered = mm._runtime_code_guard(reader, module)
        self.assertEqual(tampered["status"], "mismatch")
        self.assertFalse(tampered["checks"][first[0]])

    def test_three_embedded_objects_inline_heap_and_empty_completed(self):
        reader, module, country = base_reader(slots=2, completed="empty")
        mission = country + mm.COUNTRY_MISSIONS_OFFSET
        slot_array = 0x700000
        root0 = 0x710000
        root1 = 0x720000
        definition0 = 0x730000
        definition1 = 0x740000
        reader.qword_put(slot_array + mm.ROOT_ARRAY_OFFSET, root0)
        reader.dword_put(slot_array + mm.ROOT_COUNT_OFFSET, 1, signed=True)
        reader.qword_put(slot_array + mm.SLOT_STRIDE + mm.ROOT_ARRAY_OFFSET, root1)
        reader.dword_put(slot_array + mm.SLOT_STRIDE + mm.ROOT_COUNT_OFFSET, 1, signed=True)
        reader.qword_put(root0, definition0)
        reader.qword_put(root1, definition1)
        write_string32(reader, definition0, "inline")
        write_string32(reader, definition1, "heap", heap=True)
        snapshot = mm._snapshot(reader, module, "FRA", True)
        self.assertEqual(snapshot["status"], "observed")
        self.assertEqual(snapshot["mission_contract"]["chain_matches"], {
            "vtable_rva": True,
            "vtable_plus_8_rva": True,
            "vtable_plus_10_rva": True,
        })
        self.assertEqual([item["text"] for item in snapshot["missions"]["rootstrings"]], ["inline", "heap"])
        candidate = snapshot["missions"]["candidate_completed_missions"]
        self.assertEqual(candidate["status"], "observed")
        self.assertTrue(candidate["empty"])
        self.assertEqual(candidate["container_field"]["storage"], "embedded_object")

    def test_completed_nonempty_and_cycle_are_distinct(self):
        reader, module, country = base_reader(completed="nonempty")
        snapshot = mm._snapshot(reader, module, "FRA", True)
        self.assertEqual(snapshot["status"], "observed")
        candidate = snapshot["missions"]["candidate_completed_missions"]
        self.assertFalse(candidate["empty"])
        self.assertEqual(candidate["rootstrings"][0]["text"], "done")

        reader, _module, country = base_reader(completed="cycle")
        result = mm._completed_candidates(reader, country)
        self.assertEqual(result["status"], "unknown")
        self.assertEqual(result["unknown_reason"], "completed_node_cycle")

    def test_slot_and_root_limits_fail_closed(self):
        reader, _module, country = base_reader()
        mission = country + mm.COUNTRY_MISSIONS_OFFSET
        reader.dword_put(mission + mm.SLOT_COUNT_OFFSET, mm.MAX_MISSION_SLOTS + 1, signed=True)
        result = mm._mission_slots(reader, mission, False, country)
        self.assertEqual(result["status"], "unknown")
        self.assertEqual(result["unknown_reason"], "slot_count_out_of_bound")

        reader, _module, country = base_reader(slots=1)
        mission = country + mm.COUNTRY_MISSIONS_OFFSET
        slot_array = 0x700000
        reader.dword_put(slot_array + mm.ROOT_COUNT_OFFSET, mm.MAX_ROOTS_PER_SLOT + 1, signed=True)
        result = mm._mission_slots(reader, mission, False, country)
        self.assertEqual(result["status"], "unknown")
        self.assertEqual(result["slots"][0]["unknown_reason"], "root_count_out_of_bound")

    def test_profile_tamper_and_size_limits_fail_closed(self):
        raw = mm.PROFILE_FILE.read_bytes()
        with tempfile.TemporaryDirectory() as directory:
            tampered = Path(directory) / "tampered.json"
            altered = bytearray(raw)
            altered[-2] ^= 1
            tampered.write_bytes(altered)
            with self.assertRaises(mm.ProfileError):
                mm._load_profile(tampered, mm.EXPECTED_PROFILE_SHA256)
            oversized = Path(directory) / "oversized.json"
            oversized.write_bytes(b"x" * (mm.PROFILE_MAX_BYTES + 1))
            with self.assertRaises(mm.ProfileError):
                mm._load_profile(oversized, mm.EXPECTED_PROFILE_SHA256)

    def test_scope_is_fra_only_and_snapshot_does_not_write(self):
        with tempfile.TemporaryDirectory() as directory:
            report = mm.capture(Path(directory) / "missing-installation.json", "ENG")
            self.assertEqual(report["status"], "unsupported_country")
            self.assertEqual(report["cleanup"]["handle_close"]["status"], "not_opened")
            self.assertEqual(list(Path(directory).iterdir()), [])


if __name__ == "__main__":
    unittest.main()
