"""Owned fake-memory tests for the fixed battle-definition reader."""
from __future__ import annotations

import ctypes as C
from contextlib import ExitStack
from pathlib import Path
import unittest
from unittest.mock import patch

from bridge.information import battle_definition_memory as bd
from bridge.information import localization_memory as lm
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
        self.put(address, int(value).to_bytes(8, "little", signed=False))

    def read(self, address: int, size: int, label: str) -> bytes:
        self.bytes_requested += size
        self.calls += 1
        return bytes(self.memory.get(address + offset, 0) for offset in range(size))

    def read_code(self, address: int, size: int, label: str) -> bytes:
        return self.read(address, size, label)

    def qword(self, address: int, label: str) -> tuple[int, bytes]:
        raw = self.read(address, 8, label)
        return int.from_bytes(raw, "little"), raw


def write_definition(
    reader: FakeReader,
    address: int,
    key: str,
    kind: int,
    layout: int,
    button: int,
    *,
    capacity: int = 15,
    length: int | None = None,
    vtable: int = 0x1412345000,
) -> None:
    encoded = key.encode("ascii")
    actual_length = len(encoded) if length is None else length
    header = bytearray(32)
    header[:min(len(encoded) + 1, 16)] = (encoded + b"\x00")[:16]
    reader.put(address + bd.DEFINITION_KEY_OFFSET, bytes(header))
    reader.qword_put(address + bd.DEFINITION_KEY_LENGTH_OFFSET, actual_length)
    reader.qword_put(address + bd.DEFINITION_KEY_CAPACITY_OFFSET, capacity)
    reader.qword_put(address + bd.DEFINITION_VTABLE_OFFSET, vtable)
    scalar = int(kind).to_bytes(4, "little", signed=True)
    scalar += int(layout).to_bytes(4, "little", signed=True)
    scalar += int(button).to_bytes(1, "little", signed=False)
    reader.put(address + bd.DEFINITION_KIND_OFFSET, scalar)


def definition_fixture(
    *, include_naval: bool = True, land_kind: int = 1, naval_kind: int = 2
) -> tuple[FakeReader, int, dict[str, int]]:
    module = 0x140000000
    reader = FakeReader(module)

    game = 0x200000
    database = 0x300000
    country_table = 0x400000
    country = 0x500000
    reader.qword_put(module + mm.GAME_RVA, game)
    reader.qword_put(module + mm.DATABASE_RVA, database)
    reader.put(game + mm.GAME_DATE_OFFSET, (56563608).to_bytes(4, "little", signed=True))
    reader.qword_put(database + mm.COUNTRY_TABLE_OFFSET, country_table)
    reader.put(country_table, bytes(lm.COUNTRY_SCAN_ENTRIES * 8))
    slot = 122
    reader.qword_put(country_table + slot * 8, country)
    reader.qword_put(country + mm.COUNTRY_HANDLE_OFFSET, (slot << 32) | int.from_bytes(b"FRA", "little"))

    manager = 0x800000
    bucket_array = 0x810000
    reader.qword_put(module + bd.MANAGER_CELL_RVA, manager)
    reader.put(manager, bytes(4))
    reader.put(manager + bd.MANAGER_BUCKET_COUNT_OFFSET, (1).to_bytes(4, "little"))
    reader.qword_put(manager + bd.MANAGER_BUCKET_ARRAY_OFFSET, bucket_array)

    nodes = {"collision": 0x900000, "LANDBATTLEOVER": 0x901000, "NAVALBATTLEOVER": 0x902000}
    definitions = {"collision": 0xA00000, "LANDBATTLEOVER": 0xA01000, "NAVALBATTLEOVER": 0xA02000}
    write_definition(reader, definitions["collision"], "OTHER", 99, -1, 0)
    write_definition(reader, definitions["LANDBATTLEOVER"], "LANDBATTLEOVER", land_kind, -7, 0xA5)
    write_definition(reader, definitions["NAVALBATTLEOVER"], "NAVALBATTLEOVER", naval_kind, 9, 0x5A)

    chain_keys = ["collision", "LANDBATTLEOVER"]
    if include_naval:
        chain_keys.append("NAVALBATTLEOVER")
    for index, name in enumerate(chain_keys):
        reader.qword_put(nodes[name] + bd.NODE_DEFINITION_OFFSET, definitions[name])
        next_node = nodes[chain_keys[index + 1]] if index + 1 < len(chain_keys) else 0
        reader.qword_put(nodes[name] + bd.NODE_NEXT_OFFSET, next_node)
    reader.qword_put(bucket_array, nodes["collision"])
    return reader, module, {**nodes, **{f"def:{k}": v for k, v in definitions.items()}}


class FakeCaptureKernel:
    def __init__(self, module_base: int, *, close_result: bool = True, creation_filetime: int = 987):
        self.module_base = module_base
        self.close_result = close_result
        self.creation_filetime = creation_filetime
        self.closed: list[int] = []
        self.process_path = Path("fake-eu4.exe").resolve()

    def OpenProcess(self, _access, _inherit, _pid):
        return 0x1234

    def QueryFullProcessImageNameW(self, _handle, _flags, buffer, _length):
        buffer.value = str(self.process_path)
        return True

    def GetProcessTimes(self, _handle, creation, _exit_time, _kernel_time, _user_time):
        value = C.cast(creation, C.POINTER(mm.W.FILETIME)).contents
        value.dwLowDateTime = self.creation_filetime & 0xFFFFFFFF
        value.dwHighDateTime = (self.creation_filetime >> 32) & 0xFFFFFFFF
        return True

    def K32EnumProcessModulesEx(self, _handle, modules, _size, needed, _flags):
        modules[0] = self.module_base
        value = C.cast(needed, C.POINTER(mm.W.DWORD)).contents
        value.value = C.sizeof(mm.W.HMODULE)
        return True

    def _probe_get_module_name(self, _handle, _module, buffer, _size):
        buffer.value = str(self.process_path)
        return len(buffer.value)

    def CloseHandle(self, handle):
        self.closed.append(int(handle))
        return self.close_result

    def ReadProcessMemory(self, _handle, _address, buffer, size, actual):
        C.memset(buffer, 0, size)
        C.cast(actual, C.POINTER(C.c_size_t)).contents.value = size
        return True


def _observed_guard() -> dict[str, object]:
    return {"status": "observed", "checks": {"same": True}, "records": {}, "unknown_conditions": []}


class BattleDefinitionMemoryTests(unittest.TestCase):
    def test_profile_contract_and_hash(self):
        self.assertEqual(bd._static_contract_guard()["status"], "observed")
        self.assertEqual(bd._hash_ascii("LANDBATTLEOVER"), self._manual_hash("LANDBATTLEOVER"))

    @staticmethod
    def _manual_hash(text: str) -> int:
        value = 0
        for byte in text.encode("ascii"):
            value = ((value + byte) * 61) & 0xFFFFFFFF
        return value

    def test_exact_key_match_survives_same_bucket_collision(self):
        reader, module, _addresses = definition_fixture()
        result = bd._snapshot(reader, module, "FRA")
        self.assertEqual(result["status"], "observed")
        self.assertEqual(result["definitions"]["LANDBATTLEOVER"]["layout_raw"], -7)
        self.assertEqual(result["definitions"]["LANDBATTLEOVER"]["button_flag_raw"], 0xA5)
        self.assertEqual(result["definitions"]["LANDBATTLEOVER"]["popup_kind_raw"], 1)
        self.assertTrue(result["definitions"]["LANDBATTLEOVER"]["matches_formatter_kind"])
        self.assertEqual(result["definitions"]["LANDBATTLEOVER"]["formatter_kind"], 1)
        self.assertEqual(result["definitions"]["NAVALBATTLEOVER"]["popup_kind_raw"], 2)
        self.assertTrue(result["definitions"]["NAVALBATTLEOVER"]["matches_formatter_kind"])
        self.assertEqual(result["definitions"]["NAVALBATTLEOVER"]["formatter_kind"], 2)
        self.assertEqual(
            result["definitions"]["LANDBATTLEOVER"]["candidate_vtable_qword"]["value"],
            hex(0x1412345000),
        )
        self.assertEqual(len(result["buckets"][0]["nodes"]), 3)
        self.assertEqual(result["buckets"][0]["nodes"][0]["key"]["key_text_ascii"], "OTHER")

    def test_missing_definition_retracts_both_results(self):
        reader, module, _addresses = definition_fixture(include_naval=False)
        result = bd._snapshot(reader, module, "FRA")
        self.assertEqual(result["status"], "unknown")
        self.assertIn("definition_key_not_found:NAVALBATTLEOVER", result["unknown_reason"])
        self.assertTrue(all(entry["status"] == "unknown" for entry in result["definitions"].values()))

    def test_cycle_is_unknown(self):
        reader, module, addresses = definition_fixture()
        reader.qword_put(addresses["NAVALBATTLEOVER"] + bd.NODE_NEXT_OFFSET, addresses["collision"])
        result = bd._snapshot(reader, module, "FRA")
        self.assertEqual(result["status"], "unknown")
        self.assertIn("bucket_chain_cycle", result["unknown_reason"])

    def test_oversized_capacity_and_invalid_sso_length_are_unknown(self):
        for capacity, length, expected_reason in (
            (bd.MAX_STRING_CAPACITY + 1, len("LANDBATTLEOVER"), "capacity_or_length"),
            (15, 16, "sso_length"),
        ):
            with self.subTest(capacity=capacity, length=length):
                reader, module, addresses = definition_fixture()
                definition = addresses["def:LANDBATTLEOVER"]
                reader.qword_put(definition + bd.DEFINITION_KEY_LENGTH_OFFSET, length)
                reader.qword_put(definition + bd.DEFINITION_KEY_CAPACITY_OFFSET, capacity)
                result = bd._snapshot(reader, module, "FRA")
                self.assertEqual(result["status"], "unknown")
                self.assertIn(expected_reason, result["unknown_reason"])

    def test_zero_and_other_family_popup_kinds_are_reported_without_rejection(self):
        for popup_kind, matches in ((0, False), (2, False)):
            with self.subTest(popup_kind=popup_kind):
                reader, module, _addresses = definition_fixture(land_kind=popup_kind)
                result = bd._snapshot(reader, module, "FRA")
                self.assertEqual(result["status"], "observed")
                entry = result["definitions"]["LANDBATTLEOVER"]
                self.assertEqual(entry["popup_kind_raw"], popup_kind)
                self.assertEqual(entry["popup_kind_raw_hex"], popup_kind.to_bytes(4, "little", signed=True).hex())
                self.assertEqual(entry["formatter_kind"], 1)
                self.assertIs(entry["matches_formatter_kind"], matches)

    def test_duplicate_exact_key_in_same_bucket_is_unknown(self):
        reader, module, addresses = definition_fixture()
        duplicate_node = 0x903000
        duplicate_definition = 0xA03000
        write_definition(reader, duplicate_definition, "LANDBATTLEOVER", 1, 3, 1)
        reader.qword_put(addresses["NAVALBATTLEOVER"] + bd.NODE_NEXT_OFFSET, duplicate_node)
        reader.qword_put(duplicate_node + bd.NODE_DEFINITION_OFFSET, duplicate_definition)
        reader.qword_put(duplicate_node + bd.NODE_NEXT_OFFSET, 0)
        result = bd._snapshot(reader, module, "FRA")
        self.assertEqual(result["status"], "unknown")
        self.assertIn("duplicate_definition_key:LANDBATTLEOVER", result["unknown_reason"])

    def test_bucket_count_zero_and_over_limit_are_unknown(self):
        for count in (0, bd.MAX_BUCKET_COUNT + 1):
            with self.subTest(count=count):
                reader, module, _addresses = definition_fixture()
                manager = 0x800000
                reader.put(manager + bd.MANAGER_BUCKET_COUNT_OFFSET, count.to_bytes(4, "little"))
                result = bd._snapshot(reader, module, "FRA")
                self.assertEqual(result["status"], "unknown")
                self.assertIn("bucket_count_zero_or_out_of_bound", result["unknown_reason"])

    def test_sixty_fifth_node_exceeds_chain_bound(self):
        reader, module, addresses = definition_fixture()
        previous = addresses["NAVALBATTLEOVER"]
        for index in range(62):
            node = 0x903000 + index * 0x1000
            definition = 0xA03000 + index * 0x1000
            write_definition(reader, definition, f"OTHER{index}", 99, index, 0)
            reader.qword_put(previous + bd.NODE_NEXT_OFFSET, node)
            reader.qword_put(node + bd.NODE_DEFINITION_OFFSET, definition)
            previous = node
        reader.qword_put(previous + bd.NODE_NEXT_OFFSET, 0)
        result = bd._snapshot(reader, module, "FRA")
        self.assertEqual(result["status"], "unknown")
        self.assertIn("bucket_chain_node_limit_exceeded", result["unknown_reason"])

    def test_heap_backed_key_exact_match_and_bad_terminator(self):
        reader, module, addresses = definition_fixture()
        definition = addresses["def:LANDBATTLEOVER"]
        heap = 0xB00000
        key = b"LANDBATTLEOVER"
        header = bytearray(32)
        header[:8] = heap.to_bytes(8, "little")
        header[16:24] = len(key).to_bytes(8, "little")
        header[24:32] = (16).to_bytes(8, "little")
        reader.put(definition + bd.DEFINITION_KEY_OFFSET, header)
        reader.put(heap, key + b"\x00")
        result = bd._snapshot(reader, module, "FRA")
        self.assertEqual(result["status"], "observed")
        self.assertEqual(result["definitions"]["LANDBATTLEOVER"]["key_storage"], "heap")

        reader.put(heap, key + b"X")
        bad = bd._snapshot(reader, module, "FRA")
        self.assertEqual(bad["status"], "unknown")
        self.assertIn("definition_string_terminator_invalid", bad["unknown_reason"])

    def test_bounded_rpm_enforces_call_byte_and_single_read_limits(self):
        kernel = FakeCaptureKernel(0x140000000)
        with patch.object(bd, "MAX_TOTAL_RPM", 6), patch.object(bd, "MAX_RPM_CALLS", 4), patch.object(bd, "MAX_SINGLE_RPM", 8):
            reader = bd.BoundedRPM(kernel, 0x1234, 0x140000000)
            self.assertEqual(reader.read(0x200000, 4, "first"), bytes(4))
            with self.assertRaisesRegex(bd.ProbeError, "rpm_total_limit_exceeded"):
                reader.read(0x200008, 3, "too_many_bytes")
            self.assertEqual(reader.calls, 1)
            self.assertEqual(reader.bytes_requested, 4)

        with patch.object(bd, "MAX_TOTAL_RPM", 64), patch.object(bd, "MAX_RPM_CALLS", 1), patch.object(bd, "MAX_SINGLE_RPM", 8):
            reader = bd.BoundedRPM(kernel, 0x1234, 0x140000000)
            reader.read(0x200000, 4, "first")
            with self.assertRaisesRegex(bd.ProbeError, "rpm_call_limit_exceeded"):
                reader.read(0x200008, 1, "too_many_calls")
            self.assertEqual(reader.calls, 1)

        with patch.object(bd, "MAX_TOTAL_RPM", 64), patch.object(bd, "MAX_RPM_CALLS", 4), patch.object(bd, "MAX_SINGLE_RPM", 4):
            reader = bd.BoundedRPM(kernel, 0x1234, 0x140000000)
            with self.assertRaisesRegex(bd.ProbeError, "single_read_limit_exceeded"):
                reader.read(0x200000, 5, "too_large")
            self.assertEqual(reader.calls, 0)
            self.assertEqual(reader.bytes_requested, 0)

    def _capture_patched(self, reader: FakeReader, kernel: FakeCaptureKernel, changing_snapshot=None):
        document = {
            "pid": 123,
            "creation_filetime": 987,
            "game_sha256": bd.EXPECTED_EXE_SHA256,
            "session_id": "fake-session",
        }
        patches = [
            patch.object(lm, "_load_installation", return_value=document),
            patch.object(bd._lm, "_configure_kernel", return_value=kernel),
            patch.object(bd._lm, "_sha256_file", return_value=bd.EXPECTED_EXE_SHA256),
            patch.object(bd, "_file_code_guard", return_value=_observed_guard()),
            patch.object(bd, "_runtime_code_guard", return_value=_observed_guard()),
            patch.object(bd, "BoundedRPM", return_value=reader),
        ]
        if changing_snapshot is not None:
            patches.append(patch.object(bd, "_snapshot", side_effect=changing_snapshot))
        with ExitStack() as stack:
            for manager in patches:
                stack.enter_context(manager)
            return bd.capture(Path("fake-installation.json"), "FRA")

    def test_capture_two_pass_mutation_closes_handle_and_retracts(self):
        reader, module, _addresses = definition_fixture()
        kernel = FakeCaptureKernel(module)
        original_snapshot = bd._snapshot
        calls = 0

        def changing_snapshot(probe_reader, probe_module, country):
            nonlocal calls
            result = original_snapshot(probe_reader, probe_module, country)
            calls += 1
            if calls == 1:
                game = 0x200000
                probe_reader.put(game + mm.GAME_DATE_OFFSET, (56563609).to_bytes(4, "little", signed=True))
            return result

        report = self._capture_patched(reader, kernel, changing_snapshot)
        self.assertEqual(calls, 2)
        self.assertEqual(report["status"], "doublepass_mismatch")
        self.assertFalse(report["doublepass"]["consistent"])
        self.assertTrue(all(entry["status"] == "unknown" for entry in report["definitions"].values()))
        self.assertEqual(kernel.closed, [0x1234])
        self.assertTrue(report["cleanup"]["handle_close"]["closed"])

    def test_capture_success_closes_handle_exactly_once(self):
        reader, module, _addresses = definition_fixture()
        kernel = FakeCaptureKernel(module)
        report = self._capture_patched(reader, kernel)
        self.assertEqual(report["status"], "observed")
        self.assertTrue(report["doublepass"]["consistent"])
        self.assertEqual(report["definitions"]["LANDBATTLEOVER"]["layout_raw"], -7)
        self.assertEqual(kernel.closed, [0x1234])

    def test_close_handle_failure_retracts_both_results(self):
        reader, module, _addresses = definition_fixture()
        kernel = FakeCaptureKernel(module, close_result=False)
        report = self._capture_patched(reader, kernel)
        self.assertEqual(report["status"], "cleanup_error")
        self.assertEqual(kernel.closed, [0x1234])
        self.assertTrue(all(entry["status"] == "unknown" for entry in report["definitions"].values()))
        self.assertEqual(report["cleanup"]["handle_close"]["success"], False)

if __name__ == "__main__":
    unittest.main()
