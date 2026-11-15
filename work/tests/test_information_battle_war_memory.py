from __future__ import annotations

import ctypes as C
import tempfile
from pathlib import Path
from typing import Any
from unittest import TestCase
from unittest.mock import patch

from work import information_battle_war_memory as probe


class SparseMemory:
    def __init__(self) -> None:
        self._bytes: dict[int, int] = {}

    def put(self, address: int, value: bytes) -> None:
        for offset, byte in enumerate(value):
            self._bytes[address + offset] = byte

    def put_qword(self, address: int, value: int) -> None:
        self.put(address, int(value).to_bytes(8, "little", signed=False))

    def put_dword(self, address: int, value: int, *, signed: bool = False) -> None:
        self.put(address, int(value).to_bytes(4, "little", signed=signed))

    def get(self, address: int, size: int) -> bytes | None:
        result = bytearray()
        for offset in range(size):
            value = self._bytes.get(address + offset)
            if value is None:
                return None
            result.append(value)
        return bytes(result)


class FakeKernel:
    def __init__(self, memory: SparseMemory, *, close_success: bool = True) -> None:
        self.memory = memory
        self.close_success = close_success
        self.close_calls: list[int] = []
        self.read_calls = 0
        self.fail_reads = False

    def OpenProcess(self, access: int, inherit: bool, pid: int) -> int:
        return 7

    def CloseHandle(self, handle: int) -> bool:
        self.close_calls.append(handle)
        return self.close_success

    def ReadProcessMemory(self, handle: int, address: C.c_void_p, buffer: Any, size: int, actual: Any) -> int:
        self.read_calls += 1
        if self.fail_reads:
            actual._obj.value = 0
            return 0
        raw = self.memory.get(int(address.value), int(size))
        if raw is None:
            actual._obj.value = 0
            return 0
        C.memmove(buffer, raw, len(raw))
        actual._obj.value = len(raw)
        return 1


class FakeModuleKernel:
    def __init__(self, module_path: Path, *, present: bool = True) -> None:
        self.module_path = module_path
        self.present = present

    def K32EnumProcessModulesEx(self, handle: int, modules: Any, size: int, needed: Any, flags: int) -> int:
        if not self.present:
            needed._obj.value = 0
            return 1
        modules[0] = 0x700000
        needed._obj.value = C.sizeof(probe.W.HMODULE)
        return 1

    def _probe_get_module_name(self, handle: int, module: Any, buffer: Any, size: int) -> int:
        value = str(self.module_path)
        buffer.value = value
        return len(value)


BASE = 0x140000000
GAME = 0x5000000000
DATABASE = 0x5000010000
TABLE = 0x5000020000
FRA_COUNTRY = 0x5000030000
ENG_COUNTRY = 0x5000040000
FRA_ROWS = 0x5000050000
ENG_ROWS = 0x5000060000
WAR = 0x5000070000
SIDE_A = 0x5000080000
SIDE_B = 0x5000090000
CONTEXT = WAR  # D89A80's retained vector is embedded in the war object.
RESULT_VECTOR = 0x50000B0000
RESULT = 0x50000C0000
SIDE_A_OBJECT = 0x50000D0000
SIDE_B_OBJECT = 0x50000E0000
ROOT_VTABLE = BASE + 0x1D20BE0
SERVER = 0x5000100000
SERVER_VTABLE = 0x5000110000
PAUSE_OBJECT = 0x5000120000
HISTORY_EVENT = 0x5000130000
HISTORY_NODE = 0x5000140000
HISTORY_EVENT_2 = 0x5000150000
HISTORY_NODE_2 = 0x5000160000
HISTORY_ROOT = WAR + 0x108

FRA_HANDLE = (0 << 32) | int.from_bytes(b"FRA", "little")
ENG_HANDLE = (1 << 32) | int.from_bytes(b"ENG", "little")


def _identity(report: dict, document: dict, kernel: FakeKernel, handle: int) -> int:
    report["identity"].update(
        {
            "installation_pid": document["pid"],
            "installation_creation_filetime": document["creation_filetime"],
            "installation_session_id": document["session_id"],
            "process_path": "fake-eu4.exe",
            "process_path_sha256": probe.EXPECTED_EXE_SHA256,
            "process_path_sha256_matches_expected": True,
            "process_creation_filetime": document["creation_filetime"],
            "process_creation_utc": "2026-10-25T00:00:00Z",
            "process_creation_matches_installation": True,
            "module_path": "fake-eu4.exe",
            "module_path_matches_process": True,
            "binding_verified": True,
        }
    )
    report["module_base"] = {"va": hex(BASE)}
    return BASE


def _document() -> dict:
    return {
        "pid": 1234,
        "creation_filetime": 987654321,
        "session_id": "fake-session",
        "game_sha256": probe.EXPECTED_EXE_SHA256,
        "dll_sha256": probe.EXPECTED_DLL_SHA256,
        "modules_after_install": [{"name": "eu4_bridge_automated_diplomacy_v22.dll", "path": "fake.dll", "sha256": probe.EXPECTED_DLL_SHA256}],
    }


def _loaded_dll_observation(kernel: Any, handle: Any, document: dict, phase: str) -> dict:
    return {
        "phase": phase,
        "status": "observed",
        "expected_sha256": probe.EXPECTED_DLL_SHA256,
        "expected_path": "fake.dll",
        "expected_name": "eu4_bridge_automated_diplomacy_v22.dll",
        "loaded_module_count": 1,
        "modules": [{"path": "fake.dll", "sha256": probe.EXPECTED_DLL_SHA256}],
        "matching_modules": [{"path": "fake.dll", "sha256": probe.EXPECTED_DLL_SHA256}],
        "unknown_conditions": [],
    }


def _build_memory() -> SparseMemory:
    memory = SparseMemory()
    memory.put_qword(BASE + probe.GAME_RVA, GAME)
    memory.put_qword(BASE + probe.DATABASE_RVA, DATABASE)
    memory.put_dword(GAME + probe.GAME_DATE_OFFSET, 14551113, signed=True)
    memory.put_qword(GAME + probe.CONTROL_SERVER_OFFSET, SERVER)
    memory.put_dword(GAME + probe.CONTROL_SPEED_OFFSET, 0, signed=True)
    memory.put_qword(SERVER, SERVER_VTABLE)
    memory.put_qword(SERVER_VTABLE + probe.CONTROL_SERVER_VTABLE_SPEED_OFFSET, BASE + probe.CONTROL_GETTER_RVA)
    memory.put_qword(SERVER + probe.CONTROL_SERVER_PAUSE_OFFSET, PAUSE_OBJECT)
    memory.put(BASE + probe.CONTROL_GETTER_RVA, probe.CONTROL_GETTER_GUARD)
    memory.put(PAUSE_OBJECT + probe.CONTROL_PAUSE_FLAG_OFFSET, b"\x01")
    for name, rva, raw in probe.CODE_GUARDS:
        memory.put(BASE + rva, raw)

    memory.put_qword(DATABASE + probe.COUNTRY_TABLE_OFFSET, TABLE)
    memory.put(TABLE, b"\0" * (256 * 8))
    memory.put_qword(TABLE + 0 * 8, FRA_COUNTRY)
    memory.put_qword(TABLE + 1 * 8, ENG_COUNTRY)
    memory.put_qword(FRA_COUNTRY + probe.COUNTRY_HANDLE_OFFSET, FRA_HANDLE)
    memory.put_qword(ENG_COUNTRY + probe.COUNTRY_HANDLE_OFFSET, ENG_HANDLE)
    memory.put_qword(FRA_COUNTRY + probe.COUNTRY_RELATION_ROWS_OFFSET, FRA_ROWS)
    memory.put_dword(FRA_COUNTRY + probe.COUNTRY_RELATION_COUNT_OFFSET, 1, signed=True)
    memory.put(FRA_ROWS, b"\0" * 16)
    memory.put_dword(FRA_ROWS + 0, 1, signed=True)
    memory.put_qword(FRA_ROWS + 8, WAR)
    memory.put_qword(ENG_COUNTRY + probe.COUNTRY_RELATION_ROWS_OFFSET, ENG_ROWS)
    memory.put_dword(ENG_COUNTRY + probe.COUNTRY_RELATION_COUNT_OFFSET, 1, signed=True)
    memory.put(ENG_ROWS, b"\0" * 16)
    memory.put_dword(ENG_ROWS + 0, 0, signed=True)
    memory.put_qword(ENG_ROWS + 8, WAR)

    memory.put_qword(WAR + 0x48, SIDE_A)
    memory.put_qword(WAR + 0x50, SIDE_A + 8)
    memory.put_qword(WAR + 0x58, SIDE_A + 8)
    memory.put_qword(SIDE_A, FRA_HANDLE)
    memory.put_qword(WAR + 0x78, SIDE_B)
    memory.put_qword(WAR + 0x80, SIDE_B + 8)
    memory.put_qword(WAR + 0x88, SIDE_B + 8)
    memory.put_qword(SIDE_B, ENG_HANDLE)
    memory.put(HISTORY_ROOT, b"\0" * 0x40)
    memory.put_qword(HISTORY_ROOT, ROOT_VTABLE)
    memory.put_dword(HISTORY_ROOT + probe.HISTORY_DATE_OFFSET, 14551113, signed=True)
    memory.put_qword(HISTORY_ROOT + probe.HISTORY_CHILDREN_OFFSET, 0)
    memory.put(ROOT_VTABLE, b"\0" * 0xA8)
    memory.put_qword(ROOT_VTABLE + 0x90, BASE + 0x8F440)
    memory.put_qword(ROOT_VTABLE + 0x98, BASE + 0x7E7CC0)
    memory.put_qword(ROOT_VTABLE + 0xA0, BASE + 0x7E7D00)
    memory.put_qword(WAR + 0xF0, RESULT_VECTOR)
    memory.put_qword(WAR + 0xF8, RESULT_VECTOR + 8)
    memory.put_qword(WAR + 0x100, RESULT_VECTOR + 8)
    memory.put_qword(RESULT_VECTOR, RESULT)

    result = bytearray(probe.RESULT_SIZE)
    result[:8] = (BASE + probe.RESULT_VTABLE_RVA).to_bytes(8, "little")
    result[probe.RESULT_NAME_OFFSET:probe.RESULT_NAME_OFFSET + 16] = b"battle\0" + b"\0" * 9
    result[probe.RESULT_NAME_LENGTH_OFFSET:probe.RESULT_NAME_LENGTH_OFFSET + 8] = (6).to_bytes(8, "little")
    result[probe.RESULT_NAME_CAPACITY_OFFSET:probe.RESULT_NAME_CAPACITY_OFFSET + 8] = (6).to_bytes(8, "little")
    result[probe.RESULT_FLAG_OFFSET] = 1
    side_a = bytearray(probe.SIDE_SIZE)
    side_a[:8] = (BASE + probe.SIDE_VTABLE_RVA).to_bytes(8, "little")
    side_a[probe.SIDE_COUNTRY_OFFSET:probe.SIDE_COUNTRY_OFFSET + 8] = FRA_HANDLE.to_bytes(8, "little")
    side_a[probe.SIDE_COMMANDER_OFFSET:probe.SIDE_COMMANDER_OFFSET + 16] = b"cmd\0" + b"\0" * 12
    side_a[probe.SIDE_COMMANDER_OFFSET + 0x10:probe.SIDE_COMMANDER_OFFSET + 0x18] = (3).to_bytes(8, "little")
    side_a[probe.SIDE_COMMANDER_OFFSET + 0x18:probe.SIDE_COMMANDER_OFFSET + 0x20] = (3).to_bytes(8, "little")
    side_b = bytearray(probe.SIDE_SIZE)
    side_b[:8] = (BASE + probe.SIDE_VTABLE_RVA).to_bytes(8, "little")
    side_b[probe.SIDE_COUNTRY_OFFSET:probe.SIDE_COUNTRY_OFFSET + 8] = ENG_HANDLE.to_bytes(8, "little")
    for offset, value in ((0x38, 10), (0x3C, -2), (0x40, 3), (0x44, 4), (0x48, 5), (0x4C, 6), (0x50, 7), (0x54, 8), (0x74, 9)):
        side_a[offset:offset + 4] = value.to_bytes(4, "little", signed=True)
        side_b[offset:offset + 4] = (-value).to_bytes(4, "little", signed=True)
    result[probe.RESULT_SIDE_A_OFFSET:probe.RESULT_SIDE_A_OFFSET + probe.SIDE_SIZE] = side_a
    result[probe.RESULT_SIDE_B_OFFSET:probe.RESULT_SIDE_B_OFFSET + probe.SIDE_SIZE] = side_b
    memory.put(RESULT, bytes(result))
    return memory


class BattleWarMemoryTests(TestCase):
    def setUp(self) -> None:
        self.memory = _build_memory()
        self.kernel = FakeKernel(self.memory)
        self.document = _document()
        self.patches = [
            patch.object(probe, "_load_installation", return_value=self.document),
            patch.object(probe, "_configure_kernel", return_value=self.kernel),
            patch.object(probe, "_capture_identity", side_effect=_identity),
            patch.object(probe, "_loaded_dll_check", side_effect=_loaded_dll_observation),
            patch.object(probe, "_file_code_guard", return_value={"status": "observed", "checks": {}}),
        ]
        for item in self.patches:
            item.start()

    def tearDown(self) -> None:
        for item in reversed(self.patches):
            item.stop()

    def test_real_bounded_rpm_success_doublepass_and_signed_payload(self) -> None:
        report = probe.capture(Path("fake-installation.json"), "FRA", "ENG", 128)
        self.assertEqual(report["status"], "observed")
        self.assertTrue(report["completed"])
        self.assertEqual(report["cleanup"]["handle_close"]["status"], "closed")
        self.assertEqual(self.kernel.close_calls, [7])
        self.assertTrue(report["doublepass"]["consistent"])
        self.assertFalse(report["complete"])
        self.assertEqual(len(report["results"]), 1)
        result = report["results"][0]["result"]
        self.assertEqual(result["name"]["bytes_hex"], b"battle".hex())
        self.assertEqual(result["side_a"]["commander"]["bytes_hex"], b"cmd".hex())
        self.assertEqual(result["side_a"]["fields"]["cavalry"]["raw"], -2)
        self.assertFalse(report["native_function_invoked"])
        self.assertLessEqual(report["access"]["rpm_bytes_requested"], probe.MAX_TOTAL_RPM)

    def test_pair_set_mismatch_does_not_publish(self) -> None:
        self.memory.put_dword(ENG_ROWS + 0, 2, signed=True)
        report = probe.capture(Path("fake-installation.json"), "FRA", "ENG", 128)
        self.assertNotEqual(report["status"], "observed")
        self.assertIsNone(report["results"])
        self.assertEqual(self.kernel.close_calls, [7])

    def test_invalid_request_does_not_open_process(self) -> None:
        report = probe.capture(Path("fake-installation.json"), "ENG", "FRA", 128)
        self.assertEqual(report["status"], "invalid_request")
        self.assertEqual(self.kernel.close_calls, [])

    def test_doublepass_date_change_retracts_values(self) -> None:
        original = probe._snapshot
        calls = {"count": 0}

        def changing_snapshot(reader, module_base, actor, recipient, limit, pass_index):
            value = original(reader, module_base, actor, recipient, limit, pass_index)
            calls["count"] += 1
            if calls["count"] == 1:
                self.memory.put_dword(GAME + probe.GAME_DATE_OFFSET, 14551114, signed=True)
            return value

        with patch.object(probe, "_snapshot", side_effect=changing_snapshot):
            report = probe.capture(Path("fake-installation.json"), "FRA", "ENG", 128)
        self.assertEqual(report["status"], "doublepass_mismatch")
        self.assertIsNone(report["results"])
        self.assertTrue(any("game_date" in item for item in report["doublepass"]["mismatches"]))

    def test_budget_failure_and_cleanup_failure_retract(self) -> None:
        with patch.object(probe, "MAX_TOTAL_RPM", 32):
            report = probe.capture(Path("fake-installation.json"), "FRA", "ENG", 128)
        self.assertNotEqual(report["status"], "observed")
        self.assertIsNone(report["results"])

        self.kernel.close_success = False
        report = probe.capture(Path("fake-installation.json"), "FRA", "ENG", 128)
        self.assertEqual(report["status"], "cleanup_error")
        self.assertIsNone(report["results"])
        self.assertEqual(self.kernel.close_calls, [7, 7])

    def test_file_and_runtime_guards_fail_closed(self) -> None:
        self.patches[-1].stop()
        self.patches[-1] = patch.object(probe, "_file_code_guard", return_value={"status": "mismatch", "checks": {"result": False}})
        self.patches[-1].start()
        report = probe.capture(Path("fake-installation.json"), "FRA", "ENG", 128)
        self.assertEqual(report["status"], "file_code_mismatch")
        self.assertIsNone(report["results"])
        self.patches[-1].stop()
        self.patches[-1] = patch.object(probe, "_file_code_guard", return_value={"status": "observed", "checks": {}})
        self.patches[-1].start()
        self.memory.put(BASE + probe.RESULT_RETAIN_RVA, b"\xCC" * len(probe.RESULT_RETAIN_GUARD))
        report = probe.capture(Path("fake-installation.json"), "FRA", "ENG", 128)
        self.assertEqual(report["status"], "unknown")
        self.assertIsNone(report["results"])

    def test_identity_creation_change_between_passes_retracts(self) -> None:
        calls = {"count": 0}

        def changing_identity(report, document, kernel, handle):
            value = _identity(report, document, kernel, handle)
            calls["count"] += 1
            if calls["count"] == 2:
                report["identity"]["process_creation_filetime"] += 1
                report["identity"]["process_creation_matches_installation"] = False
            return value

        self.patches[2].stop()
        self.patches[2] = patch.object(probe, "_capture_identity", side_effect=changing_identity)
        self.patches[2].start()
        report = probe.capture(Path("fake-installation.json"), "FRA", "ENG", 128)
        self.assertEqual(report["status"], "doublepass_mismatch")
        self.assertIsNone(report["results"])
        self.assertTrue(any("identity_after" in item for item in report["doublepass"]["mismatches"]))

    def test_relation_null_reference_and_overcount_are_unknown(self) -> None:
        self.memory.put_qword(FRA_ROWS + 8, 0)
        report = probe.capture(Path("fake-installation.json"), "FRA", "ENG", 128)
        self.assertNotEqual(report["status"], "observed")
        self.memory.put_qword(FRA_ROWS + 8, WAR)
        self.memory.put_dword(FRA_COUNTRY + probe.COUNTRY_RELATION_COUNT_OFFSET, 257, signed=True)
        report = probe.capture(Path("fake-installation.json"), "FRA", "ENG", 128)
        self.assertNotEqual(report["status"], "observed")

    def test_member_vectors_reject_duplicate_handles_and_cross_side_overlap(self) -> None:
        self.memory.put_qword(WAR + 0x50, SIDE_A + 16)
        self.memory.put_qword(WAR + 0x58, SIDE_A + 16)
        self.memory.put_qword(SIDE_A + 8, FRA_HANDLE)
        report = probe.capture(Path("fake-installation.json"), "FRA", "ENG", 128)
        self.assertNotEqual(report["status"], "observed")

        self.memory = _build_memory()
        self.kernel.memory = self.memory
        self.memory.put_qword(SIDE_B, FRA_HANDLE)
        report = probe.capture(Path("fake-installation.json"), "FRA", "ENG", 128)
        self.assertNotEqual(report["status"], "observed")

    def test_sso_bad_nul_and_short_read_stay_unknown(self) -> None:
        reader = probe.AddressBoundedRPM(self.kernel, 7, BASE)
        bad_string = 0x5000150000
        header = bytearray(32)
        header[0:16] = b"bad\x00text" + b"\0" * 8
        header[0x10:0x18] = (8).to_bytes(8, "little")
        header[0x18:0x20] = (8).to_bytes(8, "little")
        self.memory.put(bad_string, bytes(header))
        decoded = probe._decode_sso32(reader, bad_string, "bad")
        self.assertEqual(decoded["status"], "unknown")
        self.kernel.fail_reads = True
        with self.assertRaises(Exception):
            reader.read(0x5000160000, 8, "short")

    def test_sso_heap_empty_reads_terminator_and_rejects_bad_capacity(self) -> None:
        reader = probe.AddressBoundedRPM(self.kernel, 7, BASE)
        address = 0x5000161000
        heap = 0x5000162000
        header = bytearray(32)
        header[0:8] = heap.to_bytes(8, "little")
        header[0x10:0x18] = (0).to_bytes(8, "little")
        header[0x18:0x20] = (16).to_bytes(8, "little")
        self.memory.put(address, bytes(header))
        self.memory.put(heap, b"\0")
        decoded = probe._decode_sso32(reader, address, "empty-heap")
        self.assertEqual(decoded["status"], "observed")
        self.assertEqual(decoded["payload_raw_hex"], "00")
        self.assertGreaterEqual(self.kernel.read_calls, 2)

        oversize = address + 0x100
        header[0x18:0x20] = (probe.MAX_SSO_CAPACITY + 1).to_bytes(8, "little")
        self.memory.put(oversize, bytes(header))
        decoded = probe._decode_sso32(reader, oversize, "oversize-heap")
        self.assertEqual(decoded["status"], "unknown")
        self.assertEqual(decoded["unknown_reason"], "string_capacity_oversize")

        bad_pointer = address + 0x200
        header[0:8] = (0).to_bytes(8, "little")
        header[0x18:0x20] = (16).to_bytes(8, "little")
        self.memory.put(bad_pointer, bytes(header))
        decoded = probe._decode_sso32(reader, bad_pointer, "bad-empty-heap")
        self.assertEqual(decoded["status"], "unknown")
        self.assertEqual(decoded["unknown_reason"], "string_heap_pointer_invalid")

    def test_loaded_dll_same_handle_path_and_hash_guard(self) -> None:
        self.patches[3].stop()
        try:
            with tempfile.TemporaryDirectory() as temporary:
                module_path = Path(temporary) / "eu4_bridge_automated_diplomacy_v22.dll"
                module_path.write_bytes(b"fake observer dll")
                document = {"modules_after_install": [{"name": module_path.name, "path": str(module_path), "sha256": probe.EXPECTED_DLL_SHA256}]}
                kernel = FakeModuleKernel(module_path)
                with patch.object(probe, "_sha256_file", return_value=probe.EXPECTED_DLL_SHA256):
                    observed = probe._loaded_dll_check(kernel, 7, document, "before")
                self.assertEqual(observed["status"], "observed")
                self.assertEqual(observed["loaded_module_count"], 1)

                absent = probe._loaded_dll_check(FakeModuleKernel(module_path, present=False), 7, document, "before")
                self.assertEqual(absent["status"], "unknown")
                self.assertIn("expected_observer_dll_not_loaded_or_hash_mismatch", absent["unknown_conditions"])

                with patch.object(probe, "_sha256_file", return_value="0" * 64):
                    swapped = probe._loaded_dll_check(kernel, 7, document, "after")
                self.assertEqual(swapped["status"], "unknown")
                self.assertIn("expected_observer_dll_not_loaded_or_hash_mismatch", swapped["unknown_conditions"])
        finally:
            self.patches[3].start()

    def test_runtime_dll_change_is_a_doublepass_mismatch(self) -> None:
        observed = _loaded_dll_observation(self.kernel, 7, self.document, "before")
        missing = dict(observed, phase="after", status="unknown", matching_modules=[], unknown_conditions=["module_missing"])
        with patch.object(probe, "_loaded_dll_check", side_effect=[observed, missing]):
            report = probe.capture(Path("fake-installation.json"), "FRA", "ENG", 128)
        self.assertEqual(report["status"], "doublepass_mismatch")
        self.assertEqual(report["dll_installation"]["before"]["status"], "observed")
        self.assertEqual(report["dll_installation"]["after"]["status"], "unknown")
        self.assertIsNone(report["results"])

    def test_partial_collection_never_publishes_complete_observation(self) -> None:
        self.memory.put_qword(WAR + 0xF8, RESULT_VECTOR + 16)
        self.memory.put_qword(WAR + 0x100, RESULT_VECTOR + 16)
        self.memory.put_qword(RESULT_VECTOR + 8, RESULT)
        report = probe.capture(Path("fake-installation.json"), "FRA", "ENG", 1)
        self.assertEqual(report["status"], "observed")
        self.assertTrue(report["results_truncated"])
        self.assertFalse(report["retained_observation_complete"])
        self.assertTrue(report["before"]["partial"])
        self.assertTrue(report["after"]["partial"])

    def test_cli_output_is_exclusive_and_preserves_existing_report(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "report.json"
            output.write_text("historical\n", encoding="utf-8")
            status = probe.main(["--installation", "fake-installation.json", "--actor", "ENG", "--recipient", "FRA", "--output", str(output)])
            self.assertEqual(status, 2)
            self.assertEqual(output.read_text(encoding="utf-8"), "historical\n")

    def test_history_root_requires_exact_vtable_and_true_slot90(self) -> None:
        reader = probe.AddressBoundedRPM(self.kernel, 7, BASE)
        history = probe._read_history(reader, BASE, WAR, HISTORY_ROOT, [RESULT], "root-valid")
        self.assertEqual(history["status"], "observed")
        self.memory.put_qword(HISTORY_ROOT, BASE + 0x1D20BF0)
        unsupported = probe._read_history(reader, BASE, WAR, HISTORY_ROOT, [RESULT], "root-vtable-mismatch")
        self.assertEqual(unsupported["status"], "unknown")
        self.assertIn("history_root_vtable_rva_mismatch", unsupported["unknown_conditions"])
        self.memory.put_qword(HISTORY_ROOT, ROOT_VTABLE)
        self.memory.put_qword(ROOT_VTABLE + 0x90, BASE + 0x8F450)
        false_root = probe._read_history(reader, BASE, WAR, HISTORY_ROOT, [RESULT], "root-slot90-false")
        self.assertEqual(false_root["status"], "unknown")
        self.assertIn("history_root_vtable_slots_unsupported", false_root["unknown_conditions"])
        self.memory.put_qword(ROOT_VTABLE + 0x90, BASE + 0x8F440)
        true_root = probe._read_history(reader, BASE, WAR, HISTORY_ROOT, [RESULT], "root-slot90-true")
        self.assertEqual(true_root["status"], "observed")

    def test_truncation_history_date_binding_and_cycle_guard(self) -> None:
        reader = probe.AddressBoundedRPM(self.kernel, 7, BASE)
        pointers = 0x5000170000
        self.memory.put(pointers, b"\0" * (129 * 8))
        for index in range(129):
            self.memory.put_qword(pointers + index * 8, RESULT)
        self.memory.put_qword(WAR + 0xF0, pointers)
        self.memory.put_qword(WAR + 0xF8, pointers + 128 * 8)
        self.memory.put_qword(WAR + 0x100, pointers + 128 * 8)
        with patch.object(probe, "_read_result", return_value={"status": "observed", "complete": True}):
            normal = probe._read_result_collection(reader, BASE, DATABASE, WAR, 128, "normal128")
            self.assertEqual(normal["status"], "observed")
            self.assertFalse(normal["truncated"])
            self.memory.put_qword(WAR + 0xF8, pointers + 129 * 8)
            self.memory.put_qword(WAR + 0x100, pointers + 129 * 8)
            collection = probe._read_result_collection(reader, BASE, DATABASE, WAR, 128, "truncated")
        self.assertEqual(collection["status"], "observed_truncated")
        self.assertTrue(collection["truncated"])
        self.memory.put(HISTORY_ROOT + probe.HISTORY_CHILDREN_OFFSET, b"\0" * 8)
        self.memory.put_qword(HISTORY_ROOT + probe.HISTORY_CHILDREN_OFFSET, HISTORY_NODE)
        self.memory.put_qword(HISTORY_NODE + 0x0, HISTORY_EVENT)
        self.memory.put_qword(HISTORY_NODE + 0x10, 0)
        self.memory.put_qword(HISTORY_EVENT, BASE + probe.HISTORY_VTABLE_EVENT_RVA)
        self.memory.put_dword(HISTORY_EVENT + probe.HISTORY_CHILD_DATE_OFFSET, 14551114, signed=True)
        self.memory.put_qword(HISTORY_EVENT + probe.HISTORY_EVENT_OWNER_OFFSET, WAR)
        self.memory.put_qword(HISTORY_EVENT + probe.HISTORY_EVENT_RESULT_OFFSET, RESULT)
        history = probe._read_history(reader, BASE, WAR, HISTORY_ROOT, [RESULT], "date")
        self.assertEqual(history["status"], "observed")
        self.assertEqual(history["bound_result_dates"][hex(RESULT)]["raw"], 14551114)
        self.memory.put_qword(HISTORY_NODE + 0x10, HISTORY_NODE_2)
        self.memory.put_qword(HISTORY_NODE_2 + 0x0, HISTORY_EVENT_2)
        self.memory.put_qword(HISTORY_NODE_2 + 0x10, 0)
        self.memory.put_qword(HISTORY_EVENT_2, BASE + probe.HISTORY_VTABLE_EVENT_RVA)
        self.memory.put_dword(HISTORY_EVENT_2 + probe.HISTORY_CHILD_DATE_OFFSET, 14551115, signed=True)
        self.memory.put_qword(HISTORY_EVENT_2 + probe.HISTORY_EVENT_OWNER_OFFSET, WAR)
        self.memory.put_qword(HISTORY_EVENT_2 + probe.HISTORY_EVENT_RESULT_OFFSET, RESULT)
        ambiguous = probe._read_history(reader, BASE, WAR, HISTORY_ROOT, [RESULT], "ambiguous")
        self.assertEqual(ambiguous["status"], "unknown")
        self.assertIn(hex(RESULT), ambiguous["ambiguous_result_dates"])
        self.assertIn("history_result_date_ambiguous", ambiguous["unknown_conditions"])
        self.memory.put_qword(HISTORY_NODE + 0x10, HISTORY_NODE)
        history = probe._read_history(reader, BASE, WAR, HISTORY_ROOT, [RESULT], "cycle")
        self.assertIn("history_node_cycle", history["unknown_conditions"])

    def test_vector_bounds_and_history_vtable_guard(self) -> None:
        reader = probe.AddressBoundedRPM(self.kernel, 7, BASE)
        collection = probe._read_result_collection(reader, BASE, DATABASE, WAR, 1, "test")
        self.assertEqual(collection["status"], "observed")
        self.memory.put_qword(WAR + 0xF8, RESULT_VECTOR + 7)
        collection = probe._read_result_collection(reader, BASE, DATABASE, WAR, 1, "bad")
        self.assertEqual(collection["status"], "unknown")
        self.memory.put_qword(WAR + 0xF8, RESULT_VECTOR + 8)
        self.memory.put_qword(ROOT_VTABLE + 0x98, BASE + 0x111111)
        history = probe._read_history(reader, BASE, WAR, HISTORY_ROOT, [RESULT], "bad-history")
        self.assertEqual(history["status"], "unknown")
        self.assertIn("history_root_vtable_slots_unsupported", history["unknown_conditions"])


if __name__ == "__main__":
    import unittest

    unittest.main()
