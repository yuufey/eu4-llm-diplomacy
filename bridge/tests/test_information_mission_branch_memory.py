"""分支输入读取器的有界 fake RPM 回归。"""
from __future__ import annotations

import ctypes as C
import json
from pathlib import Path
import tempfile
import unittest
from typing import Any
from unittest.mock import patch

from bridge.information import mission_branch_memory as br


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

    def dword_put(self, address: int, value: int, *, signed: bool = False) -> None:
        self.put(address, int(value).to_bytes(4, "little", signed=signed))

    def word_put(self, address: int, value: int, *, signed: bool = False) -> None:
        self.put(address, int(value).to_bytes(2, "little", signed=signed))

    def read(self, address: int, size: int, label: str) -> bytes:
        if size <= 0 or any(address + offset not in self.memory for offset in range(size)):
            raise br.ProbeError(f"fake_missing:{label}")
        self.bytes_requested += size
        self.calls += 1
        return bytes(self.memory[address + offset] for offset in range(size))

    def read_code(self, address: int, size: int, label: str) -> bytes:
        return self.read(address, size, label)

    def qword(self, address: int, label: str) -> tuple[int, bytes]:
        raw = self.read(address, 8, label)
        return int.from_bytes(raw, "little"), raw


class StrictAlignmentReader(FakeReader):
    """普通 read 拒绝非对齐地址，read_code 允许字节读取。"""

    def read(self, address: int, size: int, label: str) -> bytes:
        if address % 8:
            raise br.ProbeError(f"strict_alignment:{label}")
        return super().read(address, size, label)

    def read_code(self, address: int, size: int, label: str) -> bytes:
        return FakeReader.read(self, address, size, label)


class FakeRPMKernel:
    def __init__(self, memory: dict[int, int]):
        self.memory = memory

    def ReadProcessMemory(self, _handle: int, address: C.c_void_p, buffer: Any, size: int, actual: Any) -> bool:
        base = int(address.value)
        try:
            payload = bytes(self.memory[base + offset] for offset in range(size))
        except KeyError:
            return False
        C.memmove(buffer, payload, size)
        actual._obj.value = size
        return True


def write_string32(
    reader: FakeReader,
    address: int,
    text: str,
    *,
    heap: bool = False,
    heap_address: int | None = None,
) -> None:
    payload = text.encode("ascii") + b"\x00"
    length = len(text.encode("ascii"))
    header = bytearray(32)
    if heap:
        heap_address = address + 0x1000 if heap_address is None else heap_address
        reader.put(address, bytes(32))
        reader.qword_put(address, heap_address)
        reader.put(heap_address, payload)
        capacity = max(length, 16)
    else:
        if len(payload) > 16:
            raise ValueError("inline String32 test payload is too long")
        header[:len(payload)] = payload
        reader.put(address, header)
        capacity = max(length, 1)
    reader.qword_put(address + br.STRING_LENGTH_OFFSET, length)
    reader.qword_put(address + br.STRING_CAPACITY_OFFSET, capacity)


def base_reader(
    names: list[str] | None = None,
    *,
    mode: int = 0,
    domination_byte: int = 1,
    override_byte: int = 0,
) -> tuple[FakeReader, int, int]:
    names = [] if names is None else list(names)
    module = 0x140000000
    game = 0x200000
    database = 0x300000
    country_table = 0x400000
    country = 0x500000
    reader = FakeReader(module)

    # GAME_RVA and MAP_GLOBAL_RVA are the same verified global cell.
    reader.qword_put(module + br.GAME_RVA, game)
    reader.qword_put(game + br.GAME_DATE_OFFSET, 56553384)
    map_context = 0x810000
    reader.qword_put(game + br.MAP_CONTEXT_OFFSET, map_context)
    reader.dword_put(map_context + br.MAP_MODE_OFFSET, mode)

    reader.qword_put(module + br.DATABASE_RVA, database)
    reader.qword_put(database + br.COUNTRY_TABLE_OFFSET, country_table)
    reader.put(country_table, bytes(br.INITIAL_COUNTRY_TABLE_ENTRIES * 8))
    reader.qword_put(country_table + 122 * 8, country)
    reader.qword_put(country + br.COUNTRY_HANDLE_OFFSET, (122 << 32) | int.from_bytes(b"FRA", "little"))

    vtable = module + br.FLAGS_VTABLE_RVA
    reader.qword_put(country + br.FLAGS_OFFSET, vtable)
    reader.qword_put(vtable + 8, module + br.FLAGS_THUNK_RVA)
    reader.qword_put(vtable + 0x10, module + br.FLAGS_BODY_RVA)

    begin = 0x600000
    table = 0x900000
    reader.qword_put(module + br.FLAGS_TABLE_RVA, table)
    for index, name in enumerate(names):
        flag_id = 100 + index
        reader.word_put(begin + index * 2, flag_id)
        write_string32(
            reader,
            table + flag_id * br.FLAGS_ENTRY_STRIDE,
            name,
            heap=len(name) >= 16,
            heap_address=0xA00000 + index * 0x1000,
        )
    reader.qword_put(country + br.FLAGS_OFFSET + br.FLAGS_BEGIN_OFFSET, begin if names else 0)
    reader.qword_put(country + br.FLAGS_OFFSET + br.FLAGS_END_OFFSET, begin + len(names) * 2 if names else 0)
    reader.put(module + br.DOMINATION_GLOBAL_BOOL_RVA, bytes([domination_byte]))
    reader.put(module + br.DOMINATION_OVERRIDE_BYTE_RVA, bytes([override_byte]))
    populate_code_guards(reader)
    return reader, module, country


def populate_code_guards(reader: FakeReader) -> None:
    for _name, rva, expected in br._profile_code_guards():
        reader.put(reader.module_base + rva, expected)


class FakeCloseKernel:
    def __init__(self, result: bool = True, error: Exception | None = None):
        self.result = result
        self.error = error
        self.closed_handles: list[int] = []

    def CloseHandle(self, handle: int) -> bool:
        self.closed_handles.append(handle)
        if self.error is not None:
            raise self.error
        return self.result

    def OpenProcess(self, _access: int, _inherit: bool, _pid: int) -> int:
        return 123


class MissionBranchMemoryTests(unittest.TestCase):
    def test_profile_and_runtime_code_guards(self) -> None:
        static = br._static_contract_guard()
        self.assertEqual(static["status"], "observed")
        self.assertTrue(all(static["checks"].values()))
        self.assertEqual(
            static["provenance"]["source_evidence"]["domination_short_circuit_contract"]["schema"],
            "information.domination.short-circuit-contract.v1",
        )

        reader, module, _country = base_reader()
        runtime = br._runtime_code_guard(reader, module)
        self.assertEqual(runtime["status"], "observed")
        first_name, first_rva, _expected = br._profile_code_guards()[0]
        reader.memory[module + first_rva] ^= 1
        tampered = br._runtime_code_guard(reader, module)
        self.assertEqual(tampered["status"], "mismatch")
        self.assertFalse(tampered["checks"][first_name])

        guarded = dict((name, (rva, expected)) for name, rva, expected in br._profile_code_guards())
        domination_rva, domination_expected = guarded["domination_helper"]
        reader, module, _country = base_reader()
        reader.memory[module + domination_rva] ^= 1
        domination_tampered = br._runtime_code_guard(reader, module)
        self.assertEqual(domination_tampered["status"], "mismatch")
        self.assertFalse(domination_tampered["checks"]["domination_helper"])

    def test_empty_flags_are_known_false_and_map_normal(self) -> None:
        reader, module, _country = base_reader([], mode=0)
        snapshot = br._snapshot(reader, module, "FRA")
        self.assertEqual(snapshot["status"], "observed")
        self.assertEqual(snapshot["country_flags"]["status"], "observed")
        self.assertTrue(snapshot["country_flags"]["provenance"]["empty"])
        self.assertEqual(snapshot["map_setup"]["name"], "normal")
        for value in snapshot["country_flags"]["target_flags"].values():
            self.assertTrue(value["known"])
            self.assertFalse(value["value"])

    def test_nonempty_flags_expose_only_targets_and_map_random(self) -> None:
        first = br.TARGET_FLAGS[0]
        fourth = br.TARGET_FLAGS[3]
        reader, module, _country = base_reader([first, "unrelated_runtime_flag", fourth], mode=2)
        snapshot = br._snapshot(reader, module, "FRA")
        self.assertEqual(snapshot["status"], "observed")
        target = snapshot["country_flags"]["target_flags"]
        self.assertTrue(target[first]["value"])
        self.assertTrue(target[fourth]["value"])
        self.assertFalse(target[br.TARGET_FLAGS[1]]["value"])
        self.assertEqual(snapshot["map_setup"]["value"], 2)
        public = json.dumps(br._without_private(snapshot), ensure_ascii=False)
        self.assertNotIn("unrelated_runtime_flag", public)

    def test_bad_pointer_fails_closed_without_false_flags(self) -> None:
        reader, module, country = base_reader([br.TARGET_FLAGS[0]])
        reader.qword_put(module + br.FLAGS_TABLE_RVA, 0x1234)
        snapshot = br._snapshot(reader, module, "FRA")
        self.assertEqual(snapshot["status"], "unknown")
        self.assertTrue(all(not item["known"] for item in snapshot["country_flags"]["target_flags"].values()))

    def test_odd_span_and_negative_id_are_unknown(self) -> None:
        reader, module, country = base_reader([br.TARGET_FLAGS[0]])
        object_address = country + br.FLAGS_OFFSET
        begin = int.from_bytes(reader.read(object_address + br.FLAGS_BEGIN_OFFSET, 8, "begin"), "little")
        reader.qword_put(object_address + br.FLAGS_END_OFFSET, begin + 1)
        odd = br._snapshot(reader, module, "FRA")
        self.assertEqual(odd["status"], "unknown")
        self.assertIn("flags_byte_span_odd", odd["unknown_conditions"])

        reader, module, country = base_reader([br.TARGET_FLAGS[0]])
        begin = int.from_bytes(reader.read(country + br.FLAGS_OFFSET + br.FLAGS_BEGIN_OFFSET, 8, "begin"), "little")
        reader.word_put(begin, -1, signed=True)
        negative = br._snapshot(reader, module, "FRA")
        self.assertEqual(negative["status"], "unknown")
        self.assertIn("flags_negative_id", negative["unknown_conditions"])

    def test_unknown_map_mode_is_not_coerced(self) -> None:
        reader, module, _country = base_reader([], mode=4)
        snapshot = br._snapshot(reader, module, "FRA")
        self.assertEqual(snapshot["status"], "unknown")
        self.assertFalse(snapshot["map_setup"]["known"])
        self.assertIsNone(snapshot["map_setup"]["value"])

    def test_domination_short_circuit_requires_nonzero_domination_and_zero_override(self) -> None:
        cases = (
            (1, 0, True, None),
            (255, 0, True, None),
            (0, 0, False, br.DOMINATION_UNKNOWN_REASON),
            (1, 1, False, br.DOMINATION_UNKNOWN_REASON),
        )
        for domination_byte, override_byte, known, reason in cases:
            with self.subTest(domination_byte=domination_byte, override_byte=override_byte):
                reader, module, _country = base_reader(
                    [], domination_byte=domination_byte, override_byte=override_byte
                )
                result = br._read_domination(reader, module)
                self.assertEqual(result["known"], known)
                self.assertEqual(result["value"], True if known else None)
                self.assertEqual(result["unknown_reason"], reason)
                self.assertEqual(result["raw_domination_byte"], domination_byte)
                self.assertEqual(result["raw_override_byte"], override_byte)

    def test_domination_byte_reads_use_unaligned_bounded_rpm_path(self) -> None:
        source, module, _country = base_reader([], domination_byte=2, override_byte=0)
        strict = StrictAlignmentReader(module)
        strict.memory.update(source.memory)
        result = br._read_domination(strict, module)
        self.assertEqual(result["status"], "observed")
        self.assertTrue(result["known"])
        self.assertEqual(result["raw_domination_byte"], 2)
        self.assertEqual(result["raw_override_byte"], 0)

        rpm = br._mission_memory.BoundedRPM(FakeRPMKernel(source.memory), 123, module)
        with self.assertRaises(br._mission_memory.ProbeError):
            rpm.read(module + br.DOMINATION_GLOBAL_BOOL_RVA, 1, "aligned_domination_should_reject")
        self.assertEqual(
            br._read_unaligned(rpm, module + br.DOMINATION_GLOBAL_BOOL_RVA, 1, "domination.global_bool"),
            b"\x02",
        )
        with self.assertRaises(br._mission_memory.ProbeError):
            br._read_unaligned(rpm, 0x1234, 1, "invalid_domination_pointer")

    def test_domination_bytes_are_part_of_doublepass_consistency(self) -> None:
        reader, module, _country = base_reader([], domination_byte=1, override_byte=0)
        before = br._snapshot(reader, module, "FRA")
        reader.put(module + br.DOMINATION_GLOBAL_BOOL_RVA, b"\x00")
        after = br._snapshot(reader, module, "FRA")
        mismatches = br._diff_paths(br._comparison_view(before), br._comparison_view(after))
        self.assertIn("$.has_domination.global_bool", mismatches)
        self.assertEqual(before["status"], "observed")
        self.assertEqual(after["status"], "observed")
        self.assertTrue(after["country_flags"]["target_flags"][br.TARGET_FLAGS[0]]["known"])
        self.assertTrue(after["map_setup"]["known"])

    def test_doublepass_detects_date_flag_or_mode_change(self) -> None:
        reader, module, _country = base_reader([br.TARGET_FLAGS[0]], mode=0)
        before = br._snapshot(reader, module, "FRA")
        reader.dword_put(0x200000 + br.GAME_DATE_OFFSET, 56553385)
        reader.dword_put(0x810000 + br.MAP_MODE_OFFSET, 1)
        after = br._snapshot(reader, module, "FRA")
        mismatches = br._diff_paths(br._comparison_view(before), br._comparison_view(after))
        self.assertTrue(mismatches)
        self.assertIn("$.game_date", mismatches)
        self.assertIn("$.map_setup.mode", mismatches)

    def test_close_failure_is_terminal_and_handle_closes_once(self) -> None:
        report = br._base_report(Path("missing.json"), "FRA")
        report["status"] = "observed"
        kernel = FakeCloseKernel(result=False)
        br._apply_cleanup(report, kernel, 123)
        self.assertEqual(kernel.closed_handles, [123])
        self.assertEqual(report["cleanup"]["handle_close"]["status"], "error")
        self.assertEqual(report["status"], "cleanup_error")
        br._invalidate_inputs_after_cleanup_failure(report)
        self.assertFalse(report["inputs"]["has_domination"]["known"])
        self.assertIsNone(report["inputs"]["has_domination"]["value"])

        unopened = br._base_report(Path("missing.json"), "FRA")
        unopened["status"] = "unsupported_country"
        br._apply_cleanup(unopened, None, None)
        self.assertEqual(unopened["cleanup"]["handle_close"]["status"], "not_opened")
        self.assertEqual(unopened["status"], "unsupported_country")

    def test_profile_tamper_and_size_limits_fail_closed(self) -> None:
        raw = br.PROFILE_FILE.read_bytes()
        with tempfile.TemporaryDirectory() as directory:
            tampered = Path(directory) / "tampered.json"
            altered = bytearray(raw)
            altered[-2] ^= 1
            tampered.write_bytes(altered)
            with self.assertRaises(br.ProfileError):
                br._load_profile(tampered, br.EXPECTED_PROFILE_SHA256)
            oversized = Path(directory) / "oversized.json"
            oversized.write_bytes(b"x" * (br.PROFILE_MAX_BYTES + 1))
            with self.assertRaises(br.ProfileError):
                br._load_profile(oversized, br.EXPECTED_PROFILE_SHA256)

    def test_scope_is_fra_only_without_opening_a_handle(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report = br.capture_inputs(Path(directory) / "missing-installation.json", "ENG")
            self.assertEqual(report["status"], "unsupported_country")
            self.assertEqual(report["cleanup"]["handle_close"]["status"], "not_opened")
            self.assertTrue(all(not item["known"] for item in report["inputs"]["country_flags"].values()))

    def test_capture_inputs_fake_process_publishes_only_stable_targets(self) -> None:
        reader, module, _country = base_reader([br.TARGET_FLAGS[0]], mode=3)
        kernel = FakeCloseKernel()
        installation = {"pid": 123, "creation_filetime": 456, "game_sha256": br.EXPECTED_EXE_SHA256}

        def fake_identity(report, _document, _kernel, _handle):
            report["module_base"] = br._address(module)
            report["identity"]["binding_verified"] = True
            return module

        with patch.object(br, "_load_installation", return_value=installation), \
             patch.object(br, "_configure_kernel", return_value=kernel), \
             patch.object(br, "_capture_identity", side_effect=fake_identity), \
             patch.object(br._mission_memory, "BoundedRPM", return_value=reader):
            report = br.capture_inputs(Path("fake-installation.json"), "FRA")

        self.assertEqual(report["status"], "observed")
        self.assertTrue(report["doublepass"]["consistent"])
        self.assertEqual(report["inputs"]["map_setup"]["name"], "custom")
        self.assertTrue(report["inputs"]["country_flags"][br.TARGET_FLAGS[0]]["value"])
        self.assertTrue(report["inputs"]["has_domination"]["known"])
        self.assertTrue(report["inputs"]["has_domination"]["value"])
        self.assertEqual(kernel.closed_handles, [123])

    def test_capture_inputs_keeps_flags_and_map_when_domination_requires_tls(self) -> None:
        reader, module, _country = base_reader(
            [br.TARGET_FLAGS[0]], mode=3, domination_byte=1, override_byte=1
        )
        kernel = FakeCloseKernel()
        installation = {"pid": 123, "creation_filetime": 456, "game_sha256": br.EXPECTED_EXE_SHA256}

        def fake_identity(report, _document, _kernel, _handle):
            report["module_base"] = br._address(module)
            report["identity"]["binding_verified"] = True
            return module

        with patch.object(br, "_load_installation", return_value=installation), \
             patch.object(br, "_configure_kernel", return_value=kernel), \
             patch.object(br, "_capture_identity", side_effect=fake_identity), \
             patch.object(br._mission_memory, "BoundedRPM", return_value=reader):
            report = br.capture_inputs(Path("fake-installation.json"), "FRA")

        self.assertEqual(report["status"], "observed")
        self.assertTrue(report["inputs"]["country_flags"][br.TARGET_FLAGS[0]]["known"])
        self.assertTrue(report["inputs"]["map_setup"]["known"])
        self.assertFalse(report["inputs"]["has_domination"]["known"])
        self.assertIsNone(report["inputs"]["has_domination"]["value"])
        self.assertEqual(
            report["inputs"]["has_domination"]["unknown_reason"],
            br.DOMINATION_UNKNOWN_REASON,
        )
        self.assertEqual(kernel.closed_handles, [123])

    def test_capture_inputs_close_failure_withholds_inputs_but_keeps_observation(self) -> None:
        reader, module, _country = base_reader([br.TARGET_FLAGS[0]], mode=3)
        kernel = FakeCloseKernel(result=False)
        installation = {"pid": 123, "creation_filetime": 456, "game_sha256": br.EXPECTED_EXE_SHA256}

        def fake_identity(report, _document, _kernel, _handle):
            report["module_base"] = br._address(module)
            report["identity"]["binding_verified"] = True
            return module

        with patch.object(br, "_load_installation", return_value=installation), \
             patch.object(br, "_configure_kernel", return_value=kernel), \
             patch.object(br, "_capture_identity", side_effect=fake_identity), \
             patch.object(br._mission_memory, "BoundedRPM", return_value=reader):
            report = br.capture_inputs(Path("fake-installation.json"), "FRA")

        self.assertEqual(report["status"], "cleanup_error")
        self.assertEqual(report["cleanup"]["handle_close"]["status"], "error")
        self.assertEqual(kernel.closed_handles, [123])
        self.assertTrue(report["before"]["country_flags"]["target_flags"][br.TARGET_FLAGS[0]]["known"])
        self.assertTrue(report["before"]["map_setup"]["known"])
        self.assertTrue(all(not item["known"] for item in report["inputs"]["country_flags"].values()))
        self.assertTrue(all(item["value"] is None for item in report["inputs"]["country_flags"].values()))
        self.assertFalse(report["inputs"]["map_setup"]["known"])
        self.assertIsNone(report["inputs"]["map_setup"]["value"])
        self.assertFalse(report["inputs"]["has_domination"]["known"])
        self.assertIsNone(report["inputs"]["has_domination"]["value"])


if __name__ == "__main__":
    unittest.main()
