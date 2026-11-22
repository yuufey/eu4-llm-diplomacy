"""Bounded regression tests for the native localisation lookup reader."""
from __future__ import annotations

import ctypes as C
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from bridge.information import localization_memory as lm
from bridge.information import mission_memory as mm
from bridge.tests.test_information_mission_memory import FakeReader, base_reader


def _write_language(reader: FakeReader, address: int, text: str) -> None:
    payload = text.encode("ascii") + b"\x00"
    header = bytearray(32)
    header[: len(payload)] = payload
    reader.put(address, header)
    reader.qword_put(address + 0x10, len(text))
    reader.qword_put(address + 0x18, max(1, len(text)))


def _write_pool(reader: FakeReader, begin: int, values: list[bytes]) -> tuple[int, dict[str, int]]:
    offsets: dict[str, int] = {}
    cursor = 0
    for key, value in values:
        offsets[key] = cursor
        reader.put(begin + cursor, value + b"\x00")
        cursor += len(value) + 1
    return cursor, offsets


def localization_fixture(
    values: dict[str, bytes] | None = None,
    *,
    table_hashes: list[tuple[int, int]] | None = None,
) -> tuple[FakeReader, int, dict[str, int]]:
    reader, module, _country = base_reader()
    for _name, rva, expected in lm._profile_code_guards():
        reader.put(module + rva, expected)

    outer = 0x800000
    inner = 0x810000
    table = 0x820000
    pool = 0x830000
    values = values or {"name": b"Normandy", "desc": b"A cached template [Root.GetName]"}
    pool_length, offsets = _write_pool(reader, pool, list(values.items()))
    reader.qword_put(module + lm.LOCALIZATION_GLOBAL_CELL_RVA, outer)
    reader.qword_put(outer + lm.OUTER_INNER_OFFSET, inner)
    reader.qword_put(outer + lm.POOL_BEGIN_OFFSET, pool)
    reader.qword_put(outer + lm.POOL_END_OFFSET, pool + pool_length)
    reader.qword_put(outer + lm.POOL_CAPACITY_END_OFFSET, pool + pool_length + 0x100)
    _write_language(reader, inner, "l_english")

    entries = table_hashes
    if entries is None:
        entries = sorted((lm._fnv1_ascii(key), offset) for key, offset in offsets.items())
    reader.qword_put(inner + lm.INNER_TABLE_BEGIN_OFFSET, table)
    reader.qword_put(inner + lm.INNER_TABLE_END_OFFSET, table + len(entries) * lm.TABLE_ENTRY_STRIDE)
    reader.qword_put(inner + lm.INNER_TABLE_CAPACITY_OFFSET, table + (len(entries) + 2) * lm.TABLE_ENTRY_STRIDE)
    for index, (hash_value, offset) in enumerate(entries):
        reader.qword_put(table + index * lm.TABLE_ENTRY_STRIDE, hash_value)
        reader.qword_put(table + index * lm.TABLE_ENTRY_STRIDE + lm.TABLE_ENTRY_OFFSET_OFFSET, offset)
    return reader, module, offsets


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


class BudgetReader(FakeReader):
    """Reject the first read that would exceed the native RPM budget."""

    def __init__(self, *args, read_limit: int = 64, **kwargs):
        super().__init__(*args, **kwargs)
        self.read_limit = read_limit

    def read(self, address: int, size: int, label: str) -> bytes:
        if self.bytes_requested + size > self.read_limit:
            raise lm.ProbeError("rpm_total_limit_exceeded")
        return super().read(address, size, label)


def _observed_guard() -> dict[str, object]:
    return {"status": "observed", "checks": {}, "records": {}, "unknown_conditions": []}


class LocalizationMemoryTests(unittest.TestCase):
    def test_profile_and_full_code_guards(self):
        guard = lm._static_contract_guard()
        self.assertEqual(guard["status"], "observed")
        self.assertTrue(all(guard["checks"].values()))
        self.assertEqual([(name, size) for name, _rva, raw in lm._profile_code_guards() for size in [len(raw)]], [("key_hash_lookup_body", 538), ("hash_lookup_helper", 131)])
        reader, module, _ = localization_fixture()
        self.assertEqual(lm._runtime_code_guard(reader, module)["status"], "observed")
        name, rva, _raw = lm._profile_code_guards()[0]
        reader.memory[module + rva] ^= 1
        result = lm._runtime_code_guard(reader, module)
        self.assertEqual(result["status"], "mismatch")
        self.assertFalse(result["checks"][name])

    def test_fnv1_and_native_hash_only_lookup(self):
        self.assertEqual(lm._fnv1_ascii("name"), 0x2F8B3BF4)
        reader, module, _ = localization_fixture()
        snapshot = lm._snapshot(reader, module, "FRA", ["name", "desc", "missing"])
        self.assertEqual(snapshot["status"], "observed")
        self.assertEqual(snapshot["localization"]["language"]["text"], "l_english")
        self.assertEqual(snapshot["entries"]["name"]["status"], "observed")
        self.assertEqual(snapshot["entries"]["name"]["value_hex"], b"Normandy".hex())
        self.assertNotIn("value", snapshot["entries"]["name"])
        self.assertNotIn("encoding", snapshot["entries"]["name"])
        self.assertTrue(snapshot["entries"]["desc"]["native_cached_template"])
        self.assertIn(b"[Root.GetName]".hex(), snapshot["entries"]["desc"]["value_hex"])
        self.assertEqual(snapshot["entries"]["missing"]["status"], "unknown")
        self.assertEqual(snapshot["entries"]["missing"]["unknown_reason"], "localization_key_not_found")

        reader, module, _ = localization_fixture({"binary": b"\xff\xfe"})
        binary = lm._snapshot(reader, module, "FRA", ["binary"])["entries"]["binary"]
        self.assertEqual(binary["status"], "observed")
        self.assertEqual(binary["raw_hex"], "fffe")
        self.assertNotIn("value", binary)
        self.assertNotIn("encoding", binary)
        self.assertNotIn("unknown_reason", binary)

    def test_table_capacity_is_recorded_but_not_claimed_as_a_bound(self):
        reader, module, _ = localization_fixture()
        reader.qword_put(0x810000 + lm.INNER_TABLE_CAPACITY_OFFSET, 0x81FFF0)
        snapshot = lm._snapshot(reader, module, "FRA", ["name"])
        self.assertEqual(snapshot["status"], "observed")
        table = snapshot["localization"]["table"]
        self.assertEqual(table["capacity"]["value"], hex(0x81FFF0))
        self.assertFalse(table["capacity_bounds_verified"])
        self.assertEqual(table["capacity_unknown_reason"], "table_capacity_semantics_unverified")

    def test_large_primary_table_uses_bounded_binary_search(self):
        reader, module, _ = localization_fixture({"name": b"Normandy"})
        reader.qword_put(0x810000 + lm.INNER_TABLE_END_OFFSET, 0x820000 + 126787 * lm.TABLE_ENTRY_STRIDE)
        snapshot = lm._snapshot(reader, module, "FRA", ["missing"])
        self.assertEqual(snapshot["status"], "observed")
        self.assertEqual(snapshot["localization"]["table"]["count"], 126787)
        self.assertLess(snapshot["localization"]["table"]["count"], lm.MAX_TABLE_ENTRIES)
        # The fake reader would make a full scan visible immediately.
        self.assertLess(reader.calls, 60)

    def test_pool_bounds_and_capacity_are_checked(self):
        reader, module, _ = localization_fixture()
        reader.qword_put(0x800000 + lm.POOL_END_OFFSET, 0x830000 - 1)
        snapshot = lm._snapshot(reader, module, "FRA", ["name"])
        self.assertEqual(snapshot["status"], "unknown")
        self.assertIn("localization_value_pool_bounds_invalid", snapshot["unknown_conditions"])

        reader, module, _ = localization_fixture()
        reader.qword_put(0x800000 + lm.POOL_END_OFFSET, 0x830000 + 3)
        snapshot = lm._snapshot(reader, module, "FRA", ["name"])
        self.assertEqual(snapshot["status"], "unknown")
        self.assertIn("localization_snapshot_failed:localization_value_nul_not_observed_within_8192", snapshot["unknown_conditions"])

        reader, module, _ = localization_fixture()
        reader.qword_put(0x800000 + lm.POOL_CAPACITY_END_OFFSET, 0x830000 + 1)
        snapshot = lm._snapshot(reader, module, "FRA", ["name"])
        self.assertEqual(snapshot["status"], "unknown")
        self.assertIn("localization_value_pool_bounds_invalid", snapshot["unknown_conditions"])

    def test_odd_table_span_and_bad_pointers_fail_closed(self):
        reader, module, _ = localization_fixture()
        reader.qword_put(0x810000 + lm.INNER_TABLE_END_OFFSET, 0x820000 + 15)
        snapshot = lm._snapshot(reader, module, "FRA", ["name"])
        self.assertEqual(snapshot["status"], "unknown")
        self.assertIn("localization_table_span_invalid", snapshot["unknown_conditions"])

        reader, module, _ = localization_fixture()
        reader.qword_put(module + lm.LOCALIZATION_GLOBAL_CELL_RVA, 0x12345)
        snapshot = lm._snapshot(reader, module, "FRA", ["name"])
        self.assertEqual(snapshot["status"], "unknown")
        self.assertIn("localization_outer_pointer_invalid", snapshot["unknown_conditions"])

        reader, module, _ = localization_fixture({})
        reader.qword_put(0x800000 + lm.POOL_BEGIN_OFFSET, 0)
        reader.qword_put(0x800000 + lm.POOL_END_OFFSET, 0)
        reader.qword_put(0x800000 + lm.POOL_CAPACITY_END_OFFSET, 0)
        reader.qword_put(0x810000 + lm.INNER_TABLE_BEGIN_OFFSET, 0)
        reader.qword_put(0x810000 + lm.INNER_TABLE_END_OFFSET, 0)
        snapshot = lm._snapshot(reader, module, "FRA", ["missing"])
        self.assertEqual(snapshot["status"], "observed")
        self.assertEqual(snapshot["entries"]["missing"]["unknown_reason"], "localization_key_not_found")

    def test_duplicate_or_unsorted_adjacent_hashes_are_unknown(self):
        duplicate = [(lm._fnv1_ascii("name"), 0), (lm._fnv1_ascii("name"), 1)]
        reader, module, _ = localization_fixture({"name": b"a"}, table_hashes=duplicate)
        snapshot = lm._snapshot(reader, module, "FRA", ["name"])
        self.assertEqual(snapshot["status"], "unknown")
        self.assertIn("localization_snapshot_failed:localization_table_order_or_duplicate_hash", snapshot["unknown_conditions"])

    def test_two_pass_diff_and_cleanup_retract(self):
        reader, module, _ = localization_fixture()
        first = lm._snapshot(reader, module, "FRA", ["name"])
        reader.put(0x830000, b"Changed\x00")
        second = lm._snapshot(reader, module, "FRA", ["name"])
        self.assertTrue(any("value_raw_hex" in path for path in lm._diff_paths(first["_compare"], second["_compare"])))

        report = lm._base_report(Path("missing.json"), "FRA", ["name"])
        report["status"] = "observed"
        kernel = FakeCaptureKernel(module, close_result=False)
        outcome = lm._close_process_handle(kernel, 0x1234)
        self.assertEqual(kernel.closed, [0x1234])
        self.assertEqual(outcome["status"], "error")
        report["cleanup"]["handle_close"] = outcome
        report["status"] = "cleanup_error"
        report["entries"] = lm._unknown_entries(["name"], "handle_close_failed")
        self.assertEqual(report["entries"]["name"]["status"], "unknown")

    def test_capture_control_flow_identity_guards_and_close_failure(self):
        reader, module, _ = localization_fixture()
        kernel = FakeCaptureKernel(module, close_result=False)
        document = {"pid": 123, "creation_filetime": 987, "game_sha256": lm.EXPECTED_EXE_SHA256, "session_id": "fake-session"}
        with patch.object(lm, "_load_installation", return_value=document), patch.object(lm, "_configure_kernel", return_value=kernel), patch.object(lm, "_sha256_file", return_value=lm.EXPECTED_EXE_SHA256), patch.object(lm, "_file_code_guard", return_value=_observed_guard()), patch.object(lm, "_runtime_code_guard", return_value=_observed_guard()), patch.object(lm, "BoundedRPM", return_value=reader):
            report = lm.capture(Path("fake-installation.json"), "FRA", ["name"])
        self.assertEqual(kernel.closed, [0x1234])
        self.assertEqual(report["status"], "cleanup_error")
        self.assertEqual(report["entries"]["name"]["status"], "unknown")
        self.assertEqual(report["cleanup"]["handle_close"]["status"], "error")

        reader, module, _ = localization_fixture()
        kernel = FakeCaptureKernel(module, close_result=True)
        with patch.object(lm, "_load_installation", return_value=document), patch.object(lm, "_configure_kernel", return_value=kernel), patch.object(lm, "_sha256_file", return_value=lm.EXPECTED_EXE_SHA256), patch.object(lm, "_file_code_guard", return_value=_observed_guard()), patch.object(lm, "_runtime_code_guard", return_value=_observed_guard()), patch.object(lm, "BoundedRPM", return_value=reader):
            observed = lm.capture(Path("fake-installation.json"), "FRA", ["name", "missing"])
        self.assertEqual(observed["status"], "observed")
        self.assertTrue(observed["doublepass"]["consistent"])
        self.assertEqual(observed["entries"]["name"]["value_hex"], b"Normandy".hex())
        self.assertEqual(observed["entries"]["missing"]["unknown_reason"], "localization_key_not_found")
        self.assertEqual(observed["language"]["text"], "l_english")
        self.assertTrue(observed["cleanup"]["handle_close"]["closed"])

    def test_capture_identity_creation_mismatch_closes_and_retracts(self):
        reader, module, _ = localization_fixture()
        kernel = FakeCaptureKernel(module, creation_filetime=988)
        document = {"pid": 123, "creation_filetime": 987, "game_sha256": lm.EXPECTED_EXE_SHA256, "session_id": "fake-session"}
        with patch.object(lm, "_load_installation", return_value=document), patch.object(lm, "_configure_kernel", return_value=kernel), patch.object(lm, "_sha256_file", return_value=lm.EXPECTED_EXE_SHA256), patch.object(lm, "BoundedRPM", return_value=reader):
            report = lm.capture(Path("fake-installation.json"), "FRA", ["name"])
        self.assertEqual(report["status"], "error")
        self.assertEqual(report["entries"]["name"]["status"], "unknown")
        self.assertEqual(kernel.closed, [0x1234])

    def test_capture_file_and_runtime_guards_close_without_publishing(self):
        document = {"pid": 123, "creation_filetime": 987, "game_sha256": lm.EXPECTED_EXE_SHA256, "session_id": "fake-session"}

        reader, module, _ = localization_fixture()
        kernel = FakeCaptureKernel(module)
        bad_file = {"status": "mismatch", "checks": {"key_hash_lookup_body": False}, "records": {}, "unknown_conditions": ["tampered"]}
        with patch.object(lm, "_load_installation", return_value=document), patch.object(lm, "_configure_kernel", return_value=kernel), patch.object(lm, "_sha256_file", return_value=lm.EXPECTED_EXE_SHA256), patch.object(lm, "_file_code_guard", return_value=bad_file), patch.object(lm, "BoundedRPM", return_value=reader), patch.object(lm, "_runtime_code_guard", return_value=_observed_guard()) as runtime_guard:
            report = lm.capture(Path("fake-installation.json"), "FRA", ["name"])
        self.assertEqual(report["status"], "file_code_mismatch")
        self.assertEqual(report["entries"]["name"]["status"], "unknown")
        self.assertEqual(kernel.closed, [0x1234])
        runtime_guard.assert_not_called()

        reader, module, _ = localization_fixture()
        kernel = FakeCaptureKernel(module)
        bad_runtime = {"status": "mismatch", "checks": {"hash_lookup_helper": False}, "records": {}, "unknown_conditions": ["tampered"]}
        with patch.object(lm, "_load_installation", return_value=document), patch.object(lm, "_configure_kernel", return_value=kernel), patch.object(lm, "_sha256_file", return_value=lm.EXPECTED_EXE_SHA256), patch.object(lm, "_file_code_guard", return_value=_observed_guard()), patch.object(lm, "_runtime_code_guard", return_value=bad_runtime), patch.object(lm, "BoundedRPM", return_value=reader):
            report = lm.capture(Path("fake-installation.json"), "FRA", ["name"])
        self.assertEqual(report["status"], "runtime_code_mismatch")
        self.assertEqual(report["entries"]["name"]["status"], "unknown")
        self.assertEqual(kernel.closed, [0x1234])

    def test_capture_doublepass_date_and_value_changes_retract_entries(self):
        document = {"pid": 123, "creation_filetime": 987, "game_sha256": lm.EXPECTED_EXE_SHA256, "session_id": "fake-session"}
        original_snapshot = lm._snapshot
        for change_kind in ("date", "value"):
            with self.subTest(change_kind=change_kind):
                reader, module, _ = localization_fixture()
                kernel = FakeCaptureKernel(module)
                calls = 0

                def changing_snapshot(probe_reader, probe_module, probe_country, probe_keys):
                    nonlocal calls
                    result = original_snapshot(probe_reader, probe_module, probe_country, probe_keys)
                    calls += 1
                    if calls == 1:
                        if change_kind == "date":
                            probe_reader.put(0x200000 + lm.GAME_DATE_OFFSET, (56553385).to_bytes(4, "little", signed=True))
                        else:
                            probe_reader.put(0x830000, b"Changed\x00")
                    return result

                with patch.object(lm, "_load_installation", return_value=document), patch.object(lm, "_configure_kernel", return_value=kernel), patch.object(lm, "_sha256_file", return_value=lm.EXPECTED_EXE_SHA256), patch.object(lm, "_file_code_guard", return_value=_observed_guard()), patch.object(lm, "_runtime_code_guard", return_value=_observed_guard()), patch.object(lm, "BoundedRPM", return_value=reader), patch.object(lm, "_snapshot", side_effect=changing_snapshot):
                    report = lm.capture(Path("fake-installation.json"), "FRA", ["name"])
                self.assertEqual(calls, 2)
                self.assertEqual(report["status"], "doublepass_mismatch")
                self.assertFalse(report["doublepass"]["consistent"])
                self.assertEqual(report["entries"]["name"]["status"], "unknown")
                self.assertEqual(kernel.closed, [0x1234])

    def test_capture_rpm_budget_failure_closes_and_publishes_unknown(self):
        base, module, _ = localization_fixture()
        reader = BudgetReader(module, read_limit=64)
        reader.memory.update(base.memory)
        kernel = FakeCaptureKernel(module)
        document = {"pid": 123, "creation_filetime": 987, "game_sha256": lm.EXPECTED_EXE_SHA256, "session_id": "fake-session"}
        with patch.object(lm, "_load_installation", return_value=document), patch.object(lm, "_configure_kernel", return_value=kernel), patch.object(lm, "_sha256_file", return_value=lm.EXPECTED_EXE_SHA256), patch.object(lm, "_file_code_guard", return_value=_observed_guard()), patch.object(lm, "_runtime_code_guard", return_value=_observed_guard()), patch.object(lm, "BoundedRPM", return_value=reader):
            report = lm.capture(Path("fake-installation.json"), "FRA", ["name"])
        self.assertNotEqual(report["status"], "observed")
        self.assertEqual(report["entries"]["name"]["status"], "unknown")
        self.assertEqual(kernel.closed, [0x1234])

    def test_160_byte_ascii_key_is_within_profile_request_bound(self):
        key = "k" * 160
        self.assertEqual(lm.MAX_KEY_BYTES, 160)
        self.assertIsInstance(lm._fnv1_ascii(key), int)

    def test_request_scope_and_ascii_limits_close_without_opening(self):
        report = lm.capture(Path("missing.json"), "invalid-tag", ["name"])
        self.assertEqual(report["status"], "unsupported_country")
        self.assertEqual(report["cleanup"]["handle_close"]["status"], "not_opened")
        invalid = lm.capture(Path("missing.json"), "FRA", ["bad\u2603"])
        self.assertEqual(invalid["status"], "invalid_request")
        self.assertEqual(invalid["entries"]["bad\u2603"]["status"], "unknown")


if __name__ == "__main__":
    unittest.main()
