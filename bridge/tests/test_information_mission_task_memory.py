"""Bounded regression tests for the optional loaded-task vector reader."""
from __future__ import annotations

import ctypes as C
from contextlib import ExitStack
from pathlib import Path
import unittest
from unittest.mock import patch

from bridge.information import mission_memory as mm
from bridge.information import mission_task_memory as tm
from bridge.tests.test_information_mission_memory import (
    base_reader,
    populate_code_guards,
    write_string32,
)


def populate_task_guards(reader) -> None:
    for _name, rva, expected in tm._profile_code_guards():
        reader.put(reader.module_base + rva, expected)
    for item in tm._profile_vtable_guards():
        for index, entry_rva in enumerate(item["expected_entry_rvas"]):
            reader.qword_put(reader.module_base + item["rva"] + index * 8, reader.module_base + entry_rva)


def task_fixture(task_ids: tuple[str, ...] = ("task_a", "task_b")):
    reader, module, country = base_reader(slots=1, completed="empty")
    populate_code_guards(reader)
    populate_task_guards(reader)

    slot_array = 0x700000
    root_array = 0x710000
    root = 0x720000
    task_array = 0x730000
    reader.qword_put(slot_array + mm.ROOT_ARRAY_OFFSET, root_array)
    reader.dword_put(slot_array + mm.ROOT_COUNT_OFFSET, 1, signed=True)
    reader.qword_put(root_array, root)
    write_string32(reader, root, "root")
    reader.qword_put(root, module + tm.ROOT_VTABLE_RVA)
    reader.qword_put(root + tm.TASK_POINTER_OFFSET, task_array if task_ids else 0)
    reader.dword_put(root + tm.TASK_CAPACITY_OFFSET, max(len(task_ids), 1), signed=True)
    reader.dword_put(root + tm.TASK_COUNT_OFFSET, len(task_ids), signed=True)
    for index, task_id in enumerate(task_ids):
        task = 0x740000 + index * 0x1000
        reader.qword_put(task_array + index * 8, task)
        reader.qword_put(task, module + tm.TASK_VTABLE_RVA)
        write_string32(reader, task, task_id)

    snapshot = mm._snapshot(reader, module, "FRA", False)
    assert snapshot["status"] == "observed"
    return reader, module, snapshot


class FakeCaptureKernel:
    """Minimal kernel surface used to exercise mission_memory.capture control flow."""

    def __init__(self, module_base: int, *, close_result: bool = True):
        self.module_base = module_base
        self.close_result = close_result
        self.closed: list[int] = []
        self.process_path = Path("fake-eu4.exe").resolve()

    def OpenProcess(self, _access, _inherit, _pid):
        return 0x1234

    def QueryFullProcessImageNameW(self, _handle, _flags, buffer, _length):
        buffer.value = str(self.process_path)
        return True

    def GetProcessTimes(self, _handle, creation, _exit_time, _kernel_time, _user_time):
        value = C.cast(creation, C.POINTER(mm.W.FILETIME)).contents
        value.dwLowDateTime = 987
        value.dwHighDateTime = 0
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


def _observed_guard() -> dict[str, object]:
    return {"status": "observed", "checks": {}, "records": {}, "unknown_conditions": []}


def _capture_patches(reader, kernel, *, task_static=None, task_file=None, task_runtime=None, snapshot=None):
    """Return the local patch set used by full capture-path tests."""
    document = {
        "pid": 123,
        "creation_filetime": 987,
        "game_sha256": mm.EXPECTED_EXE_SHA256,
        "session_id": "fake-session",
    }
    original_snapshot = mm._snapshot

    def snapshot_wrapper(*args, **kwargs):
        if snapshot is None:
            return original_snapshot(*args, **kwargs)
        return snapshot(*args, **kwargs)

    return (
        patch.object(mm, "_load_installation", return_value=document),
        patch.object(mm, "_configure_kernel", return_value=kernel),
        patch.object(mm, "_sha256_file", return_value=mm.EXPECTED_EXE_SHA256),
        patch.object(mm, "_file_code_guard", return_value=_observed_guard()),
        patch.object(mm, "_runtime_code_guard", return_value=_observed_guard()),
        patch.object(mm, "BoundedRPM", return_value=reader),
        patch.object(mm, "_snapshot", side_effect=snapshot_wrapper),
        patch.object(tm, "_static_contract_guard", return_value=task_static or _observed_guard()),
        patch.object(tm, "_file_code_guard", return_value=task_file or _observed_guard()),
        patch.object(tm, "_runtime_code_guard", return_value=task_runtime or _observed_guard()),
    )


class LoadedTaskMemoryTests(unittest.TestCase):
    def test_profile_and_relocated_runtime_guards(self):
        reader, module, _snapshot = task_fixture(())
        self.assertEqual(tm._static_contract_guard()["status"], "observed")
        guard = tm._runtime_code_guard(reader, module)
        self.assertEqual(guard["status"], "observed")
        self.assertEqual(guard["records"]["root_vtable_table"]["entry_checks"], [True] * 6)
        self.assertEqual(guard["records"]["task_vtable_table"]["entry_checks"], [True] * 6)
        self.assertEqual(guard["records"]["root_vtable_table"]["expected_entry_rvas"][4], "0x8d7430")
        self.assertEqual(guard["records"]["task_vtable_table"]["expected_entry_rvas"][4], "0x8d5070")

    def test_observes_root_vector_and_task_ids(self):
        reader, module, snapshot = task_fixture(("task_a", "task_b"))
        result = tm.capture_loaded_tasks(reader, module, snapshot["missions"])
        loaded = result["loaded_tasks"]
        self.assertEqual(loaded["status"], "observed")
        self.assertTrue(loaded["complete"])
        self.assertEqual(loaded["total_task_count"], 2)
        root = loaded["roots"][0]
        self.assertEqual(root["root_id"], "root")
        self.assertEqual(root["vector"]["count"], 2)
        self.assertEqual(root["task_ids"], ["task_a", "task_b"])
        self.assertEqual([item["task_id"]["text"] for item in root["tasks"]], ["task_a", "task_b"])
        self.assertEqual(result["_compare"]["roots"][0]["tasks"][1]["task_id"]["text"], "task_b")

    def test_optional_snapshot_integration_preserves_root_status_and_default_reads(self):
        reader, module, _snapshot = task_fixture(("task_a",))
        default = mm._snapshot(reader, module, "FRA", False)
        self.assertEqual(default["status"], "observed")
        self.assertNotIn("loaded_tasks", default)
        with_tasks = mm._snapshot(reader, module, "FRA", False, True)
        self.assertEqual(with_tasks["status"], "observed")
        self.assertEqual(with_tasks["loaded_tasks"]["status"], "observed")
        self.assertEqual(with_tasks["loaded_tasks"]["roots"][0]["tasks"][0]["task_id"]["text"], "task_a")

    def test_empty_vector_is_observed_empty_and_does_not_dereference_zero(self):
        reader, module, snapshot = task_fixture(())
        result = tm.capture_loaded_tasks(reader, module, snapshot["missions"])
        loaded = result["loaded_tasks"]
        self.assertEqual(loaded["status"], "observed")
        self.assertTrue(loaded["complete"])
        self.assertEqual(loaded["roots"][0]["tasks"], [])
        self.assertEqual(loaded["roots"][0]["vector"]["pointer"]["va"], "0x0")

    def test_root_vtable_is_checked_before_vector_and_parser_entry_is_checked(self):
        reader, module, snapshot = task_fixture(("task_a",))
        root = 0x720000
        reader.qword_put(root, module + tm.TASK_VTABLE_RVA)
        result = tm.capture_loaded_tasks(reader, module, snapshot["missions"])
        self.assertEqual(result["loaded_tasks"]["status"], "unknown")
        root_result = result["loaded_tasks"]["roots"][0]
        self.assertIn("root_object_vtable_or_parser_mismatch", root_result["unknown_conditions"])
        self.assertIsNone(result["_compare"])

        reader, module, snapshot = task_fixture(("task_a",))
        reader.qword_put(module + tm.ROOT_VTABLE_RVA + tm.PARSER_ENTRY_OFFSET, module + tm.TASK_PARSER_RVA)
        result = tm.capture_loaded_tasks(reader, module, snapshot["missions"])
        self.assertEqual(result["loaded_tasks"]["status"], "unknown")

    def test_task_vtable_mismatch_retracts_task_ids(self):
        reader, module, snapshot = task_fixture(("task_a",))
        task = 0x740000
        reader.qword_put(task, module + tm.ROOT_VTABLE_RVA)
        result = tm.capture_loaded_tasks(reader, module, snapshot["missions"])
        self.assertEqual(result["loaded_tasks"]["status"], "unknown")
        task_result = result["loaded_tasks"]["roots"][0]["tasks"][0]
        self.assertIn("task_object_vtable_or_parser_mismatch", task_result["unknown_conditions"])
        self.assertIsNone(task_result["task_id"])

    def test_vector_limits_and_bad_string_fail_closed(self):
        reader, module, snapshot = task_fixture(("task_a",))
        root = 0x720000
        reader.dword_put(root + tm.TASK_COUNT_OFFSET, tm.MAX_TASKS_PER_ROOT + 1, signed=True)
        result = tm.capture_loaded_tasks(reader, module, snapshot["missions"])
        self.assertEqual(result["loaded_tasks"]["status"], "unknown")
        self.assertIn("task_vector_count_or_capacity_out_of_bound", result["loaded_tasks"]["roots"][0]["unknown_conditions"])

        reader, module, snapshot = task_fixture(("task_a",))
        task = 0x740000
        reader.qword_put(task + tm.TASK_DEFINITION_NAME_OFFSET, 0x12345)
        result = tm.capture_loaded_tasks(reader, module, snapshot["missions"])
        self.assertEqual(result["loaded_tasks"]["status"], "unknown")
        self.assertIsNone(result["_compare"])

    def test_task_content_change_is_visible_to_doublepass_compare(self):
        reader, module, snapshot_before = task_fixture(("task_a",))
        before = tm.capture_loaded_tasks(reader, module, snapshot_before["missions"])
        write_string32(reader, 0x740000, "task_b")
        snapshot_after = mm._snapshot(reader, module, "FRA", False)
        after = tm.capture_loaded_tasks(reader, module, snapshot_after["missions"])
        mismatches = mm._diff_paths(before["_compare"], after["_compare"])
        self.assertTrue(any("task_id" in path for path in mismatches))

    def test_code_guard_tamper_is_unknown(self):
        reader, module, _snapshot = task_fixture(())
        reader.memory[module + tm.ROOT_VTABLE_RVA + tm.PARSER_ENTRY_OFFSET] ^= 1
        result = tm._runtime_code_guard(reader, module)
        self.assertEqual(result["status"], "mismatch")
        self.assertFalse(result["checks"]["root_vtable_table"])

    def test_full_capture_task_only_mismatch_keeps_root_observed(self):
        reader, module, _snapshot = task_fixture(("task_a",))
        kernel = FakeCaptureKernel(module)
        real_snapshot = mm._snapshot
        calls = [0]

        def mutate_task_after_first_pass(*args, **kwargs):
            result = real_snapshot(*args, **kwargs)
            calls[0] += 1
            if calls[0] == 1:
                write_string32(reader, 0x740000, "task_b")
            return result

        with ExitStack() as stack:
            for context in _capture_patches(reader, kernel, snapshot=mutate_task_after_first_pass):
                stack.enter_context(context)
            report = mm.capture(Path("fake-installation.json"), "FRA", include_completed=True, include_tasks=True)
        self.assertEqual(report["status"], "observed")
        self.assertTrue(report["completed"])
        self.assertEqual(report["task_reader"]["profile_sha256"], tm.EXPECTED_PROFILE_SHA256)
        self.assertEqual(report["task_reader"]["sha256"], tm._sha256_file(Path(tm.__file__).resolve()))
        self.assertTrue(report["doublepass"]["consistent"])
        self.assertFalse(report["doublepass"]["task_consistent"])
        self.assertTrue(report["doublepass"]["task_mismatches"])
        self.assertEqual(report["loaded_tasks"]["status"], "unknown")
        self.assertEqual(report["before"]["missions"]["status"], "observed")
        self.assertEqual(report["before"]["missions"]["candidate_completed_missions"]["status"], "observed")
        self.assertEqual(report["after"]["missions"]["status"], "observed")
        self.assertEqual(kernel.closed, [0x1234])

    def test_task_guard_failures_disable_only_task_sampling_and_keep_root(self):
        failures = (
            ("static", {"status": "mismatch", "unknown_conditions": ["static-tamper"]}, None, None),
            ("file", None, {"status": "mismatch", "unknown_conditions": ["file-tamper"]}, None),
            ("runtime", None, None, {"status": "mismatch", "unknown_conditions": ["runtime-tamper"]}),
        )
        for name, static, file_guard, runtime in failures:
            with self.subTest(name=name):
                reader, module, _snapshot = task_fixture(("task_a",))
                kernel = FakeCaptureKernel(module)
                with ExitStack() as stack:
                    for context in _capture_patches(
                        reader,
                        kernel,
                        task_static=static,
                        task_file=file_guard,
                        task_runtime=runtime,
                    ):
                        stack.enter_context(context)
                    report = mm.capture(Path("fake-installation.json"), "FRA", include_completed=True, include_tasks=True)
                self.assertEqual(report["status"], "observed")
                self.assertTrue(report["doublepass"]["consistent"])
                self.assertFalse(report["doublepass"]["task_consistent"])
                self.assertEqual(report["loaded_tasks"]["status"], "unknown")
                self.assertEqual(report["before"]["missions"]["status"], "observed")
                self.assertEqual(report["before"]["missions"]["candidate_completed_missions"]["status"], "observed")
                self.assertEqual(report["after"]["missions"]["status"], "observed")

    def test_cleanup_failure_rejects_whole_capture_and_retracts_loaded_tasks(self):
        reader, module, _snapshot = task_fixture(("task_a",))
        kernel = FakeCaptureKernel(module, close_result=False)
        with ExitStack() as stack:
            for context in _capture_patches(reader, kernel):
                stack.enter_context(context)
            report = mm.capture(Path("fake-installation.json"), "FRA", include_tasks=True)
        self.assertEqual(report["status"], "cleanup_error")
        self.assertTrue(report["completed"])
        self.assertEqual(report["cleanup"]["handle_close"]["status"], "error")
        self.assertFalse(report["cleanup"]["handle_close"]["success"])
        self.assertEqual(report["loaded_tasks"]["status"], "unknown")
        self.assertEqual(report["before"]["missions"]["status"], "observed")
        self.assertEqual(kernel.closed, [0x1234])

    def test_default_capture_does_not_import_or_read_task_path(self):
        reader, module, _snapshot = task_fixture(("task_a",))
        kernel = FakeCaptureKernel(module)
        real_snapshot = mm._snapshot
        snapshot_args: list[tuple[object, ...]] = []

        def record_snapshot(*args, **kwargs):
            snapshot_args.append(args)
            return real_snapshot(*args, **kwargs)

        with ExitStack() as stack:
            for context in _capture_patches(reader, kernel, snapshot=record_snapshot):
                stack.enter_context(context)
            report = mm.capture(Path("fake-installation.json"), "FRA", include_tasks=False)
        self.assertEqual(report["status"], "observed")
        self.assertNotIn("loaded_tasks", report)
        self.assertNotIn("task_reader", report)
        self.assertIsNone(report["task_static_contract_guard"])
        self.assertIsNone(report["task_file_code_guard"])
        self.assertIsNone(report["task_runtime_code_guard"])
        self.assertTrue(snapshot_args)
        self.assertTrue(all(len(args) == 4 for args in snapshot_args))


if __name__ == "__main__":
    unittest.main()
