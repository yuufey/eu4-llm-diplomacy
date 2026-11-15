"""Synthetic tests for the bounded mission prerequisite RPM reader."""
from __future__ import annotations

import copy
import hashlib
import unittest

from bridge.information import mission_memory as mm
from bridge.information import mission_prerequisite_memory as pm
from bridge.information import mission_task_memory as tm
from bridge.tests.test_information_mission_memory import write_string32
from bridge.tests.test_information_mission_task_memory import (
    populate_task_guards,
    task_fixture,
)


def _code_guards(reader) -> list[dict[str, object]]:
    raw = bytes.fromhex("48895c240857")
    rva = 0x500
    reader.put(reader.module_base + rva, raw)
    return [{"rva": rva, "raw_hex": raw.hex(), "sha256": hashlib.sha256(raw).hexdigest()}]


def _write_string_at(reader, address: int, text: str, *, heap: bool = False) -> None:
    payload = text.encode("ascii") + b"\x00"
    header = bytearray(pm.STRING32_BYTES)
    length = len(text.encode("ascii"))
    capacity = 16 if heap else max(length, 1)
    if heap:
        pointer = address + 0x1000
        header[:8] = pointer.to_bytes(8, "little")
        reader.put(pointer, payload)
    else:
        header[:len(payload)] = payload
    header[mm.STRING_LENGTH_OFFSET:mm.STRING_LENGTH_OFFSET + 8] = length.to_bytes(8, "little")
    header[mm.STRING_CAPACITY_OFFSET:mm.STRING_CAPACITY_OFFSET + 8] = capacity.to_bytes(8, "little")
    reader.put(address, bytes(header))


def _set_prerequisites(reader, task_pointer: int, values: tuple[str, ...], *,
                       heap_indices: tuple[int, ...] = (), data_pointer: int = 0x760000) -> None:
    reader.qword_put(task_pointer + pm.PREREQUISITE_VECTOR_POINTER_OFFSET,
                     data_pointer if values else 0)
    reader.dword_put(task_pointer + pm.PREREQUISITE_VECTOR_CAPACITY_OFFSET,
                     len(values), signed=True)
    reader.dword_put(task_pointer + pm.PREREQUISITE_VECTOR_COUNT_OFFSET,
                     len(values), signed=True)
    for index, value in enumerate(values):
        _write_string_at(reader, data_pointer + index * pm.STRING32_BYTES,
                         value, heap=index in heap_indices)


def _fixture(task_ids: tuple[str, ...] = ("task_a",),
             required: tuple[str, ...] = (), *, heap_indices: tuple[int, ...] = ()):
    reader, module, snapshot = task_fixture(task_ids)
    populate_task_guards(reader)
    guards = _code_guards(reader)
    loaded = tm.capture_loaded_tasks(reader, module, snapshot["missions"])["loaded_tasks"]
    for index, task_id in enumerate(task_ids):
        _set_prerequisites(reader, 0x740000 + index * 0x1000, required,
                           heap_indices=heap_indices,
                           data_pointer=0x760000 + index * 0x10000)
    return reader, module, loaded, guards


class MissionPrerequisiteMemoryTests(unittest.TestCase):
    def test_observes_empty_inline_and_heap_string_vectors(self):
        reader, module, loaded, guards = _fixture()
        empty = pm.capture_prerequisites(reader, module, loaded, code_guards=guards)
        self.assertEqual(empty["status"], "observed")
        self.assertTrue(empty["complete"])
        self.assertEqual(empty["tasks"][0]["required_task_ids"], [])
        self.assertIsNotNone(empty["_compare"])

        reader, module, loaded, guards = _fixture(
            required=("task_a", "task_b"), heap_indices=(1,)
        )
        result = pm.capture_prerequisites(reader, module, loaded, code_guards=guards)
        self.assertEqual(result["status"], "observed")
        self.assertEqual(result["tasks"][0]["required_task_ids"], ["task_a", "task_b"])
        self.assertEqual(
            [row["storage"] for row in result["tasks"][0]["strings"]["required_task_ids"]],
            ["inline", "heap"],
        )
        self.assertEqual(result["tasks"][0]["task_pointer"]["va"], "0x740000")
        self.assertTrue(result["tasks"][0]["vector"]["raw_hex"])

    def test_bad_short_and_over_budget_vectors_fail_closed(self):
        reader, module, loaded, guards = _fixture(required=("task_a",))
        task = 0x740000
        reader.qword_put(task + pm.PREREQUISITE_VECTOR_POINTER_OFFSET, 0)
        bad_pointer = pm.capture_prerequisites(reader, module, loaded, code_guards=guards)
        self.assertEqual(bad_pointer["status"], "unknown")
        self.assertIsNone(bad_pointer["_compare"])
        self.assertIn("pointer_invalid", bad_pointer["reason"])

        reader, module, loaded, guards = _fixture(required=("task_a",))
        original_read = reader.read

        def short_array(address, size, label):
            if label.endswith("String32_array"):
                return original_read(address, max(size - 1, 0), label)
            return original_read(address, size, label)

        reader.read = short_array
        short = pm.capture_prerequisites(reader, module, loaded, code_guards=guards)
        self.assertEqual(short["status"], "unknown")
        self.assertIsNone(short["_compare"])
        self.assertIn("array_short", short["reason"])

        reader, module, loaded, guards = _fixture()
        reader.dword_put(task + pm.PREREQUISITE_VECTOR_CAPACITY_OFFSET,
                         pm.MAX_REQUIRED_PER_TASK + 1, signed=True)
        reader.dword_put(task + pm.PREREQUISITE_VECTOR_COUNT_OFFSET,
                         pm.MAX_REQUIRED_PER_TASK + 1, signed=True)
        over_bound = pm.capture_prerequisites(reader, module, loaded, code_guards=guards)
        self.assertEqual(over_bound["status"], "unknown")
        self.assertIsNone(over_bound["_compare"])
        self.assertIn("bounds_invalid", over_bound["reason"])

    def test_total_required_budget_and_short_header_are_unknown(self):
        task_ids = tuple(f"task_{index}" for index in range(9))
        reader, module, loaded, guards = _fixture(task_ids)
        data_pointer = 0x900000
        _write_string_at(reader, data_pointer, "requirement")
        header = bytes(reader.memory[data_pointer + offset] for offset in range(pm.STRING32_BYTES))
        for index in range(1, 512):
            reader.put(data_pointer + index * pm.STRING32_BYTES, header)
        for index in range(len(task_ids)):
            task_pointer = 0x740000 + index * 0x1000
            reader.qword_put(task_pointer + pm.PREREQUISITE_VECTOR_POINTER_OFFSET, data_pointer)
            reader.dword_put(task_pointer + pm.PREREQUISITE_VECTOR_CAPACITY_OFFSET, 512, signed=True)
            reader.dword_put(task_pointer + pm.PREREQUISITE_VECTOR_COUNT_OFFSET, 512, signed=True)
        over_total = pm.capture_prerequisites(reader, module, loaded, code_guards=guards)
        self.assertEqual(over_total["status"], "unknown")
        self.assertIsNone(over_total["_compare"])
        self.assertIn("total_prerequisite_limit_exceeded", over_total["reason"])

        reader, module, loaded, guards = _fixture(required=("requirement",))
        task = 0x740000
        address = 0x760000
        reader.put(address + pm.STRING32_BYTES - 1, b"x")
        original_read = reader.read

        def short_vector_header(read_address, size, label):
            if label.endswith(".vector") and "mission_prerequisite.task[" in label:
                return original_read(read_address, size - 1, label)
            return original_read(read_address, size, label)

        reader.read = short_vector_header
        short_header = pm.capture_prerequisites(reader, module, loaded, code_guards=guards)
        self.assertEqual(short_header["status"], "unknown")
        self.assertIsNone(short_header["_compare"])
        self.assertIn("vector_short", short_header["reason"])

    def test_runtime_guard_mismatch_stops_before_any_object_read(self):
        reader, module, loaded, guards = _fixture(required=("task_a",))
        guard_address = module + guards[0]["rva"]
        reader.put(guard_address, b"xxxxxx")
        calls_before = reader.calls
        result = pm.capture_prerequisites(reader, module, loaded, code_guards=guards)
        self.assertEqual(result["status"], "unknown")
        self.assertIn("runtime_mismatch", result["reason"])
        self.assertIsNone(result["_compare"])
        self.assertEqual(reader.calls, calls_before + 1)

    def test_task_object_contract_and_id_drift_are_unknown(self):
        reader, module, loaded, guards = _fixture(required=("task_a",))
        reader.qword_put(0x740000, module + tm.ROOT_VTABLE_RVA)
        mismatch = pm.capture_prerequisites(reader, module, loaded, code_guards=guards)
        self.assertEqual(mismatch["status"], "unknown")
        self.assertIn("vtable_mismatch", mismatch["reason"])
        self.assertIsNone(mismatch["_compare"])

        reader, module, loaded, guards = _fixture(required=("task_a",))
        write_string32(reader, 0x740000, "task_drifted")
        drift = pm.capture_prerequisites(reader, module, loaded, code_guards=guards)
        self.assertEqual(drift["status"], "unknown")
        self.assertIn("task_id_drift", drift["reason"])
        self.assertIsNone(drift["_compare"])

    def test_duplicate_and_incomplete_loaded_task_coverage_are_unknown(self):
        reader, module, loaded, guards = _fixture(required=("task_a",))
        duplicate_root = copy.deepcopy(loaded)
        duplicate_root["roots"].append(copy.deepcopy(duplicate_root["roots"][0]))
        duplicate_root["total_task_count"] = 2
        duplicate = pm.capture_prerequisites(reader, module, duplicate_root, code_guards=guards)
        self.assertEqual(duplicate["status"], "unknown")
        self.assertIn("duplicate_loaded_root_id", duplicate["reason"])
        self.assertIsNone(duplicate["_compare"])

        incomplete = copy.deepcopy(loaded)
        incomplete["roots"][0]["task_ids"] = []
        coverage = pm.capture_prerequisites(reader, module, incomplete, code_guards=guards)
        self.assertEqual(coverage["status"], "unknown")
        self.assertIn("task_coverage", coverage["reason"])
        self.assertIsNone(coverage["_compare"])

    def test_compare_changes_when_raw_requirement_string_changes(self):
        reader, module, loaded, guards = _fixture(required=("required_a",))
        before = pm.capture_prerequisites(reader, module, loaded, code_guards=guards)
        _write_string_at(reader, 0x760000, "required_b")
        after = pm.capture_prerequisites(reader, module, loaded, code_guards=guards)
        self.assertEqual(before["status"], "observed")
        self.assertEqual(after["status"], "observed")
        self.assertIsNotNone(before["_compare"])
        self.assertIsNotNone(after["_compare"])
        mismatches = mm._diff_paths(before["_compare"], after["_compare"])
        self.assertTrue(any("required_task_ids" in path or "strings" in path for path in mismatches))

    def test_guard_shape_and_identifier_validation_fail_closed(self):
        reader, module, loaded, guards = _fixture(required=("task_a",))
        no_guards = pm.capture_prerequisites(reader, module, loaded, code_guards=[])
        self.assertEqual(no_guards["status"], "unknown")
        self.assertIn("code_guards_missing", no_guards["reason"])

        reader, module, loaded, guards = _fixture(required=("bad-id",))
        invalid = pm.capture_prerequisites(reader, module, loaded, code_guards=guards)
        self.assertEqual(invalid["status"], "unknown")
        self.assertIn("identifier_invalid", invalid["reason"])
        self.assertIsNone(invalid["_compare"])


if __name__ == "__main__":
    unittest.main()
