"""Synthetic coverage for bounded mission prerequisite-completion RPM."""
from __future__ import annotations

import hashlib
import unittest

from bridge.information import mission_condition_memory as cm
from bridge.information import mission_memory as mm
from bridge.information import mission_prerequisite_memory as pm
from bridge.information import mission_task_memory as tm
from bridge.tests.test_information_mission_memory import (
    base_reader,
    write_string32,
)
from bridge.tests.test_information_mission_prerequisite_memory import (
    _write_string_at,
)
from bridge.tests.test_information_mission_task_memory import (
    populate_task_guards,
    task_fixture,
)


REGISTRY_POINTER = 0x680000
NAME_SENTINEL = 0x690000
NAME_BUCKETS = 0x6A0000
COMPLETED_SENTINEL = 0x6B0000
COMPLETED_BUCKETS = 0x6C0000
NAME_NODE_BASE = 0x810000
COMPLETED_NODE_BASE = 0x910000


def _fnv1(value: str) -> int:
    result = 0x811C9DC5
    for byte in value.encode("ascii"):
        result = ((result * 0x01000193) & 0xFFFFFFFF) ^ byte
    return result


def _fnv1a64(raw: bytes) -> int:
    result = 0xCBF29CE484222325
    for byte in raw:
        result = ((result ^ byte) * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    return result


def _read_qword(reader, address: int) -> int:
    return int.from_bytes(
        bytes(reader.memory.get(address + offset, 0) for offset in range(8)), "little"
    )


def _code_guards(reader) -> list[dict[str, object]]:
    raw = bytes.fromhex("48895c240857")
    rva = 0x500
    reader.put(reader.module_base + rva, raw)
    return [{"rva": rva, "raw_hex": raw.hex(), "sha256": hashlib.sha256(raw).hexdigest()}]


def _set_prerequisites(reader, task_pointer: int, values: tuple[str, ...], data_pointer: int) -> None:
    reader.qword_put(task_pointer + pm.PREREQUISITE_VECTOR_POINTER_OFFSET,
                     data_pointer if values else 0)
    reader.dword_put(task_pointer + pm.PREREQUISITE_VECTOR_CAPACITY_OFFSET,
                     len(values), signed=True)
    reader.dword_put(task_pointer + pm.PREREQUISITE_VECTOR_COUNT_OFFSET,
                     len(values), signed=True)
    for index, value in enumerate(values):
        _write_string_at(
            reader,
            data_pointer + index * pm.STRING32_BYTES,
            value,
            heap=len(value.encode("ascii")) >= 16,
        )


def _write_map_header(reader, address: int, sentinel: int, size: int, begin: int) -> None:
    bucket_count = 8
    end = begin + bucket_count * cm.MAP_BUCKET_PAIR_BYTES
    reader.qword_put(address, 0)
    reader.qword_put(address + 8, sentinel)
    reader.qword_put(address + 0x10, size)
    reader.qword_put(address + 0x18, begin)
    reader.qword_put(address + 0x20, end)
    reader.qword_put(address + 0x28, end)
    reader.qword_put(address + 0x30, bucket_count - 1)
    reader.qword_put(address + 0x38, bucket_count)
    for index in range(bucket_count):
        reader.qword_put(begin + index * 16, sentinel)
        reader.qword_put(begin + index * 16 + 8, sentinel)


def _install_name_map(reader, module: int, entries: list[tuple[str, int]]) -> dict[str, list[int]]:
    reader.qword_put(module + cm.REGISTRY_SINGLETON_RVA, REGISTRY_POINTER)
    reader.qword_put(REGISTRY_POINTER, module + cm.REGISTRY_VTABLE_RVA)
    map_address = REGISTRY_POINTER + cm.REGISTRY_MAP_OFFSET
    _write_map_header(reader, map_address, NAME_SENTINEL, len(entries), NAME_BUCKETS)
    grouped: dict[int, list[tuple[str, int, int]]] = {}
    nodes: dict[str, list[int]] = {}
    for index, (name, definition) in enumerate(entries):
        node = NAME_NODE_BASE + index * 0x1000
        bucket = _fnv1(name) & 7
        grouped.setdefault(bucket, []).append((name, definition, node))
        nodes.setdefault(name, []).append(node)
    for bucket, rows in grouped.items():
        reader.qword_put(NAME_BUCKETS + bucket * 16, rows[0][2])
        reader.qword_put(NAME_BUCKETS + bucket * 16 + 8, rows[-1][2])
        for index, (name, definition, node) in enumerate(rows):
            previous = rows[index - 1][2] if index else NAME_SENTINEL
            following = rows[index + 1][2] if index + 1 < len(rows) else NAME_SENTINEL
            reader.qword_put(node, following)
            reader.qword_put(node + 8, previous)
            write_string32(reader, node, name)
            reader.qword_put(node + 0x30, definition)
    return nodes


def _install_completed_map(reader, country: int, definitions: list[int]) -> dict[int, int]:
    map_address = country + cm.COMPLETED_MAP_OFFSET
    _write_map_header(reader, map_address, COMPLETED_SENTINEL, len(definitions), COMPLETED_BUCKETS)
    grouped: dict[int, list[tuple[int, int]]] = {}
    nodes: dict[int, int] = {}
    for index, definition in enumerate(definitions):
        node = COMPLETED_NODE_BASE + index * 0x1000
        bucket = _fnv1a64(definition.to_bytes(8, "little")) & 7
        grouped.setdefault(bucket, []).append((definition, node))
        nodes[definition] = node
    for bucket, rows in grouped.items():
        reader.qword_put(COMPLETED_BUCKETS + bucket * 16, rows[0][1])
        reader.qword_put(COMPLETED_BUCKETS + bucket * 16 + 8, rows[-1][1])
        for index, (definition, node) in enumerate(rows):
            previous = rows[index - 1][1] if index else COMPLETED_SENTINEL
            following = rows[index + 1][1] if index + 1 < len(rows) else COMPLETED_SENTINEL
            reader.qword_put(node, following)
            reader.qword_put(node + 8, previous)
            reader.qword_put(node + 0x10, definition)
    return nodes


def _fixture(task_ids: tuple[str, ...] = ("task_a",),
             required_by_task: dict[str, tuple[str, ...]] | None = None,
             *, completed_names: tuple[str, ...] = (),
             missing_names: tuple[str, ...] = (),
             aliases: dict[str, int] | None = None,
             extra_names: tuple[str, ...] = ()):
    reader, module, snapshot = task_fixture(task_ids)
    country = 0x500000
    populate_task_guards(reader)
    guards = _code_guards(reader)
    loaded = tm.capture_loaded_tasks(reader, module, snapshot["missions"])["loaded_tasks"]
    required_by_task = required_by_task or {}
    task_definitions = {
        task_id: 0x740000 + index * 0x1000
        for index, task_id in enumerate(task_ids)
    }
    for index, (task_id, definition) in enumerate(task_definitions.items()):
        _set_prerequisites(reader, definition, required_by_task.get(task_id, ()),
                           0x760000 + index * 0x10000)

    definitions = dict(task_definitions)
    required_names = {
        required for values in required_by_task.values() for required in values
    }
    names_to_add = (set(extra_names) | required_names) - set(task_ids) - set(missing_names)
    for name in sorted(names_to_add):
        if name in definitions:
            continue
        pointer = 0x780000 + len(definitions) * 0x1000
        reader.qword_put(pointer, module + tm.TASK_VTABLE_RVA)
        write_string32(reader, pointer, name)
        definitions[name] = pointer

    loaded_prerequisites = pm.capture_prerequisites(
        reader, module, loaded, code_guards=guards
    )
    assert loaded_prerequisites["status"] == "observed"
    name_entries = [(name, pointer) for name, pointer in definitions.items()]
    for name, pointer in (aliases or {}).items():
        name_entries = [(key, pointer if key == name else value) for key, value in name_entries]
        if name not in definitions:
            name_entries.append((name, pointer))
    name_nodes = _install_name_map(reader, module, name_entries)
    completed_definitions = [definitions[name] for name in completed_names if name in definitions]
    completed_nodes = _install_completed_map(reader, country, completed_definitions)
    return reader, module, country, loaded_prerequisites, guards, definitions, name_nodes, completed_nodes


def synthetic_condition_fixture(*args, **kwargs):
    """Shared fixture for unit and capture-integration tests owned by callers."""
    return _fixture(*args, **kwargs)


class MissionConditionMemoryTests(unittest.TestCase):
    def test_empty_prerequisite_and_fulfilled_prerequisite(self):
        reader, module, country, loaded, guards, _definitions, _nodes, _completed = _fixture()
        empty = cm.capture_conditions(reader, module, country, loaded, code_guards=guards)
        self.assertEqual(empty["status"], "observed")
        self.assertTrue(empty["complete"])
        self.assertEqual(empty["tasks"][0]["required"], [])
        self.assertTrue(empty["tasks"][0]["prerequisites_satisfied"])
        self.assertTrue(empty["_compare"]["rawreads"])

        reader, module, country, loaded, guards, definitions, _nodes, _completed = _fixture(
            ("task_a",), {"task_a": ("required_a",)},
            completed_names=("required_a",),
        )
        fulfilled = cm.capture_conditions(reader, module, country, loaded, code_guards=guards)
        self.assertEqual(fulfilled["status"], "observed")
        self.assertFalse(fulfilled["tasks"][0]["task_completed"])
        required = fulfilled["tasks"][0]["required"][0]
        self.assertEqual(required["task_id"], "required_a")
        self.assertEqual(required["definition_pointer"]["va"], hex(definitions["required_a"]))
        self.assertTrue(required["completed"])
        self.assertTrue(fulfilled["tasks"][0]["prerequisites_satisfied"])

    def test_existing_but_incomplete_requirement_is_false_and_absent_name_is_unknown(self):
        reader, module, country, loaded, guards, _definitions, _nodes, _completed = _fixture(
            ("task_a",), {"task_a": ("required_a",)}
        )
        incomplete = cm.capture_conditions(reader, module, country, loaded, code_guards=guards)
        self.assertEqual(incomplete["status"], "observed")
        self.assertFalse(incomplete["tasks"][0]["required"][0]["completed"])
        self.assertFalse(incomplete["tasks"][0]["prerequisites_satisfied"])

        reader, module, country, loaded, guards, _definitions, _nodes, _completed = _fixture(
            ("task_a",), {"task_a": ("required_missing",)},
            missing_names=("required_missing",),
        )
        missing = cm.capture_conditions(reader, module, country, loaded, code_guards=guards)
        self.assertEqual(missing["status"], "unknown")
        self.assertFalse(missing["complete"])
        self.assertIn("canonical_definition_missing:required_missing", missing["reason"])
        self.assertIsNone(missing["_compare"])

    def test_name_hash_collision_walks_back_from_bucket_last(self):
        collision = next(
            f"collision_{index}" for index in range(1000)
            if (_fnv1(f"collision_{index}") & 7) == (_fnv1("task_a") & 7)
        )
        reader, module, country, loaded, guards, definitions, nodes, _completed = _fixture(
            ("task_a",), extra_names=(collision,)
        )
        result = cm.capture_conditions(reader, module, country, loaded, code_guards=guards)
        self.assertEqual(result["status"], "observed")
        self.assertEqual(len(nodes["task_a"]), 1)
        key_reads = [
            row["label"] for row in result["_compare"]["rawreads"]
            if row["label"].endswith(".key.header") and "name_registry.node" in row["label"]
        ]
        self.assertGreaterEqual(len(key_reads), 2)
        self.assertIn("task_a", definitions)
        self.assertIn(hex(nodes[collision][0]), key_reads[0])
        self.assertIn(hex(nodes["task_a"][0]), key_reads[1])

    def test_completed_pointer_hash_collision_uses_prev_chain(self):
        first_pointer = 0x740000
        collision = next(
            f"hit_{index}" for index in range(1000)
            if (_fnv1a64((0x741000).to_bytes(8, "little")) & 7)
            == (_fnv1a64((first_pointer).to_bytes(8, "little")) & 7)
        )
        reader, module, country, loaded, guards, definitions, _nodes, completed_nodes = _fixture(
            ("task_a", collision), completed_names=("task_a", collision)
        )
        result = cm.capture_conditions(reader, module, country, loaded, code_guards=guards)
        self.assertEqual(result["status"], "observed")
        self.assertTrue(result["tasks"][0]["task_completed"])
        self.assertTrue(result["tasks"][1]["task_completed"])
        first_definition = definitions["task_a"]
        second_definition = definitions[collision]
        first_node = completed_nodes[first_definition]
        last_node = completed_nodes[second_definition]
        self.assertEqual(
            _read_qword(reader, COMPLETED_BUCKETS + (_fnv1a64(first_definition.to_bytes(8, "little")) & 7) * 16),
            first_node,
        )
        self.assertEqual(
            _read_qword(reader, COMPLETED_BUCKETS + (_fnv1a64(first_definition.to_bytes(8, "little")) & 7) * 16 + 8),
            last_node,
        )
        self.assertEqual(_read_qword(reader, last_node + 8), first_node)

    def test_alias_to_wrong_canonical_pointer_is_unknown(self):
        reader, module, country, loaded, guards, definitions, _nodes, _completed = _fixture(
            ("task_a",), aliases={"task_a": 0x780000}
        )
        reader.qword_put(0x780000, module + tm.TASK_VTABLE_RVA)
        write_string32(reader, 0x780000, "task_a")
        result = cm.capture_conditions(reader, module, country, loaded, code_guards=guards)
        self.assertEqual(result["status"], "unknown")
        self.assertIn("loaded_task_pointer_not_canonical", result["reason"])
        self.assertNotEqual(definitions["task_a"], 0x780000)
        self.assertIsNone(result["_compare"])

    def test_guard_registry_and_registry_header_corruption_fail_closed(self):
        reader, module, country, loaded, guards, _definitions, _nodes, _completed = _fixture()
        reader.memory[module + guards[0]["rva"]] ^= 1
        calls_before = reader.calls
        bad_guard = cm.capture_conditions(reader, module, country, loaded, code_guards=guards)
        self.assertEqual(bad_guard["status"], "unknown")
        self.assertIn("runtime_code_guard_failed", bad_guard["reason"])
        self.assertIsNone(bad_guard["_compare"])
        self.assertEqual(reader.calls, calls_before + 1)

        reader, module, country, loaded, guards, _definitions, _nodes, _completed = _fixture()
        reader.qword_put(REGISTRY_POINTER, 0)
        bad_registry = cm.capture_conditions(reader, module, country, loaded, code_guards=guards)
        self.assertEqual(bad_registry["status"], "unknown")
        self.assertIn("mission_name_registry_vtable_mismatch", bad_registry["reason"])

        reader, module, country, loaded, guards, _definitions, _nodes, _completed = _fixture()
        reader.qword_put(REGISTRY_POINTER + cm.REGISTRY_MAP_OFFSET + 0x30, 5)
        bad_header = cm.capture_conditions(reader, module, country, loaded, code_guards=guards)
        self.assertEqual(bad_header["status"], "unknown")
        self.assertIn("bucket_mask_or_count_invalid", bad_header["reason"])
        self.assertIsNone(bad_header["_compare"])

    def test_empty_registry_is_unknown_and_short_header_is_unknown(self):
        reader, module, country, loaded, guards, _definitions, _nodes, _completed = _fixture()
        registry_map = REGISTRY_POINTER + cm.REGISTRY_MAP_OFFSET
        reader.qword_put(registry_map + 0x10, 0)
        for index in range(8):
            reader.qword_put(NAME_BUCKETS + index * 16, NAME_SENTINEL)
            reader.qword_put(NAME_BUCKETS + index * 16 + 8, NAME_SENTINEL)
        empty = cm.capture_conditions(reader, module, country, loaded, code_guards=guards)
        self.assertEqual(empty["status"], "unknown")
        self.assertIn("mission_name_registry_empty", empty["reason"])

        reader, module, country, loaded, guards, _definitions, _nodes, _completed = _fixture()
        original_read = reader.read

        def short_header(address, size, label):
            raw = original_read(address, size, label)
            if label == "mission_condition.name_registry.header":
                return raw[:-1]
            return raw

        reader.read = short_header
        short = cm.capture_conditions(reader, module, country, loaded, code_guards=guards)
        self.assertEqual(short["status"], "unknown")
        self.assertIn("name_registry_header_short", short["reason"])
        self.assertIsNone(short["_compare"])

    def test_name_bucket_cycle_and_zero_size_nonempty_completion_bucket_are_unknown(self):
        collision = next(
            f"collision_{index}" for index in range(1000)
            if (_fnv1(f"collision_{index}") & 7) == (_fnv1("task_a") & 7)
        )
        reader, module, country, loaded, guards, _definitions, nodes, _completed = _fixture(
            ("task_a",), extra_names=(collision,)
        )
        task_node = nodes["task_a"][0]
        filler_node = nodes[collision][0]
        fake_first = 0x830000
        bucket = _fnv1("task_a") & 7
        reader.qword_put(NAME_BUCKETS + bucket * 16, fake_first)
        reader.qword_put(NAME_BUCKETS + bucket * 16 + 8, filler_node)
        reader.qword_put(filler_node, task_node)
        reader.qword_put(filler_node + 8, task_node)
        reader.qword_put(task_node, filler_node)
        reader.qword_put(task_node + 8, filler_node)
        cycle = cm.capture_conditions(reader, module, country, loaded, code_guards=guards)
        self.assertEqual(cycle["status"], "unknown")
        self.assertIn("bucket_node_cycle", cycle["reason"])

        reader, module, country, loaded, guards, definitions, _nodes, _completed = _fixture()
        definition = definitions["task_a"]
        bucket = _fnv1a64(definition.to_bytes(8, "little")) & 7
        node = COMPLETED_NODE_BASE
        reader.qword_put(COMPLETED_BUCKETS + bucket * 16, node)
        reader.qword_put(COMPLETED_BUCKETS + bucket * 16 + 8, node)
        reader.qword_put(node, COMPLETED_SENTINEL)
        reader.qword_put(node + 8, COMPLETED_SENTINEL)
        reader.qword_put(node + 0x10, definition)
        zero_size = cm.capture_conditions(reader, module, country, loaded, code_guards=guards)
        self.assertEqual(zero_size["status"], "unknown")
        self.assertIn("nonempty_bucket_with_zero_size", zero_size["reason"])

    def test_reader_budget_and_raw_compare_change(self):
        reader, module, country, loaded, guards, definitions, _nodes, _completed = _fixture()
        large_guards: list[dict[str, object]] = []
        for index in range(128):
            rva = 0x100000 + index * 0x2000
            raw = bytes([index & 0xFF]) * 4096
            reader.put(module + rva, raw)
            large_guards.append({
                "rva": rva,
                "raw_hex": raw.hex(),
                "sha256": hashlib.sha256(raw).hexdigest(),
            })
        over_budget = cm.capture_conditions(
            reader, module, country, loaded, code_guards=large_guards
        )
        self.assertEqual(over_budget["status"], "unknown")
        self.assertIn("condition_total_rpm_budget_exceeded", over_budget["reason"])
        self.assertIsNone(over_budget["_compare"])

        reader, module, country, loaded, guards, definitions, _nodes, _completed = _fixture()
        before = cm.capture_conditions(reader, module, country, loaded, code_guards=guards)
        self.assertEqual(before["status"], "observed")
        definition = definitions["task_a"]
        bucket = _fnv1a64(definition.to_bytes(8, "little")) & 7
        node = COMPLETED_NODE_BASE
        reader.qword_put(country + cm.COMPLETED_MAP_OFFSET + 0x10, 1)
        reader.qword_put(COMPLETED_BUCKETS + bucket * 16, node)
        reader.qword_put(COMPLETED_BUCKETS + bucket * 16 + 8, node)
        reader.qword_put(node, COMPLETED_SENTINEL)
        reader.qword_put(node + 8, COMPLETED_SENTINEL)
        reader.qword_put(node + 0x10, definition)
        after = cm.capture_conditions(reader, module, country, loaded, code_guards=guards)
        self.assertEqual(after["status"], "observed")
        self.assertFalse(before["tasks"][0]["task_completed"])
        self.assertTrue(after["tasks"][0]["task_completed"])
        self.assertNotEqual(before["_compare"]["rawreads"], after["_compare"]["rawreads"])
        self.assertTrue(mm._diff_paths(before["_compare"], after["_compare"]))

    def test_name_and_completed_walks_share_total_chain_step_budget(self):
        reader, module, country = base_reader()
        names: list[str] = []
        target_bucket: int | None = None
        for index in range(5000):
            name = f"chain_{index}"
            bucket = _fnv1(name) & 7
            if target_bucket is None:
                target_bucket = bucket
            if bucket == target_bucket:
                names.append(name)
            if len(names) == 127:
                break
        self.assertEqual(len(names), 127)

        name_entries = [
            (name, 0xA00000 + index * 0x1000)
            for index, name in enumerate(names)
        ]
        _install_name_map(reader, module, name_entries)
        shared_steps = [0]
        tracking_reader = cm._TrackingReader(reader)
        name_walk = cm._MapWalk(
            tracking_reader,
            {"begin": NAME_BUCKETS, "sentinel": NAME_SENTINEL, "mask": 7, "size": 127},
            "name_registry",
            shared_steps,
        )
        for name, (_key, definition) in zip(names[:64], name_entries[:64]):
            self.assertEqual(name_walk.find_name(name), definition)
        self.assertEqual(shared_steps[0], 127 * 64)

        completed_target = 0xB00000
        completed_bucket = _fnv1a64(completed_target.to_bytes(8, "little")) & 7
        completed_definitions = [completed_target]
        candidate = completed_target + 8
        while len(completed_definitions) < 65:
            if (_fnv1a64(candidate.to_bytes(8, "little")) & 7) == completed_bucket:
                completed_definitions.append(candidate)
            candidate += 8
        _install_completed_map(reader, country, completed_definitions)
        completed_walk = cm._MapWalk(
            tracking_reader,
            {
                "begin": COMPLETED_BUCKETS,
                "sentinel": COMPLETED_SENTINEL,
                "mask": 7,
                "size": 65,
            },
            "completed_map",
            shared_steps,
        )
        with self.assertRaisesRegex(ValueError, "max_total_chain_steps_exceeded"):
            completed_walk.contains_definition(completed_target)
        self.assertEqual(shared_steps[0], cm.MAX_TOTAL_CHAIN_STEPS)


if __name__ == "__main__":
    unittest.main()
