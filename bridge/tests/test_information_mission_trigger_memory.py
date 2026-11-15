"""Synthetic bounds/evaluation coverage for mission trigger RPM capture."""
from __future__ import annotations

import unittest
from unittest.mock import patch

from bridge.information import mission_memory as mm
from bridge.information import mission_task_memory as tm
from bridge.information import mission_trigger_memory as trigger
from bridge.tests.test_information_mission_condition_memory import (
    synthetic_condition_fixture,
)


_VTABLE_RVAS = {
    "and": trigger.ROOT_GROUP_VTABLE_RVA,
    "nested_and": 0x1D05300,
    "or": 0x1D04E00,
    "nor": 0x1D04D80,
    "sailors": 0x1D02D28,
    "explorer": 0x1D00790,
    "galley": 0x1CFDFE0,
    "unsupported": 0x1D11110,
}
_METHOD_RVAS = {
    "and": trigger.AND_EVALUATE_RVA,
    "nested_and": trigger.AND_EVALUATE_RVA,
    "or": trigger.OR_EVALUATE_RVA,
    "nor": trigger.NOR_EVALUATE_RVA,
    "sailors": trigger.SAILORS_EVALUATE_RVA,
    "explorer": trigger.EXPLORER_EVALUATE_RVA,
    "galley": trigger.GALLEY_EVALUATE_RVA,
    "unsupported": 0x1234567,
}


def _fixture(task_ids: tuple[str, ...] = ("task_a",)):
    reader, module, country, loaded, guards, definitions, _nodes, _completed = (
        synthetic_condition_fixture(task_ids)
    )
    reader.qword_put(
        module + trigger.GROUP_PARSER_VTABLE_RVA + trigger.GROUP_PARSER_CALLBACK_SLOT,
        module + trigger.GROUP_PARSER_CALLBACK_RVA,
    )
    task_pointers = {
        row["task_id"]: int(row["task_pointer"]["va"], 0)
        for row in loaded["tasks"]
    }
    return reader, module, country, loaded, guards, definitions, task_pointers


class _StrictAlignmentReader:
    """Model RPM readers that require unaligned payloads to use read_code."""

    def __init__(self, reader):
        self._reader = reader
        self.module_base = reader.module_base
        self.unaligned_code_reads: list[tuple[int, int, str]] = []

    def read(self, address: int, size: int, label: str) -> bytes:
        if size and address & 7:
            raise AssertionError(f"unaligned read() forbidden: {hex(address)} {label}")
        return self._reader.read(address, size, label)

    def read_code(self, address: int, size: int, label: str) -> bytes:
        if size and address & 7:
            self.unaligned_code_reads.append((address, size, label))
        return self._reader.read(address, size, label)


def _set_method(reader, module: int, kind: str, *, method_rva: int | None = None,
                vtable_rva: int | None = None) -> int:
    vtable_rva = _VTABLE_RVAS[kind] if vtable_rva is None else vtable_rva
    method_rva = _METHOD_RVAS[kind] if method_rva is None else method_rva
    reader.qword_put(module + vtable_rva + trigger.GROUP_EVALUATE_SLOT,
                     module + method_rva)
    return module + vtable_rva


def _write_group(reader, module: int, pointer: int, children: list[int], kind: str,
                 *, token: int | None = None, capacity: int | None = None,
                 data_pointer: int | None = None) -> None:
    capacity = max(trigger.INLINE_GROUP_CAPACITY, len(children)) if capacity is None else capacity
    vtable = _set_method(reader, module, kind)
    reader.qword_put(pointer, vtable)
    if data_pointer is None:
        data_pointer = pointer + trigger.GROUP_INLINE_OFFSET if capacity <= 4 else 0xA10000 + pointer % 0x10000
    reader.qword_put(pointer + trigger.GROUP_DATA_OFFSET, data_pointer)
    reader.dword_put(pointer + trigger.GROUP_CAPACITY_OFFSET, capacity, signed=True)
    reader.dword_put(pointer + trigger.GROUP_COUNT_OFFSET, len(children), signed=True)
    reader.qword_put(pointer + trigger.GROUP_PARSER_OFFSET,
                     module + trigger.GROUP_PARSER_VTABLE_RVA)
    if token is not None:
        reader.put(pointer + trigger.NODE_TOKEN_OFFSET,
                   token.to_bytes(4, "little"))
    for index, child in enumerate(children):
        reader.qword_put(data_pointer + index * 8, child)


def _write_leaf(reader, module: int, pointer: int, kind: str, token: int,
                threshold: int, *, literal_flag: int = 0,
                dynamic_flags: int = 0) -> None:
    reader.qword_put(pointer, _set_method(reader, module, kind))
    reader.put(pointer + trigger.NODE_LITERAL_FLAGS_OFFSET, bytes([literal_flag]))
    reader.put(pointer + trigger.NODE_TOKEN_OFFSET,
               token.to_bytes(4, "little"))
    reader.dword_put(pointer + trigger.NODE_DYNAMIC_FLAGS_OFFSET, dynamic_flags)
    reader.dword_put(pointer + trigger.NODE_THRESHOLD_OFFSET, threshold, signed=True)


def _install_root(reader, module: int, task_pointer: int, children: list[int]) -> int:
    root_pointer = task_pointer + trigger.TASK_TRIGGER_OFFSET
    _write_group(reader, module, root_pointer, children, "and")
    return root_pointer


class MissionTriggerMemoryTests(unittest.TestCase):
    def test_nested_three_state_logic_and_empty_nor(self):
        reader, module, country, loaded, guards, _definitions, pointers = _fixture()
        root = pointers["task_a"] + trigger.TASK_TRIGGER_OFFSET
        or_group, nor_group, and_group, empty_or = 0xA20000, 0xA21000, 0xA22000, 0xA23000
        unsupported_or, sailors_true = 0xA30000, 0xA31000
        unsupported_and, sailors_false = 0xA32000, 0xA33000
        _write_leaf(reader, module, unsupported_or, "unsupported", 1, 0)
        _write_leaf(reader, module, unsupported_and, "unsupported", 2, 0)
        _write_leaf(reader, module, sailors_true, "sailors", trigger.SAILORS_TOKEN, 1000)
        _write_leaf(reader, module, sailors_false, "sailors", trigger.SAILORS_TOKEN, 1000)
        reader.dword_put(country + trigger.SAILORS_CURRENT_OFFSET, 1, signed=True)
        reader.dword_put(country + trigger.SAILORS_MAX_OFFSET, 1, signed=True)
        _write_group(reader, module, or_group, [unsupported_or, sailors_true], "or", token=0x296C)
        _write_group(reader, module, nor_group, [], "nor", token=0x296D)
        _write_group(reader, module, and_group, [unsupported_and, sailors_false],
                     "nested_and", token=0x2F4D)
        _write_group(reader, module, empty_or, [], "or", token=0x296C)
        # Nested logical constructors do not use the root parser contract at +0x38.
        for nested_group in (or_group, nor_group, and_group, empty_or):
            reader.qword_put(nested_group + trigger.GROUP_PARSER_OFFSET, 0xA10000)
        _install_root(reader, module, pointers["task_a"],
                      [or_group, nor_group, and_group, empty_or])

        result = trigger.capture_triggers(reader, module, country, loaded, code_guards=guards)

        self.assertEqual(result["status"], "observed")
        self.assertTrue(result["complete"])
        tree = result["tasks"][0]["tree"]
        self.assertEqual(tree["kind"], "and")
        self.assertIsNone(tree["token"])
        self.assertEqual(tree["method_rva"], trigger.AND_EVALUATE_RVA)
        self.assertFalse(tree["evaluation"]["satisfied"])
        self.assertEqual(tree["children"][0]["evaluation"]["satisfied"], True)
        self.assertEqual(tree["children"][1]["kind"], "nor")
        self.assertEqual(tree["children"][1]["children"], [])
        self.assertTrue(tree["children"][1]["evaluation"]["satisfied"])
        self.assertFalse(tree["children"][2]["evaluation"]["satisfied"])
        self.assertFalse(tree["children"][3]["evaluation"]["satisfied"])
        self.assertEqual(result["_compare"]["tasks"][0]["task_pointer"], pointers["task_a"])
        self.assertTrue(result["_compare"]["rawreads"])

        _install_root(reader, module, pointers["task_a"], [])
        empty_and = trigger.capture_triggers(reader, module, country, loaded, code_guards=guards)
        self.assertTrue(empty_and["tasks"][0]["tree"]["evaluation"]["satisfied"])

    def test_unsupported_method_is_complete_but_unknown(self):
        reader, module, country, loaded, guards, _definitions, pointers = _fixture()
        leaf = 0xA30000
        _write_leaf(reader, module, leaf, "unsupported", 0x1234, 0)
        _install_root(reader, module, pointers["task_a"], [leaf])

        result = trigger.capture_triggers(reader, module, country, loaded, code_guards=guards)

        tree = result["tasks"][0]["tree"]
        self.assertEqual(result["status"], "observed")
        self.assertTrue(result["complete"])
        self.assertEqual(tree["evaluation"]["status"], "unknown")
        unsupported = tree["children"][0]
        self.assertEqual(unsupported["kind"], "unsupported")
        self.assertNotIn("children", unsupported)
        self.assertEqual(unsupported["evaluation"]["reason"], "unsupported_method")
        self.assertTrue(result["unknown_conditions"])

    def test_scalar_method_and_token_must_match_and_dynamic_targets_are_unknown(self):
        reader, module, country, loaded, guards, _definitions, pointers = _fixture()
        explorer, galley, mismatch = 0xA30000, 0xA31000, 0xA32000
        _write_leaf(reader, module, explorer, "explorer", trigger.EXPLORER_TOKEN, 2,
                    dynamic_flags=0x4000)
        _write_leaf(reader, module, galley, "galley", trigger.GALLEY_TOKEN, 3,
                    literal_flag=1)
        _write_leaf(reader, module, mismatch, "sailors", 0x10033F0, 0)
        _install_root(reader, module, pointers["task_a"], [explorer, galley, mismatch])

        result = trigger.capture_triggers(reader, module, country, loaded, code_guards=guards)

        tree = result["tasks"][0]["tree"]
        self.assertEqual(result["status"], "observed")
        self.assertTrue(result["complete"])
        self.assertIsNone(tree["evaluation"]["satisfied"])
        self.assertEqual(tree["children"][0]["evaluation"]["reason"], "dynamic_threshold_unsupported")
        self.assertEqual(tree["children"][1]["evaluation"]["reason"], "dynamic_threshold_unsupported")
        self.assertEqual(tree["children"][2]["kind"], "unsupported")
        self.assertEqual(tree["children"][2]["token"], 0x10033F0)
        self.assertEqual(tree["children"][2]["evaluation"]["reason"], "scalar_method_token_mismatch")

    def test_sailors_uses_truncation_wrapping_and_native_zero_max_false(self):
        reader, module, country, loaded, guards, _definitions, pointers = _fixture()
        negative, overflow, zero_max = 0xA30000, 0xA31000, 0xA32000
        _write_leaf(reader, module, negative, "sailors", trigger.SAILORS_TOKEN, -333)
        _write_leaf(reader, module, overflow, "sailors", trigger.SAILORS_TOKEN, -1000)
        _write_leaf(reader, module, zero_max, "sailors", trigger.SAILORS_TOKEN, -99999)
        _install_root(reader, module, pointers["task_a"], [negative, overflow, zero_max])
        reader.dword_put(country + trigger.SAILORS_CURRENT_OFFSET, -1, signed=True)
        reader.dword_put(country + trigger.SAILORS_MAX_OFFSET, 3, signed=True)
        # The second scalar reads the same observed current/max fields.  A separate
        # capture below changes them to exercise signed low-32-bit wrap.

        truncated = trigger.capture_triggers(reader, module, country, loaded, code_guards=guards)
        children = truncated["tasks"][0]["tree"]["children"]
        self.assertTrue(children[0]["evaluation"]["satisfied"])
        self.assertEqual(children[0]["metric"]["derived_ratio_milli"], -333)
        self.assertTrue(children[1]["evaluation"]["satisfied"])

        reader.dword_put(country + trigger.SAILORS_CURRENT_OFFSET, 1, signed=True)
        positive = trigger.capture_triggers(reader, module, country, loaded, code_guards=guards)
        self.assertEqual(
            positive["tasks"][0]["tree"]["children"][0]["metric"]["derived_ratio_milli"],
            333,
        )

        reader.dword_put(country + trigger.SAILORS_CURRENT_OFFSET, -1, signed=True)
        reader.dword_put(country + trigger.SAILORS_MAX_OFFSET, 0, signed=True)
        zero_max = trigger.capture_triggers(reader, module, country, loaded, code_guards=guards)
        zero_max_child = zero_max["tasks"][0]["tree"]["children"][2]
        self.assertFalse(zero_max_child["evaluation"]["satisfied"])
        self.assertIsNone(zero_max_child["metric"]["derived_ratio_milli"])

        reader.dword_put(country + trigger.SAILORS_CURRENT_OFFSET, 0x7FFFFFFF, signed=True)
        reader.dword_put(country + trigger.SAILORS_MAX_OFFSET, 1, signed=True)
        wrapped = trigger.capture_triggers(reader, module, country, loaded, code_guards=guards)
        wrapped_child = wrapped["tasks"][0]["tree"]["children"][1]
        self.assertEqual(wrapped_child["metric"]["derived_ratio_milli"], -1000)
        self.assertTrue(wrapped_child["evaluation"]["satisfied"])

    def test_explorer_reads_country_counter_and_retracts_on_bad_pointer_or_short_read(self):
        reader, module, country, loaded, guards, _definitions, pointers = _fixture()
        leaf, counter = 0xA30000, 0xA40000
        _write_leaf(reader, module, leaf, "explorer", trigger.EXPLORER_TOKEN, 2)
        _install_root(reader, module, pointers["task_a"], [leaf])
        reader.qword_put(country + trigger.EXPLORER_COUNTER_POINTER_OFFSET, counter)
        reader.dword_put(counter + trigger.EXPLORER_COUNTER_OFFSET, 2, signed=True)

        observed = trigger.capture_triggers(reader, module, country, loaded, code_guards=guards)
        self.assertTrue(observed["tasks"][0]["tree"]["children"][0]["evaluation"]["satisfied"])
        self.assertEqual(observed["tasks"][0]["tree"]["children"][0]["metric"]["actual"], 2)
        self.assertTrue(any("explorer_count" in row["label"] for row in observed["_compare"]["rawreads"]))

        reader.qword_put(country + trigger.EXPLORER_COUNTER_POINTER_OFFSET, 0x12345)
        bad_pointer = trigger.capture_triggers(reader, module, country, loaded, code_guards=guards)
        self.assertEqual(bad_pointer["status"], "unknown")
        self.assertFalse(bad_pointer["complete"])
        self.assertEqual(bad_pointer["tasks"], [])

        reader.qword_put(country + trigger.EXPLORER_COUNTER_POINTER_OFFSET, counter)
        original_read = reader.read

        def short_read(address, size, label):
            if address == counter + trigger.EXPLORER_COUNTER_OFFSET and size == 4:
                return b"\x02\x00"
            return original_read(address, size, label)

        reader.read = short_read
        short = trigger.capture_triggers(reader, module, country, loaded, code_guards=guards)
        self.assertEqual(short["status"], "unknown")
        self.assertFalse(short["complete"])
        self.assertEqual(short["tasks"], [])

    def test_unaligned_dwords_use_the_tracked_read_code_path(self):
        memory, module, country, loaded, guards, _definitions, pointers = _fixture()
        sailors, explorer, counter = 0xA30000, 0xA31000, 0xA40000
        _write_leaf(memory, module, sailors, "sailors", trigger.SAILORS_TOKEN, 1000)
        _write_leaf(memory, module, explorer, "explorer", trigger.EXPLORER_TOKEN, 1)
        _install_root(memory, module, pointers["task_a"], [sailors, explorer])
        memory.dword_put(country + trigger.SAILORS_CURRENT_OFFSET, 1, signed=True)
        memory.dword_put(country + trigger.SAILORS_MAX_OFFSET, 1, signed=True)
        memory.qword_put(country + trigger.EXPLORER_COUNTER_POINTER_OFFSET, counter)
        memory.dword_put(counter + trigger.EXPLORER_COUNTER_OFFSET, 1, signed=True)
        strict_reader = _StrictAlignmentReader(memory)

        result = trigger.capture_triggers(
            strict_reader, module, country, loaded, code_guards=guards
        )

        self.assertEqual(result["status"], "observed")
        self.assertTrue(result["complete"])
        unaligned_addresses = {
            address for address, _size, _label in strict_reader.unaligned_code_reads
        }
        self.assertIn(country + trigger.SAILORS_MAX_OFFSET, unaligned_addresses)
        self.assertIn(counter + trigger.EXPLORER_COUNTER_OFFSET, unaligned_addresses)

    def test_galley_counter_callback_is_tracked_and_none_stays_unknown(self):
        reader, module, country, loaded, guards, _definitions, pointers = _fixture()
        leaf, fixed_address = 0xA30000, 0xA40000
        _write_leaf(reader, module, leaf, "galley", trigger.GALLEY_TOKEN, 2)
        _install_root(reader, module, pointers["task_a"], [leaf])

        unavailable = trigger.capture_triggers(reader, module, country, loaded, code_guards=guards)
        unavailable_leaf = unavailable["tasks"][0]["tree"]["children"][0]
        self.assertEqual(unavailable["status"], "observed")
        self.assertTrue(unavailable["complete"])
        self.assertIsNone(unavailable_leaf["evaluation"]["satisfied"])
        self.assertEqual(unavailable_leaf["evaluation"]["reason"], "GALLEY_COUNTER_UNAVAILABLE")

        reader.dword_put(fixed_address, 2500, signed=True)

        def counter(tracked_reader, _module_base, _country_pointer):
            raw = tracked_reader.read(fixed_address, 4, "test.galley.raw_fixed")
            return {
                "raw_fixed_milli": int.from_bytes(raw, "little", signed=True),
                "source": "synthetic-native-fixedpoint",
            }

        available = trigger.capture_triggers(
            reader, module, country, loaded, code_guards=guards, galley_counter=counter
        )
        available_leaf = available["tasks"][0]["tree"]["children"][0]
        self.assertTrue(available_leaf["evaluation"]["satisfied"])
        self.assertEqual(available_leaf["metric"]["raw_fixed_milli"], 2500)
        self.assertEqual(available_leaf["metric"]["required_fixed_milli"], 2000)
        self.assertEqual(available_leaf["metric"]["source"], "synthetic-native-fixedpoint")
        self.assertTrue(any(row["label"] == "test.galley.raw_fixed"
                            for row in available["_compare"]["rawreads"]))

        compat = trigger.capture_triggers(
            reader, module, country, loaded, code_guards=guards,
            galley_counter=lambda _reader, _module, _country: 2,
        )
        compat_leaf = compat["tasks"][0]["tree"]["children"][0]
        self.assertTrue(compat_leaf["evaluation"]["satisfied"])
        self.assertEqual(compat_leaf["metric"]["count"], 2)
        self.assertEqual(compat_leaf["metric"]["raw_fixed_milli"], 2000)

        _write_leaf(reader, module, leaf, "galley", trigger.GALLEY_TOKEN, 2_147_484)
        wrapped = trigger.capture_triggers(
            reader, module, country, loaded, code_guards=guards,
            galley_counter=lambda _reader, _module, _country: 2_147_484,
        )
        wrapped_leaf = wrapped["tasks"][0]["tree"]["children"][0]
        self.assertEqual(wrapped_leaf["metric"]["raw_fixed_milli"], -2_147_483_296)
        self.assertEqual(wrapped_leaf["metric"]["required_fixed_milli"], -2_147_483_296)
        self.assertTrue(wrapped_leaf["evaluation"]["satisfied"])

    def test_cycle_depth_node_budget_invalid_vector_and_guard_mismatch_retract(self):
        reader, module, country, loaded, guards, _definitions, pointers = _fixture()
        root = pointers["task_a"] + trigger.TASK_TRIGGER_OFFSET
        _write_group(reader, module, root, [root], "and")
        cycle = trigger.capture_triggers(reader, module, country, loaded, code_guards=guards)
        self.assertEqual(cycle["status"], "unknown")
        self.assertFalse(cycle["complete"])
        self.assertEqual(cycle["tasks"], [])

        reader, module, country, loaded, guards, _definitions, pointers = _fixture()
        root = pointers["task_a"] + trigger.TASK_TRIGGER_OFFSET
        chain = [0xA20000 + index * 0x100 for index in range(trigger.MAX_TREE_DEPTH + 1)]
        terminal = 0xA40000
        _write_leaf(reader, module, terminal, "unsupported", 1, 0)
        _write_group(reader, module, root, [chain[0]], "and")
        for index, pointer in enumerate(chain):
            child = chain[index + 1] if index + 1 < len(chain) else terminal
            _write_group(reader, module, pointer, [child], "nested_and", token=0x2F4D)
        too_deep = trigger.capture_triggers(reader, module, country, loaded, code_guards=guards)
        self.assertEqual(too_deep["status"], "unknown")
        self.assertEqual(too_deep["tasks"], [])

        reader, module, country, loaded, guards, _definitions, pointers = _fixture()
        root = pointers["task_a"] + trigger.TASK_TRIGGER_OFFSET
        first, second = 0xA30000, 0xA31000
        _write_leaf(reader, module, first, "unsupported", 1, 0)
        _write_leaf(reader, module, second, "unsupported", 2, 0)
        _write_group(reader, module, root, [first, second], "and")
        with patch.object(trigger, "MAX_TOTAL_NODES", 2):
            over_nodes = trigger.capture_triggers(reader, module, country, loaded, code_guards=guards)
        self.assertEqual(over_nodes["status"], "unknown")
        self.assertEqual(over_nodes["tasks"], [])

        reader, module, country, loaded, guards, _definitions, pointers = _fixture()
        root = pointers["task_a"] + trigger.TASK_TRIGGER_OFFSET
        _write_group(reader, module, root, [0x12345], "and")
        bad_child = trigger.capture_triggers(reader, module, country, loaded, code_guards=guards)
        self.assertEqual(bad_child["status"], "unknown")
        self.assertEqual(bad_child["tasks"], [])

        reader, module, country, loaded, guards, _definitions, pointers = _fixture()
        root = pointers["task_a"] + trigger.TASK_TRIGGER_OFFSET
        _write_group(reader, module, root, [0xA30000] * 257, "and", capacity=257)
        over_group_count = trigger.capture_triggers(reader, module, country, loaded,
                                                    code_guards=guards)
        self.assertEqual(over_group_count["status"], "unknown")
        self.assertEqual(over_group_count["tasks"], [])

        reader, module, country, loaded, guards, _definitions, pointers = _fixture()
        root = pointers["task_a"] + trigger.TASK_TRIGGER_OFFSET
        _write_group(reader, module, root, [], "and", capacity=4097, data_pointer=0xA10000)
        over_group_capacity = trigger.capture_triggers(
            reader, module, country, loaded, code_guards=guards
        )
        self.assertEqual(over_group_capacity["status"], "unknown")
        self.assertEqual(over_group_capacity["tasks"], [])

        reader, module, country, loaded, guards, _definitions, pointers = _fixture()
        root = pointers["task_a"] + trigger.TASK_TRIGGER_OFFSET
        _write_group(reader, module, root, [0xA30000], "and", capacity=5,
                     data_pointer=(tm.MAX_USER_ADDRESS - 7) & ~7)
        checked_range = trigger.capture_triggers(reader, module, country, loaded, code_guards=guards)
        self.assertEqual(checked_range["status"], "unknown")
        self.assertEqual(checked_range["tasks"], [])

        reader, module, country, loaded, guards, _definitions, pointers = _fixture()
        root = pointers["task_a"] + trigger.TASK_TRIGGER_OFFSET
        leaf = 0xA30000
        _write_leaf(reader, module, leaf, "unsupported", 1, 0)
        _install_root(reader, module, pointers["task_a"], [leaf])
        reader.put(module + 0x500, b"\x00")
        guard_mismatch = trigger.capture_triggers(reader, module, country, loaded, code_guards=guards)
        self.assertEqual(guard_mismatch["status"], "unknown")
        self.assertEqual(guard_mismatch["tasks"], [])

    def test_group_header_drift_retracts_and_later_raw_drift_is_visible(self):
        reader, module, country, loaded, guards, _definitions, pointers = _fixture()
        root = pointers["task_a"] + trigger.TASK_TRIGGER_OFFSET
        leaf = 0xA30000
        _write_leaf(reader, module, leaf, "unsupported", 1, 0)
        _install_root(reader, module, pointers["task_a"], [leaf])
        original_read = reader.read

        def drift_header(address, size, label):
            raw = original_read(address, size, label)
            if address == root and size == 0x18:
                changed = bytearray(raw)
                changed[:8] = (module + _VTABLE_RVAS["nested_and"]).to_bytes(8, "little")
                return bytes(changed)
            return raw

        reader.read = drift_header
        drifted_capture = trigger.capture_triggers(reader, module, country, loaded, code_guards=guards)
        self.assertEqual(drifted_capture["status"], "unknown")
        self.assertEqual(drifted_capture["tasks"], [])

        reader, module, country, loaded, guards, _definitions, pointers = _fixture()
        root = pointers["task_a"] + trigger.TASK_TRIGGER_OFFSET
        leaf = 0xA30000
        _write_leaf(reader, module, leaf, "sailors", trigger.SAILORS_TOKEN, 1)
        _install_root(reader, module, pointers["task_a"], [leaf])
        reader.dword_put(country + trigger.SAILORS_CURRENT_OFFSET, 1, signed=True)
        reader.dword_put(country + trigger.SAILORS_MAX_OFFSET, 1, signed=True)
        first = trigger.capture_triggers(reader, module, country, loaded, code_guards=guards)
        reader.dword_put(country + trigger.SAILORS_CURRENT_OFFSET, 0, signed=True)
        second = trigger.capture_triggers(reader, module, country, loaded, code_guards=guards)
        self.assertTrue(mm._diff_paths(first["_compare"], second["_compare"]))
        self.assertNotEqual(first["_compare"]["rawreads"], second["_compare"]["rawreads"])


if __name__ == "__main__":
    unittest.main()
