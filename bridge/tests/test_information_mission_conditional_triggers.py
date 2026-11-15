"""Synthetic RPM coverage for loaded mission IF/ELSE trigger trees."""
from __future__ import annotations

import unittest
from unittest.mock import patch

from bridge.information import mission_memory as mm
from bridge.information import mission_trigger_memory as trigger
from bridge.tests.test_information_mission_province_triggers import (
    _province_reader,
    _root_reference,
    _write_province_leaf,
    _write_reference,
    _write_scope,
)
from bridge.tests.test_information_mission_trigger_memory import (
    _StrictAlignmentReader,
    _fixture,
    _install_root,
    _set_method,
    _write_group,
    _write_leaf,
)


_IF_VTABLE_RVA = 0x1D25000


def _write_explicit_group(reader, module: int, pointer: int,
                          children: list[int], *, kind: str = "or") -> None:
    """Write a group whose native call site, rather than vtable, chooses AND."""
    _write_group(reader, module, pointer, children, kind)


def _write_if(reader, module: int, pointer: int, *,
              limit_children: list[int], then_children: list[int],
              else_children: list[int], token: int = 0xF1234567,
              elseif_pointer: int = 0) -> None:
    # The IF object doubles as the then-body vector. Its vtable points to the
    # IF evaluator, while the native conditional flow calls B98070 directly.
    _write_group(reader, module, pointer, then_children, "unsupported", token=token)
    if_vtable = _set_method(
        reader, module, "unsupported", method_rva=trigger.IF_EVALUATE_RVA,
        vtable_rva=_IF_VTABLE_RVA,
    )
    reader.qword_put(pointer, if_vtable)
    _write_explicit_group(
        reader, module, pointer + trigger.IF_LIMIT_OFFSET, limit_children
    )
    _write_explicit_group(
        reader, module, pointer + trigger.IF_ELSE_OFFSET, else_children,
        kind="nor",
    )
    reader.qword_put(pointer + trigger.IF_ELSEIF_POINTER_OFFSET, elseif_pointer)


def _install_single_if(reader, module: int, task_pointer: int,
                       if_pointer: int, **kwargs) -> None:
    _write_if(reader, module, if_pointer, **kwargs)
    _install_root(reader, module, task_pointer, [if_pointer])


class MissionConditionalTriggerTests(unittest.TestCase):
    def test_limit_selects_then_or_else_and_exports_full_token_without_children(self):
        reader, module, country, loaded, guards, _definitions, pointers = _fixture()
        if_pointer = 0xA20000
        limit, then_leaf, else_leaf = 0xA30000, 0xA31000, 0xA32000
        _write_leaf(reader, module, limit, "sailors", trigger.SAILORS_TOKEN, 1000)
        _write_leaf(reader, module, then_leaf, "sailors", trigger.SAILORS_TOKEN, 1000)
        _write_leaf(reader, module, else_leaf, "sailors", trigger.SAILORS_TOKEN, 1001)
        reader.dword_put(country + trigger.SAILORS_CURRENT_OFFSET, 1, signed=True)
        reader.dword_put(country + trigger.SAILORS_MAX_OFFSET, 1, signed=True)
        _install_single_if(
            reader, module, pointers["task_a"], if_pointer,
            limit_children=[limit], then_children=[then_leaf],
            else_children=[else_leaf], token=0xF1234567,
        )

        then_result = trigger.capture_triggers(
            reader, module, country, loaded, code_guards=guards
        )
        then_tree = then_result["tasks"][0]["tree"]["children"][0]
        self.assertEqual(then_tree["kind"], "if")
        self.assertEqual(then_tree["token"], 0xF1234567)
        self.assertEqual(then_tree["method_rva"], trigger.IF_EVALUATE_RVA)
        self.assertNotIn("children", then_tree)
        self.assertTrue({"limit", "then", "else"}.issubset(then_tree))
        self.assertEqual(then_tree["selected_branch"], "then")
        self.assertTrue(then_tree["evaluation"]["satisfied"])
        self.assertEqual(
            then_result["_compare"]["tasks"][0]["tree"]["children"][0]
            ["branches"]["then"]["dispatch"],
            "direct_call",
        )

        reader.dword_put(country + trigger.SAILORS_CURRENT_OFFSET, 0, signed=True)
        else_result = trigger.capture_triggers(
            reader, module, country, loaded, code_guards=guards
        )
        else_tree = else_result["tasks"][0]["tree"]["children"][0]
        self.assertEqual(else_tree["selected_branch"], "else")
        self.assertFalse(else_tree["evaluation"]["satisfied"])

    def test_empty_else_is_vacuously_true_and_static_group_dispatch_is_and(self):
        reader, module, country, loaded, guards, _definitions, pointers = _fixture()
        if_pointer = 0xA20000
        false_limit, false_then = 0xA30000, 0xA31000
        _write_leaf(reader, module, false_limit, "sailors", trigger.SAILORS_TOKEN, 1001)
        _write_leaf(reader, module, false_then, "sailors", trigger.SAILORS_TOKEN, 1001)
        reader.dword_put(country + trigger.SAILORS_CURRENT_OFFSET, 1, signed=True)
        reader.dword_put(country + trigger.SAILORS_MAX_OFFSET, 1, signed=True)
        _install_single_if(
            reader, module, pointers["task_a"], if_pointer,
            limit_children=[false_limit], then_children=[false_then],
            else_children=[],
        )

        result = trigger.capture_triggers(
            reader, module, country, loaded, code_guards=guards
        )

        tree = result["tasks"][0]["tree"]["children"][0]
        self.assertEqual(tree["selected_branch"], "else")
        self.assertEqual(tree["else"]["kind"], "and")
        self.assertEqual(tree["else"]["children"], [])
        self.assertTrue(tree["else"]["evaluation"]["satisfied"])
        self.assertTrue(tree["evaluation"]["satisfied"])
        # The empty else header carries a NOR vtable, but B98070's static call
        # makes this branch an AND group with vacuous truth.
        compare_else = result["_compare"]["tasks"][0]["tree"]["children"][0]
        self.assertEqual(compare_else["branches"]["else"]["dispatch"], "direct_call")
        self.assertEqual(compare_else["branches"]["else"]["vtable"], module + 0x1D04D80)

    def test_elseif_chain_is_followed_only_as_a_verified_if_node(self):
        reader, module, country, loaded, guards, _definitions, pointers = _fixture()
        outer, inner = 0xA20000, 0xA24000
        outer_limit, outer_then, inner_then = 0xA30000, 0xA31000, 0xA32000
        _write_leaf(reader, module, outer_limit, "sailors", trigger.SAILORS_TOKEN, 1001)
        _write_leaf(reader, module, outer_then, "sailors", trigger.SAILORS_TOKEN, 1000)
        _write_leaf(reader, module, inner_then, "sailors", trigger.SAILORS_TOKEN, 1000)
        reader.dword_put(country + trigger.SAILORS_CURRENT_OFFSET, 1, signed=True)
        reader.dword_put(country + trigger.SAILORS_MAX_OFFSET, 1, signed=True)
        _write_if(
            reader, module, inner, limit_children=[], then_children=[inner_then],
            else_children=[], token=0x11223344,
        )
        _write_if(
            reader, module, outer, limit_children=[outer_limit],
            then_children=[outer_then], else_children=[], elseif_pointer=inner,
        )
        _install_root(reader, module, pointers["task_a"], [outer])

        result = trigger.capture_triggers(
            reader, module, country, loaded, code_guards=guards
        )

        tree = result["tasks"][0]["tree"]["children"][0]
        self.assertEqual(tree["selected_branch"], "else")
        self.assertEqual(tree["else"]["kind"], "if")
        self.assertEqual(tree["else"]["token"], 0x11223344)
        self.assertEqual(tree["else"]["selected_branch"], "then")
        self.assertTrue(tree["evaluation"]["satisfied"])

        # A nonzero elseif pointer to a different evaluator is not interpreted
        # using that method's unrelated semantics.
        _write_leaf(reader, module, inner, "sailors", trigger.SAILORS_TOKEN, 1000)
        bad_method = trigger.capture_triggers(
            reader, module, country, loaded, code_guards=guards
        )
        self.assertEqual(bad_method["status"], "unknown")
        self.assertFalse(bad_method["complete"])
        self.assertEqual(bad_method["tasks"], [])

    def test_unknown_limit_is_known_only_when_both_branch_values_match(self):
        for then_threshold, else_threshold, expected in (
            (1000, 1000, True),
            (1000, 1001, None),
        ):
            with self.subTest(expected=expected):
                reader, module, country, loaded, guards, _definitions, pointers = _fixture()
                if_pointer = 0xA20000
                unknown_limit, then_leaf, else_leaf = 0xA30000, 0xA31000, 0xA32000
                _write_leaf(reader, module, unknown_limit, "unsupported", 0x1234, 0)
                _write_leaf(reader, module, then_leaf, "sailors", trigger.SAILORS_TOKEN,
                            then_threshold)
                _write_leaf(reader, module, else_leaf, "sailors", trigger.SAILORS_TOKEN,
                            else_threshold)
                reader.dword_put(country + trigger.SAILORS_CURRENT_OFFSET, 1, signed=True)
                reader.dword_put(country + trigger.SAILORS_MAX_OFFSET, 1, signed=True)
                _install_single_if(
                    reader, module, pointers["task_a"], if_pointer,
                    limit_children=[unknown_limit], then_children=[then_leaf],
                    else_children=[else_leaf],
                )

                result = trigger.capture_triggers(
                    reader, module, country, loaded, code_guards=guards
                )
                tree = result["tasks"][0]["tree"]["children"][0]
                self.assertEqual(tree["selected_branch"], "unknown")
                self.assertEqual(tree["evaluation"]["satisfied"], expected)
                if expected is None:
                    self.assertEqual(tree["evaluation"]["status"], "unknown")

    def test_if_nested_in_province_scope_keeps_province_and_refuses_country_scalar(self):
        reader, module, country, loaded, guards, _definitions, pointers = _fixture()
        root_reference = _root_reference()
        reader.qword_put(country + 0x20, root_reference)
        scope_pointer, reference = 0xA20000, 0xA50000
        if_pointer, owner_leaf, scalar_leaf = 0xA30000, 0xA31000, 0xA32000
        _write_scope(reader, module, scope_pointer, reference, [if_pointer])
        _write_reference(reader, reference, province_id=7)
        _write_province_leaf(reader, module, owner_leaf, "owned")
        _write_leaf(reader, module, scalar_leaf, "sailors", trigger.SAILORS_TOKEN, 1000)
        _write_if(
            reader, module, if_pointer, limit_children=[owner_leaf],
            then_children=[scalar_leaf], else_children=[],
        )
        _install_root(reader, module, pointers["task_a"], [scope_pointer])
        calls: list[int] = []

        result = trigger.capture_triggers(
            reader, module, country, loaded, code_guards=guards,
            province_reader=_province_reader(country, root_reference, {}, calls),
        )

        tree = result["tasks"][0]["tree"]
        scoped_if = tree["children"][0]["children"][0]
        self.assertEqual(scoped_if["limit"]["children"][0]
                         ["metric"]["province_id"], 7)
        self.assertEqual(scoped_if["then"]["children"][0]
                         ["evaluation"]["reason"],
                         "country_scalar_in_province_scope_unsupported")
        self.assertIsNone(scoped_if["evaluation"]["satisfied"])
        self.assertEqual(calls, [7])

    def test_self_elseif_and_cross_branch_cycles_retract_capture(self):
        reader, module, country, loaded, guards, _definitions, pointers = _fixture()
        if_pointer = 0xA20000
        _write_if(
            reader, module, if_pointer, limit_children=[], then_children=[],
            else_children=[], elseif_pointer=if_pointer,
        )
        _install_root(reader, module, pointers["task_a"], [if_pointer])
        self_elseif = trigger.capture_triggers(
            reader, module, country, loaded, code_guards=guards
        )
        self.assertEqual(self_elseif["status"], "unknown")
        self.assertEqual(self_elseif["tasks"], [])

        reader, module, country, loaded, guards, _definitions, pointers = _fixture()
        if_pointer = 0xA20000
        else_group = if_pointer + trigger.IF_ELSE_OFFSET
        _write_if(
            reader, module, if_pointer, limit_children=[],
            then_children=[else_group], else_children=[if_pointer],
        )
        _install_root(reader, module, pointers["task_a"], [if_pointer])
        cross_branch = trigger.capture_triggers(
            reader, module, country, loaded, code_guards=guards
        )
        self.assertEqual(cross_branch["status"], "unknown")
        self.assertEqual(cross_branch["tasks"], [])

    def test_branch_group_nodes_count_toward_shared_depth_and_node_limits(self):
        reader, module, country, loaded, guards, _definitions, pointers = _fixture()
        if_pointer = 0xA20000
        _write_if(reader, module, if_pointer, limit_children=[],
                  then_children=[], else_children=[])
        _install_root(reader, module, pointers["task_a"], [if_pointer])
        with patch.object(trigger, "MAX_TOTAL_NODES", 4):
            over_branches = trigger.capture_triggers(
                reader, module, country, loaded, code_guards=guards
            )
        self.assertEqual(over_branches["status"], "unknown")
        self.assertEqual(over_branches["tasks"], [])

        reader, module, country, loaded, guards, _definitions, pointers = _fixture()
        if_pointer = 0xA20000
        child = 0xA30000
        _write_leaf(reader, module, child, "unsupported", 1, 0)
        _write_if(reader, module, if_pointer, limit_children=[child],
                  then_children=[], else_children=[])
        _install_root(reader, module, pointers["task_a"], [if_pointer])
        with patch.object(trigger, "MAX_TREE_DEPTH", 2):
            too_deep = trigger.capture_triggers(
                reader, module, country, loaded, code_guards=guards
            )
        self.assertEqual(too_deep["status"], "unknown")
        self.assertEqual(too_deep["tasks"], [])

    def test_unaligned_scalar_heads_use_strict_reader_and_equal_boolean_input_drift_is_traced(self):
        memory, module, country, loaded, guards, _definitions, pointers = _fixture()
        if_pointer, limit = 0xA20000, 0xA30000
        _write_leaf(memory, module, limit, "sailors", trigger.SAILORS_TOKEN, 1000)
        _write_if(memory, module, if_pointer, limit_children=[limit],
                  then_children=[], else_children=[])
        _install_root(memory, module, pointers["task_a"], [if_pointer])
        memory.dword_put(country + trigger.SAILORS_CURRENT_OFFSET, 1, signed=True)
        memory.dword_put(country + trigger.SAILORS_MAX_OFFSET, 1, signed=True)
        strict_reader = _StrictAlignmentReader(memory)

        first = trigger.capture_triggers(
            strict_reader, module, country, loaded, code_guards=guards
        )
        first_if = first["tasks"][0]["tree"]["children"][0]
        self.assertTrue(first_if["limit"]["evaluation"]["satisfied"])
        unaligned = {address for address, _size, _label
                     in strict_reader.unaligned_code_reads}
        self.assertIn(country + trigger.SAILORS_MAX_OFFSET, unaligned)

        memory.dword_put(country + trigger.SAILORS_CURRENT_OFFSET, 2, signed=True)
        memory.dword_put(country + trigger.SAILORS_MAX_OFFSET, 2, signed=True)
        second = trigger.capture_triggers(
            strict_reader, module, country, loaded, code_guards=guards
        )
        second_if = second["tasks"][0]["tree"]["children"][0]
        self.assertTrue(second_if["limit"]["evaluation"]["satisfied"])
        self.assertEqual(first_if["evaluation"]["satisfied"],
                         second_if["evaluation"]["satisfied"])
        self.assertTrue(mm._diff_paths(first["_compare"], second["_compare"]))
        self.assertNotEqual(first["_compare"]["rawreads"],
                            second["_compare"]["rawreads"])


if __name__ == "__main__":
    unittest.main()
