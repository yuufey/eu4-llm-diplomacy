"""Synthetic coverage for geographic and explicit-country mission scopes."""
from __future__ import annotations

import unittest
from unittest.mock import patch

from bridge.information import mission_trigger_memory as trigger
from bridge.tests.test_information_mission_conditional_triggers import _write_if
from bridge.tests.test_information_mission_province_triggers import (
    _other_reference,
    _province_reader,
    _root_reference,
    _write_province_leaf,
    _write_reference,
    _write_scope,
)
from bridge.tests.test_information_mission_trigger_memory import (
    _fixture,
    _install_root,
    _set_method,
    _write_group,
    _write_leaf,
)


_GEOGRAPHIC_VTABLE_RVA = 0x1D21000
_COUNTRY_POINTER = 0x510000
_OTHER_REF = (0x2A << 56) | (321 << 32) | int.from_bytes(b"ENG", "little")
_FRA_REF = _root_reference()
_FRA_COUNTRY_REF = (0x2A << 56) | _FRA_REF


def _write_string32(reader, address: int, value: str) -> None:
    payload = value.encode("ascii") + b"\0"
    header = bytearray(32)
    header[:len(payload)] = payload
    header[16:24] = len(value.encode("ascii")).to_bytes(8, "little")
    header[24:32] = max(len(value.encode("ascii")), 1).to_bytes(8, "little")
    reader.put(address, bytes(header))


def _write_geographic(reader, module: int, pointer: int, children: list[int],
                      name: str, *, native_type: int = trigger.GEOGRAPHIC_ALL_TYPE,
                      token: int = 0xF1234567) -> None:
    vtable = _set_method(reader, module, "unsupported",
                         method_rva=trigger.GEOGRAPHIC_EVALUATE_RVA,
                         vtable_rva=_GEOGRAPHIC_VTABLE_RVA)
    capacity = max(trigger.INLINE_GROUP_CAPACITY, len(children))
    data = (pointer + trigger.GROUP_INLINE_OFFSET if capacity <= 4
            else 0xAB0000 + pointer % 0x10000)
    reader.qword_put(pointer, vtable)
    reader.qword_put(pointer + trigger.GROUP_DATA_OFFSET, data)
    reader.dword_put(pointer + trigger.GROUP_CAPACITY_OFFSET, capacity, signed=True)
    reader.dword_put(pointer + trigger.GROUP_COUNT_OFFSET, len(children), signed=True)
    reader.dword_put(pointer + trigger.NODE_TOKEN_OFFSET, token)
    _write_string32(reader, pointer + trigger.NODE_THRESHOLD_OFFSET, name)
    reader.dword_put(pointer + trigger.GEOGRAPHIC_QUANTIFIER_OFFSET, native_type)
    for index, child in enumerate(children):
        reader.qword_put(data + index * 8, child)


def _write_country_scope_reference(reader, pointer: int, tag: str) -> int:
    reference = {"FRA": _FRA_COUNTRY_REF, "ENG": _OTHER_REF}[tag]
    raw = bytearray(0x218)
    raw[:4] = trigger.COUNTRY_REFERENCE_KIND.to_bytes(4, "little")
    raw[trigger.COUNTRY_REFERENCE_FULLREF_OFFSET:
        trigger.COUNTRY_REFERENCE_FULLREF_OFFSET + 8] = reference.to_bytes(8, "little")
    reader.put(pointer, bytes(raw))
    return reference


def _country_scope_reader(bindings: dict[int, dict], calls: list[int]):
    def read_scope(_reader, _module_base: int, fullref: int):
        calls.append(fullref)
        return bindings.get(fullref, {"status": "unknown", "reason": "fixture_missing"})

    return read_scope


def _geographic_reader(definitions: dict[str, dict], calls: list[str]):
    def read_definition(_reader, _module_base: int, name: str):
        calls.append(name)
        return definitions.get(name, {"status": "unknown", "reason": "fixture_missing"})

    return read_definition


def _known_definition(province_ids: list[int], *, found: bool = True):
    return {"status": "known", "found": found,
            "province_ids": list(province_ids), "source": "synthetic-geographic-reader"}


def _capture_geographic(*, province_ids: list[int], native_type: int,
                        rows: dict[int, dict] | None = None,
                        found: bool = True,
                        children: list[int] | None = None,
                        name: str = "test_area",
                        token: int = 0xF1234567):
    reader, module, country, loaded, guards, _definitions, pointers = _fixture()
    reader.qword_put(country + 0x20, _FRA_REF)
    geo = 0xA20000
    if children is None:
        owned = 0xA30000
        _write_province_leaf(reader, module, owned, "owned")
        children = [owned]
    _write_geographic(reader, module, geo, children, name,
                      native_type=native_type, token=token)
    _install_root(reader, module, pointers["task_a"], [geo])
    definition_calls: list[str] = []
    province_calls: list[int] = []
    result = trigger.capture_triggers(
        reader, module, country, loaded, code_guards=guards,
        province_reader=_province_reader(country, _FRA_REF, rows or {}, province_calls),
        geographic_reader=_geographic_reader(
            {name: _known_definition(province_ids, found=found)}, definition_calls
        ),
    )
    return result, reader, definition_calls, province_calls, (module, country, loaded, guards, pointers)


class MissionGeographicTriggerTests(unittest.TestCase):
    def test_all_any_empty_sets_and_not_found_are_native_vacuity_results(self):
        all_result, _reader, _defs, province_calls, _ctx = _capture_geographic(
            province_ids=[], native_type=trigger.GEOGRAPHIC_ALL_TYPE,
        )
        any_result, _reader, _defs, _calls, _ctx = _capture_geographic(
            province_ids=[], native_type=0x1234,
        )
        missing_result, _reader, _defs, _calls, _ctx = _capture_geographic(
            province_ids=[], native_type=0x1234, found=False,
        )

        all_tree = all_result["tasks"][0]["tree"]["children"][0]
        any_tree = any_result["tasks"][0]["tree"]["children"][0]
        missing_tree = missing_result["tasks"][0]["tree"]["children"][0]
        self.assertTrue(all_tree["evaluation"]["satisfied"])
        self.assertFalse(any_tree["evaluation"]["satisfied"])
        self.assertFalse(missing_tree["evaluation"]["satisfied"])
        self.assertEqual(all_tree["scope"], {
            "kind": "province_set", "name": "test_area", "quantifier": "all",
            "definition_found": True, "domain_complete": True,
        })
        self.assertEqual(any_tree["scope"]["quantifier"], "any")
        self.assertFalse(missing_tree["scope"]["domain_complete"])
        self.assertEqual(all_tree["members"], [])
        self.assertEqual(province_calls, [])

    def test_found_false_does_not_descend_even_with_poisoned_children(self):
        result, _reader, _defs, province_calls, _ctx = _capture_geographic(
            province_ids=[], native_type=trigger.GEOGRAPHIC_ALL_TYPE,
            found=False, children=[0x12345],
        )
        tree = result["tasks"][0]["tree"]["children"][0]
        self.assertEqual(result["status"], "observed")
        self.assertFalse(tree["evaluation"]["satisfied"])
        self.assertEqual(tree["members"], [])
        self.assertEqual(province_calls, [])

    def test_all_and_any_apply_three_state_member_logic(self):
        scenarios = (
            (trigger.GEOGRAPHIC_ALL_TYPE, [
                {"status": "known", "owner": {"status": "known", "tag": "ENG",
                                                  "reference": _other_reference()}},
                {"status": "unknown"},
            ], False),
            (trigger.GEOGRAPHIC_ALL_TYPE, [
                {"status": "known", "owner": {"status": "known", "tag": "FRA",
                                                  "reference": _FRA_REF}},
                {"status": "unknown"},
            ], None),
            (0x1234, [
                {"status": "known", "owner": {"status": "known", "tag": "FRA",
                                                  "reference": _FRA_REF}},
                {"status": "unknown"},
            ], True),
            (0x1234, [
                {"status": "known", "owner": {"status": "ENG",
                                                  "reference": _other_reference()}},
                {"status": "unknown"},
            ], None),
        )
        for native_type, rows, expected in scenarios:
            with self.subTest(native_type=native_type, expected=expected):
                result, _reader, _defs, calls, _ctx = _capture_geographic(
                    province_ids=[42, 43], native_type=native_type,
                    rows={42: rows[0], 43: rows[1]},
                )
                self.assertEqual(result["status"], "observed")
                tree = result["tasks"][0]["tree"]["children"][0]
                self.assertIs(tree["evaluation"]["satisfied"], expected)
                self.assertEqual(calls, [42, 43])
                self.assertEqual([row["province_id"] for row in tree["members"]], [42, 43])
                self.assertEqual(tree["members"][1]["tree"]["kind"], "unsupported")
                self.assertNotIn("children", tree["members"][1]["tree"])

    def test_area_body_is_an_inlined_and_alias_and_full_dword_token_is_kept(self):
        result, _reader, _defs, _calls, _ctx = _capture_geographic(
            province_ids=[42], native_type=trigger.GEOGRAPHIC_ALL_TYPE,
            token=0xFE123456,
        )
        tree = result["tasks"][0]["tree"]["children"][0]
        member_tree = tree["members"][0]["tree"]
        compare = result["_compare"]["tasks"][0]["tree"]["children"][0]
        self.assertEqual(tree["token"], 0xFE123456)
        self.assertEqual(member_tree["kind"], "and")
        self.assertEqual(member_tree["method_rva"], trigger.GEOGRAPHIC_EVALUATE_RVA)
        self.assertEqual(compare["members"][0]["tree"]["dispatch"], "inlined_and_loop")

    def test_geographic_definition_is_cached_by_name_and_callback_absence_is_opaque(self):
        reader, module, country, loaded, guards, _definitions, pointers = _fixture()
        first, second = 0xA20000, 0xA21000
        _write_geographic(reader, module, first, [], "same_area", token=0xF0000001)
        _write_geographic(reader, module, second, [], "same_area", token=0xF0000002)
        _install_root(reader, module, pointers["task_a"], [first, second])
        calls: list[str] = []
        result = trigger.capture_triggers(
            reader, module, country, loaded, code_guards=guards,
            geographic_reader=_geographic_reader({"same_area": _known_definition([])}, calls),
        )
        nodes = result["tasks"][0]["tree"]["children"]
        self.assertEqual(calls, ["same_area"])
        self.assertEqual([node["token"] for node in nodes], [0xF0000001, 0xF0000002])

        no_callback = trigger.capture_triggers(
            reader, module, country, loaded, code_guards=guards,
        )
        opaque = no_callback["tasks"][0]["tree"]["children"][0]
        self.assertEqual(opaque["kind"], "unsupported")
        self.assertIsNone(opaque["token"])
        self.assertEqual(opaque["evaluation"]["reason"], "unsupported_method")
        self.assertNotIn("members", opaque)

    def test_invalid_area_ids_and_65_member_definition_remain_opaque(self):
        cases = ([0], [42, 42], list(range(1, 66)))
        for province_ids in cases:
            with self.subTest(count=len(province_ids), ids=province_ids[:2]):
                result, _reader, _defs, province_calls, _ctx = _capture_geographic(
                    province_ids=province_ids,
                    native_type=trigger.GEOGRAPHIC_ALL_TYPE,
                )
                tree = result["tasks"][0]["tree"]["children"][0]
                self.assertEqual(tree["kind"], "unsupported")
                self.assertNotIn("members", tree)
                self.assertEqual(tree["evaluation"]["status"], "unknown")
                self.assertEqual(province_calls, [])
        self.assertEqual(trigger.MAX_PROVINCE_TARGETS, 128)
        self.assertEqual(trigger.MAX_GEOGRAPHIC_PROVINCE_IDS, 64)

    def test_64_member_definition_is_within_the_capture_limit(self):
        province_ids = list(range(1, 65))
        rows = {province_id: {"status": "unknown"}
                for province_id in province_ids}
        result, _reader, _defs, province_calls, _ctx = _capture_geographic(
            province_ids=province_ids, native_type=trigger.GEOGRAPHIC_ALL_TYPE,
            rows=rows, children=[0x12345],
        )
        self.assertEqual(result["status"], "observed")
        tree = result["tasks"][0]["tree"]["children"][0]
        self.assertEqual(len(tree["members"]), 64)
        self.assertEqual(province_calls, province_ids)

    def test_geographic_province_state_refusal_is_opaque_and_unknown_is_reported(self):
        result, _reader, _defs, calls, _ctx = _capture_geographic(
            province_ids=[42], native_type=trigger.GEOGRAPHIC_ALL_TYPE,
            rows={42: {"status": "unknown"}}, children=[0x12345],
        )
        tree = result["tasks"][0]["tree"]["children"][0]
        member = tree["members"][0]["tree"]
        self.assertEqual(calls, [42])
        self.assertEqual(member["kind"], "unsupported")
        self.assertEqual(member["method_rva"], trigger.GEOGRAPHIC_EVALUATE_RVA)
        self.assertIsNone(member["token"])
        self.assertNotIn("children", member)
        self.assertTrue(any("members[0].tree" in reason
                            for reason in result["unknown_conditions"]))

    def test_geographic_state_root_mismatch_is_opaque_without_descent(self):
        result, _reader, _defs, calls, _ctx = _capture_geographic(
            province_ids=[42], native_type=trigger.GEOGRAPHIC_ALL_TYPE,
            rows={42: {"observer_pointer": _COUNTRY_POINTER}}, children=[0x12345],
        )
        tree = result["tasks"][0]["tree"]["children"][0]
        member = tree["members"][0]["tree"]
        self.assertEqual(calls, [42])
        self.assertEqual(member["evaluation"]["reason"], "province_observer_root_mismatch")
        self.assertNotIn("children", member)

    def test_geographic_quantifiers_combine_known_members_with_local_target_cap(self):
        scenarios = (
            # AND needs the unread second member unless an earlier member is false.
            (trigger.GEOGRAPHIC_ALL_TYPE, "FRA", None),
            (trigger.GEOGRAPHIC_ALL_TYPE, "ENG", False),
            # OR needs the unread second member unless an earlier member is true.
            (0x1234, "ENG", None),
            (0x1234, "FRA", True),
        )
        for native_type, owner, expected in scenarios:
            with self.subTest(native_type=native_type, owner=owner):
                owner_state = {"status": "known", "tag": owner,
                               "reference": _FRA_REF if owner == "FRA" else _other_reference()}
                with patch.object(trigger, "MAX_PROVINCE_TARGETS", 1):
                    result, _reader, _defs, calls, _ctx = _capture_geographic(
                        province_ids=[42, 43], native_type=native_type,
                        rows={42: {"status": "known", "owner": owner_state}},
                    )
                self.assertEqual(result["status"], "observed")
                tree = result["tasks"][0]["tree"]["children"][0]
                self.assertIs(tree["evaluation"]["satisfied"], expected)
                self.assertEqual(calls, [42])
                capped_member = tree["members"][1]["tree"]
                self.assertEqual(capped_member["kind"], "unsupported")
                self.assertEqual(capped_member["evaluation"]["reason"],
                                 "province_target_budget_exceeded")
                self.assertNotIn("children", capped_member)

    def test_literal_scope_target_cap_keeps_other_known_conditions(self):
        reader, module, country, loaded, guards, _definitions, pointers = _fixture()
        reader.qword_put(country + 0x20, _FRA_REF)
        scope_42, scope_43, reference_42, reference_43 = (
            0xA20000, 0xA21000, 0xA30000, 0xA31000,
        )
        owned, sailors = 0xA40000, 0xA41000
        _write_reference(reader, reference_42, province_id=42)
        _write_reference(reader, reference_43, province_id=43)
        _write_province_leaf(reader, module, owned, "owned")
        _write_scope(reader, module, scope_42, reference_42, [owned])
        _write_scope(reader, module, scope_43, reference_43, [0x12345])
        _write_leaf(reader, module, sailors, "sailors", trigger.SAILORS_TOKEN, 1000)
        reader.dword_put(country + trigger.SAILORS_CURRENT_OFFSET, 1, signed=True)
        reader.dword_put(country + trigger.SAILORS_MAX_OFFSET, 1, signed=True)
        _install_root(reader, module, pointers["task_a"], [scope_42, scope_43, sailors])
        calls: list[int] = []

        with patch.object(trigger, "MAX_PROVINCE_TARGETS", 1):
            result = trigger.capture_triggers(
                reader, module, country, loaded, code_guards=guards,
                province_reader=_province_reader(country, _FRA_REF, {}, calls),
            )

        self.assertEqual(result["status"], "observed")
        tree = result["tasks"][0]["tree"]
        self.assertIsNone(tree["evaluation"]["satisfied"])
        self.assertTrue(tree["children"][0]["evaluation"]["satisfied"])
        capped_scope = tree["children"][1]
        self.assertEqual(capped_scope["kind"], "unsupported")
        self.assertEqual(capped_scope["evaluation"]["reason"],
                         "province_target_budget_exceeded")
        self.assertNotIn("children", capped_scope)
        self.assertTrue(tree["children"][2]["evaluation"]["satisfied"])
        self.assertEqual(calls, [42])

    def test_province_state_cache_is_shared_across_geographic_sets(self):
        reader, module, country, loaded, guards, _definitions, pointers = _fixture()
        first, second, owned = 0xA20000, 0xA21000, 0xA30000
        _write_province_leaf(reader, module, owned, "owned")
        _write_geographic(reader, module, first, [owned], "area_one")
        _write_geographic(reader, module, second, [owned], "area_two")
        _install_root(reader, module, pointers["task_a"], [first, second])
        state_calls: list[int] = []
        definitions = {"area_one": _known_definition([42]),
                       "area_two": _known_definition([42])}
        result = trigger.capture_triggers(
            reader, module, country, loaded, code_guards=guards,
            province_reader=_province_reader(country, _FRA_REF, {}, state_calls),
            geographic_reader=_geographic_reader(definitions, []),
        )
        self.assertEqual(result["status"], "observed")
        self.assertEqual(state_calls, [42])

    def test_geographic_body_cycle_fails_the_outer_capture(self):
        # Rebuild this fixture so the inlined body's only child points back to
        # the geographic node itself, which is still active in the parent path.
        reader, module, country, loaded, guards, _definitions, pointers = _fixture()
        reader.qword_put(country + 0x20, _FRA_REF)
        geo = 0xA20000
        _write_geographic(reader, module, geo, [geo], "cycle_area")
        _install_root(reader, module, pointers["task_a"], [geo])
        result = trigger.capture_triggers(
            reader, module, country, loaded, code_guards=guards,
            province_reader=_province_reader(country, _FRA_REF, {}, []),
            geographic_reader=_geographic_reader(
                {"cycle_area": _known_definition([42])}, []
            ),
        )
        self.assertEqual(result["status"], "unknown")
        self.assertIn("tree_cycle", result["reason"])

    def test_country_scope_fra_foreign_context_nested_if_and_root_sibling(self):
        reader, module, country, loaded, guards, _definitions, pointers = _fixture()
        reader.qword_put(country + 0x20, _FRA_REF)
        fra_scope, eng_scope, if_pointer = 0xA20000, 0xA21000, 0xA22000
        fra_ref, eng_ref = 0xA30000, 0xA31000
        fra_sailors, foreign_sailors, root_sailors = 0xA40000, 0xA41000, 0xA42000
        _write_country_scope_reference(reader, fra_ref, "FRA")
        _write_country_scope_reference(reader, eng_ref, "ENG")
        _write_scope(reader, module, fra_scope, fra_ref, [fra_sailors], token=0xF1234567)
        _write_scope(reader, module, eng_scope, eng_ref, [if_pointer], token=0xABCDEF12)
        for leaf in (fra_sailors, foreign_sailors, root_sailors):
            _write_leaf(reader, module, leaf, "sailors", trigger.SAILORS_TOKEN, 1000)
        reader.dword_put(country + trigger.SAILORS_CURRENT_OFFSET, 1, signed=True)
        reader.dword_put(country + trigger.SAILORS_MAX_OFFSET, 1, signed=True)
        _write_if(reader, module, if_pointer, limit_children=[],
                  then_children=[foreign_sailors], else_children=[], token=0xF7654321)
        _install_root(reader, module, pointers["task_a"],
                      [fra_scope, eng_scope, root_sailors])
        bindings = {
            _FRA_COUNTRY_REF: {"status": "known", "tag": "FRA", "pointer": country,
                               "fullref": _FRA_COUNTRY_REF},
            _OTHER_REF: {"status": "known", "tag": "ENG", "pointer": _COUNTRY_POINTER,
                         "fullref": _OTHER_REF},
        }
        calls: list[int] = []

        result = trigger.capture_triggers(
            reader, module, country, loaded, code_guards=guards,
            country_scope_reader=_country_scope_reader(bindings, calls),
        )

        self.assertEqual(result["status"], "observed")
        tree = result["tasks"][0]["tree"]
        fra_node, eng_node, root_node = tree["children"]
        self.assertEqual(fra_node["token"], 0xF1234567)
        self.assertEqual(fra_node["scope"], {
            "kind": "country", "country": "FRA", "selection": "literal",
        })
        self.assertTrue(fra_node["evaluation"]["satisfied"])
        self.assertEqual(eng_node["token"], 0xABCDEF12)
        nested_if = eng_node["children"][0]
        self.assertEqual(nested_if["token"], 0xF7654321)
        self.assertIsNone(nested_if["then"]["children"][0]["evaluation"]["satisfied"])
        self.assertEqual(nested_if["then"]["children"][0]["evaluation"]["reason"],
                         "foreign_country_scalar_unsupported")
        self.assertIsNone(eng_node["evaluation"]["satisfied"])
        self.assertTrue(root_node["evaluation"]["satisfied"])
        self.assertEqual(calls, [_FRA_COUNTRY_REF, _OTHER_REF])
        foreign_sailors_address = _COUNTRY_POINTER + trigger.SAILORS_CURRENT_OFFSET
        self.assertFalse(any(int(row["address"], 0) == foreign_sailors_address
                             for row in result["_compare"]["rawreads"]))

    def test_foreign_modifier_is_unknown_without_reading_definition_or_reusing_state(self):
        reader, module, country, loaded, guards, _definitions, pointers = _fixture()
        foreign_scope, reference, modifier = 0xA20000, 0xA30000, 0xA40000
        _write_country_scope_reference(reader, reference, "ENG")
        _write_scope(reader, module, foreign_scope, reference, [modifier])
        vtable = _set_method(reader, module, "unsupported",
                             method_rva=trigger.COUNTRY_MODIFIER_EVALUATE_RVA,
                             vtable_rva=0x1D20400)
        reader.qword_put(modifier, vtable)
        reader.dword_put(modifier + trigger.NODE_TOKEN_OFFSET,
                         trigger.COUNTRY_MODIFIER_TOKEN)
        reader.qword_put(modifier + 0x68, 0)
        _install_root(reader, module, pointers["task_a"], [foreign_scope])
        state_calls: list[tuple[int, str]] = []
        bindings = {_OTHER_REF: {"status": "known", "tag": "ENG",
                                 "pointer": _COUNTRY_POINTER, "fullref": _OTHER_REF}}

        def country_state_reader(_reader, _base, target, kind):
            state_calls.append((target, kind))
            return {"status": "known", "definitions": []}

        result = trigger.capture_triggers(
            reader, module, country, loaded, code_guards=guards,
            country_scope_reader=_country_scope_reader(bindings, []),
            country_state_reader=country_state_reader,
        )

        self.assertEqual(result["status"], "observed")
        leaf = result["tasks"][0]["tree"]["children"][0]["children"][0]
        self.assertEqual(leaf["evaluation"]["reason"],
                         "foreign_country_modifier_unsupported")
        self.assertEqual(state_calls, [])
        self.assertFalse(any(row["label"].endswith("modifier_definition")
                             for row in result["_compare"]["rawreads"]))

    def test_country_scope_requires_exact_canonical_binding_and_is_opaque_on_failure(self):
        invalid_bindings = (
            {"status": "unknown", "reason": "not_found"},
            {"status": "known", "tag": "FRA", "pointer": 0x520000,
             "fullref": _FRA_REF},
            {"status": "known", "tag": "ENG", "pointer": _COUNTRY_POINTER,
             "fullref": _FRA_REF},
            {"status": "known", "tag": "ENG", "pointer": 0x510001,
             "fullref": _OTHER_REF},
        )
        for binding in invalid_bindings:
            with self.subTest(binding=binding):
                reader, module, country, loaded, guards, _definitions, pointers = _fixture()
                scope, reference = 0xA20000, 0xA30000
                fullref = _write_country_scope_reference(reader, reference, "ENG")
                _write_scope(reader, module, scope, reference, [0x12345], token=0xFEDCBA98)
                _install_root(reader, module, pointers["task_a"], [scope])
                result = trigger.capture_triggers(
                    reader, module, country, loaded, code_guards=guards,
                    country_scope_reader=_country_scope_reader({fullref: binding}, []),
                )
                self.assertEqual(result["status"], "observed")
                node = result["tasks"][0]["tree"]["children"][0]
                self.assertEqual(node["kind"], "unsupported")
                self.assertEqual(node["token"], 0xFEDCBA98)
                self.assertNotIn("children", node)

    def test_country_scope_without_callback_is_opaque(self):
        reader, module, country, loaded, guards, _definitions, pointers = _fixture()
        scope, reference = 0xA20000, 0xA30000
        _write_country_scope_reference(reader, reference, "ENG")
        _write_scope(reader, module, scope, reference, [0x12345])
        _install_root(reader, module, pointers["task_a"], [scope])
        result = trigger.capture_triggers(reader, module, country, loaded,
                                          code_guards=guards)
        node = result["tasks"][0]["tree"]["children"][0]
        self.assertEqual(result["status"], "observed")
        self.assertEqual(node["kind"], "unsupported")
        self.assertNotIn("children", node)

    def test_country_scope_context_reaches_numeric_province_scope_and_preserves_root(self):
        reader, module, country, loaded, guards, _definitions, pointers = _fixture()
        reader.qword_put(country + 0x20, _FRA_REF)
        country_scope, country_ref, province_scope, province_ref = (
            0xA20000, 0xA30000, 0xA40000, 0xA50000,
        )
        owned = 0xA60000
        _write_country_scope_reference(reader, country_ref, "ENG")
        _write_reference(reader, province_ref, province_id=42)
        _write_province_leaf(reader, module, owned, "owned")
        _write_scope(reader, module, province_scope, province_ref, [owned])
        _write_scope(reader, module, country_scope, country_ref, [province_scope])
        _install_root(reader, module, pointers["task_a"], [country_scope])
        province_calls: list[int] = []
        binding_calls: list[int] = []
        bindings = {_OTHER_REF: {"status": "known", "tag": "ENG",
                                 "pointer": _COUNTRY_POINTER, "fullref": _OTHER_REF}}

        result = trigger.capture_triggers(
            reader, module, country, loaded, code_guards=guards,
            country_scope_reader=_country_scope_reader(bindings, binding_calls),
            province_reader=_province_reader(country, _FRA_REF, {}, province_calls),
        )

        self.assertEqual(result["status"], "observed")
        province_node = result["tasks"][0]["tree"]["children"][0]["children"][0]
        self.assertEqual(province_node["scope"], {
            "kind": "province", "province_id": 42, "selection": "literal",
        })
        self.assertTrue(province_node["children"][0]["evaluation"]["satisfied"])
        self.assertEqual(province_calls, [42])
        self.assertEqual(binding_calls, [_OTHER_REF])


if __name__ == "__main__":
    unittest.main()


def test_opaque_geographic_members_share_actual_node_and_depth_budgets():
    options = dict(province_ids=[42, 43], native_type=trigger.GEOGRAPHIC_ALL_TYPE,
                   rows={42: {'status': 'unknown'}, 43: {'status': 'unknown'}}, children=[0x12345])
    result, *_ = _capture_geographic(**options)
    assert result['status'] == 'observed'
    assert result['total_nodes'] == 4  # root, geographic node, two opaque members
    with patch.object(trigger, 'MAX_TOTAL_NODES', 3):
        limited, *_ = _capture_geographic(**options)
    assert limited['status'] == 'unknown'
    with patch.object(trigger, 'MAX_TREE_DEPTH', 1):
        limited, *_ = _capture_geographic(**options)
    assert limited['status'] == 'unknown'
