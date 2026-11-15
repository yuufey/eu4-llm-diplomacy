"""Synthetic scope and province-predicate coverage for mission triggers."""
from __future__ import annotations

import unittest
from unittest.mock import patch

from bridge.information import mission_task_memory as tm
from bridge.information import mission_trigger_memory as trigger
from bridge.information.mission_trigger_source import normalize_triggers, project_progress
from bridge.tests.test_information_mission_trigger_memory import (
    _fixture,
    _set_method,
    _write_group,
)
from bridge.tests.test_information_mission_trigger_source import (
    _address as _source_address,
    _group as _source_group,
    _leaf as _source_leaf,
    _normalized_state as _source_normalized_state,
    _prerequisites as _source_prerequisites,
    _report as _source_report,
    _task as _source_task,
)


_PROVINCE_METHODS = {
    "scope": (trigger.PROVINCE_SCOPE_EVALUATE_RVA, 0x1D20000),
    "owned": (trigger.PROVINCE_OWNED_EVALUATE_RVA, 0x1D20100),
    "controlled": (trigger.PROVINCE_CONTROLLED_EVALUATE_RVA, 0x1D20200),
    "held": (trigger.PROVINCE_HELD_EVALUATE_RVA, 0x1D20300),
}


def _root_reference() -> int:
    return (122 << 32) | int.from_bytes(b"FRA", "little")


def _other_reference() -> int:
    return (321 << 32) | int.from_bytes(b"ENG", "little")


def _write_reference(reader, pointer: int, *, kind: int = trigger.PROVINCE_REFERENCE_KIND,
                     province_id: int = 42, country_flag: int = 0) -> None:
    raw = bytearray(0x218)
    raw[0:4] = int(kind).to_bytes(4, "little", signed=False)
    raw[trigger.PROVINCE_REFERENCE_ID_OFFSET:
        trigger.PROVINCE_REFERENCE_ID_OFFSET + 4] = int(province_id).to_bytes(
            4, "little", signed=True
        )
    raw[trigger.PROVINCE_REFERENCE_COUNTRY_FLAG_OFFSET] = country_flag
    reader.put(pointer, bytes(raw))


def _write_scope(reader, module: int, pointer: int, reference: int,
                 children: list[int], *, token: int = 0x2A01) -> None:
    method_rva, vtable_rva = _PROVINCE_METHODS["scope"]
    vtable = _set_method(reader, module, "unsupported", method_rva=method_rva,
                         vtable_rva=vtable_rva)
    reader.qword_put(pointer, vtable)
    reader.qword_put(pointer + trigger.GROUP_DATA_OFFSET,
                      pointer + trigger.GROUP_INLINE_OFFSET)
    reader.dword_put(pointer + trigger.GROUP_CAPACITY_OFFSET,
                     trigger.INLINE_GROUP_CAPACITY, signed=True)
    reader.dword_put(pointer + trigger.GROUP_COUNT_OFFSET, len(children), signed=True)
    reader.dword_put(pointer + trigger.NODE_TOKEN_OFFSET, token)
    reader.qword_put(pointer + trigger.PROVINCE_SCOPE_REFERENCE_OFFSET, reference)
    for index, child in enumerate(children):
        reader.qword_put(pointer + trigger.GROUP_INLINE_OFFSET + index * 8, child)


def _write_province_leaf(reader, module: int, pointer: int, kind: str, *,
                         token: int | None = None,
                         selector: int = trigger.ROOT_COUNTRY_FLAGS,
                         literal_flag: int = 0) -> None:
    method_rva, vtable_rva = _PROVINCE_METHODS[kind]
    vtable = _set_method(reader, module, "unsupported", method_rva=method_rva,
                         vtable_rva=vtable_rva)
    expected_token = {
        "owned": 0x29F9,
        "controlled": 0x2B6B,
        "held": 0x3643,
    }[kind]
    reader.qword_put(pointer, vtable)
    reader.put(pointer + trigger.NODE_LITERAL_FLAGS_OFFSET, bytes([literal_flag]))
    reader.dword_put(pointer + trigger.NODE_TOKEN_OFFSET,
                     expected_token if token is None else token)
    reader.dword_put(pointer + trigger.NODE_DYNAMIC_FLAGS_OFFSET, selector)
    reader.dword_put(pointer + trigger.NODE_THRESHOLD_OFFSET, 0, signed=True)


def _province_reader(country: int, root_reference: int, rows: dict[int, dict], calls: list):
    def read_province_state(_read, _module_base: int, province_id: int):
        calls.append(province_id)
        row = rows.get(province_id, {})
        return {
            "status": row.get("status", "known"),
            "province_id": province_id,
            "observer_pointer": row.get("observer_pointer", country),
            "observer_reference": row.get("observer_reference", root_reference),
            "owner": row.get("owner", {
                "status": "known", "tag": "FRA", "reference": root_reference,
            }),
            "controller": row.get("controller", {
                "status": "known", "tag": "FRA", "reference": root_reference,
            }),
            "source": "synthetic-province-state-reader",
        }

    return read_province_state


def _write_subject_relation(reader, owner_pointer: int, *, root_slot: int = 122,
                            relation_key: int = 7, holds: bool = True) -> None:
    # Synthetic bounded projection consumed by mission_trigger_memory._subject_holds.
    parent_reference = (0x2A << 56) | (root_slot << 32) | 0x1234
    table, relation, records, holder, subject_type = (
        0xA60000, 0xA70000, 0xA80000, 0xA90000, 0xAA0000,
    )
    reader.qword_put(owner_pointer + 0x18F0, parent_reference)
    reader.qword_put(owner_pointer + 0x1510, table)
    pair = table + root_slot * 72
    reader.qword_put(pair, relation)
    reader.qword_put(pair + 0x10, relation_key << 32)
    reader.qword_put(relation + 0x128, records)
    reader.dword_put(relation + 0x134, 1, signed=True)
    record = bytearray(16)
    record[:4] = relation_key.to_bytes(4, "little", signed=True)
    record[8:16] = holder.to_bytes(8, "little")
    reader.put(records, bytes(record))
    reader.qword_put(holder + 0x40, subject_type)
    reader.put(subject_type + 0x151, bytes([1 if holds else 0]))
    reader.put(subject_type + 0x152, b"\0")


def _source_scope(children: list[dict], *, province_id: object = 42,
                  method: object = trigger.PROVINCE_SCOPE_EVALUATE_RVA,
                  scope_extra: dict | None = None,
                  evaluation: dict | None = None) -> dict:
    values = [child["evaluation"]["satisfied"] for child in children]
    satisfied = False if False in values else True if all(value is True for value in values) else None
    scope = {"kind": "province", "province_id": province_id, "selection": "literal"}
    if scope_extra:
        scope.update(scope_extra)
    return {
        "kind": "scope",
        "token": 0x2A01,
        "method_rva": method,
        "native_pointer": _source_address(),
        "scope": scope,
        "children": children,
        "evaluation": evaluation or {
            "status": "unknown" if satisfied is None else "known",
            "satisfied": satisfied,
        },
    }


def _mapping_keys(value) -> set[str]:
    if isinstance(value, dict):
        return set(value) | set().union(*(_mapping_keys(child) for child in value.values()))
    if isinstance(value, list):
        return set().union(*(_mapping_keys(child) for child in value)) if value else set()
    return set()


class MissionProvinceTriggerTests(unittest.TestCase):
    def test_literal_scope_uses_root_and_caches_each_province_through_nested_logic(self):
        reader, module, country, loaded, guards, _definitions, pointers = _fixture()
        root_reference = _root_reference()
        reader.qword_put(country + 0x20, root_reference)

        scope_42, scope_43, scope_42_again = 0xA20000, 0xA21000, 0xA22000
        nested_and, nested_or = 0xA23000, 0xA24000
        owned, controlled, held, other_owner = 0xA30000, 0xA31000, 0xA32000, 0xA33000
        _write_province_leaf(reader, module, owned, "owned")
        _write_province_leaf(reader, module, controlled, "controlled")
        _write_province_leaf(reader, module, held, "held")
        _write_province_leaf(reader, module, other_owner, "owned")
        _write_group(reader, module, nested_or, [owned, controlled, held], "or", token=0x296C)
        _write_group(reader, module, nested_and, [nested_or], "nested_and", token=0x2F4D)
        # Nested logic constructors do not use the root parser contract.
        reader.qword_put(nested_or + trigger.GROUP_PARSER_OFFSET, 0xA10000)
        reader.qword_put(nested_and + trigger.GROUP_PARSER_OFFSET, 0xA10000)

        reference_42, reference_43, reference_42_again = 0xA40000, 0xA41000, 0xA42000
        _write_reference(reader, reference_42, province_id=42)
        _write_reference(reader, reference_43, province_id=43)
        _write_reference(reader, reference_42_again, province_id=42)
        _write_scope(reader, module, scope_42, reference_42, [nested_and])
        _write_scope(reader, module, scope_43, reference_43, [other_owner])
        _write_scope(reader, module, scope_42_again, reference_42_again, [owned])
        _write_group(reader, module, pointers["task_a"] + trigger.TASK_TRIGGER_OFFSET,
                     [scope_42, scope_43, scope_42_again], "and")

        other = _other_reference()
        calls: list[int] = []
        province_reader = _province_reader(country, root_reference, {
            42: {
                "owner": {"status": "known", "tag": "FRA", "reference": root_reference},
                "controller": {"status": "known", "tag": "ENG", "reference": other},
            },
            43: {
                "owner": {"status": "known", "tag": "ENG", "reference": other},
                "controller": {"status": "known", "tag": "ENG", "reference": other},
            },
        }, calls)

        result = trigger.capture_triggers(
            reader, module, country, loaded, code_guards=guards,
            province_reader=province_reader,
        )

        self.assertEqual(result["status"], "observed")
        self.assertTrue(result["complete"])
        self.assertEqual(calls, [42, 43])
        tree = result["tasks"][0]["tree"]
        self.assertEqual(tree["children"][0]["kind"], "scope")
        self.assertEqual(tree["children"][0]["scope"], {
            "kind": "province", "province_id": 42, "selection": "literal",
        })
        self.assertTrue(tree["children"][0]["evaluation"]["satisfied"])
        nested_leaves = tree["children"][0]["children"][0]["children"][0]["children"]
        self.assertEqual([leaf["condition_name"] for leaf in nested_leaves],
                         ["owned_by", "controlled_by", "country_or_non_sovereign_subject_holds"])
        self.assertEqual([leaf["evaluation"]["satisfied"] for leaf in nested_leaves],
                         [True, False, True])
        self.assertTrue(all(leaf["metric"]["comparison_country"] == "ROOT"
                            and leaf["metric"]["province_id"] == 42
                            for leaf in nested_leaves))
        self.assertFalse(tree["children"][1]["children"][0]["evaluation"]["satisfied"])
        self.assertEqual(tree["children"][1]["children"][0]["metric"]["province_id"], 43)
        self.assertTrue(tree["children"][2]["children"][0]["evaluation"]["satisfied"])
        self.assertFalse(tree["evaluation"]["satisfied"])

    def test_normalizer_accepts_scope_under_root_and_and_results_match_children(self):
        owned = _source_leaf(
            True, token=0x29F9, method=trigger.PROVINCE_OWNED_EVALUATE_RVA,
            metric={"province_id": 42, "comparison_country": "ROOT"},
            extra={"condition_name": "owned_by"},
        )
        controlled = _source_leaf(
            False, token=0x2B6B, method=trigger.PROVINCE_CONTROLLED_EVALUATE_RVA,
            metric={"province_id": 42, "comparison_country": "ROOT"},
            extra={"condition_name": "controlled_by"},
        )
        scope = _source_scope([owned, controlled])
        root = _source_group("and", [scope, _source_leaf(True)])

        normalized = normalize_triggers(
            _source_report([_source_task(tree=root)]),
            _source_prerequisites("task_a"),
        )

        self.assertEqual(normalized["status"], "known")
        tree = normalized["tasks"][0]["tree"]
        self.assertEqual(tree["kind"], "and")
        self.assertEqual(tree["evaluation"], {"status": "known", "satisfied": False})
        normalized_scope = tree["children"][0]
        self.assertEqual(normalized_scope["scope"], {
            "kind": "province", "province_id": 42, "selection": "literal",
        })
        self.assertEqual(normalized_scope["evaluation"], {
            "status": "known", "satisfied": False,
        })

    def test_normalizer_rejects_malformed_scope_ids_boolean_ids_and_methods(self):
        leaf = _source_leaf(
            True, token=0x29F9, method=trigger.PROVINCE_OWNED_EVALUATE_RVA,
            metric={"province_id": 42, "comparison_country": "ROOT"},
        )
        invalid_scopes = (
            _source_scope([leaf], province_id=0),
            _source_scope([leaf], province_id=65536),
            _source_scope([leaf], province_id=True),
            _source_scope([leaf], method=trigger.AND_EVALUATE_RVA),
            _source_scope([leaf], method=True),
        )
        for scope in invalid_scopes:
            with self.subTest(scope=scope["scope"], method=scope["method_rva"]):
                result = normalize_triggers(
                    _source_report([_source_task(tree=_source_group("and", [scope]))]),
                    _source_prerequisites("task_a"),
                )
                self.assertEqual(result["status"], "unknown")
                self.assertEqual(result["reason"], "MISSION_TRIGGER_TREE_INVALID")

    def test_normalizer_rejects_forged_scope_result_that_disagrees_with_children(self):
        scope = _source_scope(
            [_source_leaf(True)],
            evaluation={"status": "known", "satisfied": False},
        )
        root = _source_group("and", [scope])

        result = normalize_triggers(
            _source_report([_source_task(tree=root)]),
            _source_prerequisites("task_a"),
        )

        self.assertEqual(result["status"], "unknown")
        self.assertEqual(result["reason"], "MISSION_TRIGGER_TREE_INVALID")

    def test_projection_preserves_province_root_metric_and_strips_native_details(self):
        metric = {
            "province_id": 42,
            "comparison_country": "ROOT",
            "source": "synthetic",
            "native_pointer": _source_address(),
            "method": "raw-method-name",
            "method_rva": trigger.PROVINCE_OWNED_EVALUATE_RVA,
            "_compare": {"rawreads": [{"address": "0xA00000"}]},
        }
        leaf = _source_leaf(
            True, token=0x29F9, method=trigger.PROVINCE_OWNED_EVALUATE_RVA,
            metric=metric, extra={"condition_name": "owned_by"},
        )
        scope = _source_scope([leaf], scope_extra={
            "native_pointer": _source_address(),
            "method": "raw-scope-method",
            "method_rva": trigger.PROVINCE_SCOPE_EVALUATE_RVA,
            "_compare": {"reference_raw_hex": "deadbeef"},
        })
        root = _source_group("and", [scope])
        root["_compare"] = {"rawreads": [{"address": "0xA00000"}]}
        state = _source_normalized_state([_source_task(tree=root)])
        state["mission_triggers"]["_compare"] = {"secret": "native"}

        result = project_progress(
            state, [{"root_id": "loaded", "task_id": "task_a"}], "1.37.4",
        )

        self.assertEqual(result["status"], "known")
        public_scope = result["value"]["tasks"][0]["trigger"]["children"][0]
        self.assertEqual(public_scope["scope"]["province_id"], 42)
        public_leaf = public_scope["children"][0]
        self.assertEqual(public_leaf["condition_name"], "owned_by")
        self.assertEqual(public_leaf["metric"]["province_id"], 42)
        self.assertEqual(public_leaf["metric"]["comparison_country"], "ROOT")
        self.assertEqual(public_leaf["metric"]["source"], "synthetic")
        self.assertTrue({"native_pointer", "method", "method_rva", "_compare"}.isdisjoint(
            _mapping_keys(result)
        ))

    def test_projection_keeps_selected_entry_order_and_does_not_return_partial_unmatched_rows(self):
        rows = [
            _source_task("first", _source_group("and", [_source_leaf(True)])),
            _source_task("second", _source_group("and", [_source_leaf(False)])),
        ]
        state = _source_normalized_state(rows)

        ordered = project_progress(state, [
            {"root_id": "loaded", "task_id": "second"},
            {"root_id": "loaded", "task_id": "first"},
        ], "1.37.4")
        with_unmatched = project_progress(state, [
            {"root_id": "loaded", "task_id": "second"},
            {"root_id": "loaded", "task_id": "missing",
             "declared_trigger": _source_group("and", [_source_leaf(True)])},
        ], "1.37.4")

        self.assertEqual(ordered["status"], "known")
        self.assertEqual([row["task_id"] for row in ordered["value"]["tasks"]],
                         ["second", "first"])
        self.assertEqual(with_unmatched["status"], "unknown")
        self.assertEqual(with_unmatched["reason"], "MISSION_TRIGGER_TASKS_INCOMPLETE")
        self.assertNotIn("value", with_unmatched)

    def test_nested_country_scalar_is_unknown_but_context_does_not_leak_to_sibling(self):
        reader, module, country, loaded, guards, _definitions, pointers = _fixture()
        root_reference = _root_reference()
        reader.qword_put(country + 0x20, root_reference)
        scope, nested, owned, sailors = 0xA20000, 0xA21000, 0xA30000, 0xA31000
        reference = 0xA40000
        _write_reference(reader, reference, province_id=7)
        _write_province_leaf(reader, module, owned, "owned")
        _write_scope(reader, module, scope, reference, [nested])
        _write_group(reader, module, nested, [owned, sailors], "nested_and", token=0x2F4D)
        reader.qword_put(nested + trigger.GROUP_PARSER_OFFSET, 0xA10000)
        # A country-scope scalar nested inside province scope must remain unknown.
        reader.qword_put(sailors, _set_method(reader, module, "sailors"))
        reader.put(sailors + trigger.NODE_LITERAL_FLAGS_OFFSET, b"\0")
        reader.dword_put(sailors + trigger.NODE_TOKEN_OFFSET, trigger.SAILORS_TOKEN)
        reader.dword_put(sailors + trigger.NODE_DYNAMIC_FLAGS_OFFSET, 0)
        reader.dword_put(sailors + trigger.NODE_THRESHOLD_OFFSET, 1000, signed=True)
        outside_sailors = 0xA32000
        reader.qword_put(outside_sailors, _set_method(reader, module, "sailors"))
        reader.put(outside_sailors + trigger.NODE_LITERAL_FLAGS_OFFSET, b"\0")
        reader.dword_put(outside_sailors + trigger.NODE_TOKEN_OFFSET, trigger.SAILORS_TOKEN)
        reader.dword_put(outside_sailors + trigger.NODE_DYNAMIC_FLAGS_OFFSET, 0)
        reader.dword_put(outside_sailors + trigger.NODE_THRESHOLD_OFFSET, 1000, signed=True)
        reader.dword_put(country + trigger.SAILORS_CURRENT_OFFSET, 1, signed=True)
        reader.dword_put(country + trigger.SAILORS_MAX_OFFSET, 1, signed=True)
        _write_group(reader, module, pointers["task_a"] + trigger.TASK_TRIGGER_OFFSET,
                     [scope, outside_sailors], "and")
        calls: list[int] = []

        result = trigger.capture_triggers(
            reader, module, country, loaded, code_guards=guards,
            province_reader=_province_reader(country, root_reference, {}, calls),
        )

        self.assertEqual(result["status"], "observed")
        tree = result["tasks"][0]["tree"]
        scoped_group = tree["children"][0]["children"][0]
        self.assertTrue(scoped_group["children"][0]["evaluation"]["satisfied"])
        self.assertEqual(scoped_group["children"][0]["metric"]["province_id"], 7)
        self.assertEqual(scoped_group["children"][1]["evaluation"]["reason"],
                         "country_scalar_in_province_scope_unsupported")
        self.assertIsNone(scoped_group["children"][1]["evaluation"]["satisfied"])
        self.assertTrue(tree["children"][1]["evaluation"]["satisfied"])
        self.assertEqual(tree["children"][1]["metric"]["derived_ratio_milli"], 1000)
        self.assertEqual(calls, [7])
        country_scalar_reads = [row for row in result["_compare"]["rawreads"]
                                if row["label"].endswith("sailors_current")]
        self.assertEqual(len(country_scalar_reads), 1)

    def test_nonliteral_or_country_scopes_are_opaque_and_do_not_follow_children(self):
        reader, module, country, loaded, guards, _definitions, pointers = _fixture()
        # These child pointers are deliberately invalid: unsupported scopes must
        # return an opaque node before attempting to read their child vectors.
        scope_country, scope_flag, scope_bad_id = 0xA20000, 0xA21000, 0xA22000
        ref_country, ref_flag, ref_bad_id = 0xA30000, 0xA31000, 0xA32000
        _write_reference(reader, ref_country, kind=0xF, province_id=0x2A01)
        _write_reference(reader, ref_flag, province_id=9, country_flag=0xF)
        _write_reference(reader, ref_bad_id, province_id=0)
        _write_scope(reader, module, scope_country, ref_country, [0x12345])
        _write_scope(reader, module, scope_flag, ref_flag, [0x12345])
        _write_scope(reader, module, scope_bad_id, ref_bad_id, [0x12345])
        _write_group(reader, module, pointers["task_a"] + trigger.TASK_TRIGGER_OFFSET,
                     [scope_country, scope_flag, scope_bad_id], "and")
        calls: list[int] = []

        result = trigger.capture_triggers(
            reader, module, country, loaded, code_guards=guards,
            province_reader=_province_reader(country, _root_reference(), {}, calls),
        )

        self.assertEqual(result["status"], "observed")
        self.assertEqual(calls, [])
        children = result["tasks"][0]["tree"]["children"]
        self.assertEqual([node["evaluation"]["reason"] for node in children], [
            "dynamic_or_country_scope_unsupported",
            "dynamic_or_country_scope_unsupported",
            "literal_province_id_invalid",
        ])
        self.assertTrue(all(node["kind"] == "unsupported" and "children" not in node
                            for node in children))
        self.assertIsNone(result["tasks"][0]["tree"]["evaluation"]["satisfied"])

    def test_unadmitted_or_wrong_root_province_state_stays_opaque(self):
        for row, expected_reason in (
            ({"status": "unknown"}, "province_state_not_admitted"),
            ({"observer_pointer": 0x510000}, "province_observer_root_mismatch"),
            ({"observer_reference": _other_reference()}, "province_observer_root_mismatch"),
        ):
            with self.subTest(row=row):
                reader, module, country, loaded, guards, _definitions, pointers = _fixture()
                root_reference = _root_reference()
                reader.qword_put(country + 0x20, root_reference)
                scope, reference, child = 0xA20000, 0xA30000, 0xA40000
                _write_reference(reader, reference, province_id=8)
                _write_province_leaf(reader, module, child, "owned")
                _write_scope(reader, module, scope, reference, [child])
                _write_group(reader, module, pointers["task_a"] + trigger.TASK_TRIGGER_OFFSET,
                             [scope], "and")
                calls: list[int] = []
                result = trigger.capture_triggers(
                    reader, module, country, loaded, code_guards=guards,
                    province_reader=_province_reader(country, root_reference, {8: row}, calls),
                )
                self.assertEqual(result["status"], "observed")
                self.assertEqual(calls, [8])
                scope_node = result["tasks"][0]["tree"]["children"][0]
                self.assertEqual(scope_node["evaluation"]["reason"], expected_reason)
                self.assertNotIn("children", scope_node)

    def test_province_predicates_require_literal_root_selector_and_matching_token(self):
        reader, module, country, loaded, guards, _definitions, pointers = _fixture()
        root_reference = _root_reference()
        reader.qword_put(country + 0x20, root_reference)
        scope, reference = 0xA20000, 0xA30000
        _write_reference(reader, reference, province_id=11)
        wrong_selector, wrong_token = 0xA40000, 0xA41000
        _write_province_leaf(reader, module, wrong_selector, "owned", selector=0x2A01)
        _write_province_leaf(reader, module, wrong_token, "controlled", token=0x2A01)
        _write_scope(reader, module, scope, reference, [wrong_selector, wrong_token])
        _write_group(reader, module, pointers["task_a"] + trigger.TASK_TRIGGER_OFFSET,
                     [scope], "and")
        calls: list[int] = []

        result = trigger.capture_triggers(
            reader, module, country, loaded, code_guards=guards,
            province_reader=_province_reader(country, root_reference, {}, calls),
        )

        self.assertEqual(result["status"], "observed")
        self.assertEqual(calls, [11])
        leaves = result["tasks"][0]["tree"]["children"][0]["children"]
        self.assertEqual(leaves[0]["evaluation"]["reason"],
                         "comparison_country_selector_unsupported")
        self.assertIsNone(leaves[0]["evaluation"]["satisfied"])
        self.assertEqual(leaves[1]["kind"], "unsupported")
        self.assertEqual(leaves[1]["evaluation"]["reason"],
                         "province_method_token_mismatch")
        self.assertNotIn("children", leaves[1])

    def test_holds_accepts_subject_relation_and_keeps_unverified_owner_unknown(self):
        reader, module, country, loaded, guards, _definitions, pointers = _fixture()
        root_reference = _root_reference()
        other_reference = _other_reference()
        reader.qword_put(country + 0x20, root_reference)
        subject_owner, unrelated_owner = 0xA50000, 0xA51000
        _write_subject_relation(reader, subject_owner)
        _write_subject_relation(reader, unrelated_owner, root_slot=123)

        scope_subject, scope_unrelated, scope_unverified = 0xA20000, 0xA21000, 0xA22000
        ref_subject, ref_unrelated, ref_unverified = 0xA30000, 0xA31000, 0xA32000
        held_subject, held_unrelated, held_unverified = 0xA40000, 0xA41000, 0xA42000
        for reference, province_id in ((ref_subject, 15), (ref_unrelated, 16),
                                       (ref_unverified, 17)):
            _write_reference(reader, reference, province_id=province_id)
        for leaf in (held_subject, held_unrelated, held_unverified):
            _write_province_leaf(reader, module, leaf, "held")
        _write_scope(reader, module, scope_subject, ref_subject, [held_subject])
        _write_scope(reader, module, scope_unrelated, ref_unrelated, [held_unrelated])
        _write_scope(reader, module, scope_unverified, ref_unverified, [held_unverified])
        _write_group(reader, module, pointers["task_a"] + trigger.TASK_TRIGGER_OFFSET,
                     [scope_subject, scope_unrelated, scope_unverified], "and")
        calls: list[int] = []
        province_reader = _province_reader(country, root_reference, {
            15: {"owner": {"status": "known", "tag": "ENG", "reference": other_reference,
                           "country_pointer": subject_owner}},
            16: {"owner": {"status": "known", "tag": "ENG", "reference": other_reference,
                           "country_pointer": unrelated_owner}},
            17: {"owner": {"status": "known", "tag": "ENG", "reference": other_reference}},
        }, calls)

        result = trigger.capture_triggers(
            reader, module, country, loaded, code_guards=guards,
            province_reader=province_reader,
        )

        self.assertEqual(result["status"], "observed")
        self.assertEqual(calls, [15, 16, 17])
        held_values = [scope["children"][0]["evaluation"]["satisfied"]
                       for scope in result["tasks"][0]["tree"]["children"]]
        self.assertEqual(held_values, [True, False, None])

    def test_bad_scope_reference_pointer_and_out_of_bounds_object_retract_capture(self):
        for reference in (0x12345, tm.MAX_USER_ADDRESS - 0x100):
            with self.subTest(reference=hex(reference)):
                reader, module, country, loaded, guards, _definitions, pointers = _fixture()
                scope = 0xA20000
                _write_scope(reader, module, scope, reference, [])
                _write_group(reader, module, pointers["task_a"] + trigger.TASK_TRIGGER_OFFSET,
                             [scope], "and")
                calls: list[int] = []
                result = trigger.capture_triggers(
                    reader, module, country, loaded, code_guards=guards,
                    province_reader=_province_reader(country, _root_reference(), {}, calls),
                )
                self.assertEqual(result["status"], "unknown")
                self.assertFalse(result["complete"])
                self.assertEqual(result["tasks"], [])
                self.assertIsNone(result["_compare"])
                self.assertEqual(calls, [])

    def test_scope_cycles_and_node_budget_overflow_retract_whole_capture(self):
        reader, module, country, loaded, guards, _definitions, pointers = _fixture()
        root_reference = _root_reference()
        reader.qword_put(country + 0x20, root_reference)
        root = pointers["task_a"] + trigger.TASK_TRIGGER_OFFSET
        scope, reference = 0xA20000, 0xA30000
        _write_reference(reader, reference, province_id=12)
        _write_scope(reader, module, scope, reference, [scope])
        _write_group(reader, module, root, [scope], "and")
        cycle = trigger.capture_triggers(
            reader, module, country, loaded, code_guards=guards,
            province_reader=_province_reader(country, root_reference, {}, []),
        )
        self.assertEqual(cycle["status"], "unknown")
        self.assertEqual(cycle["tasks"], [])

        reader, module, country, loaded, guards, _definitions, pointers = _fixture()
        root_reference = _root_reference()
        reader.qword_put(country + 0x20, root_reference)
        root = pointers["task_a"] + trigger.TASK_TRIGGER_OFFSET
        scope, reference, leaf = 0xA20000, 0xA30000, 0xA40000
        _write_reference(reader, reference, province_id=12)
        _write_province_leaf(reader, module, leaf, "owned")
        _write_scope(reader, module, scope, reference, [leaf])
        _write_group(reader, module, root, [scope], "and")
        with patch.object(trigger, "MAX_TOTAL_NODES", 2):
            over_budget = trigger.capture_triggers(
                reader, module, country, loaded, code_guards=guards,
                province_reader=_province_reader(country, root_reference, {}, []),
            )
        self.assertEqual(over_budget["status"], "unknown")
        self.assertFalse(over_budget["complete"])
        self.assertEqual(over_budget["tasks"], [])

        reader, module, country, loaded, guards, _definitions, pointers = _fixture()
        root_reference = _root_reference()
        reader.qword_put(country + 0x20, root_reference)
        root = pointers["task_a"] + trigger.TASK_TRIGGER_OFFSET
        scope, reference, nested, leaf = 0xA20000, 0xA30000, 0xA40000, 0xA50000
        _write_reference(reader, reference, province_id=12)
        _write_province_leaf(reader, module, leaf, "owned")
        _write_group(reader, module, nested, [leaf], "nested_and", token=0x2F4D)
        reader.qword_put(nested + trigger.GROUP_PARSER_OFFSET, 0xA10000)
        _write_scope(reader, module, scope, reference, [nested])
        _write_group(reader, module, root, [scope], "and")
        with patch.object(trigger, "MAX_TREE_DEPTH", 2):
            too_deep = trigger.capture_triggers(
                reader, module, country, loaded, code_guards=guards,
                province_reader=_province_reader(country, root_reference, {}, []),
            )
        self.assertEqual(too_deep["status"], "unknown")
        self.assertEqual(too_deep["tasks"], [])

        reader, module, country, loaded, guards, _definitions, pointers = _fixture()
        root_reference = _root_reference()
        reader.qword_put(country + 0x20, root_reference)
        root = pointers["task_a"] + trigger.TASK_TRIGGER_OFFSET
        province_scopes: list[int] = []
        calls: list[int] = []
        for index, province_id in enumerate((12, 13)):
            scope = 0xA20000 + index * 0x1000
            reference = 0xA30000 + index * 0x1000
            _write_reference(reader, reference, province_id=province_id)
            _write_scope(reader, module, scope, reference, [])
            province_scopes.append(scope)
        _write_group(reader, module, root, province_scopes, "and")
        with patch.object(trigger, "MAX_PROVINCE_TARGETS", 1):
            over_targets = trigger.capture_triggers(
                reader, module, country, loaded, code_guards=guards,
                province_reader=_province_reader(country, root_reference, {}, calls),
            )
        self.assertEqual(over_targets["status"], "observed")
        second = over_targets['tasks'][0]['tree']['children'][1]
        self.assertEqual(second['evaluation']['status'], 'unknown')
        self.assertEqual(second['evaluation']['reason'], 'province_target_budget_exceeded')
        self.assertEqual(calls, [12])
        self.assertTrue(over_targets["complete"])
        self.assertEqual(len(over_targets["tasks"]), 1)


if __name__ == "__main__":
    unittest.main()
