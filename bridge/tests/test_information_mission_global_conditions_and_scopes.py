"""Focused DLC and dynamic-scope coverage for loaded mission conditions."""
from __future__ import annotations

import json

from bridge.information import mission_trigger_memory as trigger
from bridge.information.mission_trigger_source import normalize_triggers, project_progress
from bridge.tests.test_information_mission_geographic_triggers import (
    _country_scope_reader,
    _write_country_scope_reference,
)
from bridge.tests.test_information_mission_province_triggers import (
    _province_reader,
    _root_reference,
    _write_reference,
    _write_scope,
)
from bridge.tests.test_information_mission_trigger_memory import (
    _fixture,
    _install_root,
    _set_method,
    _write_leaf,
)
from bridge.tests.test_information_mission_trigger_source import _report


DLC_EVALUATE_RVA = 0xCC5FB0
DLC_TOKEN = 0x2E20
DOMINATION_MASK = 0x80000
DLC_VTABLE_RVA = 0x1D22000
CAPITAL_REFERENCE_KIND = 0x2A01
EMPEROR_REFERENCE_KIND = 0x2939
ENG_COUNTRY_POINTER = 0x510000
ROOT_REFERENCE = _root_reference()
ENG_REFERENCE = ((0x2A << 56) | (321 << 32)
                 | int.from_bytes(b"ENG", "little"))


def _write_dlc(reader, module, pointer, *, mask=DOMINATION_MASK, token=DLC_TOKEN):
    vtable = _set_method(
        reader, module, "unsupported", method_rva=DLC_EVALUATE_RVA,
        vtable_rva=DLC_VTABLE_RVA,
    )
    reader.qword_put(pointer, vtable)
    reader.dword_put(pointer + trigger.NODE_TOKEN_OFFSET, token)
    reader.dword_put(pointer + trigger.NODE_THRESHOLD_OFFSET, mask)


def _write_dynamic_scope_reference(reader, pointer, kind, *, province_id=42):
    raw = bytearray(0x218)
    raw[0:4] = int(kind).to_bytes(4, "little")
    raw[trigger.PROVINCE_REFERENCE_ID_OFFSET:
        trigger.PROVINCE_REFERENCE_ID_OFFSET + 4] = int(province_id).to_bytes(
            4, "little", signed=True,
        )
    reader.put(pointer, bytes(raw))


def _binding(fullref, tag, pointer):
    return {"status": "known", "tag": tag, "pointer": pointer,
            "fullref": fullref}


def _capture(prepare, *, province_rows=None, dlc_reader=None,
             dynamic_scope_reader=None, country_scope_reader=None):
    reader, module, country, loaded, guards, _definitions, pointers = _fixture()
    reader.qword_put(country + 0x20, ROOT_REFERENCE)
    province_calls = []
    province_reader = _province_reader(
        country, ROOT_REFERENCE, province_rows or {}, province_calls,
    )
    children = prepare(reader, module, country, pointers)
    _install_root(reader, module, pointers["task_a"], children)
    result = trigger.capture_triggers(
        reader, module, country, loaded, code_guards=guards,
        province_reader=province_reader,
        dlc_reader=dlc_reader,
        dynamic_scope_reader=dynamic_scope_reader,
        country_scope_reader=country_scope_reader,
    )
    return result, reader, module, country, loaded, guards, pointers, province_calls


def _empty_body_scope(reader, module, scope, reference, reference_kind,
                      *, province_id=42):
    _write_dynamic_scope_reference(
        reader, reference, reference_kind, province_id=province_id,
    )
    _write_scope(reader, module, scope, reference, [])


def test_domination_dlc_is_cached_across_root_province_and_foreign_contexts():
    calls = []

    def dlc_reader(_reader, _module_base, mask):
        calls.append(mask)
        if mask == DOMINATION_MASK:
            return {"status": "known", "satisfied": True,
                    "dlc": "Domination", "source": "synthetic-dlc-reader"}
        return {"status": "unknown", "reason": "fixture_mask_unknown"}

    country_ref = 0xA21000
    country_calls = []
    country_binding = _country_scope_reader(
        {ENG_REFERENCE: _binding(ENG_REFERENCE, "ENG", ENG_COUNTRY_POINTER)},
        country_calls,
    )

    def prepare(reader, module, _country, _pointers):
        root_dlc, province_scope, province_ref, province_dlc = (
            0xA30000, 0xA20000, 0xA22000, 0xA31000,
        )
        foreign_scope, foreign_dlc = 0xA23000, 0xA32000
        _write_dlc(reader, module, root_dlc)
        _write_reference(reader, province_ref, province_id=42)
        _write_dlc(reader, module, province_dlc)
        _write_scope(reader, module, province_scope, province_ref, [province_dlc])
        _write_country_scope_reference(reader, country_ref, "ENG")
        _write_dlc(reader, module, foreign_dlc)
        _write_scope(reader, module, foreign_scope, country_ref, [foreign_dlc])
        return [root_dlc, province_scope, foreign_scope]

    result, *_rest = _capture(
        prepare, dlc_reader=dlc_reader, country_scope_reader=country_binding,
    )

    tree = result["tasks"][0]["tree"]
    assert result["status"] == "observed"
    assert tree["evaluation"]["satisfied"] is True
    assert tree["children"][0]["evaluation"]["satisfied"] is True
    assert tree["children"][1]["scope"]["kind"] == "province"
    assert tree["children"][1]["children"][0]["evaluation"]["satisfied"] is True
    assert tree["children"][2]["scope"] == {
        "kind": "country", "country": "ENG", "selection": "literal",
    }
    assert tree["children"][2]["children"][0]["evaluation"]["satisfied"] is True
    assert calls == [DOMINATION_MASK]
    assert country_calls == [ENG_REFERENCE]


def test_dlc_token_mismatch_and_unhandled_mask_remain_unknown():
    calls = []

    def dlc_reader(_reader, _module_base, mask):
        calls.append(mask)
        return {"status": "unknown", "reason": "fixture_dlc_unresolved"}

    def prepare(reader, module, _country, _pointers):
        wrong_token, other_mask = 0xA30000, 0xA31000
        _write_dlc(reader, module, wrong_token, token=DLC_TOKEN + 1)
        _write_dlc(reader, module, other_mask, mask=DOMINATION_MASK + 1)
        return [wrong_token, other_mask]

    result, *_rest = _capture(prepare, dlc_reader=dlc_reader)
    leaves = result["tasks"][0]["tree"]["children"]

    assert result["status"] == "observed"
    assert all(leaf["evaluation"]["status"] == "unknown" for leaf in leaves)
    assert all(leaf["evaluation"]["satisfied"] is None for leaf in leaves)
    # The wrong token is rejected before the global DLC reader is consulted.
    assert calls == [DOMINATION_MASK + 1]


def test_capital_selects_each_current_country_and_is_refused_inside_province():
    dynamic_calls = []
    province_rows = {42: {}, 43: {}, 44: {}}
    country_calls = []
    country_binding = _country_scope_reader(
        {ENG_REFERENCE: _binding(ENG_REFERENCE, "ENG", ENG_COUNTRY_POINTER)},
        country_calls,
    )
    def dynamic_scope_reader(_reader, _module_base, kind, current_country_pointer):
        dynamic_calls.append((kind, current_country_pointer))
        province_id = 43 if current_country_pointer == ENG_COUNTRY_POINTER else 42
        return {"status": "known", "province_id": province_id,
                "source": "synthetic-dynamic-scope-reader"}

    def prepare(reader, module, _country, _pointers):
        root_capital, root_capital_ref = 0xA20000, 0xA20100
        foreign_scope, foreign_ref = 0xA21000, 0xA21100
        foreign_capital, foreign_capital_ref = 0xA22000, 0xA22100
        province_scope, province_ref = 0xA23000, 0xA23100
        nested_capital, nested_capital_ref = 0xA24000, 0xA24100

        _empty_body_scope(reader, module, root_capital, root_capital_ref,
                          CAPITAL_REFERENCE_KIND)
        _write_country_scope_reference(reader, foreign_ref, "ENG")
        _empty_body_scope(reader, module, foreign_capital, foreign_capital_ref,
                          CAPITAL_REFERENCE_KIND)
        _write_scope(reader, module, foreign_scope, foreign_ref, [foreign_capital])
        _write_reference(reader, province_ref, province_id=44)
        _empty_body_scope(reader, module, nested_capital, nested_capital_ref,
                          CAPITAL_REFERENCE_KIND)
        _write_scope(reader, module, province_scope, province_ref, [nested_capital])
        return [root_capital, foreign_scope, province_scope]

    result, _reader, _module, country, _loaded, _guards, _ptrs, province_calls = _capture(
        prepare, province_rows=province_rows,
        dynamic_scope_reader=dynamic_scope_reader,
        country_scope_reader=country_binding,
    )
    tree = result["tasks"][0]["tree"]

    assert result["status"] == "observed"
    assert tree["children"][0]["scope"] == {
        "kind": "province", "province_id": 42, "selection": "capital",
    }
    foreign_capital_node = tree["children"][1]["children"][0]
    assert foreign_capital_node["scope"] == {
        "kind": "province", "province_id": 43, "selection": "capital",
    }
    refused = tree["children"][2]["children"][0]
    assert refused["kind"] == "unsupported"
    assert refused["evaluation"]["status"] == "unknown"
    assert dynamic_calls == [("capital", country), ("capital", ENG_COUNTRY_POINTER)]
    assert province_calls == [42, 43, 44]
    assert country_calls == [ENG_REFERENCE]


def test_emperor_scope_binds_target_country_and_preserves_root_sibling():
    dynamic_calls = []
    binding_calls = []
    country_binding = _country_scope_reader(
        {ENG_REFERENCE: _binding(ENG_REFERENCE, "ENG", ENG_COUNTRY_POINTER)},
        binding_calls,
    )

    def dynamic_scope_reader(_reader, _module_base, kind, current_country_pointer):
        dynamic_calls.append((kind, current_country_pointer))
        return {"status": "known", "fullref": ENG_REFERENCE,
                "source": "synthetic-dynamic-scope-reader"}

    def prepare(reader, module, country, _pointers):
        province_scope, province_ref = 0xA20000, 0xA20100
        emperor, emperor_ref, foreign_sailors, root_sailors = (
            0xA21000, 0xA21100, 0xA30000, 0xA31000,
        )
        _write_reference(reader, province_ref, province_id=44)
        _empty_body_scope(reader, module, emperor, emperor_ref,
                          EMPEROR_REFERENCE_KIND)
        # The emperor scope evaluates this scalar under ENG; its sibling stays
        # in the original FRA task-root context.
        _write_leaf(reader, module, foreign_sailors, "sailors",
                    trigger.SAILORS_TOKEN, 0)
        _write_leaf(reader, module, root_sailors, "sailors",
                    trigger.SAILORS_TOKEN, 0)
        reader.dword_put(country + trigger.SAILORS_CURRENT_OFFSET, 1, signed=True)
        reader.dword_put(country + trigger.SAILORS_MAX_OFFSET, 1, signed=True)
        _write_scope(reader, module, emperor, emperor_ref, [foreign_sailors])
        _write_scope(reader, module, province_scope, province_ref, [emperor])
        return [province_scope, root_sailors]

    result, _reader, _module, country, _loaded, _guards, _pointers, _province_calls = _capture(
        prepare, province_rows={44: {}}, dynamic_scope_reader=dynamic_scope_reader,
        country_scope_reader=country_binding,
    )
    tree = result["tasks"][0]["tree"]
    province_scope = tree["children"][0]
    emperor = province_scope["children"][0]

    assert result["status"] == "observed"
    assert province_scope["scope"] == {
        "kind": "province", "province_id": 44, "selection": "literal",
    }
    assert emperor["scope"] == {
        "kind": "country", "country": "ENG", "selection": "emperor",
    }
    assert emperor["children"][0]["evaluation"]["status"] == "unknown"
    assert tree["children"][1]["evaluation"]["satisfied"] is True
    assert dynamic_calls == [("emperor", country)]
    assert binding_calls == [ENG_REFERENCE]
    assert _province_calls == [44]
    compare_scope = result["_compare"]["tasks"][0]["tree"]["children"][0]["children"][0]
    assert compare_scope["bound_country_pointer"] == ENG_COUNTRY_POINTER


def test_emperor_scope_without_verified_canonical_binding_is_opaque():
    def dynamic_scope_reader(_reader, _module_base, kind, _current_country_pointer):
        assert kind == "emperor"
        return {"status": "known", "fullref": ENG_REFERENCE,
                "source": "synthetic-dynamic-scope-reader"}

    def prepare(reader, module, _country, _pointers):
        scope, reference = 0xA20000, 0xA21000
        _empty_body_scope(reader, module, scope, reference, EMPEROR_REFERENCE_KIND)
        return [scope]

    bad_echo = ENG_REFERENCE ^ (1 << 56)
    bindings = (
        None,
        {ENG_REFERENCE: {"status": "unknown", "reason": "fixture_country_unbound"}},
        {ENG_REFERENCE: {"status": "known", "tag": "ENG",
                         "pointer": ENG_COUNTRY_POINTER, "fullref": bad_echo}},
    )
    for binding_rows in bindings:
        binding_calls = []
        country_binding = (None if binding_rows is None else
                           _country_scope_reader(binding_rows, binding_calls))
        result, *_rest = _capture(
            prepare, dynamic_scope_reader=dynamic_scope_reader,
            country_scope_reader=country_binding,
        )
        node = result["tasks"][0]["tree"]["children"][0]

        assert result["status"] == "observed"
        assert node["kind"] == "unsupported"
        assert node["evaluation"]["status"] == "unknown"
        assert node["evaluation"]["satisfied"] is None
        assert "children" not in node
        assert binding_calls == ([] if binding_rows is None else [ENG_REFERENCE])


def test_dynamic_scope_selection_survives_normalize_and_public_projection():
    binding_calls = []
    country_binding = _country_scope_reader(
        {ENG_REFERENCE: _binding(ENG_REFERENCE, "ENG", ENG_COUNTRY_POINTER)},
        binding_calls,
    )

    def dynamic_scope_reader(_reader, _module_base, kind, _current_country_pointer):
        if kind == "capital":
            return {"status": "known", "province_id": 42,
                    "source": "synthetic-dynamic-scope-reader"}
        return {"status": "known", "fullref": ENG_REFERENCE,
                "source": "synthetic-dynamic-scope-reader"}

    def prepare(reader, module, _country, _pointers):
        capital, capital_ref = 0xA20000, 0xA20100
        emperor, emperor_ref = 0xA21000, 0xA21100
        _empty_body_scope(reader, module, capital, capital_ref,
                          CAPITAL_REFERENCE_KIND)
        _empty_body_scope(reader, module, emperor, emperor_ref,
                          EMPEROR_REFERENCE_KIND)
        return [capital, emperor]

    result, *_rest = _capture(
        prepare, province_rows={42: {}}, dynamic_scope_reader=dynamic_scope_reader,
        country_scope_reader=country_binding,
    )
    rows = result["tasks"]
    prerequisites = {
        "status": "known",
        "tasks": [{"root_id": row["root_id"], "task_id": row["task_id"]}
                   for row in rows],
    }
    normalized = normalize_triggers(_report(rows), prerequisites)

    assert normalized["status"] == "known"
    normalized_tree = normalized["tasks"][0]["tree"]
    assert normalized_tree["children"][0]["scope"]["selection"] == "capital"
    assert normalized_tree["children"][1]["scope"]["selection"] == "emperor"
    assert hex(ENG_REFERENCE) not in json.dumps(normalized)
    assert hex(ENG_COUNTRY_POINTER) not in json.dumps(normalized)

    public = project_progress(
        {"mission_triggers": normalized},
        prerequisites["tasks"],
        "1.37.4",
    )
    assert public["status"] == "known"
    public_children = public["value"]["tasks"][0]["trigger"]["children"]
    assert public_children[0]["scope"]["selection"] == "capital"
    assert public_children[1]["scope"]["selection"] == "emperor"
    encoded = json.dumps(public["value"])
    assert hex(ENG_REFERENCE) not in encoded
    assert hex(ENG_COUNTRY_POINTER) not in encoded


def test_unknown_dlc_value_still_exports_its_known_argument_name():
    def prepare(reader, module, _country, _pointers):
        leaf = 0xA30000
        _write_dlc(reader, module, leaf, mask=0x8000)
        return [leaf]

    result, *_rest = _capture(prepare, dlc_reader=lambda *_args: {
        "status": "unknown", "reason": "THREAD_LOCAL_DLC_OVERRIDE_UNRESOLVED"})
    pairs = [{"root_id": t["root_id"], "task_id": t["task_id"]} for t in result["tasks"]]
    normalized = normalize_triggers(_report(result["tasks"]), {"status": "known", "tasks": pairs})
    assert normalized["status"] == "known"
    public = project_progress({"mission_triggers": normalized}, pairs, "1.37.4")
    leaf = public["value"]["tasks"][0]["trigger"]["children"][0]
    assert leaf["evaluation"]["status"] == "unknown"
    assert leaf["metric"]["dlc"] == "Emperor"
