"""Literal-country selector tests for the held-by mission predicate."""
from __future__ import annotations

import json
from copy import deepcopy
from unittest.mock import patch

from bridge.information import mission_trigger_memory as trigger
from bridge.information.mission_trigger_source import normalize_triggers, project_progress
from bridge.tests.test_information_mission_province_triggers import (
    _other_reference,
    _province_reader,
    _root_reference,
    _write_province_leaf,
    _write_reference,
    _write_scope,
    _write_subject_relation,
)
from bridge.tests.test_information_mission_trigger_memory import _fixture, _install_root
from bridge.tests.test_information_mission_trigger_source import _report


ROOT_SLOT = 122
ENG_SLOT = 321
SCO_SLOT = 400
ROOT_COUNTRY_POINTER = 0x500000
ENG_COUNTRY_POINTER = 0x530000
PROVINCE_ID = 42


def _fullref(slot: int, tag: str, high_byte: int = 0x2A) -> int:
    return (high_byte << 56) | (slot << 32) | int.from_bytes(tag.encode("ascii"), "little")


ROOT_FULLREF = _fullref(ROOT_SLOT, "FRA")
ENG_FULLREF = _fullref(ENG_SLOT, "ENG")
ENG_ALT_FULLREF = _fullref(ENG_SLOT, "ENG", high_byte=0x2B)
SCO_FULLREF = _fullref(SCO_SLOT, "SCO")


def _tag(fullref: int) -> str:
    return (fullref & 0xFFFFFF).to_bytes(3, "little").decode("ascii")


def _binding(fullref: int, root_pointer: int) -> dict:
    tag = _tag(fullref)
    pointer = root_pointer if tag == "FRA" else ENG_COUNTRY_POINTER
    return {"status": "known", "tag": tag, "pointer": pointer, "fullref": fullref}


def _binding_reader(rows: dict[int, dict], calls: list[int]):
    def read_binding(_reader, _module_base: int, fullref: int):
        calls.append(fullref)
        return deepcopy(rows.get(fullref, {
            "status": "unknown", "reason": "fixture_country_not_found",
        }))

    return read_binding


def _held_leaf(reader, module: int, pointer: int, fullref: int | None,
               *, selector: int = trigger.ROOT_COUNTRY_FLAGS) -> None:
    _write_province_leaf(reader, module, pointer, "held", selector=selector)
    if fullref is not None:
        # BE9606 reads the literal fullref from node+0x48. Its high byte
        # overlays the old literal flag byte at node+0x4f.
        reader.qword_put(pointer + 0x48, fullref)


def _capture_held(owner: dict, fullrefs: list[int | None], *,
                  bindings: dict[int, dict] | None = None,
                  with_binder: bool = True, selector: int = trigger.ROOT_COUNTRY_FLAGS,
                  prepare_reader=None, province_limit: int | None = None):
    reader, module, country, loaded, guards, _definitions, pointers = _fixture()
    root_reference = ROOT_FULLREF
    reader.qword_put(country + 0x20, root_reference)
    if prepare_reader is not None:
        prepare_reader(reader, country)

    province_reference, scope = 0xA30000, 0xA20000
    leaf_pointers = [0xA40000 + index * 0x1000 for index in range(len(fullrefs))]
    _write_reference(reader, province_reference, province_id=PROVINCE_ID)
    for pointer, fullref in zip(leaf_pointers, fullrefs):
        _held_leaf(reader, module, pointer, fullref, selector=selector)
    _write_scope(reader, module, scope, province_reference, leaf_pointers)
    _install_root(reader, module, pointers["task_a"], [scope])

    province_calls: list[int] = []
    province_reader = _province_reader(
        country, root_reference,
        {PROVINCE_ID: {"owner": deepcopy(owner)}}, province_calls,
    )
    binding_calls: list[int] = []
    kwargs = {"province_reader": province_reader}
    if with_binder:
        kwargs["country_scope_reader"] = _binding_reader(bindings or {}, binding_calls)
    if province_limit is None:
        result = trigger.capture_triggers(reader, module, country, loaded,
                                          code_guards=guards, **kwargs)
    else:
        with patch.object(trigger, "MAX_PROVINCE_TARGETS", province_limit):
            result = trigger.capture_triggers(reader, module, country, loaded,
                                              code_guards=guards, **kwargs)
    return result, reader, binding_calls, province_calls, (module, country, loaded, guards)


def _leaf(result, index: int = 0) -> dict:
    return result["tasks"][0]["tree"]["children"][0]["children"][index]


def test_literal_held_match_and_mismatch_use_bound_country_even_when_flags_select_root():
    bindings = {ENG_FULLREF: _binding(ENG_FULLREF, ROOT_COUNTRY_POINTER)}
    matching, _reader, calls, _province_calls, _ctx = _capture_held(
        {"status": "known", "tag": "ENG", "reference": ENG_FULLREF},
        [ENG_FULLREF], bindings=bindings,
        selector=trigger.ROOT_COUNTRY_FLAGS,
    )
    assert matching["status"] == "observed"
    assert _leaf(matching)["evaluation"]["satisfied"] is True
    assert _leaf(matching)["metric"]["comparison_country"] == "ENG"
    assert calls == [ENG_FULLREF]

    def unrelated_owner(reader, _country):
        _write_subject_relation(reader, 0xA50000, root_slot=400)

    mismatch, _reader, calls, _province_calls, _ctx = _capture_held(
        {"status": "known", "tag": "SCO", "reference": SCO_FULLREF,
         "country_pointer": 0xA50000},
        [ENG_FULLREF], bindings=bindings, prepare_reader=unrelated_owner,
        selector=trigger.ROOT_COUNTRY_FLAGS,
    )
    assert mismatch["status"] == "observed"
    assert _leaf(mismatch)["evaluation"]["satisfied"] is False
    assert _leaf(mismatch)["metric"]["comparison_country"] == "ENG"
    assert calls == [ENG_FULLREF]


def test_foreign_literal_does_not_substitute_root_slot_or_root_subject_relation():
    # ROOT FRA owns this province and has a positive ROOT subject record.
    # A literal ENG selector must still compare with slot 321 and return false.
    def root_subject(reader, country):
        _write_subject_relation(reader, country, root_slot=ROOT_SLOT, holds=True)

    result, reader, calls, _province_calls, _ctx = _capture_held(
        {"status": "known", "tag": "FRA", "reference": ROOT_FULLREF,
         "country_pointer": ROOT_COUNTRY_POINTER},
        [ENG_FULLREF],
        bindings={ENG_FULLREF: _binding(ENG_FULLREF, ROOT_COUNTRY_POINTER)},
        prepare_reader=root_subject,
    )

    assert result["status"] == "observed"
    assert _leaf(result)["evaluation"]["satisfied"] is False
    assert _leaf(result)["metric"]["comparison_country"] == "ENG"
    assert calls == [ENG_FULLREF]
    labels = [row["label"] for row in result["_compare"]["rawreads"]]
    assert any(label.endswith("owner_parent_reference") for label in labels)
    assert not any(label.endswith("owner_relation_table") for label in labels)


def test_held_subject_relation_is_checked_against_literal_fullref_slot():
    subject_owner = 0xA50000

    def literal_subject(reader, _country):
        _write_subject_relation(reader, subject_owner, root_slot=ENG_SLOT, holds=True)

    result, _reader, calls, _province_calls, _ctx = _capture_held(
        {"status": "known", "tag": "SCO", "reference": SCO_FULLREF,
         "country_pointer": subject_owner},
        [ENG_FULLREF],
        bindings={ENG_FULLREF: _binding(ENG_FULLREF, ROOT_COUNTRY_POINTER)},
        prepare_reader=literal_subject,
    )

    assert result["status"] == "observed"
    assert _leaf(result)["evaluation"]["satisfied"] is True
    assert _leaf(result)["metric"]["comparison_country"] == "ENG"
    assert calls == [ENG_FULLREF]


def test_literal_fra_binds_the_root_object_but_exports_literal_fra_argument():
    result, _reader, calls, _province_calls, _ctx = _capture_held(
        {"status": "known", "tag": "FRA", "reference": ROOT_FULLREF},
        [ROOT_FULLREF],
        bindings={ROOT_FULLREF: _binding(ROOT_FULLREF, ROOT_COUNTRY_POINTER)},
        selector=0,
    )
    assert result["status"] == "observed"
    assert _leaf(result)["evaluation"]["satisfied"] is True
    assert _leaf(result)["metric"]["comparison_country"] == "FRA"
    assert calls == [ROOT_FULLREF]


def test_country_binding_cache_uses_fullref_identity():
    bindings = {
        ENG_FULLREF: _binding(ENG_FULLREF, ROOT_COUNTRY_POINTER),
        ENG_ALT_FULLREF: _binding(ENG_ALT_FULLREF, ROOT_COUNTRY_POINTER),
    }
    result, _reader, calls, _province_calls, _ctx = _capture_held(
        {"status": "known", "tag": "ENG", "reference": ENG_FULLREF},
        [ENG_FULLREF, ENG_FULLREF, ENG_ALT_FULLREF], bindings=bindings,
    )

    assert result["status"] == "observed"
    assert calls == [ENG_FULLREF, ENG_ALT_FULLREF]
    assert all(_leaf(result, index)["metric"]["comparison_country"] == "ENG"
               for index in range(3))


def test_unknown_missing_or_bad_echo_binding_stays_unknown_without_root_fallback():
    def root_subject(reader, country):
        _write_subject_relation(reader, country, root_slot=ROOT_SLOT, holds=True)

    cases = (
        (True, {ENG_FULLREF: {"status": "unknown", "reason": "fixture_unresolved"}},
         "fixture_unresolved"),
        (True, {ENG_FULLREF: {"status": "known", "tag": "ENG",
                              "pointer": ENG_COUNTRY_POINTER,
                              "fullref": ENG_ALT_FULLREF}},
         "country_scope_binding_contract_invalid"),
        (False, {}, "country_scope_reader_not_configured"),
    )
    for with_binder, bindings, reason in cases:
        result, _reader, calls, _province_calls, _ctx = _capture_held(
            {"status": "known", "tag": "FRA", "reference": ROOT_FULLREF,
             "country_pointer": ROOT_COUNTRY_POINTER},
            [ENG_FULLREF], bindings=bindings, with_binder=with_binder,
            prepare_reader=root_subject,
        )
        assert result["status"] == "observed"
        leaf = _leaf(result)
        assert leaf["evaluation"]["status"] == "unknown"
        assert leaf["evaluation"]["satisfied"] is None
        assert leaf["evaluation"]["reason"] == reason
        assert leaf["metric"]["comparison_country"] is None
        assert calls == ([ENG_FULLREF] if with_binder else [])


def test_root_path_needs_no_binder_and_other_literal_province_methods_stay_unknown():
    root_result, _reader, calls, _province_calls, _ctx = _capture_held(
        {"status": "known", "tag": "FRA", "reference": ROOT_FULLREF},
        [None], with_binder=False,
    )
    assert root_result["status"] == "observed"
    assert _leaf(root_result)["evaluation"]["satisfied"] is True
    assert _leaf(root_result)["metric"]["comparison_country"] == "ROOT"
    assert calls == []

    for kind in ("owned", "controlled"):
        reader, module, country, loaded, guards, _definitions, pointers = _fixture()
        reader.qword_put(country + 0x20, ROOT_FULLREF)
        province_ref, scope, leaf = 0xA30000, 0xA20000, 0xA40000
        _write_reference(reader, province_ref, province_id=PROVINCE_ID)
        _write_province_leaf(reader, module, leaf, kind)
        reader.qword_put(leaf + 0x48, ENG_FULLREF)
        _write_scope(reader, module, scope, province_ref, [leaf])
        _install_root(reader, module, pointers["task_a"], [scope])
        binding_calls: list[int] = []
        result = trigger.capture_triggers(
            reader, module, country, loaded, code_guards=guards,
            province_reader=_province_reader(country, ROOT_FULLREF, {}, []),
            country_scope_reader=_binding_reader(
                {ENG_FULLREF: _binding(ENG_FULLREF, country)}, binding_calls
            ),
        )
        node = _leaf(result)
        assert node["evaluation"]["status"] == "unknown"
        assert node["evaluation"]["reason"] == "comparison_country_selector_unsupported"
        assert node["metric"]["comparison_country"] is None
        assert binding_calls == []


def test_province_target_cap_keeps_literal_held_condition_unknown():
    result, _reader, calls, province_calls, _ctx = _capture_held(
        {"status": "known", "tag": "ENG", "reference": ENG_FULLREF},
        [ENG_FULLREF],
        bindings={ENG_FULLREF: _binding(ENG_FULLREF, ROOT_COUNTRY_POINTER)},
        province_limit=0,
    )
    scope = result["tasks"][0]["tree"]["children"][0]
    assert result["status"] == "observed"
    assert scope["kind"] == "unsupported"
    assert scope["evaluation"]["status"] == "unknown"
    assert scope["evaluation"]["reason"] == "province_target_budget_exceeded"
    assert "children" not in scope
    assert calls == []
    assert province_calls == []


def test_normalization_and_public_projection_keep_only_literal_tag():
    result, _reader, _calls, _province_calls, _ctx = _capture_held(
        {"status": "known", "tag": "ENG", "reference": ENG_FULLREF},
        [ENG_FULLREF],
        bindings={ENG_FULLREF: _binding(ENG_FULLREF, ROOT_COUNTRY_POINTER)},
    )
    loaded_tasks = [{"root_id": row["root_id"], "task_id": row["task_id"]}
                    for row in result["tasks"]]
    normalized = normalize_triggers(
        _report(result["tasks"]), {"status": "known", "tasks": loaded_tasks},
    )
    assert normalized["status"] == "known"
    normalized_leaf = normalized["tasks"][0]["tree"]["children"][0]["children"][0]
    assert normalized_leaf["metric"]["comparison_country"] == "ENG"
    assert hex(ENG_FULLREF) not in json.dumps(normalized)
    assert hex(ENG_COUNTRY_POINTER) not in json.dumps(normalized)

    public = project_progress(
        {"mission_triggers": normalized},
        loaded_tasks,
        "1.37.4",
    )
    assert public["status"] == "known"
    public_leaf = public["value"]["tasks"][0]["trigger"]["children"][0]["children"][0]
    assert public_leaf["metric"]["comparison_country"] == "ENG"
    encoded = json.dumps(public["value"])
    assert hex(ENG_FULLREF) not in encoded
    assert hex(ENG_COUNTRY_POINTER) not in encoded
    keys = _mapping_keys(public["value"])
    assert not {"fullref", "pointer", "country_pointer"} & keys


def _mapping_keys(value) -> set[str]:
    if isinstance(value, dict):
        return set(value) | set().union(*(_mapping_keys(child) for child in value.values()))
    if isinstance(value, list):
        return set().union(*(_mapping_keys(child) for child in value)) if value else set()
    return set()
