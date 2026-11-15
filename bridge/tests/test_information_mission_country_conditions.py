"""Synthetic end-to-end coverage for country-scoped mission trigger leaves."""
from __future__ import annotations

from copy import deepcopy

import pytest

from bridge.information import mission_memory
from bridge.information import mission_trigger_army as army
from bridge.information import mission_trigger_country_state as country_state
from bridge.information import mission_trigger_memory as trigger
from bridge.information import mission_trigger_profile
from bridge.information import mission_trigger_source as source
from bridge.tests.test_information_mission_conditional_triggers import (
    _install_single_if,
)
from bridge.tests.test_information_mission_memory import write_string32
from bridge.tests.test_information_mission_province_triggers import (
    _write_reference,
    _write_scope,
)
from bridge.tests.test_information_mission_trigger_country_state import (
    _known_unity_record,
)
from bridge.tests.test_information_mission_trigger_memory import (
    _fixture,
    _install_root,
    _write_group,
)


_COUNTRY_LEAVES = {
    "army_ratio": (trigger.ARMY_RATIO_EVALUATE_RVA, 0x1D26000,
                   trigger.ARMY_RATIO_TOKEN),
    "unity": (trigger.UNITY_EVALUATE_RVA, 0x1D26100,
              trigger.UNITY_TOKEN),
    "modifier": (trigger.COUNTRY_MODIFIER_EVALUATE_RVA, 0x1D26200,
                 trigger.COUNTRY_MODIFIER_TOKEN),
}
_COUNTRY_POINTER = 0xB00000
_COUNTRY_KEY = "advisor_cost"


def _write_country_leaf(
    reader,
    module: int,
    pointer: int,
    kind: str,
    threshold: int = 0,
    *,
    token: int | None = None,
    literal_flag: int = 0,
    dynamic_flags: int = 0,
    definition_pointer: int = _COUNTRY_POINTER,
) -> None:
    method_rva, vtable_rva, expected_token = _COUNTRY_LEAVES[kind]
    vtable = module + vtable_rva
    reader.qword_put(vtable + trigger.GROUP_EVALUATE_SLOT, module + method_rva)
    reader.qword_put(pointer, vtable)
    reader.put(pointer + trigger.NODE_LITERAL_FLAGS_OFFSET, bytes([literal_flag]))
    reader.dword_put(
        pointer + trigger.NODE_TOKEN_OFFSET,
        expected_token if token is None else token,
    )
    reader.dword_put(pointer + trigger.NODE_DYNAMIC_FLAGS_OFFSET, dynamic_flags)
    if kind == "modifier":
        reader.qword_put(pointer + trigger.NODE_THRESHOLD_OFFSET, definition_pointer)
    else:
        reader.dword_put(pointer + trigger.NODE_THRESHOLD_OFFSET, threshold, signed=True)


def _write_modifier_definition(reader, module: int, pointer: int, key: str = _COUNTRY_KEY) -> None:
    reader.qword_put(pointer, module + 0x1C42AE0)
    # write_string32 writes at object+DEFINITION_NAME_OFFSET (0x10); shift its
    # synthetic object base so the resulting String32 begins at definition+0x158.
    write_string32(reader, pointer + 0x148, key)


def _modifier_record(module: int, country: int, definitions: list[tuple[int, str]]) -> dict:
    compact = [{"key": key} for _pointer, key in definitions]
    nodes = [
        {"definition_address": hex(pointer), "definition": {"key": key}}
        for pointer, key in definitions
    ]
    return {
        "status": "observed",
        "module_base": hex(module),
        "country_pointer": hex(country),
        "fields": {
            "modifiers": {
                "status": "known",
                "complete": True,
                "value": deepcopy(compact),
            }
        },
        "values": {"modifiers": deepcopy(compact)},
        "observation": {
            "module_base": hex(module),
            "country_pointer": hex(country),
            "terminated": True,
            "count_observed": len(nodes),
            "nodes": nodes,
        },
    }


def _known_land_result(country: int, raw: int = 12000) -> dict:
    return {
        "status": "observed",
        "country": "FRA",
        "country_pointer": hex(country),
        "fields": {
            "force_limits": {
                "status": "partial",
                "value": {
                    "land": {
                        "status": "known",
                        "value": raw // 1000,
                        "raw": raw,
                        "scale": 1000,
                        "unit": "regiments",
                        "complete": True,
                        "partial": False,
                    }
                },
            }
        },
    }


def _install_army_group(reader, module: int, *, vector_length: int = 5) -> dict:
    group_object = 0x990000
    vtable = module + 0x1D27000
    method = module + 0x5000
    reader.qword_put(group_object, vtable)
    reader.qword_put(group_object + 0x48, 0)
    reader.qword_put(vtable + 0x80, method)
    reader.put(method, b"\xb0\x01\xc3\xcc\xcc\xcc")
    return {
        "group_object": hex(group_object),
        "vector_length": vector_length,
    }


def _capture_one(
    kind: str,
    threshold: int,
    country_state_reader,
    *,
    literal_flag: int = 0,
    dynamic_flags: int = 0,
    token: int | None = None,
    definition_pointer: int = _COUNTRY_POINTER,
    province_reader=None,
):
    reader, module, country, loaded, guards, _definitions, pointers = _fixture()
    leaf = 0xA30000
    _write_country_leaf(
        reader,
        module,
        leaf,
        kind,
        threshold,
        token=token,
        literal_flag=literal_flag,
        dynamic_flags=dynamic_flags,
        definition_pointer=definition_pointer,
    )
    _install_root(reader, module, pointers["task_a"], [leaf])
    result = trigger.capture_triggers(
        reader,
        module,
        country,
        loaded,
        code_guards=guards,
        country_state_reader=country_state_reader,
        province_reader=province_reader,
    )
    return reader, module, country, result


def _leaf(result, index: int = 0) -> dict:
    return result["tasks"][0]["tree"]["children"][index]


def _normalize_then_project(captured: dict) -> tuple[dict, dict]:
    task_pairs = [
        {"root_id": row["root_id"], "task_id": row["task_id"]}
        for row in captured["tasks"]
    ]
    prerequisites = {"status": "known", "tasks": task_pairs}
    report = {
        "request": {"include_triggers": True},
        "doublepass": {"trigger_consistent": True},
        "trigger_profile_sha256": mission_trigger_profile.PROFILE_SHA256,
        "cleanup": {"handle_close": {"closed": True}},
        "mission_triggers": captured,
    }
    normalized = source.normalize_triggers(report, prerequisites)
    entries = [
        {"root_id": row["root_id"], "task_id": row["task_id"]}
        for row in task_pairs
    ]
    progress = source.project_progress(
        {"mission_triggers": normalized}, entries, "1.37.4"
    )
    return normalized, progress


def test_real_country_producers_normalize_and_project_small_country_tree(monkeypatch):
    reader, module, country, loaded, guards, _definitions, pointers = _fixture()
    army_group = _install_army_group(reader, module, vector_length=5)
    definition = _COUNTRY_POINTER
    _write_modifier_definition(reader, module, definition)

    leaves = []
    for index, (kind, threshold) in enumerate(
        (
            ("army_ratio", 400),
            ("army_ratio", 417),
            ("unity", 500),
            ("unity", 524),
            ("modifier", 0),
            ("modifier", 0),
        )
    ):
        pointer = 0xA30000 + index * 0x1000
        _write_country_leaf(
            reader,
            module,
            pointer,
            kind,
            threshold,
            definition_pointer=definition,
        )
        leaves.append(pointer)
    _install_root(reader, module, pointers["task_a"], leaves)

    unity_record = _known_unity_record()
    modifier_snapshot = _modifier_record(
        module, country, [(definition, _COUNTRY_KEY), (definition, _COUNTRY_KEY)]
    )
    child_calls = {"religious_unity": 0, "modifiers": 0, "army_ratio": 0}

    def fake_unity_capture(_reader, _module_base, _country_pointer):
        child_calls["religious_unity"] += 1
        return deepcopy(unity_record)

    def fake_modifier_read(_reader, _module_base, _country_pointer):
        child_calls["modifiers"] += 1
        return deepcopy(modifier_snapshot)

    def fake_forces_read(_reader, _module_base, country_pointer, *, country):
        assert country == "FRA"
        return {
            "status": "observed",
            "country": "FRA",
            "country_pointer": hex(country_pointer),
            "group_count": 1,
            "groups": [army_group],
        }

    def fake_military_read(_reader, _module_base, country_pointer, *, country):
        assert country == "FRA"
        return _known_land_result(country_pointer)

    monkeypatch.setattr(
        country_state.religious_unity_memory, "capture", fake_unity_capture
    )
    monkeypatch.setattr(
        country_state.country_modifiers_memory, "read_fields", fake_modifier_read
    )
    monkeypatch.setattr(army.forces, "read_fields", fake_forces_read)
    monkeypatch.setattr(army.military_resources, "read_fields", fake_military_read)

    calls: list[tuple[int, int, int, str]] = []

    def read_country_state(tracked_reader, module_base, country_pointer, kind):
        calls.append((id(tracked_reader), module_base, country_pointer, kind))
        child_calls[kind] += int(kind == "army_ratio")
        if kind == "army_ratio":
            return army.count_army_ratio_inputs(
                tracked_reader, module_base, country_pointer
            )
        return country_state.read_country_state(
            tracked_reader, module_base, country_pointer, kind
        )

    captured = trigger.capture_triggers(
        reader,
        module,
        country,
        loaded,
        code_guards=guards,
        country_state_reader=read_country_state,
    )

    assert captured["status"] == "observed", captured
    assert captured["complete"] is True
    assert [row[3] for row in calls] == ["army_ratio", "religious_unity", "modifiers"]
    assert all(row[1:3] == (module, country) for row in calls)
    assert child_calls == {"religious_unity": 1, "modifiers": 1, "army_ratio": 1}
    tree = captured["tasks"][0]["tree"]
    assert [child["evaluation"]["satisfied"] for child in tree["children"]] == [
        True, False, True, False, True, True,
    ]
    assert tree["children"][0]["metric"] == {
        "threshold": 400,
        "numerator_raw": 5000,
        "denominator_raw": 12000,
        "raw_ratio": 416,
        "unit": "fraction_per_mille",
        "source": army.SOURCE,
    }
    assert tree["children"][2]["metric"]["upper_clamp"] is False
    assert tree["children"][4]["metric"]["direct_list_complete"] is True
    assert tree["children"][4]["metric"]["secondary_list_checked"] is False
    assert not any(
        row["label"].endswith("modifier.secondary_head")
        for row in captured["_compare"]["rawreads"]
    )

    normalized, progress = _normalize_then_project(captured)
    assert normalized["status"] == "known"
    assert progress["status"] == "known"
    assert progress["value"]["task_count"] == 1
    assert progress["value"]["evaluated_leaf_count"] == 6
    assert progress["value"]["satisfied_leaf_count"] == 4
    assert progress["value"]["unsatisfied_leaf_count"] == 2
    assert progress["value"]["unknown_leaf_count"] == 0
    assert {
        trigger.ARMY_RATIO_EVALUATE_RVA,
        trigger.UNITY_EVALUATE_RVA,
        trigger.COUNTRY_MODIFIER_EVALUATE_RVA,
    }.issubset(source._SCALAR_METHODS)


@pytest.mark.parametrize(
    ("numerator", "denominator", "threshold", "expected", "raw_ratio"),
    [
        (1, 2, 500, True, 500),
        (1, 3, 333, True, 333),
        (-1, 3, -333, True, -333),
        (1, 0, -1, True, -1),
        (1, 0, 0, False, -1),
    ],
)
def test_army_ratio_uses_s32_native_truncation_and_zero_limit(
    numerator, denominator, threshold, expected, raw_ratio
):
    result = {"status": "known", "army_raw_fixed_milli": numerator,
              "land_force_limit_raw": denominator, "source": "synthetic-army"}
    _reader, _module, _country, captured = _capture_one(
        "army_ratio", threshold, lambda *_args: result
    )
    metric = _leaf(captured)["metric"]
    assert _leaf(captured)["evaluation"]["satisfied"] is expected
    assert metric["raw_ratio"] == raw_ratio


@pytest.mark.parametrize(
    "state",
    [
        {"status": "known", "army_raw_fixed_milli": True,
         "land_force_limit_raw": 1, "source": "fake"},
        {"status": "known", "army_raw_fixed_milli": 2**31,
         "land_force_limit_raw": 1, "source": "fake"},
        {"status": "known", "army_raw_fixed_milli": 1,
         "land_force_limit_raw": -1, "source": "fake"},
        {"status": "known", "army_raw_fixed_milli": 1,
         "land_force_limit_raw": 2**31, "source": "fake"},
    ],
)
def test_army_ratio_rejects_invalid_raw_inputs(state):
    _reader, _module, _country, captured = _capture_one(
        "army_ratio", 0, lambda *_args: state
    )
    assert _leaf(captured)["evaluation"] == {
        "status": "unknown", "satisfied": None,
        "reason": "army_ratio_inputs_unknown",
    }


def test_unity_literal_uses_unclamped_raw_value_and_dynamic_threshold_stays_unknown():
    high_raw = {"status": "known", "raw_fixed_milli": 1_250_000,
                "source": "synthetic-unity"}
    _reader, _module, _country, captured = _capture_one(
        "unity", 1_200_000, lambda *_args: high_raw
    )
    assert _leaf(captured)["evaluation"]["satisfied"] is True
    assert _leaf(captured)["metric"]["raw_value"] == 1_250_000
    assert _leaf(captured)["metric"]["upper_clamp"] is False

    for literal_flag, dynamic_flags in ((1, 0), (0, 0x4000)):
        calls = []
        _reader, _module, _country, dynamic = _capture_one(
            "unity",
            100,
            lambda *args: calls.append(args) or high_raw,
            literal_flag=literal_flag,
            dynamic_flags=dynamic_flags,
        )
        assert _leaf(dynamic)["evaluation"] == {
            "status": "unknown", "satisfied": None,
            "reason": "dynamic_unity_threshold_unsupported",
        }
        assert calls == []


@pytest.mark.parametrize("raw", [True, -1, 2**31, "523"])
def test_unity_rejects_invalid_or_negative_raw_input(raw):
    state = {"status": "known", "raw_fixed_milli": raw,
             "source": "synthetic-unity"}
    _reader, _module, _country, captured = _capture_one(
        "unity", 0, lambda *_args: state
    )
    assert _leaf(captured)["evaluation"] == {
        "status": "unknown", "satisfied": None,
        "reason": "religious_unity_inputs_unknown",
    }


def test_fake_country_callback_raw_drift_changes_compare_but_not_boolean():
    reader, module, country, loaded, guards, _definitions, pointers = _fixture()
    leaf = 0xA30000
    _write_country_leaf(reader, module, leaf, "unity", threshold=500)
    _install_root(reader, module, pointers["task_a"], [leaf])
    reader.dword_put(country + 0x300, 510, signed=True)

    def read_value(tracked_reader, _module, country_pointer, kind):
        assert country_pointer == country
        assert kind == "religious_unity"
        raw = int.from_bytes(
            tracked_reader.read(country_pointer + 0x300, 4,
                                "synthetic.country.unity_raw"),
            "little",
            signed=True,
        )
        return {"status": "known", "raw_fixed_milli": raw,
                "source": "synthetic-country-reader"}

    first = trigger.capture_triggers(
        reader, module, country, loaded, code_guards=guards,
        country_state_reader=read_value,
    )
    reader.dword_put(country + 0x300, 520, signed=True)
    second = trigger.capture_triggers(
        reader, module, country, loaded, code_guards=guards,
        country_state_reader=read_value,
    )

    assert _leaf(first)["evaluation"]["satisfied"] is True
    assert _leaf(second)["evaluation"]["satisfied"] is True
    assert _leaf(first)["metric"]["raw_value"] == 510
    assert _leaf(second)["metric"]["raw_value"] == 520
    assert mission_memory._diff_paths(first["_compare"], second["_compare"])
    assert first["_compare"]["rawreads"] != second["_compare"]["rawreads"]


@pytest.mark.parametrize(
    "definitions,secondary,expected,secondary_read",
    [
        ([(_COUNTRY_POINTER, _COUNTRY_KEY)], None, True, False),
        ([], (0xB10000, _COUNTRY_POINTER, 0), True, True),
        ([], None, False, True),
    ],
)
def test_modifier_direct_secondary_and_absent_membership(
    definitions, secondary, expected, secondary_read
):
    reader, module, country, loaded, guards, _definitions, pointers = _fixture()
    definition = _COUNTRY_POINTER
    _write_modifier_definition(reader, module, definition)
    leaf = 0xA30000
    _write_country_leaf(reader, module, leaf, "modifier", definition_pointer=definition)
    _install_root(reader, module, pointers["task_a"], [leaf])
    if secondary is not None:
        head, member, following = secondary
        reader.qword_put(country + 0x220, head)
        reader.qword_put(head, member)
        reader.qword_put(head + 0x10, following)
    state = {"status": "known", "definitions": [
        {"pointer": pointer, "key": key} for pointer, key in definitions
    ], "source": "synthetic-modifier-state"}
    calls = []
    raw_reads = []
    original_read = reader.read

    def trace_read(address, size, label):
        raw_reads.append((address, size, label))
        return original_read(address, size, label)

    reader.read = trace_read
    captured = trigger.capture_triggers(
        reader, module, country, loaded, code_guards=guards,
        country_state_reader=lambda _reader, _module, _country, kind:
            calls.append(kind) or state,
    )

    assert _leaf(captured)["evaluation"]["satisfied"] is expected
    assert calls == ["modifiers"]
    read_secondary = any(address == country + 0x220 for address, _size, _label in raw_reads)
    assert read_secondary is secondary_read
    if expected:
        assert _leaf(captured)["metric"]["modifier_id"] == _COUNTRY_KEY


def test_modifier_direct_match_short_circuits_secondary_read_even_for_complete_empty_list():
    reader, module, country, loaded, guards, _definitions, pointers = _fixture()
    definition = _COUNTRY_POINTER
    _write_modifier_definition(reader, module, definition)
    leaf = 0xA30000
    _write_country_leaf(reader, module, leaf, "modifier", definition_pointer=definition)
    _install_root(reader, module, pointers["task_a"], [leaf])
    state = {"status": "known", "definitions": [
        {"pointer": definition, "key": _COUNTRY_KEY}
    ], "source": "synthetic-modifier-state"}
    reads = []
    original_read = reader.read

    def trace_read(address, size, label):
        reads.append((address, size, label))
        return original_read(address, size, label)

    reader.read = trace_read
    captured = trigger.capture_triggers(
        reader, module, country, loaded, code_guards=guards,
        country_state_reader=lambda *_args: state,
    )
    assert _leaf(captured)["evaluation"]["satisfied"] is True
    assert not any(address == country + 0x220 for address, _size, _label in reads)


@pytest.mark.parametrize(
    ("state", "token", "definition", "expected_reason", "callback_count"),
    [
        ({"status": "unknown", "reason": "source_unknown"}, None,
         _COUNTRY_POINTER, "country_modifier_instances_unknown", 1),
        ({"status": "known", "definitions": [
            {"pointer": _COUNTRY_POINTER, "key": "tax_income"}
         ]}, None, _COUNTRY_POINTER, "modifier_definition_key_conflict", 1),
        ({"status": "known", "definitions": []},
         trigger.COUNTRY_MODIFIER_TOKEN + 1, _COUNTRY_POINTER,
         "modifier_method_token_mismatch", 0),
        ({"status": "known", "definitions": []}, None,
         0x12345, "modifier_definition_pointer_invalid", 0),
    ],
)
def test_modifier_unknown_wrong_token_key_conflict_and_bad_reference_fail_closed(
    state, token, definition, expected_reason, callback_count
):
    reader, module, country, loaded, guards, _definitions, pointers = _fixture()
    _write_modifier_definition(reader, module, _COUNTRY_POINTER)
    leaf = 0xA30000
    _write_country_leaf(
        reader, module, leaf, "modifier", token=token,
        definition_pointer=definition,
    )
    _install_root(reader, module, pointers["task_a"], [leaf])
    calls = []
    captured = trigger.capture_triggers(
        reader, module, country, loaded, code_guards=guards,
        country_state_reader=lambda *_args: calls.append("modifiers") or state,
    )
    assert _leaf(captured)["evaluation"]["status"] == "unknown"
    assert _leaf(captured)["evaluation"]["reason"] == expected_reason
    assert calls == ["modifiers"] * callback_count


def test_modifier_secondary_list_cycle_retracts_the_capture():
    reader, module, country, loaded, guards, _definitions, pointers = _fixture()
    definition = _COUNTRY_POINTER
    _write_modifier_definition(reader, module, definition)
    node = 0xB10000
    reader.qword_put(country + 0x220, node)
    reader.qword_put(node, definition)
    reader.qword_put(node + 0x10, node)
    leaf = 0xA30000
    _write_country_leaf(reader, module, leaf, "modifier", definition_pointer=definition)
    _install_root(reader, module, pointers["task_a"], [leaf])
    captured = trigger.capture_triggers(
        reader, module, country, loaded, code_guards=guards,
        country_state_reader=lambda *_args: {
            "status": "known", "definitions": [], "source": "synthetic-empty"
        },
    )
    assert captured["status"] == "unknown"
    assert captured["tasks"] == []
    assert "secondary_modifier_list_invalid_or_over_bound" in captured["reason"]


def test_country_leaves_keep_root_country_in_if_and_stay_unknown_in_province_scope():
    reader, module, country, loaded, guards, _definitions, pointers = _fixture()
    limit, then_leaf, else_leaf = 0xA30000, 0xA31000, 0xA32000
    for pointer, threshold in ((limit, 500), (then_leaf, 500), (else_leaf, 501)):
        _write_country_leaf(reader, module, pointer, "unity", threshold)
    _install_single_if(
        reader, module, pointers["task_a"], 0xA20000,
        limit_children=[limit], then_children=[then_leaf], else_children=[else_leaf],
    )
    state_calls = []

    def root_state(_reader, base, country_pointer, kind):
        state_calls.append((base, country_pointer, kind))
        return {"status": "known", "raw_fixed_milli": 500, "source": "root-state"}

    if_result = trigger.capture_triggers(
        reader, module, country, loaded, code_guards=guards,
        country_state_reader=root_state,
    )
    if_tree = if_result["tasks"][0]["tree"]["children"][0]
    assert if_tree["kind"] == "if"
    assert if_tree["selected_branch"] == "then"
    assert state_calls == [(module, country, "religious_unity")]

    reader, module, country, loaded, guards, _definitions, pointers = _fixture()
    root_reference = (122 << 32) | int.from_bytes(b"FRA", "little")
    reader.qword_put(country + 0x20, root_reference)
    scope, reference = 0xA20000, 0xA40000
    _write_reference(reader, reference, province_id=42)
    scalar, modifier, army_leaf = 0xA30000, 0xA31000, 0xA32000
    _write_country_leaf(reader, module, scalar, "unity", 100)
    _write_country_leaf(reader, module, army_leaf, "army_ratio", 0)
    _write_country_leaf(reader, module, modifier, "modifier")
    _write_scope(reader, module, scope, reference, [scalar, army_leaf, modifier])
    _install_root(reader, module, pointers["task_a"], [scope])
    province_calls = []

    def province_state(_read, base, province_id):
        province_calls.append((base, province_id))
        return {
            "status": "known",
            "province_id": province_id,
            "observer_pointer": country,
            "observer_reference": root_reference,
            "owner": {"status": "known", "tag": "FRA", "reference": root_reference},
            "controller": {"status": "known", "tag": "FRA", "reference": root_reference},
        }

    country_calls = []
    scoped = trigger.capture_triggers(
        reader, module, country, loaded, code_guards=guards,
        province_reader=province_state,
        country_state_reader=lambda *args: country_calls.append(args) or pytest.fail(
            "country-only condition must stay unknown inside province scope"
        ),
    )
    scope_tree = scoped["tasks"][0]["tree"]["children"][0]
    assert scope_tree["kind"] == "scope"
    assert scope_tree["scope"]["province_id"] == 42
    assert [child["evaluation"]["reason"] for child in scope_tree["children"]] == [
        "country_scalar_in_province_scope_unsupported",
        "country_scalar_in_province_scope_unsupported",
        "country_modifier_in_province_scope_unsupported",
    ]
    assert province_calls == [(module, 42)]
    assert country_calls == []



def test_virtual_method_binding_uses_actual_aslr_module_base():
    import pytest
    from bridge.information import mission_trigger_memory as memory
    from bridge.tests.test_information_mission_trigger_memory import _fixture

    reader, preferred_base, *_rest = _fixture()
    relocated_base = 0x7FF600000000
    node = 0xA20000
    table = relocated_base + 0x1D17D70
    reader.qword_put(node, table)
    reader.qword_put(table + memory.GROUP_EVALUATE_SLOT,
                     relocated_base + memory.COUNTRY_MODIFIER_EVALUATE_RVA)
    assert memory._read_eval_method(reader, relocated_base, node)[2] == memory.COUNTRY_MODIFIER_EVALUATE_RVA
    reader.qword_put(table + memory.GROUP_EVALUATE_SLOT,
                     preferred_base + memory.COUNTRY_MODIFIER_EVALUATE_RVA)
    with pytest.raises(ValueError, match='outside_module_range'):
        memory._read_eval_method(reader, relocated_base, node)
