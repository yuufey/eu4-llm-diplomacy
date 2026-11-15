"""Bounded producer and source coverage for boolean and province-ID triggers."""

import pytest

from bridge.information import mission_trigger_memory as trigger
from bridge.information import mission_trigger_source as source
from bridge.tests.test_information_mission_counted_triggers import fixture as _count_fixture
from bridge.tests.test_information_mission_province_triggers import (
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
from bridge.tests.test_information_mission_trigger_source import (
    _normalized_state,
    _report,
)


def _write_boolean_match(reader, module, pointer, children, expected_raw):
    vtable = _set_method(
        reader, module, "unsupported",
        method_rva=trigger.BOOLEAN_MATCH_EVALUATE_RVA,
        vtable_rva=0x1D07510,
    )
    reader.qword_put(pointer, vtable)
    data = pointer + trigger.GROUP_INLINE_OFFSET
    reader.qword_put(pointer + trigger.GROUP_DATA_OFFSET, data)
    reader.dword_put(pointer + trigger.GROUP_CAPACITY_OFFSET,
                     max(trigger.INLINE_GROUP_CAPACITY, len(children)), signed=True)
    reader.dword_put(pointer + trigger.GROUP_COUNT_OFFSET, len(children), signed=True)
    reader.qword_put(pointer + trigger.GROUP_PARSER_OFFSET,
                     module + trigger.GROUP_PARSER_VTABLE_RVA)
    reader.dword_put(pointer + trigger.NODE_TOKEN_OFFSET, 0x401C)
    reader.put(pointer + 0xA0, bytes([expected_raw]))
    for index, child in enumerate(children):
        reader.qword_put(data + index * 8, child)


def _write_province_id(reader, module, pointer, *, required, flags=0, token=0x4A31):
    vtable = _set_method(
        reader, module, "unsupported",
        method_rva=trigger.PROVINCE_ID_EVALUATE_RVA,
        vtable_rva=0x1D20500,
    )
    reader.qword_put(pointer, vtable)
    reader.dword_put(pointer + trigger.NODE_TOKEN_OFFSET, token)
    reader.dword_put(pointer + trigger.NODE_DYNAMIC_FLAGS_OFFSET, flags)
    reader.dword_put(pointer + 0x64, 0)
    reader.dword_put(pointer + trigger.NODE_THRESHOLD_OFFSET, required, signed=True)


def _capture_one(reader, module, country, loaded, guards, pointer, **kwargs):
    _install_root(reader, module, kwargs.pop("task_pointer"), [pointer])
    result = trigger.capture_triggers(
        reader, module, country, loaded, code_guards=guards, **kwargs
    )
    assert result["status"] == "observed", result.get("reason")
    return result, result["tasks"][0]["tree"]["children"][0]


@pytest.mark.parametrize(
    ("expected_raw", "body", "expected_result"),
    [
        (1, "true", True),
        (1, "false", False),
        (0, "false", True),
        (1, "unknown", None),
    ],
)
def test_boolean_match_compares_and_body_to_expected(expected_raw, body, expected_result):
    reader, module, country, loaded, guards, _definitions, pointers = _fixture()
    wrapper, child = 0xA60000, 0xA61000
    children = []
    if body == "false":
        _write_province_id(reader, module, child, required=42)
        children = [child]
    elif body == "unknown":
        _write_leaf(reader, module, child, "unsupported", 0x45AA, 0)
        children = [child]
    _write_boolean_match(reader, module, wrapper, children, expected_raw)

    result, node = _capture_one(
        reader, module, country, loaded, guards, wrapper,
        task_pointer=pointers["task_a"],
    )

    assert node["kind"] == "boolean_match"
    assert node["expected_satisfied"] is bool(expected_raw)
    assert node["body"]["kind"] == "and"
    assert node["body"]["method_rva"] == trigger.AND_EVALUATE_RVA
    assert node["evaluation"]["satisfied"] is expected_result


def test_province_id_literal_context_and_dynamic_selector_results():
    for actual_id, required_id, flags, expected in (
        (42, 42, 0, True),
        (43, 42, 0, False),
        (42, 42, 0x4000, None),
    ):
        reader, module, country, loaded, guards, _definitions, pointers = _fixture()
        leaf, reference, scope = 0xA60000, 0xA61000, 0xA62000
        reader.qword_put(country + 0x20, _root_reference())
        _write_province_id(reader, module, leaf, required=required_id, flags=flags)
        _write_reference(reader, reference, province_id=actual_id)
        _write_scope(reader, module, scope, reference, [leaf])

        def province_reader(_read, _module, province_id):
            assert province_id == actual_id
            root_ref = _root_reference()
            return {
                "status": "known", "province_id": province_id,
                "observer_pointer": country, "observer_reference": root_ref,
                "owner": {"status": "known", "tag": "FRA", "reference": root_ref},
                "controller": {"status": "known", "tag": "FRA", "reference": root_ref},
            }

        _, scope_node = _capture_one(
            reader, module, country, loaded, guards, scope,
            task_pointer=pointers["task_a"], province_reader=province_reader,
        )
        node = scope_node["children"][0]
        assert node["condition_name"] == "province_id_matches"
        assert node["metric"] == {
            "province_id": actual_id,
            "required_province_id": required_id,
            "dynamic_selector": bool(flags & 0x4000),
        }
        if expected is None:
            assert node["evaluation"]["status"] == "unknown"
            assert "dynamic_province_id_selector_unsupported" in node["evaluation"]["reason"]
        else:
            assert node["evaluation"] == {"status": "known", "satisfied": expected}


def test_country_context_province_id_is_false_and_unbound_metric_is_null():
    reader, module, country, loaded, guards, _definitions, pointers = _fixture()
    leaf = 0xA60000
    _write_province_id(reader, module, leaf, required=42)

    _, node = _capture_one(
        reader, module, country, loaded, guards, leaf,
        task_pointer=pointers["task_a"],
    )

    assert node["condition_name"] == "province_id_matches"
    assert node["metric"] == {
        "province_id": None,
        "required_province_id": 42,
        "dynamic_selector": False,
    }
    assert node["evaluation"] == {"status": "known", "satisfied": False}


def _count_capture(ids=(42, 43), *, flags=0, required=42):
    reader, counter, child, _domain_calls, run = _count_fixture(
        ids=ids, threshold=1, body="false"
    )
    module = reader.module_base
    _write_province_id(reader, module, child, required=required, flags=flags)
    return run()


def test_count_filter_keeps_unbound_prototype_and_evaluates_id_samples():
    captured, node = _count_capture()

    assert node["filter"]["children"][0]["metric"] == {
        "province_id": None,
        "required_province_id": 42,
        "dynamic_selector": False,
    }
    assert node["filter"]["children"][0]["evaluation"]["status"] == "unknown"
    assert "count_member_context_unbound" in node["filter"]["children"][0]["evaluation"]["reason"]
    assert node["samples"] == [
        {"province_id": 42, "evaluation": {"status": "known", "satisfied": True}},
        {"province_id": 43, "evaluation": {"status": "known", "satisfied": False}},
    ]
    assert node["evaluation"] == {"status": "known", "satisfied": True}

    report = _report(captured["tasks"])
    report["mission_triggers"] = captured
    prerequisites = {
        "status": "known",
        "tasks": [
            {"root_id": row["root_id"], "task_id": row["task_id"]}
            for row in captured["tasks"]
        ],
    }
    normalized = source.normalize_triggers(report, prerequisites)
    assert normalized["status"] == "known", normalized
    state = _normalized_state(normalized["tasks"])
    projected = source.project_progress(
        state, [{"root_id": normalized["tasks"][0]["root_id"],
                 "task_id": normalized["tasks"][0]["task_id"]}], "1.37.4"
    )
    assert projected["status"] == "known", projected
    public_root = projected["value"]["tasks"][0]["trigger"]
    assert public_root["kind"] == "and"
    public_tree = public_root["children"][0]
    assert public_tree["kind"] == "count"
    assert public_tree["filter"]["children"][0]["condition_name"] == "province_id_matches"
    assert "native_pointer" not in str(public_tree)
    assert "method_rva" not in str(public_tree)


def test_dynamic_count_filter_remains_unknown_for_template_and_members():
    _captured, node = _count_capture(ids=(42,), flags=0x4000)

    leaf = node["filter"]["children"][0]
    assert leaf["metric"]["province_id"] is None
    assert leaf["metric"]["dynamic_selector"] is True
    assert leaf["evaluation"]["status"] == "unknown"
    assert "count_member_context_unbound" in leaf["evaluation"]["reason"]
    assert node["samples"][0]["evaluation"]["status"] == "unknown"
    assert node["samples"][0]["evaluation"]["satisfied"] is None
    assert node["evaluation"]["status"] == "unknown"
