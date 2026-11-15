"""Source normalization and public projection for real geographic captures."""
from __future__ import annotations

from copy import deepcopy

import pytest

from bridge.information import mission_trigger_memory as trigger
from bridge.information import mission_trigger_source as trigger_source
from bridge.tests import test_information_mission_conditional_triggers as conditional_fixtures
from bridge.tests import test_information_mission_geographic_triggers as geographic_fixtures
from bridge.tests import test_information_mission_trigger_memory as memory_fixtures
from bridge.tests import test_information_mission_trigger_source as source_fixtures


_SUPPORTED_VERSION = "1.37.4"
_PROVINCE_TRUE = {
    "status": "known",
    "owner": {"status": "known", "tag": "FRA",
              "reference": geographic_fixtures._FRA_REF},
}
_PROVINCE_FALSE = {
    "status": "known",
    "owner": {"status": "known", "tag": "ENG",
              "reference": geographic_fixtures._OTHER_REF},
}
_PROVINCE_UNKNOWN = {"status": "unknown"}


def _capture_pairs(capture: dict) -> list[tuple[str, str]]:
    return [(row["root_id"], row["task_id"]) for row in capture["tasks"]]


def _normalize_producer_rows(rows: list[dict]):
    task_ids = [row["task_id"] for row in rows]
    prerequisites = source_fixtures._prerequisites(*task_ids)
    # The shared helper uses a default root label; bind its task pairs to the
    # root IDs emitted by the real memory producer for this fixture.
    for prerequisite, producer_row in zip(prerequisites["tasks"], rows):
        prerequisite["root_id"] = producer_row["root_id"]
    report = source_fixtures._report(rows)
    normalized = trigger_source.normalize_triggers(report, prerequisites)
    return normalized, prerequisites


def _pipeline_from_capture(capture: dict):
    """Pass producer task rows directly through source and public projection."""
    assert capture["status"] == "observed"
    rows = capture["tasks"]
    pairs = _capture_pairs(capture)
    normalized, prerequisites = _normalize_producer_rows(rows)
    if normalized["status"] != "known":
        return normalized, None
    state = source_fixtures._normalized_state(normalized["tasks"])
    entries = [{"root_id": root_id, "task_id": task_id}
               for root_id, task_id in pairs]
    projected = trigger_source.project_progress(state, entries, _SUPPORTED_VERSION)
    return normalized, projected


def _capture_geo(*, province_rows=None, native_type=trigger.GEOGRAPHIC_ALL_TYPE,
                 province_ids=None, found=True):
    if province_ids is None:
        province_ids = [42, 43]
    return geographic_fixtures._capture_geographic(
        province_ids=province_ids,
        native_type=native_type,
        rows=province_rows or {},
        found=found,
    )[0]


def _find_geographic(node: dict) -> dict:
    if node.get("kind") == "geographic":
        return node
    if node.get("kind") == "if":
        for role in ("limit", "then", "else"):
            found = _find_geographic(node[role])
            if found:
                return found
    for child in node.get("children", []):
        found = _find_geographic(child)
        if found:
            return found
    return {}


def _normalize_mutated_capture(capture: dict, mutate):
    rows = deepcopy(capture["tasks"])
    mutate(rows[0]["tree"])
    normalized, _prerequisites = _normalize_producer_rows(rows)
    return normalized


@pytest.mark.parametrize(
    ("native_type", "province_rows", "expected"),
    [
        (trigger.GEOGRAPHIC_ALL_TYPE,
         {42: _PROVINCE_TRUE, 43: _PROVINCE_UNKNOWN}, None),
        (0x1234,
         {42: _PROVINCE_TRUE, 43: _PROVINCE_UNKNOWN}, True),
        (trigger.GEOGRAPHIC_ALL_TYPE,
         {42: _PROVINCE_FALSE, 43: _PROVINCE_UNKNOWN}, False),
        (0x1234,
         {42: _PROVINCE_FALSE, 43: _PROVINCE_UNKNOWN}, None),
    ],
)
def test_real_geographic_capture_normalizes_and_projects_three_state_all_any(
    native_type, province_rows, expected,
):
    capture = _capture_geo(native_type=native_type, province_rows=province_rows)

    normalized, projected = _pipeline_from_capture(capture)

    assert normalized["status"] == "known"
    assert projected["status"] == "known"
    native_geo = capture["tasks"][0]["tree"]["children"][0]
    normalized_geo = normalized["tasks"][0]["tree"]["children"][0]
    public_root = projected["value"]["tasks"][0]["trigger"]
    public_geo = public_root["children"][0]
    for node in (native_geo, normalized_geo, public_geo):
        assert node["evaluation"]["satisfied"] is expected
    assert public_geo["scope"]["quantifier"] == (
        "all" if native_type == trigger.GEOGRAPHIC_ALL_TYPE else "any"
    )
    assert [member["province_id"] for member in public_geo["members"]] == [42, 43]
    assert "native_pointer" not in str(projected["value"])
    assert "method_rva" not in str(projected["value"])
    for private_key in ("_compare", "rawreads", "raw_hex", "name_header_raw_hex"):
        assert private_key not in str(projected["value"])


def test_missing_definition_and_found_empty_set_keep_distinct_native_identities():
    missing_capture = _capture_geo(province_ids=[], found=False)
    all_empty_capture = _capture_geo(province_ids=[], found=True,
                                     native_type=trigger.GEOGRAPHIC_ALL_TYPE)
    any_empty_capture = _capture_geo(province_ids=[], found=True, native_type=0x1234)

    missing, missing_public = _pipeline_from_capture(missing_capture)
    all_empty, all_public = _pipeline_from_capture(all_empty_capture)
    any_empty, any_public = _pipeline_from_capture(any_empty_capture)

    missing_geo = missing["tasks"][0]["tree"]["children"][0]
    all_geo = all_empty["tasks"][0]["tree"]["children"][0]
    any_geo = any_empty["tasks"][0]["tree"]["children"][0]
    assert missing_geo["scope"]["definition_found"] is False
    assert missing_geo["evaluation"]["satisfied"] is False
    assert missing_geo["members"] == []
    assert all_geo["evaluation"]["satisfied"] is True
    assert any_geo["evaluation"]["satisfied"] is False
    assert missing_public["value"]["tasks"][0]["trigger"]["children"][0]["evaluation"]["satisfied"] is False
    assert all_public["value"]["tasks"][0]["trigger"]["children"][0]["evaluation"]["satisfied"] is True
    assert any_public["value"]["tasks"][0]["trigger"]["children"][0]["evaluation"]["satisfied"] is False


@pytest.mark.parametrize("corruption", [
    "missing_members", "malformed_member", "duplicate_member", "over_cap", "forged_truth",
])
def test_normalizer_rejects_malformed_or_forged_geographic_members(corruption):
    capture = _capture_geo(province_rows={42: _PROVINCE_TRUE})

    def mutate(root):
        geo = root["children"][0]
        if corruption == "missing_members":
            del geo["members"]
        elif corruption == "malformed_member":
            geo["members"][0] = {"province_id": 42}
        elif corruption == "duplicate_member":
            geo["members"].append(deepcopy(geo["members"][0]))
        elif corruption == "over_cap":
            member = deepcopy(geo["members"][0])
            geo["members"] = [deepcopy(member) for _ in range(65)]
            for index, row in enumerate(geo["members"], 1):
                row["province_id"] = index
        else:
            geo["evaluation"] = {"status": "known", "satisfied": False}

    normalized = _normalize_mutated_capture(capture, mutate)

    assert normalized["status"] == "unknown"
    assert normalized["reason"] == "MISSION_TRIGGER_TREE_INVALID"


def test_inlined_geographic_and_method_is_rejected_outside_member_body():
    capture = _capture_geo(province_rows={42: _PROVINCE_TRUE}, province_ids=[42])
    producer_row = capture["tasks"][0]
    invalid_tree = deepcopy(producer_row["tree"])
    geo = invalid_tree["children"][0]
    inlined_body = deepcopy(geo["members"][0]["tree"])
    assert inlined_body["kind"] == "and"
    assert inlined_body["method_rva"] == trigger.GEOGRAPHIC_EVALUATE_RVA
    invalid_tree["children"].append(inlined_body)
    forged_row = source_fixtures._task(
        task_id=producer_row["task_id"], root_id=producer_row["root_id"],
        tree=invalid_tree,
    )

    normalized, _prerequisites = _normalize_producer_rows([forged_row])

    assert normalized["status"] == "unknown"
    assert normalized["reason"] == "MISSION_TRIGGER_TREE_INVALID"


@pytest.mark.parametrize(
    ("token", "expected_status"),
    [
        (0xFFFFFFFF, "known"),
        (-1, "unknown"),
        (0x1_0000_0000, "unknown"),
        (True, "unknown"),
    ],
)
def test_geographic_tokens_use_strict_uint32_range(token, expected_status):
    capture = _capture_geo(province_rows={42: _PROVINCE_TRUE}, province_ids=[42])
    rows = deepcopy(capture["tasks"])
    rows[0]["tree"]["children"][0]["token"] = token

    normalized, _prerequisites = _normalize_producer_rows(rows)

    assert normalized["status"] == expected_status
    if expected_status == "known":
        assert normalized["tasks"][0]["tree"]["children"][0]["token"] == 0xFFFFFFFF
    else:
        assert normalized["reason"] == "MISSION_TRIGGER_TREE_INVALID"


def _foreign_scalar_capture():
    reader, module, country, loaded, guards, _definitions, pointers = (
        geographic_fixtures._fixture()
    )
    reader.qword_put(country + 0x20, geographic_fixtures._FRA_REF)
    scope, reference, leaf = 0xA20000, 0xA30000, 0xA40000
    fullref = geographic_fixtures._write_country_scope_reference(reader, reference, "ENG")
    geographic_fixtures._write_scope(reader, module, scope, reference, [leaf])
    memory_fixtures._write_leaf(
        reader, module, leaf, "sailors", trigger.SAILORS_TOKEN, 1000,
    )
    memory_fixtures._install_root(reader, module, pointers["task_a"], [scope])
    state_calls: list[tuple[int, str]] = []

    def country_state_reader(_reader, _module_base, pointer, kind):
        state_calls.append((pointer, kind))
        return {"status": "known", "raw_fixed_milli": 1000}

    bindings = {
        fullref: {"status": "known", "tag": "ENG", "pointer": 0x510000,
                  "fullref": fullref},
    }
    capture = trigger.capture_triggers(
        reader, module, country, loaded, code_guards=guards,
        country_state_reader=country_state_reader,
        country_scope_reader=geographic_fixtures._country_scope_reader(bindings, []),
    )
    return capture, state_calls


def test_foreign_known_private_scalar_is_rejected_but_memory_unknown_is_accepted():
    capture, state_calls = _foreign_scalar_capture()
    producer_scope = capture["tasks"][0]["tree"]["children"][0]
    producer_leaf = producer_scope["children"][0]
    assert capture["status"] == "observed"
    assert producer_scope["scope"]["country"] == "ENG"
    assert producer_leaf["evaluation"]["status"] == "unknown"
    assert producer_leaf["evaluation"]["reason"] == "foreign_country_scalar_unsupported"
    assert state_calls == []

    normalized, projected = _pipeline_from_capture(capture)
    assert normalized["status"] == projected["status"] == "known"
    public_scope = projected["value"]["tasks"][0]["trigger"]["children"][0]
    assert public_scope["scope"] == {"kind": "country", "country": "ENG", "selection": "literal"}
    assert public_scope["children"][0]["evaluation"]["status"] == "unknown"

    forged_rows = deepcopy(capture["tasks"])
    forged_leaf = forged_rows[0]["tree"]["children"][0]["children"][0]
    forged_leaf["evaluation"] = {"status": "known", "satisfied": False}
    forged, _prerequisites = _normalize_producer_rows(forged_rows)
    assert forged["status"] == "unknown"
    assert forged["reason"] == "MISSION_TRIGGER_TREE_INVALID"


def test_if_country_scope_geography_keeps_loaded_root_and_public_bindings():
    reader, module, country, loaded, guards, _definitions, pointers = (
        geographic_fixtures._fixture()
    )
    reader.qword_put(country + 0x20, geographic_fixtures._FRA_REF)
    if_node, country_scope, country_ref = 0xA20000, 0xA21000, 0xA30000
    geo_node, owned_leaf, root_sailors = 0xA40000, 0xA50000, 0xA60000
    fullref = geographic_fixtures._write_country_scope_reference(
        reader, country_ref, "ENG",
    )
    geographic_fixtures._write_province_leaf(reader, module, owned_leaf, "owned")
    geographic_fixtures._write_geographic(
        reader, module, geo_node, [owned_leaf], "test_area",
    )
    geographic_fixtures._write_scope(
        reader, module, country_scope, country_ref, [geo_node],
    )
    conditional_fixtures._write_if(
        reader, module, if_node, limit_children=[], then_children=[country_scope],
        else_children=[],
    )
    memory_fixtures._write_leaf(
        reader, module, root_sailors, "sailors", trigger.SAILORS_TOKEN, 1000,
    )
    reader.dword_put(country + trigger.SAILORS_CURRENT_OFFSET, 1, signed=True)
    reader.dword_put(country + trigger.SAILORS_MAX_OFFSET, 1, signed=True)
    memory_fixtures._install_root(
        reader, module, pointers["task_a"], [if_node, root_sailors],
    )

    province_calls: list[int] = []
    definition_calls: list[str] = []
    binding_calls: list[int] = []
    bindings = {
        fullref: {"status": "known", "tag": "ENG", "pointer": 0x510000,
                  "fullref": fullref},
    }
    capture = trigger.capture_triggers(
        reader, module, country, loaded, code_guards=guards,
        province_reader=geographic_fixtures._province_reader(
            country, geographic_fixtures._FRA_REF, {}, province_calls,
        ),
        geographic_reader=geographic_fixtures._geographic_reader(
            {"test_area": geographic_fixtures._known_definition([42])},
            definition_calls,
        ),
        country_scope_reader=geographic_fixtures._country_scope_reader(
            bindings, binding_calls,
        ),
    )

    normalized, projected = _pipeline_from_capture(capture)

    assert normalized["status"] == projected["status"] == "known"
    assert _capture_pairs(capture) == [("root", "task_a")]
    assert province_calls == [42]
    assert definition_calls == ["test_area"]
    assert binding_calls == [fullref]
    public_root = projected["value"]["tasks"][0]["trigger"]
    public_if = public_root["children"][0]
    public_scope = public_if["then"]["children"][0]
    public_geo = public_scope["children"][0]
    assert public_if["selected_branch"] == "then"
    assert public_scope["scope"]["country"] == "ENG"
    assert public_geo["scope"]["name"] == "test_area"
    assert public_geo["members"][0]["province_id"] == 42
    # This member predicate uses the immutable FRA ROOT even inside ENG scope.
    assert public_geo["members"][0]["tree"]["children"][0]["evaluation"]["satisfied"] is True
    assert public_root["children"][1]["evaluation"]["satisfied"] is True
    public_json = str(projected["value"])
    for private_key in ("native_pointer", "method_rva", "rawreads", "raw_hex", "_compare"):
        assert private_key not in public_json
    assert "country" in public_json and "ENG" in public_json
