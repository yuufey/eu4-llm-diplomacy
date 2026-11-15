from __future__ import annotations

from copy import deepcopy

import pytest

import bridge.information.religion_values as religion_values
from bridge.information.religion_values import faith_value, identity_value, rule_value


def _pins():
    return {
        "configuration_sha256": "1" * 64,
        "definitions_sha256": "2" * 64,
        "parser_manifest_sha256": "3" * 64,
        "cwt_sha256": "4" * 64,
        "cwt_commit": "a" * 40,
    }


def _node(key="catholic", *, kind="block", assignment="=", value=None,
          children=None, line=3, end_line=None):
    return {
        "key": key,
        "assignment": assignment,
        "kind": kind,
        "value": value,
        "children": list(children or []),
        "line": line,
        "end_line": line if end_line is None else end_line,
        "source_column": 0,
        "end_column": len(key),
    }


def _record(*, key="catholic", group_key="christian", group=False):
    pins = _pins()
    record = {
        "status": "known",
        "definition": {
            "relative_file": "common/religions/00_religions.txt",
            "line": 2,
            "file_sha256": "5" * 64,
            "source_kind": "basegame",
        },
        "source": deepcopy(pins),
        "source_pins": deepcopy(pins),
        "syntax": _node(key=group_key if group else key, children=[
            _node("icon", kind="scalar", value="catholic_icon", line=4),
        ]),
        "conditions_evaluated": False,
        "effects_executed": False,
        "runtime_state_observed": False,
    }
    if group:
        record["religion_group_key"] = group_key
    else:
        record["religion_key"] = key
        record["religion_group_key"] = group_key
    return record


def test_identity_value_requires_exact_ascii_keys_and_returns_copy():
    original = {"religion_key": "catholic", "religion_group_key": "christian"}
    result = identity_value(original)
    assert result == original
    assert result is not original
    result["religion_key"] = "mutated"
    assert original["religion_key"] == "catholic"

    for value in (
        {**original, "pointer": "0x12345678"},
        {"religion_key": "café", "religion_group_key": "christian"},
        {"religion_key": "bad\x00key", "religion_group_key": "christian"},
        {"religion_key": "catholic"},
    ):
        with pytest.raises(ValueError):
            identity_value(value)


def test_faith_value_checks_native_escape_bytes_and_copies_clean_value():
    original = {
        "primary_religion_name": {
            "text": "Catholic", "raw_hex": "436174686f6c6963", "encoding": "eu4_escape",
        },
        "icon_frame_request": 0,
    }
    result = faith_value(original)
    assert result == original
    assert result is not original
    result["primary_religion_name"]["text"] = "mutated"
    assert original["primary_religion_name"]["text"] == "Catholic"

    cases = [
        {**original, "private_path": "C:\\private\\file"},
        {**original, "icon_frame_request": True},
        {**original, "icon_frame_request": 1 << 32},
        {**original, "primary_religion_name": {
            "text": "Different", "raw_hex": "436174686f6c6963", "encoding": "eu4_escape",
        }},
        {**original, "primary_religion_name": {
            "text": "A", "raw_hex": "4100", "encoding": "eu4_escape",
        }},
        {**original, "primary_religion_name": {
            "text": "A", "raw_hex": "10", "encoding": "eu4_escape",
        }},
        {**original, "primary_religion_name": {
            "text": "A", "raw_hex": "41", "encoding": "utf8",
        }},
    ]
    for value in cases:
        with pytest.raises(ValueError):
            faith_value(value)


def test_rule_value_projects_safe_static_religion_and_group_dtos():
    source = _record()
    result = rule_value(source, "catholic")
    assert set(result) == {"status", "syntax", "definition", "source_pins", "static_semantics"}
    assert result["status"] == "known"
    assert result["syntax"]["key"] == "catholic"
    assert result["definition"] == source["definition"]
    assert result["source_pins"] == _pins()
    assert result["static_semantics"] == {
        "conditions_evaluated": False,
        "effects_executed": False,
        "runtime_state_observed": False,
    }
    result["syntax"]["children"][0]["value"] = "mutated"
    assert source["syntax"]["children"][0]["value"] == "catholic_icon"

    group_record = _record(group=True)
    group_result = rule_value(group_record, "christian", group=True)
    assert group_result["status"] == "known"
    assert group_result["syntax"]["key"] == "christian"
    assert "religion_group_key" not in group_result


def test_rule_value_sanitizes_unknown_and_rejects_key_or_private_field_mismatch():
    assert rule_value({"status": "unknown", "pointer": "0x12345678"}, "catholic") == {
        "status": "unknown", "reason": "RELIGION_RULES_UNAVAILABLE",
    }
    mismatched = _record()
    with pytest.raises(ValueError):
        rule_value(mismatched, "Catholic")
    with_private_key = _record()
    with_private_key["address"] = "0x12345678"
    with pytest.raises(ValueError):
        rule_value(with_private_key, "catholic")
    with_group_key = _record(group=True)
    with pytest.raises(ValueError):
        rule_value(with_group_key, "CHRISTIAN", group=True)


@pytest.mark.parametrize("mutation", [
    lambda node: node.update(private_path="C:\\secret\\file"),
    lambda node: node.update(assignment="invalid"),
    lambda node: node.update(value="not-a-block-value"),
    lambda node: node.update(end_line=1),
    lambda node: node.update(source_column=True),
    lambda node: node.update(key="C:\\secret\\file"),
    lambda node: node.update(value="0x12345678"),
])
def test_rule_value_rejects_private_or_malformed_ast(mutation):
    record = _record()
    mutation(record["syntax"])
    with pytest.raises(ValueError):
        rule_value(record, "catholic")


def test_rule_value_rejects_bad_definition_paths_pins_and_semantics():
    invalid_paths = [
        "C:/private/religions.txt",
        "/private/religions.txt",
        "common/religions/../secret.txt",
        "common\\religions\\secret.txt",
    ]
    for path in invalid_paths:
        record = _record()
        record["definition"]["relative_file"] = path
        with pytest.raises(ValueError):
            rule_value(record, "catholic")

    bad_pins = _record()
    bad_pins["source_pins"]["configuration_sha256"] = "z" * 64
    with pytest.raises(ValueError):
        rule_value(bad_pins, "catholic")

    bad_source = _record()
    bad_source["source"]["definitions_sha256"] = "6" * 64
    with pytest.raises(ValueError):
        rule_value(bad_source, "catholic")

    executed = _record()
    executed["effects_executed"] = True
    with pytest.raises(ValueError):
        rule_value(executed, "catholic")


def test_rule_value_enforces_ast_depth_node_and_byte_limits(monkeypatch):
    record = _record()
    monkeypatch.setattr(religion_values, "MAX_RULE_AST_NODES", 1)
    with pytest.raises(ValueError, match="RELIGION_RULE_AST_LIMIT"):
        rule_value(record, "catholic")

    monkeypatch.setattr(religion_values, "MAX_RULE_AST_NODES", 32768)
    monkeypatch.setattr(religion_values, "MAX_RULE_AST_DEPTH", 0)
    with pytest.raises(ValueError, match="RELIGION_RULE_AST_LIMIT"):
        rule_value(record, "catholic")

    monkeypatch.setattr(religion_values, "MAX_RULE_AST_DEPTH", 64)
    monkeypatch.setattr(religion_values, "MAX_RULE_AST_JSON_BYTES", 128)
    with pytest.raises(ValueError, match="RELIGION_RULE_AST_BYTE_LIMIT"):
        rule_value(record, "catholic")
