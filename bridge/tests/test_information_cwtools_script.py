"""Offline contract tests for the injected, syntax-only CWTools adapter."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from bridge.information import cwtools_script
from bridge.information.mission_definitions import MissionDefinitionIndex


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _fixture_root(tmp_path: Path, monkeypatch) -> tuple[Path, Path, Path]:
    root = tmp_path / "repo"
    (root / "tools").mkdir(parents=True)
    executable = root / "tools" / "dotnet.exe"
    library = root / "tools" / "CWTools.Parser.dll"
    executable.write_bytes(b"fake executable pin")
    library.write_bytes(b"fake parser pin")
    manifest = root / "adapter-manifest.json"
    rows = []
    for path in (executable, library):
        raw = path.read_bytes()
        rows.append({"path": path.relative_to(root).as_posix(),
                     "bytes": len(raw), "sha256": _sha(raw)})
    manifest.write_text(json.dumps({
        "schema": "eu4.cwtools.parser.v1",
        "package": {"id": "CWTools", "version": cwtools_script.PACKAGE_VERSION},
        "license": "MIT",
        "files": rows,
        "command": ["tools/dotnet.exe", "tools/CWTools.Parser.dll"],
    }), encoding="utf-8")
    monkeypatch.setattr(cwtools_script, "ROOT", root)
    return root, manifest, library


def _row(path: Path, *, items=None, encoding="utf-8-sig", parse_ok=True, errors=None,
         override=None) -> dict:
    raw = path.read_bytes()
    result = {
        "path": str(path.resolve()),
        "sha256": _sha(raw),
        "bytes": len(raw),
        "encoding": encoding,
        "parse_ok": parse_ok,
        "items": list(items or []),
        "errors": list(errors or []),
    }
    if override:
        result.update(override)
    return result


def _document(rows: list[dict]) -> dict:
    return {"schema": cwtools_script.SCHEMA,
            "parser": {"name": "CWTools", "version": cwtools_script.PACKAGE_VERSION},
            "files": rows}


def _scalar(key: str, value, line: int, operator="=", value_kind="string") -> dict:
    return {"key": key, "statement_kind": "key_value", "operator": operator,
            "value_kind": value_kind, "value": value, "source_line": line,
            "end_line": line, "source_column": 2, "end_column": 12,
            "children": [], "raw_key": key, "raw_value": str(value)}


def test_runner_ast_preserves_order_repeats_operators_bare_nodes_and_comments(tmp_path, monkeypatch):
    _root, manifest, _library = _fixture_root(tmp_path, monkeypatch)
    source = tmp_path / "sample.txt"
    source.write_bytes(b"\xef\xbb\xbftrigger = {\n  owns = 183\n}\n")
    quoted_owns = _scalar("owns", 183, 2, value_kind="integer")
    quoted_owns["raw_key"] = '"owns"'
    ast = [{
        "key": "trigger", "statement_kind": "key_value", "operator": "=",
        "value_kind": "block", "value": None, "source_line": 1, "end_line": 8,
        "source_column": 0, "end_column": 1, "children": [
            quoted_owns,
            _scalar("owns", 186, 3, value_kind="integer"),
            _scalar("stability", 1, 4, ">=", value_kind="integer"),
            {"key": None, "statement_kind": "bare_value", "operator": None,
             "value_kind": "string", "value": "add_claim", "source_line": 5,
             "end_line": 5, "source_column": 2, "end_column": 11,
             "children": [], "raw_key": None, "raw_value": "add_claim"},
            {"statement_kind": "comment", "value_kind": "comment"},
        ],
        "raw_key": "trigger", "raw_value": "{",
    }]
    seen = []

    def runner(command):
        seen.append(command)
        assert command[:2] == [str(_root / "tools/dotnet.exe"), str(_root / "tools/CWTools.Parser.dll")]
        return _document([_row(Path(command[2]), items=ast)])

    parser = cwtools_script.CwtoolsScriptParser(manifest, runner=runner)
    result = parser.parse_files([source])[str(source.resolve())]
    trigger = result["nodes"][0]
    assert [child.key for child in trigger.children] == ["owns", "owns", "stability", "add_claim"]
    assert [child.value for child in trigger.children] == ["183", "186", "1", None]
    assert [child.assignment for child in trigger.children] == ["=", "=", ">=", None]
    assert trigger.children[0].raw_key == '"owns"'
    assert trigger.children[3].kind == "bare"
    assert trigger.children[3].key == "add_claim"
    assert trigger.children[0].source_column == 2
    assert result["text"].startswith("trigger")  # utf-8-sig strips the BOM
    assert result["parser"]["semantics"] == "syntax_only"
    assert result["parser"]["conditions_evaluated"] is False
    assert result["parser"]["effects_executed"] is False
    assert len(seen) == 1


def test_windows_1252_text_and_parse_diagnostics_are_explicit(tmp_path, monkeypatch):
    _root, manifest, _library = _fixture_root(tmp_path, monkeypatch)
    source = tmp_path / "legacy.txt"
    source.write_bytes('name = "café"\n'.encode("cp1252"))
    calls = []

    def runner(command):
        calls.append(command)
        return _document([_row(Path(command[2]), encoding="windows-1252",
                               items=[_scalar("name", "café", 1)])])

    parser = cwtools_script.CwtoolsScriptParser(manifest, runner=runner)
    parsed = parser.parse_files([source])[str(source.resolve())]
    assert parsed["text"] == 'name = "café"\n'
    assert parsed["encoding"] == {"name": "windows-1252", "structural_only": False}
    assert parsed["nodes"][0].value == "café"

    def failed_runner(command):
        calls.append(command)
        return _document([_row(Path(command[2]), parse_ok=False,
                               errors=[{"code": "syntax_error", "line": 1}])])

    failed = cwtools_script.CwtoolsScriptParser(manifest, runner=failed_runner)
    value = failed.parse_files([source])[str(source.resolve())]
    assert value == {"error": "CWTOOLS_SCRIPT_PARSE_FAILED",
                     "diagnostics": [{"code": "syntax_error", "line": 1}]}
    assert len(calls) == 2  # no local-parser fallback is attempted


def test_windows_1252_undefined_slots_preserve_c1_and_neighboring_bytes(tmp_path, monkeypatch):
    _root, manifest, _library = _fixture_root(tmp_path, monkeypatch)
    source = tmp_path / "c1-slots.txt"
    source.write_bytes(b"value = \"\x80\x8d\xe9\"\n")
    parser = cwtools_script.CwtoolsScriptParser(
        manifest,
        runner=lambda command: _document([_row(Path(command[2]), encoding="windows-1252", items=[])]),
    )

    result = parser.parse_files([source])[str(source.resolve())]
    assert result["text"] == 'value = "€\x8dé"\n'
    assert [ord(char) for char in result["text"][9:12]] == [0x20AC, 0x008D, 0x00E9]
    assert result["encoding"] == {
        "name": "windows-1252", "structural_only": True,
        "c1_byte_slots_preserved": ["8d"],
    }


def test_real_cli_utf8_bom_encoding_label_is_accepted_and_stripped(tmp_path, monkeypatch):
    _root, manifest, _library = _fixture_root(tmp_path, monkeypatch)
    source = tmp_path / "utf8-bom.txt"
    source.write_bytes('\ufeffname = "café"\n'.encode("utf-8"))
    parser = cwtools_script.CwtoolsScriptParser(
        manifest,
        runner=lambda command: _document([_row(Path(command[2]), encoding="utf-8-bom",
                                                items=[_scalar("name", "café", 1)])]),
    )

    result = parser.parse_files([source])[str(source.resolve())]
    assert result["text"] == 'name = "café"\n'
    assert result["encoding"] == {"name": "utf-8-bom", "structural_only": False}
    assert result["nodes"][0].value == "café"


def test_empty_script_is_a_valid_zero_byte_input(tmp_path, monkeypatch):
    _root, manifest, _library = _fixture_root(tmp_path, monkeypatch)
    source = tmp_path / "empty.txt"
    source.write_bytes(b"")
    parser = cwtools_script.CwtoolsScriptParser(
        manifest, runner=lambda command: _document([_row(Path(command[2]), items=[])]))
    result = parser.parse_files([source])[str(source.resolve())]
    assert result["nodes"] == []
    assert result["text"] == ""
    assert cwtools_script._input_pin(source)["sha256"] == _sha(b"")


def test_adjacent_bare_name_and_bare_block_merge_without_losing_children(tmp_path, monkeypatch):
    _root, manifest, _library = _fixture_root(tmp_path, monkeypatch)
    source = tmp_path / "mission.txt"
    source.write_text("create_general_with_pips { tradition = 25 add_shock = 3 }", encoding="utf-8")
    ast = [
        {"key": None, "statement_kind": "bare_value", "operator": None,
         "value_kind": "string", "value": "create_general_with_pips",
         "source_line": 1, "end_line": 1, "source_column": 0, "end_column": 24,
         "children": [], "raw_key": "create_general_with_pips", "raw_value": None},
        {"key": None, "statement_kind": "bare_value", "operator": None,
         "value_kind": "block", "value": None,
         "source_line": 1, "end_line": 1, "source_column": 25, "end_column": 61,
         "children": [
             _scalar("tradition", 25, 1, value_kind="integer"),
             _scalar("add_shock", 3.0, 1, value_kind="decimal"),
         ], "raw_key": None, "raw_value": "{"},
    ]
    parser = cwtools_script.CwtoolsScriptParser(
        manifest, runner=lambda command: _document([_row(Path(command[2]), items=ast)]))
    nodes = parser.parse_files([source])[str(source.resolve())]["nodes"]
    assert len(nodes) == 1
    assert (nodes[0].key, nodes[0].kind, nodes[0].assignment) == (
        "create_general_with_pips", "block", None,
    )
    assert nodes[0].cwtools_normalization == "adjacent_bare_name_and_clause"
    assert [(child.key, child.value) for child in nodes[0].children] == [
        ("tradition", "25"), ("add_shock", "3.0"),
    ]
    assert nodes[0].raw_value == "{"
    assert nodes[0].end_line == 1
    assert nodes[0].end_column == 61


def test_bare_block_source_column_must_be_a_nonnegative_integer(tmp_path, monkeypatch):
    _root, manifest, _library = _fixture_root(tmp_path, monkeypatch)
    source = tmp_path / "bad-column.txt"
    source.write_text("create_general_with_pips { tradition = 25 }", encoding="utf-8")
    ast = [
        {"key": None, "statement_kind": "bare_value", "operator": None,
         "value_kind": "string", "value": "create_general_with_pips",
         "source_line": 1, "end_line": 1, "source_column": 0, "end_column": 24,
         "children": [], "raw_key": "create_general_with_pips", "raw_value": None},
        {"key": None, "statement_kind": "bare_value", "operator": None,
         "value_kind": "block", "value": None,
         "source_line": 1, "end_line": 1, "source_column": -1, "end_column": 44,
         "children": [_scalar("tradition", 25, 1, value_kind="integer")]},
    ]
    parser = cwtools_script.CwtoolsScriptParser(
        manifest, runner=lambda command: _document([_row(Path(command[2]), items=ast)]))
    with pytest.raises(ValueError, match="CWTOOLS_AST_COLUMN"):
        parser.parse_files([source])


def test_mission_index_does_not_fallback_when_injected_parser_reports_failure(tmp_path):
    game = tmp_path / "game"
    (game / "missions").mkdir(parents=True)
    (game / "launcher-settings.json").write_text(
        json.dumps({"rawVersion": "1.37.4"}), encoding="utf-8")
    mission_file = game / "missions" / "example.txt"
    mission_file.write_text(
        "root = { slot = 1 task = { trigger = { owns = 42 } } }", encoding="utf-8")

    class FailedParser:
        def __init__(self):
            self.calls = 0

        def parse_files(self, paths):
            self.calls += 1
            path = str(Path(paths[0]).resolve())
            return {path: {"error": "CWTOOLS_SCRIPT_PARSE_FAILED", "diagnostics": []}}

        def context(self):
            return {"status": "ready", "name": "CWTools", "version": cwtools_script.PACKAGE_VERSION}

    parser = FailedParser()
    index = MissionDefinitionIndex(game_root=game, enabled_mods=[], script_parser=parser)
    context = index.context()
    assert parser.calls == 1
    assert context["status"] == "unready"
    assert context["root_count"] == 0
    assert any(row["code"] == "MISSION_DEFINITION_PARSE_FAILED" for row in context["reasons"])


@pytest.mark.parametrize("override", [
    {"sha256": "0" * 64},
    {"path": "other.txt"},
])
def test_runner_file_hash_and_path_must_match_the_selected_input(tmp_path, monkeypatch, override):
    _root, manifest, _library = _fixture_root(tmp_path, monkeypatch)
    source = tmp_path / "selected.txt"
    source.write_text("owns = 4", encoding="utf-8")
    parser = cwtools_script.CwtoolsScriptParser(
        manifest,
        runner=lambda command: _document([_row(Path(command[2]), override=override)]),
    )
    with pytest.raises(ValueError, match="CWTOOLS_FILE_RESULT_INVALID"):
        parser.parse_files([source])


def test_output_schema_and_duplicate_inputs_fail_closed(tmp_path, monkeypatch):
    _root, manifest, _library = _fixture_root(tmp_path, monkeypatch)
    source = tmp_path / "one.txt"
    source.write_text("x = y", encoding="utf-8")
    parser = cwtools_script.CwtoolsScriptParser(
        manifest,
        runner=lambda command: {**_document([_row(Path(command[2]))]), "schema": "wrong"},
    )
    with pytest.raises(ValueError, match="CWTOOLS_DUPLICATE_INPUT"):
        parser.parse_files([source, source])
    with pytest.raises(ValueError, match="CWTOOLS_OUTPUT_SCHEMA_INVALID"):
        parser.parse_files([source])


@pytest.mark.parametrize("bad_node,reason", [
    ({"key": None, "statement_kind": "bare_value", "value_kind": "block",
      "value": None, "operator": None, "source_line": 1, "end_line": 1,
      "source_column": 0, "end_column": 1, "children": []}, "CWTOOLS_UNBOUND_BARE_CLAUSE"),
    ({"key": "n", "statement_kind": "key_value", "value_kind": "string",
      "value": "yes", "operator": "=", "source_line": 1, "end_line": 1,
      "source_column": -1, "end_column": 1, "children": []}, "CWTOOLS_AST_COLUMN"),
    ({"key": "n", "statement_kind": "key_value", "value_kind": "integer",
      "value": True, "operator": "=", "source_line": 1, "end_line": 1,
      "source_column": 0, "end_column": 1, "children": []}, "CWTOOLS_AST_SCALAR_TYPE"),
])
def test_malformed_statement_kinds_columns_and_json_scalar_types_fail_closed(
        tmp_path, monkeypatch, bad_node, reason):
    _root, manifest, _library = _fixture_root(tmp_path, monkeypatch)
    source = tmp_path / "malformed.txt"
    source.write_text("x = 1", encoding="utf-8")
    parser = cwtools_script.CwtoolsScriptParser(
        manifest, runner=lambda command: _document([_row(Path(command[2]), items=[bad_node])]))
    with pytest.raises(ValueError, match=reason):
        parser.parse_files([source])


def test_input_and_pinned_parser_changes_during_call_are_detected(tmp_path, monkeypatch):
    _root, manifest, library = _fixture_root(tmp_path, monkeypatch)
    source = tmp_path / "selected.txt"
    source.write_text("owns = 7", encoding="utf-8")

    def mutate_input(command):
        path = Path(command[2])
        row = _row(path)
        path.write_text("owns = 8", encoding="utf-8")
        return _document([row])

    parser = cwtools_script.CwtoolsScriptParser(manifest, runner=mutate_input)
    with pytest.raises(ValueError, match="CWTOOLS_INPUT_CHANGED"):
        parser.parse_files([source])

    def mutate_parser(command):
        row = _row(Path(command[2]))
        library.write_bytes(b"changed pinned parser")
        return _document([row])

    parser2 = cwtools_script.CwtoolsScriptParser(manifest, runner=mutate_parser)
    with pytest.raises(ValueError, match="CWTOOLS_PARSER_CHANGED"):
        parser2.parse_files([source])
    assert parser2.context()["status"] == "unready"


@pytest.mark.parametrize('declared_limit,file_count,expected_batches', [
    (None, 17, [16, 1]),
    (64, 65, [64, 1]),
])
def test_file_count_and_batch_byte_limits_split_without_losing_input_order(
        tmp_path, monkeypatch, declared_limit, file_count, expected_batches):
    _root, manifest, _library = _fixture_root(tmp_path, monkeypatch)
    if declared_limit is not None:
        document = json.loads(manifest.read_text(encoding='utf-8'))
        document['max_batch_files'] = declared_limit
        manifest.write_text(json.dumps(document), encoding='utf-8')
    tiny = [tmp_path / f"mission-{index:02d}.txt" for index in range(file_count)]
    for path in tiny:
        path.write_text("x = y", encoding="utf-8")
    batch_sizes = []

    def runner(command):
        paths = command[2:]
        batch_sizes.append(len(paths))
        return _document([_row(Path(path)) for path in paths])

    parser = cwtools_script.CwtoolsScriptParser(manifest, runner=runner)
    result = parser.parse_files(tiny)
    assert batch_sizes == expected_batches
    assert list(result) == [str(path.resolve()) for path in tiny]

    byte_batch = [tmp_path / "large-a.txt", tmp_path / "large-b.txt"]
    for path in byte_batch:
        path.write_bytes(b"x" * (2 * 1024 * 1024 + 1))
    batch_sizes.clear()
    parser.parse_files(byte_batch)
    assert batch_sizes == [1, 1]


@pytest.mark.parametrize('limit', [0, True, 65])
def test_manifest_batch_limit_must_fit_supported_range(tmp_path, monkeypatch, limit):
    _root, manifest, _library = _fixture_root(tmp_path, monkeypatch)
    document = json.loads(manifest.read_text(encoding='utf-8'))
    document['max_batch_files'] = limit
    manifest.write_text(json.dumps(document), encoding='utf-8')
    with pytest.raises(ValueError, match='CWTOOLS_MANIFEST_BATCH_SIZE_INVALID'):
        cwtools_script.CwtoolsScriptParser(manifest)
