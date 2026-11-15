"""Factory isolation and composition tests for static HRE reform definitions."""
from __future__ import annotations

import builtins
import importlib

import pytest

from tools.serve_information import _build_runtime, build_parser


def _definition():
    return [{
        "reform_id": "fixture_reform",
        "empire": "hre",
        "relative_file": "common/imperial_reforms/00_factory_fixture.txt",
        "line": 2,
        "declarations": [{
            "key": "potential", "assignment": "=", "kind": "block", "value": None,
            "children": [{"key": "owns", "assignment": "=", "kind": "scalar",
                          "value": "183", "children": [], "line": 3, "column": 0}],
            "line": 2, "column": 0,
        }],
    }]


class _FakeDefinitionIndex:
    instances = []

    def __init__(self, game_root=None, user_data=None, *, parser_manifest=None):
        self.game_root = game_root
        self.user_data = user_data
        self.parser_manifest = parser_manifest
        self.calls = []
        self.instances.append(self)

    def context(self):
        self.calls.append("context")
        return {
            "status": "ready", "complete": True, "game_version": "1.37.4",
            "configuration_sha256": "a" * 64, "definitions_sha256": "b" * 64,
            "script_parser": {"name": "CWTools", "version": "0.6.0-alpha"}, "reasons": [],
        }

    def definitions(self, empire="hre"):
        self.calls.append(("definitions", empire))
        return _definition()


def _patch_index_class(monkeypatch, index_class=_FakeDefinitionIndex):
    module_name = "bridge.information.imperial_reform_definitions"
    definitions_module = importlib.import_module(module_name)
    monkeypatch.setattr(definitions_module, "ImperialReformDefinitionIndex", index_class)


def _args(tmp_path, *options):
    return build_parser().parse_args([
        "--database", str(tmp_path / "information.sqlite3"), *map(str, options),
    ])


def _close(service, journal):
    service.close()
    if journal is not None:
        journal.close()


def test_flag_constructs_only_static_reform_owner_and_preserves_full_catalog(tmp_path, monkeypatch):
    _FakeDefinitionIndex.instances.clear()
    _patch_index_class(monkeypatch)
    default_service, default_journal = _build_runtime(_args(tmp_path, '--observer', 'FRA'))
    try:
        expected_fields = {topic['topic_id']: set(topic['fields'])
                           for topic in default_service.source.catalog()}
    finally:
        _close(default_service, default_journal)
    game_root = tmp_path / "game"
    user_data = tmp_path / "user"
    parser_manifest = tmp_path / "cwtools-manifest.json"
    args = _args(tmp_path, "--observer", "FRA", "--empire-game-data",
                 "--empire-rules-parser-manifest", parser_manifest,
                 "--static-game-root", game_root, "--static-user-data", user_data)

    service, journal = _build_runtime(args)
    try:
        assert journal is None
        assert len(_FakeDefinitionIndex.instances) == 1
        index = _FakeDefinitionIndex.instances[0]
        assert index.game_root == game_root
        assert index.user_data == user_data
        assert index.parser_manifest == parser_manifest

        adapters = service.source.adapters
        live = next(adapter for adapter in adapters if type(adapter).__name__ == "NativeEmpireSource")
        rules = next(adapter for adapter in adapters
                     if type(adapter).__name__ == "StaticImperialReformRulesSource")
        assert not any(type(adapter).__name__ == "NativeEmpirePassedReformsSource"
                       for adapter in adapters)
        assert rules.base_source is live.base_source
        assert rules.index is index

        topics = service.source.catalog()
        assert len(topics) == 74
        assert {topic['topic_id']: set(topic['fields']) for topic in topics} == expected_fields
        s01 = next(topic for topic in topics if topic["topic_id"] == "S01")
        assert {name: s01["fields"][name]["coverage"]
                for name in ("emperor", "electors", "reforms")} == {
                    "emperor": "partial", "electors": "partial", "reforms": "partial",
                }
        reform_metadata = s01["fields"]["reforms"]
        assert reform_metadata["unit"] == "imperial_reform_definition"
        assert reform_metadata["period"] == "static_definition"
        assert reform_metadata["complete"] is False
        assert "配置文件" in reform_metadata["description"]
        assert "当前已通过" in reform_metadata["description"]

        query = {"topic": "S01", "object": {"type": "country", "country": "FRA"},
                 "fields": ["emperor", "electors", "reforms"], "parameters": {}}
        result = service.source.read(query, service.source.context())
        assert result["fields"]["emperor"]["status"] == "unavailable"
        assert result["fields"]["electors"]["status"] == "unavailable"
        reforms = result["fields"]["reforms"]
        assert reforms["status"] == "known"
        assert reforms["value"][0]["reform_id"] == "fixture_reform"
        assert reforms["period"] == "static_definition"
        assert reforms["complete"] is False
    finally:
        _close(service, journal)


def test_default_factory_keeps_live_reforms_isolated_and_does_not_import_static_rules_or_capture(
        tmp_path, monkeypatch):
    from bridge.information import empire_capture

    def forbidden_capture(*_args, **_kwargs):
        raise AssertionError("factory discovery must not invoke native capture")

    monkeypatch.setattr(empire_capture, "capture", forbidden_capture)
    original_import = builtins.__import__
    forbidden_modules = {
        "bridge.information.imperial_reform_definitions",
        "bridge.information.imperial_reform_rules",
        "bridge.information.empire_capture_v3",
    }

    def guarded_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name in forbidden_modules:
            raise AssertionError(f"static reform modules imported without --empire-game-data: {name}")
        return original_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", guarded_import)
    args = _args(tmp_path, "--observer", "FRA")
    service, journal = _build_runtime(args)
    try:
        assert journal is None
        assert not any(type(adapter).__name__ == "StaticImperialReformRulesSource"
                       for adapter in service.source.adapters)
        assert any(type(adapter).__name__ == "NativeEmpirePassedReformsSource"
                   for adapter in service.source.adapters)
        topics = service.source.catalog()
        s01 = next(topic for topic in topics if topic["topic_id"] == "S01")
        assert s01["fields"]["reforms"]["coverage"] == "partial"
        assert s01["fields"]["reforms"]["source"] == "NativeEmpirePassedReformsSource"
        query = {"topic": "S01", "object": {"type": "session"},
                 "fields": ["emperor", "electors", "reforms"], "parameters": {}}
        result = service.source.read(query, service.source.context())
        assert result["fields"]["emperor"]["status"] == "unavailable"
        assert result["fields"]["electors"]["status"] == "unavailable"
        assert result["fields"]["reforms"]["status"] == "unavailable"
    finally:
        _close(service, journal)


def test_rules_parser_manifest_is_valid_only_with_the_static_reform_flag(tmp_path, monkeypatch):
    class ForbiddenIndex:
        def __init__(self, *_args, **_kwargs):
            raise AssertionError("invalid arguments must be rejected before index construction")

    _patch_index_class(monkeypatch, ForbiddenIndex)
    args = _args(tmp_path, "--empire-rules-parser-manifest", tmp_path / "parser.json")
    with pytest.raises(ValueError, match="--empire-rules-parser-manifest requires --empire-game-data"):
        _build_runtime(args)


@pytest.mark.parametrize("state_args", [
    ("--empire-save", "historical.eu4", "--observer", "FRA"),
    ("--province-interest-save", "historical.eu4", "--observer", "FRA"),
    ("--mission-save", "historical.eu4", "--observer", "FRA"),
    ("--recorded-manifest", "recorded.json"),
])
def test_static_reform_flag_rejects_historical_sources_before_opening_them(
        tmp_path, monkeypatch, state_args):
    class ForbiddenIndex:
        def __init__(self, *_args, **_kwargs):
            raise AssertionError("conflicting historical state must fail before index construction")

    _patch_index_class(monkeypatch, ForbiddenIndex)
    converted = tuple(str(tmp_path / value) if value.endswith((".eu4", ".json")) else value
                      for value in state_args)
    args = _args(tmp_path, "--empire-game-data", *converted)
    with pytest.raises(ValueError, match="--empire-game-data cannot be combined with historical state sources"):
        _build_runtime(args)
