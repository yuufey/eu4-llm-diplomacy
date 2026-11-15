"""Focused tests for ordered subject-type rule projection."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

from bridge.information.peace_rule_defines import PeaceRuleIndex
from bridge.information.peace_subject_rules import PeaceSubjectRules


_DEFAULTS = {
    "can_be_annexed": False,
    "can_be_integrated": False,
    "integration_requires_same_religion_group": True,
    "annex_cost_per_development": 0,
    "pays_overlord": 0,
    "can_send_tribute": False,
    "forcelimit_to_overlord": 0,
    "manpower_to_overlord": 0,
    "sailors_to_overlord": 0,
}


def _node(key, value=None, *, kind="scalar", assignment="=", children=(), line=1):
    raw = value if isinstance(value, str) else str(value)
    return SimpleNamespace(
        key=key, value=value, raw_value=raw, kind=kind, assignment=assignment,
        children=list(children), line=line,
    )


def _type(name, *children):
    return _node(name, kind="block", children=children)


class _Parser:
    def __init__(self, documents):
        self.documents = documents
        self._context = {"status": "ready", "complete": True, "manifest_sha256": "a" * 64}

    def context(self):
        return dict(self._context)

    def assert_current(self):
        return None

    def parse_files(self, paths):
        return {
            str(Path(path).resolve()): {
                "nodes": self.documents[Path(path).read_text(encoding="utf-8").strip()],
                "parser": dict(self._context),
            }
            for path in paths
        }


def _game(root: Path) -> Path:
    root.mkdir(parents=True)
    (root / "launcher-settings.json").write_text(json.dumps({"rawVersion": "v1.37.4.0"}), encoding="utf-8")
    return root


def _subject_file(root: Path, relative: str, marker: str) -> Path:
    path = root.joinpath(*relative.split("/"))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(marker, encoding="utf-8")
    return path


def _index(tmp_path: Path, game: Path, mods=None) -> PeaceRuleIndex:
    return PeaceRuleIndex(game_root=game, user_data=tmp_path / "user", enabled_mods=[] if mods is None else mods)


def test_duplicate_forward_declaration_copy_snapshot_and_ordered_overrides(tmp_path):
    game = _game(tmp_path / "game")
    _subject_file(game, "common/subject_types/00_rules.txt", "base")
    nodes = [
        _type("vassal"),
        _type("default",
              _node("can_be_annexed", "yes"),
              _node("annex_cost_per_development", "1.5"),
              _node("pays_overlord", "0.25")),
        _type("vassal", _node("copy_from", "default"), _node("can_be_integrated", "yes")),
        _type("default", _node("annex_cost_per_development", "3")),
        _type("vassal", _node("annex_cost_per_development", "2")),
    ]

    result = PeaceSubjectRules(_index(tmp_path, game), parser=_Parser({"base": nodes}), defaults=_DEFAULTS).read(["vassal"])

    assert result["values"]["vassal"]["can_be_annexed"] is True
    assert result["values"]["vassal"]["can_be_integrated"] is True
    assert result["values"]["vassal"]["annex_cost_per_development"] == 2
    assert result["values"]["vassal"]["pays_overlord"] == 0.25
    assert result["values"]["vassal"]["joins_overlords_wars"] is None
    assert result["reasons"]["vassal"]["joins_overlords_wars"]["code"] == "DEFAULT_UNKNOWN"


def test_empty_forward_block_keeps_supplied_defaults_until_later_assignment(tmp_path):
    game = _game(tmp_path / "game")
    _subject_file(game, "common/subject_types/types.txt", "base")
    nodes = [_type("march"), _type("march", _node("can_send_tribute", "yes"))]

    result = PeaceSubjectRules(_index(tmp_path, game), parser=_Parser({"base": nodes}), defaults=_DEFAULTS).read(["march"])

    assert result["values"]["march"]["can_be_annexed"] is False
    assert result["values"]["march"]["can_send_tribute"] is True
    assert result["values"]["march"]["sailors_to_overlord"] == 0


def test_effective_mod_file_overrides_base_declaration_and_is_hashed(tmp_path):
    game = _game(tmp_path / "game")
    relative = "common/subject_types/types.txt"
    _subject_file(game, relative, "base")
    mod = tmp_path / "mod"
    mod_file = _subject_file(mod, relative, "mod")
    descriptor = tmp_path / "overlay.mod"
    descriptor.write_text(f'name="overlay"\npath="{mod.as_posix()}"\n', encoding="utf-8")
    parser = _Parser({
        "base": [_type("vassal", _node("can_be_annexed", "no"))],
        "mod": [_type("vassal", _node("can_be_annexed", "yes"))],
    })

    result = PeaceSubjectRules(
        _index(tmp_path, game, [{"descriptor": descriptor, "root": mod}]),
        parser=parser, defaults=_DEFAULTS,
    ).read(["vassal"])

    assert result["values"]["vassal"]["can_be_annexed"] is True
    assert result["source"]["definition_files"][0]["source_kind"] == "enabled_mod"
    assert result["source"]["definition_files"][0]["sha256"] == hashlib.sha256(mod_file.read_bytes()).hexdigest()


def test_quoted_copy_name_uses_cwtools_decoded_value(tmp_path):
    game = _game(tmp_path / 'game')
    _subject_file(game, 'common/subject_types/types.txt', 'base')
    parent = _node('copy_from', 'default')
    parent.raw_value = '"default"'
    nodes = [_type('default', _node('can_be_annexed', 'yes')), _type('vassal', parent)]
    result = PeaceSubjectRules(_index(tmp_path, game), parser=_Parser({'base': nodes}),
                              defaults=_DEFAULTS).read(['vassal'])
    assert result['values']['vassal']['can_be_annexed'] is True


def test_missing_type_and_wrong_scalar_types_stay_unknown(tmp_path):
    game = _game(tmp_path / 'game')
    _subject_file(game, 'common/subject_types/types.txt', 'base')
    nodes = [_type('vassal', _node('can_be_annexed', '1'), _node('pays_overlord', 'yes'))]
    result = PeaceSubjectRules(_index(tmp_path, game), parser=_Parser({'base': nodes}),
                              defaults=_DEFAULTS).read(['vassal', 'missing'])
    assert result['values']['vassal']['can_be_annexed'] is None
    assert result['values']['vassal']['pays_overlord'] is None
    assert all(value is None for value in result['values']['missing'].values())
