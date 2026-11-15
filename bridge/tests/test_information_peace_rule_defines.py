"""Focused tests for static P06 peace-rule define extraction."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from bridge.information.peace_rule_defines import PEACE_RULE_KEYS, PeaceRuleIndex


def _write_game(root: Path) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "launcher-settings.json").write_text(
        json.dumps({"rawVersion": "v1.37.4.0"}), encoding="utf-8"
    )
    return root


def _write_defines(root: Path, relative: str, text: str) -> Path:
    path = root.joinpath(*relative.split("/"))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _index(game: Path, user: Path, mods=None) -> PeaceRuleIndex:
    return PeaceRuleIndex(game_root=game, user_data=user,
                          enabled_mods=[] if mods is None else mods)


def test_selected_diplomacy_keys_reuse_effective_defines_without_changing_defaults(tmp_path):
    game = _write_game(tmp_path / "game")
    _write_defines(game, "common/defines.lua", "NDefines = { NDiplomacy = { CALL_TO_ARMS_COST = 10 } }")
    _write_defines(game, "common/defines/10_override.lua", "NDefines.NDiplomacy.CALL_TO_ARMS_COST = 12")
    selected = PeaceRuleIndex(game_root=game, user_data=tmp_path / "user", enabled_mods=[],
                              keys=("CALL_TO_ARMS_COST",)).read()
    assert selected["values"] == {"CALL_TO_ARMS_COST": 12}
    assert selected["reasons"] == {}
    assert tuple(_index(game, tmp_path / "user").read()["values"]) == PEACE_RULE_KEYS


def test_reads_only_direct_ndiplomacy_numeric_fields_from_base_table(tmp_path):
    game = _write_game(tmp_path / "game")
    source_path = _write_defines(game, "common/defines.lua", '''
NDefines = {
    NEconomy = { WAR_REPARATIONS_FACTOR = 99 },
    NDiplomacy = {
        WAR_REPARATIONS_FACTOR = 0.5,
        WAR_REPARATIONS_YEARS = 10,
        TRUCE_YEARS = 5,
    },
}
''')

    result = _index(game, tmp_path / "user").read()

    assert result["values"]["WAR_REPARATIONS_FACTOR"] == 0.5
    assert result["values"]["WAR_REPARATIONS_YEARS"] == 10
    assert result["values"]["TRUCE_YEARS"] == 5
    assert result["values"]["ANNUL_TREATIES_YEARS"] is None
    row = next(row for row in result["source"]["definition_files"] if row["relative"] == "common/defines.lua")
    assert row["sha256"] == hashlib.sha256(source_path.read_bytes()).hexdigest()


def test_dotted_mod_override_wins_in_effective_layer_order(tmp_path):
    game = _write_game(tmp_path / "game")
    _write_defines(game, "common/defines.lua", "NDefines = { NDiplomacy = { TRUCE_YEARS = 5 } }\n")
    _write_defines(game, "common/defines/00_base.lua", "NDefines.NDiplomacy.WAR_REPARATIONS_YEARS = 10\n")
    mod = tmp_path / "mod"
    _write_defines(mod, "common/defines/10_override.lua", "NDefines.NDiplomacy.WAR_REPARATIONS_YEARS = 20\n")
    descriptor = tmp_path / "mod.mod"
    descriptor.write_text(f'name="overlay"\npath="{mod.as_posix()}"\n', encoding="utf-8")

    result = _index(game, tmp_path / "user", [{"descriptor": descriptor, "root": mod}]).read()

    assert result["values"]["WAR_REPARATIONS_YEARS"] == 20
    assert result["values"]["TRUCE_YEARS"] == 5
    assert next(row for row in result["source"]["definition_files"] if row["relative"] == "common/defines/10_override.lua")["source_kind"] == "enabled_mod"


def test_replace_path_removes_prior_defines_directory_values(tmp_path):
    game = _write_game(tmp_path / "game")
    _write_defines(game, "common/defines.lua", "NDefines = { NDiplomacy = { TRUCE_YEARS = 6 } }\n")
    _write_defines(game, "common/defines/00_base.lua", "NDefines.NDiplomacy.WAR_REPARATIONS_YEARS = 10\n")
    mod = tmp_path / "mod"
    _write_defines(mod, "common/defines/10_mod.lua", "NDefines.NDiplomacy.WAR_REPARATIONS_YEARS = 18\n")
    descriptor = tmp_path / "mod.mod"
    descriptor.write_text(
        f'name="replacement"\npath="{mod.as_posix()}"\nreplace_path="common/defines"\n',
        encoding="utf-8",
    )

    result = _index(game, tmp_path / "user", [{"descriptor": descriptor, "root": mod}]).read()

    assert result["values"]["WAR_REPARATIONS_YEARS"] == 18
    assert result["values"]["TRUCE_YEARS"] == 6
    assert [row["relative"] for row in result["source"]["definition_files"]] == [
        "common/defines.lua", "common/defines/10_mod.lua"
    ]


def test_full_defines_file_precedes_patches_sorted_across_layers(tmp_path):
    game = _write_game(tmp_path / "game")
    _write_defines(game, "common/defines.lua", "NDefines = { NDiplomacy = { WAR_REPARATIONS_YEARS = 5 } }\n")
    _write_defines(game, "common/defines/20_base.lua", "NDefines.NDiplomacy.WAR_REPARATIONS_YEARS = 20\n")
    mod = tmp_path / "mod"
    _write_defines(mod, "common/defines.lua", "NDefines = { NDiplomacy = { WAR_REPARATIONS_YEARS = 10 } }\n")
    _write_defines(mod, "common/defines/10_mod.lua", "NDefines.NDiplomacy.TRUCE_YEARS = 8\n")
    descriptor = tmp_path / "mod.mod"
    descriptor.write_text(f'name="overlay"\npath="{mod.as_posix()}"\n', encoding="utf-8")

    result = _index(game, tmp_path / "user", [{"descriptor": descriptor, "root": mod}]).read()

    assert result["values"]["WAR_REPARATIONS_YEARS"] == 20
    assert result["values"]["TRUCE_YEARS"] == 8
    assert [row["relative"] for row in result["source"]["definition_files"]] == [
        "common/defines.lua", "common/defines/10_mod.lua", "common/defines/20_base.lua"
    ]


def test_comments_strings_and_other_namespaces_are_not_values(tmp_path):
    game = _write_game(tmp_path / "game")
    _write_defines(game, "common/defines.lua", '''
-- NDefines.NDiplomacy.ANNUL_TREATIES_YEARS = 99
local quoted = "NDefines.NDiplomacy.ANNUL_TREATIES_YEARS = 98"
--[=[ NDefines.NDiplomacy.PO_TRADE_POWER_AMOUNT = 88 ]=]
NDefines = {
    NEconomy = { PO_TRADE_POWER_AMOUNT = 77 },
    NDiplomacy = { ANNUL_TREATIES_YEARS = 12 },
}
''')

    result = _index(game, tmp_path / "user").read()

    assert result["values"]["ANNUL_TREATIES_YEARS"] == 12
    assert result["values"]["PO_TRADE_POWER_AMOUNT"] is None


def test_nonliteral_or_conditional_override_invalidates_previous_value(tmp_path):
    game = _write_game(tmp_path / "game")
    _write_defines(game, "common/defines.lua", "NDefines = { NDiplomacy = { TRUCE_YEARS = 5 } }\n")
    _write_defines(game, "common/defines/10_expression.lua", "NDefines.NDiplomacy.TRUCE_YEARS = TRUCE_YEARS + 1\n")
    _write_defines(game, "common/defines/20_conditional.lua", "if enabled then NDefines.NDiplomacy.WAR_REPARATIONS_YEARS = 10 end\n")

    result = _index(game, tmp_path / "user").read()

    assert result["values"]["TRUCE_YEARS"] is None
    assert result["reasons"]["TRUCE_YEARS"]["code"] == "DEFINE_EXPRESSION_UNSUPPORTED"
    assert result["values"]["WAR_REPARATIONS_YEARS"] is None
    assert result["reasons"]["WAR_REPARATIONS_YEARS"]["code"] == "CONDITIONAL_ASSIGNMENT"


def test_missing_enabled_mod_cannot_fall_back_to_unmodified_base_rules(tmp_path):
    game = _write_game(tmp_path / 'game')
    _write_defines(game, 'common/defines.lua', 'NDefines = { NDiplomacy = { WAR_REPARATIONS_YEARS = 10 } }')
    result = _index(game, tmp_path / 'user', ['missing.mod']).read()
    assert all(value is None for value in result['values'].values())
    assert result['reasons']['WAR_REPARATIONS_YEARS']['code'] == 'ENABLED_MOD_UNSUPPORTED'
