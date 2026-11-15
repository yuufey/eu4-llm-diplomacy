from __future__ import annotations

import json
from pathlib import Path

import pytest

from bridge.information.localization import (
    ENCODING_EU4_ESCAPE_CP1252,
    LocalizationIndex,
)
from bridge.information.mission_definitions import MissionDefinitionIndex
from bridge.information.model import InformationError


def _base_mission() -> str:
    return """
    fixture_root = {
        slot = 1
        generic = no
        fixture_task = { position = 1 }
    }
    """


def _fixture(
    tmp_path: Path,
    base_text: str,
    *,
    mod_text: str | None = None,
    replace_path: str | None = None,
    enabled: bool = False,
) -> tuple[Path, Path, Path, Path | None]:
    game = tmp_path / "game"
    user = tmp_path / "user"
    (game / "missions").mkdir(parents=True)
    (game / "localisation").mkdir(parents=True)
    (game / "launcher-settings.json").write_text(
        json.dumps({"rawVersion": "v1.37.4.0"}), encoding="utf-8"
    )
    (game / "missions" / "00_fixture.txt").write_text(_base_mission(), encoding="utf-8")
    (game / "localisation" / "00_fixture.yml").write_text(base_text, encoding="utf-8")
    user.mkdir(parents=True)
    mod_dir: Path | None = None
    if mod_text is not None:
        mod_dir = user / "mod" / "overlay"
        (mod_dir / "localisation").mkdir(parents=True)
        (mod_dir / "localisation" / "00_overlay.yml").write_text(mod_text, encoding="utf-8")
        descriptor = user / "mod" / "overlay.mod"
        descriptor.write_text(
            'name="Overlay"\npath="' + str(mod_dir).replace("\\", "/") + '"\n'
            + ((f'replace_path="{replace_path}"\n') if replace_path else ""),
            encoding="utf-8",
        )
        enabled_value: list[str] = ["mod/overlay.mod"] if enabled else []
    else:
        enabled_value = []
    (user / "dlc_load.json").write_text(
        json.dumps({"enabled_mods": enabled_value}), encoding="utf-8"
    )
    return game, user, game / "localisation" / "00_fixture.yml", mod_dir


def _reason_codes(context: dict) -> set[str]:
    return {
        item["code"] for item in context.get("reasons", [])
        if isinstance(item, dict) and "code" in item
    }


def test_lookup_returns_raw_decoded_provenance_and_dynamic_tokens(tmp_path):
    game, user, path, _ = _fixture(
        tmp_path,
        """l_english:\nplain_key:0 \"Plain text\"\ndynamic_key:0 \"[Root.GetName]\" # keep comment\n""",
    )
    source = LocalizationIndex(game, user)
    assert source.context()["status"] == "ready"

    result = source.lookup(
        ["plain_key", "dynamic_key", "missing_key"],
        language="l_english", encoding="utf8",
    )
    assert result["status"] == "partial"
    plain = result["entries"]["plain_key"]
    assert plain["status"] == "known"
    assert plain["raw"]["status"] == "present"
    assert plain["raw_text"] == "Plain text"
    assert plain["decoded_status"] == "decoded"
    assert plain["decoded_text"] == "Plain text"
    assert plain["language_header"] == {"language": "l_english", "line": 1}
    assert plain["source"]["layer"] == "basegame"
    assert plain["source"]["relative_path"] == "localisation/00_fixture.yml"
    assert plain["source"]["sha256"]
    dynamic = result["entries"]["dynamic_key"]
    assert dynamic["status"] == "template"
    assert dynamic["decoded_status"] == "template"
    assert dynamic["decoded_text"] == "[Root.GetName]"
    assert dynamic["dynamic_tokens"] == ["[Root.GetName]"]
    assert result["entries"]["missing_key"]["reason"] == "LOCALISATION_KEY_MISSING"
    assert path.is_file()


def test_dollar_templates_and_unresolved_markers_fail_closed(tmp_path):
    game, user, _path, _ = _fixture(
        tmp_path,
        """l_english:
dollar_key:0 \"Hello $NAME$\"
mixed_key:0 \"[Root.GetName] / $TITLE$\"
bad_square:0 \"Broken [Root.GetName\"
bad_dollar:0 \"Broken $NAME\"
bad_empty_square:0 \"Broken []\"
bad_empty_dollar:0 \"Broken $$\"
""",
    )
    source = LocalizationIndex(game, user)
    result = source.lookup(
        [
            "dollar_key", "mixed_key", "bad_square", "bad_dollar",
            "bad_empty_square", "bad_empty_dollar",
        ],
        language="l_english", encoding="utf8",
    )

    dollar = result["entries"]["dollar_key"]
    assert dollar["status"] == "template"
    assert dollar["decoded_status"] == "template"
    assert dollar["decoded_text"] == "Hello $NAME$"
    assert dollar["dynamic_tokens"] == ["$NAME$"]

    mixed = result["entries"]["mixed_key"]
    assert mixed["status"] == "template"
    assert mixed["dynamic_tokens"] == ["[Root.GetName]", "$TITLE$"]

    for key in ("bad_square", "bad_dollar", "bad_empty_square", "bad_empty_dollar"):
        value = result["entries"][key]
        assert value["status"] == "unknown"
        assert value["decoded_status"] == "unknown"
        assert value["reason"] == "LOCALISATION_UNRESOLVED_DYNAMIC_MARKER"
        assert value["decoded_text"] is None
        assert value["malformed_dynamic_markers"]
    assert result["complete"] is False


def test_later_enabled_layer_is_selected_and_replace_path_is_explicit(tmp_path):
    game, user, _path, _ = _fixture(
        tmp_path,
        "l_english:\nname_key:0 \"base\"\nbase_only:0 \"base\"\n",
        mod_text="l_english:\nname_key:0 \"mod\"\nmod_only:0 \"mod\"\n",
        enabled=True,
    )
    source = LocalizationIndex(game, user)
    selected = source.lookup(
        ["name_key", "base_only", "mod_only"],
        language="l_english", encoding="utf8",
    )
    assert selected["entries"]["name_key"]["decoded_text"] == "mod"
    assert selected["entries"]["name_key"]["coverage_source"] == "static_enabled_stack_order"
    assert selected["entries"]["name_key"]["overridden_sources"][0]["layer"] == "basegame"

    replace_game, replace_user, _replace_path, _ = _fixture(
        tmp_path / "replace",
        "l_english:\nbase_only:0 \"base\"\n",
        mod_text="l_english:\nmod_only:0 \"mod\"\n",
        replace_path="localisation",
        enabled=True,
    )
    replaced = LocalizationIndex(replace_game, replace_user)
    result = replaced.lookup(
        ["base_only", "mod_only"], language="l_english", encoding="utf8"
    )
    assert result["entries"]["base_only"]["reason"] == "LOCALISATION_KEY_MISSING"
    assert result["entries"]["mod_only"]["status"] == "known"


def test_same_layer_duplicate_does_not_fallback(tmp_path):
    game, user, _path, _ = _fixture(
        tmp_path,
        "l_english:\nduplicate:0 \"one\"\n",
    )
    (game / "localisation" / "01_duplicate.yml").write_text(
        "l_english:\nduplicate:0 \"two\"\n", encoding="utf-8"
    )
    source = LocalizationIndex(game, user)
    result = source.lookup(["duplicate"], language="l_english", encoding="utf8")
    assert result["entries"]["duplicate"]["status"] == "unknown"
    assert result["entries"]["duplicate"]["reason"] == "LOCALISATION_SAME_LAYER_DUPLICATE"
    assert "LOCALISATION_SAME_LAYER_DUPLICATE" in _reason_codes(source.context()) or any(
        item["code"] == "LOCALISATION_SAME_LAYER_DUPLICATE"
        for item in source.context().get("warnings", [])
    )


def test_explicit_escape_codec_and_truncated_escape_are_distinguished(tmp_path):
    # 0x10 + little-endian U+0141 is represented in the UTF-8 localisation
    # file as control U+0010, 'A', U+0001.
    escaped = "l_english:\nescaped:0 \"" + "\x10A\x01" + "\"\n"
    game, user, _path, _ = _fixture(tmp_path, escaped)
    source = LocalizationIndex(game, user)
    result = source.lookup(
        ["escaped"], language="l_english", encoding=ENCODING_EU4_ESCAPE_CP1252
    )
    assert result["entries"]["escaped"]["decoded_status"] == "decoded"
    assert result["entries"]["escaped"]["decoded_text"] == "Ł"

    truncated_game, truncated_user, _path, _ = _fixture(
        tmp_path / "truncated", "l_english:\ntruncated:0 \"\x10\"\n"
    )
    truncated = LocalizationIndex(truncated_game, truncated_user)
    value = truncated.lookup(
        ["truncated"], language="l_english", encoding=ENCODING_EU4_ESCAPE_CP1252
    )["entries"]["truncated"]
    assert value["status"] == "unknown"
    assert value["decoded_status"] == "unknown"
    assert value["reason"] == "LOCALISATION_VALUE_DECODE_FAILED"


def test_unknown_codec_is_rejected_without_guessing(tmp_path):
    game, user, _path, _ = _fixture(tmp_path, "l_english:\nkey:0 \"value\"\n")
    source = LocalizationIndex(game, user)
    with pytest.raises(InformationError) as caught:
        source.lookup(["key"], language="l_english", encoding="guess")
    assert caught.value.code == "unknown_encoding"


def test_invalid_utf8_is_unavailable(tmp_path):
    game, user, _path, _ = _fixture(tmp_path, "l_english:\nkey:0 \"value\"\n")
    (game / "localisation" / "01_invalid.yml").write_bytes(
        b"l_english:\ninvalid:0 \"\xff\"\n"
    )
    source = LocalizationIndex(game, user)
    assert "LOCALISATION_FILE_INVALID" in _reason_codes(source.context())
    result = source.lookup(["key"], language="l_english", encoding="utf8")
    assert result["status"] == "unavailable"
    assert result["entries"]["key"]["status"] == "unavailable"


def test_file_and_directory_changes_fail_closed_without_old_value(tmp_path):
    game, user, path, _ = _fixture(tmp_path, "l_english:\nkey:0 \"old\"\n")
    source = LocalizationIndex(game, user)
    path.write_text("l_english:\nkey:0 \"new\"\n", encoding="utf-8")
    changed = source.lookup(["key"], language="l_english", encoding="utf8")
    assert changed["status"] == "unavailable"
    assert changed["entries"]["key"]["status"] == "unavailable"
    assert changed["entries"]["key"]["reason"] == "LOCALISATION_SOURCE_CHANGED"

    game2, user2, _path2, _ = _fixture(tmp_path / "members", "l_english:\nkey:0 \"old\"\n")
    source2 = LocalizationIndex(game2, user2)
    (game2 / "localisation" / "new.yml").write_text(
        "l_english:\nnew:0 \"new\"\n", encoding="utf-8"
    )
    assert "LOCALISATION_DIRECTORY_CHANGED" in _reason_codes(source2.context())
    assert source2.lookup(["key"], language="l_english", encoding="utf8")["status"] == "unavailable"


def test_replace_path_escape_is_rejected(tmp_path):
    game, user, _path, _ = _fixture(
        tmp_path, "l_english:\nkey:0 \"value\"\n",
        mod_text="l_english:\nmod:0 \"value\"\n",
        replace_path="../localisation", enabled=True,
    )
    source = LocalizationIndex(game, user)
    assert "LOCALISATION_PATH_ESCAPE" in _reason_codes(source.context())


def test_real_1374_enabled_stack_reads_the_current_122_target_keys():
    from work.local_config import get_path

    game = get_path("EU4_GAME_ROOT", required=False)
    user = get_path("EU4_USER_DATA", required=False)
    if game is None or user is None or not (game / "missions").is_dir() or not (user / "dlc_load.json").is_file():
        pytest.skip("local EU4 1.37.4 installation is not configured")
    mission_index = MissionDefinitionIndex(game, user)
    if mission_index.context()["status"] != "ready":
        pytest.skip("local mission/mod stack is unavailable")
    # The current FRA acceptance scope is the 18 roots captured by the
    # information-stage2 fixture; the production index itself accepts any
    # requested key and does not contain this list.
    target_roots = [
        "french_missions_1", "french_missions_1_blank_hre", "french_missions_1_Continuation_a",
        "french_missions_2", "french_missions_2_blank_hre", "french_missions_2_Continuation_b",
        "french_missions_3", "french_missions_3_blank_hre",
        "french_missions_3_continuation_after_hre_missions", "french_missions_3_normal_continued",
        "french_missions_4_normal", "french_missions_4_branching",
        "french_missions_4_normal_continuation", "french_missions_4_normal_contiuation",
        "french_missions_5_normal", "french_missions_5_branching",
        "french_missions_5_continuation_normal_1", "fra_missions_5_continuation",
    ]
    task_ids = {
        task["task_id"]
        for root in mission_index.roots(target_roots)
        for task in root.get("tasks", [])
        if isinstance(task, dict) and isinstance(task.get("task_id"), str)
    }
    keys = sorted({f"{task_id}_{suffix}" for task_id in task_ids for suffix in ("title", "desc")})
    if len(keys) != 122:
        pytest.skip(f"current local stack has {len(keys)} target keys, not the recorded 122")
    source = LocalizationIndex(game, user)
    result = source.lookup(keys, language="l_english", encoding=ENCODING_EU4_ESCAPE_CP1252)
    assert result["status"] in {"complete", "partial"}
    assert all(item["status"] in {"known", "template"} for item in result["entries"].values())
    assert all(item.get("malformed_dynamic_markers") == [] for item in result["entries"].values())
    assert all(item["source"]["layer"] == "enabled_mod[0]" for item in result["entries"].values())
