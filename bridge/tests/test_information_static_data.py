"""Static trade-node source tests, including a read-only real-install check."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from bridge.information.static_data import StaticTradeSource
from bridge.information.model import InformationError


def _write_fixture(root: Path, text: str, *, version: str = "v1.37.4.0") -> Path:
    (root / "common" / "tradenodes").mkdir(parents=True)
    (root / "launcher-settings.json").write_text(
        json.dumps({"rawVersion": version}), encoding="utf-8"
    )
    path = root / "common" / "tradenodes" / "00_fixture.txt"
    path.write_text(text, encoding="utf-8")
    return path


def _query(topic: str, obj: dict, fields: list[str]) -> dict:
    return {"topic": topic, "object": obj, "fields": fields, "parameters": {}}


def test_parser_handles_comments_quotes_nested_lists_and_repeated_outgoing(tmp_path):
    _write_fixture(
        tmp_path,
        r'''
        # A quoted key and quoted value must keep their braces and spaces.
        "alpha_node"={
            location=1
            members={ 1 2 3 }
            outgoing={ name="beta" path={ 1 2 } control={ 1.5 2.0 } }
            outgoing={ name="gamma" path={ "3" } }
        }
        beta={ members={ 4 } }
        gamma={ members={ 5 } }
        ''',
    )
    source = StaticTradeSource(game_root=tmp_path, user_data=tmp_path / "user", enabled_mods=[])
    context = source.context()
    assert context["status"] == "ready"
    result = source.read(
        _query(
            "T01",
            {"type": "trade_node", "node_id": "alpha_node"},
            ["node_id", "provinces", "downstream", "routes"],
        ),
        context,
    )
    assert result["complete"] is True
    assert result["fields"]["provinces"]["value"] == [1, 2, 3]
    assert result["fields"]["downstream"]["value"] == ["beta", "gamma"]
    assert result["fields"]["routes"]["value"][0]["path"] == [1, 2]
    assert result["fields"]["routes"]["value"][0]["control"] == [1.5, 2]
    name = source.read(
        _query("T01", {"type": "trade_node", "node_id": "alpha_node"}, ["name"]),
        context,
    )
    assert name["fields"]["name"] == {
        "status": "unknown", "reason": "LOCALISATION_NOT_READ"
    }
    assert name["complete"] is False


def test_graph_direction_and_province_to_node_mapping_are_static(tmp_path):
    _write_fixture(
        tmp_path,
        """
        east={location=10 members={10 11} outgoing={name=west path={10 11}}}
        west={location=20 members={20}}
        """,
    )
    source = StaticTradeSource(game_root=tmp_path, user_data=tmp_path / "user", enabled_mods=[])
    context = source.context()
    node = source.read(
        _query("T01", {"type": "trade_node", "node_id": "west"}, ["upstream", "downstream"]),
        context,
    )
    assert node["fields"]["upstream"] == {"status": "known", "value": ["east"]}
    assert node["fields"]["downstream"] == {"status": "known", "value": []}
    province = source.read(
        _query("G04", {"type": "province", "province_id": 11}, ["trade_node"]),
        context,
    )
    assert province["fields"]["trade_node"] == {"status": "known", "value": "east"}
    assert province["source"]["context_scope"] == "static_rules"
    for field in ("ports", "transfer_relations"):
        unsupported = source.read(
            _query("G04", {"type": "trade_node", "node_id": "east"}, [field]),
            context,
        )
        assert unsupported["fields"][field]["status"] == "unsupported"


def test_t02_exposes_only_static_route_part_and_never_infers_home_node(tmp_path):
    _write_fixture(tmp_path, "alpha={outgoing={name=beta}} beta={}")
    source = StaticTradeSource(game_root=tmp_path, user_data=tmp_path / "user", enabled_mods=[])
    result = source.read(
        _query(
            "T02",
            {"type": "trade_node", "node_id": "alpha"},
            ["home_node", "collect_node", "upstream", "leak_direction", "routes"],
        )
    )
    assert result["fields"]["home_node"]["status"] == "unsupported"
    assert result["fields"]["collect_node"]["status"] == "unsupported"
    assert result["fields"]["leak_direction"]["status"] == "unsupported"
    assert result["fields"]["routes"]["status"] == "known"
    assert result["fields"]["routes"]["value"][0]["target"] == "beta"


def test_replace_path_does_not_fall_back_to_basegame(tmp_path):
    _write_fixture(tmp_path, "base_node={members={1}}")
    user = tmp_path / "user"
    mod = user / "mod" / "overlay"
    (mod / "common" / "tradenodes").mkdir(parents=True)
    (mod / "common" / "tradenodes" / "00_overlay.txt").write_text(
        "overlay_node={members={2}}", encoding="utf-8"
    )
    descriptor = user / "mod" / "overlay.mod"
    descriptor.parent.mkdir(parents=True, exist_ok=True)
    descriptor.write_text(
        'name="Overlay"\npath="' + str(mod).replace("\\", "/") + '"\n'
        'replace_path="common/tradenodes"\n',
        encoding="utf-8",
    )
    source = StaticTradeSource(
        game_root=tmp_path,
        user_data=user,
        enabled_mods=["mod/overlay.mod"],
    )
    assert source.context()["status"] == "ready"
    assert "base_node" not in source._state.nodes
    assert "overlay_node" in source._state.nodes
    assert source.context()["enabled_mods"][0]["replace_paths"] == ["common/tradenodes"]


def test_unsupported_conditional_fails_closed_without_basegame_fallback(tmp_path):
    _write_fixture(tmp_path, "base_node={members={1}}\nif={limit={always=yes}}")
    source = StaticTradeSource(game_root=tmp_path, user_data=tmp_path / "user", enabled_mods=[])
    context = source.context()
    assert context["status"] == "unready"
    result = source.read(
        _query("T01", {"type": "trade_node", "node_id": "base_node"}, ["node_id"])
    )
    assert result["fields"]["node_id"]["status"] == "unavailable"
    assert any(reason["code"] == "UNSUPPORTED_TRADE_CONDITION" for reason in context["reasons"])


def test_input_hash_change_makes_source_unavailable(tmp_path):
    path = _write_fixture(tmp_path, "alpha={members={1}}")
    source = StaticTradeSource(game_root=tmp_path, user_data=tmp_path / "user", enabled_mods=[])
    assert source.context()["status"] == "ready"
    path.write_text("alpha={members={2}}", encoding="utf-8")
    assert source.context()["status"] == "unready"
    result = source.read(_query("T01", {"type": "trade_node", "node_id": "alpha"}, ["provinces"]))
    assert result["fields"]["provinces"]["status"] == "unavailable"


def test_trade_directory_membership_change_fails_closed_for_add_and_delete(tmp_path):
    _write_fixture(tmp_path, "alpha={members={1}}")
    source = StaticTradeSource(game_root=tmp_path, user_data=tmp_path / "user", enabled_mods=[])
    trade_dir = tmp_path / "common" / "tradenodes"
    assert source.context()["status"] == "ready"
    (trade_dir / "01_new.txt").write_text("new_node={members={2}}", encoding="utf-8")
    changed = source.context()
    assert changed["status"] == "unready"
    assert any(reason["code"] == "STATIC_TRADE_DIRECTORY_CHANGED" for reason in changed["reasons"])

    # A newly constructed source records the new member list; removing that
    # file is a separate membership change and must also stop reads.
    source_after_add = StaticTradeSource(
        game_root=tmp_path, user_data=tmp_path / "user", enabled_mods=[]
    )
    (trade_dir / "01_new.txt").unlink()
    removed = source_after_add.context()
    assert removed["status"] == "unready"
    assert any(reason["code"] == "STATIC_TRADE_DIRECTORY_CHANGED" for reason in removed["reasons"])


def test_missing_mod_trade_directory_is_recorded_and_later_creation_changes_scope(tmp_path):
    _write_fixture(tmp_path, "base_node={members={1}}")
    user = tmp_path / "user"
    mod = user / "mod" / "empty_overlay"
    mod.mkdir(parents=True)
    descriptor = user / "mod" / "empty_overlay.mod"
    descriptor.write_text(
        'name="Empty overlay"\npath="' + str(mod).replace("\\", "/") + '"\n',
        encoding="utf-8",
    )
    source = StaticTradeSource(
        game_root=tmp_path, user_data=user, enabled_mods=["mod/empty_overlay.mod"]
    )
    assert source.context()["status"] == "ready"
    mod_trade_dir = mod / "common" / "tradenodes"
    mod_trade_dir.mkdir(parents=True)
    (mod_trade_dir / "00_new.txt").write_text("new_node={members={2}}", encoding="utf-8")
    changed = source.context()
    assert changed["status"] == "unready"
    assert any(reason["code"] == "STATIC_TRADE_DIRECTORY_CHANGED" for reason in changed["reasons"])


def test_missing_scope_inputs_fail_closed_and_unknown_version_is_not_advertised(tmp_path):
    _write_fixture(tmp_path, "alpha={members={1}}")
    no_version = tmp_path / "no_version"
    (no_version / "common" / "tradenodes").mkdir(parents=True)
    (no_version / "common" / "tradenodes" / "00.txt").write_text("alpha={}")
    no_version_source = StaticTradeSource(
        game_root=no_version, user_data=no_version / "user", enabled_mods=[]
    )
    no_version_context = no_version_source.context()
    assert no_version_context["status"] == "unready"
    assert any(reason["code"] == "GAME_VERSION_UNAVAILABLE" for reason in no_version_context["reasons"])
    assert all(not topic["supported_versions"] for topic in no_version_source.catalog())
    no_version_read = no_version_source.read(
        _query("T01", {"type": "trade_node", "node_id": "alpha"}, ["node_id"])
    )
    assert no_version_read["complete"] is False

    unknown_version = tmp_path / "unknown_version"
    (unknown_version / "common" / "tradenodes").mkdir(parents=True)
    (unknown_version / "common" / "tradenodes" / "00.txt").write_text("alpha={}")
    (unknown_version / "launcher-settings.json").write_text(
        json.dumps({"version": "future-build"}), encoding="utf-8"
    )
    unknown_source = StaticTradeSource(
        game_root=unknown_version, user_data=unknown_version / "user", enabled_mods=[]
    )
    assert unknown_source.context()["status"] == "unready"
    assert all(not topic["supported_versions"] for topic in unknown_source.catalog())

    no_mod_stack = StaticTradeSource(
        game_root=tmp_path, user_data=tmp_path / "missing_user_data", enabled_mods=None
    )
    no_mod_context = no_mod_stack.context()
    assert no_mod_context["status"] == "unready"
    assert any(reason["code"] == "ENABLED_MOD_CONFIG_UNAVAILABLE" for reason in no_mod_context["reasons"])


def test_duplicate_node_key_in_one_file_is_rejected(tmp_path):
    _write_fixture(tmp_path, "alpha={members={1}} alpha={members={2}}")
    source = StaticTradeSource(game_root=tmp_path, user_data=tmp_path / "user", enabled_mods=[])
    assert source.context()["status"] == "unready"
    assert any(reason["code"] == "DUPLICATE_TRADE_NODE" for reason in source.context()["reasons"])


def test_duplicate_node_key_across_files_is_rejected(tmp_path):
    _write_fixture(tmp_path, "same_node={members={1}}")
    (tmp_path / "common" / "tradenodes" / "01_duplicate.txt").write_text(
        "same_node={members={2}}", encoding="utf-8"
    )
    source = StaticTradeSource(game_root=tmp_path, user_data=tmp_path / "user", enabled_mods=[])
    context = source.context()
    assert context["status"] == "unready"
    assert any(reason["code"] == "DUPLICATE_TRADE_NODE" for reason in context["reasons"])
    result = source.read(
        _query("T01", {"type": "trade_node", "node_id": "same_node"}, ["provinces"])
    )
    assert result["fields"]["provinces"]["status"] == "unavailable"


def test_static_source_rejects_other_topics():
    source = StaticTradeSource(game_root=Path("missing"), user_data=Path("missing"), enabled_mods=[])
    with pytest.raises(InformationError) as caught:
        source.validate_query(_query("T03", {"type": "trade_node", "node_id": "x"}, ["total_value"]))
    assert caught.value.code == "unsupported_topic"


def test_real_install_node_read_is_read_only():
    from work import local_config

    try:
        root = local_config.game_root()
    except Exception as exc:  # pragma: no cover - depends on local machine setup
        pytest.skip(str(exc))
    trade_file = root / "common" / "tradenodes" / "00_tradenodes.txt"
    if not trade_file.is_file():  # pragma: no cover - CI has no game install
        pytest.skip("configured EU4 installation has no 00_tradenodes.txt")
    source = StaticTradeSource()
    context = source.context()
    assert context["status"] == "ready"
    assert context["game_version"] == "1.37.4"
    result = source.read(
        _query("T01", {"type": "trade_node", "node_id": "english_channel"}, ["provinces", "upstream", "routes"]),
        context,
    )
    assert result["complete"] is True
    assert result["source"]["context_scope"] == "static_rules"
    assert result["source"]["definitions_sha256"]
    assert result["source"]["provenance"]["definition_files"][0]["sha256"]
    assert result["game_date"] is None
