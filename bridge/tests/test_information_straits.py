"""Offline tests for explicit static province sea-adjacency disclosure."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from bridge.information.model import InformationError
from bridge.information.strait_csv import parse_adjacencies, parse_definition_ids
from bridge.information.straits import StaticStraitsSource


_FIELDS = ("bordering", "distance", "straits", "island", "land_connection", "access", "fort", "supply")
_ADJ_HEADER = "From;To;Type;Through;start_x;start_y;stop_x;stop_y;Comment"
_EDGE = {"from_province": 1, "to_province": 2, "through_province": 7, "source_lines": [2]}
_SEA_ROW = "1;2;sea;7;-1;-1;-1;-1;explicit sea fixture"
_OTHER_ROWS = (
    "1;3;canal;4;-1;-1;-1;-1;canal fixture",
    "2;4;lake;5;-1;-1;-1;-1;lake fixture",
    "3;5;river;6;-1;-1;-1;-1;river fixture",
    "4;6;impassable;-1;-1;-1;-1;-1;impassable fixture",
)


def _definition_csv(ids=range(1, 9)) -> str:
    rows = ["province;red;green;blue;name", "0;0;0;0;sentinel"]
    rows.extend(f"{province};{province};0;0;province_{province}" for province in ids)
    return "\n".join(rows) + "\n"


def _adjacency_csv(rows=(_SEA_ROW, *_OTHER_ROWS)) -> str:
    return "\n".join((_ADJ_HEADER, *rows)) + "\n"


def _write_map(root: Path, *, rows=(_SEA_ROW, *_OTHER_ROWS), definitions: str | None = None) -> None:
    map_dir = root / "map"
    map_dir.mkdir(parents=True, exist_ok=True)
    (root / "launcher-settings.json").write_text(
        json.dumps({"rawVersion": "v1.37.4.0"}), encoding="utf-8"
    )
    (map_dir / "default.map").write_text(
        'definitions = "definition.csv"\nadjacencies = "adjacencies.csv"\n'
        "max_provinces = 9\nsea_starts = { 3 4 }\nlakes = { 8 }\n",
        encoding="utf-8",
    )
    (map_dir / "definition.csv").write_text(
        _definition_csv() if definitions is None else definitions, encoding="utf-8"
    )
    (map_dir / "adjacencies.csv").write_text(_adjacency_csv(rows), encoding="utf-8")


def _write_mod(user_data: Path, name: str, *, rows=None, replace_path: str | None = "map",
               include_adjacencies: bool = True) -> tuple[Path, Path]:
    mod_root = user_data / "mod" / name
    map_dir = mod_root / "map"
    map_dir.mkdir(parents=True, exist_ok=True)
    (mod_root / "launcher-settings.json").write_text(
        json.dumps({"rawVersion": "v1.37.4.0"}), encoding="utf-8"
    )
    (map_dir / "default.map").write_text(
        'definitions = "definition.csv"\nadjacencies = "adjacencies.csv"\nmax_provinces = 9\n',
        encoding="utf-8",
    )
    (map_dir / "definition.csv").write_text(_definition_csv(), encoding="utf-8")
    adjacency_path = map_dir / "adjacencies.csv"
    if include_adjacencies:
        (adjacency_path).write_text(_adjacency_csv(rows or (_SEA_ROW,)), encoding="utf-8")
    descriptor = user_data / "mod" / f"{name}.mod"
    descriptor.parent.mkdir(parents=True, exist_ok=True)
    text = f'name="{name}"\npath="{str(mod_root).replace(chr(92), "/")}"\n'
    if replace_path is not None:
        text += f'replace_path="{replace_path}"\n'
    descriptor.write_text(text, encoding="utf-8")
    return descriptor, adjacency_path


def _query(province_id: int, fields=("straits",)) -> dict:
    return {"topic": "G03", "object": {"type": "province", "province_id": province_id},
            "fields": list(fields), "parameters": {}}


def _source(root: Path, user: Path | None = None, mods=()) -> StaticStraitsSource:
    return StaticStraitsSource(game_root=root, user_data=user or (root / "user"), enabled_mods=list(mods))


def _known_edges(field: dict, expected: list[dict]) -> None:
    assert field["status"] == "known"
    assert field["value"] == expected
    assert field["unit"] == "sea_connection"
    assert field["scale"] == 1
    assert field["period"] == "static_rules"
    assert field["complete"] is False


def test_only_explicit_sea_rows_are_returned_and_from_to_through_are_preserved(tmp_path):
    _write_map(tmp_path)
    source = _source(tmp_path)
    context = source.context()
    assert context["status"] == "ready"
    assert context["game_version"] == "1.37.4"

    for province_id in (1, 2, 7):
        result = source.read(_query(province_id), context)
        _known_edges(result["fields"]["straits"], [_EDGE])
        assert result["source"]["context_scope"] == "static_rules"
    # Through province 7 is intentionally absent from default.map sea_starts.
    # The explicit CSV row remains authoritative and is not rewritten by map heuristics.
    empty = source.read(_query(8), context)
    _known_edges(empty["fields"]["straits"], [])
    unknown = source.read(_query(99), context)
    assert unknown["fields"]["straits"]["status"] == "unknown"
    with pytest.raises(InformationError):
        source.read(_query(0), context)


def test_g03_catalog_and_query_do_not_expand_static_edges_into_access_or_country_pairs(tmp_path):
    _write_map(tmp_path)
    source = _source(tmp_path)
    topic = next(item for item in source.catalog() if item["topic_id"] == "G03")
    assert topic["object_types"] == ["province", "country_pair"]
    assert topic["fields"]["straits"]["supported_object_types"] == ["province"]

    province = source.read(_query(1, _FIELDS))
    _known_edges(province["fields"]["straits"], [_EDGE])
    for name in set(_FIELDS) - {"straits"}:
        assert province["fields"][name]["status"] == "unsupported"

    pair_query = {"topic": "G03", "object": {"type": "country_pair", "actor": "FRA", "recipient": "ENG"},
                  "fields": ["straits"], "parameters": {}}
    pair = source.read(pair_query)
    assert pair["fields"]["straits"] == {
        "status": "unknown", "reason": "COUNTRY_PAIR_STRAITS_NOT_IMPLEMENTED"
    }


def test_csv_parser_merges_identical_duplicate_sea_rows_but_rejects_conflicts_and_bad_ids():
    ids = parse_definition_ids(_definition_csv().encode("utf-8"))
    duplicate = _adjacency_csv((_SEA_ROW, "2;1;sea;7;-1;-1;-1;-1;same undirected edge"))
    parsed = parse_adjacencies(duplicate.encode("utf-8"), ids)
    assert parsed["edges"] == [{"from_province": 1, "to_province": 2,
                                 "through_province": 7, "source_lines": [2, 3]}]
    assert parsed["statistics"]["duplicate_sea_rows_merged"] == 1

    conflict = _adjacency_csv((_SEA_ROW, "2;1;sea;8;-1;-1;-1;-1;conflicting through"))
    with pytest.raises(ValueError, match="ADJACENCY_SEA_THROUGH_CONFLICT"):
        parse_adjacencies(conflict.encode("utf-8"), ids)
    undefined = _adjacency_csv(("1;99;sea;7;-1;-1;-1;-1;undefined endpoint",))
    with pytest.raises(ValueError, match="ADJACENCY_ENDPOINT_NOT_IN_DEFINITION"):
        parse_adjacencies(undefined.encode("utf-8"), ids)
    duplicate_definition = _definition_csv() + "1;9;0;0;duplicate\n"
    with pytest.raises(ValueError, match="DEFINITION_ID_DUPLICATE"):
        parse_definition_ids(duplicate_definition.encode("utf-8"))


@pytest.mark.parametrize("case", ("conflicting_sea_duplicate", "undefined_endpoint", "duplicate_definition_id"))
def test_invalid_static_inputs_withdraw_source_instead_of_reporting_empty_edges(tmp_path, case):
    if case == "conflicting_sea_duplicate":
        rows, definitions = (_SEA_ROW, "2;1;sea;8;-1;-1;-1;-1;conflict"), None
    elif case == "undefined_endpoint":
        rows, definitions = ("1;99;sea;7;-1;-1;-1;-1;undefined",), None
    else:
        rows, definitions = (_SEA_ROW,), _definition_csv() + "1;99;0;0;duplicate id\n"
    _write_map(tmp_path, rows=rows, definitions=definitions)
    source = _source(tmp_path)
    assert source.context()["status"] == "unready"
    result = source.read(_query(1))
    assert result["fields"]["straits"]["status"] == "unavailable"


def test_mod_replace_path_uses_mod_data_and_missing_adjacencies_do_not_fall_back(tmp_path):
    _write_map(tmp_path)
    user = tmp_path / "user"
    _descriptor, _ = _write_mod(
        user, "sea_override", rows=("4;5;sea;6;-1;-1;-1;-1;mod sea",), replace_path="map"
    )
    source = _source(tmp_path, user, ("mod/sea_override.mod",))
    assert source.context()["status"] == "ready"
    _known_edges(source.read(_query(1))["fields"]["straits"], [])
    _known_edges(source.read(_query(4))["fields"]["straits"], [
        {"from_province": 4, "to_province": 5, "through_province": 6, "source_lines": [2]}])

    missing_user = tmp_path / "missing-user"
    _descriptor, missing_csv = _write_mod(
        missing_user, "missing_adjacencies", include_adjacencies=False, replace_path="map"
    )
    missing_source = _source(tmp_path, missing_user, ("mod/missing_adjacencies.mod",))
    context = missing_source.context()
    assert context["status"] == "unready"
    assert missing_source.read(_query(1))["fields"]["straits"]["status"] == "unavailable"
    assert missing_csv.name == "adjacencies.csv"


def test_changed_input_and_new_mod_candidate_retract_the_static_read(tmp_path):
    _write_map(tmp_path)
    source = _source(tmp_path)
    assert source.context()["status"] == "ready"
    adjacency_path = tmp_path / "map" / "adjacencies.csv"
    adjacency_path.write_text(_adjacency_csv(("1;4;sea;7;-1;-1;-1;-1;changed",)), encoding="utf-8")
    changed = source.context()
    assert changed["status"] == "unready"
    assert source.read(_query(1))["fields"]["straits"]["status"] == "unavailable"

    root = tmp_path / "second-game"
    _write_map(root)
    user = root / "user"
    descriptor, candidate = _write_mod(user, "late_overlay", include_adjacencies=False, replace_path=None)
    # Keep the mod's map directory absent initially; the base input is selected.
    (user / "mod" / "late_overlay" / "map").rename(user / "mod" / "late_overlay" / "map.staged")
    candidate.unlink(missing_ok=True)
    late = _source(root, user, ("mod/late_overlay.mod",))
    assert late.context()["status"] == "ready"
    mod_map = user / "mod" / "late_overlay" / "map"
    (user / "mod" / "late_overlay" / "map.staged").rename(mod_map)
    candidate.write_text(_adjacency_csv(("4;5;sea;6;-1;-1;-1;-1;new candidate",)), encoding="utf-8")
    new_candidate = late.context()
    assert new_candidate["status"] == "unready"
    assert late.read(_query(1))["fields"]["straits"]["status"] == "unavailable"
    assert descriptor.is_file()


class _Clock:
    def __init__(self, now=100.0):
        self.now = float(now)

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += float(seconds)


class _Primary:
    event_types = ()

    def __init__(self):
        self.read_calls = 0

    def context(self):
        return {"status": "ready", "mode": "live", "session_id": "strait-session",
                "observer": "FRA", "game_version": "1.37.4", "game_sha256": "fixture-game",
                "world_id": "world-a", "game_date": "1456.1.1", "paused": True}

    def catalog(self):
        from bridge.information.catalog import list_topics
        return list_topics()

    def validate_query(self, query, context=None):
        from bridge.information.catalog import validate_query
        return validate_query(query, context)

    def read(self, _query, _context):
        self.read_calls += 1
        raise AssertionError("G03 province straits must be handled by StaticStraitsSource")

    def poll_events(self, context, cursor):
        return {"events": [], "cursor": cursor or {}, "complete": True, "gaps": []}


def test_information_service_query_report_and_real_seconds_subscription_share_static_source(tmp_path):
    from bridge.information.composite import CompositeSource
    from bridge.information.service import InformationService

    root = tmp_path / "game"
    _write_map(root)
    primary = _Primary()
    static = StaticStraitsSource(game_root=root, user_data=tmp_path / "user", enabled_mods=[],
                                 context_provider=primary.context)
    clock = _Clock()
    service = InformationService(CompositeSource(primary, [static]), tmp_path / "information.sqlite3",
                                 clock=clock, owner="straits-test")
    query = _query(1)
    try:
        catalog = {item["topic_id"]: item for item in service.source.catalog()}
        g03 = catalog["G03"]
        assert set(g03["fields"]) == set(_FIELDS)
        assert g03["object_types"] == ["province", "country_pair"]
        assert g03["fields"]["straits"]["coverage"] == "partial"
        assert all(g03["fields"][name]["coverage"] == "planned" for name in set(_FIELDS) - {"straits"})
        direct = service.query("straits-direct", queries=[query])
        item = direct["items"][0]
        _known_edges(item["fields"]["straits"], [_EDGE])
        assert item["source"]["context_scope"] == "static_rules"
        assert primary.read_calls == 0

        report = service.manage_report("straits-report-create", "create",
            config={"name": "static straits", "detail": "raw", "queries": [query]})["report"]
        reported = service.query("straits-report-run", report_id=report["id"])
        _known_edges(reported["items"][0]["fields"]["straits"], [_EDGE])

        context = primary.context()
        sub = service.manage_subscription("straits-sub-create", "create", config={
            "name": "static-straits-real-seconds", "kind": "periodic", "report_id": report["id"],
            "enabled": True,
            "binding": {key: context[key] for key in ("session_id", "observer", "game_version", "world_id")},
            "schedule": {"basis": "real", "every": 1, "unit": "seconds", "missed": "coalesce"},
        })["subscription"]
        clock.advance(1)
        ticked = service.tick()
        assert len(ticked["results"]) == 1
        periodic = ticked["results"][0]
        assert periodic["subscription_id"] == sub["id"]
        _known_edges(periodic["items"][0]["fields"]["straits"], [_EDGE])
        cancelled = service.manage_subscription("straits-sub-cancel", "cancel",
            subscription_id=sub["id"], expected_version=sub["version"])["subscription"]
        assert cancelled["state"] == "cancelled"
        assert primary.read_calls == 0
    finally:
        service.close()


def test_static_game_data_cli_flag_registers_straits_source_only_when_enabled(tmp_path):
    from tools.serve_information import _build_runtime, build_parser

    game = tmp_path / "game"
    _write_map(game)
    (game / "common" / "tradenodes").mkdir(parents=True)
    (game / "common" / "tradenodes" / "00_fixture.txt").write_text("fixture_node={}\n", encoding="utf-8")
    user = tmp_path / "user"
    enabled_args = build_parser().parse_args([
        "--database", str(tmp_path / "enabled.sqlite3"), "--static-game-data",
        "--static-game-root", str(game), "--static-user-data", str(user),
    ])
    enabled_service, enabled_journal = _build_runtime(enabled_args)
    try:
        adapters = enabled_service.source.adapters
        straits_adapter = next(adapter for adapter in adapters if isinstance(adapter, StaticStraitsSource))
        assert straits_adapter.index.lookup(1)["value"] == [_EDGE]
        routed = enabled_service.query("straits-factory-route", queries=[_query(1)])
        item = routed["items"][0]
        _known_edges(item["fields"]["straits"], [_EDGE])
        assert item["source"]["name"] == "StaticStraitsSource"
        assert item["source"]["context_scope"] == "static_rules"
    finally:
        enabled_service.close()
        if enabled_journal is not None:
            enabled_journal.close()

    disabled_args = build_parser().parse_args(["--database", str(tmp_path / "disabled.sqlite3")])
    disabled_service, disabled_journal = _build_runtime(disabled_args)
    try:
        assert not any(isinstance(adapter, StaticStraitsSource) for adapter in disabled_service.source.adapters)
    finally:
        disabled_service.close()
        if disabled_journal is not None:
            disabled_journal.close()
