"""The historical HRE source must not acquire a live state adapter."""
from copy import deepcopy
from pathlib import Path

import pytest

from tools.serve_information import _build_runtime, build_parser


@pytest.mark.parametrize("additional", [
    ["--operator-session", "installation.json"],
    ["--recorded-manifest", "manifest.json"],
    ["--mission-save", "mission.eu4"],
    ["--mission-game-data"],
    ["--province-interest-save", "province.eu4"],
    ["--battle-stream", "battle.json"],
    ["--battle-ingest-installation", "installation.json"],
    ["--battle-manage-capture"],
])
def test_empire_factory_rejects_mixed_state_sources_before_opening_them(additional, tmp_path):
    args = build_parser().parse_args([
        "--empire-save", str(tmp_path / "unopened.eu4"), "--observer", "FRA", *additional,
    ])
    with pytest.raises(ValueError, match="cannot be combined"):
        _build_runtime(args)


def test_empire_factory_requires_observer_and_binds_manifest_to_save(tmp_path):
    parser = build_parser()
    with pytest.raises(ValueError, match="requires --observer"):
        _build_runtime(parser.parse_args(["--empire-save", str(tmp_path / "unopened.eu4")]))
    with pytest.raises(ValueError, match="requires --empire-save"):
        _build_runtime(parser.parse_args(["--empire-parser-manifest", "unopened.json"]))


def test_empire_factory_uses_historical_source_without_native_adapters(monkeypatch, tmp_path):
    from bridge.information import saved_empire_v2, country_records
    from bridge.information.empire_snapshot import SavedEmpireSource

    path = tmp_path / "snapshot.eu4"
    path.write_bytes(b"historical HRE fixture")
    document = {
        "schema": "eu4.save_empire_snapshot.v1", "saved_date": "1456.4.12",
        "saved_version": {"first": 1, "second": 37, "third": 4, "fourth": 0, "name": "1.37.4.0"},
        "saved_player": "POR", "country_tags": ["FRA", "POR", "HAB", "BOH"],
        "empire": {"emperor": "HAB", "electors": ["BOH"], "passed_reforms": None},
    }
    original = saved_empire_v2.SavedEmpireSnapshotV2
    calls = []

    def snapshot(save, observer, *, parser_manifest):
        calls.append((save, observer, parser_manifest))
        return original(save, observer, parser=lambda _: deepcopy(document))

    def native_adapter(*_args, **_kwargs):
        pytest.fail("historical empire source acquired a live country-record adapter")

    monkeypatch.setattr(saved_empire_v2, "SavedEmpireSnapshotV2", snapshot)
    monkeypatch.setattr(country_records, "NativeCountryRecordsSource", native_adapter)
    manifest = tmp_path / "selected-parser.json"
    args = build_parser().parse_args([
        "--empire-save", str(path), "--observer", "FRA",
        "--empire-parser-manifest", str(manifest), "--database", str(tmp_path / "info.sqlite3"),
    ])
    service, journal = _build_runtime(args)
    try:
        assert journal is None and isinstance(service.source, SavedEmpireSource)
        assert calls == [(path, "FRA", manifest)]
        context = service.source.context()
        assert context["mode"] == "recorded" and context["session_id"] is None
        assert context["observer"] == "FRA" and context["archive"]["player"] == "POR"
        result = service.source.read({"topic": "S01", "object": {"type": "session"},
                                      "fields": ["emperor", "electors", "reforms"]}, context)
        assert result["fields"]["emperor"]["value"] == "HAB"
        assert result["fields"]["electors"]["value"] == ["BOH"]
        assert result["fields"]["reforms"]["status"] == "unknown"
    finally:
        service.close()
