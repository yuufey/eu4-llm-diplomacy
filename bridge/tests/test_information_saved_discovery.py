"""Historical C02 discovery-list projection over the existing Jomini snapshot."""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest

from bridge.information.composite import CompositeSource
from bridge.information.model import InformationError
from bridge.information.province_interests_v2 import SavedProvinceInterestsSourceV2
from bridge.information.saved_discovery import SavedProvinceDiscoverySource
from bridge.information.saved_province_interests_v2 import SavedProvinceInterestsSnapshotV2
from bridge.information.service import InformationService


def _document(*, provinces=None, schema="eu4.save_provinces_snapshot.v2"):
    return {
        "schema": schema,
        "saved_date": "1456.4.12",
        "saved_version": {"first": 1, "second": 37, "third": 4,
                          "fourth": 0, "name": "1.37.4.0"},
        "saved_player": "POR",
        "country_tags": ["FRA", "POR", "ENG"],
        "provinces": deepcopy(provinces if provinces is not None else [
            {"province_id": 186, "cores": ["FRA", "ENG"], "claims": ["POR"],
             "discovered_by": ["FRA", "POR"], "territorial_core": ["FRA"]},
            {"province_id": 183, "cores": ["FRA"], "claims": [],
             "discovered_by": ["FRA"], "territorial_core": None},
            {"province_id": 188, "cores": ["POR"], "claims": ["FRA"],
             "discovered_by": ["POR"], "territorial_core": None},
        ]),
    }


def _make_snapshot(tmp_path, document=None, *, observer="FRA"):
    tmp_path.mkdir(parents=True, exist_ok=True)
    save = tmp_path / "historical.eu4"
    save.write_bytes(b"bounded test archive")
    parsed = deepcopy(document if document is not None else _document())
    parser_calls = []

    def parser(path):
        parser_calls.append(Path(path))
        assert Path(path) == save.resolve()
        return deepcopy(parsed)

    snapshot = SavedProvinceInterestsSnapshotV2(save, observer, parser=parser)
    return save, snapshot, parser_calls


def _query(obj=None, fields=None, *, parameters=None):
    return {"topic": "C02", "object": deepcopy(obj or {"type": "session"}),
            "fields": list(fields if fields is not None else ["discovered_provinces"]),
            "parameters": deepcopy(parameters if parameters is not None else {})}


def _source(tmp_path, document=None, *, observer="FRA"):
    save, snapshot, calls = _make_snapshot(tmp_path, document, observer=observer)
    return save, snapshot, SavedProvinceDiscoverySource(snapshot), calls


def _read(source, query, context=None):
    return source.read(query, source.context() if context is None else context)


def test_projection_returns_only_positive_observer_ids_and_stays_partial(tmp_path):
    _save, snapshot, source, parser_calls = _source(tmp_path)
    result = _read(source, _query())
    field = result["fields"]["discovered_provinces"]

    assert field == {
        "status": "known", "value": [183, 186], "unit": "province_id", "scale": 1,
        "period": "saved_snapshot", "complete": False,
        "basis": "saved_province.discovered_by",
        "snapshot_membership_complete": True,
        "omitted_unknown_discovery_records": 0,
    }
    assert result["complete"] is False
    assert result["source"]["context_scope"] == "saved_snapshot"
    assert result["source"]["mode"] == "recorded"
    assert result["source"]["provenance"]["live_state_observed"] is False
    assert parser_calls == [snapshot.path]


def test_missing_discovery_records_preserve_positive_subset_but_not_completeness(tmp_path):
    rows = [
        {"province_id": 186, "cores": ["FRA"], "claims": [], "discovered_by": ["FRA"]},
        {"province_id": 188, "cores": ["POR"], "claims": []},
        {"province_id": 189, "cores": [], "claims": [], "discovered_by": ["POR"]},
    ]
    _save, snapshot, source, _calls = _source(tmp_path, _document(provinces=rows))
    field = _read(source, _query())["fields"]["discovered_provinces"]

    assert field["status"] == "known" and field["value"] == [186]
    assert field["complete"] is False
    assert field["snapshot_membership_complete"] is False
    assert field["omitted_unknown_discovery_records"] == 1
    assert "FRA" not in repr(field) and "POR" not in repr(field)
    assert snapshot.discovered_provinces()["omitted_unknown_discovery_records"] == 1


def test_no_positive_ids_with_missing_records_is_unknown_not_empty(tmp_path):
    rows = [
        {"province_id": 188, "cores": ["POR"], "claims": [], "discovered_by": ["POR"]},
        {"province_id": 189, "cores": [], "claims": []},
    ]
    _save, _snapshot, source, _calls = _source(tmp_path, _document(provinces=rows))
    field = _read(source, _query())["fields"]["discovered_provinces"]
    assert field["status"] == "unknown"
    assert field["reason"] == "SNAPSHOT_DISCOVERY_NOT_ESTABLISHED"
    assert field["snapshot_membership_complete"] is False
    assert field["omitted_unknown_discovery_records"] == 1
    assert "value" not in field


def test_explicitly_empty_observer_membership_is_known_empty_only_if_all_rows_explicit(tmp_path):
    rows = [
        {"province_id": 188, "cores": ["POR"], "claims": [], "discovered_by": ["POR"]},
        {"province_id": 189, "cores": [], "claims": [], "discovered_by": ["ENG"]},
    ]
    _save, _snapshot, source, _calls = _source(tmp_path, _document(provinces=rows))
    field = _read(source, _query())["fields"]["discovered_provinces"]
    assert field["status"] == "known" and field["value"] == []
    assert field["snapshot_membership_complete"] is True
    assert field["omitted_unknown_discovery_records"] == 0
    assert field["complete"] is False


def test_view_is_limited_to_the_observer_and_session_selector(tmp_path):
    _save, _snapshot, source, _calls = _source(tmp_path)
    session_result = _read(source, _query({"type": "session"}))
    own = _read(source, _query({"type": "country", "country": "FRA"}))
    foreign = _read(source, _query({"type": "country", "country": "ENG"}))
    assert session_result["fields"]["discovered_provinces"]["value"] == [183, 186]
    assert own["fields"]["discovered_provinces"] == session_result["fields"]["discovered_provinces"]
    assert foreign["fields"]["discovered_provinces"] == {
        "status": "not_applicable", "reason": "OBSERVER_DISCOVERY_VIEW_ONLY"}

    _save2, _snapshot2, player_source, _calls2 = _source(tmp_path / "player", observer="POR")
    player = _read(player_source, _query({"type": "session"}))
    assert player["fields"]["discovered_provinces"]["value"] == [186, 188]
    assert _read(player_source, _query({"type": "country", "country": "FRA"}))["fields"]["discovered_provinces"] == {
        "status": "not_applicable", "reason": "OBSERVER_DISCOVERY_VIEW_ONLY"}


@pytest.mark.parametrize("query", [
    {"topic": "C02", "object": {"type": "session", "session_id": "invented"},
     "fields": ["discovered_provinces"], "parameters": {}},
    {"topic": "C02", "object": {"type": "country", "country": "fra"},
     "fields": ["discovered_provinces"], "parameters": {}},
    {"topic": "C02", "object": {"type": "session"},
     "fields": ["discovered_provinces"], "parameters": {"actor": "FRA"}},
    {"topic": "C02", "object": {"type": "session"},
     "fields": ["discovered_provinces", "discovered_provinces"], "parameters": {}},
])
def test_invalid_selectors_fields_and_parameters_are_rejected_before_projection(tmp_path, query):
    _save, snapshot, source, _calls = _source(tmp_path)
    with pytest.raises(InformationError):
        source.read(query, source.context())
    assert snapshot.discovered_provinces()["value"] == [183, 186]


def test_unowned_c02_fields_remain_unsupported(tmp_path):
    _save, _snapshot, source, _calls = _source(tmp_path)
    result = _read(source, _query(fields=["discovered_provinces", "discovered_countries"]))
    assert result["fields"]["discovered_provinces"]["status"] == "known"
    assert result["fields"]["discovered_countries"] == {
        "status": "unsupported", "reason": "SAVED_DISCOVERY_FIELD_NOT_IMPLEMENTED"}


def test_stale_context_and_changed_archive_retract_the_snapshot_field(tmp_path):
    save, snapshot, source, parser_calls = _source(tmp_path)
    stale = source.context()
    stale["game_date"] = "1456.4.13"
    result = _read(source, _query(), stale)
    assert result["fields"]["discovered_provinces"] == {
        "status": "unavailable", "reason": "SAVED_DISCOVERY_CONTEXT_MISMATCH"}
    assert parser_calls == [save.resolve()]

    save.write_bytes(b"changed archive")
    changed = _read(source, _query())
    assert changed["fields"]["discovered_provinces"]["status"] == "unavailable"
    assert changed["fields"]["discovered_provinces"]["reason"] in {
        "SAVED_DISCOVERY_SOURCE_UNREADY",
        "SAVED_DISCOVERY_INPUT_OR_PROJECTION_CHANGED",
        "SAVED_DISCOVERY_INPUT_OR_PARSER_CHANGED",
    }
    assert parser_calls == [save.resolve()]


def test_projection_whitelists_values_and_returns_detached_lists(tmp_path, monkeypatch):
    _save, snapshot, source, _calls = _source(tmp_path)
    original = snapshot.discovered_provinces

    def noisy_projection():
        return {**original(), "foreign_discovery": {"ENG": [188]},
                "raw_pointer": "0x12345678", "read_trace": [{"address": "0x88"}]}

    monkeypatch.setattr(snapshot, "discovered_provinces", noisy_projection)
    first = _read(source, _query())
    field = first["fields"]["discovered_provinces"]
    assert field["value"] == [183, 186]
    assert set(field) == {"status", "value", "unit", "scale", "period", "complete", "basis",
                          "snapshot_membership_complete", "omitted_unknown_discovery_records"}
    assert "0x12345678" not in repr(first) and "foreign_discovery" not in repr(first)
    field["value"].clear()
    second = _read(source, _query())
    assert second["fields"]["discovered_provinces"]["value"] == [183, 186]


def test_catalog_is_narrow_query_only_and_composes_with_existing_g01_single_parse(tmp_path):
    save, snapshot, parser_calls = _make_snapshot(tmp_path)
    interests = SavedProvinceInterestsSourceV2(snapshot)
    discovery = SavedProvinceDiscoverySource(snapshot)
    owned = discovery.catalog()[0]
    assert set(owned["fields"]) == {"discovered_provinces"}
    assert owned["triggers"] == ["query"]
    assert owned["fields"]["discovered_provinces"]["coverage"] == "partial"

    composite = CompositeSource(interests, [discovery])
    catalog = next(item for item in composite.catalog() if item["topic_id"] == "C02")
    assert catalog["fields"]["discovered_provinces"]["coverage"] == "partial"
    assert all(value["coverage"] == "planned" for key, value in catalog["fields"].items()
               if key != "discovered_provinces")

    service = InformationService(composite, tmp_path / "shared-snapshot.sqlite3")
    try:
        g01 = service.query("saved-discovery-g01", queries=[{
            "topic": "G01", "object": {"type": "province", "province_id": 186},
            "fields": ["cores"], "parameters": {},
        }])
        c02 = service.query("saved-discovery-c02", queries=[_query()])
        assert g01["items"][0]["fields"]["cores"]["status"] == "known"
        assert c02["items"][0]["fields"]["discovered_provinces"]["value"] == [183, 186]
        assert parser_calls == [save.resolve()]
    finally:
        service.close()


def test_report_reuses_snapshot_results_and_periodic_subscription_is_rejected(tmp_path):
    save, snapshot, parser_calls = _make_snapshot(tmp_path)
    composite = CompositeSource(SavedProvinceInterestsSourceV2(snapshot),
                                [SavedProvinceDiscoverySource(snapshot)])
    service = InformationService(composite, tmp_path / "snapshot-report.sqlite3")
    query = _query()
    try:
        direct = service.query("discovery-direct", queries=[query])
        report = service.manage_report("discovery-report-create", "create", config={
            "name": "snapshot discovery", "detail": "raw", "queries": [query],
        })["report"]
        rendered = service.query("discovery-report-query", report_id=report["id"])
        assert direct["items"][0]["fields"] == rendered["items"][0]["fields"]
        assert direct["complete"] is rendered["complete"] is False
        with pytest.raises(InformationError) as error:
            service.manage_subscription("discovery-periodic", "create", config={
                "kind": "periodic", "report_id": report["id"],
                "binding": {"session_id": "", "observer": "FRA", "game_version": "1.37.4"},
                "schedule": {"basis": "real", "every": 2, "unit": "seconds"},
            })
        assert error.value.code == "invalid_binding"
        assert service.manage_subscription("discovery-subscriptions", "list")["subscriptions"] == []
        assert parser_calls == [save.resolve()]
    finally:
        service.close()


def test_saved_factory_shares_snapshot_and_does_not_add_live_native_adapters(
        tmp_path, monkeypatch):
    from tools.serve_information import _build_runtime, build_parser
    from bridge.information import saved_province_interests_v2 as snapshot_module

    save = tmp_path / "factory.eu4"
    save.write_bytes(b"factory test archive")
    document = _document()
    parser_calls = []
    snapshot_instances = []
    original = snapshot_module.SavedProvinceInterestsSnapshotV2

    def make_snapshot(path, observer, *, parser_manifest=None):
        def parser(parse_path):
            parser_calls.append(Path(parse_path))
            return deepcopy(document)
        snapshot = original(path, observer, parser=parser, parser_manifest=parser_manifest)
        snapshot_instances.append(snapshot)
        return snapshot

    monkeypatch.setattr(snapshot_module, "SavedProvinceInterestsSnapshotV2", make_snapshot)
    args = build_parser().parse_args(["--province-interest-save", str(save), "--observer", "FRA",
                                      "--database", str(tmp_path / "factory.sqlite3")])
    service, journal = _build_runtime(args)
    try:
        assert journal is None
        adapters = service.source.adapters
        assert [type(adapter).__name__ for adapter in adapters] == ["SavedProvinceDiscoverySource"]
        assert adapters[0].snapshot is snapshot_instances[0]
        primary = service.source.primary
        assert isinstance(primary, SavedProvinceInterestsSourceV2)
        assert primary.snapshot is snapshot_instances[0]
        result = service.query("factory-discovery", queries=[_query()])
        assert result["items"][0]["fields"]["discovered_provinces"]["value"] == [183, 186]
        assert len(snapshot_instances) == 1
        assert parser_calls == [save.resolve()]
    finally:
        service.close()


def test_default_factory_uses_live_discovery_and_does_not_register_saved_source(tmp_path):
    from tools.serve_information import _build_runtime, build_parser

    args = build_parser().parse_args(["--observer", "FRA", "--database",
                                      str(tmp_path / "default.sqlite3")])
    service, journal = _build_runtime(args)
    try:
        assert journal is None
        assert not any(type(adapter).__name__ == "SavedProvinceDiscoverySource"
                       for adapter in service.source.adapters)
        c02 = next(item for item in service.source.catalog() if item["topic_id"] == "C02")
        assert any(type(adapter).__name__ == "NativeProvinceDiscoverySource"
                   for adapter in service.source.adapters)
        assert c02["fields"]["discovered_provinces"]["coverage"] == "partial"
        assert c02["fields"]["discovered_provinces"]["period"] == "current"
    finally:
        service.close()


def test_cli_help_names_snapshot_scope_and_query_report_only():
    from tools.serve_information import build_parser

    help_text = " ".join(build_parser().format_help().split())
    assert "--province-interest-save" in help_text
    assert "historical save" in help_text
    assert "snapshot queries/reports only" in help_text
