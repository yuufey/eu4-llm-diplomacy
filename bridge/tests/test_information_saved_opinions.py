"""Bounded, presence-aware projection of historical bilateral opinion records."""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest

from bridge.information.composite import CompositeSource
from bridge.information.model import InformationError
from bridge.information.opinion_snapshot import SavedOpinionSource
from bridge.information.saved_opinions import SavedOpinionSnapshot
from bridge.information.service import InformationService


def _record(modifier="opinion_from_event", date="1457.1.2", current_opinion="12.375",
            expiry_date=False):
    return {"modifier": modifier, "date": date,
            "current_opinion": current_opinion, "expiry_date": expiry_date}


def _document(*, countries=None, relation_projection=None):
    document = {
        "schema": "eu4.save_opinion_snapshot.v1",
        "saved_date": "1456.4.12",
        "saved_version": {"first": 1, "second": 37, "third": 4,
                          "fourth": 0, "name": "1.37.4.0"},
        "saved_player": "POR",
        "country_tags": ["ENG", "FRA", "POR"],
        "countries": deepcopy(countries if countries is not None else [
            {"country": "FRA", "active_relations": [
                {"country": "ENG", "opinions": [_record("alliance", "1455.6.1", "25.000", False)]},
                {"country": "POR", "opinions": [_record("guarantee", "1454.1.1", "4.5", True)]},
            ]},
            {"country": "ENG", "active_relations": [
                {"country": "FRA", "opinions": [_record("royal_marriage", "1455.12.31", "-7.25", False)]},
            ]},
            {"country": "POR", "active_relations": []},
        ]),
    }
    if relation_projection is not None:
        document["relation_projection"] = relation_projection
    return document


def _snapshot(tmp_path, document=None, *, observer="FRA"):
    tmp_path.mkdir(parents=True, exist_ok=True)
    save = tmp_path / "opinions.eu4"
    save.write_bytes(b"bounded opinion test archive")
    parsed = deepcopy(document if document is not None else _document())
    parser_calls = []

    def parser(path):
        parser_calls.append(Path(path))
        assert Path(path) == save.resolve()
        return deepcopy(parsed)

    snapshot = SavedOpinionSnapshot(save, observer, parser=parser)
    return save, snapshot, parser_calls


def _query(actor="FRA", recipient="ENG", *, fields=None, parameters=None):
    return {
        "topic": "R04",
        "object": {"type": "country_pair", "actor": actor, "recipient": recipient},
        "fields": list(fields if fields is not None else ["opinion_modifiers"]),
        "parameters": deepcopy(parameters if parameters is not None else {}),
    }


def _read(source, query, context=None):
    return source.read(query, source.context() if context is None else context)


def _field(result):
    return result["fields"]["opinion_modifiers"]


def test_pair_returns_two_directed_records_without_collapsing_values_or_dates(tmp_path):
    _save, snapshot, _calls = _snapshot(tmp_path)
    source = SavedOpinionSource(snapshot)

    field = _field(_read(source, _query()))
    assert field == {
        "status": "known",
        "value": [
            {"holder": "FRA", "target": "ENG", "status": "known", "records": [
                {"modifier_id": "alliance", "recorded_date": "1455.6.1",
                 "current_opinion_decimal": "25.000", "expiry_date_flag": False},
            ]},
            {"holder": "ENG", "target": "FRA", "status": "known", "records": [
                {"modifier_id": "royal_marriage", "recorded_date": "1455.12.31",
                 "current_opinion_decimal": "-7.25", "expiry_date_flag": False},
            ]},
        ],
        "unit": "directed_saved_opinion_modifiers", "scale": 1,
        "period": "saved_snapshot", "complete": False,
        "basis": "saved_country.active_relations.opinion",
    }
    assert field["value"][0]["holder"] != field["value"][0]["target"]
    assert source.context()["session_id"] is None
    assert source.context()["mode"] == "recorded"


def test_reversing_pair_reverses_direction_order_but_keeps_saved_values(tmp_path):
    _save, snapshot, _calls = _snapshot(tmp_path)
    source = SavedOpinionSource(snapshot)
    forward = _field(_read(source, _query("FRA", "ENG")))
    reverse = _field(_read(source, _query("ENG", "FRA")))

    assert [tuple((row["holder"], row["target"])) for row in forward["value"]] == [
        ("FRA", "ENG"), ("ENG", "FRA")]
    assert [tuple((row["holder"], row["target"])) for row in reverse["value"]] == [
        ("ENG", "FRA"), ("FRA", "ENG")]
    assert reverse["value"] == list(reversed(forward["value"]))


def test_one_known_direction_keeps_the_other_direction_unknown(tmp_path):
    rows = [
        {"country": "FRA", "active_relations": [
            {"country": "ENG", "opinions": [_record("known", "1456.4.12", "3.125", True)]},
        ]},
        {"country": "ENG", "active_relations": None},
        {"country": "POR", "active_relations": []},
    ]
    _save, snapshot, _calls = _snapshot(tmp_path, _document(countries=rows))
    field = _field(_read(SavedOpinionSource(snapshot), _query()))

    assert field["status"] == "known" and field["complete"] is False
    assert field["value"][0] == {
        "holder": "FRA", "target": "ENG", "status": "known",
        "records": [{"modifier_id": "known", "recorded_date": "1456.4.12",
                     "current_opinion_decimal": "3.125", "expiry_date_flag": True}],
    }
    assert field["value"][1]["status"] == "unknown"
    assert field["value"][1]["reason"] == "SAVED_ACTIVE_RELATIONS_NOT_CAPTURED"
    assert "records" not in field["value"][1]


def test_two_unestablished_directions_are_unknown_without_empty_value(tmp_path):
    rows = [
        {"country": "FRA", "active_relations": None},
        {"country": "ENG", "active_relations": []},
        {"country": "POR", "active_relations": []},
    ]
    _save, snapshot, _calls = _snapshot(tmp_path, _document(countries=rows))
    field = _field(_read(SavedOpinionSource(snapshot), _query()))

    assert field["status"] == "unknown"
    assert field["reason"] == "SAVED_OPINION_RELATIONS_NOT_ESTABLISHED"
    assert "value" not in field
    assert [row["status"] for row in field["directions"]] == ["unknown", "unknown"]
    assert all("records" not in row for row in field["directions"])


def test_projection_mode_is_preserved_in_parser_context_and_public_provenance(tmp_path):
    document = _document(relation_projection="serialized_opinion_entries_only")
    _save, snapshot, _calls = _snapshot(tmp_path, document)
    source = SavedOpinionSource(snapshot)

    assert source.context()["parser"]["relation_projection"] == "serialized_opinion_entries_only"
    result = _read(source, _query())
    assert result["source"]["provenance"]["parser"]["relation_projection"] == \
        "serialized_opinion_entries_only"


def test_filtered_absent_direction_stays_unknown_instead_of_becoming_empty(tmp_path):
    rows = [
        {"country": "FRA", "active_relations": []},
        {"country": "ENG", "active_relations": [
            {"country": "FRA", "opinions": [_record("reverse_only", "1456.1.1", "2.0", False)]},
        ]},
        {"country": "POR", "active_relations": []},
    ]
    document = _document(countries=rows,
                         relation_projection="serialized_opinion_entries_only")
    _save, snapshot, _calls = _snapshot(tmp_path, document)
    field = _field(_read(SavedOpinionSource(snapshot), _query()))

    assert field["status"] == "known"
    assert field["value"][0] == {
        "holder": "FRA", "target": "ENG", "status": "unknown",
        "reason": "SAVED_OPINION_RECORDS_NOT_ESTABLISHED",
    }
    assert "records" not in field["value"][0]
    assert field["value"][1]["status"] == "known"
    assert field["value"][1]["records"][0]["modifier_id"] == "reverse_only"


def test_unknown_relation_projection_metadata_is_rejected(tmp_path):
    document = _document(relation_projection="all_relationship_rows_and_opinions")
    tmp_path.mkdir(parents=True, exist_ok=True)
    save = tmp_path / "invalid-projection.eu4"
    save.write_bytes(b"invalid projection mode")
    with pytest.raises(ValueError, match="SAVED_OPINION_RELATION_PROJECTION_INVALID"):
        SavedOpinionSnapshot(save, "FRA", parser=lambda _path: deepcopy(document))


@pytest.mark.parametrize("relations", [
    None,
    [],
    [{"country": "ENG", "opinions": None}],
    [{"country": "ENG", "opinions": []}],
])
def test_missing_relation_or_empty_opinion_list_does_not_become_known_empty(tmp_path, relations):
    rows = [
        {"country": "FRA", "active_relations": relations},
        {"country": "ENG", "active_relations": []},
        {"country": "POR", "active_relations": []},
    ]
    _save, snapshot, _calls = _snapshot(tmp_path, _document(countries=rows))
    field = _field(_read(SavedOpinionSource(snapshot), _query()))
    assert field["status"] == "unknown" and "value" not in field
    assert field["directions"][0]["status"] == "unknown"
    assert "records" not in field["directions"][0]


def test_nullable_record_fields_and_false_expiry_flag_are_preserved(tmp_path):
    record = {"modifier": "dated_modifier", "date": None,
              "current_opinion": None, "expiry_date": False}
    rows = [
        {"country": "FRA", "active_relations": [{"country": "ENG", "opinions": [record]}]},
        {"country": "ENG", "active_relations": [{"country": "FRA", "opinions": [_record()]}]},
        {"country": "POR", "active_relations": []},
    ]
    _save, snapshot, _calls = _snapshot(tmp_path, _document(countries=rows))
    field = _field(_read(SavedOpinionSource(snapshot), _query()))
    assert field["value"][0]["records"] == [{
        "modifier_id": "dated_modifier", "recorded_date": None,
        "current_opinion_decimal": None, "expiry_date_flag": False,
    }]


def test_future_recorded_dates_are_preserved_without_expiry_evaluation(tmp_path):
    rows = [
        {"country": "FRA", "active_relations": [
            {"country": "ENG", "opinions": [_record("future", "9999.12.31", "1.0", True)]},
        ]},
        {"country": "ENG", "active_relations": [{"country": "FRA", "opinions": [_record()]}]},
        {"country": "POR", "active_relations": []},
    ]
    _save, snapshot, _calls = _snapshot(tmp_path, _document(countries=rows))
    result = _read(SavedOpinionSource(snapshot), _query())
    record = _field(result)["value"][0]["records"][0]
    assert record["recorded_date"] == "9999.12.31"
    assert record["expiry_date_flag"] is True
    assert result["source"]["provenance"]["final_opinion_evaluated"] is False
    assert result["source"]["provenance"]["decay_or_end_date_evaluated"] is False


@pytest.mark.parametrize("query", [
    {"topic": "R04", "object": {"type": "country_pair", "actor": "FRA", "recipient": "FRA"},
     "fields": ["opinion_modifiers"], "parameters": {}},
    {"topic": "R04", "object": {"type": "country_pair", "actor": "fra", "recipient": "ENG"},
     "fields": ["opinion_modifiers"], "parameters": {}},
    {"topic": "R04", "object": {"type": "country_pair", "actor": "FRA", "recipient": "ENG",
                                    "extra": "value"},
     "fields": ["opinion_modifiers"], "parameters": {}},
    {"topic": "R04", "object": {"type": "country_pair", "actor": "FRA", "recipient": "ENG"},
     "fields": ["opinion_modifiers"], "parameters": {"direction": "both"}},
])
def test_invalid_pair_or_nonempty_parameters_are_rejected(tmp_path, query):
    _save, snapshot, _calls = _snapshot(tmp_path)
    with pytest.raises(InformationError):
        SavedOpinionSource(snapshot).read(query, snapshot.context())


def test_pair_must_involve_observer_including_saved_player(tmp_path):
    _save, snapshot, _calls = _snapshot(tmp_path)
    source = SavedOpinionSource(snapshot)
    unrelated = _field(_read(source, _query("ENG", "POR")))
    assert unrelated == {"status": "not_applicable", "reason": "OBSERVER_COUNTRY_PAIR_REQUIRED"}

    _save2, player_snapshot, _calls2 = _snapshot(tmp_path / "player", observer="POR")
    player = _field(_read(SavedOpinionSource(player_snapshot), _query("POR", "FRA")))
    assert player["status"] == "known"
    assert player["value"][1]["holder"] == "FRA"
    assert player["value"][1]["records"][0]["modifier_id"] == "guarantee"


def test_other_r04_fields_remain_unsupported(tmp_path):
    _save, snapshot, _calls = _snapshot(tmp_path)
    result = _read(SavedOpinionSource(snapshot), _query(fields=[
        "opinion_modifiers", "opinion", "decay", "end_date"]))
    assert result["fields"]["opinion_modifiers"]["status"] == "known"
    for name in ("opinion", "decay", "end_date"):
        assert result["fields"][name] == {
            "status": "unsupported", "reason": "SAVED_OPINION_FIELD_NOT_IMPLEMENTED"}


def test_c01_and_r04_catalog_keep_only_four_c01_fields_and_one_partial_r04_field(tmp_path):
    _save, snapshot, _calls = _snapshot(tmp_path)
    catalog = {topic["topic_id"]: topic for topic in SavedOpinionSource(snapshot).catalog()}
    assert set(catalog["C01"]["fields"]) == {
        "session_id", "game_date", "game_day", "observer", "game_version", "game_sha256",
        "dll_sha256", "world_id", "paused", "status",
    }
    assert {name for name, meta in catalog["C01"]["fields"].items()
            if meta["coverage"] == "available"} == {"observer", "game_date", "game_version", "status"}
    assert catalog["R04"]["fields"]["opinion_modifiers"]["coverage"] == "partial"
    assert catalog["R04"]["fields"]["opinion_modifiers"]["complete"] is False
    assert {name for name, meta in catalog["R04"]["fields"].items()
            if meta["coverage"] == "partial"} == {"opinion_modifiers"}
    assert {name for name, meta in catalog["R04"]["fields"].items()
            if meta["coverage"] == "planned"} == {"opinion", "decay", "end_date"}


def test_source_whitelist_does_not_copy_cached_sum_or_extra_payload(tmp_path, monkeypatch):
    _save, snapshot, _calls = _snapshot(tmp_path)
    original = snapshot.lookup_pair

    def noisy(obj):
        return {**original(obj), "cached_sum": 999, "trust": 10,
                "raw_pointer": "0x12345678", "all_country_opinions": {"POR": ["hidden"]}}

    monkeypatch.setattr(snapshot, "lookup_pair", noisy)
    result = _read(SavedOpinionSource(snapshot), _query())
    field = _field(result)
    assert set(field) == {"status", "value", "unit", "scale", "period", "complete", "basis"}
    assert "cached_sum" not in repr(result) and "0x12345678" not in repr(result)
    assert "all_country_opinions" not in repr(result) and "trust" not in repr(field)
    field["value"][0]["records"].clear()
    assert _field(_read(SavedOpinionSource(snapshot), _query()))["value"][0]["records"]


def test_context_or_archive_drift_retracts_opinion_field(tmp_path):
    save, snapshot, _calls = _snapshot(tmp_path)
    source = SavedOpinionSource(snapshot)
    stale = source.context()
    stale["game_date"] = "1456.4.13"
    field = _field(_read(source, _query(), stale))
    assert field == {"status": "unavailable", "reason": "SAVED_OPINION_CONTEXT_MISMATCH"}

    save.write_bytes(b"changed opinion archive")
    changed = _field(_read(source, _query()))
    assert changed["status"] == "unavailable"
    assert changed["reason"] in {
        "SAVED_OPINION_SOURCE_UNREADY",
        "SAVED_OPINION_INPUT_OR_PROJECTION_CHANGED",
        "SAVED_OPINION_INPUT_OR_PARSER_CHANGED",
    }


def test_report_reuses_same_historical_field_and_periodic_requires_nonempty_session(tmp_path):
    _save, snapshot, _calls = _snapshot(tmp_path)
    source = SavedOpinionSource(snapshot)
    service = InformationService(source, tmp_path / "opinions.sqlite3")
    query = _query()
    try:
        direct = service.query("opinion-direct", queries=[query])
        report = service.manage_report("opinion-report-create", "create", config={
            "name": "saved opinion pair", "detail": "raw", "queries": [query],
        })["report"]
        rendered = service.query("opinion-report-run", report_id=report["id"])
        assert direct["items"][0]["fields"] == rendered["items"][0]["fields"]
        assert direct["complete"] is rendered["complete"] is False
        assert _field(direct["items"][0])["value"] == _field(rendered["items"][0])["value"]

        with pytest.raises(InformationError) as error:
            service.manage_subscription("opinion-periodic", "create", config={
                "name": "snapshot periodic", "kind": "periodic", "report_id": report["id"],
                "binding": {"session_id": "", "observer": "FRA", "game_version": "1.37.4"},
                "schedule": {"basis": "real", "every": 2, "unit": "seconds"},
            })
        assert error.value.code == "invalid_binding"
        assert service.manage_subscription("opinion-subscriptions", "list")["subscriptions"] == []
    finally:
        service.close()


def test_factory_uses_one_opinion_snapshot_as_primary_and_does_not_build_native_adapters(
        tmp_path, monkeypatch):
    from tools.serve_information import _build_runtime, build_parser
    from bridge.information import saved_opinions as opinion_module

    save = tmp_path / "factory.eu4"
    save.write_bytes(b"factory opinion archive")
    document = _document()
    calls, instances = [], []
    original = opinion_module.SavedOpinionSnapshot

    def make_snapshot(path, observer, *, parser=None, parser_manifest=None):
        def fake_parser(parse_path):
            calls.append(Path(parse_path))
            assert Path(parse_path) == save.resolve()
            return deepcopy(document)
        instance = original(path, observer, parser=fake_parser, parser_manifest=parser_manifest)
        instances.append(instance)
        return instance

    monkeypatch.setattr(opinion_module, "SavedOpinionSnapshot", make_snapshot)
    args = build_parser().parse_args(["--opinion-save", str(save), "--observer", "FRA",
                                      "--database", str(tmp_path / "factory.sqlite3")])
    service, journal = _build_runtime(args)
    try:
        assert journal is None
        assert isinstance(service.source, SavedOpinionSource)
        assert service.source.snapshot is instances[0]
        assert service.source.snapshot.context()["session_id"] is None
        result = service.query("opinion-factory", queries=[_query()])
        assert _field(result["items"][0])["status"] == "known"
        assert calls == [save.resolve()]
        assert len(instances) == 1
    finally:
        service.close()


@pytest.mark.parametrize("extra", [
    ["--operator-session", "unused-installation.json"],
    ["--recorded-manifest", "unused-recorded.json"],
    ["--mission-game-data"],
    ["--mission-save", "unused-mission.eu4"],
    ["--province-interest-save", "unused-province.eu4"],
    ["--empire-save", "unused-empire.eu4"],
    ["--empire-game-data"],
    ["--battle-stream", "unused-battles.json"],
])
def test_factory_rejects_parser_manifest_alone_and_mixed_state_sources_before_construction(
        tmp_path, extra, monkeypatch):
    from tools.serve_information import _build_runtime, build_parser
    from bridge.information import saved_opinions as opinion_module

    called = []
    monkeypatch.setattr(opinion_module, "SavedOpinionSnapshot",
                        lambda *args, **kwargs: called.append((args, kwargs)))
    args = build_parser().parse_args(["--opinion-save", str(tmp_path / "opinion.eu4"),
                                      "--observer", "FRA", "--database", str(tmp_path / "db.sqlite3"),
                                      *extra])
    with pytest.raises(ValueError):
        _build_runtime(args)
    assert called == []


def test_opinion_save_requires_observer_before_snapshot_construction(tmp_path, monkeypatch):
    from tools.serve_information import _build_runtime, build_parser
    from bridge.information import saved_opinions as opinion_module

    called = []
    monkeypatch.setattr(opinion_module, "SavedOpinionSnapshot",
                        lambda *args, **kwargs: called.append((args, kwargs)))
    args = build_parser().parse_args(["--opinion-save", str(tmp_path / "opinion.eu4"),
                                      "--database", str(tmp_path / "db.sqlite3")])
    with pytest.raises(ValueError, match="--opinion-save requires --observer"):
        _build_runtime(args)
    assert called == []


def test_opinion_parser_manifest_requires_save_before_snapshot_construction(tmp_path, monkeypatch):
    from tools.serve_information import _build_runtime, build_parser
    from bridge.information import saved_opinions as opinion_module

    called = []
    monkeypatch.setattr(opinion_module, "SavedOpinionSnapshot",
                        lambda *args, **kwargs: called.append((args, kwargs)))
    args = build_parser().parse_args(["--opinion-parser-manifest", str(tmp_path / "manifest.json"),
                                      "--observer", "FRA", "--database", str(tmp_path / "db.sqlite3")])
    with pytest.raises(ValueError, match="--opinion-parser-manifest requires --opinion-save"):
        _build_runtime(args)
    assert called == []


def test_default_factory_keeps_existing_live_route_without_saved_opinion_source(tmp_path):
    from tools.serve_information import _build_runtime, build_parser

    args = build_parser().parse_args(["--observer", "FRA", "--database", str(tmp_path / "default.sqlite3")])
    service, journal = _build_runtime(args)
    try:
        assert journal is None
        assert not isinstance(service.source, SavedOpinionSource)
        assert not isinstance(getattr(service.source, "primary", None), SavedOpinionSource)
        r04 = next(item for item in service.source.catalog() if item["topic_id"] == "R04")
        assert r04["fields"]["opinion_modifiers"]["coverage"] == "partial"
    finally:
        service.close()


def test_cli_help_describes_historical_opinion_snapshot_and_manifest_dependency():
    from tools.serve_information import build_parser

    help_text = " ".join(build_parser().format_help().split())
    assert "--opinion-save" in help_text and "historical EU4 save" in help_text
    assert "query-only" in help_text and "requires --observer" in help_text
    assert "--opinion-parser-manifest" in help_text
    assert "requires --opinion-save" in help_text
