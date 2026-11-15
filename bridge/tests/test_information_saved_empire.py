from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import subprocess
from types import SimpleNamespace

import pytest

from bridge.information import InformationService
from bridge.information.catalog import list_topics
from bridge.information.model import InformationError
from bridge.information.empire_snapshot import SavedEmpireSource
from bridge.information.saved_empire import DEFAULT_MANIFEST, EMPIRE_SCHEMA, SavedEmpireSnapshot
import bridge.information.saved_province_interests as saved_interests


_MISSING = object()


def document(*, empire=_MISSING, saved_player="POR", country_tags=None,
             saved_date="1456.4.12", version=(1, 37, 4, 0), schema=EMPIRE_SCHEMA):
    result = {
        "schema": schema,
        "saved_date": saved_date,
        "saved_version": {
            "first": version[0], "second": version[1],
            "third": version[2], "fourth": version[3],
            "name": ".".join(str(item) for item in version),
        },
        "saved_player": saved_player,
        "country_tags": list(["FRA", "POR", "ENG"] if country_tags is None else country_tags),
    }
    if empire is not _MISSING:
        result["empire"] = deepcopy(empire)
    return result


def make_source(tmp_path, doc=None, *, observer="FRA", save_bytes=b"empire-save-v1"):
    tmp_path.mkdir(parents=True, exist_ok=True)
    save = tmp_path / "snapshot.eu4"
    save.write_bytes(save_bytes)
    parsed = deepcopy(doc if doc is not None else document(
        empire={"emperor": "FRA", "electors": ["FRA", "ENG"],
                "passed_reforms": ["reform_one", "reform_two"]},
    ))
    parser_calls = []

    def parser(path):
        parser_calls.append(Path(path))
        assert Path(path) == save.resolve()
        return deepcopy(parsed)

    snapshot = SavedEmpireSnapshot(save, observer, parser=parser)
    return save, snapshot, SavedEmpireSource(snapshot), parser_calls


def query(source, object_value, fields, *, parameters=None, context=None):
    request = {"topic": "S01", "object": deepcopy(object_value),
               "fields": list(fields), "parameters": {} if parameters is None else parameters}
    return source.read(request, source.context() if context is None else context)


def test_snapshot_context_records_history_separately_from_observer_and_player(tmp_path):
    save, snapshot, source, parser_calls = make_source(tmp_path)

    context = source.context()
    assert context["status"] == "ready"
    assert context["mode"] == "recorded"
    assert context["observer"] == "FRA"
    assert context["game_date"] == "1456.4.12"
    assert context["game_date_kind"] == "saved_calendar_date"
    assert context["game_version"] == "1.37.4"
    assert context["game_day"] is None
    assert context["session_id"] is None
    assert context["world_id"] is None
    assert context["archive"]["player"] == "POR"
    assert context["archive"]["sha256"] == hashlib.sha256(save.read_bytes()).hexdigest()
    assert context["parser"]["snapshot_schema"] == EMPIRE_SCHEMA
    assert parser_calls == [save.resolve()]


def test_snapshot_reuses_the_empire_manifest_default():
    assert DEFAULT_MANIFEST.name == "adapter-manifest.json"
    assert DEFAULT_MANIFEST.parts[-4:] == ("tools", "rust", "eu4-save-empire", "adapter-manifest.json")


def test_global_emperor_electors_and_reforms_are_same_for_country_or_session(tmp_path):
    _save, _snapshot, source, _calls = make_source(tmp_path)

    country_fields = query(source, {"type": "country", "country": "ENG"},
                           ["emperor", "electors", "reforms"])["fields"]
    session_fields = query(source, {"type": "session"},
                           ["emperor", "electors", "reforms"])["fields"]

    assert country_fields == session_fields
    assert country_fields["emperor"]["value"] == "FRA"
    assert country_fields["emperor"]["unit"] == "country_tag"
    assert country_fields["electors"]["value"] == ["ENG", "FRA"]
    assert country_fields["electors"]["unit"] == "country_tag"
    assert country_fields["reforms"]["value"] == ["reform_one", "reform_two"]
    assert country_fields["reforms"]["unit"] == "reform_id"
    for item in country_fields.values():
        assert item["status"] == "known"
        assert item["period"] == "saved_snapshot"
        assert item["complete"] is False
        assert item["basis"] == "saved_global_empire_record"
        assert item["runtime_effect_evaluated"] is False
        assert item["current_ui_visibility_verified"] is False


def test_missing_empire_or_missing_fields_are_unknown_but_explicit_empty_lists_are_known(tmp_path):
    _save, _snapshot, absent_source, _calls = make_source(tmp_path, document())
    absent = query(absent_source, {"type": "session"}, ["emperor", "electors", "reforms"])["fields"]
    assert all(item["status"] == "unknown" for item in absent.values())
    assert {item["reason"] for item in absent.values()} == {"EMPIRE_RECORD_ABSENT"}
    assert all("value" not in item for item in absent.values())

    _save, _snapshot, empty_source, _calls = make_source(tmp_path / "empty", document(
        empire={"emperor": None, "electors": [], "passed_reforms": []},
    ))
    empty = query(empty_source, {"type": "session"}, ["emperor", "electors", "reforms"])["fields"]
    assert empty["emperor"]["status"] == "unknown"
    assert empty["emperor"]["reason"] == "EMPIRE_FIELD_NOT_CAPTURED"
    assert empty["electors"]["status"] == "known" and empty["electors"]["value"] == []
    assert empty["reforms"]["status"] == "known" and empty["reforms"]["value"] == []

    _save, _snapshot, missing_source, _calls = make_source(tmp_path / "missing", document(
        empire={"emperor": "FRA"},
    ))
    missing = query(missing_source, {"type": "session"}, ["emperor", "electors", "reforms"])["fields"]
    assert missing["emperor"]["status"] == "known"
    assert missing["electors"]["reason"] == "EMPIRE_FIELD_NOT_CAPTURED"
    assert missing["reforms"]["reason"] == "EMPIRE_FIELD_NOT_CAPTURED"


def test_each_empire_field_fails_independently_on_bad_references_or_ids(tmp_path):
    _save, _snapshot, source, _calls = make_source(tmp_path, document(
        empire={"emperor": "XXX", "electors": ["ENG", "ENG"],
                "passed_reforms": ["reform_one", "reform_one"]},
    ))

    fields = query(source, {"type": "session"}, ["emperor", "electors", "reforms"])["fields"]
    assert fields["emperor"]["status"] == "unknown"
    assert fields["emperor"]["reason"] == "EMPEROR_NOT_IN_SNAPSHOT_COUNTRIES"
    assert fields["electors"]["status"] == "unknown"
    assert fields["electors"]["reason"] == "ELECTOR_TAG_LIST_INVALID"
    assert fields["reforms"]["status"] == "unknown"
    assert fields["reforms"]["reason"] == "REFORM_ID_DUPLICATE"

    _save, _snapshot, source, _calls = make_source(tmp_path / "badids", document(
        empire={"emperor": "FRA", "electors": ["ENG", "XXX"],
                "passed_reforms": ["not a reform id"]},
    ))
    fields = query(source, {"type": "country", "country": "FRA"},
                   ["emperor", "electors", "reforms"])["fields"]
    assert fields["emperor"]["status"] == "known"
    assert fields["electors"]["reason"] == "ELECTOR_NOT_IN_SNAPSHOT_COUNTRIES"
    assert fields["reforms"]["reason"] == "REFORM_ID_INVALID"


def test_unknown_country_target_is_not_promoted_to_global_value(tmp_path):
    _save, _snapshot, source, _calls = make_source(tmp_path)

    fields = query(source, {"type": "country", "country": "ZZZ"},
                   ["emperor", "electors", "reforms"])["fields"]
    assert all(item["status"] == "unknown" for item in fields.values())
    assert all(item["reason"] == "COUNTRY_NOT_IN_SNAPSHOT" for item in fields.values())
    assert all("value" not in item for item in fields.values())


def test_s01_catalog_keeps_original_fields_and_is_query_only(tmp_path):
    _save, _snapshot, source, _calls = make_source(tmp_path)
    topics = source.catalog()
    catalog = {item["topic_id"]: item for item in topics}
    s01 = catalog["S01"]

    expected_fields = {topic["topic_id"]: set(topic["fields"]) for topic in list_topics()}
    assert len(topics) == len(expected_fields)
    assert {topic["topic_id"]: set(topic["fields"]) for topic in topics} == expected_fields
    assert set(s01["fields"]) == {
        "empire_status", "emperor", "electors", "intervention", "religious_leagues", "reforms",
    }
    assert s01["status"] == "available"
    assert set(s01["object_types"]) == {"country", "session"}
    assert s01["triggers"] == ["query"]
    for name in ("emperor", "electors", "reforms"):
        assert s01["fields"][name]["coverage"] == "partial"
    for name in ("empire_status", "intervention", "religious_leagues"):
        assert s01["fields"][name]["coverage"] == "planned"
        result = query(source, {"type": "session"}, [name])
        assert result["fields"][name]["status"] == "unsupported"
    assert source.event_types == ()


def test_direct_and_report_reads_match_and_query_only_rejects_subscriptions(tmp_path):
    _save, _snapshot, source, _calls = make_source(tmp_path)
    service = InformationService(source, tmp_path / "empire-info.sqlite3")
    request = {
        "topic": "S01",
        "object": {"type": "session"},
        "fields": ["emperor", "electors", "reforms"],
        "parameters": {},
    }
    try:
        c01 = service.query("empire-context", queries=[{
            "topic": "C01", "object": {"type": "session"},
            "fields": ["observer", "game_date", "game_version", "status"],
            "parameters": {},
        }])
        c01_fields = c01["items"][0]["fields"]
        assert c01["items"][0]["complete"] is True
        assert c01_fields["observer"]["value"] == "FRA"
        assert c01_fields["game_date"]["value"] == "1456.4.12"
        assert c01_fields["game_version"]["value"] == "1.37.4"
        assert c01_fields["status"]["value"] == "ready"

        direct = service.query("empire-direct", queries=[request])
        report = service.manage_report("empire-report-create", "create", config={
            "queries": [request], "detail": "raw",
        })["report"]
        reported = service.query("empire-report-run", report_id=report["id"])
        assert direct["items"][0]["fields"] == reported["items"][0]["fields"]
        assert direct["context"]["session_id"] is None
        assert direct["items"][0]["complete"] is False

        with pytest.raises(InformationError) as error:
            service.manage_subscription("empire-periodic", "create", config={
                "kind": "periodic",
                "report_id": report["id"],
                "binding": {"session_id": "not-a-live-session", "observer": "FRA",
                            "game_version": "1.37.4"},
                "schedule": {"basis": "real", "every": 60, "unit": "seconds"},
            })
        assert error.value.code == "unsupported_trigger"
        assert service.manage_subscription("empire-list", "list")["subscriptions"] == []
    finally:
        service.close()


def test_s01_rejects_session_binding_extras_and_nonempty_parameters(tmp_path):
    _save, _snapshot, source, _calls = make_source(tmp_path)
    with pytest.raises(InformationError) as session_error:
        query(source, {"type": "session", "session_id": "fake"}, ["emperor"])
    assert session_error.value.code == "invalid_object"

    with pytest.raises(InformationError) as country_error:
        query(source, {"type": "country", "country": "FRA", "observer": "FRA"}, ["emperor"])
    assert country_error.value.code == "invalid_parameters"

    with pytest.raises(InformationError) as parameter_error:
        query(source, {"type": "session"}, ["emperor"], parameters={"include_all": True})
    assert parameter_error.value.code == "invalid_parameters"


def test_snapshot_file_change_retracts_values_without_reparsing(tmp_path):
    save, _snapshot, source, parser_calls = make_source(tmp_path)
    save.write_bytes(b"replacement-empire-save")

    context = source.context()
    result = query(source, {"type": "session"}, ["emperor", "electors", "reforms"])
    assert context["status"] == "unready"
    assert all(item["status"] == "unavailable" for item in result["fields"].values())
    assert parser_calls == [save.resolve()]


def test_pinned_parser_dependency_change_retracts_values(tmp_path, monkeypatch):
    parser_root = tmp_path / "repo"
    parser_root.mkdir()
    binary = parser_root / "empire-parser.exe"
    adapter = parser_root / "adapter.rs"
    binary.write_bytes(b"pinned empire parser")
    adapter.write_bytes(b"pinned manifest adapter")
    monkeypatch.setattr(saved_interests, "ROOT", parser_root)

    def file_pin(path):
        raw = path.read_bytes()
        return {"path": path.name, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}

    manifest = tmp_path / "parser-manifest.json"
    manifest.write_text(json.dumps({
        "schema": "eu4.save_provinces.parser.v1",
        "jomini_commit": saved_interests.JOMINI_COMMIT,
        "binary": file_pin(binary),
        "sources": [file_pin(adapter)],
    }), encoding="utf-8")
    save = tmp_path / "snapshot.eu4"
    save.write_bytes(b"empire-save")
    expected_doc = document(empire={"emperor": "FRA", "electors": [], "passed_reforms": []})
    launches = []

    def fake_run(argv, **kwargs):
        launches.append(argv)
        kwargs["stdout"].write(json.dumps(expected_doc).encode("utf-8"))
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(saved_interests.subprocess, "run", fake_run)
    snapshot = SavedEmpireSnapshot(save, "FRA", parser_manifest=manifest)
    source = SavedEmpireSource(snapshot)
    assert source.context()["status"] == "ready"
    assert len(launches) == 1
    assert launches[0] == [str(binary.resolve()), str(save.resolve())]

    adapter.write_bytes(b"changed pinned manifest adapter")
    assert source.context()["status"] == "unready"
    result = query(source, {"type": "session"}, ["emperor"])
    assert result["fields"]["emperor"]["status"] == "unavailable"
    assert launches == [[str(binary.resolve()), str(save.resolve())]]


@pytest.mark.parametrize("bad_document,observer", [
    (document(schema="eu4.save_provinces_snapshot.v1", empire=None), "FRA"),
    (document(version=(1, 37, 5, 0), empire=None), "FRA"),
    (document(country_tags=["POR", "ENG"], empire=None), "FRA"),
    (document(empire="not-an-object"), "FRA"),
])
def test_invalid_schema_header_or_empire_shape_is_rejected(tmp_path, bad_document, observer):
    save = tmp_path / "bad.eu4"
    save.write_bytes(b"bad-save")
    with pytest.raises(ValueError):
        SavedEmpireSnapshot(save, observer, parser=lambda _path: deepcopy(bad_document))

