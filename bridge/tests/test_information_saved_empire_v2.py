from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from bridge.information import InformationService
from bridge.information.model import InformationError
from bridge.information.empire_snapshot import SavedEmpireSource
from bridge.information.empire_snapshot_v2 import SavedEmpireSourceV2
from bridge.information.saved_empire import EMPIRE_SCHEMA
from bridge.information.saved_empire_v2 import (
    GLOBAL_STATUS_FIELDS,
    SavedEmpireSnapshotV2,
    V2_SCHEMA,
)
import bridge.information.saved_province_interests as saved_interests


_MISSING = object()


def document(*, empire=_MISSING, schema=V2_SCHEMA, country_tags=None):
    result = {
        "schema": schema,
        "saved_date": "1456.4.12",
        "saved_version": {"first": 1, "second": 37, "third": 4,
                          "fourth": 0, "name": "1.37.4.0"},
        "saved_player": "POR",
        "country_tags": list(["FRA", "POR", "ENG"] if country_tags is None else country_tags),
    }
    if empire is not _MISSING:
        result["empire"] = deepcopy(empire)
    return result


def make_source(tmp_path, doc=None, *, observer="FRA"):
    tmp_path.mkdir(parents=True, exist_ok=True)
    save = tmp_path / "snapshot.eu4"
    save.write_bytes(b"v2-empire-snapshot")
    parsed = deepcopy(doc if doc is not None else document(empire={
        "emperor": "FRA", "electors": ["ENG"], "passed_reforms": ["reform_one"],
        "imperial_influence": "12.5", "imperial_ban_allowed": True,
        "internal_hre_cb": False, "hre_inheritable": True,
        "allows_female_emperor": False, "emperor_has_revoked": False,
        "imperial_realm_war": True,
    }))
    parser_calls = []

    def parser(path):
        parser_calls.append(Path(path))
        assert Path(path) == save.resolve()
        return deepcopy(parsed)

    snapshot = SavedEmpireSnapshotV2(save, observer, parser=parser)
    return save, snapshot, SavedEmpireSourceV2(snapshot), parser_calls


def query(source, obj, fields, *, context=None):
    request = {"topic": "S01", "object": deepcopy(obj), "fields": list(fields), "parameters": {}}
    return source.read(request, source.context() if context is None else context)


def test_v2_projects_decimal_boolean_false_and_saved_country_roles(tmp_path):
    _save, _snapshot, source, _calls = make_source(tmp_path)
    result = query(source, {"type": "country", "country": "FRA"}, ["empire_status"])
    field = result["fields"]["empire_status"]

    assert field["status"] == "known"
    assert field["scale"] == 1
    assert field["complete"] is False
    assert field["period"] == "saved_snapshot"
    value = field["value"]
    assert value["semantics"] == "saved_empire_status_and_country_roles"
    assert value["complete"] is False and value["current_state_observed"] is False
    influence = value["global_state"]["imperial_influence"]
    assert influence["status"] == "known"
    assert influence["value"] == "12.5"
    assert influence["representation"] == "decimal_string"
    assert influence["unit"] == "saved_imperial_influence"
    assert value["global_state"]["internal_hre_cb"]["value"] is False
    assert value["global_state"]["allows_female_emperor"]["value"] is False
    assert value["country_roles"]["is_emperor"]["value"] is True
    assert value["country_roles"]["is_elector"]["value"] is False
    assert value["country_roles"]["member_of_empire"]["status"] == "unknown"
    assert value["country_roles"]["member_of_empire"]["reason"] == "MEMBERSHIP_NOT_CAPTURED"


def test_v2_invalid_or_missing_components_are_independently_unknown(tmp_path):
    empire = {
        "emperor": "FRA", "electors": [], "passed_reforms": [],
        "imperial_influence": "NaN", "imperial_ban_allowed": 1,
        "internal_hre_cb": False, "hre_inheritable": None,
        "allows_female_emperor": "false", "emperor_has_revoked": True,
        # imperial_realm_war is intentionally absent.
    }
    _save, _snapshot, source, _calls = make_source(tmp_path, document(empire=empire))
    value = query(source, {"type": "session"}, ["empire_status"])["fields"]["empire_status"]["value"]
    states = value["global_state"]

    assert states["imperial_influence"]["status"] == "unknown"
    assert states["imperial_influence"]["reason"] == "IMPERIAL_INFLUENCE_INVALID"
    assert states["imperial_ban_allowed"]["status"] == "unknown"
    assert states["internal_hre_cb"] == {
        "status": "known", "value": False, "unit": "boolean",
        "period": "saved_snapshot", "complete": False,
        "basis": "saved_empire_status_v2.internal_hre_cb",
    }
    assert states["hre_inheritable"]["status"] == "unknown"
    assert states["allows_female_emperor"]["status"] == "unknown"
    assert states["emperor_has_revoked"]["value"] is True
    assert states["imperial_realm_war"]["reason"] == "EMPIRE_STATUS_FIELD_NOT_CAPTURED"
    for key in ("imperial_influence", "imperial_ban_allowed", "hre_inheritable",
                "allows_female_emperor", "imperial_realm_war"):
        assert "value" not in states[key]


def test_v1_compatibility_does_not_promote_injected_v2_status_fields(tmp_path):
    legacy = document(schema=EMPIRE_SCHEMA, empire={
        "emperor": "FRA", "electors": ["ENG"], "passed_reforms": [],
        "imperial_influence": "999", "imperial_ban_allowed": True,
        "internal_hre_cb": True, "hre_inheritable": True,
        "allows_female_emperor": True, "emperor_has_revoked": True,
        "imperial_realm_war": True,
    })
    _save, snapshot, source, _calls = make_source(tmp_path, legacy)
    context = source.context()
    assert context["parser"]["snapshot_schema"] == EMPIRE_SCHEMA

    old = query(source, {"type": "session"}, ["emperor", "electors", "reforms"])["fields"]
    assert old["emperor"]["value"] == "FRA"
    assert old["electors"]["value"] == ["ENG"]
    assert snapshot._global_status.keys() == set(GLOBAL_STATUS_FIELDS)

    projected = query(source, {"type": "country", "country": "FRA"}, ["empire_status"])["fields"]["empire_status"]
    assert projected["status"] == "known"  # Two identities are derivable from v1 fields.
    globals_ = projected["value"]["global_state"]
    assert all(item["status"] == "unknown" for item in globals_.values())
    assert {item["reason"] for item in globals_.values()} == {
        "LEGACY_SNAPSHOT_EMPIRE_STATUS_NOT_CAPTURED"
    }
    assert all("value" not in item for item in globals_.values())
    assert projected["value"]["country_roles"]["is_emperor"]["value"] is True
    assert projected["value"]["country_roles"]["is_elector"]["value"] is False


def test_empire_status_unknown_when_fewer_than_one_global_or_two_roles_are_known(tmp_path):
    _save, _snapshot, source, _calls = make_source(tmp_path, document(empire={
        "emperor": None, "electors": [], "passed_reforms": [],
        "imperial_influence": None,
    }))
    field = query(source, {"type": "country", "country": "FRA"}, ["empire_status"])["fields"]["empire_status"]
    assert field["status"] == "unknown"
    assert field["reason"] == "NO_EMPIRE_STATUS_COMPONENT_KNOWN"
    assert "value" not in field
    assert field["evidence"]["country_roles"]["is_emperor"]["status"] == "unknown"
    assert field["evidence"]["country_roles"]["is_elector"]["status"] == "known"
    assert "value" not in field["evidence"]["country_roles"]["is_elector"]


def test_session_roles_are_not_applicable_and_country_outside_snapshot_stays_unknown(tmp_path):
    _save, _snapshot, source, _calls = make_source(tmp_path)
    session = query(source, {"type": "session"}, ["empire_status"])["fields"]["empire_status"]["value"]
    assert {item["status"] for item in session["country_roles"].values()} == {"not_applicable"}
    assert {item["reason"] for item in session["country_roles"].values()} == {"COUNTRY_OBJECT_REQUIRED"}

    absent = query(source, {"type": "country", "country": "ZZZ"}, ["empire_status"])["fields"]["empire_status"]
    assert absent["status"] == "unknown"
    assert absent["reason"] == "COUNTRY_NOT_IN_SNAPSHOT"
    assert "value" not in absent


def test_empire_absence_is_not_inferred_from_unknown_global_state(tmp_path):
    _save, _snapshot, source, _calls = make_source(tmp_path, document())
    field = query(source, {"type": "session"}, ["empire_status"])["fields"]["empire_status"]
    assert field["status"] == "unknown"
    assert field["reason"] == "NO_EMPIRE_STATUS_COMPONENT_KNOWN"
    assert all(item["reason"] == "EMPIRE_RECORD_ABSENT"
               for item in field["evidence"]["global_state"].values())


def test_catalog_adds_only_empire_status_partial_and_keeps_query_only_contract(tmp_path):
    _save, _snapshot, source, _calls = make_source(tmp_path)
    parent = SavedEmpireSource(source.snapshot).catalog()
    child = source.catalog()
    parent_fields = {topic["topic_id"]: set(topic["fields"]) for topic in parent}
    assert len(child) == len(parent_fields)
    assert {topic["topic_id"]: set(topic["fields"]) for topic in child} == parent_fields
    by_id = {topic["topic_id"]: topic for topic in child}
    parent_by_id = {topic["topic_id"]: topic for topic in parent}
    def contract_without_source(topic):
        item = deepcopy(topic)
        item.pop("source", None)
        for field in item["fields"].values():
            field.pop("source", None)
        return item

    for topic_id in by_id.keys() - {"S01"}:
        assert contract_without_source(by_id[topic_id]) == contract_without_source(parent_by_id[topic_id])
    s01 = by_id["S01"]
    assert set(s01["fields"]) == {"empire_status", "emperor", "electors", "intervention",
                                   "religious_leagues", "reforms"}
    assert s01["fields"]["empire_status"]["coverage"] == "partial"
    for name in ("emperor", "electors", "reforms"):
        assert {key: value for key, value in s01["fields"][name].items() if key != "source"} == {
            key: value for key, value in parent_by_id["S01"]["fields"][name].items()
            if key != "source"
        }
    for name in ("intervention", "religious_leagues"):
        assert {key: value for key, value in s01["fields"][name].items() if key != "source"} == {
            key: value for key, value in parent_by_id["S01"]["fields"][name].items()
            if key != "source"
        }
        assert query(source, {"type": "session"}, [name])["fields"][name]["status"] == "unsupported"
    assert s01["triggers"] == ["query"]
    assert source.event_types == ()


def test_direct_report_match_and_periodic_subscription_rejection(tmp_path):
    _save, _snapshot, source, _calls = make_source(tmp_path)
    service = InformationService(source, tmp_path / "empire-v2.sqlite3")
    request = {"topic": "S01", "object": {"type": "session"},
               "fields": ["emperor", "empire_status"], "parameters": {}}
    try:
        direct = service.query("empire-v2-direct", queries=[request])
        report = service.manage_report("empire-v2-report", "create", config={
            "queries": [request], "detail": "raw",
        })["report"]
        reported = service.query("empire-v2-report-run", report_id=report["id"])
        assert direct["items"][0]["fields"] == reported["items"][0]["fields"]
        assert direct["items"][0]["complete"] is False
        assert direct["items"][0]["fields"]["empire_status"]["status"] == "known"
        with pytest.raises(InformationError) as error:
            service.manage_subscription("empire-v2-periodic", "create", config={
                "kind": "periodic", "report_id": report["id"],
                "binding": {"session_id": "not-a-live-session", "observer": "FRA",
                            "game_version": "1.37.4"},
                "schedule": {"basis": "real", "every": 60, "unit": "seconds"},
            })
        assert error.value.code == "unsupported_trigger"
        assert service.manage_subscription("empire-v2-list", "list")["subscriptions"] == []
    finally:
        service.close()


def test_supplied_context_mismatch_withdraws_all_supported_mixed_fields(tmp_path):
    _save, _snapshot, source, _calls = make_source(tmp_path)
    old_context = source.context()
    changed_context = deepcopy(old_context)
    changed_context["game_date"] = "1456.4.13"
    result = query(source, {"type": "session"},
                   ["empire_status", "emperor", "electors", "reforms"], context=changed_context)
    for name in ("empire_status", "emperor", "electors", "reforms"):
        assert result["fields"][name] == {
            "status": "unavailable", "reason": "SAVED_EMPIRE_CONTEXT_MISMATCH"
        }


def test_parent_context_mismatch_withdraws_all_supported_mixed_fields(tmp_path, monkeypatch):
    save, _snapshot, source, _calls = make_source(tmp_path)
    initial = source.context()
    original_context = source.context
    calls = 0

    def change_before_parent_read():
        nonlocal calls
        calls += 1
        if calls == 2:
            save.write_bytes(b"changed between outer and parent context")
        return original_context()

    monkeypatch.setattr(source, "context", change_before_parent_read)
    request = {"topic": "S01", "object": {"type": "session"},
               "fields": ["empire_status", "emperor", "electors", "reforms",
                          "intervention", "religious_leagues"], "parameters": {}}
    result = source.read(request, initial)
    for name in ("empire_status", "emperor", "electors", "reforms"):
        assert result["fields"][name] == {
            "status": "unavailable", "reason": "SAVED_EMPIRE_INPUT_OR_PARSER_CHANGED"
        }
    for name in ("intervention", "religious_leagues"):
        assert result["fields"][name]["status"] == "unsupported"


def test_snapshot_change_during_new_lookup_withdraws_all_supported_mixed_fields(tmp_path, monkeypatch):
    save, snapshot, source, _calls = make_source(tmp_path)
    original_lookup = snapshot.lookup_empire_status

    def lookup_then_change(obj):
        result = original_lookup(obj)
        save.write_bytes(b"changed during empire_status lookup")
        return result

    monkeypatch.setattr(snapshot, "lookup_empire_status", lookup_then_change)
    result = query(source, {"type": "session"},
                   ["empire_status", "emperor", "electors", "reforms",
                    "intervention", "religious_leagues"])
    for name in ("empire_status", "emperor", "electors", "reforms"):
        assert result["fields"][name] == {
            "status": "unavailable", "reason": "SAVED_EMPIRE_INPUT_OR_PARSER_CHANGED"
        }
    for name in ("intervention", "religious_leagues"):
        assert result["fields"][name]["status"] == "unsupported"


def test_snapshot_file_change_makes_new_field_unavailable_without_reparse(tmp_path):
    save, _snapshot, source, calls = make_source(tmp_path)
    save.write_bytes(b"changed-snapshot")
    result = query(source, {"type": "session"}, ["empire_status"])
    assert source.context()["status"] == "unready"
    assert result["fields"]["empire_status"] == {
        "status": "unavailable", "reason": "SAVED_EMPIRE_SOURCE_UNREADY"
    }
    assert calls == [save.resolve()]


def test_parser_dependency_pin_change_withdraws_new_field_without_relaunch(tmp_path, monkeypatch):
    parser_root = tmp_path / "repo"
    parser_root.mkdir()
    binary = parser_root / "empire-parser.exe"
    adapter = parser_root / "adapter.rs"
    binary.write_bytes(b"pinned parser binary")
    adapter.write_bytes(b"pinned adapter source")
    monkeypatch.setattr(saved_interests, "ROOT", parser_root)

    def file_pin(path):
        raw = path.read_bytes()
        return {"path": path.name, "bytes": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest()}

    manifest = tmp_path / "parser-manifest.json"
    manifest.write_text(json.dumps({
        "schema": "eu4.save_provinces.parser.v1",
        "jomini_commit": saved_interests.JOMINI_COMMIT,
        "binary": file_pin(binary), "sources": [file_pin(adapter)],
    }), encoding="utf-8")
    save = tmp_path / "snapshot.eu4"
    save.write_bytes(b"saved empire bytes")
    calls = []

    def fake_run(argv, **kwargs):
        calls.append(argv)
        kwargs["stdout"].write(json.dumps(document(empire={
            "emperor": "FRA", "electors": [], "passed_reforms": [],
            "imperial_influence": "3.75",
        })).encode("utf-8"))
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(saved_interests.subprocess, "run", fake_run)
    snapshot = SavedEmpireSnapshotV2(save, "FRA", parser_manifest=manifest)
    source = SavedEmpireSourceV2(snapshot)
    assert source.context()["status"] == "ready"
    assert source.context()["parser"]["snapshot_schema"] == V2_SCHEMA
    assert len(calls) == 1

    adapter.write_bytes(b"changed adapter source")
    result = query(source, {"type": "session"}, ["empire_status"])
    assert source.context()["status"] == "unready"
    assert result["fields"]["empire_status"]["status"] == "unavailable"
    assert calls == [[str(binary.resolve()), str(save.resolve())]]


@pytest.mark.parametrize("bad_value", [
    "01", "+1", "1e3", "Infinity", "1.", ".1", " 1", 1.0, "-0", "-0.00",
])
def test_influence_rejects_noncanonical_or_nontext_values_without_leaking_input(tmp_path, bad_value):
    _save, _snapshot, source, _calls = make_source(tmp_path, document(empire={
        "imperial_influence": bad_value, "imperial_ban_allowed": True,
    }))
    field = query(source, {"type": "session"}, ["empire_status"])["fields"]["empire_status"]
    assert field["status"] == "known"  # Other explicitly captured booleans remain usable.
    influence = field["value"]["global_state"]["imperial_influence"]
    assert influence["status"] == "unknown"
    assert "value" not in influence


def test_v2_header_still_rejects_bad_schema(tmp_path):
    save = tmp_path / "bad.eu4"
    save.write_bytes(b"bad")
    with pytest.raises(ValueError, match="SAVED_EMPIRE_DOCUMENT_SCHEMA"):
        SavedEmpireSnapshotV2(save, "FRA", parser=lambda _path: document(schema="wrong"))
