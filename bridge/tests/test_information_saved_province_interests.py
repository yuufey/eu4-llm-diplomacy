from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import subprocess

import pytest

from bridge.information import InformationService
from bridge.information.saved_province_interests import SavedProvinceInterestsSnapshot
from bridge.information.province_interests import SavedProvinceInterestsSource
import bridge.information.saved_province_interests as saved_interests


def _document(*, provinces=None, saved_player="POR", country_tags=None):
    return {
        "schema": "eu4.save_provinces_snapshot.v1",
        "saved_date": "1456.4.12",
        "saved_version": {
            "first": 1,
            "second": 37,
            "third": 4,
            "fourth": 0,
            "name": "1.37.4.0",
        },
        "saved_player": saved_player,
        "country_tags": list(country_tags or ["FRA", "POR", "ENG"]),
        "provinces": deepcopy(provinces if provinces is not None else [
            {"province_id": 186, "cores": ["FRA"], "claims": [],
             "discovered_by": ["FRA", "POR"]},
            {"province_id": 187, "cores": ["ENG"], "claims": ["FRA"],
             "discovered_by": ["FRA"]},
            # This record is present in the save, but FRA has no positive
            # discovery evidence for it and must not learn its interests.
            {"province_id": 188, "cores": ["POR"], "claims": ["FRA"],
             "discovered_by": ["POR"]},
            {"province_id": 189, "cores": [], "claims": [],
             "discovered_by": ["FRA"]},
        ]),
    }


def _make_source(tmp_path, document=None, *, observer="FRA", save_bytes=b"fixture-save-v1"):
    save = tmp_path / "snapshot.eu4"
    save.write_bytes(save_bytes)
    parsed = deepcopy(document if document is not None else _document())
    parser_calls = []

    def parser(path):
        parser_calls.append(Path(path))
        assert Path(path) == save.resolve()
        return deepcopy(parsed)

    snapshot = SavedProvinceInterestsSnapshot(save, observer, parser=parser)
    return save, snapshot, SavedProvinceInterestsSource(snapshot), parser_calls


def _read(source, object_type, target, fields):
    obj = {"type": object_type, "province_id": target} if object_type == "province" else {
        "type": object_type, "country": target,
    }
    return source.read({
        "topic": "G01",
        "object": obj,
        "fields": list(fields),
        "parameters": {},
    }, source.context())


def test_snapshot_context_is_recorded_and_binds_hash_date_version_and_archive_player(tmp_path):
    save, snapshot, source, parser_calls = _make_source(tmp_path)

    context = source.context()
    archive = context["archive"]

    assert context["mode"] == "recorded"
    assert context["observer"] == "FRA"
    assert context.get("game_date", context.get("saved_date")) == "1456.4.12"
    version = context.get("game_version", context.get("saved_version"))
    assert version in ("1.37.4", "1.37.4.0", _document()["saved_version"])
    assert context["game_day"] is None
    assert context["session_id"] is None
    assert context["world_id"] is None
    assert archive["sha256"] == hashlib.sha256(save.read_bytes()).hexdigest()
    assert archive["size_bytes"] == save.stat().st_size
    assert archive["mtime_ns"] == save.stat().st_mtime_ns
    assert archive["player"] == "POR"
    # A requested logical country tag is not silently relabeled as the
    # physical player stored in the archive.
    assert parser_calls == [save.resolve()]


def test_province_query_returns_known_core_and_claim_membership_with_snapshot_units(tmp_path):
    _save, _snapshot, source, _calls = _make_source(tmp_path)

    result = _read(source, "province", 187, ["cores", "claims"])
    cores = result["fields"]["cores"]
    claims = result["fields"]["claims"]

    assert cores["status"] == claims["status"] == "known"
    assert cores["value"] == ["ENG"]
    assert claims["value"] == ["FRA"]
    for field in (cores, claims):
        assert field["scale"] == 1
        assert field["period"] == "saved_snapshot"
        assert field["unit"] == "country_tag"


def test_discovered_province_with_no_core_or_claim_is_known_empty(tmp_path):
    _save, _snapshot, source, _calls = _make_source(tmp_path)

    result = _read(source, "province", 189, ["cores", "claims"])

    assert result["fields"]["cores"]["status"] == "known"
    assert result["fields"]["cores"]["value"] == []
    assert result["fields"]["claims"]["status"] == "known"
    assert result["fields"]["claims"]["value"] == []


@pytest.mark.parametrize("discovered_by", [None, [], ["POR"]])
def test_province_query_requires_positive_observer_discovery(tmp_path, discovered_by):
    doc = _document(provinces=[
        {"province_id": 188, "cores": ["POR"], "claims": ["FRA"],
         "discovered_by": discovered_by},
    ])
    _save, _snapshot, source, _calls = _make_source(tmp_path, doc)

    fields = _read(source, "province", 188, ["cores", "claims"])["fields"]

    assert fields["cores"]["status"] == "unknown"
    assert fields["claims"]["status"] == "unknown"
    assert "value" not in fields["cores"]
    assert "value" not in fields["claims"]


def test_country_reverse_queries_enumerate_only_discovered_provinces_and_remain_partial(tmp_path):
    _save, _snapshot, source, _calls = _make_source(tmp_path)

    result = _read(source, "country", "FRA", ["cores", "claims"])
    cores = result["fields"]["cores"]
    claims = result["fields"]["claims"]

    assert cores["status"] == claims["status"] == "known"
    assert cores["value"] == [186]
    assert claims["value"] == [187]
    for field in (cores, claims):
        assert field["unit"] == "province_id"
        assert field["scale"] == 1
        assert field["period"] == "saved_snapshot"
        assert field["complete"] is False
        assert field["collection_scope"] == "observer_discovered_provinces_in_snapshot"
    assert 188 not in cores["value"] and 188 not in claims["value"]

    # The hidden province's POR core must not appear in a reverse lookup either.
    por_cores = _read(source, "country", "POR", ["cores"])["fields"]["cores"]
    assert por_cores["status"] == "known"
    assert por_cores["value"] == []
    assert por_cores["complete"] is False


def test_unknown_province_is_not_reported_as_known_empty(tmp_path):
    _save, _snapshot, source, _calls = _make_source(tmp_path)

    fields = _read(source, "province", 999, ["cores", "claims"])["fields"]

    assert fields["cores"]["status"] == "unknown"
    assert fields["claims"]["status"] == "unknown"
    assert "value" not in fields["cores"]
    assert "value" not in fields["claims"]


def test_g01_catalog_preserves_both_object_kinds_and_unimplemented_fields(tmp_path):
    _save, _snapshot, source, _calls = _make_source(tmp_path)

    g01 = next(topic for topic in source.catalog() if topic["topic_id"] == "G01")

    assert set(g01["object_types"]) == {"province", "country"}
    assert set(g01["fields"]) == {
        "cores", "claims", "permanent_claims", "task_targets", "strategic_targets",
    }
    assert g01["triggers"] == ["query"]
    assert g01["fields"]["cores"]["coverage"] == "partial"
    assert g01["fields"]["claims"]["coverage"] == "partial"
    for name in ("permanent_claims", "task_targets", "strategic_targets"):
        assert g01["fields"][name]["coverage"] == "planned"
        result = _read(source, "province", 186, [name])
        assert result["fields"][name]["status"] == "unsupported"


@pytest.mark.parametrize("bad_document", [
    "duplicate_province",
    "invalid_core_tag",
    "invalid_claim_tag",
    "invalid_discovery_tag",
    "invalid_country_table_tag",
    "observer_not_in_country_tags",
])
def test_ambiguous_or_invalid_snapshot_records_fail_closed(tmp_path, bad_document):
    doc = _document()
    observer = "FRA"
    if bad_document == "duplicate_province":
        doc["provinces"].append(deepcopy(doc["provinces"][0]))
    elif bad_document == "invalid_core_tag":
        doc["provinces"][0]["cores"] = ["fr"]
    elif bad_document == "invalid_claim_tag":
        doc["provinces"][0]["claims"] = ["FRA!"]
    elif bad_document == "invalid_discovery_tag":
        doc["provinces"][0]["discovered_by"] = ["FR!"]
    elif bad_document == "invalid_country_table_tag":
        doc["country_tags"] = ["FRA", "POR", "fr"]
    else:
        doc["country_tags"] = ["POR", "ENG"]
        observer = "FRA"

    save = tmp_path / "bad.eu4"
    save.write_bytes(b"fixture-save-v1")
    with pytest.raises(ValueError):
        SavedProvinceInterestsSnapshot(save, observer, parser=lambda _path: deepcopy(doc))


def test_snapshot_revalidation_does_not_reparse_replaced_file(tmp_path):
    save, _snapshot, source, parser_calls = _make_source(tmp_path)
    original_mtime = save.stat().st_mtime_ns
    # Keep the size and timestamp fixed so the hash is the distinguishing check.
    save.write_bytes(b"fixture-save-v2")
    os.utime(save, ns=(save.stat().st_atime_ns, original_mtime))

    context = source.context()
    result = _read(source, "province", 186, ["cores", "claims"])

    assert context["status"] in {"unready", "unavailable"}
    assert result["fields"]["cores"]["status"] == "unavailable"
    assert result["fields"]["claims"]["status"] == "unavailable"
    assert parser_calls == [save.resolve()]


def test_information_service_query_keeps_snapshot_context_and_partial_scope(tmp_path):
    _save, _snapshot, source, _calls = _make_source(tmp_path)
    service = InformationService(source, tmp_path / "snapshot-info.sqlite3")
    try:
        result = service.query("saved-province-interest-001", queries=[{
            "topic": "C01",
            "object": {"type": "session"},
            "fields": ["observer", "game_date", "game_version", "status"],
            "parameters": {},
        }, {
            "topic": "G01",
            "object": {"type": "province", "province_id": 187},
            "fields": ["cores", "claims"],
            "parameters": {},
        }])
    finally:
        service.close()

    assert result["context"]["mode"] == "recorded"
    assert result["context"]["session_id"] is None
    assert result["context"]["world_id"] is None
    context_fields = result["items"][0]["fields"]
    assert result["items"][0]["complete"] is True
    assert context_fields["observer"]["value"] == "FRA"
    assert context_fields["game_date"]["value"] == "1456.4.12"
    assert context_fields["game_version"]["value"] == "1.37.4"
    assert context_fields["status"]["value"] == "ready"
    assert result["items"][1]["complete"] is False
    assert result["items"][1]["fields"]["cores"]["value"] == ["ENG"]


def test_snapshot_revalidation_marks_missing_file_unavailable_without_reparse(tmp_path):
    save, _snapshot, source, parser_calls = _make_source(tmp_path)
    save.unlink()

    context = source.context()
    result = _read(source, "province", 186, ["cores", "claims"])

    assert context["status"] in {"unready", "unavailable"}
    assert result["fields"]["cores"]["status"] == "unavailable"
    assert result["fields"]["claims"]["status"] == "unavailable"
    assert parser_calls == [save.resolve()]


def test_factory_accepts_snapshot_options_and_rejects_mixed_state_sources(tmp_path):
    from tools.serve_information import _build_runtime, build_parser

    save = tmp_path / "snapshot.eu4"
    manifest = tmp_path / "parser-manifest.json"
    save.write_bytes(b"save")
    manifest.write_text("{}", encoding="utf-8")
    parser = build_parser()
    args = parser.parse_args([
        "--province-interest-save", str(save),
        "--province-interest-parser-manifest", str(manifest),
        "--observer", "FRA",
    ])
    assert args.province_interest_save == save
    assert args.province_interest_parser_manifest == manifest

    for unbound in (
        ["--province-interest-parser-manifest", str(manifest)],
        ["--province-interest-save", str(save)],
    ):
        with pytest.raises(ValueError, match="province-interest"):
            _build_runtime(parser.parse_args(unbound))

    conflicts = [
        ["--operator-session", str(tmp_path / "installation.json")],
        ["--recorded-manifest", str(tmp_path / "recorded.json")],
        ["--mission-save", str(tmp_path / "mission.eu4"), "--mission-game-data"],
        ["--mission-game-data"],
    ]
    for conflict in conflicts:
        combined = parser.parse_args([
            "--province-interest-save", str(save),
            "--observer", "FRA",
            *conflict,
        ])
        with pytest.raises(ValueError, match="province-interest"):
            _build_runtime(combined)


@pytest.mark.parametrize("manifest_document", [[], None], ids=["array", "null"])
def test_parser_manifest_non_object_is_rejected_before_parser_launch(
        tmp_path, monkeypatch, manifest_document):
    save = tmp_path / "snapshot.eu4"
    manifest = tmp_path / "manifest.json"
    save.write_bytes(b"fixture-save")
    manifest.write_text(json.dumps(manifest_document), encoding="utf-8")
    launches = []

    def unexpected_launch(*args, **kwargs):
        launches.append((args, kwargs))
        raise AssertionError("invalid manifest must fail before parser launch")

    monkeypatch.setattr(saved_interests.subprocess, "run", unexpected_launch)
    with pytest.raises(ValueError, match="SAVED_INTERESTS_PARSER_MANIFEST"):
        SavedProvinceInterestsSnapshot(save, "FRA", parser_manifest=manifest)
    assert launches == []


@pytest.mark.parametrize("failure_kind", ["timeout", "oserror"])
def test_pinned_parser_startup_failures_are_normalized(tmp_path, monkeypatch, failure_kind):
    # Keep all manifest inputs under a temporary test root while exercising the
    # same pin validation and parser closure used by the operator entry point.
    parser_root = tmp_path / "repo"
    parser_root.mkdir()
    parser_binary = parser_root / "parser.bin"
    parser_source = parser_root / "adapter.py"
    parser_binary.write_bytes(b"pinned parser fixture")
    parser_source.write_bytes(b"pinned adapter fixture")
    monkeypatch.setattr(saved_interests, "ROOT", parser_root)

    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({
        "schema": "eu4.save_provinces.parser.v1",
        "jomini_commit": saved_interests.JOMINI_COMMIT,
        "binary": {
            "path": "parser.bin",
            "bytes": parser_binary.stat().st_size,
            "sha256": hashlib.sha256(parser_binary.read_bytes()).hexdigest(),
        },
        "sources": [{
            "path": "adapter.py",
            "bytes": parser_source.stat().st_size,
            "sha256": hashlib.sha256(parser_source.read_bytes()).hexdigest(),
        }],
    }), encoding="utf-8")
    save = tmp_path / "snapshot.eu4"
    save.write_bytes(b"fixture-save")
    launches = []

    def fail_to_start(command, **kwargs):
        launches.append((command, kwargs.get("timeout")))
        if failure_kind == "timeout":
            raise subprocess.TimeoutExpired(command, kwargs["timeout"])
        raise OSError("simulated process startup failure")

    monkeypatch.setattr(saved_interests.subprocess, "run", fail_to_start)
    with pytest.raises(ValueError, match="SAVED_INTERESTS_PARSER_EXECUTION_FAILED"):
        SavedProvinceInterestsSnapshot(save, "FRA", parser_manifest=manifest)

    assert len(launches) == 1
    assert launches[0][0] == [str(parser_binary.resolve()), str(save.resolve())]
    assert launches[0][1] == 45
