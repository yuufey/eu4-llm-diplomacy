from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest

from bridge.information.province_interests_v2 import SavedProvinceInterestsSourceV2
from bridge.information.saved_province_interests_v2 import (
    SavedProvinceInterestsSnapshotV2,
)


def _document(*, schema="eu4.save_provinces_snapshot.v2", provinces=None):
    return {
        "schema": schema,
        "saved_date": "1456.4.12",
        "saved_version": {
            "first": 1,
            "second": 37,
            "third": 4,
            "fourth": 0,
            "name": "1.37.4.0",
        },
        "saved_player": "POR",
        "country_tags": ["FRA", "POR", "ENG"],
        "provinces": deepcopy(provinces if provinces is not None else [
            {"province_id": 186, "cores": ["FRA", "ENG"], "claims": ["POR"],
             "discovered_by": ["FRA", "POR"], "territorial_core": ["FRA"]},
            {"province_id": 187, "cores": ["ENG"], "claims": ["FRA"],
             "discovered_by": ["FRA"], "territorial_core": ["ENG"]},
            {"province_id": 188, "cores": ["POR"], "claims": ["FRA"],
             "discovered_by": ["POR"], "territorial_core": ["POR"]},
            {"province_id": 189, "cores": [], "claims": [],
             "discovered_by": ["FRA"], "territorial_core": None},
        ]),
    }


def _make_source(tmp_path, document=None, *, observer="FRA"):
    save = tmp_path / "snapshot.eu4"
    save.write_bytes(b"v2-test-save")
    parsed = deepcopy(document if document is not None else _document())
    parser_calls = []

    def parser(path):
        parser_calls.append(Path(path))
        assert Path(path) == save.resolve()
        return deepcopy(parsed)

    snapshot = SavedProvinceInterestsSnapshotV2(save, observer, parser=parser)
    return snapshot, SavedProvinceInterestsSourceV2(snapshot), parser_calls


def _read(source, object_type, target, fields):
    obj = ({"type": "province", "province_id": target}
           if object_type == "province" else {"type": "country", "country": target})
    return source.read({
        "topic": "G01",
        "object": obj,
        "fields": list(fields),
        "parameters": {},
    }, source.context())


def test_explicit_territorial_membership_is_an_addition_to_the_existing_cores_list(tmp_path):
    snapshot, source, _calls = _make_source(tmp_path)

    result = _read(source, "province", 186, ["cores", "claims"])
    cores = result["fields"]["cores"]
    claims = result["fields"]["claims"]
    detail = cores["territorial_core_membership"]

    assert cores["status"] == claims["status"] == "known"
    assert cores["value"] == ["ENG", "FRA"]
    assert claims["value"] == ["POR"]
    assert detail == {
        "status": "known", "value": ["FRA"], "unit": "country_tag",
        "scale": 1, "period": "saved_snapshot", "complete": False,
        "basis": "saved_province.territorial_core",
    }
    assert cores["full_core_classification"] == {
        "status": "unknown", "reason": "FULL_CORE_CLASSIFICATION_NOT_EVALUATED",
    }
    assert snapshot.context()["parser"]["snapshot_schema"] == "eu4.save_provinces_snapshot.v2"


@pytest.mark.parametrize("marker", [None, [], "missing"])
def test_missing_null_or_empty_marker_does_not_become_known_empty(tmp_path, marker):
    row = {"province_id": 186, "cores": ["FRA"], "claims": [], "discovered_by": ["FRA"]}
    if marker != "missing":
        row["territorial_core"] = marker
    snapshot, _source, _calls = _make_source(tmp_path, _document(provinces=[row]))

    cores = snapshot.lookup({"type": "province", "province_id": 186}, "cores")

    assert cores["status"] == "known"
    assert cores["value"] == ["FRA"]
    assert cores["territorial_core_membership"]["status"] == "unknown"
    assert "value" not in cores["territorial_core_membership"]
    assert snapshot.context()["parser"]["snapshot_schema"] == "eu4.save_provinces_snapshot.v2"


@pytest.mark.parametrize("marker", [["ENG"], ["fr"], ["FRA", "FRA"], "FRA"])
def test_invalid_or_non_core_marker_only_withdraws_new_detail(tmp_path, marker):
    doc = _document(provinces=[{
        "province_id": 186, "cores": ["FRA"], "claims": ["ENG"],
        "discovered_by": ["FRA"], "territorial_core": marker,
    }])
    snapshot, source, _calls = _make_source(tmp_path, doc)

    result = _read(source, "province", 186, ["cores", "claims"])
    cores = result["fields"]["cores"]

    assert cores["status"] == result["fields"]["claims"]["status"] == "known"
    assert cores["value"] == ["FRA"]
    assert result["fields"]["claims"]["value"] == ["ENG"]
    assert cores["territorial_core_membership"]["status"] == "unknown"
    assert "value" not in cores["territorial_core_membership"]


def test_province_detail_uses_the_same_positive_discovery_gate_as_cores(tmp_path):
    snapshot, _source, _calls = _make_source(tmp_path)

    hidden = snapshot.lookup({"type": "province", "province_id": 188}, "cores")
    undiscovered = snapshot.lookup({"type": "province", "province_id": 999}, "cores")

    assert hidden["status"] == "unknown"
    assert "territorial_core_membership" not in hidden
    assert undiscovered["status"] == "unknown"
    assert "territorial_core_membership" not in undiscovered


def test_country_reverse_uses_only_visible_explicit_markers_and_is_incomplete(tmp_path):
    snapshot, _source, _calls = _make_source(tmp_path)

    result = snapshot.lookup({"type": "country", "country": "FRA"}, "cores")

    assert result["status"] == "known"
    assert result["value"] == [186]
    detail = result["territorial_core_membership"]
    assert detail["status"] == "known"
    assert detail["value"] == [186]
    assert detail["unit"] == "province_id"
    assert detail["scale"] == 1
    assert detail["period"] == "saved_snapshot"
    assert detail["complete"] is False
    assert detail["basis"] == "saved_province.territorial_core"
    assert detail["collection_scope"] == (
        "explicit_markers_on_observer_discovered_provinces_in_snapshot"
    )
    assert detail["unmarked_and_unobserved_provinces_omitted"] is True
    assert 188 not in detail["value"]

    # A visible explicit-marker subset exists, so a nonmatching country is a
    # known empty result within that subset, not a complete-map assertion.
    nonmatching = snapshot.lookup({"type": "country", "country": "POR"}, "cores")
    assert nonmatching["territorial_core_membership"]["status"] == "known"
    assert nonmatching["territorial_core_membership"]["value"] == []
    assert nonmatching["territorial_core_membership"]["complete"] is False


def test_reverse_detail_is_unknown_when_no_visible_explicit_marker_exists(tmp_path):
    doc = _document(provinces=[
        {"province_id": 188, "cores": ["POR"], "claims": [],
         "discovered_by": ["POR"], "territorial_core": ["POR"]},
        {"province_id": 189, "cores": ["FRA"], "claims": [],
         "discovered_by": ["FRA"], "territorial_core": []},
    ])
    snapshot, _source, _calls = _make_source(tmp_path, doc)

    result = snapshot.lookup({"type": "country", "country": "POR"}, "cores")

    assert result["status"] == "known"
    assert result["value"] == []
    assert result["territorial_core_membership"] == {
        "status": "unknown", "reason": "TERRITORIAL_CORE_MARKER_NOT_ESTABLISHED",
    }


def test_legacy_v1_snapshot_never_gains_territorial_evidence_from_an_extra_key(tmp_path):
    doc = _document(schema="eu4.save_provinces_snapshot.v1", provinces=[{
        "province_id": 186, "cores": ["FRA"], "claims": [],
        "discovered_by": ["FRA"], "territorial_core": ["FRA"],
    }])
    snapshot, _source, _calls = _make_source(tmp_path, doc)

    result = snapshot.lookup({"type": "province", "province_id": 186}, "cores")

    assert result["status"] == "known"
    assert result["value"] == ["FRA"]
    assert result["territorial_core_membership"] == {
        "status": "unknown", "reason": "LEGACY_SNAPSHOT_CORE_TYPE_NOT_CAPTURED",
    }
    assert snapshot.context()["parser"]["snapshot_schema"] == "eu4.save_provinces_snapshot.v1"


def test_v2_catalog_keeps_original_five_fields_and_adds_no_h02_event_source(tmp_path):
    _snapshot, source, _calls = _make_source(tmp_path)

    catalog = {topic["topic_id"]: topic for topic in source.catalog()}
    g01 = catalog["G01"]

    assert set(g01["fields"]) == {
        "cores", "claims", "permanent_claims", "task_targets", "strategic_targets",
    }
    assert g01["triggers"] == ["query"]
    assert g01["fields"]["cores"]["coverage"] == "partial"
    details = g01["fields"]["cores"]["detail_fields"]
    assert details["territorial_core_membership"]["coverage"] == "partial"
    assert details["territorial_core_membership"]["basis"] == "saved_province.territorial_core"
    assert details["full_core_classification"]["coverage"] == "planned"
    assert g01["fields"]["claims"]["coverage"] == "partial"
    assert all(g01["fields"][name]["coverage"] == "planned" for name in (
        "permanent_claims", "task_targets", "strategic_targets",
    ))
    assert source.event_types == ()
    assert catalog["H02"]["status"] == "planned"
    assert catalog["H02"]["triggers"] == ["query"]
