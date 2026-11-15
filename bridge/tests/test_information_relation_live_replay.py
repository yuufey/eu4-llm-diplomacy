"""Offline replay checks for the archived relation-network observations."""

from copy import deepcopy
import gzip
import json
from pathlib import Path

from bridge.information import relation_memory as subject


ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "bridge" / "tests" / "fixtures"
PRODUCTION_FIXTURE = FIXTURES / "information_relation_network_live_1374.json.gz"
INDEPENDENT_EXPECTED = FIXTURES / "information_relation_network_reference_1374.json.gz"
FAMILIES = ["alliance", "royal_marriage"]


def _load_gzip_json(path: Path) -> dict:
    with gzip.open(path, "rt", encoding="utf-8") as stream:
        value = json.load(stream)
    assert isinstance(value, dict)
    return value


def _tamper_network_row(report: dict, kind: str) -> dict:
    tampered = deepcopy(report)
    for pass_name in ("before", "after"):
        row = tampered[pass_name]["fields"]["alliance"]["rows"][0]["relation_row"]
        if kind == "relation_table":
            row["relation_table"]["value"] ^= 8
        elif kind == "recipient_fullref":
            row["recipient_fullref"]["value"] ^= 8
        else:
            raise AssertionError(kind)
    # Keep the report's projection aligned with its after-pass so the failure
    # comes from the identity/address binding, rather than a superficial
    # before/after mismatch.
    tampered["fields"] = deepcopy(tampered["after"]["fields"])
    return tampered


def test_archived_production_network_replay_and_tamper_rejection():
    report = _load_gzip_json(PRODUCTION_FIXTURE)
    archived_profile = {
        "path": str(subject.LEGACY_PROFILE_FILE),
        "profile_id": "relation-memory-1374",
        "sha256": subject.LEGACY_PROFILE_SHA256,
        "max_bytes": subject.PROFILE_MAX_BYTES,
    }
    assert report["profile"] == archived_profile
    assert not subject.validate_network_capture(report, actor="FRA", families=FAMILIES)
    assert subject.validate_network_capture(
        report, actor="FRA", families=FAMILIES, offline_legacy_archive=True
    )
    assert report["doublepass"] == {"performed": True, "consistent": True, "mismatches": []}
    assert report["cleanup"]["handle_close"]["closed"] is True
    assert report["fields"]["alliance"]["value"] == [
        {"country": "SCO", "fullref_hex": "0x1000032004f4353", "slot": 50, "active": True},
        {"country": "SAV", "fullref_hex": "0x10000d200564153", "slot": 210, "active": True},
    ]
    assert report["fields"]["royal_marriage"]["value"] == [
        {"country": "AMG", "fullref_hex": "0x100007000474d41", "slot": 112, "active": True},
        {"country": "FOI", "fullref_hex": "0x100007900494f46", "slot": 121, "active": True},
    ]
    assert not subject.validate_network_capture(
        _tamper_network_row(report, "relation_table"),
        actor="FRA",
        families=FAMILIES,
        offline_legacy_archive=True,
    )
    assert not subject.validate_network_capture(
        _tamper_network_row(report, "recipient_fullref"),
        actor="FRA",
        families=FAMILIES,
        offline_legacy_archive=True,
    )


def test_archived_network_requires_pinned_v1_profile_and_archived_source_checks():
    report = _load_gzip_json(PRODUCTION_FIXTURE)
    profile = subject._load_legacy_archive_profile()
    dependencies_ok, source_checks, unknown = subject._dependency_checks(
        profile, offline_legacy_archive=True
    )
    assert dependencies_ok, unknown
    assert source_checks["work/native/alliance-query.inc"] is True
    assert profile["profile_id"] == "relation-memory-1374"
    assert profile["profile_version"] == 1

    wrong_profile_hash = deepcopy(report)
    wrong_profile_hash["profile"]["sha256"] = subject.EXPECTED_PROFILE_SHA256
    assert not subject.validate_network_capture(
        wrong_profile_hash, actor="FRA", families=FAMILIES, offline_legacy_archive=True
    )

    wrong_source_guard = deepcopy(report)
    wrong_source_guard["static_contract_guard"]["source_hash_checks"][
        "work/native/alliance-query.inc"
    ] = False
    assert not subject.validate_network_capture(
        wrong_source_guard, actor="FRA", families=FAMILIES, offline_legacy_archive=True
    )


def test_independent_expected003_keeps_identity_and_raw_pin():
    expected = _load_gzip_json(INDEPENDENT_EXPECTED)
    assert expected["status"] == "observed"
    assert expected["raw_two_pass_consistent"] is True
    assert expected["identity_binding_verified"] is True
    assert expected["handle_closed"] is True
    assert expected["context"] == {
        "session_id": "31460-1dd653f69242d7b",
        "process_creation_filetime": 134374886912306555,
        "game_date": 56557728,
        "observer": "FRA",
    }
    assert expected["source_raw"]["path"].endswith("independent-network-raw-002.json")
    assert expected["source_raw"]["size_bytes"] == 16724979
    assert expected["fields"]["alliance"]["status"] == "known"
    assert expected["fields"]["royal_marriage"]["status"] == "known"
    assert [row["country"] for row in expected["fields"]["alliance"]["value"]] == ["SCO", "SAV"]
    assert [row["country"] for row in expected["fields"]["royal_marriage"]["value"]] == ["AMG", "FOI"]
