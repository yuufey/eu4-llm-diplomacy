"""Self-contained recorded acceptance tests for the N04 domestic-pressure adapter.

The fixture embeds the native observation and the MCP result documents.  The
historical paths in its provenance are audit metadata only; this module never
opens the runtime tree or claims that the recorded binding is current.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path

import pytest

from bridge.information.composite import CompositeSource
from bridge.information.domestic_pressure import NativeDomesticPressureSource
from bridge.information.service import InformationService


FIXTURE = Path(__file__).with_name("fixtures") / "information_domestic_pressure_live_1374.json"
COUNTRY = "FRA"
FIELDS = ["stability", "war_exhaustion", "corruption"]
MISSING_FROM_RECORDED_CAPTURE = ["overextension", "unrest"]
FIELD_UNITS = {
    "overextension": "fraction",
    "unrest": "unrest",
}
GAME_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
GAME_DATE = 56553384
SESSION_ID = "42328-1dd6450312dc2fb"
CREATION_FILETIME = 134373859476226811


def _fixture() -> dict:
    # This is the only input path used by the tests.  In particular, no
    # historical_path in the fixture is ever resolved.
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


class _RecordedSession:
    def __init__(self, directory: Path) -> None:
        self.directory = directory
        self.session_id = SESSION_ID
        self.creation_filetime = CREATION_FILETIME
        self.record = {
            "session_id": SESSION_ID,
            "creation_filetime": CREATION_FILETIME,
            "game_sha256": GAME_SHA256,
            "game_version": "1.37.4",
            "observer": COUNTRY,
        }


class _RecordedBase:
    def __init__(self, directory: Path, context: dict) -> None:
        self.session = _RecordedSession(directory)
        self._context = deepcopy(context)
        self.context_calls = 0

    def context(self) -> dict:
        self.context_calls += 1
        return deepcopy(self._context)


class _RecordedCatalog:
    """A recorded catalog seam; all value reads remain owned by the real adapter."""

    event_types: tuple[str, ...] = ()

    def __init__(self, base: _RecordedBase) -> None:
        self.base = base

    def context(self) -> dict:
        return self.base.context()

    def catalog(self) -> list[dict]:
        fields = {
            field: {
                "coverage": "planned",
                "source": "recorded-catalog",
                "supported_countries": [COUNTRY],
            }
            for field in [*FIELDS, "religious_unity", *MISSING_FROM_RECORDED_CAPTURE]
        }
        return [{
            "topic_id": "N04",
            "catalog_ids": ["N04"],
            "title": "本国国内压力（recorded catalog）",
            "status": "available",
            "fields": fields,
            "object_types": ["country"],
            "observer_roles": ["country"],
            "observer_scope": [COUNTRY],
            "parameters": {
                "type": "object", "properties": {}, "required": [],
                "additionalProperties": False,
            },
            "supported_versions": ["1.37.4"],
            "triggers": ["query", "periodic", "change"],
            "context_scope": "country_scope",
            "visibility": "country_scope",
        }]

    def validate_query(self, query: dict) -> dict:
        return deepcopy(query)

    def read(self, query: dict, context: dict) -> dict:
        raise AssertionError("recorded catalog must not read N04 values")

    def poll_events(self, context: dict, cursor):
        return {"events": [], "cursor": cursor, "complete": True, "gaps": []}


def _query(fields: list[str]) -> dict:
    return {
        "topic": "N04",
        "object": {"type": "country", "country": COUNTRY},
        "fields": list(fields),
        "parameters": {},
    }


def _context(fixture: dict) -> dict:
    return deepcopy(fixture["mcp"]["manual"]["context"])


def _build(tmp_path: Path, fixture: dict, report: dict | None = None):
    base = _RecordedBase(tmp_path, _context(fixture))
    captured = []
    captured_report = deepcopy(report if report is not None else fixture["native_capture"])

    def capture(installation, country, fields):
        captured.append((Path(installation), country, list(fields)))
        return deepcopy(captured_report)

    adapter = NativeDomesticPressureSource(base, capture=capture)
    primary = _RecordedCatalog(base)
    source = CompositeSource(primary, [adapter])
    return source, adapter, base, captured


def _native_values(fixture: dict) -> dict[str, int]:
    return fixture["native_capture"]["values"]


def _assert_known_fields(fields: dict, expected: dict[str, int]) -> None:
    assert set(expected).issubset(fields)
    for field, value in expected.items():
        item = fields[field]
        assert item["status"] == "known"
        assert item["value"] == value
        assert item["raw"] == value
        assert item["raw_hex"] == value.to_bytes(4, "little", signed=True).hex()


def test_fixture_is_recorded_self_contained_and_preserves_source_pins() -> None:
    fixture = _fixture()
    provenance = fixture["provenance"]
    assert provenance["mode"] == "recorded"
    assert provenance["original_mode"] == "live"
    assert provenance["self_contained"] is True
    assert provenance["runtime_dependency"] is False
    assert provenance["recorded_only"] is True
    assert provenance["historical_paths_are_metadata_only"] is True
    assert provenance["session"]["historical_only"] is True
    assert provenance["session"]["session_id"] == SESSION_ID
    assert provenance["session"]["pid"] == 42328
    assert provenance["game_sha256"] == GAME_SHA256
    for name in ("source_native_capture", "source_native_report", "source_mcp_report", "source_mcp_wire_audit"):
        ref = provenance[name]
        assert ref["embedded"] is True and ref["recorded_only"] is True
        assert len(ref["sha256"]) == 64
        assert ref["bytes"] > 0
    for path, sha in provenance["source_hashes"].items():
        assert isinstance(path, str) and len(path) > 0
        assert isinstance(sha, str) and len(sha) == 64
    assert fixture["native_capture"]["status"] == "observed"
    assert fixture["native_capture"]["cleanup"]["handle_close"]["closed"] is True
    assert fixture["mcp"]["report"]["status"] == "passed"
    # The historical capture predates both current UI-cache readers.  Keep it
    # honest: it contains no copied bytes for either field.
    assert "overextension" not in fixture["native_capture"]["field_results"]
    assert "unrest" not in fixture["native_capture"]["field_results"]
    assert "overextension" not in fixture["native_capture"]["values"]
    assert "unrest" not in fixture["native_capture"]["values"]


def test_real_adapter_and_information_service_replay_known_and_partial_results(tmp_path: Path, monkeypatch) -> None:
    fixture = _fixture()
    # This injected capture is an immutable historical observation. Bind its
    # recorded profile explicitly; the live adapter still requires the current
    # profile, including the audited parent-helper dependency.
    import bridge.information.domestic_pressure as domestic
    monkeypatch.setattr(domestic, "_reader_profile_pin",
                        lambda: fixture["native_capture"]["profile"]["sha256"])
    source, adapter, base, calls = _build(tmp_path, fixture)
    service = InformationService(source, tmp_path / "recorded.sqlite")
    try:
        discovery = service.discover()
        topic = next(item for item in discovery["topics"] if item["topic_id"] == "N04")
        assert topic["status"] == "available"
        assert all(topic["fields"][field]["coverage"] == "available" for field in FIELDS)
        assert all(topic["fields"][field]["runtime_validation"] == "validated" for field in FIELDS)

        known = service.query("recorded-known", queries=[_query(FIELDS)])
        assert known["status"] == "complete"
        assert known["complete"] is True
        _assert_known_fields(known["items"][0]["fields"], _native_values(fixture))

        mixed_fields = [*FIELDS, *MISSING_FROM_RECORDED_CAPTURE]
        mixed = service.query("recorded-mixed", queries=[_query(mixed_fields)])
        assert mixed["status"] == "partial"
        assert mixed["complete"] is False
        _assert_known_fields(mixed["items"][0]["fields"], _native_values(fixture))
        for field in MISSING_FROM_RECORDED_CAPTURE:
            # The current adapter supports both fields, but this old capture
            # has no native bytes.  Missing observation data stays unknown;
            # the test must never manufacture a historical value.
            assert mixed["items"][0]["fields"][field] == {
                "status": "unknown", "reason": "DOMESTIC_PRESSURE_FIELD_MISSING",
                "unit": FIELD_UNITS[field], "scale": 1000,
            }
        assert len(calls) == 2
        assert calls[0][0] == tmp_path / "installation.json"
        assert calls[0][1:] == (COUNTRY, FIELDS)
        assert calls[1][1:] == (COUNTRY, [*FIELDS, *MISSING_FROM_RECORDED_CAPTURE])
        assert base.context_calls > 0
    finally:
        service.close()


def test_recorded_single_and_periodic_mcp_documents_match_native_values() -> None:
    fixture = _fixture()
    expected = _native_values(fixture)
    manual = fixture["mcp"]["manual"]
    assert manual["status"] == "complete" and manual["complete"] is True
    _assert_known_fields(manual["items"][0]["fields"], expected)
    for field, document in fixture["mcp"]["single_fields"].items():
        assert field in FIELDS
        assert document["status"] == "complete" and document["complete"] is True
        _assert_known_fields(document["items"][0]["fields"], {field: expected[field]})
    mixed = fixture["mcp"]["mixed_unimplemented"]
    assert mixed["status"] == "partial" and mixed["complete"] is False
    for field, item in fixture["expected"]["mixed_unsupported"].items():
        assert mixed["items"][0]["fields"][field] == item
    periodic = fixture["mcp"]["periodic"]
    assert len(periodic) == 3
    assert all(item["status"] == "complete" and item["complete"] is True for item in periodic)
    for item in periodic:
        _assert_known_fields(item["items"][0]["fields"], expected)
        assert item["items"][0]["game_date"] == GAME_DATE


@pytest.mark.parametrize(
    ("mutation", "reason_fragment"),
    [
        (lambda report: report["identity"].update(process_creation_filetime=CREATION_FILETIME + 1), "IDENTITY"),
        (lambda report: report["cleanup"]["handle_close"].update(status="error", closed=False), "CLEANUP"),
    ],
)
def test_identity_or_cleanup_failure_retracts_all_known_values(
    tmp_path: Path, mutation, reason_fragment: str,
) -> None:
    fixture = _fixture()
    report = deepcopy(fixture["native_capture"])
    mutation(report)
    source, adapter, base, _ = _build(tmp_path, fixture, report)
    result = adapter.read(_query(FIELDS), base.context())
    assert result["complete"] is False
    assert all(item["status"] == "unknown" for item in result["fields"].values())
    assert all(reason_fragment in item["reason"] for item in result["fields"].values())


def test_identity_failure_through_query_service_stays_unavailable_to_known_values(tmp_path: Path) -> None:
    fixture = _fixture()
    report = deepcopy(fixture["native_capture"])
    report["identity"]["process_path_sha256"] = "0" * 64
    source, _, _, _ = _build(tmp_path, fixture, report)
    service = InformationService(source, tmp_path / "identity-failure.sqlite")
    try:
        result = service.query("recorded-identity-failure", queries=[_query(FIELDS)])
        assert result["status"] == "failed"
        assert result["complete"] is False
        fields = result["items"][0]["fields"]
        assert all(item["status"] == "unknown" for item in fields.values())
        assert all("IDENTITY" in item["reason"] for item in fields.values())
    finally:
        service.close()
