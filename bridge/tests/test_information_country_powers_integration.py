"""Integration checks for the recorded 1.37.4 country-powers evidence.

The fixture is historical evidence.  These tests inject its capture into the
adapter's seam and use a completely fake session; they never start a game or
invoke the native reader.
"""

from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path

import pytest

from bridge.information.country_state import NativeCountryStateSource
from bridge.information.model import canonical
from bridge.information.service import InformationService
from bridge.information.sources import DiplomacySource


FIXTURE_PATH = Path(__file__).parent / "fixtures" / "information_country_powers_live_1374.json"
FIXTURE = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
PROVENANCE = FIXTURE["provenance"]
CAPTURE = FIXTURE["native_capture"]
EXPECTED = FIXTURE["expected"]
GAME_SHA256 = PROVENANCE["game_sha256"]
GAME_DATE = PROVENANCE["game_date"]
SESSION_ID = PROVENANCE["session_id"]
CREATION_FILETIME = CAPTURE["identity"]["installation_creation_filetime"]


def _points_query() -> dict:
    return {
        "topic": "N06",
        "object": {"type": "country", "country": "FRA"},
        "fields": ["monarch_points"],
        "parameters": {},
    }


def _mixed_query() -> dict:
    return {
        "topic": "N06",
        "object": {"type": "country", "country": "FRA"},
        "fields": ["monarch_points", "prestige"],
        "parameters": {"reference_recipient": "PAP"},
    }


class _Session:
    observer = "FRA"

    def __init__(self, directory: Path, *, after: dict | None = None):
        self.directory = directory
        self.session_id = SESSION_ID
        self.creation_filetime = CREATION_FILETIME
        self.after = deepcopy(after)
        self.health_calls = 0
        self.record = {
            "observer": "FRA",
            "controlled_countries": ["FRA"],
            "game_sha256": GAME_SHA256,
            "game_version": "1.37.4",
            "session_id": SESSION_ID,
            "creation_filetime": CREATION_FILETIME,
            "dll_sha256": PROVENANCE.get("dll_sha256", "d80ef39d66d263788c0af4df0892b4ff781e5e3b3f9aea7ebe33759327e457db"),
        }

    def health(self) -> dict:
        self.health_calls += 1
        result = {
            "status": "ready",
            "complete": True,
            "date_raw": GAME_DATE,
            "game_version": "1.37.4",
            "game_sha256": GAME_SHA256,
            "observer": "FRA",
            "game_day": GAME_DATE // 24,
            "world_id": "world-a",
            "reasons": [],
        }
        if self.after and self.health_calls >= 2:
            result.update(deepcopy(self.after))
        return result


class _Tools:
    def __init__(self, session: _Session, public: dict | None = None):
        self.session = session
        self.public = deepcopy(public) if public is not None else deepcopy(
            FIXTURE["mixed_source"]["public"]
        )
        self.inspect_calls: list[tuple] = []

    def inspect_diplomatic_action(self, action_id, actor, recipient, phase,
                                  parameters):
        self.inspect_calls.append(
            (action_id, actor, recipient, phase, deepcopy(parameters))
        )
        return deepcopy(self.public)


def _source(tmp_path: Path, *, capture=None, after: dict | None = None,
            public: dict | None = None):
    session = _Session(tmp_path, after=after)
    tools = _Tools(session, public=public)
    source = NativeCountryStateSource(
        DiplomacySource(tools), capture=capture,
    )
    return source, session, tools


def _fixture_capture(*_args):
    return deepcopy(CAPTURE)


def test_recorded_fixture_contains_native_shape_and_original_mcp_evidence() -> None:
    assert FIXTURE["format"] == "information_country_powers_live_1374_v1"
    assert PROVENANCE["mode"] == "recorded"
    assert PROVENANCE["original_mode"] == "live"
    assert PROVENANCE["game_version"] == CAPTURE["target_build"]["version"] == "1.37.4"
    assert PROVENANCE["pure_RPM"] is True
    assert PROVENANCE["native_function_invoked"] is False
    assert PROVENANCE["business_actions_submitted"] is False
    assert PROVENANCE["dll_sha256"] == FIXTURE["mcp_manual_context"]["dll_sha256"]
    assert PROVENANCE["capture_canonical_sha256"] == hashlib.sha256(
        canonical(CAPTURE).encode("utf-8")
    ).hexdigest()
    assert PROVENANCE["artifacts"]["contract"]["sha256"] == (
        "b4e1bbe7a990c323a5bff698f1b7ce8a8f6f58e233b5bacafbf7a80d32baf358"
    )
    assert PROVENANCE["artifacts"]["profile"]["sha256"] == CAPTURE["profile"]["sha256"]
    assert len(PROVENANCE["artifacts"]["reader"]["sha256"]) == 64
    assert len(PROVENANCE["artifacts"]["source_adapter"]["sha256"]) == 64

    assert CAPTURE["status"] == "observed"
    assert CAPTURE["read_only"] is True
    assert CAPTURE["native_function_invoked"] is False
    assert CAPTURE["country"] == EXPECTED["country"] == "FRA"
    assert CAPTURE["values"] == EXPECTED["values"] == {
        "administrative": 471,
        "diplomatic": 389,
        "military": 152,
    }
    assert CAPTURE["unit"] == "monarch_points"
    assert CAPTURE["scale"] == 1
    assert CAPTURE["completed"] is True
    assert CAPTURE["doublepass"]["performed"] is True
    assert CAPTURE["doublepass"]["consistent"] is True
    assert CAPTURE["world_generation_verified"] is False
    assert CAPTURE["cleanup"]["handle_close"]["status"] == "closed"
    for guard_name in ("static_contract_guard", "file_code_guard", "runtime_code_guard"):
        assert CAPTURE[guard_name]["status"] == "observed"

    for snapshot in (CAPTURE["before"], CAPTURE["after"]):
        assert snapshot["status"] == "observed"
        assert snapshot["game_date"] == {
            "value": GAME_DATE,
            "raw_hex": "a8ef5e03",
        }
        scan = snapshot["country_scan"]
        assert scan["requested_country"] == "FRA"
        assert scan["scanned_entries"] == 256
        assert scan["matches"][0]["table_index"] == 122
        assert scan["matches"][0]["country_handle"]["tag"] == "FRA"

    assert FIXTURE["mcp_manual_context"] == FIXTURE["mcp_manual_result"]["context"]
    assert FIXTURE["mcp_manual_context"]["mode"] == "live"
    assert FIXTURE["mcp_manual_context"]["session_id"] == SESSION_ID
    assert FIXTURE["mcp_manual_context"]["game_date"] == GAME_DATE
    assert FIXTURE["mcp_manual_result"]["status"] == "complete"
    assert FIXTURE["mcp_report"]["status"] == "passed"
    assert FIXTURE["mcp_report"]["points_reader_pure_RPM"] is True
    assert FIXTURE["mcp_report"][
        "mixed_prestige_query_invokes_readonly_native_predicates"
    ] is True
    assert FIXTURE["mcp_report"]["values"] == EXPECTED["values"]
    assert FIXTURE["mcp_report"]["periodic_results"] == 3


def test_recorded_fixture_is_not_implicitly_bound_to_a_current_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A plain live adapter has no access to this historical fixture."""

    source, _, tools = _source(tmp_path)
    assert source.monarch_points_capture is None

    # Keep the fallback entirely fake.  If the adapter tried to invoke the
    # real RPM reader this test would fail by construction rather than touching
    # a process or an installation.
    import bridge.information.country_resources_memory as memory

    calls: list[tuple[Path, str]] = []

    def fake_unbound_capture(installation: Path, country: str, *, observer_scoped: bool) -> dict:
        assert observer_scoped is True
        calls.append((installation, country))
        return {}

    monkeypatch.setattr(memory, "capture", fake_unbound_capture)
    result = source.read(_points_query())

    field = result["fields"]["monarch_points"]
    assert field["status"] == "unknown"
    assert field["reason"] == "MONARCH_POINTS_CAPTURE_INVALID"
    assert result["complete"] is False
    assert calls == [(tmp_path / "installation.json", "FRA")]
    assert tools.inspect_calls == []
    assert result["source"]["provenance"]["context_guard"]["status"] == "capture_invalid"


def test_real_capture_shape_maps_through_source_and_service_with_compact_hash(
    tmp_path: Path,
) -> None:
    source, _, tools = _source(tmp_path, capture=_fixture_capture)

    direct = source.read(_points_query())
    assert direct["fields"]["monarch_points"] == {
        "status": "known",
        "value": EXPECTED["values"],
    }
    assert direct["complete"] is True
    provenance = direct["source"]["provenance"]
    assert provenance["capture_report_sha256"] == PROVENANCE["capture_canonical_sha256"]
    assert provenance["capture_report_hash_algorithm"].startswith("sha256(canonical_json_utf8")
    assert provenance["capture"]["doublepass"] == CAPTURE["doublepass"]
    assert provenance["capture"]["cleanup"]["handle_close"]["status"] == "closed"
    assert tools.inspect_calls == []

    # The public InformationService path preserves the same mapping and does
    # not reinterpret the recorded evidence as a native call.
    service = InformationService(source, tmp_path / "information.sqlite")
    try:
        result = service.query("powers-recorded", queries=[_points_query()])
    finally:
        service.close()
    assert result["complete"] is True
    item = result["items"][0]
    assert item["fields"]["monarch_points"]["status"] == "known"
    assert item["fields"]["monarch_points"]["value"] == EXPECTED["values"]
    assert item["source"]["provenance"]["capture_report_sha256"] == PROVENANCE["capture_canonical_sha256"]
    assert tools.inspect_calls == []


@pytest.mark.parametrize(
    ("label", "mutate", "reason"),
    [
        (
            "date",
            lambda report: report["before"]["game_date"].update(value=GAME_DATE + 1),
            "MONARCH_POINTS_DATE_INVALID",
        ),
        (
            "creation",
            lambda report: report["identity"].update(
                installation_creation_filetime=CREATION_FILETIME + 1
            ),
            "MONARCH_POINTS_IDENTITY_INVALID",
        ),
        (
            "guard",
            lambda report: report["runtime_code_guard"].update(status="mismatch"),
            "MONARCH_POINTS_GUARD_INVALID",
        ),
        (
            "cleanup",
            lambda report: report["cleanup"]["handle_close"].update(
                status="error", closed=False
            ),
            "MONARCH_POINTS_CLEANUP_INVALID",
        ),
    ],
)
def test_capture_contract_mutations_retract_values(
    tmp_path: Path, label: str, mutate, reason: str,
) -> None:
    report = deepcopy(CAPTURE)
    mutate(report)
    source, _, tools = _source(tmp_path, capture=lambda *_: deepcopy(report))

    result = source.read(_points_query())
    field = result["fields"]["monarch_points"]
    assert field["status"] == "unknown", label
    assert field["reason"] == reason, label
    assert result["complete"] is False
    assert tools.inspect_calls == []


def test_mixed_partial_keeps_public_prestige_failure_separate_from_points(
    tmp_path: Path,
) -> None:
    public = deepcopy(FIXTURE["mixed_source"]["public"])
    public.pop("prestige_raw")
    source, _, tools = _source(
        tmp_path, capture=_fixture_capture, public=public,
    )
    service = InformationService(source, tmp_path / "mixed.sqlite")
    try:
        result = service.query("mixed-recorded", queries=[_mixed_query()])
    finally:
        service.close()

    assert result["status"] == "partial"
    assert result["complete"] is False
    fields = result["items"][0]["fields"]
    assert fields["monarch_points"]["status"] == "known"
    assert fields["monarch_points"]["value"] == EXPECTED["values"]
    assert fields["prestige"]["status"] == "unknown"
    assert fields["prestige"]["reason"] == "PUBLIC_PRESTIGE_PROJECTION_UNAVAILABLE"
    assert "value" not in fields["prestige"]
    assert fields["prestige"].get("value") != -11643
    assert len(tools.inspect_calls) == 1
    assert tools.inspect_calls[0][:4] == (
        "offer_vassalization", "FRA", "PAP", "initiate"
    )
