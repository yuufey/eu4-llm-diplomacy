"""Recorded 1.37.4 peace overextension reaches the information field path.

The native query is not repeated here.  The fixture is the sealed R66 public
projection, and the small diplomacy stub only returns that saved projection
through the real ``DiplomacySource``/``InformationService`` route.
"""

from copy import deepcopy
import hashlib
import json
from pathlib import Path

from bridge.information import InformationService
from bridge.information import catalog as information_catalog
from bridge.information.sources import DiplomacySource


ROOT = Path(__file__).resolve().parents[2]
RAW_FIXTURE = ROOT / "bridge/tests/fixtures/r66_net_overextension_real.json"
PUBLIC_PROJECTION = (
    ROOT
    / "work/runtime/r66-netoe-consequence-queries-b-20261019-001"
    / "report-evidence/cases/demand-province-one/public.json"
)
RAW_FIXTURE_SHA256 = (
    "952f448e6fcbd69270e416f75cea288d3a5899a9b89532751fa719b13ca9015f"
)
PUBLIC_PROJECTION_SHA256 = (
    "194fdbb68be4c99c8293ebf3da308329fbd75b4d6bdf324f32d36069f2770371"
)
WAR_ID = "war_b0fb22dd717d14bf_00000001"
SESSION_ID = "17108-1dd5fca094cbafc"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _query() -> dict:
    return {
        "topic": "P05",
        "object": {
            "type": "war",
            "war_id": WAR_ID,
            "actor": "FRA",
            "recipient": "BUR",
        },
        "fields": ["overextension"],
        "parameters": {
            "action_id": "cede_province",
            "phase": "initiate",
            "peace_context": {
                "war_id": WAR_ID,
                "direction": "demand",
                "terms": [{
                    "action_id": "cede_province",
                    "beneficiary": "FRA",
                    "province_ids": [88],
                }],
            },
        },
    }


class _RecordedSession:
    def __init__(self):
        self.session_id = SESSION_ID

    def health(self):
        return {
            "status": "ready",
            "complete": True,
            "session_id": SESSION_ID,
            "observer": "FRA",
            "game_version": "1.37.4",
            "game_date": 56551848,
            "game_day": 2356327,
            "world_id": "r66-b",
            "paused": True,
        }


class _RecordedDiplomacy:
    def __init__(self, public_projection: dict):
        self.session = _RecordedSession()
        self.public_projection = deepcopy(public_projection)
        self.calls = []

    def inspect_diplomatic_action(
            self, action_id, actor, recipient, phase, parameters):
        self.calls.append({
            "action_id": action_id,
            "actor": actor,
            "recipient": recipient,
            "phase": phase,
            "parameters": deepcopy(parameters),
        })
        return deepcopy(self.public_projection)


def _load_pinned_projection() -> tuple[dict, dict]:
    assert RAW_FIXTURE.is_file()
    assert PUBLIC_PROJECTION.is_file()
    assert _sha256(RAW_FIXTURE) == RAW_FIXTURE_SHA256
    assert _sha256(PUBLIC_PROJECTION) == PUBLIC_PROJECTION_SHA256
    raw = json.loads(RAW_FIXTURE.read_text(encoding="utf-8"))
    case = next(item for item in raw["cases"]
                if item.get("name") == "demand-province-one")
    assert case["source"]["query_id"] == "inspect_37d99a6e096146c7974e6b01046992f3"
    assert case["source"]["line"] == 204
    assert case["source"]["sha256"] == (
        "c906320278c1fde9c821d20c6a60f3e37d31573a62f6da89e3332a99942602f6"
    )
    assert case["source"]["line_sha256"] == (
        "f5bab3bc2b34087d5f403e2d2ebb2ff3478b246bfe945388166a09bb92a21ef5"
    )
    public = json.loads(PUBLIC_PROJECTION.read_text(encoding="utf-8"))
    assert public["action_id"] == "cede_province"
    assert public["actor"] == "FRA"
    assert public["recipient"] == "BUR"
    assert public["phase"] == "initiate"
    assert public["peace_context"] == _query()["parameters"]["peace_context"] | {
        "complete": False,
    }
    return raw, public


def _catalog_entry(topic_id: str) -> dict:
    return next(item for item in information_catalog._CATALOG
                if item["topic_id"] == topic_id)


def test_p05_overextension_mapping_preserves_recorded_projection(
        tmp_path, monkeypatch):
    _, public = _load_pinned_projection()
    diplomacy = _RecordedDiplomacy(public)
    source = DiplomacySource(diplomacy, observer="FRA")
    query = _query()

    entry = _catalog_entry("P05")
    field = entry["fields"]["overextension"]
    fixed_paths = list(field["paths"])
    assert fixed_paths[:2] == [
        "peace_context.overextension",
        "consequences.overextension",
    ]
    assert fixed_paths[-1] == "peace_consequences.overextension"
    assert field["coverage"] == "partial"

    # Reproduce the pre-fix catalog contract through the real source path.
    monkeypatch.setitem(
        field, "paths", [
            "peace_context.overextension",
            "consequences.overextension",
        ],
    )
    service = InformationService(source, tmp_path / "information.sqlite3")
    try:
        before = service.query("p05-before", queries=[query])
        before_field = before["items"][0]["fields"]["overextension"]
        assert before_field == {
            "status": "unknown",
            "reason": "FIELD_NOT_PRESENT_IN_SOURCE",
        }

        # Restore the production catalog path and use the same real service
        # and same saved public payload; only the catalog fallback changes.
        monkeypatch.setitem(field, "paths", fixed_paths)
        after = service.query("p05-after", queries=[query])
        item = after["items"][0]
        value = item["fields"]["overextension"]

        assert item["query"] == query
        assert item["complete"] is True
        assert value["status"] == "known"
        projected = value["value"]
        assert projected["source"] == "native_peace_overextension"
        assert projected["scope"] == "selected_territorial_preview"
        assert projected["available"] is True
        assert projected["complete"] is True
        assert projected["unsupported_territorial_terms"] is False
        rows = {row["country"]: row for row in projected["countries"]}
        assert set(rows) == {"BUR", "FRA"}
        assert rows["BUR"]["current_raw"] == 120
        assert rows["BUR"]["current_recomputed_raw"] == 120
        assert rows["BUR"]["cache_matches_recomputed"] is True
        assert rows["BUR"]["lost_raw"] == 120
        assert rows["BUR"]["delta_raw"] == -120
        assert rows["BUR"]["projected_raw"] == 0
        assert rows["BUR"]["lost_province_ids"] == [88]
        assert rows["BUR"]["gained_province_ids"] == []
        assert rows["FRA"]["current_raw"] == 0
        assert rows["FRA"]["gained_raw"] == 120
        assert rows["FRA"]["delta_raw"] == 120
        assert rows["FRA"]["projected_raw"] == 120
        assert rows["FRA"]["gained_province_ids"] == [88]
        assert rows["FRA"]["lost_province_ids"] == []
        for row in rows.values():
            assert row["scale"] == 1000
            assert row["unit"] == "fraction"
        assert public["peace_context"]["direction"] == "demand"
        assert public["peace_context"]["complete"] is False
        assert public["parameters"]["complete"] is False
        assert field["coverage"] == "partial"
        expected_call = {
            "action_id": "cede_province",
            "actor": "FRA",
            "recipient": "BUR",
            "phase": "initiate",
            "parameters": {
                "peace_context": query["parameters"]["peace_context"],
            },
        }
        assert source.diplomacy_tools.calls == [expected_call, expected_call]
    finally:
        service.close()
