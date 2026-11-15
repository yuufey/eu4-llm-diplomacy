"""Targeted recorded native-public projection tests for country prestige.

The fixture is checked into the repository so this module remains runnable in
a clean checkout.  It is a recorded read-only capture; it is not a live query
and does not authorize a new native call.
"""

from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path

import pytest

from bridge.information.country_state import NativeCountryStateSource
from bridge.information.sources import DiplomacySource


ROOT = Path(__file__).resolve().parents[2]
LIVE_FIXTURE = json.loads(
    (ROOT / "bridge/tests/fixtures/information_country_relations_live_1374.json")
    .read_text(encoding="utf-8")
)
LIVE_PUBLIC = LIVE_FIXTURE["captures"]["PAP"]["public"]
EXPECTED_GAME_SHA256 = (
    "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
)
EXPECTED_DATE = LIVE_FIXTURE["original_context"]["game_date"]
EXPECTED_RECIPIENT = "PAP"


class _ReplaySession:
    observer = "FRA"

    def __init__(self, public: dict, *, game_sha256: str = EXPECTED_GAME_SHA256,
                 game_version: str = "1.37.4", after: dict | None = None):
        self.session_id = "46820-1dd5cec467bc291"
        self.public = deepcopy(public)
        self.game_sha256 = game_sha256
        self.game_version = game_version
        self.after = deepcopy(after) if after else None
        self.health_calls = 0
        self.record = {
            "observer": "FRA",
            "controlled_countries": ["FRA"],
            "game_sha256": game_sha256,
            "game_version": game_version,
            "session_id": self.session_id,
        }

    def health(self) -> dict:
        self.health_calls += 1
        values = {
            "status": "ready",
            "complete": True,
            "date_raw": EXPECTED_DATE,
            "game_version": self.game_version,
            "game_sha256": self.game_sha256,
            "observer": "FRA",
            "reasons": [],
        }
        if self.after and self.health_calls >= 2:
            values.update(self.after)
            if "session_id" in self.after:
                self.session_id = self.after["session_id"]
        return values


class _ReplayTools:
    def __init__(self, session: _ReplaySession):
        self.session = session
        self.calls: list[tuple] = []

    def inspect_diplomatic_action(self, action_id, actor, recipient, phase,
                                  parameters):
        self.calls.append((action_id, actor, recipient, phase, deepcopy(parameters)))
        return deepcopy(self.session.public)


def _source(public: dict | None = None, **session_kwargs):
    session = _ReplaySession(public or LIVE_PUBLIC, **session_kwargs)
    tools = _ReplayTools(session)
    return NativeCountryStateSource(DiplomacySource(tools)), session, tools


def _query(reference_recipient: str = EXPECTED_RECIPIENT) -> dict:
    return {
        "topic": "N06",
        "object": {"type": "country", "country": "FRA"},
        "fields": ["prestige"],
        "parameters": {"reference_recipient": reference_recipient},
    }


def test_recorded_native_public_offer_projection_is_1374_real_evidence() -> None:
    assert LIVE_FIXTURE["provenance"]["mode"] == "recorded"
    assert LIVE_FIXTURE["provenance"]["original_mode"] == "live"
    assert LIVE_FIXTURE["provenance"]["read_only_native_query"] is True
    assert LIVE_FIXTURE["provenance"]["business_actions_submitted"] is False
    assert LIVE_FIXTURE["provenance"]["game_sha256"] == EXPECTED_GAME_SHA256
    assert LIVE_FIXTURE["provenance"]["game_version"] == "1.37.4"
    assert LIVE_FIXTURE["original_context"]["observer"] == "FRA"
    assert LIVE_PUBLIC["action_id"] == "offer_vassalization"
    assert LIVE_PUBLIC["family"] == "vassalization"
    assert LIVE_PUBLIC["phase"] == "initiate"
    assert LIVE_PUBLIC["actor"] == "FRA"
    assert LIVE_PUBLIC["recipient"] == EXPECTED_RECIPIENT
    assert LIVE_PUBLIC["prestige_raw"] == -11643
    assert LIVE_PUBLIC["prestige_scale"] == 1000


def test_real_recorded_public_prestige_is_known_and_uses_offer_query_only() -> None:
    source, _, tools = _source()
    result = source.read(_query())
    topic = next(item for item in source.catalog() if item["topic_id"] == "N06")

    assert topic["fields"]["prestige"] == {
        "coverage": "available",
        "source": "DiplomacyTools.inspect_diplomatic_action",
        "description": (
            "本国当前威望；只取 offer_vassalization 公共 projection "
            "的 prestige_raw，不取取消附庸费用"
        ),
        "unit": "prestige",
        "scale": 1000,
        "raw": True,
        "raw_semantics": "prestige_raw / 1000",
        "paths": ["prestige_raw"],
    }
    assert result["fields"]["prestige"] == {
        "status": "known", "value": -11643,
    }
    assert result["complete"] is True
    assert result["source"]["provenance"]["public_path"] == "prestige_raw"
    assert result["source"]["provenance"]["action_id"] == "offer_vassalization"
    assert result["source"]["provenance"]["context_guard"]["status"] == "passed"
    assert tools.calls == [(
        "offer_vassalization", "FRA", EXPECTED_RECIPIENT, "initiate", {}
    )]


@pytest.mark.parametrize("raw", [-2147483648, -1, 0, 2147483647])
def test_prestige_raw_int32_including_negative_and_zero_is_known(raw: int) -> None:
    public = deepcopy(LIVE_PUBLIC)
    public["prestige_raw"] = raw
    source, _, _ = _source(public)

    result = source.read(_query())

    assert result["fields"]["prestige"] == {"status": "known", "value": raw}


def test_prestige_does_not_read_cancel_fee() -> None:
    public = deepcopy(LIVE_PUBLIC)
    public["prestige_raw"] = 17
    public["cancel_prestige_delta_raw"] = -25000
    source, _, _ = _source(public)

    result = source.read(_query())

    assert result["fields"]["prestige"] == {"status": "known", "value": 17}


@pytest.mark.parametrize(
    ("field", "value", "reason"),
    [
        ("prestige_raw", True, "PUBLIC_PRESTIGE_PROJECTION_UNAVAILABLE"),
        ("prestige_raw", -(1 << 31) - 1, "PUBLIC_PRESTIGE_PROJECTION_UNAVAILABLE"),
        ("prestige_raw", 1 << 31, "PUBLIC_PRESTIGE_PROJECTION_UNAVAILABLE"),
        ("prestige_scale", False, "PUBLIC_PRESTIGE_PROJECTION_UNAVAILABLE"),
        ("prestige_scale", 1, "PUBLIC_PRESTIGE_PROJECTION_UNAVAILABLE"),
        ("family", "rival", "PUBLIC_PRESTIGE_ACTION_IDENTITY_MISMATCH"),
        ("action_id", "cancel_vassalization", "PUBLIC_PRESTIGE_ACTION_IDENTITY_MISMATCH"),
        ("phase", "respond", "PUBLIC_PRESTIGE_ACTION_IDENTITY_MISMATCH"),
        ("actor", "ENG", "PUBLIC_PROJECTION_IDENTITY_MISMATCH"),
        ("recipient", "PRO", "PUBLIC_PROJECTION_IDENTITY_MISMATCH"),
    ],
)
def test_prestige_rejects_bad_public_identity_or_raw(
    field: str, value, reason: str,
) -> None:
    public = deepcopy(LIVE_PUBLIC)
    public[field] = value
    source, _, _ = _source(public)

    result = source.read(_query())

    assert result["fields"]["prestige"] == {
        "status": "unknown", "reason": reason,
    }
    assert result["complete"] is False


def test_prestige_requires_live_1374_identity_before_query() -> None:
    source, _, tools = _source(game_sha256="0" * 64)

    result = source.read(_query())

    assert result["fields"]["prestige"] == {
        "status": "unavailable", "reason": "PRESTIGE_GAME_IDENTITY_MISMATCH",
    }
    assert tools.calls == []

    source, _, tools = _source()
    recorded = {**source.context(), "mode": "recorded"}
    result = source.read(_query(), recorded)
    assert result["fields"]["prestige"] == {
        "status": "unavailable", "reason": "PRESTIGE_LIVE_CONTEXT_UNAVAILABLE",
    }
    assert tools.calls == []


def test_prestige_rejects_context_change_after_inspection() -> None:
    source, _, tools = _source(after={"date_raw": EXPECTED_DATE + 24})

    result = source.read(_query())

    assert result["fields"]["prestige"] == {
        "status": "unknown", "reason": "PRESTIGE_CONTEXT_CHANGED",
    }
    assert result["complete"] is False
    assert tools.calls == [(
        "offer_vassalization", "FRA", EXPECTED_RECIPIENT, "initiate", {}
    )]

