"""Real R73/R74 public-projection tests for country-state information."""

from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path

import pytest

from bridge.diplomacy import DiplomacyTools, ObserverSession
from bridge.information.country_state import NativeCountryStateSource
from bridge.information.model import InformationError
from bridge.information.sources import DiplomacySource
from bridge.native_text import EU4_ESCAPE_CODEC


FIXTURES = Path(__file__).parent / "fixtures"
R73 = json.loads((FIXTURES / "r73_favor_queries_real.json").read_text(encoding="utf-8"))
R74 = json.loads((FIXTURES / "r74_economic_queries_real.json").read_text(encoding="utf-8"))


class _ReplaySession:
    """Replay one captured native event through the real public adapter."""

    observer = "FRA"
    native_text_codec = EU4_ESCAPE_CODEC

    def __init__(self, event: dict, capabilities: set[str]):
        self.event = deepcopy(event)
        self.session_id = event["session_id"]
        self.capabilities = frozenset(capabilities)
        self.record = {
            "observer": "FRA",
            "controlled_countries": ["FRA"],
            "game_sha256": "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77",
        }
        self.submit_calls: list[tuple] = []

    def health(self) -> dict:
        return {
            "status": "ready",
            "date_raw": self.event["date_raw"],
            "complete": True,
            "reasons": [],
        }

    def installation_capabilities(self):
        return self.capabilities

    def inspect_alliance(self, *args, **kwargs):
        return ObserverSession._semantic_inspection(
            self.event, {}, codec=EU4_ESCAPE_CODEC
        )

    def inspect_send_gift(self, *args, **kwargs):
        return ObserverSession._semantic_inspection(
            self.event, {}, codec=EU4_ESCAPE_CODEC
        )

    def submit_alliance(self, *args, **kwargs):
        self.submit_calls.append((args, kwargs))
        raise AssertionError("country-state source must not submit diplomacy")

    def submit_send_gift(self, *args, **kwargs):
        self.submit_calls.append((args, kwargs))
        raise AssertionError("country-state source must not submit diplomacy")


def _source(event: dict, capabilities: set[str]) -> tuple[NativeCountryStateSource, _ReplaySession]:
    session = _ReplaySession(event, capabilities)
    tools = DiplomacyTools(None, session)
    return NativeCountryStateSource(DiplomacySource(tools)), session


def _query(
    topic: str,
    fields: list[str],
    reference_recipient: str | None = "PAP",
) -> dict:
    return {
        "topic": topic,
        "object": {"type": "country", "country": "FRA"},
        "fields": fields,
        "parameters": (
            {} if reference_recipient is None
            else {"reference_recipient": reference_recipient}
        ),
    }


def _r73_case(name: str) -> dict:
    return next(case["raw"] for case in R73["cases"] if case["name"] == name)


def test_catalog_exposes_only_verified_country_fields() -> None:
    source, _ = _source(
        _r73_case("men_FRA_PAP"),
        {"native_favor_men_query", "native_favor_men_submission"},
    )
    topics = {item["topic_id"]: item for item in source.catalog()}
    assert set(topics) == {"N01", "N02", "N05", "N06"}
    assert topics["N01"]["fields"]["treasury"] == {
        "coverage": "available",
        "source": "DiplomacyTools.inspect_diplomatic_action",
        "description": "本国可用国库余额；原生公共 projection 的 raw 值",
        "unit": "ducats",
        "scale": 1000,
        "paths": ["gift.controlled_treasury.raw"],
    }
    assert set(topics["N01"]["fields"]) == {
        "treasury", "monthly_income", "monthly_expenses", "monthly_balance",
        "war_income",
    }
    for field in ("monthly_income", "monthly_expenses", "monthly_balance"):
        assert topics["N01"]["fields"][field]["coverage"] == "partial"
        assert topics["N01"]["fields"][field]["reference_period"] == "previous_month"
        assert topics["N01"]["fields"][field]["value_semantics"] == (
            "previous_month_recurring_ledger"
        )
    assert set(topics["N02"]["fields"]) == {"manpower", "max_manpower", "max_sailors"}
    assert set(topics["N05"]["fields"]) == {"diplomats_available"}
    for topic in topics.values():
        assert topic["object_types"] == ["country"]
        if topic["topic_id"] == "N06":
            assert list(topic["fields"])[0] == "monarch_points"
            assert topic["parameters"]["required"] == []
        elif topic["topic_id"] == "N01":
            assert topic["parameters"]["required"] == []
        elif topic["topic_id"] == "N05":
            assert topic["parameters"]["required"] == []
            assert "diplomats_available" in topic["parameters"]["properties"]["reference_recipient"]["description"]
            assert "diplomat_tasks" in topic["parameters"]["properties"]["reference_recipient"]["description"]
        elif topic["topic_id"] == "N02":
            # Own resources use the live cache. Pair inspection is optional.
            assert topic["parameters"]["required"] == []
            description = topic["parameters"]["properties"]["reference_recipient"]["description"]
            assert "manpower" in description
        else:
            assert topic["parameters"]["required"] == ["reference_recipient"]
        assert topic["triggers"] == ["query", "periodic", "change"]

    points_only = {
        "topic": "N06",
        "object": {"type": "country", "country": "FRA"},
        "fields": ["monarch_points"],
    }
    assert source.validate_query(points_only)["parameters"] == {}
    with pytest.raises(InformationError):
        source.validate_query({**points_only, "fields": ["prestige"]})


def test_r74_treasury_uses_controlled_actor_public_projection_only() -> None:
    event = R74["economic_events"][0]
    source, session = _source(
        event, {"native_gift_query", "native_gift_submission"}
    )
    public = source.base_source.diplomacy_tools.inspect_diplomatic_action(
        "send_gift", "FRA", "PAP", "initiate", {"ducats": 25}
    )
    controlled = public["gift"]["controlled_treasury"]
    assert controlled == {
        "country": "FRA", "raw": event["native_gift"]["actor_treasury_raw"],
        "unit": "ducats", "scale": 1000,
    }

    result = source.read(_query("N01", ["treasury"]))
    assert result["fields"]["treasury"] == {
        "status": "known", "value": event["native_gift"]["actor_treasury_raw"]
    }
    assert result["source"]["provenance"]["public_path"] == "gift.controlled_treasury.raw"
    assert "recipient_treasury_raw" not in json.dumps(result, ensure_ascii=False)
    assert session.submit_calls == []


@pytest.mark.parametrize(
    ("name", "expected_manpower", "expected_diplomats"),
    [
        ("men_FRA_PAP", 38705, 1),
        ("men_FRA_SAV_no_diplomat", 39347, 0),
    ],
)
def test_r73_manpower_and_diplomat_count_follow_public_projection(
    name: str, expected_manpower: int, expected_diplomats: int
) -> None:
    event = _r73_case(name)
    source, session = _source(
        event,
        {"native_favor_men_query", "native_favor_men_submission"},
    )
    public = source.base_source.diplomacy_tools.inspect_diplomatic_action(
        "trade_favors_for_men", "FRA", event["recipient"], "initiate", {}
    )
    assert public["favor_trade"]["manpower"]["actor_raw"] == expected_manpower
    assert public["favor_trade"]["manpower"]["recipient_raw"] == event[
        "native_favor_trade"
    ]["recipient_manpower_raw"]
    assert public["resources"]["diplomats"]["available_count"] == expected_diplomats

    result_manpower = source.read(_query("N02", ["manpower"], event["recipient"]))
    result_diplomats = source.read(
        _query("N05", ["diplomats_available"], event["recipient"])
    )
    assert result_manpower["fields"]["manpower"] == {
        "status": "known", "value": expected_manpower
    }
    assert result_diplomats["fields"]["diplomats_available"] == {
        "status": "known", "value": expected_diplomats
    }
    assert "recipient_raw" not in json.dumps(result_manpower, ensure_ascii=False)
    assert result_manpower["objects"] == [{"type": "country", "country": "FRA"}]
    assert session.submit_calls == []


def test_country_scope_and_reference_recipient_are_explicit() -> None:
    source, _ = _source(
        _r73_case("men_FRA_PAP"),
        {"native_favor_men_query", "native_favor_men_submission"},
    )
    with pytest.raises(InformationError) as scope:
        source.validate_query(
            {
                **_query("N02", ["manpower"]),
                "object": {"type": "country", "country": "ENG"},
            },
            source.context(),
        )
    assert scope.value.code == "observer_scope_mismatch"

    missing_reference = _query("N02", ["manpower"])
    missing_reference["parameters"] = {}
    assert source.validate_query(missing_reference, source.context())["parameters"] == {}

    with pytest.raises(InformationError) as same:
        source.validate_query(_query("N02", ["manpower"], "FRA"), source.context())
    assert same.value.code == "invalid_parameters"


def test_n01_reference_recipient_is_optional_but_validated_when_supplied() -> None:
    source, _ = _source(
        _r73_case("men_FRA_PAP"),
        {"native_favor_men_query", "native_favor_men_submission"},
    )

    without_reference = _query("N01", ["treasury"], None)
    assert source.validate_query(without_reference, source.context())["parameters"] == {}

    with_reference = _query("N01", ["treasury"], "PAP")
    assert source.validate_query(with_reference, source.context())["parameters"] == {
        "reference_recipient": "PAP"
    }


def test_unready_source_and_unimplemented_fields_are_explicit() -> None:
    source, _ = _source(
        _r73_case("men_FRA_PAP"),
        {"native_favor_men_query", "native_favor_men_submission"},
    )
    unready_context = {**source.context(), "status": "unready"}
    result = source.read(_query("N02", ["manpower"]), unready_context)
    assert result["fields"]["manpower"] == {
        "status": "unavailable", "reason": "SESSION_UNREADY"
    }
    monthly_only = _query("N01", ["monthly_income"])
    monthly_only["parameters"] = {}
    assert source.validate_query(monthly_only, source.context())["parameters"] == {}


def test_country_state_source_has_no_event_stream() -> None:
    source, _ = _source(
        _r73_case("men_FRA_PAP"),
        {"native_favor_men_query", "native_favor_men_submission"},
    )
    assert source.poll_events(source.context(), None) == {
        "events": [], "cursor": {}, "complete": True, "gaps": []
    }
