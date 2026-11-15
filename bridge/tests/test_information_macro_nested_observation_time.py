"""Nested relation-memory captures may advance the game clock per query."""
from __future__ import annotations

from copy import deepcopy

import pytest

from bridge.information import directed_relation_memory as directed
from bridge.information import fleet_basing_memory as fleet
from bridge.information import relation_memory as relation
from bridge.information import trade_league_memory as trade_league
from bridge.information.observation_time import sampled_read


def _relation_context(game_date: int, *, date_address: str = "0x230003020") -> dict:
    return {
        "status": "observed",
        "game_date": {
            "address": {"va": date_address, "rva": "0x1c"},
            "raw_hex": game_date.to_bytes(4, "little").hex(),
            "value": game_date,
        },
        "actor": {"tag": "FRA", "fullref": {"value": 1}},
    }


def _relation_record(game_date: int) -> dict:
    return {
        "context": _relation_context(game_date),
        "read_log": [
            {"label": "game.raw_date", "raw_hex": game_date.to_bytes(4, "little").hex()},
            {"label": "database.country_table", "raw_hex": "00" * 8},
        ],
        "identity": {"pid": 1234},
        "fields": {"alliance": {"status": "known", "value": True}},
    }


def _trade_context(game_date: int, *, date_address: str = "0x230003020") -> dict:
    return {
        "game_address": "0x140000000",
        "game_pointer": "0x230003000",
        "game_raw_hex": "00" * 8,
        "game_date_address": date_address,
        "game_date_raw_hex": game_date.to_bytes(4, "little").hex(),
        "game_date": game_date,
    }


def _trade_record(game_date: int) -> dict:
    return {
        "context": _trade_context(game_date),
        "read_log": [
            {"label": "pass.game_date", "raw_hex": game_date.to_bytes(4, "little").hex()},
            {"label": "pass.game_global", "raw_hex": "00" * 8},
        ],
        "identity": {"pid": 1234},
        "fields": {"trade_league": {"status": "known", "value": False}},
    }


@pytest.mark.parametrize(
    ("stable", "record_factory"),
    [
        (relation._without_volatile, _relation_record),
        (fleet._without_volatile, _relation_record),
        (directed._without_volatile, _relation_record),
        (trade_league._stable, _trade_record),
    ],
)
def test_nested_stable_comparisons_ignore_only_clock_inside_active_window(stable, record_factory):
    before = record_factory(10)
    after = record_factory(11)
    original_before = deepcopy(before)
    with sampled_read({"topic": "R01"}, {"mode": "live", "game_date": 10}):
        assert stable(before) == stable(after)
        changed_identity = deepcopy(after)
        changed_identity["identity"]["pid"] = 1235
        assert stable(before) != stable(changed_identity)
    assert before == original_before
    assert before["read_log"][0]["label"] in {"game.raw_date", "pass.game_date"}


def test_default_remains_strict_and_date_guards_reject_rollback_and_identity_change():
    before = _relation_record(10)
    after = _relation_record(11)
    assert relation._without_volatile(before) != relation._without_volatile(after)
    assert not relation._observation_dates_match(before["context"], after["context"])
    assert not trade_league._observation_dates_match(_trade_context(10), _trade_context(11))

    with sampled_read({"topic": "R01"}, {"mode": "live", "game_date": 10}):
        assert not relation._observation_dates_match(_relation_context(12), _relation_context(11))
        assert not relation._observation_dates_match(
            _relation_context(10), _relation_context(11, date_address="0x230003024"),
        )
        assert not trade_league._observation_dates_match(_trade_context(12), _trade_context(11))
        assert not trade_league._observation_dates_match(
            _trade_context(10), _trade_context(11, date_address="0x230003024"),
        )


def test_capture_clock_must_follow_heartbeat_anchor_without_lagging_post_context():
    with sampled_read({"topic": "R01"}, {"mode": "live", "game_date": 10}):
        assert relation._observation_dates_match(_relation_context(11), _relation_context(12), 10, anchor_present=True)
        assert not relation._observation_dates_match(_relation_context(11), _relation_context(12), 12, anchor_present=True)
        assert trade_league._observation_dates_match(_trade_context(11), _trade_context(12), 10, anchor_present=True)
        assert not trade_league._observation_dates_match(_trade_context(11), _trade_context(12), 12, anchor_present=True)
