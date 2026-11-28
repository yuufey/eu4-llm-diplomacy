"""Regression tests for field paths in the information catalog.

The catalog may expose a field only when the public projection carries that
field's meaning.  An aggregate envelope, action family, or unrelated sibling
field must leave the requested field unknown.
"""

from __future__ import annotations

import pytest
from copy import deepcopy
import json
from pathlib import Path

from bridge.diplomacy import ObserverSession

from bridge.information.catalog import get_topic, list_topics
from bridge.information.sources import _field_result


def _extract(topic_id: str, field: str, payload: dict) -> dict:
    topic = get_topic(topic_id)
    fields, _complete = _field_result([field], payload, topic)
    return fields[field]


def test_catalog_shape_has_75_topics_and_406_fields():
    topics = list_topics()
    assert len(topics) == 75
    assert sum(len(topic["fields"]) for topic in topics) == 406
    battle = next(topic for topic in topics if topic["topic_id"] == "B01")
    assert "H01.battle_sequence" in battle["query_guidance"]["message"]
    assert "W03.battle_losses" in battle["query_guidance"]["message"]
    assert {"max_manpower", "max_sailors"} <= set(get_topic("N02")["fields"])


@pytest.mark.parametrize(("topic_id", "field", "path"), [
    ("D01", "beneficiary", ("parameters", "actual", "war_goal", "beneficiary")),
    ("D05", "attacker_forces", ("forces", "attackers")),
    ("D05", "defender_forces", ("forces", "defenders")),
])
def test_current_declare_war_preview_fields_use_their_live_paths(topic_id, field, path):
    fixture = Path(__file__).parent / "fixtures" / "information_declare_war_participants_FRA_GEN_live_1374.json"
    payload = json.loads(fixture.read_text(encoding="utf-8"))["inspection"]
    expected = payload
    for key in path:
        expected = expected[key]
    actual = _extract(topic_id, field, payload)
    assert actual["status"] == "known"
    assert actual["value"] == expected


@pytest.mark.parametrize(("topic_id", "field", "payload", "expected"), [
    ("D01", "beneficiary", {"beneficiary": "ORL", "parameters": {"actual": {
        "war_goal": {"beneficiary": "FRA"}}}}, "ORL"),
    ("D05", "attacker_forces", {"forces": {
        "attacker": {"total": 10}, "attackers": {"deployed": {"total": 20}}}}, {"total": 10}),
    ("D05", "defender_forces", {"war_context": {"forces": {"defender": {"total": 30}}},
        "forces": {"defenders": {"deployed": {"total": 40}}}}, {"total": 30}),
])
def test_existing_declare_war_field_aliases_keep_their_precedence(topic_id, field, payload, expected):
    assert _extract(topic_id, field, payload)["value"] == expected


def test_selected_declare_war_cost_items_project_verified_individual_resources():
    costs = ObserverSession._public_declare_war_costs({"native_costs": {
        "stability_available": True, "stability_hit_raw": 5000, "stability_scale": 1000,
        "warex_available": True, "warex_display_raw": 2000,
    }})
    costs["context"] = "selected_parameters"
    stability = _extract("D02", "stability_cost", {"costs": costs})
    exhaustion = _extract("D02", "war_exhaustion_cost", {"costs": costs})
    assert stability["value"] == 5.0 and stability["unit"] == "stability_loss"
    assert exhaustion["value"] == 2.0 and exhaustion["unit"] == "war_exhaustion"
    assert stability["scale"] == exhaustion["scale"] == 1
    assert _extract("D02", "other_costs", {"costs": costs})["status"] == "unknown"


@pytest.mark.parametrize("change", ["default_context", "unverified_unit", "duplicate_item", "wrong_amount"])
def test_declare_war_cost_items_require_selected_unique_verified_units(change):
    costs = ObserverSession._public_declare_war_costs({"native_costs": {
        "stability_available": True, "stability_hit_raw": 5000, "stability_scale": 1000,
    }})
    costs["context"] = "selected_parameters"
    if change == "default_context":
        costs["context"] = "default_parameters_unselected"
    elif change == "unverified_unit":
        costs["items"][0]["unit_verified"] = False
    elif change == "duplicate_item":
        costs["items"].append(deepcopy(costs["items"][0]))
    else:
        costs["items"][0]["amount"] = 5000
    assert _extract("D02", "stability_cost", {"costs": costs})["status"] == "unknown"


@pytest.mark.parametrize(
    ("topic_id", "field", "payload"),
    [
        (
            "D01",
            "casus_belli",
            {"parameters": {"actual": {"war_goal": {"province_id": 1}}}},
        ),
        (
            "D02",
            "other_costs",
            {"costs": {"stability": 1, "war_exhaustion": 2}},
        ),
        (
            "D04",
            "willingness",
            {"acceptance": {"predicted_response": "yes"}},
        ),
        (
            "D04",
            "reasons",
            {"acceptance": {"items": [{"reason": "unknown"}]}},
        ),
        (
            "A03",
            "parameters",
            {"parameters": {"requested": {"ducats": 25}, "complete": True}},
        ),
        (
            "A03",
            "resource_direction",
            {"family": "gift"},
        ),
        (
            "A03",
            "relation_effects",
            {"effects": {"opinion": 25}},
        ),
        (
            "A04",
            "parameters",
            {"peace_context": {"terms": []}},
        ),
        (
            "A05",
            "submitted",
            {"submitted_at": "2026-10-24T00:00:00+00:00"},
        ),
        (
            "H01",
            "snapshot_changes",
            {"payload": {"relationship_changes": [{"country": "PAP"}]}},
        ),
    ],
)
def test_aggregate_or_approximate_values_do_not_fill_specific_fields(
    topic_id: str, field: str, payload: dict
):
    assert _extract(topic_id, field, payload)["status"] == "unknown"


@pytest.mark.parametrize(
    ("topic_id", "field", "forbidden_path"),
    [
        ("D01", "casus_belli", "parameters.actual"),
        ("D02", "other_costs", "costs"),
        ("D04", "willingness", "acceptance.predicted_response"),
        ("D04", "reasons", "acceptance.items"),
        ("A03", "parameters", "parameters"),
        ("A03", "resource_direction", "family"),
        ("A03", "relation_effects", "effects"),
        ("A04", "parameters", "peace_context"),
        ("A05", "submitted", "submitted_at"),
        ("H01", "snapshot_changes", "payload"),
    ],
)
def test_specific_fields_have_no_broad_fallback_path(
    topic_id: str, field: str, forbidden_path: str
):
    paths = get_topic(topic_id)["fields"][field].get("paths", [])
    assert forbidden_path not in paths

