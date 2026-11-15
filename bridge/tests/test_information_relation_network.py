"""Public network projection boundaries; raw capture validation is tested separately."""
from copy import deepcopy

import pytest

from bridge.information.model import InformationError
from bridge.information.relation_state import NativeRelationSource


def context():
    return {"status": "ready", "mode": "live", "complete": True,
            "observer": "FRA", "game_version": "1.37.4",
            "game_sha256": "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77",
            "dll_sha256": "d" * 64, "session_id": "network-projection-test",
            "game_date": 56557728, "game_date_raw": 56557728,
            "world_id": "network-projection-test", "paused": True}


class Primary:
    def __init__(self):
        self.current = context()

    def context(self):
        return deepcopy(self.current)


def query(parameters=None):
    return {"topic": "R01", "object": {"type": "country", "country": "FRA"},
            "fields": ["relation_type", "status", "grantor", "recipient"],
            "parameters": {"relation_types": ["alliance", "royal_marriage"]} if parameters is None else parameters}


def adapter(report, *, change_context=False):
    primary = Primary()
    source = NativeRelationSource(primary)

    def accepted_report(actor, recipient, families, supplied_context):
        assert actor == "FRA" and recipient is None
        assert families == ["alliance", "royal_marriage"]
        if change_context:
            primary.current["game_date"] += 24
            primary.current["game_date_raw"] += 24
        return deepcopy(report), None

    # This seam represents a capture already accepted by the real validator.
    # It isolates public projection behavior; it is not runtime evidence.
    source._memory_report = accepted_report
    return source


def test_known_network_members_have_partner_identity_and_symmetric_roles():
    source = adapter({"fields": {
        "alliance": {"status": "known", "value": [{"country": "SAV", "active": True}]},
        "royal_marriage": {"status": "known", "value": []}}})
    result = source.read(query())
    assert result["complete"] is False
    assert result["fields"]["status"]["value"] == [
        {"relation_type": "alliance", "actor": "FRA", "partner": "SAV",
         "status": "known", "value": "active"}]
    for field in ("grantor", "recipient"):
        assert result["fields"][field]["value"][0]["status"] == "not_applicable"
    assert result["source"]["provenance"]["inspection_calls"][0]["families"]["royal_marriage"] == {
        "status": "known", "active_partner_count": 0}


@pytest.mark.parametrize("state,has_unknown", [("known", False), ("partial", True)])
def test_empty_complete_family_is_distinct_from_unresolved_enumeration(state, has_unknown):
    source = adapter({"fields": {family: {"status": state, "value": []}
                                 for family in ("alliance", "royal_marriage")}})
    result = source.read(query())
    rows = result["fields"]["status"]["value"]
    assert bool(rows) is has_unknown
    if has_unknown:
        assert len(rows) == 2
        assert all(row["status"] == "unknown" and row["partner"] is None for row in rows)


def test_context_change_withdraws_all_network_partners():
    source = adapter({"fields": {
        "alliance": {"status": "known", "value": [{"country": "SAV", "active": True}]},
        "royal_marriage": {"status": "known", "value": []}}}, change_context=True)
    result = source.read(query())
    assert all(field["status"] == "unknown" for field in result["fields"].values())
    assert all("value" not in field for field in result["fields"].values())
    assert "CONTEXT_CHANGED_DURING_QUERY" in str(result)


def test_country_view_rejects_selected_pair_only_families():
    source = NativeRelationSource(Primary())
    with pytest.raises(InformationError):
        source.validate_query(query({"relation_types": ["vassalization"]}))
    assert "SELECTED_COUNTRY_PAIR_ONLY" not in str(source.catalog())


def test_country_default_includes_all_six_current_cache_families():
    source = NativeRelationSource(Primary())
    assert source.validate_query(query({}))["parameters"]["relation_types"] == [
        "alliance", "royal_marriage", "fleet_basing", "trade_league", "guarantee", "military_access"]


@pytest.mark.parametrize("family,directions", [
    ("guarantee", [("granted", "forward"), ("received", "reverse")]),
    ("military_access", [("received", "forward"), ("granted", "reverse")]),
])
def test_directed_network_preserves_native_path_and_grantor_roles(family, directions):
    source = NativeRelationSource(Primary())
    source._directed_report = lambda *_: ({"fields": {family: {
        "status": "known", "value": [{"country": "SAV", "active": True,
                                       "direction": direction, "operand_direction": operand}
                                      for direction, operand in directions]}}}, None)
    result = source.read(query({"relation_types": [family]}))
    for index, (direction, operand) in enumerate(directions):
        status = result["fields"]["status"]["value"][index]
        assert (status["value"], status["direction"], status["operand_direction"]) == ("active", direction, operand)
        grantor = "SAV" if direction == "received" else "FRA"
        recipient = "FRA" if direction == "received" else "SAV"
        assert result["fields"]["grantor"]["value"][index]["value"] == grantor
        assert result["fields"]["recipient"]["value"][index]["value"] == recipient


def test_directed_network_partial_direction_keeps_known_partner():
    source = NativeRelationSource(Primary())
    source._directed_report = lambda *_: ({"fields": {"military_access": {
        "status": "partial", "value": [{"country": "SAV", "active": True, "direction": "received"}],
        "unknown_rows": [{"country": "SAV", "direction": "granted", "reason": "ROW_UNREAD"}]}}}, None)
    result = source.read(query({"relation_types": ["military_access"]}))
    values = result["fields"]["status"]["value"]
    assert values[0]["value"] == "active" and values[0]["direction"] == "received"
    assert values[1] == {"relation_type": "military_access", "actor": "FRA", "partner": "SAV",
                         "status": "unknown", "reason": "ROW_UNREAD", "direction": "granted"}


def test_directed_family_failure_keeps_stable_sibling_family():
    source = NativeRelationSource(Primary())
    source._directed_report = lambda *_: ({"fields": {
        "guarantee": {"status": "unknown", "value": [], "reason": "GUARANTEE_RECORD_UNREAD"},
        "military_access": {"status": "known", "value": [
            {"country": "SAV", "active": True, "direction": "granted"}]}}}, None)
    result = source.read(query({"relation_types": ["guarantee", "military_access"]}))
    rows = result["fields"]["status"]["value"]
    assert rows[0]["status"] == "unknown" and rows[0]["relation_type"] == "guarantee"
    assert rows[1]["status"] == "known" and rows[1]["value"] == "active"
    assert rows[1]["relation_type"] == "military_access"


def test_fleet_pair_preserves_both_directions_and_their_roles():
    source = NativeRelationSource(Primary())
    source._extension_report = lambda *args: ({"fields": {"fleet_basing": {
        "status": "known", "value": {direction: {"status": "known", "value": True}
                                      for direction in ("received", "granted")}}}}, None)
    selected = query({"relation_types": ["fleet_basing"]})
    selected["object"] = {"type": "country_pair", "actor": "FRA", "recipient": "SAV"}
    result = source.read(selected)
    assert [(row["direction"], row["value"]) for row in result["fields"]["grantor"]["value"]] == [
        ("received", "SAV"), ("granted", "FRA")]
    assert [(row["direction"], row["value"]) for row in result["fields"]["recipient"]["value"]] == [
        ("received", "FRA"), ("granted", "SAV")]


def test_bad_fleet_direction_preserves_the_other_direction():
    source = NativeRelationSource(Primary())
    source._extension_report = lambda *args: ({"fields": {"fleet_basing": {
        "status": "partial", "value": {
            "received": {"status": "known", "value": True},
            "granted": {"status": "unknown", "reason": "INVALID_VECTOR"}}}}}, None)
    selected = query({"relation_types": ["fleet_basing"]})
    selected["object"] = {"type": "country_pair", "actor": "FRA", "recipient": "SAV"}
    rows = source.read(selected)["fields"]["status"]["value"]
    assert rows[0] == {"relation_type": "fleet_basing", "direction": "received", "status": "known", "value": "active"}
    assert rows[1]["status"] == "unknown" and rows[1]["direction"] == "granted"


def test_trade_league_keeps_group_leader_without_inventing_grantor_role():
    source = NativeRelationSource(Primary())
    source._extension_report = lambda *args: ({"fields": {"trade_league": {
        "status": "known", "value": [{"country": "RIG", "active": True, "league_leader": "HSA"}]}}}, None)
    result = source.read(query({"relation_types": ["trade_league"]}))
    assert result["fields"]["status"]["value"] == [{
        "relation_type": "trade_league", "actor": "FRA", "partner": "RIG",
        "status": "known", "value": "active", "league_leader": "HSA"}]
    grantor = result["fields"]["grantor"]["value"][0]
    assert grantor["status"] == "not_applicable"
    assert grantor["reason"] == "GROUP_MEMBERSHIP_NO_GRANTOR_ROLE"
