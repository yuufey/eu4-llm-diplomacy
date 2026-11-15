"""Regression tests for the default LLM-facing information presentation."""
from copy import deepcopy

import pytest

from bridge.information.presentation import present_concise
from bridge.information.tools import InformationTools


def _known(value, *, scale=1, **metadata):
    return {"status": "known", "value": value, "scale": scale, **metadata}


@pytest.mark.parametrize("native,expected", [
    ({"status": "unknown", "reason": "READ_FAILED"}, None),
    (_known({"entries": []}), []),
    (_known({"entries": [{"proposal_id": "proposal-a", "actor": "SAV"}]}),
     [{"proposal_id": "proposal-a", "actor": "SAV"}]),
])
def test_pending_matters_preserve_business_status_unknown_inventory_and_cursor(native, expected):
    request = {"request_id": "uncertain", "action_id": "offer_alliance", "actor": "FRA",
               "recipient": "SAV", "phase": "initiate", "status": "unknown",
               "review_kind": "requires_reconciliation", "has_submission_claim": True,
               "claimed_at": "internal timestamp"}
    result = {"items": [{"query": {"topic": "C03"}, "fields": {"pending_matters": _known({
        "journal_requests": [request], "native_inbound_pending": native,
        "pagination": {"returned": 1, "has_more": True, "next_after_request_id": "uncertain"},
    })}}]}
    before = deepcopy(result)
    actual = present_concise(result)["items"][0]["pending_matters"]
    assert actual == {"requests": [{key: value for key, value in request.items()
                                   if key not in {"has_submission_claim", "claimed_at"}}],
                      "proposals": expected, "next_after_request_id": "uncertain"}
    assert result == before


def test_pending_matters_empty_last_page_has_no_next_cursor():
    result = {"items": [{"query": {"topic": "C03"}, "fields": {"pending_matters": _known({
        "journal_requests": [], "native_inbound_pending": _known({"entries": []}),
        "pagination": {"returned": 0, "has_more": False, "next_after_request_id": None},
    })}}]}
    assert present_concise(result)["items"] == [{"pending_matters": {"requests": [], "proposals": []}}]


def test_modifier_effects_keep_identity_and_configured_effect_names():
    result = {"items": [{"query": {"topic": "N07", "object": {"country": "FRA"}}, "fields": {
        "modifier_id": {"status": "unknown"},
        "name": _known([dict(_known("贵族的成长"), modifier_id="growth"),
                        {"modifier_id": "legacy", "status": "unknown"}]),
        "effects": _known([
            {"modifier_id": "growth", "effects": [{"index": 159, "raw": 1000, "scale": 1000,
                                                      "unit": "native_fixed_point"}],
             "named_effects": _known({"diplomatic_upkeep": _known(1), "nobles_loyalty_modifier": _known(0.1)})},
            {"modifier_id": "legacy", "effects": [{"raw": 200, "scale": 1000, "unit": "native_fixed_point"}]},
        ])}}]}
    before = deepcopy(result)
    assert present_concise(result)["items"] == [{"country": "FRA", "modifiers": [
        {"modifier_id": "growth", "name": "贵族的成长",
         "effects": {"diplomatic_upkeep": 1, "nobles_loyalty_modifier": 0.1}},
        {"modifier_id": "legacy", "name": None, "effects": None},
    ]}]
    assert result == before


def test_unavailable_modifier_collection_is_distinct_from_known_empty_collection():
    result = {"items": [
        {"query": {"topic": "N07"}, "fields": {"modifier_id": {"status": "unknown"}}},
        {"query": {"topic": "N08"}, "fields": {"remaining_days": _known([])}},
    ]}
    assert present_concise(result)["items"] == [{"modifiers": None}, {"modifiers": []}]


@pytest.mark.parametrize("operation", ["set", "replace", "remove"])
def test_rival_notifications_have_readable_dates_and_applicable_old_rival(operation):
    old_rival = "CAS" if operation == "replace" else None
    payload = {
        "country": "FRA", "actor": "FRA", "recipient": "HAB",
        "operation": operation, "old_rival": old_rival,
        "count_basis": "active_nonretired_nodes",
        "before": {"count": 2, "target_active": False, "target_since_date_raw": -1,
                   "old_active": old_rival is not None, "old_since_date_raw": 56692752},
        "after": {"count": 3, "target_active": True, "target_since_date_raw": 56692752,
                  "old_active": False, "old_since_date_raw": -1},
    }
    result = {
        "event": {"event_type": "rival_changed", "payload": payload},
        "items": [{"query": {"topic": "C04"}, "fields": {"event_payload": _known(payload)}}],
    }
    before = deepcopy(result)
    concise = present_concise(result)
    actual = concise["items"][0]["event_payload"]
    assert actual == concise["event"]["payload"]
    assert "count_basis" not in actual
    assert actual["before"]["target_since"] is None
    assert actual["after"]["target_since"] == "1471.10.11"
    assert "target_since_date_raw" not in actual["after"]
    if old_rival is None:
        assert "old_rival" not in actual
        assert "old_active" not in actual["before"]
        assert "old_since" not in actual["after"]
    else:
        assert actual["old_rival"] == old_rival
        assert actual["before"]["old_since"] == "1471.10.11"
        assert actual["after"]["old_since"] is None
    assert result == before


@pytest.mark.parametrize('date,expected', [(56685192, '1470.11.30'), ('1470.11.30', '1470.11.30'),
                                         (None, None), (-1, None)])
def test_event_dates_are_readable_in_selected_fields_and_event_metadata(date, expected):
    result = {'event': {'event_type': 'relation_changed', 'game_date': date},
              'items': [{'query': {'topic': 'C04'}, 'fields': {'event_date': _known(date)}}]}
    before = deepcopy(result)
    concise = present_concise(result)
    assert concise['event']['game_date'] == expected
    assert concise['items'][0]['event_date'] == expected
    assert result == before


@pytest.mark.parametrize('change', ['added', 'removed', 'expired'])
@pytest.mark.parametrize('end,expected_end', [(56773248, '1480.12.19'), (43800000, None)])
def test_modifier_notifications_use_readable_dates_and_hide_internal_flags(change, end, expected_end):
    payload = {'country': 'FRA', 'modifier_id': 'power_to_provinces', 'change': change,
               'start_date_raw': 43808760, 'end_date_raw': end, 'flags_raw': [1, 0, 0, 0],
               'scope': 'FRA_direct_temporary_records'}
    result = {'event': {'event_type': 'country_modifier_' + change, 'payload': payload},
              'items': [{'query': {'topic': 'C04'}, 'fields': {'event_payload': _known(payload)}}]}
    before = deepcopy(result)
    concise = present_concise(result)
    expected = {'country': 'FRA', 'modifier_id': 'power_to_provinces', 'change': change,
                'start_date': None, 'end_date': expected_end}
    assert concise['items'][0]['event_payload'] == expected
    assert concise['event']['payload'] == expected
    assert result == before


def test_modifier_dates_and_remaining_days_stay_with_their_instance():
    result = {"items": [{"query": {"topic": "N08"}, "fields": {
        "modifier_end_date": _known([
            dict(_known(56685264, unit="game_date_raw"), modifier_id="growth"),
            {"modifier_id": "permanent", "status": "not_applicable"}]),
        "remaining_days": _known([
            dict(_known(72, scale=24, unit="days"), modifier_id="growth"),
            {"modifier_id": "permanent", "status": "not_applicable"}], scale=24),
        "modifier_start_date": {"status": "unknown"},
    }}, {"query": {"topic": "N07"}, "fields": {"modifier_id": _known([])}}]}
    before = deepcopy(result)
    assert present_concise(result)["items"] == [{"modifiers": [
        {"modifier_id": "growth", "end_date": "1470.12.3", "remaining_days": 3, "start_date": None},
        {"modifier_id": "permanent", "end_date": None, "remaining_days": None, "start_date": None},
    ]}, {"modifiers": []}]
    assert result == before


def test_repeated_modifier_keys_preserve_each_instance_in_native_order():
    result = {"items": [{"query": {"topic": "N08"}, "fields": {
        "remaining_days": _known([dict(_known(ticks, scale=24), modifier_id="repeated")
                                  for ticks in (0, 48)]),
    }}]}
    assert present_concise(result)["items"] == [{"modifiers": [
        {"modifier_id": "repeated", "remaining_days": 0},
        {"modifier_id": "repeated", "remaining_days": 2},
    ]}]


def test_nested_morale_force_limits_and_resource_ranges():
    result = {"result_id": "ranges", "items": [
        {"query": {"topic": "N02", "object": {"country": "FRA"}}, "fields": {
            "army_size": _known(56), "navy_size": _known(20), "manpower": _known(47934),
            "force_limits": _known({"land": {"value": 56, "raw": 56000, "scale": 1000},
                                    "naval": {"value": 25, "raw": 25000, "scale": 1000}})}},
        {"query": {"topic": "N03"}, "fields": {
            "morale": _known({"army": 4176, "navy": 2148}, scale=1000, unit="morale"),
            "discipline": _known(1050, scale=1000)}},
        {"query": {"topic": "N04"}, "fields": {
            "stability": _known(-1000, scale=1000), "war_exhaustion": _known(0),
            "corruption": _known(1988, scale=1000), "unrest": _known(-17917, scale=1000),
            "overextension": _known(1250, scale=1000), "religious_unity": _known(1100, scale=1000)}}]}
    before = deepcopy(result)
    army, quality, domestic = present_concise(result)["items"]
    assert army["army_regiments"] == {"current": 56, "max": 56}
    assert army["navy_ships"] == {"current": 20, "max": 25}
    assert army["manpower"] == {"current": 47934, "max": None}
    assert quality == {"morale": {"army": 4.176, "navy": 2.148}, "discipline_percent": 105}
    assert domestic["stability"] == {"current": -1, "min": -3, "max": 3}
    assert domestic["war_exhaustion"] == {"current": 0, "min": 0, "max": 20}
    assert domestic["corruption"] == {"current": 1.988, "min": 0, "max": 100}
    assert domestic["average_unrest"] == -17.917
    assert domestic["overextension_percent"] == 125
    assert domestic["religious_unity_percent"] == 110
    assert result == before


@pytest.mark.parametrize("field,expected", [
    (_known({"raw": 56692752, "unit": "game_date_raw"}), "1471.10.11"),
    (_known(56692752, unit="game_date_raw"), "1471.10.11"),
    (_known({"raw": -1, "unit": "game_date_raw"}), None),
    ({"status": "unknown", "unit": "game_date_raw", "raw": 56692752}, None),
])
def test_battle_end_date_is_readable_without_mutating_stored_fields(field, expected):
    result = {"items": [{"query": {"topic": "B01"}, "fields": {"end_date": field}}]}
    before = deepcopy(result)
    assert present_concise(result)["items"] == [{"end_date": expected}]
    assert result == before


def test_battle_winner_and_text_hide_implementation_fields():
    result = {"result_id": "battle", "items": [
        {"query": {"topic": "B01"}, "fields": {"winner": _known({
            "participants": ["FRA"], "observer_outcome": "victory", "combat_side_index": 0,
            "runtime_popup_verified": False})}},
        {"query": {"topic": "B04"}, "fields": {"details": _known({"display_composition": {
            "status": "known", "line1": {"status": "known", "text": "富瓦战役"},
            "controls": [{"configured_text_assignment_condition": True, "template_key": "OURLOST",
                          "text": {"status": "known", "value": "1443"}}]}})}}]}
    winner, text = present_concise(result)["items"]
    assert winner == {"winner": {"countries": ["FRA"], "observer_outcome": "victory"}}
    assert text == {"details": "[Line1] 富瓦战役\n[OURLOST] 1443\n"}


def test_nested_raw_quantity_retains_business_value():
    result = {"result_id": "shares", "items": [{"fields": {"shares": _known({
        "FRA": {"raw": 306, "raw_hex": "32010000", "unit": "ratio", "scale": 1000}})}}]}
    assert present_concise(result)["items"] == [{"shares": {"FRA": 0.306}}]


def test_manpower_current_and_capacity_are_shown_once():
    result = {"result_id": "capacity", "items": [{"query": {"topic": "N02",
              "object": {"country": "FRA"}}, "fields": {
                  "manpower": _known(48539), "max_manpower": _known(48539)}}]}
    assert present_concise(result)["items"] == [
        {"country": "FRA", "manpower": {"current": 48539, "max": 48539}}]


@pytest.mark.parametrize("field,expected", [
    (_known(56728296, date="1475.11.1", unit="eu4_hour_tick"), "1475.11.1"),
    ({"status": "not_applicable", "reason": "DIRECT_PAIR_TRUCE_FLAG_NOT_SET"}, None),
    ({"status": "unknown", "date": "1475.11.1"}, None),
])
def test_truce_expiry_uses_available_game_calendar_date(field, expected):
    result = {"items": [{"query": {"topic": "R03", "object": {
        "actor": "FRA", "recipient": "GEL"}}, "fields": {"truce_until": field}}]}
    before = deepcopy(result)
    assert present_concise(result)["items"] == [
        {"actor": "FRA", "recipient": "GEL", "truce_until": expected}]
    assert result == before


def test_relation_tendency_alias_is_shown_once_when_both_fields_are_selected():
    result = {"items": [{"query": {"topic": "R06", "object": {
        "actor": "HAB", "recipient": "FRA"}}, "fields": {
            "ai_attitude": _known("threatened"),
            "relationship_tendency": _known("threatened"),
            "personality": _known("diplomat")}}]}
    assert present_concise(result)["items"] == [
        {"actor": "HAB", "recipient": "FRA", "ai_attitude": "threatened", "personality": "diplomat"}]
    del result['items'][0]['fields']['ai_attitude']
    assert present_concise(result)['items'][0]['relationship_tendency'] == 'threatened'


def test_c04_relation_payload_hides_record_metadata_and_keeps_unknown_business_value():
    payload = {
        "country": "FRA", "actor": "FRA", "recipient": "GEL", "relation_kind": "guarantee",
        "before": {"active": False, "guarantee": {"actor_grants": False, "recipient_grants": False},
                   "support_roles": None, "subject": None},
        "after": {"active": True, "guarantee": {"actor_grants": True, "recipient_grants": False},
                  "support_roles": None, "subject": None},
        "observation_path": "guarantee_record_enable", "command_state": None, "command_mode": None,
        "native_sequence": 8, "sequence": 1, "collected_game_date": 56683512,
        "unknown_business_value": {"status": "unknown", "reason": "not observed"},
    }
    result = {"result_id": "relation-event", "items": [{
        "query": {"topic": "C04", "object": {"type": "session"}},
        "fields": {"event_payload": {"status": "known", "value": payload}},
    }]}
    before = deepcopy(result)
    service = _InformationService()
    service.result = result
    tools = InformationTools(service)
    arguments = {"request_id": "c04-concise", "queries": [{
        "topic": "C04", "object": {"type": "session"}, "fields": ["event_payload"],
    }]}

    concise = tools.call("information_query", arguments)

    assert concise == {
        "result_id": "relation-event",
        "items": [{"event_payload": {
            "country": "FRA", "actor": "FRA", "recipient": "GEL", "relation_kind": "guarantee",
            "before": payload["before"], "after": payload["after"], "unknown_business_value": None,
        }}],
    }
    assert not {"observation_path", "command_state", "command_mode"} & set(concise["items"][0]["event_payload"])
    assert tools.call("information_query", {**arguments, "view": "full"}) == result
    assert result == before


def test_relation_recipient_field_does_not_overwrite_selected_target_identity():
    result = {"items": [
        {"query": {"topic": "R01", "object": {
            "type": "country_pair", "actor": "FRA", "recipient": "GEL"}},
         "fields": {"relation_type": _known("guarantee"), "recipient": _known([None])}},
        {"query": {"topic": "R01", "object": {"type": "session"}},
         "fields": {"recipient": _known(["FRA"])}},
    ]}

    assert present_concise(result)["items"] == [
        {"actor": "FRA", "recipient": "GEL", "relation_type": "guarantee", "relation_recipient": [None]},
        {"recipient": ["FRA"]},
    ]


def _result():
    return {
        "schema_version": 1,
        "result_id": "result-001",
        "request_id": "request-001",
        "owner": "private-owner",
        "detail": "brief",
        "context": {
            "session_id": "session-001",
            "observer": "FRA",
            "game_date": 147018,
            "game_sha256": "a" * 64,
        },
        "session_id": "session-001",
        "delivery": {"status": "delivered", "receipt": {"id": "receipt-1"}},
        "source": {"name": "recorded", "provenance": {"path": "private.json"}},
        "items": [
            {
                "topic": "N01",
                "query": {
                    "topic": "N01",
                    "object": {"type": "country", "country": "FRA"},
                    "fields": ["monthly_income", "monthly_expenses", "monthly_balance",
                               "loan_summary", "zero_count", "active", "unknown", "n/a",
                               "nested"],
                    "parameters": {},
                },
                "source": {"name": "ledger", "provenance": {"offset": 40}},
                "fields": {
                    "monthly_income": _known(
                        12345, scale=100, unit="ducat", period="month", basis="monthly",
                        date="1470.1.1", source="ledger", provenance={"record": 1},
                        raw="12345", raw_hex="0x3039", diagnostic="internal",
                    ),
                    "monthly_expenses": _known(0, scale=100, unit="ducat"),
                    "monthly_balance": _known(-500, scale=100, unit="ducat"),
                    "loan_summary": _known({
                        "loan_count": _known(0, raw=0),
                        "total_principal": _known(345600, scale=100, unit="ducat"),
                    }, source="loan-ledger", raw={"count": 0}),
                    "zero_count": _known(0),
                    "active": _known(False),
                    "unknown": {
                        "status": "unknown", "value": 999, "reason": "not observed",
                        "source": "private-source",
                    },
                    "n/a": {"status": "not_applicable", "value": 1, "reason": "not relevant"},
                    "nested": _known({
                        "cash": _known(1200, scale=100, basis="monthly"),
                        "zero": _known(0),
                        "enabled": _known(False),
                        "missing": {"status": "unknown", "value": 4},
                        "observed_at": "1470.1.1",
                        "diagnostic": "private diagnostic",
                        "source": "private-source",
                        "provenance": {"path": "private.json"},
                        "raw": "1200",
                        "raw_hex": "0x4b0",
                        "period": "month",
                        "basis": "monthly",
                    }),
                },
            },
            {
                "topic": "W01",
                "query": {
                    "topic": "W01",
                    "object": {"type": "war", "war_id": 27},
                    "fields": ["war_score"],
                    "parameters": {},
                },
                "fields": {"war_score": _known(0, scale=100)},
            },
        ],
    }


def test_present_concise_projects_values_identity_finance_and_unknowns_without_mutation():
    result = _result()
    before = deepcopy(result)

    presented = present_concise(result)

    assert presented == {
        "result_id": "result-001",
        "items": [
            {
                "country": "FRA",
                "previous_month_recurring": {
                    "income": 123.45,
                    "expenses": 0,
                    "balance": -5,
                },
                "loans": {"count": 0, "principal": 3456},
                "zero_count": 0,
                "active": False,
                "unknown": None,
                "n/a": None,
                "nested": {
                    "cash": 12,
                    "zero": 0,
                    "enabled": False,
                    "missing": None,
                },
            },
            {"war_id": 27, "war_score": 0},
        ],
    }
    assert result == before


class _InformationService:
    def __init__(self):
        self.result = _result()
        self.discovered = {
            "schema_version": 1,
            "context": {"session_id": "session-001", "observer": "FRA"},
            "event_types": ["war_started"],
            "configuration": {"delivery": "durable_outbox"},
            "topics": [
                {
                    "topic_id": "N01",
                    "title": "国家财政",
                    "status": "ready",
                    "description": "full topic description",
                    "fields": {
                        "monthly_income": {"title": "月收入", "source": "ledger"},
                        "loan_summary": {"title": "贷款", "source": "loan-ledger"},
                    },
                },
                {
                    "topic_id": "W01",
                    "title": "战争",
                    "status": "partial",
                    "description": "another full description",
                    "fields": {"war_score": {"title": "战争分数"}},
                },
            ],
        }

    def query(self, request_id, queries=None, report_id=None):
        return deepcopy(self.result)

    def get_result(self, result_id):
        assert result_id == self.result["result_id"]
        return deepcopy(self.result)

    def list_results(self, limit=50):
        assert limit == 50
        return {"results": [deepcopy(self.result)]}

    def tick(self):
        return {
            "state": "processed",
            "context": {"session_id": "session-001", "observer": "FRA"},
            "results": [deepcopy(self.result)],
        }

    def discover(self):
        return deepcopy(self.discovered)


def test_country_relation_network_keeps_partners_and_opposite_directions_in_default_view():
    identities = [
        {"actor": "FRA", "partner": "SAV", "relation_type": "alliance"},
        {"actor": "FRA", "partner": "SAV", "relation_type": "military_access", "direction": "granted"},
        {"actor": "FRA", "partner": "SAV", "relation_type": "military_access", "direction": "received"},
    ]
    fields = {name: _known([dict(identity, **value) for identity, value in zip(identities, values)])
              for name, values in {
                  "relation_type": [_known("alliance"), _known("military_access"), _known("military_access")],
                  "status": [_known("active")] * 3,
                  "grantor": [{"status": "not_applicable"}, _known("FRA"), _known("SAV")],
                  "recipient": [{"status": "not_applicable"}, _known("SAV"), _known("FRA")],
              }.items()}
    service = _InformationService()
    service.result = {"result_id": "result-001", "items": [{"query": {
        "topic": "R01", "object": {"type": "country", "country": "FRA"}}, "fields": fields}]}
    before = deepcopy(service.result)
    api = InformationTools(service)
    actual = api.call("information_get_result", {"result_id": "result-001"})
    assert actual["items"] == [{"country": "FRA", "relations": [
        {"partner": "SAV", "relation_type": "alliance", "status": "active"},
        {"partner": "SAV", "relation_type": "military_access", "direction": "granted",
         "status": "active", "grantor": "FRA", "recipient": "SAV"},
        {"partner": "SAV", "relation_type": "military_access", "direction": "received",
         "status": "active", "grantor": "SAV", "recipient": "FRA"},
    ]}]
    assert api.call("information_get_result", {"result_id": "result-001", "view": "full"}) == before
    assert service.result == before


@pytest.mark.parametrize("field,expected", [(_known([]), []), ({"status": "unknown"}, None)])
def test_country_relation_network_distinguishes_known_empty_and_unavailable(field, expected):
    result = {"items": [{"query": {"topic": "R01", "object": {"type": "country", "country": "FRA"}},
                         "fields": {"status": field}}]}
    assert present_concise(result)["items"] == [{"country": "FRA", "relations": expected}]


def test_war_score_default_keeps_score_and_goal_without_native_flags_or_scaled_raw_values():
    result = {"items": [{"query": {"topic": "W02"}, "fields": {"war_score": _known({
        "total": 4, "max_score": 100, "mode": "whole_war", "perspective": "actor",
        "verified": True, "error": None, "overview_goal_cap": 25,
        "goal": {"available": True, "present": True, "cumulative": 1.5,
                 "cumulative_raw": 1500, "cumulative_scale": 1000},
        "tooltip": {"text": "internal composition", "text_decoded": True},
    })}}]}
    before = deepcopy(result)
    assert present_concise(result)["items"] == [{"war_score": {
        "total": 4, "max_score": 100, "mode": "whole_war", "perspective": "actor",
        "goal": {"cumulative": 1.5, "max_score": 25}}}]
    assert result == before


def test_task_execution_result_has_business_transition_and_actual_game_date():
    native = {"event": "native_diplomacy_task_execution_result", "native_state": 0,
              "native_variant": 1, "native_outcome": "executed", "task_before": False,
              "task_after": True, "native_result_date": {"status": "known",
                  "unit": "game_date_raw", "game_date_raw": 56697264}}
    result = {"items": [{"query": {"topic": "A05"}, "fields": {"result": _known(native)}}]}
    before = deepcopy(result)
    assert present_concise(result)["items"] == [{"result": {
        "task_before": False, "task_after": True, "date": "1472.4.17"}}]
    assert result == before


@pytest.mark.parametrize("status", ["executed", "unknown"])
def test_request_event_keeps_business_status_and_hides_evidence_and_internal_identity(status):
    payload = {"actor": "FRA", "recipient": "SAV", "identity": {"experiment_id": "internal"},
               "request": {"request_id": "task-1", "action_id": "curry_favors", "status": status,
                           "game_outcome": status, "result": None, "updated_at": "internal time",
                           "payload": {"phase": "initiate"}, "evidence": [{"sha256": "internal"}]}}
    result = {"event": {"event_type": "diplomatic_request_result", "payload": payload}, "items": [
        {"query": {"topic": "C04"}, "fields": {"event_payload": _known(payload)}}]}
    before = deepcopy(result)
    concise = present_concise(result)
    expected = {"actor": "FRA", "recipient": "SAV", "request": {
        "request_id": "task-1", "action_id": "curry_favors", "status": status,
        "game_outcome": status, "result": None}}
    assert concise["items"][0]["event_payload"] == concise["event"]["payload"] == expected
    assert result == before


@pytest.mark.parametrize("active", [False, True])
def test_favor_task_default_does_not_describe_the_read_only_stop_inspection_as_an_action(active):
    service = _InformationService()
    service.result = {"result_id": "result-001", "items": [{"query": {"topic": "R05", "object": {
        "type": "country_pair", "actor": "FRA", "recipient": "SAV"}}, "fields": {"favor_tasks": _known({
            "action_id": "stop_curry_favors", "family": "curry_favors", "phase": "initiate",
            "task_active": active, "relationship_state": {"task_active": active}})}}]}
    before = deepcopy(service.result)
    api = InformationTools(service)
    assert api.call("information_get_result", {"result_id": "result-001"})["items"] == [
        {"actor": "FRA", "recipient": "SAV", "favor_tasks": {"task_active": active}}]
    assert api.call("information_get_result", {"result_id": "result-001", "view": "full"}) == before


_QUERY = [{
    "topic": "N01",
    "object": {"type": "country", "country": "FRA"},
    "fields": ["monthly_income"],
    "parameters": {},
}]


@pytest.mark.parametrize(
    ("tool_name", "arguments", "full_response"),
    [
        ("information_query", {"request_id": "q-1", "queries": _QUERY}, "result"),
        ("information_get_result", {"result_id": "result-001"}, "result"),
        ("information_list_results", {}, "list"),
        ("information_tick", {}, "tick"),
    ],
)
def test_information_result_tools_default_to_concise_and_full_returns_original(
    tool_name, arguments, full_response
):
    service = _InformationService()
    tools = InformationTools(service)
    concise = present_concise(service.result)

    actual = tools.call(tool_name, arguments)

    if full_response == "result":
        assert actual == concise
    else:
        assert actual == {"results": [concise]}

    full = tools.call(tool_name, {**arguments, "view": "full"})
    if full_response == "result":
        assert full == service.result
    elif full_response == "list":
        assert full == {"results": [service.result]}
    else:
        assert full == {
            "state": "processed",
            "context": {"session_id": "session-001", "observer": "FRA"},
            "results": [service.result],
        }


def test_discover_defaults_to_filtered_field_names_and_full_view_keeps_details():
    service = _InformationService()
    tools = InformationTools(service)

    concise = tools.call("information_discover", {"topics": ["N01"]})

    assert concise == {
        "topics": [{
            "topic_id": "N01",
            "title": "国家财政",
            "status": "ready",
            "fields": ["monthly_income", "loan_summary"],
        }]
    }
    full = tools.call("information_discover", {"topics": ["N01"], "view": "full"})
    assert full["context"] == service.discovered["context"]
    assert full["configuration"] == service.discovered["configuration"]
    assert full["topics"] == [service.discovered["topics"][0]]

