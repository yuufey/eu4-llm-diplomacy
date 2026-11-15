"""Version 61 parent ACK inheritance and exact rival-record admission."""
import pytest

from bridge import country_modifier_observation as country_modifier
from bridge import mission_availability_observation as mission_availability
from bridge import mission_condition_observation as mission_condition
from bridge import mission_observation
from bridge import relation_observation
from bridge import war_declaration_observation
from bridge.tests.test_support_subject_relation_record_observation import support_subject_ack


GAME_SHA = relation_observation.GAME_SHA256
RIVAL_RECORD_SCOPE = "FRA_actor_target_or_old_rival_at_command_or_country_rival_record_returns"
OLD_RIVAL_SCOPE = "FRA_actor_target_or_old_rival_at_three_country_command_entries"
COUNT_BASIS = "active_nonretired_nodes"
_MISSING = object()


def v61_ack(**changes):
    ack = support_subject_ack()
    ack.update({
        "version": 61,
        "native_rival_record_observation": True,
        "native_rival_change_wire": 2,
        "native_rival_change_scope": RIVAL_RECORD_SCOPE,
        "native_rival_record_count_basis": COUNT_BASIS,
    })
    ack.update(changes)
    return ack


def _family_results(ack, game_sha=GAME_SHA):
    return {
        "country_modifier": (
            country_modifier.supported_ack(ack, game_sha)
            and country_modifier.supported_remove_ack(ack, game_sha)
            and country_modifier.supported_expiry_ack(ack, game_sha)
        ),
        "mission_availability": mission_availability.supported_ack(ack, game_sha),
        "mission_condition": (
            mission_condition.supported_ack(ack, game_sha)
            and mission_condition.supported_province_ack(ack, game_sha)
        ),
        "mission_observation": (
            mission_observation.supported_ack(ack, game_sha)
            and mission_observation.supported_set_ack(ack, game_sha)
        ),
        "relation": (
            relation_observation.supported_ack(ack, game_sha)
            and relation_observation.supported_support_subject_record_ack(ack, game_sha)
        ),
        "war_declaration": war_declaration_observation.supported_ack(ack, game_sha),
    }


def test_v60_fixture_stays_valid_and_v61_extends_all_six_parent_contracts():
    assert all(_family_results(support_subject_ack()).values())
    result = _family_results(v61_ack())
    assert result == {
        "country_modifier": True,
        "mission_availability": True,
        "mission_condition": True,
        "mission_observation": True,
        "relation": True,
        "war_declaration": True,
    }


@pytest.mark.parametrize(
    "field,value",
    [
        ("native_rival_record_observation", _MISSING),
        ("native_rival_record_observation", False),
        ("native_rival_record_observation", 1),
        ("native_rival_change_wire", _MISSING),
        ("native_rival_change_wire", 1),
        ("native_rival_change_wire", True),
        ("native_rival_change_wire", 3),
        ("native_rival_change_wire", 2.0),
        ("native_rival_change_scope", _MISSING),
        ("native_rival_change_scope", OLD_RIVAL_SCOPE),
        ("native_rival_record_count_basis", _MISSING),
        ("native_rival_record_count_basis", "all_nodes"),
        ("native_rival_record_count_basis", True),
    ],
    ids=[
        "missing-record-capability", "false-record-capability", "integer-is-not-bool",
        "missing-wire", "old-wire", "bool-is-not-int", "wrong-wire", "float-wire",
        "missing-scope", "old-scope", "missing-count-basis", "wrong-count-basis",
        "bool-count-basis",
    ],
)
def test_v61_requires_each_exact_rival_record_field_in_all_parent_validators(field, value):
    ack = v61_ack()
    if value is _MISSING:
        ack.pop(field)
    else:
        ack[field] = value
    assert not any(_family_results(ack).values())


@pytest.mark.parametrize(
    "changes",
    [
        {"version": True},
        {"version": 65},
        {"native_relation_change_wire": 4},
        {"native_relation_change_wire": True},
        {"native_relation_change_scope": relation_observation.DIRECTED_RECORD_SCOPE},
        {relation_observation.SUPPORT_SUBJECT_RECORD_CAPABILITY: False},
    ],
    ids=[
        "bool-version", "future-version-65", "old-relation-wire", "bool-relation-wire",
        "old-relation-scope", "missing-v60-parent-capability",
    ],
)
def test_v61_preserves_v60_relation_wire5_scope_and_future_rejection(changes):
    assert not any(_family_results(v61_ack(**changes)).values())

