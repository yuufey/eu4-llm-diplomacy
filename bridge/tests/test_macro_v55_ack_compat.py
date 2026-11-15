"""Installation ACKs preserve macro capabilities through the condition release."""
import pytest

from bridge import country_modifier_observation as modifier
from bridge import mission_availability_observation as availability
from bridge import mission_condition_observation as condition
from bridge import mission_observation as mission
from bridge import relation_observation as relation
from bridge import rival_observation as rival
from bridge import war_declaration_observation as war
from bridge.tests.test_information_country_modifier_events import (
    SESSION_ID, make_session,
)


CALL_TO_ARMS = "native_call_to_arms_observation"
MACRO_CAPABILITIES = frozenset({
    modifier.CAPABILITY,
    modifier.REMOVE_CAPABILITY,
    modifier.EXPIRY_CAPABILITY,
    rival.CAPABILITY,
    war.CAPABILITY,
    relation.CAPABILITY,
    relation.RECORD_CAPABILITY,
    mission.CAPABILITY,
    mission.SET_CAPABILITY,
    availability.CAPABILITY,
})


def macro_ack(version):
    return {
        "event": "diplomacy_observer_installed",
        "session_id": SESSION_ID,
        "version": version,
        modifier.CAPABILITY: True,
        "native_country_modifier_add_wire": 1,
        "native_country_modifier_scope": modifier.SCOPE,
        modifier.REMOVE_CAPABILITY: True,
        "native_country_modifier_remove_wire": 1,
        modifier.EXPIRY_CAPABILITY: True,
        "native_country_modifier_expiry_wire": 1,
        rival.CAPABILITY: True,
        "native_rival_change_wire": 1,
        "native_rival_change_scope": rival.SCOPE,
        war.CAPABILITY: True,
        "native_war_declaration_wire": 1,
        "native_war_declaration_scope": war.SCOPE,
        relation.CAPABILITY: True,
        "native_relation_change_wire": 2,
        "native_relation_change_scope": relation.RECORD_SCOPE,
        relation.RECORD_CAPABILITY: True,
        mission.CAPABILITY: True,
        "native_mission_completion_wire": 2,
        "native_mission_completion_scope": mission.SET_SCOPE,
        mission.SET_CAPABILITY: True,
        availability.CAPABILITY: True,
        "native_mission_availability_wire": 1,
        "native_mission_availability_scope": availability.SCOPE,
        CALL_TO_ARMS: True,
        "native_call_to_arms_ai_response_held": False,
    }


@pytest.mark.parametrize(("version", "accepted"), [(55, True), (54, True), (56, True), (62, False)])
def test_macro_ack_consumer_keeps_versioned_and_independent_capabilities(
        tmp_path, version, accepted):
    session = make_session(tmp_path / str(version), ack=macro_ack(version))
    capabilities = session.installation_capabilities()
    if accepted:
        assert MACRO_CAPABILITIES <= capabilities
        assert CALL_TO_ARMS in capabilities
    else:
        assert MACRO_CAPABILITIES.isdisjoint(capabilities)
        assert capabilities == {CALL_TO_ARMS}


def test_v56_condition_ack_keeps_call_to_arms_and_all_inherited_macro_capabilities(tmp_path):
    ack = macro_ack(56)
    ack.update({condition.CAPABILITY: True, "native_mission_condition_wire": 1,
                "native_mission_condition_scope": condition.SCOPE})
    session = make_session(tmp_path, ack=ack)
    assert MACRO_CAPABILITIES | {condition.CAPABILITY, CALL_TO_ARMS} <= session.installation_capabilities()
