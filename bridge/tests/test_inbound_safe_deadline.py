"""Keep the public deadline while excluding unverified or private additions."""
from copy import deepcopy

import pytest

from bridge.diplomacy import DiplomacyTools
from bridge.proposal_expiry import deadline_from_created_date


def proposal(deadline):
    return {'proposal_id': 'a' * 32, 'action_id': 'offer_alliance', 'family': 'alliance',
            'actor': 'SAV', 'recipient': 'FRA', 'decision_country': 'FRA',
            'observer_status': 'observed_pending', 'deadline': deadline}


@pytest.mark.parametrize('created', [None, 100])
def test_admitted_deadline_survives_the_safe_projection(created):
    value = deadline_from_created_date(created)
    safe = DiplomacyTools._safe_inbound_proposal(proposal(value))
    assert safe['deadline'] == value
    assert safe['deadline'] is not value
    assert safe['execute'] == {'accept': 'unimplemented', 'reject': 'unimplemented'}


def test_unverified_rule_keeps_its_unknown_status():
    value = {**deadline_from_created_date(None), 'reason': 'PROPOSAL_EXPIRY_RULE_NOT_VERIFIED'}
    assert DiplomacyTools._safe_inbound_proposal(proposal(value))['deadline'] == value


@pytest.mark.parametrize('damage', ['private_field', 'wrong_threshold', 'wrong_unit', 'boolean_created'])
def test_malformed_deadline_is_excluded_without_dropping_the_proposal(damage):
    value = deepcopy(deadline_from_created_date(100))
    if damage == 'private_field':
        value['native_address'] = '0x123456'
    elif damage == 'wrong_threshold':
        value['value'] += 1
    elif damage == 'wrong_unit':
        value['unit'] = 'native_pointer'
    else:
        value['pending_created_game_date'] = True
    safe = DiplomacyTools._safe_inbound_proposal(proposal(value))
    assert safe['actor'] == 'SAV'
    assert 'deadline' not in safe
