from copy import deepcopy
from types import SimpleNamespace

import pytest

from bridge.information import InformationService
from bridge.information.composite import CompositeSource
from bridge.information.peace_followup import FIELDS
from bridge.information.peace_followup_conditions import (
    SUBJECT_DEFAULTS, PeaceIntegrationConditions, future_subjects,
    project_integration_conditions, project_restart_conditions,
)
from bridge.information.tools import InformationTools
from bridge.tests.test_information_peace_followup import RULES, make_source, query
from bridge.tests.test_information_peace_subject_rules import _node, _type, _Parser, _game, _subject_file, _index


def type_values():
    vassal = dict(SUBJECT_DEFAULTS, can_be_annexed=True, joins_overlords_wars=True,
        annex_cost_per_development=8, pays_overlord=1, forcelimit_to_overlord=0.1,
        overlord_can_attack=True, can_fight_independence_war=True)
    union = dict(vassal, can_be_annexed=False, can_be_integrated=True,
        pays_overlord=0, forcelimit_to_overlord=0, overlord_can_attack=False)
    return {'vassal': vassal, 'personal_union': union}


@pytest.mark.parametrize('action,kind,method,years,attack', [
    ('force_vassalization', 'vassal', 'annex_vassal', 10, True),
    ('form_personal_union', 'personal_union', 'integrate_union', 50, False)])
def test_all_p06_fields_share_preview_and_subject_rules(tmp_path, action, kind, method, years, attack):
    adapter, base, calls = make_source(tmp_path)
    base.current['game_date'] = 56682672
    values = deepcopy(RULES)
    values['values'].update(INTEGRATE_VASSAL_MIN_YEARS=10, INTEGRATE_UNION_MIN_YEARS=50,
                            DIPLOANNEX_LIBERTY_THRESHOLD=50)
    adapter.rules = SimpleNamespace(read=lambda: values)
    type_calls = []

    def read_types(names):
        type_calls.append(names)
        return {'values': type_values()}

    adapter.subject_rules = SimpleNamespace(read=read_types)
    adapter.action_conditions = SimpleNamespace(read=lambda: {'values': {
        'annexationaction': [], 'integrationaction': []}})
    service = InformationService(CompositeSource(base, [adapter]), tmp_path / 'information.sqlite3')
    try:
        selected = query([{'action_id': action, 'country': 'ENG', 'beneficiary': 'FRA'}])
        selected['fields'] = list(FIELDS)
        result = InformationTools(service).call('information_query', {
            'request_id': 'future-subject', 'queries': [selected]})
        row = result['items'][0]
        integration = row['integration_conditions'][0]
        assert integration['subject'] == 'ENG' and integration['overlord'] == 'FRA'
        assert integration['subject_type'] == kind
        option = integration['methods'][0]
        assert option['method'] == method and option['minimum_subject_years'] == years
        assert option['base_diplomatic_cost_per_development'] == 8
        assert option['progress_liberty_desire_below'] == 50
        assert row['restart_conditions']['recipient_becomes_subject'] is True
        assert row['restart_conditions']['overlord_attack_allowed_by_type'] is attack
        assert row['obligations'][0]['details']['joins_overlord_wars'] is True
        assert service.get_result(result['result_id'])['complete'] is True
        assert len(calls) == 1 and type_calls == [[kind]]
    finally:
        service.close()


def test_subject_offer_uses_future_subject_and_overlord_roles():
    peace = {'terms': [{'action_id': 'form_personal_union', 'country': 'FRA', 'beneficiary': 'ENG'}]}
    subjects = future_subjects(peace, 'ENG')
    truce = {'status': 'known', 'value': {'if_signed_on': '1470.8.17', 'estimated_until': '1476.9.1'}}
    result = project_restart_conditions(peace, {'actor': 'FRA', 'recipient': 'ENG'}, truce,
                                        subjects, {'values': type_values()})
    assert result['value']['actor_becomes_subject'] is True
    assert result['value']['independence_war_allowed_by_type'] is True


def test_annexation_reports_removed_country_and_no_new_integration():
    peace = {'terms': [{'action_id': 'full_annexation', 'country': 'ENG', 'beneficiary': 'FRA'}]}
    result = project_restart_conditions(peace, {'actor': 'FRA', 'recipient': 'ENG'}, {}, [], {})
    assert result['value'] == {'countries_removed': ['ENG']}
    assert result['complete'] is True
    assert project_integration_conditions([], {'values': {}}, {}, {})['value'] == []


def test_transfer_subject_keeps_unresolved_future_type_explicit():
    subjects = future_subjects({'terms': [{'action_id': 'transfer_subject', 'country': 'TYR'}]}, 'FRA')
    result = project_integration_conditions(subjects, {'values': {}}, {}, {})
    assert result['value'][0] == {'subject': 'TYR', 'overlord': 'FRA',
                                 'subject_type': None, 'methods': None}
    assert result['complete'] is False


@pytest.mark.parametrize('original,created,future,direction', [
    ('vassal', False, 'vassal', 'demand'),
    ('march', False, 'vassal', 'demand'),
    ('personal_union', False, 'vassal', 'demand'),
    ('client_march', True, 'client_vassal', 'demand'),
    ('client_march', True, 'client_vassal', 'offer'),
])
def test_transfer_subject_uses_native_resulting_type_rule(tmp_path, original, created, future, direction):
    adapter, base, calls = make_source(tmp_path)
    base.current['game_date'] = 56682672
    values = deepcopy(RULES)
    values['values'].update(INTEGRATE_VASSAL_MIN_YEARS=10, DIPLOANNEX_LIBERTY_THRESHOLD=50)
    adapter.rules = SimpleNamespace(read=lambda: values)
    types = type_values()
    types[original] = dict(types.get(original, {}), created_by_overlord=created)
    types['client_vassal'] = dict(types['vassal'], created_by_overlord=True, pays_overlord=0.5)
    type_calls, subject_calls = [], []

    def read_types(names):
        type_calls.append(names)
        return {'values': {name: types[name] for name in names}}

    def read_subject(selected, context):
        subject_calls.append(deepcopy(selected))
        assert context == base.current
        return {'fields': {'tribute': {'status': 'known', 'subject_type': original}}}

    adapter.subject_rules = SimpleNamespace(read=read_types)
    adapter.subject_source = SimpleNamespace(read=read_subject)
    adapter.action_conditions = SimpleNamespace(read=lambda: {'values': {'annexationaction': []}})
    service = InformationService(CompositeSource(base, [adapter]), tmp_path / 'information.sqlite3')
    try:
        selected = query([{'action_id': 'transfer_subject', 'country': 'TYR'}], direction=direction)
        selected['fields'] = list(FIELDS)
        result = InformationTools(service).call('information_query', {
            'request_id': 'transfer-subject', 'queries': [selected]})
        row = result['items'][0]
        obligation = row['obligations'][0]
        assert obligation['country'] == 'TYR'
        assert obligation['overlord'] == ('FRA' if direction == 'demand' else 'ENG')
        assert obligation['subject_type'] == future
        assert obligation['details']['vassal_tax_multiplier'] == (0.5 if created else 1)
        integration = row['integration_conditions'][0]
        assert integration['subject_type'] == future
        assert integration['methods'][0]['method'] == 'annex_vassal'
        assert integration['methods'][0]['minimum_subject_years'] == 10
        assert service.get_result(result['result_id'])['complete'] is True
        assert len(calls) == len(type_calls) == len(subject_calls) == 1
        assert subject_calls[0]['object'] == {'type': 'country', 'country': 'TYR'}
        assert subject_calls[0]['fields'] == ['tribute']
    finally:
        service.close()


def test_transfer_with_unknown_original_type_preserves_known_truce(tmp_path):
    adapter, base, _ = make_source(tmp_path)
    base.current['game_date'] = 56682672
    adapter.subject_source = SimpleNamespace(read=lambda *args: {
        'fields': {'tribute': {'status': 'unknown'}}})
    adapter.subject_rules = SimpleNamespace(read=lambda names: {'values': type_values()})
    selected = query([{'action_id': 'transfer_subject', 'country': 'TYR'}])
    selected['fields'] = list(FIELDS)
    result = adapter.read(selected)
    assert result['fields']['new_truce']['status'] == 'known'
    assert result['fields']['obligations']['value'][0]['subject_type'] is None
    assert result['fields']['integration_conditions']['value'][0]['methods'] is None
    assert result['complete'] is False


def test_multiple_transfers_resolve_each_type_and_share_configuration(tmp_path):
    adapter, base, calls = make_source(tmp_path)
    adapter.rules = SimpleNamespace(read=lambda: {'values': {
        'INTEGRATE_VASSAL_MIN_YEARS': 10, 'DIPLOANNEX_LIBERTY_THRESHOLD': 50}})
    types = type_values()
    types['client_vassal'] = dict(types['vassal'], created_by_overlord=True)
    type_calls = []

    def read_types(names):
        type_calls.append(names)
        return {'values': types}

    adapter.subject_rules = SimpleNamespace(read=read_types)
    adapter.subject_source = SimpleNamespace(read=lambda selected, context: {'fields': {
        'tribute': {'status': 'known', 'subject_type': (
            'client_vassal' if selected['object']['country'] == 'LEI' else 'vassal')}}})
    adapter.action_conditions = SimpleNamespace(read=lambda: {'values': {'annexationaction': []}})
    selected = query([{'action_id': 'transfer_subject', 'countries': ['LEI', 'TYR']}])
    selected['fields'] = ['obligations', 'integration_conditions']
    result = adapter.read(selected)
    assert result['complete'] is True
    assert [row['subject_type'] for row in result['fields']['obligations']['value']] == [
        'client_vassal', 'vassal']
    assert len(calls) == len(type_calls) == 1


def test_missing_action_rules_preserves_known_wait_and_cost():
    subjects = [{'subject': 'ENG', 'overlord': 'FRA', 'subject_type': 'vassal'}]
    values = {'values': {'INTEGRATE_VASSAL_MIN_YEARS': 10, 'DIPLOANNEX_LIBERTY_THRESHOLD': 50}}
    result = project_integration_conditions(subjects, values, {'values': type_values()}, {})
    option = result['value'][0]['methods'][0]
    assert option['minimum_subject_years'] == 10 and option['base_diplomatic_cost_per_development'] == 8
    assert option['scripted_conditions'] is None and result['complete'] is False


def test_unknown_type_permissions_keep_integration_methods_unknown():
    subjects = [{'subject': 'ENG', 'overlord': 'FRA', 'subject_type': 'vassal'}]
    result = project_integration_conditions(subjects, {'values': {}},
        {'values': {'vassal': {'can_be_annexed': None, 'can_be_integrated': False}}}, {})
    assert result['value'][0]['methods'] is None
    assert result['complete'] is False


def test_action_conditions_keep_country_scopes_order_and_opinion_threshold(tmp_path):
    game = _game(tmp_path / 'game')
    _subject_file(game, 'common/diplomatic_actions/actions.txt', 'rules')
    nodes = [_type('annexationaction', _type('condition',
        _type('potential', _type('FROM', _node('vassal_of', 'ROOT'))),
        _type('allow', _type('FROM', _type('has_opinion',
            _node('who', 'ROOT'), _node('value', '190'))))))]
    result = PeaceIntegrationConditions(_index(tmp_path, game), parser=_Parser({'rules': nodes})).read()
    assert result['values']['annexationaction'] == [{
        'when': [{'subject': [{'vassal_of': 'overlord'}]}],
        'requires': [{'subject': [{'has_opinion': [{'who': 'overlord'}, {'value': 190}]}]}]}]
