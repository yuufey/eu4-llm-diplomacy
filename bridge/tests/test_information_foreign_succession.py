from copy import deepcopy

import pytest

from bridge.information import InformationService
from bridge.information.composite import CompositeSource
from bridge.information.country_person import NativeCountryPersonSource
from bridge.information.foreign_succession import NativeForeignSuccessionSource
from bridge.information.model import InformationError
from bridge.information.tools import InformationTools
from bridge.tests.test_information_country_person import Base, make_context, make_private_fields


def query():
    return {'topic': 'F04', 'object': {'type': 'country', 'country': 'ENG'},
            'fields': ['succession_risk'], 'parameters': {}}


class PersonSource:
    def __init__(self, fields):
        self.fields = fields
        self.calls = []

    def read(self, request, context):
        self.calls.append(deepcopy(request))
        return {'fields': {name: NativeCountryPersonSource._project_private_field(
            name, self.fields['S04.' + name]) for name in request['fields']},
            'game_date': context['game_date'], 'complete': False}


@pytest.mark.parametrize('mode,present,age', [('character', True, 17), ('no_heir', False, None),
                                           ('hidden', None, None)])
def test_normal_tools_project_current_succession_indicators(tmp_path, mode, present, age):
    base = Base(tmp_path, make_context())
    person = PersonSource(make_private_fields(heir_mode=mode))
    adapter = NativeForeignSuccessionSource(base, person)
    service = InformationService(CompositeSource(base, [adapter]), tmp_path / 'information.sqlite3')
    try:
        api = InformationTools(service)
        result = api.call('information_query', {'request_id': 'succession', 'queries': [query()]})
        value = result['items'][0]['succession_risk']
        assert value['ruler_age'] == 34
        assert value['heir_present'] is present
        assert value['heir_age'] == age
        assert value['senior_country'] is None
        if present:
            assert value['heir_claim'] == {'current': 0.08, 'max': 100, 'category': 'strong'}
        else:
            assert value['heir_claim'] is None
        assert set(value) == {'ruler_age', 'heir_present', 'heir_age', 'heir_claim', 'senior_country'}
        full = api.call('information_get_result', {'result_id': result['result_id'], 'view': 'full'})
        assert full['complete'] is True
        assert len(person.calls) == 1
        assert person.calls[0] == {'topic': 'S04', 'object': query()['object'],
                                    'fields': ['ruler', 'heir', 'personal_union'], 'parameters': {}}
    finally:
        service.close()


def test_unknown_age_keeps_known_heir_and_union_information(tmp_path):
    private = make_private_fields()
    private['S04.ruler']['value']['age'] = {'status': 'unknown', 'reason': 'AGE_UNAVAILABLE'}
    private['S04.personal_union']['value'] = {'uses_senior_ruler': True, 'senior_country': 'DAN'}
    source = NativeForeignSuccessionSource(Base(tmp_path, make_context()), PersonSource(private))
    result = source.read(query())
    values = result['fields']['succession_risk']['value']
    assert values['ruler_age']['status'] == 'unknown'
    assert values['heir_present']['value'] is True
    assert values['senior_country']['value'] == 'DAN'
    assert result['complete'] is False


def test_observer_country_is_rejected(tmp_path):
    source = NativeForeignSuccessionSource(Base(tmp_path, make_context()))
    request = query()
    request['object']['country'] = 'FRA'
    with pytest.raises(InformationError):
        source.validate_query(request)


def test_invisible_country_returns_null_without_person_values(tmp_path):
    private = {key: {'status': 'invisible', 'reason': 'COUNTRY_NOT_ADMITTED'}
               for key in make_private_fields()}
    base = Base(tmp_path, make_context())
    adapter = NativeForeignSuccessionSource(base, PersonSource(private))
    service = InformationService(CompositeSource(base, [adapter]), tmp_path / 'information.sqlite3')
    try:
        result = InformationTools(service).call('information_query',
            {'request_id': 'invisible-succession', 'queries': [query()]})
        assert result['items'] == [{'country': 'ENG', 'succession_risk': None}]
    finally:
        service.close()
