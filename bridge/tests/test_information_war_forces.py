from copy import deepcopy

import pytest

from bridge.information import InformationService
from bridge.information.composite import CompositeSource
from bridge.information.tools import InformationTools
from bridge.information.war_forces import NativeWarForcesSource
from bridge.tests.test_information_foreign_technology import Base
from bridge.tests.test_information_foreign_technology_capture import make_valid_capture


@pytest.mark.parametrize('observer, country, topic, army_field, navy_field, army_label', [
    ('FRA', 'FRA', 'N02', 'army_size', 'navy_size', 'army_regiments'),
    ('TUR', 'TUR', 'N02', 'army_size', 'navy_size', 'army_regiments'),
    ('FRA', 'ENG', 'F02', 'visible_army', 'visible_navy', 'army_soldiers'),
])
def test_current_forces_reuses_one_size_query_and_keeps_units_explicit(
        tmp_path, observer, country, topic, army_field, navy_field, army_label):
    _, context, creation, _ = make_valid_capture()
    context['observer'] = observer
    base = Base(tmp_path, context, creation)
    calls = []

    class Upstream:
        def read(self, query, current):
            calls.append(deepcopy(query))
            return {'complete': False, 'fields': {
                army_field: {'status': 'known', 'value': 51, 'complete': False,
                             'strength': {'raw': 47000, 'scale': 1000}},
                navy_field: {'status': 'known', 'value': 8, 'complete': False}}}

    adapter = NativeWarForcesSource(base, Upstream(), Upstream())
    service = InformationService(CompositeSource(base, [adapter]), tmp_path / 'information.sqlite3')
    query = {'topic': 'W03', 'object': {'type': 'country', 'country': country},
             'fields': ['current_forces']}
    try:
        api = InformationTools(service)
        result = api.call('information_query', {'request_id': country, 'queries': [query]})
        assert result['items'] == [{'country': country,
                                    'current_forces': {army_label: 51, 'navy_ships': 8}}]
        full = api.call('information_get_result', {'result_id': result['result_id'], 'view': 'full'})
        assert full['items'][0]['complete'] is True
        sizes = full['items'][0]['fields']['current_forces']['value']
        assert sizes[army_label] == {'status': 'known', 'value': 51}
        assert calls == [{'topic': topic, 'object': query['object'],
                          'fields': [army_field, navy_field], 'parameters': {}}]
    finally:
        service.close()


def test_unavailable_army_keeps_known_navy(tmp_path):
    _, context, creation, _ = make_valid_capture()
    base = Base(tmp_path, context, creation)

    class Upstream:
        def read(self, query, current):
            return {'fields': {'visible_army': {'status': 'invisible', 'reason': 'HIDDEN'},
                               'visible_navy': {'status': 'known', 'value': 4}}}

    source = NativeWarForcesSource(base, None, Upstream())
    result = source.read({'topic': 'W03', 'object': {'type': 'country', 'country': 'ENG'},
                          'fields': ['current_forces']})
    assert result['complete'] is False
    assert result['fields']['current_forces']['value']['navy_ships']['value'] == 4
