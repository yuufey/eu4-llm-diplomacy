from copy import deepcopy

import pytest

from bridge.information import InformationService
from bridge.information.composite import CompositeSource
from bridge.information.tools import InformationTools
from bridge.information import war_territory as territory
from bridge.tests.test_information_foreign_technology import Base
from bridge.tests.test_information_foreign_technology_capture import (
    MODULE_BASE, WORLD, RecordingReader, make_valid_capture,
)
from bridge.tests.test_information_country_occupation_memory import put_provinces, RECORDS
from bridge.information.province_reference_memory import RECORD_STRIDE


def query(fields=None):
    return {'topic': 'W03', 'object': {'type': 'country', 'country': 'ENG'},
            'fields': list(territory.FIELDS) if fields is None else fields, 'parameters': {}}


def make_capture(fields, *, admitted=True, undiscovered=()):
    report, context, creation, fixture = make_valid_capture(admitted=admitted)
    image = fixture['image']
    profile = territory._load_profile()
    for guard in profile['code_guards']:
        image.put(MODULE_BASE + int(guard['rva'], 0), bytes.fromhex(guard['bytes']))
    put_provinces(image, fixture['target_fullref'],
        [fixture['target_fullref'], fixture['observer_fullref']],
        country=fixture['target_pointer'], world=WORLD, undiscovered=undiscovered, blockaded=[1])
    reader = RecordingReader(image)
    report['schema'], report['profile_sha256'] = territory.SCHEMA, territory.PROFILE_SHA256
    report['request']['fields'] = fields
    report['observation'] = territory._observe_for(fields)(reader, MODULE_BASE, 'ENG', profile)
    report['raw_reads'] = deepcopy(reader.read_log)
    report['access'] = {'read_only': True, 'native_function_invoked': False, 'writes': False,
        'UI_control': False, 'date_advance': False, 'save_or_reload': False,
        'limit_bytes': territory._owner.MAX_READ_BYTES,
        'calls': reader.calls, 'bytes_requested': reader.bytes_requested}
    return report, context, creation


def test_normal_query_and_recall_share_one_capture(tmp_path):
    report, context, creation = make_capture(list(territory.FIELDS))
    assert territory.validate_capture(report, context, creation, 'ENG', list(territory.FIELDS))
    base, calls = Base(tmp_path, context, creation), []

    def capture(installation, country, *, fields, observer):
        assert observer == context['observer']
        calls.append((country, fields))
        return deepcopy(report)

    adapter = territory.NativeWarTerritorySource(base, capture=capture)
    service = InformationService(CompositeSource(base, [adapter]), tmp_path / 'information.sqlite3')
    try:
        api = InformationTools(service)
        public = api.call('information_query', {'request_id': 'war-territory', 'queries': [query()]})
        assert public['items'] == [{'country': 'ENG', 'occupations': {
            'owned_provinces': 2, 'observed_provinces': 2, 'occupied_provinces': 1,
            'occupiers': {'FRA': 1}}, 'blockades': {
            'owned_provinces': 2, 'observed_provinces': 2, 'blockaded_provinces': 1}}]
        full = api.call('information_get_result', {'result_id': public['result_id'], 'view': 'full'})
        assert full['items'][0]['complete'] is True
        assert calls == [('ENG', list(territory.FIELDS))]
    finally:
        service.close()


@pytest.mark.parametrize('fields, skipped', [(['occupations'], 'occupation.blockade_flags'),
                                           (['blockades'], 'occupation.controller')])
def test_single_field_skips_unrequested_values(fields, skipped):
    report, context, creation = make_capture(fields)
    assert territory.validate_capture(report, context, creation, 'ENG', fields)
    assert not any(row['label'] == skipped for row in report['raw_reads'])


@pytest.mark.parametrize('admitted, undiscovered', [(False, ()), (True, (2,))])
def test_visibility_is_preserved_without_reading_hidden_province_flags(admitted, undiscovered):
    fields = list(territory.FIELDS)
    report, context, creation = make_capture(fields, admitted=admitted, undiscovered=undiscovered)
    assert territory.validate_capture(report, context, creation, 'ENG', fields)
    values = report['observation']['backend']['targets'][0]['fields']
    if not admitted:
        assert all(field['status'] == 'invisible' for field in values.values())
        assert not any(row['label'].startswith('occupation.') for row in report['raw_reads'])
    else:
        assert all(field['complete'] is False for field in values.values())
        address = RECORDS + 2 * RECORD_STRIDE + 0x958
        assert not any(row['address'] == hex(address) for row in report['raw_reads'])
