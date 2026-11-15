from copy import deepcopy

import pytest

from bridge.information import InformationService
from bridge.information import foreign_pressure as pressure
from bridge.information.composite import CompositeSource
from bridge.information.tools import InformationTools
from bridge.tests.test_information_foreign_technology import Base
from bridge.tests.test_information_foreign_technology_capture import (
    MODULE_BASE, WORLD, RecordingReader, make_valid_capture,
)
from bridge.tests.test_information_country_occupation_memory import put_provinces
from bridge.tests.test_information_foreign_technology_memory import COUNTRY_BASE


def query(fields=None):
    return {'topic': 'F04', 'object': {'type': 'country', 'country': 'ENG'},
            'fields': fields or ['war_exhaustion'], 'parameters': {}}


def make_pressure_capture(admitted=True, fields=None, undiscovered=(), owner_mismatch=False):
    fields = fields or ['war_exhaustion']
    report, context, creation, fixture = make_valid_capture(admitted=admitted)
    image = fixture['image']
    profile = pressure._load_profile()
    for guard in profile['code_guards']:
        image.put(MODULE_BASE + int(guard['rva'], 0), bytes.fromhex(guard['bytes']))
    for tag, value in (('FRA', 1000), ('POR', 2000), ('ENG', 7250)):
        pointer = COUNTRY_BASE + fixture['bindings'][tag]['slot'] * 0x1000
        image.put_i32(pointer + 0xd10, value)
        image.put_i32(pointer + 0x2030, {'FRA': -9000, 'POR': 3250, 'ENG': -3250}[tag])
    if 'occupied' in fields:
        put_provinces(image, fixture['target_fullref'],
            [fixture['target_fullref'], fixture['observer_fullref']],
            country=fixture['target_pointer'], world=WORLD, undiscovered=undiscovered)
        if owner_mismatch:
            from bridge.tests.test_information_country_occupation_memory import RECORDS
            from bridge.information.province_reference_memory import RECORD_STRIDE
            image.put_u64(RECORDS + RECORD_STRIDE + 0x468, fixture['observer_fullref'])
    reader = RecordingReader(image)
    report['schema'] = pressure.SCHEMA
    report['profile_sha256'] = pressure.PROFILE_SHA256
    report['request']['fields'] = fields
    report['observation'] = pressure._observe_for(fields)(reader, MODULE_BASE, 'ENG', profile)
    report['raw_reads'] = deepcopy(reader.read_log)
    report['access'] = {'read_only': True, 'native_function_invoked': False,
        'writes': False, 'UI_control': False, 'date_advance': False, 'save_or_reload': False,
        'limit_bytes': pressure._owner.MAX_READ_BYTES,
        'calls': reader.calls, 'bytes_requested': reader.bytes_requested}
    return report, context, creation


@pytest.mark.parametrize('admitted', [True, False])
def test_foreign_pressure_replays_target_value_and_admission(admitted):
    report, context, creation = make_pressure_capture(admitted)
    assert pressure.validate_capture(report, context, creation, 'ENG')
    value = report['observation']['backend']['targets'][0]['fields'][pressure.FIELD]
    if admitted:
        assert value['value'] == 7250
        assert value['scale'] == 1000
        value['value'] = 1000
        assert not pressure.validate_capture(report, context, creation, 'ENG')
    else:
        assert value['status'] == 'invisible'
        assert 'value' not in value
        assert not any(row['label'] == 'foreign_pressure.war_exhaustion'
                       for row in report['raw_reads'])


def test_service_tools_query_and_recall_keep_foreign_value_concise(tmp_path):
    report, context, creation = make_pressure_capture()
    base = Base(tmp_path, context, creation)
    calls = []

    def capture(installation, *, country, observer):
        calls.append((country, observer))
        return deepcopy(report)

    adapter = pressure.NativeForeignPressureSource(base, capture=capture)
    source = CompositeSource(base, [adapter])
    topic = next(item for item in source.catalog() if item['topic_id'] == 'F04')
    assert topic['fields']['war_exhaustion']['coverage'] == 'available'
    assert 'succession_risk' in topic['fields']
    service = InformationService(source, tmp_path / 'information.sqlite3')
    try:
        tools = InformationTools(service)
        result = tools.call('information_query', {'request_id': 'foreign-pressure', 'queries': [query()]})
        assert result['items'] == [{'country': 'ENG',
            'war_exhaustion': {'current': 7.25, 'min': 0, 'max': 20}}]
        full = tools.call('information_get_result', {'result_id': result['result_id'], 'view': 'full'})
        assert full['items'][0]['fields']['war_exhaustion']['raw'] == 7250
        assert calls == [('ENG', 'FRA')]
    finally:
        service.close()


def test_occupation_only_does_not_read_war_exhaustion():
    fields = ['occupied']
    report, context, creation = make_pressure_capture(fields=fields)
    assert pressure.validate_capture(report, context, creation, 'ENG', fields)
    assert not any(row['label'] == 'foreign_pressure.war_exhaustion' for row in report['raw_reads'])


def test_occupation_failure_preserves_independent_war_exhaustion(tmp_path):
    fields = ['war_exhaustion', 'occupied']
    report, context, creation = make_pressure_capture(fields=fields, owner_mismatch=True)
    assert pressure.validate_capture(report, context, creation, 'ENG', fields)
    adapter = pressure.NativeForeignPressureSource(Base(tmp_path, context, creation),
        capture=lambda *args, **kwargs: deepcopy(report))
    result = adapter.read(query(fields))
    assert result['fields']['war_exhaustion']['value'] == 7250
    assert result['fields']['occupied']['status'] == 'unknown'
    assert result['complete'] is False


@pytest.mark.parametrize('admitted', [True, False])
def test_foreign_average_unrest_preserves_sign_and_respects_admission(admitted):
    fields = ['unrest']
    report, context, creation = make_pressure_capture(admitted=admitted, fields=fields)
    assert pressure.validate_capture(report, context, creation, 'ENG', fields)
    value = report['observation']['backend']['targets'][0]['fields']['F04.unrest']
    if admitted:
        assert value['value'] == -3250
        assert value['scale'] == 1000
    else:
        assert value['status'] == 'invisible'
        assert not any(row['label'] == 'foreign_pressure.average_unrest' for row in report['raw_reads'])
    assert not any(row['label'].startswith('occupation.') for row in report['raw_reads'])


def test_foreign_unrest_is_concise_average_points(tmp_path):
    fields = ['unrest']
    report, context, creation = make_pressure_capture(fields=fields)
    adapter = pressure.NativeForeignPressureSource(Base(tmp_path, context, creation),
        capture=lambda *args, **kwargs: deepcopy(report))
    service = InformationService(CompositeSource(adapter.base_source, [adapter]), tmp_path / 'information.sqlite3')
    try:
        api = InformationTools(service)
        result = api.call('information_query', {'request_id': 'foreign-unrest', 'queries': [query(fields)]})
        assert result['items'] == [{'country': 'ENG', 'average_unrest': -3.25}]
    finally:
        service.close()


def test_invalid_capture_does_not_export_target_value(tmp_path):
    report, context, creation = make_pressure_capture()
    report['request']['country'] = 'POR'
    adapter = pressure.NativeForeignPressureSource(Base(tmp_path, context, creation),
        capture=lambda *args, **kwargs: report)
    result = adapter.read(query())
    assert result['fields']['war_exhaustion']['status'] == 'unknown'
    assert 'value' not in result['fields']['war_exhaustion']


@pytest.mark.parametrize('undiscovered', [(), (2,)])
def test_combined_occupation_query_reuses_one_capture_and_exports_summary(tmp_path, undiscovered):
    fields = ['war_exhaustion', 'occupied']
    report, context, creation = make_pressure_capture(fields=fields, undiscovered=undiscovered)
    assert pressure.validate_capture(report, context, creation, 'ENG', fields)
    calls = []

    def capture(installation, **arguments):
        calls.append(arguments)
        return deepcopy(report)

    adapter = pressure.NativeForeignPressureSource(Base(tmp_path, context, creation), capture=capture)
    service = InformationService(CompositeSource(adapter.base_source, [adapter]), tmp_path / 'information.sqlite3')
    try:
        api = InformationTools(service)
        public = api.call('information_query', {'request_id': 'occupation', 'queries': [query(fields)]})
        occupied = public['items'][0]['occupied']
        assert occupied['owned_provinces'] == 2
        assert occupied['observed_provinces'] == (1 if undiscovered else 2)
        assert occupied['occupied_provinces'] == (0 if undiscovered else 1)
        assert occupied['occupiers'] == ({} if undiscovered else {'FRA': 1})
        full = api.call('information_get_result', {'result_id': public['result_id'], 'view': 'full'})
        assert full['complete'] is (not bool(undiscovered))
        assert len(calls) == 1
    finally:
        service.close()
