from copy import deepcopy
from types import SimpleNamespace
from pathlib import Path

import pytest

from bridge.information import own_resource_caches as caches
from bridge.information.country_state import NativeCountryStateSource
from bridge.information.observation_time import sampled_read
from bridge.information.service import InformationService
from bridge.information.tools import InformationTools


def _context(date=100):
    return {'mode': 'live', 'status': 'ready', 'game_date': date,
            'session_id': 'session-1', 'game_sha256': 'exe', 'observer': 'FRA',
            'game_version': '1.37.4'}


def _query(topic='N01', field='treasury', parameters=None):
    return {'topic': topic, 'object': {'type': 'country', 'country': 'FRA'},
            'fields': [field], 'parameters': parameters if parameters is not None else (
                {} if topic == 'N02' and field in ('max_manpower', 'max_sailors') else
                {'reference_recipient': 'ENG'})}


def _source(after):
    return SimpleNamespace(session=SimpleNamespace(directory=Path('session'),
        record={'creation_filetime': 123}), context=lambda: deepcopy(after))


@pytest.mark.parametrize('topic,field,raw', [
    ('N01', 'treasury', -12345), ('N02', 'manpower', 23456),
    ('N02', 'max_manpower', 67890),
])
def test_running_own_cache_preserves_existing_raw_value_contract(monkeypatch, topic, field, raw):
    query = _query(topic, field)
    report = {'observation': {'backend': {'targets': [
        {'fields': {topic + '.' + field: {'status': 'known', 'value': raw}}}]}}}
    monkeypatch.setattr(caches, 'capture', lambda *args: deepcopy(report))
    monkeypatch.setattr(caches._owner, '_validate_capture_common', lambda *args, **kwargs: True)
    with sampled_read(query, _context()):
        result = caches.read(_source(_context(102)), query, _context())
    assert result['fields'][field] == {'status': 'known', 'value': raw}
    assert result['complete'] is True


@pytest.mark.parametrize('after', [_context(99), dict(_context(102), session_id='session-2')])
def test_own_cache_rejects_rollback_and_session_change(monkeypatch, after):
    monkeypatch.setattr(caches, 'capture', lambda *args: {})
    monkeypatch.setattr(caches._owner, '_validate_capture_common', lambda *args, **kwargs: True)
    with sampled_read(_query(), _context()):
        assert caches.read(_source(after), _query(), _context()) is None


def test_own_cache_requires_capture_validation_and_npc_scope(monkeypatch):
    calls = []
    monkeypatch.setattr(caches, 'capture', lambda *args: calls.append(args) or {})
    monkeypatch.setattr(caches._owner, '_validate_capture_common', lambda *args, **kwargs: False)
    with sampled_read(_query(), _context()):
        assert caches.read(_source(_context()), _query(), _context()) is None
    assert len(calls) == 1
    foreign = _query()
    foreign['object']['country'] = 'POR'
    assert caches.read(_source(_context()), foreign, _context()) is None
    assert len(calls) == 1


def test_normal_country_state_entry_routes_both_resource_fields(monkeypatch):
    seen = []
    expected = {'fields': {
        'treasury': {'status': 'known', 'value': -12345},
        'manpower': {'status': 'known', 'value': 23456},
        'max_manpower': {'status': 'known', 'value': 67890},
    }}
    def route(source, query, context):
        seen.append((query['topic'], tuple(query['fields'])))
        return {'fields': {name: expected['fields'][name] for name in query['fields']}}

    monkeypatch.setattr(caches, 'read', route)
    source = NativeCountryStateSource(_source(_context()))
    mixed = {'topic': 'N02', 'object': {'type': 'country', 'country': 'FRA'},
             'fields': ['manpower', 'max_manpower'],
             'parameters': {}}
    for query in (_query(), _query('N02', 'manpower'), _query('N02', 'max_manpower'), mixed):
        with sampled_read(query, _context()):
            result = source.read(query, _context())
            assert set(result['fields']) == set(query['fields'])
    assert seen == [
        ('N01', ('treasury',)),
        ('N02', ('manpower',)),
        ('N02', ('max_manpower',)),
        ('N02', ('manpower', 'max_manpower')),
    ]


def test_information_tools_reads_n01_treasury_and_monthly_without_reference(
    tmp_path, monkeypatch,
):
    base = _source(_context())
    preview_calls = []

    def inspect_pair(*args, **kwargs):
        preview_calls.append((args, kwargs))
        raise AssertionError('country-pair preview must not run')

    base.diplomacy_tools = SimpleNamespace(inspect_diplomatic_action=inspect_pair)
    source = NativeCountryStateSource(base)
    cache_fields = ('N01.treasury',)
    cache_report = {'observation': {'backend': {'targets': [{'fields': {
        'N01.treasury': {'status': 'known', 'value': -12345},
    }}]}}}
    captured = []
    monkeypatch.setattr(
        caches, 'capture',
        lambda _installation, fields: captured.append(tuple(fields)) or deepcopy(cache_report),
    )
    monkeypatch.setattr(
        caches._owner, '_validate_capture_common',
        lambda *args, **kwargs: True,
    )

    def monthly(normalized, _current, *, context_supplied):
        assert context_supplied is True
        assert normalized['parameters'] == {}
        return {
            'fields': {
                field: {'status': 'known', 'value': 900}
                for field in normalized['fields']
            },
            'source': {'provenance': {}},
        }

    monkeypatch.setattr(source, '_read_monthly_economy', monthly)
    service = InformationService(source, tmp_path / 'information.sqlite3')
    try:
        api = InformationTools(service)
        result = api.call('information_query', {
            'request_id': 'n01-mixed-cache',
            'queries': [{
                'topic': 'N01',
                'object': {'type': 'country', 'country': 'FRA'},
                'fields': ['treasury', 'monthly_income'],
                'parameters': {},
            }],
            'view': 'full',
        })
        fields = result['items'][0]['fields']
        assert fields['treasury'] == {'status': 'known', 'value': -12345, 'unit': 'ducats', 'scale': 1000}
        assert fields['monthly_income'] == {'status': 'known', 'value': 900, 'unit': 'ducats', 'scale': 1000}
        assert captured == [cache_fields]
        assert preview_calls == []
    finally:
        service.close()


def test_n01_unavailable_cache_without_reference_is_explicit(monkeypatch):
    base = _source(_context())
    preview_calls = []
    base.diplomacy_tools = SimpleNamespace(
        inspect_diplomatic_action=lambda *args, **kwargs: preview_calls.append((args, kwargs))
    )
    source = NativeCountryStateSource(base)
    query = _query('N01', 'treasury', parameters={})

    def unavailable_capture(*_args, **_kwargs):
        raise RuntimeError('cache unavailable')

    monkeypatch.setattr(caches, 'capture', unavailable_capture)
    with sampled_read(query, _context()):
        result = source.read(query, _context())

    assert result['fields']['treasury'] == {
        'status': 'unavailable', 'reason': 'COUNTRY_RESOURCE_CACHE_UNAVAILABLE'
    }
    assert preview_calls == []


def test_manpower_and_max_manpower_share_one_cache_capture(monkeypatch):
    query = {'topic': 'N02', 'object': {'type': 'country', 'country': 'FRA'},
             'fields': ['manpower', 'max_manpower'],
             'parameters': {}}
    captured = []
    report = {'observation': {'backend': {'targets': [{'fields': {
        'N02.manpower': {'status': 'known', 'value': 23456},
        'N02.max_manpower': {'status': 'known', 'value': 67890},
    }}]}}}
    monkeypatch.setattr(caches, 'capture', lambda _installation, fields:
                        captured.append(tuple(fields)) or deepcopy(report))
    monkeypatch.setattr(caches._owner, '_validate_capture_common', lambda *args, **kwargs: True)
    with sampled_read(query, _context()):
        result = caches.read(_source(_context()), query, _context())
    assert captured == [('N02.manpower', 'N02.max_manpower')]
    assert result['fields'] == {
        'manpower': {'status': 'known', 'value': 23456},
        'max_manpower': {'status': 'known', 'value': 67890},
    }


def test_cache_fields_use_pinned_offsets_and_do_not_invoke_native_functions(monkeypatch):
    profile = caches._load_profile()
    seen = []
    values = {0x10000 + 0xBB0: -12345, 0x10000 + 0xDB8: 23456,
              0x10000 + 0xDBC: 67890, 0x10000 + 0xDC4: 8100000}

    class Reader:
        def read(self, address, size, label):
            seen.append((address, size, label))
            return values[address].to_bytes(size, 'little', signed=True)

    def backend(reader, base, observer, targets, *, fields, admission_reader, read_fields):
        assert targets == [observer] == ['FRA']
        assert admission_reader is caches._owner._bound_admission
        return read_fields(reader, base, {'country_pointer': '0x10000'}, fields)

    monkeypatch.setattr(caches._countries, 'read_two_pass', backend)
    monkeypatch.setattr(caches._owner, '_observe',
        lambda reader, base, country, profile, *, backend_reader: backend_reader(reader, base, country))
    result = caches._observe_for(('N01.treasury', 'N02.manpower', 'N02.max_manpower'))(
        Reader(), 0x20000, 'FRA', profile)
    assert result['N01.treasury']['value'] == -12345
    assert result['N01.treasury']['scale'] == 1000
    assert result['N02.manpower']['value'] == 23456
    assert result['N02.max_manpower']['value'] == 67890
    assert result['N02.max_manpower']['raw_hex'] == (67890).to_bytes(4, 'little', signed=True).hex()
    assert [row[:2] for row in seen] == [(0x10BB0, 4), (0x10DB8, 4), (0x10DBC, 4)]
    values[0x10DB8] = -1
    result = caches._observe_for(('N02.manpower',))(Reader(), 0x20000, 'FRA', profile)
    assert result['N02.manpower']['status'] == 'unknown'
    values[0x10DBC] = -1
    result = caches._observe_for(('N02.max_manpower',))(Reader(), 0x20000, 'FRA', profile)
    assert result['N02.max_manpower'] == {
        'status': 'unknown', 'reason': 'MAX_MANPOWER_CACHE_NEGATIVE'}
    result = caches._observe_for(('N02.max_sailors',))(Reader(), 0x20000, 'FRA', profile)
    assert result['N02.max_sailors'] == {
        'status': 'known', 'value': 8100000, 'raw': 8100000,
        'raw_hex': (8100000).to_bytes(4, 'little', signed=True).hex(),
        'unit': 'sailors', 'scale': 1000}
    values[0x10DC4] = -1
    result = caches._observe_for(('N02.max_sailors',))(Reader(), 0x20000, 'FRA', profile)
    assert result['N02.max_sailors'] == {
        'status': 'unknown', 'reason': 'MAX_SAILORS_CACHE_NEGATIVE'}


def test_max_sailors_without_recipient_does_not_fall_back_to_diplomacy(monkeypatch):
    query = _query('N02', 'max_sailors')
    source = NativeCountryStateSource(_source(_context()))
    monkeypatch.setattr(caches, 'capture', lambda *args: {'status': 'unknown'})
    monkeypatch.setattr(caches._owner, '_validate_capture_common', lambda *args, **kwargs: False)
    def unexpected_inspect(*args, **kwargs):
        pytest.fail('maximum sailors must use its own cache')
    monkeypatch.setattr(source, '_inspect', unexpected_inspect)
    with sampled_read(query, _context()):
        result = source.read(query, _context())
    assert result['fields']['max_sailors'] == {
        'status': 'unknown', 'reason': 'MAX_SAILORS_CACHE_CAPTURE_INVALID'}


def test_max_manpower_query_needs_no_recipient_and_capture_failure_skips_diplomacy(monkeypatch):
    query = _query('N02', 'max_manpower')
    inspected = []
    source = NativeCountryStateSource(_source(_context()))
    monkeypatch.setattr(caches, 'capture', lambda *args: {'status': 'unknown'})
    monkeypatch.setattr(caches._owner, '_validate_capture_common', lambda *args, **kwargs: False)
    monkeypatch.setattr(source, '_inspect', lambda *args, **kwargs: inspected.append(args))
    with sampled_read(query, _context()):
        result = source.read(query, _context())
    assert result['fields']['max_manpower']['status'] == 'unknown'
    assert result['fields']['max_manpower']['reason'] == 'MAX_MANPOWER_CACHE_CAPTURE_INVALID'
    assert inspected == []
