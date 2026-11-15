from copy import deepcopy

import pytest

from bridge.information import InformationService
from bridge.information import ai_attitude as attitude
from bridge.information.composite import CompositeSource
from bridge.information.tools import InformationTools
from bridge.tests.test_information_foreign_technology import Base
from bridge.tests.test_information_foreign_technology_capture import (
    MODULE_BASE, RELATION_OWNER, RecordingReader, make_valid_capture,
)


def query(actor='ENG', recipient='FRA'):
    return {'topic': 'R06', 'object': {'type': 'country_pair', 'actor': actor, 'recipient': recipient},
            'fields': ['ai_attitude'], 'parameters': {}}


def make_capture(actor='ENG', recipient='FRA', *, admitted=True, absent=False):
    report, context, creation, fixture = make_valid_capture(admitted=admitted)
    image = fixture['image']
    row = fixture['relation_row']
    image.put(row, bytes(0x48))
    image.put_u64(row, RELATION_OWNER)
    image.put_u64(row + 0x10, fixture['target_fullref'])
    other_table = 0x6900000000
    image.put_u64(fixture['target_pointer'] + 0x1510, other_table)
    reverse_row = other_table + fixture['bindings']['FRA']['slot'] * 0x48
    image.put(reverse_row, bytes(0x48))
    image.put_u64(reverse_row, 0x6910000000)
    image.put_u64(reverse_row + 0x10, fixture['observer_fullref'])
    for index, (address, name) in enumerate(((row, 'attitude_neutral'), (reverse_row, 'attitude_hostile'))):
        definition = 0x6920000000 + index * 0x1000
        payload = 0x6930000000 + index * 0x1000
        image.put_u64(address + 0x28, 0 if absent else definition)
        raw = name.encode('ascii')
        header = bytearray(32)
        header[:8] = payload.to_bytes(8, 'little')
        header[16:24] = len(raw).to_bytes(8, 'little')
        header[24:32] = (31).to_bytes(8, 'little')
        image.put(definition + 8, bytes(header))
        image.put(payload, raw + b'\0')
    profile = attitude._load_profile()
    for guard in profile['code_guards']:
        image.put(MODULE_BASE + int(guard['rva'], 0), bytes.fromhex(guard['bytes']))
    reader = RecordingReader(image)
    report['schema'] = attitude.SCHEMA
    report['profile_sha256'] = attitude.PROFILE_SHA256
    report['request'].update(actor=actor, recipient=recipient)
    report['observation'] = attitude._observe_for(actor, recipient)(reader, MODULE_BASE, 'ENG', profile)
    report['raw_reads'] = deepcopy(reader.read_log)
    report['access'] = {'read_only': True, 'native_function_invoked': False,
        'writes': False, 'UI_control': False, 'date_advance': False, 'save_or_reload': False,
        'limit_bytes': attitude._owner.MAX_READ_BYTES,
        'calls': reader.calls, 'bytes_requested': reader.bytes_requested}
    return report, context, creation


@pytest.mark.parametrize('actor,recipient,expected', [('ENG', 'FRA', 'hostile'), ('FRA', 'ENG', 'neutral')])
def test_replayed_attitude_uses_selected_direction(actor, recipient, expected):
    report, context, creation = make_capture(actor, recipient)
    assert attitude.validate_capture(report, context, creation, actor, recipient)
    value = report['observation']['backend']['targets'][0]['fields'][attitude.FIELD]
    assert value['value'] == expected
    assert not attitude.validate_capture(report, context, creation, recipient, actor)
    value['value'] = 'friendly'
    assert not attitude.validate_capture(report, context, creation, actor, recipient)


@pytest.mark.parametrize('admitted,absent,status', [(False, False, 'invisible'), (True, True, 'unknown')])
def test_invisible_and_missing_attitudes_have_no_invented_value(admitted, absent, status):
    report, context, creation = make_capture(admitted=admitted, absent=absent)
    assert attitude.validate_capture(report, context, creation, 'ENG', 'FRA')
    value = report['observation']['backend']['targets'][0]['fields'][attitude.FIELD]
    assert value['status'] == status
    assert 'value' not in value


def test_normal_query_and_full_recall_preserve_attitude_direction(tmp_path):
    report, context, creation = make_capture()
    base = Base(tmp_path, context, creation)
    adapter = attitude.NativeAiAttitudeSource(base, capture=lambda *args: deepcopy(report))
    source = CompositeSource(base, [adapter])
    topic = next(item for item in source.catalog() if item['topic_id'] == 'R06')
    assert topic['fields']['ai_attitude']['coverage'] == 'available'
    assert 'personality' in topic['fields']
    service = InformationService(source, tmp_path / 'information.sqlite3')
    try:
        tools = InformationTools(service)
        result = tools.call('information_query', {'request_id': 'attitude-query', 'queries': [query()]})
        assert result['items'] == [{'actor': 'ENG', 'recipient': 'FRA', 'ai_attitude': 'hostile'}]
        full = tools.call('information_get_result', {'result_id': result['result_id'], 'view': 'full'})
        assert full['items'][0]['fields']['ai_attitude']['raw_name'] == 'attitude_hostile'
    finally:
        service.close()
