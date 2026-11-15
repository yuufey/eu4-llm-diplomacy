"""Bilateral war preparation dates and current R07 delivery."""
from copy import deepcopy
from types import SimpleNamespace
import struct

import pytest

from bridge.information import war_preparation_capture as capture
from bridge.information import war_preparation_memory as memory
from bridge.information.commitments import NativeCommitmentsSource
from bridge.information.composite import CompositeSource
from bridge.information.service import InformationService
from bridge.information.tools import InformationTools
from bridge.tests import test_information_country_faith_capture as fixture
from bridge.tests import test_information_foreign_technology_capture as parent
from bridge.tests import test_information_ongoing_economic_commitments as economic_fixture
from bridge.tests.test_information_foreign_economy import BaseSource


def bundle(*, delta=24, recipient='ENG', changed=False, wrong_generation=False):
    profile = capture._load_profile()
    image, state = fixture._make_image('ENG', profile)
    for tag, other in (('ENG', 'FRA'), ('FRA', 'ENG')):
        until = parent.GAME_DATE + delta if tag == recipient else 0
        reference = state['refs'][other]
        if wrong_generation:
            reference ^= 1 << 48
        pointer = state['bindings'][tag]['country_pointer']
        image.put(pointer + memory.DEADLINE_OFFSET, struct.pack('<iQ', until, reference))
    if changed:
        def change(image, address, size, label, count):
            if label == 'war_preparation.ENG' and count == 2:
                image.put(address, b'\0' * 12)
        image.on_read = change
    reader = parent.RecordingReader(image)
    observation = capture._observe(reader, parent.MODULE_BASE, 'ENG', profile)
    identity = {'binding_verified': True, 'process_creation_filetime': parent.CREATION,
                'process_path': 'synthetic-eu4.exe', 'process_path_sha256': capture._owner.EXE_SHA256}
    report = {
        'schema': capture.SCHEMA, 'status': 'observed', 'completed': True,
        'profile_sha256': capture.PROFILE_SHA256,
        'request': {'country': 'ENG', 'observer': 'FRA', 'creation_filetime': parent.CREATION,
                    'session_id': parent.SESSION_ID},
        'identity': identity, 'identity_after': deepcopy(identity),
        'module_base': hex(parent.MODULE_BASE), 'observation': observation,
        'raw_reads': reader.read_log,
        'cleanup': {'status': 'closed', 'closed': True, 'success': True},
        'access': {'read_only': True, 'native_function_invoked': False, 'writes': False,
                   'UI_control': False, 'date_advance': False, 'save_or_reload': False,
                   'limit_bytes': capture._owner.MAX_READ_BYTES,
                   'calls': reader.calls, 'bytes_requested': reader.bytes_requested},
    }
    context = {'status': 'ready', 'mode': 'live', 'observer': 'FRA',
               'session_id': parent.SESSION_ID, 'game_version': '1.37.4',
               'game_sha256': capture._owner.EXE_SHA256, 'game_date': parent.GAME_DATE}
    return report, context


@pytest.mark.parametrize('delta,expected', [(24, True), (23, False), (0, False), (-24, False)])
def test_native_day_boundary_and_exact_replay(delta, expected):
    report, context = bundle(delta=delta)
    assert capture.validate_capture(report, context, parent.CREATION, 'ENG')
    field = report['observation']['backend']['targets'][0]['fields'][memory.FIELD]
    assert field['status'] == 'known'
    assert bool(field['value']) is expected
    if expected:
        assert field['value'][0]['country'] == 'ENG'
        assert field['value'][0]['for'] == 'FRA'


def test_reverse_pledge_preserves_preparing_country():
    report, _ = bundle(recipient='FRA')
    field = report['observation']['backend']['targets'][0]['fields'][memory.FIELD]
    assert field['value'][0]['country'] == 'FRA'
    assert field['value'][0]['for'] == 'ENG'


def test_old_requester_generation_does_not_become_current_pledge():
    report, context = bundle(wrong_generation=True)
    assert capture.validate_capture(report, context, parent.CREATION, 'ENG')
    assert report['observation']['backend']['targets'][0]['fields'][memory.FIELD]['value'] == []


def test_change_between_passes_keeps_pledge_unknown():
    report, context = bundle(changed=True)
    assert capture.validate_capture(report, context, parent.CREATION, 'ENG')
    assert report['observation']['backend']['targets'][0]['fields'][memory.FIELD]['status'] == 'unknown'


def test_trace_rejects_altered_beneficiary():
    report, context = bundle()
    report['observation']['backend']['targets'][0]['fields'][memory.FIELD]['value'][0]['for'] = 'POR'
    assert not capture.validate_capture(report, context, parent.CREATION, 'ENG')


def test_normal_report_periodic_change_and_cold_reopen(tmp_path):
    positive, context = bundle()
    empty, _ = bundle(delta=0)
    economic_positive, _ = economic_fixture.make_capture()
    economic_empty, _ = economic_fixture.make_capture(present=False)
    current = [positive, economic_positive]
    base = BaseSource(tmp_path)
    base.current = context
    base.session.record.update(creation_filetime=parent.CREATION)
    economy = SimpleNamespace(base_source=base, context=base.context)
    adapter = NativeCommitmentsSource(economy, war_capture=lambda path, tag: deepcopy(current[0]),
                                    economic_capture=lambda path, tag: deepcopy(current[1]))
    source = CompositeSource(base, [adapter])
    now = [100.0]
    database = tmp_path / 'information.sqlite3'
    service = InformationService(source, database, clock=lambda: now[0])
    query = {'topic': 'R07', 'object': {'type': 'country_pair', 'actor': 'FRA', 'recipient': 'ENG'},
             'fields': ['war_commitments', 'economic_support', 'expiry']}
    try:
        tools = InformationTools(service)
        result = tools.call('information_query', {'request_id': 'prep-query', 'queries': [query]})
        assert result['items'][0]['war_commitments'][0]['country'] == 'ENG'
        assert result['items'][0]['economic_support'][0]['monthly_amount'] == 12.5
        assert 'expiry_comparison' not in repr(result)
        assert len(result['items'][0]['economic_support']) == 2
        assert result['items'][0]['economic_support'][1]['income_percent'] == 10
        assert len(result['items'][0]['expiry']) == 3
        report = tools.call('information_manage_report', {'request_id': 'prep-report', 'operation': 'create',
            'config': {'name': 'prepare for war', 'queries': [query], 'detail': 'brief'}})['report']
        periodic = tools.call('information_manage_subscription', {'request_id': 'prep-periodic',
            'operation': 'create', 'config': {'name': 'periodic', 'kind': 'periodic', 'report_id': report['id'],
            'enabled': True, 'schedule': {'basis': 'real', 'every': 1, 'unit': 'seconds', 'missed': 'coalesce'}}})
        change = tools.call('information_manage_subscription', {'request_id': 'prep-change',
            'operation': 'create', 'config': {'name': 'change', 'kind': 'change', 'report_id': report['id'],
            'enabled': True, 'schedule': {'basis': 'real', 'every': 1, 'unit': 'seconds', 'missed': 'coalesce'}}})
        now[0] += 1
        assert len(tools.call('information_tick', {'view': 'full'})['results']) == 1
        current[:] = [empty, economic_empty]
        now[0] += 1
        delivery = tools.call('information_tick', {'view': 'full'})['results']
        assert len(delivery) == 2
        assert all(row['items'][0]['fields']['war_commitments']['value'] == [] for row in delivery)
        assert all(row['items'][0]['fields']['expiry']['value'] == [] for row in delivery)
        for configured in (periodic, change):
            subscription = configured['subscription']
            tools.call('information_manage_subscription', {'request_id': 'cancel-' + subscription['id'],
                'operation': 'cancel', 'subscription_id': subscription['id'],
                'expected_version': subscription['version']})
    finally:
        service.close()
    reopened = InformationService(source, database)
    try:
        assert InformationTools(reopened).call('information_get_result', {'result_id': result['result_id']}) == result
    finally:
        reopened.close()
