"""Native inventory admission and delivery, using synthetic capture reports."""
from contextlib import closing
from copy import deepcopy
import json
from types import SimpleNamespace

import pytest

from bridge.diplomacy_journal import DurableJournal
from bridge.information import InformationService
from bridge.information import native_pending_memory as native
from bridge.information.composite import CompositeSource
from bridge.information.pending_matters import JournalPendingMattersSource
from bridge.information.tools import InformationTools
from bridge.tests.test_information_pending_matters import (
    EXPERIMENT, SESSION, FakeBase, _context, _query, _register,
)
from bridge.tests.test_information_service import FakeClock, subscription_config


def inventory(count=0, observer='FRA'):
    entries = [] if count == 0 else [{
        'entry_id': 'pending-entry-' + 'a' * 32, 'recognition': 'recognized',
        'action_id': 'offer_alliance', 'actor': 'SAV', 'recipient': observer, 'phase': 'initiate',
    }]
    return {
        'scope': native.SCOPE, 'native_queue_count': count, 'recognized_entry_count': count,
        'unresolved_entry_count': 0, 'entries': entries,
        'identity_scope': 'native_list_entry_observation', 'list_traversal_complete': True,
        'payload_details_complete': False, 'response_contexts_available': False,
    }


def capture_report(context, count=0):
    return {
        'schema': native.SCHEMA, 'status': 'observed', 'country': context['observer'],
        'game_sha256': native.GAME_SHA256, 'profile_sha256': native.PROFILE_SHA256,
        'read_only': True, 'native_function_invoked': False, 'target_memory_written': False,
        'consistent': True, 'cleanup': {'closed': True},
        'identity': {'binding_verified': True, 'installation_session_id': SESSION},
        'game_date': context['game_date'], 'player_country': 'POR', 'value': inventory(count, context['observer']),
        'private': {'node': 'private-address-secret', 'token': 'private-token-secret'},
        'access': {'rpm_bytes': 47016, 'rpm_calls': 10, 'rpm_limit': 1048576,
                   'open_process_mask': 1040, 'node': 'private-access-secret'},
    }


@pytest.fixture
def setup(tmp_path):
    journal = DurableJournal(tmp_path / 'journal.sqlite3', EXPERIMENT, SESSION)
    base = FakeBase(journal)
    base.diplomacy_tools.session.directory = tmp_path
    state = {'count': 0, 'failed': False, 'calls': []}

    def capture(path, country):
        state['calls'].append((path, country))
        if state['failed']:
            return {'status': 'unknown', 'reason': 'NATIVE_PENDING_CAPTURE_FAILED'}
        return capture_report(base._contexts[-1], state['count'])

    source = JournalPendingMattersSource(base, native_pending=True, pending_capture=capture)
    try:
        yield source, base, state, journal
    finally:
        journal.close()


def test_native_inventory_retains_journal_and_sanitizes_private_proof(setup):
    source, base, state, journal = setup
    _register(journal, 'local-request')
    result = source.read(_query(), base.context())
    field = result['fields']['pending_matters']
    assert field['status'] == 'known' and field['partial'] is True
    value = field['value']
    assert value['journal_requests'][0]['request_id'] == 'local-request'
    assert value['native_inbound_pending']['status'] == 'known'
    assert value['native_inbound_pending']['value'] == inventory()
    assert value['action_authorization'] == 'none_from_information_query'
    assert state['calls'] == [(base.diplomacy_tools.session.directory / 'installation.json', 'FRA')]
    assert 'private-' not in json.dumps(result)
    assert 'payload-token-secret' not in json.dumps(result)


@pytest.mark.parametrize('damage', [
    'session', 'date', 'player', 'write', 'close', 'private_value', 'exception',
])
def test_bad_native_report_preserves_valid_journal(setup, damage):
    source, base, _state, journal = setup
    _register(journal, 'still-visible')
    report = capture_report(base.context())
    if damage == 'session':
        report['identity']['installation_session_id'] = 'other-session'
    elif damage == 'date':
        report['game_date'] += 24
    elif damage == 'player':
        report['player_country'] = 'FRA'
    elif damage == 'write':
        report['target_memory_written'] = True
    elif damage == 'close':
        report['cleanup']['closed'] = False
    elif damage == 'private_value':
        report['value']['node'] = 'private-value-secret'

    def capture(*_args):
        if damage == 'exception':
            raise OSError('private-error-secret')
        return report

    source.pending_capture = capture
    result = source.read(_query(), base.context())
    field = result['fields']['pending_matters']
    assert field['status'] == 'known'
    assert field['value']['journal_requests'][0]['request_id'] == 'still-visible'
    assert field['value']['native_inbound_pending']['status'] == 'unknown'
    assert source.change_comparison(_query(), result, base.context()) is None
    assert 'private-' not in json.dumps(result)


@pytest.mark.parametrize('mode', ['unready', 'invalid_observer', 'disabled'])
def test_ineligible_context_does_not_capture(setup, mode):
    source, base, state, _journal = setup
    if mode == 'unready':
        base._contexts = [_context(status='unready')]
    elif mode == 'invalid_observer':
        base._contexts = [_context(observer='eng')]
    else:
        source.native_pending = False
    source.read(_query(), base.context())
    assert state['calls'] == []


def test_native_inventory_reads_the_configured_recipient(setup):
    source, base, state, _journal = setup
    base._contexts = [_context(observer='TUR')]
    state['count'] = 1
    result = source.read(_query(), base.context())
    native_entry = result['fields']['pending_matters']['value']['native_inbound_pending']['value']['entries'][0]
    assert native_entry['recipient'] == 'TUR'
    assert state['calls'][0][1] == 'TUR'
    assert source.change_comparison(_query(), result, base.context()) is not None


def test_context_change_retracts_inventory(setup):
    source, base, state, _journal = setup
    base._contexts = [_context(), _context(game_date=56554872)]
    result = source.read(_query())
    assert result['fields']['pending_matters'] == {
        'status': 'unavailable', 'reason': 'PENDING_CONTEXT_CHANGED',
    }
    assert len(state['calls']) == 1


@pytest.mark.parametrize('composite', [False, True])
def test_normal_report_change_delivery_preserves_baseline_and_cancels(tmp_path, setup, composite):
    source, base, state, _journal = setup
    if composite:
        source = CompositeSource(source)
    clock = FakeClock()
    with closing(InformationService(source, tmp_path / 'information.sqlite3', clock=clock)) as service:
        tools = InformationTools(service)
        report = tools.call('information_manage_report', {
            'request_id': 'native-report', 'operation': 'create', 'config': {
                'name': 'Current diplomatic matters', 'detail': 'brief', 'queries': [_query()],
            },
        })['report']
        queried = tools.call('information_query', {
            'request_id': 'native-query', 'report_id': report['id'],
        })
        assert queried['items'][0]['pending_matters']['proposals'] == []
        query_full = tools.call('information_get_result', {'result_id': queried['result_id'], 'view': 'full'})
        assert query_full['items'][0]['fields']['pending_matters']['value']['native_inbound_pending']['status'] == 'known'
        subscription = tools.call('information_manage_subscription', {
            'request_id': 'native-change', 'operation': 'create',
            'config': subscription_config(report['id'], kind='change', every=5),
        })['subscription']

        def tick():
            clock.advance(5)
            return tools.call('information_tick', {'view': 'full'})['results']

        assert tick() == []
        baseline = deepcopy(service.status(subscription['id'])['subscriptions'][0]['runtime']['baseline'])
        base._contexts = [_context(game_date=56554872)]
        assert tick() == []
        state['failed'] = True
        assert tick() == []
        runtime = service.status(subscription['id'])['subscriptions'][0]['runtime']
        assert runtime['baseline'] == baseline
        assert runtime['last_attempt']['status'] == 'read_failed_baseline_preserved'
        state.update(failed=False, count=1)
        rows = tick()
        assert len(rows) == 1 and rows[0]['trigger'] == 'change'
        native_value = rows[0]['items'][0]['fields']['pending_matters']['value']['native_inbound_pending']['value']
        assert native_value == inventory(1)
        concise = tools.call('information_get_result', {'result_id': rows[0]['result_id']})
        assert len(concise['items'][0]['pending_matters']['proposals']) == 1
        assert rows[0]['complete'] is False
        assert tick() == []
        tools.call('information_manage_subscription', {
            'request_id': 'native-cancel', 'operation': 'cancel',
            'subscription_id': subscription['id'], 'expected_version': subscription['version'],
        })
        calls = len(state['calls'])
        assert tick() == []
        assert len(state['calls']) == calls


@pytest.mark.parametrize('failure', [
    'second_read', 'changed_snapshot', 'close_failed',
    'NATIVE_PENDING_QUEUE_MUTATING', 'NATIVE_PENDING_NODE_RETIRED',
])
def test_capture_retracts_on_partial_failure_and_closes_exact_handle(monkeypatch, failure):
    """Exercise production cleanup without opening a process or invoking Windows."""
    handle = object()
    closed = []
    snapshots = []
    document = {'pid': 123, 'session_id': SESSION}
    monkeypatch.setattr(native.memory, '_load_profile', lambda: {})
    monkeypatch.setattr(native.memory, '_load_installation', lambda _path: document)
    monkeypatch.setattr(native.memory, '_configure_kernel', lambda: SimpleNamespace(
        OpenProcess=lambda mask, inherit, pid: handle,
    ))
    monkeypatch.setattr(native.memory, '_capture_identity', lambda *_args: 0x140000000)
    monkeypatch.setattr(native.memory, 'AddressBoundedRPM', lambda *_args: object())

    def snapshot(*_args):
        snapshots.append(True)
        if len(snapshots) == 2 and failure == 'second_read':
            raise OSError('synthetic partial read failure')
        if len(snapshots) == 2 and failure.startswith('NATIVE_PENDING_'):
            raise ValueError(failure)
        date = 56554848 + (24 if failure == 'changed_snapshot' and len(snapshots) == 2 else 0)
        return {'value': inventory(), 'game_date': date, 'player_country': 'POR'}

    def close(kernel, actual_handle):
        closed.append(actual_handle)
        return {'closed': failure != 'close_failed'}

    monkeypatch.setattr(native, '_snapshot', snapshot)
    monkeypatch.setattr(native.memory, '_close_process_handle', close)
    report = native.capture('synthetic-installation.json')
    assert report['status'] == 'unknown' and 'value' not in report
    if failure.startswith('NATIVE_PENDING_'):
        assert report['reason'] == failure
    assert closed == [handle]
    assert len(snapshots) == 2
