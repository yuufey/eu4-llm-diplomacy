"""Synthetic expiry observations correlated and delivered through normal tools."""
from contextlib import closing
from copy import deepcopy
import json
import io
from pathlib import Path

import pytest

from bridge.diplomacy import DiplomacyTools
from bridge.diplomacy_journal import DurableJournal
from bridge.information import InformationService
from bridge.information.sources import DiplomacySource
from bridge.information.tools import InformationTools
from bridge import proposal_expiry as expiry
from bridge.tests.test_call_to_arms_observation import LogSession
from bridge.tests.test_favor_trade_inbound import offer_event

SESSION = 'synthetic-expiry-session'
NOW = 56566584


def offer(action='offer_alliance', token=19, native_id=1):
    event = offer_event()
    event.update(session_id=SESSION, actor='SAV', mirror='SAV', action_id=action,
                 family=expiry.ACTION_VTABLES[action][1], proposal_id=native_id,
                 date28=NOW-96, date2c=NOW-96, created2c=NOW-96,
                 proposal3c=token, token3c=token & 0xffffffff)
    return event


def expired(action='offer_alliance', token=19, sequence=101):
    def reference(tag, slot):
        return hex(0x0100000000000000 | (slot << 32) | int.from_bytes(tag.encode(), 'little'))

    return {
        'event': 'native_alliance_lifecycle', 'session_id': SESSION,
        'kind': 'destructor_return', 'sequence': sequence, 'source_event_id': sequence,
        'caller_return_rva': expiry.EXPIRY_RETURN_RVA,
        'native_return_observed': True, 'native_flags': 1,
        'native_forward_count_by_hook_contract': 1,
        'observed_game_date_raw': NOW, 'observed_game_date_verified': True,
        'native_result': '0xprivate-result',
        'source': {'addr': '0xprivate-action', 'readable': True, 'matched': True,
                   'handles_canonical': True, 'tracked': True, 'discriminator': 0x165,
                   'state34': 0, 'variant38': 1, 'date28': NOW-96, 'date2c': NOW-96,
                   'envoy30': 3, 'proposal3c': token, 'extra60': 0,
                   'actor10': reference('SAV', 2), 'mirror18': reference('SAV', 2),
                   'recipient20': reference('FRA', 1),
                   'vtable_rva': hex(expiry.ACTION_VTABLES[action][0]),
                   'family': expiry.ACTION_VTABLES[action][1]},
    }


def session(directory, events=(), *, enabled=True):
    record = {'experiment_id': 'synthetic-expiry', 'session_id': SESSION,
              'game_sha256': expiry.GAME_SHA256, 'dll_sha256': 'a' * 64}
    path = directory / 'installation.json'
    path.write_text(json.dumps(record), encoding='utf-8')
    ack = {'event': 'diplomacy_observer_installed', 'session_id': SESSION,
           'version': 41, 'native_inbound_alliance': True, expiry.CAPABILITY: enabled}
    (directory / 'control-probe.jsonl').write_text(
        ''.join(json.dumps(row) + '\n' for row in [ack, *events]), encoding='utf-8')
    return LogSession(path, directory / 'unused.exe')


def append(session, *events, final_newline=True):
    with (session.directory / 'control-probe.jsonl').open('a', encoding='utf-8') as stream:
        stream.write('\n'.join(json.dumps(event) for event in events))
        if final_newline:
            stream.write('\n')


def lifecycle_events(session):
    return [row for row in session.read_native_inbound_events()
            if row['payload'].get('observer_status') == 'expired']


@pytest.mark.parametrize('action', list(expiry.ACTION_VTABLES))
def test_supported_actions_bind_original_public_id_without_native_identity_leak(tmp_path, action):
    observed = session(tmp_path, [offer(action), expired(action)])
    original = observed.read_native_inbound_offers()[0]
    event = lifecycle_events(observed)[0]
    assert event['payload']['proposal_id'] == original['proposal_id']
    assert event['payload']['action_id'] == action
    assert event['payload']['parameters']['proposal_lifecycle']['game_date_raw'] == NOW
    assert event['payload']['currently_pending'] is False
    assert 'private-' not in json.dumps(event)
    assert 'actor10' not in json.dumps(event) and 'token3c' not in json.dumps(event)
    assert observed.read_native_inbound_capture_gaps() == []


@pytest.mark.parametrize('damage', [
    {'kind': 'destructor'}, {'caller_return_rva': '0x3609ed'},
    {'session_id': 'other-session'}, {'native_return_observed': False},
    {'observed_game_date_verified': False}, {'observed_game_date_raw': NOW-24},
    {'observed_game_date_raw': True}, {'native_flags': True}, {'native_flags': 0},
    {'sequence': True}, {'source_event_id': 202},
    {'native_forward_count_by_hook_contract': True},
])
def test_incomplete_wrong_or_threshold_equal_observations_are_rejected(damage):
    assert expiry.validate_expiry(dict(expired(), **damage), SESSION) is None


@pytest.mark.parametrize('damage', [
    {'readable': False}, {'tracked': False}, {'handles_canonical': False},
    {'state34': 1}, {'variant38': 0}, {'discriminator': True},
    {'proposal3c': 0}, {'date2c': True}, {'date2c': 2**31-1},
    {'vtable_rva': '0x1234'}, {'family': 'gift'}, {'recipient20': '0xprivate'},
    {'mirror18': '0x1'}, {'actor10': '0x1'},
])
def test_unverified_source_shapes_are_rejected(damage):
    raw = expired()
    raw['source'].update(damage)
    assert expiry.validate_expiry(raw, SESSION) is None


@pytest.mark.parametrize('enabled', [False, 1, 'true'])
def test_expiry_requires_literal_top_level_ack(tmp_path, enabled):
    observed = session(tmp_path, [offer(), expired()], enabled=enabled)
    assert lifecycle_events(observed) == []
    assert expiry.CAPABILITY not in observed.installation_capabilities()


@pytest.mark.parametrize('damage', ['caps_only', 'foreign_build', 'inbound_disabled'])
def test_expiry_capability_remains_scoped_to_native_inbound_and_b23(tmp_path, damage):
    observed = session(tmp_path, [offer(), expired()])
    path = tmp_path / 'control-probe.jsonl'
    rows = [json.loads(line) for line in path.read_text(encoding='utf-8').splitlines()]
    if damage == 'caps_only':
        rows[0].pop(expiry.CAPABILITY)
        rows[0]['caps'] = [expiry.CAPABILITY]
    elif damage == 'foreign_build':
        observed.record['game_sha256'] = '9ad3efe1af169f40ee577f9dae5debbc87af6fb8b5450fb345ebf110dc4d771a'
    else:
        rows[0]['native_inbound_alliance'] = False
    path.write_text(''.join(json.dumps(row) + '\n' for row in rows), encoding='utf-8')
    assert lifecycle_events(observed) == []
    assert expiry.CAPABILITY not in observed.installation_capabilities()


def test_other_recipient_expiry_is_outside_scope_without_false_gap(tmp_path):
    raw = expired()
    raw['source']['recipient20'] = hex(0x0100000300000000 | int.from_bytes(b'POR', 'little'))
    observed = session(tmp_path, [offer(), raw])
    assert lifecycle_events(observed) == []
    assert observed.read_native_inbound_capture_gaps() == []


def test_inbound_event_poll_does_not_expose_france_to_another_observer(tmp_path):
    observed = session(tmp_path, [offer(), expired()])
    source = DiplomacySource(DiplomacyTools(None, observed), observer='POR')
    assert source.poll_events(source.context(), None)['events'] == []


def test_unsigned_native_token_and_repeated_lines_deduplicate(tmp_path):
    raw = expired(token=-1)
    observed = session(tmp_path, [offer(token=-1), raw, raw])
    first = lifecycle_events(observed)
    assert len(first) == 1
    append(observed, raw)
    assert lifecycle_events(observed) == first


def test_multiple_same_pair_proposals_match_only_exact_token(tmp_path):
    observed = session(tmp_path, [offer(token=19), offer(token=20, native_id=2), expired(token=20)])
    originals = observed.read_native_inbound_offers()
    assert lifecycle_events(observed)[0]['payload']['proposal_id'] == originals[1]['proposal_id']


def test_ambiguous_original_proposals_remain_unmatched(tmp_path):
    observed = session(tmp_path, [offer(), offer(native_id=2), expired()])
    assert lifecycle_events(observed) == []
    assert 'PROPOSAL_EXPIRY_UNMATCHED:1' in observed.read_native_inbound_capture_gaps()


def test_unmatched_buffer_is_bounded_and_does_not_block_correlated_events(tmp_path):
    unknown = [expired(token=100+index, sequence=200+index)
               for index in range(expiry.MAX_PENDING+1)]
    observed = session(tmp_path, unknown)
    assert lifecycle_events(observed) == []
    assert len(observed._inbound_unmatched_expiries) == expiry.MAX_PENDING
    assert len(observed._inbound_expiry_sequences) == expiry.MAX_PENDING
    assert 'PROPOSAL_EXPIRY_BUFFER_FULL' in observed.read_native_inbound_capture_gaps()
    append(observed, offer(), expired())
    assert len(lifecycle_events(observed)) == 1


def test_log_failure_preserves_verified_observations_and_reports_gap(tmp_path):
    observed = session(tmp_path, [offer(), expired()])
    first = lifecycle_events(observed)
    path = tmp_path / 'control-probe.jsonl'
    retained = tmp_path / 'retained.jsonl'
    path.rename(retained)
    # The normal capability reader also needs the ACK, so preserve its admitted value.
    capabilities = observed.installation_capabilities
    original_caps = {'native_inbound_alliance', expiry.CAPABILITY}
    observed.installation_capabilities = lambda: frozenset(original_caps)
    assert lifecycle_events(observed) == first
    assert 'PROPOSAL_LIFECYCLE_LOG_READ_FAILED' in observed.read_native_inbound_capture_gaps()
    retained.rename(path)
    observed.installation_capabilities = capabilities
    assert lifecycle_events(observed) == first
    assert 'PROPOSAL_LIFECYCLE_LOG_READ_FAILED' not in observed.read_native_inbound_capture_gaps()


def test_partial_log_failure_still_bounds_unmatched_observations(tmp_path, monkeypatch):
    unknown = [expired(token=100+index, sequence=200+index)
               for index in range(expiry.MAX_PENDING+1)]
    observed = session(tmp_path, unknown)
    path = tmp_path / 'control-probe.jsonl'
    data = path.read_bytes()
    original_open = Path.open

    class InterruptedReader(io.BytesIO):
        def read(self, size=-1):
            if self.tell() >= len(data):
                raise OSError('synthetic partial log failure')
            return super().read(size)

    def open_file(target, *args, **kwargs):
        if target == path and args == ('rb',):
            return InterruptedReader(data)
        return original_open(target, *args, **kwargs)

    monkeypatch.setattr(observed, 'installation_capabilities',
                        lambda: frozenset({'native_inbound_alliance', expiry.CAPABILITY}))
    with monkeypatch.context() as patch:
        patch.setattr(Path, 'open', open_file)
        assert lifecycle_events(observed) == []
    assert len(observed._inbound_unmatched_expiries) == expiry.MAX_PENDING
    assert 'PROPOSAL_LIFECYCLE_LOG_READ_FAILED' in observed.read_native_inbound_capture_gaps()
    append(observed, offer(), expired())
    assert len(lifecycle_events(observed)) == 1


def test_expiry_before_original_and_partial_line_recover_in_proposal_order(tmp_path):
    observed = session(tmp_path, [expired()])
    assert lifecycle_events(observed) == []
    assert 'PROPOSAL_EXPIRY_UNMATCHED:1' in observed.read_native_inbound_capture_gaps()
    append(observed, offer(), final_newline=False)
    assert lifecycle_events(observed) == []
    with (tmp_path / 'control-probe.jsonl').open('a', encoding='utf-8') as stream:
        stream.write('\n')
    events = observed.read_native_inbound_events()
    assert [row['payload']['observer_status'] for row in events] == ['observed_pending', 'expired']
    assert events[0]['log_offset'] > events[1]['log_offset']
    assert observed.read_native_inbound_capture_gaps() == []


def test_bounded_windows_preserve_unmatched_expiry_until_original(monkeypatch, tmp_path):
    observed = session(tmp_path, [expired(), offer()])
    monkeypatch.setattr('bridge.diplomacy._RESPONSE_LOG_SCAN_BYTES', 1500)
    for _ in range(5):
        events = observed.read_native_inbound_events()
        if len(events) == 2:
            break
    assert len(events) == 2
    assert [row['payload']['observer_status'] for row in events] == ['observed_pending', 'expired']


def test_deferred_expiry_preserves_other_proposal_order_and_source_offsets(tmp_path):
    observed = session(tmp_path, [expired(token=19), offer(token=20, native_id=2),
                                  offer(token=19), expired(token=20, sequence=102)])
    with closing(DurableJournal(tmp_path / 'journal.sqlite3', observed.experiment_id, SESSION)) as journal:
        source = DiplomacySource(DiplomacyTools(journal, observed))
        batch = source.poll_events(source.context(), None)
        events = batch['events']
        assert [row['payload']['observer_status'] for row in events] == [
            'observed_pending', 'observed_pending', 'expired', 'expired']
        assert events[0]['payload']['proposal_id'] == events[3]['payload']['proposal_id']
        assert events[1]['payload']['proposal_id'] == events[2]['payload']['proposal_id']
        assert [row['sequence'] for row in events] == [1, 2, 3, 4]
        originals = observed.read_native_inbound_offers()
        assert events[0]['payload']['proposal_id'] == originals[0]['proposal_id']
        assert source.poll_events(source.context(), batch['cursor'])['events'] == []
        ordered = observed.read_native_inbound_events(refresh=False)
        assert ordered[2]['log_offset'] < ordered[0]['log_offset'] < ordered[1]['log_offset']
        topics = {topic['topic_id']: topic for topic in source.catalog()}
        assert topics['A04']['proposal_lifecycle']['delivery_order'] == 'original_before_terminal'


def test_drop_reports_conflicts_and_replaced_log_remain_explicit(tmp_path):
    observed = session(tmp_path, [offer(), expired(), {'event': 'native_alliance_lifecycle_drop', 'dropped': 2}])
    assert len(lifecycle_events(observed)) == 1
    conflict = expired()
    conflict['observed_game_date_raw'] += 24
    append(observed, conflict)
    assert len(lifecycle_events(observed)) == 1
    gaps = observed.read_native_inbound_capture_gaps()
    assert 'LIFECYCLE_CAPTURE_DROPPED:2' in gaps
    assert 'PROPOSAL_EXPIRY_SEQUENCE_CONFLICT' in gaps
    path = tmp_path / 'control-probe.jsonl'
    previous = path.read_text(encoding='utf-8')
    replacement = tmp_path / 'replacement.jsonl'
    replacement.write_text(previous + '\n', encoding='utf-8')
    replacement.replace(path)
    assert len(lifecycle_events(observed)) == 1
    assert 'PROPOSAL_LIFECYCLE_LOG_RESET' in observed.read_native_inbound_capture_gaps()


def watch(service):
    query = {'topic': 'A04', 'object': {'type': 'session'},
             'fields': ['proposal_id', 'proposal_status', 'currently_pending'], 'parameters': {}}
    report = service.manage_report('recovery-report', 'create', config={
        'name': 'proposal lifecycle recovery', 'queries': [query], 'detail': 'full',
    })['report']
    service.manage_subscription('recovery-subscribe', 'create', config={
        'name': 'proposal lifecycle recovery', 'kind': 'event', 'report_id': report['id'],
        'enabled': True, 'event': {'types': ['diplomatic_proposal'], 'recipients': ['FRA']},
    })


@pytest.mark.parametrize('terminal_logged_first', [False, True])
def test_batch_persistence_failure_keeps_source_cursor_and_retries_once(tmp_path, monkeypatch,
                                                                       terminal_logged_first):
    rows = [expired(), offer()] if terminal_logged_first else [offer(), expired()]
    observed = session(tmp_path, rows)
    with closing(DurableJournal(tmp_path / 'journal.sqlite3', observed.experiment_id, SESSION)) as journal:
        source = DiplomacySource(DiplomacyTools(journal, observed))
        with closing(InformationService(source, tmp_path / 'information.sqlite3')) as service:
            watch(service)
            original = service._stage_event_data

            def fail_stage(*args):
                raise OSError('synthetic event batch persistence failure')

            monkeypatch.setattr(service, '_stage_event_data', fail_stage)
            assert service.tick()['results'] == []
            assert service._runtime('event-source').get('cursor') is None
            monkeypatch.setattr(service, '_stage_event_data', original)
            results = service.tick()['results']
            assert len(results) == 2
            assert results[-1]['items'][0]['fields']['proposal_status']['value'] == 'expired'
            assert service.tick()['results'] == []


@pytest.mark.parametrize('terminal_logged_first', [False, True])
@pytest.mark.parametrize('interrupted_status', ['observed_pending', 'expired'])
def test_interrupted_projection_reopens_from_durable_snapshot(tmp_path, monkeypatch,
                                                            terminal_logged_first, interrupted_status):
    rows = [expired(), offer()] if terminal_logged_first else [offer(), expired()]
    observed = session(tmp_path, rows)
    observed.record['world_id'] = 'synthetic-expiry-world'
    with closing(DurableJournal(tmp_path / 'journal.sqlite3', observed.experiment_id, SESSION)) as journal:
        source = DiplomacySource(DiplomacyTools(journal, observed))
        database = tmp_path / 'information.sqlite3'
        with closing(InformationService(source, database)) as service:
            watch(service)
            original = service._event_store_projection

            def fail_projection(job, result):
                if job['event']['payload'].get('observer_status') == interrupted_status:
                    raise OSError('synthetic lifecycle projection interruption')
                return original(job, result)

            monkeypatch.setattr(service, '_event_store_projection', fail_projection)
            assert len(service.tick()['results']) == (1 if interrupted_status == 'expired' else 0)
        monkeypatch.setattr(source, 'poll_events', lambda *_: pytest.fail('recovery repolled source'))
        monkeypatch.setattr(observed, 'read_native_alliance_inbound_offers', lambda: pytest.fail('recovery read log'))
        with closing(InformationService(source, database)) as reopened:
            results = reopened.tick()['results']
            expected = ['expired'] if interrupted_status == 'expired' else ['observed_pending', 'expired']
            assert [row['items'][0]['fields']['proposal_status']['value'] for row in results] == expected
            assert results[-1]['items'][0]['fields']['currently_pending']['value'] is False


@pytest.mark.parametrize('terminal_logged_first', [False, True])
def test_normal_event_delivery_retains_original_id_snapshot_and_reopen(tmp_path, monkeypatch,
                                                                    terminal_logged_first):
    rows = [expired(), offer()] if terminal_logged_first else [offer(), expired()]
    observed = session(tmp_path, rows)
    with closing(DurableJournal(tmp_path / 'journal.sqlite3', observed.experiment_id, SESSION)) as journal:
        source = DiplomacySource(DiplomacyTools(journal, observed))
        query = {'topic': 'A04', 'object': {'type': 'session'},
                 'fields': ['proposal_id', 'action_id', 'proposal_status', 'currently_pending', 'parameters'],
                 'parameters': {}}
        database = tmp_path / 'information.sqlite3'
        with closing(InformationService(source, database)) as service:
            tools = InformationTools(service)
            report = tools.call('information_manage_report', {
                'request_id': 'expiry-report', 'operation': 'create',
                'config': {'name': 'proposal lifecycle', 'queries': [query], 'detail': 'full'},
            })['report']
            tools.call('information_manage_subscription', {
                'request_id': 'expiry-subscribe', 'operation': 'create', 'config': {
                    'name': 'proposal lifecycle', 'kind': 'event', 'report_id': report['id'],
                    'enabled': True, 'event': {'types': ['diplomatic_proposal'], 'recipients': ['FRA']},
                },
            })
            results = tools.call('information_tick', {})['results']
            assert len(results) == 2
            initial, terminal = [service.get_result(row['result_id']) for row in results]
            first_id = initial['items'][0]['fields']['proposal_id']['value']
            fields = terminal['items'][0]['fields']
            assert fields['proposal_id']['value'] == first_id
            assert fields['proposal_status']['value'] == 'expired'
            assert fields['currently_pending']['value'] is False
            assert fields['currently_pending']['period'] == 'observed'
            assert terminal['event']['game_date'] == NOW
            assert tools.call('information_tick', {})['results'] == []
            context = source.context()
            monkeypatch.setattr(observed, 'read_native_inbound_events', lambda **kwargs: pytest.fail('replay read log'))
            replayed = source.replay_event(query, context, terminal['event'])
            assert replayed['fields']['proposal_status']['value'] == 'expired'
            wrong = deepcopy(terminal['event'])
            wrong['payload']['recipient'] = 'POR'
            assert not source.replay_event(query, context, wrong)['complete']
            retained_id = terminal['result_id']
        with closing(InformationService(source, database)) as reopened:
            assert reopened.get_result(retained_id)['items'] == terminal['items']
