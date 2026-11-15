"""Proposal queue-removal observations delivered through normal consumers."""
from contextlib import closing
from copy import deepcopy
import json
import pytest

from bridge.diplomacy import DiplomacyTools
from bridge.diplomacy_journal import DurableJournal
from bridge.information import InformationService
from bridge.information.sources import DiplomacySource
from bridge.information.tools import InformationTools
from bridge import proposal_expiry as expiry
from bridge.tests.test_information_proposal_expiry import (
    NOW, SESSION, append, expired, offer, session,
)


def inactivated(*, token=19, sequence=101, return_rva=expiry.INACTIVE_RETURN_RVA):
    event = expired(token=token, sequence=sequence)
    event['caller_return_rva'] = return_rva
    return event


def _query(proposal_id=None):
    parameters = {} if proposal_id is None else {'proposal_id': proposal_id}
    return {
        'topic': 'A04',
        'object': {'type': 'session'},
        'fields': ['proposal_id', 'proposal_status', 'currently_pending'],
        'parameters': parameters,
    }


def _c04_query():
    return {
        'topic': 'C04', 'object': {'type': 'session'},
        'fields': ['event_id', 'event_type', 'event_date', 'event_payload', 'complete'],
        'parameters': {},
    }


@pytest.mark.parametrize('return_rva,state', [
    (expiry.INACTIVE_RETURN_RVA, 0),
    (expiry.RECHECK_RETURN_RVA, 0),
    (expiry.RECHECK_RETURN_RVA, 1),
    (expiry.RECHECK_RETURN_RVA, -1),
    (expiry.RECHECK_RETURN_RVA, 2**31 - 1),
    (expiry.CLEAR_RETURN_RVA, 0),
    (expiry.CLEAR_RETURN_RVA, 1),
    (expiry.CLEAR_RETURN_RVA, -1),
    (expiry.CLEAR_RETURN_RVA, 2**31 - 1),
])
def test_inactivation_before_offer_reaches_a04_subscription_and_reopens(tmp_path, return_rva, state):
    observed = session(tmp_path)
    removal = inactivated(return_rva=return_rva)
    removal['source']['state34'] = state
    with (tmp_path / 'control-probe.jsonl').open('a', encoding='utf-8') as stream:
        stream.write(json.dumps(removal, separators=(',', ':')) + '\n')
    database = tmp_path / 'information.sqlite3'
    with closing(DurableJournal(tmp_path / 'journal.sqlite3', observed.experiment_id, SESSION)) as journal:
        source = DiplomacySource(DiplomacyTools(journal, observed))
        with closing(InformationService(source, database)) as service:
            tools = InformationTools(service)
            report = tools.call('information_manage_report', {
                'request_id': 'inactive-report', 'operation': 'create',
                'config': {'name': 'proposal inactivation', 'detail': 'full',
                           'queries': [_query(), _c04_query()]},
            })['report']
            tools.call('information_manage_subscription', {
                'request_id': 'inactive-subscribe', 'operation': 'create', 'config': {
                    'name': 'proposal inactivation', 'kind': 'event', 'enabled': True,
                    'report_id': report['id'], 'event': {'types': ['diplomatic_proposal'], 'recipients': ['FRA']},
                },
            })

            assert service.tick()['results'] == []
            append(observed, offer(), final_newline=False)
            assert service.tick()['results'] == []
            with (tmp_path / 'control-probe.jsonl').open('a', encoding='utf-8') as stream:
                stream.write('\n')

            delivered = service.tick()['results']
            assert len(delivered) == 2
            original, terminal = delivered
            original_fields = original['items'][0]['fields']
            terminal_fields = terminal['items'][0]['fields']
            proposal_id = original_fields['proposal_id']['value']
            assert original_fields['proposal_status']['value'] == 'observed_pending'
            assert terminal_fields['proposal_id']['value'] == proposal_id
            assert terminal_fields['proposal_status']['value'] == 'inactive'
            assert terminal_fields['currently_pending']['value'] is False
            assert terminal_fields['currently_pending']['period'] == 'observed'
            lifecycle = terminal['event']['payload']['lifecycle']
            assert lifecycle == {
                'kind': 'inactive', 'game_date_raw': NOW,
                'created_game_date_raw': NOW - 96,
                'basis': 'native_pending_queue_removal',
            }
            for result in delivered:
                c04 = result['items'][1]['fields']
                event = result['event']
                assert c04['event_id']['value'] == event['event_id']
                assert c04['event_type']['value'] == 'diplomatic_proposal'
                if event['game_date'] is None:
                    assert c04['event_date']['status'] == 'unknown'
                else:
                    assert c04['event_date']['value'] == event['game_date']
                assert c04['event_payload']['value'] == event['payload']
                assert c04['complete']['value'] == event['complete']
                replayed = source.replay_event(_c04_query(), source.context(), event)
                assert replayed['fields'] == c04

            current = tools.call('information_query', {
                'request_id': 'inactive-current-query', 'queries': [_query(proposal_id)], 'view': 'full',
            })['items'][0]['fields']
            assert current['proposal_status']['value'] == 'inactive'
            assert current['currently_pending']['value'] is False
            assert service.tick()['results'] == []
            retained_result_id = terminal['result_id']
            retained_items = terminal['items']

        new_observed = type(observed)(tmp_path / 'installation.json', tmp_path / 'unused.exe')
        new_source = DiplomacySource(DiplomacyTools(journal, new_observed))
        with closing(InformationService(new_source, database)) as reopened:
            assert reopened.get_result(retained_result_id)['items'] == retained_items
            assert reopened.tick()['results'] == []
            assert new_observed.find_native_alliance_inbound_offer(proposal_id)['observer_status'] == 'inactive'


@pytest.mark.parametrize('method', ['read_event', 'replay_event'])
@pytest.mark.parametrize('damage', [
    'session', 'observer', 'recipient', 'proposal_id', 'payload',
    'lifecycle', 'date', 'date_type', 'request_id', 'case', 'event_type',
])
def test_c04_proposal_snapshots_reject_scope_or_terminal_corruption(tmp_path, method, damage):
    observed = session(tmp_path, [offer(), inactivated()])
    with closing(DurableJournal(tmp_path / 'journal.sqlite3', observed.experiment_id, SESSION)) as journal:
        source = DiplomacySource(DiplomacyTools(journal, observed))
        event = deepcopy(source.poll_events(source.context(), None)['events'][1])
        query = _c04_query()
        if damage in {'session', 'observer'}:
            event['session_id' if damage == 'session' else 'observer'] = 'other'
        elif damage in {'recipient', 'proposal_id'}:
            event['payload'][damage] = ''
        elif damage == 'payload':
            event['payload'] = []
        elif damage == 'lifecycle':
            event['payload']['lifecycle']['basis'] = 'unknown'
        elif damage == 'date':
            event['game_date'] += 24
        elif damage == 'date_type':
            event['game_date'] = float(event['game_date'])
        else:
            query['parameters'][damage] = 'different'
        result = getattr(source, method)(query, source.context(), event)
        assert not result['complete']
        assert all(field == {'status': 'unavailable', 'reason': 'EVENT_PROPOSAL_SCOPE_MISMATCH'}
                   for field in result['fields'].values())


@pytest.mark.parametrize('ending', [inactivated, expired], ids=['inactive', 'expired'])
@pytest.mark.parametrize('interrupt_original', [False, True])
def test_c04_proposal_projection_recovers_from_durable_snapshot_without_reads(
        tmp_path, monkeypatch, ending, interrupt_original):
    observed = session(tmp_path, [offer(), ending()])
    observed.record['world_id'] = 'synthetic-c04-proposal-world'
    database = tmp_path / 'information.sqlite3'
    with closing(DurableJournal(tmp_path / 'journal.sqlite3', observed.experiment_id, SESSION)) as journal:
        source = DiplomacySource(DiplomacyTools(journal, observed))
        with closing(InformationService(source, database)) as service:
            report = service.manage_report('c04-recovery-report', 'create', config={
                'name': 'C04 proposal recovery', 'detail': 'full', 'queries': [_c04_query()],
            })['report']
            service.manage_subscription('c04-recovery-subscribe', 'create', config={
                'name': 'C04 proposal recovery', 'kind': 'event', 'enabled': True,
                'report_id': report['id'], 'event': {'types': ['diplomatic_proposal']},
            })
            original = service._event_store_projection

            def interrupted(job, result):
                is_original = job['event']['payload']['observer_status'] == 'observed_pending'
                if is_original == interrupt_original:
                    raise OSError('synthetic C04 proposal projection interruption')
                return original(job, result)

            monkeypatch.setattr(service, '_event_store_projection', interrupted)
            assert len(service.tick()['results']) == (0 if interrupt_original else 1)
        monkeypatch.setattr(source, 'poll_events', lambda *_: pytest.fail('recovery repolled source'))
        monkeypatch.setattr(observed, 'read_native_alliance_inbound_offers',
                            lambda: pytest.fail('recovery reread native log'))
        monkeypatch.setattr(observed, 'read_native_inbound_events',
                            lambda **_: pytest.fail('recovery reread native events'))
        with closing(InformationService(source, database)) as reopened:
            results = reopened.tick()['results']
            assert len(results) == (2 if interrupt_original else 1)
            for result in results:
                fields = result['items'][0]['fields']
                assert fields['event_payload']['value'] == result['event']['payload']
                assert fields['event_id']['value'] == result['event']['event_id']
                assert result['items'][0]['source']['projection'] == 'event_snapshot'
            terminal = results[-1]['items'][0]['fields']['event_payload']['value']
            assert terminal['observer_status'] == ('inactive' if ending is inactivated else 'expired')
            assert terminal['currently_pending'] is False


def test_wrong_source_and_unmatched_inactivation_leave_offer_pending(tmp_path):
    wrong_source = inactivated(sequence=101)
    wrong_source['caller_return_rva'] = '0xdeadbeef'
    mismatched = inactivated(token=20, sequence=102)
    mismatched['source']['proposal3c'] = 20

    observed = session(tmp_path, [offer(), wrong_source, mismatched])
    proposals = observed.read_native_alliance_inbound_offers()
    events = observed.read_native_inbound_events(refresh=False)

    assert len(proposals) == 1
    assert proposals[0]['observer_status'] == 'observed_pending'
    assert proposals[0].get('lifecycle') is None
    assert [row['payload']['observer_status'] for row in events] == ['observed_pending']
    assert expiry.validate_inactivation(wrong_source, SESSION) is None


def test_existing_expiry_return_still_projects_expired(tmp_path):
    observed = session(tmp_path, [offer(), expired()])

    proposal = observed.read_native_alliance_inbound_offers()[0]
    events = observed.read_native_inbound_events(refresh=False)
    terminal = [row['payload'] for row in events if row['payload'].get('observer_status') == 'expired']

    assert proposal['observer_status'] == 'expired'
    assert len(terminal) == 1
    assert terminal[0]['lifecycle']['kind'] == 'expired'
    assert terminal[0]['lifecycle']['basis'] == 'native_pending_expiry_branch'


def test_bulk_clear_keeps_distinct_proposals_and_unmatched_records(tmp_path):
    first = inactivated(token=19, sequence=101, return_rva=expiry.CLEAR_RETURN_RVA)
    second = inactivated(token=20, sequence=102, return_rva=expiry.CLEAR_RETURN_RVA)
    second['source']['state34'] = 1
    observed = session(tmp_path, [
        offer(token=19, native_id=1), offer(token=20, native_id=2), offer(token=21, native_id=3),
        first, second,
    ])
    proposals = observed.read_native_inbound_offers()
    assert len(proposals) == 3
    assert sorted(row['observer_status'] for row in proposals) == [
        'inactive', 'inactive', 'observed_pending']
    events = observed.read_native_inbound_events(refresh=False)
    assert len(events) == 5
    ends = [row['payload'] for row in events if row['payload']['observer_status'] == 'inactive']
    assert len({row['proposal_id'] for row in ends}) == 2
    assert all(row['lifecycle']['game_date_raw'] == NOW for row in ends)
    append(observed, first, second)
    assert len(observed.read_native_inbound_events()) == 5


@pytest.mark.parametrize('return_rva', expiry.INACTIVE_RETURN_RVAS)
def test_queue_removal_can_end_a_proposal_before_its_expiry_deadline(tmp_path, return_rva):
    original = offer()
    original.update(date28=NOW, date2c=NOW, created2c=NOW)
    removal = inactivated(return_rva=return_rva)
    removal['source'].update(date28=NOW, date2c=NOW)
    observed = session(tmp_path, [original, removal])

    assert expiry.validate_inactivation(removal, SESSION) is not None
    assert observed.read_native_inbound_offers()[0]['observer_status'] == 'inactive'


@pytest.mark.parametrize('removal_first', [False, True])
@pytest.mark.parametrize('return_rva,state', [
    (expiry.INACTIVE_RETURN_RVA, 0),
    (expiry.RECHECK_RETURN_RVA, 0),
    (expiry.RECHECK_RETURN_RVA, 1),
    (expiry.CLEAR_RETURN_RVA, 0),
    (expiry.CLEAR_RETURN_RVA, 1),
])
def test_classified_expiry_takes_precedence_over_later_copy_cleanup(tmp_path, removal_first, return_rva, state):
    removal = inactivated(sequence=102, return_rva=return_rva)
    removal['source']['state34'] = state
    removal['observed_game_date_raw'] = NOW + 24
    ends = [removal, expired()] if removal_first else [expired(), removal]
    observed = session(tmp_path, [offer(), *ends])
    assert observed.read_native_inbound_offers()[0]['observer_status'] == 'expired'
    assert [row['payload']['observer_status'] for row in observed.read_native_inbound_events()] == [
        'observed_pending', 'expired']


@pytest.mark.parametrize('state', [True, '1', None, -(2**31)-1, 2**31])
def test_recheck_state_requires_a_native_signed_integer(state):
    event = inactivated(return_rva=expiry.RECHECK_RETURN_RVA)
    event['source']['state34'] = state
    assert expiry.validate_inactivation(event, SESSION) is None


@pytest.mark.parametrize('state', [-1, 1, 2**31-1])
def test_nonzero_state_acceptance_is_scoped_to_the_recheck_return(state):
    event = inactivated()
    event['source']['state34'] = state
    assert expiry.validate_inactivation(event, SESSION) is None
    event['caller_return_rva'] = expiry.EXPIRY_RETURN_RVA
    assert expiry.validate_expiry(event, SESSION) is None
