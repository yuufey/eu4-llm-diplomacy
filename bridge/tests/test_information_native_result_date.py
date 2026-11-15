"""Verified native result dates survive delayed collection and durable replay."""
from contextlib import closing, contextmanager
from copy import deepcopy
import json
from pathlib import Path
import subprocess
from types import SimpleNamespace

import pytest

from bridge import native_result_date as dates
from bridge.diplomacy import DiplomacyTools, ObserverSession
from bridge.diplomacy_journal import DurableJournal
from bridge.information import InformationService
from bridge.information.sources import DiplomacySource
from bridge.information.tools import InformationTools
from bridge.tests.test_information_native_results import ArchivedSession, result_query
from bridge.tests.test_information_peace_handler_return import handler_fixture
from bridge.tests.test_peace_inbound_tools import inbound_submission
from bridge.tests.test_peace_execution import WAR_ID, money_parameters


OFFER_DATE, RESULT_DATE, COLLECTION_DATE = 56566512, 56566584, 56566824


def dated_result():
    result = {'request_id': 'dated-request', 'action_id': 'offer_alliance', 'actor': 'FRA',
              'recipient': 'SAV', 'phase': 'initiate', 'native_outcome': 'accepted',
              'date_raw': OFFER_DATE}
    event = {'native_result_game_date_raw': RESULT_DATE, 'native_result_game_date_verified': True,
             'native_result_date_basis': dates.BASIS}
    return event, result


@pytest.mark.parametrize('damage', [
    {'native_result_game_date_verified': False}, {'native_result_game_date_verified': 1},
    {'native_result_game_date_verified': 'true'}, {'native_result_game_date_raw': True},
    {'native_result_game_date_raw': 0}, {'native_result_game_date_raw': -1},
    {'native_result_game_date_raw': 2**31}, {'native_result_game_date_raw': OFFER_DATE-1},
    {'native_result_date_basis': 'collected_game_date'}, {'native_result_date_basis': None},
])
def test_bad_clock_metadata_keeps_the_valid_business_result(damage):
    event, result = dated_result()
    original = deepcopy(result)
    assert dates.attach(dict(event, **damage), result, enabled=True) is result
    assert result == original


@pytest.mark.parametrize('enabled', [False, 1, 'true', None])
def test_date_admission_requires_literal_enabled_flag(enabled):
    event, result = dated_result()
    assert dates.attach(event, result, enabled=enabled) is result


@pytest.mark.parametrize('outcome', ['unknown', 'invalidated', 'pending'])
def test_date_does_not_promote_an_unconfirmed_result(outcome):
    event, result = dated_result()
    result['native_outcome'] = outcome
    assert dates.attach(event, result, enabled=True) is result


def record_with_date():
    event, result = dated_result()
    return SimpleNamespace(request_id=result['request_id'], status='accepted', submitted_at='synthetic',
                           payload={key: result[key] for key in ('action_id', 'actor', 'recipient', 'phase')},
                           result=dates.attach(event, result, enabled=True))


@pytest.mark.parametrize('damage', ['status', 'submission', 'request', 'actor', 'phase', 'unit', 'basis', 'date'])
def test_stored_dates_require_the_matching_terminal_snapshot(damage):
    record = record_with_date()
    assert dates.for_record(record) == RESULT_DATE
    if damage == 'status':
        record.status = 'submitted'
    elif damage == 'submission':
        record.submitted_at = None
    elif damage == 'request':
        record.request_id = 'another-request'
    elif damage in ('actor', 'phase'):
        record.payload[damage] = 'other'
    elif damage in ('unit', 'basis'):
        record.result['native_result_date'][damage] = 'other'
    else:
        record.result['native_result_date']['game_date_raw'] = True
    assert dates.for_record(record) is None


def test_legacy_default_initiate_phase_and_original_values_are_preserved():
    event, result = dated_result()
    before = deepcopy(result)
    record = record_with_date()
    del record.payload['phase']
    assert dates.for_record(record) == RESULT_DATE
    assert dates.attach(event, result, enabled=True)['date_raw'] == OFFER_DATE
    assert result == before


@pytest.mark.parametrize('mode,known', [
    ('accept', True), ('reject', True), ('fallback', True), ('date_changed', False),
    ('world_changed', False), ('game_failure', False), ('date_failure', False), ('deferred', False),
    ('flush_later', True), ('tight_buffer', False), ('line_budget', False),
])
def test_production_native_date_capture_and_bounded_formatter(handler_fixture, mode, known):
    ran = subprocess.run([str(handler_fixture), mode], capture_output=True, text=True, timeout=10)
    assert ran.returncode == 0, ran.stderr
    event = json.loads(ran.stdout.splitlines()[0])
    assert ('native_result_game_date_raw' in event) is known
    if known:
        assert event['native_result_game_date_raw'] == RESULT_DATE
        assert event['native_result_game_date_verified'] is True
        assert event['native_result_date_basis'] == dates.BASIS
    assert event['outcome'] in ('accepted', 'rejected')
    if mode == 'line_budget':
        assert len(ran.stdout.splitlines()[0].encode()) <= 256*1024
        assert len(event['padding']) > 250*1024


@pytest.fixture
def callback_backend(tmp_path, handler_fixture, monkeypatch):
    @contextmanager
    def create(mode='accept', enabled=True, *, caps_only=False, game_sha=dates.GAME_SHA256):
        ran = subprocess.run([str(handler_fixture), mode], capture_output=True, text=True, timeout=10)
        assert ran.returncode == 0, ran.stderr
        event = json.loads(ran.stdout.splitlines()[0])
        ack = {'event': 'diplomacy_observer_installed', 'session_id': event['session_id'],
               'version': 41, 'native_inbound_alliance': True}
        ack['capabilities'] = [dates.CAPABILITY]
        if not caps_only:
            ack[dates.CAPABILITY] = enabled
        fixture = {'source': {'session_id': event['session_id'], 'dll_sha256': 'a' * 64}}
        session = ArchivedSession(tmp_path, fixture)
        session.record.update(world_id='synthetic-result-date-world', game_sha256=game_sha)
        monkeypatch.setattr(session, 'health', lambda: {
            'status': 'ready', 'date_raw': COLLECTION_DATE, 'complete': True, 'reasons': []})
        submission = inbound_submission(request_id=event['request_id'], session_id=session.session_id,
                                       phase=event['phase'], date_raw=event['date_raw'])
        (tmp_path / 'control-probe.jsonl').write_text(
            ''.join(json.dumps(row) + '\n' for row in (ack, submission, event)), encoding='utf-8')
        assert (dates.CAPABILITY in session.installation_capabilities()) is (
            enabled is True and not caps_only and game_sha == dates.GAME_SHA256)
        with closing(DurableJournal(tmp_path / 'journal.sqlite3', session.experiment_id, session.session_id)) as journal:
            request_id = event['request_id']
            journal.register(request_id, {
                'action_id': 'peace_offer', 'actor': 'ENG', 'recipient': 'FRA', 'phase': event['phase'],
                'parameters': {'proposal_id': 'a' * 32}})
            for status in ('queued', 'consumed', 'constructed'):
                journal.transition(request_id, status)
            claim = journal.claim_submission(request_id)
            receipt = ObserverSession._public_native_inbound_submission_receipt(
                submission, request_id, 'ENG', event['phase'], event['date_raw'], 'peace_offer')
            journal.mark_submitted(request_id, claim.claim_token, receipt)
            yield DiplomacyTools(journal, session), request_id, event
    return create


@pytest.mark.parametrize('enabled', [False, 1, 'true'])
def test_capability_rejects_nonliteral_ack_and_copied_capability_list(callback_backend, enabled):
    with callback_backend(enabled=enabled) as (backend, _request_id, _event):
        assert dates.CAPABILITY not in backend.session.installation_capabilities()


@pytest.mark.parametrize('caps_only,game_sha', [(True, dates.GAME_SHA256), (False, 'f' * 64)])
def test_result_date_capability_is_bound_to_top_level_ack_and_fixed_build(callback_backend, caps_only, game_sha):
    with callback_backend(caps_only=caps_only, game_sha=game_sha) as (backend, _request_id, _event):
        assert dates.CAPABILITY not in backend.session.installation_capabilities()


@pytest.mark.parametrize('gateway', ['alliance', 'peace', 'declare_war'])
def test_other_native_readers_preserve_synthetic_dates_and_binding_dates(tmp_path, gateway):
    session_id = 'synthetic-date-reader'
    session = ArchivedSession(tmp_path, {'source': {'session_id': session_id, 'dll_sha256': 'a' * 64}})
    if gateway == 'alliance':
        event = {'event': 'native_alliance_response_result', 'request_id': 'date-alliance',
                 'session_id': session_id, 'action_id': 'offer_alliance', 'actor': 'FRA',
                 'recipient': 'SAV', 'phase': 'initiate', 'date_raw': OFFER_DATE,
                 'native_state': 2, 'alliance_after': True, 'response_verified': True,
                 'request_binding_verified': True}
        reader = session.read_native_alliance_response
        args = (event['request_id'], 'FRA', 'SAV', 'initiate', OFFER_DATE)
    elif gateway == 'peace':
        event = {'event': 'native_peace_execution_result', 'family': 'peace',
                 'session_id': session_id, 'request_id': 'date-peace', 'action_id': 'demand_ducats',
                 'actor': 'FRA', 'recipient': 'ENG', 'phase': 'initiate', 'date_raw': OFFER_DATE,
                 'war_id': WAR_ID, 'direction': 'demand', 'amount_raw': 10000, 'province_ids': [],
                 'beneficiary': '-', 'native_state': 0, 'outcome': 'executed', 'war_before': True,
                 'war_after': False, 'response_verified': True, 'request_binding_verified': True,
                 'execution_verified': True, 'terms_verified': False}
        reader = session.read_native_peace_execution
        args = (event['request_id'], 'FRA', 'ENG', 'initiate', OFFER_DATE, 'demand_ducats', money_parameters())
    else:
        fixture = json.loads((Path(__file__).parent / 'fixtures/declare_war_r63_execution_real.json').read_text())
        event = dict(fixture['execution'], session_id=session_id)
        reader = session.read_native_declare_war_execution
        args = (event['request_id'], fixture['actor'], fixture['recipient'], fixture['phase'],
                fixture['date_raw'], fixture['parameters'])
    event.update(native_result_game_date_raw=event['date_raw']+72,
                 native_result_game_date_verified=True, native_result_date_basis=dates.BASIS)
    ack = {'event': 'diplomacy_observer_installed', 'session_id': session_id, 'version': 41,
           'native_inbound_alliance': True, dates.CAPABILITY: True}
    (tmp_path / 'control-probe.jsonl').write_text(
        json.dumps(ack)+'\n'+json.dumps(event)+'\n', encoding='utf-8')
    response = reader(*args)
    assert response['status'] in ('accepted', 'executed')
    assert response['result']['date_raw'] == event['date_raw']
    assert response['result']['native_result_date']['game_date_raw'] == event['date_raw']+72


def watch(service, request_id):
    query = result_query(request_id)
    query['parameters'] = {}
    report = service.manage_report('date-report', 'create', config={
        'name': 'native result date', 'queries': [query], 'detail': 'full'})['report']
    service.manage_subscription('date-subscription', 'create', config={
        'name': 'native result date', 'kind': 'event', 'report_id': report['id'], 'enabled': True,
        'event': {'types': ['diplomatic_request_result']}})


@pytest.mark.parametrize('mode,enabled,expected', [
    ('accept', True, RESULT_DATE), ('reject', True, RESULT_DATE), ('accept', False, None),
    ('deferred', True, None), ('date_changed', True, None), ('date_failure', True, None),
])
def test_delayed_collection_and_durable_replay_use_callback_date(
        callback_backend, tmp_path, monkeypatch, mode, enabled, expected):
    with callback_backend(mode, enabled) as (backend, request_id, _event):
        source = DiplomacySource(backend)
        topic = next(row for row in source.catalog() if row['topic_id'] == 'A05')
        assert topic['result_date']['capture_available'] is enabled
        database = tmp_path / 'information.sqlite3'
        with closing(InformationService(source, database)) as service:
            watch(service, request_id)
            delivered = InformationTools(service).call('information_tick', {"view": "full"})['results']
            assert len(delivered) == 1
            event = delivered[0]['event']
            assert event['game_date'] == expected
            assert event['collected_game_date'] == COLLECTION_DATE
            assert event['source']['date_semantics'] == (
                'native_executor_result_date' if expected is not None else 'response_time_unknown')
            result = delivered[0]['items'][0]['fields']['result']['value']
            assert result['date_raw'] == OFFER_DATE
            assert ('native_result_date' in result) is (expected is not None)
            assert InformationTools(service).call('information_tick', {"view": "full"})['results'] == []
            context = source.context()
            monkeypatch.setattr(backend, 'get_diplomatic_result', lambda *_: pytest.fail('replay read native source'))
            replay = source.replay_event(result_query(request_id), context, event)
            assert replay['fields'] == delivered[0]['items'][0]['fields']
            result_id = delivered[0]['result_id']
        with closing(InformationService(source, database)) as reopened:
            assert reopened.get_result(result_id)['event'] == event


def test_journal_failure_retry_preserves_callback_date_without_reconsuming_source(callback_backend, monkeypatch):
    with callback_backend() as (backend, request_id, _event):
        source = DiplomacySource(backend)
        original = backend.journal.mark_accepted

        def fail(*args, **kwargs):
            raise OSError('synthetic persistence failure')

        monkeypatch.setattr(backend.journal, 'mark_accepted', fail)
        first = source.poll_events(source.context(), None)
        assert not first['complete']
        monkeypatch.setattr(backend.journal, 'mark_accepted', original)
        recovered = source.poll_events(source.context(), first['cursor'])
        event = next(row for row in recovered['events'] if row['event_type'] == 'diplomatic_request_result')
        assert event['game_date'] == RESULT_DATE
        assert backend.session.read_count == 1
        assert dates.for_record(backend.journal.lookup_request(request_id)) == RESULT_DATE
