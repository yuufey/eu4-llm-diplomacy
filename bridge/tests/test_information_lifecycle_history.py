"""Recorded lifecycle pages and expiry-only event delivery reuse the shared ledger."""
from contextlib import ExitStack, closing
from copy import deepcopy
import json
from pathlib import Path

import pytest

from bridge.diplomacy import DiplomacyTools
from bridge.diplomacy_journal import DurableJournal
from bridge.information.composite import CompositeSource
from bridge.information.model import InformationError, canonical, digest
from bridge.information.proposal_expiry_history import NativeProposalExpiryHistorySource
from bridge.information.modifier_lifecycle_history import NativeModifierLifecycleHistorySource
from bridge.information.service import InformationService
from bridge.information.sources import DiplomacySource
from bridge.information.tools import InformationTools
from bridge.tests import test_information_proposal_expiry as fixture


def query(obj=None, parameters=None):
    return {'topic': 'H02', 'object': obj or {'type': 'session'},
            'fields': ['proposal_expiry'], 'parameters': parameters or {}}


def setup(tmp_path, stack, events=None, database=None):
    observed = fixture.session(tmp_path, events if events is not None else [fixture.offer(), fixture.expired()])
    observed.record['world_id'] = 'lifecycle-history-world'
    journal = stack.enter_context(closing(DurableJournal(tmp_path / 'journal.sqlite3', observed.experiment_id, fixture.SESSION)))
    base = DiplomacySource(DiplomacyTools(journal, observed))
    adapter = NativeProposalExpiryHistorySource(base)
    service = stack.enter_context(closing(InformationService(
        CompositeSource(base, [adapter]), database or tmp_path / 'information.sqlite3')))
    adapter.history_reader = service.observed_events
    return base, adapter, service


def subscribe(service, suffix='expiry', statuses=None):
    report = service.manage_report('report-' + suffix, 'create', config={
        'name': 'proposal expiry history', 'detail': 'full', 'queries': [query()]})['report']
    event = {'types': ['diplomatic_proposal']}
    if statuses is not None:
        event['proposal_statuses'] = statuses
    return service.manage_subscription('sub-' + suffix, 'create', config={
        'kind': 'event', 'report_id': report['id'], 'event': event})['subscription']


def test_expiry_only_event_matches_query_and_survives_cold_reopen(tmp_path):
    database = tmp_path / 'information.sqlite3'
    with ExitStack() as stack:
        base, adapter, service = setup(tmp_path, stack, database=database)
        api = InformationTools(service)
        assert api.call('information_query', {'request_id': 'empty-history', 'queries': [query()]})['items'][0]['proposal_expiry'] == []
        sub = subscribe(service, statuses=['expired'])
        results = service.tick()['results']
        assert len(results) == 1
        event_result = api.call('information_get_result', {'result_id': results[0]['result_id']})
        row = event_result['items'][0]['proposal_expiry'][0]
        assert row['actor'] == 'SAV' and row['recipient'] == 'FRA'
        assert row['action_id'] == 'offer_alliance' and row['event_date']
        assert 'payload' not in event_result['event']
        history = api.call('information_query', {'request_id': 'read-history', 'queries': [query()]})
        assert history['items'][0]['proposal_expiry'] == [row]
        selected = api.call('information_query', {'request_id': 'read-pair-history', 'queries': [query(
            {'type': 'country_pair', 'actor': 'SAV', 'recipient': 'FRA'})]})
        assert selected['items'][0]['proposal_expiry'] == [row]
        assert service.tick()['results'] == []
        service.manage_subscription('cancel-expiry', 'cancel', subscription_id=sub['id'], expected_version=1)
    with ExitStack() as stack:
        _, _, service = setup(tmp_path, stack, events=[], database=database)
        api = InformationTools(service)
        assert api.call('information_get_result', {'result_id': history['result_id']}) == history
        current = api.call('information_query', {'request_id': 'reopened-history', 'queries': [query()]})
        assert current['items'] == history['items']


def test_replay_uses_expiry_snapshot_and_rejects_missing_lifecycle(tmp_path, monkeypatch):
    with ExitStack() as stack:
        base, adapter, service = setup(tmp_path, stack)
        subscribe(service, statuses=['expired'])
        result = service.tick()['results'][0]
        event = result['event']
        monkeypatch.setattr(base, 'read', lambda *args: pytest.fail('Replay read current state'))
        sample = adapter.replay_event(query(), service._context(), event)
        assert sample['fields']['proposal_expiry']['status'] == 'known'
        assert sample['fields']['proposal_expiry']['value'][0]['event_date']['value'] == fixture.NOW
        changed = deepcopy(event)
        changed['payload'].pop('lifecycle')
        assert adapter.replay_event(query(), service._context(), changed)['fields']['proposal_expiry']['status'] == 'unknown'


def test_shared_ledger_pages_filter_before_limit_and_isolate_world_owner(tmp_path):
    with ExitStack() as stack:
        _, _, service = setup(tmp_path, stack, events=[])
        context = service._context()
        state = {'epoch': 0, 'complete': True, 'gaps': []}
        state['scope'] = service._event_scope(context, state)
        service._set_runtime('event-source', state)
        for index, status in enumerate(['expired', 'observed_pending', 'expired', 'inactive', 'expired']):
            event = {'event_id': 'history-event-' + str(index), 'event_type': 'diplomatic_proposal',
                     'payload': {'observer_status': status}}
            service.db.execute('INSERT INTO info_events VALUES(?,?,?,?,?)',
                (service.owner, state['scope'], event['event_id'], digest(event), canonical(event)))
        service.db.commit()
        arguments = {'event_types': ['diplomatic_proposal'], 'limit': 2,
                     'payload_filters': {'observer_status': 'expired'}}
        first = service.observed_events(context, **arguments)
        assert [event['event_id'] for event in first['events']] == ['history-event-4', 'history-event-2']
        assert first['next_cursor'] == 'history-event-2'
        second = service.observed_events(context, cursor=first['next_cursor'], **arguments)
        assert [event['event_id'] for event in second['events']] == ['history-event-0']
        assert second['next_cursor'] is None
        assert service.observed_events(dict(context, world_id='other-world'), **arguments)['events'] == []
        with pytest.raises(InformationError, match='cursor'):
            service.observed_events(context, cursor='unknown-event', **arguments)
        with closing(InformationService(service.source, tmp_path / 'information.sqlite3', owner='other')) as other:
            assert other.observed_events(context, **arguments)['events'] == []
        service._set_runtime('context-checkpoint', dict(context, game_day=context['game_day'] + 1))
        rewound = service.observed_events(context, **arguments)
        assert rewound['events'] == [] and rewound['complete'] is False
        assert rewound['gaps'] == [{'reason': 'game_date_rewound'}]


@pytest.mark.parametrize('statuses', [[], 'expired', [True], ['']])
def test_invalid_status_filters_are_rejected(tmp_path, statuses):
    with ExitStack() as stack:
        _, _, service = setup(tmp_path, stack, events=[])
        with pytest.raises(InformationError):
            subscribe(service, statuses=statuses)


def test_explicit_legacy_request_keeps_old_read_and_event_paths(tmp_path):
    with ExitStack() as stack:
        base, adapter, service = setup(tmp_path, stack, events=[])
        assert adapter.catalog()[0]['fields']['proposal_expiry']['coverage'] == 'available'
        selected = {'topic': 'H02', 'object': {'type': 'session'}, 'fields': ['proposal_expiry'],
                    'parameters': {'request_id': 'historical-request'}}
        expected = {'fields': {'proposal_expiry': {'status': 'known', 'value': 123}}}
        calls = []
        base.read = lambda query, context: calls.append('read') or deepcopy(expected)
        base.read_event = lambda query, context, event: calls.append('read_event') or deepcopy(expected)
        base.replay_event = lambda query, context, event: calls.append('replay_event') or deepcopy(expected)
        assert adapter.read(selected, service._context()) == expected
        assert adapter.read_event(selected, service._context(), {}) == expected
        assert adapter.replay_event(selected, service._context(), {}) == expected
        assert calls == ['read', 'read_event', 'replay_event']


def test_proposal_status_filter_keeps_other_requested_event_types(tmp_path):
    with ExitStack() as stack:
        _, _, service = setup(tmp_path, stack, events=[])
        subscription = {'event': {'types': ['diplomatic_proposal', 'country_modifier_expired'],
                                  'proposal_statuses': ['expired']}}
        assert service._event_matches(subscription, {
            'event_type': 'country_modifier_expired', 'payload': {'country': 'FRA'}})
        assert not service._event_matches(subscription, {
            'event_type': 'diplomatic_proposal', 'payload': {'observer_status': 'observed_pending'}})
        assert service._event_matches(subscription, {
            'event_type': 'diplomatic_proposal', 'payload': {'observer_status': 'expired'}})


def test_normal_history_pagination_exposes_only_a_real_next_page(tmp_path):
    events = [fixture.offer(), fixture.expired(), fixture.offer(token=20, native_id=2),
              fixture.expired(token=20, sequence=102)]
    with ExitStack() as stack:
        _, _, service = setup(tmp_path, stack, events=events)
        subscribe(service, statuses=['expired'])
        assert len(service.tick()['results']) == 2
        api = InformationTools(service)
        first = api.call('information_query', {'request_id': 'expiry-page-one',
            'queries': [query(parameters={'limit': 1})]})
        cursor = first['items'][0]['next_cursor']['proposal_expiry']
        assert cursor == first['items'][0]['proposal_expiry'][0]['event_id']
        second = api.call('information_query', {'request_id': 'expiry-page-two',
            'queries': [query(parameters={'limit': 1, 'cursor': cursor})]})
        assert len(second['items'][0]['proposal_expiry']) == 1
        assert 'next_cursor' not in second['items'][0]
        assert first['items'][0]['proposal_expiry'] != second['items'][0]['proposal_expiry']


def test_joint_h02_projection_keeps_unrelated_modifier_list_empty(tmp_path):
    with ExitStack() as stack:
        base, adapter, service = setup(tmp_path, stack)
        modifier = NativeModifierLifecycleHistorySource(base, history_reader=service.observed_events)
        service.source = CompositeSource(base, [adapter, modifier])
        selected = dict(query(), fields=['proposal_expiry', 'modifier_lifecycle'])
        report = service.manage_report('joint-history-report', 'create', config={
            'name': 'lifecycle events', 'queries': [selected]})['report']
        service.manage_subscription('joint-history-sub', 'create', config={
            'kind': 'event', 'report_id': report['id'],
            'event': {'types': ['diplomatic_proposal'], 'proposal_statuses': ['expired']}})
        result = service.tick()['results']
        assert len(result) == 1
        fields = result[0]['items'][0]['fields']
        assert fields['modifier_lifecycle'] == {
            'status': 'known', 'value': [], 'unit': 'modifier_lifecycle', 'complete': True}
        assert fields['proposal_expiry']['status'] == 'known'
        assert len(fields['proposal_expiry']['value']) == 1


def retained_source(document):
    class RetainedExpiry(DiplomacySource):
        def context(self):
            return deepcopy(document['context'])

        def poll_events(self, context, cursor):
            return {'events': [] if cursor else [deepcopy(document['event'])],
                    'cursor': {'delivered': True}, 'complete': True, 'gaps': []}

    return RetainedExpiry(observer='FRA')


def test_real_expiry_keeps_actual_date_separate_from_collection_date(tmp_path):
    path = Path(__file__).parent / 'fixtures' / 'information_proposal_expired_BOU_FRA_live_1374.json'
    document = json.loads(path.read_text(encoding='utf-8'))
    assert document['context']['game_date'] > document['event']['game_date']
    base = retained_source(document)
    adapter = NativeProposalExpiryHistorySource(base)
    with closing(InformationService(CompositeSource(base, [adapter]), tmp_path / 'retained-expiry.sqlite3')) as service:
        adapter.history_reader = service.observed_events
        subscribe(service, statuses=['expired'])
        result = service.tick()['results']
        assert len(result) == 1
        full_row = result[0]['items'][0]['fields']['proposal_expiry']['value'][0]
        assert full_row['event_date']['value'] == 56459232
        public = InformationTools(service).call('information_get_result', {'result_id': result[0]['result_id']})
        assert public['items'][0]['proposal_expiry'][0]['event_date'] == '1445.2.13'
        assert service.tick()['results'] == []


def test_normal_factory_shares_the_service_ledger_with_both_history_adapters(tmp_path):
    from tools.serve_information import _build_runtime, build_parser
    from bridge.information.subsidy_expiry_history import NativeSubsidyExpiryHistorySource
    from bridge.information.truce_expiry_history import NativeTruceExpiryHistorySource
    from bridge.information.claim_expiry_history import NativeClaimExpiryHistorySource
    from bridge.information.cooldown_expiry_history import CooldownExpiryHistorySource

    arguments = build_parser().parse_args(['--observer', 'FRA', '--database', str(tmp_path / 'factory.sqlite3')])
    service, journal = _build_runtime(arguments)
    try:
        assert journal is None
        adapters = service.source.adapters
        proposal = next(item for item in adapters if isinstance(item, NativeProposalExpiryHistorySource))
        modifier = next(item for item in adapters if isinstance(item, NativeModifierLifecycleHistorySource))
        subsidy = next(item for item in adapters if isinstance(item, NativeSubsidyExpiryHistorySource))
        truce = next(item for item in adapters if isinstance(item, NativeTruceExpiryHistorySource))
        claim = next(item for item in adapters if isinstance(item, NativeClaimExpiryHistorySource))
        cooldown = next(item for item in adapters if isinstance(item, CooldownExpiryHistorySource))
        assert proposal.history_reader.__self__ is service
        assert modifier.history_reader.__self__ is service
        assert subsidy.history_reader.__self__ is service
        assert truce.history_reader.__self__ is service
        assert claim.history_reader.__self__ is service
        assert cooldown.history_reader.__self__ is service
        assert cooldown.base_source.cooldown_reader.__self__ is service
        assert proposal.base_source is modifier.base_source is service.source.primary
        assert subsidy.base_source is service.source.primary
        assert truce.base_source is service.source.primary
        assert claim.base_source is cooldown.base_source is service.source.primary
    finally:
        service.close()
