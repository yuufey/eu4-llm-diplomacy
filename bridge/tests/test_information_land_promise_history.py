"""Associate observed accepted senders without changing current land flags."""
from contextlib import closing
from copy import deepcopy
from unittest.mock import Mock

import pytest

from bridge.information.composite import CompositeSource
from bridge.information.land_promise_history import attach_observed_promisors
from bridge.information.service import InformationService
from bridge.information.tools import InformationTools
from bridge import land_promise_observation as observation
from bridge.tests.test_information_country_modifier_events import make_source
from bridge.tests.test_information_war_land_view import build, query
from bridge.tests.test_land_promise_observation import DATE, SESSION, WAR_ID, context, native_ack, native_event, snapshot


def field():
    return {'status': 'known', 'complete': True, 'value': [
        {'war_id': WAR_ID, 'beneficiary': 'SAV', 'side': 'our_side', 'war_leader': 'BUR'}]}


def reader(events=None, **changes):
    return Mock(return_value={'events': events if events is not None else [snapshot()],
                              'complete': True, 'gaps': [], **changes})


def test_current_leader_and_observed_sender_retain_their_distinct_meanings():
    original = field()
    history = reader()
    result, proof = attach_observed_promisors(original, context(), history)
    assert result['value'][0] == {**original['value'][0], 'observed_promisor': 'FRA'}
    assert result['value'][0]['war_leader'] == 'BUR'
    assert original == field()
    assert proof['complete'] and not proof['gaps']
    assert proof['events'][0]['event_date'] == DATE
    assert history.call_args.kwargs['payload_filters'] == {'war_id': WAR_ID, 'beneficiary': 'SAV'}


def test_turkish_observer_can_match_a_scoped_promise_receipt():
    from bridge.tests.test_land_promise_observation import fullref

    raw = native_event(promisor="TUR")
    raw.update(wire=2, observer_ref=fullref("TUR"))
    public = observation.public_observation(raw, SESSION)
    assert public["payload"]["observer"] == "TUR"
    event = snapshot()
    event.update(observer="TUR", payload=public["payload"], objects=public["objects"])
    event["source"]["scope"] = observation.CONFIGURED_SCOPE
    configured = context(observer="TUR")
    result, proof = attach_observed_promisors(field(), configured, reader([event]))
    assert result["value"][0]["observed_promisor"] == "TUR"
    assert proof["complete"] is True
    assert not observation.valid_event_snapshot(event, context())


def test_latest_observed_promise_is_ordered_by_native_date_then_sequence():
    result, proof = attach_observed_promisors(field(), context(), reader([
        snapshot(2, 'ENG'), snapshot(1), snapshot(3, 'BUR', date_raw=DATE - 24)]))
    assert result['value'][0]['observed_promisor'] == 'ENG'
    assert proof['events'][0]['event_id'] == snapshot(2, 'ENG')['event_id']


@pytest.mark.parametrize('event', [
    snapshot(promisor='SAV', beneficiary='FRA'), snapshot(war_id='war_0123456789abcdef_00000002'),
])
def test_other_wars_and_beneficiaries_do_not_fill_a_sender(event):
    result, proof = attach_observed_promisors(field(), context(), reader([event]))
    assert result['value'][0]['observed_promisor'] is None
    assert 'LAND_PROMISE_SENDER_NOT_OBSERVED' in proof['gaps']
    assert result['complete'] is True


def test_null_current_war_id_does_not_use_old_r63_or_date_endpoint_matching():
    current = field()
    current['value'][0]['war_id'] = None
    result, proof = attach_observed_promisors(current, context(), reader())
    assert result['value'][0]['observed_promisor'] is None
    assert not proof['complete']


@pytest.mark.parametrize('damage', ['session', 'snapshot', 'future', 'conflict', 'batch', 'reader'])
def test_invalid_history_keeps_current_flags_and_leaders(damage):
    events = [snapshot()]
    history = reader(events)
    if damage == 'session':
        events[0]['session_id'] = 'other'
    elif damage == 'snapshot':
        events[0]['payload']['promisor'] = 'ENG'
    elif damage == 'future':
        events[0] = snapshot(date_raw=DATE + 48)
    elif damage == 'conflict':
        events.append(snapshot(promisor='ENG'))
    elif damage == 'batch':
        history.return_value['complete'] = 1
    else:
        history.side_effect = RuntimeError('offline')
    result, proof = attach_observed_promisors(field(), context(), history)
    assert result['value'][0]['observed_promisor'] is None
    assert result['value'][0]['war_leader'] == 'BUR'
    assert result['status'] == 'known' and result['complete']
    assert proof['gaps'] == ['LAND_PROMISE_HISTORY_READ_INVALID']


def test_missing_reader_and_empty_current_values_are_bounded():
    result, proof = attach_observed_promisors(field(), context(), None)
    assert result['value'][0]['observed_promisor'] is None
    assert proof['gaps'] == ['LAND_PROMISE_HISTORY_READER_NOT_BOUND']
    current = {'status': 'known', 'complete': True, 'value': []}
    history = reader()
    result, proof = attach_observed_promisors(current, context(), history)
    assert result == current and proof['complete']
    history.assert_not_called()


def test_recorded_sender_remains_an_observation_with_incomplete_history():
    result, proof = attach_observed_promisors(field(), context(), reader(
        complete=False, gaps=['LAND_PROMISE_CAPTURE_DROPPED'], next_cursor='older'))
    assert result['value'][0]['observed_promisor'] == 'FRA'
    assert not proof['complete'] and 'LAND_PROMISE_HISTORY_PAGE_LIMIT' in proof['gaps']


@pytest.mark.parametrize('object_type', ['country', 'war'])
def test_normal_r07_w04_report_and_cold_result_include_the_observed_sender(tmp_path, object_type):
    base, upstream, adapter, war_id, current = build(tmp_path)
    event = snapshot(beneficiary='FRA', promisor='SAV', war_id=war_id, date_raw=current['game_date'])
    event['session_id'] = current['session_id']
    event['source']['session_id'] = current['session_id']
    event['event_id'] = observation.event_id(current['session_id'], event['source']['native_sequence'])
    upstream.land_promise_history_reader = reader([event])
    selected = query({'type': 'country', 'country': 'FRA'} if object_type == 'country'
                     else {'type': 'war', 'actor': 'FRA', 'recipient': 'POR'})
    database = tmp_path / 'land-history.sqlite3'
    source = CompositeSource(base, [upstream, adapter])
    with closing(InformationService(source, database)) as service:
        tools = InformationTools(service)
        result = tools.call('information_query', {'request_id': 'accepted-promise', 'queries': [selected]})
        row = result['items'][0]['land_commitment'][0]
        assert row['observed_promisor'] == 'SAV' and row['war_leader'] == 'FRA'
        configured = tools.call('information_manage_report', {
            'request_id': 'accepted-report', 'operation': 'create',
            'config': {'name': 'land promises', 'queries': [selected], 'detail': 'full'}})['report']
        rendered = tools.call('information_query', {'request_id': 'accepted-report-read', 'report_id': configured['id']})
        assert rendered['items'] == result['items']
    with closing(InformationService(source, database)) as reopened:
        assert InformationTools(reopened).call('information_get_result', {'result_id': result['result_id']}) == result


def c04_query():
    return {'topic': 'C04', 'object': {'type': 'session'},
            'fields': ['event_id', 'event_type', 'event_date', 'event_payload'],
            'parameters': {'event_type': observation.EVENT_TYPE}}


def test_shared_session_poll_c04_snapshot_and_role_filters(tmp_path, monkeypatch):
    session, journal, primary = make_source(tmp_path, session_id=SESSION, ack=native_ack(), events=[
        native_event(promisor='SAV', beneficiary='FRA')])
    session.game_date = DATE + 24
    with closing(journal):
        assert observation.CAPABILITY in session.installation_capabilities()
        assert observation.EVENT_TYPE in primary.event_types
        refresh = Mock(wraps=session.read_native_alliance_inbound_offers)
        monkeypatch.setattr(session, 'read_native_alliance_inbound_offers', refresh)
        current = primary.context()
        batch = primary.poll_events(current, None)
        assert batch['complete'] and not batch['gaps']
        assert len(batch['events']) == 1 and refresh.call_count == 1
        assert batch['cursor']['land_promise_sequence'] == 1
        event = batch['events'][0]
        assert event['actor'] == 'SAV' and event['recipient'] == 'FRA'
        assert observation.valid_event_snapshot(event, current)
        result = primary.read_event(c04_query(), current, event)
        assert result == primary.replay_event(c04_query(), current, event)
        assert result['fields']['event_payload']['value']['war_id'] == WAR_ID
        assert result['game_date'] == DATE
        selected = primary.validate_event_filter({'types': [observation.EVENT_TYPE],
                                                  'actors': ['SAV'], 'recipients': ['FRA']})
        assert selected is None
        assert primary.poll_events(current, batch['cursor'])['events'] == []
        from bridge.information.model import InformationError
        with pytest.raises(InformationError, match='land_promise_sequence'):
            primary.poll_events(current, {'land_promise_sequence': True})
        damaged = deepcopy(event)
        damaged['payload']['war_id'] = 'war_0123456789abcdef_00000002'
        assert primary.replay_event(c04_query(), current, damaged)['complete'] is False


def test_joint_event_subscription_persists_c04_and_only_matching_roles_deliver(tmp_path):
    session, journal, primary = make_source(tmp_path, session_id=SESSION, ack=native_ack(), events=[
        native_event(1, promisor='SAV', beneficiary='FRA'), native_event(2, promisor='ENG')])
    session.game_date = DATE + 24
    database = tmp_path / 'accepted-events.sqlite3'
    with closing(journal):
        with closing(InformationService(primary, database)) as service:
            tools = InformationTools(service)
            configured = tools.call('information_manage_report', {
                'request_id': 'promise-event-report', 'operation': 'create',
                'config': {'name': 'accepted promises', 'queries': [c04_query()], 'detail': 'full'}})['report']
            tools.call('information_manage_subscription', {
                'request_id': 'promise-event-subscription', 'operation': 'create',
                'config': {'name': 'accepted calls to FRA', 'kind': 'event', 'report_id': configured['id'],
                           'enabled': True, 'event': {'types': [observation.EVENT_TYPE],
                                                    'actors': ['SAV'], 'recipients': ['FRA']}}})
            delivered = tools.call('information_tick', {'view': 'full'})['results']
            assert len(delivered) == 1
            assert delivered[0]['items'][0]['fields']['event_payload']['value']['promisor'] == 'SAV'
            history = service.observed_events(primary.context(), event_types=[observation.EVENT_TYPE], limit=1000)
            assert len(history['events']) == 2
            assert service.tick()['results'] == []
            saved = deepcopy(delivered[0])
        with closing(InformationService(primary, database)) as reopened:
            assert reopened.get_result(saved['result_id']) == saved
            assert len(reopened.observed_events(primary.context(), event_types=[observation.EVENT_TYPE])['events']) == 2
            assert reopened.tick()['results'] == []


def test_normal_factory_binds_shared_history_reader_without_capturing(tmp_path, monkeypatch):
    from tools.serve_information import _build_runtime, build_parser
    from bridge.information.commitments import NativeCommitmentsSource
    from bridge.information import war_land_commitments_capture as capture
    monkeypatch.setattr(capture, 'capture', lambda *_: pytest.fail('Factory captured current game'))
    args = build_parser().parse_args(['--observer', 'FRA', '--database', str(tmp_path / 'factory.sqlite3')])
    service, journal = _build_runtime(args)
    with closing(service):
        assert journal is None
        owner = next(item for item in service.source.adapters if isinstance(item, NativeCommitmentsSource))
        assert owner.land_promise_history_reader.__self__ is service
        assert owner.land_promise_history_reader.__func__ is service.observed_events.__func__
