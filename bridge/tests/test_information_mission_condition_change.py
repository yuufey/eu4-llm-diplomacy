"""Exercise the normal scheduler for known, partial native mission conditions."""
from copy import deepcopy

import pytest

from bridge.information import InformationService
from bridge.information.composite import CompositeSource
from bridge.information.missions import MissionInformationSource
from bridge.tests.test_information_missions import Definitions, State, query
from bridge.tests.test_information_mission_trigger_source import _group, _leaf, _normalized_state, _task
from bridge.tests.test_information_service import FakeClock, create_report, create_subscription, tick_results


def setup(tmp_path):
    state, definitions = State(), Definitions()
    state.sample['completed_missions']['task_ids'] = []
    state.sample['loaded_tasks'] = {'status': 'known', 'roots': [
        {'root_id': 'loaded', 'task_ids': ['first', 'second']}]}
    set_progress(state, False)
    adapter = MissionInformationSource(state, definitions, state.capture)
    service = InformationService(CompositeSource(state, [adapter]), tmp_path / 'missions.sqlite3', clock=FakeClock())
    return service, state, definitions, adapter


def set_progress(state, satisfied):
    tree = _group('and', [_leaf(satisfied)])
    conditions = [{'root_id': 'loaded', 'task_id': 'first',
                   'task_completed': False, 'prerequisites_satisfied': True}]
    state.sample.update(_normalized_state([_task('first', tree)],
                        condition_rows=conditions, condition_status='known'))


def selected(fields=None):
    return query('M02', fields or ['currently_completable', 'condition_progress'], task_id='first')


def tick(service, state, day):
    state.current.update(game_date=day * 24, game_day=day)
    state.sample['game_date'] = day * 24
    return tick_results(service.tick())


def subscribe(service):
    report = create_report(service, 'mission-change-report', query=selected())
    return create_subscription(service, report['id'], 'mission-change', kind='change',
                               basis='game', every=1, unit='days')


def test_known_conditions_deliver_once_through_scheduler_and_survive_reopen(tmp_path):
    service, state, definitions, adapter = setup(tmp_path)
    try:
        sub = subscribe(service)
        assert tick(service, state, 2) == []
        assert tick(service, state, 3) == []
        set_progress(state, True)
        results = tick(service, state, 4)
        assert len(results) == 1 and results[0]['trigger'] == 'change'
        result = results[0]
        assert result['complete'] is False
        fields = result['items'][0]['fields']
        assert fields['condition_progress']['value']['satisfied_leaf_count'] == 1
        assert fields['currently_completable']['value']['tasks'][0]['currently_completable'] is True
        assert tick(service, state, 5) == []
        assert service.get_result(result['result_id'])['items'] == result['items']
    finally:
        service.close()
    reopened = InformationService(CompositeSource(state, [adapter]), tmp_path / 'missions.sqlite3', clock=FakeClock())
    try:
        assert reopened.get_result(result['result_id'])['items'] == result['items']
        assert tick(reopened, state, 6) == []
        assert reopened.status(sub['id'])['subscriptions'][0]['runtime']['last_attempt']['status'] == 'unchanged'
    finally:
        reopened.close()


def test_unknown_and_read_failure_preserve_the_last_known_baseline(tmp_path):
    service, state, _definitions, _adapter = setup(tmp_path)
    try:
        sub = subscribe(service)
        assert tick(service, state, 2) == []
        prior = service.status(sub['id'])['subscriptions'][0]['runtime']['baseline']
        set_progress(state, None)
        assert tick(service, state, 3) == []
        assert service.status(sub['id'])['subscriptions'][0]['runtime']['baseline'] == prior
        state.sample['complete'] = False
        assert tick(service, state, 4) == []
        assert service.status(sub['id'])['subscriptions'][0]['runtime']['baseline'] == prior
        state.sample['complete'] = True
        set_progress(state, True)
        assert len(tick(service, state, 5)) == 1
    finally:
        service.close()


def test_definition_change_rebuilds_comparison_scope_without_false_progress(tmp_path):
    service, state, definitions, _adapter = setup(tmp_path)
    try:
        sub = subscribe(service)
        assert tick(service, state, 2) == []
        original = definitions.context
        definitions.context = lambda: dict(original(), definitions_sha256='replacement')
        set_progress(state, True)
        assert tick(service, state, 3) == []
        assert service.status(sub['id'])['subscriptions'][0]['runtime']['last_attempt']['status'] == 'baseline_scope_changed'
        set_progress(state, False)
        assert len(tick(service, state, 4)) == 1
    finally:
        service.close()


@pytest.mark.parametrize('damage', ['session', 'observer', 'date', 'membership', 'unknown',
                                    'boolean_count', 'empty_tasks', 'missing_definitions'])
def test_comparison_rejects_unbound_or_unknown_samples(tmp_path, damage):
    service, _state, _definitions, adapter = setup(tmp_path)
    try:
        context = adapter.context()
        sample = adapter.read(selected(), context)
        assert adapter.change_comparison(selected(), sample, context) is not None
        if damage in {'session', 'observer'}:
            sample['source']['session_id' if damage == 'session' else 'observer'] = 'OTHER'
        elif damage == 'date':
            sample['game_date'] += 24
        elif damage == 'membership':
            sample['source']['provenance']['task_membership_status'] = 'unknown'
        elif damage == 'missing_definitions':
            sample['source']['provenance'].pop('definitions')
        else:
            value = sample['fields']['condition_progress']['value']
            if damage == 'unknown':
                value['unknown_leaf_count'] = 1
            elif damage == 'boolean_count':
                value['unknown_leaf_count'] = False
            else:
                value['tasks'] = []
                value['task_count'] = 0
        assert adapter.change_comparison(selected(), sample, context) is None
    finally:
        service.close()


def test_comparison_is_private_to_supported_live_condition_fields(tmp_path):
    service, state, _definitions, adapter = setup(tmp_path)
    try:
        current = selected(['condition_progress', 'unlock_conditions'])
        sample = adapter.read(current, adapter.context())
        original = deepcopy(sample)
        assert adapter.change_comparison(current, sample, adapter.context()) is None
        assert sample == original
        state.current['mode'] = 'saved'
        assert adapter.change_comparison(selected(), original, state.current) is None
        topic = next(row for row in adapter.catalog() if row['topic_id'] == 'M02')
        assert topic['change_comparison']['basis'] == 'sampled_state_comparison_not_lossless_events'
    finally:
        service.close()
