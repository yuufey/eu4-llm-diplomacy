"""Written unlock requests use loaded membership and the shared result path."""
from bridge.information import InformationService
from bridge.information.composite import CompositeSource
from bridge.information.model import canonical
from bridge.tests.test_information_mission_reward_duration_integration import (
    _live_source, _put_effect, _query, _command, scalar,
)


def test_requests_are_selected_from_loaded_tasks_without_claiming_completed_rewards():
    source, primary, _, definitions = _live_source()
    _put_effect(definitions, 'task_owned', scalar('complete_mission', 'future_task', 10))
    _put_effect(definitions, 'not_loaded', scalar('unlock_cult', 'not_visible_cult', 11))
    result = source.read(_query(('unlocks',), root_id='root_main'), primary.context())
    field = result['fields']['unlocks']
    assert field['status'] == 'known' and field['complete'] is False
    value = field['value']
    assert value['task_count'] == 2 and value['literal_rule_count'] == 1
    assert value['evaluated'] is False and value['applied'] == value['actual_unlocks'] == 'unknown'
    assert value['scope_targets_resolved'] is False
    matched = [row for row in value['rules'] if row['rules']]
    assert {row['task_id'] for row in matched} == {'task_owned'}
    assert matched[0]['rules'][0]['command'] == 'complete_mission'
    assert value['unknown_task_count'] == 1
    assert next(row for row in value['rules'] if row['task_id'] == 'task_core')['status'] == 'unknown'
    refused = source.read(_query(('unlocks',), task_id='not_loaded'), primary.context())
    assert refused['fields']['unlocks']['status'] == 'unknown'
    assert refused['fields']['unlocks']['reason'] == 'TASK_NOT_IN_CAPTURED_LOADED_TASKS'


def test_unknown_missing_task_ast_does_not_become_empty_unlock_inventory():
    source, primary, _, _ = _live_source()
    result = source.read(_query(('unlocks',), task_id='task_core'), primary.context())
    assert result['fields']['unlocks']['status'] == 'unknown'
    assert 'value' not in result['fields']['unlocks']


def test_definition_drift_withdraws_declared_requests():
    source, primary, _, definitions = _live_source()
    _put_effect(definitions, 'task_owned', scalar('unlock_cult', 'cult_a', 10))
    definitions.mutate_after_first_context = True
    result = source.read(_query(('unlocks',), task_id='task_owned'), primary.context())
    assert result['fields']['unlocks']['status'] == 'stale'
    assert 'value' not in result['fields']['unlocks']


def test_query_report_and_two_periods_share_requests_and_cancel_independently(tmp_path):
    source, primary, _, definitions = _live_source(scheduling=True)
    _put_effect(definitions, 'task_owned',
        _command('unlock_government_reform', scalar('government_reform', 'reform_a', 11)))
    clock = [100.0]
    service = InformationService(CompositeSource(primary, [source]), tmp_path/'unlocks.sqlite', clock=lambda: clock[0])
    query = _query(('unlocks',), task_id='task_owned')
    try:
        direct = service.query('unlock-direct', queries=[query])
        field = direct['items'][0]['fields']['unlocks']
        assert field['status'] == 'known' and field['value']['literal_rule_count'] == 1
        report = service.manage_report('unlock-report', 'create',
            config={'name':'requests','queries':[query],'detail':'raw'})['report']
        manual = service.query('unlock-manual', report_id=report['id'])
        assert canonical(manual['items'][0]['fields']['unlocks']) == canonical(field)
        subs = {}
        for name, every in [('short', 2), ('long', 5)]:
            subs[name] = service.manage_subscription('unlock-'+name, 'create', config={
                'name':name,'kind':'periodic','report_id':report['id'],'enabled':True,
                'schedule':{'basis':'real','every':every,'unit':'seconds','missed':'coalesce'}})['subscription']
        clock[0] = 102.0
        results = service.tick()['results']
        assert len(results) == 1 and results[0]['subscription_id'] == subs['short']['id']
        assert canonical(results[0]['items'][0]['fields']['unlocks']) == canonical(field)
        service.manage_subscription('unlock-cancel-short','cancel',subscription_id=subs['short']['id'],
            expected_version=subs['short']['version'])
        clock[0] = 105.0
        results = service.tick()['results']
        assert len(results) == 1 and results[0]['subscription_id'] == subs['long']['id']
        assert canonical(results[0]['items'][0]['fields']['unlocks']) == canonical(field)
    finally:
        service.close()
