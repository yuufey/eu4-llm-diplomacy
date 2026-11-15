"""Same-report mission declarations stay distinct from applied rewards."""
from copy import deepcopy
from contextlib import closing

import pytest

from bridge.information import mission_brief
from bridge.information.presentation import present_result
from bridge.information.service import InformationService
from bridge.information.tools import InformationTools
from bridge.tests.test_information_mission_reward_rules_recorded import _service, _query


def _result(date=56566584, completable=False):
    task = {'root_id': 'french_missions_1', 'task_id': 'fra_liberate_norm', 'status': 'known'}
    rule = {'command': 'add_permanent_claim', 'raw_node': {'value': 'ROOT'},
            'parent_scope': [{'key': 'effect'}, {'key': 'brittany_area'}],
            'condition_context': [{'context_id': 'c1'}], 'context_status': 'unresolved'}

    def item(topic, field, value):
        return {'topic': topic, 'game_date': date,
                'objects': [{'type': 'country', 'country': 'FRA'}],
                'source': {'mode': 'live', 'session_id': 'synthetic', 'observer': 'FRA'},
                'fields': {field: {'status': 'known', 'value': value, 'complete': False}}}

    return {'result_id': 'synthetic-mission-result', 'detail': 'brief', 'items': [
        item('M01', 'name', {'entries': [dict(task, text='解放诺曼底')]}),
        item('M02', 'currently_completable', {'tasks': [dict(task, currently_completable=completable)]}),
        item('M04', 'claims', {'semantics': 'declared_literal_effect_rules', 'applied': 'unknown',
                             'rules': [dict(task, rules=[rule])]})]}


@pytest.mark.parametrize('date', [56566584, '1457.5.17'])
@pytest.mark.parametrize('completable', [False, True, None])
def test_selected_claims_link_to_task_facts_without_promoting_effects(date, completable):
    result = _result(date, completable)
    before = deepcopy(result)
    summary = present_result(result)['presentation']['mission_claim_summaries'][0]
    assert result == before
    assert summary['name']['value'] == '解放诺曼底'
    assert summary['currently_completable'].get('value') is completable
    assert summary['claims'][0]['declared_scope_keys'] == ['brittany_area']
    assert summary['claims'][0]['recipient_expression'] == 'ROOT'
    assert summary['claims'][0]['applicability'] == 'unknown'
    assert summary['claims'][0]['applied'] == 'unknown'
    assert summary['reward_execution_observed'] is False
    assert summary['complete'] is False
    assert '奖励实际执行状态未知' in summary['text']
    for path in (summary['name']['source_paths'][0], summary['claims'][0]['source_path']):
        node = result
        for part in path.lstrip('/').split('/'):
            node = node[int(part)] if isinstance(node, list) else node[part]
        assert node


@pytest.mark.parametrize('change', ['country', 'date', 'root', 'task', 'mode', 'session', 'observer'])
def test_unrelated_facts_cannot_be_joined(change):
    result = _result()
    for item in result['items'][:2]:
        if change == 'country':
            item['objects'][0]['country'] = 'ENG'
        elif change == 'date':
            item['game_date'] += 24
        elif change in ('mode', 'session', 'observer'):
            key = {'mode': 'mode', 'session': 'session_id', 'observer': 'observer'}[change]
            item['source'][key] = 'different'
        else:
            field = next(iter(item['fields'].values()))
            rows = field['value'].get('entries', field['value'].get('tasks'))
            rows[0]['root_id' if change == 'root' else 'task_id'] = 'different'
    summary = mission_brief.project_mission_claim_briefs(result)[0]
    assert summary['name']['status'] == 'unknown'
    assert summary['currently_completable']['status'] == 'unknown'
    assert summary['claims']


def test_conflicting_and_unverified_completion_facts_stay_unknown():
    result = _result()
    duplicate = deepcopy(result['items'][1])
    duplicate['fields']['currently_completable']['value']['tasks'][0]['currently_completable'] = True
    result['items'].append(duplicate)
    assert mission_brief.project_mission_claim_briefs(result)[0]['currently_completable']['status'] == 'unknown'
    result['items'].pop()
    row = result['items'][1]['fields']['currently_completable']['value']['tasks'][0]
    row['status'] = 'unknown'
    assert mission_brief.project_mission_claim_briefs(result)[0]['currently_completable']['status'] == 'unknown'
    row['status'], row['currently_completable'] = 'known', 0
    assert mission_brief.project_mission_claim_briefs(result)[0]['currently_completable']['status'] == 'unknown'


@pytest.mark.parametrize('value', [None, [], {}, {'semantics': 'other'},
                                  {'semantics': 'declared_literal_effect_rules', 'rules': None}])
def test_legacy_claim_shapes_preserve_business_fields(value):
    result = _result()
    result['items'][2]['fields']['claims']['value'] = value
    brief = present_result(result)
    assert brief['items'][2]['fields'] == result['items'][2]['fields']
    assert 'mission_claim_summaries' not in brief['presentation']


def test_empty_and_truncated_declarations_remain_explicit(monkeypatch):
    result = _result()
    task = result['items'][2]['fields']['claims']['value']['rules'][0]
    task['rules'] = []
    summary = mission_brief.project_mission_claim_briefs(result)[0]
    assert summary['claims'] == []
    assert '未发现字面宣称规则' in summary['text']
    result = _result()
    tasks = result['items'][2]['fields']['claims']['value']['rules']
    tasks[0]['rules'] *= 3
    tasks.append(deepcopy(tasks[0]))
    monkeypatch.setattr(mission_brief, 'MAX_TASKS', 1)
    monkeypatch.setattr(mission_brief, 'MAX_RULES', 1)
    summary = mission_brief.project_mission_claim_briefs(result)[0]
    assert summary['omitted_task_count'] == 1
    assert summary['omitted_rule_count'] == 2


def test_normal_tools_preserve_full_result_and_reopen(tmp_path):
    service, source = _service(tmp_path)
    try:
        tools = InformationTools(service)
        report = tools.call('information_manage_report', {
            'request_id': 'create-mission-brief', 'operation': 'create',
            'config': {'name': 'Declared mission claims', 'detail': 'brief',
                       'queries': [_query(fields=('claims',))]}})['report']
        arguments = {'request_id': 'read-mission-brief', 'report_id': report['id']}
        concise = tools.call('information_query', arguments)
        full = tools.call('information_get_result', {"view": "full", 'result_id': concise['result_id']})
        brief = present_result(full)
        summaries = brief['presentation']['mission_claim_summaries']
        assert summaries and any(summary['claims'] for summary in summaries)
        assert 'presentation' not in full
        expected_fields = deepcopy(full['items'][0]['fields'])
        assert expected_fields['claims'].pop('provenance')
        assert expected_fields == brief['items'][0]['fields']
        assert tools.call('information_query', arguments) == concise
        assert tools.call('information_list_results', {})['results'][0] == concise
    finally:
        service.close()
    with closing(InformationService(source, tmp_path / 'recorded-m04.sqlite3')) as reopened:
        assert reopened.get_result(full['result_id']) == full
        assert present_result(reopened.get_result(full['result_id'])) == brief
