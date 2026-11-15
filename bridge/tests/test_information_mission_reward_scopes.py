"""Declared area candidates retain their static and conditional boundaries."""
from copy import deepcopy
from contextlib import closing

import pytest

from bridge.information import mission_reward_scopes as scopes
from bridge.information.presentation import present_result
from bridge.information.composite import CompositeSource
from bridge.information.service import InformationService
from bridge.information.tools import InformationTools
from bridge.tests.test_information_mission_reward_rules_integration import _adapter, _ast_node, _query
from bridge.tests.test_information_mission_brief import _result


class Index:
    def __init__(self, tmp_path=None):
        self.calls = []
        self.members = [13, 12]
        self.kind = 'areas'
        self.revision = 1
        self.change_after_lookup = False
        self.fail = False
        self.paths = {'game_root': str(tmp_path / 'game'), 'user_data': str(tmp_path / 'user')} if tmp_path else {}

    def context(self):
        return {'status': 'ready', 'complete': True, 'game_version': '1.37.4',
                'configuration_sha256': 'map-config', 'definitions_sha256': str(self.revision),
                'enabled_mods': [], **self.paths}

    def lookup_scopes(self, names):
        self.calls.append(list(names))
        if self.fail:
            raise OSError('source unavailable')
        if self.change_after_lookup:
            self.revision += 1
        return {name: {'status': 'known', 'name': name, 'kind': self.kind,
                       'members': deepcopy(self.members),
                       'source': {'files': [{'path': 'map/area.txt', 'sha256': 'a' * 64}]}}
                for name in names}


def _field():
    return _result()['items'][2]['fields']['claims']


def _candidate(result):
    return result['value']['rules'][0]['rules'][0]['declared_area_candidates']


def _without_candidates(result):
    result = deepcopy(result)
    result['value'].pop('declared_area_candidates', None)
    for task in result['value']['rules']:
        for rule in task['rules']:
            rule.pop('declared_area_candidates', None)
    return result


def test_static_area_members_are_candidates_and_preserve_original_rules():
    field, index = _field(), Index()
    before = deepcopy(field)
    result = scopes.project_claim_scope_candidates(field, index)
    assert field == before and _without_candidates(result) == field
    assert _candidate(result)['candidate_province_ids'] == [12, 13]
    assert _candidate(result)['reward_limits_evaluated'] is False
    assert _candidate(result)['applied'] == 'unknown'
    assert result['value']['declared_area_candidates']['scope_targets_resolved'] is False
    assert index.calls == [['brittany_area']]


@pytest.mark.parametrize('members', [[True], [0], [65536], [12, 12], None, '12'])
def test_invalid_membership_keeps_literal_rule(members):
    index = Index()
    index.members = members
    field = _field()
    result = scopes.project_claim_scope_candidates(field, index)
    assert _candidate(result)['status'] == 'unknown'
    assert _without_candidates(result) == field


def test_unknown_kind_missing_index_and_lookup_failure_are_local():
    field, index = _field(), Index()
    index.kind = 'country_tag'
    assert _candidate(scopes.project_claim_scope_candidates(field, index))['reason'] == 'REWARD_AREA_SCOPE_KIND_UNSUPPORTED'
    assert _candidate(scopes.project_claim_scope_candidates(field, None))['status'] == 'unknown'
    index.fail = True
    assert _candidate(scopes.project_claim_scope_candidates(field, index))['reason'] == 'REWARD_AREA_LOOKUP_FAILED'
    index.lookup_scopes = lambda names: {name: {'status': 'unknown', 'reason': 'SCOPE_KIND_COLLISION'} for name in names}
    assert _candidate(scopes.project_claim_scope_candidates(field, index))['reason'] == 'SCOPE_KIND_COLLISION'


def test_nested_scope_budget_and_rule_limit_remain_explicit(monkeypatch):
    field, index = _field(), Index()
    rules = field['value']['rules'][0]['rules']
    rules[0]['parent_scope'].append({'key': 'owner'})
    assert _candidate(scopes.project_claim_scope_candidates(field, index))['reason'] == 'REWARD_AREA_SCOPE_CHAIN_UNSUPPORTED'
    field = _field()
    monkeypatch.setattr(scopes, 'MAX_OUTPUT_BYTES', 1)
    assert _candidate(scopes.project_claim_scope_candidates(field, index))['reason'] == 'REWARD_AREA_OUTPUT_LIMIT'
    monkeypatch.setattr(scopes, 'MAX_RULES', 1)
    field['value']['rules'][0]['rules'] *= 3
    result = scopes.project_claim_scope_candidates(field, index)
    assert result['value']['declared_area_candidates']['omitted_rule_count'] == 2


def _source(tmp_path):
    state, definitions, adapter = _adapter()
    index = Index(tmp_path)
    original = definitions.context
    definitions.context = lambda: dict(original(), **index.paths, enabled_mods=[])
    adapter.scope_index = index
    definitions.values['loaded']['tasks'][0]['effect'] = _ast_node('effect', 20, children=(
        _ast_node('brittany_area', 21, children=(
            _ast_node('limit', 22, children=(_ast_node('is_core', 23, value='ROOT'),)),
            _ast_node('add_permanent_claim', 24, value='ROOT'))),))
    return scopes.MissionRewardAreaSource(adapter), index


def test_selected_task_source_binds_map_and_legacy_queries_stay_literal(tmp_path):
    adapter, index = _source(tmp_path)
    result = adapter.read(_query(['claims'], root_id='loaded', task_id='first'))
    field = result['fields']['claims']
    assert _candidate(field)['candidate_province_ids'] == [12, 13]
    assert result['source']['provenance']['scope_definitions']['configuration_binding_verified'] is True
    assert index.calls == [['brittany_area']]
    index.calls.clear()
    result = adapter.read(_query(['claims'], root_id='loaded'))
    assert 'declared_area_candidates' not in result['fields']['claims']['value']
    assert not index.calls


@pytest.mark.parametrize('failure', ['unbound', 'changed', 'unavailable'])
def test_source_map_failures_retain_claims_and_siblings(tmp_path, failure):
    adapter, index = _source(tmp_path)
    if failure == 'unbound':
        original = index.context
        index.context = lambda: dict(original(), game_root=str(tmp_path / 'other'))
    elif failure == 'changed':
        index.change_after_lookup = True
    else:
        index.fail = True
    result = adapter.read(_query(['claims', 'casus_belli'], root_id='loaded', task_id='first'))
    field = result['fields']['claims']
    assert field['status'] == 'known' and field['value']['rules'][0]['rules']
    assert _candidate(field)['status'] == 'unknown'
    assert result['fields']['casus_belli']['status'] == 'known'
    if failure == 'changed':
        assert _candidate(field)['reason'] == 'MISSION_SCOPE_INPUT_CHANGED_DURING_COLLECTION'


@pytest.mark.parametrize('members', [[13, 12], []])
def test_brief_carries_membership_paths_without_applicability_promotion(members):
    result = _result()
    index = Index()
    index.members = members
    field = scopes.project_claim_scope_candidates(result['items'][2]['fields']['claims'], index)
    result['items'][2]['fields']['claims'] = field
    brief = present_result(result)
    claim = brief['presentation']['mission_claim_summaries'][0]['claims'][0]
    assert claim['declared_area_candidates']['candidate_province_ids'] == sorted(members)
    assert claim['declared_area_candidates']['source_path'].endswith('/declared_area_candidates')
    assert claim['applicability'] == 'unknown' and claim['applied'] == 'unknown'
    text = brief['presentation']['mission_claim_summaries'][0]['text']
    assert ('12, 13' in text) if members else ('未列出候选省份' in text)


def test_area_candidates_survive_normal_tools_and_reopen(tmp_path):
    adapter, index = _source(tmp_path)
    source = CompositeSource(adapter.base_source.base_source, [adapter])
    database = tmp_path / 'reward-areas.sqlite3'
    with closing(InformationService(source, database)) as service:
        tools = InformationTools(service)
        report = tools.call('information_manage_report', {
            'request_id': 'create-reward-areas', 'operation': 'create',
            'config': {'name': 'Declared reward area', 'detail': 'brief',
                       'queries': [_query(['claims'], root_id='loaded', task_id='first')]}})['report']
        brief = present_result(tools.call('information_query', {
            "view": "full", 'request_id': 'read-reward-areas', 'report_id': report['id']}))
        full = tools.call('information_get_result', {"view": "full", 'result_id': brief['result_id']})
        assert _candidate(full['items'][0]['fields']['claims'])['candidate_province_ids'] == [12, 13]
        assert present_result(full) == brief
        assert len(index.calls) == 1
    with closing(InformationService(source, database)) as service:
        restored = service.get_result(full['result_id'])
        assert restored == full and present_result(restored) == brief
