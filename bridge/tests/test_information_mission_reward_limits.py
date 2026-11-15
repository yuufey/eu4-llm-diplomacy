"""Current selected reward limits retain native scope and snapshot boundaries."""
from contextlib import closing
from copy import deepcopy
import json
from types import SimpleNamespace

import pytest

from bridge.information import mission_reward_inputs as native
from bridge.information import mission_reward_limits as limits
from bridge.information.composite import CompositeSource
from bridge.information.presentation import present_result
from bridge.information.service import InformationService
from bridge.information.tools import InformationTools
from bridge.tests import test_information_province_interest_memory as fixture
from bridge.tests.test_information_foreign_technology_capture import RecordingReader
from bridge.tests.test_information_mission_reward_scopes import _source, _candidate
from bridge.tests.test_information_mission_reward_rules_integration import _query, _ast_node


def _inputs(context, ids, **checks):
    return {key: context.get(key) for key in ('observer', 'session_id', 'game_date')} | {
        'provinces': {str(value): {'status': 'known', 'checks': {
            name: {'status': 'known', 'value': result} for name, result in checks.items()}}
                      for value in ids}}


def _adapter(tmp_path, predicate='is_core'):
    source, index = _source(tmp_path)
    effect = source.base_source.definitions.values['loaded']['tasks'][0]['effect']
    effect['children'][0]['children'][0]['children'] = [
        _ast_node('NOT', 23, children=(_ast_node(predicate, 24, value='ROOT'),))]
    return source, index


@pytest.mark.parametrize('value,expected', [(True, []), (False, [12, 13]), (None, [])])
def test_current_limits_are_distinct_from_actual_execution(tmp_path, value, expected):
    source, _ = _adapter(tmp_path)
    source.limit_reader = lambda ids, context: _inputs(context, ids, is_core=value)
    result = source.read(_query(['claims'], root_id='loaded', task_id='first'))
    candidate = _candidate(result['fields']['claims'])
    current = candidate['current_limit_evaluation']
    assert current['satisfying_province_ids'] == expected
    assert current['unknown_province_ids'] == ([12, 13] if value is None else [])
    assert current['execution_observed'] is False and candidate['applied'] == 'unknown'


@pytest.mark.parametrize('failure', ['session', 'date', 'observer', 'exception', 'shape'])
def test_mixed_or_failed_inputs_do_not_become_known(tmp_path, failure):
    source, _ = _adapter(tmp_path)
    def read(ids, context):
        if failure == 'exception':
            raise OSError('offline fixture')
        result = _inputs(context, ids, is_core=False)
        if failure == 'shape':
            result['provinces'] = {str(value): [] for value in ids}
        else:
            result[{'session': 'session_id', 'date': 'game_date', 'observer': 'observer'}[failure]] = 'other'
        return result
    source.limit_reader = read
    result = source.read(_query(['claims'], root_id='loaded', task_id='first'))
    assert _candidate(result['fields']['claims'])['current_limit_evaluation']['unknown_province_ids'] == [12, 13]


def test_unsupported_script_never_requests_extra_inputs(tmp_path):
    source, _ = _adapter(tmp_path, 'unsupported_predicate')
    calls = []
    source.limit_reader = lambda *args: calls.append(args)
    result = source.read(_query(['claims'], root_id='loaded', task_id='first'))
    assert not calls
    assert _candidate(result['fields']['claims'])['current_limit_evaluation']['reason'] == 'REWARD_LIMIT_SHAPE_UNSUPPORTED'


def test_map_changes_during_native_inputs_retract_current_evaluation(tmp_path):
    source, index = _adapter(tmp_path)
    def read(ids, context):
        index.revision += 1
        return _inputs(context, ids, is_core=False)
    source.limit_reader = read
    result = source.read(_query(['claims'], root_id='loaded', task_id='first'))
    assert _candidate(result['fields']['claims'])['status'] == 'unknown'
    assert 'current_limit_evaluation' not in _candidate(result['fields']['claims'])


def test_province_and_output_budgets_are_explicit(tmp_path, monkeypatch):
    source, index = _adapter(tmp_path)
    index.members = [1, 2, 3]
    monkeypatch.setattr(limits, 'MAX_PROVINCES', 2)
    seen = []
    source.limit_reader = lambda ids, context: seen.append(ids) or _inputs(context, ids, is_core=False)
    query = _query(['claims'], root_id='loaded', task_id='first')
    result = source.read(query)
    current = _candidate(result['fields']['claims'])['current_limit_evaluation']
    assert seen == [[1, 2]] and current['satisfying_province_ids'] == [1, 2]
    assert current['unknown_province_ids'] == [3] and current['omitted_province_row_count'] == 1
    monkeypatch.setattr(limits, 'MAX_OUTPUT_BYTES', 1)
    result = source.read(query)
    assert _candidate(result['fields']['claims'])['current_limit_evaluation']['reason'] == 'REWARD_LIMIT_OUTPUT_BUDGET'


def test_normal_tools_and_reopen_preserve_current_limits_and_brief(tmp_path):
    adapter, _ = _adapter(tmp_path)
    adapter.limit_reader = lambda ids, context: _inputs(context, ids, is_core=False)
    source = CompositeSource(adapter.base_source.base_source, [adapter])
    database = tmp_path / 'limits.sqlite3'
    with closing(InformationService(source, database)) as service:
        tools = InformationTools(service)
        report = tools.call('information_manage_report', {
            'request_id': 'create-limits', 'operation': 'create',
            'config': {'name': 'Current mission reward limits', 'detail': 'brief',
                       'queries': [_query(['claims'], root_id='loaded', task_id='first')]}})['report']
        brief = present_result(tools.call('information_query', {
            "view": "full", 'request_id': 'current-limits', 'report_id': report['id']}))
        full = tools.call('information_get_result', {"view": "full", 'result_id': brief['result_id']})
        assert present_result(full) == brief
        text = brief['presentation']['mission_claim_summaries'][0]['text']
        assert '满足地区奖励限制的省份为 12, 13' in text and '实际执行状态未知' in text
    with closing(InformationService(source, database)) as service:
        assert service.get_result(full['result_id']) == full


def _native_fixture(*, core=False, owned=False, subject=False, discovered=True):
    image = fixture.make_image(discovered=discovered)
    profile = native._load_profile()
    for guard in profile['code_guards']:
        image.put(fixture.BASE + int(guard['rva'], 0), bytes.fromhex(guard['bytes']))
    image.put_i32(fixture.WORLD + 0x1DD0, 56566584)
    image.put_u64(fixture.WORLD + 0x1E60, fixture._fullref('DEN', fixture.DEN_SLOT))
    owner_tag, owner_slot = ('FRA', fixture.FRA_SLOT) if owned else ('ENG', fixture.ENG_SLOT)
    record = fixture._province_record()
    image.put_u64(record + fixture.state_memory.OWNER_FULLREF_OFFSET, fixture._fullref(owner_tag, owner_slot))
    image.put_u64(record + fixture.state_memory.CONTROLLER_FULLREF_OFFSET, fixture._fullref(owner_tag, owner_slot))
    if core:
        fixture._put_core_vector(image, [fixture._fullref('FRA', fixture.FRA_SLOT)])
    owner_pointer = fixture.COUNTRY_BASE + owner_slot * 0x1000
    if subject:
        parent = fixture._fullref('FRA', fixture.FRA_SLOT)
        relation_table, relation, rows, holder, kind = (0x6600000000 + i * 0x10000 for i in range(5))
        image.put_u64(owner_pointer + 0x18F0, parent)
        image.put_u64(owner_pointer + 0x1510, relation_table)
        image.put_u64(relation_table + fixture.FRA_SLOT * 72, relation)
        image.put_u64(relation_table + fixture.FRA_SLOT * 72 + 0x10, parent)
        image.put_u64(relation + 0x128, rows)
        image.put_i32(relation + 0x134, 1)
        image.put(rows, fixture.FRA_SLOT.to_bytes(4, 'little') + bytes(4) + holder.to_bytes(8, 'little'))
        image.put_u64(holder + 0x40, kind)
        image.put(kind + 0x151, b'\x01\x00')
    reader = RecordingReader(image)
    observation = native._observe_for(fixture.PROVINCE_ID)(reader, fixture.BASE, 'FRA', profile)
    identity = {'binding_verified': True, 'process_creation_filetime': 123,
                'process_path_sha256': native.owner.EXE_SHA256}
    report = {'schema': native.SCHEMA, 'status': 'observed' if observation['stable'] else 'unknown',
              'completed': observation['stable'], 'request': {'country': 'FRA', 'observer': 'FRA',
              'session_id': 'reward-test', 'creation_filetime': 123},
              'profile_sha256': native.PROFILE_SHA256, 'identity': identity,
              'identity_after': deepcopy(identity), 'module_base': hex(fixture.BASE),
              'observation': observation, 'raw_reads': reader.read_log,
              'cleanup': {'status': 'closed', 'closed': True, 'success': True},
              'access': {'read_only': True, 'native_function_invoked': False, 'writes': False,
                         'UI_control': False, 'date_advance': False, 'save_or_reload': False,
                         'limit_bytes': native.owner.MAX_READ_BYTES,
                         'bytes_requested': reader.bytes_requested, 'calls': reader.calls}}
    context = {'status': 'ready', 'observer': 'FRA', 'session_id': 'reward-test',
               'game_date': 56566584, 'game_version': '1.37.4', 'game_sha256': native.owner.EXE_SHA256}
    return report, context, image


@pytest.mark.parametrize('core,owned,subject', [(False, False, False), (True, True, False), (False, False, True)])
def test_real_reused_memory_readers_and_trace_replay(core, owned, subject):
    report, context, _ = _native_fixture(core=core, owned=owned, subject=subject)
    assert native.validate_capture(report, context, 123, fixture.PROVINCE_ID)
    checks = report['observation']['backend']['after']['checks']
    assert checks['is_core'] == {'status': 'known', 'value': core}
    assert checks['owned_by'] == {'status': 'known', 'value': owned}
    assert checks['country_or_non_sovereign_subject_holds'] == {'status': 'known', 'value': owned or subject}
    assert native.validate_capture(json.loads(json.dumps(report)), context, 123, fixture.PROVINCE_ID)


@pytest.mark.parametrize('tamper', ['province', 'date', 'projection', 'trace', 'identity'])
def test_capture_tampering_is_rejected(tamper):
    report, context, _ = _native_fixture()
    province_id = fixture.PROVINCE_ID
    if tamper == 'province':
        province_id += 1
    elif tamper == 'date':
        context['game_date'] += 24
    elif tamper == 'projection':
        report['observation']['backend']['after']['checks']['is_core']['value'] = True
    elif tamper == 'trace':
        report['raw_reads'].pop()
    else:
        report['identity_after']['process_creation_filetime'] += 1
    assert not native.validate_capture(report, context, 123, province_id)


def test_undiscovered_province_never_produces_known_reward_inputs():
    report, context, image = _native_fixture(discovered=False)
    checks = report['observation']['backend']['after']['checks']
    assert all(check['status'] == 'unknown' for check in checks.values())
    assert not any(label.startswith('reward_limit.') for _, _, label in image.reads)


def test_public_reader_strips_native_pointers_and_binds_session(tmp_path):
    report, context, _ = _native_fixture()
    source = SimpleNamespace(session=SimpleNamespace(directory=tmp_path, record={'creation_filetime': 123}))
    reader = native.NativeMissionRewardInputs(source, capture_reader=lambda *args: deepcopy(report))
    result = reader([fixture.PROVINCE_ID], context)
    row = result['provinces'][str(fixture.PROVINCE_ID)]
    assert row['status'] == 'known' and set(row) == {'status', 'checks', 'basis', 'profile_sha256'}
    assert '0x' not in json.dumps(result)
    context['session_id'] = 'other'
    assert reader([fixture.PROVINCE_ID], context)['provinces'][str(fixture.PROVINCE_ID)]['status'] == 'unknown'


def test_native_subject_drift_and_guard_tampering_withdraw_known_results():
    _, _, image = _native_fixture()
    owner_pointer = fixture.COUNTRY_BASE + fixture.ENG_SLOT * 0x1000
    changing = fixture.MutatingReader(image, 'reward_limit.owner_parent_reference',
        lambda: image.put_u64(owner_pointer + 0x18F0, fixture._fullref('FRA', fixture.FRA_SLOT)))
    profile = native._load_profile()
    observed = native._observe_for(fixture.PROVINCE_ID)(changing, fixture.BASE, 'FRA', profile)
    assert changing.mutated and observed['stable'] is False
    guard = next(row for row in profile['code_guards'] if row['name'] == 'subject_type_getter')
    image.put(fixture.BASE + int(guard['rva'], 0), b'\x00')
    with pytest.raises(ValueError, match='RUNTIME_CODE_MISMATCH'):
        native._observe_for(fixture.PROVINCE_ID)(image, fixture.BASE, 'FRA', profile)


@pytest.mark.parametrize('operator,known,expected', [('AND', False, False), ('AND', True, None),
                                                  ('OR', True, True), ('OR', False, None)])
def test_three_valued_boolean_conditions(operator, known, expected):
    node = _ast_node('limit', 1, children=(
        _ast_node(operator, 2, children=(
            _ast_node('is_core', 3, value='ROOT'), _ast_node('owned_by', 4, value='ROOT'))),))
    assert limits._supported(node)
    assert limits._evaluate(node, {'is_core': {'status': 'known', 'value': known}}) is expected
