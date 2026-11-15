"""Counter semantics and bounded member evaluation on a synthetic RPM world."""
from unittest.mock import patch

from bridge.information import mission_trigger_memory as m
from bridge.information import mission_trigger_source as source
from bridge.tests.test_information_mission_trigger_memory import (
    _fixture, _install_root, _set_method, _write_group,
)
from bridge.tests.test_information_mission_province_triggers import _write_province_leaf


def fixture(ids=(), threshold=1, mode=0, body='empty', admitted=True):
    reader, base, country, loaded, guards, _, pointers = _fixture()
    ref = (1 << 56) | (122 << 32) | int.from_bytes(b'FRA', 'little')
    reader.qword_put(country + 0x20, ref)
    counter, child = 0xA60000, 0xA61000
    _write_group(reader, base, counter, [] if body == 'empty' else [child], 'nested_and',
                 token=0x2BF9 if mode == 0 else 0x37FC)
    reader.qword_put(counter, _set_method(reader, base, 'unsupported',
                     method_rva=m.COUNT_EVALUATE_RVA, vtable_rva=0x1D185C0))
    reader.dword_put(counter + 0x68, threshold, signed=True)
    reader.put(counter + 0x6C, bytes([mode]))
    if body == 'owned':
        _write_province_leaf(reader, base, child, 'owned')
    elif body == 'false':
        reader.qword_put(child, _set_method(reader, base, 'unsupported',
                         method_rva=m.STORED_BOOLEAN_EVALUATE_RVA, vtable_rva=0x1D18100))
        reader.dword_put(child + 0x50, 0)
        reader.put(child + 0x68, b'\x00')
    _install_root(reader, base, pointers['task_a'], [counter])
    domain_calls = []

    def domain(*args):
        domain_calls.append(args[-1])
        return {'status': 'known', 'country': 'FRA', 'country_pointer': country,
                'root_reference': ref, 'province_ids': list(ids), 'source': 'synthetic'}

    def province(_read, _base, pid):
        if not admitted:
            return {'status': 'unknown', 'reason': 'not_admitted'}
        return {'status': 'known', 'province_id': pid, 'observer_pointer': country,
                'observer_reference': ref, 'owner': {'status': 'known', 'reference': ref, 'tag': 'FRA'}}

    def run(**overrides):
        args = {'code_guards': guards, 'count_domain_reader': domain, 'province_reader': province}
        args.update(overrides)
        result = m.capture_triggers(reader, base, country, loaded, **args)
        assert result['status'] == 'observed', result.get('reason')
        return result, result['tasks'][0]['tree']['children'][0]

    return reader, counter, child, domain_calls, run


def test_empty_domain_is_false_for_nonpositive_threshold():
    for threshold in (0, -10):
        _, _, _, _, run = fixture(threshold=threshold)
        _, node = run()
        assert node['evaluation']['satisfied'] is False
        assert node['metric']['domain_count'] == 0


def test_universal_filter_preserves_duplicate_domain_members():
    _, _, _, calls, run = fixture(ids=(42, 42), threshold=2)
    result, node = run()
    assert node['evaluation']['satisfied'] is True
    assert node['metric']['lower_bound'] == node['metric']['upper_bound'] == 2
    assert node['samples'] == [] and result['count_evaluation_ops'] == 0
    assert calls == [0]


def test_false_filter_with_zero_threshold_is_still_false():
    _, _, _, _, run = fixture(ids=(42, 43), threshold=0, body='false')
    _, node = run()
    assert node['evaluation']['satisfied'] is False
    assert node['filter']['evaluation']['satisfied'] is False


def test_sampled_owned_filter_and_unbound_template():
    _, _, _, _, run = fixture(ids=(42, 43), threshold=2, body='owned')
    result, node = run()
    assert node['evaluation']['satisfied'] is True
    assert node['metric'] == {'threshold': 2, 'domain_count': 2, 'lower_bound': 2,
        'upper_bound': 2, 'sampled_count': 2, 'fully_evaluated': True}
    assert node['filter']['children'][0]['metric']['province_id'] is None
    assert node['filter']['evaluation']['status'] == 'unknown'
    assert result['total_nodes'] == 4 and result['count_evaluation_ops'] == 4
    assert result['node_metadata_cache']['hits'] > 0
    counter = [0]
    tree = result['tasks'][0]['tree']
    assert source._validate_tree(tree, depth=0, counter=counter, is_root=True)
    assert counter[0] == result['total_nodes']
    assert source._count_leaves(tree) == (1, 1, 0, 0)


def test_unsampled_members_remain_possible():
    _, _, _, _, run = fixture(ids=tuple(range(1, 9)), threshold=5, body='owned')
    _, node = run()
    assert node['evaluation']['status'] == 'unknown'
    assert (node['metric']['lower_bound'], node['metric']['upper_bound']) == (4, 8)
    assert node['metric']['fully_evaluated'] is False


def test_unadmitted_member_identity_is_not_exposed():
    _, _, _, _, run = fixture(ids=(42,), body='owned', admitted=False)
    _, node = run()
    assert node['samples'][0]['province_id'] is None
    assert node['samples'][0]['evaluation']['status'] == 'unknown'
    assert node['evaluation']['status'] == 'unknown'


def test_bad_mode_and_bad_identity_do_not_produce_counts():
    reader, counter, _, calls, run = fixture(ids=(42,))
    reader.put(counter + 0x6C, b'\x01')
    _, node = run()
    assert node['evaluation']['reason'] == 'count_token_mode_unsupported' and calls == []
    reader.put(counter + 0x6C, b'\x00')
    _, node = run(count_domain_reader=lambda *a: {'status': 'known', 'country': 'POR'})
    assert node['evaluation']['reason'] == 'count_domain_contract_invalid'


def test_evaluation_budget_is_local_and_metadata_is_fresh_next_capture():
    reader, _, child, _, run = fixture(ids=(42,), body='owned')
    with patch.object(m, 'MAX_COUNT_EVALUATION_OPS', 1):
        result, node = run()
    assert result['count_evaluation_ops'] == 1
    assert node['evaluation']['status'] == 'unknown'
    # A new outer capture must not reuse an old node's method or payload.
    reader.qword_put(child, _set_method(reader, reader.module_base, 'unsupported',
                     method_rva=m.STORED_BOOLEAN_EVALUATE_RVA, vtable_rva=0x1D18100))
    reader.put(child + 0x68, b'\x02')
    _, node = run()
    assert node['evaluation']['satisfied'] is True
