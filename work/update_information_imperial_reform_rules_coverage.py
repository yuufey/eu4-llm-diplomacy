"""Add a separately labelled static reform source without rewriting saved facts."""
from collections import Counter
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from bridge.information.imperial_reform_rules import StaticImperialReformRulesSource

STAGE = ROOT / 'work/runtime/information-empire-reform-definitions-20261103-116-001'
TARGET = ROOT / 'docs/信息字段覆盖.json'


def load(path):
    assert path.stat().st_size <= 10 * 1024 * 1024
    return json.loads(path.read_text(encoding='utf-8'))


def pin(path):
    data = path.read_bytes()
    return {'path': path.relative_to(ROOT).as_posix(), 'bytes': len(data),
            'sha256': hashlib.sha256(data).hexdigest()}


def main():
    receipt_path = (STAGE / sys.argv[1]).resolve(strict=True)
    receipt_path.relative_to(STAGE)
    receipt = load(receipt_path)
    assert receipt['status'] == 'passed' and receipt['pins_stable']
    assert len(receipt['periodic_results']) == 2 and receipt['reader_stopped']
    assert receipt['server_exit'] == 0 and receipt['current_passed_reforms_observed'] is False
    assert receipt['hre_definition_count'] == 25 and receipt['china_definition_count_excluded'] == 21
    evidence = pin(receipt_path)
    before = load(TARGET)
    data = deepcopy(before)
    topic = next(t for t in data['topics'] if t['topic_id'] == 'S01')
    old_topic = next(t for t in before['topics'] if t['topic_id'] == 'S01')
    descriptor = object.__new__(StaticImperialReformRulesSource).catalog()[0]
    name = 'StaticImperialReformRulesSource'
    assert name not in data['configuration']['adapters']
    field = deepcopy(descriptor['fields']['reforms'])
    field.update(mode='static_definition', triggers=['query', 'periodic'],
                 conditions_evaluated=False, effects_applied=False,
                 current_passed_reforms_observed=False, loaded_definition_set_verified=False,
                 validation_evidence=evidence)
    topic['fields']['reforms'].setdefault('additional_sources', []).append(field)
    topic.setdefault('additional_sources', []).append({
        'source': name, 'fields': ['reforms'], 'mode': 'static_definition',
        'period': 'static_definition', 'triggers': ['query', 'periodic'],
        'context_scope': 'static_rules', 'country_selector_semantics': 'global HRE definitions; no membership assertion',
        'current_passed_reforms_observed': False, 'conditions_evaluated': False,
        'effects_applied': False, 'loaded_definition_set_verified': False,
        'validation_evidence': evidence,
    })
    data['configuration']['adapters'].append(name)
    data['configuration']['static_imperial_reform_rules'] = {
        'source': name, 'enabled_by': '--empire-game-data', 'topic': 'S01', 'fields': ['reforms'],
        'scope': 'static_rules', 'period': 'static_definition', 'complete': False,
        'hre_definitions': 25, 'china_definitions_excluded': 21,
        'current_passed_reforms_observed': False, 'conditions_evaluated': False,
        'effects_applied': False, 'loaded_definition_set_verified': False,
        'validation_evidence': evidence,
    }
    stripped = deepcopy(data)
    stripped_topic = next(t for t in stripped['topics'] if t['topic_id'] == 'S01')
    if 'additional_sources' not in old_topic['fields']['reforms']:
        stripped_topic['fields']['reforms'].pop('additional_sources')
    else:
        stripped_topic['fields']['reforms']['additional_sources'] = deepcopy(old_topic['fields']['reforms']['additional_sources'])
    stripped_topic['additional_sources'] = deepcopy(old_topic.get('additional_sources', []))
    stripped['configuration']['adapters'] = deepcopy(before['configuration']['adapters'])
    stripped['configuration'].pop('static_imperial_reform_rules')
    assert stripped == before
    assert topic['validation_scope'] == old_topic['validation_scope']
    assert topic['validation_scope']['reforms_positive_observed'] is False
    assert data['counts'] == data['expected_counts'] == before['counts'] == before['expected_counts']
    assert len(data['topics']) == 74 and sum(len(t['fields']) for t in data['topics']) == 397
    assert dict(Counter(f['coverage'] for t in data['topics'] for f in t['fields'].values())) == data['counts']['field_counts']
    assert dict(Counter(t['status'] for t in data['topics'])) == data['counts']['topic_status_counts']
    assert data['goal_complete'] is False
    out = STAGE / 'coverage-update-001'
    out.mkdir(exist_ok=False)
    raw = TARGET.read_bytes()
    with (out / 'before.json').open('xb') as stream:
        stream.write(raw)
    temporary = TARGET.with_name(TARGET.name + '.116.tmp')
    with temporary.open('x', encoding='utf-8', newline='\n') as stream:
        json.dump(data, stream, ensure_ascii=False, indent=2)
        stream.write('\n')
    temporary.replace(TARGET)
    record = {'schema': 'information.imperial_reform_rules.coverage_update.v1',
              'status': 'passed', 'before': pin(out / 'before.json'), 'after': pin(TARGET),
              'counts_unchanged': True, 'only_allowed_paths_changed': True,
              'saved_and_live_empire_metadata_preserved': True, 'validation_evidence': evidence}
    with (out / 'receipt.json').open('x', encoding='utf-8') as stream:
        json.dump(record, stream, ensure_ascii=False, indent=2)
        stream.write('\n')
    print(json.dumps(record, ensure_ascii=False))


if __name__ == '__main__':
    main()
