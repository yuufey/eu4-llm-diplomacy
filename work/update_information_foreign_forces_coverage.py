"""Publish the two live-verified F02 force-statistic fields as partial."""
from collections import Counter
from copy import deepcopy
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / 'work/runtime/information-foreign-forces-20261029-001'


def read(path):
    assert 0 < path.stat().st_size <= 16 * 1024 * 1024
    return json.loads(path.read_bytes())


def counts(topics):
    fields = Counter(field['coverage'] for topic in topics for field in topic['fields'].values())
    statuses = Counter(topic['status'] for topic in topics)
    return {'topic_count': len(topics), 'field_count': sum(fields.values()),
        'topic_status_counts': {k: statuses[k] for k in ('available', 'partial', 'planned')},
        'field_counts': {k: fields[k] for k in ('available', 'partial', 'planned')},
        'available_topic_count': statuses['available'], 'callable_topic_count': statuses['available']}


def write(path, value):
    with path.open('x', encoding='utf-8', newline='\n') as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write('\n')


def main():
    path = ROOT / 'docs/信息字段覆盖.json'
    raw = path.read_bytes()
    matrix = json.loads(raw)
    before = deepcopy(matrix)
    assert matrix['counts']['field_counts'] == {'available': 62, 'partial': 185, 'planned': 150}
    receipt = read(STAGE / 'mcp-live-002/offline-reconciliation-001.json')
    discovery = read(STAGE / 'mcp-live-002/discovery.json')
    assert receipt['status'] == 'passed' and receipt['server_exit_code'] == 0
    assert receipt['source_pins_unchanged'] is True and receipt['checks']['no_active_subscriptions'] is True
    assert all(value is True for value in receipt['checks'].values())
    topic = next(row for row in discovery['topics'] if row['topic_id'] == 'F02')
    index = next(i for i, row in enumerate(matrix['topics']) if row['topic_id'] == 'F02')
    old = matrix['topics'][index]
    assert set(old['fields']) == set(topic['fields'])
    for key in ('visible_army', 'visible_navy'):
        assert old['fields'][key]['coverage'] == 'planned' and topic['fields'][key]['coverage'] == 'partial'
    for key in ('military_technology', 'manpower', 'visibility'):
        assert old['fields'][key]['coverage'] == topic['fields'][key]['coverage'] == 'partial'
    assert old['fields']['military_quality'] == topic['fields']['military_quality']
    matrix['topics'][index] = deepcopy(topic)
    matrix['F02'] = {key: deepcopy(topic[key]) for key in
        ('fields', 'context_scope', 'source', 'adapter_sources') if key in topic}
    matrix['counts'] = counts(matrix['topics'])
    matrix['expected_counts'] = deepcopy(matrix['counts'])
    assert matrix['counts']['field_counts'] == {'available': 62, 'partial': 187, 'planned': 148}
    assert matrix['counts']['topic_count'] == 74 and matrix['counts']['field_count'] == 397
    assert matrix['goal_complete'] is False
    assert all(a == b for a, b in zip(before['topics'], matrix['topics']) if a['topic_id'] != 'F02')
    with (STAGE / 'coverage-before-001.json').open('xb') as stream:
        stream.write(raw)
    updated = (json.dumps(matrix, ensure_ascii=False, indent=2) + '\n').encode('utf-8')
    path.write_bytes(updated)
    write(STAGE / 'coverage-update-001.json', {
        'status': 'updated_partial', 'goal_complete': False,
        'coverage_changes': {f'F02.{key}': ['planned', 'partial'] for key in ('visible_army', 'visible_navy')},
        'before_sha256': hashlib.sha256(raw).hexdigest(), 'after_sha256': hashlib.sha256(updated).hexdigest(),
        'configured_counts': matrix['counts'], 'actual_live_counts': counts(discovery['topics']),
        'scope': 'Native diplomacy soldier and ship statistics; quality, actual UI, freshness and complete battlefield visibility remain unclosed'})
    print(matrix['counts'])


if __name__ == '__main__':
    main()
