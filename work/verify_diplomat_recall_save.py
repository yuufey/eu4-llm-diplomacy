"""Read-only comparison of POR diplomat actions in the fixed recall saves."""
import json
from pathlib import Path
from local_config import user_data
from inspect_peace_save import find_country_container, find_country_body, top_level_entries


def diplomats(path):
    text = path.read_text(encoding='utf-8', errors='replace')
    body = find_country_body(find_country_container(text), 'POR')
    holder = next(e.body for e in top_level_entries(body) if e.key == 'diplomats')
    result = {}
    for envoy in top_level_entries(holder):
        if envoy.key != 'envoy':
            continue
        values = {e.key: e.value for e in top_level_entries(envoy.body) if e.value is not None}
        result[int(values['id'])] = int(values['action'])
    return result


if __name__ == '__main__':
    saves = user_data() / 'save games'
    before = diplomats(saves / 'llm_control_por_recall_before_20261007.eu4')
    after = diplomats(saves / 'llm_control_por_recall_after_20261007.eu4')
    if before != {0: 2, 1: 1, 2: 1} or after != {0: 1, 1: 1, 2: 1}:
        raise SystemExit('Serialized diplomat states differ from the expected recall transition.')
    report = {'player': 'POR', 'before_actions': before, 'after_actions': after,
              'diplomat_0_recalled': True, 'other_diplomats_unchanged': True,
              'reloaded_after_save': False}
    Path(__file__).with_name('runtime').joinpath('por-recall-save-comparison.json').write_text(
        json.dumps(report, indent=2), encoding='utf-8')
    print(json.dumps(report))
