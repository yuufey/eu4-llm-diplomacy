"""Expose existing battle tradition and exhaustion operands through B03."""
from contextlib import closing
from copy import deepcopy

import pytest

from bridge.information import InformationService
from bridge.information.battle_effects import project_effects
from bridge.information.battle_effect_text import project_effect_text_candidates
from bridge.information.presentation import present_concise, present_result
from bridge.information.tools import InformationTools
from bridge.tests.test_information_battle_effects import capture
from bridge.tests.test_information_battle_brief import configuration, fixture_source, summary
from bridge.tests.test_information_battles import LIVE_V3_FIXTURE_PATH, LIVE_V4_FIXTURE_PATH, event_id


@pytest.mark.parametrize('filename,kind', [
    ('information_battle_naval_seq3_live_v3_1374.json', 'naval'),
    ('information_battle_FRA_live_v2_1374.json', 'land'),
])
def test_effects_reuse_the_existing_text_operands_and_combat_side_order(filename, kind):
    fixture, decoded = capture(filename)
    mapping = fixture.get('expected_mapping', [1, 0])
    effects = project_effects(decoded, mapping, int(fixture['recorded_observer_ref'], 16))
    candidates = project_effect_text_candidates(decoded, mapping=mapping)['candidates']
    tradition = 'naval_tradition' if kind == 'naval' else 'army_tradition'
    for field_name, suffix in ((tradition, 'TRADITION'), ('war_exhaustion', 'EXHAUSTION')):
        field = effects[field_name]
        assert field['status'] == 'known'
        assert field['value']['unit'] == field_name
        assert field['value']['scale'] == 1000
        assert field['value']['scope'] == 'whole_combat_side'
        for side, prefix in zip(field['value']['sides'], ('OUR', 'ENEMY')):
            candidate = candidates[prefix + suffix]
            assert candidate['status'] == 'known'
            assert side['raw'] == candidate['raw_operand']
            assert candidate['value'].endswith(side['display_numeric'])
            assert side['combat_side_index'] == candidate['combat_side_index']
    if kind == 'land':
        assert effects['naval_tradition'] == {
            'status': 'unsupported', 'reason': 'NAVAL_TRADITION_REQUIRES_NAVAL_BATTLE'}
    else:
        assert effects['army_tradition']['reason'] == 'NAVAL_TRADITION_IS_NOT_ARMY_TRADITION'


def test_signed_exhaustion_operands_keep_truncation_and_negative_zero():
    fixture, decoded = capture('information_battle_naval_seq3_live_v3_1374.json')
    decoded = deepcopy(decoded)
    decoded['observation']['summary']['raw_i32'][:6] = [1999, 1, 0, 0, -1, 1099]
    effects = project_effects(decoded, fixture['expected_mapping'], int(fixture['recorded_observer_ref'], 16))
    assert [side['display_numeric'] for side in effects['naval_tradition']['value']['sides']] == ['+1.9', '+0.0']
    assert [(side['raw'], side['amount_decimal'], side['display_numeric'])
            for side in effects['war_exhaustion']['value']['sides']] == [
        (-1, '-0.001', '-0.00'), (1099, '1.099', '+1.09')]


@pytest.mark.parametrize('path,tradition,label', [
    (LIVE_V3_FIXTURE_PATH, 'naval_tradition', '海军传统'),
    (LIVE_V4_FIXTURE_PATH, 'army_tradition', '陆军传统'),
])
def test_public_query_brief_subscription_and_reopen_keep_the_new_effects(tmp_path, path, tradition, label):
    source, _primary, fixture, _db, _payload = fixture_source(tmp_path, path)
    database = tmp_path / 'information.sqlite3'
    with closing(InformationService(source, database)) as service:
        catalog = next(topic for topic in service.discover()['topics'] if topic['topic_id'] == 'B03')
        assert catalog['fields']['naval_tradition']['supported_battle_types'] == ['naval']
        assert catalog['fields']['war_exhaustion']['supported_battle_types'] == ['land', 'naval']
        report = service.manage_report('report', 'create', config=configuration())['report']
        subscription = service.manage_subscription('subscription', 'create', config={
            'name': 'Battle effects', 'kind': 'event', 'enabled': True,
            'report_id': report['id'], 'event': {'types': ['battle_observation']}})['subscription']
        tick = InformationTools(service).call('information_tick', {})
        assert len(tick['results']) == 1
        delivered = tick['results'][0]
        stored = service.get_result(delivered['result_id'])
        view = summary(present_result(stored))
        assert label in view['text'] and '厌战' in view['text']
        for side in view['sides']:
            assert side['effects'][tradition]['status'] == 'known'
            assert side['effects']['war_exhaustion']['status'] == 'known'
        query = configuration(event_id(fixture))['queries'][2]
        queried = service.query('selected', queries=[query])
        assert queried['items'][0]['fields'] == stored['items'][2]['fields']
        assert service.tick()['results'] == []
        service.manage_subscription('cancel', 'cancel', subscription_id=subscription['id'],
                                    expected_version=subscription['version'])
    with closing(InformationService(source, database)) as service:
        assert service.get_result(stored['result_id']) == stored
        assert present_concise(stored) == delivered


def test_unresolved_side_mapping_keeps_new_effects_unknown():
    fixture, decoded = capture('information_battle_naval_seq3_live_v3_1374.json')
    effects = project_effects(decoded, [None, None], int(fixture['recorded_observer_ref'], 16))
    for field_name in ('naval_tradition', 'war_exhaustion'):
        assert effects[field_name] == {'status': 'unknown', 'reason': 'BATTLE_EFFECT_SIDE_MAPPING_UNRESOLVED'}
