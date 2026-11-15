"""Present verified outcome fields with their original combat-side scope."""
from copy import deepcopy

import pytest

from bridge.information.presentation import present_result
from bridge.tests.test_information_battle_brief import fixture_source, modeled_result, summary
from bridge.tests.test_information_battles import LIVE_V3_FIXTURE_PATH, event_id


def naval_result(tmp_path):
    source, _primary, fixture, _stream, _payload = fixture_source(tmp_path, LIVE_V3_FIXTURE_PATH)
    return modeled_result(source, event_id(fixture))


def put_annihilation(result, index):
    # These outcome states are synthetic presenter inputs over recorded counts.
    sides = result['items'][0]['fields']['sides']['value']
    field = {'status': 'known', 'value': {
        'basis': 'native_combat_side_overrun_marker', 'scope': 'whole_combat_side',
        'classification_scope': 'native_overrun_path_only', 'sides': [
            {'combat_side_index': side['combat_side_index'], 'participants': deepcopy(side['participants']),
             'annihilated': {'status': 'known', 'value': True} if side['combat_side_index'] == index
                           else {'status': 'unknown', 'reason': 'NON_OVERRUN_ANNIHILATION_PATHS_UNRESOLVED'}}
            for side in sides]}}
    result['items'][2]['fields']['annihilation'] = field
    return field


def put_retreat(result):
    side = next(side for side in result['items'][0]['fields']['sides']['value'] if side['observer_participated'])
    field = {'status': 'known', 'value': {'observer': result['context']['observer'],
        'combat_side_index': side['combat_side_index'], 'retreating': True,
        'scope': 'observer_owned_units_at_regular_battle_end', 'observed_unit_count': 1,
        'count_is_lower_bound': True, 'unit': 'native_army_or_fleet_objects'}}
    result['items'][2]['fields']['retreat'] = field
    return field


def pointed(result, path):
    value = result
    for key in path.split('/')[1:]:
        value = value[int(key)] if isinstance(value, list) else value[key]
    return value


def test_unit_removal_retreat_describes_state_without_inventing_a_start(tmp_path):
    result = naval_result(tmp_path)
    field = put_retreat(result)
    field['value']['scope'] = 'observer_owned_units_before_combat_removal'
    shown = present_result(result)
    view = summary(shown)
    side = next(side for side in view['sides'] if side['observer_participated'])
    assert side['outcomes']['retreat']['scope'] == field['value']['scope']
    assert '处于撤退状态' in view['text']
    assert '开始撤退' not in view['text']


def test_verified_annihilation_is_attached_to_the_same_side_without_changing_fields(tmp_path):
    result = naval_result(tmp_path)
    losing_index = 1 - result['items'][0]['fields']['winner']['value']['combat_side_index']
    put_annihilation(result, losing_index)
    original = deepcopy(result)
    shown = present_result(result)
    view = summary(shown)
    side = next(side for side in view['sides'] if side['combat_side_index'] == losing_index)
    outcome = side['outcomes']['annihilation']
    assert outcome['value'] is True and pointed(shown, outcome['source_path']) is True
    assert '该参战侧被歼灭。' in view['text']
    assert result == original and shown['items'] == original['items']


@pytest.mark.parametrize('count', [0, 3])
def test_ship_capture_keeps_real_zero_and_the_original_capturing_side(tmp_path, count):
    result = naval_result(tmp_path)
    field = result['items'][2]['fields']['ships_captured']
    field['value'].update(total=count, by_unit={'heavy_ship': count, 'light_ship': 0, 'galley': 0, 'transport': 0})
    shown = present_result(result)
    view = summary(shown)
    capturing = field['value']['capturing_side']['value']
    side = next(side for side in view['sides'] if side['combat_side_index'] == capturing['combat_side_index'])
    assert side['participants'] == capturing['participants']
    outcome = side['outcomes']['ships_captured']
    assert outcome['value'] == pointed(shown, outcome['source_path']) == count
    assert f'俘获舰船{count}艘' in view['text']


def test_verified_retreat_only_describes_the_observers_own_participating_units(tmp_path):
    result = naval_result(tmp_path)
    put_retreat(result)
    shown = present_result(result)
    view = summary(shown)
    matching = [side for side in view['sides'] if 'retreat' in side.get('outcomes', {})]
    assert len(matching) == 1 and matching[0]['observer_participated'] is True
    outcome = matching[0]['outcomes']['retreat']
    assert outcome['observer'] == result['context']['observer']
    assert pointed(shown, outcome['source_path']) is True
    assert '观察国有参战部队开始撤退' in view['text']


@pytest.mark.parametrize('field_name', ['annihilation', 'retreat', 'ships_captured'])
def test_unknown_outcomes_remain_unknown_and_keep_the_counts_usable(tmp_path, field_name):
    result = naval_result(tmp_path)
    original = {'status': 'unknown', 'reason': 'NOT_CAPTURED'}
    result['items'][2]['fields'][field_name] = original
    shown = present_result(result)
    view = summary(shown)
    assert view['facts'][field_name] == original
    assert all(field_name not in side.get('outcomes', {}) for side in view['sides'])
    assert all(side['initial_forces']['status'] == 'known' for side in view['sides'])


@pytest.mark.parametrize('damage', ['party', 'duplicate', 'boolean_index', 'unknown'])
def test_invalid_annihilation_does_not_acquire_the_other_sides_identity(tmp_path, damage):
    result = naval_result(tmp_path)
    field = put_annihilation(result, 0)
    side = next(side for side in field['value']['sides'] if side['combat_side_index'] == 0)
    if damage == 'party':
        side['participants'] = ['WRONG']
    elif damage == 'duplicate':
        field['value']['sides'].append(deepcopy(side))
    elif damage == 'boolean_index':
        side['combat_side_index'] = False
    else:
        side['annihilated'] = {'status': 'unknown', 'reason': 'NOT_OBSERVED'}
    view = summary(present_result(result))
    assert all('annihilation' not in side.get('outcomes', {}) for side in view['sides'])
    assert '被歼灭' not in view['text']


@pytest.mark.parametrize('damage', ['observer', 'side', 'scope', 'false'])
def test_invalid_or_unverified_retreat_cannot_become_an_observer_retreat(tmp_path, damage):
    result = naval_result(tmp_path)
    value = put_retreat(result)['value']
    changes = {'observer': ('observer', 'ZZZ'), 'side': ('combat_side_index', 1 - value['combat_side_index']),
               'scope': ('scope', 'foreign_units'), 'false': ('retreating', False)}
    key, changed = changes[damage]
    value[key] = changed
    view = summary(present_result(result))
    assert all('retreat' not in side.get('outcomes', {}) for side in view['sides'])
    assert '开始撤退' not in view['text']


@pytest.mark.parametrize('damage', ['party', 'unit', 'boolean_count', 'boolean_scale', 'negative'])
def test_invalid_capture_count_cannot_be_shown_as_a_known_capture(tmp_path, damage):
    result = naval_result(tmp_path)
    value = result['items'][2]['fields']['ships_captured']['value']
    if damage == 'party':
        value['capturing_side']['value']['participants'] = ['WRONG']
    else:
        changes = {'unit': ('unit', 'men'), 'boolean_count': ('total', True),
                   'boolean_scale': ('scale', True), 'negative': ('total', -1)}
        key, changed = changes[damage]
        value[key] = changed
    view = summary(present_result(result))
    assert all('ships_captured' not in side.get('outcomes', {}) for side in view['sides'])
    assert '俘获舰船' not in view['text']
