"""Synthetic composition checks over recorded identity fixtures, never live UI."""
from copy import deepcopy

import pytest

from bridge.information.battle_display_composition import (
    project_button_candidates, project_display_composition, project_readable_text,
)
from bridge.tests.test_information_battle_compact_loss_candidates import _synthetic_land_decoded


def _decoded(*, flag=0, layout=0, kind=1):
    decoded = _synthetic_land_decoded()
    decoded['context']['kind'] = kind
    context = decoded['display_context']
    context.update(button_flag_raw=flag, layout_raw=layout, battle_kind=kind)
    context['fields']['definition_key']['raw_hex'] = (
        b'LANDBATTLEOVER' if kind == 1 else b'NAVALBATTLEOVER').hex()
    for index, raw in enumerate((b'OK', b'Accept', b'Cancel'), 1):
        context['fields'][f'button{index}'] = {'state': 'observed', 'raw_hex': raw.hex()}
    return decoded


@pytest.mark.parametrize('flag,expected', [(0, [True, False, True]),
                                          (1, [False, True, True]),
                                          (255, [False, True, True])])
@pytest.mark.parametrize('kind', [1, 2])
def test_button_branches_use_full_byte_zero_vs_nonzero_and_never_visibility(flag, expected, kind):
    decoded = _decoded(flag=flag, kind=kind)
    original = deepcopy(decoded)
    buttons = project_button_candidates(decoded)
    assert buttons['status'] == 'known'
    assert [x['configured_text_assignment_condition'] for x in buttons['controls']] == expected
    assert [x['widget'] for x in buttons['controls']] == ['CenterOK', 'AgreeButton', 'DeclineButton']
    assert [x['text'] for x in buttons['controls']] == ['OK', 'Accept', 'Cancel']
    assert all(x['actual_visibility']['status'] == 'unknown' for x in buttons['controls'])
    assert all(x['format_argument_count'] == 0 for x in buttons['controls'])
    assert decoded == original


@pytest.mark.parametrize('raw,status', [
    (b'', 'known'), (b'Literal tail $', 'known'), (b'$NAME$', 'unknown'),
    (b'$NUMBER|0$', 'unknown'), (b'$$', 'unknown'), (b'$COUNTRY$', 'unknown'),
    (b'\x10', 'unknown'), (b'A\0B', 'unknown'), (b'A' * 8192, 'known'),
    (b'A' * 8193, 'unknown'),
])
def test_button_zero_arguments_preserve_literals_and_reject_missing_substitution_or_bad_text(raw, status):
    decoded = _decoded()
    decoded['display_context']['fields']['button1'] = {'state': 'observed', 'raw_hex': raw.hex()}
    controls = project_button_candidates(decoded)['controls']
    assert controls[0]['status'] == status
    if status == 'known':
        assert controls[0]['raw_hex'] == raw.hex()
    assert controls[1]['status'] == controls[2]['status'] == 'known'


def test_button_absence_is_unknown_not_hidden_and_does_not_retract_other_labels():
    decoded = _decoded()
    decoded['display_context']['fields']['button2'] = {'state': 'absent'}
    controls = project_button_candidates(decoded)['controls']
    assert controls[1]['status'] == 'unknown'
    assert 'NOT_HIDDEN' in controls[1]['reason']
    assert controls[1]['actual_visibility']['status'] == 'unknown'
    assert controls[0]['status'] == controls[2]['status'] == 'known'


@pytest.mark.parametrize('change', ['sequence', 'date', 'definition', 'language'])
def test_unbound_display_context_cannot_supply_button_or_composed_text(change):
    decoded = _decoded()
    context = decoded['display_context']
    if change == 'sequence':
        context['sequence'] += 1
    elif change == 'date':
        context['raw_date'] += 24
    elif change == 'definition':
        context['fields']['definition_key']['raw_hex'] = b'NAVALBATTLEOVER'.hex()
    else:
        context['fields']['language'] = {'state': 'unknown'}
    assert project_button_candidates(decoded)['status'] == 'unknown'
    assert project_display_composition(decoded)['status'] == 'unknown'


@pytest.mark.parametrize('layout,chosen', [(0, 'land_compact'), (1, 'land_detailed'), (-1, 'land_detailed')])
def test_layout_branch_is_separate_from_actual_layout_and_compact_variant_text(layout, chosen):
    decoded = _decoded(layout=layout)
    original = deepcopy(decoded)
    composed = project_display_composition(decoded)
    assert composed['status'] == 'known'
    assert composed['configured_layout'] == chosen
    assert composed['actual_layout']['status'] == 'unknown'
    compact = [x for x in composed['controls'] if x.get('widget') in ('OurLost', 'EnemyLost')]
    assert len(compact) == 2
    assert all(x['configured_text_assignment_condition'] == (layout == 0) for x in compact)
    assert all(x['text']['status'] == 'known' and x['text']['derived'] for x in compact)
    assert composed['line1']['basis'] == 'derived_name_line_candidate'
    assert composed['line1']['native_line1_verified'] is False
    assert composed['title']['status'] == 'unknown'
    assert composed['full_display_complete'] is composed['visibility_verified'] is False
    assert decoded == original


def test_copied_text_duplicates_unknown_and_frame_inputs_are_preserved():
    decoded = _decoded(layout=1)
    pairs = decoded['message_template']['pairs']
    pairs.extend({'key_raw_hex': key.hex(), 'value_raw_hex': value.hex()} for key, value in
                 [(b'OURLEADER', b'Copied leader'), (b'OURPRESTIGE', b'1'),
                  (b'OURPRESTIGE', b'2'), (b'OURFIRE', b'3'), (b'COUNTRY', b'POR')])
    decoded['message_template']['pair_count'] = len(pairs)
    composed = project_display_composition(decoded)
    controls = {x.get('widget'): x for x in composed['controls']}
    assert controls['OurLeader']['text']['value'] == 'Copied leader'
    assert controls['OurLeader']['text']['derived'] is False
    assert controls['our_prestige']['text']['status'] == 'unknown'
    assert controls['our_fire_value']['text']['status'] == 'unsupported'
    assert 'native_frame_requests' in controls['our_fire_value']
    assert composed['title']['status'] == 'unknown'  # COUNTRY is never the title/observer.


def test_native_line1_precedes_the_name_candidate_without_claiming_full_window():
    decoded = _decoded()
    decoded['native_text']['text_fields']['line1_text'] = {
        'status': 'known', 'source': 'native_line1', 'raw_hex': b'Native text'.hex()}
    composed = project_display_composition(decoded)
    assert composed['line1']['text'] == 'Native text'
    assert composed['line1']['native_line1_verified'] is True
    assert composed['line1']['derived'] is False
    assert composed['complete'] is composed['visibility_verified'] is False


def test_naval_does_not_select_a_land_layout_or_invent_compact_controls():
    composed = project_display_composition(_decoded(kind=2, layout=0))
    assert composed['configured_layout'] == 'naval'
    assert all(x['layout'] == 'naval' for x in composed['controls'])
    assert all(x.get('widget') not in ('OurLost', 'EnemyLost') for x in composed['controls'])


@pytest.mark.parametrize('kind,layout', [(1, 0), (1, 1), (2, 0)])
def test_readable_sections_resolve_to_same_record_and_selected_branch(kind, layout):
    composed = project_display_composition(_decoded(kind=kind, layout=layout))
    before = deepcopy(composed)
    report = project_readable_text(composed)
    assert composed == before
    assert report['complete'] is report['selected_text_complete']
    assert report['is_native_raw_text'] is False
    assert report['remaining_gaps'] == composed['remaining_gaps']
    assert report['known_section_count'] + report['unknown_section_count'] == len(report['sections'])
    for section in report['sections']:
        value = composed
        for part in section['source_path'].split('/')[1:]:
            value = value[int(part)] if isinstance(value, list) else value[part]
        if section['status'] == 'known':
            text = value.get('text', value.get('value'))
            assert f'[{section["key"]}] {text}\n' in report['text']
            assert section['basis'] == value['basis']
            assert section['derived'] == value.get('derived', True)
        else:
            assert f'[{section["key"]}] [unknown ' in report['text']
    included_paths = {section['source_path'] for section in report['sections']}
    for index, control in enumerate(composed['controls']):
        expected = (control['configured_text_assignment_condition'] is True
                    and control['value_kind'] in ('text', 'formatted_text'))
        assert (f'/controls/{index}/text' in included_paths) is expected
    assert '/buttons/controls/0' in included_paths
    assert '/buttons/controls/1' not in included_paths


def test_readable_text_keeps_copied_literals_and_duplicate_keys_as_separate_sections():
    composed = project_display_composition(_decoded())
    copied = next(item for item in composed['controls']
                  if item['value_kind'] == 'text' and item['configured_text_assignment_condition'])
    copied['text'] = {'status': 'known', 'value': '$NAME$\n§G原始文字',
                      'basis': 'same_event_copied_native_control_input', 'derived': False}
    composed['controls'].append(deepcopy(copied))
    report = project_readable_text(composed)
    matching = [item for item in report['sections'] if item['key'] == copied['template_key']]
    assert len(matching) == 2 and matching[0]['source_path'] != matching[1]['source_path']
    assert all(item['derived'] is False for item in matching)
    assert report['text'].count('$NAME$\n§G原始文字') == 2


def test_readable_text_bounds_utf8_output_and_lists_omitted_sections(monkeypatch):
    from bridge.information import battle_display_composition
    monkeypatch.setattr(battle_display_composition, 'MAX_READABLE_TEXT_BYTES', 32)
    composed = project_display_composition(_decoded())
    composed['line1']['text'] = '中文' * 20
    report = project_readable_text(composed)
    assert len(report['text'].encode('utf-8')) <= 32
    assert report['output_limit_reached'] is True
    assert 'Line1' in report['omitted_section_keys']
    assert report['sections'][0]['status'] == 'known'
    assert report['sections'][0]['included_in_text'] is False
    assert report['complete'] is False
