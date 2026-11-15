"""Persist the same-event result text independently of the brief presenter."""
from contextlib import closing
from copy import deepcopy

import pytest

from bridge.information import InformationService
from bridge.information import battle_display_composition
from bridge.information.battle_display_composition import project_readable_text
from bridge.information.tools import InformationTools
from bridge.information.presentation import present_concise
from bridge.tests.test_information_battle_independent_line import fixture14
from bridge.tests.test_information_battles import battle_topic_query, event_id, make_source


def composition():
    return {'line1': {'status': 'known', 'text': 'Same-event name',
                     'basis': 'native_formatter_on_owned_same_event_name_candidate', 'derived': True},
            'controls': [{'template_key': 'OURLOST', 'value_kind': 'formatted_text',
                          'configured_text_assignment_condition': True,
                          'text': {'status': 'known', 'text': '100', 'basis': 'same_event_operands'}}],
            'buttons': {'controls': []}, 'remaining_gaps': ['runtime_widget_state_and_visibility'],
            'order_basis': 'static_binding_declaration_order_not_screen_order'}


@pytest.mark.parametrize('unknown', [False, True])
def test_text_completeness_only_describes_selected_text_sections(unknown):
    value = composition()
    if unknown:
        value['controls'][0]['text'] = {'status': 'unknown', 'reason': 'OPERAND_NOT_CAPTURED'}
    original = deepcopy(value)
    text = project_readable_text(value)
    assert text['selected_text_complete'] is (not unknown)
    assert text['content_scope'] == 'configured_result_text_sections'
    assert text['complete'] is (not unknown)
    assert text['is_native_raw_text'] is text['runtime_popup_verified'] is False
    assert text['remaining_gaps'] == value['remaining_gaps']
    assert value == original


def test_omitted_known_text_keeps_selected_text_incomplete(monkeypatch):
    monkeypatch.setattr(battle_display_composition, 'MAX_READABLE_TEXT_BYTES', 4)
    text = project_readable_text(composition())
    assert text['unknown_section_count'] == 0
    assert text['selected_text_complete'] is False
    assert text['output_limit_reached'] is True


def test_template_sides_identify_a_defending_observer_without_reassigning_our_values():
    value = composition()
    value['side_identity'] = {'status': 'known', 'value': {'sides': [
        {'template_label': 'OUR', 'combat_side_index': 0, 'participants': ['HSK'], 'observer_participated': False},
        {'template_label': 'ENEMY', 'combat_side_index': 1, 'participants': ['UES'], 'observer_participated': True}]}}
    text = project_readable_text(value)
    assert text['text'].startswith('[OUR] HSK\n[ENEMY] UES（观察国所在侧）\n')
    assert '[OURLOST] 100\n' in text['text']
    assert text['template_sides'] == value['side_identity']['value']['sides']
    assert text['selected_text_complete'] is True


@pytest.mark.parametrize('mode', [1, 2])
def test_full_query_event_and_reopen_retain_result_text_without_brief_presentation(tmp_path, mode):
    fixture, _base, _payload = fixture14(mode)
    source, _primary, fixture, _stream, _payload = make_source(
        tmp_path, fixture=fixture, observer='FRA', message_ids=('278',))
    database = tmp_path / 'information.sqlite3'
    query = battle_topic_query('B04', ['details', 'raw_text'], selected_event=event_id(fixture, '278'))
    with closing(InformationService(source, database)) as service:
        api = InformationTools(service)
        public = api.call('information_query', {'request_id': 'full-text-query', 'queries': [query]})
        queried = service.get_result(public['result_id'])
        details = queried['items'][0]['fields']['details']['value']
        expected = project_readable_text(details['display_composition'])
        assert details['result_text'] == expected
        assert 'Native formatted battle' in expected['text']
        assert queried['items'][0]['source']['result_text_projection_version'] == 2
        event_query = deepcopy(query)
        event_query['parameters'].pop('event_id')
        report = api.call('information_manage_report', {'request_id': 'full-report', 'operation': 'create',
            'config': {'name': 'Full battle result text', 'detail': 'full', 'queries': [event_query]}})['report']
        subscription = api.call('information_manage_subscription', {'request_id': 'full-subscription',
            'operation': 'create', 'config': {'name': 'Full battle text', 'kind': 'event', 'enabled': True,
                'report_id': report['id'], 'event': {'types': ['battle_observation']}}})['subscription']
        tick = api.call('information_tick', {})
        assert len(tick['results']) == 1
        delivered = service.get_result(tick['results'][0]['result_id'])
        assert 'presentation' not in delivered
        assert delivered['items'][0]['fields']['details']['value']['result_text'] == expected
        assert api.call('information_tick', {})['results'] == []
        api.call('information_manage_subscription', {'request_id': 'cancel-full', 'operation': 'cancel',
            'subscription_id': subscription['id'], 'expected_version': subscription['version']})
    with closing(InformationService(source, database)) as service:
        assert service.get_result(queried['result_id']) == queried
        assert service.get_result(delivered['result_id']) == delivered


def test_older_capture_keeps_existing_details_when_result_text_inputs_are_missing(tmp_path):
    source, _primary, fixture, _stream, _payload = make_source(tmp_path)
    query = battle_topic_query('B04', ['details'], selected_event=event_id(fixture))
    sample = source.read(query, source.context())
    assert sample['fields']['details']['status'] == 'known'
    assert 'result_text' not in sample['fields']['details']['value']


def test_compact_text_keeps_known_sections_without_diagnostic_placeholders():
    value = composition()
    value['controls'][0]['text'] = {'status': 'unknown', 'reason': 'INTERNAL_OPERAND_DIAGNOSTIC'}
    text = project_readable_text(value, include_unknown=False)
    assert text['text'] == '[Line1] Same-event name\n'
    assert text['complete'] is False
    assert text['unknown_section_count'] == 1
    assert text['sections'][1]['included_in_text'] is False
    assert text['output_limit_reached'] is False


def test_missing_side_identity_keeps_declared_result_text_incomplete():
    value = composition()
    value['side_identity'] = {'status': 'unknown', 'reason': 'SIDE_MAPPING_UNAVAILABLE'}
    text = project_readable_text(value)
    assert text['unknown_section_count'] == 0
    assert text['selected_text_complete'] is text['complete'] is False


def test_concise_legacy_text_retains_values_and_hides_unknown_diagnostics():
    value = composition()
    value['status'] = 'known'
    value['controls'][0]['text'] = {'status': 'unknown', 'reason': 'INTERNAL_OPERAND_DIAGNOSTIC'}
    result = present_concise({'result_id': 'old-result', 'items': [{
        'topic': 'B04', 'fields': {'details': {'status': 'known', 'value': {
            'display_composition': value}}}}]})
    assert result['items'][0]['details'] == '[Line1] Same-event name\n'


def test_concise_incomplete_legacy_composition_is_empty():
    result = present_concise({'result_id': 'old-result', 'items': [{
        'topic': 'B04', 'fields': {'details': {'status': 'known', 'value': {
            'display_composition': {'status': 'known'}}}}}]})
    assert result['items'][0]['details'] is None
