"""Recorded-identity fixture through query, event and retained-record periods."""
import pytest

from bridge.information import InformationService
from bridge.information.model import InformationError
from bridge.information.tools import InformationTools
from bridge.tests.test_information_battle_display_context_integration import GAME_SHA256, _v7_fixture
from bridge.tests.test_information_battles import battle_topic_query, event_id, make_source


def test_composition_reaches_direct_query_report_and_event_without_changing_native_text(tmp_path):
    fixture, _, _ = _v7_fixture()
    source, _, _, _, _ = make_source(tmp_path, fixture=fixture, observer='FRA', message_ids=('160',))
    selected = event_id(fixture, '160')
    query = battle_topic_query('B04', ['details', 'raw_text'], selected_event=selected)
    direct = source.read(query, source.context())
    composed = direct['fields']['details']['value']['display_composition']
    assert composed['status'] == 'known'
    assert composed['configured_layout'] == 'land_detailed'
    assert composed['buttons']['controls'][1]['text'] == ''
    assert composed['line1']['basis'] == 'derived_name_line_candidate'
    assert direct['fields']['raw_text']['status'] == 'unknown'
    assert direct['source']['projection_version'] == 30
    service = InformationService(source, tmp_path / 'information.sqlite3')
    tools = InformationTools(service)
    try:
        item = service.query('composition-query', queries=[query])['items'][0]
        assert item['fields']['details']['value']['display_composition'] == composed
        report = tools.call('information_manage_report', {
            'request_id': 'composition-report', 'operation': 'create',
            'config': {'name': 'composed battle', 'detail': 'full',
                       'queries': [battle_topic_query('B04', ['details', 'raw_text'])]},
        })['report']
        subscription = tools.call('information_manage_subscription', {
            'request_id': 'composition-subscription', 'operation': 'create',
            'config': {'name': 'composed battle event', 'kind': 'event',
                       'report_id': report['id'], 'enabled': True,
                       'binding': {'session_id': fixture['provenance']['session_id'],
                                   'observer': 'FRA', 'game_version': '1.37.4', 'game_sha256': GAME_SHA256},
                       'event': {'types': ['battle_observation']}},
        })['subscription']
        delivered = tools.call('information_tick', {"view": "full"})['results']
        assert len(delivered) == 1 and delivered[0]['event']['event_id'] == selected
        fields = delivered[0]['items'][0]['fields']
        assert fields['details']['value']['display_composition'] == composed
        assert fields['raw_text'] == item['fields']['raw_text']
        assert delivered[0]['complete'] is False
        cancelled = tools.call('information_manage_subscription', {
            'request_id': 'composition-cancel', 'operation': 'cancel',
            'subscription_id': subscription['id'], 'expected_version': subscription['version'],
        })['subscription']
        assert cancelled['state'] == 'cancelled'
    finally:
        service.close()


def test_periodic_requires_an_explicit_record_and_does_not_mutate_the_catalog_on_rejection(tmp_path):
    fixture, _, _ = _v7_fixture()
    source, _, _, _, _ = make_source(tmp_path, fixture=fixture, observer='FRA', message_ids=('162',))
    service = InformationService(source, tmp_path / 'rejected-periodic.sqlite3')
    tools = InformationTools(service)
    try:
        b04 = next(item for item in source.catalog() if item['topic_id'] == 'B04')
        assert b04['periodic_scope']['requires_event_id'] is True
        assert b04['periodic_scope']['acquires_capture'] is False
        query = battle_topic_query('B04', ['details'])
        assert all('periodic' not in entry['triggers'] for _, entry in source.query_capabilities(query))
        report = tools.call('information_manage_report', {
            'request_id': 'unselected-report', 'operation': 'create',
            'config': {'name': 'unselected event report', 'detail': 'full', 'queries': [query]},
        })['report']
        with pytest.raises(InformationError) as captured:
            tools.call('information_manage_subscription', {
                'request_id': 'unselected-periodic', 'operation': 'create',
                'config': {'name': 'invalid event poll', 'kind': 'periodic',
                           'report_id': report['id'], 'enabled': True,
                           'binding': {'session_id': fixture['provenance']['session_id'],
                                       'observer': 'FRA', 'game_version': '1.37.4', 'game_sha256': GAME_SHA256},
                           'schedule': {'basis': 'real', 'every': 2, 'unit': 'seconds', 'missed': 'coalesce'}},
            })
        assert captured.value.code == 'unsupported_trigger'
        assert tools.call('information_status', {})['subscriptions'] == []
        assert next(item for item in source.catalog() if item['topic_id'] == 'B04') == b04
        selected = battle_topic_query('B04', ['details'], selected_event=event_id(fixture, '162'))
        assert all('periodic' in entry['triggers'] for _, entry in source.query_capabilities(selected))
    finally:
        service.close()


def test_two_real_time_periodic_reports_preserve_the_same_composition_while_game_is_unchanged(tmp_path):
    fixture, _, _ = _v7_fixture()
    source, _, _, _, _ = make_source(tmp_path, fixture=fixture, observer='FRA', message_ids=('161',))
    query = battle_topic_query('B04', ['details', 'raw_text'], selected_event=event_id(fixture, '161'))
    clock = [100.0]
    service = InformationService(source, tmp_path / 'periodic.sqlite3', clock=lambda: clock[0])
    tools = InformationTools(service)
    subscriptions = []
    try:
        reference = service.query('composition-periodic-reference', queries=[query])['items'][0]['fields']
        report = tools.call('information_manage_report', {
            'request_id': 'composition-periodic-report', 'operation': 'create',
            'config': {'name': 'periodic composition', 'detail': 'full', 'queries': [query]},
        })['report']
        for seconds in (2, 5):
            subscriptions.append(tools.call('information_manage_subscription', {
                'request_id': f'composition-periodic-{seconds}', 'operation': 'create',
                'config': {'name': f'{seconds} second composition', 'kind': 'periodic',
                           'report_id': report['id'], 'enabled': True,
                           'binding': {'session_id': fixture['provenance']['session_id'],
                                       'observer': 'FRA', 'game_version': '1.37.4', 'game_sha256': GAME_SHA256},
                           'schedule': {'basis': 'real', 'every': seconds, 'unit': 'seconds', 'missed': 'coalesce'}},
            })['subscription'])
        assert tools.call('information_tick', {"view": "full"})['results'] == []
        clock[0] = 102.0
        fast = tools.call('information_tick', {"view": "full"})['results']
        assert len(fast) == 1
        assert fast[0]['items'][0]['fields'] == reference
        clock[0] = 105.0
        both = tools.call('information_tick', {"view": "full"})['results']
        assert len(both) == 2
        assert all(item['items'][0]['fields'] == reference for item in both)
        assert source.context()['game_date'] == fixture['context_date']
    finally:
        for index, subscription in enumerate(subscriptions):
            tools.call('information_manage_subscription', {
                'request_id': f'composition-periodic-cancel-{index}', 'operation': 'cancel',
                'subscription_id': subscription['id'], 'expected_version': subscription['version'],
            })
        service.close()
