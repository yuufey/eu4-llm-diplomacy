from copy import deepcopy
from contextlib import closing
import hashlib
import json
from pathlib import Path

import pytest

from bridge.information import InformationService
from bridge.information.battles import BattleObservationAdapter, decode
from bridge.information.tools import InformationTools
from bridge.tests.test_information_battles import make_source, event_id, _splitmix64_for_test


FIXTURE = Path(__file__).with_name('fixtures') / 'information_battle_FRA_rebel_live_v15_1374.json'


def retained_battle(path=FIXTURE):
    fixture = json.loads(path.read_text(encoding='utf-8'))
    payload = bytes.fromhex(fixture['payload_hex'])
    assert hashlib.sha256(payload).hexdigest() == fixture['provenance']['payload_sha256']
    return fixture, decode(payload)


@pytest.mark.parametrize('name,observer,message,expected_war', [
    (FIXTURE.name, 'FRA', '79',
     {'status': 'not_applicable', 'reason': 'REBEL_BATTLE_WITHOUT_WAR'}),
    ('information_battle_MNG_war_live_v15_1374.json', 'MNG', '5',
     {'status': 'known', 'value': 'war_cbef4e282a9c0362_00000001'}),
])
def test_real_battle_query_subscription_and_reopen(tmp_path, name, observer, message, expected_war):
    fixture, decoded = retained_battle(FIXTURE.with_name(name))
    assert decoded['context']['physical_player_full_ref'].to_bytes(8, 'little')[:3] == b'POR'
    assert observer != 'POR'
    creation = decoded['war_identity']['process_creation_filetime']
    source, *_ = make_source(tmp_path, fixture=fixture, observer=observer,
                            message_ids=(message,), process_creation_filetime=creation)
    queries = [{'topic': topic, 'object': {'type': 'battle'}, 'fields': fields,
                'parameters': {'event_id': event_id(fixture, message)}}
               for topic, fields in (('B01', ['war_id']), ('B04', ['gaps', 'raw_text', 'details']))]
    database = tmp_path / 'information.sqlite3'
    with closing(InformationService(source, database)) as service:
        api = InformationTools(service)
        public = api.call('information_query', {'request_id': 'rebel-war-id', 'queries': queries})
        queried = service.get_result(public['result_id'])
        war = queried['items'][0]['fields']['war_id']
        assert war == expected_war
        assert public['items'][0]['war_id'] == expected_war.get('value')
        gaps = queried['items'][1]['fields']['gaps']['value']
        assert 'WAR_AND_BATTLE_IDENTITIES_UNRESOLVED' not in gaps
        assert 'BATTLE_IDENTITY_UNRESOLVED' in gaps
        assert queried['items'][1]['fields']['raw_text']['status'] == 'unknown'
        text = queried['items'][1]['fields']['details']['value']['result_text']
        assert text['complete'] is text['selected_text_complete'] is True
        assert text['unknown_section_count'] == 0
        assert public['items'][1]['details'] == text['text']
        assert '[OUR]' in public['items'][1]['details']
        assert '[ENEMY]' in public['items'][1]['details']
        assert queried['complete'] is False
        assert queried['items'][0]['source']['war_identity_projection_version'] == 2
        report_queries = deepcopy(queries)
        for query in report_queries:
            query['parameters'] = {}
        report = service.manage_report('rebel-report', 'create', config={
            'name': 'Rebel battle', 'queries': report_queries, 'detail': 'full'})['report']
        subscription = service.manage_subscription('rebel-subscribe', 'create', config={
            'name': 'Rebel battle', 'kind': 'event', 'enabled': True,
            'report_id': report['id'], 'event': {'types': ['battle_observation']}})['subscription']
        results = service.tick()['results']
        assert len(results) == 1
        delivered = results[0]
        assert delivered['items'][0]['fields']['war_id'] == war
        assert service.tick()['results'] == []
        service.manage_subscription('rebel-cancel', 'cancel', subscription_id=subscription['id'],
                                    expected_version=subscription['version'])
    with closing(InformationService(source, database)) as service:
        assert service.get_result(queried['result_id']) == queried
        assert service.get_result(delivered['result_id']) == delivered


@pytest.mark.parametrize('mutation', ['ordinary', 'mixed', 'incomplete', 'invalid_war',
                                     'observed_war', 'unknown_router', 'missing_context'])
def test_other_missing_war_contexts_remain_unknown(mutation):
    _, decoded = retained_battle()
    owned = decoded['context']
    rebel = next(side for side in owned['sides']
                 if all(ref.to_bytes(8, 'little')[:3] == b'REB'
                        for ref in side['participants']['full_refs']))
    other_ref = int.from_bytes(b'ENG\0\x10\0\0\x01', 'little')
    if mutation == 'ordinary':
        rebel['participants']['full_refs'] = [other_ref]
    elif mutation == 'mixed':
        rebel['participants']['full_refs'].append(other_ref)
    elif mutation == 'incomplete':
        rebel['participants']['complete'] = False
    elif mutation == 'invalid_war':
        owned['war_context_status'] = 2
    elif mutation == 'observed_war':
        owned['war_context_status'] = 1
    elif mutation == 'unknown_router':
        owned['known_router'] = False
    else:
        decoded.pop('context')
    result, *_ = BattleObservationAdapter._war_identity_projection(
        decoded, decoded['observation']['result'], {}, {})
    assert result['status'] == 'unknown'


def test_war_filtered_history_skips_rebel_battles_without_unknown_identity_gap(tmp_path):
    fixture, decoded = retained_battle()
    creation = decoded['war_identity']['process_creation_filetime']
    source, *_ = make_source(tmp_path, fixture=fixture, observer='FRA',
                            process_creation_filetime=creation)
    result = source.read({'topic': 'W03', 'object': {
        'type': 'war', 'war_id': f'war_{_splitmix64_for_test(creation):016x}_00000001'},
        'fields': ['battle_losses'], 'parameters': {}}, source.context())
    assert 'BATTLE_HISTORY_WAR_ID_UNKNOWN' not in json.dumps(result)
    assert result['fields']['battle_losses']['value']['event_refs'] == []


def test_real_nonplayer_war_battle_is_returned_by_its_native_war_id(tmp_path):
    fixture, decoded = retained_battle(FIXTURE.with_name('information_battle_MNG_war_live_v15_1374.json'))
    identity = decoded['war_identity']
    source, *_ = make_source(tmp_path, fixture=fixture, observer='MNG', message_ids=('5',),
                            process_creation_filetime=identity['process_creation_filetime'])
    result = source.read({'topic': 'W03', 'object': {'type': 'war', 'war_id': identity['war_id']},
        'fields': ['battle_losses'], 'parameters': {}}, source.context())
    references = result['fields']['battle_losses']['value']['event_refs']
    assert len(references) == 1
    assert references[0]['event_id'] == event_id(fixture, '5')
    assert references[0]['war_id'] == {'status': 'known', 'value': identity['war_id']}
