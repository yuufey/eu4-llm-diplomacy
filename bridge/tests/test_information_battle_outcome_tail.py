"""Same-event tail data selects a modeled phrase, never a displayed popup."""
from copy import deepcopy
import hashlib
import pytest

from bridge.information.battle_outcome_composition import project_outcome_text_composition
from bridge.information.battle_outcome_tail import FIELDS, NAVAL_KEYS, project_outcome_tail_sources
from bridge.tests.test_information_battle_outcome_text import _field, _snapshot
from bridge.tests.test_information_battle_name_sources_integration import _fixture
from bridge.tests.test_information_battle_outcome_composition import _configure
from bridge.tests.test_information_battles import make_source, event_id, battle_topic_query
from bridge.information.service import InformationService
from bridge.information.tools import InformationTools
from work import information_battle_outcome_text_wire as v12
from work import information_battle_outcome_tail_wire as wire
from work.ingest_information_battle_raw_live import _decode_payload, RawIngestError


def fixture13(*, failed=False, language=b'l_english'):
    fixture, base11 = _fixture()
    text = _snapshot(base11)
    for name, value in {'YOU_WON': b'Victory', 'YOU_LOST': b'Defeat',
        'RESULT_WON': b'won', 'RESULT_LOSS': b'lost', 'MESSAGE_HEAD_MIL': b'Head',
        'WARSCORE_FROM_BATTLE': b'[$VAL|=+$ score]'}.items():
        text['text_fields'][name] = _field(value)
    base12 = v12.encode(base11, text)
    decoded = v12.decode(base12)
    fields = {name: _field(state='unknown') if failed else _field(language if name == 'language'
              else name.encode('ascii')) for name in FIELDS}
    tail = {'sequence': decoded['observation']['sequence'],
        'raw_date': decoded['observation']['result']['raw_date'], 'kind': decoded['context']['kind'],
        'failure': 8 if failed else 0, 'reserved_slots': [0, 0, 0] if failed else [-1, -2, -3],
        'text_fields': fields}
    frame = wire.encode(base12, tail)
    return fixture, base12, frame, wire.decode(frame)


@pytest.mark.parametrize('winner,observer_side', [(0, 0), (0, 1), (1, 0), (1, 1)])
@pytest.mark.parametrize('append', [False, True])
def test_event_slots_select_exactly_one_score_branch(winner, observer_side, append):
    _, _, _, decoded = fixture13()
    mapping, observer = _configure(decoded, winner=winner, observer_side=observer_side)
    opponent = decoded['context']['sides'][1 - observer_side]['participants']['full_refs'][0]
    if not append:
        decoded['outcome_tail']['reserved_slots'][1] = int.from_bytes(opponent.to_bytes(8, 'little')[4:6], 'little', signed=True)
    value = project_outcome_text_composition(decoded, mapping=mapping, observer_ref=observer)
    selected = value['winorlose']
    assert selected['status'] == 'known' and selected['selected_score_append'] is append
    assert selected['modeled_branch_selected'] is True
    key = 'candidate_if_appended' if append else 'candidate_if_not_appended'
    assert selected['raw_hex'] == selected[key]['raw_hex']
    assert selected['native_parameter_assignment_verified'] is False
    assert value['native_branch_selection_verified'] is False
    assert value['full_display_complete'] is False
    assert value['tail_language_consistent'] is True


def test_required_unknown_numeric_text_cannot_fall_back_to_no_suffix():
    _, _, _, decoded = fixture13()
    mapping, observer = _configure(decoded, winner=0, observer_side=0)
    decoded['outcome_text']['text_fields']['WARSCORE_FROM_BATTLE'] = _field(b'$UNKNOWN$')
    value = project_outcome_text_composition(decoded, mapping=mapping, observer_ref=observer)
    assert value['winorlose']['status'] == 'unknown'
    assert value['winorlose']['selected_score_append'] is True
    assert value['observer_base_phrase']['status'] == 'known'
    opponent = decoded['context']['sides'][1]['participants']['full_refs'][0]
    decoded['outcome_tail']['reserved_slots'][0] = int.from_bytes(opponent.to_bytes(8, 'little')[4:6], 'little', signed=True)
    value = project_outcome_text_composition(decoded, mapping=mapping, observer_ref=observer)
    assert value['winorlose']['status'] == 'known'
    assert value['winorlose']['raw_hex'] == value['observer_base_phrase']['raw_hex']


@pytest.mark.parametrize('failed,language,reason', [(True, b'l_english', 'OUTCOME_TAIL_INPUTS_UNKNOWN'),
    (False, b'l_french', 'OUTCOME_TAIL_LANGUAGE_MISMATCH')])
def test_failed_or_different_language_tail_preserves_sibling_text(failed, language, reason):
    _, _, _, decoded = fixture13(failed=failed, language=language)
    mapping, observer = _configure(decoded, winner=0, observer_side=0)
    value = project_outcome_text_composition(decoded, mapping=mapping, observer_ref=observer)
    assert value['winorlose']['status'] == 'unknown' and value['winorlose']['reason'] == reason
    assert value['observer_base_phrase']['status'] == value['messenger']['status'] == 'known'
    assert value['score_suffix']['append_condition']['status'] == 'unknown'
    tail = project_outcome_tail_sources(decoded)
    if failed:
        assert tail['reserved_slots']['status'] == 'unknown' and 'value' not in tail['reserved_slots']


@pytest.mark.parametrize('mutation', ['sequence', 'slot_bool', 'mixed_failure', 'language_absent', 'NUL'])
def test_tail_projection_rejects_bad_evidence(mutation):
    _, _, _, decoded = fixture13()
    value = decoded['outcome_tail']
    if mutation == 'sequence':
        value['sequence'] += 1
    elif mutation == 'slot_bool':
        value['reserved_slots'][0] = True
    elif mutation == 'mixed_failure':
        value['failure'] = 1
    elif mutation == 'language_absent':
        value['text_fields']['language'] = _field(state='absent')
    else:
        value['text_fields'][NAVAL_KEYS[0]] = _field(b'\0')
    assert project_outcome_tail_sources(decoded)['reason'] == 'OUTCOME_TAIL_INVALID_OR_EVENT_MISMATCH'


@pytest.mark.parametrize('winner,observer_side', [(0, 0), (0, 1), (1, 0), (1, 1)])
def test_naval_parameters_follow_direct_observer_branch_not_land_side_labels(winner, observer_side):
    _, _, _, decoded = fixture13()
    # Synthetic decoded naval context tests this consumer's branch model;
    # this is not a claim of a new captured naval frame.
    decoded['context']['kind'] = decoded['outcome_text']['kind'] = decoded['outcome_tail']['kind'] = 2
    mapping, observer = _configure(decoded, winner=winner, observer_side=observer_side)
    value = project_outcome_text_composition(decoded, mapping=mapping, observer_ref=observer)
    params = value['naval_format_parameters']
    victory = winner == observer_side
    assert params['status'] == 'known'
    assert params['RESULT']['key'] == ('RESULT_WON' if victory else 'RESULT_LOSS')
    assert params['OTHERRESULT']['key'] == ('COMBAT_FLEE' if victory else 'COMBAT_TRIUMPH')
    assert params['WINNER']['key'] == ('COMBAT_WINNERTYPE_OUR' if victory else 'COMBAT_WINNERTYPE_THEIR')
    assert all(params[key]['status'] == 'known' for key in ('RESULT', 'OTHERRESULT', 'WINNER'))
    assert 'land_format_parameters' not in value


def test_a_missing_naval_template_does_not_erase_captured_slots():
    _, _, _, decoded = fixture13()
    decoded['outcome_tail']['text_fields']['COMBAT_FLEE'] = _field(state='absent')
    tail = project_outcome_tail_sources(decoded)
    assert tail['status'] == 'known' and tail['reserved_slots']['value'] == [-1, -2, -3]
    assert tail['text_fields']['COMBAT_FLEE']['status'] == 'absent'


def test_old_v12_does_not_acquire_event_slots_or_a_selected_final_phrase():
    _, base, _, _ = fixture13()
    decoded = wire.decode(base)
    assert decoded == v12.decode(base) and 'outcome_tail' not in decoded
    mapping, observer = _configure(decoded, winner=0, observer_side=0)
    assert project_outcome_text_composition(decoded, mapping=mapping, observer_ref=observer)['winorlose']['status'] == 'unknown'


def test_v13_receiver_and_query_report_event_share_the_same_partial_result(tmp_path):
    fixture, _, frame, decoded = fixture13()
    version, received = _decode_payload(frame)
    assert version == 13 and received == decoded
    fixture = deepcopy(fixture)
    fixture['payload_hex'] = frame.hex()
    fixture['provenance'].update(real_capture=False, synthetic_extension=True,
        source_mode='synthetic_v13_tail_over_retained_base', payload_sha256=hashlib.sha256(frame).hexdigest())
    source, *_ = make_source(tmp_path, fixture=fixture, observer='FRA', message_ids=('230',))
    selected = event_id(fixture, '230')
    query = battle_topic_query('B04', ['details', 'raw_text'], selected_event=selected)
    item = source.read(query, source.context())
    assert item['source']['name'] == 'IBOW.v13' and item['source']['projection_version'] == 30
    assert item['source']['hash_basis'] == 'observer_visible_battle_fields'
    assert 'payload_sha256' not in item['source']
    assert item['fields']['details']['value']['outcome_tail_sources']['reserved_slots']['status'] == 'known'
    assert item['fields']['details']['value']['outcome_text_composition']['winorlose']['status'] == 'known'
    assert item['fields']['raw_text']['status'] == 'unknown'
    service = InformationService(source, tmp_path / 'information.sqlite3')
    tools = InformationTools(service)
    try:
        expected = service.query('tail-query', queries=[query])['items'][0]['fields']
        report = tools.call('information_manage_report', dict(request_id='tail-report', operation='create',
            config=dict(name='tail composition', detail='full', queries=[battle_topic_query('B04', ['details', 'raw_text'])])))['report']
        tools.call('information_manage_subscription', dict(request_id='tail-event', operation='create',
            config=dict(name='tail event', kind='event', report_id=report['id'], enabled=True,
                binding=dict(session_id=fixture['provenance']['session_id'], observer='FRA',
                    game_version='1.37.4', game_sha256=fixture['provenance']['game_sha256']),
                event=dict(types=['battle_observation']))))
        delivered = tools.call('information_tick', {"view": "full"})['results']
        assert len(delivered) == 1 and delivered[0]['items'][0]['fields'] == expected
        assert delivered[0]['complete'] is False
    finally:
        service.close()
    with pytest.raises(RawIngestError, match='v13_decode_failed'):
        _decode_payload(frame + b'\0')
