"""Recipient-bound read-only response previews through the shared information API."""
from contextlib import closing
from copy import deepcopy
import hashlib
import json
from pathlib import Path

import pytest

from bridge.diplomacy import ObserverSession
from bridge.information import InformationService, InformationError
from bridge.information.catalog import get_topic, validate_query
from bridge.information.composite import CompositeSource
from bridge.information.tools import InformationTools
from bridge.information.presentation import present_result
from bridge.tests.test_information_inbound_favor_parameters import FavorTools, native_event
from bridge.tests.test_information_inbound_current import PUBLIC_ID


def preview_source(topic='A01', phase='accept', kind='gold', event=None):
    event = deepcopy(event or native_event(kind))
    event['phase'] = phase
    tools = FavorTools(event)
    tools.envelope['phase'] = phase
    tools.envelope['legality'] = {'status': 'available', 'reasons': [], 'complete': True}
    tools.envelope['costs'] = tools.envelope['native_inbound_inspection']['costs']
    proposal = {'proposal_id': PUBLIC_ID, 'action_id': event['action_id'], 'actor': event['actor'],
                'recipient': 'FRA', 'observer_status': 'observed_pending'}
    tools.session.find_native_alliance_inbound_offer = lambda public_id: (
        deepcopy(proposal) if public_id == PUBLIC_ID else None)
    from bridge.information.sources import DiplomacySource
    source = DiplomacySource(tools)
    query = {'topic': topic, 'object': {'type': 'country_pair', 'actor': event['actor'], 'recipient': 'FRA'},
             'fields': ['legality_status', 'legality_reasons', 'costs'] if topic == 'A01' else ['parameters', 'costs'],
             'parameters': {'action_id': event['action_id'], 'phase': phase, 'proposal_id': PUBLIC_ID}}
    return source, tools, query, proposal


@pytest.mark.parametrize('topic', ['A01', 'A03'])
@pytest.mark.parametrize('phase', ['accept', 'reject'])
@pytest.mark.parametrize('kind', ['gold', 'trust', 'men'])
def test_inbound_previews_use_recipient_scope_and_the_requested_phase(topic, phase, kind):
    source, tools, query, _proposal = preview_source(topic, phase, kind)
    composite = CompositeSource(source)
    context = composite.context()
    assert validate_query(query, context) == query
    assert CompositeSource._scope_reason(query, get_topic(topic), context) is None
    result = composite.read(query, context)
    assert len(tools.inspect_calls) == 1
    assert tools.inspect_calls[0] == (query['parameters']['action_id'], query['object']['actor'],
                                    'FRA', phase, {'proposal_id': PUBLIC_ID})
    assert result['source']['provenance']['inspection_phase'] == phase
    assert result['source']['provenance']['response_executed'] is False
    if topic == 'A01':
        assert result['fields']['legality_status']['value'] == 'available'
    else:
        assert result['fields']['parameters']['value']['proposal_id'] == PUBLIC_ID
    if phase == 'reject':
        assert result['fields']['costs']['status'] == 'unknown'
        assert result['fields']['costs']['reason'] == 'REJECTION_COSTS_NOT_PROVEN_BY_ACCEPTANCE_QUOTE'
    else:
        assert result['fields']['costs']['value']['items'][0]['amount_raw'] >= 0
    assert result['objects'][0]['proposal_id'] == PUBLIC_ID


@pytest.mark.parametrize('topic', ['A01', 'A03'])
@pytest.mark.parametrize('damage', ['missing_id', 'bad_id', 'missing_action', 'unsupported_action', 'overrides', 'initiate_id'])
def test_response_selectors_fail_before_any_inspection(topic, damage):
    source, tools, query, _proposal = preview_source(topic)
    params = query['parameters']
    if damage == 'missing_id':
        params.pop('proposal_id')
    elif damage == 'bad_id':
        params['proposal_id'] = 'native-77'
    elif damage == 'missing_action':
        params.pop('action_id')
    elif damage == 'unsupported_action':
        params['action_id'] = 'send_gift'
    elif damage == 'overrides':
        params['amount_raw'] = 1
    else:
        params['phase'] = 'initiate'
    with pytest.raises(InformationError):
        source.read(query, source.context())
    assert tools.inspect_calls == []


@pytest.mark.parametrize('damage', ['outbound_foreign_actor', 'response_foreign_recipient', 'third_party'])
def test_response_scope_does_not_expand_outbound_or_third_party_access(damage):
    source, tools, query, _proposal = preview_source()
    if damage == 'outbound_foreign_actor':
        query['parameters'] = {'action_id': 'offer_alliance', 'phase': 'initiate'}
    elif damage == 'response_foreign_recipient':
        query['object'].update(actor='FRA', recipient='POR')
    else:
        query['object'].update(actor='ENG', recipient='POR')
    with pytest.raises(InformationError, match='observer scope'):
        source.read(query, source.context())
    assert tools.inspect_calls == []
    query['object'].update(actor='FRA', recipient='POR')
    query['parameters'] = {'action_id': 'offer_alliance', 'phase': 'initiate'}
    assert validate_query(query, source.context()) == query


@pytest.mark.parametrize('damage', ['missing', 'actor', 'action', 'id'])
def test_original_observation_must_match_before_native_preview(damage):
    source, tools, query, proposal = preview_source()
    if damage == 'missing':
        tools.session.find_native_alliance_inbound_offer = lambda _public_id: None
    else:
        if damage == 'actor':
            proposal['actor'] = 'POR'
        elif damage == 'action':
            proposal['action_id'] = 'offer_alliance'
        else:
            proposal['proposal_id'] = 'b' * 32
        tools.session.find_native_alliance_inbound_offer = lambda _public_id: deepcopy(proposal)
    fields = source.read(query, source.context())['fields']
    assert all(field['status'] == 'unavailable' for field in fields.values())
    assert tools.inspect_calls == []


@pytest.mark.parametrize('damage', ['phase', 'id', 'party', 'date', 'native_flags'])
def test_invalid_fresh_proof_never_exposes_available_legality(damage):
    source, tools, query, _proposal = preview_source(phase='reject')
    if damage == 'phase':
        tools.envelope['native_inbound_inspection']['phase'] = 'accept'
    elif damage == 'id':
        tools.envelope['parameters']['actual']['proposal_id'] = 'b' * 32
    elif damage == 'party':
        tools.envelope['observed_inbound_proposal']['actor'] = 'POR'
    elif damage == 'date':
        tools.envelope['native_inbound_inspection']['date_raw'] = True
    else:
        tools.envelope['native_inbound_inspection']['native_validity'] = False
    result = source.read(query, source.context())
    assert result['fields']['legality_status']['status'] in ('unknown', 'unavailable')
    assert len(tools.inspect_calls) == 1


@pytest.mark.parametrize('advance', ['native_date', 'collection_date'])
def test_fresh_response_preview_remains_available_as_game_time_advances(advance):
    source, tools, query, _proposal = preview_source(phase='reject')
    if advance == 'native_date':
        tools.envelope['native_inbound_inspection']['date_raw'] += 1
    else:
        tools.drift_after_inspect = True
    result = source.read(query, source.context())
    assert result['fields']['legality_status']['value'] == 'available'
    assert len(tools.inspect_calls) == 1


@pytest.mark.parametrize('topic', ['A01', 'A03'])
@pytest.mark.parametrize('phase', ['accept', 'reject'])
@pytest.mark.parametrize('detail', ['full', 'brief'])
def test_normal_tool_preview_and_persistent_reopen(topic, phase, detail, tmp_path):
    source, tools, query, _proposal = preview_source(topic, phase)
    source = CompositeSource(source)
    database = tmp_path / 'information.sqlite3'
    with closing(InformationService(source, database)) as service:
        report = service.manage_report('preview-report', 'create', config={
            'name': 'received response preview', 'detail': detail, 'queries': [query]})['report']
        result = present_result(InformationTools(service).call('information_query', {
            "view": "full",
            'request_id': 'preview-query', 'report_id': report['id']}))
        known = 'legality_status' if topic == 'A01' else 'parameters'
        assert result['items'][0]['fields'][known]['status'] == 'known'
        full = service.get_result(result['result_id'])
        assert (present_result(full) if detail == 'brief' else full) == result
        assert len(tools.inspect_calls) == 1
    with closing(InformationService(source, database)) as reopened:
        assert reopened.get_result(full['result_id']) == full
    assert len(tools.inspect_calls) == 1


def test_archived_native_reject_preview_preserves_its_actual_phase_and_quote_boundary(tmp_path):
    root = Path(__file__).resolve().parents[2]
    path = root / 'work/runtime/r71-favor-inbound-reject-20261020-001/native.jsonl'
    raw = path.read_bytes()
    assert len(raw) == 29640
    assert hashlib.sha256(raw).hexdigest() == 'fb5d420ef053efe00465112898bf4126b1219461c5c3cab3d104367ab6269e54'
    event = json.loads(raw.splitlines()[0])
    assert event['phase'] == 'reject'
    assert ObserverSession._valid_native_inbound_inspection(
        event, event['query_id'], event['session_id'], event['actor'], event['phase'],
        event['native_proposal_id'], event['date_raw'], event['action_id'])
    source, tools, query, _proposal = preview_source(phase='reject', event=event)
    with closing(InformationService(CompositeSource(source), tmp_path / 'information.sqlite3')) as service:
        result = InformationTools(service).call('information_query', {
            "view": "full",
            'request_id': 'archived-reject-preview', 'queries': [query]})
        assert result['items'][0]['fields']['legality_status']['value'] == 'available'
        assert result['items'][0]['fields']['costs']['status'] == 'unknown'
        assert len(tools.inspect_calls) == 1 and tools.inspect_calls[0][3] == 'reject'
    (tmp_path / 'archived-reject-preview.json').write_text(json.dumps({
        'evidence_kind': 'archived_native_reject_inspection_in_memory_harness',
        'source_sha256': hashlib.sha256(raw).hexdigest(), 'current_game_inspection': False,
        'result': result,
    }, ensure_ascii=False, indent=2), encoding='utf-8')
