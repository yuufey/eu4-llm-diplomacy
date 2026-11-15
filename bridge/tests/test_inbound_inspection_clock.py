"""Read-only inbound queries retain the native observation as game time advances."""
from copy import deepcopy
import json
from pathlib import Path

import pytest

from bridge.diplomacy import ObserverSession


FIXTURE = Path(__file__).parent / 'fixtures/military_access_r32_inbound_inspections.json'


@pytest.mark.parametrize('elapsed', [0, 1, 24, 72])
def test_query_refreshes_request_date_and_returns_actual_native_date(tmp_path, monkeypatch, elapsed):
    event = deepcopy(json.loads(FIXTURE.read_text(encoding='utf-8'))['events'][0]['event'])
    initial_date = event['date_raw']
    health_date = initial_date + 24
    actual_date = health_date + elapsed
    event.update(query_id='running_inbound', date_raw=actual_date)
    session = ObserverSession.__new__(ObserverSession)
    session.directory = tmp_path
    session.session_id = event['session_id']
    monkeypatch.setattr(session, 'installation_capabilities', lambda: frozenset({
        'native_inbound_military_access_response',
    }))
    monkeypatch.setattr(session, 'health', lambda: {'status': 'ready', 'date_raw': health_date})
    log = tmp_path / 'control-probe.jsonl'
    log.touch()
    requests = []

    def publish(wire, query_id, request_name):
        requests.append((wire, query_id, request_name))
        with log.open('a', encoding='utf-8') as stream:
            stream.write(json.dumps(event) + '\n')
        return 'published'

    monkeypatch.setattr(session, '_publish_atomic_request', publish)
    result = session.inspect_native_inbound_response(
        event['query_id'], event['actor'], event['phase'], initial_date,
        event['native_proposal_id'], action_id=event['action_id'], timeout=1,
    )
    assert 'error_code' not in result
    assert result['date_raw'] == actual_date
    assert result['pending_active'] is True
    assert len(requests) == 1
    assert requests[0][0].split('|')[4] == str(health_date)


def test_native_query_result_before_requested_date_is_rejected():
    event = deepcopy(json.loads(FIXTURE.read_text(encoding='utf-8'))['events'][0]['event'])
    assert not ObserverSession._valid_native_inbound_inspection(
        event, event['query_id'], event['session_id'], event['actor'],
        event['phase'], event['native_proposal_id'], event['date_raw'] + 1,
        event['action_id'],
    )
