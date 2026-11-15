from contextlib import closing
from copy import deepcopy

import pytest

from bridge.information import InformationService
from bridge.information.catalog import get_topic


QUERY = {'topic': 'A04', 'object': {'type': 'session'}, 'fields': ['action_id'], 'parameters': {}}
CONTEXT = {'mode': 'live', 'status': 'ready', 'session_id': 'snapshot-test', 'observer': 'FRA',
    'game_version': '1.37.4', 'game_date': 100, 'game_day': 4, 'world_id': 'world-a'}


class SnapshotSource:
    def __init__(self, *, snapshot=True, rollback=False, change_world=False, event_id='captured-event'):
        self.current = deepcopy(CONTEXT)
        self.snapshot = snapshot
        self.rollback = rollback
        self.change_world = change_world
        self.event_id = event_id

    def context(self):
        return deepcopy(self.current)

    def catalog(self):
        return [dict(get_topic('A04'), status='available', supported_versions=['1.37.4'])]

    def read(self, query, context):
        self.current.update(game_date=76 if self.rollback else 124, game_day=3 if self.rollback else 5)
        if self.change_world:
            self.current['world_id'] = 'world-b'
        source = {'name': 'CapturedProposal'}
        if self.snapshot:
            source.update(projection='event_snapshot', event_id=self.event_id)
        return {'fields': {'action_id': {'status': 'known', 'value': 'offer_alliance'}},
                'complete': True, 'source': source, 'game_date': 52}


def test_captured_event_value_survives_clock_progress_and_reopen(tmp_path):
    path = tmp_path / 'information.sqlite3'
    with closing(InformationService(SnapshotSource(), path)) as service:
        result = service.query('captured-forward', queries=[QUERY])
    assert result['items'][0]['fields']['action_id'] == {'status': 'known', 'value': 'offer_alliance'}
    assert result['items'][0]['game_date'] == 52
    with closing(InformationService(SnapshotSource(), path)) as service:
        assert service.get_result(result['result_id'])['items'] == result['items']


@pytest.mark.parametrize('options', [{'snapshot': False}, {'event_id': ''}, {'rollback': True}, {'change_world': True}])
def test_live_values_and_invalid_snapshot_context_still_become_stale(tmp_path, options):
    with closing(InformationService(SnapshotSource(**options), tmp_path / 'information.sqlite3')) as service:
        result = service.query('snapshot-invalid', queries=[QUERY])
    assert result['items'][0]['fields']['action_id']['status'] == 'stale'
    assert 'value' not in result['items'][0]['fields']['action_id']


def test_snapshot_marker_must_match_the_delivered_event(tmp_path):
    source = SnapshotSource()
    with closing(InformationService(source, tmp_path / 'information.sqlite3')) as service:
        sample = source.read(QUERY, CONTEXT)
        sample['query'] = QUERY
        result = service._build_result([QUERY], CONTEXT, 'event',
            event={'event_id': 'different-event'}, samples=[sample])
    assert result['items'][0]['fields']['action_id']['status'] == 'stale'
