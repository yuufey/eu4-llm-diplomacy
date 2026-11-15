from contextlib import closing
from copy import deepcopy
import pytest

from bridge.information import InformationService
from bridge.information.catalog import get_topic
from bridge.information.observation_time import active, dates_match, sampled_read, without_clock
from bridge.information.presentation import present_result


QUERY = {'topic': 'C03', 'object': {'type': 'session'}, 'fields': ['pending_matters'], 'parameters': {}}
CONTEXT = {'mode': 'live', 'status': 'ready', 'session_id': 'sample-test', 'observer': 'FRA',
           'game_version': '1.37.4', 'game_date': 100, 'game_day': 4, 'world_id': 'world-a'}


@pytest.mark.parametrize('topic', ['C03', 'A01', 'D03'])
def test_clock_progress_is_scoped_to_a_sampled_read(topic):
    assert not dates_match(100, 124)
    with sampled_read(dict(QUERY, topic=topic), CONTEXT) as window:
        assert active() and dates_match(100, 124)
        assert window.metadata()['end_game_date'] == 124
        assert not dates_match(124, 100)
        assert not dates_match(True, 124)
    assert not active() and not dates_match(100, 124)


def test_other_action_queries_and_recorded_reads_keep_their_strict_clock():
    for query, context in ((dict(QUERY, topic='A02'), CONTEXT), (QUERY, dict(CONTEXT, mode='recorded'))):
        with sampled_read(query, context) as window:
            assert window is None and not dates_match(100, 124)


def test_clock_normalization_preserves_business_and_identity_evidence():
    record = {'game_date': 100, 'country': 'FRA', 'value': 8,
              'read_log': [{'label': 'game.game_date', 'raw_hex': '0100'},
                           {'label': 'country.value', 'raw_hex': '0800'}]}
    with sampled_read(QUERY, CONTEXT):
        normalized = without_clock(record, date_labels=('game.game_date',))
    assert normalized == {'country': 'FRA', 'value': 8,
                          'read_log': [{'label': 'country.value', 'raw_hex': '0800'}]}
    assert record['game_date'] == 100 and len(record['read_log']) == 2


class ChangingSource:
    def __init__(self, *, rollback=False, change_world=False):
        self.current = deepcopy(CONTEXT)
        self.rollback = rollback
        self.change_world = change_world

    def context(self):
        return deepcopy(self.current)

    def catalog(self):
        return [dict(get_topic('C03'), status='available', supported_versions=['1.37.4'])]

    def read(self, query, context):
        self.current.update(game_date=76 if self.rollback else 124, game_day=3 if self.rollback else 5)
        if self.change_world:
            self.current['world_id'] = 'world-b'
        return {'fields': {'pending_matters': {'status': 'known', 'value': ['observed-proposal']}}, 'complete': True}


def test_forward_days_keep_values_and_publish_the_collection_window(tmp_path):
    with closing(InformationService(ChangingSource(), tmp_path / 'information.sqlite3')) as service:
        result = service.query('sample-forward', queries=[QUERY])
    item = result['items'][0]
    assert item['fields']['pending_matters']['value'] == ['observed-proposal']
    assert item['observation_window']['start_game_date'] == 100
    assert item['observation_window']['end_game_date'] == 124
    assert item['observation_window']['atomic_snapshot'] is False
    brief = present_result(dict(result, detail='brief'))
    assert brief['items'][0]['observation_window'] == item['observation_window']
    with closing(InformationService(ChangingSource(), tmp_path / 'information.sqlite3')) as reopened:
        restored = reopened.get_result(result['result_id'])
    assert restored['items'][0]['observation_window'] == item['observation_window']
    assert restored['items'][0]['fields'] == item['fields']


@pytest.mark.parametrize('options', [{'rollback': True}, {'change_world': True}])
def test_changed_identity_or_time_rollback_still_invalidates_a_sample(tmp_path, options):
    with closing(InformationService(ChangingSource(**options), tmp_path / 'information.sqlite3')) as service:
        result = service.query('sample-invalid', queries=[QUERY])
    field = result['items'][0]['fields']['pending_matters']
    assert field['status'] == 'stale' and 'value' not in field
