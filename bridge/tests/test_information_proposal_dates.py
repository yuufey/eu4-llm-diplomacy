"""Delayed collection must not replace an unknown proposal occurrence date."""
from contextlib import closing
from copy import deepcopy

import pytest

from bridge.diplomacy import DiplomacyTools
from bridge.diplomacy_journal import DurableJournal
from bridge.information import InformationService
from bridge.information.sources import DiplomacySource
from bridge.tests.test_information_proposal_expiry import session, offer, expired, watch, SESSION, NOW


@pytest.mark.parametrize('observation_date,payload_date,expected', [
    (None, None, None), (120, None, 120), (None, 100, 100), (120, 100, 120),
    (True, None, None), (-1, None, None), (2**31, None, None), ('120', None, None),
])
def test_proposal_dates_are_source_dates_with_explicit_collection_time(
        tmp_path, monkeypatch, observation_date, payload_date, expected):
    observed = session(tmp_path, [offer()])
    observations = observed.read_native_inbound_events()
    observations[0]['date_raw'] = observation_date
    if payload_date is not None:
        observations[0]['payload']['date_raw'] = payload_date
    monkeypatch.setattr(observed, 'read_native_inbound_events', lambda **kwargs: deepcopy(observations))
    with closing(DurableJournal(tmp_path / 'journal.sqlite3', observed.experiment_id, SESSION)) as journal:
        source = DiplomacySource(DiplomacyTools(journal, observed))
        context = dict(source.context(), game_date=NOW + 840)
        event = source.poll_events(context, None)['events'][0]
        assert event['game_date'] == expected
        assert event['collected_game_date'] == NOW + 840
        assert event['source']['collected_game_date'] == NOW + 840
        assert event['source']['date_semantics'] == ('proposal_time_unknown' if expected is None else 'proposal_source_date')


def test_delayed_original_and_expiry_keep_dates_order_and_durable_results(tmp_path, monkeypatch):
    observed = session(tmp_path, [offer(), expired()])
    with closing(DurableJournal(tmp_path / 'journal.sqlite3', observed.experiment_id, SESSION)) as journal:
        source = DiplomacySource(DiplomacyTools(journal, observed))
        current = source.context()
        monkeypatch.setattr(source, 'context', lambda: dict(current, game_date=NOW + 840))
        database = tmp_path / 'information.sqlite3'
        with closing(InformationService(source, database)) as service:
            watch(service)
            results = service.tick()['results']
            assert len(results) == 2
            initial, terminal = results
            assert initial['event']['game_date'] is None
            assert initial['event']['source']['date_semantics'] == 'proposal_time_unknown'
            assert terminal['event']['game_date'] == NOW
            assert [row['event']['collected_game_date'] for row in results] == [NOW + 840, NOW + 840]
            assert [row['items'][0]['fields']['proposal_status']['value'] for row in results] == ['observed_pending', 'expired']
            assert service.tick()['results'] == []
        with closing(InformationService(source, database)) as reopened:
            for result in results:
                assert reopened.get_result(result['result_id'])['event'] == result['event']
