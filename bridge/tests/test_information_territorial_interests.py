from copy import deepcopy
import json
import hashlib
from types import SimpleNamespace

import pytest

from bridge.information import InformationService
from bridge.information.composite import CompositeSource
from bridge.information.model import InformationError
from bridge.information.tools import InformationTools
from bridge.information import territorial_interests as interests
from bridge.tests.test_information_foreign_technology import Base
from bridge.tests.test_information_foreign_technology_capture import (
    MODULE_BASE, RecordingReader, make_valid_capture,
)


def query():
    return {'topic': 'G05', 'object': {'type': 'country_pair', 'actor': 'FRA', 'recipient': 'ENG'},
            'fields': list(interests.FIELDS), 'parameters': {'province_ids': [1, 2, 3]}}


def event():
    return {'event': interests.CAPABILITY, 'observer': 'FRA', 'actor': 'FRA',
        'recipient': 'ENG', 'submitted': False, 'frame_thread': 9, 'date_raw': 20,
        'provinces': [
            {'province_id': 1, 'visible': True, 'actor': 'vital', 'recipient': 'strategic'},
            {'province_id': 2, 'visible': True, 'actor': 'none', 'recipient': 'vital'},
            {'province_id': 3, 'visible': False, 'actor': 'none', 'recipient': 'none'}]}


def make_source(tmp_path, admitted=True):
    report, context, creation, fixture = make_valid_capture(admitted=admitted)
    reader = RecordingReader(fixture['image'])
    report['schema'] = interests.SCHEMA
    report['observation'] = interests._observe(reader, MODULE_BASE, 'ENG', interests._owner._load_profile())
    report['raw_reads'] = deepcopy(reader.read_log)
    report['access'] = {'read_only': True, 'native_function_invoked': False, 'writes': False,
        'UI_control': False, 'date_advance': False, 'save_or_reload': False,
        'limit_bytes': interests._owner.MAX_READ_BYTES,
        'calls': reader.calls, 'bytes_requested': reader.bytes_requested}
    base = Base(tmp_path, context, creation)
    base.diplomacy_tools = SimpleNamespace(session=base.session)
    calls = []

    def native_query(session, actor, recipient, ids):
        calls.append((actor, recipient, ids))
        return event()

    source = interests.NativeTerritorialInterestsSource(base,
        capture=lambda *args: deepcopy(report), native_query=native_query)
    return source, base, report, calls, creation


def test_normal_query_projects_interests_and_shared_candidates(tmp_path):
    source, base, report, calls, creation = make_source(tmp_path)
    assert interests.validate_capture(report, base.context(), creation, 'ENG')
    service = InformationService(CompositeSource(base, [source]), tmp_path / 'information.sqlite3')
    try:
        api = InformationTools(service)
        result = api.call('information_query', {'request_id': 'interests', 'queries': [query()]})
        item = result['items'][0]
        assert 'country' not in item and (item['actor'], item['recipient']) == ('FRA', 'ENG')
        assert item['interests'] == {'FRA': {'vital': [1], 'strategic': []},
                                     'ENG': {'vital': [2], 'strategic': [1]}}
        assert item['conflicts'] == [1]
        assert item['visibility'] == {'visible': [1, 2], 'hidden': [3]}
        full = api.call('information_get_result', {'result_id': result['result_id'], 'view': 'full'})
        assert full['items'][0]['complete'] is False
        assert calls == [('FRA', 'ENG', [1, 2, 3])]
    finally:
        service.close()


def test_unadmitted_country_skips_native_predicates(tmp_path):
    source, base, report, calls, creation = make_source(tmp_path, False)
    assert interests.validate_capture(report, base.context(), creation, 'ENG')
    result = source.read(query())
    assert all(field['status'] == 'invisible' for field in result['fields'].values())
    assert calls == []


def test_hidden_province_cannot_contribute_to_conflicts_or_interests():
    value = event()
    value['provinces'][2].update(actor='vital', recipient='vital')
    projected = interests.project(value)
    assert projected['conflicts']['value'] == [1]
    assert projected['interests']['value']['FRA']['vital'] == [1]


def test_full_batch_keeps_all_32_candidates_and_rejects_missing_rows():
    value = event()
    ids = list(range(1, 33))
    value['provinces'] = [{'province_id': province, 'visible': True,
                          'actor': 'vital', 'recipient': 'strategic'} for province in ids]
    assert interests._valid_response(value, 'FRA', 'ENG', ids, 20)
    assert interests.project(value)['conflicts']['value'] == ids
    value['provinces'].pop()
    assert not interests._valid_response(value, 'FRA', 'ENG', ids, 20)


def test_unresolved_province_is_unknown_and_preserves_other_candidates():
    value = event()
    value['provinces'][1].update(actor='unknown', recipient='unknown')
    result = interests.project(value)
    assert result['interests']['complete'] is False
    assert result['visibility']['value']['unavailable'] == [2]
    assert result['conflicts']['value'] == [1]


@pytest.mark.parametrize('patch', [
    {'parameters': {'province_ids': []}},
    {'parameters': {'province_ids': [1, 1]}},
    {'parameters': {'province_ids': [True]}},
    {'parameters': {'province_ids': list(range(1, 34))}},
    {'parameters': {'province_ids': [65536]}},
    {'fields': [{}]},
    {'object': {'type': 'country_pair', 'actor': 'ENG', 'recipient': 'CAS'}},
])
def test_invalid_query_is_rejected(tmp_path, patch):
    source, *_ = make_source(tmp_path)
    with pytest.raises(InformationError):
        source.validate_query(query() | patch)


def test_single_province_query_and_complete_empty_interests(tmp_path):
    source, *_ = make_source(tmp_path)
    selected = query() | {'object': {'type': 'province', 'province_id': 1},
                          'parameters': {'country': 'ENG'}}
    assert source.validate_query(selected) == selected
    value = event()
    value['provinces'] = [{'province_id': 1, 'visible': True, 'actor': 'none', 'recipient': 'none'}]
    assert interests._valid_response(value, 'FRA', 'ENG', [1], 20)
    assert interests.project(value)['interests']['complete'] is True
    assert interests.project(value)['conflicts']['value'] == []


def test_transport_uses_atomic_channel_and_matches_identity(tmp_path):
    log = tmp_path / 'control-probe.jsonl'
    log.write_bytes(b'')
    published = []

    class Session:
        directory = tmp_path
        record = {'creation_filetime': 42}
        session_id = 'session'

        def _installation_ack(self):
            return {interests.CAPABILITY: True}

        def health(self):
            return {'status': 'ready', 'date_raw': 20}

        def _publish_atomic_request(self, wire, request_id, name):
            published.append((wire, name))
            row = event() | {'query_id': request_id, 'session_id': self.session_id}
            wrong = row | {'session_id': 'old-session'}
            log.write_text(json.dumps(wrong) + '\n' + json.dumps(row) + '\n', encoding='utf-8')
            return 'published'

    result = interests.query_native(Session(), 'FRA', 'ENG', [1, 2, 3])
    assert result['event'] == interests.CAPABILITY
    assert published[0][1] == 'diplomacy-query.request'
    assert published[0][0].startswith('EU4DIP_QUERY23 2a interests_')
    assert published[0][0].endswith('1,2,3\n')


def test_manifest_extension_preserves_parent_validation(tmp_path, monkeypatch):
    from tools import start_diplomacy_observer as installer
    path = tmp_path / 'territorial-interest-query.inc'
    path.write_bytes(b'bounded getter query fixture')
    row = {'name': path.name, 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
    parent = {'name': 'parent.inc', 'sha256': 'a' * 64}
    manifest = {'version': 61, 'sources': [parent, row],
                interests.CAPABILITY: True, 'native_territorial_interest_query_wire': 23}
    inherited = []
    monkeypatch.setattr(installer, '_validate_rival_record_manifest',
                        lambda value, directory: inherited.append(value))
    installer._validate_information_battle_manifest(manifest, tmp_path)
    assert inherited[0]['sources'] == [parent]
    assert interests.CAPABILITY not in inherited[0]
    for patch in ({interests.CAPABILITY: False}, {'native_territorial_interest_query_wire': True},
                  {'sources': [parent, row, row]}):
        with pytest.raises(SystemExit, match='BUILD_MANIFEST_MISMATCH'):
            installer._validate_information_battle_manifest(manifest | patch, tmp_path)
    path.write_bytes(b'changed source')
    with pytest.raises(SystemExit, match='BUILD_MANIFEST_MISMATCH'):
        installer._validate_information_battle_manifest(manifest, tmp_path)
