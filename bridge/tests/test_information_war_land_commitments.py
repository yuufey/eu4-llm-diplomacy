"""Current land-promise records, shared capture replay and normal R07 delivery."""
from copy import deepcopy
from types import SimpleNamespace
import struct

import pytest

from bridge.information import country_scale_capture as scale_capture
from bridge.information import war_land_commitments_capture as capture
from bridge.information import war_land_commitments_memory as memory
from bridge.information.catalog import list_topics
from bridge.information.commitments import NativeCommitmentsSource
from bridge.information.composite import CompositeSource
from bridge.information.service import InformationService
from bridge.information.tools import InformationTools
from bridge.tests import test_information_country_scale_capture as fixture


RECORDS = 0x7F000000
WAR = 0x40000000


def _record(reference, promised):
    row = bytearray(0x90)
    struct.pack_into('<Q', row, 0, fixture.MODULE_BASE + 0x1D1F6B0)
    struct.pack_into('<Q', row, 0x10, reference)
    row[0x1C] = promised
    return row


def _bundle(reader_type=None, *, retired_promise=False):
    profile = capture._load_profile()
    report, context, creation, state = fixture._bundle(
        'FRA', profile=profile, registry_id=True)
    image = state['image']
    rows = [_record(state['refs']['POR'], 1), _record(state['refs']['FRA'], 0)]
    if retired_promise:
        rows.append(_record(int.from_bytes(b'OLD\0\x01\0\0\x01', 'little'), 0))
    image.put(WAR + 0xC0, struct.pack('<QQQ', RECORDS, RECORDS + len(rows) * 0x90,
                                    RECORDS + len(rows) * 0x90))
    image.put(RECORDS, b''.join(rows))
    reader = (reader_type or fixture.parent_fixture.RecordingReader)(image)
    binding = fixture._bound_module(profile)
    observation = scale_capture._observe_with_metadata(
        capture._owner._FailureReplayReader(reader), fixture.MODULE_BASE, 'FRA', profile,
        module_before=binding, module_after=deepcopy(binding), expected_creation=creation,
        war_details_reader=capture._details)
    report.update(schema=capture.SCHEMA, profile_sha256=capture.PROFILE_SHA256,
                  observation=observation, raw_reads=deepcopy(reader.read_log))
    report['access'].update(bytes_requested=reader.bytes_requested, calls=reader.calls)
    context.update(status='ready', mode='live', complete=True)
    return report, context, creation


def test_current_promise_uses_inverted_native_flag_and_excludes_retired_participant():
    report, context, creation = _bundle(retired_promise=True)
    assert capture.validate_capture(report, context, creation)
    field = capture.field_from_capture(report)
    assert field['status'] == 'known'
    assert len(field['value']) == 1
    row = field['value'][0]
    assert row['beneficiary'] == 'FRA' and row['side'] == 'our_side'
    assert 'opponents' not in row
    assert row['war_id'].endswith('_00000001')
    assert 'OLD' not in repr(field['value'])


def test_capture_replay_rejects_an_unrecorded_promise_change():
    report, context, creation = _bundle()
    changed = deepcopy(report)
    field = changed['observation']['backend']['targets'][0]['fields']['F01.wars']
    field['value']['details']['land_commitments']['value'][0]['beneficiary'] = 'POR'
    assert not capture.validate_capture(changed, context, creation)


class _ChangePromise(fixture.parent_fixture.RecordingReader):
    reads = 0

    def read(self, address, size, label):
        if label == 'land_commitments.records':
            self.reads += 1
            if self.reads == 2:
                self.source.put(RECORDS + 0x90 + 0x1C, b'\x01')
        return super().read(address, size, label)


class _ChangeUnusedScore(fixture.parent_fixture.RecordingReader):
    reads = 0

    def read(self, address, size, label):
        if label == 'land_commitments.records':
            self.reads += 1
            if self.reads == 2:
                self.source.put(RECORDS + 0x90 + 0x20, (25).to_bytes(4, 'little'))
        return super().read(address, size, label)


def test_two_pass_promise_change_is_unknown_and_replays():
    report, context, creation = _bundle(_ChangePromise)
    assert capture.validate_capture(report, context, creation)
    assert capture.field_from_capture(report)['status'] == 'unknown'


def test_unrequested_war_score_change_keeps_current_promise_known():
    report, context, creation = _bundle(_ChangeUnusedScore)
    assert capture.validate_capture(report, context, creation)
    assert capture.field_from_capture(report)['status'] == 'known'


@pytest.mark.parametrize('damage', ['record_type', 'missing_active_member', 'duplicate_member', 'vector_size'])
def test_invalid_record_state_is_unknown(damage):
    report, _, _ = _bundle()
    war = report['observation']['backend']['targets'][0]['fields']['F01.wars']
    # Replay the bounded memory from the first capture pass for the pure leaf.
    cells = {}
    for row in report['raw_reads']:
        if row.get('status') == 'observed':
            address = int(row['address'], 0)
            cells.update({address + index: value for index, value in enumerate(bytes.fromhex(row['raw_hex']))})
    if damage == 'record_type':
        cells[RECORDS] ^= 1
    elif damage in ('missing_active_member', 'duplicate_member'):
        reference = b'OLD\0\x01\0\0\x01' if damage == 'missing_active_member' else (
            bytes.fromhex(war['raw_inputs']['war_objects'][0]['side_a_raw_hex'])[:8])
        cells.update({RECORDS + 0x90 + 0x10 + index: value for index, value in enumerate(reference)})
    else:
        cells.update({WAR + 0xC8 + index: value for index, value in enumerate(struct.pack('<Q', RECORDS + 1))})

    def read(address, size, label):
        return bytes(cells[address + index] for index in range(size))

    result = memory.read_land_commitments(read, fixture.MODULE_BASE, war,
                                         capture._load_profile()['war_land_commitments'])
    assert result['status'] == 'unknown'


def _source(tmp_path, report, context, creation):
    identifier = report['observation']['backend']['targets'][0]['fields']['F01.wars']['value']['wars'][0]['war_id']['value']

    class Base:
        event_types = ()
        session = SimpleNamespace(directory=tmp_path, record={'creation_filetime': creation})

        def context(self):
            return deepcopy(context)

        def catalog(self):
            return list_topics()

        def read(self, query, supplied):
            assert query['topic'] == 'W01'
            return {'fields': {'war_id': {'status': 'known', 'value': identifier}}}

    base = Base()
    economy = SimpleNamespace(base_source=base, context=base.context)
    source = NativeCommitmentsSource(economy, land_capture=lambda installation: deepcopy(report))
    return base, source, identifier


def test_normal_tools_echo_selected_war_and_persist_business_values(tmp_path):
    report, context, creation = _bundle()
    base, adapter, identifier = _source(tmp_path, report, context, creation)
    database = tmp_path / 'information.sqlite3'
    service = InformationService(CompositeSource(base, [adapter]), database)
    try:
        tools = InformationTools(service)
        result = tools.call('information_query', {'request_id': 'land-promise', 'queries': [{
            'topic': 'R07', 'object': {'type': 'war', 'actor': 'FRA', 'recipient': 'POR'},
            'fields': ['land_commitments']}]})
        row = result['items'][0]
        assert row['war_id'] == identifier
        assert row['land_commitments'][0]['beneficiary'] == 'FRA'
        assert row['land_commitments'][0]['war_leader'] == 'FRA'
        assert 'raw_inputs' not in repr(result)
        configured = tools.call('information_manage_report', {
            'request_id': 'land-report', 'operation': 'create',
            'config': {'name': 'land obligations', 'detail': 'full', 'queries': [{
                'topic': 'R07', 'object': {'type': 'war', 'actor': 'FRA', 'recipient': 'POR'},
                'fields': ['land_commitments']}]}})
        report_result = tools.call('information_query', {
            'request_id': 'land-report-query', 'report_id': configured['report']['id']})
        assert report_result['items'] == result['items']
    finally:
        service.close()
    service = InformationService(CompositeSource(base, [adapter]), database)
    try:
        assert InformationTools(service).call('information_get_result', {
            'result_id': result['result_id']}) == result
    finally:
        service.close()


def test_country_pair_filters_current_beneficiary_and_preserves_known_empty(tmp_path):
    report, context, creation = _bundle()
    _, adapter, _ = _source(tmp_path, report, context, creation)
    query = {'topic': 'R07', 'object': {'type': 'country_pair', 'actor': 'FRA', 'recipient': 'ENG'},
             'fields': ['land_commitments'], 'parameters': {}}
    result = adapter.read(query, context)
    assert result['fields']['land_commitments']['status'] == 'known'
    assert result['fields']['land_commitments']['value'] == []
    query['object']['recipient'] = 'POR'
    result = adapter.read(query, context)
    assert result['fields']['land_commitments']['status'] == 'unknown'
