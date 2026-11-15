"""Native participation arithmetic, replay and ordinary W04 delivery."""
from contextlib import closing
from copy import deepcopy
import struct

import pytest

from bridge.information import country_scale_capture as scale
from bridge.information import war_contribution_capture as capture
from bridge.information import war_contribution_memory as memory
from bridge.information.composite import CompositeSource
from bridge.information.service import InformationService
from bridge.information.tools import InformationTools
from bridge.information.war_contribution import NativeWarContributionSource
from bridge.tests import test_information_war_land_commitments as fixture


def reference(slot):
    return (slot << 32) | 0x100000000000000


@pytest.mark.parametrize('points,expected', [
    ([10, 30], [250, 750]),
    ([0, 0], [1000, 0]),
    ([0, 30], [0, 1000]),
    ([1, 2], [333, 666]),
    ([-1, 5], [-250, 1250]),
    ([2**31 - 1, 1], [1000, 0]),
])
def test_native_signed_ratio_truncation_and_zero_total_fallback(points, expected):
    records = list(zip([1, 2], points))
    side_a = [reference(1), reference(2)]
    assert [memory.participation_share(reference(slot), side_a, records) for slot in (1, 2)] == expected


def test_native_denominator_keeps_archived_record_grouping_and_large_product():
    # d95820 assigns records absent from current side_a to its opposite group.
    records = [(1, 100), (2, 300), (3, 100)]
    assert memory.participation_share(reference(2), [reference(1)], records) == 750
    assert memory.participation_share(reference(3), [reference(1)], records) == 250
    assert memory.participation_share(reference(1), [reference(1)], [(1, 2000000000)]) == 1000


def bundle(reader_type=None, points=(300, 100)):
    profile = capture._load_profile()
    report, context, creation, state = fixture.fixture._bundle('FRA', profile=profile, registry_id=True)
    image = state['image']
    rows = [fixture._record(state['refs']['POR'], 1), fixture._record(state['refs']['FRA'], 0)]
    for row, value in zip(rows, points):
        struct.pack_into('<i', row, 0x18, value)
    image.put(fixture.WAR + 0xC0, struct.pack('<QQQ', fixture.RECORDS,
        fixture.RECORDS + len(rows) * 0x90, fixture.RECORDS + len(rows) * 0x90))
    image.put(fixture.RECORDS, b''.join(rows))
    reader = (reader_type or fixture.fixture.parent_fixture.RecordingReader)(image)
    binding = fixture.fixture._bound_module(profile)
    observation = scale._observe_with_metadata(
        capture._owner._FailureReplayReader(reader), fixture.fixture.MODULE_BASE, 'FRA', profile,
        module_before=binding, module_after=deepcopy(binding), expected_creation=creation,
        war_details_reader=capture._details)
    report.update(schema=capture.SCHEMA, profile_sha256=capture.PROFILE_SHA256,
                  observation=observation, raw_reads=deepcopy(reader.read_log))
    report['access'].update(bytes_requested=reader.bytes_requested, calls=reader.calls)
    context.update(status='ready', mode='live', complete=True)
    return report, context, creation


def test_admitted_capture_preserves_visible_country_and_hides_unadmitted_member():
    report, context, creation = bundle()
    assert capture.validate_capture(report, context, creation)
    field = capture.field_from_capture(report)
    assert field['status'] == 'known' and field['complete'] is False
    war = field['value'][0]
    assert war['our_side']['FRA']['value'] == {'percent': 100.0}
    assert war['opposing_side'] == {}
    assert war['gaps'] and war['gaps'][0]['side'] == 'opposing_side'
    assert field['raw_inputs']['unavailable_countries'] == ['POR']
    changed = deepcopy(report)
    changed['observation']['backend']['targets'][0]['fields']['F01.wars']['value']['details'][
        'contribution']['value'][0]['our_side']['FRA']['value']['percent'] = 25
    assert not capture.validate_capture(changed, context, creation)


class ChangingPoints(fixture.fixture.parent_fixture.RecordingReader):
    reads = 0

    def read(self, address, size, label):
        if label == 'land_commitments.records':
            self.reads += 1
            if self.reads == 2:
                self.source.put(fixture.RECORDS + 0x90 + 0x18, struct.pack('<i', 999))
        return super().read(address, size, label)


def test_sampling_detects_contribution_change_without_requiring_land_flag_change():
    report, context, creation = bundle(ChangingPoints)
    assert capture.validate_capture(report, context, creation)
    field = capture.field_from_capture(report)
    assert field['status'] == 'unknown'


def build(tmp_path, report=None):
    report, context, creation = bundle() if report is None else report
    base, _, war_id = fixture._source(tmp_path, report, context, creation)
    source = NativeWarContributionSource(base, capture=lambda installation: deepcopy(report))
    return base, source, context, war_id


def query(obj=None):
    return {'topic': 'W04', 'object': obj or {'type': 'country', 'country': 'FRA'},
            'fields': ['contribution'], 'parameters': {}}


def test_country_subset_is_known_while_unrelated_member_is_unavailable(tmp_path):
    _, source, context, war_id = build(tmp_path)
    own = source.read(query(), context)
    assert own['complete'] is True
    assert own['fields']['contribution']['value'] == [
        {'war_id': war_id, 'side': 'our_side', 'percent': 100.0}]
    hidden = source.read(query({'type': 'country', 'country': 'POR'}), context)
    assert hidden['fields']['contribution']['status'] == 'unknown'
    absent = source.read(query({'type': 'country', 'country': 'ENG'}), context)
    assert absent['fields']['contribution']['value'] == []


def test_war_discovery_failure_skips_capture(tmp_path):
    base, source, context, _ = build(tmp_path)
    base.read = lambda query, context: {'fields': {'war_id': {'status': 'unknown', 'reason': 'WAR_SELECTION_REQUIRED'}}}
    source.capture = lambda installation: pytest.fail('Unresolved war entered capture')
    result = source.read(query({'type': 'war', 'actor': 'FRA', 'recipient': 'POR'}), context)
    assert result['fields']['contribution']['reason'] == 'WAR_SELECTION_REQUIRED'


def test_normal_war_view_echoes_selected_identity_and_preserves_visible_percentage(tmp_path):
    base, source, _, war_id = build(tmp_path)
    selected = query({'type': 'war', 'actor': 'FRA', 'recipient': 'POR'})
    with closing(InformationService(CompositeSource(base, [source]), tmp_path / 'war.sqlite3')) as service:
        result = InformationTools(service).call('information_query', {
            'request_id': 'selected-war-contribution', 'queries': [selected]})
        assert result['items'][0]['war_id'] == war_id
        assert result['items'][0]['contribution'] == {
            'our_side': {'FRA': {'percent': 100.0}}, 'opposing_side': {}}


def test_normal_tool_report_periodic_change_and_cold_reopen(tmp_path):
    base, source, _, war_id = build(tmp_path)
    now = [100.0]
    database = tmp_path / 'contribution.sqlite3'
    with closing(InformationService(CompositeSource(base, [source]), database, clock=lambda: now[0])) as service:
        tools = InformationTools(service)
        direct = tools.call('information_query', {'request_id': 'contribution-direct', 'queries': [query()]})
        assert direct['items'][0]['contribution'] == [{'war_id': war_id, 'side': 'our_side', 'percent': 100.0}]
        report = service.manage_report('contribution-report', 'create', config={
            'name': 'current participation', 'detail': 'full', 'queries': [query()]})['report']
        copied = tools.call('information_query', {'request_id': 'contribution-report-read', 'report_id': report['id']})
        assert copied['items'] == direct['items']
        subscription = service.manage_subscription('contribution-change', 'create', config={
            'kind': 'change', 'report_id': report['id'],
            'schedule': {'basis': 'real', 'unit': 'seconds', 'every': 2}})['subscription']
        now[0] = 102.0
        assert service.tick()['results'] == []
        now[0] = 104.0
        assert service.tick()['results'] == []
        zero = bundle(points=(0, 0))[0]
        source.capture = lambda installation: deepcopy(zero)
        now[0] = 106.0
        assert len(service.tick()['results']) == 1
        service.manage_subscription('contribution-cancel', 'cancel', subscription_id=subscription['id'], expected_version=1)
        periodic = service.manage_subscription('contribution-periodic', 'create', config={
            'kind': 'periodic', 'report_id': report['id'],
            'schedule': {'basis': 'real', 'unit': 'seconds', 'every': 2}})['subscription']
        now[0] = 108.0
        assert len(service.tick()['results']) == 1
        service.manage_subscription('contribution-periodic-cancel', 'cancel', subscription_id=periodic['id'], expected_version=1)
    with closing(InformationService(CompositeSource(base, [source]), database)) as reopened:
        assert InformationTools(reopened).call('information_get_result', {'result_id': direct['result_id']}) == direct
