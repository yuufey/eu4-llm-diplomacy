"""Current province power annotations never become acquisition forecasts."""
from copy import deepcopy

import pytest

from bridge.information.trade_targets import TradeTargetsReader
from bridge.tests import test_information_trade_targets as fixtures


class PowerReader:
    def __init__(self, mutate=None, fail=False):
        self.calls = []
        self.mutate = mutate
        self.fail = fail

    def read(self, province_id, context):
        self.calls.append(province_id)
        if self.fail:
            raise RuntimeError('private 0x1234')
        result = {
            'status': 'known', 'province_id': province_id,
            'value': {'raw': 0 if province_id == 183 else 34104,
                      'scale': 1000, 'unit': 'trade_power'},
            'game_date': context['game_date'], 'period': 'current',
            'partial': True, 'complete': False,
            'basis': 'native_province_trade_power_trigger_cache',
            'acquisition_delta_evaluated': False,
            'cache_refresh_timing_verified': False,
            'source': {'name': 'NativeProvinceTradePowerReader', 'mode': 'live',
                'status': 'observed', 'observer': 'FRA',
                'session_id': context['session_id'],
                'provenance': {'observer': 'FRA', 'province_id': province_id,
                    'read_only': True, 'native_function_invoked': False,
                    'capture_report_sha256': 'a' * 64}},
        }
        if self.mutate:
            self.mutate(result)
        return result


def read(reader, rows=(183, 227)):
    graph = fixtures.FakeTradeGraph([fixtures._member(pid, i) for i, pid in enumerate(rows)])
    target = TradeTargetsReader(graph, fixtures.FakeProvinceSource(), power_reader=reader)
    return target, target.read(fixtures.NODE_ID, fixtures.LIVE_CONTEXT,
                               {'offset': 0, 'limit': len(rows)})


def test_current_zero_and_positive_power_preserve_source_and_do_not_predict_gain():
    power = PowerReader()
    _, result = read(power)
    assert result['status'] == 'known'
    assert result['value']['power_reads'] == 2
    for row, raw in zip(result['value']['rows'], (0, 34104)):
        item = row['current_trade_power']
        assert item['status'] == 'known'
        assert item['value'] == {'raw': raw, 'scale': 1000, 'unit': 'trade_power'}
        assert item['source']['provenance']['province_id'] == row['province_id']
        assert item['acquisition_delta_evaluated'] is False
        assert row['classification']['expected_benefit']['status'] == 'unknown'
        assert row['current_annotations']['fields']['owner']['status'] == 'known'


@pytest.mark.parametrize('mutate', [
    lambda r: r.update(province_id=True),
    lambda r: r.update(game_date=-1),
    lambda r: r.update(complete=True),
    lambda r: r.update(basis='node_aggregate'),
    lambda r: r.update(acquisition_delta_evaluated=True),
    lambda r: r['value'].update(raw=True),
    lambda r: r['value'].update(raw=1 << 31),
    lambda r: r['value'].update(scale=True),
    lambda r: r['value'].update(unit='ducats'),
    lambda r: r['source'].update(session_id='other-session'),
    lambda r: r['source'].update(observer='POR'),
    lambda r: r['source']['provenance'].update(native_function_invoked=True),
    lambda r: r['source']['provenance'].update(capture_report_sha256='bad'),
    lambda r: r['source']['provenance'].update(province_id=227),
])
def test_unverified_power_cannot_be_attached_to_a_candidate(mutate):
    _, result = read(PowerReader(mutate), rows=(183,))
    row = result['value']['rows'][0]
    assert row['current_trade_power']['status'] == 'unknown'
    assert row['current_trade_power']['reason'] == 'TRADE_TARGET_POWER_BINDING_INVALID'
    assert 'value' not in row['current_trade_power']
    assert row['current_annotations']['fields']['owner']['status'] == 'known'


def test_failed_power_does_not_hide_other_annotations_or_expose_addresses():
    _, result = read(PowerReader(fail=True), rows=(183,))
    row = result['value']['rows'][0]
    assert row['current_trade_power']['status'] == 'unavailable'
    assert row['current_trade_power']['reason'] == 'TRADE_TARGET_POWER_READ_FAILED'
    assert '0x' not in str(row['current_trade_power'])
    assert row['current_annotations']['fields']['owner']['status'] == 'known'


def test_unknown_reason_is_sanitized_and_never_becomes_a_zero_value():
    power = PowerReader(lambda r: r.update(status='unknown', reason='private 0x1234'))
    _, result = read(power, rows=(183,))
    item = result['value']['rows'][0]['current_trade_power']
    assert item['status'] == 'unknown'
    assert item['reason'] == 'TRADE_TARGET_POWER_UNKNOWN'
    assert 'value' not in item


def test_duplicate_candidates_share_only_within_one_page_read():
    power = PowerReader()
    target, first = read(power, rows=(183, 183))
    second = target.read(fixtures.NODE_ID, fixtures.LIVE_CONTEXT, {'offset': 0, 'limit': 2})
    assert first['value']['power_reads'] == second['value']['power_reads'] == 1
    assert power.calls == [183, 183]
    first['value']['rows'][0]['current_trade_power']['value']['raw'] = 99
    assert first['value']['rows'][1]['current_trade_power']['value']['raw'] == 0
    assert second['value']['rows'][0]['current_trade_power']['value']['raw'] == 0


def test_absent_reader_keeps_power_unknown_without_affecting_existing_fields():
    _, result = read(None, rows=(183,))
    assert result['value']['power_reads'] == 0
    row = result['value']['rows'][0]
    assert row['current_trade_power']['status'] == 'unknown'
    assert row['current_trade_power']['reason'] == 'PROVINCE_TRADE_POWER_NOT_CAPTURED'
    assert row['classification']['expected_benefit']['status'] == 'unknown'
