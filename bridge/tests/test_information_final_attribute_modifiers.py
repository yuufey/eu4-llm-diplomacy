"""N09 modifier effects reuse the bounded N07 record projection only."""
from copy import deepcopy

import pytest

from bridge.information import country_modifiers_memory
from bridge.information.final_attributes import NativeFinalAttributesSource
from bridge.information.sources import _result, _source_info
from bridge.tests.test_information_final_attributes import morale, query, scalar
from bridge.tests.test_information_war_exhaustion import _context


def _signed_hex(value):
    return int(value).to_bytes(4, 'little', signed=True).hex()


def _effect(raw, index=1):
    return {
        'index': index, 'index_raw_hex': int(index).to_bytes(4, 'little').hex(),
        'raw': raw, 'raw_hex': _signed_hex(raw), 'selector': 7,
        'selector_raw_hex': (7).to_bytes(4, 'little').hex(),
        'selector_address': '0x1000', 'pair_address': '0x2000',
        'pair_raw_hex': int(index).to_bytes(4, 'little').hex() + _signed_hex(raw),
        'scale': 1000, 'unit': 'native_fixed_point', 'business_unit': 'unknown',
    }


def _effects_field(rows):
    rows = [dict(row, basis='native_modifier_definition_entries',
                 final_effective_value=False) for row in rows]
    return {
        'status': 'known', 'value': deepcopy(rows), 'raw': deepcopy(rows),
        'unit': 'modifier_effect_records', 'scale': 1, 'period': 'current',
        'complete': False, 'partial': True,
        'basis': 'native_direct_country_modifier_records',
        'value_origin': 'copied_native_country_records', 'gaps': [],
    }


class Quality:
    def __init__(self):
        self.ctx = _context()
        self.fields = {'discipline': scalar(), 'morale': morale()}
        self.calls = []
        self.error = None

    def context(self):
        return deepcopy(self.ctx)

    def read(self, request, context):
        self.calls.append(deepcopy(request))
        if self.error:
            raise self.error
        source = _source_info(
            'NativeMilitaryQualitySource', context, complete=False,
            provenance={'capture_report_sha256': 'ab' * 32},
        )
        return _result(request, context,
                       {name: deepcopy(self.fields[name]) for name in request['fields']},
                       False, source)


class Records:
    def __init__(self, rows=None):
        self.ctx = _context()
        self.field = _effects_field(rows or [])
        self.calls = []
        self.error = None
        self.change_context = False
        self.profile = country_modifiers_memory.EXPECTED_PROFILE_SHA256

    def context(self):
        return deepcopy(self.ctx)

    def read(self, request, context):
        self.calls.append(deepcopy(request))
        if self.error:
            raise self.error
        source = _source_info(
            'NativeCountryRecordsSource', context, complete=False,
            provenance={'capture_report_sha256': 'cd' * 32,
                        'profile_sha256': self.profile},
        )
        result = _result(request, context, {'effects': deepcopy(self.field)}, False, source)
        if self.change_context:
            self.ctx['game_date'] += 1
        return result


def _source(rows=None):
    quality, records = Quality(), Records(rows)
    return NativeFinalAttributesSource(quality, records), quality, records


def test_modifier_only_reads_n07_effects_and_preserves_order_negative_and_duplicate_id():
    rows = [
        {'modifier_id': 'same', 'effects': [_effect(-150, 2)]},
        {'modifier_id': 'same', 'effects': [_effect(250, 3)]},
    ]
    source, quality, records = _source(rows)
    original = deepcopy(records.field['value'])
    result = source.read(query(('modifier_effects',)))
    field = result['fields']['modifier_effects']
    assert field['status'] == 'known'
    assert field['value'] == original
    assert field['unit'] == 'modifier_effect_records'
    assert field['scale'] == 1 and field['period'] == 'current'
    assert field['complete'] is False and field['partial'] is True
    assert {'DIRECT_COUNTRY_MODIFIER_LIST_ONLY',
            'EFFECT_BUSINESS_UNITS_UNRESOLVED',
            'ACTIVATION_AND_FINAL_CONTRIBUTIONS_NOT_PROVEN'} <= set(field['gaps'])
    assert quality.calls == []
    assert records.calls[0]['fields'] == ['effects']
    field['value'][0]['effects'][0]['raw'] = 999
    assert records.field['value'][0]['effects'][0]['raw'] == -150


def test_empty_effect_list_is_known_and_modifier_only_stays_isolated():
    source, quality, records = _source([])
    result = source.read(query(('modifier_effects',)))
    assert result['fields']['modifier_effects']['status'] == 'known'
    assert result['fields']['modifier_effects']['value'] == []
    assert quality.calls == [] and len(records.calls) == 1


def test_missing_dependency_keeps_modifier_unsupported_without_any_capture():
    quality = Quality()
    source = NativeFinalAttributesSource(quality)
    result = source.read(query(('modifier_effects',)))
    assert result['fields']['modifier_effects']['status'] == 'unsupported'
    assert quality.calls == []
    assert 'modifier_effects' not in source.catalog()[0]['fields']


def test_nonknown_n07_state_is_propagated_without_inventing_empty_records():
    source, _quality, records = _source([])
    records.field = {'status': 'unknown', 'reason': 'NATIVE_RECORDS_PENDING'}
    result = source.read(query(('modifier_effects',)))
    assert result['fields']['modifier_effects'] == records.field


@pytest.mark.parametrize('tamper', ['unit', 'raw', 'profile', 'identity'])
def test_bad_n07_evidence_only_withdraws_modifier_effects(tamper):
    source, quality, records = _source([{'modifier_id': 'one', 'effects': [_effect(1)]}])
    if tamper == 'unit':
        records.field['unit'] = 'ratio'
    elif tamper == 'raw':
        records.field['value'][0]['effects'][0]['raw_hex'] = '00000000'
        records.field['raw'] = deepcopy(records.field['value'])
    elif tamper == 'profile':
        records.profile = '00' * 32
    else:
        records.source_name = 'OtherSource'
        original_read = records.read
        def wrong_source(request, context):
            result = original_read(request, context)
            result['source']['name'] = records.source_name
            return result
        records.read = wrong_source
    result = source.read(query(('modifier_effects', 'final_value')))
    assert result['fields']['modifier_effects']['status'] == 'unknown'
    assert result['fields']['final_value']['status'] == 'known'
    assert len(quality.calls) == 1 and len(records.calls) == 1


def test_bad_n03_does_not_withdraw_valid_modifier_effects():
    source, quality, records = _source([{'modifier_id': 'one', 'effects': [_effect(-2)]}])
    quality.error = RuntimeError('quality failed')
    result = source.read(query(('modifier_effects', 'final_value')))
    assert result['fields']['final_value']['status'] == 'unknown'
    assert result['fields']['modifier_effects']['status'] == 'known'
    assert len(quality.calls) == 1 and len(records.calls) == 1


def test_context_drift_after_either_delegation_retracts_all_requested_fields():
    source, quality, records = _source([{'modifier_id': 'one', 'effects': [_effect(1)]}])
    records.change_context = True
    result = source.read(query(('modifier_effects', 'final_value')))
    assert result['fields']['final_value']['status'] == 'unavailable'
    assert result['fields']['modifier_effects']['status'] == 'unavailable'


def test_catalog_declares_modifier_effects_only_when_dependency_is_injected():
    source, _quality, _records = _source([])
    assert source.catalog()[0]['fields']['modifier_effects']['coverage'] == 'partial'


@pytest.mark.parametrize('origin', ('military', 'records'))
def test_context_drift_in_a_failed_delegation_retracts_both_sources(origin):
    source, quality, records = _source([])
    failing = quality if origin == 'military' else records

    def changed_then_failed(request, context):
        failing.ctx['game_date'] += 1
        raise RuntimeError('upstream read failed after date changed')

    failing.read = changed_then_failed
    result = source.read(query(('modifier_effects', 'final_value', 'effective_status')))
    assert result['fields']['modifier_effects']['status'] == 'unavailable'
    assert result['fields']['final_value']['status'] == 'unavailable'
    assert result['fields']['effective_status']['status'] == 'unsupported'


@pytest.mark.parametrize('claim', ('basis', 'final_effective_value'))
def test_definition_entries_cannot_claim_verified_final_contributions(claim):
    source, _, records = _source([{'modifier_id': 'one', 'effects': [_effect(1)]}])
    for key in ('value', 'raw'):
        records.field[key][0][claim] = True if claim == 'final_effective_value' else 'guessed_total'
    field = source.read(query(('modifier_effects',)))['fields']['modifier_effects']
    assert field['status'] == 'unknown' and 'value' not in field


def test_real_n07_reader_and_native_validator_feed_n09_without_new_capture(tmp_path):
    from bridge.tests.test_information_country_records import source as record_source, modifier_child
    records, base, _, calls = record_source(tmp_path, 'country_modifiers', modifier_child())
    quality = Quality()
    quality.ctx = base.context()
    result = NativeFinalAttributesSource(quality, records).read(query(('modifier_effects',)))
    field = result['fields']['modifier_effects']
    assert field['status'] == 'known'
    assert [row['modifier_id'] for row in field['value']] == [
        'papal_sanction_for_church_taxes', 'shady_people']
    assert field['value'][0]['effects'][0]['raw'] == 150
    assert calls == [('FRA', {'include_country_modifiers': True})]
    assert quality.calls == []
