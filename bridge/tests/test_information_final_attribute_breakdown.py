"""Arithmetic and binding checks over a retained, validated N03 observation."""
from copy import deepcopy
import json
from pathlib import Path

import pytest

from bridge.information.final_attributes import NativeFinalAttributesSource
from bridge.information.sources import _result, _source_info

FIXTURE = Path(__file__).with_name('fixtures')/'information_discipline_breakdown_146.json'


def signed_hex(value):
    return int(value).to_bytes(4, 'little', signed=True).hex()


class ReplayedQuality:
    def __init__(self):
        fixture = json.loads(FIXTURE.read_text())
        self.ctx = fixture['context']
        self.compact = fixture['compact']
        self.fields = {name: fixture[name] for name in ('discipline', 'morale')}
        self.calls = []

    def context(self):
        return deepcopy(self.ctx)

    def read(self, query, context):
        self.calls.append(deepcopy(query))
        source = _source_info('NativeMilitaryQualitySource', context, complete=False,
            provenance={'capture_report_sha256': 'ab'*32, 'military_effective': deepcopy(self.compact)})
        return _result(query, context, {name: deepcopy(self.fields[name]) for name in query['fields']}, False, source)

    def set_total(self, callback):
        before = (1000+callback+2**31) % 2**32-2**31
        value = max(10, before)
        self.fields['discipline'].update(raw=value, value=value, raw_hex=signed_hex(value))
        self.compact['field'] = deepcopy(self.fields['discipline'])
        obs = self.compact['observation']
        obs.update(callback_raw=callback, callback_raw_hex=signed_hex(callback),
            effective_before_clamp=before, effective_before_clamp_hex=signed_hex(before),
            effective_raw=value, effective_raw_hex=signed_hex(value))
        obs['processor'].update(callback_raw=callback, callback_raw_hex=signed_hex(callback))


def query(fields=('source_breakdown',)):
    return {'topic': 'N09', 'object': {'type': 'country', 'country': 'FRA'},
            'fields': list(fields), 'parameters': {}}


def test_recorded_total_is_explained_without_addresses_or_duplicate_capture():
    upstream = ReplayedQuality()
    result = NativeFinalAttributesSource(upstream).read(query(('source_breakdown', 'final_value')))
    field = result['fields']['source_breakdown']
    assert field['status'] == 'known' and field['complete'] is False
    value = field['value']['discipline']
    assert (value['base_raw'], value['aggregate_modifier_raw'], value['callback_raw'], value['final_raw']) == (1000, 0, 0, 1000)
    assert value['scale'] == 1000 and len(value['processor_terms']) == 4
    assert len(upstream.calls) == 1
    assert 'country_pointer' not in json.dumps(field) and 'address' not in json.dumps(field)


@pytest.mark.parametrize('modifier,expected_before,expected_final', [(150, 1150, 1150), (-2000, -1000, 10),
                                                                  (2147483647, -2147482649, 10)])
def test_modifier_and_signed_wrap_then_minimum_are_preserved(modifier, expected_before, expected_final):
    upstream = ReplayedQuality()
    raw_hex = signed_hex(modifier)
    upstream.compact['observation']['modifier'].update(modifier_raw=modifier, modifier_raw_hex=raw_hex,
                                                      storage_raw_hex=raw_hex)
    upstream.set_total(modifier)
    field = NativeFinalAttributesSource(upstream).read(query())['fields']['source_breakdown']
    assert field['status'] == 'known', field
    value = field['value']['discipline']
    assert value['before_minimum_raw'] == expected_before
    assert value['final_raw'] == expected_final


def test_bad_optional_detail_does_not_replace_known_final_value():
    upstream = ReplayedQuality()
    del upstream.compact['observation']['processor']
    result = NativeFinalAttributesSource(upstream).read(query(('source_breakdown', 'final_value')))
    assert result['fields']['source_breakdown']['status'] == 'unknown'
    assert result['fields']['final_value']['status'] == 'known'


def test_nonzero_processor_needing_thread_context_remains_unknown():
    upstream = ReplayedQuality()
    proc = upstream.compact['observation']['processor']
    key, raw = '0x102', 5000
    proc['global_flags'][key].update(raw=0, raw_hex='00', enabled=True)
    proc['inputs'][key].update(raw=raw, raw_hex=signed_hex(raw))
    proc['contributions'][key].update(raw=raw, raw_hex=signed_hex(raw), enabled=True,
                                    specific_flag_raw=0, scaled=1000)
    proc.update(thread_context_status='unavailable_nonzero_contribution', thread_context_unknown_for=[key])
    upstream.set_total(1000)
    field = NativeFinalAttributesSource(upstream).read(query())['fields']['source_breakdown']
    assert field['status'] == 'unknown' and 'value' not in field


def test_breakdown_only_requests_discipline_and_rejects_binding_drift():
    upstream = ReplayedQuality()
    upstream.compact['country_pointer'] = '0x900000'
    field = NativeFinalAttributesSource(upstream).read(query())['fields']['source_breakdown']
    assert field['status'] == 'unknown'
    assert upstream.calls[0]['fields'] == ['discipline']
