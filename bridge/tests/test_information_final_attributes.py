"""N09 keeps native attribute units, unknown siblings, and session identity."""
from copy import deepcopy

import pytest

from bridge.information.final_attributes import NativeFinalAttributesSource
from bridge.information.model import InformationError
from bridge.information.sources import _result, _source_info
from bridge.tests.test_information_war_exhaustion import _context


def scalar(value=1050):
    return {'status': 'known', 'value': value, 'raw': value,
        'raw_hex': value.to_bytes(4, 'little', signed=True).hex(), 'unit': 'ratio',
        'scale': 1000, 'period': 'current', 'complete': False}


def morale():
    values = {'army': 3150, 'navy': 2400}
    return {'status': 'known', 'value': values, 'raw': deepcopy(values),
        'raw_hex': {k: v.to_bytes(4, 'little', signed=True).hex() for k, v in values.items()},
        'unit': 'morale', 'scale': 1000, 'period': 'current', 'complete': True}


class Upstream:
    def __init__(self):
        self.ctx = _context()
        self.fields = {'discipline': scalar(), 'morale': morale()}
        self.calls = []
        self.change_context = False
        self.hash = 'ac' * 32
        self.source_name = 'NativeMilitaryQualitySource'

    def context(self):
        return deepcopy(self.ctx)

    def read(self, query, context):
        self.calls.append(deepcopy(query))
        source = _source_info(self.source_name, context, complete=False,
                              provenance={'capture_report_sha256': self.hash})
        result = _result(query, context, deepcopy(self.fields), False, source)
        if self.change_context:
            self.ctx['game_date'] += 1
        return result


def query(fields=('final_value',), country='FRA'):
    return {'topic': 'N09', 'object': {'type': 'country', 'country': country},
            'fields': list(fields), 'parameters': {}}


@pytest.mark.parametrize('observer', ('FRA', 'TUR'))
def test_values_keep_independent_units_and_partial_coverage(observer):
    upstream = Upstream()
    upstream.ctx['observer'] = observer
    result = NativeFinalAttributesSource(upstream).read(query(country=observer))
    field = result['fields']['final_value']
    assert field['status'] == 'known' and field['complete'] is False
    assert field['value']['discipline'] == upstream.fields['discipline']
    assert field['value']['morale']['value'] == {'army': 3150, 'navy': 2400}
    assert result['source']['provenance']['capture_report_sha256'] == upstream.hash
    assert upstream.calls[0]['fields'] == ['discipline', 'morale']
    assert upstream.calls[0]['object']['country'] == observer


def test_unknown_attribute_does_not_withdraw_known_sibling():
    upstream = Upstream()
    upstream.fields['discipline'] = {'status': 'unknown', 'reason': 'modifier_cache_calculating'}
    value = NativeFinalAttributesSource(upstream).read(query())['fields']['final_value']
    assert value['status'] == 'known'
    assert value['value']['discipline']['status'] == 'unknown'
    assert value['value']['morale']['status'] == 'known'


@pytest.mark.parametrize('tamper', ('raw', 'unit', 'bool'))
def test_bad_scalar_never_becomes_known_but_keeps_valid_morale(tamper):
    upstream = Upstream()
    if tamper == 'raw':
        upstream.fields['discipline']['raw_hex'] = '00000000'
    elif tamper == 'unit':
        upstream.fields['discipline']['scale'] = 1
    else:
        upstream.fields['discipline']['value'] = True
    value = NativeFinalAttributesSource(upstream).read(query())['fields']['final_value']['value']
    assert value['discipline']['status'] == 'unknown'
    assert value['morale']['status'] == 'known'


@pytest.mark.parametrize('change', ('date', 'hash', 'source'))
def test_stale_or_unproven_upstream_is_withdrawn(change):
    upstream = Upstream()
    if change == 'date':
        upstream.change_context = True
    elif change == 'hash':
        upstream.hash = None
    else:
        upstream.source_name = 'OtherSource'
    field = NativeFinalAttributesSource(upstream).read(query())['fields']['final_value']
    assert field['status'] != 'known' and 'value' not in field


def test_unsupported_fields_and_foreign_scope_do_not_read():
    upstream = Upstream()
    source = NativeFinalAttributesSource(upstream)
    result = source.read(query(('modifier_effects', 'effective_status')))
    assert all(f['status'] == 'unsupported' for f in result['fields'].values())
    with pytest.raises(InformationError, match='configured observer'):
        source.read(query(country='POR'))
    assert upstream.calls == []


def test_missing_values_preserve_unknown_states_and_catalogue_scope():
    upstream = Upstream()
    upstream.fields = {'discipline': {'status': 'unknown', 'reason': 'calculating'},
                       'morale': {'status': 'unavailable', 'reason': 'cache_missing'}}
    source = NativeFinalAttributesSource(upstream)
    field = source.read(query())['fields']['final_value']
    assert field['status'] == 'unknown' and 'value' not in field
    assert field['attributes']['morale']['reason'] == 'cache_missing'
    catalogue = source.catalog()[0]
    assert catalogue['fields']['final_value']['coverage'] == 'partial'
    assert catalogue['observer_scope'] == []
