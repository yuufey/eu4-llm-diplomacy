"""Append node-cash reconstruction without rescanning countries or nodes."""
from copy import deepcopy

from . import foreign_country_memory as _shared
from . import province_trade_power_country_memory as _country
from . import province_trade_value_parent_memory as _value_parent
from . import node_cash_aggregate_memory as _leaf

FIELD = _leaf.FIELD
_PHASES = ('pass1', 'pass2')


def _unknown(reason):
    return {'status': 'unknown', 'complete': False, 'partial': True,
            'period': 'current', 'basis': _leaf.BASIS, 'reason': reason}


def _round(limiter, base, province_id, anchor, countries, allocation, read_fields):
    evidence = {'shared_valid': False, 'field': _unknown('NODE_CASH_SHARED_UNVERIFIED')}
    try:
        before = _value_parent._shared_snapshot(limiter, base, province_id, anchor, countries)
        fields = read_fields(limiter, base, anchor['province_scan'],
            before['observer']['binding'], anchor['country_scan'], allocation)
        normalized = _country._province._normalize_field_results(fields, (FIELD,))
        evidence['field'] = normalized[FIELD]
        after = _value_parent._shared_snapshot(limiter, base, province_id, anchor, countries)
        _country._require(_shared._same_raw(before, after), 'NODE_CASH_SHARED_CHANGED')
        _country._require(normalized[FIELD].get('raw_inputs', {}).get('shared_valid') is True,
                          'NODE_CASH_SHARED_UNVERIFIED')
        evidence.update(shared_valid=True, before=before, after=after)
    except Exception:
        evidence['field'] = _unknown('NODE_CASH_SHARED_UNVERIFIED')
    return evidence


def extend(reader, base, province_id, *, observer='FRA', parent_reader, read_fields=_leaf.read_fields):
    if (observer != 'FRA' or type(province_id) is not int or not 1 <= province_id <= 65535
            or not callable(parent_reader) or not callable(read_fields)):
        raise ValueError('NODE_CASH_PARENT_SCOPE_INVALID')
    limiter = _shared._BoundedReader(_country._province._ReaderAdapter(reader))
    result = parent_reader(limiter, base, province_id, observer=observer)
    target = result['targets'][0]
    if target.get('province_id') != province_id or FIELD in target['fields']:
        raise ValueError('NODE_CASH_PARENT_TARGET_INVALID')
    target['fields'][FIELD] = _unknown('NODE_CASH_PARENT_UNVERIFIED')
    target['field_consistency'][FIELD] = {'status': 'unknown'}
    allocation = target['fields'].get('G02.province_node_allocation', {})
    if (result.get('status') != 'observed' or result.get('consistency', {}).get('status') != 'stable'
            or allocation.get('status') != 'known'
            or target['field_consistency'].get('G02.province_node_allocation', {}).get('status') != 'stable'):
        result['budget'] = limiter.summary()
        return result
    anchors, countries = result.get('pass_evidence', {}), result.get('country_inputs_evidence', {})
    if not all(isinstance(anchors.get(p), dict) and isinstance(countries.get(p), dict)
               and countries[p].get('shared_valid') is True for p in _PHASES):
        result['budget'] = limiter.summary()
        return result
    rounds = {p: _round(limiter, base, province_id, anchors[p], countries[p], allocation, read_fields)
              for p in _PHASES}
    result.setdefault('node_cash_aggregate_evidence', {})[FIELD] = rounds
    result['budget'] = limiter.summary()
    result.setdefault('errors', []).extend(limiter.errors)
    if not all(rounds[p]['shared_valid'] for p in _PHASES):
        _value_parent._retract(result, target, 'NODE_CASH_SHARED_UNVERIFIED')
        result['consistency'] = {'status': 'unknown', 'shared_mismatch_paths': ['node_cash_aggregate']}
        return result
    first, second = (rounds[p]['field'] for p in _PHASES)
    if not _shared._same_raw(first, second):
        target['fields'][FIELD] = _unknown('NODE_CASH_CHANGED_BETWEEN_PASSES')
        target['field_consistency'][FIELD] = {'status': 'changed'}
    else:
        target['fields'][FIELD] = deepcopy(second)
        target['field_consistency'][FIELD] = {'status': 'stable' if second['status'] == 'known' else 'unknown'}
    return result
