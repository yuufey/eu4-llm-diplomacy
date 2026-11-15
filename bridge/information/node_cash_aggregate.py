"""Compact public projection of a strictly replayed current node aggregate."""
from collections.abc import Mapping
from copy import deepcopy
import re

from .node_cash_aggregate_memory import FIELD, BASIS, MAX_MEMBERS
from .province_trade_value_calculation import aggregate_node_inputs
from .trade_value_memory import NODE_ID_RE

_KEYS = {'node_id', 'center_province_id', 'member_count', 'valued_member_count',
         'unresolved_province_ids', 'all_member_values_known', 'province_input_sum_raw',
         'calculated_node_cash_raw', 'cached_node_cash_raw', 'matches_cache',
         'scale', 'unit', 'current_only', 'cache_refresh_verified', 'future_income_claimed'}


def unknown(reason='NODE_CASH_INPUT_UNKNOWN'):
    return {'status': 'unknown', 'basis': BASIS, 'period': 'current', 'partial': True,
            'complete': False, 'native_function_invoked': False, 'reason': reason}


def _i32(value):
    return type(value) is int and -(1 << 31) <= value < (1 << 31)


def validate_annotation(item):
    """Validate the public shape without copying private trace/pointer fields."""
    bad = unknown('NODE_CASH_ANNOTATION_INVALID')
    common = {'status', 'basis', 'period', 'partial', 'complete', 'native_function_invoked'}
    if (not isinstance(item, Mapping) or item.get('basis') != BASIS
            or item.get('period') != 'current' or item.get('partial') is not True
            or item.get('complete') is not False or item.get('native_function_invoked') is not False):
        return bad
    if item.get('status') == 'unknown':
        reason = item.get('reason')
        if (set(item) != common | {'reason'} or type(reason) is not str
                or re.fullmatch(r'[A-Z0-9_:-]{1,128}', reason) is None or '0x' in reason.lower()):
            return bad
        return unknown(reason)
    value = item.get('value')
    if (item.get('status') != 'known' or set(item) != common | {'value'}
            or not isinstance(value, Mapping) or set(value) != _KEYS):
        return bad
    node, center, total, count, unresolved = (value.get(k) for k in
        ('node_id', 'center_province_id', 'member_count', 'valued_member_count', 'unresolved_province_ids'))
    if (type(node) is not str or NODE_ID_RE.fullmatch(node) is None
            or type(center) is not int or not 0 < center <= 65535
            or type(total) is not int or not 0 < total <= MAX_MEMBERS
            or type(count) is not int or not 0 <= count <= total
            or not isinstance(unresolved, list) or len(unresolved) != total-count
            or any(type(pid) is not int or not 0 < pid <= 65535 for pid in unresolved)
            or len(unresolved) != len(set(unresolved))
            or type(value.get('all_member_values_known')) is not bool
            or value['all_member_values_known'] != (count == total)
            or not _i32(value.get('cached_node_cash_raw'))
            or type(value.get('scale')) is not int or value['scale'] != 1000
            or value.get('unit') != 'node_cash' or value.get('current_only') is not True
            or value.get('cache_refresh_verified') is not False or value.get('future_income_claimed') is not False):
        return bad
    total_raw, calculated, matches = (value.get(k) for k in
        ('province_input_sum_raw', 'calculated_node_cash_raw', 'matches_cache'))
    if unresolved:
        if total_raw is not None or calculated is not None or matches is not None:
            return bad
    elif (not _i32(total_raw) or not _i32(calculated) or type(matches) is not bool
          or aggregate_node_inputs([total_raw])['node_input_raw'] != calculated
          or matches != (calculated == value['cached_node_cash_raw'])):
        return bad
    return {**{k: deepcopy(item[k]) for k in common}, 'value': deepcopy(dict(value))}


def project(target):
    raw = target.get('fields', {}).get(FIELD)
    state = target.get('field_consistency', {}).get(FIELD, {})
    if not isinstance(raw, Mapping) or raw.get('status') != 'known':
        return unknown()
    if (set(raw) != {'status', 'basis', 'period', 'partial', 'complete', 'value', 'raw_inputs'}
            or state.get('status') != 'stable'
            or not isinstance(raw.get('raw_inputs'), Mapping)
            or raw['raw_inputs'].get('shared_valid') is not True):
        return unknown('NODE_CASH_FIELD_INVALID')
    item = validate_annotation({k: raw[k] for k in ('status', 'basis', 'period', 'partial', 'complete', 'value')}
                              | {'native_function_invoked': False})
    if item.get('status') == 'known':
        allocation = target.get('fields', {}).get('G02.province_node_allocation', {}).get('value', {})
        if any(item['value'][k] != allocation.get(k) for k in ('node_id', 'center_province_id', 'member_count')):
            return unknown('NODE_CASH_NODE_BINDING_INVALID')
    return item
