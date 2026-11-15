"""Read cached source terms and selected direct conditions in one bounded pass.

The caller owns province admission, discovery, process identity and two passes.
This reader never executes a modifier processor or virtual method. Unknown
children withhold their sums without discarding independently known siblings.
"""
from __future__ import annotations

import re
from . import province_goods_sources_memory as _shared
from . import province_identity_memory as _identity
from . import province_modifiers_memory as _kind
from . import province_trade_power_inputs_memory as _descriptor
from . import foreign_quality_memory as _quality
from .modifier_storage import read_raw_modifier_object

FIELD = 'G02.province_goods_modifier_source'
BASIS = 'native_cached_and_reconstructed_province_modifier_sources'
DIRECT_BASIS = 'current_native_condition_reconstruction'
CACHE_COMPONENT_OFFSETS = (
    0x1B8, 0x330, 0x4A8, 0x620, 0x798, 0x910, 0xA88, 0xC00,
    0xD78, 0xEF0, 0x1068, 0x11E0, 0x1358, 0x14D0, 0x1648,
    0x17C0, 0x1938, 0x1AB0, 0x1C28, 0x1DA0, 0x1F18, 0x2150, 0x22C8,
)
DIRECT_SOURCES = (
    ('under_siege', 0x260, True), ('blockaded', 0x330, False),
    ('in_state', 0x310, True), ('prosperity', 0x250, True),
)
MAX_BYTES = _shared.MAX_TOTAL_READ_BYTES
MAX_CALLS = _shared.MAX_READ_CALLS
_KEY = re.compile(r'[A-Za-z0-9_.:-]{1,255}\Z', re.ASCII)


def _unknown(reason, raw_inputs=None):
    result = {'status': 'unknown', 'complete': False, 'period': 'current',
              'basis': BASIS, 'reason': reason}
    if raw_inputs is not None:
        result['raw_inputs'] = raw_inputs
    return result


def _reason(exc, fallback):
    if isinstance(exc, (_shared._LeafFailure, _quality._Failure)):
        candidate = str(exc)
        if re.fullmatch(r'[A-Za-z][A-Za-z0-9_:-]{0,127}', candidate) and '0x' not in candidate.lower():
            return candidate
    return fallback


def _read_key(trace, obj, private, forbidden, *, empty_allowed):
    try:
        key, pointer, payload = _shared._read_source_key(trace, obj, private, forbidden)
    except _shared._LeafFailure as exc:
        if empty_allowed and exc.reason == 'source_key_empty':
            # An empty String32 may still retain a heap allocation. Keep its
            # actual payload in the pointer-alias exclusions for raw storage.
            detail = private['source_key_string32']
            pointer = int(detail['pointer'], 0) if detail['pointer'] is not None else None
            return None, pointer, int(detail['payload_address'], 0)
        raise
    if _KEY.fullmatch(key) is None or '0x' in key.lower():
        raise _shared._LeafFailure('SOURCE_KEY_UNSUPPORTED')
    return key, pointer, payload


def _read_kind(trace, base, definition):
    vtable = _quality._valid_pointer(trace.u64(definition, 'province_sources.kind_vtable'), 'VTABLE')
    if not base <= vtable <= base + _kind.IMAGE_SIZE - 0x98:
        raise _shared._LeafFailure('KIND_VTABLE_OUTSIDE_IMAGE')
    method = trace.u64(vtable + 0x90, 'province_sources.kind_slot')
    if method == base + _kind.SUPPORTED_TRUE_METHOD_RVA:
        code, value = _kind.SUPPORTED_TRUE_METHOD_BYTES, True
    elif method == base + _kind.SUPPORTED_FALSE_METHOD_RVA:
        code, value = _kind.SUPPORTED_FALSE_METHOD_BYTES, False
    else:
        raise _shared._LeafFailure('KIND_METHOD_UNSUPPORTED')
    if trace.exact(method, len(code), 'province_sources.kind_code') != code:
        raise _shared._LeafFailure('KIND_CODE_MISMATCH')
    return value


def _definition(trace, base, manager, offset, expected, needs_kind, forbidden):
    info = {'present': None, 'raw': None, 'kind': None,
            'reason': 'DIRECT_DEFINITION_UNVERIFIED', 'private': {}}
    if manager is None:
        info['reason'] = 'STATIC_MANAGER_UNVERIFIED'
        return info
    try:
        definition = trace.u64(manager + offset, 'province_sources.definition.' + expected)
        info['present'] = definition != 0
        if not definition:
            info['reason'] = 'DIRECT_DEFINITION_NOT_PRESENT'
            return info
        definition = _quality._valid_pointer(definition, 'DEFINITION')
        if definition in (*forbidden, manager):
            raise _shared._LeafFailure('DIRECT_DEFINITION_POINTER_ALIAS')
        denied = (*forbidden, manager, definition, definition + 0x158)
        key, pointer, payload = _read_key(trace, definition, info['private'], denied, empty_allowed=False)
        if key != expected:
            raise _shared._LeafFailure('DIRECT_SOURCE_KEY_MISMATCH')
        if needs_kind:
            try:
                info['kind'] = _read_kind(trace, base, definition)
            except Exception as exc:
                info['reason'] = _reason(exc, 'DIRECT_KIND_UNVERIFIED')
        storage = read_raw_modifier_object(trace, definition, 21, 'raw_i32',
            name='province_sources.direct.' + expected,
            forbidden_pointers=tuple(item for item in (*denied, pointer, payload) if item is not None))
        info['private']['storage'] = storage
        if storage.get('status') == 'known':
            info['raw'] = storage['raw']
            if not needs_kind or info['kind'] is not None:
                info['reason'] = None
        elif info['reason'] in (None, 'DIRECT_DEFINITION_UNVERIFIED'):
            info['reason'] = 'DIRECT_STORAGE_UNVERIFIED'
    except Exception as exc:
        info['reason'] = _reason(exc, 'DIRECT_DEFINITION_UNVERIFIED')
    return info


def _direct_row(key, info, predicate, predicate_reason=None, *, kind_required=False,
                incomplete_when_true=False):
    row = {'status': 'unknown', 'source_key': key, 'definition_raw': info['raw'],
        'enabled': None, 'applied_raw': None, 'scale': 1000, 'basis': DIRECT_BASIS,
        'last_refresh_execution_observed': False}
    reason = predicate_reason or info['reason'] or 'DIRECT_CONDITION_UNVERIFIED'
    if predicate is False:
        enabled = False
    elif predicate is None:
        enabled = None
    elif incomplete_when_true:
        enabled = None
        reason = 'PROSPERITY_CONDITIONS_NOT_FULLY_MODELED'
    elif key == 'blockaded' and info['present'] is False:
        enabled = False  # This native callback explicitly tests the pointer.
    elif kind_required and info['kind'] is False:
        enabled = False
    elif kind_required and info['kind'] is not True:
        enabled = None
    elif info['raw'] is None:
        enabled = None
    else:
        enabled = True
    if enabled is not None:
        row.update(status='known', enabled=enabled, applied_raw=info['raw'] if enabled else 0)
    else:
        row['reason'] = reason
    return row


def _read(reader, base, binding):
    bounded = _shared._BudgetedSource(reader)
    trace = _quality._TraceReader(bounded)
    private = {'cached_components': [], 'direct_sources': {}}
    result = _unknown('PROVINCE_SOURCES_UNVERIFIED')
    try:
        base, record, validated = _identity._validate_binding(base, binding)
        if not 1 <= validated['province_id'] <= 0xffff:
            raise _shared._LeafFailure('PROVINCE_ID_UNSUPPORTED')
        cache, aggregate_obj = record + 0x988, record + 0x998
        if trace.u32(cache, 'province_sources.cache_state') != 2:
            raise _shared._LeafFailure('PROVINCE_MODIFIER_CACHE_NOT_READY')
        manager = _quality._valid_pointer(trace.u64(base + 0x2358060,
            'province_sources.modifier_manager'), 'MODIFIER_MANAGER')
        descriptor_address = _quality._add(manager, 21 * 0x60, 0x60)
        descriptor_raw = trace.exact(descriptor_address, 0x60, 'province_sources.descriptor21')
        private['descriptor'] = _descriptor._parse_descriptor_name(trace, descriptor_address,
            descriptor_raw, 'trade_goods_size_modifier',
            (record, cache, manager, descriptor_address, descriptor_address + 0x40), 'province_sources21')
        if descriptor_raw[0x40:0x48] != bytes(8):
            raise _shared._LeafFailure('MODIFIER_PROCESSOR_PRESENT')
        objects = tuple(cache + offset for offset in CACHE_COMPONENT_OFFSETS)
        forbidden = (base, record, cache, aggregate_obj, manager, *objects)
        aggregate = read_raw_modifier_object(trace, aggregate_obj, 21, 'raw_i32',
            name='province_sources.aggregate', forbidden_pointers=forbidden)
        private['aggregate'] = aggregate
        if aggregate.get('status') != 'known':
            raise _shared._LeafFailure('PROVINCE_AGGREGATE_UNVERIFIED')
        components = []
        for offset, obj in zip(CACHE_COMPONENT_OFFSETS, objects):
            detail = {'cache_offset': hex(offset), 'object_address': hex(obj)}
            private['cached_components'].append(detail)
            key = None
            try:
                key, pointer, payload = _read_key(trace, obj, detail, (*forbidden, obj + 0x158), empty_allowed=True)
                storage = read_raw_modifier_object(trace, obj, 21, 'raw_i32',
                    name='province_sources.cached.' + hex(offset),
                    forbidden_pointers=tuple(item for item in (*forbidden, obj + 0x158, pointer, payload) if item is not None))
                detail['storage'] = storage
                if storage.get('status') != 'known':
                    raise _shared._LeafFailure('CACHED_SOURCE_STORAGE_UNVERIFIED')
                components.append({'status': 'known', 'source_key': key, 'raw': storage['raw'], 'scale': 1000})
            except Exception as exc:
                components.append({'status': 'unknown', 'source_key': key,
                    'reason': _reason(exc, 'CACHED_SOURCE_UNVERIFIED')})
        predicates = {}
        state = None
        for key, offset, mask in (('under_siege', 0x388, None), ('blockaded', 0x958, 0x40), ('in_state', 0x2e0, None)):
            try:
                value = trace.u8(record + offset, 'province_sources.predicate.' + key) if mask else trace.u64(
                    record + offset, 'province_sources.predicate.' + key)
                if mask is None and value:
                    _quality._valid_pointer(value, 'PROVINCE_PREDICATE')
                predicates[key] = (bool(value & mask) if mask else bool(value), None)
                if key == 'in_state':
                    state = value
            except Exception:
                predicates[key] = (None, 'PROVINCE_PREDICATE_UNVERIFIED')
        try:
            if state == 0:
                predicates['prosperity'] = (False, None)
            elif state is None:
                predicates['prosperity'] = (None, 'PROVINCE_STATE_UNVERIFIED')
            else:
                value = trace.i32(state + 0x18, 'province_sources.prosperity_necessary_value')
                predicates['prosperity'] = (value >= 100000, None)
        except Exception:
            predicates['prosperity'] = (None, 'PROSPERITY_THRESHOLD_UNVERIFIED')
        try:
            static = _quality._valid_pointer(trace.u64(base + 0x242bce8,
                'province_sources.static_manager'), 'STATIC_MANAGER')
        except Exception:
            static = None
        direct = []
        for key, offset, needs_kind in DIRECT_SOURCES:
            info = _definition(trace, base, static, offset, key, needs_kind, forbidden)
            private['direct_sources'][key] = info
            predicate, reason = predicates[key]
            direct.append(_direct_row(key, info, predicate, reason, kind_required=needs_kind,
                incomplete_when_true=key == 'prosperity'))
        cached_sum = _shared._i32(sum(row['raw'] for row in components)) if all(
            row['status'] == 'known' for row in components) else None
        direct_sum = _shared._i32(sum(row['applied_raw'] for row in direct)) if all(
            row['status'] == 'known' for row in direct) else None
        residual = (_shared._i32(aggregate['raw'] - cached_sum - direct_sum)
            if cached_sum is not None and direct_sum is not None else None)
        result = {'status': 'known', 'complete': False, 'period': 'current', 'basis': BASIS,
            'value': {'province_id': validated['province_id'], 'modifier_index': 21,
                'modifier_key': 'trade_goods_size_modifier', 'aggregate_raw': aggregate['raw'],
                'cached_components': components, 'cached_sum_raw': cached_sum,
                'direct_sources': direct, 'direct_sum_raw': direct_sum, 'residual_raw': residual,
                'scale': 1000, 'current_only': True, 'full_source_coverage': False,
                'last_refresh_execution_observed': False, 'descriptor_qualified': True}}
    except Exception as exc:
        result = _unknown(_reason(exc, str(exc) if not trace.reads and isinstance(exc, ValueError)
            and re.fullmatch(r'[A-Za-z][A-Za-z0-9_:-]{0,127}', str(exc)) else 'PROVINCE_SOURCES_UNVERIFIED'))
    changed = _shared._recheck_used_bytes(trace, bounded, private)
    if changed or bounded.budget_rejected:
        result = _unknown(changed or 'PROVINCE_SOURCES_READ_BUDGET')
    private.update(reads=trace.reads, budget=bounded.budget(trace))
    result['raw_inputs'] = private
    return result


def read_fields(reader, base, province_binding, fields):
    if not isinstance(fields, (tuple, list)) or len(fields) > _identity.MAX_FIELDS:
        return {}
    if any(not isinstance(field, str) for field in fields):
        return {}
    unique = tuple(dict.fromkeys(fields))
    if len(unique) != len(fields):
        return {field: _unknown('DUPLICATE_FIELD_REQUESTED') for field in unique}
    result = {field: _unknown('UNSUPPORTED_FIELD') for field in unique if field != FIELD}
    if FIELD in unique:
        result[FIELD] = _read(reader, base, province_binding)
    return result
