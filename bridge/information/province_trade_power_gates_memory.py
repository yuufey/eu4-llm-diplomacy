"""Passive operands for a20b10's zero branches and owner-linked bonus.

The caller owns canonical discovery, country admission, session and two-pass
checks. Constant-return virtual predicates are decoded, never invoked.
The province+8a8 container is intentionally not named as a trade node.
"""
from __future__ import annotations

from copy import deepcopy

from . import foreign_quality_memory as _quality
from . import province_identity_memory as _identity
from . import country_scale_development_memory as _country

FIELD = 'G02.province_trade_power_calculation_gates'
BASIS = 'native_province_trade_power_cache_writer_gates'


def _snapshot(trace, base, record, controller, owner):
    raw = {}

    def exact(address, size, label):
        value = trace.exact(address, size, 'province_trade_gates.'+label)
        raw[label] = {'address': hex(address), 'raw_hex': value.hex()}
        return value

    def number(address, size, label, signed=False):
        return int.from_bytes(exact(address, size, label), 'little', signed=signed)

    def pointer(address, label, nullable=False):
        value = number(address, 8, label)
        return 0 if nullable and value == 0 else _quality._valid_pointer(value, label)

    controller_ref = exact(record+0x470, 8, 'controller_ref')
    if controller_ref.hex() != controller['fullref_raw_hex']:
        raise _quality._Failure('CONTROLLER_REFERENCE_CHANGED')
    node = pointer(record+0xe8, 'province_node', nullable=True)
    value = {'province_node_enabled': False, 'controller_type_enabled': None,
             'owner_bonus_active': None, 'owner_bonus_raw': None}
    if node == 0:
        return value, raw
    vtable = pointer(node, 'node_vtable')
    if not base <= vtable < base+0x3000000:
        raise _quality._Failure('NODE_VTABLE_OUTSIDE_IMAGE')
    method = number(vtable+0x40, 8, 'node_method40')
    if not base <= method < base+0x3000000:
        raise _quality._Failure('NODE_PREDICATE_OUTSIDE_IMAGE')
    body = exact(method, 3, 'node_predicate_code')
    if body not in (b'\xb0\x01\xc3', b'\xb0\x00\xc3'):
        raise _quality._Failure('NODE_PREDICATE_UNSUPPORTED')
    value['province_node_enabled'] = body[1] != 0
    if not value['province_node_enabled']:
        return value, raw
    country = int(controller['country_pointer'], 0)
    country_type = pointer(country+0x2440, 'controller_type')
    enabled = number(country_type+0x79, 1, 'controller_type_flag79') != 0
    value['controller_type_enabled'] = enabled
    if not enabled:
        return value, raw
    flags = number(record+0x958, 1, 'province_flags958')
    value.update(owner_bonus_active=False, owner_bonus_raw=0)
    if not flags & 4:
        return value, raw
    if owner is None:
        raise _quality._Failure('OWNER_ADMISSION_NOT_ESTABLISHED')
    owner_ref = exact(record+0x468, 8, 'owner_ref')
    if owner_ref.hex() != owner['fullref_raw_hex']:
        raise _quality._Failure('OWNER_REFERENCE_CHANGED')
    container = pointer(record+0x8a8, 'owner_linked_container')
    begin = number(container+0x28, 8, 'owner_entries_begin')
    end = number(container+0x30, 8, 'owner_entries_end')
    if begin == end == 0:
        return value, raw
    _quality._valid_pointer(begin, 'OWNER_ENTRIES_BEGIN')
    if end < begin or end >= 0x800000000000 or (end-begin) % 8 or (end-begin)//8 > 4096:
        raise _quality._Failure('OWNER_ENTRIES_RANGE_INVALID')
    for index in range((end-begin)//8):
        entry = pointer(begin+8*index, f'owner_entry_{index}')
        ref = exact(entry+0x1c0, 8, f'owner_entry_{index}_ref')
        # Native lookup compares the 16-bit slot and returns the first match.
        # Require its complete canonical ref too, rather than using a stale row.
        if int.from_bytes(ref[4:6], 'little') != owner['slot']:
            continue
        if ref != owner_ref:
            raise _quality._Failure('OWNER_ENTRY_REFERENCE_MISMATCH')
        if number(entry+0x40, 1, 'owner_first_match_flag40') != 0:
            value['owner_bonus_active'] = True
            value['owner_bonus_raw'] = number(base+0x233f418, 4, 'owner_bonus_global', signed=True)
        break
    return value, raw


def read_fields(reader, base, province_binding, controller_binding, owner_binding=None):
    trace = _quality._TraceReader(reader)
    raw = {}
    try:
        base, record, binding = _identity._validate_binding(base, province_binding)
        _, country, controller = _country._parse_target(base, controller_binding)
        owner = None
        if owner_binding is not None:
            _, _, owner = _country._parse_target(base, owner_binding)
        first, raw['before'] = _snapshot(trace, base, record, controller, owner)
        second, raw['after'] = _snapshot(trace, base, record, controller, owner)
        if first != second or raw['before'] != raw['after']:
            raise _quality._Failure('CALCULATION_GATES_CHANGED')
        result = {'status': 'known', 'complete': False, 'period': 'current',
                  'basis': BASIS, 'value': second}
    except Exception as exc:
        reason = exc.reason if isinstance(exc, _quality._Failure) else 'CALCULATION_GATES_UNVERIFIED'
        result = {'status': 'unknown', 'complete': False, 'period': 'current', 'basis': BASIS, 'reason': reason}
    raw['reads'] = deepcopy(trace.reads)
    raw['read_budget'] = trace.budget()
    result['raw_inputs'] = raw
    return {FIELD: result}
