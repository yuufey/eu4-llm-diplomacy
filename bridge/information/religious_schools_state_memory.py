"""Extend the frozen school reader with native activation, without game calls."""
from copy import deepcopy
from . import country_faith_memory as faith
from . import religious_schools_memory as parent
from . import religious_schools_state_values as values
from .religion_group_memory import _checked_add, _budget_error

FIELD_ID = parent.FIELD_ID
BASIS = parent.BASIS
MAX_READ_BYTES = 16384
MAX_READ_CALLS = 384
FLAG1_RVA = 0x233FF04
FLAG2_RVA = 0x233FEB6
DEFAULT_DEFINITION_RVA = 0x2458CC8
GAPS = ['THREAD_GATED_ACTIVATION_PATH_UNRESOLVED', 'INVITED_SCHOLARS_AND_RELATIONS_NOT_READ',
        'FULL_TOOLTIP_NOT_READ', 'CALLER_ADMISSION_IS_PARENT_OWNED']


def _read_state(reader, base, binding):
    raw = {'reads': [], 'read_failures': []}
    parent_snapshots = []
    state_snapshots = []
    calls = requested = 0

    def read(address, size, label, *, snapshots=None):
        nonlocal calls, requested
        address = _checked_add(address, 0, size, label)
        if calls >= MAX_READ_CALLS:
            raise ValueError('school_state_leaf_read_call_budget_exceeded')
        if requested + size > MAX_READ_BYTES:
            raise ValueError('school_state_leaf_read_budget_exceeded')
        calls += 1
        requested += size
        row = {'address': hex(address), 'size': size, 'label': 'school_state.' + label, 'status': 'requested'}
        raw['reads'].append(row)
        try:
            data = faith._read_exact(reader, address, size, row['label'])
        except Exception as exc:
            row.update(status='failed', error_type=type(exc).__name__)
            raw['read_failures'].append({'label': row['label'], 'error_type': type(exc).__name__})
            raise
        row.update(status='ok', raw_hex=data.hex())
        if snapshots is not None:
            snapshots.append((address, size, label, data))
        return data

    class ParentReader:
        def read(self, address, size, label):
            return read(address, size, label, snapshots=parent_snapshots)

    def integer(pointer, offset, size, label):
        return int.from_bytes(read(_checked_add(pointer, offset, size, label), size, label,
                                   snapshots=state_snapshots), 'little')

    def activation(group):
        try:
            definition = integer(group, 0xA0, 8, 'activation.group_definition')
            if not definition:
                definition = integer(base, DEFAULT_DEFINITION_RVA, 8, 'activation.fallback_definition')
            faith._user_pointer(definition, 'school_definition', aligned=True)
            vtable = integer(definition, 0, 8, 'activation.definition_vtable')
            faith._user_pointer(vtable, 'school_definition_vtable', aligned=True)
            method = integer(vtable, 0x40, 8, 'activation.method40')
            if vtable == base + 0x1C48550 and method == base + 0x8F450:
                return {'status': 'known', 'value': False}
            if vtable != base + 0x1D216F8 or method != base + 0xDACBC0:
                raise ValueError('unsupported_activation_definition_type')
            if integer(definition, 0x10, 8, 'activation.definition_owner') != group:
                raise ValueError('activation_definition_owner_mismatch')
            first = integer(base, FLAG1_RVA, 1, 'activation.flag1')
            second = integer(base, FLAG2_RVA, 1, 'activation.flag2')
            if first == 0 or second != 0:
                return {'status': 'unknown', 'reason': 'RELIGIOUS_SCHOOLS_THREAD_GATE_UNRESOLVED'}
            count_raw = read(_checked_add(definition, 0x2C, 4, 'activation.count'), 4,
                             'activation.count', snapshots=state_snapshots)
            count = int.from_bytes(count_raw, 'little', signed=True)
            if not 0 <= count <= parent.MAX_SCHOOLS:
                raise ValueError('activation_count_out_of_bound')
            return {'status': 'known', 'value': count != 0}
        except Exception as exc:
            if _budget_error(exc):
                raise
            return {'status': 'unknown', 'reason': 'RELIGIOUS_SCHOOLS_ACTIVATION_UNAVAILABLE'}

    try:
        old = parent.read_fields(ParentReader(), base, binding, (FIELD_ID,))[FIELD_ID]
        raw['parent'] = old
        if old['status'] != 'known':
            return parent._unknown('school_state_parent_unknown', raw)
        parent_inputs = old['raw_inputs']['religion_identity']['raw_inputs']
        group = int(parent_inputs['religion_group_pointer'], 16)
        state = activation(group)
        state_stable = True
        for address, size, label, expected in reversed(state_snapshots):
            try:
                state_stable &= read(address, size, label + '_after') == expected
            except Exception as exc:
                if _budget_error(exc):
                    raise
                state_stable = False
        if not state_stable:
            state = {'status': 'unknown', 'reason': 'RELIGIOUS_SCHOOLS_ACTIVATION_CHANGED'}
        for address, size, label, expected in reversed(parent_snapshots):
            if read(address, size, label + '_state_after') != expected:
                return parent._unknown('school_state_parent_changed', raw)
        value = deepcopy(old['value'])
        value['uses_schools'] = state
        values.public_value(value, parent_inputs['country_binding']['tag'])
        return {'status': 'known', 'complete': False, 'basis': BASIS, 'value': value,
                'raw_inputs': raw, 'gaps': list(GAPS)}
    except Exception as exc:
        if _budget_error(exc):
            raise
        return parent._unknown('school_state_read_failed:' + type(exc).__name__, raw)
    finally:
        raw['budget'] = {'calls': calls, 'bytes_requested': requested,
                         'max_calls': MAX_READ_CALLS, 'max_bytes': MAX_READ_BYTES}


def read_fields(reader, base, binding, fields):
    if not isinstance(fields, tuple) or any(not isinstance(field, str) for field in fields):
        return {FIELD_ID: parent._unknown('fields_shape_invalid', {})}
    if len(set(fields)) != len(fields):
        return {field: parent._unknown('duplicate_field_requested', {}) for field in dict.fromkeys(fields)}
    return {field: _read_state(reader, base, binding) if field == FIELD_ID else
            parent._unknown('unsupported_field', {}) for field in fields}
