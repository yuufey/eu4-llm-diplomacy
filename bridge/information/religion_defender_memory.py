"""Bounded RPM leaf for a religion's verified defender country reference.

The native predicate supplies the row address and holder field. A separate
ordinary PE consumer supplies row self-identity. Neither establishes an absent
holder sentinel, array capacity/count semantics, tier or caller visibility.
"""
from __future__ import annotations

from collections.abc import Mapping

from . import country_faith_memory as _faith
from . import country_reference_memory as _countries
from .religion_group_memory import _checked_add

FIELD_ID = 'S02.defender'
MAX_READ_BYTES = 4096
MAX_READ_CALLS = 64
MAX_RELIGION_STATE_ID = 4096
BASIS = 'bounded_native_religion_defender_country_reference'
RELIGION_VTABLE_RVA = 0x1CDE440
RECORD_STRIDE = 0x50


def _unknown(reason, raw_inputs):
    return {'status': 'unknown', 'complete': False, 'reason': reason,
            'basis': BASIS, 'raw_inputs': raw_inputs,
            'gaps': ['ABSENT_DEFENDER_SENTINEL_NOT_ESTABLISHED',
                     'DEFENDER_TIER_ELIGIBILITY_AND_TOOLTIP_NOT_READ',
                     'CALLER_ADMISSION_IS_PARENT_OWNED']}


class _Invalid(ValueError):
    pass


def _read_defender(reader, base, target_binding):
    raw_inputs = {'reads': [], 'read_failures': []}
    snapshots = []
    calls = requested = 0

    def read(address, size, name, *, remember=True):
        nonlocal calls, requested
        address = _checked_add(address, 0, size, name)
        if calls >= MAX_READ_CALLS:
            raise _Invalid('religion_defender_leaf_read_call_budget_exceeded')
        if requested + size > MAX_READ_BYTES:
            raise _Invalid('religion_defender_leaf_read_budget_exceeded')
        calls += 1
        requested += size
        row = {'address': hex(address), 'size': size,
               'label': 'religion_defender.' + name, 'status': 'requested'}
        raw_inputs['reads'].append(row)
        try:
            data = _faith._read_exact(reader, address, size, row['label'])
        except Exception as exc:
            row.update(status='failed', error_type=type(exc).__name__)
            raw_inputs['read_failures'].append({'label': row['label'], 'error_type': type(exc).__name__})
            raise
        row.update(status='ok', raw_hex=data.hex())
        if remember:
            snapshots.append((address, size, name, data))
        return data

    def ptr(address, name):
        value = int.from_bytes(read(address, 8, name + '_before'), 'little')
        _faith._user_pointer(value, name, aligned=True)
        raw_inputs[name] = hex(value)
        return value

    def at(address, offset, size, label):
        return _checked_add(address, offset, size, label)

    def require(condition, reason):
        if not condition:
            raise _Invalid(reason)

    try:
        require(type(base) is int and base & 7 == 0, 'module_base_invalid')
        _faith._user_pointer(base, 'module_base', aligned=True)
        country, binding = _faith._binding(target_binding)
        raw_inputs.update(module_base=hex(base), country_pointer=hex(country), country_binding=binding)
        entry = _faith._parse_uint(binding.get('table_entry_address'), 'table_entry_address')
        _faith._user_pointer(entry, 'table_entry_address', aligned=True)
        selected_fullref_address = at(country, 0x20, 8, 'selected_fullref')
        require(_faith._parse_uint(binding.get('country_fullref_address'), 'country_fullref_address') ==
                selected_fullref_address, 'selected_fullref_address_mismatch')
        require(binding.get('table_entry_raw_hex') == country.to_bytes(8, 'little').hex(),
                'selected_table_binding_invalid')
        require(read(entry, 8, 'selected_table_entry_before') == country.to_bytes(8, 'little'),
                'selected_table_entry_changed')
        selected_ref = int(binding['fullref'], 16)
        require(read(selected_fullref_address, 8, 'selected_fullref_before') == selected_ref.to_bytes(8, 'little'),
                'selected_fullref_changed')
        religion = ptr(at(country, 0xF30, 8, 'religion_pointer'), 'religion_pointer')
        vtable_raw = read(religion, 8, 'religion_vtable_before')
        require(int.from_bytes(vtable_raw, 'little') == at(base, RELIGION_VTABLE_RVA, 8, 'religion_vtable'),
                'unsupported_religion_type')
        state_id = int.from_bytes(read(at(religion, 0x70, 4, 'religion_state_id'), 4,
                                      'religion_state_id_before'), 'little', signed=True)
        raw_inputs['religion_state_id'] = state_id
        require(1 <= state_id <= MAX_RELIGION_STATE_ID, 'religion_state_id_out_of_bound')
        world = ptr(at(base, 0x233FE58, 8, 'world_global'), 'world_pointer')
        manager = ptr(at(world, 0x25A8, 8, 'religion_manager'), 'manager_pointer')
        records = ptr(at(manager, 0x30, 8, 'religion_records'), 'records_pointer')
        record = at(records, (state_id - 1) * RECORD_STRIDE, RECORD_STRIDE, 'religion_record')
        raw_inputs['record_pointer'] = hex(record)
        require(read(at(record, 0x10, 8, 'record_religion'), 8, 'record_religion_before') ==
                religion.to_bytes(8, 'little'), 'record_religion_identity_mismatch')
        holder_raw = read(at(record, 0x34, 8, 'holder_reference'), 8, 'holder_reference_before')
        holder_ref = int.from_bytes(holder_raw, 'little')
        raw_inputs['holder_reference'] = hex(holder_ref)
        holder_tag = _countries._tag_from_fullref(holder_ref)
        holder_slot = (holder_ref >> 32) & 0xFFFF
        require(holder_tag is not None and holder_raw[7] != 0 and 0 < holder_slot < 4096,
                'defender_reference_unresolved')
        require(holder_slot != binding['slot'] or holder_ref == selected_ref,
                'defender_selected_generation_mismatch')
        database = ptr(at(base, 0x233D8B0, 8, 'country_database_global'), 'country_database_pointer')
        table = ptr(at(database, 0x118, 8, 'country_table'), 'country_table_pointer')
        count = int.from_bytes(read(at(database, 0x124, 4, 'country_table_count'), 4,
                                   'country_table_count_before'), 'little', signed=True)
        require(1 <= count <= 4096 and holder_slot < count, 'defender_slot_out_of_bound')
        holder_country = ptr(at(table, holder_slot * 8, 8, 'holder_table_entry'), 'holder_country_pointer')
        require(read(at(holder_country, 0x20, 8, 'holder_country_fullref'), 8,
                     'holder_country_fullref_before') == holder_raw, 'defender_country_fullref_mismatch')
        # Recheck every dependency, including the selected-country binding,
        # without invoking any native function. The parent also compares passes.
        for address, size, name, expected in reversed(snapshots):
            actual = read(address, size, name.removesuffix('_before') + '_after', remember=False)
            require(actual == expected, 'defender_dependency_changed')
        value = {'defender_country': holder_tag, 'is_target_defender': holder_ref == selected_ref}
        return {'status': 'known', 'complete': False, 'basis': BASIS,
                'value': value, 'raw_inputs': raw_inputs,
                'gaps': ['ABSENT_DEFENDER_SENTINEL_NOT_ESTABLISHED',
                         'DEFENDER_TIER_ELIGIBILITY_AND_TOOLTIP_NOT_READ',
                         'CALLER_ADMISSION_IS_PARENT_OWNED']}
    except Exception as exc:
        message = str(exc)
        if 'read_budget_exceeded' in message or 'read_call_budget_exceeded' in message:
            raise
        reason = message if isinstance(exc, _Invalid) else 'religion_defender_read_failed:' + type(exc).__name__
        return _unknown(reason[:180], raw_inputs)
    finally:
        raw_inputs['budget'] = {'calls': calls, 'bytes_requested': requested,
                                'max_calls': MAX_READ_CALLS, 'max_bytes': MAX_READ_BYTES}


def read_fields(limiter, base, target_binding: Mapping, fields: tuple[str, ...]):
    if not isinstance(fields, tuple) or any(not isinstance(field, str) for field in fields):
        return {FIELD_ID: _unknown('fields_shape_invalid', {})}
    if len(set(fields)) != len(fields):
        return {field: _unknown('duplicate_field_requested', {}) for field in dict.fromkeys(fields)}
    return {field: _read_defender(limiter, base, target_binding) if field == FIELD_ID
            else _unknown('unsupported_field', {}) for field in fields}
