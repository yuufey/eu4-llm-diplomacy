"""Bounded copied papal influence, papacy controller and curia treasury.

Admission, EXE/session identity and comparison of two passes are parent-owned.
The null country-religion papacy definition is the native applicability gate;
an invalid controller reference remains unknown and never means 'no pope'.
"""
from __future__ import annotations

from . import country_faith_memory as faith
from . import country_reference_memory as countries
from . import papacy_values as values
from .religion_group_memory import _checked_add

FIELD_ID = 'S02.papacy'
BASIS = 'bounded_native_country_papacy_state'
MAX_READ_BYTES = 4096
MAX_READ_CALLS = 64
MAX_RELIGION_ID = 4096
RELIGION_VTABLE_RVA = 0x1CDE440
GAPS = ['CARDINALS_ELECTION_INVESTMENTS_AND_ANNUAL_INFLUENCE_NOT_READ',
        'ELIGIBILITY_AND_FULL_TOOLTIP_NOT_READ', 'CALLER_ADMISSION_IS_PARENT_OWNED']


class _Invalid(ValueError):
    pass


def _unknown(reason, raw_inputs):
    return {'status': 'unknown', 'complete': False, 'basis': BASIS,
            'reason': reason, 'raw_inputs': raw_inputs, 'gaps': list(GAPS)}


def _read_papacy(reader, base, target_binding):
    raw_inputs = {'reads': [], 'read_failures': []}
    snapshots = []
    calls = requested = 0

    def read(address, size, label, *, remember=True):
        nonlocal calls, requested
        address = _checked_add(address, 0, size, label)
        if calls >= MAX_READ_CALLS:
            raise ValueError('papacy_leaf_read_call_budget_exceeded')
        if requested+size > MAX_READ_BYTES:
            raise ValueError('papacy_leaf_read_budget_exceeded')
        calls += 1
        requested += size
        row = {'address': hex(address), 'size': size, 'label': 'papacy.'+label, 'status': 'requested'}
        raw_inputs['reads'].append(row)
        try:
            data = faith._read_exact(reader, address, size, row['label'])
        except Exception as exc:
            row.update(status='failed', error_type=type(exc).__name__)
            raw_inputs['read_failures'].append({'label': row['label'], 'error_type': type(exc).__name__})
            raise
        row.update(status='ok', raw_hex=data.hex())
        if remember:
            snapshots.append((address, size, label, data))
        return data

    def at(pointer, offset, size, label):
        return _checked_add(pointer, offset, size, label)

    def integer(address, size, label):
        return int.from_bytes(read(address, size, label+'_before'), 'little')

    def pointer(address, label):
        result = integer(address, 8, label)
        faith._user_pointer(result, label, aligned=True)
        raw_inputs[label] = hex(result)
        return result

    def require(condition, reason):
        if not condition:
            raise _Invalid(reason)

    def controller(reference, selected_ref, country_tag):
        unknown = {'status': 'unknown', 'reason': 'PAPACY_CONTROLLER_UNRESOLVED'}
        slot = (reference >> 32) & 0xFFFF
        tag = countries._tag_from_fullref(reference)
        if not reference >> 56 or tag is None or not 0 < slot < countries.MAX_COUNTRY_SLOTS:
            return unknown
        if tag == country_tag and reference != selected_ref:
            return unknown
        try:
            db = pointer(at(base, countries.DATABASE_GLOBAL_RVA, 8, 'controller_database'), 'controller_database')
            table = pointer(at(db, countries.DATABASE_TABLE_OFFSET, 8, 'controller_table'), 'controller_table')
            count = integer(at(db, countries.DATABASE_TABLE_COUNT_OFFSET, 4, 'controller_count'),
                            4, 'controller_count')
            if not 1 <= count <= countries.MAX_COUNTRY_SLOTS or slot >= count:
                return unknown
            cp = pointer(at(table, slot*8, 8, 'controller_slot'), 'controller_country')
            actual = integer(at(cp, 0x20, 8, 'controller_fullref'), 8, 'controller_fullref')
            if actual != reference:
                return unknown
            return {'status': 'known', 'country': tag, 'is_target_controller': reference == selected_ref}
        except Exception as exc:
            if 'read_budget_exceeded' in str(exc) or 'read_call_budget_exceeded' in str(exc):
                raise
            return unknown

    try:
        require(type(base) is int and base & 7 == 0, 'module_base_invalid')
        faith._user_pointer(base, 'module_base', aligned=True)
        country, binding = faith._binding(target_binding)
        entry = faith._parse_uint(binding.get('table_entry_address'), 'selected_table_entry')
        faith._user_pointer(entry, 'selected_table_entry', aligned=True)
        fullref_address = at(country, 0x20, 8, 'selected_fullref')
        require(faith._parse_uint(binding.get('country_fullref_address'), 'country_fullref_address') ==
                fullref_address, 'selected_fullref_address_mismatch')
        require(binding.get('table_entry_raw_hex') == country.to_bytes(8, 'little').hex(),
                'selected_table_binding_invalid')
        selected_ref = int(binding['fullref'], 16)
        require(integer(entry, 8, 'selected_table_entry') == country, 'selected_table_entry_changed')
        require(integer(fullref_address, 8, 'selected_fullref') == selected_ref, 'selected_fullref_changed')
        raw_inputs.update(module_base=hex(base), country_pointer=hex(country), country_binding=binding)
        religion = pointer(at(country, 0xF30, 8, 'religion'), 'religion_pointer')
        require(integer(religion, 8, 'religion_vtable') == base+RELIGION_VTABLE_RVA, 'unsupported_religion_type')
        definition = integer(at(religion, 0x578, 8, 'papacy_definition'), 8, 'papacy_definition')
        raw_inputs['papacy_definition_pointer'] = hex(definition) if definition else None
        if not definition:
            absent = {'status': 'not_applicable', 'reason': 'PAPACY_NOT_USED'}
            value = {'uses_papacy': False, 'papal_influence': dict(absent),
                     'curia_treasury': dict(absent), 'controller': dict(absent)}
        else:
            faith._user_pointer(definition, 'papacy_definition', aligned=True)
            owner = pointer(at(definition, 0x60, 8, 'papacy_owner'), 'papacy_owner_pointer')
            require(integer(owner, 8, 'owner_vtable') == base+RELIGION_VTABLE_RVA, 'unsupported_owner_religion_type')
            state_id_raw = read(at(owner, 0x70, 4, 'owner_state_id'), 4, 'owner_state_id_before')
            state_id = int.from_bytes(state_id_raw, 'little', signed=True)
            require(1 <= state_id <= MAX_RELIGION_ID, 'owner_state_id_out_of_bound')
            raw_inputs['owner_state_id'] = state_id
            world = pointer(at(base, 0x233FE58, 8, 'world'), 'world_pointer')
            manager = pointer(at(world, 0x25A8, 8, 'manager'), 'manager_pointer')
            records = pointer(at(manager, 0x30, 8, 'records'), 'records_pointer')
            record = at(records, (state_id-1)*0x50, 0x50, 'religion_record')
            raw_inputs['record_pointer'] = hex(record)
            require(integer(at(record, 0x10, 8, 'record_owner'), 8, 'record_owner') == owner,
                    'papacy_record_owner_mismatch')
            state = pointer(at(record, 0x40, 8, 'papacy_state'), 'papacy_state_pointer')
            influence_raw = read(at(country, 0xF50, 4, 'papal_influence'), 4, 'papal_influence_before')
            treasury_raw = read(at(state, 0x100, 4, 'curia_treasury'), 4, 'curia_treasury_before')
            controller_ref = integer(at(state, 0x24, 8, 'papacy_controller'), 8, 'papacy_controller')
            raw_inputs['controller_reference'] = hex(controller_ref)
            value = {'uses_papacy': True,
                     'papal_influence': values.number_value('papal_influence', influence_raw),
                     'curia_treasury': values.number_value('curia_treasury', treasury_raw),
                     'controller': controller(controller_ref, selected_ref, binding['tag'])}
        for address, size, name, expected in reversed(snapshots):
            require(read(address, size, name.removesuffix('_before')+'_after', remember=False) == expected,
                    'papacy_dependency_changed')
        values.public_value(value, binding['tag'])
        return {'status': 'known', 'complete': False, 'basis': BASIS,
                'value': value, 'raw_inputs': raw_inputs, 'gaps': list(GAPS)}
    except Exception as exc:
        if 'read_budget_exceeded' in str(exc) or 'read_call_budget_exceeded' in str(exc):
            raise
        reason = str(exc) if isinstance(exc, _Invalid) else 'papacy_read_failed:'+type(exc).__name__
        return _unknown(reason[:180], raw_inputs)
    finally:
        raw_inputs['budget'] = {'calls': calls, 'bytes_requested': requested,
                                'max_calls': MAX_READ_CALLS, 'max_bytes': MAX_READ_BYTES}


def read_fields(limiter, base, target_binding, fields):
    if not isinstance(fields, tuple) or any(not isinstance(field, str) for field in fields):
        return {FIELD_ID: _unknown('fields_shape_invalid', {})}
    if len(set(fields)) != len(fields):
        return {field: _unknown('duplicate_field_requested', {}) for field in dict.fromkeys(fields)}
    return {field: _read_papacy(limiter, base, target_binding) if field == FIELD_ID else
            _unknown('unsupported_field', {}) for field in fields}
