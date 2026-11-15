"""Extend the frozen holder reader with the loaded native tier selection.

No trigger/effect or game function is invoked. The world list layout and
pointer arithmetic reuse the existing ledger helper; stability and exact
country-reference checks cover every row used by this separate calculation.
"""
from __future__ import annotations

from . import country_faith_memory as faith
from . import country_ledger_membership_memory as membership
from . import country_reference_memory as countries
from . import religion_defender_memory as holder
from .religion_group_memory import _checked_add

FIELD_ID = holder.FIELD_ID
MAX_COUNTRIES = 2048
MAX_TIERS = 64
MAX_READ_BYTES = 192 * 1024
MAX_READ_CALLS = 16384
TIER_GLOBAL_RVA = 0x1FD1D08
TIER_STRIDE = 0x358
TIER_UNKNOWN = {'status': 'unknown', 'reason': 'RELIGION_DEFENDER_TIER_UNAVAILABLE'}


class _Changed(ValueError):
    pass


def _tier(reader, base, binding, original, raw_inputs):
    snapshots = []
    calls = requested = 0

    def read(address, size, label, *, remember=True):
        nonlocal calls, requested
        address = _checked_add(address, 0, size, label)
        if calls >= MAX_READ_CALLS:
            raise ValueError('religion_tier_read_call_budget_exceeded')
        if requested + size > MAX_READ_BYTES:
            raise ValueError('religion_tier_read_budget_exceeded')
        calls += 1
        requested += size
        row = {'address': hex(address), 'size': size, 'label': 'religion_tier.' + label,
               'status': 'requested'}
        raw_inputs['reads'].append(row)
        try:
            data = faith._read_exact(reader, address, size, row['label'])
        except Exception as exc:
            row.update(status='failed', error_type=type(exc).__name__)
            raise
        row.update(status='ok', raw_hex=data.hex())
        if remember:
            snapshots.append((address, size, label, data))
        return data

    def at(pointer, offset, size, name):
        return _checked_add(pointer, offset, size, name)

    def integer(address, size, name, *, signed=False):
        return int.from_bytes(read(address, size, name + '_before'), 'little', signed=signed)

    def pointer(address, name):
        value = integer(address, 8, name)
        membership._address(value, name)
        raw_inputs[name] = hex(value)
        return value

    def bridge(condition, name):
        if not condition:
            raise _Changed('RELIGION_DEFENDER_COMPONENTS_CHANGED:' + name)

    try:
        country, selected_binding = faith._binding(binding)
        previous = original['raw_inputs']
        selected_ref = int(selected_binding['fullref'], 16)
        selected_entry = faith._parse_uint(selected_binding['table_entry_address'], 'selected_entry')
        bridge(integer(selected_entry, 8, 'selected_entry') == country, 'selected_entry')
        bridge(integer(at(country, 0x20, 8, 'selected_ref'), 8, 'selected_ref') == selected_ref, 'selected_ref')
        religion = pointer(at(country, 0xF30, 8, 'religion'), 'religion')
        bridge(religion == int(previous['religion_pointer'], 16), 'religion')
        bridge(integer(religion, 8, 'religion_vtable') == base + holder.RELIGION_VTABLE_RVA, 'religion_type')
        state_id = integer(at(religion, 0x70, 4, 'religion_id'), 4, 'religion_id', signed=True)
        bridge(state_id == previous['religion_state_id'] and 1 <= state_id <= holder.MAX_RELIGION_STATE_ID, 'religion_id')
        world = pointer(at(base, 0x233FE58, 8, 'world_global'), 'world')
        bridge(world == int(previous['world_pointer'], 16), 'world')
        manager = pointer(at(world, 0x25A8, 8, 'manager'), 'manager')
        bridge(manager == int(previous['manager_pointer'], 16), 'manager')
        records = pointer(at(manager, 0x30, 8, 'records'), 'records')
        bridge(records == int(previous['records_pointer'], 16), 'records')
        record = at(records, (state_id-1) * holder.RECORD_STRIDE, holder.RECORD_STRIDE, 'record')
        bridge(record == int(previous['record_pointer'], 16), 'record')
        bridge(integer(at(record, 0x10, 8, 'record_religion'), 8, 'record_religion') == religion, 'record_religion')
        bridge(integer(at(record, 0x34, 8, 'record_holder'), 8, 'record_holder') ==
               int(previous['holder_reference'], 16), 'holder')
        database = pointer(at(base, countries.DATABASE_GLOBAL_RVA, 8, 'database_global'), 'database')
        table = pointer(at(database, countries.DATABASE_TABLE_OFFSET, 8, 'database_table'), 'database_table')
        db_count = integer(at(database, countries.DATABASE_TABLE_COUNT_OFFSET, 4, 'database_count'),
                           4, 'database_count', signed=True)
        bridge(database == int(previous['country_database_pointer'], 16) and
               table == int(previous['country_table_pointer'], 16), 'database')
        if not 1 <= db_count <= countries.MAX_COUNTRY_SLOTS:
            raise ValueError('database_count_out_of_bound')
        holder_ref = int(previous['holder_reference'], 16)
        holder_slot = (holder_ref >> 32) & 0xFFFF
        bridge(0 < holder_slot < db_count, 'holder_slot')
        holder_country = pointer(at(table, holder_slot*8, 8, 'holder_entry'), 'holder_entry')
        bridge(holder_country == int(previous['holder_country_pointer'], 16), 'holder_entry')
        bridge(integer(at(holder_country, 0x20, 8, 'holder_fullref'), 8, 'holder_fullref') ==
               holder_ref, 'holder_fullref')
        header = read(at(world, membership.WORLD_COUNTRY_POINTERS_OFFSET, 16, 'country_header'),
                      16, 'country_header_before')
        count = int.from_bytes(header[12:16], 'little', signed=True)
        array = int.from_bytes(header[:8], 'little')
        if not 0 <= count <= MAX_COUNTRIES:
            raise ValueError('country_count_out_of_bound')
        pointers = b''
        if count:
            membership._address(array, 'world_country_array')
            chunks = []
            for offset in range(0, count * 8, membership.MAX_SINGLE_READ_BYTES):
                size = min(membership.MAX_SINGLE_READ_BYTES, count * 8-offset)
                chunks.append(read(at(array, offset, size, 'country_rows'), size,
                                   f'country_rows_{offset}_before'))
            pointers = b''.join(chunks)
        seen_pointers, seen_refs = set(), set()
        matching = 0
        for index in range(count):
            address = int.from_bytes(pointers[index*8:index*8+8], 'little')
            membership._address(address, 'country_row')
            if address in seen_pointers:
                raise ValueError('duplicate_country_pointer')
            seen_pointers.add(address)
            fullref = integer(at(address, 0x20, 8, 'row_fullref'), 8, f'country_{index}_fullref')
            slot = (fullref >> 32) & 0xFFFF
            if (fullref in seen_refs or not fullref >> 56 or countries._tag_from_fullref(fullref) is None
                    or not 0 < slot < db_count):
                raise ValueError('country_reference_invalid')
            seen_refs.add(fullref)
            if integer(at(table, slot*8, 8, 'row_table_entry'), 8, f'country_{index}_table_entry') != address:
                raise ValueError('country_table_entry_mismatch')
            current = integer(at(address, 0xF30, 8, 'row_religion'), 8, f'country_{index}_religion')
            matching += int(current == religion)
        tier_header = read(at(base, TIER_GLOBAL_RVA, 16, 'tier_header'), 16, 'tier_header_before')
        tier_count = int.from_bytes(tier_header[12:16], 'little', signed=True)
        tier_array = int.from_bytes(tier_header[:8], 'little')
        if not 0 <= tier_count <= MAX_TIERS:
            raise ValueError('tier_count_out_of_bound')
        if tier_count:
            membership._address(tier_array, 'tier_array')
        selected = None
        for index in range(tier_count):
            prefix = read(at(tier_array, index*TIER_STRIDE, 0x30, 'tier_record'),
                          0x30, f'tier_{index}_prefix_before')
            lower = int.from_bytes(prefix[0x20:0x24], 'little', signed=True)
            upper = int.from_bytes(prefix[0x24:0x28], 'little', signed=True)
            level = int.from_bytes(prefix[0x28:0x2C], 'little', signed=True)
            if selected is None and lower <= matching and (upper == 0 or matching < upper):
                selected = {'status': 'known', 'level': level, 'same_faith_country_count': matching,
                            'range_from': lower, 'range_to_exclusive': upper if upper else None}
        for address, size, label, expected in reversed(snapshots):
            if read(address, size, label.removesuffix('_before')+'_after', remember=False) != expected:
                # A changed common holder/identity also retracts its component.
                shared = not label.startswith(('country_header_', 'country_rows_', 'country_', 'tier_'))
                if shared:
                    raise _Changed('RELIGION_DEFENDER_COMPONENTS_CHANGED')
                raise ValueError('tier_dependency_changed')
        raw_inputs.update(world=hex(world), religion=hex(religion), country_count=count,
                          same_faith_country_count=matching, tier_count=tier_count)
        return selected if selected is not None else dict(TIER_UNKNOWN)
    finally:
        raw_inputs['budget'] = {'calls': calls, 'bytes_requested': requested,
                                'max_calls': MAX_READ_CALLS, 'max_bytes': MAX_READ_BYTES}


def read_fields(limiter, base, target_binding, fields):
    result = holder.read_fields(limiter, base, target_binding, fields)
    field = result.get(FIELD_ID)
    if not field or field.get('status') != 'known':
        return result
    raw_inputs = {'reads': []}
    field['raw_inputs']['tier'] = raw_inputs
    try:
        tier = _tier(limiter, base, target_binding, field, raw_inputs)
    except Exception as exc:
        if 'read_budget_exceeded' in str(exc) or 'read_call_budget_exceeded' in str(exc):
            raise
        raw_inputs['error_type'] = type(exc).__name__
        if isinstance(exc, _Changed):
            field.pop('value', None)
            field.update(status='unknown', reason='RELIGION_DEFENDER_COMPONENTS_CHANGED')
            return result
        tier = dict(TIER_UNKNOWN)
    field['value']['tier'] = tier
    field['gaps'] = ['ABSENT_DEFENDER_SENTINEL_NOT_ESTABLISHED',
                     'DEFENDER_ELIGIBILITY_AND_TOOLTIP_NOT_READ', 'CALLER_ADMISSION_IS_PARENT_OWNED']
    return result
