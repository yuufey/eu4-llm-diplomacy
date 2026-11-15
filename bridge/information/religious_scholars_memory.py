"""Copy both native country-modifier lists for scholar-key membership.

Admission belongs to the shared owner. Invitation history is not inferred
from a modifier's presence or raw dates. The existing direct reader and the
frozen school state reader remain unchanged.
"""
from copy import deepcopy
from . import country_faith_memory as faith
from . import country_modifiers_memory as modifiers
from . import religious_schools_state_memory as parent
from .religion_group_memory import _checked_add, _budget_error

FIELD_ID = parent.FIELD_ID
BASIS = parent.BASIS
MAX_READ_BYTES = 196608
MAX_READ_CALLS = 4096
MAX_SECONDARY = 128
MAX_KEY_CAPACITY = 8192
GAPS = ['INVITER_AND_INVITATION_HISTORY_NOT_READ', 'MODIFIER_DATE_LIFECYCLE_NOT_PROVEN',
        'THREAD_GATED_ACTIVATION_PATH_UNRESOLVED', 'SCHOOL_RELATIONS_AND_FULL_TOOLTIP_NOT_READ']


def _read_scholars(reader, base, binding):
    raw = {'reads': [], 'read_failures': []}
    parent_snapshots, modifier_snapshots = [], []
    calls = requested = 0
    exhausted = False

    def read(address, size, label, *, snapshots=None):
        nonlocal calls, requested, exhausted
        address = _checked_add(address, 0, size, label)
        if calls >= MAX_READ_CALLS:
            exhausted = True
            raise ValueError('scholar_leaf_read_call_budget_exceeded')
        if requested + size > MAX_READ_BYTES:
            exhausted = True
            raise ValueError('scholar_leaf_read_budget_exceeded')
        calls += 1
        requested += size
        row = {'address': hex(address), 'size': size, 'label': 'religious_scholars.' + label,
               'status': 'requested'}
        raw['reads'].append(row)
        try:
            data = faith._read_exact(reader, address, size, row['label'])
        except Exception as exc:
            if _budget_error(exc):
                exhausted = True
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

    class ModifierReader:
        def read(self, address, size, label):
            return read(address, size, label, snapshots=modifier_snapshots)

        def read_code(self, address, size, label):
            return self.read(address, size, label)

    def at(pointer, offset, size):
        return _checked_add(pointer, offset, size, 'scholar_dependency')

    def uint(pointer, offset, size, label):
        return int.from_bytes(read(at(pointer, offset, size), size, label,
                                   snapshots=modifier_snapshots), 'little')

    def definition_key(pointer, ordinal):
        faith._user_pointer(pointer, 'secondary_definition', aligned=True)
        if uint(pointer, 0, 8, f'secondary.definition_{ordinal}.vtable') != base + modifiers.DEFINITION_VTABLE_RVA:
            raise ValueError('secondary_definition_type_invalid')
        label = f'secondary.definition_{ordinal}.key'
        header = read(at(pointer, 0x158, 32), 32, label + '_header', snapshots=modifier_snapshots)
        length = int.from_bytes(header[16:24], 'little')
        capacity = int.from_bytes(header[24:32], 'little')
        if not 1 <= length <= modifiers.MAX_KEY_BYTES or not length <= capacity <= MAX_KEY_CAPACITY:
            raise ValueError('secondary_definition_key_bounds')
        if capacity < 16:
            if length > 15:
                raise ValueError('secondary_inline_key_bounds')
            payload = header[:length + 1]
        else:
            heap = int.from_bytes(header[:8], 'little')
            faith._user_pointer(heap, 'secondary_key_heap')
            payload = read(at(heap, 0, length + 1), length + 1, label + '_payload',
                           snapshots=modifier_snapshots)
        return modifiers._ascii_key(payload)

    def copy_memberships(country):
        try:
            record = modifiers.read_fields(ModifierReader(), base, country)
            raw['direct_record'] = record
            # The reused reader catches read errors. A shared/local owner
            # budget failure must still reach the outer capture owner.
            if exhausted:
                raise ValueError('scholar_shared_read_budget_exceeded')
            if (record.get('status') != 'observed' or record.get('module_base') != hex(base)
                    or record.get('country_pointer') != hex(country)
                    or modifiers.validate_record(record) is not True):
                raise ValueError('direct_modifier_record_invalid')
            field = record['fields']['modifiers']
            if field.get('status') != 'known' or field.get('complete') is not True:
                raise ValueError('direct_modifier_field_incomplete')
            instances = []
            for row in field['value']:
                instances.append({'source': 'direct', 'key': row['key'],
                    'start_date_raw': row['start_date_raw'], 'date_raw': row['date_raw'],
                    'flags': deepcopy(row['flags'])})
            current = uint(country, 0x220, 8, 'secondary.head')
            seen = set()
            while current:
                faith._user_pointer(current, 'secondary_node', aligned=True)
                if current in seen or len(seen) >= MAX_SECONDARY:
                    raise ValueError('secondary_modifier_list_cycle_or_over_bound')
                ordinal = len(seen)
                seen.add(current)
                definition = uint(current, 0, 8, f'secondary.node_{ordinal}.definition')
                next_node = uint(current, 0x10, 8, f'secondary.node_{ordinal}.next')
                key = definition_key(definition, ordinal)
                instances.append({'source': 'secondary', 'key': key,
                    'start_date_raw': None, 'date_raw': None, 'flags': None})
                current = next_node
            raw['secondary_count'] = len(seen)
            return {'status': 'known', 'membership_complete': True, 'modifier_instances': instances}
        except Exception as exc:
            if exhausted or _budget_error(exc):
                raise ValueError('scholar_shared_read_budget_exceeded') from exc
            raw['modifier_error'] = {'type': type(exc).__name__, 'detail': str(exc)[:160]}
            return {'status': 'unknown', 'reason': 'SCHOLAR_MODIFIERS_UNAVAILABLE'}

    try:
        old = parent.read_fields(ParentReader(), base, binding, (FIELD_ID,))[FIELD_ID]
        raw['parent'] = old
        if old['status'] != 'known':
            return parent.parent._unknown('scholar_parent_unknown', raw)
        inputs = old['raw_inputs']['parent']['raw_inputs']['religion_identity']['raw_inputs']
        country = int(inputs['country_pointer'], 16)
        memberships = copy_memberships(country)
        stable = True
        for address, size, label, expected in reversed(modifier_snapshots):
            try:
                stable &= read(address, size, label + '_scholar_after') == expected
            except Exception as exc:
                if exhausted or _budget_error(exc):
                    raise
                stable = False
        if not stable:
            memberships = {'status': 'unknown', 'reason': 'SCHOLAR_MODIFIERS_CHANGED'}
        for address, size, label, expected in reversed(parent_snapshots):
            if read(address, size, label + '_scholar_after') != expected:
                return parent.parent._unknown('scholar_parent_changed', raw)
        value = deepcopy(old['value'])
        value['invited_scholars'] = memberships
        from .religious_scholars_values import native_value
        native_value(value, inputs['country_binding']['tag'])
        return {'status': 'known', 'complete': False, 'basis': BASIS,
                'value': value, 'raw_inputs': raw, 'gaps': list(GAPS)}
    except Exception as exc:
        if exhausted or _budget_error(exc):
            raise ValueError('scholar_shared_read_budget_exceeded') from exc
        return parent.parent._unknown('scholar_read_failed:' + type(exc).__name__, raw)
    finally:
        raw['budget'] = {'calls': calls, 'bytes_requested': requested,
                         'max_calls': MAX_READ_CALLS, 'max_bytes': MAX_READ_BYTES}


def read_fields(reader, base, binding, fields):
    if not isinstance(fields, tuple) or any(not isinstance(field, str) for field in fields):
        return {FIELD_ID: parent.parent._unknown('fields_shape_invalid', {})}
    if len(set(fields)) != len(fields):
        return {field: parent.parent._unknown('duplicate_field_requested', {}) for field in dict.fromkeys(fields)}
    return {field: _read_scholars(reader, base, binding) if field == FIELD_ID else
            parent.parent._unknown('unsupported_field', {}) for field in fields}
