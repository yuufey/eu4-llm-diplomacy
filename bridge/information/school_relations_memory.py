"""Extend frozen scholar state with native unordered school-pair relations."""
from copy import deepcopy
from . import country_faith_memory as faith
from . import religion_identity_memory as strings
from . import religious_scholars_memory as parent
from .religion_group_memory import _checked_add, _budget_error

FIELD_ID = parent.FIELD_ID
BASIS = parent.BASIS
MAX_READ_BYTES = 262144
MAX_READ_CALLS = 8192
MAX_SCHOOLS = 64
MAX_GROUP_ID = 256
MAX_PAIR_ROWS = 2048
GAPS = ['SCHOOL_RELATION_TOOLTIP_NOT_READ', 'INVITER_AND_INVITATION_HISTORY_NOT_READ',
        'MODIFIER_DATE_LIFECYCLE_NOT_PROVEN', 'THREAD_GATED_ACTIVATION_PATH_UNRESOLVED']


def _unknown(reason, raw):
    return {'status': 'unknown', 'complete': False, 'reason': reason,
            'basis': BASIS, 'raw_inputs': raw, 'gaps': list(GAPS)}


def _read_relations(reader, base, binding):
    raw = {'reads': [], 'read_failures': []}
    parent_snapshots, relation_snapshots = [], []
    calls = requested = 0
    exhausted = False

    def read(address, size, label, *, snapshots=None):
        nonlocal calls, requested, exhausted
        address = _checked_add(address, 0, size, label)
        if calls >= MAX_READ_CALLS:
            exhausted = True
            raise ValueError('school_relation_leaf_read_call_budget_exceeded')
        if requested + size > MAX_READ_BYTES:
            exhausted = True
            raise ValueError('school_relation_leaf_read_budget_exceeded')
        calls += 1
        requested += size
        row = {'address': hex(address), 'size': size, 'label': 'school_relations.' + label,
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

    class RelationReader:
        def read(self, address, size, label):
            return read(address, size, label, snapshots=relation_snapshots)

    def at(pointer, offset, size):
        return _checked_add(pointer, offset, size, 'school_relation_dependency')

    def uint(pointer, offset, size, label):
        return int.from_bytes(read(at(pointer, offset, size), size, label,
                                   snapshots=relation_snapshots), 'little')

    def pointer(pointer, offset, label):
        value = uint(pointer, offset, 8, label)
        faith._user_pointer(value, label, aligned=True)
        raw[label] = hex(value)
        return value

    def copy_relations(old, group, country):
        if not old['value']['has_school']:
            return {'status': 'not_applicable', 'reason': 'NO_CURRENT_RELIGIOUS_SCHOOL'}
        try:
            definition = pointer(group, 0xA0, 'relation.definition')
            if uint(definition, 0x10, 8, 'relation.definition_owner') != group:
                raise ValueError('relation_definition_owner_mismatch')
            count = uint(definition, 0x2C, 4, 'relation.school_count')
            if not 1 <= count <= MAX_SCHOOLS:
                raise ValueError('relation_school_count_out_of_bound')
            array = pointer(definition, 0x20, 'relation.school_array')
            source = pointer(country, 0x28B8, 'relation.current_school')
            schools = []
            seen_pointers, seen_keys = set(), set()
            for i in range(count):
                school = pointer(array, i * 8, f'relation.school_{i}.pointer')
                if school in seen_pointers:
                    raise ValueError('duplicate_relation_school_pointer')
                seen_pointers.add(school)
                if uint(school, 0, 8, f'relation.school_{i}.vtable') != base + 0x1D21740:
                    raise ValueError('unsupported_relation_school_type')
                if uint(school, 0x170, 8, f'relation.school_{i}.group') != group:
                    raise ValueError('relation_school_owner_mismatch')
                if uint(school, 0x178, 4, f'relation.school_{i}.ordinal') != i:
                    raise ValueError('relation_school_ordinal_mismatch')
                key = strings._read_string32_before(RelationReader(), school, 0x150,
                    f'relation_school_{i}_key', raw)['key']
                if key.casefold() in seen_keys:
                    raise ValueError('duplicate_relation_school_key')
                seen_keys.add(key.casefold())
                schools.append((school, key))
            source_keys = [key for school, key in schools if school == source]
            if source_keys != [old['value']['current_school']['key']]:
                raise ValueError('relation_source_school_binding_mismatch')
            group_id = uint(group, 0x58, 4, 'relation.group_id')
            if not 1 <= group_id <= MAX_GROUP_ID:
                raise ValueError('relation_group_id_out_of_bound')
            world = pointer(base, 0x233FE58, 'relation.world')
            manager = pointer(world, 0x25A8, 'relation.manager')
            groups = pointer(manager, 0x18, 'relation.group_table')
            state = pointer(groups, (group_id - 1) * 8, 'relation.group_state')
            count_raw = read(at(state, 0x2C, 4), 4, 'relation.pair_count', snapshots=relation_snapshots)
            pair_count = int.from_bytes(count_raw, 'little', signed=True)
            if not 0 <= pair_count <= MAX_PAIR_ROWS:
                raise ValueError('relation_pair_count_out_of_bound')
            pairs = pointer(state, 0x20, 'relation.pair_array') if pair_count else None
            first = {}
            for i in range(pair_count):
                row = pointer(pairs, i * 8, f'relation.pair_{i}.pointer')
                # Endpoints are compared, never dereferenced. Irrelevant rows
                # and duplicate pairs follow the native first-match search.
                a = uint(row, 0x18, 8, f'relation.pair_{i}.a')
                b = uint(row, 0x20, 8, f'relation.pair_{i}.b')
                data = read(at(row, 0x28, 4), 4, f'relation.pair_{i}.value', snapshots=relation_snapshots)
                first.setdefault(tuple(sorted((a, b))), data)
            entries = []
            for school, key in schools:
                if school == source:
                    continue
                data = first.get(tuple(sorted((source, school))))
                if data is None:
                    entries.append({'school_key': key, 'status': 'unknown', 'reason': 'SCHOOL_RELATION_NOT_FOUND'})
                else:
                    entries.append({'school_key': key, 'status': 'known',
                                    'value': int.from_bytes(data, 'little', signed=True), 'raw_hex': data.hex()})
            raw.update(relation_group_id=group_id, relation_school_count=count, relation_pair_count=pair_count)
            return {'status': 'known', 'religion_group_key': old['value']['religion_group_key'],
                    'source_school_key': source_keys[0], 'symmetric': True, 'entries': entries,
                    'complete': False, 'basis': 'native_school_pair_relation_cache'}
        except Exception as exc:
            if exhausted or _budget_error(exc):
                raise ValueError('school_relation_shared_read_budget_exceeded') from exc
            raw['relation_error'] = {'type': type(exc).__name__, 'detail': str(exc)[:160]}
            return {'status': 'unknown', 'reason': 'SCHOOL_RELATIONS_UNAVAILABLE'}

    try:
        old = parent.read_fields(ParentReader(), base, binding, (FIELD_ID,))[FIELD_ID]
        raw['parent'] = old
        if old['status'] != 'known':
            return _unknown('school_relations_parent_unknown', raw)
        inputs = old['raw_inputs']['parent']['raw_inputs']['parent']['raw_inputs']['religion_identity']['raw_inputs']
        group = int(inputs['religion_group_pointer'], 16)
        country = int(inputs['country_pointer'], 16)
        relations = copy_relations(old, group, country)
        stable = True
        for address, size, label, expected in reversed(relation_snapshots):
            try:
                stable &= read(address, size, label + '_relations_after') == expected
            except Exception as exc:
                if exhausted or _budget_error(exc):
                    raise
                stable = False
        if not stable:
            relations = {'status': 'unknown', 'reason': 'SCHOOL_RELATIONS_CHANGED'}
        for address, size, label, expected in reversed(parent_snapshots):
            if read(address, size, label + '_relations_after') != expected:
                return _unknown('school_relations_parent_changed', raw)
        value = deepcopy(old['value'])
        value['relations'] = relations
        from .school_relations_values import native_value
        native_value(value, inputs['country_binding']['tag'])
        return {'status': 'known', 'complete': False, 'basis': BASIS,
                'value': value, 'raw_inputs': raw, 'gaps': list(GAPS)}
    except Exception as exc:
        if exhausted or _budget_error(exc):
            raise ValueError('school_relation_shared_read_budget_exceeded') from exc
        return _unknown('school_relations_read_failed:' + type(exc).__name__, raw)
    finally:
        raw['budget'] = {'calls': calls, 'bytes_requested': requested,
                         'max_calls': MAX_READ_CALLS, 'max_bytes': MAX_READ_BYTES}


def read_fields(reader, base, binding, fields):
    if not isinstance(fields, tuple) or any(not isinstance(field, str) for field in fields):
        return {FIELD_ID: _unknown('fields_shape_invalid', {})}
    if len(set(fields)) != len(fields):
        return {field: _unknown('duplicate_field_requested', {}) for field in dict.fromkeys(fields)}
    return {field: _read_relations(reader, base, binding) if field == FIELD_ID else
            _unknown('unsupported_field', {}) for field in fields}
