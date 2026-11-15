"""Bounded current-school identity copied from the admitted country.

The native empty school is separate from mechanism activation. The latter
depends on native global/thread state and is deliberately not inferred here.
"""
from . import country_faith_memory as faith
from . import religion_identity_memory as identity
from . import religious_schools_values as values
from .religion_group_memory import _checked_add, _budget_error

FIELD_ID = 'S02.schools'
BASIS = 'bounded_native_country_religious_school'
MAX_READ_BYTES = 8192
MAX_READ_CALLS = 128
MAX_SCHOOLS = 64
GAPS = ['SCHOOL_ACTIVATION_INVITED_SCHOLARS_AND_RELATIONS_NOT_READ',
        'FULL_TOOLTIP_NOT_READ', 'CALLER_ADMISSION_IS_PARENT_OWNED']


class _Invalid(ValueError):
    pass


def _unknown(reason, raw):
    return {'status': 'unknown', 'complete': False, 'basis': BASIS,
            'reason': reason, 'raw_inputs': raw, 'gaps': list(GAPS)}


def _read_school(reader, base, target_binding):
    raw = {'reads': [], 'read_failures': []}
    snapshots = []
    calls = requested = 0

    class Recorder:
        def read(self, address, size, label, *, remember=True):
            nonlocal calls, requested
            address = _checked_add(address, 0, size, label)
            if calls >= MAX_READ_CALLS:
                raise ValueError('school_leaf_read_call_budget_exceeded')
            if requested + size > MAX_READ_BYTES:
                raise ValueError('school_leaf_read_budget_exceeded')
            calls += 1
            requested += size
            row = {'address': hex(address), 'size': size,
                   'label': 'religious_schools.' + label, 'status': 'requested'}
            raw['reads'].append(row)
            try:
                data = faith._read_exact(reader, address, size, row['label'])
            except Exception as exc:
                row.update(status='failed', error_type=type(exc).__name__)
                raw['read_failures'].append({'label': row['label'], 'error_type': type(exc).__name__})
                raise
            row.update(status='ok', raw_hex=data.hex())
            if remember:
                snapshots.append((address, size, label, data))
            return data

    recorder = Recorder()

    def integer(address, size, label):
        return int.from_bytes(recorder.read(address, size, label), 'little')

    def pointer(address, label):
        value = integer(address, 8, label)
        faith._user_pointer(value, label, aligned=True)
        raw[label] = hex(value)
        return value

    def at(pointer, offset, size=8):
        return _checked_add(pointer, offset, size, 'school_dependency')

    def require(condition, reason):
        if not condition:
            raise _Invalid(reason)

    try:
        parent = identity.read_fields(recorder, base, target_binding, (identity.FIELD_ID,))[identity.FIELD_ID]
        raw['religion_identity'] = parent
        require(parent['status'] == 'known', 'school_religion_identity_unknown')
        inputs = parent['raw_inputs']
        country = int(inputs['country_pointer'], 16)
        group = int(inputs['religion_group_pointer'], 16)
        school = pointer(at(country, 0x28B8), 'school_pointer')
        vtable = pointer(school, 'school_vtable')
        require(vtable in (base + 0x1C48598, base + 0x1D21740), 'unsupported_school_type')
        has_school = vtable == base + 0x1D21740
        expected_method = base + (0x8F440 if has_school else 0x8F450)
        require(integer(at(vtable, 0x88), 8, 'school_valid_method') == expected_method,
                'unsupported_school_valid_method')
        if has_school:
            definition = pointer(at(group, 0xA0), 'school_group_definition')
            require(integer(at(definition, 0x10), 8, 'school_group_owner') == group,
                    'school_group_owner_mismatch')
            require(integer(at(school, 0x170), 8, 'school_owner_group') == group,
                    'school_owner_group_mismatch')
            count = integer(at(definition, 0x2C, 4), 4, 'school_count')
            capacity = integer(at(definition, 0x28, 4), 4, 'school_capacity')
            ordinal = integer(at(school, 0x178, 4), 4, 'school_ordinal')
            require(1 <= count <= MAX_SCHOOLS and count <= capacity <= MAX_SCHOOLS * 2,
                    'school_array_bounds_invalid')
            require(ordinal < count, 'school_ordinal_out_of_bound')
            array = pointer(at(definition, 0x20), 'school_array')
            require(integer(at(array, ordinal * 8), 8, 'school_member') == school,
                    'school_array_member_mismatch')
            key = identity._read_string32_before(recorder, school, 0x150, 'school_key', raw)['key']
            current = {'status': 'known', 'key': key}
            raw.update(school_count=count, school_capacity=capacity, school_ordinal=ordinal)
        else:
            current = dict(values.NONE)
        value = {'has_school': has_school, **parent['value'], 'current_school': current,
                 **{name: {'status': 'unknown', 'reason': reason}
                    for name, reason in values.UNRESOLVED.items()}}
        # Recheck all dependencies, including the parent identity reads, after
        # the school copy. This prevents a same-date religion/school splice.
        for address, size, label, expected in reversed(snapshots):
            require(recorder.read(address, size, label + '_school_after', remember=False) == expected,
                    'school_dependency_changed')
        values.public_value(value, inputs['country_binding']['tag'])
        return {'status': 'known', 'complete': False, 'basis': BASIS,
                'value': value, 'raw_inputs': raw, 'gaps': list(GAPS)}
    except Exception as exc:
        if _budget_error(exc):
            raise
        reason = str(exc) if isinstance(exc, _Invalid) else 'school_read_failed:' + type(exc).__name__
        return _unknown(reason[:180], raw)
    finally:
        raw['budget'] = {'calls': calls, 'bytes_requested': requested,
                         'max_calls': MAX_READ_CALLS, 'max_bytes': MAX_READ_BYTES}


def read_fields(limiter, base, target_binding, fields):
    if not isinstance(fields, tuple) or any(not isinstance(field, str) for field in fields):
        return {FIELD_ID: _unknown('fields_shape_invalid', {})}
    if len(set(fields)) != len(fields):
        return {field: _unknown('duplicate_field_requested', {}) for field in dict.fromkeys(fields)}
    return {field: _read_school(limiter, base, target_binding) if field == FIELD_ID else
            _unknown('unsupported_field', {}) for field in fields}
