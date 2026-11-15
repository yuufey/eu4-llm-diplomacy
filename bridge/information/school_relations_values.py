"""Validate copied school-pair relation values and compose scholar projection."""
from __future__ import annotations

from copy import deepcopy
import re

from . import religious_scholars_values


_RELATION_UNKNOWN_REASONS = {
    'SCHOOL_RELATIONS_UNAVAILABLE',
    'SCHOOL_RELATIONS_CHANGED',
}
_RELATION_NOT_FOUND = 'SCHOOL_RELATION_NOT_FOUND'
_SCHOLARS_RELATIONS_UNKNOWN = {
    'status': 'unknown', 'reason': 'SCHOOL_RELATIONS_NOT_READ',
}
_RELATION_BASIS = 'native_school_pair_relation_cache'
_RELIGION_KEY = re.compile(r'[A-Za-z0-9_][A-Za-z0-9_.:-]{0,127}\Z', re.ASCII)
_RAW_HEX32 = re.compile(r'[0-9a-f]{8}\Z')
_NATIVE_KEYS = {
    'has_school', 'religion_key', 'religion_group_key', 'current_school',
    'uses_schools', 'invited_scholars', 'relations',
}
_RELATION_KNOWN_KEYS = {
    'status', 'religion_group_key', 'source_school_key', 'symmetric',
    'entries', 'complete', 'basis',
}
_KNOWN_ENTRY_KEYS = {'school_key', 'status', 'value', 'raw_hex'}
_UNKNOWN_ENTRY_KEYS = {'school_key', 'status', 'reason'}
_MAX_DESTINATIONS = 63


def _valid_key(value: object) -> bool:
    return type(value) is str and _RELIGION_KEY.fullmatch(value) is not None


def _int32(value: object) -> bool:
    return type(value) is int and -(1 << 31) <= value < (1 << 31)


def _relation_value(value: object, *, has_school: bool,
                    religion_group_key: str, source_school_key: str | None) -> dict:
    if not isinstance(value, dict):
        raise ValueError('SCHOOL_RELATION_SHAPE')
    status = value.get('status')
    if status == 'unknown':
        reason = value.get('reason')
        if (set(value) != {'status', 'reason'} or type(reason) is not str
                or reason not in _RELATION_UNKNOWN_REASONS):
            raise ValueError('SCHOOL_RELATION_UNKNOWN')
        return deepcopy(value)
    if status == 'not_applicable':
        if (has_school or set(value) != {'status', 'reason'}
                or value.get('reason') != 'NO_CURRENT_RELIGIOUS_SCHOOL'):
            raise ValueError('SCHOOL_RELATION_NOT_APPLICABLE')
        return deepcopy(value)
    if (set(value) != _RELATION_KNOWN_KEYS or status != 'known' or not has_school
            or value.get('religion_group_key') != religion_group_key
            or value.get('source_school_key') != source_school_key
            or value.get('symmetric') is not True or value.get('complete') is not False
            or value.get('basis') != _RELATION_BASIS):
        raise ValueError('SCHOOL_RELATION_KNOWN_SHAPE')
    entries = value.get('entries')
    if not isinstance(entries, list) or len(entries) > _MAX_DESTINATIONS:
        raise ValueError('SCHOOL_RELATION_ENTRY_COUNT')
    seen: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict) or type(entry.get('school_key')) is not str:
            raise ValueError('SCHOOL_RELATION_ENTRY_SHAPE')
        school_key = entry['school_key']
        if not _valid_key(school_key):
            raise ValueError('SCHOOL_RELATION_DESTINATION_KEY')
        folded = school_key.casefold()
        if (source_school_key is None or folded == source_school_key.casefold()
                or folded in seen):
            raise ValueError('SCHOOL_RELATION_DESTINATION_DUPLICATE_OR_SELF')
        seen.add(folded)
        if entry.get('status') == 'known':
            if set(entry) != _KNOWN_ENTRY_KEYS or not _int32(entry.get('value')):
                raise ValueError('SCHOOL_RELATION_KNOWN_ENTRY')
            raw_hex = entry.get('raw_hex')
            if type(raw_hex) is not str or _RAW_HEX32.fullmatch(raw_hex) is None:
                raise ValueError('SCHOOL_RELATION_RAW_HEX')
            raw = bytes.fromhex(raw_hex)
            if int.from_bytes(raw, 'little', signed=True) != entry['value']:
                raise ValueError('SCHOOL_RELATION_RAW_VALUE_MISMATCH')
        elif entry.get('status') == 'unknown':
            if (set(entry) != _UNKNOWN_ENTRY_KEYS
                    or entry.get('reason') != _RELATION_NOT_FOUND):
                raise ValueError('SCHOOL_RELATION_MISSING_ENTRY')
        else:
            raise ValueError('SCHOOL_RELATION_ENTRY_STATUS')
    return deepcopy(value)


def native_value(value: object, target: str) -> dict:
    """Validate relations while delegating the other six fields to 173's owner."""
    if not isinstance(value, dict) or set(value) != _NATIVE_KEYS:
        raise ValueError('SCHOOL_RELATION_NATIVE_VALUE_SHAPE')
    relation = value.get('relations')
    projection = deepcopy(value)
    projection['relations'] = deepcopy(_SCHOLARS_RELATIONS_UNKNOWN)
    native = religious_scholars_values.native_value(projection, target)
    current = native['current_school']
    source_school_key = current.get('key') if current.get('status') == 'known' else None
    native['relations'] = _relation_value(
        relation,
        has_school=native['has_school'],
        religion_group_key=native['religion_group_key'],
        source_school_key=source_school_key,
    )
    return native


def public_value(value: object, target: str, mapping: object) -> dict:
    """Project scholar memberships and restore independently validated relations."""
    native = native_value(value, target)
    relations = deepcopy(native['relations'])
    projection = deepcopy(native)
    projection['relations'] = deepcopy(_SCHOLARS_RELATIONS_UNKNOWN)
    projected = religious_scholars_values.public_value(projection, target, mapping)
    projected['relations'] = relations
    return projected
