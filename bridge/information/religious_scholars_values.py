"""Validate native country-modifier membership and project static scholar keys."""
from __future__ import annotations

from copy import deepcopy
from pathlib import PurePosixPath
import re

from . import religious_schools_state_values as state_values
from .model import canonical


_MAPPING_UNKNOWN = {
    'status': 'unknown',
    'reason': 'RELIGIOUS_SCHOLAR_MAPPING_UNAVAILABLE',
}
_NATIVE_UNKNOWN_REASONS = {
    'SCHOLAR_MODIFIERS_UNAVAILABLE',
    'SCHOLAR_MODIFIERS_CHANGED',
}
_NATIVE_KEYS = {
    'has_school', 'religion_key', 'religion_group_key', 'current_school',
    'uses_schools', 'invited_scholars', 'relations',
}
_CHILD_KNOWN_KEYS = {'status', 'membership_complete', 'modifier_instances'}
_INSTANCE_KEYS = {'source', 'key', 'start_date_raw', 'date_raw', 'flags'}
_FLAG_KEYS = {'ruler_modifier', 'parliament_modifier', 'permanent', 'hidden'}
_MAPPING_KEYS = {
    'status', 'mappings', 'source_pins', 'conditions_evaluated',
    'effects_executed', 'runtime_state_observed',
}
_MAPPING_ROW_KEYS = {
    'religion_group_key', 'school_key', 'modifier_key', 'definition', 'source_pins',
    'conditions_evaluated', 'effects_executed', 'runtime_state_observed',
}
_PIN_KEYS = {
    'configuration_sha256', 'definitions_sha256', 'parser_manifest_sha256',
    'cwt_sha256', 'cwt_commit',
}
_RELIGION_KEY = re.compile(r'[A-Za-z0-9_][A-Za-z0-9_.:-]{0,127}\Z', re.ASCII)
_MODIFIER_KEY = re.compile(r'[A-Za-z0-9_-]{1,255}\Z', re.ASCII)
_FILE_SHA = re.compile(r'[0-9a-f]{64}\Z')
_HEX64 = re.compile(r'[0-9a-f]{64}\Z')
_HEX40 = re.compile(r'[0-9a-f]{40}\Z')
_MAX_INSTANCES = 256
_MAX_MAPPING_ROWS = 2048
_MAX_DEFINITION_BYTES = 4 * 1024 * 1024
_SCHOLAR_BASIS = 'native_country_modifier_key_membership'
_HISTORY_UNKNOWN = {
    'status': 'unknown', 'reason': 'SCHOLAR_INVITATION_HISTORY_NOT_READ',
}
_DATE_SEMANTICS = 'copied_raw_dates_expiry_and_timer_unproven'


def _i32(value: object) -> bool:
    return type(value) is int and -(1 << 31) <= value < (1 << 31)


def _key(value: object, pattern: re.Pattern[str]) -> bool:
    return type(value) is str and pattern.fullmatch(value) is not None


def _native_child(value: object) -> dict:
    if not isinstance(value, dict):
        raise ValueError('SCHOLAR_CHILD_SHAPE')
    if value.get('status') == 'unknown':
        reason = value.get('reason')
        if (set(value) != {'status', 'reason'} or type(reason) is not str
                or reason not in _NATIVE_UNKNOWN_REASONS):
            raise ValueError('SCHOLAR_CHILD_UNKNOWN')
        return deepcopy(value)
    if (set(value) != _CHILD_KNOWN_KEYS or value.get('status') != 'known'
            or value.get('membership_complete') is not True):
        raise ValueError('SCHOLAR_CHILD_KNOWN_SHAPE')
    instances = value.get('modifier_instances')
    if not isinstance(instances, list) or len(instances) > _MAX_INSTANCES:
        raise ValueError('SCHOLAR_INSTANCE_COUNT')
    for item in instances:
        if not isinstance(item, dict) or set(item) != _INSTANCE_KEYS:
            raise ValueError('SCHOLAR_INSTANCE_SHAPE')
        if not _key(item.get('key'), _MODIFIER_KEY):
            raise ValueError('SCHOLAR_MODIFIER_KEY')
        source = item.get('source')
        if source == 'direct':
            if not _i32(item.get('start_date_raw')) or not _i32(item.get('date_raw')):
                raise ValueError('SCHOLAR_DIRECT_DATES')
            flags = item.get('flags')
            if not isinstance(flags, dict) or set(flags) != _FLAG_KEYS:
                raise ValueError('SCHOLAR_DIRECT_FLAGS_SHAPE')
            if any(type(flags.get(name)) is not int or not 0 <= flags[name] <= 255
                   for name in _FLAG_KEYS):
                raise ValueError('SCHOLAR_DIRECT_FLAG_BYTE')
        elif source == 'secondary':
            if (item.get('start_date_raw') is not None or item.get('date_raw') is not None
                    or item.get('flags') is not None):
                raise ValueError('SCHOLAR_SECONDARY_RAW_FIELDS')
        else:
            raise ValueError('SCHOLAR_INSTANCE_SOURCE')
    return deepcopy(value)


def native_value(value: object, target: str) -> dict:
    """Validate the 172 native value plus the scholar-modifier child."""
    if not isinstance(value, dict) or set(value) != _NATIVE_KEYS:
        raise ValueError('SCHOLAR_NATIVE_VALUE_SHAPE')
    native = deepcopy(value)
    child = native.get('invited_scholars')
    # The 172 validator owns the other six fields; substitute its documented
    # unresolved child while checking those fields, then validate this child.
    identity_projection = deepcopy(native)
    identity_projection['invited_scholars'] = {
        'status': 'unknown', 'reason': 'INVITED_SCHOLARS_NOT_READ',
    }
    state_values.public_value(identity_projection, target)
    native['invited_scholars'] = _native_child(child)
    return native


def _pin_bundle(value: object) -> bool:
    if not isinstance(value, dict) or set(value) != _PIN_KEYS:
        return False
    for key in ('configuration_sha256', 'definitions_sha256',
                'parser_manifest_sha256', 'cwt_sha256'):
        if type(value.get(key)) is not str or _HEX64.fullmatch(value[key]) is None:
            return False
    return type(value.get('cwt_commit')) is str and _HEX40.fullmatch(value['cwt_commit']) is not None


def _valid_definition(value: object) -> bool:
    if not isinstance(value, dict) or set(value) != {
            'relative_file', 'line', 'file_sha256', 'source_kind'}:
        return False
    relative = value.get('relative_file')
    if (type(relative) is not str or not relative or '\\' in relative or '\x00' in relative
            or ':' in relative
            or relative.startswith('/') or any(part in ('', '.', '..')
                                               for part in relative.split('/'))):
        return False
    path = PurePosixPath(relative)
    if (path.is_absolute() or len(path.parts) < 3 or path.parts[:2] != ('common', 'religions')
            or path.suffix.casefold() != '.txt' or '..' in path.parts):
        return False
    if type(value.get('line')) is not int or value['line'] < 1:
        return False
    if type(value.get('file_sha256')) is not str or _FILE_SHA.fullmatch(value['file_sha256']) is None:
        return False
    source_kind = value.get('source_kind')
    return type(source_kind) is str and source_kind in ('basegame', 'mod')


def _validated_mapping(value: object) -> list[dict] | None:
    if not isinstance(value, dict):
        return None
    if value.get('status') == 'unknown':
        return None if value == _MAPPING_UNKNOWN else None
    if set(value) != _MAPPING_KEYS or value.get('status') != 'known':
        return None
    if (value.get('conditions_evaluated') is not False
            or value.get('effects_executed') is not False
            or value.get('runtime_state_observed') is not False):
        return None
    top_pins = value.get('source_pins')
    if not _pin_bundle(top_pins):
        return None
    rows = value.get('mappings')
    if not isinstance(rows, list) or len(rows) > _MAX_MAPPING_ROWS:
        return None
    seen: set[tuple[str, str]] = set()
    checked = []
    try:
        encoded = canonical(value).encode('utf-8')
    except Exception:
        return None
    if len(encoded) > _MAX_DEFINITION_BYTES:
        return None
    for row in rows:
        if not isinstance(row, dict) or set(row) != _MAPPING_ROW_KEYS:
            return None
        if (row.get('conditions_evaluated') is not False
                or row.get('effects_executed') is not False
                or row.get('runtime_state_observed') is not False):
            return None
        group = row.get('religion_group_key')
        school = row.get('school_key')
        modifier = row.get('modifier_key')
        if (not _key(group, _RELIGION_KEY) or not _key(school, _RELIGION_KEY)
                or not _key(modifier, _MODIFIER_KEY)):
            return None
        pair = (group.casefold(), school.casefold())
        if pair in seen:
            return None
        seen.add(pair)
        if row.get('source_pins') != top_pins or not _pin_bundle(row.get('source_pins')):
            return None
        if not _valid_definition(row.get('definition')):
            return None
        checked.append(row)
    return deepcopy(checked)


def public_value(value: object, target: str, mapping: object) -> dict:
    """Project exact modifier-key membership without interpreting dates/effects."""
    native = native_value(value, target)
    child = native['invited_scholars']
    if child.get('status') != 'known':
        return native
    rows = _validated_mapping(mapping)
    if rows is None:
        native['invited_scholars'] = deepcopy(_MAPPING_UNKNOWN)
        return native

    instances = child['modifier_instances']
    scholars = []
    for row in rows:
        matching = [item for item in instances if item['key'] == row['modifier_key']]
        scholars.append({
            'religion_group_key': row['religion_group_key'],
            'school_key': row['school_key'],
            'modifier_key': row['modifier_key'],
            'present': bool(matching),
            'instances': deepcopy(matching),
        })
    cooldown_key = 'has_invited_scholar_recently'
    cooldown_instances = [item for item in instances if item['key'] == cooldown_key]
    native['invited_scholars'] = {
        'status': 'known',
        'membership_complete': True,
        'basis': _SCHOLAR_BASIS,
        'scholars': scholars,
        'invitation_cooldown': {
            'modifier_key': cooldown_key,
            'present': bool(cooldown_instances),
            'instances': deepcopy(cooldown_instances),
        },
        'invitation_history': deepcopy(_HISTORY_UNKNOWN),
        'date_semantics': _DATE_SEMANTICS,
        'complete': False,
    }
    return native
