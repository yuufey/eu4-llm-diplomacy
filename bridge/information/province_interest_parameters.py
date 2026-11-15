"""Common mission selectors and explicit caller goals for live G01 owners."""
from copy import deepcopy
import re

from .model import InformationError, canonical

_IDENTIFIER = r'^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'
_INTENTS = ('acquire', 'return_core', 'protect_subject', 'weaken_country', 'other')
_MAX_INPUT_BYTES = 64 * 1024


def parameters_schema():
    properties = {
        name: {'type': 'string', 'pattern': _IDENTIFIER}
        for name in ('root_id', 'task_id')}
    target_types = [
        {'type': 'object', 'required': ['type', 'province_id'], 'additionalProperties': False,
         'properties': {'type': {'const': 'province'},
                        'province_id': {'type': 'integer', 'minimum': 1, 'maximum': 65535}}},
        {'type': 'object', 'required': ['type', 'name'], 'additionalProperties': False,
         'properties': {'type': {'enum': ['area', 'region']},
                        'name': {'type': 'string', 'pattern': _IDENTIFIER}}},
        {'type': 'object', 'required': ['type', 'country'], 'additionalProperties': False,
         'properties': {'type': {'const': 'country'},
                        'country': {'type': 'string', 'pattern': '^[A-Z0-9]{3}$'}}},
    ]
    properties['strategic_targets'] = {'type': 'array', 'maxItems': 64, 'items': {
        'type': 'object', 'required': ['id', 'intent', 'target'], 'additionalProperties': False,
        'properties': {'id': {'type': 'string', 'pattern': _IDENTIFIER},
                       'intent': {'type': 'string', 'enum': list(_INTENTS)},
                       'target': {
                           'type': 'object', 'required': ['type'], 'additionalProperties': False,
                           'properties': {
                               'type': {'type': 'string', 'enum': ['province', 'area', 'region', 'country']},
                               'province_id': {'type': 'integer', 'minimum': 1, 'maximum': 65535},
                               'name': {'type': 'string', 'pattern': _IDENTIFIER},
                               'country': {'type': 'string', 'pattern': '^[A-Z0-9]{3}$'}},
                           'oneOf': target_types},
                       'description': {'type': 'string', 'minLength': 1, 'maxLength': 2048}}}}
    return {'type': 'object', 'properties': properties, 'additionalProperties': False}


def _identifier(value):
    return isinstance(value, str) and re.fullmatch(_IDENTIFIER, value) is not None


def _valid_target(target):
    if not isinstance(target, dict):
        return False
    if target.get('type') == 'province':
        return (set(target) == {'type', 'province_id'} and type(target['province_id']) is int
                and 1 <= target['province_id'] <= 65535)
    if target.get('type') in ('area', 'region'):
        return set(target) == {'type', 'name'} and _identifier(target['name'])
    if target.get('type') == 'country':
        return (set(target) == {'type', 'country'} and isinstance(target['country'], str)
                and re.fullmatch(r'[A-Z0-9]{3}', target['country']) is not None)
    return False


def _valid_declarations(items):
    if not isinstance(items, list) or len(items) > 64:
        return False
    seen = set()
    for item in items:
        if (not isinstance(item, dict) or not {'id', 'intent', 'target'} <= set(item)
                or set(item) - {'id', 'intent', 'target', 'description'}
                or not _identifier(item['id']) or item['id'] in seen
                or not isinstance(item['intent'], str) or item['intent'] not in _INTENTS
                or not _valid_target(item['target'])):
            return False
        if 'description' in item and (not isinstance(item['description'], str)
                or not item['description'].strip() or len(item['description']) > 2048):
            return False
        seen.add(item['id'])
    return True


def validate_parameters(value):
    if (not isinstance(value, dict) or set(value) - {'root_id', 'task_id', 'strategic_targets'}
            or any(not _identifier(value[name]) for name in ('root_id', 'task_id') if name in value)
            or ('strategic_targets' in value and not _valid_declarations(value['strategic_targets']))):
        raise InformationError('invalid_parameters', 'G01 mission selectors or structured strategic targets are invalid')
    try:
        size = len(canonical(value).encode('utf-8'))
    except (TypeError, ValueError, UnicodeError) as exc:
        raise InformationError('invalid_parameters', 'G01 parameters must be valid JSON') from exc
    if size > _MAX_INPUT_BYTES:
        raise InformationError('invalid_parameters', 'G01 parameters exceed 64 KiB')
    return deepcopy(value)
