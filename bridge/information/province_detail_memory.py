"""Compose private province leaves after the parent discovery admission."""
from collections.abc import Mapping
from copy import deepcopy

from . import province_identity_memory as _identity
from . import province_scalar_memory as _scalar
from . import province_state_memory as _state
from . import province_development_memory as _development
from . import province_resource_memory as _resource
from . import province_resource_localization_memory as _resource_name
from . import province_cot_memory as _cot

FIELDS = _state.FIELDS + ('G02.culture', 'G02.religion', 'G02.autonomy',
    'G02.development', 'G02.resource', 'G02.center_of_trade')
_RESOURCE_FIELD = 'G02.resource'


def _resource_with_cached_name(reader, base, binding, fields):
    result = _resource.read_fields(reader, base, binding, fields)
    item = result.get(_RESOURCE_FIELD)
    if not isinstance(item, Mapping) or item.get('status') != 'known':
        return result

    value = item.get('value')
    raw_inputs = item.get('raw_inputs')
    if (not isinstance(value, Mapping)
            or not isinstance(raw_inputs, Mapping)
            or not isinstance(value.get('localization_key'), str)):
        return result

    try:
        name_capture = _resource_name.read_cached_name(
            reader, base, value['localization_key'])
    except Exception as exc:
        name_capture = {
            'status': 'unknown',
            'reason': 'LOCALIZATION_CAPTURE_FAILED',
            'raw_inputs': {'error_type': type(exc).__name__},
        }

    copied = deepcopy(dict(item))
    copied_value = deepcopy(dict(value))
    if (isinstance(name_capture, Mapping)
            and name_capture.get('status') == 'known'
            and isinstance(name_capture.get('raw_hex'), str)
            and len(name_capture['raw_hex']) % 2 == 0
            and isinstance(name_capture.get('language'), str)):
        try:
            bytes.fromhex(name_capture['raw_hex'])
        except ValueError:
            name = {'status': 'unknown', 'reason': 'LOCALIZATION_CAPTURE_INVALID'}
        else:
            name = {
                'status': 'known',
                'raw_hex': name_capture['raw_hex'],
                'language': name_capture['language'],
            }
    else:
        reason = (name_capture.get('reason') if isinstance(name_capture, Mapping)
                  else None)
        if (not isinstance(reason, str)
                or not reason.isascii()
                or not reason
                or len(reason) > 64
                or any(character not in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_'
                       for character in reason)):
            reason = 'RESOURCE_LOCALIZATION_UNKNOWN'
        name = {'status': 'unknown', 'reason': reason}

    copied_value['name'] = name
    copied['value'] = copied_value
    copied_raw = deepcopy(dict(raw_inputs))
    copied_raw['resource_name_capture'] = (
        deepcopy(dict(name_capture)) if isinstance(name_capture, Mapping)
        else {'status': 'unknown', 'reason': 'LOCALIZATION_CAPTURE_INVALID'})
    copied['raw_inputs'] = copied_raw
    result = dict(result)
    result[_RESOURCE_FIELD] = copied
    return result


def read_fields(reader, base, binding, fields):
    result = {}
    groups = ((_state.FIELDS, _state._default_read_fields),
              (('G02.culture', 'G02.religion'), _identity.read_fields),
              (('G02.autonomy',), lambda reader,base,binding,selected:
                  _scalar.read_fields(reader.read,base,binding,selected)),
              (('G02.development',), _development.read_fields),
              ((_RESOURCE_FIELD,), _resource_with_cached_name),
              (('G02.center_of_trade',), _cot.read_fields))
    for supported, read in groups:
        selected = tuple(field for field in fields if field in supported)
        if selected:
            result.update(read(reader, base, binding, selected))
    return {field: result.get(field, {'status': 'unknown', 'reason': 'UNSUPPORTED_FIELD'})
            for field in fields}


def _resource_without_name(item):
    if not isinstance(item, Mapping) or item.get('status') != 'known':
        return None
    value = item.get('value')
    raw_inputs = item.get('raw_inputs')
    if (not isinstance(value, Mapping) or 'name' not in value
            or not isinstance(raw_inputs, Mapping)
            or 'resource_name_capture' not in raw_inputs):
        return None
    stripped = deepcopy(dict(item))
    stripped_value = deepcopy(dict(value))
    stripped_value.pop('name', None)
    stripped['value'] = stripped_value
    stripped_inputs = deepcopy(dict(raw_inputs))
    stripped_inputs.pop('resource_name_capture', None)
    stripped['raw_inputs'] = stripped_inputs
    return stripped


def reconcile_resource_name(observation):
    """Keep a stable resource key/icon when only the cache name changed.

    The generic two-pass backend conservatively withdraws the entire resource
    field whenever its copied read result changes.  This narrow reconciliation
    restores only the resource leaf's stable base data after removing the
    localization name and its private cache snapshot from both pass records.
    Shared evidence and every other field remain untouched.
    """
    if not isinstance(observation, Mapping):
        return observation
    result = deepcopy(dict(observation))
    shared_consistency = result.get('consistency')
    if (not isinstance(shared_consistency, Mapping)
            or shared_consistency.get('status') != 'stable'):
        return result
    targets = result.get('targets')
    evidence = result.get('pass_evidence')
    if not isinstance(targets, list) or len(targets) != 1 or not isinstance(evidence, Mapping):
        return result
    target = targets[0]
    if not isinstance(target, Mapping):
        return result
    fields = target.get('fields')
    consistency = target.get('field_consistency')
    if not isinstance(fields, Mapping) or not isinstance(consistency, Mapping):
        return result
    current = fields.get(_RESOURCE_FIELD)
    current_consistency = consistency.get(_RESOURCE_FIELD)
    if (not isinstance(current, Mapping)
            or current.get('status') != 'unknown'
            or current.get('reason') != 'FIELD_RAW_DATA_CHANGED'
            or not isinstance(current_consistency, Mapping)
            or current_consistency.get('status') != 'changed'):
        return result
    first_pass = evidence.get('pass1')
    second_pass = evidence.get('pass2')
    if not isinstance(first_pass, Mapping) or not isinstance(second_pass, Mapping):
        return result
    first_fields = first_pass.get('fields_raw')
    second_fields = second_pass.get('fields_raw')
    if not isinstance(first_fields, Mapping) or not isinstance(second_fields, Mapping):
        return result
    first = first_fields.get(_RESOURCE_FIELD)
    second = second_fields.get(_RESOURCE_FIELD)
    first_base = _resource_without_name(first)
    second_base = _resource_without_name(second)
    if (first_base is None or second_base is None
            or _state._shared._same_raw(first, second)
            or not _state._shared._same_raw(first_base, second_base)):
        return result

    restored = deepcopy(dict(second))
    restored_value = deepcopy(dict(restored['value']))
    restored_value['name'] = {
        'status': 'unknown',
        'reason': 'RESOURCE_NAME_CHANGED',
    }
    restored['value'] = restored_value
    result_target = deepcopy(dict(target))
    result_fields = deepcopy(dict(fields))
    result_consistency = deepcopy(dict(consistency))
    result_fields[_RESOURCE_FIELD] = restored
    result_consistency[_RESOURCE_FIELD] = {
        'status': 'partial',
        'base': 'stable',
        'name': 'changed',
        'reason': 'RESOURCE_NAME_CHANGED',
    }
    result_target['fields'] = result_fields
    result_target['field_consistency'] = result_consistency
    result['targets'][0] = result_target
    return result
