"""School DTO extension for the proven native mechanism activation paths."""
from copy import deepcopy
from . import religious_schools_values as parent

UNKNOWN_REASONS = {
    parent.UNRESOLVED['uses_schools'],
    'RELIGIOUS_SCHOOLS_THREAD_GATE_UNRESOLVED',
    'RELIGIOUS_SCHOOLS_ACTIVATION_UNAVAILABLE',
    'RELIGIOUS_SCHOOLS_ACTIVATION_CHANGED',
}


def public_value(value, target):
    if not isinstance(value, dict) or 'uses_schools' not in value:
        raise ValueError('SCHOOL_STATE_VALUE_SHAPE')
    activation = value['uses_schools']
    if not isinstance(activation, dict):
        raise ValueError('SCHOOL_ACTIVATION_SHAPE')
    if activation.get('status') == 'known':
        if set(activation) != {'status', 'value'} or type(activation.get('value')) is not bool:
            raise ValueError('SCHOOL_ACTIVATION_BOOLEAN')
    elif (set(activation) != {'status', 'reason'} or activation.get('status') != 'unknown'
          or activation.get('reason') not in UNKNOWN_REASONS):
        raise ValueError('SCHOOL_ACTIVATION_UNKNOWN')
    projected = deepcopy(value)
    projected['uses_schools'] = {'status': 'unknown', 'reason': parent.UNRESOLVED['uses_schools']}
    parent.public_value(projected, target)
    return deepcopy(value)
