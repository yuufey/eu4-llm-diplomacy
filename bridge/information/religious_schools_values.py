"""Public copied school identity; activation and guest scholars stay explicit."""
from copy import deepcopy
import re

KEY = re.compile(r'[A-Za-z0-9_][A-Za-z0-9_.:-]{0,127}\Z', re.ASCII)
UNRESOLVED = {
    'uses_schools': 'RELIGIOUS_SCHOOLS_ACTIVATION_NOT_READ',
    'invited_scholars': 'INVITED_SCHOLARS_NOT_READ',
    'relations': 'SCHOOL_RELATIONS_NOT_READ',
}
NONE = {'status': 'none', 'reason': 'NATIVE_SCHOOL_SENTINEL'}


def public_value(value, target):
    keys = {'has_school', 'religion_key', 'religion_group_key', 'current_school', *UNRESOLVED}
    if not isinstance(value, dict) or set(value) != keys:
        raise ValueError('SCHOOL_VALUE_SHAPE')
    if type(target) is not str or re.fullmatch(r'[A-Z0-9]{3}', target) is None:
        raise ValueError('SCHOOL_TARGET')
    if type(value['has_school']) is not bool:
        raise ValueError('SCHOOL_FLAG')
    for name in ('religion_key', 'religion_group_key'):
        if type(value[name]) is not str or KEY.fullmatch(value[name]) is None:
            raise ValueError('SCHOOL_RELIGION_KEY')
    for name, reason in UNRESOLVED.items():
        if value[name] != {'status': 'unknown', 'reason': reason}:
            raise ValueError('SCHOOL_UNPROVEN_STATE')
    school = value['current_school']
    if value['has_school']:
        if (not isinstance(school, dict) or set(school) != {'status', 'key'}
                or school.get('status') != 'known' or type(school.get('key')) is not str
                or KEY.fullmatch(school['key']) is None):
            raise ValueError('SCHOOL_KEY')
    elif school != NONE:
        raise ValueError('SCHOOL_SENTINEL')
    return deepcopy(value)
