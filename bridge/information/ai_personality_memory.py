"""Copy the effective AI personality, including shared-ruler inheritance."""
from types import SimpleNamespace
import re

from . import mission_memory as _strings
from . import subject_type_memory as _subjects


_NAME = re.compile(r'(?:human|ai_[a-z_]+)\Z')


def _u64(read, address, label):
    return int.from_bytes(read.read(address, 8, label), 'little')


def _country(rows, fullref):
    slot = (fullref >> 32) & 0xffff
    row = rows.get(slot)
    if not row or row.get('fullref') != hex(fullref) or not row.get('country_pointer'):
        raise ValueError('AI_PERSONALITY_COUNTRY_BINDING_UNAVAILABLE')
    return int(row['country_pointer'], 0)


def _shared_ruler_parent(read, pointer, spec):
    parent, definition = _subjects.read_definition(read, pointer, spec)
    if definition == 0:
        return None
    flag = read.read(definition + spec['shared_ruler_flag_offset'], 1, 'ai_personality.shared_ruler')
    return parent if flag != b'\0' else None


def read_personality(read, module_base, binding, rows, spec):
    state = int(binding['country_pointer'], 0) + spec['country_state_offset']
    seen = set()
    for _ in range(spec['max_inheritance_depth']):
        if state in seen:
            raise ValueError('AI_PERSONALITY_INHERITANCE_CYCLE')
        seen.add(state)
        definition = _u64(read, state + spec['cached_definition_offset'], 'ai_personality.cache')
        if definition == 0:
            definition = _u64(read, module_base + spec['default_definition_rva'],
                              'ai_personality.default')
            break
        owner_ref = _u64(read, state + spec['state_country_ref_offset'], 'ai_personality.owner')
        owner = _country(rows, owner_ref)
        parent_ref = _shared_ruler_parent(read, owner, spec)
        if parent_ref is None:
            break
        state = _country(rows, parent_ref) + spec['country_state_offset']
    else:
        raise ValueError('AI_PERSONALITY_INHERITANCE_LIMIT')
    address = definition + spec['definition_name_offset']
    header = read.read(address, 32, 'ai_personality.name')
    decoded = _strings._decode_string32(SimpleNamespace(read=read.read, module_base=module_base),
                                       address, header, 'ai_personality.name')
    name = decoded.get('text')
    if (decoded['status'] != 'observed' or not isinstance(name, str)
            or len(name) > spec['max_name_bytes'] or not _NAME.fullmatch(name)):
        return {'status': 'unknown', 'reason': 'AI_PERSONALITY_NAME_UNAVAILABLE'}
    return {'status': 'known', 'value': name.removeprefix('ai_'), 'raw_name': name,
            'unit': 'ai_personality', 'scale': 1}
