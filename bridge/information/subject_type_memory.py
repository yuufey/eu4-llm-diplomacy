"""Loaded subject definitions shared by AI personality and obligation readers."""
from types import SimpleNamespace
import re

from . import mission_memory as _strings


def read_definition(read, pointer, spec):
    # Preserve the established trace labels for existing personality captures.
    parent = int.from_bytes(read.read(pointer + spec['overlord_fullref_offset'], 8,
        'ai_personality.overlord'), 'little')
    if parent >> 56 == 0:
        return parent, 0
    slot = (parent >> 32) & 0xffff
    table = int.from_bytes(read.read(pointer + spec['relation_table_offset'], 8,
        'ai_personality.relation_table'), 'little')
    row = read.read(table + slot * spec['relation_row_stride'], 24, 'ai_personality.relation_row')
    owner = int.from_bytes(row[:8], 'little')
    recipient = int.from_bytes(row[16:24], 'little')
    if recipient != parent:
        raise ValueError('AI_PERSONALITY_OVERLORD_ROW_MISMATCH')
    header = read.read(owner + spec['subject_types_offset'], 16, 'ai_personality.subject_types')
    count = int.from_bytes(header[12:16], 'little', signed=True)
    if not 0 <= count <= spec['max_subject_types']:
        raise ValueError('AI_PERSONALITY_SUBJECT_TYPE_COUNT_INVALID')
    if count == 0:
        return parent, 0
    vector = int.from_bytes(header[:8], 'little')
    records = read.read(vector, count * 16, 'ai_personality.subject_type_records')
    for offset in range(0, len(records), 16):
        if int.from_bytes(records[offset:offset + 4], 'little', signed=True) != slot:
            continue
        relation = int.from_bytes(records[offset + 8:offset + 16], 'little')
        if relation == 0:
            return parent, 0
        definition = int.from_bytes(read.read(relation + spec['subject_definition_offset'], 8,
            'ai_personality.subject_definition'), 'little')
        return parent, definition
    return parent, 0


def read_obligations(read, module_base, binding, relationship_spec, spec, fields):
    parent, definition = read_definition(read, int(binding['country_pointer'], 0), relationship_spec)
    if not parent or not definition:
        raise ValueError('SUBJECT_TYPE_DEFINITION_UNAVAILABLE')
    table = int.from_bytes(read.read(definition, 8, 'subject_type.vtable'), 'little')
    if table != module_base + spec['vtable_rva']:
        raise ValueError('SUBJECT_TYPE_CLASS_UNAVAILABLE')
    address = definition + spec['name_offset']
    header = read.read(address, 32, 'subject_type.name')
    decoded = _strings._decode_string32(SimpleNamespace(read=read.read, module_base=module_base),
                                       address, header, 'subject_type.name')
    name = decoded.get('text')
    if (decoded['status'] != 'observed' or not isinstance(name, str)
            or re.fullmatch(r'[A-Za-z0-9_.:-]{1,64}', name) is None):
        raise ValueError('SUBJECT_TYPE_NAME_UNAVAILABLE')
    result = {}
    for field in fields:
        values = {}
        for key, member in spec['fields'][field].items():
            raw = read.read(definition + member['offset'], member['width'], 'subject_type.' + key)
            if member['kind'] == 'bool':
                values[key] = raw != b'\0'
            else:
                value = int.from_bytes(raw, 'little', signed=True)
                values[key] = {'status': 'known', 'value': value, 'raw': value,
                               'scale': member['scale']}
        result[field] = {'status': 'known', 'value': values, 'subject_type': name}
    return name, result
