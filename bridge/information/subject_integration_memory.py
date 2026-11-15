"""Read the selected bilateral integration task and its invested diplomatic power."""


def _selected_task(read, binding, other, relationship, spec):
    pointer = int(binding['country_pointer'], 0)
    reference = int(other['fullref'], 0)
    slot = (reference >> 32) & 0xffff
    table = int.from_bytes(read.read(pointer + relationship['relation_table_offset'], 8,
        'integration.relation_table'), 'little')
    row = read.read(table + slot * relationship['relation_row_stride'], 24,
                    'integration.relation_row')
    if int.from_bytes(row[16:24], 'little') != reference:
        raise ValueError('INTEGRATION_RELATION_ROW_MISMATCH')
    root = int.from_bytes(row[:8], 'little')
    header = read.read(root + spec['index_offset'], 16, 'integration.index_header')
    vector = int.from_bytes(header[:8], 'little')
    capacity = int.from_bytes(header[8:12], 'little', signed=True)
    count = int.from_bytes(header[12:16], 'little', signed=True)
    if not 0 <= count <= capacity <= spec['max_entries']:
        raise ValueError('INTEGRATION_INDEX_COUNT_INVALID')
    if not count:
        return None
    records = read.read(vector, count * 16, 'integration.index_records')
    selected = [int.from_bytes(records[offset + 8:offset + 16], 'little')
                for offset in range(0, len(records), 16)
                if int.from_bytes(records[offset:offset + 4], 'little', signed=True) == slot]
    if len(selected) > 1:
        raise ValueError('INTEGRATION_INDEX_DUPLICATE')
    return selected[0] if selected else None


def read_progress(read, module_base, subject, overlord, relationship, spec):
    forward = _selected_task(read, overlord, subject, relationship, spec)
    reverse = _selected_task(read, subject, overlord, relationship, spec)
    if forward != reverse:
        raise ValueError('INTEGRATION_INDEXES_DISAGREE')
    if forward is None:
        return {'in_progress': False, 'diplomatic_power_spent': 0}
    body = read.read(forward, spec['body_bytes'], 'integration.task')
    if (int.from_bytes(body[:8], 'little') != module_base + spec['vtable_rva']
            or body[spec['removed_offset']] != 0
            or int.from_bytes(body[16:24], 'little') != int(overlord['fullref'], 0)
            or int.from_bytes(body[24:32], 'little') != int(subject['fullref'], 0)):
        raise ValueError('INTEGRATION_TASK_BINDING_UNAVAILABLE')
    offset = spec['progress_offset']
    invested = int.from_bytes(body[offset:offset + 4], 'little', signed=True)
    if invested < 0:
        raise ValueError('INTEGRATION_PROGRESS_INVALID')
    return {'in_progress': True, 'diplomatic_power_spent': {
        'status': 'known', 'value': invested, 'raw': invested, 'scale': spec['progress_scale']}}
