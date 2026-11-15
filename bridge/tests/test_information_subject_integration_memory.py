import pytest

from bridge.information import subject_integration_memory, subject_pressure
from bridge.tests.test_information_foreign_technology_memory import MemoryReader


def make_reader(*, active=True):
    profile = subject_pressure._load_profile()
    relationship = profile['attitude']['personality']
    spec = profile['subject_integration_task']
    reader = MemoryReader()
    base, task = 0x140000000, 0x6800000000
    parties = [{'country_pointer': hex(0x6400000000 + i * 0x10000),
                'fullref': hex((0x100 << 48) | (i << 32) | 0x4e4f52)} for i in (1, 2)]
    subject, overlord = parties
    roots = []
    for i, (binding, other) in enumerate(((subject, overlord), (overlord, subject))):
        pointer = int(binding['country_pointer'], 0)
        reference = int(other['fullref'], 0)
        table, root, vector = 0x6500000000 + i * 0x10000, 0x6600000000 + i * 0x10000, 0x6700000000 + i * 0x10000
        roots.append(root)
        reader.put_u64(pointer + relationship['relation_table_offset'], table)
        slot = (reference >> 32) & 0xffff
        reader.put(table + slot * relationship['relation_row_stride'],
                   root.to_bytes(8, 'little') + bytes(8) + reference.to_bytes(8, 'little'))
        reader.put(root + spec['index_offset'], vector.to_bytes(8, 'little')
                   + int(active).to_bytes(4, 'little') * 2)
        reader.put(vector, slot.to_bytes(4, 'little') + bytes(4) + task.to_bytes(8, 'little'))
    body = bytearray(spec['body_bytes'])
    body[:8] = (base + spec['vtable_rva']).to_bytes(8, 'little')
    body[16:24] = int(overlord['fullref'], 0).to_bytes(8, 'little')
    body[24:32] = int(subject['fullref'], 0).to_bytes(8, 'little')
    body[32:36] = (56682672).to_bytes(4, 'little')
    body[64:68] = (12500).to_bytes(4, 'little')
    reader.put(task, bytes(body))
    return reader, base, subject, overlord, relationship, spec, roots, task


def test_progress_uses_invested_power_member_and_preserves_fixed_point():
    reader, base, subject, overlord, relationship, spec, _, _ = make_reader()
    result = subject_integration_memory.read_progress(reader, base, subject, overlord, relationship, spec)
    assert result == {'in_progress': True, 'diplomatic_power_spent': {
        'status': 'known', 'value': 12500, 'raw': 12500, 'scale': 1000}}


def test_bilateral_absence_reports_no_current_integration():
    reader, base, subject, overlord, relationship, spec, _, _ = make_reader(active=False)
    result = subject_integration_memory.read_progress(reader, base, subject, overlord, relationship, spec)
    assert result == {'in_progress': False, 'diplomatic_power_spent': 0}
    assert not any(label == 'integration.task' for _, _, label in reader.reads)


@pytest.mark.parametrize('fault', ['one_sided', 'wrong_type', 'wrong_roles'])
def test_mismatched_current_task_is_unknown(fault):
    reader, base, subject, overlord, relationship, spec, roots, task = make_reader()
    if fault == 'one_sided':
        reader.put_i32(roots[0] + spec['index_offset'] + 12, 0)
    elif fault == 'wrong_type':
        reader.put_u64(task, base)
    else:
        reader.put_u64(task + 16, int(subject['fullref'], 0))
    with pytest.raises(ValueError, match='INTEGRATION_'):
        subject_integration_memory.read_progress(reader, base, subject, overlord, relationship, spec)
