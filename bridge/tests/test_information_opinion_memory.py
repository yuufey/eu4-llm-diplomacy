from copy import deepcopy

import pytest

from bridge.information import opinion_memory as leaf


def binding(tag, slot, pointer):
    ref = int.from_bytes(tag.encode('ascii')+b'\0'+slot.to_bytes(2, 'little')+b'\0\1', 'little')
    return {'tag': tag, 'slot': slot, 'country_pointer': hex(pointer), 'fullref': hex(ref)}


class Memory:
    def __init__(self):
        self.fra = binding('FRA', 3, 0x20000)
        self.eng = binding('ENG', 5, 0x30000)
        self.cells = {}
        self.reads = []
        self.override = None
        for record, begin, value, slot in ((self.fra, 0x40000, -200, 5),
                                           (self.eng, 0x50000, 177, 3)):
            pointer = int(record['country_pointer'], 0)
            self.cells[pointer+0x20, 8] = int(record['fullref'], 0).to_bytes(8, 'little')
            self.header(record, begin, begin+12)
            self.cells[begin+slot*2, 2] = value.to_bytes(2, 'little', signed=True)

    def header(self, record, begin, end):
        pointer = int(record['country_pointer'], 0)
        self.cells[pointer+leaf.TABLE_BEGIN, 8] = begin.to_bytes(8, 'little')
        self.cells[pointer+leaf.TABLE_END, 8] = end.to_bytes(8, 'little')

    def read(self, address, size, label):
        self.reads.append((address, size, label))
        raw = self.cells[address, size]
        return self.override(raw, label) if self.override else raw


def test_signed_directional_values_are_distinct_and_only_cells_are_copied():
    memory = Memory()
    result = leaf.read_fields(memory, memory.fra, memory.eng)
    assert [result[name]['value']['opinion'] for name in leaf.FIELDS] == [-200, 177]
    assert result[leaf.FIELDS[0]]['value']['holder'] == 'FRA'
    assert result[leaf.FIELDS[1]]['value']['holder'] == 'ENG'
    assert result[leaf.FIELDS[0]]['value']['raw_hex'] == '38ff'
    assert len(memory.reads) == 18 and sum(row[1] for row in memory.reads) == 132
    assert all(size in (2, 8) for _, size, _ in memory.reads)


def test_zero_is_known_and_missing_slot_is_unknown():
    memory = Memory()
    memory.cells[0x40000+5*2, 2] = b'\0\0'
    assert leaf.read_direction(memory, memory.fra, memory.eng)['value']['opinion'] == 0
    memory.header(memory.fra, 0x40000, 0x40000+5*2)
    memory.reads.clear()
    result = leaf.read_direction(memory, memory.fra, memory.eng)
    assert result == {'status': 'unknown', 'reason': 'OPINION_TABLE_SLOT_ABSENT'}
    assert not any(size == 2 for _, size, _ in memory.reads)


@pytest.mark.parametrize('begin,end', [
    (0, 0), (0x40001, 0x4000d), (0x40000, 0x3fffe),
    (0x40000, 0x40000+2*(leaf.MAX_ENTRIES+1)),
    (0x800000000000, 0x80000000000c),
])
def test_absent_or_invalid_headers_never_read_a_cell(begin, end):
    memory = Memory()
    memory.header(memory.fra, begin, end)
    result = leaf.read_direction(memory, memory.fra, memory.eng)
    assert result['status'] == 'unknown' and 'value' not in result
    assert not any(size == 2 for _, size, _ in memory.reads)


@pytest.mark.parametrize('suffix,reason', [
    ('begin.after', 'OPINION_TABLE_HEADER_CHANGED'),
    ('holder_ref.after', 'OPINION_COUNTRY_REBOUND'),
])
def test_one_unstable_direction_does_not_remove_the_other(suffix, reason):
    memory = Memory()
    memory.override = lambda raw, label: (bytes([raw[0] ^ 2])+raw[1:]
        if label == 'opinion.ENG.to.FRA.'+suffix else raw)
    result = leaf.read_fields(memory, memory.fra, memory.eng)
    assert result[leaf.FIELDS[0]]['status'] == 'known'
    assert result[leaf.FIELDS[1]] == {'status': 'unknown', 'reason': reason}


@pytest.mark.parametrize('field,value', [('slot', True), ('slot', 4096),
    ('tag', 'POR'), ('country_pointer', '0x20001'), ('fullref', '0x1')])
def test_invalid_binding_is_rejected_before_any_memory_read(field, value):
    memory = Memory()
    record = deepcopy(memory.fra)
    record[field] = value
    assert leaf.read_direction(memory, record, memory.eng)['status'] == 'unknown'
    assert memory.reads == []


def test_reader_failure_is_unknown_and_does_not_leak_exception_text():
    memory = Memory()
    def fail(raw, label):
        raise RuntimeError('private pointer / untrusted reader details')
    memory.override = fail
    result = leaf.read_direction(memory, memory.fra, memory.eng)
    assert result == {'status': 'unknown', 'reason': 'OPINION_CELL_READ_FAILED'}


def test_only_requested_direction_is_read():
    memory = Memory()
    result = leaf.read_fields(memory, memory.fra, memory.eng, (leaf.FIELDS[1],))
    assert list(result) == [leaf.FIELDS[1]]
    assert len(memory.reads) == 9
