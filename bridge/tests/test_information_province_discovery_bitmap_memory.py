"""Native bitmap length prevents out-of-domain reads and false memberships."""
import pytest

from bridge.information import province_discovery_bitmap_memory as memory

BASE = 0x140000000
RECORD = 0x200000000
HEAP = 0x300000000


class Image:
    def __init__(self, *, capacity=128, length=44, pointer=HEAP, vtable=None, word=0):
        self.reads = []
        self.header = (int(BASE + memory.BITMAP_VTABLE_RVA if vtable is None else vtable).to_bytes(8, 'little')
            + pointer.to_bytes(8, 'little') + capacity.to_bytes(4, 'little', signed=True)
            + length.to_bytes(4, 'little', signed=True))
        self.pointer, self.word = pointer, word

    def read(self, address, size, label):
        self.reads.append((address, size, label))
        if label == 'province_bitmap.header':
            assert address == RECORD + memory.BITMAP_OFFSET and size == 24
            return self.header
        assert label == 'province_bitmap.word_u32' and size == 4
        return self.word.to_bytes(4, 'little')


@pytest.mark.parametrize('slot', [0, 31, 32, 122, 1407, 4095])
@pytest.mark.parametrize('known', [False, True])
def test_membership_uses_slot_word_and_bit_with_native_length(slot, known):
    image = Image(length=128, word=(1 << (slot & 31)) if known else 0)
    result = memory.read_discovery(image, RECORD, slot, BASE)
    assert result['status'] == 'known' and result['value'] is known
    assert image.reads[-1][0] == HEAP + (slot >> 5) * 4
    assert result['raw_inputs']['length_words'] == 128


@pytest.mark.parametrize('kwargs,slot,reason', [
    ({'length': 44}, 1408, 'OBSERVER_OUTSIDE_BITMAP_LENGTH'),
    ({'length': 0}, 122, 'OBSERVER_OUTSIDE_BITMAP_LENGTH'),
    ({'length': 129}, 122, 'BITMAP_LENGTH_OR_CAPACITY_INVALID'),
    ({'capacity': 129}, 122, 'BITMAP_LENGTH_OR_CAPACITY_INVALID'),
    ({'length': -1}, 122, 'BITMAP_LENGTH_OR_CAPACITY_INVALID'),
    ({'capacity': -1}, 122, 'BITMAP_LENGTH_OR_CAPACITY_INVALID'),
    ({'capacity': 1, 'length': 2}, 0, 'BITMAP_LENGTH_OR_CAPACITY_INVALID'),
    ({'pointer': 0}, 122, 'BITMAP_POINTER_INVALID'),
    ({'pointer': HEAP + 1}, 122, 'BITMAP_POINTER_INVALID'),
    ({'pointer': RECORD + 0x100}, 122, 'BITMAP_STORAGE_OVERLAPS_RECORD'),
    ({'pointer': RECORD - 4}, 122, 'BITMAP_STORAGE_OVERLAPS_RECORD'),
    ({'vtable': BASE + memory.BITMAP_VTABLE_RVA + 8}, 122, 'BITMAP_TYPE_MISMATCH'),
])
def test_invalid_or_missing_native_range_never_reads_word_or_returns_false(kwargs, slot, reason):
    image = Image(**kwargs)
    result = memory.read_discovery(image, RECORD, slot, BASE)
    assert result['status'] == 'unknown' and result['reason'] == reason
    assert 'value' not in result and len(image.reads) == 1


def test_inline_storage_is_recognized_without_treating_it_as_heap_overlap():
    image = Image(pointer=RECORD + memory.INLINE_OFFSET, word=1 << 26)
    result = memory.read_discovery(image, RECORD, 122, BASE)
    assert result['value'] is True and result['raw_inputs']['inline_storage'] is True


@pytest.mark.parametrize('slot', [True, -1, 4096, '122'])
def test_invalid_slot_does_not_read(slot):
    image = Image()
    assert memory.read_discovery(image, RECORD, slot, BASE)['reason'] == 'OBSERVER_SLOT_OUT_OF_RANGE'
    assert not image.reads


@pytest.mark.parametrize('on_word', [False, True])
def test_short_or_failing_reads_withdraw_value(on_word):
    image = Image()

    def read(address, size, label):
        if (label == 'province_bitmap.word_u32') == on_word:
            return b''
        return image.read(address, size, label)

    result = memory.read_discovery(read, RECORD, 122, BASE)
    assert result['status'] == 'unknown' and 'value' not in result
    assert result['reason'] == 'BITMAP_SHORT_OR_INVALID_READ'
