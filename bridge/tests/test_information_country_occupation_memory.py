import pytest

from bridge.information import country_occupation_memory as occupation
from bridge.information import foreign_pressure
from bridge.information import province_discovery_bitmap_memory as discovery
from bridge.information import province_reference_memory as provinces
from bridge.tests.test_information_foreign_technology_memory import MemoryReader


BASE = 0x140000000
WORLD = 0x5000000000
RECORDS = 0x5200000000
COUNTRY = 0x6400000000
ARRAY = 0x6a00000000
OWNED = 0x6b00000000


def reference(tag, slot):
    return (0x100 << 48) | (slot << 32) | int.from_bytes(tag.encode('ascii'), 'little')


def put_provinces(image, target_ref, controllers, *, country=COUNTRY, world=WORLD,
                  observer_slot=122, undiscovered=(), blockaded=()):
    image.put_u64(BASE + provinces.PROVINCE_GLOBAL_RVA, world)
    image.put_u64(world + provinces.ARRAY_BEGIN_OFFSET, ARRAY)
    image.put_u64(world + provinces.ARRAY_END_OFFSET, ARRAY + (len(controllers) + 2) * 8)
    image.put_u64(world + provinces.RECORDS_POINTER_OFFSET, RECORDS)
    image.put_u64(country + 0x1338, OWNED)
    image.put_i32(country + 0x1344, len(controllers))
    if controllers:
        image.put(OWNED, b''.join(i.to_bytes(4, 'little') for i in range(1, len(controllers) + 1)))
    for province, controller in enumerate(controllers, 1):
        record = RECORDS + province * provinces.RECORD_STRIDE
        image.put_i32(record + provinces.RECORD_ID_OFFSET, province)
        bitset = record + discovery.INLINE_OFFSET
        words = (observer_slot >> 5) + 1
        image.put(record + discovery.BITMAP_OFFSET,
            (BASE + discovery.BITMAP_VTABLE_RVA).to_bytes(8, 'little')
            + bitset.to_bytes(8, 'little') + words.to_bytes(4, 'little') * 2)
        word = 0 if province in undiscovered else 1 << (observer_slot & 31)
        image.put_i32(bitset + (observer_slot >> 5) * 4, word)
        image.put_u64(record + 0x468, target_ref)
        image.put_u64(record + 0x470, controller)
        image.put(record + 0x958, bytes([0x40 if province in blockaded else 0]))


def read(image, controllers, *, undiscovered=()):
    refs = {tag: reference(tag, slot) for slot, tag in enumerate(('ENG', 'FRA', 'REB'), 1)}
    put_provinces(image, refs['ENG'], [refs[tag] for tag in controllers], undiscovered=undiscovered)
    rows = {hex(value): {'tag': tag} for tag, value in refs.items()}
    return occupation.read_occupation(image, BASE,
        {'country_pointer': hex(COUNTRY), 'fullref': hex(refs['ENG'])},
        {'slot': 122}, rows, foreign_pressure._load_profile()['occupation'])


def test_summarizes_only_owned_provinces_and_resolves_rebel_control():
    image = MemoryReader()
    result = read(image, ['ENG', 'FRA', 'REB'])
    assert result == {'status': 'known', 'complete': True, 'value': {
        'owned_provinces': 3, 'observed_provinces': 3, 'occupied_provinces': 2,
        'occupiers': {'FRA': 1, 'REB': 1}}}
    assert not any(label == 'province_reference.id[4]' for _, _, label in image.reads)


def test_undiscovered_province_never_reads_its_owner_or_controller():
    image = MemoryReader()
    result = read(image, ['ENG', 'FRA'], undiscovered=[2])
    assert result['complete'] is False
    assert result['value'] == {'owned_provinces': 2, 'observed_provinces': 1,
                               'occupied_provinces': 0, 'occupiers': {}}
    record = RECORDS + 2 * provinces.RECORD_STRIDE
    assert not any(address in (record + 0x468, record + 0x470) for address, _, _ in image.reads)


def test_reads_more_than_one_province_batch():
    image = MemoryReader()
    result = read(image, ['FRA'] * 70)
    assert result['value']['occupied_provinces'] == 70
    assert image.label_counts['province_reference.array_begin'] == 3


def test_empty_country_needs_no_province_records():
    image = MemoryReader()
    result = read(image, [])
    assert result['complete'] is True
    assert result['value']['owned_provinces'] == result['value']['occupied_provinces'] == 0
    assert all(not label.startswith('province_reference.') for _, _, label in image.reads)


@pytest.mark.parametrize('fault', ['duplicate', 'owner_mismatch'])
def test_invalid_owned_list_or_changed_owner_is_rejected(fault):
    image = MemoryReader()
    target = reference('ENG', 1)
    put_provinces(image, target, [target, target])
    if fault == 'duplicate':
        image.put(OWNED, (1).to_bytes(4, 'little') * 2)
    else:
        image.put_u64(RECORDS + provinces.RECORD_STRIDE + 0x468, reference('FRA', 2))
    with pytest.raises(ValueError, match='OCCUPATION_'):
        occupation.read_occupation(image, BASE,
            {'country_pointer': hex(COUNTRY), 'fullref': hex(target)}, {'slot': 122},
            {hex(target): {'tag': 'ENG'}}, foreign_pressure._load_profile()['occupation'])


def test_blockades_share_province_traversal_and_can_skip_controller_reads():
    image = MemoryReader()
    target = reference('ENG', 1)
    put_provinces(image, target, [target, target], blockaded=[2])
    image.put(RECORDS + provinces.RECORD_STRIDE + 0x958, b'\x01')
    result = occupation.read_occupation(image, BASE,
        {'country_pointer': hex(COUNTRY), 'fullref': hex(target)}, {'slot': 122},
        {hex(target): {'tag': 'ENG'}}, foreign_pressure._load_profile()['occupation'],
        blockade_spec={'flags_offset': 0x958, 'mask': 0x40}, include_occupation=False)
    assert result['blockades'] == {'status': 'known', 'complete': True, 'value': {
        'owned_provinces': 2, 'observed_provinces': 2, 'blockaded_provinces': 1}}
    assert not any(label == 'occupation.controller' for _, _, label in image.reads)
    assert image.label_counts['province_reference.array_begin'] == 1


def test_blockade_read_failure_preserves_known_occupation_summary():
    class MissingFlags(MemoryReader):
        def read(self, address, size, label):
            if label == 'occupation.blockade_flags':
                raise ValueError('flag unavailable')
            return super().read(address, size, label)

    image = MissingFlags()
    target = reference('ENG', 1)
    put_provinces(image, target, [target])
    result = occupation.read_occupation(image, BASE,
        {'country_pointer': hex(COUNTRY), 'fullref': hex(target)}, {'slot': 122},
        {hex(target): {'tag': 'ENG'}}, foreign_pressure._load_profile()['occupation'],
        blockade_spec={'flags_offset': 0x958, 'mask': 0x40})
    assert result['complete'] is True
    assert result['value']['observed_provinces'] == 1
    assert result['blockades']['complete'] is False
    assert result['blockades']['value']['observed_provinces'] == 0
