from bridge.information import country_discovery_memory_v2 as memory
from bridge.tests.test_information_country_discovery_memory import BASE, make_image as original_image


def make_image():
    image, bindings = original_image()
    for binding in bindings.values():
        image.put_i32(int(binding['country_pointer'], 16) + 0x1344, 1)
    image.reads.clear()
    return image, bindings


def test_extinct_target_skips_unreadable_capital_without_becoming_unknown():
    image, bindings = make_image()
    pointer = int(bindings['DEN']['country_pointer'], 16)
    image.put_i32(pointer + 0x1344, 0)
    image.put_u64(pointer + 0x14b0, 0)
    result = memory.read_two_pass(image, BASE)
    assert result['status'] == 'known' and result['value'] == ['FRA', 'SWE']
    assert result['scope']['country_existence_filter_applied'] is True
    assert result['scope']['candidate_count'] == 4
    assert result['scope']['existing_candidate_count'] == 3
    assert result['complete'] is False and result['domain_complete'] is False
    assert not any(address == pointer + 0x14b0 for address, _, _ in image.reads)
    for current in result['passes']:
        row = next(row for row in current['candidates'] if row['tag'] == 'DEN')
        assert row['exists'] is False and row['knowledge_evaluated'] is False


def test_observer_must_exist_before_any_knowledge_reads():
    image, bindings = make_image()
    image.put_i32(int(bindings['FRA']['country_pointer'], 16) + 0x1344, 0)
    result = memory.read_two_pass(image, BASE)
    assert result['status'] == 'unknown' and result['reason'] == 'OBSERVER_EXISTENCE_NOT_VERIFIED'
    assert 'value' not in result
    assert not any(label.startswith('country_knowledge.') for _, _, label in image.reads)


def test_missing_existence_state_withdraws_the_whole_collection():
    image, bindings = make_image()
    bad = int(bindings['DEN']['country_pointer'], 16) + 0x1344

    def read(address, size, label):
        return b'' if address == bad else image.read(address, size, label)

    result = memory.read_two_pass(read, BASE)
    assert result['status'] == 'unknown' and result['reason'] == 'COUNTRY_EXISTENCE_UNKNOWN'
    assert 'value' not in result


def test_existence_raw_drift_with_same_boolean_withdraws_list():
    image, bindings = make_image()
    state = int(bindings['DEN']['country_pointer'], 16) + 0x1344
    count = 0

    def read(address, size, label):
        nonlocal count
        raw = image.read(address, size, label)
        if address == state:
            count += 1
            if count == 1:
                image.put_i32(state, 2)
        return raw

    result = memory.read_two_pass(read, BASE)
    assert result['status'] == 'unknown' and result['reason'] == 'TWO_PASS_EVIDENCE_CHANGED'
    assert 'candidates' in result['consistency']['changed_components']


def test_existing_unknown_knowledge_is_not_dropped_as_extinct():
    image, bindings = make_image()
    image.put_u64(int(bindings['DEN']['country_pointer'], 16) + 0x14b0, 0)
    result = memory.read_two_pass(image, BASE)
    assert result['status'] == 'unknown' and result['reason'] == 'COUNTRY_KNOWLEDGE_UNKNOWN'


def test_invalid_viewpoint_does_no_read():
    image, _ = make_image()
    result = memory.read_two_pass(image, BASE, 'POR')
    assert result['status'] == 'unknown' and not image.reads
