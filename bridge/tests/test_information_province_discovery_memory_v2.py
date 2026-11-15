from bridge.information import province_discovery_memory_v2 as memory
from bridge.information import province_discovery_memory as original
from bridge.information import province_discovery_bitmap_memory as bitmap
from bridge.information import province_reference_memory as province
from bridge.tests.test_information_province_discovery_memory import make_membership_image
from bridge.tests.test_information_province_state_memory import BASES, RECORDS, DISCOVERY_BITS, FRA_SLOT


def make_image(values=(True, False, True)):
    image = make_membership_image(values)
    for pid in range(1, len(values) + 1):
        record = RECORDS + pid * province.RECORD_STRIDE
        image.put_u64(record + bitmap.BITMAP_OFFSET, BASES[0] + bitmap.BITMAP_VTABLE_RVA)
        image.put_u32(record + 0x5e8, 128)
        image.put_u32(record + 0x5ec, 44)
    return image


def test_bounded_sweep_preserves_observer_scope_and_does_not_claim_complete_domain():
    image = make_image()
    result = memory.read_two_pass(image, BASES[0])
    assert result['status'] == 'known' and result['value'] == [1, 3]
    assert result['schema'] == memory.SCHEMA
    assert result['scope']['bitmap_words_native_length_bounded'] is True
    assert result['complete'] is False and result['domain_complete'] is False
    assert sum(label == 'province_bitmap.header' for _, _, label in image.reads) == 6
    assert not any(label == 'province_state.discovery.bitset_pointer' for _, _, label in image.reads)


def test_truncated_bitmap_withdraws_the_entire_sweep_without_reading_its_word():
    image = make_image()
    record = RECORDS + 2 * province.RECORD_STRIDE
    image.put_u32(record + 0x5ec, FRA_SLOT >> 5)
    result = memory.read_two_pass(image, BASES[0])
    assert result['status'] == 'unknown' and 'value' not in result
    assert result['passes'][0]['candidates'][-1]['reason'] == 'OBSERVER_OUTSIDE_BITMAP_LENGTH'
    assert sum(label == 'province_bitmap.word_u32' for _, _, label in image.reads) == 1


def test_header_change_between_passes_with_unchanged_membership_withdraws_result():
    image = make_image((True,))

    def read(address, size, label):
        raw = image.read(address, size, label)
        if label == 'province_bitmap.word_u32':
            image.put_u32(RECORDS + province.RECORD_STRIDE + 0x5ec, 43)
        return raw

    result = memory.read_two_pass(read, BASES[0])
    assert result['status'] == 'unknown' and result['reason'] == 'TWO_PASS_EVIDENCE_CHANGED'
    assert result['consistency']['changed_components'] == ['candidates']


def test_undiscovered_membership_is_not_replaced_by_missing_bitmap():
    image = make_image((False,))
    assert memory.read_two_pass(image, BASES[0])['value'] == []
    image = make_image((False,))
    image.put_u64(RECORDS + province.RECORD_STRIDE + 0x5e0, 0)
    result = memory.read_two_pass(image, BASES[0])
    assert result['status'] == 'unknown' and 'value' not in result


def test_observed_count_reserve_fits_current_domain_without_raising_hard_budgets():
    import pytest
    reader = original._BudgetReader(lambda *_: b'')
    reader.calls, reader.bytes_requested = 2787, 22239
    original._preflight_candidates(reader, 4941, 1, 32, 1390)
    with pytest.raises(original._ReadStop, match='CANDIDATE_SCAN_EXCEEDS_CALL_BUDGET'):
        original._preflight_candidates(reader, 4941, 1, 32)
    reader.calls = original.MAX_READ_CALLS
    with pytest.raises(original._ReadStop, match='READ_CALL_BUDGET_EXCEEDED'):
        reader.read(0x200000000, 4, 'growth_exceeds_budget')
