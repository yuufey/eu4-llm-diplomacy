"""Current subsidy obligations reuse the existing bounded pair fixtures."""
import struct

import pytest

from bridge.information import economic_commitments as memory
from bridge.tests import test_bilateral_subsidies_memory as fixture


def environment(**kwargs):
    image, observer, target, locations = fixture._environment(**kwargs)
    image.put_u64(fixture.OBSERVER_POINTER + 0x18F0, 0)
    image.put_u64(fixture.TARGET_POINTER + 0x18F0, 0)
    return image, observer, target, locations


def read(image, observer, target, date=fixture.START):
    return memory.read_fields(image, fixture.BASE, observer, target, memory.FIELDS,
                              observed_date=date)


@pytest.mark.parametrize("payer,amount", [("FRA", 12_500), ("ENG", 2_500), ("ENG", -2_500)])
def test_active_contract_keeps_native_amount_parties_and_expiry(payer, amount):
    image, observer, target, _ = environment(payer=payer, amount=amount)
    fields = read(image, observer, target)
    support = fields[memory.SUPPORT_FIELD]["value"]
    entry = support["active_payment_obligations"]["value"][0]
    assert entry["payer"] == payer
    assert entry["recipient"] == ("ENG" if payer == "FRA" else "FRA")
    assert entry["monthly_amount"]["value"] == amount
    assert entry["monthly_amount"]["scale"] == 1000
    assert entry["end_date"]["value"] == fixture.START + 2 * 8760
    assert fields[memory.EXPIRY_FIELD]["value"][0]["end_date"] == entry["end_date"]
    assert "current_date" not in repr(fields)


@pytest.mark.parametrize("delta,active", [(-1, True), (0, True), (1, False)])
def test_native_expiry_keeps_deadline_inclusive(delta, active):
    image, observer, target, _ = environment()
    end = fixture.START + 2 * 8760
    fields = read(image, observer, target, end + delta)
    assert bool(fields[memory.SUPPORT_FIELD]["value"]["active_payment_obligations"]["value"]) is active
    assert bool(fields[memory.EXPIRY_FIELD]["value"]) is active


def test_removed_contract_has_no_current_obligation_even_before_its_deadline():
    image, observer, target, locations = environment()
    image.put(locations["object"] + 0x28, b"\x01")
    fields = read(image, observer, target)
    assert fields[memory.SUPPORT_FIELD]["value"]["active_payment_obligations"]["value"] == []
    assert fields[memory.EXPIRY_FIELD]["value"] == []
    assert fields[memory.SUPPORT_FIELD]["value"]["registered_subsidy_evidence"]["pair_relation"]["present"] is True


def test_absent_pair_is_known_empty_current_support_and_expiry():
    image, observer, target, _ = environment(forward_entries=[], reverse_entries=[])
    fields = read(image, observer, target)
    assert fields[memory.SUPPORT_FIELD]["value"]["active_payment_obligations"]["value"] == []
    assert fields[memory.EXPIRY_FIELD]["value"] == []


@pytest.mark.parametrize("disabled", [None, 0x11B, 0x14B, 0x121, 0x13E, 0x151, 0x148])
def test_payer_subject_exception_follows_all_native_definition_flags(disabled):
    image, observer, target, locations = environment()
    image.put_u64(fixture.OBSERVER_POINTER + 0x18F0, int(target["fullref"], 0))
    vector, relation, definition = 0x91000000, 0x92000000, 0x93000000
    image.put(locations["observer_owner"] + 0x128, struct.pack("<Qii", vector, 1, 1))
    image.put(vector, struct.pack("<i4xQ", target["slot"], relation))
    image.put_u64(relation + 0x40, definition)
    values = {0x11B: True, 0x14B: True, 0x121: False, 0x13E: False, 0x151: False, 0x148: True}
    if disabled is not None:
        values[disabled] = not values[disabled]
    for offset, value in values.items():
        image.put(definition + offset, bytes([value]))
    fields = read(image, observer, target)
    assert bool(fields[memory.SUPPORT_FIELD]["value"]["active_payment_obligations"]["value"]) is (disabled is None)


def test_unreadable_subject_state_keeps_registered_terms_and_unknown_current_obligation():
    image, observer, target, _ = environment()
    image.short_labels.add("economic_commitments.payer_overlord")
    fields = read(image, observer, target)
    support = fields[memory.SUPPORT_FIELD]["value"]
    assert support["registered_subsidy_evidence"]["status"] == "known"
    assert support["active_payment_obligations"]["status"] == "unknown"
    assert fields[memory.EXPIRY_FIELD]["status"] == "unknown"


def test_signed_native_expiry_wrap_is_preserved():
    image, observer, target, _ = environment(start=0x7FFFFFF0, duration=1)
    fields = read(image, observer, target)
    assert fields[memory.EXPIRY_FIELD]["value"] == []
