"""Current war-reparations terms over the existing bounded pair byte graph."""
import pytest

from bridge.information import reparations_commitments as memory
from bridge.information.presentation import _concise_value
from bridge.tests import test_bilateral_reparations_memory as fixture


def environment(*, present=True, payer="FRA", factor=100):
    image, observer, target, locations = fixture._environment(present=present, payer=payer)
    for role, binding in (("observer", observer), ("target", target)):
        old_owner = locations[role + "_owner"]
        owner = int(binding["country_pointer"], 0) + 0x14F8
        image.put_u64(locations[role + "_row"], owner)
        image.put(owner + 0x98, image.read(old_owner + 0x98, 16, "fixture.vector_header"))
    if present:
        image.put(fixture.TREATY + 0x28, b"\0")
        image.put_i32(fixture.BASE + memory.INCOME_FACTOR_RVA, factor)
    return image, observer, target, locations


def read(image, observer, target, date=fixture.START_DATE):
    return memory.read_fields(image, fixture.BASE, observer, target, memory.FIELDS,
                              observed_date=date)


@pytest.mark.parametrize("payer,factor", [("FRA", 100), ("ENG", 250), ("ENG", -125)])
def test_current_contract_keeps_direction_native_income_percent_and_deadline(payer, factor):
    image, observer, target, _ = environment(payer=payer, factor=factor)
    fields = read(image, observer, target)
    support = fields[memory.SUPPORT_FIELD]["value"]
    entry = support["active_payment_obligations"]["value"][0]
    assert entry["kind"] == "war_reparations"
    assert entry["payer"] == payer
    assert entry["recipient"] == ("ENG" if payer == "FRA" else "FRA")
    assert entry["income_percent"]["raw"] == factor
    assert _concise_value(entry["income_percent"]) == factor / 10
    assert entry["end_date"]["value"] == fixture.END_DATE
    assert fields[memory.EXPIRY_FIELD]["value"][0]["end_date"] == entry["end_date"]
    assert support["registered_reparations_evidence"]["pair_relation"]["present"] is True


@pytest.mark.parametrize("delta,active", [(-1, True), (0, False), (1, False)])
def test_native_deadline_expires_on_the_end_date(delta, active):
    image, observer, target, _ = environment()
    fields = read(image, observer, target, fixture.END_DATE + delta)
    assert bool(fields[memory.SUPPORT_FIELD]["value"]["active_payment_obligations"]["value"]) is active
    assert bool(fields[memory.EXPIRY_FIELD]["value"]) is active


def test_native_expiry_has_no_extra_start_date_condition():
    image, observer, target, _ = environment()
    fields = read(image, observer, target, fixture.START_DATE - 1)
    assert len(fields[memory.EXPIRY_FIELD]["value"]) == 1


def test_cancelled_record_keeps_registered_terms_and_has_no_current_obligation():
    image, observer, target, _ = environment()
    image.put(fixture.TREATY + 0x28, b"\x01")
    fields = read(image, observer, target)
    assert fields[memory.SUPPORT_FIELD]["value"]["active_payment_obligations"]["value"] == []
    assert fields[memory.EXPIRY_FIELD]["value"] == []
    assert fields[memory.SUPPORT_FIELD]["value"]["registered_reparations_evidence"]["contracts"]


def test_absent_pair_is_known_empty_without_reading_rate_or_contract_flag():
    image, observer, target, _ = environment(present=False)
    fields = read(image, observer, target)
    assert fields[memory.SUPPORT_FIELD]["value"]["active_payment_obligations"]["value"] == []
    assert fields[memory.EXPIRY_FIELD]["value"] == []
    assert not any(label.startswith("reparations_commitments.") for _, _, label in image.reads)


def test_unreadable_rate_preserves_current_contract_and_known_expiry():
    image, observer, target, _ = environment()
    image.short_at.add(fixture.BASE + memory.INCOME_FACTOR_RVA)
    fields = read(image, observer, target)
    active = fields[memory.SUPPORT_FIELD]["value"]["active_payment_obligations"]
    assert active["status"] == "known"
    assert active["partial"] is True
    assert active["value"][0]["income_percent"]["status"] == "unknown"
    assert len(fields[memory.EXPIRY_FIELD]["value"]) == 1


def test_unreadable_cancelled_flag_keeps_registered_terms_and_unknown_current_state():
    image, observer, target, _ = environment()
    image.short_at.add(fixture.TREATY + 0x28)
    fields = read(image, observer, target)
    support = fields[memory.SUPPORT_FIELD]["value"]
    assert support["registered_reparations_evidence"]["status"] == "known"
    assert support["active_payment_obligations"]["status"] == "unknown"
    assert fields[memory.EXPIRY_FIELD]["status"] == "unknown"


def test_pair_owner_must_be_the_bound_countrys_economy_subobject():
    image, observer, target, locations = environment()
    image.put_u64(locations["observer_row"], fixture.OBSERVER_OWNER)
    fields = read(image, observer, target)
    assert fields[memory.SUPPORT_FIELD]["reason"] == "PAIR_OWNER_NOT_ECONOMY_VECTOR"
    assert fields[memory.EXPIRY_FIELD]["status"] == "unknown"


def test_unstable_pair_identity_does_not_publish_a_contract():
    image, observer, target, locations = environment()
    image.put_u64(locations["observer_row"] + 0x10, 0)
    fields = read(image, observer, target)
    assert all(field["status"] == "unknown" for field in fields.values())


def test_computation_clock_is_absent_from_unchanged_contract_fields():
    image, observer, target, _ = environment()
    first = read(image, observer, target)
    second = read(image, observer, target, fixture.START_DATE + 24)
    assert first == second
