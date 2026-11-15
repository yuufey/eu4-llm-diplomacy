"""Current coalition graph tests over a bounded fake country database."""
import struct

import pytest

from bridge.information import coalition_memory as memory
from bridge.information import country_reference_memory as countries
from bridge.tests.test_information_foreign_country_memory import MemoryImage, fullref


BASE = 0x140000000
DATABASE = 0x6200000000
TABLE = 0x6300000000
NODE = 0x6800000000


def make_graph(*, removed=False):
    image = MemoryImage()
    image.put_u64(BASE + countries.DATABASE_GLOBAL_RVA, DATABASE)
    image.put_u64(DATABASE + countries.DATABASE_TABLE_OFFSET, TABLE)
    image.put_i32(DATABASE + countries.DATABASE_TABLE_COUNT_OFFSET, 4)
    pointers, refs = {}, {}
    for slot, tag in enumerate(("FRA", "ENG", "CAS"), 1):
        pointer = 0x6400000000 + slot * 0x4000
        reference = fullref(tag, slot, 0x0100)
        pointers[tag], refs[tag] = pointer, reference
        image.put_u64(TABLE + slot * 8, pointer)
        image.put_u64(pointer + 0x20, reference)
        image.put_u64(pointer + memory.TARGET_OFFSET, 0)
        image.put(pointer + memory.MEMBERS_OFFSET, b"\0" * 24)
    image.put_u64(pointers["ENG"] + memory.TARGET_OFFSET, refs["FRA"])
    image.put(pointers["FRA"] + memory.MEMBERS_OFFSET, struct.pack("<QQiB3x", NODE, NODE, 1, 0))
    image.put(NODE, struct.pack("<QQQB7x", refs["ENG"], 0, 0, removed))
    scan = countries.resolve_countries(image.read, BASE, ["FRA", "ENG", "CAS"])
    return image, scan, pointers, refs


def read_graph(image, scan, tag="FRA", fields=memory.FIELDS, admit=None):
    return memory.read_fields(image, BASE, scan["requested"][tag], fields,
                              country_scan=scan, admit_country=admit)


def test_incoming_members_and_outgoing_target_have_opposite_directions():
    image, scan, _pointers, _refs = make_graph()
    own = read_graph(image, scan)
    other = read_graph(image, scan, "ENG")
    assert own[memory.FIELDS[0]]["value"] == ["ENG"]
    assert own[memory.FIELDS[1]]["value"] == []
    assert other[memory.FIELDS[0]]["value"] == []
    assert other[memory.FIELDS[1]]["value"] == ["FRA"]


def test_removed_node_does_not_resolve_its_stale_country_reference():
    image, scan, _pointers, _refs = make_graph(removed=True)
    image.put_u64(NODE, 0xFFFF000000000000)
    result = read_graph(image, scan)
    assert result[memory.FIELDS[0]]["value"] == []
    assert result[memory.FIELDS[1]]["value"] == []


@pytest.mark.parametrize("failure", ["generation", "reverse_target", "previous", "cycle", "removed_flag", "count", "short"])
def test_invalid_incoming_graph_keeps_members_unknown_and_independent_target_known(failure):
    image, scan, pointers, refs = make_graph()
    if failure == "generation":
        image.put_u64(NODE, refs["ENG"] ^ (1 << 48))
    elif failure == "reverse_target":
        image.put_u64(pointers["ENG"] + memory.TARGET_OFFSET, refs["CAS"])
    elif failure == "previous":
        image.put_u64(NODE + 8, NODE)
    elif failure == "cycle":
        image.put_u64(NODE + 16, NODE)
    elif failure == "removed_flag":
        image.put(NODE + 24, b"\x02")
    elif failure == "count":
        image.put_i32(pointers["FRA"] + memory.MEMBERS_OFFSET + 16, memory.MAX_MEMBERS + 1)
    else:
        image.short_at.add(NODE)
    result = read_graph(image, scan)
    assert result[memory.FIELDS[0]]["status"] == "unknown"
    assert result[memory.FIELDS[1]]["value"] == []


def test_outgoing_target_requires_a_current_reciprocal_member_node():
    image, scan, _pointers, _refs = make_graph(removed=True)
    assert read_graph(image, scan, "ENG")[memory.FIELDS[1]]["status"] == "unknown"


def test_country_visibility_is_required_before_public_member_or_target_identity():
    image, scan, _pointers, _refs = make_graph()
    assert read_graph(image, scan, admit=lambda binding: False)[memory.FIELDS[0]]["status"] == "unknown"
    assert read_graph(image, scan, "ENG", admit=lambda binding: False)[memory.FIELDS[1]]["status"] == "unknown"


def test_unrequested_incoming_list_is_not_read_by_the_leaf():
    image, scan, _pointers, _refs = make_graph()
    image.fail_at.add(NODE)
    result = read_graph(image, scan, fields=(memory.FIELDS[1],))
    assert result[memory.FIELDS[1]]["value"] == []
