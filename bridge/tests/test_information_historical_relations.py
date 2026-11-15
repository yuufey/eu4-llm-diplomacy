from copy import deepcopy

import pytest

from bridge.information import ai_attitude as attitude
from bridge.information import InformationService
from bridge.information.composite import CompositeSource
from bridge.information.tools import InformationTools
from bridge.tests.test_information_ai_attitude import make_capture
from bridge.tests.test_information_foreign_technology import Base
from bridge.tests.test_information_foreign_technology_capture import (
    MODULE_BASE, RecordingReader, make_valid_capture,
)
from bridge.tests.test_information_foreign_technology_memory import MemoryReader


def _fullref(tag, slot, generation=0):
    return ((generation & 0xFFFF) << 48) | (slot << 32) | int.from_bytes(tag.encode("ascii"), "little")


def _put_history_list(image, pointer, history, name, fullrefs, *, count=None,
                      node_address=None, next_pointer=None):
    values = list(fullrefs)
    count = len(values) if count is None else count
    head = (node_address if node_address is not None else
            0x6A00000000 + ((pointer & 0xFFFFF) << 8) + history[name])
    header = bytearray(20)
    header[:8] = (head if values or count else 0).to_bytes(8, "little")
    header[history["count_offset"]:history["count_offset"] + 4] = count.to_bytes(
        4, "little", signed=True)
    image.put(pointer + history[name], bytes(header))
    for index, fullref in enumerate(values):
        node = head + index * 0x100
        if index + 1 < len(values):
            following = node + 0x100
        elif next_pointer is not None:
            following = next_pointer
        else:
            following = 0
        raw = bytearray(24)
        raw[:8] = fullref.to_bytes(8, "little")
        raw[history["node_next_offset"]:history["node_next_offset"] + 8] = following.to_bytes(8, "little")
        image.put(node, bytes(raw))
    return head


def _pair_memory():
    _, _, _, fixture = make_valid_capture(country="ENG")
    profile = attitude._load_profile()
    image = fixture["image"]
    for guard in profile["code_guards"]:
        image.put(MODULE_BASE + int(guard["rva"], 0), bytes.fromhex(guard["bytes"]))
    return image, fixture, profile


def _combined_capture(actor="ENG", recipient="FRA", fields=("ai_attitude", "history")):
    # Reuse the established public capture fixture for identity/context and its
    # expected attitude value; build the extended memory graph with the same
    # bounded MemoryReader and trace recorder used by that fixture.
    report, context, creation = make_capture(actor, recipient)
    image, fixture, profile = _pair_memory()
    bindings = fixture["bindings"]
    holder = bindings[actor]
    target = bindings[recipient]
    spec = profile["attitude"]

    table = 0x6900000000
    image.put_u64(holder["country_pointer"] + spec["relation_table_offset"], table)
    row = table + target["slot"] * spec["relation_row_stride"]
    image.put(row, bytes(spec["relation_row_stride"]))
    image.put_u64(row + spec["recipient_fullref_offset"], target["fullref"])
    image.put_u64(row + spec["attitude_pointer_offset"], 0x6920000000)

    source_attitude = report["observation"]["backend"]["targets"][0]["fields"][attitude.FIELD]
    raw_name = source_attitude["raw_name"]
    payload = 0x6930000000
    raw = raw_name.encode("ascii")
    header = bytearray(32)
    header[:8] = payload.to_bytes(8, "little")
    header[16:24] = len(raw).to_bytes(8, "little")
    header[24:32] = (31).to_bytes(8, "little")
    image.put(0x6920000000 + spec["definition_name_offset"], bytes(header))
    image.put(payload, raw + b"\0")

    history = spec["history"]
    _put_history_list(image, holder["country_pointer"], history, "historical_friend",
                      [_fullref("SWE", target["slot"], 0xABCD)])
    _put_history_list(image, holder["country_pointer"], history, "historical_rival", [])

    reader = RecordingReader(image)
    selected = tuple(fields)
    observation = attitude._observe_for(actor, recipient, selected)(
        reader, MODULE_BASE, "ENG", profile)
    report = deepcopy(report)
    report["request"].update(actor=actor, recipient=recipient, fields=list(selected))
    report["observation"] = observation
    report["raw_reads"] = deepcopy(reader.read_log)
    report["access"].update(calls=reader.calls, bytes_requested=reader.bytes_requested)
    return report, context, creation, image, fixture


def test_history_is_directional_and_matches_the_bound_target_slot():
    image, fixture, profile = _pair_memory()
    history = profile["attitude"]["history"]
    bindings = fixture["bindings"]
    eng = bindings["ENG"]["country_pointer"]
    fra = bindings["FRA"]["country_pointer"]

    # A different tag and generation still matches when the low 16-bit slot
    # equals the requested recipient's bound slot.
    _put_history_list(image, eng, history, "historical_friend",
                      [_fullref("SWE", bindings["FRA"]["slot"], 0x1234)])
    _put_history_list(image, eng, history, "historical_rival",
                      [_fullref("FRA", 901)])
    _put_history_list(image, fra, history, "historical_friend",
                      [_fullref("ENG", 902)])
    _put_history_list(image, fra, history, "historical_rival",
                      [_fullref("SWE", bindings["ENG"]["slot"], 0x5678)])

    for actor, recipient, expected in (
        ("ENG", "FRA", {"historical_friend": True, "historical_rival": False}),
        ("FRA", "ENG", {"historical_friend": False, "historical_rival": True}),
    ):
        reader = RecordingReader(image)
        observed = attitude._observe_for(actor, recipient, ("history",))(
            reader, MODULE_BASE, "ENG", profile)
        value = observed["backend"]["targets"][0]["fields"][attitude.HISTORY_FIELD]
        assert value["status"] == "known"
        assert {name: item["value"] for name, item in value["value"].items()} == expected


def test_empty_historical_lists_are_known_false():
    image = MemoryReader()
    pointer = 0x6400000000
    history = attitude._load_profile()["attitude"]["history"]
    _put_history_list(image, pointer, history, "historical_friend", [])
    _put_history_list(image, pointer, history, "historical_rival", [])

    result = attitude._read_history(image, pointer, 122, history)

    assert result["status"] == "known"
    assert result["value"] == {
        "historical_friend": {"status": "known", "value": False},
        "historical_rival": {"status": "known", "value": False},
    }


@pytest.mark.parametrize("failure", ["invalid_count", "cycle"])
def test_a_bad_list_keeps_the_other_history_component_known(failure):
    image = MemoryReader()
    pointer = 0x6400000000
    history = attitude._load_profile()["attitude"]["history"]
    if failure == "invalid_count":
        _put_history_list(image, pointer, history, "historical_friend", [],
                          count=history["max_entries"] + 1, node_address=0x6A10000000)
    else:
        head = _put_history_list(image, pointer, history, "historical_friend",
                                 [_fullref("ENG", 122)], count=2,
                                 node_address=0x6A10000000, next_pointer=0x6A10000000)
        assert head == 0x6A10000000
    _put_history_list(image, pointer, history, "historical_rival", [_fullref("FRA", 122)])

    result = attitude._read_history(image, pointer, 122, history)

    assert result["value"]["historical_friend"]["status"] == "unknown"
    assert result["value"]["historical_rival"] == {"status": "known", "value": True}


def test_history_only_selection_does_not_read_attitude_relationship_rows():
    image, fixture, profile = _pair_memory()
    holder = fixture["bindings"]["ENG"]
    history = profile["attitude"]["history"]
    _put_history_list(image, holder["country_pointer"], history, "historical_friend", [])
    _put_history_list(image, holder["country_pointer"], history, "historical_rival", [])
    reader = RecordingReader(image)

    observed = attitude._observe_for("ENG", "FRA", ("history",))(
        reader, MODULE_BASE, "ENG", profile)

    labels = [row["label"] for row in reader.read_log]
    assert observed["backend"]["targets"][0]["fields"][attitude.HISTORY_FIELD]["status"] == "known"
    assert "ai_attitude.relation_table" not in labels
    assert "ai_attitude.relation_row" not in labels
    assert not any(label.startswith("ai_attitude.name") for label in labels)


def test_joint_information_query_returns_concise_and_full_history_once(tmp_path):
    report, context, creation, _image, _fixture = _combined_capture()
    base = Base(tmp_path, context, creation)
    captures = []

    def capture_once(*args):
        captures.append(args)
        return deepcopy(report)

    adapter = attitude.NativeAiAttitudeSource(base, capture=capture_once)
    source = CompositeSource(base, [adapter])
    service = InformationService(source, tmp_path / "information.sqlite3")
    try:
        tools = InformationTools(service)
        request = {
            "topic": "R06",
            "object": {"type": "country_pair", "actor": "ENG", "recipient": "FRA"},
            "fields": ["ai_attitude", "history"],
            "parameters": {},
        }
        result = tools.call("information_query", {
            "request_id": "historical-relations-query", "queries": [request],
        })
        assert result["items"] == [{
            "actor": "ENG", "recipient": "FRA", "ai_attitude": "hostile",
            "history": {"historical_friend": True, "historical_rival": False},
        }]
        assert len(captures) == 1

        full = tools.call("information_get_result", {
            "result_id": result["result_id"], "view": "full",
        })
        fields = full["items"][0]["fields"]
        assert fields["ai_attitude"]["raw_name"] == "attitude_hostile"
        assert fields["history"]["value"]["historical_friend"] == {
            "status": "known", "value": True,
        }
        assert fields["history"]["value"]["historical_rival"] == {
            "status": "known", "value": False,
        }
        assert len(captures) == 1
    finally:
        service.close()


def test_attitude_read_failure_does_not_discard_observed_history():
    image, fixture, profile = _pair_memory()
    holder = fixture["bindings"]["ENG"]
    history = profile["attitude"]["history"]
    _put_history_list(image, holder["country_pointer"], history, "historical_friend",
                      [_fullref("FRA", fixture["bindings"]["FRA"]["slot"])])
    _put_history_list(image, holder["country_pointer"], history, "historical_rival", [])

    def fail_attitude_table(_reader, _address, _size, label, _count):
        if label == "ai_attitude.relation_table":
            raise OSError("synthetic attitude table read failure")

    image.on_read = fail_attitude_table
    reader = RecordingReader(image)

    observed = attitude._observe_for("ENG", "FRA", ("ai_attitude", "history"))(
        reader, MODULE_BASE, "ENG", profile)
    fields = observed["backend"]["targets"][0]["fields"]

    assert fields[attitude.FIELD]["status"] == "unknown"
    assert fields[attitude.HISTORY_FIELD]["status"] == "known"
    assert fields[attitude.HISTORY_FIELD]["value"]["historical_friend"] == {
        "status": "known", "value": True,
    }
