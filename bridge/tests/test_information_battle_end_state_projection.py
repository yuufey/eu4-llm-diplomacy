"""Consumer coverage for wire9 battle overrun projection and old records."""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import struct

from bridge.information.battles import BattleInformationSource
from bridge.tests.test_information_battle_display_context_wire import _v6_base
from bridge.tests.test_information_battle_end_state_wire import (
    _base7,
    _base8,
    _known,
)
from bridge.tests.test_information_battles import (
    battle_query,
    battle_topic_query,
    event_id,
    load_fra_fixture,
    load_fixture,
    load_live_v3_fixture,
    make_source,
)
from work import information_battle_display_context_wire as v7_wire
from work import information_battle_end_state_wire as end_state_wire
from work import information_battle_name_handoff_wire as v8_wire
from work import information_battle_naval_wire as v3_wire
from work import information_battle_native_text_wire as v6_wire


ROOT = Path(__file__).resolve().parents[2]


def _snapshot(base: bytes, gates=(0, 1)) -> dict:
    return _known(base, gates)


def _frame_for_fixture(fixture: dict, base: bytes, *, gates=(0, 1), state="known") -> dict:
    if state == "unknown":
        payload = end_state_wire.encode(base, {"state": "unknown"})
    else:
        payload = end_state_wire.encode(base, _snapshot(base, gates))
    return _fixture_with_payload(fixture, payload)


def _battle_source(tmp_path: Path, fixture: dict, *, observer: str,
                   observer_ref: str | None = None) -> BattleInformationSource:
    tmp_path.mkdir(parents=True, exist_ok=True)
    source, _primary, _adapted, _database, _payload = make_source(
        tmp_path,
        fixture=fixture,
        observer=observer,
        observer_ref=observer_ref,
        message_ids=("9",),
    )
    return source


def _raw_naval_base8() -> bytes:
    """Layer old codecs around the captured v3 naval fixture, unchanged."""
    base3 = bytes.fromhex(load_live_v3_fixture()["payload_hex"])
    assert v3_wire.decode(base3)["context"]["kind"] == 2
    # Version 4's existing fixture builder emits an absent BTXT block while
    # preserving the actual v3 naval payload byte-for-byte.
    from work.tests.test_information_battle_template_wire import frame as encode_v4

    base4 = encode_v4(base3, present=0)
    base5_body = struct.pack("<BBIQiQQB", 0, 2, 0, 0, 0, 0, 0, 0)
    base5 = (b"IBOW" + struct.pack("<HI", 5, len(base4)) + base4
             + b"WARI" + base5_body)
    unknown_v6 = {
        name: {"state": "unknown"}
        for name in ("definition_key", "auxiliary_text", "title_helper_candidate", "line1_text")
    }
    unknown_v6.update({"native_date": {"state": "unknown"},
                       "raw_flags": {"state": "unknown"}})
    base6 = v6_wire.encode(base5, unknown_v6)
    base7 = v7_wire.encode(base6, {"state": "unknown", "failure": 4})
    base8 = v8_wire.encode(base7, {"state": "unknown"})
    assert v8_wire.decode(base8)["context"]["kind"] == 2
    return base8


def _known_v9(base: bytes, gates=(0, 1)) -> bytes:
    return end_state_wire.encode(base, _known(base, gates))


def _fixture_with_payload(fixture: dict, payload: bytes) -> dict:
    adapted = deepcopy(fixture)
    adapted["payload_hex"] = payload.hex()
    decoded = end_state_wire.decode(payload)
    raw_date = decoded["observation"]["result"]["raw_date"]
    adapted["context_date"] = max(int(adapted["context_date"]), raw_date)
    return adapted


def _country_ref(tag: str) -> str:
    raw = tag.encode("ascii") + b"\0" * 5
    return f"{int.from_bytes(raw, 'little'):016x}"


def test_land_loser_gate_one_is_public_as_known_b03_annihilation(tmp_path):
    base7 = _base7()
    frame = _known_v9(base7, (0, 1))
    assert frame[10:10 + len(base7)] == base7
    source = _battle_source(
        tmp_path,
        _fixture_with_payload(load_fra_fixture(), frame),
        observer="FRA",
    )

    result = source.read(
        battle_topic_query("B03", ["annihilation"],
                           selected_event=event_id(load_fra_fixture(), "9")),
        source.context(),
    )

    annihilation = result["fields"]["annihilation"]
    assert result["source"]["name"] == "IBOW.v9"
    assert result["source"]["projection_version"] == 30
    assert annihilation["status"] == "known"
    assert annihilation["value"]["sides"][1]["participants"] == ["FRA"]
    assert annihilation["value"]["sides"][1]["annihilated"] == {
        "status": "known", "value": True,
    }


def test_land_clear_and_unknown_extension_do_not_assert_annihilation_and_keep_base_report(tmp_path):
    fixture = load_fra_fixture()
    base7 = _base7()

    clear_source = _battle_source(
        tmp_path / "clear",
        _fixture_with_payload(fixture, _known_v9(base7, (0, 0))),
        observer="FRA",
    )
    clear = clear_source.read(
        battle_topic_query("B03", ["annihilation"],
                           selected_event=event_id(fixture, "9")),
        clear_source.context(),
    )["fields"]["annihilation"]
    assert clear["status"] == "known"
    assert all(side["annihilated"] == {
        "status": "unknown", "reason": "NON_OVERRUN_ANNIHILATION_PATHS_UNRESOLVED",
    } for side in clear["value"]["sides"])
    assert all(side["annihilated"].get("value") is not False
               for side in clear["value"]["sides"])

    unknown_source = _battle_source(
        tmp_path / "unknown",
        _frame_for_fixture(fixture, base7, state="unknown"),
        observer="FRA",
    )
    base_report = unknown_source.read(
        battle_query(["name", "winner"], selected_event=event_id(fixture, "9")),
        unknown_source.context(),
    )
    unknown = unknown_source.read(
        battle_topic_query("B03", ["annihilation"],
                           selected_event=event_id(fixture, "9")),
        unknown_source.context(),
    )["fields"]["annihilation"]
    assert base_report["fields"]["name"]["status"] == "known"
    assert base_report["fields"]["winner"]["status"] == "known"
    assert unknown == {"status": "unknown", "reason": "BATTLE_END_STATE_NOT_CAPTURED"}


def test_naval_generic_marker_conflicting_with_legacy_navl_is_unknown(tmp_path):
    fixture = load_live_v3_fixture()
    base8 = _raw_naval_base8()
    # This captured v3/NAVL fixture has a raw gate of 1 on side 0.  The generic
    # v9 pair disagrees, so the consumer must withhold classification.
    base3 = bytes.fromhex(fixture["payload_hex"])
    old_naval = v3_wire.decode(base3)["naval"]["sides"]
    assert old_naval[0]["raw_gate"] == 1
    payload = _known_v9(base8, (0, 0))
    source = _battle_source(
        tmp_path,
        _fixture_with_payload(fixture, payload),
        observer="ATJ",
    )

    result = source.read(
        battle_topic_query("B03", ["annihilation"],
                           selected_event=event_id(fixture, "9")),
        source.context(),
    )

    assert result["fields"]["annihilation"] == {
        "status": "unknown", "reason": "BATTLE_END_STATE_NAVAL_MARKER_CONFLICT",
    }


def test_v9_decode_preserves_old_v7_v8_decodes_and_embedded_bytes():
    for base, legacy in ((_base7(), v7_wire.decode),
                         (_base8(), v8_wire.decode)):
        before = legacy(base)
        assert end_state_wire.decode(base) == before
        frame = _known_v9(base)
        decoded = end_state_wire.decode(frame)
        assert frame[10:10 + len(base)] == base
        assert all(decoded[key] == value for key, value in before.items())
        assert decoded["wire9"]["version"] == 9


def test_legacy_wire1_through8_dispatch_matches_v8_decoder():
    from work import information_battle_context_wire as v2_wire
    from work.tests.test_information_battle_native_text_wire import _v5_payload
    from work.tests.test_information_battle_template_wire import frame as encode_v4

    base2 = bytes.fromhex(load_fixture()["payload_hex"])
    base2_decoded = v2_wire.decode(base2)
    inner_v1_bytes = base2_decoded["wire"]["inner_v1_length"]
    base1 = base2[10:10 + inner_v1_bytes]
    base3 = bytes.fromhex(load_live_v3_fixture()["payload_hex"])
    base4 = encode_v4(base3, present=0)
    bases = [base1, base2, base3, base4, _v5_payload(),
             _v6_base(), _base7(), _base8()]

    assert [int.from_bytes(base[4:6], "little") for base in bases] == list(range(1, 9))
    for base in bases:
        assert end_state_wire.decode(base) == v8_wire.decode(base)


def test_v9_does_not_expand_event_access_to_nonparticipant_observer(tmp_path):
    fixture = load_fra_fixture()
    payload = _known_v9(_base7(), (0, 1))
    nonparticipant_ref = _country_ref("POR")
    source = _battle_source(
        tmp_path,
        _fixture_with_payload(fixture, payload),
        observer="POR",
        observer_ref=nonparticipant_ref,
    )

    result = source.read(
        battle_topic_query("B03", ["annihilation"],
                           selected_event=event_id(fixture, "9")),
        source.context(),
    )

    assert result["fields"]["annihilation"] == {
        "status": "unavailable", "reason": "BATTLE_RECORD_NOT_AVAILABLE_IN_OBSERVER_SCOPE",
    }
