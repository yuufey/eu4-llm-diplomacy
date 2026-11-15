from __future__ import annotations

from copy import deepcopy
import gzip
import json
from pathlib import Path

import pytest

from bridge.information import trade_league_memory as memory


MODULE_BASE = 0x140000000
DATABASE = 0x210000000
TABLE = 0x210001000
FRA = 0x220000000
HSA = 0x220001000
RIG = 0x220002000
FRA_OBJECT = 0x230000000
HSA_OBJECT = 0x230001000
VECTOR = 0x230002000
GAME = 0x230003000


def _qword(value: int) -> bytes:
    return value.to_bytes(8, "little", signed=False)


def _i32(value: int) -> bytes:
    return (value & 0xFFFFFFFF).to_bytes(4, "little", signed=False)


def _fullref(tag: str, slot: int) -> bytes:
    return tag.encode("ascii") + b"\x00" + slot.to_bytes(2, "little") + b"\x00\x00"


class Reader:
    """Small bounded-memory seam; it never opens a process."""

    def __init__(self) -> None:
        self.segments: list[tuple[int, bytes]] = []
        self.reads: list[tuple[int, int, str]] = []

    def put(self, address: int, value: bytes) -> None:
        self.segments.append((address, bytes(value)))

    def read(self, address: int, size: int, label: str) -> bytes:
        self.reads.append((address, size, label))
        for start, value in reversed(self.segments):
            end = start + len(value)
            if start <= address and address + size <= end:
                offset = address - start
                return value[offset:offset + size]
        raise AssertionError(f"unexpected read: {label} {address:#x} {size}")


def _make_object(vtable: int, begin: int = 0, end: int = 0) -> bytes:
    value = bytearray(0x40)
    value[:8] = _qword(vtable)
    value[0x20:0x28] = _qword(begin)
    value[0x28:0x30] = _qword(end)
    return bytes(value)


def _build_reader(*, active_actor: bool = True, bad_member: bool = False) -> tuple[Reader, dict[str, int]]:
    reader = Reader()
    profile = memory._active_profile()
    layout = profile["_layout"]

    # The code guards are the only executable/static bytes consumed by the child.
    reader.put(MODULE_BASE + 0x8F450, bytes.fromhex("32c0c3"))
    reader.put(MODULE_BASE + 0x8F440, bytes.fromhex("b001c3"))
    reader.put(MODULE_BASE + 0x1C48548, _qword(MODULE_BASE + 0x8F450))
    reader.put(MODULE_BASE + 0x1CE8988, _qword(MODULE_BASE + 0x8F440))

    # Database and country table.  Index 0 is a deliberate null slot; fullref
    # slots of real countries match their table indexes.
    reader.put(MODULE_BASE + layout["database_global_rva"], _qword(DATABASE))
    reader.put(DATABASE + layout["table_offset"], _qword(TABLE))
    reader.put(DATABASE + layout["count_offset"], _i32(4))
    reader.put(TABLE, _qword(0) + _qword(FRA) + _qword(HSA) + _qword(RIG))
    reader.put(FRA + layout["fullref_offset"], _fullref("FRA", 1))
    reader.put(HSA + layout["fullref_offset"], _fullref("HSA", 2))
    reader.put(RIG + layout["fullref_offset"], _fullref("RIG", 3))

    # Game date is included so _capture_pass can be tested without a process.
    reader.put(MODULE_BASE + layout["game_global_rva"], _qword(GAME))
    reader.put(GAME + layout["game_date_offset"], _i32(56557728))

    null_vtable = MODULE_BASE + layout["null_vtable_rva"]
    active_vtable = MODULE_BASE + layout["active_vtable_rva"]
    reader.put(FRA + layout["trade_league_offset"], _qword(FRA_OBJECT))
    reader.put(HSA + layout["trade_league_offset"], _qword(HSA_OBJECT))
    reader.put(RIG + layout["trade_league_offset"], _qword(HSA_OBJECT))
    reader.put(FRA_OBJECT, _make_object(null_vtable))
    member_raw = _fullref("HSA", 2) + (_fullref("ZZZ", 5) if bad_member else _fullref("RIG", 3))
    reader.put(HSA_OBJECT, _make_object(active_vtable, VECTOR, VECTOR + len(member_raw)))
    reader.put(VECTOR, member_raw)
    return reader, {"FRA": FRA, "HSA": HSA, "RIG": RIG}


def _build_archived_raw_reader() -> tuple[Reader, dict[str, int], dict]:
    """Turn the self-contained archived raw fixture into a bounded seam."""
    path = Path("bridge/tests/fixtures/information_trade_league_live_1374.json.gz")
    with gzip.open(path, "rt", encoding="utf-8") as stream:
        raw = json.load(stream)
    assert raw["schema"] == "information_trade_league_raw_fixture.v1"
    module_base = int(raw["module_base"], 0)
    database_info = raw["database"]
    database = int(database_info["pointer"], 0)
    table = int(database_info["table_pointer"], 0)
    count = int(database_info["count"])
    reader = Reader()
    for guard in raw["code_guards"]:
        reader.put(module_base + int(guard["rva"], 0), bytes.fromhex(guard["raw_hex"]))

    profile = memory._active_profile()
    layout = profile["_layout"]
    reader.put(module_base + layout["database_global_rva"], _qword(database))
    reader.put(database + layout["table_offset"], _qword(table))
    reader.put(database + layout["count_offset"], _i32(count))
    pointer_array = bytearray(count * 8)
    pointers: dict[str, int] = {}
    for entry in database_info["entries"]:
        index = int(entry["index"])
        pointer_raw = bytes.fromhex(entry["country_pointer_raw_hex"])
        pointer_array[index * 8:(index + 1) * 8] = pointer_raw
        pointer = int.from_bytes(pointer_raw, "little")
        if entry.get("status") != "known_null_country_sentinel" and entry.get("tag"):
            pointers[entry["tag"]] = pointer
        if pointer:
            reader.put(pointer + layout["fullref_offset"], bytes.fromhex(entry["fullref_raw_hex"]))
    reader.put(table, bytes(pointer_array))

    game = int(raw["game"]["pointer"], 0)
    reader.put(module_base + layout["game_global_rva"], _qword(game))
    reader.put(game + layout["game_date_offset"], bytes.fromhex(raw["game"]["date_raw_hex"]))
    for country, obj in raw["countries"].items():
        pointer = int(obj["country_pointer"], 0)
        object_pointer = int.from_bytes(bytes.fromhex(obj["country_pointer_raw_hex"]), "little")
        reader.put(pointer + layout["trade_league_offset"], _qword(object_pointer))
        reader.put(object_pointer, bytes.fromhex(obj["object_prefix_raw_hex"]))
        vtable = int(obj["vtable_pointer"], 0)
        reader.put(vtable + layout["vtable_method_slot"], bytes.fromhex(obj["vtable_method_raw_hex"]))
        if obj["vector_count"]:
            reader.put(int(obj["vector_begin"], 0), bytes.fromhex(obj["vector_raw_hex"]))
    return reader, pointers, raw


def _build_archived_capture(actor: str) -> tuple[dict, dict, Reader, Reader]:
    before_reader, before_pointers, fixture = _build_archived_raw_reader()
    after_reader, after_pointers, _ = _build_archived_raw_reader()
    module_base = int(fixture["module_base"], 0)
    profile = memory._active_profile()
    before = memory._capture_pass(before_reader, module_base, profile, actor, None)
    after = memory._capture_pass(after_reader, module_base, profile, actor, None)
    report = memory._base_report(Path("archived-trade-league-fixture"), actor, None)
    report["probe_script_sha256"] = "offline-fixture-replay"
    report["static_contract_guard"] = memory._static_contract_guard(profile)
    report["file_code_guard"] = {
        "status": "observed", "path": "profile-pinned-static-guard",
        "checks": {item["name"]: True for item in profile["_guards"]},
        "records": {}, "unknown_conditions": [],
    }
    report["identity"].update({
        "installation_pid": fixture["identity"]["pid"],
        "installation_creation_filetime": fixture["identity"]["creation_filetime"],
        "installation_session_id": fixture["identity"]["session_id"],
        "process_path": "archived-exe-not-opened",
        "process_path_sha256": fixture["identity"]["process_path_sha256"],
        "process_path_sha256_matches_expected": True,
        "process_creation_filetime": fixture["identity"]["creation_filetime"],
        "process_creation_matches_installation": True,
        "module_path": "archived-exe-not-opened",
        "module_path_matches_process": True,
        "binding_verified": True,
    })
    report["module_base"] = hex(module_base)
    report["before"] = before
    report["after"] = after
    report["context_before"] = before["context"]
    report["context_after"] = after["context"]
    report["fields"] = deepcopy(after["fields"])
    report["doublepass"] = {"performed": True, "consistent": memory._stable(before) == memory._stable(after), "mismatches": []}
    report["runtime_code_guard"] = {"status": "observed", "passes": [
        before["actor_record"]["runtime_code_guard"], after["actor_record"]["runtime_code_guard"]
    ]}
    report["access"].update({
        "offline_replay": True,
        "rpm_bytes_requested": sum(size for _address, size, _label in before_reader.reads + after_reader.reads),
        "rpm_calls": len(before_reader.reads) + len(after_reader.reads),
    })
    report["cleanup"]["handle_close"] = {"status": "closed", "success": True, "closed": True, "offline_replay": True}
    report["status"] = "observed"
    report["completed"] = True
    assert before_pointers[actor] == after_pointers[actor]
    return report, fixture, before_reader, after_reader


def test_null_singleton_is_known_inactive_and_validates() -> None:
    reader, pointers = _build_reader(active_actor=False)
    record = memory.read_fields(reader, MODULE_BASE, pointers["FRA"])

    assert record["status"] == "observed"
    assert record["country"] == "FRA"
    assert record["predicate"] is False
    assert record["members"] == []
    assert record["fields"]["trade_league"]["value"] == []
    assert memory.validate_record(record)


def test_active_network_preserves_native_order_and_first_leader() -> None:
    reader, pointers = _build_reader()
    record = memory.read_fields(reader, MODULE_BASE, pointers["HSA"])

    assert record["status"] == "observed"
    assert [item["country"] for item in record["fields"]["trade_league"]["value"]] == ["HSA", "RIG"]
    assert record["first_leader"]["country"] == "HSA"
    assert record["league_leader"] == "HSA"
    assert memory.validate_record(record)

    changed = deepcopy(record)
    changed["members"][1]["country"] = "FRA"
    assert not memory.validate_record(changed)


def test_unmapped_member_is_unknown_and_never_empty_known() -> None:
    reader, pointers = _build_reader(bad_member=True)
    record = memory.read_fields(reader, MODULE_BASE, pointers["HSA"])

    assert record["status"] == "unknown"
    assert record["fields"]["trade_league"]["status"] == "unknown"
    assert record["fields"]["trade_league"]["value"] == []
    assert "member_fullref_unmapped" in record["reason"]


def test_pair_requires_same_active_object_and_returns_leader_metadata() -> None:
    reader, pointers = _build_reader()
    profile = memory._active_profile()

    pair = memory._capture_pass(reader, MODULE_BASE, profile, "HSA", "RIG")
    assert pair["status"] == "observed"
    assert pair["fields"]["trade_league"]["value"] is True
    assert pair["fields"]["trade_league"]["league_leader"] == "HSA"

    inactive = memory._capture_pass(reader, MODULE_BASE, profile, "FRA", "HSA")
    assert inactive["status"] == "observed"
    assert inactive["fields"]["trade_league"]["value"] is False
    assert inactive["fields"]["trade_league"]["league_leader"] is None


def test_runtime_guard_rejects_before_country_table_read() -> None:
    reader, pointers = _build_reader()
    reader.put(MODULE_BASE + 0x8F440, b"\x90\x90\xc3")
    record = memory.read_fields(reader, MODULE_BASE, pointers["FRA"])

    assert record["status"] == "unknown"
    assert "runtime_code_guard_failed" in record["reason"]
    assert not any("country_table" in label for _address, _size, label in reader.reads)


def test_retract_removes_known_value() -> None:
    reader, pointers = _build_reader()
    record = memory.read_fields(reader, MODULE_BASE, pointers["HSA"])
    retracted = memory.retract_record(record, "context_changed")

    assert retracted["status"] == "unknown"
    assert retracted["completed"] is False
    assert retracted["fields"]["trade_league"]["status"] == "unknown"
    assert retracted["fields"]["trade_league"]["reason"] == "context_changed"


def test_profile_failure_happens_before_reader_use(monkeypatch: pytest.MonkeyPatch) -> None:
    reader, pointers = _build_reader()

    def reject() -> dict:
        raise memory.ProfileError("profile rejected")

    monkeypatch.setattr(memory, "_active_profile", reject)
    record = memory.read_fields(reader, MODULE_BASE, pointers["FRA"])
    assert record["status"] == "unknown"
    assert reader.reads == []


def test_archived_raw004_replays_fra_and_hsa_without_public_values() -> None:
    reader, pointers, raw = _build_archived_raw_reader()

    module_base = int(raw["module_base"], 0)
    fra = memory.read_fields(reader, module_base, pointers["FRA"])
    hsa = memory.read_fields(reader, module_base, pointers["HSA"])
    assert fra["status"] == "observed" and fra["predicate"] is False
    assert hsa["status"] == "observed" and hsa["predicate"] is True
    assert [item["country"] for item in hsa["members"]] == ["HSA", "RIG", "OLD", "BRE", "HAM"]
    assert memory.validate_record(fra) and memory.validate_record(hsa)

    changed = deepcopy(hsa)
    changed["object"]["vector_raw_hex"] = changed["object"]["vector_raw_hex"][:-2] + "00"
    assert not memory.validate_record(changed)


@pytest.mark.parametrize(
    ("actor", "expected_partners"),
    [("FRA", []), ("HSA", ["RIG", "OLD", "BRE", "HAM"])],
)
def test_archived_fixture_capture_validator_closes_identity_context_and_cleanup(
    actor: str, expected_partners: list[str]
) -> None:
    report, fixture, _before_reader, _after_reader = _build_archived_capture(actor)
    context = {
        "session_id": fixture["identity"]["session_id"],
        "process_creation_filetime": fixture["identity"]["creation_filetime"],
        "game_date": fixture["identity"]["game_date"],
    }

    assert memory.validate_capture(
        report, context, fixture["identity"]["creation_filetime"], actor, None
    )
    assert report["completed"] is True
    assert report["cleanup"]["handle_close"]["closed"] is True
    assert report["doublepass"] == {"performed": True, "consistent": True, "mismatches": []}
    assert report["identity"]["binding_verified"] is True
    partners = [item["country"] for item in report["fields"]["trade_league"]["value"]]
    assert partners == expected_partners
    # The native vector contains HSA exactly once; public network output omits
    # that one self occurrence rather than treating it as a second partner.
    if actor == "HSA":
        assert sum(item["country"] == "HSA" for item in report["before"]["actor_record"]["members"]) == 1
        assert all(item["country"] != "HSA" for item in report["fields"]["trade_league"]["value"])


def test_archived_fixture_vector_conflict_retracts_to_unknown_not_false() -> None:
    report, fixture, _before_reader, after_reader = _build_archived_capture("HSA")
    module_base = int(fixture["module_base"], 0)
    hsa = fixture["countries"]["HSA"]
    vector_address = int(hsa["vector_begin"], 0)
    # Keep the object active and same, but make the second pass duplicate HSA
    # in the native vector.  This is an invalid observation, not pair=false.
    vector = bytearray(bytes.fromhex(hsa["vector_raw_hex"]))
    vector[-8:] = vector[:8]
    after_reader.put(vector_address, bytes(vector))
    after = memory._capture_pass(after_reader, module_base, memory._active_profile(), "HSA", None)

    assert after["status"] == "unknown"
    assert after["fields"]["trade_league"]["status"] == "unknown"
    assert after["fields"]["trade_league"]["value"] == []
    assert report["fields"]["trade_league"]["status"] == "known"


def test_pair_vector_conflict_is_unknown_before_projection(monkeypatch: pytest.MonkeyPatch) -> None:
    reader, pointers = _build_reader()
    actor = deepcopy(memory.read_fields(reader, MODULE_BASE, pointers["HSA"], recipient="RIG"))
    recipient = deepcopy(memory.read_fields(reader, MODULE_BASE, pointers["RIG"], recipient="RIG"))
    # Keep the same native object but model an inconsistent second vector
    # observation.  The capture path must retract to unknown before it can
    # turn the mismatch into a pair=false value.
    recipient["object"]["vector_raw_hex"] = "00" * 16
    records = iter((actor, recipient))
    monkeypatch.setattr(memory, "_read_game_date", lambda *args: {"game_date": "56557728"})
    monkeypatch.setattr(memory, "_find_country_pointer", lambda *args: pointers["HSA"])
    monkeypatch.setattr(memory, "read_fields", lambda *args, **kwargs: next(records))
    monkeypatch.setattr(memory, "validate_record", lambda record: True)

    result = memory._capture_pass(reader, MODULE_BASE, memory._active_profile(), "HSA", "RIG")

    assert result["status"] == "unknown"
    assert result["fields"]["trade_league"]["status"] == "unknown"
    assert result["fields"]["trade_league"]["reason"] == "TRADE_LEAGUE_VECTOR_IDENTITY_MISMATCH"


def test_pair_validator_rejects_shared_object_vector_mismatch(monkeypatch: pytest.MonkeyPatch) -> None:
    report, fixture, _before_reader, _after_reader = _build_archived_capture("HSA")
    before_reader, _ = _build_reader()
    after_reader, _ = _build_reader()
    profile = memory._active_profile()
    report["request"]["recipient"] = "RIG"
    report["before"] = memory._capture_pass(before_reader, MODULE_BASE, profile, "HSA", "RIG")
    report["after"] = memory._capture_pass(after_reader, MODULE_BASE, profile, "HSA", "RIG")
    report["context_before"] = report["before"]["context"]
    report["context_after"] = report["after"]["context"]
    report["fields"] = deepcopy(report["after"]["fields"])
    report["doublepass"] = {"performed": True, "consistent": True, "mismatches": []}
    # Keep both records otherwise acceptable, but make the recipient's vector
    # disagree with the actor's shared object and recompute the candidate
    # known-false projection.  The validator must reject this forged result.
    for pass_report in (report["before"], report["after"]):
        pass_report["recipient_record"]["object"]["vector_raw_hex"] = "00" * 16
        field = pass_report["fields"]["trade_league"]
        field["value"] = False
        field["league_leader"] = None
        field["raw"]["same_vector"] = False
    report["fields"] = deepcopy(report["after"]["fields"])
    monkeypatch.setattr(memory, "validate_record", lambda record: True)

    assert not memory.validate_capture(
        report,
        {"session_id": fixture["identity"]["session_id"],
         "process_creation_filetime": fixture["identity"]["creation_filetime"],
         "game_date": fixture["identity"]["game_date"]},
        fixture["identity"]["creation_filetime"],
        "HSA", "RIG",
    )
