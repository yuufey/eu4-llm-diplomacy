from __future__ import annotations

import json
from pathlib import Path

import bridge.map_live_capture as live


BASE = 0x10000000
WORLD = 0x20000000
BEGIN = 0x30000000
RECORDS = 0x40000000
BITSETS = 0x50000000
DATABASE = 0x60000000
COUNTRY_TABLE = 0x61000000
COUNTRY_RECORDS = 0x62000000
OBSERVER_SLOT = 1


class Memory:
    def __init__(self):
        self.values = {}
        self.reads = []

    def put(self, address, value, size, *, signed=False):
        self.values[address] = value.to_bytes(size, "little", signed=signed)

    def read(self, address, size, label):
        self.reads.append((address, size, label))
        raw = self.values[address]
        assert len(raw) == size
        return raw


def _fullref(tag, slot, *, high=1, byte48=0):
    return ((high << 56) | (byte48 << 48) | (slot << 32)
            | int.from_bytes(tag.encode("ascii") + b"\0", "little"))


def _memory():
    memory = Memory()
    refs = {
        "ABC": _fullref("ABC", OBSERVER_SLOT),
        "DEF": _fullref("DEF", 2),
        "GHI": _fullref("GHI", 3),
        # These exist in the table but fail the province-state fullref guards.
        "BAD": _fullref("BAD", 4, high=0),
        "JKL": _fullref("JKL", 5, byte48=7),
        "MNO": _fullref("MNO", 7),
    }
    memory.put(BASE + live._country.DATABASE_GLOBAL_RVA, DATABASE, 8)
    memory.put(DATABASE + live._country.DATABASE_TABLE_OFFSET, COUNTRY_TABLE, 8)
    memory.put(DATABASE + live._country.DATABASE_TABLE_COUNT_OFFSET, 8, 4, signed=True)
    tags_by_slot = {1: "ABC", 2: "DEF", 3: "GHI", 4: "BAD", 5: "JKL", 6: "MNO"}
    for slot in range(8):
        address = COUNTRY_RECORDS + slot * 0x1000 if slot in tags_by_slot else 0
        memory.put(COUNTRY_TABLE + slot * 8, address, 8)
        if address:
            memory.put(address + live._country.COUNTRY_FULLREF_OFFSET, refs[tags_by_slot[slot]], 8)
    memory.put(BASE + live._province_ref.PROVINCE_GLOBAL_RVA, WORLD, 8)
    memory.put(WORLD + live._province_ref.ARRAY_BEGIN_OFFSET, BEGIN, 8)
    memory.put(WORLD + live._province_ref.ARRAY_END_OFFSET, BEGIN + 10 * 8, 8)
    memory.put(WORLD + live._province_ref.RECORDS_POINTER_OFFSET, RECORDS, 8)
    samples = (
        (1, refs["DEF"], refs["GHI"]),
        (2, refs["DEF"], refs["DEF"]),
        (3, refs["DEF"], refs["GHI"] ^ (1 << 56)),
        (4, 0, refs["GHI"]),
        (5, None, None),  # undiscovered; no owner/controller bytes provided
        (6, refs["DEF"], refs["BAD"]),
        (7, refs["DEF"], refs["JKL"]),
        (8, refs["DEF"], refs["MNO"]),
        (9, refs["DEF"], 0),
    )
    for province_id, owner_ref, controller_ref in samples:
        record = RECORDS + province_id * live._province_ref.RECORD_STRIDE
        bitset = BITSETS + province_id * 0x1000
        memory.put(record + live._province_ref.RECORD_ID_OFFSET, province_id, 4, signed=True)
        memory.put(record + live._state.DISCOVERY_BITSET_POINTER_OFFSET, bitset, 8)
        memory.put(bitset, (1 << OBSERVER_SLOT) if owner_ref is not None else 0, 4)
        if owner_ref is not None:
            memory.put(record + live._state.OWNER_FULLREF_OFFSET, owner_ref, 8)
            memory.put(record + live._state.CONTROLLER_FULLREF_OFFSET, controller_ref, 8)
    return memory


def _installation(tmp_path: Path) -> Path:
    path = tmp_path / "installation.json"
    path.write_text(json.dumps({"pid": 42}), encoding="utf-8")
    return path


def test_request_is_bounded_and_rejects_duplicates(tmp_path):
    path = _installation(tmp_path)
    assert live._validate_request(path, "TUR", [1, 2])[2] == (1, 2)
    for values in ([1, 1], [], list(range(live.MAX_PROVINCES + 1))):
        try:
            live._validate_request(path, "TUR", values)
        except live.MapLiveCaptureError:
            pass
        else:
            raise AssertionError("invalid request was accepted")


def test_observe_many_keeps_known_and_unknown_owners(monkeypatch):
    contexts = [{"game_date": 100, "observer": "TUR"}, {"game_date": 100, "observer": "TUR"}]
    monkeypatch.setattr(live._owner, "_guards", lambda *args: [{"status": "known"}])
    monkeypatch.setattr(live._owner, "_context", lambda *args: contexts.pop(0))
    values = {1: {"discovered": True, "owner": "TUR", "controller": "TUR"},
              2: {"discovered": False, "owner": None, "controller": None}}
    monkeypatch.setattr(live, "_read_pass", lambda *args: {
        "status": "observed", "values": values, "raw_references": {1: (10, 10), 2: (None, None)}})
    result = live._observe_many(object(), 0x10000, "TUR", (1, 2), {})
    assert result["stable"] is True
    assert result["values"][1]["owner"] == "TUR"
    assert result["values"][2]["discovered"] is False


def test_read_pass_checks_discovery_and_canonical_references():
    memory = _memory()
    values = live._read_pass(memory, BASE, "ABC", tuple(range(1, 10)))["values"]
    assert values[1] == {"discovered": True, "owner": "DEF", "controller": "GHI"}
    assert values[2] == {"discovered": True, "owner": "DEF", "controller": "DEF"}
    assert values[3]["controller"] is None  # same tag but different generation bits
    assert values[4]["owner"] is None
    assert values[4]["controller"] == "GHI"
    assert values[5] == {"discovered": False, "owner": None, "controller": None}
    assert all(values[province_id]["controller"] is None for province_id in (6, 7, 8, 9))
    addresses = [address for address, _, _ in memory.reads]
    hidden = RECORDS + 5 * live._province_ref.RECORD_STRIDE
    assert hidden + live._state.OWNER_FULLREF_OFFSET not in addresses
    assert hidden + live._state.CONTROLLER_FULLREF_OFFSET not in addresses
    # Repeated country references reuse the proof in a pass.
    assert sum(label.endswith(".canonical_fullref") for _, _, label in memory.reads) == 2


def test_capture_live_projects_identity_and_timings(monkeypatch, tmp_path):
    path = _installation(tmp_path)
    monkeypatch.setattr(live._owner, "_capture_common", lambda *args, **kwargs: {
        "status": "observed", "completed": True,
        "identity": {"installation_pid": 42, "process_creation_filetime": 77},
        "request": {"session_id": "s", "pid": 42, "creation_filetime": 77},
        "observation": {"stable": True, "context_after": {"game_date": 56896992},
                        "values": {
                            1: {"discovered": True, "owner": "ABC", "controller": "DEF"},
                            2: {"discovered": True, "owner": "ABC", "controller": "ABC"},
                            3: {"discovered": True, "owner": None, "controller": "DEF"},
                            4: {"discovered": True, "owner": "ABC", "controller": None},
                            5: {"discovered": False, "owner": "ABC", "controller": "DEF"},
                            6: {"discovered": True, "owner": "ABC"},
                        }},
        "access": {"calls": 5, "bytes_requested": 120},
    })
    result = live.capture_live(path, "ABC", range(1, 7))
    assert result["date"] == "1495.2.3"
    assert result["owners"] == {1: "ABC", 2: "ABC", 3: None, 4: "ABC", 6: "ABC"}
    assert result["controllers"] == {1: "DEF"}
    assert result["identity"]["pid"] == 42
    assert result["timings"]["rpm_calls"] == 5


def test_controller_change_between_passes_rejects_snapshot(monkeypatch):
    passes = iter((
        {"values": {1: {"discovered": True, "owner": "ABC", "controller": "ABC"}},
         "raw_references": {1: (10, 10)}},
        {"values": {1: {"discovered": True, "owner": "ABC", "controller": "DEF"}},
         "raw_references": {1: (10, 11)}},
    ))
    monkeypatch.setattr(live._owner, "_context", lambda *_: {"game_date": 56896992})
    monkeypatch.setattr(live._owner, "_guards", lambda *_: [])
    monkeypatch.setattr(live, "_read_pass", lambda *_: next(passes))
    observation = live._observe_many(None, BASE, "ABC", (1,), {})
    assert observation["stable"] is False
    assert observation["values"] == {}


def test_fullref_change_with_identical_tags_rejects_snapshot(monkeypatch):
    value = {1: {"discovered": True, "owner": "ABC", "controller": "DEF"}}
    passes = iter((
        {"values": value, "raw_references": {1: (10, 11)}},
        {"values": value, "raw_references": {1: (10, 12)}},
    ))
    monkeypatch.setattr(live._owner, "_context", lambda *_: {"game_date": 56896992})
    monkeypatch.setattr(live._owner, "_guards", lambda *_: [])
    monkeypatch.setattr(live, "_read_pass", lambda *_: next(passes))
    assert not live._observe_many(None, BASE, "ABC", (1,), {})["stable"]


def test_date_change_with_identical_provinces_rejects_snapshot(monkeypatch):
    dates = iter((56896992, 56897016))
    monkeypatch.setattr(live._owner, "_context", lambda *_: {"game_date": next(dates)})
    monkeypatch.setattr(live._owner, "_guards", lambda *_: [])
    monkeypatch.setattr(live, "_read_pass", lambda *_: {
        "values": {1: {"owner": "TUR"}}, "raw_references": {1: (10, 10)}})
    assert not live._observe_many(None, 0, "TUR", (1,), {})["stable"]
