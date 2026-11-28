"""Tests for own-army scope, location binding, and unstable captures."""
from copy import deepcopy

from bridge import map_military_armies as army


BASE = 0x140000000
WORLD = 0x2100000
PROVINCES = 0x3000000
BEGIN = 0x2000000
LAND = 0x5000000
NAVY = 0x5001000
UNKNOWN = 0x5002000


class Memory:
    def __init__(self):
        self.data = {}

    def put(self, address, value, size):
        for index, byte in enumerate(value.to_bytes(size, "little")):
            self.data[address + index] = byte

    def put_bytes(self, address, value):
        for index, byte in enumerate(value):
            self.data[address + index] = byte

    def read(self, address, size, label):
        return bytes(self.data[address + index] for index in range(size))


def fixture(monkeypatch, *, location=123, unknown=False):
    mem = Memory()
    mem.put(BASE + army._provinces.PROVINCE_GLOBAL_RVA, WORLD, 8)
    mem.put(WORLD + army._provinces.ARRAY_BEGIN_OFFSET, BEGIN, 8)
    mem.put(WORLD + army._provinces.ARRAY_END_OFFSET, BEGIN + 500 * 8, 8)
    mem.put(WORLD + army._provinces.RECORDS_POINTER_OFFSET, PROVINCES, 8)
    for vtable, v80, v88 in ((army._LAND_VTABLE_RVA, 0x8F440, 0x8F450),
                             (army._NAVAL_VTABLE_RVA, 0x8F450, 0x8F440)):
        mem.put(BASE + vtable + 0x80, BASE + v80, 8)
        mem.put(BASE + vtable + 0x88, BASE + v88, 8)
    mem.put_bytes(BASE + 0x8F440, bytes.fromhex("b001c3"))
    mem.put_bytes(BASE + 0x8F450, bytes.fromhex("32c0c3"))
    mem.put_bytes(BASE + army._LOCATION_CODE_RVA, army._LOCATION_CODE)
    mem.put(LAND, BASE + army._LAND_VTABLE_RVA, 8)
    mem.put(NAVY, BASE + army._NAVAL_VTABLE_RVA, 8)
    mem.put(LAND + army._GROUP_LOCATION_OFFSET,
            PROVINCES + location * army._provinces.RECORD_STRIDE, 8)
    mem.put(PROVINCES + location * army._provinces.RECORD_STRIDE + 0x20, location, 4)
    groups = [{"group_object": hex(LAND)}, {"group_object": hex(NAVY)}]
    records = [{"group_index": 0, "type_kind": 0, "strength_raw": 900},
               {"group_index": 0, "type_kind": 2, "strength_raw": 750},
               {"group_index": 1, "type_kind": 4, "strength_raw": 1000}]
    if unknown:
        mem.put(UNKNOWN, BASE + 0x1000, 8)
        groups.append({"group_object": hex(UNKNOWN)})
    monkeypatch.setattr(army._forces, "_find_country", lambda *args: (0x6000000, {"tag": "ABC"}))
    monkeypatch.setattr(army._forces, "_read_force_chain",
                        lambda *args: {"groups": deepcopy(groups), "records": deepcopy(records)})
    return mem


def test_filters_requested_provinces_and_never_projects_navy(monkeypatch):
    mem = fixture(monkeypatch, unknown=True)
    result = army._read_pass(mem, BASE, "ABC", frozenset({123}), {}, object())
    assert result["records"] == [{"province_id": 123, "owner": "ABC",
                                  "men": 1650, "relation": "own"}]
    assert result["omissions"] == ["UNRECOGNIZED_OWN_GROUP_TYPE"]
    assert army._read_pass(mem, BASE, "ABC", frozenset({124}), {}, object())["records"] == []


def test_unresolvable_location_is_omitted(monkeypatch):
    mem = fixture(monkeypatch)
    mem.put(LAND + army._GROUP_LOCATION_OFFSET, PROVINCES + 1, 8)
    result = army._read_pass(mem, BASE, "ABC", frozenset({123}), {}, object())
    assert result["records"] == []
    assert result["omissions"] == ["OWN_GROUP_LOCATION_UNAVAILABLE"]


def test_changed_own_armies_in_same_date_are_retracted(monkeypatch):
    first = {"records": [{"men": 1000}], "omissions": []}
    second = {"records": [{"men": 2000}], "omissions": []}
    passes = iter((first, second))
    monkeypatch.setattr(army._forces, "_load_profile", lambda: {})
    monkeypatch.setattr(army._forces, "_runtime_code_guard", lambda *args: {"status": "observed"})
    monkeypatch.setattr(army._owner, "_context", lambda *args: {"game_date": 123})
    monkeypatch.setattr(army._owner, "_guards", lambda *args: ["ok"])
    monkeypatch.setattr(army, "_read_pass", lambda *args: next(passes))
    result = army._observe(None, BASE, "ABC", frozenset({123}), {})
    assert result["stable"] is False
    assert result["records"] == []


def test_public_result_carries_date_world_identity_and_foreign_gap(monkeypatch, tmp_path):
    installation = tmp_path / "installation.json"
    installation.touch()
    context = {"game_date": 56896992, "world_pointer": "0x2100000"}
    monkeypatch.setattr(army._owner, "_capture_common", lambda *args, **kwargs: {
        "status": "observed", "completed": True,
        "request": {"pid": 1, "creation_filetime": 2, "session_id": "session"},
        "observation": {"stable": True, "context_after": context,
                        "records": [{"province_id": 123, "owner": "ABC", "men": 1650, "relation": "own"}],
                        "omissions": []}, "access": {}})
    result = army.capture_armies(installation, "ABC", [123])
    assert result["status"] == "partial"
    assert result["date"] == "1495.2.3"
    assert result["date_raw"] == 56896992
    assert result["world_token"] == army._map._world_token(context)
    assert result["identity"] == {"pid": 1, "creation_filetime": 2, "session_id": "session"}
    assert result["gaps"] == ["FOREIGN_ARMY_VISIBILITY_UNVERIFIED"]


def test_capture_failure_never_exposes_previous_or_partial_records(monkeypatch, tmp_path):
    installation = tmp_path / "installation.json"
    installation.touch()
    monkeypatch.setattr(army._owner, "_capture_common", lambda *args, **kwargs: {
        "status": "unknown", "completed": False, "errors": [{"reason": "changed"}],
        "observation": {"records": [{"men": 1000}]}})
    result = army.capture_armies(installation, "ABC", [123])
    assert result["status"] == "unavailable"
    assert result["records"] == []
    assert result["reason"] == "changed"
