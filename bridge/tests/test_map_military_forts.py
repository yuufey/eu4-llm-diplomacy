from __future__ import annotations

from copy import deepcopy
import json

import pytest

import bridge.map_military_forts as forts


BASE = 0x10000000
WORLD = 0x20000000
BEGIN = 0x30000000
RECORDS = 0x40000000
BITSETS = 0x50000000
SLOT = 35
DATABASE = 0x60000000
COUNTRY_TABLE = 0x61000000
COUNTRY_RECORDS = 0x62000000


class Memory:
    def __init__(self):
        self.memory = {}
        self.reads = []

    def put(self, address, value, size, signed=False):
        self.memory[address] = value.to_bytes(size, "little", signed=signed)

    def read(self, address, size, label):
        self.reads.append((address, size, label))
        value = self.memory[address]
        assert len(value) == size
        return value


def _memory():
    memory = Memory()
    memory.put(BASE + forts._province.PROVINCE_GLOBAL_RVA, WORLD, 8)
    memory.put(WORLD + forts._province.ARRAY_BEGIN_OFFSET, BEGIN, 8)
    memory.put(WORLD + forts._province.ARRAY_END_OFFSET, BEGIN + 8 * 50, 8)
    memory.put(WORLD + forts._province.RECORDS_POINTER_OFFSET, RECORDS, 8)
    for province_id, discovered, level in ((1, True, 3), (2, False, 6), (3, True, -1)):
        record = RECORDS + province_id * forts._province.RECORD_STRIDE
        bitset = BITSETS + province_id * 0x1000
        memory.put(record + forts._province.RECORD_ID_OFFSET, province_id, 4, signed=True)
        memory.put(record + forts._state.DISCOVERY_BITSET_POINTER_OFFSET, bitset, 8)
        memory.put(bitset + (SLOT >> 5) * 4, (1 << (SLOT & 31)) if discovered else 0, 4)
        memory.put(record + forts._fort.PROVINCE_FORT_LEVEL_OFFSET, level, 4, signed=True)
    return memory


def _fullref(tag, slot):
    return (1 << 56) | (slot << 32) | int.from_bytes(tag.encode("ascii") + b"\0", "little")


def _scoped_memory():
    memory = _memory()
    refs = {tag: _fullref(tag, slot) for tag, slot in (("TUR", SLOT), ("ENG", 7), ("FRA", 9))}
    memory.put(BASE + forts._country.DATABASE_GLOBAL_RVA, DATABASE, 8)
    memory.put(DATABASE + forts._country.DATABASE_TABLE_OFFSET, COUNTRY_TABLE, 8)
    memory.put(DATABASE + forts._country.DATABASE_TABLE_COUNT_OFFSET, SLOT + 1, 4, signed=True)
    slots = {SLOT: refs["TUR"], 7: refs["ENG"], 9: refs["FRA"]}
    for slot in range(SLOT + 1):
        country_record = COUNTRY_RECORDS + slot * 0x1000 if slot in slots else 0
        memory.put(COUNTRY_TABLE + slot * 8, country_record, 8)
        if country_record:
            memory.put(country_record + forts._country.COUNTRY_FULLREF_OFFSET, slots[slot], 8)
    for province_id, owner, level in ((1, refs["TUR"], 3), (3, refs["ENG"], -1),
                                      (4, refs["FRA"], 6),
                                      (5, refs["TUR"] ^ (1 << 56), 7), (6, 0, 8)):
        record = RECORDS + province_id * forts._province.RECORD_STRIDE
        bitset = BITSETS + province_id * 0x1000
        memory.put(record + forts._province.RECORD_ID_OFFSET, province_id, 4, signed=True)
        memory.put(record + forts._state.DISCOVERY_BITSET_POINTER_OFFSET, bitset, 8)
        memory.put(bitset + (SLOT >> 5) * 4, 1 << (SLOT & 31), 4)
        memory.put(record + forts._state.OWNER_FULLREF_OFFSET, owner, 8)
        memory.put(record + forts._fort.PROVINCE_FORT_LEVEL_OFFSET, level, 4, signed=True)
    return memory, refs


def _admit_scoped(monkeypatch):
    def admission(_read, _base, countries, observer, _target):
        binding = countries["requested"][observer]
        return {"status": "known", "admitted": True,
                "observer": {"tag": observer, "binding": binding}}
    monkeypatch.setattr(forts._owner, "_bound_admission", admission)


@pytest.fixture
def admitted(monkeypatch):
    binding = {"tag": "TUR", "slot": SLOT, "fullref_raw_hex": "1234567890abcdef"}
    monkeypatch.setattr(forts._country, "resolve_countries", lambda *a: {
        "status": "observed", "requested": {"TUR": binding}})
    monkeypatch.setattr(forts._owner, "_bound_admission", lambda *a: {
        "status": "known", "admitted": True,
        "observer": {"tag": "TUR", "binding": binding}})


def test_live_pass_reads_forts_only_after_discovery(admitted):
    memory = _memory()
    result = forts._read_pass(memory, BASE, "TUR", (1, 2, 3))
    assert [result["values"][i]["level"] for i in (1, 2, 3)] == [3, None, -1]
    addresses = [address for address, _, _ in memory.reads]
    hidden_level = RECORDS + 2 * forts._province.RECORD_STRIDE + forts._fort.PROVINCE_FORT_LEVEL_OFFSET
    assert hidden_level not in addresses


def test_self_admission_failure_precedes_fort_reads(admitted, monkeypatch):
    memory = _memory()
    monkeypatch.setattr(forts._owner, "_bound_admission", lambda *a: {
        "status": "known", "admitted": False})
    with pytest.raises(forts.FortCaptureError, match="SELF_ADMISSION"):
        forts._read_pass(memory, BASE, "TUR", (1,))
    assert memory.reads == []


def test_discovery_or_binding_failure_rejects_batch(admitted):
    memory = _memory()
    record = RECORDS + forts._province.RECORD_STRIDE
    memory.put(record + forts._state.DISCOVERY_BITSET_POINTER_OFFSET, 0, 8)
    with pytest.raises(forts.FortCaptureError, match="DISCOVERY"):
        forts._read_pass(memory, BASE, "TUR", (1,))
    memory = _memory()
    memory.put(record + forts._province.RECORD_ID_OFFSET, 2, 4, signed=True)
    with pytest.raises(forts.FortCaptureError, match="RESOLUTION"):
        forts._read_pass(memory, BASE, "TUR", (1,))


def test_two_pass_field_or_context_drift_is_not_exported(monkeypatch):
    first = {"values": {1: {"level": 1}}}
    second = {"values": {1: {"level": 2}}}
    passes = iter((first, second))
    monkeypatch.setattr(forts._owner, "_guards", lambda *a: [{"matches": True}])
    monkeypatch.setattr(forts._owner, "_context", lambda *a: {"game_date": 123})
    monkeypatch.setattr(forts, "_read_pass", lambda *a: next(passes))
    result = forts._observe_many(None, BASE, "TUR", (1,), {})
    assert result["stable"] is False
    assert result["values"] == {}

    contexts = iter(({"game_date": 123}, {"game_date": 124}))
    monkeypatch.setattr(forts._owner, "_context", lambda *a: next(contexts))
    monkeypatch.setattr(forts, "_read_pass", lambda *a: deepcopy(first))
    assert not forts._observe_many(None, BASE, "TUR", (1,), {})["stable"]


def test_scoped_pass_checks_current_canonical_owner_before_level(monkeypatch):
    _admit_scoped(monkeypatch)
    memory, _ = _scoped_memory()
    result = forts._read_pass(memory, BASE, "TUR", (1, 2, 3, 4, 5, 6), ("ENG", "TUR"))
    assert [result["values"][i]["level"] for i in (1, 2, 3, 4, 5, 6)] == [3, None, -1, None, None, None]
    assert [result["values"][i].get("owner") for i in (1, 3, 4, 5, 6)] == ["TUR", "ENG", None, None, None]
    reads = [address for address, _, _ in memory.reads]
    for province_id in (2, 4, 5, 6):
        record = RECORDS + province_id * forts._province.RECORD_STRIDE
        assert record + forts._fort.PROVINCE_FORT_LEVEL_OFFSET not in reads
    assert RECORDS + 2 * forts._province.RECORD_STRIDE + forts._state.OWNER_FULLREF_OFFSET not in reads
    for province_id in (1, 3):
        record = RECORDS + province_id * forts._province.RECORD_STRIDE
        assert reads.index(record + forts._state.OWNER_FULLREF_OFFSET) < reads.index(
            record + forts._fort.PROVINCE_FORT_LEVEL_OFFSET)


def test_scoped_owner_change_between_passes_is_rejected(monkeypatch):
    _admit_scoped(monkeypatch)
    memory, refs = _scoped_memory()
    owner_address = RECORDS + forts._province.RECORD_STRIDE + forts._state.OWNER_FULLREF_OFFSET
    original_read = memory.read
    seen = 0
    def changing_read(address, size, label):
        nonlocal seen
        if address == owner_address:
            seen += 1
            if seen == 2:
                memory.put(address, refs["FRA"], 8)
        return original_read(address, size, label)
    memory.read = changing_read
    monkeypatch.setattr(forts._owner, "_guards", lambda *a: [])
    monkeypatch.setattr(forts._owner, "_context", lambda *a: {"game_date": 56896992})
    result = forts._observe_many(memory, BASE, "TUR", (1,), {}, ("TUR",))
    assert not result["stable"]
    assert result["values"] == {}
    level_address = RECORDS + forts._province.RECORD_STRIDE + forts._fort.PROVINCE_FORT_LEVEL_OFFSET
    assert [address for address, _, _ in memory.reads].count(level_address) == 1


def test_scoped_participant_requires_current_canonical_reference(monkeypatch):
    _admit_scoped(monkeypatch)
    memory, refs = _scoped_memory()
    reference_address = COUNTRY_RECORDS + SLOT * 0x1000 + forts._country.COUNTRY_FULLREF_OFFSET
    original_read = memory.read
    seen = 0
    def changing_read(address, size, label):
        nonlocal seen
        if address == reference_address:
            seen += 1
            if seen == 2:
                memory.put(address, refs["TUR"] ^ (1 << 56), 8)
        return original_read(address, size, label)
    memory.read = changing_read
    with pytest.raises(forts.FortCaptureError, match="PARTICIPANT_BINDING"):
        forts._read_pass(memory, BASE, "TUR", (1,), ("TUR",))
    assert not any(label == forts._fort.READ_LABEL for _, _, label in memory.reads)


def test_scoped_public_capture_omits_foreign_stale_and_unknown_owners(monkeypatch, tmp_path):
    _admit_scoped(monkeypatch)
    memory, _ = _scoped_memory()
    path = tmp_path / "installation.json"
    path.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(forts._owner, "_guards", lambda *a: [])
    monkeypatch.setattr(forts._owner, "_context", lambda *a: {"game_date": 56896992})
    def capture(_path, _observer, *, observe, **_kwargs):
        return {"status": "observed", "completed": True,
                "request": {"pid": 42, "creation_filetime": 99, "session_id": "s"},
                "observation": observe(memory, BASE, "TUR", {})}
    monkeypatch.setattr(forts._owner, "_capture_common", capture)
    monkeypatch.setattr(forts, "_terrain_overrides", lambda *a: ({}, {"status": "unavailable"}))
    result = forts.capture_forts(path, "TUR", [1, 2, 3, 4, 5, 6],
                                 participants=(tag for tag in ("TUR", "ENG")))
    assert result["status"] == "partial"
    assert result["records"] == [{"province_id": 1, "level": 3, "owner": "TUR"},
                                 {"province_id": 3, "level": -1, "owner": "ENG"}]
    assert result["field_metadata"]["level"]["scope"] == "discovered_provinces_owned_by_participants"
    assert forts.capture_forts(path, "TUR", [1, 4], participants=[])['records'] == []


@pytest.mark.parametrize("participants", ["TUR", ["tur"], ["TOOLONG"], [1], {"TUR": True}])
def test_invalid_participants_are_rejected_before_capture(monkeypatch, tmp_path, participants):
    path = tmp_path / "installation.json"
    path.write_text("{}", encoding="utf-8")
    def unexpected_capture(*args, **kwargs):
        pytest.fail("invalid participants must not start a capture")
    monkeypatch.setattr(forts._owner, "_capture_common", unexpected_capture)
    with pytest.raises(forts.FortCaptureError, match="PARTICIPANTS_INVALID"):
        forts.capture_forts(path, "TUR", [1], participants=participants)


def test_public_capture_exports_zero_but_omits_undiscovered(monkeypatch, tmp_path):
    path = tmp_path / "installation.json"
    path.write_text(json.dumps({"pid": 42}), encoding="utf-8")
    report = {
        "status": "observed", "completed": True,
        "request": {"pid": 42, "creation_filetime": 99, "session_id": "s"},
        "observation": {"stable": True, "context_after": {"game_date": 56896992, "world_pointer": "0x20000000"},
                        "values": {1: {"discovery": {"value": True}, "level": 0},
                                   2: {"discovery": {"value": False}, "level": None}}},
    }
    monkeypatch.setattr(forts._owner, "_capture_common", lambda *a, **k: report)
    monkeypatch.setattr(forts, "_terrain_overrides", lambda *a: ({}, {"status": "unavailable"}))
    result = forts.capture_forts(path, "TUR", [1, 2])
    assert result["status"] == "partial"
    assert result["date"] == "1495.2.3"
    assert result["identity"] == {"pid": 42, "creation_filetime": 99, "session_id": "s"}
    assert result["world_token"] == forts._map._world_token(report["observation"]["context_after"])
    assert result["records"] == [{"province_id": 1, "level": 0}]
    assert result["field_metadata"]["level"]["complete"] is False
    assert result["field_metadata"]["level"]["status"] == "known"

    report["observation"]["stable"] = False
    assert forts.capture_forts(path, "TUR", [1, 2])["status"] == "unavailable"


def test_invalid_or_duplicate_request_is_rejected(tmp_path):
    path = tmp_path / "installation.json"
    path.write_text("{}", encoding="utf-8")
    with pytest.raises(forts._map.MapLiveCaptureError):
        forts.capture_forts(path, "TUR", [1, 1])


def test_explicit_terrain_only_and_conflicting_overrides_are_omitted():
    raw = b"""categories = {
        woods = { defence = 1 terrain_override = { 1 2 } }
        farmlands = { type = plains terrain_override = { 3 } }
        mountains = { defence = 2 terrain_override = { 2 4 } }
    }"""
    assert forts._parse_terrain_overrides(raw) == {
        1: {"terrain": "woods", "terrain_bonus": 1},
        3: {"terrain": "farmlands"},
        4: {"terrain": "mountains", "terrain_bonus": 2},
    }
    cached = forts._parse_terrain_overrides(raw)
    with pytest.raises(TypeError):
        cached[1]["terrain_bonus"] = 9
    assert forts._parse_terrain_overrides(raw) is cached


def test_effective_terrain_file_uses_enabled_mod_overlay(tmp_path):
    game = tmp_path / "game"
    user = tmp_path / "user"
    map_dir = game / "map"
    map_dir.mkdir(parents=True)
    (game / "launcher-settings.json").write_text('{"rawVersion":"v1.37.4.0"}', encoding="utf-8")
    (map_dir / "default.map").write_text(
        'definitions="definition.csv"\nadjacencies="adjacencies.csv"\n'
        'terrain_definition="terrain.txt"\n', encoding="utf-8")
    (map_dir / "definition.csv").write_text(
        'province;red;green;blue;name\n0;0;0;0;none\n1;1;0;0;one\n', encoding="utf-8")
    (map_dir / "adjacencies.csv").write_text(
        'From;To;Type;Through;start_x;start_y;stop_x;stop_y;Comment\n', encoding="utf-8")
    (map_dir / "terrain.txt").write_text(
        'categories={woods={defence=1 terrain_override={1}}}', encoding="utf-8")
    mod_map = user / "mod" / "overlay" / "map"
    mod_map.mkdir(parents=True)
    (mod_map / "terrain.txt").write_text(
        'categories={mountain={defence=2 terrain_override={1}}}', encoding="utf-8")
    descriptor = user / "mod" / "overlay.mod"
    mod_path = (user / "mod" / "overlay").as_posix()
    descriptor.write_text(f'name="overlay"\npath="{mod_path}"\n', encoding="utf-8")
    (user / "dlc_load.json").write_text('{"enabled_mods":["mod/overlay.mod"]}', encoding="utf-8")
    result, metadata = forts._terrain_overrides(game, user)
    assert result == {1: {"terrain": "mountain", "terrain_bonus": 2}}
    assert metadata["status"] == "partial"
    assert metadata["basis"] == forts.TERRAIN_BASIS
    cache_info = forts._parse_terrain_overrides.cache_info()
    forts._terrain_overrides(game, user)
    assert forts._parse_terrain_overrides.cache_info().hits == cache_info.hits + 1
    (mod_map / "terrain.txt").write_text(
        'categories={hills={defence=1 terrain_override={1}}}', encoding="utf-8")
    changed, new_metadata = forts._terrain_overrides(game, user)
    assert changed == {1: {"terrain": "hills", "terrain_bonus": 1}}
    assert new_metadata["terrain_definition_sha256"] != metadata["terrain_definition_sha256"]
