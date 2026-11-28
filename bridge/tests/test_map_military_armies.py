"""Tests for army scope, location binding, and unstable captures."""
from copy import deepcopy

import pytest

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
        self.reads = []

    def put(self, address, value, size):
        for index, byte in enumerate(value.to_bytes(size, "little")):
            self.data[address + index] = byte

    def put_bytes(self, address, value):
        for index, byte in enumerate(value):
            self.data[address + index] = byte

    def read(self, address, size, label):
        self.reads.append(label)
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


def test_scoped_country_lookup_resolves_all_sides_in_one_table_scan(monkeypatch):
    mem = Memory()
    database, table = 0x7000000, 0x7100000
    layout = {"pointer_min": 0x10000, "pointer_max": 0x7FFFFFFFFFFF,
              "database_global_rva": 0x70, "database_table_offset": 8,
              "database_table_count_offset": 16, "database_max_slots": 16,
              "country_fullref_offset": 0x20}
    monkeypatch.setattr(army._forces, "_profile_layout", lambda profile: layout)
    mem.put(BASE + 0x70, database, 8)
    mem.put(database + 8, table, 8)
    mem.put(database + 16, 4, 4)
    mem.put(table, 0, 8)
    for slot, tag in enumerate(("ABC", "DEF", "GHI"), start=1):
        pointer = 0x7200000 + slot * 0x1000
        mem.put(table + slot * 8, pointer, 8)
        mem.put(pointer + 0x20, int.from_bytes(tag.encode("ascii"), "little") | (slot << 32), 8)
    result = army._find_countries(mem, BASE, frozenset({"ABC", "DEF", "GHI"}),
                                  {}, army._forces._ReadBudget())
    assert {tag: row["slot"] for tag, row in result["matches"].items()} == {
        "ABC": 1, "DEF": 2, "GHI": 3}
    assert len([label for label in mem.reads if label.startswith("country_forces.country_table[")]) == 4
    with pytest.raises(army._forces.ReadError, match="country_identity_match_count_invalid"):
        army._find_countries(mem, BASE, frozenset({"ABC", "ZZZ"}), {}, army._forces._ReadBudget())


def test_war_projection_filters_enemies_by_own_positive_land_presence(monkeypatch):
    mem = fixture(monkeypatch)
    chains = {}
    locations = {
        "ABC": [(123, 1000), (125, 800), (127, 0)],
        "DEF": [(124, 11000)],
        "GHI": [(123, 7078), (124, 3000), (125, 5000), (126, 6000), (127, 7000), (128, 8000)],
        "JKL": [(123, 5846)],
    }
    for country_index, (country, stacks) in enumerate(locations.items()):
        groups, records = [], []
        for index, (province, men) in enumerate(stacks):
            group = 0x8000000 + country_index * 0x10000 + index * 0x1000
            location = PROVINCES + province * army._provinces.RECORD_STRIDE
            mem.put(group, BASE + army._LAND_VTABLE_RVA, 8)
            mem.put(group + army._GROUP_LOCATION_OFFSET, location, 8)
            mem.put(location + army._provinces.RECORD_ID_OFFSET, province, 4)
            groups.append({"group_object": hex(group)})
            records.append({"group_index": index, "type_kind": 0, "strength_raw": men})
        chains[country] = {"groups": groups, "records": records}
    monkeypatch.setattr(army, "_find_countries", lambda *args: {"matches": {
        tag: {"pointer": hex(0x9000000 + index * 0x1000)}
        for index, tag in enumerate(locations)}})
    seen = []

    def read_chain(reader, pointer, country, profile, budget):
        seen.append(country)
        return deepcopy(chains[country])

    monkeypatch.setattr(army._forces, "_read_force_chain", read_chain)
    result = army._read_war_pass(mem, BASE, "ABC", frozenset({123, 124, 125, 126, 127}),
                                 {}, object(), allies=frozenset({"ABC", "DEF"}),
                                 enemies=frozenset({"GHI", "JKL"}),
                                 land_ids=frozenset({123, 124, 126, 127}))
    assert seen == ["ABC", "DEF", "GHI", "JKL"]
    assert [(row["owner"], row["province_id"], row["men"], row["visibility_basis"])
            for row in result["records"]] == [
        ("ABC", 123, 1000, "observer_country"),
        ("ABC", 125, 800, "observer_country"),
        ("ABC", 127, 0, "observer_country"),
        ("DEF", 124, 11000, "selected_war_same_side"),
        ("GHI", 123, 7078, "observer_army_same_land_province"),
        ("JKL", 123, 5846, "observer_army_same_land_province"),
    ]


def test_hidden_enemy_changes_retract_the_entire_scoped_capture(monkeypatch):
    first = {"records": [{"owner": "ABC"}], "omissions": [], "chains": {"GHI": "first"}}
    second = {"records": [{"owner": "ABC"}], "omissions": [], "chains": {"GHI": "second"}}
    passes = iter((first, second))
    monkeypatch.setattr(army._forces, "_load_profile", lambda: {})
    monkeypatch.setattr(army._forces, "_runtime_code_guard", lambda *args: {"status": "observed"})
    monkeypatch.setattr(army._owner, "_context", lambda *args: {"game_date": 123})
    monkeypatch.setattr(army._owner, "_guards", lambda *args: ["ok"])
    monkeypatch.setattr(army, "_read_war_pass", lambda *args, **kwargs: next(passes))
    result = army._observe(None, BASE, "ABC", frozenset({123}), {}, war_scope=(
        frozenset({"ABC", "DEF"}), frozenset({"GHI"}), frozenset({123})))
    assert result["stable"] is False
    assert result["records"] == []


def test_no_eligible_own_land_army_skips_all_enemy_chains(monkeypatch):
    mem = fixture(monkeypatch)
    monkeypatch.setattr(army, "_find_countries", lambda *args: {"matches": {
        tag: {"pointer": hex(0x9000000 + index * 0x1000)}
        for index, tag in enumerate(("ABC", "DEF", "GHI"))}})
    original = army._forces._read_force_chain
    seen = []

    def read_chain(reader, pointer, country, profile, budget):
        seen.append(country)
        return original(reader, pointer, country, profile, budget)

    monkeypatch.setattr(army._forces, "_read_force_chain", read_chain)
    result = army._read_war_pass(mem, BASE, "ABC", frozenset({123, 124}), {}, object(),
                                 allies=frozenset({"ABC", "DEF"}),
                                 enemies=frozenset({"GHI"}), land_ids=frozenset({124}))
    assert seen == ["ABC", "DEF"]
    assert result["enemy_chains_read"] is False
    assert all(row["relation"] != "enemy" for row in result["records"])


@pytest.mark.parametrize("allies,enemies,land", [
    (["ABC"], None, []),
    (["DEF"], ["GHI"], [123]),
    (["ABC", "ABC"], ["GHI"], [123]),
    (["ABC", "DEF"], ["DEF"], [123]),
    (["ABC"], ["ghI"], [123]),
    (["ABC"], ["GHI"], [True]),
    (["ABC"], ["GHI"], [123, 123]),
    ("ABC", ["GHI"], [123]),
])
def test_invalid_war_scopes_are_rejected(allies, enemies, land):
    with pytest.raises(army._map.MapLiveCaptureError, match="MAP_MILITARY_ARMY_SCOPE_INVALID"):
        army._war_scope("ABC", allies, enemies, land)


def test_scoped_public_result_reports_basis_and_partial_coverage(monkeypatch, tmp_path):
    installation = tmp_path / "installation.json"
    installation.touch()
    context = {"game_date": 56896992, "world_pointer": "0x2100000"}
    records = [{"province_id": 123, "owner": "GHI", "men": 7078,
                "relation": "enemy", "visibility_basis": "observer_army_same_land_province"}]
    monkeypatch.setattr(army._owner, "_capture_common", lambda *args, **kwargs: {
        "status": "observed", "completed": True,
        "request": {"pid": 1, "creation_filetime": 2, "session_id": "session"},
        "observation": {"stable": True, "context_after": context,
                        "records": records, "omissions": []}, "access": {}})
    result = army.capture_armies(installation, "ABC", [123], allies=["ABC", "DEF"],
                                  enemies=["GHI"], land_province_ids=[123])
    assert result["status"] == "partial"
    assert result["records"] == records
    assert result["date_raw"] == 56896992
    assert result["fields"]["visibility"]["native_visibility_rule_verified"] is False
    assert result["fields"]["visibility"]["allies"] == "selected_war_same_side"
    assert "WAR_ENEMIES_OUTSIDE_OBSERVER_ARMY_PROVINCES_NOT_INCLUDED" in result["gaps"]
