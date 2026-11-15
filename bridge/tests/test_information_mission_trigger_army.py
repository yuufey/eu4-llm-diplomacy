"""Synthetic tests for the army-ratio adapter's bounded read decisions."""
from __future__ import annotations

from copy import deepcopy

from bridge.information import mission_trigger_army as army


MODULE = 0x140000000
COUNTRY = 0x500000


class SyntheticReader:
    def __init__(self):
        self.memory: dict[int, int] = {}
        self.reads: list[tuple[int, int, str]] = []
        self.fail_addresses: set[int] = set()

    def put(self, address: int, data: bytes) -> None:
        for offset, value in enumerate(data):
            self.memory[address + offset] = value

    def qword_put(self, address: int, value: int) -> None:
        self.put(address, int(value).to_bytes(8, "little", signed=False))

    def read(self, address: int, size: int, label: str) -> bytes:
        self.reads.append((address, size, label))
        if address in self.fail_addresses:
            raise OSError("synthetic read failure")
        return bytes(self.memory.get(address + offset, 0) for offset in range(size))

    def read_code(self, address: int, size: int, label: str) -> bytes:
        return self.read(address, size, label)


def _force_result(groups):
    return {
        "status": "observed",
        "country": "FRA",
        "group_count": len(groups),
        "country_pointer": hex(COUNTRY),
        "groups": groups,
        # The adapter must count vector lengths and must not project records.
        "records": [
            {"group_index": 0, "type_kind": "not-used", "strength_raw": object()},
        ],
    }


def _military_result(*, raw=12000, unit="regiments", status="known"):
    land = {
        "status": status,
        "value": raw // 1000,
        "raw": raw,
        "scale": 1000,
        "unit": unit,
        "complete": True,
        "partial": False,
    }
    if status != "known":
        land["reason"] = "fixture_land_unknown"
    return {
        "status": "observed",
        "country": "FRA",
        "country_pointer": hex(COUNTRY),
        "fields": {"force_limits": {"status": "partial", "value": {
            "land": land,
            "naval": {"status": "unknown", "reason": "not-needed"},
        }}},
    }


def fixture(monkeypatch, *, lengths=(3,), codes=(b"\xb0\x01\xc3\xcc\xcc\xcc",),
            auxiliary=(0,), flag_bytes=(1,), military=None):
    reader = SyntheticReader()
    groups = []
    force_calls = []
    military_calls = []
    for index, length in enumerate(lengths):
        group_object = 0x900000 + index * 0x1000
        vtable = MODULE + 0x1D00000 + index * 0x100
        method = MODULE + 0x5000 + index * 0x100
        aux = auxiliary[index]
        reader.qword_put(group_object, vtable)
        reader.qword_put(group_object + 0x48, aux)
        reader.qword_put(vtable + 0x80, method)
        reader.put(method, codes[index])
        if aux:
            nested = 0xA00000 + index * 0x1000
            reader.qword_put(aux + 0x28, nested)
            reader.put(nested + 0x291, bytes([flag_bytes[index]]))
        groups.append({"group_object": hex(group_object), "vector_length": length})

    observed_forces = _force_result(groups)
    observed_military = _military_result() if military is None else military

    def read_forces(actual_reader, module_base, country_pointer, *, country):
        force_calls.append((actual_reader, module_base, country_pointer, country))
        return deepcopy(observed_forces)

    def read_military(actual_reader, module_base, country_pointer, *, country):
        military_calls.append((actual_reader, module_base, country_pointer, country))
        return deepcopy(observed_military)

    monkeypatch.setattr(army.forces, "read_fields", read_forces)
    monkeypatch.setattr(army.military_resources, "read_fields", read_military)
    return reader, groups, force_calls, military_calls


def test_null_optional_pointer_continues_to_true_method(monkeypatch):
    reader, _groups, force_calls, military_calls = fixture(monkeypatch)

    result = army.count_army_ratio_inputs(reader, MODULE, COUNTRY)

    assert result == {
        "status": "known",
        "army_raw_fixed_milli": 3000,
        "land_force_limit_raw": 12000,
        "source": army.SOURCE,
    }
    assert len(force_calls) == len(military_calls) == 1
    assert force_calls[0] == (reader, MODULE, COUNTRY, "FRA")
    assert military_calls[0] == (reader, MODULE, COUNTRY, "FRA")


def test_false_method_adds_no_count(monkeypatch):
    reader, _groups, _force_calls, _military_calls = fixture(
        monkeypatch, codes=(b"\x32\xc0\xc3\xcc\xcc\xcc",), lengths=(17,))

    result = army.count_army_ratio_inputs(reader, MODULE, COUNTRY)

    assert result["status"] == "known"
    assert result["army_raw_fixed_milli"] == 0


def test_true_method_uses_only_vector_lengths_not_record_kind_or_strength(monkeypatch):
    reader, _groups, _force_calls, _military_calls = fixture(
        monkeypatch,
        lengths=(2, 3),
        codes=(b"\xb0\x01\xc3\xcc\xcc\xcc", b"\xb8\x01\x00\x00\x00\xc3"),
        auxiliary=(0, 0),
    )
    # The fake source carries arbitrary record contents; only validated group
    # vector lengths participate in the native numerator.
    result = army.count_army_ratio_inputs(reader, MODULE, COUNTRY)

    assert result["army_raw_fixed_milli"] == 5000
    assert result["land_force_limit_raw"] == 12000


def test_optional_pointer_flag_zero_skips_group_before_method_read(monkeypatch):
    auxiliary_pointer = 0xB00000
    reader, _groups, _force_calls, _military_calls = fixture(
        monkeypatch, lengths=(9,), codes=(b"\x90" * 6,),
        auxiliary=(auxiliary_pointer,), flag_bytes=(0,))

    result = army.count_army_ratio_inputs(reader, MODULE, COUNTRY)

    assert result["status"] == "known"
    assert result["army_raw_fixed_milli"] == 0
    assert not any(label.endswith(".method_bytes") for _addr, _size, label in reader.reads)


def test_optional_pointer_flag_nonzero_includes_true_group(monkeypatch):
    reader, _groups, _force_calls, _military_calls = fixture(
        monkeypatch, lengths=(4,), auxiliary=(0xB00000,), flag_bytes=(1,))

    result = army.count_army_ratio_inputs(reader, MODULE, COUNTRY)

    assert result["status"] == "known"
    assert result["army_raw_fixed_milli"] == 4000


def test_unknown_method_bytes_remain_unknown(monkeypatch):
    reader, _groups, _force_calls, _military_calls = fixture(
        monkeypatch, codes=(b"\x90" * 6,))

    result = army.count_army_ratio_inputs(reader, MODULE, COUNTRY)

    assert result["status"] == "unknown"
    assert "METHOD_NOT_CONSTANT" in result["reason"]


def test_bad_optional_pointer_or_method_pointer_remains_unknown(monkeypatch):
    reader, groups, _force_calls, _military_calls = fixture(monkeypatch)
    group_object = int(groups[0]["group_object"], 0)
    reader.qword_put(group_object + 0x48, 0xB00001)
    result = army.count_army_ratio_inputs(reader, MODULE, COUNTRY)
    assert result["status"] == "unknown"
    assert "auxiliary_pointer_invalid" in result["reason"]

    reader, groups, _force_calls, _military_calls = fixture(monkeypatch)
    group_object = int(groups[0]["group_object"], 0)
    vtable = MODULE + 0x1D00000
    reader.qword_put(vtable + 0x80, 0x7FFF000000000000)
    result = army.count_army_ratio_inputs(reader, MODULE, COUNTRY)
    assert result["status"] == "unknown"
    assert "method_outside_code" in result["reason"]


def test_read_failure_returns_unknown(monkeypatch):
    reader, groups, _force_calls, _military_calls = fixture(monkeypatch)
    method = MODULE + 0x5000
    reader.fail_addresses.add(method)

    result = army.count_army_ratio_inputs(reader, MODULE, COUNTRY)

    assert result["status"] == "unknown"
    assert "synthetic read failure" in result["reason"]


def test_unknown_zero_or_wrong_unit_land_denominator_stays_unknown(monkeypatch):
    for military in (
        _military_result(status="unknown"),
        _military_result(raw=0),
        _military_result(unit="ships"),
    ):
        reader, _groups, _force_calls, _military_calls = fixture(
            monkeypatch, military=military)

        result = army.count_army_ratio_inputs(reader, MODULE, COUNTRY)

        assert result["status"] == "unknown"
        assert "LAND_FORCE_LIMIT" in result["reason"]


def test_s32_wrap_helper_matches_native_signed_accumulation():
    assert army._wrap_s32(0x7FFFFFFF + 1) == -0x80000000
    assert army._wrap_s32(-0x80000000 - 1) == 0x7FFFFFFF
    assert army._wrap_s32(0xFFFFFFFF * 1000) == -1000
