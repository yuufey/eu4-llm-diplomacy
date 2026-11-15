"""Pure-memory tests for retained capital and emperor scope selectors."""
from __future__ import annotations

import pytest

from bridge.information import empire_memory
from bridge.information import mission_trigger_dynamic_scopes as dynamic_scopes
from bridge.tests.test_information_mission_memory import FakeReader


MODULE = 0x140000000
COUNTRY = 0x500000
WORLD = 0x600000
SOURCE = dynamic_scopes.SOURCE


class CodePathReader(FakeReader):
    """Record byte reads to ensure the helper uses the unaligned reader path."""

    def __init__(self):
        super().__init__(MODULE)
        self.code_reads: list[tuple[int, int, str]] = []

    def read_code(self, address: int, size: int, label: str) -> bytes:
        self.code_reads.append((address, size, label))
        return super().read(address, size, label)


def _install_emperor(reader: FakeReader, *, fullref: int | None = None) -> int:
    world = WORLD
    hre = world + empire_memory.HRE_OFFSET
    reader.qword_put(MODULE + empire_memory.WORLD_GLOBAL_RVA, world)
    reader.qword_put(world, MODULE + empire_memory.WORLD_VTABLE_RVA)
    reader.qword_put(hre, MODULE + empire_memory.HRE_VTABLE_RVA)
    if fullref is not None:
        reader.qword_put(hre + dynamic_scopes.EMPEROR_FULLREF_OFFSET, fullref)
    return hre


def _fullref(slot: int, tag: str) -> int:
    return (slot << 32) | int.from_bytes(tag.encode("ascii"), "little")


def test_capital_reads_signed_province_id_from_country_14b8():
    reader = CodePathReader()
    reader.dword_put(COUNTRY + 0x14B8, 183, signed=True)
    # The adjacent field is a capital pointer. It must not supply the result.
    reader.qword_put(COUNTRY + 0x14B0, 0x660000)

    result = dynamic_scopes.read_scope_selector(reader, MODULE, "capital", COUNTRY)

    assert result == {"status": "known", "province_id": 183, "source": SOURCE}
    assert (COUNTRY + 0x14B8, 4, "mission_scope.capital.province_id") in reader.code_reads
    assert not any(address == COUNTRY + 0x14B0 for address, _size, _label in reader.code_reads)


@pytest.mark.parametrize("province_id", [0, -1, 65536])
def test_capital_zero_negative_and_out_of_range_ids_are_unknown(province_id: int):
    reader = FakeReader(MODULE)
    reader.dword_put(COUNTRY + dynamic_scopes.COUNTRY_CAPITAL_ID_OFFSET,
                     province_id, signed=True)

    result = dynamic_scopes.read_scope_selector(reader, MODULE, "capital", COUNTRY)

    assert result["status"] == "unknown"
    assert "capital_province_id_missing_or_invalid" in result["reason"]


def test_emperor_returns_validated_world_hre_fullref_through_code_path():
    reader = CodePathReader()
    hre = _install_emperor(reader, fullref=_fullref(3, "HAB"))

    result = dynamic_scopes.read_scope_selector(reader, MODULE, "emperor", COUNTRY)

    assert result == {
        "status": "known",
        "fullref": _fullref(3, "HAB"),
        "source": SOURCE,
    }
    assert (MODULE + empire_memory.WORLD_GLOBAL_RVA, 8,
            "mission_scope.emperor.world") in reader.code_reads
    assert (hre + dynamic_scopes.EMPEROR_FULLREF_OFFSET, 8,
            "mission_scope.emperor.fullref") in reader.code_reads


def test_emperor_bad_vtable_and_invalid_fullref_fail_closed():
    bad_vtable_reader = FakeReader(MODULE)
    hre = _install_emperor(bad_vtable_reader, fullref=_fullref(3, "HAB"))
    bad_vtable_reader.qword_put(WORLD, MODULE + empire_memory.WORLD_VTABLE_RVA + 8)

    bad_vtable = dynamic_scopes.read_scope_selector(
        bad_vtable_reader, MODULE, "emperor", COUNTRY
    )

    invalid_ref_reader = FakeReader(MODULE)
    _install_emperor(invalid_ref_reader, fullref=0)
    invalid_ref = dynamic_scopes.read_scope_selector(
        invalid_ref_reader, MODULE, "emperor", COUNTRY
    )

    assert bad_vtable["status"] == "unknown"
    assert "emperor_world_vtable_mismatch" in bad_vtable["reason"]
    assert invalid_ref["status"] == "unknown"
    assert "EMPIRE_FULLREF_TAG_INVALID:emperor" in invalid_ref["reason"]
    assert hre == WORLD + empire_memory.HRE_OFFSET


def test_bad_kind_boolean_base_and_short_read_are_unknown():
    reader = FakeReader(MODULE)
    bad_kind = dynamic_scopes.read_scope_selector(reader, MODULE, "monarch", COUNTRY)
    boolean_base = dynamic_scopes.read_scope_selector(reader, True, "capital", COUNTRY)

    class ShortReadReader(FakeReader):
        def read_code(self, _address: int, _size: int, _label: str) -> bytes:
            raise OSError("synthetic short read")

    short_read = dynamic_scopes.read_scope_selector(
        ShortReadReader(MODULE), MODULE, "capital", COUNTRY
    )

    assert bad_kind["status"] == "unknown"
    assert "dynamic_scope_kind_unsupported" in bad_kind["reason"]
    assert boolean_base["status"] == "unknown"
    assert "dynamic_scope_module_base_invalid" in boolean_base["reason"]
    assert short_read["status"] == "unknown"
    assert "synthetic short read" in short_read["reason"]
