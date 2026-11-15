from copy import deepcopy

import pytest

from bridge.information import mission_trigger_country_scope as country_scope
from bridge.information import province_state_memory


MODULE_BASE = 0x140000000
DATABASE = 0x600000
TABLE = 0x700000


class DictRPM:
    """Address-indexed fake backend that records the actual tracked reads."""

    def __init__(self, *, fail_address=None):
        self.memory = {}
        self.fail_address = fail_address
        self.read_code_calls = []
        self.read_calls = []

    def put(self, address, value):
        if type(value) is int:
            value = value.to_bytes(8, "little", signed=False)
        for offset, byte in enumerate(value):
            self.memory[address + offset] = byte

    def read_code(self, address, size, label):
        self.read_code_calls.append((address, size, label))
        if address == self.fail_address:
            raise OSError("synthetic_rpm_failure")
        try:
            return bytes(self.memory[address + offset] for offset in range(size))
        except KeyError as exc:
            raise OSError("synthetic_memory_missing") from exc

    def read(self, address, size, label):
        self.read_calls.append((address, size, label))
        raise AssertionError("resolver should use the unaligned tracked path")


def _fullref(tag, slot, *, high_byte=1, byte48=0):
    low = int.from_bytes(tag.encode("ascii") + b"\0", "little")
    return (high_byte << 56) | (byte48 << 48) | (slot << 32) | low


def _database(tag="FRA", slot=122, count=4096, *, canonical_fullref=None,
              fail_address=None):
    backend = DictRPM(fail_address=fail_address)
    country_pointer = 0x900000 + slot * 0x1000
    fullref = _fullref(tag, slot)
    echo = fullref if canonical_fullref is None else canonical_fullref
    global_cell = MODULE_BASE + province_state_memory.DATABASE_GLOBAL_RVA
    table_cell = DATABASE + province_state_memory.DATABASE_TABLE_OFFSET
    count_cell = DATABASE + province_state_memory.DATABASE_COUNT_OFFSET
    entry = TABLE + slot * 8

    backend.put(global_cell, DATABASE)
    backend.put(table_cell, TABLE)
    backend.put(count_cell, count.to_bytes(4, "little", signed=True))
    if slot < count:
        backend.put(entry, country_pointer)
        backend.put(
            country_pointer + province_state_memory.COUNTRY_FULLREF_OFFSET,
            echo.to_bytes(8, "little"),
        )
    return backend, fullref, country_pointer, {
        "global_cell": global_cell,
        "table_cell": table_cell,
        "count_cell": count_cell,
        "entry": entry,
        "country_ref": country_pointer + province_state_memory.COUNTRY_FULLREF_OFFSET,
    }


def _synthetic_resolver_success(fullref, pointer, tag=None):
    slot = (fullref >> 32) & 0xFFFF
    tag = tag or fullref.to_bytes(8, "little")[:3].decode("ascii")
    raw = fullref.to_bytes(8, "little")
    return {
        "status": "known",
        "value": tag,
        "basis": "province_discovery_bit_one_canonical_country_fullref",
        "raw_inputs": {
            "fullref_raw_hex": raw.hex(),
            "fullref": hex(fullref),
            "high_byte": (fullref >> 56) & 0xFF,
            "byte48": (fullref >> 48) & 0xFF,
            "slot": slot,
            "tag": tag,
            "database": hex(DATABASE),
            "table": hex(TABLE),
            "count": 4096,
            "table_entry_address": hex(TABLE + slot * 8),
            "table_entry_raw_hex": pointer.to_bytes(8, "little").hex(),
            "country_pointer": hex(pointer),
            "canonical_fullref_address": hex(
                pointer + province_state_memory.COUNTRY_FULLREF_OFFSET
            ),
            "canonical_fullref": hex(fullref),
            "canonical_fullref_raw_hex": raw.hex(),
        },
    }


def test_fra_fullref_binds_to_canonical_pointer_without_scanning_table():
    backend, fullref, pointer, addresses = _database(
        tag="FRA", slot=122, count=4096
    )

    result = country_scope.bind_country_scope(backend, MODULE_BASE, fullref)

    assert result == {
        "status": "known",
        "tag": "FRA",
        "pointer": pointer,
        "fullref": fullref,
    }
    assert [call[0] for call in backend.read_code_calls] == [
        addresses["global_cell"],
        addresses["table_cell"],
        addresses["count_cell"],
        addresses["entry"],
        addresses["country_ref"],
    ]
    assert len(backend.read_code_calls) == 5
    assert sum(call[1] for call in backend.read_code_calls) == 36
    assert backend.read_calls == []
    assert all(call[2].startswith("province_state.mission_country_scope.")
               for call in backend.read_code_calls)


@pytest.mark.parametrize(("tag", "slot"), [("ENG", 7), ("POR", 24)])
def test_foreign_fullrefs_return_the_exact_tag_pointer_and_reference(tag, slot):
    backend, fullref, pointer, _ = _database(tag=tag, slot=slot, count=4096)

    assert country_scope.bind_country_scope(
        backend, MODULE_BASE, fullref
    ) == {
        "status": "known",
        "tag": tag,
        "pointer": pointer,
        "fullref": fullref,
    }
    assert len(backend.read_code_calls) == 5


@pytest.mark.parametrize("fullref", [True, False, -1, 2**64, 2**64 + 1])
def test_fullref_requires_a_non_bool_uint64(fullref):
    backend = DictRPM()

    assert country_scope.bind_country_scope(
        backend, MODULE_BASE, fullref
    ) == {
        "status": "unknown",
        "reason": "COUNTRY_SCOPE_FULLREF_INVALID",
    }
    assert backend.read_code_calls == []


@pytest.mark.parametrize(
    ("fullref", "reason"),
    [
        (_fullref("FRA", 12, high_byte=0), "COUNTRY_FULLREF_HIGH_BYTE_ZERO"),
        (_fullref("FRA", 12, byte48=7), "COUNTRY_FULLREF_BYTE48_SEVEN"),
        (_fullref("fra", 12), "COUNTRY_FULLREF_TAG_INVALID"),
    ],
)
def test_invalid_fullref_encodings_fail_before_database_reads(fullref, reason):
    backend = DictRPM()

    assert country_scope.bind_country_scope(
        backend, MODULE_BASE, fullref
    ) == {"status": "unknown", "reason": reason}
    assert backend.read_code_calls == []


def test_slot_outside_country_count_is_unknown_without_slot_read():
    backend, fullref, _, addresses = _database(
        tag="ENG", slot=12, count=12
    )

    result = country_scope.bind_country_scope(
        backend, MODULE_BASE, fullref
    )

    assert result == {
        "status": "unknown",
        "reason": "COUNTRY_FULLREF_SLOT_OUT_OF_RANGE",
    }
    assert [call[0] for call in backend.read_code_calls] == [
        addresses["global_cell"],
        addresses["table_cell"],
        addresses["count_cell"],
    ]


def test_invalid_country_count_is_unknown_without_slot_read():
    backend, fullref, _, addresses = _database(
        tag="FRA", slot=1, count=0
    )

    assert country_scope.bind_country_scope(
        backend, MODULE_BASE, fullref
    ) == {
        "status": "unknown",
        "reason": "COUNTRY_TABLE_COUNT_OUT_OF_RANGE",
    }
    assert [call[0] for call in backend.read_code_calls] == [
        addresses["global_cell"],
        addresses["table_cell"],
        addresses["count_cell"],
    ]


def test_table_row_pointer_must_echo_the_country_fullref():
    backend, fullref, _, addresses = _database(
        tag="ENG",
        slot=11,
        canonical_fullref=_fullref("ENG", 10),
    )

    assert country_scope.bind_country_scope(
        backend, MODULE_BASE, fullref
    ) == {
        "status": "unknown",
        "reason": "COUNTRY_FULLREF_ECHO_MISMATCH",
    }
    assert [call[0] for call in backend.read_code_calls][-1] == addresses["country_ref"]
    assert len(backend.read_code_calls) == 5


def test_read_failure_is_unknown_and_remains_in_the_tracked_read_trace():
    backend, fullref, _, addresses = _database(
        tag="FRA", slot=4, count=32, fail_address=TABLE + 4 * 8
    )

    result = country_scope.bind_country_scope(
        backend, MODULE_BASE, fullref
    )

    assert result["status"] == "unknown"
    assert result["reason"].startswith(
        "read_failed:province_state.mission_country_scope.country_pointer"
    )
    assert backend.read_code_calls[-1][0] == addresses["entry"]
    assert backend.read_calls == []


@pytest.mark.parametrize(
    ("mutation", "reason"),
    [
        (
            lambda raw: raw.update(tag="ENG"),
            "COUNTRY_SCOPE_TAG_ECHO_MISMATCH",
        ),
        (
            lambda raw: raw.update(fullref=hex(0x1234)),
            "COUNTRY_SCOPE_FULLREF_ECHO_MISMATCH",
        ),
        (
            lambda raw: raw.update(canonical_fullref=hex(0x1234)),
            "COUNTRY_SCOPE_FULLREF_ECHO_MISMATCH",
        ),
        (
            lambda raw: raw.update(country_pointer=hex(0x900001)),
            "COUNTRY_SCOPE_POINTER_INVALID",
        ),
        (
            lambda raw: raw.update(table_entry_raw_hex=(0x901000).to_bytes(8, "little").hex()),
            "COUNTRY_SCOPE_POINTER_ECHO_MISMATCH",
        ),
        (
            lambda raw: raw.update(canonical_fullref_address=hex(0x900000)),
            "COUNTRY_SCOPE_CANONICAL_ADDRESS_MISMATCH",
        ),
    ],
)
def test_malformed_success_evidence_fails_closed(monkeypatch, mutation, reason):
    fullref = _fullref("FRA", 5)
    pointer = 0x900000
    resolved = _synthetic_resolver_success(fullref, pointer)
    mutation(resolved["raw_inputs"])
    monkeypatch.setattr(
        country_scope.province_state_memory,
        "_resolve_country_reference",
        lambda *args: deepcopy(resolved),
    )
    backend = DictRPM()

    assert country_scope.bind_country_scope(
        backend, MODULE_BASE, fullref
    ) == {"status": "unknown", "reason": reason}
    assert backend.read_code_calls == []


@pytest.mark.parametrize(
    ("module_base", "fullref", "reason"),
    [
        (True, _fullref("FRA", 1), "COUNTRY_SCOPE_MODULE_BASE_INVALID"),
        (0, _fullref("FRA", 1), "COUNTRY_SCOPE_MODULE_BASE_INVALID"),
        (MODULE_BASE, _fullref("FRA", 1), "COUNTRY_TABLE_COUNT_OUT_OF_RANGE"),
    ],
)
def test_bad_module_or_source_inputs_fail_closed(module_base, fullref, reason):
    if module_base == MODULE_BASE:
        backend, fullref, _, _ = _database(
            tag="FRA", slot=1, count=0
        )
    else:
        backend = DictRPM()

    result = country_scope.bind_country_scope(backend, module_base, fullref)

    assert result == {"status": "unknown", "reason": reason}
    if module_base != MODULE_BASE:
        assert backend.read_code_calls == []
