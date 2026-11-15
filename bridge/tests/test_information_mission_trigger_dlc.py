import pytest

from bridge.information import mission_branch_memory
from bridge.information import mission_trigger_dlc as dlc


MODULE_BASE = 0x140000000
DOMINATION_ADDRESS = MODULE_BASE + mission_branch_memory.DOMINATION_GLOBAL_BOOL_RVA
OVERRIDE_ADDRESS = MODULE_BASE + mission_branch_memory.DOMINATION_OVERRIDE_BYTE_RVA


class ByteReader:
    def __init__(self, domination=b"\x01", override=b"\x00", *, short_label=None,
                 error_label=None):
        self.values = {
            DOMINATION_ADDRESS: domination,
            OVERRIDE_ADDRESS: override,
        }
        self.short_label = short_label
        self.error_label = error_label
        self.code_reads = []
        self.aligned_reads = []

    def read_code(self, address, size, label):
        self.code_reads.append((address, size, label))
        if label == self.error_label:
            raise OSError("fixture_read_error")
        value = self.values[address]
        if label == self.short_label:
            return value[: max(0, size - 1)]
        return value

    def read(self, address, size, label):
        self.aligned_reads.append((address, size, label))
        return self.read_code(address, size, label)


def test_domination_known_only_when_global_byte_nonzero_and_override_zero():
    reader = ByteReader(domination=b"\x02", override=b"\x00")

    result = dlc.read_dlc_state(reader, MODULE_BASE, 0x80000)

    assert result == {
        "status": "known",
        "satisfied": True,
        "dlc": "Domination",
        "source": "mission_branch_memory._read_domination",
    }
    assert reader.code_reads == [
        (DOMINATION_ADDRESS, 1, "domination.global_bool"),
        (OVERRIDE_ADDRESS, 1, "domination.override_byte"),
    ]
    assert reader.aligned_reads == []


def test_zero_global_byte_keeps_dlc_unknown():
    reader = ByteReader(domination=b"\x00", override=b"\x00")

    result = dlc.read_dlc_state(reader, MODULE_BASE, dlc.DOMINATION_MASK)

    assert result == {
        "status": "unknown",
        "reason": "THREAD_LOCAL_DLC_OVERRIDE_UNRESOLVED",
    }
    assert len(reader.code_reads) == 2


def test_nonzero_override_keeps_dlc_unknown_without_tls_read():
    reader = ByteReader(domination=b"\x01", override=b"\x01")

    result = dlc.read_dlc_state(reader, MODULE_BASE, dlc.DOMINATION_MASK)

    assert result == {
        "status": "unknown",
        "reason": "THREAD_LOCAL_DLC_OVERRIDE_UNRESOLVED",
    }
    assert len(reader.code_reads) == 2
    assert all("tls" not in label.lower() for _, _, label in reader.code_reads)


def test_unsupported_or_malformed_masks_are_unknown_without_reads():
    for mask in (0x80000000, 0x80001, 0, True, False, "0x80000", None):
        reader = ByteReader()

        result = dlc.read_dlc_state(reader, MODULE_BASE, mask)

        assert result["status"] == "unknown"
        assert reader.code_reads == []
        assert reader.aligned_reads == []


def test_short_read_and_reader_exception_fail_closed_on_tracked_path():
    short_reader = ByteReader(short_label="domination.global_bool")
    short_result = dlc.read_dlc_state(short_reader, MODULE_BASE, dlc.DOMINATION_MASK)
    assert short_result == {
        "status": "unknown",
        "reason": "domination_read_failed:domination_byte_read_size_invalid",
    }
    assert [label for _, _, label in short_reader.code_reads] == [
        "domination.global_bool",
        "domination.override_byte",
    ]

    error_reader = ByteReader(error_label="domination.override_byte")
    error_result = dlc.read_dlc_state(error_reader, MODULE_BASE, dlc.DOMINATION_MASK)
    assert error_result == {
        "status": "unknown",
        "reason": "domination_read_failed:fixture_read_error",
    }
    assert [label for _, _, label in error_reader.code_reads] == [
        "domination.global_bool",
        "domination.override_byte",
    ]


@pytest.mark.parametrize("mask,name,global_rva", [
    (0x1, "Conquest of Paradise", 0x233FF40),
    (0x80, "Mare Nostrum", 0x233FF1C),
    (0x8000, "Emperor", 0x233FF24),
    (0x40000000, "Dharma - Hindu Unit Pack", 0x233FF58),
])
def test_other_single_bit_dlc_reads_its_own_bound_byte(mask, name, global_rva):
    reader = ByteReader()
    address = MODULE_BASE + global_rva
    reader.values[address] = b"\x03"
    result = dlc.read_dlc_state(reader, MODULE_BASE, mask)
    assert result["status"] == "known" and result["satisfied"] is True
    assert result["dlc"] == name
    assert reader.code_reads == [(address, 1, "dlc.global_bool"),
                                 (OVERRIDE_ADDRESS, 1, "dlc.override_byte")]


def test_other_dlc_zero_or_override_remains_unknown_and_never_reads_tls():
    for global_raw, override_raw in [(b"\x00", b"\x00"), (b"\x01", b"\x01")]:
        reader = ByteReader(override=override_raw)
        reader.values[MODULE_BASE + 0x233FF24] = global_raw
        result = dlc.read_dlc_state(reader, MODULE_BASE, 0x8000)
        assert result["status"] == "unknown"
        assert result["reason"] == "THREAD_LOCAL_DLC_OVERRIDE_UNRESOLVED"
        assert len(reader.code_reads) == 2


def test_other_dlc_short_read_or_error_stays_unknown():
    for kwargs in ({"short_label": "dlc.global_bool"}, {"error_label": "dlc.override_byte"}):
        reader = ByteReader(**kwargs)
        reader.values[MODULE_BASE + 0x233FF24] = b"\x01"
        assert dlc.read_dlc_state(reader, MODULE_BASE, 0x8000)["status"] == "unknown"
