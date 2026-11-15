"""Bounded synthetic tests for the opt-in country force type-key reader."""
from __future__ import annotations

from copy import deepcopy
import hashlib
from pathlib import Path

import pytest

from bridge.information import country_forces_memory as memory


MODULE_BASE = 0x140000000
DATABASE = 0x6200000000
TABLE = 0x6300000000
GAME = 0x6500000000
COUNTRY = 0x6400000000
GROUP_HEAD = 0x6100000000
GROUP_OBJECT = 0x6100001000
VECTOR = 0x6100002000
RECORDS = (0x6700000000, 0x6700001000)
TYPES = (0x6800000000, 0x6800001000)
HEAP_KEY = 0x6900000000
CREATION = 134375854500787403
SESSION = "synthetic-type-key-capture"


class Reader:
    def __init__(self) -> None:
        self.memory: dict[int, int] = {}

    def put(self, address: int, raw: bytes) -> None:
        self.memory.update({address + offset: value for offset, value in enumerate(raw)})

    def qword(self, address: int, value: int) -> None:
        self.put(address, int(value).to_bytes(8, "little"))

    def i32(self, address: int, value: int) -> None:
        self.put(address, int(value).to_bytes(4, "little", signed=True))

    def read(self, address: int, size: int, label: str) -> bytes:
        try:
            return bytes(self.memory[address + offset] for offset in range(size))
        except KeyError as exc:
            raise AssertionError(f"unexpected synthetic read {label} {address:#x} {size}") from exc

    def read_code(self, address: int, size: int, label: str) -> bytes:
        return self.read(address, size, label)


class ChangingTypeReader(Reader):
    def __init__(self) -> None:
        super().__init__()
        self.changed = False

    def read(self, address: int, size: int, label: str) -> bytes:
        raw = super().read(address, size, label)
        if not self.changed and label == "country_forces.unit_type.type[0].string_bytes":
            self.put(TYPES[0] + 0x60, b"infantry_new\x00" + b"\x00" * 3)
            self.changed = True
        return raw


class FailingTypeReader(Reader):
    def read(self, address: int, size: int, label: str) -> bytes:
        if label == "country_forces.unit_type.type[0].string_bytes":
            raise AssertionError("synthetic type string read failure")
        return super().read(address, size, label)


def _fullref(tag: str, slot: int) -> int:
    return (slot << 32) | int.from_bytes(tag.encode("ascii"), "little")


def _type_file_guard(profile):
    records = {}
    checks = {}
    for name, rva, end, raw in memory._profile_code_guards(profile):
        digest = hashlib.sha256(raw).hexdigest()
        records[name] = {
            "rva": hex(rva), "rva_end_exclusive": hex(end),
            "expected_hex": raw.hex(), "actual_hex": raw.hex(),
            "expected_sha256": digest, "actual_sha256": digest,
        }
        checks[name] = True
    return {"status": "observed", "path": "synthetic-eu4.exe",
            "checks": checks, "records": records, "unknown_conditions": []}


def _reader(reader_type=Reader, *, bad_vptr: bool = False):
    reader = reader_type()
    base_profile = memory._load_profile()
    for _name, rva, _end, raw in memory._profile_code_guards(base_profile):
        reader.put(MODULE_BASE + rva, raw)
    type_profile = memory._load_type_profile()
    for _name, rva, _end, raw in memory._profile_code_guards(type_profile):
        reader.put(MODULE_BASE + rva, raw)

    base_layout = memory._profile_layout(base_profile)
    reader.qword(MODULE_BASE + base_layout["database_global_rva"], DATABASE)
    reader.qword(DATABASE + base_layout["database_table_offset"], TABLE)
    reader.i32(DATABASE + base_layout["database_table_count_offset"], 6)
    for slot in range(6):
        reader.qword(TABLE + slot * 8, COUNTRY if slot == 5 else 0)
    reader.qword(COUNTRY + base_layout["country_fullref_offset"], _fullref("FRA", 5))
    reader.qword(MODULE_BASE + base_layout["game_global_rva"], GAME)
    reader.i32(GAME + base_layout["game_date_offset"], 56562768)
    reader.qword(COUNTRY + base_layout["country_group_offset"], GROUP_HEAD)
    reader.qword(GROUP_HEAD + base_layout["group_object_offset"], GROUP_OBJECT)
    reader.qword(GROUP_HEAD + base_layout["group_next_offset"], 0)
    reader.qword(GROUP_OBJECT + base_layout["group_vector_begin_offset"], VECTOR)
    reader.qword(GROUP_OBJECT + base_layout["group_vector_end_offset"], VECTOR + 16)
    for index, pointer in enumerate(RECORDS):
        reader.qword(VECTOR + index * 8, pointer)

    type_profile_layout = memory._type_profile_layout(type_profile)
    vtable = MODULE_BASE + type_profile_layout["type_vtable_rva"]
    member = MODULE_BASE + type_profile_layout["member_rva"]
    reader.qword(vtable + type_profile_layout["vtable_member_offset"], member)
    for index, (record_pointer, type_pointer, kind, strength) in enumerate(zip(
            RECORDS, TYPES, (0, 3), (981, 670))):
        body = bytearray(0x30)
        body[0x10:0x14] = (55).to_bytes(4, "little")
        body[0x14:0x18] = (13512 + index).to_bytes(4, "little")
        body[0x20:0x28] = type_pointer.to_bytes(8, "little")
        body[0x28:0x2C] = strength.to_bytes(4, "little", signed=True)
        reader.put(record_pointer, bytes(body))
        reader.i32(type_pointer + base_layout["type_kind_offset"], kind)
        reader.qword(type_pointer, vtable ^ (1 if bad_vptr and index == 0 else 0))
        if index == 0:
            reader.qword(type_pointer + 0x78, 15)
            reader.put(type_pointer + 0x60, b"infantry\x00" + b"\x00" * 7)
        else:
            reader.qword(type_pointer + 0x78, 20)
            reader.qword(type_pointer + 0x60, HEAP_KEY)
            reader.put(HEAP_KEY, b"cavalry_reinforce\x00" + b"\x00" * 3)
    return reader


def _fake_capture_environment(monkeypatch, reader):
    class FakeKernel:
        def OpenProcess(self, _mask, _inherit, _pid):
            return object()

        def CloseHandle(self, _handle):
            return True

    def fake_identity(report, _document, _kernel, _handle):
        report["identity"].update({
            "installation_pid": 101,
            "installation_creation_filetime": CREATION,
            "installation_session_id": SESSION,
            "process_creation_filetime": CREATION,
            "process_path": "synthetic-eu4.exe",
            "process_path_sha256": memory.EXPECTED_EXE_SHA256,
            "process_path_sha256_matches_expected": True,
            "process_creation_matches_installation": True,
            "module_path": "synthetic-eu4.exe",
            "module_path_matches_process": True,
            "binding_verified": True,
        })
        return MODULE_BASE

    monkeypatch.setattr(memory, "_load_installation", lambda _path: {
        "pid": 101, "creation_filetime": CREATION, "session_id": SESSION,
        "game_sha256": memory.EXPECTED_EXE_SHA256,
    })
    monkeypatch.setattr(memory, "_configure_kernel", lambda: FakeKernel())
    monkeypatch.setattr(memory, "_capture_identity", fake_identity)
    monkeypatch.setattr(memory, "_file_code_guard", lambda _path, _profile=None: {
        "status": "observed", "checks": {"synthetic": True},
    })
    monkeypatch.setattr(memory, "_type_file_code_guard", lambda _path, profile=None: _type_file_guard(profile))
    monkeypatch.setattr(memory, "AddressBoundedRPM", lambda _kernel, _handle, _base: reader)


def _capture_context():
    return {"session_id": SESSION, "game_sha256": memory.EXPECTED_EXE_SHA256,
            "game_date": 56562768}


def test_opt_in_capture_reads_inline_and_heap_keys_with_private_validated_proofs(monkeypatch):
    reader = _reader()
    _fake_capture_environment(monkeypatch, reader)
    report = memory.capture(Path("synthetic-installation.json"), include_type_keys=True)
    assert report["status"] == "observed", report["errors"]
    assert report["type_key_enhancement"]["status"] == "observed"
    assert report["type_key_enhancement"]["cross_pass_consistent"] is True
    rows = report["after"]["record"]["records"]
    assert [row["unit_type"] for row in rows] == [
        {"status": "known", "key": "infantry"},
        {"status": "known", "key": "cavalry_reinforce"},
    ]
    assert [row["unit_type_proof"]["storage"] for row in rows] == ["inline", "heap"]
    assert all("unit_type_proof" not in row
               for row in report["fields"][memory.FIELD_KEY]["value"])
    assert max(item["size"] for item in report["after"]["record"]["observation"]["read_log"]
               if item["label"].startswith("country_forces.unit_type.type[")) <= 129
    assert report["access"]["rpm_bytes_requested"] <= memory.READ_BUDGET_BYTES
    assert memory.validate_capture(report, _capture_context(), CREATION)

    tampered = deepcopy(report)
    tampered["after"]["record"]["records"][0]["unit_type"]["key"] = "cavalry"
    assert not memory.validate_capture(tampered, _capture_context(), CREATION)
    no_envelope = deepcopy(report)
    no_envelope.pop("type_key_enhancement")
    assert not memory.validate_capture(no_envelope, _capture_context(), CREATION)


@pytest.mark.parametrize("reader_type,bad_vptr", [
    (FailingTypeReader, False),
    (Reader, True),
])
def test_type_key_failure_is_local_and_keeps_force_rows(monkeypatch, reader_type, bad_vptr):
    reader = _reader(reader_type, bad_vptr=bad_vptr)
    _fake_capture_environment(monkeypatch, reader)
    report = memory.capture(Path("synthetic-installation.json"), include_type_keys=True)
    assert report["status"] == "observed", report["errors"]
    assert report["fields"][memory.FIELD_KEY]["status"] == "known"
    assert len(report["fields"][memory.FIELD_KEY]["value"]) == 2
    first = report["after"]["record"]["records"][0]
    assert first["unit_type"] == {"status": "unknown", "reason": (
        "UNIT_TYPE_READ_FAILED" if reader_type is FailingTypeReader else "UNIT_TYPE_VPTR_MISMATCH")}
    assert memory.validate_capture(report, _capture_context(), CREATION)


def test_type_key_change_between_passes_is_unknown_without_retracting_raw_records(monkeypatch):
    reader = _reader(ChangingTypeReader)
    _fake_capture_environment(monkeypatch, reader)
    report = memory.capture(Path("synthetic-installation.json"), include_type_keys=True)
    assert report["status"] == "observed", report["errors"]
    assert report["doublepass"]["consistent"] is True
    assert report["type_key_enhancement"]["cross_pass_consistent"] is False
    assert report["type_key_enhancement"]["status"] == "partial"
    before = report["before"]["record"]["records"][0]
    after = report["after"]["record"]["records"][0]
    assert before["unit_type"] == after["unit_type"] == {
        "status": "unknown", "reason": "UNIT_TYPE_CHANGED_BETWEEN_PASSES",
    }
    assert [(row["id"], row["strength_raw"]) for row in report["fields"][memory.FIELD_KEY]["value"]] == [
        (13512, 981), (13513, 670),
    ]
    assert memory.validate_capture(report, _capture_context(), CREATION)


@pytest.mark.parametrize("capacity,raw,reason", [
    (15, b"x" * 16, "UNIT_TYPE_KEY_NUL_MISSING"),
    (15, b"\x00" * 16, "UNIT_TYPE_KEY_EMPTY"),
    (15, b"\xff\x00" + b"\x00" * 14, "UNIT_TYPE_KEY_NOT_ASCII"),
    (15, b"bad/key\x00" + b"\x00" * 8, "UNIT_TYPE_KEY_INVALID"),
    (4097, b"", "UNIT_TYPE_CAPACITY_INVALID"),
])
def test_invalid_type_string_is_isolated_and_capture_remains_valid(monkeypatch, capacity, raw, reason):
    reader = _reader()
    reader.qword(TYPES[0] + 0x78, capacity)
    if raw:
        reader.put(TYPES[0] + 0x60, raw)
    _fake_capture_environment(monkeypatch, reader)
    report = memory.capture(Path("synthetic-installation.json"), include_type_keys=True)
    assert report["status"] == "observed"
    row = report["before"]["record"]["records"][0]
    assert row["unit_type"] == {"status": "unknown", "reason": reason}
    assert row["strength_raw"] == 981
    assert memory.validate_capture(report, _capture_context(), CREATION)


def test_heap_type_key_accepts_exact_128_byte_limit(monkeypatch):
    reader = _reader()
    reader.qword(TYPES[1] + 0x78, 128)
    reader.put(HEAP_KEY, b"x" * 128 + b"\x00")
    _fake_capture_environment(monkeypatch, reader)
    report = memory.capture(Path("synthetic-installation.json"), include_type_keys=True)
    assert report["status"] == "observed"
    assert report["before"]["record"]["records"][1]["unit_type"] == {
        "status": "known", "key": "x" * 128}
    assert memory.validate_capture(report, _capture_context(), CREATION)


def test_shared_type_is_read_once_per_pass_and_rechecked_next_pass(monkeypatch):
    reader = _reader()
    reader.qword(RECORDS[1] + 0x20, TYPES[0])
    _fake_capture_environment(monkeypatch, reader)
    report = memory.capture(Path("synthetic-installation.json"), include_type_keys=True)
    assert report["status"] == "observed"
    for snapshot in (report["before"], report["after"]):
        reads = snapshot["record"]["observation"]["read_log"]
        assert sum(row["label"].endswith(".string_bytes") for row in reads) == 1
        assert [row["unit_type"]["key"] for row in snapshot["record"]["records"]] == ["infantry"] * 2
    assert memory.validate_capture(report, _capture_context(), CREATION)


def test_type_runtime_code_drift_preserves_original_force_records(monkeypatch):
    reader = _reader()
    profile = memory._load_type_profile()
    _name, rva, _end, expected = next(iter(memory._profile_code_guards(profile)))
    reader.put(MODULE_BASE + rva, bytes([expected[0] ^ 1]) + expected[1:])
    _fake_capture_environment(monkeypatch, reader)
    report = memory.capture(Path("synthetic-installation.json"), include_type_keys=True)
    assert report["status"] == "observed"
    rows = report["before"]["record"]["records"]
    assert [row["strength_raw"] for row in rows] == [981, 670]
    assert all(row["unit_type"]["status"] == "unknown" for row in rows)
    assert memory.validate_capture(report, _capture_context(), CREATION)


def test_invalid_type_profile_preserves_default_force_capture(monkeypatch):
    reader = _reader()
    _fake_capture_environment(monkeypatch, reader)

    def invalid_profile(*args, **kwargs):
        raise memory.ProfileError("synthetic profile mismatch")

    monkeypatch.setattr(memory, "_load_type_profile", invalid_profile)
    report = memory.capture(Path("synthetic-installation.json"), include_type_keys=True)
    assert report["status"] == "observed"
    assert report["type_key_enhancement"]["profile_status"] == "unknown"
    rows = report["before"]["record"]["records"]
    assert [row["strength_raw"] for row in rows] == [981, 670]
    assert all(row["unit_type"] == {"status": "unknown", "reason": "UNIT_TYPE_PROFILE_INVALID"}
               for row in rows)
    assert memory.validate_capture(report, _capture_context(), CREATION)


def test_galley_record_uses_existing_type_key_and_strength_reader(monkeypatch):
    reader = _reader()
    reader.i32(TYPES[1] + 0x10, 5)
    reader.put(HEAP_KEY, b"galley\x00" + b"\x00" * 14)
    _fake_capture_environment(monkeypatch, reader)
    report = memory.capture(Path("synthetic-installation.json"), include_type_keys=True)
    assert memory.validate_capture(report, _capture_context(), CREATION)
    from bridge.information.country_forces import _projection
    fields = _projection(report["before"]["record"]["records"])
    assert fields["navy_size"]["value"] == 1
    galley = fields["navy_composition"]["value"][2]
    assert galley["native_kind"] == 5 and galley["category"] == "galley"
    assert galley["count"] == 1 and galley["strength"]["raw"] == 670
    assert galley["record_strengths"]["raw_values"] == [670]
    assert galley["unit_types"]["value"][0]["key"] == "galley"
