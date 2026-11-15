"""Fake-process regression tests for the bounded country-resource reader.

The fixture below models only the audited pointer chain.  It deliberately
never starts EU4: ``capture`` is exercised through the same seams that the
native adapter uses, while every read still goes through
``AddressBoundedRPM`` and the two-pass comparison.
"""
from __future__ import annotations

import ctypes as C
import hashlib
import json
from pathlib import Path

import pytest

from bridge.information import country_resources_memory as crm


MODULE_BASE = 0x140000000
GAME_POINTER = 0x200000
DATABASE_POINTER = 0x300000
COUNTRY_TABLE = 0x400000
COUNTRY_POINTER = 0x500000
COUNTRY_INDEX = 122
HANDLE = 0x1234


def _profile() -> dict[str, object]:
    return {
        "profile_id": "country-resources-memory-1374",
        "game_version": crm.EXPECTED_VERSION,
        "executable": {"sha256": crm.EXPECTED_EXE_SHA256},
        "globals": {
            "database_rva": hex(crm._loc.DATABASE_RVA),
            "game_rva": hex(crm._loc.GAME_RVA),
            "game_date_offset": hex(crm._loc.GAME_DATE_OFFSET),
        },
        "country": {
            "supported_country": "FRA",
            "table_offset": hex(crm._loc.COUNTRY_TABLE_OFFSET),
            "handle_offset": hex(crm._loc.COUNTRY_HANDLE_OFFSET),
            "country_scan_entries": crm._loc.COUNTRY_SCAN_ENTRIES,
        },
        "powers": {
            "administrative_offset": "0x100",
            "diplomatic_offset": "0x104",
            "military_offset": "0x108",
            "component_width": 4,
            "signed": True,
            "scale": 1,
        },
        "code_guards": [
            {"name": "resource_reader_guard", "rva": "0x1000", "hex": "aabbccdd"},
            {"name": "resource_pointer_guard", "rva": "0x2000", "hex": "11223344"},
        ],
        "provenance": {
            "dependencies": [
                {
                    "path": "bridge/information/mission_memory.py",
                    "sha256": crm._sha256_file(Path(crm._mm.__file__)),
                },
            ]
        },
    }


class FakeKernel:
    """Sparse ReadProcessMemory implementation with observable cleanup."""

    def __init__(
        self,
        *,
        close_result: bool = True,
        short_read: bool = False,
        memory: dict[int, int] | None = None,
    ):
        self.close_result = close_result
        self.short_read = short_read
        self.memory = memory if memory is not None else {}
        self.read_calls: list[tuple[int, int]] = []
        self.closed: list[int] = []

    def OpenProcess(self, _access: int, _inherit: bool, _pid: int) -> int:
        return HANDLE

    def ReadProcessMemory(
        self, _handle: int, address: object, buffer: object, size: int, actual: object
    ) -> bool:
        value = int(getattr(address, "value", address))
        self.read_calls.append((value, size))
        raw = bytes(self.memory.get(value + offset, 0) for offset in range(size))
        C.memmove(buffer, raw, size)
        getattr(actual, "_obj").value = size - 1 if self.short_read else size
        return True

    def CloseHandle(self, handle: int) -> bool:
        self.closed.append(int(handle))
        return self.close_result


def _put(memory: dict[int, int], address: int, raw: bytes) -> None:
    memory.update({address + offset: value for offset, value in enumerate(raw)})


def _put_qword(memory: dict[int, int], address: int, value: int) -> None:
    _put(memory, address, int(value).to_bytes(8, "little", signed=False))


def _put_s32(memory: dict[int, int], address: int, value: int) -> None:
    _put(memory, address, int(value).to_bytes(4, "little", signed=True))


def _fixture_memory(profile: dict[str, object]) -> dict[int, int]:
    memory: dict[int, int] = {}
    _put_qword(memory, MODULE_BASE + crm._loc.GAME_RVA, GAME_POINTER)
    _put_qword(memory, MODULE_BASE + crm._loc.DATABASE_RVA, DATABASE_POINTER)
    _put_s32(memory, GAME_POINTER + crm._loc.GAME_DATE_OFFSET, 56553384)

    table_address = DATABASE_POINTER + int(str(profile["country"]["table_offset"]), 0)  # type: ignore[index]
    _put_qword(memory, table_address, COUNTRY_TABLE)
    _put_qword(memory, COUNTRY_TABLE + COUNTRY_INDEX * 8, COUNTRY_POINTER)
    handle = (COUNTRY_INDEX << 32) | int.from_bytes(b"FRA", "little")
    _put_qword(memory, COUNTRY_POINTER + crm._loc.COUNTRY_HANDLE_OFFSET, handle)

    powers = profile["powers"]  # type: ignore[index]
    for name, value in (("administrative_offset", -12), ("diplomatic_offset", 0), ("military_offset", 345)):
        offset = int(str(powers[name]), 0)  # type: ignore[index]
        _put_s32(memory, COUNTRY_POINTER + offset, value)

    for _name, rva, expected in crm._profile_code_guards(profile):
        _put(memory, MODULE_BASE + rva, expected)
    return memory


def _observed_file_guard(profile: dict[str, object]) -> dict[str, object]:
    checks = {name: True for name, _rva, _expected in crm._profile_code_guards(profile)}
    return {"status": "observed", "checks": checks, "records": {}, "unknown_conditions": []}


def _identity(report: dict[str, object], _document: dict[str, object], _kernel: object, _handle: object) -> int:
    identity = report["identity"]
    assert isinstance(identity, dict)
    identity.update(
        {
            "installation_pid": 123,
            "installation_creation_filetime": 987,
            "installation_session_id": "fake-session",
            "process_path": "fake-eu4.exe",
            "process_path_sha256": crm.EXPECTED_EXE_SHA256,
            "process_path_sha256_matches_expected": True,
            "process_creation_filetime": 987,
            "process_creation_matches_installation": True,
            "module_path": "fake-eu4.exe",
            "module_path_matches_process": True,
            "binding_verified": True,
        }
    )
    return MODULE_BASE


@pytest.fixture
def capture_setup(monkeypatch: pytest.MonkeyPatch):
    profile = _profile()
    kernel = FakeKernel(memory=_fixture_memory(profile))
    document = {
        "pid": 123,
        "creation_filetime": 987,
        "game_sha256": crm.EXPECTED_EXE_SHA256,
        "session_id": "fake-session",
    }
    monkeypatch.setattr(crm, "PROFILE", profile)
    monkeypatch.setattr(crm, "_load_profile", lambda *args, **kwargs: profile)
    monkeypatch.setattr(crm, "_load_installation", lambda _path: document)
    monkeypatch.setattr(crm, "_configure_kernel", lambda: kernel)
    monkeypatch.setattr(crm, "_capture_identity", _identity)
    monkeypatch.setattr(crm, "_file_code_guard", lambda _path: _observed_file_guard(profile))
    return profile, kernel


def _capture(setup: tuple[dict[str, object], FakeKernel]) -> dict[str, object]:
    _profile_value, _kernel = setup
    return crm.capture(Path("fake-installation.json"), "FRA")


def test_static_contract_and_full_capture_keep_identity_and_signed_values(capture_setup):
    profile, kernel = capture_setup
    contract = crm._static_contract_guard()
    assert contract["status"] == "observed"
    assert all(value is True for value in contract["checks"].values())

    report = _capture(capture_setup)
    assert report["status"] == "observed"
    assert report["completed"] is True
    assert report["country"] == "FRA"
    assert report["read_only"] is True
    assert report["native_function_invoked"] is False
    assert report["values"] == {"administrative": -12, "diplomatic": 0, "military": 345}
    assert report["unit"] == "monarch_points"
    assert report["scale"] == 1
    assert report["identity"]["binding_verified"] is True
    assert report["identity"]["installation_session_id"] == "fake-session"
    assert report["file_code_guard"]["status"] == "observed"
    assert report["runtime_code_guard"]["status"] == "observed"
    assert report["doublepass"]["performed"] is True
    assert report["doublepass"]["consistent"] is True
    assert report["doublepass"]["mismatches"] == []
    assert report["doublepass"]["atomic"] is False
    assert report["doublepass"]["atomic_main_thread_snapshot"] is False
    assert report["world_generation_verified"] is False
    assert report["captured_at"] == report["captured_at_utc"]
    assert report["captured_at_utc"].endswith("+00:00")
    assert report["cleanup"]["handle_close"]["status"] == "closed"
    assert kernel.closed == [HANDLE]

    before = report["before"]
    after = report["after"]
    assert before["status"] == after["status"] == "observed"
    assert before["game_date"]["value"] == after["game_date"]["value"] == 56553384
    assert before["values"] == after["values"] == report["values"]
    labels = {entry["label"] for entry in before["read_log"]}
    assert "code_guard.resource_reader_guard" in labels
    assert "database.country_table" in labels
    assert "country_table.first_bounded_window" in labels
    assert "country[122].handle" in labels
    assert "game.game_date" in labels
    assert {f"country.{field}" for field in crm.POWER_FIELDS} <= labels
    assert all(entry["status"] == "observed" for entry in before["read_log"])
    assert profile["country"]["supported_country"] == "FRA"


def test_static_contract_rejects_changed_dependency_bytes(capture_setup):
    profile, _kernel = capture_setup
    profile["provenance"]["dependencies"] = [{
        "path": crm.PROFILE_FILE.relative_to(Path(__file__).resolve().parents[2]).as_posix(),
        "sha256": "b" * 64,
    }]
    contract = crm._static_contract_guard()
    assert contract["status"] == "unknown"
    assert contract["checks"]["provenance_dependencies"] is False
    assert any("dependency_sha256_mismatch" in item for item in contract["unknown_conditions"])


def test_historical_python_reference_does_not_reject_current_implementation(capture_setup, monkeypatch):
    profile, _kernel = capture_setup
    profile["provenance"]["dependencies"][0]["sha256"] = "b" * 64
    original_hash = crm._sha256_file

    def hash_data_only(path):
        assert path.suffix != ".py"
        return original_hash(path)

    monkeypatch.setattr(crm, "_sha256_file", hash_data_only)
    contract = crm._static_contract_guard()
    assert contract["status"] == "observed"
    assert contract["dependency_hash_checks"] == {}


def test_static_guard_rechecks_profile_bytes_after_import(monkeypatch, tmp_path):
    profile = _profile()
    raw = json.dumps(profile, sort_keys=True, separators=(",", ":")).encode("utf-8")
    path = tmp_path / "country-resources-memory-1374.json"
    path.write_bytes(raw)
    digest = hashlib.sha256(raw).hexdigest()
    monkeypatch.setattr(crm, "PROFILE_FILE", path)
    monkeypatch.setattr(crm, "EXPECTED_PROFILE_SHA256", digest)
    monkeypatch.setattr(crm, "PROFILE", crm._load_profile(path, digest))

    assert crm._static_contract_guard()["status"] == "observed"
    path.write_bytes(raw + b"\n")
    changed = crm._static_contract_guard()
    assert changed["status"] == "unknown"
    assert any("profile_sha256_mismatch" in item for item in changed["unknown_conditions"])


def test_file_code_guard_reads_profile_rvas_and_rejects_changed_bytes(monkeypatch):
    profile = _profile()
    monkeypatch.setattr(crm, "PROFILE", profile)
    expected = {(rva, len(raw)): raw for _name, rva, raw in crm._profile_code_guards(profile)}
    calls: list[tuple[int, int]] = []

    def read_pe(_path, rva, size):
        calls.append((rva, size))
        return expected[(rva, size)]

    monkeypatch.setattr(crm, "_read_pe_rva_bytes", read_pe)
    observed = crm._file_code_guard(Path("fake-eu4.exe"))
    assert observed["status"] == "observed"
    assert calls == [(rva, len(raw)) for _name, rva, raw in crm._profile_code_guards(profile)]

    bad_rva, bad_size = calls[0]
    def read_bad_pe(_path, rva, size):
        if (rva, size) == (bad_rva, bad_size):
            return b"\x00" * size
        return expected[(rva, size)]

    monkeypatch.setattr(crm, "_read_pe_rva_bytes", read_bad_pe)
    mismatched = crm._file_code_guard(Path("fake-eu4.exe"))
    assert mismatched["status"] == "mismatch"
    assert mismatched["checks"][crm._profile_code_guards(profile)[0][0]] is False


def test_invalid_global_pointer_fails_before_derived_address_reads(capture_setup):
    _profile_value, kernel = capture_setup
    _put_qword(kernel.memory, MODULE_BASE + crm._loc.GAME_RVA, crm.MAX_USER_ADDRESS)
    report = _capture(capture_setup)
    assert report["status"] == "unknown"
    assert report["completed"] is False
    assert report["values"] is None
    assert report["before"]["status"] == "unknown"
    assert "game_or_database_pointer_invalid" in report["before"]["unknown_reason"]
    labels = {entry["label"] for entry in report["before"]["read_log"]}
    assert "game.game_date" not in labels
    assert "database.country_table" not in labels
    assert report["cleanup"]["handle_close"]["status"] == "closed"


def test_short_read_retracts_values_and_closes_handle(capture_setup, monkeypatch):
    profile, kernel = capture_setup
    short_kernel = FakeKernel(short_read=True, memory=kernel.memory)
    monkeypatch.setattr(crm, "_configure_kernel", lambda: short_kernel)
    monkeypatch.setattr(crm, "_file_code_guard", lambda _path: _observed_file_guard(profile))
    report = _capture(capture_setup)
    assert report["status"] == "unknown"
    assert report["completed"] is False
    assert report["values"] is None
    assert report["before"]["status"] == "unknown"
    assert report["before"]["unknown_reason"].startswith("runtime_code_guard_failed")
    assert short_kernel.closed == [HANDLE]


def test_address_reader_rejects_low_overflow_and_single_read_limits():
    kernel = FakeKernel()
    reader = crm.AddressBoundedRPM(kernel, HANDLE, MODULE_BASE)

    with pytest.raises(crm.ProbeError, match="invalid_address"):
        reader.read(0xFFFF, 1, "low")
    with pytest.raises(crm.ProbeError, match="address_range_overflow"):
        reader.read(crm.MAX_USER_ADDRESS - 1, 2, "overflow")
    with pytest.raises(crm.ProbeError, match="invalid_size"):
        reader.read(0x10000, crm.MAX_SINGLE_RPM + 1, "single")
    assert kernel.read_calls == []
    assert [entry["reason"] for entry in reader.read_log] == [
        "invalid_address",
        "address_range_overflow",
        "invalid_size",
    ]


def test_address_reader_enforces_total_budget_and_logs_raw_reads():
    kernel = FakeKernel()
    _put(kernel.memory, 0x10000, b"abcd")
    reader = crm.AddressBoundedRPM(kernel, HANDLE, MODULE_BASE)
    assert reader.read(0x10000, 4, "first") == b"abcd"
    assert reader.bytes_requested == 4
    assert reader.calls == 1
    assert reader.read_log[-1]["raw_hex"] == "61626364"

    reader.bytes_requested = crm.MAX_TOTAL_RPM - 1
    with pytest.raises(crm.ProbeError, match="RPM_TOTAL_BUDGET_EXCEEDED"):
        reader.read(0x10000, 2, "budget")
    assert reader.calls == 1
    assert reader.read_log[-1]["status"] == "rejected"
    assert reader.read_log[-1]["reason"] == "RPM_TOTAL_BUDGET_EXCEEDED"


def test_date_change_is_seen_in_doublepass_and_retracts_values(capture_setup, monkeypatch):
    _profile_value, kernel = capture_setup
    original = crm._snapshot
    calls = 0

    def changing(reader, module_base, country, profile):
        nonlocal calls
        snapshot = original(reader, module_base, country, profile)
        calls += 1
        if calls == 1:
            _put_s32(kernel.memory, GAME_POINTER + crm._loc.GAME_DATE_OFFSET, 56553385)
        return snapshot

    monkeypatch.setattr(crm, "_snapshot", changing)
    report = _capture(capture_setup)
    assert report["status"] == "doublepass_mismatch"
    assert report["completed"] is False
    assert report["values"] is None
    assert report["doublepass"]["consistent"] is False
    assert any(path.startswith("$.game_date") for path in report["doublepass"]["mismatches"])
    assert report["before"]["values"] is None
    assert report["after"]["values"] is None


def test_power_raw_change_is_seen_in_doublepass_and_retracts_values(capture_setup, monkeypatch):
    profile, kernel = capture_setup
    original = crm._snapshot
    calls = 0
    military_offset = int(str(profile["powers"]["military_offset"]), 0)

    def changing(reader, module_base, country, active_profile):
        nonlocal calls
        snapshot = original(reader, module_base, country, active_profile)
        calls += 1
        if calls == 1:
            _put_s32(kernel.memory, COUNTRY_POINTER + military_offset, 346)
        return snapshot

    monkeypatch.setattr(crm, "_snapshot", changing)
    report = _capture(capture_setup)
    assert report["status"] == "doublepass_mismatch"
    assert report["values"] is None
    assert report["doublepass"]["consistent"] is False
    assert any(path.startswith("$.values") or path.startswith("$.value_raw_hex") for path in report["doublepass"]["mismatches"])


def test_runtime_code_guard_change_is_logged_and_retracts_values(capture_setup, monkeypatch):
    _profile_value, kernel = capture_setup
    original = crm._snapshot
    calls = 0

    def changing(reader, module_base, country, profile):
        nonlocal calls
        snapshot = original(reader, module_base, country, profile)
        calls += 1
        if calls == 1:
            kernel.memory[module_base + 0x1000] ^= 1
        return snapshot

    monkeypatch.setattr(crm, "_snapshot", changing)
    report = _capture(capture_setup)
    assert report["status"] == "doublepass_mismatch"
    assert report["values"] is None
    assert report["doublepass"]["consistent"] is False
    assert report["doublepass"]["mismatches"] == ["$.after.status"]
    assert report["after"]["status"] == "unknown"
    assert report["after"]["runtime_code_guard"]["status"] == "mismatch"
    assert report["cleanup"]["handle_close"]["status"] == "closed"


def test_cleanup_failure_retracts_an_observation(capture_setup, monkeypatch):
    profile, kernel = capture_setup
    failing_kernel = FakeKernel(close_result=False, memory=kernel.memory)
    monkeypatch.setattr(crm, "_configure_kernel", lambda: failing_kernel)
    monkeypatch.setattr(crm, "_file_code_guard", lambda _path: _observed_file_guard(profile))
    report = _capture(capture_setup)
    assert report["status"] == "cleanup_error"
    assert report["completed"] is False
    assert report["values"] is None
    assert report["before"]["values"] is None
    assert report["after"]["values"] is None
    assert report["cleanup"]["handle_close"]["status"] == "error"
    assert failing_kernel.closed == [HANDLE]


def test_identity_failure_closes_handle_and_publishes_no_values(capture_setup, monkeypatch):
    _profile_value, kernel = capture_setup
    monkeypatch.setattr(crm, "_capture_identity", lambda *_args: (_ for _ in ()).throw(crm.ProbeError("identity_mismatch")))
    report = _capture(capture_setup)
    assert report["status"] == "error"
    assert report["values"] is None
    assert report["completed"] is False
    assert report["cleanup"]["handle_close"]["status"] == "closed"
    assert kernel.closed == [HANDLE]

