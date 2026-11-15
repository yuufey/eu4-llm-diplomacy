"""Fake-process coverage for the bounded domestic-pressure RPM reader.

The fixture models only the profile-driven pointer chain.  It never starts
EU4 and replaces the Windows identity seams, while every value read still
passes through ``AddressBoundedRPM`` and the production two-pass comparison.
"""
from __future__ import annotations

import ctypes as C
from pathlib import Path

import pytest

from bridge.information import domestic_pressure_memory as dpm


MODULE_BASE = 0x140000000
GAME_POINTER = 0x200000
DATABASE_POINTER = 0x300000
COUNTRY_TABLE = 0x400000
COUNTRY_POINTER = 0x500000
SAVE_TOKEN_VECTOR = 0x600000
COUNTRY_INDEX = 2
HANDLE = 0x777


def _profile() -> dict[str, object]:
    return {
        "profile_id": "domestic-pressure-memory-1374",
        "game_version": dpm.EXPECTED_VERSION,
        "executable": {"sha256": dpm.EXPECTED_EXE_SHA256},
        "globals": {"database_rva": "0x200", "game_rva": "0x208", "game_date_offset": "0x20"},
        "country": {"supported_country": "FRA", "table_offset": "0x10", "handle_offset": "0x20", "country_scan_entries": 4},
        "scalars": {
            "stability": {"offset": "0x30", "width": 4, "signed": True, "scale": 1000, "unit": "stability"},
            "war_exhaustion": {"offset": "0x34", "width": 4, "signed": True, "scale": 1000, "unit": "war_exhaustion"},
            "corruption": {"offset": "0x38", "width": 4, "signed": True, "scale": 1000, "unit": "corruption"},
        },
        "save_tokens": {
            "vector_rva": "0x400",
            "tokens": {
                "stability": {"key_id": 10374, "name": "stability"},
                "war_exhaustion": {"key_id": 10009, "name": "war_exhaustion"},
                "corruption": {"key_id": 13297, "name": "corruption"},
            },
        },
        "code_guards": [
            {"name": "domestic_reader_guard", "rva": "0x1000", "hex": "aabbccdd"},
            {"name": "domestic_scalar_guard", "rva": "0x2000", "hex": "11223344"},
        ],
        "provenance": {"dependencies": [{"path": "bridge/information/domestic_pressure_memory.py", "sha256": dpm._sha256_file(Path(dpm.__file__))}]},
    }


class FakeKernel:
    """Sparse ReadProcessMemory implementation with controllable failures."""

    def __init__(self, *, memory: dict[int, int] | None = None, close_result: bool = True, short_addresses: set[int] | None = None):
        self.memory = memory if memory is not None else {}
        self.close_result = close_result
        self.short_addresses = short_addresses or set()
        self.read_calls: list[tuple[int, int]] = []
        self.closed: list[int] = []

    def OpenProcess(self, _access: int, _inherit: bool, _pid: int) -> int:
        return HANDLE

    def ReadProcessMemory(self, _handle: int, address: object, buffer: object, size: int, actual: object) -> bool:
        value = int(getattr(address, "value", address))
        self.read_calls.append((value, size))
        raw = bytes(self.memory.get(value + offset, 0) for offset in range(size))
        C.memmove(buffer, raw, size)
        getattr(actual, "_obj").value = size - 1 if value in self.short_addresses else size
        return True

    def CloseHandle(self, handle: int) -> bool:
        self.closed.append(int(handle))
        return self.close_result


def _put(memory: dict[int, int], address: int, raw: bytes) -> None:
    memory.update({address + index: value for index, value in enumerate(raw)})


def _put_qword(memory: dict[int, int], address: int, value: int) -> None:
    _put(memory, address, int(value).to_bytes(8, "little", signed=False))


def _put_s32(memory: dict[int, int], address: int, value: int) -> None:
    _put(memory, address, int(value).to_bytes(4, "little", signed=True))


def _put_string32_inline(memory: dict[int, int], address: int, text: str) -> None:
    payload = text.encode("ascii") + b"\x00"
    assert len(payload) <= 16
    header = bytearray(32)
    header[:len(payload)] = payload
    header[16:24] = len(text).to_bytes(8, "little")
    header[24:32] = len(text).to_bytes(8, "little")
    _put(memory, address, bytes(header))


def _profile_int(value: object) -> int:
    return int(str(value), 0)


def _fixture_memory(profile: dict[str, object]) -> dict[int, int]:
    memory: dict[int, int] = {}
    globals_ = profile["globals"]
    country = profile["country"]
    scalars = profile["scalars"]
    save_tokens = profile["save_tokens"]
    assert isinstance(globals_, dict) and isinstance(country, dict) and isinstance(scalars, dict) and isinstance(save_tokens, dict)
    _put_qword(memory, MODULE_BASE + _profile_int(globals_["game_rva"]), GAME_POINTER)
    _put_qword(memory, MODULE_BASE + _profile_int(globals_["database_rva"]), DATABASE_POINTER)
    _put_s32(memory, GAME_POINTER + _profile_int(globals_["game_date_offset"]), 56553384)
    _put_qword(memory, DATABASE_POINTER + _profile_int(country["table_offset"]), COUNTRY_TABLE)
    _put_qword(memory, COUNTRY_TABLE + COUNTRY_INDEX * 8, COUNTRY_POINTER)
    handle = (COUNTRY_INDEX << 32) | int.from_bytes(b"FRA", "little")
    _put_qword(memory, COUNTRY_POINTER + _profile_int(country["handle_offset"]), handle)
    _put_qword(memory, MODULE_BASE + _profile_int(save_tokens["vector_rva"]), SAVE_TOKEN_VECTOR)
    tokens = save_tokens["tokens"]
    assert isinstance(tokens, dict)
    for field, token in tokens.items():
        assert isinstance(token, dict)
        _put_string32_inline(memory, SAVE_TOKEN_VECTOR + int(token["key_id"]) * 32, str(token["name"]))
    for field, value in (("stability", -12), ("war_exhaustion", 0), ("corruption", 345)):
        item = scalars[field]
        assert isinstance(item, dict)
        _put_s32(memory, COUNTRY_POINTER + _profile_int(item["offset"]), value)
    for _name, rva, expected in dpm._profile_code_guards(profile):
        _put(memory, MODULE_BASE + rva, expected)
    return memory


def _observed_file_guard(profile: dict[str, object]) -> dict[str, object]:
    checks = {name: True for name, _rva, _expected in dpm._profile_code_guards(profile)}
    return {"status": "observed", "checks": checks, "records": {}, "unknown_conditions": []}


def _identity(report: dict[str, object], _document: dict[str, object], _kernel: object, _handle: object) -> int:
    identity = report["identity"]
    assert isinstance(identity, dict)
    identity.update({"installation_pid": 123, "installation_creation_filetime": 987, "installation_session_id": "fake-session", "process_path": "fake-eu4.exe", "process_path_sha256": dpm.EXPECTED_EXE_SHA256, "process_path_sha256_matches_expected": True, "process_creation_filetime": 987, "process_creation_matches_installation": True, "module_path": "fake-eu4.exe", "module_path_matches_process": True, "binding_verified": True})
    return MODULE_BASE


@pytest.fixture
def capture_setup(monkeypatch: pytest.MonkeyPatch):
    profile = _profile()
    kernel = FakeKernel(memory=_fixture_memory(profile))
    document = {"pid": 123, "creation_filetime": 987, "game_sha256": dpm.EXPECTED_EXE_SHA256, "session_id": "fake-session"}
    monkeypatch.setattr(dpm, "PROFILE", profile)
    monkeypatch.setattr(dpm, "_load_profile", lambda *args, **kwargs: profile)
    monkeypatch.setattr(dpm, "_load_installation", lambda _path: document)
    monkeypatch.setattr(dpm, "_configure_kernel", lambda: kernel)
    monkeypatch.setattr(dpm, "_capture_identity", _identity)
    monkeypatch.setattr(dpm, "_file_code_guard", lambda _path, active_profile: _observed_file_guard(active_profile))
    return profile, kernel


def _capture(setup, fields=None):
    return dpm.capture(Path("fake-installation.json"), "FRA", fields)


def test_full_capture_publishes_profile_driven_signed_field_results(capture_setup):
    profile, kernel = capture_setup
    contract = dpm._static_contract_guard()
    assert contract["status"] == "observed"
    assert all(value is True for value in contract["checks"].values())

    report = _capture(capture_setup)
    assert report["status"] == "observed"
    assert report["completed"] is True
    assert report["complete"] is True
    assert report["values"] == {"stability": -12, "war_exhaustion": 0, "corruption": 345}
    assert report["read_only"] is True
    assert report["native_function_invoked"] is False
    assert report["identity"]["binding_verified"] is True
    assert report["file_code_guard"]["status"] == "observed"
    assert report["runtime_code_guard"]["status"] == "observed"
    assert report["save_token_guard"]["status"] == "observed"
    assert report["doublepass"]["performed"] is True
    assert report["doublepass"]["consistent"] is True
    assert report["cleanup"]["handle_close"]["status"] == "closed"
    assert kernel.closed == [HANDLE]
    assert report["before"]["field_results"] == report["after"]["field_results"] == report["field_results"]
    assert report["field_results"]["stability"]["unit"] == "stability"
    assert report["field_results"]["stability"]["scale"] == 1000
    assert report["captured_at"] == report["captured_at_utc"]
    assert report["world_generation_verified"] is False
    assert all(entry["status"] == "observed" for entry in report["before"]["read_log"])
    assert report["before"]["save_token_guard"]["checks"] == {field: True for field in dpm.FIELDS}
    labels = {entry["label"] for entry in report["before"]["read_log"]}
    assert "save_tokens.vector" in labels
    assert {f"save_token.{field}.String32" for field in dpm.FIELDS} <= labels


def test_partial_scalar_read_keeps_other_known_fields_without_zero_fill(capture_setup, monkeypatch):
    profile, kernel = capture_setup
    item = profile["scalars"]["corruption"]
    assert isinstance(item, dict)
    address = COUNTRY_POINTER + _profile_int(item["offset"])
    partial_kernel = FakeKernel(memory=kernel.memory, short_addresses={address})
    # The same deterministic short read occurs in both passes.
    monkeypatch.setattr(dpm, "_configure_kernel", lambda: partial_kernel)
    report = _capture((profile, partial_kernel))
    assert report["status"] == "observed"
    assert report["completed"] is True
    assert report["complete"] is False
    assert report["values"] == {"stability": -12, "war_exhaustion": 0}
    assert report["field_results"]["corruption"]["status"] == "unknown"
    assert "corruption" not in report["values"]
    assert report["doublepass"]["consistent"] is True
    assert any(entry["label"] == "country.corruption" and entry["status"] == "error" for entry in report["before"]["read_log"])


def test_stable_save_token_name_mismatch_retracts_only_its_field(capture_setup):
    profile, kernel = capture_setup
    tokens = profile["save_tokens"]["tokens"]
    assert isinstance(tokens, dict)
    stability = tokens["stability"]
    assert isinstance(stability, dict)
    _put_string32_inline(kernel.memory, SAVE_TOKEN_VECTOR + int(stability["key_id"]) * 32, "stabilitY")

    report = _capture(capture_setup)
    assert report["status"] == "observed"
    assert report["completed"] is True
    assert report["complete"] is False
    assert report["field_results"]["stability"]["status"] == "unknown"
    assert "save_token_guard_failed" in report["field_results"]["stability"]["reason"]
    assert set(report["values"]) == {"war_exhaustion", "corruption"}
    assert report["before"]["save_token_guard"]["checks"]["stability"] is False
    assert report["before"]["save_token_guard"]["checks"]["corruption"] is True


def test_save_token_name_change_between_passes_retracts_observation(capture_setup, monkeypatch):
    profile, kernel = capture_setup
    original = dpm._snapshot
    calls = 0
    tokens = profile["save_tokens"]["tokens"]
    assert isinstance(tokens, dict)
    war = tokens["war_exhaustion"]
    assert isinstance(war, dict)

    def changing(reader, module_base, country, active_profile, fields):
        nonlocal calls
        snapshot = original(reader, module_base, country, active_profile, fields)
        calls += 1
        if calls == 1:
            _put_string32_inline(kernel.memory, SAVE_TOKEN_VECTOR + int(war["key_id"]) * 32, "war_exhaustioX")
        return snapshot

    monkeypatch.setattr(dpm, "_snapshot", changing)
    report = _capture(capture_setup)
    assert report["status"] == "doublepass_mismatch"
    assert report["completed"] is False
    assert report["values"] is None
    assert any(path.startswith("$.save_token_guard") for path in report["doublepass"]["mismatches"])
    assert report["after"]["save_token_guard"]["checks"]["war_exhaustion"] is False


def test_invalid_save_token_profile_fails_static_guard(capture_setup):
    profile, _kernel = capture_setup
    tokens = profile["save_tokens"]["tokens"]
    assert isinstance(tokens, dict)
    tokens["stability"]["name"] = "wrong_name"  # type: ignore[index]
    contract = dpm._static_contract_guard()
    assert contract["status"] == "unknown"
    assert any("profile_save_token_name_mismatch" in item for item in contract["unknown_conditions"])


@pytest.mark.parametrize("change", ["field", "date", "code"])
def test_second_pass_change_retracts_all_values(capture_setup, monkeypatch, change):
    profile, kernel = capture_setup
    original = dpm._snapshot
    calls = 0

    def changing(reader, module_base, country, active_profile, fields):
        nonlocal calls
        snapshot = original(reader, module_base, country, active_profile, fields)
        calls += 1
        if calls == 1:
            if change == "field":
                scalar = active_profile["scalars"]["stability"]
                assert isinstance(scalar, dict)
                _put_s32(kernel.memory, COUNTRY_POINTER + _profile_int(scalar["offset"]), -11)
            elif change == "date":
                globals_ = active_profile["globals"]
                assert isinstance(globals_, dict)
                _put_s32(kernel.memory, GAME_POINTER + _profile_int(globals_["game_date_offset"]), 56553385)
            else:
                kernel.memory[MODULE_BASE + 0x1000] ^= 1
        return snapshot

    monkeypatch.setattr(dpm, "_snapshot", changing)
    report = _capture(capture_setup)
    assert report["status"] == "doublepass_mismatch"
    assert report["completed"] is False
    assert report["values"] is None
    assert report["complete"] is False
    assert report["doublepass"]["consistent"] is False
    assert report["before"]["values"] is None
    assert report["after"]["values"] is None
    if change == "date":
        assert any(path.startswith("$.game_date") for path in report["doublepass"]["mismatches"])
    elif change == "field":
        assert any(path.startswith("$.field_results") or path.startswith("$.values") for path in report["doublepass"]["mismatches"])
    else:
        assert report["after"]["status"] == "unknown"
        assert report["after"]["runtime_code_guard"]["status"] == "mismatch"


def test_request_bounds_and_country_are_rejected_before_open(capture_setup):
    _profile_value, kernel = capture_setup
    for fields in ([], ["stability", "stability"], ["not-a-field"], list(dpm.FIELDS) + ["stability"], "stability", 3):
        report = dpm.capture(Path("fake-installation.json"), "FRA", fields)  # type: ignore[arg-type]
        assert report["status"] == "invalid_request"
        assert report["completed"] is False
        assert report["cleanup"]["handle_close"]["status"] == "not_opened"
    report = dpm.capture(Path("fake-installation.json"), "SAV")
    assert report["status"] == "unsupported_country"
    assert report["completed"] is False
    assert kernel.closed == []


def test_default_fields_can_be_omitted(capture_setup):
    report = _capture(capture_setup, None)
    assert list(report["field_results"]) == list(dpm.FIELDS)


def test_address_reader_enforces_span_single_and_total_limits():
    kernel = FakeKernel()
    reader = dpm.AddressBoundedRPM(kernel, HANDLE, MODULE_BASE)
    with pytest.raises(dpm.ProbeError, match="invalid_address"):
        reader.read(0xFFFF, 1, "low")
    with pytest.raises(dpm.ProbeError, match="address_range_overflow"):
        reader.read(dpm.MAX_USER_ADDRESS - 1, 2, "overflow")
    with pytest.raises(dpm.ProbeError, match="invalid_size"):
        reader.read(0x10000, dpm.MAX_SINGLE_RPM + 1, "single")
    _put(kernel.memory, 0x10000, b"abcd")
    assert reader.read(0x10000, 4, "first") == b"abcd"
    reader.bytes_requested = dpm.MAX_TOTAL_RPM - 1
    with pytest.raises(dpm.ProbeError, match="RPM_TOTAL_BUDGET_EXCEEDED"):
        reader.read(0x10000, 2, "budget")
    assert reader.read_log[-1]["status"] == "rejected"
    assert reader.read_log[-1]["reason"] == "RPM_TOTAL_BUDGET_EXCEEDED"


def test_short_read_is_logged_as_reader_failure():
    address = 0x12000
    kernel = FakeKernel(short_addresses={address})
    _put(kernel.memory, address, b"abcd")
    reader = dpm.AddressBoundedRPM(kernel, HANDLE, MODULE_BASE)
    with pytest.raises(dpm.ProbeError, match="short_read"):
        reader.read(address, 4, "short")
    assert reader.read_log[-1]["status"] == "error"
    assert reader.read_log[-1]["error"].startswith("short_read")


def test_invalid_global_pointer_fails_before_derived_reads(capture_setup):
    profile, kernel = capture_setup
    globals_ = profile["globals"]
    assert isinstance(globals_, dict)
    _put_qword(kernel.memory, MODULE_BASE + _profile_int(globals_["game_rva"]), dpm.MAX_USER_ADDRESS)
    report = _capture(capture_setup)
    assert report["status"] == "unknown"
    assert report["completed"] is False
    assert report["values"] is None
    assert "game_or_database_pointer_invalid" in report["before"]["unknown_reason"]
    labels = {entry["label"] for entry in report["before"]["read_log"]}
    assert "game.game_date" not in labels
    assert "database.country_table" not in labels


def test_cleanup_failure_retracts_successful_observation(capture_setup, monkeypatch):
    profile, kernel = capture_setup
    failing = FakeKernel(memory=kernel.memory, close_result=False)
    monkeypatch.setattr(dpm, "_configure_kernel", lambda: failing)
    report = _capture(capture_setup)
    assert report["status"] == "cleanup_error"
    assert report["completed"] is False
    assert report["values"] is None
    assert report["before"]["values"] is None
    assert report["after"]["values"] is None
    assert report["cleanup"]["handle_close"]["status"] == "error"
    assert failing.closed == [HANDLE]


def test_identity_failure_closes_handle_and_publishes_no_values(capture_setup, monkeypatch):
    _profile_value, kernel = capture_setup
    monkeypatch.setattr(dpm, "_capture_identity", lambda *_args: (_ for _ in ()).throw(dpm.ProbeError("identity_mismatch")))
    report = _capture(capture_setup)
    assert report["status"] == "error"
    assert report["values"] is None
    assert report["completed"] is False
    assert report["cleanup"]["handle_close"]["status"] == "closed"
    assert kernel.closed == [HANDLE]


def test_unverified_identity_return_is_rejected(capture_setup, monkeypatch):
    _profile_value, kernel = capture_setup

    def unverified(report, _document, _kernel, _handle):
        report["identity"]["binding_verified"] = False
        return MODULE_BASE

    monkeypatch.setattr(dpm, "_capture_identity", unverified)
    report = _capture(capture_setup)
    assert report["status"] == "error"
    assert report["completed"] is False
    assert report["values"] is None
    assert any("identity_binding_not_verified" in item["error"] for item in report["errors"])
    assert kernel.closed == [HANDLE]


def test_file_code_guard_failure_blocks_memory_reads(capture_setup, monkeypatch):
    _profile_value, kernel = capture_setup
    monkeypatch.setattr(dpm, "_file_code_guard", lambda *_args: {"status": "mismatch", "checks": {"guard": False}, "records": {}, "unknown_conditions": ["changed"]})
    report = _capture(capture_setup)
    assert report["status"] == "file_code_mismatch"
    assert report["completed"] is False
    assert report["values"] is None
    assert kernel.read_calls == []


def test_profile_or_dependency_failure_fails_closed(capture_setup, monkeypatch):
    monkeypatch.setattr(dpm, "_load_profile", lambda *args, **kwargs: (_ for _ in ()).throw(dpm.ProfileError("profile_missing")))
    report = dpm.capture(Path("fake-installation.json"), "FRA")
    assert report["status"] == "static_contract_mismatch"
    assert report["completed"] is False
    assert report["values"] is None

    # The profile seam can also be malformed while still loading.  This
    # exercises the provenance/layout guard rather than the file-read path.
    profile = _profile()
    root = Path(dpm.__file__).resolve().parents[2]
    profile["provenance"]["dependencies"].append({
        "path": dpm.PROFILE_FILE.relative_to(root).as_posix(), "sha256": "f" * 64,
    })
    monkeypatch.setattr(dpm, "_load_profile", lambda *args, **kwargs: profile)
    contract = dpm._static_contract_guard()
    assert contract["status"] == "unknown"
    assert contract["checks"]["provenance_dependencies"] is False

