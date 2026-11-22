"""Synthetic contract tests for the bounded military-resources reader.

These tests never open a game process.  The byte reader models only the
profiled pointers, fields, modifier container, and processor slots.
"""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest

from bridge.information import military_resources_memory as m
from bridge.information.military_resources import NativeMilitaryResourcesSource


BASE = 0x140000000
DATABASE = 0x10000000
TABLE = 0x10001000
COUNTRY = 0x10002000
GAME = 0x10003000
MODIFIER = COUNTRY + 0x28D0
INLINE_VTABLE_SENTINEL = 0x10009000
VALUES = 0x10005000
MANAGER = 0x10006000
COUNTRY_2 = 0x10008000


def test_python_source_evidence_is_historical_and_not_rehashed(monkeypatch) -> None:
    original_bounded_file = m._bounded_file

    def checked_bounded_file(path: Path, limit: int, label: str) -> bytes:
        assert Path(path).suffix != ".py"
        return original_bounded_file(path, limit, label)

    monkeypatch.setattr(m, "_bounded_file", checked_bounded_file)
    profile = m._load_profile()
    historical = [item for item in profile["_validated_source_evidence"]
                   if Path(item["path"]).suffix == ".py"]
    assert historical
    assert all(item["verification"] == "historical_reference" for item in historical)


def test_non_python_source_evidence_still_requires_current_hash(monkeypatch) -> None:
    profile = m._load_profile()
    dependency = next(item for item in profile["source_evidence"]
                      if Path(item["path"]).suffix != ".py")
    target = (m._workspace_root() / dependency["path"]).resolve()
    original_bounded_file = m._bounded_file

    def changed_bounded_file(path: Path, limit: int, label: str) -> bytes:
        if Path(path).resolve() == target:
            return b"\0" * dependency["bytes"]
        return original_bounded_file(path, limit, label)

    monkeypatch.setattr(m, "_bounded_file", changed_bounded_file)
    with pytest.raises(m.ProfileError, match="source_evidence_sha256_mismatch"):
        m._source_evidence(profile)


def _u64(value: int) -> bytes:
    return int(value).to_bytes(8, "little", signed=False)


def _i32(value: int) -> bytes:
    return int(value).to_bytes(4, "little", signed=True)


class MemoryReader:
    def __init__(self) -> None:
        self.bytes: dict[int, int] = {}

    def put(self, address: int, raw: bytes | bytearray) -> None:
        self.bytes.update({address + index: value for index, value in enumerate(bytes(raw))})

    def read(self, address: int, size: int, label: str) -> bytes:
        try:
            return bytes(self.bytes[address + index] for index in range(size))
        except KeyError as exc:
            raise OSError(f"missing:{label}:{address:#x}+{size}") from exc

    def read_code(self, address: int, size: int, label: str) -> bytes:
        return self.read(address, size, label)

    def clone(self, source: int, destination: int, size: int) -> None:
        self.put(destination, self.read(source, size, "clone"))


def _make_reader(
    *,
    mode: str = "dense",
    sailors: int = 2_597_984,
    values: dict[int, int] | None = None,
    sparse_entries: list[tuple[int, int]] | None = None,
    processors: dict[int, int] | None = None,
    date: int = 56_562_768,
    cache_state: int = 2,
) -> MemoryReader:
    profile = m._load_profile()
    reader = MemoryReader()
    for guard in profile["code_guards"]:
        reader.put(BASE + int(guard["rva"], 0), bytes.fromhex(guard["hex"]))
    handle = int.from_bytes(b"FRA", "little")
    reader.put(BASE + 0x233D8B0, _u64(DATABASE))
    reader.put(DATABASE + 0x118, _u64(TABLE))
    reader.put(DATABASE + 0x124, _i32(1))
    reader.put(TABLE, _u64(COUNTRY))
    reader.put(COUNTRY + 0x20, _u64(handle))
    reader.put(BASE + 0x233FE58, _u64(GAME))
    reader.put(GAME + 0x1DD0, _i32(date))
    reader.put(COUNTRY + 0xDC0, _i32(sailors))
    reader.put(COUNTRY + 0x28C8, _i32(cache_state))
    header = bytearray(0x68)
    # The inline object begins with a nonzero vtable-like qword. It must not be
    # mistaken for a pointer to another modifier object.
    header[0:8] = _u64(INLINE_VTABLE_SENTINEL)
    header[0x10] = 1 if mode == "dense" else 0
    header[0x58:0x60] = _u64(VALUES)
    header[0x64:0x68] = _i32(len(sparse_entries or []))
    reader.put(MODIFIER, header)
    if mode == "dense":
        for ident, raw in (values or {54: 37_777, 55: 16_946, 56: 500, 57: 500}).items():
            reader.put(VALUES + ident * 8 + 4, _i32(raw))
    else:
        for index, (ident, raw) in enumerate(sparse_entries or []):
            reader.put(VALUES + index * 8, _i32(ident) + _i32(raw))
    reader.put(BASE + 0x2358060, _u64(MANAGER))
    for ident in m.FORCE_IDS:
        pointer = (processors or {}).get(ident, 0)
        reader.put(MANAGER + ident * 0x60 + 0x40, _u64(pointer))
    return reader


def _observed(reader: MemoryReader, *, country_pointer: int = COUNTRY) -> dict:
    return m.read_fields(reader, BASE, country_pointer, profile=m._load_profile())


def _capture_like(reader: MemoryReader, country: str = "FRA") -> tuple[dict, dict, dict]:
    profile = m._load_profile()
    static = m._static_contract_guard(profile)
    first = m._snapshot(reader, BASE, country, profile, static, m._ReadBudget())
    second = m._snapshot(reader, BASE, country, profile, static, m._ReadBudget())
    report = {
        "status": "observed", "completed": True, "read_only": True, "country": country,
        "module_base": hex(BASE), "country_pointer": first["private"]["country_pointer"],
        "before": first, "after": second,
        "country_scan": {"before": first["private"]["country_scan"], "after": second["private"]["country_scan"]},
        "fields": deepcopy(second["fields"]), "values": deepcopy(second["values"]), "raw_hex": deepcopy(second["raw_hex"]),
        "identity": {"installation_path": "synthetic-installation.json", "installation_pid": 91, "installation_creation_filetime": 92, "installation_session_id": "synthetic-session", "process_path_sha256": m.EXPECTED_EXE_SHA256, "process_path_sha256_matches_expected": True, "process_creation_filetime": 92, "process_creation_matches_installation": True, "binding_verified": True},
        "request": {"installation": "synthetic-installation.json", "country": country, "pid": 91, "creation_filetime": 92, "session_id": "synthetic-session", "game_sha256": m.EXPECTED_EXE_SHA256},
        "cleanup": {"handle_close": {"status": "closed", "success": True, "closed": True}},
        "access": {
            "native_game_calls": False, "target_memory_writes": False, "mcp_query": False,
            "rpm_bytes_requested": sum(item["record"]["observation"]["read_budget"]["bytes_reserved"] for item in (first, second)),
            "rpm_calls": sum(len(item["record"]["observation"]["read_log"]) for item in (first, second)),
        },
        "doublepass": {"performed": True, "consistent": True, "mismatches": []},
    }
    return report, first, second


def test_dense_values_are_public_and_private_graph_validates() -> None:
    result = _observed(_make_reader())
    assert result["status"] == "observed"
    assert result["fields"]["sailors"]["value"] == 2_597_984
    assert result["fields"]["sailors"]["raw"] == 2_597_984
    assert result["fields"]["sailors"]["display_value"] == 2_597
    assert result["fields"]["force_limits"]["value"]["land"]["value"] == 56
    assert result["fields"]["force_limits"]["value"]["naval"]["value"] == 25
    assert "country_pointer" not in result["fields"]["sailors"]
    modifier = result["private"]["force"]["modifier"]
    assert modifier["storage"] == "inline"
    assert modifier["object_address"] == hex(MODIFIER)
    assert modifier["header_raw_hex"].startswith(_u64(INLINE_VTABLE_SENTINEL).hex())
    trace = result["record"]["observation"]["read_log"]
    header_rows = [row for row in trace if row["label"] == "military_resources.modifier_header"]
    assert len(header_rows) == 1 and header_rows[0]["address"] == hex(MODIFIER)
    assert not any(row["label"] == "military_resources.modifier_object" for row in trace)
    assert not any(row["address"] == hex(INLINE_VTABLE_SENTINEL) for row in trace)
    assert m.validate_record(result["record"])


def test_sparse_first_match_and_missing_values_are_bounded() -> None:
    result = _observed(_make_reader(mode="sparse", sparse_entries=[(54, 10), (54, 99), (56, 50)]))
    force = result["fields"]["force_limits"]
    assert force["value"]["land"]["value"] == 1
    assert force["value"]["naval"]["value"] == 1
    private = result["private"]["force"]["modifier"]
    assert private["mode"] == "sparse"
    assert private["ids"]["54"]["value_raw"] == 10
    assert private["ids"]["54"]["first_match_index"] == 0
    assert private["ids"]["55"]["value_raw"] == 0
    assert m.validate_record(result["record"])


def test_nonnull_processor_retracts_only_affected_force_field() -> None:
    result = _observed(_make_reader(processors={54: 0x10007000}))
    force = result["fields"]["force_limits"]
    assert result["fields"]["sailors"]["status"] == "known"
    assert force["value"]["land"]["status"] == "unknown"
    assert force["value"]["land"]["reason"] == "DYNAMIC_FORCE_LIMIT_PROCESSOR_UNSUPPORTED"
    assert force["value"]["naval"]["status"] == "known"
    assert m.validate_record(result["record"])


def test_cache_calculating_keeps_sailors_known_and_force_unknown() -> None:
    result = _observed(_make_reader(cache_state=1))
    assert result["fields"]["sailors"]["status"] == "known"
    assert result["fields"]["sailors"]["value"] == 2_597_984
    assert result["fields"]["force_limits"]["value"]["land"]["reason"] == "FORCE_LIMIT_CACHE_CALCULATING"
    assert result["fields"]["force_limits"]["value"]["naval"]["reason"] == "FORCE_LIMIT_CACHE_CALCULATING"
    assert m.validate_record(result["record"])


def test_trace_binding_rejects_self_consistent_sailors_and_force_tampering() -> None:
    original = _observed(_make_reader())["record"]
    tampered_sailors = deepcopy(original)
    sailors = tampered_sailors["fields"]["sailors"]
    sailors.update({"value": 1_234_000, "raw": 1_234_000, "raw_hex": _i32(1_234_000).hex(), "display_value": 1234})
    assert not m.validate_record(tampered_sailors)

    tampered_force = deepcopy(original)
    land = tampered_force["fields"]["force_limits"]["value"]["land"]
    land.update({"value": 99, "raw": 99_000, "raw_hex": _i32(99_000).hex()})
    assert not m.validate_record(tampered_force)


def test_modifier_trace_and_sparse_first_match_are_authoritative() -> None:
    dense = _observed(_make_reader())["record"]
    row = dense["private"]["force"]["modifier"]["ids"]["54"]
    row.update({"value_raw": 100, "raw_hex": _i32(100).hex()})
    dense["private"]["force"]["values"]["54"] = 100
    assert not m.validate_record(dense)

    sparse = _observed(_make_reader(mode="sparse", sparse_entries=[(54, 10), (54, 99), (56, 50)]))["record"]
    modifier = sparse["private"]["force"]["modifier"]
    modifier["ids"]["54"].update({"value_raw": 99, "raw_hex": _i32(99).hex(), "first_match_index": 1, "address": hex(VALUES + 8 + 4)})
    sparse["private"]["force"]["values"]["54"] = 99
    values = {int(key): value for key, value in sparse["private"]["force"]["values"].items()}
    processors = {int(key): None for key in sparse["private"]["force"]["processors"]["slots"]}
    sparse["fields"]["force_limits"], sparse["private"]["force"]["field"] = m._force_field(values, processors)
    assert not m.validate_record(sparse)


def test_nonnull_processor_cannot_be_relabelled_as_null() -> None:
    result = _observed(_make_reader(processors={54: 0x10007000}))
    record = result["record"]
    row = record["private"]["force"]["processors"]["slots"]["54"]
    row.update({"processor_pointer": None, "processor_pointer_raw_hex": "0000000000000000",
                "slot_raw_hex": "0000000000000000", "status": "absent"})
    assert not m.validate_record(record)


def test_float32_display_and_fail_closed_sailor_guard() -> None:
    boundary = _observed(_make_reader(sailors=16_777_999))
    assert boundary["fields"]["sailors"]["display_value"] == 16_778
    negative = _observed(_make_reader(sailors=-1))
    assert negative["status"] == "unknown"
    assert "sailors_negative" in negative["error"]


def test_negative_base_uses_native_minimum_and_factor_overflow_is_unknown() -> None:
    negative = _observed(_make_reader(values={54: -10, 55: 16_946, 56: 0, 57: 500}))
    assert negative["fields"]["force_limits"]["value"]["land"]["value"] == 1
    overflow = _observed(_make_reader(values={54: 1, 55: 16_946, 56: 2_147_483_647, 57: 500}))
    assert overflow["fields"]["force_limits"]["value"]["land"]["status"] == "unknown"
    assert "factor_outside_i32" in overflow["fields"]["force_limits"]["value"]["land"]["reason"]


def test_two_pass_country_and_date_changes_are_visible() -> None:
    reader = _make_reader()
    profile = m._load_profile()
    static = m._static_contract_guard(profile)
    first = m._snapshot(reader, BASE, "FRA", profile, static, m._ReadBudget())
    # Copy only the profiled country fields; unmapped padding is intentionally
    # absent from the synthetic address space.
    for offset, size in ((0x20, 8), (0xDC0, 4), (0x28C8, 4), (0x28D0, 0x68)):
        reader.put(COUNTRY_2 + offset, reader.read(COUNTRY + offset, size, "copy-country-field"))
    reader.put(TABLE, _u64(COUNTRY_2))
    reader.put(COUNTRY_2 + 0x20, _u64(int.from_bytes(b"FRA", "little")))
    reader.put(GAME + 0x1DD0, _i32(56_562_769))
    second = m._snapshot(reader, BASE, "FRA", profile, static, m._ReadBudget())
    assert first["private"]["country_pointer"] != second["private"]["country_pointer"]
    assert first["private"]["game_date"] != second["private"]["game_date"]
    assert m._diff_paths(m._stable_record(first["record"]), m._stable_record(second["record"])
                         )


def test_validate_capture_rejects_raw_binding_or_outer_identity_tamper() -> None:
    report, first, _second = _capture_like(_make_reader())
    assert m.validate_capture(report, {"game_date": 56_562_768, "session_id": "synthetic-session", "game_sha256": m.EXPECTED_EXE_SHA256}, 92)
    tampered = deepcopy(report)
    tampered["before"]["record"]["private"]["game_date"]["value"] += 1
    assert not m.validate_capture(tampered, {"game_date": 56_562_768, "session_id": "synthetic-session", "game_sha256": m.EXPECTED_EXE_SHA256}, 92)
    tampered = deepcopy(report)
    tampered["access"]["rpm_bytes_requested"] += 1
    assert not m.validate_capture(tampered, {"game_date": 56_562_768, "session_id": "synthetic-session", "game_sha256": m.EXPECTED_EXE_SHA256}, 92)
    tampered = deepcopy(report)
    tampered["access"]["rpm_calls"] += 1
    assert not m.validate_capture(tampered, {"game_date": 56_562_768, "session_id": "synthetic-session", "game_sha256": m.EXPECTED_EXE_SHA256}, 92)


@pytest.mark.parametrize("country", ["FRA", "TUR", "D01"])
def test_real_capture_validation_reaches_military_resources_adapter(tmp_path: Path, country: str) -> None:
    reader = _make_reader()
    reader.put(COUNTRY + 0x20, _u64(int.from_bytes(country.encode("ascii"), "little")))
    report, _first, _second = _capture_like(reader, country)
    context = {
        "status": "ready", "complete": True, "mode": "live", "observer": country,
        "game_version": "1.37.4", "game_sha256": m.EXPECTED_EXE_SHA256,
        "session_id": "synthetic-session", "game_date": 56_562_768,
        "game_date_raw": 56_562_768,
    }
    session = SimpleNamespace(directory=tmp_path, creation_filetime=92,
                              record={"session_id": "synthetic-session", "creation_filetime": 92})
    base = SimpleNamespace(session=session, context=lambda: deepcopy(context))
    source = NativeMilitaryResourcesSource(base, capture=lambda *_args, **_kwargs: deepcopy(report))
    query = {"topic": "N02", "object": {"type": "country", "country": country},
             "fields": ["sailors", "force_limits"], "parameters": {}}
    result = source.read(query, context)
    assert result["fields"]["sailors"]["value"] == 2_597_984
    assert result["fields"]["sailors"]["display_value"] == 2_597
    force = result["fields"]["force_limits"]
    assert force["status"] == "known" and force["complete"] is False and force["partial"] is True
    assert force["value"]["land"]["value"] == 56
    assert force["value"]["naval"]["value"] == 25
    tampered = deepcopy(report)
    tampered["before"]["record"]["private"]["force"]["cache_state"]["raw_hex"] = "00000000"
    assert not m.validate_capture(tampered, {"game_date": 56_562_768, "session_id": "synthetic-session", "game_sha256": m.EXPECTED_EXE_SHA256}, 92)


def test_capture_marks_close_failure_unknown(monkeypatch: pytest.MonkeyPatch) -> None:
    reader = _make_reader()
    exe = Path("C:/fixture/eu4.exe")
    class Kernel:
        def OpenProcess(self, *_args):
            return object()

    document = {"pid": 91, "creation_filetime": 92, "session_id": "synthetic-session", "game_sha256": m.EXPECTED_EXE_SHA256}
    def fake_identity(report, _document, _kernel, _handle):
        report["identity"].update({"installation_pid": 91, "installation_creation_filetime": 92, "installation_session_id": "synthetic-session", "process_path": str(exe), "process_path_sha256": m.EXPECTED_EXE_SHA256, "process_path_sha256_matches_expected": True, "process_creation_filetime": 92, "process_creation_matches_installation": True, "module_path": str(exe), "module_path_matches_process": True, "binding_verified": True})
        return BASE

    monkeypatch.setattr(m, "_load_installation", lambda _path: document)
    monkeypatch.setattr(m, "_configure_kernel", lambda: Kernel())
    monkeypatch.setattr(m, "_capture_identity", fake_identity)
    monkeypatch.setattr(m, "_file_code_guard", lambda *_args: {"status": "observed", "checks": {"synthetic": True}, "records": {}})
    monkeypatch.setattr(m, "AddressBoundedRPM", lambda *_args: reader)
    monkeypatch.setattr(m, "_close_process_handle", lambda *_args: {"status": "error", "success": False, "closed": False})
    report = m.capture(Path("synthetic-installation.json"))
    assert report["completed"] is True
    assert report["status"] == "unknown"
    assert report["cleanup"]["handle_close"]["closed"] is False


def test_unknown_profile_version_is_rejected() -> None:
    profile = deepcopy(m._load_profile())
    profile["game_version"] = "1.37.3"
    with pytest.raises(m.ProfileError):
        m._prepare_profile(profile)
