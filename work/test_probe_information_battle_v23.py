"""Bounded mock tests for the v23 read-only preflight."""
from __future__ import annotations

import ctypes as C
import importlib.util
from pathlib import Path
import struct

import pytest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("probe_information_battle_v23", ROOT / "work" / "probe_information_battle_v23.py")
assert SPEC and SPEC.loader
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)


class MappingReader:
    def __init__(self, module_base: int):
        self.module_base = module_base
        self._bytes: list[tuple[int, bytes]] = []

    def put(self, address: int, raw: bytes) -> None:
        self._bytes.append((address, bytes(raw)))

    def read(self, address: int, size: int, label: str, *, aligned: bool = False) -> bytes:
        del label, aligned
        for start, raw in reversed(self._bytes):
            if start <= address and address + size <= start + len(raw):
                return raw[address - start:address - start + size]
        raise AssertionError(f"missing fake read {hex(address)}+{size}")

    def read_code(self, address: int, size: int, label: str) -> bytes:
        return self.read(address, size, label)

    def qword(self, address: int, label: str) -> tuple[int, bytes]:
        raw = self.read(address, 8, label, aligned=True)
        return int.from_bytes(raw, "little"), raw

    def dword(self, address: int, label: str, *, signed: bool = False) -> tuple[int, bytes]:
        raw = self.read(address, 4, label)
        return int.from_bytes(raw, "little", signed=signed), raw


def _synthetic_pe(symbols: list[tuple[str, int]]) -> bytes:
    raw = bytearray(0x1000)
    raw[:2] = b"MZ"
    struct.pack_into("<I", raw, 0x3C, 0x80)
    raw[0x80:0x84] = b"PE\0\0"
    coff = 0x84
    symbol_pointer = 0x600
    struct.pack_into("<HHIIIHH", raw, coff, 0x8664, 1, 0, symbol_pointer, len(symbols), 0xF0, 0)
    struct.pack_into("<H", raw, coff + 20, 0x20B)
    section = coff + 20 + 0xF0
    raw[section:section + 8] = b".text\0\0\0"
    struct.pack_into("<IIIIIIHHI", raw, section + 8, 0x1000, 0x1000, 0x200, 0x300, 0, 0, 0, 0, 0x60000020)
    string = bytearray(b"\x00\x00\x00\x00")
    offsets: list[int] = []
    for name, _ in symbols:
        offsets.append(len(string))
        string.extend(name.encode("ascii") + b"\0")
    for index, ((_, value), name_offset) in enumerate(zip(symbols, offsets)):
        offset = symbol_pointer + index * 18
        struct.pack_into("<II", raw, offset, 0, name_offset)
        struct.pack_into("<I", raw, offset + 8, value)
        struct.pack_into("<h", raw, offset + 12, 1)
        struct.pack_into("<H", raw, offset + 14, 0x20)
        raw[offset + 16] = 2
        raw[offset + 17] = 0
    struct.pack_into("<I", string, 0, len(string))
    raw[symbol_pointer + len(symbols) * 18:symbol_pointer + len(symbols) * 18 + len(string)] = string
    return bytes(raw)


def _snapshot_reader() -> tuple[MappingReader, int]:
    base = 0x140000000
    game = 0x200000000
    server = 0x300000000
    vtable = 0x300001000
    pause = 0x300002000
    reader = MappingReader(base)
    reader.put(base + probe.GAME_RVA, game.to_bytes(8, "little"))
    reader.put(game + probe.GAME_DATE_OFFSET, (56553384).to_bytes(4, "little", signed=True))
    reader.put(game + probe.GAME_PLAYER_OFFSET, (0x010000BD00415246).to_bytes(8, "little"))
    reader.put(game + probe._war.CONTROL_SERVER_OFFSET, server.to_bytes(8, "little"))
    reader.put(server, vtable.to_bytes(8, "little"))
    reader.put(vtable + probe._war.CONTROL_SERVER_VTABLE_SPEED_OFFSET, (base + probe._war.CONTROL_GETTER_RVA).to_bytes(8, "little"))
    reader.put(base + probe._war.CONTROL_GETTER_RVA, probe._war.CONTROL_GETTER_GUARD)
    reader.put(game + probe._war.CONTROL_SPEED_OFFSET, (0).to_bytes(4, "little", signed=True))
    reader.put(server + probe._war.CONTROL_SERVER_PAUSE_OFFSET, pause.to_bytes(8, "little"))
    reader.put(pause + probe._war.CONTROL_PAUSE_FLAG_OFFSET, b"\x01")
    return reader, base


def test_coff_symbol_resolution_and_ambiguity() -> None:
    one = probe._coff_symbol_from_bytes(_synthetic_pe([(probe.STUB_SYMBOL, 0x40)]))
    assert one["status"] == "observed"
    assert one["rva"] == "0x1040"
    assert one["section"]["name"] == ".text"

    missing = probe._coff_symbol_from_bytes(_synthetic_pe([("other", 0x40)]))
    assert missing["status"] == "unknown"
    assert "stub_symbol_not_unique" in missing["unknown_conditions"]

    duplicate = probe._coff_symbol_from_bytes(_synthetic_pe([(probe.STUB_SYMBOL, 0x40), (probe.STUB_SYMBOL, 0x50)]))
    assert duplicate["status"] == "unknown"
    assert "stub_symbol_not_unique" in duplicate["unknown_conditions"]


def test_reused_live_artifact_requires_pinned_v23_source_manifest() -> None:
    live_dir = probe.ROOT / "work" / "runtime" / "diplomacy-observer-20261025-information-battle-live-001"
    manifest = {
        "experiment_id": probe.LIVE_BUILD_ID,
        "artifact_reuse": {
            "source_manifest": str(probe.SOURCE_MANIFEST_PATH.resolve()),
            "source_manifest_sha256": probe.EXPECTED_MANIFEST_SHA256,
            "source_dll_sha256": probe.EXPECTED_DLL_SHA256,
            "compiled_in_this_directory": False,
        },
    }
    accepted = probe._artifact_reuse_contract(manifest, live_dir)
    assert accepted["status"] == "observed"

    tampered = dict(manifest)
    tampered["artifact_reuse"] = dict(manifest["artifact_reuse"])
    tampered["artifact_reuse"]["source_manifest_sha256"] = "0" * 64
    rejected = probe._artifact_reuse_contract(tampered, live_dir)
    assert rejected["status"] == "unknown"
    assert "source_manifest_sha256" in rejected["unknown_conditions"][0]


def test_installed_guard_has_absolute_stub_and_original_tail() -> None:
    stub = 0x180000000
    installed = probe._installed_entry(stub)
    assert len(installed) == probe.ENTRY_SIZE
    assert installed[:2] == b"\xff\x25"
    assert installed[2:6] == b"\0" * 4
    assert int.from_bytes(installed[6:14], "little") == stub
    assert installed[14:21] == b"\x90" * 7
    assert installed[21:] == probe.ENTRY_PREFIX[21:]

    reader = MappingReader(0x140000000)
    reader.put(reader.module_base + probe.ENTRY_RVA, installed)
    reader.put(reader.module_base + probe.UNWIND_RVA, probe.UNWIND_PREFIX)
    guard = probe._runtime_code_guard(reader, reader.module_base, "mock", "installed", stub)
    assert guard["status"] == "observed"
    assert guard["installed_shape"]["stub_pointer_matches_coff"] is True
    assert guard["installed_shape"]["seven_nop"] is True


def test_retreat_manifest_defaults_to_two_entries_and_strictly_selects_third():
    legacy = probe._retreat_specs_for_manifest({"version": 44})
    assert len(legacy) == 2
    assert [spec["key"] for spec in legacy] == ["outcome", "unit_path"]

    extended = probe._retreat_specs_for_manifest({
        "version": 44,
        probe.RETREAT_UNIT_REMOVAL_KEY: True,
        probe.RETREAT_MAX_EXTENSION_VERSION_KEY: 2,
    })
    assert len(extended) == 3
    unit_removal = extended[-1]
    assert unit_removal["symbol"] == "information_battle_unit_removal_retreat_hook"
    assert (unit_removal["rva"], unit_removal["end_rva"], unit_removal["unwind_rva"]) == (
        0x23B200, 0x23B397, 0x1DE6F20,
    )
    assert len(unit_removal["prefix"]) == unit_removal["patch_bytes"] == 27
    assert unit_removal["prefix"].hex() == "48895c240848896c24104889742420574883ec20410fb6e8488bfa"
    assert len(unit_removal["unwind"]) == 32
    assert unit_removal["unwind"].hex() == "11140800146409001454070014340600143210709c4da3013c6fde0128dd9add"
    assert unit_removal["projected_unwind_bytes"] == 20
    assert unit_removal["stack_delta"] == 0x28
    assert unit_removal["home_slot_offset"] == 0x18


@pytest.mark.parametrize("manifest", [
    {"information_battle_retreat_unit_removal": True},
    {"information_battle_retreat_max_extension_version": 2},
    {"information_battle_retreat_unit_removal": 1,
     "information_battle_retreat_max_extension_version": 2},
    {"information_battle_retreat_unit_removal": True,
     "information_battle_retreat_max_extension_version": True},
    {"information_battle_retreat_unit_removal": True,
     "information_battle_retreat_max_extension_version": 1},
])
def test_retreat_manifest_rejects_partial_or_inexact_unit_removal_metadata(manifest):
    with pytest.raises(probe.V23ProbeError, match="retreat_unit_removal_manifest_mismatch"):
        probe._retreat_specs_for_manifest(manifest)


def test_file_and_live_code_guards_follow_legacy_or_extended_entry_set(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    legacy = probe._retreat_specs_for_manifest({"version": 44})
    extended = probe._retreat_specs_for_manifest({
        probe.RETREAT_UNIT_REMOVAL_KEY: True,
        probe.RETREAT_MAX_EXTENSION_VERSION_KEY: 2,
    })

    def read_pe(_path, rva, size):
        if rva == probe.ENTRY_RVA:
            return probe.ENTRY_PREFIX[:size]
        if rva == probe.UNWIND_RVA:
            return probe.UNWIND_PREFIX[:size]
        for spec in extended:
            if rva == spec["rva"]:
                return bytes(spec["prefix"][:size])
            if rva == spec["unwind_rva"]:
                return bytes(spec["unwind"][:size])
        raise AssertionError(f"unexpected file RVA {hex(rva)}")

    monkeypatch.setattr(probe._loc, "_read_pe_rva_bytes", read_pe)
    legacy_file = probe._file_code_guard(tmp_path / "game.exe", include_retreat=True,
                                        retreat_specs=legacy)
    extended_file = probe._file_code_guard(tmp_path / "game.exe", include_retreat=True,
                                           retreat_specs=extended)
    assert legacy_file["status"] == "observed"
    assert len(legacy_file["records"]) == 6
    assert extended_file["status"] == "observed"
    assert len(extended_file["records"]) == 8
    assert "retreat_unit_removal_entry_23b200_original" in extended_file["records"]

    for specs in (legacy, extended):
        for phase in ("original", "installed"):
            module_base = 0x140000000
            stub_va = 0x180000000
            reader = MappingReader(module_base)
            entry = (probe.ENTRY_PREFIX if phase == "original"
                     else probe._installed_entry(stub_va))
            reader.put(module_base + probe.ENTRY_RVA, entry)
            reader.put(module_base + probe.UNWIND_RVA, probe.UNWIND_PREFIX)
            hooks = {}
            for index, spec in enumerate(specs):
                key = str(spec["key"])
                hook_va = 0x180001000 + index * 0x1000
                hooks[key] = hook_va
                retreat_entry = (bytes(spec["prefix"]) if phase == "original"
                                 else probe._retreat_absolute_patch(
                                     hook_va, int(spec["patch_bytes"])))
                reader.put(module_base + int(spec["rva"]), retreat_entry)
                reader.put(module_base + int(spec["unwind_rva"]), bytes(spec["unwind"]))
            guard = probe._runtime_code_guard(
                reader, module_base, "mock", phase, stub_va, hooks, specs)
            assert guard["status"] == "observed"
            assert len(guard["records"]) == 2 + 2 * len(specs)
            if phase == "installed" and len(specs) == 3:
                assert guard["retreat_installed_shapes"]["unit_removal"][
                    "hook_pointer_matches_coff"] is True


@pytest.mark.parametrize("unit_removal_enabled", [False, True])
def test_static_prepare_reports_two_or_three_coff_hooks_by_manifest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, unit_removal_enabled: bool,
):
    dll_sha = "a" * 64
    manifest = {
        "version": 44,
        "experiment_id": "synthetic-v44-retreat-origin",
        "dll_sha256": dll_sha,
        "game_sha256": probe.EXPECTED_EXE_SHA256,
    }
    if unit_removal_enabled:
        manifest.update({
            probe.RETREAT_UNIT_REMOVAL_KEY: True,
            probe.RETREAT_MAX_EXTENSION_VERSION_KEY: 2,
        })
    source = {
        "status": "observed",
        "manifest": {"sha256": "b" * 64},
        "source_manifest": {"path": "manifest.json", "sha256": "c" * 64},
    }
    monkeypatch.setattr(probe, "_manifest_static_guard", lambda _directory: source)
    monkeypatch.setattr(probe, "_read_json_bounded", lambda _path, *_args: (manifest, {}))
    monkeypatch.setattr(probe, "_stable_file_pin", lambda *_args, **_kwargs: {
        "status": "observed", "sha256": dll_sha, "bytes": 100,
    })

    def coff_symbol(_path, symbol=probe.STUB_SYMBOL):
        rva = 0x1000 if symbol == probe.STUB_SYMBOL else next(
            int(spec["rva"]) for spec in (
                probe.RETREAT_ENTRY_SPECS + (probe.UNIT_REMOVAL_RETREAT_ENTRY_SPEC,)
            ) if spec["symbol"] == symbol
        )
        return {"status": "observed", "rva": hex(rva), "symbol": symbol}

    monkeypatch.setattr(probe, "_coff_symbol", coff_symbol)
    report = probe._base_report(tmp_path / "installation.json", tmp_path / "report.json", "original")
    build = probe._static_prepare(report, tmp_path)
    expected_count = 3 if unit_removal_enabled else 2
    assert len(build["retreat_entry_specs"]) == expected_count
    assert len(build["retreat_hook_rvas"]) == expected_count
    assert len(report["target_build"]["retreat_entry_specs"]) == expected_count
    if unit_removal_enabled:
        report_spec = report["target_build"]["retreat_entry_specs"][-1]
        assert report_spec["projected_unwind_bytes"] == 20
        assert report_spec["stack_delta"] == "0x28"
        assert report_spec["home_slot_offset"] == "0x18"
        assert report_spec["current_rsp_home_slot_offset"] == "0x40"


def test_snapshot_contains_complete_game_and_physical_player_ref() -> None:
    reader, base = _snapshot_reader()
    snapshot = probe._snapshot(reader, base, "mock")
    assert snapshot["status"] == "observed"
    assert snapshot["game_pointer"]["value"] == hex(0x200000000)
    assert snapshot["game_pointer"]["rva"] == hex(probe.GAME_RVA)
    player = snapshot["physical_player"]
    assert player["raw_hex"] == "46524100bd000001"
    assert player["tag"] == "FRA"
    assert player["slot"] == 189
    assert player["complete"] is True
    assert snapshot["control"]["paused"]["value"] is True
    assert snapshot["control"]["speed"]["value"] == 0


class ZeroKernel:
    def ReadProcessMemory(self, handle, address, buffer, size, actual):
        del handle, address
        C.memset(buffer, 0, size)
        actual._obj.value = size
        return 1


def test_rpm_budget_and_single_read_limits() -> None:
    reader = probe.V23RPM(ZeroKernel(), 1, 0x140000000)
    for index in range(16):
        reader.read(0x200000000 + index * probe.MAX_SINGLE_RPM, probe.MAX_SINGLE_RPM, f"mock.{index}")
    with pytest.raises(probe.V23ProbeError, match="RPM_BUDGET_OR_ADDRESS_EXCEEDED"):
        reader.read(0x200100000, 1, "over_budget")
    with pytest.raises(probe.V23ProbeError, match="invalid_size"):
        reader.read(0x200200000, probe.MAX_SINGLE_RPM + 1, "oversize")


def test_plan_report_is_explicitly_not_runtime(tmp_path: Path) -> None:
    output = tmp_path / "report.json"
    report = probe.plan_report(output)
    assert report["status"] == "not_run_waiting_for_v23_installation"
    assert report["runtime_accessed"] is False
    assert report["provenance"]["source"]["status"] == "observed"
    assert report["provenance"]["ordinary_pe_coff"]["status"] == "observed"
    assert report["provenance"]["rpm"]["status"] == "not_run"
    assert report["request"]["control_command_sent"] is False
    assert report["cleanup"]["handle_close"]["calls"] == 0

