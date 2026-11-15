"""Offline v37 probe SourceProof checks; no process or RPM access."""
from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

from bridge.tests.test_information_battle_v37_manifest import make_v37_manifest_fixture


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "probe_information_battle_v37_manifest",
    ROOT / "work" / "probe_information_battle_v23.py",
)
assert SPEC and SPEC.loader
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)


def test_v37_static_prepare_pins_both_retreat_hook_coff_symbols(tmp_path: Path, monkeypatch):
    build_dir = tmp_path / "v37-static-probe"
    manifest, dll_path = make_v37_manifest_fixture(build_dir)
    hook_rvas = {
        "information_battle_outcome_retreat_hook": "0x5000",
        "information_battle_unit_retreat_hook": "0x6000",
    }
    calls: list[str] = []

    def coff(path: Path, symbol: str = probe.STUB_SYMBOL) -> dict:
        assert path == dll_path
        calls.append(symbol)
        rva = "0x1040" if symbol == probe.STUB_SYMBOL else hook_rvas[symbol]
        return {"status": "observed", "rva": rva, "symbol": symbol,
                "source": "ordinary_pe_coff"}

    monkeypatch.setattr(probe, "_coff_symbol", coff)
    report = {"target_build": {}, "provenance": {}, "stub": {}}
    build = probe._static_prepare(report, build_dir)

    assert build["manifest"]["version"] == 37
    assert build["dll_path"] == dll_path
    assert build["retreat_hook_rvas"] == {"outcome": "0x5000", "unit_path": "0x6000"}
    assert report["provenance"]["source"]["status"] == "observed"
    assert report["retreat_hooks"]["outcome"]["symbol"] == "information_battle_outcome_retreat_hook"
    assert report["retreat_hooks"]["unit_path"]["symbol"] == "information_battle_unit_retreat_hook"
    assert set(calls) == {
        probe.STUB_SYMBOL,
        "information_battle_outcome_retreat_hook",
        "information_battle_unit_retreat_hook",
    }


def test_v37_static_prepare_rejects_missing_retreat_hook_symbol(tmp_path: Path, monkeypatch):
    build_dir = tmp_path / "v37-missing-hook-symbol"
    _manifest, dll_path = make_v37_manifest_fixture(build_dir)

    def coff(path: Path, symbol: str = probe.STUB_SYMBOL) -> dict:
        assert path == dll_path
        if symbol == "information_battle_unit_retreat_hook":
            return {"status": "unknown", "symbol": symbol, "source": "ordinary_pe_coff"}
        return {"status": "observed", "rva": "0x1040", "symbol": symbol,
                "source": "ordinary_pe_coff"}

    monkeypatch.setattr(probe, "_coff_symbol", coff)
    report = {"target_build": {}, "provenance": {}, "stub": {}}
    with pytest.raises(probe.V23ProbeError, match="retreat_hook_coff_symbol_unavailable:unit_path"):
        probe._static_prepare(report, build_dir)


def test_v37_on_disk_guard_checks_both_original_prefixes_and_unwind_rows(
    tmp_path: Path, monkeypatch
):
    exe = tmp_path / "synthetic-game.exe"
    values = {
        probe.ENTRY_RVA: probe.ENTRY_PREFIX,
        probe.UNWIND_RVA: probe.UNWIND_PREFIX,
    }
    for spec in probe.RETREAT_ENTRY_SPECS:
        values[spec["rva"]] = spec["prefix"]
        values[spec["unwind_rva"]] = spec["unwind"]

    def read_rva(path: Path, rva: int, size: int) -> bytes:
        del path
        raw = values[rva]
        assert len(raw) == size
        return raw

    monkeypatch.setattr(probe._loc, "_read_pe_rva_bytes", read_rva)
    accepted = probe._file_code_guard(exe, include_retreat=True)
    assert accepted["status"] == "observed"
    assert len(accepted["records"]) == 6

    values[probe.RETREAT_ENTRY_SPECS[1]["rva"]] = b"\xcc" * 28
    rejected = probe._file_code_guard(exe, include_retreat=True)
    assert rejected["status"] == "mismatch"
    assert "on_disk_original_image_guard_mismatch" in rejected["unknown_conditions"]


class _CodeReader:
    def __init__(self, data: dict[int, bytes]):
        self.data = data

    def read_code(self, address: int, size: int, label: str) -> bytes:
        del label
        value = self.data[address]
        assert len(value) == size
        return value


def test_v37_runtime_guard_checks_installed_jump_targets_and_unchanged_unwind():
    module_base = 0x140000000
    stub_va = 0x700001040
    retreat_hook_vas = {"outcome": 0x700005000, "unit_path": 0x700006000}
    data = {
        module_base + probe.ENTRY_RVA: probe._installed_entry(stub_va),
        module_base + probe.UNWIND_RVA: probe.UNWIND_PREFIX,
    }
    for spec in probe.RETREAT_ENTRY_SPECS:
        key = spec["key"]
        data[module_base + spec["rva"]] = probe._retreat_absolute_patch(
            retreat_hook_vas[key], spec["patch_bytes"])
        data[module_base + spec["unwind_rva"]] = spec["unwind"]

    accepted = probe._runtime_code_guard(
        _CodeReader(data), module_base, "after", "installed", stub_va,
        retreat_hook_vas)
    assert accepted["status"] == "observed"
    assert accepted["retreat_installed_shapes"]["outcome"]["hook_pointer_matches_coff"] is True
    assert accepted["retreat_installed_shapes"]["unit_path"]["nops_after_jump"] is True
    assert all(
        item["matches"] for key, item in accepted["records"].items()
        if key.startswith("retreat_")
    )

    data[module_base + probe.RETREAT_ENTRY_SPECS[1]["rva"]] = probe._retreat_absolute_patch(
        retreat_hook_vas["unit_path"] + 1, 28)
    rejected = probe._runtime_code_guard(
        _CodeReader(data), module_base, "after", "installed", stub_va,
        retreat_hook_vas)
    assert rejected["status"] == "mismatch"

