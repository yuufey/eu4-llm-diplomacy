"""Mocked end-to-end read-only probe flow for v36, v37 and v41 manifests."""
from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "probe_information_battle_v37_run_flow",
    ROOT / "work" / "probe_information_battle_v23.py",
)
assert SPEC and SPEC.loader
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)


@pytest.mark.parametrize("version", [36, 37, 41])
def test_run_uses_validated_manifest_version_and_routes_versioned_entry_guards(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, version: int
):
    game_path = tmp_path / "synthetic-game.exe"
    game_path.write_bytes(b"offline mock identity only")
    installation = tmp_path / "installation.json"
    output = tmp_path / "run-report.json"
    pid = 6472
    creation = 0x123456789
    session = f"{pid}-{creation:x}"
    dll_sha = "d" * 64
    document = {
        "experiment_id": f"retreat-v{version}-mock",
        "game_sha256": probe.EXPECTED_EXE_SHA256,
        "dll_sha256": dll_sha,
        "pid": pid,
        "creation_filetime": creation,
        "session_id": session,
        "process_path": str(game_path),
    }
    hook_rvas = ({"outcome": "0x4e9b0", "unit_path": "0x4eff0"}
                 if version in (37, 41) else {})
    build = {
        "manifest": {
            "version": version,
            "experiment_id": document["experiment_id"],
            "game_sha256": document["game_sha256"],
        },
        "dll_path": tmp_path / f"eu4_bridge_diplomacy_observer_v{version}.dll",
        "dll_sha256": dll_sha,
        "retreat_hook_rvas": hook_rvas,
    }
    module_base = 0x140000000
    dll_module_base = 0x700000000
    identity_calls: list[str] = []
    runtime_calls: list[tuple] = []
    file_guard_calls: list[tuple[Path, bool]] = []
    close_calls: list[tuple] = []

    class FakeKernel:
        def OpenProcess(self, access, inherit, requested_pid):
            assert access == probe.PROCESS_ACCESS
            assert inherit is False
            assert requested_pid == pid
            return 0x5678

    kernel = FakeKernel()

    def static_prepare(report: dict, build_dir: Path):
        assert build_dir == tmp_path.resolve()
        report["provenance"]["source"] = {"status": "observed"}
        report["provenance"]["ordinary_pe_coff"] = {"status": "observed"}
        report["stub"] = {"symbol": probe.STUB_SYMBOL, "rva": "0x1040", "status": "observed"}
        report["target_build"]["observer_version"] = version
        if version in (37, 41):
            report["retreat_hooks"] = {
                "outcome": {"symbol": "information_battle_outcome_retreat_hook", "rva": hook_rvas["outcome"]},
                "unit_path": {"symbol": "information_battle_unit_retreat_hook", "rva": hook_rvas["unit_path"]},
            }
        return build

    def capture_identity(_kernel, _handle, _document, expected_exe, phase):
        assert expected_exe == game_path.resolve()
        identity_calls.append(phase)
        return {
            "status": "observed",
            "phase": phase,
            "session_id": session,
            "pid": pid,
            "module_base": hex(module_base),
        }

    loaded = {
        "status": "observed",
        "matching_modules": [{"base": hex(dll_module_base)}],
        "modules": [{"path": str(build["dll_path"]), "base": hex(dll_module_base)}],
    }

    def query_modules(_kernel, _handle, expected_path, expected_sha):
        assert expected_path == build["dll_path"]
        assert expected_sha == dll_sha
        return {**loaded, "matching_modules": list(loaded["matching_modules"]),
                "modules": list(loaded["modules"])}

    def file_guard(path: Path, *, include_retreat: bool = False):
        file_guard_calls.append((path, include_retreat))
        return {"status": "observed", "records": {"mock": {"matches": True}}}

    def runtime_guard(reader, base, phase, expect_patch, stub_va, retreat_hook_vas=None):
        assert isinstance(reader, probe.V23RPM)
        assert base == module_base
        assert expect_patch == "installed"
        assert stub_va == dll_module_base + 0x1040
        runtime_calls.append((phase, retreat_hook_vas))
        records = {"main_entry": {"matches": True}}
        if version in (37, 41):
            records["retreat_outcome"] = {"matches": True}
            records["retreat_unit_path"] = {"matches": True}
        return {"status": "observed", "records": records}

    def snapshot(_reader, _base, phase):
        return {"phase": phase, "status": "observed", "game_date": {"raw": 56559504}}

    def close_process(_kernel, handle):
        close_calls.append((_kernel, handle))
        return {"status": "closed", "success": True, "closed": True}

    monkeypatch.setattr(probe, "_load_document", lambda _path: (document, {"status": "observed"}))
    monkeypatch.setattr(probe, "_static_prepare", static_prepare)
    monkeypatch.setattr(probe, "_capture_identity", capture_identity)
    monkeypatch.setattr(probe, "_query_module_records", query_modules)
    monkeypatch.setattr(probe, "_file_code_guard", file_guard)
    monkeypatch.setattr(probe, "_runtime_code_guard", runtime_guard)
    monkeypatch.setattr(probe, "_snapshot", snapshot)
    monkeypatch.setattr(probe, "_write_new", lambda _path, _report: "mock-report-sha")
    monkeypatch.setattr(probe._loc, "_configure_kernel", lambda: kernel)
    monkeypatch.setattr(probe._loc, "_close_process_handle", close_process)

    report = probe.run(installation, output, "installed")

    assert report["status"] == "passed_read_only_preflight"
    assert report["completed"] is True
    assert report["target_build"]["observer_version"] == version
    assert identity_calls == ["before", "after"]
    assert len(close_calls) == 1 and close_calls[0][1] == 0x5678
    assert file_guard_calls == [(game_path.resolve(), version in (37, 41))]
    assert [call[0] for call in runtime_calls] == ["before", "after"]
    if version == 36:
        assert [call[1] for call in runtime_calls] == [None, None]
        assert "retreat_hooks" not in report
    else:
        expected_hook_vas = {
            "outcome": dll_module_base + int(hook_rvas["outcome"], 0),
            "unit_path": dll_module_base + int(hook_rvas["unit_path"], 0),
        }
        assert [call[1] for call in runtime_calls] == [expected_hook_vas, expected_hook_vas]
        assert report["retreat_hooks"]["outcome"]["expected_runtime_va"] == hex(expected_hook_vas["outcome"])
        assert report["retreat_hooks"]["unit_path"]["expected_runtime_va"] == hex(expected_hook_vas["unit_path"])
