"""Prepare, but do not perform, the v23 information-battle installation.

This is a file-only preflight.  It verifies the final v23 artifact, the
installer/restart/host guards, and the empty control directory.  It never
opens a game process, calls RPM, starts a restart, loads a DLL, or writes a
control request.  A successful report therefore means *prepared*; it does
not mean that a valid game identity or a ready v23 runtime has been observed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BUILD = ROOT / "work/runtime/diplomacy-observer-20261025-information-battle-v23-005"
DEFAULT_STAGE = ROOT / "work/runtime/information-battle-live-20261025-001"
DEFAULT_OUTPUT = DEFAULT_STAGE / "install-preparation-001.json"

EXPECTED_DLL_SHA256 = "eaf53986e159bfca7af717228a7bc983a8df03fec32a23eb4a82e5ca503133c3"
EXPECTED_EXE_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
EXPECTED_SOURCE_COUNT = 103
MAX_ARTIFACT_BYTES = 16 * 1024 * 1024
HEX = frozenset("0123456789abcdef")

REQUIRED_INFORMATION_SOURCES = (
    "information-battle-observer.inc",
    "information-battle-entry-stub.S",
    "information-battle-entry-plan.h",
    "information-battle-owned-result.h",
    "information-battle-owned-summary.h",
    "information-battle-buffer.h",
    "information-battle-drain.h",
    "information-battle-wire.h",
    "information-battle-log-writer.h",
    "information-battle-observation-wire.h",
    "information-battle-fragment.h",
)

FIXED_R70_SAVE_NAME = "llm_diplomacy_r70_country_money_rejected_20261020.eu4"
FIXED_R70_SAVE_SHA256 = "ffa91dbd2a2d544b18d586a895bb9b0c2b90e94ece47b2c74507555b8f58c2e0"


class PreparationError(ValueError):
    """Raised when a bounded preparation input is invalid."""


def _rel(path: Path) -> str:
    try:
        return path.resolve().relative_to(ROOT).as_posix()
    except ValueError:
        return str(path.resolve())


def _sha256(path: Path, *, maximum: int = MAX_ARTIFACT_BYTES) -> str:
    if not path.is_file():
        raise PreparationError(f"missing_file:{_rel(path)}")
    size = path.stat().st_size
    if size > maximum:
        raise PreparationError(f"file_over_bound:{_rel(path)}:{size}")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_json(path: Path) -> dict[str, Any]:
    if not path.is_file() or path.stat().st_size > MAX_ARTIFACT_BYTES:
        raise PreparationError(f"manifest_missing_or_oversize:{_rel(path)}")
    value = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise PreparationError(f"json_object_required:{_rel(path)}")
    return value


def _source_lines(path: Path) -> list[str]:
    if not path.is_file() or path.stat().st_size > MAX_ARTIFACT_BYTES:
        raise PreparationError(f"source_missing_or_oversize:{_rel(path)}")
    return path.read_text(encoding="utf-8", errors="replace").splitlines()


def _refs(path: Path, needles: Iterable[str], *, per_needle: int = 4) -> list[dict[str, Any]]:
    lines = _source_lines(path)
    result: list[dict[str, Any]] = []
    for needle in needles:
        matches = [
            {"line": index + 1, "text": line.strip()[:240]}
            for index, line in enumerate(lines)
            if needle in line
        ][:per_needle]
        result.append({"needle": needle, "matches": matches})
    return result


def _first_line(path: Path, needle: str) -> int | None:
    for index, line in enumerate(_source_lines(path), 1):
        if needle in line:
            return index
    return None


def _contains_all(text: str, needles: Iterable[str]) -> list[str]:
    return [needle for needle in needles if needle not in text]


def _safe_manifest_name(value: object) -> bool:
    return isinstance(value, str) and bool(value) and Path(value).name == value and value not in {".", ".."}


def _artifact_check(build: Path) -> dict[str, Any]:
    manifest_path = build / "build-manifest.json"
    manifest_sha = _sha256(manifest_path)
    manifest = _read_json(manifest_path)
    sources = manifest.get("sources")
    if not isinstance(sources, list):
        raise PreparationError("manifest_sources_not_list")

    source_errors: list[str] = []
    names: set[str] = set()
    records: list[dict[str, str]] = []
    for index, item in enumerate(sources):
        if not isinstance(item, dict):
            source_errors.append(f"source_record_{index}_not_object")
            continue
        name = item.get("name")
        digest = item.get("sha256")
        if not _safe_manifest_name(name):
            source_errors.append(f"source_name_invalid_{index}")
            continue
        if name in names:
            source_errors.append(f"source_duplicate:{name}")
        names.add(name)
        if not isinstance(digest, str) or len(digest) != 64 or any(c.lower() not in HEX for c in digest):
            source_errors.append(f"source_hash_invalid:{name}")
            continue
        record = {"name": name, "sha256": digest.lower()}
        records.append(record)
        build_source = build / name
        root_source = ROOT / "work/native" / name
        try:
            build_sha = _sha256(build_source)
        except PreparationError as error:
            source_errors.append(str(error))
            continue
        if build_sha != record["sha256"]:
            source_errors.append(f"build_source_hash_mismatch:{name}")
        try:
            root_sha = _sha256(root_source)
        except PreparationError as error:
            source_errors.append(str(error))
            continue
        if root_sha != record["sha256"]:
            source_errors.append(f"root_source_hash_mismatch:{name}")

    dll_name = "eu4_bridge_diplomacy_observer_v23.dll"
    dll_path = build / dll_name
    dll_sha = _sha256(dll_path)
    manifest_dll = manifest.get("dll")
    manifest_dll_matches = False
    if isinstance(manifest_dll, str):
        manifest_dll_matches = Path(manifest_dll).resolve() == dll_path.resolve()
    required_missing = sorted(set(REQUIRED_INFORMATION_SOURCES) - names)
    required_hashes = {
        record["name"]: record["sha256"]
        for record in records
        if record["name"] in REQUIRED_INFORMATION_SOURCES
    }
    return {
        "path": _rel(build),
        "manifest": {
            "path": _rel(manifest_path),
            "sha256": manifest_sha,
            "version": manifest.get("version"),
            "experiment_id": manifest.get("experiment_id"),
            "compiled": manifest.get("compiled"),
            "runtime_verified": manifest.get("runtime_verified"),
            "reason_metadata_requested": manifest.get("reason_metadata_requested"),
            "information_battle_research_lifecycle": manifest.get("information_battle_research_lifecycle"),
            "game_sha256": manifest.get("game_sha256"),
            "dll_manifest_path_matches": manifest_dll_matches,
        },
        "sources": {
            "count": len(sources),
            "expected_count": EXPECTED_SOURCE_COUNT,
            "count_matches": len(sources) == EXPECTED_SOURCE_COUNT,
            "unique_names": len(names),
            "all_root_and_build_hashes_match_manifest": not source_errors,
            "error_count": len(source_errors),
            "errors": source_errors[:64],
            "required_source_names": list(REQUIRED_INFORMATION_SOURCES),
            "required_source_missing": required_missing,
            "required_source_manifest_hashes": required_hashes,
        },
        "dll": {
            "path": _rel(dll_path),
            "sha256": dll_sha,
            "expected_sha256": EXPECTED_DLL_SHA256,
            "sha256_matches": dll_sha == EXPECTED_DLL_SHA256,
            "bytes": dll_path.stat().st_size,
        },
    }


def _directory_preflight(build: Path) -> dict[str, Any]:
    exact = (
        "installation.json",
        "information-battle-control.request",
        "information-battle-control.processing",
        "information-battle-binding.json",
        "information-battle-status.json",
        "information-battle-raw.jsonl",
    )
    found: list[dict[str, Any]] = []
    for child in build.iterdir():
        name = child.name
        pending = (
            name in exact
            or name.startswith("information-battle-control.")
            or name.startswith("information-battle-started-")
            or name.startswith("information-battle-response-")
            or name.startswith("information-battle-status.")
            or name.endswith(".pending")
            or name.endswith(".processing")
            or name.endswith(".request")
        )
        if pending:
            found.append({"name": name, "directory": child.is_dir(), "bytes": child.stat().st_size})
    return {
        "checked_directory": _rel(build),
        "required_absent": list(exact),
        "found_control_or_pending": found,
        "clear_for_new_install_attempt": not found,
        "unrelated_existing_entries": sorted(
            child.name for child in build.iterdir() if child.name not in {item["name"] for item in found}
        ),
    }


def _source_record(path: Path, needles: Iterable[str]) -> dict[str, Any]:
    text = "\n".join(_source_lines(path))
    return {"path": _rel(path), "sha256": _sha256(path), "references": _refs(path, needles), "bytes": path.stat().st_size}


def _static_checks() -> dict[str, Any]:
    installer = ROOT / "tools/start_diplomacy_observer.py"
    loader = ROOT / "work/native/inject_probe.py"
    restart = ROOT / "work/native/restart-game.ps1"
    restart_1375 = ROOT / "work/native/restart-test-game-1375.ps1"
    restart_args = ROOT / "work/native/restart-arguments-1375.ps1"
    r70_source = ROOT / "work/crosscheck_information_battle_war_save.py"
    host = ROOT / "work/native/diplomacy-observer-v10.cpp"
    source = ROOT / "work/native/information-battle-observer.inc"

    installer_text = "\n".join(_source_lines(installer))
    loader_text = "\n".join(_source_lines(loader))
    restart_text = "\n".join(_source_lines(restart))
    restart_1375_text = "\n".join(_source_lines(restart_1375))
    restart_args_text = "\n".join(_source_lines(restart_args))
    host_text = "\n".join(_source_lines(host))
    source_text = "\n".join(_source_lines(source))

    installer_requirements = (
        "--pid",
        "--manifest",
        "--confirm-load-warning",
        "--native-text-codec",
        "--wait-ready",
        "_validate_information_battle_manifest",
        "candidate[\"modules\"]",
        "FRESH_VERIFIED_GAME_PROCESS_REQUIRED",
        "_assert_same_unloaded_process",
        "EXPERIMENT_ALREADY_ATTEMPTED_USE_NEW_DIRECTORY_AND_PROCESS",
        "--ack-test-save",
        "INSTALLATION_FAILED_NO_RETRY_IN_THIS_PROCESS",
    )
    loader_requirements = (
        '"--ack-test-save"',
        "An EU4 bridge DLL is already loaded",
        "BridgeStart",
        "BridgeStart returned",
        "DLL remains loaded",
    )
    host_requirements = (
        "ObserverControlStart(argument)",
        "information_battle_start(module_path,observation_creation)",
        "observer_legacy_frame(context)",
        "information_battle_tick();",
        "observation_frame_inside",
    )
    source_requirements = (
        "enum State : long { cold, ready, enabled, disabled",
        'status("","startup",true,"awaiting_process_bound_enable",false)',
        "transition(ready)",
        "if (state.load(std::memory_order_acquire)==cold) return;",
        "if (thread_changed || (bound_thread && GetCurrentThreadId()!=bound_thread))",
        'status("","heartbeat",usable,usable?"observed":"terminal_source_state",false)',
    )
    booleans = {
        "installer": {needle: needle in installer_text for needle in installer_requirements},
        "loader": {needle: needle in loader_text for needle in loader_requirements},
        "host": {needle: needle in host_text for needle in host_requirements},
        "source": {needle: needle in source_text for needle in source_requirements},
        "restart": {
            "target_exe_hash_guard": "B23FA0E1F698D31B01CDD1C3817A675805D8C6286CB66F9C231E6E2A42544D77" in restart_text,
            "explicit_save_name": "$SaveName" in restart_text,
            "save_exists_guard": "Requested test save does not exist" in restart_text,
            "continue_argument": "-continue=" in restart_text,
            "new_pid_output": "new PID" in restart_text,
        },
        "restart_1375": {
            "wrong_build_guard_present": "9AD3EFE1AF169F40EE577F9DAE5DEBBC87AF6FB8B5450FB345EBF110DC4D771A" in restart_1375_text,
            "save_name_is_required": "$SaveName" in restart_1375_text,
        },
        "restart_args": {
            "removes_previous_continue": "ConvertTo-TestRestartArguments" in restart_args_text and "continue" in restart_args_text,
        },
    }

    host_lines = _source_lines(host)
    observer_line = _first_line(host, "observer_legacy_frame(context)")
    thread_guard_line = _first_line(host, "if (!thread_changed && frame_thread==GetCurrentThreadId())")
    tick_line = _first_line(host, "information_battle_tick();")
    start_control_line = _first_line(host, "DWORD result=ObserverControlStart(argument);")
    start_battle_line = _first_line(host, "information_battle_start(module_path,observation_creation)")
    frame_guard_line = _first_line(host, "observation_frame_inside")
    start_source_line = _first_line(source, "static bool information_battle_start")
    startup_status_line = _first_line(source, 'status("","startup",true,"awaiting_process_bound_enable",false)')
    ready_transition_line = _first_line(source, "transition(ready)")

    host_order = {
        "legacy_frame_before_thread_gate": bool(observer_line and thread_guard_line and observer_line < thread_guard_line),
        "battle_tick_after_thread_gate": bool(thread_guard_line and tick_line and thread_guard_line < tick_line),
        "battle_tick_inside_reentrancy_function": bool(frame_guard_line and tick_line and frame_guard_line < tick_line),
        "observer_control_before_battle_start": bool(start_control_line and start_battle_line and start_control_line < start_battle_line),
    }

    return {
        "installer": _source_record(installer, ("def _validate_information_battle_manifest", "def _wait_until_ready", "def _install_once", "parser.add_argument(\"--pid\"", "--ack-test-save")),
        "loader": _source_record(loader, ("--ack-test-save", "known_bridge", "BridgeStart returned", "DLL remains loaded")),
        "restart": _source_record(restart, ("$expectedHash", "$SaveName", "-continue=", "new PID")),
        "restart_1375": _source_record(restart_1375, ("$expectedHash", "$SaveName", "-continue=<verified test filename>")),
        "restart_arguments": _source_record(restart_args, ("ConvertTo-TestRestartArguments", "continue", "$kept.Add")),
        "r70_save_reference": {
            "path": _rel(r70_source),
            "sha256": _sha256(r70_source),
            "fixed_save_name": FIXED_R70_SAVE_NAME,
            "fixed_save_sha256": FIXED_R70_SAVE_SHA256,
            "references": _refs(r70_source, ("DEFAULT_SAVE", "EXPECTED_SAVE_SHA256")),
        },
        "host": _source_record(host, ("extern \"C\" void bridge_frame_tick", "observer_legacy_frame(context)", "information_battle_tick();", "BridgeStart", "ObserverControlStart(argument)")),
        "native_source": _source_record(source, ("enum State : long", "information_battle_start", "status(\"\",\"startup\"", "information_battle_tick", "transition(ready)")),
        "checks": booleans,
        "host_line_order": host_order,
        "line_numbers": {
            "host_observer_legacy_frame": observer_line,
            "host_thread_guard": thread_guard_line,
            "host_information_battle_tick": tick_line,
            "host_observer_control_start": start_control_line,
            "host_information_battle_start": start_battle_line,
            "host_reentrancy_guard": frame_guard_line,
            "native_information_battle_start": start_source_line,
            "native_startup_status": startup_status_line,
            "native_ready_transition": ready_transition_line,
        },
    }


def _required_pid_input() -> dict[str, Any]:
    return {
        "provided": False,
        "verified": False,
        "pid": None,
        "creation_filetime": None,
        "session_id": None,
        "required_after_restart": [
            "new PID from the completed restart, never a historical PID",
            "same-process creation FILETIME from probe_identity",
            "session_id from the same identity probe",
            "exact 1.37.4 EXE SHA and exactly one newly loaded v23 DLL path/SHA",
            "ready status from the v23 status file after BridgeStart startup",
        ],
        "historical_identity_reuse_forbidden": True,
    }


def build_report(build: Path) -> dict[str, Any]:
    build = build.resolve(strict=True)
    artifact = _artifact_check(build)
    directory = _directory_preflight(build)
    static = _static_checks()
    static_ok = all(
        value
        for group in static["checks"].values()
        if isinstance(group, dict)
        for value in group.values()
    ) and all(static["host_line_order"].values())
    artifact_ok = (
        artifact["manifest"]["version"] == 23
        and artifact["manifest"]["information_battle_research_lifecycle"] is True
        and artifact["manifest"]["reason_metadata_requested"] is True
        and artifact["manifest"]["game_sha256"] == EXPECTED_EXE_SHA256
        and artifact["manifest"]["dll_manifest_path_matches"]
        and artifact["sources"]["count_matches"]
        and artifact["sources"]["unique_names"] == EXPECTED_SOURCE_COUNT
        and artifact["sources"]["all_root_and_build_hashes_match_manifest"]
        and not artifact["sources"]["required_source_missing"]
        and artifact["dll"]["sha256_matches"]
    )
    prepared = artifact_ok and directory["clear_for_new_install_attempt"] and static_ok

    return {
        "schema": "information-battle-live-install-preparation/1",
        "status": "prepared_runtime_identity_pending" if prepared else "blocked_static_preflight",
        "read_only": True,
        "executed_installation": False,
        "executed_restart": False,
        "executed_injection": False,
        "executed_game_access": False,
        "target_build": artifact,
        "directory_preflight": directory,
        "static_preflight": static,
        "r70_restart": {
            "fixed_save_name": FIXED_R70_SAVE_NAME,
            "fixed_save_sha256": FIXED_R70_SAVE_SHA256,
            "command_template": [
                "./work/native/restart-game.ps1",
                "-SavedTestGame",
                "-SaveName",
                FIXED_R70_SAVE_NAME,
            ],
            "script_does_not_pin_save_sha": True,
            "operator_must_verify_loaded_save_before_install": True,
            "incompatible_alternative": {
                "path": "work/native/restart-test-game-1375.ps1",
                "reason": "expects the 1.37.5 EXE SHA and is not the fixed 1.37.4 R70 restart path",
            },
        },
        "execution_templates": {
            "restart": "./work/native/restart-game.ps1 -SavedTestGame -SaveName " + FIXED_R70_SAVE_NAME,
            "install": "python tools/start_diplomacy_observer.py --pid <NEW_PID> --manifest work/runtime/diplomacy-observer-20261025-information-battle-v23-005/build-manifest.json --confirm-load-warning --native-text-codec eu4_escape --wait-ready 120",
            "status_after_install": "python tools/control_information_battle_observer.py --installation work/runtime/diplomacy-observer-20261025-information-battle-v23-005/installation.json --command status",
            "enable_after_status": "python tools/control_information_battle_observer.py --installation work/runtime/diplomacy-observer-20261025-information-battle-v23-005/installation.json --command enable --player-ref <16_LOWERCASE_HEX_PHYSICAL_PLAYER_REF>",
            "disable_after_acceptance": "python tools/control_information_battle_observer.py --installation work/runtime/diplomacy-observer-20261025-information-battle-v23-005/installation.json --command disable",
        },
        "required_new_pid_input": _required_pid_input(),
        "findings": [
            {
                "code": "RUNTIME_IDENTITY_NOT_YET_VERIFIED",
                "severity": "blocking_for_install",
                "message": "No new PID/creation/session or loaded v23 module identity has been observed; this report must not be used as an installation receipt.",
            },
            {
                "code": "RESTART_SAVE_SHA_NOT_ENFORCED_BY_SCRIPT",
                "severity": "operator_guard",
                "message": "restart-game.ps1 verifies the 1.37.4 executable and save-file existence, then appends the requested -continue name; it does not hash or inspect the fixed R70 save. Verify the fixed save independently before installation.",
            },
            {
                "code": "INSTALLER_SINGLE_ATTEMPT",
                "severity": "terminal_on_failure",
                "message": "The installer writes installation.json before the loader; timeout or loader failure is terminal for that process and directory. Use a fresh process and directory for a new attempt.",
            },
            {
                "code": "READY_AND_ACK_ARE_SEPARATE",
                "severity": "operator_guard",
                "message": "--ack-test-save is a required disposable-save acknowledgement for inject_probe; it is not a v23 ready/capture proof. Check the post-install status file and the same PID identity before any control request.",
            },
            {
                "code": "NATIVE_CAPTURE_DISABLED_AT_START",
                "severity": "expected",
                "message": "BridgeStart publishes cold/ready startup state and the frame tick does not capture until an explicit bound enable command; no business result is implied by a successful installation.",
            },
        ],
        "limitations": [
            "This file-only preparation did not restart a game, enumerate a process, load a DLL, call RPM, write installation/control/pending files, or issue an enable request.",
            "The command template contains placeholders for the new PID, identity, and physical player reference; placeholders are not evidence.",
            "The v23 research lifecycle remains capture_complete=false/business_export_available=false until a separate live acceptance proves the runtime path.",
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", type=Path, default=DEFAULT_BUILD)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args(argv)
    build = args.build_dir.expanduser().resolve(strict=True)
    output = args.output.expanduser().resolve()
    if not output.is_relative_to(ROOT):
        raise PreparationError("output_must_remain_inside_workspace")
    if output.exists():
        raise PreparationError(f"refusing_to_overwrite:{_rel(output)}")
    output.parent.mkdir(parents=True, exist_ok=True)
    report = build_report(build)
    report["script"] = {
        "path": _rel(Path(__file__).resolve()),
        "sha256": _sha256(Path(__file__).resolve()),
        "command": "python work/prepare_information_battle_live_install.py",
    }
    with output.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(report, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    print(json.dumps({
        "status": report["status"],
        "output": _rel(output),
        "target_dll_sha256": report["target_build"]["dll"]["sha256"],
        "source_count": report["target_build"]["sources"]["count"],
        "directory_clear": report["directory_preflight"]["clear_for_new_install_attempt"],
        "runtime_identity_verified": report["required_new_pid_input"]["verified"],
    }, ensure_ascii=False))
    return 0 if report["status"] == "prepared_runtime_identity_pending" else 1


if __name__ == "__main__":
    raise SystemExit(main())
