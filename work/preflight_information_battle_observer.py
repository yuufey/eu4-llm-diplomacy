"""Pure-RPM preflight for the current information battle observer session.

This is deliberately a preflight, not a battle/history query.  It opens the
PID recorded by the current installation manifest with
``PROCESS_QUERY_INFORMATION | PROCESS_VM_READ`` (0x410), validates the live
process and the loaded v22 observer DLL, reads only the audited date/control
state and two code guards, then closes that one handle exactly once.  It never
starts, injects, unloads, saves, advances the game, invokes a native game
function, or dispatches a business request.

The installation and health files are historical/static inputs.  A successful
result requires a fresh process identity and fresh ReadProcessMemory values;
the metadata files are retained only to show what was declared before this
probe and are not used as a substitute for those observations.
"""
from __future__ import annotations

import argparse
import ctypes as C
from ctypes import wintypes as W
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sys
from typing import Any, Mapping

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from bridge.information import localization_memory as _loc
from work import information_battle_war_memory as _war


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_INSTALLATION = ROOT / "work/runtime/diplomacy-observer-20261025-information-battle-002/installation.json"
DEFAULT_OUTPUT = ROOT / "work/runtime/information-battle-observer-20261025-001/live-preflight-001/report.json"
STATIC_UNWIND_REFERENCE = ROOT / "work/runtime/information-battle-entry-20261025-001/entry-unwind-pe-001.json"

EXPECTED_VERSION = "1.37.4"
EXPECTED_EXE_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
EXPECTED_DLL_SHA256 = "d80ef39d66d263788c0af4df0892b4ff781e5e3b3f9aea7ebe33759327e457db"
EXPECTED_IMAGE_BASE = 0x140000000
PROCESS_ACCESS = 0x410
MAX_USER_ADDRESS = 0x0000800000000000
MAX_SINGLE_RPM = 64 * 1024
MAX_TOTAL_RPM = 1024 * 1024

ENTRY_RVA = 0x238620
ENTRY_PREFIX = bytes.fromhex(
    "48895c241048894c24085556574154415541564157488dac2460fbffff4881eca0050000"
)
UNWIND_RVA = 0x1DE6C98
UNWIND_PREFIX = bytes.fromhex(
    "11240b002434bd002401b40015f013e011d00fc00d700c600b5000009c4da301"
)

HEALTH_METADATA_NAMES = ("information-preflight-health.json", "information-preflight-control.json")


class PreflightError(RuntimeError):
    """A bounded preflight operation could not be completed safely."""


def _parse_int(value: Any, label: str) -> int:
    if isinstance(value, bool):
        raise PreflightError(f"{label}_bool_not_integer")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError as exc:
            raise PreflightError(f"{label}_invalid") from exc
    raise PreflightError(f"{label}_invalid")


def _sha256_file(path: Path) -> str:
    """Stream a file hash without loading the executable or DLL."""
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _stat_pin(path: Path) -> dict[str, Any]:
    try:
        st = path.stat()
        return {
            "path": str(path),
            "size_bytes": st.st_size,
            "mtime_ns": st.st_mtime_ns,
            "sha256": _sha256_file(path),
        }
    except OSError as exc:
        return {"path": str(path), "status": "unavailable", "error": f"{type(exc).__name__}:{exc}"}


def _read_json_bounded(path: Path, *, max_bytes: int = 64 * 1024) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    try:
        size = path.stat().st_size
        if size > max_bytes:
            return None, {"path": str(path), "status": "rejected", "reason": "file_size_limit", "size_bytes": size}
        raw = path.read_bytes()
        value = json.loads(raw.decode("utf-8"))
        if not isinstance(value, dict):
            return None, {"path": str(path), "status": "rejected", "reason": "not_object", "size_bytes": size}
        return value, {"path": str(path), "status": "read", "size_bytes": size, "sha256": hashlib.sha256(raw).hexdigest()}
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        return None, {"path": str(path), "status": "unavailable", "error": f"{type(exc).__name__}:{exc}"}


def _utc_filetime(value: int) -> str | None:
    try:
        return datetime.fromtimestamp(value / 10_000_000 - 11644473600, timezone.utc).isoformat()
    except (OverflowError, OSError, ValueError):
        return None


def _hex(value: int | None) -> str | None:
    return hex(value) if isinstance(value, int) else None


def _safe_address(value: int, *, aligned: bool = False) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0x10000 <= value < MAX_USER_ADDRESS and (not aligned or value % 8 == 0)


class PreflightRPM:
    """One-handle bounded ReadProcessMemory seam with a 1 MiB hard cap."""

    def __init__(self, kernel: Any, handle: Any, module_base: int):
        self.kernel = kernel
        self.handle = handle
        self.module_base = module_base
        self.bytes_requested = 0
        self.calls = 0
        self.read_log: list[dict[str, Any]] = []

    def read(self, address: int, size: int, label: str, *, aligned: bool = False) -> bytes:
        if not _safe_address(address, aligned=aligned):
            raise PreflightError(f"invalid_address:{label}")
        if not isinstance(size, int) or isinstance(size, bool) or size <= 0 or size > MAX_SINGLE_RPM:
            raise PreflightError(f"invalid_size:{label}")
        if address + size > MAX_USER_ADDRESS:
            raise PreflightError(f"address_overflow:{label}")
        if self.bytes_requested + size > MAX_TOTAL_RPM:
            raise PreflightError("RPM_TOTAL_BUDGET_EXCEEDED")
        self.bytes_requested += size
        self.calls += 1
        item: dict[str, Any] = {"label": label, "address": hex(address), "size": size, "status": "requested"}
        self.read_log.append(item)
        buffer = C.create_string_buffer(size)
        actual = C.c_size_t()
        try:
            ok = self.kernel.ReadProcessMemory(self.handle, C.c_void_p(address), buffer, size, C.byref(actual))
        except Exception as exc:
            item.update(status="error", error=f"{type(exc).__name__}:{exc}")
            raise
        if not ok:
            item.update(status="error", error="ReadProcessMemory_failed")
            raise C.WinError(C.get_last_error())
        if actual.value != size:
            item.update(status="error", error=f"short_read:{actual.value}/{size}")
            raise PreflightError(f"short_read:{label}:{actual.value}/{size}")
        item["status"] = "observed"
        return buffer.raw

    def read_code(self, address: int, size: int, label: str) -> bytes:
        return self.read(address, size, label, aligned=False)

    def qword(self, address: int, label: str) -> tuple[int, bytes]:
        raw = self.read(address, 8, label, aligned=True)
        return int.from_bytes(raw, "little"), raw

    def dword(self, address: int, label: str, *, signed: bool = False) -> tuple[int, bytes]:
        raw = self.read(address, 4, label, aligned=False)
        return int.from_bytes(raw, "little", signed=signed), raw


def _guard_record(actual: bytes, expected: bytes, rva: int) -> dict[str, Any]:
    return {
        "rva": hex(rva),
        "size_bytes": len(expected),
        "expected_hex": expected.hex(),
        "actual_hex": actual.hex(),
        "expected_sha256": hashlib.sha256(expected).hexdigest(),
        "actual_sha256": hashlib.sha256(actual).hexdigest(),
        "matches": actual == expected,
    }


def _file_code_guard(process_path: Path) -> dict[str, Any]:
    result: dict[str, Any] = {
        "status": "unknown",
        "source": "bound_process_file_stream",
        "records": {},
        "unknown_conditions": [],
    }
    try:
        entry = _loc._read_pe_rva_bytes(process_path, ENTRY_RVA, len(ENTRY_PREFIX))
        unwind = _loc._read_pe_rva_bytes(process_path, UNWIND_RVA, len(UNWIND_PREFIX))
        result["records"]["entry_238620_prefix"] = _guard_record(entry, ENTRY_PREFIX, ENTRY_RVA)
        result["records"]["unwind_1de6c98_prefix"] = _guard_record(unwind, UNWIND_PREFIX, UNWIND_RVA)
        result["status"] = "observed" if all(item["matches"] for item in result["records"].values()) else "mismatch"
        if result["status"] != "observed":
            result["unknown_conditions"].append("fixed_file_code_guard_mismatch")
    except Exception as exc:
        result["unknown_conditions"].append(f"fixed_file_code_guard_read_failed:{type(exc).__name__}:{exc}")
    return result


def _runtime_code_guard(reader: PreflightRPM, module_base: int, phase: str) -> dict[str, Any]:
    records: dict[str, Any] = {}
    result: dict[str, Any] = {
        "phase": phase,
        "status": "unknown",
        "module_base": hex(module_base),
        "records": records,
        "unknown_conditions": [],
    }
    try:
        entry = reader.read_code(module_base + ENTRY_RVA, len(ENTRY_PREFIX), f"{phase}.code.238620")
        unwind = reader.read_code(module_base + UNWIND_RVA, len(UNWIND_PREFIX), f"{phase}.code.1de6c98")
        records["entry_238620_prefix"] = _guard_record(entry, ENTRY_PREFIX, ENTRY_RVA)
        records["unwind_1de6c98_prefix"] = _guard_record(unwind, UNWIND_PREFIX, UNWIND_RVA)
        result["status"] = "observed" if all(item["matches"] for item in records.values()) else "mismatch"
        if result["status"] != "observed":
            result["unknown_conditions"].append("runtime_code_guard_mismatch")
    except Exception as exc:
        result["unknown_conditions"].append(f"runtime_code_guard_read_failed:{type(exc).__name__}:{exc}")
    return result


def _snapshot(reader: PreflightRPM, module_base: int, pass_name: str) -> dict[str, Any]:
    game_address = module_base + _war.GAME_RVA
    game, game_raw = reader.qword(game_address, f"{pass_name}.game_pointer")
    if not _safe_address(game, aligned=True):
        raise PreflightError(f"{pass_name}_game_pointer_invalid")
    date_address = game + _war.GAME_DATE_OFFSET
    date_raw = reader.read(date_address, 4, f"{pass_name}.game_date", aligned=False)
    control = _war._control_state(reader, module_base, game)
    date_value = int.from_bytes(date_raw, "little", signed=True)
    return {
        "pass": pass_name,
        "status": "observed" if control.get("status") == "observed" else "unknown",
        "module_base": hex(module_base),
        "game_pointer": {"address": hex(game_address), "value": hex(game), "raw_hex": game_raw.hex(), "rva": hex(_war.GAME_RVA)},
        "game_date": {"address": hex(date_address), "raw": date_value, "raw_hex": date_raw.hex(), "field_offset": hex(_war.GAME_DATE_OFFSET)},
        "control": control,
        "rpm": {"bytes_requested": reader.bytes_requested, "calls": reader.calls},
    }


def _state_projection(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    date = snapshot.get("game_date") if isinstance(snapshot.get("game_date"), Mapping) else {}
    control = snapshot.get("control") if isinstance(snapshot.get("control"), Mapping) else {}
    speed = control.get("speed") if isinstance(control.get("speed"), Mapping) else {}
    paused = control.get("paused") if isinstance(control.get("paused"), Mapping) else {}
    game = snapshot.get("game_pointer") if isinstance(snapshot.get("game_pointer"), Mapping) else {}
    return {
        "game_pointer_raw_hex": game.get("raw_hex"),
        "game_date_raw_hex": date.get("raw_hex"),
        "game_date_raw": date.get("raw"),
        "speed_raw_hex": speed.get("raw_hex"),
        "speed_value": speed.get("value"),
        "paused_raw_hex": paused.get("raw_hex"),
        "paused_raw": paused.get("raw"),
        "paused_value": paused.get("value"),
        "control_status": control.get("status"),
    }


def _diff_projection(before: Mapping[str, Any], after: Mapping[str, Any]) -> list[str]:
    left = _state_projection(before)
    right = _state_projection(after)
    return [key for key in left if left.get(key) != right.get(key)]


def _metadata_only(installation_dir: Path, document: Mapping[str, Any]) -> dict[str, Any]:
    files: list[dict[str, Any]] = []
    declarations: dict[str, Any] = {}
    for name in HEALTH_METADATA_NAMES:
        value, pin = _read_json_bounded(installation_dir / name)
        if value is not None:
            if name.endswith("health.json"):
                declarations[name] = {key: value.get(key) for key in ("status", "state_id", "date_raw", "complete") if key in value}
            else:
                declarations[name] = {key: value.get(key) for key in ("pid", "read_only", "date_raw", "speed", "paused_flag") if key in value}
        files.append(pin)
    explicit: dict[str, Any] = {}
    for key in ("frame_hook", "frame_hook_status", "hook", "hook_status"):
        if key in document:
            explicit[key] = document.get(key)
    return {
        "status": "declared" if explicit else "not_declared",
        "metadata_only": True,
        "native_status_command_invoked": False,
        "installation_ready_reason": document.get("ready_reason"),
        "explicit_installation_declarations": explicit,
        "files": files,
        "declarations": declarations,
        "interpretation": "No frame-hook claim is made when the installation/health metadata has no explicit field; fresh process and code checks below are independent.",
    }


def _base_report(installation: Path, output: Path) -> dict[str, Any]:
    return {
        "schema": "information_battle_observer_live_preflight_v1",
        "probe": "information-battle-observer",
        "probe_version": 1,
        "probe_script": str(Path(__file__).resolve()),
        "probe_script_sha256": None,
        "read_only": True,
        "evidence_kind": "fresh_pure_rpm_preflight",
        "target_build": {
            "version": EXPECTED_VERSION,
            "expected_exe_sha256": EXPECTED_EXE_SHA256,
            "expected_dll_sha256": EXPECTED_DLL_SHA256,
            "image_base": hex(EXPECTED_IMAGE_BASE),
            "open_process_mask": "PROCESS_QUERY_INFORMATION|PROCESS_VM_READ",
            "open_process_mask_hex": hex(PROCESS_ACCESS),
        },
        "request": {
            "installation": str(installation),
            "output": str(output),
            "business_query_invoked": False,
            "native_game_function_invoked": False,
            "target_memory_writes": False,
            "dll_injection": False,
            "dll_unload": False,
            "save_or_reload": False,
            "date_advance": False,
            "dispatch": False,
        },
        "installation": None,
        "frame_hook_metadata": None,
        "identity": {
            "installation_pid": None,
            "installation_creation_filetime": None,
            "installation_session_id": None,
            "expected_session_id_from_installation": None,
            "current_session_id": None,
            "session_id_matches_installation": None,
            "session_id_matches_current_identity": None,
            "process_path": None,
            "process_path_sha256": None,
            "process_creation_filetime": None,
            "binding_verified": False,
        },
        "module_base": None,
        "loaded_dll": None,
        "fixed_file_code_guard": None,
        "runtime_code_guard": {"before": None, "after": None},
        "before": None,
        "after": None,
        "doublepass": {"performed": False, "consistent": None, "mismatches": []},
        "access": {
            "rpm_total_limit": MAX_TOTAL_RPM,
            "rpm_single_read_limit": MAX_SINGLE_RPM,
            "rpm_bytes_requested": 0,
            "rpm_calls": 0,
            "read_log": [],
        },
        "cleanup": {"handle_close": {"status": "unknown", "success": None, "closed": False, "calls": 0}},
        "status": "starting",
        "errors": [],
        "completed": False,
    }


def _write_report(path: Path, report: Mapping[str, Any]) -> None:
    if path.exists():
        raise PreflightError(f"output_exists:{path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    try:
        tmp.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
        tmp.replace(path)
    finally:
        if tmp.exists():
            tmp.unlink()


def run(installation: Path, output: Path) -> dict[str, Any]:
    report = _base_report(installation, output)
    handle = None
    kernel = None
    reader: PreflightRPM | None = None
    try:
        report["probe_script_sha256"] = _sha256_file(Path(__file__).resolve())
        document = _loc._load_installation(installation)
        install_pin = _stat_pin(installation)
        report["installation"] = {
            "file": install_pin,
            "recorded_pid": document.get("pid"),
            "recorded_creation_filetime": document.get("creation_filetime"),
            "recorded_session_id": document.get("session_id"),
            "recorded_game_sha256": str(document.get("game_sha256", "")).lower(),
            "recorded_dll_sha256": str(document.get("dll_sha256", "")).lower(),
            "runtime_verified_record": document.get("runtime_verified"),
            "runtime_verified_record_is_not_fresh_observation": True,
        }
        report["frame_hook_metadata"] = _metadata_only(installation.parent, document)
        pid = _parse_int(document.get("pid"), "installation_pid")
        creation = _parse_int(document.get("creation_filetime"), "installation_creation_filetime")
        session = document.get("session_id")
        if not isinstance(session, str) or not session:
            raise PreflightError("installation_session_id_missing")
        if str(document.get("game_sha256", "")).lower() != EXPECTED_EXE_SHA256:
            raise PreflightError("installation_game_sha256_mismatch")
        report["identity"].update({
            "installation_pid": pid,
            "installation_creation_filetime": creation,
            "installation_session_id": session,
            "expected_session_id_from_installation": f"{pid}-{creation:x}",
        })
        kernel = _loc._configure_kernel()
        handle = kernel.OpenProcess(PROCESS_ACCESS, False, pid)
        if not handle:
            raise C.WinError(C.get_last_error())

        module_base = _loc._capture_identity(report, document, kernel, handle)
        # The PE image base is the static RVA anchor.  A live Windows image
        # may be relocated by ASLR, so the runtime module base must be a
        # canonical aligned pointer; it must not be forced to equal the PE
        # preferred base.
        module_base_valid = _safe_address(module_base, aligned=True)
        report["module_base"] = {
            "va": hex(module_base),
            "static_pe_image_base": hex(EXPECTED_IMAGE_BASE),
            "runtime_base_is_canonical_aligned": module_base_valid,
            "aslr_relocation_observed": module_base != EXPECTED_IMAGE_BASE,
            "rvas_resolved_against_runtime_base": True,
        }
        current_creation = report["identity"].get("process_creation_filetime")
        current_session = f"{pid}-{int(current_creation):x}" if isinstance(current_creation, int) else None
        report["identity"]["current_session_id"] = current_session
        report["identity"]["session_id_matches_installation"] = session == f"{pid}-{creation:x}"
        report["identity"]["session_id_matches_current_identity"] = current_session == session
        report["identity"]["binding_verified"] = bool(
            report["identity"].get("binding_verified") is True
            and module_base_valid
            and report["identity"]["session_id_matches_installation"] is True
            and report["identity"]["session_id_matches_current_identity"] is True
        )
        if not report["identity"]["binding_verified"]:
            raise PreflightError("fresh_process_identity_or_session_mismatch")

        process_path = Path(str(report["identity"].get("process_path")))
        report["fixed_file_code_guard"] = _file_code_guard(process_path)
        report["loaded_dll"] = _war._loaded_dll_check(kernel, handle, document, "fresh")
        if report["fixed_file_code_guard"].get("status") != "observed":
            raise PreflightError("fixed_file_code_guard_failed")
        if report["loaded_dll"].get("status") != "observed":
            raise PreflightError("loaded_v22_dll_guard_failed")

        reader = PreflightRPM(kernel, handle, module_base)
        report["runtime_code_guard"]["before"] = _runtime_code_guard(reader, module_base, "before")
        report["before"] = _snapshot(reader, module_base, "before")
        report["runtime_code_guard"]["after"] = _runtime_code_guard(reader, module_base, "after")
        report["after"] = _snapshot(reader, module_base, "after")
        report["doublepass"]["performed"] = True
        report["doublepass"]["mismatches"] = _diff_projection(report["before"], report["after"])
        report["doublepass"]["consistent"] = not report["doublepass"]["mismatches"]
        if report["runtime_code_guard"]["before"].get("status") != "observed":
            raise PreflightError("runtime_code_guard_before_failed")
        if report["runtime_code_guard"]["after"].get("status") != "observed":
            raise PreflightError("runtime_code_guard_after_failed")
        if report["before"].get("status") != "observed" or report["after"].get("status") != "observed":
            raise PreflightError("date_pause_speed_observation_incomplete")
        if report["doublepass"]["consistent"] is not True:
            raise PreflightError("date_pause_speed_changed_between_readbacks")
        report["status"] = "passed_read_only_preflight"
    except Exception as exc:
        report["status"] = "failed_read_only_preflight"
        report["errors"].append({"stage": "preflight", "status": "unknown", "error": f"{type(exc).__name__}:{exc}"})
    finally:
        if reader is not None:
            report["access"]["rpm_bytes_requested"] = reader.bytes_requested
            report["access"]["rpm_calls"] = reader.calls
            report["access"]["read_log"] = list(reader.read_log)
        close = _loc._close_process_handle(kernel, handle)
        close["calls"] = 1 if close.get("status") == "closed" else 0
        report["cleanup"]["handle_close"] = close
        report["completed"] = True
        if report["status"] == "passed_read_only_preflight" and close.get("status") != "closed":
            report["status"] = "failed_read_only_preflight"
            report["errors"].append({"stage": "cleanup", "status": "unknown", "error": "process_handle_not_closed"})
    _write_report(output, report)
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--installation", type=Path, default=DEFAULT_INSTALLATION)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args(argv)
    try:
        report = run(args.installation.resolve(), args.output.resolve())
    except Exception as exc:
        print(f"preflight did not write a report: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({"status": report["status"], "output": str(args.output.resolve()), "errors": report["errors"]}, ensure_ascii=False))
    return 0 if report["status"] == "passed_read_only_preflight" else 1


if __name__ == "__main__":
    raise SystemExit(main())
