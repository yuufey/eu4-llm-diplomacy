"""Read-only verification of an installed v23-v33 information-battle artifact.

The manifest and DLL hashes are operator-supplied trust pins.  The probe never
derives an expected hash from the artifact it is checking.  Static artifact
copies, the current development source tree, and fresh process observations
are reported as separate evidence classes.
"""
from __future__ import annotations

import argparse
import ctypes as C
from ctypes import wintypes as W
import hashlib
import json
import os
from pathlib import Path
import re
import sys
from typing import Any, Mapping

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools import start_diplomacy_observer as _start
from work import probe_information_battle_v23 as _legacy


ROOT = Path(__file__).resolve().parents[1]
EXPECTED_EXE_VERSION = "1.37.4"
EXPECTED_EXE_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
EXPECTED_SOURCE_COUNTS = {
    23: 103, 24: 105, 25: 107, 26: 110, 27: 110, 28: 112, 29: 116,
    30: 118, 31: 121, 32: 121, 33: 124,
}
PROCESS_ACCESS = _legacy.PROCESS_ACCESS
MAX_JSON_BYTES = 256 * 1024
MAX_SOURCE_BYTES = 16 * 1024 * 1024
MAX_DLL_BYTES = 16 * 1024 * 1024
MAX_TOTAL_RPM = _legacy.MAX_TOTAL_RPM
MAX_SINGLE_RPM = _legacy.MAX_SINGLE_RPM
ENTRY_RVA = _legacy.ENTRY_RVA
UNWIND_RVA = _legacy.UNWIND_RVA
ENTRY_SIZE = _legacy.ENTRY_SIZE
UNWIND_SIZE = _legacy.UNWIND_SIZE
STUB_SYMBOL = _legacy.STUB_SYMBOL
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_COUNTRY_CONTROL_SAVED_RE = re.compile(
    r"^country-control-([A-Za-z0-9_-]{1,64})\.request\.saved$"
)
_COUNTRY_CONTROL_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_COUNTRY_CONTROL_DECIMAL_RE = re.compile(r"^(?:0|[1-9][0-9]*)$")
_COUNTRY_CONTROL_TERMINAL = {"confirmed", "rejected", "failed"}
_COUNTRY_CONTROL_PAIRS = {("POR", "FRA"), ("FRA", "POR")}
_MAX_COUNTRY_CONTROL_PACKET = 320
_MAX_COUNTRY_CONTROL_ATTEMPT_LOG = 128 * 1024

# These helpers are deliberately aliases to the reviewed v23 implementation.
# The new probe supplies the artifact path and expected hashes instead of using
# the old fixed v23 build constants.
V23RPM = _legacy.V23RPM
_capture_identity = _legacy._capture_identity
_query_module_records = _legacy._query_module_records
_runtime_code_guard = _legacy._runtime_code_guard
_snapshot = _legacy._snapshot
_file_code_guard = _legacy._file_code_guard
_coff_symbol = _legacy._coff_symbol
_guard_record = _legacy._guard_record
_configure_kernel = _legacy._loc._configure_kernel
_close_process_handle = _legacy._loc._close_process_handle
_configured_game_exe = _legacy._configured_game_exe
_coff_symbol_from_bytes = _legacy._coff_symbol_from_bytes


# These are the two fixed 1.37.4 entries used by the v26 template source.
# The bytes are copied from information-battle-message-entry-plan.h and are
# kept here as a bounded runtime guard, not as a second patch implementation.
MESSAGE_ENTRY_SPECS: dict[str, dict[str, Any]] = {
    "router": {
        "entry_rva": 0x23A020,
        "end_rva": 0x23A6B8,
        "unwind_rva": 0x1DE6D8C,
        "prefix": bytes.fromhex(
            "48895c24105556574154415541564157488bec4881ec80000000"
        ),
        "unwind": bytes.fromhex(
            "111a0a00 1a341900 1af210f0 0ee00cd0 0ac00870 07600650 9c4da301"
        ),
        "projected_unwind_bytes": 24,
        "stack_delta": 184,
    },
    "message": {
        "entry_rva": 0x244630,
        "end_rva": 0x2446EE,
        "unwind_rva": 0x1DE7940,
        "prefix": bytes.fromhex(
            "4889542410534881ec00010000488bda"
        ),
        "unwind": bytes.fromhex(
            "110d03000d012000063000009c4da301"
        ),
        "projected_unwind_bytes": 12,
        "stack_delta": 264,
    },
}
# v27 adds one independently guarded formatter-cleanup entry.  Keep it out of
# MESSAGE_ENTRY_SPECS so the v26 artifact and its helpers continue to inspect
# exactly the two original entries.
FORMATTER_CONTAINER_ENTRY_SPEC: dict[str, Any] = {
    "entry_rva": 0x1AF740,
    "end_rva": 0x1AF755,
    "unwind_rva": 0x1DCAD04,
    "prefix": bytes.fromhex("48895c2410564883ec20488b19488bf1"),
    "unwind": bytes.fromhex("010a04000a3407000a320660"),
    "projected_unwind_bytes": 12,
    "stack_delta": 40,
}
MESSAGE_ENTRY_HOOK_SYMBOLS = {
    "router": "information_battle_router_hook",
    "message": "information_battle_message_hook",
}
MESSAGE_ENTRY_ORIGINAL_SYMBOLS = {
    "router": "information_battle_router_original",
    "message": "information_battle_message_original",
}
MESSAGE_ENTRY_SYMBOLS = {
    "router_hook": MESSAGE_ENTRY_HOOK_SYMBOLS["router"],
    "message_hook": MESSAGE_ENTRY_HOOK_SYMBOLS["message"],
    "router_original": MESSAGE_ENTRY_ORIGINAL_SYMBOLS["router"],
    "message_original": MESSAGE_ENTRY_ORIGINAL_SYMBOLS["message"],
}
FORMATTER_CONTAINER_SYMBOLS = {
    "container_hook": "information_battle_container_hook",
    "container_original": "information_battle_container_original",
}
LINE1_ENTRY_SPEC: dict[str, Any] = {
    "entry_rva": 0x152AD10,
    "end_rva": 0x152AD92,
    "unwind_rva": 0x1DCA66C,
    "prefix": bytes.fromhex(
        "48895c240848896c24104889742418574883ec20"
    ),
    "unwind": bytes.fromhex(
        "0114080014640800145407001434060014321070"
    ),
    "projected_unwind_bytes": 20,
    "stack_delta": 0x28,
    "trampoline_layout": "absolute_jump",
    "trampoline_jump_bytes": 14,
}
LINE1_ENTRY_SYMBOLS = {
    "line1_hook": "information_battle_line1_hook",
    "line1_original": "information_battle_line1_original",
}
TRAMPOLINE_BYTES = 128
HOME_SLOT_JUMP_BYTES = 29
PAGE_EXECUTE_READ = 0x20
MEM_COMMIT = 0x1000


def _entry_specs_for_version(version: int) -> Mapping[str, Mapping[str, Any]]:
    """Return the entry set for one artifact version without mutating v26 data."""
    if version >= 27:
        specs: dict[str, Mapping[str, Any]] = {
            **MESSAGE_ENTRY_SPECS, "container": FORMATTER_CONTAINER_ENTRY_SPEC,
        }
        if version >= 29:
            specs["line1"] = LINE1_ENTRY_SPEC
        return specs
    return MESSAGE_ENTRY_SPECS


def _entry_symbols_for_version(version: int) -> Mapping[str, str]:
    if version >= 27:
        symbols: dict[str, str] = {
            **MESSAGE_ENTRY_SYMBOLS, **FORMATTER_CONTAINER_SYMBOLS,
        }
        if version >= 29:
            symbols.update(LINE1_ENTRY_SYMBOLS)
        return symbols
    return MESSAGE_ENTRY_SYMBOLS


class _MemoryBasicInformation(C.Structure):
    _fields_ = [
        ("BaseAddress", C.c_void_p),
        ("AllocationBase", C.c_void_p),
        ("AllocationProtect", W.DWORD),
        ("PartitionId", W.WORD),
        ("RegionSize", C.c_size_t),
        ("State", W.DWORD),
        ("Protect", W.DWORD),
        ("Type", W.DWORD),
    ]


class InstalledProbeError(RuntimeError):
    """A bounded static, identity, or read-only runtime guard failed."""


def _sha256_pin(value: object, label: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise InstalledProbeError(f"{label}_must_be_exact_64_hex")
    return value.lower()


def _sha256_file(path: Path, *, max_bytes: int) -> dict[str, Any]:
    result: dict[str, Any] = {"path": str(path.resolve()), "status": "unknown"}
    try:
        before = path.stat()
    except OSError as exc:
        result.update({"status": "unavailable", "error": f"{type(exc).__name__}:{exc}"})
        return result
    result["size_bytes"] = before.st_size
    if not path.is_file():
        result.update({"status": "unavailable", "error": "not_a_file"})
        return result
    if before.st_size > max_bytes:
        result.update({"status": "rejected", "reason": "file_size_limit", "max_bytes": max_bytes})
        return result
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            while True:
                block = stream.read(1024 * 1024)
                if not block:
                    break
                digest.update(block)
        after = path.stat()
    except OSError as exc:
        result.update({"status": "unavailable", "error": f"{type(exc).__name__}:{exc}"})
        return result
    result["sha256"] = digest.hexdigest()
    result["status"] = (
        "observed"
        if (before.st_size, before.st_mtime_ns, before.st_ctime_ns)
        == (after.st_size, after.st_mtime_ns, after.st_ctime_ns)
        else "changed_during_hash"
    )
    return result


def _read_json(path: Path, *, limit: int = MAX_JSON_BYTES) -> tuple[dict[str, Any], dict[str, Any]]:
    pin = _sha256_file(path, max_bytes=limit)
    if pin.get("status") != "observed":
        raise InstalledProbeError(f"json_{pin.get('status', 'unavailable')}:{path}")
    try:
        raw = path.read_bytes()
        if len(raw) > limit:
            raise InstalledProbeError(f"json_file_size_limit:{path}")
        if (len(raw) != pin.get("size_bytes")
                or hashlib.sha256(raw).hexdigest() != pin.get("sha256")):
            raise InstalledProbeError(f"json_changed_after_hash:{path}")
        value = json.loads(raw.decode("utf-8-sig"))
    except InstalledProbeError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise InstalledProbeError(f"json_invalid:{path}") from exc
    if not isinstance(value, dict):
        raise InstalledProbeError(f"json_object_required:{path}")
    return value, pin


def _country_control_packet(raw: bytes, filename_id: str,
                            identity: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(raw, bytes) or not 0 < len(raw) <= _MAX_COUNTRY_CONTROL_PACKET:
        raise InstalledProbeError("saved_request_size_invalid")
    if (not raw.endswith(b"\n") or raw.count(b"\n") != 1
            or b"\r" in raw or b"\x00" in raw):
        raise InstalledProbeError("saved_request_line_grammar_invalid")
    try:
        line = raw[:-1].decode("ascii")
    except UnicodeError as exc:
        raise InstalledProbeError("saved_request_not_ascii") from exc
    fields = line.split(" ")
    if len(fields) != 9 or any(not field for field in fields):
        raise InstalledProbeError("saved_request_token_count_invalid")
    magic, mode, request_id, pid_text, creation_text, date_text, dll_sha, from_tag, to_tag = fields
    if magic != "EU4COUNTRY1" or mode != "TEST_ONLY":
        raise InstalledProbeError("saved_request_protocol_invalid")
    if _COUNTRY_CONTROL_ID_RE.fullmatch(request_id) is None or request_id != filename_id:
        raise InstalledProbeError("saved_request_id_filename_mismatch")
    if (_COUNTRY_CONTROL_DECIMAL_RE.fullmatch(pid_text) is None
            or _COUNTRY_CONTROL_DECIMAL_RE.fullmatch(creation_text) is None
            or _COUNTRY_CONTROL_DECIMAL_RE.fullmatch(date_text) is None):
        raise InstalledProbeError("saved_request_decimal_invalid")
    pid, creation, date = int(pid_text), int(creation_text), int(date_text)
    if pid <= 0 or creation <= 0 or date > 0x7FFFFFFF:
        raise InstalledProbeError("saved_request_decimal_out_of_range")
    expected_pid = _strict_positive(identity.get("pid"), "installation_pid")
    expected_creation = _strict_positive(identity.get("creation_filetime"), "installation_creation")
    expected_dll = identity.get("dll_sha256")
    if (not isinstance(expected_dll, str) or _SHA256_RE.fullmatch(expected_dll) is None
            or expected_dll != expected_dll.lower()):
        raise InstalledProbeError("installation_dll_sha_invalid")
    if pid != expected_pid or creation != expected_creation or dll_sha != expected_dll:
        raise InstalledProbeError("saved_request_installation_identity_mismatch")
    if _SHA256_RE.fullmatch(dll_sha) is None or dll_sha != dll_sha.lower():
        raise InstalledProbeError("saved_request_dll_sha_invalid")
    if (from_tag, to_tag) not in _COUNTRY_CONTROL_PAIRS:
        raise InstalledProbeError("saved_request_direction_invalid")
    return {
        "request_id": request_id,
        "pid": pid,
        "creation_filetime": creation,
        "date": date,
        "dll_sha256": dll_sha,
        "request_from": from_tag,
        "request_to": to_tag,
        "request_ascii_without_lf": line,
    }


def _country_control_status_identity(directory: Path,
                                     identity: Mapping[str, Any]) -> dict[str, Any]:
    status, pin = _read_json(directory / "information-country-control-status.json",
                             limit=128 * 1024)
    expected_pid = _strict_positive(identity.get("pid"), "installation_pid")
    expected_creation = _strict_positive(identity.get("creation_filetime"), "installation_creation")
    expected_dll = identity.get("dll_sha256")
    if (status.get("schema") != "EU4COUNTRY1"
            or type(status.get("pid")) is not int or status.get("pid") != expected_pid
            or _strict_positive(status.get("creation_filetime"), "country_status_creation") != expected_creation
            or status.get("dll_sha256") != expected_dll):
        raise InstalledProbeError("country_status_installation_identity_mismatch")
    return {"value": status, "pin": pin}


def _country_control_terminal_evidence(directory: Path, packet: Mapping[str, Any],
                                       current_status: Mapping[str, Any]) -> dict[str, Any]:
    request_id = str(packet["request_id"])
    from_tag = str(packet["request_from"])
    to_tag = str(packet["request_to"])
    attempt_path = directory / f"information-country-control-{to_tag}.attempt.jsonl"
    if attempt_path.exists():
        before = attempt_path.stat()
        if not attempt_path.is_file() or before.st_size > _MAX_COUNTRY_CONTROL_ATTEMPT_LOG:
            raise InstalledProbeError("country_attempt_log_size_invalid")
        raw = attempt_path.read_bytes()
        after = attempt_path.stat()
        if ((before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                != (after.st_size, after.st_mtime_ns, after.st_ctime_ns)
                or len(raw) != before.st_size):
            raise InstalledProbeError("country_attempt_log_changed_during_read")
        terminal_records: list[dict[str, Any]] = []
        reserved_records: list[dict[str, Any]] = []
        try:
            lines = raw.decode("utf-8").splitlines()
            for line in lines:
                if not line:
                    continue
                record = json.loads(line)
                if not isinstance(record, dict):
                    raise InstalledProbeError("country_attempt_log_record_invalid")
                if record.get("request_id") != request_id:
                    continue
                if record.get("event") == "reserved_before_native":
                    reserved_records.append(record)
                elif record.get("event") == "terminal":
                    terminal_records.append(record)
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise InstalledProbeError("country_attempt_log_json_invalid") from exc
        if len(reserved_records) > 1 or len(terminal_records) > 1:
            raise InstalledProbeError("country_attempt_log_duplicate_id")
        if reserved_records:
            if reserved_records[0].get("request_ascii") != packet["request_ascii_without_lf"]:
                raise InstalledProbeError("country_attempt_log_request_mismatch")
        if terminal_records:
            terminal = terminal_records[0]
            state = terminal.get("state")
            if state not in _COUNTRY_CONTROL_TERMINAL:
                raise InstalledProbeError("country_attempt_not_terminal")
            if (type(terminal.get("native_attempted")) is not bool
                    or type(terminal.get("native_return")) is not int
                    or terminal.get("native_return") not in (0, 1)
                    or not isinstance(terminal.get("observed_ref"), str)
                    or re.fullmatch(r"[0-9a-f]{16}", terminal["observed_ref"]) is None
                    or type(terminal.get("date")) is not int
                    or not isinstance(terminal.get("reason"), str)):
                raise InstalledProbeError("country_attempt_terminal_fields_invalid")
            if state == "confirmed" and not (
                    terminal.get("native_attempted") is True
                    and type(terminal.get("native_return")) is int
                    and terminal.get("native_return") == 1):
                raise InstalledProbeError("country_attempt_confirmation_invalid")
            return {
                "status": "observed_terminal_attempt_log",
                "state": state,
                "path": str(attempt_path),
                "bytes": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest(),
            }

    status = current_status.get("value") if isinstance(current_status, Mapping) else None
    if (isinstance(status, Mapping)
            and status.get("request_id") == request_id
            and status.get("request_from") == from_tag
            and status.get("request_to") == to_tag
            and status.get("state") in _COUNTRY_CONTROL_TERMINAL
            and status.get("date_before") == packet.get("date")):
        if (type(status.get("native_attempted")) is not bool
                or status.get("native_return") not in (None, 0, 1)
                or (status.get("native_return") is not None
                    and type(status.get("native_return")) is not int)
                or type(status.get("native_calls")) is not int):
            raise InstalledProbeError("country_status_terminal_fields_invalid")
        if status.get("state") == "confirmed" and not (
                status.get("native_attempted") is True
                and type(status.get("native_return")) is int
                and status.get("native_return") == 1):
            raise InstalledProbeError("country_status_confirmation_invalid")
        if status.get("state") == "confirmed" and status.get("native_calls") <= 0:
            raise InstalledProbeError("country_status_confirmation_call_count_invalid")
        return {
            "status": "observed_current_terminal_status",
            "state": status["state"],
            "path": str(directory / "information-country-control-status.json"),
            "sha256": current_status["pin"].get("sha256"),
        }
    raise InstalledProbeError("saved_request_terminal_evidence_missing")


def classify_country_control_consumed_receipts(
        directory: Path, identity: Mapping[str, Any]) -> dict[str, Any]:
    """Classify only exact saved request names with matching identity and terminal evidence.

    This is file-only evidence.  It never opens a process or uses RPM/native APIs.
    Invalid lookalikes remain unverified and must stay in any pending-channel result.
    """
    directory = Path(directory)
    candidates: list[dict[str, Any]] = []
    invalid: list[dict[str, Any]] = []
    if not directory.is_dir():
        return {"status": "directory_unavailable", "closed": candidates,
                "unverified": invalid, "native_calls": 0, "game_access": False}
    paths = [path for path in directory.iterdir()
             if path.is_file() and _COUNTRY_CONTROL_SAVED_RE.fullmatch(path.name)]
    if not paths:
        return {"status": "no_candidates", "closed": candidates,
                "unverified": invalid, "native_calls": 0, "game_access": False}
    try:
        current_status = _country_control_status_identity(directory, identity)
    except Exception as exc:
        current_status = None
        status_error = f"{type(exc).__name__}:{exc}"
    else:
        status_error = None
    for path in sorted(paths, key=lambda item: item.name):
        match = _COUNTRY_CONTROL_SAVED_RE.fullmatch(path.name)
        assert match is not None
        try:
            before = path.stat()
            if not path.is_file() or before.st_size <= 0 or before.st_size > _MAX_COUNTRY_CONTROL_PACKET:
                raise InstalledProbeError("saved_request_size_invalid")
            raw = path.read_bytes()
            after = path.stat()
            if ((before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                    != (after.st_size, after.st_mtime_ns, after.st_ctime_ns)
                    or len(raw) != before.st_size):
                raise InstalledProbeError("saved_request_changed_during_read")
            packet = _country_control_packet(raw, match.group(1), identity)
            if current_status is None:
                raise InstalledProbeError(status_error or "country_status_identity_unavailable")
            terminal = _country_control_terminal_evidence(directory, packet, current_status)
            candidates.append({
                "name": path.name,
                "request_id": packet["request_id"],
                "request_from": packet["request_from"],
                "request_to": packet["request_to"],
                "pid": packet["pid"],
                "creation_filetime": str(packet["creation_filetime"]),
                "dll_sha256": packet["dll_sha256"],
                "file": {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()},
                "terminal_evidence": terminal,
            })
        except Exception as exc:
            invalid.append({"name": path.name,
                            "reason": f"{type(exc).__name__}:{exc}"})
    return {
        "status": "observed" if not invalid else "partial_unverified_candidates",
        "closed": candidates,
        "unverified": invalid,
        "native_calls": 0,
        "game_access": False,
    }


def _native_registration_status(directory: Path) -> dict[str, Any]:
    """Copy native status fields without treating them as an independent unwind proof."""
    path = directory / "information-battle-status.json"
    result: dict[str, Any] = {
        "source": "native_information_battle_status_json",
        "path": str(path.resolve()),
        "status": "unavailable",
        "rtl_lookup_independent": False,
    }
    try:
        value, pin = _read_json(path)
        result.update({
            "status": "observed",
            "file": pin,
            "state": value.get("state"),
            "code_patch_installed": value.get("code_patch_installed"),
            "unwind_registered": value.get("unwind_registered"),
            "publication_stage": value.get("publication_stage"),
        })
    except InstalledProbeError as exc:
        result["reason"] = str(exc)
    return result


def _safe_child(directory: Path, name: object, label: str) -> Path:
    if not isinstance(name, str) or not name or len(name) > 512:
        raise InstalledProbeError(f"{label}_invalid_name")
    relative = Path(name)
    if relative.is_absolute() or relative.drive or ".." in relative.parts:
        raise InstalledProbeError(f"{label}_unsafe_name")
    resolved_directory = directory.resolve()
    resolved = (resolved_directory / relative).resolve()
    try:
        resolved.relative_to(resolved_directory)
    except ValueError as exc:
        raise InstalledProbeError(f"{label}_outside_artifact_directory") from exc
    return resolved


def _required_source_names(version: int) -> tuple[str, ...]:
    if version == 33:
        return tuple(_start.INFORMATION_BATTLE_DISPLAY_CONTEXT_REQUIRED_SOURCES)
    if version == 31:
        return tuple(_start.INFORMATION_CURRENT_COUNTRY_CONTROL_REQUIRED_SOURCES)
    if version in (32, 33):
        return tuple(_start.INFORMATION_BATTLE_GATE_TRACE_REQUIRED_SOURCES)
    if version == 30:
        return tuple(_start.INFORMATION_BATTLE_NATIVE_TITLE_QUERY_REQUIRED_SOURCES)
    if version == 29:
        return tuple(_start.INFORMATION_BATTLE_NATIVE_TEXT_REQUIRED_SOURCES)
    if version == 28:
        return tuple(_start.INFORMATION_BATTLE_WAR_IDENTITY_REQUIRED_SOURCES)
    if version >= 26:
        return tuple(_start.INFORMATION_BATTLE_TEMPLATE_REQUIRED_SOURCES)
    if version == 25:
        return tuple(_start.INFORMATION_BATTLE_NAVAL_REQUIRED_SOURCES)
    if version == 24:
        return tuple(_start.INFORMATION_BATTLE_CONTEXT_REQUIRED_SOURCES)
    return tuple(_start.INFORMATION_BATTLE_REQUIRED_SOURCES)


def _message_entry_symbols(path: Path, *, version: int = 26) -> dict[str, Any]:
    """Read the selected v26/v27 hook/global symbols from one bounded DLL image."""
    result: dict[str, Any] = {
        "status": "unknown",
        "source": "ordinary_pe_coff",
        "path": str(path.resolve()),
        "symbols": {},
        "unknown_conditions": [],
    }
    try:
        size = path.stat().st_size
        if size > MAX_DLL_BYTES:
            result["unknown_conditions"].append("dll_size_limit")
            return result
        raw = path.read_bytes()
        if len(raw) != size:
            result["unknown_conditions"].append("dll_size_changed")
            return result
        result["file_sha256"] = hashlib.sha256(raw).hexdigest()
        for role, symbol in _entry_symbols_for_version(version).items():
            row = _coff_symbol_from_bytes(raw, symbol)
            row["symbol"] = symbol
            result["symbols"][role] = row
        failed = [
            role for role, row in result["symbols"].items()
            if not isinstance(row, dict)
            or row.get("status") != "observed"
            or not isinstance(row.get("rva"), str)
        ]
        if failed:
            result["unknown_conditions"].append("coff_symbol_guard_failed:" + ",".join(failed))
        else:
            result["status"] = "observed"
    except (OSError, MemoryError, TypeError, ValueError) as exc:
        result["unknown_conditions"].append(f"coff_symbol_read_failed:{type(exc).__name__}:{exc}")
    return result


def _scope_address(value: object, *, size: int = 1) -> bool:
    if isinstance(value, bool) or not isinstance(value, int):
        return False
    return (value >= 0x10000 and size > 0
            and value < _legacy.MAX_USER_ADDRESS
            and size <= _legacy.MAX_USER_ADDRESS - value)


def _installed_message_prefix(target: int, size: int) -> bytes:
    if size < 14 or not _scope_address(target):
        raise InstalledProbeError("message_hook_target_invalid")
    return b"\xff\x25\0\0\0\0" + int(target).to_bytes(8, "little") + b"\x90" * (size - 14)


def _home_slot_jump(displacement: int, target: int) -> bytes:
    if displacement < 0 or displacement > 0xFFFFFFFF - 4 or not _scope_address(target):
        raise InstalledProbeError("message_trampoline_target_invalid")
    low = int(target).to_bytes(8, "little")
    return (
        b"\xc7\x84\x24" + int(displacement).to_bytes(4, "little") + low[:4]
        + b"\xc7\x84\x24" + int(displacement + 4).to_bytes(4, "little") + low[4:]
        + b"\xff\xa4\x24" + int(displacement).to_bytes(4, "little")
    )


def _projected_unwind(spec: Mapping[str, Any]) -> bytes:
    original = bytes(spec["unwind"])
    size = int(spec["projected_unwind_bytes"])
    if size <= 0 or size > len(original):
        raise InstalledProbeError("message_projected_unwind_invalid")
    return bytes([original[0] & 0x07]) + original[1:size]


def _file_message_code_guard(path: Path, *, version: int = 26) -> dict[str, Any]:
    """Compare the selected source entry/unwind windows with ordinary PE bytes."""
    result: dict[str, Any] = {
        "status": "unknown",
        "source": "ordinary_pe_file",
        "expected_phase": "original_image_on_disk",
        "records": {},
        "source_pdata": {
            "status": "not_independently_read",
            "reason": "no_bounded_pdata_row_locator_in_installed_probe",
        },
        "unknown_conditions": [],
    }
    try:
        for name, spec in _entry_specs_for_version(version).items():
            entry = _legacy._loc._read_pe_rva_bytes(path, int(spec["entry_rva"]), len(spec["prefix"]))
            unwind = _legacy._loc._read_pe_rva_bytes(path, int(spec["unwind_rva"]), len(spec["unwind"]))
            result["records"][f"{name}_entry_original"] = _guard_record(
                entry, bytes(spec["prefix"]), int(spec["entry_rva"]), f"{name}_entry_original"
            )
            result["records"][f"{name}_unwind_original"] = _guard_record(
                unwind, bytes(spec["unwind"]), int(spec["unwind_rva"]), f"{name}_unwind_original"
            )
        failed = [key for key, row in result["records"].items() if row.get("matches") is not True]
        if failed:
            result["unknown_conditions"].append("message_file_code_guard_mismatch:" + ",".join(failed))
        else:
            result["status"] = "observed"
    except (OSError, InstalledProbeError, TypeError, ValueError) as exc:
        result["unknown_conditions"].append(f"message_file_code_guard_failed:{type(exc).__name__}:{exc}")
    return result


def _query_rx_owned_128(kernel: Any, handle: Any, address: int) -> dict[str, Any]:
    """Use VirtualQueryEx on the existing read-only handle, when available."""
    result: dict[str, Any] = {
        "status": "unknown",
        "address": hex(address),
        "size_bytes": TRAMPOLINE_BYTES,
        "checks": {},
        "unknown_conditions": [],
    }
    query = getattr(kernel, "VirtualQueryEx", None)
    if query is None:
        result["unknown_conditions"].append("virtual_query_ex_unavailable")
        return result
    try:
        try:
            query.argtypes = [W.HANDLE, C.c_void_p, C.POINTER(_MemoryBasicInformation), C.c_size_t]
            query.restype = C.c_size_t
        except (AttributeError, TypeError):
            # Python fake kernels intentionally expose a plain callable seam.
            pass
        info = _MemoryBasicInformation()
        returned = query(handle, C.c_void_p(address), C.byref(info), C.sizeof(info))
        if not returned:
            result["unknown_conditions"].append("virtual_query_ex_failed")
            return result
        base = int(C.cast(info.BaseAddress, C.c_void_p).value or 0)
        allocation = int(C.cast(info.AllocationBase, C.c_void_p).value or 0)
        region_size = int(info.RegionSize)
        protect = int(info.Protect)
        state = int(info.State)
        result["region"] = {
            "base": hex(base),
            "allocation_base": hex(allocation),
            "region_size": region_size,
            "state": hex(state),
            "protect": hex(protect),
        }
        result["checks"] = {
            "query_struct_complete": int(returned) >= C.sizeof(info),
            "committed": state == MEM_COMMIT,
            "exact_allocation_base": allocation == address,
            "range_within_region": base <= address and address + TRAMPOLINE_BYTES <= base + region_size,
            "rx": (protect & 0xFF) == PAGE_EXECUTE_READ,
        }
        failed = [key for key, value in result["checks"].items() if value is not True]
        if failed:
            result["unknown_conditions"].append("trampoline_region_guard_failed:" + ",".join(failed))
        else:
            result["status"] = "observed"
    except (OSError, TypeError, ValueError, OverflowError) as exc:
        result["unknown_conditions"].append(f"virtual_query_ex_error:{type(exc).__name__}:{exc}")
    return result


def _message_entry_runtime_guard(
    reader: Any,
    game_module_base: int,
    dll_module_base: int,
    phase: str,
    expect_patch: str,
    symbols: Mapping[str, Mapping[str, Any]],
    original_symbols: Mapping[str, Mapping[str, Any]] | None = None,
    *,
    kernel: Any = None,
    handle: Any = None,
    version: int = 26,
) -> dict[str, Any]:
    """Pure RPM guard for the selected entries and published trampolines.

    The default remains the v26 two-entry guard for callers and fixtures that
    predate the formatter-container entry.  v27 callers opt into the third
    entry explicitly from the artifact version.
    """
    result: dict[str, Any] = {
        "phase": phase,
        "source": "rpm",
        "status": "unknown",
        "expect_patch": expect_patch,
        "records": {},
        "trampolines": {},
        "source_pdata": {
            "status": "not_independently_read",
            "reason": "RtlLookupFunctionEntry_is_not_called_by_probe",
        },
        "unknown_conditions": [],
    }
    try:
        for name, spec in _entry_specs_for_version(version).items():
            hook = symbols.get(f"{name}_hook")
            if not isinstance(hook, Mapping) or hook.get("status") != "observed":
                raise InstalledProbeError(f"message_hook_symbol_unavailable:{name}")
            hook_rva = int(str(hook["rva"]), 0)
            target = dll_module_base + hook_rva
            expected_prefix = bytes(spec["prefix"])
            if expect_patch == "installed":
                expected_prefix = _installed_message_prefix(target, len(expected_prefix))
            actual_prefix = reader.read_code(
                game_module_base + int(spec["entry_rva"]), len(spec["prefix"]),
                f"{phase}.{name}.entry"
            )
            actual_unwind = reader.read_code(
                game_module_base + int(spec["unwind_rva"]), len(spec["unwind"]),
                f"{phase}.{name}.unwind"
            )
            result["records"][f"{name}_entry"] = _guard_record(
                actual_prefix, expected_prefix, int(spec["entry_rva"]),
                f"{expect_patch}_{name}_entry"
            )
            result["records"][f"{name}_unwind"] = _guard_record(
                actual_unwind, bytes(spec["unwind"]), int(spec["unwind_rva"]),
                f"{name}_unwind_unchanged"
            )
            result["records"][f"{name}_entry"]["hook_symbol"] = hook.get("symbol")
            result["records"][f"{name}_entry"]["hook_target"] = hex(target)

        if expect_patch == "installed":
            if not isinstance(original_symbols, Mapping):
                raise InstalledProbeError("message_original_symbols_unavailable")
            for name, spec in _entry_specs_for_version(version).items():
                original = original_symbols.get(f"{name}_original")
                if not isinstance(original, Mapping) or original.get("status") != "observed":
                    raise InstalledProbeError(f"message_original_symbol_unavailable:{name}")
                original_rva = int(str(original["rva"]), 0)
                pointer_address = dll_module_base + original_rva
                trampoline, raw_pointer = reader.qword(
                    pointer_address, f"{phase}.{name}.original_pointer"
                )
                if not _scope_address(trampoline, size=TRAMPOLINE_BYTES):
                    raise InstalledProbeError(f"message_trampoline_address_invalid:{name}")
                image = reader.read_code(
                    trampoline, TRAMPOLINE_BYTES, f"{phase}.{name}.trampoline"
                )
                layout = str(spec.get("trampoline_layout", "home_slot"))
                jump_bytes = int(spec.get(
                    "trampoline_jump_bytes", HOME_SLOT_JUMP_BYTES
                ))
                continuation = game_module_base + int(spec["entry_rva"]) \
                    + len(spec["prefix"])
                if layout == "absolute_jump":
                    expected_jump = _installed_message_prefix(
                        continuation, jump_bytes
                    )
                else:
                    expected_jump = _home_slot_jump(
                        int(spec["stack_delta"]) + 0x18,
                        continuation,
                    )
                expected_projected = _projected_unwind(spec)
                code_end = len(spec["prefix"]) + jump_bytes
                jump_matches = image[len(spec["prefix"]):code_end] == expected_jump
                checks = {
                    "prefix_matches_original": image[:len(spec["prefix"])] == bytes(spec["prefix"]),
                    "trampoline_jump_matches": jump_matches,
                    "home_slot_jump_matches": (
                        jump_matches if layout != "absolute_jump" else True
                    ),
                    "absolute_jump_matches": (
                        jump_matches if layout == "absolute_jump" else True
                    ),
                    "image_gap_zeroed": image[code_end:64] == b"\0" * (64 - code_end),
                    "projected_unwind_flags_clear": (image[64] & 0xF8) == 0,
                    "projected_unwind_handler_cleared": (
                        image[64] == (bytes(spec["unwind"])[0] & 0x07)
                        and image[64:64 + len(expected_projected)] == expected_projected
                    ),
                    "image_tail_zeroed": image[64 + len(expected_projected):] == b"\0" * (128 - 64 - len(expected_projected)),
                }
                region = _query_rx_owned_128(kernel, handle, trampoline)
                checks["rx_owned_128"] = region.get("status") == "observed"
                result["trampolines"][name] = {
                    "pointer_address": hex(pointer_address),
                    "pointer_raw_hex": raw_pointer.hex(),
                    "trampoline": hex(trampoline),
                    "image_sha256": hashlib.sha256(image).hexdigest(),
                    "code_end_bytes": code_end,
                    "projected_unwind_bytes": len(expected_projected),
                    "checks": checks,
                    "region": region,
                    "status": "observed" if all(checks.values()) else "mismatch",
                }
                if not all(checks.values()):
                    raise InstalledProbeError(f"message_trampoline_guard_failed:{name}")
        failed = [key for key, row in result["records"].items() if row.get("matches") is not True]
        if failed:
            result["unknown_conditions"].append("message_runtime_code_guard_mismatch:" + ",".join(failed))
        elif expect_patch == "installed" and any(
                row.get("status") != "observed" for row in result["trampolines"].values()):
            result["unknown_conditions"].append("message_trampoline_guard_mismatch")
        else:
            result["status"] = "observed"
    except Exception as exc:
        result["unknown_conditions"].append(f"message_runtime_guard_failed:{type(exc).__name__}:{exc}")
    return result


def _validate_recorded_module(document: Mapping[str, Any], dll_path: Path, dll_sha: str) -> dict[str, Any]:
    records = document.get("modules_after_install")
    if not isinstance(records, list) or len(records) != 1 or not isinstance(records[0], dict):
        raise InstalledProbeError("installation_modules_after_install_not_unique")
    record = records[0]
    recorded_path = record.get("path")
    if not isinstance(recorded_path, str):
        raise InstalledProbeError("installation_module_path_missing")
    try:
        path_matches = Path(recorded_path).resolve() == dll_path.resolve()
    except OSError as exc:
        raise InstalledProbeError("installation_module_path_invalid") from exc
    name_matches = record.get("name") == dll_path.name
    sha_matches = str(record.get("sha256", "")).lower() == dll_sha
    checks = {
        "path_matches_manifest_dll": path_matches,
        "name_matches_manifest_dll": name_matches,
        "sha256_matches_expected_dll": sha_matches,
    }
    if not all(checks.values()):
        raise InstalledProbeError("installation_module_record_mismatch")
    return {"status": "observed", "record": dict(record), "checks": checks}


def _validate_artifact(
    build_dir: Path,
    *,
    expected_manifest_sha256: str,
    expected_dll_sha256: str,
) -> dict[str, Any]:
    """Validate one immutable build directory without consulting root sources."""
    expected_manifest = _sha256_pin(expected_manifest_sha256, "expected_manifest_sha256")
    expected_dll = _sha256_pin(expected_dll_sha256, "expected_dll_sha256")
    build_dir = build_dir.resolve()
    manifest_path = build_dir / "build-manifest.json"
    manifest, manifest_pin = _read_json(manifest_path)
    if manifest_pin.get("sha256") != expected_manifest:
        raise InstalledProbeError("manifest_sha256_does_not_match_external_pin")
    version = manifest.get("version")
    if type(version) is not int or version not in EXPECTED_SOURCE_COUNTS:
        raise InstalledProbeError("unsupported_manifest_version")
    if _sha256_pin(manifest.get("game_sha256"), "manifest_game_sha256") != EXPECTED_EXE_SHA256:
        raise InstalledProbeError("manifest_game_sha256_mismatch")
    if _sha256_pin(manifest.get("dll_sha256"), "manifest_dll_sha256") != expected_dll:
        raise InstalledProbeError("manifest_dll_sha256_mismatch")
    if manifest.get("information_battle_research_lifecycle") is not True:
        raise InstalledProbeError("information_battle_research_lifecycle_missing")

    if version in (24, 25, 26, 27, 28, 29, 30, 31, 32, 33):
        if (type(manifest.get("information_battle_context_wire")) is not int
                or manifest["information_battle_context_wire"] != 2
                or manifest.get("information_battle_owned_context") is not True):
            raise InstalledProbeError("v24_context_capability_mismatch")
        arguments = manifest.get("compiler_arguments")
        if (not isinstance(arguments, list)
                or "-DBRIDGE_INFORMATION_BATTLE=1" not in arguments
                or "-DINFORMATION_BATTLE_CONTEXT=1" not in arguments):
            raise InstalledProbeError("v24_compiler_macro_missing")
    if version in (25, 26, 27, 28, 29, 30, 31, 32, 33):
        if (type(manifest.get("information_battle_naval_wire")) is not int
                or manifest["information_battle_naval_wire"] != 3
                or manifest.get("information_battle_owned_naval") is not True
                or "-DINFORMATION_BATTLE_NAVAL=1" not in manifest["compiler_arguments"]):
            raise InstalledProbeError("v25_naval_capability_mismatch")
    if version in (26, 27, 28, 29, 30, 31, 32, 33):
        arguments = manifest.get("compiler_arguments")
        if (type(manifest.get("information_battle_template_wire")) is not int
                or manifest["information_battle_template_wire"] != 4
                or manifest.get("information_battle_owned_template") is not True
                or manifest.get("information_battle_message_scope") is not True
                or not isinstance(arguments, list)
                or "-DINFORMATION_BATTLE_TEMPLATE=1" not in arguments):
            raise InstalledProbeError("v26_template_capability_mismatch")
    if version in (27, 28, 29, 30, 31, 32, 33):
        arguments = manifest.get("compiler_arguments")
        if (manifest.get("information_battle_formatter_container") is not True
                or manifest.get("information_battle_template_extensions") != [1, 2]
                or not isinstance(arguments, list)
                or "-DINFORMATION_BATTLE_CONTAINER=1" not in arguments):
            raise InstalledProbeError("v27_formatter_container_capability_mismatch")
    if version in (28, 29, 30, 31, 32, 33):
        arguments = manifest.get("compiler_arguments")
        if (manifest.get("information_battle_war_identity") is not True
                or manifest.get("information_battle_war_identity_wire") != 5
                or manifest.get("information_battle_war_identity_scope")
                    != "observer_session"
                or manifest.get("information_battle_war_identity_read_only")
                    is not True
                or manifest.get("information_battle_war_identity_complete")
                    is not False
                or not isinstance(arguments, list)
                or "-DINFORMATION_BATTLE_WAR_IDENTITY=1" not in arguments):
            raise InstalledProbeError("v28_war_identity_capability_mismatch")
    if version in (29, 30, 31, 32, 33):
        arguments = manifest.get("compiler_arguments")
        if (manifest.get("information_battle_native_text") is not True
                or manifest.get("information_battle_native_text_wire") != 6
                or manifest.get("information_battle_native_text_scope")
                    != "observer_session"
                or manifest.get("information_battle_native_text_read_only")
                    is not True
                or manifest.get("information_battle_native_text_complete")
                    is not False
                or not isinstance(arguments, list)
                or "-DINFORMATION_BATTLE_NATIVE_TEXT=1" not in arguments):
            raise InstalledProbeError("v29_native_text_capability_mismatch")
    if version in (30, 31, 32, 33):
        arguments = manifest.get("compiler_arguments")
        if (manifest.get("information_battle_native_title_query") is not True
                or manifest.get("information_battle_native_title_query_mode")
                    != "native_helper_owned_output"
                or manifest.get("information_battle_native_title_query_wire") != 6
                or manifest.get("information_battle_native_title_query_complete") is not False
                or not isinstance(arguments, list)
                or "-DINFORMATION_BATTLE_NATIVE_TITLE_QUERY=1" not in arguments):
            raise InstalledProbeError("v30_native_title_query_capability_mismatch")
    if version == 31:
        arguments = manifest.get("compiler_arguments")
        if (manifest.get("current_country_control_test_only") is not True
                or manifest.get("current_country_control_protocol") != "EU4COUNTRY1"
                or manifest.get("current_country_control_entry_rva") != "0x779360"
                or manifest.get("runtime_verified") is not False
                or not isinstance(arguments, list)
                or "-DBRIDGE_CURRENT_COUNTRY_CONTROL=1" not in arguments
                or _start._has_compiler_define(
                    arguments,"INFORMATION_CURRENT_COUNTRY_HOST_FIXTURE")):
            raise InstalledProbeError("v31_current_country_control_capability_mismatch")
    if version in (32, 33):
        arguments = manifest.get("compiler_arguments")
        if (manifest.get("information_battle_gate_trace") is not True
                or manifest.get("information_battle_gate_trace_protocol")
                    != "EU4-BATTLE-GATE-TRACE/1"
                or manifest.get("information_battle_gate_trace_runtime_verified") is not False
                or not isinstance(arguments, list)
                or "-DINFORMATION_BATTLE_GATE_TRACE=1" not in arguments
                or _start._has_compiler_define(arguments, "BRIDGE_CURRENT_COUNTRY_CONTROL")
                or _start._has_compiler_define(
                    arguments, "INFORMATION_CURRENT_COUNTRY_HOST_FIXTURE")
                or any(key in manifest for key in (
                    "current_country_control_test_only",
                    "current_country_control_protocol",
                    "current_country_control_entry_rva",
                ))):
            raise InstalledProbeError("v32_battle_gate_trace_capability_mismatch")

    display_keys = (
        "information_battle_display_context", "information_battle_display_context_wire",
        "information_battle_display_context_scope", "information_battle_display_context_stage",
        "information_battle_display_context_read_only", "information_battle_display_context_complete",
    )
    arguments = manifest.get("compiler_arguments")
    if version == 33:
        if (manifest.get(display_keys[0]) is not True
                or type(manifest.get(display_keys[1])) is not int or manifest[display_keys[1]] != 7
                or manifest.get(display_keys[2]) != "same_battle_event"
                or manifest.get(display_keys[3]) != "router_scope_exit"
                or manifest.get(display_keys[4]) is not True
                or manifest.get(display_keys[5]) is not False
                or not isinstance(arguments, list)
                or "-DINFORMATION_BATTLE_DISPLAY_CONTEXT=1" not in arguments):
            raise InstalledProbeError("v33_display_context_capability_mismatch")
    elif (_start._has_compiler_define(arguments, "INFORMATION_BATTLE_DISPLAY_CONTEXT")
          or any(key in manifest for key in display_keys)):
        raise InstalledProbeError("unexpected_display_context_capability")

    records = manifest.get("sources")
    expected_count = EXPECTED_SOURCE_COUNTS[version]
    participants = manifest.get("native_war_participants_query", False)
    if version in (30, 31, 32, 33):
        if type(participants) is not bool:
            raise InstalledProbeError("native_war_participants_flag_invalid")
        expected_count += int(participants)
    if not isinstance(records, list) or len(records) != expected_count:
        raise InstalledProbeError("manifest_source_count_mismatch")
    required_names = set(_required_source_names(version))
    if version in (30, 31, 32, 33) and participants:
        required_names.update(("peace-context-query.inc", "peace-war-context-query.inc",
                               "peace-war-side-members.inc"))
    source_records: list[dict[str, Any]] = []
    seen: set[str] = set()
    source_failures: list[str] = []
    for index, row in enumerate(records):
        if not isinstance(row, dict):
            raise InstalledProbeError(f"manifest_source_record_invalid:{index}")
        name = row.get("name")
        digest = _sha256_pin(row.get("sha256"), f"manifest_source_sha256:{index}")
        path = _safe_child(build_dir, name, f"manifest_source:{index}")
        if name in seen:
            raise InstalledProbeError(f"manifest_source_duplicate:{name}")
        seen.add(name)
        actual = _sha256_file(path, max_bytes=MAX_SOURCE_BYTES)
        matches = actual.get("status") == "observed" and actual.get("sha256") == digest
        if not matches:
            source_failures.append(str(name))
        source_records.append({
            "name": name,
            "path": str(path),
            "manifest_sha256": digest,
            "actual": actual,
            "matches": matches,
        })
    if (version in (32, 33)
            and seen.intersection(_start.INFORMATION_CURRENT_COUNTRY_CONTROL_ONLY_SOURCES)):
        raise InstalledProbeError("v32_current_country_control_sources_forbidden")
    if set(seen) & required_names != required_names:
        missing = sorted(required_names - seen)
        raise InstalledProbeError("manifest_required_sources_missing:" + ",".join(missing))
    if source_failures:
        raise InstalledProbeError("artifact_source_copy_hash_mismatch")

    dll_path = build_dir / f"eu4_bridge_diplomacy_observer_v{version}.dll"
    dll_pin = _sha256_file(dll_path, max_bytes=MAX_DLL_BYTES)
    if dll_pin.get("status") != "observed" or dll_pin.get("sha256") != expected_dll:
        raise InstalledProbeError("artifact_dll_hash_mismatch")
    artifact = {
        "status": "observed",
        "build_directory": str(build_dir),
        "manifest": {"path": str(manifest_path), **manifest_pin, "external_expected_sha256": expected_manifest},
        "version": version,
        "target_build_version": EXPECTED_EXE_VERSION,
        "dll": {"path": str(dll_path), **dll_pin, "external_expected_sha256": expected_dll},
        "source_count": expected_count,
        "source_records": source_records,
        "required_sources": sorted(required_names),
        "v24_capability": {
            "context_wire": manifest.get("information_battle_context_wire") if version >= 24 else None,
            "owned_context": manifest.get("information_battle_owned_context") if version >= 24 else None,
            "compiler_macros": (
                ["-DBRIDGE_INFORMATION_BATTLE=1", "-DINFORMATION_BATTLE_CONTEXT=1"]
                if version >= 24 else []
            ),
        },
        "naval_capability": {
            "wire": manifest.get("information_battle_naval_wire") if version >= 25 else None,
            "owned_naval": manifest.get("information_battle_owned_naval") if version >= 25 else None,
        },
        "template_capability": {
            "wire": manifest.get("information_battle_template_wire") if version >= 26 else None,
            "owned_template": manifest.get("information_battle_owned_template") if version >= 26 else None,
            "message_scope": manifest.get("information_battle_message_scope") if version >= 26 else None,
            "formatter_container": manifest.get("information_battle_formatter_container") if version >= 27 else None,
            "template_extensions": manifest.get("information_battle_template_extensions") if version >= 27 else None,
            "compiler_macros": (
                (["-DINFORMATION_BATTLE_TEMPLATE=1", "-DINFORMATION_BATTLE_CONTAINER=1"]
                 if version >= 27 else ["-DINFORMATION_BATTLE_TEMPLATE=1"] if version >= 26 else [])
            ),
            "scope_entry_runtime_verified": False,
            "scope_entry_runtime_status": "not_implemented",
        },
        "manifest_value": manifest,
    }
    if version in (28, 29, 30, 31, 32, 33):
        artifact["war_identity_capability"] = {
            "enabled": manifest.get("information_battle_war_identity"),
            "wire": manifest.get("information_battle_war_identity_wire"),
            "scope": manifest.get("information_battle_war_identity_scope"),
            "read_only": manifest.get("information_battle_war_identity_read_only"),
            "complete": manifest.get("information_battle_war_identity_complete"),
            "compiler_macro": "-DINFORMATION_BATTLE_WAR_IDENTITY=1",
            "source_guard": True,
        }
    if version in (29, 30, 31, 32, 33):
        artifact["native_text_capability"] = {
            "enabled": manifest.get("information_battle_native_text"),
            "wire": manifest.get("information_battle_native_text_wire"),
            "scope": manifest.get("information_battle_native_text_scope"),
            "read_only": manifest.get("information_battle_native_text_read_only"),
            "complete": manifest.get("information_battle_native_text_complete"),
            "compiler_macro": "-DINFORMATION_BATTLE_NATIVE_TEXT=1",
            "source_guard": True,
        }
    if version in (30, 31, 32, 33):
        artifact["native_title_query_capability"] = {
            "enabled": manifest.get("information_battle_native_title_query"),
            "mode": manifest.get("information_battle_native_title_query_mode"),
            "wire": manifest.get("information_battle_native_title_query_wire"),
            "complete": manifest.get("information_battle_native_title_query_complete"),
            "compiler_macro": "-DINFORMATION_BATTLE_NATIVE_TITLE_QUERY=1",
            "source_guard": True,
            "helper_invoked": False,
            "scope_entry_runtime_verified": False,
            "scope_entry_runtime_status": "not_called_helper_pure_rpm",
        }
    if version in (32, 33):
        artifact["battle_gate_trace_capability"] = {
            "enabled": manifest.get("information_battle_gate_trace"),
            "protocol": manifest.get("information_battle_gate_trace_protocol"),
            "runtime_verified": manifest.get(
                "information_battle_gate_trace_runtime_verified"),
            "compiler_macro": "-DINFORMATION_BATTLE_GATE_TRACE=1",
            "private_diagnostic_sidecar": True,
            "business_b04_upgrade": False,
            "source_guard": True,
        }
    if version == 33:
        artifact["display_context_capability"] = {
            "enabled": manifest.get("information_battle_display_context"),
            "wire": manifest.get("information_battle_display_context_wire"),
            "scope": manifest.get("information_battle_display_context_scope"),
            "stage": manifest.get("information_battle_display_context_stage"),
            "read_only": manifest.get("information_battle_display_context_read_only"),
            "complete": manifest.get("information_battle_display_context_complete"),
            "compiler_macro": "-DINFORMATION_BATTLE_DISPLAY_CONTEXT=1",
            "source_guard": True,
            "runtime_popup_verified": False,
        }
    if version == 31:
        artifact["current_country_control_capability"] = {
            "test_only": manifest.get("current_country_control_test_only"),
            "protocol": manifest.get("current_country_control_protocol"),
            "entry_rva": manifest.get("current_country_control_entry_rva"),
            "runtime_verified": False,
            "compiler_macro": "-DBRIDGE_CURRENT_COUNTRY_CONTROL=1",
            "source_guard": True,
        }
    return artifact


def _development_root_delta(manifest: Mapping[str, Any], build_dir: Path, root_source_dir: Path) -> dict[str, Any]:
    """Report current development-source differences without affecting artifact status."""
    rows: list[dict[str, Any]] = []
    for row in manifest.get("sources", []):
        if not isinstance(row, dict) or not isinstance(row.get("name"), str):
            continue
        name = row["name"]
        try:
            artifact_path = _safe_child(build_dir, name, "development_delta_artifact")
            development_path = _safe_child(root_source_dir, name, "development_delta_root")
        except InstalledProbeError as exc:
            rows.append({"name": name, "status": "unknown", "reason": str(exc)})
            continue
        artifact_sha = str(row.get("sha256", "")).lower()
        current = _sha256_file(development_path, max_bytes=MAX_SOURCE_BYTES)
        if current.get("status") != "observed":
            rows.append({"name": name, "status": "unavailable", "artifact_sha256": artifact_sha, "development": current})
        else:
            rows.append({
                "name": name,
                "status": "same" if current.get("sha256") == artifact_sha else "different",
                "artifact_sha256": artifact_sha,
                "development_sha256": current.get("sha256"),
                "development_path": str(development_path),
            })
    counts: dict[str, int] = {}
    for row in rows:
        counts[row["status"]] = counts.get(row["status"], 0) + 1
    return {
        "status": "observed",
        "evidence_kind": "current_development_root_delta",
        "artifact_guard_affected": False,
        "root_source_directory": str(root_source_dir.resolve()),
        "counts": counts,
        "records": rows,
    }


def _strict_positive(value: object, label: str) -> int:
    if isinstance(value, bool):
        raise InstalledProbeError(f"{label}_invalid")
    if type(value) is int:
        result = value
    elif isinstance(value, str) and value and value.isascii() and value.isdecimal():
        result = int(value, 10)
    else:
        raise InstalledProbeError(f"{label}_invalid")
    if result <= 0:
        raise InstalledProbeError(f"{label}_invalid")
    return result


def _strict_loaded_module_guard(
    loaded: Mapping[str, Any], dll_path: Path, expected_dll_sha: str
) -> dict[str, Any]:
    """Require exactly one loaded eu4_bridge DLL, and make it the pinned one."""
    modules = loaded.get("modules")
    if not isinstance(modules, list):
        raise InstalledProbeError("loaded_module_enumeration_missing")
    bridge_modules: list[dict[str, Any]] = []
    expected_matches: list[dict[str, Any]] = []
    expected_path = dll_path.resolve()
    for row in modules:
        if not isinstance(row, dict) or not isinstance(row.get("path"), str):
            continue
        try:
            path = Path(row["path"]).resolve()
        except OSError:
            continue
        if path.name.lower().startswith("eu4_bridge"):
            bridge_modules.append(row)
        if path == expected_path and str(row.get("sha256", "")).lower() == expected_dll_sha:
            expected_matches.append(row)
    checks = {
        "exactly_one_eu4_bridge_module": len(bridge_modules) == 1,
        "exactly_one_expected_module": len(expected_matches) == 1,
        "expected_path": len(expected_matches) == 1 and Path(expected_matches[0]["path"]).resolve() == expected_path,
        "expected_sha256": len(expected_matches) == 1 and str(expected_matches[0].get("sha256", "")).lower() == expected_dll_sha,
    }
    if not all(checks.values()):
        raise InstalledProbeError("loaded_module_set_guard_failed")
    return {
        "status": "observed",
        "checks": checks,
        "bridge_module_count": len(bridge_modules),
        "expected_module": dict(expected_matches[0]),
    }


def _load_installation(
    path: Path,
    expected_dll_sha: str,
    expected_experiment_id: object,
) -> tuple[dict[str, Any], dict[str, Any], Path]:
    path = path.resolve()
    if path.name.lower() != "installation.json" or not path.is_file():
        raise InstalledProbeError("installation_path_invalid")
    document, pin = _read_json(path)
    pid = _strict_positive(document.get("pid"), "installation_pid")
    creation = _strict_positive(document.get("creation_filetime"), "installation_creation_filetime")
    if document.get("experiment_id") != expected_experiment_id:
        raise InstalledProbeError("installation_experiment_id_mismatch")
    returncode = document.get("installation_returncode")
    if type(returncode) is not int or returncode != 0:
        raise InstalledProbeError("installation_returncode_not_zero")
    session = document.get("session_id")
    if not isinstance(session, str) or session != f"{pid}-{creation:x}":
        raise InstalledProbeError("installation_session_id_mismatch")
    if _sha256_pin(document.get("game_sha256"), "installation_game_sha256") != EXPECTED_EXE_SHA256:
        raise InstalledProbeError("installation_game_sha256_mismatch")
    if _sha256_pin(document.get("dll_sha256"), "installation_dll_sha256") != expected_dll_sha:
        raise InstalledProbeError("installation_dll_sha256_mismatch")
    process_value = document.get("process_path") or document.get("game_path")
    process_path = Path(process_value).resolve() if isinstance(process_value, str) and process_value else Path(_configured_game_exe()).resolve()
    if not process_path.is_file():
        raise InstalledProbeError("configured_process_path_missing")
    return document, {"path": str(path), **pin}, process_path


def _base_report(installation: Path, output: Path, expect_patch: str, expected_manifest: str, expected_dll: str) -> dict[str, Any]:
    return {
        "schema": "information_battle_installed_preflight_v1",
        "probe": "information-battle-installed",
        "probe_script": str(Path(__file__).resolve()),
        "probe_script_sha256": _sha256_file(Path(__file__), max_bytes=MAX_JSON_BYTES).get("sha256"),
        "read_only": True,
        "game_access": False,
        "process_opened": False,
        "runtime_accessed": False,
        "remote_rpm": False,
        "native_game_function_invoked": False,
        "target_memory_writes": False,
        "request": {
            "installation": str(installation.resolve()),
            "output": str(output.resolve()),
            "expect_patch": expect_patch,
            "expected_manifest_sha256": expected_manifest,
            "expected_dll_sha256": expected_dll,
            "business_query_invoked": False,
            "native_game_function_invoked": False,
            "target_memory_writes": False,
            "dll_injection": False,
            "control_command_sent": False,
            "save_or_reload": False,
            "date_advance": False,
        },
        "target_build": {
            "version": EXPECTED_EXE_VERSION,
            "expected_exe_sha256": EXPECTED_EXE_SHA256,
            "process_access": hex(PROCESS_ACCESS),
            "entry_rva": hex(ENTRY_RVA),
            "unwind_rva": hex(UNWIND_RVA),
            "scope_entry_runtime_verified": False,
            "scope_entry_runtime_status": "not_implemented",
        },
        "template_capability": {
            "wire": None,
            "owned_template": None,
            "message_scope": None,
            "formatter_container": None,
            "template_extensions": None,
            "scope_entry_runtime_verified": False,
            "scope_entry_runtime_status": "not_implemented",
        },
        "message_entry_symbols": None,
        "message_entry_file_guard": None,
        "message_entry_guard": {"before": None, "after": None},
        "formatter_container_entry_guard": {"before": None, "after": None},
        "line1_entry_guard": {"before": None, "after": None},
        "native_text_capability": {
            "enabled": None,
            "wire": None,
            "scope": None,
            "read_only": None,
            "complete": None,
            "scope_entry_runtime_verified": False,
            "scope_entry_runtime_status": "not_implemented",
        },
        "native_title_query_capability": {
            "enabled": None,
            "mode": None,
            "wire": None,
            "complete": None,
            "helper_invoked": False,
            "scope_entry_runtime_verified": False,
            "scope_entry_runtime_status": "not_implemented",
        },
        "registration_status": {
            "source": "native_information_battle_status_json",
            "status": "not_independently_verified",
            "rtl_lookup_independent": False,
        },
        "country_control_consumed_receipts": {
            "status": "not_checked", "closed": [], "unverified": [],
            "native_calls": 0, "game_access": False,
        },
        "artifact": None,
        "development_root_delta": None,
        "installation": None,
        "identity": {"before": None, "after": None, "binding_verified": False},
        "loaded_dll": {"before": None, "after": None, "same_path_sha": None},
        "stub": None,
        "fixed_file_code_guard": None,
        "runtime_code_guard": {"before": None, "after": None},
        "before": None,
        "after": None,
        "doublepass": {"performed": False, "consistent": None, "checks": {}},
        "access": {"rpm_total_limit": MAX_TOTAL_RPM, "rpm_single_read_limit": MAX_SINGLE_RPM, "remote_rpm": False, "rpm_bytes_requested": 0, "rpm_calls": 0, "read_log": []},
        "cleanup": {"handle_close": {"status": "not_opened", "closed": False, "calls": 0}},
        "status": "starting",
        "errors": [],
        "completed": False,
    }


def _write_new(path: Path, value: Mapping[str, Any]) -> str:
    path = path.resolve()
    raw = (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")
    if len(raw) > 2 * 1024 * 1024:
        raise InstalledProbeError("report_size_limit")
    path.parent.mkdir(parents=True, exist_ok=True)
    created = False
    try:
        with path.open("xb") as stream:
            created = True
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    except FileExistsError as exc:
        raise InstalledProbeError(f"output_exists:{path}") from exc
    except OSError as exc:
        if created:
            try:
                path.unlink()
            except OSError:
                pass
        raise InstalledProbeError(f"output_write_failed:{path}") from exc
    return hashlib.sha256(raw).hexdigest()


def run(
    installation: Path,
    output: Path,
    *,
    expected_manifest_sha256: str,
    expected_dll_sha256: str,
    expect_patch: str = "installed",
    development_root: Path | None = None,
) -> dict[str, Any]:
    output = output.resolve()
    if output.exists():
        raise InstalledProbeError(f"output_exists:{output}")
    expected_manifest = _sha256_pin(expected_manifest_sha256, "expected_manifest_sha256")
    expected_dll = _sha256_pin(expected_dll_sha256, "expected_dll_sha256")
    if expect_patch not in {"original", "installed"}:
        raise InstalledProbeError("expect_patch_invalid")
    report = _base_report(installation, output, expect_patch, expected_manifest, expected_dll)
    kernel = None
    handle = None
    reader = None
    try:
        installation = installation.resolve()
        build_dir = installation.parent
        artifact = _validate_artifact(
            build_dir,
            expected_manifest_sha256=expected_manifest,
            expected_dll_sha256=expected_dll,
        )
        report["artifact"] = {key: value for key, value in artifact.items() if key != "manifest_value"}
        report["template_capability"] = dict(artifact["template_capability"])
        if artifact["version"] in (28, 29, 30, 31, 32, 33):
            report["war_identity_capability"] = dict(
                artifact["war_identity_capability"]
            )
        if artifact["version"] in (29, 30, 31, 32, 33):
            report["native_text_capability"] = dict(
                artifact["native_text_capability"]
            )
        if artifact["version"] in (30, 31, 32, 33):
            report["native_title_query_capability"] = dict(
                artifact["native_title_query_capability"]
            )
        if artifact["version"] in (32, 33):
            report["battle_gate_trace_capability"] = dict(
                artifact["battle_gate_trace_capability"]
            )
        if artifact["version"] == 33:
            report["display_context_capability"] = dict(artifact["display_context_capability"])
        if artifact["version"] == 31:
            report["current_country_control_capability"] = dict(
                artifact["current_country_control_capability"]
            )
        manifest = artifact["manifest_value"]
        if artifact["version"] >= 26:
            report["registration_status"] = _native_registration_status(build_dir)
        root_source_dir = (development_root or ROOT / "work/native").resolve()
        report["development_root_delta"] = _development_root_delta(manifest, build_dir, root_source_dir)
        document, installation_pin, expected_exe = _load_installation(
            installation, expected_dll, manifest.get("experiment_id")
        )
        report["country_control_consumed_receipts"] = (
            classify_country_control_consumed_receipts(build_dir, document)
        )
        dll_path = Path(artifact["dll"]["path"])
        module_record = _validate_recorded_module(document, dll_path, expected_dll)
        report["installation"] = {
            "file": installation_pin,
            "experiment_id": document.get("experiment_id"),
            "recorded_pid": document.get("pid"),
            "recorded_creation_filetime": document.get("creation_filetime"),
            "recorded_session_id": document.get("session_id"),
            "recorded_module": module_record,
            "process_path": str(expected_exe),
        }
        pe = _coff_symbol(dll_path)
        report["stub"] = {
            "symbol": STUB_SYMBOL,
            "rva": pe.get("rva"),
            "source": "ordinary_pe_coff",
            "status": pe.get("status"),
            "file_sha256": pe.get("file_sha256"),
        }
        if pe.get("status") != "observed" or not isinstance(pe.get("rva"), str):
            raise InstalledProbeError("entry_stub_coff_symbol_unavailable")
        message_symbols = None
        if artifact["version"] >= 26:
            message_symbols = _message_entry_symbols(dll_path, version=artifact["version"])
            report["message_entry_symbols"] = message_symbols
            if message_symbols.get("status") != "observed":
                raise InstalledProbeError("message_entry_coff_symbol_guard_failed")
        report["fixed_file_code_guard"] = _file_code_guard(expected_exe)
        if report["fixed_file_code_guard"].get("status") != "observed":
            raise InstalledProbeError("on_disk_original_code_guard_failed")
        if artifact["version"] >= 26:
            report["message_entry_file_guard"] = _file_message_code_guard(
                expected_exe, version=artifact["version"]
            )
            if report["message_entry_file_guard"].get("status") != "observed":
                raise InstalledProbeError("on_disk_message_entry_guard_failed")

        kernel = _configure_kernel()
        handle = kernel.OpenProcess(PROCESS_ACCESS, False, int(document["pid"]))
        if not handle:
            raise InstalledProbeError("open_process_failed")
        report["process_opened"] = True
        report["runtime_accessed"] = True
        report["game_access"] = True
        report["remote_rpm"] = True
        report["access"]["remote_rpm"] = True
        identity_before = _capture_identity(kernel, handle, document, expected_exe, "before")
        report["identity"]["before"] = identity_before
        if identity_before.get("status") != "observed":
            raise InstalledProbeError("fresh_process_identity_before_failed")
        game_module_base = int(str(identity_before["module_base"]), 0)
        loaded_before = _query_module_records(kernel, handle, dll_path, expected_dll)
        report["loaded_dll"]["before"] = loaded_before
        if loaded_before.get("status") != "observed":
            raise InstalledProbeError("loaded_dll_before_failed")
        loaded_before_guard = _strict_loaded_module_guard(loaded_before, dll_path, expected_dll)
        report["loaded_dll"]["before_guard"] = loaded_before_guard
        dll_module_base = int(loaded_before["matching_modules"][0]["base"], 0)
        stub_rva = int(str(pe["rva"]), 0)
        stub_va = dll_module_base + stub_rva
        report["stub"].update({"dll_module_base": hex(dll_module_base), "runtime_va": hex(stub_va)})
        reader = V23RPM(kernel, handle, game_module_base)
        runtime_before = _runtime_code_guard(reader, game_module_base, "before", expect_patch, stub_va)
        report["runtime_code_guard"]["before"] = runtime_before
        message_guard_before = None
        if artifact["version"] >= 26 and message_symbols is not None:
            message_guard_before = _message_entry_runtime_guard(
                reader, game_module_base, dll_module_base, "before", expect_patch,
                {key: value for key, value in message_symbols["symbols"].items()
                 if key.endswith("_hook")},
                {key: value for key, value in message_symbols["symbols"].items()
                 if key.endswith("_original")},
                kernel=kernel, handle=handle,
                version=artifact["version"],
            )
            report["message_entry_guard"]["before"] = message_guard_before
            if artifact["version"] >= 27:
                report["formatter_container_entry_guard"]["before"] = message_guard_before
            if artifact["version"] >= 29:
                report["line1_entry_guard"]["before"] = {
                    "status": message_guard_before.get("status"),
                    "records": {
                        key: value for key, value in message_guard_before.get(
                            "records", {}
                        ).items() if key.startswith("line1_")
                    },
                    "trampolines": {
                        "line1": message_guard_before.get(
                            "trampolines", {}
                        ).get("line1")
                    },
                }
        before = _snapshot(reader, game_module_base, "before")
        report["before"] = before
        if (runtime_before.get("status") != "observed"
                or (message_guard_before is not None and message_guard_before.get("status") != "observed")
                or before.get("status") != "observed"):
            raise InstalledProbeError("before_runtime_guard_or_context_failed")

        identity_after = _capture_identity(kernel, handle, document, expected_exe, "after")
        report["identity"]["after"] = identity_after
        loaded_after = _query_module_records(kernel, handle, dll_path, expected_dll)
        report["loaded_dll"]["after"] = loaded_after
        loaded_after_guard = _strict_loaded_module_guard(loaded_after, dll_path, expected_dll)
        report["loaded_dll"]["after_guard"] = loaded_after_guard
        runtime_after = _runtime_code_guard(reader, game_module_base, "after", expect_patch, stub_va)
        report["runtime_code_guard"]["after"] = runtime_after
        message_guard_after = None
        if artifact["version"] >= 26 and message_symbols is not None:
            message_guard_after = _message_entry_runtime_guard(
                reader, game_module_base, dll_module_base, "after", expect_patch,
                {key: value for key, value in message_symbols["symbols"].items()
                 if key.endswith("_hook")},
                {key: value for key, value in message_symbols["symbols"].items()
                 if key.endswith("_original")},
                kernel=kernel, handle=handle,
                version=artifact["version"],
            )
            report["message_entry_guard"]["after"] = message_guard_after
            if artifact["version"] >= 27:
                report["formatter_container_entry_guard"]["after"] = message_guard_after
            if artifact["version"] >= 29:
                report["line1_entry_guard"]["after"] = {
                    "status": message_guard_after.get("status"),
                    "records": {
                        key: value for key, value in message_guard_after.get(
                            "records", {}
                        ).items() if key.startswith("line1_")
                    },
                    "trampolines": {
                        "line1": message_guard_after.get(
                            "trampolines", {}
                        ).get("line1")
                    },
                }
        after = _snapshot(reader, game_module_base, "after")
        report["after"] = after
        report["doublepass"]["performed"] = True
        identity_before_compare = {key: value for key, value in identity_before.items() if key != "phase"}
        identity_after_compare = {key: value for key, value in identity_after.items() if key != "phase"}
        comparisons = {
            "identity_pid_creation_session_exe": identity_before_compare == identity_after_compare,
            "loaded_dll_path_sha": loaded_before == loaded_after,
            "loaded_bridge_module_set": loaded_before_guard == loaded_after_guard,
            "runtime_entry_unwind_guard": runtime_before.get("records") == runtime_after.get("records"),
            "message_entry_unwind_guard": (
                message_guard_before is None
                or message_guard_after is not None
                and message_guard_before.get("records") == message_guard_after.get("records")
            ),
            "message_entry_guard_status": (
                message_guard_before is None
                or (message_guard_before.get("status") == "observed"
                    and message_guard_after is not None
                    and message_guard_after.get("status") == "observed")
            ),
            "snapshot_pause_speed_date_player": before == {**after, "phase": "before"},
            "after_identity_observed": identity_after.get("status") == "observed",
            "after_module_observed": loaded_after.get("status") == "observed",
            "after_runtime_observed": runtime_after.get("status") == "observed",
            "after_snapshot_observed": after.get("status") == "observed",
        }
        report["doublepass"]["checks"] = comparisons
        report["doublepass"]["consistent"] = all(comparisons.values())
        report["identity"]["binding_verified"] = all((
            identity_before.get("status") == "observed",
            identity_after.get("status") == "observed",
            identity_before.get("session_id") == identity_after.get("session_id") == document.get("session_id"),
            identity_before.get("pid") == identity_after.get("pid") == document.get("pid"),
            identity_before.get("process_creation_filetime") == identity_after.get("process_creation_filetime") == document.get("creation_filetime"),
        ))
        report["loaded_dll"]["same_path_sha"] = loaded_before == loaded_after
        if report["doublepass"]["consistent"] is not True or report["identity"]["binding_verified"] is not True:
            raise InstalledProbeError("after_or_doublepass_guard_failed")
        report["provenance"] = {
            "artifact": "manifest_and_DLL_external_pins_plus_source_copy_hashes",
            "development_root": "reported_separately_only",
            "ordinary_pe_coff": True,
            "rpm": {"status": "observed", "process_access": hex(PROCESS_ACCESS), "same_handle_before_after": True},
        }
        if artifact["version"] >= 26:
            report["template_capability"].update({
                "scope_entry_runtime_verified": True,
                "scope_entry_runtime_status": "observed_pure_rpm_guard",
                "scope_entry_runtime_expect_patch": expect_patch,
            })
            report["target_build"].update({
                "scope_entry_runtime_verified": True,
                "scope_entry_runtime_status": "observed_pure_rpm_guard",
            })
        if artifact["version"] in (29, 30, 31, 32, 33):
            report["native_text_capability"].update({
                "scope_entry_runtime_verified": True,
                "scope_entry_runtime_status": "observed_pure_rpm_guard",
                "scope_entry_runtime_expect_patch": expect_patch,
            })
        if artifact["version"] in (30, 31, 32, 33):
            report["native_title_query_capability"].update({
                "helper_invoked": False,
                "scope_entry_runtime_verified": False,
                "scope_entry_runtime_status": "not_called_helper_pure_rpm",
            })
        report["status"] = "passed_read_only_installed_preflight"
    except Exception as exc:
        report["status"] = "failed_read_only_installed_preflight"
        report["errors"].append({"stage": "preflight", "status": "unknown", "error": f"{type(exc).__name__}:{exc}"})
    finally:
        if reader is not None:
            report["access"].update({
                "rpm_bytes_requested": reader.bytes_requested,
                "rpm_calls": reader.calls,
                "read_log": list(reader.read_log),
            })
        close = _close_process_handle(kernel, handle)
        if not isinstance(close, dict):
            close = {"status": "unknown", "closed": False}
        close = dict(close)
        close["calls"] = 1 if close.get("status") == "closed" else 0
        report["cleanup"]["handle_close"] = close
        report["completed"] = True
        if report["status"] == "passed_read_only_installed_preflight" and close.get("status") != "closed":
            report["status"] = "failed_read_only_installed_preflight"
            report["errors"].append({"stage": "cleanup", "status": "unknown", "error": "process_handle_not_closed"})
        _write_new(output, report)
    return report


def _sha256_argument(value: str) -> str:
    try:
        return _sha256_pin(value, "expected_sha256")
    except InstalledProbeError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--installation", type=Path, required=True)
    parser.add_argument("--expected-manifest-sha256", type=_sha256_argument, required=True)
    parser.add_argument("--expected-dll-sha256", type=_sha256_argument, required=True)
    parser.add_argument("--expect-patch", choices=("original", "installed"), default="installed")
    parser.add_argument("--development-root", type=Path, default=ROOT / "work/native")
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "work/runtime/information-battle-context-live-20261025-001/installed-preflight-001/report.json",
    )
    args = parser.parse_args(argv)
    try:
        report = run(
            args.installation,
            args.output,
            expected_manifest_sha256=args.expected_manifest_sha256,
            expected_dll_sha256=args.expected_dll_sha256,
            expect_patch=args.expect_patch,
            development_root=args.development_root,
        )
    except Exception as exc:
        print(json.dumps({"status": "failed_to_write_report", "error": f"{type(exc).__name__}:{exc}"}, ensure_ascii=False), file=sys.stderr)
        return 2
    print(json.dumps({"status": report["status"], "output": str(args.output.resolve()), "errors": report["errors"]}, ensure_ascii=False))
    return 0 if report["status"] == "passed_read_only_installed_preflight" else 1


if __name__ == "__main__":
    raise SystemExit(main())
