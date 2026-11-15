"""Read-only startup-path probe for the audited EU4 1.37.4 process.

The probe binds the requested PID to the audited executable and process
creation identity, then performs a small, explicitly budgeted set of
ReadProcessMemory calls.  It never calls an EU4 function, writes target
memory, injects code, enumerates private heap regions, or controls the UI.

The startup path is the 32-byte Engine String32 at module RVA 0x1FD3A08.
Its QWORD length and capacity are at +0x10 and +0x18.  Inline storage is
decoded from the first 16 bytes; heap storage is followed only after bounded
length/capacity checks and for at most 512 bytes.
"""
from __future__ import annotations

import argparse
import ctypes as C
from ctypes import wintypes as W
import hashlib
import json
from pathlib import Path
import sys
from datetime import datetime, timezone


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from work.local_config import game_exe  # noqa: E402


EXPECTED_EXE_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
STARTUP_PATH_RVA = 0x1FD3A08
GAME_POINTER_RVA = 0x233FE58
GAME_DATE_OFFSET = 0x1DD0
GAME_PLAYER_OFFSET = 0x1E60
MAX_RPM_BYTES = 4096
MAX_STRING_LENGTH = 512
MAX_STRING_CAPACITY = 4096
MAX_USER_ADDRESS = 0x0000800000000000


class ProbeError(RuntimeError):
    pass


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def filetime_value(value: W.FILETIME) -> int:
    return (int(value.dwHighDateTime) << 32) | int(value.dwLowDateTime)


def filetime_iso(ticks: int) -> str | None:
    if not ticks:
        return None
    try:
        seconds = ticks / 10_000_000 - 11644473600
        return datetime.fromtimestamp(seconds, timezone.utc).isoformat()
    except (OverflowError, OSError, ValueError):
        return None


def printable_tag(handle: int) -> str | None:
    raw = (handle & 0xFFFFFF).to_bytes(3, "little")
    if all(0x20 <= byte <= 0x7E for byte in raw):
        return raw.decode("ascii")
    return None


def decode_text(raw: bytes) -> tuple[str | None, str | None]:
    try:
        return raw.decode("utf-8"), "utf-8"
    except UnicodeDecodeError:
        try:
            return raw.decode("cp1252"), "cp1252"
        except UnicodeDecodeError:
            return None, None


def parse_string32(header: bytes, read_memory) -> dict:
    """Decode only the bounded String32 forms supported by the probe."""
    if len(header) != 32:
        raise ProbeError("String32 header length is not 32 bytes")
    union_value = int.from_bytes(header[0:8], "little")
    length = int.from_bytes(header[0x10:0x18], "little")
    capacity = int.from_bytes(header[0x18:0x20], "little")
    result = {
        "header_hex": header.hex(),
        "union_value": hex(union_value),
        "length": length,
        "length_offset": hex(0x10),
        "capacity": capacity,
        "capacity_offset": hex(0x18),
        "storage": "unknown",
        "path": None,
        "path_nonempty": None,
        "encoding": None,
        "status": "unknown",
        "unknown_reason": None,
    }

    if length > MAX_STRING_LENGTH:
        result["unknown_reason"] = "length_exceeds_512_bound"
        return result
    if capacity < length:
        result["unknown_reason"] = "capacity_below_length"
        return result

    if capacity < 16:
        result["storage"] = "inline"
        if length > 15:
            result["unknown_reason"] = "inline_length_exceeds_15"
            return result
        payload = header[:16][:length]
        nul_ok = length < 16 and header[length] == 0
        result["nul_terminator_observed"] = nul_ok
        if not nul_ok:
            result["unknown_reason"] = "inline_nul_missing"
            return result
    else:
        result["storage"] = "heap"
        if capacity > MAX_STRING_CAPACITY:
            result["unknown_reason"] = "capacity_exceeds_4096_bound"
            return result
        if length == 0:
            result["payload_read_bytes"] = 0
            result["nul_terminator_observed"] = None
            result["path"] = ""
            result["path_nonempty"] = False
            result["status"] = "observed"
            return result
        if union_value < 0x10000 or union_value >= MAX_USER_ADDRESS or union_value % 8:
            result["unknown_reason"] = "heap_pointer_outside_bounded_user_memory"
            return result
        request_size = min(MAX_STRING_LENGTH, length + 1)
        payload = read_memory(union_value, request_size)
        result["heap_pointer"] = hex(union_value)
        result["payload_read_bytes"] = len(payload)
        nul_ok = length >= len(payload) or payload[length] == 0
        result["nul_terminator_observed"] = nul_ok if length < len(payload) else None
        if not nul_ok:
            result["unknown_reason"] = "heap_nul_missing"
            return result
        payload = payload[:length]

    text, encoding = decode_text(payload)
    if text is None:
        result["unknown_reason"] = "path_bytes_not_decodable"
        return result
    result["path"] = text
    result["path_nonempty"] = bool(text)
    result["encoding"] = encoding
    result["status"] = "observed"
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pid", required=True, type=int)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    sys.dont_write_bytecode = True
    args.output.parent.mkdir(parents=True, exist_ok=True)

    report: dict = {
        "probe": "information-startup-path",
        "probe_version": 1,
        "probe_script": str(Path(__file__).resolve()),
        "probe_script_sha256": None,
        "pid": args.pid,
        "read_only": True,
        "target_build": {
            "version": "1.37.4",
            "expected_exe_sha256": EXPECTED_EXE_SHA256,
            "startup_path_rva": hex(STARTUP_PATH_RVA),
            "game_pointer_rva": hex(GAME_POINTER_RVA),
        },
        "access": {
            "open_process_mask": "QUERY_INFORMATION|VM_READ",
            "open_process_mask_hex": hex(0x0400 | 0x0010),
            "rpm_byte_budget": MAX_RPM_BYTES,
            "rpm_bytes_requested": 0,
            "native_game_calls": False,
            "target_memory_writes": False,
            "dll_injection": False,
            "private_heap_scan": False,
            "ui_control": False,
        },
        "identity": {
            "configured_path": None,
            "configured_path_sha256": None,
            "process_path": None,
            "process_path_matches_configured": None,
            "process_path_sha256": None,
            "process_hash_matches_expected": None,
            "binding_verified": False,
            "process_times": None,
        },
        "module_base": None,
        "startup_path": None,
        "game_state": {
            "status": "unknown",
            "game_pointer": None,
            "current_raw_date": None,
            "player_handle": None,
            "player_tag": None,
            "player_slot": None,
        },
        "map_loaded_claim": {
            "status": "unknown",
            "reason": "Player/date fields are diagnostic only; this probe does not establish map loading.",
        },
        "status": "starting",
        "errors": [],
    }
    try:
        report["probe_script_sha256"] = sha256_file(Path(__file__).resolve())
    except OSError as error:
        report["errors"].append({"stage": "probe_identity", "status": "unknown", "error": str(error)})

    handle = None
    try:
        if sys.platform != "win32" or C.sizeof(C.c_void_p) != 8:
            raise ProbeError("Requires 64-bit Windows Python")
        configured = game_exe().resolve()
        report["identity"]["configured_path"] = str(configured)
        configured_hash = sha256_file(configured)
        report["identity"]["configured_path_sha256"] = configured_hash
        if configured_hash.lower() != EXPECTED_EXE_SHA256:
            raise ProbeError("Configured executable SHA-256 differs from the audited 1.37.4 image")

        kernel = C.WinDLL("kernel32", use_last_error=True)
        kernel.OpenProcess.argtypes = [W.DWORD, W.BOOL, W.DWORD]
        kernel.OpenProcess.restype = W.HANDLE
        kernel.CloseHandle.argtypes = [W.HANDLE]
        kernel.CloseHandle.restype = W.BOOL
        kernel.QueryFullProcessImageNameW.argtypes = [W.HANDLE, W.DWORD, W.LPWSTR, C.POINTER(W.DWORD)]
        kernel.QueryFullProcessImageNameW.restype = W.BOOL
        kernel.GetProcessTimes.argtypes = [W.HANDLE, C.POINTER(W.FILETIME), C.POINTER(W.FILETIME), C.POINTER(W.FILETIME), C.POINTER(W.FILETIME)]
        kernel.GetProcessTimes.restype = W.BOOL
        kernel.K32EnumProcessModulesEx.argtypes = [W.HANDLE, C.POINTER(W.HMODULE), W.DWORD, C.POINTER(W.DWORD), W.DWORD]
        kernel.K32EnumProcessModulesEx.restype = W.BOOL
        kernel.ReadProcessMemory.argtypes = [W.HANDLE, C.c_void_p, C.c_void_p, C.c_size_t, C.POINTER(C.c_size_t)]
        kernel.ReadProcessMemory.restype = W.BOOL

        handle = kernel.OpenProcess(0x0400 | 0x0010, False, args.pid)
        if not handle:
            raise C.WinError(C.get_last_error())

        process_path_buffer = C.create_unicode_buffer(32768)
        process_path_length = W.DWORD(len(process_path_buffer))
        if not kernel.QueryFullProcessImageNameW(handle, 0, process_path_buffer, C.byref(process_path_length)):
            raise C.WinError(C.get_last_error())
        process_path = Path(process_path_buffer.value).resolve()
        report["identity"]["process_path"] = str(process_path)
        report["identity"]["process_path_matches_configured"] = process_path == configured
        process_hash = sha256_file(process_path)
        report["identity"]["process_path_sha256"] = process_hash
        report["identity"]["process_hash_matches_expected"] = process_hash.lower() == EXPECTED_EXE_SHA256

        creation = W.FILETIME()
        exit_time = W.FILETIME()
        kernel_time = W.FILETIME()
        user_time = W.FILETIME()
        if not kernel.GetProcessTimes(handle, C.byref(creation), C.byref(exit_time), C.byref(kernel_time), C.byref(user_time)):
            report["identity"]["process_times"] = {"status": "unknown", "error": str(C.WinError(C.get_last_error()))}
        else:
            report["identity"]["process_times"] = {
                "status": "observed",
                "creation_filetime": filetime_value(creation),
                "creation_utc": filetime_iso(filetime_value(creation)),
                "exit_filetime": filetime_value(exit_time),
                "kernel_time_100ns": filetime_value(kernel_time),
                "user_time_100ns": filetime_value(user_time),
            }

        identity_ok = (
            report["identity"]["process_path_matches_configured"] is True
            and report["identity"]["process_hash_matches_expected"] is True
        )
        report["identity"]["binding_verified"] = identity_ok
        if not identity_ok:
            report["status"] = "identity_mismatch"
            report["errors"].append({"stage": "identity", "status": "unknown", "error": "Process path/hash binding did not match the audited image"})
        else:
            modules = (W.HMODULE * 1024)()
            needed = W.DWORD()
            if not kernel.K32EnumProcessModulesEx(handle, modules, C.sizeof(modules), C.byref(needed), 3):
                raise C.WinError(C.get_last_error())
            if not needed.value or needed.value > C.sizeof(modules) or needed.value % C.sizeof(W.HMODULE):
                raise ProbeError("Invalid or oversized module list")
            module_base = int(modules[0])
            if module_base < 0x10000:
                raise ProbeError("Invalid module base")
            report["module_base"] = hex(module_base)

            def read_memory(address: int, size: int) -> bytes:
                if address < 0x10000 or address >= MAX_USER_ADDRESS or size <= 0 or size > MAX_RPM_BYTES:
                    raise ProbeError("Invalid bounded RPM range")
                if report["access"]["rpm_bytes_requested"] + size > MAX_RPM_BYTES:
                    raise ProbeError("RPM byte budget exceeded")
                report["access"]["rpm_bytes_requested"] += size
                buffer = C.create_string_buffer(size)
                actual = C.c_size_t()
                if not kernel.ReadProcessMemory(handle, C.c_void_p(address), buffer, size, C.byref(actual)):
                    raise C.WinError(C.get_last_error())
                if actual.value != size:
                    raise ProbeError(f"ReadProcessMemory returned {actual.value} of {size} bytes")
                return buffer.raw

            startup_address = module_base + STARTUP_PATH_RVA
            try:
                startup_header = read_memory(startup_address, 32)
                report["startup_path"] = parse_string32(startup_header, read_memory)
                report["startup_path"]["address"] = hex(startup_address)
            except Exception as error:
                report["startup_path"] = {
                    "status": "unknown",
                    "address": hex(startup_address),
                    "unknown_reason": f"read_failed: {error}",
                }
                report["errors"].append({"stage": "startup_path", "status": "unknown", "error": str(error)})

            game_info = report["game_state"]
            try:
                game_pointer = int.from_bytes(read_memory(module_base + GAME_POINTER_RVA, 8), "little")
                if game_pointer < 0x10000 or game_pointer >= MAX_USER_ADDRESS or game_pointer % 8:
                    game_info["status"] = "unknown"
                    game_info["game_pointer"] = hex(game_pointer)
                    game_info["reason"] = "game_pointer_invalid"
                else:
                    game_info["game_pointer"] = hex(game_pointer)
                    try:
                        raw_date = int.from_bytes(read_memory(game_pointer + GAME_DATE_OFFSET, 4), "little", signed=True)
                        game_info["current_raw_date"] = raw_date
                    except Exception as error:
                        game_info["current_raw_date_status"] = "unknown"
                        game_info["current_raw_date_error"] = str(error)
                        report["errors"].append({"stage": "game_date", "status": "unknown", "error": str(error)})
                    try:
                        player_handle = int.from_bytes(read_memory(game_pointer + GAME_PLAYER_OFFSET, 8), "little")
                        game_info["player_handle"] = hex(player_handle)
                        game_info["player_slot"] = (player_handle >> 32) & 0xFFFF
                        game_info["player_tag"] = printable_tag(player_handle)
                    except Exception as error:
                        game_info["player_handle_status"] = "unknown"
                        game_info["player_handle_error"] = str(error)
                        report["errors"].append({"stage": "player_handle", "status": "unknown", "error": str(error)})
                    game_info["status"] = "observed"
            except Exception as error:
                game_info["status"] = "unknown"
                game_info["game_pointer_error"] = str(error)
                report["errors"].append({"stage": "game_pointer", "status": "unknown", "error": str(error)})

            if report["status"] == "starting":
                report["status"] = "observed"
    except Exception as error:
        report["status"] = "error"
        report["errors"].append({"stage": "probe", "status": "unknown", "error": str(error)})
    finally:
        if handle:
            kernel.CloseHandle(handle)

    report["completed"] = report["status"] in {"observed", "identity_mismatch"}
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report["status"] == "observed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
