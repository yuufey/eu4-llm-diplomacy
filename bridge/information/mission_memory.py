"""Bounded read-only runtime reader for the 1.37.4 country mission tree.

The production reader is bound to the small, hashed profile shipped beside
this module.  It opens one operator-owned process with
``QUERY_INFORMATION | VM_READ`` only, verifies the executable and the
profile's code guards, and follows the narrow mission contracts.  It never
calls an EU4 function, writes target memory, injects code, walks an arbitrary
heap, or advances/saves the game.

The public ``capture(installation, country)`` function returns a JSON-ready
observation and does not write files.  The CLI is the only code that writes
``--output``.  A running object's vtable RVA and the vtable +8/+0x10 targets
are checked against the audited thunk/writer chain before any slot is read; a
mismatch is retained as a raw contract observation and stops that pass without
trying another offset.  Static facts in the profile are ordinary file
analysis; the returned mission data remains a bounded runtime observation.
"""
from __future__ import annotations

import argparse
import ctypes as C
from ctypes import wintypes as W
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any, Mapping

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    __package__ = "bridge.information"

from . import country_reference_memory as _countries
from . import observation_time as _time


PROFILE_FILE = Path(__file__).resolve().parent / "profiles" / "mission-memory-1374.json"
PROFILE_MAX_BYTES = 64 * 1024
EXPECTED_PROFILE_SHA256 = "b506e2a006a9d88504d5c2bad4ceec3a3b837c9a34b1d68145edfeddaf831037"


class ProfileError(RuntimeError):
    """The shipped production profile is absent, oversized, or tampered."""


def _load_profile(path: Path = PROFILE_FILE, expected_sha256: str = EXPECTED_PROFILE_SHA256) -> dict[str, Any]:
    """Load a profile only after its bounded size and exact SHA-256 check."""
    try:
        size = path.stat().st_size
        if size <= 0 or size > PROFILE_MAX_BYTES:
            raise ProfileError(f"profile_size_out_of_bound:{size}")
        raw = path.read_bytes()
    except (OSError, UnicodeError) as exc:
        raise ProfileError(f"profile_read_failed:{exc}") from exc
    if len(raw) != size or len(raw) > PROFILE_MAX_BYTES:
        raise ProfileError("profile_read_size_changed")
    actual = hashlib.sha256(raw).hexdigest()
    if actual.lower() != expected_sha256.lower():
        raise ProfileError("profile_sha256_mismatch")
    try:
        profile = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ProfileError(f"profile_json_invalid:{exc}") from exc
    if not isinstance(profile, dict) or profile.get("profile_id") != "mission-memory-1374":
        raise ProfileError("profile_shape_invalid")
    return profile


PROFILE = _load_profile()


def _profile_int(value: Any, label: str) -> int:
    if isinstance(value, bool):
        parsed = None
    elif isinstance(value, int):
        parsed = value
    elif isinstance(value, str):
        try:
            parsed = int(value, 0)
        except ValueError:
            parsed = None
    else:
        parsed = None
    if parsed is None or parsed < 0:
        raise ProfileError(f"profile_integer_invalid:{label}")
    return parsed


EXPECTED_EXE_SHA256 = str(PROFILE["executable"]["sha256"]).lower()
EXPECTED_VERSION = str(PROFILE["game_version"])
EXPECTED_COUNTRY = "FRA"

# These are the only module-relative globals used by this reader.  They are
# copied from the fixed profile, never from work/runtime reports.
DATABASE_RVA = _profile_int(PROFILE["globals"]["database_rva"], "database_rva")
GAME_RVA = _profile_int(PROFILE["globals"]["game_rva"], "game_rva")
EXPECTED_MISSION_VTABLE_RVA = _profile_int(PROFILE["mission_chain"]["vtable_rva"], "vtable_rva")
EXPECTED_MISSION_THUNK_RVA = _profile_int(PROFILE["mission_chain"]["vtable_plus_8_rva"], "vtable_plus_8_rva")
EXPECTED_MISSION_WRITER_RVA = _profile_int(PROFILE["mission_chain"]["vtable_plus_10_rva"], "vtable_plus_10_rva")

GAME_DATE_OFFSET = _profile_int(PROFILE["globals"]["game_date_offset"], "game_date_offset")
COUNTRY_TABLE_OFFSET = _profile_int(PROFILE["country"]["table_offset"], "country.table_offset")
COUNTRY_MISSIONS_OFFSET = _profile_int(PROFILE["country"]["missions_offset"], "country.missions_offset")
COUNTRY_COMPLETED_OFFSET = _profile_int(PROFILE["country"]["completed_offset"], "country.completed_offset")
COUNTRY_HANDLE_OFFSET = _profile_int(PROFILE["country"]["handle_offset"], "country.handle_offset")

SLOT_ARRAY_OFFSET = _profile_int(PROFILE["mission_chain"]["slots"]["array_offset"], "slots.array_offset")
SLOT_COUNT_OFFSET = _profile_int(PROFILE["mission_chain"]["slots"]["count_offset"], "slots.count_offset")
SLOT_STRIDE = _profile_int(PROFILE["mission_chain"]["slots"]["stride"], "slots.stride")
ROOT_ARRAY_OFFSET = _profile_int(PROFILE["mission_chain"]["slots"]["root_array_offset"], "slots.root_array_offset")
ROOT_COUNT_OFFSET = _profile_int(PROFILE["mission_chain"]["slots"]["root_count_offset"], "slots.root_count_offset")
DEFINITION_NAME_OFFSET = _profile_int(PROFILE["mission_chain"]["slots"]["definition_name_offset"], "slots.definition_name_offset")
STRING_LENGTH_OFFSET = _profile_int(PROFILE["string32"]["length_offset"], "string32.length_offset")
STRING_CAPACITY_OFFSET = _profile_int(PROFILE["string32"]["capacity_offset"], "string32.capacity_offset")

# Runtime limits are intentionally smaller than the game could support.
PROCESS_ACCESS = 0x0400 | 0x0010  # PROCESS_QUERY_INFORMATION | PROCESS_VM_READ
MAX_TOTAL_RPM = _profile_int(PROFILE["limits"]["max_total_rpm"], "limits.max_total_rpm")
MAX_SINGLE_RPM = _profile_int(PROFILE["limits"]["max_single_rpm"], "limits.max_single_rpm")
MAX_USER_ADDRESS = 0x0000800000000000
MAX_MISSION_SLOTS = _profile_int(PROFILE["limits"]["max_mission_slots"], "limits.max_mission_slots")
MAX_ROOTS_PER_SLOT = _profile_int(PROFILE["limits"]["max_roots_per_slot"], "limits.max_roots_per_slot")
MAX_ASCII_ROOT_LENGTH = _profile_int(PROFILE["string32"]["max_ascii_length"], "string32.max_ascii_length")
MAX_STRING_CAPACITY = _profile_int(PROFILE["string32"]["max_capacity"], "string32.max_capacity")
MAX_COMPLETED_NODES = _profile_int(PROFILE["limits"]["max_completed_nodes"], "limits.max_completed_nodes")


class ProbeError(RuntimeError):
    """A bounded read or contract check failed without a safe fallback."""


def _hex(value: int | None) -> str | None:
    return hex(value) if isinstance(value, int) else None


def _parse_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError:
            return None
    return None


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _filetime_value(value: W.FILETIME) -> int:
    return (int(value.dwHighDateTime) << 32) | int(value.dwLowDateTime)


def _filetime_iso(value: int) -> str | None:
    if not value:
        return None
    try:
        return datetime.fromtimestamp(value / 10_000_000 - 11644473600, timezone.utc).isoformat()
    except (OverflowError, OSError, ValueError):
        return None


def _valid_pointer(value: int) -> bool:
    return isinstance(value, int) and 0x10000 <= value < MAX_USER_ADDRESS and value % 8 == 0


def _address(value: int | None, module_base: int | None = None, *, known_rva: int | None = None) -> dict[str, Any]:
    """Represent a VA without claiming that heap addresses are module RVAs."""
    result: dict[str, Any] = {"va": _hex(value), "rva": None, "rva_identity": "not_applicable"}
    if not isinstance(value, int):
        return result
    if known_rva is not None:
        result["rva"] = _hex(known_rva)
        result["rva_identity"] = "contract_module_rva"
    elif module_base is not None and module_base <= value < module_base + 0x40000000:
        # This is an address-relative identity only.  It is not a claim that
        # an arbitrary runtime pointer belongs to an executable section.
        result["rva"] = _hex(value - module_base)
        result["rva_identity"] = "module_relative_candidate"
    else:
        result["rva_identity"] = "runtime_va_or_heap"
    return result


def _load_installation(path: Path) -> dict[str, Any]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ProbeError(f"installation_read_failed: {exc}") from exc
    if not isinstance(document, dict):
        raise ProbeError("installation_not_object")
    pid = _parse_int(document.get("pid"))
    creation = _parse_int(document.get("creation_filetime"))
    if pid is None or pid <= 0 or creation is None or creation <= 0:
        raise ProbeError("installation_pid_or_creation_invalid")
    if str(document.get("game_sha256", "")).lower() != EXPECTED_EXE_SHA256:
        raise ProbeError("installation_game_sha256_mismatch")
    return document


def _base_report(
    installation: Path,
    country: str,
    include_completed: bool,
    include_tasks: bool = False,
) -> dict[str, Any]:
    return {
        "probe": "information-missions-runtime",
        "probe_version": 1,
        "probe_script": str(Path(__file__).resolve()),
        "probe_script_sha256": None,
        "profile": {
            "path": str(PROFILE_FILE),
            "sha256": EXPECTED_PROFILE_SHA256,
            "max_bytes": PROFILE_MAX_BYTES,
        },
        "read_only": True,
        "evidence_kind": "pure_runtime_observation_not_static_evidence",
        "target_build": {
            "version": EXPECTED_VERSION,
            "expected_exe_sha256": EXPECTED_EXE_SHA256,
            "database_rva": _hex(DATABASE_RVA),
            "game_rva": _hex(GAME_RVA),
            "expected_mission_vtable_rva": _hex(EXPECTED_MISSION_VTABLE_RVA),
            "expected_mission_thunk_rva": _hex(EXPECTED_MISSION_THUNK_RVA),
            "expected_mission_body_rva": _hex(EXPECTED_MISSION_WRITER_RVA),
        },
        "static_contract_reference": {
            "evidence_kind": PROFILE.get("source_evidence_kind"),
            "profile_id": PROFILE.get("profile_id"),
            "profile_sha256": EXPECTED_PROFILE_SHA256,
            "source_evidence_sha256": dict(PROFILE.get("source_evidence", {})),
            "used_as_runtime_contract": True,
            "static_results_are_not_runtime_observation": True,
        },
        "static_contract_guard": None,
        "file_code_guard": None,
        "runtime_code_guard": None,
        "task_static_contract_guard": None,
        "task_file_code_guard": None,
        "task_runtime_code_guard": None,
        "request": {
            "installation": str(installation),
            "country": country,
            "include_completed": include_completed,
            "include_tasks": include_tasks,
        },
        "access": {
            "open_process_mask": "QUERY_INFORMATION|VM_READ",
            "open_process_mask_hex": _hex(PROCESS_ACCESS),
            "rpm_total_limit": MAX_TOTAL_RPM,
            "rpm_single_read_limit": MAX_SINGLE_RPM,
            "rpm_bytes_requested": 0,
            "rpm_calls": 0,
            "slots_limit": MAX_MISSION_SLOTS,
            "roots_per_slot_limit": MAX_ROOTS_PER_SLOT,
            "completed_nodes_limit": MAX_COMPLETED_NODES,
            "ascii_root_length_limit": MAX_ASCII_ROOT_LENGTH,
            "native_game_calls": False,
            "target_memory_writes": False,
            "dll_injection": False,
            "private_heap_scan": False,
            "ui_control": False,
            "date_advance": False,
            "save_or_reload": False,
        },
        "identity": {
            "installation_path": str(installation),
            "installation_pid": None,
            "installation_creation_filetime": None,
            "installation_session_id": None,
            "process_path": None,
            "process_path_sha256": None,
            "process_path_sha256_matches_expected": None,
            "process_creation_filetime": None,
            "process_creation_utc": None,
            "process_creation_matches_installation": None,
            "module_path": None,
            "module_path_matches_process": None,
            "binding_verified": False,
        },
        "module_base": None,
        "before": None,
        "after": None,
        "doublepass": {
            "performed": False,
            "consistent": None,
            "mismatches": [],
            "task_consistent": None,
            "task_mismatches": [],
        },
        "cleanup": {
            "handle_close": {
                "status": "unknown",
                "success": None,
                "closed": False,
            },
        },
        "status": "starting",
        "errors": [],
        "completed": False,
    }


def _static_contract_guard() -> dict[str, Any]:
    """Verify the bounded ordinary-static facts frozen in the profile."""
    result: dict[str, Any] = {
        "status": "unknown",
        "evidence_kind": "ordinary_file_analysis_not_REA_Evidence",
        "profile": str(PROFILE_FILE),
        "profile_sha256": None,
        "source_evidence_sha256": None,
        "checks": {},
        "unknown_conditions": [],
    }
    try:
        profile = _load_profile()
        result["profile_sha256"] = EXPECTED_PROFILE_SHA256
        result["source_evidence_sha256"] = dict(profile.get("source_evidence", {}))
        chain = profile["mission_chain"]
        slots = chain["slots"]
        completed = profile["completed"]
        helpers = completed["helpers"]
        result["checks"].update({
            "profile_sha256": True,
            "game_sha256": profile["executable"]["sha256"].lower() == EXPECTED_EXE_SHA256,
            "evidence_kind": profile.get("source_evidence_kind") == "ordinary_file_analysis_not_REA_Evidence",
            "country_missions_embedded_lea": profile["country"]["embedded_mission_lea"] == {
                "rva": "0x2e10fe", "bytes": "4d8d87d8990000", "operands": "r8,[r15+0x99d8]",
            },
            "country_missions_wrapper": chain["wrapper_dispatch_guard"] == {
                "rva": "0x1707948", "bytes": "48ff6008", "operands": "jmp QWORD PTR [rax+0x8]",
            },
            "mission_vtable_chain": (
                chain["vtable_rva"] == "0x1c573c8"
                and chain["vtable_plus_8_rva"] == "0xd2f280"
                and chain["vtable_plus_10_rva"] == "0x445570"
            ),
            "slot_array_plus_18": slots["array_offset"] == "0x18",
            "slot_count_plus_24": slots["count_offset"] == "0x24",
            "slot_stride_24": slots["stride"] == 24,
            "root_array_plus_8": slots["root_array_offset"] == "0x8",
            "root_count_plus_14": slots["root_count_offset"] == "0x14",
            "definition_name_plus_10": slots["definition_name_offset"] == "0x10",
            "completed_embedded_container": (
                completed["container_storage"] == "embedded_object"
                and completed["container_offset"] == "0x9998"
                and completed["sentinel_offset"] == "0x8"
            ),
            "completed_begin_helper": helpers["begin"] == {
                "rva": "0x10c5b0", "bytes": "488b4108488b08", "operands": "sentinel=[container+8]; begin=[sentinel+0]",
            },
            "completed_end_helper": helpers["end"] == {
                "rva": "0xc3050", "bytes": "488b4108488902", "operands": "end=[container+8]",
            },
            "completed_next_helper": helpers["next"] == {
                "rva": "0x416630", "bytes": "488b01488902", "operands": "next=[node+0]",
            },
            "completed_definition_helper": helpers["definition"] == {
                "rva": "0x9a920", "bytes": "488d4110", "operands": "definition_string=[definition+0x10]",
            },
        })
        result["raw_profile_contract"] = {
            "embedded_mission_lea": profile["country"]["embedded_mission_lea"],
            "wrapper_dispatch_guard": chain["wrapper_dispatch_guard"],
            "thunk_guards": chain["thunk_guards"],
            "completed_helpers": helpers,
        }
        failed = [key for key, value in result["checks"].items() if value is not True]
        if failed:
            result["unknown_conditions"].append("profile_contract_check_failed:" + ",".join(failed))
        else:
            result["status"] = "observed"
    except (ProfileError, KeyError, TypeError, AttributeError) as exc:
        result["unknown_conditions"].append(f"profile_contract_read_failed:{exc}")
    return result


def _configure_kernel() -> Any:
    if sys.platform != "win32" or C.sizeof(C.c_void_p) != 8:
        raise ProbeError("WINDOWS_X64_SESSION_REQUIRED")
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
    get_module_name = getattr(kernel, "K32GetModuleFileNameExW", None)
    if get_module_name is None:
        get_module_name = C.WinDLL("psapi", use_last_error=True).GetModuleFileNameExW
    get_module_name.argtypes = [W.HANDLE, W.HMODULE, W.LPWSTR, W.DWORD]
    get_module_name.restype = W.DWORD
    kernel._probe_get_module_name = get_module_name
    kernel.ReadProcessMemory.argtypes = [W.HANDLE, C.c_void_p, C.c_void_p, C.c_size_t, C.POINTER(C.c_size_t)]
    kernel.ReadProcessMemory.restype = W.BOOL
    return kernel


class BoundedRPM:
    """ReadProcessMemory wrapper with a hard, shared byte budget."""

    def __init__(self, kernel: Any, handle: Any, module_base: int):
        self.kernel = kernel
        self.handle = handle
        self.module_base = module_base
        self.bytes_requested = 0
        self.calls = 0

    def _read(self, address: int, size: int, label: str, *, aligned: bool) -> bytes:
        valid_address = _valid_pointer(address) if aligned else (
            isinstance(address, int) and 0x10000 <= address < MAX_USER_ADDRESS
        )
        if not valid_address or not isinstance(size, int) or size <= 0 or size > MAX_SINGLE_RPM:
            raise ProbeError(f"invalid_bounded_read:{label}")
        if self.bytes_requested + size > MAX_TOTAL_RPM:
            raise ProbeError("RPM_TOTAL_BUDGET_EXCEEDED")
        # Count requested bytes even when Windows rejects the read.
        self.bytes_requested += size
        self.calls += 1
        buffer = C.create_string_buffer(size)
        actual = C.c_size_t()
        if not self.kernel.ReadProcessMemory(
            self.handle, C.c_void_p(address), buffer, size, C.byref(actual)
        ):
            raise C.WinError(C.get_last_error())
        if actual.value != size:
            raise ProbeError(f"short_read:{label}:{actual.value}/{size}")
        return buffer.raw

    def read(self, address: int, size: int, label: str) -> bytes:
        return self._read(address, size, label, aligned=True)

    def read_code(self, address: int, size: int, label: str) -> bytes:
        """Read a small executable slice; instruction RVAs need not align."""
        return self._read(address, size, label, aligned=False)

    def qword(self, address: int, label: str) -> tuple[int, bytes]:
        raw = self.read(address, 8, label)
        return int.from_bytes(raw, "little"), raw


def _profile_code_guards(profile: Mapping[str, Any] | None = None) -> list[tuple[str, int, bytes]]:
    """Return the exact bounded code guards frozen in the profile."""
    profile = PROFILE if profile is None else profile
    country = profile["country"]
    chain = profile["mission_chain"]
    completed = profile["completed"]
    guards: list[tuple[str, int, bytes]] = []

    def add(name: str, item: Mapping[str, Any]) -> None:
        raw_hex = item.get("bytes")
        if not isinstance(raw_hex, str) or len(raw_hex) % 2:
            raise ProfileError(f"profile_code_guard_hex_invalid:{name}")
        try:
            raw = bytes.fromhex(raw_hex)
        except ValueError as exc:
            raise ProfileError(f"profile_code_guard_hex_invalid:{name}") from exc
        guards.append((name, _profile_int(item.get("rva"), f"code_guard.{name}.rva"), raw))

    add("country_missions_embedded_lea", country["embedded_mission_lea"])
    add("country_missions_wrapper_dispatch", chain["wrapper_dispatch_guard"])
    for index, item in enumerate(chain["thunk_guards"]):
        add(f"writer_thunk_{index}", item)
    for name in ("begin", "end", "next", "definition"):
        add(f"completed_{name}_helper", completed["helpers"][name])
    return guards


def _read_pe_rva_bytes(path: Path, rva: int, size: int) -> bytes:
    """Read a small PE section slice without loading the executable."""
    if not isinstance(rva, int) or rva < 0 or not isinstance(size, int) or size <= 0 or size > MAX_SINGLE_RPM:
        raise ProbeError("file_code_guard_range_invalid")
    try:
        file_size = path.stat().st_size
        with path.open("rb") as stream:
            dos = stream.read(64)
            if len(dos) != 64 or dos[:2] != b"MZ":
                raise ProbeError("file_not_pe_dos")
            pe_offset = int.from_bytes(dos[0x3C:0x40], "little")
            if pe_offset < 64 or pe_offset + 24 > 64 * 1024:
                raise ProbeError("pe_header_out_of_bound")
            stream.seek(pe_offset)
            coff = stream.read(24)
            if len(coff) != 24 or coff[:4] != b"PE\x00\x00":
                raise ProbeError("file_not_pe_signature")
            section_count = int.from_bytes(coff[6:8], "little")
            optional_size = int.from_bytes(coff[20:22], "little")
            if section_count <= 0 or section_count > 96:
                raise ProbeError("pe_section_count_out_of_bound")
            section_table = pe_offset + 24 + optional_size
            section_table_end = section_table + section_count * 40
            if section_table_end > 64 * 1024:
                raise ProbeError("pe_section_table_out_of_bound")
            stream.seek(section_table)
            sections = stream.read(section_count * 40)
            if len(sections) != section_count * 40:
                raise ProbeError("pe_section_table_short")
            match: tuple[int, int, int] | None = None
            for index in range(section_count):
                header = sections[index * 40:(index + 1) * 40]
                virtual_size = int.from_bytes(header[8:12], "little")
                virtual_address = int.from_bytes(header[12:16], "little")
                raw_size = int.from_bytes(header[16:20], "little")
                raw_pointer = int.from_bytes(header[20:24], "little")
                if raw_size <= 0 or rva < virtual_address or rva + size > virtual_address + raw_size:
                    continue
                offset = raw_pointer + (rva - virtual_address)
                if offset < 0 or offset + size > file_size:
                    raise ProbeError("pe_section_slice_out_of_file")
                match = (offset, raw_pointer, raw_size)
                break
            if match is None:
                raise ProbeError(f"pe_rva_not_in_raw_section:{hex(rva)}")
            stream.seek(match[0])
            raw = stream.read(size)
            if len(raw) != size:
                raise ProbeError("pe_section_slice_short")
            return raw
    except OSError as exc:
        raise ProbeError(f"file_code_guard_read_failed:{exc}") from exc


def _file_code_guard(path: Path) -> dict[str, Any]:
    """Compare profile code bytes with the bound executable on disk."""
    result: dict[str, Any] = {
        "status": "unknown",
        "path": str(path),
        "checks": {},
        "records": {},
        "unknown_conditions": [],
    }
    try:
        for name, rva, expected in _profile_code_guards():
            actual = _read_pe_rva_bytes(path, rva, len(expected))
            result["records"][name] = {
                "rva": _hex(rva),
                "expected_hex": expected.hex(),
                "actual_hex": actual.hex(),
            }
            result["checks"][name] = actual == expected
        failed = [name for name, value in result["checks"].items() if value is not True]
        if failed:
            result["status"] = "mismatch"
            result["unknown_conditions"].append("file_code_guard_mismatch:" + ",".join(failed))
        else:
            result["status"] = "observed"
    except (ProbeError, ProfileError, KeyError, TypeError, ValueError) as exc:
        result["unknown_conditions"].append(str(exc))
    return result


def _runtime_code_guard(reader: BoundedRPM, module_base: int) -> dict[str, Any]:
    """Compare profile code bytes with bounded ReadProcessMemory slices."""
    result: dict[str, Any] = {
        "status": "unknown",
        "module_base": _address(module_base),
        "checks": {},
        "records": {},
        "unknown_conditions": [],
    }
    try:
        for name, rva, expected in _profile_code_guards():
            address = module_base + rva
            actual = reader.read_code(address, len(expected), f"code_guard.{name}")
            result["records"][name] = {
                "address": _address(address, module_base, known_rva=rva),
                "expected_hex": expected.hex(),
                "actual_hex": actual.hex(),
            }
            result["checks"][name] = actual == expected
        failed = [name for name, value in result["checks"].items() if value is not True]
        if failed:
            result["status"] = "mismatch"
            result["unknown_conditions"].append("runtime_code_guard_mismatch:" + ",".join(failed))
        else:
            result["status"] = "observed"
    except (ProbeError, ProfileError, KeyError, TypeError, ValueError, OSError) as exc:
        result["unknown_conditions"].append(str(exc))
    return result


def _field_address(reader: BoundedRPM, address: int, raw: bytes, value: int, *, offset: int | None = None, known_rva: int | None = None) -> dict[str, Any]:
    result = {
        "address": _address(address, reader.module_base, known_rva=known_rva),
        "raw_hex": raw.hex(),
        "value": _hex(value),
        "value_address": _address(value, reader.module_base),
    }
    if offset is not None:
        result["field_offset"] = _hex(offset)
    return result


def _unknown_string(address: int, reader: BoundedRPM, header: bytes | None, reason: str) -> dict[str, Any]:
    return {
        "status": "unknown",
        "complete": False,
        "address": _address(address, reader.module_base),
        "header_hex": header.hex() if isinstance(header, bytes) else None,
        "payload_hex": None,
        "text": None,
        "unknown_reason": reason,
    }


def _decode_string32(reader: BoundedRPM, header_address: int, header: bytes, label: str) -> dict[str, Any]:
    if len(header) != 32:
        return _unknown_string(header_address, reader, header, "string32_header_size")
    length = int.from_bytes(header[STRING_LENGTH_OFFSET:STRING_LENGTH_OFFSET + 8], "little")
    capacity = int.from_bytes(header[STRING_CAPACITY_OFFSET:STRING_CAPACITY_OFFSET + 8], "little")
    result: dict[str, Any] = {
        "status": "unknown",
        "complete": False,
        "address": _address(header_address, reader.module_base),
        "header_hex": header.hex(),
        "length": length,
        "length_offset": _hex(STRING_LENGTH_OFFSET),
        "capacity": capacity,
        "capacity_offset": _hex(STRING_CAPACITY_OFFSET),
        "storage": "inline" if capacity < 16 else "heap",
        "heap_pointer": None,
        "payload_hex": None,
        "nul_terminator_observed": None,
        "text": None,
        "unknown_reason": None,
        "read_label": label,
    }
    if length > MAX_ASCII_ROOT_LENGTH:
        result["unknown_reason"] = "ascii_root_length_exceeds_256"
        return result
    if capacity < length:
        result["unknown_reason"] = "string_capacity_below_length"
        return result
    if capacity >= 16 and capacity > MAX_STRING_CAPACITY:
        result["unknown_reason"] = "string_capacity_exceeds_4096_bound"
        return result

    if capacity < 16:
        if length > 15:
            result["unknown_reason"] = "inline_length_exceeds_15"
            return result
        payload_with_nul = header[:16]
    else:
        heap_pointer = int.from_bytes(header[:8], "little")
        result["heap_pointer"] = _address(heap_pointer, reader.module_base)
        if length == 0:
            payload_with_nul = b"\x00"
        else:
            if not _valid_pointer(heap_pointer):
                result["unknown_reason"] = "heap_pointer_invalid"
                return result
            payload_with_nul = reader.read(heap_pointer, length + 1, f"{label}.payload")

    if length >= len(payload_with_nul):
        result["unknown_reason"] = "string_nul_not_readable"
        return result
    payload = payload_with_nul[:length]
    nul_ok = payload_with_nul[length] == 0
    result["payload_hex"] = payload_with_nul.hex()
    result["nul_terminator_observed"] = nul_ok
    if not nul_ok:
        result["unknown_reason"] = "string_nul_missing"
        return result
    if b"\x00" in payload:
        result["unknown_reason"] = "embedded_nul"
        return result
    if any(byte >= 0x80 for byte in payload):
        result["unknown_reason"] = "root_string_not_ascii"
        return result
    try:
        text = payload.decode("ascii")
    except UnicodeDecodeError:
        result["unknown_reason"] = "root_string_not_ascii"
        return result
    result.update({"status": "observed", "complete": True, "text": text})
    return result


def _country_scan(reader: BoundedRPM, database: int, requested_country: str) -> dict[str, Any]:
    """Bind a canonical mission owner across the live B23 country manager."""
    result: dict[str, Any] = {
        "status": "unknown",
        "requested_country": requested_country,
        "table_field": None,
        "max_entries": _countries.MAX_COUNTRY_SLOTS,
        "scanned_entries": 0,
        "matches": [],
        "country_pointer": None,
        "country_handle": None,
    }
    try:
        scan = _countries.resolve_countries(reader.read_code, reader.module_base, [requested_country])
    except _countries.CountryReferenceError as exc:
        result["unknown_reason"] = str(exc)
        return result
    if int(scan["database"], 16) != database:
        result["unknown_reason"] = "country_database_changed_during_scan"
        return result
    row = scan["requested"][requested_country]
    table = int(scan["table"], 16)
    match = {
        "table_index": row["slot"],
        "country_pointer": _address(int(row["country_pointer"], 16), reader.module_base),
        "country_handle": {
            "address": _address(int(row["country_fullref_address"], 16), reader.module_base),
            "field_offset": _hex(COUNTRY_HANDLE_OFFSET),
            "raw_hex": row["fullref_raw_hex"],
            "value": row["fullref"],
            "tag": requested_country,
            "slot": row["slot"],
        },
    }
    result.update(
        status="observed",
        table_field=_field_address(reader, database + COUNTRY_TABLE_OFFSET,
                                   bytes.fromhex(scan["table_pointer_raw_hex"]), table,
                                   offset=COUNTRY_TABLE_OFFSET),
        scanned_entries=scan["count"],
        matches=[match],
        **match,
    )
    return result


def _mission_slots(reader: BoundedRPM, mission_object: int, include_completed: bool, country: int) -> dict[str, Any]:
    result: dict[str, Any] = {
        "status": "unknown",
        "mission_object": _address(mission_object, reader.module_base),
        "slot_array": None,
        "slot_count": None,
        "slot_header_hex": None,
        "slots": [],
        "rootstrings": [],
        "candidate_completed_missions": None,
    }
    header = reader.read(mission_object, SLOT_COUNT_OFFSET + 4, "country_missions.header")
    slot_array = int.from_bytes(header[SLOT_ARRAY_OFFSET:SLOT_ARRAY_OFFSET + 8], "little")
    slot_count = int.from_bytes(header[SLOT_COUNT_OFFSET:SLOT_COUNT_OFFSET + 4], "little", signed=True)
    result.update({
        "slot_array": _address(slot_array, reader.module_base),
        "slot_count": slot_count,
        "slot_header_hex": header.hex(),
        "slot_array_field_offset": _hex(SLOT_ARRAY_OFFSET),
        "slot_count_field_offset": _hex(SLOT_COUNT_OFFSET),
    })
    if slot_count < 0 or slot_count > MAX_MISSION_SLOTS:
        result["unknown_reason"] = "slot_count_out_of_bound"
        return result
    if slot_count and not _valid_pointer(slot_array):
        result["unknown_reason"] = "slot_array_pointer_invalid"
        return result
    if slot_count:
        slots_raw = reader.read(slot_array, slot_count * SLOT_STRIDE, "country_missions.slot_array")
    else:
        slots_raw = b""
    all_complete = True
    for slot_index in range(slot_count):
        offset = slot_index * SLOT_STRIDE
        slot_raw = slots_raw[offset:offset + SLOT_STRIDE]
        root_array = int.from_bytes(slot_raw[ROOT_ARRAY_OFFSET:ROOT_ARRAY_OFFSET + 8], "little")
        root_count = int.from_bytes(slot_raw[ROOT_COUNT_OFFSET:ROOT_COUNT_OFFSET + 4], "little", signed=True)
        slot_result: dict[str, Any] = {
            "slot_index": slot_index,
            "address": _address(slot_array + offset, reader.module_base),
            "raw_hex": slot_raw.hex(),
            "stride": SLOT_STRIDE,
            "root_array": _address(root_array, reader.module_base),
            "root_array_field_offset": _hex(ROOT_ARRAY_OFFSET),
            "root_count": root_count,
            "root_count_field_offset": _hex(ROOT_COUNT_OFFSET),
            "root_array_raw_hex": None,
            "roots": [],
            "status": "unknown",
        }
        if root_count < 0 or root_count > MAX_ROOTS_PER_SLOT:
            slot_result["unknown_reason"] = "root_count_out_of_bound"
            result["slots"].append(slot_result)
            all_complete = False
            continue
        if root_count and not _valid_pointer(root_array):
            slot_result["unknown_reason"] = "root_array_pointer_invalid"
            result["slots"].append(slot_result)
            all_complete = False
            continue
        root_raw = reader.read(root_array, root_count * 8, f"slot[{slot_index}].root_pointers") if root_count else b""
        slot_result["root_array_raw_hex"] = root_raw.hex()
        slot_complete = True
        for root_index in range(root_count):
            raw = root_raw[root_index * 8:(root_index + 1) * 8]
            definition = int.from_bytes(raw, "little")
            root_result: dict[str, Any] = {
                "slot_index": slot_index,
                "root_index": root_index,
                "pointer_raw_hex": raw.hex(),
                "definition": _address(definition, reader.module_base),
                "definition_name": None,
                "status": "unknown",
            }
            if not _valid_pointer(definition):
                root_result["unknown_reason"] = "definition_pointer_invalid"
                slot_complete = False
                slot_result["roots"].append(root_result)
                continue
            header_address = definition + DEFINITION_NAME_OFFSET
            root_result["definition_name_address"] = _address(header_address, reader.module_base)
            root_result["definition_name_field_offset"] = _hex(DEFINITION_NAME_OFFSET)
            try:
                name_header = reader.read(header_address, 32, f"slot[{slot_index}].root[{root_index}].String32")
                decoded = _decode_string32(reader, header_address, name_header, f"slot[{slot_index}].root[{root_index}]")
            except Exception as exc:
                decoded = _unknown_string(header_address, reader, None, f"String32_read_failed:{exc}")
            root_result["definition_name"] = decoded
            root_result["status"] = decoded["status"]
            if decoded["status"] != "observed":
                root_result["unknown_reason"] = decoded.get("unknown_reason")
                slot_complete = False
            else:
                result["rootstrings"].append({
                    "slot_index": slot_index,
                    "root_index": root_index,
                    "text": decoded["text"],
                    "status": "observed",
                })
            slot_result["roots"].append(root_result)
        slot_result["status"] = "observed" if slot_complete else "unknown"
        if not slot_complete:
            slot_result.setdefault("unknown_reason", "one_or_more_root_strings_unknown")
        all_complete = all_complete and slot_complete
        result["slots"].append(slot_result)
    result["status"] = "observed" if all_complete else "unknown"
    if result["status"] != "observed":
        result.setdefault("unknown_reason", "one_or_more_slots_or_root_strings_unknown")
    if include_completed and result["status"] == "observed":
        result["candidate_completed_missions"] = _completed_candidates(reader, country)
        if result["candidate_completed_missions"].get("status") != "observed":
            result["status"] = "unknown"
            result["unknown_reason"] = "completed_candidate_list_unknown"
    return result


def _completed_candidates(reader: BoundedRPM, country: int) -> dict[str, Any]:
    result: dict[str, Any] = {
        "status": "unknown",
        "container": None,
        "sentinel": None,
        "begin": None,
        "nodes": [],
        "rootstrings": [],
        "max_nodes": MAX_COMPLETED_NODES,
    }
    # The static caller uses ``lea rcx,[r15+0x9998]``.  This is another
    # embedded container object: its address is passed to the helper, which
    # reads the sentinel from ``[container+8]``.  The first qword at the
    # address is therefore not an object pointer to follow.
    container_address = country + COUNTRY_COMPLETED_OFFSET
    container = container_address
    result["container_field"] = {
        "address": _address(container_address, reader.module_base),
        "field_offset": _hex(COUNTRY_COMPLETED_OFFSET),
        "raw_hex": None,
        "value": _address(container, reader.module_base),
        "storage": "embedded_object",
    }
    if not _valid_pointer(container):
        result["unknown_reason"] = "completed_container_pointer_invalid"
        return result
    sentinel_address = container + 8
    sentinel, sentinel_raw = reader.qword(sentinel_address, "completed.container.sentinel")
    result["sentinel_field"] = {
        "address": _address(sentinel_address, reader.module_base),
        "field_offset": "0x8",
        "raw_hex": sentinel_raw.hex(),
        "value": _address(sentinel, reader.module_base),
    }
    if not _valid_pointer(sentinel):
        result["unknown_reason"] = "completed_sentinel_pointer_invalid"
        return result
    begin, begin_raw = reader.qword(sentinel, "completed.sentinel.begin")
    result["begin_field"] = {
        "address": _address(sentinel, reader.module_base),
        "raw_hex": begin_raw.hex(),
        "value": _address(begin, reader.module_base),
    }
    result["container"] = _address(container, reader.module_base)
    result["sentinel"] = _address(sentinel, reader.module_base)
    result["begin"] = _address(begin, reader.module_base)
    if begin == sentinel:
        result.update({"status": "observed", "empty": True})
        return result
    if not _valid_pointer(begin):
        result["unknown_reason"] = "completed_begin_pointer_invalid"
        return result

    seen: set[int] = set()
    node = begin
    for node_index in range(MAX_COMPLETED_NODES):
        if node == sentinel:
            result.update({"status": "observed", "empty": False, "node_count": node_index})
            return result
        if not _valid_pointer(node):
            result["unknown_reason"] = "completed_node_pointer_invalid"
            return result
        if node in seen:
            result["unknown_reason"] = "completed_node_cycle"
            return result
        seen.add(node)
        node_raw = reader.read(node, 0x18, f"completed.node[{node_index}]")
        next_node = int.from_bytes(node_raw[0:8], "little")
        definition = int.from_bytes(node_raw[0x10:0x18], "little")
        item: dict[str, Any] = {
            "order": node_index,
            "node": _address(node, reader.module_base),
            "node_raw_hex": node_raw.hex(),
            "next": _address(next_node, reader.module_base),
            "definition": _address(definition, reader.module_base),
            "status": "unknown",
        }
        if not _valid_pointer(definition):
            item["unknown_reason"] = "completed_definition_pointer_invalid"
            result["nodes"].append(item)
            result["unknown_reason"] = "completed_definition_pointer_invalid"
            return result
        header_address = definition + DEFINITION_NAME_OFFSET
        item["definition_name_address"] = _address(header_address, reader.module_base)
        name_header = reader.read(header_address, 32, f"completed.node[{node_index}].String32")
        decoded = _decode_string32(reader, header_address, name_header, f"completed.node[{node_index}]")
        item["definition_name"] = decoded
        item["status"] = decoded["status"]
        result["nodes"].append(item)
        if decoded["status"] != "observed":
            result["unknown_reason"] = decoded.get("unknown_reason")
            return result
        result["rootstrings"].append({"order": node_index, "text": decoded["text"], "status": "observed"})
        node = next_node
    result["unknown_reason"] = "completed_node_limit_or_missing_sentinel"
    return result


def _snapshot(
    reader: BoundedRPM,
    module_base: int,
    country: str,
    include_completed: bool,
    include_tasks: bool = False,
    prerequisite_profile: Mapping[str, Any] | None = None,
    condition_profile: Mapping[str, Any] | None = None,
    trigger_profile: Mapping[str, Any] | None = None,
    trigger_selector: dict[str, str] | None = None,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "status": "unknown",
        "unknown_conditions": [],
        "game_pointer": None,
        "database_pointer": None,
        "game_date": None,
        "country_scan": None,
        "country_missions": None,
        "mission_contract": None,
        "missions": None,
    }
    if include_tasks:
        result["loaded_tasks"] = None
    try:
        game_field_address = module_base + GAME_RVA
        game, game_raw = reader.qword(game_field_address, "global.game_pointer")
        database_field_address = module_base + DATABASE_RVA
        database, database_raw = reader.qword(database_field_address, "global.database_pointer")
        result["game_pointer"] = _field_address(reader, game_field_address, game_raw, game, known_rva=GAME_RVA)
        result["database_pointer"] = _field_address(reader, database_field_address, database_raw, database, known_rva=DATABASE_RVA)
        if not _valid_pointer(game) or not _valid_pointer(database):
            result["unknown_conditions"].append("game_or_database_pointer_invalid")
            return result

        date_address = game + GAME_DATE_OFFSET
        date_raw = reader.read(date_address, 4, "game.raw_date")
        date_value = int.from_bytes(date_raw, "little", signed=True)
        result["game_date"] = {
            "address": _address(date_address, module_base),
            "field_offset": _hex(GAME_DATE_OFFSET),
            "raw_hex": date_raw.hex(),
            "raw": date_value,
        }
        country_scan = _country_scan(reader, database, country)
        result["country_scan"] = country_scan
        if country_scan.get("status") != "observed":
            result["unknown_conditions"].append(country_scan.get("unknown_reason", "country_identity_unknown"))
            return result
        country_pointer = _parse_int(str(country_scan["country_pointer"]["va"]))
        if country_pointer is None or not _valid_pointer(country_pointer):
            result["unknown_conditions"].append("country_pointer_invalid_after_scan")
            return result

        # The static caller uses ``lea r8,[r15+0x99d8]``.  This is an
        # embedded mission object, so its address is the field address and
        # the first qword at that address is the vtable.  Do not treat the
        # first qword as another object pointer.
        missions_field_address = country_pointer + COUNTRY_MISSIONS_OFFSET
        mission_object = missions_field_address
        mission_object_raw = reader.read(mission_object, 8, "country.country_missions.embedded_vtable")
        vtable = int.from_bytes(mission_object_raw, "little")
        result["country_missions"] = {
            "address": _address(missions_field_address, module_base),
            "field_offset": _hex(COUNTRY_MISSIONS_OFFSET),
            "raw_hex": mission_object_raw.hex(),
            "value": _address(mission_object, module_base),
            "storage": "embedded_object",
            "vtable_raw_value": _address(vtable, module_base),
        }
        if not _valid_pointer(mission_object):
            result["unknown_conditions"].append("country_missions_embedded_address_invalid")
            return result

        if not _valid_pointer(vtable):
            result["unknown_conditions"].append("country_missions_vtable_invalid")
            result["mission_contract"] = {
                "object": _address(mission_object, module_base),
                "vtable": {"raw_hex": mission_object_raw.hex(), "value": _address(vtable, module_base)},
                "status": "unknown",
            }
            return result
        thunk_address = vtable + 8
        thunk, thunk_raw = reader.qword(thunk_address, "country_missions.vtable_plus_8")
        thunk_rva = thunk - module_base if thunk >= module_base else None
        body_address = vtable + 0x10
        body, body_raw = reader.qword(body_address, "country_missions.vtable_plus_10")
        body_rva = body - module_base if body >= module_base else None
        vtable_rva = vtable - module_base if vtable >= module_base else None
        contract = {
            "object": _address(mission_object, module_base),
            "vtable": {
                "address": _address(mission_object, module_base),
                "raw_hex": mission_object_raw.hex(),
                "value": _address(vtable, module_base),
                "observed_rva": _hex(vtable_rva),
            },
            "vtable_plus_8": {
                "address": _address(thunk_address, module_base),
                "field_offset": "0x8",
                "raw_hex": thunk_raw.hex(),
                "value": _address(thunk, module_base),
                "observed_rva": _hex(thunk_rva),
            },
            "vtable_plus_10": {
                "address": _address(body_address, module_base),
                "field_offset": "0x10",
                "raw_hex": body_raw.hex(),
                "value": _address(body, module_base),
                "observed_rva": _hex(body_rva),
            },
            "expected_chain": {
                "vtable_rva": _hex(EXPECTED_MISSION_VTABLE_RVA),
                "vtable_plus_8_rva": _hex(EXPECTED_MISSION_THUNK_RVA),
                "vtable_plus_10_rva": _hex(EXPECTED_MISSION_WRITER_RVA),
            },
            "chain_matches": {
                "vtable_rva": vtable_rva == EXPECTED_MISSION_VTABLE_RVA,
                "vtable_plus_8_rva": thunk_rva == EXPECTED_MISSION_THUNK_RVA,
                "vtable_plus_10_rva": body_rva == EXPECTED_MISSION_WRITER_RVA,
            },
            "status": "observed"
            if (
                vtable_rva == EXPECTED_MISSION_VTABLE_RVA
                and thunk_rva == EXPECTED_MISSION_THUNK_RVA
                and body_rva == EXPECTED_MISSION_WRITER_RVA
            ) else "mismatch",
            "raw_recorded_before_stop": True,
        }
        result["mission_contract"] = contract
        if contract["status"] != "observed":
            result["status"] = "contract_mismatch"
            result["unknown_conditions"].append("running_object_vtable_chain_rva_mismatch")
            return result

        missions = _mission_slots(reader, mission_object, include_completed, country_pointer)
        result["missions"] = missions
        if missions.get("status") != "observed":
            result["unknown_conditions"].append(missions.get("unknown_reason", "mission_slots_unknown"))
            if include_tasks:
                try:
                    from . import mission_task_memory as task_memory

                    result["loaded_tasks"] = task_memory.unknown_loaded_tasks("root_missions_not_observed")
                except Exception as exc:
                    result["loaded_tasks"] = {
                        "status": "unknown",
                        "complete": False,
                        "roots": [],
                        "total_task_count": 0,
                        "unknown_conditions": [f"root_missions_not_observed:{exc}"],
                    }
                result["_loaded_tasks_compare"] = None
            return result
        if include_tasks:
            try:
                from . import mission_task_memory as task_memory

                loaded = task_memory.capture_loaded_tasks(reader, module_base, missions)
                result["loaded_tasks"] = loaded.get("loaded_tasks")
                result["_loaded_tasks_compare"] = loaded.get("_compare")
                if prerequisite_profile is not None:
                    from .mission_prerequisite_memory import capture_prerequisites
                    prerequisites = capture_prerequisites(
                        reader, module_base, result["loaded_tasks"],
                        code_guards=prerequisite_profile["code_guards"],
                    )
                    result["loaded_prerequisites"] = {key: value for key, value in prerequisites.items() if key != "_compare"}
                    result["_loaded_prerequisites_compare"] = prerequisites.get("_compare")
                    if condition_profile is not None:
                        from .mission_condition_memory import capture_conditions
                        conditions = capture_conditions(
                            reader, module_base, country_pointer, prerequisites,
                            code_guards=condition_profile['code_guards'])
                        result['mission_conditions'] = {key: value for key, value in conditions.items() if key != '_compare'}
                        result['_mission_conditions_compare'] = conditions.get('_compare')
                    if trigger_profile is not None:
                        from functools import partial
                        from .mission_trigger_memory import capture_triggers
                        from .mission_trigger_galleys import count_galleys
                        from .mission_trigger_provinces import make_province_reader
                        from .mission_trigger_army import count_army_ratio_inputs
                        from .mission_trigger_country_state import read_country_state
                        from .mission_trigger_geography import read_geographic_state
                        from .mission_trigger_country_scope import bind_country_scope
                        from .mission_trigger_dlc import read_dlc_state
                        from .mission_trigger_dynamic_scopes import read_scope_selector
                        from .mission_trigger_count_domain import read_count_domain
                        def country_condition_inputs(tracked_reader, base, pointer, kind):
                            if kind == 'army_ratio':
                                return count_army_ratio_inputs(tracked_reader, base, pointer, country=country)
                            return read_country_state(tracked_reader, base, pointer, kind)
                        triggers=capture_triggers(reader,module_base,country_pointer,prerequisites,
                            code_guards=trigger_profile['code_guards'],
                            galley_counter=partial(count_galleys, country=country),
                            province_reader=make_province_reader(observer=country),country_state_reader=country_condition_inputs,
                            task_selector=trigger_selector,
                            geographic_reader=read_geographic_state,country_scope_reader=bind_country_scope,
                            dlc_reader=read_dlc_state,dynamic_scope_reader=read_scope_selector,
                            count_domain_reader=read_count_domain,country=country)
                        result['mission_triggers']={key:value for key,value in triggers.items() if key!='_compare'}
                        result['_mission_triggers_compare']=triggers.get('_compare')
            except Exception as exc:
                result["loaded_tasks"] = {
                    "status": "unknown",
                    "complete": False,
                    "roots": [],
                    "total_task_count": 0,
                    "unknown_conditions": [f"loaded_task_read_failed:{exc}"],
                }
                result["_loaded_tasks_compare"] = None
        result["status"] = "observed"
        return result
    except Exception as exc:
        result["status"] = "unknown"
        result["unknown_conditions"].append(f"snapshot_read_failed:{exc}")
        if include_tasks:
            try:
                from . import mission_task_memory as task_memory

                result["loaded_tasks"] = task_memory.unknown_loaded_tasks(f"snapshot_task_read_failed:{exc}")
            except Exception:
                result["loaded_tasks"] = {
                    "status": "unknown",
                    "complete": False,
                    "roots": [],
                    "total_task_count": 0,
                    "unknown_conditions": [f"snapshot_task_read_failed:{exc}"],
                }
            result["_loaded_tasks_compare"] = None
        return result


def _without_private(value: Any) -> Any:
    """Remove internal comparison keys before placing a snapshot in a report."""
    if isinstance(value, dict):
        return {key: _without_private(item) for key, item in value.items() if not key.startswith("_")}
    if isinstance(value, list):
        return [_without_private(item) for item in value]
    return value


def _task_consistency_view(snapshot: Mapping[str, Any]) -> Any:
    return snapshot.get("_loaded_tasks_compare")


def _consistency_view(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    """Select raw identity and mission fields for the before/after compare."""
    game_date = snapshot.get("game_date")
    if _time.active() and isinstance(game_date, dict):
        game_date = {key: value for key, value in game_date.items()
                     if key not in ("raw", "raw_hex")}
    return {
        "game_pointer": snapshot.get("game_pointer"),
        "database_pointer": snapshot.get("database_pointer"),
        "game_date": game_date,
        "country_scan": {
            "status": (snapshot.get("country_scan") or {}).get("status"),
            "country_pointer": (snapshot.get("country_scan") or {}).get("country_pointer"),
            "country_handle": (snapshot.get("country_scan") or {}).get("country_handle"),
        },
        "country_missions": snapshot.get("country_missions"),
        "mission_contract": snapshot.get("mission_contract"),
        "missions": snapshot.get("missions"),
    }


def _snapshot_mismatches(before: Mapping[str, Any], after: Mapping[str, Any]) -> list[str]:
    mismatches = _diff_paths(_consistency_view(before), _consistency_view(after))
    if not _time.dates_match(before.get("game_date", {}).get("raw"),
                             after.get("game_date", {}).get("raw")):
        mismatches.append("$.game_date")
    return mismatches


def _diff_paths(left: Any, right: Any, path: str = "$") -> list[str]:
    if type(left) is not type(right):
        return [path]
    if isinstance(left, dict):
        paths: list[str] = []
        for key in sorted(set(left) | set(right)):
            if key not in left or key not in right:
                paths.append(f"{path}.{key}")
            else:
                paths.extend(_diff_paths(left[key], right[key], f"{path}.{key}"))
        return paths
    if isinstance(left, list):
        paths = []
        if len(left) != len(right):
            paths.append(f"{path}.length")
        for index, (a, b) in enumerate(zip(left, right)):
            paths.extend(_diff_paths(a, b, f"{path}[{index}]"))
        return paths
    return [] if left == right else [path]


def _close_process_handle(kernel: Any, handle: Any) -> dict[str, Any]:
    """Close an opened process handle exactly once and report its outcome."""
    if kernel is None or handle is None:
        return {"status": "not_opened", "success": None, "closed": False}
    try:
        if not bool(handle):
            return {"status": "not_opened", "success": None, "closed": False}
    except Exception as exc:
        return {"status": "error", "success": False, "closed": False, "error": str(exc)}
    try:
        closed = bool(kernel.CloseHandle(handle))
    except Exception as exc:
        return {"status": "error", "success": False, "closed": False, "error": str(exc)}
    if closed:
        return {"status": "closed", "success": True, "closed": True}
    return {
        "status": "error",
        "success": False,
        "closed": False,
        "error": f"CloseHandle returned false (last_error={C.get_last_error()})",
    }


def _apply_cleanup(report: dict[str, Any], kernel: Any, handle: Any) -> None:
    """Record cleanup and prevent a close failure from being reported as success."""
    outcome = _close_process_handle(kernel, handle)
    report["cleanup"]["handle_close"] = outcome
    if outcome["status"] == "error":
        previous_status = report.get("status")
        outcome["previous_status"] = previous_status
        report["status"] = "cleanup_error"
        report["errors"].append({
            "stage": "cleanup",
            "status": "error",
            "error": outcome.get("error", "CloseHandle failed"),
            "previous_status": previous_status,
        })


def capture(
    installation: Path,
    country: str,
    *,
    include_completed: bool = False,
    include_tasks: bool = False,
    include_prerequisites: bool = False,
    include_conditions: bool = False,
    include_triggers: bool = False,
    trigger_selector: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Capture one bounded double-pass observation without writing a file."""
    installation = Path(installation)
    report = _base_report(installation, country, include_completed, include_tasks)
    prerequisite_profile = None
    condition_profile = None
    trigger_profile = None
    trigger_options = {}
    if trigger_selector is not None:
        from .mission_trigger_selection import select_tasks
        select_tasks([], trigger_selector)
        if not include_triggers:
            raise ValueError('trigger_selector requires include_triggers')
        trigger_options['trigger_selector'] = dict(trigger_selector)
        report['request']['trigger_selector'] = dict(trigger_selector)
    if include_triggers and not include_conditions:
        raise ValueError('include_triggers requires include_conditions')
    if include_conditions and not include_prerequisites:
        raise ValueError('include_conditions requires include_prerequisites')
    if include_prerequisites:
        if not include_tasks:
            raise ValueError('include_prerequisites requires include_tasks')
        report["request"]["include_prerequisites"] = True
        report["doublepass"]["prerequisite_consistent"] = False
        report["loaded_prerequisites"] = {"status": "unknown", "complete": False,
                                            "reason": "PREREQUISITES_NOT_CAPTURED"}
        try:
            from .mission_prerequisite_profile import load_profile, PROFILE_SHA256
            prerequisite_profile = load_profile()
            report["prerequisite_profile_sha256"] = PROFILE_SHA256
            from . import mission_prerequisite_memory
            report['prerequisite_reader'] = {
                'path': str(Path(mission_prerequisite_memory.__file__).resolve()),
                'sha256': _sha256_file(Path(mission_prerequisite_memory.__file__)),
            }
        except Exception as exc:
            report["status"] = "prerequisite_profile_mismatch"
            report["errors"].append({"stage": "prerequisite_profile", "error": str(exc)})
            _apply_cleanup(report, None, None)
            return report
    if include_conditions:
        report['request']['include_conditions'] = True
        report['doublepass']['condition_consistent'] = False
        report['mission_conditions'] = {'status': 'unknown', 'complete': False, 'reason': 'MISSION_CONDITIONS_NOT_CAPTURED'}
        try:
            from .mission_condition_profile import load_profile as load_condition_profile, PROFILE_SHA256 as CONDITION_PROFILE_SHA
            from . import mission_condition_memory
            condition_profile = load_condition_profile()
            report['condition_profile_sha256'] = CONDITION_PROFILE_SHA
            report['condition_reader'] = {'path': str(Path(mission_condition_memory.__file__).resolve()),
                                          'sha256': _sha256_file(Path(mission_condition_memory.__file__))}
        except Exception as exc:
            report['status'] = 'condition_profile_mismatch'
            report['errors'].append({'stage': 'condition_profile', 'error': str(exc)})
            _apply_cleanup(report, None, None)
            return report
    if include_triggers:
        report['request']['include_triggers']=True
        report['doublepass']['trigger_consistent']=False
        report['mission_triggers']={'status':'unknown','complete':False,'reason':'MISSION_TRIGGERS_NOT_CAPTURED'}
        try:
            from .mission_trigger_profile import load_profile as load_trigger_profile, PROFILE_SHA256 as TRIGGER_PROFILE_SHA
            from . import mission_trigger_memory, mission_trigger_galleys, mission_trigger_provinces
            from . import mission_trigger_army, mission_trigger_country_state
            from . import mission_trigger_geography, mission_trigger_country_scope
            from . import mission_trigger_dlc, mission_trigger_dynamic_scopes
            from . import mission_trigger_count_domain
            trigger_profile=load_trigger_profile()
            report['trigger_profile_sha256']=TRIGGER_PROFILE_SHA
            report['trigger_reader']={
                'path':str(Path(mission_trigger_memory.__file__).resolve()),
                'sha256':_sha256_file(Path(mission_trigger_memory.__file__)),
                'galley_adapter_sha256':_sha256_file(Path(mission_trigger_galleys.__file__)),
                'province_adapter_sha256':_sha256_file(Path(mission_trigger_provinces.__file__)),
                'army_adapter_sha256':_sha256_file(Path(mission_trigger_army.__file__)),
                'country_state_adapter_sha256':_sha256_file(Path(mission_trigger_country_state.__file__)),
                'geographic_adapter_sha256':_sha256_file(Path(mission_trigger_geography.__file__)),
                'country_scope_adapter_sha256':_sha256_file(Path(mission_trigger_country_scope.__file__)),
                'dlc_adapter_sha256':_sha256_file(Path(mission_trigger_dlc.__file__)),
                'dynamic_scope_adapter_sha256':_sha256_file(Path(mission_trigger_dynamic_scopes.__file__)),
                'count_domain_adapter_sha256':_sha256_file(Path(mission_trigger_count_domain.__file__))}
        except Exception as exc:
            report['status']='trigger_profile_mismatch'
            report['errors'].append({'stage':'trigger_profile','error':str(exc)})
            _apply_cleanup(report,None,None)
            return report
    try:
        report["probe_script_sha256"] = _sha256_file(Path(__file__).resolve())
    except OSError as exc:
        report["errors"].append({"stage": "probe_identity", "status": "unknown", "error": str(exc)})
    task_memory = None
    task_sampling_enabled = bool(include_tasks)
    if include_tasks:
        from . import mission_task_memory as task_memory

        try:
            task_reader_path = Path(task_memory.__file__).resolve()
            task_reader_sha256 = task_memory._sha256_file(task_reader_path)
        except (OSError, AttributeError) as exc:
            task_reader_path = Path(getattr(task_memory, "__file__", "")).resolve()
            task_reader_sha256 = None
            report["errors"].append({"stage": "task_reader_identity", "status": "unknown", "error": str(exc)})
        report["task_reader"] = {
            "path": str(task_reader_path),
            "sha256": task_reader_sha256,
            "profile_path": str(task_memory.PROFILE_FILE),
            "profile_sha256": task_memory.EXPECTED_PROFILE_SHA256,
        }
    report["static_contract_guard"] = _static_contract_guard()
    if report["static_contract_guard"].get("status") != "observed":
        report["status"] = "static_contract_mismatch"
        if include_tasks:
            from . import mission_task_memory as task_memory

            report["loaded_tasks"] = task_memory.unknown_loaded_tasks("mission_static_contract_mismatch")
        report["errors"].append({
            "stage": "static_contract",
            "status": "unknown",
            "error": "Bounded profile LEA/wrapper/slot guards did not match",
        })
        _apply_cleanup(report, None, None)
        return report
    if include_tasks:
        report["task_static_contract_guard"] = task_memory._static_contract_guard()
        if report["task_static_contract_guard"].get("status") != "observed":
            task_sampling_enabled = False
            report["loaded_tasks"] = task_memory.unknown_loaded_tasks("task_static_contract_mismatch")
            report["doublepass"]["task_consistent"] = False
            report["doublepass"]["task_mismatches"] = ["$.task_static_contract_guard"]
            report["errors"].append({
                "stage": "task_static_contract",
                "status": "unknown",
                "error": "Loaded-task profile/vector/parser guards did not match",
            })
    if not isinstance(country, str) or re.fullmatch(r"[A-Z0-9]{3}", country) is None:
        report["status"] = "unsupported_country"
        report["errors"].append({"stage": "request", "status": "unknown", "error": "Invalid country tag"})
        if include_tasks:
            report["loaded_tasks"] = task_memory.unknown_loaded_tasks("unsupported_country")
        _apply_cleanup(report, None, None)
        return report

    handle = None
    kernel = None
    reader: BoundedRPM | None = None
    try:
        document = _load_installation(installation)
        pid = _parse_int(document.get("pid"))
        expected_creation = _parse_int(document.get("creation_filetime"))
        assert pid is not None and expected_creation is not None
        report["identity"].update({
            "installation_pid": pid,
            "installation_creation_filetime": expected_creation,
            "installation_session_id": document.get("session_id"),
        })
        kernel = _configure_kernel()
        handle = kernel.OpenProcess(PROCESS_ACCESS, False, pid)
        if not handle:
            raise C.WinError(C.get_last_error())

        process_path_buffer = C.create_unicode_buffer(32768)
        process_path_length = W.DWORD(len(process_path_buffer))
        if not kernel.QueryFullProcessImageNameW(handle, 0, process_path_buffer, C.byref(process_path_length)):
            raise C.WinError(C.get_last_error())
        process_path = Path(process_path_buffer.value).resolve()
        process_hash = _sha256_file(process_path)
        report["identity"].update({
            "process_path": str(process_path),
            "process_path_sha256": process_hash,
            "process_path_sha256_matches_expected": process_hash.lower() == EXPECTED_EXE_SHA256,
        })
        report["file_code_guard"] = _file_code_guard(process_path)
        if include_tasks and task_sampling_enabled:
            report["task_file_code_guard"] = task_memory._file_code_guard(process_path)

        creation = W.FILETIME()
        exit_time = W.FILETIME()
        kernel_time = W.FILETIME()
        user_time = W.FILETIME()
        if not kernel.GetProcessTimes(handle, C.byref(creation), C.byref(exit_time), C.byref(kernel_time), C.byref(user_time)):
            raise C.WinError(C.get_last_error())
        process_creation = _filetime_value(creation)
        report["identity"].update({
            "process_creation_filetime": process_creation,
            "process_creation_utc": _filetime_iso(process_creation),
            "process_creation_matches_installation": process_creation == expected_creation,
        })

        modules = (W.HMODULE * 1024)()
        needed = W.DWORD()
        if not kernel.K32EnumProcessModulesEx(handle, modules, C.sizeof(modules), C.byref(needed), 3):
            raise C.WinError(C.get_last_error())
        if not needed.value or needed.value > C.sizeof(modules) or needed.value % C.sizeof(W.HMODULE):
            raise ProbeError("module_list_invalid")
        module_base = int(getattr(modules[0], "value", modules[0]))
        if module_base < 0x10000:
            raise ProbeError("module_base_invalid")
        module_name_buffer = C.create_unicode_buffer(32768)
        module_name_length = kernel._probe_get_module_name(handle, modules[0], module_name_buffer, len(module_name_buffer))
        module_path = Path(module_name_buffer.value).resolve() if module_name_length else None
        report["module_base"] = _address(module_base)
        report["identity"]["module_path"] = str(module_path) if module_path else None
        report["identity"]["module_path_matches_process"] = module_path == process_path if module_path else False

        identity_ok = (
            report["identity"]["process_path_sha256_matches_expected"] is True
            and report["identity"]["process_creation_matches_installation"] is True
            and report["identity"]["module_path_matches_process"] is True
            and str(document.get("game_sha256", "")).lower() == EXPECTED_EXE_SHA256
        )
        report["identity"]["binding_verified"] = identity_ok
        if not identity_ok:
            report["status"] = "identity_mismatch"
            report["errors"].append({"stage": "identity", "status": "unknown", "error": "PID creation/path/SHA/module binding mismatch"})
        elif report["file_code_guard"].get("status") != "observed":
            report["status"] = "file_code_mismatch"
            report["errors"].append({"stage": "file_code_guard", "status": "unknown", "error": "Profile code bytes did not match the bound executable file"})
        else:
            if include_tasks and task_sampling_enabled and report["task_file_code_guard"].get("status") != "observed":
                task_sampling_enabled = False
                report["loaded_tasks"] = task_memory.unknown_loaded_tasks("task_file_code_mismatch")
                report["doublepass"]["task_consistent"] = False
                report["doublepass"]["task_mismatches"] = ["$.task_file_code_guard"]
                report["errors"].append({"stage": "task_file_code_guard", "status": "unknown", "error": "Loaded-task profile code/table bytes did not match the bound executable file; root capture continued without task sampling"})
            reader = BoundedRPM(kernel, handle, module_base)
            if include_prerequisites:
                from .mission_observer_guard import bind_loaded_observer
                try:
                    bind_loaded_observer(reader, document, installation, modules,
                                         needed.value // C.sizeof(W.HMODULE))
                except (OSError, ValueError):
                    reader.mission_observer_binding = None
            report["runtime_code_guard"] = _runtime_code_guard(reader, module_base)
            if report["runtime_code_guard"].get("status") != "observed":
                report["status"] = "runtime_code_mismatch"
                if include_tasks:
                    report["loaded_tasks"] = task_memory.unknown_loaded_tasks("runtime_code_mismatch")
                report["errors"].append({"stage": "runtime_code_guard", "status": "unknown", "error": "Profile code bytes did not match process memory"})
            elif include_tasks and task_sampling_enabled:
                report["task_runtime_code_guard"] = task_memory._runtime_code_guard(reader, module_base)
                if report["task_runtime_code_guard"].get("status") != "observed":
                    task_sampling_enabled = False
                    report["loaded_tasks"] = task_memory.unknown_loaded_tasks("task_runtime_code_mismatch")
                    report["doublepass"]["task_consistent"] = False
                    report["doublepass"]["task_mismatches"] = ["$.task_runtime_code_guard"]
                    report["errors"].append({"stage": "task_runtime_code_guard", "status": "unknown", "error": "Loaded-task parser/vtable table did not match process memory; root capture continued without task sampling"})
            if report["status"] == "runtime_code_mismatch":
                pass
            else:
                before = (
                    _snapshot(reader,module_base,country,include_completed,True,prerequisite_profile,condition_profile,trigger_profile,**trigger_options)
                    if trigger_profile is not None and task_sampling_enabled else
                    _snapshot(reader, module_base, country, include_completed, True, prerequisite_profile, condition_profile)
                    if condition_profile is not None and task_sampling_enabled else
                    _snapshot(reader, module_base, country, include_completed, True, prerequisite_profile)
                    if prerequisite_profile is not None and task_sampling_enabled else
                    _snapshot(reader, module_base, country, include_completed, True)
                    if task_sampling_enabled
                    else _snapshot(reader, module_base, country, include_completed)
                )
                report["before"] = _without_private(before)
                if before.get("status") == "observed":
                    after = (
                        _snapshot(reader,module_base,country,include_completed,True,prerequisite_profile,condition_profile,trigger_profile,**trigger_options)
                        if trigger_profile is not None and task_sampling_enabled else
                        _snapshot(reader, module_base, country, include_completed, True, prerequisite_profile, condition_profile)
                        if condition_profile is not None and task_sampling_enabled else
                        _snapshot(reader, module_base, country, include_completed, True, prerequisite_profile)
                        if prerequisite_profile is not None and task_sampling_enabled else
                        _snapshot(reader, module_base, country, include_completed, True)
                        if task_sampling_enabled
                        else _snapshot(reader, module_base, country, include_completed)
                    )
                    report["after"] = _without_private(after)
                    report["doublepass"]["performed"] = True
                    if after.get("status") == "observed":
                        mismatches = _snapshot_mismatches(before, after)
                        report["doublepass"]["mismatches"] = mismatches[:128]
                        report["doublepass"]["consistent"] = not mismatches
                        report["status"] = "observed" if not mismatches else "doublepass_mismatch"
                        if mismatches:
                            report["errors"].append({"stage": "doublepass", "status": "unknown", "error": "Before/after runtime identities or mission strings differ", "paths": mismatches[:128]})
                        if task_sampling_enabled:
                            task_left = _task_consistency_view(before)
                            task_right = _task_consistency_view(after)
                            task_mismatches = _diff_paths(task_left, task_right)
                            report["doublepass"]["task_mismatches"] = task_mismatches[:128]
                            if task_left is not None and task_right is not None:
                                report["doublepass"]["task_consistent"] = not task_mismatches
                            else:
                                report["doublepass"]["task_consistent"] = False
                            if task_mismatches:
                                report["loaded_tasks"] = task_memory.unknown_loaded_tasks("loaded_task_doublepass_mismatch")
                                report["errors"].append({"stage": "loaded_tasks_doublepass", "status": "unknown", "error": "Loaded task vector or task ID content changed between passes", "paths": task_mismatches[:128]})
                            elif task_left is not None and task_right is not None:
                                if mismatches:
                                    report["loaded_tasks"] = task_memory.unknown_loaded_tasks("root_doublepass_mismatch")
                                else:
                                    report["loaded_tasks"] = _without_private(before.get("loaded_tasks"))
                            else:
                                report["loaded_tasks"] = task_memory.unknown_loaded_tasks("loaded_task_observation_unknown")
                        if prerequisite_profile is not None:
                            prereq_left = before.get("_loaded_prerequisites_compare")
                            prereq_right = after.get("_loaded_prerequisites_compare")
                            prereq_mismatches = _diff_paths(prereq_left, prereq_right)
                            prereq_consistent = (not mismatches and report["doublepass"].get("task_consistent") is True
                                                 and prereq_left is not None and prereq_right is not None
                                                 and not prereq_mismatches)
                            report["doublepass"]["prerequisite_consistent"] = prereq_consistent
                            report["doublepass"]["prerequisite_mismatches"] = prereq_mismatches[:128]
                            report["loaded_prerequisites"] = (
                                _without_private(before["loaded_prerequisites"]) if prereq_consistent else
                                {"status": "unknown", "complete": False, "reason": "PREREQUISITE_CAPTURE_OR_CONSISTENCY_FAILED"})
                        if condition_profile is not None:
                            condition_left = before.get('_mission_conditions_compare')
                            condition_right = after.get('_mission_conditions_compare')
                            condition_mismatches = _diff_paths(condition_left, condition_right)
                            consistent = (report['doublepass'].get('prerequisite_consistent') is True
                                          and condition_left is not None and condition_right is not None
                                          and not condition_mismatches)
                            report['doublepass']['condition_consistent'] = consistent
                            report['doublepass']['condition_mismatches'] = condition_mismatches[:128]
                            report['mission_conditions'] = (
                                _without_private(before['mission_conditions']) if consistent else
                                {'status': 'unknown', 'complete': False, 'reason': 'MISSION_CONDITION_CAPTURE_OR_CONSISTENCY_FAILED'})
                        if trigger_profile is not None:
                            trigger_left=before.get('_mission_triggers_compare')
                            trigger_right=after.get('_mission_triggers_compare')
                            trigger_mismatches=_diff_paths(trigger_left,trigger_right)
                            consistent=(report['doublepass'].get('prerequisite_consistent') is True
                                        and trigger_left is not None and trigger_right is not None
                                        and not trigger_mismatches)
                            report['doublepass']['trigger_consistent']=consistent
                            report['doublepass']['trigger_mismatches']=trigger_mismatches[:128]
                            report['mission_triggers']=(
                                _without_private(before['mission_triggers']) if consistent else
                                {'status':'unknown','complete':False,'reason':'MISSION_TRIGGER_CAPTURE_OR_CONSISTENCY_FAILED'})
                    else:
                        report["doublepass"]["consistent"] = False
                        report["doublepass"]["mismatches"] = ["$.after.status"]
                        report["status"] = "doublepass_mismatch"
                        report["errors"].append({"stage": "doublepass", "status": "unknown", "error": "Second pass was not observed"})
                        if task_sampling_enabled:
                            report["doublepass"]["task_consistent"] = False
                            report["loaded_tasks"] = task_memory.unknown_loaded_tasks("loaded_task_second_pass_unknown")
                elif before.get("status") == "contract_mismatch":
                    report["status"] = "contract_mismatch"
                    report["errors"].append({"stage": "mission_contract", "status": "unknown", "error": "vtable/thunk/writer chain did not match the audited RVAs; raw contract was retained and sampling stopped"})
                    if task_sampling_enabled:
                        report["loaded_tasks"] = task_memory.unknown_loaded_tasks("mission_contract_mismatch")
                else:
                    report["status"] = "unknown"
                    report["errors"].append({"stage": "before", "status": "unknown", "error": "Initial runtime pass did not reach a complete mission snapshot"})
                    if task_sampling_enabled:
                        report["loaded_tasks"] = task_memory.unknown_loaded_tasks("loaded_task_first_pass_unknown")
    except Exception as exc:
        report["status"] = "error"
        report["errors"].append({"stage": "probe", "status": "unknown", "error": str(exc)})
    finally:
        if reader is not None:
            report["access"]["rpm_bytes_requested"] = reader.bytes_requested
            report["access"]["rpm_calls"] = reader.calls
        _apply_cleanup(report, kernel, handle)
        if include_tasks and report.get("cleanup", {}).get("handle_close", {}).get("status") == "error":
            report["loaded_tasks"] = task_memory.unknown_loaded_tasks("handle_close_failed")
    if include_tasks and report.get("loaded_tasks") is None:
        report["loaded_tasks"] = task_memory.unknown_loaded_tasks(f"loaded_task_capture_not_observed:{report.get('status')}")
    if include_prerequisites and report.get("cleanup", {}).get("handle_close", {}).get("closed") is not True:
        report["loaded_prerequisites"] = {"status": "unknown", "complete": False, "reason": "HANDLE_CLOSE_NOT_VERIFIED"}
        report["doublepass"]["prerequisite_consistent"] = False
    if include_conditions and report.get('cleanup', {}).get('handle_close', {}).get('closed') is not True:
        report['mission_conditions'] = {'status': 'unknown', 'complete': False, 'reason': 'HANDLE_CLOSE_NOT_VERIFIED'}
        report['doublepass']['condition_consistent'] = False
    if include_triggers and report.get('cleanup',{}).get('handle_close',{}).get('closed') is not True:
        report['mission_triggers']={'status':'unknown','complete':False,'reason':'HANDLE_CLOSE_NOT_VERIFIED'}
        report['doublepass']['trigger_consistent']=False
    report["completed"] = report["status"] in {
        "observed", "contract_mismatch", "doublepass_mismatch", "identity_mismatch",
        "file_code_mismatch", "runtime_code_mismatch", "task_static_contract_mismatch",
        "task_file_code_mismatch", "task_runtime_code_mismatch", "cleanup_error",
    }
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--installation", required=True, type=Path)
    parser.add_argument("--country", default=EXPECTED_COUNTRY)
    parser.add_argument("--include-completed", action="store_true", help="Read the separately contracted completed-list candidate with the same double pass")
    parser.add_argument("--include-tasks", action="store_true", help="Read each already observed root's bounded loaded-task vector with a separate double pass")
    parser.add_argument('--include-prerequisites', action='store_true', help='Read loaded required_missions vectors; requires --include-tasks')
    parser.add_argument('--include-conditions', action='store_true', help='Resolve canonical tasks and completion pointer keys; requires --include-prerequisites')
    parser.add_argument('--include-triggers',action='store_true',help='Read and partially evaluate loaded trigger trees; requires --include-conditions')
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    if args.include_prerequisites and not args.include_tasks:
        parser.error('--include-prerequisites requires --include-tasks')
    if args.include_conditions and not args.include_prerequisites:
        parser.error('--include-conditions requires --include-prerequisites')
    if args.include_triggers and not args.include_conditions:
        parser.error('--include-triggers requires --include-conditions')
    report = capture(
        args.installation,
        args.country,
        include_completed=args.include_completed,
        include_tasks=args.include_tasks,
        include_prerequisites=args.include_prerequisites,
        include_conditions=args.include_conditions,
        include_triggers=args.include_triggers,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    summary = {
        "probe": report["probe"],
        "status": report["status"],
        "country": report["request"]["country"],
        "doublepass": report["doublepass"],
        "rpm_bytes_requested": report["access"]["rpm_bytes_requested"],
        "output": str(args.output),
    }
    print(json.dumps(summary, ensure_ascii=False))
    return 0 if report["status"] == "observed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
