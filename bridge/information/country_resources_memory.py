"""Bounded read-only native monarch-point capture for EU4 1.37.4.

This module owns only the low-level country-resource reader.  It follows the
profile's fixed globals, country table and three signed 32-bit components,
and never calls a game function or writes target memory.  Profile loading is
fail-closed: an absent or mismatched profile makes ``capture`` return an
unknown report.
"""
from __future__ import annotations

import ctypes as C
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Mapping

from . import localization_memory as _loc
from . import monthly_economy_memory as _monthly
from . import mission_memory as _mm
from . import observation_time as _time


PROFILE_FILE = Path(__file__).resolve().parent / "profiles" / "country-resources-memory-1374-r2-sampling-r2.json"
PROFILE_MAX_BYTES = 64 * 1024
# The checked-in build contract supplies the final profile pin.
EXPECTED_PROFILE_SHA256 = "b85eda10474650afa108189fd11ce2fe9ffeab896e6d7f3d600769395bdd5836"
EXPECTED_EXE_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
EXPECTED_VERSION = "1.37.4"
EXPECTED_COUNTRY = "FRA"

PROCESS_ACCESS = _mm.PROCESS_ACCESS
MAX_USER_ADDRESS = _mm.MAX_USER_ADDRESS
MAX_SINGLE_RPM = 65_536
MAX_TOTAL_RPM = 512 * 1024
GAME_DATE_WIDTH = 4
POWER_FIELDS = ("administrative", "diplomatic", "military")


class ProfileError(RuntimeError):
    """The bounded country-resource profile is absent or invalid."""


class ProbeError(RuntimeError):
    """A bounded read or identity/contract check failed."""


def _parse_int(value: Any, label: str = "value") -> int:
    if isinstance(value, bool):
        raise ProfileError(f"profile_integer_invalid:{label}")
    if isinstance(value, int):
        parsed = value
    elif isinstance(value, str):
        try:
            parsed = int(value, 0)
        except ValueError as exc:
            raise ProfileError(f"profile_integer_invalid:{label}") from exc
    else:
        raise ProfileError(f"profile_integer_invalid:{label}")
    if parsed < 0:
        raise ProfileError(f"profile_integer_negative:{label}")
    return parsed


def _load_profile(
    path: Path | None = None,
    expected_sha256: str | None = None,
) -> dict[str, Any]:
    if path is None:
        path = PROFILE_FILE
    if expected_sha256 is None:
        expected_sha256 = EXPECTED_PROFILE_SHA256
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
    if not isinstance(expected_sha256, str) or len(expected_sha256) != 64:
        raise ProfileError("profile_sha256_pin_invalid")
    if actual.lower() != expected_sha256.lower():
        raise ProfileError("profile_sha256_mismatch")
    try:
        profile = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ProfileError(f"profile_json_invalid:{exc}") from exc
    if not isinstance(profile, dict) or profile.get("profile_id") != "country-resources-memory-1374":
        raise ProfileError("profile_shape_invalid")
    return profile


try:
    PROFILE: dict[str, Any] | None = _load_profile()
except ProfileError:
    # Keep the module importable when the profile is unavailable; capture then
    # fails closed through the static contract guard.
    PROFILE = None


def _active_profile() -> dict[str, Any]:
    profile = PROFILE
    if isinstance(profile, dict):
        return profile
    return _load_profile()


def _hex(value: int | None) -> str | None:
    return hex(value) if isinstance(value, int) else None


def _address(value: int | None, module_base: int | None = None, *, known_rva: int | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {"va": _hex(value), "rva": None, "rva_identity": "not_applicable"}
    if not isinstance(value, int):
        return result
    if known_rva is not None:
        result.update(rva=_hex(known_rva), rva_identity="contract_module_rva")
    elif isinstance(module_base, int) and module_base <= value < module_base + 0x40000000:
        result.update(rva=_hex(value - module_base), rva_identity="module_relative_candidate")
    else:
        result["rva_identity"] = "runtime_va_or_heap"
    return result


def _profile_code_guards(profile: Mapping[str, Any] | None = None) -> list[tuple[str, int, bytes]]:
    profile = _active_profile() if profile is None else profile
    raw_guards = profile.get("code_guards")
    if not isinstance(raw_guards, list) or not raw_guards:
        raise ProfileError("profile_code_guards_invalid")
    guards: list[tuple[str, int, bytes]] = []
    for item in raw_guards:
        if not isinstance(item, Mapping):
            raise ProfileError("profile_code_guard_not_object")
        name = item.get("name")
        if not isinstance(name, str) or not name:
            raise ProfileError("profile_code_guard_name_invalid")
        rva = _parse_int(item.get("rva"), f"code_guard.{name}.rva")
        raw_hex = item.get("hex", item.get("bytes"))
        if not isinstance(raw_hex, str) or not raw_hex or len(raw_hex) % 2:
            raise ProfileError(f"profile_code_guard_hex_invalid:{name}")
        try:
            raw = bytes.fromhex(raw_hex)
        except ValueError as exc:
            raise ProfileError(f"profile_code_guard_hex_invalid:{name}") from exc
        if not raw or len(raw) > MAX_SINGLE_RPM:
            raise ProfileError(f"profile_code_guard_size_invalid:{name}")
        guards.append((name, rva, raw))
    return guards


def _profile_layout(profile: Mapping[str, Any] | None = None) -> dict[str, Any]:
    profile = _active_profile() if profile is None else profile
    try:
        globals_ = profile["globals"]
        country = profile["country"]
        powers = profile["powers"]
        return {
            "database_rva": _parse_int(globals_["database_rva"], "globals.database_rva"),
            "game_rva": _parse_int(globals_["game_rva"], "globals.game_rva"),
            "game_date_offset": _parse_int(globals_["game_date_offset"], "globals.game_date_offset"),
            "supported_country": country["supported_country"],
            "table_offset": _parse_int(country["table_offset"], "country.table_offset"),
            "handle_offset": _parse_int(country["handle_offset"], "country.handle_offset"),
            "country_scan_entries": _parse_int(country["country_scan_entries"], "country.country_scan_entries"),
            "power_offsets": {
                key: _parse_int(powers[f"{key}_offset"], f"powers.{key}_offset")
                for key in POWER_FIELDS
            },
            "component_width": _parse_int(powers["component_width"], "powers.component_width"),
            "signed": powers["signed"],
            "scale": _parse_int(powers["scale"], "powers.scale"),
        }
    except (KeyError, TypeError) as exc:
        raise ProfileError(f"profile_layout_invalid:{exc}") from exc


def _static_contract_guard() -> dict[str, Any]:
    result: dict[str, Any] = {
        "status": "unknown",
        "evidence_kind": "ordinary_static_file_analysis_plus_bounded_runtime_reader",
        "profile": str(PROFILE_FILE),
        "profile_sha256": EXPECTED_PROFILE_SHA256,
        "checks": {},
        "unknown_conditions": [],
    }
    try:
        # Re-read and re-pin the profile on every guard invocation.  This is
        # deliberate: an in-memory profile loaded at import time must not
        # hide a later on-disk change.
        profile = _load_profile()
        layout = _profile_layout(profile)
        executable = profile.get("executable", {})
        provenance = profile.get("provenance", {})
        dependencies = provenance.get("dependencies") if isinstance(provenance, Mapping) else None
        dependency_hashes_ok, dependency_hash_checks, dependency_unknown = _dependency_hash_checks(dependencies)
        result["source_dependencies"] = deepcopy(dependencies) if isinstance(dependencies, list) else []
        result["dependency_hash_checks"] = dependency_hash_checks
        result["unknown_conditions"].extend(dependency_unknown)
        result["checks"] = {
            "profile_sha256": True,
            "profile_id": profile.get("profile_id") == "country-resources-memory-1374",
            "game_version": profile.get("game_version") == EXPECTED_VERSION,
            "game_sha256": str(executable.get("sha256", "")).lower() == EXPECTED_EXE_SHA256,
            "supported_country": layout["supported_country"] == EXPECTED_COUNTRY,
            "database_rva": layout["database_rva"] == _loc.DATABASE_RVA,
            "game_rva": layout["game_rva"] == _loc.GAME_RVA,
            "game_date_offset": layout["game_date_offset"] == _loc.GAME_DATE_OFFSET,
            "table_offset": layout["table_offset"] == _loc.COUNTRY_TABLE_OFFSET,
            "handle_offset": layout["handle_offset"] == _loc.COUNTRY_HANDLE_OFFSET,
            "country_scan_entries": layout["country_scan_entries"] == _loc.COUNTRY_SCAN_ENTRIES,
            "component_width": layout["component_width"] == 4,
            "signed": layout["signed"] is True,
            "scale": layout["scale"] == 1,
            "power_offsets_distinct": len(set(layout["power_offsets"].values())) == 3,
            "code_guards": bool(_profile_code_guards(profile)),
            "provenance_dependencies": dependency_hashes_ok,
        }
        failed = [key for key, value in result["checks"].items() if value is not True]
        if failed:
            result["unknown_conditions"].append("profile_contract_check_failed:" + ",".join(failed))
        else:
            result["status"] = "observed"
    except (ProfileError, KeyError, TypeError, ValueError, AttributeError) as exc:
        result["unknown_conditions"].append(f"profile_contract_read_failed:{exc}")
    return result


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _dependency_path(raw_path: str) -> Path:
    """Resolve a profile dependency relative to this repository."""
    path = Path(raw_path)
    if path.is_absolute():
        return path.resolve()
    return (Path(__file__).resolve().parents[2] / path).resolve()


def _dependency_hash_checks(dependencies: Any) -> tuple[bool, dict[str, bool], list[str]]:
    """Validate references and hash runtime data dependencies.

    Python references retain the analysis revision. Current Python code runs
    under the pinned profile, native instructions and runtime identity checks.
    """
    if not isinstance(dependencies, list) or not dependencies:
        return False, {}, ["dependencies_missing_or_empty"]
    checks: dict[str, bool] = {}
    unknown: list[str] = []
    workspace = Path(__file__).resolve().parents[2]
    max_bytes = 16 * 1024 * 1024
    for item in dependencies:
        if not isinstance(item, Mapping):
            unknown.append("dependency_not_object")
            continue
        raw_path = item.get("path")
        expected = item.get("sha256")
        if not isinstance(raw_path, str) or not raw_path:
            unknown.append("dependency_path_invalid")
            continue
        key = raw_path
        if not isinstance(expected, str) or re.fullmatch(r"[0-9a-fA-F]{64}", expected) is None:
            checks[key] = False
            unknown.append(f"dependency_sha256_invalid:{key}")
            continue
        dependency_path = _dependency_path(raw_path)
        if workspace != dependency_path and workspace not in dependency_path.parents:
            checks[key] = False
            unknown.append(f"dependency_outside_workspace:{key}")
            continue
        if dependency_path.suffix == ".py":
            continue
        try:
            if not dependency_path.is_file():
                raise OSError("dependency_not_regular_file")
            size = dependency_path.stat().st_size
            if size > max_bytes:
                raise OSError(f"dependency_size_out_of_bound:{size}")
            actual = _sha256_file(dependency_path)
            if dependency_path.stat().st_size != size:
                raise OSError("dependency_changed_during_hash")
        except (OSError, ValueError) as exc:
            checks[key] = False
            unknown.append(f"dependency_read_failed:{key}:{exc}")
            continue
        checks[key] = actual.lower() == expected.lower()
        if not checks[key]:
            unknown.append(f"dependency_sha256_mismatch:{key}")
    return all(checks.values()) and not unknown, checks, unknown


class AddressBoundedRPM:
    """ReadProcessMemory wrapper with byte-address and hard budget guards."""

    def __init__(self, kernel: Any, handle: Any, module_base: int):
        self.kernel = kernel
        self.handle = handle
        self.module_base = module_base
        self.bytes_requested = 0
        self.calls = 0
        self.read_log: list[dict[str, Any]] = []

    def _reject(self, address: Any, size: Any, label: str, reason: str) -> None:
        self.read_log.append({
            "label": label, "address": _hex(address) if isinstance(address, int) else None,
            "size": size, "status": "rejected", "reason": reason,
        })
        raise ProbeError(f"{reason}:{label}")

    def read(self, address: int, size: int, label: str) -> bytes:
        if not isinstance(address, int) or isinstance(address, bool) or address < 0x10000:
            self._reject(address, size, label, "invalid_address")
        if not isinstance(size, int) or isinstance(size, bool) or size <= 0 or size > MAX_SINGLE_RPM:
            self._reject(address, size, label, "invalid_size")
        if address + size > MAX_USER_ADDRESS:
            self._reject(address, size, label, "address_range_overflow")
        if self.bytes_requested + size > MAX_TOTAL_RPM:
            self._reject(address, size, label, "RPM_TOTAL_BUDGET_EXCEEDED")
        self.bytes_requested += size
        self.calls += 1
        entry: dict[str, Any] = {
            "label": label, "address": hex(address), "size": size, "status": "requested"
        }
        self.read_log.append(entry)
        buffer = C.create_string_buffer(size)
        actual = C.c_size_t()
        try:
            ok = self.kernel.ReadProcessMemory(
                self.handle, C.c_void_p(address), buffer, size, C.byref(actual)
            )
        except Exception as exc:
            entry.update(status="error", error=f"{type(exc).__name__}:{exc}")
            raise
        if not ok:
            entry.update(status="error", error="ReadProcessMemory_failed")
            raise C.WinError(C.get_last_error())
        if actual.value != size:
            entry.update(status="error", error=f"short_read:{actual.value}/{size}")
            raise ProbeError(f"short_read:{label}:{actual.value}/{size}")
        raw = buffer.raw
        entry.update(status="observed", raw_hex=raw.hex())
        return raw

    def read_code(self, address: int, size: int, label: str) -> bytes:
        return self.read(address, size, label)

    def _read(self, address: int, size: int, label: str, *, aligned: bool = False) -> bytes:
        """Compatibility seam for the other bounded readers.

        This reader does not require alignment for ordinary byte ranges; the
        optional check is provided only when a caller explicitly asks for a
        qword-aligned access.
        """
        if aligned and (not isinstance(address, int) or address % 8):
            self._reject(address, size, label, "invalid_alignment")
        return self.read(address, size, label)

    def qword(self, address: int, label: str) -> tuple[int, bytes]:
        raw = self.read(address, 8, label)
        return int.from_bytes(raw, "little"), raw


def _read_pe_rva_bytes(path: Path, rva: int, size: int) -> bytes:
    return _loc._read_pe_rva_bytes(path, rva, size)


def _file_code_guard(path: Path) -> dict[str, Any]:
    result: dict[str, Any] = {
        "status": "unknown", "path": str(path), "checks": {}, "records": {}, "unknown_conditions": []
    }
    try:
        for name, rva, expected in _profile_code_guards():
            actual = _read_pe_rva_bytes(path, rva, len(expected))
            result["records"][name] = {
                "rva": _hex(rva), "expected_hex": expected.hex(), "actual_hex": actual.hex()
            }
            result["checks"][name] = actual == expected
        failed = [name for name, ok in result["checks"].items() if ok is not True]
        if failed:
            result["status"] = "mismatch"
            result["unknown_conditions"].append("file_code_guard_mismatch:" + ",".join(failed))
        else:
            result["status"] = "observed"
    except (OSError, ProbeError, ProfileError, KeyError, TypeError, ValueError) as exc:
        result["unknown_conditions"].append(str(exc))
    return result


def _runtime_code_guard(reader: AddressBoundedRPM, module_base: int) -> dict[str, Any]:
    result: dict[str, Any] = {
        "status": "unknown", "module_base": _address(module_base),
        "checks": {}, "records": {}, "unknown_conditions": []
    }
    try:
        for name, rva, expected in _profile_code_guards():
            address = module_base + rva
            actual = reader.read_code(address, len(expected), f"code_guard.{name}")
            result["records"][name] = {
                "address": _address(address, module_base, known_rva=rva),
                "expected_hex": expected.hex(), "actual_hex": actual.hex(),
            }
            result["checks"][name] = actual == expected
        failed = [name for name, ok in result["checks"].items() if ok is not True]
        if failed:
            result["status"] = "mismatch"
            result["unknown_conditions"].append("runtime_code_guard_mismatch:" + ",".join(failed))
        else:
            result["status"] = "observed"
    except (OSError, ProbeError, ProfileError, KeyError, TypeError, ValueError) as exc:
        result["unknown_conditions"].append(str(exc))
    return result


# The identity and selected-country traversal are deliberately shared with
# the already audited reader.  Their profile constants are checked above.
_load_installation = _loc._load_installation
_configure_kernel = _loc._configure_kernel
_capture_identity = _loc._capture_identity
_country_identity = _loc._country_identity
_close_process_handle = _loc._close_process_handle


def _va(value: Any) -> int | None:
    if isinstance(value, Mapping):
        raw = value.get("va")
    else:
        raw = value
    if isinstance(raw, int):
        return raw
    if isinstance(raw, str):
        try:
            return int(raw, 0)
        except ValueError:
            return None
    return None


def _snapshot(
    reader: AddressBoundedRPM,
    module_base: int,
    country: str,
    profile: Mapping[str, Any],
    include_monthly_economy: bool = False,
    include_trade_income: bool = False,
    include_home_trade_node: bool = False,
    include_trade_power: bool = False,
    include_trade_details: bool = False,
    include_military_quality: bool = False,
    include_country_loans: bool = False,
    include_country_modifiers: bool = False,
    include_trade_power_sum: bool = False,
    trade_income_node_id: str | None = None,
) -> dict[str, Any]:
    layout = _profile_layout(profile)
    result: dict[str, Any] = {
        "status": "unknown", "game_pointer": None, "database_pointer": None,
        "game_date": None, "country_scan": None, "values": None,
    }
    game_address = module_base + layout["game_rva"]
    game, game_raw = reader.qword(game_address, "globals.game_pointer")
    database_address = module_base + layout["database_rva"]
    database, database_raw = reader.qword(database_address, "globals.database_pointer")
    if not _mm._valid_pointer(game) or not _mm._valid_pointer(database):
        raise ProbeError("game_or_database_pointer_invalid")
    date_address = game + layout["game_date_offset"]
    date_raw = reader.read(date_address, GAME_DATE_WIDTH, "game.game_date")
    game_date = int.from_bytes(date_raw, "little", signed=True)
    country_scan = _country_identity(reader, database, country)
    if country_scan.get("status") != "observed":
        raise ProbeError(f"country_identity:{country_scan.get('unknown_reason', 'unknown')}")
    country_pointer = _va(country_scan.get("country_pointer"))
    if country_pointer is None:
        raise ProbeError("country_pointer_missing")
    values: dict[str, int] = {}
    value_raw: dict[str, str] = {}
    for field in POWER_FIELDS:
        address = country_pointer + layout["power_offsets"][field]
        raw = reader.read(address, layout["component_width"], f"country.{field}")
        values[field] = int.from_bytes(raw, "little", signed=True)
        value_raw[field] = raw.hex()
    result.update({
        "status": "observed",
        "game_pointer": {"address": _address(game_address, module_base, known_rva=layout["game_rva"]), "raw_hex": game_raw.hex(), "value": _address(game, module_base)},
        "database_pointer": {"address": _address(database_address, module_base, known_rva=layout["database_rva"]), "raw_hex": database_raw.hex(), "value": _address(database, module_base)},
        "game_date": {"value": game_date, "raw_hex": date_raw.hex()},
        "country_scan": country_scan,
        "values": values,
        "value_raw_hex": value_raw,
    })
    if include_monthly_economy:
        try:
            result["monthly_economy"] = _monthly.read_fields(reader, module_base, country_pointer)
        except Exception as exc:
            result["monthly_economy"] = _monthly.retract_record(
                None, f"monthly_economy_reader_failed:{type(exc).__name__}:{exc}"
            )
    if include_trade_income:
        try:
            from . import trade_income_memory as _trade
            result["trade_income"] = _trade.read_fields(reader, module_base, country_pointer)
        except Exception as exc:
            from . import trade_income_memory as _trade
            result["trade_income"] = _trade.retract_record(
                None, f"trade_income_reader_failed:{type(exc).__name__}:{exc}"
            )
    if include_home_trade_node:
        try:
            from . import home_trade_node_memory as _home
            result["home_trade_node"] = _home.read_fields(
                reader, module_base, result.get("trade_income")
            )
        except Exception as exc:
            from . import home_trade_node_memory as _home
            result["home_trade_node"] = _home.retract_record(
                None, f"home_trade_node_reader_failed:{type(exc).__name__}:{exc}"
            )
    if include_trade_power:
        try:
            from . import trade_power_memory as _power
            result["trade_power"] = _power.read_fields(
                reader, module_base, result.get("trade_income")
            )
        except Exception as exc:
            from . import trade_power_memory as _power
            result["trade_power"] = _power.retract_record(
                None, f"trade_power_reader_failed:{type(exc).__name__}:{exc}"
            )
    if include_trade_power_sum:
        from importlib import import_module
        _sum = import_module(".trade_power_sum_capture", __package__)
        try:
            result["trade_power_sum"] = _sum.read_fields(
                reader, module_base, result.get("trade_income"), country_scan
            )
        except Exception as exc:
            result["trade_power_sum"] = _sum.retract_record(
                None, f"trade_power_sum_reader_failed:{type(exc).__name__}:{exc}"
            )
    if trade_income_node_id is not None:
        from importlib import import_module
        _calculation = import_module(".trade_income_calculation_capture", __package__)
        try:
            result["trade_income_calculation"] = _calculation.read_fields(
                reader, module_base, result.get("trade_income"), country_scan,
                result.get("trade_power_sum"), node_id=trade_income_node_id,
            )
        except Exception as exc:
            result["trade_income_calculation"] = _calculation.retract_record(
                None, f"trade_income_calculation_reader_failed:{type(exc).__name__}:{exc}"
            )
    if include_trade_details:
        try:
            from . import trade_details_memory as _details
            result["trade_details"] = _details.read_fields(
                reader, module_base, result.get("trade_income")
            )
        except Exception as exc:
            from . import trade_details_memory as _details
            result["trade_details"] = _details.retract_record(
                None, f"trade_details_reader_failed:{type(exc).__name__}:{exc}"
            )
    if include_military_quality:
        from . import military_quality_memory as _military
        try:
            result["military_quality"] = _military.read_fields(reader, module_base, country_pointer)
        except Exception as exc:
            result["military_quality"] = _military.retract_record(
                None, f"military_quality_reader_failed:{type(exc).__name__}:{exc}"
            )
        from . import military_tradition_memory as _tradition
        try:
            result["military_tradition"] = _tradition.read_fields(reader, module_base, country_pointer)
        except Exception as exc:
            result["military_tradition"] = _tradition.retract_record(
                None, f"military_tradition_reader_failed:{type(exc).__name__}:{exc}"
            )
        from . import military_effective_memory as _effective
        try:
            result["military_effective"] = _effective.read_fields(reader, module_base, country_pointer)
        except Exception as exc:
            result["military_effective"] = _effective.retract_record(
                None, f"military_effective_reader_failed:{type(exc).__name__}:{exc}"
            )
        from . import military_morale_memory as _morale
        try:
            result["military_morale"] = _morale.read_fields(reader, module_base, country_pointer)
        except Exception as exc:
            result["military_morale"] = _morale.retract_record(
                None, f"military_morale_reader_failed:{type(exc).__name__}:{exc}"
            )
        from . import military_professionalism_memory as _professionalism
        try:
            result["military_professionalism"] = _professionalism.read_fields(reader, module_base, country_pointer)
        except Exception as exc:
            result["military_professionalism"] = _professionalism.retract_record(
                None, f"military_professionalism_reader_failed:{type(exc).__name__}:{exc}"
            )
    for enabled, key in ((include_country_loans, "country_loans"),
                         (include_country_modifiers, "country_modifiers")):
        if enabled:
            from importlib import import_module
            child = import_module(f".{key}_memory", __package__)
            try:
                result[key] = child.read_fields(reader, module_base, country_pointer)
            except Exception as exc:
                result[key] = child.retract_record(None, f"{key}_reader_failed:{type(exc).__name__}:{exc}")
    return result


def _retract_country_records(result, reason, *, include_country_loans=False,
                             include_country_modifiers=False):
    """Retract only the requested record children, keeping sibling data intact."""
    from importlib import import_module
    for enabled, key in ((include_country_loans, "country_loans"),
                         (include_country_modifiers, "country_modifiers")):
        if enabled or key in result:
            child = import_module(f".{key}_memory", __package__)
            result[key] = child.retract_record(result.get(key), reason)


def _retract_trade_power_sum(result, reason, *, enabled=False):
    """Retract only the optional trade-power sum child when it is present/requested."""
    if enabled or "trade_power_sum" in result:
        from importlib import import_module
        child = import_module(".trade_power_sum_capture", __package__)
        result["trade_power_sum"] = child.retract_record(
            result.get("trade_power_sum"), reason
        )


def _retract_trade_income_calculation(result, reason, *, enabled=False):
    """Retract only the requested optional trade-income calculation child."""
    if enabled or "trade_income_calculation" in result:
        from importlib import import_module
        child = import_module(".trade_income_calculation_capture", __package__)
        result["trade_income_calculation"] = child.retract_record(
            result.get("trade_income_calculation"), reason
        )


def _pass(
    reader: AddressBoundedRPM,
    module_base: int,
    country: str,
    profile: Mapping[str, Any],
    start: int,
    include_monthly_economy: bool = False,
    include_trade_income: bool = False,
    include_home_trade_node: bool = False,
    include_trade_power: bool = False,
    include_trade_details: bool = False,
    include_military_quality: bool = False,
    include_country_loans: bool = False,
    include_country_modifiers: bool = False,
    include_trade_power_sum: bool = False,
    trade_income_node_id: str | None = None,
) -> dict[str, Any]:
    runtime_guard = _runtime_code_guard(reader, module_base)
    if runtime_guard.get("status") != "observed":
        result = {
            "status": "unknown", "runtime_code_guard": runtime_guard,
            "read_log": deepcopy(reader.read_log[start:]), "values": None,
            "unknown_reason": "runtime_code_guard_failed",
        }
        if include_monthly_economy:
            result["monthly_economy"] = _monthly.retract_record(None, "runtime_code_guard_failed")
        if include_trade_income:
            from . import trade_income_memory as _trade
            result["trade_income"] = _trade.retract_record(None, "runtime_code_guard_failed")
        if include_home_trade_node:
            from . import home_trade_node_memory as _home
            result["home_trade_node"] = _home.retract_record(None, "runtime_code_guard_failed")
        if include_trade_power:
            from . import trade_power_memory as _power
            result["trade_power"] = _power.retract_record(None, "runtime_code_guard_failed")
        _retract_trade_power_sum(
            result, "runtime_code_guard_failed", enabled=include_trade_power_sum
        )
        _retract_trade_income_calculation(
            result, "runtime_code_guard_failed", enabled=trade_income_node_id is not None
        )
        if include_trade_details:
            from . import trade_details_memory as _details
            result["trade_details"] = _details.retract_record(None, "runtime_code_guard_failed")
        if include_military_quality:
            from . import military_quality_memory as _military
            result["military_quality"] = _military.retract_record(None, "runtime_code_guard_failed")
            from . import military_tradition_memory as _tradition
            result["military_tradition"] = _tradition.retract_record(None, "runtime_code_guard_failed")
            from . import military_effective_memory as _effective
            result["military_effective"] = _effective.retract_record(None, "runtime_code_guard_failed")
            from . import military_morale_memory as _morale
            result["military_morale"] = _morale.retract_record(None, "runtime_code_guard_failed")
            from . import military_professionalism_memory as _professionalism
            result["military_professionalism"] = _professionalism.retract_record(None, "runtime_code_guard_failed")
        _retract_country_records(result, "runtime_code_guard_failed",
                                 include_country_loans=include_country_loans,
                                 include_country_modifiers=include_country_modifiers)
        return result
    try:
        if trade_income_node_id is not None:
            snapshot = _snapshot(
                reader, module_base, country, profile,
                include_monthly_economy=include_monthly_economy,
                include_trade_income=include_trade_income,
                include_home_trade_node=include_home_trade_node,
                include_trade_power=include_trade_power,
                include_trade_details=include_trade_details,
                include_military_quality=include_military_quality,
                include_country_loans=include_country_loans,
                include_country_modifiers=include_country_modifiers,
                include_trade_power_sum=include_trade_power_sum,
                trade_income_node_id=trade_income_node_id,
            )
        elif include_trade_power_sum:
            snapshot = _snapshot(
                reader, module_base, country, profile,
                include_monthly_economy=include_monthly_economy,
                include_trade_income=include_trade_income,
                include_home_trade_node=include_home_trade_node,
                include_trade_power=include_trade_power,
                include_trade_details=include_trade_details,
                include_military_quality=include_military_quality,
                include_country_loans=include_country_loans,
                include_country_modifiers=include_country_modifiers,
                include_trade_power_sum=True,
            )
        elif include_country_loans or include_country_modifiers:
            snapshot = _snapshot(
                reader, module_base, country, profile,
                include_monthly_economy, include_trade_income,
                include_home_trade_node, include_trade_power, include_trade_details,
                include_military_quality=include_military_quality,
                include_country_loans=include_country_loans,
                include_country_modifiers=include_country_modifiers,
            )
        elif include_military_quality:
            snapshot = _snapshot(
                reader, module_base, country, profile,
                include_monthly_economy, include_trade_income,
                include_home_trade_node, include_trade_power, include_trade_details,
                include_military_quality=True,
            )
        elif include_trade_details:
            snapshot = _snapshot(
                reader,
                module_base,
                country,
                profile,
                include_monthly_economy,
                True,
                include_home_trade_node,
                include_trade_power,
                True,
            )
        elif include_trade_power:
            snapshot = _snapshot(
                reader,
                module_base,
                country,
                profile,
                include_monthly_economy,
                True,
                include_home_trade_node,
                True,
            )
        elif include_home_trade_node:
            snapshot = _snapshot(
                reader,
                module_base,
                country,
                profile,
                include_monthly_economy,
                True,
                True,
            )
        elif include_trade_income:
            snapshot = _snapshot(
                reader,
                module_base,
                country,
                profile,
                include_monthly_economy,
                True,
            )
        elif include_monthly_economy:
            # Keep the established five-argument monthly seam intact.
            snapshot = _snapshot(reader, module_base, country, profile, True)
        else:
            # Keep the established four-argument seam for existing probes and
            # tests that wrap the default power-only snapshot.
            snapshot = _snapshot(reader, module_base, country, profile)
    except Exception as exc:
        result = {
            "status": "unknown", "runtime_code_guard": runtime_guard,
            "read_log": deepcopy(reader.read_log[start:]), "values": None,
            "unknown_reason": f"snapshot_failed:{type(exc).__name__}:{exc}",
        }
        if include_monthly_economy:
            result["monthly_economy"] = _monthly.retract_record(
                None, f"snapshot_failed:{type(exc).__name__}:{exc}"
            )
        if include_trade_income:
            from . import trade_income_memory as _trade
            result["trade_income"] = _trade.retract_record(
                None, f"snapshot_failed:{type(exc).__name__}:{exc}"
            )
        if include_home_trade_node:
            from . import home_trade_node_memory as _home
            result["home_trade_node"] = _home.retract_record(
                None, f"snapshot_failed:{type(exc).__name__}:{exc}"
            )
        if include_trade_power:
            from . import trade_power_memory as _power
            result["trade_power"] = _power.retract_record(
                None, f"snapshot_failed:{type(exc).__name__}:{exc}"
            )
        _retract_trade_power_sum(
            result,
            f"snapshot_failed:{type(exc).__name__}:{exc}",
            enabled=include_trade_power_sum,
        )
        _retract_trade_income_calculation(
            result,
            f"snapshot_failed:{type(exc).__name__}:{exc}",
            enabled=trade_income_node_id is not None,
        )
        if include_trade_details:
            from . import trade_details_memory as _details
            result["trade_details"] = _details.retract_record(
                None, f"snapshot_failed:{type(exc).__name__}:{exc}"
            )
        if include_military_quality:
            from . import military_quality_memory as _military
            result["military_quality"] = _military.retract_record(
                None, f"snapshot_failed:{type(exc).__name__}:{exc}"
            )
            from . import military_tradition_memory as _tradition
            result["military_tradition"] = _tradition.retract_record(
                None, f"snapshot_failed:{type(exc).__name__}:{exc}"
            )
            from . import military_effective_memory as _effective
            result["military_effective"] = _effective.retract_record(
                None, f"snapshot_failed:{type(exc).__name__}:{exc}"
            )
            from . import military_morale_memory as _morale
            result["military_morale"] = _morale.retract_record(
                None, f"snapshot_failed:{type(exc).__name__}:{exc}"
            )
            from . import military_professionalism_memory as _professionalism
            result["military_professionalism"] = _professionalism.retract_record(
                None, f"snapshot_failed:{type(exc).__name__}:{exc}"
            )
        _retract_country_records(result, f"snapshot_failed:{type(exc).__name__}:{exc}",
                                 include_country_loans=include_country_loans,
                                 include_country_modifiers=include_country_modifiers)
        return result
    snapshot["runtime_code_guard"] = runtime_guard
    snapshot["read_log"] = deepcopy(reader.read_log[start:])
    return snapshot


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


def _compare_snapshot(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    result = {
        "status": snapshot.get("status"),
        "runtime_code_guard": snapshot.get("runtime_code_guard"),
        "game_pointer": snapshot.get("game_pointer"),
        "database_pointer": snapshot.get("database_pointer"),
        "game_date": snapshot.get("game_date"),
        "country_scan": snapshot.get("country_scan"),
        "values": snapshot.get("values"),
        "value_raw_hex": snapshot.get("value_raw_hex"),
        "read_log": snapshot.get("read_log"),
    }
    if "monthly_economy" in snapshot:
        result["monthly_economy"] = snapshot.get("monthly_economy")
    if "trade_income" in snapshot:
        result["trade_income"] = snapshot.get("trade_income")
    if "home_trade_node" in snapshot:
        result["home_trade_node"] = snapshot.get("home_trade_node")
    if "trade_power" in snapshot:
        result["trade_power"] = snapshot.get("trade_power")
    if "trade_power_sum" in snapshot:
        result["trade_power_sum"] = snapshot.get("trade_power_sum")
    if "trade_income_calculation" in snapshot:
        result["trade_income_calculation"] = snapshot.get("trade_income_calculation")
    if "trade_details" in snapshot:
        result["trade_details"] = snapshot.get("trade_details")
    if "military_quality" in snapshot:
        result["military_quality"] = snapshot.get("military_quality")
    if "military_tradition" in snapshot:
        result["military_tradition"] = snapshot.get("military_tradition")
    if "military_effective" in snapshot:
        result["military_effective"] = snapshot.get("military_effective")
    if "military_morale" in snapshot:
        result["military_morale"] = snapshot.get("military_morale")
    if "military_professionalism" in snapshot:
        result["military_professionalism"] = snapshot.get("military_professionalism")
    for key in ("country_loans", "country_modifiers"):
        if key in snapshot:
            result[key] = snapshot.get(key)
    return _time.without_clock(result, date_labels=('game.game_date',))


def _base_report(
    installation: Path,
    country: str,
    include_monthly_economy: bool = False,
    include_trade_income: bool = False,
    include_home_trade_node: bool = False,
    include_trade_power: bool = False,
    include_trade_details: bool = False,
    include_military_quality: bool = False,
    include_country_loans: bool = False,
    include_country_modifiers: bool = False,
    include_trade_power_sum: bool = False,
    trade_income_node_id: str | None = None,
) -> dict[str, Any]:
    captured_at_utc = datetime.now(timezone.utc).isoformat()
    result = {
        "probe": "information-country-resources-runtime",
        "probe_version": 1,
        "probe_script": str(Path(__file__).resolve()),
        "probe_script_sha256": None,
        "profile": {"path": str(PROFILE_FILE), "sha256": EXPECTED_PROFILE_SHA256, "max_bytes": PROFILE_MAX_BYTES},
        "read_only": True,
        "native_function_invoked": False,
        "evidence_kind": "pure_runtime_observation_not_static_evidence",
        "captured_at": captured_at_utc,
        "captured_at_utc": captured_at_utc,
        "request": {"installation": str(installation), "country": country},
        "country": country,
        "target_build": {"version": EXPECTED_VERSION, "expected_exe_sha256": EXPECTED_EXE_SHA256},
        "static_contract_guard": None,
        "file_code_guard": None,
        "runtime_code_guard": None,
        "identity": {
            "installation_path": str(installation), "installation_pid": None,
            "installation_creation_filetime": None, "installation_session_id": None,
            "process_path": None, "process_path_sha256": None,
            "process_path_sha256_matches_expected": None, "process_creation_filetime": None,
            "process_creation_utc": None, "process_creation_matches_installation": None,
            "module_path": None, "module_path_matches_process": None,
            "binding_verified": False,
        },
        "module_base": None,
        "before": None,
        "after": None,
        "doublepass": {
            "performed": False,
            "consistent": None,
            "mismatches": [],
            "atomic": False,
            "atomic_main_thread_snapshot": False,
        },
        "world_generation_verified": False,
        "values": None,
        "unit": "monarch_points",
        "scale": 1,
        "access": {
            "open_process_mask": "QUERY_INFORMATION|VM_READ",
            "open_process_mask_hex": _hex(PROCESS_ACCESS),
            "rpm_total_limit": MAX_TOTAL_RPM, "rpm_single_read_limit": MAX_SINGLE_RPM,
            "rpm_bytes_requested": 0, "rpm_calls": 0,
            "native_game_calls": False, "target_memory_writes": False,
            "dll_injection": False, "private_heap_scan": False, "ui_control": False,
            "date_advance": False, "save_or_reload": False,
        },
        "cleanup": {"handle_close": {"status": "unknown", "success": None, "closed": False}},
        "status": "starting", "errors": [], "completed": False,
    }
    if include_monthly_economy is True:
        result["request"]["include_monthly_economy"] = True
        result["monthly_economy"] = None
    if include_trade_income is True:
        result["request"]["include_trade_income"] = True
        result["trade_income"] = None
    if include_home_trade_node is True:
        result["request"]["include_home_trade_node"] = True
        result["home_trade_node"] = None
    if include_trade_power is True:
        result["request"]["include_trade_power"] = True
        result["trade_power"] = None
    if include_trade_power_sum is True:
        result["request"]["include_trade_power_sum"] = True
        result["trade_power_sum"] = None
    if trade_income_node_id is not None:
        result["request"]["trade_income_node_id"] = (
            trade_income_node_id if type(trade_income_node_id) is str else None
        )
        result["trade_income_calculation"] = None
    if include_trade_details is True:
        result["request"]["include_trade_details"] = True
        result["trade_details"] = None
    if include_military_quality is True:
        result["request"]["include_military_quality"] = True
        result["military_quality"] = None
        result["military_tradition"] = None
        result["military_effective"] = None
        result["military_morale"] = None
        result["military_professionalism"] = None
    for enabled, key in ((include_country_loans, "country_loans"),
                         (include_country_modifiers, "country_modifiers")):
        if enabled is True:
            result["request"][f"include_{key}"] = True
            result[key] = None
    return result


def _retract(report: dict[str, Any]) -> None:
    report["values"] = None
    _retract_country_records(report, "observation_retracted")
    if "military_quality" in report:
        from . import military_quality_memory as _military
        report["military_quality"] = _military.retract_record(
            report.get("military_quality"), "observation_retracted"
        )
    if "military_tradition" in report:
        from . import military_tradition_memory as _tradition
        report["military_tradition"] = _tradition.retract_record(
            report.get("military_tradition"), "observation_retracted"
        )
    if "military_effective" in report:
        from . import military_effective_memory as _effective
        report["military_effective"] = _effective.retract_record(
            report.get("military_effective"), "observation_retracted"
        )
    if "military_morale" in report:
        from . import military_morale_memory as _morale
        report["military_morale"] = _morale.retract_record(
            report.get("military_morale"), "observation_retracted"
        )
    if "military_professionalism" in report:
        from . import military_professionalism_memory as _professionalism
        report["military_professionalism"] = _professionalism.retract_record(
            report.get("military_professionalism"), "observation_retracted"
        )
    if "monthly_economy" in report:
        report["monthly_economy"] = _monthly.retract_record(
            report.get("monthly_economy"), "observation_retracted"
        )
    if "trade_income" in report:
        from . import trade_income_memory as _trade
        report["trade_income"] = _trade.retract_record(
            report.get("trade_income"), "observation_retracted"
        )
    if "home_trade_node" in report:
        from . import home_trade_node_memory as _home
        report["home_trade_node"] = _home.retract_record(
            report.get("home_trade_node"), "observation_retracted"
        )
    if "trade_power" in report:
        from . import trade_power_memory as _power
        report["trade_power"] = _power.retract_record(
            report.get("trade_power"), "observation_retracted"
        )
    _retract_trade_power_sum(report, "observation_retracted")
    _retract_trade_income_calculation(report, "observation_retracted")
    if "trade_details" in report:
        from . import trade_details_memory as _details
        report["trade_details"] = _details.retract_record(
            report.get("trade_details"), "observation_retracted"
        )
    for key in ("before", "after"):
        if isinstance(report.get(key), dict):
            report[key]["values"] = None
            _retract_country_records(report[key], "observation_retracted")
            if "military_quality" in report[key]:
                from . import military_quality_memory as _military
                report[key]["military_quality"] = _military.retract_record(
                    report[key].get("military_quality"), "observation_retracted"
                )
            if "military_tradition" in report[key]:
                from . import military_tradition_memory as _tradition
                report[key]["military_tradition"] = _tradition.retract_record(
                    report[key].get("military_tradition"), "observation_retracted"
                )
            if "military_effective" in report[key]:
                from . import military_effective_memory as _effective
                report[key]["military_effective"] = _effective.retract_record(
                    report[key].get("military_effective"), "observation_retracted"
                )
            if "military_morale" in report[key]:
                from . import military_morale_memory as _morale
                report[key]["military_morale"] = _morale.retract_record(
                    report[key].get("military_morale"), "observation_retracted"
                )
            if "military_professionalism" in report[key]:
                from . import military_professionalism_memory as _professionalism
                report[key]["military_professionalism"] = _professionalism.retract_record(
                    report[key].get("military_professionalism"), "observation_retracted"
                )
            if "monthly_economy" in report[key]:
                report[key]["monthly_economy"] = _monthly.retract_record(
                    report[key].get("monthly_economy"), "observation_retracted"
                )
            if "trade_income" in report[key]:
                from . import trade_income_memory as _trade
                report[key]["trade_income"] = _trade.retract_record(
                    report[key].get("trade_income"), "observation_retracted"
                )
            if "home_trade_node" in report[key]:
                from . import home_trade_node_memory as _home
                report[key]["home_trade_node"] = _home.retract_record(
                    report[key].get("home_trade_node"), "observation_retracted"
                )
            if "trade_power" in report[key]:
                from . import trade_power_memory as _power
                report[key]["trade_power"] = _power.retract_record(
                    report[key].get("trade_power"), "observation_retracted"
                )
            _retract_trade_power_sum(report[key], "observation_retracted")
            _retract_trade_income_calculation(report[key], "observation_retracted")
            if "trade_details" in report[key]:
                from . import trade_details_memory as _details
                report[key]["trade_details"] = _details.retract_record(
                    report[key].get("trade_details"), "observation_retracted"
                )


def _apply_cleanup(report: dict[str, Any], kernel: Any, handle: Any) -> None:
    outcome = _close_process_handle(kernel, handle)
    report["cleanup"]["handle_close"] = outcome
    if outcome.get("status") == "error":
        previous = report.get("status")
        report["status"] = "cleanup_error"
        report["errors"].append({
            "stage": "cleanup", "status": "error",
            "error": outcome.get("error", "CloseHandle failed"),
            "previous_status": previous,
        })
        _retract(report)
    report["completed"] = report.get("status") == "observed" and outcome.get("status") == "closed"
    if not report["completed"]:
        _retract(report)


def capture(
    installation: Path,
    country: str,
    *,
    include_monthly_economy: bool = False,
    include_trade_income: bool = False,
    include_home_trade_node: bool = False,
    include_trade_power: bool = False,
    include_trade_details: bool = False,
    include_military_quality: bool = False,
    include_country_loans: bool = False,
    include_country_modifiers: bool = False,
    include_trade_power_sum: bool = False,
    trade_income_node_id: str | None = None,
) -> dict[str, Any]:
    """Capture one bounded two-pass observation without writing files."""
    installation = Path(installation)
    military_options = {"include_military_quality": True} if include_military_quality is True else {}
    for option, enabled in (("include_country_loans", include_country_loans),
                            ("include_country_modifiers", include_country_modifiers)):
        if enabled is True:
            military_options[option] = True
    report_options = dict(military_options)
    if include_trade_power_sum is True:
        report_options["include_trade_power_sum"] = True
    if trade_income_node_id is not None:
        report_options["trade_income_node_id"] = trade_income_node_id
    report = _base_report(
        installation,
        country,
        include_monthly_economy,
        include_trade_income,
        include_home_trade_node,
        include_trade_power,
        include_trade_details,
        **report_options,
    )
    for option, enabled in (("include_country_loans", include_country_loans),
                            ("include_country_modifiers", include_country_modifiers)):
        if type(enabled) is not bool:
            report["status"] = "invalid_request"
            report["errors"].append({"stage": "request", "status": "unknown",
                                     "error": f"{option}_must_be_bool"})
            _apply_cleanup(report, None, None)
            return report
    if type(include_military_quality) is not bool:
        report["status"] = "invalid_request"
        report["errors"].append({
            "stage": "request", "status": "unknown",
            "error": "include_military_quality_must_be_bool",
        })
        _apply_cleanup(report, None, None)
        return report
    if type(include_monthly_economy) is not bool:
        report["status"] = "invalid_request"
        report["errors"].append({
            "stage": "request",
            "status": "unknown",
            "error": "include_monthly_economy_must_be_bool",
        })
        _apply_cleanup(report, None, None)
        return report
    if type(include_trade_income) is not bool:
        report["status"] = "invalid_request"
        report["errors"].append({
            "stage": "request",
            "status": "unknown",
            "error": "include_trade_income_must_be_bool",
        })
        _apply_cleanup(report, None, None)
        return report
    if type(include_home_trade_node) is not bool:
        report["status"] = "invalid_request"
        report["errors"].append({
            "stage": "request",
            "status": "unknown",
            "error": "include_home_trade_node_must_be_bool",
        })
        _apply_cleanup(report, None, None)
        return report
    if type(include_trade_power) is not bool:
        report["status"] = "invalid_request"
        report["errors"].append({
            "stage": "request",
            "status": "unknown",
            "error": "include_trade_power_must_be_bool",
        })
        _apply_cleanup(report, None, None)
        return report
    if type(include_trade_power_sum) is not bool:
        report["status"] = "invalid_request"
        report["errors"].append({
            "stage": "request",
            "status": "unknown",
            "error": "include_trade_power_sum_must_be_bool",
        })
        _apply_cleanup(report, None, None)
        return report
    if type(include_trade_details) is not bool:
        report["status"] = "invalid_request"
        report["errors"].append({
            "stage": "request",
            "status": "unknown",
            "error": "include_trade_details_must_be_bool",
        })
        _apply_cleanup(report, None, None)
        return report
    if trade_income_node_id is not None and (
        type(trade_income_node_id) is not str
        or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", trade_income_node_id) is None
        or trade_income_node_id.casefold() == "null"
    ):
        report["status"] = "invalid_request"
        report["errors"].append({
            "stage": "request", "status": "unknown",
            "error": "trade_income_node_id_invalid",
        })
        _apply_cleanup(report, None, None)
        return report
    if include_home_trade_node and not include_trade_income:
        report["status"] = "invalid_request"
        report["errors"].append({
            "stage": "request",
            "status": "unknown",
            "error": "include_home_trade_node_requires_include_trade_income",
        })
        _apply_cleanup(report, None, None)
        return report
    if include_trade_power and not include_trade_income:
        report["status"] = "invalid_request"
        report["errors"].append({
            "stage": "request",
            "status": "unknown",
            "error": "include_trade_power_requires_include_trade_income",
        })
        _apply_cleanup(report, None, None)
        return report
    if include_trade_power_sum and not include_trade_income:
        report["status"] = "invalid_request"
        report["errors"].append({
            "stage": "request",
            "status": "unknown",
            "error": "include_trade_power_sum_requires_include_trade_income",
        })
        _apply_cleanup(report, None, None)
        return report
    if include_trade_power_sum and not include_trade_power:
        report["status"] = "invalid_request"
        report["errors"].append({
            "stage": "request",
            "status": "unknown",
            "error": "include_trade_power_sum_requires_include_trade_power",
        })
        _apply_cleanup(report, None, None)
        return report
    if trade_income_node_id is not None:
        for option, enabled in (
            ("include_trade_income", include_trade_income),
            ("include_trade_power", include_trade_power),
            ("include_trade_power_sum", include_trade_power_sum),
        ):
            if enabled is not True:
                report["status"] = "invalid_request"
                report["errors"].append({
                    "stage": "request", "status": "unknown",
                    "error": f"trade_income_node_id_requires_{option}",
                })
                _apply_cleanup(report, None, None)
                return report
    if include_trade_details and not include_trade_income:
        report["status"] = "invalid_request"
        report["errors"].append({
            "stage": "request",
            "status": "unknown",
            "error": "include_trade_details_requires_include_trade_income",
        })
        _apply_cleanup(report, None, None)
        return report
    try:
        report["probe_script_sha256"] = _sha256_file(Path(__file__).resolve())
    except OSError as exc:
        report["errors"].append({"stage": "probe_identity", "status": "unknown", "error": str(exc)})
    if country != EXPECTED_COUNTRY:
        report["status"] = "unsupported_country"
        report["errors"].append({"stage": "request", "status": "unknown", "error": "Only FRA is permitted"})
        _apply_cleanup(report, None, None)
        return report

    contract = _static_contract_guard()
    report["static_contract_guard"] = contract
    if contract.get("status") != "observed":
        report["status"] = "static_contract_mismatch"
        report["errors"].append({"stage": "static_contract", "status": "unknown", "error": "Country-resource profile or dependencies did not match"})
        _apply_cleanup(report, None, None)
        return report

    kernel = None
    handle = None
    reader: AddressBoundedRPM | None = None
    try:
        profile = _active_profile()
        document = _load_installation(installation)
        pid = _parse_int(document.get("pid"), "installation.pid")
        kernel = _configure_kernel()
        handle = kernel.OpenProcess(PROCESS_ACCESS, False, pid)
        if not handle:
            raise C.WinError(C.get_last_error())
        module_base = _capture_identity(report, document, kernel, handle)
        report["module_base"] = _address(module_base)
        process_path = Path(report["identity"]["process_path"])
        report["file_code_guard"] = _file_code_guard(process_path)
        if report["file_code_guard"].get("status") != "observed":
            report["status"] = "file_code_mismatch"
            report["errors"].append({"stage": "file_code_guard", "status": "unknown", "error": "Profile code bytes did not match executable"})
        else:
            reader = AddressBoundedRPM(kernel, handle, module_base)
            start = len(reader.read_log)
            pass_options = dict(military_options)
            if include_trade_power_sum is True:
                pass_options["include_trade_power_sum"] = True
            if trade_income_node_id is not None:
                pass_options["trade_income_node_id"] = trade_income_node_id
            before = _pass(
                reader, module_base, country, profile, start,
                include_monthly_economy, include_trade_income, include_home_trade_node, include_trade_power,
                include_trade_details,
                **pass_options,
            )
            report["before"] = before
            if before.get("status") != "observed":
                report["status"] = "unknown"
                report["errors"].append({"stage": "before", "status": "unknown", "error": before.get("unknown_reason", "first_pass_unknown")})
            else:
                start = len(reader.read_log)
                after = _pass(
                    reader, module_base, country, profile, start,
                    include_monthly_economy, include_trade_income, include_home_trade_node, include_trade_power,
                    include_trade_details,
                    **pass_options,
                )
                report["after"] = after
                report["doublepass"]["performed"] = True
                if after.get("status") != "observed":
                    report["doublepass"]["mismatches"] = ["$.after.status"]
                    report["doublepass"]["consistent"] = False
                    report["status"] = "doublepass_mismatch"
                    report["errors"].append({"stage": "doublepass", "status": "unknown", "error": after.get("unknown_reason", "second_pass_unknown")})
                else:
                    mismatch = _diff_paths(_compare_snapshot(before), _compare_snapshot(after))
                    if not _time.dates_match(before['game_date']['value'], after['game_date']['value']):
                        mismatch.append('$.game_date')
                    report["doublepass"]["mismatches"] = mismatch[:256]
                    report["doublepass"]["consistent"] = not mismatch
                    if mismatch:
                        report["status"] = "doublepass_mismatch"
                        report["errors"].append({"stage": "doublepass", "status": "unknown", "error": "Runtime read logs, guards, identity, date or values changed", "paths": mismatch[:256]})
                    else:
                        report["status"] = "observed"
                        report["values"] = deepcopy(after.get("values"))
                        if include_monthly_economy:
                            report["monthly_economy"] = deepcopy(after.get("monthly_economy"))
                        if include_trade_income:
                            report["trade_income"] = deepcopy(after.get("trade_income"))
                        if include_home_trade_node:
                            report["home_trade_node"] = deepcopy(after.get("home_trade_node"))
                        if include_trade_power:
                            report["trade_power"] = deepcopy(after.get("trade_power"))
                        if include_trade_power_sum:
                            report["trade_power_sum"] = deepcopy(after.get("trade_power_sum"))
                        if trade_income_node_id is not None:
                            report["trade_income_calculation"] = deepcopy(
                                after.get("trade_income_calculation")
                            )
                        if include_trade_details:
                            report["trade_details"] = deepcopy(after.get("trade_details"))
                        if include_military_quality:
                            report["military_quality"] = deepcopy(after.get("military_quality"))
                            report["military_tradition"] = deepcopy(after.get("military_tradition"))
                            report["military_effective"] = deepcopy(after.get("military_effective"))
                            report["military_morale"] = deepcopy(after.get("military_morale"))
                            report["military_professionalism"] = deepcopy(after.get("military_professionalism"))
                        for enabled, key in ((include_country_loans, "country_loans"),
                                             (include_country_modifiers, "country_modifiers")):
                            if enabled:
                                report[key] = deepcopy(after.get(key))
            report["runtime_code_guard"] = {
                "status": "observed" if all(
                    isinstance(item.get("runtime_code_guard"), Mapping)
                    and item["runtime_code_guard"].get("status") == "observed"
                    for item in (report.get("before") or {}, report.get("after") or {})
                    if item
                ) and report.get("after") is not None else "unknown",
                "passes": [
                    (report.get("before") or {}).get("runtime_code_guard"),
                    (report.get("after") or {}).get("runtime_code_guard"),
                ],
            }
            report["access"]["rpm_bytes_requested"] = reader.bytes_requested
            report["access"]["rpm_calls"] = reader.calls
    except Exception as exc:
        report["status"] = "error"
        report["errors"].append({"stage": "capture", "status": "unknown", "error": f"{type(exc).__name__}:{exc}"})
    finally:
        if reader is not None:
            report["access"]["rpm_bytes_requested"] = reader.bytes_requested
            report["access"]["rpm_calls"] = reader.calls
    _apply_cleanup(report, kernel, handle)
    return report


__all__ = [
    "AddressBoundedRPM", "PROFILE_FILE", "PROFILE_MAX_BYTES", "EXPECTED_PROFILE_SHA256",
    "EXPECTED_EXE_SHA256", "MAX_SINGLE_RPM", "MAX_TOTAL_RPM", "MAX_USER_ADDRESS",
    "ProfileError", "ProbeError", "capture", "_load_profile", "_static_contract_guard",
    "_profile_code_guards", "_file_code_guard", "_runtime_code_guard", "_snapshot",
]
