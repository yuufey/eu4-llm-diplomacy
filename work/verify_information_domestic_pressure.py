"""核验第十批 N04 国内压力证据。

本脚本只读取工作区内的有界 JSON、源码和 profile，不连接游戏进程，也不
调用原生查询。所有运行时、存档、MCP 和测试材料必须有明确路径与 SHA-256；
缺少任何一项时整批失败关闭。它不会递归读取或复制历史归档。
"""
from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import py_compile
import re
import sys
import tempfile
from typing import Any, Mapping


ROOT = Path(__file__).resolve().parents[1]
ROOT_RESOLVED = ROOT.resolve()
DEFAULT_STAGE = ROOT / "work/runtime/information-domestic-pressure-20261025-001"
MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_PROFILE_BYTES = 64 * 1024
MAX_OUTPUT_BYTES = 16 * 1024 * 1024
MAX_ARCHIVE_TOTAL_BYTES = 128 * 1024 * 1024
EXPECTED_VERSION = "1.37.4"
EXPECTED_COUNTRY = "FRA"
EXPECTED_EXE_SHA = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
EXPECTED_SESSION = "37376-1dd639fff00a820"
EXPECTED_CREATION_FILETIME = 134373102720165920
EXPECTED_GAME_DATE = 56553384
FIELDS = ("stability", "war_exhaustion", "corruption")
UNITS = {
    "stability": "stability",
    "war_exhaustion": "war_exhaustion",
    "corruption": "corruption",
}
# This is the catalog shape required after the effective N04 correction.  The
# sixth N04 field, religious_unity, remains a planned catalog entry and is
# intentionally absent from FIELDS/UNITS and all current runtime/save checks.
EXPECTED_CATALOG = {
    "topic_count": 74,
    "field_count": 397,
    "available_topic_count": 35,
    "field_counts": {"available": 51, "partial": 107, "planned": 239},
}
EXPECTED_CURRENT_CONTRACT_ID = "native-domestic-pressure-contract-003"
EXPECTED_EXCLUDED_FIELD = "religious_unity"
EXPECTED_PROFILE_EXCLUSION_REASON = "EE0_is_province_component_not_effective_unity"
EXPECTED_CONTRACT_EXCLUSION_REASON = (
    "The native getter labels EE0 as RELIG_UNITY_FROM_PROVINCES, adds modifier0xa8 "
    "with a possible callback, handles a special rule and can clamp to1000. "
    "Reading the saved component does not give final current religious unity."
)
BASELINE = ROOT / "work/runtime/information-country-scalars-20261024-001/delivery/manifest.json"
BASELINE_SHA = "01bf780b08d13dab03c5c3de166fa9eb06114063ef5ac895face01a32e5e78b1"
PREVIOUS_BASELINE = ROOT / "work/runtime/information-country-relations-20261024-001/delivery/manifest.json"
PREVIOUS_BASELINE_SHA = "b24cf0c61c56a95e36621d764080a4f9c22025649970c9cfdfafe96927e2e6f7"


class VerificationError(ValueError):
    """输入不满足本批证据合同。"""


@dataclass(frozen=True)
class Paths:
    stage: Path
    profile: Path
    contract: Path
    capture: Path
    native_report: Path
    live_report: Path
    save_crosscheck: Path
    fixture: Path
    test_summary: Path
    baseline: Path


def _resolve(path: Path | str) -> Path:
    candidate = Path(path).expanduser()
    try:
        resolved = candidate.resolve()
    except (OSError, RuntimeError) as exc:
        raise VerificationError(f"path_resolve_failed:{candidate}") from exc
    if not resolved.is_relative_to(ROOT_RESOLVED):
        raise VerificationError(f"path_outside_workspace:{candidate}")
    return resolved


def bounded_file(path: Path | str, *, max_bytes: int = MAX_FILE_BYTES) -> Path:
    resolved = _resolve(path)
    if not resolved.is_file():
        raise VerificationError(f"regular_file_required:{resolved}")
    size = resolved.stat().st_size
    if size > max_bytes:
        raise VerificationError(f"file_over_limit:{resolved}:{size}>{max_bytes}")
    return resolved


def digest(path: Path | str, *, max_bytes: int = MAX_FILE_BYTES) -> str:
    source = bounded_file(path, max_bytes=max_bytes)
    size = source.stat().st_size
    value = hashlib.sha256()
    with source.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    if source.stat().st_size != size:
        raise VerificationError(f"file_changed_during_hash:{source}")
    return value.hexdigest()


def read_json(path: Path | str, *, max_bytes: int = MAX_FILE_BYTES) -> Any:
    source = bounded_file(path, max_bytes=max_bytes)
    size = source.stat().st_size
    try:
        raw = source.read_bytes()
        if len(raw) != size or source.stat().st_size != size:
            raise VerificationError(f"file_changed_during_read:{source}")
        return json.loads(raw.decode("utf-8"))
    except VerificationError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise VerificationError(f"invalid_json:{source}") from exc


def write_json(path: Path | str, value: Any) -> Path:
    destination = _resolve(path)
    raw = (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")
    if len(raw) > MAX_OUTPUT_BYTES:
        raise VerificationError(f"audit_over_limit:{destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(raw)
    return destination


def _mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise VerificationError(f"mapping_required:{label}")
    return value


def _equal(value: Mapping[str, Any], key: str, expected: Any, label: str) -> None:
    if value.get(key) != expected:
        raise VerificationError(f"value_mismatch:{label}.{key}")


def _true(value: Mapping[str, Any], key: str, label: str) -> None:
    if value.get(key) is not True:
        raise VerificationError(f"true_required:{label}.{key}")


def _integer(value: Any, label: str, *, minimum: int | None = None) -> int:
    if type(value) is not int:
        raise VerificationError(f"integer_required:{label}")
    if minimum is not None and value < minimum:
        raise VerificationError(f"integer_below_minimum:{label}")
    return value


def _profile_integer(value: Any, label: str) -> int:
    """Profile layout integers may use the checked-in ``0x...`` spelling."""
    if type(value) is int:
        result = value
    elif isinstance(value, str):
        try:
            result = int(value, 0)
        except ValueError as exc:
            raise VerificationError(f"profile_integer_invalid:{label}") from exc
    else:
        raise VerificationError(f"profile_integer_invalid:{label}")
    if result < 0:
        raise VerificationError(f"profile_integer_negative:{label}")
    return result


def _sha(value: Any, label: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-fA-F]{64}", value) is None:
        raise VerificationError(f"sha256_invalid:{label}")
    return value.lower()


def relative(path: Path | str) -> str:
    return _resolve(path).relative_to(ROOT_RESOLVED).as_posix()


def _require_path(explicit: Path | None, candidates: list[Path], label: str) -> Path:
    if explicit is not None:
        return bounded_file(explicit)
    for candidate in candidates:
        if candidate.is_file():
            return bounded_file(candidate)
    raise VerificationError(f"required_evidence_missing:{label}")


def _load_paths(
    *, stage: Path = DEFAULT_STAGE, profile: Path | None = None, contract: Path | None = None,
    capture: Path | None = None, native_report: Path | None = None, live_report: Path | None = None,
    save_crosscheck: Path | None = None, fixture: Path | None = None,
    test_summary: Path | None = None, baseline: Path | None = None,
) -> Paths:
    stage = _resolve(stage)
    if not stage.is_dir():
        raise VerificationError(f"stage_directory_required:{stage}")
    profile = bounded_file(profile or ROOT / "bridge/information/profiles/domestic-pressure-memory-1374.json", max_bytes=MAX_PROFILE_BYTES)
    profile_obj = read_json(profile, max_bytes=MAX_PROFILE_BYTES)
    if contract is None and isinstance(profile_obj, dict):
        provenance = profile_obj.get("provenance")
        if isinstance(provenance, dict) and isinstance(provenance.get("contract_path"), str):
            contract = ROOT / provenance["contract_path"]
    if contract is None:
        contract = stage / "domestic-pressure-contract-001.json"
    capture = _require_path(capture, [stage / "native-runtime-001/native-capture.json"], "native_capture")
    native_report = _require_path(native_report, [stage / "native-runtime-001/report.json"], "native_report")
    live_report = _require_path(live_report, [stage / "live-acceptance-002/report.json", stage / "live-acceptance-001/report.json"], "live_report")
    save_candidates = (
        sorted(stage.glob("*save*cross*.json"))
        + sorted(stage.glob("save*cross*.json"))
        + [stage / "save-scalars-survey-001.json"]
    )
    save_candidates = list(dict.fromkeys(save_candidates))
    save_crosscheck = _require_path(save_crosscheck, save_candidates, "save_crosscheck")
    fixture = _require_path(fixture, [
        ROOT / "bridge/tests/fixtures/information_domestic_pressure_live_1374.json",
        ROOT / "bridge/tests/fixtures/information_country_domestic_pressure_live_1374.json",
    ], "recorded_fixture")
    test_summary = _require_path(test_summary, [stage / "test-summary.json"], "test_summary")
    baseline = bounded_file(baseline or BASELINE)
    return Paths(stage, profile, bounded_file(contract), capture, native_report, live_report,
                 save_crosscheck, fixture, test_summary, baseline)


def _record(path: Path, *, role: str, expected: str | None = None,
            max_bytes: int = MAX_FILE_BYTES) -> dict[str, Any]:
    actual = digest(path, max_bytes=max_bytes)
    if expected is not None and actual != _sha(expected, f"{role}.sha256"):
        raise VerificationError(f"source_pin_changed:{relative(path)}")
    return {"path": relative(path), "bytes": path.stat().st_size, "sha256": actual, "role": role}


def _path_record(value: Any, label: str, *, default_role: str) -> tuple[str, str, str, int | None] | None:
    if not isinstance(value, dict):
        return None
    path = value.get("path")
    expected = value.get("sha256", value.get("sha"))
    if not isinstance(path, str) or not isinstance(expected, str):
        return None
    role = value.get("role", default_role)
    if not isinstance(role, str) or not role:
        role = default_role
    declared = value.get("bytes")
    if declared is not None and type(declared) is not int:
        raise VerificationError(f"reference_bytes_invalid:{label}")
    return path, _sha(expected, label), role, declared


def _profile_refs(profile: Mapping[str, Any]) -> list[dict[str, Any]]:
    refs: list[dict[str, Any]] = []
    seen: dict[str, str] = {}

    def legacy_source(name: str, expected: str, label: str) -> None:
        # The oldest mission profile stores only a basename -> SHA map.  Its
        # frozen directory is explicit; do not search the whole workspace.
        candidates = [
            ROOT / "work/runtime/information-missions-20261024-001" / name,
            ROOT / "work/runtime/information-loaded-tasks-20261024-001" / name,
            ROOT / "work/runtime/information-branches-20261024-001" / name,
        ]
        matches = [candidate for candidate in candidates if candidate.is_file() and digest(candidate) == expected]
        if len(matches) != 1:
            raise VerificationError(f"legacy_profile_reference_unresolved:{label}")
        path = matches[0]
        refs.append({"path": relative(path), "sha256": expected, "bytes": path.stat().st_size,
                     "role": "legacy profile source evidence"})

    def collect(value: Any, label: str, role: str) -> None:
        record = _path_record(value, label, default_role=role)
        if record is not None:
            raw_path, expected, item_role, declared = record
            path = bounded_file(ROOT / raw_path)
            actual = digest(path)
            if actual != expected:
                raise VerificationError(f"profile_reference_changed:{raw_path}")
            if declared is not None and declared != path.stat().st_size:
                raise VerificationError(f"profile_reference_size_changed:{raw_path}")
            if raw_path in seen:
                if seen[raw_path] != actual:
                    raise VerificationError(f"profile_reference_conflict:{raw_path}")
            else:
                seen[raw_path] = actual
            refs.append({"path": relative(path), "sha256": actual, "bytes": path.stat().st_size,
                         "role": item_role})
            return
        if isinstance(value, list):
            for index, item in enumerate(value):
                collect(item, f"{label}[{index}]", role)
        elif isinstance(value, dict):
            for key, item in value.items():
                if key in {"dependencies", "source_evidence", "evidence", "references", "files"}:
                    collect(item, f"{label}.{key}", role)
                elif isinstance(item, (dict, list)):
                    collect(item, f"{label}.{key}", role)

    provenance = profile.get("provenance")
    if provenance is None:
        provenance = {}
    if not isinstance(provenance, dict):
        raise VerificationError("profile_provenance_invalid")
    collect(provenance.get("dependencies"), "provenance.dependencies", "profile dependency")
    collect(profile.get("source_evidence"), "source_evidence", "static evidence")
    collect(provenance.get("source_evidence"), "provenance.source_evidence", "static evidence")
    source_evidence = profile.get("source_evidence")
    if isinstance(source_evidence, dict):
        for name, value in source_evidence.items():
            if isinstance(value, str) and re.fullmatch(r"[0-9a-fA-F]{64}", value):
                legacy_source(name, value.lower(), f"source_evidence.{name}")
    if not refs:
        raise VerificationError("profile_dependencies_missing")
    return refs


def _profile_guard_specs(profile: Mapping[str, Any], label: str) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    """Validate the N04 profile's byte guards and save-token names.

    The profile is a compact declaration, so the verifier recomputes every
    declared guard digest and derives the expected bytes from its hex field.
    This keeps the later runtime checks tied to the exact profile rather than
    trusting a report's names or ``consistent`` flag.
    """
    raw_guards = profile.get("code_guards")
    if not isinstance(raw_guards, list) or len(raw_guards) != 11:
        raise VerificationError(f"profile_code_guard_count_changed:{label}")
    guards: dict[str, dict[str, Any]] = {}
    for index, item in enumerate(raw_guards):
        guard = _mapping(item, f"{label}.code_guards[{index}]")
        name = guard.get("name")
        if not isinstance(name, str) or not name or name in guards:
            raise VerificationError(f"profile_code_guard_name_invalid:{label}:{index}")
        raw_hex = guard.get("hex", guard.get("bytes"))
        if not isinstance(raw_hex, str) or re.fullmatch(r"[0-9a-fA-F]+", raw_hex) is None or len(raw_hex) % 2:
            raise VerificationError(f"profile_code_guard_hex_invalid:{label}:{name}")
        try:
            expected_bytes = bytes.fromhex(raw_hex)
        except ValueError as exc:
            raise VerificationError(f"profile_code_guard_hex_invalid:{label}:{name}") from exc
        size = _profile_integer(guard.get("size"), f"{label}.code_guards.{name}.size")
        rva = _profile_integer(guard.get("rva"), f"{label}.code_guards.{name}.rva")
        end = _profile_integer(guard.get("end_rva_exclusive"), f"{label}.code_guards.{name}.end_rva_exclusive")
        if size != len(expected_bytes) or end != rva + size:
            raise VerificationError(f"profile_code_guard_range_invalid:{label}:{name}")
        expected_sha = _sha(guard.get("sha256"), f"{label}.code_guards.{name}.sha256")
        actual_sha = hashlib.sha256(expected_bytes).hexdigest()
        if expected_sha != actual_sha:
            raise VerificationError(f"profile_code_guard_sha_invalid:{label}:{name}")
        guards[name] = {
            "name": name, "rva": rva, "size": size,
            "expected_sha256": expected_sha,
            "expected_bytes": expected_bytes,
        }

    raw_tokens = _mapping(profile.get("save_tokens"), f"{label}.save_tokens")
    _profile_integer(raw_tokens.get("vector_rva"), f"{label}.save_tokens.vector_rva")
    token_map = _mapping(raw_tokens.get("tokens"), f"{label}.save_tokens.tokens")
    if set(token_map) != set(FIELDS):
        raise VerificationError(f"profile_save_token_field_set_changed:{label}")
    tokens: dict[str, dict[str, Any]] = {}
    for field in FIELDS:
        token = _mapping(token_map[field], f"{label}.save_tokens.tokens.{field}")
        key_id = _integer(token.get("key_id"), f"{label}.save_tokens.tokens.{field}.key_id", minimum=0)
        if token.get("name") != field:
            raise VerificationError(f"profile_save_token_name_changed:{label}:{field}")
        tokens[field] = {"key_id": key_id, "name": field}
    return guards, tokens


def validate_profile(paths: Paths) -> dict[str, Any]:
    profile = _mapping(read_json(paths.profile, max_bytes=MAX_PROFILE_BYTES), "domestic profile")
    profile_sha = digest(paths.profile, max_bytes=MAX_PROFILE_BYTES)
    _equal(profile, "profile_id", "domestic-pressure-memory-1374", "domestic profile")
    _equal(profile, "game_version", EXPECTED_VERSION, "domestic profile")
    executable = _mapping(profile.get("executable"), "domestic profile executable")
    _equal(executable, "sha256", EXPECTED_EXE_SHA, "domestic profile executable")
    country = _mapping(profile.get("country"), "domestic profile country")
    _equal(country, "supported_country", EXPECTED_COUNTRY, "domestic profile country")
    scalars = _mapping(profile.get("scalars"), "domestic profile scalars")
    if set(scalars) != set(FIELDS):
        raise VerificationError("domestic_profile_scalar_set_changed")
    scalar_meta: dict[str, Any] = {}
    for field in FIELDS:
        item = _mapping(scalars[field], f"profile.scalars.{field}")
        _profile_integer(item.get("offset"), f"profile.scalars.{field}.offset")
        _equal(item, "width", 4, f"profile.scalars.{field}")
        _true(item, "signed", f"profile.scalars.{field}")
        _equal(item, "scale", 1000, f"profile.scalars.{field}")
        if item.get("unit") != UNITS[field]:
            raise VerificationError(f"domestic_profile_unit_changed:{field}")
        scalar_meta[field] = {k: item[k] for k in ("offset", "width", "signed", "scale", "unit")}
    guard_specs, token_specs = _profile_guard_specs(profile, "domestic-pressure-memory-1374")
    refs = _profile_refs(profile)
    provenance = _mapping(profile.get("provenance"), "domestic profile provenance")
    contract_path = provenance.get("contract_path")
    contract_sha = provenance.get("contract_sha256")
    if not isinstance(contract_path, str) or not isinstance(contract_sha, str):
        raise VerificationError("profile_contract_reference_missing")
    if profile.get("contract_sha256") is not None and profile.get("contract_sha256") != contract_sha:
        raise VerificationError("profile_contract_sha_mismatch")
    if _resolve(paths.contract) != _resolve(ROOT / contract_path):
        raise VerificationError("contract_path_mismatch")
    contract_record = _record(paths.contract, role="native contract", expected=contract_sha)
    contract = _mapping(read_json(paths.contract, max_bytes=MAX_FILE_BYTES), "native contract")
    _equal(contract, "contract_id", EXPECTED_CURRENT_CONTRACT_ID, "native contract")
    contract_fields = _mapping(contract.get("fields"), "native contract fields")
    if set(contract_fields) != set(FIELDS):
        raise VerificationError("native_contract_field_set_changed")
    profile_excluded = profile.get("excluded_fields")
    if profile_excluded != {EXPECTED_EXCLUDED_FIELD: EXPECTED_PROFILE_EXCLUSION_REASON}:
        raise VerificationError("domestic_profile_exclusion_reason_changed")
    contract_excluded = _mapping(contract.get("excluded_fields"), "native contract excluded_fields")
    unity_exclusion = _mapping(contract_excluded.get(EXPECTED_EXCLUDED_FIELD),
                               "native contract excluded_fields.religious_unity")
    _equal(unity_exclusion, "status", "not_implemented", "native contract religious_unity exclusion")
    _equal(unity_exclusion, "country_offset_0xee0", "province_component_only",
           "native contract religious_unity exclusion")
    _equal(unity_exclusion, "reason", EXPECTED_CONTRACT_EXCLUSION_REASON,
           "native contract religious_unity exclusion")
    return {"path": relative(paths.profile), "sha256": profile_sha, "bytes": paths.profile.stat().st_size,
            "profile_id": profile["profile_id"], "scalars": scalar_meta,
            "contract": contract_record, "references": refs,
            "code_guards": [{key: value for key, value in item.items() if key != "expected_bytes"}
                            for item in guard_specs.values()],
            "save_tokens": token_specs,
            "reader_self_reference": provenance.get("reader_self_reference")}


def validate_profile_group(path: Path, *, current: bool = False, paths: Paths | None = None) -> dict[str, Any]:
    """Validate every checked-in profile and every occurrence of its references."""
    if current:
        if paths is None:
            raise VerificationError("current_profile_paths_missing")
        return validate_profile(paths)
    profile = _mapping(read_json(path, max_bytes=MAX_PROFILE_BYTES), f"profile:{path.name}")
    profile_sha = digest(path, max_bytes=MAX_PROFILE_BYTES)
    profile_id = profile.get("profile_id")
    if not isinstance(profile_id, str) or not profile_id:
        raise VerificationError(f"profile_id_missing:{path.name}")
    _equal(profile, "game_version", EXPECTED_VERSION, f"profile:{path.name}")
    executable = _mapping(profile.get("executable"), f"profile:{path.name}.executable")
    _equal(executable, "sha256", EXPECTED_EXE_SHA, f"profile:{path.name}.executable")
    # All profiles are required to carry an explicit observer-country scope
    # when they declare one; an absent section remains an unresolved scope,
    # rather than being inferred here.
    if isinstance(profile.get("country"), dict):
        supported = profile["country"].get("supported_country")
        if supported is not None and supported != EXPECTED_COUNTRY:
            raise VerificationError(f"profile_country_scope_changed:{path.name}")
    refs = _profile_refs(profile)
    return {"path": relative(path), "sha256": profile_sha, "bytes": path.stat().st_size,
            "profile_id": profile_id, "references": refs,
            "source_evidence_kind": profile.get("source_evidence_kind")}


def validate_static_profiles(profile_path: Path | None = None, contract_path: Path | None = None) -> list[dict[str, Any]]:
    """Audit all checked-in profiles without requiring runtime evidence paths."""
    profile_paths = sorted((ROOT / "bridge/information/profiles").glob("*.json"))
    if len(profile_paths) != 7:
        raise VerificationError(f"profile_count_changed:{len(profile_paths)}")
    groups: list[dict[str, Any]] = []
    current = _resolve(profile_path or ROOT / "bridge/information/profiles/domestic-pressure-memory-1374.json")
    for path in profile_paths:
        if path.resolve() != current:
            groups.append(validate_profile_group(path))
            continue
        profile = _mapping(read_json(path, max_bytes=MAX_PROFILE_BYTES), "domestic profile")
        provenance = _mapping(profile.get("provenance"), "domestic profile provenance")
        chosen_contract = _resolve(contract_path or ROOT / provenance.get("contract_path", ""))
        dummy = Paths(DEFAULT_STAGE, path, chosen_contract, path, path, path, path, path, path, BASELINE)
        groups.append(validate_profile(dummy))
    if not any(group.get("profile_id") == "domestic-pressure-memory-1374" for group in groups):
        raise VerificationError("domestic_profile_not_in_profile_set")
    return groups


def validate_all_profiles(paths: Paths) -> list[dict[str, Any]]:
    return validate_static_profiles(paths.profile, paths.contract)


def _check_guard(value: Any, label: str, *, static: bool = False) -> dict[str, Any]:
    guard = _mapping(value, label)
    _equal(guard, "status", "observed", label)
    checks = guard.get("checks")
    if checks is None:
        raise VerificationError(f"guard_checks_missing:{label}")
    checks = _mapping(checks, f"{label}.checks")
    if not checks or any(item is not True for item in checks.values()):
        raise VerificationError(f"guard_check_failed:{label}")
    if static:
        dependencies = guard.get("dependency_hash_checks")
        if dependencies is None:
            raise VerificationError(f"guard_dependencies_missing:{label}")
        dependencies = _mapping(dependencies, f"{label}.dependency_hash_checks")
        if not dependencies or any(item is not True for item in dependencies.values()):
            raise VerificationError(f"guard_dependency_check_failed:{label}")
    return {"status": guard.get("status"), "checks": sorted(checks or {})}


def _guard_hash(record: Mapping[str, Any], side: str, label: str) -> tuple[bytes | None, str]:
    """Read a guard record's bytes/hash without retaining code bytes in audit."""
    raw_hex = record.get(f"{side}_hex")
    raw_bytes: bytes | None = None
    if raw_hex is not None:
        if not isinstance(raw_hex, str) or re.fullmatch(r"[0-9a-fA-F]+", raw_hex) is None or len(raw_hex) % 2:
            raise VerificationError(f"guard_{side}_hex_invalid:{label}")
        try:
            raw_bytes = bytes.fromhex(raw_hex)
        except ValueError as exc:
            raise VerificationError(f"guard_{side}_hex_invalid:{label}") from exc
    declared = record.get(f"{side}_sha256")
    if declared is None:
        if raw_bytes is None:
            raise VerificationError(f"guard_{side}_hash_missing:{label}")
        declared_sha = hashlib.sha256(raw_bytes).hexdigest()
    else:
        declared_sha = _sha(declared, f"{label}.{side}_sha256")
    if raw_bytes is not None and hashlib.sha256(raw_bytes).hexdigest() != declared_sha:
        raise VerificationError(f"guard_{side}_sha_mismatch:{label}")
    return raw_bytes, declared_sha


def _validate_guard_records(value: Any, label: str, specs: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
    """Check every code guard against profile RVA, bytes and SHA declarations."""
    guard = _mapping(value, label)
    _equal(guard, "status", "observed", label)
    checks = _mapping(guard.get("checks"), f"{label}.checks")
    if set(checks) != set(specs) or any(item is not True for item in checks.values()):
        raise VerificationError(f"guard_check_set_failed:{label}")
    records = _mapping(guard.get("records"), f"{label}.records")
    if set(records) != set(specs):
        raise VerificationError(f"guard_record_set_changed:{label}")
    compact: dict[str, Any] = {}
    for name, spec in specs.items():
        record = _mapping(records[name], f"{label}.records.{name}")
        rva = record.get("rva")
        if rva is None and isinstance(record.get("address"), dict):
            rva = record["address"].get("rva")
        if _profile_integer(rva, f"{label}.records.{name}.rva") != spec["rva"]:
            raise VerificationError(f"guard_rva_mismatch:{label}:{name}")
        expected_bytes, expected_sha = _guard_hash(record, "expected", f"{label}.{name}")
        actual_bytes, actual_sha = _guard_hash(record, "actual", f"{label}.{name}")
        if expected_bytes is not None:
            if expected_bytes != spec["expected_bytes"]:
                raise VerificationError(f"guard_expected_bytes_mismatch:{label}:{name}")
        elif expected_sha != spec["expected_sha256"]:
            raise VerificationError(f"guard_expected_sha_mismatch:{label}:{name}")
        if actual_bytes is not None:
            if len(actual_bytes) != spec["size"] or actual_bytes != spec["expected_bytes"]:
                raise VerificationError(f"guard_actual_bytes_mismatch:{label}:{name}")
        if actual_sha != spec["expected_sha256"]:
            raise VerificationError(f"guard_actual_sha_mismatch:{label}:{name}")
        compact[name] = {"rva": spec["rva"], "expected_sha256": expected_sha,
                         "actual_sha256": actual_sha}
        if isinstance(record.get("address"), dict):
            compact[name]["address"] = record["address"].get("value", record["address"].get("address"))
    return {"status": "observed", "checks": sorted(checks), "records": compact}


def _validate_runtime_guard(value: Any, label: str, specs: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
    guard = _mapping(value, label)
    _equal(guard, "status", "observed", label)
    passes = guard.get("passes")
    if not isinstance(passes, list) or len(passes) != 2:
        raise VerificationError(f"runtime_guard_pass_count_changed:{label}")
    normalized: list[dict[str, Any]] = []
    for index, item in enumerate(passes):
        normalized.append(_validate_guard_records(item, f"{label}.passes[{index}]", specs))
    if normalized[0] != normalized[1]:
        raise VerificationError(f"runtime_guard_passes_differ:{label}")
    return {"status": "observed", "passes": normalized}


def _validate_save_token_guard(value: Any, label: str, tokens: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
    guard = _mapping(value, label)
    _equal(guard, "status", "observed", label)
    passes = guard.get("passes")
    if not isinstance(passes, list) or len(passes) != 2:
        raise VerificationError(f"save_token_guard_pass_count_changed:{label}")
    normalized: list[dict[str, Any]] = []
    for pass_index, item in enumerate(passes):
        current = _mapping(item, f"{label}.passes[{pass_index}]")
        _equal(current, "status", "observed", f"{label}.passes[{pass_index}]")
        checks = _mapping(current.get("checks"), f"{label}.passes[{pass_index}].checks")
        if set(checks) != set(tokens) or any(value is not True for value in checks.values()):
            raise VerificationError(f"save_token_guard_checks_changed:{label}")
        records = _mapping(current.get("records"), f"{label}.passes[{pass_index}].records")
        if set(records) != set(tokens):
            raise VerificationError(f"save_token_guard_fields_changed:{label}")
        compact_records: dict[str, Any] = {}
        for field, token in tokens.items():
            record = _mapping(records[field], f"{label}.passes[{pass_index}].records.{field}")
            if record.get("status") != "observed" or record.get("key_id") != token["key_id"]:
                raise VerificationError(f"save_token_guard_record_changed:{label}:{field}")
            if record.get("expected_name") != field or record.get("actual_name") != field:
                raise VerificationError(f"save_token_guard_name_changed:{label}:{field}")
            compact_records[field] = {"key_id": token["key_id"], "name": field,
                                     "status": "observed"}
        normalized.append({"status": "observed", "checks": sorted(checks),
                           "records": compact_records})
    if normalized[0] != normalized[1]:
        raise VerificationError(f"save_token_guard_passes_differ:{label}")
    top_checks = guard.get("checks")
    if top_checks is not None:
        top_checks = _mapping(top_checks, f"{label}.checks")
        if set(top_checks) != set(tokens) or any(value is not True for value in top_checks.values()):
            raise VerificationError(f"save_token_guard_top_checks_changed:{label}")
    return {"status": "observed", "passes": normalized}


def _date_snapshot(value: Any, label: str) -> int:
    snapshot = _mapping(value, label)
    if "status" in snapshot:
        _equal(snapshot, "status", "observed", label)
    date = snapshot.get("game_date")
    if isinstance(date, dict):
        number = _integer(date.get("value"), f"{label}.game_date.value")
        raw_hex = date.get("raw_hex")
        if not isinstance(raw_hex, str) or re.fullmatch(r"[0-9a-fA-F]{8}", raw_hex) is None:
            raise VerificationError(f"game_date_raw_missing:{label}")
        if int.from_bytes(bytes.fromhex(raw_hex), "little", signed=True) != number:
            raise VerificationError(f"game_date_raw_mismatch:{label}")
        return number
    raise VerificationError(f"game_date_object_missing:{label}")


def _validate_values(value: Any, label: str) -> dict[str, int]:
    values = _mapping(value, label)
    if set(values) != set(FIELDS):
        raise VerificationError(f"field_set_changed:{label}")
    return {field: _integer(values[field], f"{label}.{field}") for field in FIELDS}


def _validate_field_results(report: Mapping[str, Any]) -> dict[str, int]:
    results = _mapping(report.get("field_results"), "native_capture.field_results")
    if set(results) != set(FIELDS):
        raise VerificationError("native_capture_field_set_changed")
    values = _validate_values(report.get("values"), "native_capture.values")
    for field in FIELDS:
        item = _mapping(results[field], f"field_results.{field}")
        _equal(item, "status", "known", f"field_results.{field}")
        raw = _integer(item.get("raw"), f"field_results.{field}.raw")
        if raw < -(1 << 31) or raw > (1 << 31) - 1:
            raise VerificationError(f"raw_int32_out_of_range:{field}")
        raw_hex = item.get("raw_hex")
        if not isinstance(raw_hex, str) or re.fullmatch(r"[0-9a-fA-F]{8}", raw_hex) is None:
            raise VerificationError(f"raw_hex_invalid:{field}")
        if int.from_bytes(bytes.fromhex(raw_hex), "little", signed=True) != raw:
            raise VerificationError(f"raw_hex_mismatch:{field}")
        _equal(item, "unit", UNITS[field], f"field_results.{field}")
        _equal(item, "scale", 1000, f"field_results.{field}")
        if values[field] != raw:
            raise VerificationError(f"values_mismatch:{field}")
    return values


def _identity_audit(identity: Any, label: str) -> dict[str, Any]:
    value = _mapping(identity, label)
    _true(value, "binding_verified", label)
    session_id = value.get("installation_session_id")
    process_path_sha = value.get("process_path_sha256")
    if not isinstance(session_id, str) or not session_id:
        raise VerificationError(f"identity_missing:{label}.installation_session_id")
    if not isinstance(process_path_sha, str) or not process_path_sha:
        raise VerificationError(f"identity_missing:{label}.process_path_sha256")
    if session_id != EXPECTED_SESSION:
        raise VerificationError(f"identity_session_mismatch:{label}")
    if process_path_sha.lower() != EXPECTED_EXE_SHA:
        raise VerificationError(f"identity_exe_mismatch:{label}")
    install_creation = _integer(value.get("installation_creation_filetime"),
                                 f"{label}.installation_creation_filetime", minimum=0)
    process_creation = _integer(value.get("process_creation_filetime"),
                                 f"{label}.process_creation_filetime", minimum=0)
    if install_creation != EXPECTED_CREATION_FILETIME or process_creation != EXPECTED_CREATION_FILETIME:
        raise VerificationError(f"identity_creation_mismatch:{label}")
    return {"installation_session_id": session_id,
            "process_path_sha256": process_path_sha.lower(),
            "installation_creation_filetime": install_creation,
            "process_creation_filetime": process_creation}


def validate_capture(paths: Paths, profile: dict[str, Any]) -> dict[str, Any]:
    capture = _mapping(read_json(paths.capture), "native capture")
    _equal(capture, "status", "observed", "native capture")
    _true(capture, "read_only", "native capture")
    if capture.get("native_function_invoked") is not False:
        raise VerificationError("native_capture_function_scope_changed")
    _equal(capture, "country", EXPECTED_COUNTRY, "native capture")
    _true(capture, "completed", "native capture")
    if "scale" in capture and capture.get("scale") != 1000:
        raise VerificationError("native_capture_scale_changed")
    target = _mapping(capture.get("target_build"), "native capture target_build")
    _equal(target, "version", EXPECTED_VERSION, "native capture target_build")
    _equal(target, "expected_exe_sha256", EXPECTED_EXE_SHA, "native capture target_build")
    profile_item = _mapping(capture.get("profile"), "native capture profile")
    if profile_item.get("sha256") != profile["sha256"]:
        raise VerificationError("native_capture_profile_sha_mismatch")
    probe_sha = capture.get("probe_script_sha256")
    if probe_sha is not None:
        expected_probe = digest(ROOT / "bridge/information/domestic_pressure_memory.py")
        if _sha(probe_sha, "native capture probe_script_sha256") != expected_probe:
            raise VerificationError("native_capture_reader_sha_mismatch")
    identity = _identity_audit(capture.get("identity"), "native capture identity")
    raw_profile = _mapping(read_json(paths.profile, max_bytes=MAX_PROFILE_BYTES), "domestic profile")
    guard_specs, token_specs = _profile_guard_specs(raw_profile, "domestic-pressure-memory-1374")
    static_guard = _check_guard(capture.get("static_contract_guard"), "native capture static_contract_guard", static=True)
    static_raw = _mapping(capture.get("static_contract_guard"), "native capture static_contract_guard")
    if static_raw.get("profile_sha256") not in (None, profile["sha256"]):
        raise VerificationError("native_static_profile_sha_mismatch")
    expected_refs = {item["path"]: item["sha256"] for item in profile["references"]}
    dependencies = static_raw.get("source_dependencies")
    if not isinstance(dependencies, list) or not dependencies:
        raise VerificationError("native_static_dependencies_missing")
    for index, item in enumerate(dependencies):
        dependency = _mapping(item, f"native static source_dependencies[{index}]")
        path = dependency.get("path")
        sha = _sha(dependency.get("sha256"), f"native static dependency[{index}]")
        if path not in expected_refs or expected_refs[path] != sha:
            raise VerificationError(f"native_static_dependency_not_pinned:{path}")
    dependency_checks = _mapping(static_raw.get("dependency_hash_checks"), "native static dependency_hash_checks")
    if (not dependency_checks or not set(dependency_checks).issubset(expected_refs)
            or any(item is not True for item in dependency_checks.values())):
        raise VerificationError("native_static_dependency_hash_check_failed")
    file_guard = _validate_guard_records(capture.get("file_code_guard"), "native capture file_code_guard", guard_specs)
    runtime_guard = _validate_runtime_guard(capture.get("runtime_code_guard"), "native capture runtime_code_guard", guard_specs)
    token_guard = _validate_save_token_guard(capture.get("save_token_guard"), "native capture save_token_guard", token_specs)
    doublepass = _mapping(capture.get("doublepass"), "native capture doublepass")
    _true(doublepass, "performed", "native capture doublepass")
    _true(doublepass, "consistent", "native capture doublepass")
    if doublepass.get("mismatches") != []:
        raise VerificationError("native_capture_doublepass_mismatch_list_not_empty")
    cleanup = _mapping(capture.get("cleanup"), "native capture cleanup")
    close = _mapping(cleanup.get("handle_close"), "native capture cleanup.handle_close")
    _equal(close, "status", "closed", "native capture cleanup.handle_close")
    if close.get("closed") is not True and "closed" in close:
        raise VerificationError("native_capture_handle_not_closed")
    before_date = _date_snapshot(capture.get("before"), "native capture before")
    after_date = _date_snapshot(capture.get("after"), "native capture after")
    if before_date != after_date:
        raise VerificationError("native_capture_date_changed")
    if before_date != EXPECTED_GAME_DATE:
        raise VerificationError("native_capture_date_control_mismatch")
    before = _mapping(capture.get("before"), "native capture before")
    after = _mapping(capture.get("after"), "native capture after")
    differences = _diff_paths(before, after)
    if differences:
        raise VerificationError("native_capture_raw_passes_differ:" + ",".join(differences[:32]))
    values = _validate_field_results(capture)
    return {"path": relative(paths.capture), "sha256": digest(paths.capture), "identity": identity,
            "values": values, "game_date": before_date,
            "static_contract_guard": static_guard,
            "file_code_guard": file_guard,
            "runtime_code_guard": runtime_guard,
            "save_token_guard": token_guard}


def _report_values(value: Any, label: str) -> dict[str, int]:
    values = _mapping(value, label)
    return {field: _integer(values.get(field), f"{label}.{field}") for field in FIELDS}


def validate_native_report(paths: Paths, capture: dict[str, Any]) -> dict[str, Any]:
    report = _mapping(read_json(paths.native_report), "native runtime report")
    _equal(report, "status", "passed", "native runtime report")
    # The N04 runner predates the explicit ``pure_RPM`` label used by the
    # country-powers runner.  Its live mode plus read-only guards is the same
    # contract; either spelling is accepted, but an explicit false is fatal.
    if report.get("pure_RPM") is not True and not (
        report.get("mode") == "live" and report.get("read_only", True) is True
    ):
        raise VerificationError("native_runtime_not_pure_rpm")
    if report.get("native_function_invoked") is not False:
        raise VerificationError("native_runtime_function_scope_changed")
    for key in ("business_actions_submitted", "date_advance", "save_or_reload", "dll_installation"):
        if key in report and report[key] is not False:
            raise VerificationError(f"native_runtime_scope_changed:{key}")
    if "values" not in report or _report_values(report["values"], "native runtime values") != capture["values"]:
        raise VerificationError("native_runtime_values_mismatch")
    _equal(report, "country", EXPECTED_COUNTRY, "native runtime report")
    _equal(report, "session_id", EXPECTED_SESSION, "native runtime report")
    if report.get("game_sha256") is not None:
        _equal(report, "game_sha256", EXPECTED_EXE_SHA, "native runtime report")
    if report.get("date_raw") is not None:
        _integer(report.get("date_raw"), "native runtime report.date_raw")
        if report["date_raw"] != capture["game_date"]:
            raise VerificationError("native_runtime_date_mismatch")
    raw_sha = _sha(report.get("raw_capture_sha256"), "native runtime raw_capture_sha256")
    if raw_sha != capture["sha256"]:
        raise VerificationError("native_runtime_raw_capture_mismatch")
    source_sha = report.get("source_sha256")
    if source_sha is not None:
        expected_source = digest(ROOT / "work/capture_information_domestic_pressure.py")
        if _sha(source_sha, "native runtime source_sha256") != expected_source:
            raise VerificationError("native_runtime_capture_source_mismatch")
    checks = _mapping(report.get("checks"), "native runtime checks")
    if not checks or any(item is not True for item in checks.values()):
        raise VerificationError("native_runtime_check_failed")
    return {"path": relative(paths.native_report), "sha256": digest(paths.native_report),
            "raw_capture_sha256": raw_sha, "values": capture["values"],
             "session_id": report["session_id"], "date_raw": report.get("date_raw")}


def _source_files(value: Any, label: str) -> list[dict[str, Any]]:
    mapping = _mapping(value, label)
    checked = []
    for name, item in mapping.items():
        if isinstance(item, str):
            path, expected = name, item
        else:
            record = _mapping(item, f"{label}.{name}")
            path, expected = record.get("path", name), record.get("sha256")
        if not isinstance(path, str):
            raise VerificationError(f"source_path_invalid:{label}.{name}")
        source = bounded_file(ROOT / path)
        checked.append(_record(source, role=f"{label}.{name}", expected=expected))
    if not checked:
        raise VerificationError(f"source_files_empty:{label}")
    return checked


def validate_live(paths: Paths, native: dict[str, Any]) -> dict[str, Any]:
    live = _mapping(read_json(paths.live_report), "live acceptance report")
    _equal(live, "status", "passed", "live acceptance report")
    _equal(live, "country", EXPECTED_COUNTRY, "live acceptance report")
    _true(live, "read_only", "live acceptance report")
    if live.get("native_function_invoked") is not False:
        raise VerificationError("live_acceptance_function_scope_changed")
    if live.get("session_id") != EXPECTED_SESSION:
        raise VerificationError("live_acceptance_session_mismatch")
    if live.get("game_sha256") is not None and live["game_sha256"] != EXPECTED_EXE_SHA:
        raise VerificationError("live_acceptance_exe_mismatch")
    if live.get("date_raw") is not None and live["date_raw"] != EXPECTED_GAME_DATE:
        raise VerificationError("live_acceptance_date_mismatch")
    periodic = _integer(live.get("periodic_results"), "live periodic_results", minimum=3)
    checks = _mapping(live.get("checks"), "live checks")
    if not checks or any(value is not True for value in checks.values()):
        raise VerificationError("live_acceptance_check_failed")
    if live.get("business_actions_submitted") is not False:
        raise VerificationError("live_acceptance_business_action_scope_changed")
    reference_value = live.get("native_reference_sha256")
    if reference_value is None and isinstance(live.get("native_reference"), dict):
        reference_value = live["native_reference"].get("sha256")
    if reference_value is None:
        raise VerificationError("live_native_reference_missing")
    reference = _sha(reference_value, "live native_reference_sha256")
    if reference not in {native["sha256"], native.get("raw_capture_sha256")}:
        raise VerificationError("live_native_reference_mismatch")
    if "values" in live and _report_values(live["values"], "live values") != native["values"]:
        raise VerificationError("live_values_mismatch")
    sources = _source_files(live.get("source_files"), "live source_files")
    if not any(item["path"] == "tools/serve_information.py" for item in sources):
        raise VerificationError("live_serve_source_pin_missing")
    source_sha = live.get("source_sha256")
    if source_sha is not None:
        expected_source = digest(ROOT / "work/validate_information_domestic_pressure.py")
        if _sha(source_sha, "live source_sha256") != expected_source:
            raise VerificationError("live_validator_source_mismatch")
    return {"path": relative(paths.live_report), "sha256": digest(paths.live_report),
            "periodic_results": periodic, "checks": sorted(checks), "source_files": sources,
             "native_reference_sha256": reference}


def validate_save(paths: Paths) -> dict[str, Any]:
    save = _mapping(read_json(paths.save_crosscheck), "save crosscheck")
    if save.get("save_is_recorded") is not True and save.get("mode") != "recorded":
        raise VerificationError("save_crosscheck_recorded_marker_missing")
    if save.get("not_a_live_state_fallback") is not True:
        raise VerificationError("save_crosscheck_live_fallback_marker_missing")
    if save.get("world_generation_verified") is not False:
        raise VerificationError("save_world_generation_must_remain_unverified")
    source = save.get("source") if isinstance(save.get("source"), dict) else {}
    save_sha = (save.get("save_sha256") or save.get("expected_save_sha256")
                or save.get("sha256") or source.get("expected_sha256") or source.get("sha256"))
    save_sha = _sha(save_sha, "save crosscheck save_sha256")
    source_path = source.get("path")
    source_record: dict[str, Any] | None = None
    if source_path is not None:
        if not isinstance(source_path, str) or not source_path:
            raise VerificationError("save_crosscheck_source_path_invalid")
        declared_bytes = source.get("bytes")
        if type(declared_bytes) is not int or declared_bytes <= 0:
            raise VerificationError("save_crosscheck_source_bytes_invalid")
        # The historical EU4txt save is deliberately outside this workspace;
        # its stream checker already recorded the content hash.  Re-read it
        # only when a future report points at an in-workspace bounded artifact.
        candidate = Path(source_path)
        try:
            resolved_candidate = _resolve(candidate)
        except VerificationError:
            resolved_candidate = None
        if resolved_candidate is not None:
            actual_source_sha = digest(resolved_candidate)
            if actual_source_sha != save_sha or resolved_candidate.stat().st_size != declared_bytes:
                raise VerificationError("save_crosscheck_source_sha_mismatch")
        elif _sha(source.get("sha256"), "save source.sha256") != save_sha:
            raise VerificationError("save_crosscheck_external_source_sha_mismatch")
        else:
            actual_source_sha = save_sha
        if source.get("expected_sha256") is not None and _sha(source["expected_sha256"], "save source.expected_sha256") != actual_source_sha:
            raise VerificationError("save_crosscheck_expected_sha_mismatch")
        source_record = {"path": source_path, "sha256": save_sha, "bytes": declared_bytes,
                         "workspace_read": resolved_candidate is not None}
    return {"path": relative(paths.save_crosscheck), "sha256": digest(paths.save_crosscheck),
            "save_sha256": save_sha, "mode": "recorded", "world_generation_verified": False,
            "source": source_record}


def _fixture_pin_records(value: Any) -> list[dict[str, Any]]:
    result = []
    if isinstance(value, dict):
        for name, item in value.items():
            record = _path_record(item, f"fixture.{name}", default_role="fixture artifact")
            if record is not None:
                path, expected, role, _ = record
                source = bounded_file(ROOT / path)
                result.append(_record(source, role=role, expected=expected))
    return result


def validate_fixture(paths: Paths, capture: dict[str, Any], native: dict[str, Any], live: dict[str, Any]) -> dict[str, Any]:
    fixture = _mapping(read_json(paths.fixture), "recorded fixture")
    raw_capture = read_json(paths.capture)
    raw_native = read_json(paths.native_report)
    raw_live = read_json(paths.live_report)
    provenance = _mapping(fixture.get("provenance"), "recorded fixture provenance")
    for key, expected in (
        ("mode", "recorded"), ("original_mode", "live"),
        ("game_version", EXPECTED_VERSION), ("observer", EXPECTED_COUNTRY),
        ("session_id", EXPECTED_SESSION), ("game_date", capture["game_date"]),
        ("game_sha256", EXPECTED_EXE_SHA),
    ):
        _equal(provenance, key, expected, "recorded fixture")
    for key in ("business_actions_submitted", "native_function_invoked", "date_advance", "save_or_reload"):
        if provenance.get(key) is not False:
            raise VerificationError(f"fixture_scope_changed:{key}")
    if provenance.get("pure_RPM") is not True:
        raise VerificationError("fixture_pure_rpm_marker_missing")
    expected = _mapping(fixture.get("expected"), "recorded fixture expected")
    _equal(expected, "country", EXPECTED_COUNTRY, "recorded fixture expected")
    expected_values = _validate_values(expected.get("values"), "recorded fixture expected.values")
    if expected_values != capture["values"]:
        raise VerificationError("fixture_expected_values_mismatch")

    for key, source in (("native_capture", raw_capture), ("native_report", raw_native), ("mcp_report", raw_live)):
        value = fixture.get(key)
        if not isinstance(value, dict):
            raise VerificationError(f"fixture_{key}_missing")
        if value != source:
            raise VerificationError(f"fixture_{key}_changed")

    manual_path = paths.live_report.parent / "manual-result.json"
    manual_path = bounded_file(manual_path)
    manual = _mapping(read_json(manual_path), "recorded fixture manual result")
    if not isinstance(fixture.get("mcp_manual_result"), dict) or fixture["mcp_manual_result"] != manual:
        raise VerificationError("fixture_mcp_manual_result_changed")
    manual_context = _mapping(manual.get("context"), "recorded fixture manual context")
    if fixture.get("mcp_manual_context") != manual_context:
        raise VerificationError("fixture_mcp_manual_context_changed")

    try:
        from bridge.information.model import canonical
        canonical_sha = hashlib.sha256(canonical(raw_capture).encode("utf-8")).hexdigest()
    except Exception as exc:
        raise VerificationError("fixture_canonical_hash_unavailable") from exc
    if _sha(provenance.get("capture_canonical_sha256"), "fixture.capture_canonical_sha256") != canonical_sha:
        raise VerificationError("fixture_capture_canonical_mismatch")
    for key, path in (("native_report_sha256", paths.native_report), ("mcp_report_sha256", paths.live_report)):
        if _sha(provenance.get(key), f"fixture.{key}") != digest(path):
            raise VerificationError(f"fixture_{key}_mismatch")
    required_sources = ("source_capture", "source_report", "mcp_manual_result", "mcp_report")
    for key in required_sources:
        record = _mapping(provenance.get(key), f"fixture.provenance.{key}")
        path = record.get("path")
        expected_sha = _sha(record.get("sha256"), f"fixture.provenance.{key}.sha256")
        if type(record.get("bytes")) is not int:
            raise VerificationError(f"fixture_provenance_bytes_missing:{key}")
        source_path = bounded_file(ROOT / path)
        if digest(source_path) != expected_sha or source_path.stat().st_size != record["bytes"]:
            raise VerificationError(f"fixture_source_pin_changed:{path}")
    artifacts = _mapping(provenance.get("artifacts"), "fixture artifacts")
    if not artifacts:
        raise VerificationError("fixture_artifact_pins_missing")
    pins: list[dict[str, Any]] = []
    for name, item in artifacts.items():
        record = _mapping(item, f"fixture.artifacts.{name}")
        path = record.get("path")
        expected_sha = _sha(record.get("sha256"), f"fixture.artifacts.{name}.sha256")
        if type(record.get("bytes")) is not int:
            raise VerificationError(f"fixture_artifact_bytes_missing:{name}")
        source_path = bounded_file(ROOT / path)
        pins.append(_record(source_path, role=f"fixture.{name}", expected=expected_sha))
        if source_path.stat().st_size != record["bytes"]:
            raise VerificationError(f"fixture_artifact_size_changed:{name}")
    return {"path": relative(paths.fixture), "sha256": digest(paths.fixture),
            "bytes": paths.fixture.stat().st_size, "mode": "recorded", "artifacts": pins}


def validate_test_summary(paths: Paths) -> dict[str, Any]:
    summary = _mapping(read_json(paths.test_summary), "test summary")
    information = _mapping(summary.get("information"), "test summary information")
    statuses = _mapping(information.get("case_element_statuses"), "test summary information.case_element_statuses")
    for key in ("passed", "failure", "error"):
        if type(statuses.get(key)) is not int:
            raise VerificationError(f"information_test_status_missing:{key}")
    if statuses["failure"] != 0 or statuses["error"] != 0:
        raise VerificationError("information_tests_not_clean")
    if statuses["passed"] <= 0:
        raise VerificationError("information_test_pass_count_missing")

    overall = _mapping(summary.get("overall"), "test summary overall")
    overall_suite = _mapping(overall.get("junit_suite"), "test summary overall.junit_suite")
    for key in ("tests", "failures", "errors"):
        if type(overall_suite.get(key)) is not int:
            raise VerificationError(f"full_test_summary_status_missing:{key}")
    overall_logs = _mapping(overall.get("log_numbers"), "test summary overall.log_numbers")
    for key in ("passed", "failed", "errors"):
        if type(overall_logs.get(key)) is not int:
            raise VerificationError(f"full_test_log_status_missing:{key}")

    targeted = [
        value for name, value in summary.items()
        if "targeted" in name and name.endswith("_checkpoint") and isinstance(value, dict)
    ]
    if len(targeted) != 1:
        raise VerificationError("targeted_test_checkpoint_missing_or_ambiguous")
    checkpoint = targeted[0]
    if checkpoint.get("status") != "passed":
        raise VerificationError("targeted_test_checkpoint_not_passed")
    checkpoint_statuses = _mapping(checkpoint.get("case_element_statuses"), "targeted checkpoint statuses")
    for key in ("passed", "failure", "error"):
        if type(checkpoint_statuses.get(key)) is not int:
            raise VerificationError(f"targeted_checkpoint_status_missing:{key}")
    if checkpoint_statuses["failure"] != 0 or checkpoint_statuses["error"] != 0:
        raise VerificationError("targeted_test_checkpoint_not_clean")
    checkpoint_suite = _mapping(checkpoint.get("junit_suite"), "targeted checkpoint junit_suite")
    for key in ("tests", "failures", "errors"):
        if type(checkpoint_suite.get(key)) is not int:
            raise VerificationError(f"targeted_checkpoint_suite_missing:{key}")
    comparison = _mapping(summary.get("comparison_to_previous_batch"), "test summary comparison")
    for side in ("baseline", "current"):
        item = _mapping(comparison.get(side), f"test summary comparison.{side}")
        _mapping(item.get("junit_suite"), f"test summary comparison.{side}.junit_suite")
        for status_key in ("case_element_statuses", "information_case_element_statuses"):
            side_status = _mapping(item.get(status_key), f"test summary comparison.{side}.{status_key}")
            for key in ("passed", "failure", "error"):
                if type(side_status.get(key)) is not int:
                    raise VerificationError(f"comparison_status_missing:{side}:{status_key}:{key}")

    def verify_artifact_map(value: Any, label: str) -> list[dict[str, Any]]:
        mapping = _mapping(value, label)
        if not mapping:
            raise VerificationError(f"{label}_empty")
        checked: list[dict[str, Any]] = []
        for name, item in mapping.items():
            record = _mapping(item, f"{label}.{name}")
            path = record.get("path")
            expected = _sha(record.get("sha256"), f"{label}.{name}.sha256")
            if type(record.get("bytes")) is not int:
                raise VerificationError(f"{label}_bytes_missing:{name}")
            source = bounded_file(ROOT / path)
            checked.append(_record(source, role=f"{label}.{name}", expected=expected))
            if source.stat().st_size != record["bytes"]:
                raise VerificationError(f"{label}_size_changed:{name}")
        return checked

    checked = verify_artifact_map(summary.get("artifacts"), "test summary artifacts")
    evidence = _mapping(summary.get("evidence_checkpoints"), "test summary evidence_checkpoints")
    if not evidence:
        raise VerificationError("test_summary_evidence_checkpoints_missing")
    evidence_checked: list[dict[str, Any]] = []
    for name, item in evidence.items():
        record = _mapping(item, f"test summary evidence_checkpoints.{name}")
        if not all(key in record for key in ("path", "sha256", "bytes")):
            raise VerificationError(f"test_summary_evidence_pin_missing:{name}")
        expected = _sha(record.get("sha256"), f"test summary evidence_checkpoints.{name}.sha256")
        source = bounded_file(ROOT / record["path"])
        evidence_checked.append(_record(source, role=f"test summary evidence_checkpoints.{name}", expected=expected))
        if source.stat().st_size != record["bytes"]:
            raise VerificationError(f"test_summary_evidence_size_changed:{name}")
    return {"path": relative(paths.test_summary), "sha256": digest(paths.test_summary),
            "bytes": paths.test_summary.stat().st_size, "statuses": statuses,
            "full_summary": {"junit_suite": overall_suite, "log_numbers": overall_logs},
            "targeted_checkpoint": {"status": "passed", "case_element_statuses": checkpoint_statuses,
                                    "junit_suite": checkpoint_suite},
            "comparison": comparison, "artifacts": checked, "evidence_checkpoints": evidence_checked}


def validate_baseline(paths: Paths) -> dict[str, Any]:
    actual = digest(paths.baseline)
    if paths.baseline == BASELINE and actual != BASELINE_SHA:
        raise VerificationError("baseline_manifest_changed")
    manifest = _mapping(read_json(paths.baseline), "baseline manifest")
    if manifest.get("goal_complete") is not False:
        raise VerificationError("baseline_goal_complete_changed")
    previous = manifest.get("previous_manifest")
    predecessor = None
    if not isinstance(previous, dict):
        raise VerificationError("baseline_predecessor_missing")
    path = previous.get("path")
    expected = previous.get("sha256")
    if not isinstance(path, str) or not isinstance(expected, str):
        raise VerificationError("baseline_predecessor_pin_invalid")
    source = bounded_file(ROOT / path)
    predecessor = _record(source, role="baseline predecessor", expected=expected)
    if source != PREVIOUS_BASELINE or predecessor["sha256"] != PREVIOUS_BASELINE_SHA:
        raise VerificationError("baseline_predecessor_changed")
    return {"path": relative(paths.baseline), "sha256": actual, "bytes": paths.baseline.stat().st_size,
            "goal_complete": False, "previous": predecessor, "recursive_archive_copy": False}


def build_catalog() -> dict[str, Any]:
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    try:
        from bridge.information.composite import CompositeSource
        from bridge.information.country_state import NativeCountryStateSource
        from bridge.information.domestic_pressure import NativeDomesticPressureSource
        from bridge.information.sources import DiplomacySource
        from bridge.information.subject_relations import NativeSubjectRelationSource
        from bridge.information.static_data import StaticTradeSource
        from bridge.information.mission_definitions import MissionDefinitionIndex
        from bridge.information.missions import MissionInformationSource, NativeMissionReader
        primary = DiplomacySource(observer=EXPECTED_COUNTRY)
        adapters = [
            NativeCountryStateSource(primary),
            NativeDomesticPressureSource(primary),
            NativeSubjectRelationSource(primary),
            StaticTradeSource(context_provider=primary.context),
            MissionInformationSource(primary, MissionDefinitionIndex(), NativeMissionReader(primary)),
        ]
        topics = CompositeSource(primary, adapters).catalog()
    except Exception as exc:
        raise VerificationError(f"offline_catalog_failed:{type(exc).__name__}:{exc}") from exc
    n04 = next((item for item in topics if item.get("topic_id") == "N04"), None)
    if not isinstance(n04, dict) or n04.get("status") != "available":
        raise VerificationError("N04_catalog_not_available")
    fields = _mapping(n04.get("fields"), "N04 catalog fields")
    # CompositeSource retains the six-field N04 topic while the adapter
    # replaces only the three proven scalar fields.  Keep this assertion tied
    # to the actual current catalog shape; do not infer coverage for the two
    # remaining fields from similar names.
    if len(fields) != 6 or not set(FIELDS).issubset(fields):
        raise VerificationError("N04_catalog_field_set_changed")
    for field in FIELDS:
        item = _mapping(fields[field], f"N04 catalog.{field}")
        if item.get("coverage") not in {"available", "partial"} or item.get("unit") != UNITS[field] or item.get("scale") != 1000:
            raise VerificationError(f"N04_catalog_metadata_changed:{field}")
        if item.get("supported_countries") != [EXPECTED_COUNTRY]:
            raise VerificationError(f"N04_catalog_scope_changed:{field}")
    counts = Counter(field.get("coverage") for topic in topics for field in topic.get("fields", {}).values())
    result = {"schema_version": 1, "topic_count": len(topics),
              "field_count": sum(len(topic.get("fields", {})) for topic in topics),
              "available_topic_count": sum(topic.get("status") == "available" for topic in topics),
              "field_counts": dict(counts), "topics": topics,
            "configuration": {"live_session_opened": False, "N04_native_adapter": True,
                              "current_live_adapters": ["NativeCountryStateSource",
                                                         "NativeDomesticPressureSource",
                                                         "NativeSubjectRelationSource"],
                              "offline_static_adapters": ["StaticTradeSource",
                                                            "MissionInformationSource"],
                              "catalog_is_not_live_acceptance": True}}
    for key, expected in EXPECTED_CATALOG.items():
        if result[key] != expected:
            raise VerificationError(f"catalog_coverage_changed:{key}")
    return result


def compile_sources() -> dict[str, Any]:
    paths: list[Path] = []
    paths.extend(sorted((ROOT / "bridge/information").glob("*.py")))
    paths.extend(sorted((ROOT / "bridge/tests").glob("test_information*.py")))
    paths.extend([ROOT / "work/verify_information_domestic_pressure.py",
                  ROOT / "work/finalize_information_domestic_pressure.py"])
    records = []
    with tempfile.TemporaryDirectory(prefix="information-domestic-pressure-compile-") as temp:
        target = Path(temp)
        for index, path in enumerate(paths):
            source = bounded_file(path)
            py_compile.compile(str(source), cfile=str(target / f"{index}.pyc"), doraise=True)
            records.append({"path": relative(source), "bytes": source.stat().st_size, "sha256": digest(source)})
    return {"status": "passed", "file_count": len(records), "files": records,
            "scope": ["bridge/information/*.py", "bridge/tests/test_information*.py", "N04 verification/finalization scripts"]}


def run_validation(*, paths: Paths | None = None, write_artifacts: bool = True, **path_kwargs: Any) -> dict[str, Any]:
    paths = paths or _load_paths(**path_kwargs)
    profile_groups = validate_all_profiles(paths)
    profile = next(group for group in profile_groups
                   if group.get("profile_id") == "domestic-pressure-memory-1374")
    capture = validate_capture(paths, profile)
    native = validate_native_report(paths, capture)
    live = validate_live(paths, native)
    save = validate_save(paths)
    fixture = validate_fixture(paths, capture, native, live)
    tests = validate_test_summary(paths)
    baseline = validate_baseline(paths)
    catalog = build_catalog()
    compile_audit = compile_sources()
    result = {"status": "passed", "paths": {key: relative(value) for key, value in paths.__dict__.items()},
              "profile": profile, "profile_groups": profile_groups,
              "capture": capture, "native_report": native, "live": live,
              "save_crosscheck": save, "fixture": fixture, "test_summary": tests,
              "baseline": baseline, "coverage": catalog, "compile_audit": compile_audit}
    if write_artifacts:
        write_json(paths.stage / "coverage.json", catalog)
        write_json(paths.stage / "compile-audit.json", compile_audit)
        write_json(paths.stage / "source-audit.json", {
            "status": "passed", "batch": "information-domestic-pressure-20261025-001",
            "paths": result["paths"], "profile": profile, "profile_groups": profile_groups, "reports": {
                "native_capture": capture, "native_report": native,
                "live": live, "save_crosscheck": save, "fixture": fixture,
                "test_summary": tests}, "baseline": baseline,
            "source_fingerprints": compile_audit["files"],
        })
    return result


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stage", type=Path, default=DEFAULT_STAGE)
    parser.add_argument("--profile", type=Path)
    parser.add_argument("--contract", type=Path)
    parser.add_argument("--capture", type=Path)
    parser.add_argument("--native-report", type=Path)
    parser.add_argument("--live-report", type=Path)
    parser.add_argument("--save-crosscheck", type=Path)
    parser.add_argument("--fixture", type=Path)
    parser.add_argument("--test-summary", type=Path)
    parser.add_argument("--baseline", type=Path)
    parser.add_argument("--check-only", action="store_true", help="只核验，不写 stage 审计文件")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        result = run_validation(
            stage=args.stage, profile=args.profile, contract=args.contract,
            capture=args.capture, native_report=args.native_report, live_report=args.live_report,
            save_crosscheck=args.save_crosscheck, fixture=args.fixture,
            test_summary=args.test_summary, baseline=args.baseline,
            write_artifacts=not args.check_only,
        )
    except (VerificationError, OSError, py_compile.PyCompileError) as exc:
        print(json.dumps({"status": "failed", "error": str(exc)}, ensure_ascii=False))
        return 2
    print(json.dumps({"status": result["status"], "stage": result["paths"]["stage"],
                      "reports": {key: result[key].get("sha256") for key in ("capture", "native_report", "live", "save_crosscheck", "fixture")},
                      "coverage": {key: result["coverage"][key] for key in ("topic_count", "field_count", "available_topic_count", "field_counts")},
                      "compiled": result["compile_audit"]["file_count"]}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
