"""离线核对第九批本国君主点数证据并生成有界审计文件。

本脚本只读取已经保存的 JSON、源码和有界 profile，不连接游戏进程，也不
调用原生查询。原生两遍 RPM 结果、混合 MCP 周期验收以及历史存档向量保留
各自的证据类型；其中存档只作有序数值交叉核对，不能替代实时状态。
"""
from __future__ import annotations

from collections import Counter
import hashlib
import json
from pathlib import Path
import py_compile
import sys
import tempfile
from typing import Any, Mapping


ROOT = Path(__file__).resolve().parents[1]
ROOT_RESOLVED = ROOT.resolve()
STAGE = ROOT / "work/runtime/information-country-scalars-20261024-001"
NATIVE_CAPTURE = STAGE / "native-runtime-001/native-capture.json"
NATIVE_REPORT = STAGE / "native-runtime-001/report.json"
LIVE_REPORT = STAGE / "live-acceptance-002/report.json"
SAVE_REPORT = STAGE / "save-powers-crosscheck-001.json"
PROFILE = ROOT / "bridge/information/profiles/country-resources-memory-1374.json"
CUSTOM_PROFILE = ROOT / "bridge/information/profiles/custom-localization-memory-1374.json"
PREVIOUS = ROOT / "work/runtime/information-country-relations-20261024-001/delivery/manifest.json"
PREVIOUS_SHA = "b24cf0c61c56a95e36621d764080a4f9c22025649970c9cfdfafe96927e2e6f7"
CONTRACT2_REL = "work/runtime/information-dynamic-text-20261024-001/dynamic-localization-contract-002.json"
CONTRACT2_SHA = "ea13b783902b9a5410aa808ae7956e03732fe57376383cd0d4ea094ac9f1a5f7"
CAPTURE_SCRIPT = ROOT / "work/capture_information_country_powers.py"
READER_SOURCE = ROOT / "bridge/information/country_resources_memory.py"
INSTALLATION = ROOT / "work/runtime/diplomacy-observer-20261024-information-a/installation.json"

MAX_ARCHIVE_BYTES = 16 * 1024 * 1024
MAX_PROFILE_BYTES = 64 * 1024
EXPECTED_EXE_SHA = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
EXPECTED_VERSION = "1.37.4"
EXPECTED_COUNTRY = "FRA"
EXPECTED_SESSION = "37376-1dd639fff00a820"
EXPECTED_DATE = 56553384
EXPECTED_VALUES = {"administrative": 471, "diplomatic": 389, "military": 152}
EXPECTED_COVERAGE = {
    "topic_count": 74,
    "field_count": 397,
    "available_topic_count": 34,
    "field_counts": {"available": 51, "partial": 104, "planned": 242},
}
WORK_SOURCES = (
    ROOT / "work/capture_information_country_powers.py",
    ROOT / "work/validate_information_country_powers.py",
    ROOT / "work/freeze_information_country_powers.py",
    ROOT / "work/verify_information_country_powers_save.py",
    ROOT / "work/verify_information_country_powers.py",
    ROOT / "work/finalize_information_country_powers.py",
    ROOT / "work/research_information_power_access.py",
    ROOT / "work/research_information_country_scalars.py",
    ROOT / "work/audit_information_country_powers_tests.py",
)


def bounded_file(path: Path | str, *, max_bytes: int = MAX_ARCHIVE_BYTES) -> Path:
    candidate = Path(path)
    try:
        resolved = candidate.expanduser().resolve()
    except (OSError, RuntimeError) as exc:
        raise ValueError(f"cannot_resolve:{candidate}") from exc
    if not resolved.is_relative_to(ROOT_RESOLVED):
        raise ValueError(f"path_outside_workspace:{candidate}")
    if not resolved.is_file():
        raise ValueError(f"regular_file_required:{candidate}")
    size = resolved.stat().st_size
    if size > max_bytes:
        raise ValueError(f"file_over_limit:{resolved}:{size}>{max_bytes}")
    return resolved


def digest(path: Path | str, *, max_bytes: int = MAX_ARCHIVE_BYTES) -> str:
    source = bounded_file(path, max_bytes=max_bytes)
    value = hashlib.sha256()
    with source.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def read_json(path: Path | str, *, max_bytes: int = MAX_ARCHIVE_BYTES) -> Any:
    source = bounded_file(path, max_bytes=max_bytes)
    try:
        raw = source.read_bytes()
        if len(raw) != source.stat().st_size:
            raise ValueError("file_changed_during_read")
        return json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid_json:{source}") from exc


def write_json(path: Path | str, value: Any) -> Path:
    destination = Path(path).expanduser().resolve()
    if not destination.is_relative_to(ROOT_RESOLVED):
        raise ValueError(f"output_outside_workspace:{destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    raw = (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    if len(raw) > MAX_ARCHIVE_BYTES:
        raise ValueError(f"audit_over_limit:{destination}")
    destination.write_bytes(raw)
    return destination


def require_mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"mapping_required:{label}")
    return value


def require_equal(mapping: Mapping[str, Any], key: str, expected: Any, label: str) -> None:
    if mapping.get(key) != expected:
        raise ValueError(f"value_mismatch:{label}.{key}")


def require_true(mapping: Mapping[str, Any], key: str, label: str) -> None:
    if mapping.get(key) is not True:
        raise ValueError(f"true_required:{label}.{key}")


def require_int(value: Any, label: str, *, minimum: int | None = None) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"integer_required:{label}")
    if minimum is not None and value < minimum:
        raise ValueError(f"integer_below_minimum:{label}")
    return value


def _relative(path: Path) -> str:
    return path.resolve().relative_to(ROOT_RESOLVED).as_posix()


def _valid_sha(value: Any) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False
    try:
        int(value, 16)
    except ValueError:
        return False
    return True


def _hash_at(mapping: Mapping[str, Any], names: tuple[str, ...]) -> tuple[str | None, str | None]:
    """Return the first present SHA field, retaining its actual field name.

    The runtime capture has a stable ``probe_script_sha256``/``profile`` shape;
    the outer acceptance report may expose the same pins under a more explicit
    current-* name. Aliases are accepted only when present and still require a
    64-hex digest, so a missing or malformed pin cannot pass silently.
    """
    for name in names:
        value = mapping.get(name)
        if value is not None:
            if not _valid_sha(value):
                raise ValueError(f"sha256_invalid:{name}")
            return value.lower(), name
    return None, None


def _validate_profile_reference(
    record: Any,
    *,
    label: str,
    default_role: str,
    seen: dict[str, str],
) -> dict[str, Any]:
    if isinstance(record, str):
        relative, expected, declared_bytes, role, evidence_id = record, None, None, default_role, None
    else:
        item = require_mapping(record, label)
        relative = item.get("path")
        expected = item.get("sha256")
        declared_bytes = item.get("bytes")
        role = item.get("role", default_role)
        evidence_id = item.get("evidence_id")
    if not isinstance(relative, str) or not relative:
        raise ValueError(f"profile_reference_path_invalid:{label}")
    if expected is None or not _valid_sha(expected):
        raise ValueError(f"profile_reference_sha_invalid:{label}")
    source = bounded_file(ROOT / relative)
    actual = digest(source)
    if actual.lower() != expected.lower():
        raise ValueError(f"profile_reference_changed:{relative}")
    size = source.stat().st_size
    if declared_bytes is not None and declared_bytes != size:
        raise ValueError(f"profile_reference_size_changed:{relative}")
    previous = seen.get(relative)
    if previous is not None and previous != actual:
        raise ValueError(f"profile_reference_conflicting_sha:{relative}")
    seen[relative] = actual
    result: dict[str, Any] = {
        "path": _relative(source), "sha256": actual, "bytes": size, "role": role,
    }
    if evidence_id is not None:
        result["evidence_id"] = evidence_id
    return result


def validate_profiles() -> list[dict[str, Any]]:
    """Validate the power profile and every old/new dependency it pins."""
    profile = require_mapping(read_json(PROFILE, max_bytes=MAX_PROFILE_BYTES), "power profile")
    profile_sha = digest(PROFILE, max_bytes=MAX_PROFILE_BYTES)
    require_equal(profile, "profile_id", "country-resources-memory-1374", "power profile")
    require_equal(profile, "game_version", EXPECTED_VERSION, "power profile")
    executable = require_mapping(profile.get("executable"), "power profile executable")
    require_equal(executable, "sha256", EXPECTED_EXE_SHA, "power profile executable")
    powers = require_mapping(profile.get("powers"), "power profile powers")
    require_equal(powers, "unit", "monarch_points", "power profile powers")
    require_int(powers.get("scale"), "power profile scale", minimum=0)
    if powers.get("scale") != 1 or powers.get("signed") is not True:
        raise ValueError("power_profile_scale_or_signed_mismatch")
    require_equal(powers, "kind_enum", {"0": "ADM_POWER", "1": "DIP_POWER", "2": "MIL_POWER"}, "power profile")
    provenance = require_mapping(profile.get("provenance"), "power profile provenance")
    contract_path = provenance.get("contract_path")
    contract_sha = provenance.get("contract_sha256")
    if contract_path != "work/runtime/information-country-scalars-20261024-001/native-power-contract-001.json":
        raise ValueError("power_contract_path_changed")
    if not _valid_sha(contract_sha):
        raise ValueError("power_contract_sha_invalid")
    contract = bounded_file(ROOT / contract_path)
    if digest(contract) != contract_sha or digest(contract) != profile.get("contract_sha256"):
        raise ValueError("power_contract_sha_mismatch")

    seen: dict[str, str] = {}
    references: list[dict[str, Any]] = []
    source_evidence = require_mapping(profile.get("source_evidence"), "power profile source_evidence")
    for name, record in source_evidence.items():
        item = _validate_profile_reference(record, label=f"source_evidence.{name}",
                                            default_role="profile source_evidence", seen=seen)
        item["name"] = name
        references.append(item)
    dependencies = provenance.get("dependencies")
    if not isinstance(dependencies, list) or not dependencies:
        raise ValueError("power_profile_dependencies_missing")
    for index, record in enumerate(dependencies):
        references.append(_validate_profile_reference(record, label=f"provenance.dependencies[{index}]",
                                                      default_role="profile provenance dependency", seen=seen))
    # The low-level static guard uses this same dependency list. A missing or
    # false self-reference would make the runtime contract ambiguous.
    if provenance.get("reader_self_reference") is not False:
        raise ValueError("power_profile_reader_self_reference_changed")

    custom = require_mapping(read_json(CUSTOM_PROFILE, max_bytes=MAX_PROFILE_BYTES), "custom localization profile")
    require_equal(custom, "contract_sha256", CONTRACT2_SHA, "custom localization profile")
    custom_evidence = require_mapping(custom.get("source_evidence"), "custom localization source_evidence")
    contract_record = custom_evidence.get("dynamic_localization_contract")
    if not isinstance(contract_record, dict):
        raise ValueError("custom_contract2_reference_missing")
    if contract_record.get("path") != CONTRACT2_REL or contract_record.get("sha256") != CONTRACT2_SHA:
        raise ValueError("custom_contract2_pin_changed")
    custom_path = bounded_file(ROOT / CONTRACT2_REL)
    if digest(custom_path) != CONTRACT2_SHA:
        raise ValueError("custom_contract2_file_changed")
    # Preserve the profile hash in the audit without treating it as one of its
    # own dependencies. The hash is checked again against native capture below.
    groups = [{"profile": _relative(PROFILE), "profile_sha256": profile_sha,
               "profile_bytes": PROFILE.stat().st_size, "references": references}]
    for path in sorted(PROFILE.parent.glob("*.json")):
        if path.resolve() == PROFILE.resolve():
            continue
        previous_profile = require_mapping(read_json(path, max_bytes=MAX_PROFILE_BYTES), path.name)
        evidence = require_mapping(previous_profile.get("source_evidence"), path.name + ".source_evidence")
        previous_refs = []
        for name, record in evidence.items():
            if isinstance(record, str):
                record = {"path": "work/runtime/information-missions-20261024-001/" + name,
                          "sha256": record}
            previous_refs.append(_validate_profile_reference(
                record, label=path.name + "." + name,
                default_role="previous profile source evidence", seen=seen))
        groups.append({"profile": _relative(path), "profile_sha256": digest(path),
                       "profile_bytes": path.stat().st_size, "references": previous_refs})
    if sum(len(group["references"]) for group in groups[1:]) != 41:
        raise ValueError("previous_profile_source_reference_count_changed")
    return groups


def _validate_identity(identity: Any, label: str) -> dict[str, Any]:
    value = require_mapping(identity, label)
    require_true(value, "binding_verified", label)
    if value.get("installation_session_id") != EXPECTED_SESSION:
        raise ValueError(f"session_mismatch:{label}")
    for key in ("installation_creation_filetime", "process_creation_filetime"):
        if require_int(value.get(key), f"{label}.{key}", minimum=0) != 134373102720165920:
            raise ValueError(f"creation_time_mismatch:{label}.{key}")
    require_equal(value, "process_path_sha256", EXPECTED_EXE_SHA, label)
    return value


def _validate_guard(guard: Any, label: str) -> dict[str, Any]:
    value = require_mapping(guard, label)
    require_equal(value, "status", "observed", label)
    checks = value.get("checks")
    if isinstance(checks, dict) and any(item is not True for item in checks.values()):
        raise ValueError(f"guard_check_failed:{label}")
    return value


def _validate_values(values: Any, label: str) -> dict[str, int]:
    value = require_mapping(values, label)
    if set(value) != set(EXPECTED_VALUES):
        raise ValueError(f"power_value_keys_changed:{label}")
    result: dict[str, int] = {}
    for field, expected in EXPECTED_VALUES.items():
        actual = require_int(value.get(field), f"{label}.{field}")
        if actual != expected:
            raise ValueError(f"power_value_mismatch:{label}.{field}")
        result[field] = actual
    return result


def _validate_snapshot(snapshot: Any, label: str) -> dict[str, Any]:
    value = require_mapping(snapshot, label)
    require_equal(value, "status", "observed", label)
    game_date = require_mapping(value.get("game_date"), f"{label}.game_date")
    if require_int(game_date.get("value"), f"{label}.game_date.value") != EXPECTED_DATE:
        raise ValueError(f"date_mismatch:{label}")
    if not isinstance(game_date.get("raw_hex"), str) or not game_date["raw_hex"]:
        raise ValueError(f"game_date_raw_missing:{label}")
    if (len(game_date["raw_hex"]) != 8
            or int.from_bytes(bytes.fromhex(game_date["raw_hex"]), "little", signed=True) != EXPECTED_DATE):
        raise ValueError(f"game_date_raw_mismatch:{label}")
    _validate_values(value.get("values"), f"{label}.values")
    country_scan = require_mapping(value.get("country_scan"), f"{label}.country_scan")
    require_equal(country_scan, "status", "observed", f"{label}.country_scan")
    require_equal(country_scan, "requested_country", EXPECTED_COUNTRY, f"{label}.country_scan")
    raw_values = require_mapping(value.get("value_raw_hex"), label + ".value_raw_hex")
    for key, expected in EXPECTED_VALUES.items():
        raw = bytes.fromhex(raw_values[key])
        if len(raw) != 4 or int.from_bytes(raw, "little", signed=True) != expected:
            raise ValueError(f"power_raw_mismatch:{label}.{key}")
    runtime_guard = value.get("runtime_code_guard")
    if runtime_guard is not None:
        _validate_guard(runtime_guard, f"{label}.runtime_code_guard")
    return value


def _validate_profile_pin(capture: Mapping[str, Any], profile_sha: str,
                          profile_references: list[dict[str, Any]]) -> dict[str, Any]:
    profile = require_mapping(capture.get("profile"), "native capture profile")
    if not _valid_sha(profile.get("sha256")) or profile["sha256"].lower() != profile_sha:
        raise ValueError("native_capture_profile_sha_mismatch")
    if profile.get("max_bytes") != MAX_PROFILE_BYTES:
        raise ValueError("native_capture_profile_limit_changed")
    static = require_mapping(capture.get("static_contract_guard"), "native capture static_contract_guard")
    _validate_guard(static, "native capture static_contract_guard")
    if static.get("profile_sha256") is not None and static.get("profile_sha256") != profile_sha:
        raise ValueError("native_static_profile_sha_mismatch")
    expected_dependencies = {item["path"]: item["sha256"] for item in profile_references}
    recorded_dependencies = static.get("source_dependencies")
    if not isinstance(recorded_dependencies, list) or not recorded_dependencies:
        raise ValueError("native_static_dependencies_missing")
    for index, item in enumerate(recorded_dependencies):
        dependency = require_mapping(item, f"native static source_dependencies[{index}]")
        path = dependency.get("path")
        sha = dependency.get("sha256")
        if path not in expected_dependencies or sha != expected_dependencies[path]:
            raise ValueError(f"native_static_dependency_not_pinned:{path}")
    checks = static.get("dependency_hash_checks")
    if not isinstance(checks, dict) or any(value is not True for value in checks.values()):
        raise ValueError("native_static_dependency_hash_check_failed")
    return {"path": profile.get("path"), "sha256": profile_sha, "max_bytes": profile.get("max_bytes")}


def validate_native_capture(profile_audit: list[dict[str, Any]]) -> dict[str, Any]:
    capture = require_mapping(read_json(NATIVE_CAPTURE), "native capture")
    profile_sha = profile_audit[0]["profile_sha256"]
    require_equal(capture, "status", "observed", "native capture")
    require_true(capture, "completed", "native capture")
    require_true(capture, "read_only", "native capture")
    if capture.get("native_function_invoked") is not False:
        raise ValueError("native_capture_game_call_or_unknown")
    require_equal(capture, "country", EXPECTED_COUNTRY, "native capture")
    require_equal(capture, "unit", "monarch_points", "native capture")
    if require_int(capture.get("scale"), "native capture scale", minimum=0) != 1:
        raise ValueError("native_capture_scale_changed")
    target_build = require_mapping(capture.get("target_build"), "native capture target_build")
    require_equal(target_build, "version", EXPECTED_VERSION, "native capture target_build")
    require_equal(target_build, "expected_exe_sha256", EXPECTED_EXE_SHA, "native capture target_build")
    identity = _validate_identity(capture.get("identity"), "native capture identity")
    _validate_profile_pin(capture, profile_sha, profile_audit[0]["references"])
    for name in ("file_code_guard", "runtime_code_guard"):
        _validate_guard(capture.get(name), f"native capture {name}")
    _validate_snapshot(capture.get("before"), "native capture before")
    _validate_snapshot(capture.get("after"), "native capture after")
    doublepass = require_mapping(capture.get("doublepass"), "native capture doublepass")
    require_true(doublepass, "performed", "native capture doublepass")
    require_true(doublepass, "consistent", "native capture doublepass")
    if capture["before"] != capture["after"] or doublepass.get("mismatches") != []:
        raise ValueError("native_capture_raw_passes_differ")
    cleanup = require_mapping(capture.get("cleanup"), "native capture cleanup")
    handle_close = require_mapping(cleanup.get("handle_close"), "native capture cleanup.handle_close")
    require_equal(handle_close, "status", "closed", "native capture cleanup.handle_close")
    access = require_mapping(capture.get("access"), "native capture access")
    for key in ("native_game_calls", "target_memory_writes", "dll_injection", "ui_control",
                "date_advance", "save_or_reload"):
        if key in access and access[key] is not False:
            raise ValueError(f"native_capture_access_scope_changed:{key}")
    for key in ("rpm_bytes_requested", "rpm_calls"):
        if key in access:
            require_int(access[key], f"native capture access.{key}", minimum=0)
    if access.get("rpm_bytes_requested", 0) > 512 * 1024:
        raise ValueError("native_capture_rpm_total_budget_exceeded")
    values = _validate_values(capture.get("values"), "native capture values")
    report_identity = {
        "session_id": identity.get("installation_session_id"),
        "date_raw": capture["after"]["game_date"]["value"],
        "values": values,
        "profile_sha256": profile_sha,
        "reader_sha256": capture.get("probe_script_sha256"),
    }
    reader_sha = capture.get("probe_script_sha256")
    if reader_sha is not None:
        if not _valid_sha(reader_sha) or reader_sha.lower() != digest(READER_SOURCE):
            raise ValueError("native_capture_reader_sha_mismatch")
        report_identity["reader_sha256"] = reader_sha.lower()
    return {"capture": capture, "profile_sha256": profile_sha, "identity": report_identity,
            "sha256": digest(NATIVE_CAPTURE)}


def _validate_native_report(native: dict[str, Any], native_capture: dict[str, Any]) -> dict[str, Any]:
    require_equal(native, "status", "passed", "native runtime report")
    require_true(native, "pure_RPM", "native runtime report")
    if native.get("native_function_invoked") is not False:
        raise ValueError("native runtime report invoked a game function")
    require_equal(native, "session_id", EXPECTED_SESSION, "native runtime report")
    require_equal(native, "values", EXPECTED_VALUES, "native runtime report")
    if native.get("game_sha256") is not None:
        require_equal(native, "game_sha256", EXPECTED_EXE_SHA, "native runtime report")
    require_equal(native, "date_raw", EXPECTED_DATE, "native runtime report")
    for key in ("business_actions_submitted", "date_advance", "save_or_reload", "dll_installation"):
        if native.get(key) is not False:
            raise ValueError(f"native runtime report scope changed:{key}")
    raw_sha, raw_name = _hash_at(native, ("raw_capture_sha256", "rawCaptureSha256"))
    if raw_sha is None:
        raise ValueError("native_runtime_raw_capture_sha_missing")
    if raw_sha != native_capture["sha256"]:
        raise ValueError("native_runtime_raw_capture_sha_mismatch")
    reader_sha, reader_name = _hash_at(native, ("current_reader_sha256", "currentreaderSHA", "reader_sha256"))
    profile_sha, profile_name = _hash_at(native, ("current_profile_sha256", "currentprofileSHA", "profile_sha256"))
    # The raw capture is the authoritative fallback for reports produced by
    # the current capture script; explicit outer pins, when present, must agree.
    if reader_sha is None:
        reader_sha = native_capture["identity"].get("reader_sha256")
        reader_name = "native_capture.probe_script_sha256"
    if profile_sha is None:
        profile_sha = native_capture["profile_sha256"]
        profile_name = "native_capture.profile.sha256"
    if reader_sha is not None and reader_sha != digest(READER_SOURCE):
        raise ValueError("native_runtime_reader_sha_mismatch")
    if profile_sha != native_capture["profile_sha256"]:
        raise ValueError("native_runtime_profile_sha_mismatch")
    source_sha = native.get("source_sha256")
    if source_sha is not None:
        if not _valid_sha(source_sha) or source_sha.lower() != digest(CAPTURE_SCRIPT):
            raise ValueError("native_runtime_capture_script_sha_mismatch")
    return {"sha256": digest(NATIVE_REPORT),
            "raw_capture_sha256": raw_sha, "raw_capture_field": raw_name,
            "reader_sha256": reader_sha, "reader_sha_field": reader_name,
            "profile_sha256": profile_sha, "profile_sha_field": profile_name}


def _validate_source_map(source_files: Any, label: str) -> list[dict[str, Any]]:
    if not isinstance(source_files, dict):
        raise ValueError(f"source_files_missing:{label}")
    checked: list[dict[str, Any]] = []
    for name, raw in source_files.items():
        if isinstance(raw, str):
            relative, expected = name, raw
        else:
            item = require_mapping(raw, f"{label}.{name}")
            relative, expected = item.get("path"), item.get("sha256")
        if not isinstance(relative, str) or not _valid_sha(expected):
            raise ValueError(f"source_file_pin_invalid:{label}.{name}")
        source = bounded_file(ROOT / relative)
        actual = digest(source)
        if actual != expected.lower():
            raise ValueError(f"source_file_changed:{relative}")
        checked.append({"name": name, "path": _relative(source), "bytes": source.stat().st_size,
                        "sha256": actual})
    return checked


def _validate_live(live: dict[str, Any], native: dict[str, Any]) -> dict[str, Any]:
    require_equal(live, "status", "passed", "live acceptance report")
    require_true(live, "points_reader_pure_RPM", "live acceptance report")
    require_true(live, "mixed_prestige_query_invokes_readonly_native_predicates", "live acceptance report")
    require_equal(live, "session_id", EXPECTED_SESSION, "live acceptance report")
    require_equal(live, "values", EXPECTED_VALUES, "live acceptance report")
    periodic = require_int(live.get("periodic_results"), "live periodic_results", minimum=0)
    if periodic < 2:
        raise ValueError("live_periodic_samples_too_few")
    checks = require_mapping(live.get("checks"), "live acceptance checks")
    if not checks or any(value is not True for value in checks.values()):
        raise ValueError("live_acceptance_check_failed")
    if live.get("business_actions_submitted") is not None and live["business_actions_submitted"] is not False:
        raise ValueError("live_acceptance_submitted_business_action")
    configured = live.get("configured_field_counts")
    if configured is not None and configured != EXPECTED_COVERAGE["field_counts"]:
        raise ValueError("live_configured_field_counts_changed")
    source_files = _validate_source_map(live.get("source_files"), "live acceptance report")
    source_sha = live.get("source_sha256")
    if not _valid_sha(source_sha) or source_sha.lower() != digest(ROOT / "work/validate_information_country_powers.py"):
        raise ValueError("live_acceptance_validator_sha_mismatch")
    reference = live.get("native_reference_sha256")
    if reference != native["sha256"]:
        raise ValueError("live_native_reference_sha_mismatch")
    return {"sha256": digest(LIVE_REPORT), "periodic_results": periodic,
            "checks": sorted(checks), "native_reference_sha256": reference,
            "native_report_sha256": native["sha256"], "source_sha256": source_sha,
            "source_files": source_files}


def _validate_save(save: dict[str, Any]) -> dict[str, Any]:
    require_true(save, "save_is_recorded", "save cross-check")
    require_true(save, "not_a_live_state_fallback", "save cross-check")
    if save.get("world_generation_verified") is not False:
        raise ValueError("save_world_generation_must_remain_unverified")
    require_equal(save, "sha256", "ffa91dbd2a2d544b18d586a895bb9b0c2b90e94ece47b2c74507555b8f58c2e0", "save cross-check")
    require_equal(save, "expected_save_sha256", save["sha256"], "save cross-check")
    date = require_mapping(save.get("date"), "save cross-check date")
    require_equal(date, "date", "1455.11.13", "save cross-check date")
    powers = require_mapping(save.get("powers"), "save cross-check powers")
    vector = powers.get("ordered_vector")
    if vector != [EXPECTED_VALUES["administrative"], EXPECTED_VALUES["diplomatic"], EXPECTED_VALUES["military"]]:
        raise ValueError("save_power_vector_changed")
    if save.get("component_order_verified") is not False:
        raise ValueError("save_component_order_must_remain_unverified")
    return {"sha256": digest(SAVE_REPORT), "save_sha256": save["sha256"],
            "date": date["date"], "ordered_vector": vector,
            "component_order_verified": save["component_order_verified"],
            "world_generation_verified": save["world_generation_verified"]}


def validate_reports(profile_audit: list[dict[str, Any]]) -> dict[str, Any]:
    native_capture = validate_native_capture(profile_audit)
    native_report = _validate_native_report(read_json(NATIVE_REPORT, max_bytes=MAX_ARCHIVE_BYTES), native_capture)
    live = _validate_live(read_json(LIVE_REPORT), native_report)
    save = _validate_save(read_json(SAVE_REPORT))
    installation: dict[str, Any] | None = None
    if INSTALLATION.is_file():
        installation = require_mapping(read_json(INSTALLATION), "installation manifest")
        if installation.get("game_sha256") is not None:
            require_equal(installation, "game_sha256", EXPECTED_EXE_SHA, "installation")
        if installation.get("session_id") is not None:
            require_equal(installation, "session_id", EXPECTED_SESSION, "installation")
    return {
        "identity": {
            "game_sha256": EXPECTED_EXE_SHA, "version": EXPECTED_VERSION,
            "session_id": EXPECTED_SESSION, "game_date_raw": EXPECTED_DATE,
            "country": EXPECTED_COUNTRY, "values": EXPECTED_VALUES,
        },
        "report_sha256": {
            "native_capture": native_capture["sha256"],
            "native_runtime": native_report["sha256"],
            "live": live["sha256"], "save": save["sha256"],
        },
        "native_capture": native_capture,
        "native_runtime": native_report,
        "live": live,
        "save": save,
        "installation": {
            "path": _relative(INSTALLATION), "sha256": digest(INSTALLATION)
        } if installation is not None else None,
    }


def build_offline_catalog() -> dict[str, Any]:
    """Import catalog sources only; this function opens no live session."""
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    from bridge.information.composite import CompositeSource
    from bridge.information.country_state import NativeCountryStateSource
    from bridge.information.mission_definitions import MissionDefinitionIndex
    from bridge.information.missions import MissionInformationSource, NativeMissionReader
    from bridge.information.sources import DiplomacySource
    from bridge.information.static_data import StaticTradeSource
    from bridge.information.subject_relations import NativeSubjectRelationSource

    primary = DiplomacySource(observer=EXPECTED_COUNTRY)
    adapters = [
        NativeCountryStateSource(primary), NativeSubjectRelationSource(primary),
        StaticTradeSource(context_provider=primary.context),
        MissionInformationSource(primary, MissionDefinitionIndex(), NativeMissionReader(primary)),
    ]
    topics = CompositeSource(primary, adapters).catalog()
    counts = Counter(field["coverage"] for topic in topics for field in topic["fields"].values())
    summary = {
        "schema_version": 1,
        "topic_count": len(topics),
        "field_count": sum(len(topic["fields"]) for topic in topics),
        "available_topic_count": sum(topic["status"] == "available" for topic in topics),
        "field_counts": dict(counts),
        "topics": topics,
        "configuration": {
            "native_country_state": True, "native_subject_relations": True,
            "static_trade": True, "mission_game_data": True,
            "live_session_opened": False,
            "implementation_coverage_is_not_full_live_acceptance": True,
        },
    }
    if {key: summary[key] for key in ("topic_count", "field_count", "available_topic_count")} != {
        key: EXPECTED_COVERAGE[key] for key in ("topic_count", "field_count", "available_topic_count")
    } or counts != Counter(EXPECTED_COVERAGE["field_counts"]):
        raise ValueError("offline_catalog_coverage_changed")
    if not any(topic.get("topic_id") == "N06" and topic.get("status") == "available"
               and topic.get("fields", {}).get("monarch_points", {}).get("coverage") == "available"
               for topic in topics):
        raise ValueError("N06_monarch_points_not_available")
    return summary


def compile_fingerprints() -> dict[str, Any]:
    paths = sorted((ROOT / "bridge/information").glob("*.py"))
    paths.extend(path for path in WORK_SOURCES if path not in paths)
    records: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="information-powers-compile-") as temporary:
        target = Path(temporary)
        for path in paths:
            source = bounded_file(path)
            py_compile.compile(str(source), cfile=str(target / (source.name + ".pyc")), doraise=True)
            records.append({"path": _relative(source), "bytes": source.stat().st_size,
                            "sha256": digest(source)})
    return {"status": "passed", "file_count": len(records), "files": records,
            "scope": ["bridge/information/*.py", "country-power batch work scripts"]}


def validate_previous_manifest() -> dict[str, Any]:
    previous = bounded_file(PREVIOUS)
    actual = digest(previous)
    if actual != PREVIOUS_SHA:
        raise ValueError("previous_delivery_manifest_changed")
    return {"path": _relative(previous), "sha256": actual, "recursive_archive_copy": False}


def validate_fixture() -> dict[str, Any]:
    """Bind the self-contained recorded fixture to the unchanged live files."""
    from bridge.information.model import canonical
    path = ROOT / "bridge/tests/fixtures/information_country_powers_live_1374.json"
    fixture = require_mapping(read_json(path), "recorded powers fixture")
    provenance = require_mapping(fixture.get("provenance"), "recorded fixture provenance")
    for key, expected in (("mode", "recorded"), ("original_mode", "live"),
                          ("game_version", EXPECTED_VERSION), ("observer", EXPECTED_COUNTRY),
                          ("session_id", EXPECTED_SESSION), ("game_date", EXPECTED_DATE)):
        require_equal(provenance, key, expected, "recorded fixture")
    if fixture.get("native_capture") != read_json(NATIVE_CAPTURE):
        raise ValueError("fixture_native_capture_changed")
    if fixture.get("native_report") != read_json(NATIVE_REPORT):
        raise ValueError("fixture_native_report_changed")
    if fixture.get("mcp_report") != read_json(LIVE_REPORT):
        raise ValueError("fixture_final_mcp_report_changed")
    if (fixture.get("mcp_manual_result") != read_json(LIVE_REPORT.parent / "manual-result.json")
            or fixture.get("mcp_manual_context") != fixture["mcp_manual_result"]["context"]):
        raise ValueError("fixture_final_mcp_manual_changed")
    expected = hashlib.sha256(canonical(fixture["native_capture"]).encode("utf-8")).hexdigest()
    require_equal(provenance, "capture_canonical_sha256", expected, "recorded fixture")
    records = [provenance[key] for key in ("source_capture", "source_report", "mcp_manual_result", "mcp_report")]
    records.extend(require_mapping(provenance.get("artifacts"), "fixture artifacts").values())
    for record in records:
        source = bounded_file(ROOT / record["path"])
        if digest(source) != record["sha256"] or ("bytes" in record and source.stat().st_size != record["bytes"]):
            raise ValueError("fixture_source_pin_changed:" + record["path"])
    return {"path": _relative(path), "sha256": digest(path), "bytes": path.stat().st_size,
            "mode": "recorded", "capture_canonical_sha256": expected,
            "metadata_correction": {"path": _relative(STAGE / "fixture-metadata-correction-001.json"),
                                    "sha256": digest(STAGE / "fixture-metadata-correction-001.json")}}


def run_validation(*, write_artifacts: bool = True) -> dict[str, Any]:
    profiles = validate_profiles()
    reports = validate_reports(profiles)
    coverage = build_offline_catalog()
    fixture = validate_fixture()
    compile_audit = compile_fingerprints()
    previous = validate_previous_manifest()
    result = {"reports": reports, "profile_references": profiles,
              "coverage": coverage, "compile_audit": compile_audit,
              "previous_manifest": previous, "fixture": fixture}
    if write_artifacts:
        write_json(STAGE / "coverage.json", coverage)
        write_json(STAGE / "compile-audit.json", compile_audit)
        write_json(STAGE / "source-audit.json", {
            "status": "passed", "profile_reference_groups": profiles,
            "current_source_fingerprints": compile_audit["files"],
            "native_reports": reports["report_sha256"],
            "native_runtime_pins": reports["native_runtime"],
            "identity": reports["identity"],
            "fixture": fixture,
        })
    return result


def main() -> int:
    result = run_validation(write_artifacts=True)
    print(json.dumps({
        "status": "passed",
        "reports": result["reports"]["report_sha256"],
        "catalog": {key: result["coverage"][key] for key in (
            "topic_count", "field_count", "available_topic_count", "field_counts")},
        "profile_groups": len(result["profile_references"]),
        "compiled": result["compile_audit"]["file_count"],
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
