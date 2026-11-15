"""Bounded audit and explicit archive entry point for the information recovery batch.

The script is deliberately independent from the older domestic-pressure
verifiers.  It validates the current three-field contract, the live-005
identity chain, the recorded save cross-check, the current coverage export,
the batch-11 baseline, and the battle-research pins.  ``--audit`` writes only
an audit record.  ``--archive`` is an explicit second step and copies an
enumerated source list into a new delivery directory; it never walks an old
delivery tree.

No game, process, DLL, RPM, REA, or dispatch operation is performed here.
All reads are bounded to 16 MiB per file.  A historical save mentioned by the
cross-check is intentionally represented by its recorded SHA and metadata;
the 43 MiB save itself is outside the archive budget and is never opened.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sys
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]
MAX_SINGLE_BYTES = 16 * 1024 * 1024
MAX_TOTAL_BYTES = 128 * 1024 * 1024
EXPECTED_EXE_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
EXPECTED_GAME_VERSION = "1.37.4"
EXPECTED_DLL_SHA256 = "d80ef39d66d263788c0af4df0892b4ff781e5e3b3f9aea7ebe33759327e457db"
EXPECTED_PROFILE_SHA256 = "b727bcd112ace025fcbc0fce78e6194cbb5055642ff12fd85280356e8347d9fd"
EXPECTED_CONTRACT_SHA256 = "902bef470421f8abe3ac4636ce13cb2d2c57f60e2985fcc7c40a28ca89bcaeaf"
EXPECTED_BATCH11_MANIFEST_SHA256 = "aa50a2a5b2c58097e5444829836e902994c8ebbf5d03d55aa59ae755717b517a"
EXPECTED_BASE_MCP_VALIDATOR_SHA256 = "b23811dd3a64bf9d327b757250bf5fa1f0860df3526c1548c146d0a1b53ed7e9"
EXPECTED_LIVE_MCP_VALIDATOR_SHA256 = "e7c7b74cef2a7808aef149404881da4efb3c3651537a4a23d784523083a54dc1"
EXPECTED_FIELDS = ("stability", "war_exhaustion", "corruption")
EXPECTED_UNIMPLEMENTED = ("overextension", "unrest")
EXPECTED_FIELD_META = {
    "stability": {"unit": "stability", "scale": 1000},
    "war_exhaustion": {"unit": "war_exhaustion", "scale": 1000},
    "corruption": {"unit": "corruption", "scale": 1000},
}
EXPECTED_GUARDS = {
    "compiled_token_stability",
    "compiled_token_war_exhaustion",
    "compiled_token_corruption",
    "compiled_token_religious_unity",
    "country_save_writer",
    "fixed_point_copy",
    "fixed_point_writer",
    "signed_fixed_point_formatter",
    "save_key_resolver",
    "compiled_save_token_initializer",
    "save_key_vector",
}
EXPECTED_COVERAGE = {
    "topic_count": 74,
    "field_count": 397,
    "available_topic_count": 35,
    "callable_topic_count": 35,
    "field_counts": {"available": 54, "partial": 107, "planned": 236},
}


class AuditError(ValueError):
    """An input is malformed or fails a fail-closed audit guard."""


def _is_int(value: Any) -> bool:
    return type(value) is int


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def _hex_sha(value: Any, label: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", value):
        raise AuditError(f"{label} must be a 64-character SHA-256")
    return value.lower()


def _root_relative(value: str | os.PathLike[str]) -> tuple[str, Path]:
    """Resolve a report path without permitting workspace escape."""

    raw = str(value).replace("\\", "/")
    candidate = Path(raw)
    if candidate.is_absolute():
        resolved = candidate.resolve(strict=False)
    else:
        pieces = [part for part in raw.split("/") if part not in ("", ".")]
        if ".." in pieces:
            raise AuditError(f"path escapes workspace: {value!r}")
        resolved = (ROOT / Path(*pieces)).resolve(strict=False)
    try:
        rel = resolved.relative_to(ROOT)
    except ValueError as exc:
        raise AuditError(f"path escapes workspace: {value!r}") from exc
    return rel.as_posix(), resolved


def _bounded_path(value: str | os.PathLike[str], *, allow_missing: bool = False) -> tuple[str, Path]:
    rel, path = _root_relative(value)
    if not path.exists():
        if allow_missing:
            return rel, path
        raise AuditError(f"missing input: {rel}")
    if not path.is_file():
        raise AuditError(f"input is not a regular file: {rel}")
    size = path.stat().st_size
    if size > MAX_SINGLE_BYTES:
        raise AuditError(f"file exceeds {MAX_SINGLE_BYTES} byte bound: {rel} ({size})")
    return rel, path


def _load_json(value: str | os.PathLike[str]) -> tuple[str, Path, Any]:
    rel, path = _bounded_path(value)
    try:
        raw = path.read_bytes()
        data = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise AuditError(f"cannot read JSON {rel}: {exc}") from exc
    return rel, path, data


def _same_path(a: Any, b: Path) -> bool:
    try:
        _, path = _root_relative(str(a))
    except AuditError:
        return False
    return path == b.resolve(strict=False)


def _short(value: Any, limit: int = 500) -> Any:
    text = repr(value)
    return value if len(text) <= limit else text[: limit - 3] + "..."


class Audit:
    def __init__(self) -> None:
        self.errors: list[str] = []
        self.warnings: list[str] = []
        self.inputs: dict[str, dict[str, Any]] = {}

    def require(self, condition: bool, message: str) -> bool:
        if not condition:
            self.errors.append(message)
        return condition

    def warn(self, message: str) -> None:
        self.warnings.append(message)

    def input(self, label: str, value: str | os.PathLike[str], *, json_input: bool = False) -> Any:
        try:
            rel, path = _bounded_path(value)
            digest = _sha256(path)
            item = {"path": rel, "bytes": path.stat().st_size, "sha256": digest}
            self.inputs[label] = item
            if json_input:
                return _load_json(value)[2]
            return path
        except AuditError as exc:
            self.errors.append(f"{label}: {exc}")
            return None


def _dict(value: Any, label: str, audit: Audit) -> dict[str, Any]:
    if not isinstance(value, dict):
        audit.errors.append(f"{label}: expected object, got {type(value).__name__}")
        return {}
    return value


def _list(value: Any, label: str, audit: Audit) -> list[Any]:
    if not isinstance(value, list):
        audit.errors.append(f"{label}: expected list, got {type(value).__name__}")
        return []
    return value


def _all_true(mapping: Any, label: str, audit: Audit, expected: set[str] | None = None) -> bool:
    if not isinstance(mapping, dict):
        audit.errors.append(f"{label}: expected boolean check object")
        return False
    if expected is not None:
        audit.require(set(mapping) == expected, f"{label}: check names changed: {sorted(set(mapping) ^ expected)}")
    ok = True
    for key, value in mapping.items():
        if type(value) is not bool:
            audit.errors.append(f"{label}.{key}: value is not a boolean")
            ok = False
        elif not value:
            audit.errors.append(f"{label}.{key}: false")
            ok = False
    return ok


def _field_values(data: Any, *, label: str, audit: Audit) -> dict[str, int]:
    values = _dict(data.get("values") if isinstance(data, dict) else None, f"{label}.values", audit)
    audit.require(set(values) == set(EXPECTED_FIELDS), f"{label}.values fields are not exactly {EXPECTED_FIELDS}")
    result: dict[str, int] = {}
    for field in EXPECTED_FIELDS:
        value = values.get(field)
        if not _is_int(value):
            audit.errors.append(f"{label}.values.{field}: expected non-bool int")
        else:
            result[field] = value
    return result


def _context_key(context: Any, *, label: str, audit: Audit) -> dict[str, Any]:
    ctx = _dict(context, label, audit)
    for key in ("complete", "mode", "status", "observer", "game_version", "game_sha256", "dll_sha256", "session_id", "game_date", "game_date_raw"):
        audit.require(key in ctx, f"{label}: missing {key}")
    audit.require(ctx.get("complete") is True, f"{label}.complete is not true")
    audit.require(ctx.get("mode") == "live", f"{label}.mode is not live")
    audit.require(ctx.get("status") == "ready", f"{label}.status is not ready")
    audit.require(ctx.get("observer") == "FRA", f"{label}.observer is not FRA")
    audit.require(ctx.get("game_version") == EXPECTED_GAME_VERSION, f"{label}.game_version mismatch")
    audit.require(ctx.get("game_sha256") == EXPECTED_EXE_SHA256, f"{label}.game_sha256 mismatch")
    audit.require(ctx.get("dll_sha256") == EXPECTED_DLL_SHA256, f"{label}.dll_sha256 mismatch")
    if not _is_int(ctx.get("game_date")) or not _is_int(ctx.get("game_date_raw")):
        audit.errors.append(f"{label}: date values must be integer")
    else:
        audit.require(ctx["game_date"] == ctx["game_date_raw"], f"{label}: game_date/raw mismatch")
    return {key: ctx.get(key) for key in ("mode", "status", "observer", "game_version", "game_sha256", "dll_sha256", "session_id", "game_date", "game_date_raw")}


def _compare_context(a: dict[str, Any], b: dict[str, Any], label: str, audit: Audit) -> None:
    for key in ("mode", "status", "observer", "game_version", "game_sha256", "dll_sha256", "session_id", "game_date", "game_date_raw"):
        audit.require(a.get(key) == b.get(key), f"{label}: context {key} differs")


def _identity_from_installation(installation: dict[str, Any], audit: Audit) -> dict[str, Any]:
    for key in ("pid", "creation_filetime", "game_sha256", "session_id"):
        audit.require(key in installation, f"installation missing {key}")
    if not _is_int(installation.get("pid")) or not _is_int(installation.get("creation_filetime")):
        audit.errors.append("installation pid/creation_filetime must be non-bool integers")
    audit.require(installation.get("game_sha256") == EXPECTED_EXE_SHA256, "installation game SHA mismatch")
    audit.require(isinstance(installation.get("session_id"), str) and bool(installation["session_id"]), "installation session_id missing")
    audit.require(installation.get("installation_returncode") == 0, "installation returncode is not zero")
    audit.require(installation.get("installation_attempted") is True, "installation_attempted is not true")
    return {
        "pid": installation.get("pid"),
        "creation_filetime": installation.get("creation_filetime"),
        "session_id": installation.get("session_id"),
        "game_sha256": installation.get("game_sha256"),
        "dll_sha256": installation.get("dll_sha256"),
    }


def _assert_identity(identity: Any, expected: dict[str, Any], label: str, audit: Audit) -> None:
    obj = _dict(identity, label, audit)
    audit.require(obj.get("binding_verified") is True, f"{label}.binding_verified is not true")
    values = {
        "pid": obj.get("installation_pid", obj.get("pid")),
        "creation_filetime": obj.get("installation_creation_filetime", obj.get("creation_filetime")),
        "session_id": obj.get("installation_session_id", obj.get("session_id")),
        "game_sha256": obj.get("process_path_sha256", obj.get("game_sha256")),
    }
    for key, value in values.items():
        audit.require(value == expected.get(key), f"{label}.{key} does not match installation identity")
    if "process_creation_filetime" in obj:
        audit.require(obj.get("process_creation_filetime") == expected.get("creation_filetime"), f"{label}.process_creation_filetime mismatch")
    audit.require(obj.get("process_path_sha256_matches_expected") is True, f"{label}.process_path_sha256_matches_expected is not true")
    audit.require(obj.get("process_creation_matches_installation") is True, f"{label}.process_creation_matches_installation is not true")


def _validate_profile_contract(
    audit: Audit,
    profile_path: str,
    contract_path: str,
) -> tuple[dict[str, Any], dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    profile_rel, profile_file, profile = _load_json(profile_path)
    contract_rel, contract_file, contract = _load_json(contract_path)
    profile_sha = _sha256(profile_file)
    contract_sha = _sha256(contract_file)
    audit.inputs["profile"] = {"path": profile_rel, "bytes": profile_file.stat().st_size, "sha256": profile_sha}
    audit.inputs["contract"] = {"path": contract_rel, "bytes": contract_file.stat().st_size, "sha256": contract_sha}
    audit.require(profile_sha == EXPECTED_PROFILE_SHA256, "current domestic-pressure profile SHA changed")
    audit.require(contract_sha == EXPECTED_CONTRACT_SHA256, "current domestic-pressure contract SHA changed")
    audit.require(profile.get("profile_id") == "domestic-pressure-memory-1374", "profile_id mismatch")
    audit.require(profile.get("profile_version") == 3, "profile_version is not 3")
    audit.require(profile.get("game_version") == EXPECTED_GAME_VERSION, "profile game_version mismatch")
    executable = _dict(profile.get("executable"), "profile.executable", audit)
    audit.require(executable.get("sha256") == EXPECTED_EXE_SHA256, "profile executable SHA mismatch")
    audit.require(profile.get("contract_sha256") == contract_sha, "profile contract pin mismatch")
    scalars = _dict(profile.get("scalars"), "profile.scalars", audit)
    audit.require(set(scalars) == set(EXPECTED_FIELDS), "profile scalar set is not exactly the three current fields")
    for field, metadata in EXPECTED_FIELD_META.items():
        row = _dict(scalars.get(field), f"profile.scalars.{field}", audit)
        for key, value in metadata.items():
            audit.require(row.get(key) == value, f"profile scalar {field}.{key} mismatch")
        audit.require(_is_int(row.get("width")) and row.get("width") == 4, f"profile scalar {field}.width mismatch")
        audit.require(row.get("signed") is True, f"profile scalar {field}.signed is not true")
    save_tokens = _dict(profile.get("save_tokens"), "profile.save_tokens", audit)
    tokens = _dict(save_tokens.get("tokens"), "profile.save_tokens.tokens", audit)
    audit.require(set(tokens) == set(EXPECTED_FIELDS), "profile save token set is not exactly the three current fields")
    contract_fields = _dict(contract.get("fields"), "contract.fields", audit)
    audit.require(set(contract_fields) == set(EXPECTED_FIELDS), "contract.fields contains a non-current field")
    game = _dict(contract.get("game"), "contract.game", audit)
    audit.require(game.get("version") == EXPECTED_GAME_VERSION, "contract game version mismatch")
    audit.require(game.get("exe_sha256") == EXPECTED_EXE_SHA256, "contract executable SHA mismatch")
    excluded = _dict(contract.get("excluded_fields"), "contract.excluded_fields", audit)
    for name in ("religious_unity", "overextension", "unrest"):
        audit.require(name in excluded, f"contract exclusion missing {name}")
    audit.require("religious_unity" not in contract_fields, "religious_unity must remain excluded from current contract")
    guards = _list(profile.get("code_guards"), "profile.code_guards", audit)
    names = {item.get("name") for item in guards if isinstance(item, dict)}
    audit.require(len(guards) == 11 and names == EXPECTED_GUARDS, "profile code guard set is not the expected 11")
    for item in guards:
        if not isinstance(item, dict):
            continue
        try:
            actual = bytes.fromhex(item.get("hex", ""))
            expected_sha = _hex_sha(item.get("sha256"), f"profile.code_guards.{item.get('name')}.sha256")
            audit.require(hashlib.sha256(actual).hexdigest() == expected_sha, f"profile code guard {item.get('name')} hex/SHA mismatch")
        except (ValueError, AuditError) as exc:
            audit.errors.append(str(exc))
    provenance = _dict(profile.get("provenance"), "profile.provenance", audit)
    dependencies = _list(provenance.get("dependencies"), "profile.provenance.dependencies", audit)
    dep_paths: list[dict[str, Any]] = []
    seen: set[str] = set()
    for dep in dependencies:
        if not isinstance(dep, dict) or not isinstance(dep.get("path"), str):
            audit.errors.append("profile provenance contains malformed dependency")
            continue
        try:
            rel, path = _bounded_path(dep["path"])
            actual_sha = _sha256(path)
            expected_sha = _hex_sha(dep.get("sha256"), f"dependency {rel}.sha256")
            audit.require(actual_sha == expected_sha, f"profile dependency changed: {rel}")
            audit.require(rel not in seen, f"duplicate profile dependency: {rel}")
            seen.add(rel)
            dep_paths.append({"path": rel, "bytes": path.stat().st_size, "sha256": actual_sha, "role": dep.get("role")})
        except AuditError as exc:
            audit.errors.append(str(exc))
    audit.require(provenance.get("contract_sha256") == contract_sha, "profile provenance contract pin mismatch")
    source_evidence = _dict(profile.get("source_evidence"), "profile.source_evidence", audit)
    audit.require(len(source_evidence) == 7, "profile source_evidence must retain all seven guarded records")
    for name, row in source_evidence.items():
        if not isinstance(row, dict):
            audit.errors.append(f"source_evidence.{name} is not an object")
            continue
        try:
            rel, path = _bounded_path(row.get("path"))
            expected_sha = _hex_sha(row.get("sha256"), f"source_evidence.{name}.sha256")
            audit.require(_sha256(path) == expected_sha, f"source evidence changed: {rel}")
        except AuditError as exc:
            audit.errors.append(str(exc))
    # Reuse the bounded static profile walker for the complete seven-profile
    # source graph.  N04's 19 runtime dependencies above are only one group;
    # the archive must pin every source-evidence/dependency occurrence from
    # all groups, including repeated paths.  The helper does not walk old
    # delivery trees or run any game/native operation.
    all_profile_refs: list[dict[str, Any]] = []
    try:
        if str(ROOT) not in sys.path:
            sys.path.insert(0, str(ROOT))
        from work.verify_information_domestic_pressure import validate_static_profiles

        groups = validate_static_profiles(Path(profile_path), Path(contract_path))
        audit.require(len(groups) == 7, f"static profile group count changed: {len(groups)}")
        for group in groups:
            refs = group.get("references", []) if isinstance(group, dict) else []
            audit.require(isinstance(refs, list), f"profile references malformed: {group.get('profile_id') if isinstance(group, dict) else group!r}")
            if isinstance(refs, list):
                for ref in refs:
                    if not isinstance(ref, dict) or not isinstance(ref.get("path"), str):
                        audit.errors.append("profile reference is malformed")
                        continue
                    try:
                        rel, path = _bounded_path(ref["path"])
                        expected_sha = _hex_sha(ref.get("sha256"), f"profile reference {rel}.sha256")
                        actual_sha = _sha256(path)
                        audit.require(actual_sha == expected_sha, f"profile reference changed: {rel}")
                        if ref.get("bytes") is not None:
                            audit.require(_is_int(ref.get("bytes")) and path.stat().st_size == ref.get("bytes"), f"profile reference byte count changed: {rel}")
                        all_profile_refs.append({"path": rel, "bytes": path.stat().st_size, "sha256": actual_sha, "role": ref.get("role"), "profile_id": group.get("profile_id")})
                    except AuditError as exc:
                        audit.errors.append(str(exc))
        reference_count = len(all_profile_refs)
        audit.require(reference_count == 80, f"profile reference occurrence count changed: {reference_count}")
        audit.inputs["profile_groups"] = {
            "count": len(groups),
            "reference_occurrences": reference_count,
            "profiles": [{"profile_id": group.get("profile_id"), "path": group.get("path"), "sha256": group.get("sha256"), "reference_count": len(group.get("references", []))} for group in groups if isinstance(group, dict)],
        }
    except Exception as exc:
        audit.errors.append(f"all profile static audit failed: {type(exc).__name__}: {exc}")
    return profile, contract, dep_paths, all_profile_refs


def _validate_snapshot(snapshot: Any, label: str, audit: Audit) -> int | None:
    obj = _dict(snapshot, label, audit)
    audit.require(obj.get("status") == "observed", f"{label}.status is not observed")
    game_date = _dict(obj.get("game_date"), f"{label}.game_date", audit)
    value = game_date.get("value")
    raw_hex = game_date.get("raw_hex")
    if not _is_int(value):
        audit.errors.append(f"{label}.game_date.value is not an integer")
    if not isinstance(raw_hex, str) or not re.fullmatch(r"[0-9a-fA-F]{8}", raw_hex):
        audit.errors.append(f"{label}.game_date.raw_hex is not four-byte hex")
    elif _is_int(value):
        audit.require(int.from_bytes(bytes.fromhex(raw_hex), "little", signed=False) == (value & 0xFFFFFFFF), f"{label}.game_date raw/value mismatch")
    scan = _dict(obj.get("country_scan"), f"{label}.country_scan", audit)
    audit.require(scan.get("status") == "observed", f"{label}.country_scan.status is not observed")
    audit.require(scan.get("requested_country") == "FRA", f"{label}.country_scan.requested_country mismatch")
    matches = scan.get("matches")
    if not isinstance(matches, list):
        audit.errors.append(f"{label}.country_scan.matches is not a list")
    else:
        audit.require(len(matches) == 1, f"{label}.country_scan must have exactly one match")
        if matches:
            audit.require(matches[0].get("tag") == "FRA", f"{label}.country_scan match is not FRA")
    return value if _is_int(value) else None


def _validate_guards(capture: dict[str, Any], profile: dict[str, Any], audit: Audit) -> None:
    static = _dict(capture.get("static_contract_guard"), "native.static_contract_guard", audit)
    audit.require(static.get("status") == "observed", "static contract guard status is not observed")
    static_checks = {"profile_sha256", "profile_id", "game_version", "game_sha256", "supported_country", "globals", "scalar_fields_exact", "scalar_widths", "scalar_signed", "scalar_metadata", "save_token_schema", "save_token_key_ids_bounded", "save_token_names", "code_guards", "provenance_dependencies"}
    _all_true(static.get("checks"), "native.static_contract_guard.checks", audit, static_checks)
    audit.require(static.get("unknown_conditions") == [], "native static contract guard has unknown conditions")
    deps = _list(static.get("source_dependencies"), "native.static_contract_guard.source_dependencies", audit)
    expected_deps = profile.get("provenance", {}).get("dependencies", [])
    dep_pairs = {(row.get("path"), row.get("sha256")) for row in deps if isinstance(row, dict)}
    expected_pairs = {(row.get("path"), row.get("sha256")) for row in expected_deps if isinstance(row, dict)}
    audit.require(dep_pairs == expected_pairs, "native static dependency list differs from profile provenance")
    checks = _dict(static.get("dependency_hash_checks"), "native.static_contract_guard.dependency_hash_checks", audit)
    audit.require(set(checks) == {row.get("path") for row in expected_deps if isinstance(row, dict)}, "native dependency check names differ")
    _all_true(checks, "native.static_contract_guard.dependency_hash_checks", audit)

    profile_guards = {row.get("name"): row for row in profile.get("code_guards", []) if isinstance(row, dict)}
    file_guard = _dict(capture.get("file_code_guard"), "native.file_code_guard", audit)
    audit.require(file_guard.get("status") == "observed", "file code guard status is not observed")
    _all_true(file_guard.get("checks"), "native.file_code_guard.checks", audit, EXPECTED_GUARDS)
    audit.require(file_guard.get("unknown_conditions") == [], "native file code guard has unknown conditions")
    _validate_code_records(file_guard.get("records"), profile_guards, "native.file_code_guard.records", audit)

    runtime = _dict(capture.get("runtime_code_guard"), "native.runtime_code_guard", audit)
    passes = _list(runtime.get("passes"), "native.runtime_code_guard.passes", audit)
    audit.require(len(passes) == 2, "runtime code guard must contain two passes")
    for index, row in enumerate(passes):
        row = _dict(row, f"native.runtime_code_guard.passes[{index}]", audit)
        audit.require(row.get("status") == "observed", f"runtime code guard pass {index} not observed")
        _all_true(row.get("checks"), f"runtime code guard pass {index}.checks", audit, EXPECTED_GUARDS)
        audit.require(row.get("unknown_conditions") == [], f"runtime code guard pass {index} has unknown conditions")
        _validate_code_records(row.get("records"), profile_guards, f"runtime code guard pass {index}.records", audit)

    save = _dict(capture.get("save_token_guard"), "native.save_token_guard", audit)
    save_passes = _list(save.get("passes"), "native.save_token_guard.passes", audit)
    audit.require(len(save_passes) == 2, "save token guard must contain two passes")
    for index, row in enumerate(save_passes):
        row = _dict(row, f"native.save_token_guard.passes[{index}]", audit)
        audit.require(row.get("status") == "observed", f"save token guard pass {index} not observed")
        _all_true(row.get("checks"), f"save token guard pass {index}.checks", audit, set(EXPECTED_FIELDS))
        audit.require(row.get("unknown_conditions") == [], f"save token guard pass {index} has unknown conditions")
        records = _dict(row.get("records"), f"native.save_token_guard.passes[{index}].records", audit)
        audit.require(set(records) == set(EXPECTED_FIELDS), f"save token guard pass {index} has non-current token")
        for field in EXPECTED_FIELDS:
            rec = _dict(records.get(field), f"native.save_token_guard.passes[{index}].records.{field}", audit)
            token = _dict(profile.get("save_tokens", {}).get("tokens", {}).get(field), f"profile token {field}", audit)
            audit.require(rec.get("key_id") == token.get("key_id"), f"save token {field} key id mismatch")
            audit.require(rec.get("expected_name") == field and rec.get("actual_name") == field, f"save token {field} name mismatch")
            audit.require(rec.get("status") == "observed" and rec.get("nul_terminator_observed") is True, f"save token {field} is not observed/terminated")


def _validate_code_records(records: Any, expected: dict[str, dict[str, Any]], label: str, audit: Audit) -> None:
    rows = _dict(records, label, audit)
    audit.require(set(rows) == set(expected), f"{label}: record names changed")
    for name, profile_row in expected.items():
        row = _dict(rows.get(name), f"{label}.{name}", audit)
        expected_hex = profile_row.get("hex")
        audit.require(row.get("expected_hex") == expected_hex, f"{label}.{name}.expected_hex mismatch")
        actual_hex = row.get("actual_hex")
        audit.require(actual_hex == expected_hex, f"{label}.{name}.actual_hex mismatch")
        try:
            digest = hashlib.sha256(bytes.fromhex(actual_hex)).hexdigest()
            audit.require(digest == profile_row.get("sha256"), f"{label}.{name} bytes/SHA mismatch")
        except (TypeError, ValueError):
            audit.errors.append(f"{label}.{name}.actual_hex is invalid hex")


def _validate_native_capture(
    audit: Audit,
    capture_path: str,
    native_report_path: str,
    installation_path: str,
    profile: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    capture_rel, capture_file, capture = _load_json(capture_path)
    report_rel, report_file, report = _load_json(native_report_path)
    install_rel, install_file, installation = _load_json(installation_path)
    capture_sha = _sha256(capture_file)
    report_sha = _sha256(report_file)
    install_sha = _sha256(install_file)
    audit.inputs.update({
        "native_capture": {"path": capture_rel, "bytes": capture_file.stat().st_size, "sha256": capture_sha},
        "native_report": {"path": report_rel, "bytes": report_file.stat().st_size, "sha256": report_sha},
        "installation": {"path": install_rel, "bytes": install_file.stat().st_size, "sha256": install_sha},
    })
    expected_identity = _identity_from_installation(installation, audit)
    audit.require(installation.get("dll_sha256") == EXPECTED_DLL_SHA256, "installation DLL SHA mismatch")
    audit.require(capture.get("status") == "observed" and capture.get("completed") is True and capture.get("complete") is True, "native capture is not complete observed")
    audit.require(capture.get("country") == "FRA", "native capture country is not FRA")
    audit.require(capture.get("read_only") is True and capture.get("native_function_invoked") is False, "native capture read-only flags failed")
    request = _dict(capture.get("request"), "native.request", audit)
    audit.require(request.get("country") == "FRA" and set(request.get("fields", [])) == set(EXPECTED_FIELDS), "native request is not FRA three-field request")
    prof = _dict(capture.get("profile"), "native.profile", audit)
    audit.require(prof.get("profile_id") == profile.get("profile_id"), "native profile id mismatch")
    audit.require(prof.get("sha256") == EXPECTED_PROFILE_SHA256, "native profile SHA mismatch")
    audit.require(_same_path(prof.get("path"), ROOT / "bridge/information/profiles/domestic-pressure-memory-1374.json"), "native profile path is not the current profile")
    probe_script = capture.get("probe_script")
    try:
        probe_rel, probe_file = _bounded_path(probe_script)
        probe_sha = _sha256(probe_file)
        audit.require(capture.get("probe_script_sha256") == probe_sha, "native reader source SHA mismatch")
        audit.inputs["native_reader"] = {"path": probe_rel, "bytes": probe_file.stat().st_size, "sha256": probe_sha}
    except AuditError as exc:
        audit.errors.append(f"native reader source: {exc}")
    target = _dict(capture.get("target_build"), "native.target_build", audit)
    audit.require(target.get("version") == EXPECTED_GAME_VERSION and target.get("expected_exe_sha256") == EXPECTED_EXE_SHA256, "native target build mismatch")
    _assert_identity(capture.get("identity"), expected_identity, "native.identity", audit)
    before_date = _validate_snapshot(capture.get("before"), "native.before", audit)
    after_date = _validate_snapshot(capture.get("after"), "native.after", audit)
    audit.require(before_date is not None and before_date == after_date, "native before/after game date differs")
    values = _field_values(capture, label="native", audit=audit)
    field_results = _dict(capture.get("field_results"), "native.field_results", audit)
    field_defs = _dict(capture.get("field_definitions"), "native.field_definitions", audit)
    contract_fields = _dict(profile.get("scalars"), "profile.scalars", audit)
    for field in EXPECTED_FIELDS:
        result = _dict(field_results.get(field), f"native.field_results.{field}", audit)
        definition = _dict(field_defs.get(field), f"native.field_definitions.{field}", audit)
        profile_row = _dict(contract_fields.get(field), f"profile.scalars.{field}", audit)
        audit.require(result.get("status") == "known", f"native {field} is not known")
        audit.require(_is_int(result.get("raw")) and result.get("raw") == values.get(field), f"native {field} raw/value mismatch")
        audit.require(result.get("scale") == 1000 and result.get("unit") == field, f"native {field} unit/scale mismatch")
        for key in ("offset", "width", "signed", "scale", "unit"):
            expected = profile_row.get(key) if key != "offset" else int(str(profile_row.get("offset")), 16)
            audit.require(definition.get(key) == expected, f"native field definition {field}.{key} mismatch")
    _validate_guards(capture, profile, audit)
    doublepass = _dict(capture.get("doublepass"), "native.doublepass", audit)
    audit.require(doublepass.get("performed") is True and doublepass.get("consistent") is True and doublepass.get("mismatches") == [], "native doublepass guard failed")
    cleanup = _dict(capture.get("cleanup"), "native.cleanup", audit)
    close = _dict(cleanup.get("handle_close"), "native.cleanup.handle_close", audit)
    audit.require(close.get("status") == "closed" and close.get("closed") is True and close.get("success") is True, "native handle close was not observed")
    access = _dict(capture.get("access"), "native.access", audit)
    for key in ("native_game_calls", "target_memory_writes", "dll_injection", "private_heap_scan", "ui_control", "date_advance", "save_or_reload"):
        audit.require(access.get(key) is False, f"native access.{key} is not false")

    audit.require(report.get("status") == "passed" and report.get("mode") == "live", "native wrapper report is not passed live")
    audit.require(report.get("country") == "FRA" and set(report.get("fields", [])) == set(EXPECTED_FIELDS), "native wrapper report scope mismatch")
    for key in ("read_only", "native_function_invoked", "business_actions_submitted", "date_advance", "save_or_reload", "dll_installation", "historical_values_used"):
        expected = False if key != "read_only" else True
        audit.require(report.get(key) is expected, f"native wrapper report {key} guard failed")
    audit.require(report.get("pid") == expected_identity.get("pid"), "native wrapper PID mismatch")
    audit.require(report.get("session_id") == expected_identity.get("session_id"), "native wrapper session mismatch")
    audit.require(report.get("game_sha256") == EXPECTED_EXE_SHA256, "native wrapper executable SHA mismatch")
    audit.require(report.get("date_raw") == before_date, "native wrapper date mismatch")
    audit.require(report.get("values") == values, "native wrapper values differ from raw capture")
    audit.require(report.get("raw_capture_sha256") == capture_sha, "native wrapper capture SHA mismatch")
    capture_script = ROOT / "work" / "capture_information_domestic_pressure.py"
    if capture_script.exists():
        audit.require(report.get("source_sha256") == _sha256(capture_script), "native wrapper capture-script SHA mismatch")
    audit.require(report.get("installation_sha256") == install_sha, "native wrapper installation SHA mismatch")
    audit.require(_all_true(report.get("checks"), "native wrapper checks", audit), "native wrapper checks are incomplete")
    return capture, report, {"identity": expected_identity, "capture_sha256": capture_sha, "report_sha256": report_sha, "installation_sha256": install_sha, "installation": installation}


def _result_item(result: Any, label: str, audit: Audit) -> dict[str, Any]:
    obj = _dict(result, label, audit)
    items = obj.get("items")
    audit.require(isinstance(items, list) and len(items) == 1, f"{label}.items must contain one item")
    return items[0] if isinstance(items, list) and items and isinstance(items[0], dict) else {}


def _validate_context_result(result: Any, label: str, expected_context: dict[str, Any], audit: Audit, expected_status: str = "complete", expected_complete: bool = True) -> dict[str, Any]:
    obj = _dict(result, label, audit)
    audit.require(obj.get("status") == expected_status, f"{label}.status mismatch")
    audit.require(obj.get("complete") is expected_complete, f"{label}.complete mismatch")
    context = _context_key(obj.get("context"), label=label + ".context", audit=audit)
    _compare_context(context, expected_context, label, audit)
    delivery = _dict(obj.get("delivery"), label + ".delivery", audit)
    audit.require(delivery.get("status") == "delivered", f"{label}.delivery.status is not delivered")
    return _result_item(result, label, audit)


def _validate_result_fields(item: dict[str, Any], expected_values: dict[str, int], fields: Iterable[str], label: str, audit: Audit, *, allow_extra: bool = False) -> None:
    item_fields = _dict(item.get("fields"), label + ".fields", audit)
    expected = set(fields)
    audit.require((set(item_fields) >= expected if allow_extra else set(item_fields) == expected), f"{label}.fields set mismatch")
    for field in expected:
        row = _dict(item_fields.get(field), f"{label}.fields.{field}", audit)
        audit.require(row.get("status") == "known", f"{label}.{field} is not known")
        audit.require(_is_int(row.get("raw")) and row.get("raw") == expected_values.get(field), f"{label}.{field} raw mismatch")
        audit.require(row.get("value") == expected_values.get(field), f"{label}.{field} value mismatch")
        audit.require(row.get("unit") == field and row.get("scale") == 1000, f"{label}.{field} unit/scale mismatch")
    audit.require(item.get("game_date") is not None and _is_int(item.get("game_date")), f"{label}.game_date missing")
    objects = item.get("objects")
    audit.require(objects == [{"country": "FRA", "type": "country"}], f"{label}.objects does not bind FRA")
    query = _dict(item.get("query"), label + ".query", audit)
    audit.require(query.get("topic") == "N04", f"{label}.query.topic mismatch")
    audit.require(query.get("object") == {"country": "FRA", "type": "country"}, f"{label}.query.object mismatch")


def _validate_live(
    audit: Audit,
    live_report_path: str,
    live_dir: str,
    native: dict[str, Any],
    native_meta: dict[str, Any],
    installation_path: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    report_rel, report_file, report = _load_json(live_report_path)
    wire_rel, wire_file, wire = _load_json(str(Path(live_dir) / "mcp-wire-audit.json"))
    audit.inputs["live_report"] = {"path": report_rel, "bytes": report_file.stat().st_size, "sha256": _sha256(report_file)}
    audit.inputs["mcp_wire_audit"] = {"path": wire_rel, "bytes": wire_file.stat().st_size, "sha256": _sha256(wire_file)}
    identity = native_meta["identity"]
    expected_values = _field_values(native, label="native", audit=audit)
    audit.require(report.get("status") == "passed", "live report status is not passed")
    audit.require(report.get("mode") == "paused_live_mcp_with_independent_pure_rpm_samples", "live report mode changed")
    audit.require(report.get("country") == "FRA" and set(report.get("fields", [])) == set(EXPECTED_FIELDS), "live report scope is not N04 FRA three-field")
    audit.require(set(report.get("mixed_unimplemented_fields", [])) == set(EXPECTED_UNIMPLEMENTED), "live report unsupported-field scope changed")
    for key in ("read_only", "native_function_invoked", "business_actions_submitted", "date_advance", "save_or_reload", "dll_installation", "historical_values_used"):
        expected = False if key != "read_only" else True
        audit.require(report.get(key) is expected, f"live report {key} guard failed")
    audit.require(report.get("pid") == identity.get("pid"), "live report PID mismatch")
    audit.require(report.get("session_id") == identity.get("session_id"), "live report session mismatch")
    audit.require(report.get("creation_filetime") == identity.get("creation_filetime"), "live report creation filetime mismatch")
    audit.require(report.get("game_sha256") == EXPECTED_EXE_SHA256, "live report executable SHA mismatch")
    audit.require(_is_int(report.get("game_date")), "live report game_date is not integer")
    audit.require(report.get("installation_sha256") == native_meta.get("installation_sha256"), "live report installation SHA mismatch")
    audit.require(report.get("mcp_wire_audit_sha256") == _sha256(wire_file), "live report wire-audit SHA mismatch")
    source_files = _dict(report.get("source_files"), "live report.source_files", audit)
    for rel, expected_sha in source_files.items():
        try:
            _, path = _bounded_path(rel)
            audit.require(_hex_sha(expected_sha, f"live source {rel}") == _sha256(path), f"live source changed: {rel}")
        except AuditError as exc:
            audit.errors.append(str(exc))
    validator = ROOT / "work" / "validate_information_domestic_pressure_live_004.py"
    if validator.exists():
        validator_sha = _sha256(validator)
        audit.require(validator_sha == EXPECTED_LIVE_MCP_VALIDATOR_SHA256, "live validator source SHA changed")
        audit.require(report.get("source_sha256") == validator_sha, "live validator source SHA mismatch")
        audit.require(report.get("runner_sha256") == validator_sha, "live runner source SHA mismatch")
    base_validator = ROOT / "work" / "validate_information_domestic_pressure.py"
    audit.require(base_validator.exists(), "base MCP validator is missing")
    if base_validator.exists():
        base_sha = _sha256(base_validator)
        audit.require(base_sha == EXPECTED_BASE_MCP_VALIDATOR_SHA256, "base MCP validator source SHA changed")
        audit.inputs["mcp_base_validator"] = {"path": "work/validate_information_domestic_pressure.py", "bytes": base_validator.stat().st_size, "sha256": base_sha}
        audit.inputs["mcp_live_runner"] = {"path": "work/validate_information_domestic_pressure_live_004.py", "bytes": validator.stat().st_size if validator.exists() else None, "sha256": _sha256(validator) if validator.exists() else None}
    checks = _dict(report.get("checks"), "live report.checks", audit)
    _all_true(checks, "live report.checks", audit)
    subscription = _dict(report.get("subscription"), "live report.subscription", audit)
    audit.require(subscription.get("state") == "cancelled", "live subscription was not cancelled")
    audit.require(_is_int(subscription.get("version")), "live subscription version missing")

    wire_entries = _list(wire.get("entries"), "mcp wire entries", audit)
    audit.require(wire.get("schema") == "information_domestic_pressure_mcp_wire_audit_v1", "MCP wire schema mismatch")
    audit.require(wire.get("protocol_version") == "2025-03-26", "MCP protocol version mismatch")
    audit.require(wire.get("raw_payloads_written") is False, "MCP wire audit unexpectedly wrote raw payloads")
    methods = [row.get("method") for row in wire_entries if isinstance(row, dict)]
    audit.require(methods.count("initialize") == 1 and "notifications/initialized" in methods, "MCP initialize handshake incomplete")
    audit.require(len(wire_entries) >= 24, "MCP wire audit is missing expected calls")
    audit.require(all(isinstance(row, dict) and row.get("kind") in {"rpc", "notification"} for row in wire_entries), "MCP wire entry kind malformed")

    # The wire audit intentionally contains no OS child-handle or server-exit
    # fields.  The three periodic wrapper samples are child-exit evidence for
    # their native capture subprocesses only; they are not MCP-server exit
    # evidence.  Server closure is checked separately from the runner's close
    # control-flow receipt.
    samples = _list(report.get("native_samples"), "live native_samples", audit)
    periodic_samples = [row for row in samples if isinstance(row, dict) and str(row.get("label", "")).startswith("native-periodic-")]
    audit.require(len(periodic_samples) == 3, "live report does not contain three periodic native samples")
    for row in periodic_samples:
        audit.require(row.get("subprocess_returncode") == 0, f"periodic native child did not exit zero: {row.get('label')}")
        audit.require(row.get("session_id") == identity.get("session_id") and row.get("pid") == identity.get("pid"), f"periodic sample identity mismatch: {row.get('label')}")
        audit.require(row.get("values") == expected_values, f"periodic sample values mismatch: {row.get('label')}")
        audit.require(row.get("game_date") == report.get("game_date") and row.get("before_game_date") == row.get("after_game_date"), f"periodic sample date mismatch: {row.get('label')}")

    report_context = _context_key(_load_json(str(Path(live_dir) / "final-status-summary.json"))[2].get("context"), label="live final context", audit=audit)
    audit.require(report_context.get("session_id") == identity.get("session_id"), "final live context session mismatch")
    audit.require(report_context.get("game_date") == report.get("game_date"), "final live context date mismatch")
    audit.require(report_context.get("observer") == "FRA", "final live context observer mismatch")

    _validate_context_result(_load_json(str(Path(live_dir) / "manual-result.json"))[2], "live.manual", report_context, audit)
    single = _load_json(str(Path(live_dir) / "single-field-results.json"))[2]
    audit.require(set(single) == set(EXPECTED_FIELDS), "single-field result set mismatch")
    for field in EXPECTED_FIELDS:
        item = _validate_context_result(single.get(field), f"live.single.{field}", report_context, audit)
        _validate_result_fields(item, expected_values, (field,), f"live.single.{field}", audit)
    mixed = _load_json(str(Path(live_dir) / "mixed-unimplemented-result.json"))[2]
    mixed_item = _validate_context_result(mixed, "live.mixed", report_context, audit, expected_status="partial", expected_complete=False)
    _validate_result_fields(mixed_item, expected_values, EXPECTED_FIELDS, "live.mixed", audit, allow_extra=True)
    mixed_fields = _dict(mixed_item.get("fields"), "live.mixed.fields", audit)
    for field in EXPECTED_UNIMPLEMENTED:
        row = _dict(mixed_fields.get(field), f"live.mixed.fields.{field}", audit)
        audit.require(row.get("status") == "unsupported" and row.get("reason") == "FIELD_NOT_IMPLEMENTED_BY_ADAPTER", f"live mixed unsupported {field} changed")
    periodic = _load_json(str(Path(live_dir) / "periodic-results.json"))[2]
    audit.require(isinstance(periodic, list) and len(periodic) == 3, "periodic result file must contain three results")
    if isinstance(periodic, list):
        for index, result in enumerate(periodic):
            item = _validate_context_result(result, f"live.periodic[{index}]", report_context, audit)
            _validate_result_fields(item, expected_values, EXPECTED_FIELDS, f"live.periodic[{index}]", audit)
            audit.require(item.get("game_date") == report.get("game_date"), f"live.periodic[{index}] date mismatch")
    associations = _list(report.get("associations"), "live.associations", audit)
    audit.require(len(associations) >= 8, "live associations are incomplete")
    for index, row in enumerate(associations):
        if not isinstance(row, dict):
            audit.errors.append(f"live.associations[{index}] malformed")
            continue
        audit.require(row.get("session_id") == identity.get("session_id") and row.get("pid") == identity.get("pid"), f"association {index} identity mismatch")
        if row.get("native_sample_label") == "Provided independent native reference":
            audit.require(row.get("native_report_sha256") == native_meta.get("capture_sha256"), f"association {index} native capture SHA mismatch")
        else:
            try:
                sample_rel, sample_path = _bounded_path(row.get("native_report_path"))
                audit.require(row.get("native_report_sha256") == _sha256(sample_path), f"association {index} periodic capture SHA mismatch: {sample_rel}")
            except AuditError as exc:
                audit.errors.append(f"association {index}: {exc}")
        audit.require(row.get("mcp_game_date") == report.get("game_date"), f"association {index} date mismatch")
    return report, {"wire_sha256": _sha256(wire_file), "wire": wire, "context": report_context, "base_validator_sha256": _sha256(base_validator) if base_validator.exists() else None, "runner_sha256": _sha256(validator) if validator.exists() else None}


def _validate_mcp_server_closure(
    audit: Audit,
    receipt_path: str,
    live_report: dict[str, Any],
    live_meta: dict[str, Any],
    probe_dir: str,
) -> dict[str, Any]:
    """Validate the MCP server's own close/exit receipt.

    ``mcp-wire-audit.json`` has protocol entries only and deliberately does
    not contain an OS process handle or return code.  The native periodic
    samples likewise describe their own wrapper subprocesses.  A separate
    receipt therefore has to bind the server close to the two validator
    sources.  The accepted receipt may be a separate JSON file or an inline
    ``server_closure`` object supplied by a runner; neither form is inferred
    from a native sample.
    """

    data: dict[str, Any]
    source_meta: dict[str, Any] | None = None
    try:
        rel, file, loaded = _load_json(receipt_path)
        data = _dict(loaded, "MCP server closure receipt", audit)
        audit.inputs["mcp_server_closure"] = {"path": rel, "bytes": file.stat().st_size, "sha256": _sha256(file)}
    except AuditError:
        inline = live_report.get("server_closure") or live_report.get("mcp_server_closure")
        if isinstance(inline, dict):
            data = inline
            audit.warn("MCP server closure is an inline runner receipt; no separate receipt file was archived")
        else:
            audit.errors.append("MCP server closure receipt is missing; native wrapper exit is not MCP server exit evidence")
            return {}

    audit.require(data.get("schema") == "information_mcp_server_closure_receipt_v1", "MCP server closure receipt schema changed")
    audit.require(data.get("evidence_kind") == "standalone_health_probe", "MCP server closure receipt is not a standalone health probe")
    for field, report_field in (
        ("session_id", "session_id"),
        ("pid", "pid"),
        ("creation_filetime", "creation_filetime"),
        ("game_date", "game_date"),
        ("installation_sha256", "installation_sha256"),
    ):
        audit.require(data.get(field) == live_report.get(report_field), f"MCP closure {field} does not match live installation context")
    audit.require(_is_int(data.get("pid")) and _is_int(data.get("creation_filetime")) and _is_int(data.get("game_date")), "MCP closure identity/date fields are not non-bool integers")
    audit.require(data.get("paused_date_preserved") is True, "MCP closure did not prove paused date preservation")
    relation = _dict(data.get("relation"), "MCP closure relation", audit)
    audit.require(relation.get("original_live_005_returncode") == "not_recorded", "MCP closure must not invent live-005 returncode")
    audit.require(relation.get("original_live_005_close") == "runner close/wait/returncode control-flow inference only", "MCP closure original-run boundary changed")
    audit.require(relation.get("direct_os_exit_applies_to") == "standalone_health_probe", "MCP closure direct-exit scope changed")

    process = data.get("server_process") or data.get("process") or data.get("server")
    if not isinstance(process, dict):
        process = data
    status = process.get("status", data.get("status"))
    audit.require(status in {"passed", "observed", "closed"}, "MCP server closure receipt status is not observed/passed")
    returncode = None
    for key in ("server_returncode", "server_exit_code", "returncode", "exit_code"):
        if key in process:
            returncode = process.get(key)
            break
    audit.require(_is_int(returncode) and returncode == 0, "MCP server closure receipt lacks server returncode 0")
    close = data.get("close") if isinstance(data.get("close"), dict) else process
    closed = close.get("closed", close.get("close_completed", close.get("wait_completed")))
    audit.require(closed is True, "MCP server close/wait was not explicitly completed")
    if "close_called" in close:
        audit.require(close.get("close_called") is True, "MCP server close was not called")
    source_meta = _dict(data.get("source_files"), "MCP closure source_files", audit)
    expected_sources = {
        "base_validator_sha256": ("work/validate_information_domestic_pressure.py", live_meta.get("base_validator_sha256")),
        "runner_sha256": ("work/validate_information_domestic_pressure_live_004.py", live_meta.get("runner_sha256")),
        "tools/serve_information.py": ("tools/serve_information.py", None),
        "probe_sha256": ("work/verify_information_mcp_closure.py", None),
    }
    for key, (path_value, expected_sha) in expected_sources.items():
        try:
            _, source_path = _bounded_path(path_value)
            actual_sha = _sha256(source_path)
            pinned_sha = _hex_sha(source_meta.get(key), f"MCP closure source_files.{key}")
            audit.require(pinned_sha == actual_sha, f"MCP closure source pin mismatch: {path_value}")
            if expected_sha is not None:
                audit.require(pinned_sha == expected_sha, f"MCP closure validator source pin mismatch: {path_value}")
            audit.inputs.setdefault("mcp_closure_sources", {})[path_value] = {"path": path_value, "bytes": source_path.stat().st_size, "sha256": actual_sha}
        except AuditError as exc:
            audit.errors.append(str(exc))
    audit.require(data.get("native_subprocess_exit_evidence") is False, "MCP server receipt conflates native wrapper exit with server exit")
    audit.require(data.get("wire_exit_evidence") is False, "MCP server receipt falsely attributes exit to wire audit")

    probe_root = Path(probe_dir)
    before_rel, before_file, before = _load_json(probe_root / "before-control.json")
    after_rel, after_file, after = _load_json(probe_root / "after-control.json")
    wire_rel, wire_file, wire = _load_json(probe_root / "mcp-wire-audit.json")
    audit.inputs["mcp_closure_probe"] = {
        "directory": _root_relative(probe_root)[0],
        "before": {"path": before_rel, "bytes": before_file.stat().st_size, "sha256": _sha256(before_file)},
        "after": {"path": after_rel, "bytes": after_file.stat().st_size, "sha256": _sha256(after_file)},
        "wire": {"path": wire_rel, "bytes": wire_file.stat().st_size, "sha256": _sha256(wire_file)},
    }
    audit.require(data.get("wire_audit_sha256") == _sha256(wire_file), "MCP closure wire-audit SHA mismatch")
    audit.require(wire.get("schema") == "information_domestic_pressure_mcp_wire_audit_v1", "MCP closure probe wire schema changed")
    audit.require(wire.get("protocol_version") == "2025-03-26" and wire.get("raw_payloads_written") is False, "MCP closure probe wire guard failed")
    wire_entries = _list(wire.get("entries"), "MCP closure probe wire entries", audit)
    methods = [row.get("method") for row in wire_entries if isinstance(row, dict)]
    audit.require(methods.count("initialize") == 1 and "notifications/initialized" in methods and "tools/call" in methods, "MCP closure probe handshake is incomplete")
    before_obj = _dict(before, "MCP closure probe before", audit)
    after_obj = _dict(after, "MCP closure probe after", audit)
    audit.require(before_obj == after_obj, "MCP closure probe before/after control state changed")
    audit.require(before_obj.get("pid") == live_report.get("pid") and before_obj.get("date_raw") == live_report.get("game_date"), "MCP closure probe identity/date mismatch")
    audit.require(before_obj.get("speed") == 0 and before_obj.get("paused_flag") == 1, "MCP closure probe did not remain paused")
    return data


def _validate_save_crosscheck(audit: Audit, path: str, native_values: dict[str, int], native_meta: dict[str, Any]) -> dict[str, Any]:
    rel, file, data = _load_json(path)
    digest = _sha256(file)
    audit.inputs["save_crosscheck"] = {"path": rel, "bytes": file.stat().st_size, "sha256": digest}
    audit.require(data.get("status") == "passed" and data.get("mode") == "recorded", "save cross-check is not recorded/passed")
    audit.require(data.get("save_is_recorded") is True and data.get("not_a_live_state_fallback") is True, "save cross-check recording guard failed")
    audit.require(data.get("world_generation_verified") is False, "save cross-check must not claim world generation proof")
    source = _dict(data.get("source"), "save cross-check.source", audit)
    expected_save_sha = "ffa91dbd2a2d544b18d586a895bb9b0c2b90e94ece47b2c74507555b8f58c2e0"
    audit.require(source.get("sha256") == expected_save_sha and source.get("expected_sha256") == expected_save_sha and data.get("save_sha256") == expected_save_sha, "recorded save SHA mismatch")
    audit.require(_is_int(source.get("bytes")) and source.get("bytes") > MAX_SINGLE_BYTES, "recorded save size should remain explicit and outside copy bound")
    audit.require(data.get("native_capture", {}).get("sha256") == native_meta.get("capture_sha256"), "save/native capture SHA association mismatch")
    fields = _dict(data.get("fields"), "save cross-check.fields", audit)
    audit.require(set(fields) == set(EXPECTED_FIELDS), "save cross-check field set changed")
    for field in EXPECTED_FIELDS:
        row = _dict(fields.get(field), f"save cross-check.fields.{field}", audit)
        audit.require(row.get("equal") is True and row.get("native_scale") == 1000, f"save cross-check {field} equality/scale failed")
        audit.require(row.get("native_raw") == native_values.get(field), f"save cross-check {field} raw differs from native")
    audit.require(data.get("all_equal") is True, "save cross-check all_equal is not true")
    return data


def _coverage_summary(data: Any, label: str, audit: Audit) -> dict[str, Any]:
    obj = _dict(data, label, audit)
    counts = _dict(obj.get("counts"), label + ".counts", audit)
    for key, expected in EXPECTED_COVERAGE.items():
        if key == "field_counts":
            audit.require(counts.get(key) == expected, f"{label}.{key} mismatch")
        else:
            audit.require(counts.get(key) == expected, f"{label}.{key} mismatch")
    topics = _list(obj.get("topics"), label + ".topics", audit)
    audit.require(len(topics) == EXPECTED_COVERAGE["topic_count"], f"{label}.topics count mismatch")
    n04 = _dict(obj.get("N04"), label + ".N04", audit)
    n04_fields = _dict(n04.get("fields"), label + ".N04.fields", audit)
    audit.require(set(n04_fields) == set(EXPECTED_FIELDS) | set(EXPECTED_UNIMPLEMENTED) | {"religious_unity"}, f"{label}.N04 field set changed")
    for field in EXPECTED_FIELDS:
        row = _dict(n04_fields.get(field), f"{label}.N04.{field}", audit)
        audit.require(row.get("coverage") == "available" and row.get("runtime_validation") == "validated" and row.get("scale") == 1000 and row.get("supported_countries") == ["FRA"], f"{label}.N04.{field} metadata mismatch")
    for field in ("overextension", "unrest", "religious_unity"):
        audit.require(_dict(n04_fields.get(field), f"{label}.N04.{field}", audit).get("coverage") == "planned", f"{label}.N04.{field} must remain planned")
    return {"counts": counts, "n04": n04}


def _validate_coverage(audit: Audit, stage_coverage: str, docs_coverage: str) -> dict[str, Any]:
    stage_rel, stage_file, stage = _load_json(stage_coverage)
    docs_rel, docs_file, docs = _load_json(docs_coverage)
    stage_sha = _sha256(stage_file)
    docs_sha = _sha256(docs_file)
    audit.inputs["coverage_stage"] = {"path": stage_rel, "bytes": stage_file.stat().st_size, "sha256": stage_sha}
    audit.inputs["coverage_docs"] = {"path": docs_rel, "bytes": docs_file.stat().st_size, "sha256": docs_sha}
    _coverage_summary(stage, "coverage.stage", audit)
    _coverage_summary(docs, "coverage.docs", audit)
    audit.require(stage == docs, "stage coverage and docs coverage exports differ")
    audit.require(stage.get("goal_complete") is False and docs.get("goal_complete") is False, "coverage export must not claim overall goal complete")
    return stage


def _extract_failure_nodes(summary: dict[str, Any]) -> tuple[int | None, int | None, Any]:
    comparison = None
    for key in ("failure_error_node_comparison", "latest_baseline_comparison", "stable_baseline_comparison"):
        candidate = summary.get(key)
        if isinstance(candidate, dict) and (
            "new_failure_or_error_nodes" in candidate or "added_nodes" in candidate
        ):
            comparison = candidate
            break
    # The recovery runner nests the same node comparison below its batch
    # comparison object.  Keep message-only changes outside this guard: only
    # failure/error nodes are allowed to block a delivery.
    if comparison is None:
        batch = summary.get("comparison_to_previous_batch")
        if isinstance(batch, dict):
            nested = batch.get("failure_error_nodes")
            if isinstance(nested, dict) and (
                "new_failure_or_error_nodes" in nested or "added_nodes" in nested
            ):
                comparison = nested
    if not isinstance(comparison, dict):
        return None, None, None
    added = comparison.get("new_failure_or_error_nodes", comparison.get("added_nodes"))
    return (len(added) if isinstance(added, list) else None, comparison.get("persistent_unique_keys"), comparison)


def _summary_pinned_files(value: Any, label: str, audit: Audit) -> list[dict[str, Any]]:
    """Normalize a summary's list or mapping of path/sha/size pins."""

    rows: list[dict[str, Any]] = []
    if isinstance(value, list):
        for index, item in enumerate(value):
            if not isinstance(item, dict):
                audit.errors.append(f"{label}[{index}] is not a pinned file object")
                continue
            rows.append(item)
    elif isinstance(value, dict):
        for key, item in value.items():
            if isinstance(item, dict):
                row = dict(item)
                row.setdefault("path", key)
                rows.append(row)
            else:
                audit.errors.append(f"{label}.{key} has no SHA/size pin")
    else:
        audit.errors.append(f"{label} is not a list or mapping of pinned files")
    return rows


def _validate_pinned_file(audit: Audit, item: dict[str, Any], label: str) -> dict[str, Any] | None:
    path_value = item.get("path")
    try:
        rel, path = _bounded_path(path_value)
        expected_sha = _hex_sha(item.get("sha256"), f"{label}.sha256")
        expected_bytes = item.get("bytes")
        audit.require(_is_int(expected_bytes), f"{label}.bytes is not an integer")
        actual_sha = _sha256(path)
        audit.require(actual_sha == expected_sha, f"{label} SHA mismatch: {rel}")
        if _is_int(expected_bytes):
            audit.require(path.stat().st_size == expected_bytes, f"{label} byte count mismatch: {rel}")
        return {"path": rel, "bytes": path.stat().st_size, "sha256": actual_sha}
    except AuditError as exc:
        audit.errors.append(f"{label}: {exc}")
        return None


def _validate_source_snapshot(audit: Audit, value: Any) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Validate the full002 before/after source-pin snapshot.

    ``source_files`` in the recovery summary is a metadata envelope.  Only the
    two nested path-to-SHA mappings are file records; ``count``, ``changed``,
    and snapshot metadata must never be interpreted as paths.
    """

    obj = _dict(value, "test_summary.source_files", audit)
    expected_keys = {"before_full002", "after_full002", "changed", "missing_after", "before_snapshot", "after_snapshot", "count", "all_unchanged"}
    audit.require(set(obj) == expected_keys, "test summary source_files metadata keys changed")
    before = obj.get("before_full002")
    after = obj.get("after_full002")
    audit.require(isinstance(before, dict) and isinstance(after, dict), "test summary source_files before/after snapshots are missing")
    count = obj.get("count")
    audit.require(_is_int(count) and count == 76, "test summary source_files count is not 76")
    audit.require(obj.get("changed") == [], "test summary source_files changed is not empty")
    audit.require(obj.get("missing_after") == [], "test summary source_files missing_after is not empty")
    audit.require(obj.get("all_unchanged") is True, "test summary source_files all_unchanged is not true")
    source_records: list[dict[str, Any]] = []
    if isinstance(before, dict) and isinstance(after, dict):
        audit.require(set(before) == set(after), "test summary source_files before/after keys differ")
        audit.require(len(before) == count and len(after) == count, "test summary source_files snapshot size differs from count")
        for path_value, before_sha_value in before.items():
            label = f"test_summary.source_files.before_full002[{path_value!r}]"
            try:
                if not isinstance(path_value, str):
                    raise AuditError("source path is not a string")
                before_sha = _hex_sha(before_sha_value, label + ".sha256")
                after_sha = _hex_sha(after.get(path_value), f"test_summary.source_files.after_full002[{path_value!r}].sha256")
                audit.require(before_sha == after_sha, f"test summary source SHA changed between snapshots: {path_value}")
                rel, path = _bounded_path(path_value)
                actual_sha = _sha256(path)
                audit.require(actual_sha == before_sha, f"test summary source SHA does not match current file: {rel}")
                source_records.append({"path": rel, "bytes": path.stat().st_size, "sha256": actual_sha, "role": "test-summary-source-snapshot", "kind": "source_code_or_fixture"})
            except AuditError as exc:
                audit.errors.append(str(exc))
    snapshot_records: list[dict[str, Any]] = []
    for name in ("before_snapshot", "after_snapshot"):
        row = obj.get(name)
        record = _validate_pinned_file(audit, row, f"test_summary.source_files.{name}") if isinstance(row, dict) else None
        if record:
            record["role"] = f"test-summary-{name}"
            record["kind"] = "source_pin_snapshot"
            snapshot_records.append(record)
    audit.inputs["test_summary_source_snapshot"] = {
        "count": count,
        "all_unchanged": obj.get("all_unchanged"),
        "changed": obj.get("changed"),
        "missing_after": obj.get("missing_after"),
        "before_snapshot": snapshot_records[0] if len(snapshot_records) > 0 else None,
        "after_snapshot": snapshot_records[1] if len(snapshot_records) > 1 else None,
        "files": source_records,
    }
    return source_records, snapshot_records


def _collect_artifact_pins(value: Any, label: str, out: list[tuple[str, dict[str, Any]]], *, depth: int = 0) -> None:
    if depth > 12:
        return
    if isinstance(value, dict):
        if isinstance(value.get("path"), str) and ("sha256" in value or "bytes" in value):
            out.append((label, value))
            return
        for key, child in value.items():
            _collect_artifact_pins(child, f"{label}.{key}", out, depth=depth + 1)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _collect_artifact_pins(child, f"{label}[{index}]", out, depth=depth + 1)


def _explicit_count(value: Any) -> int | None:
    """Read a non-negative report count without treating bool as an integer."""

    if type(value) is int and value >= 0:
        return value
    if isinstance(value, str) and re.fullmatch(r"[0-9]+", value):
        return int(value)
    return None


def _validate_test_summary(audit: Audit, summary_path: str, baseline_path: str | None) -> dict[str, Any]:
    rel, file, summary = _load_json(summary_path)
    digest = _sha256(file)
    audit.inputs["test_summary"] = {"path": rel, "bytes": file.stat().st_size, "sha256": digest}
    audit.require(isinstance(summary.get("schema"), str), "new test summary schema is missing")
    info = _dict(summary.get("information"), "test_summary.information", audit)
    info_payload = info.get("information") if isinstance(info.get("information"), dict) else info
    info_payload = _dict(info_payload, "test_summary.information.payload", audit)
    # The summary must expose explicit information-suite status.  It is not
    # sufficient to infer this from the top-level pytest exit code.
    failure_ids = info_payload.get("failure_ids")
    error_ids = info_payload.get("error_ids")
    if isinstance(failure_ids, list) and isinstance(error_ids, list):
        audit.require(not failure_ids and not error_ids, "information test summary contains failures or errors")
    else:
        # The current runner emits explicit aggregate counts rather than ID
        # lists.  Missing IDs are acceptable only when those counts are
        # present and zero; absence of both forms remains a hard failure.
        info_result = _dict(info_payload.get("reported_result"), "test_summary.information.reported_result", audit)
        audit.require(_is_int(info_result.get("failed")) and _is_int(info_result.get("errors")), "test summary information failure/error fields are missing")
        audit.require(info_result.get("failed") == 0 and info_result.get("errors") == 0, "information test summary contains failures or errors")
    info_status_value = info_payload.get("case_element_statuses", info.get("case_element_statuses"))
    info_status = _dict(info_status_value, "test_summary.information.case_element_statuses", audit)
    if "failure" in info_status or "failures" in info_status or "error" in info_status or "errors" in info_status:
        info_failure = info_status.get("failure", info_status.get("failures"))
        info_error = info_status.get("error", info_status.get("errors"))
        audit.require(_is_int(info_failure) and _is_int(info_error), "information failure/error counts are not explicit")
        audit.require(info_failure == 0 and info_error == 0, "information failure/error counts are non-zero")
    overall = summary.get("overall") if isinstance(summary.get("overall"), dict) else summary.get("full")
    overall = _dict(overall, "test_summary.overall_or_full", audit)
    overall_junit = _dict(overall.get("junit_suite"), "test_summary.overall_or_full.junit_suite", audit)
    audit.require(_explicit_count(overall_junit.get("failed", overall_junit.get("failures"))) is not None, "test summary full failure count missing")
    audit.require(_explicit_count(overall_junit.get("errors")) is not None, "test summary full error count missing")
    full_status = overall.get("case_element_statuses")
    if isinstance(full_status, dict):
        audit.require(_is_int(full_status.get("failure", full_status.get("failures"))), "test summary full case failure count missing")
        audit.require(_is_int(full_status.get("error", full_status.get("errors"))), "test summary full case error count missing")
    audit.require(type(summary.get("full_suite_passed")) is bool, "test summary full_suite_passed is missing")
    audit.require(_is_int(summary.get("full_exit_code")), "test summary full_exit_code is missing")
    added, persistent, comparison = _extract_failure_nodes(summary)
    audit.require(comparison is not None, "test summary failure/error node comparison is missing")
    if comparison is not None:
        added_nodes = comparison.get("new_failure_or_error_nodes", comparison.get("added_nodes"))
        audit.require(isinstance(added_nodes, list), "test summary new failure/error node list is missing")
        audit.require(added == 0, "new test summary has failure/error nodes absent from previous baseline")
        audit.require(_is_int(comparison.get("baseline_nodes")) and _is_int(comparison.get("current_nodes")), "test summary failure/error node totals are missing")
    baseline = None
    if baseline_path:
        try:
            baseline_rel, baseline_file, baseline = _load_json(baseline_path)
            audit.inputs["test_summary_baseline"] = {"path": baseline_rel, "bytes": baseline_file.stat().st_size, "sha256": _sha256(baseline_file)}
            audit.require(isinstance(baseline.get("schema"), str), "test summary baseline schema is missing")
        except AuditError as exc:
            audit.errors.append(f"test summary baseline: {exc}")
    artifact_records: list[dict[str, Any]] = []
    source_records: list[dict[str, Any]] = []
    source_snapshot_artifacts: list[dict[str, Any]] = []
    source_value = summary.get("source_files")
    if isinstance(source_value, dict) and "before_full002" in source_value:
        source_records, source_snapshot_artifacts = _validate_source_snapshot(audit, source_value)
    else:
        sources = _summary_pinned_files(source_value, "test_summary.source_files", audit)
        for index, item in enumerate(sources):
            record = _validate_pinned_file(audit, item, f"test_summary.source_files[{index}]")
            if record:
                source_records.append(record)
        audit.require(bool(source_records) and len(source_records) == len(sources), "test summary source pins are incomplete")
    seen_artifacts: set[str] = set()
    for index, record in enumerate(source_snapshot_artifacts):
        if record["path"] not in seen_artifacts:
            item = dict(record)
            item["name"] = f"test_summary.source_files.snapshot[{index}]"
            artifact_records.append(item)
            seen_artifacts.add(record["path"])
    artifact_candidates: list[tuple[str, dict[str, Any]]] = []
    for name in ("artifacts", "artifacts_preserved", "previous_recovery", "full", "information", "http_isolated_recheck"):
        if name in summary:
            _collect_artifact_pins(summary.get(name), f"test_summary.{name}", artifact_candidates)
    for label, item in artifact_candidates:
        record = _validate_pinned_file(audit, item, label)
        if record and record["path"] not in seen_artifacts:
            record["name"] = label
            artifact_records.append(record)
            seen_artifacts.add(record["path"])
    audit.inputs["test_summary_artifact_pins"] = artifact_records
    return {"summary": summary, "artifacts": artifact_records, "sources": source_records, "comparison": comparison, "baseline": baseline}


def _validate_baseline_manifest(audit: Audit, manifest_path: str) -> dict[str, Any]:
    rel, file, manifest = _load_json(manifest_path)
    digest = _sha256(file)
    audit.inputs["batch11_manifest"] = {"path": rel, "bytes": file.stat().st_size, "sha256": digest}
    audit.require(digest == EXPECTED_BATCH11_MANIFEST_SHA256, "batch-11 manifest SHA changed")
    files = _list(manifest.get("files"), "batch11 manifest.files", audit)
    changed: list[dict[str, Any]] = []
    unexpected: list[dict[str, Any]] = []
    # Exact paths only.  In particular, catalog.py is not permitted merely
    # because the field-export JSON is an allowed metadata snapshot, and a
    # directory prefix must never authorize an unrelated production change.
    allowed_paths = {
        "bridge/information/domestic_pressure.py",
        "bridge/tests/test_information_domestic_pressure.py",
        "bridge/tests/fixtures/information_domestic_pressure_live_1374.json",
        "docs/信息字段覆盖.json",
        "docs/信息导出与订阅开发计划.md",
        "docs/信息导出开发进展.md",
        "docs/信息接口使用说明.md",
        "docs/国内压力原生来源.md",
        "docs/国家资源信息接口.md",
        "docs/信息计划验收清单.md",
        "HANDOFF.md",
        "README(agent).md",
    }
    for row in files:
        if not isinstance(row, dict) or not isinstance(row.get("path"), str):
            audit.errors.append("batch11 manifest contains malformed file row")
            continue
        try:
            item_rel, item_path = _bounded_path(row["path"])
            actual = _sha256(item_path)
            expected = _hex_sha(row.get("sha256"), f"batch11 manifest {item_rel}.sha256")
            if actual != expected:
                change = {"path": item_rel, "baseline_sha256": expected, "current_sha256": actual}
                changed.append(change)
                if item_rel not in allowed_paths:
                    unexpected.append(change)
        except AuditError as exc:
            audit.warn(f"batch11 historical file not present for comparison: {row.get('path')}: {exc}")
    audit.require(not unexpected, f"unexpected changes relative to batch11 manifest: {[row['path'] for row in unexpected]}")
    return {"path": rel, "sha256": digest, "changed_allowed": changed, "unexpected": unexpected, "manifest": manifest}


def _validate_battle_pins(audit: Audit, index_path: str, source_audit_path: str, queue_path: str) -> dict[str, Any]:
    index_rel, index_file, index = _load_json(index_path)
    source_rel, source_file, source_audit = _load_json(source_audit_path)
    queue_rel, queue_file, queue = _load_json(queue_path)
    index_sha = _sha256(index_file)
    source_sha = _sha256(source_file)
    queue_sha = _sha256(queue_file)
    audit.inputs["battle_research_index"] = {"path": index_rel, "bytes": index_file.stat().st_size, "sha256": index_sha}
    audit.inputs["battle_source_audit"] = {"path": source_rel, "bytes": source_file.stat().st_size, "sha256": source_sha}
    audit.inputs["battle_queue_test"] = {"path": queue_rel, "bytes": queue_file.stat().st_size, "sha256": queue_sha}
    audit.require(index.get("schema") == "information_battle_layout_research_index_v1", "battle research index schema mismatch")
    audit.require(index.get("rea_count") == 7 and index.get("selection_error_count") == 1, "battle research index REA count/selection error changed")
    audit.require(index.get("goal_complete") is False, "battle research index must remain goal incomplete")
    scope = _dict(index.get("scope"), "battle index.scope", audit)
    audit.require(scope.get("executable_sha256") == EXPECTED_EXE_SHA256 and scope.get("no_dispatch") is True and scope.get("no_game_or_process") is True, "battle index authority guard mismatch")
    audit.require(source_audit.get("schema") == "information_battle_layout_source_audit_v1", "battle source audit schema mismatch")
    audit.require(source_audit.get("fixed_executable_sha256") == EXPECTED_EXE_SHA256, "battle source audit executable SHA mismatch")
    audit.require(source_audit.get("rea_count") == 7 and source_audit.get("selection_error_count") == 1, "battle source audit REA count changed")
    audit.require(source_audit.get("all_profile_request_run_guards") is True, "battle source audit profile/request/run guard missing")
    audit.require(queue.get("schema") == "information-battle-buffer-test-report.v2" and queue.get("status") == "passed", "battle queue test not passed")
    queue_sources = _list(queue.get("sources"), "battle queue.sources", audit)
    expected_queue_sources = {
        "work/native/information-battle-buffer.h": "header",
        "work/native/tests/information-battle-buffer-test.cpp": "test",
    }
    actual_queue_sources: dict[str, dict[str, Any]] = {}
    for source_index, row in enumerate(queue_sources):
        item = _dict(row, f"battle queue.sources[{source_index}]", audit)
        record = _validate_pinned_file(audit, item, f"battle queue.sources[{source_index}]")
        if record:
            actual_queue_sources[record["path"]] = record
    audit.require(set(actual_queue_sources) == set(expected_queue_sources), "battle queue header/test source set changed")
    rea_records = _list(index.get("rea_records"), "battle index.rea_records", audit)
    audit.require(len(rea_records) == 7, "battle index.rea_records count changed")
    source_boundaries = _list(source_audit.get("rea_boundaries"), "battle source audit.rea_boundaries", audit)
    audit.require(len(source_boundaries) == len(rea_records), "battle source audit boundary count differs from index")
    rea_files: list[dict[str, Any]] = []
    expected_profile_digest: str | None = None
    seen_rva: set[str] = set()
    for index_no, row in enumerate(rea_records):
        row = _dict(row, f"battle index.rea_records[{index_no}]", audit)
        rva = row.get("rva")
        audit.require(isinstance(rva, str) and rva not in seen_rva, f"battle REA RVA duplicate/invalid: {rva!r}")
        if isinstance(rva, str):
            seen_rva.add(rva)
        audit.require(row.get("subject_sha256") == EXPECTED_EXE_SHA256, f"battle REA subject SHA mismatch: {rva}")
        authority = _dict(row.get("authority"), f"battle REA {rva}.authority", audit)
        for key, expected in (("read_only", True), ("game_access", False), ("native_function_invoked", False), ("dispatch_authorized", False)):
            audit.require(authority.get(key) is expected, f"battle REA {rva}.authority.{key} guard failed")
        profile_guard = _dict(row.get("profile_guard"), f"battle REA {rva}.profile_guard", audit)
        audit.require(profile_guard.get("status") == "passed", f"battle REA {rva}.profile_guard status changed")
        _all_true(profile_guard.get("checks"), f"battle REA {rva}.profile_guard.checks", audit)
        profile_digest = profile_guard.get("profile_digest")
        if expected_profile_digest is None:
            expected_profile_digest = profile_digest
        audit.require(profile_digest == expected_profile_digest, f"battle REA {rva}.profile_digest differs")
        boundary = source_boundaries[index_no] if index_no < len(source_boundaries) else {}
        boundary = _dict(boundary, f"battle source audit.rea_boundaries[{index_no}]", audit)
        audit.require(boundary.get("evidence_id") == row.get("evidence_id"), f"battle source boundary evidence id mismatch: {rva}")
        audit.require(boundary.get("evidence_sha256") == row.get("evidence_sha256"), f"battle source boundary evidence SHA mismatch: {rva}")
        evidence_item = {"path": row.get("evidence_path"), "bytes": row.get("evidence_bytes"), "sha256": row.get("evidence_sha256")}
        evidence_record = _validate_pinned_file(audit, evidence_item, f"battle REA {rva}.evidence")
        if evidence_record:
            evidence_record.update({"role": f"battle-rea-{rva}-raw", "kind": "rea_evidence"})
            rea_files.append(evidence_record)
        for kind, nested_key in (("request", "request"), ("run", "run"), ("readback", "readback_report"), ("selected", "selected_report")):
            nested = row.get(nested_key)
            if nested is None:
                continue
            nested = _dict(nested, f"battle REA {rva}.{nested_key}", audit)
            nested_record = _validate_pinned_file(audit, nested, f"battle REA {rva}.{nested_key}")
            if nested_record:
                nested_record.update({"role": f"battle-rea-{rva}-{kind}", "kind": "rea_evidence"})
                rea_files.append(nested_record)
        request = _dict(row.get("request"), f"battle REA {rva}.request", audit)
        run = _dict(row.get("run"), f"battle REA {rva}.run", audit)
        audit.require(request.get("status") == "passed" and run.get("status") == "passed", f"battle REA {rva} request/run status changed")
        processes = _list(run.get("processes"), f"battle REA {rva}.run.processes", audit)
        for process in processes:
            process = _dict(process, f"battle REA {rva}.run.process", audit)
            audit.require(process.get("closed") is True and process.get("below_1gb") is True, f"battle REA {rva} process guard failed")
    selection_errors = [row for row in rea_records if isinstance(row, dict) and row.get("selection_role") == "selection_error"]
    audit.require(len(selection_errors) == 1 and selection_errors[0].get("usable_for_writer_semantics") is False, "battle selection-error pin changed")
    related = _list(index.get("related_reports"), "battle index.related_reports", audit)
    related_records: list[dict[str, Any]] = []
    for row in related:
        if not isinstance(row, dict) or not isinstance(row.get("path"), str):
            audit.errors.append("battle related report malformed")
            continue
        try:
            rel, path = _bounded_path(row["path"])
            actual = _sha256(path)
            expected = _hex_sha(row.get("sha256"), f"battle related {rel}.sha256")
            audit.require(actual == expected, f"battle related report changed: {rel}")
            related_records.append({"path": rel, "bytes": path.stat().st_size, "sha256": actual, "role": row.get("role"), "status": row.get("status")})
        except AuditError as exc:
            audit.errors.append(str(exc))
    return {
        "index": index,
        "index_sha256": index_sha,
        "index_path": index_rel,
        "source_audit": source_audit,
        "source_audit_sha256": source_sha,
        "source_audit_path": source_rel,
        "queue": queue,
        "queue_sha256": queue_sha,
        "queue_path": queue_rel,
        "queue_sources": list(actual_queue_sources.values()),
        "rea_files": rea_files,
        "related": related_records,
    }


def _validate_fixture(audit: Audit, fixture_path: str, native_meta: dict[str, Any], live_report: dict[str, Any]) -> dict[str, Any]:
    rel, file, fixture = _load_json(fixture_path)
    digest = _sha256(file)
    audit.inputs["fixture"] = {"path": rel, "bytes": file.stat().st_size, "sha256": digest}
    audit.require(fixture.get("format") in {"information_domestic_pressure_live_1374_v1", "information_domestic_pressure_live_fixture_v2"}, "fixture format is not the self-contained live format")
    expected = _dict(fixture.get("expected"), "fixture.expected", audit)
    audit.require(expected.get("country") == "FRA" and set(_dict(expected.get("fields"), "fixture.expected.fields", audit)) == set(EXPECTED_FIELDS), "fixture expected scope mismatch")
    audit.require(expected.get("game_version") == EXPECTED_GAME_VERSION and expected.get("game_sha256") == EXPECTED_EXE_SHA256, "fixture target build mismatch")
    audit.require(expected.get("game_date") == live_report.get("game_date"), "fixture date mismatch")
    for field in EXPECTED_FIELDS:
        row = _dict(expected.get("fields", {}).get(field), f"fixture.expected.{field}", audit)
        audit.require(row.get("raw") == native_meta["values"].get(field) and row.get("scale") == 1000 and row.get("unit") == field, f"fixture expected {field} differs from native")
    capture = _dict(fixture.get("native_capture"), "fixture.native_capture", audit)
    report = _dict(fixture.get("native_report"), "fixture.native_report", audit)
    mcp = _dict(fixture.get("mcp"), "fixture.mcp", audit)
    provenance = _dict(fixture.get("provenance"), "fixture.provenance", audit)
    audit.require(provenance.get("self_contained") is True and provenance.get("recorded_only") is True and provenance.get("runtime_dependency") is False, "fixture provenance is not self-contained recorded-only")
    audit.require(provenance.get("mode") == "recorded" and provenance.get("original_mode") == "live", "fixture mode provenance mismatch")
    audit.require(report.get("raw_capture_sha256") == native_meta.get("capture_sha256"), "fixture native report capture SHA mismatch")
    audit.require(report.get("installation_sha256") == live_report.get("installation_sha256"), "fixture native report installation SHA mismatch")
    audit.require(report.get("values") == native_meta["values"] and report.get("session_id") == native_meta["identity"].get("session_id"), "fixture native report identity/value mismatch")
    audit.require(capture.get("status") == "observed" and capture.get("completed") is True, "fixture native capture is not observed complete")
    mcp_report = _dict(mcp.get("report"), "fixture.mcp.report", audit)
    audit.require(mcp_report.get("status") == "passed" and mcp_report.get("session_id") == live_report.get("session_id"), "fixture MCP report identity/status mismatch")
    audit.require(mcp_report.get("mcp_wire_audit_sha256") == live_report.get("mcp_wire_audit_sha256"), "fixture MCP wire SHA mismatch")
    audit.require(isinstance(mcp.get("manual"), dict) and isinstance(mcp.get("single_fields"), dict) and isinstance(mcp.get("mixed_unimplemented"), dict), "fixture MCP result components incomplete")
    periodic = mcp.get("periodic")
    audit.require(isinstance(periodic, list) and len(periodic) == 3, "fixture periodic result count mismatch")
    wire = _dict(mcp.get("wire_audit"), "fixture.mcp.wire_audit", audit)
    audit.require(wire.get("raw_payloads_written") is False, "fixture wire audit writes raw payloads")
    return fixture


def _validate_recovery_controls(audit: Audit, stage: Path, identity: dict[str, Any], native_date: int | None, installation_sha: str) -> dict[str, Any]:
    """Validate the fixed control/health snapshots without opening control-probe output."""

    paths = {
        "startup": stage / "startup-recovery-001.json",
        "final_control": stage / "final-control-001.json",
        "final_health": stage / "final-health-001.json",
    }
    records: dict[str, Any] = {}
    for label, path in paths.items():
        rel, file, data = _load_json(str(path))
        audit.inputs[f"recovery_{label}"] = {"path": rel, "bytes": file.stat().st_size, "sha256": _sha256(file)}
        records[label] = data
    startup = records["startup"]
    audit.require(startup.get("status") == "passed", "startup recovery report is not passed")
    binding = _dict(startup.get("binding"), "startup.binding", audit)
    for key in ("pid", "creation_filetime", "session_id", "game_sha256", "dll_sha256"):
        expected = identity.get(key) if key != "dll_sha256" else EXPECTED_DLL_SHA256
        audit.require(binding.get(key) == expected, f"startup.binding.{key} mismatch")
    restored = _dict(startup.get("restored_save"), "startup.restored_save", audit)
    audit.require(restored.get("sha256") == "ffa91dbd2a2d544b18d586a895bb9b0c2b90e94ece47b2c74507555b8f58c2e0", "startup restored-save SHA mismatch")
    scope = _dict(startup.get("scope"), "startup.scope", audit)
    for key in ("new_business_request_submitted", "old_business_request_replayed", "game_date_advanced_after_load", "new_save_created", "battle_hook_installed", "production_header_in_loaded_dll"):
        audit.require(scope.get(key) is False, f"startup scope.{key} is not false")
    _all_true(startup.get("checks"), "startup.checks", audit)
    final_pause = _dict(startup.get("final_pause"), "startup.final_pause", audit)
    audit.require(final_pause.get("pid") == identity.get("pid") and final_pause.get("date_raw") == native_date and final_pause.get("speed") == 0 and final_pause.get("paused_flag") == 1, "startup final pause snapshot mismatch")

    control = records["final_control"]
    audit.require(control.get("read_only") is True and control.get("pid") == identity.get("pid"), "final control read-only/PID mismatch")
    audit.require(control.get("date_raw") == native_date and control.get("speed") == 0 and control.get("paused_flag") == 1, "final control date/pause mismatch")

    health = records["final_health"]
    audit.require(health.get("status") == "passed", "final health status is not passed")
    audit.require(health.get("pid") == identity.get("pid") and health.get("creation_filetime") == identity.get("creation_filetime") and health.get("session_id") == identity.get("session_id"), "final health identity mismatch")
    health_state = _dict(health.get("health"), "final_health.health", audit)
    audit.require(health_state.get("status") == "ready" and health_state.get("complete") is True and health_state.get("date_raw") == native_date, "final health state/date mismatch")
    audit.require(health.get("pending_request_files") == [], "final health reports pending request files")
    audit.require(health.get("installation_sha256") == installation_sha, "final health installation SHA mismatch")
    return records


def _path_record(path: str, *, role: str, kind: str | None = None) -> dict[str, Any]:
    rel, file = _bounded_path(path)
    return {"path": rel, "bytes": file.stat().st_size, "sha256": _sha256(file), "role": role, "kind": kind or role}


def _add_source(sources: dict[str, dict[str, Any]], path: str, *, role: str, kind: str | None = None) -> None:
    rel, _ = _root_relative(path)
    if rel in sources:
        return
    sources[rel] = _path_record(path, role=role, kind=kind)


def _archive_sources(
    audit: Audit,
    args: argparse.Namespace,
    profile_refs: list[dict[str, Any]],
    native_meta: dict[str, Any],
    battle: dict[str, Any],
    test_data: dict[str, Any],
) -> list[dict[str, Any]]:
    sources: dict[str, dict[str, Any]] = {}
    core = [
        "bridge/information/domestic_pressure.py",
        "bridge/information/domestic_pressure_memory.py",
        "bridge/information/catalog.py",
        "bridge/information/composite.py",
        "bridge/information/service.py",
        "bridge/information/sources.py",
        "bridge/information/model.py",
        "tools/serve_information.py",
        "work/capture_information_domestic_pressure.py",
        "work/validate_information_domestic_pressure.py",
        "work/validate_information_domestic_pressure_live_004.py",
        args.installation,
    ]
    for path in core:
        _add_source(sources, path, role="recovery-input")
    _add_source(sources, args.profile, role="current_profile", kind="static_profile")
    _add_source(sources, args.contract, role="current_contract", kind="static_contract")
    _add_source(sources, args.native_capture, role="independent_native_capture", kind="native_runtime_evidence")
    _add_source(sources, args.native_report, role="independent_native_report", kind="native_runtime_evidence")
    _add_source(sources, args.save_crosscheck, role="recorded_save_crosscheck", kind="recorded_save_evidence")
    _add_source(sources, args.fixture, role="self_contained_fixture", kind="fixture")
    for path, role, kind in (
        (args.coverage_stage, "recovery_coverage_export", "coverage_export"),
        (args.coverage_docs, "coverage_docs_snapshot", "coverage_export"),
        (args.baseline_manifest, "batch11_baseline_manifest", "baseline_manifest"),
        (args.battle_index, "battle_research_index", "battle_static_evidence"),
        (args.battle_source_audit, "battle_source_audit", "battle_static_evidence"),
        (args.queue_report, "battle_queue_test", "battle_static_evidence"),
    ):
        _add_source(sources, path, role=role, kind=kind)
    for row in battle.get("queue_sources", []):
        _add_source(sources, row["path"], role=f"battle-queue-{row['path'].rsplit('/', 1)[-1]}", kind="battle_queue_source")
    for row in battle.get("rea_files", []):
        _add_source(sources, row["path"], role=row.get("role") or "battle-rea-evidence", kind=row.get("kind") or "rea_evidence")
    # These are the bounded, named scripts that produced or froze the seven
    # layout queries.  This is an explicit list; no work tree is traversed.
    for path in (
        "work/extract_information_battle_layout_evidence.py",
        "work/freeze_information_battle_layout_research.py",
        "work/probe_information_battle_result_vtable.py",
        "work/probe_information_battle_save_keys.py",
        "work/probe_information_battle_side_save_keys.py",
        "work/scout_information_battle_messages.py",
        "work/audit_information_recovery_delivery.py",
    ):
        _add_source(sources, path, role="battle_research_script", kind="reproducibility_script")
    # Keep the current information source graph flat and explicit.  These
    # globs are restricted to one directory level and never enter old
    # delivery trees.
    for path in sorted((ROOT / "bridge/information").glob("*.py")):
        _add_source(sources, path, role="information_source", kind="information_source")
    for path in sorted((ROOT / "bridge/tests").glob("test_information_*.py")):
        _add_source(sources, path, role="information_test", kind="information_test")
    for path in sorted((ROOT / "bridge/tests/fixtures").glob("information_*") ):
        if path.is_file():
            _add_source(sources, path, role="information_fixture", kind="information_fixture")
    for path in sorted((ROOT / "bridge/information/profiles").glob("*.json")):
        _add_source(sources, path, role="information_profile", kind="information_profile")
    for path, role, kind in (
        ("work/runtime/information-recovery-20261025-001/startup-recovery-001.json", "startup_recovery", "runtime_control_evidence"),
        ("work/runtime/information-recovery-20261025-001/final-control-001.json", "final_control", "runtime_control_evidence"),
        ("work/runtime/information-recovery-20261025-001/final-health-001.json", "final_health", "runtime_control_evidence"),
        ("work/prepare_information_observer_reuse.py", "binary_reuse_helper", "offline_helper"),
        ("work/export_information_recovery_coverage.py", "coverage_exporter", "offline_helper"),
        ("work/verify_information_mcp_closure.py", "mcp_closure_probe_helper", "offline_helper"),
    ):
        _add_source(sources, path, role=role, kind=kind)
    for name, role in (
        ("before-control.json", "mcp_closure_probe_before"),
        ("after-control.json", "mcp_closure_probe_after"),
        ("mcp-wire-audit.json", "mcp_closure_probe_wire"),
    ):
        _add_source(sources, Path(args.closure_probe_dir) / name, role=role, kind="mcp_server_evidence")
    for dep in profile_refs:
        _add_source(sources, dep["path"], role=dep.get("role") or "profile-dependency", kind="profile_dependency")
    for row in battle.get("related", []):
        _add_source(sources, row["path"], role=row.get("role") or "battle-related-report", kind="battle_static_evidence")
    live_dir = args.live_dir
    for name, role in (
        ("report.json", "live_report"),
        ("mcp-wire-audit.json", "mcp_wire_audit"),
        ("final-status-summary.json", "live_final_context"),
        ("manual-result.json", "live_manual_result"),
        ("single-field-results.json", "live_single_field_result"),
        ("mixed-unimplemented-result.json", "live_mixed_result"),
        ("periodic-results.json", "live_periodic_results"),
        ("discovery-summary.json", "live_discovery"),
    ):
        _add_source(sources, str(Path(live_dir) / name), role=role, kind="live_mcp_evidence")
    for index in range(1, 4):
        periodic_dir = Path(live_dir) / f"native-periodic-{index:03d}"
        _add_source(sources, periodic_dir / "native-capture.json", role=f"native_periodic_{index:03d}_capture", kind="native_runtime_evidence")
        _add_source(sources, periodic_dir / "report.json", role=f"native_periodic_{index:03d}_report", kind="native_runtime_evidence")
    if _root_relative(args.server_closure)[1].exists():
        _add_source(sources, args.server_closure, role="mcp_server_closure", kind="mcp_server_evidence")
    for row in test_data.get("artifacts", []):
        _add_source(sources, row["path"], role="test-artifact", kind="test_artifact")
    for row in test_data.get("sources", []):
        _add_source(sources, row["path"], role="test-source", kind="source_code_or_fixture")
    for doc in (
        "docs/逐场战报原生来源.md",
        "docs/信息字段覆盖.json",
        "docs/信息导出与订阅开发计划.md",
        "docs/信息导出开发进展.md",
        "docs/信息接口使用说明.md",
        "docs/信息服务合同.md",
        "docs/国家资源信息接口.md",
        "docs/国内压力原生来源.md",
        "docs/信息计划验收清单.md",
        "docs/逐场战报原生来源.md",
        "开发过程自动化.md",
        "HANDOFF.md",
        "README(agent).md",
    ):
        _add_source(sources, doc, role="documentation", kind="documentation")
    _add_source(sources, args.test_summary, role="test-summary", kind="test_summary")
    if args.test_summary_baseline:
        _add_source(sources, args.test_summary_baseline, role="test-summary-baseline", kind="baseline_test_summary")
    # The 43 MiB save is intentionally not in this list.  Its recorded SHA is
    # checked by _validate_save_crosscheck and is retained in the manifest.
    return list(sources.values())


def _copy_archive(stage: Path, records: list[dict[str, Any]], *, revision: str, metadata: dict[str, Any]) -> Path:
    delivery = stage / "delivery"
    if delivery.exists():
        raise AuditError(f"refusing to overwrite existing delivery: {delivery}")
    total = 0
    for record in records:
        if record["bytes"] > MAX_SINGLE_BYTES:
            raise AuditError(f"archive source exceeds single-file bound: {record['path']}")
        total += record["bytes"]
    if total > MAX_TOTAL_BYTES:
        raise AuditError(f"archive source set exceeds total bound: {total}")
    temp = stage / f".delivery-{revision}.tmp"
    if temp.exists():
        raise AuditError(f"refusing to overwrite temporary delivery: {temp}")
    temp.mkdir(parents=True)
    copied: list[dict[str, Any]] = []
    try:
        for record in records:
            source = ROOT / Path(*record["path"].split("/"))
            destination = temp / "files" / Path(*record["path"].split("/"))
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)
            copied_sha = _sha256(destination)
            if copied_sha != record["sha256"] or destination.stat().st_size != record["bytes"]:
                raise AuditError(f"source changed while archiving: {record['path']}")
            copied.append({**record, "archive_path": (Path("files") / Path(*record["path"].split("/"))).as_posix()})
        manifest = {
            "schema": "information_recovery_delivery_manifest_v1",
            "revision": revision,
            "mode": "limited_production_accepted_recorded_and_live_evidence",
            "goal_complete": False,
            "identity": metadata.get("identity"),
            "coverage": EXPECTED_COVERAGE,
            "live": metadata.get("live"),
            "native": metadata.get("native"),
            "save_crosscheck": metadata.get("save_crosscheck"),
            "test_summary": metadata.get("test_summary"),
            "baseline": metadata.get("baseline"),
            "evidence_boundaries": {
                "live_native_runtime": "observed live read-only native capture and MCP results",
                "recorded_save": "historical literal equality only; no save file copied",
                "battle_research": "static REA/ordinary index only; no dispatch authority",
                "goal_complete": False,
            },
            "file_count": len(copied),
            "total_bytes": total,
            "files": copied,
        }
        (temp / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        temp.replace(delivery)
    except Exception:
        shutil.rmtree(temp, ignore_errors=True)
        raise
    return delivery


def run(args: argparse.Namespace) -> tuple[dict[str, Any], int]:
    audit = Audit()
    stage = (ROOT / Path(*str(args.stage).replace("\\", "/").split("/"))).resolve()
    if ROOT not in stage.parents and stage != ROOT:
        raise AuditError("stage escapes workspace")
    try:
        stage.mkdir(parents=True, exist_ok=True)
        profile, contract, profile_deps, profile_refs = _validate_profile_contract(audit, args.profile, args.contract)
        _install_rel, _install_file, installation = _load_json(args.installation)
        installation_identity = _identity_from_installation(installation, audit)
        capture, native_report, native_meta = _validate_native_capture(audit, args.native_capture, args.native_report, args.installation, profile)
        native_values = _field_values(capture, label="native", audit=audit)
        recovery_controls = _validate_recovery_controls(audit, stage, installation_identity, _validate_snapshot(capture.get("before"), "native.before.recheck", audit), native_meta["installation_sha256"])
        save_crosscheck = _validate_save_crosscheck(audit, args.save_crosscheck, native_values, native_meta)
        live_report, live_meta = _validate_live(audit, args.live_report, args.live_dir, capture, native_meta, args.installation)
        server_closure = _validate_mcp_server_closure(audit, args.server_closure, live_report, live_meta, args.closure_probe_dir)
        _compare_context({"session_id": live_report.get("session_id"), "game_date": live_report.get("game_date")}, {"session_id": native_meta["identity"].get("session_id"), "game_date": _validate_snapshot(capture.get("before"), "native.before.recheck", audit)}, "live/native", audit)
        coverage = _validate_coverage(audit, args.coverage_stage, args.coverage_docs)
        fixture = _validate_fixture(audit, args.fixture, {"values": native_values, **native_meta}, live_report)
        test_data = _validate_test_summary(audit, args.test_summary, args.test_summary_baseline)
        baseline = _validate_baseline_manifest(audit, args.baseline_manifest)
        battle = _validate_battle_pins(audit, args.battle_index, args.battle_source_audit, args.queue_report)
        audit_record: dict[str, Any] = {
            "schema": "information_recovery_delivery_audit_v1",
            "status": "passed" if not audit.errors else "failed",
            "mode": "offline_bounded_audit",
            "goal_complete": False,
            "bounds": {"max_single_file_bytes": MAX_SINGLE_BYTES, "max_archive_bytes": MAX_TOTAL_BYTES, "large_save_policy": "recorded_sha_only"},
            "identity": installation_identity,
            "inputs": audit.inputs,
            "checks": {
                "profile_contract": {"status": "observed", "profile_version": profile.get("profile_version"), "contract_id": contract.get("contract_id"), "current_profile_dependency_count": len(profile_deps), "profile_group_count": audit.inputs.get("profile_groups", {}).get("count"), "profile_reference_occurrences": audit.inputs.get("profile_groups", {}).get("reference_occurrences"), "guard_count": len(profile.get("code_guards", []))},
                "native": {"status": native_report.get("status"), "capture_sha256": native_meta.get("capture_sha256"), "report_sha256": native_meta.get("report_sha256"), "values": native_values},
                "recovery_controls": {"status": "passed", "startup": audit.inputs.get("recovery_startup"), "final_control": audit.inputs.get("recovery_final_control"), "final_health": audit.inputs.get("recovery_final_health")},
                "live": {"status": live_report.get("status"), "schema": live_report.get("schema"), "wire_sha256": live_meta.get("wire_sha256"), "subscription": live_report.get("subscription"), "periodic_native_child_exit_zero": True, "mcp_server_closure": server_closure, "mcp_server_exit_evidence": "standalone health probe direct OS exit; original live-005 exit not recorded; live-005 close is runner control-flow inference only"},
                "save_crosscheck": {"status": save_crosscheck.get("status"), "mode": save_crosscheck.get("mode"), "save_sha256": save_crosscheck.get("save_sha256"), "world_generation_verified": save_crosscheck.get("world_generation_verified")},
                "coverage": coverage.get("counts"),
                "fixture": {"status": "self_contained_recorded", "sha256": audit.inputs.get("fixture", {}).get("sha256")},
                "tests": {"status": test_data["summary"].get("status"), "information_failure_error_zero": True, "full_suite_green": False, "comparison": test_data.get("comparison")},
                "baseline": {"sha256": baseline.get("sha256"), "changed_allowed": baseline.get("changed_allowed", []), "unexpected": baseline.get("unexpected", [])},
                "battle": {"index_sha256": battle.get("index_sha256"), "source_audit_sha256": battle.get("source_audit_sha256"), "queue_sha256": battle.get("queue_sha256"), "rea_count": battle.get("index", {}).get("rea_count"), "selection_error_count": battle.get("index", {}).get("selection_error_count")},
            },
            "archive": {"status": "not_requested", "source_count": 0, "total_bytes": 0},
            "warnings": audit.warnings,
            "errors": audit.errors,
        }
        if args.archive and not audit.errors:
            records = _archive_sources(audit, args, profile_refs, native_meta, battle, test_data)
            audit_record["archive"] = {"status": "planned", "source_count": len(records), "total_bytes": sum(row["bytes"] for row in records), "sources": records}
            if audit.errors:
                audit_record["status"] = "failed"
            else:
                delivery = _copy_archive(stage, records, revision=args.revision, metadata={"identity": installation_identity, "live": live_report, "native": native_report, "save_crosscheck": save_crosscheck, "test_summary": test_data["summary"], "baseline": baseline})
                audit_record["archive"] = {"status": "created", "path": delivery.relative_to(ROOT).as_posix(), "source_count": len(records), "total_bytes": sum(row["bytes"] for row in records)}
        output = stage / f"audit-{args.revision}.json"
        if output.exists():
            raise AuditError(f"refusing to overwrite audit output: {output}")
        output.write_text(json.dumps(audit_record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        return audit_record, 0 if audit_record["status"] == "passed" else 1
    except (AuditError, OSError, ValueError) as exc:
        record = {
            "schema": "information_recovery_delivery_audit_v1",
            "status": "failed",
            "mode": "offline_bounded_audit",
            "goal_complete": False,
            "bounds": {"max_single_file_bytes": MAX_SINGLE_BYTES, "max_archive_bytes": MAX_TOTAL_BYTES},
            "errors": [str(exc)],
        }
        output = stage / f"audit-{args.revision}.json"
        if not output.exists():
            stage.mkdir(parents=True, exist_ok=True)
            output.write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        return record, 1


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stage", default="work/runtime/information-recovery-20261025-001")
    parser.add_argument("--revision", default="001", choices=[f"{i:03d}" for i in range(1, 1000)])
    parser.add_argument("--profile", default="bridge/information/profiles/domestic-pressure-memory-1374.json")
    parser.add_argument("--contract", default="work/runtime/information-domestic-pressure-20261025-001/native-domestic-pressure-contract-003.json")
    parser.add_argument("--installation", default="work/runtime/diplomacy-observer-20261025-information-battle-002/installation.json")
    parser.add_argument("--native-capture", default="work/runtime/information-domestic-pressure-20261025-001/independent-native-002/native-capture.json")
    parser.add_argument("--native-report", default="work/runtime/information-domestic-pressure-20261025-001/independent-native-002/report.json")
    parser.add_argument("--live-dir", default="work/runtime/information-domestic-pressure-20261025-001/live-acceptance-005")
    parser.add_argument("--live-report", default="work/runtime/information-domestic-pressure-20261025-001/live-acceptance-005/report.json")
    parser.add_argument("--server-closure", default="work/runtime/information-recovery-20261025-001/mcp-server-closure-001.json", help="separate MCP server close/wait/exit receipt; native sample returncodes do not satisfy this")
    parser.add_argument("--closure-probe-dir", default="work/runtime/information-recovery-20261025-001/mcp-closure-probe-001", help="bounded before/after/wire evidence for the standalone MCP closure probe")
    parser.add_argument("--save-crosscheck", default="work/runtime/information-domestic-pressure-20261025-001/save-native-crosscheck-002.json")
    parser.add_argument("--fixture", default="bridge/tests/fixtures/information_domestic_pressure_live_1374.json")
    parser.add_argument("--coverage-stage", default="work/runtime/information-recovery-20261025-001/coverage-001.json")
    parser.add_argument("--coverage-docs", default="docs/信息字段覆盖.json")
    parser.add_argument("--test-summary", required=True, help="new full/information test summary; never defaults to an old summary")
    parser.add_argument("--test-summary-baseline", default="work/runtime/information-mission-rewards-20261025-001/test-summary-002.json")
    parser.add_argument("--baseline-manifest", default="work/runtime/information-mission-rewards-20261025-001/delivery/manifest.json")
    parser.add_argument("--battle-index", default="work/runtime/information-battle-layout-20261025-001/research-index-001.json")
    parser.add_argument("--battle-source-audit", default="work/runtime/information-battle-layout-20261025-001/source-audit-001.json")
    parser.add_argument("--queue-report", default="work/runtime/information-battle-layout-20261025-001/native-buffer-test-001/report.json")
    parser.add_argument("--archive", action="store_true", help="after a passed audit, create a new delivery directory")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    record, code = run(args)
    print(json.dumps({"status": record.get("status"), "audit": str((ROOT / Path(*str(args.stage).replace("\\", "/").split("/")) / f"audit-{args.revision}.json").relative_to(ROOT)), "errors": len(record.get("errors", [])), "archive": record.get("archive", {}).get("status")}, ensure_ascii=False))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
