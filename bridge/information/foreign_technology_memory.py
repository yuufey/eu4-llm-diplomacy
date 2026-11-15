"""Bounded, private foreign-country technology cache reader.

This leaf binds requested tags to country-manager rows and copies the fixed
1.37.4 ``mil_tech`` cache value twice.  It never opens a process or calls a
native function.  Two stable reads establish only a private cache observation;
foreign-target admission and public visibility remain unknown.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from bridge.information import country_reference_memory
from bridge.information import military_quality_memory


SCHEMA = "information.foreign_technology_memory.v1"
BASIS = "pure_RPM_technology_cache_not_UI_observation"
OBSERVER_TAG = "FRA"
MAX_TARGETS = 8
MAX_COUNTRY_SLOTS = 4096
MAX_TOTAL_READ_BYTES = 512 * 1024
MAX_MISMATCH_PATHS = 256
_MAX_U64 = 0xFFFFFFFFFFFFFFFF
_TAG_ALPHABET = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")


class _ReadBudgetExceeded(RuntimeError):
    def __init__(self, address: int, size: int, label: str, limit: int):
        super().__init__(f"global_read_budget_exceeded:{label}")
        self.address = address
        self.size = size
        self.label = label
        self.limit = limit


class _BoundedReader:
    """Account every delegated memory request across both complete passes."""

    def __init__(self, reader: Any, limit: int = MAX_TOTAL_READ_BYTES):
        self._reader = reader
        self.limit = limit
        self.bytes_requested = 0
        self.bytes_returned = 0
        self.calls = 0
        self.max_single_read = 0
        self.rejected_bytes = 0

    def read(self, address: int, size: int, label: str) -> bytes:
        if type(size) is not int or size <= 0:
            raise ValueError(f"read_size_invalid:{label}")
        if self.bytes_requested + size > self.limit:
            self.rejected_bytes += size
            raise _ReadBudgetExceeded(address, size, label, self.limit)
        self.bytes_requested += size
        self.calls += 1
        self.max_single_read = max(self.max_single_read, size)
        raw = self._reader.read(address, size, label)
        try:
            self.bytes_returned += len(raw)
        except TypeError:
            pass
        return raw


def _visibility() -> dict[str, Any]:
    return {
        "status": "unknown",
        "reason": "FOREIGN_TARGET_ADMISSION_NOT_VERIFIED",
        "complete": False,
        "public_export_ready": False,
    }


def _hex_u64(value: Any, label: str) -> int:
    if isinstance(value, bool):
        raise ValueError(f"expected_ref_invalid:{label}")
    if isinstance(value, int):
        result = value
    elif isinstance(value, str):
        try:
            result = int(value, 0)
        except ValueError as exc:
            raise ValueError(f"expected_ref_invalid:{label}") from exc
    else:
        raise ValueError(f"expected_ref_invalid:{label}")
    if not 0 <= result <= _MAX_U64:
        raise ValueError(f"expected_ref_invalid:{label}")
    return result


def _valid_tag(tag: Any) -> bool:
    return (isinstance(tag, str) and len(tag) == 3
            and all(char in _TAG_ALPHABET for char in tag))


def _tag_from_fullref(value: int) -> str | None:
    raw = (value & 0xFFFFFF).to_bytes(3, "little")
    if not all(byte in b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" for byte in raw):
        return None
    return raw.decode("ascii")


def _normalize_request(
    observer: Any,
    targets: Any,
    expected_refs: Any,
) -> tuple[str | None, list[str], dict[str, str], list[dict[str, Any]]]:
    errors: list[dict[str, Any]] = []
    observer_tag = observer if isinstance(observer, str) else None
    target_tags: list[str] = []
    normalized_refs: dict[str, str] = {}

    if not _valid_tag(observer):
        errors.append({"code": "observer_tag_invalid", "path": "observer", "detail": "expected uppercase three-character tag"})
    elif observer != OBSERVER_TAG:
        errors.append({"code": "observer_not_supported", "path": "observer", "detail": "this private reader currently accepts observer FRA only"})

    if not isinstance(targets, (list, tuple)):
        errors.append({"code": "target_list_invalid", "path": "targets", "detail": "expected list or tuple"})
    elif not targets:
        errors.append({"code": "invalid_request", "path": "targets", "detail": "at least one target is required"})
    elif len(targets) > MAX_TARGETS:
        errors.append({"code": "target_count_out_of_range", "path": "targets", "detail": f"maximum is {MAX_TARGETS}"})
    else:
        seen: set[str] = set()
        for index, tag in enumerate(targets):
            if not _valid_tag(tag):
                errors.append({"code": "target_tag_invalid", "path": f"targets[{index}]", "detail": "expected uppercase three-character tag"})
                continue
            if tag == observer_tag:
                errors.append({"code": "target_alias_observer", "path": f"targets[{index}]", "detail": tag})
            if tag in seen:
                errors.append({"code": "duplicate_target", "path": f"targets[{index}]", "detail": tag})
            seen.add(tag)
            target_tags.append(tag)

    requested = {tag for tag in ([observer_tag] if observer_tag else []) + target_tags}
    if expected_refs is None:
        expected_refs = {}
    if not isinstance(expected_refs, Mapping):
        errors.append({"code": "expected_refs_invalid", "path": "expected_refs", "detail": "expected a mapping"})
    else:
        seen_values: dict[int, str] = {}
        for tag, raw_ref in expected_refs.items():
            if tag not in requested:
                errors.append({"code": "expected_ref_not_requested", "path": f"expected_refs.{tag}", "detail": "tag is not in this request"})
                continue
            try:
                value = _hex_u64(raw_ref, str(tag))
            except ValueError as exc:
                errors.append({"code": "expected_ref_invalid", "path": f"expected_refs.{tag}", "detail": str(exc)})
                continue
            if not _valid_tag(tag) or _tag_from_fullref(value) != tag:
                errors.append({"code": "expected_ref_tag_mismatch", "path": f"expected_refs.{tag}", "detail": hex(value)})
                continue
            prior = seen_values.get(value)
            if prior is not None and prior != tag:
                errors.append({"code": "expected_ref_alias", "path": f"expected_refs.{tag}", "detail": f"same fullref as {prior}"})
                continue
            seen_values[value] = tag
            normalized_refs[tag] = hex(value)

    return observer_tag, target_tags, normalized_refs, errors


def _base_result(
    observer: str | None,
    targets: list[str],
    expected_refs: Mapping[str, str],
    limiter: _BoundedReader | None,
    *,
    status: str = "unknown",
    errors: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "status": status,
        "basis": BASIS,
        "profile": {
            "profile_id": "military-quality-memory-1374",
            "profile_sha256": military_quality_memory.EXPECTED_PROFILE_SHA256,
            "game_version": military_quality_memory.EXPECTED_VERSION,
            "executable_sha256": military_quality_memory.EXPECTED_EXE_SHA256,
        },
        "observer": {
            "tag": observer,
            "fullref": None,
            "binding_status": "unknown",
            "bindings_by_pass": {"pass1": None, "pass2": None},
        },
        "targets": [
            {
                "tag": tag,
                "fullref": None,
                "binding_status": "unknown",
                "bindings_by_pass": {"pass1": None, "pass2": None},
                "technology": {
                    "status": "unknown",
                    "reason": "NOT_STABLE_TWO_PASS",
                    "value": None,
                    "raw_hex": None,
                    "lookup": None,
                    "state": None,
                    "guard_by_pass": {"pass1": None, "pass2": None},
                    "basis": BASIS,
                },
                "pass_evidence": {"pass1": None, "pass2": None},
                "admission_by_pass": {"pass1": None, "pass2": None},
            }
            for tag in targets
        ],
        "admission": {
            "status": "unknown",
            "reason": "FOREIGN_TARGET_ADMISSION_NOT_VERIFIED",
            "provided": False,
            "by_target": {},
        },
        "expected_refs": dict(expected_refs),
        "country_scans": [],
        "runtime_code_guards": [],
        "consistency": {
            "status": "incomplete",
            "passed": False,
            "completed_passes": 0,
            "mismatch_paths": [],
        },
        "budget": {
            "limit_bytes": MAX_TOTAL_READ_BYTES,
            "bytes_requested": limiter.bytes_requested if limiter else 0,
            "bytes_returned": limiter.bytes_returned if limiter else 0,
            "calls": limiter.calls if limiter else 0,
            "max_single_read": limiter.max_single_read if limiter else 0,
            "rejected_bytes": limiter.rejected_bytes if limiter else 0,
            "country_slot_limit": MAX_COUNTRY_SLOTS,
            "target_limit": MAX_TARGETS,
        },
        "visibility": _visibility(),
        "errors": list(errors or []),
    }


def _country_scan_evidence(scan: Mapping[str, Any]) -> dict[str, Any]:
    fields = (
        "status", "basis", "module_base", "database_global_rva",
        "database_global_address", "database_global_raw_hex", "database",
        "table_pointer_address", "table_pointer_raw_hex", "table",
        "count_address", "count_raw_hex", "count", "requested", "read_summary",
    )
    return {key: scan.get(key) for key in fields}


def _read_one_pass(
    pass_number: int,
    limiter: _BoundedReader,
    module_base: int,
    observer: str,
    targets: list[str],
    expected_refs: Mapping[str, int | str],
    profile: Mapping[str, Any],
    admission_reader: Any = None,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    errors: list[dict[str, Any]] = []
    guard_budget = military_quality_memory._ReadBudget(military_quality_memory.READ_BUDGET_BYTES)
    guard = military_quality_memory._runtime_code_guard(
        limiter, module_base, profile, guard_budget
    )
    result: dict[str, Any] = {
        "pass": pass_number,
        "runtime_code_guard": guard,
        "country_scan": None,
        "technology_by_tag": {},
        "admission_by_tag": {},
        "status": "incomplete",
    }
    if guard.get("status") != "observed":
        errors.append({
            "code": "runtime_code_guard_failed",
            "path": f"passes[{pass_number}].runtime_code_guard",
            "detail": guard,
        })
        return result, errors

    try:
        scan = country_reference_memory.resolve_countries(
            limiter.read,
            module_base,
            [observer, *targets],
            expected_refs=expected_refs,
        )
    except Exception as exc:
        errors.append({
            "code": "country_resolution_failed",
            "path": f"passes[{pass_number}].country_scan",
            "detail": f"{type(exc).__name__}:{exc}",
        })
        return result, errors

    result["country_scan"] = _country_scan_evidence(scan)
    if admission_reader is not None:
        for tag in targets:
            try:
                admission = admission_reader(
                    limiter.read, module_base, scan, observer, tag
                )
                if not isinstance(admission, Mapping):
                    raise TypeError("admission_reader_result_not_mapping")
                result["admission_by_tag"][tag] = dict(admission)
            except Exception as exc:
                result["admission_by_tag"][tag] = {
                    "status": "unknown",
                    "reason": f"{type(exc).__name__}:{exc}",
                }
                errors.append({
                    "code": "admission_reader_failed",
                    "path": f"passes[{pass_number}].admission_by_tag.{tag}",
                    "detail": result["admission_by_tag"][tag]["reason"],
                })
    for tag in targets:
        binding = scan["requested"][tag]
        country_pointer = int(binding["country_pointer"], 16)
        budget = military_quality_memory._ReadBudget(military_quality_memory.READ_BUDGET_BYTES)
        try:
            value, state = military_quality_memory._read_technology(
                limiter, module_base, country_pointer, profile, budget
            )
            result["technology_by_tag"][tag] = {
                "status": "observed",
                "value": value,
                "raw_hex": state["raw_hex"],
                "lookup": state["lookup"],
                "state": state,
                "read_bytes_reserved": budget.used,
            }
        except Exception as exc:
            detail = dict(getattr(exc, "detail", {}) or {})
            reason = getattr(exc, "reason", None) or str(exc)
            result["technology_by_tag"][tag] = {
                "status": "unknown",
                "value": None,
                "raw_hex": None,
                "lookup": detail.get("lookup"),
                "state": detail or None,
                "read_bytes_reserved": budget.used,
                "reason": reason,
            }
            errors.append({
                "code": "technology_read_failed",
                "path": f"passes[{pass_number}].technology_by_tag.{tag}",
                "detail": {"reason": reason, "state": detail, "bytes_reserved": budget.used},
            })

    result["status"] = "observed" if all(
        item.get("status") == "observed"
        for item in result["technology_by_tag"].values()
    ) else "incomplete"
    return result, errors


def _diff_paths(left: Any, right: Any, path: str) -> list[str]:
    if type(left) is not type(right):
        return [path]
    if isinstance(left, Mapping):
        result: list[str] = []
        keys = set(left) | set(right)
        for key in sorted(keys, key=str):
            child = f"{path}.{key}" if path else str(key)
            if key not in left or key not in right:
                result.append(child)
            else:
                result.extend(_diff_paths(left[key], right[key], child))
            if len(result) >= MAX_MISMATCH_PATHS:
                return result[:MAX_MISMATCH_PATHS]
        return result
    if isinstance(left, list):
        if len(left) != len(right):
            return [path]
        result = []
        for index, (a, b) in enumerate(zip(left, right)):
            result.extend(_diff_paths(a, b, f"{path}[{index}]"))
            if len(result) >= MAX_MISMATCH_PATHS:
                return result[:MAX_MISMATCH_PATHS]
        return result
    return [] if left == right else [path]


def _country_signature(scan: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: scan.get(key)
        for key in (
            "module_base", "database_global_address", "database_global_raw_hex",
            "database", "table_pointer_address", "table_pointer_raw_hex", "table",
            "count_address", "count_raw_hex", "count", "requested",
        )
    }


def _collect_mismatches(first: Mapping[str, Any], second: Mapping[str, Any]) -> list[str]:
    mismatches: list[str] = []
    mismatches.extend(_diff_paths(
        first.get("runtime_code_guard"), second.get("runtime_code_guard"),
        "runtime_code_guard",
    ))
    scan1 = first.get("country_scan")
    scan2 = second.get("country_scan")
    if isinstance(scan1, Mapping) and isinstance(scan2, Mapping):
        mismatches.extend(_diff_paths(
            _country_signature(scan1), _country_signature(scan2), "country_scan"
        ))
    for tag in sorted(set(first.get("technology_by_tag", {})) | set(second.get("technology_by_tag", {}))):
        item1 = first.get("technology_by_tag", {}).get(tag)
        item2 = second.get("technology_by_tag", {}).get(tag)
        mismatches.extend(_diff_paths(item1, item2, f"technology_by_tag.{tag}"))
    if first.get("admission_by_tag") or second.get("admission_by_tag"):
        mismatches.extend(_diff_paths(
            first.get("admission_by_tag"), second.get("admission_by_tag"),
            "admission_by_tag",
        ))
    return mismatches[:MAX_MISMATCH_PATHS]


def _binding_for(pass_result: Mapping[str, Any], tag: str) -> Any:
    scan = pass_result.get("country_scan")
    if not isinstance(scan, Mapping):
        return None
    requested = scan.get("requested")
    if not isinstance(requested, Mapping):
        return None
    return requested.get(tag)


def read_two_pass(
    reader: Any,
    module_base: int,
    observer: str,
    targets: list[str] | tuple[str, ...],
    *,
    expected_refs: Mapping[str, int | str] | None = None,
    admission_reader: Any = None,
) -> dict[str, Any]:
    """Read bounded technology-cache values for up to eight foreign targets.

    ``reader`` must expose ``read(address, size, label)`` and must already be
    bound by a parent to the intended installation/session.  This leaf does
    not establish process identity, game date, UI observation, or foreign
    visibility.  An optional trusted ``admission_reader`` may add independent
    per-target admission evidence.  Its evidence is compared across both
    passes but never makes this leaf public-export-ready.
    """
    observer_tag, target_tags, normalized_expected, input_errors = _normalize_request(
        observer, targets, expected_refs
    )
    if input_errors:
        return _base_result(
            observer_tag, target_tags, normalized_expected, None, errors=input_errors
        )
    if admission_reader is not None and not callable(admission_reader):
        return _base_result(
            observer_tag, target_tags, normalized_expected, None,
            errors=[{"code": "admission_reader_not_callable", "path": "admission_reader", "detail": None}],
        )
    method = getattr(reader, "read", None)
    if not callable(method):
        return _base_result(
            observer_tag, target_tags, normalized_expected, None,
            errors=[{"code": "reader_read_method_missing", "path": "reader.read", "detail": None}],
        )
    if (not military_quality_memory._valid_address(module_base)
            or module_base & 7
            or module_base > country_reference_memory.MAX_USER_ADDRESS_EXCLUSIVE - 1):
        return _base_result(
            observer_tag, target_tags, normalized_expected, None,
            errors=[{"code": "module_base_invalid", "path": "module_base", "detail": hex(module_base) if isinstance(module_base, int) else repr(module_base)}],
        )

    try:
        profile = military_quality_memory._active_profile()
        military_quality_memory._validate_profile_shape(profile)
    except Exception as exc:
        return _base_result(
            observer_tag, target_tags, normalized_expected, None,
            errors=[{"code": "profile_rejected", "path": "profile", "detail": f"{type(exc).__name__}:{exc}"}],
        )

    limiter = _BoundedReader(reader)
    passes: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    for pass_number in (1, 2):
        pass_result, pass_errors = _read_one_pass(
            pass_number,
            limiter,
            module_base,
            observer_tag,
            target_tags,
            expected_refs or {},
            profile,
            admission_reader,
        )
        passes.append(pass_result)
        errors.extend(pass_errors)
        if pass_result["status"] != "observed":
            break

    output = _base_result(
        observer_tag, target_tags, normalized_expected, limiter, errors=errors
    )
    output["runtime_code_guards"] = [
        {"pass": item["pass"], **item["runtime_code_guard"]} for item in passes
    ]
    output["country_scans"] = [
        {"pass": item["pass"], **item["country_scan"]}
        for item in passes if isinstance(item.get("country_scan"), Mapping)
    ]
    output["consistency"]["completed_passes"] = len(passes)
    if len(passes) == 2 and all(item["status"] == "observed" for item in passes):
        mismatches = _collect_mismatches(passes[0], passes[1])
        output["consistency"]["mismatch_paths"] = mismatches
        output["consistency"]["passed"] = not mismatches
        output["consistency"]["status"] = "stable" if not mismatches else "mismatch"
        if mismatches:
            output["errors"].append({
                "code": "two_pass_mismatch",
                "path": "consistency.mismatch_paths",
                "detail": mismatches,
            })
    else:
        output["consistency"]["status"] = "incomplete"

    output["pass_evidence"] = passes
    stable = output["consistency"]["passed"] is True
    if stable:
        output["status"] = "observed"
        output["observer"]["binding_status"] = "observed"
        output["observer"]["bindings_by_pass"] = {
            "pass1": _binding_for(passes[0], observer_tag),
            "pass2": _binding_for(passes[1], observer_tag),
        }
        output["observer"]["fullref"] = _binding_for(passes[1], observer_tag)["fullref"]
        output["admission"]["provided"] = admission_reader is not None
        if admission_reader is not None:
            admission_by_target = {
                tag: {
                    "pass1": passes[0].get("admission_by_tag", {}).get(tag),
                    "pass2": passes[1].get("admission_by_tag", {}).get(tag),
                }
                for tag in target_tags
            }
            output["admission"]["by_target"] = admission_by_target
            all_known = all(
                isinstance(item, Mapping)
                and item.get("status") in ("known", "observed", "passed")
                and type(item.get("admitted")) is bool
                for pair in admission_by_target.values()
                for item in pair.values()
            )
            output["admission"]["status"] = "known" if all_known else "unknown"
            output["admission"]["reason"] = None if all_known else "ADMISSION_EVIDENCE_INCOMPLETE"
        else:
            output["admission"]["status"] = "unknown"
            output["admission"]["reason"] = "FOREIGN_TARGET_ADMISSION_NOT_VERIFIED"
        for item in output["targets"]:
            tag = item["tag"]
            binding1 = _binding_for(passes[0], tag)
            binding2 = _binding_for(passes[1], tag)
            tech1 = passes[0]["technology_by_tag"][tag]
            tech2 = passes[1]["technology_by_tag"][tag]
            item["fullref"] = binding2["fullref"]
            item["binding_status"] = "observed"
            item["bindings_by_pass"] = {"pass1": binding1, "pass2": binding2}
            item["admission_by_pass"] = {
                "pass1": passes[0].get("admission_by_tag", {}).get(tag),
                "pass2": passes[1].get("admission_by_tag", {}).get(tag),
            }
            item["pass_evidence"] = {"pass1": tech1, "pass2": tech2}
            state = tech2["state"]
            item["technology"] = {
                "status": "observed",
                "reason": None,
                "value": tech2["value"],
                "raw_hex": tech2["raw_hex"],
                "lookup": tech2["lookup"],
                "state": state,
                "country_pointer": binding2["country_pointer"],
                "technology_pointer": state["technology_pointer"],
                "vector": {
                    "begin": state["vector_begin"],
                    "end": state["vector_end"],
                    "count": state["vector_count"],
                    "definition_index": state["definition_index"],
                    "value_address": state["value_address"],
                },
                "guard_by_pass": {
                    "pass1": passes[0]["runtime_code_guard"],
                    "pass2": passes[1]["runtime_code_guard"],
                },
                "read_bytes_reserved_by_pass": {
                    "pass1": tech1["read_bytes_reserved"],
                    "pass2": tech2["read_bytes_reserved"],
                },
                "basis": BASIS,
            }
    else:
        # Preserve per-pass raw observations for diagnosis, but retract every
        # committed identity/value so callers cannot mistake a torn read as a
        # stable foreign-country fact.
        output["observer"]["bindings_by_pass"] = {
            f"pass{entry['pass']}": _binding_for(entry, observer_tag)
            for entry in passes
        }
        if admission_reader is not None:
            output["admission"]["provided"] = True
            output["admission"]["status"] = "unknown"
            output["admission"]["reason"] = "TWO_PASS_NOT_STABLE"
            output["admission"]["by_target"] = {
                tag: {
                    f"pass{entry['pass']}": entry.get("admission_by_tag", {}).get(tag)
                    for entry in passes
                }
                for tag in target_tags
            }
        for item in output["targets"]:
            item["bindings_by_pass"] = {
                f"pass{entry['pass']}": _binding_for(entry, item["tag"])
                for entry in passes
            }
            item["admission_by_pass"] = {
                f"pass{entry['pass']}": entry.get("admission_by_tag", {}).get(item["tag"])
                for entry in passes
            }
        if len(passes) == 2:
            mismatches = output["consistency"]["mismatch_paths"]
            output["errors"].append({
                "code": "outputs_retracted",
                "path": "targets.*.technology",
                "detail": {"mismatch_paths": mismatches},
            })
        for item in output["targets"]:
            item["pass_evidence"] = {
                f"pass{entry['pass']}": entry.get("technology_by_tag", {}).get(item["tag"])
                for entry in passes
            }
            target_errors = [
                error for error in output["errors"]
                if error.get("code") == "technology_read_failed"
                and item["tag"] in error.get("path", "")
            ]
            item["technology"]["reason"] = (
                target_errors[0].get("detail") if target_errors
                else "TWO_PASS_MISMATCH" if len(passes) == 2
                else "INCOMPLETE_TWO_PASS_READ"
            )
        output["status"] = "unknown"
    output["budget"] = {
        **output["budget"],
        "bytes_requested": limiter.bytes_requested,
        "bytes_returned": limiter.bytes_returned,
        "calls": limiter.calls,
        "max_single_read": limiter.max_single_read,
        "rejected_bytes": limiter.rejected_bytes,
    }
    return output
