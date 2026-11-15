"""Query a completed persistent Ghidra project through REA's public CLI."""
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time
import uuid
import psutil


from .catalog import project_root
from .ghidra_cache import (CacheError, _CacheLock, _complete_evidence, _hash_file,
                           _load_config, _read_json, _resolve_target, _target_from_cache, _write_json)
from .rea import _capture_logs, _owned_children, _stop_process

PRESET = "eu4-persistent-default-analysis-v1"
JAVA_HEAP_CHOICES = ("256M", "384M", "512M")
DEFAULT_JAVA_HEAP = "512M"
SUPPORTED_OPERATIONS = ("function", "search_strings", "xrefs")
FUNCTION_OUTPUT_FILTER_PATHS = (
    "error",
    "code",
    "category",
    "message",
    "retryable",
    "remediation",
    "details",
    "evidence_id",
    "subject",
    "provider",
    "analysis_profile",
    "predicate_type",
    "operation",
    "parameters",
    "confidence",
    "authority",
    "environment",
    "limitations",
    "locations",
    "evidence_links",
    "raw_result.limitations",
    "raw_result.value.procedure",
    "raw_result.value.pseudocode",
    "raw_result.value.assembly",
    "raw_result.value.comments",
    "raw_result.value.callers",
    "raw_result.value.callees",
    "raw_result.value.incoming_references",
    "raw_result.value.outgoing_references",
    "raw_result.value.referenced_strings",
    "raw_result.value.referenced_names",
    "raw_result.value.basic_blocks",
    "raw_result.value.native_api",
    "raw_result.value.limitations",
)
FUNCTION_OUTPUT_FILTER_ARGUMENT = ",".join(FUNCTION_OUTPUT_FILTER_PATHS)
FUNCTION_OUTPUT_FILTER_OMITTED_PATHS = (
    "normalized_result",
    "raw_result.value.native_value_flow",
    "raw_result.value.flow",
    "raw_result.value.pcode",
    "raw_result.value.high_pcode",
)
_CANONICAL_ADDRESS = re.compile(
    r"^(?:0x[0-9a-f]+|(?:[A-Za-z0-9._~-]|%[0-9A-F]{2})+:0x[0-9a-f]+)$"
)
_INPUT_ADDRESS = re.compile(
    r"^(?:(?:0[xX])?[0-9a-fA-F]+|(?:[A-Za-z0-9._~-]|%[0-9A-F]{2})+:0[xX][0-9a-fA-F]+)$"
)


def _validated_java_heap(args) -> str:
    """Validate older Namespace callers before touching the target or cache."""
    value = getattr(args, "java_heap", DEFAULT_JAVA_HEAP)
    if not isinstance(value, str) or value not in JAVA_HEAP_CHOICES:
        raise CacheError("Java heap must be one of 256M, 384M, or 512M")
    return value


def _validated_operation(args) -> str:
    """Read the optional operation without changing old Namespace callers."""
    value = getattr(args, "operation", "function")
    if value is None:
        value = "function"
    if not isinstance(value, str) or value not in SUPPORTED_OPERATIONS:
        raise CacheError("Operation must be one of function, search_strings, or xrefs")
    return value


def _validated_filtered_function_output(args, operation: str) -> bool:
    """Allow bounded function-output filtering only for function requests."""
    value = getattr(args, "filtered_function_output", False)
    if not isinstance(value, bool):
        raise CacheError("filtered_function_output must be boolean")
    if value and operation != "function":
        raise CacheError("filtered_function_output is only available for function queries")
    return value


def _operation_parameters(args, operation: str) -> dict:
    """Validate the exact public REA CLI inputs for the inventory operations."""
    if operation == "search_strings":
        pattern = getattr(args, "pattern", None)
        if not isinstance(pattern, str) or not pattern:
            raise CacheError("search_strings requires a non-empty pattern")
        mode = getattr(args, "mode", "literal")
        if mode not in {"literal", "regex"}:
            raise CacheError("search_strings mode must be literal or regex")
        case_sensitive = getattr(args, "case_sensitive", False)
        if not isinstance(case_sensitive, bool):
            raise CacheError("search_strings case_sensitive must be boolean")
        return {"pattern": pattern, "mode": mode, "case_sensitive": case_sensitive}
    if operation == "xrefs":
        address = getattr(args, "address", None)
        if not isinstance(address, str) or _INPUT_ADDRESS.fullmatch(address) is None:
            raise CacheError("xrefs requires a hexadecimal analysis address")
        return {"address": address}
    return {}


def _read_query_evidence(path: Path) -> tuple[dict | None, dict]:
    """Read the provider result without weakening the shared JSON bound.

    A postread failure is part of the query receipt.  It must not erase the
    provider's already-observed exit code or the process cleanup evidence.
    """

    try:
        evidence = _read_json(path)
    except CacheError as exc:
        message = str(exc)
        guard = "拒绝读取超过" in message
        return None, {
            "status": "guard_rejected" if guard else "error",
            "reason": "postread_guard_rejected" if guard else "postread_error",
            "exit_code": 1,
            "error": message,
        }
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError, RecursionError) as exc:
        return None, {
            "status": "error",
            "reason": "postread_error",
            "exit_code": 1,
            "error": str(exc),
        }
    if not isinstance(evidence, dict):
        return None, {
            "status": "validation_error",
            "reason": "postread_validation_error",
            "exit_code": 1,
            "error": "provider evidence must be a JSON object",
        }
    return evidence, {
        "status": "read",
        "reason": None,
        "exit_code": 0,
        "error": None,
    }


def _validate_cached_result(evidence: dict, request: dict, digest: str,
                            manifest_sha: str, database_sha: str,
                            metadata: dict) -> bool:
    profile = evidence.get("analysis_profile", {}).get("parameters", {})
    result = evidence.get("raw_result", {}).get("value", {})
    valid = (
        profile.get("analyzer_preset") == PRESET
        and profile.get("local_adapter_sha256") == request["adapter_sha256"]
        and profile.get("completed_manifest_sha256") == manifest_sha
        and profile.get("completed_database_sha256") == database_sha
    )
    valid = valid and evidence.get("subject", {}).get("digest", {}).get("sha256") == digest
    valid = valid and evidence.get("provider", {}).get("version") == metadata["ghidra_version"]
    return bool(
        valid
        and result.get("assembly")
        and result.get("pseudocode")
        and result.get("procedure", {}).get("body", {}).get("contains_entry")
    )


def _is_canonical_address(value) -> bool:
    return isinstance(value, str) and _CANONICAL_ADDRESS.fullmatch(value) is not None


def _same_json_value(left, right) -> bool:
    """Compare decoded JSON values without Python's bool/int equivalence."""
    try:
        return json.dumps(left, sort_keys=True, separators=(",", ":"), ensure_ascii=False) == json.dumps(
            right, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        )
    except (TypeError, ValueError):
        return False


def _validate_inventory_result(evidence: dict, request: dict, digest: str,
                               manifest_sha: str, database_sha: str,
                               metadata: dict, operation: str) -> bool:
    """Validate the bounded result contracts for search_strings and xrefs."""
    expected_parameters = request.get("parameters")
    if (
        request.get("operation") != operation
        or not isinstance(expected_parameters, dict)
        or evidence.get("operation") != operation
        or not isinstance(evidence.get("parameters"), dict)
        or not _same_json_value(evidence["parameters"], expected_parameters)
    ):
        return False
    profile = evidence.get("analysis_profile", {}).get("parameters", {})
    valid = (
        profile.get("analyzer_preset") == PRESET
        and profile.get("local_adapter_sha256") == request["adapter_sha256"]
        and profile.get("completed_manifest_sha256") == manifest_sha
        and profile.get("completed_database_sha256") == database_sha
        and evidence.get("subject", {}).get("digest", {}).get("sha256") == digest
        and evidence.get("provider", {}).get("version") == metadata["ghidra_version"]
    )
    if not valid:
        return False
    # The public CLI emits inventory results as a direct list under
    # ``raw_result``.  Older retained records wrapped the same list as
    # ``raw_result.value``.  Accept exactly these two shapes; all identity,
    # profile, parameter, and address checks above remain mandatory.
    raw_result = evidence.get("raw_result")
    if isinstance(raw_result, list):
        result = raw_result
    elif isinstance(raw_result, dict):
        result = raw_result.get("value")
    else:
        result = None
    if not isinstance(result, list):
        return False
    if operation == "xrefs":
        return all(_is_canonical_address(address) for address in result)
    if operation == "search_strings":
        return all(
            isinstance(item, dict)
            and set(item) == {"address", "value"}
            and _is_canonical_address(item["address"])
            and isinstance(item["value"], str)
            for item in result
        )
    return False


def _validate_cached_result_for_operation(evidence: dict, request: dict, digest: str,
                                          manifest_sha: str, database_sha: str,
                                          metadata: dict) -> bool:
    operation = request.get("operation", "function")
    if operation == "function":
        return _validate_cached_result(evidence, request, digest, manifest_sha, database_sha, metadata)
    return _validate_inventory_result(
        evidence, request, digest, manifest_sha, database_sha, metadata, operation
    )


def _finalize_query_receipt(*, output: Path, request: dict,
                            evidence_path: Path, cache: Path, digest: str,
                            manifest_sha: str, database_sha: str,
                            metadata: dict, started: float,
                            provider_exit_code: int | None,
                            supervisor_reason: str,
                            peaks: dict, cleanup_errors: list[str] | None = None,
                            process_wait_error: str | None = None) -> tuple[dict, int]:
    """Persist a query receipt even when provider readback is bounded away.

    ``provider_exit_code`` is the original child return code.  ``exit_code``
    and ``wrapper_exit_code`` are the final CLI result after postread,
    database, and cleanup checks.  A database result is true only after an
    actual post-query commitment comparison; checking failures remain null.
    """

    cleanup_errors = list(cleanup_errors or [])
    evidence, postread = _read_query_evidence(evidence_path)
    if provider_exit_code == 0:
        if postread["status"] in {"guard_rejected", "error"}:
            final_exit_code = 1
            reason = postread["reason"]
        elif postread["status"] == "validation_error":
            final_exit_code = 1
            reason = "postread_validation_error"
        else:
            try:
                valid_readback = _validate_cached_result_for_operation(
                    evidence, request, digest, manifest_sha, database_sha, metadata
                )
            except (AttributeError, KeyError, TypeError, ValueError):
                valid_readback = False
        if provider_exit_code == 0 and postread["status"] == "read" and not (
            postread["reason"] is None and valid_readback
        ):
            final_exit_code = 1
            reason = "postread_validation_error"
        elif provider_exit_code == 0 and postread["status"] == "read":
            final_exit_code = 0 if supervisor_reason == "completed" else 1
            reason = supervisor_reason
    else:
        final_exit_code = provider_exit_code if provider_exit_code is not None else 1
        reason = supervisor_reason
        if reason == "completed":
            reason = "provider_failed" if provider_exit_code is not None else "provider_wait_error"
        if postread["status"] == "read":
            postread = {**postread, "status": "read_not_validated_provider_failed"}

    database_check = {
        "expected_sha256": database_sha,
        "actual_sha256": None,
        "unchanged": None,
        "status": "not_checked",
        "error": None,
    }
    try:
        actual_database_sha = database_commitment(cache)
        database_check["actual_sha256"] = actual_database_sha
        database_check["unchanged"] = actual_database_sha == database_sha
        database_check["status"] = "matched" if database_check["unchanged"] else "changed"
        if not database_check["unchanged"]:
            final_exit_code, reason = 1, "read_only_database_changed"
    except (CacheError, OSError, ValueError) as exc:
        database_check["status"] = "error"
        database_check["error"] = str(exc)
        final_exit_code, reason = 1, "database_commitment_check_error"

    cleanup_status = "complete"
    running = [row for row in peaks.values()
               if row.get("still_running_same_process")]
    if running or cleanup_errors or process_wait_error:
        cleanup_status = "error"
        final_exit_code, reason = 1, "process_cleanup_incomplete"

    if final_exit_code == 0 and reason == "completed":
        status = "completed"
    elif reason == "postread_guard_rejected":
        status = "postread_guard_error"
    elif reason in {"postread_error", "postread_validation_error"}:
        status = "postread_error"
    else:
        status = "failed"
    cleanup = {
        "status": cleanup_status,
        "errors": cleanup_errors,
        "process_wait_error": process_wait_error,
        "closed_process_receipt": not running and not cleanup_errors and process_wait_error is None,
    }
    summary = {
        **request,
        "provider_exit_code": provider_exit_code,
        "supervisor_reason": supervisor_reason,
        "exit_code": final_exit_code,
        "wrapper_exit_code": final_exit_code,
        "status": status,
        "reason": reason,
        "elapsed_seconds": round(time.monotonic() - started, 2),
        "processes": list(peaks.values()),
        "cleanup": cleanup,
        "postread": postread,
        "postread_exit_code": postread["exit_code"],
        "database": database_check,
        "database_unchanged": database_check["unchanged"],
        "evidence_id": evidence.get("evidence_id") if evidence is not None else None,
    }
    _write_json(output / "run.json", summary)
    print(json.dumps({key: summary[key] for key in [
        "exit_code", "provider_exit_code", "reason", "elapsed_seconds", "evidence_id"
    ]}), flush=True)
    return summary, final_exit_code


def database_commitment(cache: Path) -> str:
    """Commit the project files in streaming chunks, excluding OS lock files."""
    project = (cache / "project").resolve(strict=True)
    files = sorted(path for path in project.rglob("*") if path.is_file()
                   and not path.name.endswith((".lock", ".lock~")))
    if not files or len(files) > 8192:
        raise CacheError("Unexpected/unbounded persistent database file inventory")
    digest = hashlib.sha256()
    for path in files:
        if not path.resolve(strict=True).is_relative_to(project):
            raise CacheError("Database file escapes the selected project")
        digest.update(path.relative_to(project).as_posix().encode("utf-8"))
        digest.update(b"\0" + _hash_file(path).encode("ascii") + b"\n")
    return digest.hexdigest()


def latest_cache() -> Path | None:
    pointer = project_root() / "work/runtime/ghidra-full/latest.json"
    if not pointer.is_file():
        return None
    value = _read_json(pointer, max_bytes=65536)
    cache = Path(value["cache"])
    if not cache.is_absolute():
        raise CacheError("Latest cache pointer must be absolute")
    if _hash_file(cache / "build.json") != value["build_manifest_sha256"]:
        raise CacheError("Latest cache manifest changed; explicitly select and verify the cache")
    return cache


def publish_cache(cache: Path) -> None:
    metadata = _read_json(cache / "build.json")
    if metadata.get("status") != "complete" or not _complete_evidence(cache, metadata):
        raise CacheError("Refuse to publish an incomplete analysis cache")
    pointer = project_root() / "work/runtime/ghidra-full/latest.json"
    pointer.parent.mkdir(parents=True, exist_ok=True)
    _write_json(pointer, {"cache": str(cache.resolve()), "target_sha256": metadata["target_sha256"],
                          "build_manifest_sha256": _hash_file(cache / "build.json")})


def query(args) -> int:
    operation = _validated_operation(args)
    parameters = _operation_parameters(args, operation)
    filtered_function_output = _validated_filtered_function_output(args, operation)
    java_heap = _validated_java_heap(args)
    target, registry, digest = _resolve_target(args.binary)
    cache = (args.cache or latest_cache()).resolve(strict=True)
    with _CacheLock(cache):
        _, _, cached_digest, metadata = _target_from_cache(cache)
        if cached_digest != digest or metadata.get("status") != "complete" or not _complete_evidence(cache, metadata):
            raise CacheError("缓存与目标不匹配，或默认自动分析尚未完整保存")
        if metadata["ghidra_version"] != "12.1.4":
            raise CacheError("缓存查询适配器仅验证了 Ghidra 12.1.4")
        database_sha = database_commitment(cache)
        manifest_sha = _hash_file(cache / "build.json")
        if operation == "function":
            image_base = int(str(registry["binary"]["image_base"]), 0)
            selected = next((node for node in registry["nodes"] if node["id"] == args.node), None)
            if selected is not None:
                if selected.get("address_role") != "procedure_entry":
                    raise CacheError("所选节点不是函数入口")
                procedure = f"{image_base + int(str(selected['rva']), 0):#x}"
            elif args.node.startswith("0x"):
                address = int(args.node, 16)
                procedure = f"{address if address >= image_base else image_base + address:#x}"
            else:
                # REA resolves exact analyzed names. Names are passed as argv, never shell text.
                procedure = args.node
            parameters = None
        else:
            procedure = None
        config = _load_config(args.config)
        cli = config["args"]
        if Path(config["command"]).name.lower() not in {"node", "node.exe"} or cli[-1] != "mcp":
            raise CacheError("缓存入口需要直接 Node + public scripts/rea.mjs 注册")
        entry = Path(cli[0]).resolve(strict=True)
        package = entry.parent.parent
        if _read_json(package / "package.json")["version"] != "6.4.0":
            raise CacheError("缓存入口只验证了 REA 6.4.0")
        loader = Path(__file__).with_name("rea_cache_loader.mjs").resolve(strict=True)
        environment = os.environ.copy()
        environment.update(config.get("env", {}))
        environment.pop("REA_GHIDRA_SEED_FILE", None)
        environment.update({"EU4_REA_PACKAGE_ROOT": str(package), "EU4_REA_CACHE_PROJECT": str(cache / "project"),
                            "EU4_REA_CACHE_MANIFEST": str(cache / "build.json"),
                            "EU4_REA_CACHE_DATABASE_SHA256": database_sha,
                            "REA_GHIDRA_STARTUP_TIMEOUT_MS": str(args.timeout * 1000),
                            "GHIDRA_HEADLESS_MAXMEM": java_heap})
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        output = (args.output or project_root() / "work/runtime" / f"rea-cache-{stamp}-{uuid.uuid4().hex[:8]}").resolve()
        if output.is_relative_to(cache / "project"):
            raise CacheError("查询输出不能写入分析工程内部")
        output.mkdir(parents=True, exist_ok=False)
        command = [config["command"], "--import", loader.as_uri(), *cli[:-1]]
        if operation == "function":
            command.extend(["function", str(target), procedure])
            request = {"target_sha256": digest, "node": args.node, "procedure": procedure, "cache": str(cache)}
            print_target = procedure
        elif operation == "search_strings":
            command.extend(["search", str(target), f"--pattern={parameters['pattern']}",
                             "--kind", "strings", "--mode", parameters["mode"]])
            if parameters["case_sensitive"]:
                command.append("--case-sensitive")
            request = {"target_sha256": digest, "operation": operation, "parameters": parameters,
                       "cache": str(cache)}
            print_target = parameters["pattern"]
        else:
            command.extend(["xrefs", str(target), f"--address={parameters['address']}"])
            request = {"target_sha256": digest, "operation": operation, "parameters": parameters,
                       "cache": str(cache)}
            print_target = parameters["address"]
        command.extend(["--provider", "ghidra", "--format", "json"])
        if filtered_function_output:
            command.extend(["--filter-output", FUNCTION_OUTPUT_FILTER_ARGUMENT])
            request["filtered_function_output"] = True
            request["function_output_filter"] = {
                "paths": list(FUNCTION_OUTPUT_FILTER_PATHS),
                "omitted_high_volume_paths": list(FUNCTION_OUTPUT_FILTER_OMITTED_PATHS),
                "high_pcode_retained": False,
            }
        request.update({"preset": PRESET, "adapter_sha256": _hash_file(loader),
                        "completed_manifest_sha256": manifest_sha,
                        "completed_database_sha256": database_sha, "query_reanalysis": False,
                        "java_heap": java_heap, "process_memory_limit_bytes": 1024**3,
                        "timeout_seconds": args.timeout})
        _write_json(output / "request.json", request)
        print(f"REA 持久化库查询：{print_target}；输出 {output}", flush=True)
        peaks = {}
        cleanup_errors = []
        process_wait_error = None

        def stop_safely(candidate) -> None:
            try:
                _stop_process(candidate, psutil)
            except (psutil.Error, OSError, ValueError) as exc:
                cleanup_errors.append(f"{type(exc).__name__}: {exc}")

        started = time.monotonic()
        reason = "completed"
        with (output / "evidence.json").open("xb") as stdout, (output / "stderr.log").open("xb") as stderr:
            process = psutil.Popen(command, env=environment, stdout=stdout, stderr=stderr)
            last_report = 0
            try:
                while process.poll() is None:
                    for child in _owned_children(process, psutil):
                        try:
                            arguments = " ".join(child.cmdline()).lower()
                            if child.name().lower() not in {"java.exe", "javaw.exe"} or "ghidra" not in arguments or "analyzeheadless" not in arguments:
                                continue
                            private = getattr(child.memory_info(), "private", child.memory_info().vms)
                            row = peaks.setdefault(child.pid, {"pid": child.pid, "create_time": child.create_time(), "peak_committed_bytes": 0})
                            row["peak_committed_bytes"] = max(row["peak_committed_bytes"], private)
                            _capture_logs(child, output)
                            if private > 1024**3:
                                reason = "memory_limit"
                                stop_safely(child)
                        except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
                            continue
                    elapsed = time.monotonic() - started
                    if elapsed - last_report >= 30:
                        print(f"缓存查询等待 {elapsed:.0f}s", flush=True)
                        last_report = elapsed
                    if elapsed > args.timeout + 35:
                        reason = "supervisor_deadline"
                        break
                    time.sleep(1)
            finally:
                if process.poll() is None:
                    for child in reversed(_owned_children(process, psutil)):
                        stop_safely(child)
                    stop_safely(process)
            try:
                provider_exit_code = process.wait(timeout=15)
            except (psutil.TimeoutExpired, psutil.Error, OSError, ValueError) as exc:
                process_wait_error = f"{type(exc).__name__}: {exc}"
                provider_exit_code = process.poll()
        for row in peaks.values():
            try:
                remaining = psutil.Process(row["pid"])
                if remaining.create_time() == row["create_time"]:
                    arguments = " ".join(remaining.cmdline()).lower()
                    if "ghidra" in arguments and "analyzeheadless" in arguments:
                        stop_safely(remaining)
                row["still_running_same_process"] = remaining.is_running() and remaining.create_time() == row["create_time"]
            except psutil.NoSuchProcess:
                row["still_running_same_process"] = False
            except (psutil.Error, OSError, ValueError) as exc:
                row["still_running_same_process"] = None
                row["cleanup_error"] = f"{type(exc).__name__}: {exc}"
                cleanup_errors.append(row["cleanup_error"])
        _summary, final_exit_code = _finalize_query_receipt(
            output=output,
            request=request,
            evidence_path=output / "evidence.json",
            cache=cache,
            digest=digest,
            manifest_sha=manifest_sha,
            database_sha=database_sha,
            metadata=metadata,
            started=started,
            provider_exit_code=provider_exit_code,
            supervisor_reason=reason,
            peaks=peaks,
            cleanup_errors=cleanup_errors,
            process_wait_error=process_wait_error,
        )
        return final_exit_code
