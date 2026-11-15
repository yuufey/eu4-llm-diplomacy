"""Archive batch 70 rivals evidence after source, regression, and live gates.

Default invocation is inert. The batch 69 final-readback is the authority for
its 991 artifact pins, two immutable database snapshots, and 284 predecessor
pins; this helper does not re-evaluate batch 69 source files.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / "work/runtime/information-diplomacy-state-20261028-001"
DEFAULT_SPEC = STAGE / "publication-spec-001.json"
PREVIOUS_STAGE = ROOT / "work/runtime/information-country-force-resources-20261027-001"
PREVIOUS_FINAL_READBACK = PREVIOUS_STAGE / "final-readback-001.json"
PREVIOUS_ARCHIVE_ROOT = STAGE / "archive-inherited-batch69"
PREVIOUS_READBACK_COPY = PREVIOUS_ARCHIVE_ROOT / "final-readback-001.json"
PREVIOUS_ARCHIVE_COPY = PREVIOUS_ARCHIVE_ROOT / "archive-verification-001.json"
PREVIOUS_DB_COPY_ROOT = STAGE / "archive-inherited-batch69/databases"
CHUNK_BYTES = 1024 * 1024
MAX_JSON_BYTES = 16 * 1024 * 1024
BATCH = 70
OUTPUTS = (
    STAGE / "archive-verification-001.json",
    STAGE / "archive-self-readback-001.json",
)


class ArchiveError(RuntimeError):
    pass


def _full_suite_summary(path: Path) -> str:
    candidate = None
    with path.open("r", encoding="utf-8-sig", errors="replace") as stream:
        for line in stream:
            if "passed" in line and "failed" in line and " in " in line:
                candidate = line.strip("= \r\n")
    if not candidate:
        raise ArchiveError("full_log_summary_missing")
    return candidate


def _root_path(value: str | Path) -> Path:
    path = Path(value)
    if not path.is_absolute():
        path = ROOT / path
    resolved = path.resolve()
    try:
        resolved.relative_to(ROOT.resolve())
    except ValueError as exc:
        raise ArchiveError(f"path_outside_workspace:{value}") from exc
    return resolved


def _pin(path: Path) -> dict[str, Any]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        while chunk := stream.read(CHUNK_BYTES):
            size += len(chunk)
            digest.update(chunk)
    return {"path": path.resolve().relative_to(ROOT.resolve()).as_posix(),
            "bytes": size, "sha256": digest.hexdigest()}


def _read_json(path: Path) -> Any:
    if not path.is_file():
        raise ArchiveError(f"missing_json:{path}")
    if path.stat().st_size > MAX_JSON_BYTES:
        raise ArchiveError(f"json_over_bound:{path}:{path.stat().st_size}")
    try:
        with path.open("r", encoding="utf-8-sig") as stream:
            return json.load(stream)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ArchiveError(f"invalid_json:{path}:{type(exc).__name__}") from exc


def _write_new(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("x", encoding="utf-8", newline="\n") as stream:
            json.dump(value, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
    except FileExistsError as exc:
        raise ArchiveError(f"output_exists:{path}") from exc


def _pointer(value: Any, pointer: str) -> Any:
    if pointer in ("", "/"):
        return value
    if not isinstance(pointer, str) or not pointer.startswith("/"):
        raise ArchiveError(f"invalid_json_pointer:{pointer!r}")
    current = value
    for part in pointer[1:].split("/"):
        part = part.replace("~1", "/").replace("~0", "~")
        if isinstance(current, dict) and part in current:
            current = current[part]
        elif isinstance(current, list) and part.isdecimal() and int(part) < len(current):
            current = current[int(part)]
        else:
            raise ArchiveError(f"json_pointer_missing:{pointer}")
    return current


def _spec_pointer(value: Any, pointer: str) -> Any:
    return _pointer(value, pointer)


def _copy_new(source: Path, destination: Path, expected: dict[str, Any]) -> dict[str, Any]:
    if not source.is_file() or _pin(source)["sha256"] != expected.get("sha256"):
        raise ArchiveError(f"predecessor_source_pin_mismatch:{source}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    try:
        with source.open("rb") as src, destination.open("xb") as dst:
            while chunk := src.read(CHUNK_BYTES):
                dst.write(chunk)
    except FileExistsError as exc:
        raise ArchiveError(f"snapshot_exists:{destination}") from exc
    copied = _pin(destination)
    if copied["bytes"] != expected.get("bytes") or copied["sha256"] != expected.get("sha256"):
        raise ArchiveError(f"predecessor_copy_mismatch:{source}")
    return copied


def _load_spec(path: Path, helper_review: Path | None = None):
    spec = _read_json(path)
    if spec.get("schema") != "information.country_rivals.publication_spec.v1":
        raise ArchiveError("invalid_publication_spec_schema")
    if spec.get("stage") != STAGE.relative_to(ROOT).as_posix() or path.parent.resolve() != STAGE.resolve():
        raise ArchiveError("publication_spec_stage_mismatch")
    inputs = spec.get("inputs")
    required = {"installation", "source_audit", "source_freeze",
                "source_postverify", "regression_comparison", "full_log", "live",
                "database_snapshot_verification"}
    if not isinstance(inputs, dict) or not required.issubset(inputs):
        raise ArchiveError("publication_spec_inputs_incomplete")
    paths, records, pins = {}, {}, {}
    for key, item in inputs.items():
        if (not isinstance(item, dict) or not isinstance(item.get("path"), str)
                or not re.fullmatch(r"[0-9a-f]{64}", str(item.get("sha256", "")))):
            raise ArchiveError(f"invalid_input_pin:{key}")
        source = _root_path(item["path"])
        if not source.is_file():
            raise ArchiveError(f"missing_input:{key}")
        actual = _pin(source)
        if actual["sha256"] != item["sha256"] or (
                "bytes" in item and actual["bytes"] != item["bytes"]):
            raise ArchiveError(f"input_pin_mismatch:{key}")
        paths[key], pins[key] = source, actual
        if item.get("format", "json") == "json":
            records[key] = _read_json(source)
    _validate_qualification(spec, records, pins, path, helper_review)
    return spec, paths, records, pins


def _validate_qualification(spec: dict[str, Any], records: dict[str, Any],
                            pins: dict[str, dict[str, Any]], spec_path: Path,
                            helper_review: Path | None = None) -> None:
    freeze, post = records["source_freeze"], records["source_postverify"]
    comparison, live = records["regression_comparison"], records["live"]
    if (freeze.get("status") != "passed" or freeze.get("batch") != BATCH
            or freeze.get("count") != 184 or len(freeze.get("files", [])) != 184):
        raise ArchiveError("source_freeze_not_184_passed")
    if (post.get("status") != "passed" or post.get("batch") != BATCH
            or post.get("count") != 184 or post.get("current_matches_snapshots") is not True):
        raise ArchiveError("source_postverify_failed")
    freeze_pin = spec["inputs"]["source_freeze"]
    post_freeze = post.get("freeze")
    if (not isinstance(post_freeze, dict)
            or post_freeze.get("sha256") != freeze_pin.get("sha256")
            or post_freeze.get("path") != str(freeze_pin["path"]).replace("\\", "/")):
        raise ArchiveError("postverify_freeze_pin_mismatch")
    if comparison.get("no_new_bad") is not True or comparison.get("baseline_batch") != 69:
        raise ArchiveError("comparison_not_clean_against_batch69")
    for name in ("new_failure_nodes", "new_test_failures"):
        if name in comparison and comparison[name] != []:
            raise ArchiveError(f"comparison_has_new_failures:{name}")
    if live.get("status") != "passed" or live.get("server_exit_code") != 0:
        raise ArchiveError("live_acceptance_not_passed")
    checks = live.get("checks")
    if not isinstance(checks, dict) or not checks or any(value is not True for value in checks.values()):
        raise ArchiveError("live_acceptance_checks_not_all_true")
    identity = spec.get("identity")
    installation = records["installation"]
    if not isinstance(identity, dict) or not isinstance(installation, dict):
        raise ArchiveError("identity_missing")
    installation_pointers = spec.get("identity_installation_pointers", {})
    live_pointers = spec.get("identity_live_pointers", {})
    for key in ("pid", "creation_filetime", "session_id", "game_sha256", "dll_sha256"):
        expected = identity.get(key)
        install_value = _spec_pointer(installation, installation_pointers.get(key, "/" + key))
        live_value = _spec_pointer(live, live_pointers.get(key, "/identity/" + key))
        if expected is None or expected != install_value or expected != live_value:
            raise ArchiveError(f"installation_live_spec_identity_mismatch:{key}")
    if identity.get("installation_sha256") != pins["installation"]["sha256"]:
        raise ArchiveError("installation_sha256_mismatch")
    live_installation_path_pointer = spec.get("live_installation_path_pointer")
    if live_installation_path_pointer:
        live_installation_path = _root_path(_spec_pointer(live, live_installation_path_pointer))
        if live_installation_path != _root_path(spec["inputs"]["installation"]["path"]):
            raise ArchiveError("live_installation_path_mismatch")
    elif _spec_pointer(live, spec.get("live_installation_sha_pointer",
                                     "/identity/installation_sha256")) != pins["installation"]["sha256"]:
        raise ArchiveError("live_installation_sha256_mismatch")
    if identity.get("date_raw") is not None:
        date = _pointer(live, spec.get("identity_date_pointer", "/before_control/date_raw"))
        if date != identity["date_raw"]:
            raise ArchiveError("live_date_identity_mismatch")
    if identity.get("game_version") is not None:
        version = _pointer(live, spec.get("identity_version_pointer", "/build_manifest/version"))
        if version != identity["game_version"]:
            raise ArchiveError("live_version_identity_mismatch")
    if records["source_audit"].get("status") != "passed":
        raise ArchiveError("source_audit_not_passed")
    if spec.get("publication", {}).get("nonempty_live_reader_accepted") is not False:
        raise ArchiveError("nonempty_live_reader_must_remain_unaccepted")
    if records["source_audit"].get("status") != "passed":
        raise ArchiveError("source_audit_not_passed")
    helper_paths = {"work/finalize_information_country_rivals.py",
                    "work/archive_information_country_rivals.py"}
    frozen_paths = {str(item.get("source", {}).get("path", "")).replace("\\", "/")
                    for item in freeze.get("files", []) if isinstance(item, dict)}
    if frozen_paths.intersection(helper_paths):
        raise ArchiveError("publication_helper_in_runtime_freeze")
    _verify_frozen_members(freeze)
    summary_path = STAGE / "development-summary-001.json"
    coverage_update_path = STAGE / "coverage-update-001.json"
    if not summary_path.is_file() or not coverage_update_path.is_file():
        raise ArchiveError("finalizer_outputs_missing")
    summary, update = _read_json(summary_path), _read_json(coverage_update_path)
    if summary.get("status") != "passed" or summary.get("batch") != BATCH:
        raise ArchiveError("development_summary_not_passed")
    if summary.get("publication_spec") != _pin(spec_path):
        raise ArchiveError("publication_spec_changed_after_finalization")
    if summary.get("qualification") != {name: pins[name] for name in
            ("installation", "source_audit", "source_freeze", "source_postverify",
             "regression_comparison", "full_log", "live",
             "database_snapshot_verification")}:
        raise ArchiveError("summary_qualification_pin_mismatch")
    if summary.get("publication_spec") != _pin(spec_path):
        raise ArchiveError("publication_spec_changed_after_finalization")
    if summary.get("identity") != identity or summary.get("nonempty_live_reader_accepted") is not False:
        raise ArchiveError("summary_identity_or_scope_mismatch")
    context_roles = spec.get("publication", {}).get("context_input_roles", [])
    expected_context = {name: pins[name] for name in context_roles}
    if summary.get("context_only_evidence") != expected_context:
        raise ArchiveError("summary_context_receipt_pins_mismatch")
    if summary.get("scope", {}).get("b04_promoted") is not False:
        raise ArchiveError("summary_promoted_adjacent_B04")
    observed = _spec_pointer(live, spec["publication"]["live_value_pointer"])
    if observed != [] or summary.get("observed_rivals") != observed:
        raise ArchiveError("live_rivals_observation_scope_mismatch")
    if summary.get("full_suite") != _full_suite_summary(
            _root_path(spec["inputs"]["full_log"]["path"])):
        raise ArchiveError("summary_full_suite_mismatch")
    if (update.get("status") != "passed" or update.get("batch") != BATCH
            or update.get("counts") != {"available": 62, "partial": 164, "planned": 171}):
        raise ArchiveError("coverage_update_not_qualified")
    coverage_path = _root_path(spec["publication"].get("coverage_path", "docs/信息字段覆盖.json"))
    if not coverage_path.is_file() or _pin(coverage_path) != update.get("after"):
        raise ArchiveError("published_coverage_pin_mismatch")
    database_snapshots = _validate_database_snapshots(records["database_snapshot_verification"])
    if summary.get("database_snapshots") != database_snapshots:
        raise ArchiveError("summary_database_snapshot_pin_mismatch")
    if summary.get("database_snapshot_verification") != pins["database_snapshot_verification"]:
        raise ArchiveError("summary_database_snapshot_receipt_mismatch")
    _verify_helper_review(spec, helper_review)


def _verify_frozen_members(freeze: dict[str, Any]) -> None:
    files = freeze["files"]
    for index, item in enumerate(files):
        source_ref, snapshot_ref = item.get("source"), item.get("snapshot")
        if not isinstance(source_ref, dict) or not isinstance(snapshot_ref, dict):
            raise ArchiveError(f"freeze_member_shape_invalid:{index}")
        source, snapshot = _root_path(source_ref["path"]), _root_path(snapshot_ref["path"])
        if not source.is_file() or not snapshot.is_file():
            raise ArchiveError(f"freeze_member_missing:{index}")
        if _pin(source) != source_ref or _pin(snapshot) != snapshot_ref:
            raise ArchiveError(f"freeze_member_pin_mismatch:{index}")
        if (source_ref["bytes"], source_ref["sha256"]) != (snapshot_ref["bytes"], snapshot_ref["sha256"]):
            raise ArchiveError(f"freeze_source_snapshot_diverge:{index}")


def _validate_database_snapshots(receipt: dict[str, Any]) -> list[dict[str, Any]]:
    if (receipt.get("status") != "passed" or receipt.get("batch") != BATCH
            or receipt.get("all_snapshots_closed_immutable_ro_verified") is not True
            or receipt.get("source_wal_shm_deleted") is not False
            or receipt.get("source_databases_modified") is not False):
        raise ArchiveError("live_database_snapshot_receipt_failed")
    backups = receipt.get("backups")
    if not isinstance(backups, list) or len(backups) != 2:
        raise ArchiveError("live_database_snapshot_count_mismatch")
    if receipt.get("fresh_snapshot_count", 2) != 2:
        raise ArchiveError("live_database_snapshot_count_mismatch")
    names, result = set(), []
    expected_parent = STAGE / "final-database-snapshots" / "live-acceptance-001"
    for index, item in enumerate(backups):
        snapshot = item.get("snapshot") if isinstance(item, dict) else None
        if (not isinstance(snapshot, dict) or item.get("integrity") != "ok"
                or item.get("snapshot_verification") != "mode=ro&immutable=1"
                or item.get("contextlib_closing") is not True):
            raise ArchiveError(f"invalid_live_database_snapshot:{index}")
        snapshot_path = _root_path(snapshot.get("path", ""))
        if snapshot_path.parent != expected_parent or _pin(snapshot_path) != snapshot:
            raise ArchiveError(f"live_database_snapshot_pin_mismatch:{index}")
        source_path = _root_path(item.get("source_path", ""))
        source_pin = _pin(source_path)
        if (source_pin["bytes"] != item.get("source_bytes")
                or source_pin["sha256"] != item.get("source_sha256")):
            raise ArchiveError(f"live_database_source_pin_mismatch:{index}")
        names.add(snapshot_path.name)
        result.append(snapshot)
    if names != {"diplomacy.sqlite3", "information.sqlite3"}:
        raise ArchiveError("unexpected_live_database_snapshot_names")
    return result


def _inherited_batch69():
    readback = _read_json(PREVIOUS_FINAL_READBACK)
    if (readback.get("status") != "passed" or readback.get("batch") != 69
            or readback.get("artifact_count") != 991
            or readback.get("previous68_pins_checked") != 284
            or len(readback.get("databases", [])) != 2):
        raise ArchiveError("batch69_final_readback_not_authoritative")
    archive_ref = readback.get("archive")
    if not isinstance(archive_ref, dict):
        raise ArchiveError("batch69_archive_pin_missing")
    archive_path = _root_path(archive_ref["path"])
    if _pin(archive_path) != archive_ref:
        raise ArchiveError("batch69_archive_pin_changed")
    manifest = _read_json(archive_path)
    if (manifest.get("status") != "passed" or manifest.get("batch") != 69
            or manifest.get("artifact_count") != 991 or len(manifest.get("artifacts", [])) != 991
            or len(manifest.get("database_snapshots", [])) != 2
            or manifest.get("previous_batch68", {}).get("pins_checked") != 284):
        raise ArchiveError("batch69_archive_manifest_conflicts_with_final_readback")
    manifest_databases = [item.get("snapshot") for item in manifest["database_snapshots"]]
    readback_databases = [item.get("snapshot") for item in readback["databases"]]
    if sorted((item.get("bytes"), item.get("sha256")) for item in manifest_databases if isinstance(item, dict)) != sorted(
            (item.get("bytes"), item.get("sha256")) for item in readback_databases if isinstance(item, dict)):
        raise ArchiveError("batch69_database_manifest_final_readback_mismatch")
    database_sources = []
    for index, item in enumerate(readback["databases"]):
        snapshot = item.get("snapshot")
        if not isinstance(snapshot, dict):
            raise ArchiveError(f"batch69_database_pin_missing:{index}")
        original = _root_path(snapshot["path"])
        if _pin(original) != snapshot:
            raise ArchiveError(f"batch69_database_pin_changed:{index}")
        database_sources.append((original, snapshot, item))
    if PREVIOUS_ARCHIVE_ROOT.exists():
        raise ArchiveError("inherited_batch69_snapshot_already_started")
    readback_copy = _copy_new(PREVIOUS_FINAL_READBACK, PREVIOUS_READBACK_COPY,
                              _pin(PREVIOUS_FINAL_READBACK))
    archive_copy = _copy_new(archive_path, PREVIOUS_ARCHIVE_COPY, archive_ref)
    database_copies = []
    for index, (original, snapshot, item) in enumerate(database_sources):
        copied = _copy_new(original, PREVIOUS_DB_COPY_ROOT / original.name, snapshot)
        database_copies.append({"source": snapshot, "snapshot": copied,
                                "integrity": item.get("integrity"),
                                "active_subscriptions": item.get("active_subscriptions")})
    return {
        "authority": _pin(PREVIOUS_FINAL_READBACK),
        "final_readback_snapshot": readback_copy,
        "final_readback_status": readback["status"],
        "artifact_count": readback["artifact_count"],
        "archive": archive_ref,
        "archive_snapshot": archive_copy,
        "immutable_database_snapshots": database_copies,
        "predecessor_pin_count": readback["previous68_pins_checked"],
        "batch69_artifact_pins_revalidated_against_current_sources": False,
        "reason": "batch69 final-readback is the sealed authority; the full artifact manifest is retained by exact archive copy",
    }


def _verify_helper_review(spec: dict[str, Any], override: Path | None = None) -> dict[str, Any]:
    reference = spec.get("publication", {}).get("helper_review")
    if not isinstance(reference, dict) or not isinstance(reference.get("path"), str):
        raise ArchiveError("publication_helper_review_pin_missing")
    path = _root_path(reference["path"])
    actual_review_pin = _pin(path)
    if (actual_review_pin["sha256"] != reference.get("sha256")
            or ("bytes" in reference and actual_review_pin["bytes"] != reference["bytes"])):
        raise ArchiveError("publication_helper_review_pin_mismatch")
    if override is not None:
        override = _root_path(override)
        override.relative_to(STAGE.resolve())
        amended = _read_json(override)
        if amended.get("supersedes") != actual_review_pin:
            raise ArchiveError("helper_review_override_predecessor_mismatch")
        path = override
    review = _read_json(path)
    if review.get("status") != "passed" or review.get("runtime_freeze_included") is not False:
        raise ArchiveError("publication_helper_review_not_passed_or_in_freeze")
    helpers = review.get("helpers")
    if not isinstance(helpers, list) or len(helpers) != 2:
        raise ArchiveError("publication_helper_pins_missing")
    for item in helpers:
        source = _root_path(item["source"]["path"])
        snapshot = _root_path(item["snapshot"]["path"])
        if _pin(source) != item["source"] or _pin(snapshot) != item["snapshot"]:
            raise ArchiveError(f"publication_helper_snapshot_mismatch:{source.name}")
        if item["source"]["sha256"] != item["snapshot"]["sha256"]:
            raise ArchiveError(f"publication_helper_snapshot_diverged:{source.name}")
    return _pin(path)


def _is_working_database(path: Path) -> bool:
    relative = path.relative_to(STAGE)
    if "final-database-snapshots" in relative.parts:
        return False
    lower = path.name.lower()
    return (lower.endswith(("-wal", "-shm"))
            or path.suffix.lower() in {".sqlite", ".sqlite3", ".db"})


def _stage_artifacts() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    excluded = {path.name for path in OUTPUTS}
    files, databases = [], []
    for path in sorted(STAGE.rglob("*")):
        if not path.is_file() or path.name in excluded:
            continue
        if _is_working_database(path):
            databases.append({"path": path.relative_to(ROOT).as_posix(),
                              "bytes": path.stat().st_size,
                              "reason": "working SQLite/WAL/SHM excluded; source retained"})
            continue
        files.append(_pin(path))
    return files, databases


def archive(spec_path: Path, helper_review: Path | None = None) -> dict[str, Any]:
    spec, _, records, input_pins = _load_spec(spec_path, helper_review)
    for path in OUTPUTS:
        if path.exists():
            raise ArchiveError(f"archive_output_exists:{path}")
    if PREVIOUS_ARCHIVE_ROOT.exists():
        raise ArchiveError("inherited_batch69_snapshot_already_started")
    summary = _read_json(STAGE / "development-summary-001.json")
    coverage_update = _read_json(STAGE / "coverage-update-001.json")
    artifacts, database_exclusions = _stage_artifacts()
    inherited = _inherited_batch69()
    helper_review = _verify_helper_review(spec, helper_review)
    current_database_snapshots = _validate_database_snapshots(
        records["database_snapshot_verification"])

    manifest = {
        "schema": "information.country_rivals.archive.v1",
        "status": "passed", "batch": BATCH,
        "qualification": {name: input_pins[name] for name in (
            "installation", "source_audit", "source_freeze", "source_postverify",
            "regression_comparison", "full_log", "live",
            "database_snapshot_verification")},
        "database_snapshot_verification": input_pins["database_snapshot_verification"],
        "database_snapshots": current_database_snapshots,
        "summary": _pin(STAGE / "development-summary-001.json"),
        "coverage_update": _pin(STAGE / "coverage-update-001.json"),
        "source_count": 184,
        "baseline_comparison_batch": 69,
        "artifacts": artifacts,
        "artifact_count": len(artifacts),
        "excluded_working_databases": database_exclusions,
        "inherited_batch69": inherited,
        "publication_helpers": _pin(ROOT / "work/finalize_information_country_rivals.py"),
        "archive_helper": _pin(ROOT / "work/archive_information_country_rivals.py"),
        "publication_helper_review": helper_review,
        "original_publication_helper_review": spec["publication"]["helper_review"],
        "publication_helper_freeze_scope": "separate snapshot; not part of the 184-source runtime freeze",
        "preservation": {
            "all_stage_files_pinned_in_place": True,
            "static_fixture_and_failure_receipts_retained": True,
            "stage_files_moved_or_deleted": False,
            "batch69_sources_rehashed_against_current_files": False,
            "batch69_final_readback_used_as_authority": True,
            "game_or_mcp_or_native_or_rpm_or_tests_run": False,
        },
        "scope": {"goal_complete": False, "b04_promoted": False,
                  "nonempty_reader_live_accepted": False},
    }
    _write_new(OUTPUTS[0], manifest)
    for item in artifacts:
        if _pin(_root_path(item["path"])) != item:
            raise ArchiveError(f"artifact_readback_mismatch:{item['path']}")
    self_readback = {
        "schema": "information.country_rivals.archive_self_readback.v1",
        "status": "passed", "batch": BATCH,
        "archive": _pin(OUTPUTS[0]), "artifact_count": len(artifacts),
        "all_stage_artifact_pins_rechecked": True,
        "batch69_authority": inherited["authority"],
        "batch69_copy_hashes_inherited": True,
    }
    _write_new(OUTPUTS[1], self_readback)
    return {"status": "passed", "batch": BATCH,
            "artifact_count": len(artifacts),
            "batch69_artifact_count": inherited["artifact_count"],
            "batch69_database_snapshots": len(inherited["immutable_database_snapshots"]),
            "predecessor_pins": inherited["predecessor_pin_count"],
            "archive": _pin(OUTPUTS[0]), "self_readback": _pin(OUTPUTS[1])}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec", type=Path, default=DEFAULT_SPEC,
                        help="normalized publication spec with current receipts and identity")
    parser.add_argument("--run", action="store_true",
                        help="create the exclusive offline archive after all gates pass")
    parser.add_argument("--helper-review", type=Path,
                        help="archive-only superseding review; preserves the published spec and summary")
    args = parser.parse_args()
    if not args.run:
        print(json.dumps({
            "status": "inert", "batch": BATCH, "spec": args.spec.as_posix(),
            "required_source_count": 184, "required_baseline_comparison": 69,
            "batch69_authority": PREVIOUS_FINAL_READBACK.relative_to(ROOT).as_posix(),
            "batch69_expected_artifacts": 991, "batch69_expected_databases": 2,
            "batch68_predecessor_pins": 284, "archive": False,
        }, ensure_ascii=False))
        return 0
    try:
        result = archive(_root_path(args.spec), args.helper_review)
    except (ArchiveError, OSError, ValueError, KeyError, TypeError) as exc:
        print(json.dumps({"status": "blocked", "error": f"{type(exc).__name__}:{exc}"},
                         ensure_ascii=False))
        return 2
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
