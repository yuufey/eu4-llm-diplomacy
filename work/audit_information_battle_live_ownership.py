"""Read-only pre-install ownership/no-repeat audit for the information observer.

The audit deliberately works from archived installation, recovery, journal, and
control artifacts.  It never opens the game, calls RPM/REA, publishes a
request, or mutates an existing artifact.  JSONL and SQLite inputs are read
with bounded parsers; the output is created exclusively so a later run cannot
silently replace evidence.
"""

from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sqlite3
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = (
    ROOT
    / "work"
    / "runtime"
    / "information-battle-live-20261025-001"
    / "ownership-audit-001.json"
)
MAX_JSON_BYTES = 2 * 1024 * 1024
MAX_LINE_BYTES = 2 * 1024 * 1024
HASH_CHUNK_BYTES = 1024 * 1024

V22_DIR = ROOT / "work" / "runtime" / "diplomacy-observer-20261025-information-battle-002"
V23_DIR = ROOT / "work" / "runtime" / "diplomacy-observer-20261025-information-battle-v23-005"
RECOVERY_DIR = ROOT / "work" / "runtime" / "information-recovery-20261025-001"
R70_DIR = ROOT / "work" / "runtime" / "r70-country-money-execution-20261020-001-evidence"
R70_DELIVERY = ROOT / "work" / "runtime" / "r70-country-money-delivery-20261020-001"
R70_JOURNAL = ROOT / "work" / "runtime" / "r70-journal-reopen-20261020-001"
R70_PROGRESS = ROOT / "work" / "runtime" / "r70-progress.json"
HANDOFF = ROOT / "HANDOFF.md"
AUTOMATION = ROOT / "开发过程自动化.md"
V23_SOURCE = V23_DIR / "information-battle-observer.inc"


def rel(path: Path) -> str:
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except ValueError:
        return str(path)


def sha256_file(path: Path) -> str | None:
    if not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while True:
            chunk = stream.read(HASH_CHUNK_BYTES)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def file_record(path: Path, role: str, *, include_hash: bool = True) -> dict[str, Any]:
    record: dict[str, Any] = {"path": rel(path), "role": role, "exists": path.is_file()}
    if not path.is_file():
        return record
    stat = path.stat()
    record["bytes"] = stat.st_size
    record["sha256"] = sha256_file(path) if include_hash else None
    return record


def read_json(path: Path) -> tuple[Any | None, dict[str, Any]]:
    record = file_record(path, "json")
    if not path.is_file():
        record["parse"] = "missing"
        return None, record
    size = path.stat().st_size
    if size > MAX_JSON_BYTES:
        record["parse"] = "too_large"
        record["max_bytes"] = MAX_JSON_BYTES
        return None, record
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        record["parse"] = "error"
        record["error"] = type(exc).__name__
        return None, record
    record["parse"] = "ok"
    return value, record


def json_scalar(value: Any) -> Any:
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return None


def installation_summary(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {"parse": "not_object"}
    attempts = value.get("ready_attempts")
    outcomes = Counter()
    if isinstance(attempts, list):
        for attempt in attempts:
            if isinstance(attempt, dict) and isinstance(attempt.get("outcome"), str):
                outcomes[attempt["outcome"]] += 1
    return {
        "pid_recorded": json_scalar(value.get("pid")),
        "creation_filetime": json_scalar(value.get("creation_filetime")),
        "session_id": json_scalar(value.get("session_id")),
        "experiment_id": json_scalar(value.get("experiment_id")),
        "game_sha256": json_scalar(value.get("game_sha256")),
        "dll_sha256": json_scalar(value.get("dll_sha256")),
        "installation_attempted": json_scalar(value.get("installation_attempted")),
        "installation_started": json_scalar(value.get("installation_started")),
        "installation_returncode": json_scalar(value.get("installation_returncode")),
        "runtime_verified": json_scalar(value.get("runtime_verified")),
        "ready_reason": json_scalar(value.get("ready_reason")),
        "ready_attempt_count": len(attempts) if isinstance(attempts, list) else None,
        "ready_attempt_outcomes": dict(outcomes),
        "preflight_player_tag": json_scalar(value.get("preflight_player_tag")),
        "modules_after_install": value.get("modules_after_install")
        if isinstance(value.get("modules_after_install"), list)
        else [],
    }


def selected_summary(value: Any, keys: Iterable[str]) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {"parse": "not_object"}
    result: dict[str, Any] = {}
    for key in keys:
        if key in value:
            item = value[key]
            if isinstance(item, list):
                result[key] = item[:32]
                if len(item) > 32:
                    result[f"{key}_truncated"] = True
            elif isinstance(item, dict):
                result[key] = {
                    k: json_scalar(v)
                    for k, v in item.items()
                    if isinstance(v, (str, int, float, bool)) or v is None
                }
            else:
                result[key] = json_scalar(item)
    return result


def stream_jsonl(path: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    record = file_record(path, "runtime_jsonl")
    stats: dict[str, Any] = {
        "lines": 0,
        "parsed": 0,
        "invalid_lines": 0,
        "oversize_lines": 0,
        "event_counts": {},
        "status_counts": {},
        "action_ids": [],
        "request_ids": [],
        "selected_events": [],
    }
    events: Counter[str] = Counter()
    statuses: Counter[str] = Counter()
    action_ids: set[str] = set()
    request_ids: set[str] = set()
    selected: list[dict[str, Any]] = []
    if not path.is_file():
        record["parse"] = "missing"
        return stats, record
    with path.open("rb") as stream:
        for line_number, raw in enumerate(stream, 1):
            stats["lines"] = line_number
            if len(raw) > MAX_LINE_BYTES:
                stats["oversize_lines"] += 1
                continue
            try:
                value = json.loads(raw.decode("utf-8"))
            except (UnicodeError, json.JSONDecodeError):
                stats["invalid_lines"] += 1
                continue
            if not isinstance(value, dict):
                stats["invalid_lines"] += 1
                continue
            stats["parsed"] += 1
            event = value.get("event")
            if isinstance(event, str):
                events[event] += 1
            for key, target in (("status", statuses), ("state", statuses), ("outcome", statuses)):
                item = value.get(key)
                if isinstance(item, str):
                    target[f"{key}={item}"] += 1
            action = value.get("action_id")
            request = value.get("request_id")
            if isinstance(action, str):
                action_ids.add(action)
            if isinstance(request, str):
                request_ids.add(request)
            if event in {
                "native_diplomacy_inbound_pending_restored",
                "native_diplomacy_saved_pending_scan_complete",
            }:
                keep = {
                    "line": line_number,
                    "event": event,
                    "session_id": value.get("session_id"),
                    "proposal_id": value.get("proposal_id"),
                    "action_id": value.get("action_id"),
                    "family": value.get("family"),
                    "actor": value.get("actor"),
                    "mirror": value.get("mirror"),
                    "recipient": value.get("recipient"),
                    "decision_country": value.get("decision_country"),
                    "date_raw": value.get("date_raw"),
                    "date28": value.get("date28"),
                    "date2c": value.get("date2c"),
                    "state34": value.get("state34"),
                    "variant38": value.get("variant38"),
                    "proposal3c": value.get("proposal3c"),
                    "token3c": value.get("token3c"),
                    "created2c": value.get("created2c"),
                    "queue_after_count": value.get("queue_after_count"),
                    "queue_readable": value.get("queue_readable"),
                    "list_integrity": value.get("list_integrity"),
                    "new_entry": value.get("new_entry"),
                    "payload_readable": value.get("payload_readable"),
                    "decision_country_verified": value.get("decision_country_verified"),
                    "pending_source": value.get("pending_source"),
                    "source_verified": value.get("source_verified"),
                    "call_redirected": value.get("call_redirected"),
                    "saved_queue_restored": value.get("saved_queue_restored"),
                    "native_queue_membership_verified": value.get("native_queue_membership_verified"),
                    "native_node": value.get("native_node"),
                    "native_action": value.get("native_action"),
                    "business_result": value.get("business_result"),
                    "native_queue_count": value.get("native_queue_count"),
                    "native_queue_unchanged": value.get("native_queue_unchanged"),
                    "restored_count": value.get("restored_count"),
                }
                selected.append({k: v for k, v in keep.items() if v is not None})
    stats["event_counts"] = dict(events)
    stats["status_counts"] = dict(statuses)
    stats["action_ids"] = sorted(action_ids)
    stats["request_ids"] = sorted(request_ids)
    stats["selected_events"] = selected
    record["parse"] = "jsonl_bounded"
    record["max_line_bytes"] = MAX_LINE_BYTES
    return stats, record


def sqlite_snapshot(path: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    record = file_record(path, "read_only_sqlite")
    result: dict[str, Any] = {
        "mode": "missing",
        "query_only": None,
        "tables": [],
        "table_counts": {},
        "request_rows": [],
        "status_counts": {},
        "evidence_rows": [],
    }
    if not path.is_file():
        return result, record
    uri = f"{path.resolve().as_uri()}?mode=ro"
    connection: sqlite3.Connection | None = None
    try:
        connection = sqlite3.connect(uri, uri=True, timeout=2.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only=ON")
        result["query_only"] = bool(connection.execute("PRAGMA query_only").fetchone()[0])
        tables = [
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
            )
        ]
        result["mode"] = "read_only"
        result["tables"] = tables
        for table in tables:
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", table):
                continue
            result["table_counts"][table] = int(
                connection.execute(f'SELECT count(*) FROM "{table}"').fetchone()[0]
            )
        if "diplomacy_requests" in tables:
            rows = connection.execute(
                """
                SELECT experiment_id, session_id, request_id, status,
                       submission_id, submission_token, claimed_at, submitted_at,
                       created_at, updated_at
                  FROM diplomacy_requests
                 ORDER BY created_at, request_id
                 LIMIT 256
                """
            ).fetchall()
            result["request_rows"] = [dict(row) for row in rows]
            result["status_counts"] = {
                str(row[0]): int(row[1])
                for row in connection.execute(
                    "SELECT status, count(*) FROM diplomacy_requests GROUP BY status ORDER BY status"
                )
            }
        if "diplomacy_evidence" in tables:
            rows = connection.execute(
                """
                SELECT evidence_id, request_id, event_id, arrival_layer,
                       evidence_type, content_sha256, observed_at, recorded_at
                  FROM diplomacy_evidence
                 ORDER BY evidence_id
                 LIMIT 256
                """
            ).fetchall()
            result["evidence_rows"] = [dict(row) for row in rows]
    except (OSError, sqlite3.Error) as exc:
        result["mode"] = "error"
        result["error"] = type(exc).__name__
    finally:
        if connection is not None:
            connection.close()
    record["parse"] = result["mode"]
    return result, record


def policy_lines(path: Path, patterns: list[str]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    record = file_record(path, "policy_reference")
    hits: list[dict[str, Any]] = []
    if not path.is_file():
        record["parse"] = "missing"
        return hits, record
    compiled = [re.compile(pattern, re.IGNORECASE) for pattern in patterns]
    with path.open("r", encoding="utf-8", errors="replace") as stream:
        for line_number, line in enumerate(stream, 1):
            if any(pattern.search(line) for pattern in compiled):
                hits.append({"line": line_number, "text": line.rstrip()[:1200]})
                if len(hits) >= 12:
                    break
    record["parse"] = "line_scan"
    return hits, record


def source_contract(path: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    record = file_record(path, "v23_static_contract")
    result: dict[str, Any] = {"static_only": True, "markers": []}
    if not path.is_file():
        result["status"] = "missing"
        record["parse"] = "missing"
        return result, record
    patterns = (
        "No historical or unknown command",
        'strcmp(tokens[2],"enable")',
        "information-battle-control.request",
        "information-battle-status.json",
        "business_export_available",
        "request_id",
    )
    with path.open("r", encoding="utf-8", errors="replace") as stream:
        for line_number, line in enumerate(stream, 1):
            if any(marker in line for marker in patterns):
                result["markers"].append({"line": line_number, "text": line.rstrip()[:1200]})
    result["status"] = "observed" if result["markers"] else "no_marker"
    record["parse"] = "source_line_scan"
    return result, record


def control_file_inventory() -> list[dict[str, Any]]:
    names = [
        "information-battle-control.request",
        "information-battle-control.processing",
        "information-battle-status.json",
        "information-preflight-control.json",
        "information-preflight-health.json",
        "information-battle-raw.jsonl",
    ]
    records = [file_record(V22_DIR / name, "v22_control_or_status") for name in names]
    for pattern in ("information-battle-response-*.json", "information-battle-started-*.json"):
        for path in sorted(V22_DIR.glob(pattern)):
            records.append(file_record(path, "v22_control_receipt"))
    return records


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument(
        "--verify-existing",
        action="store_true",
        help="load an existing output and validate its JSON without rewriting it",
    )
    args = parser.parse_args()
    output = args.output if args.output.is_absolute() else ROOT / args.output
    if args.verify_existing:
        if not output.is_file():
            raise SystemExit(f"missing existing report: {output}")
        value = json.loads(output.read_text(encoding="utf-8"))
        if not isinstance(value, dict) or value.get("schema") != "information-battle-live-ownership-audit/1":
            raise SystemExit("existing report schema mismatch")
        print(json.dumps({"status": "verified", "path": rel(output), "bytes": output.stat().st_size}, ensure_ascii=False))
        return 0
    if output.exists():
        raise SystemExit(f"refusing to overwrite existing report: {output}")

    installation, installation_record = read_json(V22_DIR / "installation.json")
    v22_manifest, v22_manifest_record = read_json(V22_DIR / "build-manifest.json")
    v23_manifest, v23_manifest_record = read_json(V23_DIR / "build-manifest.json")
    preflight_control, preflight_control_record = read_json(V22_DIR / "information-preflight-control.json")
    preflight_health, preflight_health_record = read_json(V22_DIR / "information-preflight-health.json")
    startup_recovery, startup_recovery_record = read_json(RECOVERY_DIR / "startup-recovery-001.json")
    final_health, final_health_record = read_json(RECOVERY_DIR / "final-health-001.json")
    final_control, final_control_record = read_json(RECOVERY_DIR / "final-control-001.json")
    r70_submission, r70_submission_record = read_json(R70_DIR / "outbound-submission.json")
    r70_result, r70_result_record = read_json(R70_DIR / "outbound-result.json")
    r70_journal, r70_journal_record = read_json(R70_JOURNAL / "report.json")
    r70_manifest, r70_manifest_record = read_json(R70_DELIVERY / "manifest.json")
    r70_progress, r70_progress_record = read_json(R70_PROGRESS)
    r70_db, r70_db_record = sqlite_snapshot(R70_DIR / "diplomacy.sqlite3")
    control_probe_stats, control_probe_record = stream_jsonl(V22_DIR / "control-probe.jsonl")
    handoff_hits, handoff_record = policy_lines(
        HANDOFF,
        [r"历史120动作批", r"success/dispatched/unknown", r"原final-pass", r"未闭合ownership"],
    )
    automation_hits, automation_record = policy_lines(
        AUTOMATION,
        [r"所有历史成功", r"旧业务请求", r"重放", r"未闭合"],
    )
    v23_contract, v23_contract_record = source_contract(V23_SOURCE)

    startup_scope = (
        startup_recovery.get("scope", {}) if isinstance(startup_recovery, dict) else {}
    )
    final_health_scope = (
        final_health.get("scope", {}) if isinstance(final_health, dict) else {}
    )
    submission_result = r70_submission.get("result", {}) if isinstance(r70_submission, dict) else {}
    r70_row = None
    if r70_db.get("request_rows"):
        r70_row = r70_db["request_rows"][0]
    pending_event = next(
        (
            item
            for item in control_probe_stats.get("selected_events", [])
            if item.get("event") == "native_diplomacy_inbound_pending_restored"
        ),
        None,
    )
    pending_scan = next(
        (
            item
            for item in control_probe_stats.get("selected_events", [])
            if item.get("event") == "native_diplomacy_saved_pending_scan_complete"
        ),
        None,
    )

    records = [
        installation_record,
        v22_manifest_record,
        v23_manifest_record,
        preflight_control_record,
        preflight_health_record,
        startup_recovery_record,
        final_health_record,
        final_control_record,
        r70_submission_record,
        r70_result_record,
        r70_journal_record,
        r70_manifest_record,
        r70_progress_record,
        r70_db_record,
        control_probe_record,
        handoff_record,
        automation_record,
        v23_contract_record,
    ]
    records.extend(control_file_inventory())

    explicit_exclusions: list[dict[str, Any]] = []
    if isinstance(r70_row, dict):
        explicit_exclusions.append(
            {
                "kind": "historical_submitted_request",
                "request_id": r70_row.get("request_id"),
                "action_id": "release_nation",
                "session_id": r70_row.get("session_id"),
                "status": r70_row.get("status"),
                "submitted_at": r70_row.get("submitted_at"),
                "submission_id": r70_row.get("submission_id"),
                "submission_token": r70_row.get("submission_token"),
                "must_exclude_from_replay": True,
                "reason": "submitted/native receipt exists even though terminal native outcome was rejected",
                "source": rel(R70_DIR / "diplomacy.sqlite3"),
            }
        )
    if pending_event is not None:
        explicit_exclusions.append(
            {
                "kind": "restored_inbound_pending_observation",
                "proposal_id": pending_event.get("proposal_id"),
                "action_id": pending_event.get("action_id"),
                "family": pending_event.get("family"),
                "actor": pending_event.get("actor"),
                "recipient": pending_event.get("recipient"),
                "decision_country": pending_event.get("decision_country"),
                "state34": pending_event.get("state34"),
                "queue_after_count": pending_event.get("queue_after_count"),
                "business_result": pending_event.get("business_result"),
                "must_exclude_from_response_or_replay": True,
                "reason": "saved pending entry was observed/restored; no response or old dispatch was created",
                "source": rel(V22_DIR / "control-probe.jsonl"),
                "source_line": pending_event.get("line"),
            }
        )

    categories = {
        "success": {
            "must_exclude": True,
            "inventory": "not_enumerated_in_scoped_artifacts",
            "note": "HANDOFF policy covers historical success records; this audit does not infer an empty global ledger.",
        },
        "dispatched_or_submitted": {
            "must_exclude": True,
            "inventory": "one_explicit_r70_row" if r70_row else "not_enumerated",
        },
        "unknown": {
            "must_exclude": True,
            "inventory": "not_enumerated_in_scoped_artifacts",
            "note": "No central all-history ledger was found in the exact paths; unknown actions remain prohibited by policy.",
        },
        "unclosed_ownership": {
            "must_exclude": True,
            "inventory": "one_restored_saved_pending_observation" if pending_event else "not_observed",
        },
        "original_final_pass_ids": {
            "must_exclude": True,
            "inventory": "not_enumerated_in_scoped_artifacts",
            "note": "No canonical final-pass ID list was present in the scoped records; this is not evidence that the global list is empty.",
        },
    }

    report: dict[str, Any] = {
        "schema": "information-battle-live-ownership-audit/1",
        "status": "passed_with_no_replay_authorization",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "scope": {
            "kind": "read_only_pre_install_ownership_no_repeat_audit",
            "game_access": False,
            "rpm": False,
            "rea": False,
            "dispatch_or_replay": False,
            "business_data_mutation": False,
            "current_process_checked": False,
            "historical_pid_is_not_current_identity": True,
            "bounded_json_bytes": MAX_JSON_BYTES,
            "bounded_jsonl_line_bytes": MAX_LINE_BYTES,
            "sqlite_mode": "URI mode=ro; PRAGMA query_only=ON",
        },
        "current_v22_installation": {
            "path": rel(V22_DIR / "installation.json"),
            "recorded_identity": installation_summary(installation),
            "manifest": selected_summary(
                v22_manifest,
                ["version", "experiment_id", "compiled", "runtime_verified", "reason_metadata_requested", "game_sha256", "dll_sha256", "dll"],
            ),
            "record_status_caveat": "archived record only; no live process check was performed by this audit",
            "preflight_control": selected_summary(
                preflight_control,
                ["pid", "read_only", "player_slot", "date_raw", "speed", "paused_flag", "server", "server_vtable_rva"],
            ),
            "preflight_health": selected_summary(
                preflight_health,
                ["status", "complete", "state_id", "date_raw", "reasons"],
            ),
            "final_health_record": selected_summary(
                final_health,
                ["status", "session_id", "pid", "creation_filetime", "observer_installation", "installation_sha256", "scope", "health", "pending_request_files"],
            ),
            "final_control_record": selected_summary(
                final_control,
                ["pid", "read_only", "player_slot", "date_raw", "speed", "paused_flag"],
            ),
            "control_probe": control_probe_stats,
            "control_files": control_file_inventory(),
        },
        "historical_r70_lineage": {
            "restored_save_sha256": "ffa91dbd2a2d544b18d586a895bb9b0c2b90e94ece47b2c74507555b8f58c2e0",
            "startup_recovery": {
                "status": startup_recovery.get("status") if isinstance(startup_recovery, dict) else None,
                "binding": startup_recovery.get("binding") if isinstance(startup_recovery, dict) else None,
                "scope": startup_scope,
                "checks": startup_recovery.get("checks") if isinstance(startup_recovery, dict) else None,
                "note": startup_recovery.get("note") if isinstance(startup_recovery, dict) else None,
            },
            "request_journal": {
                "database": rel(R70_DIR / "diplomacy.sqlite3"),
                "snapshot": r70_db,
                "explicit_row": r70_row,
            },
            "submission_artifact": {
                "request_id": r70_submission.get("request_id") if isinstance(r70_submission, dict) else None,
                "action_id": r70_submission.get("action_id") if isinstance(r70_submission, dict) else None,
                "status": r70_submission.get("status") if isinstance(r70_submission, dict) else None,
                "submitted": r70_submission.get("submitted") if isinstance(r70_submission, dict) else None,
                "game_outcome": r70_submission.get("game_outcome") if isinstance(r70_submission, dict) else None,
                "result": {
                    key: submission_result.get(key)
                    for key in [
                        "outcome",
                        "native_outcome",
                        "native_state",
                        "execution_verified",
                        "response_verified",
                        "request_binding_verified",
                        "terms_verified",
                        "date_raw",
                    ]
                    if key in submission_result
                },
            },
            "journal_reopen": selected_summary(
                r70_journal,
                ["status", "session_id", "checks", "result"],
            ),
            "delivery_manifest": selected_summary(
                r70_manifest,
                ["stage", "status", "progress", "historical_family_reference"],
            ),
            "progress": selected_summary(
                r70_progress,
                ["stage", "status", "goal_status", "session_id", "actual_outbound_requests", "native_ai_outcome", "request_id", "journal_reopen_equal", "dedicated_save_reload"],
            ),
        },
        "ownership_no_repeat_policy": {
            "categories": categories,
            "explicit_exclusions": explicit_exclusions,
            "policy_references": {
                "handoff": handoff_hits,
                "automation": automation_hits,
            },
            "inventory_limit": "This report does not claim that absent final-pass, success, or unknown IDs do not exist globally.",
        },
        "v23_observer_scope": {
            "build": selected_summary(
                v23_manifest,
                ["version", "experiment_id", "compiled", "runtime_verified", "reason_metadata_requested", "game_sha256", "dll_sha256", "dll", "information_battle_research_lifecycle"],
            ),
            "build_directory_has_installation_record": (V23_DIR / "installation.json").is_file(),
            "active_v23_installation_observed": False,
            "source_contract": v23_contract,
            "allowed_scope": ["install/startup", "status", "enable", "disable"],
            "constructs_diplomacy_requests": False,
            "replays_historical_or_unknown_actions": False,
            "does_not_close_existing_business_ownership": True,
            "static_only_caveat": "source/build inspection is not a runtime installation or business-action authorization",
        },
        "artifact_records": records,
        "findings": [
            {
                "id": "OWN-001",
                "severity": "must_exclude",
                "state": "historical_submitted_terminal_rejected",
                "request_id": "r70_country_money_001_outbound",
                "action_id": "release_nation",
                "evidence": [rel(R70_DIR / "outbound-submission.json"), rel(R70_DIR / "outbound-result.json"), rel(R70_DIR / "diplomacy.sqlite3")],
                "conclusion": "submitted/native receipt exists; terminal rejection does not permit replay",
            },
            {
                "id": "OWN-002",
                "severity": "must_exclude",
                "state": "saved_inbound_pending_observed",
                "action_id": pending_event.get("action_id") if pending_event else None,
                "proposal_id": pending_event.get("proposal_id") if pending_event else None,
                "queue_after_count": pending_event.get("queue_after_count") if pending_event else None,
                "evidence": [rel(V22_DIR / "control-probe.jsonl"), rel(RECOVERY_DIR / "startup-recovery-001.json")],
                "conclusion": "native saved pending was observed/restored with no response or old dispatch; treat as unclosed and do not answer/replay",
            },
            {
                "id": "OWN-003",
                "severity": "boundary",
                "state": "request_files_empty_in_archived_final_health",
                "evidence": [rel(RECOVERY_DIR / "final-health-001.json")],
                "conclusion": "pending_request_files=[] is a bounded archived file check, not proof that all historical ownership is closed",
            },
            {
                "id": "OWN-004",
                "severity": "boundary",
                "state": "v23_not_installed",
                "evidence": [rel(V23_DIR / "build-manifest.json")],
                "conclusion": "v23 is a compiled artifact only in this audit; install/startup must be separately authorized and re-bound",
            },
        ],
        "limitations": [
            "The historical PID/session in installation.json was not checked against a live process; it is not current identity evidence.",
            "No canonical global ledger enumerating every historical success, unknown, unclosed ownership, or original final-pass ID was present in the scoped files; policy therefore remains exclusionary rather than permissive.",
            "The R70 SQLite row is a different historical session and is included as lineage evidence only.",
            "Static observer source and fixture checks do not authorize diplomacy dispatch, response, replay, or closure of the restored pending entry.",
        ],
        "decision": {
            "business_actions_authorized": False,
            "observer_install_scope_only": True,
            "requires_root_decision_before_any_specific_action": True,
        },
    }

    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(report, stream, ensure_ascii=False, indent=2, sort_keys=True)
        stream.write("\n")
    print(
        json.dumps(
            {
                "status": report["status"],
                "path": rel(output),
                "bytes": output.stat().st_size,
                "sha256": sha256_file(output),
                "explicit_exclusions": len(explicit_exclusions),
                "pending_event": pending_event is not None,
                "r70_request_rows": len(r70_db.get("request_rows", [])),
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
