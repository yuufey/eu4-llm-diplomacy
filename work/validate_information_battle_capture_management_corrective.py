"""Run the once-only corrective live capture-management acceptance.

This validator is deliberately narrower than the original lifecycle runner.
It audits the completed live001 receipt, the existing service database, the
native status file, and the capture journal before starting MCP.  It then
reuses the already-created B04 report, exercises one new subscription through
enable/pause/resume, runs the existing natural-window helper exactly once,
and relies on the server scheduler for post-window ingestion.  It never
repeats the old two-consumer cycle or creates a report/query again.

The command is inert unless the caller supplies the concrete live paths and
the required ``--test-only`` flag.  Every output JSON is opened with ``x``;
an audit failure returns before a new subscription or native control can be
issued.
"""

from __future__ import annotations

import argparse
from collections import Counter
from copy import deepcopy
import json
from pathlib import Path
import sqlite3
import sys
import time
from typing import Any, Mapping

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.control_information_battle_observer import run_control
from work.validate_information_battle_capture_management_live import (
    AcceptanceUnavailable,
    GAME_SHA256,
    GAME_VERSION,
    HEX16,
    HEX64,
    StdioClient,
    _delivery_arguments,
    _event_results,
    _fullref_tag,
    _manage_subscription,
    _read_json,
    _request_namespace,
    _run_natural_window,
    _status_step,
    _step,
    _write_json_new,
)
from work.probe_information_battle_installed import (
    classify_country_control_consumed_receipts,
)


DEFAULT_EXPECTED_DATE = 56561088
DEFAULT_DAYS = 35
AUDIT_SCHEMA = "information_battle_capture_management_corrective_audit.v1"
REPORT_SCHEMA = "information_battle_capture_management_corrective.v1"


class AuditFailure(RuntimeError):
    """The read-only preflight did not authorize a new corrective cycle."""


def _require_int(value: Any, label: str, *, positive: bool = False) -> int:
    if isinstance(value, bool) or type(value) is not int:
        raise AcceptanceUnavailable(f"{label}_must_be_integer")
    if positive and value <= 0:
        raise AcceptanceUnavailable(f"{label}_must_be_positive")
    if value < 0:
        raise AcceptanceUnavailable(f"{label}_must_be_nonnegative")
    return value


def _load_existing_inputs(installation_path: Path, stream_path: Path,
                          database_path: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    """Validate the existing live binding without requiring a new database."""
    installation_path = installation_path.resolve(strict=True)
    stream_path = stream_path.resolve(strict=True)
    database_path = database_path.resolve(strict=True)
    installation = _read_json(installation_path)
    if not isinstance(installation, dict):
        raise AcceptanceUnavailable("installation_not_object")
    session_id = installation.get("session_id")
    game_sha256 = installation.get("game_sha256")
    if not isinstance(session_id, str) or not session_id:
        raise AcceptanceUnavailable("installation_session_missing")
    if game_sha256 != GAME_SHA256:
        raise AcceptanceUnavailable("installation_game_sha_mismatch")
    creation = _require_int(installation.get("creation_filetime"), "creation_filetime", positive=True)

    stream = _read_json(stream_path, limit=256 * 1024)
    if (not isinstance(stream, dict)
            or set(stream) != {"schema", "database", "binding"}
            or stream.get("schema") != "EU4-BATTLE-STREAM/1"):
        raise AcceptanceUnavailable("battle_stream_shape_mismatch")
    configured_database = stream.get("database")
    if not isinstance(configured_database, str) or not configured_database:
        raise AcceptanceUnavailable("battle_stream_database_missing")
    configured_path = Path(configured_database)
    if not configured_path.is_absolute():
        configured_path = stream_path.parent / configured_path
    if configured_path.resolve() != database_path:
        raise AcceptanceUnavailable("battle_stream_database_differs_from_cli_database")

    binding = stream.get("binding")
    if not isinstance(binding, dict):
        raise AcceptanceUnavailable("battle_stream_binding_missing")
    if binding.get("mode") != "live":
        raise AcceptanceUnavailable("battle_stream_binding_not_live")
    if binding.get("game_sha256") != game_sha256:
        raise AcceptanceUnavailable("battle_stream_game_sha_mismatch")
    if binding.get("session_id") != session_id:
        raise AcceptanceUnavailable("battle_stream_session_mismatch")
    if binding.get("process_creation_filetime") != creation:
        raise AcceptanceUnavailable("battle_stream_creation_mismatch")
    for key in ("installation", "generation", "observer_ref"):
        if not isinstance(binding.get(key), str) or HEX16.fullmatch(binding[key]) is None:
            raise AcceptanceUnavailable(f"battle_stream_{key}_invalid")
    if _fullref_tag(binding["observer_ref"]) != "FRA":
        raise AcceptanceUnavailable("battle_stream_observer_must_be_FRA")
    return {
        "path": installation_path,
        "pid": installation.get("pid"),
        "creation_filetime": creation,
        "session_id": session_id,
        "game_sha256": game_sha256,
        "dll_sha256": installation.get("dll_sha256"),
    }, deepcopy(binding)


def _pending_channel_scan(directory: Path,
                          installation: Mapping[str, Any] | None = None
                          ) -> tuple[list[str], dict[str, Any]]:
    """Find only live request/processing channels, never source snapshots."""
    receipts = (
        classify_country_control_consumed_receipts(directory, installation)
        if isinstance(installation, Mapping)
        else {"status": "identity_unavailable", "closed": [], "unverified": [],
              "native_calls": 0, "game_access": False}
    )
    closed_names = {item.get("name") for item in receipts.get("closed", [])
                    if isinstance(item, Mapping)}
    exact = {
        "information-battle-control.request",
        "information-battle-control.processing",
        "game-control.request",
        "game-control.processing",
        "game-control.intent",
    }
    names: list[str] = []
    for path in directory.iterdir():
        if not path.is_file():
            continue
        lower = path.name.lower()
        if path.name in closed_names:
            continue
        if (lower in exact or lower.endswith((".request", ".processing", ".intent", ".req"))
                or ".request." in lower or ".processing." in lower):
            names.append(path.name)
    return sorted(names), receipts


def _pending_channel_files(directory: Path,
                           installation: Mapping[str, Any] | None = None) -> list[str]:
    return _pending_channel_scan(directory, installation)[0]


def _sqlite_read_only(path: Path, report_id: str,
                      prior_subscription_ids: Mapping[str, str]) -> dict[str, Any]:
    uri = path.resolve(strict=True).as_uri() + "?mode=ro"
    connection = sqlite3.connect(uri, uri=True)
    connection.row_factory = sqlite3.Row
    try:
        connection.execute("PRAGMA query_only=ON")
        tables = {
            row[0] for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'")
        }
        required = {"info_config", "info_runtime", "info_requests"}
        if not required.issubset(tables):
            raise AuditFailure(f"sqlite_tables_missing:{sorted(required - tables)}")
        report_row = connection.execute(
            "SELECT owner, id, body FROM info_config WHERE kind='report' AND id=?",
            (report_id,),
        ).fetchone()
        if report_row is None:
            raise AuditFailure("reused_report_missing_from_database")
        report_value = json.loads(report_row["body"])
        if not isinstance(report_value, dict) or report_value.get("id") != report_id:
            raise AuditFailure("reused_report_body_mismatch")
        queries = report_value.get("queries")
        if (report_value.get("detail") != "raw" or not isinstance(queries, list)
                or not any(isinstance(q, Mapping) and q.get("topic") == "B04"
                           for q in queries)):
            raise AuditFailure("reused_report_config_not_raw_B04")

        rows = []
        for row in connection.execute(
                "SELECT owner, id, body FROM info_config WHERE kind='subscription' ORDER BY id"):
            value = json.loads(row["body"])
            if not isinstance(value, dict):
                raise AuditFailure(f"subscription_body_not_object:{row['id']}")
            rows.append(value)
        expected_names = set(prior_subscription_ids)
        actual_names = {value.get("name") for value in rows}
        if actual_names != expected_names:
            raise AuditFailure(
                f"old_subscription_names_mismatch:{sorted(actual_names)}:{sorted(expected_names)}")
        old_rows: list[dict[str, Any]] = []
        for value in rows:
            name = value.get("name")
            if (value.get("id") != prior_subscription_ids.get(name)
                    or value.get("state") != "cancelled"
                    or value.get("enabled") is not False
                    or value.get("report_id") != report_id):
                raise AuditFailure(f"old_subscription_not_cancelled:{value}")
            old_rows.append({
                "id": value.get("id"), "name": name,
                "state": value.get("state"), "version": value.get("version"),
                "enabled": value.get("enabled"), "report_id": value.get("report_id"),
            })

        runtime_rows = []
        for row in connection.execute(
                "SELECT id, body FROM info_runtime WHERE id IN (?, ?, ?)",
                ("capture-source", *prior_subscription_ids.values())):
            runtime_rows.append({"id": row["id"], "body": json.loads(row["body"])})
        pending_request_rows = int(connection.execute(
            "SELECT count(*) FROM info_requests").fetchone()[0])
        return {
            "database": str(path.resolve()),
            "tables": sorted(tables),
            "report": {"owner": report_row["owner"], "id": report_id,
                        "queries": queries, "detail": report_value.get("detail")},
            "old_subscriptions": old_rows,
            "runtime_rows": runtime_rows,
            "info_request_row_count": pending_request_rows,
            "read_only": True,
        }
    finally:
        connection.close()


def _previous_receipt(previous_report: Path, database: Path) -> tuple[dict[str, Any], str, dict[str, str]]:
    previous_report = previous_report.resolve(strict=True)
    prior = _read_json(previous_report)
    if not isinstance(prior, dict) or prior.get("schema") != "information_battle_capture_management_live.v1":
        raise AuditFailure("previous_report_schema_mismatch")
    expected_checks = {
        "tool_schemas_and_B04_event_capability",
        "sub1_manager_enabled_owned_one",
        "sub2_added_as_second_consumer",
        "sub2_pause_cancel_keeps_sub1_enabled_owned",
        "last_consumer_pause_disables_capture",
        "server_exit_code_zero",
    }
    checks = prior.get("checks")
    if not isinstance(checks, Mapping) or any(checks.get(key) is not True for key in expected_checks):
        raise AuditFailure("previous_report_successful_checks_missing")

    report_candidates: list[tuple[Path, str]] = []
    prior_subscription_ids: dict[str, str] = {}
    for path in sorted(previous_report.parent.glob("tool-*-response.json")):
        try:
            value = _read_json(path)
        except Exception:
            continue
        report = value.get("report")
        if isinstance(report, Mapping) and isinstance(report.get("id"), str):
            report_candidates.append((path, report["id"]))
        subscription = value.get("subscription")
        if isinstance(subscription, Mapping):
            name = subscription.get("name")
            ident = subscription.get("id")
            if name in {"managed-battle-sub1", "managed-battle-sub2"} and isinstance(ident, str):
                prior_subscription_ids[str(name)] = ident
    if len(report_candidates) != 1:
        raise AuditFailure(f"previous_report_id_evidence_count:{len(report_candidates)}")
    if set(prior_subscription_ids) != {"managed-battle-sub1", "managed-battle-sub2"}:
        raise AuditFailure("previous_subscription_id_evidence_missing")
    report_id = report_candidates[0][1]
    db_audit = _sqlite_read_only(database, report_id, prior_subscription_ids)
    return {
        "path": str(previous_report),
        "status": prior.get("status"),
        "checks": {key: checks.get(key) for key in sorted(expected_checks)},
        "report_response_path": str(report_candidates[0][0]),
        "report_id": report_id,
        "subscription_ids": dict(sorted(prior_subscription_ids.items())),
        "sqlite": db_audit,
    }, report_id, prior_subscription_ids


def _complete_audit(installation: Mapping[str, Any], binding: Mapping[str, Any],
                   database: Path, previous_report: Path) -> tuple[dict[str, Any], str | None]:
    failures: list[str] = []
    audit: dict[str, Any] = {
        "schema": AUDIT_SCHEMA,
        "status": "running",
        "checked_at_ns": time.time_ns(),
        "installation": str(installation["path"]),
        "database": str(database.resolve()),
        "pending_channel_files": [],
    }
    report_id: str | None = None

    try:
        status = run_control(installation["path"], "status")
        native = status.get("native") if isinstance(status, Mapping) else None
        audit["native_status"] = {
            "status": status.get("status") if isinstance(status, Mapping) else None,
            "fresh": status.get("fresh") if isinstance(status, Mapping) else None,
            "observed_at_ns": status.get("observed_at_ns") if isinstance(status, Mapping) else None,
            "native_state": native.get("state") if isinstance(native, Mapping) else None,
            "native_installation": status.get("installation") if isinstance(status, Mapping) else None,
        }
        if (not isinstance(status, Mapping) or status.get("status") != "observed"
                or status.get("fresh") is not True
                or not isinstance(status.get("observed_at_ns"), int)
                or not isinstance(native, Mapping) or native.get("state") != "disabled"):
            failures.append("native_status_not_fresh_disabled")
    except Exception as error:
        audit["native_status_error"] = {"type": type(error).__name__, "message": str(error)}
        failures.append("native_status_read_failed")

    journal_path = Path(installation["path"]).parent / "information-battle-capture-journal.json"
    try:
        journal = _read_json(journal_path, limit=128 * 1024)
        audit["capture_journal"] = {
            "path": str(journal_path),
            "schema": journal.get("schema"), "state": journal.get("state"),
            "owned": journal.get("owned"), "updated_at": journal.get("updated_at"),
            "identity": deepcopy(journal.get("identity")),
        }
        identity = journal.get("identity")
        expected_native_installation = int(str(binding["installation"]), 16)
        expected_generation = int(str(binding["generation"]), 16)
        if (journal.get("schema") != "eu4-information-battle-capture/1"
                or journal.get("state") != "completed-disabled"
                or journal.get("owned") is not False
                or not isinstance(identity, Mapping)
                or identity.get("creation_filetime") != installation.get("creation_filetime")
                or identity.get("game_sha256") != GAME_SHA256
                or identity.get("dll_sha256") != installation.get("dll_sha256")
                or identity.get("installation") != expected_native_installation
                or identity.get("generation") != expected_generation
                or Path(str(identity.get("installation_path"))).resolve() != Path(installation["path"]).resolve()):
            failures.append("capture_journal_not_completed_disabled_unowned")
    except Exception as error:
        audit["capture_journal_error"] = {"type": type(error).__name__, "message": str(error)}
        failures.append("capture_journal_read_failed")

    try:
        pending, consumed_receipts = _pending_channel_scan(
            Path(installation["path"]).parent, installation)
        audit["pending_channel_files"] = pending
        audit["country_control_consumed_receipts"] = consumed_receipts
        if pending:
            failures.append("pending_control_execution_gamecontrol_channel")
    except Exception as error:
        audit["pending_channel_error"] = {"type": type(error).__name__, "message": str(error)}
        failures.append("pending_channel_scan_failed")

    try:
        prior, report_id, prior_ids = _previous_receipt(previous_report, database)
        audit["previous_receipt"] = prior
        audit["old_subscriptions_cancelled"] = True
    except Exception as error:
        audit["previous_receipt_error"] = {"type": type(error).__name__, "message": str(error)}
        failures.append("previous_receipt_or_readonly_sql_failed")

    audit["status"] = "passed" if not failures else "failed"
    audit["failures"] = failures
    audit["native_control_issued"] = False
    return audit, report_id


def _event_keys(results: list[dict[str, Any]]) -> list[tuple[str, str]]:
    keys: list[tuple[str, str]] = []
    for item in results:
        event = item.get("event")
        event_id = event.get("event_id") if isinstance(event, Mapping) else None
        subscription_id = item.get("subscription_id")
        if not isinstance(subscription_id, str) or not isinstance(event_id, str):
            raise AssertionError(f"event_result_identity_missing:{item}")
        keys.append((subscription_id, event_id))
    return keys


def _result_ids(results: list[dict[str, Any]]) -> list[str]:
    ids = []
    for item in results:
        result_id = item.get("result_id")
        if not isinstance(result_id, str):
            raise AssertionError(f"event_result_id_missing:{item}")
        ids.append(result_id)
    return ids


def run(args: argparse.Namespace) -> int:
    if not args.test_only:
        raise AssertionError("--test-only is mandatory for corrective acceptance")
    output = args.output.resolve()
    if output.exists():
        raise AssertionError(f"refusing_to_overwrite_output:{output}")
    output.mkdir(parents=True, exist_ok=False)
    natural_output = ((args.natural_window_output or (output.parent / "natural-window-001")).resolve())
    previous_report = (args.previous_report or (output.parent / "live-acceptance-001" / "report.json")).resolve()
    report: dict[str, Any] = {
        "schema": REPORT_SCHEMA,
        "status": "running",
        "mode": "live_corrective",
        "mcp_started": False,
        "inputs": {
            "installation": str(args.installation),
            "battle_stream": str(args.battle_stream),
            "database": str(args.database),
            "database_must_exist": True,
            "previous_report": str(previous_report),
            "output": str(output),
            "natural_window_output": str(natural_output),
            "test_only": True,
            "expected_manifest_sha256": args.expected_manifest_sha256,
            "expected_dll_sha256": args.expected_dll_sha256,
            "expected_date": args.expected_date,
            "days": args.days,
            "scheduler_tick_seconds": 1.0,
        },
        "checks": {}, "steps": [], "lifecycle": [],
        "limitations": [
            "The previous live001 report, report configuration, and query are reused; no discovery or report creation is repeated.",
            "The preflight calls run_control(status) only and refuses all new control when any audit check fails.",
            "The natural-window helper is invoked exactly once with explicit --test-only; post-window ingestion uses the MCP scheduler.",
        ],
    }
    client: StdioClient | None = None
    namespace = _request_namespace(output)
    subscription: dict[str, Any] | None = None
    return_code = 1
    try:
        installation, stream_binding = _load_existing_inputs(
            args.installation, args.battle_stream, args.database)
        report["identity"] = {
            key: installation.get(key)
            for key in ("pid", "creation_filetime", "session_id", "game_sha256", "dll_sha256")
        }
        report["binding"] = {
            key: stream_binding.get(key)
            for key in ("installation", "generation", "observer_ref", "session_id",
                        "process_creation_filetime", "mode")
        }

        audit, report_id = _complete_audit(
            installation, stream_binding, args.database.resolve(), previous_report)
        report["audit"] = audit
        _write_json_new(output / "preflight-audit.json", audit)
        if audit.get("status") != "passed" or not isinstance(report_id, str):
            raise AuditFailure(";".join(audit.get("failures", [])) or "audit_report_id_missing")
        report["reused_report_id"] = report_id
        report["checks"]["complete_read_only_preflight"] = True

        client = StdioClient(installation["path"], args.battle_stream.resolve(),
                             args.database.resolve(), output, tick_seconds=1.0)
        report["mcp_started"] = True
        listed = client.rpc("tools/list", {})
        definitions = {
            item["name"]: item["inputSchema"]
            for item in listed.get("tools", [])
            if isinstance(item, Mapping) and isinstance(item.get("name"), str)
            and isinstance(item.get("inputSchema"), Mapping)
        }
        required_tools = {"information_manage_subscription", "information_status", "information_tick"}
        if not required_tools.issubset(definitions):
            raise AssertionError(f"mcp_tool_schema_missing:{sorted(required_tools - set(definitions))}")
        delivery_tool = ("information_list_deliveries"
                         if "information_list_deliveries" in definitions
                         else "information_list_results")
        if delivery_tool not in definitions:
            raise AssertionError("mcp_delivery_listing_tool_missing")
        client.set_tool_schemas(definitions)
        report["tool_schema"] = {
            "names": sorted(definitions), "delivery_listing_tool": delivery_tool,
            "discovery_repeated": False, "report_creation_repeated": False,
        }
        report["checks"]["reused_report_and_tool_schema"] = True

        delivery_args = _delivery_arguments(client, delivery_tool)

        subscription_binding = {
            "session_id": installation["session_id"], "observer": "FRA",
            "game_version": GAME_VERSION, "game_sha256": GAME_SHA256,
        }
        config = {
            "name": "managed-battle-corrective",
            "kind": "event", "report_id": report_id, "enabled": True,
            "binding": subscription_binding,
            "event": {"types": ["battle_observation"]},
        }
        subscription = _manage_subscription(
            client, report, namespace, "corrective-create", "create", config=config)
        if subscription.get("state") != "active":
            raise AssertionError(f"corrective_subscription_not_active:{subscription}")
        _status_step(client, report, "after-corrective-create", expected=("enabled", True, 1))
        report["checks"]["corrective_create_enable_owned_one"] = True

        subscription = _manage_subscription(
            client, report, namespace, "corrective-pause", "pause", subscription=subscription)
        _status_step(client, report, "after-corrective-pause", expected=("disabled", False, 0))
        report["checks"]["corrective_pause_disables_owned_capture"] = True

        subscription = _manage_subscription(
            client, report, namespace, "corrective-resume", "resume", subscription=subscription)
        _status_step(
            client, report, "after-corrective-resume-fresh-heartbeat",
            expected=("enabled", True, 1),
        )
        report["checks"]["corrective_resume_fresh_owned_enable_one"] = True

        prewindow_tick = _step(client, report, "prewindow-tick", "information_tick", {})
        prewindow_delivery = _step(
            client, report, "prewindow-deliveries", delivery_tool, delivery_args)
        del prewindow_tick
        baseline_events = _event_results(prewindow_delivery, subscription["id"])
        baseline_keys = _event_keys(baseline_events)
        baseline_result_ids = _result_ids(baseline_events)
        report["prewindow_baseline"] = {
            "delivery_tool": delivery_tool,
            "event_count": len(baseline_events),
            "event_keys": baseline_keys,
            "result_ids": baseline_result_ids,
            "tick_used": True,
        }

        window_args = argparse.Namespace(**vars(args))
        window_args.natural_window_output = natural_output
        _run_natural_window(window_args, installation["path"], output, report)
        natural = report.get("natural_window", {})
        if (not isinstance(natural, Mapping)
                or natural.get("returncode") != 0
                or natural.get("status") != "observed_target_and_paused"):
            raise AssertionError(f"natural_window_not_observed_and_paused:{natural}")
        report["checks"]["natural_window_once_observed_paused"] = True

        # The manager is already enabled.  Give the server's own scheduler a
        # bounded opportunity to ingest and deliver the new event.  No
        # post-window information_tick is sent by this corrective validator.
        time.sleep(2.0)
        first_delivery = _step(
            client, report, "post-window-scheduler-deliveries-1", delivery_tool, delivery_args)
        time.sleep(1.2)
        second_delivery = _step(
            client, report, "post-window-scheduler-deliveries-2", delivery_tool, delivery_args)
        after_events = _event_results(second_delivery, subscription["id"])
        after_keys = _event_keys(after_events)
        after_result_ids = _result_ids(after_events)
        key_counts = Counter(after_keys)
        if any(count > 1 for count in key_counts.values()):
            raise AssertionError(f"corrective_event_dedup_failed:{key_counts}")
        if not set(baseline_keys).issubset(set(after_keys)):
            raise AssertionError("prewindow_baseline_disappeared_after_scheduler")
        new_keys = sorted(set(after_keys) - set(baseline_keys))
        new_result_ids = sorted(set(after_result_ids) - set(baseline_result_ids))
        report["event_observation"] = {
            "delivery_listing_tool": delivery_tool,
            "first_scheduler_event_count": len(_event_results(first_delivery, subscription["id"])),
            "second_scheduler_event_count": len(after_events),
            "baseline_event_keys": baseline_keys,
            "after_event_keys": after_keys,
            "new_event_keys": new_keys,
            "baseline_result_ids": baseline_result_ids,
            "after_result_ids": after_result_ids,
            "new_result_ids": new_result_ids,
            "dedup_checked": True,
            "new_id_difference_checked": True,
            "natural_fra_event_absent": not bool(new_keys),
            "post_window_information_tick_sent": False,
            "scheduler_wait_seconds": [2.0, 1.2],
        }
        report["checks"]["scheduler_delivery_dedup_and_new_id_difference"] = True
        _status_step(client, report, "after-window-scheduler-delivery", expected=("enabled", True, 1))

        subscription = _manage_subscription(
            client, report, namespace, "corrective-cancel", "cancel", subscription=subscription)
        _status_step(client, report, "after-corrective-cancel", expected=("disabled", False, 0))
        listed_subscriptions = _step(
            client, report, "corrective-final-subscription-list",
            "information_manage_subscription", {
                "request_id": f"{namespace}-corrective-final-list", "operation": "list",
            })
        rows = listed_subscriptions.get("subscriptions")
        if not isinstance(rows, list):
            raise AssertionError("corrective_final_subscription_list_shape_missing")
        active = [row for row in rows if isinstance(row, Mapping) and row.get("state") == "active"]
        if active:
            raise AssertionError(f"corrective_active_subscription_after_cancel:{active}")
        report["checks"]["corrective_cancel_no_active_subscriptions"] = True
        return_code = 0
        report["status"] = "passed"
    except AuditFailure as error:
        report["status"] = "audit_failed"
        report["error"] = {"type": type(error).__name__, "message": str(error)}
        return_code = 2
    except Exception as error:
        report["status"] = "failed"
        report["error"] = {"type": type(error).__name__, "message": str(error)}
        return_code = 1
    finally:
        if client is not None:
            if subscription is not None and subscription.get("state") in {"active", "paused"}:
                try:
                    subscription = _manage_subscription(
                        client, report, namespace, "corrective-cleanup-cancel", "cancel",
                        subscription=subscription)
                except Exception as error:
                    report.setdefault("cleanup_errors", []).append({
                        "type": type(error).__name__, "message": str(error),
                    })
            try:
                report["server_exit_code"] = client.close()
            except Exception as error:
                report["cleanup_close_error"] = {
                    "type": type(error).__name__, "message": str(error),
                }
        if report.get("cleanup_errors") or report.get("cleanup_close_error"):
            report["status"] = "failed"
            return_code = 1
        if client is not None and report.get("server_exit_code") != 0:
            report["status"] = "failed"
            return_code = 1
        if report.get("server_exit_code") == 0:
            report.setdefault("checks", {})["server_exit_code_zero"] = True
        _write_json_new(output / "report.json", report)
    print(json.dumps({
        "status": report["status"], "output": str(output),
        "server_exit_code": report.get("server_exit_code"),
        "natural_window": report.get("natural_window", {"status": "not_requested"}),
        "audit": report.get("audit", {}).get("status"),
    }, ensure_ascii=False, sort_keys=True))
    return return_code


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--installation", required=True, type=Path)
    parser.add_argument("--battle-stream", required=True, type=Path)
    parser.add_argument("--database", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--previous-report", type=Path)
    parser.add_argument("--natural-window-output", type=Path)
    parser.add_argument("--test-only", required=True, action="store_true",
                        help="Required: permit exactly one existing natural-window helper invocation")
    parser.add_argument("--expected-manifest-sha256", required=True)
    parser.add_argument("--expected-dll-sha256", required=True)
    parser.add_argument("--expected-date", type=int, default=DEFAULT_EXPECTED_DATE)
    parser.add_argument("--days", type=int, choices=(1, 5, 35), default=DEFAULT_DAYS)
    args = parser.parse_args(argv)
    for name in ("expected_manifest_sha256", "expected_dll_sha256"):
        if HEX64.fullmatch(getattr(args, name)) is None:
            parser.error(f"{name} must be exact lowercase SHA-256")
    try:
        return run(args)
    except (OSError, ValueError, RuntimeError, AcceptanceUnavailable, AssertionError) as error:
        print(json.dumps({"status": "unavailable", "error": str(error)}, ensure_ascii=False))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
