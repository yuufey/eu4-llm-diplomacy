"""Validate one scheduler-driven live battle-capture observation window.

The command is inert until the caller supplies a fresh service database and
explicit ``--test-only`` pins.  It starts one MCP server with the managed
capture lease, lets the background scheduler ingest and deliver the retained
configured zero- or 21-record baseline, invokes the natural-window helper once,
and then observes only scheduler ticks and durable result listings.

This validator never installs a DLL, injects a process, sends diplomacy, or
uses ``information_tick`` to manufacture post-window evidence.  Every request
and successful response is written by the reused stdio client; all validator
JSON artifacts are created with exclusive ``x`` mode.
"""

from __future__ import annotations

import argparse
from collections import Counter
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import sys
import time
from typing import Any, Mapping

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from work.validate_information_battle_capture_management_live import (
    AcceptanceUnavailable,
    GAME_SHA256,
    GAME_VERSION,
    HEX16,
    HEX64,
    MAX_JSON_BYTES,
    StdioClient,
    _capture_snapshot,
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


DEFAULT_EXPECTED_DATE = 56561928
DEFAULT_DAYS = 35
EXPECTED_BASELINE_RECORDS = 21
EXPECTED_VISIBLE_BASELINE_SEQUENCES = (1, 18)
REPORT_SCHEMA = "information_battle_capture_autonomous_live.v1"
AUDIT_SCHEMA = "information_battle_capture_autonomous_live_preflight.v1"
BAD_EVENT_GAP_REASONS = {
    "BATTLE_INGEST_FAILED",
    "BATTLE_EVENT_SOURCE_UNAVAILABLE",
}
REQUIRED_BATTLE_TABLES = {
    "battle_records", "battle_streams", "observed_gaps", "open_gap_ranges",
    "fragment_groups", "complete_messages",
}


def _resolve_configured_path(stream_path: Path, configured: Any) -> Path:
    if not isinstance(configured, str) or not configured:
        raise AcceptanceUnavailable("battle_stream_database_missing")
    path = Path(configured).expanduser()
    return (stream_path.parent / path).resolve() if not path.is_absolute() else path.resolve()


def _same_file(left: Path, right: Path) -> bool:
    if left.resolve(strict=False) == right.resolve(strict=False):
        return True
    if left.exists() and right.exists():
        try:
            return os.path.samefile(left, right)
        except (OSError, ValueError):
            return False
    return False


def _parse_identity(value: Any) -> int | None:
    if type(value) is int and value >= 0:
        return value
    if not isinstance(value, str) or not value:
        return None
    try:
        if value.isdigit():
            return int(value, 10)
        if HEX16.fullmatch(value):
            return int(value, 16)
    except ValueError:
        return None
    return None


def _load_live_inputs(
        installation_path: Path, stream_path: Path, service_database: Path,
) -> tuple[dict[str, Any], dict[str, Any], Path]:
    """Load the operator binding and require a distinct existing stream DB."""

    installation_path = installation_path.resolve(strict=True)
    stream_path = stream_path.resolve(strict=True)
    service_database = service_database.resolve()
    if service_database.exists():
        raise AcceptanceUnavailable("service_database_must_be_new")
    installation = _read_json(installation_path)
    if not isinstance(installation, dict):
        raise AcceptanceUnavailable("installation_not_object")
    session_id = installation.get("session_id")
    if not isinstance(session_id, str) or not session_id:
        raise AcceptanceUnavailable("installation_session_missing")
    if installation.get("game_sha256") != GAME_SHA256:
        raise AcceptanceUnavailable("installation_game_sha_mismatch")
    creation = installation.get("creation_filetime")
    if isinstance(creation, bool) or type(creation) is not int or creation <= 0:
        raise AcceptanceUnavailable("creation_filetime_invalid")

    stream = _read_json(stream_path, limit=256 * 1024)
    if (not isinstance(stream, dict)
            or set(stream) != {"schema", "database", "binding"}
            or stream.get("schema") != "EU4-BATTLE-STREAM/1"):
        raise AcceptanceUnavailable("battle_stream_shape_mismatch")
    battle_database = _resolve_configured_path(stream_path, stream.get("database"))
    if not battle_database.is_file():
        raise AcceptanceUnavailable(f"battle_stream_database_missing:{battle_database}")
    if _same_file(service_database, battle_database):
        raise AcceptanceUnavailable("service_and_battle_database_must_differ")
    binding = stream.get("binding")
    if not isinstance(binding, dict):
        raise AcceptanceUnavailable("battle_stream_binding_missing")
    if binding.get("mode") != "live":
        raise AcceptanceUnavailable("battle_stream_binding_not_live")
    if binding.get("game_sha256") != GAME_SHA256:
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
        "game_sha256": GAME_SHA256,
        "dll_sha256": installation.get("dll_sha256"),
    }, deepcopy(binding), battle_database


def _file_pin(path: Path, *, max_bytes: int = 16 * 1024 * 1024) -> dict[str, Any]:
    path = path.resolve(strict=True)
    before = path.stat()
    if not path.is_file() or before.st_size > max_bytes:
        raise AcceptanceUnavailable(f"artifact_file_invalid_or_oversize:{path}")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
    after = path.stat()
    if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
            after.st_size, after.st_mtime_ns, after.st_ctime_ns):
        raise AcceptanceUnavailable(f"artifact_changed_during_hash:{path}")
    return {"path": str(path), "bytes": after.st_size, "sha256": digest.hexdigest()}


def _validate_artifact_pins(
        installation: Mapping[str, Any], expected_manifest: str,
        expected_dll: str,
) -> dict[str, Any]:
    if HEX64.fullmatch(expected_manifest) is None or HEX64.fullmatch(expected_dll) is None:
        raise AcceptanceUnavailable("expected_manifest_and_dll_must_be_lowercase_sha256")
    directory = Path(str(installation["path"])).parent
    manifest_path = directory / "build-manifest.json"
    manifest = _read_json(manifest_path, limit=256 * 1024)
    if not isinstance(manifest, dict):
        raise AcceptanceUnavailable("build_manifest_not_object")
    version = manifest.get("version")
    if isinstance(version, bool) or type(version) is not int or version <= 0:
        raise AcceptanceUnavailable("build_manifest_version_invalid")
    dll_path = directory / f"eu4_bridge_diplomacy_observer_v{version}.dll"
    manifest_pin = _file_pin(manifest_path)
    dll_pin = _file_pin(dll_path)
    if manifest_pin["sha256"] != expected_manifest:
        raise AcceptanceUnavailable("manifest_sha256_does_not_match_external_pin")
    if dll_pin["sha256"] != expected_dll:
        raise AcceptanceUnavailable("dll_sha256_does_not_match_external_pin")
    if manifest.get("game_sha256") != GAME_SHA256:
        raise AcceptanceUnavailable("manifest_game_sha_mismatch")
    if manifest.get("dll_sha256") != expected_dll:
        raise AcceptanceUnavailable("manifest_dll_sha_mismatch")
    if installation.get("dll_sha256") != expected_dll:
        raise AcceptanceUnavailable("installation_dll_sha_mismatch")
    return {
        "expected_manifest_sha256": expected_manifest,
        "expected_dll_sha256": expected_dll,
        "manifest": manifest_pin,
        "dll": dll_pin,
    }


def _pending_channel_scan(directory: Path,
                          installation: Mapping[str, Any] | None = None
                          ) -> tuple[list[str], dict[str, Any]]:
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
        "diplomacy-execute.req",
        "diplomacy-authority-test.req",
    }
    result: list[str] = []
    for path in directory.iterdir():
        if not path.is_file():
            continue
        lower = path.name.lower()
        if path.name in closed_names:
            continue
        if (lower in exact or lower.endswith((".request", ".processing", ".intent", ".req"))
                or ".request." in lower or ".processing." in lower):
            result.append(path.name)
    return sorted(result), receipts


def _pending_channel_files(directory: Path,
                           installation: Mapping[str, Any] | None = None) -> list[str]:
    return _pending_channel_scan(directory, installation)[0]


def _battle_db_stats(path: Path, binding: Mapping[str, Any]) -> dict[str, Any]:
    """Read the established transport/reassembly statistics in SQLite RO mode."""

    installation = str(binding["installation"])
    generation = str(binding["generation"])
    connection = sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True,
                                 timeout=5.0)
    connection.row_factory = sqlite3.Row
    try:
        connection.execute("PRAGMA query_only=ON")
        tables = {
            row[0] for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type=?", ("table",))
        }
        missing = REQUIRED_BATTLE_TABLES - tables
        if missing:
            raise AcceptanceUnavailable(f"battle_database_tables_missing:{sorted(missing)}")
        records = connection.execute(
            "SELECT COUNT(*) AS n FROM battle_records WHERE installation=? AND world_generation=?",
            (installation, generation)).fetchone()
        stream = connection.execute(
            "SELECT first_sequence,max_sequence,received_count,observed_gap "
            "FROM battle_streams WHERE installation=? AND world_generation=?",
            (installation, generation)).fetchone()
        if stream is None and records is not None and int(records["n"]) == 0 and EXPECTED_BASELINE_RECORDS == 0:
            stream = {"first_sequence": "0", "max_sequence": "0", "received_count": 0, "observed_gap": 0}
        if records is None or stream is None:
            raise AcceptanceUnavailable("battle_stream_identity_row_missing")
        groups = {
            str(row["status"]): int(row["n"])
            for row in connection.execute(
                "SELECT status,COUNT(*) AS n FROM fragment_groups "
                "WHERE installation=? AND world_generation=? GROUP BY status",
                (installation, generation))
        }
        complete_messages = connection.execute(
            "SELECT COUNT(*) FROM complete_messages c JOIN fragment_groups g USING(group_id) "
            "WHERE g.installation=? AND g.world_generation=?",
            (installation, generation)).fetchone()[0]
        observed_gaps = connection.execute(
            "SELECT COUNT(*) FROM observed_gaps WHERE installation=? AND world_generation=?",
            (installation, generation)).fetchone()[0]
        open_gaps = connection.execute(
            "SELECT COUNT(*) FROM open_gap_ranges r JOIN observed_gaps g USING(gap_id) "
            "WHERE g.installation=? AND g.world_generation=?",
            (installation, generation)).fetchone()[0]

        def sequence(value: Any, label: str) -> int:
            if not isinstance(value, str) or not value.isdigit() or (
                    len(value) > 1 and value.startswith("0")):
                raise AcceptanceUnavailable(f"battle_sequence_invalid:{label}")
            return int(value, 10)

        first_sequence = sequence(stream["first_sequence"], "first")
        max_sequence = sequence(stream["max_sequence"], "max")
        return {
            "database": str(path.resolve()),
            "tables": sorted(tables),
            "battle_records_count": int(records["n"]),
            "battle_stream": {
                "first_sequence": first_sequence,
                "max_sequence": max_sequence,
                "received_count": int(stream["received_count"]),
                "observed_gap": int(stream["observed_gap"]),
            },
            "fragment_groups_by_status": groups,
            "complete_groups_count": groups.get("complete", 0),
            "complete_messages_count": int(complete_messages),
            "observed_gaps_count": int(observed_gaps),
            "open_gap_ranges_count": int(open_gaps),
        }
    finally:
        connection.close()


def _service_db_audit(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"database": str(path.resolve()), "exists": False}
    connection = sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True,
                                 timeout=5.0)
    connection.row_factory = sqlite3.Row
    try:
        connection.execute("PRAGMA query_only=ON")
        tables = {
            row[0] for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type=?", ("table",))
        }
        if "info_config" not in tables:
            raise AcceptanceUnavailable("service_database_info_config_missing")
        subscriptions: list[dict[str, Any]] = []
        for row in connection.execute(
                "SELECT id,body FROM info_config WHERE kind=? ORDER BY id", ("subscription",)):
            value = json.loads(row["body"])
            if isinstance(value, dict):
                subscriptions.append({
                    "id": value.get("id"), "name": value.get("name"),
                    "state": value.get("state"), "version": value.get("version"),
                })
        active = [row for row in subscriptions if row.get("state") == "active"]
        result = {
            "database": str(path.resolve()), "exists": True,
            "tables": sorted(tables), "subscriptions": subscriptions,
            "active_subscriptions": active,
        }
        if "info_results" in tables:
            result["result_rows"] = int(connection.execute(
                "SELECT COUNT(*) FROM info_results").fetchone()[0])
        if "info_events" in tables:
            result["event_rows"] = int(connection.execute(
                "SELECT COUNT(*) FROM info_events").fetchone()[0])
        return result
    finally:
        connection.close()


def _native_preflight(
        installation: Mapping[str, Any], binding: Mapping[str, Any],
        battle_database: Path, service_database: Path,
) -> dict[str, Any]:
    """Perform read-only native, channel, and DB checks before MCP starts."""

    failures: list[str] = []
    path = Path(str(installation["path"])).resolve()
    directory = path.parent
    audit: dict[str, Any] = {
        "schema": AUDIT_SCHEMA,
        "status": "running",
        "native_control_issued": False,
        "installation": str(path),
        "service_database": str(service_database.resolve()),
        "battle_database": str(battle_database.resolve()),
    }
    try:
        from tools.control_information_battle_observer import run_control
        observed = run_control(path, "status")
        native = observed.get("native") if isinstance(observed, Mapping) else None
        audit["native_status"] = {
            "status": observed.get("status") if isinstance(observed, Mapping) else None,
            "fresh": observed.get("fresh") if isinstance(observed, Mapping) else None,
            "observed_at_ns": observed.get("observed_at_ns") if isinstance(observed, Mapping) else None,
            "state": native.get("state") if isinstance(native, Mapping) else None,
            "pid": native.get("pid") if isinstance(native, Mapping) else None,
            "creation_filetime": native.get("creation_filetime") if isinstance(native, Mapping) else None,
            "installation": native.get("installation") if isinstance(native, Mapping) else None,
            "generation": native.get("generation") if isinstance(native, Mapping) else None,
            "exe_sha256": native.get("exe_sha256") if isinstance(native, Mapping) else None,
            "dll_sha256": native.get("dll_sha256") if isinstance(native, Mapping) else None,
        }
        identity_ok = (
            isinstance(observed, Mapping) and observed.get("status") == "observed"
            and observed.get("fresh") is True
            and isinstance(observed.get("observed_at_ns"), int)
            and isinstance(native, Mapping) and native.get("state") == "disabled"
            and native.get("pid") == installation.get("pid")
            and _parse_identity(native.get("creation_filetime")) == installation.get("creation_filetime")
            and native.get("exe_sha256") == GAME_SHA256
            and native.get("dll_sha256") == installation.get("dll_sha256")
            and _parse_identity(native.get("installation")) == int(str(binding["installation"]), 16)
            and _parse_identity(native.get("generation")) == int(str(binding["generation"]), 16)
        )
        if not identity_ok:
            failures.append("native_status_not_fresh_disabled_or_identity_mismatch")
    except Exception as error:
        audit["native_status_error"] = {"type": type(error).__name__, "message": str(error)}
        failures.append("native_status_read_failed")

    status_path = directory / "information-battle-status.json"
    journal_path = directory / "information-battle-capture-journal.json"
    try:
        native_file = _read_json(status_path, limit=128 * 1024)
        audit["native_file"] = {
            "path": str(status_path), "state": native_file.get("state"),
            "last_sequence": native_file.get("last_sequence"),
            "captured": native_file.get("captured"),
            "dll_pinned": native_file.get("dll_pinned"),
        }
        if native_file.get("state") != "disabled":
            failures.append("native_status_file_not_disabled")
    except Exception as error:
        audit["native_file_error"] = {"type": type(error).__name__, "message": str(error)}
        failures.append("native_status_file_read_failed")
    try:
        if not journal_path.exists() and EXPECTED_BASELINE_RECORDS == 0:
            # A freshly bootstrapped, disabled installation has no previous
            # manager lease. The manager itself permits this initial state.
            journal = {"initial_lease": True}
        else:
            journal = _read_json(journal_path, limit=128 * 1024)
        identity = journal.get("identity")
        expected_installation = int(str(binding["installation"]), 16)
        expected_generation = int(str(binding["generation"]), 16)
        audit["capture_journal"] = {
            "path": str(journal_path), "schema": journal.get("schema"),
            "state": journal.get("state"), "owned": journal.get("owned"),
            "updated_at_ns": journal.get("updated_at_ns"),
        }
        journal_ok = (
            journal.get("schema") == "eu4-information-battle-capture/1"
            and journal.get("state") == "completed-disabled"
            and journal.get("owned") is False
            and isinstance(identity, Mapping)
            and identity.get("creation_filetime") == installation.get("creation_filetime")
            and identity.get("game_sha256") == GAME_SHA256
            and identity.get("dll_sha256") == installation.get("dll_sha256")
            and identity.get("installation") == expected_installation
            and identity.get("generation") == expected_generation
            and Path(str(identity.get("installation_path"))).resolve() == path
        )
        if journal.get("initial_lease") is True:
            audit["capture_journal"]["state"] = "absent_initial_lease"
            journal_ok = True
        if not journal_ok:
            failures.append("capture_journal_not_completed_disabled_unowned")
    except Exception as error:
        audit["capture_journal_error"] = {"type": type(error).__name__, "message": str(error)}
        failures.append("capture_journal_read_failed")

    try:
        pending, consumed_receipts = _pending_channel_scan(directory, installation)
        audit["pending_channel_files"] = pending
        audit["country_control_consumed_receipts"] = consumed_receipts
        if pending:
            failures.append("pending_control_business_or_advance_channel")
    except Exception as error:
        audit["pending_channel_error"] = {"type": type(error).__name__, "message": str(error)}
        failures.append("pending_channel_scan_failed")

    try:
        stats = _battle_db_stats(battle_database, binding)
        audit["battle_database_before"] = stats
        stream = stats["battle_stream"]
        if not (
                stats["battle_records_count"] == EXPECTED_BASELINE_RECORDS
                and stream["first_sequence"] == (1 if EXPECTED_BASELINE_RECORDS else 0)
                and stream["max_sequence"] == EXPECTED_BASELINE_RECORDS
                and stream["received_count"] == EXPECTED_BASELINE_RECORDS
                and stream["observed_gap"] == 0
                and stats["complete_groups_count"] == EXPECTED_BASELINE_RECORDS
                and stats["complete_messages_count"] == EXPECTED_BASELINE_RECORDS
                and stats["observed_gaps_count"] == 0
                and stats["open_gap_ranges_count"] == 0):
            failures.append(f"battle_database_baseline_not_exactly_{EXPECTED_BASELINE_RECORDS}_complete_records")
    except Exception as error:
        audit["battle_database_error"] = {"type": type(error).__name__, "message": str(error)}
        failures.append("battle_database_read_only_audit_failed")

    audit["service_database_initial"] = _service_db_audit(service_database)
    if audit["service_database_initial"].get("exists"):
        failures.append("service_database_was_not_new")
    audit["failures"] = failures
    audit["status"] = "passed" if not failures else "failed"
    return audit


def _event_source_issues(status: Mapping[str, Any]) -> list[dict[str, Any]]:
    source = status.get("event_source")
    if not isinstance(source, Mapping):
        return [{"reason": "event_source_missing"}]
    issues: list[dict[str, Any]] = []
    if not source.get("last_attempt"):
        issues.append({"reason": "event_source_attempt_missing"})
    if source.get("error") is not None:
        issues.append({"reason": "event_source_error", "error": deepcopy(source.get("error"))})
    if source.get("last_ingest_error") is not None:
        issues.append({"reason": "last_ingest_error", "error": deepcopy(source.get("last_ingest_error"))})
    gaps = source.get("gaps", [])
    if isinstance(gaps, list):
        for gap in gaps:
            if not isinstance(gap, Mapping):
                continue
            reason = gap.get("reason")
            reason_upper = reason.upper() if isinstance(reason, str) else ""
            if (reason in BAD_EVENT_GAP_REASONS
                    or any(token in reason_upper for token in ("ERROR", "FAILED", "UNAVAILABLE"))):
                issues.append(deepcopy(dict(gap)))
    elif gaps is not None:
        issues.append({"reason": "event_source_gaps_malformed"})
    return issues


def _event_sequence(event_id: Any) -> int:
    if not isinstance(event_id, str):
        raise AssertionError("event_id_must_be_string")
    suffix = event_id.rsplit(":", 1)[-1]
    if not suffix.isdigit() or (len(suffix) > 1 and suffix.startswith("0")):
        raise AssertionError(f"event_id_sequence_unavailable:{event_id}")
    return int(suffix, 10)


def _event_keys(results: list[dict[str, Any]]) -> list[tuple[str, str]]:
    keys: list[tuple[str, str]] = []
    for item in results:
        event = item.get("event")
        event_id = event.get("event_id") if isinstance(event, Mapping) else None
        subscription_id = item.get("subscription_id")
        if not isinstance(subscription_id, str) or not isinstance(event_id, str):
            raise AssertionError("event_result_identity_missing")
        keys.append((subscription_id, event_id))
    return keys


def _result_sample(item: Mapping[str, Any]) -> dict[str, Any]:
    status = item.get("status")
    if status not in ("partial", "complete"):
        raise AssertionError(f"event_result_status_invalid:{status}")
    event = item.get("event")
    if not isinstance(event, Mapping) or not isinstance(event.get("event_id"), str):
        raise AssertionError("event_result_event_missing")
    entries = item.get("items")
    if not isinstance(entries, list) or not entries:
        raise AssertionError("event_result_items_empty")
    fields_summary: list[dict[str, Any]] = []
    has_known = False
    for entry in entries:
        if not isinstance(entry, Mapping):
            raise AssertionError("event_result_item_not_object")
        fields = entry.get("fields")
        if not isinstance(fields, Mapping) or not fields:
            raise AssertionError("event_result_fields_empty")
        item_fields: dict[str, Any] = {}
        for name, field in fields.items():
            if not isinstance(field, Mapping) or not isinstance(field.get("status"), str):
                raise AssertionError(f"event_result_field_contract_invalid:{name}")
            field_status = field["status"]
            has_known |= field_status in {"known", "not_applicable"}
            item_fields[str(name)] = {
                "status": field_status,
                "has_value": "value" in field,
            }
        fields_summary.append(item_fields)
    if not has_known:
        raise AssertionError("event_result_has_no_known_or_not_applicable_field")
    delivery = item.get("delivery")
    if not isinstance(delivery, Mapping) or delivery.get("status") != "delivered":
        raise AssertionError(f"event_result_delivery_not_persisted:{delivery}")
    return {
        "result_id": item.get("result_id"),
        "event_id": event.get("event_id"),
        "status": status,
        "complete": item.get("complete"),
        "delivery": {"status": delivery.get("status"), "adapter": delivery.get("adapter")},
        "fields": fields_summary,
    }


def _visible_event_summary(value: Mapping[str, Any], subscription_id: str) -> dict[str, Any]:
    events = _event_results(value, subscription_id)
    keys = _event_keys(events)
    counts = Counter(keys)
    if any(count > 1 for count in counts.values()):
        raise AssertionError(f"duplicate_visible_event_results:{counts}")
    return {
        "count": len(events),
        "keys": [[subscription, event_id] for subscription, event_id in keys],
        "result_ids": [item.get("result_id") for item in events],
        "event_ids": [key[1] for key in keys],
    }


def _service_result_snapshot(value: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "result_id": value.get("result_id"),
        "status": value.get("status"),
        "complete": value.get("complete"),
        "delivery": deepcopy(value.get("delivery")),
    }


def _all_result_ids(value: Mapping[str, Any]) -> list[str]:
    rows = value.get("results")
    if not isinstance(rows, list):
        raise AssertionError("delivery_listing_results_missing")
    ids: list[str] = []
    for row in rows:
        if not isinstance(row, Mapping) or not isinstance(row.get("result_id"), str):
            raise AssertionError("delivery_listing_result_id_missing")
        ids.append(row["result_id"])
    if len(ids) != len(set(ids)):
        raise AssertionError("delivery_listing_result_ids_duplicate")
    return ids


def _wait_for_baseline(
        client: StdioClient, report: dict[str, Any], delivery_tool: str,
        subscription_id: str, binding: Mapping[str, Any], battle_database: Path,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    delivery_args = _delivery_arguments(client, delivery_tool)
    latest: dict[str, Any] | None = None
    latest_stats: dict[str, Any] | None = None
    attempts: list[dict[str, Any]] = []
    for index in range(5):
        time.sleep(2.2 if index == 0 else 1.2)
        latest = _step(client, report, f"pre-window-list-{index + 1}", delivery_tool,
                       delivery_args)
        latest_stats = _battle_db_stats(battle_database, binding)
        events = _event_results(latest, subscription_id)
        attempts.append({
            "attempt": index + 1,
            "event_count": len(events),
            "unique_event_ids": len({item.get("event", {}).get("event_id") for item in events}),
            "battle_records_count": latest_stats["battle_records_count"],
        })
        # The raw store has 21 battles, but the observer directly participated
        # in only sequences 1 and 18 (batch63's retained live003 receipt).
        if len(events) == len(EXPECTED_VISIBLE_BASELINE_SEQUENCES):
            break
    if latest is None or latest_stats is None:
        raise AssertionError("pre_window_scheduler_listing_missing")
    events = _event_results(latest, subscription_id)
    keys = _event_keys(events)
    ids = [key[1] for key in keys]
    if len(ids) != len(EXPECTED_VISIBLE_BASELINE_SEQUENCES) or len(set(ids)) != len(EXPECTED_VISIBLE_BASELINE_SEQUENCES):
        raise AssertionError(f"pre_window_baseline_event_count:{len(ids)}")
    if sorted(_event_sequence(event_id) for event_id in ids) != list(EXPECTED_VISIBLE_BASELINE_SEQUENCES):
        raise AssertionError("pre_window_visible_baseline_sequences_differ")
    if latest_stats["battle_records_count"] != EXPECTED_BASELINE_RECORDS:
        raise AssertionError("pre_window_ingest_raw_count_differs")
    if latest_stats["battle_stream"]["max_sequence"] != EXPECTED_BASELINE_RECORDS:
        raise AssertionError("pre_window_ingest_max_sequence_differs")
    samples = [_result_sample(item) for item in events]
    baseline = {
        "scheduler_wait_and_list_attempts": attempts,
        "event_ids": ids,
        "result_ids": [item.get("result_id") for item in events],
        "sample_count": len(samples),
        "sample_statuses": dict(Counter(sample["status"] for sample in samples)),
    }
    return latest, latest_stats, baseline


def _wait_for_post_window(
        client: StdioClient, report: dict[str, Any], delivery_tool: str,
        subscription_id: str, baseline_ids: set[str], baseline_stats: Mapping[str, Any],
        binding: Mapping[str, Any], battle_database: Path,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    delivery_args = _delivery_arguments(client, delivery_tool)
    first: dict[str, Any] | None = None
    first_stats: dict[str, Any] | None = None
    attempts: list[dict[str, Any]] = []
    for index in range(8):
        time.sleep(1.2)
        value = _step(client, report, f"post-window-list-{index + 1}", delivery_tool,
                      delivery_args)
        stats = _battle_db_stats(battle_database, binding)
        events = _event_results(value, subscription_id)
        event_ids = [item.get("event", {}).get("event_id") for item in events]
        new_ids = [event_id for event_id in event_ids
                   if isinstance(event_id, str) and event_id not in baseline_ids]
        attempts.append({
            "attempt": index + 1,
            "event_count": len(events),
            "new_event_count": len(new_ids),
            "battle_records_count": stats["battle_records_count"],
            "max_sequence": stats["battle_stream"]["max_sequence"],
        })
        if new_ids:
            first, first_stats = value, stats
            break
    if first is None or first_stats is None:
        if not attempts:
            raise AssertionError("post_window_scheduler_listing_missing")
        # Preserve the bounded no-event observation for the final report; the
        # caller will fail explicitly rather than treating it as a pass.
        first = value
        first_stats = stats
    time.sleep(1.2)
    second = _step(client, report, "post-window-list-stability", delivery_tool,
                   delivery_args)
    second_stats = _battle_db_stats(battle_database, binding)
    first_events = _event_results(first, subscription_id)
    second_events = _event_results(second, subscription_id)
    first_ids = set(_all_result_ids(first))
    second_ids = set(_all_result_ids(second))
    if first_ids != second_ids:
        raise AssertionError("scheduled_result_id_set_changed_on_stability_list")
    if len(second_ids) != len(second_events):
        raise AssertionError("scheduled_result_ids_duplicate")
    visible = _visible_event_summary(second, subscription_id)
    new_ids = sorted(set(visible["event_ids"]) - baseline_ids)
    if not new_ids:
        report["post_window_without_positive"] = {"attempts": attempts, "database": second_stats,
                                                    "visible": visible}
        raise AcceptanceUnavailable("natural_fra_event_absent_no_vacuous_pass")
    new_sequences = sorted(_event_sequence(event_id) for event_id in new_ids)
    if any(sequence <= EXPECTED_BASELINE_RECORDS for sequence in new_sequences):
        raise AssertionError(f"new_event_sequence_not_above_baseline:{new_sequences}")
    samples = []
    for item in second_events:
        event_id = item.get("event", {}).get("event_id") if isinstance(item.get("event"), Mapping) else None
        if event_id in new_ids:
            samples.append(_result_sample(item))
    if not samples:
        raise AssertionError("new_event_samples_missing")
    if (second_stats["battle_records_count"] <= baseline_stats["battle_records_count"]
            or second_stats["complete_messages_count"] <= baseline_stats["complete_messages_count"]
            or second_stats["battle_stream"]["max_sequence"] <= EXPECTED_BASELINE_RECORDS):
        raise AssertionError("post_window_battle_database_raw_count_did_not_increase")
    post = {
        "scheduler_only_attempts": attempts,
        "first_listing": _visible_event_summary(first, subscription_id),
        "stable_listing": visible,
        "new_event_ids": new_ids,
        "new_event_sequences": new_sequences,
        "new_samples": samples,
        "result_id_set_stable": True,
        "dedup_checked": True,
    }
    return first, first_stats, second, {"stats": second_stats, "summary": post}


def run(args: argparse.Namespace) -> int:
    if not args.test_only:
        raise AssertionError("--test-only is mandatory")
    output = args.output.resolve()
    natural_output = args.natural_window_output.resolve()
    if output.exists():
        raise AssertionError(f"refusing_to_overwrite_output:{output}")
    if natural_output.exists():
        raise AssertionError(f"natural_window_output_exists:{natural_output}")
    runtime_root = (ROOT / "work/runtime").resolve()
    for label, path in (("output", output), ("natural_window_output", natural_output)):
        try:
            path.relative_to(runtime_root)
        except ValueError as error:
            raise AcceptanceUnavailable(f"{label}_must_be_under_work_runtime") from error
    output.mkdir(parents=True, exist_ok=False)
    report: dict[str, Any] = {
        "schema": REPORT_SCHEMA,
        "status": "running",
        "mode": "live_autonomous_scheduler",
        "mcp_started": False,
        "inputs": {
            "installation": str(args.installation),
            "battle_stream": str(args.battle_stream),
            "database": str(args.database),
            "database_role": "independent service reports/subscriptions/outbox DB",
            "natural_window_output": str(natural_output),
            "output": str(output),
            "test_only": True,
            "expected_manifest_sha256": args.expected_manifest_sha256,
            "expected_dll_sha256": args.expected_dll_sha256,
            "expected_date": args.expected_date,
            "expected_physical_player_tag": args.expected_player_tag,
            "days": args.days,
            "scheduler_tick_seconds": 1.0,
        },
        "checks": {}, "steps": [], "lifecycle": [],
        "limitations": [
            "The service and battle-stream databases are intentionally different files.",
            "Post-window ingestion and delivery are observed only through the 1-second scheduler and list calls; no information_tick is sent.",
            "The natural-window helper is invoked at most once and only with explicit --test-only.",
            "If FRA has no new visible event, the report records that absence and fails without retrying the window.",
        ],
    }
    client: StdioClient | None = None
    subscription: dict[str, Any] | None = None
    subscription_cancel_unknown = False
    namespace = _request_namespace(output)
    installation: dict[str, Any] | None = None
    binding: dict[str, Any] | None = None
    battle_database: Path | None = None
    try:
        installation, binding, battle_database = _load_live_inputs(
            args.installation, args.battle_stream, args.database)
        report["identity"] = {
            key: installation.get(key)
            for key in ("pid", "creation_filetime", "session_id", "game_sha256", "dll_sha256")
        }
        report["binding"] = {
            key: binding.get(key)
            for key in ("installation", "generation", "observer_ref", "session_id",
                        "process_creation_filetime", "mode")
        }
        report["database_paths"] = {
            "service_database": str(args.database.resolve()),
            "battle_stream_database": str(battle_database),
            "distinct": True,
        }
        report["artifact_pins"] = _validate_artifact_pins(
            installation, args.expected_manifest_sha256, args.expected_dll_sha256)
        audit = _native_preflight(installation, binding, battle_database, args.database.resolve())
        report["preflight"] = audit
        _write_json_new(output / "preflight-audit.json", audit)
        if audit.get("status") != "passed":
            raise AcceptanceUnavailable("preflight_failed:" + ";".join(audit.get("failures", [])))
        report["checks"]["read_only_preflight_passed"] = True
        report["checks"]["service_and_battle_databases_distinct"] = True

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
        required = {
            "information_discover", "information_manage_report",
            "information_manage_subscription", "information_status",
            "information_get_result",
        }
        if not required.issubset(definitions):
            raise AssertionError(f"mcp_tool_schema_missing:{sorted(required - set(definitions))}")
        delivery_tool = "information_list_deliveries" if "information_list_deliveries" in definitions else "information_list_results"
        if delivery_tool not in definitions:
            raise AssertionError("mcp_delivery_listing_tool_missing")
        client.set_tool_schemas(definitions)
        report["tool_schema"] = {
            "names": sorted(definitions),
            "delivery_listing_tool": delivery_tool,
            "required_present": sorted(required),
            "information_get_result_properties": sorted(
                definitions["information_get_result"].get("properties", {})),
        }

        discovery = _step(client, report, "discover", "information_discover", {})
        b04 = next((item for item in discovery.get("topics", [])
                    if isinstance(item, Mapping) and item.get("topic_id") == "B04"), None)
        if not isinstance(b04, Mapping) or not isinstance(b04.get("fields"), Mapping):
            raise AssertionError("B04_discovery_missing")
        fields_meta = b04["fields"]
        if any(field not in fields_meta for field in ("details", "raw_text")):
            raise AssertionError("B04_details_or_raw_text_missing")
        if "event" not in b04.get("triggers", []):
            raise AssertionError("B04_event_trigger_missing")
        query = {"topic": "B04", "object": {"type": "battle"},
                 "fields": ["details", "raw_text"]}
        if "parameters" in query or "event_id" in query:
            raise AssertionError("B04_event_selector_was_set")
        report["checks"]["B04_details_raw_text_event_without_selector"] = True
        report_config = _step(client, report, "report-create", "information_manage_report", {
            "request_id": f"{namespace}-report-create", "operation": "create",
            "config": {"name": "autonomous live battle B04", "detail": "raw", "queries": [query]},
        })
        report_value = report_config.get("report")
        if not isinstance(report_value, Mapping) or not isinstance(report_value.get("id"), str):
            raise AssertionError("report_id_missing")
        report["report_id"] = report_value["id"]
        subscription_binding = {
            "session_id": installation["session_id"], "observer": "FRA",
            "game_version": GAME_VERSION, "game_sha256": GAME_SHA256,
        }
        subscription = _manage_subscription(
            client, report, namespace, "subscription-create", "create", config={
                "name": "autonomous managed battle capture",
                "kind": "event", "report_id": report_value["id"], "enabled": True,
                "binding": subscription_binding,
                "event": {"types": ["battle_observation"]},
            })
        if subscription.get("state") != "active":
            raise AssertionError(f"subscription_not_active:{subscription}")
        report["checks"]["one_event_subscription_created"] = True
        _status_step(client, report, "after-subscription-create", expected=("enabled", True, 1))
        report["checks"]["manager_owned_enabled_one"] = True

        baseline_value, baseline_stats, baseline = _wait_for_baseline(
            client, report, delivery_tool, subscription["id"], binding, battle_database)
        report["pre_window"] = {
            "database": baseline_stats,
            "delivery": _visible_event_summary(baseline_value, subscription["id"]),
            "baseline": baseline,
        }
        status_before = _status_step(client, report, "pre-window-status",
                                     expected=("enabled", True, 1))
        pre_context = status_before.get("context")
        if (not isinstance(pre_context, Mapping)
                or pre_context.get("game_date_raw", pre_context.get("game_date")) != args.expected_date):
            raise AcceptanceUnavailable("pre_window_game_date_does_not_match_expected_date")
        status_issues = _event_source_issues(status_before)
        report["pre_window"]["event_source"] = deepcopy(status_before.get("event_source"))
        report["pre_window"]["event_source_issues"] = status_issues
        if status_issues:
            raise AcceptanceUnavailable("pre_window_event_source_error")
        report["checks"]["pre_window_scheduler_delivered_visible_baseline_no_ingest_error"] = True

        _run_natural_window(args, installation["path"], output, report)
        if report.get("natural_window", {}).get("status") != "observed_target_and_paused":
            raise AcceptanceUnavailable("natural_window_not_observed_target_and_paused_no_retry")

        first_post, first_post_stats, second_post, post_data = _wait_for_post_window(
            client, report, delivery_tool, subscription["id"],
            set(baseline["event_ids"]), baseline_stats, binding, battle_database)
        post_summary = post_data["summary"]
        report["post_window"] = {
            "first_database": first_post_stats,
            "stable_database": post_data["stats"],
            "first_delivery": post_summary["first_listing"],
            "stable_delivery": post_summary["stable_listing"],
            "scheduler_only_attempts": post_summary["scheduler_only_attempts"],
            "new_event_ids": post_summary["new_event_ids"],
            "new_event_sequences": post_summary["new_event_sequences"],
            "new_samples": post_summary["new_samples"],
            "result_id_set_stable": post_summary["result_id_set_stable"],
            "dedup_checked": post_summary["dedup_checked"],
        }
        status_after = _status_step(client, report, "post-window-status",
                                    expected=("enabled", True, 1))
        post_context = status_after.get("context")
        expected_target = args.expected_date + args.days * 24
        if (not isinstance(post_context, Mapping)
                or post_context.get("game_date_raw", post_context.get("game_date")) != expected_target):
            raise AcceptanceUnavailable("post_window_game_date_does_not_match_expected_target")
        post_issues = _event_source_issues(status_after)
        report["post_window"]["event_source"] = deepcopy(status_after.get("event_source"))
        report["post_window"]["event_source_issues"] = post_issues
        if post_issues:
            raise AcceptanceUnavailable("post_window_event_source_error")
        final_stats = post_data["stats"]
        if (final_stats["observed_gaps_count"] != baseline_stats["observed_gaps_count"]
                or final_stats["open_gap_ranges_count"] != 0
                or final_stats["battle_stream"]["observed_gap"] != 0):
            raise AssertionError("post_window_ingest_gap_observed")
        report["checks"].update({
            "natural_fra_event_positive": True,
            "new_event_ids_above_baseline": True,
            "raw_and_complete_message_counts_increased": True,
            "post_window_ingest_error_gaps_clear": True,
            "post_window_sample_status_and_fields_checked": True,
            "durable_delivery_result_persisted": True,
            "scheduled_list_dedup_and_result_id_stability": True,
        })

        sample_id = post_summary["new_samples"][0].get("result_id")
        if not isinstance(sample_id, str):
            raise AssertionError("new_sample_result_id_missing")
        durable = _step(client, report, "get-durable-sample-result",
                        "information_get_result", {"result_id": sample_id})
        if durable.get("result_id") != sample_id or durable.get("delivery", {}).get("status") != "delivered":
            raise AssertionError("durable_sample_result_mismatch")
        report["post_window"]["durable_sample_result"] = _service_result_snapshot(durable)

        try:
            subscription = _manage_subscription(
                client, report, namespace, "subscription-cancel", "cancel",
                subscription=subscription)
        except Exception:
            # The cancel request's outcome is unknown.  Do not issue the same
            # state-changing request again from finally; cleanup only retries
            # a known active subscription whose cancel was never attempted.
            subscription_cancel_unknown = True
            raise
        _status_step(client, report, "after-subscription-cancel",
                     expected=("disabled", False, 0))
        listed_subscriptions = _step(client, report, "subscription-list-after-cancel",
                                      "information_manage_subscription", {
                                          "request_id": f"{namespace}-subscription-list",
                                          "operation": "list",
                                      })
        rows = listed_subscriptions.get("subscriptions")
        if not isinstance(rows, list):
            raise AssertionError("subscription_list_shape_missing")
        active_rows = [row for row in rows if isinstance(row, Mapping)
                       and row.get("state") == "active"]
        if active_rows:
            raise AssertionError(f"active_subscription_after_cancel:{active_rows}")
        report["checks"]["cancel_no_active_subscriptions_manager_disabled"] = True
        report["status"] = "passed"
    except Exception as error:
        report["status"] = "failed"
        report["error"] = {"type": type(error).__name__, "message": str(error)}
    finally:
        if client is not None:
            if (not subscription_cancel_unknown and subscription is not None
                    and subscription.get("state") == "active"):
                try:
                    subscription = _manage_subscription(
                        client, report, namespace, "cleanup-subscription-cancel", "cancel",
                        subscription=subscription)
                except Exception as error:
                    subscription_cancel_unknown = True
                    report.setdefault("cleanup_errors", []).append({
                        "type": type(error).__name__, "message": str(error),
                        "action": "cancel_known_active_subscription_once",
                    })
            try:
                if not subscription_cancel_unknown:
                    final = _status_step(client, report, "final-status-before-server-close")
                    capture = final.get("capture")
                    if not (isinstance(capture, Mapping)
                            and capture.get("producer_state") == "disabled"
                            and capture.get("owned") is False
                            and capture.get("consumer_count") == 0):
                        report.setdefault("cleanup_errors", []).append({
                            "type": "AssertionError",
                            "message": "manager_not_disabled_before_server_close",
                        })
                    else:
                        report.setdefault("checks", {})["final_manager_disabled_zero_consumers"] = True
            except Exception as error:
                report.setdefault("cleanup_errors", []).append({
                    "type": type(error).__name__, "message": str(error), "action": "final_status",
                })
            try:
                report["server_exit_code"] = client.close()
            except Exception as error:
                report["cleanup_close_error"] = {"type": type(error).__name__, "message": str(error)}
                report["status"] = "failed"
        if args.database.resolve().exists():
            try:
                report["service_database_final"] = _service_db_audit(args.database.resolve())
                if report["service_database_final"].get("active_subscriptions"):
                    report.setdefault("cleanup_errors", []).append({
                        "type": "AssertionError", "message": "service_database_active_subscription_remains",
                    })
                else:
                    report.setdefault("checks", {})["service_database_no_active_subscriptions"] = True
            except Exception as error:
                report["service_database_final_error"] = {
                    "type": type(error).__name__, "message": str(error),
                }
        if report.get("cleanup_errors") or report.get("server_exit_code") != 0:
            report["status"] = "failed"
        if report.get("server_exit_code") == 0:
            report.setdefault("checks", {})["server_exit_code_zero"] = True
        _write_json_new(output / "report.json", report)
    print(json.dumps({
        "status": report["status"], "output": str(output),
        "server_exit_code": report.get("server_exit_code"),
        "natural_window": report.get("natural_window", {"status": "not_requested"}),
        "new_event_ids": report.get("post_window", {}).get("new_event_ids", []),
    }, ensure_ascii=False, sort_keys=True))
    return 0 if report["status"] == "passed" else 1


def main(argv: list[str] | None = None) -> int:
    global EXPECTED_BASELINE_RECORDS, EXPECTED_VISIBLE_BASELINE_SEQUENCES
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--installation", required=True, type=Path)
    parser.add_argument("--battle-stream", required=True, type=Path)
    parser.add_argument("--database", required=True, type=Path,
                        help="Fresh service database; it must differ from battle-stream.database")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--natural-window-output", required=True, type=Path)
    parser.add_argument("--expected-manifest-sha256", required=True)
    parser.add_argument("--expected-dll-sha256", required=True)
    parser.add_argument("--expected-date", type=int, default=DEFAULT_EXPECTED_DATE)
    parser.add_argument("--expected-player-tag", choices=("POR", "FRA"), default="POR",
                        help="Expected physical player tag; the service observer remains FRA")
    parser.add_argument("--days", type=int, default=DEFAULT_DAYS)
    parser.add_argument("--baseline-raw-count", type=int, choices=(0, 21), default=21)
    parser.add_argument("--test-only", action="store_true", required=True,
                        help="Required once-only natural observation window")
    args = parser.parse_args(argv)
    EXPECTED_BASELINE_RECORDS = args.baseline_raw_count
    EXPECTED_VISIBLE_BASELINE_SEQUENCES = () if args.baseline_raw_count == 0 else (1, 18)
    if args.days <= 0:
        parser.error("--days must be positive")
    try:
        return run(args)
    except (OSError, ValueError, RuntimeError, AcceptanceUnavailable, AssertionError) as error:
        print(json.dumps({"status": "unavailable", "error": str(error)}, ensure_ascii=False))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
