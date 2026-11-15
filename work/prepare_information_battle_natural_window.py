"""Prepare a bounded, observation-only natural-date window.

This file is deliberately a file and source audit.  It never opens a game
process, reads process memory, publishes a control request, or responds to a
pending diplomacy item.  The resulting report gives the operator the exact
TEST_ONLY wire strings and the terminal evidence required before a date
window can be considered observed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from work.probe_information_battle_installed import (  # noqa: E402
    classify_country_control_consumed_receipts,
)
DEFAULT_LIVE_DIR = (
    ROOT / "work/runtime/diplomacy-observer-20261025-information-battle-live-001"
)
# The first run intentionally remains at the historical mistaken location.
# New runs use the v22/v23 live-preparation stage and refuse replacement.
DEFAULT_OUTPUT = (
    ROOT / "work/runtime/information-battle-live-20261025-001"
    / "natural-window-preparation-001.json"
)
EXPECTED_EXE_SHA256 = (
    "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
)
EXPECTED_DLL_SHA256 = (
    "eaf53986e159bfca7af717228a7bc983a8df03fec32a23eb4a82e5ca503133c3"
)
EXPECTED_DATE_RAW = 56553384
EXPECTED_PLAYER_TAG = "POR"
EXPECTED_PLAYER_SLOT = 189
MAX_SOURCE_BYTES = 16 * 1024 * 1024
MAX_METADATA_BYTES = 1 * 1024 * 1024
MAX_CONTROL_LOG_BYTES = 8 * 1024 * 1024
MAX_CONTROL_LINE_BYTES = 64 * 1024


class PreparationError(RuntimeError):
    """A bounded, reportable preparation failure."""


def _relative(path: Path) -> str:
    try:
        return path.resolve().relative_to(ROOT).as_posix()
    except ValueError:
        return str(path.resolve())


def _inside_workspace(path: Path) -> Path:
    resolved = path.expanduser().resolve()
    try:
        resolved.relative_to(ROOT)
    except ValueError as error:
        raise PreparationError(f"path_outside_workspace:{resolved}") from error
    return resolved


def _bounded_size(path: Path, maximum: int) -> int:
    try:
        size = path.stat().st_size
    except OSError as error:
        raise PreparationError(f"stat_failed:{path}:{error}") from error
    if size > maximum:
        raise PreparationError(f"file_exceeds_bound:{path}:{size}>{maximum}")
    return size


def _sha256(path: Path, maximum: int = MAX_SOURCE_BYTES) -> str:
    _bounded_size(path, maximum)
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while True:
            block = stream.read(1024 * 1024)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def _read_json(path: Path) -> dict[str, Any]:
    _bounded_size(path, MAX_METADATA_BYTES)
    try:
        with path.open("r", encoding="utf-8") as stream:
            value = json.load(stream)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PreparationError(f"json_read_failed:{path}:{error}") from error
    if not isinstance(value, dict):
        raise PreparationError(f"json_object_required:{path}")
    return value


def _read_text(path: Path, maximum: int = MAX_SOURCE_BYTES) -> str:
    _bounded_size(path, maximum)
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as error:
        raise PreparationError(f"text_read_failed:{path}:{error}") from error


def _line_numbers(text: str, needles: Iterable[str]) -> dict[str, int | None]:
    lines = text.splitlines()
    return {
        needle: next(
            (index for index, line in enumerate(lines, start=1) if needle in line),
            None,
        )
        for needle in needles
    }


def _source_record(relative: str, needles: Iterable[str]) -> dict[str, Any]:
    path = _inside_workspace(ROOT / relative)
    text = _read_text(path)
    numbers = _line_numbers(text, needles)
    return {
        "path": _relative(path),
        "size": path.stat().st_size,
        "sha256": _sha256(path),
        "line_refs": numbers,
        "all_requested_markers_found": all(value is not None for value in numbers.values()),
    }


def _select(value: dict[str, Any], keys: Iterable[str]) -> dict[str, Any]:
    return {key: value[key] for key in keys if key in value}


def _parse_raw_header(text: str) -> dict[str, Any]:
    match = re.fullmatch(
        r"EU4_OWNED_BATTLE_WIRE_V1 ([0-9a-f]{16}) ([0-9a-f]{16})\n",
        text,
    )
    if not match:
        return {"valid": False, "raw": text}
    return {
        "valid": True,
        "magic": "EU4_OWNED_BATTLE_WIRE_V1",
        "installation_hex": match.group(1),
        "generation_hex": match.group(2),
        "raw": text,
    }


def _scan_control_log(path: Path) -> dict[str, Any]:
    size = _bounded_size(path, MAX_CONTROL_LOG_BYTES)
    counts: dict[str, int] = {}
    pending: list[dict[str, Any]] = []
    authority: list[dict[str, Any]] = []
    malformed = 0
    line_count = 0
    with path.open("rb") as stream:
        for raw in stream:
            line_count += 1
            if len(raw) > MAX_CONTROL_LINE_BYTES:
                raise PreparationError(f"control_line_exceeds_bound:{path}:{line_count}")
            try:
                value = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                malformed += 1
                continue
            if not isinstance(value, dict):
                malformed += 1
                continue
            event = value.get("event")
            if isinstance(event, str):
                counts[event] = counts.get(event, 0) + 1
            if event == "native_diplomacy_inbound_pending_restored":
                pending.append(
                    _select(
                        value,
                        (
                            "event",
                            "proposal_id",
                            "action_id",
                            "family",
                            "actor",
                            "recipient",
                            "decision_country",
                            "date_raw",
                            "state34",
                            "business_result",
                            "saved_queue_restored",
                            "native_queue_membership_verified",
                            "call_redirected",
                        ),
                    )
                )
            elif event == "native_diplomacy_saved_pending_scan_complete":
                pending.append(
                    _select(
                        value,
                        (
                            "event",
                            "date_raw",
                            "decision_country",
                            "native_queue_count",
                            "restored_count",
                            "native_queue_unchanged",
                        ),
                    )
                )
            elif event in {
                "alliance_execution_handler_installed",
                "diplomacy_observer_installed",
            }:
                authority.append(
                    _select(
                        value,
                        (
                            "event",
                            "version",
                            "pid",
                            "session_id",
                            "authority_lock_enabled",
                            "incoming_offer",
                            "incoming_mode",
                            "authority_scope",
                            "native_execution_enabled",
                            "native_offer_submission",
                        ),
                    )
                )
    return {
        "path": _relative(path),
        "size": size,
        "sha256": _sha256(path, MAX_CONTROL_LOG_BYTES),
        "line_count": line_count,
        "malformed_lines": malformed,
        "event_counts": dict(sorted(counts.items())),
        "pending_events": pending,
        "authority_events": authority,
    }


def _runtime_channel_scan(live_dir: Path,
                          installation: dict[str, Any] | None = None) -> dict[str, Any]:
    names = sorted(item.name for item in live_dir.iterdir())
    lower = {name: name.lower() for name in names}
    receipts = (
        classify_country_control_consumed_receipts(live_dir, installation)
        if isinstance(installation, dict)
        else {"status": "identity_unavailable", "closed": [], "unverified": [],
              "native_calls": 0, "game_access": False}
    )
    closed_names = {item.get("name") for item in receipts.get("closed", [])
                    if isinstance(item, dict)}
    request_names = [
        name
        for name in names
        if name not in closed_names
        and (lower[name].endswith((".request", ".processing"))
             or ".request." in lower[name] or ".processing." in lower[name])
    ]
    business_names = [
        name
        for name in names
        if any(token in lower[name] for token in ("business", "journal", "dispatch"))
        and not lower[name].endswith((".h", ".inc", ".cpp", ".s"))
    ]
    test_request_names = [
        name
        for name in request_names
        if any(token in lower[name] for token in ("test", "diplomacy", "execute", "pending"))
    ]
    source_copy_count = sum(
        lower[name].endswith((".h", ".inc", ".cpp", ".s")) for name in names
    )
    observer_artifacts = [
        name
        for name in names
        if lower[name].startswith(
            (
                "control-probe",
                "information-battle-",
                "installation",
                "loader-output",
                "ready-attempt-",
            )
        )
    ]
    return {
        "top_level_file_count": len(names),
        "request_or_processing_files": request_names,
        "country_control_consumed_receipts": receipts,
        "test_or_business_request_files": test_request_names,
        "business_journal_candidates": business_names,
        "observer_artifact_files": observer_artifacts,
        "source_copy_file_count_excluded_from_runtime_scan": source_copy_count,
        "source_copy_files_are_not_runtime_channels": True,
        "no_natural_control_request_present": "game-control.request" not in names,
        "no_information_control_request_present": "information-battle-control.request" not in names,
    }


def _live_evidence(live_dir: Path) -> dict[str, Any]:
    if not live_dir.is_dir():
        raise PreparationError(f"live_directory_missing:{live_dir}")
    installation_path = live_dir / "installation.json"
    status_path = live_dir / "information-battle-status.json"
    binding_path = live_dir / "information-battle-binding.json"
    raw_path = live_dir / "information-battle-raw.jsonl"
    control_path = live_dir / "control-probe.jsonl"
    installation = _read_json(installation_path)
    status = _read_json(status_path)
    binding = _read_json(binding_path)
    raw_text = _read_text(raw_path, MAX_METADATA_BYTES)
    raw_header = _parse_raw_header(raw_text)

    identity = {
        "pid": installation.get("pid"),
        "creation_filetime": installation.get("creation_filetime"),
        "session_id": installation.get("session_id"),
        "game_sha256": installation.get("game_sha256"),
        "dll_sha256": installation.get("dll_sha256"),
        "installation": status.get("installation"),
        "generation": status.get("generation"),
        "binding_installation": binding.get("installation"),
        "binding_generation": binding.get("generation"),
        "binding_player_ref": binding.get("player_ref"),
    }
    expected_installation = None
    expected_generation = None
    if raw_header.get("valid"):
        expected_installation = int(raw_header["installation_hex"], 16)
        expected_generation = int(raw_header["generation_hex"], 16)
    identity_checks = {
        "pid_matches_status": installation.get("pid") == status.get("pid"),
        "pid_matches_binding": installation.get("pid") == binding.get("pid"),
        "creation_matches_status": str(installation.get("creation_filetime"))
        == str(status.get("creation_filetime")),
        "creation_matches_binding": str(installation.get("creation_filetime"))
        == str(binding.get("creation_filetime")),
        "session_matches_binding": installation.get("session_id") == binding.get("session_id"),
        "exe_matches_fixed_build": installation.get("game_sha256") == EXPECTED_EXE_SHA256,
        "dll_matches_fixed_build": installation.get("dll_sha256") == EXPECTED_DLL_SHA256,
        "dll_matches_status": installation.get("dll_sha256") == status.get("dll_sha256"),
        "dll_matches_binding": installation.get("dll_sha256") == binding.get("dll_sha256"),
        "installation_matches_binding": status.get("installation") == binding.get("installation"),
        "generation_matches_binding": status.get("generation") == binding.get("generation"),
        "raw_header_installation_matches_status": expected_installation is not None
        and str(expected_installation) == str(status.get("installation")),
        "raw_header_generation_matches_status": expected_generation is not None
        and str(expected_generation) == str(status.get("generation")),
    }
    raw_lines = raw_text.splitlines()
    natural_raw_frames = max(0, len(raw_lines) - 1) if raw_lines and raw_lines[0].startswith("EU4_") else None
    selected_installation = _select(
        installation,
        (
            "pid",
            "creation_filetime",
            "session_id",
            "game_sha256",
            "dll_sha256",
            "runtime_verified",
            "ready_reason",
            "installation_returncode",
        ),
    )
    selected_status = _select(
        status,
        (
            "schema",
            "pid",
            "creation_filetime",
            "installation",
            "generation",
            "state",
            "command",
            "accepted",
            "reason",
            "code_patch_installed",
            "dll_pinned",
            "unwind_registered",
            "capture_complete",
            "visibility_verified",
            "business_export_available",
            "last_sequence",
            "captured",
            "writer_status",
        ),
    )
    selected_binding = _select(
        binding,
        (
            "pid",
            "creation_filetime",
            "session_id",
            "installation",
            "generation",
            "player_ref",
            "game_sha256",
            "dll_sha256",
        ),
    )
    return {
        "directory": _relative(live_dir),
        "installation": selected_installation,
        "status": selected_status,
        "binding": selected_binding,
        "identity_checks": identity_checks,
        "identity_checks_all_pass": all(identity_checks.values()),
        "raw_log": {
            "path": _relative(raw_path),
            "size": raw_path.stat().st_size,
            "sha256": _sha256(raw_path, MAX_METADATA_BYTES),
            "header": raw_header,
            "natural_payload_frame_count": natural_raw_frames,
        },
        "control_log": _scan_control_log(control_path),
        "runtime_channel_scan": _runtime_channel_scan(live_dir, installation),
        "process_identity_verified_by_this_file_only": False,
        "runtime_verified_field_from_installation": installation.get("runtime_verified"),
    }


def _build_report(live_dir: Path) -> dict[str, Any]:
    automated = _source_record(
        "work/native/automated-control.inc",
        (
            "game-control.request",
            'control_call(false,"0")',
            'control_call(false,"4")',
            'strcmp(request,"TEST_ONLY pause\\n")',
            'strcmp(request,"TEST_ONLY advance_35_days\\n")',
            'strcmp(request,"TEST_ONLY advance_5_days\\n")',
            'strcmp(request,"TEST_ONLY advance_1_days\\n")',
            "control_target=date+days*24",
            "GetTickCount64()+120000",
            "control_advance_begin",
            "control_advance_complete",
            "control_console_result",
            "DeleteFileW(control_request)",
            "player&0xffffff",
        ),
    )
    advance = _source_record(
        "work/advance_diplomacy_context.py",
        (
            "RAW_PER_DAY = 24",
            "SEGMENT_DAYS = (35, 5, 1)",
            "PLAYER_SLOT = 189",
            "def _completion_kind",
            "def _completion_health",
            "def _publish_control_request",
            '"request_republished": False',
            "SEGMENT_DEADLINE_SECONDS = 140.0",
        ),
    )
    pending_source = _source_record(
        "work/native/inbound-pending-recovery.inc",
        (
            "neither creates native proposals",
            "inbound_saved_queue_tick",
            "native_diplomacy_inbound_pending_restored",
            "business_result",
            "native_diplomacy_saved_pending_scan_complete",
            "native_queue_unchanged",
        ),
    )
    control_probe = _source_record(
        "work/native/control-probe.cpp",
        (
            "automated_control_tick();",
            "BridgeStart(void*)",
            "automated_control_start(directory)",
            "control_frame",
        ),
    )
    host = _source_record(
        "work/native/diplomacy-observer-v10.cpp",
        (
            "observer_legacy_frame(context);",
            "if (!thread_changed && frame_thread==GetCurrentThreadId())",
            "information_battle_tick();",
            "diplomacy_observer_health",
        ),
    )
    information_source = _source_record(
        "work/native/information-battle-observer.inc",
        (
            "static bool information_battle_start",
            "static void information_battle_tick()",
            "information-battle-control.request",
            "source_changed",
        ),
    )
    docs_source = _source_record(
        "docs/逐场战报观察器生命周期.md",
        (
            "启动后默认不采集",
            "逐场战报观察器生命周期",
            "下一步先完成新进程安装前的所有权与现场审计",
        ),
    )
    live = _live_evidence(live_dir)
    pending_events = live["control_log"]["pending_events"]
    authority_events = live["control_log"]["authority_events"]
    restored = next(
        (
            item
            for item in pending_events
            if item.get("event") == "native_diplomacy_inbound_pending_restored"
        ),
        {},
    )
    authority = next(
        (
            item
            for item in authority_events
            if item.get("event") == "diplomacy_observer_installed"
        ),
        {},
    )
    static_pass = all(
        record["all_requested_markers_found"]
        for record in (
            automated,
            advance,
            pending_source,
            control_probe,
            host,
            information_source,
            docs_source,
        )
    )
    runtime_scan = live["runtime_channel_scan"]
    runtime_clean = (
        not runtime_scan["request_or_processing_files"]
        and not runtime_scan["business_journal_candidates"]
    )
    pending_guard_evidence = (
        restored.get("action_id") == "ask_military_access"
        and restored.get("actor") == "SIE"
        and restored.get("recipient") == "FRA"
        and restored.get("decision_country") == "FRA"
        and restored.get("state34") == 0
        and restored.get("business_result") == "pending_observed"
        and restored.get("call_redirected") is False
        and authority.get("incoming_mode") == "state0_deferred_pending_observe;state1_2_llm_response"
        and authority.get("authority_lock_enabled") is True
    )
    identity_pass = live["identity_checks_all_pass"]
    return {
        "schema": "information-battle-natural-window-preparation/1",
        "status": "prepared_observation_only",
        "read_only": True,
        "game_accessed": False,
        "rpm_used": False,
        "rea_used": False,
        "requests_published_by_this_script": False,
        "pending_response_sent_by_this_script": False,
        "business_action_replayed": False,
        "source_script": {
            "path": _relative(Path(__file__).resolve()),
            "sha256": _sha256(Path(__file__).resolve()),
        },
        "fixed_build": {
            "version": "1.37.4",
            "exe_sha256": EXPECTED_EXE_SHA256,
            "information_dll_sha256": EXPECTED_DLL_SHA256,
        },
        "static_sources": {
            "automated_control": automated,
            "advance_runner": advance,
            "pending_recovery": pending_source,
            "control_probe": control_probe,
            "observer_host": host,
            "information_battle_source": information_source,
            "lifecycle_document": docs_source,
        },
        "static_protocol_checks": {
            "all_source_markers_found": static_pass,
            "accepted_requests": [
                "TEST_ONLY advance_1_days\\n",
                "TEST_ONLY advance_5_days\\n",
                "TEST_ONLY advance_35_days\\n",
            ],
            "request_file": "game-control.request",
            "request_file_path": _relative(live_dir / "game-control.request"),
            "request_is_deleted_before_control_execution": True,
            "raw_units_per_day": 24,
            "advance_days_options": [1, 5, 35],
            "advance_speed_argument": "4",
            "native_auto_pause_argument": "0",
            "advance_deadline_ms": 120000,
            "begin_event": {
                "event": "control_advance_begin",
                "fields": ["days"],
            },
            "completion_event": {
                "event": "control_advance_complete",
                "fields": [
                    "date_raw",
                    "target_raw",
                    "reached",
                    "paused_command_success",
                ],
            },
            "console_result_event": {
                "event": "control_console_result",
                "fields": ["command", "success", "thread"],
                "pause_command_value": "0",
            },
            "health_event": {
                "event": "diplomacy_observer_health",
                "fields": [
                    "session_id",
                    "thread_changed",
                    "frames",
                    "state_readable",
                    "player",
                    "date_raw",
                ],
            },
            "player_guard": {"tag": EXPECTED_PLAYER_TAG, "slot": EXPECTED_PLAYER_SLOT},
            "frame_thread_guard": True,
            "one_target_at_a_time": True,
            "source_failure_clears_target": True,
        },
        "completion_contract": {
            "exact_success": [
                "control_advance_complete.target_raw equals the requested target raw date",
                "control_advance_complete.reached is true",
                "control_advance_complete.date_raw equals target_raw",
                "control_advance_complete.paused_command_success is true",
                "a later bound health record is ready at the same target raw date",
                "an independent paused readback remains true before the next window",
            ],
            "target_not_reached_terminal": [
                "reached is false with the same target and paused_command_success true",
                "record target_not_reached and stop; do not publish another request",
            ],
            "unknown_stop": [
                "missing/wrong-target completion, paused_command_success false, speed-call failure, heartbeat loss, or identity/date change",
                "retain the request/intent evidence and stop without replay",
            ],
            "health_after_completion": {
                "status": "ready",
                "date_raw_must_equal_target": True,
                "request_republished": False,
            },
            "event_names": [
                "control_advance_begin",
                "control_advance_complete",
                "control_console_result",
                "diplomacy_observer_health",
            ],
        },
        "stop_pause_contract": {
            "explicit_request": "TEST_ONLY pause\\n",
            "native_action": "control_call(false,\"0\")",
            "advance_auto_pause": "control_call(false,\"0\") at target or 120000 ms deadline",
            "pause_result_caveat": "the native explicit-pause branch ignores the bool return and clears control_target; a later paused readback is mandatory",
            "request_file_path": _relative(live_dir / "game-control.request"),
            "required_console_result": {
                "event": "control_console_result",
                "command": "0",
                "success": True,
                "thread_must_match_bound_frame_thread": True,
            },
            "required_followup_health": {
                "event": "diplomacy_observer_health",
                "thread_changed": False,
                "state_readable": True,
                "player": EXPECTED_PLAYER_TAG,
                "date_raw": "same as the terminal/last observed date",
            },
            "safe_stop_preconditions": [
                "no game-control.request or control-pending intent is present",
                "the operator is stopping after an observed completion or has explicitly frozen an unknown advance",
                "no diplomacy response or business request is being published",
            ],
            "pause_failure_policy": "if control_console_result is absent or success is false, or the follow-up health is not stable, the window remains unknown and stops; do not automatically retry pause or advance",
            "safe_stop_condition": "only treat the stop as safe after the console result and the independent health/paused/date/identity checks pass",
        },
        "window_plan": {
            "baseline_required_before_first_request": {
                "raw_date": EXPECTED_DATE_RAW,
                "player_tag": EXPECTED_PLAYER_TAG,
                "player_slot": EXPECTED_PLAYER_SLOT,
                "paused": True,
                "speed": 0,
                "process_creation_and_loaded_dll_rechecked": True,
                "information_source_status": "ready_or_enabled_with_same_identity",
                "pending_response_queue": "observe_only",
            },
            "recommended_bounded_sequence": [
                {
                    "step": 1,
                    "request": "TEST_ONLY advance_1_days\\n",
                    "purpose": "one-day canary; target is start_date_raw + 24",
                    "request_file": "game-control.request",
                },
                {
                    "step": 2,
                    "request": "TEST_ONLY advance_5_days\\n",
                    "purpose": "only after exact step-1 completion and paused health",
                },
                {
                    "step": 3,
                    "request": "TEST_ONLY advance_35_days\\n",
                    "purpose": "only after exact step-2 completion and paused health",
                },
            ],
            "publication_rule": "at most one game-control.request; record intent and verify ready/date before atomic publication; an existing request or ambiguous intent stops the window",
            "natural_observation_scope": "observe control/health and information raw output only; do not create battle, diplomacy, response, save, or replay requests",
        },
        "pending_protection": {
            "static_contract": "inbound-pending-recovery reads the bounded recipient queue and records pending_observed; it neither creates native proposals nor chooses a response",
            "observed_pending": restored,
            "observed_authority": {
                "incoming_mode": authority.get("incoming_mode"),
                "authority_lock_enabled": authority.get("authority_lock_enabled"),
                "authority_scope": authority.get("authority_scope"),
            },
            "automatic_response_expected": False,
            "reason": [
                "the restored SIE→FRA item has state34=0 and business_result=pending_observed",
                "the v23 authority mode defers state0 incoming FRA items for LLM accept/reject",
                "no response request or redirected call was observed",
            ],
            "scope_limit": "This is evidence for the observed pending item and state; it is not a claim that every future inbound state is harmless.",
        },
        "live_artifact_evidence": live,
        "verification": {
            "static_protocol_contract": static_pass,
            "live_file_identity_consistent": identity_pass,
            "runtime_channels_clean_at_scan": runtime_clean,
            "pending_protection_evidence": pending_guard_evidence,
            "process_identity_verified_by_this_report": False,
            "paused_readback_performed_by_this_report": False,
            "window_publish_authorized": False,
        },
        "limitations": [
            "No process handle or RPM was opened; installation/status JSON and control-probe log are file evidence only.",
            "The live status explicitly says runtime_verified=false, capture_complete=false, visibility_verified=false, and business_export_available=false.",
            "The raw battle log contains its header and zero payload frames; a natural date window cannot be called a battle capture.",
            "The report does not authorize publishing any request. A separate operator must recheck the PID, creation time, loaded DLL, paused state, date, thread, and pending queue immediately before each request.",
        ],
        "prepared_checks": {
            "static_protocol": static_pass,
            "live_identity_file_consistency": identity_pass,
            "runtime_request_scan": runtime_clean,
            "pending_state_protection": pending_guard_evidence,
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--live-dir", type=Path, default=DEFAULT_LIVE_DIR)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args(argv)
    live_dir = _inside_workspace(args.live_dir)
    output = _inside_workspace(args.output)
    if output.exists():
        raise PreparationError(f"refusing_to_overwrite:{output}")
    report = _build_report(live_dir)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(report, stream, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    print(
        json.dumps(
            {
                "status": report["status"],
                "output": _relative(output),
                "static_protocol": report["verification"]["static_protocol_contract"],
                "live_identity_file_consistent": report["verification"]["live_file_identity_consistent"],
                "runtime_channels_clean": report["verification"]["runtime_channels_clean_at_scan"],
                "pending_protection": report["verification"]["pending_protection_evidence"],
                "requests_published": report["requests_published_by_this_script"],
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except PreparationError as error:
        print(f"preparation_error: {error}", file=sys.stderr)
        raise SystemExit(2)
