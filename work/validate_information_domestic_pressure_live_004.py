"""Run the fourth paused-live N04 acceptance without reusing old identities.

The runner first consumes an independently produced pure bounded-RPM capture
(or starts that capture as a child when ``--reference`` is omitted).  It then
starts the stdio MCP server and checks the three supported
fields, single-field selection, a mixed query containing only the two current
unsupported fields, and three delivered periodic results.  Every result is
linked to a native capture report and to the before/after paused game date.

This file is intentionally a new runner.  It does not change the older N04
validator, its historical thresholds, or any production adapter/profile.  It
does not start, advance, save, reload, install, or submit a game action.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from bridge.diplomacy import ObserverSession
from work.local_config import game_exe
from work.run_alliance_inbound_response import control_snapshot
from work.validate_information_live import sha, write
from work.validate_information_domestic_pressure import (
    CompactMCPClient,
    _check_discovery,
    _check_result,
    _check_result_fields,
    _query,
)


FIELDS = ("stability", "war_exhaustion", "corruption")
MIXED_UNIMPLEMENTED_FIELDS = ("overextension", "unrest")
DISCOVERY_PLANNED_FIELDS = ("religious_unity", "overextension", "unrest")
EXPECTED_VERSION = "1.37.4"
EXPECTED_GAME_SHA256 = (
    "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
)
MAX_NATIVE_REPORT_BYTES = 8 * 1024 * 1024


def require(value: Any, reason: str) -> None:
    if not value:
        raise ValueError(reason)


def _json_bytes(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True,
        separators=(",", ":"), allow_nan=False,
    ).encode("utf-8")


def _file_sha(path: Path) -> str:
    return sha(path)


def _read_json(path: Path, *, max_bytes: int = MAX_NATIVE_REPORT_BYTES) -> tuple[dict, str]:
    require(path.is_file(), f"Missing JSON artifact: {path}")
    require(path.stat().st_size <= max_bytes, f"JSON artifact exceeds bound: {path}")
    raw = path.read_bytes()
    value = json.loads(raw.decode("utf-8"))
    require(isinstance(value, dict), f"JSON artifact is not an object: {path}")
    return value, hashlib.sha256(raw).hexdigest()


def _control_identity(snapshot: dict) -> dict:
    require(isinstance(snapshot, dict), "Control snapshot is not an object")
    for key in ("player_slot", "paused_flag", "date_raw", "speed"):
        require(key in snapshot, f"Control snapshot lacks {key}")
    require(type(snapshot["paused_flag"]) is int and snapshot["paused_flag"] == 1,
            "Game is not paused")
    require(type(snapshot["speed"]) is int and snapshot["speed"] == 0,
            "Game speed is not zero")
    require(type(snapshot["date_raw"]) is int, "Control date is not an integer")
    return {key: snapshot[key] for key in ("player_slot", "paused_flag", "date_raw", "speed")}


def _assert_same_control(before: dict, after: dict, label: str) -> None:
    left = _control_identity(before)
    right = _control_identity(after)
    require(left == right, f"{label}: paused control/date changed")


def _native_identity(report: dict, installation: Path, session: ObserverSession) -> dict:
    identity = report.get("identity")
    require(isinstance(identity, dict), "Native capture identity is missing")
    require(identity.get("binding_verified") is True, "Native capture identity is unbound")
    require(Path(str(identity.get("installation_path"))).resolve() == installation,
            "Native capture installation path differs")
    record = session.record
    pid = int(record["pid"])
    creation = int(record["creation_filetime"])
    require(identity.get("installation_pid") == pid, "Native capture PID differs")
    require(identity.get("installation_creation_filetime") == creation,
            "Native capture installation creation differs")
    require(identity.get("process_creation_filetime") == creation,
            "Native capture process creation differs")
    require(identity.get("installation_session_id") == session.session_id,
            "Native capture session differs")
    require(identity.get("process_creation_matches_installation") is True,
            "Native capture process creation is not bound")
    require(identity.get("process_path_sha256_matches_expected") is True,
            "Native capture process SHA guard failed")
    require(identity.get("module_path_matches_process") is True,
            "Native capture module path guard failed")
    return {
        "pid": pid,
        "creation_filetime": creation,
        "session_id": session.session_id,
        "installation_path": str(installation),
    }


def _native_field_values(report: dict) -> dict[str, int]:
    fields = report.get("field_results")
    require(isinstance(fields, dict), "Native capture field_results is missing")
    values: dict[str, int] = {}
    for field in FIELDS:
        item = fields.get(field)
        require(isinstance(item, dict) and item.get("status") == "known",
                f"Native field {field} is not known")
        raw = item.get("raw")
        raw_hex = item.get("raw_hex")
        require(type(raw) is int, f"Native field {field} raw is not signed int")
        require(isinstance(raw_hex, str) and len(raw_hex) == 8,
                f"Native field {field} raw_hex is not 4 bytes")
        require(int.from_bytes(bytes.fromhex(raw_hex), "little", signed=True) == raw,
                f"Native field {field} raw bytes differ")
        require(item.get("unit") == field and item.get("scale") == 1000,
                f"Native field {field} metadata differs")
        values[field] = raw
    return values


def _native_date(report: dict, name: str) -> int:
    snapshot = report.get(name)
    require(isinstance(snapshot, dict), f"Native {name} snapshot is missing")
    game_date = snapshot.get("game_date")
    require(isinstance(game_date, dict) and type(game_date.get("value")) is int,
            f"Native {name} game_date is missing")
    return int(game_date["value"])


def _validate_native(report: dict, installation: Path, session: ObserverSession,
                     control_date: int, label: str) -> dict:
    require(report.get("status") == "observed", f"{label}: native status is not observed")
    require(report.get("completed") is True and report.get("complete") is True,
            f"{label}: native capture is incomplete")
    require(report.get("read_only") is True, f"{label}: native capture is not read-only")
    require(report.get("native_function_invoked") is False,
            f"{label}: native function was invoked")
    require(report.get("country") == "FRA", f"{label}: native country differs")
    target = report.get("target_build")
    require(isinstance(target, dict)
            and target.get("version") == EXPECTED_VERSION
            and target.get("expected_exe_sha256", target.get("exe_sha256")) == EXPECTED_GAME_SHA256,
            f"{label}: native target identity differs")
    _native_identity(report, installation, session)
    before_date = _native_date(report, "before")
    after_date = _native_date(report, "after")
    require(before_date == after_date == control_date,
            f"{label}: native before/after date differs")
    doublepass = report.get("doublepass")
    require(isinstance(doublepass, dict)
            and doublepass.get("performed") is True
            and doublepass.get("consistent") is True
            and doublepass.get("mismatches", []) == [],
            f"{label}: native doublepass is not consistent")
    cleanup = report.get("cleanup", {}).get("handle_close", {})
    require(isinstance(cleanup, dict)
            and cleanup.get("status") == "closed"
            and cleanup.get("closed") is True,
            f"{label}: native handle was not closed")
    access = report.get("access", {})
    for key in ("native_game_calls", "target_memory_writes", "dll_injection",
                "date_advance", "save_or_reload"):
        require(access.get(key) is False, f"{label}: access guard failed: {key}")
    values = _native_field_values(report)
    return {
        "label": label,
        "report": report,
        "values": values,
        "game_date": control_date,
        "before_game_date": before_date,
        "after_game_date": after_date,
        "session_id": session.session_id,
        "pid": int(session.record["pid"]),
        "creation_filetime": int(session.record["creation_filetime"]),
    }


def _run_native_sample(installation: Path, output: Path, session: ObserverSession,
                       control_before: dict, label: str, timeout: float) -> dict:
    sample_dir = output / label
    command = [
        sys.executable, str(ROOT / "work/capture_information_domestic_pressure.py"),
        "--installation", str(installation), "--output", str(sample_dir),
        "--fields", *FIELDS,
    ]
    completed = subprocess.run(
        command, cwd=ROOT, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True, encoding="utf-8", timeout=timeout,
        check=False,
    )
    # capture_information_domestic_pressure.py writes a small wrapper report
    # plus the actual pure-RPM capture.  Only the latter carries the native
    # observation contract consumed below.
    report_path = sample_dir / "native-capture.json"
    wrapper_path = sample_dir / "report.json"
    require(completed.returncode == 0,
            f"{label}: independent native capture exited {completed.returncode}")
    native, report_sha = _read_json(report_path)
    wrapper, wrapper_sha = _read_json(wrapper_path)
    require(wrapper.get("status") == "passed",
            f"{label}: capture wrapper did not pass")
    control_date = _control_identity(control_before)["date_raw"]
    checked = _validate_native(native, installation, session, control_date, label)
    checked.update({
        "report_path": str(report_path),
        "report_sha256": report_sha,
        "wrapper_report_path": str(wrapper_path),
        "wrapper_report_sha256": wrapper_sha,
        "capture_script_path": str(ROOT / "work/capture_information_domestic_pressure.py"),
        "capture_script_sha256": _file_sha(ROOT / "work/capture_information_domestic_pressure.py"),
        "subprocess_returncode": completed.returncode,
        "stdout_sha256": hashlib.sha256(completed.stdout.encode("utf-8")).hexdigest(),
        "stderr_sha256": hashlib.sha256(completed.stderr.encode("utf-8")).hexdigest(),
        "stdout_bytes": len(completed.stdout.encode("utf-8")),
        "stderr_bytes": len(completed.stderr.encode("utf-8")),
    })
    return checked


def _reference_context(sample: dict) -> dict:
    return {
        "session_id": sample["session_id"],
        "game_date": sample["game_date"],
        "values": dict(sample["values"]),
    }


def _check_query_echo(result: dict, fields: list[str], label: str) -> None:
    items = result.get("items")
    require(isinstance(items, list) and len(items) == 1 and isinstance(items[0], dict),
            f"{label}: result item is missing")
    query = items[0].get("query")
    if isinstance(query, dict) and "fields" in query:
        require(query.get("fields") == fields, f"{label}: returned field selection differs")


def _check_mixed_without_religious_unity(result: dict, reference: dict,
                                         session_id: str, game_date: int,
                                         requested_fields: list[str]) -> dict:
    require(result.get("status") == "partial" and result.get("complete") is False,
            "Mixed N04 result is not partial")
    values = _check_result_fields(result, list(FIELDS), reference, session_id, game_date)
    _check_query_echo(result, requested_fields, "mixed query")
    item = result["items"][0]
    require(item.get("complete") is False, "Mixed N04 item incorrectly reports complete")
    fields = item.get("fields")
    require(isinstance(fields, dict), "Mixed N04 fields are missing")
    for field in MIXED_UNIMPLEMENTED_FIELDS:
        require(isinstance(fields.get(field), dict)
                and fields[field].get("status") == "unsupported",
                f"{field} was fabricated")
    religion = fields.get("religious_unity")
    require(religion is None or religion.get("status") == "unsupported",
            "religious_unity was unexpectedly evaluated")
    return values


def _association(result: dict, sample: dict, label: str) -> dict:
    context = result.get("context")
    require(isinstance(context, dict), f"{label}: MCP context is missing")
    require(context.get("session_id") == sample["session_id"],
            f"{label}: MCP session/native session differs")
    require(context.get("game_date") == sample["game_date"],
            f"{label}: MCP date/native date differs")
    return {
        "label": label,
        "native_sample_label": sample["label"],
        "native_report_path": sample["report_path"],
        "native_report_sha256": sample["report_sha256"],
        "native_capture_script_sha256": sample["capture_script_sha256"],
        "session_id": sample["session_id"],
        "pid": sample["pid"],
        "creation_filetime": sample["creation_filetime"],
        "native_before_game_date": sample["before_game_date"],
        "native_after_game_date": sample["after_game_date"],
        "mcp_game_date": context["game_date"],
        "mcp_status": result.get("status"),
        "mcp_complete": result.get("complete"),
        "result_id": result.get("result_id"),
        "subscription_id": result.get("subscription_id"),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--installation", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--reference", type=Path,
        help="Existing independent native-capture.json; omit only to run a new child capture",
    )
    parser.add_argument("--tick-seconds", type=float, default=0.25)
    parser.add_argument("--wait-seconds", type=float, default=15.0)
    parser.add_argument("--native-timeout", type=float, default=180.0)
    parser.add_argument("--expected-field-coverage", choices=("partial", "available"), default="partial")
    args = parser.parse_args()
    require(args.tick_seconds > 0, "--tick-seconds must be positive")
    require(args.wait_seconds >= 6, "--wait-seconds must allow three two-second samples")
    require(args.native_timeout >= 10, "--native-timeout is too small")
    installation = args.installation.resolve(strict=True)
    require(args.output.resolve() != installation, "Output cannot be the installation file")
    args.output.mkdir(parents=True, exist_ok=False)

    report: dict[str, Any] = {
        "status": "failed",
        "schema": "information_domestic_pressure_live_acceptance_004",
        "mode": "paused_live_mcp_with_independent_pure_rpm_samples",
        "country": "FRA",
        "fields": list(FIELDS),
        "mixed_unimplemented_fields": list(MIXED_UNIMPLEMENTED_FIELDS),
        "religious_unity": "excluded_from_queries; discovery-only planned check",
        "expected_field_coverage": args.expected_field_coverage,
        "read_only": True,
        "native_function_invoked": False,
        "business_actions_submitted": False,
        "date_advance": False,
        "save_or_reload": False,
        "dll_installation": False,
        "historical_values_used": False,
        "installation": str(installation),
        "checks": {},
        "native_samples": [],
        "associations": [],
    }
    client: CompactMCPClient | None = None
    subscription: dict | None = None
    before_control: dict | None = None
    session: ObserverSession | None = None
    try:
        session = ObserverSession(installation, game_exe())
        pid = int(session.record["pid"])
        creation = int(session.record["creation_filetime"])
        report["binding"] = {
            "pid": pid, "creation_filetime": creation,
            "session_id": session.session_id,
            "installation_path": str(installation),
            "game_sha256": session.record.get("game_sha256"),
        }
        before_control = control_snapshot(pid, args.output / "before-control.json")
        before_identity = _control_identity(before_control)
        write(args.output / "before-health.json", session.health())
        require(session.health().get("status") == "ready", "Native source is not ready")
        report["checks"]["paused_read_only_start"] = True

        # This reference must be independent of the MCP response.  A caller
        # may provide a separately produced native-capture.json so the live
        # runner does not repeat an already completed reference sample.
        if args.reference is None:
            reference = _run_native_sample(
                installation, args.output, session, before_control,
                "native-reference-000", args.native_timeout,
            )
        else:
            reference_path = args.reference.resolve(strict=True)
            native, reference_sha = _read_json(reference_path)
            reference = _validate_native(
                native, installation, session,
                _control_identity(before_control)["date_raw"],
                "Provided independent native reference",
            )
            reference.update({
                "report_path": str(reference_path),
                "report_sha256": reference_sha,
                "capture_script_path": native.get("probe_script"),
                "capture_script_sha256": native.get("probe_script_sha256"),
                "provided_reference": True,
            })
        report["native_samples"].append({k: v for k, v in reference.items() if k != "report"})
        write(args.output / "native-reference-summary.json", report["native_samples"][0])
        after_native = control_snapshot(pid, args.output / "after-native-reference-control.json")
        _assert_same_control(before_control, after_native, "after independent native sample")
        report["checks"]["independent_pure_rpm_reference_bound_to_pid_creation_session"] = True

        reference_context = _reference_context(reference)
        client = CompactMCPClient(installation, args.output, tick_seconds=args.tick_seconds)
        report["mcp_protocol"] = {
            "protocol_version": client.initialize_result.get("protocolVersion"),
            "server_info": client.initialize_result.get("serverInfo"),
        }
        discovery = client.call("information_discover")
        discovery_summary = _check_discovery(discovery, args.expected_field_coverage)
        for field in DISCOVERY_PLANNED_FIELDS:
            require(discovery_summary["fields"][field].get("coverage") == "planned",
                    f"Discovery {field} is not planned")
        write(args.output / "discovery-summary.json", discovery_summary)
        report["checks"]["n04_discovery_three_fields_and_planned_exclusions"] = True

        full_query = _query(list(FIELDS))
        manual = client.call(
            "information_query", request_id="domestic-pressure-live004-manual",
            queries=[full_query],
        )
        _check_result(manual, list(FIELDS), reference_context,
                      session.session_id, reference["game_date"])
        _check_query_echo(manual, list(FIELDS), "manual query")
        report["associations"].append(_association(manual, reference, "manual"))
        write(args.output / "manual-result.json", manual)
        report["checks"]["three_field_query_matches_independent_native"] = True

        single_results: dict[str, dict] = {}
        for field in FIELDS:
            selected = [field]
            single = client.call(
                "information_query", request_id="domestic-pressure-live004-single-" + field,
                queries=[_query(selected)],
            )
            _check_result(single, selected, reference_context,
                          session.session_id, reference["game_date"])
            _check_query_echo(single, selected, "single " + field)
            report["associations"].append(_association(single, reference, "single-" + field))
            single_results[field] = single
        write(args.output / "single-field-results.json", single_results)
        report["checks"]["single_field_selection_preserves_native_values"] = True

        mixed_fields = list(FIELDS) + list(MIXED_UNIMPLEMENTED_FIELDS)
        mixed = client.call(
            "information_query", request_id="domestic-pressure-live004-mixed",
            queries=[_query(mixed_fields)],
        )
        _check_mixed_without_religious_unity(
            mixed, reference_context, session.session_id, reference["game_date"], mixed_fields,
        )
        report["associations"].append(_association(mixed, reference, "mixed-unsupported"))
        write(args.output / "mixed-unimplemented-result.json", mixed)
        report["checks"]["mixed_two_unimplemented_fields_remain_partial"] = True

        saved = client.call(
            "information_manage_report", request_id="domestic-pressure-live004-report",
            operation="create",
            config={"name": "domestic-pressure-live004", "queries": [full_query], "detail": "raw"},
        )
        report_config = saved.get("report")
        require(isinstance(report_config, dict) and isinstance(report_config.get("id"), str),
                "N04 report was not created")
        sub_result = client.call(
            "information_manage_subscription", request_id="domestic-pressure-live004-subscription",
            operation="create",
            config={
                "name": "domestic-pressure-live004-periodic", "kind": "periodic",
                "report_id": report_config["id"], "enabled": True,
                "schedule": {"basis": "real", "every": 2, "unit": "seconds", "missed": "coalesce"},
            },
        )
        subscription = sub_result.get("subscription")
        require(isinstance(subscription, dict) and isinstance(subscription.get("id"), str),
                "N04 subscription was not created")
        report["subscription"] = {key: subscription[key] for key in ("id", "version", "state") if key in subscription}

        periodic: list[dict] = []
        periodic_by_id: set[str] = set()
        deadline = time.monotonic() + args.wait_seconds
        while time.monotonic() < deadline and len(periodic) < 3:
            listed = client.call("information_list_results", limit=50)
            candidates = [item for item in listed.get("results", [])
                          if isinstance(item, dict)
                          and item.get("subscription_id") == subscription["id"]
                          and isinstance(item.get("result_id"), str)
                          and item["result_id"] not in periodic_by_id]
            for item in candidates:
                index = len(periodic) + 1
                require(item.get("delivery", {}).get("status") == "delivered",
                        "N04 periodic result was not delivered")
                control_before_period = control_snapshot(
                    pid, args.output / f"periodic-{index:03d}-before-control.json",
                )
                sample = _run_native_sample(
                    installation, args.output, session, control_before_period,
                    f"native-periodic-{index:03d}", args.native_timeout,
                )
                report["native_samples"].append({k: v for k, v in sample.items() if k != "report"})
                control_after_period = control_snapshot(
                    pid, args.output / f"periodic-{index:03d}-after-control.json",
                )
                _assert_same_control(control_before_period, control_after_period,
                                     f"periodic {index} native sample")
                _check_result(item, list(FIELDS), _reference_context(sample),
                              session.session_id, sample["game_date"])
                _check_query_echo(item, list(FIELDS), f"periodic {index}")
                periodic.append(item)
                periodic_by_id.add(item["result_id"])
                report["associations"].append(_association(item, sample, f"periodic-{index:03d}"))
                if len(periodic) >= 3:
                    break
            if len(periodic) < 3:
                time.sleep(min(0.25, max(0.01, deadline - time.monotonic())))
        require(len(periodic) >= 3, f"Too few two-second N04 samples: {len(periodic)}")
        write(args.output / "periodic-results.json", periodic[:3])
        report["periodic_results"] = len(periodic[:3])
        report["checks"]["three_periodic_results_each_bound_to_native_and_date"] = True

        cancelled = client.call(
            "information_manage_subscription", request_id="domestic-pressure-live004-cancel",
            operation="cancel", subscription_id=subscription["id"],
            expected_version=subscription["version"],
        )
        require(cancelled.get("subscription", {}).get("state") == "cancelled",
                "N04 subscription was not cancelled")
        cancelled_subscription = cancelled.get("subscription")
        if isinstance(cancelled_subscription, dict):
            subscription.update({
                key: cancelled_subscription[key]
                for key in ("id", "version", "state")
                if key in cancelled_subscription
            })
            report["subscription"] = {
                key: subscription[key]
                for key in ("id", "version", "state")
                if key in subscription
            }
        report["checks"]["subscription_cancelled_without_game_action"] = True
        final_status = client.call("information_status")
        write(args.output / "final-status-summary.json", {
            key: final_status[key]
            for key in ("status", "owner", "context", "reports", "subscriptions", "results")
            if key in final_status
        })

        client.close()
        client = None
        after_control = control_snapshot(pid, args.output / "after-control.json")
        _assert_same_control(before_control, after_control, "final control")
        require(after_control["date_raw"] == before_identity["date_raw"],
                "Final date differs from initial date")
        report["checks"]["paused_player_and_date_preserved"] = True
        report.update(
            status="passed", session_id=session.session_id, pid=pid,
            creation_filetime=creation, game_sha256=session.record.get("game_sha256"),
            game_date=before_identity["date_raw"],
            source_sha256=sha(Path(__file__)),
            installation_sha256=sha(installation),
            mcp_wire_audit_sha256=sha(args.output / "mcp-wire-audit.json"),
            source_files={name: sha(ROOT / name) for name in (
                "bridge/information/domestic_pressure.py",
                "bridge/information/domestic_pressure_memory.py",
                "tools/serve_information.py",
            )},
        )
    except Exception as exc:
        report["error"] = {"type": type(exc).__name__, "message": str(exc)}
        raise
    finally:
        if client is not None:
            try:
                if subscription is not None and subscription.get("state") != "cancelled":
                    try:
                        client.call(
                            "information_manage_subscription",
                            request_id="domestic-pressure-live004-finally-cancel",
                            operation="cancel", subscription_id=subscription["id"],
                            expected_version=subscription["version"],
                        )
                    except Exception as exc:
                        report.setdefault("cleanup_errors", []).append({
                            "stage": "subscription_cancel", "type": type(exc).__name__, "message": str(exc),
                        })
                client.close()
            except Exception as exc:
                report.setdefault("cleanup_errors", []).append({
                    "stage": "mcp_close", "type": type(exc).__name__, "message": str(exc),
                })
        report["runner_sha256"] = sha(Path(__file__))
        write(args.output / "report.json", report)
    print(json.dumps(report, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
