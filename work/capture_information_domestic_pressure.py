"""Capture an independent, bounded N04 native sample.

The runner performs only the existing native reader's read-only capture and
paused-state checks.  It never advances the game, submits an action, saves,
reloads, installs a DLL, or treats the historical save values as a live
expectation.  An optional reference is an independently produced native
capture; it is compared by raw field bytes and is never taken from this
runner's own response.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from bridge.diplomacy import ObserverSession
from bridge.information.domestic_pressure_memory import capture
from work.local_config import game_exe
from work.run_alliance_inbound_response import control_snapshot
from work.validate_information_live import sha, write


FIELDS = ("stability", "war_exhaustion", "corruption")
UNITS = {
    "stability": "stability",
    "war_exhaustion": "war_exhaustion",
    "corruption": "corruption",
}
EXPECTED_VERSION = "1.37.4"
EXPECTED_GAME_SHA256 = (
    "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
)
MAX_REFERENCE_BYTES = 8 * 1024 * 1024


def require(value, reason):
    if not value:
        raise ValueError(reason)


def _read_json(path: Path) -> tuple[dict, str]:
    size = path.stat().st_size
    require(size <= MAX_REFERENCE_BYTES, "Independent reference is too large")
    raw = path.read_bytes()
    value = json.loads(raw.decode("utf-8"))
    require(isinstance(value, dict), "Independent reference must be a JSON object")
    return value, hashlib.sha256(raw).hexdigest()


def _native_item(item: object, field: str) -> dict:
    require(isinstance(item, dict), f"{field}: field result is not an object")
    require(item.get("status") == "known", f"{field}: native field is not known")
    raw = item.get("raw")
    require(type(raw) is int, f"{field}: raw value is not a signed integer")
    raw_hex = item.get("raw_hex")
    require(isinstance(raw_hex, str) and len(raw_hex) == 8, f"{field}: raw_hex is not 4 bytes")
    try:
        decoded = int.from_bytes(bytes.fromhex(raw_hex), "little", signed=True)
    except ValueError as exc:
        raise ValueError(f"{field}: raw_hex is not hexadecimal") from exc
    require(decoded == raw, f"{field}: raw and raw_hex differ")
    require(item.get("unit") == UNITS[field], f"{field}: unit differs")
    require(item.get("scale") == 1000, f"{field}: scale differs")
    return {key: item[key] for key in ("raw", "raw_hex", "unit", "scale")}


def _capture_fields(report: object, fields: list[str]) -> dict[str, dict]:
    require(isinstance(report, dict), "Native capture is not an object")
    field_results = report.get("field_results")
    require(isinstance(field_results, dict), "Native capture has no field_results")
    result = {}
    for field in fields:
        result[field] = _native_item(field_results.get(field), field)
    values = report.get("values")
    if values is not None:
        require(isinstance(values, dict), "Native capture values is not an object")
        for field in fields:
            require(values.get(field) == result[field]["raw"], f"{field}: values differs from field_results")
    return result


def _game_date(report: dict, pass_name: str) -> int:
    snapshot = report.get(pass_name)
    require(isinstance(snapshot, dict), f"{pass_name}: native snapshot is missing")
    game_date = snapshot.get("game_date")
    require(isinstance(game_date, dict) and type(game_date.get("value")) is int,
            f"{pass_name}: native game_date is missing")
    return game_date["value"]


def _validate_capture_contract(
    report: dict,
    fields: list[str],
    *,
    session_id: str,
    creation_filetime: int,
    control_date: int,
    label: str,
) -> dict[str, dict]:
    require(report.get("status") == "observed", f"{label}: native capture is not observed")
    require(report.get("completed") is True, f"{label}: native capture is not completed")
    require(report.get("complete") is True, f"{label}: native fields are incomplete")
    require(report.get("read_only") is True, f"{label}: native capture is not read-only")
    require(report.get("native_function_invoked") is False, f"{label}: native capture invoked a game function")
    require(report.get("country") == "FRA", f"{label}: native capture country differs")
    target_build = report.get("target_build")
    require(isinstance(target_build, dict), f"{label}: native target build is missing")
    require(target_build.get("version") == EXPECTED_VERSION, f"{label}: native game version differs")
    require(
        target_build.get("expected_exe_sha256", target_build.get("exe_sha256")) == EXPECTED_GAME_SHA256,
        f"{label}: native executable identity differs",
    )
    identity = report.get("identity")
    require(isinstance(identity, dict) and identity.get("binding_verified") is True,
            f"{label}: native identity is unbound")
    require(identity.get("installation_session_id", identity.get("session_id")) == session_id,
            f"{label}: native session differs")
    require(identity.get("installation_creation_filetime", identity.get("creation_filetime")) == creation_filetime,
            f"{label}: native installation creation differs")
    require(identity.get("process_creation_filetime", identity.get("process_creation")) == creation_filetime,
            f"{label}: native process creation differs")
    require(_game_date(report, "before") == control_date, f"{label}: native before date differs")
    require(_game_date(report, "after") == control_date, f"{label}: native after date differs")
    doublepass = report.get("doublepass")
    require(isinstance(doublepass, dict)
            and doublepass.get("performed") is True
            and doublepass.get("consistent") is True
            and doublepass.get("mismatches", []) == [],
            f"{label}: native doublepass differs")
    handle_close = report.get("cleanup", {}).get("handle_close", {})
    require(isinstance(handle_close, dict)
            and handle_close.get("status") == "closed"
            and handle_close.get("closed") is True,
            f"{label}: native handle was not closed")
    access = report.get("access", {})
    for key in ("native_game_calls", "target_memory_writes", "dll_injection", "date_advance", "save_or_reload"):
        require(access.get(key) is False, f"{label}: native access guard failed: {key}")
    return _capture_fields(report, fields)


def _reference_payload(value: dict) -> dict:
    # Allow a small wrapper used by independent capture tooling, while still
    # requiring the actual capture to carry its own status and field results.
    if isinstance(value.get("native_capture"), dict):
        return value["native_capture"]
    if isinstance(value.get("capture"), dict) and "field_results" in value["capture"]:
        return value["capture"]
    return value


def _compare_reference(
    report: dict,
    reference_path: Path,
    fields: list[str],
    *,
    session_id: str,
    creation_filetime: int,
    control_date: int,
) -> dict:
    reference, reference_sha = _read_json(reference_path)
    expected = _reference_payload(reference)
    expected_fields = _validate_capture_contract(
        expected, fields, session_id=session_id, creation_filetime=creation_filetime,
        control_date=control_date, label="Independent reference",
    )
    actual_fields = _validate_capture_contract(
        report, fields, session_id=session_id, creation_filetime=creation_filetime,
        control_date=control_date, label="Current native capture",
    )
    mismatches = [
        field for field in fields
        if expected_fields[field] != actual_fields[field]
    ]
    require(not mismatches, "Independent native reference differs: " + ",".join(mismatches))
    return {
        "path": str(reference_path),
        "sha256": reference_sha,
        "fields": fields,
        "matched": True,
        "historical_values_used": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--installation", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--reference", "--expected-reference", dest="reference", type=Path,
        help="Optional independently produced native capture JSON; never a save or this run's output",
    )
    parser.add_argument("--fields", nargs="+", choices=FIELDS, default=list(FIELDS))
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    installation = args.installation.resolve(strict=True)
    fields = list(dict.fromkeys(args.fields))
    report = {
        "status": "failed",
        "mode": "live",
        "country": "FRA",
        "fields": fields,
        "read_only": True,
        "native_function_invoked": False,
        "business_actions_submitted": False,
        "date_advance": False,
        "save_or_reload": False,
        "dll_installation": False,
        "historical_values_used": False,
        "checks": {},
    }
    try:
        session = ObserverSession(installation, game_exe())
        pid = int(session.record["pid"])
        before = control_snapshot(pid, args.output / "before-control.json")
        write(args.output / "before-health.json", session.health())
        require(
            (before["player_slot"], before["paused_flag"], before["date_raw"], before["speed"])
            == (189, 1, 56553384, 0),
            "Unexpected initial controls",
        )
        require(session.health()["status"] == "ready", "Native source not ready")
        report["checks"]["paused_read_only_start"] = True

        raw = capture(installation, "FRA", fields)
        write(args.output / "native-capture.json", raw)
        _validate_capture_contract(
            raw, fields, session_id=session.session_id,
            creation_filetime=session.record["creation_filetime"],
            control_date=before["date_raw"], label="Current native capture",
        )
        report["checks"]["native_contract_doublepass_cleanup"] = True

        if args.reference is not None:
            reference_path = args.reference.resolve(strict=True)
            require(reference_path != (args.output / "native-capture.json").resolve(), "Reference cannot be this run's capture")
            report["independent_reference"] = _compare_reference(
                raw, reference_path, fields, session_id=session.session_id,
                creation_filetime=session.record["creation_filetime"],
                control_date=before["date_raw"],
            )
            report["checks"]["independent_native_reference_matches"] = True

        after = control_snapshot(pid, args.output / "after-control.json")
        require(before == after, "Control state changed")
        report["checks"]["pause_player_date_preserved"] = True
        report.update(
            status="passed",
            session_id=session.session_id,
            pid=pid,
            game_sha256=session.record["game_sha256"],
            date_raw=before["date_raw"],
            values={field: raw["field_results"][field]["raw"] for field in fields},
            raw_capture_sha256=sha(args.output / "native-capture.json"),
            source_sha256=sha(Path(__file__)),
            installation_sha256=sha(installation),
        )
    except Exception as exc:
        report["error"] = {"type": type(exc).__name__, "message": str(exc)}
        raise
    finally:
        write(args.output / "report.json", report)
    print(json.dumps(report, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
