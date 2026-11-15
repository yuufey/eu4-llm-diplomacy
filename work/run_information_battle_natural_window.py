"""One TEST_ONLY forward-time observation window; never retries a dispatch."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.control_information_battle_observer import run_control
from bridge.diplomacy_session import probe_identity
from work.local_config import game_exe

EXPECTED_PLAYER_TAGS = ("POR", "FRA")


def write_new(path: Path, document: dict) -> None:
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(document, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())


def read(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def pin(path: Path) -> dict:
    with path.open("rb") as stream:
        sha = hashlib.file_digest(stream, "sha256").hexdigest()
    return {"path": str(path), "bytes": path.stat().st_size, "sha256": sha}


def check_completion(events: list[dict], target: int, expected_player_tag: str = "POR") -> bool:
    if expected_player_tag not in EXPECTED_PLAYER_TAGS:
        raise ValueError("expected_player_tag_must_be_POR_or_FRA")
    for index, event in enumerate(events):
        if (event.get("event") != "control_advance_complete"
                or event.get("date_raw") != target or event.get("target_raw") != target
                or event.get("reached") is not True
                or event.get("paused_command_success") is not True):
            continue
        console = any(item.get("event") == "control_console_result"
                      and item.get("command") == "0" and item.get("success") is True
                      for item in events[:index + 1])
        health = any(item.get("event") == "diplomacy_observer_health"
                     and item.get("date_raw") == target
                     and item.get("thread_changed") is False
                     and item.get("state_readable") is True
                     and item.get("player") == expected_player_tag
                     for item in events[index + 1:])
        if console and health:
            return True
    return False


def publish_request(directory: Path, text: str, output: Path, name: str) -> None:
    target = directory / "game-control.request"
    if target.exists():
        raise RuntimeError("CONTROL_REQUEST_ALREADY_PRESENT_NO_DISPATCH")
    temporary = directory / ("game-control." + name + ".tmp")
    write_new(output / (name + "-started.json"), {
        "state": "dispatch_started_no_automatic_retry", "request": text,
        "target": str(target), "recorded_at_utc": datetime.now(timezone.utc).isoformat(),
    })
    with temporary.open("xb") as stream:
        stream.write(text.encode("ascii"))
        stream.flush()
        os.fsync(stream.fileno())
    try:
        os.link(temporary, target)  # Atomic publication, never replaces a request.
    finally:
        temporary.unlink(missing_ok=True)


def probe(installation: Path, output: Path) -> dict:
    command = [sys.executable, str(ROOT / "work/probe_information_battle_v23.py"),
               "--installation", str(installation), "--expect-patch", "installed",
               "--output", str(output)]
    result = subprocess.run(command, cwd=ROOT, capture_output=True, timeout=30)
    with output.with_suffix(".runner.log").open("xb") as stream:
        stream.write(result.stdout + result.stderr)
    if result.returncode:
        raise RuntimeError("INDEPENDENT_PREFLIGHT_FAILED")
    document = read(output)
    if document.get("status") != "passed_read_only_preflight":
        raise RuntimeError("INDEPENDENT_PREFLIGHT_NOT_PASSED")
    return document


def log_identity(stat: os.stat_result) -> tuple[int, int]:
    if not stat.st_ino:
        raise RuntimeError("CONTROL_LOG_IDENTITY_UNAVAILABLE")
    return stat.st_dev, stat.st_ino


def read_control_chunk(log: Path, expected_identity: tuple[int, int], offset: int) -> bytes:
    with log.open("rb") as stream:
        stat = os.fstat(stream.fileno())
        if log_identity(stat) != expected_identity or log_identity(log.stat()) != expected_identity:
            raise RuntimeError("CONTROL_LOG_REPLACED_UNKNOWN")
        if stat.st_size < offset:
            raise RuntimeError("CONTROL_LOG_TRUNCATED_UNKNOWN")
        stream.seek(offset)
        chunk = stream.read(256 * 1024)
        if log_identity(log.stat()) != expected_identity:
            raise RuntimeError("CONTROL_LOG_REPLACED_DURING_READ_UNKNOWN")
        return chunk


def execute(installation: Path, days: int, expected_date: int, output: Path,
            *, test_only: bool = False, expected_player_tag: str = "POR") -> dict:
    if expected_player_tag not in EXPECTED_PLAYER_TAGS:
        raise ValueError("expected_player_tag_must_be_POR_or_FRA")
    installation = installation.resolve()
    output = output.resolve()
    if not output.is_relative_to(ROOT / "work/runtime"):
        raise ValueError("output must remain under work/runtime")
    output.mkdir(parents=True, exist_ok=False)
    directory = installation.parent
    events: list[dict] = []
    published: bool | None = False
    log = directory / "control-probe.jsonl"
    outcome = {"schema": "BATTLE-NATURAL-WINDOW/1", "days": days,
               "start_raw": expected_date, "target_raw": None,
               "expected_physical_player_tag": expected_player_tag,
               "business_dispatch": False, "save_requested": False,
               "constructs_battle_or_diplomacy": False,
               "business_battle_complete": False, "visibility_verified": False}
    try:
        if test_only is not True or type(days) is not int or days not in (1, 5, 35):
            raise ValueError("EXPLICIT_TEST_ONLY_SUPPORTED_WINDOW_REQUIRED")
        if type(expected_date) is not int or expected_date < 0:
            raise ValueError("INVALID_EXPECTED_DATE")
        target = expected_date + days * 24
        if target > 0x7fffffff:
            raise ValueError("INVALID_TARGET_DATE")
        outcome["target_raw"] = target
        identity = read(installation)
        expected_creation = identity["creation_filetime"]
        before = probe(installation, output / "before.json")
        for phase in ("before", "after"):
            snapshot = before[phase]
            if (snapshot["game_date"]["raw"] != expected_date
                    or snapshot["control"]["paused"]["value"] is not True
                    or snapshot["control"]["speed"]["value"] != 0):
                raise RuntimeError("WINDOW_REQUIRES_EXACT_PAUSED_START")
        status = run_control(installation, "status")
        native = status["native"]
        if native["state"] != "enabled" or native["code_patch_installed"] is not True:
            raise RuntimeError("CAPTURE_NOT_ENABLED")
        for name in ("diplomacy-execute.req", "diplomacy-authority-test.req",
                     "game-control.request", "information-battle-control.request",
                     "information-battle-control.processing"):
            if (directory / name).exists():
                raise RuntimeError("PENDING_REQUEST_PREVENTS_WINDOW:" + name)
        current = probe_identity(identity["pid"], game_exe())
        if current["creation_filetime"] != expected_creation or current["session_id"] != identity["session_id"]:
            raise RuntimeError("PROCESS_CHANGED_NO_DISPATCH")
        with log.open("rb") as stream:
            stat = os.fstat(stream.fileno())
            expected_log_identity = log_identity(stat)
            offset = stat.st_size
            if offset:
                stream.seek(offset - 1)
                if stream.read(1) != b"\n":
                    raise RuntimeError("CONTROL_LOG_INCOMPLETE_BASELINE_NO_DISPATCH")
            if log_identity(log.stat()) != expected_log_identity:
                raise RuntimeError("CONTROL_LOG_REPLACED_NO_DISPATCH")
        write_new(output / "before-source-status.json", status)
        write_new(output / "window-intent.json", {
            **outcome, "identity": current, "control_log_offset": offset,
            "control_log_identity": list(expected_log_identity), "test_only": True,
            "expected_physical_player_tag": expected_player_tag,
            "installation_pin": pin(installation), "script_pin": pin(Path(__file__)),
            "authorization": "user goal and 开发过程自动化.md; TEST_ONLY natural observation",
            "no_replay": "no diplomacy requests/responses, no historical IDs, no battle construction",
        })
        published = None  # Publication exceptions have an ambiguous outcome, never a retry.
        publish_request(directory, f"TEST_ONLY advance_{days}_days\n", output, "advance")
        published = True
        deadline = time.monotonic() + 150
        pending = b""
        while time.monotonic() < deadline:
            chunk = read_control_chunk(log, expected_log_identity, offset)
            offset += len(chunk)
            pending += chunk
            while b"\n" in pending:
                line, pending = pending.split(b"\n", 1)
                if len(line) > 64 * 1024:
                    raise RuntimeError("OVERSIZE_CONTROL_RECORD")
                if not line.strip():
                    continue
                event = json.loads(line)
                if event.get("event") in ("control_advance_complete", "control_console_result",
                    "diplomacy_observer_health", "control_request_rejected"):
                    events.append(event)
            if len(pending) > 64 * 1024:
                raise RuntimeError("OVERSIZE_PARTIAL_CONTROL_RECORD")
            if len(events) > 4096:
                raise RuntimeError("CONTROL_EVENT_BUDGET")
            if check_completion(events, target, expected_player_tag):
                break
            time.sleep(0.2)
        else:
            raise TimeoutError("OBSERVATION_TIMEOUT_NO_RETRY")
        after = probe(installation, output / "after.json")
        for phase in ("before", "after"):
            snapshot = after[phase]
            if (snapshot["game_date"]["raw"] != target
                    or snapshot["control"]["paused"]["value"] is not True
                    or snapshot["control"]["speed"]["value"] != 0):
                raise RuntimeError("TARGET_DATE_OR_PAUSE_NOT_PROVEN")
        final_status = run_control(installation, "status")
        write_new(output / "after-source-status.json", final_status)
        outcome.update(status="observed_target_and_paused", request_published=True,
                       source_state=final_status["native"]["state"],
                       captured=final_status["native"]["captured"],
                       last_sequence=final_status["native"]["last_sequence"])
    except Exception as error:
        outcome.update(status="unknown_no_retry" if published is not False else "not_dispatched_or_publication_unknown",
                       request_published=published, error=type(error).__name__ + ":" + str(error),
                       automatic_retry=False)
        # No second request, process restart, or implicit business action.
        # A safety pause requires an explicit separately audited decision.
    write_new(output / "control-events.json", {"events": events})
    write_new(output / "report.json", outcome)
    return outcome


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--installation", type=Path, required=True)
    parser.add_argument("--days", type=int, choices=(1, 5, 35), required=True)
    parser.add_argument("--expected-date", type=int, required=True)
    parser.add_argument("--expected-player-tag", choices=EXPECTED_PLAYER_TAGS, default="POR")
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--test-only", action="store_true", required=True)
    args = parser.parse_args()
    report = execute(args.installation, args.days, args.expected_date, args.output_dir,
                     test_only=args.test_only, expected_player_tag=args.expected_player_tag)
    print(json.dumps(report))
    return 0 if report["status"] == "observed_target_and_paused" else 2


if __name__ == "__main__":
    raise SystemExit(main())
