"""Capture fresh public vassalization queries for prestige and pair relations.

The existing DLL executes its read-only native query predicates. This is not
a pure RPM capture and never submits a diplomatic action, installs, advances,
saves, or reloads the game. Existing runtime logs are only read from a newly
recorded byte offset; historical business requests are not replayed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from bridge.diplomacy import DiplomacyTools, ObserverSession
from work.local_config import game_exe
from work.run_alliance_inbound_response import control_snapshot

EXE_SHA = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
DLL_SHA = "d80ef39d66d263788c0af4df0892b4ff781e5e3b3f9aea7ebe33759327e457db"


def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(65536), b""):
            h.update(block)
    return h.hexdigest()


def write(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--installation", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    report = {"status": "failed", "read_only_native_query": True,
              "pure_RPM": False, "native_query_functions_invoked": True,
              "business_actions_submitted": False, "date_advance": False,
              "save_or_reload": False, "dll_installation": False}
    try:
        session = ObserverSession(args.installation, game_exe())
        require(session.record["game_sha256"] == EXE_SHA, "EXE mismatch")
        require(session.record["dll_sha256"] == DLL_SHA, "DLL mismatch")
        before = control_snapshot(session.record["pid"], args.output / "before-control.json")
        require((before["player_slot"], before["paused_flag"], before["date_raw"])
                == (189, 1, 56553384), "Unexpected initial controls")
        health = session.health()
        write(args.output / "before-health.json", health)
        require(health["status"] == "ready", "Session unready")
        tools = DiplomacyTools(None, session)
        log = session.directory / "control-probe.jsonl"
        captures = {}
        for recipient in ("PAP", "ORL"):
            offset = log.stat().st_size
            value = tools.inspect_diplomatic_action("offer_vassalization", "FRA", recipient, "initiate", {})
            write(args.output / (recipient + "-public.json"), value)
            require(isinstance(value, dict) and not value.get("error_code"), f"{recipient}: query unavailable")
            require((value.get("actor"), value.get("recipient"), value.get("action_id"), value.get("family"))
                    == ("FRA", recipient, "offer_vassalization", "vassalization"), "Projection identity mismatch")
            require(type(value.get("prestige_raw")) is int and value.get("prestige_scale") == 1000,
                    "Prestige value/scale unavailable")
            end = log.stat().st_size
            require(0 <= end - offset <= 262144, "Query log delta exceeds budget")
            with log.open("rb") as stream:
                stream.seek(offset)
                raw = stream.read(end - offset)
            require(not raw or raw.endswith(b"\n"), "Incomplete query log delta")
            (args.output / (recipient + "-new-log.jsonl")).write_bytes(raw)
            records = [json.loads(line) for line in raw.splitlines() if line]
            native = [record for record in records
                      if record.get("event") == "native_alliance_inspection"
                      and record.get("session_id") == session.session_id
                      and record.get("action_id") == "offer_vassalization"
                      and record.get("actor") == "FRA" and record.get("recipient") == recipient]
            require(len(native) == 1, "Expected exactly one matching new native inspection")
            event = native[0]
            require(event.get("submitted") is False, "Native query may have submitted an action")
            require(event.get("date_raw") == before["date_raw"], "Native query date mismatch")
            require(event.get("prestige_raw") == value["prestige_raw"], "Raw/public prestige mismatch")
            write(args.output / (recipient + "-native.json"), event)
            captures[recipient] = {"public": value, "native": event, "log_offset": offset, "log_end": end}
        after = control_snapshot(session.record["pid"], args.output / "after-control.json")
        require(before == after, "Controls changed during queries")
        after_health = session.health()
        write(args.output / "after-health.json", after_health)
        require(after_health["status"] == "ready" and after_health["date_raw"] == before["date_raw"], "Final health changed")
        report.update(status="passed", session_id=session.session_id, game_sha256=EXE_SHA, dll_sha256=DLL_SHA,
            installation_sha256=digest(args.installation), captures=captures,
            source_sha256=digest(Path(__file__)),
            source_contracts={name: digest(ROOT / name) for name in (
                "work/native/vassal-query.inc", "work/native/alliance-query.inc", "bridge/diplomacy.py")})
    except Exception as exc:
        report["error"] = {"type": type(exc).__name__, "message": str(exc)}
        raise
    finally:
        write(args.output / "report.json", report)
    print(json.dumps({k: report[k] for k in ("status", "session_id", "business_actions_submitted")}))


if __name__ == "__main__":
    main()
