"""Record OS exit for a separate read-only MCP health probe.

The direct exit applies to this probe only. Acceptance 005 keeps its original
report; its successful close is inferred from the pinned runner control flow.
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
from work.local_config import game_exe
from work.run_alliance_inbound_response import control_snapshot
from work.validate_information_domestic_pressure import CompactMCPClient


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--installation", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args()
    if args.receipt.exists():
        raise FileExistsError(args.receipt)
    args.output.mkdir(parents=True, exist_ok=False)
    session = ObserverSession(args.installation.resolve(strict=True), game_exe())
    pid = session.record["pid"]
    before = control_snapshot(pid, args.output / "before-control.json")
    keys = ("player_slot", "date_raw", "speed", "paused_flag")
    assert before["player_slot"] == 189 and before["speed"] == 0 and before["paused_flag"] == 1
    client = None
    report = {"schema": "information_mcp_server_closure_receipt_v1", "status": "failed",
              "evidence_kind": "standalone_health_probe", "session_id": session.session_id,
              "pid": pid, "creation_filetime": session.record["creation_filetime"],
              "game_date": before["date_raw"], "installation_sha256": sha(args.installation),
              "native_subprocess_exit_evidence": False, "wire_exit_evidence": False,
              "relation": {"original_live_005_returncode": "not_recorded",
                           "original_live_005_close": "runner close/wait/returncode control-flow inference only",
                           "direct_os_exit_applies_to": "standalone_health_probe"},
              "source_files": {
                  "base_validator_sha256": sha(ROOT / "work/validate_information_domestic_pressure.py"),
                  "runner_sha256": sha(ROOT / "work/validate_information_domestic_pressure_live_004.py"),
                  "tools/serve_information.py": sha(ROOT / "tools/serve_information.py"),
                  "probe_sha256": sha(Path(__file__))}}
    try:
        client = CompactMCPClient(args.installation.resolve(), args.output)
        server_pid = client.process.pid
        status = client.call("information_status")
        context = status["context"]
        assert context["session_id"] == session.session_id and context["game_date"] == before["date_raw"]
        client.close()
        code = client.process.poll()
        assert code == 0 and client.closed and not client.reader.is_alive()
        report["server_process"] = {"pid": server_pid, "status": "closed", "returncode": code}
        report["close"] = {"close_called": True, "wait_completed": True, "closed": client.closed,
                           "reader_thread_joined": not client.reader.is_alive()}
        after = control_snapshot(pid, args.output / "after-control.json")
        assert {key: before[key] for key in keys} == {key: after[key] for key in keys}
        report.update(status="passed", paused_date_preserved=True,
                      wire_audit_sha256=sha(args.output / "mcp-wire-audit.json"))
    except Exception as exc:
        report["error"] = {"type": type(exc).__name__, "message": str(exc)}
    finally:
        if client is not None and not client.closed:
            client.close()
        with args.receipt.open("x", encoding="utf-8") as stream:
            json.dump(report, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
    print(json.dumps(report, ensure_ascii=False))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
