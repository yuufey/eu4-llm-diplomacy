"""Capture a fresh, bounded pure-RPM power sample without game calls."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from bridge.diplomacy import ObserverSession
from bridge.information.country_resources_memory import capture
from work.local_config import game_exe
from work.run_alliance_inbound_response import control_snapshot
from work.validate_information_live import sha, write


def require(value, reason):
    if not value:
        raise ValueError(reason)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--installation", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--save-reference", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    report = {"status": "failed", "pure_RPM": True, "native_function_invoked": False,
              "business_actions_submitted": False, "date_advance": False,
              "save_or_reload": False, "dll_installation": False, "checks": {}}
    try:
        session = ObserverSession(args.installation, game_exe())
        before = control_snapshot(session.record["pid"], args.output / "before-control.json")
        require((before["player_slot"], before["paused_flag"], before["date_raw"], before["speed"])
                == (189, 1, 56553384, 0), "Unexpected initial controls")
        health = session.health()
        write(args.output / "before-health.json", health)
        require(health["status"] == "ready", "Session not ready")
        raw = capture(args.installation, "FRA")
        raw_path = args.output / "native-capture.json"
        write(raw_path, raw)
        require(raw["status"] == "observed" and raw["completed"] is True, "Native capture failed")
        require(raw["native_function_invoked"] is False and raw["read_only"] is True, "Reader scope differs")
        require(raw["identity"]["installation_session_id"] == session.session_id, "Session differs")
        require(raw["identity"]["process_creation_filetime"] == session.record["creation_filetime"], "Creation differs")
        require(raw["before"]["game_date"]["value"] == before["date_raw"]
                == raw["after"]["game_date"]["value"], "Native dates differ")
        require(raw["doublepass"]["consistent"] is True, "Read passes differ")
        require(raw["cleanup"]["handle_close"]["status"] == "closed", "Handle not closed")
        report["checks"]["pure_rpm_guarded_doublepass"] = True
        require(args.save_reference.stat().st_size < 1024 * 1024, "Save reference too large")
        saved = json.loads(args.save_reference.read_text("utf-8"))
        # The save's own component labels remain unproven. We compare its
        # ordered sample with the independently labelled native component order.
        vector = [raw["values"][key] for key in ("administrative", "diplomatic", "military")]
        require(saved["sha256"] == "ffa91dbd2a2d544b18d586a895bb9b0c2b90e94ece47b2c74507555b8f58c2e0"
                and saved["date"]["date"] == "1455.11.13", "Save reference identity differs")
        require(saved["powers"]["ordered_vector"] == vector, "Ordered saved/native samples differ")
        report["checks"]["ordered_sample_matches_recorded_save"] = True
        report["save_crosscheck"] = {
            "source": str(args.save_reference), "sha256": sha(args.save_reference),
            "world_generation_verified": False,
            "save_component_labels_independently_verified": False,
            "claim": "ordered sample equality only; native labels come from the REA contract",
        }
        after = control_snapshot(session.record["pid"], args.output / "after-control.json")
        require(before == after, "Control state changed")
        report["checks"]["pause_player_date_preserved"] = True
        report.update(status="passed", session_id=session.session_id,
                      game_sha256=session.record["game_sha256"], values=raw["values"],
                      date_raw=before["date_raw"], raw_capture_sha256=sha(raw_path),
                      source_sha256=sha(Path(__file__)), installation_sha256=sha(args.installation))
    except Exception as exc:
        report["error"] = {"type": type(exc).__name__, "message": str(exc)}
        raise
    finally:
        write(args.output / "report.json", report)
    print(json.dumps(report, ensure_ascii=False))


if __name__ == "__main__":
    main()
