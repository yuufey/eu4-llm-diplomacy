"""Bind a new installed collector once, then leave it disabled for leases."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.control_information_battle_observer import run_control
from work.verify_information_battle_autonomous import read, put


EXPECTED_PLAYER_TAGS = ("POR", "FRA")


def validate_preflight(audit, expected_date, expected_player_tag="POR"):
    """Return the exact physical fullref after checking both paused snapshots."""
    if expected_player_tag not in EXPECTED_PLAYER_TAGS:
        raise ValueError("expected_player_tag_must_be_POR_or_FRA")
    if audit.get("status") != "passed_read_only_installed_preflight":
        raise ValueError("preflight_failed")

    references = []
    for phase in ("before", "after"):
        world = audit[phase]
        physical = world["physical_player"]
        if (world["game_date"]["raw"] != expected_date
                or physical.get("tag") != expected_player_tag
                or physical.get("complete") is not True
                or world["control"]["speed"]["value"] != 0
                or world["control"]["paused"]["value"] is not True):
            raise ValueError("world_differs")
        try:
            reference = int(physical["value"], 16)
        except (KeyError, TypeError, ValueError) as error:
            raise ValueError("physical_player_fullref_invalid") from error
        if not 0 < reference <= 0xFFFFFFFFFFFFFFFF:
            raise ValueError("physical_player_fullref_invalid")
        references.append(reference)
    if references[0] != references[1]:
        raise ValueError("physical_player_changed_during_preflight")
    # This value comes from the preflight's full raw reference; the tag is only
    # a guard and is never used to synthesize a player_ref.
    return f"{references[1]:016x}"


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--installation", type=Path, required=True)
    p.add_argument("--preflight", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--expected-date", type=int, required=True)
    p.add_argument("--expected-player-tag", choices=EXPECTED_PLAYER_TAGS, default="POR")
    p.add_argument("--test-only", action="store_true", required=True)
    args = p.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    audit = read(args.preflight)
    physical = validate_preflight(audit, args.expected_date, args.expected_player_tag)
    directory = args.installation.parent
    if (directory / "information-battle-binding.json").exists():
        raise ValueError("already_bound_no_retry")
    pending = [x.name for x in directory.iterdir() if x.name.endswith((".req", ".request", ".processing", ".intent"))]
    if pending:
        raise ValueError("pending_requests")
    before = run_control(args.installation, "status")
    put(args.output / "status-before.json", before)
    if before["native"]["state"] != "ready" or int(before["native"]["captured"]) != 0:
        raise ValueError("source_not_new_ready")
    put(args.output / "intent.json", {"purpose": "new installation bootstrap only", "player_ref": physical,
                                       "physical_player_tag": args.expected_player_tag,
                                       "test_only": True, "business_dispatch": False, "retry_authorized": False})
    enabled = run_control(args.installation, "enable", physical)
    put(args.output / "enable.json", enabled)
    if enabled["status"] != "accepted" or enabled["response"]["state"] != "enabled":
        raise ValueError("bootstrap_enable_not_accepted_no_retry")
    disabled = run_control(args.installation, "disable")
    put(args.output / "disable.json", disabled)
    if disabled["status"] != "accepted" or disabled["response"]["state"] != "disabled":
        raise ValueError("bootstrap_disable_not_accepted_no_retry")
    deadline = time.monotonic() + 3.0
    while True:
        final = run_control(args.installation, "status")
        if final["native"]["state"] == "disabled" and final["native"]["code_patch_installed"] is True:
            break
        if time.monotonic() >= deadline:
            put(args.output / "status-timeout.json", final)
            raise ValueError("bootstrap_status_timeout_no_control_retry")
        time.sleep(0.1)
    put(args.output / "status-after.json", final)
    put(args.output / "report.json", {"status": "passed", "player_ref": physical,
        "physical_player_tag": args.expected_player_tag,
        "native_state": final["native"]["state"], "control_requests": 2,
        "business_dispatch": False, "advance": False, "save": False})
    print(json.dumps({"status": "passed", "physical_ref": physical, "binding": final["binding"]}))


if __name__ == "__main__":
    main()
