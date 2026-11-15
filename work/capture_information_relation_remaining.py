"""Capture the two new read-only relation children against independent bytes.

Default/help are inert.  --replay reuses the original production reports and
never opens the game process.  Large production reports are streamed to disk;
the receipt contains only the normalized comparison and immutable pins.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
STAGE = ROOT / "work/runtime/information-relation-remaining-20261027-001"
INSTALLATION = ROOT / "work/runtime/diplomacy-observer-20261026-information-battle-v27-002/installation.json"


def load(path: Path, limit: int = 8 * 1024 * 1024):
    if not 0 < path.stat().st_size <= limit:
        raise ValueError(f"json_size_out_of_bound:{path}")
    with path.open(encoding="utf-8-sig") as stream:
        return json.load(stream)


def pin(path: Path):
    with path.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    return {"path": str(path.relative_to(ROOT)), "bytes": path.stat().st_size, "sha256": digest}


def write(path: Path, value):
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2, sort_keys=True)
        stream.write("\n")


def run(args) -> int:
    from bridge.information import fleet_basing_memory, trade_league_memory

    if args.receipt.exists():
        raise FileExistsError(args.receipt)
    args.output.mkdir(parents=True, exist_ok=args.replay)
    installation = load(args.installation)
    fleet = load(STAGE / "expected-fleet-basing-projection-001.json")
    trade = load(STAGE / "expected-trade-league-current-001.json")
    date = fleet["context"]["game_date"]
    if isinstance(date, dict):
        date = date["value"]
    context = {"session_id": installation["session_id"], "game_date": date}
    cases = (("fleet_basing", "FRA", fleet_basing_memory),
             ("trade_league", "FRA", trade_league_memory),
             ("trade_league", "HSA", trade_league_memory))
    checks = {}
    observations = []
    for family, actor, module in cases:
        path = args.output / f"{family}-{actor}.json"
        if args.replay:
            # The production child record is capped explicitly. This is not
            # the 76 MiB independent probe or the 29 MiB independent reference.
            report = load(path, 64 * 1024 * 1024)
        else:
            report = module.capture(args.installation, actor, None)
            write(path, report)
        prefix = f"{family}_{actor}"
        checks[prefix + "_production_validator"] = module.validate_capture(
            report, context, installation["creation_filetime"], actor, None) is True
        checks[prefix + "_completed"] = report.get("completed") is True
        access = report.get("access", {})
        checks[prefix + "_no_game_calls_or_writes"] = (
            access.get("native_game_calls") is False and access.get("target_memory_writes") is False)
        field = report.get("fields", {}).get(family, {})
        checks[prefix + "_field_known"] = field.get("status") == "known"
        values = field.get("value", [])
        if family == "fleet_basing":
            actual = {direction: [row["country"] for row in values if row.get("direction") == direction]
                      for direction in ("received", "granted")}
            expected = {direction: [row["country"] for row in fleet["actors"][actor]["fields"][direction]["value"]]
                        for direction in ("received", "granted")}
        else:
            actual = [row["country"] for row in values]
            expected = [row["country"] for row in trade["fields"][actor]["members"]["value"]
                        if row["country"] != actor]
            checks[prefix + "_leader"] = field.get("league_leader") == ("HSA" if actor == "HSA" else None)
        checks[prefix + "_independent_partners_match"] = actual == expected
        observations.append({"family": family, "actor": actor, "public_actor": actor == "FRA",
                             "value": actual, "raw": pin(path), "source": pin(Path(module.__file__)),
                             "profile": pin(module.PROFILE_FILE)})
        del report
    receipt = {"schema": "information_relation_remaining_production_comparison.v1",
               "status": "passed" if all(checks.values()) else "failed", "checks": checks,
               "observations": observations, "session_id": installation["session_id"], "game_date": date,
               "references": [pin(STAGE / "expected-fleet-basing-projection-001.json"),
                              pin(STAGE / "expected-trade-league-current-001.json")],
               "read_only": True, "native_game_calls": False, "target_memory_writes": False,
               "offline_replay": args.replay, "save_restart_or_date_advance": False,
               "fleet_positive_runtime_sample": False}
    write(args.receipt, receipt)
    print(json.dumps(receipt, ensure_ascii=False))
    return 0 if receipt["status"] == "passed" else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--replay", action="store_true")
    parser.add_argument("--installation", type=Path, default=INSTALLATION)
    parser.add_argument("--output", type=Path, default=STAGE / "production-capture-001")
    parser.add_argument("--receipt", type=Path, default=STAGE / "production-comparison-001.json")
    args = parser.parse_args()
    if not args.run:
        parser.print_help()
        return 0
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())
