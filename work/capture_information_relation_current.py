"""Capture one read-only production relation network and compare raw reference."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from bridge.information import relation_memory


def load(path):
    return json.loads(path.read_text(encoding="utf-8"))


def pin(path):
    with path.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    return {"path": str(path), "bytes": path.stat().st_size,
            "sha256": digest}


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2, sort_keys=True)
        stream.write("\n")


def run(args):
    if (args.output.exists() and not args.replay) or args.receipt.exists():
        raise FileExistsError("capture/receipt already exists")
    expected = load(args.expected)
    assert expected["status"] == "observed"
    assert expected["request"]["mode"] == "network"
    assert expected["raw_two_pass_consistent"] and expected["handle_closed"]
    installation = load(args.installation)
    families = ["alliance", "royal_marriage"]
    if args.replay:
        report = load(args.output)
    else:
        report = relation_memory.capture_network(args.installation, "FRA", families)
        write(args.output, report)
    valid = relation_memory.validate_network_capture(
        report, creation_filetime=installation["creation_filetime"],
        actor="FRA", families=families)
    checks = {"real_production_validator": valid is True,
              "completed": report.get("completed") is True}
    actual = {}
    for family in families:
        field = report.get("fields", {}).get(family, {})
        reference = expected["fields"][family]
        actual[family] = {"status": field.get("status"), "value": field.get("value")}
        # Both readers preserve native country table order; normalize only fullref
        # presentation (the production reader uses numeric hex, raw uses bytes).
        view = lambda rows: [(row["country"], row["slot"], row["active"]) for row in rows]
        checks[family + "_status_matches"] = field.get("status") == reference.get("status")
        checks[family + "_partners_match"] = view(field.get("value", [])) == view(reference.get("value", []))
    result = {"schema": "information_relation_current_raw_comparison.v1",
              "status": "passed" if all(checks.values()) else "failed",
              "checks": checks, "fields": actual,
              "independent_reference": pin(args.expected), "production_raw": pin(args.output),
              "production_source": pin(Path(relation_memory.__file__)),
              "offline_replay": args.replay,
              "read_only": True, "native_game_calls": False, "save_or_reload": False}
    write(args.receipt, result)
    print(json.dumps(result, ensure_ascii=False))
    return 0 if result["status"] == "passed" else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--replay", action="store_true", help="compare existing --output raw; no RPM")
    for name in ("installation", "expected", "output", "receipt"):
        parser.add_argument("--" + name, type=Path)
    args = parser.parse_args()
    if not args.run:
        parser.print_help()
        return 0
    if any(getattr(args, name) is None for name in ("installation", "expected", "output", "receipt")):
        parser.error("--run requires --installation, --expected, --output and --receipt")
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())
