"""Cross-check fresh public values against a fixed historical save, by streaming.

Matching values corroborate the captured sample. They do not prove world
generation identity or authorize replacing a live query with this save.
"""
from __future__ import annotations
import argparse
from decimal import Decimal
import hashlib
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from work.local_config import user_data
from work.verify_r71_favor_save import brace_delta
from work import inspect_peace_subject_save as subjects

EXPECTED_SHA = "ffa91dbd2a2d544b18d586a895bb9b0c2b90e94ece47b2c74507555b8f58c2e0"
SAVE_NAME = "llm_diplomacy_r70_country_money_rejected_20261020.eu4"


def load(path):
    if path.stat().st_size > 16 * 1024 * 1024:
        raise ValueError("JSON exceeds budget")
    return json.loads(path.read_text(encoding="utf-8"))


def scan_prestige(path):
    before = path.stat()
    depth = 0
    countries_depth = country_depth = None
    country_count = 0
    country_complete = countries_complete = False
    dates, values = [], []
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        ordinal = 0
        while True:
            line = stream.readline(1024 * 1024 + 1)
            if not line:
                break
            ordinal += 1
            if len(line) > 1024 * 1024:
                raise ValueError("Save line exceeds streaming budget")
            if ordinal == 1 and not line.startswith(b"EU4txt"):
                raise ValueError("Expected EU4txt save")
            digest.update(line)
            stripped = line.strip()
            if depth == 0:
                match = re.fullmatch(rb'date\s*=\s*"?(\d+\.\d+\.\d+)"?', stripped)
                if match:
                    dates.append(match.group(1).decode("ascii"))
                if stripped == b"countries={":
                    if countries_depth is not None or countries_complete:
                        raise ValueError("Duplicate countries block")
                    countries_depth = depth + 1
            elif countries_depth is not None and depth == countries_depth and stripped == b"FRA={":
                country_count += 1
                country_depth = depth + 1
            elif country_depth is not None and depth == country_depth:
                match = re.fullmatch(rb"prestige\s*=\s*([-+]?\d+(?:\.\d*)?)", stripped)
                if match:
                    number = Decimal(match.group(1).decode("ascii"))
                    raw = number * 1000
                    if raw != raw.to_integral_value() or not -2**31 <= raw < 2**31:
                        raise ValueError("Prestige does not fit the scale1000 int32 contract")
                    values.append({"line": ordinal, "decimal": str(number), "raw": int(raw),
                                   "source": stripped.decode("ascii"), "scale": 1000})
            next_depth = depth + brace_delta(line)
            if next_depth < 0:
                raise ValueError("Invalid save brace nesting")
            if country_depth is not None and next_depth < country_depth:
                country_complete = True
                country_depth = None
            if countries_depth is not None and next_depth < countries_depth:
                countries_complete = True
                countries_depth = None
            depth = next_depth
    after = path.stat()
    if ((before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns)
            or depth != 0 or country_count != 1 or not country_complete
            or not countries_complete or len(values) != 1 or len(dates) != 1):
        raise ValueError("Save membership, completeness, date or file stability failed")
    if digest.hexdigest() != EXPECTED_SHA:
        raise ValueError("Historical save SHA mismatch")
    return {"sha256": digest.hexdigest(), "bytes": after.st_size, "date": dates[0],
            "country": "FRA", "prestige": values[0], "full_braces_closed": True,
            "streaming": True, "max_line_bytes": 1024 * 1024}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise ValueError("New output required")
    save = user_data() / "save games" / SAVE_NAME
    report = {"status": "failed", "save_is_recorded": True, "not_a_live_state_fallback": True,
              "world_generation_verified": False}
    try:
        native = load(args.capture)
        if native.get("status") != "passed":
            raise ValueError("Native reference capture failed")
        parsed = scan_prestige(save)
        relation = subjects.scan_save(save, {"FRA", "ORL", "PAP"})
        public = native["captures"]["PAP"]["public"]
        if parsed["prestige"]["raw"] != public["prestige_raw"] or public["prestige_scale"] != 1000:
            raise ValueError("Prestige sample differs from historical save")
        matches = [r for r in relation["records"] if {r.get("first"), r.get("second")} == {"FRA", "ORL"}]
        if len(matches) != 1 or matches[0].get("subject_type") != "appanage":
            raise ValueError("Expected one saved FRA/ORL appanage record")
        if (not relation["scan"].get("diplomacy_block_found")
                or not relation["scan"].get("diplomacy_block_complete")
                or not relation["scan"].get("brace_balance_ok")
                or relation["scan"].get("unknown")):
            raise ValueError("Historical diplomacy scan incomplete")
        report.update(status="passed", save_path=str(save), save=parsed, saved_relation=matches[0],
                      subject_scan=relation["scan"], native_capture_sha256=hashlib.sha256(args.capture.read_bytes()).hexdigest(),
                      scope="Current prestige sample and selected ORL relation agree with the fixed historical save")
    except Exception as exc:
        report["error"] = {"type": type(exc).__name__, "message": str(exc)}
        raise
    finally:
        args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": report["status"], "prestige": report["save"]["prestige"]}))


if __name__ == "__main__":
    main()
