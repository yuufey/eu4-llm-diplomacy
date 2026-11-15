"""Compare a fresh native sample with already parsed, fixed historical save fields."""
from __future__ import annotations

import argparse
from decimal import Decimal
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from work.freeze_information_country_powers import read_json_bounded, sha256_file, _write_json_new

SAVE_SHA = "ffa91dbd2a2d544b18d586a895bb9b0c2b90e94ece47b2c74507555b8f58c2e0"
SURVEY_SHA = "b3f2ccf6ac9d35f129a39a615b9c2af27a95550fadf74e5997b4770c61cb874f"
FIELDS = ("stability", "war_exhaustion", "corruption")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture", type=Path, required=True)
    parser.add_argument("--survey", type=Path, default=ROOT / "work/runtime/information-domestic-pressure-20261025-001/save-scalars-survey-001.json")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise FileExistsError(args.output)
    survey, survey_size, survey_sha = read_json_bounded(args.survey)
    capture, capture_size, capture_sha = read_json_bounded(args.capture)
    if survey_sha != SURVEY_SHA or survey["source"]["sha256"] != SAVE_SHA:
        raise ValueError("historical_survey_identity_changed")
    save_size, actual_save_sha = sha256_file(Path(survey["source"]["path"]))
    if actual_save_sha != SAVE_SHA or save_size != survey["source"]["bytes"]:
        raise ValueError("historical_save_identity_changed")
    if not (survey["status"] == "passed" and survey["save_is_recorded"] is True
            and survey["scope"]["country"]["complete"] is True
            and survey["date"]["date"] == "1455.11.13"):
        raise ValueError("historical_survey_incomplete")
    if not (capture["status"] == "observed" and capture["completed"] is True
            and capture["complete"] is True and capture["country"] == "FRA"
            and capture["before"]["game_date"]["value"] == 56553384
            == capture["after"]["game_date"]["value"]
            and capture["read_only"] is True and capture["native_function_invoked"] is False):
        raise ValueError("current_native_capture_incomplete")
    comparisons = {}
    for field in FIELDS:
        saved = survey["direct_fields"][field]
        if not (saved["status"] == "observed" and saved["direct"] is True
                and saved["scope_closed"] is True and len(saved["hits"]) == 1):
            raise ValueError(f"historical_direct_field_ambiguous:{field}")
        hit = saved["hits"][0]
        live = capture["field_results"][field]
        if live["status"] != "known" or live["scale"] != 1000:
            raise ValueError(f"native_field_not_known:{field}")
        scaled = Decimal(hit["raw_value"]) * Decimal(1000)
        if scaled != scaled.to_integral_value():
            raise ValueError(f"historical_literal_not_exact_at_native_scale:{field}")
        comparisons[field] = {"saved_literal": hit["raw_value"], "saved_line": hit["line"],
                              "native_raw": live["raw"], "native_scale": live["scale"],
                              "equal": int(scaled) == live["raw"]}
    report = {"status": "passed", "mode": "recorded", "save_is_recorded": True,
              "save_sha256": SAVE_SHA, "source": survey["source"], "date": survey["date"],
              "survey": {"path": str(args.survey), "sha256": survey_sha, "bytes": survey_size},
              "native_capture": {"path": str(args.capture), "sha256": capture_sha, "bytes": capture_size},
              "fields": comparisons, "all_equal": all(x["equal"] for x in comparisons.values()),
              "world_generation_verified": False, "not_a_live_state_fallback": True,
              "claim": "literal equality with a historical save only; current values come exclusively from the separately guarded native capture",
              "source_sha256": sha256_file(Path(__file__))[1]}
    _write_json_new(args.output, report, overwrite=False)
    print(json.dumps(report, ensure_ascii=False))


if __name__ == "__main__":
    main()
