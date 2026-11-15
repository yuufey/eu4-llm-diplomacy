"""Use the existing natural-window runner with the v23/v24 artifact probe."""
from __future__ import annotations

import argparse
from pathlib import Path
import json
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from work import run_information_battle_natural_window as window
from work.probe_information_battle_installed import run as installed_probe


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--installation", type=Path, required=True)
    parser.add_argument("--days", type=int, choices=(1, 5, 35), required=True)
    parser.add_argument("--expected-date", type=int, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--expected-manifest-sha256", required=True)
    parser.add_argument("--expected-dll-sha256", required=True)
    parser.add_argument("--test-only", action="store_true", required=True)
    args = parser.parse_args()
    provider = args.output_dir.parent / (args.output_dir.name + "-provider.json")
    window.write_new(provider, {
        "adapter": window.pin(Path(__file__)), "executor": window.pin(Path(window.__file__)),
        "probe": window.pin(ROOT / "work/probe_information_battle_installed.py"),
        "expected_manifest_sha256": args.expected_manifest_sha256,
        "expected_dll_sha256": args.expected_dll_sha256, "test_only": args.test_only})

    def probe(installation: Path, output: Path) -> dict:
        report = installed_probe(installation, output,
            expected_manifest_sha256=args.expected_manifest_sha256,
            expected_dll_sha256=args.expected_dll_sha256, expect_patch="installed")
        if report["status"] != "passed_read_only_installed_preflight":
            raise RuntimeError("INSTALLED_ARTIFACT_PREFLIGHT_FAILED")
        return report

    # The executor and its single-publication/timeout policy are unchanged.
    window.probe = probe
    result = window.execute(args.installation, args.days, args.expected_date,
        args.output_dir, test_only=args.test_only)
    print(json.dumps(result))
    return 0 if result["status"] == "observed_target_and_paused" else 2


if __name__ == "__main__":
    raise SystemExit(main())
