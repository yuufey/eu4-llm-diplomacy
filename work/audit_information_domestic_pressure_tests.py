"""Audit completed N04 offline tests against the sealed ninth-batch baseline."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from work.audit_information_country_powers_tests import build_summary, _artifact

STAGE = ROOT / "work/runtime/information-domestic-pressure-20261025-001"
BASELINE = ROOT / "work/runtime/information-country-scalars-20261024-001"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stage", type=Path, default=STAGE)
    parser.add_argument("--exit-code", type=int, required=True)
    args = parser.parse_args()
    stage = args.stage.resolve()
    output = stage / "test-summary.json"
    if output.exists():
        raise FileExistsError(output)
    values = dict(current_xml=stage / "full-pytest.xml", current_log=stage / "full-pytest.log",
                  baseline_xml=BASELINE / "pytest-full.xml", baseline_log=BASELINE / "pytest-full.log",
                  baseline_summary=BASELINE / "test-summary.json", output=output,
                  directed_xml=stage / "information-pytest-002.xml",
                  directed_log=stage / "information-pytest-002.log",
                  fixture=None, compile_audit=None, source_audit=None, live_report=None,
                  native_report=None, save_crosscheck=None,
                  command="python -m pytest -q bridge/tests --junitxml=work/runtime/information-domestic-pressure-20261025-001/full-pytest.xml",
                  exit_code=args.exit_code)
    # Reuse the streaming duplicate-node/message comparison without importing
    # any native reader or connecting a session.
    summary = build_summary(SimpleNamespace(**values))
    summary["schema"] = "information-domestic-pressure-offline-regression-audit-v1"
    summary["targeted_domestic_pressure_checkpoint"] = summary.pop("targeted_powers_checkpoint")
    summary.pop("evidence_checkpoints")
    summary["live_validation"] = {"status": "pending", "native_capture_available": False,
                                  "reason": "The historical process exited; no eu4.exe was present at preflight."}
    summary["goal_complete"] = False
    summary["source_files"] = {name: _artifact(ROOT / name) for name in (
        "bridge/information/domestic_pressure_memory.py", "bridge/information/domestic_pressure.py",
        "bridge/information/profiles/domestic-pressure-memory-1374.json", "tools/serve_information.py",
        "bridge/tests/test_information_domestic_pressure_memory.py",
        "bridge/tests/test_information_domestic_pressure.py",
    )}
    summary["artifacts"]["preflight_failure"] = _artifact(stage / "independent-native-001/report.json")
    summary["artifacts"]["audit_helper"] = _artifact(ROOT / "work/audit_information_country_powers_tests.py")
    summary["artifacts"]["audit_script"] = _artifact(Path(__file__))
    # Store portable repository paths for downstream pin verification.
    def portable(value):
        if isinstance(value, dict):
            for key, child in value.items():
                if key in {"path", "directory"} and isinstance(child, str):
                    path = Path(child)
                    if path.is_absolute() and path.resolve().is_relative_to(ROOT):
                        value[key] = path.resolve().relative_to(ROOT).as_posix()
                else:
                    portable(child)
        elif isinstance(value, list):
            for child in value:
                portable(child)
    portable(summary)
    output.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"path": output.relative_to(ROOT).as_posix(),
                      "information": summary["information"]["case_element_statuses"],
                      "failure_comparison": summary["failure_error_node_comparison"],
                      "live_validation": summary["live_validation"]}, ensure_ascii=False))


if __name__ == "__main__":
    main()
