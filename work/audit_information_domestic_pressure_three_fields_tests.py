"""Audit the final three-field N04 test artifacts against batch nine.

This wrapper only parses already-produced JUnit XML/log files.  It reuses the
bounded streaming counter and duplicate failure/message comparison from the
country-powers audit helper, but writes a new versioned three-field summary
without changing any historical summary.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from work.audit_information_country_powers_tests import _artifact, build_summary  # noqa: E402


STAGE = ROOT / "work/runtime/information-domestic-pressure-20261025-001"
BASELINE = ROOT / "work/runtime/information-country-scalars-20261024-001"
NATIVE_FIELDS = ("stability", "war_exhaustion", "corruption")
PLANNED_FIELDS = ("religious_unity", "overextension", "unrest")
SOURCE_FILES = (
    "bridge/information/domestic_pressure_memory.py",
    "bridge/information/domestic_pressure.py",
    "bridge/information/profiles/domestic-pressure-memory-1374.json",
    "bridge/information/composite.py",
    "bridge/information/catalog.py",
    "tools/serve_information.py",
    "bridge/tests/test_information_domestic_pressure_memory.py",
    "bridge/tests/test_information_domestic_pressure.py",
    "work/capture_information_domestic_pressure.py",
    "work/validate_information_domestic_pressure.py",
    "work/verify_information_domestic_pressure.py",
    "work/audit_information_domestic_pressure_three_fields_tests.py",
    "work/audit_information_domestic_pressure_three_fields_offline.py",
)


def _workspace_file(path: Path, label: str) -> Path:
    candidate = path.expanduser().resolve()
    if not candidate.is_relative_to(ROOT.resolve()):
        raise ValueError(f"{label} is outside the workspace: {candidate}")
    if not candidate.is_file():
        raise FileNotFoundError(f"{label} is missing: {candidate}")
    return candidate


def _relative_pin(path: Path) -> dict:
    source = _workspace_file(path, "source file")
    item = _artifact(source)
    item["path"] = source.relative_to(ROOT.resolve()).as_posix()
    return item


def _source_pins() -> dict[str, dict]:
    return {name: _relative_pin(ROOT / name) for name in SOURCE_FILES}


def _portable(value):
    if isinstance(value, dict):
        for key, child in value.items():
            if key in {"path", "directory"} and isinstance(child, str):
                candidate = Path(child)
                if candidate.is_absolute():
                    try:
                        value[key] = candidate.resolve().relative_to(ROOT.resolve()).as_posix()
                    except ValueError:
                        pass
            else:
                _portable(child)
    elif isinstance(value, list):
        for child in value:
            _portable(child)


def build_three_field_summary(args: argparse.Namespace) -> dict:
    stage = Path(args.stage).expanduser().resolve()
    if not stage.is_relative_to(ROOT.resolve()) or not stage.is_dir():
        raise NotADirectoryError(stage)
    output = _workspace_file(Path(args.output), "existing output") if Path(args.output).exists() else Path(args.output).resolve()
    if not output.is_relative_to(ROOT.resolve()):
        raise ValueError(f"output is outside the workspace: {output}")
    if output.exists():
        raise FileExistsError(output)

    current_xml = _workspace_file(stage / args.current_xml, "current full JUnit XML")
    current_log = _workspace_file(stage / args.current_log, "current full pytest log")
    directed_xml = _workspace_file(stage / args.directed_xml, "directed JUnit XML")
    directed_log = _workspace_file(stage / args.directed_log, "directed pytest log")
    baseline_xml = _workspace_file(BASELINE / args.baseline_xml, "batch-nine JUnit XML")
    baseline_log = _workspace_file(BASELINE / args.baseline_log, "batch-nine pytest log")
    baseline_summary = _workspace_file(BASELINE / args.baseline_summary, "batch-nine test summary")

    values = SimpleNamespace(
        current_xml=current_xml,
        current_log=current_log,
        baseline_xml=baseline_xml,
        baseline_log=baseline_log,
        baseline_summary=baseline_summary,
        output=output,
        directed_xml=directed_xml,
        directed_log=directed_log,
        fixture=None,
        compile_audit=None,
        source_audit=None,
        live_report=None,
        native_report=None,
        save_crosscheck=None,
        command=(
            "python -m pytest -q bridge/tests "
            "--junitxml=work/runtime/information-domestic-pressure-20261025-001/full-pytest-002.xml"
        ),
        exit_code=args.exit_code,
    )
    summary = build_summary(values)
    targeted = summary.get("targeted_powers_checkpoint")
    if not isinstance(targeted, dict) or targeted.get("status") != "passed":
        raise ValueError("targeted_domestic_pressure_checkpoint_not_clean")
    summary["schema"] = "information-domestic-pressure-three-fields-regression-audit-v2"
    summary["field_scope"] = {
        "native_fields": list(NATIVE_FIELDS),
        "planned_fields": list(PLANNED_FIELDS),
        "native_coverage": "partial",
        "religious_unity_runtime_validation": "not_attempted",
    }
    summary["targeted_domestic_pressure_checkpoint"] = summary.pop("targeted_powers_checkpoint")
    summary.pop("evidence_checkpoints", None)
    summary["live_validation"] = {
        "status": "pending",
        "native_capture_available": False,
        "mcp_acceptance": False,
        "reason": "The test audit contains no current game-process capture or live MCP result.",
    }
    summary["goal_complete"] = False
    summary["source_files"] = _source_pins()
    summary.setdefault("artifacts", {})["audit_script"] = _relative_pin(Path(__file__))
    summary["notes"] = list(summary.get("notes", [])) + [
        "This version audits the effective three-field N04 contract; religious_unity remains a planned field.",
        "The audit parses completed JUnit/log artifacts and does not rerun pytest, the game, RPM, MCP, or REA.",
    ]
    _portable(summary)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stage", type=Path, default=STAGE)
    parser.add_argument("--output", type=Path, default=STAGE / "test-summary-002.json")
    parser.add_argument("--current-xml", default="full-pytest-002.xml")
    parser.add_argument("--current-log", default="full-pytest-002.log")
    parser.add_argument("--directed-xml", default="information-pytest-003.xml")
    parser.add_argument("--directed-log", default="information-pytest-003.log")
    parser.add_argument("--baseline-xml", default="pytest-full.xml")
    parser.add_argument("--baseline-log", default="pytest-full.log")
    parser.add_argument("--baseline-summary", default="test-summary.json")
    parser.add_argument("--exit-code", type=int, required=True,
                        help="exit code recorded by the already completed full pytest run")
    args = parser.parse_args(argv)
    summary = build_three_field_summary(args)
    print(json.dumps({
        "path": Path(args.output).resolve().relative_to(ROOT.resolve()).as_posix(),
        "schema": summary["schema"],
        "status": summary["status"],
        "information": summary["information"]["case_element_statuses"],
        "targeted": summary["targeted_domestic_pressure_checkpoint"]["case_element_statuses"],
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
