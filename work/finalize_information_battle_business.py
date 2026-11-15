"""Freeze type/context components and bounded static evidence, keeping scope open."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from work.finalize_information_battle_live import coverage

STAGE = ROOT / "work/runtime/information-battle-business-20261025-001"
CONTEXT = ROOT / "work/runtime/information-battle-owned-context-20261025-001"
WIRE = ROOT / "work/runtime/information-battle-context-wire-20261025-001"
OUTPUT = STAGE / "development-summary-001.json"


def read(path: Path) -> dict:
    assert path.stat().st_size <= 2 * 1024 * 1024, path
    return json.loads(path.read_text(encoding="utf-8-sig"))


def pin(path: Path) -> dict:
    with path.open("rb") as stream:
        sha = hashlib.file_digest(stream, "sha256").hexdigest()
    return {"bytes": path.stat().st_size, "sha256": sha}


def check_sources(value: dict) -> None:
    """Compare every locally recorded source pin in final native reports."""
    if isinstance(value.get("path"), str) and isinstance(value.get("sha256"), str):
        path = Path(value["path"])
        path = path if path.is_absolute() else ROOT / path
        assert pin(path)["sha256"] == value["sha256"], path
    for child in value.values():
        if isinstance(child, dict):
            check_sources(child)


def assemble() -> dict:
    context = read(CONTEXT / "context-test-003/report.json")
    wire = read(WIRE / "context-wire-test-003/report.json")
    assert context["status"] == wire["status"] == "passed"
    assert context["compile"]["returncode"] == context["run"]["returncode"] == 0
    assert wire["compile"]["returncode"] == wire["run"]["returncode"] == 0
    check_sources(context["source_pins"])
    check_sources(wire["source_pins"])
    assert context["scope"]["game_access"] is False
    assert wire["scope"]["game_access"] is False
    assert wire["native_checks"]["capture_component_case"] is True
    assert wire["native_checks"]["failed"] == wire["decoder_checks"]["failed"] == 0
    assert wire["contract"]["business_flags"]["business_complete"] is False
    preservation = read(STAGE / "preservation-audit-001.json")
    # Exact audit schema is retained as an artifact; require no reported errors.
    assert not preservation.get("errors") and not preservation.get("mismatches")
    assert "pass" in preservation["status"]
    preflight = read(STAGE / "final-live-preflight-002.json")
    assert preflight["status"] == "passed_read_only_preflight"
    for phase in ("before", "after"):
        assert preflight[phase]["game_date"]["raw"] == 56554248
        assert preflight[phase]["control"]["paused"]["value"] is True
        assert preflight[phase]["control"]["speed"]["value"] == 0
    source_status = read(STAGE / "final-source-status-001.json")
    assert source_status["status"] == "observed" and source_status["native"]["state"] == "disabled"
    queries = []
    for name in ("rea-placeholder-evaluator-001", "rea-result-summary-effects-001", "rea-result-summary-prestige-001"):
        run = read(STAGE / name / "run.json")
        assert run["provider_exit_code"] == run["wrapper_exit_code"] == 0
        assert run["database_unchanged"] is True and run["query_reanalysis"] is False
        assert run["cleanup"]["closed_process_receipt"] is True and not run["cleanup"]["errors"]
        assert all(item["still_running_same_process"] is False
                   and item["peak_committed_bytes"] <= 1024**3 for item in run["processes"])
        queries.append({"name": name, "evidence_id": run["evidence_id"], "elapsed_seconds": run["elapsed_seconds"],
                        "processes": run["processes"], "database_unchanged": True})
    paths = {path for directory in (STAGE, CONTEXT, WIRE) for path in directory.rglob("*")
             if path.is_file() and path != OUTPUT}
    paths.update(ROOT / name for name in (
        "HANDOFF.md", "README(agent).md", "docs/信息导出与订阅开发计划.md", "docs/信息导出开发进展.md",
        "docs/逐场战报类型与原始上下文.md",
        "work/native/information-battle-owned-context.h", "work/native/test-information-battle-owned-context.cpp",
        "work/test_information_battle_owned_context.py", "work/native/information-battle-context-wire.h",
        "work/native/test-information-battle-context-wire.cpp", "work/information_battle_context_wire.py",
        "work/test_information_battle_context_wire.py", "work/survey_information_battle_business_fields.py",
        "work/survey_information_battle_visibility_paths.py", "work/survey_information_battle_service_integration.py",
        "work/probe_information_battle_context_contract.py", "work/probe_information_battle_placeholder_contract.py",
        "work/probe_information_battle_summary_effect_contract.py", "work/audit_information_battle_business_preservation.py",
    ))
    paths.add(Path(__file__).resolve())
    pins = {path.relative_to(ROOT).as_posix(): pin(path) for path in sorted(paths)}
    return {"schema": "INFORMATION-BATTLE-BUSINESS-DEVELOPMENT/1",
            "status": "owned_context_and_wire_verified_natural_business_acceptance_pending",
            "previous_goal_turn": "no_progress_single_http_explanation", "current_goal_turn": "progress_context_components_and_static_contracts",
            "goal_complete": False, "coverage": coverage(), "native_game_functions_invoked": False,
            "game_code_or_data_written": False, "new_dll_built_or_installed": False,
            "date_advanced": False, "battle_source_connected_to_information_service": False,
            "context_checks": context["checks"], "wire_native_checks": wire["native_checks"],
            "wire_decoder_checks": wire["decoder_checks"], "new_static_queries": queries,
            "full_pytest_run": False,
            "latest_full_suite": {"passed": 2443, "failed": 107, "errors": 35, "subtests": 1888, "green": False},
            "remaining": ["new observer integration and real context/type leaf acceptance",
                "observer visibility and same-address same-date load generation",
                "stable war/battle identities", "final roles/counts/units/full result UI text",
                "actual battle InformationService and LLM subscriptions/delivery",
                "full original 74-topic 397-field plan, phases 2/3/4 and overall acceptance"],
            "collected_shell_sessions": {"93351": 0, "74449": 0, "73950": 0, "10253": 0},
            "pin_count": len(pins), "pins": pins}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify-existing", action="store_true")
    args = parser.parse_args()
    if args.verify_existing:
        report = read(OUTPUT)
        for name, expected in report["pins"].items():
            assert pin(ROOT / name) == expected, name
    else:
        report = assemble()
        with OUTPUT.open("x", encoding="utf-8", newline="\n") as stream:
            json.dump(report, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
    print(json.dumps({"status": report["status"], "pins": report["pin_count"], "goal_complete": False}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
