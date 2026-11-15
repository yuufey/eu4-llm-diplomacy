"""在第十批证据和信息测试摘要通过后建立 N04 只读交付快照。

终结器默认只做严格校验；它在所有守卫通过前不会创建 ``delivery``。复制使用
精确文件清单，不递归复制任何旧批次归档，并在每次复制前后重算 SHA-256。
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import py_compile
import shutil
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
ROOT_RESOLVED = ROOT.resolve()
STAGE = ROOT / "work/runtime/information-domestic-pressure-20261025-001"
MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_ARCHIVE_TOTAL_BYTES = 128 * 1024 * 1024
ARCHIVE_SUFFIXES = {".json", ".xml", ".log", ".md", ".py", ".txt"}
PREVIOUS_BASELINE = ROOT / "work/runtime/information-country-scalars-20261024-001/delivery/manifest.json"
PREVIOUS_BASELINE_SHA = "01bf780b08d13dab03c5c3de166fa9eb06114063ef5ac895face01a32e5e78b1"
RELATIONS_BASELINE = ROOT / "work/runtime/information-country-relations-20261024-001/delivery/manifest.json"
RELATIONS_BASELINE_SHA = "b24cf0c61c56a95e36621d764080a4f9c22025649970c9cfdfafe96927e2e6f7"

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from work import verify_information_domestic_pressure as checker  # noqa: E402


DOCS = (
    "HANDOFF.md",
    "README(agent).md",
    "docs/信息导出与订阅开发计划.md",
    "docs/信息导出开发进展.md",
    "docs/信息接口使用说明.md",
    "docs/信息服务合同.md",
    "docs/信息字段覆盖.json",
    "docs/国家资源信息接口.md",
    "docs/国内压力原生来源.md",
    "docs/信息计划验收清单.md",
)
PLAN_GATES = ROOT / "work/runtime/information-plan-gates-20261025-001/plan-gates-audit-001.json"
REQUIRED_FIXTURES = (
    "r73_favor_queries_real.json",
    "r74_economic_queries_real.json",
    "vassalization_r35_native_inspections.json",
)


def bounded_file(path: Path | str) -> Path:
    return checker.bounded_file(path, max_bytes=MAX_FILE_BYTES)


def digest(path: Path | str) -> str:
    return checker.digest(path, max_bytes=MAX_FILE_BYTES)


def read_json(path: Path | str) -> Any:
    return checker.read_json(path, max_bytes=MAX_FILE_BYTES)


def _add(paths: set[Path], path: Path | str, *, role: str = "archive") -> None:
    source = bounded_file(path)
    paths.add(source)


def _assert_audits(validation: dict[str, Any], stage: Path) -> None:
    expected = {
        "coverage.json": validation["coverage"],
        "compile-audit.json": validation["compile_audit"],
    }
    for name, value in expected.items():
        actual = read_json(stage / name)
        if actual != value:
            raise checker.VerificationError(f"stale_audit:{name}")
    source = read_json(stage / "source-audit.json")
    if not isinstance(source, dict) or source.get("status") != "passed":
        raise checker.VerificationError("source_audit_not_passed")
    if source.get("source_fingerprints") != validation["compile_audit"]["files"]:
        raise checker.VerificationError("stale_audit:source_fingerprints")
    if source.get("profile_groups") != validation["profile_groups"]:
        raise checker.VerificationError("stale_audit:profile_groups")
    reports = source.get("reports")
    if not isinstance(reports, dict):
        raise checker.VerificationError("source_audit_reports_missing")


def _archive_paths(validation: dict[str, Any], paths: checker.Paths) -> list[Path]:
    selected: set[Path] = set()
    information = ROOT / "bridge/information"
    for source in information.glob("*"):
        if source.is_file() and source.suffix.lower() in ARCHIVE_SUFFIXES:
            _add(selected, source)
    tests = ROOT / "bridge/tests"
    for source in tests.glob("test_information*.py"):
        _add(selected, source)
    fixtures = tests / "fixtures"
    for source in fixtures.glob("information_*.json"):
        _add(selected, source)
    for name in REQUIRED_FIXTURES:
        _add(selected, fixtures / name)
    for relative in DOCS:
        _add(selected, ROOT / relative)
    _add(selected, PLAN_GATES)
    profiles = information / "profiles"
    for source in sorted(profiles.glob("*.json")):
        _add(selected, source)

    # The current service entry is a required source pin even if a live report
    # omitted it.  Batch-specific research/capture scripts are included only
    # when they exist; no broad work/archive tree is traversed.
    _add(selected, ROOT / "tools/serve_information.py")
    for pattern in (
        "work/*domestic_pressure*.py",
        "work/*domestic-pressure*.py",
    ):
        for source in ROOT.glob(pattern):
            if source.is_file():
                _add(selected, source)

    # Exact evidence and profile pins, not a recursive walk of their parents.
    for source in (paths.profile, paths.contract, paths.capture, paths.native_report,
                   paths.live_report, paths.save_crosscheck, paths.fixture,
                   paths.test_summary, paths.baseline):
        _add(selected, source)
    _add(selected, RELATIONS_BASELINE)
    for group in validation["profile_groups"]:
        for record in group["references"]:
            _add(selected, ROOT / record["path"])
    for record in validation["live"]["source_files"]:
        _add(selected, ROOT / record["path"])
    for record in validation["test_summary"].get("artifacts", []):
        _add(selected, ROOT / record["path"])
    for record in validation["test_summary"].get("evidence_checkpoints", []):
        _add(selected, ROOT / record["path"])

    # Preserve this batch's bounded evidence files.  A delivery directory is
    # deliberately excluded, so a previous archive can never be copied into
    # the next archive by accident.
    for source in paths.stage.rglob("*"):
        if not source.is_file() or source.suffix.lower() not in ARCHIVE_SUFFIXES:
            continue
        if "delivery" in source.relative_to(paths.stage).parts:
            continue
        _add(selected, source)

    ordered = sorted(selected, key=lambda item: item.relative_to(ROOT_RESOLVED).as_posix())
    total = sum(item.stat().st_size for item in ordered)
    if total > MAX_ARCHIVE_TOTAL_BYTES:
        raise checker.VerificationError(f"archive_total_over_limit:{total}>{MAX_ARCHIVE_TOTAL_BYTES}")
    return ordered


def _typed_evidence(validation: dict[str, Any]) -> dict[str, Any]:
    return {
        "ordinary_profile_and_code_guard_sources": [
            {"profile": group["path"], "profile_sha256": group["sha256"],
             "references": group["references"]}
            for group in validation["profile_groups"]
        ],
        "pure_RPM_native_capture": [validation["capture"]],
        "native_runtime_report": [validation["native_report"]],
        "mixed_native_query_periodic": [validation["live"]],
        "recorded_save_crosscheck": [validation["save_crosscheck"]],
        "recorded_fixture": [validation["fixture"]],
    }


def _manifest(validation: dict[str, Any], entries: list[dict[str, Any]], paths: checker.Paths) -> dict[str, Any]:
    return {
        "format": "information_domestic_pressure_delivery_v1",
        "status": "source_and_evidence_snapshot_verified",
        "goal_complete": False,
        "file_count": len(entries),
        "files": entries,
        "evidence_reports": {
            "native_capture": validation["capture"],
            "native_runtime": validation["native_report"],
            "live_acceptance": validation["live"],
            "save_crosscheck": validation["save_crosscheck"],
            "recorded_fixture": validation["fixture"],
        },
        "typed_evidence": _typed_evidence(validation),
        "profile": validation["profile"],
        "profile_groups": validation["profile_groups"],
        "tests": validation["test_summary"],
        "baseline": validation["baseline"],
        "coverage": validation["coverage"],
        "compiled_source_fingerprints": validation["compile_audit"],
        "scope": {
            "topic": "N04",
            "country": "FRA",
            "observer": "FRA",
            "fields": list(checker.FIELDS),
            "read_only": True,
            "native_business_actions_submitted": False,
            "save_is_not_live_fallback": True,
            "world_generation_verified": False,
            "catalog_is_not_full_live_acceptance": True,
        },
        "remaining": [
            "其他国家和未证国内字段仍不属于本批范围",
            "sampled change triggers do not prove lossless native event delivery",
            "world generation, UI binding and positive in-game change are unverified",
            "goal_complete remains false until the broader information plan is complete",
        ],
        "read_only_archival": True,
        "no_recursive_old_archive_copy": True,
        "baseline_manifest": {"path": checker.relative(paths.baseline),
                              "sha256": validation["baseline"]["sha256"],
                              "relations_path": checker.relative(RELATIONS_BASELINE),
                              "relations_sha256": RELATIONS_BASELINE_SHA},
        "plan_gates": {"path": checker.relative(PLAN_GATES),
                        "sha256": digest(PLAN_GATES)},
    }


def archive(*, output: Path, paths: checker.Paths, validation: dict[str, Any], check_only: bool = False) -> dict[str, Any]:
    output = checker._resolve(output)
    if not output.is_relative_to(paths.stage):
        raise checker.VerificationError("archive_output_outside_batch_stage")
    if output.exists():
        raise checker.VerificationError("archive_output_must_be_new")
    _assert_audits(validation, paths.stage)
    sources = _archive_paths(validation, paths)
    if check_only:
        return {"status": "ready", "file_count": len(sources),
                "bytes": sum(item.stat().st_size for item in sources),
                "output": checker.relative(output)}
    output.mkdir(parents=True, exist_ok=False)
    entries: list[dict[str, Any]] = []
    try:
        for source in sources:
            relative = source.relative_to(ROOT_RESOLVED)
            destination = output / "files" / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            expected = digest(source)
            shutil.copyfile(source, destination)
            if digest(source) != expected or digest(destination) != expected:
                raise checker.VerificationError(f"source_changed_during_archive:{relative}")
            entries.append({"path": relative.as_posix(), "bytes": source.stat().st_size,
                            "sha256": expected})
        manifest = _manifest(validation, entries, paths)
        manifest_path = output / "manifest.json"
        raw = (json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")
        if len(raw) > MAX_FILE_BYTES:
            raise checker.VerificationError("archive_manifest_over_limit")
        manifest_path.write_bytes(raw)
        if digest(manifest_path) != __import__("hashlib").sha256(raw).hexdigest():
            raise checker.VerificationError("archive_manifest_hash_failed")
        return {"status": manifest["status"], "goal_complete": False,
                "file_count": len(entries), "manifest": checker.relative(manifest_path),
                "manifest_sha256": digest(manifest_path)}
    except Exception:
        # A failed copy is never presented as a completed delivery.  Removing
        # only this newly-created output is safe and leaves all source evidence.
        shutil.rmtree(output, ignore_errors=True)
        raise


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--stage", type=Path, default=STAGE)
    parser.add_argument("--profile", type=Path)
    parser.add_argument("--contract", type=Path)
    parser.add_argument("--capture", type=Path)
    parser.add_argument("--native-report", type=Path)
    parser.add_argument("--live-report", type=Path)
    parser.add_argument("--save-crosscheck", type=Path)
    parser.add_argument("--fixture", type=Path)
    parser.add_argument("--test-summary", type=Path)
    parser.add_argument("--baseline", type=Path)
    parser.add_argument("--check-only", action="store_true", help="只校验归档清单，不创建 delivery")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        paths = checker._load_paths(
            stage=args.stage, profile=args.profile, contract=args.contract,
            capture=args.capture, native_report=args.native_report, live_report=args.live_report,
            save_crosscheck=args.save_crosscheck, fixture=args.fixture,
            test_summary=args.test_summary, baseline=args.baseline,
        )
        validation = checker.run_validation(paths=paths, write_artifacts=False)
        result = archive(output=args.output, paths=paths, validation=validation, check_only=args.check_only)
    except (checker.VerificationError, OSError, json.JSONDecodeError, py_compile.PyCompileError) as exc:
        print(json.dumps({"status": "failed", "error": str(exc)}, ensure_ascii=False))
        return 2
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
