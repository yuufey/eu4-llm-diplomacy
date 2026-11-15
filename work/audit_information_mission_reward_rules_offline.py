"""Run a bounded offline source audit for the M04 literal-rule adapter.

This audit is intentionally independent of a game process, MCP, RPM, REA and
pytest.  It pins the current seven profile groups, the domestic-pressure
contract used by the shared static reader guard, the merged catalog, bounded
source compilation and the three historical delivery manifests.  It also
projects the already recorded FRA loaded-task fixture through the pure M04
projector.  That projection is a literal rule inventory only: it does not
prove that a reward is currently applied, nor does it cover the planned
``unlocks`` and ``duration`` fields.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import py_compile
import sys
import tempfile
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
ROOT_RESOLVED = ROOT.resolve()
if str(ROOT_RESOLVED) not in sys.path:
    sys.path.insert(0, str(ROOT_RESOLVED))

from bridge.information.composite import CompositeSource  # noqa: E402
from bridge.information.country_state import NativeCountryStateSource  # noqa: E402
from bridge.information.domestic_pressure_memory import _static_contract_guard  # noqa: E402
from bridge.information.domestic_pressure import NativeDomesticPressureSource  # noqa: E402
from bridge.information.mission_definitions import MissionDefinitionIndex  # noqa: E402
from bridge.information.missions import MissionInformationSource, NativeMissionReader  # noqa: E402
from bridge.information.mission_reward_rules import project_reward_rules  # noqa: E402
from bridge.information.sources import DiplomacySource  # noqa: E402
from bridge.information.static_data import StaticTradeSource  # noqa: E402
from bridge.information.subject_relations import NativeSubjectRelationSource  # noqa: E402
from work.verify_information_domestic_pressure import (  # noqa: E402
    MAX_FILE_BYTES,
    MAX_PROFILE_BYTES,
    VerificationError,
    validate_static_profiles,
)


STAGE = ROOT / "work/runtime/information-mission-rewards-20261025-001"
PROFILE = ROOT / "bridge/information/profiles/domestic-pressure-memory-1374.json"
CONTRACT = ROOT / "work/runtime/information-domestic-pressure-20261025-001/native-domestic-pressure-contract-003.json"
LOADED_TASK_FIXTURE = ROOT / "bridge/tests/fixtures/information_loaded_tasks_live_1374.json"

EXPECTED_PROFILE_SHA256 = "b727bcd112ace025fcbc0fce78e6194cbb5055642ff12fd85280356e8347d9fd"
EXPECTED_PROFILE_BYTES = 60428
EXPECTED_CONTRACT_SHA256 = "902bef470421f8abe3ac4636ce13cb2d2c57f60e2985fcc7c40a28ca89bcaeaf"
EXPECTED_PROFILE_COUNT = 7
EXPECTED_PROFILE_REFERENCES = 80

EXPECTED_CATALOG = {
    "topic_count": 74,
    "field_count": 397,
    "available_topic_count": 35,
    "field_counts": {"available": 51, "partial": 110, "planned": 236},
}
M04_FIELDS = ("rewards", "unlocks", "claims", "casus_belli", "trade_modifiers", "duration")
M04_RULE_FIELDS = ("claims", "casus_belli", "trade_modifiers")
M04_LITERAL_RULE_COUNTS = {"claims": 24, "casus_belli": 2, "trade_modifiers": 2}

PRESERVED_MANIFESTS = (
    (
        "work/runtime/information-country-scalars-20261024-001/delivery/manifest.json",
        "01bf780b08d13dab03c5c3de166fa9eb06114063ef5ac895face01a32e5e78b1",
        "batch-nine manifest",
    ),
    (
        "work/runtime/information-country-relations-20261024-001/delivery/manifest.json",
        "b24cf0c61c56a95e36621d764080a4f9c22025649970c9cfdfafe96927e2e6f7",
        "batch-eight manifest",
    ),
    (
        "work/runtime/information-dynamic-text-20261024-001/delivery/manifest.json",
        "c2feea2e334fb1796541956d440c55237451cf32d49d486b34c7ce06b8b6aafe",
        "batch-seven manifest",
    ),
)

MAX_INPUT_BYTES = MAX_FILE_BYTES
MAX_OUTPUT_BYTES = 16 * 1024 * 1024
MAX_FIXTURE_BYTES = 16 * 1024 * 1024


def _fail(message: str) -> None:
    raise VerificationError(message)


def _regular_bounded(path: Path, *, limit: int = MAX_INPUT_BYTES) -> Path:
    resolved = path.resolve(strict=True)
    if not resolved.is_file():
        _fail(f"regular_file_required:{resolved}")
    size = resolved.stat().st_size
    if size > limit:
        _fail(f"bounded_input_exceeded:{resolved}:{size}>{limit}")
    return resolved


def _sha256(path: Path, *, limit: int = MAX_INPUT_BYTES) -> tuple[str, int]:
    source = _regular_bounded(path, limit=limit)
    before = (source.stat().st_size, source.stat().st_mtime_ns)
    digest = hashlib.sha256()
    total = 0
    with source.open("rb", buffering=1024 * 1024) as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            total += len(block)
            if total > limit:
                _fail(f"bounded_read_exceeded:{source}:{total}>{limit}")
            digest.update(block)
    after = (source.stat().st_size, source.stat().st_mtime_ns)
    if before != after:
        _fail(f"source_changed_during_read:{source}")
    return digest.hexdigest(), total


def _read_json(path: Path, *, limit: int = MAX_INPUT_BYTES) -> Any:
    source = _regular_bounded(path, limit=limit)
    with source.open("rb", buffering=1024 * 1024) as stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        _fail(f"json_read_exceeded:{source}")
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        _fail(f"json_invalid:{source}:{type(exc).__name__}")


def _record(path: Path, *, role: str, expected: str | None = None,
            limit: int = MAX_INPUT_BYTES) -> dict[str, Any]:
    source = _regular_bounded(path, limit=limit)
    sha256, size = _sha256(source, limit=limit)
    if expected is not None and sha256 != expected:
        _fail(f"artifact_sha_changed:{role}:{source}:{sha256}")
    return {
        "path": source.relative_to(ROOT_RESOLVED).as_posix(),
        "sha256": sha256,
        "bytes": size,
        "role": role,
    }


def _write_new(path: Path, value: Any) -> dict[str, Any]:
    destination = path.resolve()
    if not destination.is_relative_to(ROOT_RESOLVED):
        _fail(f"output_outside_workspace:{destination}")
    if destination.exists():
        raise FileExistsError(destination)
    encoded = (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")
    if len(encoded) > MAX_OUTPUT_BYTES:
        _fail(f"audit_output_exceeded:{destination}:{len(encoded)}>{MAX_OUTPUT_BYTES}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(encoded)
    return {
        "path": destination.relative_to(ROOT_RESOLVED).as_posix(),
        "sha256": hashlib.sha256(encoded).hexdigest(),
        "bytes": len(encoded),
    }


def _revision(value: str | int) -> int:
    """Parse a positive, at most three-digit report revision."""

    text = str(value)
    if not text.isascii() or not text.isdigit() or not 1 <= len(text) <= 3:
        raise argparse.ArgumentTypeError("revision must be a positive integer of at most three digits")
    number = int(text)
    if number < 1 or number > 999:
        raise argparse.ArgumentTypeError("revision must be between 1 and 999")
    return number


def _validate_profiles_and_contract() -> tuple[list[dict[str, Any]], dict[str, Any]]:
    profile_record = _record(PROFILE, role="current domestic-pressure profile",
                             expected=EXPECTED_PROFILE_SHA256, limit=MAX_PROFILE_BYTES)
    if profile_record["bytes"] != EXPECTED_PROFILE_BYTES:
        _fail(f"domestic_profile_bytes_changed:{profile_record['bytes']}")
    contract_record = _record(CONTRACT, role="domestic-pressure contract003",
                              expected=EXPECTED_CONTRACT_SHA256)
    groups = validate_static_profiles(PROFILE, CONTRACT)
    if len(groups) != EXPECTED_PROFILE_COUNT:
        _fail(f"profile_count_changed:{len(groups)}")
    reference_count = sum(len(group.get("references", [])) for group in groups)
    if reference_count != EXPECTED_PROFILE_REFERENCES:
        _fail(f"profile_reference_count_changed:{reference_count}")

    profile = _read_json(PROFILE, limit=MAX_PROFILE_BYTES)
    if not isinstance(profile, dict) or profile.get("profile_version") != 3:
        _fail("domestic_profile_version_changed")
    contract = _read_json(CONTRACT)
    if not isinstance(contract, dict) or contract.get("contract_id") != "native-domestic-pressure-contract-003":
        _fail("domestic_contract003_id_changed")
    fields = contract.get("fields")
    if not isinstance(fields, dict) or set(fields) != {"stability", "war_exhaustion", "corruption"}:
        _fail("domestic_contract003_field_set_changed")
    excluded = contract.get("excluded_fields")
    if not isinstance(excluded, dict) or set(excluded) != {"religious_unity", "overextension", "unrest"}:
        _fail("domestic_contract003_exclusion_set_changed")

    current = next((group for group in groups
                    if group.get("profile_id") == "domestic-pressure-memory-1374"), None)
    if not isinstance(current, dict):
        _fail("current_domestic_profile_missing")
    return groups, {
        "profile": profile_record,
        "profile_version": profile.get("profile_version"),
        "profile_id": profile.get("profile_id"),
        "contract": contract_record,
        "contract_id": contract.get("contract_id"),
        "contract_fields": sorted(fields),
        "excluded_fields": sorted(excluded),
        "profile_reference_occurrences": reference_count,
    }


def _validate_static_reader_guard(current_profile: dict[str, Any]) -> dict[str, Any]:
    guard = _static_contract_guard()
    if not isinstance(guard, dict) or guard.get("status") != "observed":
        _fail("static_reader_guard_not_observed")
    if guard.get("unknown_conditions") not in ([], None):
        _fail("static_reader_guard_has_unknown_conditions")
    if guard.get("profile_sha256") != current_profile.get("sha256"):
        _fail("static_reader_guard_profile_sha_mismatch")
    checks = guard.get("checks")
    dependencies = guard.get("dependency_hash_checks")
    if (not isinstance(checks, dict) or not checks or any(value is not True for value in checks.values())
            or not isinstance(dependencies, dict) or not dependencies
            or any(value is not True for value in dependencies.values())):
        _fail("static_reader_guard_check_failed")
    # The guard contains source paths and hashes but no native bytes to copy;
    # retaining it makes every dependency check auditable without expanding a
    # raw-code payload into the new stage artifact.
    return guard


def _build_catalog() -> tuple[dict[str, Any], dict[str, Any]]:
    try:
        primary = DiplomacySource(observer="FRA")
        adapters = [
            NativeCountryStateSource(primary),
            NativeDomesticPressureSource(primary),
            NativeSubjectRelationSource(primary),
            StaticTradeSource(context_provider=primary.context),
            MissionInformationSource(primary, MissionDefinitionIndex(), NativeMissionReader(primary)),
        ]
        topics = CompositeSource(primary, adapters).catalog()
    except Exception as exc:  # pragma: no cover - failure is reported as audit failure
        _fail(f"offline_catalog_failed:{type(exc).__name__}:{exc}")
    if not isinstance(topics, list):
        _fail("catalog_topics_not_list")
    field_counts = Counter(
        field.get("coverage")
        for topic in topics
        if isinstance(topic, dict)
        for field in (topic.get("fields", {}) or {}).values()
        if isinstance(field, dict)
    )
    summary = {
        "topic_count": len(topics),
        "field_count": sum(len(topic.get("fields", {})) for topic in topics),
        "available_topic_count": sum(topic.get("status") == "available" for topic in topics),
        "field_counts": {key: field_counts.get(key, 0) for key in ("available", "partial", "planned")},
        "callable_topic_count": sum(topic.get("status") == "available" for topic in topics),
    }
    expected = {key: summary[key] for key in EXPECTED_CATALOG}
    if expected != EXPECTED_CATALOG:
        _fail(f"catalog_counts_changed:{expected}")

    m04 = next((topic for topic in topics
                if isinstance(topic, dict) and topic.get("topic_id") == "M04"), None)
    if not isinstance(m04, dict) or m04.get("status") != "available":
        _fail("M04_catalog_not_available")
    fields = m04.get("fields")
    if not isinstance(fields, dict) or set(fields) != set(M04_FIELDS):
        _fail("M04_catalog_field_set_changed")
    for field in M04_RULE_FIELDS:
        item = fields[field]
        if item.get("coverage") != "partial" or item.get("declared_literal_effect_rules") is not True:
            _fail(f"M04_rule_field_coverage_changed:{field}")
        if item.get("runtime_conditions_evaluated") is not False or item.get("actual_reward_status") != "unknown":
            _fail(f"M04_rule_field_semantics_changed:{field}")
    if fields["rewards"].get("coverage") != "partial":
        _fail("M04_rewards_coverage_changed")
    for field in ("unlocks", "duration"):
        if fields[field].get("coverage") != "planned":
            _fail(f"M04_planned_field_coverage_changed:{field}")

    coverage = {
        "schema": "information-mission-reward-rules-offline-coverage-v1",
        "status": "passed",
        "goal_complete": False,
        "counts": summary,
        "expected_counts": EXPECTED_CATALOG | {"callable_topic_count": 35},
        "topics": topics,
        "M04": {
            "status": m04["status"],
            "fields": {field: fields[field] for field in M04_FIELDS},
            "literal_rule_fields": list(M04_RULE_FIELDS),
            "planned_fields": ["unlocks", "duration"],
            "actual_reward_status": "unknown",
            "runtime_conditions_evaluated": False,
        },
        "configuration": {
            "observer": "FRA",
            "live_session_opened": False,
            "catalog_is_not_live_acceptance": True,
            "adapters": [
                "NativeCountryStateSource",
                "NativeDomesticPressureSource",
                "NativeSubjectRelationSource",
                "StaticTradeSource",
                "MissionInformationSource",
            ],
        },
    }
    return summary, coverage


def _recorded_m04_inventory() -> dict[str, Any]:
    fixture_record = _record(LOADED_TASK_FIXTURE, role="recorded loaded-task fixture",
                             limit=MAX_FIXTURE_BYTES)
    fixture = _read_json(LOADED_TASK_FIXTURE, limit=MAX_FIXTURE_BYTES)
    if not isinstance(fixture, dict) or not isinstance(fixture.get("native_capture"), dict):
        _fail("loaded_task_fixture_shape_changed")
    capture = fixture["native_capture"]
    loaded = capture.get("loaded_tasks")
    if not isinstance(loaded, dict) or loaded.get("status") != "observed" or loaded.get("complete") is not True:
        _fail("loaded_task_fixture_not_observed_complete")
    roots = loaded.get("roots")
    if not isinstance(roots, list) or len(roots) != 18 or loaded.get("total_task_count") != 61:
        _fail("loaded_task_fixture_scope_changed")

    definitions = MissionDefinitionIndex()
    definition_context = definitions.context()
    if (definition_context.get("status") != "ready"
            or definition_context.get("game_version") != "1.37.4"):
        _fail("mission_definition_context_not_ready")
    tasks: list[dict[str, Any]] = []
    root_ids: list[str] = []
    seen_pairs: set[tuple[str, str]] = set()
    for captured_root in roots:
        if not isinstance(captured_root, dict) or not isinstance(captured_root.get("root_id"), str):
            _fail("loaded_task_root_invalid")
        root_id = captured_root["root_id"]
        root_ids.append(root_id)
        captured_ids = captured_root.get("task_ids")
        if not isinstance(captured_ids, list):
            _fail(f"loaded_task_ids_invalid:{root_id}")
        try:
            root = definitions.root(root_id)
        except Exception as exc:
            _fail(f"loaded_task_root_definition_missing:{root_id}:{type(exc).__name__}")
        definitions_by_id = {task.get("task_id"): task for task in root.get("tasks", [])}
        if set(captured_ids) != set(definitions_by_id):
            _fail(f"loaded_task_definition_membership_changed:{root_id}")
        for task_id in captured_ids:
            pair = (root_id, task_id)
            if pair in seen_pairs:
                _fail(f"loaded_task_duplicate:{root_id}:{task_id}")
            seen_pairs.add(pair)
            tasks.append(dict(definitions_by_id[task_id], root_id=root_id))
    if len(tasks) != 61:
        _fail(f"loaded_task_count_changed:{len(tasks)}")

    fields: dict[str, dict[str, Any]] = {}
    for field in M04_RULE_FIELDS:
        projected = project_reward_rules(tasks, field)
        if not isinstance(projected, dict) or projected.get("status") != "known":
            _fail(f"recorded_m04_projection_not_known:{field}")
        value = projected.get("value")
        if not isinstance(value, dict):
            _fail(f"recorded_m04_projection_value_missing:{field}")
        rules = value.get("rules")
        if not isinstance(rules, list):
            _fail(f"recorded_m04_projection_shape_changed:{field}")
        literal_rule_count = value.get("literal_rule_count")
        if type(literal_rule_count) is not int or literal_rule_count != M04_LITERAL_RULE_COUNTS[field]:
            _fail(f"recorded_m04_rule_count_changed:{field}:{literal_rule_count}")
        encoded_size = len(json.dumps(projected, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8"))
        if encoded_size > 8 * 1024 * 1024:
            _fail(f"recorded_m04_projection_budget_changed:{field}:{encoded_size}")
        fields[field] = {
            "status": projected.get("status"),
            "task_count": len(tasks),
            "known_task_count": value.get("known_task_count"),
            "unknown_task_count": value.get("unknown_task_count"),
            "literal_rule_count": literal_rule_count,
            "materialized_task_count": value.get("materialized_task_count"),
            "context_table_count": value.get("context_table_count"),
            "serialized_projection_bytes": encoded_size,
            "literal_inventory": "nonempty" if literal_rule_count else "empty",
            "semantics": value.get("semantics"),
            "evaluated": value.get("evaluated"),
            "applied": value.get("applied"),
            "complete": value.get("complete"),
        }
    return {
        "mode": "recorded",
        "status": "observed",
        "country": "FRA",
        "root_count": len(root_ids),
        "task_count": len(tasks),
        "root_ids": root_ids,
        "fixture": fixture_record,
        "definition_context": {
            key: definition_context.get(key)
            for key in ("status", "mode", "game_version", "configuration_sha256", "definitions_sha256", "root_count", "static_source")
        },
        "fields": fields,
        "semantics": "declared_literal_effect_rules",
        "actual_reward_status": "unknown",
        "conditions_evaluated": False,
        "effects_applied": False,
        "scope_targets_resolved": False,
        "scripted_effects_expanded": False,
        "runtime_scope_verified": False,
        "complete": False,
        "source_is_recorded_fixture": True,
        "not_live_reward_state": True,
        "unlocks_and_duration": "planned",
    }


def _compile_sources() -> list[dict[str, Any]]:
    candidates = set((ROOT / "bridge/information").glob("*.py"))
    candidates.update((ROOT / "bridge/tests").glob("test_information*.py"))
    candidates.update({
        ROOT / "tools/serve_information.py",
        ROOT / "work/validate_information_mission_reward_rules_recorded.py",
        ROOT / "work/audit_information_mission_reward_rules_offline.py",
    })
    sources = [_record(path, role="bounded compile source") for path in sorted(candidates)]
    with tempfile.TemporaryDirectory(prefix="information-mission-rewards-compile-") as temp:
        target = Path(temp)
        for index, item in enumerate(sources):
            source = ROOT / item["path"]
            py_compile.compile(str(source), cfile=str(target / f"{index}.pyc"), doraise=True)
    return sources


def _preserved_manifests() -> list[dict[str, Any]]:
    return [_record(ROOT / path, role=role, expected=expected)
            for path, expected, role in PRESERVED_MANIFESTS]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stage", type=Path, default=STAGE)
    parser.add_argument("--revision", type=_revision, default=1,
                        help="positive report revision, at most three digits (default: 001)")
    args = parser.parse_args(argv)
    stage = args.stage.resolve()
    if stage != STAGE.resolve() or not stage.is_relative_to(ROOT_RESOLVED):
        _fail("stage_must_be_current_information_mission_rewards")
    stage.mkdir(parents=True, exist_ok=True)

    profile_groups, profile_contract = _validate_profiles_and_contract()
    current_profile = next(group for group in profile_groups
                           if group.get("profile_id") == "domestic-pressure-memory-1374")
    static_guard = _validate_static_reader_guard(current_profile)
    catalog_summary, coverage = _build_catalog()
    recorded_m04 = _recorded_m04_inventory()
    compiled = _compile_sources()
    preserved = _preserved_manifests()

    suffix = f"{args.revision:03d}"
    coverage_artifact = _write_new(stage / f"coverage-{suffix}.json", coverage)
    report = {
        "schema": "information-mission-reward-rules-offline-source-audit-v1",
        "status": "offline_checks_passed_live_pending",
        "goal_complete": False,
        "native_capture_available": False,
        "live_mcp_accepted": False,
        "delivery_created": False,
        "profiles": profile_groups,
        "profile_count": len(profile_groups),
        "profile_reference_occurrences": sum(len(group.get("references", [])) for group in profile_groups),
        "current_profile_and_contract": profile_contract,
        "static_reader_guard": static_guard,
        "coverage": catalog_summary,
        "coverage_artifact": coverage_artifact,
        "recorded_m04_literal_rule_inventory": recorded_m04,
        "compiled_sources": compiled,
        "compiled_source_count": len(compiled),
        "preserved_manifests": preserved,
        "n04_status": {
            "fields": ["stability", "war_exhaustion", "corruption"],
            "status": "live_pending",
            "native_capture_available": False,
            "live_mcp_accepted": False,
        },
        "limitations": [
            "M04 rules are a recorded literal inventory from the FRA loaded-task fixture, not actual applied rewards or current game state.",
            "Runtime conditions, target scope, scripted effects and reward application were not evaluated; M04 unlocks and duration remain planned.",
            "N04 domestic-pressure live capture and MCP acceptance remain pending; this audit does not convert partial fields to verified values.",
            "The audit uses bounded JSON/source reads and compilation only; it does not run pytest, MCP, RPM, REA or a game process.",
            "Historical batch-seven, batch-eight and batch-nine manifests are checked by exact SHA and are not recursively copied.",
        ],
    }
    audit_artifact = _write_new(stage / f"offline-source-audit-{suffix}.json", report)
    print(json.dumps({
        "status": report["status"],
        "profile_count": report["profile_count"],
        "profile_reference_occurrences": report["profile_reference_occurrences"],
        "compiled_source_count": report["compiled_source_count"],
        "coverage": report["coverage"],
        "recorded_m04_rule_counts": {
            field: recorded_m04["fields"][field]["literal_rule_count"] for field in M04_RULE_FIELDS
        },
        "artifacts": {"coverage": coverage_artifact, "audit": audit_artifact},
    }, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
