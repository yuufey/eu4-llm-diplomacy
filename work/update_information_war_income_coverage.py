"""Update the N01 war_income coverage entry after batch-97 acceptance receipts pass."""
from __future__ import annotations

import argparse
from collections import Counter
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / "work/runtime/information-bankruptcy-visibility-20261101-001"
OUTPUT = STAGE / "coverage-preparation-001"
COVERAGE_PATH = ROOT / "docs/信息字段覆盖.json"
BACKUP_PATHS = {
    "docs/月度经济台账只读接口.md": (
        STAGE / "implementation-before-001/docs/月度经济台账只读接口.md"
    ),
    "docs/信息接口使用说明.md": (
        STAGE / "implementation-before-001/docs/信息接口使用说明.md"
    ),
}
DOCUMENT_PATHS = tuple(ROOT / relative for relative in BACKUP_PATHS)
EXPECTED_BACKUP_SHA256 = {
    "docs/月度经济台账只读接口.md":
        "7e46cca49aa5215f98777438b27f8230b345f5dff0158107b4607dc47d1e0506",
    "docs/信息接口使用说明.md":
        "f5661024aab7f49b62895d00cc95739a4e03769bec8783bbb814c46af41caea0",
}
COUNTRY_STATE_SOURCE = ROOT / "bridge/information/country_state.py"
WAR_INCOME_PROJECTION_SOURCE = ROOT / "bridge/information/war_income_projection.py"
EXPECTED_COUNTS_BEFORE = {
    "topic_count": 74,
    "field_count": 397,
    "topic_status_counts": {"available": 48, "partial": 4, "planned": 22},
    "field_counts": {"available": 62, "partial": 192, "planned": 143},
    "available_topic_count": 48,
    "callable_topic_count": 48,
}
EXPECTED_COUNTS_AFTER = deepcopy(EXPECTED_COUNTS_BEFORE)
EXPECTED_COUNTS_AFTER["field_counts"] = {
    "available": 62, "partial": 193, "planned": 142,
}

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def _hash_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _pin_bytes(path: Path, data: bytes) -> dict[str, object]:
    return {
        "path": path.resolve().relative_to(ROOT).as_posix(),
        "bytes": len(data),
        "sha256": _hash_bytes(data),
    }


def _pin_file(path: Path) -> dict[str, object]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
            size += len(block)
    return {
        "path": path.resolve().relative_to(ROOT).as_posix(),
        "bytes": size,
        "sha256": digest.hexdigest(),
    }


def _assert_pin_unchanged(pin: dict, label: str) -> None:
    path = ROOT / pin["path"]
    current = _pin_file(path)
    expected = {key: pin[key] for key in ("path", "bytes", "sha256")}
    if current != expected:
        raise RuntimeError(f"{label}_changed_during_coverage_preparation")


def _workspace_file(value: str, label: str) -> Path:
    path = Path(value)
    if not path.is_absolute():
        path = ROOT / path
    path = path.resolve()
    try:
        path.relative_to(ROOT)
    except ValueError as exc:
        raise ValueError(f"{label}_outside_workspace") from exc
    if not path.is_file():
        raise FileNotFoundError(f"{label}_missing:{path}")
    if path.stat().st_size > 16 * 1024 * 1024:
        raise ValueError(f"{label}_exceeds_16MiB")
    return path


def _contains_text(value: object, token: str) -> bool:
    needle = token.casefold()
    if isinstance(value, str):
        return needle in value.casefold()
    if isinstance(value, dict):
        return any(
            _contains_text(key, token) or _contains_text(item, token)
            for key, item in value.items()
        )
    if isinstance(value, list):
        return any(_contains_text(item, token) for item in value)
    return False


def _accepted_receipt(
    path_arg: str, label: str, *, require_war_income: bool = False
) -> tuple[dict, dict]:
    path = _workspace_file(path_arg, label)
    raw = path.read_bytes()
    try:
        receipt = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label}_invalid_json") from exc
    if not isinstance(receipt, dict) or receipt.get("status") != "passed":
        raise ValueError(f"{label}_status_not_passed")
    batch = receipt.get("batch")
    if batch is not None and (type(batch) is not int or batch != 97):
        raise ValueError(f"{label}_batch_not_97")
    if batch is None:
        try:
            path.relative_to(STAGE.resolve())
        except ValueError as exc:
            raise ValueError(f"{label}_missing_batch_and_not_in_batch97_stage") from exc
    if require_war_income and not _contains_text(receipt, "war_income"):
        raise ValueError(f"{label}_does_not_identify_war_income")
    pin = _pin_bytes(path, raw)
    return receipt, {**pin, "status": receipt["status"], "batch": batch}


def _field_coverage_counts(topics: list[dict]) -> dict[str, int]:
    counts = Counter(
        field.get("coverage")
        for topic in topics
        for field in topic.get("fields", {}).values()
    )
    return {
        "available": counts.get("available", 0),
        "partial": counts.get("partial", 0),
        "planned": counts.get("planned", 0),
    }


def _write_new(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(data)


def _catalog_n01() -> tuple[dict, dict]:
    # Use the adapter's actual catalog. _SPECS is not the public catalog source
    # for N01 and must not be used to synthesize its coverage metadata.
    from bridge.information.country_state import NativeCountryStateSource

    catalog = object.__new__(NativeCountryStateSource).catalog()
    matches = [row for row in catalog if row.get("topic_id") == "N01"]
    if len(matches) != 1:
        raise ValueError("native_country_state_catalog_N01_not_unique")
    topic = matches[0]
    fields = topic.get("fields")
    if not isinstance(fields, dict) or "war_income" not in fields:
        raise ValueError("native_country_state_catalog_war_income_missing")
    field = fields["war_income"]
    required = {
        "coverage": "partial",
        "source": "NativeCountryStateSource",
        "unit": "war_income_information",
        "scale": 1,
        "period": "month",
        "reference_period": "previous_month",
        "basis": "native_previous_month_war_related_income_slots",
        "complete": False,
        "paths": ["monthly_economy.income_slots"],
    }
    if not isinstance(field, dict) or any(field.get(key) != value for key, value in required.items()):
        raise ValueError("native_country_state_war_income_catalog_contract_changed")
    parameters = topic.get("parameters")
    reference = (parameters.get("properties", {}).get("reference_recipient")
                 if isinstance(parameters, dict) else None)
    parameter_description = reference.get("description") if isinstance(reference, dict) else None
    if (not isinstance(parameter_description, str)
            or "war_income" not in parameter_description
            or "treasury" not in parameter_description):
        raise ValueError("native_country_state_N01_parameter_scope_invalid")
    scope_note = topic.get("scope_note")
    if (not isinstance(scope_note, str) or "war_income" not in scope_note
            or "partial" not in scope_note):
        raise ValueError("native_country_state_N01_scope_note_invalid")
    return topic, field


def _assert_only_allowed_changes(before: dict, after: dict, topic_index: int) -> None:
    reverted = deepcopy(after)
    original_topic = before["topics"][topic_index]
    reverted_topic = reverted["topics"][topic_index]
    reverted_topic["fields"]["war_income"] = deepcopy(
        original_topic["fields"]["war_income"]
    )
    reverted_topic["parameters"] = deepcopy(original_topic["parameters"])
    reverted_topic["scope_note"] = original_topic["scope_note"]
    reverted["N01"]["fields"]["war_income"] = deepcopy(
        before["N01"]["fields"]["war_income"]
    )
    reverted["counts"] = deepcopy(before["counts"])
    reverted["expected_counts"] = deepcopy(before["expected_counts"])
    if reverted != before:
        raise ValueError("coverage_update_changed_data_outside_authorized_paths")


def update(mcp_receipt_arg: str, rpm_receipt_arg: str) -> dict:
    _mcp_receipt, mcp_pin = _accepted_receipt(
        mcp_receipt_arg, "mcp_receipt", require_war_income=True
    )
    _rpm_receipt, rpm_pin = _accepted_receipt(rpm_receipt_arg, "pure_rpm_receipt")

    source_before = {
        "country_state": _pin_file(COUNTRY_STATE_SOURCE),
        "war_income_projection": _pin_file(WAR_INCOME_PROJECTION_SOURCE),
    }
    native_topic, field_metadata = _catalog_n01()
    previous = COVERAGE_PATH.read_bytes()
    before = json.loads(previous.decode("utf-8"))
    if (before.get("schema") != "information-recovery-coverage-v1"
            or before.get("status") != "passed"):
        raise ValueError("coverage_matrix_schema_or_status_invalid")
    if (before.get("counts") != EXPECTED_COUNTS_BEFORE
            or before.get("expected_counts") != EXPECTED_COUNTS_BEFORE
            or len(before.get("topics", [])) != 74
            or sum(len(row.get("fields", {})) for row in before["topics"]) != 397
            or _field_coverage_counts(before["topics"])
            != EXPECTED_COUNTS_BEFORE["field_counts"]):
        raise ValueError("coverage_matrix_baseline_counts_invalid")

    topic_rows = [
        (index, row) for index, row in enumerate(before["topics"])
        if row.get("topic_id") == "N01"
    ]
    if len(topic_rows) != 1:
        raise ValueError("coverage_N01_topic_not_unique")
    topic_index, topic_before = topic_rows[0]
    if topic_before.get("fields", {}).get("war_income", {}).get("coverage") != "planned":
        raise ValueError("coverage_N01_war_income_not_planned")
    if (topic_before.get("fields", {}).get("loans", {}).get("source")
            != "NativeCountryRecordsSource"
            or topic_before.get("fields", {}).get("loans", {}).get("coverage") != "partial"):
        raise ValueError("coverage_N01_loans_independent_source_guard_failed")
    if (topic_before.get("fields", {}).get("treasury", {}).get("coverage") != "available"
            or topic_before.get("fields", {}).get("treasury", {}).get("source")
            != "DiplomacyTools.inspect_diplomatic_action"):
        raise ValueError("coverage_N01_treasury_route_guard_failed")
    top_n01 = before.get("N01")
    if (not isinstance(top_n01, dict)
            or top_n01.get("fields", {}).get("war_income", {}).get("coverage") != "planned"):
        raise ValueError("coverage_top_level_N01_war_income_not_planned")

    data = deepcopy(before)
    topic = data["topics"][topic_index]
    topic["fields"]["war_income"] = deepcopy(field_metadata)
    topic["parameters"] = deepcopy(native_topic["parameters"])
    topic["scope_note"] = native_topic["scope_note"]
    data["N01"]["fields"]["war_income"] = deepcopy(field_metadata)
    for counts_key in ("counts", "expected_counts"):
        counts = data[counts_key]
        counts["field_counts"] = deepcopy(EXPECTED_COUNTS_AFTER["field_counts"])
    if (data["counts"] != EXPECTED_COUNTS_AFTER
            or data["expected_counts"] != EXPECTED_COUNTS_AFTER
            or _field_coverage_counts(data["topics"])
            != EXPECTED_COUNTS_AFTER["field_counts"]
            or len(data["topics"]) != 74
            or sum(len(row.get("fields", {})) for row in data["topics"]) != 397):
        raise ValueError("coverage_matrix_updated_counts_invalid")
    _assert_only_allowed_changes(before, data, topic_index)

    current = (json.dumps(data, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    before_pin = _pin_bytes(COVERAGE_PATH, previous)
    candidate_pin = _pin_bytes(COVERAGE_PATH, current)
    source_after = {
        "country_state": _pin_file(COUNTRY_STATE_SOURCE),
        "war_income_projection": _pin_file(WAR_INCOME_PROJECTION_SOURCE),
    }
    if source_before != source_after:
        raise RuntimeError("war_income_sources_changed_during_coverage_preparation")
    document_pins_before = {
        path.relative_to(ROOT).as_posix(): _pin_file(path)
        for path in DOCUMENT_PATHS
    }
    backup_pins = {}
    for relative, backup_path in BACKUP_PATHS.items():
        if not backup_path.is_file():
            raise ValueError(f"original_document_backup_missing_or_changed:{relative}")
        backup_pin = _pin_file(backup_path)
        if backup_pin["sha256"] != EXPECTED_BACKUP_SHA256[relative]:
            raise ValueError(f"original_document_backup_missing_or_changed:{relative}")
        backup_pins[relative] = backup_pin

    OUTPUT.mkdir(parents=True, exist_ok=True)
    _write_new(OUTPUT / "coverage-before-001.json", previous)
    _write_new(OUTPUT / "coverage-candidate-001.json", current)
    source_report = {
        "schema": "information.war_income.coverage_source_report.v1",
        "batch": 97,
        "status": "prepared_from_passed_receipts",
        "native_catalog": {
            "class": "bridge.information.country_state.NativeCountryStateSource",
            "topic_id": "N01",
            "field": "war_income",
            "metadata": deepcopy(field_metadata),
            "parameter_schema": deepcopy(native_topic["parameters"]),
            "scope_note": native_topic["scope_note"],
            "read_from": "NativeCountryStateSource.catalog()",
            "default_SPECS_used_as_coverage_source": False,
        },
        "source_pins_before": source_before,
        "source_pins_after": source_after,
        "mcp_receipt": mcp_pin,
        "pure_rpm_receipt": rpm_pin,
        "document_backups": {
            relative: backup_pins[relative]
            for relative in BACKUP_PATHS
        },
        "current_document_pins": document_pins_before,
    }
    _write_new(
        OUTPUT / "coverage-source-report-001.json",
        (json.dumps(source_report, ensure_ascii=False, indent=2) + "\n").encode("utf-8"),
    )

    if COVERAGE_PATH.read_bytes() != previous:
        raise RuntimeError("coverage_matrix_changed_after_preflight")
    if document_pins_before != {
        path.relative_to(ROOT).as_posix(): _pin_file(path)
        for path in DOCUMENT_PATHS
    }:
        raise RuntimeError("documentation_changed_during_coverage_preparation")
    _assert_pin_unchanged(mcp_pin, "mcp_receipt")
    _assert_pin_unchanged(rpm_pin, "pure_rpm_receipt")
    COVERAGE_PATH.write_bytes(current)
    actual_current = _pin_file(COVERAGE_PATH)
    if actual_current != candidate_pin:
        raise RuntimeError("coverage_matrix_written_bytes_do_not_match_candidate")
    if source_before != {
        "country_state": _pin_file(COUNTRY_STATE_SOURCE),
        "war_income_projection": _pin_file(WAR_INCOME_PROJECTION_SOURCE),
    }:
        raise RuntimeError("war_income_sources_changed_during_coverage_write")

    report = {
        "schema": "information.war_income.configured_coverage_update.v1",
        "batch": 97,
        "status": "passed",
        "before": before_pin,
        "current": actual_current,
        "source_report": _pin_file(OUTPUT / "coverage-source-report-001.json"),
        "before_snapshot": _pin_file(OUTPUT / "coverage-before-001.json"),
        "candidate_snapshot": _pin_file(OUTPUT / "coverage-candidate-001.json"),
        "changed_paths": [
            "topics[N01].fields.war_income",
            "topics[N01].parameters",
            "topics[N01].scope_note",
            "N01.fields.war_income",
            "counts.field_counts.partial",
            "counts.field_counts.planned",
            "expected_counts.field_counts.partial",
            "expected_counts.field_counts.planned",
        ],
        "invariants": {
            "topic_count": 74,
            "field_count": 397,
            "field_coverage_counts": EXPECTED_COUNTS_AFTER["field_counts"],
            "callable_topic_count": 48,
            "available_topic_count": 48,
            "topic_status_counts_unchanged": True,
            "loans_remain_NativeCountryRecordsSource_partial": True,
            "treasury_remains_available_public_route": True,
            "all_unauthorized_matrix_paths_unchanged": True,
            "source_pins_stable_during_write": True,
        },
        "live_session_opened_by_updater": False,
        "test_or_game_action_performed_by_updater": False,
    }
    report_path = OUTPUT / "coverage-update-001.json"
    _write_new(report_path, (json.dumps(report, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", required=True)
    parser.add_argument("--mcp-receipt", required=True)
    parser.add_argument("--rpm-receipt", required=True)
    args = parser.parse_args()
    report = update(args.mcp_receipt, args.rpm_receipt)
    print(json.dumps(report, ensure_ascii=False), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
