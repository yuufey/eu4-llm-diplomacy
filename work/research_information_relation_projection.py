"""Build the bounded, offline R01 relation projection contract.

This script consumes only the already archived relation-source report and its
JSON pointers.  It never starts a game or calls a native reader.  The rival
examples are passed through the existing pure semantic helper so the report
records the same relationship_state shape as ``inspect_rival``.
"""
from __future__ import annotations

from copy import deepcopy
import argparse
import hashlib
import json
from pathlib import Path
import sys
from typing import Any

# A work/ script is normally launched by path, so make the repository root
# importable before using the pure semantic helper below.
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from bridge.diplomacy import ObserverSession
from bridge.information.relation_records import ACTION_MAPPING, SUPPORTED_FAMILIES, project


SOURCE_REPORT = ROOT / "work/runtime/information-relations-20261027-001/relation-source-001.json"
RIVAL_FIXTURE = ROOT / "bridge/tests/fixtures/rival_r34b_real_native_inspections.json"
DEFAULT_OUTPUT = ROOT / (
    "work/runtime/information-country-records-localization-20261027-001/"
    "relation-projection-contract-001.json"
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _pointer(value: Any, pointer: str) -> Any:
    if not isinstance(pointer, str) or not pointer.startswith("/"):
        raise ValueError(f"unsupported JSON pointer: {pointer!r}")
    current = value
    for part in pointer[1:].split("/"):
        part = part.replace("~1", "/").replace("~0", "~")
        current = current[int(part)] if isinstance(current, list) else current[part]
    return current


def _subset_matches(observed: Any, actual: Any) -> bool:
    if isinstance(observed, dict):
        return isinstance(actual, dict) and all(
            key in actual and _subset_matches(value, actual[key])
            for key, value in observed.items()
        )
    if isinstance(observed, list):
        return isinstance(actual, list) and observed == actual
    return observed == actual


def _read_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as stream:
        return json.load(stream)


def _archived_examples(source: dict[str, Any]) -> tuple[list[dict[str, Any]], list[str]]:
    examples: list[dict[str, Any]] = []
    errors: list[str] = []
    for index, pin in enumerate(source.get("archived_example_pins", [])):
        path = ROOT / pin["path"]
        try:
            document = _read_json(path)
            actual_sha = _sha256(path)
            actual = _pointer(document, pin["json_pointer"])
        except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            errors.append(f"PIN_{index}_READ:{type(exc).__name__}")
            continue
        if actual_sha != pin.get("sha256"):
            errors.append(f"PIN_{index}_SHA256_MISMATCH")
        # ``available_requested_keys`` is report metadata describing the
        # requested projection, not a key in the pointed inspection object.
        observed = deepcopy(pin.get("observed", {}))
        if isinstance(observed, dict):
            observed.pop("available_requested_keys", None)
        if not _subset_matches(observed, actual):
            errors.append(f"PIN_{index}_OBSERVED_MISMATCH")
        actor = actual.get("actor") if isinstance(actual, dict) else None
        recipient = actual.get("recipient") if isinstance(actual, dict) else None
        action_id = actual.get("action_id") if isinstance(actual, dict) else None
        result = project(
            action_id,
            actual,
            actor,
            recipient,
            source_ref={
                "path": pin["path"],
                "json_pointer": pin["json_pointer"],
                "sha256": actual_sha,
            },
        )
        examples.append({
            "name": f"archived_pin_{index}",
            "kind": "archived_inspect_diplomatic_action",
            "source": {
                "path": pin["path"],
                "json_pointer": pin["json_pointer"],
                "sha256": actual_sha,
                "relation_state_present": pin.get("relation_state_present") is True,
            },
            "observed": observed,
            "projection": result,
        })
    return examples, errors


def _rival_examples() -> list[dict[str, Any]]:
    document = _read_json(RIVAL_FIXTURE)
    fixture_sha = _sha256(RIVAL_FIXTURE)
    examples: list[dict[str, Any]] = []
    for event_index in (0, 4):
        event = deepcopy(document["events"][event_index]["event"])
        inspection = ObserverSession._semantic_rival_inspection(event)
        pointer = f"/events/{event_index}/event"
        result = project(
            event["action_id"],
            inspection,
            event["actor"],
            event["recipient"],
            source_ref={"path": str(RIVAL_FIXTURE.relative_to(ROOT)).replace("\\", "/"),
                        "json_pointer": pointer, "sha256": fixture_sha},
        )
        examples.append({
            "name": "rival_active" if event_index == 0 else "rival_inactive",
            "kind": "archived_rival_semantic_fixture",
            "source": {"path": str(RIVAL_FIXTURE.relative_to(ROOT)).replace("\\", "/"),
                       "json_pointer": pointer, "sha256": fixture_sha},
            "native_input_shape": "rival event passed through ObserverSession._semantic_rival_inspection",
            "observed": {
                "action_id": event["action_id"], "actor": event["actor"],
                "recipient": event["recipient"], "family": event["family"],
                "rival_state_verified": event["rival_state_verified"],
                "rival_active": event["rival_active"],
            },
            "projection": result,
        })
    return examples


def build_report() -> dict[str, Any]:
    source = _read_json(SOURCE_REPORT)
    source_sha = _sha256(SOURCE_REPORT)
    examples, errors = _archived_examples(source)
    examples.extend(_rival_examples())

    # The royal-marriage and alliance pointers are retained as explicit
    # negative evidence.  Neither has a current relation_state.
    family_counts: dict[str, dict[str, int]] = {
        family: {state: 0 for state in ("active", "inactive", "unknown")}
        for family in SUPPORTED_FAMILIES
    }
    for example in examples:
        rows = example["projection"]["records"]
        if not rows:
            continue
        row = rows[0]
        relation = row["relation_type"]
        status = row["status"]
        family = relation.get("value") if relation.get("status") == "known" else None
        state = status.get("value") if status.get("status") == "known" else "unknown"
        if family in family_counts and state in family_counts[family]:
            family_counts[family][state] += 1

    source_refs = deepcopy(source.get("source_refs", []))
    return {
        "schema": "information_relation_projection_contract.v1",
        "status": "observed_bounded_offline_projection",
        "topic": "R01",
        "identity": {"game_version": "1.37.4",
                      "game_sha256": "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77",
                      "observer": "FRA"},
        "source_report": {"path": str(SOURCE_REPORT.relative_to(ROOT)).replace("\\", "/"),
                          "sha256": source_sha,
                          "schema": source.get("schema"),
                          "status": source.get("status")},
        "source_refs": source_refs,
        "action_mapping": deepcopy(ACTION_MAPPING),
        "supported_families": {
            family: {
                "state_key": f"{family if family != 'vassalization' else 'vassal'}_active",
                "verified_guard": f"{family if family != 'vassalization' else 'vassal'}_state_verified",
                "role_policy": "exclusive_vassal_flags" if family == "vassalization" else
                ("not_applicable_rival" if family == "rival" else "direction_unproven"),
            }
            for family in SUPPORTED_FAMILIES
        },
        "projection_contract": {
            "object": {"type": "country_pair", "actor": "FRA", "recipient": "TAG"},
            "parameters": {},
            "records": {
                "actor": "selected actor endpoint",
                "selected_recipient": "selected recipient endpoint",
                "relation_type": "field result known only after family-specific relationship_state.complete",
                "status": "field result active|inactive|unknown",
                "grantor": "known only for exclusive vassalization role flags; otherwise unknown/not_applicable",
                "recipient": "known only for exclusive vassalization role flags; otherwise unknown/not_applicable",
                "expires_at": {"status": "unknown", "reason": "RELATION_EXPIRY_UNREAD"},
                "visibility": "preserved inspection metadata",
                "raw_sourcepath": "archived source path when supplied",
                "raw_json_pointer": "archived JSON pointer when supplied",
            },
            "missing": [
                "RELATION_EXPIRY_UNREAD",
                "FULL_RELATION_NETWORK_UNSUPPORTED",
                "ALLIANCE_CURRENT_STATE_UNSUPPORTED",
                "ROYAL_MARRIAGE_CURRENT_STATE_UNSUPPORTED",
            ],
            "negative_rules": [
                "legality, acceptance, pending queue entries, and native_would_accept do not establish current status",
                "the action id alone does not establish a relation",
                "selected endpoints are not renamed grantor/recipient without native role proof",
            ],
        },
        "examples": examples,
        "family_state_counts": family_counts,
        "verification_errors": errors,
        "coverage": "partial_selected_country_pair_only",
        "expires_at_status": "unsupported_no_current_relation_expiry_source",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    report = build_report()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8", newline="\n") as stream:
        json.dump(report, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    print(json.dumps({"output": str(args.output),
                      "examples": len(report["examples"]),
                      "verification_errors": report["verification_errors"]},
                     ensure_ascii=False))
    return 0 if not report["verification_errors"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
