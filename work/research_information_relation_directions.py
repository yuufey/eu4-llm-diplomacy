"""Review the direction semantics of the R01 relation-state readers.

This is an offline, bounded review.  It consumes the existing relation source
report, a small set of already archived JSON observations, and narrow source
windows from the diplomacy/projector modules.  It never starts a game, calls a
native reader, dispatches an action, or performs a new REA/RPM observation.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from bridge.information.relation_records import ACTION_MAPPING, SUPPORTED_FAMILIES


GAME_SHA256 = (
    "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
)
SOURCE_REPORT = ROOT / "work/runtime/information-relations-20261027-001/relation-source-001.json"
DEFAULT_OUTPUT = ROOT / (
    "work/runtime/information-country-records-localization-20261027-001/"
    "relation-direction-source-001.json"
)
MAX_JSON_BYTES = 2 * 1024 * 1024


# These are deliberately a few selected observations rather than a scan of
# the historical runtime tree.  The first four source pins are the established
# family contracts.  The extra active/reverse observations are from the
# already archived direction/reload reports and are used only as asymmetric
# checks, never as a new runtime source.
ARCHIVED_CASES: tuple[dict[str, Any], ...] = (
    {
        "name": "vassal_active_role_proof",
        "path": "work/runtime/diplomacy-query-20261016-r35-vassal-a/"
                "vassalization-queries-08b4e54e917040af8bddeaa95f6513f1/report.json",
        "pointer": "/queries/ORL/offer_vassalization",
        "family": "vassalization",
        "state_key": "vassal_active",
        "expected": True,
        "source_pin": True,
    },
    {
        "name": "guarantee_inactive_selected_pair",
        "path": "work/runtime/diplomacy-query-20261015-r30-guarantee-a/"
                "guarantee-queries-7cacb0e7cd4349218a6e6815a0dd8292/report.json",
        "pointer": "/queries/SAV/proclaim_guarantee",
        "family": "guarantee",
        "state_key": "guarantee_active",
        "expected": False,
        "source_pin": True,
    },
    {
        "name": "support_inactive_selected_pair",
        "path": "work/runtime/diplomacy-query-20261015-r31-support-a/"
                "support-independence-queries-9bf1deccef644b96a056d65c8c6c257a/report.json",
        "pointer": "/queries/SWE/support_independence",
        "family": "support_independence",
        "state_key": "support_independence_active",
        "expected": False,
        "source_pin": True,
    },
    {
        "name": "military_inactive_selected_pair",
        "path": "work/runtime/diplomacy-query-20261015-r32-military-access-a/"
                "military-access-queries-7a97bc04b2ee4d5f89fc5cbac7ef3fab/report.json",
        "pointer": "/queries/ARA/ask_military_access",
        "family": "military_access",
        "state_key": "military_access_active",
        "expected": False,
        "source_pin": True,
    },
    {
        "name": "guarantee_active_before_revocation",
        "path": "work/runtime/diplomacy-query-20261015-r30-guarantee-b-active-reload/"
                "guarantee-execution-25a7b1fe1d7640a2be536ef2604c70a0/report.json",
        "pointer": "/before/queries/proclaim_guarantee",
        "family": "guarantee",
        "state_key": "guarantee_active",
        "expected": True,
        "source_pin": False,
    },
    {
        "name": "guarantee_inactive_after_revocation",
        "path": "work/runtime/diplomacy-query-20261015-r30-guarantee-b-active-reload/"
                "guarantee-execution-25a7b1fe1d7640a2be536ef2604c70a0/report.json",
        "pointer": "/after/queries/proclaim_guarantee",
        "family": "guarantee",
        "state_key": "guarantee_active",
        "expected": False,
        "source_pin": False,
    },
    {
        "name": "support_active_after_reload",
        "path": "work/runtime/diplomacy-query-20261015-r31-support-b-active-reload/"
                "support-independence-reload-e98f54ba138e4c0ea58fe1c328910101/report.json",
        "pointer": "/after/queries/support_independence",
        "family": "support_independence",
        "state_key": "support_independence_active",
        "expected": True,
        "source_pin": False,
    },
    {
        "name": "military_active_cas_to_fra",
        "path": "work/runtime/diplomacy-query-20261015-r32-military-access-d-final-reload/"
                "military-access-directions-reload-b7cff90f3e44482aa508b856459d332f/report.json",
        "pointer": "/after/directions/CAS->FRA/actions/ask_military_access",
        "family": "military_access",
        "state_key": "military_access_active",
        "expected": True,
        "source_pin": False,
    },
    {
        "name": "military_inactive_reverse_fra_to_cas",
        "path": "work/runtime/diplomacy-query-20261015-r32-military-access-d-final-reload/"
                "military-access-directions-reload-b7cff90f3e44482aa508b856459d332f/report.json",
        "pointer": "/after/directions/FRA->CAS/actions/ask_military_access",
        "family": "military_access",
        "state_key": "military_access_active",
        "expected": False,
        "source_pin": False,
    },
    {
        "name": "royal_marriage_legality_without_state",
        "path": "work/runtime/diplomacy-query-20261015-r25-royal-d/"
                "royal-marriage-queries-7011638465244738b2c9582292e54651/report.json",
        "pointer": "/queries/offer_royal_marriage:LAN",
        "family": "royal_marriage",
        "state_key": None,
        "expected": None,
        "source_pin": True,
    },
    {
        "name": "alliance_pending_queue_without_state",
        "path": "work/runtime/alliance-observer-20261013-r3/"
                "alliance-inspection-1791873501775372000.json",
        "pointer": "/countries/2/actions/0",
        "family": "alliance",
        "state_key": None,
        "expected": None,
        "source_pin": True,
    },
)


STATIC_WINDOWS: tuple[dict[str, Any], ...] = (
    {
        "name": "diplomacy_semantic_family_states",
        "path": "bridge/diplomacy.py",
        "start": 8688,
        "end": 8770,
        "markers": (
            'event.get("family") == "guarantee"',
            'event.get("family") == "support_independence"',
            'event.get("family") == "military_access"',
            'event.get("family") == "vassalization"',
            'relationship_state',
        ),
        "meaning": "The producer binds each family-specific active bool to the inspected event's actor and recipient, and only vassalization carries explicit role flags.",
    },
    {
        "name": "diplomacy_family_state_guards",
        "path": "bridge/diplomacy.py",
        "start": 11460,
        "end": 11535,
        "markers": (
            'action_id in ("proclaim_guarantee", "revoke_guarantee")',
            'action_id in ("support_independence", "revoke_support_independence")',
            'action_id in ("ask_military_access", "cancel_military_access")',
            'state_verified',
        ),
        "meaning": "The verifier requires family, exact active bool, and the family state_verified guard; action id alone is not a relation claim.",
    },
    {
        "name": "observer_family_entry_points",
        "path": "bridge/diplomacy.py",
        "start": 15244,
        "end": 15320,
        "markers": (
            "def inspect_alliance",
            "if phase != \"initiate\"",
            "controlled = self.record.get(\"controlled_countries\"",
        ),
        "meaning": "inspect_alliance is the shared bounded query wire and queue/inspection path, not a proven established-alliance current-state getter.",
    },
    {
        "name": "observer_royal_and_family_wrappers",
        "path": "bridge/diplomacy.py",
        "start": 15914,
        "end": 16022,
        "markers": (
            "def inspect_royal_marriage",
            "def inspect_guarantee",
            "def inspect_support_independence",
            "def inspect_military_access",
            "return self.inspect_alliance(",
        ),
        "meaning": "Royal, guarantee, support-independence, and military-access wrappers pass the selected actor/recipient pair into the shared query wire; the wrappers do not introduce grantor/recipient role fields.",
    },
    {
        "name": "pure_relation_role_projection",
        "path": "bridge/information/relation_records.py",
        "start": 145,
        "end": 190,
        "markers": (
            'if family == "rival"',
            'RELATION_ROLE_DIRECTION_UNPROVEN',
            'actor_is_overlord',
            'actor_is_subject',
        ),
        "meaning": "The pure projection keeps selected_recipient separate and derives relation roles only from exclusive vassal flags; non-vassal roles remain unknown.",
    },
    {
        "name": "subject_role_projection",
        "path": "bridge/information/subject_relations.py",
        "start": 263,
        "end": 345,
        "markers": (
            'actor_is_overlord',
            'actor_is_subject',
            'if actor_is_overlord:',
            'values = {"overlord": recipient',
        ),
        "meaning": "The existing subject reader independently enforces exact role booleans and maps the opposite endpoint only after the exclusive role proof.",
    },
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _read_json(path: Path) -> Any:
    size = path.stat().st_size
    if size > MAX_JSON_BYTES:
        raise ValueError(f"bounded JSON read refused ({size} bytes): {path}")
    with path.open("r", encoding="utf-8") as stream:
        return json.load(stream)


def _pointer(value: Any, pointer: str) -> Any:
    if not isinstance(pointer, str) or not pointer.startswith("/"):
        raise ValueError(f"invalid JSON pointer: {pointer!r}")
    current = value
    for raw_part in pointer[1:].split("/"):
        part = raw_part.replace("~1", "/").replace("~0", "~")
        if isinstance(current, list):
            current = current[int(part)]
        else:
            current = current[part]
    return current


def _relative(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def _source_pin_index(source: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    result: dict[tuple[str, str], dict[str, Any]] = {}
    for pin in source.get("archived_example_pins", []):
        if not isinstance(pin, dict):
            continue
        path = pin.get("path")
        pointer = pin.get("json_pointer")
        if isinstance(path, str) and isinstance(pointer, str):
            result[(path.replace("\\", "/"), pointer)] = pin
    return result


def _summarize(value: Any, family: str, state_key: str | None) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {"shape": type(value).__name__, "relation_state_present": False}
    state = value.get("relationship_state")
    summary: dict[str, Any] = {
        "action_id": value.get("action_id"),
        "actor": value.get("actor"),
        "recipient": value.get("recipient"),
        "family": value.get("family"),
        "relationship_state_present": isinstance(state, dict),
    }
    if isinstance(state, dict):
        summary["relationship_state_complete"] = state.get("complete")
        if state_key is not None:
            summary["active_key"] = state_key
            summary["active"] = state.get(state_key)
    if family == "vassalization":
        summary.update({
            "actor_is_overlord": value.get("actor_is_overlord"),
            "actor_is_subject": value.get("actor_is_subject"),
            "subject_type": value.get("subject_type"),
        })
    if family in {"royal_marriage", "alliance"}:
        summary["legality_present"] = isinstance(value.get("legality"), dict)
        summary["acceptance_present"] = isinstance(value.get("acceptance"), dict)
        summary["pending_or_queue_complete"] = value.get("complete")
    return summary


def _bounded_window(spec: dict[str, Any]) -> dict[str, Any]:
    path = ROOT / spec["path"]
    start = int(spec["start"])
    end = int(spec["end"])
    markers = tuple(spec.get("markers", ()))
    found: dict[str, list[int]] = {marker: [] for marker in markers}
    bytes_examined = 0
    with path.open("rb") as stream:
        for line_number, raw in enumerate(stream, 1):
            if line_number > end:
                break
            if line_number < start:
                continue
            bytes_examined += len(raw)
            try:
                line = raw.decode("utf-8").rstrip("\r\n")
            except UnicodeDecodeError:
                line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
            for marker in markers:
                if marker in line:
                    found[marker].append(line_number)
    return {
        "path": spec["path"],
        "sha256": _sha256(path),
        "line_range_inclusive": [start, end],
        "bytes_examined": bytes_examined,
        "markers": {key: value for key, value in found.items() if value},
        "missing_markers": [key for key, value in found.items() if not value],
        "meaning": spec["meaning"],
    }


def _load_case(case: dict[str, Any], source_pins: dict[tuple[str, str], dict[str, Any]]) -> tuple[dict[str, Any], list[str]]:
    path = ROOT / case["path"]
    errors: list[str] = []
    try:
        document = _read_json(path)
        actual_sha = _sha256(path)
        value = _pointer(document, case["pointer"])
    except (OSError, ValueError, KeyError, IndexError, TypeError, json.JSONDecodeError) as exc:
        return {
            "name": case["name"],
            "source": {"path": case["path"], "json_pointer": case["pointer"]},
            "error": f"{type(exc).__name__}:{exc}",
        }, [f"{case['name']}:READ_FAILED"]

    source_pin = source_pins.get((case["path"], case["pointer"]))
    if source_pin is not None and actual_sha != source_pin.get("sha256"):
        errors.append(f"{case['name']}:SOURCE_PIN_SHA256_MISMATCH")
    if case.get("state_key") is not None:
        state = value.get("relationship_state") if isinstance(value, dict) else None
        actual = state.get(case["state_key"]) if isinstance(state, dict) else None
        if actual is not case.get("expected"):
            errors.append(f"{case['name']}:STATE_MISMATCH")
        if not isinstance(state, dict) or state.get("complete") is not True:
            errors.append(f"{case['name']}:STATE_NOT_COMPLETE")
    else:
        if isinstance(value, dict) and "relationship_state" in value:
            errors.append(f"{case['name']}:UNEXPECTED_RELATIONSHIP_STATE")

    summary = _summarize(value, case["family"], case.get("state_key"))
    result: dict[str, Any] = {
        "name": case["name"],
        "family": case["family"],
        "source": {
            "path": case["path"],
            "json_pointer": case["pointer"],
            "sha256": actual_sha,
            "size_bytes": path.stat().st_size,
            "source_report_pin": bool(source_pin),
        },
        "observed": summary,
    }
    if source_pin is not None:
        result["source_report_note"] = source_pin.get("note")
    if case.get("state_key") is not None:
        result["direction_interpretation"] = {
            "state_is_scoped_to": "the exact inspected actor/recipient pair",
            "selected_actor": summary.get("actor"),
            "selected_recipient": summary.get("recipient"),
            "generic_grantor": "unproven",
            "generic_recipient_role": "unproven",
        }
    else:
        result["direction_interpretation"] = {
            "state_is_scoped_to": "none; this object is legality/acceptance or a pending queue item",
            "generic_grantor": "unavailable",
            "generic_recipient_role": "unavailable",
        }
    return result, errors


def build_report() -> dict[str, Any]:
    source = _read_json(SOURCE_REPORT)
    source_sha = _sha256(SOURCE_REPORT)
    source_pins = _source_pin_index(source)
    cases: list[dict[str, Any]] = []
    errors: list[str] = []
    for case in ARCHIVED_CASES:
        result, case_errors = _load_case(case, source_pins)
        cases.append(result)
        errors.extend(case_errors)

    windows: list[dict[str, Any]] = []
    for spec in STATIC_WINDOWS:
        try:
            window = _bounded_window(spec)
        except (OSError, ValueError) as exc:
            errors.append(f"STATIC_{spec['name']}:READ_FAILED:{type(exc).__name__}")
            continue
        if window["missing_markers"]:
            errors.append(f"STATIC_{spec['name']}:MISSING_MARKERS")
        windows.append(window)

    military_case = next(item for item in cases if item["name"] == "military_active_cas_to_fra")
    military_reverse = next(item for item in cases if item["name"] == "military_inactive_reverse_fra_to_cas")
    guarantee_before = next(item for item in cases if item["name"] == "guarantee_active_before_revocation")
    guarantee_after = next(item for item in cases if item["name"] == "guarantee_inactive_after_revocation")
    support_active = next(item for item in cases if item["name"] == "support_active_after_reload")

    conclusion = {
        "selected_pair_rule": (
            "For guarantee, support_independence, and military_access, *_active is a verified current-state boolean for the exact inspected actor/recipient pair. "
            "The producer and public contract do not prove a generic grantor/recipient role, so the two role fields remain unknown while the selected endpoints stay explicit."
        ),
        "vassalization": {
            "status": "direction_proven_when_role_flags_are_exclusive",
            "proof": "actor_is_overlord=true and actor_is_subject=false maps actor to overlord/grantor and selected recipient to subject/recipient; the opposite exclusive flags reverse the endpoints",
            "sample": "FRA actor -> ORL recipient, actor_is_overlord=true, actor_is_subject=false",
        },
        "guarantee": {
            "state_key": "guarantee_active",
            "selected_pair": "actor/recipient only",
            "role_mapping": "unproven; do not rename actor or recipient to grantor/beneficiary",
            "archive_check": "FRA->SAV true before the archived revoke and false after it; this validates state changes for the same selected pair, not role names",
        },
        "support_independence": {
            "state_key": "support_independence_active",
            "selected_pair": "actor/recipient only",
            "role_mapping": "unproven; do not infer a supporter/beneficiary role from action_id or direction",
            "archive_check": "FRA->SWE false in the established source pin and true in the archived active reload",
        },
        "military_access": {
            "state_key": "military_access_active",
            "selected_pair": "actor/recipient only",
            "role_mapping": "unproven; preserve selected endpoints and do not infer who grants access",
            "archive_check": "CAS->FRA true while FRA->CAS false in one archived direction report; this is a non-symmetric pair-state observation, not a role label",
        },
        "rival": {
            "state_key": "rival_active",
            "role_mapping": "not_applicable; rival is one-sided and has no grantor/recipient relation role",
        },
        "alliance_current_state": {
            "status": "unresolved",
            "reusable_entry": "none proven",
            "bounded_entry": "ObserverSession.inspect_alliance at bridge/diplomacy.py:15244-15320 is a shared query wire/queue path, and the archived alliance object is pending/incomplete without relationship_state",
            "next_gap": "a current established-alliance relation-state getter or verified relation-state field",
        },
        "royal_marriage_current_state": {
            "status": "unresolved",
            "reusable_entry": "none proven",
            "bounded_entry": "ObserverSession.inspect_royal_marriage at bridge/diplomacy.py:15914-15920 delegates to inspect_alliance with a Royal ACK; the archived object contains legality/acceptance but no relationship_state",
            "next_gap": "a current established-royal-marriage relation-state getter or verified relation-state field",
        },
        "do_not_infer": [
            "action_id names, legality.status, acceptance.predicted_response, pending queue entries, or visibility do not establish an active relation or role direction",
            "the observer query deadline is not relation expiry",
        ],
    }

    asymmetric_checks = [
        {
            "name": "military_reverse_pair",
            "source_sha256": military_case.get("source", {}).get("sha256"),
            "pairs": [
                {
                    "actor": military_case.get("observed", {}).get("actor"),
                    "recipient": military_case.get("observed", {}).get("recipient"),
                    "active": military_case.get("observed", {}).get("active"),
                    "json_pointer": military_case.get("source", {}).get("json_pointer"),
                },
                {
                    "actor": military_reverse.get("observed", {}).get("actor"),
                    "recipient": military_reverse.get("observed", {}).get("recipient"),
                    "active": military_reverse.get("observed", {}).get("active"),
                    "json_pointer": military_reverse.get("source", {}).get("json_pointer"),
                },
            ],
            "interpretation": "different selected pair states are preserved; no grantor role is assigned",
        },
        {
            "name": "guarantee_same_pair_transition",
            "source_sha256": guarantee_before.get("source", {}).get("sha256"),
            "pairs": [
                {
                    "actor": guarantee_before.get("observed", {}).get("actor"),
                    "recipient": guarantee_before.get("observed", {}).get("recipient"),
                    "active": guarantee_before.get("observed", {}).get("active"),
                    "json_pointer": guarantee_before.get("source", {}).get("json_pointer"),
                },
                {
                    "actor": guarantee_after.get("observed", {}).get("actor"),
                    "recipient": guarantee_after.get("observed", {}).get("recipient"),
                    "active": guarantee_after.get("observed", {}).get("active"),
                    "json_pointer": guarantee_after.get("source", {}).get("json_pointer"),
                },
            ],
            "interpretation": "same endpoints with a state transition; role names remain unproven",
        },
    ]

    return {
        "schema": "information_relation_direction_source.v1",
        "status": "bounded_static_and_archived_direction_review",
        "topic": "R01",
        "identity": {
            "game_version": "1.37.4",
            "game_sha256": GAME_SHA256,
            "observer_scope": "FRA selected country pairs",
            "new_runtime_observation": False,
        },
        "conclusion": conclusion,
        "source_report": {
            "path": _relative(SOURCE_REPORT),
            "sha256": source_sha,
            "schema": source.get("schema"),
            "status": source.get("status"),
        },
        "action_mapping": deepcopy(ACTION_MAPPING),
        "supported_families": list(SUPPORTED_FAMILIES),
        "archived_cases": cases,
        "asymmetric_checks": asymmetric_checks,
        "static_bounded_evidence": windows,
        "reusable_getter_review": {
            "alliance": "No current established-relation getter proven; retain inspect_alliance only as a bounded query-wire entry until a relation_state field is verified.",
            "royal_marriage": "No current established-relation getter proven; retain inspect_royal_marriage only as the Royal-ACK query wrapper until a relation_state field is verified.",
        },
        "gaps": [
            "generic grantor/recipient roles for guarantee, support_independence, and military_access",
            "current alliance relation state",
            "current royal-marriage relation state",
            "complete relation enumeration and relation expiry",
        ],
        "verification_errors": errors,
        "resource_policy": {
            "read_mode": "bounded existing JSON and source windows",
            "max_json_bytes": MAX_JSON_BYTES,
            "new_rpm": 0,
            "new_rea": 0,
            "game_access": False,
        },
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
    summary = {
        "output": _relative(args.output) if args.output.is_absolute() else str(args.output),
        "archived_cases": len(report["archived_cases"]),
        "static_windows": len(report["static_bounded_evidence"]),
        "verification_errors": report["verification_errors"],
    }
    print(json.dumps(summary, ensure_ascii=False))
    return 0 if not report["verification_errors"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
