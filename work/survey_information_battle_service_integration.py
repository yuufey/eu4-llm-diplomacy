"""Static contract survey for the future battle -> InformationService adapter.

This tool deliberately does not import the bridge, open a game installation, or
inspect a native image.  It hashes a small, explicit source/test allow-list and
uses Python's AST only to record the symbols and test names that support the
contract conclusions.  The output is exclusive: an existing report is never
overwritten.  ``--verify-existing`` checks an existing report against the same
allow-list without writing it.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]
MAX_FILE_BYTES = 2 * 1024 * 1024

SOURCE_FILES = (
    "bridge/information/model.py",
    "bridge/information/service.py",
    "bridge/information/sources.py",
    "bridge/information/composite.py",
    "bridge/information/catalog.py",
    "work/information_battle_transport.py",
    "work/information_battle_reassembly.py",
    "work/information_battle_observation_wire.py",
    "work/information_battle_log_reader.py",
    "work/ingest_information_battle_raw_live.py",
)

TEST_FILES = (
    "bridge/tests/test_information_service.py",
    "bridge/tests/test_information_sources.py",
    "bridge/tests/test_information_composite.py",
    "work/tests/test_information_battle_transport.py",
    "work/tests/test_information_battle_reassembly.py",
    "work/tests/test_information_battle_log_reader.py",
    "work/test_ingest_information_battle_raw_live.py",
    "work/test_information_battle_observation_wire.py",
)


def _relative(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def _sha256(path: Path) -> tuple[int, str]:
    size = path.stat().st_size
    if size > MAX_FILE_BYTES:
        raise RuntimeError(f"refusing oversized survey input: {_relative(path)} ({size})")
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return size, digest.hexdigest()


def _text(path: Path) -> str:
    if path.stat().st_size > MAX_FILE_BYTES:
        raise RuntimeError(f"refusing oversized AST input: {_relative(path)}")
    return path.read_text(encoding="utf-8")


def _symbols(text: str, path: str) -> list[dict[str, Any]]:
    tree = ast.parse(text, filename=path)
    found: list[dict[str, Any]] = []

    def visit(node: ast.AST, parent: str | None) -> None:
        current = parent
        if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            name = node.name
            qualified = f"{parent}.{name}" if parent else name
            found.append(
                {
                    "kind": type(node).__name__,
                    "name": name,
                    "qualified": qualified,
                    "line": node.lineno,
                    "end_line": getattr(node, "end_lineno", node.lineno),
                }
            )
            current = qualified
        for child in ast.iter_child_nodes(node):
            visit(child, current)

    visit(tree, None)
    return sorted(found, key=lambda item: (item["line"], item["qualified"]))


def _pin(path_text: str, *, tests: bool = False) -> dict[str, Any]:
    path = ROOT / path_text
    if not path.is_file():
        raise FileNotFoundError(path)
    size, digest = _sha256(path)
    symbols = _symbols(_text(path), path_text)
    if tests:
        test_functions = [
            item for item in symbols
            if item["kind"] in {"FunctionDef", "AsyncFunctionDef"}
            and item["name"].startswith("test_")
        ]
        return {
            "path": path_text,
            "size_bytes": size,
            "sha256": digest,
            "test_function_count": len(test_functions),
            "test_functions": test_functions,
        }
    return {
        "path": path_text,
        "size_bytes": size,
        "sha256": digest,
        "symbols": symbols,
    }


def _paths(items: Iterable[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {item["path"]: item for item in items}


def _finding(
    finding_id: str,
    title: str,
    evidence: list[dict[str, Any]],
    conclusion: str,
    boundary: str,
) -> dict[str, Any]:
    return {
        "id": finding_id,
        "title": title,
        "evidence": evidence,
        "conclusion": conclusion,
        "boundary": boundary,
    }


def _contract_findings() -> list[dict[str, Any]]:
    return [
        _finding(
            "IS-API-001",
            "InformationSource is the narrow integration boundary",
            [
                {"path": "bridge/information/model.py", "lines": "51-55", "symbol": "InformationSource", "observed": "context(), catalog(), read(query, context), poll_events(context, cursor)"},
                {"path": "bridge/information/service.py", "lines": "102-112", "symbol": "InformationService._context", "observed": "source context failures become typed source_unavailable/unready context"},
                {"path": "bridge/information/service.py", "lines": "169-202", "symbol": "InformationService._queries", "observed": "catalog-driven topic/object/field/parameter validation precedes source.read"},
                {"path": "bridge/information/service.py", "lines": "403-434", "symbol": "InformationService._collect", "observed": "source field envelopes are normalized and status/value rules are enforced"},
            ],
            "A future battle adapter must implement the four InformationSource methods (and optionally validate_query) and advertise B01-B04 through the catalog before service queries can use them. It must return field envelopes rather than raw transport lines.",
            "This is a static interface conclusion; no battle source is registered in bridge/information.",
        ),
        _finding(
            "IS-DUR-002",
            "Durability and idempotency are layered, not interchangeable",
            [
                {"path": "bridge/information/service.py", "lines": "37-85", "symbol": "InformationService.__init__", "observed": "SQLite FULL/WAL tables include owner-scoped requests, results, runtime, and event dedupe"},
                {"path": "bridge/information/service.py", "lines": "153-167", "symbol": "InformationService._request", "observed": "same owner/request fingerprint replays a response; conflicting arguments are rejected"},
                {"path": "bridge/information/service.py", "lines": "550-638", "symbol": "InformationService.tick", "observed": "periodic/change scheduling persists runtime and budgets results"},
                {"path": "bridge/information/service.py", "lines": "640-711", "symbol": "InformationService._poll_events", "observed": "source cursor, pending batch, event scope digest, event IDs and conflicting duplicate digests are persisted"},
                {"path": "work/information_battle_transport.py", "lines": "128-146,472-578,610-742", "symbol": "BattleFrame/BattleTransportStore", "observed": "attempt_sequence is transport idempotency; commit precedes ack; stream gaps are bounded historical metadata"},
                {"path": "work/information_battle_reassembly.py", "lines": "292-391,420-517,720-866", "symbol": "BattleReassemblyStore", "observed": "source-file cursor binding, fragment identity, cursor CAS and durable fragment progress are independent of InformationService"},
                {"path": "work/information_battle_log_reader.py", "lines": "260-662", "symbol": "BattleLogTailer", "observed": "file identity/header/cursor and ack-before-checkpoint are durable at the log boundary"},
            ],
            "The adapter must consume only committed reassembly/transport records, maintain a stable source cursor, and emit stable business event_id values. attempt_sequence, received_order, fragment message_id, and InformationService event_id must remain separate identities. Cursor advancement must not discard an unprocessed batch; service pending events cover only the final service boundary.",
            "There is no existing shared schema that maps an opaque transport attempt or fragment group to a public battle event.",
        ),
        _finding(
            "IS-SCOPE-003",
            "Session, world, game version and observer scope are mandatory guards",
            [
                {"path": "bridge/information/service.py", "lines": "249-310", "symbol": "_schedule/_check_triggers/_subscription_config", "observed": "binding session/observer/game_version/world_id and trigger/version checks are validated"},
                {"path": "bridge/information/service.py", "lines": "377-401", "symbol": "_observer_matches/_scope_error", "observed": "object/parameter observer and session mismatches are rejected"},
                {"path": "bridge/information/service.py", "lines": "522-523", "symbol": "_binding_matches", "observed": "subscription binding is compared with current context"},
                {"path": "bridge/information/service.py", "lines": "550-568", "symbol": "tick", "observed": "same-session date rewind clears baseline/event source epoch; unknown world restart requires revalidation"},
                {"path": "bridge/information/sources.py", "lines": "356-376,645-726", "symbol": "DiplomacySource.context/poll_events", "observed": "live context and event payloads carry session/observer/game version/date/source provenance"},
            ],
            "A battle source must expose a ready context with session_id, observer, game_version, game_day/date, mode live and a stable world_id (plus executable/DLL provenance when available). It must refuse reads/events after session, observer, version or world changes; historical source data must not silently satisfy a live binding.",
            "The existing service provides the guard, but no battle adapter currently supplies or verifies these fields.",
        ),
        _finding(
            "IS-PARTIAL-004",
            "Partial, invisible and stale values have explicit field semantics",
            [
                {"path": "bridge/information/service.py", "lines": "403-461", "symbol": "_collect/_save_result", "observed": "known requires value; unknown/invisible/unavailable/stale/unsupported omit value; complete requires all selected fields known or not_applicable"},
                {"path": "bridge/information/service.py", "lines": "640-711", "symbol": "_poll_events", "observed": "incomplete source batches/events downgrade generated results and preserve gaps"},
                {"path": "work/information_battle_observation_wire.py", "lines": "85-166", "symbol": "decode", "observed": "raw observation sets complete=false, visibility_verified=false and public identity absent"},
                {"path": "work/ingest_information_battle_raw_live.py", "lines": "269-332", "symbol": "_message_report", "observed": "transport/raw payload completeness never promotes business/battle/overall completeness"},
                {"path": "work/information_battle_reassembly.py", "lines": "777-866,987-1020", "symbol": "poll_from_store/get_message", "observed": "transport completion is separate and battle/overall completion remain false"},
            ],
            "The adapter must publish unknown/invisible/unavailable/stale fields without values, preserve partial results and gaps, and only set complete after its own business identity, visibility and event completeness checks. A raw-only record must remain partial/unknown and cannot be emitted as a B01-B04 known battle result.",
            "Transport-complete opaque bytes are not a business-complete battle report.",
        ),
        _finding(
            "IS-WAR-ID-005",
            "No reusable stable war_id/battle_id registry is present",
            [
                {"path": "bridge/information/catalog.py", "lines": "168-171", "symbol": "B01-B04 catalog rows", "observed": "war_id/battle fields are declared but all four topics are planned"},
                {"path": "work/information_battle_observation_wire.py", "lines": "144-166", "symbol": "decode", "observed": "public_identity.status=absent and war_id/battle_id are null"},
                {"path": "work/ingest_information_battle_raw_live.py", "lines": "276-332", "symbol": "_message_report", "observed": "raw report does not create a public business identity"},
                {"path": "work/information_battle_reassembly.py", "lines": "559-618,987-1020", "symbol": "_latch_conflict/_assemble_complete/get_message", "observed": "message_id identifies an opaque fragment group and transport completion only"},
                {"path": "bridge/information/sources.py", "lines": "331-338,645-726", "symbol": "DiplomacySource", "observed": "existing live event types are diplomacy/journal/evidence, not battles"},
            ],
            "Do not reuse transport attempt_sequence, received_order, fragment message_id, event_id, country references or a raw pointer as war_id/battle_id. A future source needs an explicit, versioned business identity registry or an independently guarded derivation before B01 can be available.",
            "The conclusion is absence of a reusable registry in the inspected source; it is not evidence that no registry could ever be added.",
        ),
        _finding(
            "IS-COMPOSITE-006",
            "Battle events must be owned by the primary event source",
            [
                {"path": "bridge/information/composite.py", "lines": "13-43", "symbol": "CompositeSource", "observed": "primary owns context and event_types; adapters contribute catalog/read routes"},
                {"path": "bridge/information/composite.py", "lines": "45-84", "symbol": "CompositeSource.validate_query/read/poll_events", "observed": "adapter fields route to their adapter; poll_events delegates only to primary"},
                {"path": "bridge/information/service.py", "lines": "640-711", "symbol": "_poll_events", "observed": "one source cursor/pending batch is consumed for all event subscriptions"},
            ],
            "A battle event stream must be the primary source or be merged by one unified primary event source. A second CompositeSource adapter cannot independently poll battle events without a new fan-in/cursor contract; its read-only route is insufficient for B01-B04 event subscriptions.",
            "No production fan-in or battle adapter is present.",
        ),
        _finding(
            "IS-RECORDED-007",
            "Recorded sources do not prove a live battle integration",
            [
                {"path": "bridge/information/sources.py", "lines": "729-917", "symbol": "RecordedSource", "observed": "recorded context/events are archive-derived and use generated recorded event IDs"},
                {"path": "bridge/tests/test_information_sources.py", "lines": "200-260", "symbol": "recorded fixture tests", "observed": "tests preserve recorded provenance/identity and event behavior"},
            ],
            "Recorded fixtures may test envelope and cursor behavior, but they cannot establish current session/world scope, native visibility, or live battle identity. A production battle source must not use RecordedSource as a substitute for those guards.",
            "This survey intentionally does not add a fake source or claim end-to-end support.",
        ),
    ]


def _coverage_summary(source_pins: list[dict[str, Any]], test_pins: list[dict[str, Any]]) -> dict[str, Any]:
    by_path = _paths(test_pins)
    service_tests = by_path["bridge/tests/test_information_service.py"]["test_functions"]
    source_tests = by_path["bridge/tests/test_information_sources.py"]["test_functions"]
    composite_tests = by_path["bridge/tests/test_information_composite.py"]["test_functions"]
    battle_paths = [
        "work/tests/test_information_battle_transport.py",
        "work/tests/test_information_battle_reassembly.py",
        "work/tests/test_information_battle_log_reader.py",
        "work/test_ingest_information_battle_raw_live.py",
        "work/test_information_battle_observation_wire.py",
    ]
    battle_count = sum(by_path[path]["test_function_count"] for path in battle_paths)
    return {
        "service_core": {
            "files": ["bridge/tests/test_information_service.py", "bridge/tests/test_information_sources.py", "bridge/tests/test_information_composite.py"],
            "test_function_count": len(service_tests) + len(source_tests) + len(composite_tests),
            "areas": [
                "catalog-driven query validation and identity/observer scope",
                "request idempotency and owner isolation",
                "periodic/event/change schedules, missed periods, pause/resume/cancel",
                "event filtering, per-scope dedupe, over-budget batches and cursor reset",
                "source failures/partial and context-change stale results",
                "durable delivery claim and no resend after unknown receipt",
                "restart/world revalidation, configuration and concurrent requests",
                "composite static/live routing and recorded provenance",
            ],
        },
        "battle_pipeline": {
            "files": battle_paths,
            "test_function_count": battle_count,
            "areas": [
                "wire validation and raw bounded decoding",
                "transport commit-before-ack, idempotency, conflict, stream gaps and paging",
                "reassembly fragment identity, CRC/conflict/capacity, source binding, cursor CAS and native fixture",
                "checked log header/file identity/locking/cursor checkpoint and native handoff",
                "offline tailer -> transport -> reassembly raw ingestion",
            ],
        },
        "end_to_end_battle_source_to_information_service": {
            "covered": False,
            "reason": "No inspected test constructs a battle InformationSource, advertises B01-B04 as available, or feeds a committed battle event through InformationService._poll_events.",
        },
        "coverage_gaps": [
            "No production battle source/adapter is registered in bridge/information.",
            "No service schema maps transport/reassembly cursors or attempts to a business event cursor.",
            "No stable war_id/battle_id registry, visibility proof, winner/side semantics, or public battle event envelope exists.",
            "No test proves live battle session/world/observer revalidation through InformationService.",
            "No test proves a raw-only or transport-complete record is rejected as a complete B01-B04 result at the service boundary.",
        ],
    }


def _build_report() -> dict[str, Any]:
    source_pins = [_pin(path) for path in SOURCE_FILES]
    test_pins = [_pin(path, tests=True) for path in TEST_FILES]
    return {
        "schema": "information_battle_service_integration_survey_v1",
        "status": "static_contract_survey_complete",
        "generated_by": "work/survey_information_battle_service_integration.py",
        "scope": {
            "read_only": True,
            "game_access": False,
            "rea_or_rpm": False,
            "production_modified": False,
            "historical_reports_modified": False,
            "fake_battle_source_added": False,
            "runtime_or_live_claim": False,
        },
        "survey_inputs": {
            "source_allow_list": list(SOURCE_FILES),
            "test_allow_list": list(TEST_FILES),
            "max_input_bytes": MAX_FILE_BYTES,
            "method": "streaming SHA-256 plus bounded AST symbol extraction; no imports or dynamic execution",
        },
        "source_pins": source_pins,
        "test_pins": test_pins,
        "contract_findings": _contract_findings(),
        "integration_contract": {
            "minimum_battle_source_api": {
                "methods": [
                    "context() -> dict",
                    "catalog() -> list[dict]",
                    "read(query, context) -> dict",
                    "poll_events(context, cursor) -> dict",
                ],
                "context_required": [
                    "status=ready",
                    "session_id",
                    "observer",
                    "game_version",
                    "game_day and game_date",
                    "mode=live",
                    "world_id (or explicit revalidation/needs_rebind behavior)",
                    "source provenance such as game_sha256/dll_sha256 when available",
                ],
                "event_batch_shape": ["events", "cursor", "complete", "gaps"],
                "event_shape_before_service_acceptance": [
                    "stable business event_id",
                    "session_id/observer/game_version/world_id",
                    "game date/day",
                    "source provenance",
                    "complete and visibility/business identity guards",
                    "B01-B04 field envelopes with status/value rules",
                ],
                "catalog_requirement": "B01-B04 must move from planned to an explicitly supported/partial status with field-level capability and trigger event_types before query/subscription validation can accept them.",
            },
            "durable_cursor_and_idempotency": {
                "information_service": "info_runtime stores event-source scope, cursor, pending events, completion/gaps and epoch; info_events deduplicates by owner/scope/event_id plus digest; owner/request fingerprints make repeated request IDs idempotent.",
                "transport": "BattleTransportStore durably commits opaque attempt_sequence records before ack; attempt identity is installation+world_generation+attempt_sequence and stream gaps are historical bounded metadata.",
                "reassembly": "BattleReassemblyStore binds a stable source file/schema, consumes received_order with cursor CAS, and persists fragment attempts/groups/conflicts/complete opaque payloads.",
                "tailer": "BattleLogTailer persists file identity/header/cursor and checkpoints only after receiver ack.",
                "adapter_requirement": "The battle adapter must consume only committed rows, retain a stable source cursor and map one business event to a stable event_id; it must preserve pending/gap information if a source cursor advances before service processing. No attempt/fragment/order ID may be used as public battle identity.",
            },
            "session_world_observer_guard": {
                "service_guards": ["binding session/observer/game_version/world_id", "object/parameter observer role", "source context status", "same-session date rewind reset", "unknown-world restart requires explicit rebind/resume"],
                "adapter_requirement": "Revalidate session, world generation, observer and game version at every poll/read boundary; a changed or unknown world must block automatic reads and clear/invalidate event baseline/cursor as required by service runtime.",
                "historical_data_rule": "Recorded/archive data is not allowed to satisfy a live binding unless an explicit recorded mode is requested and its scope is separately identified.",
            },
            "partial_invisible_values": {
                "accepted_non_known_statuses": ["unknown", "invisible", "not_applicable", "unavailable", "stale", "unsupported"],
                "known_rule": "known requires value; non-known field must not carry value",
                "result_rule": "complete only when source complete and all selected fields are known or not_applicable; partial/failed remain queryable",
                "raw_boundary": "wire/reassembly/ingest may report transport_complete or raw_payload_complete, but business/battle/overall completeness and visibility remain false until independently proven",
            },
            "war_id_registry": {
                "reusable_registry_found": False,
                "do_not_reuse": ["transport attempt_sequence", "received_order", "fragment message_id", "generic InformationService event_id", "country raw references", "native/raw pointer values"],
                "required_before_B01": "an explicit versioned war_id/battle_id registry or a narrowly guarded derivation with scope, collision and visibility evidence",
            },
            "raw_only_rejection_points": [
                {"path": "work/information_battle_observation_wire.py", "lines": "85-166", "reason": "decode explicitly returns complete=false, visibility_verified=false and absent public_identity"},
                {"path": "work/ingest_information_battle_raw_live.py", "lines": "269-332", "reason": "raw ingest keeps business_complete/battle_complete/overall_complete false"},
                {"path": "work/information_battle_reassembly.py", "lines": "777-866,987-1020", "reason": "transport-complete opaque payload does not become battle/overall complete"},
                {"path": "bridge/information/composite.py", "lines": "81-84", "reason": "adapter pollers are not independently fanned into service event processing"},
            ],
        },
        "test_coverage": _coverage_summary(source_pins, test_pins),
        "limitations": [
            "Static source/test evidence only; no game, native runtime, REA/RPM, or live battle event was accessed.",
            "The report does not claim B01-B04 availability or an InformationService battle integration.",
            "Source hashes pin the inspected snapshot; any later production change requires a new survey.",
        ],
    }


def _verify_existing(output: Path) -> int:
    with output.open("r", encoding="utf-8") as handle:
        report = json.load(handle)
    expected = _build_report()
    mismatches: list[str] = []
    for section in ("source_pins", "test_pins"):
        actual_by_path = {item["path"]: item for item in report.get(section, [])}
        expected_by_path = {item["path"]: item for item in expected.get(section, [])}
        for path, current in expected_by_path.items():
            old = actual_by_path.get(path)
            if not old:
                mismatches.append(f"{section} missing {path}")
                continue
            for key in ("size_bytes", "sha256"):
                if old.get(key) != current.get(key):
                    mismatches.append(f"{path} {key}: report={old.get(key)!r} current={current.get(key)!r}")
    if mismatches:
        print(json.dumps({"verified": False, "mismatches": mismatches}, ensure_ascii=False, indent=2))
        return 1
    print(json.dumps({"verified": True, "report": str(output), "source_count": len(expected["source_pins"]), "test_file_count": len(expected["test_pins"])}, ensure_ascii=False, indent=2))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("work/runtime/information-battle-business-20261025-001/service-integration-contract-001.json"))
    parser.add_argument("--verify-existing", action="store_true", help="verify pins in an existing report without writing")
    args = parser.parse_args(argv)
    output = args.output if args.output.is_absolute() else ROOT / args.output
    if args.verify_existing:
        if not output.is_file():
            raise SystemExit(f"report does not exist: {output}")
        return _verify_existing(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    report = _build_report()
    report["output"] = {"path": _relative(output), "exclusive": True}
    encoded = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    try:
        with output.open("x", encoding="utf-8", newline="\n") as handle:
            handle.write(encoded)
    except FileExistsError:
        raise SystemExit(f"refusing to overwrite existing report: {output}")
    print(json.dumps({"created": True, "path": _relative(output), "bytes": len(encoded.encode('utf-8')), "sources": len(SOURCE_FILES), "test_files": len(TEST_FILES)}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
