"""Bounded, read-only survey of the existing battle-message call gates.

This is an offline mechanical report builder.  It consumes the already saved
REA evidence or bounded selected reports for the six functions in the known
result-message path.  It intentionally does not query REA, attach to a game,
or infer visibility, ABI, hook safety, or player semantics.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / "work" / "runtime" / "information-battle-fragments-20261025-001"
OUTPUT = STAGE / "capture-gate-survey-001.json"

FIXED_BUILD = "1.37.4"
FIXED_EXE_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
MAX_FULL_JSON_BYTES = 10 * 1024 * 1024
MAX_SELECTED_JSON_BYTES = 2 * 1024 * 1024
MAX_CONTEXT_LINES = 120
MAX_OUTPUT_BYTES = 4 * 1024 * 1024


def rel(path: Path) -> str:
    """Return a repository-relative path without exposing machine prefixes."""

    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except ValueError:
        return str(path.resolve())


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_json_bounded(path: Path, limit: int) -> tuple[dict[str, Any], dict[str, Any]]:
    """Read one small JSON report and ensure it did not change while reading."""

    before = path.stat()
    if before.st_size > limit:
        raise ValueError(f"bounded JSON limit exceeded: {rel(path)} ({before.st_size} > {limit})")
    content = path.read_bytes()
    after = path.stat()
    if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        raise ValueError(f"source changed during bounded read: {rel(path)}")
    try:
        value = json.loads(content.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid UTF-8 JSON: {rel(path)}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"top-level JSON object required: {rel(path)}")
    return value, {
        "path": rel(path),
        "bytes": before.st_size,
        "mtime_ns": before.st_mtime_ns,
        "sha256": hashlib.sha256(content).hexdigest(),
        "read_limit_bytes": limit,
        "stable_during_read": True,
    }


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def value_of(node: Any, path: str) -> Any:
    """Extract a selected-report bounded value wrapper."""

    require(isinstance(node, dict), f"missing wrapper: {path}")
    require(node.get("status") == "observed", f"unobserved selected value: {path}")
    value = node.get("value")
    require(value is not None, f"missing selected value: {path}")
    return value


def body_summary(procedure: dict[str, Any]) -> dict[str, Any]:
    body = procedure.get("body")
    require(isinstance(body, dict), "procedure body missing")
    return {
        "address": procedure.get("address"),
        "name": procedure.get("name"),
        "body": {
            "ranges": body.get("ranges"),
            "total_bytes": body.get("total_bytes"),
            "span_bytes": body.get("span_bytes"),
            "non_contiguous": body.get("non_contiguous"),
            "contains_entry": body.get("contains_entry"),
        },
    }


def _subject_sha(raw: dict[str, Any]) -> str:
    subject = raw.get("subject")
    require(isinstance(subject, dict), "subject missing")
    digest = subject.get("digest")
    require(isinstance(digest, dict), "subject digest missing")
    value = digest.get("sha256")
    require(isinstance(value, str), "subject sha256 missing")
    return value


def _selected_subject_sha(report: dict[str, Any]) -> str:
    top = report.get("top_level")
    require(isinstance(top, dict), "selected top_level missing")
    subject = value_of(top.get("subject"), "top_level.subject")
    require(isinstance(subject, dict), "selected subject missing")
    digest = subject.get("digest")
    require(isinstance(digest, dict), "selected subject digest missing")
    value = digest.get("sha256")
    require(isinstance(value, str), "selected subject sha256 missing")
    return value


def _procedure_rva(address: str) -> str:
    require(isinstance(address, str) and address.startswith("0x"), f"bad procedure address: {address!r}")
    return "0x" + address[3:].lower() if address.startswith("0x140") else address.lower()


def load_raw(spec: dict[str, Any]) -> dict[str, Any]:
    path = ROOT / spec["path"]
    report, file_meta = load_json_bounded(path, MAX_FULL_JSON_BYTES)
    require(file_meta["bytes"] == spec["bytes"], f"raw size changed: {spec['name']}")
    require(file_meta["sha256"] == spec["sha256"], f"raw sha changed: {spec['name']}")
    require(report.get("evidence_id") == spec["evidence_id"], f"raw evidence id changed: {spec['name']}")
    require(_subject_sha(report) == FIXED_EXE_SHA256, f"raw EXE SHA mismatch: {spec['name']}")
    parameters = report.get("parameters")
    require(isinstance(parameters, dict), f"raw parameters missing: {spec['name']}")
    require(parameters.get("procedure") == spec["procedure"], f"raw procedure mismatch: {spec['name']}")
    value = report.get("raw_result", {}).get("value")
    require(isinstance(value, dict), f"raw result value missing: {spec['name']}")
    procedure = value.get("procedure")
    require(isinstance(procedure, dict), f"raw procedure body missing: {spec['name']}")
    require(procedure.get("address") == spec["procedure"], f"raw result address mismatch: {spec['name']}")
    return {
        "name": spec["name"],
        "kind": "raw_rea_evidence",
        "evidence_id": report["evidence_id"],
        "procedure_rva": spec["rva"],
        "procedure_address": spec["procedure"],
        "fixed_build": FIXED_BUILD,
        "source": file_meta,
        "target": {"sha256": _subject_sha(report), "path": rel(path)},
        "body": body_summary(procedure),
        "pseudocode": value.get("pseudocode"),
        "assembly": value.get("assembly"),
        "callees": value.get("callees"),
    }


def load_selected(spec: dict[str, Any]) -> dict[str, Any]:
    path = ROOT / spec["path"]
    report, selected_meta = load_json_bounded(path, MAX_SELECTED_JSON_BYTES)
    require(selected_meta["bytes"] == spec["selected_bytes"], f"selected size changed: {spec['name']}")
    require(selected_meta["sha256"] == spec["selected_sha256"], f"selected sha changed: {spec['name']}")
    require(report.get("status") == "observed", f"selected status is not observed: {spec['name']}")
    require(_selected_subject_sha(report) == FIXED_EXE_SHA256, f"selected EXE SHA mismatch: {spec['name']}")
    top = report.get("top_level")
    evidence_id = value_of(top.get("evidence_id"), "top_level.evidence_id")
    require(evidence_id == spec["evidence_id"], f"selected evidence id changed: {spec['name']}")
    source = report.get("source")
    require(isinstance(source, dict), f"selected source missing: {spec['name']}")
    require(source.get("sha256") == spec["raw_sha256"], f"selected raw source sha changed: {spec['name']}")
    require(source.get("size_bytes") == spec["raw_bytes"], f"selected raw source size changed: {spec['name']}")
    require(source.get("stable_before_after") is True, f"selected source was not stable: {spec['name']}")
    source_path = Path(str(source.get("path")))
    require(source_path.exists(), f"selected raw source missing: {source_path}")
    source_stat = source_path.stat()
    require(source_stat.st_size == spec["raw_bytes"], f"selected raw source stat changed: {spec['name']}")
    query = report.get("query")
    if query is not None:
        require(query.get("target_sha256") == FIXED_EXE_SHA256, f"selected query EXE mismatch: {spec['name']}")
        require(query.get("authorised_procedure") == spec["procedure"], f"selected query procedure mismatch: {spec['name']}")
        require(query.get("authorised_rva") == spec["rva"], f"selected query RVA mismatch: {spec['name']}")
    value = report.get("raw_result_value")
    require(isinstance(value, dict), f"selected raw result value missing: {spec['name']}")
    procedure = value_of(value.get("procedure"), "raw_result_value.procedure")
    require(procedure.get("address") == spec["procedure"], f"selected result address mismatch: {spec['name']}")
    return {
        "name": spec["name"],
        "kind": "bounded_selected_report",
        "evidence_id": evidence_id,
        "procedure_rva": spec["rva"],
        "procedure_address": spec["procedure"],
        "fixed_build": FIXED_BUILD,
        "selected_report": selected_meta,
        "raw_source": {
            "path": rel(source_path),
            "bytes": source.get("size_bytes"),
            "sha256": source.get("sha256"),
            "stat_size_bytes": source_stat.st_size,
            "sha256_from_selected_report": True,
            "raw_json_loaded": False,
            "reason": "source exceeds the full-JSON survey read path; selected values were used",
        },
        "target": {"sha256": _selected_subject_sha(report)},
        "body": body_summary(procedure),
        "pseudocode": value.get("pseudocode"),
        "assembly": value.get("assembly"),
        "callees": value.get("callees"),
    }


def pseudocode_text(source: dict[str, Any]) -> str:
    value = source.get("pseudocode")
    if isinstance(value, str):
        return value
    return str(value_of(value, f"{source['name']}.pseudocode"))


def pseudo_context(source: dict[str, Any], label: str, start: int, end: int) -> dict[str, Any]:
    require(1 <= start <= end, f"bad context range: {source['name']} {label}")
    require(end - start + 1 <= MAX_CONTEXT_LINES, f"context too large: {source['name']} {label}")
    lines = pseudocode_text(source).splitlines()
    actual_start = max(1, start)
    actual_end = min(len(lines), end)
    return {
        "kind": "pseudocode",
        "label": label,
        "source": source["name"],
        "line_start": actual_start,
        "line_end": actual_end,
        "requested_line_start": start,
        "requested_line_end": end,
        "lines": [{"line": i, "text": lines[i - 1]} for i in range(actual_start, actual_end + 1)],
    }


_ADDRESS_RE = re.compile(r"^0x([0-9a-fA-F]+):")


def assembly_context(source: dict[str, Any], label: str, start: int, end: int) -> dict[str, Any]:
    assembly = source.get("assembly")
    if not isinstance(assembly, list) or not assembly:
        return {
            "kind": "assembly",
            "label": label,
            "source": source["name"],
            "status": "unavailable_in_selected_report",
            "requested_address_start": hex(start),
            "requested_address_end": hex(end),
            "reason": "the bounded selected report contains pseudocode/callees but no assembly value",
            "lines": [],
        }
    selected: list[dict[str, Any]] = []
    for index, item in enumerate(assembly, 1):
        if not isinstance(item, str):
            continue
        match = _ADDRESS_RE.match(item)
        if not match:
            continue
        address = int(match.group(1), 16)
        if start <= address <= end:
            selected.append({"line": index, "address": hex(address), "text": item})
    return {
        "kind": "assembly",
        "label": label,
        "source": source["name"],
        "status": "observed",
        "requested_address_start": hex(start),
        "requested_address_end": hex(end),
        "lines": selected,
    }


def context_entry(source: dict[str, Any], label: str, pseudo: tuple[int, int] | None = None,
                  assembly: tuple[int, int] | None = None) -> dict[str, Any]:
    entry: dict[str, Any] = {"source": source["name"], "label": label}
    if pseudo is not None:
        entry["pseudocode"] = pseudo_context(source, label, *pseudo)
    if assembly is not None:
        entry["assembly"] = assembly_context(source, label, *assembly)
    return entry


def find_literal_keys(source: dict[str, Any]) -> list[str]:
    text = pseudocode_text(source)
    # Keep only the literal formatter keys; do not treat them as semantic proof.
    keys = sorted(set(re.findall(r'"([A-Z][A-Z0-9_]{2,63})"', text)))
    return [key for key in keys if any(token in key for token in ("OUR", "ENEMY", "YOU_", "RESULT", "BATTLE", "WIN", "LOSS"))]


def source_descriptor(source: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": source["name"],
        "kind": source["kind"],
        "evidence_id": source["evidence_id"],
        "procedure_rva": source["procedure_rva"],
        "procedure_address": source["procedure_address"],
        "fixed_build": source["fixed_build"],
        "body": source["body"],
        "source": source["source"] if source["kind"] == "raw_rea_evidence" else source["selected_report"],
        "raw_source": source.get("raw_source"),
    }


def main() -> int:
    if OUTPUT.exists():
        raise SystemExit(f"refusing to overwrite existing output: {rel(OUTPUT)}")

    specs: list[dict[str, Any]] = [
        {
            "name": "result_router_23a020",
            "kind": "raw",
            "path": "work/runtime/information-battles-20261025-001/rea-battle-result-router-001/evidence.json",
            "bytes": 2968377,
            "sha256": "e90c41522700fba9add03336fc7224b8086c7d426dbdea1c409e968ed989d663",
            "evidence_id": "ev_c499fbd451a6770ca30c322fada384276fa7aba73aae2447fc14a1479753eae3",
            "procedure": "0x14023a020",
            "rva": "0x23a020",
        },
        {
            "name": "land_formatter_232a80",
            "kind": "selected",
            "path": "work/runtime/information-battle-layout-20261025-001/rea-land-result-message-001/selected-evidence-001.json",
            "selected_bytes": 109103,
            "selected_sha256": "82455e0f1f9fe27bc3dba2e3bea176743ce21d89b076f5e789a8b7f5cef83242",
            "raw_bytes": 10281549,
            "raw_sha256": "272c19c062bdb9ce628689e0bbe2fd93d2e2a54a5ff8b4af6d252ebb182a7921",
            "evidence_id": "ev_5afd555610c9df1e0d724c03a92c96db97bee25a3c8c007a0132fb362bf42c89",
            "procedure": "0x140232a80",
            "rva": "0x232a80",
        },
        {
            "name": "naval_formatter_22e6b0",
            "kind": "selected",
            "path": "work/runtime/information-battles-20261025-001/rea-message-dispatch-001/selected-evidence-001.json",
            "selected_bytes": 124699,
            "selected_sha256": "ca5bf66fa2682e6e066d8ee75d6b5e56a325cbd67654c25b9a6d51509a576d6b",
            "raw_bytes": 10577723,
            "raw_sha256": "017a28a7d4ded0ff1bc4668da53d7fdb72750045fa229a39c40a88a4d7177734",
            "evidence_id": "ev_b2600be25bd20c48261bd979bc6a9c44ae67edeedacc1a4d4a604da7a22bad2e",
            "procedure": "0x14022e6b0",
            "rva": "0x22e6b0",
        },
        {
            "name": "message_instance_8d44a0",
            "kind": "raw",
            "path": "work/runtime/information-battle-message-20261025-001/rea-message-instance-001/evidence.json",
            "bytes": 2668879,
            "sha256": "daf82cdd676cbd73be15a174835e5a5c625513aeab5f4e234479398a1025b1f4",
            "evidence_id": "ev_3d93e7a0b9c66ea6a4fc361d80868c62dc546c73c0fa1f8b963ea30c47ba0b73",
            "procedure": "0x1408d44a0",
            "rva": "0x8d44a0",
        },
        {
            "name": "result_delivery_244630",
            "kind": "raw",
            "path": "work/runtime/information-battle-message-20261025-001/rea-result-delivery-001/evidence.json",
            "bytes": 288037,
            "sha256": "3ef501de2358e305fe6688850f3744b1caa4985d257e09f5f438eca9c984ae6e",
            "evidence_id": "ev_3e8d5882cbd806cf067d34b97665b40eaecb95cdf25935fca5d923d1ebdadbf9",
            "procedure": "0x140244630",
            "rva": "0x244630",
        },
        {
            "name": "message_consumer_8c05f0",
            "kind": "raw",
            "path": "work/runtime/information-battle-message-20261025-001/rea-message-consumer-001/evidence.json",
            "bytes": 4028167,
            "sha256": "23556b112b309dc39e6543a89446566d4988a2df635cdd487f57c16052751612",
            "evidence_id": "ev_7c83800baf700500a9000917e68dbbc53387cb49d61a9f8ba977378feb2801d1",
            "procedure": "0x1408c05f0",
            "rva": "0x8c05f0",
        },
    ]

    loaded: dict[str, dict[str, Any]] = {}
    for spec in specs:
        loaded[spec["name"]] = load_raw(spec) if spec["kind"] == "raw" else load_selected(spec)

    contexts = [
        context_entry(loaded["result_router_23a020"], "router setup and type dispatch", (131, 197), (0x14023A3F0, 0x14023A470)),
        context_entry(loaded["land_formatter_232a80"], "land side selection and country lookup", (83, 140)),
        context_entry(loaded["land_formatter_232a80"], "land result strings and formatter gate", (1373, 1474)),
        context_entry(loaded["naval_formatter_22e6b0"], "naval side selection and current-id lookup", (73, 117)),
        context_entry(loaded["naval_formatter_22e6b0"], "naval result strings and formatter gate", (1375, 1441)),
        context_entry(loaded["naval_formatter_22e6b0"], "naval loss branch and formatter gate", (1540, 1592)),
        context_entry(loaded["message_instance_8d44a0"], "message object copy and reference fallback", (15, 85), (0x1408D44B4, 0x1408D4610)),
        context_entry(loaded["result_delivery_244630"], "delivery optional-pair branches", (18, 43), (0x140244681, 0x1402446B5)),
        context_entry(loaded["message_consumer_8c05f0"], "consumer early suppression gate", (82, 150)),
        context_entry(loaded["message_consumer_8c05f0"], "consumer log and message-object gate", (263, 349), (0x1408C0D20, 0x1408C0D50)),
    ]

    chain = [
        {
            "kind": "mechanical_static_branch",
            "from": "0x23a020",
            "to": "0x22e6b0",
            "condition": "virtual call at *param_1+0x60 returns 2",
            "location": {"pseudocode_lines": [183, 185], "assembly_addresses": ["0x14023a419", "0x14023a425"]},
            "evidence_id": loaded["result_router_23a020"]["evidence_id"],
        },
        {
            "kind": "mechanical_static_branch",
            "from": "0x23a020",
            "to": "0x232a80",
            "condition": "virtual call at *param_1+0x60 returns 1",
            "location": {"pseudocode_lines": [187, 191], "assembly_addresses": ["0x14023a432", "0x14023a441"]},
            "evidence_id": loaded["result_router_23a020"]["evidence_id"],
        },
        {
            "kind": "mechanical_static_call",
            "from": "0x232a80",
            "to": "0x8d44a0",
            "location": {"pseudocode_line": 1469},
            "evidence_id": loaded["land_formatter_232a80"]["evidence_id"],
        },
        {
            "kind": "mechanical_static_call",
            "from": "0x232a80",
            "to": "0x244630",
            "location": {"pseudocode_line": 1470},
            "evidence_id": loaded["land_formatter_232a80"]["evidence_id"],
        },
        {
            "kind": "mechanical_static_call",
            "from": "0x22e6b0",
            "to": "0x8d44a0",
            "location": {"pseudocode_line": 1589},
            "evidence_id": loaded["naval_formatter_22e6b0"]["evidence_id"],
        },
        {
            "kind": "mechanical_static_call",
            "from": "0x22e6b0",
            "to": "0x244630",
            "location": {"pseudocode_line": 1590},
            "evidence_id": loaded["naval_formatter_22e6b0"]["evidence_id"],
        },
        {
            "kind": "mechanical_static_call",
            "from": "0x244630",
            "to": "0x8c05f0",
            "condition": "param_3 == 0 or param_4 == 0 branch",
            "location": {"pseudocode_line": 21, "assembly_address": "0x1402446B2"},
            "evidence_id": loaded["result_delivery_244630"]["evidence_id"],
        },
        {
            "kind": "mechanical_static_call",
            "from": "0x244630",
            "to": "0x8c05f0",
            "condition": "param_3 != 0 and param_4 != 0 branch",
            "location": {"pseudocode_line": 35, "assembly_address": "0x14024468C"},
            "evidence_id": loaded["result_delivery_244630"]["evidence_id"],
        },
        {
            "kind": "mechanical_static_call",
            "from": "0x8c05f0",
            "to": "0x8d44a0",
            "condition": "param_2+0x48 path and param_3+0x38 is nonzero",
            "location": {"pseudocode_line": 327, "assembly_address": "0x1408C0D3C"},
            "evidence_id": loaded["message_consumer_8c05f0"]["evidence_id"],
        },
    ]

    observations = [
        {
            "id": "land_formatter_gate",
            "function": "0x232a80",
            "evidence_id": loaded["land_formatter_232a80"]["evidence_id"],
            "mechanical_condition": "bVar31 is derived from *(char *)(param_2+0x4c)==0; when !bVar31, control jumps to cleanup before LANDBATTLEOVER/UI creation (line 1441). When the selected side vector count is zero, the 8d44a0/244630 block is skipped (lines 1453-1470).",
            "semantic_status": "condition observed; meaning as allied/enemy/nonparticipant is unresolved",
        },
        {
            "id": "naval_formatter_gate",
            "function": "0x22e6b0",
            "evidence_id": loaded["naval_formatter_22e6b0"]["evidence_id"],
            "mechanical_condition": "both side vectors at lVar17+0x28 and lVar17+0x20 must be nonempty before NAVALBATTLEOVER, 8d44a0, and 244630 (lines 1565-1590).",
            "semantic_status": "condition observed; meaning as allied/enemy/nonparticipant is unresolved",
        },
        {
            "id": "consumer_top_gate",
            "function": "0x8c05f0",
            "evidence_id": loaded["message_consumer_8c05f0"]["evidence_id"],
            "mechanical_condition": "the early branch clears param_2+0x60 and param_2+0x10 when global mode/handle checks, param_1+0x48, or FUN_1408c1ba0() fail (lines 82-87).",
            "semantic_status": "condition observed; no player/allied/enemy/participant label is established",
        },
        {
            "id": "consumer_message_object_gate",
            "function": "0x8c05f0",
            "evidence_id": loaded["message_consumer_8c05f0"]["evidence_id"],
            "mechanical_condition": "the later 8d44a0 construction is under *(char *)(lVar8+0x11)!=0 and has a separate param_3+0x38 null/non-null branch (lines 286-327).",
            "semantic_status": "condition observed; no visibility contract inferred",
        },
        {
            "id": "current_reference_resolution",
            "function": "0x232a80/0x22e6b0/0x8d44a0",
            "evidence_id": loaded["message_instance_8d44a0"]["evidence_id"],
            "mechanical_condition": "land/naval select a short ID from DAT_14233fe58+0x1e60/+0x1e68 and resolve through DAT_14233d8b0+0x118; 8d44a0 can fill param_1[9] from param_4 or param_7 top-byte/short-ID data and a country-table +0x14b8 entry.",
            "semantic_status": "reference/table resolution observed; player/root identity is unproven",
        },
    ]

    literal_keys = {
        name: find_literal_keys(source)
        for name, source in loaded.items()
        if name in {"land_formatter_232a80", "naval_formatter_22e6b0"}
    }

    result: dict[str, Any] = {
        "schema": "information-battle-capture-gate-survey-001",
        "status": "observed_static_mechanical_only",
        "read_only": True,
        "scope": {
            "fixed_build": FIXED_BUILD,
            "fixed_executable_sha256": FIXED_EXE_SHA256,
            "chain": ["0x23a020", "0x232a80", "0x22e6b0", "0x8d44a0", "0x244630", "0x8c05f0"],
            "purpose": "record bounded call/branch contexts before and through result-message formatting/consumption",
            "out_of_scope": ["new REA", "game access", "visibility decision", "ABI or hook safety", "runtime lifetime", "player/root semantic proof"],
        },
        "limits": {
            "full_json_max_bytes": MAX_FULL_JSON_BYTES,
            "selected_report_max_bytes": MAX_SELECTED_JSON_BYTES,
            "max_context_lines": MAX_CONTEXT_LINES,
            "max_output_bytes": MAX_OUTPUT_BYTES,
            "large_selected_sources_loaded": False,
        },
        "sources": [source_descriptor(source) for source in loaded.values()],
        "contexts": contexts,
        "mechanical_call_chain": chain,
        "mechanical_gate_observations": observations,
        "formatter_literal_keys_observed": literal_keys,
        "unresolved_questions": [
            {
                "id": "visibility_suppression_mapping",
                "question": "Which concrete predicate or object field distinguishes allied, enemy, and nonparticipant recipients before or inside the formatter/consumer gates?",
                "evidence_boundary": "The selected contexts expose side-vector counts, byte flags, globals, and opaque calls, but no reliable semantic label for those predicates.",
            },
            {
                "id": "player_root_resolution",
                "question": "Which runtime object, if any, is the player/root reference used for message visibility?",
                "evidence_boundary": "Current-country/table lookup and 8d44a0 fallback reference resolution are visible; neither is labeled player/root.",
            },
            {
                "id": "formatter_input_ownership",
                "question": "Do the pointers copied by 8d44a0 remain valid for the consumer and any later UI/log callbacks?",
                "evidence_boundary": "This survey records static call order only and does not prove lifetime, reentrancy, or ABI safety.",
            },
        ],
        "evidence_boundary": {
            "source_kind": "saved REA static function evidence and bounded selected values",
            "runtime_effects_observed": False,
            "visibility_contract_proven": False,
            "player_or_root_binding_proven": False,
            "abi_or_hook_safety_proven": False,
            "notes": "OUR/ENEMY and result strings are formatter literals; their presence is not treated as a proof of recipient classification.",
        },
    }

    encoded = json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8")
    if len(encoded) > MAX_OUTPUT_BYTES:
        raise ValueError(f"survey output exceeds bounded output budget: {len(encoded)}")
    STAGE.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_bytes(encoded + b"\n")
    print(json.dumps({"path": rel(OUTPUT), "bytes": len(encoded) + 1, "sha256": hashlib.sha256(encoded + b"\n").hexdigest(), "sources": len(loaded), "contexts": len(contexts)}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"survey failed closed: {exc}", file=sys.stderr)
        raise SystemExit(1)
