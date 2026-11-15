"""Correct the type-8 professionalism path with retained REA evidence.

``professionalism-binding-004`` followed the small object-cleanup path after
``fbe450`` and correctly found no arithmetic there, but it classified the
vector helpers as generic record machinery.  The retained Ghidra evidence
identifies them as the C++ constructor/destructor iterator pair and shows the
actual business call to ``0x14b33a0``.  This correction preserves 004 and
does not issue a new REA query, game call, RPM read, or production change.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / "work/runtime/information-military-effective-20261027-001"
PRIOR_PATH = STAGE / "professionalism-binding-004.json"
EVIDENCE_PATH = STAGE / "rea-professionalism-widget-fbe450-001/evidence.json"
OUTPUT = STAGE / "professionalism-binding-005.json"

EXPECTED_PRIOR_SHA256 = (
    "043e5c27b6a4a214f6d85128ca542e07a9a4e30a980205b190e9ce9dd6384f4c"
)
EXPECTED_EVIDENCE_SHA256 = (
    "963e4b957503d91418d97a4d592a8292de5e022c797fda96c352b87cf3146428"
)
EXPECTED_EXE_SHA256 = (
    "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
)
EXPECTED_EVIDENCE_ID = "ev_003912965cf254703c5f3b56fcdbc6d123b14b07b6161945959ec4303f701e6a"


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _load_pinned(path: Path, expected_sha256: str) -> dict[str, Any]:
    actual = _sha256_file(path)
    if actual != expected_sha256:
        raise RuntimeError(f"input_pin_mismatch:{path}:{actual}")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError(f"report_not_object:{path}")
    return value


def _find_callee(callees: list[dict[str, Any]], address: str) -> dict[str, Any]:
    for item in callees:
        if item.get("address") == address:
            return item
    raise RuntimeError(f"rea_callee_missing:{address}")


def build_report() -> dict[str, Any]:
    prior = _load_pinned(PRIOR_PATH, EXPECTED_PRIOR_SHA256)
    evidence = _load_pinned(EVIDENCE_PATH, EXPECTED_EVIDENCE_SHA256)
    if evidence.get("evidence_id") != EXPECTED_EVIDENCE_ID:
        raise RuntimeError("rea_evidence_id_changed")
    subject = evidence.get("subject", {})
    if subject.get("digest", {}).get("sha256") != EXPECTED_EXE_SHA256:
        raise RuntimeError("rea_subject_binary_mismatch")
    normalized = evidence.get("normalized_result", {})
    procedure = normalized.get("procedure", {})
    if procedure.get("address") != "0x140fbe450":
        raise RuntimeError("rea_subject_function_changed")
    pseudocode = normalized.get("pseudocode", "")
    required_fragments = (
        "_eh_vector_constructor_iterator_",
        "FUN_1414b33a0(param_1,\"ARMY_PROFESSIONALISM_VALUE\",local_78,1)",
        "_eh_vector_destructor_iterator_",
        "local_50 = 8",
        "local_20 = *param_4",
    )
    for fragment in required_fragments:
        if fragment not in pseudocode:
            raise RuntimeError(f"rea_pseudocode_fragment_missing:{fragment}")
    callees = normalized.get("callees", [])
    business = _find_callee(callees, "0x1414b33a0")
    constructor = _find_callee(callees, "0x141a33274")
    destructor = _find_callee(callees, "0x141a332e4")
    if constructor.get("name") != "`eh_vector_constructor_iterator'":
        raise RuntimeError("constructor_classification_changed")
    if destructor.get("name") != "`eh_vector_destructor_iterator'":
        raise RuntimeError("destructor_classification_changed")

    prior_frame = prior.get("fbe450_to_ui_chain", {}).get("frame", {})
    if prior_frame.get("type_tag_value") != 8:
        raise RuntimeError("prior_frame_tag_changed")
    if prior_frame.get("raw_value_offset") != "0x58":
        raise RuntimeError("prior_frame_raw_offset_changed")

    return {
        "schema": "information_military_professionalism_type8_business_call_correction.v1",
        "status": "partial",
        "source_kind": "REA_retained_Ghidra_plus_prior_bounded_PE_static",
        "scope": "N03.army_professionalism.type8_business_callee_boundary",
        "binary": {
            "path": subject.get("name"),
            "size": prior.get("binary", {}).get("size"),
            "sha256": EXPECTED_EXE_SHA256,
            "image_base": prior.get("binary", {}).get("image_base"),
            "version_pin": "EU4 1.37.4",
        },
        "method": {
            "game_or_rpm": False,
            "rea_query_issued_this_run": False,
            "rea_evidence_reused": True,
            "native_calls": False,
            "new_pe_decode_bytes": 0,
            "scope_note": (
                "This is a correction based on the retained read-only Ghidra evidence for fbe450. "
                "No new decompilation, runtime read, game call, or production import was performed."
            ),
        },
        "source_pins": {
            "prior_static_correction_004": {
                "path": PRIOR_PATH.relative_to(ROOT).as_posix(),
                "sha256": EXPECTED_PRIOR_SHA256,
                "bytes": PRIOR_PATH.stat().st_size,
            },
            "rea_professionalism_widget_fbe450": {
                "path": EVIDENCE_PATH.relative_to(ROOT).as_posix(),
                "sha256": EXPECTED_EVIDENCE_SHA256,
                "bytes": EVIDENCE_PATH.stat().st_size,
                "evidence_id": EXPECTED_EVIDENCE_ID,
                "provider": evidence.get("provider"),
                "analysis_profile_sha256": evidence.get("analysis_profile", {}).get("digest"),
            },
        },
        "correction_of_004": {
            "preserved": True,
            "old_negative_path": {
                "0x1a33274": "bounded helper previously treated as record-builder prefix",
                "0x1a332e4": "bounded helper previously treated as record-builder tail",
                "0x8ee90": "bounded callback previously treated as string/object cleanup callback",
            },
            "correction": (
                "REA names 0x1a33274 as eh_vector_constructor_iterator and 0x1a332e4 as "
                "eh_vector_destructor_iterator; 0x8ee90 is the destructor callback path. "
                "The absence of numeric arithmetic in that path is therefore cleanup evidence, "
                "not evidence that the business consumer is absent."
            ),
        },
        "fbe450_rea_contract": {
            "procedure": {
                "address": procedure.get("address"),
                "name": procedure.get("name"),
                "body": procedure.get("body"),
            },
            "caller": {
                "address": "0x140fb4ba0",
                "rva": "0xfb4ba0",
                "callsite_rva": "0xfb9294",
                "source": "retained REA incoming reference plus prior bounded PE tail",
            },
            "pseudocode_contract": {
                "constructor": {
                    "rva": "0x1a33274",
                    "name": constructor.get("name"),
                    "arguments": ["frame", "0x68", "1", "0x8f670", "0x8ee90"],
                },
                "frame_key": {
                    "literal": "VALUE",
                    "frame_base": "RSP+0x40",
                },
                "type_tag": {
                    "frame_offset": "0x28",
                    "stack_location": "RSP+0x68",
                    "value": 8,
                },
                "raw_value": {
                    "frame_offset": "0x58",
                    "stack_location": "RSP+0x98",
                    "pseudocode": "local_20 = *param_4",
                    "prior_static_source": "country+0x50 QWORD copied through R9/RBX",
                },
                "business_call": {
                    "rva": "0x14b33a0",
                    "static_va": "0x1414b33a0",
                    "callsite_rva": "0xfbe4d0",
                    "arguments": [
                        {"ordinal": 1, "register": "RCX", "expression": "param_1"},
                        {"ordinal": 2, "register": "RDX", "expression": "ARMY_PROFESSIONALISM_VALUE"},
                        {"ordinal": 3, "register": "R8", "expression": "frame/local_78"},
                        {"ordinal": 4, "register": "R9D", "expression": "1"},
                    ],
                    "callee_body": business.get("body"),
                    "role": "actual business localization/argument consumer candidate; scale still unresolved",
                },
                "destructor": {
                    "rva": "0x1a332e4",
                    "name": destructor.get("name"),
                    "arguments": ["frame", "0x68", "1", "0x8ee90"],
                },
            },
        },
        "numeric_consumer": {
            "status": "pending_cached_query",
            "minimum_next_target": {
                "rva": "0x14b33a0",
                "static_va": "0x1414b33a0",
                "range_from_rea": ["0x1414b33a0", "0x1414b35b9"],
                "reason": "The business call receives the frame with tag=8 and raw QWORD at +0x58; inspect this callee's type8 branch next.",
            },
            "not_numeric_evidence": [
                "0x1a332e4 and 0x8ee90 are destructor machinery, not the type8 business consumer.",
                "The separate 0x14bc950 fixed-point contract remains unconnected until 0x14b33a0 or its downstream formatter proves the ABI.",
                "The independent raw QWORD sample is not used to infer scale."
            ],
        },
        "unit_and_scale": {
            "status": "unresolved_pending_0x14b33a0",
            "known": [
                "The locale key is ARMY_PROFESSIONALISM_VALUE.",
                "The business argument has type/tag candidate 8 and raw source at frame+0x58.",
            ],
            "unknown": [
                "Whether type 8 means ratio, already-percent, fixed-point, or another numeric representation.",
                "Any division/multiplication and the exact formatter output convention."
            ],
            "do_not_infer": [
                "Do not apply signed_i32/1000 from the trade formatter without the 0x14b33a0 ABI connection.",
                "Do not apply the unrelated 0x954c0 raw*1000 helper."
            ],
        },
        "conclusion": {
            "closed": [
                "The only business call in fbe450 is 0x14b33a0(param_1, ARMY_PROFESSIONALISM_VALUE, frame, 1).",
                "The frame's +0x28=8 and +0x58 raw QWORD are arguments to that business callee.",
                "The vector constructor/destructor path is cleanup and should not be used as the numeric-consumer negative conclusion."
            ],
            "pending": [
                "Inspect 0x14b33a0 for the type-8 branch and downstream numeric formatter.",
                "Keep professionalism planned/partial until that callee establishes the raw scale."
            ],
            "publication": "Wait for the retained/read-only 0x14b33a0 query before extending the evidence chain."
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=OUTPUT)
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()
    report = build_report()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    if args.output.exists() and not args.force:
        raise FileExistsError(f"refusing to overwrite existing report: {args.output}")
    args.output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(
        json.dumps(
            {
                "output": str(args.output),
                "status": report["status"],
                "rea_query_issued_this_run": report["method"]["rea_query_issued_this_run"],
                "business_callee": report["fbe450_rea_contract"]["pseudocode_contract"]["business_call"]["rva"],
                "numeric_consumer": report["numeric_consumer"]["status"],
                "unit_scale": report["unit_and_scale"]["status"],
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
