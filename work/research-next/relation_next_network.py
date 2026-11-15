"""Create the bounded batch-56 guarantee/military-access network source report.

This is an offline report builder.  It only pins already archived source and
REA evidence; it never opens the game, invokes REA/RPM, or changes production.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Iterable


ROOT = Path(__file__).resolve().parents[2]
STAGE = ROOT / "work" / "runtime" / "information-relation-network-remaining-20261027-001"
OUTPUT = STAGE / "source-002.json"
SOURCE_001 = STAGE / "source-001.json"
TARGET_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
IMAGE_BASE = 0x140000000


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while True:
            chunk = stream.read(1024 * 1024)
            if not chunk:
                return digest.hexdigest()
            digest.update(chunk)


def require_file(relative: str) -> Path:
    path = ROOT / relative
    if not path.is_file():
        raise FileNotFoundError(relative)
    return path


def bounded_window(relative: str, start: int, end: int, markers: Iterable[str]) -> dict:
    """Pin a small inclusive source window while hashing the whole source stream."""

    path = require_file(relative)
    selected: list[str] = []
    bytes_examined = 0
    with path.open("r", encoding="utf-8", errors="replace") as stream:
        for line_number, line in enumerate(stream, 1):
            if start <= line_number <= end:
                selected.append(line)
                bytes_examined += len(line.encode("utf-8"))
            if line_number > end:
                break
    text = "".join(selected)
    marker_presence = {marker: marker in text for marker in markers}
    missing = [marker for marker, present in marker_presence.items() if not present]
    if missing:
        raise RuntimeError(f"source markers missing in {relative}: {missing}")
    return {
        "line_range_inclusive": [start, end],
        "bytes_examined": bytes_examined,
        "markers_present": marker_presence,
    }


def file_pin(relative: str, role: str, windows: list[dict] | None = None) -> dict:
    path = require_file(relative)
    result = {
        "path": relative,
        "sha256": sha256_file(path),
        "bytes": path.stat().st_size,
        "role": role,
    }
    if windows:
        result["bounded_windows"] = windows
    return result


def current_pe_window(pe, begin: int, end: int, label: str) -> dict:
    """Read one small current-EXE window and retain only its bounded digest."""

    if not (0 <= begin < end) or end - begin > 0x4000:
        raise ValueError(f"invalid current PE window {begin:#x}:{end:#x}")
    if not pe.executable(begin) or not pe.executable(end - 1):
        raise ValueError(f"current PE window is not executable {begin:#x}:{end:#x}")
    raw = pe.bytes_at(begin, end - begin)
    if len(raw) != end - begin:
        raise ValueError(f"short current PE window {begin:#x}:{end:#x}")
    return {
        "label": label,
        "rva_start": hex(begin),
        "rva_end_exclusive": hex(end),
        "va_start": hex(pe.base + begin),
        "va_end_exclusive": hex(pe.base + end),
        "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "raw_hex": raw.hex(),
        "provenance": "ordinary bounded current-PE read; not REA",
    }


def subject_sha(relative: str) -> str | None:
    """Return an archived evidence target SHA without treating report data as PE bytes."""

    path = require_file(relative)
    with path.open("r", encoding="utf-8", errors="replace") as stream:
        data = json.load(stream)
    subject = data.get("subject") if isinstance(data, dict) else None
    if isinstance(subject, dict):
        digest = subject.get("digest")
        if isinstance(digest, dict) and isinstance(digest.get("sha256"), str):
            return digest["sha256"]
    return None


def target_binary_sha(relative: str) -> str | None:
    path = require_file(relative)
    with path.open("r", encoding="utf-8", errors="replace") as stream:
        data = json.load(stream)
    if isinstance(data, dict):
        target = data.get("target_binary")
        if isinstance(target, dict) and isinstance(target.get("sha256"), str):
            return target["sha256"]
    return None


def build_source_002() -> dict:
    """Build the corrected guarantee-focused report without touching source-001."""

    if not SOURCE_001.is_file():
        raise FileNotFoundError("source-001.json must remain available for the audit")

    # The ordinary reader is deliberately imported only for this two-window,
    # current-binary check.  No process, game, RPM, or REA session is opened.
    import sys

    sys.path.insert(0, str(ROOT))
    from work.discover_diplomacy import PE
    from work.local_config import game_exe

    pe = PE(game_exe())
    current_sha = hashlib.sha256(pe.data).hexdigest()
    if current_sha != TARGET_SHA256 or pe.base != IMAGE_BASE:
        raise ValueError(f"unsupported current PE: sha={current_sha} base={pe.base:#x}")
    current_windows = [
        current_pe_window(pe, 0xA69E00, 0xA69E5A, "guarantee_current_relation_helper"),
    ]
    pdata = pe.function(0x521B00)
    # The third tuple member is build-specific unwind RVA; only the start and
    # end boundary are part of this report.
    if not pdata or pdata[0:2] != (0x521B00, 0x521F24):
        raise ValueError(f"unexpected current legality boundary: {pdata}")
    current_windows.append(current_pe_window(pe, 0x521B00, 0x521F24, "guarantee_legality_function"))

    rea_a69e00 = "work/runtime/guarantee-support-identification-20261015-001/guarantee-integration-20261015-001/rea-a69e00/evidence.json"
    rea_521b00 = "work/runtime/guarantee-support-identification-20261015-001/rea-521b00/evidence.json"
    rea_a68e60 = "work/runtime/military-access-integration-20261015-001/rea-a68e60/evidence.json"
    rea_525530 = "work/runtime/military-access-identification-20261015-001/rea-525530/evidence.json"
    for evidence_path in (rea_a69e00, rea_521b00, rea_a68e60, rea_525530):
        if subject_sha(evidence_path) != TARGET_SHA256:
            raise ValueError(f"REA subject SHA is not current target: {evidence_path}")

    query_window = bounded_window(
        "work/native/alliance-query.inc",
        277,
        415,
        (
            "unilateral_guarantee",
            "factory_query_relation_active",
            "military_query_active",
            "country+0x1510",
            "base+0xa68e60",
        ),
    )
    guarantee_report_window = bounded_window(
        "work/runtime/guarantee-support-identification-20261015-001/guarantee-integration-20261015-001/report.md",
        117,
        145,
        ("FUN_140521b00", "owner+0x1a0", "+0x1ac", "FUN_140a69e00", "entry+0x8"),
    )
    old_workflow_window = bounded_window(
        "docs/rea-workflow-1375.md",
        51,
        57,
        ("9ad3efe1af169f40ee577f9dae5debbc87af6fb8b5450fb345ebf110dc4d771a", "RVA", "REA Evidence"),
    )
    readme_history_window = bounded_window(
        "README(agent).md",
        441,
        452,
        ("1.37.5", "1.37.4", "历史"),
    )

    source_001_data = json.loads(SOURCE_001.read_text(encoding="utf-8"))
    source_001_target = source_001_data.get("target_binary", {}).get("sha256")
    if source_001_target != TARGET_SHA256:
        raise ValueError(f"source-001 target changed unexpectedly: {source_001_target}")

    report = {
        "schema": "information_relation_network_remaining_source.v2",
        "report_id": "relation-network-remaining-source-002",
        "stage": "information-relation-network-remaining-20261027-001",
        "status": "guarantee_current_predicate_closed_with_sha_audit",
        "supersedes": {
            "path": "work/runtime/information-relation-network-remaining-20261027-001/source-001.json",
            "sha256": sha256_file(SOURCE_001),
            "scope": "source-001 remains unchanged; this report corrects its guarantee gap and makes binary-version evidence explicit",
        },
        "review_scope": {
            "kind": "offline_sha_audit_plus_bounded_current_pe_guarantee_review",
            "new_game_query": False,
            "new_rpm": False,
            "new_rea": False,
            "new_native_call": False,
            "pytest_run": False,
            "production_changes": False,
            "ordinary_current_pe_windows": 2,
            "ordinary_current_pe_bytes": 1150,
            "full_binary_disassembly": False,
            "current_pe_windows": "0xA69E00..0xA69E5A and pdata-bounded 0x521B00..0x521F24 only",
        },
        "target_binary": {
            "version": "1.37.4",
            "sha256": TARGET_SHA256,
            "image_base": "0x140000000",
            "rva_va_rule": "VA = 0x140000000 + RVA; RVA and VA are retained separately",
        },
        "sha_audit": {
            "current_target": TARGET_SHA256,
            "historical_workflow_sha": {
                "sha256": "9ad3efe1af169f40ee577f9dae5debbc87af6fb8b5450fb345ebf110dc4d771a",
                "label": "historical 1.37.5 workflow/document rule",
                "path": "docs/rea-workflow-1375.md",
                "line_range_inclusive": [51, 57],
                "interpretation": "not a target identity for the current b23fa0...1.37.4 binary and not used to downgrade matching current evidence",
            },
            "source_001_target": {
                "sha256": source_001_target,
                "classification": "matches_current_target",
                "note": "source-001 itself records current b23fa0...; this report separately audits every referenced REA subject before reusing an address",
            },
            "rea_subjects": [
                {
                    "path": rea_a69e00,
                    "evidence_id": "ev_b602b9bcefcd85043989b7e8da1e08e8e79f2c446c710a6f0510e0b18b63ee48",
                    "subject_sha256": subject_sha(rea_a69e00),
                    "classification": "current_match_reusable",
                },
                {
                    "path": rea_521b00,
                    "evidence_id": "ev_afc1824d3e7a825710b504941ae5053c5a591218f9053c54b14c6762d597ef6c",
                    "subject_sha256": subject_sha(rea_521b00),
                    "classification": "current_match_legality_context",
                },
                {
                    "path": rea_a68e60,
                    "evidence_id": "ev_0dd1460e4ae8b6b19678e5a7ef9f40aef6e2cd68ad253487bf5157f8f871e7a2",
                    "subject_sha256": subject_sha(rea_a68e60),
                    "classification": "current_match_reusable_by_root_military_reader",
                },
                {
                    "path": rea_525530,
                    "evidence_id": "ev_9a7be37875ce61993957e90d8ab94a749ee81fd30a0abec9e649d721e57d9146",
                    "subject_sha256": subject_sha(rea_525530),
                    "classification": "current_match_broader_validity_context",
                },
            ],
            "archived_pair_reports": [
                {
                    "path": "work/runtime/diplomacy-query-20261015-r30-guarantee-a/guarantee-queries-7cacb0e7cd4349218a6e6815a0dd8292/report.json",
                    "file_sha256": sha256_file(require_file("work/runtime/diplomacy-query-20261015-r30-guarantee-a/guarantee-queries-7cacb0e7cd4349218a6e6815a0dd8292/report.json")),
                    "embedded_exe_sha256": None,
                    "classification": "historical_runtime_pair_result; no binary identity claim",
                },
                {
                    "path": "work/runtime/diplomacy-query-20261015-r32-military-access-a/military-access-queries-7a97bc04b2ee4d5f89fc5cbac7ef3fab/report.json",
                    "file_sha256": sha256_file(require_file("work/runtime/diplomacy-query-20261015-r32-military-access-a/military-access-queries-7a97bc04b2ee4d5f89fc5cbac7ef3fab/report.json")),
                    "embedded_exe_sha256": None,
                    "classification": "historical_runtime_pair_result; no binary identity claim",
                },
            ],
            "reuse_rule": "an address is reusable for current 1.37.4 only when its evidence subject or ordinary current PE bytes match b23fa0e1...; historical 9ad3... text and runtime report hashes are never substituted for an EXE SHA",
        },
        "guarantee_current_predicate": {
            "status": "closed_for_selected_row_boolean",
            "rva": "0xa69e00",
            "va": "0x140a69e00",
            "ordinary_current_range_rva": ["0xa69e00", "0xa69e5a"],
            "ordinary_current_range_va": ["0x140a69e00", "0x140a69e5a"],
            "ordinary_current_bytes": 90,
            "ordinary_current_sha256": current_windows[0]["sha256"],
            "ordinary_current_provenance": "current b23fa0... PE, exact 90-byte window; no game/process access",
            "rea_reported_range_rva": ["0xa69e00", "0xa69e59"],
            "rea_reported_range_va": ["0x140a69e00", "0x140a69e59"],
            "rea_reported_total_bytes": 90,
            "rea_range_note": "the archived REA body reports end 0x...e59 with total_bytes 90; the ordinary current-PE byte window uses the exclusive end 0x...e5a to include the 0xc3 at 0x...e59",
            "evidence_id": "ev_b602b9bcefcd85043989b7e8da1e08e8e79f2c446c710a6f0510e0b18b63ee48",
            "evidence_file": {
                "path": rea_a69e00,
                "sha256": sha256_file(require_file(rea_a69e00)),
                "subject_sha256": subject_sha(rea_a69e00),
            },
            "abi": "RCX=relation row; [relation_row+0x0] is owner; [relation_row+0x10] carries recipient fullref",
            "reads": {
                "owner_vector_begin": "owner+0x1a0",
                "owner_vector_count": "owner+0x1ac signed i32",
                "element_stride": 16,
                "element_key": "entry+0 DWORD equals sign_extend_i16((relation_row+0x10 fullref >> 32) & 0xffff)",
                "element_record": "entry+0x8 pointer must be non-null",
                "record_identity": "*(entry+0x8)+0x18, shifted >>32, must have the same target slot",
            },
            "return": "false on empty/exhausted vector, null record, or record fullref mismatch; true only for matching key, non-null record, and matching record identity",
            "direction": "actor country owns the +0x1510 row; row+0x10 is the selected target; preserve actor/recipient labels until public role mapping is separately proven",
            "country_network_use": "the same row predicate can be applied during a bounded country scan after country/fullref/row identity guards; this closes the family boolean, not runtime completeness, expiry, or generic role names",
        },
        "guarantee_legality_context": {
            "rva": "0x521b00",
            "va": "0x140521b00",
            "current_pdata_range_rva": ["0x521b00", "0x521f24"],
            "current_pdata_range_va": ["0x140521b00", "0x140521f24"],
            "current_pdata_bytes": 1060,
            "current_pedata_sha256": current_windows[1]["sha256"],
            "rea_evidence_id": "ev_afc1824d3e7a825710b504941ae5053c5a591218f9053c54b14c6762d597ef6c",
            "mode_zero": "reads the same owner+0x1a0/+0x1ac vector and accepts entry key plus non-null entry+0x8; failure may write HASNOTGUARANT",
            "mode_one": "contains initiation legality checks (subject, treaty, war and rival constraints); do not use those branches as current state",
            "role": "legality callback corroborating the owner offsets, not the pure country-network predicate; use 0xA69E00 for current membership",
        },
        "country_1510_network_contract": {
            "database_global_rva": "0x233d8b0",
            "database_table_offset": "0x118",
            "database_count_offset": "0x124",
            "country_fullref_offset": "0x20",
            "relation_table_offset": "0x1510",
            "row_stride": 72,
            "row_owner_offset": "0x0",
            "row_recipient_fullref_offset": "0x10",
            "owner_equals_actor": False,
            "guarantee_family_read": "resolve row owner, then +0x1a0/+0x1ac and validate every 0x10-byte entry before calling or reproducing A69E00",
            "bounds": "country and vector counts must be 0..4096; unread, null, invalid, or budget-truncated rows remain unknown, never inactive",
            "runtime_gap": "no country-wide two-pass runtime capture was performed in this source task",
        },
        "direction_and_expiry": {
            "guarantee": {
                "native_storage_direction": "actor-owned row to selected target",
                "public_grantor": "unknown until role projection is separately proven; preserve actor/recipient",
            },
            "expires_at": {"status": "unknown", "reason": "A69E00 and 521B00 read no relation expiry field"},
            "not_sources": ["proclaim/revoke action id alone", "visibility", "legality initiation branches", "pending/acceptance objects"],
        },
        "source_pins": [
            file_pin("work/runtime/information-relation-network-remaining-20261027-001/source-001.json", "unchanged prior report audited by this report"),
            file_pin("work/native/alliance-query.inc", "current source family descriptor and row contract", [query_window]),
            file_pin("work/runtime/guarantee-support-identification-20261015-001/guarantee-integration-20261015-001/report.md", "existing guarantee owner/predicate interpretation", [guarantee_report_window]),
            file_pin("work/runtime/guarantee-support-identification-20261015-001/guarantee-integration-20261015-001/rea-a69e00/evidence.json", "current-target REA guarantee predicate"),
            file_pin("work/runtime/guarantee-support-identification-20261015-001/rea-521b00/evidence.json", "current-target REA legality context"),
            file_pin("work/runtime/military-access-integration-20261015-001/rea-a68e60/evidence.json", "current-target REA military predicate audited from source-001"),
            file_pin("work/runtime/military-access-identification-20261015-001/rea-525530/evidence.json", "current-target REA military validity context audited from source-001"),
            file_pin("docs/rea-workflow-1375.md", "historical 1.37.5 SHA rule; not current target", [old_workflow_window]),
            file_pin("README(agent).md", "historical 1.37.5/1.37.4 separation", [readme_history_window]),
            file_pin("work/runtime/information-relation-current-20261027-001/relation-current-source-001.json", "prior current-target relation contract"),
            file_pin("work/runtime/information-relation-current-20261027-001/relation-current-source-002.json", "prior bounded relation leaves and target SHA"),
            file_pin("work/runtime/information-relations-20261027-001/relation-source-001.json", "archived selected-pair state examples"),
        ],
        "conclusion": {
            "sha": "The four audited REA evidence files carry subject SHA b23fa0e1...d77 and are current-target evidence; the separate 9ad3... text in the 1.37.5 workflow is historical and is not substituted.",
            "guarantee": "Current 1.37.4 pure row membership is closed at A69E00. It reads owner+1A0/+1AC and verifies both target key and pointed record+18 fullref.",
            "network": "A bounded country-network reader can reuse country+1510 row identity plus A69E00 semantics. Runtime full-country completeness, directed role names and expiry remain open.",
            "root_coordination": "Current guarantee helper to coordinate with root: RVA 0xA69E00 / VA 0x140A69E00; legality context RVA 0x521B00 / VA 0x140521B00.",
        },
    }
    return report




def main() -> int:
    """Write the corrected source-002 report without overwriting source-001."""

    if OUTPUT.exists():
        raise FileExistsError(f"refusing to overwrite {OUTPUT}")
    STAGE.mkdir(parents=True, exist_ok=True)
    report = build_source_002()
    OUTPUT.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {OUTPUT}")
    print(f"sha256 {sha256_file(OUTPUT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
