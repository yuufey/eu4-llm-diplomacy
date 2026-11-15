#!/usr/bin/env python3
"""Build a bounded, static survey of battle-message visibility paths.

This is an evidence ledger only.  It deliberately does not load the game,
invoke REA, read process memory, or disassemble a binary.  The selected
evidence files are small JSON extracts; large provider reports are represented
by their already recorded provenance pins and are never read by this script.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping, Optional


FIXED_VERSION = "1.37.4"
FIXED_EXE_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
FIXED_EXE_SIZE = 38_463_016
STATIC_IMAGE_BASE = "0x140000000"
MAX_SOURCE_BYTES = 16 * 1024 * 1024
CHUNK_BYTES = 1024 * 1024


# These are selected excerpts or compact indexes.  The raw provider reports
# behind some of them are larger than the bounded reading budget and are kept
# as provenance-only declarations below.
EXPECTED_SMALL_FILES: Mapping[str, str] = {
    "work/runtime/information-battle-message-20261025-001/research-index-001.json":
        "62e57ecfeaa4a5414165df3dbf6162298aca646cfab57da24f125ae16cab8e83",
    "work/runtime/information-battle-fragments-20261025-001/research-index-001.json":
        "93d3fbef629a0d5784478d2637c50e76902163f74d0e107dc2b98f8a180b59a1",
    "work/runtime/information-battle-popup-20261025-001/research-index-002.json":
        "130fc2882d5da9c1bd50a99c996e6a59cadd347b8ec7b06b8c7f096e46c8fe16",
    "work/runtime/information-battle-capture-contract-20261025-001/research-index-002.json":
        "5fbe175bcec6ea7e94ae1fbf023ff83969490f34f9a32e86530483d43f17a1aa",
    "work/runtime/information-battle-fragments-20261025-001/capture-gate-survey-001.json":
        "9700143bb609a0098f5549b389c3f47b7d3be460c91a35a982f76d70b3f0c504",
    "work/runtime/information-battle-fragments-20261025-001/capture-scope-text-ledger-001.json":
        "b8c26963a8c953c56611910a664d8bda1297a3e157d723cb87c9b7229a99b4e2",
    "work/runtime/information-battle-popup-20261025-001/popup-field-ledger-001.json":
        "84d18633f9612129579d9b35a9a56faf4ecdcbbb341540fa3c53cff04b6ed007",
    "work/runtime/information-battle-popup-20261025-001/popup-template-widget-context-002.json":
        "ccb4cbfe75a4e6e357631c08e4469f38bba8b7301a78085c00de2f6dbef31485",
    "work/runtime/information-battle-capture-contract-20261025-001/formatted-text-survey-002.json":
        "ec89f8dd757d96a51f5ba7ba7d46687409657d33c4a27cea43addd28449e7586",
    "work/runtime/information-battle-fragments-20261025-001/rea-message-setting-001/selected-evidence-001.json":
        "ae05c0b87d8c4a56acf6a386ede08af6bf85777839d80212f52dad8cdada20c5",
    "work/runtime/information-battle-fragments-20261025-001/rea-message-membership-001/selected-evidence-001.json":
        "c88c14912c80251cc3e55dcb4752c5ed03ccd5dce7d0d4af948e3e626fcd68e6",
    "work/runtime/information-battle-fragments-20261025-001/rea-localized-format-001/selected-evidence-001.json":
        "48dfd0dec340cf031b64fe5d7f08ad6958179af736093cd91e93ea56d41a7bdc",
    "work/runtime/information-battle-popup-20261025-001/rea-popup-message-copy-001/selected-evidence-001.json":
        "ea2d284a4f3f7edab0d663bf823406aa7234f3bca53dd5fdc7ecc9b8afc797cb",
    "work/runtime/information-battle-popup-20261025-001/rea-template-node-copy-001/selected-evidence-001.json":
        "b265547e02ad0d9a9f35991074c6b7a03d972376f36ae1bd735bcb9000bc68b0",
    "work/runtime/information-battle-popup-20261025-001/rea-land-popup-fields-001/selected-evidence-001.json":
        "7e2e3407706bcd49ac526fcf15f895370ae366e8d852f6c7f15adf2208fecb23",
    "work/runtime/information-battle-popup-20261025-001/rea-naval-popup-fields-001/selected-evidence-001.json":
        "19dc34efb678afb575115523dbcd4f5ab5a4f3872748af39fd473d0100dd97b3",
    "work/runtime/information-battle-layout-20261025-001/rea-land-result-message-001/selected-evidence-001.json":
        "82455e0f1f9fe27bc3dba2e3bea176743ce21d89b076f5e789a8b7f5cef83242",
    "work/runtime/information-battles-20261025-001/rea-message-dispatch-001/selected-evidence-001.json":
        "ca5bf66fa2682e6e066d8ee75d6b5e56a325cbd67654c25b9a6d51509a576d6b",
}

DOC_FILES = (
    "docs/逐场战报消息与传输.md",
    "docs/逐场战报分片与采集范围.md",
    "docs/逐场战报窗口与本地日志.md",
    "docs/逐场战报采集与交付边界.md",
)


LARGE_PROVENANCE = (
    {
        "path": "work/runtime/information-battle-layout-20261025-001/rea-land-result-message-001/evidence.json",
        "size": 10_281_549,
        "sha256": "272c19c062bdb9ce628689e0bbe2fd93d2e2a54a5ff8b4af6d252ebb182a7921",
        "read_mode": "not_read_large_provider_report; selected_excerpt_used",
    },
    {
        "path": "work/runtime/information-battles-20261025-001/rea-message-dispatch-001/evidence.json",
        "size": 10_577_723,
        "sha256": "017a28a7d4ded0ff1bc4668da53d7fdb72750045fa229a39c40a88a4d7177734",
        "read_mode": "not_read_large_provider_report; selected_excerpt_used",
    },
    {
        "path": "work/runtime/information-battle-fragments-20261025-001/rea-localized-format-001/evidence.json",
        "size": 32_568_212,
        "sha256": "12acdf06a8a12f9e09ef31448e19594a454819668c1c4de8d6dd5134f313d966",
        "read_mode": "not_read_large_provider_report; selected_excerpt_used",
    },
    {
        "path": "work/runtime/information-battle-popup-20261025-001/rea-land-popup-fields-001/evidence.json",
        "size": 9_029_993,
        "sha256": "3ee7b0d2f2b109bfe63a5ffd13889a90b62ab851262a13e4b429c8e92ff7f3f7",
        "read_mode": "not_read_provider_report; selected_excerpt_used",
    },
    {
        "path": "work/runtime/information-battle-popup-20261025-001/rea-naval-popup-fields-001/evidence.json",
        "size": 4_784_095,
        "sha256": "27e6b071188410af8da00f79be1367d3f5b0b4f607f93d5c06763c8371cff257",
        "read_mode": "not_read_provider_report; selected_excerpt_used",
    },
)


def _sha256(path: Path) -> str:
    size = path.stat().st_size
    if size > MAX_SOURCE_BYTES:
        raise ValueError(f"source exceeds bounded file limit: {path} ({size})")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while True:
            chunk = stream.read(CHUNK_BYTES)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _pin(root: Path, relative: str, expected: Optional[str] = None) -> Dict[str, Any]:
    path = root / relative
    if not path.is_file():
        raise FileNotFoundError(relative)
    size = path.stat().st_size
    if size > MAX_SOURCE_BYTES:
        raise ValueError(f"bounded source unexpectedly too large: {relative}")
    actual = _sha256(path)
    if expected is not None and actual != expected:
        raise ValueError(f"source SHA mismatch for {relative}: {actual} != {expected}")
    return {
        "path": relative,
        "size": size,
        "sha256": actual,
        "read_mode": "streamed_bounded",
    }


def _body(start: str, end: str, size: int, *, segments: Optional[int] = None) -> Dict[str, Any]:
    value: Dict[str, Any] = {
        "start_va": start,
        "end_va_inclusive": end,
        "body_bytes": size,
    }
    if segments is not None:
        value["noncontiguous_segments"] = segments
    return value


def _findings() -> list[Dict[str, Any]]:
    return [
        {
            "id": "message_setting_only_8c1ba0",
            "path_kind": "message_definition_setting",
            "rva": "0x8c1ba0",
            "va": "0x1408c1ba0",
            "body": _body("0x1408c1ba0", "0x1408c2a0", 257),
            "evidence_id": "ev_078491e6b218b6e5505934dbb69ebb6640f0666201165b5733239466446646ff",
            "status": "settings_only_not_visibility",
            "observation": "Selects definition slots (+88/+90/+98/+A0) from message reference/settings fields; it compares selected slots, not an observer/player or country-known predicate.",
            "visibility_claim": "none",
        },
        {
            "id": "membership_tree_84c0b0",
            "path_kind": "membership_lookup_candidate",
            "rva": "0x84c0b0",
            "va": "0x14084c0b0",
            "body": _body("0x14084c0b0", "0x14084c100", 81),
            "evidence_id": "ev_3aa6d4acac0eecef99822869664565c516af7255560f739e09d14a5879b3f05d",
            "status": "candidate_unresolved",
            "observation": "Tree lookup uses signed bits 32..47 and returns node+20; no-match clears AL and the caller tests AL. The saved evidence gives no allied/enemy/fog or observer-country meaning.",
            "visibility_claim": "possible_input_to_a_range_gate_but_unproven",
        },
        {
            "id": "formatter_nonempty_gates",
            "path_kind": "formatter_input_gate",
            "rvas": ["0x232a80", "0x22e6b0"],
            "vas": ["0x140232a80", "0x14022e6b0"],
            "bodies": [
                _body("0x140232a80", "0x14023674e", 15627, segments=7),
                _body("0x14022e6b0", "0x140232a40", 17342, segments=7),
            ],
            "evidence_id": "ev_5afd555610c9df1e0d724c03a92c96db97bee25a3c8c007a0132fb362bf42c89 / ev_b2600be25bd20c48261bd979bc6a9c44ae67edeedacc1a4d4a604da7a22bad2e",
            "status": "participant_or_input_gate_unresolved",
            "observation": "Land checks a summary flag and naval checks two side-vector counts before message construction. Empty input suppresses downstream delivery, but the selected evidence does not identify this as country visibility.",
            "visibility_claim": "none_without_runtime_or_object_semantics",
        },
        {
            "id": "consumer_8c05f0",
            "path_kind": "notification_consumer_gate",
            "rva": "0x8c05f0",
            "va": "0x1408c05f0",
            "body": _body("0x1408c05f0", "0x1408c1086", 2708, segments=5),
            "evidence_id": "ev_7c83800baf700500a9000917e68dbbc53387cb49d61a9f8ba977378feb2801d1",
            "status": "message_mode_gate_not_visibility",
            "observation": "Branches on global mode/handle, param_1+48, and message fields; may clear fields or enter notification/window/log handling. No observer/player/country-known condition is established.",
            "visibility_claim": "none",
        },
        {
            "id": "message_move_delivery",
            "path_kind": "message_lifetime_boundary",
            "rvas": ["0x8d44a0", "0x244630"],
            "vas": ["0x1408d44a0", "0x140244630"],
            "bodies": [
                _body("0x1408d44a0", "0x1408d4658", 441),
                _body("0x140244630", "0x1402446ed", 190),
            ],
            "evidence_id": "ev_3d93e7a0b9c66ea6a4fc361d80868c62dc546c73c0fa1f8b963ea30c47ba0b73 / ev_3e8d5882cbd806cf067d34b97665b40eaecb95cdf25935fca5d923d1ebdadbf9",
            "status": "capture_boundary_not_visibility",
            "observation": "8D44A0 moves/copies message data and can fill a reference-derived country value; 244630 performs delivery branching and cleanup. Capturing only at 244630 can miss formatter-suppressed messages, and delayed reads cannot use the old container address.",
            "visibility_claim": "none; lifetime and suppression are unresolved",
        },
        {
            "id": "log_text_8d4660",
            "path_kind": "date_log_text",
            "rva": "0x8d4660",
            "va": "0x1408d4660",
            "body": {
                "segments": 7,
                "total_bytes": 1206,
                "first_start_va": "0x1408d4660",
                "last_end_va_inclusive": "0x1408d4b1a",
            },
            "evidence_id": "ev_a59809c0f69256c01009ad31b139ed149c94fd9fbb6a9a3e6e202d1c10a4d34f",
            "status": "log_only_not_complete_frame",
            "observation": "Uses a message key and _LOG/date text; it is not evidence of a complete battle-result frame or country visibility.",
            "visibility_claim": "none",
        },
        {
            "id": "presentation_route",
            "path_kind": "presentation_route",
            "rvas": ["0x8c1270", "0x8c1dc0"],
            "vas": ["0x1408c1270", "0x1408c1dc0"],
            "bodies": [
                _body("0x1408c1270", "0x1408c1941", 1746),
                _body("0x1408c1dc0", "0x1408c20dd", 798),
            ],
            "evidence_id": "ev_6ff807ae2f2177c75bbbacd5f0ba6dff3417221a2d086c677dbb49cc19077ae2 / ev_e1e4b9eda31a62e4c07fa1dfe03224c3a795713f4c2d80283485ade03f433cae",
            "status": "presentation_route_not_visibility",
            "observation": "Selects land/compact/naval result windows and passes the message into an internal window object. The saved evidence does not prove that the chosen presentation is the observer's full known result.",
            "visibility_claim": "none",
        },
        {
            "id": "popup_field_sources",
            "path_kind": "complete_frame_field_sources",
            "rvas": ["0x8c75d0", "0x8ca460"],
            "vas": ["0x1408c75d0", "0x1408ca460"],
            "bodies": [
                _body("0x1408c75d0", "noncontiguous", 11811, segments=28),
                _body("0x1408ca460", "noncontiguous", 6775, segments=4),
            ],
            "evidence_id": "ev_c7a8b8253d9ca7139375ba824564871a0309cb6e70d7c0bea72f53008b80ea74 / ev_9036822f562930ea96fe3af5ba6a6a7224db478e73afd13a898cba83f50c273e",
            "status": "field_sources_observed_complete_frame_unproven",
            "observation": "These paths fill many result-window controls and template keys (for example WINORLOSE, OURPRESTIGE, and side/unit fields). OUR/ENEMY labels do not establish the current observer or an enemy relationship; the land and naval paths use similar UI vocabulary.",
            "visibility_claim": "not_proven",
        },
        {
            "id": "localization_14b33a0",
            "path_kind": "localized_template_format",
            "rva": "0x14b33a0",
            "va": "0x1414b33a0",
            "body": _body("0x1414b33a0", "0x1414b35b9", 538),
            "evidence_id": "ev_48919e3903f355e10997c47979823883c122867db887ce13bc26cb04cf244167",
            "status": "text_format_only_not_visibility",
            "observation": "Hash lookup and placeholder expansion can produce localized text or a fallback key, but this does not identify a complete popup frame, visibility predicate, or observer scope.",
            "visibility_claim": "none",
        },
        {
            "id": "message_copy_and_template_nodes",
            "path_kind": "copy_points_for_live_frame",
            "rvas": ["0x598dc0", "0x5b29c0"],
            "vas": ["0x140598dc0", "0x1405b29c0"],
            "bodies": [
                _body("0x140598dc0", "0x140598ee8", 297),
                _body("0x1405b29c0", "0x1405b2ac6", 263),
            ],
            "evidence_id": "ev_51d6347595d0a8d8b6a9436bf23fd1e269096574bce32a9ae105935c16a7bbbe / ev_4582c75bb5b831a70732042fe45b85e723646f30e12d5c8d64a6287719f11ab7",
            "status": "copy_point_requires_live_lifetime_contract",
            "observation": "Copies message template containers and links key/value nodes. A future observer could copy fields while the message/window objects are alive, before the documented move/cleanup boundary, but the selected evidence does not prove ownership or country visibility.",
            "visibility_claim": "none",
        },
        {
            "id": "side_resolution_237fc0_21c7d0",
            "path_kind": "side_and_country_resolution",
            "rvas": ["0x237fc0", "0x21c7d0"],
            "vas": ["0x140237fc0", "0x14021c7d0"],
            "status": "identity_and_side_semantics_unresolved",
            "observation": "The result builder may swap raw sides using a selected-country reference, and the country selector resolves references through unit/virtual objects. Raw sides must be kept separate from final sides; these paths do not prove player visibility or a complete observer-known scope.",
            "visibility_claim": "candidate_identity_input_only",
        },
    ]


def build_report(root: Path) -> Dict[str, Any]:
    source_pins = []
    for relative, expected in EXPECTED_SMALL_FILES.items():
        source_pins.append(_pin(root, relative, expected))
    for relative in DOC_FILES:
        source_pins.append(_pin(root, relative))

    return {
        "schema": "information_battle_existing_visibility_paths.v1",
        "status": "passed_static_reuse_survey",
        "read_only": True,
        "game_access": False,
        "rpm_access": False,
        "rea_invoked": False,
        "native_function_invoked": False,
        "runtime_observed": False,
        "goal_complete": False,
        "fixed_build": {
            "version": FIXED_VERSION,
            "exe_sha256": FIXED_EXE_SHA256,
            "exe_size": FIXED_EXE_SIZE,
            "static_image_base": STATIC_IMAGE_BASE,
            "address_note": "RVA values are offsets from the image base; VA values are static image-base plus RVA and are not runtime module addresses.",
        },
        "source_policy": {
            "selected_evidence_only": True,
            "large_provider_reports_read": False,
            "max_source_bytes": MAX_SOURCE_BYTES,
            "hashing": "streamed chunks for listed small sources; no whole-file JSON load for large provider reports",
            "source_pins": source_pins,
            "large_provider_provenance": list(LARGE_PROVENANCE),
        },
        "conclusions": {
            "observer_message_setting_proven": False,
            "message_mode_or_notification_flags_only": True,
            "country_known_visibility_contract_proven": False,
            "player_or_root_binding_proven": False,
            "runtime_effects_observed": False,
            "complete_result_frame_source_proven": False,
            "complete_result_frame_copy_point": {
                "status": "best_static_copy_window_only",
                "window": "after 0x232a80/0x22e6b0 formatter work and before 0x8d44a0/0x244630 move/cleanup invalidates transient message storage",
                "field_fill_paths": ["0x8c75d0", "0x8ca460"],
                "message_copy_paths": ["0x598dc0", "0x5b29c0"],
                "limitation": "A natural event can supply a copy point, but saved evidence does not establish that all fields are populated for the observer or that the frame is a complete public battle result.",
            },
        },
        "findings": _findings(),
        "unresolved_questions": [
            "Which concrete object field or predicate suppresses allied/enemy/nonparticipant battle messages for the observer country?",
            "Which runtime reference binds a message to the observer/player/root, if any?",
            "Does the presentation path retain every result-frame field or only a selected subset?",
            "What is the ownership/lifetime contract for the message container through formatter, consumer, and cleanup?",
        ],
        "recommended_unqueried_functions": [
            {
                "rva": "0x14b2b40",
                "va": "0x1414b2b40",
                "reason": "The saved localization evidence identifies a separate placeholder-expansion helper; a bounded query could establish whether expansion preserves a complete frame or only a single text value.",
                "status": "candidate_only_unqueried_in_saved_paths",
                "do_not_infer": "No visibility or observer semantics should be inferred from this helper alone.",
            }
        ],
        "limitations": [
            "OUR/ENEMY/template keys, notification mode, side-vector nonemptiness, and observer flags are not equivalent to country-known visibility.",
            "Natural-window raw records and retained-subset cross-checks are transport/readout evidence only; they do not close B01-B04 or prove full business semantics.",
            "No new REA, game, RPM, native call, or runtime visibility observation was performed by this survey.",
        ],
    }


def main(argv: Optional[Iterable[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, default=None)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("work/runtime/information-battle-business-20261025-001/existing-visibility-paths-001.json"),
    )
    args = parser.parse_args(list(argv) if argv is not None else None)
    root = (args.workspace or Path(__file__).resolve().parents[1]).resolve()
    output = args.output if args.output.is_absolute() else root / args.output
    report = build_report(root)
    output.parent.mkdir(parents=True, exist_ok=True)
    # A stage report is an immutable checkpoint.  Refuse accidental overwrite.
    with output.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(report, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    print(json.dumps({"output": str(output), "sha256": _sha256(output), "findings": len(report["findings"])}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
