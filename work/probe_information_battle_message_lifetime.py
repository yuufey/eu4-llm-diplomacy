"""Link fixed-build message move/consume/popup paths without executing EU4.

REA observations, ordinary PE bytes and static interpretations stay separate.
No function in this script calls a game function or installs a hook.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from probe_information_battle_side_identity import excerpt

ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / "work/runtime/information-battle-message-20261025-001"
TARGET_SHA = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
IMAGE_BASE = 0x140000000
SPECS = {
    "instance": ("rea-message-instance-001", 0x8D44A0, "ev_3d93e7a0b9c66ea6a4fc361d80868c62dc546c73c0fa1f8b963ea30c47ba0b73"),
    "delivery": ("rea-result-delivery-001", 0x244630, "ev_3e8d5882cbd806cf067d34b97665b40eaecb95cdf25935fca5d923d1ebdadbf9"),
    "move": ("rea-message-move-001", 0x1AF380, "ev_4d63427b63ccf62f291119bc8a8fe5dfd4d152de9182151f454dce7750fb5aa7"),
    "consumer": ("rea-message-consumer-001", 0x8C05F0, "ev_7c83800baf700500a9000917e68dbbc53387cb49d61a9f8ba977378feb2801d1"),
    "logtext": ("rea-message-logtext-001", 0x8D4660, "ev_a59809c0f69256c01009ad31b139ed149c94fd9fbb6a9a3e6e202d1c10a4d34f"),
    "presenter": ("rea-message-presenter-001", 0x8C1270, "ev_6ff807ae2f2177c75bbbacd5f0ba6dff3417221a2d086c677dbb49cc19077ae2"),
    "popup": ("rea-popup-instance-001", 0x8C1DC0, "ev_e1e4b9eda31a62e4c07fa1dfe03224c3a795713f4c2d80283485ade03f433cae"),
}


def read(name: str) -> tuple[dict, dict]:
    directory, rva, expected_id = SPECS[name]
    path = STAGE / directory / "evidence.json"
    if path.stat().st_size > 4 * 1024 * 1024:
        raise ValueError(f"input exceeds bounded read: {path}")
    raw = path.read_bytes()
    document = json.loads(raw)
    if document["evidence_id"] != expected_id or document["subject"]["digest"]["sha256"] != TARGET_SHA:
        raise ValueError(f"evidence identity mismatch: {path}")
    value = document["normalized_result"]
    if value["procedure"]["address"] != hex(IMAGE_BASE + rva):
        raise ValueError(f"procedure mismatch: {path}")
    for key in ("procedure", "pseudocode", "assembly"):
        if value[key] != document["raw_result"]["value"][key]:
            raise ValueError(f"raw/normalized mismatch: {path}: {key}")
    return value, {"path": path.relative_to(ROOT).as_posix(), "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(), "evidence_id": expected_id,
        "rva": hex(rva), "static_va": hex(IMAGE_BASE + rva),
        "body_inclusive": value["procedure"]["body"]}


def main() -> None:
    output = STAGE / "message-lifetime-ledger-001.json"
    if output.exists():
        raise FileExistsError(output)
    values, sources = {}, {}
    for name in SPECS:
        values[name], sources[name] = read(name)
    instance, delivery, move = (values[x] for x in ("instance", "delivery", "move"))
    consumer, logtext, presenter, popup = (values[x] for x in ("consumer", "logtext", "presenter", "popup"))
    facts = [
        {"id": "message_owns_moved_template_container", "source": "instance",
         "observation": "8d44a0 writes vtable1c426e0 and the message-definition reference at +8; it transfers the template container's three header slots to message+10/+18/+20 and clears the source container. It also moves the string argument into message+60..+7f and clears the source string. This is not production of one continuous final result text.",
         "proof": [excerpt(instance, "param_1[2] = *param_3;", after=13),
                   excerpt(instance, "param_9[2] = 0;", after=6)],
         "unresolved": "Container node shape, deep string ownership and complete ABI/lifetime must be independently validated before copying a runtime message."},
        {"id": "message_records_game_date", "source": "instance",
         "observation": "Message+88 receives the 4-byte game+1dd0 date. Message+8c is initially zero. This date belongs to this natural message construction, not an external polling timestamp.",
         "proof": [excerpt(instance, "*(undefined4 *)(param_1 + 0x11)", after=3)],
         "unresolved": "No runtime date, world generation or correspondence with a real battle is observed in this batch."},
        {"id": "delivery_moves_before_consume", "source": "delivery",
         "observation": "244630 creates a stack destination with1af380, calls8c05f0 with the returned message pointer and optional callback wrapper, then cleans the original message+60 string and +10 container. Its generated pseudocode omits the second argument of1af380, but machine RDX still contains the original message argument at the call. The separately analyzed1af380 reads RDX and clears the source container/string fields.",
         "proof": [excerpt(delivery, "0x140244630:", assembly=True, after=23),
                   excerpt(delivery, "0x1402446d4:", assembly=True, after=7)],
         "unresolved": "Calling shape does not establish a general ABI contract for an external trampoline; stack alignment, registers and reentrancy still require audit."},
        {"id": "move_invalidates_source_headers", "source": "move",
         "observation": "1af380 transfers the message-definition/context fields, container slots+10/+18/+20 and string+60..+7f to its destination. It clears source container slots, source string length/capacity and first character. Capture after the move cannot assume the original headers still describe the payload.",
         "proof": [excerpt(move, "*(undefined8 *)(param_2 + 0x10) = 0;", after=7),
                   excerpt(move, "*(undefined8 *)(param_2 + 0x70) = 0;", after=9)],
         "unresolved": "No allocation-free deep copy of arbitrary template nodes is implemented by this finding."},
        {"id": "consumer_has_drop_and_route_gates", "source": "consumer",
         "observation": "8c05f0 tests game+1e66/+1e00, manager+48, game+74e0 and8c1ba0 before routing. A rejected branch cleans the message instead of producing popup/log output. Other branches use definition flags+10/+11/+12/+13/+14, may allocate notification objects, transfer ownership or call UI virtual methods. A single later UI or log hook is therefore not proven to cover every naturally constructed battle result.",
         "proof": [excerpt(consumer, "if ((((*(char *)(DAT_14233fe58", after=12),
                   excerpt(consumer, "if (*(char *)(lVar8 + 0x11)", after=22)],
         "unresolved": "The business meaning of all raw gate flags, player visibility, callback execution and suppressed-message coverage remain unresolved."},
        {"id": "native_log_is_separate_from_popup", "source": "logtext",
         "observation": "8d4660 constructs the definition key plus inline '_LOG', resolves it with template entries, formats message+88 date and joins it with ' - '. The consumer calls this only when global233fc10 is nonzero. A native log line is not proof of complete popup text or every popup field.",
         "proof": [excerpt(logtext, "local_120[0] = 0x474f4c5f;", after=3),
                   excerpt(logtext, "FUN_1414b33a0(local_78", after=8)],
         "unresolved": "Actual localization language, dynamic substitutions, UI text and runtime log output are not sampled."},
        {"id": "popup_selection_is_explicit", "source": "presenter",
         "observation": "8c1270 reads message-definition+58. Kind2 selects EndOfNavalCombatPopup. Kind1 chooses EndOfLandCombatCompactPopup when definition+5c is zero, otherwise EndOfLandCombatPopup. These string references close the earlier bounded GUI xref gap; they do not by themselves expose final displayed text.",
         "proof": [excerpt(presenter, '"EndOfNavalCombatPopup"', after=5),
                   excerpt(presenter, '"EndOfLandCombatCompactPopup"', after=5),
                   excerpt(presenter, '"EndOfLandCombatPopup"', after=5)],
         "unresolved": "Definition mutation/visibility, actual window lifetime and complete widget content are not runtime-validated."},
        {"id": "popup_embeds_another_message_object", "source": "popup",
         "observation": "8c1dc0 calls598dc0 at popup+1c0 using the incoming message, sets window callback fields, then routes kind1 to8c75d0 and kind2 to8ca460. The297-byte598dc0 helper was not newly analyzed, so whether this is a deep copy or another ownership transfer remains unresolved.",
         "proof": [excerpt(popup, "FUN_140598dc0(param_1 + 0x38,param_3);", after=6),
                   excerpt(popup, "FUN_1408c75d0(param_1);", after=6)],
         "unresolved": "Persistent retention, close-time cleanup, exact result text widgets and callback effects require further static and runtime evidence."},
    ]
    selected_paths = [
        ROOT / "work/runtime/information-battle-layout-20261025-001/rea-land-result-message-001/selected-evidence-001.json",
        ROOT / "work/runtime/information-battles-20261025-001/rea-message-dispatch-001/selected-evidence-001.json",
    ]
    manager_alias = []
    for path in selected_paths:
        raw = path.read_bytes()
        selected = json.loads(raw)
        lines = selected["raw_result_value"]["pseudocode"]["value"].splitlines()
        matches = [{"line_1based": index+1, "line": line} for index, line in enumerate(lines)
                   if "local_res8 = FUN_1408befa0();" in line or "FUN_140244630(local_res8," in line]
        if len(matches) != 2:
            raise ValueError(f"late manager alias assignments changed: {path}")
        manager_alias.append({"path": path.relative_to(ROOT).as_posix(), "bytes": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest(), "matches": matches})
    report = {
        "schema": "information_battle_message_lifetime_ledger_v1",
        "status": "bounded_static_move_consume_popup_findings",
        "target_exe_sha256": TARGET_SHA, "static_image_base": hex(IMAGE_BASE),
        "address_convention": "RVA in findings, static VA and inclusive body ranges in sources",
        "runtime_observed": False, "native_game_functions_called": 0, "hooks_installed": 0,
        "rea_sources": sources, "facts": facts,
        "late_manager_alias_correction": {"source_pins": manager_alias,
            "meaning": "In both land/naval final paths local_res8 is overwritten with8befa0() before244630. Its earlier param1/combat alias must not be carried into the final message-manager call."},
        "ordinary_pe_report": {"path": "work/runtime/information-battle-message-20261025-001/message-vtable-window-001.json",
            "sha256": "6adf74e12e95d4721cb54bb012433bc2c7e55f3fb65d5fdf06330a082ca5c596",
            "kind": "128-byte ordinary PE window; separate from REA; no slot semantics inferred"},
        "next_questions": [
            {"rva": "0x598dc0", "inclusive_bytes": 297, "question": "Determine message deep-copy/transfer semantics at popup+1c0."},
            {"rva": "0x8c75d0", "inclusive_bytes": 11811, "question": "Track actual land result text widgets and source-to-displayed-field mapping."},
            {"rva": "0x8ca460", "inclusive_bytes": 6775, "question": "Track actual naval result text widgets and captured-ship detail."},
        ],
        "catalog_promotion": False,
        "limitations": [
            "Seven read-only REA records observe static code, not real gameplay effects or correct runtime pointer lifetime.",
            "Message generation, observer visibility, native capture, queue handoff and LLM delivery remain separate stages.",
            "No full popup text, hook ABI, safe lifetime, battle/war identity, complete B01-B04 payload or real land/naval acceptance is established.",
            "No game function analyzed here is authorized as a fresh query or diplomacy dispatch by these findings.",
        ],
    }
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"path": output.relative_to(ROOT).as_posix(), "facts": len(facts),
        "sha256": hashlib.sha256(output.read_bytes()).hexdigest()}))


if __name__ == "__main__":
    main()
