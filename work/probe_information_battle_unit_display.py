"""Build a bounded unit-display source ledger from frozen REA selections.

The selected land and naval pseudocode is already bounded and stored as small
artifacts.  This script reads only those selections plus the small conversion
helper report; it does not open the original multi-megabyte REA JSON, query
REA, access a game process, call a native function, or infer a player/country
view from the template names.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
EXPECTED_EXE_SHA256 = (
    "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
)
IMAGE_BASE = 0x140000000
MAX_INPUT_BYTES = 16 * 1024 * 1024
MAX_REPORT_BYTES = 4 * 1024 * 1024

DEFAULT_CONVERSION = (
    ROOT
    / "work/runtime/information-battle-scalar-writers-20261025-001/"
    "rea-count-conversion-001/evidence.json"
)
DEFAULT_LAND = (
    ROOT
    / "work/runtime/information-battle-layout-20261025-001/"
    "rea-land-result-message-001/selected-evidence-001.json"
)
DEFAULT_NAVAL = (
    ROOT
    / "work/runtime/information-battles-20261025-001/"
    "rea-message-dispatch-001/selected-evidence-001.json"
)
DEFAULT_OUTPUT = (
    ROOT
    / "work/runtime/information-battle-layout-20261025-001/"
    "unit-display-ledger-001.json"
)


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _relative(path: Path) -> str:
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except ValueError:
        return str(path.resolve())


def _read_small_json(path: Path) -> tuple[dict[str, Any], bytes]:
    path = path.resolve()
    if not path.is_file():
        raise FileNotFoundError(path)
    size = path.stat().st_size
    if size > MAX_INPUT_BYTES:
        raise ValueError(f"input exceeds 16 MiB bound: {path} ({size})")
    raw = path.read_bytes()
    document = json.loads(raw.decode("utf-8"))
    if not isinstance(document, dict):
        raise ValueError(f"input root is not an object: {path}")
    return document, raw


def _value(node: Any, key: str) -> Any:
    value = node.get(key) if isinstance(node, dict) else None
    if not isinstance(value, dict) or "value" not in value:
        raise ValueError(f"bounded selected value is missing: {key}")
    return value["value"]


def _line_window(lines: list[str], start: int, end: int) -> list[dict[str, Any]]:
    if start < 1 or end < start or end > len(lines):
        raise ValueError(f"line window outside pseudocode: {start}..{end}")
    return [{"line": number, "text": lines[number - 1]} for number in range(start, end + 1)]


def _find_template_line(lines: list[str], template: str, expected: int) -> int:
    hits = [
        number
        for number, line in enumerate(lines, 1)
        if f'"{template}"' in line
    ]
    if hits != [expected]:
        raise ValueError(f"template {template} lines changed: {hits!r} != {[expected]!r}")
    return expected


def _hex_offsets(offsets: list[int]) -> list[str]:
    return [hex(offset) for offset in offsets]


def _row(
    *,
    lines: list[str],
    template: str,
    expected_line: int,
    side: str,
    unit: str,
    phase: str,
    source_binding: str,
    offsets: list[int],
    formula: str,
    expression_range: tuple[int, int],
    conversion_path: str,
    end_divide_before_subtract: bool | None,
    notes: str,
) -> dict[str, Any]:
    line = _find_template_line(lines, template, expected_line)
    start, end = expression_range
    return {
        "template": template,
        "side_label": side,
        "unit_label": unit,
        "phase": phase,
        "template_line": line,
        "source_binding": source_binding,
        "native_combat_side_offsets": _hex_offsets(offsets),
        "formula_as_decompiled": formula,
        "conversion_path": conversion_path,
        "end_divide_each_operand_before_subtract": end_divide_before_subtract,
        "expression_lines": _line_window(lines, start, end),
        "player_or_country_view": "unresolved; OUR/ENEMY is only the native template label",
        "notes": notes,
    }


def _selected_descriptor(path: Path, document: dict[str, Any], raw: bytes, role: str) -> dict[str, Any]:
    top = document.get("top_level", {})
    evidence_id = None
    if isinstance(top.get("evidence_id"), dict):
        evidence_id = top["evidence_id"].get("value")
    identity = document.get("identity_audit")
    target_sha = identity.get("subject_sha256") if isinstance(identity, dict) else None
    if target_sha is None:
        request = document.get("request", {})
        actual = request.get("actual", {}) if isinstance(request, dict) else {}
        target_sha = actual.get("target_sha256")
    if target_sha != EXPECTED_EXE_SHA256:
        raise ValueError(f"{role} selected evidence target SHA mismatch: {target_sha!r}")
    source = document.get("source")
    if not isinstance(source, dict):
        raise ValueError(f"{role} selected evidence lacks source metadata")
    pseudo = _value(document.get("raw_result_value"), "pseudocode")
    if not isinstance(pseudo, str) or not pseudo:
        raise ValueError(f"{role} pseudocode is not a bounded string")
    procedure = _value(document.get("raw_result_value"), "procedure")
    if not isinstance(procedure, dict):
        raise ValueError(f"{role} procedure value is not an object")
    address = procedure.get("address")
    if not isinstance(address, str) or not address.startswith("0x"):
        raise ValueError(f"{role} procedure address is missing")
    return {
        "role": role,
        "selected_artifact": {
            "path": _relative(path),
            "bytes": len(raw),
            "sha256": _sha256(raw),
            "status": document.get("status"),
            "evidence_id": evidence_id,
        },
        "original_evidence_metadata": {
            "path": source.get("path"),
            "sha256": source.get("sha256"),
            "size_bytes": source.get("size_bytes"),
            "stable_before_after": source.get("stable_before_after"),
        },
        "target_exe_sha256": target_sha,
        "procedure": {
            "address": address,
            "rva": hex(int(address, 16) - IMAGE_BASE),
            "body": procedure.get("body"),
        },
        "pseudocode_lines": len(pseudo.splitlines()),
        "pseudocode": pseudo,
    }


def _conversion_descriptor(path: Path, document: dict[str, Any], raw: bytes) -> dict[str, Any]:
    value = document.get("raw_result", {}).get("value", {})
    if not isinstance(value, dict):
        raise ValueError("conversion REA value is missing")
    subject_sha = document.get("subject", {}).get("digest", {}).get("sha256")
    if subject_sha != EXPECTED_EXE_SHA256:
        raise ValueError(f"conversion evidence target SHA mismatch: {subject_sha!r}")
    procedure = value.get("procedure")
    if not isinstance(procedure, dict):
        raise ValueError("conversion procedure metadata is missing")
    body = procedure.get("body", {})
    ranges = body.get("ranges", [])
    if (
        procedure.get("address") != "0x1400cfcd0"
        or body.get("total_bytes") != 18
        or ranges != [{"start": "0x1400cfcd0", "end": "0x1400cfce1"}]
    ):
        raise ValueError("conversion helper body contract changed")
    pseudocode = value.get("pseudocode")
    if not isinstance(pseudocode, str) or "return *param_1 / 1000;" not in pseudocode:
        raise ValueError("conversion helper pseudocode does not show signed /1000")
    assembly = value.get("assembly")
    if not isinstance(assembly, list) or not assembly:
        raise ValueError("conversion helper assembly is missing")
    return {
        "source": {
            "path": _relative(path),
            "bytes": len(raw),
            "sha256": _sha256(raw),
            "evidence_id": document.get("evidence_id"),
            "subject_exe_sha256": subject_sha,
        },
        "procedure": {
            "address": procedure["address"],
            "rva": hex(int(procedure["address"], 16) - IMAGE_BASE),
            "body_ranges": ranges,
            "body_bytes": body.get("total_bytes"),
        },
        "pseudocode": pseudocode,
        "assembly": assembly,
        "interpretation": {
            "conversion": "signed integer pointed value divided by 1000, as decompiled",
            "rounding_or_display_rule": "unresolved",
            "runtime_observed": False,
        },
    }


def _land_rows(lines: list[str]) -> list[dict[str, Any]]:
    our = "lVar29 = *local_b8 = *(param_1 + 0x20)"
    enemy = "lVar30 = *local_100 = *(param_1 + 0x28)"
    rows = [
        ("OURCAVSTART", 407, "OUR", "CAV", "START", [0x11C], "raw lVar29 field / 1000", (402, 407), "direct integer /1000 in the formatter argument", None, "start value"),
        ("OURINFSTART", 427, "OUR", "INF", "START", [0x118], "raw lVar29 field / 1000", (422, 427), "direct integer /1000 in the formatter argument", None, "start value"),
        ("OURARTSTART", 447, "OUR", "ART", "START", [0x120], "raw lVar29 field / 1000", (442, 447), "direct integer /1000 in the formatter argument", None, "start value"),
        ("OURCAVLOST", 472, "OUR", "CAV", "LOST", [0x138], "FUN_1400cfcd0(raw lVar29 field)", (462, 472), "CFCD0 conversion, then additional formatter/marker path", None, "loss field is directly read before CFCD0"),
        ("OURINFLOST", 507, "OUR", "INF", "LOST", [0x134], "FUN_1400cfcd0(raw lVar29 field)", (497, 507), "CFCD0 conversion, then additional formatter/marker path", None, "loss field is directly read before CFCD0"),
        ("OURARTLOST", 542, "OUR", "ART", "LOST", [0x13C], "FUN_1400cfcd0(raw lVar29 field)", (532, 542), "CFCD0 conversion, then additional formatter/marker path", None, "loss field is directly read before CFCD0"),
        ("OURLOST", 556, "OUR", "ALL", "LOST", [0x1C], "FUN_1400cfcd0(raw lVar29 aggregate field)", (550, 556), "CFCD0 conversion", None, "aggregate template retained as an extra ledger row"),
        ("OURCAVEND", 578, "OUR", "CAV", "END", [0x11C, 0x138], "CFCD0(+0x11C) - CFCD0(+0x138)", (564, 578), "each operand is converted before subtraction", True, "end expression uses iVar12 - iVar11"),
        ("OURINFEND", 586, "OUR", "INF", "END", [0x118, 0x134], "CFCD0(+0x118) - CFCD0(+0x134)", (564, 586), "each operand is converted before subtraction", True, "end expression uses iVar8 - iVar6"),
        ("OURARTEND", 594, "OUR", "ART", "END", [0x120, 0x13C], "CFCD0(+0x120) - CFCD0(+0x13C)", (568, 594), "each operand is converted before subtraction", True, "end expression uses iVar10 - iVar9"),
        ("ENEMYCAVSTART", 950, "ENEMY", "CAV", "START", [0x11C], "raw lVar30 field / 1000 via CFCD0", (946, 950), "CFCD0 conversion", None, "enemy-side raw field"),
        ("ENEMYINFSTART", 960, "ENEMY", "INF", "START", [0x118], "raw lVar30 field / 1000 via CFCD0", (956, 960), "CFCD0 conversion", None, "enemy-side raw field"),
        ("ENEMYARTSTART", 970, "ENEMY", "ART", "START", [0x120], "raw lVar30 field / 1000 via CFCD0", (966, 970), "CFCD0 conversion", None, "enemy-side raw field"),
        ("ENEMYCAVLOST", 982, "ENEMY", "CAV", "LOST", [0x138], "FUN_1400cfcd0(raw lVar30 field)", (976, 982), "CFCD0 conversion, then additional formatter/marker path", None, "loss field is directly read before CFCD0"),
        ("ENEMYINFLOST", 996, "ENEMY", "INF", "LOST", [0x134], "FUN_1400cfcd0(raw lVar30 field)", (990, 996), "CFCD0 conversion, then additional formatter/marker path", None, "loss field is directly read before CFCD0"),
        ("ENEMYARTLOST", 1010, "ENEMY", "ART", "LOST", [0x13C], "FUN_1400cfcd0(raw lVar30 field)", (1004, 1010), "CFCD0 conversion, then additional formatter/marker path", None, "loss field is directly read before CFCD0"),
        ("ENEMYLOST", 1024, "ENEMY", "ALL", "LOST", [0x1C], "FUN_1400cfcd0(raw lVar30 aggregate field)", (1018, 1024), "CFCD0 conversion", None, "aggregate template retained as an extra ledger row"),
        ("ENEMYCAVEND", 1046, "ENEMY", "CAV", "END", [0x11C, 0x138], "CFCD0(+0x11C) - CFCD0(+0x138)", (1032, 1046), "each operand is converted before subtraction", True, "end expression uses iVar12 - iVar11"),
        ("ENEMYINFEND", 1054, "ENEMY", "INF", "END", [0x118, 0x134], "CFCD0(+0x118) - CFCD0(+0x134)", (1032, 1054), "each operand is converted before subtraction", True, "end expression uses iVar8 - iVar6"),
        ("ENEMYARTEND", 1062, "ENEMY", "ART", "END", [0x120, 0x13C], "CFCD0(+0x120) - CFCD0(+0x13C)", (1036, 1062), "each operand is converted before subtraction", True, "end expression uses iVar10 - iVar9"),
    ]
    result = []
    for template, line, side, unit, phase, offsets, formula, span, conversion, divide, notes in rows:
        result.append(
            _row(
                lines=lines,
                template=template,
                expected_line=line,
                side=side,
                unit=unit,
                phase=phase,
                source_binding=our if side == "OUR" else enemy,
                offsets=offsets,
                formula=formula,
                expression_range=span,
                conversion_path=conversion,
                end_divide_before_subtract=divide,
                notes=notes,
            )
        )
    return result


def _naval_rows(lines: list[str]) -> list[dict[str, Any]]:
    our = "lVar18 = *(param_1 + 0x20) at entry"
    enemy = "lVar18 = local_d8 = *(param_1 + 0x28) before ENEMY rows"
    rows = [
        ("OURCAVSTART", 370, "OUR", "CAV", "START", [0x124], "raw lVar18 field / 1000", (358, 370), "direct integer /1000", None, "entry side +0x20"),
        ("OURINFSTART", 390, "OUR", "INF", "START", [0x128], "raw lVar18 field / 1000", (359, 390), "direct integer /1000", None, "entry side +0x20"),
        ("OURARTSTART", 410, "OUR", "ART", "START", [0x12C], "raw lVar18 field / 1000", (361, 410), "direct integer /1000", None, "entry side +0x20"),
        ("OURTRANSSTART", 430, "OUR", "TRANS", "START", [0x130], "raw lVar18 field / 1000", (362, 430), "direct integer /1000", None, "entry side +0x20"),
        ("OURCAVLOST", 504, "OUR", "CAV", "LOST", [0x140], "CFCD0(+0x140), sign/participant adjustments", (446, 504), "CFCD0 then branch and participant adjustments", None, "iVar16 is reused after start setup"),
        ("OURINFLOST", 512, "OUR", "INF", "LOST", [0x144], "CFCD0(+0x144), sign/participant adjustments", (446, 512), "CFCD0 then branch and participant adjustments", None, "iVar23 is reused after start setup"),
        ("OURARTLOST", 520, "OUR", "ART", "LOST", [0x148], "CFCD0(+0x148), sign/participant adjustments", (446, 520), "CFCD0 then branch and participant adjustments", None, "iVar24 is reused after start setup"),
        ("OURTRANSLOST", 528, "OUR", "TRANS", "LOST", [0x14C], "CFCD0(+0x14C), sign/participant adjustments", (446, 528), "CFCD0 then branch and participant adjustments", None, "iVar21 is reused after start setup"),
        ("OURCAVEND", 546, "OUR", "CAV", "END", [0x124, 0x140], "start accumulator + signed loss accumulator", (534, 546), "addition after prior conversions; alternate branch zeroes result", False, "iVar22 = local_158 + iVar16"),
        ("OURINFEND", 554, "OUR", "INF", "END", [0x128, 0x144], "start accumulator + signed loss accumulator", (534, 554), "addition after prior conversions; alternate branch zeroes result", False, "local_e4 = local_res20 + iVar23"),
        ("OURARTEND", 562, "OUR", "ART", "END", [0x12C, 0x148], "start accumulator + signed loss accumulator", (534, 562), "addition after prior conversions; alternate branch zeroes result", False, "local_224 = local_154 + iVar24"),
        ("OURTRANSEND", 570, "OUR", "TRANS", "END", [0x130, 0x14C], "start accumulator + signed loss accumulator", (534, 570), "addition after prior conversions; alternate branch zeroes result", False, "local_228 = local_e8 + iVar21"),
        ("ENEMYCAVSTART", 829, "ENEMY", "CAV", "START", [0x124], "raw lVar18 field / 1000", (818, 829), "CFCD0 conversion", None, "lVar18 was rebound to local_d8 (+0x28)"),
        ("ENEMYINFSTART", 837, "ENEMY", "INF", "START", [0x128], "raw lVar18 field / 1000", (820, 837), "CFCD0 conversion", None, "lVar18 was rebound to local_d8 (+0x28)"),
        ("ENEMYARTSTART", 845, "ENEMY", "ART", "START", [0x12C], "raw lVar18 field / 1000", (823, 845), "CFCD0 conversion", None, "lVar18 was rebound to local_d8 (+0x28)"),
        ("ENEMYTRANSSTART", 853, "ENEMY", "TRANS", "START", [0x130], "raw lVar18 field / 1000", (825, 853), "CFCD0 conversion", None, "lVar18 was rebound to local_d8 (+0x28)"),
        ("ENEMYCAVLOST", 926, "ENEMY", "CAV", "LOST", [0x140], "CFCD0(+0x140), sign/participant adjustments", (861, 926), "CFCD0 then branch and participant adjustments", None, "iVar16 is reused after start setup"),
        ("ENEMYINFLOST", 934, "ENEMY", "INF", "LOST", [0x144], "CFCD0(+0x144), sign/participant adjustments", (861, 934), "CFCD0 then branch and participant adjustments", None, "iVar23 is reused after start setup"),
        ("ENEMYARTLOST", 942, "ENEMY", "ART", "LOST", [0x148], "CFCD0(+0x148), sign/participant adjustments", (861, 942), "CFCD0 then branch and participant adjustments", None, "iVar24 is reused after start setup"),
        ("ENEMYTRANSLOST", 950, "ENEMY", "TRANS", "LOST", [0x14C], "CFCD0(+0x14C), sign/participant adjustments", (861, 950), "CFCD0 then branch and participant adjustments", None, "iVar21 is reused after start setup"),
        ("ENEMYCAVEND", 970, "ENEMY", "CAV", "END", [0x124, 0x140], "start accumulator + signed loss accumulator", (956, 970), "addition after prior conversions; alternate branch zeroes result", False, "iVar16 = local_228 + iVar16"),
        ("ENEMYINFEND", 978, "ENEMY", "INF", "END", [0x128, 0x144], "start accumulator + signed loss accumulator", (956, 978), "addition after prior conversions; alternate branch zeroes result", False, "iVar23 = local_res20 + iVar23"),
        ("ENEMYARTEND", 986, "ENEMY", "ART", "END", [0x12C, 0x148], "start accumulator + signed loss accumulator", (956, 986), "addition after prior conversions; alternate branch zeroes result", False, "iVar24 = local_158 + iVar24"),
        ("ENEMYTRANSEND", 994, "ENEMY", "TRANS", "END", [0x130, 0x14C], "start accumulator + signed loss accumulator", (956, 994), "addition after prior conversions; alternate branch zeroes result", False, "iVar21 = local_154 + iVar21"),
    ]
    result = []
    for template, line, side, unit, phase, offsets, formula, span, conversion, divide, notes in rows:
        result.append(
            _row(
                lines=lines,
                template=template,
                expected_line=line,
                side=side,
                unit=unit,
                phase=phase,
                source_binding=our if side == "OUR" else enemy,
                offsets=offsets,
                formula=formula,
                expression_range=span,
                conversion_path=conversion,
                end_divide_before_subtract=divide,
                notes=notes,
            )
        )
    return result


def _land_alias(lines: list[str]) -> dict[str, Any]:
    exact = [84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 141, 142]
    return {
        "kind": "top_alias_and_raw_side_binding",
        "source_lines": _line_window(lines, 84, 94) + _line_window(lines, 141, 142),
        "raw_side_pointers": {
            "local_b8": "param_1 + 0x20",
            "local_100": "param_1 + 0x28",
        },
        "orientation_flag": "*(char *)(param_2 + 0x4c) == 0",
        "when_flag_is_zero": {"plVar14": "local_100", "plVar16": "local_b8"},
        "when_flag_is_nonzero": {"plVar14": "local_b8", "plVar16": "local_100"},
        "scalar_rows_after_alias": {
            "OUR_lVar29": "*local_b8 = *(param_1 + 0x20)",
            "ENEMY_lVar30": "*local_100 = *(param_1 + 0x28)",
        },
        "exact_line_numbers_checked": exact,
        "player_view": "not established by this branch; preserve raw +0x20/+0x28 and do not call either side FRA/player",
    }


def _naval_side_binding(lines: list[str]) -> dict[str, Any]:
    return {
        "kind": "raw_side_binding_without_land_alias_branch",
        "source_lines": _line_window(lines, 74, 75) + _line_window(lines, 711, 713),
        "entry_OUR_side": "lVar18 = *(param_1 + 0x20)",
        "entry_other_side_storage": "local_d8 = *(param_1 + 0x28)",
        "ENEMY_rebind": "lVar18 = local_d8 before ENEMY scalar rows",
        "player_view": "not established; template labels remain native OUR/ENEMY only",
    }


def build_report(conversion_path: Path, land_path: Path, naval_path: Path) -> dict[str, Any]:
    conversion_document, conversion_raw = _read_small_json(conversion_path)
    land_document, land_raw = _read_small_json(land_path)
    naval_document, naval_raw = _read_small_json(naval_path)

    conversion = _conversion_descriptor(conversion_path, conversion_document, conversion_raw)
    land_descriptor = _selected_descriptor(land_path, land_document, land_raw, "land")
    naval_descriptor = _selected_descriptor(naval_path, naval_document, naval_raw, "naval")
    land_lines = land_descriptor.pop("pseudocode").splitlines()
    naval_lines = naval_descriptor.pop("pseudocode").splitlines()
    if len(land_lines) != 1477 or len(naval_lines) != 1597:
        raise ValueError("selected pseudocode line counts changed")

    land_descriptor["alias_branch"] = _land_alias(land_lines)
    land_descriptor["templates"] = _land_rows(land_lines)
    naval_descriptor["side_binding"] = _naval_side_binding(naval_lines)
    naval_descriptor["templates"] = _naval_rows(naval_lines)

    script_path = Path(__file__).resolve()
    land_source_size = land_descriptor["original_evidence_metadata"].get("size_bytes")
    return {
        "schema": "information-battle-unit-display-ledger-001",
        "status": "static_expression_ledger",
        "read_only": True,
        "runtime_observed": False,
        "native_function_invoked": False,
        "target_build": {
            "version": "1.37.4",
            "executable_sha256": EXPECTED_EXE_SHA256,
            "image_base": hex(IMAGE_BASE),
            "address_convention": "REA VAs are retained; RVA is VA minus 0x140000000",
        },
        "script": {"path": _relative(script_path), "sha256": _file_sha256(script_path)},
        "conversion_helper": conversion,
        "selected_sources": {
            "land": land_descriptor,
            "naval": naval_descriptor,
        },
        "conversion_and_end_rules": {
            "helper": "FUN_1400cfcd0 decompiled as signed int pointed value / 1000",
            "land": {
                "start": "direct raw field /1000 expressions",
                "lost": "CFCD0 conversion of each listed loss field",
                "end": "each start and loss operand is separately CFCD0-converted, then the converted values are subtracted",
                "end_divide_before_subtract": True,
            },
            "naval": {
                "start": "direct /1000 expressions for the four start fields",
                "lost": "CFCD0 conversion followed by sign and participant adjustments",
                "end": "signed loss accumulators are added to converted starts under the zero-flag branch; alternate branch zeroes the displayed end accumulator",
                "end_divide_before_subtract": False,
                "direct_subtraction_observed": False,
            },
            "rounding_and_display": "unresolved; formatter AE8A80 was not analyzed here",
        },
        "errata": {
            "land_original_evidence_size": {
                "bytes": land_source_size,
                "greater_than_decimal_10000000": isinstance(land_source_size, int)
                and land_source_size > 10_000_000,
                "less_than_binary_10MiB": isinstance(land_source_size, int)
                and land_source_size < 10 * 1024 * 1024,
                "statement": "The prior land artifact's 10,281,549-byte size is above 10,000,000 decimal bytes but below 10 MiB; this report records the distinction and does not modify that artifact.",
                "old_artifact_modified": False,
            }
        },
        "semantic_limits": [
            "OUR and ENEMY are template labels, not proof of player, attacker, defender, or FRA identity.",
            "The raw +0x20/+0x28 side pointers and land orientation branch remain separate from any player-view interpretation.",
            "The ledger records native offsets and expressions only; it does not assign unit business names beyond the literal template token.",
            "No runtime values, side ordering, initial/remaining semantics, rounding, or display formatting were observed.",
            "No full original evidence was reread; only bounded selected artifacts were loaded.",
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--conversion-evidence", type=Path, default=DEFAULT_CONVERSION)
    parser.add_argument("--land-selected", type=Path, default=DEFAULT_LAND)
    parser.add_argument("--naval-selected", type=Path, default=DEFAULT_NAVAL)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args(argv)

    report = build_report(
        args.conversion_evidence.resolve(),
        args.land_selected.resolve(),
        args.naval_selected.resolve(),
    )
    output = args.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    encoded = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if len(encoded.encode("utf-8")) > MAX_REPORT_BYTES:
        raise ValueError("generated report exceeds 4 MiB bound")
    output.write_text(encoded, encoding="utf-8", newline="\n")
    json.loads(output.read_text(encoding="utf-8"))
    print(json.dumps({"output": _relative(output), "bytes": output.stat().st_size}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
