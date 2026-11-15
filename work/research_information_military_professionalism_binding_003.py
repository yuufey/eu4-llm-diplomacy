"""Pin the professionalism locale contract against the bounded UI frame.

This is a static, no-new-decode follow-up to ``professionalism-binding-002``.
It streams only the four installed cradle-of-civilization locale files and
reuses the hash-pinned ``0xfbe450`` instruction records from that report.  It
does not open REA, attach to a process, invoke native code, or modify a
production reader.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from work.local_config import game_exe  # noqa: E402


EXPECTED_EXE_SHA256 = (
    "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
)
EXPECTED_EXE_BYTES = 38_463_016
EXPECTED_IMAGE_BASE = 0x140000000

PRIOR_PATH = ROOT / (
    "work/runtime/information-military-effective-20261027-001/"
    "professionalism-binding-002.json"
)
EXPECTED_PRIOR_SHA256 = (
    "2a219bfd1aaf79f35456124257d9fa83182b7eeead26ea8ba55fc17a659868dd"
)

FORMATTER_PATH = ROOT / (
    "work/runtime/information-trade-source-details-20261027-001/"
    "trade-details-source-index-003.json"
)
EXPECTED_FORMATTER_SHA256 = (
    "43f7f699c61ea08f7e298aeda210368c296df6d6addeb5db65ac7401f52e7674"
)

OUTPUT = ROOT / (
    "work/runtime/information-military-effective-20261027-001/"
    "professionalism-binding-003.json"
)

MAX_LOCALE_BYTES = 4 * 1024 * 1024
LOCALES = ("english", "french", "german", "spanish")
LOCALE_KEYS = (
    "ARMY_PROFESSIONALISM_VALUE",
    "ARMY_PROFESSIONALISM_ICON_TIP",
    "PROFESSIONALISM_MARKER_TOOLTIP",
)

_PLACEHOLDER_RE = re.compile(
    r"\$(?P<name>VALUE|VAL)\|(?P<color>[A-Za-z])%(?P<precision>[0-9]+)\$"
)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _load_json_pinned(path: Path, expected_sha256: str) -> tuple[dict[str, Any], str]:
    actual = _sha256_file(path)
    if actual != expected_sha256:
        raise RuntimeError(f"input_pin_mismatch:{path}:{actual}")
    with path.open("r", encoding="utf-8") as stream:
        value = json.load(stream)
    if not isinstance(value, dict):
        raise RuntimeError(f"report_not_object:{path}")
    return value, actual


def _find_locale_line(path: Path, key: str) -> dict[str, Any]:
    """Read one exact localization line without loading the file as a blob."""
    if not path.is_file():
        raise FileNotFoundError(path)
    size = path.stat().st_size
    if size > MAX_LOCALE_BYTES:
        raise RuntimeError(f"locale_file_exceeds_bound:{path}:{size}")
    needle = key.encode("ascii") + b":"
    matches: list[tuple[int, bytes]] = []
    with path.open("rb") as stream:
        for line_number, line in enumerate(stream, 1):
            if needle not in line:
                continue
            raw = line.rstrip(b"\r\n")
            matches.append((line_number, raw))
    if len(matches) != 1:
        raise RuntimeError(f"locale_key_count:{path}:{key}:{len(matches)}")
    line_number, raw = matches[0]
    try:
        decoded = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RuntimeError(f"locale_utf8_error:{path}:{key}") from exc
    return {
        "key": key,
        "line": line_number,
        "raw_hex": raw.hex(),
        "decoded_utf8": decoded,
    }


def _placeholder_contract(text: str, key: str) -> dict[str, Any]:
    matches = [
        {
            "name": item.group("name"),
            "color": item.group("color"),
            "precision": int(item.group("precision")),
            "raw": item.group(0),
        }
        for item in _PLACEHOLDER_RE.finditer(text)
    ]
    wanted = [item for item in matches if item["name"] in {"VALUE", "VAL"}]
    if not wanted:
        raise RuntimeError(f"percent_placeholder_missing:{key}")
    return {
        "key": key,
        "placeholders": matches,
        "value_placeholders": wanted,
        "percent_directive_present": any(
            item["raw"].startswith(("$VALUE|", "$VAL|"))
            and "%" in item["raw"]
            for item in wanted
        ),
    }


def _locale_contract(installation_root: Path) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    for language in LOCALES:
        path = installation_root / "localisation" / (
            f"cradle_of_civilization_l_{language}.yml"
        )
        size = path.stat().st_size
        lines = {key: _find_locale_line(path, key) for key in LOCALE_KEYS}
        rows.append(
            {
                "language": language,
                "path": str(path),
                "relative_path": f"localisation/cradle_of_civilization_l_{language}.yml",
                "bytes": size,
                "sha256": _sha256_file(path),
                "lines": lines,
                "placeholder_contracts": {
                    key: _placeholder_contract(lines[key]["decoded_utf8"], key)
                    for key in LOCALE_KEYS
                },
            }
        )
    return {
        "installation_root": str(installation_root),
        "files": rows,
        "selection": {
            "key": "ARMY_PROFESSIONALISM_VALUE",
            "all_languages_match": all(
                "$VALUE|Y%2$" in row["lines"]["ARMY_PROFESSIONALISM_VALUE"]["decoded_utf8"]
                for row in rows
            ),
            "display_precision": 2,
            "display_unit": "percent_presentation_directive",
            "color_directive": "Y",
        },
    }


def _widget_instructions(prior: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    ranges = prior.get("new_bounded_ranges")
    if not isinstance(ranges, list):
        raise RuntimeError("prior_widget_ranges_missing")
    widget = next(
        (item for item in ranges if item.get("label") == "professionalism_value_widget"),
        None,
    )
    if not isinstance(widget, dict):
        raise RuntimeError("prior_value_widget_range_missing")
    instructions = widget.get("instructions")
    if not isinstance(instructions, list):
        raise RuntimeError("prior_value_widget_instructions_missing")
    by_rva = {int(item["rva"], 16): item for item in instructions}
    addresses = (
        0xFBE467,
        0xFBE46A,
        0xFBE4A3,
        0xFBE4A8,
        0xFBE4B0,
        0xFBE4B3,
        0xFBE4BB,
        0xFBE4C1,
        0xFBE4C6,
        0xFBE4CD,
        0xFBE4D0,
        0xFBE4D5,
        0xFBE4DD,
        0xFBE4E5,
        0xFBE4E9,
        0xFBE4EE,
    )
    selected = []
    for address in addresses:
        item = by_rva.get(address)
        if item is None:
            raise RuntimeError(f"prior_widget_instruction_missing:{address:#x}")
        selected.append(item)
    expected = {
        0xFBE4A8: ("c744246808000000", "DWORD PTR [rsp+0x68],0x8"),
        0xFBE4B0: ("488b03", "rax,QWORD PTR [rbx]"),
        0xFBE4B3: ("4889842498000000", "QWORD PTR [rsp+0x98],rax"),
        0xFBE4BB: ("41b901000000", "r9d,0x1"),
        0xFBE4C1: ("4c8d442440", "r8,[rsp+0x40]"),
        0xFBE4C6: ("488d15fba7d800", "rdx,[rip+0xd8a7fb]        # 0x141d48cc8"),
        0xFBE4D0: ("e8cb4e4f00", "0x1414b33a0"),
        0xFBE4E5: ("448d4299", "r8d,[rdx-0x67]"),
        0xFBE4EE: ("e8f14da700", "0x141a332e4"),
    }
    for address, (raw, operands) in expected.items():
        item = by_rva[address]
        if item.get("bytes") != raw or item.get("operands") != operands:
            raise RuntimeError(f"prior_widget_instruction_changed:{address:#x}")
    return widget, selected


def _formatter_contract() -> dict[str, Any]:
    formatter, digest = _load_json_pinned(FORMATTER_PATH, EXPECTED_FORMATTER_SHA256)
    guard = next(
        (
            item
            for item in formatter.get("code_guards", [])
            if item.get("name") == "fixed_point_formatter_14bc950"
        ),
        None,
    )
    if not isinstance(guard, dict):
        raise RuntimeError("fixed_point_formatter_guard_missing")
    return {
        "source_report": FORMATTER_PATH.relative_to(ROOT).as_posix(),
        "source_report_sha256": digest,
        "guard": {
            "name": guard["name"],
            "rva": guard["rva"],
            "rva_end_exclusive": guard["rva_end_exclusive"],
            "va": guard["va"],
            "va_end_exclusive": guard["va_end_exclusive"],
            "sha256": guard["sha256"],
            "kind": guard["kind"],
        },
        "proven_contract": {
            "caller_kind": 2,
            "caller_flag": 1,
            "formula": "signed_i32(raw_or_effective) / 1000",
            "scope": "Only callsites proven to pass kind=2/flag=1 to 0x14bc950.",
        },
    }


def build_report() -> dict[str, Any]:
    executable = game_exe()
    size = executable.stat().st_size
    exe_sha = _sha256_file(executable)
    if size != EXPECTED_EXE_BYTES or exe_sha != EXPECTED_EXE_SHA256:
        raise RuntimeError(f"unexpected_executable:{size}:{exe_sha}")

    prior, prior_sha = _load_json_pinned(PRIOR_PATH, EXPECTED_PRIOR_SHA256)
    binary = prior.get("binary", {})
    if (
        binary.get("sha256") != EXPECTED_EXE_SHA256
        or binary.get("size") != EXPECTED_EXE_BYTES
        or binary.get("image_base") != hex(EXPECTED_IMAGE_BASE)
    ):
        raise RuntimeError("prior_binary_identity_mismatch")
    widget, selected = _widget_instructions(prior)
    formatter = _formatter_contract()
    locales = _locale_contract(executable.parent)

    return {
        "schema": "information_military_professionalism_locale_frame_static.v3",
        "status": "partial",
        "source_kind": "ordinary_pe_and_installed_locale_bounded_static_not_REA",
        "scope": "N03.army_professionalism.current_country_display_unit_boundary",
        "binary": {
            "path": str(executable),
            "size": size,
            "sha256": exe_sha,
            "image_base": hex(EXPECTED_IMAGE_BASE),
            "version_pin": "EU4 1.37.4",
        },
        "method": {
            "game_or_rpm": False,
            "rea": False,
            "native_calls": False,
            "new_pe_decode_bytes": 0,
            "reused_static_report": PRIOR_PATH.relative_to(ROOT).as_posix(),
            "locale_read_mode": "bounded_binary_line_stream",
            "locale_max_file_bytes": MAX_LOCALE_BYTES,
            "scope_note": (
                "No new PE decode was performed.  The 0xfbe450 instruction records are reused only "
                "after the prior report hash and exact selected bytes are verified; locale files are "
                "hashed and scanned line by line."
            ),
        },
        "source_pins": {
            "professionalism_binding_002": {
                "path": PRIOR_PATH.relative_to(ROOT).as_posix(),
                "sha256": prior_sha,
                "bytes": PRIOR_PATH.stat().st_size,
            },
            "fixed_point_formatter_source_index_003": {
                "path": FORMATTER_PATH.relative_to(ROOT).as_posix(),
                "sha256": formatter["source_report_sha256"],
                "bytes": FORMATTER_PATH.stat().st_size,
            },
        },
        "locale_contract": locales,
        "fbe450_frame": {
            "range": {
                "start_rva": widget["start_rva"],
                "end_rva_exclusive": widget["end_rva_exclusive"],
                "start_va": widget["start_va"],
                "end_va_exclusive": widget["end_va_exclusive"],
                "bytes_sha256": widget["bytes_sha256"],
                "evidence_kind": "reused_bounded_instruction_range",
            },
            "frame_base": "RSP+0x40",
            "selected_instructions": selected,
            "fields": {
                "key_pointer": {
                    "location": "[RSP+0x40]",
                    "value": "VALUE",
                    "meaning": "localized argument key/name field",
                },
                "type_tag_candidate": {
                    "status": "unresolved_semantic_type",
                    "location": "[RSP+0x68] = frame_base + 0x28",
                    "rva": "0xfbe4a8",
                    "raw_bytes": "c744246808000000",
                    "raw_dword": 8,
                    "instruction": "DWORD PTR [RSP+0x68] = 0x8",
                    "meaning": (
                        "A frame field constant/tag candidate.  The bounded evidence does not identify "
                        "it as integer, double, ratio, or fixed-point."
                    ),
                },
                "raw_value_qword": {
                    "location": "[RSP+0x98] = frame_base + 0x58",
                    "rva": "0xfbe4b3",
                    "raw_bytes": "4889842498000000",
                    "effect": "QWORD [RBX] is copied verbatim into [RSP+0x98]",
                    "source_chain": "RBX=R9; R9 holds the output of the country+0x50 leaf",
                },
            },
            "calls": {
                "localized_key_helper": {
                    "rva": "0x14b33a0",
                    "callsite_rva": "0xfbe4d0",
                    "role": "localized key/hash lookup helper",
                },
                "record_builder": {
                    "rva": "0x1a332e4",
                    "callsite_rva": "0xfbe4ee",
                    "role": "argument-record/vector builder; not proven numeric formatter",
                },
                "fixed_point_formatter": {
                    "rva": "0x14bc950",
                    "callsite_present_in_fbe450": False,
                    "reason": "The selected fbe450 path calls 0x14b33a0 and 0x1a332e4, not 0x14bc950.",
                },
            },
        },
        "formatter_reuse_assessment": {
            **formatter,
            "status": "not_reused_for_fbe450_without_variant_consumer_proof",
            "fbe450_call_arguments": {
                "r9d_at_key_lookup": 1,
                "r8d_at_record_builder": 1,
                "frame_tag_candidate": 8,
            },
            "why_not_applied": (
                "The existing signed_i32/1000 contract is pinned only for a callsite that passes kind=2 "
                "and flag=1 to 0x14bc950.  The fbe450 bounded path has a frame field value 8 and calls "
                "different helpers; no bounded evidence maps this field to the kind=2 contract."
            ),
            "next_minimal_target": (
                "A bounded variant/template consumer that interprets frame_base+0x28 (or the template "
                "parser's numeric argument) is required; 0x14b33a0 is a key helper, not that consumer."
            ),
        },
        "unit_and_scale": {
            "display_unit_status": "closed_as_percent_presentation",
            "display_unit": "percent",
            "display_precision": 2,
            "evidence": [
                "All four installed ARMY_PROFESSIONALISM_VALUE templates contain $VALUE|Y%2$.",
                "The English icon tooltip uses $VAL|Y%0$ and marker tooltip uses $VALUE|Y%1$.",
                "The percent directive is an on-disk presentation instruction, not a proven storage conversion.",
            ],
            "ratio_vs_percent_input": {
                "status": "unresolved",
                "reason": (
                    "The locale proves percent presentation, but the bounded fbe450 frame does not prove "
                    "whether the formatter receives a 0..1 ratio, a 0..100 percent, or another scaled raw value."
                ),
            },
            "source_raw_contract": {
                "status": "closed_identity_only",
                "expression": "display_argument_raw = i64_bits(country_qword_at_0x50)",
                "evidence": ["0x9a530", "0xfb927a", "0xfbe4b0", "0xfbe4b3"],
                "source_scale": "unresolved",
            },
            "do_not_infer": [
                "Do not apply signed_i32/1000 merely because the separate 0x14bc950 kind=2 contract exists.",
                "Do not apply the separate 32768 ratio/percent candidate paths at 0xd02da0/0xd03d90.",
                "Do not publish a complete N03 professionalism scalar from this locale-only percentage directive.",
            ],
        },
        "conclusion": {
            "closed": [
                "Installed English, French, German, and Spanish templates identify this value as percent-formatted with two decimal places.",
                "The current-country QWORD remains raw through the getter and the fbe450 argument frame; no scale operation appears in that bounded path.",
                "The existing fixed-point formatter contract was checked but is not statically connected to this frame.",
            ],
            "unresolved": [
                "The numeric input convention (ratio versus already-percent) and source scale remain unresolved.",
                "Frame field 0x8 is only a type/tag candidate until its bounded consumer is identified.",
            ],
            "publication": "Keep N03 professionalism partial/planned at the source-scale boundary.",
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
        raise FileExistsError(
            f"refusing to overwrite existing report; use --force explicitly: {args.output}"
        )
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
                "new_pe_decode_bytes": report["method"]["new_pe_decode_bytes"],
                "locale_files": len(report["locale_contract"]["files"]),
                "display_unit": report["unit_and_scale"]["display_unit"],
                "display_precision": report["unit_and_scale"]["display_precision"],
                "source_scale": report["unit_and_scale"]["source_raw_contract"]["source_scale"],
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
