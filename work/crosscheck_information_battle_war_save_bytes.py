#!/usr/bin/env python3
"""Preserve exact bytes for the recorded FRA/BUR battle in the fixed R70 save.

This is intentionally independent of the text save parser.  It iterates a
binary file by physical LF (0x0A) only, keeps the already audited active_war
line range bounded, and never decodes the EU4 name/commander carrier as text.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / "work" / "runtime" / "information-battle-war-records-20261025-001"
DEFAULT_SAVE = Path(
    r"C:\Users\wangyufei\Documents\Paradox Interactive\Europa Universalis IV"
    r"\save games\llm_diplomacy_r70_country_money_rejected_20261020.eu4"
)
DEFAULT_OUTPUT = STAGE / "save-bytes-fra-bur-001" / "report.json"
LEGACY_REPORT = STAGE / "save-crosscheck-fra-bur-001" / "report.json"

EXPECTED_SAVE_SHA256 = "ffa91dbd2a2d544b18d586a895bb9b0c2b90e94ece47b2c74507555b8f58c2e0"
EXPECTED_LEGACY_REPORT_SHA256 = "e1a9a3e771f9afbc4e09edcc277538c656f61ec50a2e922a1a36810185d3c72d"
EXPECTED_HEADER = b"EU4txt"
LINE_START = 2_201_638
LINE_END = 2_202_005
MAX_SELECTION_BYTES = 1024 * 1024
MAX_REPORT_BYTES = 1024 * 1024
HASH_CHUNK_BYTES = 1024 * 1024
EXPECTED_ACTIVE_WAR_CAPTURE_SHA256 = "3f3f78e57ac3fd0c63c1af45a8935cb43736755014494245fce0eb03e8d33113"
EXPECTED_LEGACY_TEXT_CAPTURE_BYTES = 4890
EXPECTED_NAME_HEX = "11315710544e10bb6c10776d12e153"
EXPECTED_BUR_COMMANDER_HEX = "10819c105390102b592056616c6b656e737761617264"

DATE_KEY_RE = re.compile(rb"^\s*([0-9]{1,4}\.[0-9]{1,2}\.[0-9]{1,2})\s*=\s*\{\s*$")
ASSIGNMENT_RE = re.compile(rb"^\s*([A-Za-z0-9_.-]+)\s*=\s*(.*)$")
ASCII_PRINTABLE = set(range(0x20, 0x7F))


class BinarySaveCrosscheckError(RuntimeError):
    """Raised when the fixed binary baseline cannot be trusted."""


def _relative(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(ROOT)).replace("\\", "/")
    except ValueError:
        return str(path)


def _stream_sha256(path: Path, *, max_bytes: int | None = None) -> tuple[str, int, int]:
    digest = hashlib.sha256()
    total = 0
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(HASH_CHUNK_BYTES), b""):
            total += len(chunk)
            if max_bytes is not None and total > max_bytes:
                raise BinarySaveCrosscheckError(f"bounded input exceeded {max_bytes} bytes: {path}")
            digest.update(chunk)
    return digest.hexdigest(), total, path.stat().st_mtime_ns


def _file_fingerprint(path: Path) -> dict[str, Any]:
    stat = path.stat()
    return {
        "path": str(path),
        "size_bytes": stat.st_size,
        "mtime_ns": stat.st_mtime_ns,
    }


def _load_legacy_report(path: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    if not path.is_file():
        raise BinarySaveCrosscheckError(f"legacy FRA/BUR report is missing: {path}")
    digest, size, mtime_ns = _stream_sha256(path, max_bytes=MAX_REPORT_BYTES)
    if digest != EXPECTED_LEGACY_REPORT_SHA256:
        raise BinarySaveCrosscheckError(
            f"legacy report SHA mismatch: expected {EXPECTED_LEGACY_REPORT_SHA256}, got {digest}"
        )
    try:
        data = json.loads(path.read_bytes())
    except (OSError, json.JSONDecodeError) as exc:
        raise BinarySaveCrosscheckError(f"cannot parse legacy report: {exc}") from exc
    if not isinstance(data, dict):
        raise BinarySaveCrosscheckError("legacy report is not an object")
    return data, {"path": _relative(path), "size_bytes": size, "mtime_ns": mtime_ns, "sha256": digest}


def _brace_delta(body: bytes) -> tuple[int, bool, bool]:
    """Count braces outside quotes; return delta, quote ambiguity, escape seen."""

    delta = 0
    in_quote = False
    escaped = False
    escape_seen = False
    for byte in body:
        if in_quote:
            if escaped:
                escaped = False
            elif byte == 0x5C:
                escaped = True
                escape_seen = True
            elif byte == 0x22:
                in_quote = False
            continue
        if byte == 0x22:
            in_quote = True
        elif byte == 0x7B:
            delta += 1
        elif byte == 0x7D:
            delta -= 1
    return delta, in_quote or escaped, escape_seen


def _assignment(body: bytes) -> tuple[str, bytes] | None:
    match = ASSIGNMENT_RE.match(body)
    if match is None:
        return None
    try:
        key = match.group(1).decode("ascii")
    except UnicodeDecodeError as exc:
        raise BinarySaveCrosscheckError(f"non-ASCII field key at binary line: {body[:80].hex()}") from exc
    return key, match.group(2).rstrip(b" \t\r")


def _ascii_if_unambiguous(value: bytes) -> str | None:
    if not value or any(byte not in ASCII_PRINTABLE for byte in value):
        return None
    try:
        return value.decode("ascii")
    except UnicodeDecodeError:
        return None


def _raw_value_record(value: bytes, line_no: int, field: str) -> dict[str, Any]:
    """Record bytes and quote certainty without producing a lossy text value."""

    record: dict[str, Any] = {
        "field": field,
        "line": line_no,
        "raw_value_bytes_hex": value.hex(),
    }
    if value.startswith(b'"'):
        record["quote_form"] = "quoted"
        record["raw_quoted_bytes_hex"] = value.hex()
        if len(value) < 2 or not value.endswith(b'"'):
            record.update({"quote_status": "unbalanced", "text_status": "not_claimed"})
            return record
        inner = value[1:-1]
        record["raw_unquoted_bytes_hex"] = inner.hex()
        if b'"' in inner or b"\\" in inner:
            record.update({"quote_status": "internal_quote_or_escape", "text_status": "not_claimed"})
            return record
        ascii_text = _ascii_if_unambiguous(inner)
        record["quote_status"] = "balanced_no_escape"
        if ascii_text is None:
            record["text_status"] = "binary_carrier_not_decoded"
        else:
            record.update({"text_status": "ascii_unambiguous", "ascii_if_unambiguous": ascii_text})
        return record

    record["quote_form"] = "unquoted"
    record["raw_unquoted_bytes_hex"] = value.hex()
    ascii_text = _ascii_if_unambiguous(value)
    if ascii_text is None:
        record["text_status"] = "binary_carrier_not_decoded"
    else:
        record.update({"text_status": "ascii_unambiguous", "ascii_if_unambiguous": ascii_text})
    return record


def _date_record(raw_key: bytes, line_no: int) -> dict[str, Any]:
    return {
        "line": line_no,
        "raw_key_bytes_hex": raw_key.hex(),
        "ascii_if_unambiguous": raw_key.decode("ascii"),
        "text_status": "ascii_unambiguous",
    }


def _line_body(raw_line: bytes) -> tuple[bytes, str]:
    """Remove exactly one physical LF, never split on other Unicode separators."""

    if raw_line.endswith(b"\n"):
        body = raw_line[:-1]
        return body, "lf"
    return raw_line, "eof_without_lf"


def _find_target_battle(lines: list[dict[str, Any]]) -> dict[str, Any]:
    candidates: list[dict[str, Any]] = []
    for index, entry in enumerate(lines):
        match = DATE_KEY_RE.match(entry["body"])
        if match is None:
            continue
        date_key = match.group(1)
        delta, ambiguous, _ = _brace_delta(entry["body"])
        if ambiguous or delta != 1:
            continue
        depth = delta
        block = [entry]
        for later in lines[index + 1 :]:
            block.append(later)
            later_delta, later_ambiguous, _ = _brace_delta(later["body"])
            if later_ambiguous:
                raise BinarySaveCrosscheckError(
                    f"ambiguous quote/escape in selected battle block at line {later['line']}"
                )
            depth += later_delta
            if depth == 0:
                break
        if depth != 0:
            raise BinarySaveCrosscheckError(f"unclosed date block at line {entry['line']}")
        top_fields: dict[str, dict[str, Any]] = {}
        sides: dict[str, dict[str, Any]] = {}
        depth = 1
        active_side: str | None = None
        container_depth: int | None = None
        for part in block[1:]:
            assignment = _assignment(part["body"])
            if assignment is not None:
                key, value = assignment
                if depth == 1 and key == "battle" and value == b"{":
                    container_depth = 2
                elif depth == (container_depth or 1):
                    if key in {"attacker", "defender"} and value == b"{":
                        active_side = key
                        sides.setdefault(key, {})
                    else:
                        top_fields[key] = _raw_value_record(value, part["line"], key)
                elif container_depth is not None and depth == container_depth + 1 and active_side is not None:
                    sides[active_side][key] = _raw_value_record(value, part["line"], key)
            delta_part, ambiguous_part, _ = _brace_delta(part["body"])
            if ambiguous_part:
                raise BinarySaveCrosscheckError(
                    f"ambiguous quote/escape in selected battle block at line {part['line']}"
                )
            depth_before = depth
            depth += delta_part
            if active_side is not None and container_depth is not None and depth_before == container_depth + 1 and depth == container_depth:
                active_side = None
        if date_key == b"1455.9.26" and {"name", "location", "result"}.issubset(top_fields) and {"attacker", "defender"}.issubset(sides):
            candidates.append({
                "date": _date_record(date_key, entry["line"]),
                "line_start": entry["line"],
                "line_end": block[-1]["line"],
                "byte_start": entry["byte_start"],
                "byte_end_exclusive": block[-1]["byte_end_exclusive"],
                "name": top_fields["name"],
                "location": top_fields["location"],
                "result": top_fields["result"],
                "sides": sides,
                "other_raw_fields": {
                    key: value
                    for key, value in top_fields.items()
                    if key not in {"name", "location", "result"}
                },
                "raw_values_uninterpreted": True,
            })
    if len(candidates) != 1:
        raise BinarySaveCrosscheckError(f"expected one FRA/BUR battle block, found {len(candidates)}")
    return candidates[0]


def _scan_selected(path: Path) -> dict[str, Any]:
    lines: list[dict[str, Any]] = []
    offset = 0
    selected_bytes = 0
    physical_digest = hashlib.sha256()
    selected_lf_count = 0
    selected_non_lf_count = 0
    selected_0x85_count = 0
    with path.open("rb") as stream:
        for line_no, raw_line in enumerate(stream, 1):
            byte_start = offset
            offset += len(raw_line)
            if line_no < LINE_START:
                continue
            if line_no > LINE_END:
                break
            if selected_bytes + len(raw_line) > MAX_SELECTION_BYTES:
                raise BinarySaveCrosscheckError("selected active_war range exceeds 1 MiB")
            body, ending = _line_body(raw_line)
            selected_bytes += len(raw_line)
            physical_digest.update(raw_line)
            selected_lf_count += ending == "lf"
            selected_non_lf_count += ending != "lf"
            selected_0x85_count += body.count(b"\x85")
            lines.append({
                "line": line_no,
                "byte_start": byte_start,
                "byte_end_exclusive": offset,
                "body": body,
                "line_ending": ending,
            })
    if len(lines) != LINE_END - LINE_START + 1:
        raise BinarySaveCrosscheckError(
            f"selected physical line range incomplete: {len(lines)} lines"
        )
    if selected_non_lf_count:
        raise BinarySaveCrosscheckError("selected active_war range contains a non-LF line ending")
    battle = _find_target_battle(lines)
    return {
        "line_start": LINE_START,
        "line_end": LINE_END,
        "byte_start": lines[0]["byte_start"],
        "byte_end_exclusive": lines[-1]["byte_end_exclusive"],
        "physical_bytes_captured": selected_bytes,
        "physical_range_sha256": physical_digest.hexdigest(),
        "line_count": len(lines),
        "physical_lf_count": selected_lf_count,
        "non_lf_line_count": selected_non_lf_count,
        "literal_0x85_bytes_in_selected_lines": selected_0x85_count,
        "splitter": "binary iteration split by physical 0x0A only; no str.splitlines",
        "battle": battle,
    }


def _validate_legacy_metadata(legacy: dict[str, Any]) -> dict[str, Any]:
    try:
        record = legacy["pair_result"]["records"][0]
        battle = record["battle_history"]["battles"][0]
    except (KeyError, IndexError, TypeError) as exc:
        raise BinarySaveCrosscheckError(f"legacy FRA/BUR report shape changed: {exc}") from exc
    expected = {
        "line_start": LINE_START,
        "line_end": LINE_END,
        "bytes_captured": EXPECTED_LEGACY_TEXT_CAPTURE_BYTES,
        "active_war_capture_sha256": EXPECTED_ACTIVE_WAR_CAPTURE_SHA256,
    }
    actual = {key: record.get(key) for key in expected}
    if actual != expected:
        raise BinarySaveCrosscheckError(f"legacy active_war metadata changed: {actual!r}")
    if record.get("original_sides") != {"original_attacker": "FRA", "original_defender": "BUR"}:
        raise BinarySaveCrosscheckError("legacy active_war is no longer FRA/BUR")
    name_text = battle.get("name", {}).get("decoded_text")
    commander_text = battle.get("sides", {}).get("defender", {}).get("commander", {}).get("decoded_text")
    return {
        "legacy_report_name_decoded_contains_replacement": isinstance(name_text, str) and "\ufffd" in name_text,
        "legacy_report_defender_commander_contains_replacement": isinstance(commander_text, str) and "\ufffd" in commander_text,
        "legacy_report_decoding_policy": "UTF-8 errors=replace in old text report; not a binary payload claim",
    }


def run_crosscheck(save_path: Path, output_path: Path) -> dict[str, Any]:
    if not save_path.is_file():
        raise BinarySaveCrosscheckError(f"save is missing: {save_path}")
    legacy, legacy_pin = _load_legacy_report(LEGACY_REPORT)
    legacy_loss = _validate_legacy_metadata(legacy)

    before_stat = _file_fingerprint(save_path)
    before_sha, before_size, before_mtime = _stream_sha256(save_path)
    if before_size < len(EXPECTED_HEADER) or before_sha != EXPECTED_SAVE_SHA256:
        raise BinarySaveCrosscheckError(
            f"fixed R70 save SHA mismatch: expected {EXPECTED_SAVE_SHA256}, got {before_sha}"
        )
    with save_path.open("rb") as stream:
        header = stream.read(len(EXPECTED_HEADER))
    if header != EXPECTED_HEADER:
        raise BinarySaveCrosscheckError(f"unexpected save header bytes: {header.hex()}")
    selection = _scan_selected(save_path)
    after_sha, after_size, after_mtime = _stream_sha256(save_path)
    after_stat = _file_fingerprint(save_path)
    if (before_sha, before_size, before_mtime) != (after_sha, after_size, after_mtime):
        raise BinarySaveCrosscheckError("save changed during binary crosscheck")
    battle = selection["battle"]
    name_hex = battle["name"].get("raw_unquoted_bytes_hex")
    commander_hex = battle["sides"]["defender"]["commander"].get("raw_unquoted_bytes_hex")
    if name_hex != EXPECTED_NAME_HEX or commander_hex != EXPECTED_BUR_COMMANDER_HEX:
        raise BinarySaveCrosscheckError(
            f"binary target bytes changed: name={name_hex}, commander={commander_hex}"
        )

    report: dict[str, Any] = {
        "schema": "information_battle_war_save_bytes_crosscheck_v1",
        "status": "passed_binary_save_crosscheck",
        "read_only": True,
        "native_query_called": False,
        "rea_called": False,
        "game_access": False,
        "production_changed": False,
        "target": {
            "actor": "FRA",
            "recipient": "BUR",
            "purpose": "Exact binary comparison baseline for the existing recorded FRA/BUR battle.",
            "source_range": {"line_start": LINE_START, "line_end": LINE_END, "max_bytes": MAX_SELECTION_BYTES},
            "text_decoding": "No name/commander text decoding; raw quoted and unquoted bytes are authoritative.",
        },
        "save": {
            "path": str(save_path),
            "header_bytes_hex": header.hex(),
            "size_bytes": before_size,
            "expected_sha256": EXPECTED_SAVE_SHA256,
            "sha256_before": before_sha,
            "sha256_after": after_sha,
            "mtime_ns_before": before_stat["mtime_ns"],
            "mtime_ns_after": after_stat["mtime_ns"],
            "hash_before_after_equal": True,
            "unchanged_during_scan": True,
        },
        "legacy_text_report": {
            **legacy_pin,
            **legacy_loss,
            "legacy_utf8_replacement_is_not_current_binary_mismatch": True,
            "binary_report_is_authoritative_for_name_and_commander_bytes": True,
        },
        "selection": selection,
        "legacy_capture_metadata": {
            "line_start": LINE_START,
            "line_end": LINE_END,
            "text_parser_reencoded_bytes": EXPECTED_LEGACY_TEXT_CAPTURE_BYTES,
            "text_parser_reencoded_sha256": EXPECTED_ACTIVE_WAR_CAPTURE_SHA256,
            "physical_binary_bytes": selection["physical_bytes_captured"],
            "physical_binary_sha256": selection["physical_range_sha256"],
            "difference_reason": "旧parser按UTF-8 errors=replace后重新编码，不能与本次物理保存字节数/哈希直接比较。",
        },
        "binary_targets": {
            "name_expected_unquoted_hex": EXPECTED_NAME_HEX,
            "name_actual_unquoted_hex": name_hex,
            "name_match": True,
            "bur_commander_expected_unquoted_hex": EXPECTED_BUR_COMMANDER_HEX,
            "bur_commander_actual_unquoted_hex": commander_hex,
            "bur_commander_match": True,
        },
        "boundaries": [
            "Only physical LF (0x0A) split lines were selected; 0x85 was not treated as a separator.",
            "The old active_war capture byte count/SHA are text-parser re-encoded metadata; the new physical range has its own byte count/SHA.",
            "Name and commander bytes remain uninterpreted EU4 carriers; no encoding, unit, or semantic inference is made.",
            "The old UTF-8 errors=replace report is retained only as a lossy-display comparison and was not rewritten.",
            "This is recorded-save evidence, not a live/native reader result or catalog fallback.",
        ],
    }
    encoded = (json.dumps(report, ensure_ascii=False, indent=2, sort_keys=False) + "\n").encode("utf-8")
    if len(encoded) > MAX_REPORT_BYTES:
        raise BinarySaveCrosscheckError(f"report exceeds {MAX_REPORT_BYTES} bytes")
    output_path = output_path.resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if output_path.exists():
        raise BinarySaveCrosscheckError(f"refusing to overwrite existing output: {output_path}")
    output_path.write_bytes(encoded)
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--save", type=Path, default=DEFAULT_SAVE)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args(argv)
    try:
        report = run_crosscheck(args.save, args.output)
    except (OSError, BinarySaveCrosscheckError, ValueError) as exc:
        print(f"binary save crosscheck failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({
        "status": report["status"],
        "output": str(args.output.resolve()),
        "save_sha256": report["save"]["sha256_before"],
        "selected_bytes": report["selection"]["physical_bytes_captured"],
        "battle_lines": [report["selection"]["battle"]["line_start"], report["selection"]["battle"]["line_end"]],
        "name_hex": report["binary_targets"]["name_actual_unquoted_hex"],
        "bur_commander_hex": report["binary_targets"]["bur_commander_actual_unquoted_hex"],
    }, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
