#!/usr/bin/env python3
"""Bounded, save-only baseline for the fixed R70 war-history reader.

This module never opens the game and never calls native/REA/RPM tooling.  It
reuses the repository's streaming EU4 text scanner, keeps each matching
``active_war`` block below the existing 2 MiB capture limit, and extracts only
serialized battle history fields needed for an offline comparison.  A missing
FRA/ENG active-war match is an explicit result, not a fallback or a native
claim.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

try:
    from work import inspect_declare_war_save_pair as war_parser
    from work import inspect_dissolve_save_pair as bounded
except ModuleNotFoundError:  # direct execution from another working directory
    ROOT_FOR_IMPORT = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(ROOT_FOR_IMPORT))
    from work import inspect_declare_war_save_pair as war_parser
    from work import inspect_dissolve_save_pair as bounded

ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / "work" / "runtime" / "information-battle-war-records-20261025-001"
DEFAULT_SAVE = Path(
    r"C:\Users\wangyufei\Documents\Paradox Interactive\Europa Universalis IV"
    r"\save games\llm_diplomacy_r70_country_money_rejected_20261020.eu4"
)
DEFAULT_OUTPUT = STAGE / "save-crosscheck-001" / "report.json"
EXPECTED_SAVE_SHA256 = "ffa91dbd2a2d544b18d586a895bb9b0c2b90e94ece47b2c74507555b8f58c2e0"
EXPECTED_HEADER = "EU4txt"
MAX_INPUT_BYTES = 128 * 1024 * 1024
MAX_WAR_CAPTURE_BYTES = int(getattr(war_parser, "MAX_WAR_CAPTURE_BYTES", 2 * 1024 * 1024))
MAX_WAR_RECORDS = int(getattr(war_parser, "MAX_WAR_RECORDS", 64))
MAX_BATTLES_PER_WAR = 128
MAX_REPORT_BYTES = 1024 * 1024
MAX_TEXT_BYTES = 8192
TAG_RE = re.compile(r"^[A-Z][A-Z0-9_]{1,5}$")
DATE_RE = re.compile(r"^\d{1,4}\.\d{1,2}\.\d{1,2}$")
HISTORY_BLOCK_LINE_RE = re.compile(r"^\s*([A-Za-z0-9_.-]+)\s*=\s*\{")
HISTORY_SCALAR_LINE_RE = re.compile(r"^\s*([A-Za-z0-9_.-]+)\s*=\s*(.*)$")


class SaveCrosscheckError(RuntimeError):
    """Raised when the save or the bounded extraction cannot be trusted."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def file_fingerprint(path: Path) -> dict[str, Any]:
    stat = path.stat()
    return {
        "path": str(path.resolve()),
        "size_bytes": stat.st_size,
        "mtime_ns": stat.st_mtime_ns,
    }


def clipped_text(value: Any, limit: int = MAX_TEXT_BYTES) -> tuple[Any, bool]:
    """Keep text bounded while preserving its raw decoded representation."""

    if not isinstance(value, str):
        return value, False
    encoded = value.encode("utf-8", "replace")
    if len(encoded) <= limit:
        return value, False
    return encoded[:limit].decode("utf-8", "replace"), True


def clipped_raw(value: Any, limit: int = MAX_TEXT_BYTES) -> tuple[Any, bool]:
    if isinstance(value, list):
        result: list[Any] = []
        truncated = False
        for item in value[:64]:
            clipped, item_truncated = clipped_raw(item, limit)
            result.append(clipped)
            truncated = truncated or item_truncated
        if len(value) > 64:
            truncated = True
        return result, truncated
    return clipped_text(value, limit)


def last_scalar(fields: dict[str, Any], key: str) -> Any:
    values = war_parser.scalar_values(fields.get(key))
    return values[-1] if values else None


def text_field(fields: dict[str, Any], key: str) -> dict[str, Any]:
    raw = last_scalar(fields, key)
    clipped, truncated = clipped_raw(raw)
    decoded = war_parser.unquoted(raw) if isinstance(raw, str) else None
    decoded, decoded_truncated = clipped_text(decoded)
    return {
        "present": raw is not None,
        "raw": clipped,
        "decoded_text": decoded,
        "truncated": bool(truncated or decoded_truncated),
    }


def history_top_level_entries(body: str) -> list[Any]:
    """Parse one bounded history body, including dotted date keys.

    The shared save parser intentionally uses a narrower identifier grammar for
    its older country/relation use.  EU4 history keys are dates such as
    ``1455.9.10``; this local bounded helper accepts only that additional
    punctuation and still delegates brace/quote handling to the shared parser.
    """

    entries: list[Any] = []
    depth = 0
    offset = 0
    for line in body.splitlines(keepends=True):
        if depth == 0:
            block_match = HISTORY_BLOCK_LINE_RE.match(line)
            if block_match:
                open_index = offset + line.find("{")
                entries.append(
                    bounded.Entry(
                        block_match.group(1),
                        None,
                        bounded.extract_block(body, open_index),
                    )
                )
            else:
                scalar_match = HISTORY_SCALAR_LINE_RE.match(line)
                if scalar_match:
                    entries.append(
                        bounded.Entry(
                            scalar_match.group(1),
                            scalar_match.group(2).strip(),
                            None,
                        )
                    )
        depth += bounded.brace_delta(line)
        offset += len(line)
    return entries


def parse_side(entry: Any) -> dict[str, Any]:
    """Extract raw country/commander and untyped raw quantity fields."""

    if entry.body is None:
        return {
            "present": False,
            "country": {"present": False, "raw": None, "decoded_text": None, "truncated": False},
            "commander": {"present": False, "raw": None, "decoded_text": None, "truncated": False},
            "raw_quantity_fields": {},
            "raw_fields": {},
            "blocks": [],
        }
    entries = bounded.top_level_entries(entry.body)
    fields, blocks = bounded.flatten_entries(entries)
    raw_fields: dict[str, Any] = {}
    raw_quantity_fields: dict[str, Any] = {}
    any_truncated = False
    excluded = {"country", "commander", "is_attacker"}
    for key, value in fields.items():
        clipped, truncated = clipped_raw(value)
        raw_fields[key] = clipped
        any_truncated = any_truncated or truncated
        leaf = key.rsplit(".", 1)[-1]
        if leaf not in excluded:
            raw_quantity_fields[key] = clipped
    country = text_field(fields, "country")
    commander = text_field(fields, "commander")
    any_truncated = any_truncated or country["truncated"] or commander["truncated"]
    return {
        "present": True,
        "country": country,
        "commander": commander,
        "raw_quantity_fields": raw_quantity_fields,
        "raw_fields": raw_fields,
        "blocks": blocks[:256],
        "truncated": any_truncated,
    }


def extract_battle_history(active_war_text: str) -> dict[str, Any]:
    """Extract bounded history/date/battle records from one active_war block."""

    open_index = active_war_text.find("{")
    if open_index < 0:
        return {"status": "unknown", "reason": "active_war_open_brace_missing", "battles": []}
    try:
        body = bounded.extract_block(active_war_text, open_index)
        entries = bounded.top_level_entries(body)
    except Exception as exc:  # keep the containing war result explicit
        return {
            "status": "unknown",
            "reason": "history_parse_failed:" + type(exc).__name__,
            "battles": [],
        }

    battles: list[dict[str, Any]] = []
    history_blocks = 0
    unknown: list[str] = []
    for history_entry in entries:
        if history_entry.key != "history" or history_entry.body is None:
            continue
        history_blocks += 1
        try:
            dated_entries = history_top_level_entries(history_entry.body)
        except Exception as exc:
            unknown.append("history_dates_parse_failed:" + type(exc).__name__)
            continue
        for date_index, dated_entry in enumerate(dated_entries):
            if dated_entry.body is None:
                continue
            date_raw, date_truncated = clipped_text(dated_entry.key)
            try:
                history_entries = bounded.top_level_entries(dated_entry.body)
            except Exception as exc:
                unknown.append("history_entry_parse_failed:" + type(exc).__name__)
                continue
            for battle_index, battle_entry in enumerate(history_entries):
                if battle_entry.key != "battle" or battle_entry.body is None:
                    continue
                if len(battles) >= MAX_BATTLES_PER_WAR:
                    unknown.append("battle_entry_limit_reached")
                    break
                try:
                    battle_children = bounded.top_level_entries(battle_entry.body)
                    fields, blocks = bounded.flatten_entries(battle_children)
                except Exception as exc:
                    unknown.append("battle_parse_failed:" + type(exc).__name__)
                    continue
                raw_fields: dict[str, Any] = {}
                fields_truncated = bool(date_truncated)
                for key, value in fields.items():
                    clipped, truncated = clipped_raw(value)
                    raw_fields[key] = clipped
                    fields_truncated = fields_truncated or truncated
                sides: dict[str, Any] = {}
                for side_name in ("attacker", "defender"):
                    side_entry = next(
                        (item for item in battle_children
                         if item.key == side_name and item.body is not None),
                        None,
                    )
                    sides[side_name] = parse_side(side_entry) if side_entry is not None else parse_side(type("Empty", (), {"body": None})())
                    fields_truncated = fields_truncated or bool(sides[side_name].get("truncated"))
                location_raw = last_scalar(fields, "location")
                result_raw = last_scalar(fields, "result")
                battles.append({
                    "date": {"raw": date_raw, "date_shape_recognized": bool(DATE_RE.fullmatch(str(date_raw)))},
                    "history_entry_index": date_index,
                    "battle_entry_index": battle_index,
                    "name": text_field(fields, "name"),
                    "location": {"present": location_raw is not None, "raw": clipped_raw(location_raw)[0]},
                    "result": {"present": result_raw is not None, "raw": clipped_raw(result_raw)[0]},
                    "sides": sides,
                    "raw_fields": raw_fields,
                    "raw_nested_blocks": blocks[:256],
                    "raw_values_uninterpreted": True,
                    "truncated": fields_truncated,
                })
            if len(battles) >= MAX_BATTLES_PER_WAR:
                break
    return {
        "status": "known" if not unknown else "partial",
        "history_block_count": history_blocks,
        "battle_count": len(battles),
        "battles": battles,
        "unknown": unknown,
        "limits": {"max_battles_per_war": MAX_BATTLES_PER_WAR, "max_text_bytes": MAX_TEXT_BYTES},
    }


class CaptureActiveWarScanner(war_parser.ActiveWarScanner):
    """Existing bounded scanner plus one bounded active-war text parse."""

    def finish(self, end_line: int | None, complete: bool) -> None:
        current = self.current
        self.current = None
        if current is None:
            return
        if not complete:
            self.unknown.append(f"active_war_unclosed_at_line_{current['line_start']}")
            return
        if current["too_large"]:
            self.unknown.append(
                f"active_war_lines_{current['line_start']}_{end_line}_exceeded_{MAX_WAR_CAPTURE_BYTES}_bytes"
            )
            return
        text = "".join(current["lines"])
        try:
            record = war_parser.parse_active_war_block(
                text,
                self.actor,
                self.recipient,
                current["line_start"],
                end_line,
                current["bytes_captured"],
            )
            if record is None:
                return
            history = extract_battle_history(text)
            record["battle_history"] = history
            record["active_war_capture_sha256"] = hashlib.sha256(
                text.encode("utf-8", "replace")
            ).hexdigest()
            record["active_war_capture_text_bytes"] = len(
                text.encode("utf-8", "replace")
            )
        except war_parser.WarReaderError as exc:
            self.unknown.append(str(exc))
            return
        except Exception as exc:
            self.unknown.append(
                f"active_war_bounded_extract_failed_at_line_{current['line_start']}:"
                + type(exc).__name__
            )
            return
        if len(self.records) >= MAX_WAR_RECORDS:
            self.unknown.append("matching_active_war_record_limit_reached")
        else:
            self.records.append(record)


def scan_matching(path: Path, source: dict[str, Any], actor: str, recipient: str) -> dict[str, Any]:
    scanner = CaptureActiveWarScanner(actor, recipient)
    with bounded.open_gamestate(path, source) as stream:
        scanner.consume(stream)
    return {
        "actor": actor,
        "recipient": recipient,
        "line_count": scanner.line_count,
        "final_brace_depth": scanner.depth,
        "brace_balance_ok": scanner.depth == 0,
        "active_war_blocks_seen": scanner.blocks_seen,
        "matching_active_wars": scanner.records,
        "unknown": scanner.unknown,
    }


def record_summary(record: dict[str, Any]) -> dict[str, Any]:
    """Drop the old parser's raw excerpt while retaining bounded provenance."""

    return {
        "line_start": record.get("line_start"),
        "line_end": record.get("line_end"),
        "bytes_captured": record.get("bytes_captured"),
        "active_war_capture_text_bytes": record.get("active_war_capture_text_bytes"),
        "active_war_capture_sha256": record.get("active_war_capture_sha256"),
        "pair_currently_active": record.get("pair_currently_active"),
        "current_sides": record.get("current_sides"),
        "original_sides": record.get("original_sides"),
        "name": record.get("name"),
        "date_candidates": record.get("date_candidates"),
        "battle_history": record.get("battle_history"),
        "parser_unknown": record.get("parser_unknown"),
    }


def source_provenance(path: Path, before: dict[str, Any], sha: str) -> dict[str, Any]:
    source = bounded.detect_container(path)
    source.update({
        "sha256": sha,
        "expected_sha256": EXPECTED_SAVE_SHA256,
        "sha256_matches_expected": sha.casefold() == EXPECTED_SAVE_SHA256,
        "mtime_ns": before["mtime_ns"],
        "selection_mode": "streaming_plain_EU4txt_active_war_blocks",
    })
    return source


def ensure_save(path: Path) -> tuple[dict[str, Any], dict[str, Any], str]:
    resolved = path.expanduser().resolve()
    if not resolved.is_file():
        raise SaveCrosscheckError(f"save path is not a file: {resolved}")
    before = file_fingerprint(resolved)
    if before["size_bytes"] > MAX_INPUT_BYTES:
        raise SaveCrosscheckError(
            f"save exceeds bounded input limit: {before['size_bytes']} > {MAX_INPUT_BYTES}"
        )
    source = bounded.detect_container(resolved)
    if source.get("container") != "plain" or source.get("header") != EXPECTED_HEADER:
        raise SaveCrosscheckError(
            f"unsupported save container/header: {source.get('container')}/{source.get('header')}"
        )
    sha = sha256_file(resolved)
    if sha.casefold() != EXPECTED_SAVE_SHA256:
        raise SaveCrosscheckError(
            f"save SHA mismatch: expected {EXPECTED_SAVE_SHA256}, got {sha}"
        )
    return before, source, sha


def run_crosscheck(
    save_path: Path,
    output_path: Path,
    actor: str = "FRA",
    recipient: str = "ENG",
) -> dict[str, Any]:
    if TAG_RE.fullmatch(actor) is None or TAG_RE.fullmatch(recipient) is None:
        raise SaveCrosscheckError("actor/recipient must be uppercase save country tags")
    if actor == recipient:
        raise SaveCrosscheckError("actor and recipient must be distinct for a pair crosscheck")
    before, source_raw, save_sha = ensure_save(save_path)
    source = source_provenance(save_path.resolve(), before, save_sha)

    # The pair scan is the authoritative result.  Individual scans are kept as
    # bounded context only, so FRA/BUR and ENG/CNN are never joined as FRA/ENG.
    pair_scan = scan_matching(save_path, source, actor, recipient)
    actor_scan = scan_matching(save_path, source, actor, actor)
    recipient_scan = scan_matching(save_path, source, recipient, recipient)

    after = file_fingerprint(save_path.resolve())
    after_sha = sha256_file(save_path.resolve())
    hash_stable = (
        after == before
        and after_sha.casefold() == save_sha.casefold()
    )
    if not hash_stable:
        raise SaveCrosscheckError(
            "save changed during bounded scan; refusing to emit trusted comparison"
        )

    pair_records = pair_scan["matching_active_wars"]
    pair_battles = sum(
        int((item.get("battle_history") or {}).get("battle_count", 0))
        for item in pair_records
    )
    pair_status = "known_empty" if not pair_records else "known"
    pair_reason = (
        "no_active_war_contains_both_requested_country_tags"
        if not pair_records else None
    )
    individual = {}
    for tag, scan in ((actor, actor_scan), (recipient, recipient_scan)):
        individual[tag] = {
            "scope": "individual_membership_context_only",
            "matching_active_war_count": len(scan["matching_active_wars"]),
            "records": [record_summary(item) for item in scan["matching_active_wars"]],
            "unknown": scan["unknown"],
        }

    parser_sources = []
    for parser_path in (
        ROOT / "work" / "inspect_declare_war_save_pair.py",
        ROOT / "work" / "inspect_dissolve_save_pair.py",
    ):
        parser_sources.append({
            "path": str(parser_path.relative_to(ROOT)),
            "bytes": parser_path.stat().st_size,
            "sha256": sha256_file(parser_path),
        })

    report: dict[str, Any] = {
        "schema": "information_battle_war_save_crosscheck_v1",
        "status": "passed_static_save_crosscheck; pair_fra_eng_not_present" if pair_status == "known_empty" else "passed_static_save_crosscheck",
        "read_only": True,
        "native_query_called": False,
        "rea_called": False,
        "game_access": False,
        "production_changed": False,
        "goal_complete": False,
        "target": {
            "actor": actor,
            "recipient": recipient,
            "purpose": "independent recorded-save baseline for root's separate pure-RPM war-history reader",
            "native_or_catalog_fallback": False,
            "comparison_rule": "Do not combine individual war contexts into a FRA/ENG war; no matching active_war is an explicit empty result.",
        },
        "save": {
            "path": str(save_path.resolve()),
            "size_bytes": source["size_bytes"],
            "sha256": save_sha,
            "expected_sha256": EXPECTED_SAVE_SHA256,
            "sha256_matches_expected": True,
            "container": source["container"],
            "header": source["header"],
            "mtime_ns_before": before["mtime_ns"],
            "mtime_ns_after": after["mtime_ns"],
            "date": "1455.11.13",
            "player": "POR",
            "provenance": {
                "HANDOFF": {"path": "HANDOFF.md", "line_refs": [107, 139, 177, 454], "sha256": "9c7f3b46a0646f93cadb1fe27995aee50156a0cb84206c9768ee31217c1e99cd"},
                "automation_doc": {"path": "开发过程自动化.md", "line_refs": [222, 230], "sha256": "5e48f310757237a78b1890d70ff5dff1cfc6558696ad812ffa6f1037887ae6c1"},
            },
        },
        "streaming_guard": {
            "input_max_bytes": MAX_INPUT_BYTES,
            "active_war_capture_max_bytes": MAX_WAR_CAPTURE_BYTES,
            "battle_output_max_bytes": MAX_REPORT_BYTES,
            "max_battles_per_war": MAX_BATTLES_PER_WAR,
            "max_text_field_bytes": MAX_TEXT_BYTES,
            "hash_before_after_equal": hash_stable,
            "save_was_not_modified": hash_stable,
        },
        "parser_sources": parser_sources,
        "selection": {
            "parser": "work.inspect_declare_war_save_pair.ActiveWarScanner + parse_active_war_block",
            "scanner_extension": "CaptureActiveWarScanner adds only bounded history/battle extraction; old parser file unchanged",
            "save_scan": {
                "active_war_blocks_seen": pair_scan["active_war_blocks_seen"],
                "line_count": pair_scan["line_count"],
                "final_brace_depth": pair_scan["final_brace_depth"],
                "brace_balance_ok": pair_scan["brace_balance_ok"],
                "unknown": pair_scan["unknown"],
            },
            "battle_field_contract": [
                "history date key as saved",
                "battle name raw/decoded_text",
                "location raw",
                "attacker/defender country raw/decoded_text",
                "attacker/defender commander raw/decoded_text",
                "attacker/defender raw_quantity_fields (no scale/unit inference)",
                "active_war line/byte boundaries and capture SHA",
            ],
        },
        "pair_result": {
            "status": pair_status,
            "reason": pair_reason,
            "matching_active_war_count": len(pair_records),
            "battle_entry_count": pair_battles,
            "records": [record_summary(item) for item in pair_records],
            "unknown": pair_scan["unknown"],
        },
        "individual_membership_context": individual,
        "native_comparison": {
            "status": "not_run",
            "reason": "This artifact is an offline save baseline only; root's pure-RPM reader and current live process were not invoked or joined.",
            "expected_use": "Compare root reader's explicit FRA/ENG result and saved history fields; preserve unknown/absence if no native object can be joined.",
        },
        "important_boundaries": [
            "pair_result.known_empty means no serialized active_war block contained both FRA and ENG in this save; it is not evidence that the game has no historical FRA/ENG battle ever.",
            "individual FRA and ENG records are context-only and are not merged.",
            "battle quantities remain raw serialized values; no unit, scale, commander decoding, location-name lookup, or native semantics are inferred.",
            "This report is recorded mode and cannot promote W01/B01 fields or serve as a live/native fallback.",
        ],
    }
    encoded = json.dumps(report, ensure_ascii=False, indent=2).encode("utf-8")
    if len(encoded) > MAX_REPORT_BYTES:
        raise SaveCrosscheckError(
            f"report exceeds bounded output limit: {len(encoded)} > {MAX_REPORT_BYTES}"
        )
    output_path = output_path.resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if output_path.exists():
        raise SaveCrosscheckError(f"refusing to overwrite existing output: {output_path}")
    output_path.write_bytes(encoded + b"\n")
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--save", type=Path, default=DEFAULT_SAVE)
    parser.add_argument("--actor", default="FRA")
    parser.add_argument("--recipient", default="ENG")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args(argv)
    try:
        report = run_crosscheck(args.save, args.output, args.actor.upper(), args.recipient.upper())
    except (OSError, SaveCrosscheckError, ValueError) as exc:
        print(f"save-crosscheck failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({
        "status": report["status"],
        "output": str(args.output.resolve()),
        "save_sha256": report["save"]["sha256"],
        "pair_status": report["pair_result"]["status"],
        "matching_active_wars": report["pair_result"]["matching_active_war_count"],
        "pair_battles": report["pair_result"]["battle_entry_count"],
        "individual_context_counts": {
            key: value["matching_active_war_count"]
            for key, value in report["individual_membership_context"].items()
        },
    }, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
