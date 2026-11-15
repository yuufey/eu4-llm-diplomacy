"""Stream fixed R70 save fields directly under ``countries.FRA``.

This is a recorded-save survey.  It keeps the exact source literals and
location for the four requested domestic-pressure fields, while refusing to
interpret nested lookalikes as country fields.  It does not claim a current
live value, a native offset, a getter mapping, or a component scale.
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
from work.local_config import user_data  # noqa: E402
from work.verify_r71_favor_save import brace_delta  # noqa: E402


EXPECTED_SAVE_SHA256 = (
    "ffa91dbd2a2d544b18d586a895bb9b0c2b90e94ece47b2c74507555b8f58c2e0"
)
SAVE_NAME = "llm_diplomacy_r70_country_money_rejected_20261020.eu4"
MAX_LINE_BYTES = 1024 * 1024
MAX_BLOCK_BYTES = 128 * 1024
DIRECT_FIELDS = (
    "stability",
    "war_exhaustion",
    "corruption",
    "religious_unity",
)
OPTIONAL_CANDIDATES = ("overextension",)
TARGET_FIELDS = frozenset(DIRECT_FIELDS + OPTIONAL_CANDIDATES)
FIELD_RE = re.compile(
    rb"^[ \t]*([A-Za-z_][A-Za-z0-9_]*)[ \t]*=[ \t]*(.*?)[ \t]*$"
)
DATE_RE = re.compile(
    rb"^[ \t]*date[ \t]*=[ \t]*\"?([0-9]+\.[0-9]+\.[0-9]+)\"?[ \t]*$"
)


def _is_open(line: bytes, key: str) -> bool:
    return line.strip() == key.encode("ascii") + b"={"


def _body(line: bytes) -> bytes:
    if line.endswith(b"\r\n"):
        return line[:-2]
    if line.endswith((b"\n", b"\r")):
        return line[:-1]
    return line


def _display(line: bytes) -> str:
    return _body(line).decode("utf-8", errors="replace")


def _relative(path: Path) -> str:
    try:
        return path.relative_to(ROOT).as_posix()
    except ValueError:
        return str(path)


def _field_result(key: str, hits: list[dict[str, Any]], *, scope_closed: bool) -> dict[str, Any]:
    if not hits:
        return {
            "status": "missing",
            "field": key,
            "parent": "countries.FRA",
            "direct": True,
            "scope_closed": scope_closed,
            "hits": [],
            "reason": "no direct countries.FRA assignment",
        }
    status = "observed" if len(hits) == 1 else "ambiguous_duplicate"
    return {
        "status": status,
        "field": key,
        "parent": "countries.FRA",
        "direct": True,
        "scope_closed": scope_closed,
        "hits": hits,
        "reason": None if len(hits) == 1 else "multiple direct assignments",
    }


def scan_save(path: Path) -> dict[str, Any]:
    """Read the fixed save once with bounded line and I/O sizes."""

    if not path.is_file():
        raise FileNotFoundError(path)
    before_stat = path.stat()
    digest = hashlib.sha256()
    line_count = 0
    depth = 0
    first_line_ok = False
    root_dates: list[dict[str, Any]] = []

    countries_found = False
    countries_complete = False
    countries_depth: int | None = None
    countries_start_line: int | None = None
    countries_end_line: int | None = None
    fra_count = 0
    fra_complete = False
    fra_depth: int | None = None
    fra_start_line: int | None = None
    fra_end_line: int | None = None
    hits: dict[str, list[dict[str, Any]]] = {
        field: [] for field in TARGET_FIELDS
    }
    nested_lookalikes_ignored: list[dict[str, Any]] = []
    structural_errors: list[str] = []

    with path.open("rb", buffering=MAX_BLOCK_BYTES) as stream:
        for line_number, line in enumerate(stream, 1):
            line_count = line_number
            if len(line) > MAX_LINE_BYTES:
                raise ValueError(
                    f"save line exceeds {MAX_LINE_BYTES} bytes at line {line_number}"
                )
            digest.update(line)
            before_depth = depth
            stripped = line.strip()
            if line_number == 1:
                first_line_ok = stripped == b"EU4txt"
                if not first_line_ok:
                    raise ValueError("expected EU4txt save header")

            if before_depth == 0:
                date_match = DATE_RE.fullmatch(stripped)
                if date_match:
                    root_dates.append(
                        {"line": line_number, "date": date_match.group(1).decode("ascii")}
                    )

            if not countries_found and before_depth == 0 and _is_open(line, "countries"):
                countries_found = True
                countries_start_line = line_number
                countries_depth = before_depth + brace_delta(line)
            elif (
                countries_found
                and not countries_complete
                and fra_depth is None
                and countries_depth is not None
                and before_depth == countries_depth
                and _is_open(line, "FRA")
            ):
                fra_count += 1
                if fra_count > 1:
                    structural_errors.append("duplicate direct countries.FRA block")
                else:
                    fra_start_line = line_number
                    fra_depth = before_depth + brace_delta(line)

            match = FIELD_RE.fullmatch(_body(line))
            key = match.group(1).decode("ascii") if match else None
            if key in TARGET_FIELDS and fra_depth is not None:
                if before_depth == fra_depth:
                    hits[key].append(
                        {
                            "line": line_number,
                            "parent": "countries.FRA",
                            "parent_depth": fra_depth,
                            "direct": True,
                            "scope_closed": None,
                            "raw_value": match.group(2).decode(
                                "utf-8", errors="replace"
                            ),
                            "source": _display(line),
                            "line_bytes": len(line),
                        }
                    )
                elif before_depth > fra_depth:
                    # Keep a bounded audit of lookalikes that were deliberately
                    # excluded, without treating them as direct country data.
                    if len(nested_lookalikes_ignored) < 64:
                        nested_lookalikes_ignored.append(
                            {
                                "field": key,
                                "line": line_number,
                                "depth": before_depth,
                                "parent": "countries.FRA",
                                "direct": False,
                                "source": _display(line),
                            }
                        )

            next_depth = depth + brace_delta(line)
            if next_depth < 0:
                raise ValueError(f"negative save brace depth at line {line_number}")

            if fra_depth is not None and next_depth < fra_depth:
                fra_complete = True
                fra_end_line = line_number
                fra_depth = None
            if countries_depth is not None and next_depth < countries_depth:
                countries_complete = True
                countries_end_line = line_number
                countries_depth = None
            depth = next_depth

    after_stat = path.stat()
    if (before_stat.st_size, before_stat.st_mtime_ns) != (
        after_stat.st_size,
        after_stat.st_mtime_ns,
    ):
        raise ValueError("save changed during streaming scan")
    if not first_line_ok or depth != 0:
        raise ValueError("save header or final brace depth invalid")
    if len(root_dates) != 1:
        raise ValueError(f"expected exactly one root date, found {len(root_dates)}")
    if not countries_found or not countries_complete:
        raise ValueError("top-level countries block missing or incomplete")
    if fra_count != 1 or not fra_complete:
        raise ValueError("direct countries.FRA block missing or incomplete")
    if structural_errors:
        raise ValueError("; ".join(structural_errors))
    if digest.hexdigest() != EXPECTED_SAVE_SHA256:
        raise ValueError(
            f"historical save SHA mismatch: {digest.hexdigest()}"
        )

    for field_hits in hits.values():
        for hit in field_hits:
            hit["scope_closed"] = fra_complete

    direct_fields = {
        field: _field_result(field, hits[field], scope_closed=fra_complete)
        for field in DIRECT_FIELDS
    }
    optional_candidates = {
        field: _field_result(field, hits[field], scope_closed=fra_complete)
        for field in OPTIONAL_CANDIDATES
    }
    minimum_result: dict[str, Any] = {}
    for field, result in direct_fields.items():
        if result["status"] == "observed":
            hit = result["hits"][0]
            minimum_result[field] = {
                "status": "observed",
                "raw_value": hit["raw_value"],
                "line": hit["line"],
            }
        else:
            minimum_result[field] = {
                "status": result["status"],
                "raw_value": None,
                "line": None,
            }

    return {
        "schema": "information_domestic_pressure_save_scalars_survey_v1",
        "status": "passed",
        "source": {
            "path": _relative(path),
            "sha256": digest.hexdigest(),
            "bytes": after_stat.st_size,
            "save_name": path.name,
            "expected_sha256": EXPECTED_SAVE_SHA256,
        },
        "date": root_dates[0],
        "minimum_result": minimum_result,
        "direct_fields": direct_fields,
        "optional_candidates": optional_candidates,
        "scope": {
            "countries": {
                "parent": "root",
                "depth": 1,
                "start_line": countries_start_line,
                "end_line": countries_end_line,
                "direct": True,
                "complete": countries_complete,
            },
            "country": {
                "parent": "countries",
                "tag": "FRA",
                "depth": 2,
                "start_line": fra_start_line,
                "end_line": fra_end_line,
                "direct": True,
                "complete": fra_complete,
            },
        },
        "nested_lookalikes_ignored": nested_lookalikes_ignored,
        "streaming": {
            "single_pass": True,
            "read_bytes_used": False,
            "max_line_bytes": MAX_LINE_BYTES,
            "io_buffer_bytes": MAX_BLOCK_BYTES,
            "line_count": line_count,
        },
        "evidence_kind": "recorded_save_streaming_direct_country_scope",
        "save_is_recorded": True,
        "not_a_live_state_fallback": True,
        "world_generation_verified": False,
        "component_order_verified": False,
        "unresolved": [
            "The decimal literals are retained verbatim; no unit or scale is assigned.",
            "A recorded save does not prove the current live state or process identity.",
            "No native offset, getter mapping, or runtime visibility follows from this scan.",
            "Nested lookalike names are excluded from the direct countries.FRA result.",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--save",
        type=Path,
        default=user_data() / "save games" / SAVE_NAME,
        help="fixed historical save path (defaults to the R70 save)",
    )
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise ValueError(f"refusing to overwrite existing report: {args.output}")

    report = scan_save(args.save.resolve())
    report["script"] = {
        "path": _relative(Path(__file__).resolve()),
        "sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(
        json.dumps(
            {
                "status": report["status"],
                "save_sha256": report["source"]["sha256"],
                "date": report["date"]["date"],
                "minimum_result": report["minimum_result"],
                "output": str(args.output),
            },
            ensure_ascii=False,
        )
    )


if __name__ == "__main__":
    main()
