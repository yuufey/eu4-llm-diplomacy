"""Stream the fixed R70 save's direct ``countries.FRA.powers`` vector.

The result is recorded-save evidence only.  It preserves the three integers
in source order and deliberately does not assign ADM/DIP/MIL meanings to the
positions.  The parser follows only the top-level ``countries`` block and its
direct ``FRA`` child; nested ``ai.powers`` and unrelated historical blocks are
ignored.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from work.local_config import user_data  # noqa: E402
from work.verify_r71_favor_save import brace_delta  # noqa: E402


EXPECTED_SAVE_SHA256 = (
    "ffa91dbd2a2d544b18d586a895bb9b0c2b90e94ece47b2c74507555b8f58c2e0"
)
SAVE_NAME = "llm_diplomacy_r70_country_money_rejected_20261020.eu4"
MAX_LINE_BYTES = 1024 * 1024
VECTOR_RE = re.compile(
    rb"^[ \t]*([-+]?\d+)[ \t]+([-+]?\d+)[ \t]+([-+]?\d+)[ \t]*$"
)
DATE_RE = re.compile(rb"^[ \t]*date\s*=\s*\"?(\d+\.\d+\.\d+)\"?[ \t]*$")


def _is_open(line: bytes, key: str) -> bool:
    return line.strip() == key.encode("ascii") + b"={"


def _display(line: bytes) -> str:
    return line.rstrip(b"\r\n").decode("utf-8", errors="replace")


def _relative(path: Path) -> str:
    try:
        return path.relative_to(ROOT).as_posix()
    except ValueError:
        return str(path)


def scan_save(path: Path) -> dict[str, object]:
    """Scan one save in one streaming pass with exact parent-depth checks."""
    if not path.is_file():
        raise FileNotFoundError(path)
    before = path.stat()
    depth = 0
    line_count = 0
    source_size = 0
    digest = hashlib.sha256()
    first_line_ok = False
    root_dates: list[dict[str, object]] = []
    countries_found = False
    countries_complete = False
    countries_depth: int | None = None
    countries_start_line: int | None = None
    countries_end_line: int | None = None
    fra_count = 0
    country_depth: int | None = None
    country_start_line: int | None = None
    country_end_line: int | None = None
    country_complete = False
    powers_count = 0
    powers_depth: int | None = None
    powers_start_line: int | None = None
    powers_end_line: int | None = None
    powers_complete = False
    vectors: list[dict[str, object]] = []
    powers_other_direct_lines: list[dict[str, object]] = []

    with path.open("rb", buffering=1024 * 1024) as stream:
        for line_number, line in enumerate(stream, 1):
            line_count = line_number
            if len(line) > MAX_LINE_BYTES:
                raise ValueError(f"save line exceeds {MAX_LINE_BYTES} bytes at line {line_number}")
            source_size += len(line)
            digest.update(line)
            stripped = line.strip()
            before_depth = depth

            if line_number == 1:
                first_line_ok = stripped == b"EU4txt"
                if not first_line_ok:
                    raise ValueError("expected EU4txt save header")

            if before_depth == 0:
                match = DATE_RE.fullmatch(stripped)
                if match:
                    root_dates.append(
                        {"line": line_number, "date": match.group(1).decode("ascii")}
                    )

            if not countries_found and before_depth == 0 and _is_open(line, "countries"):
                countries_found = True
                countries_start_line = line_number
                countries_depth = before_depth + brace_delta(line)
            elif countries_found and not countries_complete:
                if (
                    country_depth is None
                    and countries_depth is not None
                    and before_depth == countries_depth
                    and _is_open(line, "FRA")
                ):
                    fra_count += 1
                    if fra_count > 1:
                        raise ValueError("duplicate direct countries.FRA block")
                    country_start_line = line_number
                    country_depth = before_depth + brace_delta(line)

            if country_depth is not None and not country_complete:
                if before_depth == country_depth and _is_open(line, "powers"):
                    powers_count += 1
                    if powers_count > 1:
                        raise ValueError("duplicate direct countries.FRA.powers block")
                    powers_start_line = line_number
                    powers_depth = before_depth + brace_delta(line)
                elif powers_depth is not None and before_depth == powers_depth:
                    if stripped != b"}":
                        match = VECTOR_RE.fullmatch(stripped)
                        if match:
                            vectors.append(
                                {
                                    "line": line_number,
                                    "ordered_vector": [
                                        int(match.group(1)),
                                        int(match.group(2)),
                                        int(match.group(3)),
                                    ],
                                    "source": _display(line),
                                }
                            )
                        else:
                            powers_other_direct_lines.append(
                                {"line": line_number, "source": _display(line)}
                            )

            next_depth = depth + brace_delta(line)
            if next_depth < 0:
                raise ValueError(f"negative save brace depth at line {line_number}")

            if powers_depth is not None and next_depth < powers_depth:
                powers_complete = True
                powers_end_line = line_number
                powers_depth = None
            if country_depth is not None and next_depth < country_depth:
                country_complete = True
                country_end_line = line_number
                country_depth = None
            if countries_depth is not None and next_depth < countries_depth:
                countries_complete = True
                countries_end_line = line_number
                countries_depth = None
            depth = next_depth

    after = path.stat()
    if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        raise ValueError("save changed during streaming scan")
    if not first_line_ok or depth != 0:
        raise ValueError("save header or final brace depth invalid")
    if len(root_dates) != 1:
        raise ValueError(f"expected exactly one root date, found {len(root_dates)}")
    if not countries_found or not countries_complete:
        raise ValueError("top-level countries block missing or incomplete")
    if fra_count != 1 or not country_complete:
        raise ValueError("direct countries.FRA block missing or incomplete")
    if powers_count != 1 or not powers_complete:
        raise ValueError("direct countries.FRA.powers block missing or incomplete")
    if len(vectors) != 1 or powers_other_direct_lines:
        raise ValueError(
            "direct powers block did not contain exactly one three-integer vector"
        )
    if digest.hexdigest() != EXPECTED_SAVE_SHA256:
        raise ValueError(f"historical save SHA mismatch: {digest.hexdigest()}")

    return {
        "sha256": digest.hexdigest(),
        "source_sha256": digest.hexdigest(),
        "bytes": after.st_size,
        "path": _relative(path),
        "date": root_dates[0],
        "scope": {
            "countries": {
                "start_line": countries_start_line,
                "end_line": countries_end_line,
                "depth": 1,
                "parent": "root",
                "direct": True,
                "complete": countries_complete,
            },
            "country": {
                "tag": "FRA",
                "start_line": country_start_line,
                "end_line": country_end_line,
                "depth": 2,
                "parent": "countries",
                "direct": True,
                "complete": country_complete,
            },
            "powers": {
                "start_line": powers_start_line,
                "end_line": powers_end_line,
                "depth": 3,
                "parent": "countries.FRA",
                "direct": True,
                "complete": powers_complete,
            },
        },
        "powers": vectors[0],
        "component_order_verified": False,
        "evidence_kind": "recorded_save_streaming_not_live_state",
        "save_is_recorded": True,
        "not_a_live_state_fallback": True,
        "world_generation_verified": False,
        "streaming": {
            "line_count": line_count,
            "max_line_bytes": MAX_LINE_BYTES,
            "single_pass": True,
            "read_bytes_used": False,
        },
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
    script_sha256 = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    report = scan_save(args.save.resolve())
    report.update(
        {
            "schema": "information_country_powers_save_crosscheck_v1",
            "script": {
                "path": _relative(Path(__file__).resolve()),
                "sha256": script_sha256,
            },
            "expected_save_sha256": EXPECTED_SAVE_SHA256,
            "unresolved": [
                "The three source-order integers are not assigned to ADM, DIP, or MIL.",
                "A recorded save does not prove the current live state or process identity.",
                "No getter, unit scale, or runtime visibility follows from this save-only scan.",
            ],
        }
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(
        json.dumps(
            {
                "status": "passed",
                "save_sha256": report["sha256"],
                "date": report["date"]["date"],
                "ordered_vector": report["powers"]["ordered_vector"],
                "output": str(args.output),
            },
            ensure_ascii=False,
        )
    )


if __name__ == "__main__":
    main()
