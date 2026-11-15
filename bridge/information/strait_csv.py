"""Bounded parsers for EU4 province definitions and static adjacencies.

The module consumes caller-supplied bytes only. It does not choose source
files, resolve mod overrides, or grant runtime visibility or movement access.
"""
from __future__ import annotations

import csv
import io
import re
from typing import Iterator


MAX_INPUT_BYTES = 4 * 1024 * 1024
MAX_DEFINITION_ROWS = 65_536
MAX_ADJACENCY_ROWS = 20_000
MAX_LINE_CHARS = 8_192
MAX_FIELD_CHARS = 4_096
MAX_COLUMNS = 64

_UTF8_BOM = b"\xef\xbb\xbf"
_DEFINITION_HEADER = "province"
_ADJACENCY_HEADER = (
    "from", "to", "type", "through", "start_x", "start_y", "stop_x", "stop_y", "comment",
)
_ADJACENCY_TYPES = frozenset({"sea", "canal", "lake", "river", "impassable"})
_INTEGER = re.compile(r"[0-9]+\Z", re.ASCII)
_SIGNED_INTEGER = re.compile(r"-?[0-9]+\Z", re.ASCII)


class _CSVLineSource:
    """Filter blank/comment lines while keeping original physical line IDs."""

    def __init__(self, text: str):
        self._stream = io.StringIO(text, newline="")
        self.physical_lines: list[int] = []
        self.blank_lines = 0
        self.comment_lines = 0

    def __iter__(self) -> Iterator[str]:
        for line_number, line in enumerate(self._stream, 1):
            body = line.rstrip("\r\n")
            if len(body) > MAX_LINE_CHARS:
                raise ValueError(f"CSV_LINE_TOO_LONG:{line_number}")
            stripped = body.lstrip(" \t\v\f")
            if not stripped:
                self.blank_lines += 1
                continue
            if stripped.startswith("#"):
                self.comment_lines += 1
                continue
            self.physical_lines.append(line_number)
            yield line


def _decode_bounded(raw: bytes) -> tuple[str, str]:
    if not isinstance(raw, bytes):
        raise ValueError("CSV_INPUT_MUST_BE_BYTES")
    if not raw or len(raw) > MAX_INPUT_BYTES:
        raise ValueError("CSV_INPUT_SIZE_OUT_OF_RANGE")
    has_bom = raw.startswith(_UTF8_BOM)
    try:
        return raw.decode("utf-8-sig" if has_bom else "utf-8", errors="strict"), (
            "utf-8-sig" if has_bom else "utf-8"
        )
    except UnicodeDecodeError:
        fallback_bytes = raw[len(_UTF8_BOM):] if has_bom else raw
        try:
            return fallback_bytes.decode("cp1252", errors="strict"), (
                "cp1252-after-utf8-bom" if has_bom else "cp1252"
            )
        except UnicodeDecodeError as exc:
            raise ValueError("CSV_ENCODING_UNSUPPORTED") from exc


def _csv_records(text: str, *, max_rows: int, label: str) -> tuple[list[tuple[int, list[str]]], _CSVLineSource]:
    source = _CSVLineSource(text)
    reader = csv.reader(source, delimiter=";", strict=True)
    result: list[tuple[int, list[str]]] = []
    consumed_lines = 0
    try:
        for row in reader:
            new_consumed = reader.line_num
            physical = source.physical_lines[consumed_lines:new_consumed]
            consumed_lines = new_consumed
            if len(physical) != 1:
                raise ValueError(f"{label}_MULTILINE_RECORD_UNSUPPORTED")
            if not row or all(not value.strip() for value in row):
                continue
            if len(row) > MAX_COLUMNS:
                raise ValueError(f"{label}_TOO_MANY_COLUMNS:{physical[0]}")
            if any(len(value) > MAX_FIELD_CHARS for value in row):
                raise ValueError(f"{label}_FIELD_TOO_LONG:{physical[0]}")
            result.append((physical[0], row))
            if len(result) > max_rows:
                raise ValueError(f"{label}_ROW_LIMIT_EXCEEDED")
    except csv.Error as exc:
        line = source.physical_lines[min(reader.line_num - 1, len(source.physical_lines) - 1)] if source.physical_lines else 0
        raise ValueError(f"{label}_CSV_SYNTAX_ERROR:{line}") from exc
    return result, source


def _normalized_header(row: list[str]) -> tuple[str, ...]:
    return tuple(cell.strip().casefold() for cell in row)


def _parse_decimal(value: str, *, label: str, line: int, allow_minus_one: bool = False) -> int:
    text = value.strip()
    if allow_minus_one and text == "-1":
        return -1
    if not _INTEGER.fullmatch(text):
        raise ValueError(f"{label}_INVALID_INTEGER:{line}")
    number = int(text, 10)
    if number > 0x7FFFFFFF:
        raise ValueError(f"{label}_INTEGER_OUT_OF_RANGE:{line}")
    return number


def parse_definition_ids(raw: bytes) -> set[int]:
    """Return unique positive province IDs from a bounded definition.csv.

    The first column must be the `province` ID column. Row payload columns are
    ignored after basic CSV length checks. A single province ID 0 is accepted
    as the map's sentinel and omitted from the returned set.
    """
    text, _encoding = _decode_bounded(raw)
    records, _source = _csv_records(text, max_rows=MAX_DEFINITION_ROWS, label="DEFINITION")
    if not records:
        raise ValueError("DEFINITION_HEADER_MISSING")
    header_line, header = records[0]
    if not header or header[0].strip().casefold() != _DEFINITION_HEADER:
        raise ValueError(f"DEFINITION_ID_HEADER_INVALID:{header_line}")

    seen: set[int] = set()
    ids: set[int] = set()
    for line, row in records[1:]:
        if not row:
            raise ValueError(f"DEFINITION_ROW_EMPTY:{line}")
        province_id = _parse_decimal(row[0], label="DEFINITION_ID", line=line)
        if province_id in seen:
            raise ValueError(f"DEFINITION_ID_DUPLICATE:{line}:{province_id}")
        seen.add(province_id)
        if province_id != 0:
            ids.add(province_id)
    if not ids:
        raise ValueError("DEFINITION_HAS_NO_POSITIVE_IDS")
    return ids


def _is_actual_sentinel(row: list[str]) -> bool:
    cells = [cell.strip() for cell in row]
    return cells == ["-1", "-1", "", "-1", "-1", "-1", "-1", "-1", "-1", ""]


def _validate_id_set(valid_ids: set[int]) -> None:
    if type(valid_ids) is not set or any(type(value) is not int or value <= 0 for value in valid_ids):
        raise ValueError("ADJACENCY_VALID_IDS_INVALID")


def parse_adjacencies(raw: bytes, valid_ids: set[int]) -> dict:
    """Parse sea edges and row statistics from bounded adjacencies.csv bytes.

    Sea edges are deduplicated by unordered endpoint pair while preserving the
    first record's From/To order. Identical duplicate Through values merge
    their source lines; conflicting values fail closed. Other known adjacency
    kinds are validated and counted but omitted from `edges`.
    """
    _validate_id_set(valid_ids)
    text, encoding = _decode_bounded(raw)
    records, source = _csv_records(text, max_rows=MAX_ADJACENCY_ROWS, label="ADJACENCY")
    if not records:
        raise ValueError("ADJACENCY_HEADER_MISSING")
    header_line, header = records[0]
    if _normalized_header(header) != _ADJACENCY_HEADER:
        raise ValueError(f"ADJACENCY_HEADER_INVALID:{header_line}")

    edges: list[dict] = []
    edge_index: dict[tuple[int, int], dict] = {}
    type_counts = {kind: 0 for kind in sorted(_ADJACENCY_TYPES)}
    ordinary_rows = 0
    sentinel_rows = 0
    sea_source_rows = 0
    duplicate_sea_rows = 0
    sentinel_seen = False

    for line, row in records[1:]:
        if sentinel_seen:
            raise ValueError(f"ADJACENCY_ROW_AFTER_SENTINEL:{line}")
        if len(row) == 10 and _is_actual_sentinel(row):
            sentinel_seen = True
            sentinel_rows += 1
            continue
        if len(row) != 9:
            raise ValueError(f"ADJACENCY_ROW_WIDTH_INVALID:{line}")
        ordinary_rows += 1
        if not (ordinary_rows <= MAX_ADJACENCY_ROWS):
            raise ValueError("ADJACENCY_ROW_LIMIT_EXCEEDED")

        from_id = _parse_decimal(row[0], label="ADJACENCY_FROM", line=line)
        to_id = _parse_decimal(row[1], label="ADJACENCY_TO", line=line)
        through_id = _parse_decimal(row[3], label="ADJACENCY_THROUGH", line=line, allow_minus_one=True)
        kind = row[2].strip().casefold()
        if kind not in _ADJACENCY_TYPES:
            raise ValueError(f"ADJACENCY_TYPE_UNKNOWN:{line}")
        if from_id <= 0 or to_id <= 0:
            raise ValueError(f"ADJACENCY_ENDPOINT_NOT_POSITIVE:{line}")
        if from_id not in valid_ids or to_id not in valid_ids:
            raise ValueError(f"ADJACENCY_ENDPOINT_NOT_IN_DEFINITION:{line}")
        if through_id != -1 and (through_id <= 0 or through_id not in valid_ids):
            raise ValueError(f"ADJACENCY_THROUGH_NOT_IN_DEFINITION:{line}")

        type_counts[kind] += 1
        if kind != "sea":
            continue

        sea_source_rows += 1
        through = None if through_id == -1 else through_id
        key = (min(from_id, to_id), max(from_id, to_id))
        existing = edge_index.get(key)
        if existing is None:
            edge = {"from_province": from_id, "to_province": to_id,
                    "through_province": through, "source_lines": [line]}
            edge_index[key] = edge
            edges.append(edge)
        elif existing["through_province"] != through:
            raise ValueError(f"ADJACENCY_SEA_THROUGH_CONFLICT:{line}")
        else:
            existing["source_lines"].append(line)
            duplicate_sea_rows += 1

    statistics = {
        "header_rows": 1,
        "ordinary_rows": ordinary_rows,
        "sentinel_rows": sentinel_rows,
        "total_data_rows": ordinary_rows + sentinel_rows,
        "type_counts": type_counts,
        "sea_source_rows": sea_source_rows,
        "unique_sea_edges": len(edges),
        "duplicate_sea_rows_merged": duplicate_sea_rows,
        "blank_lines_skipped": source.blank_lines,
        "comment_lines_skipped": source.comment_lines,
    }
    return {"edges": edges, "statistics": statistics, "encoding": encoding}


__all__ = ["parse_definition_ids", "parse_adjacencies"]
