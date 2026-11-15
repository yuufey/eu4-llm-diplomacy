"""Offline comparison for the batch57 B01 war-id production evidence.

The helper is inert unless ``--run`` is supplied.  It reads one already
captured SQLite payload, manually decodes its v5 WARI suffix, and compares
only ``B01.war_id`` with the original public query and the saved shared
peace-registry cross-check.  It never starts a process, calls an adapter,
backfills a producer result, or claims that B01-B04 are complete.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sqlite3
import struct
from typing import Any, Mapping


ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / "work/runtime/information-battle-war-identity-20261027-001"
DEFAULT_DATABASE = STAGE / "battle-raw-002.sqlite"
DEFAULT_INGEST = STAGE / "raw-ingest-002.json"
DEFAULT_QUERY = STAGE / "live-acceptance-003/query.json"
DEFAULT_REGISTRY = STAGE / "live-acceptance-003/peace-context-crosscheck.json"
DEFAULT_OUTPUT = STAGE / "production-comparison-001.json"
MAX_JSON_BYTES = 16 * 1024 * 1024
MAX_PAYLOAD_BYTES = 512 * 1024
MAX_ROWS = 512
WARI = b"WARI"
WAR_ID_RE = re.compile(rb"war_[0-9a-f]{16}_[0-9a-f]{8}\Z")


def _sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _pin(path: Path) -> dict[str, Any]:
    path = path.resolve(strict=True)
    return {"path": path.relative_to(ROOT).as_posix(), "bytes": path.stat().st_size, "sha256": _sha(path)}


def _json(path: Path, *, limit: int = MAX_JSON_BYTES) -> Any:
    path = path.resolve(strict=True)
    if path.stat().st_size <= 0 or path.stat().st_size > limit:
        raise ValueError(f"json_size_out_of_bound:{path}")
    with path.open("r", encoding="utf-8-sig") as stream:
        return json.load(stream)


def _write_exclusive(path: Path, value: Any) -> None:
    path = path.resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2, sort_keys=True)
        stream.write("\n")


def _raw_row(database: Path, sequence: str) -> dict[str, Any]:
    database = database.resolve(strict=True)
    uri = database.as_uri() + "?mode=ro"
    connection = sqlite3.connect(uri, uri=True)
    try:
        connection.execute("PRAGMA query_only=ON")
        row = connection.execute(
            "SELECT g.installation, g.world_generation, g.message_id, c.payload, c.payload_sha256, c.total_bytes "
            "FROM complete_messages AS c JOIN fragment_groups AS g ON g.group_id=c.group_id "
            "WHERE g.message_id=? AND g.status='complete' LIMIT 1",
            (str(sequence),),
        ).fetchone()
    finally:
        connection.close()
    if row is None:
        raise ValueError(f"raw_record_missing:{sequence}")
    payload = bytes(row[3])
    actual_sha = hashlib.sha256(payload).hexdigest()
    if str(row[4]) != actual_sha or int(row[5]) != len(payload):
        raise ValueError("raw_record_payload_pin_mismatch")
    return {
        "installation": str(row[0]),
        "world_generation": str(row[1]),
        "attempt_sequence": str(row[2]),
        "payload": payload,
        "payload_sha256": actual_sha,
        "payload_bytes": len(payload),
    }


def _parse_wari(payload: bytes) -> dict[str, Any]:
    """Decode only the bounded IBOW v5/WARI framing needed for B01."""
    if len(payload) < 14 or len(payload) > MAX_PAYLOAD_BYTES:
        raise ValueError("payload_size_out_of_bound")
    if payload[:4] != b"IBOW" or struct.unpack_from("<H", payload, 4)[0] != 5:
        raise ValueError("not_v5_payload")
    base_bytes = struct.unpack_from("<I", payload, 6)[0]
    base_end = 10 + base_bytes
    if base_bytes <= 0 or base_end + 4 > len(payload) or payload[base_end:base_end + 4] != WARI:
        raise ValueError("wari_extension_missing")
    cursor = base_end + 4
    fixed_bytes = 1 + 1 + 4 + 8 + 4 + 8 + 8 + 1
    if cursor + fixed_bytes > len(payload):
        raise ValueError("wari_header_truncated")
    status_code, reason, flags = struct.unpack_from("<BBI", payload, cursor)
    cursor += 6
    creation_filetime = struct.unpack_from("<Q", payload, cursor)[0]
    cursor += 8
    raw_date = struct.unpack_from("<i", payload, cursor)[0]
    cursor += 4
    pair_full_refs = list(struct.unpack_from("<QQ", payload, cursor))
    cursor += 16
    id_length = payload[cursor]
    cursor += 1
    if id_length > 29 or cursor + id_length != len(payload):
        raise ValueError("wari_id_length_invalid")
    id_bytes = payload[cursor:cursor + id_length]
    war_id: str | None = None
    if status_code == 1:
        if reason != 0 or flags != 63 or creation_filetime == 0 or id_length != 29:
            raise ValueError("wari_bound_guard_invalid")
        if not WAR_ID_RE.fullmatch(id_bytes):
            raise ValueError("wari_bound_id_invalid")
        war_id = id_bytes.decode("ascii")
    elif status_code == 2:
        if id_bytes:
            raise ValueError("wari_invalid_record_has_id")
    elif status_code != 0 or id_bytes:
        raise ValueError("wari_status_invalid")
    return {
        "status_code": status_code,
        "status": {0: "absent", 1: "bound", 2: "invalid"}.get(status_code, "unknown"),
        "reason": reason,
        "binding_flags": flags,
        "creation_filetime": creation_filetime,
        "raw_date": raw_date,
        "pair_full_refs": [f"{value:016x}" for value in pair_full_refs],
        "war_id": war_id,
        "base_v4_bytes": base_bytes,
        "wari_bytes": len(payload) - base_end,
    }


def _query_war_id(query: Mapping[str, Any]) -> tuple[str, dict[str, Any], Mapping[str, Any]]:
    items = query.get("items")
    if not isinstance(items, list):
        raise ValueError("public_query_items_missing")
    matches: list[tuple[str, dict[str, Any], Mapping[str, Any]]] = []
    for item in items:
        if not isinstance(item, Mapping):
            continue
        query_meta = item.get("query")
        topic = query_meta.get("topic") if isinstance(query_meta, Mapping) else None
        if topic != "B01":
            continue
        fields = item.get("fields")
        field = fields.get("war_id") if isinstance(fields, Mapping) else None
        if not isinstance(field, Mapping) or field.get("status") != "known" or not isinstance(field.get("value"), str):
            raise ValueError("public_query_b01_war_id_not_known")
        matches.append((field["value"], dict(item), query_meta))
    if len(matches) != 1:
        raise ValueError("public_query_b01_item_not_unique")
    value, item, query_meta = matches[0]
    if WAR_ID_RE.fullmatch(value.encode("ascii", errors="strict")) is None:
        raise ValueError("public_query_b01_war_id_format_invalid")
    return value, item, query_meta


def _registry_war_id(registry: Mapping[str, Any]) -> str:
    if registry.get("status") != "matched":
        raise ValueError("shared_registry_not_matched")
    value = registry.get("war_id")
    expected = registry.get("expected_war_id")
    current = registry.get("current_war_ids")
    if not isinstance(value, str) or value != expected or not isinstance(current, list) or value not in current:
        raise ValueError("shared_registry_war_id_invalid")
    if WAR_ID_RE.fullmatch(value.encode("ascii", errors="strict")) is None:
        raise ValueError("shared_registry_war_id_format_invalid")
    return value


def run(args: argparse.Namespace) -> int:
    if args.output.exists():
        raise FileExistsError(args.output)
    raw = _raw_row(args.database, args.sequence)
    wari = _parse_wari(raw["payload"])
    query = _json(args.query)
    registry = _json(args.registry)
    query_war_id, query_item, query_meta = _query_war_id(query)
    registry_war_id = _registry_war_id(registry)
    ingest = _json(args.ingest)
    messages = ingest.get("messages") if isinstance(ingest, Mapping) else None
    if not isinstance(messages, list) or len(messages) > MAX_ROWS:
        raise ValueError("raw_ingest_messages_invalid")
    completeness = ingest.get("completeness") if isinstance(ingest, Mapping) else None
    public_identity = completeness.get("public_identity") if isinstance(completeness, Mapping) else None
    bound_count = public_identity.get("v5_bound_count") if isinstance(public_identity, Mapping) else None
    invalid_count = public_identity.get("v5_invalid_count") if isinstance(public_identity, Mapping) else None
    checks = {
        "raw_sequence_9_wari_bound": raw["attempt_sequence"] == str(args.sequence) and wari["status"] == "bound",
        "raw_wari_matches_original_b01_query": wari["war_id"] == query_war_id,
        "raw_wari_matches_shared_registry": wari["war_id"] == registry_war_id,
        "query_and_registry_match": query_war_id == registry_war_id,
        "raw_ingest_has_twenty_records": len(messages) == 20,
        "raw_ingest_bound_invalid_counts": bound_count == 14 and invalid_count == 6,
    }
    receipt = {
        "schema": "information_battle_war_identity_production_comparison.v1",
        "status": "passed" if all(checks.values()) else "failed",
        "scope": {
            "fields": ["B01.war_id"],
            "shared_registry": "current_war_id_crosscheck",
            "identity_scope": "observer_session",
            "full_B01_B04_claimed": False,
        },
        "checks": checks,
        "raw_record": {
            "sequence": raw["attempt_sequence"],
            "installation": raw["installation"],
            "world_generation": raw["world_generation"],
            "payload": {"bytes": raw["payload_bytes"], "sha256": raw["payload_sha256"]},
            "manual_wari": wari,
        },
        "public_query": {
            "request_id": query.get("request_id"),
            "topic": query_meta.get("topic"),
            "war_id": query_war_id,
            "item_complete": query_item.get("complete"),
        },
        "shared_registry": {
            "status": registry.get("status"),
            "actor": registry.get("actor"),
            "recipient": registry.get("recipient"),
            "war_id": registry_war_id,
            "identity_scope": registry.get("identity_scope"),
        },
        "identity": {
            "session_id": (query.get("context") or {}).get("session_id") if isinstance(query.get("context"), Mapping) else None,
            "game_date": (query.get("context") or {}).get("game_date") if isinstance(query.get("context"), Mapping) else None,
            "game_sha256": (query.get("context") or {}).get("game_sha256") if isinstance(query.get("context"), Mapping) else None,
            "exe_dll_sha256": (query.get("context") or {}).get("dll_sha256") if isinstance(query.get("context"), Mapping) else None,
        },
        "read_only": True,
        "native_game_calls": False,
        "target_memory_writes": False,
        "offline_replay": True,
        "producer_backfill": False,
        "source_pins": {
            "database": _pin(args.database),
            "ingest": _pin(args.ingest),
            "original_public_query": _pin(args.query),
            "shared_registry_crosscheck": _pin(args.registry),
            "helper": _pin(Path(__file__).resolve()),
        },
        "note": "This receipt independently parses raw sequence 9's WARI suffix and compares only B01.war_id with the original public query and current shared registry. It does not backfill producer output or claim full B01-B04 coverage.",
    }
    _write_exclusive(args.output, receipt)
    print(json.dumps(receipt, ensure_ascii=False))
    return 0 if receipt["status"] == "passed" else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true", help="run the bounded offline comparison")
    parser.add_argument("--database", type=Path, default=DEFAULT_DATABASE)
    parser.add_argument("--ingest", type=Path, default=DEFAULT_INGEST)
    parser.add_argument("--query", type=Path, default=DEFAULT_QUERY)
    parser.add_argument("--registry", type=Path, default=DEFAULT_REGISTRY)
    parser.add_argument("--sequence", default="9")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.run:
        build_parser().print_help()
        return 0
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())
