"""Prepare a bounded battle-stream and title-event manifest from a v6 database.

This helper is deliberately a recorded-input operation.  It never opens the
game, starts an MCP server, or calls the production native-text decoder.  The
NTXT extension is parsed here from its wire contract so that the independent
expected value cannot be populated from the public projection.

The command is inert unless ``--run`` is supplied.  A run needs an existing
installation manifest, completed SQLite ingest database, and ingest report.
It writes a live battle-stream configuration plus every complete event in
whose *current context participant vectors* FRA is present.  A title witness
is selected only when the manually parsed title-helper field is observed and
non-empty.  A real window without such a witness is written as an explicit
unavailable manifest; no synthetic title is invented.
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
STAGE = ROOT / "work/runtime/information-battle-native-observer-20261027-001"
GAME_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
GAME_VERSION = "1.37.4"
STREAM_SCHEMA = "EU4-BATTLE-STREAM/1"
MANIFEST_SCHEMA = "information_battle_native_title_event_manifest.v1"
EXPECTED_SCHEMA = "information_battle_native_title_independent_expected.v1"
MAX_JSON_BYTES = 8 * 1024 * 1024
MAX_DATABASE_BYTES = 512 * 1024 * 1024
MAX_PAYLOAD_BYTES = 512 * 1024
MAX_MESSAGE_COUNT = 4096
MAX_DATABASE_PAYLOAD_BYTES = 64 * 1024 * 1024
MAX_KEY_BYTES = 256
MAX_TEXT_BYTES = 8192
MAGIC = b"IBOW"
VERSION = 6
BASE_VERSION = 5
EXTENSION_MAGIC = b"NTXT"
EXTENSION_VERSION = 1
FIELD_ORDER = (
    "definition_key",
    "auxiliary_text",
    "title_helper_candidate",
    "line1_text",
)
FIELD_SOURCES = {
    "definition_key": "message_metadata",
    "auxiliary_text": "message_metadata",
    "title_helper_candidate": "title_helper_candidate",
    "line1_text": "native_line1",
}
SOURCE_IDS = {value: index for index, value in enumerate(
    ("message_metadata", "title_helper_candidate", "native_line1"), start=1)}
SOURCE_BY_ID = {value: key for key, value in SOURCE_IDS.items()}
STATE_NAMES = {0: "unknown", 1: "observed", 2: "absent"}
STATUS_NAMES = {"unknown": "unknown", "observed": "known", "absent": "absent"}
HEX16 = re.compile(r"[0-9a-f]{16}\Z")


class PreparationUnavailable(RuntimeError):
    """The supplied recorded inputs cannot support a strict title manifest."""


def _read_json(path: Path, *, limit: int = MAX_JSON_BYTES) -> Any:
    path = path.resolve(strict=True)
    if path.stat().st_size <= 0 or path.stat().st_size > limit:
        raise PreparationUnavailable(f"json_size_out_of_bound:{path}")
    with path.open("r", encoding="utf-8-sig") as stream:
        return json.load(stream)


def _sha_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _write_json_exclusive(path: Path, value: Any) -> None:
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2, sort_keys=True)
        stream.write("\n")


def _write_bytes_exclusive(path: Path, value: bytes) -> None:
    with path.open("xb") as stream:
        stream.write(value)


def _integer(value: Any, label: str, *, positive: bool = False) -> int:
    if isinstance(value, bool) or type(value) is not int:
        raise PreparationUnavailable(f"{label}_must_be_integer")
    if positive and value <= 0:
        raise PreparationUnavailable(f"{label}_must_be_positive")
    if value < 0 or value >= (1 << 64):
        raise PreparationUnavailable(f"{label}_out_of_range")
    return value


def _decimal_identity(value: Any, label: str) -> int:
    """Accept the ingest report's decimal identity string, never bool/float."""

    if isinstance(value, bool):
        raise PreparationUnavailable(f"{label}_must_be_integer")
    if type(value) is int:
        result = value
    elif isinstance(value, str) and re.fullmatch(r"[0-9]+", value):
        result = int(value, 10)
    else:
        raise PreparationUnavailable(f"{label}_must_be_integer")
    if result < 0 or result >= (1 << 64):
        raise PreparationUnavailable(f"{label}_out_of_range")
    return result


def _wire_hex(value: int) -> str:
    return f"{value:016x}"


def _fullref_tag(value: Any) -> str | None:
    if isinstance(value, bool) or type(value) is not int or not 0 <= value < (1 << 64):
        return None
    try:
        tag = value.to_bytes(8, "little")[:3].decode("ascii")
    except (UnicodeDecodeError, OverflowError):
        return None
    return tag if re.fullmatch(r"[A-Z0-9]{3}", tag) else None


def _load_installation(path: Path) -> dict[str, Any]:
    value = _read_json(path, limit=512 * 1024)
    if not isinstance(value, dict):
        raise PreparationUnavailable("installation_not_object")
    creation = _integer(value.get("creation_filetime"), "creation_filetime", positive=True)
    session = value.get("session_id")
    game_sha = value.get("game_sha256")
    if not isinstance(session, str) or not session:
        raise PreparationUnavailable("installation_session_missing")
    if game_sha != GAME_SHA256:
        raise PreparationUnavailable("installation_game_sha_mismatch")
    return {
        "path": path.resolve(),
        "creation_filetime": creation,
        "session_id": session,
        "game_sha256": game_sha,
        "dll_sha256": value.get("dll_sha256"),
        "raw": value,
    }


def _load_ingest(path: Path, installation: Mapping[str, Any], database: Path) -> dict[str, Any]:
    report = _read_json(path)
    if not isinstance(report, dict):
        raise PreparationUnavailable("ingest_report_not_object")
    binding = report.get("binding")
    if not isinstance(binding, Mapping):
        raise PreparationUnavailable("ingest_binding_missing")
    if binding.get("session_id") != installation["session_id"]:
        raise PreparationUnavailable("ingest_session_mismatch")
    if _decimal_identity(binding.get("creation_filetime"), "ingest_creation_filetime") != installation["creation_filetime"]:
        raise PreparationUnavailable("ingest_creation_mismatch")
    generation = binding.get("generation")
    install = binding.get("installation")
    if not isinstance(generation, Mapping) or not isinstance(install, Mapping):
        raise PreparationUnavailable("ingest_wire_binding_missing")
    generation_hex = generation.get("wire_hex")
    installation_hex = install.get("wire_hex")
    if (not isinstance(generation_hex, str) or HEX16.fullmatch(generation_hex) is None
            or not isinstance(installation_hex, str) or HEX16.fullmatch(installation_hex) is None):
        raise PreparationUnavailable("ingest_wire_binding_invalid")
    if int(generation_hex, 16) != installation["creation_filetime"]:
        raise PreparationUnavailable("ingest_generation_mismatch")
    requested = report.get("request")
    if isinstance(requested, Mapping) and isinstance(requested.get("database"), str):
        requested_path = (ROOT / requested["database"]).resolve()
        if requested_path != database.resolve():
            raise PreparationUnavailable("ingest_database_mismatch")
    messages = report.get("messages")
    if not isinstance(messages, list) or len(messages) > MAX_MESSAGE_COUNT:
        raise PreparationUnavailable("ingest_messages_invalid")
    return {
        "path": path.resolve(),
        "sha256": _sha_file(path),
        "raw": report,
        "binding": binding,
        "generation": generation_hex,
        "installation": installation_hex,
        "messages": messages,
    }


def _database_rows(database: Path, installation: str, generation: str) -> dict[str, dict[str, Any]]:
    database = database.resolve(strict=True)
    if database.stat().st_size <= 0 or database.stat().st_size > MAX_DATABASE_BYTES:
        raise PreparationUnavailable("battle_database_size_out_of_bound")
    uri = database.as_uri() + "?mode=ro"
    rows: dict[str, dict[str, Any]] = {}
    total = 0
    try:
        connection = sqlite3.connect(uri, uri=True)
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("PRAGMA query_only=ON")
            cursor = connection.execute(
                "SELECT g.message_id,c.payload,c.payload_sha256,c.total_bytes "
                "FROM fragment_groups g JOIN complete_messages c USING(group_id) "
                "WHERE g.installation=? AND g.world_generation=? AND g.status='complete' "
                "ORDER BY CAST(g.message_id AS INTEGER),g.message_id",
                (installation, generation),
            )
            for row in cursor:
                if len(rows) >= MAX_MESSAGE_COUNT:
                    raise PreparationUnavailable("battle_message_count_over_bound")
                message_id = row["message_id"]
                payload = row["payload"]
                if (not isinstance(message_id, str) or not message_id.isdigit()
                        or not isinstance(payload, bytes)
                        or not 0 < len(payload) <= MAX_PAYLOAD_BYTES
                        or row["total_bytes"] != len(payload)
                        or not isinstance(row["payload_sha256"], str)):
                    raise PreparationUnavailable("battle_database_row_invalid")
                if message_id in rows:
                    raise PreparationUnavailable("battle_database_message_id_duplicate")
                digest = hashlib.sha256(payload).hexdigest()
                if digest != row["payload_sha256"]:
                    raise PreparationUnavailable("battle_database_payload_hash_mismatch")
                total += len(payload)
                if total > MAX_DATABASE_PAYLOAD_BYTES:
                    raise PreparationUnavailable("battle_database_payload_budget_exceeded")
                rows[message_id] = {
                    "message_id": message_id,
                    "payload": payload,
                    "sha256": digest,
                    "bytes": len(payload),
                    "total_bytes": row["total_bytes"],
                }
        finally:
            connection.close()
    except sqlite3.Error as exc:
        raise PreparationUnavailable(f"battle_database_read_failed:{type(exc).__name__}") from exc
    if not rows:
        raise PreparationUnavailable("battle_database_has_no_complete_messages")
    return rows


def _context_refs(message: Mapping[str, Any]) -> tuple[list[int], str]:
    try:
        value = message["decode"]["value"]
        context = value["context"]
        sides = context["sides"]
    except (KeyError, TypeError):
        raise PreparationUnavailable("current_context_vectors_missing") from None
    if not isinstance(sides, list) or not sides:
        raise PreparationUnavailable("current_context_vectors_invalid")
    refs: list[int] = []
    for side in sides:
        if not isinstance(side, Mapping):
            raise PreparationUnavailable("current_context_side_invalid")
        participants = side.get("participants")
        if not isinstance(participants, Mapping) or participants.get("complete") is not True:
            raise PreparationUnavailable("current_context_participant_vector_incomplete")
        full_refs = participants.get("full_refs")
        if not isinstance(full_refs, list) or not full_refs:
            raise PreparationUnavailable("current_context_full_ref_vector_invalid")
        for full_ref in full_refs:
            if isinstance(full_ref, bool) or type(full_ref) is not int or not 0 <= full_ref < (1 << 64):
                raise PreparationUnavailable("current_context_full_ref_invalid")
            refs.append(full_ref)
    return refs, "ingest.decode.value.context.sides[].participants.full_refs"


def _manual_ntxt(payload: bytes, codec: str) -> dict[str, Any]:
    """Parse only the v6 NTXT extension; no legacy/native decoder is called."""

    if not isinstance(payload, bytes) or len(payload) > MAX_PAYLOAD_BYTES:
        raise PreparationUnavailable("payload_size_out_of_bound")
    if len(payload) < 20 or payload[:4] != MAGIC:
        raise PreparationUnavailable("v6_magic_missing")
    if struct.unpack_from("<H", payload, 4)[0] != VERSION:
        raise PreparationUnavailable("v6_version_required")
    base_bytes = struct.unpack_from("<I", payload, 6)[0]
    base_end = 10 + base_bytes
    if not 10 <= base_bytes <= MAX_PAYLOAD_BYTES or base_end + 10 > len(payload):
        raise PreparationUnavailable("v6_base_length_invalid")
    base = payload[10:base_end]
    if len(base) < 6 or base[:4] != MAGIC or struct.unpack_from("<H", base, 4)[0] != BASE_VERSION:
        raise PreparationUnavailable("v6_base_v5_required")
    if payload[base_end:base_end + 4] != EXTENSION_MAGIC:
        raise PreparationUnavailable("v6_ntxt_magic_missing")
    ext_version = struct.unpack_from("<H", payload, base_end + 4)[0]
    ext_bytes = struct.unpack_from("<I", payload, base_end + 6)[0]
    ext_start = base_end + 10
    if ext_version != EXTENSION_VERSION or ext_bytes != len(payload) - ext_start:
        raise PreparationUnavailable("v6_ntxt_length_invalid")
    body = payload[ext_start:]
    if len(body) < 16:
        raise PreparationUnavailable("v6_ntxt_body_too_short")
    flags, reserved, date_state, flag_state, entry_count, reserved_byte, native_date, flag8c, flag8d, reserved_tail = struct.unpack_from("<HHBBBBiBBH", body, 0)
    if flags or reserved or reserved_byte or reserved_tail or entry_count != 4:
        raise PreparationUnavailable("v6_ntxt_noncanonical_header")
    if date_state not in STATE_NAMES or flag_state not in STATE_NAMES:
        raise PreparationUnavailable("v6_ntxt_metadata_state_invalid")
    if date_state != 1 and native_date != 0:
        raise PreparationUnavailable("v6_ntxt_unobserved_date_nonzero")
    if flag_state != 1 and (flag8c or flag8d):
        raise PreparationUnavailable("v6_ntxt_unobserved_flags_nonzero")
    position = 16
    fields: dict[str, dict[str, Any]] = {}
    for expected_id, name in enumerate(FIELD_ORDER, start=1):
        if position + 8 > len(body):
            raise PreparationUnavailable(f"v6_ntxt_entry_truncated:{name}")
        field_id, state, source_id, reserved_entry, length = struct.unpack_from("<BBBBI", body, position)
        position += 8
        max_length = MAX_KEY_BYTES if name == "definition_key" else MAX_TEXT_BYTES
        if field_id != expected_id or state not in STATE_NAMES or source_id not in SOURCE_BY_ID:
            raise PreparationUnavailable(f"v6_ntxt_entry_header_invalid:{name}")
        source = SOURCE_BY_ID[source_id]
        if source != FIELD_SOURCES[name] or reserved_entry or length > max_length:
            raise PreparationUnavailable(f"v6_ntxt_entry_contract_invalid:{name}")
        if position + length > len(body):
            raise PreparationUnavailable(f"v6_ntxt_entry_truncated:{name}")
        raw = body[position:position + length]
        position += length
        if state != 1 and raw:
            raise PreparationUnavailable(f"v6_ntxt_unobserved_raw:{name}")
        state_name = STATE_NAMES[state]
        fields[name] = {
            "status": STATUS_NAMES[state_name],
            "state": state_name,
            "source": source,
            "codec": codec,
            "raw_hex": raw.hex() if state == 1 else None,
        }
    if position != len(body):
        raise PreparationUnavailable("v6_ntxt_trailing_bytes")
    return {
        "codec": codec,
        "metadata": {
            "native_date": {
                "status": STATUS_NAMES[STATE_NAMES[date_state]],
                "state": STATE_NAMES[date_state],
                "value": native_date if date_state == 1 else None,
            },
            "raw_flags": {
                "status": STATUS_NAMES[STATE_NAMES[flag_state]],
                "state": STATE_NAMES[flag_state],
                "raw_flag_8c": flag8c if flag_state == 1 else None,
                "raw_flag_8d": flag8d if flag_state == 1 else None,
            },
        },
        "text_fields": fields,
        "complete": False,
        "parser": "manual_ntxt_v1",
    }


def _event_id(installation: str, generation: str, message_id: str) -> str:
    return f"battle-observation:{installation}:{generation}:{message_id}"


def _binding(installation: Mapping[str, Any], ingest: Mapping[str, Any], observer_ref: str) -> dict[str, Any]:
    return {
        "game_sha256": GAME_SHA256,
        "generation": ingest["generation"],
        "installation": ingest["installation"],
        "mode": "live",
        "observer_ref": observer_ref,
        "process_creation_filetime": installation["creation_filetime"],
        "session_id": installation["session_id"],
    }


def _source_pin(path: Path) -> dict[str, Any]:
    return {"path": str(path.resolve()), "sha256": _sha_file(path), "bytes": path.stat().st_size}


def _prepare(installation_path: Path, database_path: Path, ingest_path: Path,
             output_dir: Path) -> dict[str, Any]:
    output_dir = output_dir.resolve()
    if output_dir.exists():
        raise PreparationUnavailable(f"refusing_to_overwrite_output:{output_dir}")
    installation = _load_installation(installation_path.resolve(strict=True))
    database = database_path.resolve(strict=True)
    ingest = _load_ingest(ingest_path.resolve(strict=True), installation, database)
    rows = _database_rows(database, ingest["installation"], ingest["generation"])
    messages = ingest["messages"]
    by_id: dict[str, Mapping[str, Any]] = {}
    for message in messages:
        if not isinstance(message, Mapping):
            raise PreparationUnavailable("ingest_message_not_object")
        message_id = message.get("message_id")
        if not isinstance(message_id, str) or not message_id.isdigit() or message_id in by_id:
            raise PreparationUnavailable("ingest_message_id_invalid")
        if message_id not in rows:
            raise PreparationUnavailable(f"ingest_message_missing_database_row:{message_id}")
        if message.get("payload_sha256") != rows[message_id]["sha256"] or message.get("payload_bytes") != rows[message_id]["bytes"]:
            raise PreparationUnavailable(f"ingest_payload_pin_mismatch:{message_id}")
        by_id[message_id] = message
    codec = installation["raw"].get("native_text_codec")
    if not isinstance(codec, str) or not codec:
        raise PreparationUnavailable("native_text_codec_missing")

    direct_refs: set[int] = set()
    event_specs: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    for message_id in sorted(by_id, key=lambda value: (int(value), value)):
        message = by_id[message_id]
        refs, context_source = _context_refs(message)
        fra_refs = [ref for ref in refs if _fullref_tag(ref) == "FRA"]
        direct_refs.update(fra_refs)
        if not fra_refs:
            continue
        if len(set(fra_refs)) != 1:
            raise PreparationUnavailable(f"multiple_fra_context_fullrefs:{message_id}")
        row = rows[message_id]
        title = _manual_ntxt(row["payload"], codec)["text_fields"]["title_helper_candidate"]
        event_id = _event_id(ingest["installation"], ingest["generation"], message_id)
        event_specs.append({
            "event_id": event_id,
            "message_id": message_id,
            "sha256": row["sha256"],
            "bytes": row["bytes"],
            "direct_fra": {
                "status": "known",
                "fullref": _wire_hex(fra_refs[0]),
                "tag": "FRA",
                "source": context_source,
            },
            "title": title,
            "context": {
                "source": context_source,
                "participant_count": len(refs),
                "vectors_complete": True,
            },
        })
    if len(direct_refs) != 1:
        if not direct_refs:
            raise PreparationUnavailable("fra_fullref_not_observed_in_current_context_vectors")
        raise PreparationUnavailable("fra_fullref_changed_across_current_context_vectors")
    observer_ref = _wire_hex(next(iter(direct_refs)))
    binding = _binding(installation, ingest, observer_ref)
    events = sorted(event_specs, key=lambda item: (int(item["message_id"]), item["message_id"]))
    candidates = [item for item in events
                  if item["title"].get("status") == "known"
                  and isinstance(item["title"].get("raw_hex"), str)
                  and bool(item["title"]["raw_hex"])]
    selected = candidates[0] if candidates else None
    stream = {"schema": STREAM_SCHEMA, "database": str(database), "binding": binding}
    manifest: dict[str, Any] = {
        "schema": MANIFEST_SCHEMA,
        "status": "ready" if selected else "unavailable",
        "mode": "recorded_database_to_live_stream",
        "database": {
            "path": str(database),
            "sha256": _sha_file(database),
            "bytes": database.stat().st_size,
            "table": "complete_messages",
        },
        "binding": binding,
        "events": events,
        "event_count": len(events),
        "source_pins": {
            "installation": _source_pin(installation["path"]),
            "ingest_report": _source_pin(ingest["path"]),
            "database": _source_pin(database),
        },
        "selection": {
            "status": "ready" if selected else "unavailable",
            "reason": None if selected else "FRA_DIRECT_EVENT_WITH_NONEMPTY_TITLE_CANDIDATE_NOT_OBSERVED",
            "event_id": selected["event_id"] if selected else None,
            "candidate_count": len(candidates),
            "basis": "manual_ntxt_title_helper_candidate_and_current_context_participant_vectors",
        },
        "artifacts": {
            "payload": "payload.bin" if selected else None,
            "expected": "independent-expected.json" if selected else None,
        },
        "limitations": [
            "No game or MCP access was used by this helper.",
            "Only direct FRA participation in complete current context vectors is included.",
            "A non-empty observed title-helper candidate is required before a payload witness is selected.",
            "The manual parser records NTXT bytes and status; it does not decode display text or claim a complete B04 title.",
        ],
        "skipped": skipped,
    }
    output_dir.mkdir(parents=True, exist_ok=False)
    _write_json_exclusive(output_dir / "battle-stream.json", stream)
    if selected is not None:
        row = rows[selected["message_id"]]
        _write_bytes_exclusive(output_dir / "payload.bin", row["payload"])
        expected = {
            "schema": EXPECTED_SCHEMA,
            "event_id": selected["event_id"],
            "message_id": selected["message_id"],
            "payload_sha256": selected["sha256"],
            "payload_bytes": selected["bytes"],
            "binding": binding,
            "native_text": _manual_ntxt(row["payload"], codec),
            "title": selected["title"],
            "source": {
                "parser": "manual_ntxt_v1",
                "database": str(database),
                "database_sha256": manifest["database"]["sha256"],
                "ingest_report_sha256": ingest["sha256"],
            },
        }
        _write_json_exclusive(output_dir / "independent-expected.json", expected)
        selected["artifacts"] = {"payload": "payload.bin", "expected": "independent-expected.json"}
    _write_json_exclusive(output_dir / "event-manifest.json", manifest)
    return manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true", help="read the completed database and write a manifest")
    parser.add_argument("--installation", type=Path)
    parser.add_argument("--database", type=Path)
    parser.add_argument("--ingest-report", type=Path)
    parser.add_argument("--output-dir", type=Path)
    args = parser.parse_args(argv)
    if not args.run:
        print(json.dumps({"status": "inert", "run": False}, sort_keys=True))
        return 0
    missing = [name for name, value in (
        ("installation", args.installation), ("database", args.database),
        ("ingest-report", args.ingest_report), ("output-dir", args.output_dir))
               if value is None]
    if missing:
        parser.error("--run requires " + ", ".join("--" + item for item in missing))
    try:
        manifest = _prepare(args.installation, args.database, args.ingest_report, args.output_dir)
    except (OSError, ValueError, sqlite3.Error, PreparationUnavailable) as error:
        print(json.dumps({"status": "unavailable", "error": str(error)}, ensure_ascii=False))
        return 1
    print(json.dumps({
        "status": manifest["status"],
        "output_dir": str(args.output_dir.resolve()),
        "event_count": manifest["event_count"],
        "selected_event_id": manifest["selection"]["event_id"],
    }, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
