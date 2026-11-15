# Acceptance-only revision003: strict title manifest over the corrected text helper.
"""Thin title-witness wrapper around the established native-text live check.

The wrapper adds one strict recorded-input boundary to
``validate_information_battle_native_text_live_004.py``.  It validates the
event manifest, installation/session binding, SQLite row pins, and the
independently manually parsed NTXT expected file before delegating.  It then
temporarily replaces the legacy module's event map with the manifest's event
set, so no event number (including the historical ``7``) is special here.

The command is inert unless ``--run`` is supplied.  It does not read files on
the default/help path and never starts the MCP server itself; the delegated
legacy helper is the only live operation when explicitly requested.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path
import re
from typing import Any, Mapping

try:
    from work.prepare_information_battle_native_title_live import (
        GAME_SHA256,
        GAME_VERSION,
        EXPECTED_SCHEMA,
        HEX16,
        MANIFEST_SCHEMA,
        MAX_JSON_BYTES,
        PreparationUnavailable,
        _database_rows,
        _fullref_tag,
        _load_installation,
        _manual_ntxt,
        _read_json,
        _sha_file,
    )
except ImportError:  # pragma: no cover - direct script execution from work/
    from prepare_information_battle_native_title_live import (  # type: ignore
        GAME_SHA256,
        GAME_VERSION,
        EXPECTED_SCHEMA,
        HEX16,
        MANIFEST_SCHEMA,
        MAX_JSON_BYTES,
        PreparationUnavailable,
        _database_rows,
        _fullref_tag,
        _load_installation,
        _manual_ntxt,
        _read_json,
        _sha_file,
    )


ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / "work/runtime/information-battle-native-title-20261027-001"
LEGACY_PATH = ROOT / "work/validate_information_battle_native_text_live_004.py"
EVENT_ID = re.compile(r"^battle-observation:([0-9a-f]{16}):([0-9a-f]{16}):([1-9][0-9]{0,19})\Z")
MAX_MANIFEST_BYTES = 4 * 1024 * 1024


def _write_json(path: Path, value: Any) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2, sort_keys=True)
        stream.write("\n")


def _resolve_child(parent: Path, raw: Any, label: str) -> Path:
    if not isinstance(raw, str) or not raw or Path(raw).is_absolute():
        raise PreparationUnavailable(f"{label}_must_be_relative_path")
    parent = parent.resolve()
    candidate = (parent / raw).resolve(strict=True)
    try:
        candidate.relative_to(parent)
    except ValueError as exc:
        raise PreparationUnavailable(f"{label}_escapes_manifest_directory") from exc
    return candidate


def _require_binding(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise PreparationUnavailable(f"{label}_binding_not_object")
    expected = {
        "game_sha256", "generation", "installation", "mode", "observer_ref",
        "process_creation_filetime", "session_id",
    }
    if set(value) != expected:
        raise PreparationUnavailable(f"{label}_binding_keys_mismatch")
    binding = dict(value)
    if binding["game_sha256"] != GAME_SHA256 or binding["mode"] != "live":
        raise PreparationUnavailable(f"{label}_binding_game_or_mode_mismatch")
    for key in ("generation", "installation", "observer_ref"):
        if not isinstance(binding[key], str) or HEX16.fullmatch(binding[key]) is None:
            raise PreparationUnavailable(f"{label}_{key}_invalid")
    if _fullref_tag(int(binding["observer_ref"], 16)) != "FRA":
        raise PreparationUnavailable(f"{label}_observer_must_be_FRA")
    if isinstance(binding["process_creation_filetime"], bool) or type(binding["process_creation_filetime"]) is not int:
        raise PreparationUnavailable(f"{label}_creation_invalid")
    if not isinstance(binding["session_id"], str) or not binding["session_id"]:
        raise PreparationUnavailable(f"{label}_session_invalid")
    return binding


def _source_pin_ok(value: Any, label: str) -> None:
    if not isinstance(value, Mapping):
        raise PreparationUnavailable(f"{label}_source_pin_missing")
    path = value.get("path")
    digest = value.get("sha256")
    size = value.get("bytes")
    if not isinstance(path, str) or not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise PreparationUnavailable(f"{label}_source_pin_invalid")
    source = Path(path).resolve(strict=True)
    if _sha_file(source) != digest or source.stat().st_size != size:
        raise PreparationUnavailable(f"{label}_source_pin_changed")


def _strict_event_manifest(manifest_path: Path, installation_path: Path,
                           database_path: Path, battle_stream_path: Path) -> tuple[
                               dict[str, Any], dict[str, Any], str, Path, Path, dict[str, tuple[str, int]]]:
    manifest_path = manifest_path.resolve(strict=True)
    manifest = _read_json(manifest_path, limit=MAX_MANIFEST_BYTES)
    if not isinstance(manifest, dict) or manifest.get("schema") != MANIFEST_SCHEMA:
        raise PreparationUnavailable("event_manifest_schema_mismatch")
    binding = _require_binding(manifest.get("binding"), "event_manifest")
    installation = _load_installation(installation_path.resolve(strict=True))
    if (binding["session_id"] != installation["session_id"]
            or binding["process_creation_filetime"] != installation["creation_filetime"]
            or binding["game_sha256"] != installation["game_sha256"]):
        raise PreparationUnavailable("event_manifest_installation_binding_mismatch")
    stream_path = battle_stream_path.resolve(strict=True)
    stream = _read_json(stream_path, limit=MAX_JSON_BYTES)
    if not isinstance(stream, dict) or set(stream) != {"schema", "database", "binding"}:
        raise PreparationUnavailable("battle_stream_strict_shape_mismatch")
    if stream.get("schema") != "EU4-BATTLE-STREAM/1":
        raise PreparationUnavailable("battle_stream_schema_mismatch")
    stream_binding = _require_binding(stream.get("binding"), "battle_stream")
    if stream_binding != binding:
        raise PreparationUnavailable("battle_stream_binding_mismatch")
    database = database_path.resolve(strict=True)
    database_info = manifest.get("database")
    if not isinstance(database_info, Mapping):
        raise PreparationUnavailable("event_manifest_database_missing")
    if (database_info.get("sha256") != _sha_file(database)
            or database_info.get("bytes") != database.stat().st_size):
        raise PreparationUnavailable("event_manifest_database_pin_changed")
    source_pins = manifest.get("source_pins")
    if not isinstance(source_pins, Mapping):
        raise PreparationUnavailable("event_manifest_source_pins_missing")
    for name in ("installation", "ingest_report", "database"):
        _source_pin_ok(source_pins.get(name), name)
    rows = _database_rows(database, binding["installation"], binding["generation"])
    events = manifest.get("events")
    if not isinstance(events, list) or not events:
        raise PreparationUnavailable("event_manifest_events_missing")
    codec = installation["raw"].get("native_text_codec")
    if not isinstance(codec, str) or not codec:
        raise PreparationUnavailable("native_text_codec_missing")
    event_map: dict[str, dict[str, Any]] = {}
    payload_manifest: dict[str, tuple[str, int]] = {}
    for event in events:
        if not isinstance(event, Mapping):
            raise PreparationUnavailable("event_manifest_event_not_object")
        event_id = event.get("event_id")
        message_id = event.get("message_id")
        match = EVENT_ID.fullmatch(event_id) if isinstance(event_id, str) else None
        if match is None or message_id != match.group(3) or event_id in event_map:
            raise PreparationUnavailable("event_manifest_event_id_invalid")
        if match.group(1) != binding["installation"] or match.group(2) != binding["generation"]:
            raise PreparationUnavailable("event_manifest_event_binding_mismatch")
        row = rows.get(message_id)
        if row is None or event.get("sha256") != row["sha256"] or event.get("bytes") != row["bytes"]:
            raise PreparationUnavailable(f"event_manifest_payload_pin_mismatch:{message_id}")
        direct = event.get("direct_fra")
        if (not isinstance(direct, Mapping) or direct.get("status") != "known"
                or direct.get("tag") != "FRA" or direct.get("fullref") != binding["observer_ref"]):
            raise PreparationUnavailable(f"event_manifest_direct_fra_binding_invalid:{message_id}")
        manual = _manual_ntxt(row["payload"], codec)
        title = event.get("title")
        if not isinstance(title, Mapping) or dict(title) != manual["text_fields"]["title_helper_candidate"]:
            raise PreparationUnavailable(f"event_manifest_title_not_manual_ntxt:{message_id}")
        event_map[event_id] = dict(event)
        payload_manifest[event_id] = (row["sha256"], row["bytes"])
    selection = manifest.get("selection")
    if not isinstance(selection, Mapping) or selection.get("status") != "ready":
        raise PreparationUnavailable("title_witness_not_available")
    selected_id = selection.get("event_id")
    if not isinstance(selected_id, str) or selected_id not in event_map:
        raise PreparationUnavailable("selected_event_missing_from_manifest")
    selected_title = event_map[selected_id]["title"]
    if selected_title.get("status") != "known" or not selected_title.get("raw_hex"):
        raise PreparationUnavailable("selected_title_candidate_not_known_nonempty")
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, Mapping):
        raise PreparationUnavailable("selected_artifacts_missing")
    selected = event_map[selected_id]
    selected_artifacts = selected.get("artifacts") if isinstance(selected.get("artifacts"), Mapping) else artifacts
    payload_path = _resolve_child(manifest_path.parent, selected_artifacts.get("payload"), "payload")
    expected_path = _resolve_child(manifest_path.parent, selected_artifacts.get("expected"), "expected")
    if _sha_file(payload_path) != payload_manifest[selected_id][0] or payload_path.stat().st_size != payload_manifest[selected_id][1]:
        raise PreparationUnavailable("selected_payload_artifact_pin_mismatch")
    expected = _read_json(expected_path, limit=2 * 1024 * 1024)
    if (not isinstance(expected, Mapping)
            or expected.get("schema") != EXPECTED_SCHEMA
            or expected.get("event_id") != selected_id):
        raise PreparationUnavailable("selected_expected_event_mismatch")
    if (expected.get("payload_sha256") != payload_manifest[selected_id][0]
            or expected.get("payload_bytes") != payload_manifest[selected_id][1]):
        raise PreparationUnavailable("selected_expected_payload_pin_mismatch")
    if expected.get("binding") != binding:
        raise PreparationUnavailable("selected_expected_binding_mismatch")
    native = expected.get("native_text")
    row = rows[selected["message_id"]]
    if not isinstance(native, Mapping) or dict(native.get("text_fields", {})) != dict(_manual_ntxt(row["payload"], codec)["text_fields"]):
        raise PreparationUnavailable("selected_expected_not_manual_ntxt")
    if expected.get("title") != selected_title:
        raise PreparationUnavailable("selected_expected_title_mismatch")
    return manifest, binding, selected_id, payload_path, expected_path, payload_manifest


def _load_legacy_module() -> Any:
    spec = importlib.util.spec_from_file_location("_battle_native_text_live_004", LEGACY_PATH)
    if spec is None or spec.loader is None:
        raise PreparationUnavailable("legacy_live_helper_import_unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _genericize_report(output: Path, selected_id: str, manifest_path: Path) -> None:
    report_path = output / "report.json"
    if not report_path.is_file():
        return
    value = _read_json(report_path, limit=MAX_JSON_BYTES)
    if not isinstance(value, dict):
        return
    checks = value.get("checks")
    if isinstance(checks, dict):
        selected_check = checks.pop("selected_event7_occurs_once_and_matches_query", None)
        if selected_check is not None:
            checks["selected_event_occurs_once_and_matches_query"] = selected_check
    value["selected_event_id"] = selected_id
    value["event_manifest"] = str(manifest_path)
    _write_json(report_path, value)


def run(manifest_path: Path, installation_path: Path, database_path: Path,
        battle_stream_path: Path, output: Path, *, event_id: str | None = None,
        resume_query: Path | None = None,
        resume_report_query: Path | None = None) -> int:
    manifest, binding, selected_id, payload_path, expected_path, payload_manifest = _strict_event_manifest(
        manifest_path, installation_path, database_path, battle_stream_path)
    if event_id is not None and event_id != selected_id:
        raise PreparationUnavailable("requested_event_id_differs_from_manifest_selection")
    legacy = _load_legacy_module()
    old_map = legacy.EXPECTED_EVENT_PAYLOADS
    legacy.EXPECTED_EVENT_PAYLOADS = {
        event.rsplit(":", 1)[-1]: payload_manifest[event]
        for event in payload_manifest
    }
    argv = [
        "--run", "--installation", str(installation_path), "--database", str(database_path),
        "--battle-stream", str(battle_stream_path), "--event-id", selected_id,
        "--expected", str(expected_path), "--payload", str(payload_path),
        "--output", str(output),
    ]
    if resume_query is not None:
        argv.extend(["--resume-query", str(resume_query)])
    if resume_report_query is not None:
        argv.extend(["--resume-report-query", str(resume_report_query)])
    try:
        result = legacy.main(argv)
    finally:
        legacy.EXPECTED_EVENT_PAYLOADS = old_map
    if output.is_dir():
        _genericize_report(output, selected_id, manifest_path.resolve())
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true", help="delegate the explicit live read-only acceptance")
    parser.add_argument("--installation", type=Path)
    parser.add_argument("--database", type=Path)
    parser.add_argument("--battle-stream", type=Path)
    parser.add_argument("--event-manifest", type=Path)
    parser.add_argument("--event-id")
    parser.add_argument("--resume-query", type=Path)
    parser.add_argument("--resume-report-query", type=Path)
    parser.add_argument("--output", type=Path,
                        default=STAGE / "live-acceptance-003")
    args = parser.parse_args(argv)
    if not args.run:
        print(json.dumps({"status": "inert", "run": False}, sort_keys=True))
        return 0
    missing = [name for name, value in (
        ("installation", args.installation), ("database", args.database),
        ("battle-stream", args.battle_stream), ("event-manifest", args.event_manifest))
               if value is None]
    if missing:
        parser.error("--run requires " + ", ".join("--" + item for item in missing))
    try:
        return run(args.event_manifest, args.installation, args.database,
                   args.battle_stream, args.output, event_id=args.event_id,
                   resume_query=args.resume_query,
                   resume_report_query=args.resume_report_query)
    except (OSError, ValueError, RuntimeError, PreparationUnavailable) as error:
        print(json.dumps({"status": "unavailable", "error": str(error)}, ensure_ascii=False))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
