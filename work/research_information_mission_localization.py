"""Bounded static audit of FRA mission localization in the enabled EU4 stack.

The mission definitions and enabled-mod order come from the existing
``MissionDefinitionIndex``.  Localization files are streamed line by line;
the complete save, game process, native analysis cache, and production
information sources are never opened.  A decoded string in this report is a
static candidate.  It is not treated as proof that the running game selected
the same language or displayed the same text.
"""

from __future__ import annotations

from collections import defaultdict
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from bridge.information.mission_definitions import MissionDefinitionIndex  # noqa: E402
from bridge.native_text import (  # noqa: E402
    EU4_ESCAPE_CODEC,
    InvalidNativeText,
    decode_native_text,
)


SNAPSHOT = ROOT / "work/runtime/information-missions-20261024-001/live-acceptance-003/saved-snapshot.json"
OUTPUT = ROOT / "work/runtime/information-loaded-tasks-20261024-001/localization-source-review.json"
CODEC_SOURCE = ROOT / "bridge/native_text.py"

SUPPORTED_VERSION = "1.37.4"
TARGET_COUNTRY = "FRA"
MAX_LOCALISATION_FILE_BYTES = 8 * 1024 * 1024
MAX_TOTAL_SCAN_BYTES = 128 * 1024 * 1024
MAX_FILES_PER_LAYER = 4096
MAX_LINE_BYTES = 1024 * 1024
MAX_VALUE_BYTES = 64 * 1024
EXPECTED_ROOT_COUNT = 18
EXPECTED_TASK_COUNT = 61

_HEADER_RE = re.compile(r"^\s*(l_[A-Za-z0-9_]+)\s*:\s*(?:#.*)?$")
_KEY_RE = re.compile(
    r'^\s*([A-Za-z0-9_.:-]+)\s*:\s*(-?\d+)\s+"'
)
_TOKEN_RE = re.compile(r"\[[^\]\r\n]{1,128}\]")


def _sha256_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    total = 0
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            total += len(block)
            digest.update(block)
    return digest.hexdigest(), total


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _rel(path: Path, root: Path) -> str:
    return path.relative_to(root).as_posix()


def _read_json(path: Path) -> tuple[dict[str, Any], str, int]:
    raw = path.read_bytes()
    payload = json.loads(raw.decode("utf-8-sig"))
    if not isinstance(payload, dict):
        raise ValueError(f"expected JSON object: {path}")
    return payload, _sha256_bytes(raw), len(raw)


def _snapshot_roots() -> tuple[list[str], dict[str, Any]]:
    payload, digest, size = _read_json(SNAPSHOT)
    if payload.get("mode") != "recorded" or payload.get("country") != TARGET_COUNTRY:
        raise ValueError("the recorded snapshot is not the FRA source")
    missions = payload.get("country_missions")
    slots = missions.get("mission_slots") if isinstance(missions, dict) else None
    if missions.get("present") is not True or not isinstance(slots, list) or len(slots) != 5:
        raise ValueError("the recorded snapshot does not contain five country mission slots")
    roots: list[str] = []
    for slot_number, slot in enumerate(slots, 1):
        if not isinstance(slot, dict) or slot.get("index") != slot_number:
            raise ValueError("mission slot order is not explicit in the recorded snapshot")
        values = slot.get("root_ids")
        if not isinstance(values, list) or not values or any(not isinstance(v, str) for v in values):
            raise ValueError("recorded mission slot has no explicit root IDs")
        roots.extend(values)
    if len(roots) != EXPECTED_ROOT_COUNT or len(set(roots)) != EXPECTED_ROOT_COUNT:
        raise ValueError(f"expected {EXPECTED_ROOT_COUNT} distinct recorded roots, got {len(roots)}")
    return roots, {
        "path": str(SNAPSHOT),
        "sha256": digest,
        "size_bytes": size,
        "mode": payload.get("mode"),
        "country": payload.get("country"),
        "date": payload.get("date"),
        "version": payload.get("version"),
        "slot_count": len(slots),
        "root_count": len(roots),
        "slots": [
            {"index": item.get("index"), "root_ids": list(item.get("root_ids", []))}
            for item in slots
        ],
    }


def _cp1252_escape_bytes(text: str) -> bytes:
    """Reverse the on-disk UTF-8/CP1252 presentation used by the CN mod.

    The mod stores a UTF-8 file.  After UTF-8 decoding, EU4 escape payloads
    such as ``\x10ã‰`` contain the CP1252 characters ``ã`` and ``‰``.  Encoding
    those characters back to CP1252 yields bytes ``e3 89`` and lets the
    existing, explicitly selected ``eu4_escape`` decoder restore ``解``.
    C1 code points which CP1252 leaves undefined are preserved one-to-one;
    this handles source bytes such as ``0x90`` without guessing a new codec.
    """

    result = bytearray()
    for character in text:
        try:
            result.extend(character.encode("cp1252"))
        except UnicodeEncodeError:
            codepoint = ord(character)
            if 0x80 <= codepoint <= 0x9F:
                result.append(codepoint)
            else:
                raise
    return bytes(result)


def _quoted_value(text: str, start: int) -> tuple[str, int] | None:
    end = start
    while end < len(text):
        if text[end] == '"':
            backslashes = 0
            cursor = end - 1
            while cursor >= start and text[cursor] == "\\":
                backslashes += 1
                cursor -= 1
            if backslashes % 2 == 0:
                return text[start:end], end
        end += 1
    return None


def _parse_localisation_line(text: str) -> tuple[str, str, int] | None:
    match = _KEY_RE.match(text)
    if not match:
        return None
    key = match.group(1)
    version = int(match.group(2))
    value = _quoted_value(text, match.end())
    if value is None:
        return None
    return key, value[0], version


def _decode_candidate(value: str) -> dict[str, Any]:
    result: dict[str, Any] = {
        "codec": EU4_ESCAPE_CODEC,
        "on_disk_transform": "utf8_file_text_to_cp1252_bytes_then_eu4_escape",
        "display_semantics_verified": False,
    }
    try:
        encoded = _cp1252_escape_bytes(value)
        result["encoded_bytes_hex"] = encoded.hex()
        if len(encoded) > MAX_VALUE_BYTES:
            result.update(status="rejected", reason="LOCALISATION_VALUE_TOO_LARGE")
            return result
        result["decoded_candidate"] = decode_native_text(
            encoded, EU4_ESCAPE_CODEC, max_bytes=min(MAX_VALUE_BYTES, 8192),
            max_bytes_limit=8192,
        )
        result["status"] = "decoded_candidate"
    except UnicodeEncodeError as exc:
        result.update(status="rejected", reason="ON_DISK_CP1252_PRESENTATION_UNSUPPORTED",
                      error=str(exc))
    except (InvalidNativeText, ValueError) as exc:
        result.update(status="rejected", reason="EU4_ESCAPE_DECODE_FAILED", error=str(exc))
    return result


def _direct_codec_probe(value: str) -> dict[str, Any]:
    """Show why the UTF-8 file payload is not passed directly to eu4_escape."""

    result: dict[str, Any] = {"codec": EU4_ESCAPE_CODEC, "input": "utf8_encoded_file_payload"}
    raw = value.encode("utf-8")
    try:
        result["decoded"] = decode_native_text(raw, EU4_ESCAPE_CODEC, max_bytes=min(len(raw), 8192),
                                                max_bytes_limit=8192)
        result["status"] = "decoded_but_not_on_disk_bridge_text"
    except (InvalidNativeText, ValueError) as exc:
        result.update(status="rejected", reason="EU4_ESCAPE_DECODE_FAILED", error=str(exc))
    return result


def _scan_layer(layer: dict[str, Any], target_keys: set[str], total_counter: list[int]) -> dict[str, Any]:
    root = Path(layer["root"])
    directory = root / "localisation"
    result: dict[str, Any] = {
        "layer": layer["layer"],
        "order": layer["order"],
        "root": str(root),
        "directory": str(directory),
        "exists": directory.is_dir(),
        "files_scanned": 0,
        "bytes_scanned": 0,
        "target_hit_files": [],
        "errors": [],
    }
    if not directory.is_dir():
        result["file_manifest_sha256"] = _sha256_bytes(b"[]")
        return result
    paths = sorted(
        [item for item in directory.rglob("*") if item.is_file() and item.suffix.lower() in {".yml", ".yaml"}],
        key=lambda item: item.relative_to(directory).as_posix().casefold(),
    )
    if len(paths) > MAX_FILES_PER_LAYER:
        raise ValueError(f"localisation directory exceeds file cap: {directory}")
    manifest: list[dict[str, Any]] = []
    hits: list[dict[str, Any]] = []
    for path in paths:
        relative = path.relative_to(root).as_posix()
        size = path.stat().st_size
        if size > MAX_LOCALISATION_FILE_BYTES:
            result["errors"].append({"path": str(path), "reason": "FILE_TOO_LARGE", "size_bytes": size})
            continue
        digest = hashlib.sha256()
        headers: list[dict[str, Any]] = []
        entries: list[dict[str, Any]] = []
        line_count = 0
        encoding = "utf-8-sig" if path.open("rb").read(3) == b"\xef\xbb\xbf" else "utf-8"
        with path.open("rb") as stream:
            for line_number, raw_line in enumerate(stream, 1):
                line_count = line_number
                if len(raw_line) > MAX_LINE_BYTES:
                    result["errors"].append({"path": str(path), "line": line_number,
                                             "reason": "LINE_TOO_LARGE"})
                    continue
                total_counter[0] += len(raw_line)
                if total_counter[0] > MAX_TOTAL_SCAN_BYTES:
                    raise ValueError("localisation scan exceeds total byte cap")
                digest.update(raw_line)
                try:
                    text = raw_line.decode("utf-8-sig" if line_number == 1 else "utf-8").rstrip("\r\n")
                except UnicodeDecodeError as exc:
                    result["errors"].append({"path": str(path), "line": line_number,
                                             "reason": "INVALID_UTF8", "error": str(exc)})
                    continue
                header = _HEADER_RE.match(text)
                if header:
                    headers.append({"line": line_number, "header": header.group(1)})
                parsed = _parse_localisation_line(text)
                if parsed is None or parsed[0] not in target_keys:
                    continue
                key, value, version = parsed
                decoded = _decode_candidate(value)
                decoded["key"] = key
                decoded["entry_version"] = version
                decoded["line"] = line_number
                decoded["relative_path"] = relative
                decoded["source_layer"] = layer["layer"]
                decoded["language_headers"] = [item["header"] for item in headers]
                decoded["raw_value_text"] = value
                decoded["raw_line_sha256"] = _sha256_bytes(raw_line)
                decoded["dynamic_tokens"] = sorted(set(_TOKEN_RE.findall(value)))
                entries.append(decoded)
                hits.append({
                    "key": key,
                    "relative_path": relative,
                    "absolute_path": str(path),
                    "source_layer": layer["layer"],
                    "layer_order": layer["order"],
                    "line": line_number,
                    "file_sha256": None,
                    "file_size_bytes": size,
                    "language_headers": [item["header"] for item in headers],
                    "entry": decoded,
                })
        file_digest = digest.hexdigest()
        manifest.append({"relative_path": relative, "size_bytes": size, "sha256": file_digest,
                         "line_count": line_count, "language_headers": headers})
        for hit in hits:
            if hit["relative_path"] == relative and hit["source_layer"] == layer["layer"]:
                hit["file_sha256"] = file_digest
        if entries:
            result["target_hit_files"].append({
                "relative_path": relative,
                "absolute_path": str(path),
                "size_bytes": size,
                "sha256": file_digest,
                "encoding": encoding,
                "line_count": line_count,
                "language_headers": headers,
                "entry_count": len(entries),
            })
        result["files_scanned"] += 1
        result["bytes_scanned"] += size
    result["file_manifest_sha256"] = _sha256_bytes(_canonical(manifest).encode("utf-8"))
    result["manifest_file_count"] = len(manifest)
    result["target_entries"] = hits
    return result


def _enabled_layers(context: dict[str, Any]) -> list[dict[str, Any]]:
    game_root = context.get("game_root")
    if not isinstance(game_root, str) or not game_root:
        raise ValueError("MissionDefinitionIndex did not provide game_root")
    layers = [{"layer": "basegame", "order": 0, "root": game_root,
               "source_kind": "basegame", "descriptor": None,
               "descriptor_sha256": None, "replace_paths": []}]
    for index, item in enumerate(context.get("enabled_mods", []), 1):
        if not isinstance(item, dict) or not isinstance(item.get("root"), str):
            raise ValueError("enabled mod stack has no resolved root")
        layers.append({
            "layer": f"enabled_mod[{index - 1}]",
            "order": index,
            "root": item["root"],
            "source_kind": "enabled_mod",
            "descriptor": item.get("descriptor"),
            "descriptor_sha256": item.get("descriptor_sha256"),
            "name": item.get("name"),
            "replace_paths": item.get("replace_paths", []),
        })
    return layers


def _target_records(index: MissionDefinitionIndex, root_ids: list[str]) -> tuple[list[dict[str, Any]], list[str]]:
    roots = index.roots(root_ids)
    records: list[dict[str, Any]] = []
    task_ids: list[str] = []
    for root in roots:
        source = root.get("source", {})
        task_rows: list[dict[str, Any]] = []
        for task in root.get("tasks", []):
            task_id = task.get("task_id")
            if not isinstance(task_id, str):
                raise ValueError("mission index returned a task without a string ID")
            task_ids.append(task_id)
            task_rows.append({
                "task_id": task_id,
                "title_key": f"{task_id}_title",
                "desc_key": f"{task_id}_desc",
                "definition_line": task.get("source", {}).get("line"),
                "definition_end_line": task.get("source", {}).get("end_line"),
            })
        records.append({
            "root_id": root.get("root_id"),
            "slot": root.get("slot"),
            "source": {
                "path": source.get("path"),
                "absolute_path": source.get("absolute_path"),
                "source_kind": source.get("source_kind"),
                "source": source.get("source"),
                "sha256": source.get("sha256"),
                "size_bytes": source.get("size"),
                "line": source.get("line"),
                "end_line": source.get("end_line"),
                "encoding": source.get("encoding"),
            },
            "tasks": task_rows,
        })
    if len(records) != EXPECTED_ROOT_COUNT or len(task_ids) != EXPECTED_TASK_COUNT:
        raise ValueError(f"expected {EXPECTED_ROOT_COUNT} roots/{EXPECTED_TASK_COUNT} tasks, got {len(records)}/{len(task_ids)}")
    if len(set(task_ids)) != EXPECTED_TASK_COUNT:
        raise ValueError("target mission task IDs are repeated; refusing ambiguous localization mapping")
    return records, task_ids


def _select_effective(entries: Iterable[dict[str, Any]], target_keys: list[str]) -> dict[str, Any]:
    by_key: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for entry in entries:
        by_key[entry["key"]].append(entry)
    selected: dict[str, Any] = {}
    duplicates: list[dict[str, Any]] = []
    for key in target_keys:
        candidates = sorted(by_key.get(key, []), key=lambda item: (item["layer_order"], item["relative_path"].casefold(), item["line"]))
        if not candidates:
            selected[key] = {"status": "missing", "candidates": []}
            continue
        highest = max(item["layer_order"] for item in candidates)
        same_layer = [item for item in candidates if item["layer_order"] == highest]
        if len(same_layer) != 1:
            duplicates.append({"key": key, "layer_order": highest,
                               "candidates": same_layer})
            selected[key] = {"status": "ambiguous_same_layer_duplicate", "candidates": candidates}
            continue
        selected[key] = {
            "status": "selected_by_later_layer",
            "selected": same_layer[0],
            "candidates": candidates,
        }
    return {"selected": selected, "duplicates": duplicates}


def _codec_source_record() -> dict[str, Any]:
    digest, size = _sha256_file(CODEC_SOURCE)
    return {
        "path": str(CODEC_SOURCE),
        "sha256": digest,
        "size_bytes": size,
        "existing_codec": EU4_ESCAPE_CODEC,
        "markers": ["0x10", "0x11", "0x12", "0x13"],
        "static_note": "native_text.decode_native_text 正确处理原始 EU4 escape 字节；本地化文件还需要报告中单独记录的 UTF-8 文本到 CP1252 字节逆变换。",
    }


def build_report() -> dict[str, Any]:
    root_ids, snapshot_record = _snapshot_roots()
    index = MissionDefinitionIndex()
    context = index.context()
    if context.get("status") != "ready" or context.get("game_version") != SUPPORTED_VERSION:
        raise ValueError(f"MissionDefinitionIndex is not ready for {SUPPORTED_VERSION}: {context.get('reasons')}")
    root_records, task_ids = _target_records(index, root_ids)
    target_keys = [f"{task_id}_{suffix}" for task_id in task_ids for suffix in ("title", "desc")]
    layers = _enabled_layers(context)
    total_counter = [0]
    layer_reports = [_scan_layer(layer, set(target_keys), total_counter) for layer in layers]
    all_entries = [
        entry
        for layer_report in layer_reports
        for entry in layer_report.get("target_entries", [])
    ]
    selection = _select_effective(all_entries, target_keys)
    task_reports: list[dict[str, Any]] = []
    for task_id in task_ids:
        title = selection["selected"][f"{task_id}_title"]
        desc = selection["selected"][f"{task_id}_desc"]
        task_reports.append({
            "script_id": task_id,
            "title_key": f"{task_id}_title",
            "desc_key": f"{task_id}_desc",
            "title": title,
            "desc": desc,
        })
    effective_counts: dict[str, int] = defaultdict(int)
    decoded_counts = {"title": 0, "desc": 0}
    dynamic_tokens: set[str] = set()
    for row in task_reports:
        for kind in ("title", "desc"):
            selected = row[kind].get("selected") if row[kind].get("status") == "selected_by_later_layer" else None
            if selected is None:
                continue
            effective_counts[selected["source_layer"]] += 1
            entry = selected.get("entry", {})
            if entry.get("status") == "decoded_candidate":
                decoded_counts[kind] += 1
            dynamic_tokens.update(entry.get("dynamic_tokens", []))

    codec_probe: dict[str, Any] = {}
    sample = selection["selected"].get("fra_liberate_norm_title")
    if sample and sample.get("selected"):
        entry = sample["selected"]["entry"]
        value = entry.get("raw_value_text")
        if isinstance(value, str):
            codec_probe = {
                "sample_key": "fra_liberate_norm_title",
                "source_layer": sample["selected"].get("source_layer"),
                "direct_eu4_escape_on_utf8_bytes": _direct_codec_probe(value),
                "on_disk_bridge": _decode_candidate(value),
                "static_note": "直接把 UTF-8 文件 payload 交给 eu4_escape 会得到错误文本；先按文件表示逆变换后可得到静态候选。两者都不证明当前游戏语言选择。",
            }

    mission_context = {
        "status": context.get("status"),
        "mode": context.get("mode"),
        "context_scope": context.get("context_scope"),
        "game_version": context.get("game_version"),
        "game_version_raw": context.get("game_version_raw"),
        "supported_versions": context.get("supported_versions"),
        "configuration_sha256": context.get("configuration_sha256"),
        "config_sha256": context.get("config_sha256"),
        "definitions_sha256": context.get("definitions_sha256"),
        "configuration_files": context.get("configuration_files", []),
        "enabled_mods": context.get("enabled_mods", []),
        "resolved_root_count": context.get("root_count"),
        "target_source_files": sorted({
            root["source"]["absolute_path"]: root["source"]
            for root in root_records
            if root.get("source", {}).get("absolute_path")
        }.values(), key=lambda item: str(item.get("absolute_path"))),
    }
    return {
        "schema": "information.loaded_tasks.localization_source_review.v1",
        "status": "static_review_complete",
        "evidence_kind": "ordinary_bounded_static_file_scan",
        "scope": {
            "country": TARGET_COUNTRY,
            "script_ids_are_names": False,
            "native_query_performed": False,
            "game_process_read": False,
            "rea_or_ghidra_used": False,
            "save_file_read": False,
            "runtime_language_selection_verified": False,
            "user_visible_text_verified": False,
        },
        "limits": {
            "max_localisation_file_bytes": MAX_LOCALISATION_FILE_BYTES,
            "max_total_scan_bytes": MAX_TOTAL_SCAN_BYTES,
            "max_line_bytes": MAX_LINE_BYTES,
            "max_files_per_layer": MAX_FILES_PER_LAYER,
            "actual_total_scan_bytes": total_counter[0],
        },
        "recorded_target_snapshot": snapshot_record,
        "mission_definition_index": mission_context,
        "target_roots": root_records,
        "target_task_count": len(task_ids),
        "target_key_count": len(target_keys),
        "enabled_stack_layers": layers,
        "localisation_layers": layer_reports,
        "precedence": {
            "order": [layer["layer"] for layer in layers],
            "rule_used_for_static_review": "basegame first, then enabled_mod order from dlc_load.json; a later layer uniquely defining a key is selected",
            "same_layer_duplicate_policy": "ambiguous and not selected",
            "engine_merge_semantics_verified": False,
            "effective_selection": selection["selected"],
            "same_layer_duplicates": selection["duplicates"],
        },
        "tasks": task_reports,
        "coverage": {
            "task_count": len(task_ids),
            "expected_title_desc_keys": len(target_keys),
            "keys_with_unique_effective_source": sum(1 for item in selection["selected"].values() if item.get("status") == "selected_by_later_layer"),
            "missing_keys": [key for key, item in selection["selected"].items() if item.get("status") == "missing"],
            "ambiguous_keys": [key for key, item in selection["selected"].items() if item.get("status") == "ambiguous_same_layer_duplicate"],
            "decoded_title_candidates": decoded_counts["title"],
            "decoded_desc_candidates": decoded_counts["desc"],
            "effective_entries_by_layer": dict(effective_counts),
            "dynamic_tokens": sorted(dynamic_tokens),
        },
        "codec_source": _codec_source_record(),
        "codec_probe": codec_probe,
        "unresolved": [
            "本报告没有读取运行中的语言设置或本地化缓存，不能证明 l_english 当前被游戏选中。",
            "静态解码候选没有证明 UI tooltip 的最终格式化、国家/君主替换值或 DLC 分支选择。",
            "dynamic_tokens 只记录字符串中的占位符，不对 Root/Monarch 等上下文求值。",
            "任务 script_id 与用户可见名称是两个不同字段；缺少本地化条目时不能用 script_id 猜名称。",
        ],
    }


def main() -> int:
    try:
        report = build_report()
        OUTPUT.parent.mkdir(parents=True, exist_ok=True)
        OUTPUT.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({
            "output": str(OUTPUT),
            "task_count": report["target_task_count"],
            "keys": report["target_key_count"],
            "total_scan_bytes": report["limits"]["actual_total_scan_bytes"],
            "missing": len(report["coverage"]["missing_keys"]),
            "ambiguous": len(report["coverage"]["ambiguous_keys"]),
        }, ensure_ascii=False))
        return 0
    except Exception as exc:
        print(f"localization research failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
