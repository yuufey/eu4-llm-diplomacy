"""Bounded static research for dynamic FRA mission localisation.

This script joins the already verified static mission/localisation indexes and
then searches only the explicit ``common/scripted_*`` directories in the
basegame and enabled mod layers.  It records rule AST and source provenance;
it does not evaluate triggers, resolve dynamic tokens, inspect a process, or
claim that a UI rendered any candidate text.
"""

from __future__ import annotations

from collections import Counter
import hashlib
import json
from pathlib import Path
import sys
from typing import Any, Iterable, Mapping

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from bridge.information.localization import (  # noqa: E402
    ENCODING_EU4_ESCAPE_CP1252,
    LocalizationIndex,
)
from bridge.information.mission_definitions import (  # noqa: E402
    MissionDefinitionIndex,
    _node_json,
    _parse_mission_script,
)


OUTPUT = ROOT / "work/runtime/information-localization-20261024-001/dynamic-localization-source-review.json"
TARGET_COUNTRY = "FRA"
LANGUAGE = "l_english"
ENCODING = ENCODING_EU4_ESCAPE_CP1252
SUPPORTED_VERSION = "1.37.4"
MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_TOTAL_BYTES = 128 * 1024 * 1024
MAX_LINE_BYTES = 1024 * 1024
MAX_CONTEXT_LINES = 4
MAX_EXCERPT_CHARS = 4096

TARGET_ROOTS = [
    "french_missions_1", "french_missions_1_blank_hre", "french_missions_1_Continuation_a",
    "french_missions_2", "french_missions_2_blank_hre", "french_missions_2_Continuation_b",
    "french_missions_3", "french_missions_3_blank_hre",
    "french_missions_3_continuation_after_hre_missions", "french_missions_3_normal_continued",
    "french_missions_4_normal", "french_missions_4_branching",
    "french_missions_4_normal_continuation", "french_missions_4_normal_contiuation",
    "french_missions_5_normal", "french_missions_5_branching",
    "french_missions_5_continuation_normal_1", "fra_missions_5_continuation",
]

SEARCH_TERMS = (
    "GetSelectableMissionTitle",
    "GetSelectableMissionDescription",
    "selectable_mission_trigger_tt",
    "selectable_mission",
)
SCRIPTED_DIRECTORY_NAMES = (
    "common/scripted_localisation",
    "common/scripted_localization",
    "common/scripted_triggers",
    "common/scripted_functions",
    "common/scripted_effects",
)


def _sha256_file(path: Path, limit: int = MAX_FILE_BYTES) -> tuple[str, int]:
    digest = hashlib.sha256()
    total = 0
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            total += len(block)
            if total > limit:
                raise ValueError(f"file exceeds {limit} bytes: {path}")
            digest.update(block)
    return digest.hexdigest(), total


def _json_hash(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _compact_source(source: Mapping[str, Any] | None) -> dict[str, Any]:
    if not isinstance(source, Mapping):
        return {}
    return {
        key: source.get(key)
        for key in ("path", "absolute_path", "source_kind", "source", "sha256", "size", "line", "end_line", "encoding")
        if key in source
    }


def _children(node: Any) -> list[Mapping[str, Any]]:
    if not isinstance(node, Mapping):
        return []
    children = node.get("children")
    return [item for item in children if isinstance(item, Mapping)] if isinstance(children, list) else []


def _leaf_dependencies(node: Any, path: tuple[str, ...] = ()) -> list[dict[str, Any]]:
    """Flatten structural AST leaves without applying any condition."""

    if not isinstance(node, Mapping):
        return []
    key = node.get("key") if isinstance(node.get("key"), str) else "?"
    current = path + (key,)
    children = _children(node)
    if children:
        result: list[dict[str, Any]] = []
        for child in children:
            result.extend(_leaf_dependencies(child, current))
        return result
    return [{
        "path": list(current),
        "key": key,
        "value": node.get("value"),
        "operator": node.get("operator") or node.get("assignment"),
        "line": node.get("line"),
        "end_line": node.get("end_line"),
        "ast_semantics": node.get("ast_semantics"),
    }]


def _mission_stack(context: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "game_version": context.get("game_version"),
        "game_version_raw": context.get("game_version_raw"),
        "game_root": context.get("game_root"),
        "user_data": context.get("user_data"),
        "configuration_files": [
            {key: item.get(key) for key in ("path", "kind", "sha256") if key in item}
            for item in context.get("configuration_files", [])
            if isinstance(item, Mapping)
        ],
        "enabled_mods": [
            {
                "order": order,
                "descriptor": item.get("descriptor"),
                "descriptor_sha256": item.get("descriptor_sha256"),
                "root": item.get("root"),
                "replace_paths": list(item.get("replace_paths", [])),
            }
            for order, item in enumerate(context.get("enabled_mods", []))
            if isinstance(item, Mapping)
        ],
    }


def _target_records(index: MissionDefinitionIndex) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]], list[str]]:
    roots = index.roots(TARGET_ROOTS)
    root_records: list[dict[str, Any]] = []
    task_map: dict[str, dict[str, Any]] = {}
    task_ids: list[str] = []
    for root in roots:
        root_record = {
            "root_id": root.get("root_id"),
            "slot": root.get("slot"),
            "generic": root.get("generic"),
            "potential": root.get("potential"),
            "potential_on_load": root.get("potential_on_load"),
            "potential_dependencies": _leaf_dependencies(root.get("potential")),
            "source": _compact_source(root.get("source")),
            "tasks": [],
        }
        for task in root.get("tasks", []):
            if not isinstance(task, Mapping):
                continue
            task_id = task.get("task_id")
            if not isinstance(task_id, str):
                continue
            task_record = {
                "task_id": task_id,
                "position": task.get("position"),
                "required_missions": task.get("required_missions"),
                "trigger": task.get("trigger"),
                "effect": task.get("effect"),
                "required_mission_dependencies": _leaf_dependencies(task.get("required_missions")),
                "trigger_dependencies": _leaf_dependencies(task.get("trigger")),
                "effect_dependencies": _leaf_dependencies(task.get("effect")),
                "source": _compact_source(task.get("source")),
            }
            root_record["tasks"].append(task_record)
            if task_id in task_map:
                raise ValueError(f"duplicate task ID in target roots: {task_id}")
            task_map[task_id] = {"root_id": root.get("root_id"), "task": task_record}
            task_ids.append(task_id)
        root_records.append(root_record)
    if len(root_records) != 18 or len(task_ids) != 61 or len(set(task_ids)) != len(task_ids):
        raise ValueError(f"target scope changed: roots={len(root_records)} tasks={len(task_ids)}")
    return root_records, task_map, task_ids


def _read_script_text(path: Path) -> tuple[str, str]:
    raw = path.read_bytes()
    if len(raw) > MAX_FILE_BYTES:
        raise ValueError(f"file exceeds {MAX_FILE_BYTES} bytes: {path}")
    try:
        return raw.decode("utf-8-sig"), "utf-8-sig"
    except UnicodeDecodeError:
        return raw.decode("latin-1"), "latin-1_structural_only"


def _node_matches(node: Any, terms: tuple[str, ...]) -> bool:
    if not isinstance(node, Mapping):
        return False
    for field in ("key", "value", "raw_key", "raw_value"):
        value = node.get(field)
        if isinstance(value, str) and any(term in value for term in terms):
            return True
    return any(_node_matches(child, terms) for child in _children(node))


def _matched_nodes(nodes: Iterable[Any], terms: tuple[str, ...]) -> list[dict[str, Any]]:
    matches: list[dict[str, Any]] = []
    for node in nodes:
        if _node_matches(node, terms):
            matches.append(_node_json(node))
        matches.extend(_matched_nodes(_children(node), terms))
    return matches


def _scan_script_file(path: Path, *, layer: Mapping[str, Any], relative: str, total: list[int]) -> dict[str, Any]:
    size = path.stat().st_size
    record: dict[str, Any] = {
        "relative_path": relative,
        "path": str(path),
        "size_bytes": size,
        "sha256": None,
        "encoding": None,
        "line_count": 0,
        "matched_terms": [],
        "matches": [],
        "ast_status": "not_attempted",
        "ast_matches": [],
        "error": None,
        "layer": layer.get("layer"),
        "order": layer.get("order"),
        "source_kind": layer.get("source_kind"),
    }
    if size > MAX_FILE_BYTES:
        record.update(error="FILE_TOO_LARGE", ast_status="rejected")
        return record
    total[0] += size
    if total[0] > MAX_TOTAL_BYTES:
        raise ValueError("scripted localisation scan exceeds total byte cap")
    digest = hashlib.sha256()
    matched_terms: set[str] = set()
    context_lines: list[tuple[int, str]] = []
    try:
        with path.open("rb") as stream:
            for line_number, raw_line in enumerate(stream, 1):
                record["line_count"] = line_number
                if len(raw_line) > MAX_LINE_BYTES:
                    raise ValueError(f"line {line_number} exceeds {MAX_LINE_BYTES} bytes")
                digest.update(raw_line)
                try:
                    text = raw_line.decode("utf-8-sig" if line_number == 1 else "utf-8")
                    if record["encoding"] is None:
                        record["encoding"] = "utf-8-sig" if line_number == 1 and raw_line.startswith(b"\xef\xbb\xbf") else "utf-8"
                except UnicodeDecodeError:
                    text = raw_line.decode("latin-1")
                    record["encoding"] = "latin-1_structural_only"
                text = text.rstrip("\r\n")
                hits = [term for term in SEARCH_TERMS if term in text]
                if hits:
                    matched_terms.update(hits)
                    context_lines.append((line_number, text[:MAX_EXCERPT_CHARS]))
        record["sha256"] = digest.hexdigest()
        record["matched_terms"] = sorted(matched_terms)
        if context_lines:
            record["matches"] = [
                {"line": line, "text": text}
                for line, text in context_lines[:128]
            ]
            try:
                text, encoding = _read_script_text(path)
                record["encoding"] = encoding
                nodes = _parse_mission_script(text)
                record["ast_status"] = "parsed"
                record["ast_matches"] = _matched_nodes(nodes, tuple(sorted(matched_terms)))[:64]
            except Exception as exc:
                record["ast_status"] = "parse_failed"
                record["error"] = str(exc)
        else:
            record["ast_status"] = "no_matching_term"
    except Exception as exc:
        record["error"] = str(exc)
        if record["sha256"] is None:
            try:
                record["sha256"], _ = _sha256_file(path)
            except Exception:
                pass
    return record


def _scripted_search(context: Mapping[str, Any]) -> dict[str, Any]:
    layers: list[dict[str, Any]] = []
    game_root = context.get("game_root")
    if isinstance(game_root, str):
        layers.append({
            "layer": "basegame", "order": 0, "root": game_root,
            "source_kind": "basegame", "source": "basegame",
            "replace_paths": [],
        })
    for order, item in enumerate(context.get("enabled_mods", []), 1):
        if isinstance(item, Mapping) and isinstance(item.get("root"), str):
            layers.append({
                "layer": f"enabled_mod[{order - 1}]", "order": order,
                "root": item["root"], "source_kind": "enabled_mod",
                "source": item.get("descriptor") or item.get("root"),
                "replace_paths": list(item.get("replace_paths", [])),
            })
    total = [0]
    scopes: list[dict[str, Any]] = []
    candidates: list[dict[str, Any]] = []
    for layer in layers:
        root = Path(str(layer["root"]))
        for relative_dir in SCRIPTED_DIRECTORY_NAMES:
            directory = root / Path(relative_dir)
            scope = {
                "layer": layer["layer"], "order": layer["order"],
                "root": str(root), "relative_directory": relative_dir,
                "directory": str(directory), "exists": directory.is_dir(),
                "files_scanned": 0, "bytes_scanned": 0,
                "errors": [],
            }
            if directory.is_dir():
                paths = sorted(
                    [item for item in directory.rglob("*.txt") if item.is_file()],
                    key=lambda item: item.relative_to(root).as_posix().casefold(),
                )
                for path in paths:
                    scope["files_scanned"] += 1
                    scope["bytes_scanned"] += path.stat().st_size
                    relative = path.relative_to(root).as_posix()
                    record = _scan_script_file(path, layer=layer, relative=relative, total=total)
                    if record.get("matched_terms") or record.get("error"):
                        candidates.append(record)
                    if record.get("error"):
                        scope["errors"].append({"path": str(path), "error": record["error"]})
            scopes.append(scope)
    return {
        "terms": list(SEARCH_TERMS),
        "directories": list(SCRIPTED_DIRECTORY_NAMES),
        "scopes": scopes,
        "candidate_files": candidates,
        "total_bytes_scanned": total[0],
        "limits": {
            "max_file_bytes": MAX_FILE_BYTES,
            "max_total_bytes": MAX_TOTAL_BYTES,
            "max_line_bytes": MAX_LINE_BYTES,
        },
        "static_definition_result": (
            "found_candidate_files" if candidates else "no_matching_static_definition_in_scoped_directories"
        ),
        "unresolved": [
            "GetSelectableMissionTitle/Description definition and override order are not established by the scoped script search when no candidate is found.",
            "Mission trigger/effect and root potential inputs are recorded as structural AST only; no condition is evaluated.",
        ] if not candidates else [
            "Candidate scripts are structural evidence only; no dynamic function or UI display behavior is inferred.",
        ],
    }


def _branch_records(task_map: Mapping[str, Mapping[str, Any]], dynamic_tasks: Iterable[str]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    # The seven selectable branch tasks are the only dynamic title/description
    # candidates whose script IDs carry the explicit branch prefix.  Other
    # target tasks can contain ordinary scope placeholders and are retained in
    # ``dynamic_token_occurrences`` without being mislabeled as branch inputs.
    branch_ids = {
        task_id for task_id in dynamic_tasks
        if isinstance(task_id, str) and task_id.startswith("fra_branch_mission_")
    }
    for task_id in sorted(branch_ids):
        item = task_map.get(task_id)
        if not item:
            records.append({"task_id": task_id, "status": "task_definition_missing"})
            continue
        task = item["task"]
        records.append({
            "task_id": task_id,
            "root_id": item.get("root_id"),
            "status": "structural_only",
            "position": task.get("position"),
            "required_missions": task.get("required_missions"),
            "trigger": task.get("trigger"),
            "effect": task.get("effect"),
            "required_mission_dependencies": task.get("required_mission_dependencies", []),
            "trigger_dependencies": task.get("trigger_dependencies", []),
            "effect_dependencies": task.get("effect_dependencies", []),
            "source": task.get("source"),
            "conditions_evaluated": False,
        })
    return records


def build_report() -> dict[str, Any]:
    mission_index = MissionDefinitionIndex()
    mission_context = mission_index.context()
    if mission_context.get("status") != "ready" or mission_context.get("game_version") != SUPPORTED_VERSION:
        raise RuntimeError(f"mission source unavailable: {mission_context.get('reasons')}")
    root_records, task_map, task_ids = _target_records(mission_index)

    localisation = LocalizationIndex()
    localisation_context = localisation.context()
    keys = [f"{task_id}_{suffix}" for task_id in task_ids for suffix in ("title", "desc")]
    lookup = localisation.lookup(keys, language=LANGUAGE, encoding=ENCODING)
    entries = lookup.get("entries", {})
    token_occurrences: list[dict[str, Any]] = []
    token_classes: Counter[str] = Counter()
    malformed: list[dict[str, Any]] = []
    effective_sources: Counter[tuple[str, str, str]] = Counter()
    for task_id in task_ids:
        for suffix in ("title", "desc"):
            key = f"{task_id}_{suffix}"
            entry = entries.get(key, {})
            for token in entry.get("dynamic_tokens", []) if isinstance(entry, Mapping) else []:
                token_classes[str(token)] += 1
                token_occurrences.append({
                    "task_id": task_id,
                    "key": key,
                    "kind": suffix,
                    "token": token,
                    "entry_status": entry.get("status"),
                    "decoded_status": entry.get("decoded_status"),
                    "raw_text": entry.get("raw_text"),
                    "decoded_text": entry.get("decoded_text"),
                    "line": entry.get("line"),
                    "line_sha256": entry.get("raw", {}).get("line_sha256"),
                    "file_sha256": entry.get("file_sha256"),
                    "source": entry.get("source"),
                })
            if entry.get("malformed_dynamic_markers"):
                malformed.append({
                    "task_id": task_id, "key": key,
                    "markers": list(entry.get("malformed_dynamic_markers", [])),
                    "status": entry.get("status"),
                })
            source = entry.get("source") if isinstance(entry, Mapping) else None
            if isinstance(source, Mapping):
                effective_sources[(str(source.get("layer")), str(source.get("relative_path")), str(source.get("sha256")))] += 1

    helper_keys = ["selectable_mission_trigger_tt"]
    helper_lookup = localisation.lookup(helper_keys, language=LANGUAGE, encoding=ENCODING)
    scripted_search = _scripted_search(mission_context)
    dynamic_task_ids = [item["task_id"] for item in token_occurrences]
    return {
        "schema": "information.dynamic_localization_source_review/v1",
        "evidence_kind": "bounded_static_dynamic_localization_research",
        "mode": "static",
        "runtime_game_read": False,
        "rea_used": False,
        "save_read": False,
        "country": TARGET_COUNTRY,
        "game_version": mission_context.get("game_version"),
        "language": LANGUAGE,
        "encoding": ENCODING,
        "scope": {
            "target_root_count": len(root_records),
            "target_task_count": len(task_ids),
            "target_key_count": len(keys),
            "keys_sha256": _json_hash(keys),
            "target_roots": TARGET_ROOTS,
            "target_task_ids": task_ids,
        },
        "stack": _mission_stack(mission_context),
        "mission_context": {
            "status": mission_context.get("status"),
            "configuration_sha256": mission_context.get("configuration_sha256"),
            "definitions_sha256": mission_context.get("definitions_sha256"),
            "reasons": mission_context.get("reasons", []),
        },
        "localisation_context": {
            "status": localisation_context.get("status"),
            "configuration_sha256": localisation_context.get("configuration_sha256"),
            "file_count": localisation_context.get("file_count"),
            "total_bytes": localisation_context.get("total_bytes"),
            "reasons": localisation_context.get("reasons", []),
            "warnings": localisation_context.get("warnings", []),
            "layers": localisation_context.get("localisation_layers", []),
        },
        "lookup": {
            "status": lookup.get("status"),
            "complete": lookup.get("complete"),
            "entry_status_counts": dict(Counter(
                str(item.get("status")) for item in entries.values() if isinstance(item, Mapping)
            )),
            "decoded_status_counts": dict(Counter(
                str(item.get("decoded_status")) for item in entries.values() if isinstance(item, Mapping)
            )),
            "missing_keys": [key for key in keys if key not in entries or entries[key].get("reason") == "LOCALISATION_KEY_MISSING"],
            "malformed_target_entries": malformed,
            "effective_sources": [
                {"layer": layer, "relative_path": path, "sha256": digest, "entry_count": count}
                for (layer, path, digest), count in sorted(effective_sources.items())
            ],
        },
        "dynamic_token_classes": [
            {"token": token, "occurrence_count": count}
            for token, count in sorted(token_classes.items())
        ],
        "dynamic_token_occurrences": token_occurrences,
        "helper_key_lookup": {
            "requested": helper_keys,
            "status": helper_lookup.get("status"),
            "entries": helper_lookup.get("entries", {}),
            "interpretation": "static localisation provenance only; not proof of helper execution or UI display",
        },
        "roots": root_records,
        "branch_task_inputs": _branch_records(task_map, dynamic_task_ids),
        "scripted_definition_search": scripted_search,
        "conclusions": [
            "The target 122 title/description entries were read from the explicit enabled stack with a caller-selected language and codec.",
            "Dynamic tokens are recorded as unresolved templates; no token value, trigger, branch, or UI display was evaluated.",
            "The scoped common/scripted_* search does not establish a static definition or override order for the selectable-mission helper when it finds no candidate file.",
        ],
        "unresolved": [
            "Root.GetSelectableMissionTitle and Root.GetSelectableMissionDescription may be native or otherwise outside the scoped static script directories.",
            "Branch potential, required missions, trigger tooltip and effect tooltip inputs remain structural; their runtime truth is unknown.",
            "A decoded candidate does not prove the active game language or final rendered Chinese text.",
        ],
        "research_script": {
            "path": str(Path(__file__)),
            "sha256": _sha256_file(Path(__file__))[0],
        },
    }


def main() -> int:
    report = build_report()
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({
        "output": str(OUTPUT),
        "target_tasks": report["scope"]["target_task_count"],
        "target_keys": report["scope"]["target_key_count"],
        "dynamic_occurrences": len(report["dynamic_token_occurrences"]),
        "dynamic_classes": len(report["dynamic_token_classes"]),
        "scripted_search": report["scripted_definition_search"]["static_definition_result"],
        "scripted_bytes": report["scripted_definition_search"]["total_bytes_scanned"],
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
