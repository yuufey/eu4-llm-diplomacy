"""Bounded static search for custom/scripted localization helper definitions.

This report supplements the earlier common/scripted_* search.  It examines only
the first-level directories under ``common`` whose names contain ``local`` and
whose names begin with ``custom`` or ``scripted`` (both localisation and
localization spellings are accepted).  It uses the already verified mission
configuration for the active base/mod stack and records replace_path values;
it does not inspect a process, call REA/RPM, read saves, or evaluate scripts.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any, Iterable, Mapping

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from bridge.information.mission_definitions import (  # noqa: E402
    MissionDefinitionIndex,
    _parse_mission_script,
)


OUTPUT = ROOT / "work/runtime/information-dynamic-text-20261024-001/custom-localization-source-001.json"
SUPPORTED_VERSION = "1.37.4"
TARGET_TERMS = ("GetSelectableMissionTitle", "GetSelectableMissionDescription")
MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_TOTAL_BYTES = 128 * 1024 * 1024
MAX_LINE_BYTES = 1024 * 1024
MAX_EXCERPT_CHARS = 4096
MAX_MATCHES_PER_FILE = 128
MAX_AST_NODES = 256
MAX_AST_DEPTH = 12
DIRECTORY_RE = re.compile(r"^(?:custom.*local|scripted.*local)", re.IGNORECASE)


def _sha256_file(path: Path, limit: int = MAX_FILE_BYTES) -> tuple[str, int]:
    digest = hashlib.sha256()
    total = 0
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            total += len(chunk)
            if total > limit:
                raise ValueError(f"file exceeds {limit} bytes: {path}")
            digest.update(chunk)
    return digest.hexdigest(), total


def _json_hash(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _normalise_relative(value: str) -> str:
    value = value.replace("\\", "/").strip()
    while value.startswith("./"):
        value = value[2:]
    return value.rstrip("/")


def _under(relative: str, prefix: str) -> bool:
    relative = _normalise_relative(relative)
    prefix = _normalise_relative(prefix)
    return not prefix or relative == prefix or relative.startswith(prefix + "/")


def _decode_structural(raw_line: bytes, first: bool) -> tuple[str, str]:
    try:
        if first:
            return raw_line.decode("utf-8-sig"), "utf-8-sig"
        return raw_line.decode("utf-8"), "utf-8"
    except UnicodeDecodeError:
        return raw_line.decode("latin-1"), "latin-1_structural_only"


def _read_bounded_text(path: Path) -> tuple[str, str]:
    size = path.stat().st_size
    if size > MAX_FILE_BYTES:
        raise ValueError(f"file exceeds {MAX_FILE_BYTES} bytes: {path}")
    chunks: list[bytes] = []
    total = 0
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            total += len(chunk)
            if total > MAX_FILE_BYTES:
                raise ValueError(f"file exceeds {MAX_FILE_BYTES} bytes: {path}")
            chunks.append(chunk)
    raw = b"".join(chunks)
    try:
        return raw.decode("utf-8-sig"), "utf-8-sig"
    except UnicodeDecodeError:
        return raw.decode("latin-1"), "latin-1_structural_only"


def _node_key(node: Any) -> str | None:
    value = getattr(node, "key", None)
    return value if isinstance(value, str) else None


def _node_value(node: Any) -> str | None:
    value = getattr(node, "value", None)
    return value if isinstance(value, str) else None


def _node_children(node: Any) -> list[Any]:
    children = getattr(node, "children", None)
    return list(children) if isinstance(children, list) else []


def _node_summary(node: Any, *, depth: int = 0, budget: list[int] | None = None) -> dict[str, Any]:
    """Keep AST evidence bounded while retaining source positions and values."""

    if budget is None:
        budget = [MAX_AST_NODES]
    budget[0] -= 1
    result: dict[str, Any] = {
        "key": _node_key(node),
        "line": getattr(node, "line", None),
        "end_line": getattr(node, "end_line", None),
        "kind": getattr(node, "kind", None),
        "assignment": getattr(node, "assignment", None),
    }
    value = _node_value(node)
    if value is not None:
        result["value"] = value[:MAX_EXCERPT_CHARS]
    children = _node_children(node)
    result["child_count"] = len(children)
    if depth < MAX_AST_DEPTH and children and budget[0] > 0:
        result["children"] = [
            _node_summary(child, depth=depth + 1, budget=budget)
            for child in children[: budget[0]]
        ]
    elif children:
        result["children_truncated"] = True
    return result


def _walk_nodes(nodes: Iterable[Any]) -> Iterable[Any]:
    for node in nodes:
        yield node
        yield from _walk_nodes(_node_children(node))


def _semantic_extract(nodes: list[Any]) -> dict[str, Any]:
    """Report structural condition/text-key candidates without evaluating them."""

    conditions: list[dict[str, Any]] = []
    return_textkeys: list[dict[str, Any]] = []
    condition_words = ("trigger", "potential", "condition", "allow", "has_", "is_", "can_")
    text_words = ("text", "title", "description", "localisation", "localization", "tooltip")
    for node in _walk_nodes(nodes):
        key = _node_key(node) or ""
        value = _node_value(node)
        lowered_key = key.casefold()
        if any(word in lowered_key for word in condition_words):
            conditions.append({
                "key": key,
                "value": value,
                "line": getattr(node, "line", None),
                "end_line": getattr(node, "end_line", None),
            })
        if value is not None and (
            any(word in lowered_key for word in text_words)
            or any(term in value for term in TARGET_TERMS)
            or value.endswith(("_title", "_desc", "_description"))
        ):
            return_textkeys.append({
                "key": key,
                "value": value,
                "line": getattr(node, "line", None),
                "end_line": getattr(node, "end_line", None),
            })
    return {
        "conditions": conditions[:MAX_MATCHES_PER_FILE],
        "conditions_truncated": len(conditions) > MAX_MATCHES_PER_FILE,
        "return_textkeys": return_textkeys[:MAX_MATCHES_PER_FILE],
        "return_textkeys_truncated": len(return_textkeys) > MAX_MATCHES_PER_FILE,
        "conditions_evaluated": False,
    }


def _scan_file(path: Path, *, layer: Mapping[str, Any], relative: str, total: list[int]) -> dict[str, Any]:
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
        "static_extract": {
            "conditions": [],
            "return_textkeys": [],
            "conditions_evaluated": False,
        },
        "error": None,
        "layer": layer.get("layer"),
        "order": layer.get("order"),
        "source_kind": layer.get("source_kind"),
        "replace_paths": list(layer.get("replace_paths", [])),
    }
    if size > MAX_FILE_BYTES:
        record.update(error="FILE_TOO_LARGE", ast_status="rejected")
        return record
    total[0] += size
    if total[0] > MAX_TOTAL_BYTES:
        raise ValueError("custom localization scan exceeds total byte cap")
    digest = hashlib.sha256()
    matched_terms: set[str] = set()
    matches: list[dict[str, Any]] = []
    try:
        with path.open("rb") as stream:
            for line_number, raw_line in enumerate(stream, 1):
                record["line_count"] = line_number
                if len(raw_line) > MAX_LINE_BYTES:
                    raise ValueError(f"line {line_number} exceeds {MAX_LINE_BYTES} bytes")
                digest.update(raw_line)
                text, encoding = _decode_structural(raw_line, line_number == 1)
                if record["encoding"] is None:
                    record["encoding"] = encoding
                text = text.rstrip("\r\n")
                hits = [term for term in TARGET_TERMS if term in text]
                if hits:
                    matched_terms.update(hits)
                    if len(matches) < MAX_MATCHES_PER_FILE:
                        matches.append({"line": line_number, "text": text[:MAX_EXCERPT_CHARS], "terms": hits})
        record["sha256"] = digest.hexdigest()
        record["matched_terms"] = sorted(matched_terms)
        record["matches"] = matches
        if not matched_terms:
            record["ast_status"] = "no_matching_term"
            return record
        text, encoding = _read_bounded_text(path)
        record["encoding"] = encoding
        nodes = _parse_mission_script(text)
        record["ast_status"] = "parsed"
        matched_nodes = [
            node for node in _walk_nodes(nodes)
            if any(term in (_node_key(node) or "") or term in (_node_value(node) or "") for term in TARGET_TERMS)
        ]
        record["ast_matches"] = [
            _node_summary(node, budget=[MAX_AST_NODES]) for node in matched_nodes[:MAX_MATCHES_PER_FILE]
        ]
        record["ast_matches_truncated"] = len(matched_nodes) > MAX_MATCHES_PER_FILE
        record["static_extract"] = _semantic_extract(nodes)
    except Exception as exc:
        record["error"] = str(exc)
        if record["sha256"] is None:
            try:
                record["sha256"], _ = _sha256_file(path)
            except Exception:
                pass
    return record


def _stack(context: Mapping[str, Any]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    game_root = context.get("game_root")
    if isinstance(game_root, str) and game_root:
        result.append({
            "layer": "basegame",
            "order": 0,
            "root": game_root,
            "source_kind": "basegame",
            "descriptor": None,
            "descriptor_sha256": None,
            "replace_paths": [],
        })
    for order, item in enumerate(context.get("enabled_mods", []), 1):
        if not isinstance(item, Mapping) or not isinstance(item.get("root"), str):
            continue
        result.append({
            "layer": f"enabled_mod[{order - 1}]",
            "order": order,
            "root": item["root"],
            "source_kind": "enabled_mod",
            "descriptor": item.get("descriptor"),
            "descriptor_sha256": item.get("descriptor_sha256"),
            "name": item.get("name"),
            "replace_paths": list(item.get("replace_paths", [])),
        })
    return result


def _directories_for_layer(layer: Mapping[str, Any]) -> tuple[dict[str, Any], list[Path]]:
    root = Path(str(layer["root"]))
    common = root / "common"
    scope: dict[str, Any] = {
        "layer": layer.get("layer"),
        "order": layer.get("order"),
        "root": str(root),
        "relative_directory": "common",
        "directory": str(common),
        "exists": common.is_dir(),
        "common_directory_names": [],
        "local_like_directory_names": [],
        "matched_directory_names": [],
        "replace_path_checks": [],
        "files_scanned": 0,
        "bytes_scanned": 0,
        "candidate_files": [],
        "errors": [],
    }
    if not common.is_dir():
        scope["errors"].append({"code": "COMMON_DIRECTORY_MISSING"})
        return scope, []
    directories = sorted((item for item in common.iterdir() if item.is_dir()), key=lambda item: item.name.casefold())
    scope["common_directory_names"] = [item.name for item in directories]
    scope["local_like_directory_names"] = [item.name for item in directories if "local" in item.name.casefold()]
    selected = [item for item in directories if DIRECTORY_RE.match(item.name)]
    scope["matched_directory_names"] = [item.name for item in selected]
    for raw in layer.get("replace_paths", []):
        normalised = _normalise_relative(str(raw))
        scope["replace_path_checks"].append({
            "raw": raw,
            "normalised": normalised,
            "affects_common": _under(normalised, "common"),
            "affects_matched_directory": any(
                _under(normalised, f"common/{item.name}") or _under(f"common/{item.name}", normalised)
                for item in selected
            ),
        })
    return scope, selected


def build_report() -> dict[str, Any]:
    mission = MissionDefinitionIndex()
    context = mission.context()
    stack = _stack(context)
    scopes: list[dict[str, Any]] = []
    total = [0]
    candidate_files: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    for layer in stack:
        scope, directories = _directories_for_layer(layer)
        for directory in directories:
            paths = sorted(
                (item for item in directory.rglob("*") if item.is_file() and not item.is_symlink()),
                key=lambda item: item.relative_to(Path(str(layer["root"]))).as_posix().casefold(),
            )
            for path in paths:
                scope["files_scanned"] += 1
                scope["bytes_scanned"] += path.stat().st_size
                relative = path.relative_to(Path(str(layer["root"]))).as_posix()
                try:
                    record = _scan_file(path, layer=layer, relative=relative, total=total)
                except Exception as exc:
                    record = {
                        "relative_path": relative,
                        "path": str(path),
                        "error": str(exc),
                        "ast_status": "rejected",
                        "layer": layer.get("layer"),
                        "order": layer.get("order"),
                    }
                    errors.append(record)
                if record.get("matched_terms") or record.get("error"):
                    scope["candidate_files"].append(record)
                    if record.get("matched_terms"):
                        candidate_files.append(record)
                if record.get("error"):
                    scope["errors"].append({"path": str(path), "error": record["error"]})
        scopes.append(scope)
    status = "static_review_complete" if context.get("status") == "ready" and context.get("game_version") == SUPPORTED_VERSION else "blocked"
    return {
        "schema": "information.dynamic_text.custom_localization_source_review/v1",
        "status": status,
        "evidence_kind": "bounded_static_custom_localization_search",
        "mode": "static",
        "runtime_game_read": False,
        "rea_used": False,
        "rpm_used": False,
        "save_read": False,
        "game_version": context.get("game_version"),
        "game_version_raw": context.get("game_version_raw"),
        "configuration_sha256": context.get("configuration_sha256"),
        "definitions_sha256": context.get("definitions_sha256"),
        "stack": stack,
        "search": {
            "terms": list(TARGET_TERMS),
            "relative_root": "common",
            "directory_pattern": "custom*local* or scripted*local* (case-insensitive)",
            "spellings": ["localisation", "localization"],
            "scopes": scopes,
            "candidate_file_count": len(candidate_files),
            "total_bytes_scanned": total[0],
            "limits": {
                "max_file_bytes": MAX_FILE_BYTES,
                "max_total_bytes": MAX_TOTAL_BYTES,
                "max_line_bytes": MAX_LINE_BYTES,
                "max_ast_nodes": MAX_AST_NODES,
            },
        },
        "candidate_files": candidate_files,
        "errors": errors,
        "conclusions": [
            "The verified base/mod stack and its replace_path values were read from MissionDefinitionIndex; no enabled layer was reordered or inferred from file contents.",
            "Only matching first-level common custom/scripted localization directories were searched; no script condition was evaluated and no return text key was promoted to a runtime result.",
            "A missing matching directory or a no-hit bounded search does not prove that the native helper has no definition elsewhere.",
        ],
        "unresolved": [
            "Native or generated definitions outside these exact common first-level directories remain unresolved.",
            "Engine merge precedence, branch conditions, token substitution, and final UI display remain unverified.",
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
        "status": report["status"],
        "candidate_file_count": report["search"]["candidate_file_count"],
        "total_bytes_scanned": report["search"]["total_bytes_scanned"],
    }, ensure_ascii=False))
    return 0 if report["status"] == "static_review_complete" and not report["errors"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
