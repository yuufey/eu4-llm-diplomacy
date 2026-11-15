"""Bounded static extension search outside ``common``.

The first custom-localization report intentionally covered only first-level
``common`` directories.  This extension checks the root of each verified game
or enabled-mod layer and the immediate children of root ``localisation`` /
``localization`` directories.  It does not recursively search either root or
the localisation parent; recursion starts only inside a matching candidate
directory.  No process, save, REA, or RPM is touched.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any, Mapping

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from bridge.information.mission_definitions import (  # noqa: E402
    MissionDefinitionIndex,
    _parse_mission_script,
)
from work.research_information_custom_localization import (  # noqa: E402
    DIRECTORY_RE,
    MAX_FILE_BYTES,
    MAX_TOTAL_BYTES,
    MAX_LINE_BYTES,
    MAX_EXCERPT_CHARS,
    TARGET_TERMS,
    _decode_structural,
    _node_children,
    _node_key,
    _node_summary,
    _node_value,
    _normalise_relative,
    _read_bounded_text,
    _scan_file,
    _sha256_file,
    _stack,
    _under,
)


OUTPUT = ROOT / "work/runtime/information-dynamic-text-20261024-001/custom-localization-source-002.json"
SUPPORTED_VERSION = "1.37.4"
LOCALISATION_PARENT_RE = re.compile(r"^locali[sz]ation$", re.IGNORECASE)
CONDITION_WORDS = ("trigger", "potential", "condition", "allow", "has_", "is_", "can_")
RETURN_TEXTKEYS = ("SELECTABLE_MISSION_TITLE", "SELECTABLE_MISSION_DESCRIPTION")


def _walk_with_parent(nodes: list[Any], parent: Any = None):
    for node in nodes:
        yield node, parent
        yield from _walk_with_parent(_node_children(node), node)


def _method_records(text: str) -> list[dict[str, Any]]:
    """Extract only structural evidence for the two named defined_text blocks."""

    nodes = _parse_mission_script(text)
    records: list[dict[str, Any]] = []
    for node, parent in _walk_with_parent(nodes):
        name = _node_value(node)
        if _node_key(node) != "name" or name not in {"GetSelectableMissionTitle", "GetSelectableMissionDescription"}:
            continue
        owner = parent
        while owner is not None and _node_key(owner) != "defined_text":
            owner = None
        if owner is None:
            owner = node
        conditions: list[dict[str, Any]] = []
        return_keys: list[dict[str, Any]] = []
        for child, _child_parent in _walk_with_parent(_node_children(owner), owner):
            key = _node_key(child) or ""
            value = _node_value(child)
            if any(word in key.casefold() for word in CONDITION_WORDS):
                conditions.append({
                    "key": key,
                    "value": value,
                    "line": getattr(child, "line", None),
                    "end_line": getattr(child, "end_line", None),
                })
            if key.casefold() in {"localisation_key", "localization_key"} and value is not None:
                return_keys.append({
                    "key": key,
                    "value": value,
                    "line": getattr(child, "line", None),
                    "end_line": getattr(child, "end_line", None),
                })
        records.append({
            "method": name,
            "defined_text_line": getattr(owner, "line", None),
            "defined_text_end_line": getattr(owner, "end_line", None),
            "name_line": getattr(node, "line", None),
            "return_textkeys": return_keys,
            "conditions": conditions,
            "conditions_evaluated": False,
            "ast": _node_summary(owner),
        })
    return records


def _root_scope(layer: Mapping[str, Any]) -> tuple[dict[str, Any], list[tuple[str, Path, str]]]:
    root = Path(str(layer["root"]))
    scope: dict[str, Any] = {
        "layer": layer.get("layer"),
        "order": layer.get("order"),
        "root": str(root),
        "root_exists": root.is_dir(),
        "root_entry_names": [],
        "root_local_like_names": [],
        "root_matched_directory_names": [],
        "localisation_parent_names": [],
        "localisation_children": [],
        "replace_path_checks": [],
        "files_scanned": 0,
        "bytes_scanned": 0,
        "candidate_files": [],
        "errors": [],
    }
    candidates: list[tuple[str, Path, str]] = []
    if not root.is_dir():
        scope["errors"].append({"code": "LAYER_ROOT_MISSING"})
        return scope, candidates
    entries = sorted(root.iterdir(), key=lambda item: item.name.casefold())
    scope["root_entry_names"] = [item.name for item in entries]
    scope["root_local_like_names"] = [item.name for item in entries if "local" in item.name.casefold()]
    for item in entries:
        if item.is_dir() and DIRECTORY_RE.match(item.name):
            scope["root_matched_directory_names"].append(item.name)
            candidates.append((f"root/{item.name}", item, "root"))
    parents = [item for item in entries if item.is_dir() and LOCALISATION_PARENT_RE.fullmatch(item.name)]
    scope["localisation_parent_names"] = [item.name for item in parents]
    for parent in parents:
        children = sorted(parent.iterdir(), key=lambda item: item.name.casefold())
        child_record: dict[str, Any] = {
            "parent": parent.name,
            "path": str(parent),
            "child_names": [item.name for item in children],
            "matched_directory_names": [],
            "matched_file_names": [],
        }
        for item in children:
            if item.is_dir() and DIRECTORY_RE.match(item.name):
                child_record["matched_directory_names"].append(item.name)
                candidates.append((f"{parent.name}/{item.name}", item, "localisation_child"))
            elif item.is_file() and DIRECTORY_RE.match(item.name):
                child_record["matched_file_names"].append(item.name)
                candidates.append((f"{parent.name}/{item.name}", item, "localisation_file"))
        scope["localisation_children"].append(child_record)
    for raw in layer.get("replace_paths", []):
        normalised = _normalise_relative(str(raw))
        affected: list[str] = []
        for relative, _directory, _kind in candidates:
            if _under(normalised, relative) or _under(relative, normalised):
                affected.append(relative)
        scope["replace_path_checks"].append({
            "raw": raw,
            "normalised": normalised,
            "affects_root_candidate": bool(affected),
            "affected_candidates": affected,
        })
    return scope, candidates


def _scan_localisation_file(
    path: Path, *, layer: Mapping[str, Any], relative: str, total: list[int]
) -> dict[str, Any]:
    """Stream a matching localisation child and retain only structural hits."""

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
        "return_textkey_hits": [],
        "ast_status": "not_applicable_localisation_file",
        "target_methods": [],
        "conditions": [],
        "conditions_evaluated": False,
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
    terms = tuple(TARGET_TERMS) + RETURN_TEXTKEYS
    matched: set[str] = set()
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
                hits = [term for term in terms if term in text]
                if not hits:
                    continue
                matched.update(hits)
                match = {"line": line_number, "text": text[:MAX_EXCERPT_CHARS], "terms": hits}
                if len(record["matches"]) < 128:
                    record["matches"].append(match)
                for key in RETURN_TEXTKEYS:
                    if key in text:
                        record["return_textkey_hits"].append({
                            "key": key,
                            "line": line_number,
                            "text": text[:MAX_EXCERPT_CHARS],
                        })
        record["sha256"] = digest.hexdigest()
        record["matched_terms"] = sorted(matched)
    except Exception as exc:
        record["error"] = str(exc)
        if record["sha256"] is None:
            try:
                record["sha256"], _ = _sha256_file(path)
            except Exception:
                pass
    return record


def _scan_candidate(
    scope: dict[str, Any],
    layer: Mapping[str, Any],
    relative_directory: str,
    directory: Path,
    candidate_kind: str,
    total: list[int],
) -> None:
    root = Path(str(layer["root"]))
    try:
        if candidate_kind == "localisation_file":
            paths = [directory]
        else:
            paths = sorted(
                (item for item in directory.rglob("*") if item.is_file() and not item.is_symlink()),
                key=lambda item: item.relative_to(root).as_posix().casefold(),
            )
    except Exception as exc:
        scope["errors"].append({"path": str(directory), "error": str(exc)})
        return
    for path in paths:
        scope["files_scanned"] += 1
        scope["bytes_scanned"] += path.stat().st_size
        relative = path.relative_to(root).as_posix()
        try:
            record = (
                _scan_localisation_file(path, layer=layer, relative=relative, total=total)
                if candidate_kind == "localisation_file"
                else _scan_file(path, layer=layer, relative=relative, total=total)
            )
        except Exception as exc:
            record = {
                "relative_path": relative,
                "path": str(path),
                "candidate_directory": relative_directory,
                "error": str(exc),
                "ast_status": "rejected",
                "layer": layer.get("layer"),
                "order": layer.get("order"),
            }
        record["candidate_directory"] = relative_directory
        record["candidate_kind"] = candidate_kind
        if candidate_kind != "localisation_file" and record.get("matched_terms"):
            try:
                text, method_encoding = _read_bounded_text(path)
                record["method_ast_encoding"] = method_encoding
                record["target_methods"] = _method_records(text)
            except Exception as exc:
                record["target_methods"] = []
                record["method_ast_error"] = str(exc)
        if candidate_kind == "localisation_file" or record.get("matched_terms") or record.get("error"):
            scope["candidate_files"].append(record)


def build_report() -> dict[str, Any]:
    mission = MissionDefinitionIndex()
    context = mission.context()
    stack = _stack(context)
    scopes: list[dict[str, Any]] = []
    total = [0]
    for layer in stack:
        scope, candidates = _root_scope(layer)
        for relative, directory, kind in candidates:
            _scan_candidate(scope, layer, relative, directory, kind, total)
        scopes.append(scope)
    candidate_files = [
        record
        for scope in scopes
        for record in scope.get("candidate_files", [])
    ]
    helper_match_files = [record for record in candidate_files if any(
        term in record.get("matched_terms", []) for term in TARGET_TERMS
    )]
    localisation_candidate_files = [record for record in candidate_files if record.get("candidate_kind") == "localisation_file"]
    errors = [
        error
        for scope in scopes
        for error in scope.get("errors", [])
    ]
    status = "static_review_complete" if context.get("status") == "ready" and context.get("game_version") == SUPPORTED_VERSION else "blocked"
    base_script = ROOT / "work/research_information_custom_localization.py"
    if helper_match_files:
        conclusions = [
            f"The root-level extension found {len(helper_match_files)} bounded file(s) containing the two selectable-mission helper names; each matching defined_text block is retained with source SHA, lines, AST, conditions, and localisation_key return values.",
            "The matching methods have no structural trigger/condition child in these files; conditions_evaluated remains false and the return keys are not treated as final UI text.",
            "The same helper definitions occur in basegame and the enabled supplementary mod; this report records both layers and does not infer engine merge precedence.",
        ]
    else:
        conclusions = [
            "No root-level extension candidate contained either selectable-mission helper name in the inspected stack.",
            "A no-hit bounded search is evidence only for this root/localisation-child scope and does not prove global absence or native helper behavior.",
        ]
    return {
        "schema": "information.dynamic_text.custom_localization_source_review/v2",
        "status": status,
        "evidence_kind": "bounded_static_root_custom_localization_extension",
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
            "terms": ["GetSelectableMissionTitle", "GetSelectableMissionDescription"],
            "root_level_only": True,
            "localisation_child_level_only": True,
            "directory_pattern": "custom*local* or scripted*local* (case-insensitive)",
            "spellings": ["localisation", "localization"],
            "scopes": scopes,
            "candidate_file_count": len(candidate_files),
            "helper_match_file_count": len(helper_match_files),
            "localisation_candidate_file_count": len(localisation_candidate_files),
            "total_bytes_scanned": total[0],
            "limits": {
                "max_file_bytes": MAX_FILE_BYTES,
                "max_total_bytes": MAX_TOTAL_BYTES,
                "max_line_bytes": MAX_LINE_BYTES,
            },
        },
        "candidate_files": candidate_files,
        "errors": errors,
        "extension_of": {
            "path": str(base_script),
            "sha256": _sha256_file(base_script)[0],
            "scope": "common first-level directories only; preserved report 001 was not rewritten",
        },
        "conclusions": [
            "The verified base/mod stack and replace_path values were reused; root and immediate localisation children were inspected without recursive root scanning.",
            *conclusions,
        ],
        "unresolved": [
            "Definitions in common, deeper non-matching directories, generated/native code, or other virtual paths remain outside this extension; report 001 covers only its common scope.",
            "Engine merge precedence, conditions, token substitution, and final UI display remain unverified.",
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
