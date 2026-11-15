"""Publish batch 70 rivals metadata from pinned, normalized receipts.

Default invocation is inert. The publication spec supplies receipt pins and
the current installation identity; this helper does not freeze, test, query,
or contact the game or MCP.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import tempfile
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / "work/runtime/information-diplomacy-state-20261028-001"
DEFAULT_SPEC = STAGE / "publication-spec-001.json"
CHUNK_BYTES = 1024 * 1024
MAX_JSON_BYTES = 16 * 1024 * 1024
EXPECTED_COVERAGE = {"available": 62, "partial": 164, "planned": 171}
MARKER = "<!-- batch70-country-rivals-summary:start -->"
END_MARKER = "<!-- batch70-country-rivals-summary:end -->"
TOP_DOCUMENTS = ("HANDOFF.md", "README(agent).md",
                 "docs/信息导出与订阅开发计划.md")


class PublicationError(RuntimeError):
    pass


def _root_path(value: str | Path) -> Path:
    path = Path(value)
    if not path.is_absolute():
        path = ROOT / path
    resolved = path.resolve()
    try:
        resolved.relative_to(ROOT.resolve())
    except ValueError as exc:
        raise PublicationError(f"path_outside_workspace:{value}") from exc
    return resolved


def _pin(path: Path) -> dict[str, Any]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        while chunk := stream.read(CHUNK_BYTES):
            size += len(chunk)
            digest.update(chunk)
    return {"path": path.resolve().relative_to(ROOT.resolve()).as_posix(),
            "bytes": size, "sha256": digest.hexdigest()}


def _read_json(path: Path) -> Any:
    if not path.is_file():
        raise PublicationError(f"missing_json:{path}")
    if path.stat().st_size > MAX_JSON_BYTES:
        raise PublicationError(f"json_over_bound:{path}:{path.stat().st_size}")
    try:
        with path.open("r", encoding="utf-8-sig") as stream:
            return json.load(stream)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PublicationError(f"invalid_json:{path}:{type(exc).__name__}") from exc


def _write_new(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("x", encoding="utf-8", newline="\n") as stream:
            json.dump(value, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
    except FileExistsError as exc:
        raise PublicationError(f"output_exists:{path}") from exc


def _copy_pinned_source(source: Path, destination: Path,
                        expected_sha256: str) -> dict[str, Any]:
    if not source.is_file() or _pin(source)["sha256"] != expected_sha256:
        raise PublicationError(f"backup_source_pin_mismatch:{source}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    try:
        with source.open("rb") as src, destination.open("xb") as dst:
            while chunk := src.read(CHUNK_BYTES):
                dst.write(chunk)
    except FileExistsError as exc:
        raise PublicationError(f"backup_exists:{destination}") from exc
    copied = _pin(destination)
    if copied["sha256"] != expected_sha256:
        raise PublicationError(f"backup_hash_mismatch:{source}")
    return copied


def _pointer(value: Any, pointer: str) -> Any:
    if pointer in ("", "/"):
        return value
    if not isinstance(pointer, str) or not pointer.startswith("/"):
        raise PublicationError(f"invalid_json_pointer:{pointer!r}")
    current = value
    for part in pointer[1:].split("/"):
        part = part.replace("~1", "/").replace("~0", "~")
        if isinstance(current, dict) and part in current:
            current = current[part]
        elif isinstance(current, list) and part.isdecimal() and int(part) < len(current):
            current = current[int(part)]
        else:
            raise PublicationError(f"json_pointer_missing:{pointer}")
    return current


def _verify_inputs(spec: dict[str, Any]):
    if spec.get("schema") != "information.country_rivals.publication_spec.v1":
        raise PublicationError("invalid_publication_spec_schema")
    if spec.get("stage") != STAGE.relative_to(ROOT).as_posix():
        raise PublicationError("publication_spec_stage_mismatch")
    inputs = spec.get("inputs")
    if not isinstance(inputs, dict):
        raise PublicationError("publication_spec_inputs_missing")
    required = {"installation", "source_audit", "source_freeze",
                "source_postverify", "regression_comparison", "full_log", "live",
                "database_snapshot_verification"}
    if not required.issubset(inputs):
        raise PublicationError("publication_spec_missing_inputs:" +
                               ",".join(sorted(required - set(inputs))))
    paths, records, pins = {}, {}, {}
    for key, item in inputs.items():
        if (not isinstance(key, str) or not isinstance(item, dict)
                or not isinstance(item.get("path"), str)
                or not re.fullmatch(r"[0-9a-f]{64}", str(item.get("sha256", "")))):
            raise PublicationError(f"invalid_input_pin:{key}")
        input_format = item.get("format", "text" if key == "full_log" else "json")
        if key == "full_log" and input_format != "text":
            raise PublicationError(f"input_format_mismatch:{key}")
        if key in required - {"full_log"} and input_format != "json":
            raise PublicationError(f"input_format_mismatch:{key}")
        if input_format not in {"json", "text", "binary"}:
            raise PublicationError(f"unsupported_input_format:{key}")
        path = _root_path(item["path"])
        if not path.is_file():
            raise PublicationError(f"missing_input:{key}")
        actual = _pin(path)
        if actual["sha256"] != item["sha256"]:
            raise PublicationError(f"input_hash_mismatch:{key}")
        if "bytes" in item and actual["bytes"] != item["bytes"]:
            raise PublicationError(f"input_size_mismatch:{key}")
        paths[key], pins[key] = path, actual
        if input_format == "json":
            records[key] = _read_json(path)
    _require_identity(spec, records, pins)
    _require_qualification(spec, records)
    frozen_paths = {str(item.get("source", {}).get("path", "")).replace("\\", "/")
                    for item in records["source_freeze"].get("files", [])
                    if isinstance(item, dict)}
    helpers = ("work/finalize_information_country_rivals.py",
               "work/archive_information_country_rivals.py")
    if frozen_paths.intersection(helpers):
        raise PublicationError("publication_helper_in_runtime_freeze")
    return paths, records, pins


def _require_identity(spec: dict[str, Any], records: dict[str, Any],
                      pins: dict[str, dict[str, Any]]) -> None:
    identity = spec.get("identity")
    installation = records.get("installation")
    live = records.get("live")
    if not isinstance(identity, dict) or not isinstance(installation, dict) or not isinstance(live, dict):
        raise PublicationError("identity_inputs_missing")
    installation_pointers = spec.get("identity_installation_pointers", {})
    live_pointers = spec.get("identity_live_pointers", {})
    for name in ("pid", "creation_filetime", "session_id", "game_sha256", "dll_sha256"):
        expected = identity.get(name)
        installation_value = _pointer(
            installation, installation_pointers.get(name, "/" + name))
        live_value = _pointer(live, live_pointers.get(name, "/identity/" + name))
        if expected is None or installation_value != expected or live_value != expected:
            raise PublicationError(f"installation_live_spec_identity_mismatch:{name}")
    install_sha = pins["installation"]["sha256"]
    if identity.get("installation_sha256") != install_sha:
        raise PublicationError("installation_pin_identity_mismatch")
    live_installation_path_pointer = spec.get("live_installation_path_pointer")
    if live_installation_path_pointer:
        live_installation_path = _root_path(_pointer(live, live_installation_path_pointer))
        spec_installation_path = _root_path(spec["inputs"]["installation"]["path"])
        if live_installation_path != spec_installation_path:
            raise PublicationError("live_installation_path_mismatch")
    else:
        live_installation_sha_pointer = spec.get("live_installation_sha_pointer", "/identity/installation_sha256")
        if _pointer(live, live_installation_sha_pointer) != install_sha:
            raise PublicationError("live_installation_pin_mismatch")
    if identity.get("date_raw") is not None:
        date = _pointer(records["live"], spec.get("identity_date_pointer", "/before_control/date_raw"))
        if date != identity["date_raw"]:
            raise PublicationError("live_date_identity_mismatch")
    if identity.get("game_version") is not None:
        version = _pointer(records["live"], spec.get("identity_version_pointer", "/build_manifest/version"))
        if version != identity["game_version"]:
            raise PublicationError("live_version_identity_mismatch")


def _require_qualification(spec: dict[str, Any], records: dict[str, Any]) -> None:
    freeze, post = records["source_freeze"], records["source_postverify"]
    comparison, live = records["regression_comparison"], records["live"]
    if (freeze.get("status") != "passed" or freeze.get("batch") != 70
            or freeze.get("count") != 184 or len(freeze.get("files", [])) != 184):
        raise PublicationError("production_source_freeze_not_184_passed")
    if (post.get("status") != "passed" or post.get("batch") != 70
            or post.get("count") != 184 or post.get("current_matches_snapshots") is not True):
        raise PublicationError("production_source_postverify_failed")
    freeze_pin = spec["inputs"]["source_freeze"]
    post_freeze = post.get("freeze")
    if (not isinstance(post_freeze, dict)
            or post_freeze.get("sha256") != freeze_pin.get("sha256")
            or post_freeze.get("path") != str(freeze_pin["path"]).replace("\\", "/")):
        raise PublicationError("postverify_freeze_pin_mismatch")
    if comparison.get("no_new_bad") is not True or comparison.get("baseline_batch") != 69:
        raise PublicationError("full_comparison_not_batch69_clean")
    for key in ("new_failure_nodes", "new_test_failures"):
        if key in comparison and comparison[key] != []:
            raise PublicationError(f"full_comparison_has_new_failures:{key}")
    if live.get("status") != "passed" or live.get("server_exit_code") != 0:
        raise PublicationError("live_acceptance_not_passed")
    checks = live.get("checks")
    if not isinstance(checks, dict) or not checks or any(value is not True for value in checks.values()):
        raise PublicationError("live_acceptance_checks_not_all_true")
    db_receipt = records["database_snapshot_verification"]
    if (db_receipt.get("status") != "passed" or db_receipt.get("batch") != 70
            or db_receipt.get("all_snapshots_closed_immutable_ro_verified") is not True
            or db_receipt.get("source_wal_shm_deleted") is not False
            or db_receipt.get("source_databases_modified") is not False):
        raise PublicationError("immutable_database_snapshot_verification_failed")
    backups = db_receipt.get("backups")
    if not isinstance(backups, list) or len(backups) != 2:
        raise PublicationError("immutable_database_snapshot_count_mismatch")
    if db_receipt.get("fresh_snapshot_count", 2) != 2:
        raise PublicationError("immutable_database_snapshot_count_mismatch")
    names = set()
    for index, item in enumerate(backups):
        snapshot = item.get("snapshot") if isinstance(item, dict) else None
        if (not isinstance(snapshot, dict) or item.get("integrity") != "ok"
                or item.get("snapshot_verification") != "mode=ro&immutable=1"
                or item.get("contextlib_closing") is not True):
            raise PublicationError(f"invalid_immutable_database_snapshot:{index}")
        snapshot_path = _root_path(snapshot.get("path", ""))
        if (snapshot_path.parent != STAGE / "final-database-snapshots" / "live-acceptance-001"
                or _pin(snapshot_path) != snapshot):
            raise PublicationError(f"immutable_database_snapshot_pin_mismatch:{index}")
        source_path = _root_path(item.get("source_path", ""))
        source_pin = _pin(source_path)
        if (source_pin["bytes"] != item.get("source_bytes")
                or source_pin["sha256"] != item.get("source_sha256")):
            raise PublicationError(f"database_source_pin_mismatch:{index}")
        names.add(snapshot_path.name)
    if names != {"diplomacy.sqlite3", "information.sqlite3"}:
        raise PublicationError("unexpected_live_database_snapshot_names")
    if records["source_audit"].get("status") != "passed":
        raise PublicationError("rivals_source_audit_not_passed")
    publication = spec.get("publication", {})
    if publication.get("country") != "FRA" or publication.get("nonempty_live_reader_accepted") is not False:
        raise PublicationError("nonempty_live_reader_scope_must_remain_unaccepted")
    if not isinstance(publication.get("live_value_pointer"), str):
        raise PublicationError("live_value_pointer_missing")


def _adapter_topic() -> dict[str, Any]:
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    from bridge.information.composite import CompositeSource
    from bridge.information.country_rivals import NativeCountryRivalsSource
    from bridge.information.sources import DiplomacySource

    primary = DiplomacySource(observer="FRA")
    return next(topic for topic in CompositeSource(
        primary, [NativeCountryRivalsSource(primary)]).catalog()
        if topic["topic_id"] == "R03")


def _coverage_counts(matrix: dict[str, Any]) -> dict[str, int]:
    counts = {"available": 0, "partial": 0, "planned": 0}
    for topic in matrix.get("topics", []):
        for field in topic.get("fields", {}).values():
            status = field.get("coverage")
            if status not in counts:
                raise PublicationError(f"unknown_coverage:{status}")
            counts[status] += 1
    return counts


def _topic_status_counts(matrix: dict[str, Any]) -> dict[str, int]:
    counts = {"available": 0, "partial": 0, "planned": 0}
    for topic in matrix.get("topics", []):
        status = topic.get("status")
        if status not in counts:
            raise PublicationError(f"unknown_topic_status:{status}")
        counts[status] += 1
    return counts


def _full_suite_summary(path: Path) -> str:
    candidate = None
    try:
        with path.open("r", encoding="utf-8-sig", errors="replace") as stream:
            for line in stream:
                if "passed" in line and "failed" in line and " in " in line:
                    candidate = line.strip("= \r\n")
    except OSError as exc:
        raise PublicationError(f"full_log_unreadable:{type(exc).__name__}") from exc
    if not candidate:
        raise PublicationError("full_log_summary_missing")
    return candidate


def _serialized(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def _replace_pinned(path: Path, old_sha: str, content: bytes) -> dict[str, Any]:
    if not path.is_file() or _pin(path)["sha256"] != old_sha:
        raise PublicationError(f"document_changed_before_publish:{path}")
    fd, temporary = tempfile.mkstemp(prefix=path.name + ".", suffix=".publication-tmp",
                                     dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return _pin(path)


def _render(spec: dict[str, Any], live: dict[str, Any], counts: dict[str, int],
            full_summary: str):
    publication = spec["publication"]
    observed = _pointer(live, publication["live_value_pointer"])
    if observed != []:
        raise PublicationError("live_rivals_value_not_sorted_unique_tag_list")
    compact = json.dumps(observed, ensure_ascii=False)
    adjacent_note = publication.get("adjacent_context_note", "")
    if not isinstance(adjacent_note, str):
        raise PublicationError("adjacent_context_note_must_be_text")
    note = (
        f"{MARKER}\n"
        "## 第七十批：本国当前主动指定的宿敌\n\n"
        "R03 rivals 已接通只读查询与周期采样；字段只表示所选国家主动声明的当前宿敌，"
        "不包含历史宿敌、AI候选优先级或其他国家对本国的指定。公开顺序为国家标签升序。\n\n"
        f"本轮实机观察值为 {compact}；只有空列表通过了当前实机验收，非空链尚未通过真实游戏进程验收。"
        "双遍一致性检查不代表原子快照。\n\n"
        f"覆盖为74主题397字段、{counts['available']} available/"
        f"{counts['partial']} partial/{counts['planned']} planned。R03其余字段仍为planned；"
        f"full suite 为 {full_summary}。本批不改变B04战报正文资格，完整阶段2/3/4、"
        "LLM自主订阅与完整B01–B04继续，goal active。\n\n"
        + (adjacent_note + "\n\n" if adjacent_note else "")
        + "接口见[本国主动宿敌只读接口](docs/本国主动指定宿敌只读接口.md)。\n"
        f"{END_MARKER}\n\n"
    )
    limitations = publication.get("limitations", [
        "仅限当前固定版本与已绑定安装身份",
        "非空真实链尚未验收",
        "双遍一致不证明原子快照",
    ])
    interface = (
        "# 本国主动宿敌只读接口\n\n"
        "## 字段范围\n\n"
        "R03 rivals 返回本国当前主动指定的宿敌标签列表，按标签升序排列。"
        "这是本国发出的单向声明，不表示其他国家对本国的指定。\n\n"
        "字段不包含历史宿敌、AI候选优先级、incoming声明、关系动作合法性或宿敌变更建议。"
        "查询不调用原生游戏业务函数，只读取国家宿敌链及目标国家身份数据。\n\n"
        "## 可用范围\n\n"
        f"- 国家：{publication.get('country', 'FRA')}。\n"
        f"- 游戏版本：{publication.get('game_version', '固定版本')}。\n"
        "- 方向：outgoing_declared_by_country。\n"
        "- 有效采样返回known、国家标签数组、unit为country_tags、scale为1、period为current、complete为true。\n"
        "- capture或身份校验失败时不会把部分节点列表发布为已知结果。\n"
        f"- 实机观察：{compact}。\n"
        "- 空链已通过实机验收；非空链目前只有夹具验证，未通过实机验收。\n\n"
        "## 完整性边界\n\n"
        "- 按声明数量读取并要求末节点为空；循环、重复成员、数量不符或身份不一致时拒绝投影。\n"
        "- 双遍一致不证明缓存读取是原子快照。\n- "
        + "；\n- ".join(str(item) for item in limitations) + "。\n"
    )
    return observed, note, interface


def publish(spec_path: Path) -> dict[str, Any]:
    if spec_path.parent.resolve() != STAGE.resolve():
        raise PublicationError("publication_spec_outside_stage")
    spec = _read_json(spec_path)
    paths, receipts, pins = _verify_inputs(spec)
    publication = spec.get("publication")
    if not isinstance(publication, dict):
        raise PublicationError("publication_section_missing")
    outputs = {
        "summary": STAGE / "development-summary-001.json",
        "coverage_update": STAGE / "coverage-update-001.json",
        "coverage_before": STAGE / "coverage-matrix-before-001.json",
    }
    backup_root = STAGE / "publication-document-backups-001"
    interface_path = _root_path(publication.get(
        "interface_path", "docs/本国主动指定宿敌只读接口.md"))
    coverage_path = _root_path(publication.get("coverage_path", "docs/信息字段覆盖.json"))
    doc_paths = {name: _root_path(name) for name in TOP_DOCUMENTS}
    if any(path.exists() for path in (*outputs.values(), interface_path, backup_root)):
        raise PublicationError("publication_output_already_exists")
    if interface_path == coverage_path or coverage_path in doc_paths.values():
        raise PublicationError("publication_path_collision")

    document_pins = spec.get("document_pins")
    if not isinstance(document_pins, dict):
        raise PublicationError("document_pins_missing")
    checked_documents = {"coverage": coverage_path, **doc_paths}
    for key, path in checked_documents.items():
        item = document_pins.get(key)
        if (not isinstance(item, dict) or item.get("path") != path.relative_to(ROOT).as_posix()
                or not re.fullmatch(r"[0-9a-f]{64}", str(item.get("sha256", "")))
                or not path.is_file() or _pin(path)["sha256"] != item["sha256"]):
            raise PublicationError(f"document_pin_mismatch:{key}")
    backup_destinations = {
        key: backup_root / (key.replace("/", "_") + ".original")
        for key in checked_documents
    }

    topic = _adapter_topic()
    fields = topic.get("fields")
    if not isinstance(fields, dict) or "rivals" not in fields:
        raise PublicationError("adapter_catalog_has_no_rivals")
    matrix = _read_json(coverage_path)
    topics = matrix.get("topics")
    if not isinstance(topics, list):
        raise PublicationError("coverage_topics_missing")
    existing = next((item for item in topics if item.get("topic_id") == "R03"), None)
    if not isinstance(existing, dict) or existing.get("fields", {}).get("rivals", {}).get("coverage") != "planned":
        raise PublicationError("R03_rivals_baseline_not_planned")
    before_pin = _pin(coverage_path)
    updated = deepcopy(matrix)
    target = next(item for item in updated["topics"] if item.get("topic_id") == "R03")
    target["fields"]["rivals"] = deepcopy(fields["rivals"])
    target["source"] = topic["source"]
    target_status = topic.get("status")
    if target_status not in {"available", "partial", "planned"}:
        raise PublicationError(f"adapter_topic_status_invalid:{target_status}")
    target["status"] = target_status
    target["triggers"] = list(dict.fromkeys(
        [*target.get("triggers", []), *topic.get("triggers", ["query"])]))
    counts = _coverage_counts(updated)
    if counts != EXPECTED_COVERAGE:
        raise PublicationError(f"unexpected_coverage_counts:{counts}")
    for key in ("counts", "expected_counts"):
        if isinstance(updated.get(key), dict):
            block = updated[key]
            block["field_counts"] = deepcopy(counts)
            block["field_count"] = sum(counts.values())
            block["topic_count"] = len(updated["topics"])
            status_counts = _topic_status_counts(updated)
            block["topic_status_counts"] = status_counts
            block["available_topic_count"] = status_counts["available"]
            block["callable_topic_count"] = status_counts["available"]
    updated["goal_complete"] = False
    coverage_bytes = _serialized(updated)
    after_sha = hashlib.sha256(coverage_bytes).hexdigest()
    full_summary = _full_suite_summary(paths["full_log"])
    observed, note, interface = _render(spec, receipts["live"], counts, full_summary)
    context_roles = publication.get("context_input_roles", [])
    if (not isinstance(context_roles, list)
            or any(not isinstance(name, str) or name not in pins for name in context_roles)):
        raise PublicationError("context_input_roles_invalid")
    updated_docs = {}
    for name, path in doc_paths.items():
        text = path.read_text(encoding="utf-8-sig")
        if MARKER in text or END_MARKER in text:
            raise PublicationError(f"publication_marker_exists:{path}")
        document_note = note.replace("(docs/", "(") if name.startswith("docs/") else note
        updated_docs[name] = document_note.encode("utf-8") + path.read_bytes()
    summary = {
        "schema": "information.country_rivals.development_summary.v1",
        "status": "passed", "batch": 70,
        "publication_spec": _pin(spec_path),
        "qualification": {name: pins[name] for name in (
            "installation", "source_audit", "source_freeze", "source_postverify",
            "regression_comparison", "full_log", "live",
            "database_snapshot_verification")},
        "identity": deepcopy(spec["identity"]),
        "observed_rivals": observed, "observed_empty_list_only": observed == [],
        "nonempty_live_reader_accepted": False,
        "scope": {"field": "rivals", "direction": "outgoing_declared_by_country",
                  "historical_rivals_included": False, "ai_priorities_included": False,
                  "incoming_declarations_included": False, "b04_promoted": False},
        "coverage": counts, "goal_complete": False,
        "full_suite": full_summary,
        "source_audit": pins["source_audit"],
        "context_only_evidence": {name: pins[name] for name in context_roles},
        "database_snapshot_verification": pins["database_snapshot_verification"],
        "database_snapshots": [item["snapshot"] for item in
                               receipts["database_snapshot_verification"]["backups"]],
        "original_documents": {},
        "helper_not_in_runtime_freeze": True,
        "limitations": list(publication.get("limitations", [])),
    }
    coverage_update = {
        "schema": "information.country_rivals.coverage_update.v1",
        "status": "passed", "batch": 70, "before": before_pin,
        "after": {"path": before_pin["path"], "bytes": len(coverage_bytes),
                  "sha256": after_sha},
        "changed_field": "R03.rivals", "new_available_fields": ["rivals"],
        "counts": counts, "goal_complete": False,
    }
    for path in (*outputs.values(), interface_path):
        if path.exists():
            raise PublicationError(f"publication_output_raced:{path}")
    for key, path in checked_documents.items():
        if _pin(path)["sha256"] != document_pins[key]["sha256"]:
            raise PublicationError(f"document_changed_during_preflight:{key}")
    backups = {
        key: _copy_pinned_source(path, backup_destinations[key], document_pins[key]["sha256"])
        for key, path in checked_documents.items()
    }
    summary["original_documents"] = backups
    _write_new(outputs["coverage_before"], matrix)
    _write_new(outputs["summary"], summary)
    _write_new(outputs["coverage_update"], coverage_update)
    with interface_path.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(interface)
    _replace_pinned(coverage_path, document_pins["coverage"]["sha256"], coverage_bytes)
    for name, path in doc_paths.items():
        _replace_pinned(path, document_pins[name]["sha256"], updated_docs[name])
    return {"status": "passed", "batch": 70, "coverage": counts,
            "summary": _pin(outputs["summary"]), "coverage_update": _pin(outputs["coverage_update"]),
            "interface": _pin(interface_path), "runtime_freeze_modified": False}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec", type=Path, default=DEFAULT_SPEC,
                        help="normalized publication spec with receipt pins and current identity")
    parser.add_argument("--run", action="store_true",
                        help="publish only after all qualification and document pins pass")
    args = parser.parse_args()
    if not args.run:
        print(json.dumps({
            "status": "inert", "batch": 70, "spec": args.spec.as_posix(),
            "required_spec_inputs": ["installation", "source_audit", "source_freeze",
                                     "source_postverify", "regression_comparison", "full_log",
                                     "live", "database_snapshot_verification"],
            "required_gates": {"source_freeze": 184, "baseline_batch": 69,
                               "coverage": EXPECTED_COVERAGE},
            "publication": False, "freeze_full_live_or_archive": False,
        }, ensure_ascii=False))
        return 0
    try:
        result = publish(_root_path(args.spec))
    except PublicationError as exc:
        print(json.dumps({"status": "blocked", "error": str(exc)}, ensure_ascii=False))
        return 2
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
