"""只读流式核对国家资源 live 结果与一份历史 EU4 存档。

本 checker 只比较 FRA 的国库和人力。国库复用 R74 经济存档 checker
的 ``countries/<tag>/treasury`` 解析；人力复用 R73 人情/人力存档
checker 的 ``countries/<tag>/manpower`` 解析。存档本身按二进制行流式
读取，不把 43 MB 文件载入内存，也不启动游戏或发送外交查询。
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from work import verify_r73_favor_save as manpower_checker
from work import verify_r74_economic_save as economic_checker
from work.local_config import user_data


SAVE_NAME = "llm_diplomacy_r70_country_money_rejected_20261020.eu4"
EXPECTED_SAVE_SHA256 = (
    "ffa91dbd2a2d544b18d586a895bb9b0c2b90e94ece47b2c74507555b8f58c2e0"
)
OBSERVER = "FRA"
MANUAL_RESULT = Path(
    "work/runtime/information-stage2-20261024-001/live-acceptance-001/manual-result.json"
)
DEFAULT_OUTPUT = Path(
    "work/runtime/information-stage2-20261024-001/save-country-crosscheck.json"
)
MAX_JSON_BYTES = 16 * 1024 * 1024

FIELD_CONTRACT: dict[str, dict[str, Any]] = {
    "treasury": {
        "topic": "N01",
        "unit": "ducats",
        "public_scale": 1000,
        "save_scale": 1000,
        "save_path": "countries/FRA/treasury",
        "save_parser": "work.verify_r74_economic_save.scan_save",
    },
    "manpower": {
        "topic": "N02",
        "unit": "men",
        "public_scale": 1,
        # EU4 serializes manpower as a decimal in thousands; the public
        # country-state projection exposes the resulting integer men value.
        "save_scale": 1000,
        "save_path": "countries/FRA/manpower",
        "save_parser": "work.verify_r73_favor_save.scan",
    },
}


def _resolve_existing(path: Path) -> Path:
    return path.expanduser().resolve(strict=True)


def _default_save() -> Path:
    return _resolve_existing(user_data() / "save games" / SAVE_NAME)


def _load_json(path: Path) -> dict[str, Any]:
    resolved = _resolve_existing(path)
    if resolved.stat().st_size > MAX_JSON_BYTES:
        raise ValueError(f"JSON_INPUT_OVER_LIMIT:{resolved}:{MAX_JSON_BYTES}")
    with resolved.open("r", encoding="utf-8-sig") as stream:
        value = json.load(stream)
    if not isinstance(value, dict):
        raise ValueError(f"manual result must be an object: {resolved}")
    return value


def _int_value(value: object) -> int | None:
    return value if type(value) is int else None


def _manual_field(document: dict[str, Any], field: str) -> dict[str, Any]:
    """Extract one observer-country field without exposing any other country."""

    topic = FIELD_CONTRACT[field]["topic"]
    matches: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for item in document.get("items", []):
        if not isinstance(item, dict) or item.get("topic") != topic:
            continue
        query = item.get("query")
        query_object = query.get("object") if isinstance(query, dict) else None
        if not isinstance(query_object, dict):
            continue
        if query_object.get("type") != "country":
            continue
        if query_object.get("country") != OBSERVER:
            continue
        fields = item.get("fields")
        value = fields.get(field) if isinstance(fields, dict) else None
        if isinstance(value, dict):
            matches.append((item, value))
    if len(matches) != 1:
        raise ValueError(f"expected one {topic}/{field} observer item, found {len(matches)}")

    item, value = matches[0]
    raw_value = _int_value(value.get("value"))
    expected = FIELD_CONTRACT[field]
    errors: list[str] = []
    if raw_value is None:
        errors.append("value is not an integer")
    if value.get("status") != "known":
        errors.append(f"field status is {value.get('status')!r}")
    if value.get("scale") != expected["public_scale"]:
        errors.append(
            f"scale is {value.get('scale')!r}, expected {expected['public_scale']}"
        )
    if value.get("unit") != expected["unit"]:
        errors.append(f"unit is {value.get('unit')!r}, expected {expected['unit']!r}")
    if item.get("complete") is not True:
        errors.append("item is not complete")
    query = item.get("query")
    parameters = query.get("parameters") if isinstance(query, dict) else None
    source = item.get("source")
    return {
        "topic": topic,
        "field": field,
        "value": raw_value,
        "scale": value.get("scale"),
        "unit": value.get("unit"),
        "status": value.get("status"),
        "item_complete": item.get("complete"),
        "source": {
            "name": source.get("name") if isinstance(source, dict) else None,
            "status": source.get("status") if isinstance(source, dict) else None,
            "mode": source.get("mode") if isinstance(source, dict) else None,
            "reference_recipient": (
                parameters.get("reference_recipient")
                if isinstance(parameters, dict)
                else None
            ),
        },
        "errors": errors,
    }


def _save_fields(save_path: Path) -> tuple[dict[str, Any], list[str]]:
    """Run the two existing bounded scanners as separate streaming passes."""

    errors: list[str] = []
    before = save_path.stat()
    treasury_state = economic_checker.scan_save(save_path, None, {OBSERVER})
    treasury_field = economic_checker._treasury_field(
        treasury_state.countries.get(OBSERVER)
    )

    # The R73 scanner needs the expected key to retain only FRA/manpower.
    manpower_expected = {(OBSERVER, None, "manpower"): {"raw": 0, "scale": 1000}}
    manpower_state = manpower_checker.scan(
        save_path, manpower_expected, treasury_state.sha256
    )
    after = save_path.stat()
    if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        errors.append("save changed between the two streaming scanner passes")
    errors.extend(f"treasury scanner: {error}" for error in treasury_state.errors)
    errors.extend(f"manpower scanner: {error}" for error in manpower_state["errors"])

    manpower_field = manpower_state["fields"].get((OBSERVER, None, "manpower"))
    save = {
        "path": str(save_path),
        "file_name": save_path.name,
        "size_bytes": after.st_size,
        "sha256": treasury_state.sha256,
        "expected_sha256": EXPECTED_SAVE_SHA256,
        "sha256_match": treasury_state.sha256.casefold() == EXPECTED_SAVE_SHA256,
        "top_level_date": treasury_state.top_level_date,
        "top_level_save_game": treasury_state.top_level_save_game,
        "target_country": OBSERVER,
        "countries_found": treasury_state.countries_found,
        "countries_complete": treasury_state.countries_complete,
        "final_brace_depth": treasury_state.final_depth,
        "streaming": {
            "passes": 2,
            "hash_passes": 1,
            "memory_strategy": "bounded line streaming; no whole-save string/array",
            "file_mutated_during_scan": bool(errors and any("changed between" in e for e in errors)),
        },
        "fields": {
            "treasury": {
                "save_path": FIELD_CONTRACT["treasury"]["save_path"],
                "line": treasury_field.line if treasury_field is not None else None,
                "decimal": treasury_field.decimal if treasury_field is not None else None,
                "raw": treasury_field.raw if treasury_field is not None else None,
                "unit": FIELD_CONTRACT["treasury"]["unit"],
                "save_scale": FIELD_CONTRACT["treasury"]["save_scale"],
                "public_scale": FIELD_CONTRACT["treasury"]["public_scale"],
                "parser": FIELD_CONTRACT["treasury"]["save_parser"],
            },
            "manpower": {
                "save_path": FIELD_CONTRACT["manpower"]["save_path"],
                "line": manpower_field.get("line") if manpower_field else None,
                "decimal": manpower_field.get("value") if manpower_field else None,
                "raw": manpower_field.get("raw") if manpower_field else None,
                "unit": FIELD_CONTRACT["manpower"]["unit"],
                "save_scale": FIELD_CONTRACT["manpower"]["save_scale"],
                "public_scale": FIELD_CONTRACT["manpower"]["public_scale"],
                "parser": FIELD_CONTRACT["manpower"]["save_parser"],
            },
        },
    }
    if treasury_field is None:
        errors.append("FRA treasury field is absent or duplicated")
    if manpower_field is None:
        errors.append("FRA manpower field is absent or duplicated")
    if not save["sha256_match"]:
        errors.append("save SHA-256 does not match the handoff value")
    if not treasury_state.countries_complete or treasury_state.final_depth != 0:
        errors.append("treasury scanner did not close the countries block")
    if not manpower_state["countries_complete"]:
        errors.append("manpower scanner did not close the countries block")
    return save, errors


def _comparison(field: str, save: dict[str, Any], manual: dict[str, Any]) -> dict[str, Any]:
    saved = save["fields"][field]
    expected = FIELD_CONTRACT[field]
    match = (
        not manual["errors"]
        and saved["raw"] is not None
        and manual["value"] is not None
        and saved["raw"] == manual["value"]
    )
    return {
        "field": field,
        "topic": expected["topic"],
        "unit": expected["unit"],
        "public_scale": expected["public_scale"],
        "save_serialization_scale": saved.get("save_scale"),
        "save_path": expected["save_path"],
        "save_raw": saved["raw"],
        "save_decimal": saved.get("decimal"),
        "manual_raw": manual["value"],
        "match": match,
        "evidence": {
            "save_line": saved.get("line"),
            "manual_item_source": manual.get("source"),
        },
    }


def build_report(save_path: Path, manual_path: Path) -> dict[str, Any]:
    errors: list[str] = []
    save: dict[str, Any]
    try:
        save, save_errors = _save_fields(save_path)
        errors.extend(save_errors)
    except (OSError, UnicodeError, ValueError) as exc:
        save = {
            "path": str(save_path),
            "file_name": save_path.name,
            "sha256_match": False,
            "fields": {
                name: {"save_path": spec["save_path"], "raw": None}
                for name, spec in FIELD_CONTRACT.items()
            },
        }
        errors.append(f"save scan failed: {exc}")

    manual: dict[str, Any] = {
        "path": str(manual_path),
        "fields": {},
        "document_status": None,
        "complete": None,
    }
    try:
        document = _load_json(manual_path)
        context = document.get("context")
        manual.update(
            {
                "document_status": document.get("status"),
                "complete": document.get("complete"),
                "collected_at": document.get("collected_at"),
                "context": {
                    "mode": context.get("mode") if isinstance(context, dict) else None,
                    "observer": context.get("observer") if isinstance(context, dict) else None,
                    "game_date_raw": context.get("game_date_raw") if isinstance(context, dict) else None,
                    "session_id": context.get("session_id") if isinstance(context, dict) else None,
                },
            }
        )
        if document.get("status") != "complete" or document.get("complete") is not True:
            errors.append("manual result document is not complete")
        for field in FIELD_CONTRACT:
            try:
                manual["fields"][field] = _manual_field(document, field)
            except (TypeError, ValueError) as exc:
                manual["fields"][field] = {"field": field, "value": None, "errors": [str(exc)]}
                errors.append(f"manual {field}: {exc}")
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
        errors.append(f"manual result load failed: {exc}")
        for field in FIELD_CONTRACT:
            manual["fields"][field] = {"field": field, "value": None, "errors": [str(exc)]}

    comparisons = [
        _comparison(field, save, manual["fields"][field])
        for field in FIELD_CONTRACT
    ]
    if not all(row["match"] for row in comparisons):
        errors.append("one or more FRA country fields differ between save and manual result")
    status = "passed" if not errors else "failed"
    return {
        "schema": "information_country_save_crosscheck_v1",
        "status": status,
        "observer": OBSERVER,
        "fields_compared": ["treasury", "manpower"],
        "save": save,
        "manual_result": manual,
        "comparisons": comparisons,
        "excluded_fields": [
            {
                "field": "diplomats_available",
                "reason": "历史存档核对范围没有独立的本国外交官序列化证据，因此不把 live 值写入本报告。",
            }
        ],
        "evidence_scope": {
            "proven": [
                "FRA treasury raw value at countries/FRA/treasury",
                "FRA manpower raw value at countries/FRA/manpower",
            ],
            "not_proven": [
                "income or expense flow",
                "diplomats_available persistence",
                "opponent resources",
                "same-timestamp live/save identity",
            ],
        },
        "errors": errors,
        "read_only": True,
        "game_operations": [],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--save", type=Path, default=None)
    parser.add_argument("--manual-result", type=Path, default=MANUAL_RESULT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--overwrite", action="store_true")
    args = parser.parse_args()
    save_path = _default_save() if args.save is None else _resolve_existing(args.save)
    manual_path = args.manual_result.expanduser().resolve()
    output = args.output.expanduser().resolve()
    if output.exists() and not args.overwrite:
        raise ValueError(f"OUTPUT_EXISTS:{output}")
    report = build_report(save_path, manual_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": report["status"], "output": str(output), "errors": report["errors"]}, ensure_ascii=False))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
