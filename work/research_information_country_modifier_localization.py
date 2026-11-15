"""Bounded static check of the country-modifier localization key convention.

This script reads only the small localization resource line by line.  It does
not start the game, call native code, or treat disk text as a native cache
observation.  The report is an input to the country-record localization
adapter, not a runtime acceptance receipt.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / "work" / "runtime" / "information-country-records-localization-20261027-001"
REPORT = STAGE / "modifier-localization-source-001.json"
EXPECTED_EXE_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
EXPECTED_VERSION = "1.37.4"
COUNTRY_KEYS = (
    "papal_sanction_for_church_taxes",
    "shady_people",
)


def _game_root() -> Path:
    try:
        sys.path.insert(0, str(ROOT / "work"))
        from local_config import game_root

        return game_root()
    except Exception:
        configured = os.environ.get("EU4_GAME_ROOT")
        if configured:
            return Path(configured)
        raise RuntimeError("EU4_GAME_ROOT is not configured")


def _sha256(path: Path, *, chunk: int = 1024 * 1024) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        while True:
            block = stream.read(chunk)
            if not block:
                break
            digest.update(block)
            size += len(block)
    return digest.hexdigest(), size


def _line_key(line: str) -> str | None:
    text = line.lstrip(" \t\ufeff")
    if ":" not in text:
        return None
    key = text.split(":", 1)[0].strip()
    return key or None


def _scan_resource(path: Path) -> dict[str, Any]:
    expected = []
    for key in COUNTRY_KEYS:
        expected.extend((key, f"desc_{key}"))
    wanted = set(expected)
    found: dict[str, dict[str, Any]] = {}
    with path.open("r", encoding="utf-8-sig", newline="") as stream:
        for line_number, raw in enumerate(stream, 1):
            key = _line_key(raw)
            if key not in wanted:
                continue
            normalized = raw.rstrip("\r\n")
            found[key] = {
                "line": line_number,
                "key": key,
                "raw_line_sha256": hashlib.sha256(normalized.encode("utf-8")).hexdigest(),
                "raw_line": normalized,
            }
    missing = sorted(wanted - set(found))
    pairs = []
    for key in COUNTRY_KEYS:
        pairs.append({
            "modifier_key": key,
            "name_key": key,
            "description_key": f"desc_{key}",
            "name": found.get(key),
            "description": found.get(f"desc_{key}"),
            "matched": key in found and f"desc_{key}" in found,
        })
    return {"pairs": pairs, "missing_keys": missing}


def build_report() -> dict[str, Any]:
    root = _game_root().resolve()
    exe = root / "eu4.exe"
    resource = root / "localisation" / "modifers_l_english.yml"
    if not exe.is_file() or not resource.is_file():
        raise FileNotFoundError(f"missing expected static resource: {exe} / {resource}")
    exe_sha, exe_bytes = _sha256(exe)
    resource_sha, resource_bytes = _sha256(resource)
    scan = _scan_resource(resource)
    report: dict[str, Any] = {
        "schema": "information_country_modifier_localization_source.v1",
        "stage": "information-country-records-localization-20261027-001",
        "evidence_kind": "ordinary_static_resource",
        "read_only": True,
        "target": {
            "game_version": EXPECTED_VERSION,
            "executable": {"path": str(exe), "sha256": exe_sha, "bytes": exe_bytes},
            "expected_exe_sha256": EXPECTED_EXE_SHA256,
            "executable_sha_match": exe_sha.lower() == EXPECTED_EXE_SHA256,
            "observer": "FRA",
        },
        "resource": {
            "path": str(resource),
            "relative_path": "localisation/modifers_l_english.yml",
            "sha256": resource_sha,
            "bytes": resource_bytes,
            "encoding": "utf-8-sig_or_utf-8",
            "language": "l_english",
            "scan": scan,
        },
        "convention": {
            "name_key": "the validated native modifier key exactly",
            "description_key": "desc_ + the validated native modifier key",
            "case_sensitive": True,
            "raw_native_key_is_not_rewritten": True,
            "disk_text_is_not_a_runtime_fallback": True,
        },
        "observed_records": [
            "papal_sanction_for_church_taxes",
            "shady_people",
        ],
        "runtime_contract": {
            "reader": "bridge.information.native_localization.NativeLocalizationReader",
            "request_country": "FRA",
            "request_context": "ready live FRA context only",
            "literal_only": True,
            "dynamic_or_template": "unknown_with_raw_template_preserved",
            "missing_key": "unknown_LOCALIZATION_KEY_UNRESOLVED",
            "reader_failure": "unknown_without_disk_text_fallback",
            "shared_lookup": True,
            "native_cache_and_name_values_atomic": False,
        },
        "source_bindings": {
            "modifier_child_profile": {
                "path": "bridge/information/profiles/country-modifiers-memory-1374-v2.json",
                "role": "validated native modifier key/date/effect record",
            },
            "localization_reader_module": {
                "path": "bridge/information/native_localization.py",
                "role": "bounded literal native localization cache reader",
            },
            "trade_reuse_report": {
                "path": "work/runtime/information-trade-merchant-state-20261027-001/dynamic-lookup-reuse-001.json",
                "role": "same key filter/reader provenance contract",
            },
        },
        "unknowns": [
            "This static file does not prove that either key is present in the current native cache.",
            "This report does not prove a native UI callsite or modifier activation/expiry semantics.",
            "Localization batches are not atomic with the country modifier child capture.",
        ],
        "analysis": {"native_game_call": False, "rpm": False, "rea": False, "mcp": False, "game_process_started": False},
    }
    if not scan["pairs"] or scan["missing_keys"]:
        raise RuntimeError(f"modifier localization convention incomplete: {scan['missing_keys']}")
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=REPORT)
    args = parser.parse_args()
    output = args.output if args.output.is_absolute() else ROOT / args.output
    if output.exists():
        raise SystemExit(f"refusing to overwrite existing evidence: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    report = build_report()
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(output), "sha256": hashlib.sha256(output.read_bytes()).hexdigest(), "pairs": len(report["resource"]["scan"]["pairs"])}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
