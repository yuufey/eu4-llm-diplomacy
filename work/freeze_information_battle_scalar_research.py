"""Freeze the bounded static evidence for battle scalar display research.

The script audits three already-completed read-only REA reports, the two
small derived ledgers, and two ordinary PE padding literals.  It does not
query REA, disassemble the image, access a game process, or call a native
function.  REA evidence, derived reports, and ordinary file bytes remain
separate in the generated index and source audit.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import mmap
import struct
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
EXPECTED_EXE_SHA256 = (
    "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
)
IMAGE_BASE = 0x140000000
MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_REPORT_BYTES = 4 * 1024 * 1024
DEFAULT_EXE = Path(r"D:\Downloads\Europa Universalis IV（1.37.4）\Europa Universalis IV\eu4.exe")
DEFAULT_STAGE = ROOT / "work/runtime/information-battle-scalar-writers-20261025-001"

EVIDENCE_SPECS = (
    {
        "name": "scalar_writer_1707b30",
        "path": DEFAULT_STAGE / "rea-scalar-writer-001/evidence.json",
        "expected_id": "ev_aed48f3663f7c2a170398a4c4685fb3a7d5fab7a0d017d0fbda62c4f3eaae28c",
        "expected_procedure": "0x141707b30",
    },
    {
        "name": "signed_count_conversion_cfcd0",
        "path": DEFAULT_STAGE / "rea-count-conversion-001/evidence.json",
        "expected_id": "ev_4c3cd7bbb0db4a6ea25ed7678f09db838425668457a2234c38b8ab5f1f20c504",
        "expected_procedure": "0x1400cfcd0",
    },
    {
        "name": "unit_display_ae8a80",
        "path": DEFAULT_STAGE / "rea-count-display-001/evidence.json",
        "expected_id": "ev_959dd5e56c1114bb51d5b23ab36d9685586c3bbf60f33296eb7a7cc7b361adb1",
        "expected_procedure": "0x140ae8a80",
    },
)

DERIVED_SPECS = (
    {
        "name": "scalar_field_writer_ledger",
        "path": DEFAULT_STAGE / "scalar-field-writer-001.json",
        "expected_sha256": "3bd495ce9575b7f4a3134512f7fb27fd9ad6594632b1afd4026e9a419b574400",
    },
    {
        "name": "unit_display_ledger",
        "path": ROOT / "work/runtime/information-battle-layout-20261025-001/unit-display-ledger-001.json",
        "expected_sha256": "20ba4eb0a313bf369c0afba2d79b7541620d932ef70724b105b6282ab0e85d41",
    },
)

PADDING_SPECS = (
    {"rva": 0x1C42024, "literal_prefix": b"00", "label": "two_zero_padding_literal"},
    {"rva": 0x1C424E8, "literal_prefix": b"0", "label": "one_zero_padding_literal"},
)


def _sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _relative(path: Path) -> str:
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except ValueError:
        return str(path.resolve())


def _load_json(path: Path) -> tuple[dict[str, Any], bytes]:
    path = path.resolve()
    if not path.is_file():
        raise FileNotFoundError(path)
    size = path.stat().st_size
    if size > MAX_FILE_BYTES:
        raise ValueError(f"input exceeds 16 MiB bound: {path} ({size})")
    raw = path.read_bytes()
    document = json.loads(raw.decode("utf-8"))
    if not isinstance(document, dict):
        raise ValueError(f"JSON root is not an object: {path}")
    return document, raw


def _rva_hex(value: int) -> str:
    return hex(value)


def _body_descriptor(procedure: dict[str, Any]) -> dict[str, Any]:
    body = procedure.get("body")
    if not isinstance(body, dict):
        raise ValueError("REA procedure body is missing")
    ranges = body.get("ranges")
    if not isinstance(ranges, list) or not ranges:
        raise ValueError("REA procedure body ranges are missing")
    converted: list[dict[str, Any]] = []
    total = 0
    for item in ranges:
        if not isinstance(item, dict):
            raise ValueError("REA body range is not an object")
        start_va = int(item["start"], 16)
        end_va = int(item["end"], 16)
        if end_va < start_va:
            raise ValueError("REA body range is reversed")
        length = end_va - start_va + 1
        total += length
        converted.append(
            {
                "start_va": hex(start_va),
                "end_va_inclusive": hex(end_va),
                "start_rva": hex(start_va - IMAGE_BASE),
                "end_rva_inclusive": hex(end_va - IMAGE_BASE),
                "bytes_inclusive": length,
            }
        )
    if total != body.get("total_bytes"):
        raise ValueError(
            f"REA body inclusive range total mismatch: {total} != {body.get('total_bytes')}"
        )
    return {
        "ranges_inclusive": converted,
        "total_bytes": body.get("total_bytes"),
        "span_bytes": body.get("span_bytes"),
        "non_contiguous": body.get("non_contiguous"),
        "contains_entry": body.get("contains_entry"),
        "provenance": body.get("provenance"),
    }


def _evidence_descriptor(spec: dict[str, Any]) -> dict[str, Any]:
    path = Path(spec["path"]).resolve()
    document, raw = _load_json(path)
    if document.get("evidence_id") != spec["expected_id"]:
        raise ValueError(f"evidence id changed: {path}")
    subject_sha = document.get("subject", {}).get("digest", {}).get("sha256")
    if subject_sha != EXPECTED_EXE_SHA256:
        raise ValueError(f"evidence target SHA changed: {path}")
    value = document.get("raw_result", {}).get("value")
    if not isinstance(value, dict):
        raise ValueError(f"raw REA value is missing: {path}")
    procedure = value.get("procedure")
    if not isinstance(procedure, dict) or procedure.get("address") != spec["expected_procedure"]:
        raise ValueError(f"REA procedure changed: {path}")
    profile = document.get("analysis_profile")
    if not isinstance(profile, dict) or not isinstance(profile.get("parameters"), dict):
        raise ValueError(f"REA analysis profile is missing: {path}")
    profile_parameters = profile["parameters"]
    request_path = path.parent / "request.json"
    run_path = path.parent / "run.json"
    request, request_raw = _load_json(request_path)
    run, run_raw = _load_json(run_path)
    if request.get("target_sha256") != EXPECTED_EXE_SHA256 or run.get("target_sha256") != EXPECTED_EXE_SHA256:
        raise ValueError(f"request/run target SHA changed: {path.parent}")
    if request.get("procedure") != spec["expected_procedure"] or run.get("procedure") != spec["expected_procedure"]:
        raise ValueError(f"request/run procedure changed: {path.parent}")
    if run.get("exit_code") != 0 or run.get("reason") != "completed" or run.get("database_unchanged") is not True:
        raise ValueError(f"REA run did not complete read-only: {run_path}")
    if request.get("java_heap") != "512M" or request.get("query_reanalysis") is not False:
        raise ValueError(f"request query policy changed: {request_path}")
    if profile_parameters.get("database_mutation") != "read-only-no-save" or profile_parameters.get("query_reanalysis") is not False:
        raise ValueError(f"profile query policy changed: {path}")
    limitations = document.get("limitations", [])
    if not any("-readOnly" in str(item) and "-noanalysis" in str(item) for item in limitations):
        raise ValueError(f"readOnly/noanalysis limitation is missing: {path}")
    processes = run.get("processes", [])
    if (
        not isinstance(processes, list)
        or not processes
        or any(not isinstance(item, dict) for item in processes)
        or any(
            item.get("still_running_same_process") is not False
            or item.get("peak_committed_bytes", 2**31) >= 1024 * 1024 * 1024
            for item in processes
        )
    ):
        raise ValueError(f"REA process closure/memory guard failed: {run_path}")
    body = _body_descriptor(procedure)
    cache_path = request.get("cache")
    cache = {
        "path": cache_path,
        "adapter_sha256": request.get("adapter_sha256"),
        "completed_manifest_sha256": request.get("completed_manifest_sha256"),
        "completed_database_sha256": request.get("completed_database_sha256"),
    }
    if not all(isinstance(cache[key], str) and cache[key] for key in cache):
        raise ValueError(f"cache commitment is incomplete: {request_path}")
    return {
        "name": spec["name"],
        "evidence": {
            "path": _relative(path),
            "bytes": len(raw),
            "sha256": _sha256_bytes(raw),
            "evidence_id": document["evidence_id"],
            "target_exe_sha256": subject_sha,
        },
        "procedure": {
            "address_va": procedure["address"],
            "rva": hex(int(procedure["address"], 16) - IMAGE_BASE),
            "body": body,
        },
        "request": {
            "path": _relative(request_path),
            "bytes": len(request_raw),
            "sha256": _sha256_bytes(request_raw),
            "node": request.get("node"),
            "procedure": request.get("procedure"),
            "preset": request.get("preset"),
            "java_heap": request.get("java_heap"),
            "process_memory_limit_bytes": request.get("process_memory_limit_bytes"),
            "query_reanalysis": request.get("query_reanalysis"),
        },
        "run": {
            "path": _relative(run_path),
            "bytes": len(run_raw),
            "sha256": _sha256_bytes(run_raw),
            "exit_code": run.get("exit_code"),
            "reason": run.get("reason"),
            "database_unchanged": run.get("database_unchanged"),
            "elapsed_seconds": run.get("elapsed_seconds"),
            "processes": run.get("processes"),
        },
        "profile": {
            "sha256": profile.get("digest"),
            "analyzer_preset": profile_parameters.get("analyzer_preset"),
            "provider": profile.get("provider"),
            "completed_manifest_sha256": profile_parameters.get("completed_manifest_sha256"),
            "completed_database_sha256": profile_parameters.get("completed_database_sha256"),
            "database_mutation": profile_parameters.get("database_mutation"),
            "query_reanalysis": profile_parameters.get("query_reanalysis"),
            "import_mode": profile_parameters.get("import_mode"),
        },
        "cache": cache,
        "query_policy": {
            "read_only": profile_parameters.get("database_mutation") == "read-only-no-save",
            "noanalysis": True,
            "source": "REA evidence limitations explicitly retain -readOnly and -noanalysis",
        },
    }


def _derived_descriptor(spec: dict[str, Any]) -> dict[str, Any]:
    path = Path(spec["path"]).resolve()
    document, raw = _load_json(path)
    actual = _sha256_bytes(raw)
    if actual != spec["expected_sha256"]:
        raise ValueError(f"derived ledger SHA changed: {path}")
    return {
        "name": spec["name"],
        "path": _relative(path),
        "bytes": len(raw),
        "sha256": actual,
        "status": document.get("status"),
        "runtime_observed": document.get("runtime_observed"),
        "read_only": document.get("read_only"),
    }


def _parse_pe(mm: mmap.mmap) -> dict[str, Any]:
    if mm.size() < 0x40 or bytes(mm[:2]) != b"MZ":
        raise ValueError("target executable is not a DOS/PE image")
    pe_offset = struct.unpack_from("<I", mm, 0x3C)[0]
    if pe_offset < 0x40 or pe_offset + 24 > mm.size() or bytes(mm[pe_offset : pe_offset + 4]) != b"PE\0\0":
        raise ValueError("invalid PE header")
    _machine, sections, _ts, _sp, _ns, optional_size, _chars = struct.unpack_from("<HHIIIHH", mm, pe_offset + 4)
    optional = pe_offset + 24
    if struct.unpack_from("<H", mm, optional)[0] != 0x20B:
        raise ValueError("target is not PE32+")
    image_base = struct.unpack_from("<Q", mm, optional + 24)[0]
    section_table = optional + optional_size
    result: list[dict[str, Any]] = []
    for index in range(sections):
        offset = section_table + index * 40
        name = bytes(mm[offset : offset + 8]).split(b"\0", 1)[0].decode("ascii", errors="replace")
        virtual_size, virtual_address, raw_size, raw_pointer = struct.unpack_from("<IIII", mm, offset + 8)
        if raw_pointer + raw_size > mm.size():
            raise ValueError(f"PE section exceeds file: {name}")
        result.append(
            {
                "name": name,
                "virtual_size": virtual_size,
                "virtual_address": virtual_address,
                "raw_size": raw_size,
                "raw_pointer": raw_pointer,
            }
        )
    return {"machine": _machine, "image_base": image_base, "sections": result}


def _map_rva(pe: dict[str, Any], rva: int, length: int) -> tuple[int, str]:
    for section in pe["sections"]:
        start = section["virtual_address"]
        if start <= rva < start + max(section["virtual_size"], section["raw_size"]):
            delta = rva - start
            if delta + length > section["raw_size"]:
                raise ValueError("RVA read crosses section raw boundary")
            return section["raw_pointer"] + delta, section["name"]
    raise ValueError(f"RVA is not file-backed: {rva:#x}")


def _ordinary_pe_padding(executable: Path) -> dict[str, Any]:
    executable = executable.resolve()
    if executable.stat().st_size > 64 * 1024 * 1024:
        raise ValueError("executable exceeds 64 MiB ordinary-read bound")
    actual_sha = _sha256_file(executable)
    if actual_sha != EXPECTED_EXE_SHA256:
        raise ValueError(f"fixed executable SHA mismatch: {actual_sha}")
    entries: list[dict[str, Any]] = []
    with executable.open("rb") as handle:
        with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            pe = _parse_pe(mm)
            if pe["image_base"] != IMAGE_BASE:
                raise ValueError("PE image base changed")
            for spec in PADDING_SPECS:
                file_offset, section = _map_rva(pe, spec["rva"], 8)
                raw = bytes(mm[file_offset : file_offset + 8])
                prefix = spec["literal_prefix"]
                if not raw.startswith(prefix) or raw[len(prefix)] != 0:
                    raise ValueError(f"padding literal guard failed at {spec['rva']:#x}")
                entries.append(
                    {
                        "label": spec["label"],
                        "rva": hex(spec["rva"]),
                        "static_va": hex(IMAGE_BASE + spec["rva"]),
                        "file_offset": hex(file_offset),
                        "section": section,
                        "read_length": 8,
                        "raw_hex": raw.hex(),
                        "ascii_escaped": "".join(chr(b) if 32 <= b < 127 else f"\\x{b:02x}" for b in raw),
                        "literal_prefix_hex": prefix.hex(),
                        "zero_terminator_index": len(prefix),
                        "prefix_and_zero_terminator_verified": True,
                    }
                )
            return {
                "kind": "ordinary_pe_mmap_bytes",
                "executable_path": str(executable),
                "executable_sha256": actual_sha,
                "file_size": mm.size(),
                "image_base": hex(pe["image_base"]),
                "max_bytes_per_rva_read": 8,
                "entries": entries,
            }


def _find_line(lines: list[str], token: str) -> dict[str, Any]:
    hits = [{"line": index, "text": line} for index, line in enumerate(lines, 1) if token in line]
    if len(hits) != 1:
        raise ValueError(f"display expression token {token!r} count changed: {len(hits)}")
    return hits[0]


def _display_formula(evidence: dict[str, Any]) -> dict[str, Any]:
    document, _raw = _load_json(ROOT / evidence["evidence"]["path"])
    pseudo = document["raw_result"]["value"]["pseudocode"]
    lines = pseudo.splitlines()
    formula = _find_line(lines, "iVar10 = (int)((float)param_3 * ((float)*param_2 / 1000.0));")
    high = _find_line(lines, "if (99999 < iVar10) {")
    low = _find_line(lines, "if (iVar10 < 1000) {")
    remainder = _find_line(lines, "iVar11 = iVar10 % 1000;")
    remainder_two_digits = _find_line(lines, "if (iVar11 < 10) {")
    remainder_one_digit = _find_line(lines, "else if (iVar11 < 100) {")
    k_suffix = _find_line(lines, "local_a8 = (undefined8 *******)0x6b;")
    divide_hits = [
        {"line": index, "text": line}
        for index, line in enumerate(lines, 1)
        if "lVar2 = FUN_1417061a0(iVar10 / 1000,local_40);" in line
    ]
    if len(divide_hits) != 2 or divide_hits[0]["line"] >= divide_hits[1]["line"]:
        raise ValueError(
            "display thousands expression count/order changed: "
            f"{[item['line'] for item in divide_hits]}"
        )
    divide_high, divide_grouped = divide_hits
    pad_two = _find_line(lines, "puVar7 = &DAT_141c42024;")
    pad_one = _find_line(lines, "puVar7 = &DAT_141c424e8;")
    return {
        "function": {
            "address_va": "0x140ae8a80",
            "rva": "0xae8a80",
            "body_ranges_are_inclusive": True,
        },
        "expression": {
            "text": formula["text"],
            "line": formula["line"],
            "value_before_branch": "int(float(param_3) * (float(*param_2) / 1000.0))",
            "float_precision_and_overflow": "not runtime verified",
        },
        "branches": {
            "small_integer": {
                "predicate": "iVar10 < 1000",
                "line": low["line"],
                "format_path": "integer iVar10 branch",
            },
            "grouped_1000_to_99999": {
                "predicate": "1000 <= iVar10 <= 99999",
                "source_boundary": "the high branch is 99999 < iVar10 and the low branch is iVar10 < 1000",
                "remainder_expression": remainder,
                "thousands_expression": divide_grouped,
                "format_path": "thousands part, comma, remainder with padding branches",
            },
            "thousands_k": {
                "exact_native_predicate": "99999 < iVar10",
                "integer_boundary_equivalent": "iVar10 >= 100000",
                "line": high["line"],
                "thousands_expression": divide_high,
                "suffix_literal": {
                    "line": k_suffix["line"],
                    "hex": "0x6b",
                    "ascii": "k",
                    "source_text": k_suffix["text"],
                },
                "format_path": "thousands part followed by inline k path",
            },
        },
        "remainder_padding": {
            "two_zero_predicate": {
                "line": remainder_two_digits["line"],
                "predicate": "iVar11 < 10",
                "prefix_length": 2,
            },
            "one_zero_predicate": {
                "line": remainder_one_digit["line"],
                "predicate": "iVar11 < 100",
                "prefix_length": 1,
            },
            "otherwise": "iVar11 >= 100 uses no zero prefix; together the grouped path emits a three-digit remainder",
        },
        "padding_references": {
            "two_digit_remainder": pad_two,
            "one_digit_remainder": pad_one,
            "meaning": "static address references recorded; helper semantics are not independently claimed here",
        },
        "display_semantics": {
            "runtime_observed": False,
            "mathematical_exactness": "not guaranteed because the native expression uses float conversion and int cast",
            "source_object_display_text_and_unit_semantics_separate": True,
        },
    }


def _write_json(path: Path, document: dict[str, Any]) -> None:
    encoded = json.dumps(document, ensure_ascii=False, indent=2) + "\n"
    if len(encoded.encode("utf-8")) > MAX_REPORT_BYTES:
        raise ValueError(f"generated report exceeds 4 MiB: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(encoded, encoding="utf-8", newline="\n")
    json.loads(path.read_text(encoding="utf-8"))


def build_reports(executable: Path, stage: Path) -> tuple[Path, Path]:
    script_path = Path(__file__).resolve()
    evidence = [_evidence_descriptor(spec) for spec in EVIDENCE_SPECS]
    derived = [_derived_descriptor(spec) for spec in DERIVED_SPECS]
    display_evidence = next(item for item in evidence if item["name"] == "unit_display_ae8a80")
    ordinary = _ordinary_pe_padding(executable)
    formula = _display_formula(display_evidence)
    index_path = stage / "research-index-001.json"
    audit_path = stage / "source-audit-001.json"
    index = {
        "schema": "information-battle-scalar-research-index-001",
        "status": "static_research_frozen",
        "read_only": True,
        "runtime_observed": False,
        "native_function_invoked": False,
        "target_build": {
            "version": "1.37.4",
            "executable_sha256": EXPECTED_EXE_SHA256,
            "image_base": hex(IMAGE_BASE),
            "address_convention": "REA VA plus RVA; body ranges are inclusive",
        },
        "script": {"path": _relative(script_path), "sha256": _sha256_file(script_path)},
        "rea_evidence": evidence,
        "derived_ledgers": derived,
        "display_formula": formula,
        "ordinary_pe_padding": ordinary,
        "limitations": [
            "REA evidence is static and read-only; no runtime values were observed.",
            "The scalar writer and unit-display ledgers keep source object, display text, and unit semantics separate.",
            "Float precision, integer-cast edge behavior, overflow, rounding, and actual UI formatting were not runtime verified.",
            "No side ordering, player/FRA view, or initial/remaining battle-unit semantics are inferred by this freeze.",
            "The two padding references were checked with bounded 8-byte ordinary PE reads only.",
        ],
    }
    _write_json(index_path, index)
    index_sha = _sha256_file(index_path)
    checks = [
        {"name": "fixed_target_executable", "passed": ordinary["executable_sha256"] == EXPECTED_EXE_SHA256},
        {"name": "three_expected_evidence_ids", "passed": len(evidence) == 3},
        {"name": "all_rea_runs_completed", "passed": all(item["run"]["exit_code"] == 0 for item in evidence)},
        {"name": "all_read_only_noanalysis", "passed": all(item["query_policy"]["read_only"] and item["query_policy"]["noanalysis"] for item in evidence)},
        {"name": "body_ranges_inclusive", "passed": all(item["procedure"]["body"]["ranges_inclusive"] for item in evidence)},
        {"name": "derived_ledgers_pinned", "passed": all(item["sha256"] for item in derived)},
        {"name": "ordinary_padding_guards", "passed": all(item["prefix_and_zero_terminator_verified"] for item in ordinary["entries"])},
        {"name": "display_boundary_expression", "passed": formula["branches"]["thousands_k"]["exact_native_predicate"] == "99999 < iVar10"},
    ]
    audit = {
        "schema": "information-battle-scalar-source-audit-001",
        "status": "passed_static_source_audit",
        "read_only": True,
        "runtime_observed": False,
        "target_exe_sha256": EXPECTED_EXE_SHA256,
        "script": {"path": _relative(script_path), "sha256": _sha256_file(script_path)},
        "research_index": {"path": _relative(index_path), "sha256": index_sha},
        "source_files": evidence,
        "derived_ledgers": derived,
        "ordinary_pe_padding": ordinary,
        "checks": checks,
        "all_checks_passed": all(item["passed"] for item in checks),
        "limitations": index["limitations"],
    }
    _write_json(audit_path, audit)
    return index_path, audit_path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--executable", type=Path, default=DEFAULT_EXE)
    parser.add_argument("--stage", type=Path, default=DEFAULT_STAGE)
    args = parser.parse_args(argv)
    index_path, audit_path = build_reports(args.executable.resolve(), args.stage.resolve())
    print(
        json.dumps(
            {
                "index": _relative(index_path),
                "index_sha256": _sha256_file(index_path),
                "audit": _relative(audit_path),
                "audit_sha256": _sha256_file(audit_path),
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
