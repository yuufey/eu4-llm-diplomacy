#!/usr/bin/env python3
"""Extract fixed B23 age-helper bytes and run them only in an owned process."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import re
import struct
import subprocess
import sys
from pathlib import Path

STAGE = Path(__file__).resolve().parent
ROOT = STAGE.parents[1]
EXPECTED_EXE_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
ORDINARY_PATH = ROOT / "work/runtime/information-country-person-20261029-001/person-date-helpers-ordinary-001.json"
ORDINARY_SHA256 = "67f3104ffa41063a0c658c45fa0fdc6f023efe88cad639e03b9890c4062fd688"
PROBE_PATH = ROOT / "work/runtime/information-country-person-20261029-001/probe_person_native_inputs_001.json"
PROBE_SHA256 = "1356236563002e318670368e0428c7f7f343b32b9f307c0e71a0e523cf1c0c2a"
BASE_RAW = 0x029C55C0  # 5000 * 365 * 24 hours
YEAR_HOURS = 365 * 24
MONTH_DAYS = (31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)
MONTH_RVA = 0x01C3A5C8
CODE_SEGMENTS = {
    "a4e140": (0x00A4E140, 0xD0),
    "cfd70-to-cfe10": (0x000CFD70, 0xA0),
    "cfe10": (0x000CFE10, 0x67),
    "14c8020": (0x014C8020, 0x11F),
}
EXPECTED_PDATA = {
    0x00A4E140: (0x00A4E140, 0x00A4E210, 0x01DC9CDC),
    0x000CFE10: (0x000CFE10, 0x000CFE77, None),
    0x014C8020: (0x014C8020, 0x014C813F, None),
}


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> tuple[int, str]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        while True:
            block = stream.read(1024 * 1024)
            if not block:
                break
            size += len(block)
            digest.update(block)
    return size, digest.hexdigest()


def load_env_file() -> dict[str, str]:
    result: dict[str, str] = {}
    for line in (ROOT / "local.env").read_text(encoding="utf-8-sig").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        result[key.strip()] = value.strip().strip('"').strip("'")
    return result


class PEImage:
    def __init__(self, path: Path):
        self.path = path
        self.stream = path.open("rb")
        self.file_size = os.fstat(self.stream.fileno()).st_size
        dos = self.read_file(0, 64)
        if dos[:2] != b"MZ":
            raise ValueError("not a PE image")
        pe_offset = struct.unpack_from("<I", dos, 0x3C)[0]
        if self.read_file(pe_offset, 4) != b"PE\0\0":
            raise ValueError("bad PE signature")
        coff = self.read_file(pe_offset + 4, 20)
        (self.machine, section_count, _timestamp, _symptr, _symcount,
         optional_size, self.characteristics) = struct.unpack("<HHIIIHH", coff)
        if self.machine != 0x8664 or section_count > 32 or optional_size > 4096:
            raise ValueError("unexpected PE machine/header bounds")
        optional = self.read_file(pe_offset + 24, optional_size)
        if struct.unpack_from("<H", optional)[0] != 0x20B:
            raise ValueError("expected PE32+")
        self.image_base = struct.unpack_from("<Q", optional, 24)[0]
        self.size_of_image, self.size_of_headers = struct.unpack_from("<II", optional, 56)
        directory_count = struct.unpack_from("<I", optional, 108)[0]
        if directory_count <= 3:
            raise ValueError("exception data directory missing")
        self.exception_rva, self.exception_size = struct.unpack_from("<II", optional, 112 + 3 * 8)
        section_offset = pe_offset + 24 + optional_size
        self.sections = []
        for index in range(section_count):
            raw = self.read_file(section_offset + index * 40, 40)
            name = raw[:8].split(b"\0", 1)[0].decode("ascii", "replace")
            virtual_size, virtual_address, raw_size, raw_pointer = struct.unpack_from("<IIII", raw, 8)
            self.sections.append({
                "name": name, "rva": virtual_address, "virtual_size": virtual_size,
                "raw_size": raw_size, "raw_pointer": raw_pointer,
            })

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()
        return False

    def close(self) -> None:
        self.stream.close()

    def read_file(self, offset: int, size: int) -> bytes:
        if offset < 0 or size < 0 or size > 1024 * 1024 or offset + size > self.file_size:
            raise ValueError("bounded file read rejected")
        self.stream.seek(offset)
        data = self.stream.read(size)
        if len(data) != size:
            raise ValueError("short PE read")
        return data

    def map_rva(self, rva: int, size: int) -> tuple[dict, int]:
        for section in self.sections:
            span = max(section["virtual_size"], section["raw_size"])
            if section["rva"] <= rva and rva + size <= section["rva"] + span:
                delta = rva - section["rva"]
                if delta + size > section["raw_size"]:
                    break
                return section, section["raw_pointer"] + delta
        raise ValueError(f"RVA not backed by a section: {rva:#x}+{size:#x}")

    def read_rva(self, rva: int, size: int) -> bytes:
        _section, offset = self.map_rva(rva, size)
        return self.read_file(offset, size)

    def runtime_functions(self) -> list[tuple[int, int, int, bytes]]:
        if not self.exception_size or self.exception_size % 12:
            raise ValueError("malformed x64 exception table")
        table = self.read_rva(self.exception_rva, self.exception_size)
        rows = []
        for offset in range(0, len(table), 12):
            raw = table[offset:offset + 12]
            rows.append((*struct.unpack("<III", raw), raw))
        return rows


def record_source_pins(exe_path: Path) -> dict:
    exe_bytes, exe_hash = sha256_file(exe_path)
    if exe_hash != EXPECTED_EXE_SHA256:
        raise ValueError(f"fixed EXE SHA mismatch: {exe_hash}")
    ordinary_bytes, ordinary_hash = sha256_file(ORDINARY_PATH)
    if ordinary_hash != ORDINARY_SHA256:
        raise ValueError(f"ordinary evidence SHA mismatch: {ordinary_hash}")
    probe_bytes, probe_hash = sha256_file(PROBE_PATH)
    if probe_hash != PROBE_SHA256:
        raise ValueError(f"probe artifact SHA mismatch: {probe_hash}")
    return {
        "exe": {"path_from_local_env": "EU4_GAME_ROOT/eu4.exe", "bytes": exe_bytes, "sha256": exe_hash},
        "ordinary_evidence": {"path": ORDINARY_PATH.relative_to(ROOT).as_posix(), "bytes": ordinary_bytes, "sha256": ordinary_hash},
        "person_probe": {"path": PROBE_PATH.relative_to(ROOT).as_posix(), "bytes": probe_bytes, "sha256": probe_hash},
    }


def date_raw(year: int, month: int, day: int, hour: int = 0) -> int:
    if not (0 <= year <= 10000 and 1 <= month <= 12 and 0 <= hour <= 23):
        raise ValueError("date outside fixture generator bounds")
    if not (1 <= day <= MONTH_DAYS[month - 1]):
        raise ValueError("invalid 365-day calendar date")
    days = sum(MONTH_DAYS[:month - 1]) + day - 1
    result = BASE_RAW + year * YEAR_HOURS + days * 24 + hour
    if not (0 < result <= 0x7FFFFFFF):
        raise ValueError("raw date outside positive signed i32 range")
    return result


def date_parts(raw: int) -> tuple[int, int, int]:
    if not (0 < raw <= 0x7FFFFFFF):
        raise ValueError("raw date outside positive signed i32 range")
    delta = raw - BASE_RAW
    if delta < 0:
        raise ValueError("pre-epoch raw date not in fixture domain")
    total_days = delta // 24
    year, day_of_year = divmod(total_days, 365)
    month = 1
    while day_of_year >= MONTH_DAYS[month - 1]:
        day_of_year -= MONTH_DAYS[month - 1]
        month += 1
    return year, month, day_of_year + 1


def expected_age(birth_raw: int, current_raw: int) -> int:
    birth_year, birth_month, birth_day = date_parts(birth_raw)
    current_year, current_month, current_day = date_parts(current_raw)
    before_birthday = (current_month, current_day) < (birth_month, birth_day)
    return max(0, current_year - birth_year - int(before_birthday))


def extract_actual_person_inputs(probe: dict) -> tuple[list[dict], list[dict]]:
    if probe.get("status") != "passed" or probe.get("source_pins_stable") is not True:
        raise ValueError("person probe is not a stable passed source")
    cases = []
    provenance = []
    by_country = {item["country"]: item for item in probe.get("capture_reports", [])}
    for country in ("FRA", "ENG"):
        report = by_country[country]
        capture = report["capture"]
        if (report.get("offline_replay_valid") is not True or capture.get("completed") is not True or
                capture.get("identity", {}).get("process_path_sha256") != EXPECTED_EXE_SHA256):
            raise ValueError(f"prior {country} probe lineage invalid")
        reads = capture["raw_reads"]
        for role in ("ruler", "heir"):
            label = f"person.{role}.header80"
            rows = [row for row in reads if row.get("label") == label]
            headers = [bytes.fromhex(row["raw_hex"]) for row in rows]
            if len(headers) != 2 or any(len(header) != 0x80 for header in headers) or headers[0] != headers[1]:
                raise ValueError(f"prior {country}/{role} header double-read mismatch")
            birth_raw = struct.unpack_from("<i", headers[0], 0x70)[0]
            date_rows = [row for row in reads if row.get("label") == "foreign_tech.date"]
            dates = [struct.unpack("<i", bytes.fromhex(row["raw_hex"]))[0] for row in date_rows]
            if len(dates) != 2 or dates[0] != dates[1] or dates[0] != 56564448:
                raise ValueError(f"prior {country} world date pin mismatch")
            name = f"actual_probe_{country}_{role}"
            expected = expected_age(birth_raw, dates[0])
            cases.append({"label": name, "birth_raw": birth_raw, "current_raw": dates[0], "expected": expected})
            provenance.append({"label": name, "country": country, "role": role,
                               "source_read_label": label, "header_bytes": 0x80,
                               "birth_offset": "0x70", "birth_raw": birth_raw,
                               "date_source_label": "foreign_tech.date", "current_raw": dates[0],
                               "double_reads_equal": True})
    return cases, provenance


def build_cases(probe: dict) -> tuple[list[dict], list[dict]]:
    cases: list[dict] = []

    def add(label: str, birth: tuple[int, int, int, int], current: tuple[int, int, int, int]) -> None:
        braw = date_raw(*birth)
        craw = date_raw(*current)
        cases.append({"label": label, "birth_raw": braw, "current_raw": craw,
                      "expected": expected_age(braw, craw),
                      "birth_ymdh": list(birth), "current_ymdh": list(current)})

    explicit = [
        ("same_birthday", (1450, 6, 15, 0), (1500, 6, 15, 0)),
        ("day_before_birthday", (1450, 6, 15, 0), (1500, 6, 14, 23)),
        ("birthday_midnight", (1450, 6, 15, 0), (1500, 6, 15, 0)),
        ("day_after_birthday", (1450, 6, 15, 23), (1500, 6, 16, 0)),
        ("feb28_before", (1480, 2, 28, 0), (1500, 2, 27, 23)),
        ("feb28_birthday", (1480, 2, 28, 0), (1500, 2, 28, 0)),
        ("feb28_then_mar1", (1480, 2, 28, 23), (1500, 3, 1, 0)),
        ("mar1_birthday_before", (1480, 3, 1, 0), (1500, 2, 28, 23)),
        ("mar1_birthday", (1480, 3, 1, 0), (1500, 3, 1, 0)),
        ("dec31_to_jan1", (1499, 12, 31, 23), (1500, 1, 1, 0)),
        ("dec30_before_year_end", (1499, 12, 31, 0), (1500, 12, 30, 23)),
        ("dec31_birthday", (1499, 12, 31, 0), (1500, 12, 31, 0)),
        ("jan1_after_year_boundary", (1499, 12, 31, 0), (1501, 1, 1, 0)),
        ("future_birth_same_calendar_day", (1501, 10, 1, 0), (1500, 10, 1, 0)),
        ("future_birth_earlier_day", (1501, 10, 2, 0), (1500, 10, 1, 23)),
        ("epoch_zero_year", (0, 1, 1, 0), (0, 1, 1, 0)),
        ("raw_day_hour_floor", (1499, 4, 30, 23), (1500, 5, 1, 0)),
    ]
    for row in explicit:
        add(*row)

    rng = random.Random(0xA4E140)
    for index in range(512):
        birth_year = rng.randint(0, 9000)
        current_year = max(0, min(10000, birth_year + rng.randint(-15, 80)))
        birth_month = rng.randint(1, 12)
        current_month = rng.randint(1, 12)
        birth_day = rng.randint(1, MONTH_DAYS[birth_month - 1])
        current_day = rng.randint(1, MONTH_DAYS[current_month - 1])
        add(f"random_{index:04d}",
            (birth_year, birth_month, birth_day, rng.randint(0, 23)),
            (current_year, current_month, current_day, rng.randint(0, 23)))

    actual, provenance = extract_actual_person_inputs(probe)
    cases.extend(actual)
    if len(cases) < 500:
        raise AssertionError("case count below required randomized coverage")
    labels = [case["label"] for case in cases]
    if len(labels) != len(set(labels)):
        raise AssertionError("duplicate fixture labels")
    return cases, provenance


def compare_project_age(cases: list[dict]) -> tuple[dict[str, int | str], dict]:
    sys.path.insert(0, str(ROOT))
    from bridge.information.person_age_memory import project_age

    helper_path = ROOT / "bridge/information/person_age_memory.py"
    helper_bytes, helper_hash = sha256_file(helper_path)
    results: dict[str, int | str] = {}
    mismatches = []
    for case in cases:
        try:
            projected = project_age(case["birth_raw"], case["current_raw"])
            results[case["label"]] = projected
            case["production_projection"] = projected
            case["projection_matches_independent"] = projected == case["expected"]
            if projected != case["expected"]:
                mismatches.append({"label": case["label"], "independent_expected": case["expected"],
                                   "production_projection": projected})
        except Exception as exc:
            value = f"{type(exc).__name__}: {exc}"
            results[case["label"]] = value
            case["production_projection"] = value
            case["projection_matches_independent"] = False
            mismatches.append({"label": case["label"], "independent_expected": case["expected"],
                               "production_projection_error": value})
    return results, {"path": "bridge/information/person_age_memory.py", "bytes": helper_bytes,
                     "sha256_before": helper_hash, "mismatches": mismatches}


def c_string(text: str) -> str:
    return json.dumps(text, ensure_ascii=True)


def write_case_files(cases: list[dict], actual_inputs: list[dict], pins: dict) -> None:
    cases_path = STAGE / "cases.json"
    cases_doc = {
        "schema": "owned-person-age-fixture-cases/1",
        "oracle": "independent 365-day calendar; raw=5000*365*24 + year*8760 + day_of_year*24 + hour; age=max(0,current_year-birth_year-before_birthday)",
        "calendar_month_days": list(MONTH_DAYS),
        "random_seed": "0xA4E140",
        "random_case_count": 512,
        "case_count": len(cases),
        "actual_probe_inputs": actual_inputs,
        "source_pins": pins,
        "cases": cases,
    }
    cases_path.write_text(json.dumps(cases_doc, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
    rows = ["static const AgeCase kCases[] = {"]
    for case in cases:
        rows.append("    {%s, %d, %d, %d}," % (
            c_string(case["label"]), case["birth_raw"], case["current_raw"], case["expected"]))
    rows.append("};")
    (STAGE / "age_cases.inc").write_text("\n".join(rows) + "\n", encoding="utf-8")


def disassemble(objdump: Path, exe: Path, name: str, rva: int, size: int) -> tuple[str, dict]:
    start = 0x140000000 + rva
    stop = start + size
    cmd = [str(objdump), "-d", f"--start-address=0x{start:x}", f"--stop-address=0x{stop:x}", str(exe)]
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    (STAGE / f"objdump-{name}.stdout.txt").write_text(result.stdout, encoding="utf-8")
    (STAGE / f"objdump-{name}.stderr.txt").write_text(result.stderr, encoding="utf-8")
    if result.returncode != 0:
        raise RuntimeError(f"objdump failed for {name}: {result.returncode}")
    instructions = [line for line in result.stdout.splitlines() if re.match(r"^\s*[0-9a-f]+:\s", line)]
    calls = []
    branches = []
    rip_targets = []
    for line in instructions:
        call = re.search(r"\bcallq?\s+0x([0-9a-f]+)", line, re.IGNORECASE)
        if call:
            calls.append(int(call.group(1), 16))
        branch = re.search(r"\b(j[a-z]+)\s+0x([0-9a-f]+)", line, re.IGNORECASE)
        if branch:
            branches.append(int(branch.group(2), 16))
        if "(%rip)" in line:
            target = re.search(r"#\s*0x([0-9a-f]+)", line, re.IGNORECASE)
            if target:
                rip_targets.append(int(target.group(1), 16))
    meta = {"argv": cmd, "returncode": result.returncode, "instruction_rows": len(instructions),
            "direct_call_targets_va": [f"0x{x:x}" for x in calls],
            "direct_branch_targets_va": [f"0x{x:x}" for x in branches],
            "rip_relative_targets_va": [f"0x{x:x}" for x in rip_targets]}
    return result.stdout, meta


def validate_dependencies(disassemblies: dict[str, dict]) -> None:
    va = lambda rva: 0x140000000 + rva
    expected_calls = {
        "cfd70-to-cfe10": [],
        "cfe10": [va(0x000CFD70)],
        "14c8020": [va(0x000CFE10), va(0x000CFE10)],
        "a4e140": [va(0x000CFD70), va(0x000CFD70), va(0x000CFE10),
                   va(0x014C8020), va(0x000CFE10), va(0x014C8020)],
    }
    expected_rip = {
        "cfd70-to-cfe10": [],
        "cfe10": [],
        "14c8020": [va(MONTH_RVA)],
        "a4e140": [va(0x0233FE58), va(MONTH_RVA)],
    }
    for name in CODE_SEGMENTS:
        calls = [int(v, 16) for v in disassemblies[name]["direct_call_targets_va"]]
        if sorted(calls) != sorted(expected_calls[name]):
            raise ValueError(f"unexpected call dependency in {name}: {calls}")
        rip = [int(v, 16) for v in disassemblies[name]["rip_relative_targets_va"]]
        if sorted(rip) != sorted(expected_rip[name]):
            raise ValueError(f"unexpected RIP dependency in {name}: {rip}")
        begin = 0x140000000 + CODE_SEGMENTS[name][0]
        end = begin + CODE_SEGMENTS[name][1]
        for target in disassemblies[name]["direct_branch_targets_va"]:
            if not (begin <= int(target, 16) < end):
                raise ValueError(f"branch escapes copied span {name}: {target}")


def extract_and_guard(exe_path: Path, cxx: Path, pins: dict) -> dict:
    ordinary = json.loads(ORDINARY_PATH.read_text(encoding="utf-8"))
    with PEImage(exe_path) as pe:
        if pe.image_base != 0x140000000 or pe.size_of_image != 0x025E0000:
            raise ValueError("fixed PE image identity fields differ")
        pdata_section = next((s for s in pe.sections if s["name"] == ".pdata"), None)
        if not pdata_section or pdata_section["rva"] != pe.exception_rva or pdata_section["virtual_size"] != pe.exception_size:
            raise ValueError("exception directory is not the expected .pdata span")
        runtime = pe.runtime_functions()
        matched = {}
        for target in [0x00A4E140, 0x000CFE10, 0x014C8020, 0x000CFD70]:
            rows = [(b, e, u, raw) for b, e, u, raw in runtime if b <= target < e]
            if target == 0x000CFD70:
                if rows:
                    raise ValueError("cfd70 unexpectedly has a .pdata function record")
                matched["0xcfd70"] = None
                continue
            if len(rows) != 1:
                raise ValueError(f"target {target:#x} has {len(rows)} .pdata rows")
            b, e, u, raw = rows[0]
            expected = EXPECTED_PDATA[target]
            if (b, e) != expected[:2] or (expected[2] is not None and u != expected[2]):
                raise ValueError(f".pdata boundary mismatch at {target:#x}")
            matched[f"0x{target:08x}"] = {"begin_rva": f"0x{b:08x}", "end_rva_exclusive": f"0x{e:08x}",
                                           "unwind_rva": f"0x{u:08x}", "entry_hex": raw.hex()}

        evidence_functions = {int(item["rva"], 16): item for item in ordinary["functions"]}
        extracted = {}
        (STAGE / "code").mkdir(exist_ok=True)
        dis_meta = {}
        objdump = cxx.parent / "objdump.exe"
        if not objdump.is_file():
            raise FileNotFoundError(objdump)
        for name, (rva, size) in CODE_SEGMENTS.items():
            data = pe.read_rva(rva, size)
            if name == "cfd70-to-cfe10":
                prefix = bytes.fromhex(evidence_functions[0x000CFD70]["bytes"])
                if len(prefix) != 96 or data[:96] != prefix:
                    raise ValueError("cfd70 first 96 bytes differ from ordinary evidence")
                if data[0x93] != 0xC3 or any(byte != 0xCC for byte in data[0x94:]):
                    raise ValueError("cfd70 bounded span lacks its return plus int3 tail")
            else:
                evidence = evidence_functions[rva]
                if evidence.get("end_rva_exclusive") != hex(rva + size) or bytes.fromhex(evidence["bytes"]) != data:
                    raise ValueError(f"ordinary evidence bytes/bounds differ for {name}")
            path = STAGE / "code" / f"{name}.bin"
            path.write_bytes(data)
            extracted[name] = {"rva": f"0x{rva:08x}", "bytes": len(data), "sha256": sha256_bytes(data),
                               "path": path.relative_to(STAGE).as_posix()}
            _dump, meta = disassemble(objdump, exe_path, name, rva, size)
            dis_meta[name] = meta
        validate_dependencies(dis_meta)

        table = pe.read_rva(MONTH_RVA, 48)
        expected_table = bytes.fromhex(ordinary["month_table"]["bytes"])
        if table != expected_table or len(table) != 48:
            raise ValueError("month table differs from stored ordinary evidence")
        values = struct.unpack("<12i", table)
        if tuple(values) != MONTH_DAYS:
            raise ValueError("month table is not the audited 365-day sequence")
        (STAGE / "code" / "month-table.bin").write_bytes(table)
        extracted["month_table"] = {"rva": f"0x{MONTH_RVA:08x}", "bytes": len(table),
                                    "sha256": sha256_bytes(table), "path": "code/month-table.bin",
                                    "i32": list(values)}

        month_page = next((s for s in pe.sections if s["rva"] <= MONTH_RVA < s["rva"] + max(s["virtual_size"], s["raw_size"])), None)
        if month_page is None:
            raise ValueError("month table is outside PE sections")
        cfd_begin = 0x000CFD70
        cfd_end = 0x000CFE10
        return {
            "pe": {"sha256": pins["exe"]["sha256"], "bytes": pins["exe"]["bytes"],
                   "machine": f"0x{pe.machine:04x}", "image_base": f"0x{pe.image_base:x}",
                   "size_of_image": f"0x{pe.size_of_image:x}",
                   "exception_directory_rva": f"0x{pe.exception_rva:08x}",
                   "exception_directory_bytes": pe.exception_size,
                   "pdata_section": {"rva": f"0x{pdata_section['rva']:08x}",
                                     "virtual_size": pdata_section["virtual_size"],
                                     "raw_pointer": f"0x{pdata_section['raw_pointer']:08x}",
                                     "raw_size": pdata_section["raw_size"]},
                   "month_table_section": month_page["name"]},
            "pdata_matches": matched,
            "cfd70_bounded_without_pdata": {"rva": f"0x{cfd_begin:08x}", "end_rva_exclusive": f"0x{cfd_end:08x}",
                                             "span_bytes": cfd_end - cfd_begin,
                                             "ret_rva": "0x000cfe03", "tail": "0x000cfe04..0x000cfe0f are int3 padding"},
            "segments": extracted,
            "bounded_disassembly": dis_meta,
            "dependency_validation": "passed; all direct calls target copied helper spans; RIP-relative reads target the owned world pointer cell or owned month table; all direct branches remain within each copied span",
        }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-owned-only", action="store_true", help="extract, compile and execute only the owned Win64 fixture")
    args = parser.parse_args()
    if not args.run_owned_only:
        parser.error("explicit --run-owned-only is required")

    receipt_path = STAGE / "receipt.json"
    receipt = {"schema": "owned-person-age-fixture-receipt/1", "status": "running",
               "game_process_opened": False, "game_function_called": False, "dll_loaded_into_game": False,
               "source_pins": {}, "errors": []}
    try:
        env = load_env_file()
        if "EU4_GAME_ROOT" not in env or "EU4_CXX" not in env:
            raise ValueError("local.env must define EU4_GAME_ROOT and EU4_CXX")
        exe_path = Path(env["EU4_GAME_ROOT"]) / "eu4.exe"
        cxx = Path(env["EU4_CXX"])
        if not exe_path.is_file() or not cxx.is_file():
            raise FileNotFoundError("configured EU4 executable or C++ compiler is absent")
        receipt["source_pins"] = record_source_pins(exe_path)
        pins = receipt["source_pins"]
        ordinary = json.loads(ORDINARY_PATH.read_text(encoding="utf-8"))
        probe = json.loads(PROBE_PATH.read_text(encoding="utf-8"))
        pe_summary = extract_and_guard(exe_path, cxx, pins)
        receipt["binary_extract"] = pe_summary

        cases, actual_inputs = build_cases(probe)
        projection_values, projection_pin = compare_project_age(cases)
        write_case_files(cases, actual_inputs, pins)
        receipt["independent_oracle"] = {"base_raw": BASE_RAW, "base_hours_expression": "5000*365*24",
                                         "year_hours": YEAR_HOURS, "month_days": list(MONTH_DAYS),
                                         "random_seed": "0xA4E140", "random_cases": 512,
                                         "total_cases": len(cases), "actual_probe_cases": len(actual_inputs),
                                         "probe_inputs": actual_inputs}
        receipt["production_projection"] = projection_pin

        version = subprocess.run([str(cxx), "--version"], capture_output=True, text=True, check=False)
        (STAGE / "compiler-version.stdout.txt").write_text(version.stdout, encoding="utf-8")
        (STAGE / "compiler-version.stderr.txt").write_text(version.stderr, encoding="utf-8")
        if version.returncode != 0:
            raise RuntimeError(f"configured CXX version probe failed: {version.returncode}")
        build_dir = STAGE / "build"
        build_dir.mkdir(exist_ok=True)
        binary_path = build_dir / "owned_age_fixture.exe"
        cpp_path = STAGE / "owned_age_fixture.cpp"
        compile_command = [str(cxx), "-std=c++17", "-O2", "-Wall", "-Wextra", "-Werror",
                           "-static", "-static-libgcc", "-static-libstdc++", f"-I{STAGE}",
                           str(cpp_path), "-o", str(binary_path)]
        compiled = subprocess.run(compile_command, capture_output=True, text=True, check=False)
        (STAGE / "compile.stdout.txt").write_text(compiled.stdout, encoding="utf-8")
        (STAGE / "compile.stderr.txt").write_text(compiled.stderr, encoding="utf-8")
        receipt["compile"] = {"argv": compile_command, "returncode": compiled.returncode,
                               "stdout_path": "compile.stdout.txt", "stderr_path": "compile.stderr.txt",
                               "compiler_version_path": "compiler-version.stdout.txt"}
        if compiled.returncode != 0:
            raise RuntimeError(f"owned fixture compile failed: {compiled.returncode}")
        binary_bytes, binary_hash = sha256_file(binary_path)
        receipt["owned_fixture_binary"] = {"path": binary_path.relative_to(STAGE).as_posix(),
                                            "bytes": binary_bytes, "sha256": binary_hash}
        (STAGE / "owned_source_pins.json").write_text(json.dumps({
            "prepare_and_run.py": sha256_file(Path(__file__))[1],
            "owned_age_fixture.cpp": sha256_file(cpp_path)[1],
            "age_cases.inc": sha256_file(STAGE / "age_cases.inc")[1],
            "cases.json": sha256_file(STAGE / "cases.json")[1],
        }, indent=2) + "\n", encoding="utf-8")

        run = subprocess.run([str(binary_path)], cwd=STAGE, capture_output=True, text=True,
                             check=False, timeout=120)
        (STAGE / "run.stdout.jsonl").write_text(run.stdout, encoding="utf-8")
        (STAGE / "run.stderr.txt").write_text(run.stderr, encoding="utf-8")
        parsed = []
        for line in run.stdout.splitlines():
            try:
                parsed.append(json.loads(line))
            except json.JSONDecodeError:
                parsed.append({"kind": "unparsed_output", "line": line})
        case_rows = [item for item in parsed if item.get("kind") == "case"]
        expected_by_label = {item["label"]: item for item in cases}
        mismatches = []
        seen = set()
        for row in case_rows:
            label = row.get("label")
            expected = expected_by_label.get(label)
            if expected is None or label in seen:
                mismatches.append({"label": label, "reason": "unknown_or_duplicate_label", "row": row})
                continue
            seen.add(label)
            if (row.get("birth_raw") != expected["birth_raw"] or
                    row.get("current_raw") != expected["current_raw"] or
                    row.get("expected") != expected["expected"] or
                    row.get("actual") != expected["expected"] or row.get("pass") is not True):
                mismatches.append({"label": label, "expected_case": expected, "actual_row": row})
        missing_labels = sorted(set(expected_by_label) - seen)
        native_by_label = {item.get("label"): item for item in case_rows}
        three_way_rows = []
        three_way_mismatches = []
        for case in cases:
            native = native_by_label.get(case["label"])
            projection = projection_values.get(case["label"])
            row = {"label": case["label"], "birth_raw": case["birth_raw"],
                   "current_raw": case["current_raw"], "independent_expected": case["expected"],
                   "production_projection": projection,
                   "owned_copied_native_actual": native.get("actual") if native else None,
                   "projection_matches_independent": projection == case["expected"],
                   "owned_actual_matches_independent": bool(native and native.get("actual") == case["expected"]),
                   "all_three_agree": bool(native and projection == case["expected"] and
                                            native.get("actual") == case["expected"])}
            three_way_rows.append(row)
            if not row["all_three_agree"]:
                three_way_mismatches.append(row)
        (STAGE / "three-way-comparison.jsonl").write_text(
            "".join(json.dumps(row, ensure_ascii=True, separators=(",", ":")) + "\n" for row in three_way_rows),
            encoding="utf-8")
        summary = next((item for item in parsed if item.get("kind") == "summary"), None)
        cleanup = next((item for item in parsed if item.get("kind") == "cleanup"), None)
        setup = next((item for item in parsed if item.get("kind") == "setup"), None)
        receipt["run"] = {"argv": [str(binary_path)], "returncode": run.returncode,
                          "stdout_path": "run.stdout.jsonl", "stderr_path": "run.stderr.txt",
                          "setup": setup, "summary": summary, "cleanup": cleanup,
                          "case_rows": len(case_rows), "reported_pairs": len(seen),
                          "missing_labels": missing_labels, "mismatches": mismatches,
                          "three_way_rows": len(three_way_rows),
                          "three_way_mismatches": three_way_mismatches,
                          "stderr_bytes": len(run.stderr.encode("utf-8"))}
        source_pins_after = record_source_pins(exe_path)
        receipt["source_pins_after"] = source_pins_after
        receipt["input_source_pins_stable"] = source_pins_after == pins
        _person_age_bytes_after, person_age_hash_after = sha256_file(ROOT / "bridge/information/person_age_memory.py")
        receipt["production_projection"]["sha256_after"] = person_age_hash_after
        receipt["production_projection"]["source_stable"] = (
            person_age_hash_after == receipt["production_projection"]["sha256_before"])
        success = (run.returncode == 0 and not mismatches and not missing_labels and
                   len(case_rows) == len(cases) and summary is not None and
                   summary.get("failed") == 0 and cleanup is not None and
                   cleanup.get("virtual_free_return") is True and receipt["input_source_pins_stable"] and
                   not projection_pin["mismatches"] and not three_way_mismatches and
                   receipt["production_projection"]["source_stable"])
        receipt["status"] = "passed" if success else "failed"
        receipt["case_count"] = len(cases)
        receipt["passed_count"] = summary.get("passed") if summary else None
        receipt["failed_count"] = summary.get("failed") if summary else None
        receipt["errors"] = [] if success else ["Owned fixture, independent comparison, cleanup, or source-pin check failed."]
        receipt_path.write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({"status": receipt["status"], "receipt": receipt_path.relative_to(STAGE).as_posix(),
                          "cases": len(cases), "passed": receipt["passed_count"], "failed": receipt["failed_count"],
                          "virtual_free": cleanup.get("virtual_free_return") if cleanup else None,
                          "receipt_sha256": sha256_file(receipt_path)[1]}, ensure_ascii=False))
        return 0 if success else 1
    except Exception as exc:
        receipt["status"] = "failed"
        receipt["errors"].append(f"{type(exc).__name__}: {exc}")
        receipt_path.write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({"status": "failed", "receipt": receipt_path.relative_to(STAGE).as_posix(),
                          "error": receipt["errors"][-1], "receipt_sha256": sha256_file(receipt_path)[1]}, ensure_ascii=False))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
