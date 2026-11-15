"""Bounded static research for EU4 ``map_setup`` trigger dispatch.

This module only reads the explicitly configured 1.37.4 executable.  It does
not attach to a running game, read a save, call a native address, or infer the
current map mode from mission or save data.  The generated JSON is a static
contract: it records the bytes and addresses that support a read-only mode
input path, as well as the parts that remain unresolved.
"""

from __future__ import annotations

import hashlib
import json
import struct
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from discover_diplomacy import PE, check_memory_budget  # noqa: E402
from local_config import get_path, get_value  # noqa: E402


EXPECTED_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
EXPECTED_IMAGE_BASE = 0x140000000
MAX_FILE_BYTES = 128 * 1024 * 1024
MAX_RANGE_BYTES = 64 * 1024
MAX_DECODE_BYTES = 256 * 1024
MAX_FUNCTIONS = 8

# These are only search anchors.  The report still checks each anchor against
# the selected PE and labels the interpretation separately from raw evidence.
CONSTRUCTOR_RVA = 0xBB95E0
MAP_EVALUATOR_RVA = 0xD15590
MAP_TABLE_RVA = 0x1CEF3E8
MODE_GLOBAL_RVA = 0x233FE58

TOKEN_NAMES = (
    "map_setup",
    "map_setup_normal",
    "map_setup_historical",
    "map_setup_random",
    "map_setup_custom",
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while True:
            block = stream.read(1024 * 1024)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def hx(value: int | None) -> str | None:
    return None if value is None else hex(value)


def section_for_rva(pe: PE, rva: int) -> dict | None:
    for section in pe.sections:
        if section["rva"] <= rva < section["rva"] + section["size"]:
            return section
    return None


def read_u64_at_rva(pe: PE, rva: int) -> int | None:
    offset = pe.to_offset(rva)
    if offset is None or offset + 8 > len(pe.data):
        return None
    return pe.u64(offset)


def find_token_descriptors(pe: PE) -> list[dict]:
    """Find the exact ASCII descriptors and their adjacent integer IDs."""

    data_section = next((s for s in pe.sections if s["name"] == ".data"), None)
    if data_section is None:
        return []
    raw_start = data_section["raw"]
    raw_end = raw_start + data_section["size"]
    raw = pe.data[raw_start:raw_end]
    found: list[dict] = []
    for name in TOKEN_NAMES:
        needle = name.encode("ascii") + b"\0"
        cursor = 0
        while True:
            index = raw.find(needle, cursor)
            if index < 0:
                break
            descriptor_offset = raw_start + index - 4
            if descriptor_offset < raw_start:
                cursor = index + 1
                continue
            descriptor_rva = pe.to_rva(descriptor_offset)
            string_rva = pe.to_rva(raw_start + index)
            if descriptor_rva is None or string_rva is None:
                cursor = index + 1
                continue
            found.append(
                {
                    "name": name,
                    "descriptor_rva": hx(descriptor_rva),
                    "descriptor_va": hx(pe.base + descriptor_rva),
                    "string_rva": hx(string_rva),
                    "string_va": hx(pe.base + string_rva),
                    "token_id": pe.u32(descriptor_offset),
                    "token_id_hex": hx(pe.u32(descriptor_offset)),
                    "evidence": "ASCII descriptor with adjacent little-endian ID",
                }
            )
            cursor = index + len(needle)
    return found


def direct_call_refs(pe: PE, target_rva: int) -> list[dict]:
    """Return direct E8 call sites to one target, without decoding .text."""

    refs: list[dict] = []
    for section in pe.sections:
        if section["name"] != ".text":
            continue
        start = section["raw"]
        end = start + section["size"]
        for offset in range(start, end - 4):
            if pe.data[offset] != 0xE8:
                continue
            instruction_rva = pe.to_rva(offset)
            if instruction_rva is None:
                continue
            destination = instruction_rva + 5 + struct.unpack_from("<i", pe.data, offset + 1)[0]
            if destination != target_rva:
                continue
            function = pe.function(instruction_rva)
            refs.append(
                {
                    "instruction_rva": hx(instruction_rva),
                    "instruction_va": hx(pe.base + instruction_rva),
                    "target_rva": hx(destination),
                    "target_va": hx(pe.base + destination),
                    "caller_function_range_rva":
                        [hx(function[0]), hx(function[1])] if function else None,
                    "evidence": "direct relative E8 call target",
                }
            )
    return refs


def constructor_table_candidates(pe: PE) -> list[dict]:
    """Decode only the constructor's LEA targets and identify its table."""

    function = pe.function(CONSTRUCTOR_RVA)
    if function is None:
        start, end = CONSTRUCTOR_RVA, CONSTRUCTOR_RVA + 0x80
    else:
        start, end = function[0], min(function[1], CONSTRUCTOR_RVA + MAX_RANGE_BYTES)
    code = pe.bytes_at(start, end - start)
    candidates: list[dict] = []
    for index in range(0, max(0, len(code) - 6)):
        # The constructor uses 48 8d 05 disp32 for both a table and a shared
        # pointer.  Computing the RIP target is enough; no broad disassembly is
        # needed for this bounded candidate list.
        if code[index:index + 3] != b"\x48\x8d\x05":
            continue
        instruction_rva = start + index
        target_rva = instruction_rva + 7 + struct.unpack_from("<i", code, index + 3)[0]
        first = read_u64_at_rva(pe, target_rva)
        slot_values = [read_u64_at_rva(pe, target_rva + 8 * slot) for slot in range(9)]
        executable_slots = [
            hx(value - pe.base) if value is not None and value >= pe.base
            and pe.executable(value - pe.base) else None
            for value in slot_values
        ]
        candidates.append(
            {
                "instruction_rva": hx(instruction_rva),
                "instruction_va": hx(pe.base + instruction_rva),
                "target_rva": hx(target_rva),
                "target_va": hx(pe.base + target_rva),
                "first_qword": hx(first),
                "slot_rvas": executable_slots,
                "is_map_table_candidate": target_rva == MAP_TABLE_RVA
                and slot_values[6] == pe.base + MAP_EVALUATOR_RVA,
                "evidence": "constructor RIP-relative LEA target",
            }
        )
    return candidates


def bounded_objdump(
    objdump: Path, exe: Path, start_rva: int, end_rva: int
) -> dict:
    if end_rva <= start_rva:
        raise ValueError("objdump range must be non-empty")
    size = end_rva - start_rva
    if size > MAX_RANGE_BYTES:
        raise ValueError("single objdump range exceeds 64 KiB")
    start_va = EXPECTED_IMAGE_BASE + start_rva
    end_va = EXPECTED_IMAGE_BASE + end_rva
    command = [
        str(objdump),
        "-d",
        "-Mintel",
        f"--start-address={hex(start_va)}",
        f"--stop-address={hex(end_va)}",
        str(exe),
    ]
    completed = subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
    )
    return {
        "range_rva": [hx(start_rva), hx(end_rva)],
        "range_va": [hx(start_va), hx(end_va)],
        "requested_bytes": size,
        "returncode": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
        "command": command,
    }


def build_report() -> dict:
    exe = get_path("EU4_GAME_ROOT") / "eu4.exe"
    objdump_value = get_value("EU4_OBJDUMP", required=False)
    objdump = Path(objdump_value) if objdump_value else None
    if not exe.exists():
        raise FileNotFoundError(f"Configured EU4 executable does not exist: {exe}")
    size = exe.stat().st_size
    if size > MAX_FILE_BYTES:
        raise ValueError("Refusing executable larger than 128 MiB")
    digest = sha256_file(exe)
    if digest.lower() != EXPECTED_SHA256:
        raise ValueError(f"Unexpected EU4 executable SHA-256: {digest}")
    pe = PE(exe)
    if pe.base != EXPECTED_IMAGE_BASE:
        raise ValueError(f"Unexpected PE image base: {pe.base:#x}")
    check_memory_budget()

    token_descriptors = find_token_descriptors(pe)
    token_by_name = {record["name"]: record for record in token_descriptors}
    ctor_function = pe.function(CONSTRUCTOR_RVA)
    evaluator_function = pe.function(MAP_EVALUATOR_RVA)
    constructor_candidates = constructor_table_candidates(pe)
    map_table = next(
        (candidate for candidate in constructor_candidates if candidate["is_map_table_candidate"]),
        None,
    )
    table_slots: list[str | None] = []
    if map_table is not None:
        table_rva = int(map_table["target_rva"], 16)
        table_slots = map_table["slot_rvas"]
    else:
        table_rva = MAP_TABLE_RVA
        for slot in range(9):
            value = read_u64_at_rva(pe, table_rva + slot * 8)
            table_slots.append(
                hx(value - pe.base) if value is not None and value >= pe.base
                and pe.executable(value - pe.base) else None
            )

    caller_refs = direct_call_refs(pe, CONSTRUCTOR_RVA)
    caller_function = pe.function(0xB934D4)

    map_token_ids = {
        name: token_by_name.get(name, {}).get("token_id") for name in TOKEN_NAMES
    }
    mode_mapping = [
        {
            "token": "map_setup_normal",
            "token_id": map_token_ids.get("map_setup_normal"),
            "mode_value": 0,
            "condition": "mode DWORD == 0",
        },
        {
            "token": "map_setup_historical",
            "token_id": map_token_ids.get("map_setup_historical"),
            "mode_value": 1,
            "condition": "mode DWORD == 1",
        },
        {
            "token": "map_setup_random",
            "token_id": map_token_ids.get("map_setup_random"),
            "mode_value": 2,
            "condition": "mode DWORD == 2",
        },
        {
            "token": "map_setup_custom",
            "token_id": map_token_ids.get("map_setup_custom"),
            "mode_value": 3,
            "condition": "mode DWORD == 3",
        },
    ]

    report: dict = {
        "schema": "information.map_setup.static_contract.v1",
        "mode": "offline_static_only",
        "status": "static_candidate_with_read_only_input_path",
        "scope": {
            "purpose": "定位 map_setup 触发器的静态 token、构造器/函数表候选和地图模式读取链",
            "runtime_value_read": False,
            "current_map_mode_claimed": False,
            "save_or_mission_inference_used": False,
            "native_call_performed": False,
        },
        "executable": {
            "path": str(exe),
            "size_bytes": size,
            "sha256": digest,
            "expected_sha256": EXPECTED_SHA256,
            "image_base": hx(pe.base),
            "sha256_match": digest.lower() == EXPECTED_SHA256,
        },
        "bounds": {
            "max_single_disassembly_bytes": MAX_RANGE_BYTES,
            "max_total_requested_decode_bytes": MAX_DECODE_BYTES,
            "max_followed_function_or_range_count": MAX_FUNCTIONS,
            "actual_disassembly_range_count": 4,
        },
        "token_descriptors": token_descriptors,
        "constructor_candidate": {
            "rva": hx(CONSTRUCTOR_RVA),
            "va": hx(pe.base + CONSTRUCTOR_RVA),
            "function_range_rva": [hx(ctor_function[0]), hx(ctor_function[1])] if ctor_function else None,
            "object_size_bytes_observed": 0x70,
            "object_field_initialized": {"offset": hx(0x68), "value": 0},
            "vtable_candidates": constructor_candidates,
            "selected_map_table": map_table,
            "interpretation": "构造器候选；它把函数表地址写入新对象，未证明对象类名或运行时注册语义",
        },
        "vtable_candidate": {
            "rva": hx(table_rva),
            "va": hx(pe.base + table_rva),
            "slot_rvas": table_slots,
            "map_evaluator_slot_offset": hx(0x30),
            "map_evaluator_rva": hx(MAP_EVALUATOR_RVA),
            "map_evaluator_va": hx(pe.base + MAP_EVALUATOR_RVA),
            "rtti_validated": False,
            "evidence": "构造器写入的非 RTTI 函数表候选；第 7 个 qword（偏移 +0x30）指向直接读取地图模式链的叶函数",
        },
        "factory_candidate": {
            "direct_constructor_calls": caller_refs,
            "notable_call_site": {
                "instruction_rva": hx(0xB934D4),
                "instruction_va": hx(pe.base + 0xB934D4),
                "caller_function_range_rva":
                    [hx(caller_function[0]), hx(caller_function[1])] if caller_function else None,
                "adjacent_branch_pattern": "同一小片段还调用 BB9540、BB9650、BB96F0 等相邻构造器并随后调用通用处理函数",
            },
            "interpretation": "触发器工厂/注册分支候选；静态证据未解析出选择器输入与最终注册表",
            "unresolved": ["调用方的上游分支条件", "map_setup 通用 token（0x38ca）的独立语义", "运行时对象是否已注册"],
        },
        "read_only_mode_input": {
            "proven": True,
            "evaluator": {
                "rva": hx(MAP_EVALUATOR_RVA),
                "va": hx(pe.base + MAP_EVALUATOR_RVA),
                "function_range_rva": [hx(evaluator_function[0]), hx(evaluator_function[1])]
                if evaluator_function else [hx(MAP_EVALUATOR_RVA), hx(0xD155DE)],
                "range_kind": "manual_leaf_until_ret" if evaluator_function is None else "pdata_function",
                "object_token_field_offset": hx(0x68),
            },
            "input_chain": {
                "global_pointer_cell_rva": hx(MODE_GLOBAL_RVA),
                "global_pointer_cell_va": hx(pe.base + MODE_GLOBAL_RVA),
                "global_to_context_pointer_offset": hx(0x2150),
                "context_to_mode_dword_offset": hx(0x34),
                "read_description": "读取 [image+0x233fe58] 得到指针，再读取该对象 +0x2150 的指针，最后读取其 +0x34 的 DWORD；本报告没有读取这些地址的运行时值",
            },
            "mode_mapping": mode_mapping,
            "generic_parent_token": {
                "token": "map_setup",
                "token_id": map_token_ids.get("map_setup"),
                "leaf_cases_seen": False,
                "meaning": "该叶函数没有把 0x38ca 作为 0/1/2/3 模式分支处理，独立语义未知",
            },
            "standalone_getter_proven": False,
            "interpretation": "已证明一个只读触发器评估路径直接读取地图模式 DWORD；尚未证明单独导出的 getter 或当前地图模式值",
        },
        "disassembly": [],
        "evidence_notes": [
            "字符串和 token ID 属于静态二进制证据；它们不代表当前游戏状态。",
            "构造器和函数表关系由有界指令解码与 qword 目标共同支持；没有把它命名为 MSVC RTTI。",
            "地图模式的 0/1/2/3 对应关系来自叶函数对 0x38cb..0x38ce 的比较；没有用任务 membership 或存档头反推模式。",
            "当前模式值、全局指针指向的运行时对象和 trigger 注册结果均未读取。",
        ],
    }

    if objdump is None or not objdump.exists():
        report["disassembly_error"] = "EU4_OBJDUMP 未配置或路径不存在；静态地址候选仍保留，但未附 objdump 文本"
    else:
        ranges = [
            (CONSTRUCTOR_RVA, 0xBB9650, "constructor"),
            (0xB934A4, 0xB93540, "factory_call_window"),
            (MAP_EVALUATOR_RVA, 0xD155DE, "map_evaluator_leaf"),
            (0xD155E0, 0xD15A40, "sibling_virtual_method_window"),
        ]
        total = sum(end - start for start, end, _ in ranges)
        if total > MAX_DECODE_BYTES or len(ranges) > MAX_FUNCTIONS:
            raise AssertionError("bounded disassembly budget violated")
        for start, end, label in ranges:
            item = bounded_objdump(objdump, exe, start, end)
            item["label"] = label
            report["disassembly"].append(item)
        report["disassembly_budget_used_bytes"] = total

    check_memory_budget()
    return report


def main() -> int:
    output = Path(__file__).resolve().parent / "runtime/information-branches-20261024-001/map-setup-trigger-contract.json"
    try:
        report = build_report()
    except Exception as exc:  # keep a deterministic failure visible to callers
        print(f"research failed: {exc}", file=sys.stderr)
        return 1
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
