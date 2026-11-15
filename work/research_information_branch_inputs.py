"""为信息服务分支输入生成有界的普通静态合同。

本脚本只分析固定 SHA-256 的 EU4 1.37.4 PE 文件，不打开游戏进程、不调用
RPM/REA、不写入生产 profile，也不把静态推断当作 FRA 的运行时观测。代码
解码范围由脚本固定，单段和总量均受 ``work/AGENTS.md`` 的限制。
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from work.discover_diplomacy import PE, check_memory_budget, make_disassembler
from work.local_config import game_exe


EXPECTED_SHA256 = (
    "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
)
IMAGE_BASE = 0x140000000
MAX_RANGE_BYTES = 64 * 1024
MAX_TOTAL_DECODE_BYTES = 256 * 1024

# These are the only code ranges decoded by this report.  The constructor ranges
# are corroboration for the static vtable/layout family; they do not identify the
# country object's runtime vtable.
CODE_RANGES = (
    (0x2DC6E0, 0x2E125B, "country_writer"),
    (0x737CE0, 0x737ECB, "flag_serializer_body"),
    (0x17091B0, 0x1709298, "token_helper"),
    (0x74C8E0, 0x74D6D2, "vtable_constructor_corroboration"),
    (0x9D5890, 0x9D6308, "vtable_constructor_corroboration_2"),
)


def _decode_range(pe: PE, md, begin: int, end: int):
    """Decode one explicit range and return compact instruction records."""
    if md is not None:
        return [
            {
                "rva": hex(ins.address - pe.base),
                "bytes": ins.bytes.hex(),
                "mnemonic": ins.mnemonic,
                "operands": ins.op_str,
            }
            for ins in md.disasm(pe.bytes_at(begin, end - begin), pe.base + begin)
        ]

    command = [
        "objdump",
        "-d",
        "-w",
        "-Mintel",
        f"--start-address={pe.base + begin:#x}",
        f"--stop-address={pe.base + end:#x}",
        str(pe.path),
    ]
    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        errors="replace",
        check=True,
        timeout=30,
    )
    # Keep the fallback bounded even if a toolchain emits unexpected output.
    if len(result.stdout) > 8 * 1024 * 1024:
        raise ValueError("bounded objdump output exceeded 8 MiB")
    rows = []
    pattern = re.compile(
        r"^\s*([0-9a-fA-F]+):\s+((?:[0-9a-fA-F]{2}\s+)+)"
        r"\s*(\S+)(?:\s+(.*))?$"
    )
    for line in result.stdout.splitlines():
        match = pattern.match(line)
        if not match:
            continue
        address = int(match.group(1), 16)
        rva = address - pe.base
        byte_tokens = match.group(2).split()
        if not begin <= rva < end:
            continue
        rows.append(
            {
                "rva": hex(rva),
                "bytes": "".join(byte_tokens).lower(),
                "mnemonic": match.group(3),
                "operands": match.group(4) or "",
            }
        )
    return rows


def _instruction_by_rva(instructions, rva: int):
    for row in instructions:
        if int(row["rva"], 16) == rva:
            return row
    raise AssertionError(f"decoder did not return instruction at RVA {rva:#x}")


def _selected(instructions, addresses):
    return [_instruction_by_rva(instructions, address) for address in addresses]


def _assert_bytes(pe: PE, expected):
    for rva, hex_bytes in expected.items():
        actual = pe.bytes_at(rva, len(hex_bytes) // 2).hex()
        if actual != hex_bytes:
            raise AssertionError(
                f"unexpected bytes at RVA {rva:#x}: {actual} != {hex_bytes}"
            )


def _hash_file(path: Path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _range_record(pe: PE, instructions, begin: int, end: int, label: str):
    raw = pe.bytes_at(begin, end - begin)
    if len(raw) != end - begin:
        raise AssertionError(f"PE range is not fully file-backed: {begin:#x}:{end:#x}")
    function = pe.function(begin)
    record = {
        "label": label,
        "start_rva": hex(begin),
        "end_rva_exclusive": hex(end),
        "byte_length": len(raw),
        "bytes_sha256": hashlib.sha256(raw).hexdigest(),
        "function_boundary_from_pdata": (
            [hex(function[0]), hex(function[1])] if function else None
        ),
        "decoded_instruction_count": len(instructions),
    }
    if function and (function[0] != begin or function[1] != end):
        record["range_relation"] = (
            "显式有界读取范围与 .pdata 函数边界不同；范围仅用于固定字节证据，"
            "不把相邻填充字节解释为 helper 指令"
        )
    return record


def _prior_source(path: Path):
    return {
        "path": path.relative_to(ROOT).as_posix(),
        "sha256": _hash_file(path),
        "evidence_kind": "prior_ordinary_static_report",
    }


def build_report():
    pe = PE(game_exe())
    digest = hashlib.sha256(pe.data).hexdigest()
    if digest != EXPECTED_SHA256:
        raise ValueError(f"unsupported game binary SHA-256: {digest}")
    if pe.base != IMAGE_BASE:
        raise ValueError(f"unexpected image base: {pe.base:#x}")

    md, capstone = make_disassembler(ROOT / "work/deps/capstone-5.0.7")
    decoded = {}
    ranges = []
    total = 0
    for begin, end, label in CODE_RANGES:
        if not 0 <= begin < end or end - begin > MAX_RANGE_BYTES:
            raise AssertionError(f"range limit failure: {begin:#x}:{end:#x}")
        if not pe.executable(begin) or not pe.executable(end - 1):
            raise AssertionError(f"range is not executable: {begin:#x}:{end:#x}")
        total += end - begin
        if total > MAX_TOTAL_DECODE_BYTES:
            raise AssertionError("total decode limit failure")
        instructions = _decode_range(pe, md, begin, end)
        decoded[label] = instructions
        ranges.append(_range_record(pe, instructions, begin, end, label))

    # The writer gate and indirect call are the direct static contract for the
    # country field.  Keep exact bytes here so a later report cannot silently
    # drift to another 1.37.4 build.
    _assert_bytes(
        pe,
        {
            0x2DCDD2: "498b8788020000",
            0x2DCDD9: "492b8780020000",
            0x2DCDE0: "4883f802",
            0x2DCDE4: "7221",
            0x2DCDE6: "bacc290000",
            0x2DCDEB: "488bce",
            0x2DCDEE: "e8bdc34201",
            0x2DCDF3: "498b8770020000",
            0x2DCDFD: "498d8f70020000",
            0x2DCE04: "ff5008",
            0x737D1D: "488b4118",
            0x737D21: "482b4110",
            0x737D25: "48d1f8",
            0x737D28: "4c63f8",
            0x737D2B: "85c0",
            0x737D2D: "0f8e71010000",
            0x737D3E: "498b4610",
            0x737D42: "0fbf1458",
            0x737D46: "48c1e20548",
            0x737D4A: "4803150f00c201",
            0x737D51: "48837a1810",
            0x737D56: "7203",
            0x737D58: "488b12",
            0x737D5B: "488bce",
            0x737D5E: "e8ad10fd00",
        },
    )

    writer_selected = _selected(
        decoded["country_writer"],
        (
            0x2DCDD2,
            0x2DCDD9,
            0x2DCDE0,
            0x2DCDE4,
            0x2DCDE6,
            0x2DCDEB,
            0x2DCDEE,
            0x2DCDF3,
            0x2DCDFD,
            0x2DCE04,
        ),
    )
    body_selected = _selected(
        decoded["flag_serializer_body"],
        (
            0x737D1D,
            0x737D21,
            0x737D25,
            0x737D28,
            0x737D2B,
            0x737D2D,
            0x737D3E,
            0x737D42,
            0x737D46,
            0x737D4A,
            0x737D51,
            0x737D56,
            0x737D58,
            0x737D5B,
            0x737D5E,
        ),
    )
    constructor_selected = _selected(
        decoded["vtable_constructor_corroboration"],
        (0x74CB16, 0x74CB1D, 0x74CB24, 0x74CB2B),
    )
    constructor2_selected = _selected(
        decoded["vtable_constructor_corroboration_2"],
        (0x9D5A5B, 0x9D5A62, 0x9D5A69, 0x9D5A70),
    )

    string_rva = 0x20A630C
    string_offset = pe.to_offset(string_rva)
    if string_offset is None or pe.bytes_at(string_rva, 6) != b"flags\0":
        raise AssertionError("flags key string was not found at the pinned RVA")
    token_rva = string_rva - 4
    token_offset = pe.to_offset(token_rva)
    if token_offset is None or pe.u32(token_offset) != 0x29CC:
        raise AssertionError("flags token preceding the key is not 0x29cc")

    vtable_rva = 0x1C57520
    vtable_offset = pe.to_offset(vtable_rva)
    if vtable_offset is None:
        raise AssertionError("pinned vtable is not file-backed")
    vtable_raw = pe.bytes_at(vtable_rva, 5 * 8)
    vtable_slots = {
        hex(index * 8): hex(struct.unpack_from("<Q", vtable_raw, index * 8)[0] - pe.base)
        for index in range(5)
    }
    if vtable_slots != {
        "0x0": "0x2cbd80",
        "0x8": "0xd2f280",
        "0x10": "0x737ce0",
        "0x18": "0x17067e0",
        "0x20": "0x7373c0",
    }:
        raise AssertionError(f"unexpected vtable slots: {vtable_slots}")

    prior_paths = (
        ROOT / "work/runtime/information-missions-20261024-001/mission-writer-boundary.json",
        ROOT / "work/runtime/information-missions-20261024-001/mission-serialization.json",
    )
    prior_sources = [_prior_source(path) for path in prior_paths if path.exists()]

    report = {
        "schema": "information.country.flags.static-contract.v1",
        "evidence_kind": "ordinary_static_file_analysis_not_REA_Evidence",
        "game_sha256": digest,
        "game_version": "1.37.4",
        "image_base": hex(pe.base),
        "address_kind": "RVA",
        "scope": {
            "country": "FRA",
            "country_identity": "未在本次静态报告中观测；运行时必须由独立上下文证明",
            "supported_scope": "仅允许后续读取器显式选择 FRA",
        },
        "analysis": {
            "decoder": (
                "capstone " + capstone.__version__
                if capstone is not None
                else "bounded objdump -w -Mintel"
            ),
            "decoded_bytes": total,
            "limits": {
                "single_code_range_bytes": MAX_RANGE_BYTES,
                "total_code_decode_bytes": MAX_TOTAL_DECODE_BYTES,
                "runtime_process_opened": False,
                "rpm_used": False,
                "rea_used": False,
                "production_profile_written": False,
            },
        },
        "prior_sources": prior_sources,
        "ranges": ranges,
        "selected_instructions": {
            "country_writer": writer_selected,
            "flag_serializer_body": body_selected,
            "vtable_constructor_corroboration": constructor_selected,
            "vtable_constructor_corroboration_2": constructor2_selected,
        },
        "static_data": {
            "key_record": {
                "token_id": "0x29cc",
                "token_rva": hex(token_rva),
                "token_file_offset": hex(token_offset),
                "string": "flags",
                "string_rva": hex(string_rva),
                "string_file_offset": hex(string_offset),
                "bytes_sha256": hashlib.sha256(pe.bytes_at(token_rva, 12)).hexdigest(),
            },
            "vtable": {
                "rva": hex(vtable_rva),
                "bytes_sha256": hashlib.sha256(vtable_raw).hexdigest(),
                "slots_rva": vtable_slots,
            },
        },
        "findings": {
            "serialized_key": {
                "name": "flags",
                "token_id": "0x29cc",
                "token_helper_rva": "0x17091b0",
                "evidence": "country writer loads token 0x29cc and calls the bounded helper before the virtual call",
            },
            "country_writer": {
                "writer_rva_range": ["0x2dc6e0", "0x2e125b"],
                "flag_container_field_offset": "0x270",
                "embedded_object": True,
                "begin_pointer_offset_from_object": "0x10",
                "end_pointer_offset_from_object": "0x18",
                "begin_pointer_country_offset": "0x280",
                "end_pointer_country_offset": "0x288",
                "nonempty_gate": "(end - begin) >= 2",
                "array_element_width_bytes": 2,
                "virtual_call_slot": "0x8",
                "runtime_vtable_identity": "未由静态国家 writer 绑定；运行时必须校验对象内 vtable",
            },
            "serializer_body": {
                "body_rva_range": ["0x737ce0", "0x737ecb"],
                "count_expression": "(end - begin) >> 1",
                "element_type": "signed int16",
                "element_load": "movsx WORD PTR [array + index * 2]",
                "iteration_order": "begin 到 end 的地址顺序",
                "name_table_pointer_rva": "0x2357d60",
                "name_table_entry_stride_bytes": 32,
                "name_table_entry_expression": "table + (signed_int16_id << 5)",
                "string32": {
                    "length_offset": "0x10",
                    "capacity_offset": "0x18",
                    "inline_storage_when": "capacity < 0x10",
                    "heap_pointer_offset_when_long": "0x0",
                    "name_writer_rva": "0x1708e10",
                },
                "empty_set_condition": "body 以 test eax,eax; jle 跳过循环；对合法非负偶数跨度，begin == end；读失败不能解释为空集合",
                "semantic_limits": ["静态证据不证明排序或唯一性", "静态证据不证明当前分支可见性"],
            },
            "vtable_candidate": {
                "rva": hex(vtable_rva),
                "slots_rva": vtable_slots,
                "provenance": "静态 .rdata 表及独立构造路径；不是 FRA 运行时观测",
                "runtime_guard": "[country+0x270] 必须在两次读取中等于 module_base + 0x1c57520，并同时检查 +0x8/+0x10 目标",
            },
            "constructor_corroboration": {
                "first": {
                    "range": ["0x74c8e0", "0x74d6d2"],
                    "vtable_rva_loaded": "0x1c57520",
                    "field_offsets": ["0xb38", "0xb48", "0xb50"],
                    "interpretation": "同一静态布局家族的独立构造路径；不等同于 country+0x270 的运行时赋值",
                },
                "second": {
                    "range": ["0x9d5890", "0x9d6308"],
                    "vtable_rva_loaded": "0x1c57520",
                    "field_offsets": ["0x1b8", "0x1c8", "0x1d0"],
                    "interpretation": "独立构造路径的静态佐证",
                },
            },
        },
        "runtime_read_contract": {
            "status": "proposed_bounded_reader_guards_only",
            "identity": [
                "验证安装 EXE SHA-256 等于 game_sha256",
                "从独立运行时上下文证明 country == FRA；本报告不能猜测身份",
                "确认模块 base 后再将所有 RVA 转为 VA",
            ],
            "object": {
                "address": "country_pointer + 0x270",
                "embedded_object": True,
                "vtable_rva": "0x1c57520",
                "required_vtable_slots": {"0x8": "0xd2f280", "0x10": "0x737ce0"},
            },
            "container": {
                "begin_address": "object + 0x10",
                "end_address": "object + 0x18",
                "require_end_at_least_begin": True,
                "require_even_byte_span": True,
                "max_elements": 4096,
            },
            "name_resolution": {
                "table_pointer_address": "module_base + 0x2357d60",
                "entry_stride_bytes": 32,
                "reject_negative_id": True,
                "max_name_bytes": 256,
                "require_length_le_capacity": True,
                "inline_capacity_threshold": 16,
                "reject_unreadable_pointer_or_malformed_string": True,
            },
            "stability": {
                "max_total_rpm_bytes": 512 * 1024,
                "read_before_and_after": True,
                "require_exact_ids_and_names_match": True,
                "read_failure_is_unknown_not_empty": True,
                "no_calls_writes_injection_or_game_progress": True,
            },
        },
        "unresolved": [
            "本次未打开游戏进程，未观测 FRA country pointer、对象 vtable、begin/end 或任何旗标 ID",
            "RVA 0x2357d60 的运行时表指针及表项数量未静态绑定为具体内存地址",
            "country+0x270 的运行时 vtable 是否为 0x1c57520 必须由读取器校验",
            "对象 +0x20/+0x28 的容量或辅助字符串语义未确定；读取器不得把它们当作已知字段",
            "静态报告不能证明当前世界、存档或分支状态",
        ],
        "peak_committed_bytes": check_memory_budget(),
    }
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = build_report()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    # Do not silently replace an earlier evidence record.
    with args.output.open("x", encoding="utf-8") as output:
        json.dump(report, output, ensure_ascii=False, indent=2)
        output.write("\n")
    print(
        json.dumps(
            {
                "output": str(args.output),
                "game_sha256": report["game_sha256"],
                "decoded_bytes": report["analysis"]["decoded_bytes"],
                "ranges": len(report["ranges"]),
                "runtime_process_opened": report["analysis"]["limits"]["runtime_process_opened"],
                "peak_committed_bytes": report["peak_committed_bytes"],
            },
            ensure_ascii=False,
        )
    )


if __name__ == "__main__":
    main()
