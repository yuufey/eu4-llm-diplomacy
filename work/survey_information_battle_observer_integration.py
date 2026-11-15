"""Survey the v22 observer's source, installer, and build integration.

This is a bounded, source-only survey.  It reads the recorded installation
and build manifest, hashes the manifest's 92 source copies, and records
line-scoped source evidence for startup, frame dispatch, command files,
installation, and ownership.  It does not start a process, install a DLL,
read game memory, invoke REA, or inspect a large disassembly.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]
MAX_FILE_BYTES = 16 * 1024 * 1024
DEFAULT_INSTALLATION = (
    ROOT
    / "work"
    / "runtime"
    / "diplomacy-observer-20261025-information-battle-002"
    / "installation.json"
)
DEFAULT_OUTPUT = (
    ROOT
    / "work"
    / "runtime"
    / "information-battle-observer-20261025-001"
    / "integration-survey-001.json"
)
EXPECTED_EXE_SHA = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
EXPECTED_DLL_SHA = "d80ef39d66d263788c0af4df0892b4ff781e5e3b3f9aea7ebe33759327e457db"


def _inside(path: Path) -> Path:
    resolved = path.expanduser().resolve()
    try:
        resolved.relative_to(ROOT)
    except ValueError as exc:
        raise ValueError(f"path outside workspace: {path}") from exc
    return resolved


def _path(value: str | Path) -> Path:
    candidate = Path(value)
    if not candidate.is_absolute():
        candidate = ROOT / candidate
    resolved = _inside(candidate)
    if not resolved.is_file():
        raise FileNotFoundError(resolved)
    return resolved


def _relative(path: Path) -> str:
    return _inside(path).relative_to(ROOT).as_posix()


def _digest(path: Path) -> tuple[int, str]:
    path = _inside(path)
    if not path.is_file():
        raise FileNotFoundError(path)
    size = path.stat().st_size
    if size > MAX_FILE_BYTES:
        raise ValueError(f"oversized file refused: {path} ({size} bytes)")
    digest = hashlib.sha256()
    count = 0
    with path.open("rb") as stream:
        while True:
            chunk = stream.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            count += len(chunk)
    if count != size:
        raise OSError(f"short hash read: {path}")
    return size, digest.hexdigest()


def _read_json(path: Path) -> Any:
    size = path.stat().st_size
    if size > MAX_FILE_BYTES:
        raise ValueError(f"oversized JSON refused: {path} ({size} bytes)")
    with path.open("r", encoding="utf-8-sig") as stream:
        return json.load(stream)


def _read_lines(path: Path) -> list[str]:
    size = path.stat().st_size
    if size > MAX_FILE_BYTES:
        raise ValueError(f"oversized source refused: {path} ({size} bytes)")
    with path.open("r", encoding="utf-8-sig", errors="replace") as stream:
        return stream.read().splitlines()


def _selected_text(path: Path, ranges: Iterable[tuple[int, int]]) -> tuple[list[str], int]:
    lines = _read_lines(path)
    selected: list[str] = []
    for start, end in ranges:
        if start < 1 or end < start or end > len(lines):
            raise ValueError(f"invalid line range {start}-{end} for {_relative(path)}")
        selected.extend(lines[start - 1 : end])
    return selected, len(lines)


def _source_pin(
    relative: str,
    role: str,
    ranges: list[tuple[int, int]],
    tokens: list[str],
) -> dict[str, Any]:
    path = _path(relative)
    size, digest = _digest(path)
    selected, line_count = _selected_text(path, ranges)
    joined = "\n".join(selected)
    missing = [token for token in tokens if token not in joined]
    if missing:
        raise ValueError(f"source guard missing in {relative}: {missing}")
    return {
        "path": _relative(path),
        "bytes": size,
        "sha256": digest,
        "line_count": line_count,
        "line_ranges_inclusive": [[start, end] for start, end in ranges],
        "role": role,
        "token_guards": tokens,
    }


def _artifact_pin(path: Path, role: str) -> dict[str, Any]:
    size, digest = _digest(path)
    return {"path": _relative(path), "bytes": size, "sha256": digest, "role": role}


def _source_specs() -> list[tuple[str, str, list[tuple[int, int]], list[str]]]:
    return [
        (
            "work/native/diplomacy-observer-v10.cpp",
            "v22 native root, frame wrapper, startup identity and installation ACK",
            [(1, 11), (233, 265), (366, 408), (411, 445), (553, 591)],
            [
                "#define BridgeStart ObserverControlStart",
                "extern \"C\" void bridge_frame_tick(void* context)",
                "extern \"C\" __declspec(dllexport) DWORD WINAPI BridgeStart",
                "creation_filetime",
                "version\\\":22",
            ],
        ),
        (
            "work/native/control-probe.cpp",
            "v22 DLL entry, one-start guard, frame patch and DllMain module identity",
            [(12, 25), (40, 70), (87, 106), (107, 156), (187, 203), (206, 209)],
            [
                "static volatile LONG started",
                "extern \"C\" __declspec(dllexport) DWORD WINAPI BridgeStart",
                "base+0x10a6d90",
                "control_frame_patch_plan.targets[0]={target,20",
                "BOOL WINAPI DllMain",
            ],
        ),
        (
            "work/native/frame_stub.S",
            "existing frame entry shim and volatile register/XMM restoration",
            [(319, 355)],
            [
                ".globl bridge_frame_stub",
                "subq $0xc8, %rsp",
                "movdqu %xmm0",
                "call bridge_frame_tick",
                "jmp *bridge_trampoline(%rip)",
            ],
        ),
        (
            "work/native/automated-control.inc",
            "frame-thread request-file command parser",
            [(1, 20), (44, 92)],
            [
                "game-control.request",
                "TEST_ONLY savegame",
                "TEST_ONLY pause",
                "TEST_ONLY advance_35_days",
            ],
        ),
        (
            "work/native/popup-control.inc",
            "frame-thread popup confirmation request parser",
            [(1, 34)],
            [
                "popup_request",
                "TEST_ONLY %lu %llx %llx %llx",
                "popup_confirmation_rejected",
            ],
        ),
        (
            "work/native/entry-patch-transaction.inc",
            "shared bounded patch transaction and published trampoline lifetime",
            [(1, 18), (29, 107), (150, 164), (868, 921)],
            [
                "The trampoline must remain executable for the",
                "Published entries are never cleared",
                "guarded_patch_apply",
                "guarded_patch_rollback",
                "guarded_patch_retry_pending",
            ],
        ),
        (
            "tools/start_diplomacy_observer.py",
            "operator installation orchestration and no-retry installation record",
            [(1, 7), (344, 383), (389, 416)],
            [
                "native/inject_probe.py",
                "EXPERIMENT_ALREADY_ATTEMPTED_USE_NEW_DIRECTORY_AND_PROCESS",
                "INSTALLATION_FAILED_NO_RETRY_IN_THIS_PROCESS",
                "modules_after_install",
            ],
        ),
        (
            "work/native/inject_probe.py",
            "remote loader duplicate-bridge policy and BridgeStart lifetime",
            [(1, 22), (434, 480), (521, 571)],
            [
                "An EU4 bridge DLL is already loaded",
                "restart the game before installing another build",
                "BridgeStart returned",
                "dll_unloaded",
            ],
        ),
        (
            "work/prepare_information_observer_reuse.py",
            "pinned 92-source reuse verifier and fresh-copy manifest",
            [(1, 12), (36, 75), (80, 104)],
            [
                "len(manifest[\"sources\"]) == 92",
                "validated_source_changed",
                '"recompiled": False',
                '"verified_source_count": 92',
            ],
        ),
        (
            "work/native/build-diplomacy-observer.ps1",
            "v22 build source list and manifest writer",
            [(1, 16), (35, 46)],
            [
                "eu4_bridge_diplomacy_observer_v22.dll",
                "$sourceNames",
                "build-manifest.json",
                "dll_sha256",
            ],
        ),
        (
            "bridge/diplomacy_observer_service.py",
            "read-only HTTP observer status/capability surface",
            [(41, 82)],
            [
                "/observer/v1/capabilities",
                "read_only",
                "read_only_observer",
                "do_POST = refuse_write",
            ],
        ),
        (
            "bridge/diplomacy.py",
            "installation ACK capability and runtime health checks",
            [(405, 425), (17387, 17400)],
            [
                "diplomacy_observer_installed",
                "LOADED_MODULE_IDENTITY_MISMATCH",
                "FRAME_HEARTBEAT_STALE",
            ],
        ),
        (
            "work/native/information-battle-entry-plan.h",
            "new natural battle-entry candidate; research-only and outside v22 manifest",
            [(10, 23), (129, 161)],
            [
                "Fixed1374 RVA238620 candidate only",
                "kPatchBytes = 21",
                "neither allocates executable memory nor publishes",
                "Status::prepared",
            ],
        ),
        (
            "work/probe_information_battle_entry_contract.py",
            "bounded research association for the 0x238620 candidate",
            [(65, 76), (90, 107)],
            [
                "CALL238620",
                "at23A408",
                '"business_dispatch": False',
                '"B01_B04_available": False',
            ],
        ),
    ]


def _source_pin_list(manifest: dict[str, Any], runtime_dir: Path) -> dict[str, Any]:
    entries = manifest.get("sources")
    if not isinstance(entries, list) or len(entries) != 92:
        raise ValueError("current v22 manifest does not contain exactly 92 sources")
    canonical = [{"name": item.get("name"), "sha256": item.get("sha256")} for item in entries]
    fingerprint = hashlib.sha256(
        json.dumps(canonical, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    pins: list[dict[str, Any]] = []
    mismatches: list[str] = []
    for item in entries:
        name = item.get("name")
        expected = item.get("sha256")
        if not isinstance(name, str) or Path(name).name != name or not isinstance(expected, str):
            raise ValueError("invalid current manifest source entry")
        root_path = ROOT / "work" / "native" / name
        runtime_path = runtime_dir / name
        root_hash = _digest(root_path)[1] if root_path.is_file() else None
        runtime_hash = _digest(runtime_path)[1] if runtime_path.is_file() else None
        match = expected == root_hash == runtime_hash
        if not match:
            mismatches.append(name)
        pins.append({
            "name": name,
            "manifest_sha256": expected,
            "root_native_sha256": root_hash,
            "runtime_copy_sha256": runtime_hash,
            "matches_manifest_and_each_other": match,
        })
    return {
        "count": len(pins),
        "ordered_name_sha256_fingerprint": fingerprint,
        "mismatches": mismatches,
        "pins": pins,
    }


def _explicit_command_search(paths: list[Path]) -> dict[str, Any]:
    tokens = ["observer_status", "enable_observer", "disable_observer"]
    hits: dict[str, list[dict[str, Any]]] = {token: [] for token in tokens}
    for path in paths:
        lines = _read_lines(path)
        for number, line in enumerate(lines, 1):
            for token in tokens:
                if token in line:
                    hits[token].append({"path": _relative(path), "line": number})
    return {
        "tokens_checked": tokens,
        "paths_checked": [_relative(path) for path in paths],
        "hits": hits,
        "all_explicit_tokens_absent": not any(hits.values()),
    }


def _build_report(installation: Path) -> dict[str, Any]:
    installation = _path(installation)
    record = _read_json(installation)
    if not isinstance(record, dict):
        raise ValueError("installation record is not an object")
    runtime_dir = installation.parent
    manifest_path = runtime_dir / "build-manifest.json"
    manifest = _read_json(manifest_path)
    if not isinstance(manifest, dict):
        raise ValueError("build manifest is not an object")

    installation_pin = _artifact_pin(installation, "recorded observer installation")
    manifest_pin = _artifact_pin(manifest_path, "recorded v22 build manifest")
    loader_path = runtime_dir / "loader-output.txt"
    loader_pin = _artifact_pin(loader_path, "recorded loader output") if loader_path.is_file() else None
    source_archive_manifest = None
    reuse = manifest.get("artifact_reuse")
    if isinstance(reuse, dict) and isinstance(reuse.get("source_manifest"), str):
        source_archive_path = _inside(Path(reuse["source_manifest"]))
        if source_archive_path.is_file():
            source_archive_manifest = _artifact_pin(source_archive_path, "pinned source manifest referenced by artifact_reuse")

    source_fingerprint = _source_pin_list(manifest, runtime_dir)
    source_pins = [_source_pin(*spec) for spec in _source_specs()]
    current_source_names = {item["name"] for item in manifest["sources"]}
    for item in source_pins:
        item["current_v22_manifest_source"] = Path(item["path"]).name in current_source_names

    command_paths = [
        _path("work/native/diplomacy-observer-v10.cpp"),
        _path("work/native/control-probe.cpp"),
        _path("work/native/automated-control.inc"),
        _path("work/native/popup-control.inc"),
        _path("tools/start_diplomacy_observer.py"),
        _path("bridge/diplomacy_observer_service.py"),
    ]

    frame_start = 0x10A6D90
    frame_size = 20
    entry_start = 0x238620
    entry_size = 21
    frame_end = frame_start + frame_size
    entry_end = entry_start + entry_size
    overlap = frame_start < entry_end and entry_start < frame_end

    modules_after = record.get("modules_after_install")
    module_summary = []
    if isinstance(modules_after, list):
        for module in modules_after:
            if isinstance(module, dict):
                module_summary.append({
                    "name": module.get("name"),
                    "path": module.get("path"),
                    "path_relative": _relative(Path(module["path"])) if isinstance(module.get("path"), str) and Path(module["path"]).exists() else module.get("path"),
                    "sha256": module.get("sha256"),
                })

    installer_source = _path("work/native/inject_probe.py")
    observer_sources = [
        _path("work/native/diplomacy-observer-v10.cpp"),
        _path("work/native/control-probe.cpp"),
        _path("work/native/frame_stub.S"),
        _path("work/native/entry-patch-transaction.inc"),
        _path("tools/start_diplomacy_observer.py"),
        installer_source,
        _path("bridge/diplomacy_observer_service.py"),
    ]
    command_search = _explicit_command_search(observer_sources)

    return {
        "schema": "information_battle_observer_integration/source_survey_v1",
        "status": "source_only_complete_with_unresolved_natural_entry_integration",
        "scope": {
            "purpose": "盘点当前v22观察器的安装、命令、frame tick、构建来源、身份和生命周期接入点，并核对238620候选是否与已有frame补丁重叠",
            "performed": [
                "bounded source reads with line-range/token guards",
                "streamed SHA-256 for the installation, build manifests, v22 source copies, and selected source files",
                "machine-derived 92-source consistency and ordered-name fingerprint",
            ],
            "not_performed": [
                "game start/installation/RPM/REA/disassembly or native test execution",
                "any production/source/report modification outside this survey and its output",
            ],
            "evidence_separation": "source facts, recorded installation artifacts, and research-only 0x238620 candidate evidence are separate; no current v22 runtime proof is inferred for the candidate",
        },
        "provenance": {
            "installation": installation_pin,
            "build_manifest": manifest_pin,
            "loader_output": loader_pin,
            "source_archive_manifest": source_archive_manifest,
            "script_sha256": _digest(Path(__file__))[1],
            "fixed_build": {
                "version": manifest.get("version"),
                "game_sha256": manifest.get("game_sha256"),
                "expected_game_sha256": EXPECTED_EXE_SHA,
                "dll_sha256": manifest.get("dll_sha256"),
                "expected_dll_sha256": EXPECTED_DLL_SHA,
                "experiment_id": manifest.get("experiment_id"),
            },
        },
        "build_fingerprint": {
            "manifest_version": manifest.get("version"),
            "compiled": manifest.get("compiled"),
            "runtime_verified": manifest.get("runtime_verified"),
            "source_count": source_fingerprint["count"],
            "ordered_name_sha256_fingerprint": source_fingerprint["ordered_name_sha256_fingerprint"],
            "source_pins_mismatches": source_fingerprint["mismatches"],
            "manifest_sources": source_fingerprint["pins"],
            "compiler_arguments": manifest.get("compiler_arguments"),
            "artifact_reuse": manifest.get("artifact_reuse"),
            "reused_build": manifest.get("reused_build"),
            "update_path": {
                "builder": "work/native/build-diplomacy-observer.ps1:35-45",
                "reuse_verifier": "work/prepare_information_observer_reuse.py:36-104",
                "rule": "更新v22时由builder重新哈希$sourceNames并写build-manifest.json；复用模式先验证92个源文件和固定DLL，再在新runtime目录生成manifest，不能把新入口文件视为已接入。",
            },
        },
        "source_pins": source_pins,
        "installation_observation": {
            "recorded_only": True,
            "identity": {
                key: record.get(key)
                for key in (
                    "pid", "creation_filetime", "session_id", "game_sha256",
                    "dll_sha256", "experiment_id", "installation_returncode",
                    "runtime_verified", "ready_reason",
                )
            },
            "modules_after_install": module_summary,
            "module_count": len(module_summary),
            "loader_exit_status": "recorded loader-output.txt reports BridgeStart exit 0; this does not prove the new natural entry is wired",
            "runtime_verification_field": record.get("runtime_verified"),
        },
        "native_root_and_lifecycle": {
            "root": {
                "path": "work/native/diplomacy-observer-v10.cpp",
                "lines": [411, 591],
                "facts": [
                    "BridgeStart obtains the current process creation FILETIME and the DLL directory, sets request paths, deletes stale request files, delegates to ObserverControlStart, then installs the observer family.",
                    "A failed family installation attempts rollback and reports restart_required; the final ACK is version 22 and includes pid/session/creation_filetime.",
                    "bridge_frame_tick has a reentrancy guard, forwards to observer_legacy_frame, then performs frame-thread reads/flushes and emits health heartbeats.",
                ],
            },
            "dll_entry": {
                "path": "work/native/control-probe.cpp",
                "lines": [107, 156, 206, 208],
                "facts": [
                    "BridgeStart uses an InterlockedCompareExchange started guard, so a second BridgeStart call in the same DLL instance returns 10.",
                    "DllMain records self_module and calls DisableThreadLibraryCalls on process attach; no unload/disable observer command is registered here.",
                ],
            },
            "published_lifetime": {
                "path": "work/native/entry-patch-transaction.inc",
                "lines": [1, 18, 150, 164, 868, 880],
                "facts": [
                    "The helper requires caller-owned executable trampoline storage and says it must remain executable after the first INT3 publication.",
                    "Published target-to-trampoline registry entries are never cleared; rollback restores bytes but keeps the published route/trampoline alive.",
                    "The current injector records dll_unloaded=false and does not attempt DLL unload after BridgeStart.",
                ],
            },
        },
        "frame_and_command_integration": {
            "frame_patch": {
                "path": "work/native/control-probe.cpp",
                "lines": [139, 156],
                "target_rva": "0x10a6d90",
                "patch_bytes": 20,
                "trampoline_bytes": 34,
                "expected_prefix_bytes": 20,
                "replacement": "absolute jump to bridge_frame_stub padded to 20 bytes",
                "transaction": "bridge_entry_patch::guarded_patch_apply(control_frame_patch_plan)",
            },
            "frame_stub": {
                "path": "work/native/frame_stub.S",
                "lines": [319, 355],
                "facts": [
                    "bridge_frame_stub allocates 0xc8 bytes, saves volatile GPRs RAX/RCX/RDX/R8/R9/R10/R11 and XMM0-XMM5, calls bridge_frame_tick, restores them, then tail-jumps to bridge_trampoline.",
                    "The assembly comment/source does not preserve arithmetic flags; it is the existing frame shim contract, separate from the new natural battle-entry ABI fixture.",
                ],
            },
            "command_parser": [
                {
                    "path": "work/native/automated-control.inc",
                    "lines": [18, 20, 44, 92],
                    "surface": "game-control.request",
                    "commands": ["TEST_ONLY savegame", "TEST_ONLY autosave", "TEST_ONLY pause", "TEST_ONLY advance_1_days/5_days/35_days"],
                    "meaning": "test-save/time-control requests consumed on the observed frame thread; not observer enable/status/disable registration",
                },
                {
                    "path": "work/native/popup-control.inc",
                    "lines": [2, 34],
                    "surface": "popup-confirm.request",
                    "commands": ["TEST_ONLY <pid> <object> <button> <owner>"],
                    "meaning": "bounded test popup callback request; not observer enable/status/disable registration",
                },
            ],
            "explicit_observer_command_search": command_search,
            "status_surface": {
                "path": "bridge/diplomacy_observer_service.py",
                "lines": [41, 82],
                "facts": [
                    "Authenticated loopback GET exposes /observer/v1/capabilities and effect observations.",
                    "POST/PUT/DELETE/PATCH all route to refuse_write and return 405 for authorized or 403 for unauthorized callers; no enable/disable/status write route exists.",
                    "ObserverSession.health separately checks installation return code, same session, exactly one loaded module with the recorded DLL hash, and a fresh heartbeat.",
                ],
            },
        },
        "natural_entry_238620": {
            "candidate": {
                "path": "work/native/information-battle-entry-plan.h",
                "lines": [10, 23],
                "rva": "0x238620",
                "patch_bytes": 21,
                "status": "research_only_plan_not_in_current_v22_manifest",
            },
            "contract": {
                "path": "work/probe_information_battle_entry_contract.py",
                "lines": [69, 76],
                "finding": "The fixed-build research contract associates CALL238620 with return 0x23A40D at callsite 0x23A408 and treats RBX as a private caller context candidate; it explicitly keeps business dispatch unavailable.",
                "status": "ordinary/research evidence, not current DLL wiring",
            },
            "current_v22_manifest_membership": {
                "entry_plan_header": False,
                "entry_contract_script": False,
                "new_entry_sources_in_92_source_list": False,
            },
            "existing_frame_range": {
                "rva_start": "0x10a6d90",
                "rva_end_exclusive": "0x10a6da4",
                "bytes": 20,
            },
            "candidate_entry_range": {
                "rva_start": "0x238620",
                "rva_end_exclusive": "0x238635",
                "bytes": 21,
            },
            "rva_ranges_overlap": overlap,
            "conclusion": "RVA范围机械上不重叠；当前v22没有238620的源/manifest接入或运行确认。若要接入，需新版本/新build manifest并在新的安装目录和新进程中验证。",
        },
        "coexistence_and_update": {
            "installer_policy": {
                "path": "work/native/inject_probe.py",
                "lines": [461, 473],
                "finding": "The injector rejects any already loaded eu4_bridge_*, eu4_pair_lifecycle_*, or eu4_pair_pipeline_* module and tells the operator to restart the game before installing another build.",
            },
            "current_recorded_module": {
                "count": len(module_summary),
                "modules": module_summary,
                "dll_unloaded": False,
            },
            "answer": "现有安装路径不支持在同一游戏进程加载第二个observer；要求新进程/重启。DLL直接多实例加载能力没有被当前源和记录证明，不能据文件名推断支持共存。",
            "source_build_fingerprint_update": "使用build-diplomacy-observer.ps1重新生成92项source name/SHA列表和DLL hash；若加入238620接入代码，必须形成新的version/manifest/DLL SHA并由start_diplomacy_observer.py在新runtime目录记录，现有reuse脚本不会把额外文件自动纳入。",
        },
        "unresolved": [
            "当前v22 DLL是否能够在绕过injector的情况下安全加载第二个observer实例；没有共存验证，不作结论。",
            "238620自然入口的实际线程/重入/对象生命周期和生产发布路径；当前仅有研究计划/合同，未接入v22。",
            "observer status/enable/disable 的未来命令合同；当前只有health/capabilities读取和测试请求文件，未发现显式命令登记。",
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--installation", type=Path, default=DEFAULT_INSTALLATION)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args(argv)
    report = _build_report(args.installation)
    output = _inside(args.output if args.output.is_absolute() else ROOT / args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({
        "status": report["status"],
        "output": _relative(output),
        "output_sha256": _digest(output)[1],
        "source_count": report["build_fingerprint"]["source_count"],
        "source_mismatches": report["build_fingerprint"]["source_pins_mismatches"],
        "rva_ranges_overlap": report["natural_entry_238620"]["rva_ranges_overlap"],
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
