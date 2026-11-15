"""Bounded, read-only plugin detour binding for the failed v30 process.

Inert without --run. Does not use the failed installation as a usable source.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from work import probe_information_battle_v23 as probe
from work.local_config import game_exe

PLUGIN_SHA = "a73a8b6c82e620fc7d577bdb64df731b779a72bb43c2363a11ed12be23a9d819"
FRAGMENT = bytes.fromhex("488d55d848837df010480f4355d84c8b45e8488bcbff15ce440400ff35c0440400c3")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--installation", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if not args.run:
        print(json.dumps({"status": "inert", "game_access": False}))
        return
    if args.installation is None or args.output is None:
        parser.error("--installation and --output required")
    if args.output.exists():
        raise FileExistsError(args.output)
    doc = json.loads(args.installation.read_text(encoding="utf-8-sig"))
    kernel = probe._loc._configure_kernel()
    handle = kernel.OpenProcess(probe.PROCESS_ACCESS, False, doc["pid"])
    if not handle:
        raise RuntimeError("OpenProcess failed")
    result = {"schema": "information.battle.title_plugin_binding.v1",
              "status": "failed", "read_only": True, "native_calls": 0,
              "writes": 0, "control_requests": 0}
    reader = None
    try:
        before = probe._capture_identity(kernel, handle, doc, game_exe(), "before")
        result["identity_before"] = before
        assert before["status"] == "observed", before
        base = int(before["module_base"], 0)
        plugin_path = game_exe().parent / "plugins" / "plugin64.dll"
        module = probe._query_module_records(kernel, handle, plugin_path, PLUGIN_SHA)
        result["plugin"] = module
        assert module["status"] == "observed", module
        plugin_base = int(module["matching_modules"][0]["base"], 0)
        reader = probe.V23RPM(kernel, handle, base)
        def capture(phase: str) -> dict:
            patch = reader.read(base + 0x23aac3, 26, phase + ".exe_patch_and_displaced_call")
            fragment = reader.read(plugin_base + 0x3dbe7, len(FRAGMENT), phase + ".bridge")
            slots = reader.read(plugin_base + 0x820c8, 16, phase + ".slots")
            callee = reader.read(plugin_base + 0x373a0, 0x375cb - 0x373a0, phase + ".callee")
            return {"patch_hex": patch.hex(), "fragment_hex": fragment.hex(),
                    "fragment_matches_file": fragment == FRAGMENT,
                    "target": hex(int.from_bytes(patch[6:14], "little")),
                    "target_rva": hex(int.from_bytes(patch[6:14], "little") - plugin_base),
                    "return_va": hex(int.from_bytes(slots[:8], "little")),
                    "return_game_rva": hex(int.from_bytes(slots[:8], "little") - base),
                    "call_va": hex(int.from_bytes(slots[8:], "little")),
                    "call_plugin_rva": hex(int.from_bytes(slots[8:], "little") - plugin_base),
                    "callee_hex": callee.hex(),
                    "callee_sha256": hashlib.sha256(callee).hexdigest()}
        first, last = capture("before"), capture("after")
        result.update(binding_before=first, binding_after=last, binding_stable=first == last)
        after = probe._capture_identity(kernel, handle, doc, game_exe(), "after")
        result["identity_after"] = after
        assert after["status"] == "observed" and before["module_base"] == after["module_base"]
        assert first == last and first["fragment_matches_file"]
        assert first["target_rva"] == "0x3dbe7" and first["call_plugin_rva"] == "0x373a0"
        result["status"] = "observed"
    finally:
        result["handle_closed"] = bool(kernel.CloseHandle(handle))
        if reader is not None:
            result["rpm_bytes"] = reader.bytes_requested
            result["rpm_calls"] = reader.calls
            result["read_log"] = reader.read_log
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("x", encoding="utf-8", newline="\n") as stream:
            json.dump(result, stream, indent=2, sort_keys=True)
            stream.write("\n")
    print(json.dumps({"status": result["status"], "binding": first,
                      "handle_closed": result["handle_closed"]}))


if __name__ == "__main__":
    main()
