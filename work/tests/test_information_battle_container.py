"""Focused offline v27 formatter-container install and probe guards."""
from __future__ import annotations

import ctypes as C
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from tools import control_information_battle_observer as control
from tools import start_diplomacy_observer as start
from work import probe_information_battle_installed as probe
from work.local_config import game_exe


GAME_BASE = 0x140000000
DLL_BASE = 0x180000000


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class V27ArtifactFixture:
    def __init__(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.dll = self.root / "eu4_bridge_diplomacy_observer_v27.dll"
        self.dll.write_bytes(b"probe-v27-dll")
        names = list(start.INFORMATION_BATTLE_CONTAINER_REQUIRED_SOURCES)
        names.extend(f"container-filler-{index:03d}.inc"
                     for index in range(110 - len(names)))
        self.sources: dict[str, Path] = {}
        for name in names:
            path = self.root / name
            path.write_bytes(("artifact-source:" + name).encode("ascii"))
            self.sources[name] = path
        self.manifest = {
            "version": 27,
            "experiment_id": "information-battle-container-test",
            "game_sha256": probe.EXPECTED_EXE_SHA256,
            "dll_sha256": _sha256(self.dll),
            "information_battle_research_lifecycle": True,
            "information_battle_context_wire": 2,
            "information_battle_owned_context": True,
            "information_battle_naval_wire": 3,
            "information_battle_owned_naval": True,
            "information_battle_template_wire": 4,
            "information_battle_owned_template": True,
            "information_battle_message_scope": True,
            "information_battle_formatter_container": True,
            "information_battle_template_extensions": [1, 2],
            "compiler_arguments": [
                "-DBRIDGE_INFORMATION_BATTLE=1",
                "-DINFORMATION_BATTLE_CONTEXT=1",
                "-DINFORMATION_BATTLE_NAVAL=1",
                "-DINFORMATION_BATTLE_TEMPLATE=1",
                "-DINFORMATION_BATTLE_CONTAINER=1",
            ],
            "sources": [
                {"name": name, "sha256": _sha256(path)}
                for name, path in self.sources.items()
            ],
        }
        self.write_manifest()

    def write_manifest(self) -> None:
        (self.root / "build-manifest.json").write_text(
            json.dumps(self.manifest, sort_keys=True), encoding="utf-8"
        )

    @property
    def manifest_sha(self) -> str:
        return _sha256(self.root / "build-manifest.json")

    @property
    def dll_sha(self) -> str:
        return _sha256(self.dll)

    def close(self) -> None:
        self.temp.cleanup()


class _MappingReader:
    def __init__(self, memory: dict[tuple[int, int], bytes]) -> None:
        self.memory = memory

    def _read(self, address: int, size: int) -> bytes:
        for (base, extent), raw in self.memory.items():
            if base <= address and address + size <= base + extent:
                offset = address - base
                return raw[offset:offset + size]
        raise probe.InstalledProbeError(f"synthetic_short_read:{hex(address)}:{size}")

    def read_code(self, address: int, size: int, _label: str) -> bytes:
        return self._read(address, size)

    def qword(self, address: int, _label: str) -> tuple[int, bytes]:
        raw = self._read(address, 8)
        return int.from_bytes(raw, "little"), raw


class _MemoryQueryKernel:
    def VirtualQueryEx(self, _handle: object, address: object, info: object, _size: int) -> int:
        value = int(C.cast(address, C.c_void_p).value or 0)
        target = C.cast(info, C.POINTER(probe._MemoryBasicInformation)).contents
        target.BaseAddress = value
        target.AllocationBase = value
        target.RegionSize = probe.TRAMPOLINE_BYTES
        target.State = probe.MEM_COMMIT
        target.Protect = probe.PAGE_EXECUTE_READ
        return C.sizeof(probe._MemoryBasicInformation)


class InformationBattleContainerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fx = V27ArtifactFixture()

    def tearDown(self) -> None:
        self.fx.close()

    def test_v27_manifest_pins_container_capability_and_sources(self) -> None:
        start._validate_information_battle_manifest(self.fx.manifest, self.fx.root)
        control._validate_manifest(self.fx.manifest, self.fx.root)
        artifact = probe._validate_artifact(
            self.fx.root,
            expected_manifest_sha256=self.fx.manifest_sha,
            expected_dll_sha256=self.fx.dll_sha,
        )
        self.assertEqual(artifact["version"], 27)
        self.assertEqual(artifact["source_count"], 110)
        self.assertTrue(artifact["template_capability"]["formatter_container"])
        self.assertEqual(artifact["template_capability"]["template_extensions"], [1, 2])
        self.assertIn("-DINFORMATION_BATTLE_CONTAINER=1",
                      artifact["manifest_value"]["compiler_arguments"])

    def test_v27_start_and_probe_reject_missing_macro_or_capability(self) -> None:
        manifest = json.loads(json.dumps(self.fx.manifest))
        manifest["compiler_arguments"].remove("-DINFORMATION_BATTLE_CONTAINER=1")
        with self.assertRaises(SystemExit) as raised:
            start._validate_information_battle_manifest(manifest, self.fx.root)
        self.assertEqual(str(raised.exception), "BUILD_MANIFEST_MISMATCH")
        with self.assertRaises(control.ControlError) as raised:
            control._validate_manifest(manifest, self.fx.root)
        self.assertEqual(raised.exception.reason, "BUILD_MANIFEST_MISMATCH")
        self.fx.manifest["information_battle_formatter_container"] = False
        self.fx.write_manifest()
        with self.assertRaises(probe.InstalledProbeError) as raised:
            probe._validate_artifact(
                self.fx.root,
                expected_manifest_sha256=self.fx.manifest_sha,
                expected_dll_sha256=self.fx.dll_sha,
            )
        self.assertEqual(str(raised.exception),
                         "v27_formatter_container_capability_mismatch")

    def test_cleanup_fixed_pe_prefix_and_unwind_are_independently_guarded(self) -> None:
        executable = Path(game_exe())
        self.assertTrue(executable.is_file())
        self.assertEqual(probe.FORMATTER_CONTAINER_ENTRY_SPEC["entry_rva"], 0x1AF740)
        self.assertEqual(probe.FORMATTER_CONTAINER_ENTRY_SPEC["end_rva"], 0x1AF755)
        self.assertEqual(probe.FORMATTER_CONTAINER_ENTRY_SPEC["unwind_rva"], 0x1DCAD04)
        prefix = bytes.fromhex("48895c2410564883ec20488b19488bf1")
        unwind = bytes.fromhex("010a04000a3407000a320660")
        self.assertEqual(
            probe._legacy._loc._read_pe_rva_bytes(
                executable, probe.FORMATTER_CONTAINER_ENTRY_SPEC["entry_rva"], len(prefix)
            ),
            prefix,
        )
        self.assertEqual(
            probe._legacy._loc._read_pe_rva_bytes(
                executable, probe.FORMATTER_CONTAINER_ENTRY_SPEC["unwind_rva"], len(unwind)
            ),
            unwind,
        )
        guard = probe._file_message_code_guard(executable, version=27)
        self.assertEqual(guard["status"], "observed")
        self.assertTrue(guard["records"]["container_entry_original"]["matches"])
        self.assertTrue(guard["records"]["container_unwind_original"]["matches"])

    def test_v27_guard_checks_container_hook_global_and_rx_trampoline(self) -> None:
        memory: dict[tuple[int, int], bytes] = {}
        symbols = {
            "router_hook": {"status": "observed", "rva": "0x1000", "symbol": "information_battle_router_hook"},
            "message_hook": {"status": "observed", "rva": "0x2000", "symbol": "information_battle_message_hook"},
            "container_hook": {"status": "observed", "rva": "0x3000", "symbol": "information_battle_container_hook"},
            "router_original": {"status": "observed", "rva": "0x4000", "symbol": "information_battle_router_original"},
            "message_original": {"status": "observed", "rva": "0x5000", "symbol": "information_battle_message_original"},
            "container_original": {"status": "observed", "rva": "0x6000", "symbol": "information_battle_container_original"},
        }
        originals = {key: value for key, value in symbols.items() if key.endswith("_original")}
        for index, (name, spec) in enumerate(probe._entry_specs_for_version(27).items()):
            hook_target = DLL_BASE + int(symbols[f"{name}_hook"]["rva"], 0)
            entry_prefix = probe._installed_message_prefix(hook_target, len(spec["prefix"]))
            memory[(GAME_BASE + int(spec["entry_rva"]), len(entry_prefix))] = entry_prefix
            memory[(GAME_BASE + int(spec["unwind_rva"]), len(spec["unwind"]))] = bytes(spec["unwind"])
            trampoline = 0x500000000 + index * 0x1000
            pointer_address = DLL_BASE + int(symbols[f"{name}_original"]["rva"], 0)
            memory[(pointer_address, 8)] = trampoline.to_bytes(8, "little")
            image = bytearray(probe.TRAMPOLINE_BYTES)
            image[:len(spec["prefix"])] = bytes(spec["prefix"])
            home = probe._home_slot_jump(
                int(spec["stack_delta"]) + 0x18,
                GAME_BASE + int(spec["entry_rva"]) + len(spec["prefix"]),
            )
            image[len(spec["prefix"]):len(spec["prefix"]) + len(home)] = home
            projected = probe._projected_unwind(spec)
            image[64:64 + len(projected)] = projected
            memory[(trampoline, probe.TRAMPOLINE_BYTES)] = bytes(image)

        reader = _MappingReader(memory)
        result = probe._message_entry_runtime_guard(
            reader, GAME_BASE, DLL_BASE, "before", "installed", symbols, originals,
            kernel=_MemoryQueryKernel(), handle=object(), version=27,
        )
        self.assertEqual(result["status"], "observed")
        self.assertEqual(set(result["trampolines"]), {"router", "message", "container"})
        self.assertTrue(result["trampolines"]["container"]["checks"]["rx_owned_128"])
        self.assertEqual(
            result["trampolines"]["container"]["pointer_address"], hex(DLL_BASE + 0x6000)
        )


if __name__ == "__main__":
    unittest.main()
