"""Bounded offline v26-v32 artifact checks for the installed preflight probe."""
from __future__ import annotations

import hashlib
import json
import ctypes as C
from pathlib import Path
import tempfile
import unittest

from work import probe_information_battle_installed as probe
from work.local_config import game_exe
from tools import start_diplomacy_observer as start


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class V26ArtifactFixture:
    def __init__(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.dll = self.root / "eu4_bridge_diplomacy_observer_v26.dll"
        self.dll.write_bytes(b"probe-v26-dll")
        names = list(start.INFORMATION_BATTLE_TEMPLATE_REQUIRED_SOURCES)
        names.extend(f"template-filler-{index:03d}.inc" for index in range(110 - len(names)))
        self.sources = {}
        for name in names:
            path = self.root / name
            path.write_bytes(("artifact-source:" + name).encode("ascii"))
            self.sources[name] = path
        self.manifest = {
            "version": 26,
            "experiment_id": "probe-v26",
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
            "compiler_arguments": [
                "-DBRIDGE_INFORMATION_BATTLE=1",
                "-DINFORMATION_BATTLE_CONTEXT=1",
                "-DINFORMATION_BATTLE_NAVAL=1",
                "-DINFORMATION_BATTLE_TEMPLATE=1",
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


class InstalledProbeV26Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.fx = V26ArtifactFixture()

    def tearDown(self) -> None:
        self.fx.close()

    def _validate(self) -> dict:
        return probe._validate_artifact(
            self.fx.root,
            expected_manifest_sha256=self.fx.manifest_sha,
            expected_dll_sha256=self.fx.dll_sha,
        )

    def test_v26_artifact_requires_110_sources_and_reports_unverified_scope(self) -> None:
        artifact = self._validate()
        self.assertEqual(artifact["version"], 26)
        self.assertEqual(artifact["source_count"], 110)
        self.assertEqual(artifact["template_capability"]["wire"], 4)
        self.assertTrue(artifact["template_capability"]["owned_template"])
        self.assertTrue(artifact["template_capability"]["message_scope"])
        self.assertFalse(artifact["template_capability"]["scope_entry_runtime_verified"])
        self.assertEqual(artifact["template_capability"]["scope_entry_runtime_status"], "not_implemented")

    def test_v26_artifact_rejects_missing_template_copy(self) -> None:
        (self.fx.root / "information-battle-owned-template.h").unlink()
        with self.assertRaises(probe.InstalledProbeError) as raised:
            self._validate()
        self.assertEqual(str(raised.exception), "artifact_source_copy_hash_mismatch")

    def test_v26_artifact_rejects_missing_template_macro(self) -> None:
        self.fx.manifest["compiler_arguments"].remove("-DINFORMATION_BATTLE_TEMPLATE=1")
        self.fx.write_manifest()
        with self.assertRaises(probe.InstalledProbeError) as raised:
            self._validate()
        self.assertEqual(str(raised.exception), "v26_template_capability_mismatch")

    def test_report_defaults_never_claim_scope_runtime(self) -> None:
        report = probe._base_report(
            self.fx.root / "installation.json",
            self.fx.root / "report.json",
            "installed",
            self.fx.manifest_sha,
            self.fx.dll_sha,
        )
        self.assertFalse(report["template_capability"]["scope_entry_runtime_verified"])
        self.assertEqual(report["target_build"]["scope_entry_runtime_status"], "not_implemented")

    def test_pure_rpm_guard_accepts_original_and_installed_message_entries(self) -> None:
        reader, kernel, symbols, originals = _message_fixture("installed")
        installed = probe._message_entry_runtime_guard(
            reader, GAME_BASE, DLL_BASE, "before", "installed", symbols,
            originals, kernel=kernel, handle=object(),
        )
        self.assertEqual(installed["status"], "observed")
        self.assertEqual(len(installed["trampolines"]), 2)

        original_reader, original_kernel, _, _ = _message_fixture("original")
        original = probe._message_entry_runtime_guard(
            original_reader, GAME_BASE, DLL_BASE, "before", "original", symbols,
            originals, kernel=original_kernel, handle=object(),
        )
        self.assertEqual(original["status"], "observed")
        self.assertEqual(original["trampolines"], {})

    def test_pure_rpm_guard_rejects_wrong_hook_target(self) -> None:
        reader, kernel, symbols, originals = _message_fixture("installed")
        wrong = dict(symbols)
        wrong["router_hook"] = dict(symbols["router_hook"], rva="0x9999")
        result = probe._message_entry_runtime_guard(
            reader, GAME_BASE, DLL_BASE, "before", "installed", wrong,
            originals, kernel=kernel, handle=object(),
        )
        self.assertNotEqual(result["status"], "observed")

    def test_pure_rpm_guard_rejects_unwind_metadata_and_truncated_image(self) -> None:
        reader, kernel, symbols, originals = _message_fixture("installed")
        metadata_bad = dict(reader.memory)
        metadata_bad[(GAME_BASE + probe.MESSAGE_ENTRY_SPECS["router"]["unwind_rva"], 28)] = b"\0" * 28
        result = probe._message_entry_runtime_guard(
            _MappingReader(metadata_bad), GAME_BASE, DLL_BASE, "before", "installed", symbols,
            originals, kernel=kernel, handle=object(),
        )
        self.assertNotEqual(result["status"], "observed")

        truncated = dict(reader.memory)
        trampoline = 0x500000000
        image = truncated[(trampoline, probe.TRAMPOLINE_BYTES)]
        truncated.pop((trampoline, probe.TRAMPOLINE_BYTES))
        truncated[(trampoline, 32)] = image[:32]
        result = probe._message_entry_runtime_guard(
            _MappingReader(truncated), GAME_BASE, DLL_BASE, "before", "installed", symbols,
            originals, kernel=kernel, handle=object(),
        )
        self.assertNotEqual(result["status"], "observed")

    def test_fixed_exe_message_unwind_preserves_original_handler_bytes(self) -> None:
        """Use the independent fixed-PE sample, including its real handler RVA."""
        executable = Path(game_exe())
        self.assertTrue(executable.is_file())
        expected = bytes.fromhex("110d03000d012000063000009c4da301")
        actual = probe._legacy._loc._read_pe_rva_bytes(executable, 0x1DE7940, len(expected))
        self.assertEqual(actual, expected)
        guard = probe._file_message_code_guard(executable)
        record = guard["records"]["message_unwind_original"]
        self.assertEqual(record["actual_hex"], actual.hex())
        self.assertEqual(record["expected_hex"], expected.hex())
        self.assertTrue(record["matches"])


class V28ArtifactFixture:
    def __init__(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.dll = self.root / "eu4_bridge_diplomacy_observer_v28.dll"
        self.dll.write_bytes(b"probe-v28-dll")
        names = list(start.INFORMATION_BATTLE_WAR_IDENTITY_REQUIRED_SOURCES)
        names.extend(
            f"war-identity-filler-{index:03d}.inc"
            for index in range(probe.EXPECTED_SOURCE_COUNTS[28] - len(names))
        )
        self.sources = {}
        for name in names:
            path = self.root / name
            path.write_bytes(("artifact-source:" + name).encode("ascii"))
            self.sources[name] = path
        self.manifest = {
            "version": 28,
            "experiment_id": "probe-v28-war-identity",
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
            "information_battle_war_identity": True,
            "information_battle_war_identity_wire": 5,
            "information_battle_war_identity_scope": "observer_session",
            "information_battle_war_identity_read_only": True,
            "information_battle_war_identity_complete": False,
            "compiler_arguments": [
                "-DBRIDGE_INFORMATION_BATTLE=1",
                "-DINFORMATION_BATTLE_CONTEXT=1",
                "-DINFORMATION_BATTLE_NAVAL=1",
                "-DINFORMATION_BATTLE_TEMPLATE=1",
                "-DINFORMATION_BATTLE_CONTAINER=1",
                "-DINFORMATION_BATTLE_WAR_IDENTITY=1",
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


class InstalledProbeV28Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.fx = V28ArtifactFixture()

    def tearDown(self) -> None:
        self.fx.close()

    def _validate(self) -> dict:
        return probe._validate_artifact(
            self.fx.root,
            expected_manifest_sha256=self.fx.manifest_sha,
            expected_dll_sha256=self.fx.dll_sha,
        )

    def test_v28_artifact_identifies_wire5_and_exact_war_source_set(self) -> None:
        artifact = self._validate()
        self.assertEqual(artifact["version"], 28)
        self.assertEqual(artifact["source_count"], 112)
        self.assertEqual(
            tuple(artifact["required_sources"]),
            tuple(sorted(start.INFORMATION_BATTLE_WAR_IDENTITY_REQUIRED_SOURCES)),
        )
        self.assertEqual(artifact["war_identity_capability"]["wire"], 5)
        self.assertEqual(
            artifact["war_identity_capability"]["scope"], "observer_session"
        )
        self.assertTrue(artifact["war_identity_capability"]["source_guard"])
        self.assertEqual(
            set(probe._entry_specs_for_version(28)),
            {"router", "message", "container"},
        )

    def test_v28_artifact_rejects_wrong_scope_and_wrong_wire(self) -> None:
        self.fx.manifest["information_battle_war_identity_scope"] = "cross_save"
        self.fx.write_manifest()
        with self.assertRaises(probe.InstalledProbeError) as raised:
            self._validate()
        self.assertEqual(str(raised.exception),
                         "v28_war_identity_capability_mismatch")

        self.fx.manifest["information_battle_war_identity_scope"] = "observer_session"
        self.fx.manifest["information_battle_war_identity_wire"] = 4
        self.fx.write_manifest()
        with self.assertRaises(probe.InstalledProbeError) as raised:
            self._validate()
        self.assertEqual(str(raised.exception),
                         "v28_war_identity_capability_mismatch")

    def test_v28_artifact_rejects_missing_identity_source_copy(self) -> None:
        (self.fx.root / "information-battle-war-identity-wire.h").unlink()
        with self.assertRaises(probe.InstalledProbeError) as raised:
            self._validate()
        self.assertEqual(str(raised.exception),
                         "artifact_source_copy_hash_mismatch")


class V29ArtifactFixture:
    def __init__(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.dll = self.root / "eu4_bridge_diplomacy_observer_v29.dll"
        self.dll.write_bytes(b"probe-v29-dll")
        names = list(start.INFORMATION_BATTLE_NATIVE_TEXT_REQUIRED_SOURCES)
        names.extend(
            f"native-text-filler-{index:03d}.inc"
            for index in range(probe.EXPECTED_SOURCE_COUNTS[29] - len(names))
        )
        self.sources = {}
        for name in names:
            path = self.root / name
            path.write_bytes(("artifact-source:" + name).encode("ascii"))
            self.sources[name] = path
        self.manifest = {
            "version": 29,
            "experiment_id": "probe-v29-native-text",
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
            "information_battle_war_identity": True,
            "information_battle_war_identity_wire": 5,
            "information_battle_war_identity_scope": "observer_session",
            "information_battle_war_identity_read_only": True,
            "information_battle_war_identity_complete": False,
            "information_battle_native_text": True,
            "information_battle_native_text_wire": 6,
            "information_battle_native_text_scope": "observer_session",
            "information_battle_native_text_read_only": True,
            "information_battle_native_text_complete": False,
            "compiler_arguments": [
                "-DBRIDGE_INFORMATION_BATTLE=1",
                "-DINFORMATION_BATTLE_CONTEXT=1",
                "-DINFORMATION_BATTLE_NAVAL=1",
                "-DINFORMATION_BATTLE_TEMPLATE=1",
                "-DINFORMATION_BATTLE_CONTAINER=1",
                "-DINFORMATION_BATTLE_WAR_IDENTITY=1",
                "-DINFORMATION_BATTLE_NATIVE_TEXT=1",
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


class InstalledProbeV29Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.fx = V29ArtifactFixture()

    def tearDown(self) -> None:
        self.fx.close()

    def _validate(self) -> dict:
        return probe._validate_artifact(
            self.fx.root,
            expected_manifest_sha256=self.fx.manifest_sha,
            expected_dll_sha256=self.fx.dll_sha,
        )

    def test_v29_artifact_requires_native_text_wire6_and_source_set(self) -> None:
        artifact = self._validate()
        self.assertEqual(artifact["version"], 29)
        self.assertEqual(artifact["source_count"], 116)
        self.assertEqual(
            tuple(artifact["required_sources"]),
            tuple(sorted(start.INFORMATION_BATTLE_NATIVE_TEXT_REQUIRED_SOURCES)),
        )
        native = artifact["native_text_capability"]
        self.assertTrue(native["enabled"])
        self.assertEqual(native["wire"], 6)
        self.assertEqual(native["scope"], "observer_session")
        self.assertTrue(native["read_only"])
        self.assertFalse(native["complete"])
        self.assertEqual(
            set(probe._entry_specs_for_version(29)),
            {"router", "message", "container", "line1"},
        )
        self.assertEqual(
            set(probe._entry_symbols_for_version(29)),
            {
                "router_hook", "message_hook", "container_hook", "line1_hook",
                "router_original", "message_original", "container_original",
                "line1_original",
            },
        )

    def test_v29_line1_spec_is_fixed_build_header_and_unwind(self) -> None:
        spec = probe.LINE1_ENTRY_SPEC
        self.assertEqual(spec["entry_rva"], 0x152AD10)
        self.assertEqual(spec["end_rva"], 0x152AD92)
        self.assertEqual(spec["unwind_rva"], 0x1DCA66C)
        self.assertEqual(
            bytes(spec["prefix"]).hex(),
            "48895c240848896c24104889742418574883ec20",
        )
        self.assertEqual(
            bytes(spec["unwind"]).hex(),
            "0114080014640800145407001434060014321070",
        )
        self.assertEqual(len(spec["prefix"]), 20)
        self.assertEqual(len(spec["unwind"]), 20)
        self.assertEqual(spec["trampoline_layout"], "absolute_jump")
        self.assertEqual(spec["trampoline_jump_bytes"], 14)
        self.assertEqual(spec["stack_delta"], 0x28)

    def test_v29_artifact_rejects_native_text_metadata_or_macro(self) -> None:
        for key, value in (
            ("information_battle_native_text_wire", 5),
            ("information_battle_native_text_scope", "cross_save"),
            ("information_battle_native_text_read_only", False),
            ("information_battle_native_text_complete", True),
        ):
            with self.subTest(key=key):
                self.fx.manifest[key] = value
                self.fx.write_manifest()
                with self.assertRaises(probe.InstalledProbeError) as raised:
                    self._validate()
                self.assertEqual(
                    str(raised.exception),
                    "v29_native_text_capability_mismatch",
                )
                self.fx.manifest[key] = {
                    "information_battle_native_text_wire": 6,
                    "information_battle_native_text_scope": "observer_session",
                    "information_battle_native_text_read_only": True,
                    "information_battle_native_text_complete": False,
                }[key]
                self.fx.write_manifest()

        self.fx.manifest["compiler_arguments"].remove(
            "-DINFORMATION_BATTLE_NATIVE_TEXT=1"
        )
        self.fx.write_manifest()
        with self.assertRaises(probe.InstalledProbeError) as raised:
            self._validate()
        self.assertEqual(str(raised.exception),
                         "v29_native_text_capability_mismatch")

    def test_v29_line1_guard_uses_fourteen_byte_absolute_jump(self) -> None:
        reader, kernel, symbols, originals = _message_fixture(
            "installed", version=29
        )
        result = probe._message_entry_runtime_guard(
            reader, GAME_BASE, DLL_BASE, "before", "installed", symbols,
            originals, kernel=kernel, handle=object(), version=29,
        )
        self.assertEqual(result["status"], "observed")
        self.assertEqual(
            set(result["trampolines"]), {"router", "message", "container", "line1"}
        )
        line1 = result["trampolines"]["line1"]
        self.assertEqual(line1["code_end_bytes"], 34)
        self.assertEqual(line1["projected_unwind_bytes"], 20)
        self.assertTrue(line1["checks"]["absolute_jump_matches"])
        self.assertTrue(line1["checks"]["trampoline_jump_matches"])
        self.assertTrue(line1["checks"]["image_gap_zeroed"])

    def test_v29_line1_guard_rejects_home_slot_or_tampered_jump(self) -> None:
        reader, kernel, symbols, originals = _message_fixture(
            "installed", version=29
        )
        line1_trampoline = 0x500003000
        image = bytearray(reader.memory[(line1_trampoline, probe.TRAMPOLINE_BYTES)])
        image[20] ^= 0x01
        reader.memory[(line1_trampoline, probe.TRAMPOLINE_BYTES)] = bytes(image)
        result = probe._message_entry_runtime_guard(
            reader, GAME_BASE, DLL_BASE, "before", "installed", symbols,
            originals, kernel=kernel, handle=object(), version=29,
        )
        self.assertNotEqual(result["status"], "observed")


class V30ArtifactFixture(V29ArtifactFixture):
    """A v30 artifact retaining v29 guards plus two title-query sources."""

    def __init__(self) -> None:
        super().__init__()
        old_dll = self.dll
        self.dll = self.root / "eu4_bridge_diplomacy_observer_v30.dll"
        old_dll.rename(self.dll)
        for name in start.INFORMATION_BATTLE_NATIVE_TITLE_QUERY_REQUIRED_SOURCES[-2:]:
            path = self.root / name
            path.write_bytes(("artifact-source:" + name).encode("ascii"))
            self.sources[name] = path
        self.manifest.update({
            "version": 30,
            "experiment_id": "probe-v30-native-title-query",
            "dll_sha256": _sha256(self.dll),
            "information_battle_native_title_query": True,
            "information_battle_native_title_query_mode": "native_helper_owned_output",
            "information_battle_native_title_query_wire": 6,
            "information_battle_native_title_query_complete": False,
            "compiler_arguments": self.manifest["compiler_arguments"] + [
                "-DINFORMATION_BATTLE_NATIVE_TITLE_QUERY=1",
            ],
        })
        self.manifest["sources"] = [
            {"name": name, "sha256": _sha256(path)}
            for name, path in self.sources.items()
        ]
        self.write_manifest()


class V32ArtifactFixture(V30ArtifactFixture):
    """A v32 gate-trace artifact retaining v30 and replacing v31 control."""

    def __init__(self) -> None:
        super().__init__()
        old_dll = self.dll
        self.dll = self.root / "eu4_bridge_diplomacy_observer_v32.dll"
        old_dll.rename(self.dll)
        for name in start.INFORMATION_BATTLE_GATE_TRACE_REQUIRED_SOURCES[-3:]:
            path = self.root / name
            path.write_bytes(("artifact-source:" + name).encode("ascii"))
            self.sources[name] = path
        self.manifest.update({
            "version": 32,
            "experiment_id": "probe-v32-battle-gate-trace",
            "dll_sha256": _sha256(self.dll),
            "information_battle_gate_trace": True,
            "information_battle_gate_trace_protocol": "EU4-BATTLE-GATE-TRACE/1",
            "information_battle_gate_trace_runtime_verified": False,
            "compiler_arguments": self.manifest["compiler_arguments"] + [
                "-DINFORMATION_BATTLE_GATE_TRACE=1",
            ],
        })
        self.manifest["sources"] = [
            {"name": name, "sha256": _sha256(path)}
            for name, path in self.sources.items()
        ]
        self.write_manifest()


class InstalledProbeV30Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.fx = V30ArtifactFixture()

    def tearDown(self) -> None:
        self.fx.close()

    def _validate(self) -> dict:
        return probe._validate_artifact(
            self.fx.root,
            expected_manifest_sha256=self.fx.manifest_sha,
            expected_dll_sha256=self.fx.dll_sha,
        )

    def test_v30_artifact_requires_title_query_metadata_and_118_sources(self) -> None:
        artifact = self._validate()
        self.assertEqual(artifact["version"], 30)
        self.assertEqual(artifact["source_count"], 118)
        self.assertEqual(
            tuple(artifact["required_sources"]),
            tuple(sorted(start.INFORMATION_BATTLE_NATIVE_TITLE_QUERY_REQUIRED_SOURCES)),
        )
        native = artifact["native_text_capability"]
        self.assertEqual(native["wire"], 6)
        title = artifact["native_title_query_capability"]
        self.assertTrue(title["enabled"])
        self.assertEqual(title["mode"], "native_helper_owned_output")
        self.assertEqual(title["wire"], 6)
        self.assertFalse(title["complete"])
        self.assertFalse(title["helper_invoked"])
        self.assertFalse(title["scope_entry_runtime_verified"])
        self.assertEqual(title["scope_entry_runtime_status"], "not_called_helper_pure_rpm")
        self.assertEqual(
            set(probe._entry_specs_for_version(30)),
            {"router", "message", "container", "line1"},
        )

    def test_v30_title_query_metadata_and_macro_are_strict(self) -> None:
        for key, value in (
            ("information_battle_native_title_query", False),
            ("information_battle_native_title_query_mode", "runtime"),
            ("information_battle_native_title_query_wire", 5),
            ("information_battle_native_title_query_complete", True),
        ):
            with self.subTest(key=key):
                self.fx.manifest[key] = value
                self.fx.write_manifest()
                with self.assertRaises(probe.InstalledProbeError) as raised:
                    self._validate()
                self.assertEqual(
                    str(raised.exception),
                    "v30_native_title_query_capability_mismatch",
                )
                self.fx.manifest[key] = {
                    "information_battle_native_title_query": True,
                    "information_battle_native_title_query_mode": "native_helper_owned_output",
                    "information_battle_native_title_query_wire": 6,
                    "information_battle_native_title_query_complete": False,
                }[key]
                self.fx.write_manifest()

        self.fx.manifest["compiler_arguments"].remove(
            "-DINFORMATION_BATTLE_NATIVE_TITLE_QUERY=1"
        )
        self.fx.write_manifest()
        with self.assertRaises(probe.InstalledProbeError) as raised:
            self._validate()
        self.assertEqual(
            str(raised.exception),
            "v30_native_title_query_capability_mismatch",
        )

    def test_v30_reuses_v29_entry_and_line1_rpm_guards_without_helper_call(self) -> None:
        reader, kernel, symbols, originals = _message_fixture(
            "installed", version=30
        )
        result = probe._message_entry_runtime_guard(
            reader, GAME_BASE, DLL_BASE, "before", "installed", symbols,
            originals, kernel=kernel, handle=object(), version=30,
        )
        self.assertEqual(result["status"], "observed")
        self.assertEqual(
            set(result["trampolines"]),
            {"router", "message", "container", "line1"},
        )
        artifact = self._validate()
        title = artifact["native_title_query_capability"]
        self.assertFalse(title["helper_invoked"])
        self.assertFalse(title["scope_entry_runtime_verified"])


class InstalledProbeV32Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.fx = V32ArtifactFixture()

    def tearDown(self) -> None:
        self.fx.close()

    def _validate(self) -> dict:
        return probe._validate_artifact(
            self.fx.root,
            expected_manifest_sha256=self.fx.manifest_sha,
            expected_dll_sha256=self.fx.dll_sha,
        )

    def test_v32_artifact_inherits_wire6_and_marks_gate_trace_private_unverified(self) -> None:
        artifact = self._validate()
        self.assertEqual(artifact["version"], 32)
        self.assertEqual(artifact["source_count"], 121)
        self.assertEqual(
            set(artifact["required_sources"]),
            set(start.INFORMATION_BATTLE_GATE_TRACE_REQUIRED_SOURCES),
        )
        self.assertEqual(artifact["native_title_query_capability"]["wire"], 6)
        self.assertFalse(artifact["native_title_query_capability"]["helper_invoked"])
        self.assertEqual(artifact["native_text_capability"]["wire"], 6)
        gate = artifact["battle_gate_trace_capability"]
        self.assertTrue(gate["enabled"])
        self.assertEqual(gate["protocol"], "EU4-BATTLE-GATE-TRACE/1")
        self.assertFalse(gate["runtime_verified"])
        self.assertTrue(gate["private_diagnostic_sidecar"])
        self.assertFalse(gate["business_b04_upgrade"])
        self.assertNotIn("current_country_control_capability", artifact)
        self.assertEqual(
            set(probe._entry_specs_for_version(32)),
            {"router", "message", "container", "line1"},
        )

    def test_v32_gate_manifest_rejects_control_and_fixture_contracts(self) -> None:
        baseline = json.loads(json.dumps(self.fx.manifest))
        mutations = {
            "gate_flag": lambda data: data.update({"information_battle_gate_trace": False}),
            "protocol": lambda data: data.update({
                "information_battle_gate_trace_protocol": "EU4-BATTLE-GATE-TRACE/2"
            }),
            "runtime_verified": lambda data: data.update({
                "information_battle_gate_trace_runtime_verified": True
            }),
            "gate_macro": lambda data: data["compiler_arguments"].remove(
                "-DINFORMATION_BATTLE_GATE_TRACE=1"
            ),
            "country_control_macro": lambda data: data["compiler_arguments"].append(
                "-DBRIDGE_CURRENT_COUNTRY_CONTROL=1"
            ),
            "country_control_split_macro": lambda data: data["compiler_arguments"].extend(
                ["-D", "BRIDGE_CURRENT_COUNTRY_CONTROL=1"]
            ),
            "fixture_macro": lambda data: data["compiler_arguments"].append(
                "-DINFORMATION_CURRENT_COUNTRY_HOST_FIXTURE=1"
            ),
            "country_control_metadata": lambda data: data.update({
                "current_country_control_test_only": True
            }),
            "country_control_source": lambda data: data["sources"][-1].update({
                "name": "information-current-country-control.inc"
            }),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                self.fx.manifest = json.loads(json.dumps(baseline))
                mutate(self.fx.manifest)
                self.fx.write_manifest()
                with self.assertRaises(probe.InstalledProbeError) as raised:
                    self._validate()
                if name == "country_control_source":
                    self.assertEqual(
                        str(raised.exception),
                        "v32_current_country_control_sources_forbidden",
                    )
                elif name in {"gate_flag", "protocol", "runtime_verified", "gate_macro",
                              "country_control_macro", "country_control_split_macro",
                              "fixture_macro", "country_control_metadata"}:
                    self.assertEqual(
                        str(raised.exception),
                        "v32_battle_gate_trace_capability_mismatch",
                    )
        self.fx.manifest = json.loads(json.dumps(baseline))
        self.fx.write_manifest()


GAME_BASE = 0x140000000
DLL_BASE = 0x180000000


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
    def __init__(self, *, protect: int = probe.PAGE_EXECUTE_READ) -> None:
        self.protect = protect

    def VirtualQueryEx(self, _handle: object, address: object, info: object, _size: int) -> int:
        value = int(C.cast(address, C.c_void_p).value or 0)
        target = C.cast(info, C.POINTER(probe._MemoryBasicInformation)).contents
        target.BaseAddress = value
        target.AllocationBase = value
        target.RegionSize = probe.TRAMPOLINE_BYTES
        target.State = probe.MEM_COMMIT
        target.Protect = self.protect
        return C.sizeof(probe._MemoryBasicInformation)


def _message_fixture(
    mode: str, *, version: int = 26
) -> tuple[_MappingReader, _MemoryQueryKernel, dict, dict]:
    memory: dict[tuple[int, int], bytes] = {}
    symbols = {}
    symbol_rvas = {
        "router_hook": "0x1000",
        "message_hook": "0x2000",
        "container_hook": "0x2500",
        "line1_hook": "0x2800",
        "router_original": "0x3000",
        "message_original": "0x4000",
        "container_original": "0x4500",
        "line1_original": "0x4800",
    }
    for role, symbol in probe._entry_symbols_for_version(version).items():
        symbols[role] = {
            "status": "observed",
            "rva": symbol_rvas[role],
            "symbol": symbol,
        }
    originals = {key: value for key, value in symbols.items() if key.endswith("_original")}
    for ordinal, (name, spec) in enumerate(
        probe._entry_specs_for_version(version).items()
    ):
        prefix = bytes(spec["prefix"])
        if mode == "installed":
            target = DLL_BASE + int(symbols[f"{name}_hook"]["rva"], 0)
            prefix = probe._installed_message_prefix(target, len(prefix))
        memory[(GAME_BASE + int(spec["entry_rva"]), len(prefix))] = prefix
        memory[(GAME_BASE + int(spec["unwind_rva"]), len(spec["unwind"]))] = bytes(spec["unwind"])
        if mode == "installed":
            trampoline = 0x500000000 + ordinal * 0x1000
            pointer_address = DLL_BASE + int(symbols[f"{name}_original"]["rva"], 0)
            memory[(pointer_address, 8)] = trampoline.to_bytes(8, "little")
            image = bytearray(probe.TRAMPOLINE_BYTES)
            prefix_original = bytes(spec["prefix"])
            image[:len(prefix_original)] = prefix_original
            continuation = GAME_BASE + int(spec["entry_rva"]) + len(prefix_original)
            if spec.get("trampoline_layout") == "absolute_jump":
                jump = probe._installed_message_prefix(
                    continuation, int(spec["trampoline_jump_bytes"])
                )
            else:
                jump = probe._home_slot_jump(
                    int(spec["stack_delta"]) + 0x18, continuation
                )
            image[len(prefix_original):len(prefix_original) + len(jump)] = jump
            projected = probe._projected_unwind(spec)
            image[64:64 + len(projected)] = projected
            memory[(trampoline, probe.TRAMPOLINE_BYTES)] = bytes(image)
    return _MappingReader(memory), _MemoryQueryKernel(), symbols, originals


if __name__ == "__main__":
    unittest.main()
