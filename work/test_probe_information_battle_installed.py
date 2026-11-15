from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from work import probe_information_battle_installed as subject


class ArtifactFixture:
    def __init__(self, version: int = 24) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.version = version
        self.dll = self.root / f"eu4_bridge_diplomacy_observer_v{version}.dll"
        self.dll.write_bytes(b"synthetic installed observer " + str(version).encode("ascii"))
        self.game = self.root / "eu4.exe"
        self.game.write_bytes(b"synthetic game image")
        required = list(subject._required_source_names(version))
        count = subject.EXPECTED_SOURCE_COUNTS[version]
        required.extend(f"artifact-only-{index:03d}.inc" for index in range(count - len(required)))
        self.source_names = required
        for name in required:
            (self.root / name).write_bytes(("artifact-copy:" + name).encode("ascii"))
        self.manifest = {
            "version": version,
            "experiment_id": f"installed-v{version}-fixture",
            "game_sha256": subject.EXPECTED_EXE_SHA256,
            "dll_sha256": _hash(self.dll),
            "information_battle_research_lifecycle": True,
            "sources": [
                {"name": name, "sha256": _hash(self.root / name)}
                for name in required
            ],
        }
        if version == 24:
            self.manifest.update({
                "information_battle_context_wire": 2,
                "information_battle_owned_context": True,
                "compiler_arguments": [
                    "-DBRIDGE_INFORMATION_BATTLE=1",
                    "-DINFORMATION_BATTLE_CONTEXT=1",
                ],
            })
        if version == 28:
            self.manifest.update({
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
            })
        if version == 30:
            self.manifest.update({
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
                "information_battle_native_title_query": True,
                "information_battle_native_title_query_mode": "native_helper_owned_output",
                "information_battle_native_title_query_wire": 6,
                "information_battle_native_title_query_complete": False,
                "compiler_arguments": [
                    "-DBRIDGE_INFORMATION_BATTLE=1",
                    "-DINFORMATION_BATTLE_CONTEXT=1",
                    "-DINFORMATION_BATTLE_NAVAL=1",
                    "-DINFORMATION_BATTLE_TEMPLATE=1",
                    "-DINFORMATION_BATTLE_CONTAINER=1",
                    "-DINFORMATION_BATTLE_WAR_IDENTITY=1",
                    "-DINFORMATION_BATTLE_NATIVE_TEXT=1",
                    "-DINFORMATION_BATTLE_NATIVE_TITLE_QUERY=1",
                ],
            })
        self.manifest_path = self.root / "build-manifest.json"
        self.write_manifest()
        self.installation_path = self.root / "installation.json"
        self.installation = {
            "experiment_id": self.manifest["experiment_id"],
            "installation_returncode": 0,
            "pid": 45678,
            "creation_filetime": 0x123456789,
            "session_id": "45678-123456789",
            "game_sha256": subject.EXPECTED_EXE_SHA256,
            "dll_sha256": self.manifest["dll_sha256"],
            "process_path": str(self.game),
            "modules_after_install": [{
                "name": self.dll.name,
                "path": str(self.dll),
                "sha256": self.manifest["dll_sha256"],
            }],
        }
        self.write_installation()
        self.development = self.root / "development"
        self.development.mkdir()

    def write_manifest(self) -> None:
        self.manifest_path.write_text(json.dumps(self.manifest, sort_keys=True), encoding="utf-8")

    def write_installation(self) -> None:
        self.installation_path.write_text(json.dumps(self.installation, sort_keys=True), encoding="utf-8")

    @property
    def manifest_sha(self) -> str:
        return _hash(self.manifest_path)

    @property
    def dll_sha(self) -> str:
        return self.manifest["dll_sha256"]

    def close(self) -> None:
        self.temp.cleanup()


def _hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_manifest_and_hash(fx: ArtifactFixture) -> str:
    fx.write_manifest()
    return fx.manifest_sha


class FakeKernel:
    def __init__(self) -> None:
        self.open_calls: list[tuple[int, bool, int]] = []

    def OpenProcess(self, access: int, inherit: bool, pid: int) -> object:
        self.open_calls.append((access, inherit, pid))
        return object()


class InstalledArtifactProbeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fx = ArtifactFixture(24)

    def tearDown(self) -> None:
        self.fx.close()

    def test_v23_and_v24_artifact_source_counts_and_pins(self) -> None:
        subject._validate_artifact(
            self.fx.root,
            expected_manifest_sha256=self.fx.manifest_sha,
            expected_dll_sha256=self.fx.dll_sha,
        )
        old = ArtifactFixture(23)
        self.addCleanup(old.close)
        result = subject._validate_artifact(
            old.root,
            expected_manifest_sha256=old.manifest_sha,
            expected_dll_sha256=old.dll_sha,
        )
        self.assertEqual(result["version"], 23)
        self.assertEqual(result["source_count"], 103)
        self.assertEqual(result["status"], "observed")
        self.assertEqual(len(result["source_records"]), 103)

    def test_v28_artifact_identifies_war_identity_source_scope(self) -> None:
        fixture = ArtifactFixture(28)
        self.addCleanup(fixture.close)
        result = subject._validate_artifact(
            fixture.root,
            expected_manifest_sha256=fixture.manifest_sha,
            expected_dll_sha256=fixture.dll_sha,
        )
        self.assertEqual(result["version"], 28)
        self.assertEqual(result["source_count"], 112)
        self.assertEqual(
            tuple(result["required_sources"]),
            tuple(sorted(subject._start.INFORMATION_BATTLE_WAR_IDENTITY_REQUIRED_SOURCES)),
        )
        self.assertEqual(result["war_identity_capability"]["wire"], 5)
        self.assertEqual(
            result["war_identity_capability"]["scope"], "observer_session"
        )
        self.assertTrue(result["war_identity_capability"]["source_guard"])
        self.assertEqual(
            set(subject._entry_specs_for_version(28)),
            {"router", "message", "container"},
        )

    def test_v30_artifact_identifies_title_query_helper_owned_output(self) -> None:
        fixture = ArtifactFixture(30)
        self.addCleanup(fixture.close)
        result = subject._validate_artifact(
            fixture.root,
            expected_manifest_sha256=fixture.manifest_sha,
            expected_dll_sha256=fixture.dll_sha,
        )
        self.assertEqual(result["version"], 30)
        self.assertEqual(result["source_count"], 118)
        title = result["native_title_query_capability"]
        self.assertEqual(title["mode"], "native_helper_owned_output")
        self.assertEqual(title["wire"], 6)
        self.assertFalse(title["complete"])
        self.assertFalse(title["helper_invoked"])
        self.assertFalse(title["scope_entry_runtime_verified"])

    def test_v28_artifact_rejects_wrong_identity_scope_and_missing_source(self) -> None:
        fixture = ArtifactFixture(28)
        self.addCleanup(fixture.close)
        fixture.manifest["information_battle_war_identity_scope"] = "cross_save"
        expected_manifest = _write_manifest_and_hash(fixture)
        with self.assertRaises(subject.InstalledProbeError) as raised:
            subject._validate_artifact(
                fixture.root,
                expected_manifest_sha256=expected_manifest,
                expected_dll_sha256=fixture.dll_sha,
            )
        self.assertEqual(str(raised.exception),
                         "v28_war_identity_capability_mismatch")

        fixture.manifest["information_battle_war_identity_scope"] = "observer_session"
        missing = fixture.root / "information-battle-war-identity-wire.h"
        missing.unlink()
        expected_manifest = _write_manifest_and_hash(fixture)
        with self.assertRaises(subject.InstalledProbeError) as raised:
            subject._validate_artifact(
                fixture.root,
                expected_manifest_sha256=expected_manifest,
                expected_dll_sha256=fixture.dll_sha,
            )
        self.assertEqual(str(raised.exception), "artifact_source_copy_hash_mismatch")

    def test_installation_json_requires_stable_exact_identity_and_success(self) -> None:
        for field, value in (
            ("installation_returncode", 1),
            ("installation_returncode", 0.0),
            ("installation_returncode", True),
            ("experiment_id", "different-build"),
        ):
            with self.subTest(field=field, value=value):
                original = self.fx.installation[field]
                self.fx.installation[field] = value
                self.fx.write_installation()
                with self.assertRaises(subject.InstalledProbeError):
                    subject._load_installation(
                        self.fx.installation_path,
                        self.fx.dll_sha,
                        self.fx.manifest["experiment_id"],
                    )
                self.fx.installation[field] = original
                self.fx.write_installation()
        for field, value in (("pid", 45678.0), ("creation_filetime", True)):
            with self.subTest(field=field, value=value):
                original = self.fx.installation[field]
                self.fx.installation[field] = value
                self.fx.write_installation()
                with self.assertRaises(subject.InstalledProbeError):
                    subject._load_installation(
                        self.fx.installation_path,
                        self.fx.dll_sha,
                        self.fx.manifest["experiment_id"],
                    )
                self.fx.installation[field] = original
                self.fx.write_installation()

    def test_external_pins_are_required_and_artifact_tamper_fails(self) -> None:
        with self.assertRaises(subject.InstalledProbeError):
            subject._validate_artifact(
                self.fx.root,
                expected_manifest_sha256="0" * 64,
                expected_dll_sha256=self.fx.dll_sha,
            )
        with self.assertRaises(subject.InstalledProbeError):
            subject._sha256_pin("not-a-sha", "expected_dll_sha256")
        tampered = self.fx.root / self.fx.source_names[0]
        tampered.write_bytes(b"tampered artifact copy")
        with self.assertRaises(subject.InstalledProbeError):
            subject._validate_artifact(
                self.fx.root,
                expected_manifest_sha256=self.fx.manifest_sha,
                expected_dll_sha256=self.fx.dll_sha,
            )

    def test_v24_capability_wire_bool_macro_and_required_header_guards(self) -> None:
        for key, value in (
            ("information_battle_context_wire", 1),
            ("information_battle_context_wire", True),
            ("information_battle_owned_context", False),
        ):
            with self.subTest(key=key, value=value):
                self.fx.manifest[key] = value
                expected_manifest = _write_manifest_and_hash(self.fx)
                with self.assertRaises(subject.InstalledProbeError):
                    subject._validate_artifact(
                        self.fx.root,
                        expected_manifest_sha256=expected_manifest,
                        expected_dll_sha256=self.fx.dll_sha,
                    )
                self.fx.manifest[key] = 2 if key == "information_battle_context_wire" else True
        self.fx.manifest["compiler_arguments"] = ["-DBRIDGE_INFORMATION_BATTLE=1"]
        expected_manifest = _write_manifest_and_hash(self.fx)
        with self.assertRaises(subject.InstalledProbeError):
            subject._validate_artifact(
                self.fx.root,
                expected_manifest_sha256=expected_manifest,
                expected_dll_sha256=self.fx.dll_sha,
            )

    def test_development_root_delta_is_separate_from_artifact_guard(self) -> None:
        artifact = subject._validate_artifact(
            self.fx.root,
            expected_manifest_sha256=self.fx.manifest_sha,
            expected_dll_sha256=self.fx.dll_sha,
        )
        first = self.fx.development / self.fx.source_names[0]
        first.write_bytes(b"new development source")
        delta = subject._development_root_delta(self.fx.manifest, self.fx.root, self.fx.development)
        self.assertEqual(delta["status"], "observed")
        self.assertGreaterEqual(delta["counts"].get("different", 0), 1)
        self.assertEqual(artifact["status"], "observed")

    def test_json_bytes_must_match_hash_pin_after_read(self) -> None:
        path = self.fx.root / "small.json"
        path.write_text('{"value": 1}', encoding="utf-8")
        fake_pin = {"status": "observed", "size_bytes": path.stat().st_size, "sha256": "0" * 64}
        with mock.patch.object(subject, "_sha256_file", return_value=fake_pin):
            with self.assertRaises(subject.InstalledProbeError) as raised:
                subject._read_json(path)
        self.assertIn("json_changed_after_hash", str(raised.exception))

    def test_output_is_exclusive_and_existing_evidence_is_not_overwritten(self) -> None:
        output = self.fx.root / "existing.json"
        output.write_bytes(b"original")
        with self.assertRaises(subject.InstalledProbeError):
            subject.run(
                self.fx.installation_path,
                output,
                expected_manifest_sha256=self.fx.manifest_sha,
                expected_dll_sha256=self.fx.dll_sha,
                development_root=self.fx.development,
            )
        self.assertEqual(output.read_bytes(), b"original")

    def test_extra_loaded_bridge_dll_is_rejected(self) -> None:
        loaded = {
            "status": "observed",
            "modules": [
                {"path": str(self.fx.dll), "sha256": self.fx.dll_sha},
                {"path": str(self.fx.root / "eu4_bridge_different.dll"), "sha256": "1" * 64},
            ],
        }
        with self.assertRaises(subject.InstalledProbeError) as raised:
            subject._strict_loaded_module_guard(loaded, self.fx.dll, self.fx.dll_sha)
        self.assertEqual(str(raised.exception), "loaded_module_set_guard_failed")

    def test_mocked_doublepass_checks_identity_module_entry_unwind_context_and_close(self) -> None:
        fake_kernel = FakeKernel()
        identity = {
            "status": "observed",
            "pid": self.fx.installation["pid"],
            "process_creation_filetime": self.fx.installation["creation_filetime"],
            "session_id": self.fx.installation["session_id"],
            "process_path": str(self.fx.game),
            "process_path_sha256_matches_expected": True,
            "creation_matches_installation": True,
            "session_matches_installation": True,
            "module_base": "0x180000000",
        }
        loaded = {
            "status": "observed",
            "modules": [{"base": "0x190000000", "path": str(self.fx.dll), "sha256": self.fx.dll_sha}],
            "matching_modules": [{"base": "0x190000000", "path": str(self.fx.dll), "sha256": self.fx.dll_sha}],
        }
        code = {"status": "observed", "records": {"entry": {"matches": True}, "unwind": {"matches": True}}}
        snapshots = {
            "before": {"phase": "before", "status": "observed", "game_date": 56554248, "control": {"paused": True, "speed": 0}, "physical_player": {"raw": "0102"}},
            "after": {"phase": "after", "status": "observed", "game_date": 56554248, "control": {"paused": True, "speed": 0}, "physical_player": {"raw": "0102"}},
        }
        output = self.fx.root / "report.json"
        with mock.patch.multiple(
            subject,
            _coff_symbol=mock.Mock(return_value={"status": "observed", "rva": "0x100", "file_sha256": self.fx.dll_sha}),
            _file_code_guard=mock.Mock(return_value={"status": "observed", "records": {}}),
            _configure_kernel=mock.Mock(return_value=fake_kernel),
            _close_process_handle=mock.Mock(return_value={"status": "closed", "closed": True}),
            _capture_identity=mock.Mock(side_effect=lambda _k, _h, _d, _e, phase: {**identity, "phase": phase}),
            _query_module_records=mock.Mock(return_value=loaded),
            _runtime_code_guard=mock.Mock(return_value=code),
            _snapshot=mock.Mock(side_effect=lambda _reader, _base, phase: snapshots[phase]),
        ):
            report = subject.run(
                self.fx.installation_path,
                output,
                expected_manifest_sha256=self.fx.manifest_sha,
                expected_dll_sha256=self.fx.dll_sha,
                development_root=self.fx.development,
            )
        self.assertEqual(report["status"], "passed_read_only_installed_preflight")
        self.assertTrue(report["doublepass"]["consistent"])
        self.assertTrue(report["identity"]["binding_verified"])
        self.assertEqual(report["cleanup"]["handle_close"]["calls"], 1)
        self.assertEqual(fake_kernel.open_calls, [(subject.PROCESS_ACCESS, False, self.fx.installation["pid"])])
        self.assertEqual(report["artifact"]["source_count"], 105)
        self.assertTrue(report["process_opened"])
        self.assertTrue(report["runtime_accessed"])
        self.assertTrue(report["game_access"])
        self.assertTrue(report["access"]["remote_rpm"])
        self.assertIsInstance(report["access"]["read_log"], list)
        self.assertFalse(report["request"]["native_game_function_invoked"])
        self.assertFalse(report["request"]["target_memory_writes"])
        self.assertTrue(output.is_file())

    def test_identity_change_fails_but_still_closes_handle_once(self) -> None:
        fake_kernel = FakeKernel()
        before = {
            "status": "observed",
            "pid": self.fx.installation["pid"],
            "process_creation_filetime": self.fx.installation["creation_filetime"],
            "session_id": self.fx.installation["session_id"],
            "process_path": str(self.fx.game),
            "module_base": "0x180000000",
        }
        after = {**before, "phase": "after", "process_creation_filetime": before["process_creation_filetime"] + 1}
        output = self.fx.root / "mismatch.json"
        with mock.patch.multiple(
            subject,
            _coff_symbol=mock.Mock(return_value={"status": "observed", "rva": "0x100"}),
            _file_code_guard=mock.Mock(return_value={"status": "observed", "records": {}}),
            _configure_kernel=mock.Mock(return_value=fake_kernel),
            _close_process_handle=mock.Mock(return_value={"status": "closed", "closed": True}),
            _capture_identity=mock.Mock(side_effect=[{**before, "phase": "before"}, after]),
            _query_module_records=mock.Mock(return_value={
                "status": "observed",
                "modules": [{"path": str(self.fx.dll), "sha256": self.fx.dll_sha}],
                "matching_modules": [{"base": "0x190000000", "path": str(self.fx.dll), "sha256": self.fx.dll_sha}],
            }),
        ):
            report = subject.run(
                self.fx.installation_path,
                output,
                expected_manifest_sha256=self.fx.manifest_sha,
                expected_dll_sha256=self.fx.dll_sha,
                development_root=self.fx.development,
            )
        self.assertEqual(report["status"], "failed_read_only_installed_preflight")
        self.assertEqual(report["cleanup"]["handle_close"]["calls"], 1)
        self.assertTrue(output.is_file())


if __name__ == "__main__":
    unittest.main()
