from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools import start_diplomacy_observer as subject


class InformationBattleObserverStartTests(unittest.TestCase):
    """Offline manifest/build-selection checks for the v23-v32 battle chain."""

    @staticmethod
    def _identity() -> dict:
        return {
            "pid": 61029,
            "creation_filetime": 9988,
            "session_id": "61029-2704",
            "game_sha256": "game",
            "modules": [],
        }

    def _setup(self, version: int):
        temp = tempfile.TemporaryDirectory()
        directory = Path(temp.name)
        dll = directory / f"eu4_bridge_diplomacy_observer_v{version}.dll"
        dll.write_bytes(b"reviewed observer")
        manifest_path = directory / "build-manifest.json"
        data = {
            "version": version,
            "experiment_id": "observer-information-battle-test",
            "game_sha256": "game",
            "dll_sha256": subject.file_hash(dll, refresh=True),
        }
        if version >= 23:
            if version == 23:
                names = subject.INFORMATION_BATTLE_REQUIRED_SOURCES
            elif version in (24,):
                names = subject.INFORMATION_BATTLE_CONTEXT_REQUIRED_SOURCES
            elif version in (25,):
                names = subject.INFORMATION_BATTLE_NAVAL_REQUIRED_SOURCES
            elif version in (26,):
                names = subject.INFORMATION_BATTLE_TEMPLATE_REQUIRED_SOURCES
            elif version in (27,):
                names = subject.INFORMATION_BATTLE_CONTAINER_REQUIRED_SOURCES
            elif version in (28,):
                names = subject.INFORMATION_BATTLE_WAR_IDENTITY_REQUIRED_SOURCES
            elif version in (29,):
                names = subject.INFORMATION_BATTLE_NATIVE_TEXT_REQUIRED_SOURCES
            elif version == 30:
                names = subject.INFORMATION_BATTLE_NATIVE_TITLE_QUERY_REQUIRED_SOURCES
            elif version == 31:
                names = subject.INFORMATION_CURRENT_COUNTRY_CONTROL_REQUIRED_SOURCES
            else:
                names = subject.INFORMATION_BATTLE_GATE_TRACE_REQUIRED_SOURCES
            if version in (30, 31, 32):
                source_count = 118 + (3 if version in (31, 32) else 0)
                names = tuple(names) + tuple(
                    f"title-query-filler-{index:03d}.inc"
                    for index in range(source_count - len(names))
                )
            records = []
            for name in names:
                source = directory / name
                source.write_bytes(("source:" + name).encode("ascii"))
                records.append({"name": name, "sha256": subject.file_hash(source, refresh=True)})
            data.update({
                "information_battle_research_lifecycle": True,
                "sources": records,
                "compiler_arguments": ["-DBRIDGE_INFORMATION_BATTLE=1"],
            })
            if version >= 24:
                data.update({
                    "information_battle_context_wire": 2,
                    "information_battle_owned_context": True,
                })
                data["compiler_arguments"].append("-DINFORMATION_BATTLE_CONTEXT=1")
            if version >= 25:
                data.update({
                    "information_battle_naval_wire": 3,
                    "information_battle_owned_naval": True,
                })
                data["compiler_arguments"].append("-DINFORMATION_BATTLE_NAVAL=1")
            if version >= 26:
                data.update({
                    "information_battle_template_wire": 4,
                    "information_battle_owned_template": True,
                    "information_battle_message_scope": True,
                })
                data["compiler_arguments"].append("-DINFORMATION_BATTLE_TEMPLATE=1")
            if version >= 27:
                data.update({
                    "information_battle_formatter_container": True,
                    "information_battle_template_extensions": [1, 2],
                })
                data["compiler_arguments"].append("-DINFORMATION_BATTLE_CONTAINER=1")
            if version >= 28:
                data.update({
                    "information_battle_war_identity": True,
                    "information_battle_war_identity_wire": 5,
                    "information_battle_war_identity_scope": "observer_session",
                    "information_battle_war_identity_read_only": True,
                    "information_battle_war_identity_complete": False,
                })
                data["compiler_arguments"].append("-DINFORMATION_BATTLE_WAR_IDENTITY=1")
            if version >= 29:
                data.update({
                    "information_battle_native_text": True,
                    "information_battle_native_text_wire": 6,
                    "information_battle_native_text_scope": "observer_session",
                    "information_battle_native_text_read_only": True,
                    "information_battle_native_text_complete": False,
                })
                data["compiler_arguments"].append("-DINFORMATION_BATTLE_NATIVE_TEXT=1")
            if version >= 30:
                data.update({
                    "information_battle_native_title_query": True,
                    "information_battle_native_title_query_mode": "native_helper_owned_output",
                    "information_battle_native_title_query_wire": 6,
                    "information_battle_native_title_query_complete": False,
                })
                data["compiler_arguments"].append(
                    "-DINFORMATION_BATTLE_NATIVE_TITLE_QUERY=1"
                )
            if version == 31:
                data.update({
                    "current_country_control_test_only": True,
                    "current_country_control_protocol": "EU4COUNTRY1",
                    "current_country_control_entry_rva": "0x779360",
                    "runtime_verified": False,
                })
                data["compiler_arguments"].append("-DBRIDGE_CURRENT_COUNTRY_CONTROL=1")
            if version == 32:
                data.update({
                    "information_battle_gate_trace": True,
                    "information_battle_gate_trace_protocol": "EU4-BATTLE-GATE-TRACE/1",
                    "information_battle_gate_trace_runtime_verified": False,
                })
                data["compiler_arguments"].append("-DINFORMATION_BATTLE_GATE_TRACE=1")
        manifest_path.write_text(json.dumps(data), encoding="utf-8")
        return temp, directory, manifest_path, dll

    def _setup_v35_or_v36(self, version: int, *, name_handoff: bool = False,
                          header_dependencies: tuple[str, ...] = ()):
        self.assertIn(version, (35, 36))
        if version == 35:
            name_handoff = True
        self.assertTrue(set(header_dependencies) <=
                        subject.INFORMATION_BATTLE_END_STATE_HEADER_DEPENDENCIES)
        temp = tempfile.TemporaryDirectory()
        directory = Path(temp.name)
        dll = directory / f"eu4_bridge_diplomacy_observer_v{version}.dll"
        dll.write_bytes(b"reviewed observer")

        names = (set(subject.INFORMATION_BATTLE_V33_SOURCE_NAMES)
                 | set(subject.INFORMATION_DEBT_QUOTE_REQUIRED_SOURCES))
        if version == 36:
            names |= set(subject.INFORMATION_BATTLE_END_STATE_SOURCES)
        if name_handoff:
            names |= set(subject.INFORMATION_BATTLE_NAME_HANDOFF_SOURCES)
        else:
            names |= set(header_dependencies)
        records = []
        for name in sorted(names):
            source = directory / name
            source.write_bytes(("source:" + name).encode("ascii"))
            records.append({"name": name, "sha256": subject.file_hash(source, refresh=True)})

        arguments = [
            "-DBRIDGE_INFORMATION_BATTLE=1",
            "-DINFORMATION_BATTLE_CONTEXT=1",
            "-DINFORMATION_BATTLE_NAVAL=1",
            "-DINFORMATION_BATTLE_TEMPLATE=1",
            "-DINFORMATION_BATTLE_CONTAINER=1",
            "-DINFORMATION_BATTLE_WAR_IDENTITY=1",
            "-DINFORMATION_BATTLE_NATIVE_TEXT=1",
            "-DINFORMATION_BATTLE_NATIVE_TITLE_QUERY=1",
            "-DINFORMATION_BATTLE_GATE_TRACE=1",
            "-DINFORMATION_BATTLE_DISPLAY_CONTEXT=1",
            "-DBRIDGE_DEBT_QUOTE_QUERY=1",
        ]
        data = {
            "version": version,
            "experiment_id": "observer-information-battle-end-state-test",
            "game_sha256": "game",
            "dll_sha256": subject.file_hash(dll, refresh=True),
            "information_battle_research_lifecycle": True,
            "native_war_participants_query": True,
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
            "information_battle_gate_trace": True,
            "information_battle_gate_trace_protocol": "EU4-BATTLE-GATE-TRACE/1",
            "information_battle_gate_trace_runtime_verified": False,
            "information_battle_display_context": True,
            "information_battle_display_context_wire": 7,
            "information_battle_display_context_scope": "same_battle_event",
            "information_battle_display_context_stage": "router_scope_exit",
            "information_battle_display_context_read_only": True,
            "information_battle_display_context_complete": False,
            "information_debt_quote_query": True,
            "information_debt_quote_query_wire": 1,
            "information_debt_quote_read_only": True,
            "information_debt_quote_fp_context": True,
            "compiler_arguments": arguments,
            "sources": records,
        }
        if version == 36:
            data.update({
                "information_battle_end_state": True,
                "information_battle_end_state_wire": 9,
                "information_battle_end_state_complete": False,
                "information_battle_name_handoff": name_handoff,
            })
            arguments.append("-DINFORMATION_BATTLE_END_STATE=1")
        if name_handoff:
            data.update({
                "information_battle_name_handoff": True,
                "information_battle_name_handoff_wire": 8,
                "information_battle_name_handoff_stage": "before_pair_move",
                "information_battle_name_handoff_complete": False,
            })
            arguments.append("-DINFORMATION_BATTLE_NAME_HANDOFF=1")
        manifest_path = directory / "build-manifest.json"
        manifest_path.write_text(json.dumps(data), encoding="utf-8")
        return temp, directory, manifest_path, dll

    def test_v36_manifest_accepts_end_state_without_v35_name_hook(self):
        temp, directory, manifest_path, _dll = self._setup_v35_or_v36(36)
        self.addCleanup(temp.cleanup)
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

        subject._validate_information_battle_manifest(manifest, directory)

        names = {record["name"] for record in manifest["sources"]}
        self.assertEqual(len(names), 129)
        self.assertTrue(set(subject.INFORMATION_BATTLE_END_STATE_SOURCES) <= names)
        self.assertFalse(set(subject.INFORMATION_BATTLE_NAME_HANDOFF_SOURCES) & names)
        self.assertIs(manifest["information_battle_name_handoff"], False)

    def test_v36_allows_name_headers_as_dependencies_without_enabling_hook(self):
        dependencies = tuple(sorted(subject.INFORMATION_BATTLE_END_STATE_HEADER_DEPENDENCIES))
        temp, directory, manifest_path, _dll = self._setup_v35_or_v36(
            36, header_dependencies=dependencies)
        self.addCleanup(temp.cleanup)
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

        subject._validate_information_battle_manifest(manifest, directory)

        names = {record["name"] for record in manifest["sources"]}
        self.assertTrue(set(dependencies) <= names)
        self.assertNotIn("information-battle-name-handoff-observer-stub.S", names)
        self.assertNotIn("-DINFORMATION_BATTLE_NAME_HANDOFF=1", manifest["compiler_arguments"])

    def test_v36_explicit_name_handoff_uses_v35_gate_with_end_state(self):
        temp, directory, manifest_path, _dll = self._setup_v35_or_v36(
            36, name_handoff=True)
        self.addCleanup(temp.cleanup)
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

        subject._validate_information_battle_manifest(manifest, directory)

        names = {record["name"] for record in manifest["sources"]}
        self.assertTrue(set(subject.INFORMATION_BATTLE_NAME_HANDOFF_SOURCES) <= names)
        self.assertIn("-DINFORMATION_BATTLE_END_STATE=1", manifest["compiler_arguments"])

    def test_v36_end_state_contract_and_gate_conflicts_are_strict(self):
        temp, directory, manifest_path, _dll = self._setup_v35_or_v36(36)
        self.addCleanup(temp.cleanup)
        baseline = json.loads(manifest_path.read_text(encoding="utf-8"))
        mutations = {
            "missing_end_state": lambda data: data.pop("information_battle_end_state"),
            "wrong_wire": lambda data: data.update({"information_battle_end_state_wire": 8}),
            "boolean_wire": lambda data: data.update({"information_battle_end_state_wire": True}),
            "complete_must_remain_false": lambda data: data.update({
                "information_battle_end_state_complete": True
            }),
            "missing_macro": lambda data: data["compiler_arguments"].remove(
                "-DINFORMATION_BATTLE_END_STATE=1"
            ),
            "missing_end_state_source": lambda data: data["sources"].pop(),
            "name_hook_source_without_enable": lambda data: data["sources"].append({
                "name": "information-battle-name-handoff-observer-stub.S",
                "sha256": "0" * 64,
            }),
            "current_country_control_macro_forbidden": lambda data: data["compiler_arguments"].append(
                "-DBRIDGE_CURRENT_COUNTRY_CONTROL=1"
            ),
            "current_country_control_metadata_forbidden": lambda data: data.update({
                "current_country_control_test_only": True
            }),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                data = json.loads(json.dumps(baseline))
                mutate(data)
                with self.assertRaises(SystemExit) as raised:
                    subject._validate_information_battle_manifest(data, directory)
                self.assertEqual(str(raised.exception), "BUILD_MANIFEST_MISMATCH")

    def test_v35_name_handoff_contract_remains_mandatory(self):
        temp, directory, manifest_path, _dll = self._setup_v35_or_v36(35)
        self.addCleanup(temp.cleanup)
        baseline = json.loads(manifest_path.read_text(encoding="utf-8"))
        subject._validate_information_battle_manifest(baseline, directory)

        data = json.loads(json.dumps(baseline))
        data.pop("information_battle_name_handoff")
        with self.assertRaises(SystemExit) as raised:
            subject._validate_information_battle_manifest(data, directory)
        self.assertEqual(str(raised.exception), "BUILD_MANIFEST_MISMATCH")

    def test_v36_main_selects_v36_dll_without_building_or_game_access(self):
        temp, _directory, manifest_path, dll = self._setup_v35_or_v36(36)
        self.addCleanup(temp.cleanup)
        with patch.object(
            subject,
            "_wait_until_ready",
            return_value=(self._identity(), {}, None, "ready", []),
        ), patch.object(subject, "_install_once") as install, patch.object(
            subject, "get_value", return_value="python"
        ), contextlib.redirect_stdout(io.StringIO()):
            subject.main(["--pid", "61036", "--manifest", str(manifest_path),
                          "--native-text-codec", "utf8"])

        self.assertEqual(install.call_count, 1)
        self.assertEqual(install.call_args.args[3], dll.resolve())

    def test_v29_manifest_accepts_wire6_and_all_native_text_pins(self):
        temp, directory, manifest_path, _dll = self._setup(29)
        self.addCleanup(temp.cleanup)
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

        subject._validate_information_battle_manifest(manifest, directory)
        self.assertEqual(
            set(subject.INFORMATION_BATTLE_NATIVE_TEXT_REQUIRED_SOURCES),
            {record["name"] for record in manifest["sources"]},
        )

    def test_v29_manifest_rejects_each_native_text_guard(self):
        temp, directory, manifest_path, _dll = self._setup(29)
        self.addCleanup(temp.cleanup)
        baseline = json.loads(manifest_path.read_text(encoding="utf-8"))
        mutations = {
            "wrong_wire": lambda data: data.update({"information_battle_native_text_wire": 5}),
            "wrong_scope": lambda data: data.update({"information_battle_native_text_scope": "global"}),
            "missing_read_only": lambda data: data.pop("information_battle_native_text_read_only"),
            "complete_must_remain_false": lambda data: data.update(
                {"information_battle_native_text_complete": True}
            ),
            "missing_native_define": lambda data: data["compiler_arguments"].remove(
                "-DINFORMATION_BATTLE_NATIVE_TEXT=1"
            ),
            "missing_line1_source": lambda data: data["sources"].pop(),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                data = json.loads(json.dumps(baseline))
                mutate(data)
                with self.assertRaises(SystemExit) as raised:
                    subject._validate_information_battle_manifest(data, directory)
                self.assertEqual(str(raised.exception), "BUILD_MANIFEST_MISMATCH")

    def test_v28_manifest_remains_accepted_without_v29_metadata(self):
        temp, directory, manifest_path, _dll = self._setup(28)
        self.addCleanup(temp.cleanup)
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        subject._validate_information_battle_manifest(manifest, directory)
        self.assertNotIn("information_battle_native_text", manifest)

    def test_v29_main_selects_v29_dll_without_game_or_build(self):
        temp, directory, manifest_path, dll = self._setup(29)
        self.addCleanup(temp.cleanup)
        with patch.object(
            subject,
            "_wait_until_ready",
            return_value=(self._identity(), {}, None, "ready", []),
        ), patch.object(subject, "_install_once") as install, patch.object(
            subject, "get_value", return_value="python"
        ), contextlib.redirect_stdout(io.StringIO()):
            subject.main(["--pid", "61029", "--manifest", str(manifest_path),
                          "--native-text-codec", "utf8"])

        self.assertEqual(install.call_count, 1)
        self.assertEqual(install.call_args.args[3], dll.resolve())

    def test_v30_manifest_requires_title_query_metadata_and_118_sources(self):
        temp, directory, manifest_path, _dll = self._setup(30)
        self.addCleanup(temp.cleanup)
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

        subject._validate_information_battle_manifest(manifest, directory)
        self.assertEqual(len(manifest["sources"]), 118)
        self.assertTrue(
            set(subject.INFORMATION_BATTLE_NATIVE_TITLE_QUERY_REQUIRED_SOURCES)
            <= {record["name"] for record in manifest["sources"]}
        )
        self.assertEqual(
            manifest["information_battle_native_title_query_mode"],
            "native_helper_owned_output",
        )
        self.assertFalse(manifest["information_battle_native_title_query_complete"])

    def test_v32_manifest_pins_gate_trace_sources_and_rejects_control_macros(self):
        temp, directory, manifest_path, _dll = self._setup(32)
        self.addCleanup(temp.cleanup)
        baseline = json.loads(manifest_path.read_text(encoding="utf-8"))

        subject._validate_information_battle_manifest(baseline, directory)
        self.assertEqual(len(baseline["sources"]), 121)
        self.assertTrue(
            set(subject.INFORMATION_BATTLE_GATE_TRACE_REQUIRED_SOURCES)
            <= {record["name"] for record in baseline["sources"]}
        )

        mutations = {
            "missing_capability": lambda data: data.update({"information_battle_gate_trace": False}),
            "wrong_protocol": lambda data: data.update({
                "information_battle_gate_trace_protocol": "EU4-BATTLE-GATE-TRACE/2"
            }),
            "runtime_must_remain_unverified": lambda data: data.update({
                "information_battle_gate_trace_runtime_verified": True
            }),
            "missing_gate_macro": lambda data: data["compiler_arguments"].remove(
                "-DINFORMATION_BATTLE_GATE_TRACE=1"
            ),
            "country_control_macro_forbidden": lambda data: data["compiler_arguments"].append(
                "-DBRIDGE_CURRENT_COUNTRY_CONTROL=1"
            ),
            "country_control_split_macro_forbidden": lambda data: data["compiler_arguments"].extend(
                ["-D", "BRIDGE_CURRENT_COUNTRY_CONTROL=1"]
            ),
            "fixture_macro_forbidden": lambda data: data["compiler_arguments"].append(
                "-DINFORMATION_CURRENT_COUNTRY_HOST_FIXTURE=1"
            ),
            "country_control_metadata_forbidden": lambda data: data.update({
                "current_country_control_test_only": True
            }),
            "country_control_source_forbidden": lambda data: data["sources"][-1].update({
                "name": "information-current-country-control.inc",
            }),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                data = json.loads(json.dumps(baseline))
                mutate(data)
                with self.assertRaises(SystemExit) as raised:
                    subject._validate_information_battle_manifest(data, directory)
                self.assertEqual(str(raised.exception), "BUILD_MANIFEST_MISMATCH")

    def test_v32_main_selects_v32_dll_without_building_or_game_access(self):
        temp, directory, manifest_path, dll = self._setup(32)
        self.addCleanup(temp.cleanup)
        with patch.object(
            subject,
            "_wait_until_ready",
            return_value=(self._identity(), {}, None, "ready", []),
        ), patch.object(subject, "_install_once") as install, patch.object(
            subject, "get_value", return_value="python"
        ), contextlib.redirect_stdout(io.StringIO()):
            subject.main(["--pid", "61032", "--manifest", str(manifest_path),
                          "--native-text-codec", "utf8"])

        self.assertEqual(install.call_count, 1)
        self.assertEqual(install.call_args.args[3], dll.resolve())

    def test_v30_title_query_metadata_and_source_count_are_strict(self):
        temp, directory, manifest_path, _dll = self._setup(30)
        self.addCleanup(temp.cleanup)
        baseline = json.loads(manifest_path.read_text(encoding="utf-8"))
        mutations = {
            "wrong_mode": lambda data: data.update(
                {"information_battle_native_title_query_mode": "runtime"}
            ),
            "wrong_wire": lambda data: data.update(
                {"information_battle_native_title_query_wire": 5}
            ),
            "complete_must_remain_false": lambda data: data.update(
                {"information_battle_native_title_query_complete": True}
            ),
            "missing_title_macro": lambda data: data["compiler_arguments"].remove(
                "-DINFORMATION_BATTLE_NATIVE_TITLE_QUERY=1"
            ),
            "missing_title_source": lambda data: data["sources"].pop(),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                data = json.loads(json.dumps(baseline))
                mutate(data)
                with self.assertRaises(SystemExit) as raised:
                    subject._validate_information_battle_manifest(data, directory)
                self.assertEqual(str(raised.exception), "BUILD_MANIFEST_MISMATCH")

    def test_build_script_declares_v29_switch_cascade_and_source_manifest(self):
        build_script = (
            Path(__file__).resolve().parents[2]
            / "work"
            / "native"
            / "build-diplomacy-observer.ps1"
        ).read_text(encoding="utf-8")
        expected_fragments = (
            "[switch]$InformationBattleNativeText",
            "if ($InformationBattleNativeText) { $InformationBattleWarIdentity = $true }",
            "if ($InformationBattleNativeText) { 29 }",
            "-DINFORMATION_BATTLE_NATIVE_TEXT=1",
            "information-battle-owned-native-text.h",
            "information-battle-native-text-wire.h",
            "information-battle-line1-entry-plan.h",
            "information-battle-line1-observer-stub.S",
            "$manifest.information_battle_native_text_wire = 6",
            "[switch]$InformationBattleNativeTitleQuery",
            "if ($InformationBattleNativeTitleQuery) { $InformationBattleNativeText = $true }",
            "if ($InformationBattleNativeTitleQuery) { 30 }",
            "-DINFORMATION_BATTLE_NATIVE_TITLE_QUERY=1",
            "information-battle-owned-title-query.h",
            "information-battle-title-query-plan.h",
            ("$manifest.information_battle_native_title_query_mode = if ($BattleNameSources) "
             "{ 'cached_sources_no_helper_invoke' } else { 'native_helper_owned_output' }"),
            "[switch]$BattleGateTrace",
            "if ($BattleGateTrace -and $CurrentCountryControl)",
            "if ($BattleGateTrace) { $InformationBattleNativeTitleQuery = $true }",
            "if ($BattleGateTrace) { 32 }",
            "-DINFORMATION_BATTLE_GATE_TRACE=1",
            "information-battle-owned-gate-inputs.h",
            "information-battle-gate-trace.h",
            "information-battle-gate-marker-entry-plan.h",
            "$manifest.information_battle_gate_trace_protocol = 'EU4-BATTLE-GATE-TRACE/1'",
            "$manifest.information_battle_gate_trace_runtime_verified = $false",
        )
        for fragment in expected_fragments:
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, build_script)
        self.assertLess(
            build_script.index("if ($BattleGateTrace -and $CurrentCountryControl)"),
            build_script.index("New-Item -ItemType Directory"),
        )


if __name__ == "__main__":
    unittest.main()
