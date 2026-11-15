from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools import start_diplomacy_observer as subject


class DebtQuoteObserverManifestTests(unittest.TestCase):
    """Offline checks for the v34 debt-quote build and install contract."""

    @staticmethod
    def _v33_arguments() -> list[str]:
        return [
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
        ]

    def _setup(self, version: int):
        temp = tempfile.TemporaryDirectory()
        directory = Path(temp.name)
        dll = directory / f"eu4_bridge_diplomacy_observer_v{version}.dll"
        dll.write_bytes(b"offline fake observer dll")
        manifest_path = directory / "build-manifest.json"

        args = self._v33_arguments()
        data = {
            "version": version,
            "experiment_id": "observer-debt-quote-manifest-test",
            "compiled": True,
            "runtime_verified": False,
            "game_sha256": "a" * 64,
            "dll_sha256": subject.file_hash(dll, refresh=True),
            "native_war_participants_query": True,
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
            "compiler_arguments": args,
        }

        names = sorted(subject.INFORMATION_BATTLE_V33_SOURCE_NAMES)
        if version == 34:
            names.extend(subject.INFORMATION_DEBT_QUOTE_REQUIRED_SOURCES)
            args.append("-DBRIDGE_DEBT_QUOTE_QUERY=1")
            data.update({
                "information_debt_quote_query": True,
                "information_debt_quote_query_wire": 1,
                "information_debt_quote_read_only": True,
                "information_debt_quote_fp_context": True,
            })

        records = []
        for name in names:
            source = directory / name
            source.write_bytes(("source:" + name).encode("ascii"))
            records.append({"name": name, "sha256": subject.file_hash(source, refresh=True)})
        data["sources"] = records
        manifest_path.write_text(json.dumps(data), encoding="utf-8")
        return temp, directory, manifest_path, dll, data

    def test_v34_accepts_complete_v33_chain_plus_two_pinned_quote_sources(self):
        temp, directory, _manifest_path, _dll, manifest = self._setup(34)
        self.addCleanup(temp.cleanup)

        subject._validate_information_battle_manifest(manifest, directory)

        names = [record["name"] for record in manifest["sources"]]
        self.assertEqual(len(names), 127)
        self.assertEqual(len(names), len(set(names)))
        self.assertEqual(
            set(names),
            subject.INFORMATION_BATTLE_V33_SOURCE_NAMES
            | set(subject.INFORMATION_DEBT_QUOTE_REQUIRED_SOURCES),
        )
        self.assertEqual(
            [name for name in names if name in subject.INFORMATION_DEBT_QUOTE_REQUIRED_SOURCES],
            list(subject.INFORMATION_DEBT_QUOTE_REQUIRED_SOURCES),
        )

    def test_v34_rejects_missing_or_wrong_debt_quote_metadata_and_v33_chain(self):
        temp, directory, _manifest_path, _dll, baseline = self._setup(34)
        self.addCleanup(temp.cleanup)
        mutations = {
            "missing_query_flag": lambda data: data.pop("information_debt_quote_query"),
            "wrong_wire": lambda data: data.update({"information_debt_quote_query_wire": 2}),
            "bool_is_not_wire_integer": lambda data: data.update({"information_debt_quote_query_wire": True}),
            "not_read_only": lambda data: data.update({"information_debt_quote_read_only": False}),
            "missing_fp_context": lambda data: data.pop("information_debt_quote_fp_context"),
            "missing_v33_display_context": lambda data: data.pop("information_battle_display_context"),
            "missing_v33_gate_macro": lambda data: data["compiler_arguments"].remove(
                "-DINFORMATION_BATTLE_GATE_TRACE=1"
            ),
            "missing_v33_native_participant_source_set": lambda data: data.update({
                "native_war_participants_query": False,
            }),
            "v33_control_contract_forbidden": lambda data: data.update({
                "current_country_control_test_only": True,
            }),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                data = json.loads(json.dumps(baseline))
                mutate(data)
                with self.assertRaises(SystemExit) as raised:
                    subject._validate_information_battle_manifest(data, directory)
                self.assertEqual(str(raised.exception), "BUILD_MANIFEST_MISMATCH")

    def test_v34_requires_one_exact_quote_define_and_rejects_other_values(self):
        temp, directory, _manifest_path, _dll, baseline = self._setup(34)
        self.addCleanup(temp.cleanup)
        mutations = {
            "missing": lambda data: data["compiler_arguments"].remove(
                "-DBRIDGE_DEBT_QUOTE_QUERY=1"
            ),
            "wrong_value": lambda data: data["compiler_arguments"].append(
                "-DBRIDGE_DEBT_QUOTE_QUERY=0"
            ),
            "duplicate": lambda data: data["compiler_arguments"].append(
                "-DBRIDGE_DEBT_QUOTE_QUERY=1"
            ),
            "split_wrong_value": lambda data: data["compiler_arguments"].extend(
                ["-D", "BRIDGE_DEBT_QUOTE_QUERY=0"]
            ),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                data = json.loads(json.dumps(baseline))
                mutate(data)
                with self.assertRaises(SystemExit) as raised:
                    subject._validate_information_battle_manifest(data, directory)
                self.assertEqual(str(raised.exception), "BUILD_MANIFEST_MISMATCH")

    def test_v34_rejects_missing_duplicate_unpinned_and_extra_quote_sources(self):
        temp, directory, _manifest_path, _dll, baseline = self._setup(34)
        self.addCleanup(temp.cleanup)
        mutations = {
            "missing_source_record": lambda data: data["sources"].pop(
                next(i for i, row in enumerate(data["sources"])
                     if row["name"] == subject.INFORMATION_DEBT_QUOTE_REQUIRED_SOURCES[0])
            ),
            "duplicate_required_name": lambda data: data["sources"][-1].update({
                "name": subject.INFORMATION_DEBT_QUOTE_REQUIRED_SOURCES[0],
            }),
            "duplicate_other_name": lambda data: data["sources"][-1].update({
                "name": data["sources"][-2]["name"],
            }),
            "unexpected_quote_source_replaces_v33_source": lambda data: next(
                row for row in data["sources"]
                if row["name"] in subject.INFORMATION_BATTLE_V33_SOURCE_NAMES
            ).update({"name": "debt-quote-unexpected.inc"}),
            "extra_record": lambda data: data["sources"].append({
                "name": "unrequested-extra.inc", "sha256": "b" * 64,
            }),
            "malformed_digest": lambda data: next(
                row for row in data["sources"]
                if row["name"] == subject.INFORMATION_DEBT_QUOTE_REQUIRED_SOURCES[0]
            ).update({"sha256": "not-a-sha256"}),
            "valid_shape_but_wrong_digest": lambda data: next(
                row for row in data["sources"]
                if row["name"] == subject.INFORMATION_DEBT_QUOTE_REQUIRED_SOURCES[0]
            ).update({"sha256": "b" * 64}),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                data = json.loads(json.dumps(baseline))
                mutate(data)
                with self.assertRaises(SystemExit) as raised:
                    subject._validate_information_battle_manifest(data, directory)
                self.assertEqual(str(raised.exception), "BUILD_MANIFEST_MISMATCH")

    def test_v34_hashes_every_source_record_including_inherited_v33_files(self):
        temp, directory, _manifest_path, _dll, manifest = self._setup(34)
        self.addCleanup(temp.cleanup)
        (directory / "alliance-query.inc").write_bytes(b"changed after manifest pin")

        with self.assertRaises(SystemExit) as raised:
            subject._validate_information_battle_manifest(manifest, directory)
        self.assertEqual(str(raised.exception), "BUILD_MANIFEST_MISMATCH")

    def test_v33_remains_accepted_but_cannot_claim_debt_quote(self):
        temp, directory, _manifest_path, _dll, baseline = self._setup(33)
        self.addCleanup(temp.cleanup)

        subject._validate_information_battle_manifest(baseline, directory)
        self.assertEqual(
            {record["name"] for record in baseline["sources"]},
            subject.INFORMATION_BATTLE_V33_SOURCE_NAMES,
        )
        self.assertNotIn("information_debt_quote_query", baseline)
        contaminated = json.loads(json.dumps(baseline))
        contaminated["compiler_arguments"].append("-DBRIDGE_DEBT_QUOTE_QUERY=1")
        with self.assertRaises(SystemExit) as raised:
            subject._validate_information_battle_manifest(contaminated, directory)
        self.assertEqual(str(raised.exception), "BUILD_MANIFEST_MISMATCH")

    def test_main_selects_v34_dll_without_build_or_game_access(self):
        temp, directory, manifest_path, dll, _manifest = self._setup(34)
        self.addCleanup(temp.cleanup)
        with patch.object(
            subject,
            "_wait_until_ready",
            return_value=(
                {"pid": 61034, "session_id": "test-session-61034"},
                {},
                None,
                "ready",
                [],
            ),
        ), patch.object(subject, "_install_once") as install, patch.object(
            subject, "get_value", return_value="python"
        ), contextlib.redirect_stdout(io.StringIO()):
            subject.main(["--native-text-codec", "utf8", "--pid", "61034", "--manifest", str(manifest_path)])

        self.assertEqual(install.call_count, 1)
        self.assertEqual(install.call_args.args[3], dll.resolve())

    def test_builder_declares_v34_switch_cascade_sources_and_manifest(self):
        build_script = (
            Path(__file__).resolve().parents[2]
            / "work"
            / "native"
            / "build-diplomacy-observer.ps1"
        ).read_text(encoding="utf-8")
        expected_fragments = (
            "[switch]$DebtQuoteQuery",
            "if ($DebtQuoteQuery) { $BattleDisplayContext = $true }",
            "if ($DebtQuoteQuery) { 34 }",
            "-DBRIDGE_DEBT_QUOTE_QUERY=1",
            "'debt-quote-query.inc', 'debt-quote-native-guards.h'",
            "$manifest.information_debt_quote_query = $true",
            "$manifest.information_debt_quote_query_wire = 1",
            "$manifest.information_debt_quote_read_only = $true",
            "$manifest.information_debt_quote_fp_context = $true",
        )
        for fragment in expected_fragments:
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, build_script)


if __name__ == "__main__":
    unittest.main()
