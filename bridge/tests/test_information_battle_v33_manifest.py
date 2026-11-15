"""Offline v33 manifest contract checks for the three metadata entry points."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from tools import control_information_battle_observer as control
from tools import start_diplomacy_observer as start
from work import probe_information_battle_installed as probe


DISPLAY_FIELDS = {
    "information_battle_display_context": True,
    "information_battle_display_context_wire": 7,
    "information_battle_display_context_scope": "same_battle_event",
    "information_battle_display_context_stage": "router_scope_exit",
    "information_battle_display_context_read_only": True,
    "information_battle_display_context_complete": False,
}
DISPLAY_SOURCES = start.INFORMATION_BATTLE_DISPLAY_CONTEXT_REQUIRED_SOURCES[-3:]
PEACE_PARTICIPANT_SOURCES = (
    "peace-context-query.inc",
    "peace-war-context-query.inc",
    "peace-war-side-members.inc",
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _required_source_names(version: int) -> tuple[str, ...]:
    return {
        23: start.INFORMATION_BATTLE_REQUIRED_SOURCES,
        24: start.INFORMATION_BATTLE_CONTEXT_REQUIRED_SOURCES,
        25: start.INFORMATION_BATTLE_NAVAL_REQUIRED_SOURCES,
        26: start.INFORMATION_BATTLE_TEMPLATE_REQUIRED_SOURCES,
        27: start.INFORMATION_BATTLE_CONTAINER_REQUIRED_SOURCES,
        28: start.INFORMATION_BATTLE_WAR_IDENTITY_REQUIRED_SOURCES,
        29: start.INFORMATION_BATTLE_NATIVE_TEXT_REQUIRED_SOURCES,
        30: start.INFORMATION_BATTLE_NATIVE_TITLE_QUERY_REQUIRED_SOURCES,
        31: start.INFORMATION_CURRENT_COUNTRY_CONTROL_REQUIRED_SOURCES,
        32: start.INFORMATION_BATTLE_GATE_TRACE_REQUIRED_SOURCES,
        33: start.INFORMATION_BATTLE_DISPLAY_CONTEXT_REQUIRED_SOURCES,
    }[version]


class _ManifestFixture:
    """Small temporary build directory with a complete pinned source set."""

    def __init__(self, version: int, *, participants: bool = False) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.directory = Path(self.temp.name)
        self.version = version
        self.participants = participants
        self.manifest_path = self.directory / "build-manifest.json"
        self.dll_path = self.directory / f"eu4_bridge_diplomacy_observer_v{version}.dll"
        self.dll_path.write_bytes(f"owned metadata fixture v{version}".encode("ascii"))
        self.manifest = self._make_manifest()
        self.write_manifest(self.manifest)

    def _make_manifest(self) -> dict:
        required = list(_required_source_names(self.version))
        if self.participants and self.version >= 30:
            required.extend(PEACE_PARTICIPANT_SOURCES)
        expected_count = probe.EXPECTED_SOURCE_COUNTS[self.version]
        if self.version >= 30 and self.participants:
            expected_count += 1
        names = list(required)
        filler_index = 0
        while len(names) < expected_count:
            name = f"manifest-test-v{self.version}-filler-{filler_index:03d}.inc"
            filler_index += 1
            if name not in names:
                names.append(name)
        if len(names) != expected_count or len(set(names)) != expected_count:
            raise AssertionError("fixture_source_count_or_names_invalid")

        records = []
        for name in names:
            path = self.directory / name
            path.parent.mkdir(parents=True, exist_ok=True)
            data = ("owned-v" + str(self.version) + ":" + name).encode("ascii")
            path.write_bytes(data)
            records.append({"name": name, "sha256": hashlib.sha256(data).hexdigest()})

        arguments = ["-DBRIDGE_INFORMATION_BATTLE=1"]
        manifest = {
            "version": self.version,
            "experiment_id": f"offline-v{self.version}-manifest-contract",
            "game_sha256": probe.EXPECTED_EXE_SHA256,
            "dll_sha256": _sha256(self.dll_path),
            "information_battle_research_lifecycle": True,
            "native_war_participants_query": self.participants,
            "sources": records,
            "compiler_arguments": arguments,
        }
        if self.version >= 24:
            manifest.update({
                "information_battle_context_wire": 2,
                "information_battle_owned_context": True,
            })
            arguments.append("-DINFORMATION_BATTLE_CONTEXT=1")
        if self.version >= 25:
            manifest.update({
                "information_battle_naval_wire": 3,
                "information_battle_owned_naval": True,
            })
            arguments.append("-DINFORMATION_BATTLE_NAVAL=1")
        if self.version >= 26:
            manifest.update({
                "information_battle_template_wire": 4,
                "information_battle_owned_template": True,
                "information_battle_message_scope": True,
            })
            arguments.append("-DINFORMATION_BATTLE_TEMPLATE=1")
        if self.version >= 27:
            manifest.update({
                "information_battle_formatter_container": True,
                "information_battle_template_extensions": [1, 2],
            })
            arguments.append("-DINFORMATION_BATTLE_CONTAINER=1")
        if self.version >= 28:
            manifest.update({
                "information_battle_war_identity": True,
                "information_battle_war_identity_wire": 5,
                "information_battle_war_identity_scope": "observer_session",
                "information_battle_war_identity_read_only": True,
                "information_battle_war_identity_complete": False,
            })
            arguments.append("-DINFORMATION_BATTLE_WAR_IDENTITY=1")
        if self.version >= 29:
            manifest.update({
                "information_battle_native_text": True,
                "information_battle_native_text_wire": 6,
                "information_battle_native_text_scope": "observer_session",
                "information_battle_native_text_read_only": True,
                "information_battle_native_text_complete": False,
            })
            arguments.append("-DINFORMATION_BATTLE_NATIVE_TEXT=1")
        if self.version >= 30:
            manifest.update({
                "information_battle_native_title_query": True,
                "information_battle_native_title_query_mode": "native_helper_owned_output",
                "information_battle_native_title_query_wire": 6,
                "information_battle_native_title_query_complete": False,
            })
            arguments.append("-DINFORMATION_BATTLE_NATIVE_TITLE_QUERY=1")
        if self.version == 31:
            manifest.update({
                "current_country_control_test_only": True,
                "current_country_control_protocol": "EU4COUNTRY1",
                "current_country_control_entry_rva": "0x779360",
                "runtime_verified": False,
            })
            arguments.append("-DBRIDGE_CURRENT_COUNTRY_CONTROL=1")
        if self.version >= 32:
            manifest.update({
                "information_battle_gate_trace": True,
                "information_battle_gate_trace_protocol": "EU4-BATTLE-GATE-TRACE/1",
                "information_battle_gate_trace_runtime_verified": False,
            })
            arguments.append("-DINFORMATION_BATTLE_GATE_TRACE=1")
        if self.version == 33:
            manifest.update(DISPLAY_FIELDS)
            arguments.append("-DINFORMATION_BATTLE_DISPLAY_CONTEXT=1")
        return manifest

    def write_manifest(self, manifest: dict) -> None:
        self.manifest = manifest
        self.manifest_path.write_text(
            json.dumps(manifest, ensure_ascii=False, sort_keys=True),
            encoding="utf-8",
        )

    def validate_probe(self) -> dict:
        return probe._validate_artifact(
            self.directory,
            expected_manifest_sha256=_sha256(self.manifest_path),
            expected_dll_sha256=_sha256(self.dll_path),
        )

    def close(self) -> None:
        self.temp.cleanup()

    def __enter__(self) -> "_ManifestFixture":
        return self

    def __exit__(self, _kind, _value, _traceback) -> None:
        self.close()


class InformationBattleV33ManifestTests(unittest.TestCase):
    def _accept_all(self, fixture: _ManifestFixture) -> dict:
        start._validate_information_battle_manifest(fixture.manifest, fixture.directory)
        control._validate_manifest(fixture.manifest, fixture.directory)
        return fixture.validate_probe()

    def _reject_all(self, fixture: _ManifestFixture) -> None:
        with self.assertRaises(SystemExit) as start_error:
            start._validate_information_battle_manifest(
                fixture.manifest, fixture.directory
            )
        self.assertEqual(str(start_error.exception), "BUILD_MANIFEST_MISMATCH")

        with self.assertRaises(control.ControlError) as control_error:
            control._validate_manifest(fixture.manifest, fixture.directory)
        self.assertEqual(control_error.exception.reason, "BUILD_MANIFEST_MISMATCH")

        with self.assertRaises(probe.InstalledProbeError):
            fixture.validate_probe()

    def test_v33_manifest_is_accepted_by_start_control_and_probe(self) -> None:
        with _ManifestFixture(33) as fixture:
            artifact = self._accept_all(fixture)
            self.assertEqual(artifact["status"], "observed")
            self.assertEqual(artifact["source_count"], 124)
            self.assertEqual(artifact["display_context_capability"], {
                "enabled": True,
                "wire": 7,
                "scope": "same_battle_event",
                "stage": "router_scope_exit",
                "read_only": True,
                "complete": False,
                "compiler_macro": "-DINFORMATION_BATTLE_DISPLAY_CONTEXT=1",
                "source_guard": True,
                "runtime_popup_verified": False,
            })
            self.assertTrue(
                set(DISPLAY_SOURCES) <= {row["name"] for row in fixture.manifest["sources"]}
            )
            self.assertFalse(
                set(start.INFORMATION_CURRENT_COUNTRY_CONTROL_ONLY_SOURCES)
                & {row["name"] for row in fixture.manifest["sources"]}
            )

    def test_v33_source_count_includes_optional_participant_sources(self) -> None:
        with _ManifestFixture(33, participants=True) as fixture:
            artifact = self._accept_all(fixture)
            self.assertEqual(artifact["source_count"], 125)
            self.assertTrue(
                set(PEACE_PARTICIPANT_SOURCES)
                <= {row["name"] for row in fixture.manifest["sources"]}
            )

    def test_each_v33_display_header_source_is_required(self) -> None:
        baseline = _ManifestFixture(33)
        self.addCleanup(baseline.close)
        original = copy.deepcopy(baseline.manifest)
        filler = next(row["name"] for row in original["sources"]
                      if "-filler-" in row["name"])
        for index, missing_name in enumerate(DISPLAY_SOURCES):
            with self.subTest(source=missing_name):
                mutant = copy.deepcopy(original)
                removed = next(row for row in mutant["sources"]
                               if row["name"] == missing_name)
                mutant["sources"].remove(removed)
                replacement_name = f"display-missing-replacement-{index}.inc"
                replacement_path = baseline.directory / replacement_name
                data = f"replacement:{replacement_name}".encode("ascii")
                replacement_path.write_bytes(data)
                mutant["sources"].append({
                    "name": replacement_name,
                    "sha256": hashlib.sha256(data).hexdigest(),
                })
                self.assertEqual(len(mutant["sources"]), len(original["sources"]))
                baseline.write_manifest(mutant)
                self._reject_all(baseline)
                baseline.write_manifest(copy.deepcopy(original))

    def test_each_v33_display_field_is_required(self) -> None:
        with _ManifestFixture(33) as fixture:
            original = copy.deepcopy(fixture.manifest)
            for key in DISPLAY_FIELDS:
                with self.subTest(missing_field=key):
                    mutant = copy.deepcopy(original)
                    del mutant[key]
                    fixture.write_manifest(mutant)
                    self._reject_all(fixture)
            fixture.write_manifest(original)

    def test_each_v33_display_field_has_a_strict_type_and_value(self) -> None:
        bad_values = {
            "information_battle_display_context": (1, False),
            # bool is an int subclass in Python; the validator must reject True here.
            "information_battle_display_context_wire": (True, 6),
            "information_battle_display_context_scope": (1, "observer_session"),
            "information_battle_display_context_stage": ([], "message_dispatch"),
            "information_battle_display_context_read_only": (1, False),
            "information_battle_display_context_complete": (0, True),
        }
        with _ManifestFixture(33) as fixture:
            original = copy.deepcopy(fixture.manifest)
            for key, (wrong_type, wrong_value) in bad_values.items():
                for label, value in (("wrong_type", wrong_type),
                                     ("wrong_value", wrong_value)):
                    with self.subTest(field=key, mutation=label):
                        mutant = copy.deepcopy(original)
                        mutant[key] = value
                        fixture.write_manifest(mutant)
                        self._reject_all(fixture)
            fixture.write_manifest(original)

    def test_country_control_macros_metadata_and_sources_are_forbidden_in_v33(self) -> None:
        with _ManifestFixture(33) as fixture:
            original = copy.deepcopy(fixture.manifest)
            macro_cases = {
                "direct_country_control": ["-DBRIDGE_CURRENT_COUNTRY_CONTROL=1"],
                "split_country_control": ["-D", "BRIDGE_CURRENT_COUNTRY_CONTROL=1"],
                "host_fixture": ["-DINFORMATION_CURRENT_COUNTRY_HOST_FIXTURE=1"],
            }
            for label, extra in macro_cases.items():
                with self.subTest(macro=label):
                    mutant = copy.deepcopy(original)
                    mutant["compiler_arguments"].extend(extra)
                    fixture.write_manifest(mutant)
                    self._reject_all(fixture)

            mutant = copy.deepcopy(original)
            mutant["current_country_control_test_only"] = True
            fixture.write_manifest(mutant)
            self._reject_all(fixture)

            for index, forbidden_source in enumerate(
                    start.INFORMATION_CURRENT_COUNTRY_CONTROL_ONLY_SOURCES):
                with self.subTest(source=forbidden_source):
                    mutant = copy.deepcopy(original)
                    filler = next(row for row in mutant["sources"]
                                  if "-filler-" in row["name"])
                    replacement = f"country-source-{index}".encode("ascii")
                    replacement_path = fixture.directory / forbidden_source
                    replacement_path.write_bytes(replacement)
                    mutant["sources"].remove(filler)
                    mutant["sources"].append({
                        "name": forbidden_source,
                        "sha256": hashlib.sha256(replacement).hexdigest(),
                    })
                    self.assertEqual(len(mutant["sources"]), len(original["sources"]))
                    fixture.write_manifest(mutant)
                    self._reject_all(fixture)
            fixture.write_manifest(original)

    def test_legacy_v32_remains_valid_but_cannot_claim_display_context(self) -> None:
        with _ManifestFixture(32) as fixture:
            original = copy.deepcopy(fixture.manifest)
            artifact = self._accept_all(fixture)
            self.assertEqual(artifact["source_count"], 121)
            self.assertNotIn("display_context_capability", artifact)
            self.assertNotIn("information_battle_display_context", original)

            mutations = {
                "display_macro": lambda data: data["compiler_arguments"].append(
                    "-DINFORMATION_BATTLE_DISPLAY_CONTEXT=1"),
                "split_display_macro": lambda data: data["compiler_arguments"].extend(
                    ["-D", "INFORMATION_BATTLE_DISPLAY_CONTEXT=1"]),
                "display_metadata": lambda data: data.update(
                    {"information_battle_display_context": True}),
            }
            for label, mutate in mutations.items():
                with self.subTest(fake_display=label):
                    mutant = copy.deepcopy(original)
                    mutate(mutant)
                    fixture.write_manifest(mutant)
                    self._reject_all(fixture)

    def test_versions_23_through_32_remain_accepted(self) -> None:
        for version in range(23, 33):
            with self.subTest(version=version):
                with _ManifestFixture(version) as fixture:
                    artifact = self._accept_all(fixture)
                    self.assertEqual(
                        artifact["source_count"],
                        probe.EXPECTED_SOURCE_COUNTS[version],
                    )
                    self.assertNotIn("display_context_capability", artifact)


if __name__ == "__main__":
    unittest.main()
