"""Offline coverage for read-only persistent-cache inventory operations."""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import time
import unittest
from unittest import mock

from reverse_engineering import cache_query
from reverse_engineering.ghidra_cache import CacheError


TARGET_SHA = "a" * 64
MANIFEST_SHA = "b" * 64
DATABASE_SHA = "c" * 64
ADAPTER_SHA = "d" * 64


class _FakeProcess:
    def poll(self):
        return 0

    def wait(self, timeout=None):
        return 0


class _Unlocked:
    def __init__(self, *_args, **_kwargs):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False


def _evidence(value, operation: str, parameters: dict) -> dict:
    return {
        "evidence_id": "ev_inventory_test",
        "operation": operation,
        "parameters": parameters,
        "analysis_profile": {
            "parameters": {
                "analyzer_preset": cache_query.PRESET,
                "local_adapter_sha256": ADAPTER_SHA,
                "completed_manifest_sha256": MANIFEST_SHA,
                "completed_database_sha256": DATABASE_SHA,
            }
        },
        "subject": {"digest": {"sha256": TARGET_SHA}},
        "provider": {"version": "12.1.4"},
        "raw_result": {"value": value},
    }


class CacheQueryOperationTests(unittest.TestCase):
    def test_operation_inputs_follow_public_cli_contract_and_fail_before_cache(self):
        self.assertEqual(
            cache_query._operation_parameters(
                SimpleNamespace(pattern="OpinionOfFROM", mode="literal", case_sensitive=True),
                "search_strings",
            ),
            {"pattern": "OpinionOfFROM", "mode": "literal", "case_sensitive": True},
        )
        self.assertEqual(
            cache_query._operation_parameters(SimpleNamespace(address="0x140012340"), "xrefs"),
            {"address": "0x140012340"},
        )
        with self.assertRaises(CacheError):
            cache_query._validated_operation(SimpleNamespace(operation="analyze_function"))
        with self.assertRaises(CacheError):
            cache_query._operation_parameters(SimpleNamespace(pattern=""), "search_strings")
        with self.assertRaises(CacheError):
            cache_query._operation_parameters(SimpleNamespace(address=None), "xrefs")
        with self.assertRaises(CacheError):
            cache_query._operation_parameters(SimpleNamespace(address="OpinionOfFROM"), "xrefs")

        args = SimpleNamespace(operation="not-an-operation", java_heap="512M", binary=object(), cache=None)
        with mock.patch.object(cache_query, "_resolve_target", side_effect=AssertionError("target read")) as target:
            with self.assertRaises(CacheError):
                cache_query.query(args)
        target.assert_not_called()

    def test_inventory_result_contracts_accept_empty_and_reject_wrong_shapes(self):
        common = {"adapter_sha256": ADAPTER_SHA}
        for operation, value in (
            ("search_strings", []),
            ("search_strings", [{"address": "0x140012340", "value": "OpinionOfFROM"}]),
            ("xrefs", []),
            ("xrefs", ["0x140012340", "ram:0x20"]),
        ):
            parameters = (
                {"pattern": "OpinionOfFROM", "mode": "literal", "case_sensitive": False}
                if operation == "search_strings" else {"address": "0x140012340"}
            )
            request = {**common, "operation": operation, "parameters": parameters}
            with self.subTest(operation=operation, value=value):
                self.assertTrue(
                    cache_query._validate_inventory_result(
                        _evidence(value, operation, parameters), request,
                        TARGET_SHA, MANIFEST_SHA, DATABASE_SHA,
                        {"ghidra_version": "12.1.4"}, operation,
                    )
                )
        search_parameters = {"pattern": "x", "mode": "literal", "case_sensitive": False}
        search_request = {**common, "operation": "search_strings", "parameters": search_parameters}
        self.assertFalse(
            cache_query._validate_inventory_result(
                _evidence([{"address": "140012340", "value": "x"}], "search_strings", search_parameters),
                search_request, TARGET_SHA, MANIFEST_SHA, DATABASE_SHA,
                {"ghidra_version": "12.1.4"}, "search_strings",
            )
        )
        valid_parameters = {"address": "0x140012340"}
        valid_request = {**common, "operation": "xrefs", "parameters": valid_parameters}
        self.assertFalse(
            cache_query._validate_inventory_result(
                _evidence({"value": ["0x140012340"]}, "xrefs", valid_parameters),
                valid_request, TARGET_SHA, MANIFEST_SHA, DATABASE_SHA,
                {"ghidra_version": "12.1.4"}, "xrefs",
            )
        )

    def test_inventory_readback_rejects_operation_or_parameter_mismatch(self):
        parameters = {"address": "0x140012340"}
        request = {
            "adapter_sha256": ADAPTER_SHA,
            "operation": "xrefs",
            "parameters": parameters,
        }
        value = ["0x140012340"]
        mismatched_operation = _evidence(value, "search_strings", {
            "pattern": "x", "mode": "literal", "case_sensitive": False,
        })
        self.assertFalse(
            cache_query._validate_inventory_result(
                mismatched_operation, request, TARGET_SHA, MANIFEST_SHA, DATABASE_SHA,
                {"ghidra_version": "12.1.4"}, "xrefs",
            )
        )
        mismatched_parameters = _evidence(value, "xrefs", {"address": "0x140012341"})
        self.assertFalse(
            cache_query._validate_inventory_result(
                mismatched_parameters, request, TARGET_SHA, MANIFEST_SHA, DATABASE_SHA,
                {"ghidra_version": "12.1.4"}, "xrefs",
            )
        )
        bool_coercion = _evidence([{"address": "0x140012340", "value": "x"}], "search_strings", {
            "pattern": "x", "mode": "literal", "case_sensitive": 0,
        })
        search_request = {
            "adapter_sha256": ADAPTER_SHA,
            "operation": "search_strings",
            "parameters": {"pattern": "x", "mode": "literal", "case_sensitive": False},
        }
        self.assertFalse(
            cache_query._validate_inventory_result(
                bool_coercion, search_request, TARGET_SHA, MANIFEST_SHA, DATABASE_SHA,
                {"ghidra_version": "12.1.4"}, "search_strings",
            )
        )

    def test_actual_public_xrefs_shape_is_accepted_and_tampering_is_rejected(self):
        fixture_path = (
            Path(__file__).resolve().parent
            / "fixtures/cached-native-xrefs-186.json"
        )
        evidence = json.loads(fixture_path.read_text(encoding="utf-8"))
        profile = evidence["analysis_profile"]["parameters"]
        request = {
            "operation": "xrefs",
            "parameters": {"address": "0x141ccf388"},
            "adapter_sha256": profile["local_adapter_sha256"],
        }
        metadata = {"ghidra_version": evidence["provider"]["version"]}

        # This is the direct-list shape emitted by the public CLI, rather than
        # the older {"value": [...]} retained-record shape.
        self.assertIsInstance(evidence["raw_result"], list)
        self.assertTrue(
            cache_query._validate_inventory_result(
                evidence, request, evidence["subject"]["digest"]["sha256"],
                profile["completed_manifest_sha256"],
                profile["completed_database_sha256"], metadata, "xrefs",
            )
        )

        cases = {
            "target": ("subject", "digest", "sha256", "e" * 64),
            "profile": ("analysis_profile", "parameters", "analyzer_preset", "wrong"),
            "parameters": ("parameters", "address", None, "0x141ccf389"),
            "invalid_address": ("raw_result", 0, None, "not-an-analysis-address"),
        }
        for name, (first, second, third, replacement) in cases.items():
            with self.subTest(tamper=name):
                invalid = json.loads(json.dumps(evidence))
                if name == "parameters":
                    invalid["parameters"][second] = replacement
                elif name == "invalid_address":
                    invalid[first][second] = replacement
                else:
                    invalid[first][second][third] = replacement
                self.assertFalse(
                    cache_query._validate_inventory_result(
                        invalid, request, evidence["subject"]["digest"]["sha256"],
                        profile["completed_manifest_sha256"],
                        profile["completed_database_sha256"], metadata, "xrefs",
                    )
                )

    def test_query_builds_search_and_xrefs_argv_without_starting_analysis(self):
        with tempfile.TemporaryDirectory(prefix="cache-query-operations-") as temp:
            base = Path(temp)
            cache = base / "cache"
            cache.mkdir()
            package = base / "rea-package"
            entry = package / "scripts" / "rea.mjs"
            entry.parent.mkdir(parents=True)
            entry.write_text("", encoding="utf-8")
            (package / "package.json").write_text(json.dumps({"version": "6.4.0"}), encoding="utf-8")
            config = {"command": "node", "args": [str(entry), "mcp"], "env": {}}
            metadata = {"status": "complete", "ghidra_version": "12.1.4"}

            for operation, extra, expected in (
                (
                    "search_strings",
                    {"pattern": "OpinionOfFROM", "mode": "literal", "case_sensitive": True},
                    ["search", str(base / "eu4.exe"), "--pattern=OpinionOfFROM", "--kind", "strings",
                     "--mode", "literal", "--case-sensitive"],
                ),
                (
                    "xrefs",
                    {"address": "0x140012340"},
                    ["xrefs", str(base / "eu4.exe"), "--address=0x140012340"],
                ),
            ):
                with self.subTest(operation=operation):
                    output = base / (operation + "-output")
                    observed = {}
                    args = SimpleNamespace(
                        operation=operation, **extra, java_heap="256M", binary=base / "eu4.exe",
                        cache=cache, config=base / "config.toml", output=output, timeout=30,
                    )

                    def fake_popen(command, **kwargs):
                        observed["command"] = command
                        observed["environment"] = kwargs["env"]
                        return _FakeProcess()

                    with mock.patch.object(cache_query, "_resolve_target",
                                           return_value=(args.binary, {}, TARGET_SHA)), \
                         mock.patch.object(cache_query, "_CacheLock", _Unlocked), \
                         mock.patch.object(cache_query, "_target_from_cache",
                                           return_value=(None, None, TARGET_SHA, metadata)), \
                         mock.patch.object(cache_query, "_complete_evidence", return_value=True), \
                         mock.patch.object(cache_query, "database_commitment", return_value=DATABASE_SHA), \
                         mock.patch.object(cache_query, "_hash_file", return_value=ADAPTER_SHA), \
                         mock.patch.object(cache_query, "_load_config", return_value=config), \
                         mock.patch.object(cache_query, "_owned_children", return_value=[]), \
                         mock.patch.object(cache_query, "_finalize_query_receipt",
                                           return_value=({}, 0)), \
                         mock.patch.object(cache_query.psutil, "Popen", side_effect=fake_popen):
                        self.assertEqual(cache_query.query(args), 0)

                    command = observed["command"]
                    self.assertEqual(command[4:4 + len(expected)], expected)
                    self.assertEqual(command[-4:], ["--provider", "ghidra", "--format", "json"])
                    self.assertEqual(observed["environment"]["GHIDRA_HEADLESS_MAXMEM"], "256M")
                    request = json.loads((output / "request.json").read_text(encoding="utf-8"))
                    self.assertEqual(request["operation"], operation)
                    self.assertEqual(request["parameters"], extra)
                    self.assertFalse(request["query_reanalysis"])

    def test_finalize_uses_operation_specific_readback_and_keeps_function_default(self):
        with tempfile.TemporaryDirectory(prefix="cache-query-finalize-") as temp:
            root = Path(temp)
            cache = root / "cache"
            cache.mkdir()
            for operation, value, parameters in (
                ("search_strings", [{"address": "0x140012340", "value": "x"}],
                 {"pattern": "x", "mode": "literal", "case_sensitive": False}),
                ("xrefs", ["0x140012340"], {"address": "0x140012340"}),
            ):
                with self.subTest(operation=operation):
                    output = root / operation
                    output.mkdir()
                    evidence_path = output / "evidence.json"
                    evidence_path.write_text(
                        json.dumps(_evidence(value, operation, parameters)), encoding="utf-8"
                    )
                    request = {
                        "target_sha256": TARGET_SHA, "operation": operation, "parameters": parameters,
                        "preset": cache_query.PRESET, "adapter_sha256": ADAPTER_SHA,
                        "completed_manifest_sha256": MANIFEST_SHA,
                        "completed_database_sha256": DATABASE_SHA, "query_reanalysis": False,
                    }
                    with mock.patch.object(cache_query, "database_commitment", return_value=DATABASE_SHA):
                        summary, exit_code = cache_query._finalize_query_receipt(
                            output=output, request=request, evidence_path=evidence_path, cache=cache,
                            digest=TARGET_SHA, manifest_sha=MANIFEST_SHA, database_sha=DATABASE_SHA,
                            metadata={"ghidra_version": "12.1.4"}, started=time.monotonic(),
                            provider_exit_code=0, supervisor_reason="completed", peaks={},
                        )
                    self.assertEqual(exit_code, 0)
                    self.assertEqual(summary["status"], "completed")


if __name__ == "__main__":
    unittest.main()
