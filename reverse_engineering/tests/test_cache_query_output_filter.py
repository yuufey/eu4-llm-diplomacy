"""Offline checks for the opt-in public-CLI function output filter."""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest import mock

from reverse_engineering import cache_query
from reverse_engineering.ghidra_cache import CacheError


TARGET_SHA = "a" * 64
MANIFEST_SHA = "b" * 64
DATABASE_SHA = "c" * 64
ADAPTER_SHA = "d" * 64
_MISSING = object()


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


class CacheQueryOutputFilterTests(unittest.TestCase):
    def _run_function_query(self, filter_value=_MISSING):
        with tempfile.TemporaryDirectory(prefix="cache-query-output-filter-") as temp:
            root = Path(temp)
            cache = root / "cache"
            cache.mkdir()
            package = root / "rea-package"
            entry = package / "scripts" / "rea.mjs"
            entry.parent.mkdir(parents=True)
            entry.write_text("", encoding="utf-8")
            (package / "package.json").write_text(
                json.dumps({"version": "6.4.0"}), encoding="utf-8"
            )
            binary = root / "eu4.exe"
            config = {"command": "node.exe", "args": [str(entry), "mcp"], "env": {}}
            metadata = {"status": "complete", "ghidra_version": "12.1.4"}
            output = root / "output"
            args = SimpleNamespace(
                operation="function", java_heap="256M", binary=binary, cache=cache,
                node="0x383890", config=root / "config.toml", output=output, timeout=30,
            )
            if filter_value is not _MISSING:
                args.filtered_function_output = filter_value
            registry = {"binary": {"image_base": "0x140000000"}, "nodes": []}
            observed = {}

            def fake_popen(command, **kwargs):
                observed["command"] = command
                observed["environment"] = kwargs["env"]
                return _FakeProcess()

            with mock.patch.object(cache_query, "_resolve_target",
                                   return_value=(binary, registry, TARGET_SHA)), \
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

            request = json.loads((output / "request.json").read_text(encoding="utf-8"))
            return observed["command"], request

    def test_filtered_function_query_uses_public_filter_and_records_contract(self):
        command, request = self._run_function_query(True)

        self.assertEqual(command[4], "function")
        self.assertEqual(Path(command[5]).name, "eu4.exe")
        self.assertEqual(command[6], "0x140383890")
        self.assertEqual(command[-6:-4], ["--provider", "ghidra"])
        self.assertEqual(command[-4:-2], ["--format", "json"])
        self.assertEqual(command[-2], "--filter-output")
        self.assertEqual(command[-1], cache_query.FUNCTION_OUTPUT_FILTER_ARGUMENT)
        self.assertEqual(request["procedure"], "0x140383890")
        self.assertIs(request["filtered_function_output"], True)
        filter_record = request["function_output_filter"]
        self.assertEqual(filter_record["paths"], list(cache_query.FUNCTION_OUTPUT_FILTER_PATHS))
        self.assertIs(filter_record["high_pcode_retained"], False)
        self.assertIn("raw_result.value.native_value_flow", filter_record["omitted_high_volume_paths"])
        self.assertIn("raw_result.value.procedure", filter_record["paths"])
        self.assertIn("raw_result.value.pseudocode", filter_record["paths"])
        self.assertIn("raw_result.value.assembly", filter_record["paths"])
        self.assertIn("raw_result.value.limitations", filter_record["paths"])

    def test_filter_retains_provider_failure_diagnostics(self):
        command, request = self._run_function_query(True)
        paths = set(command[command.index('--filter-output') + 1].split(','))
        failure = {
            'error': 'Analysis failed', 'code': 'execution_failure', 'category': 'execution_failure',
            'message': 'Target snapshot admission failed', 'retryable': False,
            'remediation': {'action': 'Inspect process permissions'},
            'details': {'diagnostics': {'failure_cause': {'code': 'EACCES', 'message': 'Win32 5'}}},
        }
        self.assertEqual({key: value for key, value in failure.items() if key in paths}, failure)
        self.assertTrue(set(failure) <= set(request['function_output_filter']['paths']))

    def test_missing_filter_keeps_default_function_argv_and_request(self):
        command, request = self._run_function_query()

        self.assertEqual(command[-4:], ["--provider", "ghidra", "--format", "json"])
        self.assertNotIn("--filter-output", command)
        self.assertNotIn("filtered_function_output", request)
        self.assertNotIn("function_output_filter", request)

    def test_filter_rejects_nonboolean_and_nonfunction_before_target_or_cache(self):
        cases = (
            SimpleNamespace(operation="function", filtered_function_output=1, binary=object()),
            SimpleNamespace(operation="xrefs", address="0x140012340",
                            filtered_function_output=True, binary=object()),
            SimpleNamespace(operation="search_strings", pattern="opinion", mode="literal",
                            case_sensitive=False, filtered_function_output=True, binary=object()),
        )
        for args in cases:
            with self.subTest(operation=args.operation):
                with mock.patch.object(cache_query, "_resolve_target",
                                       side_effect=AssertionError("target/cache touched")) as resolver:
                    with self.assertRaises(CacheError):
                        cache_query.query(args)
                resolver.assert_not_called()

    def test_function_readback_still_requires_pseudocode_assembly_and_entry(self):
        request = {"adapter_sha256": ADAPTER_SHA}
        metadata = {"ghidra_version": "12.1.4"}
        evidence = {
            "analysis_profile": {"parameters": {
                "analyzer_preset": cache_query.PRESET,
                "local_adapter_sha256": ADAPTER_SHA,
                "completed_manifest_sha256": MANIFEST_SHA,
                "completed_database_sha256": DATABASE_SHA,
            }},
            "subject": {"digest": {"sha256": TARGET_SHA}},
            "provider": {"version": "12.1.4"},
            "raw_result": {"value": {
                "procedure": {"body": {"contains_entry": True}},
                "pseudocode": "int f(void) { return 1; }",
                "assembly": [{"address": "0x140001000", "mnemonic": "ret"}],
            }},
        }
        self.assertTrue(cache_query._validate_cached_result(
            evidence, request, TARGET_SHA, MANIFEST_SHA, DATABASE_SHA, metadata
        ))
        for required in ("pseudocode", "assembly"):
            with self.subTest(missing=required):
                invalid = json.loads(json.dumps(evidence))
                del invalid["raw_result"]["value"][required]
                self.assertFalse(cache_query._validate_cached_result(
                    invalid, request, TARGET_SHA, MANIFEST_SHA, DATABASE_SHA, metadata
                ))
        invalid = json.loads(json.dumps(evidence))
        del invalid["raw_result"]["value"]["procedure"]["body"]["contains_entry"]
        self.assertFalse(cache_query._validate_cached_result(
            invalid, request, TARGET_SHA, MANIFEST_SHA, DATABASE_SHA, metadata
        ))


if __name__ == "__main__":
    unittest.main()
