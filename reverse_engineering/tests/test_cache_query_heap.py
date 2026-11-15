"""Heap option validation for persistent-cache queries and seeded fallback."""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest import mock

from reverse_engineering import cache_query, rea
from reverse_engineering.ghidra_cache import CacheError


class _FakeProcess:
    def poll(self):
        return 0

    def wait(self, timeout=None):
        return 0


class CacheQueryHeapTests(unittest.TestCase):
    def test_helper_defaults_old_namespace_and_accepts_only_supported_heaps(self):
        self.assertEqual(cache_query._validated_java_heap(SimpleNamespace()), "512M")
        for value in ("256M", "384M", "512M"):
            with self.subTest(value=value):
                self.assertEqual(
                    cache_query._validated_java_heap(SimpleNamespace(java_heap=value)), value
                )
        for value in ("128M", "512m", None, 512):
            with self.subTest(value=value):
                with self.assertRaises(CacheError):
                    cache_query._validated_java_heap(SimpleNamespace(java_heap=value))

    def test_query_rejects_invalid_heap_before_target_or_cache_reads(self):
        args = SimpleNamespace(java_heap="128M", binary=object(), cache=None)
        with mock.patch.object(cache_query, "_resolve_target", side_effect=AssertionError("target read")) as target, \
             mock.patch.object(cache_query, "latest_cache", side_effect=AssertionError("cache read")) as latest:
            with self.assertRaises(CacheError):
                cache_query.query(args)
        target.assert_not_called()
        latest.assert_not_called()

    def test_cli_rejects_nondefault_heap_in_seeded_modes_before_loading_inputs(self):
        with mock.patch.object(cache_query, "latest_cache", side_effect=AssertionError("cache read")) as latest, \
             mock.patch.object(cache_query, "query", side_effect=AssertionError("cache query")) as query, \
             mock.patch.object(rea, "load_catalog", side_effect=AssertionError("binary/catalog read")) as catalog:
            for mode in (("--seeded", "--java-heap", "256M"),
                         ("--seed", "second-node", "--java-heap", "384M")):
                with self.subTest(mode=mode), self.assertRaises(SystemExit) as error:
                    rea.main(["first-node", *mode])
                self.assertEqual(error.exception.code, 2)
        latest.assert_not_called()
        query.assert_not_called()
        catalog.assert_not_called()

    def test_cli_argparse_limits_heap_choices(self):
        with mock.patch.object(rea, "load_catalog", side_effect=AssertionError("catalog read")) as catalog:
            with self.assertRaises(SystemExit) as error:
                rea.main(["first-node", "--seeded", "--java-heap", "128M"])
        self.assertEqual(error.exception.code, 2)
        catalog.assert_not_called()

    def test_query_uses_one_heap_value_for_environment_and_request_metadata(self):
        # Use unittest's temporary directory management rather than an external process or Java.
        from tempfile import TemporaryDirectory

        with TemporaryDirectory(prefix="rea-cache-heap-") as temp:
            base = Path(temp)
            cache = base / "cache"
            cache.mkdir()
            output = base / "query-output"
            package = base / "rea-package"
            entry = package / "scripts" / "rea.mjs"
            entry.parent.mkdir(parents=True)
            entry.write_text("", encoding="utf-8")
            (package / "package.json").write_text(json.dumps({"version": "6.4.0"}), encoding="utf-8")

            observed = {}
            config = {"command": "node", "args": [str(entry), "mcp"], "env": {}}
            metadata = {"status": "complete", "ghidra_version": "12.1.4"}
            args = SimpleNamespace(
                java_heap="384M", binary=base / "eu4.exe", cache=cache, node="fixture-node",
                config=base / "config.toml", output=output, timeout=30,
            )

            def fake_popen(command, **kwargs):
                observed["environment"] = kwargs["env"]
                observed["command"] = command
                return _FakeProcess()

            class _Unlocked:
                def __init__(self, *_args, **_kwargs):
                    pass

                def __enter__(self):
                    return self

                def __exit__(self, *_args):
                    return False

            registry = {"binary": {"image_base": "0x140000000"},
                        "nodes": [{"id": "fixture-node", "address_role": "procedure_entry",
                                   "rva": "0x3f2e40"}]}
            with mock.patch.object(cache_query, "_resolve_target",
                                   return_value=(args.binary, registry, "a" * 64)), \
                 mock.patch.object(cache_query, "_CacheLock", _Unlocked), \
                 mock.patch.object(cache_query, "_target_from_cache",
                                   return_value=(None, None, "a" * 64, metadata)), \
                 mock.patch.object(cache_query, "_complete_evidence", return_value=True), \
                 mock.patch.object(cache_query, "database_commitment", return_value="b" * 64), \
                 mock.patch.object(cache_query, "_hash_file", return_value="c" * 64), \
                 mock.patch.object(cache_query, "_load_config", return_value=config), \
                 mock.patch.object(cache_query, "_owned_children", return_value=[]), \
                 mock.patch.object(cache_query, "_finalize_query_receipt",
                                   side_effect=lambda **kwargs: (observed.setdefault("request", kwargs["request"]) or {}, 0)), \
                 mock.patch.object(cache_query.psutil, "Popen", side_effect=fake_popen):
                result = cache_query.query(args)

            self.assertEqual(result, 0)
            request = json.loads((output / "request.json").read_text(encoding="utf-8"))
            self.assertEqual(request["java_heap"], "384M")
            self.assertEqual(observed["request"]["java_heap"], "384M")
            self.assertEqual(observed["environment"]["GHIDRA_HEADLESS_MAXMEM"], "384M")
            self.assertEqual(request["process_memory_limit_bytes"], 1024**3)
            self.assertEqual(observed["command"][0], "node")


if __name__ == "__main__":
    unittest.main()
