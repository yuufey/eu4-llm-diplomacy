"""Regression tests for cache-query receipts after bounded provider readback."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest import mock

from reverse_engineering import cache_query
from reverse_engineering.ghidra_cache import CacheError, MAX_JSON_BYTES


TARGET_SHA = "a" * 64
MANIFEST_SHA = "b" * 64
DATABASE_SHA = "c" * 64
ADAPTER_SHA = "d" * 64


def _request() -> dict:
    return {
        "target_sha256": TARGET_SHA,
        "node": "fixture-node",
        "procedure": "0x140000000",
        "preset": cache_query.PRESET,
        "adapter_sha256": ADAPTER_SHA,
        "completed_manifest_sha256": MANIFEST_SHA,
        "completed_database_sha256": DATABASE_SHA,
        "query_reanalysis": False,
    }


def _evidence() -> dict:
    return {
        "evidence_id": "ev_receipt_test",
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
        "raw_result": {
            "value": {
                "assembly": "bounded assembly",
                "pseudocode": "bounded pseudocode",
                "procedure": {"body": {"contains_entry": True}},
            }
        },
    }


class CacheQueryPostreadTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="cache-query-postread-")
        self.root = Path(self.temp.name)
        self.output = self.root / "query"
        self.output.mkdir()
        self.evidence = self.output / "evidence.json"
        self.cache = self.root / "cache"
        self.cache.mkdir()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def finalize(
        self,
        *,
        provider_exit_code: int | None = 0,
        evidence_path: Path | None = None,
        cleanup_errors: list[str] | None = None,
        peaks: dict | None = None,
        database_side_effect=DATABASE_SHA,
        supervisor_reason: str = "completed",
    ) -> tuple[dict, int]:
        if evidence_path is None:
            evidence_path = self.evidence
        if callable(database_side_effect):
            database_patch = mock.patch.object(
                cache_query, "database_commitment", side_effect=database_side_effect
            )
        else:
            database_patch = mock.patch.object(
                cache_query, "database_commitment", return_value=database_side_effect
            )
        with database_patch:
            return cache_query._finalize_query_receipt(
                output=self.output,
                request=_request(),
                evidence_path=evidence_path,
                cache=self.cache,
                digest=TARGET_SHA,
                manifest_sha=MANIFEST_SHA,
                database_sha=DATABASE_SHA,
                metadata={"ghidra_version": "12.1.4"},
                started=time.monotonic(),
                provider_exit_code=provider_exit_code,
                supervisor_reason=supervisor_reason,
                peaks=peaks or {},
                cleanup_errors=cleanup_errors,
            )

    def read_receipt(self) -> dict:
        with (self.output / "run.json").open(encoding="utf-8") as stream:
            return json.load(stream)

    def test_oversize_sparse_evidence_keeps_provider_exit_and_receipt(self) -> None:
        with self.evidence.open("wb") as stream:
            stream.write(b"{")
            stream.seek(MAX_JSON_BYTES + 1)
            stream.write(b"\n")
        before_size = self.evidence.stat().st_size
        before_edges = (self.evidence.read_bytes()[:1], self.evidence.read_bytes()[-1:])

        with self.assertRaisesRegex(CacheError, "超过"):
            cache_query._read_json(self.evidence)
        _, exit_code = self.finalize()
        receipt = self.read_receipt()

        self.assertEqual(exit_code, 1)
        self.assertEqual(receipt["provider_exit_code"], 0)
        self.assertEqual(receipt["exit_code"], 1)
        self.assertEqual(receipt["wrapper_exit_code"], 1)
        self.assertEqual(receipt["status"], "postread_guard_error")
        self.assertEqual(receipt["reason"], "postread_guard_rejected")
        self.assertEqual(receipt["postread"]["status"], "guard_rejected")
        self.assertIsNone(receipt["evidence_id"])
        self.assertTrue(receipt["database_unchanged"])
        self.assertTrue(receipt["cleanup"]["closed_process_receipt"])
        self.assertEqual(self.evidence.stat().st_size, before_size)
        after_edges = (self.evidence.read_bytes()[:1], self.evidence.read_bytes()[-1:])
        self.assertEqual(after_edges, before_edges)

    def test_invalid_json_keeps_raw_bytes_and_writes_postread_error(self) -> None:
        raw = b'{"unterminated":'
        self.evidence.write_bytes(raw)
        before_sha = hashlib.sha256(raw).hexdigest()

        _, exit_code = self.finalize()
        receipt = self.read_receipt()

        self.assertEqual(exit_code, 1)
        self.assertEqual(receipt["provider_exit_code"], 0)
        self.assertEqual(receipt["status"], "postread_error")
        self.assertEqual(receipt["reason"], "postread_error")
        self.assertEqual(receipt["postread"]["exit_code"], 1)
        self.assertIsNone(receipt["evidence_id"])
        self.assertTrue(receipt["database_unchanged"])
        self.assertEqual(hashlib.sha256(self.evidence.read_bytes()).hexdigest(), before_sha)

    def test_deep_json_within_bound_keeps_raw_bytes_and_writes_receipt(self) -> None:
        raw = b"[" * 1500 + b"0" + b"]" * 1500
        self.evidence.write_bytes(raw)
        before_sha = hashlib.sha256(raw).hexdigest()

        self.assertLess(len(raw), MAX_JSON_BYTES)
        with self.assertRaises(RecursionError):
            cache_query._read_json(self.evidence)
        _, exit_code = self.finalize()
        receipt = self.read_receipt()

        self.assertEqual(exit_code, 1)
        self.assertEqual(receipt["provider_exit_code"], 0)
        self.assertEqual(receipt["status"], "postread_error")
        self.assertEqual(receipt["reason"], "postread_error")
        self.assertEqual(receipt["postread"]["status"], "error")
        self.assertIsNone(receipt["evidence_id"])
        self.assertTrue(receipt["database_unchanged"])
        self.assertEqual(hashlib.sha256(self.evidence.read_bytes()).hexdigest(), before_sha)

    def test_valid_small_success_preserves_success_shape_and_id(self) -> None:
        self.evidence.write_text(json.dumps(_evidence()), encoding="utf-8")

        _, exit_code = self.finalize()
        receipt = self.read_receipt()

        self.assertEqual(exit_code, 0)
        self.assertEqual(receipt["provider_exit_code"], 0)
        self.assertEqual(receipt["exit_code"], 0)
        self.assertEqual(receipt["status"], "completed")
        self.assertEqual(receipt["reason"], "completed")
        self.assertEqual(receipt["postread"]["status"], "read")
        self.assertEqual(receipt["evidence_id"], "ev_receipt_test")
        self.assertTrue(receipt["database_unchanged"])

    def test_database_change_is_false_after_actual_rehash(self) -> None:
        self.evidence.write_text(json.dumps(_evidence()), encoding="utf-8")

        _, exit_code = self.finalize(
            database_side_effect="e" * 64,
            supervisor_reason="memory_limit",
        )
        receipt = self.read_receipt()

        self.assertEqual(exit_code, 1)
        self.assertEqual(receipt["provider_exit_code"], 0)
        self.assertEqual(receipt["reason"], "read_only_database_changed")
        self.assertEqual(receipt["supervisor_reason"], "memory_limit")
        self.assertEqual(receipt["database"]["status"], "changed")
        self.assertFalse(receipt["database_unchanged"])
        self.assertEqual(receipt["database"]["actual_sha256"], "e" * 64)
        self.assertEqual(receipt["evidence_id"], "ev_receipt_test")

    def test_database_check_error_is_unknown_not_true(self) -> None:
        self.evidence.write_text(json.dumps(_evidence()), encoding="utf-8")

        def fail_database(_cache: Path) -> str:
            raise CacheError("simulated commitment failure")

        _, exit_code = self.finalize(database_side_effect=fail_database)
        receipt = self.read_receipt()

        self.assertEqual(exit_code, 1)
        self.assertEqual(receipt["reason"], "database_commitment_check_error")
        self.assertEqual(receipt["database"]["status"], "error")
        self.assertIsNone(receipt["database_unchanged"])
        self.assertIsNone(receipt["database"]["actual_sha256"])

    def test_cleanup_error_keeps_receipt_and_marks_not_closed(self) -> None:
        self.evidence.write_text(json.dumps(_evidence()), encoding="utf-8")

        _, exit_code = self.finalize(
            cleanup_errors=["AccessDenied: simulated cleanup failure"],
            peaks={17: {"pid": 17, "still_running_same_process": False}},
        )
        receipt = self.read_receipt()

        self.assertEqual(exit_code, 1)
        self.assertEqual(receipt["provider_exit_code"], 0)
        self.assertEqual(receipt["reason"], "process_cleanup_incomplete")
        self.assertEqual(receipt["cleanup"]["status"], "error")
        self.assertFalse(receipt["cleanup"]["closed_process_receipt"])
        self.assertEqual(receipt["cleanup"]["errors"], [
            "AccessDenied: simulated cleanup failure"
        ])
        self.assertTrue(receipt["database_unchanged"])

    def test_memory_limit_after_valid_read_forces_wrapper_failure(self) -> None:
        self.evidence.write_text(json.dumps(_evidence()), encoding="utf-8")

        _, exit_code = self.finalize(supervisor_reason="memory_limit")
        receipt = self.read_receipt()

        self.assertEqual(exit_code, 1)
        self.assertEqual(receipt["provider_exit_code"], 0)
        self.assertEqual(receipt["exit_code"], 1)
        self.assertEqual(receipt["status"], "failed")
        self.assertEqual(receipt["reason"], "memory_limit")
        self.assertEqual(receipt["supervisor_reason"], "memory_limit")
        self.assertEqual(receipt["postread"]["status"], "read")
        self.assertEqual(receipt["evidence_id"], "ev_receipt_test")
        self.assertTrue(receipt["database_unchanged"])

    def test_supervisor_deadline_after_valid_read_forces_wrapper_failure(self) -> None:
        self.evidence.write_text(json.dumps(_evidence()), encoding="utf-8")

        _, exit_code = self.finalize(supervisor_reason="supervisor_deadline")
        receipt = self.read_receipt()

        self.assertEqual(exit_code, 1)
        self.assertEqual(receipt["provider_exit_code"], 0)
        self.assertEqual(receipt["exit_code"], 1)
        self.assertEqual(receipt["status"], "failed")
        self.assertEqual(receipt["reason"], "supervisor_deadline")
        self.assertEqual(receipt["supervisor_reason"], "supervisor_deadline")
        self.assertEqual(receipt["postread"]["status"], "read")
        self.assertEqual(receipt["evidence_id"], "ev_receipt_test")
        self.assertTrue(receipt["database_unchanged"])

    def test_provider_failure_remains_distinct_from_postread_wrapper_result(self) -> None:
        self.evidence.write_text(json.dumps(_evidence()), encoding="utf-8")

        _, exit_code = self.finalize(provider_exit_code=7)
        receipt = self.read_receipt()

        self.assertEqual(exit_code, 7)
        self.assertEqual(receipt["provider_exit_code"], 7)
        self.assertEqual(receipt["exit_code"], 7)
        self.assertEqual(receipt["reason"], "provider_failed")
        self.assertEqual(receipt["postread"]["status"], "read_not_validated_provider_failed")
        self.assertTrue(receipt["database_unchanged"])


if __name__ == "__main__":
    unittest.main()
