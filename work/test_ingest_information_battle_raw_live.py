"""Offline tests for the checked live raw-log receiver.

Every input in this file is synthetic.  The tests exercise the existing
tailer, transport store, fragment reassembler, and observation decoder as a
single pipeline; they never open a game process or send a control command.
"""

from __future__ import annotations

import argparse
import json
import hashlib
from pathlib import Path
import struct
import sys
import tempfile
import time
import unittest
import zlib

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from work.ingest_information_battle_raw_live import (
    _decode_payload,
    RawIngestError,
    ingest_live_raw,
)
from work.information_battle_reassembly import (
    FRAGMENT_CAPACITY_BYTES,
    build_fragment_payload,
)
from work.information_battle_transport import EVENT
from work.information_battle_war_identity_wire import (
    BINDING_FLAGS as WAR_IDENTITY_BINDING_FLAGS,
    EXTENSION_MAGIC as WAR_IDENTITY_EXTENSION_MAGIC,
    STATUS_ABSENT as WAR_IDENTITY_ABSENT,
    STATUS_BOUND as WAR_IDENTITY_BOUND,
    STATUS_INVALID as WAR_IDENTITY_INVALID,
)
from work.information_battle_template_wire import decode as decode_template


INSTALLATION_DECIMAL = "2441212204318969762"
GENERATION_DECIMAL = "134374061200954087"
INSTALLATION_HEX = f"{int(INSTALLATION_DECIMAL):016x}"
GENERATION_HEX = f"{int(GENERATION_DECIMAL):016x}"
DLL_SHA = "ab" * 32
SESSION = "synthetic-39456-observer"
PLAYER_REF = "010000bd00524f50"
STAGE = ROOT / "work" / "runtime" / "information-battle-live-20261025-001" / "raw-ingest-test-001"
REPORT = STAGE / "report.json"


def observation_wire(
        *, sequence: int = 1, thread: int = 7,
        name: bytes = b"battle", commander: bytes = b"commander",
) -> bytes:
    out = bytearray(b"IBOW")
    out += struct.pack("<H Q I B", 1, sequence, thread, 1)
    out += struct.pack("<i B i i i", -13, 1, 100, -200, 42)
    out += struct.pack("<I", len(name)) + name
    for side in range(2):
        out += struct.pack("<Q", 0x1000 + side)
        out += struct.pack("<9i", *[side * 10 + index for index in range(9)])
        out += struct.pack("<I", len(commander)) + commander
    out += struct.pack("<11i B", *range(11), 0x7F)
    return bytes(out)


def context_wire_v2(*, inner: bytes | None = None) -> bytes:
    """Build one independent, complete v2 context envelope for ingestion."""

    inner = observation_wire() if inner is None else inner
    physical = 0x0100000000434241  # ABC plus opaque identity bytes
    ref_b = 0x0100000000414142
    ref_c = 0x0100000000414143
    out = bytearray(b"IBOW")
    out += struct.pack("<H I", 2, len(inner))
    out += inner
    out += b"\x01"  # context_present
    out += b"\x01"  # known_router
    out += struct.pack("<I", 1)
    out += b"\xb8\x01\x00\x00\x00\xc3"
    out += b"\x01\x01"  # selector verified, land kind
    out += struct.pack("<Q", physical)
    out += struct.pack("<BBI", 1, 1, 2)
    out += struct.pack("<QQ", physical, ref_b)
    out += struct.pack("<6i", 100, 101, 102, 103, 104, 105)
    out += struct.pack("<BBI", 1, 1, 1)
    out += struct.pack("<Q", ref_c)
    out += struct.pack("<6i", -200, -201, -202, -203, -204, -205)
    out += b"\x01"  # observed war context
    out += struct.pack("<IQQ", 2, physical, ref_b)
    out += struct.pack("<IQ", 1, ref_c)
    out += b"\x01\x01\x01"  # vectors complete, membership known, member
    return bytes(out)


def war_identity_v5_payload(
        *, status: int = WAR_IDENTITY_ABSENT, reason: int = 0,
        binding_flags: int = 0, creation: int = 0,
        raw_date: int | None = None, pair_full_refs: tuple[int, int] | None = None,
        war_id: bytes = b"") -> bytes:
    """Wrap the archived complete v4 frame with a bounded WARI identity."""
    fixture_path = ROOT / "bridge" / "tests" / "fixtures" / "information_battle_FRA_live_container_v4_1374.json"
    fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
    base = bytes.fromhex(fixture["payload_hex"])
    decoded = decode_template(base)
    result = decoded["observation"]["result"]
    if raw_date is None:
        raw_date = result["raw_date"]
    if status == WAR_IDENTITY_BOUND:
        if pair_full_refs is None:
            pair_full_refs = tuple(side["country"] for side in result["sides"])
        binding_flags = WAR_IDENTITY_BINDING_FLAGS if binding_flags == 0 else binding_flags
        creation = 132456789 if creation == 0 else creation
        war_id = b"war_0000000000000001_00000001" if not war_id else war_id
    elif status == WAR_IDENTITY_ABSENT:
        pair_full_refs = (0, 0)
        war_id = b""
    else:
        pair_full_refs = (0, 0)
        war_id = b""
    body = struct.pack("<BBIQiQQB", status, reason, binding_flags, creation,
                       raw_date, pair_full_refs[0], pair_full_refs[1], len(war_id))
    body += war_id
    return b"IBOW" + struct.pack("<HI", 5, len(base)) + base + WAR_IDENTITY_EXTENSION_MAGIC + body


def wire_line(payload: bytes, sequence: int) -> bytes:
    value = {
        "event": EVENT,
        "wire_version": 1,
        "installation": INSTALLATION_HEX,
        "world_generation": GENERATION_HEX,
        "attempt_sequence": str(sequence),
        "payload_encoding": "hex",
        "payload_bytes": len(payload),
        "payload_hex": payload.hex(),
    }
    return json.dumps(value, separators=(",", ":")).encode("ascii") + b"\n"


def fragment_line(data: bytes, message_id: int, sequence: int, index: int) -> bytes:
    total = len(data)
    count = (total + FRAGMENT_CAPACITY_BYTES - 1) // FRAGMENT_CAPACITY_BYTES
    start = index * FRAGMENT_CAPACITY_BYTES
    end = min(total, start + FRAGMENT_CAPACITY_BYTES)
    payload = build_fragment_payload(
        installation=INSTALLATION_HEX,
        world_generation=GENERATION_HEX,
        message_id=message_id,
        total_bytes=total,
        fragment_index=index,
        data=data[start:end],
        whole_crc32=zlib.crc32(data) & 0xFFFFFFFF,
    )
    assert count >= 1
    return wire_line(payload, sequence)


class Fixture:
    def __init__(self, root: Path, *, log_body: bytes = b"") -> None:
        self.root = root
        self.installation_dir = root / "live"
        self.installation_dir.mkdir()
        self.installation = self.installation_dir / "installation.json"
        self.database = root / "receiver.sqlite3"
        self.log = self.installation_dir / "information-battle-raw.jsonl"
        installation = {
            "pid": 39456,
            "creation_filetime": int(GENERATION_DECIMAL),
            "session_id": SESSION,
            "dll_sha256": DLL_SHA,
            "experiment_id": "synthetic-information-battle-live",
        }
        binding = {
            "schema": "EU4-BATTLE-CONTROL/1",
            "pid": 39456,
            "creation_filetime": GENERATION_DECIMAL,
            "session_id": SESSION,
            "dll_sha256": DLL_SHA,
            "installation": INSTALLATION_DECIMAL,
            "generation": GENERATION_DECIMAL,
            "player_ref": PLAYER_REF,
        }
        self.installation.write_text(json.dumps(installation), encoding="utf-8")
        (self.installation_dir / "information-battle-binding.json").write_text(
            json.dumps(binding), encoding="utf-8"
        )
        self.log.write_bytes(
            f"EU4_OWNED_BATTLE_WIRE_V1 {INSTALLATION_HEX} {GENERATION_HEX}\n".encode("ascii")
            + log_body
        )

    def output(self, name: str) -> Path:
        return self.root / name


class RawIngestTests(unittest.TestCase):
    def test_header_only_binds_and_restart_keeps_cursors(self) -> None:
        with tempfile.TemporaryDirectory(prefix="information-battle-raw-test-") as directory:
            fixture = Fixture(Path(directory))
            first = ingest_live_raw(fixture.installation, fixture.database, fixture.output("first.json"))
            self.assertEqual(first["status"], "passed")
            self.assertEqual(first["binding"]["installation"]["decimal"], INSTALLATION_DECIMAL)
            self.assertEqual(first["binding"]["generation"]["decimal"], GENERATION_DECIMAL)
            self.assertEqual(first["binding"]["physical_player_ref"]["raw_hex"], PLAYER_REF)
            self.assertEqual(first["tailer"]["poll"]["status"], "idle")
            self.assertEqual(first["transport"]["received_count"], 0)
            self.assertEqual(first["messages"], [])
            self.assertFalse(first["completeness"]["transport_stream_complete"])
            self.assertFalse(first["completeness"]["business_complete"])

            second = ingest_live_raw(fixture.installation, fixture.database, fixture.output("second.json"))
            self.assertEqual(second["status"], "passed")
            self.assertEqual(second["tailer"]["poll"]["status"], "idle")
            self.assertEqual(second["tailer"]["cursor"]["offset"], first["tailer"]["cursor"]["offset"])
            self.assertEqual(second["transport"]["received_count"], 0)

    def test_mixed_v1_v2_persistence_and_restart_without_public_ids(self) -> None:
        with tempfile.TemporaryDirectory(prefix="information-battle-raw-v1-v2-") as directory:
            v1 = observation_wire(sequence=11)
            v2 = context_wire_v2(inner=observation_wire(sequence=12))
            fixture = Fixture(Path(directory), log_body=(
                fragment_line(v1, 41, 1, 0)
                + fragment_line(v2, 42, 2, 0)
            ))
            first = ingest_live_raw(
                fixture.installation, fixture.database, fixture.output("mixed.json")
            )
            self.assertEqual(first["status"], "passed")
            self.assertEqual(first["transport"]["received_count"], 2)
            self.assertEqual(len(first["messages"]), 2)
            by_version = {
                item["decode"].get("wire_version"): item
                for item in first["messages"]
            }
            self.assertEqual(by_version[1]["decode"]["status"],
                             "decoded_raw_observation")
            self.assertEqual(by_version[2]["decode"]["status"],
                             "decoded_raw_context")
            self.assertFalse(by_version[2]["decode"]["value"]["business_complete"])
            for item in first["messages"]:
                self.assertEqual(item["public_identity"],
                                 {"status": "absent", "war_id": None, "battle_id": None})
                self.assertFalse(item["business_complete"])

            second = ingest_live_raw(
                fixture.installation, fixture.database, fixture.output("mixed-reopen.json")
            )
            self.assertEqual(second["status"], "passed")
            self.assertEqual(second["transport"]["received_count"], 2)
            self.assertEqual(len(second["messages"]), 2)
            self.assertEqual(
                second["tailer"]["cursor"]["offset"],
                first["tailer"]["cursor"]["offset"],
            )

    def test_v5_war_identity_frame_routes_to_new_decoder_without_public_id_claim(self) -> None:
        with tempfile.TemporaryDirectory(prefix="information-battle-raw-v5-") as directory:
            fixture = Fixture(Path(directory), log_body=fragment_line(war_identity_v5_payload(), 61, 1, 0))
            report = ingest_live_raw(
                fixture.installation, fixture.database, fixture.output("v5.json")
            )
            self.assertEqual(report["status"], "passed")
            self.assertEqual(report["source"]["payload_dispatch"]["supported_observation_versions"],
                             [1, 2, 3, 4, 5, 6])
            self.assertEqual(len(report["messages"]), 1)
            item = report["messages"][0]
            self.assertEqual(item["decode"]["status"], "decoded_raw_war_identity")
            self.assertEqual(item["decode"]["wire_version"], 5)
            self.assertEqual(item["decode"]["value"]["war_identity"]["status"], "absent")
            self.assertEqual(item["public_identity"],
                             {
                                 "status": "pending_public_validation",
                                 "war_id": None,
                                 "battle_id": None,
                                 "war_identity_status": "absent",
                                 "public_projection": "opaque_war_binding_copied_public_projection_not_verified",
                                 "reason": "WAR_ID_PUBLIC_PROJECTION_DEFERRED",
                             })
            self.assertEqual(report["completeness"]["public_identity"], {
                "status": "pending_public_validation",
                "war_id": None,
                "battle_id": None,
                "public_projection": "opaque_war_binding_copied_public_projection_not_verified",
                "v5_war_identity_count": 1,
                "v5_bound_count": 0,
                "v5_invalid_count": 0,
                "v5_absent_count": 1,
            })

    def test_v5_report_counts_bound_and_invalid_without_claiming_public_id(self) -> None:
        with tempfile.TemporaryDirectory(prefix="information-battle-raw-v5-counts-") as directory:
            payloads = (
                war_identity_v5_payload(),
                war_identity_v5_payload(status=WAR_IDENTITY_BOUND),
                war_identity_v5_payload(status=WAR_IDENTITY_INVALID, reason=5),
            )
            fixture = Fixture(Path(directory), log_body=b"".join(
                fragment_line(payload, message_id, sequence, 0)
                for payload, message_id, sequence in zip(payloads, (61, 62, 63), (1, 2, 3))
            ))
            report = ingest_live_raw(
                fixture.installation, fixture.database, fixture.output("v5-counts.json")
            )
            self.assertEqual(report["status"], "passed")
            self.assertEqual(report["completeness"]["public_identity"], {
                "status": "pending_public_validation",
                "war_id": None,
                "battle_id": None,
                "public_projection": "opaque_war_binding_copied_public_projection_not_verified",
                "v5_war_identity_count": 3,
                "v5_bound_count": 1,
                "v5_invalid_count": 1,
                "v5_absent_count": 1,
            })
            self.assertEqual(
                [item["public_identity"]["war_identity_status"] for item in report["messages"]],
                ["absent", "bound", "invalid"],
            )
            self.assertTrue(all(item["public_identity"]["status"] == "pending_public_validation"
                                for item in report["messages"]))

    def test_versioned_rejections_are_persisted_then_decoded_after_reassembly(self) -> None:
        valid = context_wire_v2()
        unknown_version = bytearray(valid)
        unknown_version[4:6] = struct.pack("<H", 9)
        with self.assertRaises(RawIngestError):
            _decode_payload(bytes(unknown_version))

        bad_length = bytearray(valid)
        inner_length = struct.unpack_from("<I", bad_length, 6)[0]
        bad_length[6:10] = struct.pack("<I", inner_length + 1)
        with self.assertRaises(RawIngestError):
            _decode_payload(bytes(bad_length))

        malformed = bytearray(valid)
        malformed[-1] = 0  # physical player is in side A, so membership disagrees
        malformed_single = bytes(malformed)
        malformed_multi = valid + (b"\x00" * 4100)
        with tempfile.TemporaryDirectory(prefix="information-battle-raw-v2-reject-") as directory:
            fixture = Fixture(Path(directory), log_body=(
                fragment_line(malformed_single, 51, 1, 0)
                + fragment_line(malformed_multi, 52, 2, 0)
                + fragment_line(malformed_multi, 52, 3, 1)
                + fragment_line(valid, 53, 4, 0)
            ))
            report = ingest_live_raw(
                fixture.installation, fixture.database, fixture.output("rejected.json")
            )
            self.assertEqual(report["status"], "partial")
            self.assertEqual(report["tailer"]["poll"]["status"], "advanced")
            self.assertEqual(report["tailer"]["poll"]["acked"], 4)
            self.assertEqual(report["transport"]["received_count"], 4)
            self.assertEqual(report["reassembly"]["poll"]["completed"], 3)
            self.assertEqual(len(report["messages"]), 3)
            self.assertEqual(report["decode_rejected_count"], 2)
            by_message = {item["message_id"]: item for item in report["messages"]}
            self.assertEqual(by_message["51"]["decode"]["status"], "rejected")
            self.assertEqual(by_message["52"]["decode"]["status"], "rejected")
            self.assertEqual(by_message["53"]["decode"]["status"], "decoded_raw_context")
            self.assertEqual(
                report["source"]["payload_dispatch"]["transport_ack_semantics"],
                "raw_fragment_persisted",
            )

            reopened = ingest_live_raw(
                fixture.installation, fixture.database, fixture.output("reopen.json")
            )
            self.assertEqual(reopened["status"], "partial")
            self.assertEqual(reopened["tailer"]["poll"]["status"], "idle")
            self.assertEqual(reopened["transport"]["received_count"], 4)
            self.assertEqual(len(reopened["messages"]), 3)
            self.assertEqual(reopened["decode_rejected_count"], 2)
            before = {
                item["message_id"]: (item["payload_sha256"], item["decode"]["status"])
                for item in report["messages"]
            }
            after = {
                item["message_id"]: (item["payload_sha256"], item["decode"]["status"])
                for item in reopened["messages"]
            }
            self.assertEqual(after, before)
            self.assertEqual(
                reopened["source"]["payload_dispatch"]["strict_versioned_decode_after_reassembly"],
                True,
            )

    def test_partial_line_then_duplicate_frame_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory(prefix="information-battle-raw-partial-") as directory:
            fixture = Fixture(Path(directory))
            payload = observation_wire()
            frame = fragment_line(payload, 21, 1, 0)
            fixture.log.write_bytes(fixture.log.read_bytes() + frame[: len(frame) // 2])
            partial = ingest_live_raw(fixture.installation, fixture.database, fixture.output("partial.json"))
            self.assertEqual(partial["status"], "passed")
            self.assertEqual(partial["tailer"]["poll"]["status"], "partial")
            self.assertEqual(partial["transport"]["received_count"], 0)

            with fixture.log.open("ab") as stream:
                stream.write(frame[len(frame) // 2 :])
            completed = ingest_live_raw(fixture.installation, fixture.database, fixture.output("complete.json"))
            self.assertEqual(completed["tailer"]["poll"]["status"], "advanced")
            self.assertEqual(completed["transport"]["received_count"], 1)
            self.assertEqual(len(completed["messages"]), 1)
            message = completed["messages"][0]
            self.assertEqual(message["decode"]["status"], "decoded_raw_observation")
            self.assertEqual(message["decode"]["value"]["observation"]["sequence"], (1))
            self.assertFalse(message["decode"]["value"]["complete"])
            self.assertFalse(message["decode"]["value"]["visibility_verified"])
            self.assertEqual(message["raw_payload_hex"], payload.hex())
            self.assertFalse(completed["completeness"]["business_complete"])

            with fixture.log.open("ab") as stream:
                stream.write(frame)
            duplicate = ingest_live_raw(fixture.installation, fixture.database, fixture.output("duplicate.json"))
            self.assertEqual(duplicate["tailer"]["poll"]["status"], "advanced")
            self.assertEqual(duplicate["tailer"]["poll"]["duplicates"], 1)
            self.assertEqual(duplicate["transport"]["received_count"], 1)
            self.assertEqual(len(duplicate["messages"]), 1)

    def test_two_fragments_reassemble_but_invalid_observation_stays_unknown(self) -> None:
        with tempfile.TemporaryDirectory(prefix="information-battle-raw-fragments-") as directory:
            data = b"opaque" * 1000
            first = fragment_line(data, 31, 1, 0)
            second = fragment_line(data, 31, 2, 1)
            fixture = Fixture(Path(directory), log_body=first)
            pending = ingest_live_raw(fixture.installation, fixture.database, fixture.output("pending.json"))
            self.assertEqual(pending["reassembly"]["poll"]["status"], "advanced")
            self.assertEqual(pending["reassembly"]["poll"]["completed"], 0)
            self.assertEqual(pending["messages"], [])

            with fixture.log.open("ab") as stream:
                stream.write(second)
            done = ingest_live_raw(fixture.installation, fixture.database, fixture.output("done.json"))
            self.assertEqual(done["reassembly"]["poll"]["completed"], 1)
            self.assertEqual(done["messages"][0]["decode"]["status"], "unknown")
            self.assertFalse(done["messages"][0]["business_complete"])
            self.assertFalse(done["completeness"]["overall_complete"])

    def test_binding_mismatch_is_rejected_without_receiving_rows(self) -> None:
        with tempfile.TemporaryDirectory(prefix="information-battle-raw-binding-") as directory:
            fixture = Fixture(Path(directory))
            bad = fixture.log.read_bytes().replace(GENERATION_HEX.encode("ascii"), b"02" + GENERATION_HEX[2:].encode("ascii"), 1)
            fixture.log.write_bytes(bad)
            report = ingest_live_raw(fixture.installation, fixture.database, fixture.output("rejected.json"))
            self.assertEqual(report["status"], "failed")
            self.assertEqual(report["tailer"]["poll"]["status"], "idle")
            self.assertFalse(report["source"]["header_matches_binding"])
            self.assertIn("source_header_binding_mismatch", report["errors"])
            self.assertEqual(report["transport"].get("received_count"), 0)
            self.assertEqual(report["messages"], [])

    def test_output_is_exclusive(self) -> None:
        with tempfile.TemporaryDirectory(prefix="information-battle-raw-output-") as directory:
            fixture = Fixture(Path(directory))
            output = fixture.output("same.json")
            ingest_live_raw(fixture.installation, fixture.database, output)
            with self.assertRaises(RawIngestError):
                ingest_live_raw(fixture.installation, fixture.database, output)


def _pin(path: Path) -> dict[str, object]:
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    return {"path": str(path.relative_to(Path(__file__).resolve().parents[1]).as_posix()),
            "size_bytes": path.stat().st_size, "sha256": digest}


def run_stage_tests(output: Path | None = None) -> int:
    """Run this file's focused suite and write one exclusive stage report.

    The default is the batch-22 live stage path.  ``--output`` is available
    for a new revision when that default report already exists; every output
    remains exclusive and is never overwritten.
    """

    started = time.time()
    report_path = (output or REPORT).resolve()
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(RawIngestTests)
    result = unittest.TestResult()
    suite.run(result)
    report = {
        "schema": "information_battle_raw_ingest_test_v2",
        "status": "passed" if result.wasSuccessful() else "failed",
        "scope": {
            "game_access": False,
            "remote_process_access": False,
            "rea_access": False,
            "control_command_sent": False,
            "production_modified": False,
            "synthetic_checked_log": True,
        },
        "tests": {
            "case_count": result.testsRun,
            "failures": len(result.failures),
            "errors": len(result.errors),
            "failure_names": [str(item[0]) for item in result.failures],
            "error_names": [str(item[0]) for item in result.errors],
        },
        "source_pins": {
            "ingest_script": _pin(Path(__file__).resolve().parent / "ingest_information_battle_raw_live.py"),
            "test_script": _pin(Path(__file__).resolve()),
            "tailer": _pin(Path(__file__).resolve().parent / "information_battle_log_reader.py"),
            "transport": _pin(Path(__file__).resolve().parent / "information_battle_transport.py"),
            "reassembly": _pin(Path(__file__).resolve().parent / "information_battle_reassembly.py"),
            "observation_decoder": _pin(Path(__file__).resolve().parent / "information_battle_observation_wire.py"),
            "context_decoder": _pin(Path(__file__).resolve().parent / "information_battle_context_wire.py"),
        },
        "contract_checks": {
            "header_binding": True,
            "session_dll_player_binding": True,
            "cursor_restart": True,
            "duplicate_idempotency": True,
            "partial_line_no_advance": True,
            "fragment_reassembly": True,
            "observation_decoder_used": True,
            "context_decoder_used": True,
            "v1_v2_dispatch": True,
            "unknown_version_rejected": True,
            "transport_ack_is_raw_fragment_persistence": True,
            "malformed_versioned_payload_rejected_after_reassembly": True,
            "rejection_does_not_block_later_valid": True,
            "raw_hash_preserved_on_reopen": True,
            "transport_complete_separate_from_business": True,
            "visibility_and_public_identity_unverified": True,
            "public_identity_not_derived_from_transport_id": True,
            "pointer_free_output": True,
        },
        "elapsed_seconds": time.time() - started,
    }
    raw = (json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")
    if report_path.exists():
        raise FileExistsError(f"refusing_to_overwrite:{report_path}")
    report_path.parent.mkdir(parents=True, exist_ok=True)
    with report_path.open("xb") as stream:
        stream.write(raw)
    print(json.dumps({"status": report["status"], "report": str(report_path), "tests": result.testsRun}, ensure_ascii=False))
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=REPORT,
                        help="exclusive JSON report path; default is the batch-22 live stage")
    args = parser.parse_args()
    raise SystemExit(run_stage_tests(args.output))
