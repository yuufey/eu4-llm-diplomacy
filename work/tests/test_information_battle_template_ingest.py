"""Checked-log to SQLite regression for a bounded v4 template payload."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sqlite3
import struct
import zlib

from work.information_battle_naval_wire import decode as decode_naval
from work.information_battle_reassembly import build_fragment_payload
from work.ingest_information_battle_raw_live import (
    _decode_payload,
    ingest_live_raw,
)
from work.information_battle_template_wire import MAX_WIRE_BYTES
from bridge.information.battle_ingest import LiveBattleIngestor


ROOT = Path(__file__).resolve().parents[2]
V3_FIXTURE = ROOT / "bridge/tests/fixtures/information_battle_naval_seq3_live_v3_1374.json"
GAME_SHA = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
INSTALLATION_WIRE = "000000000000007b"
GENERATION_WIRE = "00000000000001c8"


def _large_v4_payload() -> bytes:
    base = bytes.fromhex(json.loads(V3_FIXTURE.read_text(encoding="utf-8"))["payload_hex"])
    raw_date = decode_naval(base)["observation"]["result"]["raw_date"]
    # Eight values of 8191 plus one-byte keys exactly fill the 64 KiB arena;
    # the envelope itself is therefore larger than 64 KiB but within v4's
    # 256 KiB wire budget.
    pairs = [(b"k", b"v" * 8191) for _ in range(8)]
    body = struct.pack("<iBBIBII", raw_date, 0xa1, 0x5e, 0xfeedbeef,
                       0x7a, len(pairs), 0)
    for key, value in pairs:
        body += struct.pack("<I", len(key)) + key
        body += struct.pack("<I", len(value)) + value
    payload = (b"IBOW" + struct.pack("<HI", 4, len(base)) + base
               + b"\x01BTXT" + struct.pack("<HI", 1, len(body)) + body)
    assert len(payload) > 64 * 1024
    assert len(payload) <= MAX_WIRE_BYTES
    version, decoded = _decode_payload(payload)
    assert version == 4
    assert decoded["message_template"]["pair_count"] == 8
    return payload


def _write_installation(tmp_path: Path) -> Path:
    live = tmp_path / "installed"
    live.mkdir()
    installation = live / "installation.json"
    installation.write_text(json.dumps({
        "pid": 1,
        "creation_filetime": 1,
        "session_id": "template-ingest-session",
        "dll_sha256": GAME_SHA,
    }), encoding="utf-8")
    (live / "information-battle-binding.json").write_text(json.dumps({
        "schema": "EU4-BATTLE-CONTROL/1",
        "pid": 1,
        "creation_filetime": "1",
        "session_id": "template-ingest-session",
        "dll_sha256": GAME_SHA,
        "installation": "123",
        "generation": "456",
        "player_ref": "010000bd00524f50",
    }), encoding="utf-8")
    return installation


def _write_checked_log(installation: Path, payload: bytes) -> None:
    crc = zlib.crc32(payload) & 0xffffffff
    fragment_size = 4032
    count = (len(payload) + fragment_size - 1) // fragment_size
    lines = [f"EU4_OWNED_BATTLE_WIRE_V1 {INSTALLATION_WIRE} {GENERATION_WIRE}\n".encode()]
    for index in range(count):
        part = payload[index * fragment_size:(index + 1) * fragment_size]
        fragment = build_fragment_payload(
            installation=INSTALLATION_WIRE,
            world_generation=GENERATION_WIRE,
            message_id=77,
            total_bytes=len(payload),
            fragment_index=index,
            data=part,
            whole_crc32=crc,
        )
        frame = {
            "event": "information_owned_battle_record",
            "wire_version": 1,
            "installation": INSTALLATION_WIRE,
            "world_generation": GENERATION_WIRE,
            "attempt_sequence": str(index + 1),
            "payload_encoding": "hex",
            "payload_bytes": len(fragment),
            "payload_hex": fragment.hex(),
        }
        lines.append((json.dumps(frame, separators=(",", ":")) + "\n").encode())
    (installation.parent / "information-battle-raw.jsonl").write_bytes(b"".join(lines))


def test_checked_v4_log_reassembles_large_template_and_restart_is_idle(tmp_path, monkeypatch):
    installation = _write_installation(tmp_path)
    payload = _large_v4_payload()
    _write_checked_log(installation, payload)
    database = tmp_path / "raw.sqlite3"
    report_path = tmp_path / "ingest-report.json"

    # Force the bounded human report budget to omit the large message while
    # leaving the durable SQLite payload untouched.
    monkeypatch.setattr(
        "work.ingest_information_battle_raw_live.MAX_MESSAGE_REPORT_BYTES", 128,
    )
    report = ingest_live_raw(installation, database, report_path)
    assert report["status"] == "passed"
    assert report["message_report_scope"]["limited"] is True
    assert report["message_report_scope"]["messages_in_report"] == 0
    assert report["message_report_scope"]["omitted_payloads_remain_in_database"] is True
    assert report["completeness"]["business_complete"] is False

    with sqlite3.connect(database) as connection:
        stored = connection.execute("SELECT payload FROM complete_messages").fetchone()[0]
    assert bytes(stored) == payload
    assert len(stored) > 64 * 1024
    assert hashlib.sha256(bytes(stored)).hexdigest() == hashlib.sha256(payload).hexdigest()
    version, decoded = _decode_payload(bytes(stored))
    assert version == 4
    assert decoded["wire"]["template_present"] is True
    assert decoded["message_template"]["pair_count"] == 8

    reopened = LiveBattleIngestor(installation, database)
    try:
        summary = reopened.refresh()
        assert summary["status"] == "idle"
        assert summary["tailer"]["poll"].get("acked", 0) == 0
        assert summary["reassembly"]["poll"].get("processed", 0) == 0
    finally:
        reopened.close()
