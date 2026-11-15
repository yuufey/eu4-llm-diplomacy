"""Offline strict-envelope and raw-read replay tests for the income child."""
from __future__ import annotations

from copy import deepcopy

import pytest

from bridge.information import trade_income_calculation_capture as capture


MODULE_BASE = 0x140000000
NODE_ID = "champagne"
TRADE_RECORD = {"status": "observed", "country": "FRA", "nodes": [{"node_id": NODE_ID}]}
COUNTRY_SCAN = {"status": "observed", "requested_country": "FRA", "matches": []}
POWER_SUM_RECORD = {"status": "observed", "value": 123}
CODE_RVA = 0x100
LEAF_RVA = 0x200
CODE_BYTES = bytes.fromhex("aabbccdd")
LEAF_BYTES = (4589).to_bytes(4, "little", signed=True)


class Reader:
    def __init__(self, *, code_bytes: bytes = CODE_BYTES):
        self.data = {
            MODULE_BASE + CODE_RVA: code_bytes,
            MODULE_BASE + LEAF_RVA: LEAF_BYTES,
        }
        self.read_log: list[dict] = []

    def read(self, address: int, size: int, label: str) -> bytes:
        self.read_log.append({"address": hex(address), "size": size, "label": label})
        raw = self.data.get(address)
        if raw is None or len(raw) != size:
            raise AssertionError(f"unexpected capture read {label} {address:#x} {size}")
        return raw


def _install_capture(monkeypatch: pytest.MonkeyPatch, *, code_bytes=CODE_BYTES, leaf_status="observed"):
    calls = []
    monkeypatch.setattr(capture, "_load_profile", lambda: {
        "code_guards": [{"name": "synthetic_guard", "rva": hex(CODE_RVA), "bytes": CODE_BYTES.hex()}]
    })

    def read_leaf(reader, base, trade_income, country_scan, power_sum, *, node_id):
        calls.append((reader, base, trade_income, country_scan, power_sum, node_id))
        raw = reader.read(base + LEAF_RVA, 4, capture.PREFIX + "synthetic_leaf")
        return {
            "status": leaf_status,
            "stable": leaf_status == "observed",
            "node_id": node_id,
            "value": {"income_raw": int.from_bytes(raw, "little", signed=True)},
        }

    monkeypatch.setattr(capture._memory, "read_fields", read_leaf)
    return Reader(code_bytes=code_bytes), calls


def _parent_log(record):
    return [
        {
            "address": row["address"],
            "size": row["size"],
            "label": row["label"],
            "raw_hex": row["raw_hex"],
            "status": "observed",
        }
        for row in record["raw_reads"]
    ]


def _capture(reader, *, trade=TRADE_RECORD, scan=COUNTRY_SCAN, power_sum=POWER_SUM_RECORD, node_id=NODE_ID):
    return capture.read_fields(reader, MODULE_BASE, trade, scan, power_sum, node_id=node_id)


def test_capture_envelope_strictly_replays_and_binds_parent_read_log(monkeypatch):
    reader, calls = _install_capture(monkeypatch)
    record = _capture(reader)

    assert record["status"] == "observed"
    assert record["schema"] == capture.SCHEMA
    assert record["profile_sha256"] == capture.PROFILE_SHA256
    assert record["observation"]["value"]["income_raw"] == 4589
    assert record["complete"] is False
    assert len(record["raw_reads"]) == 2
    assert all(row["status"] == "observed" for row in record["raw_reads"])
    assert capture.validate_record(
        record, TRADE_RECORD, COUNTRY_SCAN, POWER_SUM_RECORD,
        node_id=NODE_ID, parent_read_log=_parent_log(record),
    ) is True
    # The original capture and the strict replay both execute the leaf adapter.
    assert len(calls) == 2


@pytest.mark.parametrize("source", ["trade", "country_scan", "power_sum"])
def test_capture_validation_rejects_changed_parent_source(monkeypatch, source):
    reader, _calls = _install_capture(monkeypatch)
    record = _capture(reader)
    changed = deepcopy({"trade": TRADE_RECORD, "country_scan": COUNTRY_SCAN,
                        "power_sum": POWER_SUM_RECORD}[source])
    changed["tampered"] = True
    args = {
        "trade": (changed, COUNTRY_SCAN, POWER_SUM_RECORD),
        "country_scan": (TRADE_RECORD, changed, POWER_SUM_RECORD),
        "power_sum": (TRADE_RECORD, COUNTRY_SCAN, changed),
    }[source]

    assert capture.validate_record(record, *args, node_id=NODE_ID) is False


def test_capture_validation_rejects_tampered_projection_selector_and_reads(monkeypatch):
    reader, _calls = _install_capture(monkeypatch)
    record = _capture(reader)

    changed_projection = deepcopy(record)
    changed_projection["observation"]["value"]["income_raw"] += 1
    assert capture.validate_record(
        changed_projection, TRADE_RECORD, COUNTRY_SCAN, POWER_SUM_RECORD, node_id=NODE_ID
    ) is False

    assert capture.validate_record(
        record, TRADE_RECORD, COUNTRY_SCAN, POWER_SUM_RECORD, node_id="sevilla"
    ) is False

    changed_reads = deepcopy(record)
    changed_reads["raw_reads"][0]["raw_hex"] = "00000000"
    assert capture.validate_record(
        changed_reads, TRADE_RECORD, COUNTRY_SCAN, POWER_SUM_RECORD, node_id=NODE_ID
    ) is False


def test_capture_validation_rejects_parent_log_mismatch_and_failed_status(monkeypatch):
    reader, _calls = _install_capture(monkeypatch)
    record = _capture(reader)
    parent = _parent_log(record)
    assert capture.validate_record(
        record, TRADE_RECORD, COUNTRY_SCAN, POWER_SUM_RECORD,
        node_id=NODE_ID, parent_read_log=parent,
    ) is True

    failed_status = deepcopy(parent)
    failed_status[0]["status"] = "failed"
    assert capture.validate_record(
        record, TRADE_RECORD, COUNTRY_SCAN, POWER_SUM_RECORD,
        node_id=NODE_ID, parent_read_log=failed_status,
    ) is False

    changed_bytes = deepcopy(parent)
    changed_bytes[-1]["raw_hex"] = "00000000"
    assert capture.validate_record(
        record, TRADE_RECORD, COUNTRY_SCAN, POWER_SUM_RECORD,
        node_id=NODE_ID, parent_read_log=changed_bytes,
    ) is False

    assert capture.validate_record(
        record, TRADE_RECORD, COUNTRY_SCAN, POWER_SUM_RECORD,
        node_id=NODE_ID, parent_read_log={},
    ) is False


@pytest.mark.parametrize(
    "record",
    [None, [], "invalid", {"status": "unknown"}, {"status": "observed", "raw_reads": None}],
)
def test_capture_validation_rejects_false_status_and_wrong_record_types(monkeypatch, record):
    _reader, _calls = _install_capture(monkeypatch)
    assert capture.validate_record(
        record, TRADE_RECORD, COUNTRY_SCAN, POWER_SUM_RECORD, node_id=NODE_ID
    ) is False


def test_runtime_guard_mismatch_is_not_promoted_to_observed(monkeypatch):
    reader, calls = _install_capture(monkeypatch, code_bytes=b"nope")
    result = _capture(reader)

    assert result["status"] == "unknown"
    assert result["runtime_code_guard"]["status"] == "mismatch"
    assert result["observation"] is None
    assert len(calls) == 0


@pytest.mark.parametrize("node_id", ["Null", True, "bad/node"])
def test_invalid_selector_is_unknown_before_any_capture_reads(monkeypatch, node_id):
    reader, calls = _install_capture(monkeypatch)
    result = _capture(reader, node_id=node_id)

    assert result["status"] == "unknown"
    assert result["raw_reads"] == []
    assert len(reader.read_log) == 0
    assert calls == []


def test_invalid_module_base_type_is_unknown_without_memory_reads(monkeypatch):
    reader, calls = _install_capture(monkeypatch)
    result = capture.read_fields(
        reader, True, TRADE_RECORD, COUNTRY_SCAN, POWER_SUM_RECORD, node_id=NODE_ID
    )

    assert result["status"] == "unknown"
    assert result["raw_reads"] == []
    assert reader.read_log == []
    assert calls == []


def test_unknown_leaf_status_is_not_promoted_by_capture(monkeypatch):
    reader, _calls = _install_capture(monkeypatch, leaf_status="unknown")
    result = _capture(reader)

    assert result["status"] == "unknown"
    assert result["observation"]["status"] == "unknown"
    assert result["reason"] == "TRADE_INCOME_CALCULATION_UNVERIFIED"
