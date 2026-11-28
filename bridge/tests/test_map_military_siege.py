from __future__ import annotations

from copy import deepcopy

import pytest

import bridge.map_military_siege as siege

BASE = 0x10000000
RECORDS = {1: 0x20000000, 2: 0x20010000, 3: 0x20020000, 4: 0x20030000}
OBJECT = 0x30000000


class Memory:
    def __init__(self):
        self.values = {}
        self.reads = []

    def put(self, address, value, size):
        self.values[address] = value.to_bytes(size, "little")

    def read(self, address, size, label):
        self.reads.append(address)
        raw = self.values[address]
        assert len(raw) == size
        return raw


def _scopes():
    def row(pid, discovered, participant):
        return {"binding": {"record_pointer": hex(RECORDS[pid])},
                "discovery": {"value": discovered}, "participant": participant,
                "owner": "QAR" if participant else None, "owner_fullref": 123}
    return {"values": {1: row(1, True, True), 2: row(2, False, False),
                       3: row(3, True, False), 4: row(4, True, True)}}


def test_siege_read_respects_discovery_and_current_owner_scope(monkeypatch):
    monkeypatch.setattr(siege._forts, "_read_pass", lambda *args: _scopes())
    mem = Memory()
    mem.put(RECORDS[1] + 0x388, OBJECT, 8)
    mem.put(OBJECT, BASE + siege._SIEGE_VTABLE_RVA, 8)
    mem.put(OBJECT + 0x68, 42, 4)
    mem.put(RECORDS[4] + 0x388, 0, 8)
    result = siege._read_pass(mem, BASE, "TUR", (1, 2, 3, 4), ("QAR",))
    assert result["rows"][1]["elapsed_days"] == 42
    assert result["rows"][1]["owner"] == "QAR"
    assert result["rows"][4]["elapsed_days"] is None
    assert RECORDS[2] + 0x388 not in mem.reads
    assert RECORDS[3] + 0x388 not in mem.reads


def test_unknown_object_type_is_rejected(monkeypatch):
    monkeypatch.setattr(siege._forts, "_read_pass", lambda *args: _scopes())
    mem = Memory()
    mem.put(RECORDS[1] + 0x388, OBJECT, 8)
    mem.put(OBJECT, BASE + 0x1234, 8)
    with pytest.raises(ValueError, match="OBJECT_VTABLE_UNVERIFIED"):
        siege._read_pass(mem, BASE, "TUR", (1,), ("QAR",))
    assert OBJECT + 0x68 not in mem.reads


def test_runtime_code_and_serializer_slot_guards():
    mem = Memory()
    for rva, raw in siege._CODE_GUARDS:
        mem.values[BASE + rva] = raw
    mem.put(BASE + siege._SIEGE_VTABLE_RVA + 0x10, BASE + siege._SERIALIZER_RVA, 8)
    siege._siege_guards(mem, BASE)
    address = BASE + siege._CODE_GUARDS[0][0]
    mem.values[address] = bytes(len(mem.values[address]))
    with pytest.raises(ValueError, match="CODE_GUARD_MISMATCH"):
        siege._siege_guards(mem, BASE)


def test_changed_values_or_date_reject_both_passes(monkeypatch):
    monkeypatch.setattr(siege._owner, "_guards", lambda *args: [])
    monkeypatch.setattr(siege, "_siege_guards", lambda *args: (b"guard",))
    monkeypatch.setattr(siege._owner, "_context", lambda *args: {"game_date": 1})
    samples = iter(({"rows": {1: {"elapsed_days": 42}}}, {"rows": {1: {"elapsed_days": 43}}}))
    monkeypatch.setattr(siege, "_read_pass", lambda *args: next(samples))
    result = siege._observe(None, BASE, "TUR", (1,), {}, ("QAR",))
    assert result["stable"] is False and result["rows"] == {}

    contexts = iter(({"game_date": 1}, {"game_date": 2}))
    monkeypatch.setattr(siege._owner, "_context", lambda *args: next(contexts))
    sample = {"rows": {1: {"elapsed_days": 42}}}
    monkeypatch.setattr(siege, "_read_pass", lambda *args: deepcopy(sample))
    assert not siege._observe(None, BASE, "TUR", (1,), {}, ("QAR",))["stable"]


def test_public_result_never_turns_null_or_unknown_into_zero(tmp_path, monkeypatch):
    install = tmp_path / "installation.json"
    install.write_text("{}", encoding="utf8")
    report = {"status": "observed", "completed": True,
              "request": {"pid": 1, "creation_filetime": 2, "session_id": "session"},
              "observation": {"stable": True,
                              "context_after": {"game_date": 56928336, "world_pointer": "0x12345"},
                              "rows": {1: {"pointer": OBJECT, "elapsed_days": 42, "owner": "QAR"},
                                       2: {"pointer": 0, "elapsed_days": None, "owner": "QAR"}}}}
    monkeypatch.setattr(siege._owner, "_capture_common", lambda *args, **kwargs: deepcopy(report))
    result = siege.capture_sieges(install, "TUR", (1, 2), participants=("QAR",))
    assert result["records"] == [{"province_id": 1, "elapsed_days": 42, "owner": "QAR"}]
    assert result["field_metadata"]["siege_percent"]["status"] == "unavailable"
    assert result["field_metadata"]["null_pointer_proves_absence"] is False
    report["observation"]["stable"] = False
    assert siege.capture_sieges(install, "TUR", (1,), participants=("QAR",))["status"] == "unavailable"
