from __future__ import annotations

from copy import deepcopy
import json

import pytest

from bridge.information.model import InformationError
from bridge.information.trade_value import NativeTradeValueSource


GAME_SHA = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"


def _context(**updates):
    value = {
        "status": "ready",
        "mode": "live",
        "session_id": "session-trade-value-test",
        "observer": "FRA",
        "game_version": "1.37.4",
        "game_sha256": GAME_SHA,
        "game_date": 56556984,
    }
    value.update(updates)
    return value


def _money(raw, basis):
    return {
        "status": "known",
        "value": raw,
        "raw": raw,
        "raw_hex": (raw & 0xFFFFFFFF).to_bytes(4, "little").hex(),
        "unit": "ducats",
        "scale": 1000,
        "period": "current",
        "basis": basis,
        "value_origin": "copied_native_trade_node_cache",
        "complete": False,
        # This should be removed by the adapter's public field allowlist.
        "private_pointer": "0xDEADBEEF",
    }


def _projected():
    return {
        "local_value": _money(12000, "native_trade_node_local_value_cache"),
        "incoming_value": _money(7000, "native_trade_node_incoming_value_cache"),
        "total_value": _money(18000, "native_trade_node_total_value_cache"),
        "collected_value": _money(9000, "native_trade_node_retention_tooltip_amount"),
        "outgoing_value": {
            "status": "known",
            "value": {
                "total_raw": 1000,
                "routes": [{"node_id": "beta_node", "raw": 1000, "private": "omit"}],
            },
            "unit": "ducats",
            "scale": 1000,
            "period": "current",
            "basis": "native_trade_node_outgoing_value_cache",
            "value_origin": "copied_native_trade_node_cache",
            "complete": False,
            "private_pointer": "0xBAD0",
        },
        # The adapter must ignore anything outside the five public fields.
        "private_payload": {"memory_address": "0xDEADBEEF"},
    }


class _Session:
    def __init__(self, directory):
        self.directory = directory
        self.record = {"creation_filetime": 123456789}
        self.creation_filetime = 123456789


class _Base:
    def __init__(self, directory, contexts=None):
        self.session = _Session(directory)
        self._contexts = list(contexts or [_context(), _context(), _context()])
        self._last = deepcopy(self._contexts[-1])
        self.context_calls = 0

    def context(self):
        self.context_calls += 1
        if self._contexts:
            self._last = deepcopy(self._contexts.pop(0))
        return deepcopy(self._last)


class _CaptureModule:
    def __init__(self, base, *, valid=True, projected=None, mutate=None,
                 schema="information.trade_value_capture.v2"):
        self.base = base
        self.valid = valid
        self.projected = projected if projected is not None else _projected()
        self.mutate = mutate
        self.schema = schema
        self.capture_calls = []
        self.validation_calls = []
        self.project_calls = []

    def capture(self, installation, node_id, *, observer):
        self.capture_calls.append((installation, node_id, observer))
        report = {
            "schema": self.schema,
            "observer": observer,
            "object": {"type": "trade_node", "node_id": node_id},
            "private_payload": {"pointer": "0xPRIVATE", "raw_memory": "hidden"},
        }
        if self.mutate is not None:
            self.mutate()
        return report

    def validate_capture(self, report, context, creation_filetime, node_id):
        self.validation_calls.append((report, deepcopy(context), creation_filetime, node_id))
        return self.valid

    def project_fields(self, report):
        self.project_calls.append(report)
        return self.projected


def _query(fields=None, *, node_id="alpha_node", parameters=None):
    return {
        "topic": "T03",
        "object": {"type": "trade_node", "node_id": node_id},
        "fields": fields or ["local_value"],
        "parameters": {} if parameters is None else parameters,
    }


def _source(tmp_path, contexts=None, *, module=None):
    base = _Base(str(tmp_path), contexts)
    module = module or _CaptureModule(base)
    return NativeTradeValueSource(base, capture=module), base, module


def test_catalog_marks_all_five_fields_partial_and_describes_retained_amount():
    source = NativeTradeValueSource(_Base("unused"), capture=object())
    item = source.catalog()[0]
    assert item["topic_id"] == "T03"
    assert item["status"] == "available"
    assert all(item["fields"][name]["coverage"] == "partial" for name in (
        "local_value", "incoming_value", "total_value", "outgoing_value", "collected_value"))
    collected = item["fields"]["collected_value"]
    assert collected["basis"] == "native_trade_node_retention_tooltip_amount"
    assert collected["scale"] == 1000 and collected["unit"] == "ducats"
    assert "贸易效率修正前" in collected["description"]
    assert "贸易力量百分比" in collected["description"]
    assert item["source"] == "NativeTradeValueSource"
    assert collected["source"].endswith("trade_value_capture_v2.capture")


def test_default_capture_api_imports_v2_module(tmp_path, monkeypatch):
    import bridge.information.trade_value as trade_value_module

    source = NativeTradeValueSource(_Base(str(tmp_path)))
    fake = _CaptureModule(source.base_source)
    calls = []

    def import_module(name, package):
        calls.append((name, package))
        return fake

    monkeypatch.setattr(trade_value_module.importlib, "import_module", import_module)
    module, capture_fn = source._capture_api()
    assert calls == [(".trade_value_capture_v2", "bridge.information")]
    assert module is fake and capture_fn == fake.capture


def test_query_validation_requires_bounded_node_and_empty_parameters():
    source = NativeTradeValueSource(_Base("unused"), capture=object())
    assert source.validate_query(_query(["total_value"]))["object"]["node_id"] == "alpha_node"
    for bad in (
        _query(node_id="Null"),
        _query(node_id="../alpha"),
        _query(parameters={"include_private": True}),
        _query(["total_value", "total_value"]),
        _query(["collected_value", "not_a_field"]),
    ):
        with pytest.raises(InformationError):
            source.validate_query(bad)


def test_collected_only_captures_once_and_projects_typed_value(tmp_path):
    source, base, module = _source(tmp_path)
    result = source.read(_query(["collected_value"]), _context())
    assert len(module.capture_calls) == 1
    assert len(module.validation_calls) == len(module.project_calls) == 1
    field = result["fields"]["collected_value"]
    assert field == {
        "status": "known", "value": 9000, "raw": 9000, "raw_hex": "28230000",
        "unit": "ducats", "scale": 1000, "period": "current",
        "basis": "native_trade_node_retention_tooltip_amount",
        "value_origin": "copied_native_trade_node_cache", "complete": False,
    }
    assert result["source"]["provenance"]["capture_performed"] is True
    assert result["complete"] is False


def test_five_cache_fields_share_one_capture_and_projector(tmp_path):
    source, base, module = _source(tmp_path)
    fields = ["local_value", "incoming_value", "total_value", "outgoing_value", "collected_value"]
    result = source.read(_query(fields), _context())
    assert len(module.capture_calls) == 1
    installation, node_id, observer = module.capture_calls[0]
    assert installation == (tmp_path / "installation.json")
    assert (node_id, observer) == ("alpha_node", "FRA")
    assert len(module.validation_calls) == len(module.project_calls) == 1
    assert module.validation_calls[0][1] == _context()
    assert module.validation_calls[0][2:] == (123456789, "alpha_node")
    assert result["fields"]["local_value"]["value"] == 12000
    assert result["fields"]["incoming_value"]["value"] == 7000
    assert result["fields"]["total_value"]["value"] == 18000
    assert result["fields"]["outgoing_value"]["value"] == {
        "total_raw": 1000, "routes": [{"node_id": "beta_node", "raw": 1000}]}
    assert result["fields"]["collected_value"]["value"] == 9000
    assert result["fields"]["collected_value"]["basis"] == "native_trade_node_retention_tooltip_amount"
    assert result["complete"] is False
    provenance = result["source"]["provenance"]
    assert provenance["read_only"] is True
    assert provenance["native_function_invoked"] is False
    assert provenance["actual_UI_observed"] is False
    assert provenance["current_center_discovery_positive"] is True
    encoded = json.dumps(result, sort_keys=True)
    assert "PRIVATE" not in encoded and "DEADBEEF" not in encoded and "private_pointer" not in encoded


def test_stale_context_refuses_capture(tmp_path):
    stale = _context(game_date=56556983)
    source, base, module = _source(tmp_path, contexts=[_context(), _context()])
    result = source.read(_query(), stale)
    assert result["fields"]["local_value"]["status"] == "unknown"
    assert result["fields"]["local_value"]["reason"] == "TRADE_VALUE_CONTEXT_STALE"
    assert module.capture_calls == []


def test_context_drift_after_capture_retracts_all_values(tmp_path):
    source, base, module = _source(tmp_path, contexts=[_context(), _context(game_date=56556985)])
    result = source.read(_query(["local_value", "total_value", "collected_value"]), _context())
    assert len(module.capture_calls) == 1
    assert module.validation_calls == []
    assert module.project_calls == []
    assert all(value["status"] == "unknown" for value in result["fields"].values())
    assert result["fields"]["local_value"]["reason"] == "TRADE_VALUE_CONTEXT_OR_INSTALLATION_CHANGED"
    assert result["fields"]["collected_value"]["reason"] == "TRADE_VALUE_CONTEXT_OR_INSTALLATION_CHANGED"


def test_installation_creation_drift_retracts_before_validation(tmp_path):
    base = _Base(str(tmp_path))
    def drift():
        base.session.directory = str(tmp_path / "replacement")
        base.session.record["creation_filetime"] += 1
        base.session.creation_filetime += 1
    module = _CaptureModule(base, mutate=drift)
    source = NativeTradeValueSource(base, capture=module)
    result = source.read(_query(["local_value", "incoming_value"]), _context())
    assert len(module.capture_calls) == 1
    assert module.validation_calls == []
    assert module.project_calls == []
    assert all(value["status"] == "unknown" for value in result["fields"].values())


def test_capture_validation_denial_blocks_projector(tmp_path):
    source, base, module = _source(tmp_path, module=None)
    module.valid = False
    result = source.read(_query(["local_value", "outgoing_value"]), _context())
    assert len(module.capture_calls) == 1
    assert len(module.validation_calls) == 1
    assert module.project_calls == []
    assert all(value == {"status": "unknown", "reason": "TRADE_VALUE_CAPTURE_INVALID"}
               for value in result["fields"].values())


def test_collected_capture_validation_failure_uses_capture_reason(tmp_path):
    source, base, module = _source(tmp_path, module=None)
    module.valid = False
    result = source.read(_query(["collected_value"]), _context())
    assert len(module.capture_calls) == len(module.validation_calls) == 1
    assert module.project_calls == []
    assert result["fields"]["collected_value"] == {
        "status": "unknown", "reason": "TRADE_VALUE_CAPTURE_INVALID"}


def test_legacy_v1_capture_keeps_legacy_collected_unknown(tmp_path):
    projected = _projected()
    projected["collected_value"] = {
        "status": "unknown", "reason": "NODE_COLLECTED_VALUE_NOT_PROVEN"}
    module = _CaptureModule(
        _Base(str(tmp_path)), projected=projected,
        schema="information.trade_value_capture.v1")
    source = NativeTradeValueSource(module.base, capture=module)
    result = source.read(_query(["collected_value"]), _context())
    assert len(module.capture_calls) == len(module.validation_calls) == len(module.project_calls) == 1
    assert result["fields"]["collected_value"] == {
        "status": "unknown", "reason": "NODE_COLLECTED_VALUE_NOT_PROVEN"}


def test_unrecognized_outer_capture_schema_blocks_projection(tmp_path):
    source, base, module = _source(tmp_path)
    module.schema = "information.trade_value_capture.v3"
    result = source.read(_query(["collected_value"]), _context())
    assert len(module.capture_calls) == len(module.validation_calls) == 1
    assert module.project_calls == []
    assert result["fields"]["collected_value"] == {
        "status": "unknown", "reason": "TRADE_VALUE_CAPTURE_SHAPE_INVALID"}


@pytest.mark.parametrize("mutate", [
    lambda field: field.update(value=True),
    lambda field: field.update(value=1 << 31),
    lambda field: field.update(raw=9001),
])
def test_collected_projection_rejects_bad_signed_or_forged_value(tmp_path, mutate):
    source, base, module = _source(tmp_path)
    projected = _projected()
    mutate(projected["collected_value"])
    module.projected = projected
    result = source.read(_query(["collected_value"]), _context())
    assert result["fields"]["collected_value"] == {
        "status": "unknown", "reason": "TRADE_VALUE_SIGNED_RAW_INVALID"}


def test_invalid_public_projection_is_retracted_and_private_keys_are_not_copied(tmp_path):
    source, base, module = _source(tmp_path)
    projected = _projected()
    projected["total_value"]["value"] = True
    module.projected = projected
    result = source.read(_query(["local_value", "total_value", "outgoing_value"]), _context())
    assert result["fields"]["local_value"]["status"] == "known"
    assert result["fields"]["total_value"] == {
        "status": "unknown", "reason": "TRADE_VALUE_SIGNED_RAW_INVALID"}
    assert "private_pointer" not in result["fields"]["local_value"]
    assert "private_pointer" not in result["fields"]["outgoing_value"]
    assert "private" not in json.dumps(result, sort_keys=True).lower()


def test_invalid_capture_binding_never_reaches_projector(tmp_path):
    source, base, module = _source(tmp_path)
    original_capture = module.capture
    def wrong_capture(installation, node_id, *, observer):
        report = original_capture(installation, node_id, observer=observer)
        report["object"]["node_id"] = "other_node"
        return report
    module.capture = wrong_capture
    result = source.read(_query(["total_value"]), _context())
    assert result["fields"]["total_value"] == {
        "status": "unknown", "reason": "TRADE_VALUE_CAPTURE_SHAPE_INVALID"}
    assert module.project_calls == []


def test_poll_events_is_empty_and_keeps_cursor():
    source = NativeTradeValueSource(_Base("unused"), capture=object())
    cursor = {"sequence": 7}
    result = source.poll_events(_context(), cursor)
    assert result == {"events": [], "cursor": cursor, "complete": True, "gaps": []}
    assert result["cursor"] is not cursor
