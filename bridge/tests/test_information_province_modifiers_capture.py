"""Tests for the strict province-modifier capture wrapper."""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest

from bridge.information import province_modifiers_capture as capture
from bridge.information import province_modifiers_memory as leaf


PROVINCE_ID = 227
BASE = 0x140000000
KEYS = ["tagus_estuary_modifier", "river_estuary_modifier", "custom_key"]


def _leaf_result(keys=KEYS, *, rows=None, status="partial"):
    if rows is None:
        rows = {
            keys[0]: {"status": "known", "value": True,
                      "raw_inputs": {"definition_pointer": "0x210000"}},
            keys[1]: {"status": "known", "value": False,
                      "raw_inputs": {"definition_pointer": "0x220000"}},
            keys[2]: {"status": "unknown", "reason": "secondary_definition_missing",
                      "raw_inputs": {"manager": "secondary"}},
        }
    return {
        "schema": leaf.SCHEMA,
        "status": status,
        "complete": False,
        "predicates": deepcopy(rows),
        "basis": leaf.BASIS,
        "gaps": ["PARENT_TWO_PASS_CONTEXT_AND_FIELD_STABILITY_NOT_PERFORMED"],
        "raw_inputs": {
            "reads": [{"label": "primary.bucket_head[0]", "raw_hex": "01"}],
            "read_budget": {"bytes_used": 24, "limit_bytes": leaf.MAX_READ_BYTES},
        },
    }


def _patch_owner(monkeypatch, leaf_result):
    calls = {"read_two_pass": [], "observe": [], "capture_common": []}

    def fake_read_two_pass(reader, module_base, province_id, *, observer, fields, read_fields):
        calls["read_two_pass"].append((reader, module_base, province_id, observer, fields, read_fields))
        binding = {
            "province_id": province_id,
            "record_id": province_id,
            "record_pointer": "0x100000000",
            "id_address": "0x100000020",
            "id_raw_hex": "e3000000",
        }
        return {
            "status": "observed",
            "fields": read_fields(reader, module_base, binding, fields),
        }

    def fake_observe(reader, module_base, country, profile, *, backend_reader):
        calls["observe"].append((reader, module_base, country, profile))
        return {
            "stable": True,
            "backend": backend_reader(reader, module_base, country),
        }

    def fake_capture_common(installation, country, *, observer, schema,
                            profile_sha256, load_profile, observe,
                            allow_observer_target=False):
        calls["capture_common"].append({
            "installation": installation,
            "country": country,
            "observer": observer,
            "schema": schema,
            "profile_sha256": profile_sha256,
            "load_profile": load_profile,
            "allow_observer_target": allow_observer_target,
            "observe": observe,
        })
        return {
            "schema": schema,
            "status": "observed",
            "completed": True,
            "observation": observe(object(), BASE, country, {"profile_id": "fixture"}),
        }

    monkeypatch.setattr(capture._province, "read_two_pass", fake_read_two_pass)
    monkeypatch.setattr(capture._owner, "_observe", fake_observe)
    monkeypatch.setattr(capture._owner, "_capture_common", fake_capture_common)
    monkeypatch.setattr(capture._leaf, "read_predicates", lambda reader, base, binding, keys:
                        deepcopy(leaf_result))
    return calls


def test_capture_uses_fra_owner_and_projects_true_false_unknown_with_raw_leaf():
    # Exercise the actual callback through its owner is done in the next test;
    # this case focuses on shape projection without process access.
    result = _leaf_result()
    projected = capture._project_leaf_result(result, tuple(KEYS))

    assert projected["status"] == "known"
    assert projected["complete"] is False
    assert projected["basis"] == "native_has_province_modifier_predicates"
    assert projected["value"] == {
        "predicates": {
            KEYS[0]: {"status": "known", "value": True},
            KEYS[1]: {"status": "known", "value": False},
            KEYS[2]: {"status": "unknown", "reason": "secondary_definition_missing"},
        }
    }
    assert projected["raw_inputs"]["leaf_result"] == result
    assert projected["gaps"] == result["gaps"]


def test_capture_calls_profiled_owner_and_existing_g02_double_pass(monkeypatch):
    raw = _leaf_result()
    calls = _patch_owner(monkeypatch, raw)

    report = capture.capture(Path("installation.json"), PROVINCE_ID, KEYS, observer="FRA")

    assert set(report) == {"schema", "observer", "object", "modifier_keys", "capture"}
    assert report["schema"] == capture.SCHEMA
    assert report["observer"] == "FRA"
    assert report["object"] == {"type": "province", "province_id": PROVINCE_ID}
    assert report["modifier_keys"] == KEYS
    assert report["capture"]["schema"] == capture.INNER_SCHEMA
    owner_args = calls["capture_common"][0]
    assert owner_args["installation"] == Path("installation.json")
    assert owner_args["country"] == owner_args["observer"] == "FRA"
    assert owner_args["schema"] == capture.INNER_SCHEMA
    assert owner_args["profile_sha256"] == capture.PROFILE_SHA256
    assert owner_args["load_profile"] is capture._load_profile
    assert owner_args["allow_observer_target"] is True
    callback = calls["read_two_pass"][0]
    assert callback[1:5] == (BASE, PROVINCE_ID, "FRA", (capture.FIELD,))
    assert callback[5] is not None
    field = report["capture"]["observation"]["backend"]["fields"][capture.FIELD]
    assert field["status"] == "known"
    assert field["value"]["predicates"][KEYS[2]] == {
        "status": "unknown", "reason": "secondary_definition_missing"
    }
    assert field["raw_inputs"]["leaf_result"] == raw


def test_all_unknown_leaf_still_projects_per_key_unknown_without_false():
    rows = {key: {"status": "unknown", "reason": f"unknown_{index}"}
            for index, key in enumerate(KEYS)}
    projected = capture._project_leaf_result(
        _leaf_result(rows=rows, status="unknown"), tuple(KEYS)
    )

    assert projected["status"] == "known"
    assert projected["value"] == {"predicates": rows}
    assert all(item["status"] == "unknown" for item in projected["value"]["predicates"].values())


@pytest.mark.parametrize("mutate", [
    lambda result: result.update(schema="wrong"),
    lambda result: result.update(complete=True),
    lambda result: result["predicates"].update(tagus_estuary_modifier={"status": "known", "value": 1}),
    lambda result: result["predicates"].update(custom_key={"status": "unknown"}),
    lambda result: result["predicates"].pop("river_estuary_modifier"),
])
def test_malformed_leaf_projection_is_unknown_not_false(mutate):
    result = _leaf_result()
    mutate(result)

    projected = capture._project_leaf_result(result, tuple(KEYS))

    assert projected["status"] == "unknown"
    assert "value" not in projected
    assert projected["basis"] == capture.BASIS
    assert projected["raw_inputs"]["leaf_result"] == result


@pytest.mark.parametrize("province_id", [0, -1, 0x10000, True])
def test_capture_rejects_invalid_province_id_before_owner_call(monkeypatch, province_id):
    calls = []
    monkeypatch.setattr(capture._owner, "_capture_common", lambda *args, **kwargs: calls.append((args, kwargs)))

    with pytest.raises(ValueError, match="PROVINCE_MODIFIERS_REQUEST_SCOPE"):
        capture.capture(Path("installation.json"), province_id, KEYS)

    assert calls == []


@pytest.mark.parametrize("bad_keys", [
    [],
    ["bad key"],
    ["repeated", "repeated"],
    ["x" * 256],
    [f"k{index}" for index in range(65)],
])
def test_capture_rejects_invalid_keys_before_owner_call(monkeypatch, bad_keys):
    calls = []
    monkeypatch.setattr(capture._owner, "_capture_common", lambda *args, **kwargs: calls.append((args, kwargs)))

    with pytest.raises(ValueError):
        capture.capture(Path("installation.json"), PROVINCE_ID, bad_keys)

    assert calls == []


def _outer_report(keys=KEYS, *, province_id=PROVINCE_ID):
    return {
        "schema": capture.SCHEMA,
        "observer": "FRA",
        "object": {"type": "province", "province_id": province_id},
        "modifier_keys": list(keys),
        "capture": {"schema": capture.INNER_SCHEMA},
    }


def test_validate_capture_enforces_outer_key_order_and_require_access(monkeypatch):
    calls = []

    def fake_validate(report, context, creation, country, **kwargs):
        calls.append((report, context, creation, country, kwargs))
        return True

    monkeypatch.setattr(capture._owner, "_validate_capture_common", fake_validate)
    context = {"observer": "FRA"}
    report = _outer_report()

    assert capture.validate_capture(report, context, 123, PROVINCE_ID, KEYS) is True
    args = calls[0]
    assert args[3] == "FRA"
    assert args[4]["schema"] == capture.INNER_SCHEMA
    assert args[4]["profile_sha256"] == capture.PROFILE_SHA256
    assert args[4]["load_profile"] is capture._load_profile
    assert args[4]["allow_observer_target"] is True
    assert args[4]["require_access"] is True

    calls.clear()
    assert capture.validate_capture(report, context, 123, PROVINCE_ID, list(reversed(KEYS))) is False
    assert calls == []
    report["extra"] = True
    assert capture.validate_capture(report, context, 123, PROVINCE_ID, KEYS) is False
    assert calls == []


@pytest.mark.parametrize("mutation", [
    lambda report: report.update(schema="wrong"),
    lambda report: report.update(observer="ENG"),
    lambda report: report.update(modifier_keys=[*KEYS, "extra"]),
    lambda report: report.update(object={"type": "country", "province_id": PROVINCE_ID}),
])
def test_validate_capture_rejects_wrong_outer_binding_without_owner_call(monkeypatch, mutation):
    calls = []
    monkeypatch.setattr(capture._owner, "_validate_capture_common", lambda *args, **kwargs: calls.append(args))
    report = _outer_report()
    mutation(report)

    assert capture.validate_capture(report, {"observer": "FRA"}, 123, PROVINCE_ID, KEYS) is False
    assert calls == []


def test_profile_manifest_pin_and_layout_dependencies_are_current():
    profile = capture._load_profile()

    assert profile["profile_id"] == "province-modifiers-memory-1374"
    assert capture.PROFILE_FILE.name == "province-modifiers-memory-1374-v2-sampling-r1.json"
    assert profile["profile_version"] == 2
    assert profile["game_version"] == "1.37.4"
    assert profile["layout"]["province_modifier_predicates"]["definition_key_string32_offset"] == "0x158"

