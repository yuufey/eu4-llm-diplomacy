"""FRA-owned capture envelope for the current province trade-power cache."""
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest

from bridge.information import province_trade_power_capture as capture_module
from bridge.information import province_trade_power_memory as trade_power_memory


PROVINCE_ID = 183
MODULE_BASE = 0x140000000
FIELD = trade_power_memory.FIELD_PROVINCE_TRADE_POWER
CREATION = 134384086783026355
CONTEXT = {
    "observer": "FRA",
    "session_id": "test-session",
    "game_version": "1.37.4",
    "game_sha256": "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77",
    "game_date": "1456.7.26",
}


class _ReadSentinel:
    pass


def _backend_result(province_id=PROVINCE_ID, raw=1250):
    return {
        "status": "observed",
        "consistency": {"status": "stable"},
        "targets": [{
            "province_id": province_id,
            "fields": {
                FIELD: {
                    "status": "known",
                    "complete": False,
                    "value": {"raw": raw, "scale": 1000, "unit": "trade_power"},
                    "basis": "native_province_trade_power_trigger_cache",
                },
            },
        }],
    }


def _outer_report(province_id=PROVINCE_ID):
    return {
        "schema": capture_module.SCHEMA,
        "observer": "FRA",
        "object": {"type": "province", "province_id": province_id},
        "capture": {
            "schema": capture_module.INNER_SCHEMA,
            "status": "observed",
            "completed": True,
            "cleanup": {"status": "closed", "closed": True, "success": True},
        },
    }


def _patch_capture_owner(monkeypatch, *, backend_result=None, owner_result=None):
    calls = {"two_pass": [], "observe": [], "capture_common": []}

    def read_two_pass(reader, module_base, province_id, *, observer, fields, read_fields):
        calls["two_pass"].append((reader, module_base, province_id, observer, fields, read_fields))
        return deepcopy(backend_result if backend_result is not None
                        else _backend_result(province_id))

    def observe(reader, module_base, country, profile, *, backend_reader):
        calls["observe"].append((reader, module_base, country, deepcopy(profile)))
        backend = backend_reader(reader, module_base, country)
        return {
            "stable": True,
            "context_before": {"game_date": CONTEXT["game_date"]},
            "context_after": {"game_date": CONTEXT["game_date"]},
            "backend": backend,
        }

    def capture_common(installation, country, *, observer, schema, profile_sha256,
                       load_profile, observe, allow_observer_target):
        calls["capture_common"].append({
            "installation": installation,
            "country": country,
            "observer": observer,
            "schema": schema,
            "profile_sha256": profile_sha256,
            "load_profile": load_profile,
            "observe": observe,
            "allow_observer_target": allow_observer_target,
        })
        if owner_result is not None:
            return deepcopy(owner_result)
        return {
            "schema": schema,
            "status": "observed",
            "completed": True,
            "observation": observe(
                _ReadSentinel(), MODULE_BASE, country, {"profile_id": "capture-test"},
            ),
            "cleanup": {"status": "closed", "closed": True, "success": True},
        }

    monkeypatch.setattr(capture_module._province, "read_two_pass", read_two_pass)
    monkeypatch.setattr(capture_module._owner, "_observe", observe)
    monkeypatch.setattr(capture_module._owner, "_capture_common", capture_common)
    return calls


def _patch_validator(monkeypatch, *, result=True):
    calls = []

    def validate_common(report, context, creation, country, *, schema, profile_sha256,
                        load_profile, observe, allow_observer_target, require_access):
        calls.append({
            "report": deepcopy(report),
            "context": deepcopy(context),
            "creation": creation,
            "country": country,
            "schema": schema,
            "profile_sha256": profile_sha256,
            "load_profile": load_profile,
            "observe": observe,
            "allow_observer_target": allow_observer_target,
            "require_access": require_access,
        })
        # Exercise the callback the shared validator will use for strict replay.
        observe(_ReadSentinel(), MODULE_BASE, country, {"profile_id": "replay-test"})
        return result

    monkeypatch.setattr(capture_module._owner, "_validate_capture_common", validate_common)
    return calls


@pytest.mark.parametrize("raw", [1250, -275])
def test_capture_binds_outer_province_to_single_field_two_pass_owner(monkeypatch, raw):
    backend = _backend_result(raw=raw)
    calls = _patch_capture_owner(monkeypatch, backend_result=backend)

    report = capture_module.capture(Path("installation.json"), PROVINCE_ID)

    assert set(report) == {"schema", "observer", "object", "capture"}
    assert report["schema"] == "information.province_trade_power_capture.v1"
    assert report["observer"] == "FRA"
    assert report["object"] == {"type": "province", "province_id": PROVINCE_ID}
    assert report["capture"]["observation"]["backend"] == backend
    assert calls["capture_common"][0]["country"] == "FRA"
    args = calls["capture_common"][0]
    assert args["observer"] == "FRA"
    assert args["schema"] == "information.province_trade_power_observer_snapshot.v1"
    assert args["profile_sha256"] == capture_module.PROFILE_SHA256
    assert callable(args["load_profile"])
    assert args["allow_observer_target"] is True
    reader, base, province_id, observer, fields, read_fields = calls["two_pass"][0]
    assert isinstance(reader, _ReadSentinel)
    assert (base, province_id, observer, fields) == (
        MODULE_BASE, PROVINCE_ID, "FRA", (FIELD,),
    )
    assert read_fields is trade_power_memory.read_fields


def test_capture_preserves_an_owner_failure_inside_the_bound_outer_envelope(monkeypatch):
    failed_inner = {
        "schema": capture_module.INNER_SCHEMA,
        "status": "unknown",
        "completed": False,
        "errors": [{"type": "OSError", "reason": "reader unavailable"}],
    }
    calls = _patch_capture_owner(monkeypatch, owner_result=failed_inner)

    report = capture_module.capture(Path("installation.json"), PROVINCE_ID)

    assert report == {
        "schema": capture_module.SCHEMA,
        "observer": "FRA",
        "object": {"type": "province", "province_id": PROVINCE_ID},
        "capture": failed_inner,
    }
    assert calls["two_pass"] == []


def test_capture_rejects_noncanonical_ids_before_opening_the_owner(monkeypatch):
    def unexpected(*_args, **_kwargs):
        pytest.fail("owner must not be called for an invalid province ID")

    monkeypatch.setattr(capture_module._owner, "_capture_common", unexpected)
    for province_id in (True, 0, -1, 0x10000):
        with pytest.raises(ValueError, match="PROVINCE_TRADE_POWER_REQUEST_SCOPE"):
            capture_module.capture(Path("installation.json"), province_id)


def test_capture_rejects_non_fra_observer_before_opening_the_owner(monkeypatch):
    def unexpected(*_args, **_kwargs):
        pytest.fail("owner must not be called for a non-FRA observer")

    monkeypatch.setattr(capture_module._owner, "_capture_common", unexpected)
    with pytest.raises(ValueError, match="PROVINCE_TRADE_POWER_REQUEST_SCOPE"):
        capture_module.capture(Path("installation.json"), PROVINCE_ID, observer="ENG")


def test_replay_callback_rejects_wrong_country_before_reading_province_state(monkeypatch):
    observe_calls = []
    two_pass_calls = []

    def observe(_reader, _base, country, _profile, *, backend_reader):
        observe_calls.append(country)
        return backend_reader(_ReadSentinel(), MODULE_BASE, "ENG")

    def two_pass(*_args, **_kwargs):
        two_pass_calls.append(True)
        return _backend_result()

    monkeypatch.setattr(capture_module._owner, "_observe", observe)
    monkeypatch.setattr(capture_module._province, "read_two_pass", two_pass)

    with pytest.raises(ValueError, match="PROVINCE_TRADE_POWER_OBSERVER_SCOPE"):
        capture_module._observe_for(PROVINCE_ID)(
            _ReadSentinel(), MODULE_BASE, "FRA", {"profile_id": "test"},
        )
    assert observe_calls == ["FRA"]
    assert two_pass_calls == []


def test_validator_requires_access_and_replays_the_same_province_field(monkeypatch):
    stack_calls = _patch_capture_owner(monkeypatch)
    validator_calls = _patch_validator(monkeypatch)
    report = _outer_report()

    assert capture_module.validate_capture(report, CONTEXT, CREATION, PROVINCE_ID)

    args = validator_calls[0]
    assert args["report"] == report["capture"]
    assert args["context"] == CONTEXT
    assert args["creation"] == CREATION
    assert args["country"] == "FRA"
    assert args["schema"] == capture_module.INNER_SCHEMA
    assert args["profile_sha256"] == capture_module.PROFILE_SHA256
    assert callable(args["load_profile"])
    assert args["allow_observer_target"] is True
    assert args["require_access"] is True
    assert len(stack_calls["two_pass"]) == 1
    assert stack_calls["two_pass"][0][2:5] == (PROVINCE_ID, "FRA", (FIELD,))
    assert stack_calls["two_pass"][0][5] is trade_power_memory.read_fields


def test_validator_rejects_malformed_outer_envelope_without_replay(monkeypatch):
    calls = _patch_validator(monkeypatch)
    reports = []

    wrong_schema = _outer_report()
    wrong_schema["schema"] = "information.foreign_capture.v1"
    reports.append(wrong_schema)

    wrong_observer = _outer_report()
    wrong_observer["observer"] = "ENG"
    reports.append(wrong_observer)

    wrong_object_type = _outer_report()
    wrong_object_type["object"]["type"] = "country"
    reports.append(wrong_object_type)

    wrong_object_id = _outer_report()
    wrong_object_id["object"]["province_id"] = PROVINCE_ID + 1
    reports.append(wrong_object_id)

    boolean_object_id = _outer_report()
    boolean_object_id["object"]["province_id"] = True
    reports.append(boolean_object_id)

    extra_outer_key = _outer_report()
    extra_outer_key["extra"] = "not in the capture schema"
    reports.append(extra_outer_key)

    missing_inner_capture = _outer_report()
    del missing_inner_capture["capture"]
    reports.append(missing_inner_capture)

    for report in reports:
        assert not capture_module.validate_capture(report, CONTEXT, CREATION, PROVINCE_ID)
    assert calls == []


def test_validator_rejects_invalid_requested_ids_before_replay(monkeypatch):
    calls = _patch_validator(monkeypatch)
    report = _outer_report()

    for province_id in (True, 0, -1, 0x10000):
        assert not capture_module.validate_capture(report, CONTEXT, CREATION, province_id)
    assert calls == []


def test_frozen_profile_pin_layout_and_dependencies_match():
    profile = capture_module._load_profile()

    assert profile["profile_id"] == "province-trade-power-memory-1374"
    assert profile["profile_version"] == 1
    assert profile["game_version"] == "1.37.4"
    assert profile["layout"]["province_trade_power"] == capture_module._LAYOUT
    assert profile["semantics"]["supported_fields"] == [FIELD]
    assert profile["semantics"]["unit"] == "trade_power"
    assert profile["semantics"]["scale"] == 1000
    assert capture_module.PROFILE_FILE.stat().st_size <= 256 * 1024
