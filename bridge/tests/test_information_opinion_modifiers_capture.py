from __future__ import annotations

from pathlib import Path

from bridge.information import opinion_modifiers_capture as capture


def test_capture_delegates_to_shared_readonly_owner(monkeypatch):
    calls = {}

    def fake_common(installation, country, **kwargs):
        calls.update(installation=installation, country=country, kwargs=kwargs)
        return {"status": "observed"}

    monkeypatch.setattr(capture._owner, "_capture_common", fake_common)
    installation = Path("C:/installation.json")
    assert capture.capture(installation, "ENG") == {"status": "observed"}
    assert calls["installation"] == installation
    assert calls["country"] == "ENG"
    assert calls["kwargs"]["observer"] == "FRA"
    assert calls["kwargs"]["schema"] == capture.SCHEMA
    assert calls["kwargs"]["profile_sha256"] == capture.PROFILE_SHA256
    assert calls["kwargs"]["load_profile"] is capture._memory._load_profile
    assert calls["kwargs"]["observe"] is capture._memory._observe


def test_capture_scope_rejects_non_tag_and_observer_target():
    for country in ("eng", "EN", "FRA", "FRA\x00"):
        try:
            capture.capture(Path("C:/installation.json"), country)
        except ValueError as exc:
            assert str(exc) == "OPINION_MODIFIERS_REQUEST_SCOPE"
        else:
            raise AssertionError(country)


def test_validate_capture_uses_strict_replay_and_required_access(monkeypatch):
    calls = {}

    def fake_validate(report, context, creation, country, **kwargs):
        calls.update(report=report, context=context, creation=creation,
                     country=country, kwargs=kwargs)
        return True

    monkeypatch.setattr(capture._owner, "_validate_capture_common", fake_validate)
    report = {"schema": capture.SCHEMA}
    context = {"observer": "FRA"}
    assert capture.validate_capture(report, context, 123, "ENG") is True
    assert calls["kwargs"]["schema"] == capture.SCHEMA
    assert calls["kwargs"]["profile_sha256"] == capture.PROFILE_SHA256
    assert calls["kwargs"]["load_profile"] is capture._memory._load_profile
    assert calls["kwargs"]["observe"] is capture._memory._observe
    assert calls["kwargs"]["require_access"] is True


def test_validate_capture_rejects_wrong_schema_without_owner_call(monkeypatch):
    monkeypatch.setattr(
        capture._owner, "_validate_capture_common",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("called")),
    )
    assert capture.validate_capture({"schema": "wrong"}, {}, 1, "ENG") is False
