"""Offline projection tests; all NSRC values here are synthetic test inputs.

The body cases reuse the existing synthetic v7 wrapper over the recorded FRA
v6 event. They do not represent a live name-source capture or rendered popup.
"""
import pytest

from bridge.information.battle_body_candidate import project_body_candidate
from bridge.information.battle_name_sources import (
    project_name_candidate,
    project_name_sources,
)
from bridge.tests.test_information_battle_display_context_integration import _v7_fixture
from work import information_battle_display_context_wire as v7_wire

def _field(raw: bytes = b"", state: str = "known") -> dict:
    return {"state": state, "length": len(raw), "raw_hex": raw.hex()}

def _decoded(**changes) -> dict:
    fields = {name: _field(raw) for name, raw in {
        "owner_name": b"", "global_name": b"PARIS",
        "battle_of_template": b"BATTLE_OF_", "language": b"l_english",
    }.items()}
    snapshot = dict(sequence=17, raw_date=9876, kind=1, raw_failure=0,
                    prefix_failure=0, transform_mode=1, text_fields=fields)
    snapshot.update(changes)
    return {
        "wire11": {"version": 11, "source": "owned_name_sources"},
        "observation": {"sequence": 17, "result": {"raw_date": 9876}},
        "context": {"kind": 1},
        "name_sources": snapshot,
    }

def _partial(result: dict) -> None:
    assert result["status"] in ("known", "unknown")
    assert result["not_raw_text"] is True
    for key in ("native_helper_invoked", "native_name_handoff_verified",
                "native_line1_verified", "full_display_complete",
                "visibility_verified", "complete"):
        assert result[key] is False

def test_original_helper_projects_literal_prefix_then_global_and_owner_raw_bytes():
    decoded = _decoded()
    source = project_name_sources(decoded)
    candidate = project_name_candidate(decoded)
    assert source["status"] == "known"
    assert source["capture_stage"] == "entry_before_client_gate"
    assert source["transform_mode"] == "original_helper"
    assert source["text_fields"]["owner_name"]["raw_hex"] == ""
    assert candidate["status"] == "known"
    assert candidate["decoded"] == {"status": "known", "value": "BATTLE_OF_PARIS"}
    assert candidate["raw_hex"] == b"BATTLE_OF_PARIS".hex()
    assert candidate["input_source"] == "owned_name_sources_candidate"
    _partial(source)
    _partial(candidate)

@pytest.mark.parametrize("mode,reason", [
    (0, "NAME_SOURCE_TRANSFORM_UNQUALIFIED"),
])
def test_unqualified_transform_never_concatenates(mode, reason):
    candidate = project_name_candidate(_decoded(transform_mode=mode))
    assert candidate["status"] == "unknown"
    assert candidate["reason"] == reason
    _partial(candidate)

def test_unknown_raw_group_preserves_known_prefix_and_known_raw_group_preserves_unknown_prefix():
    raw_unknown = _decoded(raw_failure=3)
    raw_unknown["name_sources"]["text_fields"].update(
        owner_name=_field(state="unknown"), global_name=_field(state="unknown"),
    )
    first = project_name_sources(raw_unknown)
    assert first["status"] == "known"
    assert first["text_fields"]["battle_of_template"]["decoded"]["value"] == "BATTLE_OF_"
    assert project_name_candidate(raw_unknown)["status"] == "unknown"

    prefix_unknown = _decoded(prefix_failure=4)
    prefix_unknown["name_sources"]["text_fields"].update(
        battle_of_template=_field(state="unknown"), language=_field(state="unknown"),
    )
    second = project_name_sources(prefix_unknown)
    assert second["status"] == "known"
    assert second["text_fields"]["global_name"]["raw_hex"] == b"PARIS".hex()
    assert project_name_candidate(prefix_unknown)["status"] == "unknown"

def test_absent_template_differs_from_known_empty_template():
    absent = _decoded()
    absent["name_sources"]["text_fields"]["battle_of_template"] = _field(state="absent")
    absent_projection = project_name_sources(absent)
    assert absent_projection["text_fields"]["battle_of_template"]["status"] == "absent"
    assert project_name_candidate(absent)["status"] == "unknown"

    empty = _decoded()
    empty["name_sources"]["text_fields"]["battle_of_template"] = _field(b"")
    empty_projection = project_name_sources(empty)
    assert empty_projection["text_fields"]["battle_of_template"]["status"] == "known"
    assert project_name_candidate(empty)["decoded"]["value"] == "PARIS"

@pytest.mark.parametrize("mutate", [
    lambda d: d["name_sources"].update(sequence=18),
    lambda d: d["name_sources"].update(raw_date=9877),
    lambda d: d["name_sources"].update(kind=2),
    lambda d: d["name_sources"].update(sequence=True),
    lambda d: d["name_sources"].update(raw_failure=True),
    lambda d: d["name_sources"]["text_fields"].update(owner_name=_field(state="unknown")),
    lambda d: d["name_sources"]["text_fields"].update(owner_name={
        "state": "unknown", "length": 1, "raw_hex": "41",
    }),
    lambda d: d["name_sources"]["text_fields"].update(global_name=_field(b"PA\x00RIS")),
    lambda d: d["name_sources"]["text_fields"].update(language=_field(b"english")),
])
def test_identity_scalars_groups_and_text_fields_are_strict(mutate):
    decoded = _decoded()
    mutate(decoded)
    result = project_name_sources(decoded)
    assert result["status"] == "unknown"
    assert result["reason"] == "NAME_SOURCES_INVALID_OR_EVENT_MISMATCH"
    _partial(result)

@pytest.mark.parametrize("name,raw", [
    ("owner_name", b"x" * 8193),
    ("global_name", b"x" * 8193),
    ("battle_of_template", b"x" * 8193),
    ("language", b"l_" + b"x" * 255),
])
def test_text_field_byte_limits_are_enforced(name, raw):
    decoded = _decoded()
    decoded["name_sources"]["text_fields"][name] = _field(raw)
    assert project_name_sources(decoded)["status"] == "unknown"

def test_bad_codec_keeps_copied_raw_bytes_but_blocks_candidate():
    decoded = _decoded()
    decoded["name_sources"]["text_fields"]["owner_name"] = _field(b"\x10")
    source = project_name_sources(decoded)
    owner = source["text_fields"]["owner_name"]
    assert owner["status"] == "known"
    assert owner["raw_hex"] == "10"
    assert owner["decoded"]["status"] == "unknown"
    assert project_name_candidate(decoded)["status"] == "unknown"

def _with_synthetic_sources(*, prefix: bytes, global_name: bytes, owner: bytes) -> dict:
    _, _, payload = _v7_fixture()
    decoded = v7_wire.decode(payload)
    obs = decoded["observation"]
    decoded.update(wire11={"version": 11, "source": "owned_name_sources"},
                   name_sources=_decoded()["name_sources"])
    decoded["name_sources"].update(sequence=obs["sequence"],
        raw_date=obs["result"]["raw_date"], kind=decoded["context"]["kind"])
    decoded["name_sources"]["text_fields"].update(
        battle_of_template=_field(prefix), global_name=_field(global_name), owner_name=_field(owner))
    return decoded

def test_same_v7_event_body_can_replace_name_from_pre_gate_candidate():
    decoded = _with_synthetic_sources(
        prefix=b"BATTLE_OF_", global_name=b"PARIS", owner=b"",
    )
    decoded["native_text"]["text_fields"]["title_helper_candidate"].update(
        status="unknown", state="unknown", raw_hex="",
    )
    candidate = project_body_candidate(decoded)
    assert candidate["status"] == "known"
    assert candidate["decoded"]["value"] == "BATTLE_OF_PARIS"
    assert candidate["input_source"] == "owned_name_sources_candidate"
    assert candidate["complete"] is False
    assert candidate["not_raw_text"] is True

def test_same_v7_event_conflicting_pre_gate_candidate_stays_unknown():
    candidate = project_body_candidate(_with_synthetic_sources(
        prefix=b"", global_name=b"LYON", owner=b"",
    ))
    assert candidate["status"] == "unknown"
    assert candidate["reason"] == "BODY_CANDIDATE_NAME_SOURCE_CONFLICT"
