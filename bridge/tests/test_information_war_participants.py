"""W01 participant-list extension tests.

The side vectors used below are copied from the pinned R74 selected-offer
observation.  The test wraps that recorded QUERY4 ``native_war_context`` in a
synthetic QUERY1 ``wars[].participants`` extension; it is deliberately not a
claim that R74 emitted a new native QUERY1 result.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path

import pytest

from bridge.diplomacy import ObserverSession
from bridge.information import InformationService
from bridge.information.catalog import get_topic
from bridge.information.model import InformationError
from bridge.information.sources import DiplomacySource
from bridge.war_participants import project_war_participants
from tools import start_diplomacy_observer as observer_start


ROOT = Path(__file__).resolve().parents[2]
R74_PROBE = ROOT / "work/runtime/diplomacy-observer-20261020-r74-war-e/control-probe.jsonl"
R74_PROBE_SHA256 = "9529d2f7fedf69ccbc361adb9df53936a9356c352c1c773f8425bd475d52c633"
R74_DATE = 56553384
SESSION_ID = "24568-1dd6013342932bc"
WAR_ID = "war_7456bcce61621cef_00000001"
CAPABILITY = "native_war_participants_query"


def _r74_selected_offer() -> dict:
    """Read one bounded, pinned selected-offer line from the R74 probe."""

    assert R74_PROBE.is_file()
    assert R74_PROBE.stat().st_size <= 1_048_576
    digest = hashlib.sha256()
    selected = None
    with R74_PROBE.open("rb") as stream:
        for raw_line in stream:
            digest.update(raw_line)
            try:
                event = json.loads(raw_line.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                continue
            if (isinstance(event, dict)
                    and event.get("event") == "native_peace_empty_offer_inspection"
                    and event.get("query_id") == "inspect_d7d10bfd63b74ac4a67968a758f3d24d"
                    and event.get("actor") == "FRA"
                    and event.get("recipient") == "BUR"
                    and isinstance(event.get("native_war_context"), dict)):
                selected = event
    assert digest.hexdigest() == R74_PROBE_SHA256
    assert selected is not None
    context = selected["native_war_context"]
    assert context["side_a_members"] == [
        "FRA", "AMG", "AUV", "BOU", "FOI", "ORL", "SAV", "GNV"
    ]
    assert context["side_b_members"] == [
        "BUR", "HSA", "NEV", "BRB", "FLA", "HOL", "LAN", "RIG", "BRE", "HAM"
    ]
    assert context["actor_side"] == "side_a"
    assert context["recipient_side"] == "side_b"
    return selected


def _participants_from_r74() -> dict:
    selected = _r74_selected_offer()
    context = selected["native_war_context"]
    # This is an intentionally synthetic QUERY1 extension assembled from the
    # recorded QUERY4 vector, rather than a new native observation.
    return {
        "source": "native_war_side_vectors",
        "status": "available",
        "complete": True,
        "side_a": list(context["side_a_members"]),
        "side_b": list(context["side_b_members"]),
        "actor_side": context["actor_side"],
        "recipient_side": context["recipient_side"],
        "reason": None,
    }


def _unknown_participants(reason: str = "NATIVE_SIDE_CAPTURE_UNAVAILABLE") -> dict:
    return {
        "source": "native_war_side_vectors",
        "status": "unknown",
        "complete": False,
        "side_a": [],
        "side_b": [],
        "actor_side": None,
        "recipient_side": None,
        "reason": reason,
    }


def test_project_war_participants_accepts_r74_vector_and_is_pointer_free():
    value = _participants_from_r74()
    projected = project_war_participants(value, "FRA", "BUR")
    assert projected == value
    assert projected is not value
    assert set(projected) == {
        "source", "status", "complete", "side_a", "side_b",
        "actor_side", "recipient_side", "reason",
    }


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value.update({"private": "0x1234"}),
        lambda value: value["side_a"].append(value["side_a"][0]),
        lambda value: value["side_b"].append(value["side_a"][0]),
        lambda value: value.update(side_a=[]),
        lambda value: value.update(side_a=[f"{i:03d}" for i in range(257)]),
        lambda value: value.update(actor_side="attacker"),
        lambda value: value.update(recipient_side="defender"),
        lambda value: value.update(status="available", complete=False),
        lambda value: value.update(reason="BAD reason"),
    ],
)
def test_project_war_participants_rejects_malformed_or_private_vectors(mutation):
    value = _participants_from_r74()
    mutation(value)
    assert project_war_participants(value, "FRA", "BUR") is None


def test_project_war_participants_unknown_and_old_missing_extension_are_distinct():
    unknown = _unknown_participants()
    assert project_war_participants(unknown, "FRA", "BUR") == unknown
    assert project_war_participants(
        {**unknown, "side_a": ["FRA"]}, "FRA", "BUR") is None

    # A pre-extension QUERY1 row has no participants key.  The helper leaves
    # that absence alone; the source adapter below reports it as unknown.
    row = {
        "war_id": WAR_ID,
        "identity_scope": "observer_session",
        "actor": "FRA",
        "recipient": "BUR",
        "pair_at_war": True,
        "actor_war_role": None,
        "recipient_war_role": None,
        "roles_verified": False,
        "actor_is_war_leader": None,
        "recipient_is_war_leader": None,
        "leaders_verified": False,
        "context_complete": False,
    }
    assert "participants" not in row


def _synthetic_query1(participants: dict | None = None) -> dict:
    row = {
        "war_id": WAR_ID,
        "identity_scope": "observer_session",
        "actor": "FRA",
        "recipient": "BUR",
        "pair_at_war": True,
        "actor_war_role": None,
        "recipient_war_role": None,
        "roles_verified": False,
        "actor_is_war_leader": None,
        "recipient_is_war_leader": None,
        "leaders_verified": False,
        "context_complete": False,
        "native_war_reference": "0xprivate",
        "join_dates": ["private-only"],
    }
    if participants is not None:
        row["participants"] = deepcopy(participants)
    return {
        "event": "native_peace_context_inspection",
        "family": "peace",
        "query_id": "inspect_synthetic_query1_extension",
        "session_id": SESSION_ID,
        "action_id": "white_peace",
        "actor": "FRA",
        "recipient": "BUR",
        "phase": "initiate",
        "date_raw": R74_DATE,
        "discovery": True,
        "query_complete": True,
        "enumeration_complete": True,
        "native_offer_inspected": False,
        "full_rules_complete": False,
        "submitted": False,
        "wars": [row],
    }


def test_observer_validator_and_semantic_projection_preserve_only_member_tags():
    participants = _participants_from_r74()
    event = _synthetic_query1(participants)
    assert ObserverSession._valid_native_peace_context_inspection(
        event, "white_peace", "FRA", "BUR", "initiate", R74_DATE,
        event["query_id"], SESSION_ID)

    semantic = ObserverSession._semantic_peace_context_inspection(event)
    row = semantic["war_contexts"][0]
    assert row["participants"] == participants
    assert row["actor_war_role"] is None
    assert row["recipient_war_role"] is None
    assert row["leaders_verified"] is False
    assert "native_war_reference" not in row
    assert "join_dates" not in row
    assert "side_a_members" not in row

    malformed = deepcopy(event)
    malformed["wars"][0]["participants"]["side_a"].append("FRA")
    assert not ObserverSession._valid_native_peace_context_inspection(
        malformed, "white_peace", "FRA", "BUR", "initiate", R74_DATE,
        event["query_id"], SESSION_ID)


class _StubSession:
    """Bounded InformationSource session stand-in; never contacts a game."""

    def __init__(self, response: dict, *, mutation: str | None = None,
                 capabilities=frozenset({CAPABILITY})):
        self.response = deepcopy(response)
        self.mutation = mutation
        self.capabilities = capabilities
        self.session_id = SESSION_ID
        self.experiment_id = "information-war-participants-test"
        self.observer = "FRA"
        self.date_raw = R74_DATE
        self.inspect_calls: list[tuple[str, str, str, str]] = []

    def health(self) -> dict:
        return {
            "status": "ready",
            "complete": True,
            "session_id": self.session_id,
            "observer": self.observer,
            "game_version": "1.37.4",
            "game_sha256": "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77",
            "dll_sha256": "3d9e1fea9d8f34297a4a20646ea0b45d7d0f6a4af11cef6411586dd8b3264964",
            "game_date": self.date_raw,
            "game_day": self.date_raw // 24,
            "world_id": "r74-participants-test-world",
            "paused": True,
        }

    def installation_capabilities(self):
        return self.capabilities

    def inspect_peace_contexts(self, action_id, actor, recipient, phase):
        self.inspect_calls.append((action_id, actor, recipient, phase))
        if self.mutation == "session":
            self.session_id = "changed-session-after-query1"
        elif self.mutation == "date":
            self.date_raw += 24
        result = deepcopy(self.response)
        if self.mutation == "response-session":
            result["session_id"] = "foreign-session"
        elif self.mutation == "response-date":
            result["date_raw"] = R74_DATE + 24
        return result


class _StubDiplomacyTools:
    def __init__(self, session: _StubSession):
        self.session = session
        self.inspect_diplomatic_calls: list[tuple] = []

    def inspect_diplomatic_action(self, *args):
        self.inspect_diplomatic_calls.append(args)
        raise AssertionError("W01 must use ObserverSession.inspect_peace_contexts")


def _base_response(participants: dict | None = None, *, two_rows=False) -> dict:
    rows = []
    for index in range(2 if two_rows else 1):
        row = {
            "war_id": WAR_ID if index == 0 else "war_0123456789abcdef_00000004",
            "identity_scope": "observer_session",
            "actor": "FRA",
            "recipient": "BUR",
            "pair_at_war": True,
            "actor_war_role": None,
            "recipient_war_role": None,
            "roles_verified": False,
            "actor_is_war_leader": None,
            "recipient_is_war_leader": None,
            "leaders_verified": False,
            "context_complete": False,
        }
        if participants is not None:
            row["participants"] = deepcopy(participants)
        rows.append(row)
    return {
        "event": "native_peace_context_inspection",
        "family": "peace",
        "query_id": "inspect_information_participants",
        "session_id": SESSION_ID,
        "action_id": "white_peace",
        "actor": "FRA",
        "recipient": "BUR",
        "phase": "initiate",
        "date_raw": R74_DATE,
        "context_discovery": True,
        "query_complete": True,
        "war_context_enumeration_complete": True,
        "native_offer_inspected": False,
        "full_rules_complete": False,
        "submitted": False,
        "war_contexts": rows,
    }


def _query(fields=("war_id", "participants"), *, object_type="country_pair",
           war_id=None):
    obj = {"type": object_type, "actor": "FRA", "recipient": "BUR"}
    if war_id is not None:
        obj["war_id"] = war_id
    parameters = {"action_id": "white_peace", "phase": "initiate"}
    if war_id is not None:
        parameters["war_id"] = war_id
    return {
        "topic": "W01",
        "object": obj,
        "fields": list(fields),
        "parameters": parameters,
    }


def _service(tmp_path: Path, response: dict, *, mutation=None,
             capabilities=frozenset({CAPABILITY})):
    session = _StubSession(response, mutation=mutation, capabilities=capabilities)
    tools = _StubDiplomacyTools(session)
    source = DiplomacySource(tools, observer="FRA")
    service = InformationService(source, tmp_path / "information.sqlite3")
    return service, session, tools


def _item(result: dict) -> dict:
    assert len(result["items"]) == 1
    return result["items"][0]


def test_w01_information_source_projects_unique_explicit_members_once(tmp_path):
    participants = _participants_from_r74()
    service, session, tools = _service(tmp_path, _base_response(participants))
    try:
        result = service.query("w01-participants-unique", queries=[_query()])
        item = _item(result)
        assert item["complete"] is True and result["complete"] is True
        assert item["fields"]["war_id"] == {"status": "known", "value": WAR_ID}
        assert item["fields"]["participants"] == {
            "status": "known", "value": participants,
        }
        provenance = item["source"]["provenance"]
        assert provenance["participant_lists_complete"] is True
        assert provenance["side_roles_verified"] is False
        assert provenance["leaders_verified"] is False
        assert "join_dates" not in item["fields"]
        assert item["objects"] == [{
            "type": "war", "war_id": WAR_ID, "actor": "FRA", "recipient": "BUR",
        }]
        assert session.inspect_calls == [("white_peace", "FRA", "BUR", "initiate")]
        assert tools.inspect_diplomatic_calls == []

        # An explicit war object is still one QUERY1 reader call and selects
        # the same session-scoped row.
        service.close()
        service, session, tools = _service(
            tmp_path / "explicit", _base_response(participants))
        explicit = _query(object_type="war", war_id=WAR_ID)
        explicit_result = service.query("w01-participants-explicit", queries=[explicit])
        assert _item(explicit_result)["fields"]["participants"] == {
            "status": "known", "value": participants,
        }
        assert session.inspect_calls == [("white_peace", "FRA", "BUR", "initiate")]
        assert tools.inspect_diplomatic_calls == []
    finally:
        service.close()


def test_w01_information_source_preserves_old_missing_and_unknown_or_missing_capability(
        tmp_path):
    # Old QUERY1 has no extension: the war id remains known, but participants
    # are unknown rather than inferred from pair identity or counts.
    service, session, tools = _service(tmp_path / "old", _base_response())
    try:
        item = _item(service.query("w01-participants-old", queries=[_query()]))
        assert item["fields"]["war_id"] == {"status": "known", "value": WAR_ID}
        assert item["fields"]["participants"] == {
            "status": "unknown", "reason": "WAR_PARTICIPANTS_SOURCE_UNAVAILABLE",
        }
        assert item["complete"] is False
        assert len(session.inspect_calls) == 1
        assert tools.inspect_diplomatic_calls == []
    finally:
        service.close()

    service, session, tools = _service(
        tmp_path / "unknown", _base_response(_unknown_participants()))
    try:
        item = _item(service.query("w01-participants-unknown", queries=[_query()]))
        assert item["fields"]["participants"] == {
            "status": "unknown", "reason": "NATIVE_SIDE_CAPTURE_UNAVAILABLE",
        }
    finally:
        service.close()

    service, session, tools = _service(
        tmp_path / "capability", _base_response(_participants_from_r74()), capabilities=frozenset())
    try:
        item = _item(service.query("w01-participants-capability", queries=[_query()]))
        assert item["fields"]["war_id"] == {"status": "known", "value": WAR_ID}
        assert item["fields"]["participants"] == {
            "status": "unknown", "reason": "WAR_PARTICIPANTS_CAPABILITY_UNAVAILABLE",
        }
    finally:
        service.close()

    service, session, tools = _service(
        tmp_path / "capability-method-missing", _base_response(_participants_from_r74()))
    session.installation_capabilities = None
    try:
        item = _item(service.query(
            "w01-participants-capability-method-missing", queries=[_query()]))
        assert item["fields"]["participants"] == {
            "status": "unknown", "reason": "WAR_PARTICIPANTS_CAPABILITY_UNAVAILABLE",
        }
    finally:
        service.close()


def test_w01_information_source_selection_conflict_and_context_anomalies_do_not_retry(
        tmp_path):
    participants = _participants_from_r74()
    service, session, tools = _service(
        tmp_path / "multiple", _base_response(participants, two_rows=True))
    try:
        item = _item(service.query("w01-participants-multiple", queries=[_query()]))
        assert item["fields"]["war_id"] == {
            "status": "unknown", "reason": "WAR_SELECTION_REQUIRED",
        }
        assert item["fields"]["participants"] == {
            "status": "unknown", "reason": "WAR_SELECTION_REQUIRED",
        }
        assert len(session.inspect_calls) == 1
    finally:
        service.close()

    service, session, tools = _service(
        tmp_path / "conflict", _base_response(participants))
    try:
        conflicting = _query(war_id=WAR_ID)
        conflicting["parameters"]["war_id"] = "war_0123456789abcdef_00000009"
        with pytest.raises(InformationError) as raised:
            service.query("w01-participants-conflict", queries=[conflicting])
        assert raised.value.code == "object_parameter_conflict"
        assert session.inspect_calls == []
    finally:
        service.close()

    service, session, tools = _service(
        tmp_path / "forward-clock", _base_response(participants), mutation="date")
    try:
        item = _item(service.query("w01-participants-forward-clock", queries=[_query()]))
        assert item["fields"]["participants"] == {"status": "known", "value": participants}
        assert item["observation_window"]["end_game_date"] > item["observation_window"]["start_game_date"]
        assert len(session.inspect_calls) == 1
        assert tools.inspect_diplomatic_calls == []
    finally:
        service.close()

    for mutation, expected in (
            ("session", "WAR_DISCOVERY_CONTEXT_CHANGED"),
            ("response-session", "WAR_DISCOVERY_IDENTITY_MISMATCH"),
            ("response-date", "WAR_DISCOVERY_IDENTITY_MISMATCH")):
        service, session, tools = _service(
            tmp_path / mutation, _base_response(participants), mutation=mutation)
        try:
            item = _item(service.query(
                f"w01-participants-{mutation}", queries=[_query()]))
            assert item["fields"]["participants"] == {
                "status": "unknown", "reason": expected,
            }
            assert len(session.inspect_calls) == 1
            assert tools.inspect_diplomatic_calls == []
        finally:
            service.close()


def _installer_manifest(tmp_path: Path, *, participants: bool,
                        include_flag: bool = True) -> tuple[dict, Path]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    required = list(observer_start.INFORMATION_BATTLE_NATIVE_TITLE_QUERY_REQUIRED_SOURCES)
    if participants:
        required.extend(("peace-context-query.inc", "peace-war-context-query.inc",
                         "peace-war-side-members.inc"))
    names = list(dict.fromkeys(required))
    target = 118 + int(participants)
    names.extend(f"synthetic-source-{index:03d}.inc"
                 for index in range(target - len(names)))
    sources = []
    for name in names:
        path = tmp_path / name
        path.write_text("synthetic participant manifest source:" + name,
                        encoding="ascii")
        digest = observer_start.file_hash(path, refresh=True)
        sources.append({"name": name, "sha256": digest})
    manifest = {
        "version": 30,
        "information_battle_research_lifecycle": True,
        "information_battle_context_wire": 2,
        "information_battle_owned_context": True,
        "information_battle_naval_wire": 3,
        "information_battle_owned_naval": True,
        "information_battle_template_wire": 4,
        "information_battle_owned_template": True,
        "information_battle_message_scope": True,
        "information_battle_formatter_container": True,
        "information_battle_template_extensions": [1, 2],
        "information_battle_war_identity": True,
        "information_battle_war_identity_wire": 5,
        "information_battle_war_identity_scope": "observer_session",
        "information_battle_war_identity_read_only": True,
        "information_battle_war_identity_complete": False,
        "information_battle_native_text": True,
        "information_battle_native_text_wire": 6,
        "information_battle_native_text_scope": "observer_session",
        "information_battle_native_text_read_only": True,
        "information_battle_native_text_complete": False,
        "information_battle_native_title_query": True,
        "information_battle_native_title_query_mode": "native_helper_owned_output",
        "information_battle_native_title_query_wire": 6,
        "information_battle_native_title_query_complete": False,
        "compiler_arguments": [
            "-DBRIDGE_INFORMATION_BATTLE=1",
            "-DINFORMATION_BATTLE_CONTEXT=1",
            "-DINFORMATION_BATTLE_NAVAL=1",
            "-DINFORMATION_BATTLE_TEMPLATE=1",
            "-DINFORMATION_BATTLE_CONTAINER=1",
            "-DINFORMATION_BATTLE_WAR_IDENTITY=1",
            "-DINFORMATION_BATTLE_NATIVE_TEXT=1",
            "-DINFORMATION_BATTLE_NATIVE_TITLE_QUERY=1",
        ],
        "sources": sources,
    }
    if include_flag:
        manifest["native_war_participants_query"] = participants
    return manifest, tmp_path


def test_v30_participant_capability_manifest_accepts_118_or_119_sources(tmp_path):
    old_manifest, old_root = _installer_manifest(tmp_path / "old", participants=False)
    observer_start._validate_information_battle_manifest(old_manifest, old_root)
    assert len(old_manifest["sources"]) == 118

    new_manifest, new_root = _installer_manifest(tmp_path / "new", participants=True)
    observer_start._validate_information_battle_manifest(new_manifest, new_root)
    assert len(new_manifest["sources"]) == 119
    assert new_manifest["native_war_participants_query"] is True


def test_v30_participant_capability_manifest_rejects_bad_flag_shared_source_and_count(
        tmp_path):
    manifest, root = _installer_manifest(tmp_path / "bad-flag", participants=True)
    manifest["native_war_participants_query"] = "true"
    with pytest.raises(SystemExit, match="BUILD_MANIFEST_MISMATCH"):
        observer_start._validate_information_battle_manifest(manifest, root)

    manifest, root = _installer_manifest(tmp_path / "missing", participants=True)
    manifest["sources"] = [
        record for record in manifest["sources"]
        if record["name"] != "peace-war-side-members.inc"
    ]
    with pytest.raises(SystemExit, match="BUILD_MANIFEST_MISMATCH"):
        observer_start._validate_information_battle_manifest(manifest, root)

    manifest, root = _installer_manifest(tmp_path / "hash", participants=True)
    (root / "peace-war-context-query.inc").write_text("tampered", encoding="ascii")
    with pytest.raises(SystemExit, match="BUILD_MANIFEST_MISMATCH"):
        observer_start._validate_information_battle_manifest(manifest, root)

    manifest, root = _installer_manifest(tmp_path / "count", participants=True)
    manifest["sources"].pop()
    with pytest.raises(SystemExit, match="BUILD_MANIFEST_MISMATCH"):
        observer_start._validate_information_battle_manifest(manifest, root)


def test_observer_session_participant_capability_requires_exact_top_level_ack(tmp_path):
    def make_session(name: str, ack: dict) -> ObserverSession:
        directory = tmp_path / name
        directory.mkdir()
        installation = directory / "installation.json"
        installation.write_text(json.dumps({
            "experiment_id": "participant-ack-test",
            "session_id": "ack-session",
        }), encoding="utf-8")
        (directory / "control-probe.jsonl").write_text(
            json.dumps({
                "event": "diplomacy_observer_installed",
                "session_id": "ack-session",
                **ack,
            }) + "\n",
            encoding="utf-8",
        )
        return ObserverSession(installation, directory / "eu4.exe")

    exact = make_session("exact", {CAPABILITY: True})
    assert CAPABILITY in exact.installation_capabilities()
    copied = make_session("copied", {"caps": {CAPABILITY: True}})
    assert CAPABILITY not in copied.installation_capabilities()
    nonbool = make_session("nonbool", {CAPABILITY: "true"})
    assert CAPABILITY not in nonbool.installation_capabilities()


def test_w01_catalog_exposes_participants_as_partial_without_leader_inference():
    topic = get_topic("W01")
    field = topic["fields"]["participants"]
    assert field["paths"] == ["war_contexts[].participants"]
    assert field["capability"] == CAPABILITY
    assert topic["status"] == "available"
    assert "leaders" in topic["fields"]
    assert "join_dates" in topic["fields"]

