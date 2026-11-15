"""Coalition capture replay and normal R03 tool integration."""
from copy import deepcopy
from types import SimpleNamespace
import struct

import pytest

from bridge.information import InformationService
from bridge.information import coalition_capture as capture
from bridge.information import coalition_memory as memory
from bridge.information.coalitions import NativeCoalitionsSource
from bridge.information.composite import CompositeSource
from bridge.information.country_rivals import NativeCountryRivalsSource
from bridge.information.tools import InformationTools
from bridge.tests import test_information_country_faith_capture as faith_fixture
from bridge.tests import test_information_foreign_technology_capture as parent_fixture
from bridge.tests.test_information_foreign_economy import BaseSource


NODE = 0x6800000000


def make_capture(country="ENG", *, admitted=True, changed=False):
    profile = capture._load_profile()
    image, fixture = faith_fixture._make_image("ENG", profile, admitted=admitted)
    for tag, row in fixture["bindings"].items():
        pointer = row["country_pointer"]
        image.put_u64(pointer + memory.TARGET_OFFSET, 0)
        image.put(pointer + memory.MEMBERS_OFFSET, b"\0" * 24)
    fra = fixture["bindings"]["FRA"]["country_pointer"]
    eng = fixture["bindings"]["ENG"]["country_pointer"]
    admission = parent_fixture.admission
    own_slot = fixture["bindings"]["FRA"]["slot"]
    own_row = parent_fixture.RELATION_TABLE + own_slot * admission.RELATION_ROW_STRIDE
    image.put_u64(own_row + admission.RELATION_ROW_OWNER_OFFSET, parent_fixture.RELATION_OWNER)
    image.put_u64(own_row + admission.RELATION_ROW_RECIPIENT_FULLREF_OFFSET, fixture["refs"]["FRA"])
    own_counter = (parent_fixture.RELATION_COUNTERS + admission.RELATION_COUNTER_FIRST_OFFSET
                   + own_slot * admission.RELATION_COUNTER_STRIDE)
    image.put_i32(own_counter, 1)
    image.put(fra + memory.MEMBERS_OFFSET, struct.pack("<QQiB3x", NODE, NODE, 1, 0))
    image.put(NODE, struct.pack("<QQQB7x", fixture["refs"]["ENG"], 0, 0, 0))
    image.put_u64(eng + memory.TARGET_OFFSET, fixture["refs"]["FRA"])
    if changed:
        def change_target(memory_image, address, _size, label, count):
            if label == "coalition.ENG.target" and count == 2:
                memory_image.put_u64(address, 0)
        image.on_read = change_target
    reader = parent_fixture.RecordingReader(image)
    observation = capture._observe(reader, parent_fixture.MODULE_BASE, country, profile)
    identity = {"binding_verified": True, "process_creation_filetime": parent_fixture.CREATION,
                "process_path": "synthetic-eu4.exe", "process_path_sha256": capture._owner.EXE_SHA256}
    report = {
        "schema": capture.SCHEMA, "status": "observed", "completed": True,
        "profile_sha256": capture.PROFILE_SHA256,
        "request": {"country": country, "observer": "FRA", "creation_filetime": parent_fixture.CREATION,
                    "session_id": parent_fixture.SESSION_ID},
        "identity": identity, "identity_after": deepcopy(identity),
        "module_base": hex(parent_fixture.MODULE_BASE), "observation": observation,
        "raw_reads": reader.read_log,
        "cleanup": {"status": "closed", "closed": True, "success": True},
        "access": {"read_only": True, "native_function_invoked": False, "writes": False,
                   "UI_control": False, "date_advance": False, "save_or_reload": False,
                   "limit_bytes": capture._owner.MAX_READ_BYTES,
                   "calls": reader.calls, "bytes_requested": reader.bytes_requested},
    }
    context = {"status": "ready", "mode": "live", "observer": "FRA",
               "session_id": parent_fixture.SESSION_ID, "game_version": "1.37.4",
               "game_sha256": capture._owner.EXE_SHA256, "game_date": parent_fixture.GAME_DATE}
    return report, context


def query(country="ENG"):
    return {"topic": "R03", "object": {"type": "country", "country": country},
            "fields": ["coalition_members", "targets"], "parameters": {}}


@pytest.mark.parametrize("country,expected", [("FRA", (["ENG"], [])), ("ENG", ([], ["FRA"]))])
def test_exact_trace_replay_preserves_both_coalition_directions(country, expected):
    report, context = make_capture(country)
    assert capture.validate_capture(report, context, parent_fixture.CREATION, country)
    fields = report["observation"]["backend"]["targets"][0]["fields"]
    assert [fields[name]["value"] for name in memory.FIELDS] == list(expected)


def test_change_between_passes_keeps_only_the_unaffected_field_known():
    report, context = make_capture("FRA", changed=True)
    assert capture.validate_capture(report, context, parent_fixture.CREATION, "FRA")
    fields = report["observation"]["backend"]["targets"][0]["fields"]
    assert fields[memory.FIELDS[0]]["status"] == "unknown"
    assert fields[memory.FIELDS[1]]["value"] == []


@pytest.mark.parametrize("tamper", ["field", "trace", "session", "creation", "date", "cleanup"])
def test_replay_rejects_changed_payload_trace_or_identity(tamper):
    report, context = make_capture()
    creation = parent_fixture.CREATION
    if tamper == "field":
        report["observation"]["backend"]["targets"][0]["fields"][memory.FIELDS[1]]["value"] = ["CAS"]
    elif tamper == "trace":
        report["raw_reads"][-1]["raw_hex"] = "00"
    elif tamper == "session":
        context["session_id"] = "other-session"
    elif tamper == "creation":
        creation += 1
    elif tamper == "date":
        context["game_date"] += 24
    else:
        report["cleanup"]["closed"] = False
    assert not capture.validate_capture(report, context, creation, "ENG")


def test_denied_country_remains_invisible():
    report, context = make_capture(admitted=False)
    assert capture.validate_capture(report, context, parent_fixture.CREATION, "ENG")
    fields = report["observation"]["backend"]["targets"][0]["fields"]
    assert all(field["status"] == "invisible" for field in fields.values())


def test_normal_tools_report_and_foreign_scope_do_not_inherit_rivals_observer_limit(tmp_path):
    report, context = make_capture()
    base = BaseSource(tmp_path)
    base.current = context
    base.session = SimpleNamespace(directory=tmp_path, creation_filetime=parent_fixture.CREATION,
                                   record={"creation_filetime": parent_fixture.CREATION})
    base.poll_events = lambda context, cursor: {"events": [], "cursor": cursor, "complete": True}
    calls = []

    def recorded_capture(installation, country, *, observer):
        calls.append((country, observer))
        return deepcopy(report)

    source = CompositeSource(base, [NativeCountryRivalsSource(base),
                                   NativeCoalitionsSource(base, capture=recorded_capture)])
    now = [1000.0]
    database = tmp_path / "coalition-service.sqlite3"
    service = InformationService(source, database, clock=lambda: now[0])
    tools = InformationTools(service)
    try:
        full = tools.call("information_query", {"request_id": "coalition-query", "queries": [query()], "view": "full"})
        fields = full["items"][0]["fields"]
        assert fields["coalition_members"]["value"] == []
        assert fields["targets"]["value"] == ["FRA"]
        assert calls == [("ENG", "FRA")]
        concise = tools.call("information_get_result", {"result_id": full["result_id"]})
        assert concise["items"] == [{"country": "ENG", "coalition_members": [], "targets": ["FRA"]}]
        saved = tools.call("information_manage_report", {"request_id": "coalition-report", "operation": "create",
            "config": {"name": "opposing coalitions", "queries": [query()], "detail": "brief"}})["report"]
        replay = tools.call("information_query", {"request_id": "coalition-report-query", "report_id": saved["id"]})
        assert replay["items"] == concise["items"]
        subscriptions = []
        for kind in ("periodic", "change"):
            subscriptions.append(tools.call("information_manage_subscription", {
                "request_id": "coalition-" + kind, "operation": "create",
                "config": {"name": kind, "kind": kind, "report_id": saved["id"], "enabled": True,
                           "schedule": {"basis": "real", "every": 1, "unit": "seconds", "missed": "coalesce"}},
            })["subscription"])
        now[0] += 1
        delivery = tools.call("information_tick", {"view": "full"})["results"]
        assert [item["subscription_id"] for item in delivery] == [subscriptions[0]["id"]]
        assert delivery[0]["items"][0]["fields"]["targets"]["value"] == ["FRA"]
        for subscription in subscriptions:
            tools.call("information_manage_subscription", {"request_id": "cancel-" + subscription["id"],
                "operation": "cancel", "subscription_id": subscription["id"],
                "expected_version": subscription["version"]})
    finally:
        service.close()
    reopened = InformationService(source, database)
    try:
        assert InformationTools(reopened).call("information_get_result", {"result_id": full["result_id"]}) == concise
    finally:
        reopened.close()
