"""Cross-request last-known values for the macro decision topics.

These tests deliberately use the public information tools with a small live
source.  The source has no historical behavior of its own, so every
``last_known`` value must come from the service result store and must obey the
current report and world identity.
"""

from __future__ import annotations

from copy import deepcopy
import json

import pytest

from bridge.information import InformationService
from bridge.information.tools import InformationTools
from bridge.information.presentation import present_result


MACRO_TOPICS = ("N01", "N02", "N03", "N04")
NON_MACRO_TOPICS = ("N05", "N06")
ALL_TOPICS = MACRO_TOPICS + NON_MACRO_TOPICS + ("A01",)


class MacroClock:
    def __init__(self, now: float = 100.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class MacroSource:
    """Minimal live source with controllable per-field status and identity."""

    event_types = ["battle"]

    def __init__(self, *, world_id: str | None = "world-a") -> None:
        self.session_id = "session-a"
        self.observer = "FRA"
        self.game_version = "1.37.4"
        self.world_id = world_id
        self.game_sha256 = "a" * 64
        self.dll_sha256 = "b" * 64
        self.game_day = 100
        self.game_date = 100
        self.values: dict[tuple[str, str], object] = {
            (topic, "value"): 10 for topic in ALL_TOPICS
        }
        self.statuses: dict[tuple[str, str], tuple[str, str | None]] = {}
        self.event_pages: list[dict] = []

    def context(self) -> dict:
        return {
            "status": "ready",
            "mode": "live",
            "session_id": self.session_id,
            "observer": self.observer,
            "game_version": self.game_version,
            "world_id": self.world_id,
            "game_sha256": self.game_sha256,
            "dll_sha256": self.dll_sha256,
            "game_day": self.game_day,
            "game_date": self.game_date,
            "paused": False,
        }

    def catalog(self) -> list[dict]:
        return [
            {
                "topic_id": topic,
                "status": "available",
                "context_scope": "live",
                "fields": {
                    "value": {"type": "integer", "unit": "fixture_units"},
                },
                "object_types": ["country"],
                "parameters": {
                    "type": "object",
                    "properties": {"tag": {"type": "string"}},
                    "additionalProperties": False,
                },
                "supported_versions": [self.game_version],
                "triggers": ["query", "periodic", "event", "change"],
            }
            for topic in ALL_TOPICS
        ]

    def validate_query(self, query: dict) -> dict:
        return deepcopy(query)

    def read(self, query: dict, context: dict) -> dict:
        fields = {}
        for name in query["fields"]:
            status, reason = self.statuses.get((query["topic"], name), ("known", None))
            if status == "known":
                fields[name] = {
                    "status": "known",
                    "value": self.values[(query["topic"], name)],
                    "complete": True,
                    "provenance": {"fixture_private": "keep-in-full-result"},
                }
            else:
                fields[name] = {"status": status, **({"reason": reason} if reason else {})}
        return {
            "fields": fields,
            "complete": all(field["status"] in {"known", "not_applicable"}
                             for field in fields.values()),
            "source": {"name": "macro-last-known-fixture"},
        }

    def poll_events(self, context: dict, cursor) -> dict:
        if self.event_pages:
            return deepcopy(self.event_pages.pop(0))
        return {"events": [], "cursor": cursor, "complete": True, "gaps": []}

    def set_status(self, topic: str, status: str, reason: str | None = None) -> None:
        self.statuses[(topic, "value")] = (status, reason)

    def set_date(self, value: int) -> None:
        self.game_day = value
        self.game_date = value


def _query(topic: str = "N01", *, tag: str | None = None) -> dict:
    return {
        "topic": topic,
        "object": {"type": "country", "country": "FRA"},
        "fields": ["value"],
        "parameters": {} if tag is None else {"tag": tag},
    }


def _tools(tmp_path, *, owner: str = "llm", world_id: str | None = "world-a"):
    source = MacroSource(world_id=world_id)
    clock = MacroClock()
    service = InformationService(source, tmp_path / f"{owner}.sqlite3", clock=clock, owner=owner)
    return service, source, clock, InformationTools(service)


def _report(tools: InformationTools, query: dict, *, request_id: str = "report-create", detail: str = "brief") -> dict:
    return tools.call("information_manage_report", {
        "request_id": request_id,
        "operation": "create",
        "config": {"name": "macro fixture", "queries": [query], "detail": detail},
    })["report"]


def _field(result: dict, name: str = "value") -> dict:
    return result["items"][0]["fields"][name]


def _query_report(tools: InformationTools, request_id: str, report: dict) -> dict:
    return tools.call("information_query", {"view": "full", "request_id": request_id, "report_id": report["id"]})


@pytest.mark.parametrize("topic", MACRO_TOPICS)
def test_each_macro_topic_attaches_last_known_on_unavailable_field(tmp_path, topic):
    service, source, _clock, tools = _tools(tmp_path)
    try:
        report = _report(tools, _query(topic))
        first = _query_report(tools, f"{topic}-known", report)
        source.set_status(topic, "unavailable", "temporary-native-read")
        failed = _query_report(tools, f"{topic}-failed", report)
        current = _field(failed)
        assert current["status"] == "unavailable"
        assert current["reason"] == "temporary-native-read"
        history = current["last_known"]
        assert history["field"] == _field(first)
        assert history["result_id"] == first["result_id"]
        assert history["collected_at"] == first["collected_at"]
        assert history["context"] == first["context"]
        assert history["basis"] == "previous_successful_field_observation"
        assert failed["detail"] == "brief"
        stored = tools.call("information_get_result", {"view": "full", "result_id": failed["result_id"]})
        stored_field = stored["items"][0]["fields"]["value"]
        assert stored_field["status"] == current["status"]
        assert stored_field["reason"] == current["reason"]
        assert stored_field["last_known"]["result_id"] == history["result_id"]
    finally:
        service.close()


def test_manual_and_periodic_results_share_report_history(tmp_path):
    service, source, clock, tools = _tools(tmp_path)
    try:
        report = _report(tools, _query())
        first = _query_report(tools, "manual-known", report)
        subscription = tools.call("information_manage_subscription", {
            "request_id": "periodic-create", "operation": "create",
            "config": {
                "name": "periodic", "kind": "periodic", "report_id": report["id"],
                "enabled": True,
                "schedule": {"basis": "real", "every": 10, "unit": "seconds", "missed": "coalesce"},
            },
        })["subscription"]
        source.set_status("N01", "unavailable", "tick-unavailable")
        clock.advance(10)
        generated = tools.call("information_tick", {"view": "full"})["results"]
        assert len(generated) == 1
        current = _field(generated[0])
        assert current["status"] == "unavailable"
        assert current["reason"] == "tick-unavailable"
        assert current["last_known"]["result_id"] == first["result_id"]
        assert generated[0]["subscription_id"] == subscription["id"]
    finally:
        service.close()


def test_zero_is_retained_and_latest_known_field_wins(tmp_path):
    service, source, _clock, tools = _tools(tmp_path)
    try:
        report = _report(tools, _query())
        source.values[("N01", "value")] = 0
        first = _query_report(tools, "zero-known", report)
        source.values[("N01", "value")] = 9
        second = _query_report(tools, "nine-known", report)
        source.set_status("N01", "unknown", "not-read-this-pass")
        failed = _query_report(tools, "unknown-after-known", report)
        history = _field(failed)["last_known"]
        assert history["field"]["value"] == 9
        assert history["result_id"] == second["result_id"]
        assert history["field"]["value"] != first["items"][0]["fields"]["value"]["value"]
    finally:
        service.close()


def test_partial_fields_keep_their_independent_last_successful_observations(tmp_path):
    service, source, _clock, tools = _tools(tmp_path)
    original_catalog = source.catalog

    def catalog_with_second_field():
        topics = original_catalog()
        topics[0]["fields"]["other"] = {"type": "integer", "unit": "fixture_units"}
        return topics

    source.catalog = catalog_with_second_field
    source.values[("N01", "other")] = 0
    try:
        report = _report(tools, dict(_query(), fields=["value", "other"]))
        first = _query_report(tools, "partial-first", report)
        source.set_status("N01", "unavailable", "partial-failure")
        second = _query_report(tools, "partial-second", report)
        assert _field(second)["last_known"]["result_id"] == first["result_id"]
        assert _field(second, "other")["status"] == "known"
        assert "last_known" not in _field(second, "other")
        source.set_status("N01", "known")
        source.values[("N01", "value")] = 22
        source.statuses[("N01", "other")] = ("unknown", "other-read-failed")
        third = _query_report(tools, "partial-third", report)
        assert _field(third)["value"] == 22
        assert _field(third, "other")["last_known"]["field"]["value"] == 0
        assert _field(third, "other")["last_known"]["result_id"] == second["result_id"]
        source.set_status("N01", "unknown", "both-read-failed")
        fourth = _query_report(tools, "partial-fourth", report)
        assert _field(fourth)["last_known"]["result_id"] == third["result_id"]
        assert _field(fourth, "other")["last_known"]["result_id"] == second["result_id"]
    finally:
        service.close()


def test_normal_clock_progress_does_not_expire_a_historical_value(tmp_path):
    service, source, _clock, tools = _tools(tmp_path)
    try:
        report = _report(tools, _query())
        first = _query_report(tools, "before-years", report)
        source.set_date(100 + 24 * 365 * 10)
        source.set_status("N01", "unavailable", "later-read-failed")
        failed = _query_report(tools, "after-years", report)
        history = _field(failed)["last_known"]
        assert history["result_id"] == first["result_id"]
        assert history["context"]["game_date"] == 100
        assert failed["context"]["game_date"] == source.game_date
    finally:
        service.close()


def test_known_world_can_read_results_created_before_instance_metadata(tmp_path):
    service, source, _clock, tools = _tools(tmp_path)
    try:
        report = _report(tools, _query())
        first = _query_report(tools, "legacy-known", report)
        legacy = service.get_result(first["result_id"])
        legacy.pop("collection_instance_id")
        with service.db:
            service.db.execute("UPDATE info_results SET body=? WHERE owner=? AND id=?",
                               (json.dumps(legacy, sort_keys=True, separators=(",", ":")),
                                service.owner, first["result_id"]))
            service.db.execute("DELETE FROM info_runtime WHERE owner=?", (service.owner,))
        source.set_status("N01", "unavailable", "legacy-read-failed")
        failed = _query_report(tools, "legacy-failed", report)
        assert _field(failed)["last_known"]["result_id"] == first["result_id"]
    finally:
        service.close()


@pytest.mark.parametrize("status", ["invisible", "not_applicable", "unsupported", "stale"])
def test_non_fallback_statuses_keep_original_shape(tmp_path, status):
    service, source, _clock, tools = _tools(tmp_path)
    try:
        report = _report(tools, _query())
        _query_report(tools, f"{status}-known", report)
        source.set_status("N01", status, f"reason-{status}")
        failed = _query_report(tools, f"{status}-current", report)
        current = _field(failed)
        assert current["status"] == status
        assert current["reason"] == f"reason-{status}"
        assert "last_known" not in current
    finally:
        service.close()


def test_unknown_does_not_overwrite_previous_known_field(tmp_path):
    service, source, _clock, tools = _tools(tmp_path)
    try:
        report = _report(tools, _query())
        first = _query_report(tools, "known-before-unknown", report)
        source.set_status("N01", "unknown", "missing-now")
        failed = _query_report(tools, "unknown-current", report)
        current = _field(failed)
        assert current["status"] == "unknown"
        assert current["reason"] == "missing-now"
        assert current["last_known"]["field"] == first["items"][0]["fields"]["value"]
        assert "value" not in current
    finally:
        service.close()


@pytest.mark.parametrize("identity", ["session_id", "observer", "game_version", "world_id", "game_sha256", "dll_sha256"])
def test_identity_change_blocks_history(tmp_path, identity):
    service, source, _clock, tools = _tools(tmp_path)
    try:
        report = _report(tools, _query())
        _query_report(tools, f"identity-known-{identity}", report)
        source.set_status("N01", "unavailable", "identity-changed")
        if identity == "session_id":
            source.session_id = "session-b"
        elif identity == "observer":
            source.observer = "ENG"
        elif identity == "game_version":
            source.game_version = "1.37.5"
        elif identity == "world_id":
            source.world_id = "world-b"
        elif identity == "game_sha256":
            source.game_sha256 = "c" * 64
        else:
            source.dll_sha256 = "d" * 64
        failed = _query_report(tools, f"identity-failed-{identity}", report)
        assert _field(failed)["status"] == "unavailable"
        assert "last_known" not in _field(failed)
    finally:
        service.close()


def test_query_parameters_and_report_version_never_cross_history(tmp_path):
    service, source, _clock, tools = _tools(tmp_path)
    try:
        report = _report(tools, _query(tag="FRA"))
        first = _query_report(tools, "parameter-known", report)
        source.set_status("N01", "unavailable", "parameter-failed")
        changed_query = _query(tag="ENG")
        changed = tools.call("information_manage_report", {
            "request_id": "report-update", "operation": "update", "report_id": report["id"],
            "expected_version": report["version"],
            "config": {"name": "macro fixture", "queries": [changed_query], "detail": "brief"},
        })["report"]
        assert changed["version"] == report["version"] + 1
        parameter_failed = _query_report(tools, "parameter-failed", changed)
        assert "last_known" not in _field(parameter_failed)

        # The original report's version remains addressable only through a
        # fresh report object.  Its old successful result is still stored.
        assert tools.call("information_get_result", {"view": "full", "result_id": first["result_id"]})["result_id"] == first["result_id"]
    finally:
        service.close()


def test_report_version_change_alone_never_crosses_history(tmp_path):
    service, source, _clock, tools = _tools(tmp_path)
    try:
        query = _query(tag="FRA")
        report = _report(tools, query, request_id="version-only-report")
        _query_report(tools, "version-only-known", report)
        updated = tools.call("information_manage_report", {
            "request_id": "version-only-update", "operation": "update", "report_id": report["id"],
            "expected_version": report["version"],
            "config": {"name": "macro fixture renamed", "queries": [query], "detail": "brief"},
        })["report"]
        source.set_status("N01", "unavailable", "version-only-failure")
        failed = _query_report(tools, "version-only-failed", updated)
        assert updated["version"] == report["version"] + 1
        assert _field(failed)["reason"] == "version-only-failure"
        assert "last_known" not in _field(failed)
    finally:
        service.close()


def test_brief_hides_last_known_field_provenance_but_full_result_keeps_it(tmp_path):
    service, source, _clock, tools = _tools(tmp_path)
    try:
        report = _report(tools, _query(), request_id="provenance-report", detail="brief")
        _query_report(tools, "provenance-known", report)
        source.set_status("N01", "unavailable", "provenance-failure")
        brief = present_result(_query_report(tools, "provenance-failed", report))
        brief_history = _field(brief)["last_known"]["field"]
        assert "provenance" not in brief_history
        stored = tools.call("information_get_result", {"view": "full", "result_id": brief["result_id"]})
        full_history = _field(stored)["last_known"]["field"]
        assert full_history["provenance"] == {"fixture_private": "keep-in-full-result"}
    finally:
        service.close()


def test_non_macro_topics_are_never_backfilled(tmp_path):
    service, source, _clock, tools = _tools(tmp_path)
    try:
        for topic in NON_MACRO_TOPICS:
            report = _report(tools, _query(topic), request_id=f"report-{topic}")
            _query_report(tools, f"known-{topic}", report)
            source.set_status(topic, "unavailable", f"no-{topic}")
            failed = _query_report(tools, f"failed-{topic}", report)
            assert _field(failed)["status"] == "unavailable"
            assert "last_known" not in _field(failed)
    finally:
        service.close()


def test_event_result_does_not_attach_manual_history(tmp_path):
    service, source, clock, tools = _tools(tmp_path)
    try:
        report = _report(tools, _query())
        _query_report(tools, "event-history-known", report)
        source.set_status("N01", "unavailable", "event-read-failed")
        source.event_pages = [{
            "events": [{
                "event_id": "battle-1", "event_type": "battle", "actor": "FRA",
                "recipient": "BUR", "session_id": source.session_id,
                "observer": source.observer, "game_day": source.game_day,
            }],
            "cursor": "event-1", "complete": True, "gaps": [],
        }]
        tools.call("information_manage_subscription", {
            "request_id": "event-subscription", "operation": "create",
            "config": {
                "name": "event", "kind": "event", "report_id": report["id"], "enabled": True,
                "event": {"types": ["battle"]},
            },
        })
        result = tools.call("information_tick", {"view": "full"})["results"]
        assert len(result) == 1
        assert _field(result[0])["status"] == "unavailable"
        assert "last_known" not in _field(result[0])
    finally:
        service.close()


def test_known_world_reopen_can_use_persisted_history(tmp_path):
    database = tmp_path / "llm.sqlite3"
    service, source, _clock, tools = _tools(tmp_path)
    report = _report(tools, _query())
    first = _query_report(tools, "persisted-known", report)
    service.close()

    replacement = MacroSource(world_id="world-a")
    replacement.set_status("N01", "unavailable", "after-reopen")
    reopened = InformationService(replacement, database, owner="llm")
    try:
        reopened_tools = InformationTools(reopened)
        failed = _query_report(reopened_tools, "persisted-failed", report)
        assert _field(failed)["last_known"]["result_id"] == first["result_id"]
        assert reopened_tools.call("information_get_result", {"view": "full", "result_id": failed["result_id"]})["result_id"] == failed["result_id"]
    finally:
        reopened.close()


def test_missing_world_history_is_instance_local_and_not_reopened(tmp_path):
    database = tmp_path / "llm.sqlite3"
    service, source, _clock, tools = _tools(tmp_path, world_id=None)
    report = _report(tools, _query())
    _query_report(tools, "same-instance-known", report)
    source.set_status("N01", "unavailable", "same-instance-failure")
    same_instance = _query_report(tools, "same-instance-failed", report)
    assert "last_known" in _field(same_instance)
    service.close()

    replacement = MacroSource(world_id=None)
    replacement.set_status("N01", "unavailable", "reopened-failure")
    reopened = InformationService(replacement, database, owner="llm")
    try:
        failed = _query_report(InformationTools(reopened), "reopened-failed", report)
        assert "last_known" not in _field(failed)
    finally:
        reopened.close()


def test_date_rollback_clears_history_even_after_returning_to_old_date(tmp_path):
    service, source, _clock, tools = _tools(tmp_path)
    try:
        report = _report(tools, _query())
        _query_report(tools, "date-known", report)
        source.set_status("N01", "unavailable", "rollback-failure")
        source.set_date(99)
        rolled_back = _query_report(tools, "date-rollback", report)
        assert "last_known" not in _field(rolled_back)
        source.set_date(100)
        restored = _query_report(tools, "date-restored", report)
        assert "last_known" not in _field(restored)
    finally:
        service.close()


def test_owner_isolation_blocks_cross_owner_last_known(tmp_path):
    database = tmp_path / "owners.sqlite3"
    source_a = MacroSource()
    source_b = MacroSource()
    service_a = InformationService(source_a, database, owner="owner-a")
    service_b = InformationService(source_b, database, owner="owner-b")
    try:
        tools_a = InformationTools(service_a)
        tools_b = InformationTools(service_b)
        report_a = _report(tools_a, _query(), request_id="owner-a-report")
        _query_report(tools_a, "owner-a-known", report_a)
        report_b = _report(tools_b, _query(), request_id="owner-b-report")
        source_b.set_status("N01", "unavailable", "owner-b-failure")
        failed = _query_report(tools_b, "owner-b-failed", report_b)
        assert "last_known" not in _field(failed)
    finally:
        service_a.close()
        service_b.close()


def test_unknown_world_services_in_one_owner_do_not_share_history(tmp_path):
    database = tmp_path / "same-owner-unknown-world.sqlite3"
    source_a = MacroSource(world_id=None)
    source_b = MacroSource(world_id=None)
    service_a = InformationService(source_a, database, owner="same-owner")
    # A's collection instance is established before B opens the same store.
    service_b = InformationService(source_b, database, owner="same-owner")
    try:
        tools_a = InformationTools(service_a)
        tools_b = InformationTools(service_b)
        report = _report(tools_b, _query(), request_id="same-owner-report")
        known = _query_report(tools_b, "same-owner-b-known", report)
        assert known["collection_instance_id"] == service_b._history_generation

        source_a.set_status("N01", "unavailable", "a-read-failed")
        failed = _query_report(tools_a, "same-owner-a-failed", report)
        assert _field(failed)["status"] == "unavailable"
        assert "last_known" not in _field(failed)
    finally:
        service_a.close()
        service_b.close()


def test_change_subscription_failure_has_no_last_known_result(tmp_path):
    service, source, clock, tools = _tools(tmp_path)
    try:
        report = _report(tools, _query())
        subscription = tools.call("information_manage_subscription", {
            "request_id": "change-subscription", "operation": "create",
            "config": {
                "name": "change", "kind": "change", "report_id": report["id"], "enabled": True,
                "schedule": {"basis": "real", "every": 10, "unit": "seconds", "missed": "coalesce"},
            },
        })["subscription"]
        clock.advance(10)
        assert tools.call("information_tick", {"view": "full"})["results"] == []
        source.set_status("N01", "unavailable", "change-read-failed")
        clock.advance(10)
        assert tools.call("information_tick", {"view": "full"})["results"] == []
        runtime = tools.call("information_status", {"subscription_id": subscription["id"]})["subscriptions"][0]["runtime"]
        assert runtime["last_attempt"]["status"] == "read_failed_baseline_preserved"
        assert "last_known" not in str(runtime["last_attempt"])
    finally:
        service.close()

