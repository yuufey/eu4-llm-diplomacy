"""T01 literal-name delivery through CompositeSource and InformationService."""

from __future__ import annotations

from copy import deepcopy
import json

from bridge.information.catalog import list_topics, validate_query
from bridge.information.composite import CompositeSource
from bridge.information.service import InformationService
from bridge.information.static_data import StaticTradeSource


class _Clock:
    def __init__(self, now=100.0):
        self.now = float(now)

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += float(seconds)


class _LivePrimary:
    event_types = ()

    def __init__(self):
        self.session_id = "session-a"
        self.game_day = 100
        self.game_date = "1444.01.01"
        self.name_reads = 0
        self.native_calls = 0
        self.mission_calls = 0

    def context(self):
        return {
            "status": "ready",
            "mode": "live",
            "session_id": self.session_id,
            "observer": "FRA",
            "game_version": "1.37.4",
            "game_sha256": "game-sha",
            "world_id": "world-a",
            "game_day": self.game_day,
            "game_date": self.game_date,
            "paused": False,
        }

    def catalog(self):
        return list_topics()

    def validate_query(self, query, context=None):
        return validate_query(query, context)

    def read(self, query, context):
        self.name_reads += 1
        raise AssertionError("T01 must be handled by StaticTradeSource")

    def poll_events(self, context, cursor):
        return {"events": [], "cursor": deepcopy(cursor or {}), "complete": True, "gaps": []}


class _MutableLiteralReader:
    def __init__(self):
        self.text = "初始英吉利海峡"
        self.calls = []
        self.mission_calls = 0
        self.native_calls = 0

    def localized_text(self, country, context, keys):
        self.calls.append({
            "country": country,
            "context": deepcopy(context),
            "keys": list(keys),
            "text": self.text,
        })
        return {
            "status": "known",
            "language": "l_simp_chinese",
            "entries": {
                key: {
                    "status": "known",
                    "text": self.text,
                    "raw_template_hex": self.text.encode("utf-8").hex(),
                    "decoded_status": "decoded",
                }
                for key in keys
            },
            "provenance": {
                "reader": "fake-neutral-literal-reader",
                "capture_id": len(self.calls),
                "session_id": context.get("session_id"),
                "game_date": context.get("game_date"),
            },
        }


def _write_trade_fixture(root):
    (root / "common" / "tradenodes").mkdir(parents=True)
    (root / "launcher-settings.json").write_text(
        json.dumps({"rawVersion": "1.37.4"}), encoding="utf-8"
    )
    (root / "common" / "tradenodes" / "00_fixture.txt").write_text(
        "english_channel={location=1 members={1} outgoing={name=sevilla}}\n"
        "sevilla={location=2 members={2}}\n",
        encoding="utf-8",
    )


def _query(fields=("name",)):
    return {
        "topic": "T01",
        "object": {"type": "trade_node", "node_id": "english_channel"},
        "fields": list(fields),
        "parameters": {},
    }


def _build(tmp_path):
    root = tmp_path / "game"
    _write_trade_fixture(root)
    primary = _LivePrimary()
    reader = _MutableLiteralReader()
    static = StaticTradeSource(
        game_root=root,
        user_data=tmp_path / "user",
        enabled_mods=[],
        context_provider=primary.context,
        localization_reader=reader,
    )
    source = CompositeSource(primary, [static])
    clock = _Clock()
    service = InformationService(source, tmp_path / "information.sqlite3", clock=clock,
                                 owner="trade-name-delivery")
    return service, primary, static, reader, clock


def _subscription(service, request_id, report_id, every):
    return service.manage_subscription(
        request_id,
        "create",
        config={
            "name": f"trade-name-{every}",
            "kind": "periodic",
            "report_id": report_id,
            "binding": {
                "session_id": "session-a",
                "observer": "FRA",
                "game_version": "1.37.4",
                "world_id": "world-a",
            },
            "schedule": {
                "basis": "real",
                "every": every,
                "unit": "seconds",
                "missed": "coalesce",
            },
        },
    )["subscription"]


def test_t01_live_name_is_query_periodic_and_two_layer_provenance(tmp_path):
    service, primary, static, reader, clock = _build(tmp_path)
    try:
        topics = {item["topic_id"]: item for item in static.catalog()}
        assert topics["T01"]["triggers"] == ["query", "periodic"]
        assert "queryonly" not in topics["T01"]["triggers"]
        assert topics["G04"]["triggers"] == ["query"]
        assert topics["T02"]["triggers"] == ["query"]

        result = service.query("trade-name-query", queries=[_query()])
        item = result["items"][0]
        assert result["complete"] is True
        assert item["fields"]["name"] == {"status": "known", "value": "初始英吉利海峡"}
        assert primary.name_reads == 0
        assert len(reader.calls) == 1
        assert item["source"]["provenance"]["definitions_sha256"]
        assert item["source"]["name_localization"]["key"] == "english_channel"
        assert item["source"]["name_localization"]["status"] == "known"
        assert item["source"]["name_localization"]["reader_provenance"]["reader"] == "fake-neutral-literal-reader"
        assert item["source"]["name_localization"]["reader_provenance"]["capture_id"] == 1
    finally:
        service.close()


def test_periodic_report_subscriptions_collect_current_literal_each_due_tick_and_update_cancel(
    tmp_path,
):
    service, primary, _static, reader, clock = _build(tmp_path)
    try:
        report = service.manage_report(
            "trade-name-report-create",
            "create",
            config={"name": "trade names", "detail": "raw", "queries": [_query()]},
        )["report"]
        fast = _subscription(service, "trade-name-sub-fast", report["id"], 1)
        slow = _subscription(service, "trade-name-sub-slow", report["id"], 2)

        reader.text = "第一个周期"
        clock.advance(1)
        first = service.tick()
        assert len(first["results"]) == 1
        assert first["results"][0]["items"][0]["fields"]["name"]["value"] == "第一个周期"
        assert first["results"][0]["subscription_id"] == fast["id"]

        reader.text = "第二个周期"
        clock.advance(1)
        second = service.tick()
        assert {result["subscription_id"] for result in second["results"]} == {fast["id"], slow["id"]}
        assert all(
            result["items"][0]["fields"]["name"]["value"] == "第二个周期"
            for result in second["results"]
        )
        assert [call["text"] for call in reader.calls] == [
            "第一个周期", "第二个周期", "第二个周期"
        ]
        assert all(
            result["items"][0]["source"]["name_localization"]["reader_provenance"]["capture_id"]
            in (1, 2, 3)
            for result in [first["results"][0], *second["results"]]
        )

        updated = service.manage_subscription(
            "trade-name-sub-fast-update",
            "update",
            subscription_id=fast["id"],
            expected_version=fast["version"],
            config={
                "name": "trade-name-fast-updated",
                "kind": "periodic",
                "report_id": report["id"],
                "binding": fast["binding"],
                "schedule": {"basis": "real", "every": 3, "unit": "seconds", "missed": "coalesce"},
            },
        )["subscription"]
        assert updated["version"] == 2
        cancelled = service.manage_subscription(
            "trade-name-sub-slow-cancel",
            "cancel",
            subscription_id=slow["id"],
            expected_version=slow["version"],
        )["subscription"]
        assert cancelled["state"] == "cancelled"
    finally:
        service.close()


def test_session_change_invalidates_bound_periodic_reads_without_reader_or_mission_calls(tmp_path):
    service, primary, _static, reader, clock = _build(tmp_path)
    try:
        report = service.manage_report(
            "trade-name-session-report",
            "create",
            config={"name": "trade names", "queries": [_query()]},
        )["report"]
        subscription = _subscription(service, "trade-name-session-sub", report["id"], 1)
        clock.advance(1)
        service.tick()
        calls_before = len(reader.calls)

        primary.session_id = "session-b"
        reader.text = "不应被读取"
        clock.advance(1)
        stale = service.tick()
        assert stale["results"] == []
        assert len(reader.calls) == calls_before
        assert reader.native_calls == 0
        assert reader.mission_calls == 0
        state = service.status(subscription["id"])["subscriptions"][0]
        assert state["runtime"]["state"] == "scope_mismatch"
    finally:
        service.close()
