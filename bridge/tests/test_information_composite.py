"""Independent state/rule sources retain separate scope and missing fields."""
from copy import deepcopy

import pytest

from bridge.information import InformationError, InformationService
from bridge.information.composite import CompositeSource


EMPTY = {"type": "object", "properties": {}, "additionalProperties": False}


def topic(name, fields, *, status="available", scope="game", version="1.37.4"):
    return {"topic_id": name, "catalog_ids": [name], "status": status,
            "fields": {field: {"coverage": "available" if status == "available" else "planned"} for field in fields},
            "parameters": EMPTY, "supported_versions": [version], "context_scope": scope,
            "object_types": ["session"], "triggers": ["query", "periodic", "change"]}


class Primary:
    event_types = ["request"]

    def __init__(self):
        self.current = {"status": "unready", "session_id": None, "game_version": None, "observer": None}
        self.reads = []
        self.polls = 0
        self.change_on_read = False

    def context(self):
        return deepcopy(self.current)

    def catalog(self):
        return [topic("C01", ["date"]), topic("T01", ["routes", "live_value"], status="planned"),
                topic("W02", ["score"], version="1.37.5")]

    def read(self, query, context):
        self.reads.append(deepcopy(query))
        if self.change_on_read:
            self.current["session_id"] = "session-b"
        return {"fields": {field: {"status": "known", "value": 7} for field in query["fields"]},
                "source": {"name": "primary"}, "complete": True}

    def poll_events(self, context, cursor):
        self.polls += 1
        return {"events": [], "cursor": "next", "complete": True, "gaps": []}


class Rules:
    def __init__(self):
        self.reads = []

    def catalog(self):
        return [topic("T01", ["routes"], scope="static_rules")]

    def validate_query(self, query):
        if query["object"] != {"type": "session"}:
            raise InformationError("invalid_object", "Invalid rule selector")
        assert query["fields"] == ["routes"]
        return deepcopy(query)

    def read(self, query, context):
        self.reads.append(deepcopy(query))
        return {"fields": {"routes": {"status": "known", "value": ["upstream", "downstream"]}},
                "source": {"name": "rules", "context_scope": "static_rules", "mode": "static"}, "complete": True}

    def poll_events(self, context, cursor):
        raise AssertionError("Read adapter must not duplicate primary event polling")


class EventRules(Rules):
    def __init__(self):
        super().__init__()
        self.event_reads = []

    def read_event(self, query, context, event):
        self.event_reads.append((deepcopy(query), deepcopy(event)))
        return {
            "fields": {
                "routes": {"status": "known", "value": event["payload"]["routes"]},
            },
            "source": {"name": "event-rules"},
            "complete": True,
        }


def query(name, fields):
    return {"topic": name, "object": {"type": "session"}, "fields": fields, "parameters": {}}


def ready(primary):
    primary.current = {"status": "ready", "session_id": "session-a", "game_version": "1.37.4", "observer": "FRA", "world_id": "world-a", "game_day": 1}


def test_static_read_without_running_game_does_not_invent_a_session(tmp_path):
    primary, rules = Primary(), Rules()
    service = InformationService(CompositeSource(primary, [rules]), tmp_path / "info.db")
    try:
        result = service.query("static", queries=[query("T01", ["routes"])])
        assert result["complete"] is True
        assert result["context"]["status"] == "unready"
        assert result["context"]["session_id"] is None
        assert result["items"][0]["source"]["mode"] == "static"
        assert primary.reads == []
    finally:
        service.close()


def test_mixed_query_preserves_static_success_when_live_source_is_unready(tmp_path):
    primary, rules = Primary(), Rules()
    service = InformationService(CompositeSource(primary, [rules]), tmp_path / "info.db")
    try:
        result = service.query("mixed", queries=[query("C01", ["date"]), query("T01", ["routes"])])
        assert result["status"] == "partial"
        assert result["items"][0]["fields"]["date"]["status"] == "unavailable"
        assert result["items"][1]["fields"]["routes"]["status"] == "known"
    finally:
        service.close()


def test_unsupported_version_of_one_topic_does_not_destroy_other_read(tmp_path):
    primary = Primary()
    ready(primary)
    service = InformationService(primary, tmp_path / "info.db")
    try:
        result = service.query("version", queries=[query("C01", ["date"]), query("W02", ["score"])])
        assert result["status"] == "partial"
        assert result["items"][0]["complete"] is True
        assert result["items"][1]["fields"]["score"]["reason"] == "unsupported_game_version"
        assert len(primary.reads) == 1
    finally:
        service.close()


def test_static_definitions_survive_live_session_change_but_live_values_do_not(tmp_path):
    primary, rules = Primary(), Rules()
    ready(primary)
    primary.change_on_read = True
    service = InformationService(CompositeSource(primary, [rules]), tmp_path / "info.db")
    try:
        result = service.query("change", queries=[query("C01", ["date"]), query("T01", ["routes"])])
        assert result["items"][0]["fields"]["date"]["status"] == "stale"
        assert result["items"][1]["fields"]["routes"]["status"] == "known"
    finally:
        service.close()


def test_missing_fields_remain_gaps_and_are_not_sent_to_narrow_adapter(tmp_path):
    primary, rules = Primary(), Rules()
    source = CompositeSource(primary, [rules])
    service = InformationService(source, tmp_path / "info.db")
    try:
        result = service.query("missing", queries=[query("T01", ["routes", "live_value"])])
        assert result["status"] == "partial"
        assert result["items"][0]["fields"]["live_value"]["status"] == "unsupported"
        assert rules.reads[0]["fields"] == ["routes"]
        source.poll_events(source.context(), None)
        assert primary.polls == 1
    finally:
        service.close()


def test_event_read_routes_to_adapter_hook_and_preserves_missing_field_contract():
    primary, rules = Primary(), EventRules()
    ready(primary)
    source = CompositeSource(primary, [rules])
    sample = source.read_event(
        query("T01", ["routes", "live_value"]),
        primary.context(),
        {"event_id": "routes-1", "payload": {"routes": ["event-route"]}},
    )

    assert sample["fields"]["routes"] == {"status": "known", "value": ["event-route"]}
    assert sample["fields"]["live_value"] == {
        "status": "unsupported",
        "reason": "FIELD_NOT_IMPLEMENTED_BY_ADAPTER",
    }
    assert rules.event_reads[0][0]["fields"] == ["routes"]
    assert primary.reads == []


def test_event_read_falls_back_to_legacy_adapter_read():
    primary, rules = Primary(), Rules()
    ready(primary)
    source = CompositeSource(primary, [rules])
    sample = source.read_event(
        query("T01", ["routes", "live_value"]),
        primary.context(),
        {"event_id": "routes-legacy", "payload": {"routes": ["current-route"]}},
    )

    assert sample["fields"]["routes"] == {
        "status": "known",
        "value": ["upstream", "downstream"],
    }
    assert sample["fields"]["live_value"]["status"] == "unsupported"
    assert rules.reads[0]["fields"] == ["routes"]


def test_duplicate_topic_routes_are_rejected():
    with pytest.raises(InformationError, match="T01") as error:
        CompositeSource(Primary(), [Rules(), Rules()])
    assert error.value.code == "duplicate_adapter_topic"


def test_default_fields_keep_existing_view_when_another_owner_needs_a_country(tmp_path):
    class CountryOnly:
        def catalog(self):
            item = topic("T01", ["live_value"], scope="country_scope")
            item["object_types"] = ["country"]
            return [item]

        def validate_query(self, query):
            raise InformationError("invalid_object", "country required")

        def read(self, query, context):
            raise AssertionError("Inapplicable owner must not read")

    primary = Primary()
    ready(primary)
    service = InformationService(CompositeSource(primary, [CountryOnly(), Rules()]), tmp_path/"views.db")
    try:
        # Omitting fields selects the catalog defaults, including the new
        # country-only field. Existing session rules must remain readable.
        result = service.query("default-view", queries=[{"topic": "T01", "object": {"type": "session"}}])
        fields = result["items"][0]["fields"]
        assert fields["routes"]["status"] == "known"
        assert fields["live_value"] == {"status": "not_applicable", "reason": "OBJECT_TYPE_NOT_SUPPORTED_BY_ADAPTER"}
        with pytest.raises(InformationError) as error:
            service.query("wrong-only-view", queries=[query("T01", ["live_value"])])
        assert error.value.code == "invalid_object"
    finally:
        service.close()


def _field_owner_topic(name, fields, *, scope, triggers):
    entry = topic("T01", fields, scope=scope)
    # Keep a shared selector schema so the cross-owner conflict test reaches
    # service normalization instead of failing as an unknown parameter.
    entry["parameters"] = {
        "type": "object",
        "properties": {"node_id": {"type": "string"}},
        "additionalProperties": False,
    }
    entry["source"] = name
    entry["object_types"] = ["session"]
    entry["supported_versions"] = ["1.37.4"]
    entry["triggers"] = list(triggers)
    for field in fields:
        entry["fields"][field].update({
            "owner": name,
            "object_types": ["session"],
            "supported_versions": ["1.37.4"],
            "triggers": list(triggers),
            "context_scope": scope,
        })
    return entry


class FieldOwner:
    """Small owner adapter used to test field-level routing contracts."""

    def __init__(self, name, fields, *, scope, triggers, fail=False, mutate=None):
        self.name = name
        self.fields = tuple(fields)
        self.scope = scope
        self.triggers = tuple(triggers)
        self.fail = fail
        self.mutate = mutate
        self.reads = []
        self.validated = []

    def catalog(self):
        return [_field_owner_topic(self.name, self.fields,
                                    scope=self.scope, triggers=self.triggers)]

    def validate_query(self, value):
        self.validated.append(deepcopy(value))
        assert set(value["fields"]).issubset(self.fields)
        return deepcopy(value)

    def read(self, value, context):
        self.reads.append(deepcopy(value))
        if self.fail:
            raise InformationError("owner_read_failed", self.name)
        fields = {
            field: {
                "status": "known",
                "value": f"{self.name}:{field}",
                "source": {
                    "name": self.name,
                    "field_owner": self.name,
                    "context_scope": self.scope,
                },
            }
            for field in value["fields"]
        }
        if self.mutate is not None:
            self.mutate()
        return {
            "fields": fields,
            "source": {"name": self.name, "context_scope": self.scope},
            "complete": True,
        }

    def poll_events(self, context, cursor):
        raise AssertionError("Field owners must not duplicate primary event polling")


def _field_routing_sources(*, live_fail=False, live_mutate=None):
    primary = Primary()
    static = FieldOwner("static-routes", ["routes"], scope="static_rules", triggers=("query",))
    live = FieldOwner("live-value", ["live_value"], scope="game",
                      triggers=("query", "periodic"), fail=live_fail, mutate=live_mutate)
    return primary, static, live, CompositeSource(primary, [static, live])


def test_same_topic_disjoint_field_owners_route_subqueries_and_preserve_metadata():
    primary, static, live, source = _field_routing_sources()
    ready(primary)
    mixed = query("T01", ["routes", "live_value"])

    static_entry = source.query_catalog(query("T01", ["routes"]))
    assert static_entry["fields"].keys() == {"routes"}
    assert static_entry["object_types"] == ["session"]
    assert static_entry["supported_versions"] == ["1.37.4"]
    assert static_entry["triggers"] == ["query"]
    assert static_entry["fields"]["routes"]["owner"] == "static-routes"
    assert static_entry["fields"]["routes"]["context_scope"] == "static_rules"

    capabilities = source.query_capabilities(mixed)
    assert len(capabilities) == 2
    by_owner = {entry["source"]: (subquery, entry) for subquery, entry in capabilities}
    assert by_owner["static-routes"][0]["fields"] == ["routes"]
    assert by_owner["live-value"][0]["fields"] == ["live_value"]
    assert by_owner["live-value"][1]["triggers"] == ["query", "periodic"]
    assert by_owner["live-value"][1]["fields"]["live_value"]["owner"] == "live-value"

    sample = source.read(mixed, primary.context())
    assert static.reads[0]["fields"] == ["routes"]
    assert live.reads[0]["fields"] == ["live_value"]
    assert sample["fields"]["routes"]["source"]["field_owner"] == "static-routes"
    assert sample["fields"]["live_value"]["source"]["field_owner"] == "live-value"
    assert sample["field_context_scopes"] == {
        "routes": "static_rules",
        "live_value": "game",
    }


def test_mixed_same_topic_owner_failure_keeps_other_field_known(tmp_path):
    primary, static, live, source = _field_routing_sources(live_fail=True)
    ready(primary)
    service = InformationService(source, tmp_path / "mixed-owner-failure.db")
    try:
        result = service.query("mixed-owner-failure", queries=[query("T01", ["routes", "live_value"])])
        item = result["items"][0]
        assert result["status"] == "partial"
        assert item["fields"]["routes"]["status"] == "known"
        assert item["fields"]["routes"]["source"]["field_owner"] == "static-routes"
        assert item["fields"]["live_value"]["status"] == "unavailable"
        assert item["complete"] is False
        assert static.reads[0]["fields"] == ["routes"]
        assert live.reads[0]["fields"] == ["live_value"]
    finally:
        service.close()


def test_static_field_survives_unready_and_context_change_live_field_does_not(tmp_path):
    primary, static, live, source = _field_routing_sources()
    service = InformationService(source, tmp_path / "field-scopes.db")
    try:
        unready = service.query("static-unready", queries=[query("T01", ["routes", "live_value"])])
        fields = unready["items"][0]["fields"]
        assert fields["routes"]["status"] == "known"
        assert fields["routes"]["source"]["field_owner"] == "static-routes"
        assert fields["live_value"]["status"] == "unavailable"
        assert primary.reads == []

        ready(primary)
        live.mutate = lambda: primary.current.update(session_id="session-b")
        changed = service.query("static-context-change", queries=[query("T01", ["routes", "live_value"])])
        fields = changed["items"][0]["fields"]
        assert fields["routes"]["status"] == "known"
        assert fields["routes"]["source"]["context_scope"] == "static_rules"
        assert fields["live_value"]["status"] == "stale"
        assert fields["live_value"]["reason"] == "context_changed_during_collection"
    finally:
        service.close()


def test_periodic_trigger_is_checked_per_owner_field(tmp_path):
    primary, static, live, source = _field_routing_sources()
    ready(primary)
    service = InformationService(source, tmp_path / "field-triggers.db")
    binding = {"session_id": "session-a", "observer": "FRA", "game_version": "1.37.4"}
    schedule = {"basis": "real", "every": 1, "unit": "seconds"}
    try:
        live_report = service.manage_report(
            "field-trigger-live-report", "create",
            config={"queries": [query("T01", ["live_value"])]},
        )["report"]
        live_subscription = service.manage_subscription(
            "field-trigger-live-subscription", "create",
            config={"kind": "periodic", "report_id": live_report["id"],
                    "binding": binding, "schedule": schedule},
        )
        assert live_subscription["subscription"]["state"] == "active"

        static_report = service.manage_report(
            "field-trigger-static-report", "create",
            config={"queries": [query("T01", ["routes"])]},
        )["report"]
        with pytest.raises(InformationError, match="periodic") as error:
            service.manage_subscription(
                "field-trigger-static-subscription", "create",
                config={"kind": "periodic", "report_id": static_report["id"],
                        "binding": binding, "schedule": schedule},
            )
        assert error.value.code == "unsupported_trigger"
    finally:
        service.close()


def test_cross_owner_object_parameter_conflict_is_rejected_during_normalization(tmp_path):
    primary, static, live, source = _field_routing_sources()
    ready(primary)
    service = InformationService(source, tmp_path / "field-conflict.db")
    conflicting = {
        "topic": "T01",
        "object": {"type": "session", "node_id": "routes"},
        "fields": ["routes", "live_value"],
        "parameters": {"node_id": "live_value"},
    }
    try:
        with pytest.raises(InformationError, match="node_id") as error:
            service.query("cross-owner-object-parameter-conflict", queries=[conflicting])
        assert error.value.code == "object_parameter_conflict"
        assert static.reads == []
        assert live.reads == []
    finally:
        service.close()
