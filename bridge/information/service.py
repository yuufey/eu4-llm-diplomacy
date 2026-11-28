"""Durable read-only information service; all triggers share one query path.

SQLite transactions serialize configuration changes and scheduler claims. External
delivery is an explicit separate stage; the built-in outbox is durable receipt,
never proof that an LLM has read the information.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
import sqlite3
import threading
import time
import uuid

from .model import InformationError, canonical, digest, identifier, keys, utc_now
from .collection_lock import CollectionLock
from .catalog import observer_roles_for_query
from .observation_time import sampled_read

_EVENT_WAIT_REASONS = frozenset({"source_unavailable", "world_revalidation_required"})


def _initialize_sqlite(operation):
    """WAL negotiation can return BUSY immediately during concurrent first open.

    Retry only idempotent initialization, never a query, delivery or mutation.
    SQLite's normal busy timeout continues to govern later transactions.
    """
    deadline = time.monotonic() + 15
    while True:
        try:
            return operation()
        except sqlite3.OperationalError as exc:
            code = getattr(exc, "sqlite_errorcode", 0) & 0xff
            if code not in (sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED) or time.monotonic() >= deadline:
                raise
            time.sleep(min(0.05, max(0, deadline - time.monotonic())))


class InformationService:
    def __init__(self, source, database, output=None, clock=None, owner="llm"):
        self.source, self.output = source, output
        self.clock = clock or time.time
        self.owner = identifier(owner, "owner")
        self.lock = threading.RLock()
        self.collection_lock = CollectionLock(database)
        self._tick_guard = threading.Lock()
        self._last_tick_context = {}
        self._closed = False
        if str(database) != ":memory:":
            Path(database).parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(str(database), timeout=15, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        _initialize_sqlite(lambda: self.db.execute("PRAGMA journal_mode=WAL").fetchall())
        self.db.execute("PRAGMA synchronous=FULL")
        _initialize_sqlite(lambda: self.db.executescript("""
            CREATE TABLE IF NOT EXISTS info_config (
                owner TEXT NOT NULL, kind TEXT NOT NULL, id TEXT NOT NULL,
                version INTEGER NOT NULL, body TEXT NOT NULL,
                PRIMARY KEY(owner,kind,id));
            CREATE TABLE IF NOT EXISTS info_requests (
                owner TEXT NOT NULL, id TEXT NOT NULL, digest TEXT NOT NULL,
                response TEXT NOT NULL, PRIMARY KEY(owner,id));
            CREATE TABLE IF NOT EXISTS info_results (
                owner TEXT NOT NULL, id TEXT NOT NULL, body TEXT NOT NULL,
                PRIMARY KEY(owner,id));
            CREATE TABLE IF NOT EXISTS info_runtime (
                owner TEXT NOT NULL, id TEXT NOT NULL, body TEXT NOT NULL,
                PRIMARY KEY(owner,id));
            CREATE TABLE IF NOT EXISTS info_events (
                owner TEXT NOT NULL, scope TEXT NOT NULL, id TEXT NOT NULL,
                digest TEXT NOT NULL, body TEXT NOT NULL,
                PRIMARY KEY(owner,scope,id));
            CREATE TABLE IF NOT EXISTS info_event_targets (
                owner TEXT NOT NULL, scope TEXT NOT NULL, event_id TEXT NOT NULL,
                subscription_id TEXT NOT NULL, status TEXT NOT NULL, body TEXT NOT NULL,
                PRIMARY KEY(owner,scope,event_id,subscription_id));
        """))
        # Without a world generation, a reopened service cannot authenticate
        # observations from a previously loaded world in the same process.
        self._history_generation = uuid.uuid4().hex
        # Process identity alone does not identify a loaded world. When an
        # adapter cannot supply a generation, a restart preserves configuration
        # but requires an explicit resume/update before using old runtime data.
        if self._context().get("mode") == "live":
            def recover():
                uncertain = False
                for subscription in self._all("subscription"):
                    if subscription["state"] == "active" and not subscription["binding"].get("world_id"):
                        uncertain = True
                        runtime = self._runtime(subscription["id"])
                        runtime.update(state="world_revalidation_required", needs_rebind=True)
                        runtime.pop("baseline", None)
                        runtime.pop("baseline_scope", None)
                        self._set_runtime(subscription["id"], runtime)
                if uncertain:
                    previous = self._runtime("event-source")
                    self._set_runtime("event-source", {"epoch": previous.get("epoch", 0) + 1,
                        "reset_reason": "restart_without_world_identity", "complete": False})
            self._transaction(recover)

    def close(self):
        # Wait for source reads without holding the configuration/SQLite lock.
        worker = getattr(self, "map_export_worker", None)
        if worker is not None:
            worker.close()
        with self.collection_lock.acquire():
            with self.lock:
                if self._closed:
                    return
                self._closed = True
                try:
                    closer = getattr(self.source, "close_capture", None)
                    if callable(closer):
                        self.capture_close_result = closer()
                finally:
                    self.db.close()

    def _capture_status(self):
        reader = getattr(self.source, "capture_status", None)
        return copy.deepcopy(reader()) if callable(reader) else None

    def _requires_capture(self, subscription):
        predicate = getattr(self.source, "requires_capture", None)
        return bool(callable(predicate) and predicate(subscription))

    @staticmethod
    def _capture_ready(runtime):
        capture = runtime.get("capture") or {}
        return not capture.get("managed") or capture.get("producer_state") == "enabled"

    def _sync_capture(self):
        """Reconcile live producer demand after configuration commits.

        Native control must never run inside the configuration transaction:
        rolling SQLite back cannot undo a published frame-thread request.
        The durable configuration records demand; runtime records readiness.
        """
        hook = getattr(self.source, "sync_subscriptions", None)
        if not callable(hook):
            return None
        with self.lock:
            context = self._context()
            subscriptions = self._all("subscription")
            prior = set(self._runtime("capture-source").get("consumers", []))
            active = [s for s in subscriptions if s["state"] == "active"
                      and not self._runtime(s["id"]).get("needs_rebind")]
            if context.get("status") == "ready":
                valid = [s for s in active if self._binding_matches(s, context)]
            else:
                # A transient read failure must not interrupt an already
                # authenticated producer or authorize a new consumer.
                valid = [s for s in active if s["id"] in prior]
            try:
                capture = hook(valid, context)
            except Exception as exc:
                capture = {"managed": True, "producer_state": "unavailable", "owned": False,
                           "consumers": sorted(prior & {s["id"] for s in active}),
                           "reason": getattr(exc, "code", "capture_reconciliation_failed"),
                           "complete": False}
            if capture is None:
                return None
            canonical(capture)
            def persist():
                self._set_runtime("capture-source", capture)
                for subscription in subscriptions:
                    if not self._requires_capture(subscription):
                        continue
                    runtime = self._runtime(subscription["id"])
                    runtime["capture"] = copy.deepcopy(capture)
                    if subscription["state"] == "active":
                        if runtime.get("needs_rebind"):
                            runtime["state"] = "world_revalidation_required"
                        elif context.get("status") != "ready":
                            runtime["state"] = "source_unavailable"
                        elif not self._binding_matches(subscription, context):
                            runtime["state"] = "scope_mismatch"
                        else:
                            runtime["state"] = "active" if self._capture_ready(runtime) else "source_unavailable"
                    self._set_runtime(subscription["id"], runtime)
            self._transaction(persist)
            return copy.deepcopy(capture)

    def _subscription_response(self, response):
        capture = self._capture_status()
        if capture is None or not capture.get("managed"):
            return response
        result = copy.deepcopy(response)
        result["capture"] = capture
        if "subscription" in result:
            result["runtime"] = self._runtime(result["subscription"]["id"])
        return result

    def _transaction(self, action):
        with self.lock:
            self.db.execute("BEGIN IMMEDIATE")
            try:
                value = action()
                self.db.commit()
                return copy.deepcopy(value)
            except BaseException:
                self.db.rollback()
                raise

    def _context(self):
        try:
            context = self.source.context()
            if not isinstance(context, dict):
                raise ValueError("Invalid context")
            canonical(context)
            return copy.deepcopy(context)
        except Exception as exc:
            return {"status": "unready", "session_id": None, "observer": None,
                    "game_version": None, "game_day": None, "mode": "unknown",
                    "error": {"code": "source_unavailable", "message": str(exc)}}

    def _topics(self):
        return {item["topic_id"]: item for item in self.source.catalog()}

    def discover(self):
        with self.lock:
            result = {"schema_version": 1, "context": self._context(),
                    "topics": copy.deepcopy(list(self._topics().values())),
                    "event_types": list(getattr(self.source, "event_types", [])),
                    "configuration": {"time_bases": {"real": ["seconds"], "game": ["days"]},
                        "missed": ["coalesce", "skip"], "subscription_kinds": ["periodic", "event", "change"],
                        "details": ["raw", "brief", "full"], "delivery": "durable_outbox",
                        "session_policy": "fixed_binding_revalidate_on_every_attempt",
                        "change_detection": "sampled_state_comparison_not_lossless_events",
                        "resume_policy": "new_schedule_and_change_baseline",
                        "report_update_policy": "atomic_revalidate_all_referencing_subscriptions"}}
            capture = self._capture_status()
            if capture is not None:
                result["capture"] = capture
            return result

    def _get(self, kind, item_id):
        identifier(item_id)
        row = self.db.execute("SELECT body FROM info_config WHERE owner=? AND kind=? AND id=?",
                              (self.owner, kind, item_id)).fetchone()
        if row is None:
            raise InformationError("not_found", f"Unknown {kind}: {item_id}")
        return json.loads(row[0])

    def _all(self, kind):
        return [json.loads(row[0]) for row in self.db.execute(
            "SELECT body FROM info_config WHERE owner=? AND kind=? ORDER BY rowid", (self.owner, kind))]

    def _put(self, kind, value):
        self.db.execute("INSERT OR REPLACE INTO info_config VALUES(?,?,?,?,?)",
            (self.owner, kind, value["id"], value["version"], canonical(value)))

    def _runtime(self, item_id):
        row = self.db.execute("SELECT body FROM info_runtime WHERE owner=? AND id=?", (self.owner, item_id)).fetchone()
        return json.loads(row[0]) if row else {}

    def _set_runtime(self, item_id, value):
        self.db.execute("INSERT OR REPLACE INTO info_runtime VALUES(?,?,?)", (self.owner, item_id, canonical(value)))

    def _request(self, request_id, payload, action):
        identifier(request_id, "request_id")
        fingerprint = digest(payload)
        def run():
            row = self.db.execute("SELECT digest,response FROM info_requests WHERE owner=? AND id=?",
                                  (self.owner, request_id)).fetchone()
            if row:
                if row[0] != fingerprint:
                    raise InformationError("request_conflict", "Request ID already used for different arguments")
                return json.loads(row[1])
            response = action()
            self.db.execute("INSERT INTO info_requests VALUES(?,?,?,?)",
                            (self.owner, request_id, fingerprint, canonical(response)))
            return response
        return self._transaction(run)

    def _queries(self, queries):
        if not isinstance(queries, list) or not 1 <= len(queries) <= 64:
            raise InformationError("invalid_queries", "queries must contain 1 to 64 items")
        topics = self._topics()
        normalized = []
        for raw in queries:
            keys(raw, {"topic", "object", "fields", "parameters"}, {"topic", "object"}, "query")
            if not isinstance(raw["topic"], str):
                raise InformationError("invalid_topic", "topic must be a string")
            topic = topics.get(raw["topic"])
            if topic is None:
                raise InformationError("unknown_topic", str(raw["topic"]))
            if topic.get("status") != "available":
                guidance = topic.get("query_guidance", {}).get("message")
                raise InformationError("unsupported_topic", guidance or raw["topic"])
            obj = raw["object"]
            if not isinstance(obj, dict) or obj.get("type") not in topic["object_types"]:
                raise InformationError("invalid_object", "Object type not declared by topic")
            # Each adapter may impose stronger object identity checks too.
            fields = raw.get("fields", list(topic["fields"]))
            if not isinstance(fields, list) or not fields or any(not isinstance(f, str) or f not in topic["fields"] for f in fields) or len(set(fields)) != len(fields):
                raise InformationError("invalid_fields", "Unknown, duplicate or empty field selection")
            parameters = raw.get("parameters", {})
            from .tools import validate_schema
            validate_schema(parameters, topic.get("parameters", {"type": "object", "properties": {}, "additionalProperties": False}), "parameters")
            for identity in ("actor", "recipient", "war_id", "province_id", "country", "node_id"):
                if identity in obj and identity in parameters and obj[identity] != parameters[identity]:
                    raise InformationError("object_parameter_conflict", f"Conflicting {identity} in object and parameters")
            query = {"topic": raw["topic"], "object": copy.deepcopy(obj), "fields": fields[:], "parameters": copy.deepcopy(parameters)}
            validator = getattr(self.source, "validate_query", None)
            if callable(validator):
                query = validator(query)
            canonical(query)
            normalized.append(query)
        return normalized

    def _report_config(self, config):
        keys(config, {"name", "queries", "detail"}, {"queries"}, "report")
        name = config.get("name", "")
        if not isinstance(name, str) or len(name) > 256:
            raise InformationError("invalid_name", "name must be at most 256 characters")
        detail = config.get("detail", "raw")
        if detail not in ("raw", "brief", "full"):
            raise InformationError("invalid_detail", str(detail))
        return {"name": name, "queries": self._queries(config["queries"]), "detail": detail}

    def _version(self, old, expected):
        if type(expected) is not int or old["version"] != expected:
            raise InformationError("version_conflict", "Mutation requires the current expected_version")

    def manage_report(self, request_id, operation, report_id=None, config=None, expected_version=None):
        if operation == "get":
            with self.lock:
                return {"report": self._get("report", report_id)}
        if operation == "list":
            with self.lock:
                return {"reports": self._all("report")}
        def change():
            if operation == "create":
                value = dict(self._report_config(config), id="report-" + uuid.uuid4().hex, version=1)
            elif operation in ("update", "delete"):
                old = self._get("report", report_id)
                self._version(old, expected_version)
                references = [s for s in self._all("subscription") if s["report_id"] == report_id and s["state"] != "cancelled"]
                if operation == "delete":
                    if references:
                        raise InformationError("report_in_use", "Cancel referencing subscriptions before deleting report")
                    self.db.execute("DELETE FROM info_config WHERE owner=? AND kind='report' AND id=?", (self.owner, report_id))
                    return {"deleted": True, "report_id": report_id, "version": old["version"]}
                value = dict(self._report_config(config), id=report_id, version=old["version"] + 1)
                for subscription in references:
                    self._check_triggers(subscription, value)
                    runtime = self._runtime(subscription["id"])
                    runtime.pop("baseline", None)
                    runtime.pop("baseline_scope", None)
                    self._set_runtime(subscription["id"], runtime)
            else:
                raise InformationError("invalid_operation", str(operation))
            self._put("report", value)
            return {"report": value}
        return self._request(request_id, ["report", operation, report_id, config, expected_version], change)

    def _schedule(self, raw):
        keys(raw, {"basis", "every", "unit", "missed"}, {"basis", "every", "unit"}, "schedule")
        if (raw["basis"], raw["unit"]) not in (("real", "seconds"), ("game", "days")):
            raise InformationError("unsupported_schedule", "Use real/seconds or game/days")
        if type(raw["every"]) is not int or not 1 <= raw["every"] <= 315576000:
            raise InformationError("invalid_schedule", "every must be a positive bounded integer")
        missed = raw.get("missed", "coalesce")
        if missed not in ("coalesce", "skip"):
            raise InformationError("unsupported_missed_policy", str(missed))
        return dict(raw, missed=missed)

    def _check_triggers(self, subscription, report):
        topics = self._topics()
        capability_reader = getattr(self.source, "query_capabilities", None)
        capabilities = [capability for query in report["queries"] for capability in (
            capability_reader(query) if callable(capability_reader) else [(query, topics[query["topic"]])]
        )]
        for query, topic in capabilities:
            binding = subscription.get("binding", {})
            if binding.get("game_version") not in topic.get("supported_versions", []):
                raise InformationError("unsupported_game_version", f"{query['topic']} does not support bound game version")
            if not self._observer_matches(query, topic, binding.get("observer")):
                raise InformationError("observer_scope_mismatch", "Report object differs from subscription observer scope")
            if query["object"].get("session_id", binding.get("session_id")) != binding.get("session_id"):
                raise InformationError("session_scope_mismatch", "Report object belongs to another session")
            required = subscription["kind"] if subscription["kind"] != "event" else "query"
            if required not in topic.get("triggers", []):
                raise InformationError("unsupported_trigger", f"{query['topic']} does not support {required}")
            scope = topic.get("change_scope")
            if (required == "change" and isinstance(scope, dict)
                    and not set(query["fields"]) <= set(scope.get("fields", []))):
                raise InformationError("unsupported_trigger", f"{query['topic']} change is limited to its declared field scope")
            if required == "change" and isinstance(scope, dict):
                for name, expected in scope.get("required_parameters", {}).items():
                    actual = query.get("parameters", {}).get(name)
                    if type(actual) is not type(expected) or actual != expected:
                        raise InformationError("unsupported_trigger", f"{query['topic']} change requires parameter {name}")

    def _subscription_config(self, config):
        keys(config, {"name", "kind", "report_id", "enabled", "binding", "schedule", "event"}, {"kind", "report_id"}, "subscription")
        kind = config["kind"]
        if kind not in ("periodic", "event", "change"):
            raise InformationError("invalid_kind", str(kind))
        report = self._get("report", config["report_id"])
        value = copy.deepcopy(config)
        if not isinstance(value.get("name", ""), str) or len(value.get("name", "")) > 256:
            raise InformationError("invalid_name", "Invalid subscription name")
        value.setdefault("name", "")
        value.setdefault("enabled", True)
        if type(value["enabled"]) is not bool:
            raise InformationError("invalid_enabled", "enabled must be boolean")
        context = self._context()
        binding = value.get("binding", {k: context.get(k) for k in ("session_id", "observer", "game_version", "game_sha256", "world_id") if context.get(k) is not None})
        keys(binding, {"session_id", "observer", "game_version", "game_sha256", "world_id"}, {"session_id", "observer", "game_version"}, "binding")
        if any(not isinstance(v, str) or not v for v in binding.values()):
            raise InformationError("invalid_binding", "Binding identities must be nonempty strings")
        value["binding"] = binding
        if kind == "event":
            if "schedule" in value:
                raise InformationError("invalid_schedule", "Event subscriptions do not have polling schedules")
            event = value.get("event")
            keys(event, {"types", "actors", "recipients", "proposal_statuses"}, {"types"}, "event filter")
            supported = set(getattr(self.source, "event_types", []))
            if not isinstance(event["types"], list) or not event["types"] or any(not isinstance(t, str) or t not in supported for t in event["types"]):
                raise InformationError("unsupported_event", "Event type not supported by source")
            for key in ("actors", "recipients"):
                if key in event and (not isinstance(event[key], list) or not event[key] or any(not isinstance(t, str) or len(t) != 3 or not t.isascii() or not t.isupper() or not t.isalnum() for t in event[key])):
                    raise InformationError("invalid_event_filter", key)
            if 'proposal_statuses' in event:
                statuses = event['proposal_statuses']
                if not isinstance(statuses, list) or not statuses:
                    raise InformationError('invalid_event_filter', 'proposal_statuses')
                for status in statuses:
                    identifier(status, 'proposal status')
            validator = getattr(self.source, "validate_event_filter", None)
            if callable(validator):
                validator(copy.deepcopy(event))
        else:
            if "event" in value:
                raise InformationError("invalid_event_filter", "Only event subscriptions accept event filters")
            value["schedule"] = self._schedule(value.get("schedule"))
        self._check_triggers(value, report)
        return value

    def manage_subscription(self, request_id, operation, subscription_id=None, config=None, expected_version=None):
        if operation == "get":
            with self.lock:
                return self._subscription_response({"subscription": self._get("subscription", subscription_id)})
        if operation == "list":
            with self.lock:
                return self._subscription_response({"subscriptions": self._all("subscription")})
        changed = False
        def change():
            nonlocal changed
            if operation == "create":
                value = dict(self._subscription_config(config), id="subscription-" + uuid.uuid4().hex, version=1)
                value["state"] = "active" if value["enabled"] else "paused"
            elif operation in ("update", "pause", "resume", "cancel"):
                old = self._get("subscription", subscription_id)
                self._version(old, expected_version)
                if old["state"] == "cancelled":
                    raise InformationError("subscription_cancelled", "Cancelled subscriptions cannot resume")
                value = (dict(self._subscription_config(config), id=subscription_id, version=old["version"] + 1)
                         if operation == "update" else dict(old, version=old["version"] + 1))
                value["state"] = ("cancelled" if operation == "cancel" else "paused" if operation == "pause"
                                  else "active" if operation == "resume" or value["enabled"] else "paused")
                value["enabled"] = value["state"] == "active"
            else:
                raise InformationError("invalid_operation", str(operation))
            self._put("subscription", value)
            runtime = self._runtime(value["id"])
            for key in ("next_due", "baseline", "baseline_scope", "last_clock", "needs_rebind", "collection"):
                runtime.pop(key, None)
            runtime["state"] = value["state"]
            if value["kind"] != "event" and value["state"] == "active":
                context = self._context()
                now = self.clock() if value["schedule"]["basis"] == "real" else context.get("game_day")
                if type(now) in (int, float):
                    runtime["next_due"] = now + value["schedule"]["every"]
                    runtime["last_clock"] = now
            self._set_runtime(value["id"], runtime)
            changed = True
            return {"subscription": value}
        with self.lock:
            result = self._request(request_id, ["subscription", operation, subscription_id, config, expected_version], change)
            if changed:
                self._sync_capture()
            return self._subscription_response(result)

    def configure(self, request_id, operation, values=None, expected_version=None):
        defaults = {"enabled": True, "max_results_per_tick": 100}
        def effective():
            try:
                entry = self._get("global", "settings")
            except InformationError:
                entry = {"id": "settings", "version": 0, "overrides": {}}
            return dict(entry, effective=dict(defaults, **entry["overrides"]))
        if operation == "get":
            with self.lock:
                return {"config": effective()}
        def change():
            old = effective()
            self._version(old, expected_version)
            if operation == "update":
                keys(values, set(defaults), label="global settings")
                merged = dict(old["overrides"], **values)
                if type(merged.get("enabled", True)) is not bool or type(merged.get("max_results_per_tick", 100)) is not int or not 1 <= merged.get("max_results_per_tick", 100) <= 1000:
                    raise InformationError("invalid_settings", "Invalid enabled or max_results_per_tick")
            elif operation == "clear":
                merged = {}
            else:
                raise InformationError("invalid_operation", str(operation))
            self._put("global", {"id": "settings", "version": old["version"] + 1, "overrides": merged})
            return {"config": effective()}
        return self._request(request_id, ["configure", operation, values, expected_version], change)

    @staticmethod
    def _observer_matches(query, topic, observer):
        roles = observer_roles_for_query(topic, query)
        values = [query["object"].get(role, query["parameters"].get(role)) for role in roles]
        values = [value for value in values if value is not None]
        return not values or observer in values

    def _scope_error(self, queries, context):
        topics = self._topics()
        for query in queries:
            query_catalog = getattr(self.source, "query_catalog", None)
            topic = query_catalog(query) if callable(query_catalog) else topics[query["topic"]]
            if topic.get("context_scope") == "adapter_managed":
                # A multi-owner adapter checks each field source separately,
                # retaining static successes when a live source is unavailable.
                continue
            static = topic.get("context_scope") == "static_rules"
            if not static and context.get("status") != "ready":
                return "source_unavailable"
            versions = topic.get("supported_versions", [])
            if (not static or context.get("game_version") is not None) and context.get("game_version") not in versions:
                return "unsupported_game_version"
            if static:
                continue
            obj = query["object"]
            if obj.get("session_id") is not None and obj["session_id"] != context.get("session_id"):
                return "session_scope_mismatch"
            if not self._observer_matches(query, topic, context.get("observer")):
                return "observer_scope_mismatch"
        return None

    def _change_comparison(self, sample, context):
        """Keep full samples unchanged; partial samples require an owner-qualified scope."""
        if sample.get('complete') is True:
            return copy.deepcopy(sample['fields']), None
        hook = getattr(self.source, 'change_comparison', None)
        if not callable(hook):
            return None
        try:
            comparison = hook(copy.deepcopy(sample['query']), copy.deepcopy(sample), copy.deepcopy(context))
            if (not isinstance(comparison, dict) or set(comparison) != {'schema', 'scope', 'fields'}
                    or comparison['schema'] != 'information.change_comparison.v1'
                    or not isinstance(comparison['scope'], str) or not 1 <= len(comparison['scope']) <= 2048
                    or any(char not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.:,-' for char in comparison['scope'])
                    or canonical(comparison['fields']) != canonical(sample['fields'])):
                return None
            # Scope is part of the digest, so comparisons never cross supported domains.
            return copy.deepcopy(comparison), comparison['scope']
        except Exception:
            return None

    def _collect(self, queries, context, event=None, replay=False):
        items = []
        topics = self._topics()
        for query in queries:
            try:
                error = self._scope_error([query], context)
                if error:
                    raise InformationError(error, error)
                if event is not None:
                    read_event = getattr(self.source, "replay_event" if replay else "read_event", None)
                else:
                    read_event = None
                with sampled_read(query, context, enabled=event is None and not replay) as window:
                    if callable(read_event):
                        sample = read_event(copy.deepcopy(query), copy.deepcopy(context), copy.deepcopy(event))
                    elif replay:
                        sample = {"fields": {name: {"status": "unknown",
                            "reason": "EVENT_PROJECTION_INTERRUPTED_NOT_REPLAYED"} for name in query["fields"]},
                            "complete": False, "source": {"name": type(self.source).__name__,
                                "provenance": {"replay": "unsupported_no_live_fallback"}}}
                    else:
                        sample = self.source.read(copy.deepcopy(query), copy.deepcopy(context))
                    if window is not None:
                        sample = dict(sample, observation_window=window.metadata())
                canonical(sample)
                raw_fields = sample.get("fields", {})
                fields = {}
                for field in query["fields"]:
                    item = raw_fields.get(field, {"status": "unknown", "reason": "field_missing"})
                    if not isinstance(item, dict) or item.get("status") not in {"known", "unknown", "invisible", "not_applicable", "unavailable", "stale", "unsupported"}:
                        item = {"status": "unknown", "reason": "invalid_field_contract"}
                    if item["status"] == "known" and "value" not in item:
                        item = {"status": "unknown", "reason": "known_value_missing"}
                    elif item["status"] != "known":
                        item = {k: v for k, v in item.items() if k != "value"}
                    item = dict(item)
                    for metadata in ("unit", "scale"):
                        if metadata in topics[query["topic"]]["fields"][field]:
                            item[metadata] = topics[query["topic"]]["fields"][field][metadata]
                    fields[field] = item
                sample = dict(sample, query=query, fields=fields,
                              complete=sample.get("complete") is True and all(v["status"] in ("known", "not_applicable") for v in fields.values()))
                items.append(sample)
            except Exception as exc:
                items.append({"query": query, "complete": False, "fields": {field: {"status": "unavailable", "reason": getattr(exc, "code", "source_error")} for field in query["fields"]},
                              "error": {"code": getattr(exc, "code", "source_error"), "message": str(exc)}})
        return items

    def _build_result(self, queries, context, trigger, subscription=None, event=None, samples=None, report=None):
        items = self._collect(queries, context, event=event) if samples is None else samples
        # Identity changes invalidate readings. Macro samples retain their
        # observation window while the game clock advances normally.
        after = self._context()
        identity_changed = (any(context.get(k) != after.get(k) for k in (
            "session_id", "observer", "game_version", "world_id")) or after.get("status") != "ready")
        clock_changed = (context.get('game_day') != after.get('game_day')
                         or context.get('game_date') != after.get('game_date'))
        forward_clock = (type(context.get('game_date')) is int and type(after.get('game_date')) is int
                         and after['game_date'] >= context['game_date'])
        if context.get("status") == "ready" and (identity_changed or clock_changed):
            for item in items:
                source = item.get('source', {})
                snapshot_id = source.get('event_id') if isinstance(source, dict) else None
                event_snapshot = (isinstance(source, dict) and source.get('projection') == 'event_snapshot'
                    and isinstance(snapshot_id, str) and bool(snapshot_id)
                    and (event is None or snapshot_id == event.get('event_id')))
                if not identity_changed and forward_clock and event_snapshot:
                    continue
                if not identity_changed and forward_clock and 'observation_window' in item:
                    window = item['observation_window']
                    window['collection_end_game_date'] = after['game_date']
                    window['end_game_date'] = max(window.get('end_game_date') or after['game_date'], after['game_date'])
                    continue
                query_catalog = getattr(self.source, "query_catalog", None)
                topic = query_catalog(item["query"]) if callable(query_catalog) else self._topics()[item["query"]["topic"]]
                if topic.get("context_scope") == "static_rules":
                    continue
                item["complete"] = False
                item["fields"] = {field: {"status": "stale", "reason": "context_changed_during_collection"}
                                  if value["status"] in ("known", "not_applicable") and item.get("field_context_scopes", {}).get(field) != "static_rules" else value
                                  for field, value in item["fields"].items()}
        complete = all(item["complete"] for item in items)
        result = {"schema_version": 1, "result_id": "result-" + uuid.uuid4().hex,
                  "owner": self.owner, "context": context, "collected_at": utc_now(),
                  "trigger": trigger, "subscription_id": subscription["id"] if subscription else None,
                  "subscription_version": subscription["version"] if subscription else None,
                  "report_id": report["id"] if report else None,
                  "report_version": report["version"] if report else None,
                  "detail": report["detail"] if report else "raw", "items": items,
                  "complete": complete, "status": "complete" if complete else "partial" if any(any(f["status"] == "known" for f in i["fields"].values()) for i in items) else "failed",
                  "event": copy.deepcopy(event), "delivery": {"status": "pending", "adapter": "external" if self.output else "durable_outbox", "llm_read": "unknown"}}
        if self.output is None:
            result["delivery"].update(status="delivered", delivered_at=utc_now())
        return result

    def _save_result(self, queries, context, trigger, subscription=None, event=None, samples=None, report=None):
        result = self._build_result(queries, context, trigger, subscription, event, samples, report)
        self._attach_last_known(result)
        self.db.execute("INSERT INTO info_results VALUES(?,?,?)", (self.owner, result["result_id"], canonical(result)))
        return result

    def _attach_last_known(self, result):
        """Attach dated historical facts without changing the current read.

        Called inside the result's commit transaction. History uses the same
        owner, report version, query and live identity, including world when
        available. Current identity is checked once before reading stored
        observations.
        """
        if result.get("event") is not None or result.get("trigger") not in {"manual", "periodic"}:
            return
        items = [item for item in result["items"]
                 if item["query"]["topic"] in {"N01", "N02", "N03", "N04"}
                 and item["query"]["object"].get("type") == "country"
                 and item["query"]["object"].get("country") == result["context"].get("observer")]
        if not items:
            return
        before, after = result["context"], self._context()
        identity_keys = ("mode", "session_id", "observer", "game_version", "world_id", "game_sha256", "dll_sha256")
        if (before.get("mode") != "live" or before.get("status") != "ready"
                or after.get("status") != "ready"
                or any(before.get(key) != after.get(key) for key in identity_keys)
                or any(not before.get(key) for key in ("session_id", "observer", "game_version"))
                or type(before.get("game_date")) is not int or type(after.get("game_date")) is not int):
            return
        identity = {key: before.get(key) for key in identity_keys}
        generation = None if identity["world_id"] else self._history_generation
        result["collection_instance_id"] = self._history_generation
        state_id = "macro-history-" + digest([identity, generation])
        state = self._runtime(state_id)
        floor = state.get("floor", 0)
        date = after["game_date"]
        if date < before["game_date"] or before["game_date"] < state.get("game_date", before["game_date"]):
            floor = self.db.execute(
                "SELECT COALESCE(MAX(rowid),0) FROM info_results WHERE owner=?", (self.owner,)
            ).fetchone()[0]
        self._set_runtime(state_id, {"game_date": date, "floor": floor})
        if date < before["game_date"]:
            return
        scope_sql = " AND ".join(
            "json_extract(r.body, '$.context." + key + "') IS ?" for key in identity_keys
        )
        for item in items:
            for name, field in item["fields"].items():
                if field["status"] not in {"unknown", "unavailable"}:
                    continue
                if field.get("reason") in {"invalid_field_contract", "known_value_missing"}:
                    continue
                row = self.db.execute(
                    "SELECT r.id, json_extract(r.body,'$.collected_at'), "
                    "json_extract(r.body,'$.context'), i.value FROM info_results r, "
                    "json_each(r.body,'$.items') i WHERE r.owner=? AND r.rowid>? AND "
                    + scope_sql +
                    " AND json_extract(r.body,'$.context.status')='ready'"
                    " AND json_extract(r.body,'$.context.game_date')<=?"
                    " AND COALESCE(json_extract(i.value,'$.observation_window.end_game_date'),"
                    "json_extract(r.body,'$.context.game_date'))<=?"
                    " AND json_extract(r.body,'$.report_id') IS ?"
                    " AND json_extract(r.body,'$.report_version') IS ?"
                    " AND (? IS NULL OR json_extract(r.body,'$.collection_instance_id')=?)"
                    " AND json_extract(r.body,'$.event') IS NULL"
                    " AND json_extract(r.body,'$.trigger') IN ('manual','periodic')"
                    " AND json_extract(i.value,'$.query')=json(?)"
                    " AND json_extract(i.value,?)='known' ORDER BY r.rowid DESC LIMIT 1",
                    (self.owner, floor, *identity.values(), before["game_date"], before["game_date"],
                     result.get("report_id"), result.get("report_version"), generation, generation,
                     canonical(item["query"]),
                     '$.fields.' + name + '.status'),
                ).fetchone()
                if row is None:
                    continue
                previous = json.loads(row[3])
                last_known = {"field": previous["fields"][name], "result_id": row[0],
                              "collected_at": row[1], "context": json.loads(row[2]),
                              "basis": "previous_successful_field_observation"}
                if "observation_window" in previous:
                    last_known["observation_window"] = previous["observation_window"]
                field["last_known"] = last_known

    def _deliver(self, result):
        if self.output is None or result["delivery"]["status"] != "pending":
            return result
        # Claim before external side effects, across service instances too.
        # A crash leaves delivering (unknown receipt), never an automatic retry.
        def claim():
            current = self.get_result(result["result_id"])
            if current["delivery"]["status"] != "pending":
                return current, False
            if current.get("subscription_id"):
                try:
                    subscription = self._get("subscription", current["subscription_id"])
                    report = self._get("report", subscription["report_id"])
                    delivery_context = self._context()
                    valid = (subscription["state"] == "active"
                        and subscription["version"] == current["subscription_version"]
                        and report["id"] == current["report_id"]
                        and report["version"] == current["report_version"]
                        and self.configure(None, "get")["config"]["effective"]["enabled"]
                        and delivery_context.get("status") == "ready"
                        and self._binding_matches(subscription, delivery_context))
                except InformationError:
                    valid = False
                if not valid:
                    current["delivery"] = {"status": "failed", "adapter": "external",
                        "error": {"code": "subscription_changed_before_delivery"}, "llm_read": "unknown"}
                    self.db.execute("UPDATE info_results SET body=? WHERE owner=? AND id=?",
                                    (canonical(current), self.owner, current["result_id"]))
                    return current, False
            current["delivery"]["status"] = "delivering"
            self.db.execute("UPDATE info_results SET body=? WHERE owner=? AND id=?", (canonical(current), self.owner, current["result_id"]))
            return current, True
        result, claimed = self._transaction(claim)
        if not claimed:
            return result
        try:
            from .presentation import present_concise
            receipt = self.output.deliver(present_concise(result))
            canonical(receipt)
            if not isinstance(receipt, dict) or receipt.get("status") != "delivered":
                raise InformationError("output_not_delivered", str(receipt))
            delivery = {"status": "delivered", "adapter": "external", "receipt": receipt, "llm_read": "unknown"}
        except Exception as exc:
            delivery = {"status": "failed", "adapter": "external", "error": {"code": getattr(exc, "code", "output_error"), "message": str(exc)}, "llm_read": "unknown"}
        result = dict(result, delivery=delivery)
        def save():
            self.db.execute("UPDATE info_results SET body=? WHERE owner=? AND id=?", (canonical(result), self.owner, result["result_id"]))
        self._transaction(save)
        return result

    def query(self, request_id, queries=None, report_id=None):
        claimed = False
        selection = report = context = None
        claim_id = uuid.uuid4().hex
        def claim():
            nonlocal claimed, selection, report, context
            if (queries is None) == (report_id is None):
                raise InformationError("invalid_query", "Specify either queries or report_id")
            report = self._get("report", report_id) if report_id else None
            selection = report["queries"] if report else self._queries(queries)
            context = self._context()
            claimed = True
            return {"_query_collection": claim_id, "request_id": request_id, "claimed_at": utc_now()}
        with self.collection_lock.acquire():
            if self._closed:
                raise InformationError("service_closed", "Information service is closed")
            previous = self._request(request_id, ["query", queries, report_id], claim)
            if not claimed:
                if "_query_collection" in previous:
                    raise InformationError("request_outcome_unknown", "The prior read did not complete; it will not be repeated")
                return self._deliver(self.get_result(previous["result_id"]))
            result = self._build_result(selection, context, "manual", report=report)
            result["request_id"] = request_id
            def save():
                # A request claim survives interruption. Never repeat that read
                # merely because its final result was not committed.
                row = self.db.execute("SELECT response FROM info_requests WHERE owner=? AND id=?",
                                      (self.owner, request_id)).fetchone()
                if row is None or json.loads(row[0]).get("_query_collection") != claim_id:
                    raise InformationError("request_conflict", "Query claim changed during collection")
                report_changed = False
                if report is not None:
                    try:
                        current_report = self._get("report", report["id"])
                    except InformationError:
                        current_report = None
                    report_changed = current_report is None or current_report["version"] != report["version"]
                    if report_changed:
                        for item in result["items"]:
                            item["complete"] = False
                            item["fields"] = {name: {"status": "stale", "reason": "report_changed_during_collection"}
                                if field["status"] in ("known", "not_applicable") else field
                                for name, field in item["fields"].items()}
                        result.update(complete=False, status="failed")
                if not report_changed:
                    self._attach_last_known(result)
                self.db.execute("INSERT INTO info_results VALUES(?,?,?)", (self.owner, result["result_id"], canonical(result)))
                self.db.execute("UPDATE info_requests SET response=? WHERE owner=? AND id=?",
                                (canonical(result), self.owner, request_id))
            self._transaction(save)
            return self._deliver(result)

    def get_result(self, result_id):
        identifier(result_id)
        with self.lock:
            row = self.db.execute("SELECT body FROM info_results WHERE owner=? AND id=?", (self.owner, result_id)).fetchone()
            if row is None:
                raise InformationError("not_found", "Unknown result")
            return json.loads(row[0])

    def previous_war_forces(self, context, obj):
        from .war_force_change import previous_force_sample
        with self.lock:
            return previous_force_sample(self.db, self.owner, context, obj)

    def action_cooldown_expiries(self, context, cursor=None):
        from .cooldown_expiry import poll
        with self.lock:
            return poll(self.db, self.owner, context, cursor)

    def observed_events(self, context, *, event_types, limit=50, cursor=None, payload_filters=None):
        """Read a bounded page from the existing owner/world event ledger."""
        if type(limit) is not int or not 1 <= limit <= 1000:
            raise InformationError('invalid_limit', 'limit must be 1..1000')
        clauses = ['owner=?', 'scope=?']
        with self.lock:
            previous = self._runtime('context-checkpoint')
            if (previous.get('session_id') == context.get('session_id')
                    and type(previous.get('game_day')) is int and type(context.get('game_day')) is int
                    and context['game_day'] < previous['game_day']):
                return {'events': [], 'next_cursor': None, 'complete': False,
                        'gaps': [{'reason': 'game_date_rewound'}]}
            state = self._runtime('event-source')
            scope = self._event_scope(context, state)
            parameters = [self.owner, scope]
            if not event_types:
                return {'events': [], 'next_cursor': None, 'complete': True, 'gaps': []}
            clauses.append("json_extract(body,'$.event_type') IN (" + ','.join('?' for _ in event_types) + ')')
            parameters.extend(event_types)
            for key, value in (payload_filters or {}).items():
                clauses.append('json_extract(body,?)=?')
                parameters.extend(['$.payload.' + key, value])
            if cursor is not None:
                identifier(cursor, 'event cursor')
                row = self.db.execute('SELECT rowid FROM info_events WHERE owner=? AND scope=? AND id=?',
                                      (self.owner, scope, cursor)).fetchone()
                if row is None:
                    raise InformationError('invalid_cursor', 'Unknown event cursor in the current scope')
                clauses.append('rowid<?')
                parameters.append(row[0])
            rows = self.db.execute('SELECT id,body FROM info_events WHERE ' + ' AND '.join(clauses)
                                   + ' ORDER BY rowid DESC LIMIT ?', (*parameters, limit + 1)).fetchall()
            current_scope = state.get('scope') == scope
            return {'events': [json.loads(row['body']) for row in rows[:limit]],
                    'next_cursor': rows[limit - 1]['id'] if len(rows) > limit else None,
                    'complete': state.get('complete', True) if current_scope else True,
                    'gaps': copy.deepcopy(state.get('gaps', [])) if current_scope else []}

    def list_results(self, limit=50):
        if type(limit) is not int or not 1 <= limit <= 1000:
            raise InformationError("invalid_limit", "limit must be 1..1000")
        with self.lock:
            return {"results": [json.loads(row[0]) for row in self.db.execute("SELECT body FROM info_results WHERE owner=? ORDER BY rowid DESC LIMIT ?", (self.owner, limit))]}

    def _binding_matches(self, subscription, context):
        return all(context.get(key) == value for key, value in subscription["binding"].items())

    def status(self, subscription_id=None):
        with self.lock:
            subscriptions = [self._get("subscription", subscription_id)] if subscription_id else self._all("subscription")
            context = self._context()
            rows = []
            for subscription in subscriptions:
                runtime = self._runtime(subscription["id"])
                state = subscription["state"]
                if state == "active":
                    state = "scope_mismatch" if not self._binding_matches(subscription, context) else "source_unavailable" if context.get("status") != "ready" else runtime.get("state", state)
                last = runtime.get("last_result_id")
                if last:
                    runtime["last_delivery"] = self.get_result(last)["delivery"]
                rows.append({"subscription": subscription, "runtime": dict(runtime, state=state)})
            result = {"context": context, "config": self.configure(None, "get")["config"], "subscriptions": rows,
                      "event_source": self._runtime("event-source"), "pending_delivery_policy": "no_automatic_retry_after_restart"}
            capture = self._capture_status()
            if capture is not None:
                result["capture"] = capture
            return result

    def _event_matches(self, subscription, event):
        filters = subscription["event"]
        if event.get("event_type") not in filters["types"]:
            return False
        payload = event.get("payload", {})
        if (event.get('event_type') == 'diplomatic_proposal' and 'proposal_statuses' in filters
                and payload.get('observer_status') not in filters['proposal_statuses']):
            return False
        return all(key not in filters or payload.get(field, event.get(field)) in filters[key]
                   for key, field in (("actors", "actor"), ("recipients", "recipient")))

    def _tick_start(self):
        context = self._context()
        self._last_tick_context = copy.deepcopy(context)
        previous = self._runtime("context-checkpoint")
        rewound = (previous.get("session_id") == context.get("session_id")
            and type(previous.get("game_day")) is int and type(context.get("game_day")) is int
            and context["game_day"] < previous["game_day"])
        subscriptions = self._all("subscription")
        for subscription in subscriptions:
            runtime = self._runtime(subscription["id"])
            changed = False
            # The OS collection lock is exclusive. A surviving marker belongs
            # to an interrupted attempt, not another currently reading tick.
            interrupted = runtime.pop("collection", None)
            if interrupted is not None:
                runtime.setdefault("last_attempt", {})["status"] = "collection_interrupted_unpublished"
                changed = True
            if rewound:
                for key in ("baseline", "baseline_scope", "next_due", "last_clock"):
                    runtime.pop(key, None)
                runtime["discontinuity"] = {"reason": "game_date_rewound",
                    "from": previous["game_day"], "to": context["game_day"]}
                changed = True
            if changed:
                self._set_runtime(subscription["id"], runtime)
        if rewound:
            state = self._runtime("event-source")
            self._set_runtime("event-source", {"epoch": state.get("epoch", 0) + 1,
                "reset_reason": "game_date_rewound", "complete": False})
        if context.get("status") == "ready":
            self._set_runtime("context-checkpoint", {k: context.get(k) for k in ("session_id", "game_day")})
        settings = self.configure(None, "get")["config"]["effective"]
        return context, settings, [s["id"] for s in subscriptions if s["state"] == "active"]

    def _tick_claim(self, subscription_id, context, generated_count):
        settings = self.configure(None, "get")["config"]
        if not settings["effective"]["enabled"]:
            return None
        subscription = self._get("subscription", subscription_id)
        if subscription["state"] != "active":
            return None
        runtime = self._runtime(subscription_id)
        if runtime.get("needs_rebind"):
            runtime["state"] = "world_revalidation_required"
        elif context.get("status") != "ready" or not self._binding_matches(subscription, context):
            runtime["state"] = "source_unavailable" if context.get("status") != "ready" else "scope_mismatch"
        else:
            runtime["state"] = "active"
            if subscription["kind"] == "event":
                if self._requires_capture(subscription) and not self._capture_ready(runtime):
                    runtime["state"] = "source_unavailable"
            else:
                schedule = subscription["schedule"]
                now = self.clock() if schedule["basis"] == "real" else context.get("game_day")
                if type(now) not in (int, float):
                    runtime["state"] = "clock_unavailable"
                else:
                    if "last_clock" in runtime and now < runtime["last_clock"]:
                        runtime.pop("baseline", None)
                        runtime.pop("baseline_scope", None)
                        runtime["next_due"] = now + schedule["every"]
                        runtime["discontinuity"] = {"reason": "clock_rewound", "from": runtime["last_clock"], "to": now}
                    runtime["last_clock"] = now
                    runtime.setdefault("next_due", now + schedule["every"])
                    if now >= runtime["next_due"] and generated_count < settings["effective"]["max_results_per_tick"]:
                        count = int((now - runtime["next_due"]) // schedule["every"]) + 1
                        due = runtime["next_due"]
                        runtime["next_due"] += count * schedule["every"]
                        runtime["last_attempt"] = {"collected_at": utc_now(), "due": due, "clock": now,
                            "due_count": count, "missed": schedule["missed"], "game_date": context.get("game_date")}
                        if schedule["missed"] == "skip" and count > 1:
                            runtime["last_attempt"]["status"] = "skipped_missed_intervals"
                        else:
                            report = self._get("report", subscription["report_id"])
                            claim_id = uuid.uuid4().hex
                            runtime["collection"] = {"id": claim_id,
                                "subscription_version": subscription["version"], "report_version": report["version"],
                                "settings_version": settings["version"]}
                            runtime["last_attempt"]["status"] = "collecting"
                            self._set_runtime(subscription_id, runtime)
                            return {"id": claim_id, "subscription": subscription, "report": report,
                                    "settings_version": settings["version"], "context": copy.deepcopy(context)}
        self._set_runtime(subscription_id, runtime)
        return None

    def _tick_commit(self, job, result, comparisons):
        subscription = self._get("subscription", job["subscription"]["id"])
        runtime = self._runtime(subscription["id"])
        if runtime.get("collection", {}).get("id") != job["id"]:
            return None  # A control operation already invalidated this attempt.
        runtime.pop("collection", None)
        settings = self.configure(None, "get")["config"]
        try:
            report = self._get("report", job["report"]["id"])
        except InformationError:
            report = None
        after = self._context()
        reason = None
        if subscription["state"] != "active" or subscription["version"] != job["subscription"]["version"]:
            reason = "subscription_changed"
        elif report is None or report["version"] != job["report"]["version"]:
            reason = "report_changed"
        elif not settings["effective"]["enabled"] or settings["version"] != job["settings_version"]:
            reason = "configuration_changed"
        elif runtime.get("needs_rebind") or not self._binding_matches(subscription, after) or after.get("status") != "ready":
            reason = "scope_changed"
        if reason:
            runtime.setdefault("last_attempt", {})["status"] = "discarded_" + reason
            self._set_runtime(subscription["id"], runtime)
            return None
        if subscription["kind"] == "change":
            if any(comparison is None for comparison in comparisons):
                runtime["last_attempt"]["status"] = "read_failed_baseline_preserved"
                runtime["last_attempt"]["incomplete_queries"] = [
                    {"query": copy.deepcopy(sample["query"]), "complete": False,
                     "fields": {name: {k: copy.deepcopy(field[k]) for k in ("status", "reason", "complete") if k in field}
                                for name, field in sample["fields"].items()}}
                    for sample, comparison in zip(result["items"], comparisons) if comparison is None]
                self._set_runtime(subscription["id"], runtime)
                return None
            current = digest([comparison[0] for comparison in comparisons])
            scopes = [comparison[1] for comparison in comparisons]
            scope_hash = digest(scopes)
            prior, old_scope = runtime.get("baseline"), runtime.get("baseline_scope")
            scope_changed = (prior is not None and ((old_scope is not None and old_scope != scope_hash)
                or (old_scope is None and any(scope is not None for scope in scopes))))
            runtime.update(baseline=current, baseline_scope=scope_hash)
            if any(scope is not None for scope in scopes):
                runtime["last_attempt"]["comparison_scopes"] = scopes
            if prior is None or prior == current or scope_changed:
                runtime["last_attempt"]["status"] = ("baseline_created" if prior is None
                    else "baseline_scope_changed" if scope_changed else "unchanged")
                self._set_runtime(subscription["id"], runtime)
                return None
        runtime["last_result_id"] = result["result_id"]
        runtime["last_attempt"]["status"] = result["status"]
        result["schedule"] = copy.deepcopy(runtime["last_attempt"])
        self._attach_last_known(result)
        self.db.execute("INSERT INTO info_results VALUES(?,?,?)", (self.owner, result["result_id"], canonical(result)))
        self._set_runtime(subscription["id"], runtime)
        return result

    def tick(self):
        busy = lambda: {"state": "busy", "results": [], "context": copy.deepcopy(self._last_tick_context)}
        if not self._tick_guard.acquire(blocking=False):
            return busy()
        try:
            with self.collection_lock.acquire(blocking=False) as acquired:
                if not acquired:
                    return busy()
                if self._closed:
                    return {"state": "closed", "results": [], "context": copy.deepcopy(self._last_tick_context)}
                self._sync_capture()
                context, settings, subscriptions = self._transaction(self._tick_start)
                if not settings["enabled"]:
                    return {"state": "disabled", "results": [], "context": context}
                generated = []
                event_plan = self._collect_events(context)
                for subscription_id in subscriptions:
                    job = self._transaction(lambda: self._tick_claim(subscription_id, context, len(generated)))
                    if job is None:
                        continue
                    # Neither the SQLite transaction nor self.lock is held here.
                    result = self._build_result(job["report"]["queries"], context,
                        job["subscription"]["kind"], job["subscription"], report=job["report"])
                    comparisons = ([self._change_comparison(sample, context) for sample in result["items"]]
                                   if job["subscription"]["kind"] == "change" else None)
                    committed = self._transaction(lambda: self._tick_commit(job, result, comparisons))
                    if committed is not None:
                        generated.append(committed)
                effective = self.configure(None, "get")["config"]["effective"]
                if effective["enabled"]:
                    self._poll_events(event_plan, generated)
                enabled = self.configure(None, "get")["config"]["effective"]["enabled"]
                context = self._context()
                self._last_tick_context = copy.deepcopy(context)
                return {"state": "disabled" if not enabled else "processed" if context.get("status") == "ready" else "source_unavailable",
                        "context": context, "results": [self._deliver(result) for result in generated]}
        finally:
            self._tick_guard.release()


    @staticmethod
    def _event_scope(context, state):
        return digest({**{k: context.get(k) for k in ("session_id", "observer", "game_version", "world_id")},
                       "epoch": state.get("epoch", 0)})

    def _event_subscribers(self, context):
        snapshots = []
        for subscription in self._all("subscription"):
            if (subscription["state"] == "active" and subscription["kind"] == "event"
                    and self._binding_matches(subscription, context)
                    and not self._runtime(subscription["id"]).get("needs_rebind")):
                snapshots.append({"subscription": subscription,
                                  "report": self._get("report", subscription["report_id"])})
        return snapshots

    def _stage_event_data(self, state, events, snapshots, context):
        pending, seen = [], {}
        for event in events:
            reason = None
            if not isinstance(event, dict):
                reason = "malformed_event"
            else:
                try:
                    event_id = identifier(event.get("event_id"), "event_id")
                except InformationError:
                    reason = "invalid_event_id"
            if reason is None and (event.get("session_id") != context.get("session_id")
                    or event.get("observer") != context.get("observer")
                    or (event.get("world_id") is not None and context.get("world_id") is not None
                        and event["world_id"] != context["world_id"])):
                reason = "event_scope_mismatch"
            if reason:
                state.setdefault("gaps", []).append({"reason": reason})
                state["complete"] = False
                continue
            fingerprint = digest(event)
            if event_id in seen:
                if seen[event_id] != fingerprint:
                    state.setdefault("gaps", []).append({"event_id": event_id, "reason": "event_identity_conflict"})
                    state["complete"] = False
                continue
            seen[event_id] = fingerprint
            prior = self.db.execute("SELECT digest FROM info_events WHERE owner=? AND scope=? AND id=?",
                (self.owner, state["scope"], event_id)).fetchone()
            if prior is not None:
                if prior[0] != fingerprint:
                    state.setdefault("gaps", []).append({"event_id": event_id, "reason": "event_identity_conflict"})
                    state["complete"] = False
                    continue
            else:
                self.db.execute("INSERT INTO info_events VALUES(?,?,?,?,?)",
                    (self.owner, state["scope"], event_id, fingerprint, canonical(event)))
                for snapshot in snapshots:
                    sub = snapshot["subscription"]
                    if self._event_matches(sub, event):
                        self.db.execute("INSERT INTO info_event_targets VALUES(?,?,?,?,?,?)",
                            (self.owner, state["scope"], event_id, sub["id"], "pending", canonical(snapshot)))
            outstanding = self.db.execute("SELECT 1 FROM info_event_targets WHERE owner=? AND scope=? AND event_id=? "
                "AND status IN ('pending','collecting','ready') LIMIT 1",
                (self.owner, state["scope"], event_id)).fetchone()
            if outstanding:
                pending.append(copy.deepcopy(event))
        state.update(pending=pending, targets_staged=True)

    def _event_prepare(self, context):
        if not self.configure(None, "get")["config"]["effective"]["enabled"]:
            return None
        now = self._context()
        if now.get("status") != "ready":
            return None
        if (now.get("session_id") == context.get("session_id")
                and type(now.get("game_day")) is int and type(context.get("game_day")) is int
                and now["game_day"] < context["game_day"]):
            return None  # The next tick resets the rewind epoch and baselines.
        state = self._runtime("event-source")
        scope = self._event_scope(now, state)
        if state.get("scope") != scope:
            old_scope = state.get("scope")
            if old_scope:
                self.db.execute("UPDATE info_event_targets SET status='discarded' WHERE owner=? AND scope=? "
                    "AND status IN ('pending','collecting','ready')", (self.owner, old_scope))
            state = {"scope": scope, "cursor": None, "epoch": state.get("epoch", 0),
                     "reset_reason": state.get("reset_reason", "session_or_world_changed")}
        snapshots = self._event_subscribers(now)
        if state.get("pending"):
            if state.get("targets_staged") is not True:
                # Compatibility with a pre-ledger pending batch. Once staged,
                # its recipients never expand to newly created subscriptions.
                state.setdefault("batch_complete", state.get("complete", False))
                self._stage_event_data(state, state["pending"], snapshots, now)
                self._set_runtime("event-source", state)
            return {"scope": scope, "context": now, "poll": False}
        if not snapshots and not getattr(self.source, "event_types", ()):
            self._set_runtime("event-source", state)
            return None
        poll_id = uuid.uuid4().hex
        state.update(poll_claim=poll_id, last_attempt=utc_now())
        self._set_runtime("event-source", state)
        return {"scope": scope, "context": now, "poll": True, "id": poll_id,
                "cursor": copy.deepcopy(state.get("cursor")), "snapshots": snapshots}

    def _event_stage_batch(self, plan, batch):
        state = self._runtime("event-source")
        if state.get("scope") != plan["scope"] or state.get("poll_claim") != plan["id"]:
            return False
        after = self._context()
        rewound = (type(after.get("game_day")) is int and type(plan["context"].get("game_day")) is int
                   and after["game_day"] < plan["context"]["game_day"])
        if after.get("status") == "ready" and (self._event_scope(after, state) != plan["scope"] or rewound):
            state.pop("poll_claim", None)
            state.update(complete=False, error={"code": "event_scope_changed_during_poll"})
            self._set_runtime("event-source", state)
            return False
        if not isinstance(batch, dict) or not isinstance(batch.get("events", []), list) or not isinstance(batch.get("gaps", []), list):
            raise InformationError("invalid_event_batch", "Event source returned an invalid batch")
        canonical(batch)
        state.update(cursor=copy.deepcopy(batch.get("cursor")), complete=batch.get("complete") is True,
            batch_complete=batch.get("complete") is True, gaps=copy.deepcopy(batch.get("gaps", [])), last_attempt=utc_now())
        self._stage_event_data(state, batch.get("events", []), plan["snapshots"], plan["context"])
        if after.get("status") != "ready":
            # Keep a returned batch even if a health read is temporarily
            # uncertain; do not repoll a source that may have local effects.
            state.update(poll_health_unverified=True, complete=False)
        else:
            state.pop("poll_health_unverified", None)
        state.pop("poll_claim", None)
        state.pop("error", None)
        # Cursor, exact payloads, fingerprints and frozen recipients commit
        # together, before any report reads or external delivery.
        self._set_runtime("event-source", state)
        return True

    def _event_error(self, plan, exc):
        state = self._runtime("event-source")
        if plan is not None and state.get("scope") != plan.get("scope"):
            return
        state.pop("poll_claim", None)
        state.update(complete=False, error={"code": getattr(exc, "code", "event_source_error"), "message": str(exc)})
        self._set_runtime("event-source", state)

    def _event_target(self, scope, event_id, subscription_id):
        row = self.db.execute("SELECT status,body FROM info_event_targets WHERE owner=? AND scope=? AND event_id=? AND subscription_id=?",
            (self.owner, scope, event_id, subscription_id)).fetchone()
        return (row[0], json.loads(row[1])) if row is not None else (None, None)

    def _event_put_target(self, scope, event_id, subscription_id, status, body):
        self.db.execute("UPDATE info_event_targets SET status=?,body=? WHERE owner=? AND scope=? AND event_id=? AND subscription_id=?",
            (status, canonical(body), self.owner, scope, event_id, subscription_id))

    def _event_target_reason(self, body, scope):
        try:
            subscription = self._get("subscription", body["subscription"]["id"])
            report = self._get("report", body["report"]["id"])
        except InformationError:
            return "configuration_removed"
        if subscription["state"] != "active" or subscription["version"] != body["subscription"]["version"]:
            return "subscription_changed"
        if report["version"] != body["report"]["version"]:
            return "report_changed"
        state = self._runtime("event-source")
        after = self._context()
        if state.get("scope") != scope:
            return "scope_changed"
        if after.get("status") != "ready":
            return "source_unavailable"
        if self._runtime(subscription["id"]).get("needs_rebind"):
            return "world_revalidation_required"
        if self._event_scope(after, state) != scope or not self._binding_matches(subscription, after):
            return "scope_changed"
        return None

    def _event_head(self, scope):
        state = self._runtime("event-source")
        if state.get("scope") != scope or not state.get("pending"):
            return None
        event = state["pending"][0]
        ids = []
        for row in self.db.execute("SELECT subscription_id,status,body FROM info_event_targets WHERE owner=? AND scope=? AND event_id=?",
                                   (self.owner, scope, event["event_id"])).fetchall():
            if row[1] not in ("pending", "collecting", "ready"):
                continue
            body = json.loads(row[2]);reason = self._event_target_reason(body, scope)
            if reason and reason not in _EVENT_WAIT_REASONS:
                body["discard_reason"] = reason
                self._event_put_target(scope, event["event_id"], row[0], "discarded", body)
            else:
                ids.append(row[0])
        return {"event": copy.deepcopy(event), "ids": ids,
                "batch_complete": state.get("batch_complete", state.get("complete", False)),
                "gaps": copy.deepcopy(state.get("gaps", []))}

    def _event_claim(self, scope, event, subscription_id):
        if not self.configure(None, "get")["config"]["effective"]["enabled"]:
            return None
        status, body = self._event_target(scope, event["event_id"], subscription_id)
        if status not in ("pending", "collecting", "ready"):
            return None
        reason = self._event_target_reason(body, scope)
        if reason:
            if reason in _EVENT_WAIT_REASONS:
                return None
            body["discard_reason"] = reason
            self._event_put_target(scope, event["event_id"], subscription_id, "discarded", body)
            return None
        if status == "ready":
            return {"prepared": True, "scope": scope, "event": event, "subscription_id": subscription_id}
        replay = status == "collecting"
        claim_id = uuid.uuid4().hex
        body.pop("wait_reason", None)
        body.update(claim_id=claim_id, attempts=body.get("attempts", 0) + 1, replay=replay)
        self._event_put_target(scope, event["event_id"], subscription_id, "collecting", body)
        runtime = self._runtime(subscription_id)
        runtime.update(collection={"id": claim_id, "event_id": event["event_id"]},
            last_attempt={"collected_at": utc_now(), "event_id": event["event_id"], "status": "collecting"})
        self._set_runtime(subscription_id, runtime)
        return {"id": claim_id, "scope": scope, "event": event, "subscription_id": subscription_id,
                "subscription": body["subscription"], "report": body["report"],
                "context": self._context(), "replay": replay, "prepared": False}

    def _event_store_projection(self, job, result):
        status, body = self._event_target(job["scope"], job["event"]["event_id"], job["subscription_id"])
        if status != "collecting" or body.get("claim_id") != job["id"]:
            return
        runtime = self._runtime(job["subscription_id"])
        if runtime.get("collection", {}).get("id") == job["id"]:
            runtime.pop("collection", None)
            self._set_runtime(job["subscription_id"], runtime)
        reason = self._event_target_reason(body, job["scope"])
        if reason in _EVENT_WAIT_REASONS:
            # Health uncertainty cannot consume an event. A later attempt may
            # reconstruct only through an explicit durable replay provider.
            body["wait_reason"] = reason
            self._event_put_target(job["scope"], job["event"]["event_id"], job["subscription_id"], "collecting", body)
        elif reason:
            body["discard_reason"] = reason
            self._event_put_target(job["scope"], job["event"]["event_id"], job["subscription_id"], "discarded", body)
        else:
            body["prepared_result"] = result
            self._event_put_target(job["scope"], job["event"]["event_id"], job["subscription_id"], "ready", body)

    def _event_publish(self, job, generated_count, allow_group_overflow):
        status, body = self._event_target(job["scope"], job["event"]["event_id"], job["subscription_id"])
        if status != "ready":
            return None
        reason = self._event_target_reason(body, job["scope"])
        if reason:
            if reason in _EVENT_WAIT_REASONS:
                return None
            body["discard_reason"] = reason
            self._event_put_target(job["scope"], job["event"]["event_id"], job["subscription_id"], "discarded", body)
            return None
        settings = self.configure(None, "get")["config"]["effective"]
        if not settings["enabled"] or (not allow_group_overflow and generated_count >= settings["max_results_per_tick"]):
            return None
        result = copy.deepcopy(body["prepared_result"])
        if self.output is None:
            result["delivery"]["delivered_at"] = utc_now()
        self.db.execute("INSERT INTO info_results VALUES(?,?,?)", (self.owner, result["result_id"], canonical(result)))
        body.pop("prepared_result", None)
        body["result_id"] = result["result_id"]
        self._event_put_target(job["scope"], job["event"]["event_id"], job["subscription_id"], "committed", body)
        runtime = self._runtime(job["subscription_id"])
        runtime.update(state="active" if self._capture_ready(runtime) else "source_unavailable",
            last_result_id=result["result_id"],
            last_attempt={"collected_at": result["collected_at"], "event_id": job["event"]["event_id"], "status": result["status"]})
        self._set_runtime(job["subscription_id"], runtime)
        return result

    def _event_finish(self, scope, event):
        state = self._runtime("event-source")
        if state.get("scope") != scope or not state.get("pending"):
            return False
        outstanding = self.db.execute("SELECT 1 FROM info_event_targets WHERE owner=? AND scope=? AND event_id=? "
            "AND status IN ('pending','collecting','ready') LIMIT 1", (self.owner, scope, event["event_id"])).fetchone()
        if outstanding:
            return False
        if digest(state["pending"][0]) != digest(event):
            return False
        state["pending"] = state["pending"][1:]
        self._set_runtime("event-source", state)
        return True

    def _collect_events(self, context):
        """Archive one source page before scheduled reports read its history."""
        plan = None
        try:
            plan = self._transaction(lambda: self._event_prepare(context))
            if plan is None:
                return None
            if plan["poll"]:
                batch = self.source.poll_events(copy.deepcopy(plan["context"]), copy.deepcopy(plan["cursor"]))
                if not self._transaction(lambda: self._event_stage_batch(plan, batch)):
                    return None
            return plan
        except Exception as exc:
            self._transaction(lambda: self._event_error(plan, exc))
            return None

    def _poll_events(self, plan, generated):
        if plan is None:
            return
        try:
            while True:
                head = self._transaction(lambda: self._event_head(plan["scope"]))
                if head is None:
                    break
                settings = self.configure(None, "get")["config"]["effective"]
                if not settings["enabled"]:
                    break
                if generated and len(generated) + len(head["ids"]) > settings["max_results_per_tick"]:
                    break
                allow_overflow = not generated
                for subscription_id in head["ids"]:
                    job = self._transaction(lambda: self._event_claim(plan["scope"], head["event"], subscription_id))
                    if job is None:
                        continue
                    if not job["prepared"]:
                        samples = (self._collect(job["report"]["queries"], job["context"], event=job["event"], replay=True)
                                   if job["replay"] else None)
                        result = self._build_result(job["report"]["queries"], job["context"], "event",
                            job["subscription"], event=job["event"], samples=samples, report=job["report"])
                        result["event_batch"] = {"complete": head["batch_complete"] is True,
                                                 "gaps": copy.deepcopy(head["gaps"])}
                        if job["event"].get("complete") is not True or head["batch_complete"] is not True:
                            result["complete"] = False
                            if result["status"] == "complete":
                                result["status"] = "partial"
                        self._transaction(lambda: self._event_store_projection(job, result))
                    result = self._transaction(lambda: self._event_publish(job, len(generated), allow_overflow))
                    if result is not None:
                        generated.append(result)
                if not self._transaction(lambda: self._event_finish(plan["scope"], head["event"])):
                    break
        except Exception as exc:
            self._transaction(lambda: self._event_error(plan, exc))
