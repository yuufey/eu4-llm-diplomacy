"""Compose state and rule adapters without inventing a shared game session.

The primary source owns runtime identity and event collection. Read adapters
own disjoint topic routes; fields they do not implement remain explicit gaps.
"""
from __future__ import annotations

from copy import deepcopy

from .model import InformationError, canonical
from .catalog import observer_roles_for_query


class CompositeSource:
    def __init__(self, primary, adapters=()):
        self.primary = primary
        self.adapters = tuple(adapters)
        self._topics = {entry["topic_id"]: deepcopy(entry) for entry in primary.catalog()}
        self._routes = {}
        for adapter in self.adapters:
            for entry in adapter.catalog():
                topic = entry["topic_id"]
                if topic not in self._topics:
                    raise InformationError("unknown_adapter_topic", topic)
                if not entry.get("fields"):
                    raise InformationError("invalid_adapter", f"No fields for {topic}")
                prior = self._routes.setdefault(topic, [])
                if any(set(entry["fields"]) & set(old["fields"]) for _, old in prior):
                    raise InformationError("duplicate_adapter_topic", topic)
                if prior:
                    # A query has one parameter object. Distinct owners must
                    # agree on its schema before they can share a topic.
                    schemas = [deepcopy(item.get("parameters", {})) for _, item in prior] + [deepcopy(entry.get("parameters", {}))]
                    for schema in schemas:
                        schema.setdefault("required", [])
                    if any(canonical(schema) != canonical(schemas[0]) for schema in schemas[1:]):
                        raise InformationError("adapter_parameter_schema_conflict", topic)
                original = self._topics[topic]
                merged = dict(original, **{k: deepcopy(v) for k, v in entry.items() if k != "fields"})
                merged["fields"] = dict(deepcopy(original["fields"]), **deepcopy(entry["fields"]))
                if prior:
                    owners = [item for _, item in prior] + [entry]
                    for key in ("object_types", "supported_versions", "triggers", "observer_roles"):
                        merged[key] = list(dict.fromkeys(value for owner in owners for value in owner.get(key, [])))
                    merged["source"] = "CompositeSource"
                    merged["context_scope"] = "adapter_managed"
                    merged["adapter_sources"] = [type(owner).__name__ for owner, _ in prior] + [type(adapter).__name__]
                    visibility = list(dict.fromkeys(owner.get("visibility") for owner in owners))
                    if len(visibility) > 1:
                        merged["visibility"] = "adapter_managed"
                    notes = list(dict.fromkeys(owner.get("scope_note") for owner in owners))
                    if len(notes) > 1:
                        # A last-writer note must not describe all disjoint fields.
                        merged.pop("scope_note", None)
                    for _, owner in [*prior, (adapter, entry)]:
                        for name in owner["fields"]:
                            merged["fields"][name]["triggers"] = deepcopy(owner.get("triggers", []))
                            merged["fields"][name]["object_types"] = deepcopy(owner.get("object_types", []))
                            merged["fields"][name]["supported_versions"] = deepcopy(owner.get("supported_versions", []))
                            for key in ("context_scope", "visibility", "scope_note"):
                                if key in owner:
                                    merged["fields"][name].setdefault(key, deepcopy(owner[key]))
                self._topics[topic] = merged
                prior.append((adapter, deepcopy(entry)))
        canonical(list(self._topics.values()))

    @property
    def event_types(self):
        return tuple(getattr(self.primary, "event_types", ()))

    def context(self):
        return self.primary.context()

    def catalog(self):
        return deepcopy(list(self._topics.values()))

    def validate_event_filter(self, event_filter):
        validator = getattr(self.primary, "validate_event_filter", None)
        if callable(validator):
            return validator(deepcopy(event_filter))
        return None

    def validate_query(self, query):
        topic = query["topic"]
        if topic not in self._routes:
            validator = getattr(self.primary, "validate_query", None)
            return validator(query) if callable(validator) else deepcopy(query)
        routes = self._routes[topic]
        if len(routes) > 1:
            normalized = None
            for subquery, entry in self.query_capabilities(query):
                adapter = next(owner for owner, candidate in routes if candidate is entry)
                validator = getattr(adapter, "validate_query", None)
                value = validator(deepcopy(subquery)) if callable(validator) else subquery
                selector = {key: value for key, value in value.items() if key != "fields"}
                if normalized is not None and canonical(selector) != canonical(normalized):
                    raise InformationError("adapter_query_normalization_conflict", topic)
                normalized = selector
            return dict(normalized or deepcopy(query), fields=deepcopy(query["fields"]))
        adapter, entry = routes[0]
        implemented = [field for field in query["fields"] if field in entry["fields"]]
        # Validate selectors even if the request contains only missing fields.
        probe = dict(deepcopy(query), fields=implemented or [next(iter(entry["fields"]))])
        validator = getattr(adapter, "validate_query", None)
        validated = validator(probe) if callable(validator) else probe
        return dict(validated, fields=deepcopy(query["fields"]))

    def query_capabilities(self, query):
        """Return the actual field owners for scope and trigger checks."""
        routes = self._routes.get(query["topic"], [])
        selected = []
        for _, entry in routes:
            fields = [field for field in query["fields"] if field in entry["fields"]]
            if fields:
                selected.append((dict(deepcopy(query), fields=fields), entry))
        applicable = [(subquery, entry) for subquery, entry in selected
                      if query["object"].get("type") in entry.get("object_types", [])]
        if applicable:
            # A default field selection can span different object views.
            # Validate the owners of this view; retain a direct selector error
            # when the request has no applicable owner at all.
            selected = applicable
        if not selected and routes:
            # Missing planned fields still need a valid selector; prefer an
            # owner that admits the requested object type.
            entry = next((entry for _, entry in routes if query["object"].get("type") in entry.get("object_types", [])), routes[0][1])
            selected = [(dict(deepcopy(query), fields=[next(iter(entry["fields"]))]), entry)]
        return selected or [(deepcopy(query), self._topics[query["topic"]])]

    def query_catalog(self, query):
        capabilities = self.query_capabilities(query)
        return deepcopy(capabilities[0][1] if len(capabilities) == 1 else self._topics[query["topic"]])

    @staticmethod
    def _scope_reason(query, entry, context):
        static = entry.get("context_scope") == "static_rules"
        if not static and context.get("status") != "ready":
            return "source_unavailable"
        if (not static or context.get("game_version") is not None) and context.get("game_version") not in entry.get("supported_versions", []):
            return "unsupported_game_version"
        if not static:
            if query["object"].get("session_id", context.get("session_id")) != context.get("session_id"):
                return "session_scope_mismatch"
            values = [query["object"].get(role, query.get("parameters", {}).get(role))
                      for role in observer_roles_for_query(entry, query)]
            values = [value for value in values if value is not None]
            if values and context.get("observer") not in values:
                return "observer_scope_mismatch"
        return None

    def _read_multi(self, query, context, event):
        fields, sources, scopes = {}, [], {}
        objects = [deepcopy(query['object'])]
        complete = True
        for adapter, entry in self._routes[query["topic"]]:
            selected = [field for field in query["fields"] if field in entry["fields"]]
            if not selected:
                continue
            subquery = dict(deepcopy(query), fields=selected)
            if query['object'].get('type') == 'war' and objects[0].get('war_id'):
                subquery['object'] = deepcopy(objects[0])
            scope = entry.get("context_scope", "game")
            scopes.update({field: scope for field in selected})
            try:
                if query["object"].get("type") not in entry.get("object_types", []):
                    fields.update({field: {"status": "not_applicable", "reason": "OBJECT_TYPE_NOT_SUPPORTED_BY_ADAPTER"}
                                   for field in selected})
                    sources.append({"fields": selected, "source": {"name": type(adapter).__name__, "context_scope": scope}})
                    continue
                reason = self._scope_reason(subquery, entry, context)
                if reason:
                    raise InformationError(reason, reason)
                sample = self._read_from(adapter, subquery, deepcopy(context), event)
                if not isinstance(sample, dict):
                    raise InformationError("invalid_source_result", "Adapter result must be an object")
                canonical(sample)
                resolved = sample.get('objects', [])
                if (query['object'].get('type') == 'war' and len(resolved) == 1
                        and resolved[0].get('war_id')):
                    if any(resolved[0].get(key) != value for key, value in subquery['object'].items()):
                        raise InformationError('resolved_object_mismatch', 'Adapter selected a different war')
                    objects[0]['war_id'] = resolved[0]['war_id']
                for field in selected:
                    fields[field] = deepcopy(sample.get("fields", {}).get(field, {"status": "unknown", "reason": "field_missing"}))
                sources.append({"fields": selected, "source": deepcopy(sample.get("source", {}))})
                complete = complete and sample.get("complete") is True
            except Exception as exc:
                fields.update({field: {"status": "unavailable", "reason": getattr(exc, "code", "source_error")} for field in selected})
                sources.append({"fields": selected, "source": {"name": type(adapter).__name__, "context_scope": scope},
                                "error": {"code": getattr(exc, "code", "source_error"), "message": str(exc)}})
                complete = False
        for field in query["fields"]:
            if field not in fields:
                fields[field] = {"status": "unsupported", "reason": "FIELD_NOT_IMPLEMENTED_BY_ADAPTER"}
                complete = False
        return {"query": deepcopy(query), "objects": objects, "fields": fields,
                "complete": complete, "field_context_scopes": scopes,
                "source": {"name": "CompositeSource", "context_scope": "mixed", "sources": sources}}

    @staticmethod
    def _read_from(source, query, context, event=None):
        if event is not None:
            read_event = getattr(source, "read_event", None)
            if callable(read_event):
                return read_event(query, context, event)
        return source.read(query, context)

    def _read_route(self, query, context, event=None):
        topic = query["topic"]
        if topic not in self._routes:
            return self._read_from(self.primary, query, context, event)
        routes = self._routes[topic]
        if len(routes) > 1:
            selected = [(adapter, entry) for adapter, entry in routes
                        if set(query['fields']) & set(entry['fields'])]
            if (len(selected) != 1
                    or query.get('object', {}).get('type') not in selected[0][1].get('object_types', [])
                    or self._scope_reason(query, selected[0][1], context)):
                return self._read_multi(query, context, event)
            # An unrequested second owner must not strip the selected owner's
            # date/source proof or disable its scoped partial comparisons.
            adapter, entry = selected[0]
        else:
            adapter, entry = routes[0]
        implemented = [field for field in query["fields"] if field in entry["fields"]]
        if implemented:
            sample = self._read_from(
                adapter,
                dict(deepcopy(query), fields=implemented),
                context,
                event,
            )
            if not isinstance(sample, dict):
                raise InformationError("invalid_source_result", "Adapter result must be an object")
            sample = deepcopy(sample)
        else:
            sample = {"fields": {}, "complete": False,
                      "source": {"name": type(adapter).__name__, "context_scope": entry.get("context_scope", "game")}}
        fields = sample.setdefault("fields", {})
        for field in query["fields"]:
            if field not in fields:
                fields[field] = {"status": "unsupported", "reason": "FIELD_NOT_IMPLEMENTED_BY_ADAPTER"}
                sample["complete"] = False
        sample["query"] = deepcopy(query)
        sample.setdefault("objects", [deepcopy(query["object"])])
        return sample

    def read(self, query, context):
        return self._read_route(query, context)

    def read_event(self, query, context, event):
        return self._read_route(query, context, event)

    def replay_event(self, query, context, event):
        """Rebuild an event projection using only explicit replay hooks."""
        from .event_replay import replay_composite_event

        return replay_composite_event(self, query, context, event)

    def change_comparison(self, query, sample, context):
        """A scoped partial comparison must cover the entire query at one owner."""
        routes = self._routes.get(query.get('topic'), [])
        if not routes:
            owner = self.primary
        else:
            owners = [(owner, entry) for owner, entry in routes
                      if set(query.get('fields', [])) <= set(entry['fields'])
                      and query.get('object', {}).get('type') in entry.get('object_types', [])]
            if len(owners) != 1:
                return None
            owner = owners[0][0]
        hook = getattr(owner, 'change_comparison', None)
        return hook(deepcopy(query), deepcopy(sample), deepcopy(context)) if callable(hook) else None

    def poll_events(self, context, cursor):
        # Read adapters are not an additional consumer of the same native
        # stream. The primary remains the single shared event collector.
        return self.primary.poll_events(context, cursor)
