"""Collect mission lists and rules without unrelated trigger-progress reads.

The existing native capture and normalizer retain all their identity, code,
cleanup and double-pass checks. Selected M02 progress and eligibility collect
only the requested trigger trees. Cached state lives inside one source.read.
"""
from contextlib import contextmanager
from contextvars import ContextVar
from copy import deepcopy
from dataclasses import dataclass, field


RULE_TOPICS = frozenset({"M03", "M04", "M05"})
STATE_ONLY_FIELDS = frozenset({"completion_status", "prerequisites"})


def capture_rule_inputs(installation, country, *, include_completed=True, include_tasks=True):
    from .mission_memory import capture
    return capture(installation, country, include_completed=include_completed, include_tasks=include_tasks,
                   include_prerequisites=True, include_conditions=True, include_triggers=False)


@dataclass
class _ReadScope:
    context: dict
    reader: object
    trigger_selector: dict | None = None
    cache: dict = field(default_factory=dict)
    reader_calls: int = 0
    cache_hits: int = 0


class MissionScopedReader:
    def __init__(self, original, rule_reader=None):
        self.original = original
        self.rule_reader = rule_reader if rule_reader is not None else original
        self._scope = ContextVar('mission_read_scope', default=None)

    def __getattr__(self, name):
        return getattr(self.original, name)

    @contextmanager
    def collection(self, context, *, trigger_selector=None):
        # A new operation always gets a new cache, including at the same game
        # date. ContextVar tokens also isolate nested calls and other threads.
        reader = self.original if trigger_selector is not None else self.rule_reader
        scope = _ReadScope(deepcopy(context), reader, deepcopy(trigger_selector))
        token = self._scope.set(scope)
        try:
            yield scope
        finally:
            self._scope.reset(token)
            scope.cache.clear()

    def __call__(self, country):
        scope = self._scope.get()
        if scope is None:
            return self.original(country)
        if country in scope.cache:
            scope.cache_hits += 1
        else:
            scope.reader_calls += 1
            try:
                if (scope.trigger_selector is not None
                        and getattr(scope.reader, 'supports_trigger_selection', False) is True):
                    value = scope.reader(country, trigger_selector=deepcopy(scope.trigger_selector))
                else:
                    value = scope.reader(country)
                scope.cache[country] = (True, deepcopy(value))
            except Exception as exc:
                # A failed capture is not retried by another field owner in
                # this operation. The next independent request starts fresh.
                scope.cache[country] = (False, exc)
        succeeded, value = scope.cache[country]
        if not succeeded:
            raise value
        return deepcopy(value)


class MissionReadSource:
    """Preserve existing routes/capabilities while sharing one rule snapshot."""
    def __init__(self, source, reader):
        self.source = source
        self.reader = reader

    def __getattr__(self, name):
        return getattr(self.source, name)

    def _read(self, query, context, event=None):
        read = self.source.read if event is None else self.source.read_event
        args = (query, context) if event is None else (query, context, event)
        mission_rules = (query.get('topic') in RULE_TOPICS
                         or query.get('topic') == 'M01'
                         or (query.get('topic') == 'M02'
                             and set(query.get('fields', [])) <= STATE_ONLY_FIELDS)
                         or (query.get('topic') == 'G01' and 'task_targets' in query.get('fields', [])))
        trigger_selector = (query.get('parameters') or None
                            if query.get('topic') == 'M02' and not mission_rules else None)
        if not mission_rules and trigger_selector is None:
            return read(*args)
        with self.reader.collection(context, trigger_selector=trigger_selector) as scope:
            result = read(*args)
            result = deepcopy(result)
            result.setdefault('source', {})['mission_collection'] = {
                'scope': 'one_source_read', 'state_reader_calls': scope.reader_calls,
                'shared_state_hits': scope.cache_hits, 'cross_request_cache': False,
                'trigger_progress_requested': trigger_selector is not None,
                'snapshot_atomic_main_thread': False,
            }
            if trigger_selector is not None:
                result['source']['mission_collection']['trigger_task_selector'] = deepcopy(trigger_selector)
            return result

    def read(self, query, context):
        return self._read(query, context)

    def read_event(self, query, context, event):
        return self._read(query, context, event)
