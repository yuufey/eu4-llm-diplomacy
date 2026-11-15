"""Per-query sampling windows for read-only macro information."""
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field

_CLOCK_KEYS = frozenset({'game_date', 'game_date_raw_hex', 'game_day'})
_MACRO_PREFIXES = frozenset({'C', 'N', 'F', 'R', 'M', 'T', 'G', 'W'})
_CURRENT = ContextVar('information_observation_window', default=None)


@dataclass
class ObservationWindow:
    dates: list[int] = field(default_factory=list)

    def metadata(self):
        return {'basis': 'sampled_game_state', 'start_game_date': min(self.dates) if self.dates else None,
                'end_game_date': max(self.dates) if self.dates else None,
                'atomic_snapshot': False, 'clock_progress_allowed': True}


def active():
    return _CURRENT.get() is not None


def dates_match(*dates):
    if not dates or any(type(value) is not int or value < 0 for value in dates):
        return False
    window = _CURRENT.get()
    if window is None:
        return all(value == dates[0] for value in dates)
    if any(left > right for left, right in zip(dates, dates[1:])):
        return False
    window.dates.extend(dates)
    return True


def context_identity(context, keys):
    return tuple(context.get(key) for key in keys if not active() or key not in _CLOCK_KEYS)


def without_clock(value, *, date_labels=()):
    if not active():
        return value
    if isinstance(value, dict):
        return {key: without_clock(child, date_labels=date_labels)
                for key, child in value.items() if key not in _CLOCK_KEYS}
    if isinstance(value, (list, tuple)):
        rows = [without_clock(child, date_labels=date_labels) for child in value
                if not (isinstance(child, dict) and child.get('label') in date_labels)]
        return tuple(rows) if isinstance(value, tuple) else rows
    return value


@contextmanager
def sampled_read(query, context, *, enabled=True):
    topic = query.get('topic', '')
    selected = (enabled and context.get('mode') == 'live' and isinstance(topic, str)
                and (topic[:1] in _MACRO_PREFIXES or topic in ('P06', 'A01', 'D03'))
                and type(context.get('game_date')) is int)
    if not selected:
        yield None
        return
    window = ObservationWindow([context['game_date']])
    token = _CURRENT.set(window)
    try:
        yield window
    finally:
        _CURRENT.reset(token)
