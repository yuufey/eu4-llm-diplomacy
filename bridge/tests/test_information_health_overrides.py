"""Keep the original no-argument health override contract for adapters."""
import pytest

from bridge.diplomacy import ObserverSession


@pytest.mark.parametrize('override_kind', ['subclass', 'instance'])
def test_information_health_calls_existing_no_argument_overrides_once(override_kind):
    calls = []

    def custom_health():
        calls.append('health')
        return {'status': 'ready', 'date_raw': 100}

    if override_kind == 'subclass':
        class Session(ObserverSession):
            def health(self):
                return custom_health()

        session = object.__new__(Session)
    else:
        session = object.__new__(ObserverSession)
        session.health = custom_health
    assert session.information_health() == {'status': 'ready', 'date_raw': 100}
    assert calls == ['health']


def test_base_information_health_allows_clock_progress_and_execution_health_stays_strict(monkeypatch):
    flags = []

    def health(self, *, allow_date_progress=False):
        flags.append(allow_date_progress)
        return {'status': 'ready'}

    monkeypatch.setattr(ObserverSession, 'health', health)
    session = object.__new__(ObserverSession)
    assert session.information_health()['status'] == 'ready'
    assert session.health()['status'] == 'ready'
    assert flags == [True, False]


def test_type_error_from_custom_health_is_not_retried():
    calls = []
    session = object.__new__(ObserverSession)

    def broken_health():
        calls.append('health')
        raise TypeError('internal adapter error')

    session.health = broken_health
    with pytest.raises(TypeError, match='internal adapter error'):
        session.information_health()
    assert calls == ['health']
