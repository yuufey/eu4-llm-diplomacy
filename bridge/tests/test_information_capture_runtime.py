"""Runtime wiring boundaries for managed battle capture."""

from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from tools.serve_information import _build_runtime


class _Harness:
    def __init__(self, *, mode="live", service_error=None, manager_error=None):
        self.events = []
        self.service_error = service_error
        self.manager_error = manager_error
        self.binding = {
            "session_id": "battle-session",
            "installation": "0000000000000001",
            "generation": "0000000000000002",
            "mode": mode,
        }
        self.streams = []
        self.ingestors = []
        self.managers = []
        self.services = []
        self.journals = []
        self.battle_database = None


class _Journal:
    def __init__(self, harness, *args, **kwargs):
        self.harness = harness
        self.args = args
        self.kwargs = kwargs
        self.closed = False
        harness.journals.append(self)

    def close(self):
        if not self.closed:
            self.closed = True
            self.harness.events.append("journal.close")


class _Session:
    experiment_id = "battle-capture-experiment"
    session_id = "battle-capture-session"

    def __init__(self, path, executable):
        self.path = Path(path)
        self.executable = Path(executable)


class _DiplomacyTools:
    def __init__(self, journal, session):
        self.journal = journal
        self.session = session

    def inspect_diplomatic_action(self, *args, **kwargs):
        raise AssertionError("Runtime wiring tests must not inspect game actions")


class _Source:
    event_types = ()

    def __init__(self, harness, *args, **kwargs):
        self.harness = harness
        self.args = args
        self.kwargs = kwargs

    def context(self):
        return {"status": "ready", "mode": "live", "context_scope": "live"}


class _Composite:
    def __init__(self, primary, adapters=()):
        self.primary = primary
        self.adapters = tuple(adapters)

    def context(self):
        return self.primary.context()


class _Adapter:
    def __init__(self, *args, **kwargs):
        self.args = args
        self.kwargs = kwargs

    def context(self):
        return self.args[0].context()

    def read(self, *args, **kwargs):
        raise AssertionError("Runtime wiring tests must not read adapter data")


class _Localization:
    def __init__(self, source):
        self.source = source


class _BattleStream:
    def __init__(self, harness, primary, config_path):
        self.harness = harness
        self.primary = primary
        self.config_path = Path(config_path)
        self.battles = SimpleNamespace(
            database=(harness.battle_database
                      if harness.battle_database is not None
                      else Path("battle-stream.sqlite3")),
            binding=harness.binding,
        )
        self.ingestor = None
        self.capture_manager = None
        harness.streams.append(self)

    def context(self):
        return self.primary.context()

    def close_capture(self):
        self.harness.events.append("source.close_capture")
        if self.capture_manager is not None:
            return self.capture_manager.close()
        return None


class _Ingestor:
    def __init__(self, harness, installation, database, expected_binding=None):
        self.harness = harness
        self.installation = installation
        self.database = database
        self.expected_binding = expected_binding
        self.closed = False
        harness.ingestors.append(self)

    def close(self):
        if not self.closed:
            self.closed = True
            self.harness.events.append("ingestor.close")


class _CaptureManager:
    def __init__(self, harness, installation, expected_binding):
        harness.events.append("manager.init")
        if harness.manager_error is not None:
            raise harness.manager_error
        self.harness = harness
        self.installation = installation
        self.expected_binding = expected_binding
        self.closed = False
        harness.managers.append(self)

    def close(self):
        if not self.closed:
            self.closed = True
            self.harness.events.append("manager.close")
        return {"status": "closed"}


class _Service:
    def __init__(self, harness, source, database, owner="llm", **kwargs):
        if harness.service_error is not None:
            raise harness.service_error
        self.harness = harness
        self.source = source
        self.database = database
        self.owner = owner
        harness.services.append(self)

    def close(self):
        self.harness.events.append("service.close")
        closer = getattr(self.source, "close_capture", None)
        if callable(closer):
            closer()

    def previous_war_forces(self, *_args, **_kwargs):
        raise AssertionError("factory wiring must not collect war-force history")

    def observed_events(self, *_args, **_kwargs):
        raise AssertionError("factory wiring must not collect event history")

    def action_cooldown_expiries(self, *_args, **_kwargs):
        raise AssertionError("factory wiring must not collect cooldown history")


def _args(tmp_path, **overrides):
    values = dict(
        recorded_manifest=None,
        operator_session=None,
        observer="FRA",
        static_game_data=False,
        mission_game_data=False,
        static_game_root=None,
        static_user_data=None,
        mission_save=None,
        journal=tmp_path / "journal.sqlite3",
        database=tmp_path / "information.sqlite3",
        owner="battle-capture-runtime",
        battle_stream=None,
        battle_ingest_installation=None,
        battle_manage_capture=False,
    )
    values.update(overrides)
    return SimpleNamespace(**values)


@pytest.fixture
def wiring(monkeypatch):
    """Replace every runtime constructor used by _build_runtime with a stub."""

    import bridge.diplomacy as diplomacy
    import bridge.diplomacy_journal as diplomacy_journal
    import bridge.information.battle_capture as battle_capture
    import bridge.information.battle_ingest as battle_ingest
    import bridge.information.battles as battles
    import bridge.information.composite as composite
    import bridge.information.country_records as country_records
    import bridge.information.country_state as country_state
    import bridge.information.diplomat_tasks as diplomat_tasks
    import bridge.information.domestic_pressure as domestic_pressure
    import bridge.information.military_quality as military_quality
    import bridge.information.native_localization as native_localization
    import bridge.information.relation_state as relation_state
    import bridge.information.service as service
    import bridge.information.sources as sources
    import bridge.information.subject_relations as subject_relations
    import bridge.information.trade_details as trade_details
    import bridge.information.trade_home as trade_home
    import bridge.information.trade_income as trade_income
    import bridge.information.trade_power as trade_power
    import bridge.information.trade_transfer as trade_transfer
    import work.local_config as local_config

    harness = _Harness()
    monkeypatch.setattr(diplomacy, "ObserverSession", _Session)
    monkeypatch.setattr(diplomacy, "DiplomacyTools", _DiplomacyTools)
    monkeypatch.setattr(diplomacy_journal, "DurableJournal",
                        lambda *args, **kwargs: _Journal(harness, *args, **kwargs))
    monkeypatch.setattr(local_config, "game_exe", lambda: Path("fake-game.exe"))
    monkeypatch.setattr(sources, "DiplomacySource",
                        lambda *args, **kwargs: _Source(harness, *args, **kwargs))
    monkeypatch.setattr(sources, "RecordedSource", _Source)
    monkeypatch.setattr(composite, "CompositeSource", _Composite)
    monkeypatch.setattr(native_localization, "NativeLocalizationReader", _Localization)
    monkeypatch.setattr(service, "InformationService",
                        lambda source, database, owner="llm", **kwargs:
                        _Service(harness, source, database, owner, **kwargs))

    for module, name in (
        (country_state, "NativeCountryStateSource"),
        (domestic_pressure, "NativeDomesticPressureSource"),
        (subject_relations, "NativeSubjectRelationSource"),
        (relation_state, "NativeRelationSource"),
        (trade_income, "NativeTradeIncomeSource"),
        (trade_home, "NativeTradeHomeSource"),
        (trade_power, "NativeTradePowerSource"),
        (trade_details, "NativeTradeDetailsSource"),
        (trade_transfer, "NativeTradeTransferSource"),
        (military_quality, "NativeMilitaryQualitySource"),
        (country_records, "NativeCountryRecordsSource"),
        (diplomat_tasks, "NativeDiplomatTasksSource"),
    ):
        monkeypatch.setattr(module, name, _Adapter)

    monkeypatch.setattr(
        battles,
        "BattleInformationSource",
        SimpleNamespace(from_config=lambda primary, path: _BattleStream(harness, primary, path)),
    )
    monkeypatch.setattr(
        battle_ingest,
        "LiveBattleIngestor",
        lambda installation, database, expected_binding=None:
        _Ingestor(harness, installation, database, expected_binding),
    )
    monkeypatch.setattr(
        battle_capture,
        "BattleCaptureManager",
        lambda installation, expected_binding:
        _CaptureManager(harness, installation, expected_binding),
    )
    return harness


def _live_args(tmp_path, *, manage=False):
    installation = tmp_path / "installation.json"
    return _args(
        tmp_path,
        operator_session=installation,
        battle_ingest_installation=installation,
        battle_stream=tmp_path / "battle-stream.json",
        battle_manage_capture=manage,
    )


def test_readonly_ingestor_keeps_legacy_path_without_manager(tmp_path, wiring):
    service, journal = _build_runtime(_live_args(tmp_path))
    stream = wiring.streams[0]
    ingestor = wiring.ingestors[0]
    try:
        assert wiring.managers == []
        assert stream.capture_manager is None
        assert stream.ingestor is ingestor
        assert service.battle_ingestor is ingestor
    finally:
        service.close()
        ingestor.close()
        journal.close()


def test_managed_runtime_passes_same_installation_and_binding_and_attaches(tmp_path, wiring):
    args = _live_args(tmp_path, manage=True)
    service, journal = _build_runtime(args)
    stream = wiring.streams[0]
    ingestor = wiring.ingestors[0]
    manager = wiring.managers[0]
    try:
        assert ingestor.installation == args.battle_ingest_installation
        assert ingestor.expected_binding is stream.battles.binding
        assert manager.installation == args.battle_ingest_installation
        assert manager.expected_binding is stream.battles.binding
        assert stream.ingestor is ingestor
        assert stream.capture_manager is manager
        assert service.battle_ingestor is ingestor
    finally:
        service.close()
        ingestor.close()
        journal.close()


def test_managed_runtime_rejects_recorded_binding_and_closes_ingestor(tmp_path, wiring):
    wiring.binding["mode"] = "recorded"
    with pytest.raises(ValueError, match="live battle stream"):
        _build_runtime(_live_args(tmp_path, manage=True))

    assert wiring.managers == []
    assert len(wiring.ingestors) == 1
    assert wiring.ingestors[0].closed is True


def test_close_releases_source_capture_before_ingestor(tmp_path, wiring):
    service, journal = _build_runtime(_live_args(tmp_path, manage=True))
    ingestor = wiring.ingestors[0]
    try:
        service.close()
        ingestor.close()
        assert wiring.events.index("source.close_capture") < wiring.events.index("ingestor.close")
        assert wiring.events.index("manager.close") < wiring.events.index("ingestor.close")
    finally:
        journal.close()


def test_service_initialization_failure_closes_source_then_ingestor(tmp_path, monkeypatch, wiring):
    wiring.service_error = RuntimeError("service init failed")
    with pytest.raises(RuntimeError, match="service init failed"):
        _build_runtime(_live_args(tmp_path, manage=True))

    assert wiring.events.index("source.close_capture") < wiring.events.index("manager.close")
    assert wiring.events.index("manager.close") < wiring.events.index("ingestor.close")


def test_manager_initialization_failure_closes_ingestor(tmp_path, wiring):
    wiring.manager_error = RuntimeError("manager init failed")
    with pytest.raises(RuntimeError, match="manager init failed"):
        _build_runtime(_live_args(tmp_path, manage=True))

    assert wiring.ingestors[0].closed is True


def test_managed_runtime_requires_matching_operator_and_ingest_installation(tmp_path, wiring):
    args = _live_args(tmp_path, manage=True)
    args.battle_ingest_installation = tmp_path / "other-installation.json"
    with pytest.raises(ValueError, match="matching"):
        _build_runtime(args)

    assert wiring.ingestors == []
    assert wiring.managers == []


@pytest.mark.parametrize("alias_kind", ("same_path", "normalized_path", "hard_link"))
def test_ingest_database_alias_is_rejected_before_constructors_and_closes_journal(
    tmp_path, wiring, alias_kind
):
    battle_database = tmp_path / "battle.sqlite3"
    if alias_kind == "same_path":
        service_database = battle_database
    elif alias_kind == "normalized_path":
        service_database = tmp_path / "nested" / ".." / "battle.sqlite3"
    else:
        battle_database.write_bytes(b"sqlite-placeholder")
        service_database = tmp_path / "information.sqlite3"
        try:
            os.link(battle_database, service_database)
        except (OSError, NotImplementedError):
            pytest.skip("hard links are unavailable on this filesystem")

    wiring.battle_database = battle_database
    args = _live_args(tmp_path)
    args.database = service_database
    with pytest.raises(ValueError, match="must be different files"):
        _build_runtime(args)

    assert wiring.ingestors == []
    assert wiring.managers == []
    assert wiring.services == []
    assert wiring.journals and wiring.journals[0].closed is True
    assert wiring.events.count("journal.close") == 1


def test_same_database_remains_allowed_without_ingest_flag(tmp_path, wiring):
    database = tmp_path / "same.sqlite3"
    wiring.battle_database = database
    args = _args(
        tmp_path,
        database=database,
        battle_stream=tmp_path / "battle-stream.json",
    )
    service, journal = _build_runtime(args)
    try:
        assert journal is None
        assert wiring.ingestors == []
        assert wiring.managers == []
        assert service.database == database
    finally:
        service.close()
