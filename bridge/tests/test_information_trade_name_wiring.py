"""Runtime wiring boundaries for consumers of the shared literal-name reader."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from tools.serve_information import _build_runtime


class _Service:
    def __init__(self, source, database, owner="llm", **_kwargs):
        self.source = source
        self.database = database
        self.owner = owner

    def close(self):
        return None

    def previous_war_forces(self, *_args, **_kwargs):
        raise AssertionError("factory wiring must not collect war-force history")

    def observed_events(self, *_args, **_kwargs):
        raise AssertionError("factory wiring must not collect event history")

    def action_cooldown_expiries(self, *_args, **_kwargs):
        raise AssertionError("factory wiring must not collect cooldown history")


class _Journal:
    def __init__(self, *args, **kwargs):
        self.args = args
        self.kwargs = kwargs

    def close(self):
        return None


class _Session:
    experiment_id = "trade-name-experiment"
    session_id = "trade-name-session"

    def __init__(self, path, executable):
        self.path = Path(path)
        self.executable = Path(executable)


class _DiplomacyTools:
    def __init__(self, journal, session):
        self.journal = journal
        self.session = session

    def inspect_diplomatic_action(self, *_args, **_kwargs):
        raise AssertionError("wiring tests must not inspect a game action")


class _Composite:
    def __init__(self, primary, adapters=()):
        self.primary = primary
        self.adapters = tuple(adapters)


class _StaticTrade:
    instances = []

    @staticmethod
    def _configured_path(kind):
        """Keep scope-index setup unconfigured in these wiring-only tests."""
        assert kind in {"game_root", "user_data"}
        return None

    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.game_root = kwargs["game_root"]
        self.user_data = kwargs["user_data"]
        self.enabled_mods = None
        type(self).instances.append(self)

    def catalog(self):
        return []

    def context(self):
        return self.kwargs["context_provider"]()

    def read(self, *_args, **_kwargs):
        raise AssertionError("wiring tests must not read static game data")


class _StaticStraits:
    """Keep trade wiring tests independent of the real map-file index."""

    instances = []

    def __init__(self, **kwargs):
        self.kwargs = kwargs
        type(self).instances.append(self)

    def catalog(self):
        return []


class _EstuaryDefinition:
    def __init__(self, *args, **kwargs):
        pass

    def context(self):
        raise AssertionError("wiring tests must not read estuary definitions")


class _Localization:
    instances = []

    def __init__(self, base_source, capture=None):
        self.base_source = base_source
        self.capture = capture
        type(self).instances.append(self)

    def read(self, *_args, **_kwargs):
        raise AssertionError("wiring tests must not read the live localization cache")


class _NativeMission:
    instances = []

    def __init__(self, base_source, capture=None, **kwargs):
        self.base_source = base_source
        self.capture = capture
        self.kwargs = kwargs
        type(self).instances.append(self)

    def read(self, *_args, **_kwargs):
        raise AssertionError("wiring tests must not read live mission state")


class _MissionDefinitions:
    def __init__(self, **kwargs):
        self.kwargs = kwargs


class _MissionInformation:
    instances = []

    def __init__(self, source, definitions, reader, **kwargs):
        self.source = source
        self.definitions = definitions
        self.reader = reader
        self.kwargs = kwargs
        type(self).instances.append(self)

    def catalog(self):
        return []


class _SavedSnapshot:
    def __init__(self, path, observer):
        self.path = Path(path)
        self.observer = observer


class _SavedSource:
    def __init__(self, snapshot):
        self.snapshot = snapshot
        self.capture = self._reject_capture

    def context(self):
        return {"status": "ready", "mode": "recorded", "context_scope": "saved"}

    def _reject_capture(self, *_args, **_kwargs):
        raise AssertionError("saved wiring tests must not capture game state")


def _args(tmp_path, **overrides):
    values = dict(
        recorded_manifest=None,
        operator_session=None,
        observer=None,
        static_game_data=False,
        mission_game_data=False,
        static_game_root=None,
        static_user_data=None,
        mission_save=None,
        journal=None,
        database=tmp_path / "information.sqlite3",
        owner="trade-name-wiring",
    )
    values.update(overrides)
    return SimpleNamespace(**values)


@pytest.fixture
def wiring_modules(monkeypatch):
    """Replace lifecycle constructors while preserving _build_runtime logic."""
    import bridge.information.composite as composite
    import bridge.information.mission_definitions as mission_definitions
    import bridge.information.missions as missions
    import bridge.information.native_localization as native_localization
    import bridge.information.province_estuary_definitions as province_estuary_definitions
    import bridge.information.saved_missions as saved_missions
    import bridge.information.service as service
    import bridge.information.sources as sources
    import bridge.information.static_data as static_data
    import bridge.information.straits as straits

    _StaticTrade.instances.clear()
    _StaticStraits.instances.clear()
    _Localization.instances.clear()
    _NativeMission.instances.clear()
    _MissionInformation.instances.clear()
    monkeypatch.setattr(service, "InformationService", _Service)
    monkeypatch.setattr(composite, "CompositeSource", _Composite)
    monkeypatch.setattr(static_data, "StaticTradeSource", _StaticTrade)
    monkeypatch.setattr(straits, "StaticStraitsSource", _StaticStraits)
    monkeypatch.setattr(province_estuary_definitions, "BoundEstuaryDefinition", _EstuaryDefinition)
    monkeypatch.setattr(native_localization, "NativeLocalizationReader", _Localization)
    monkeypatch.setattr(missions, "NativeMissionReader", _NativeMission)
    monkeypatch.setattr(missions, "MissionInformationSource", _MissionInformation)
    monkeypatch.setattr(mission_definitions, "MissionDefinitionIndex", _MissionDefinitions)
    monkeypatch.setattr(missions, "SavedMissionContextSource", _SavedSource)
    monkeypatch.setattr(saved_missions, "SavedMissionSnapshot", _SavedSnapshot)
    monkeypatch.setattr(
        sources,
        "RecordedSource",
        lambda path: SimpleNamespace(
            path=Path(path),
            context=lambda: {"status": "ready", "mode": "recorded", "context_scope": "recorded"},
        ),
    )

    import bridge.diplomacy as diplomacy
    import bridge.diplomacy_journal as diplomacy_journal
    import work.local_config as local_config
    monkeypatch.setattr(diplomacy, "ObserverSession", _Session)
    monkeypatch.setattr(diplomacy, "DiplomacyTools", _DiplomacyTools)
    monkeypatch.setattr(diplomacy_journal, "DurableJournal", _Journal)
    monkeypatch.setattr(local_config, "game_exe", lambda: Path("fake-game.exe"))
    return {
        "static": _StaticTrade,
        "straits": _StaticStraits,
        "localization": _Localization,
        "mission": _NativeMission,
        "mission_information": _MissionInformation,
    }


def test_static_only_live_runtime_injects_reader_without_constructing_mission_reader(
    tmp_path, monkeypatch, wiring_modules
):
    """Static-only live construction proves capability without mission capture."""
    called = []
    mission_capture_calls = []
    import bridge.information.mission_memory as mission_memory
    monkeypatch.setattr(
        mission_memory,
        "capture",
        lambda *args, **kwargs: mission_capture_calls.append((args, kwargs)),
    )
    monkeypatch.setattr(
        wiring_modules["mission"],
        "__init__",
        lambda self, *args, **kwargs: called.append((args, kwargs))
        or (_ for _ in ()).throw(AssertionError("mission reader must not be constructed")),
    )
    args = _args(
        tmp_path,
        operator_session=tmp_path / "installation.json",
        observer="FRA",
        static_game_data=True,
    )
    service, journal = _build_runtime(args)
    try:
        assert journal is not None
        assert len(wiring_modules["localization"].instances) == 1
        assert len(wiring_modules["static"].instances) == 1
        assert wiring_modules["static"].instances[0].kwargs["localization_reader"] is wiring_modules["localization"].instances[0]
        assert called == []
        assert mission_capture_calls == []
        assert wiring_modules["static"].instances[0] in service.source.adapters
    finally:
        service.close()
        journal.close()


def test_live_static_and_mission_adapters_share_one_neutral_reader(tmp_path, wiring_modules):
    from bridge.information.mission_read_scope import MissionScopedReader, capture_rule_inputs

    args = _args(
        tmp_path,
        operator_session=tmp_path / "installation.json",
        observer="FRA",
        static_game_data=True,
        mission_game_data=True,
    )
    service, journal = _build_runtime(args)
    try:
        assert len(wiring_modules["localization"].instances) == 1
        neutral = wiring_modules["localization"].instances[0]
        assert wiring_modules["static"].instances[0].kwargs["localization_reader"] is neutral
        state_reader, rule_reader = wiring_modules["mission"].instances
        assert state_reader.kwargs["localization_reader"] is neutral
        assert rule_reader.kwargs["localization_reader"] is neutral
        assert state_reader.capture is None
        assert rule_reader.capture is capture_rule_inputs
        reader = wiring_modules["mission_information"].instances[0].reader
        assert isinstance(reader, MissionScopedReader)
        assert reader.original is state_reader
        assert reader.rule_reader is rule_reader
        assert service.source.reader is reader
    finally:
        service.close()
        journal.close()


def test_live_country_records_receive_neutral_reader_without_static_or_mission_flags(tmp_path, wiring_modules):
    from bridge.information.country_records import NativeCountryRecordsSource
    from bridge.information.relation_state import NativeRelationSource

    args = _args(tmp_path, operator_session=tmp_path / "installation.json", observer="FRA")
    service, journal = _build_runtime(args)
    try:
        assert len(wiring_modules["localization"].instances) == 1
        records = next(a for a in service.source.adapters if isinstance(a, NativeCountryRecordsSource))
        assert records.localization_reader is wiring_modules["localization"].instances[0]
        assert any(isinstance(a, NativeRelationSource) for a in service.source.adapters)
        assert wiring_modules["static"].instances == []
        assert wiring_modules["mission"].instances == []
    finally:
        service.close()
        journal.close()


@pytest.mark.parametrize(
    "source_args",
    [
        {"recorded_manifest": "recorded.json", "static_game_data": True},
        {"static_game_data": True},
    ],
)
def test_recorded_or_unbound_static_runtime_never_injects_live_cache_reader(
    tmp_path, source_args, wiring_modules
):
    args = _args(tmp_path, **{
        key: tmp_path / value if key == "recorded_manifest" else value
        for key, value in source_args.items()
    })
    service, journal = _build_runtime(args)
    try:
        assert wiring_modules["localization"].instances == []
        assert wiring_modules["static"].instances[0].kwargs["localization_reader"] is None
        assert journal is None
    finally:
        service.close()


def test_saved_mission_runtime_uses_saved_capture_and_no_live_cache_reader(
    tmp_path, wiring_modules
):
    from bridge.information.mission_read_scope import MissionScopedReader

    args = _args(
        tmp_path,
        mission_save=tmp_path / "save.eu4",
        observer="FRA",
        static_game_data=True,
        mission_game_data=True,
    )
    service, journal = _build_runtime(args)
    try:
        assert journal is None
        assert wiring_modules["localization"].instances == []
        assert wiring_modules["static"].instances[0].kwargs["localization_reader"] is None
        assert wiring_modules["mission"].instances == []
        reader = service.source.reader
        assert isinstance(reader, MissionScopedReader)
        assert reader.original is service.source.primary.capture
        assert reader.rule_reader is reader.original
        assert wiring_modules["mission_information"].instances[0].reader is reader
    finally:
        service.close()


def test_unbound_mission_runtime_does_not_inject_live_cache_reader(tmp_path, wiring_modules):
    from bridge.information.mission_read_scope import MissionScopedReader, capture_rule_inputs

    args = _args(tmp_path, mission_game_data=True, observer="FRA")
    service, journal = _build_runtime(args)
    try:
        assert journal is None
        assert wiring_modules["localization"].instances == []
        assert len(wiring_modules["mission"].instances) == 2
        state_reader, rule_reader = wiring_modules["mission"].instances
        assert state_reader.capture is None
        assert rule_reader.capture is capture_rule_inputs
        assert state_reader.base_source is rule_reader.base_source
        assert state_reader.kwargs["localization_reader"] is None
        assert rule_reader.kwargs["localization_reader"] is None
        reader = service.source.reader
        assert isinstance(reader, MissionScopedReader)
        assert reader.original is state_reader
        assert reader.rule_reader is rule_reader
        assert wiring_modules["mission_information"].instances[0].reader is reader
    finally:
        service.close()
