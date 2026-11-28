"""Explicit country binding for historical FRA-only diplomacy fixtures.

This adapter is limited to tests of the old fixed-country samples. Tests for
country selection, read-only sessions, and authorization use the production
classes directly.
"""
import re

from bridge.diplomacy import DiplomacyTools, ObserverSession


class FixedFranceObserverSession(ObserverSession):
    def __init__(self, installation, game_exe):
        super().__init__(installation, game_exe, controlled_country="FRA")


class FixedFranceDiplomacyTools(DiplomacyTools):
    def __init__(self, journal, session=None):
        super().__init__(journal, session)
        selected = getattr(session, "controlled_country", None)
        if not isinstance(selected, str) or re.fullmatch(r"[A-Z0-9]{3}", selected) is None:
            self.controlled_country = "FRA"
            if isinstance(session, ObserverSession):
                session.controlled_country = "FRA"
