"""Trusted per-connection country authority for diplomatic decisions."""
from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any


class DiplomacyPermissionError(ValueError):
    """A request exceeds the country assigned by the service operator."""


@dataclass(frozen=True)
class DiplomacyControl:
    principal: str
    controlled_country: str | None

    def __post_init__(self):
        if not isinstance(self.principal, str) or not re.fullmatch(
                r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", self.principal):
            raise ValueError("INVALID_CONTROL_PRINCIPAL")
        if self.controlled_country is not None and (
                not isinstance(self.controlled_country, str)
                or not re.fullmatch(r"[A-Z0-9]{3}", self.controlled_country)):
            raise ValueError("INVALID_CONTROLLED_COUNTRY")

    @staticmethod
    def decision_country(actor: str, recipient: str, phase: str) -> str:
        return recipient if phase in ("accept", "reject") else actor

    def authorize(self, action_id: str, actor: str, recipient: str,
                  phase: str = "initiate") -> str:
        country = self.decision_country(actor, recipient, phase)
        if self.controlled_country is None or country != self.controlled_country:
            raise DiplomacyPermissionError("DIPLOMACY_COUNTRY_NOT_AUTHORIZED")
        return country

    def authorize_listing(self, actor: str | None, recipient: str | None) -> str | None:
        if self.controlled_country is None:
            return actor
        if actor is None and recipient is None:
            return self.controlled_country
        if self.controlled_country not in (actor, recipient):
            raise DiplomacyPermissionError("DIPLOMACY_COUNTRY_NOT_AUTHORIZED")
        return actor

    def authorize_record(self, record: Any) -> None:
        payload = record.payload
        self.authorize(payload["action_id"], payload["actor"], payload["recipient"],
                       payload.get("phase", "initiate"))
        principal = getattr(record, "principal", None)
        if principal is not None and principal != self.principal:
            raise DiplomacyPermissionError("DIPLOMACY_REQUEST_NOT_OWNED")
        country = getattr(record, "decision_country", None)
        if country is not None and country != self.controlled_country:
            raise DiplomacyPermissionError("DIPLOMACY_REQUEST_COUNTRY_MISMATCH")
