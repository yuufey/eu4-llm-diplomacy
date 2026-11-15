"""Add saved HRE status values without changing the v1 empire snapshot."""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import re

from .saved_empire import EMPIRE_SCHEMA, SavedEmpireSnapshot


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MANIFEST = ROOT / "tools/rust/eu4-save-empire-v2/adapter-manifest.json"
V1_SCHEMA = EMPIRE_SCHEMA
V2_SCHEMA = "eu4.save_empire_snapshot.v2"

GLOBAL_STATUS_FIELDS = (
    "imperial_influence",
    "imperial_ban_allowed",
    "internal_hre_cb",
    "hre_inheritable",
    "allows_female_emperor",
    "emperor_has_revoked",
    "imperial_realm_war",
)
_BOOLEAN_FIELDS = frozenset(GLOBAL_STATUS_FIELDS) - {"imperial_influence"}
_DECIMAL = re.compile(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?\Z")


class SavedEmpireSnapshotV2(SavedEmpireSnapshot):
    """Accept v1/v2 payloads and derive only the newly captured S01 status."""

    def __init__(self, path, observer, *, parser=None, parser_manifest=None):
        manifest = DEFAULT_MANIFEST if parser_manifest is None else parser_manifest
        super().__init__(path, observer, parser=parser, parser_manifest=manifest)

    @staticmethod
    def _unknown(reason):
        return {"status": "unknown", "reason": reason, "period": "saved_snapshot",
                "complete": False, "basis": "saved_empire_status_v2"}

    def _load(self, document):
        if (not isinstance(document, dict)
                or document.get("schema") not in (V1_SCHEMA, V2_SCHEMA)):
            raise ValueError("SAVED_EMPIRE_DOCUMENT_SCHEMA")
        self._snapshot_schema = document["schema"]
        normalized = dict(document)
        # The v1 loader owns validation for the shared header and original
        # emperor/elector/reform fields. Only the schema label is normalized.
        normalized["schema"] = V1_SCHEMA
        super()._load(normalized)

        if self._snapshot_schema == V1_SCHEMA:
            self._global_status = {
                field: self._unknown("LEGACY_SNAPSHOT_EMPIRE_STATUS_NOT_CAPTURED")
                for field in GLOBAL_STATUS_FIELDS
            }
            return

        if not self._empire_present:
            reason = "EMPIRE_RECORD_ABSENT"
            self._global_status = {field: self._unknown(reason) for field in GLOBAL_STATUS_FIELDS}
            return

        empire = document.get("empire")
        self._global_status = {}
        for field in GLOBAL_STATUS_FIELDS:
            if not isinstance(empire, dict) or field not in empire or empire[field] is None:
                self._global_status[field] = self._unknown("EMPIRE_STATUS_FIELD_NOT_CAPTURED")
            elif field == "imperial_influence":
                value = empire[field]
                if (not isinstance(value, str) or len(value) > 64
                        or _DECIMAL.fullmatch(value) is None
                        or (value.startswith("-") and set(value[1:].replace(".", "")) == {"0"})):
                    self._global_status[field] = self._unknown("IMPERIAL_INFLUENCE_INVALID")
                else:
                    self._global_status[field] = {
                        "status": "known", "value": value,
                        "unit": "saved_imperial_influence",
                        "representation": "decimal_string",
                        "period": "saved_snapshot", "complete": False,
                        "basis": "saved_empire_status_v2.imperial_influence",
                    }
            elif field in _BOOLEAN_FIELDS:
                value = empire[field]
                if type(value) is not bool:
                    self._global_status[field] = self._unknown("EMPIRE_STATUS_BOOLEAN_INVALID")
                else:
                    self._global_status[field] = {
                        "status": "known", "value": value, "unit": "boolean",
                        "period": "saved_snapshot", "complete": False,
                        "basis": f"saved_empire_status_v2.{field}",
                    }
            else:  # Defensive if the allowlist is expanded without a validator.
                self._global_status[field] = self._unknown("EMPIRE_STATUS_FIELD_UNIMPLEMENTED")

    def context(self):
        result = super().context()
        result["parser"]["snapshot_schema"] = self._snapshot_schema
        return result

    @staticmethod
    def _role_known(value, basis):
        return {"status": "known", "value": value, "unit": "boolean",
                "period": "saved_snapshot", "complete": False, "basis": basis}

    @staticmethod
    def _role_unknown(reason, basis):
        return {"status": "unknown", "reason": reason, "unit": "boolean",
                "period": "saved_snapshot", "complete": False, "basis": basis}

    @staticmethod
    def _role_not_applicable():
        return {"status": "not_applicable", "reason": "COUNTRY_OBJECT_REQUIRED",
                "unit": "boolean", "period": "saved_snapshot", "complete": False,
                "basis": "saved_empire_status_country_role"}

    @staticmethod
    def _evidence_summary(global_state, country_roles):
        def summary(item):
            return {key: item[key] for key in ("status", "reason") if key in item}
        return {"global_state": {key: summary(value) for key, value in global_state.items()},
                "country_roles": {key: summary(value) for key, value in country_roles.items()},
                "complete": False, "current_state_observed": False}

    def lookup_empire_status(self, obj):
        self._assert_current()
        global_state = deepcopy(self._global_status)
        if obj.get("type") == "session":
            roles = {name: self._role_not_applicable() for name in (
                "is_emperor", "is_elector", "member_of_empire")}
        elif obj.get("type") == "country" and obj.get("country") not in self._countries:
            roles = {name: self._role_unknown("COUNTRY_NOT_IN_SNAPSHOT", name) for name in (
                "is_emperor", "is_elector", "member_of_empire")}
        elif obj.get("type") == "country":
            country = obj["country"]
            emperor = super().lookup(obj, "emperor")
            electors = super().lookup(obj, "electors")
            if emperor.get("status") == "known" and isinstance(emperor.get("value"), str):
                is_emperor = self._role_known(emperor["value"] == country,
                                              "saved_v1_emperor_tag_equality")
            else:
                is_emperor = self._role_unknown(
                    emperor.get("reason", "EMPEROR_NOT_KNOWN"), "saved_v1_emperor_tag_equality")
            if electors.get("status") == "known" and isinstance(electors.get("value"), list):
                is_elector = self._role_known(country in electors["value"],
                                              "saved_v1_elector_list_membership")
            else:
                is_elector = self._role_unknown(
                    electors.get("reason", "ELECTORS_NOT_KNOWN"), "saved_v1_elector_list_membership")
            roles = {
                "is_emperor": is_emperor,
                "is_elector": is_elector,
                "member_of_empire": self._role_unknown(
                    "MEMBERSHIP_NOT_CAPTURED", "saved_empire_membership_not_captured"),
            }
        else:
            roles = {name: self._role_unknown("S01_OBJECT_INVALID", name) for name in (
                "is_emperor", "is_elector", "member_of_empire")}

        global_known = sum(item.get("status") == "known" for item in global_state.values())
        roles_known = sum(item.get("status") == "known" for item in roles.values())
        target_valid = not (obj.get("type") == "country" and obj.get("country") not in self._countries)
        field_known = target_valid and (global_known >= 1 or roles_known >= 2)
        if not field_known:
            reason = "COUNTRY_NOT_IN_SNAPSHOT" if not target_valid else "NO_EMPIRE_STATUS_COMPONENT_KNOWN"
            return {
                "status": "unknown",
                "reason": reason,
                "scale": 1,
                "period": "saved_snapshot",
                "complete": False,
                "basis": "saved_empire_status_and_country_roles",
                "runtime_effect_evaluated": False,
                "current_state_observed": False,
                "evidence": self._evidence_summary(global_state, roles),
            }
        return {
            "status": "known",
            "scale": 1,
            "period": "saved_snapshot",
            "complete": False,
            "basis": "saved_empire_status_and_country_roles",
            "runtime_effect_evaluated": False,
            "current_state_observed": False,
            "value": {
                "semantics": "saved_empire_status_and_country_roles",
                "global_state": global_state,
                "country_roles": roles,
                "complete": False,
                "current_state_observed": False,
            },
        }


__all__ = ["DEFAULT_MANIFEST", "GLOBAL_STATUS_FIELDS", "SavedEmpireSnapshotV2", "V1_SCHEMA", "V2_SCHEMA"]
