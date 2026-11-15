"""Validate a recorded HRE snapshot produced by the pinned Jomini runner."""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import re

from .saved_province_interests import (
    JOMINI_COMMIT,
    TAG,
    SavedProvinceInterestsSnapshot,
    _tag_list,
)


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MANIFEST = ROOT / "tools/rust/eu4-save-empire/adapter-manifest.json"
EMPIRE_SCHEMA = "eu4.save_empire_snapshot.v1"
_REFORM_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_IMPLEMENTED_FIELDS = frozenset({"emperor", "electors", "reforms"})
_MAX_REFORMS = 4096


class SavedEmpireSnapshot(SavedProvinceInterestsSnapshot):
    """Own an immutable saved HRE record without fabricating province rows.

    The inherited constructor and trust-checked parser runner are reused. Only
    the default manifest and document-specific loader/context metadata differ.
    """

    def __init__(self, path, observer, *, parser=None, parser_manifest=None):
        manifest = DEFAULT_MANIFEST if parser_manifest is None else parser_manifest
        super().__init__(path, observer, parser=parser, parser_manifest=manifest)

    def _load(self, document):
        if not isinstance(document, dict) or document.get("schema") != EMPIRE_SCHEMA:
            raise ValueError("SAVED_EMPIRE_DOCUMENT_SCHEMA")

        date = document.get("saved_date")
        if not isinstance(date, str) or re.fullmatch(r"[0-9]{1,4}\.[0-9]{1,2}\.[0-9]{1,2}", date) is None:
            raise ValueError("SAVED_EMPIRE_DATE_INVALID")
        year, month, day = map(int, date.split("."))
        month_days = (29 if year % 4 == 0 else 28) if month == 2 else 30 if month in (4, 6, 9, 11) else 31
        if not 1 <= year <= 9999 or not 1 <= month <= 12 or not 1 <= day <= month_days:
            raise ValueError("SAVED_EMPIRE_DATE_INVALID")

        version = document.get("saved_version")
        if (not isinstance(version, dict)
                or any(type(version.get(key)) is not int or not 0 <= version[key] <= 65535
                       for key in ("first", "second", "third", "fourth"))):
            raise ValueError("SAVED_EMPIRE_VERSION_INVALID")
        self.version = ".".join(str(version[key]) for key in ("first", "second", "third"))
        if self.version != "1.37.4":
            raise ValueError("SAVED_EMPIRE_VERSION_UNSUPPORTED")

        player = document.get("saved_player")
        if not isinstance(player, str) or TAG.fullmatch(player) is None:
            raise ValueError("SAVED_EMPIRE_PLAYER_INVALID")
        try:
            self._countries = frozenset(_tag_list(document.get("country_tags")))
        except ValueError as exc:
            raise ValueError("SAVED_EMPIRE_COUNTRY_TAGS_INVALID") from exc
        if self.observer not in self._countries:
            raise ValueError("SAVED_EMPIRE_OBSERVER_ABSENT")

        if "empire" not in document or document["empire"] is None:
            self._empire_present = False
            self._empire_fields = {}
        elif isinstance(document["empire"], dict):
            self._empire_present = True
            # Store only the three contracted values. Unknown parser fields do
            # not escape through a query or context response.
            empire = document["empire"]
            source_keys = {"emperor": "emperor", "electors": "electors",
                           "reforms": "passed_reforms"}
            self._empire_fields = {
                field: deepcopy(empire[source_key])
                for field, source_key in source_keys.items() if source_key in empire
            }
        else:
            raise ValueError("SAVED_EMPIRE_RECORD_INVALID")
        self.date, self.player = date, player

    def context(self):
        result = super().context()
        result["parser"]["snapshot_schema"] = EMPIRE_SCHEMA
        return result

    def lookup(self, obj, field):
        self._assert_current()
        if field not in _IMPLEMENTED_FIELDS:
            return {"status": "unsupported", "reason": "SAVED_EMPIRE_FIELD_NOT_IMPLEMENTED"}

        common = {
            "scale": 1,
            "period": "saved_snapshot",
            "complete": False,
            "basis": "saved_global_empire_record",
            "runtime_effect_evaluated": False,
            "current_ui_visibility_verified": False,
        }
        if obj.get("type") == "country" and obj.get("country") not in self._countries:
            return {**common, "status": "unknown", "reason": "COUNTRY_NOT_IN_SNAPSHOT"}
        if not self._empire_present:
            return {**common, "status": "unknown", "reason": "EMPIRE_RECORD_ABSENT"}
        if field not in self._empire_fields or self._empire_fields[field] is None:
            return {**common, "status": "unknown", "reason": "EMPIRE_FIELD_NOT_CAPTURED"}

        value = self._empire_fields[field]
        if field == "emperor":
            if not isinstance(value, str) or TAG.fullmatch(value) is None:
                return {**common, "status": "unknown", "reason": "EMPEROR_TAG_INVALID"}
            if value not in self._countries:
                return {**common, "status": "unknown", "reason": "EMPEROR_NOT_IN_SNAPSHOT_COUNTRIES"}
            return {**common, "status": "known", "value": value, "unit": "country_tag"}

        if field == "electors":
            try:
                tags = _tag_list(value)
            except ValueError:
                return {**common, "status": "unknown", "reason": "ELECTOR_TAG_LIST_INVALID"}
            if any(tag not in self._countries for tag in tags):
                return {**common, "status": "unknown", "reason": "ELECTOR_NOT_IN_SNAPSHOT_COUNTRIES"}
            return {**common, "status": "known", "value": tags, "unit": "country_tag"}

        if not isinstance(value, list) or len(value) > _MAX_REFORMS:
            return {**common, "status": "unknown", "reason": "PASSED_REFORMS_INVALID"}
        if (any(not isinstance(reform, str) or _REFORM_ID.fullmatch(reform) is None
                for reform in value)):
            return {**common, "status": "unknown", "reason": "REFORM_ID_INVALID"}
        if len(value) != len(set(value)):
            return {**common, "status": "unknown", "reason": "REFORM_ID_DUPLICATE"}
        return {**common, "status": "known", "value": list(value), "unit": "reform_id"}


__all__ = ["DEFAULT_MANIFEST", "EMPIRE_SCHEMA", "JOMINI_COMMIT", "SavedEmpireSnapshot"]
