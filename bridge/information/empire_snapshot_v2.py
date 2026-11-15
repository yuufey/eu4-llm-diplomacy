"""Read-only S01 adapter for the v2 saved empire snapshot."""
from __future__ import annotations

from copy import deepcopy

from .empire_snapshot import SavedEmpireSource
from .sources import _result


_EMPIRE_STATUS_FIELD = "empire_status"
_OLD_SUPPORTED_FIELDS = frozenset({"emperor", "electors", "reforms"})


class SavedEmpireSourceV2(SavedEmpireSource):
    """Extend the saved S01 projection while preserving its v1 fields."""

    def catalog(self):
        topics = super().catalog()
        s01 = next(topic for topic in topics if topic["topic_id"] == "S01")
        s01["source"] = type(self).__name__
        status = s01["fields"][_EMPIRE_STATUS_FIELD]
        status.update({
            "source": type(self).__name__,
            "coverage": "partial",
            "complete": False,
            "period": "saved_snapshot",
            "scale": 1,
            "value_origin": "jomini_eu4save_empire_snapshot_v2",
            "basis": "saved_empire_status_and_country_roles",
            "unit": "saved_empire_status_and_country_roles",
            "supported_object_types": ["country", "session"],
            "description": (
                "保存快照中的神圣罗马帝国影响力、机制标志及有限国家身份；"
                "不表示当前状态、帝国成员全集或游戏中的实际效果。"
            ),
            "gaps": [
                "HISTORICAL_SNAPSHOT_NOT_LIVE",
                "EMPIRE_MEMBERSHIP_NOT_CAPTURED",
                "CURRENT_RUNTIME_EFFECTS_NOT_VERIFIED",
            ],
            "detail_fields": [
                "imperial_influence", "imperial_ban_allowed", "internal_hre_cb",
                "hre_inheritable", "allows_female_emperor", "emperor_has_revoked",
                "imperial_realm_war", "is_emperor", "is_elector", "member_of_empire",
            ],
        })
        return topics

    def read(self, query, context=None):
        normalized = self.validate_query(query, context)
        before = self.context()
        parent_result = super().read(query, context)
        if normalized["topic"] != "S01" or _EMPIRE_STATUS_FIELD not in normalized["fields"]:
            return parent_result

        fields = deepcopy(parent_result["fields"])
        parent_source = parent_result.get("source", {})
        parent_provenance = parent_source.get("provenance", {})
        parent_context_matches = (
            parent_result.get("game_date") == before.get("game_date")
            and parent_source.get("mode") == before.get("mode")
            and parent_source.get("session_id") == before.get("session_id")
            and parent_source.get("observer") == before.get("observer")
            and parent_source.get("status") == ("observed" if before.get("status") == "ready" else "unavailable")
            and parent_provenance.get("archive") == before.get("archive")
            and parent_provenance.get("parser") == before.get("parser")
        )
        supported_fields = set(normalized["fields"]) & (_OLD_SUPPORTED_FIELDS | {_EMPIRE_STATUS_FIELD})
        if context is not None and context != before:
            projected = {"status": "unavailable", "reason": "SAVED_EMPIRE_CONTEXT_MISMATCH"}
        elif before.get("status") != "ready" or not parent_context_matches:
            reason = ("SAVED_EMPIRE_SOURCE_UNREADY" if before.get("status") != "ready"
                      else "SAVED_EMPIRE_INPUT_OR_PARSER_CHANGED")
            projected = {"status": "unavailable", "reason": reason}
        else:
            try:
                projected = self.snapshot.lookup_empire_status(normalized["object"])
            except (OSError, ValueError):
                projected = {"status": "unavailable", "reason": "SAVED_EMPIRE_INPUT_CHANGED"}
        fields[_EMPIRE_STATUS_FIELD] = projected

        after = self.context()
        withdrawal_reason = None
        if context is not None and context != before:
            withdrawal_reason = "SAVED_EMPIRE_CONTEXT_MISMATCH"
        elif before.get("status") != "ready":
            withdrawal_reason = "SAVED_EMPIRE_SOURCE_UNREADY"
        elif not parent_context_matches or after != before:
            withdrawal_reason = "SAVED_EMPIRE_INPUT_OR_PARSER_CHANGED"
        if withdrawal_reason is not None:
            for name in supported_fields:
                fields[name] = {"status": "unavailable", "reason": withdrawal_reason}
        source = deepcopy(parent_result["source"])
        source["name"] = type(self).__name__
        source["complete"] = False
        return _result(normalized, before, fields, False, source)


__all__ = ["SavedEmpireSourceV2"]
