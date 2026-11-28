"""Partial battle reports from the durable local v2/v3/v4 capture stream.

Only direct participation admits a record. War membership and the fact that
the global callback ran do not establish an observer's knowledge. No native
call or game-state mutation is performed by the record adapter. An explicitly
configured capture manager may enable/disable the installed producer for live
event subscriptions; queries alone never acquire it. Observation event IDs
identify captured records, not battles.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re
import sqlite3

from bridge.native_text import decode_native_text_hex
from .battle_native_text import (
    BattleNativeTextError,
    project_native_text,
    project_raw_text,
)
from .battle_display_context import project_display_context
from .battle_body_candidate import project_body_candidate
from .battle_name_sources import project_name_sources, project_name_candidate
from .battle_outcome_text import project_outcome_text_sources
from .battle_outcome_composition import project_outcome_text_composition
from .battle_outcome_tail import project_outcome_tail_sources
from .battle_independent_line import project_independent_line
from .battle_flag_inputs import project_flag_inputs
from .battle_compact_loss_candidates import project_compact_loss_candidates
from .battle_display_composition import project_display_composition, project_readable_text
from .battle_retreat import project_retreat
from .battle_display_sides import COMBAT_ROLES
try:
    # Each extension delegates older frames unchanged.
    from work.information_battle_flag_inputs_wire import (  # type: ignore
        decode,
        OutcomeTailWireError,
        OutcomeTextWireError,
        NameSourcesWireError,
        RetreatWireError,
        EndStateWireError,
        NameHandoffWireError,
        DisplayContextWireError,
        MAX_WIRE_BYTES,
    )
    from work.information_battle_native_text_wire import NativeTextWireError
    from work.information_battle_war_identity_wire import WarIdentityWireError
    from work.information_battle_template_wire import TemplateWireError
except ImportError:  # the v5 helper is optional while old fixtures are used
    from work.information_battle_war_identity_wire import (
        decode, WarIdentityWireError, MAX_WIRE_BYTES,
    )
    from work.information_battle_template_wire import TemplateWireError

    NativeTextWireError = TemplateWireError
    DisplayContextWireError = TemplateWireError
    NameHandoffWireError = TemplateWireError
    EndStateWireError = TemplateWireError
    RetreatWireError = TemplateWireError
    NameSourcesWireError = TemplateWireError
    OutcomeTextWireError = TemplateWireError
    OutcomeTailWireError = TemplateWireError
from .catalog import get_topic, _validate_schema, validate_query as validate_catalog_query
from .composite import CompositeSource
from .battle_effects import project_effects
from .battle_text import project_template
from .battle_display import project_display
from .battle_values import FIELDS as FORCE_FIELDS, project_forces, project_outcome
from .event_replay import unknown_event_projection
from .model import InformationError, canonical, identifier


GAME_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
EVENT_TYPE = "battle_observation"
PAGE_SIZE = 64
MAX_PAYLOAD = MAX_WIRE_BYTES
MAX_HISTORY_PAGE = 256
_HISTORY_FIELDS = {"H01": "battle_sequence", "W03": "battle_losses"}
_B01_DISCOVERY_GUIDANCE = {
    "requires": "parameters.event_id",
    "single_record": True,
    "message": "B01 按 event_id 读取单场战斗。先从 H01.battle_sequence 或 W03.battle_losses 的 event_refs 取得 event_id。",
    "discovery_queries": [
        {"topic": "H01", "field": "battle_sequence",
         "purpose": "按观察国或会话发现已保留的战斗 event_id"},
        {"topic": "W03", "field": "battle_losses",
         "purpose": "按战争分页发现已保留的战斗 event_id"},
    ],
}
_HISTORY_PAGE_GAPS = [
    "ONLY_DIRECT_PARTICIPATION_SUPPORTED",
    "WAR_AND_BATTLE_IDENTITIES_UNRESOLVED",
    "LEGACY_NAVAL_LOSS_OPERANDS_AND_AGGREGATE_LOSS_UNRESOLVED",
]
_HEX16 = re.compile(r"[0-9a-f]{16}\Z")
_FIELDS = {
    "B01": ("event_id", "battle_type", "name", "location", "end_date", "sides", "commanders", "war_id", "winner"),
    "B02": FORCE_FIELDS,
    "B03": ("ships_captured", "war_score", "prestige", "army_tradition", "naval_tradition", "war_exhaustion", "annihilation", "retreat"),
    "B04": ("raw_text", "details", "record_order", "deduplication", "completeness", "gaps"),
}
_GAPS = [
    "ONLY_DIRECT_PARTICIPATION_SUPPORTED",
    "OTHER_KNOWN_BATTLES_VISIBILITY_UNRESOLVED",
    "CAPTURE_WINDOW_AND_SAME_DATE_RELOAD_COVERAGE_UNPROVEN",
    "WAR_AND_BATTLE_IDENTITIES_UNRESOLVED",
    "FULL_DISPLAY_UNRESOLVED",
    "LEGACY_NAVAL_LOSS_OPERANDS_NOT_CAPTURED",
    "LAND_POPUP_AND_AGGREGATE_LOSS_NOT_VERIFIED",
]
_WAR_ID_RE = re.compile(r"war_([0-9a-f]{16})_([0-9a-f]{8})\Z")
_WAR_ID_REASON_NAMES = {
    1: "WAR_ID_UNKNOWN_CALLER",
    2: "WAR_ID_CONTEXT_UNAVAILABLE",
    3: "WAR_ID_RESULT_PAIR_UNVERIFIED",
    4: "WAR_ID_ASSOCIATION_UNAVAILABLE",
    5: "WAR_ID_ASSOCIATION_CHANGED",
    6: "WAR_ID_REGISTRY_FULL",
}
_U64_MASK = (1 << 64) - 1


def _tag(full_ref):
    return int(full_ref).to_bytes(8, "little")[:3].decode("ascii")


def _known(value):
    return {"status": "known", "value": deepcopy(value)}


def _nonnegative_integer(value):
    """Accept the two identity encodings used by observer bindings."""
    if type(value) is int:
        return 0 <= value <= _U64_MASK
    if not isinstance(value, str):
        return False
    if re.fullmatch(r"[0-9]+", value) is not None:
        return len(value) <= 20 and int(value, 10) <= _U64_MASK
    return re.fullmatch(r"[0-9a-fA-F]{1,16}", value) is not None


def _identity_integer(value):
    if type(value) is int and value >= 0:
        return value
    if isinstance(value, str):
        # installation.json/binding.json use canonical decimal text, while
        # a few observer records use a 16-digit hexadecimal identity string.
        if re.fullmatch(r"[0-9]+", value):
            parsed = int(value, 10)
            return parsed if parsed <= _U64_MASK else None
        if re.fullmatch(r"[0-9a-fA-F]{1,16}", value):
            return int(value, 16)
    return None


def _splitmix64(value):
    """The u64 epoch used by the shared peace registry ID formatter."""
    value = (int(value) + 0x9E3779B97F4A7C15) & _U64_MASK
    value = ((value ^ (value >> 30)) * 0xBF58476D1CE4E5B9) & _U64_MASK
    value = ((value ^ (value >> 27)) * 0x94D049BB133111EB) & _U64_MASK
    return (value ^ (value >> 31)) & _U64_MASK


def _history_catalog_entry(topic_id: str) -> dict:
    """Return the narrow history projection advertised by this source.

    The global catalog still describes H01/W03.  This copy only adds the
    durable battle-stream field and its bounded paging parameters, so a
    caller can discover the projection without changing the global catalog.
    """

    if topic_id not in _HISTORY_FIELDS:
        raise InformationError("unknown_topic", topic_id)
    topic = get_topic(topic_id)
    field = _HISTORY_FIELDS[topic_id]
    topic["fields"][field] = {
        "description": "已持久化且在观察范围内的战斗事件引用；战损保留逐场原值与缺项，不是战争累计损失",
        "coverage": "partial",
        "paths": [f"payload.{field}"],
        "source": "BattleObservationAdapter",
        "complete": False,
        "history_scope": "retained_direct_participant_records",
    }
    if topic_id == "W03":
        topic["status"] = "available"
        topic["supported_versions"] = ["1.37.4"]
        topic["source"] = "BattleObservationAdapter"
        topic["triggers"] = ["query", "periodic", "change"]
        topic["observer_roles"] = ["country"]
        topic["change_detection"] = "sampled_retained_history_page_comparison"
        topic["scope_note"] = ("只查询指定分页内已保留的本国直接参战记录；不保证未来采集、"
                               "战争总战损或分页以外的变化通知。")
        topic["fields"][field].update(
            supported_object_types=["country", "session", "war"],
            unit="battle_loss_event_page", scale=1, period="captured_history",
            paths=["event_refs[].losses"],
            war_selection="object.war_id_only; actor/recipient selection unsupported",
            gaps=deepcopy(_HISTORY_PAGE_GAPS))
    properties = ({} if topic_id == "W03"
                  else dict(topic.get("parameters", {}).get("properties", {})))
    if topic_id == "W03":
        properties["event_type"] = {"type": "string", "const": EVENT_TYPE}
    properties.update({
        "after_event_id": {"type": "string", "pattern": r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$"},
        "limit": {"type": "integer", "minimum": 1, "maximum": MAX_HISTORY_PAGE},
    })
    topic["parameters"] = {
        "type": "object", "properties": properties, "additionalProperties": False,
    }
    return topic


class BattleObservationAdapter:
    """Read complete captured payloads, filtering before returning any fields.

    The binding is trusted operator configuration, separate from model query
    arguments. It never changes the primary context's observer or world.
    """

    def __init__(self, database, binding):
        required = {"session_id", "installation", "generation", "game_sha256",
                    "observer_ref", "mode"}
        optional = {"world_id", "process_creation_filetime", "creation_filetime"}
        if not isinstance(binding, dict) or set(binding) - (required | optional) or required - set(binding):
            raise InformationError("invalid_battle_binding", "Incomplete battle stream binding")
        identifier(binding["session_id"], "session_id")
        for field in ("installation", "generation", "observer_ref"):
            if not isinstance(binding[field], str) or not _HEX16.fullmatch(binding[field]) or int(binding[field], 16) == 0:
                raise InformationError("invalid_battle_binding", f"{field} must be nonzero lowercase hex16")
        if binding["game_sha256"] != GAME_SHA256 or binding["mode"] not in ("live", "recorded"):
            raise InformationError("invalid_battle_binding", "Unsupported game build or source mode")
        try:
            observer = _tag(int(binding["observer_ref"], 16))
        except (ValueError, UnicodeError):
            observer = ""
        if re.fullmatch(r"[A-Z0-9]{3}", observer) is None:
            raise InformationError("invalid_battle_binding", "observer_ref must contain a country tag")
        if "world_id" in binding:
            identifier(binding["world_id"], "world_id")
        for field in ("process_creation_filetime", "creation_filetime"):
            if field in binding and not _nonnegative_integer(binding[field]):
                raise InformationError("invalid_battle_binding", f"{field} must be a nonnegative integer")
        self.database = Path(database).resolve()
        self.binding = deepcopy(binding)
        self.observer = observer
        self.observer_ref = int(binding["observer_ref"], 16)
        self.prefix = f"battle-observation:{binding['installation']}:{binding['generation']}:"
        self.binding_id = hashlib.sha256(canonical(binding).encode()).hexdigest()

    def catalog(self):
        result = []
        for topic_id, implemented in _FIELDS.items():
            topic = get_topic(topic_id)
            topic.update(status="available", object_types=["battle"],
                         supported_versions=["1.37.4"], triggers=["query", "event"],
                         source="BattleObservationAdapter", visibility="direct_participant",
                         context_scope="event_scope", observer_roles=[])
            topic["event_filters"] = {"types": [EVENT_TYPE], "actors": False, "recipients": False,
                                      "reason": "Battle side order does not establish actor/recipient roles"}
            topic["parameters"] = {"type": "object", "properties": {
                "event_id": {"type": "string", "pattern": r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$"}},
                "additionalProperties": False}
            topic["fields"] = {field: {
                "coverage": "partial", "source": "IBOW.v2/v3/v4/v5/v6/v7/v8/v9/v10/v11",
                "description": "观察国直接参战的已采集记录；完整战报仍有缺口",
            } for field in implemented}
            if topic_id == "B01":
                topic["query_guidance"] = deepcopy(_B01_DISCOVERY_GUIDANCE)
                topic["fields"]["event_id"].update(
                    selection="one_captured_battle_record",
                    discovery_topics=["H01.battle_sequence", "W03.battle_losses"],
                )
            if topic_id == "B01":
                topic["fields"]["sides"].update(
                    battle_role_basis="fixed1374_combat_save_keys",
                    combat_side_roles={"0": "attacker", "1": "defender"},
                    result_side_order_can_reverse=True,
                )
            if topic_id == "B03":
                topic["fields"]["retreat"].update(
                    source="IBOW.v10.RETR",
                    description="本国军队或舰队退却正例，数量为观测下限；已验证败方原生全歼时撤退不适用，其余无观测仍未知",
                    complete=False,
                    basis="event_owned_losing_unit_state_before_path_update",
                    classification_scope="observer_owned_units_at_regular_battle_end",
                    known_true_supported=True,
                    known_false_supported=False,
                    native_overrun_not_applicable_supported=True,
                    count_is_lower_bound=True,
                    foreign_unit_visibility_verified=False,
                    destinations_captured=False,
                    arrival_captured=False,
                )
                topic["fields"]["annihilation"].update(
                    source="IBOW.v9.EOST / legacy naval NAVL",
                    description="同场原生overrun标志已置位的败方全歼结果；wire9支持陆海战，旧NAVL仅海战，清零不证明未全歼",
                    complete=False,
                    basis="native_combat_side_overrun_marker",
                    classification_scope="native_overrun_path_only",
                    known_true_supported=True,
                    known_false_supported=False,
                    surviving_units_after_cleanup_verified=False,
                    zero_remaining_implies_annihilation=False,
                )
            if topic_id == "B04":
                topic["triggers"].append("periodic")
                topic["periodic_scope"] = {
                    "requires_event_id": True,
                    "semantics": "reread_one_retained_record_not_new_battle_capture",
                    "acquires_capture": False,
                }
                topic["fields"]["details"].update(
                    frame_requests_revision=1,
                    flag_inputs={"capture_wire": 15, "path": "details.value.flag_inputs",
                                 "capture_stage": "formatter_container_before_cleanup",
                                 "runtime_widget_state_verified": False},
                    independent_line={"capture_wire": 14,
                                      "path": "details.value.independent_line",
                                      "producer_required": "same_event_owned_native_formatter",
                                      "input_semantics": "derived_name_candidate",
                                      "native_line1_verified": False},
                    description=(
                        "同场输入、控件和侧别；含组合结果、按钮分支及派生名称行和紧凑损失候选，"
                        "技能和领袖图标保留固定版本的帧请求；候选不表示原生Line1、控件或布局已显示"
                    ),
                )
                topic["fields"]["raw_text"].update(
                    coverage="partial",
                    source="IBOW.v6/v7/v8/v9",
                    paths=["payload.battle_fields.raw_text"],
                    description=(
                        "仅逐场记录中经 wire6 原生捕获并通过日期与文本解码检查的 Line1 片段；"
                        "不包含标题、按钮文本、最终布局或完整战报正文"
                    ),
                    unit="native_text_sections",
                    basis="wire6_native_line1",
                    partial=True,
                    complete=False,
                    full_display_complete=False,
                    native_visibility_verified=False,
                )
            if topic_id == "B01":
                topic["fields"]["war_id"].update(
                    description="同一观察会话中由共享原生战争注册表绑定的透明 ID；日期、进程和双方 full-ref 守卫缺一不可",
                    identity_scope="observer_session", native_integer_id_proven=False,
                    complete=False)
                topic["fields"]["winner"].update(
                    description="原生结束处理确定的获胜参战侧、参与国及观察国胜负；窗口尚未逐项对照",
                    scope="whole_combat_side", runtime_popup_verified=False)
            if topic_id == "B02":
                for field, metadata in topic["fields"].items():
                    metadata.update(description="整条原始参战侧的步兵、骑兵、炮兵数量；不按单个国家分摊",
                                    supported_battle_types=["land"], scope="whole_combat_side",
                                    units_by_battle_type={"land": "men"}, scale=1,
                                    runtime_popup_verified=False)
                    metadata.update(
                        description="整条参战侧的兵种数量；海战v3支持有符号净变化和剩余，v2只有初始",
                        supported_battle_types=["land", "naval"],
                        units_by_battle_type={"land": "men", "naval": "ships"},
                        naval_loss_semantics="net_change_negative_loss_positive_gain")
            if topic_id == "B03":
                topic["fields"]["ships_captured"].update(
                    description="原生海战结果显示操作数；整条参战侧的舰船俘获值，不是国家实际变化",
                    supported_battle_types=["naval"], scope="whole_combat_side",
                    unit="ships", scale=1, units_by_battle_type={"naval": "ships"},
                    requires_wire_version=3, requires_naval_extension=True,
                    native_semantics="result_display_operand", runtime_popup_verified=False)
                topic["fields"]["prestige"].update(
                    description="原生陆海战结果显示操作数；不推导国家实际威望变化",
                    supported_battle_types=["land", "naval"], scope="whole_combat_side",
                    unit="prestige", scale=1000,
                    units_by_battle_type={"land": "prestige", "naval": "prestige"},
                    native_semantics="result_display_operand", runtime_popup_verified=False)
                topic["fields"]["war_score"].update(
                    description="原生陆海战结果显示操作数；不是战争总分或已应用的国家状态变化",
                    supported_battle_types=["land", "naval"], scope="whole_combat_side",
                    unit="war_score", scale=1000,
                    units_by_battle_type={"land": "war_score", "naval": "war_score"},
                    quantity="result_window_side_operand",
                    native_semantics="result_window_side_operand",
                    display_presence="unverified", runtime_popup_verified=False)
                topic["fields"]["army_tradition"].update(
                    description="原生陆战结果显示操作数；不推导国家实际军事传统变化",
                    supported_battle_types=["land"], scope="whole_combat_side",
                    unit="army_tradition", scale=1000,
                    units_by_battle_type={"land": "army_tradition"},
                    native_semantics="result_display_operand", runtime_popup_verified=False)
                topic["fields"]["naval_tradition"].update(
                    description="原生海战结果显示操作数，按整条参战侧提供",
                    supported_battle_types=["naval"], scope="whole_combat_side",
                    unit="naval_tradition", scale=1000,
                    units_by_battle_type={"naval": "naval_tradition"},
                    native_semantics="result_display_operand", runtime_popup_verified=False)
                topic["fields"]["war_exhaustion"].update(
                    description="原生陆海战厌战结果显示操作数，按整条参战侧提供",
                    supported_battle_types=["land", "naval"], scope="whole_combat_side",
                    unit="war_exhaustion", scale=1000,
                    units_by_battle_type={"land": "war_exhaustion", "naval": "war_exhaustion"},
                    native_semantics="result_display_operand", runtime_popup_verified=False)
            result.append(topic)
        return result

    def validate_query(self, query):
        if not isinstance(query, dict) or set(query) - {"topic", "object", "fields", "parameters"}:
            raise InformationError("invalid_query", "Invalid battle query")
        topic = next((t for t in self.catalog() if t["topic_id"] == query.get("topic")), None)
        if topic is None:
            raise InformationError("unknown_topic", "Unknown battle topic")
        if query.get("object") != {"type": "battle"}:
            raise InformationError("invalid_object", "Battle observations require a battle object")
        fields = query.get("fields")
        if not isinstance(fields, list) or not fields or any(f not in topic["fields"] for f in fields):
            raise InformationError("invalid_fields", "Unsupported battle fields")
        parameters = query.get("parameters", {})
        _validate_schema(parameters, topic["parameters"], "parameters")
        return dict(deepcopy(query), parameters=deepcopy(parameters))

    def _bound(self, context):
        return (context.get("status") == "ready"
                and context.get("session_id") == self.binding["session_id"]
                and context.get("observer") == self.observer
                and context.get("game_version") == "1.37.4"
                and context.get("game_sha256") == GAME_SHA256
                and context.get("mode") == self.binding["mode"]
                and context.get("observer_ref", self.binding["observer_ref"]) == self.binding["observer_ref"]
                and context.get("world_id") == self.binding.get("world_id"))

    def _rows(self, *, after=0, message_id=None, limit=PAGE_SIZE):
        # RO mode neither creates a missing database nor modifies the research
        # stream. Bounded substr prevents a corrupt large BLOB allocation.
        if type(limit) is not int or not 1 <= limit <= MAX_HISTORY_PAGE:
            raise InformationError("invalid_history_limit", "limit must be 1..256")
        connection = sqlite3.connect(self.database.as_uri() + "?mode=ro", uri=True)
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("PRAGMA query_only=ON")
            sql = ("SELECT g.group_id,g.message_id,c.payload_sha256,c.total_bytes,"
                   "length(c.payload) AS payload_bytes,substr(c.payload,1,?) AS payload "
                   "FROM fragment_groups g JOIN complete_messages c USING(group_id) "
                   "WHERE g.installation=? AND g.world_generation=? AND g.status='complete' ")
            args = [MAX_PAYLOAD + 1, self.binding["installation"], self.binding["generation"]]
            if message_id is not None:
                sql += "AND g.message_id=? "
                args.append(message_id)
            else:
                sql += "AND g.group_id>? "
                args.append(after)
            return [dict(row) for row in connection.execute(sql + "ORDER BY g.group_id LIMIT ?", args + [limit])]
        finally:
            connection.close()

    def _history_cursor_prefix(self, war_id=None):
        scope = self.binding_id[:32]
        if war_id is not None:
            scope = hashlib.sha256(canonical({
                "binding": self.binding_id, "war_id": war_id,
            }).encode("utf-8")).hexdigest()[:32]
        return f"battle-page:{scope}:"

    def _history_cursor(self, group_id, war_id=None):
        # Storage progress can pass filtered rows. It is not the identity of
        # an undisclosed battle and is never emitted as an event reference.
        return f"{self._history_cursor_prefix(war_id)}{group_id:016x}"

    def _row_group_after_event(self, event_id, context, war_id=None):
        """Resolve an opaque page cursor without scanning the stream."""

        page_prefix = self._history_cursor_prefix(war_id)
        if isinstance(event_id, str) and event_id.startswith(page_prefix):
            position = event_id[len(page_prefix):]
            if re.fullmatch(r"[0-9a-f]{16}", position):
                return int(position, 16)
        if not isinstance(event_id, str) or not event_id.startswith(self.prefix):
            raise InformationError("battle_history_cursor_binding_mismatch",
                                   "History cursor belongs to another battle stream")
        message_id = event_id[len(self.prefix):]
        if not re.fullmatch(r"[1-9][0-9]{0,19}", message_id):
            raise InformationError("invalid_history_cursor", "Invalid battle history cursor")
        rows = self._rows(message_id=message_id)
        event = self._event(rows[0], context) if rows else None
        if event is None:
            raise InformationError("battle_history_cursor_not_found",
                                   "History cursor is not available in the observer scope")
        if war_id is not None:
            identity = event["payload"]["battle_fields"].get("war_id", {})
            if identity.get("status") != "known" or identity.get("value") != war_id:
                raise InformationError("battle_history_cursor_war_mismatch",
                                       "History cursor is outside the selected war")
        return rows[0]["group_id"]

    def _history_reference(self, event, *, include_losses=False):
        fields = event["payload"]["battle_fields"]

        def value(field):
            item = fields.get(field)
            if isinstance(item, dict) and item.get("status") == "known":
                return deepcopy(item.get("value"))
            return None

        reference = {
            "event_id": event["event_id"],
            "event_type": EVENT_TYPE,
            "game_date": event.get("game_date"),
            "battle_type": value("battle_type"),
            "location": value("location"),
            "participant_countries": deepcopy(event["payload"].get("participant_countries", [])),
            "war_id": deepcopy(fields.get("war_id", {
                "status": "unknown", "reason": "WAR_ID_UNRESOLVED",
            })),
            "source": deepcopy(event.get("source", {})),
        }
        if include_losses:
            reference["losses"] = deepcopy(fields.get("losses", {
                "status": "unknown", "reason": "BATTLE_LOSSES_NOT_CAPTURED",
            }))
        return reference

    def _history_page(self, context, *, after_event_id=None, limit=PAGE_SIZE,
                      include_losses=False, war_id=None):
        if not self._bound(context):
            return None, {"reason": "BATTLE_OBSERVER_BINDING_MISMATCH"}
        after_group = self._row_group_after_event(after_event_id, context, war_id) if after_event_id else 0
        # Read one look-ahead row where possible.  This lets a page with
        # exactly ``limit`` returned references advertise whether another
        # durable row exists without an unbounded count query.
        scan_limit = MAX_HISTORY_PAGE
        rows = self._rows(after=after_group, limit=scan_limit)
        references = []
        gaps = [dict(reason=reason) for reason in _HISTORY_PAGE_GAPS]
        scanned = 0
        cursor = after_event_id
        processed_group = after_group
        date_behind = False
        for row in rows:
            scanned += 1
            row_cursor = f"{self.prefix}{row['message_id']}"
            try:
                event = self._event(row, context)
            except InformationError as error:
                if error.code == "battle_context_date_behind":
                    gaps.append({"reason": "BATTLE_CONTEXT_DATE_BEHIND"})
                    date_behind = True
                    break
                gaps.append({"reason": "BATTLE_PAYLOAD_REJECTED", "code": error.code})
                processed_group = row["group_id"]
                cursor = self._history_cursor(processed_group, war_id)
                continue
            except (ValueError, UnicodeError):
                gaps.append({"reason": "BATTLE_PAYLOAD_REJECTED"})
                processed_group = row["group_id"]
                cursor = self._history_cursor(processed_group, war_id)
                continue
            processed_group = row["group_id"]
            if event is None:
                cursor = self._history_cursor(processed_group, war_id)
                continue
            if war_id is not None:
                identity = event["payload"]["battle_fields"].get("war_id", {})
                if identity.get("status") != "known":
                    if (identity.get("status") != "not_applicable"
                            and not any(gap["reason"] == "BATTLE_HISTORY_WAR_ID_UNKNOWN" for gap in gaps)):
                        gaps.append({"reason": "BATTLE_HISTORY_WAR_ID_UNKNOWN"})
                    cursor = self._history_cursor(processed_group, war_id)
                    continue
                if identity.get("value") != war_id:
                    cursor = self._history_cursor(processed_group, war_id)
                    continue
            cursor = row_cursor
            references.append(self._history_reference(event, include_losses=include_losses))
            if len(references) >= limit and scanned < len(rows):
                break
        # A date-ahead row remains available to the next request, just as it
        # does for poll_events.  Other rows are durably skipped by cursor.
        has_more = date_behind or scanned < len(rows) or len(rows) == scan_limit
        next_cursor = (cursor or self._history_cursor(processed_group, war_id)) if has_more else None
        coverage = {
            "complete": False,
            "page_complete": next_cursor is None,
            "has_more": next_cursor is not None,
            "after_event_id": after_event_id,
            "next_cursor": next_cursor,
            "returned": len(references),
            "gaps": gaps,
        }
        if war_id is not None:
            coverage.update(war_id=war_id, war_selection="verified_event_war_id_match_only",
                            war_existence_proven_by_empty_page=False)
        return {
            "event_refs": references,
            "next_cursor": next_cursor,
            "coverage": coverage,
        }, None

    @staticmethod
    def _war_identity_projection(decoded, result, context, binding):
        """Validate the optional v5 registry identity without exposing a pointer."""
        wire_identity = decoded.get("war_identity")
        owned = decoded.get("context") or {}
        sides = owned.get("sides", [])
        complete_sides = (len(sides) == 2 and all(
            side.get("present") is True and side.get("participants", {}).get("complete") is True
            and side["participants"].get("full_refs") for side in sides))
        if (owned.get("known_router") is True and owned.get("war_context_status") == 0
                and complete_sides and (wire_identity or {}).get("status") != "bound"):
            countries = [{_tag(ref) for ref in side["participants"]["full_refs"]} for side in sides]
            if ((countries[0] == {"REB"} and "REB" not in countries[1])
                    or (countries[1] == {"REB"} and "REB" not in countries[0])):
                reason = "REBEL_BATTLE_WITHOUT_WAR"
                return ({"status": "not_applicable", "reason": reason},
                        {"status": "not_applicable", "public_reason": reason},
                        {"war_identity_status": "not_applicable", "war_identity_reason": reason})
        if not isinstance(wire_identity, dict):
            return ({"status": "unknown", "reason": "WAR_ID_UNRESOLVED"}, None, {})

        status = wire_identity.get("status")
        reason_value = wire_identity.get("reason")
        reason_code = reason_value if type(reason_value) is int and 0 <= reason_value <= 255 else None
        raw_date = wire_identity.get("raw_date")
        creation = wire_identity.get("process_creation_filetime")
        binding_flags = wire_identity.get("binding_flags")
        pair = wire_identity.get("pair_full_refs")
        war_id = wire_identity.get("war_id")
        scope = wire_identity.get("identity_scope")

        # Only bounded scalar wire values are copied into diagnostics.  In
        # particular, no native pointer or arbitrary object is propagated.
        detail = {
            "status": status if status in ("bound", "absent", "invalid") else "invalid",
            "reason": reason_code if reason_code is not None else reason_value,
            "binding_flags": binding_flags if type(binding_flags) is int else None,
            "process_creation_filetime": creation if type(creation) is int else None,
            "raw_date": raw_date if type(raw_date) is int else None,
            "pair_full_refs": deepcopy(pair) if isinstance(pair, list) and len(pair) == 2
                              and all(type(value) is int and value >= 0 for value in pair) else None,
            "identity_scope": scope if isinstance(scope, str) else None,
        }
        if isinstance(war_id, str) and len(war_id) <= 64:
            detail["war_id"] = war_id

        if status != "bound":
            if reason_code in _WAR_ID_REASON_NAMES:
                public_reason = _WAR_ID_REASON_NAMES[reason_code]
            elif status == "absent" and reason_code in (None, 0):
                public_reason = "WAR_ID_UNRESOLVED"
            elif status == "absent":
                public_reason = "WAR_ID_ABSENT"
            else:
                public_reason = "WAR_ID_INVALID"
            detail["public_reason"] = public_reason
            return ({"status": "unknown", "reason": public_reason}, detail,
                    {"war_identity_status": status or "invalid", "war_identity_reason": reason_code})

        if type(binding_flags) is not int or binding_flags != 63:
            return ({"status": "unknown", "reason": "WAR_ID_BINDING_FLAGS_UNVERIFIED"}, detail,
                    {"war_identity_status": "bound", "war_identity_reason": "BINDING_FLAGS"})
        if scope != "observer_session":
            return ({"status": "unknown", "reason": "WAR_ID_SCOPE_UNVERIFIED"}, detail,
                    {"war_identity_status": "bound", "war_identity_reason": "SCOPE"})
        if type(raw_date) is not int or raw_date != result.get("raw_date"):
            return ({"status": "unknown", "reason": "WAR_ID_DATE_MISMATCH"}, detail,
                    {"war_identity_status": "bound", "war_identity_reason": "DATE"})

        identity_values = []
        for holder in (binding, context):
            if not isinstance(holder, dict):
                continue
            for key in ("process_creation_filetime", "creation_filetime"):
                if key in holder:
                    parsed = _identity_integer(holder[key])
                    if parsed is not None:
                        identity_values.append(parsed)
        expected_creation = identity_values[0] if identity_values else None
        if expected_creation is None:
            return ({"status": "unknown", "reason": "WAR_ID_PROCESS_CREATION_UNAVAILABLE"}, detail,
                    {"war_identity_status": "bound", "war_identity_reason": "CREATION_MISSING"})
        if (not all(value == expected_creation for value in identity_values)
                or type(creation) is not int or creation != expected_creation):
            return ({"status": "unknown", "reason": "WAR_ID_PROCESS_CREATION_MISMATCH"}, detail,
                    {"war_identity_status": "bound", "war_identity_reason": "CREATION"})

        expected_pair = []
        for side in result.get("sides", ()):
            candidate = side.get("country")
            if type(candidate) is not int or candidate < 0:
                candidate = side.get("full_ref")
            if type(candidate) is not int or candidate < 0:
                expected_pair = []
                break
            expected_pair.append(candidate)
        if (len(expected_pair) != 2 or not isinstance(pair, list) or len(pair) != 2
                or any(type(value) is not int or value < 0 for value in pair)
                or pair != expected_pair):
            return ({"status": "unknown", "reason": "WAR_ID_RESULT_PAIR_MISMATCH"}, detail,
                    {"war_identity_status": "bound", "war_identity_reason": "PAIR"})

        if not isinstance(war_id, str):
            return ({"status": "unknown", "reason": "WAR_ID_FORMAT_INVALID"}, detail,
                    {"war_identity_status": "bound", "war_identity_reason": "ID"})
        match = _WAR_ID_RE.fullmatch(war_id)
        if match is None:
            return ({"status": "unknown", "reason": "WAR_ID_FORMAT_INVALID"}, detail,
                    {"war_identity_status": "bound", "war_identity_reason": "ID"})
        # The eight-digit serial is monotonic across reusable registry slots.
        if int(match.group(2), 16) < 1:
            return ({"status": "unknown", "reason": "WAR_ID_SUFFIX_OUT_OF_RANGE"}, detail,
                    {"war_identity_status": "bound", "war_identity_reason": "SUFFIX"})
        if int(match.group(1), 16) != _splitmix64(expected_creation):
            return ({"status": "unknown", "reason": "WAR_ID_EPOCH_MISMATCH"}, detail,
                    {"war_identity_status": "bound", "war_identity_reason": "EPOCH"})
        detail["public_reason"] = "BOUND"
        return ({"status": "known", "value": war_id}, detail,
                {"war_identity_status": "bound", "war_identity_reason": 0,
                 "war_identity_scope": "observer_session",
                 "war_registry": "shared_native_peace_registry"})

    def _event(self, row, context):
        raw = row["payload"]
        if (row["payload_bytes"] != row["total_bytes"] or not 0 < len(raw) <= MAX_PAYLOAD
                or hashlib.sha256(raw).hexdigest() != row["payload_sha256"]):
            raise InformationError("battle_payload_invalid", "Invalid captured payload")
        try:
            decoded = decode(raw)
            native_wire_version = decoded.get("wire6", {}).get(
                "version", decoded.get("wire", {}).get("version")
            )
            native_text = (
                project_native_text(decoded)
                if native_wire_version == 6
                else None
            )
            raw_text = project_raw_text(native_text, wire_version=native_wire_version)
        except (TemplateWireError, WarIdentityWireError, NativeTextWireError,
                DisplayContextWireError, NameHandoffWireError, EndStateWireError, RetreatWireError,
                NameSourcesWireError, OutcomeTextWireError, OutcomeTailWireError, BattleNativeTextError, ValueError):
            # Old v1 records have no participant context. They remain in the
            # research store, without disclosing their details to this observer.
            return None
        owned = decoded.get("context")
        if not owned or owned.get("known_router") is not True:
            return None
        participant_sides = [side for side in owned["sides"]
                             if side["present"] and side["participants"]["complete"]
                             and self.observer_ref in side["participants"]["full_refs"]]
        if len(participant_sides) != 1:
            return None
        observation = decoded["observation"]
        result = observation["result"]
        if (type(context.get("game_date")) is not int
                or result["raw_date"] > context["game_date"]):
            raise InformationError("battle_context_date_behind", "Captured record is ahead of context date")
        def text(value):
            try:
                return _known(decode_native_text_hex(value["raw_hex"], codec="eu4_escape", max_bytes=4096))
            except (ValueError, UnicodeError):
                return {"status": "unknown", "reason": "BATTLE_TEXT_DECODE_FAILED"}
        sides = []
        candidates = [[i for i, raw_side in enumerate(owned["sides"])
                       if raw_side["present"] and raw_side["participants"]["complete"]
                       and side["country"] in raw_side["participants"]["full_refs"]]
                      for side in result["sides"]]
        mapping = ([items[0] for items in candidates]
                   if all(len(items) == 1 for items in candidates) else [None, None])
        if len(set(mapping)) != 2:
            mapping = [None, None]
        for index, side in enumerate(result["sides"]):
            combat_index = mapping[index]
            participants = (owned["sides"][combat_index]["participants"] if combat_index is not None
                            else {"complete": False, "full_refs": []})
            try:
                representative = _tag(side["country"])
            except (ValueError, UnicodeError):
                representative = {"status": "unknown", "reason": "RESULT_REPRESENTATIVE_UNRESOLVED"}
            role = {"status": "unknown", "reason": "RESULT_SIDE_MAPPING_UNRESOLVED"}
            if combat_index is not None:
                role = _known(COMBAT_ROLES[combat_index])
            sides.append({"index": index, "index_scope": "result_side", "combat_side_index": combat_index,
                          "representative": representative,
                          "participants": [_tag(ref) for ref in participants["full_refs"]],
                          "participants_complete": participants["complete"],
                          "observer_participated": (self.observer_ref in participants["full_refs"]
                                                    if combat_index is not None else None),
                          "role": role})
        event_id = self.prefix + row["message_id"]
        identifier(event_id, "event_id")
        template = project_template(decoded)
        gaps = [gap for gap in _GAPS if gap != "LEGACY_NAVAL_LOSS_OPERANDS_NOT_CAPTURED"
                or (owned["kind"] == 2 and decoded.get("naval") is None)]
        if None in mapping:
            gaps.append("RESULT_SIDE_MAPPING_UNRESOLVED")
        fields = {
            "event_id": event_id,
            "battle_type": {1: "land", 2: "naval"}[owned["kind"]],
            "name": text(result["name"]),
            "location": {"province_id": result["province_id"]},
            "end_date": {"raw": result["raw_date"], "unit": "game_date_raw"},
            "sides": sides,
            "commanders": [{"side_index": index, "index_scope": "result_side",
                            "combat_side_index": mapping[index], "name": text(side["commander"])}
                           for index, side in enumerate(result["sides"])],
            "details": {"result_raw": {key: result[key] for key in ("flag108", "aux100", "aux104")},
                        "side_result_raw_i32": [deepcopy(side["raw_fields"]) for side in result["sides"]],
                        "side_combat_raw_i32": [deepcopy(side["raw_fields"]) for side in owned["sides"]],
                        "summary": deepcopy(observation["summary"]),
                        "message_template": template,
                        "display": project_display(decoded, template, mapping=mapping,
                                                   observer_ref=self.observer_ref,
                                                   native_line1=raw_text),
                        "semantics": "uninterpreted_native_values"},
            "record_order": {"capture_sequence": str(observation["sequence"])},
            "deduplication": {"scope": "captured_record", "key": event_id,
                              "same_battle_deduplication_verified": False},
            "completeness": {"business_complete": False, "full_display_complete": False,
                             "own_participation_verified": True,
                             "native_visibility_verified": False},
            "gaps": gaps,
        }
        war_id_field, war_identity_detail, war_identity_source = self._war_identity_projection(
            decoded, result, context, self.binding)
        if war_id_field["status"] in ("known", "not_applicable"):
            fields["gaps"] = ["BATTLE_IDENTITY_UNRESOLVED" if gap == "WAR_AND_BATTLE_IDENTITIES_UNRESOLVED"
                              else gap for gap in fields["gaps"]]
        if war_identity_detail is not None:
            fields["details"]["war_identity"] = war_identity_detail
        fields = {field: value if field == "name" else _known(value) for field, value in fields.items()}
        fields["raw_text"] = raw_text
        if native_text is not None:
            fields["details"]["value"]["native_text"] = native_text
        if decoded.get("wire7", {}).get("version") == 7:
            display_context = project_display_context(decoded)
            display_context["body_candidate"] = project_body_candidate(decoded)
            display_context["compact_loss_candidates"] = project_compact_loss_candidates(decoded)
            fields["details"]["value"]["display_context"] = display_context
            composition = project_display_composition(decoded, mapping=mapping, observer_ref=self.observer_ref)
            fields["details"]["value"]["display_composition"] = composition
            fields["details"]["value"]["result_text"] = (
                project_readable_text(composition) if composition.get("status") == "known" else
                {"status": "unknown", "reason": composition.get("reason", "BATTLE_RESULT_TEXT_UNAVAILABLE")})
        if decoded.get("wire8", {}).get("version") == 8:
            fields["details"]["value"]["name_handoff"] = deepcopy(
                decoded.get("name_handoff", {
                    "status": "unknown",
                    "reason": "NAME_HANDOFF_NOT_CAPTURED",
                }))
        if decoded.get("wire11", {}).get("version") == 11:
            fields["details"]["value"]["name_sources"] = project_name_sources(decoded)
            fields["details"]["value"]["name_source_candidate"] = project_name_candidate(decoded)
        if decoded.get("wire12", {}).get("version") == 12:
            fields["details"]["value"]["outcome_text_sources"] = project_outcome_text_sources(decoded)
            fields["details"]["value"]["outcome_text_composition"] = project_outcome_text_composition(
                decoded, mapping=mapping, observer_ref=self.observer_ref)
        if decoded.get("wire13", {}).get("version") == 13:
            fields["details"]["value"]["outcome_tail_sources"] = project_outcome_tail_sources(decoded)
        if decoded.get("wire14", {}).get("version") == 14:
            fields["details"]["value"]["independent_line"] = project_independent_line(decoded)
        if decoded.get("wire15", {}).get("version") == 15:
            fields["details"]["value"]["flag_inputs"] = project_flag_inputs(decoded)
        # ``war_id_field`` is already a public status/value object; unlike the
        # other raw projection values it must not be wrapped a second time.
        fields["war_id"] = war_id_field
        fields.update(project_forces(decoded, mapping))
        fields.update(project_effects(decoded, mapping, self.observer_ref))
        from .battle_annihilation import project_annihilation
        fields["annihilation"] = project_annihilation(decoded, mapping, self.observer_ref)
        fields["winner"] = project_outcome(decoded, mapping, self.observer_ref)
        fields["retreat"] = project_retreat(decoded, mapping, self.observer_ref)
        wire_version = decoded.get("wire13", {}).get("version", decoded.get("wire12", {}).get("version", decoded.get("wire11", {}).get("version", decoded.get("wire10", {}).get("version", decoded.get("wire9", {}).get(
            "version", decoded.get("wire8", {}).get("version", decoded.get("wire7", {}).get(
                "version", native_wire_version)))))))
        wire_version = decoded.get("wire14", {}).get("version", wire_version)
        wire_version = decoded.get("wire15", {}).get("version", wire_version)
        source = {"name": f"IBOW.v{wire_version}", "mode": self.binding["mode"],
                  "projection": "event_snapshot", "event_id": event_id,
                  "projection_version": 32 if wire_version == 15 else 31 if wire_version == 14 else 30,
                  "effect_projection_version": 2,
                  "war_identity_projection_version": 2,
                  "identity_scope": "captured_record_not_game_battle",
                  "knowledge_basis": "observer_full_ref_in_complete_participant_vector",
                  "battle_role_basis": "fixed1374_combat_save_keys",
                  "complete": False}
        source.update(war_identity_source)
        if decoded.get("wire7", {}).get("version") == 7:
            source["display_composition_projection_version"] = 2
            source["result_text_projection_version"] = 2
        if wire_version in (10, 11, 12, 13, 14, 15):
            source["retreat_projection_version"] = 2
            # The private raw envelope also contains foreign-unit owner/flags.
            # Its digest is an ingest check, never an observer-visible digest.
            source.update(public_projection_sha256=hashlib.sha256(canonical(fields).encode()).hexdigest(),
                          hash_basis="observer_visible_battle_fields")
        else:
            source["payload_sha256"] = row["payload_sha256"]
        return {"event_id": event_id, "event_type": EVENT_TYPE,
                "session_id": context["session_id"], "observer": context["observer"],
                "game_date": result["raw_date"], "objects": [{"type": "battle"}],
                "complete": False,
                "payload": {"participant_countries": sorted({_tag(ref) for side in owned["sides"]
                                                              for ref in side["participants"]["full_refs"]}),
                            "battle_fields": fields},
                "source": source}

    def poll_events(self, context, cursor):
        if cursor is not None and (not isinstance(cursor, dict) or cursor.get("binding") != self.binding_id):
            return {"events": [], "cursor": cursor, "complete": False,
                    "gaps": [{"reason": "BATTLE_CURSOR_BINDING_MISMATCH_REBIND_REQUIRED"}]}
        cursor = cursor or {}
        after = cursor.get("after", 0)
        if type(after) is not int or after < 0:
            raise InformationError("invalid_battle_cursor", "Invalid stream cursor")
        if not self._bound(context):
            return {"events": [], "cursor": cursor, "complete": False,
                    "gaps": [{"reason": "BATTLE_OBSERVER_BINDING_MISMATCH"}]}
        rows = self._rows(after=after)
        events, rejected, date_behind = [], False, False
        for row in rows:
            try:
                event = self._event(row, context)
            except InformationError as error:
                if error.code == "battle_context_date_behind":
                    date_behind = True
                    break
                rejected = True
                event = None
            except (ValueError, UnicodeError):
                rejected = True
                event = None
            if event is not None:
                events.append(event)
            after = row["group_id"]
        gaps = [{"reason": gap} for gap in _GAPS]
        if rejected:
            gaps.append({"reason": "BATTLE_PAYLOAD_REJECTED"})
        if date_behind:
            gaps.append({"reason": "BATTLE_CONTEXT_DATE_BEHIND"})
        return {"events": events, "cursor": {"binding": self.binding_id, "after": after},
                "complete": False, "gaps": gaps}

    def read(self, query, context):
        query = self.validate_query(query)
        requested = query["parameters"].get("event_id")
        event = None
        if self._bound(context) and isinstance(requested, str) and requested.startswith(self.prefix):
            message_id = requested[len(self.prefix):]
            if re.fullmatch(r"[1-9][0-9]{0,19}", message_id):
                rows = self._rows(message_id=message_id)
                if rows:
                    try:
                        event = self._event(rows[0], context)
                    except (InformationError, ValueError, UnicodeError):
                        event = None
        reason = "BATTLE_EVENT_ID_REQUIRED" if requested is None else "BATTLE_RECORD_NOT_AVAILABLE_IN_OBSERVER_SCOPE"
        values = event["payload"]["battle_fields"] if event else {}
        unavailable = {"status": "unavailable", "reason": reason}
        if requested is None:
            unavailable["guidance"] = deepcopy(_B01_DISCOVERY_GUIDANCE)
        return {"query": query, "fields": {field: deepcopy(values[field]) if field in values else
                deepcopy(unavailable) for field in query["fields"]},
                "objects": [deepcopy(query["object"])], "complete": False,
                "source": deepcopy(event["source"]) if event else {"name": "IBOW.battle_stream", "complete": False}}

    def validate_history_query(self, query):
        topic_id = query.get("topic") if isinstance(query, dict) else None
        topic = _history_catalog_entry(topic_id)
        if not isinstance(query, dict) or set(query) - {"topic", "object", "fields", "parameters"}:
            raise InformationError("invalid_query", "Invalid battle history query")
        fields = query.get("fields")
        if (not isinstance(fields, list) or not fields or
                any(not isinstance(field, str) or field not in topic["fields"] for field in fields) or
                len(set(fields)) != len(fields)):
            raise InformationError("invalid_fields", "Unsupported battle history fields")
        parameters = query.get("parameters", {})
        _validate_schema(parameters, topic["parameters"], "parameters")
        page_parameters = {"after_event_id", "limit"}
        base = deepcopy(query)
        base["parameters"] = {key: value for key, value in parameters.items()
                               if key not in page_parameters}
        # The global validator supplies the common object identity and field
        # checks.  It deliberately does not gate on topic status, so W03 can
        # expose only this partial battle-loss reference projection.
        validated = validate_catalog_query(base)
        validated["parameters"] = deepcopy(parameters)
        return validated

    def read_history(self, query, context):
        query = self.validate_history_query(query)
        topic_id = query["topic"]
        field = _HISTORY_FIELDS[topic_id]
        obj = query["object"]
        if obj.get("type") == "country" and obj.get("country") not in (None, self.observer):
            return {"query": query, "fields": {field: {"status": "unavailable",
                    "reason": "BATTLE_OBSERVER_SCOPE_MISMATCH"}}, "objects": [deepcopy(obj)],
                    "complete": False, "source": {"name": "IBOW.battle_stream", "complete": False}}
        if obj.get("type") == "session" and obj.get("session_id") not in (
                None, self.binding["session_id"]):
            return {"query": query, "fields": {field: {"status": "unavailable",
                    "reason": "BATTLE_SESSION_SCOPE_MISMATCH"}}, "objects": [deepcopy(obj)],
                    "complete": False, "source": {"name": "IBOW.battle_stream", "complete": False}}
        selected_war = None
        if obj.get("type") == "war":
            reason = "WAR_ID_UNRESOLVED"
            candidate = obj.get("war_id")
            if topic_id == "W03" and candidate is not None:
                if any(key in obj for key in ("actor", "recipient")):
                    reason = "WAR_HISTORY_PAIR_SELECTION_UNSUPPORTED"
                else:
                    match = _WAR_ID_RE.fullmatch(candidate)
                    identities = [_identity_integer(holder[key])
                                  for holder in (self.binding, context)
                                  for key in ("process_creation_filetime", "creation_filetime")
                                  if key in holder]
                    if (match is not None and identities and identities[0] is not None
                            and all(value == identities[0] for value in identities)
                            and int(match.group(1), 16) == _splitmix64(identities[0])
                            and int(match.group(2), 16) >= 1):
                        selected_war = candidate
            if selected_war is None:
                return {"query": query, "fields": {field: {"status": "unavailable",
                        "reason": reason}}, "objects": [deepcopy(obj)],
                        "complete": False, "source": {"name": "IBOW.battle_stream", "complete": False}}
        parameters = query["parameters"]
        if (set(parameters) & {"request_id", "case"}
                or parameters.get("event_type", EVENT_TYPE) != EVENT_TYPE):
            return {"query": query, "fields": {field: {"status": "unavailable",
                    "reason": "BATTLE_HISTORY_FILTER_NOT_SUPPORTED"}}, "complete": False,
                    "source": {"name": "IBOW.battle_stream", "complete": False}}
        limit = parameters.get("limit", PAGE_SIZE)
        after = parameters.get("after_event_id")
        try:
            page, failure = self._history_page(
                context, after_event_id=after, limit=limit,
                include_losses=topic_id == "W03",
                war_id=selected_war,
            )
        except InformationError as error:
            page, failure = None, {"reason": error.code}
        except (OSError, sqlite3.Error) as error:
            page, failure = None, {"reason": "BATTLE_EVENT_SOURCE_UNAVAILABLE",
                                    "detail": type(error).__name__}
        if page is None:
            return {"query": query, "fields": {field: {"status": "unavailable",
                    "reason": failure["reason"]}}, "objects": [deepcopy(obj)],
                    "complete": False, "source": {"name": "IBOW.battle_stream", "complete": False}}
        item = _known(page)
        if topic_id == "W03":
            item.update(complete=False, partial=True, unit="battle_loss_event_page",
                        scale=1, period="captured_history")
        return {"query": query, "fields": {field: item},
                "objects": [deepcopy(obj)], "complete": False,
                "next_cursor": page["next_cursor"], "coverage": deepcopy(page["coverage"]),
                "source": {"name": "IBOW.battle_stream", "mode": self.binding["mode"],
                           "complete": False, "history_scope": "direct_participant_records"}}

    def read_event(self, query, context, event):
        # Resolve the durable record again, so a retained pending event cannot
        # bypass a changed observer binding or inject its own battle fields.
        query = deepcopy(query)
        selector = query.setdefault("parameters", {}).get("event_id")
        if event.get("event_type") == EVENT_TYPE and selector not in (None, event.get("event_id")):
            return {"query": query, "fields": {field: {"status": "unavailable",
                    "reason": "BATTLE_EVENT_SELECTOR_MISMATCH"} for field in query["fields"]},
                    "complete": False, "source": {"name": "IBOW.battle_stream", "complete": False}}
        if event.get("event_type") == EVENT_TYPE and selector in (None, event.get("event_id")):
            query["parameters"]["event_id"] = event.get("event_id")
        return self.read(query, context)

    def replay_event(self, query, context, event):
        """Replay only by resolving the already durable battle record again."""
        if event.get("event_type") != EVENT_TYPE:
            return {
                "query": deepcopy(query),
                "fields": {field: {"status": "unavailable", "reason": "BATTLE_EVENT_TYPE_MISMATCH"}
                           for field in query.get("fields", [])},
                "objects": [deepcopy(query.get("object", {}))],
                "complete": False,
                "source": {"name": "IBOW.battle_stream", "complete": False},
            }
        return self.read_event(deepcopy(query), deepcopy(context), deepcopy(event))


class BattleInformationSource:
    """Preserve the primary source and add one explicitly bound event stream."""

    def __init__(self, primary, database, binding):
        self.primary = primary
        self.battles = BattleObservationAdapter(database, binding)
        self.reads = CompositeSource(primary, [self.battles])
        # Explicit operator opt-in; the default remains a read-only stream.
        self.ingestor = None
        self.last_ingest_error = None
        self.capture_manager = None

    @staticmethod
    def requires_capture(subscription):
        return (subscription.get("kind") == "event"
                and EVENT_TYPE in subscription.get("event", {}).get("types", []))

    def capture_status(self):
        if self.capture_manager is not None:
            result = deepcopy(self.capture_manager.snapshot())
            result["mode"] = "subscription_managed_live"
            return result
        return {"managed": False, "owned": False, "producer_state": "unverified",
                "mode": "external_live_ingest" if self.ingestor is not None else "retained_records_only",
                "future_capture_verified": False, "complete": False}

    def sync_subscriptions(self, subscriptions, context):
        if self.capture_manager is None:
            return None
        consumers = {item["id"] for item in subscriptions if self.requires_capture(item)}
        if context.get("status") == "ready" and not self.battles._bound(context):
            consumers.clear()
        result = deepcopy(self.capture_manager.reconcile(consumers))
        result["mode"] = "subscription_managed_live"
        return result

    def close_capture(self):
        if self.capture_manager is not None:
            return self.capture_manager.close()
        return None

    def _refresh(self, context):
        if self.ingestor is None or not self.battles._bound(context):
            return
        try:
            self.ingestor.refresh()
            self.last_ingest_error = None
        except Exception as error:
            # Previously committed records remain readable during an ingest
            # failure; the event batch reports the acquisition gap.
            self.last_ingest_error = getattr(error, "code", "battle_ingest_failed")

    @classmethod
    def from_config(cls, primary, config_path):
        path = Path(config_path).resolve()
        if path.stat().st_size > 16384:
            raise InformationError("invalid_battle_config", "Battle config exceeds 16 KiB")
        config = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(config, dict) or set(config) != {"schema", "database", "binding"} or config["schema"] != "EU4-BATTLE-STREAM/1":
            raise InformationError("invalid_battle_config", "Invalid battle stream config")
        if not isinstance(config["database"], str) or not config["database"]:
            raise InformationError("invalid_battle_config", "Battle database path is required")
        return cls(primary, path.parent / config["database"], config["binding"])

    @property
    def event_types(self):
        return tuple(dict.fromkeys((*getattr(self.primary, "event_types", ()), EVENT_TYPE)))

    def context(self):
        return self.primary.context()

    def catalog(self):
        topics = self.reads.catalog()
        for topic in topics:
            topic_id = topic.get("topic_id")
            if topic_id in _FIELDS:
                topic["capture"] = self.capture_status()
            if topic_id in _HISTORY_FIELDS:
                history = _history_catalog_entry(topic_id)
                field = _HISTORY_FIELDS[topic_id]
                topic["fields"] = dict(topic.get("fields", {}), **{
                    field: deepcopy(history["fields"][field]),
                })
                topic["parameters"] = deepcopy(history["parameters"])
                if topic_id == "W03":
                    topic.update({key: deepcopy(history[key]) for key in (
                        "status", "supported_versions", "source", "triggers", "observer_roles",
                        "change_detection", "scope_note")})
                    topic["capture"] = self.capture_status()
        return topics

    def validate_query(self, query):
        if isinstance(query, dict) and query.get("topic") in _HISTORY_FIELDS:
            if _HISTORY_FIELDS[query["topic"]] not in query.get("fields", []):
                validator = getattr(self.primary, "validate_query", None)
                return validator(query) if callable(validator) else deepcopy(query)
            return self.battles.validate_history_query(query)
        return self.reads.validate_query(query)

    def query_capabilities(self, query):
        """Keep scheduling checks scoped to the actual history/primary owners."""
        topic = query.get("topic") if isinstance(query, dict) else None
        field = _HISTORY_FIELDS.get(topic)
        if field is None or field not in query.get("fields", []):
            capabilities = self.reads.query_capabilities(query)
            return [(subquery, self._retained_record_capability(subquery, entry))
                    for subquery, entry in capabilities]
        normalized = self.battles.validate_history_query(query)
        history_query = dict(deepcopy(normalized), fields=[field])
        capabilities = [(history_query, _history_catalog_entry(topic))]
        remaining = [name for name in normalized["fields"] if name != field]
        if remaining:
            primary_query = dict(deepcopy(normalized), fields=remaining)
            primary_query["parameters"] = {key: value for key, value in normalized["parameters"].items()
                                           if key not in {"after_event_id", "limit"}}
            reader = getattr(self.primary, "query_capabilities", None)
            if callable(reader):
                capabilities.extend(reader(primary_query))
            else:
                catalog = {item["topic_id"]: item for item in self.primary.catalog()}
                capabilities.append((primary_query, catalog[topic]))
        return capabilities

    @staticmethod
    def _retained_record_capability(query, entry):
        """An unselected event report cannot be scheduled as a new-event poll."""
        if (query.get("topic") == "B04" and entry.get("source") == "BattleObservationAdapter"
                and not query.get("parameters", {}).get("event_id")):
            entry = deepcopy(entry)
            entry["triggers"] = [value for value in entry.get("triggers", []) if value != "periodic"]
        return entry

    def change_comparison(self, query, sample, context):
        # No battle partial record opts in; ordinary source owners retain their scopes.
        return self.reads.change_comparison(deepcopy(query), deepcopy(sample), deepcopy(context))

    def validate_event_filter(self, event_filter):
        if EVENT_TYPE in event_filter.get("types", []) and any(key in event_filter for key in ("actors", "recipients")):
            raise InformationError("unsupported_event_filter", "Battle observations do not establish actor/recipient roles")
        validator = getattr(self.primary, "validate_event_filter", None)
        if callable(validator):
            validator(event_filter)

    def read(self, query, context):
        topic = query.get("topic") if isinstance(query, dict) else None
        if topic in _FIELDS or (topic in _HISTORY_FIELDS and _HISTORY_FIELDS[topic] in query.get("fields", [])):
            self._refresh(context)
        if isinstance(query, dict) and query.get("topic") in _HISTORY_FIELDS:
            if _HISTORY_FIELDS[query["topic"]] not in query.get("fields", []):
                return self.primary.read(query, context)
            normalized = self.battles.validate_history_query(query)
            history_fields = {_HISTORY_FIELDS[normalized["topic"]]}
            primary_fields = [field for field in normalized["fields"] if field not in history_fields]
            if not primary_fields:
                return self.battles.read_history(normalized, context)
            primary_query = deepcopy(normalized)
            primary_query["fields"] = primary_fields
            primary_query["parameters"] = {
                key: value for key, value in normalized["parameters"].items()
                if key not in {"after_event_id", "limit"}
            }
            validator = getattr(self.primary, "validate_query", None)
            if callable(validator):
                primary_query = validator(primary_query)
            primary_sample = self.primary.read(primary_query, context)
            if not isinstance(primary_sample, dict):
                raise InformationError("invalid_source_result", "Primary result must be an object")
            history_sample = self.battles.read_history(normalized, context)
            primary_result_fields = primary_sample.get("fields", {})
            history_result_fields = history_sample.get("fields", {})
            merged_fields = {
                field: deepcopy(history_result_fields[field]) if field in history_result_fields else
                deepcopy(primary_result_fields.get(field, {"status": "unknown", "reason": "field_missing"}))
                for field in normalized["fields"]
            }
            result = dict(history_sample)
            result["query"] = normalized
            result["fields"] = merged_fields
            result["objects"] = [deepcopy(normalized["object"])]
            result["complete"] = bool(primary_sample.get("complete") is True and history_sample.get("complete") is True)
            result["source"] = {"name": "BattleInformationSource", "complete": False,
                                 "primary": deepcopy(primary_sample.get("source", {})),
                                 "battle": deepcopy(history_sample.get("source", {}))}
            return result
        return self.reads.read(query, context)

    def read_event(self, query, context, event):
        if isinstance(query, dict) and query.get("topic") in _HISTORY_FIELDS:
            # A history query is a durable page read.  Do not trust an event
            # payload that bypasses the committed stream or its scope guard.
            return self.read(query, context)
        if query.get("topic") in _FIELDS:
            self._refresh(context)
        return self.reads.read_event(query, context, event)

    def replay_event(self, query, context, event):
        """Rebuild projections strictly from retained battle records."""
        topic = query.get("topic") if isinstance(query, dict) else None
        if topic in _FIELDS:
            # The safe CompositeSource replay view routes B01-B04 to the
            # adapter's explicit durable-record replay hook. It never calls
            # this wrapper's _refresh or any ordinary read fallback.
            return self.reads.replay_event(query, context, event)

        history_field = _HISTORY_FIELDS.get(topic)
        if history_field is not None and history_field in query.get("fields", []):
            normalized = self.battles.validate_history_query(query)
            history_query = dict(deepcopy(normalized), fields=[history_field])
            history_sample = self.battles.read_history(history_query, context)
            primary_fields = [field for field in normalized["fields"] if field != history_field]
            if not primary_fields:
                history_sample["query"] = deepcopy(normalized)
                return history_sample

            primary_query = deepcopy(normalized)
            primary_query["fields"] = primary_fields
            primary_query["parameters"] = {
                key: value for key, value in normalized["parameters"].items()
                if key not in {"after_event_id", "limit"}
            }
            validator = getattr(self.primary, "validate_query", None)
            if callable(validator):
                primary_query = validator(primary_query)
            replay = getattr(self.primary, "replay_event", None)
            primary_sample = (
                replay(deepcopy(primary_query), deepcopy(context), deepcopy(event))
                if callable(replay) else unknown_event_projection(primary_query, self.primary)
            )
            if not isinstance(primary_sample, dict):
                raise InformationError("invalid_source_result", "Replay result must be an object")
            primary_result_fields = primary_sample.get("fields", {})
            history_result_fields = history_sample.get("fields", {})
            merged_fields = {
                field: deepcopy(history_result_fields[history_field]) if field == history_field else
                deepcopy(primary_result_fields.get(field, {
                    "status": "unknown", "reason": "EVENT_PROJECTION_INTERRUPTED_NOT_REPLAYED",
                }))
                for field in normalized["fields"]
            }
            result = deepcopy(history_sample)
            result["query"] = deepcopy(normalized)
            result["fields"] = merged_fields
            result["objects"] = [deepcopy(normalized["object"])]
            result["complete"] = bool(
                primary_sample.get("complete") is True and history_sample.get("complete") is True
            )
            result["source"] = {
                "name": "BattleInformationSource", "complete": False,
                "primary": deepcopy(primary_sample.get("source", {})),
                "battle": deepcopy(history_sample.get("source", {})),
            }
            return result

        replay = getattr(self.primary, "replay_event", None)
        if callable(replay):
            return replay(deepcopy(query), deepcopy(context), deepcopy(event))
        return unknown_event_projection(query, self.primary)

    def poll_events(self, context, cursor):
        self._refresh(context)
        cursor = cursor if isinstance(cursor, dict) else {}
        batches = {}
        for name, source in (("primary", self.primary), ("battle", self.battles)):
            if name == "battle" and self.capture_manager is not None:
                capture = self.capture_status()
                if not capture.get("consumer_count"):
                    # Other event types must not drain a paused battle stream.
                    batches[name] = {"events": [], "cursor": cursor.get(name),
                                     "complete": True, "gaps": []}
                    continue
                if capture.get("producer_state") != "enabled":
                    batches[name] = {"events": [], "cursor": cursor.get(name), "complete": False,
                                     "gaps": [{"reason": "BATTLE_CAPTURE_UNAVAILABLE",
                                               "code": capture.get("reason")} ]}
                    continue
            try:
                batches[name] = source.poll_events(context, cursor.get(name))
            except Exception:
                batches[name] = {"events": [], "cursor": cursor.get(name), "complete": False,
                                 "gaps": [{"reason": f"{name.upper()}_EVENT_SOURCE_UNAVAILABLE"}]}
        if self.last_ingest_error:
            batches["battle"].setdefault("gaps", []).append({"reason": "BATTLE_INGEST_FAILED",
                                                            "code": self.last_ingest_error})
            batches["battle"]["complete"] = False
        return {"events": batches["primary"]["events"] + batches["battle"]["events"],
                "cursor": {name: batch.get("cursor") for name, batch in batches.items()},
                "complete": all(batch.get("complete") is True for batch in batches.values()),
                "gaps": [dict(gap, stream=name) for name, batch in batches.items()
                         for gap in batch.get("gaps", [])]}
