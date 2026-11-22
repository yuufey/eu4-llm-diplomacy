"""Field-level catalog for the read-only information sources.

Topic registration is deliberately separate from field availability. A
planned topic may be discovered by an LLM while a source reports every
requested field as unsupported until a real adapter exists.
"""
from __future__ import annotations

from copy import deepcopy
import re
from typing import Any

from .model import InformationError, canonical


# The adapter in this module is validated against the 1.37.4
# DiplomacyTools projection.  A different executable may be identified by a
# source, but it is not advertised as query-compatible until its projection
# has its own evidence.
SUPPORTED_VERSIONS = ("1.37.4",)
_COUNTRY = r"^[A-Z0-9]{3}$"
_ID = r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$"

_OBJECT_SCHEMAS = {
    "session": {"type": "object",
        "properties": {"type": {"type": "string", "const": "session"},
                       "session_id": {"type": "string", "pattern": _ID}},
        "required": ["type"], "additionalProperties": False},
    "country": {"type": "object",
        "properties": {"type": {"type": "string", "const": "country"},
                       "country": {"type": "string", "pattern": _COUNTRY}},
        "required": ["type"], "additionalProperties": False},
    "country_pair": {"type": "object",
        "properties": {"type": {"type": "string", "const": "country_pair"},
                       "actor": {"type": "string", "pattern": _COUNTRY},
                       "recipient": {"type": "string", "pattern": _COUNTRY}},
        "required": ["type"], "additionalProperties": False},
    "war": {"type": "object",
        "properties": {"type": {"type": "string", "const": "war"},
                       "war_id": {"type": "string", "pattern": _ID},
                       "actor": {"type": "string", "pattern": _COUNTRY},
                       "recipient": {"type": "string", "pattern": _COUNTRY}},
        "required": ["type"], "additionalProperties": False},
    "province": {"type": "object",
        "properties": {"type": {"type": "string", "const": "province"},
                       "province_id": {"type": "integer", "minimum": 0}},
        "required": ["type"], "additionalProperties": False},
    "trade_node": {"type": "object",
        "properties": {"type": {"type": "string", "const": "trade_node"},
                       "node_id": {"type": "string", "pattern": _ID}},
        "required": ["type"], "additionalProperties": False},
    "battle": {"type": "object",
        "properties": {"type": {"type": "string", "const": "battle"}},
        "required": ["type"], "additionalProperties": False},
}

_PARAMETERS = {
    "type": "object",
    "properties": {
        "action_id": {"type": "string", "pattern": _ID},
        "actor": {"type": "string", "pattern": _COUNTRY},
        "recipient": {"type": "string", "pattern": _COUNTRY},
        "phase": {"type": "string", "enum": ["query", "initiate", "accept", "reject", "withdraw"]},
        "request_id": {"type": "string", "pattern": _ID},
        "proposal_id": {"type": "string", "pattern": _ID},
        "fresh_pending": {"type": "boolean"},
        "war_id": {"type": "string", "pattern": _ID},
        "country": {"type": "string", "pattern": _COUNTRY},
        "province_id": {"type": "integer", "minimum": 0},
        "node_id": {"type": "string", "pattern": _ID},
        "kind": {"type": "string", "enum": ["gold", "trust", "men", "peace", "war_score"]},
        "direction": {"type": "string", "enum": ["demand", "offer"]},
        "insult_id": {"type": "integer", "minimum": 0},
        "selection": {"type": "object", "additionalProperties": True},
        "terms": {"type": "array", "items": {"type": "object", "additionalProperties": True}},
        "peace_context": {"type": "object", "additionalProperties": True},
        "event_type": {"type": "string", "pattern": _ID},
        "case": {"type": "string", "pattern": _ID},
        "limit": {"type": "integer", "minimum": 1, "maximum": 1000},
        "cursor": {"type": "string", "pattern": _ID},
        "casus_belli": {"type": "string", "pattern": _ID},
        "war_goal": {"type": "string", "pattern": _ID},
        "beneficiary": {"type": "string", "pattern": _COUNTRY},
        "ducats": {"type": "integer", "minimum": 0},
        "amount_raw": {"type": "integer", "minimum": 0},
        "diplomat_id": {"type": "integer", "minimum": 0},
        "province_ids": {"type": "array", "items": {"type": "integer", "minimum": 0}},
        "country_ids": {"type": "array", "items": {"type": "string", "pattern": _COUNTRY}},
    },
    "additionalProperties": False,
}

_R05_KIND_ACTIONS = {
    "trust": "trade_favors_for_trust",
    "men": "trade_favors_for_men",
    "gold": "trade_favors_for_gold",
}


def _field(name: str, *, coverage: str = "planned", paths: tuple[str, ...] = (),
           unit: str | None = None, scale: int | float | str | None = None,
           direction: str | None = None,
           description: str | None = None,
           source: str | None = None) -> dict:
    value = {"description": description or name.replace("_", " "), "coverage": coverage}
    if paths:
        value["paths"] = list(paths)
    if unit is not None:
        value["unit"] = unit
    if scale is not None:
        value["scale"] = scale
    if direction is not None:
        value["direction"] = direction
    if source is not None:
        value["source"] = source
    return value


# id, title, fields, accepted objects, topic status, source, visibility, triggers
_SPECS = [
("C01","决策背景与当前会话","session_id game_date game_day observer game_version game_sha256 dll_sha256 world_id paused status","session","available","ObserverSession.health","observer","query"),
("C02","已发现国家、省份及相关国家集合","discovered_countries discovered_provinces related_countries","session country","planned","not_implemented","visible_scope","query"),
("C03","战略目标、外交限制与待回应事项","strategic_goals diplomatic_constraints pending_matters","session","planned","not_implemented","input_or_unknown","query"),
("C04","重要局势变化","event_id event_type event_date event_objects event_payload complete","session","available","DurableJournal","recorded","query event change"),
("N01","本国财政","treasury monthly_income monthly_expenses monthly_balance loans war_income","country","planned","not_implemented","country_scope","query"),
("N02","本国军队与人力","army_size navy_size army_composition navy_composition manpower max_manpower sailors max_sailors force_limits","country","planned","not_implemented","country_scope","query"),
("N03","本国军事质量","military_technology morale discipline army_tradition professionalism military_modifiers","country","planned","not_implemented","country_scope","query"),
("N04","本国国内压力","stability war_exhaustion overextension unrest corruption religious_unity","country","planned","not_implemented","country_scope","query"),
("N05","本国外交官与关系容量","diplomats_total diplomats_available diplomat_tasks relations_count relations_limit","country","planned","not_implemented","country_scope","query"),
("N06","本国点数与外交负担","monarch_points diplomatic_reputation prestige integrating governance_capacity","country","planned","not_implemented","country_scope","query"),
("N07","本国当前修正","modifier_id name description source target effects","country province","planned","not_implemented","country_scope","query"),
("N08","修正期限与持续条件","modifier_start_date modifier_end_date remaining_days duration_type removal_conditions","country province","planned","not_implemented","country_scope","query"),
("N09","修正效果与最终属性","modifier_effects effective_status source_breakdown final_value","country province","planned","not_implemented","country_scope","query"),
("F01","外国实力规模","development territory subject_scale major_power wars","country","planned","not_implemented","visible_scope","query"),
("F02","外国可见军力","visible_army visible_navy military_technology manpower military_quality visibility","country","planned","not_implemented","visible_scope","query"),
("F03","外国经济承受能力","income debt bankruptcy_risk reparations subsidies","country","planned","not_implemented","visible_scope","query"),
("F04","外国压力与继承风险","war_exhaustion unrest occupied subject_loyalty succession_risk","country","planned","not_implemented","visible_scope","query"),
("R01","外交关系网","relation_type grantor recipient status expires_at","country_pair","planned","not_implemented","visible_scope","query"),
("R02","宗主与属国关系","overlord subject subject_type confederation tribute permissions","country_pair country","planned","not_implemented","visible_scope","query"),
("R03","停战、战争、宿敌与包围网","truce_until wars rivals coalition_members targets","country_pair country","planned","not_implemented","visible_scope","query"),
("R04","双向好感","opinion opinion_modifiers decay end_date","country_pair","planned","not_implemented","visible_scope","query"),
("R05","信任与人情","trust favors_available favors_direction favor_tasks exchange_conditions","country_pair country","available","DiplomacyTools.inspect_diplomatic_action","visible_scope","query"),
("R06","AI 态度与公开关系倾向","ai_attitude history personality relationship_tendency","country_pair","planned","not_implemented","visible_scope","query"),
("R07","持续承诺","land_commitments war_commitments economic_support expiry source","country_pair war","planned","not_implemented","visible_scope","query"),
("M01","当前实际加载的任务树","task_id name description branches","country session","planned","not_implemented","country_scope","query"),
("M02","任务前置与状态","prerequisites unlock_conditions completion_status currently_completable condition_progress","country","planned","not_implemented","country_scope","query"),
("M03","任务具体目标条件","provinces regions countries control ownership cores subjects","country","planned","not_implemented","country_scope","query"),
("M04","任务奖励与后续解锁","rewards unlocks claims casus_belli trade_modifiers duration","country","planned","not_implemented","country_scope","query"),
("M05","任务链与候选扩张方案","linked_targets reward_timing costs basis","country","planned","not_implemented","analysis","query"),
("G01","核心、宣称与战略目标","cores claims permanent_claims task_targets strategic_targets","country province","planned","not_implemented","visible_scope","query"),
("G02","省份状态与资源","owner controller development culture religion autonomy center_of_trade resource","province","planned","not_implemented","visible_scope","query"),
("G03","地理与通行条件","bordering distance straits island land_connection access fort supply","province country_pair","planned","not_implemented","visible_scope","query"),
("G04","领土与贸易节点关系","trade_node ports transfer_relations","province trade_node","planned","not_implemented","visible_scope","query"),
("G05","公开领土兴趣","country interests conflicts visibility","country_pair province","planned","not_implemented","visible_scope","query"),
("T01","贸易节点网络","node_id name provinces upstream downstream routes","trade_node","planned","not_implemented","visible_scope","query"),
("T02","本埠与贸易收集路线","home_node collect_node upstream leak_direction routes","country trade_node","planned","not_implemented","visible_scope","query"),
("T03","节点贸易价值","local_value incoming_value total_value outgoing_value collected_value","trade_node","planned","not_implemented","visible_scope","query"),
("T04","贸易竞争力与份额","country_power total_power shares sources","trade_node","planned","not_implemented","visible_scope","query"),
("T05","贸易收集、转移与收入","collection transfer merchant_task steering_direction income","country trade_node","planned","not_implemented","visible_scope","query"),
("T06","贸易扩张与外交收益","targets expected_trade assumptions costs","country province trade_node","planned","not_implemented","analysis","query"),
("D01","可用宣战理由","action_id target casus_belli beneficiary expiry war_goal","country_pair","available","DiplomacyTools.inspect_diplomatic_action","visible_scope","query"),
("D02","宣战合法性与成本","legality_status legality_reasons stability_cost war_exhaustion_cost other_costs","country_pair","available","DiplomacyTools.inspect_diplomatic_action","visible_scope","query"),
("D03","宣战参战方案","automatic_participants allies guarantors subjects co_belligerents","country_pair","available","DiplomacyTools.inspect_diplomatic_action","visible_scope","query"),
("D04","盟友参战意愿","ally willingness reasons favor_requirement land_promise_available","country_pair","available","DiplomacyTools.inspect_diplomatic_action","visible_scope","query"),
("D05","宣战阵营兵力与风险","attacker_forces defender_forces resource_comparison reachability risks","country_pair","available","DiplomacyTools.inspect_diplomatic_action","visible_scope","query"),
("D06","宣战理由与议和规则","allowed_terms forbidden_terms beneficiaries cost_rules","country_pair","available","DiplomacyTools.inspect_diplomatic_action","visible_scope","query"),
("W01","战争身份与参战名单","war_id leaders participants join_dates co_belligerent_roles","war country_pair","available","ObserverSession.inspect_peace_contexts","visible_scope","query"),
("W02","战争分与战争目标","war_score war_score_sources war_goal_controller cumulative_goal_score duration","war country_pair","available","DiplomacyTools.inspect_diplomatic_action","visible_scope","query"),
("W03","占领、封锁与战损","occupations blockades battle_losses current_forces reinforcement_change","war country session","planned","not_implemented","visible_scope","query"),
("W04","战争承受能力与贡献","war_exhaustion contribution land_commitment exit_risk","war country","planned","not_implemented","visible_scope","query"),
("B01","逐场战役身份","event_id war_id battle_type name location end_date sides commanders winner","war battle","planned","battle result observer","event_scope","event"),
("B02","逐场战役数量与损失","initial_forces losses remaining_forces unit_breakdown","battle","planned","battle result observer","event_scope","event"),
("B03","逐场战役结果效果","annihilation retreat ships_captured war_score prestige army_tradition naval_tradition war_exhaustion","battle","planned","battle result observer","event_scope","event"),
("B04","逐场战役完整结果文本","raw_text details record_order deduplication completeness gaps","battle","planned","battle result observer","event_scope","event"),
("P01","当前战争可用和约条款","war_id terms candidates beneficiaries scope","war country_pair","available","DiplomacyTools.inspect_diplomatic_action","visible_scope","query"),
("P02","和约合法性与成本","legality_status war_score_cost war_score_limit term_compatibility rejection_reasons","war country_pair","available","DiplomacyTools.inspect_diplomatic_action","visible_scope","query"),
("P03","对方接受度预览","acceptance_status acceptance_total acceptance_threshold acceptance_factors acceptance_complete","war country_pair","available","DiplomacyTools.inspect_diplomatic_action","visible_scope","query"),
("P04","和约后果预览","consequences territorial_changes money_changes relation_changes subject_changes","war country_pair","available","DiplomacyTools.inspect_diplomatic_action","visible_scope","query"),
("P05","和约扩张成本","overextension affected_countries coalition core_admin_points unjustified_diplomatic_points","war country_pair","available","DiplomacyTools.inspect_diplomatic_action","visible_scope","query"),
("P06","和约持续义务与后续条件","new_truce obligations integration_conditions restart_conditions","war country_pair","planned","not_implemented","visible_scope","query"),
("A01","日常外交行动与合法性","action_id actor recipient phase legality_status legality_reasons costs diplomat_required cooldown","country_pair","available","DiplomacyTools.inspect_diplomatic_action","visible_scope","query"),
("A02","具体外交行动接受意愿","acceptance_status acceptance_total acceptance_threshold acceptance_factors acceptance_complete","country_pair","available","DiplomacyTools.inspect_diplomatic_action","visible_scope","query"),
("A03","经济与人情外交预览","parameters costs duration resource_direction relation_effects acceptance_status","country_pair","available","DiplomacyTools.inspect_diplomatic_action","visible_scope","query"),
("A04","外来提议","proposal_id action_id actor recipient phase proposal_status currently_pending parameters deadline response_consequences","country_pair session","available","ObserverSession.read_native_alliance_inbound_offers","decision_country","query"),
("A05","本国请求的实际回应与结果","request_id action_id status submitted game_outcome result evidence updated_at","country_pair session","available","DurableJournal","journal","query event change"),
("S01","神圣罗马帝国机制","empire_status emperor electors intervention religious_leagues reforms","country session","planned","not_implemented","visible_scope","query"),
("S02","宗教与教廷机制","religion_group faith defender papacy schools mechanics","country session","planned","not_implemented","visible_scope","query"),
("S03","属国忠诚与义务","liberty_desire loyalty support_independence tribute levy integration","country_pair country","planned","not_implemented","visible_scope","query"),
("S04","统治者、继承人与共主邦联","ruler heir dynasty succession_dispute personal_union","country country_pair","planned","not_implemented","visible_scope","query"),
("S05","特殊外交机制","great_power_intervention trade_league tributary colonial_nation government_mechanics","country session","planned","not_implemented","visible_scope","query"),
("H01","历史快照与逐场战报序列","snapshot_changes relationship_changes military_changes war_score_changes resource_changes battle_sequence","session country war","available","DurableJournal","recorded","query event change"),
("H02","到期事件与修正生命周期","truce_expiry claim_expiry cooldown_expiry subsidy_expiry modifier_lifecycle proposal_expiry","session country country_pair","available","DurableJournal","recorded","query periodic event change"),
("H03","威胁、机会与候选方案推算","threats opportunities candidates inputs uncertainty","session country","planned","not_implemented","analysis","query"),
("H04","既有判断、承诺与实际结果差异","judgement commitments actual_results differences decision_source","session country_pair","planned","project_record","project_record","query"),
]

_PATHS = {
    "C01": {key: (key,) for key in "session_id game_date game_day observer game_version game_sha256 dll_sha256 world_id paused status".split()},
    "C04": {"event_id": ("event_id",), "event_type": ("event_type",), "event_date": ("game_date", "date_raw"), "event_objects": ("objects",), "event_payload": ("payload",), "complete": ("complete",)},
    # The native inspection payload uses ``native_favor_trade``.  The shorter
    # aliases are retained for normalized adapter payloads and older archives.
    "R05": {
        # Prefer the public projection when present.  The raw aliases are
        # retained for recorded native query fixtures and are explicitly
        # marked below with their scale.
        "trust": ("trust", "favor_trade.trust.value", "favor_trade.trust.raw",
                   "native_favor_trade.recipient_trust_raw",
                   "favor_trade.recipient_trust_raw"),
        "favors_available": (
            "favors_available", "favor_trade.favors.current_raw",
            "native_favor_trade.favors_available_raw",
            "favor_trade.favors_available_raw",
        ),
        # ``kind`` identifies the exchange resource (trust/men/gold); it does
        # not identify who holds the bilateral favors.  A direction is known
        # only when a source publishes that relationship explicitly.
        "favors_direction": (
            "favors_direction", "favor_trade.favors.direction",
            "native_favor_trade.favors_direction",
            "favor_trade.favors_direction",
        ),
        "favor_tasks": ("favor_tasks",),
        "exchange_conditions": ("exchange_conditions",),
    },
    "D01": {"action_id": ("action_id",), "target": ("recipient",), "casus_belli": ("parameters.actual.casus_belli", "casus_belli"), "beneficiary": ("parameters.actual.beneficiary", "beneficiary", "parameters.actual.war_goal.beneficiary"), "expiry": ("parameters.actual.expiry", "expiry"), "war_goal": ("war_context.goal", "war_goal", "parameters.actual.war_goal")},
    "D02": {"legality_status": ("legality.status",), "legality_reasons": ("legality.reasons",), "stability_cost": ("costs.stability", "costs.stability_cost"), "war_exhaustion_cost": ("costs.war_exhaustion", "costs.war_exhaustion_cost")},
    "D03": {"automatic_participants": ("participants.automatic", "war_context.participants.automatic"), "allies": ("participants.allies", "war_context.participants.allies"), "guarantors": ("participants.guarantors",), "subjects": ("participants.subjects",), "co_belligerents": ("participants.co_belligerents",)},
    "D04": {"ally": ("participants.ally", "participants.candidates"), "willingness": ("participants.willingness", "participants.candidates"), "reasons": ("participants.reasons", "participants.candidates"), "favor_requirement": ("participants.favor_requirement",), "land_promise_available": ("participants.land_promise_available", "participants.candidates")},
    "D05": {"attacker_forces": ("forces.attacker", "war_context.forces.attacker", "forces.attackers"), "defender_forces": ("forces.defender", "war_context.forces.defender", "forces.defenders"), "resource_comparison": ("forces.resources",), "reachability": ("reachability",), "risks": ("risks",)},
    "D06": {"allowed_terms": ("peace_rules.allowed_terms", "war_context.allowed_terms"), "forbidden_terms": ("peace_rules.forbidden_terms", "peace_term_rules.disabled.disabled_actions"), "beneficiaries": ("peace_rules.beneficiaries",), "cost_rules": ("peace_rules.cost_rules",)},
    "W01": {"war_id": ("war_context.war_id", "war_id"), "leaders": ("war_context.leaders",), "participants": ("war_context.participants",), "join_dates": ("war_context.join_dates",), "co_belligerent_roles": ("war_context.roles",)},
    "W02": {
        "war_score": ("war_context.war_score", "war_score"),
        "war_score_sources": ("war_context.war_score_sources",),
        "war_goal_controller": ("war_context.goal_controller",),
        # The live score adapter publishes a metric object here.  Keep the
        # older aggregate aliases only as recorded-source fallbacks; callers
        # must not infer a goal score from an unrelated sibling field.
        "cumulative_goal_score": (
            "war_context.war_score.goal.cumulative",
            "war_context.goal_score",
            "score.goal.cumulative_raw",
        ),
        "duration": ("war_context.duration",),
    },
    "P01": {"war_id": ("peace_context.war_id", "war_context.war_id"), "terms": ("peace_context.terms", "terms"), "candidates": ("peace_context.candidates", "candidates"), "beneficiaries": ("peace_context.beneficiaries",), "scope": ("peace_context.scope",)},
    "P02": {"legality_status": ("legality.status", "peace_context.legality.status"), "war_score_cost": ("peace_context.costs.war_score", "costs.war_score"), "war_score_limit": ("peace_context.costs.war_score_limit", "costs.war_score_limit"), "term_compatibility": ("peace_context.term_compatibility",), "rejection_reasons": ("legality.reasons", "peace_context.rejection_reasons")},
    "P03": {"acceptance_status": ("acceptance.predicted_response", "acceptance.status"), "acceptance_total": ("acceptance.native_total", "acceptance.total"), "acceptance_threshold": ("acceptance.acceptance_threshold", "acceptance.threshold"), "acceptance_factors": ("acceptance.items", "acceptance.factors"), "acceptance_complete": ("acceptance.details_complete", "acceptance.complete")},
    "P04": {"consequences": ("peace_context.consequences", "consequences", "peace_consequences"), "territorial_changes": ("peace_context.territorial_changes", "peace_consequences.territorial"), "money_changes": ("peace_context.money_changes",), "relation_changes": ("peace_context.relation_changes",), "subject_changes": ("peace_context.subject_changes",)},
    "P05": {"overextension": ("peace_context.overextension", "consequences.overextension", "peace_consequences.overextension"), "affected_countries": ("peace_context.affected_countries",), "coalition": ("peace_context.coalition", "peace_consequences.coalition"), "core_admin_points": ("peace_context.core_admin_points",), "unjustified_diplomatic_points": ("peace_context.unjustified_diplomatic_points",)},
    "A01": {"action_id": ("action_id",), "actor": ("actor",), "recipient": ("recipient",), "phase": ("phase",), "legality_status": ("legality.status",), "legality_reasons": ("legality.reasons",), "costs": ("costs",), "diplomat_required": ("diplomat_required", "resources.diplomats.native_requirement", "native_rule_components.diplomat_required"), "cooldown": ("cooldown", "parameters.actual.cooldown")},
    "A02": {"acceptance_status": ("acceptance.predicted_response", "acceptance.status"), "acceptance_total": ("acceptance.native_total", "acceptance.total"), "acceptance_threshold": ("acceptance.acceptance_threshold", "acceptance.threshold"), "acceptance_factors": ("acceptance.items", "acceptance.factors"), "acceptance_complete": ("acceptance.details_complete", "acceptance.complete")},
    "A03": {"parameters": ("parameters.actual",), "costs": ("costs",), "duration": ("duration", "parameters.actual.duration"), "resource_direction": ("resource_direction",), "relation_effects": ("relation_effects",), "acceptance_status": ("acceptance.predicted_response", "acceptance.status")},
    "A04": {"proposal_id": ("proposal_id",), "action_id": ("action_id",), "actor": ("actor",), "recipient": ("recipient",), "phase": ("phase",), "proposal_status": ("observer_status", "proposal_status"), "currently_pending": ("currently_pending",), "parameters": ("parameters",), "deadline": ("deadline",), "response_consequences": ("response_consequences",)},
    "A05": {"request_id": ("request_id",), "action_id": ("action_id", "payload.action_id"), "status": ("status",), "submitted": ("submitted",), "game_outcome": ("game_outcome",), "result": ("result",), "evidence": ("evidence",), "updated_at": ("updated_at",)},
    "H01": {"snapshot_changes": ("payload.snapshot_changes",), "relationship_changes": ("payload.relationship_changes",), "military_changes": ("payload.military_changes",), "war_score_changes": ("payload.war_score_changes",), "resource_changes": ("payload.resource_changes",), "battle_sequence": ("payload.battle_sequence",)},
    "H02": {"truce_expiry": ("payload.truce_expiry",), "claim_expiry": ("payload.claim_expiry",), "cooldown_expiry": ("payload.cooldown_expiry",), "subsidy_expiry": ("payload.subsidy_expiry",), "modifier_lifecycle": ("payload.modifier_lifecycle",), "proposal_expiry": ("payload.proposal_expiry",)},
}

_PARTIAL = {
    "C01": {"game_day", "game_version", "game_sha256", "dll_sha256", "world_id", "paused"},
    "C04": {"event_date", "event_objects", "event_payload"},
    "R05": {"trust", "favors_available", "favors_direction", "favor_tasks", "exchange_conditions"},
    "D01": {"casus_belli", "beneficiary", "expiry", "war_goal"},
    "D02": {"stability_cost", "war_exhaustion_cost", "other_costs"},
    "D03": {"automatic_participants", "allies", "guarantors", "subjects", "co_belligerents"},
    "D04": {"ally", "willingness", "reasons", "favor_requirement", "land_promise_available"},
    "D05": {"attacker_forces", "defender_forces", "resource_comparison", "reachability", "risks"},
    "D06": {"allowed_terms", "forbidden_terms", "beneficiaries", "cost_rules"},
    "W01": {"leaders", "participants", "join_dates", "co_belligerent_roles"},
    "W02": {"war_score", "war_score_sources", "war_goal_controller", "cumulative_goal_score", "duration"},
    "P01": {"war_id", "candidates", "beneficiaries", "scope"},
    "P02": {"war_score_cost", "war_score_limit", "term_compatibility"},
    "P03": {"acceptance_total", "acceptance_threshold", "acceptance_factors"},
    "P04": {"consequences", "territorial_changes", "money_changes", "relation_changes", "subject_changes"},
    "P05": {"overextension", "affected_countries", "coalition", "core_admin_points", "unjustified_diplomatic_points"},
    "A01": {"diplomat_required", "cooldown"},
    "A02": {"acceptance_total", "acceptance_threshold", "acceptance_factors"},
    "A03": {"duration", "resource_direction", "relation_effects", "acceptance_status"},
    "A04": {"parameters", "proposal_status", "currently_pending", "deadline", "response_consequences"}, "A05": {"result", "evidence"},
    "H01": {"snapshot_changes", "relationship_changes", "military_changes", "war_score_changes", "resource_changes", "battle_sequence"},
    "H02": {"truce_expiry", "claim_expiry", "cooldown_expiry", "subsidy_expiry", "modifier_lifecycle"},
}


def _build_catalog() -> list[dict]:
    # Parameters are topic-scoped.  The shared base above documents the
    # primitive shapes; this allow-list prevents a query from accepting a
    # parameter which the adapter would then ignore.
    parameter_keys = {
        "R05": {"action_id", "kind", "phase"},
        **{topic: {
            "action_id", "phase", "selection", "terms", "war_id",
            "casus_belli", "war_goal", "beneficiary", "province_ids",
            "country_ids",
        } for topic in ("D01", "D02", "D03", "D04", "D05", "D06")},
        "W01": {"action_id", "phase", "war_id"},
        "W02": {"action_id", "phase", "war_id", "peace_context"},
        **{topic: {
            "action_id", "phase", "selection", "terms", "war_id",
            "beneficiary", "province_ids", "country_ids", "peace_context",
        } for topic in ("P01", "P02", "P03", "P04", "P05")},
        **{topic: {
            "action_id", "phase", "selection", "terms", "direction",
            "insult_id", "ducats", "amount_raw", "diplomat_id",
        } for topic in ("A01", "A02", "A03")},
        "A04": {"proposal_id", "phase", "event_type", "fresh_pending"},
        "A05": {"request_id", "event_type"},
        "C04": {"request_id", "event_type", "case"},
        "H01": {"request_id", "event_type", "case"},
        "H02": {"request_id", "event_type", "case", "limit", "cursor"},
    }
    parameter_keys["A01"].add("proposal_id")
    parameter_keys["A03"].add("proposal_id")

    def parameters_for(topic_id: str, status: str) -> dict:
        keys = parameter_keys.get(topic_id, set()) if status == "available" else set()
        properties = {}
        for key in sorted(keys):
            if topic_id.startswith("D") and key == "selection":
                participants = {"type": "array", "items": {"type": "string", "pattern": r"[A-Z]{3}"}}
                properties[key] = {
                    "type": "object",
                    "description": "具体宣战方案的只读预览参数，复用外交接口的CB、战争目标与参战选择合同",
                    "properties": {
                        "casus_belli": {"type": "string", "pattern": r"[A-Za-z0-9_]{1,128}"},
                        "war_goal": {
                            "type": "object",
                            "properties": {
                                "province_id": {"type": "integer", "minimum": -1, "maximum": 2147483647},
                                "beneficiary": {"type": "string", "pattern": r"(?:---|[A-Z]{3})"},
                            },
                            "required": ["province_id", "beneficiary"], "additionalProperties": False,
                        },
                        "call_allies": deepcopy(participants),
                        "promise_land_to": deepcopy(participants),
                        "co_belligerents": deepcopy(participants),
                    },
                    "required": ["casus_belli", "war_goal", "call_allies"], "additionalProperties": False,
                }
            elif topic_id == "W02" and key == "peace_context":
                # W02 is the read-only live score request.  It never carries
                # peace terms; an empty terms list is part of the native
                # query identity and prevents a selected peace action from
                # being mistaken for a score discovery request.
                properties[key] = {
                    "type": "object",
                    "properties": {
                        "war_id": {"type": "string", "pattern": _ID},
                        "direction": {
                            "type": "string", "enum": ["demand", "offer"],
                        },
                        "terms": {
                            "type": "array", "items": {
                                "type": "object", "additionalProperties": True,
                            }, "maxItems": 0,
                        },
                    },
                    "required": ["war_id", "direction", "terms"],
                    "additionalProperties": False,
                }
            else:
                properties[key] = deepcopy(_PARAMETERS["properties"][key])
        return {
            "type": "object",
            "properties": properties,
            "additionalProperties": False,
        }

    result = []
    field_metadata = {
        "A01": {
            "cooldown": {
                "description": (
                    "当前行动是否被外交等待期限阻止，及原生界面显示的可再次派遣日期；"
                    "识别中文、英文ENROUTE提示，通用动作条件通过时blocked=false"
                ),
            },
        },
        "W01": {
            "leaders": {
                "description": "当前本方与对方阵营的战争领袖，按our_side和opposing_side提供国家。",
            },
            "war_id": {
                "description": (
                    "session-scoped war identifier; use the unique candidate automatically, "
                    "but require objects.war_id when multiple candidates exist"
                ),
            },
        },
        "W02": {
            "war_score": {
                "description": (
                    "public war-score object with raw/value/unit/scale/mode/"
                    "perspective/complete; score direction remains the selected actor's view"
                ),
            },
            "cumulative_goal_score": {
                "description": (
                    "war-score goal cumulative metric object; preserve raw/value/unit/scale "
                    "and distinguish configured, inapplicable, and unknown goals"
                ),
            },
        },
        "D03": {
            "automatic_participants": {"description": "原生候选中automatic=true的国家及所属一侧。"},
            "allies": {"description": "当前预览call_allies已选国家及所属一侧，范围为selected_preview。"},
            "co_belligerents": {"description": "当前预览co_belligerents已选国家及所属一侧。"},
            "guarantors": {"description": "需要已证明的参战原因分类，缺少分类时保持未知。"},
            "subjects": {"description": "需要已证明的参战原因分类，缺少分类时保持未知。"},
        },
        "D04": {
            "ally": {"description": "宣战预览中的参战候选，按country列出side与automatic；保留旧单盟友值。"},
            "willingness": {"unit": "acceptance_points", "scale": 1,
                            "description": "按候选country对应的原生score与threshold。"},
            "reasons": {"description": "按候选country对应的原生原因值与文字。"},
            "land_promise_available": {"description": "按候选country对应的许诺土地可用性。"},
            "favor_requirement": {"description": "使用人情召集可选盟友且不许诺土地时的生效配置门槛，without_land_promise以人情计。旧原生或录制值优先。"},
        },
        "D06": {
            "allowed_terms": {"description": "CB为攻守方声明的正当条款及省份、国家、必需条约和吞并条件，declared_justified保留声明含义，具体和约合法性通过P01预览。"},
            "forbidden_terms": {"description": "CB禁用表中已明确的disabled_actions；表完整性在完整结果保留。"},
            "beneficiaries": {"description": "所选CB已枚举的战争目标受益国和目标省份，以及当前选择，按war_goal_candidates和selected_war_goal返回。"},
            "cost_rules": {"description": "所选CB的战争分数、侵略扩张及威望倍率，按攻守方列出适用条款与省份条件。具体和约费用沿原生预览读取。"},
        },
        "R05": {
            "trust": {
                "unit": "trust", "scale": 1,
                "description": "recipient 对 actor 的信任 (trust from recipient toward actor)",
            },
            "favors_available": {"unit": "favors_raw", "scale": 1000},
            "favors_direction": {"direction": "actor_holds_for_recipient"},
            "favor_tasks": {
                "unit": "task_state", "scale": 1,
                "direction": "actor_to_recipient",
                "description": "选定国家对中 actor→recipient 的当前获取人情任务状态；不枚举全网",
            },
        },
    }

    for topic_id, title, raw_fields, raw_objects, status, source, visibility, raw_triggers in _SPECS:
        fields = {}
        for field in raw_fields.split():
            coverage = "available" if status == "available" else "planned"
            if field in _PARTIAL.get(topic_id, set()):
                coverage = "partial"
            paths = _PATHS.get(topic_id, {}).get(field, ())
            if status == "available" and not paths:
                # A bare field name would make the adapter accept a payload
                # key without documenting how the source obtains it.  Keep
                # such fields visible in the topic while marking them as
                # planned until a concrete projection is evidenced.
                coverage = "planned"
            metadata = field_metadata.get(topic_id, {}).get(field, {})
            fields[field] = _field(
                field, coverage=coverage, paths=paths,
                unit=metadata.get("unit"), scale=metadata.get("scale"),
                direction=metadata.get("direction"),
                description=metadata.get("description"),
                source=source if paths else None,
            )
        triggers = raw_triggers.split()
        if status == "available":
            # A repeatable read is suitable for periodic snapshots and
            # sampled change detection.  Journal-backed readers additionally
            # preserve event pages.  A04's inbound reader is intentionally
            # advertised as sampled state; its poll method cannot claim a
            # lossless native event stream.
            for trigger in ("periodic", "change"):
                if trigger not in triggers:
                    triggers.append(trigger)
            if source == "DurableJournal" and "event" not in triggers:
                triggers.append("event")
        topic_result = {"topic_id": topic_id, "catalog_ids": [topic_id], "title": title,
                       "status": status, "fields": fields, "object_types": raw_objects.split(),
                       "parameters": parameters_for(topic_id, status),
                       "supported_versions": ["1.37.4"] if status == "available" else [],
                       "triggers": triggers, "source": source, "visibility": visibility}
        if topic_id == "W01":
            fields["leaders"].update(
                paths=["war_contexts[].participants.side_a[0]", "war_contexts[].participants.side_b[0]"],
                capability="native_war_participants_query",
                basis="native_current_side_leader_getter",
            )
            fields["participants"].update(
                description=("Selected war's complete native side_a/side_b country-tag lists and "
                             "actor/recipient side membership; side labels do not imply "
                             "attacker/defender, leadership, join dates or co-belligerent roles"),
                paths=["war_contexts[].participants"],
                capability="native_war_participants_query",
            )
            topic_result["object_requirements"] = {
                "country_pair": {"required": ["actor", "recipient"]},
                "war": {"required": ["actor", "recipient"], "optional": ["war_id"]},
            }
            topic_result["war_selection"] = (
                "Use the unique war candidate in this session automatically; when "
                "multiple candidates exist, select objects.war_id explicitly. "
                "A complete zero-candidate enumeration is not applicable."
            )
        if topic_id == "W02":
            war_id_sources = [
                "object.war_id",
                "parameters.war_id",
                "parameters.peace_context.war_id",
            ]
            topic_result["object_requirements"] = {
                "country_pair": {
                    "required": ["actor", "recipient"],
                    "war_id_required": True,
                    "war_id_sources": war_id_sources,
                },
                "war": {
                    "required": ["actor", "recipient"],
                    "war_id_required": True,
                    "war_id_sources": war_id_sources,
                },
            }
            topic_result["capability_required"] = "native_live_war_score_query"
            topic_result["war_selection"] = (
                "Use an explicit war_id from object.war_id, parameters.war_id, "
                "or parameters.peace_context.war_id; do not discover or guess a war."
            )
        if topic_id == "A05":
            topic_result["observer_roles"] = ["actor", "recipient"]
        if topic_id in ("A01", "A03"):
            topic_result["observer_roles_by_phase"] = {
                "accept": ["recipient"], "reject": ["recipient"]}
            topic_result["response_preview"] = {
                "phases": ["accept", "reject"], "required_parameter": "proposal_id",
                "binding": "original_observed_proposal", "read_only": True,
                "supported_versions": ["1.37.4"],
                "response_authority": False}
        if topic_id == "A04":
            # An inbound offer is visible to its recipient.  The actor may be
            # a foreign country and must not be treated as the local observer.
            topic_result["observer_roles"] = ["recipient"]
            topic_result["change_scope"] = {
                "fields": ["currently_pending"], "required_parameters": {"fresh_pending": True},
                "detection": "polling_selected_observed_proposal", "supported_modes": ["live"],
                "inactive_reason": "unknown",
            }
            topic_result["fields"]["currently_pending"].update(
                complete=False, unit="boolean", scale=1, period="current",
                description="按明确proposal_id和fresh_pending只读复查当前是否待处理；变化订阅沿配置间隔轮询。",
                supported_modes=["live"],
                current_state_parameter="fresh_pending")
            topic_result["fields"]["proposal_status"].update(
                complete=False, unit="proposal_state", scale=1,
                description="普通查询提供原提议观察状态；fresh_pending=true复查当前pending/inactive。已关联过期事件提供expired快照及观察日期。",
                current_state_parameter="fresh_pending",
                gaps=["CURRENT_PENDING_REQUIRES_EXPLICIT_FRESH_INSPECTION", "NATIVE_PENDING_SET_NOT_ENUMERATED"])
            topic_result["fields"]["parameters"].update(
                description="固定内容提议提供空参数；完整议和条款提供peace_context。显式fresh_pending可复用同次检查补取议和条款或人情交换的当前规则报价，保留资源数量、方向和人情价格。",
                current_state_parameter="fresh_pending")
            topic_result["fields"]["response_consequences"].update(
                description="按当前检查与既有响应合同推算人情资源或主要关系变化；支持独立方向另需原生双方宗属身份上下文。其它直接后果未知。",
                current_state_parameter="fresh_pending", complete=False,
                supported_actions=["trade_favors_for_gold", "trade_favors_for_trust", "trade_favors_for_men",
                                   "offer_alliance", "offer_royal_marriage", "ask_military_access", "offer_vassalization",
                                   "support_independence"],
                derived=True, response_authority=False)
            topic_result["fields"]["deadline"].update(
                unit="game_date_raw", scale=1, period="proposal",
                description="原生待办创建日期加3天的期限阈值，清理条件为当前日期严格大于该值；实际过期时间沿事件。",
                supported_modes=["live"],
                expiry_comparison="current_game_date > value",
                event_occurrence_date_derived=False)
        result.append(topic_result)
    return result


_CATALOG = _build_catalog()


def observer_roles_for_query(topic: dict, query: dict) -> list[str]:
    phase = query.get("parameters", {}).get("phase", "initiate")
    return topic.get("observer_roles_by_phase", {}).get(phase, topic.get("observer_roles", ["actor"]))


def _validate_schema(value: Any, schema: dict, path: str) -> None:
    if not isinstance(schema, dict):
        raise InformationError("invalid_catalog", f"{path}: schema must be an object")
    kind = schema.get("type")
    checks = {"object": isinstance(value, dict), "array": isinstance(value, list),
              "string": isinstance(value, str), "integer": type(value) is int,
              "number": type(value) in (int, float) and not isinstance(value, bool),
              "boolean": type(value) is bool}
    if kind not in checks or not checks[kind]:
        raise InformationError("invalid_parameters", f"{path} must be {kind}")
    if "const" in schema and value != schema["const"]:
        raise InformationError("invalid_parameters", f"{path} must equal {schema['const']!r}")
    if "enum" in schema and value not in schema["enum"]:
        raise InformationError("invalid_parameters", f"{path} is outside the allowed values")
    if kind == "object":
        properties = schema.get("properties", {})
        missing = set(schema.get("required", [])) - set(value)
        extra = set(value) - set(properties)
        if missing or (extra and schema.get("additionalProperties", False) is False):
            raise InformationError("invalid_parameters", f"{path}: missing={sorted(missing)}, unknown={sorted(extra)}")
        for key, child in value.items():
            if key in properties:
                _validate_schema(child, properties[key], f"{path}.{key}")
    elif kind == "array":
        if "minItems" in schema and len(value) < schema["minItems"]:
            raise InformationError("invalid_parameters", f"{path} has too few items")
        if "maxItems" in schema and len(value) > schema["maxItems"]:
            raise InformationError("invalid_parameters", f"{path} has too many items")
        for index, child in enumerate(value):
            _validate_schema(child, schema.get("items", {}), f"{path}[{index}]")
    elif kind == "string" and "pattern" in schema and re.fullmatch(schema["pattern"], value) is None:
        raise InformationError("invalid_parameters", f"{path} does not match its pattern")
    elif kind in ("integer", "number"):
        if "minimum" in schema and value < schema["minimum"]:
            raise InformationError("invalid_parameters", f"{path} is below minimum")
        if "maximum" in schema and value > schema["maximum"]:
            raise InformationError("invalid_parameters", f"{path} is above maximum")


def list_topics() -> list[dict]:
    return deepcopy(_CATALOG)


def catalog() -> list[dict]:
    return list_topics()


def get_topic(topic_id: str) -> dict:
    for topic in _CATALOG:
        if topic["topic_id"] == topic_id:
            return deepcopy(topic)
    raise InformationError("unknown_topic", f"Unknown information topic: {topic_id!r}")


def topic_ids() -> tuple[str, ...]:
    return tuple(topic["topic_id"] for topic in _CATALOG)


def coverage_report(source=None) -> dict:
    topics = source.catalog() if source is not None else list_topics()
    return {"schema_version": 1, "topic_count": len(topics),
            "field_count": sum(len(item["fields"]) for item in topics),
            "available_topics": [item["topic_id"] for item in topics if item["status"] == "available"],
            "topics": topics}


def validate_query(query: dict, context: dict | None = None) -> dict:
    if not isinstance(query, dict):
        raise InformationError("invalid_parameters", "query must be an object")
    allowed = {"topic", "object", "fields", "parameters"}
    missing = {"topic", "object", "fields"} - set(query)
    extra = set(query) - allowed
    if missing or extra:
        raise InformationError("invalid_parameters", f"query: missing={sorted(missing)}, unknown={sorted(extra)}")
    topic_id = query["topic"]
    if not isinstance(topic_id, str):
        raise InformationError("invalid_topic", "topic must be a string")
    topic = next((item for item in _CATALOG if item["topic_id"] == topic_id), None)
    if topic is None:
        raise InformationError("unknown_topic", f"Unknown information topic: {topic_id!r}")
    obj = query["object"]
    if not isinstance(obj, dict):
        raise InformationError("invalid_object", "object must be an object")
    object_type = obj.get("type")
    if object_type not in topic["object_types"]:
        raise InformationError("invalid_object", f"{topic_id} does not accept object type {object_type!r}")
    _validate_schema(obj, _OBJECT_SCHEMAS[object_type], "object")
    # Entity selectors are part of the object identity.  Keeping the type
    # alone would make a country-pair query silently depend on an arbitrary
    # current UI selection, and would weaken the observer scope boundary.
    if object_type == "country" and "country" not in obj:
        raise InformationError("invalid_object", "country object requires country")
    if object_type == "country_pair":
        if "actor" not in obj or "recipient" not in obj:
            raise InformationError("invalid_object", "country_pair requires actor and recipient")
        if obj["actor"] == obj["recipient"]:
            raise InformationError("invalid_object", "country_pair actor and recipient must differ")
    if object_type == "province" and "province_id" not in obj:
        raise InformationError("invalid_object", "province object requires province_id")
    if object_type == "trade_node" and "node_id" not in obj:
        raise InformationError("invalid_object", "trade_node object requires node_id")
    if object_type == "war" and not (
        "war_id" in obj or ("actor" in obj and "recipient" in obj)
    ):
        raise InformationError("invalid_object", "war object requires war_id or actor and recipient")
    fields = query["fields"]
    if not isinstance(fields, list) or not fields or any(not isinstance(item, str) for item in fields):
        raise InformationError("invalid_fields", "fields must be a non-empty list of strings")
    if len(set(fields)) != len(fields):
        raise InformationError("invalid_fields", "fields must not contain duplicates")
    unknown = set(fields) - set(topic["fields"])
    if unknown:
        raise InformationError("unknown_field", f"{topic_id}: unknown fields {sorted(unknown)}")
    parameters = query.get("parameters", {})
    _validate_schema(parameters, topic["parameters"], "parameters")
    if topic_id in ("A01", "A03"):
        phase = parameters.get("phase", "initiate")
        if phase in ("accept", "reject"):
            from ..diplomacy import _inbound_family
            if (set(parameters) - {"action_id", "phase", "proposal_id"}
                    or not isinstance(parameters.get("proposal_id"), str)
                    or re.fullmatch(r"[0-9a-f]{32}", parameters["proposal_id"]) is None
                    or _inbound_family(parameters.get("action_id")) is None):
                raise InformationError("invalid_parameters",
                    "Response preview requires an inbound action and its public proposal_id")
        elif "proposal_id" in parameters:
            raise InformationError("invalid_parameters", "proposal_id requires accept or reject phase")
    if topic_id == "A04" and parameters.get("fresh_pending") is True:
        if 'proposal_id' not in parameters or parameters.get('phase', 'initiate') != 'initiate':
            raise InformationError('invalid_parameters',
                'fresh_pending requires an explicit proposal_id and the observed initiate phase')
    if topic_id == "R05":
        kind = parameters.get("kind")
        action_id = parameters.get("action_id")
        expected_action = _R05_KIND_ACTIONS.get(kind)
        if expected_action is not None and action_id is not None and action_id != expected_action:
            raise InformationError(
                "invalid_parameters",
                "R05 kind selects a different action_id",
            )
    if context is not None:
        if not isinstance(context, dict):
            raise InformationError("invalid_context", "context must be an object")
        requested, current = obj.get("session_id"), context.get("session_id")
        if requested is not None and current is not None and requested != current:
            raise InformationError("context_mismatch", "query object belongs to another session")
        observer = context.get("observer")
        scope_checked = (
            context.get("mode") != "recorded"
            and topic.get("visibility") in {"visible_scope", "decision_country", "country_scope"}
        )
        roles = observer_roles_for_query(topic, {"parameters": parameters})
        observed_values = [
            obj.get(role, parameters.get(role)) for role in roles
            if obj.get(role, parameters.get(role)) is not None
        ]
        if (scope_checked and observed_values and isinstance(observer, str)
                and observer not in observed_values):
            raise InformationError("observer_scope_mismatch",
                                   "query is outside the observer scope")
    normalized = {"topic": topic_id, "object": deepcopy(obj), "fields": list(fields),
                  "parameters": deepcopy(parameters)}
    canonical(normalized)
    return normalized


if len(_CATALOG) != 74:
    raise RuntimeError(f"Information catalog must contain 74 topics, found {len(_CATALOG)}")

