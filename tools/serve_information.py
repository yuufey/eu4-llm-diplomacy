"""Serve EU4 information and diplomacy over MCP stdio or simple JSONL.

The default transport is MCP stdio.  ``--jsonl`` is a small diagnostic mode
for scripts that send ``{"tool": ..., "arguments": ...}`` records; it is not
an alternative permission boundary. Both modes register information queries,
subscriptions and diplomacy actions once, sharing the live operator session
and request journal. Diplomacy execution can change the game.
With --battle-manage-capture,
subscriptions also manage the already-installed passive battle producer.
"""
from __future__ import annotations

import argparse
import math
import os
from pathlib import Path
import json
import logging
import sys
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from bridge.information.mcp import parse_json_line, serve_stdio
from bridge.information.model import InformationError
from bridge.game_tools import GameTools


DEFAULT_DATABASE = ROOT / "work" / "runtime" / "information-service" / "information.sqlite3"
DEFAULT_JOURNAL = ROOT / "work" / "runtime" / "information-service" / "diplomacy.sqlite3"


def _positive_seconds(value: str) -> float:
    try:
        result = float(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("--tick-seconds must be a number") from error
    if not math.isfinite(result) or result < 0 or result > 86400:
        raise argparse.ArgumentTypeError("--tick-seconds must be between 0 and 86400")
    return result


def _same_database_file(left: Path | str, right: Path | str) -> bool:
    """Return whether two configured database paths name one file."""

    left_path = Path(left).expanduser()
    right_path = Path(right).expanduser()
    try:
        if left_path.resolve(strict=False) == right_path.resolve(strict=False):
            return True
    except OSError:
        # A malformed/unavailable path still gets the conservative existing
        # file check below; this helper must not open either database.
        pass
    if left_path.exists() and right_path.exists():
        try:
            return os.path.samefile(left_path, right_path)
        except (OSError, ValueError):
            return False
    return False


def _build_runtime(args: argparse.Namespace):
    from bridge.diplomacy_control import DiplomacyControl

    controlled_country = getattr(args, "controlled_country", None) or args.observer
    control = DiplomacyControl(args.owner, controlled_country)
    managed_countries = getattr(args, "managed_countries", None)
    if managed_countries is None:
        managed_countries = [controlled_country] if controlled_country is not None else []
    for country in managed_countries:
        DiplomacyControl(args.owner, country)
    if controlled_country is not None and controlled_country not in managed_countries:
        raise ValueError("CONTROLLED_COUNTRY_OUTSIDE_MANAGED_COUNTRIES")
    battle_only = getattr(args, "battle_only", False)
    if battle_only:
        if not args.operator_session or not args.observer or not args.battle_stream:
            raise ValueError("--battle-only requires --operator-session, --observer and --battle-stream")
        incompatible = ("recorded_manifest", "mission_save", "mission_game_data", "province_interest_save",
                        "empire_save", "empire_game_data", "opinion_save", "decision_context",
                        "static_game_data")
        if any(getattr(args, name, None) for name in incompatible):
            raise ValueError("--battle-only cannot combine battle context with another information source")
    """Construct source/service and keep operator resources for shutdown."""

    from bridge.information.service import InformationService
    from bridge.information.sources import DiplomacySource, RecordedSource
    from bridge.information.composite import CompositeSource
    from bridge.information.country_state import NativeCountryStateSource
    from bridge.information.domestic_pressure import NativeDomesticPressureSource
    from bridge.information.subject_relations import NativeSubjectRelationSource
    from bridge.information.relation_state import NativeRelationSource
    from bridge.information.trade_income import NativeTradeIncomeSource
    from bridge.information.trade_collection import NativeTradeCollectionSource
    from bridge.information.trade_value import NativeTradeValueSource
    from bridge.information.trade_home import NativeTradeHomeSource
    from bridge.information.trade_power import NativeTradePowerSource
    from bridge.information.trade_details import NativeTradeDetailsSource
    from bridge.information.trade_transfer import NativeTradeTransferSource
    from bridge.information.military_quality import NativeMilitaryQualitySource
    from bridge.information.own_military_modifiers import NativeOwnMilitaryModifiersSource
    from bridge.information.country_records import NativeCountryRecordsSource
    from bridge.information.diplomat_tasks import NativeDiplomatTasksSource
    from bridge.information.relations_capacity import NativeRelationsCapacitySource
    from bridge.information.diplomatic_reputation import NativeDiplomaticReputationSource
    from bridge.information.diplomats_total import NativeDiplomatsTotalSource
    from bridge.information.governance_capacity import NativeGovernanceCapacitySource
    from bridge.information.country_forces import NativeCountryForcesSource
    from bridge.information.military_resources import NativeMilitaryResourcesSource
    from bridge.information.country_rivals import NativeCountryRivalsSource
    from bridge.information.foreign_technology import NativeForeignTechnologySource
    from bridge.information.foreign_economy import NativeForeignEconomySource
    from bridge.information.country_faith import NativeCountryFaithSource
    from bridge.information.religion_group import NativeReligionGroupSource
    from bridge.information.religion_information import NativeReligionInformationSource
    from bridge.information.religion_defender import NativeReligionDefenderSource
    from bridge.information.papacy import NativePapacySource
    from bridge.information.religious_schools import NativeReligiousSchoolsSource
    from bridge.information.country_scale import NativeCountryScaleSource
    from bridge.information.country_person import NativeCountryPersonSource
    from bridge.information.province_state import NativeProvinceStateSource
    from bridge.information.province_interests_live import NativeProvinceInterestsSource
    from bridge.information.province_permanent_claims import NativeProvincePermanentClaimsSource
    from bridge.information.empire_live import NativeEmpireSource

    battle_stream = getattr(args, "battle_stream", None)
    battle_ingest_installation = getattr(args, "battle_ingest_installation", None)
    battle_manage_capture = getattr(args, "battle_manage_capture", False)
    province_interest_save = getattr(args, "province_interest_save", None)
    province_interest_parser_manifest = getattr(args, "province_interest_parser_manifest", None)
    empire_save = getattr(args, "empire_save", None)
    empire_parser_manifest = getattr(args, "empire_parser_manifest", None)
    opinion_save = getattr(args, "opinion_save", None)
    opinion_parser_manifest = getattr(args, "opinion_parser_manifest", None)
    empire_game_data = getattr(args, "empire_game_data", False)
    empire_rules_parser_manifest = getattr(args, "empire_rules_parser_manifest", None)
    if empire_rules_parser_manifest is not None and not empire_game_data:
        raise ValueError("--empire-rules-parser-manifest requires --empire-game-data")
    if empire_game_data and (empire_save is not None or province_interest_save is not None
                             or opinion_save is not None
                             or args.mission_save is not None or args.recorded_manifest is not None):
        raise ValueError("--empire-game-data cannot be combined with historical state sources")
    if empire_parser_manifest is not None and empire_save is None:
        raise ValueError("--empire-parser-manifest requires --empire-save")
    if empire_save is not None:
        if args.observer is None:
            raise ValueError("--empire-save requires --observer")
        if (args.operator_session is not None or args.recorded_manifest is not None
                or args.mission_save is not None or args.mission_game_data
                or province_interest_save is not None or opinion_save is not None
                or battle_stream is not None
                or battle_ingest_installation is not None or battle_manage_capture):
            raise ValueError("--empire-save cannot be combined with another state source")
    if province_interest_parser_manifest is not None and province_interest_save is None:
        raise ValueError("--province-interest-parser-manifest requires --province-interest-save")
    if province_interest_save is not None:
        if args.observer is None:
            raise ValueError("--province-interest-save requires --observer")
        if (args.operator_session is not None or args.recorded_manifest is not None
                or args.mission_save is not None or args.mission_game_data
                or opinion_save is not None
                or battle_stream is not None or battle_ingest_installation is not None
                or battle_manage_capture):
            raise ValueError("--province-interest-save cannot be combined with another state source")
    if opinion_parser_manifest is not None and opinion_save is None:
        raise ValueError("--opinion-parser-manifest requires --opinion-save")
    if opinion_save is not None:
        if args.observer is None:
            raise ValueError("--opinion-save requires --observer")
        if (args.operator_session is not None or args.recorded_manifest is not None
                or args.mission_save is not None or args.mission_game_data
                or province_interest_save is not None or empire_save is not None
                or empire_game_data or battle_stream is not None
                or battle_ingest_installation is not None or battle_manage_capture):
            raise ValueError("--opinion-save cannot be combined with another state source")
    if battle_ingest_installation is not None and battle_stream is None:
        raise ValueError("--battle-ingest-installation requires --battle-stream")
    if battle_manage_capture and (
            battle_ingest_installation is None or args.operator_session is None
            or Path(battle_ingest_installation).resolve() != Path(args.operator_session).resolve()):
        raise ValueError("--battle-manage-capture requires matching --operator-session and --battle-ingest-installation")
    if args.recorded_manifest is not None and args.operator_session is not None:
        raise ValueError("--recorded-manifest cannot be combined with --operator-session")
    if args.recorded_manifest is not None and args.observer is not None:
        raise ValueError("--observer cannot rewrite a recorded manifest's observer")
    if not (args.static_game_data or args.mission_game_data or empire_game_data) and (args.static_game_root is not None or args.static_user_data is not None):
        raise ValueError("Static paths require --static-game-data or --mission-game-data")
    if args.mission_save is not None:
        if not args.mission_game_data or args.observer is None:
            raise ValueError("--mission-save requires --mission-game-data and --observer")
        if args.operator_session is not None or args.recorded_manifest is not None:
            raise ValueError("--mission-save cannot be combined with another state source")
    if args.mission_game_data and args.recorded_manifest is not None:
        raise ValueError("A recorded diplomacy manifest does not supply mission slot state; use --mission-save")
    mission_parser_manifest = getattr(args, "mission_parser_manifest", None)
    if mission_parser_manifest is not None and not args.mission_game_data:
        raise ValueError("--mission-parser-manifest requires --mission-game-data")

    journal = None
    diplomacy_tools = None
    session = None
    if args.operator_session:
        # One session and journal serve both the read-only information source
        # and explicit diplomacy tool calls. Sources still call query methods.
        from bridge.diplomacy import DiplomacyTools, ObserverSession
        from bridge.diplomacy_journal import DurableJournal
        from work.local_config import game_exe

        session = ObserverSession(args.operator_session, game_exe())
        session.controlled_country = controlled_country
        configure_control = getattr(session, "configure_controlled_countries", None)
        if controlled_country is not None and callable(configure_control):
            configure_control(managed_countries)
        if not battle_only:
            journal_path = args.journal or DEFAULT_JOURNAL
            journal_path.parent.mkdir(parents=True, exist_ok=True)
            journal = DurableJournal(
                journal_path,
                experiment_id=session.experiment_id,
                session_id=session.session_id,
                global_request_ids=True,
            )
            diplomacy_tools = DiplomacyTools(journal, session)
            diplomacy_tools.control = control
            diplomacy_tools.controlled_country = controlled_country

    # A recorded manifest is an explicit historical source.  Without either
    # kind of binding the default remains an unready live adapter so discover
    # can describe the catalog without presenting history as current state.
    source = (RecordedSource(args.recorded_manifest)
              if args.recorded_manifest is not None
              else DiplomacySource(diplomacy_tools=diplomacy_tools, observer=args.observer))
    if battle_only:
        from bridge.information.battle_observer_context import BattleObserverContextSource
        source = BattleObserverContextSource(session, args.operator_session, args.observer)
    # A live operator session shares one neutral literal-localization reader
    # across country records, static trade and missions.  Keep
    # this construction strictly inside the live/operator branch: recorded,
    # saved and unbound sources must never acquire a live cache reader.
    localization_reader = None
    if args.operator_session is not None and not battle_only:
        from bridge.information.native_localization import NativeLocalizationReader
        localization_reader = NativeLocalizationReader(source)
    if args.mission_save is not None:
        from bridge.information.missions import SavedMissionContextSource
        from bridge.information.saved_missions import SavedMissionSnapshot
        source = SavedMissionContextSource(SavedMissionSnapshot(args.mission_save, args.observer))
    if province_interest_save is not None:
        from bridge.information.saved_province_interests_v2 import SavedProvinceInterestsSnapshotV2
        from bridge.information.province_interests_v2 import SavedProvinceInterestsSourceV2
        source = SavedProvinceInterestsSourceV2(SavedProvinceInterestsSnapshotV2(
            province_interest_save, args.observer, parser_manifest=province_interest_parser_manifest))
    if empire_save is not None:
        from bridge.information.saved_empire_v2 import SavedEmpireSnapshotV2
        from bridge.information.empire_snapshot_v2 import SavedEmpireSourceV2
        source = SavedEmpireSourceV2(SavedEmpireSnapshotV2(
            empire_save, args.observer, parser_manifest=empire_parser_manifest))
    if opinion_save is not None:
        from bridge.information.saved_opinions import SavedOpinionSnapshot
        from bridge.information.opinion_snapshot import SavedOpinionSource
        source = SavedOpinionSource(SavedOpinionSnapshot(
            opinion_save, args.observer, parser_manifest=opinion_parser_manifest))
    adapters = []
    live_adapters = (not battle_only and args.recorded_manifest is None and args.mission_save is None
                     and province_interest_save is None and empire_save is None and opinion_save is None)
    trade_scenarios = None
    decision_context = getattr(args, "decision_context", None)
    if decision_context is not None:
        from bridge.information.decision_context_inputs import DecisionContextInputsSource
        shared_parameters = None
        if live_adapters:
            from bridge.information.pending_matters import _PARAMETERS as shared_parameters
        adapters.append(DecisionContextInputsSource(source, decision_context,
                                                    shared_parameters=shared_parameters))
    if province_interest_save is not None:
        from bridge.information.saved_discovery import SavedProvinceDiscoverySource
        adapters.append(SavedProvinceDiscoverySource(source.snapshot))
    if live_adapters:
        from bridge.information.declaration_cost_rules import DeclarationCostRules
        source.declaration_rules = DeclarationCostRules(
            game_root=args.static_game_root, user_data=args.static_user_data)
        from bridge.information.pending_matters import JournalPendingMattersSource
        adapters.append(JournalPendingMattersSource(source, native_pending=True))
        from bridge.information.proposal_expiry_history import NativeProposalExpiryHistorySource
        from bridge.information.modifier_lifecycle_history import NativeModifierLifecycleHistorySource
        from bridge.information.subsidy_expiry_history import NativeSubsidyExpiryHistorySource
        from bridge.information.truce_expiry_history import NativeTruceExpiryHistorySource
        from bridge.information.cooldown_expiry_history import CooldownExpiryHistorySource
        from bridge.information.claim_expiry_history import NativeClaimExpiryHistorySource
        proposal_history = NativeProposalExpiryHistorySource(source)
        modifier_history = NativeModifierLifecycleHistorySource(source)
        subsidy_history = NativeSubsidyExpiryHistorySource(source)
        truce_history = NativeTruceExpiryHistorySource(source)
        cooldown_history = CooldownExpiryHistorySource(source)
        claim_history = NativeClaimExpiryHistorySource(source)
        adapters.extend((proposal_history, modifier_history, subsidy_history, truce_history, cooldown_history, claim_history))
        # Local N02 selectors also validate planned-only queries without
        # acquiring a manpower pair recipient or invoking its inspection.
        own_forces = NativeCountryForcesSource(source, localization_reader=localization_reader)
        adapters.append(own_forces)
        adapters.append(NativeMilitaryResourcesSource(source))
        adapters.append(NativeCountryRivalsSource(source))
        from bridge.information.coalitions import NativeCoalitionsSource
        adapters.append(NativeCoalitionsSource(source))
        foreign_military = NativeForeignTechnologySource(source)
        adapters.append(foreign_military)
        from bridge.information.war_forces import NativeWarForcesSource
        war_forces = NativeWarForcesSource(source, own_forces, foreign_military)
        from bridge.information.foreign_pressure import NativeForeignPressureSource
        foreign_pressure = NativeForeignPressureSource(source)
        adapters.append(foreign_pressure)
        from bridge.information.war_territory import NativeWarTerritorySource
        war_territory = NativeWarTerritorySource(source)
        from bridge.information.war_situation import NativeWarSituationSource
        war_situation = NativeWarSituationSource(source, war_territory, war_forces)
        adapters.append(war_situation)
        from bridge.information.peace_followup import PeaceFollowupSource
        adapters.append(PeaceFollowupSource(source))
        from bridge.information.territorial_interests import NativeTerritorialInterestsSource
        adapters.append(NativeTerritorialInterestsSource(source))
        from bridge.information.ai_attitude import NativeAiAttitudeSource
        adapters.append(NativeAiAttitudeSource(source))
        from bridge.information.subject_pressure import NativeSubjectPressureSource
        adapters.append(NativeSubjectPressureSource(source))
        foreign_economy = NativeForeignEconomySource(source)
        adapters.append(foreign_economy)
        from bridge.information.commitments import NativeCommitmentsSource
        commitments = NativeCommitmentsSource(foreign_economy)
        adapters.append(commitments)
        from bridge.information.war_land_commitments import NativeWarLandCommitmentsSource
        adapters.append(NativeWarLandCommitmentsSource(commitments))
        from bridge.information.war_contribution import NativeWarContributionSource
        adapters.append(NativeWarContributionSource(source))
        adapters.append(NativeReligionInformationSource(source,
            faith_source=NativeCountryFaithSource(source),
            group_source=NativeReligionGroupSource(source)))
        adapters.append(NativeReligionDefenderSource(source))
        adapters.append(NativePapacySource(source))
        adapters.append(NativeReligiousSchoolsSource(source))
        from bridge.information.war_relations import NativeWarRelationsSource
        country_scale = NativeCountryScaleSource(source)
        adapters.append(country_scale)
        adapters.append(NativeWarRelationsSource(country_scale))
        from bridge.information.truce_dates import NativeTruceDatesSource
        adapters.append(NativeTruceDatesSource(source))
        person_source = NativeCountryPersonSource(source)
        adapters.append(person_source)
        from bridge.information.foreign_succession import NativeForeignSuccessionSource
        adapters.append(NativeForeignSuccessionSource(source, person_source))
        province_state = NativeProvinceStateSource(source)
        adapters.append(province_state)
        from bridge.information.province_ports import NativeProvincePortSource
        province_ports = NativeProvincePortSource(source)
        adapters.append(province_ports)
        from bridge.information.province_forts import NativeProvinceFortSource
        adapters.append(NativeProvinceFortSource(source))
        adapters.append(NativeProvinceInterestsSource(source))
        adapters.append(NativeProvincePermanentClaimsSource(source))
        from bridge.information.strategic_targets import StrategicTargetsSource
        strategy_source = StrategicTargetsSource(source)
        adapters.append(strategy_source)
        from bridge.information.province_discovery import NativeProvinceDiscoverySource
        adapters.append(NativeProvinceDiscoverySource(source))
        from bridge.information.country_discovery import NativeCountryDiscoverySource
        adapters.append(NativeCountryDiscoverySource(source))
        adapters.append(NativeEmpireSource(source))
        if not empire_game_data:
            from bridge.information.empire_live_v3 import NativeEmpirePassedReformsSource
            adapters.append(NativeEmpirePassedReformsSource(source))
        adapters.append(NativeCountryStateSource(source))
        from bridge.information.war_exhaustion import NativeWarExhaustionSource
        pressure = NativeDomesticPressureSource(source)
        adapters.append(pressure)
        adapters.append(NativeWarExhaustionSource(pressure, foreign_pressure, source))
        adapters.append(NativeSubjectRelationSource(source))
        relations = NativeRelationSource(source)
        from bridge.information.declaration_roles import DeclarationParticipantRoles
        source.declaration_roles = DeclarationParticipantRoles(source, relations)
        adapters.append(relations)
        from bridge.information.opinion import NativeOpinionSource
        adapters.append(NativeOpinionSource(source))
        from bridge.information.opinion_modifiers import NativeOpinionModifiersSource
        opinion_definitions = None
        if args.static_game_data:
            from bridge.information.opinion_definitions import OpinionModifierDefinitionIndex
            opinion_definitions = OpinionModifierDefinitionIndex(
                game_root=args.static_game_root, user_data=args.static_user_data)
        adapters.append(NativeOpinionModifiersSource(source, definitions=opinion_definitions))
        from bridge.information.opinion_decay import NativeOpinionDecaySource
        adapters.append(NativeOpinionDecaySource(source))
        from bridge.information.opinion_end_dates import NativeOpinionEndDatesSource
        adapters.append(NativeOpinionEndDatesSource(source))
        from bridge.information.special_diplomacy import NativeSpecialDiplomacySource
        adapters.append(NativeSpecialDiplomacySource(relations))
        trade_income = NativeTradeIncomeSource(source)
        adapters.append(trade_income)
        adapters.append(NativeTradeCollectionSource(trade_income))
        adapters.append(NativeTradeValueSource(source))
        adapters.append(NativeTradeHomeSource(source))
        trade_power = NativeTradePowerSource(source)
        adapters.append(trade_power)
        from bridge.information.trade_scenario_baseline import TradeScenarioBaselineReader
        from bridge.information.trade_scenarios import TradeScenarioSource
        from bridge.information.trade_scenario_costs import TradeScenarioCostReader
        trade_cost_reader = (TradeScenarioCostReader(diplomacy_tools.inspect_diplomatic_action)
                             if diplomacy_tools is not None else None)
        trade_scenarios = TradeScenarioSource(TradeScenarioBaselineReader(trade_power), trade_cost_reader)
        adapters.append(trade_scenarios)
        adapters.append(NativeTradeDetailsSource(source))
        trade_transfers = NativeTradeTransferSource(source)
        adapters.append(trade_transfers)
        military_quality = NativeMilitaryQualitySource(source)
        adapters.append(military_quality)
        adapters.append(NativeOwnMilitaryModifiersSource(source))
        country_records = NativeCountryRecordsSource(source, localization_reader=localization_reader)
        from bridge.information.final_attributes import NativeFinalAttributesSource
        from bridge.information.province_goods_sources import NativeProvinceGoodsSourceBreakdownSource
        relations_capacity = NativeRelationsCapacitySource(source)
        diplomatic_reputation = NativeDiplomaticReputationSource(source)
        diplomats_total = NativeDiplomatsTotalSource(source)
        adapters.append(NativeFinalAttributesSource(military_quality, country_records, scalar_sources={
            'relations_limit': relations_capacity, 'diplomatic_reputation': diplomatic_reputation,
            'diplomats_total': diplomats_total},
            province_breakdown_source=NativeProvinceGoodsSourceBreakdownSource(source, projection_version=2)))
        adapters.append(country_records)
        adapters.append(NativeDiplomatTasksSource(source))
        adapters.append(relations_capacity)
        adapters.append(diplomatic_reputation)
        adapters.append(diplomats_total)
        adapters.append(NativeGovernanceCapacitySource(source))
    static_trade = None
    if args.static_game_data:
        from bridge.information.static_data import StaticTradeSource
        from bridge.information.straits import StaticStraitsSource
        static_trade = StaticTradeSource(game_root=args.static_game_root,
                                        user_data=args.static_user_data,
                                        context_provider=source.context,
                                        localization_reader=localization_reader)
        adapters.append(static_trade)
        if trade_scenarios is not None:
            from bridge.information.trade_target_graph import TradeTargetGraphReader
            from bridge.information.trade_targets import TradeTargetsReader
            from bridge.information.province_estuary_definitions import BoundEstuaryDefinition
            from bridge.information.province_estuaries import NativeProvinceEstuaryReader
            from bridge.information.province_trade_power import NativeProvinceTradePowerReader
            estuary_rules = BoundEstuaryDefinition(static_trade.game_root, static_trade.user_data,
                                                   enabled_mods=static_trade.enabled_mods)
            estuary_reader = NativeProvinceEstuaryReader(source, estuary_rules)
            trade_scenarios.target_reader = TradeTargetsReader(
                TradeTargetGraphReader(static_trade), province_state, province_ports, estuary_reader,
                NativeProvinceTradePowerReader(source, with_numeric_inputs=True, with_country_inputs=True,
                    with_calculation=True, with_node_allocation=True, with_value_calculation=True,
                    with_node_cash=True))
        adapters.append(StaticStraitsSource(game_root=args.static_game_root,
                                           user_data=args.static_user_data,
                                           context_provider=source.context))
    if live_adapters:
        from bridge.information.geographic_trade_transfer import GeographicTradeTransferSource
        adapters.append(GeographicTradeTransferSource(source, trade_transfers, static_trade))
    if empire_game_data:
        from bridge.information.imperial_reform_definitions import ImperialReformDefinitionIndex
        from bridge.information.imperial_reform_rules import StaticImperialReformRulesSource
        reform_definitions = ImperialReformDefinitionIndex(
            game_root=args.static_game_root, user_data=args.static_user_data,
            parser_manifest=empire_rules_parser_manifest)
        adapters.append(StaticImperialReformRulesSource(source, reform_definitions))
    if args.mission_game_data:
        from bridge.information.mission_definitions import MissionDefinitionIndex
        from bridge.information.cwtools_script import CwtoolsScriptParser
        from bridge.information.mission_scope_index import StaticMissionScopeIndex
        from bridge.information.missions import MissionInformationSource, NativeMissionReader
        from bridge.information.mission_analysis import MissionAnalysisSource
        from bridge.information.province_task_targets import ProvinceTaskTargetsSource
        from bridge.information.mission_candidate_costs import MissionCandidateCostReader
        from bridge.information.mission_read_scope import MissionReadSource, MissionScopedReader, capture_rule_inputs
        script_parser = CwtoolsScriptParser(mission_parser_manifest)
        definitions = MissionDefinitionIndex(game_root=args.static_game_root, user_data=args.static_user_data,
                                             script_parser=script_parser)
        scope_index = StaticMissionScopeIndex(game_root=args.static_game_root, user_data=args.static_user_data,
                                              script_parser=script_parser)
        reader = (source.capture if args.mission_save is not None
                  else NativeMissionReader(source, localization_reader=localization_reader))
        rule_reader = (None if args.mission_save is not None else
                       NativeMissionReader(source, capture=capture_rule_inputs, localization_reader=localization_reader))
        scoped_mission_reader = MissionScopedReader(reader, rule_reader)
        mission_source = MissionInformationSource(source, definitions, scoped_mission_reader,
                                                 scheduling=args.mission_save is None, scope_index=scope_index)
        from bridge.information.mission_reward_scopes import MissionRewardAreaSource
        limit_reader = None
        if live_adapters and args.mission_save is None:
            from bridge.information.mission_reward_inputs import NativeMissionRewardInputs
            limit_reader = NativeMissionRewardInputs(source)
        adapters.append(MissionRewardAreaSource(mission_source, limit_reader=limit_reader))
        cost_reader=(MissionCandidateCostReader(diplomacy_tools.inspect_diplomatic_action)
                     if diplomacy_tools is not None and args.mission_save is None else None)
        mission_analysis = MissionAnalysisSource(mission_source,cost_reader=cost_reader)
        adapters.append(mission_analysis)
        if live_adapters:
            adapters.append(ProvinceTaskTargetsSource(mission_analysis))
    if live_adapters and (args.mission_game_data or args.static_game_data):
        if args.mission_game_data:
            strategy_source.scope_index = scope_index
        else:
            from bridge.information.mission_scope_index import StaticMissionScopeIndex
            strategy_source.scope_index = StaticMissionScopeIndex(
                game_root=args.static_game_root, user_data=args.static_user_data)
    if adapters:
        source = CompositeSource(source, adapters)
    if args.mission_game_data:
        source = MissionReadSource(source, scoped_mission_reader)
    if battle_stream:
        # Battle records are an explicit opt-in source.  Keep the import lazy
        # so the normal/offline server does not require the battle adapter or
        # inspect a local stream file.  The adapter wraps the complete source
        # assembled above and remains read-only with respect to the game.
        from bridge.information.battles import BattleInformationSource

        source = BattleInformationSource.from_config(source, Path(battle_stream))
    battle_ingestor = None
    if battle_ingest_installation is not None:
        # Keep construction explicit and lazy.  The source wrapper owns the
        # read-only battle database; the ingestor only advances that database
        # when its refresh() method is called by the service owner.
        if not hasattr(source, "battles"):
            raise ValueError("--battle-ingest-installation requires a battle stream source")
        battle_database = getattr(source.battles, "database", None)
        if battle_database is None:
            raise ValueError("Battle stream source does not expose an ingestion database")
        if _same_database_file(args.database, battle_database):
            if journal is not None:
                journal.close()
            raise ValueError(
                "--database (service configuration/results DB) and battle ingestion DB must be different files"
            )
        battle_binding = getattr(source.battles, "binding", None)
        if not isinstance(battle_binding, dict):
            raise ValueError("Battle stream source does not expose an ingestion binding")
        from bridge.information.battle_ingest import LiveBattleIngestor
        battle_ingestor = LiveBattleIngestor(
            battle_ingest_installation,
            battle_database,
            expected_binding=battle_binding,
        )
        # Expose the handle for the scheduler/host integration without
        # changing BattleInformationSource or InformationService contracts.
        setattr(source, "ingestor", battle_ingestor)
        if battle_manage_capture:
            try:
                if battle_binding.get("mode") != "live":
                    raise ValueError("--battle-manage-capture requires a live battle stream")
                from bridge.information.battle_capture import BattleCaptureManager
                source.capture_manager = BattleCaptureManager(battle_ingest_installation, battle_binding)
            except Exception:
                battle_ingestor.close()
                if journal is not None:
                    journal.close()
                raise
    args.database.parent.mkdir(parents=True, exist_ok=True)
    try:
        service = InformationService(source, args.database, owner=args.owner)
        if live_adapters:
            war_situation.force_history = service.previous_war_forces
            proposal_history.history_reader = service.observed_events
            modifier_history.history_reader = service.observed_events
            subsidy_history.history_reader = service.observed_events
            truce_history.history_reader = service.observed_events
            cooldown_history.history_reader = service.observed_events
            claim_history.history_reader = service.observed_events
            commitments.land_promise_history_reader = service.observed_events
            cooldown_history.base_source.cooldown_reader = service.action_cooldown_expiries
            from bridge.information.cooldown_expiry import EVENT_TYPE as cooldown_event_type
            cooldown_history.base_source.event_types = (*cooldown_history.base_source.event_types, cooldown_event_type)
    except Exception:
        closer = getattr(source, "close_capture", None)
        try:
            if callable(closer):
                closer()
        finally:
            if battle_ingestor is not None:
                battle_ingestor.close()
            if journal is not None:
                journal.close()
        raise
    if battle_ingestor is not None:
        setattr(service, "battle_ingestor", battle_ingestor)
    service.diplomacy_tools = diplomacy_tools
    service.diplomacy_control = control
    return service, journal


def _run_jsonl(service: Any, source: Iterable[str], *, tools: Any = None) -> int:
    tools = tools if tools is not None else GameTools(service)
    for line in source:
        if not line.strip():
            continue
        try:
            request = parse_json_line(line)
            if not isinstance(request, dict) or set(request) != {"tool", "arguments"}:
                raise InformationError("invalid_request", "Each JSONL record must contain tool and arguments")
            if not isinstance(request["tool"], str) or not isinstance(request["arguments"], dict):
                raise InformationError("invalid_request", "JSONL tool must be a string and arguments an object")
            result = tools.call(request["tool"], request["arguments"])
        except InformationError as error:
            result = error.as_dict()
        except (ValueError, TypeError, json.JSONDecodeError) as error:
            result = {"error": {"code": "invalid_request", "message": str(error)}}
        except Exception:
            # A bad source or one malformed model request must not terminate a
            # long-running JSONL process.  Keep details out of the wire.
            logging.getLogger(__name__).exception("game JSONL request failed")
            result = {"error": {"code": "internal_error", "message": "Game tool failed"}}
        try:
            wire = json.dumps(result, ensure_ascii=False, allow_nan=False, separators=(",", ":"))
        except (TypeError, ValueError):
            # Keep a malformed adapter result from terminating the JSONL
            # process or emitting a non-JSON line.
            wire = json.dumps(
                {"error": {"code": "non_json_result", "message": "Information tool returned a non-JSON value"}},
                ensure_ascii=False,
                separators=(",", ":"),
            )
        print(wire, flush=True)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", type=Path, default=DEFAULT_DATABASE,
                        help="SQLite database for reports, subscriptions and outbox")
    parser.add_argument("--operator-session", type=Path,
                        help="Verified observer installation.json; omit for offline discovery")
    parser.add_argument("--observer", default=None,
                        help="Trusted operator country tag; kept distinct from the game's player tag")
    parser.add_argument("--controlled-country", default=None,
                        help="Country this LLM may control; defaults to --observer, omitting both leaves diplomacy read-only")
    parser.add_argument("--managed-countries", nargs="+", default=None,
                        help="Complete native managed-country set shared by LLM connections; defaults to the controlled country")
    parser.add_argument("--battle-only", action="store_true",
                        help="Serve session context and battles for a native-verified non-player observer")
    parser.add_argument("--static-game-data", action="store_true",
                        help="Enable static trade definitions from configured local game/mod files")
    parser.add_argument("--static-game-root", type=Path, default=None)
    parser.add_argument("--static-user-data", type=Path, default=None)
    parser.add_argument("--mission-game-data", action="store_true",
                        help="Enable country mission slots, completion records and unevaluated mission definitions")
    parser.add_argument("--mission-save", type=Path, default=None,
                        help="Explicit historical EU4txt save for mission queries; never used as current live state")
    parser.add_argument("--mission-parser-manifest", type=Path, default=None,
                        help="Operator-only pinned CWTools parser manifest; requires --mission-game-data")
    parser.add_argument("--province-interest-save", type=Path, default=None,
                        help=("Explicit historical save for discovered-province cores/claims and the observer's "
                              "known province IDs; snapshot queries/reports only, requires --observer"))
    parser.add_argument("--province-interest-parser-manifest", type=Path, default=None,
                        help="Operator-only pinned Jomini parser manifest; used with --province-interest-save")
    parser.add_argument("--empire-save", type=Path, default=None,
                        help="Explicit historical save for HRE status, emperor, electors and reform records; requires --observer")
    parser.add_argument("--empire-parser-manifest", type=Path, default=None,
                        help="Operator-only pinned Jomini parser manifest; used with --empire-save")
    parser.add_argument("--empire-game-data", action="store_true",
                        help="Expose configured HRE reform declarations; does not observe passed reforms or evaluate effects")
    parser.add_argument("--empire-rules-parser-manifest", type=Path, default=None,
                        help="Operator-only pinned CWTools parser manifest; requires --empire-game-data")
    parser.add_argument("--opinion-save", type=Path, default=None,
                        help="Explicit historical EU4 save for directed opinion modifiers; query-only and requires --observer")
    parser.add_argument("--opinion-parser-manifest", type=Path, default=None,
                        help="Operator-only pinned Jomini parser manifest; requires --opinion-save")
    parser.add_argument("--recorded-manifest", type=Path, default=None,
                        help="Read-only recorded source archive/manifest; cannot be combined with --operator-session")
    parser.add_argument("--decision-context", type=Path, default=None,
                        help="Explicit operator goal/constraint declarations; input metadata, not game facts")
    parser.add_argument("--battle-stream", type=Path, default=None,
                        help=("Opt-in local battle-record source configuration/SQLite; "
                              "requires the operator binding file and exposes only "
                              "records where the observer directly participates"))
    parser.add_argument("--battle-ingest-installation", type=Path, default=None,
                        help=("Enable bounded local raw-log ingestion for an installed "
                              "observer installation.json; requires --battle-stream and "
                              "writes only its configured SQLite database"))
    parser.add_argument("--battle-manage-capture", action="store_true",
                        help=("Let live event subscriptions share enable/disable control of the "
                              "already-installed battle producer; requires the same operator "
                              "and ingest installation. Never injects, advances time or saves."))
    parser.add_argument("--journal", type=Path, default=None,
                        help="Operator DiplomacyTools journal (used with --operator-session)")
    parser.add_argument("--owner", default="llm",
                        help="Operator-assigned caller identity and information namespace")
    parser.add_argument("--tick-seconds", type=_positive_seconds, default=0.0,
                        help="Run the background scheduler every N real seconds; 0 disables it")
    parser.add_argument("--jsonl", action="store_true",
                        help="Use simple tool/arguments JSONL instead of MCP stdio")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        service, journal = _build_runtime(args)
    except (OSError, ValueError, RuntimeError, ImportError) as error:
        parser.error(str(error))
    try:
        tools = GameTools(service)
        if args.jsonl:
            return _run_jsonl(service, sys.stdin, tools=tools)
        return serve_stdio(service, tick_seconds=args.tick_seconds, tools=tools)
    finally:
        # serve_stdio closes the service itself.  JSONL mode needs the same
        # lifecycle cleanup here.  The operator journal is closed after the
        # service has released its source resources.
        try:
            ingestor = getattr(service, "battle_ingestor", None)
            try:
                service.close()
            finally:
                if ingestor is not None:
                    ingestor.close()
        finally:
            if journal is not None:
                journal.close()


if __name__ == "__main__":
    raise SystemExit(main())
