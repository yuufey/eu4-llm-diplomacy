"""Operator-only install of one immutable observer build into one game process.

Startup can expose the country database before the world and load-warning
dialog are ready. The ready loop probes the same verified PID and creation
time. Repeated missing confirmations permit one window minimize/restore to
release the observed D3D/DWM startup wait. Once installation is recorded, the
native installer is called exactly once and its error is terminal.
An explicitly named test-save startup may use one recorded C shortcut when
the native load-warning lookup returns no unique confirmation.
"""
from __future__ import annotations

import argparse
import ctypes as C
from ctypes import wintypes as W
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "work"))
from local_config import game_exe, get_value
from bridge.diplomacy_session import file_hash, probe_identity
from acknowledge_startup_error import acknowledge_startup_error
from work.observer_runtime_ready import (
    _enumerate_windows_for_pid, _is_iconic, _show_window_async,
)


MAX_WAIT_READY = 300
PREFLIGHT_TIMEOUT = 30.0
DIALOG_SCAN_TIMEOUT = 22.0
DIALOG_ATTEMPT_TIMEOUT = 52.0
READY_POLL_SECONDS = 3.0
IDENTITY_POLL_SECONDS = 1.0
STARTUP_ERROR_SCAN_SECONDS = 5.0
TRANSIENT_IDENTITY_WINERRORS = frozenset((6, 299))
LOAD_WARNING_SHORTCUT_RECEIPT = "load-warning-shortcut.json"
INFORMATION_BATTLE_REQUIRED_SOURCES = (
    "information-battle-observer.inc",
    "information-battle-entry-stub.S",
    "information-battle-entry-plan.h",
    "information-battle-owned-result.h",
    "information-battle-owned-summary.h",
    "information-battle-buffer.h",
    "information-battle-drain.h",
    "information-battle-wire.h",
    "information-battle-log-writer.h",
    "information-battle-observation-wire.h",
    "information-battle-fragment.h",
)
INFORMATION_BATTLE_CONTEXT_REQUIRED_SOURCES = INFORMATION_BATTLE_REQUIRED_SOURCES + (
    "information-battle-owned-context.h",
    "information-battle-context-wire.h",
)
INFORMATION_BATTLE_NAVAL_REQUIRED_SOURCES = INFORMATION_BATTLE_CONTEXT_REQUIRED_SOURCES + (
    "information-battle-owned-naval.h",
    "information-battle-naval-wire.h",
)
INFORMATION_BATTLE_TEMPLATE_REQUIRED_SOURCES = INFORMATION_BATTLE_NAVAL_REQUIRED_SOURCES + (
    "information-battle-owned-template.h",
    "information-battle-template-wire.h",
    "information-battle-message-entry-plan.h",
)
# v27 keeps the v26 production source set.  The formatter-container support is
# an opt-in compile unit in the existing observer source, so a new header must
# not be silently accepted here.
INFORMATION_BATTLE_CONTAINER_REQUIRED_SOURCES = INFORMATION_BATTLE_TEMPLATE_REQUIRED_SOURCES
INFORMATION_BATTLE_WAR_IDENTITY_REQUIRED_SOURCES = INFORMATION_BATTLE_CONTAINER_REQUIRED_SOURCES + (
    "information-battle-war-binding.h",
    "information-battle-war-identity-wire.h",
)
INFORMATION_BATTLE_NATIVE_TEXT_REQUIRED_SOURCES = INFORMATION_BATTLE_WAR_IDENTITY_REQUIRED_SOURCES + (
    "information-battle-owned-native-text.h",
    "information-battle-native-text-wire.h",
    "information-battle-line1-entry-plan.h",
    "information-battle-line1-observer-stub.S",
)
INFORMATION_BATTLE_NATIVE_TITLE_QUERY_REQUIRED_SOURCES = INFORMATION_BATTLE_NATIVE_TEXT_REQUIRED_SOURCES + (
    "information-battle-owned-title-query.h",
    "information-battle-title-query-plan.h",
)
INFORMATION_BATTLE_GATE_TRACE_REQUIRED_SOURCES = INFORMATION_BATTLE_NATIVE_TITLE_QUERY_REQUIRED_SOURCES + (
    "information-battle-owned-gate-inputs.h",
    "information-battle-gate-trace.h",
    "information-battle-gate-marker-entry-plan.h",
)
INFORMATION_BATTLE_DISPLAY_CONTEXT_REQUIRED_SOURCES = INFORMATION_BATTLE_GATE_TRACE_REQUIRED_SOURCES + (
    "information-battle-display-context-layout.h",
    "information-battle-owned-display-context.h",
    "information-battle-display-context-wire.h",
)
# Exact source-name inventory from the pinned v33 R74 manifest; v34 adds only the two quote units.
# Base manifest SHA-256: 06e60f75fb9888cdee9d0613d61d5d9935d47e604a40fd999dfd8a2a27eedd7a
INFORMATION_BATTLE_V33_SOURCE_NAMES = frozenset((
    'diplomacy-observer-v10.cpp',
    'alliance-query.inc',
    'favor-state.inc',
    'gift-influence-state.inc',
    'insult-query.inc',
    'rival-query.inc',
    'vassal-query.inc',
    'declarewar-query.inc',
    'peace-context-query.inc',
    'peace-empty-offer-query.inc',
    'peace-offer-evaluation-query.inc',
    'peace-money-query.inc',
    'peace-war-context-query.inc',
    'live-war-score-query.inc',
    'live-war-score-query.h',
    'peace-payload.h',
    'peace-native-payload.inc',
    'peace-province-candidates.inc',
    'peace-province-selection.inc',
    'declarewar-payload.h',
    'declarewar-native-payload.inc',
    'declarewar-execution-preflight.inc',
    'declarewar-execution-state.inc',
    'declarewar-cost-query.inc',
    'declarewar-candidates.inc',
    'vassal-test-context.inc',
    'vassal-test-context-script.h',
    'vassal-inbound-test-context.inc',
    'vassal-inbound-test-context-script.h',
    'rival-authority.inc',
    'rival-command-observer.inc',
    'rival-execution.inc',
    'rival-command-authority.h',
    'rival-command-wire.h',
    'alliance-reason-metadata.inc',
    'alliance-reason-metadata-bind.inc',
    'alliance-reason-key-branch.h',
    'alliance-reason-row.h',
    'alliance-lifecycle.inc',
    'alliance-entry-observer.inc',
    'alliance-protocol-observer.inc',
    'alliance-transport.inc',
    'alliance-authority-ledger.h',
    'alliance-execution-wire.h',
    'alliance-inbound-response-wire.h',
    'alliance-inbound-inspection-event.h',
    'alliance-pending-membership.h',
    'alliance-inbound.inc',
    'inbound-pending-recovery.inc',
    'alliance-execution.inc',
    'entry-patch-transaction.inc',
    'control-probe.cpp',
    'automated-control.inc',
    'popup-control.inc',
    'frame_stub.S',
    'peace-payload-ref.h',
    'peace-action-native-payload.inc',
    'peace-lifecycle-hooks.inc',
    'peace-execution-preflight.inc',
    'peace-handler-authority.inc',
    'peace-war-side-members.inc',
    'peace-execution-wire.h',
    'peace-execution.inc',
    'peace-inbound-context.inc',
    'peace-receiver-observer.inc',
    'peace-wrapper-rule-query.inc',
    'peace-effects.h',
    'peace-effect-state.inc',
    'peace-core-effects.inc',
    'peace-subject-effects.inc',
    'peace-country-effects.inc',
    'peace-special-selection.inc',
    'peace-special-state.inc',
    'religion-war-context.inc',
    'religion-war-context-script.h',
    'peace-reparations-selection.inc',
    'peace-reparations-state.inc',
    'peace-annul-selection.inc',
    'peace-core-candidates.inc',
    'peace-subject-candidates.inc',
    'peace-country-candidates.inc',
    'peace-annex-selection.inc',
    'peace-selected-rules.inc',
    'declarewar-details-query.inc',
    'declarewar-peace-options-query.inc',
    'declarewar-selection.h',
    'declarewar-participants-query.inc',
    'declarewar-force-sides.inc',
    'declarewar-forces-query.inc',
    'peace-consequences-query.inc',
    'peace-coalition-capture.inc',
    'peace-overextension-query.inc',
    'peace-justification-query.inc',
    'information-battle-observer.inc',
    'information-battle-entry-stub.S',
    'information-battle-entry-plan.h',
    'information-battle-owned-result.h',
    'information-battle-owned-summary.h',
    'information-battle-buffer.h',
    'information-battle-drain.h',
    'information-battle-wire.h',
    'information-battle-log-writer.h',
    'information-battle-observation-wire.h',
    'information-battle-fragment.h',
    'information-battle-owned-context.h',
    'information-battle-context-wire.h',
    'information-battle-owned-naval.h',
    'information-battle-naval-wire.h',
    'information-battle-owned-template.h',
    'information-battle-template-wire.h',
    'information-battle-message-entry-plan.h',
    'information-battle-war-binding.h',
    'information-battle-war-identity-wire.h',
    'information-battle-owned-native-text.h',
    'information-battle-native-text-wire.h',
    'information-battle-line1-entry-plan.h',
    'information-battle-line1-observer-stub.S',
    'information-battle-owned-title-query.h',
    'information-battle-title-query-plan.h',
    'information-battle-owned-gate-inputs.h',
    'information-battle-gate-trace.h',
    'information-battle-gate-marker-entry-plan.h',
    'information-battle-display-context-layout.h',
    'information-battle-owned-display-context.h',
    'information-battle-display-context-wire.h',
))
INFORMATION_DEBT_QUOTE_REQUIRED_SOURCES = (
    "debt-quote-query.inc",
    "debt-quote-native-guards.h",
)
INFORMATION_BATTLE_END_STATE_SOURCES = (
    "information-battle-owned-end-state.h",
    "information-battle-end-state-wire.h",
)
INFORMATION_BATTLE_END_STATE_HEADER_DEPENDENCIES = frozenset((
    "information-battle-owned-name-handoff.h",
    "information-battle-name-handoff-wire.h",
))
INFORMATION_BATTLE_RETREAT_SOURCES = (
    "information-battle-retreat-wire.h",
    "information-battle-owned-retreat.h",
    "information-battle-retreat-entry-plan.h",
    "information-battle-retreat-observer.inc",
)
INFORMATION_BATTLE_NAME_SOURCES_SOURCES = (
    "information-battle-owned-name-sources.h",
    "information-battle-owned-name-prefix.h",
    "information-battle-name-sources-wire.h",
)
INFORMATION_BATTLE_OUTCOME_TEXT_SOURCES = (
    "information-battle-owned-outcome-text.h",
    "information-battle-outcome-text-wire.h",
    "information-battle-outcome-text-record.h",
)
INFORMATION_BATTLE_OUTCOME_TAIL_SOURCES = (
    "information-battle-owned-outcome-tail.h",
    "information-battle-outcome-tail-wire.h",
    "information-battle-outcome-tail-record.h",
)
INFORMATION_BATTLE_CALL_TO_ARMS_SOURCES = (
    "call-to-arms-observer.inc",
)
INFORMATION_BATTLE_INDEPENDENT_LINE_SOURCES = (
    "information-battle-independent-line-wire.h",
    "information-battle-owned-independent-line.h",
    "information-battle-independent-line-plan.h",
    "format_input_builder.h",
    "format_expansion_plan.h",
)
INFORMATION_BATTLE_FLAG_INPUTS_SOURCES = (
    "information-battle-flag-input-wire.h",
    "information-battle-owned-flag-inputs.h",
)
SUPPORT_ROLE_CONTEXT_SOURCES = ("support-role-state.h",)
SUPPORT_ROLE_CONTEXT_FIELDS = (
    "support_roles_readable", "support_actor_is_subject", "support_recipient_is_subject",
)
SUPPORT_ROLE_CONTEXT_KEYS = (
    "native_support_role_context", "native_support_role_context_read_only",
    "native_support_role_context_fields",
)
COUNTRY_MODIFIER_OBSERVATION_SOURCES = (
    "information-country-modifier-add.h", "information-country-modifier-entry-plan.h",
    "information-country-modifier-observer.inc",
)
COUNTRY_MODIFIER_OBSERVATION_KEYS = (
    "native_country_modifier_add_observation", "native_country_modifier_add_wire",
    "native_country_modifier_scope",
)
COUNTRY_MODIFIER_REMOVAL_SOURCES = (
    "information-country-modifier-remove.h", "information-country-modifier-remove-entry-plan.h",
)
COUNTRY_MODIFIER_REMOVAL_KEYS = (
    "native_country_modifier_remove_observation", "native_country_modifier_remove_wire",
)
COUNTRY_MODIFIER_EXPIRY_SOURCES = (
    "information-country-modifier-expiry.h", "information-country-modifier-expiry-entry.S",
)
COUNTRY_MODIFIER_EXPIRY_KEYS = (
    "native_country_modifier_expiry_observation", "native_country_modifier_expiry_wire",
)
RIVAL_CHANGE_SOURCES = (
    "information-rival-change.h", "information-rival-observer.inc",
)
RIVAL_CHANGE_KEYS = (
    "native_rival_change_observation", "native_rival_change_wire",
    "native_rival_change_scope",
)
RIVAL_CHANGE_SCOPE = "FRA_actor_target_or_old_rival_at_three_country_command_entries"
WAR_DECLARATION_SOURCES = (
    "information-war-declaration.h", "information-war-declaration-observer.inc",
)
WAR_DECLARATION_KEYS = (
    "native_war_declaration_observation", "native_war_declaration_wire",
    "native_war_declaration_scope",
)
WAR_DECLARATION_SCOPE = "FRA_member_in_new_declared_pair_war"
WAR_REGISTRY_SOURCE = "information-war-registry.h"
RELATION_CHANGE_SOURCES = (
    "information-relation-change.h", "information-relation-observer.inc",
)
RELATION_CHANGE_KEYS = (
    "native_relation_change_observation", "native_relation_change_wire",
    "native_relation_change_scope",
)
RELATION_CHANGE_SCOPE = "FRA_pair_at_six_relation_command_returns"
MISSION_COMPLETION_SOURCES = (
    "information-mission-completion.h", "information-mission-observer.inc",
)
MISSION_COMPLETION_KEYS = (
    "native_mission_completion_observation", "native_mission_completion_wire",
    "native_mission_completion_scope",
)
MISSION_COMPLETION_SCOPE = "FRA_completed_transition_at_native_mission_command_return"
MACRO_EVENT_KEYS = frozenset(
    WAR_DECLARATION_KEYS + RELATION_CHANGE_KEYS + MISSION_COMPLETION_KEYS)
MACRO_EVENT_SOURCE_NAMES = frozenset(
    WAR_DECLARATION_SOURCES + RELATION_CHANGE_SOURCES + MISSION_COMPLETION_SOURCES)
MACRO_EVENT_ACK_SOURCE = "diplomacy-observer-v10.cpp"
MACRO_EVENT_ACK_SOURCE_BLOCKS = (
    r'''#ifdef BRIDGE_WAR_DECLARATION_OBSERVATION
            ",\"native_war_declaration_observation\":true,\"native_war_declaration_wire\":1,"
            "\"native_war_declaration_scope\":\"FRA_member_in_new_declared_pair_war\""
#endif''',
    r'''#ifdef BRIDGE_RELATION_OBSERVATION
            ",\"native_relation_change_observation\":true,\"native_relation_change_wire\":1,"
            "\"native_relation_change_scope\":\"FRA_pair_at_six_relation_command_returns\""
#endif''',
    r'''#ifdef BRIDGE_MISSION_COMPLETION_OBSERVATION
            ",\"native_mission_completion_observation\":true,\"native_mission_completion_wire\":1,"
            "\"native_mission_completion_scope\":\"FRA_completed_transition_at_native_mission_command_return\""
#endif''',
)
MACRO_EVENT_V51_VERSION_BLOCK = r'''#ifdef BRIDGE_MISSION_COMPLETION_OBSERVATION
        version_marker[sizeof("\"version\":")-1]='5';
        version_marker[sizeof("\"version\":")]='1';
#elif defined(BRIDGE_RELATION_OBSERVATION)'''
MISSION_AVAILABILITY_SOURCES = (
    "information-mission-availability.h",
    "information-mission-availability-entry-plan.h",
    "information-mission-availability-observer.inc",
)
MISSION_AVAILABILITY_KEYS = (
    "native_mission_availability_observation",
    "native_mission_availability_wire",
    "native_mission_availability_scope",
)
MISSION_AVAILABILITY_SCOPE = "FRA_native_task_eligibility_return"
MISSION_COMPLETED_SET_CAPABILITY = "native_mission_completed_set_observation"
ALLIANCE_RECORD_CAPABILITY = "native_alliance_record_observation"
ALLIANCE_RECORD_SCOPE = "FRA_pair_at_six_relation_command_or_alliance_record_returns"
MISSION_COMPLETED_SET_SCOPE = "FRA_completed_set_insert_at_command_or_effect_return"
MACRO_SOURCE_SOURCES = (
    MISSION_AVAILABILITY_SOURCES
    + ("information-mission-completed-set-entry-plan.h",
       "information-mission-completed-set-observer.inc",
       "information-alliance-record-entry-plan.h",
       "information-alliance-record-observer.inc")
)
MACRO_SOURCE_KEYS = frozenset(
    MISSION_AVAILABILITY_KEYS
    + (MISSION_COMPLETED_SET_CAPABILITY, ALLIANCE_RECORD_CAPABILITY))
MACRO_SOURCE_DEFINE_NAMES = (
    "BRIDGE_MISSION_AVAILABILITY_OBSERVATION",
    "BRIDGE_MISSION_COMPLETED_SET_OBSERVATION",
    "BRIDGE_ALLIANCE_RECORD_OBSERVATION",
)
MACRO_SOURCE_NAMES = frozenset(MACRO_SOURCE_SOURCES)
MACRO_SOURCE_RELATION_ACK_BLOCK = r'''#ifdef BRIDGE_RELATION_OBSERVATION
#ifndef BRIDGE_ALLIANCE_RECORD_OBSERVATION
            ",\"native_relation_change_observation\":true,\"native_relation_change_wire\":1,"
            "\"native_relation_change_scope\":\"FRA_pair_at_six_relation_command_returns\""
#else
            ",\"native_relation_change_observation\":true,\"native_relation_change_wire\":2,"
            "\"native_relation_change_scope\":\"FRA_pair_at_six_relation_command_or_alliance_record_returns\","
            "\"native_alliance_record_observation\":true"
#endif
#endif'''
MACRO_SOURCE_MISSION_ACK_BLOCK = r'''#ifndef BRIDGE_MISSION_COMPLETED_SET_OBSERVATION
#ifdef BRIDGE_MISSION_COMPLETION_OBSERVATION
            ",\"native_mission_completion_observation\":true,\"native_mission_completion_wire\":1,"
            "\"native_mission_completion_scope\":\"FRA_completed_transition_at_native_mission_command_return\""
#endif
#else
            ",\"native_mission_completion_observation\":true,\"native_mission_completion_wire\":2,"
            "\"native_mission_completion_scope\":\"FRA_completed_set_insert_at_command_or_effect_return\","
            "\"native_mission_completed_set_observation\":true"
#endif'''
MACRO_SOURCE_AVAILABILITY_ACK_BLOCK = r'''#ifdef BRIDGE_MISSION_AVAILABILITY_OBSERVATION
            ",\"native_mission_availability_observation\":true,\"native_mission_availability_wire\":1,"
            "\"native_mission_availability_scope\":\"FRA_native_task_eligibility_return\""
#endif'''
MACRO_SOURCE_V54_VERSION_BLOCK = r'''#ifdef BRIDGE_MISSION_AVAILABILITY_OBSERVATION
        version_marker[sizeof("\"version\":")-1]='5';
        version_marker[sizeof("\"version\":")]='2';
#endif
#ifdef BRIDGE_MISSION_COMPLETED_SET_OBSERVATION
        version_marker[sizeof("\"version\":")-1]='5';
        version_marker[sizeof("\"version\":")]='3';
#endif
#ifdef BRIDGE_ALLIANCE_RECORD_OBSERVATION
        version_marker[sizeof("\"version\":")-1]='5';
        version_marker[sizeof("\"version\":")]='4';
#endif'''
MACRO_SOURCE_V55_VERSION_BLOCK = r'''#ifdef BRIDGE_MISSION_AVAILABILITY_OBSERVATION
        version_marker[sizeof("\"version\":")-1]='5';
        version_marker[sizeof("\"version\":")]='2';
#endif
#ifdef BRIDGE_MISSION_COMPLETED_SET_OBSERVATION
        version_marker[sizeof("\"version\":")-1]='5';
        version_marker[sizeof("\"version\":")]='3';
#endif
#ifdef BRIDGE_ALLIANCE_RECORD_OBSERVATION
        version_marker[sizeof("\"version\":")-1]='5';
        version_marker[sizeof("\"version\":")]='5';
#endif'''
MISSION_CONDITION_SOURCES = (
    "information-mission-conditions.h",
    "information-mission-condition-entry-plan.h",
    "information-mission-condition-observer.inc",
)
MISSION_CONDITION_KEYS = (
    "native_mission_condition_observation",
    "native_mission_condition_wire",
    "native_mission_condition_scope",
)
MISSION_CONDITION_SCOPE = "FRA_root_conjunction_child_returns"
MISSION_CONDITION_DEFINE = "BRIDGE_MISSION_CONDITION_OBSERVATION"
MISSION_CONDITION_ACK_BLOCK = r'''#ifdef BRIDGE_MISSION_CONDITION_OBSERVATION
            ",\"native_mission_condition_observation\":true,\"native_mission_condition_wire\":1,"
            "\"native_mission_condition_scope\":\"FRA_root_conjunction_child_returns\""
#endif'''
MISSION_CONDITION_V56_VERSION_BLOCK = r'''#ifdef BRIDGE_MISSION_CONDITION_OBSERVATION
        version_marker[sizeof("\"version\":")-1]='5';
        version_marker[sizeof("\"version\":")]='6';
#endif'''
MISSION_PROVINCE_CONDITION_SOURCES = (
    "information-mission-province-conditions.h",
    "information-mission-province-entry-plan.h",
    "information-mission-province-observer.inc",
)
MISSION_PROVINCE_CONDITION_CAPABILITY = "native_mission_province_condition_observation"
MISSION_PROVINCE_CONDITION_DEFINE = "BRIDGE_MISSION_PROVINCE_CONDITION_OBSERVATION"
MISSION_PROVINCE_CONDITION_SCOPE = (
    "FRA_root_and_direct_area_province_holding_returns")
MISSION_PROVINCE_CONDITION_ACK_BLOCK = r'''#ifdef BRIDGE_MISSION_CONDITION_OBSERVATION
#ifdef BRIDGE_MISSION_PROVINCE_CONDITION_OBSERVATION
            ",\"native_mission_condition_observation\":true,\"native_mission_condition_wire\":2,"
            "\"native_mission_condition_scope\":\"FRA_root_and_direct_area_province_holding_returns\","
            "\"native_mission_province_condition_observation\":true"
#else
            ",\"native_mission_condition_observation\":true,\"native_mission_condition_wire\":1,"
            "\"native_mission_condition_scope\":\"FRA_root_conjunction_child_returns\""
#endif
#endif'''
MISSION_PROVINCE_CONDITION_ACK_BLOCK_PREFIX = (
    "#ifdef BRIDGE_MISSION_CONDITION_OBSERVATION\n"
    "#ifdef BRIDGE_MISSION_PROVINCE_CONDITION_OBSERVATION\n")
MISSION_PROVINCE_CONDITION_V57_VERSION_BLOCK = r'''#ifdef BRIDGE_MISSION_PROVINCE_CONDITION_OBSERVATION
        version_marker[sizeof("\"version\":")-1]='5';
        version_marker[sizeof("\"version\":")]='7';
#endif'''
MISSION_PROVINCE_CONDITION_VERSION_BLOCK_PREFIX = (
    "#ifdef BRIDGE_MISSION_PROVINCE_CONDITION_OBSERVATION\n"
    "        version_marker")
ROYAL_RECORD_SOURCES = (
    "information-royal-record-entry-plan.h",
    "information-royal-record-observer.inc",
)
ROYAL_RECORD_CAPABILITY = "native_royal_record_observation"
ROYAL_RECORD_DEFINE = "BRIDGE_ROYAL_RECORD_OBSERVATION"
ROYAL_RECORD_SCOPE = (
    "FRA_pair_at_six_relation_command_or_alliance_or_royal_record_returns")
DIRECTED_RECORD_SOURCES = (
    "information-directed-record-entry-plan.h",
    "information-directed-record-observer.inc",
)
DIRECTED_RECORD_CAPABILITY = "native_directed_record_observation"
DIRECTED_RECORD_DEFINE = "BRIDGE_DIRECTED_RECORD_OBSERVATION"
DIRECTED_RECORD_SCOPE = (
    "FRA_pair_at_six_relation_command_or_alliance_or_royal_or_directed_record_returns")
SUPPORT_SUBJECT_RECORD_SOURCES = (
    "information-support-subject-record-entry-plan.h",
    "information-support-subject-record-observer.inc",
)
SUPPORT_SUBJECT_RECORD_CAPABILITY = "native_support_subject_record_observation"
SUPPORT_SUBJECT_RECORD_DEFINE = "BRIDGE_SUPPORT_SUBJECT_RECORD_OBSERVATION"
SUPPORT_SUBJECT_RECORD_SCOPE = (
    "FRA_pair_at_six_relation_command_or_six_family_record_returns")
ROYAL_RECORD_RELATION_ACK_BLOCK = r'''#ifdef BRIDGE_RELATION_OBSERVATION
#ifdef BRIDGE_ROYAL_RECORD_OBSERVATION
            ",\"native_relation_change_observation\":true,\"native_relation_change_wire\":3,"
            "\"native_relation_change_scope\":\"FRA_pair_at_six_relation_command_or_alliance_or_royal_record_returns\","
            "\"native_alliance_record_observation\":true,\"native_royal_record_observation\":true"
#elif !defined(BRIDGE_ALLIANCE_RECORD_OBSERVATION)
            ",\"native_relation_change_observation\":true,\"native_relation_change_wire\":1,"
            "\"native_relation_change_scope\":\"FRA_pair_at_six_relation_command_returns\""
#else
            ",\"native_relation_change_observation\":true,\"native_relation_change_wire\":2,"
            "\"native_relation_change_scope\":\"FRA_pair_at_six_relation_command_or_alliance_record_returns\","
            "\"native_alliance_record_observation\":true"
#endif
#endif'''
ROYAL_RECORD_RELATION_ACK_PREFIX = (
    "#ifdef BRIDGE_RELATION_OBSERVATION\n"
    "#ifdef BRIDGE_ROYAL_RECORD_OBSERVATION\n")
DIRECTED_RECORD_RELATION_ACK_BLOCK = r'''#ifdef BRIDGE_RELATION_OBSERVATION
#ifdef BRIDGE_DIRECTED_RECORD_OBSERVATION
            ",\"native_relation_change_observation\":true,\"native_relation_change_wire\":4,"
            "\"native_relation_change_scope\":\"FRA_pair_at_six_relation_command_or_alliance_or_royal_or_directed_record_returns\","
            "\"native_alliance_record_observation\":true,\"native_royal_record_observation\":true,\"native_directed_record_observation\":true"
#elif defined(BRIDGE_ROYAL_RECORD_OBSERVATION)
            ",\"native_relation_change_observation\":true,\"native_relation_change_wire\":3,"
            "\"native_relation_change_scope\":\"FRA_pair_at_six_relation_command_or_alliance_or_royal_record_returns\","
            "\"native_alliance_record_observation\":true,\"native_royal_record_observation\":true"
#elif !defined(BRIDGE_ALLIANCE_RECORD_OBSERVATION)
            ",\"native_relation_change_observation\":true,\"native_relation_change_wire\":1,"
            "\"native_relation_change_scope\":\"FRA_pair_at_six_relation_command_returns\""
#else
            ",\"native_relation_change_observation\":true,\"native_relation_change_wire\":2,"
            "\"native_relation_change_scope\":\"FRA_pair_at_six_relation_command_or_alliance_record_returns\","
            "\"native_alliance_record_observation\":true"
#endif
#endif'''
DIRECTED_RECORD_RELATION_ACK_PREFIX = (
    "#ifdef BRIDGE_RELATION_OBSERVATION\n"
    "#ifdef BRIDGE_DIRECTED_RECORD_OBSERVATION\n")
ROYAL_RECORD_V58_VERSION_BLOCK = r'''#ifdef BRIDGE_ROYAL_RECORD_OBSERVATION
        version_marker[sizeof("\"version\":")-1]='5';
        version_marker[sizeof("\"version\":")]='8';
#endif'''
ROYAL_RECORD_VERSION_BLOCK_PREFIX = (
    "#ifdef BRIDGE_ROYAL_RECORD_OBSERVATION\n"
    "        version_marker")
DIRECTED_RECORD_V59_VERSION_BLOCK = r'''#ifdef BRIDGE_DIRECTED_RECORD_OBSERVATION
        version_marker[sizeof("\"version\":")-1]='5';
        version_marker[sizeof("\"version\":")]='9';
#elif defined(BRIDGE_ROYAL_RECORD_OBSERVATION)
        version_marker[sizeof("\"version\":")-1]='5';
        version_marker[sizeof("\"version\":")]='8';
#endif'''
DIRECTED_RECORD_VERSION_BLOCK_PREFIX = (
    "#ifdef BRIDGE_DIRECTED_RECORD_OBSERVATION\n"
    "        version_marker")
SUPPORT_SUBJECT_RECORD_RELATION_ACK_BLOCK = r'''#ifdef BRIDGE_RELATION_OBSERVATION
#ifdef BRIDGE_SUPPORT_SUBJECT_RECORD_OBSERVATION
            ",\"native_relation_change_observation\":true,\"native_relation_change_wire\":5,"
            "\"native_relation_change_scope\":\"FRA_pair_at_six_relation_command_or_six_family_record_returns\","
            "\"native_alliance_record_observation\":true,\"native_royal_record_observation\":true,\"native_directed_record_observation\":true,\"native_support_subject_record_observation\":true"
#elif defined(BRIDGE_DIRECTED_RECORD_OBSERVATION)
            ",\"native_relation_change_observation\":true,\"native_relation_change_wire\":4,"
            "\"native_relation_change_scope\":\"FRA_pair_at_six_relation_command_or_alliance_or_royal_or_directed_record_returns\","
            "\"native_alliance_record_observation\":true,\"native_royal_record_observation\":true,\"native_directed_record_observation\":true"
#elif defined(BRIDGE_ROYAL_RECORD_OBSERVATION)
            ",\"native_relation_change_observation\":true,\"native_relation_change_wire\":3,"
            "\"native_relation_change_scope\":\"FRA_pair_at_six_relation_command_or_alliance_or_royal_record_returns\","
            "\"native_alliance_record_observation\":true,\"native_royal_record_observation\":true"
#elif !defined(BRIDGE_ALLIANCE_RECORD_OBSERVATION)
            ",\"native_relation_change_observation\":true,\"native_relation_change_wire\":1,"
            "\"native_relation_change_scope\":\"FRA_pair_at_six_relation_command_returns\""
#else
            ",\"native_relation_change_observation\":true,\"native_relation_change_wire\":2,"
            "\"native_relation_change_scope\":\"FRA_pair_at_six_relation_command_or_alliance_record_returns\","
            "\"native_alliance_record_observation\":true"
#endif
#endif'''
SUPPORT_SUBJECT_RECORD_RELATION_ACK_PREFIX = (
    "#ifdef BRIDGE_RELATION_OBSERVATION\n"
    "#ifdef BRIDGE_SUPPORT_SUBJECT_RECORD_OBSERVATION\n")
DIRECTED_RECORD_RELATION_ACK_BRANCH = r'''#elif defined(BRIDGE_DIRECTED_RECORD_OBSERVATION)
            ",\"native_relation_change_observation\":true,\"native_relation_change_wire\":4,"
            "\"native_relation_change_scope\":\"FRA_pair_at_six_relation_command_or_alliance_or_royal_or_directed_record_returns\","
            "\"native_alliance_record_observation\":true,\"native_royal_record_observation\":true,\"native_directed_record_observation\":true"'''
DIRECTED_RECORD_RELATION_ACK_BRANCH_PREFIX = (
    "#elif defined(BRIDGE_DIRECTED_RECORD_OBSERVATION)\n")
ROYAL_RECORD_RELATION_ACK_BRANCH = r'''#elif defined(BRIDGE_ROYAL_RECORD_OBSERVATION)
            ",\"native_relation_change_observation\":true,\"native_relation_change_wire\":3,"
            "\"native_relation_change_scope\":\"FRA_pair_at_six_relation_command_or_alliance_or_royal_record_returns\","
            "\"native_alliance_record_observation\":true,\"native_royal_record_observation\":true"'''
ROYAL_RECORD_RELATION_ACK_BRANCH_PREFIX = (
    "#elif defined(BRIDGE_ROYAL_RECORD_OBSERVATION)\n")
SUPPORT_SUBJECT_RECORD_V60_VERSION_BLOCK = r'''#ifdef BRIDGE_SUPPORT_SUBJECT_RECORD_OBSERVATION
        version_marker[sizeof("\"version\":")-1]='6';
        version_marker[sizeof("\"version\":")]='0';
#elif defined(BRIDGE_DIRECTED_RECORD_OBSERVATION)
        version_marker[sizeof("\"version\":")-1]='5';
        version_marker[sizeof("\"version\":")]='9';
#elif defined(BRIDGE_ROYAL_RECORD_OBSERVATION)
        version_marker[sizeof("\"version\":")-1]='5';
        version_marker[sizeof("\"version\":")]='8';
#endif'''
SUPPORT_SUBJECT_RECORD_VERSION_BLOCK_PREFIX = (
    "#ifdef BRIDGE_SUPPORT_SUBJECT_RECORD_OBSERVATION\n"
    "        version_marker")
RIVAL_RECORD_SOURCES = (
    "information-rival-record-entry-plan.h", "information-rival-record-observer.inc",
)
RIVAL_RECORD_DEFINE = "BRIDGE_RIVAL_RECORD_OBSERVATION"
RIVAL_RECORD_CAPABILITY = "native_rival_record_observation"
RIVAL_RECORD_SCOPE = "FRA_actor_target_or_old_rival_at_command_or_country_rival_record_returns"
RIVAL_RECORD_COUNT_BASIS = "active_nonretired_nodes"
RIVAL_RECORD_ACK_BLOCK = r'''#ifdef BRIDGE_RIVAL_OBSERVATION
#ifdef BRIDGE_RIVAL_RECORD_OBSERVATION
            ",\"native_rival_change_observation\":true,\"native_rival_change_wire\":2,"
            "\"native_rival_change_scope\":\"FRA_actor_target_or_old_rival_at_command_or_country_rival_record_returns\","
            "\"native_rival_record_observation\":true,\"native_rival_record_count_basis\":\"active_nonretired_nodes\""
#else
            ",\"native_rival_change_observation\":true,\"native_rival_change_wire\":1,"
            "\"native_rival_change_scope\":\"FRA_actor_target_or_old_rival_at_three_country_command_entries\""
#endif
#endif'''
RIVAL_RECORD_ACK_PREFIX = (
    "#ifdef BRIDGE_RIVAL_OBSERVATION\n#ifdef BRIDGE_RIVAL_RECORD_OBSERVATION\n"
    r'''            ",\"native_rival_change_observation\":true,''')
RIVAL_RECORD_VERSION_PREFIX = "#ifdef BRIDGE_RIVAL_RECORD_OBSERVATION\n        version_marker"
RIVAL_RECORD_V61_VERSION_BLOCK = (
    r'''#ifdef BRIDGE_RIVAL_RECORD_OBSERVATION
        version_marker[sizeof("\"version\":")-1]='6';
        version_marker[sizeof("\"version\":")]='1';
#elif defined(BRIDGE_SUPPORT_SUBJECT_RECORD_OBSERVATION)
''' + SUPPORT_SUBJECT_RECORD_V60_VERSION_BLOCK.split("\n", 1)[1])
EXPIRY_V62_VERSION_PREFIX = (
    "#if defined(BRIDGE_SUBSIDY_EXPIRY_OBSERVATION) || defined(BRIDGE_TRUCE_EXPIRY_OBSERVATION)\n"
    "        version_marker")
EXPIRY_V62_VERSION_BLOCK = (
    r'''#if defined(BRIDGE_SUBSIDY_EXPIRY_OBSERVATION) || defined(BRIDGE_TRUCE_EXPIRY_OBSERVATION)
        version_marker[sizeof("\"version\":")-1]='6';
        version_marker[sizeof("\"version\":")]='2';
#elif defined(BRIDGE_RIVAL_RECORD_OBSERVATION)
''' + RIVAL_RECORD_V61_VERSION_BLOCK.split("\n", 1)[1])
CLAIM_V63_VERSION_PREFIX = "#if defined(BRIDGE_CLAIM_EXPIRY_OBSERVATION)\n        version_marker"
CLAIM_V63_VERSION_BLOCK = (
    r'''#if defined(BRIDGE_CLAIM_EXPIRY_OBSERVATION)
        version_marker[sizeof("\"version\":")-1]='6';
        version_marker[sizeof("\"version\":")]='3';
#elif defined(BRIDGE_SUBSIDY_EXPIRY_OBSERVATION) || defined(BRIDGE_TRUCE_EXPIRY_OBSERVATION)
''' + EXPIRY_V62_VERSION_BLOCK.split("\n", 1)[1])
LAND_PROMISE_V64_VERSION_PREFIX = "#if defined(BRIDGE_LAND_PROMISE_OBSERVATION)\n        version_marker"
LAND_PROMISE_V64_VERSION_BLOCK = (
    r'''#if defined(BRIDGE_LAND_PROMISE_OBSERVATION)
        version_marker[sizeof("\"version\":")-1]='6';
        version_marker[sizeof("\"version\":")]='4';
#elif defined(BRIDGE_CLAIM_EXPIRY_OBSERVATION)
''' + CLAIM_V63_VERSION_BLOCK.split("\n", 1)[1])
SUBSIDY_EXPIRY_ACK_BLOCK = r'''#ifdef BRIDGE_SUBSIDY_EXPIRY_OBSERVATION
    {
        char* end=strrchr(message,'}');
        if (end) snprintf(end,sizeof(message)-static_cast<size_t>(end-message),
            ",\"native_subsidy_expiry_observation\":true,\"native_subsidy_expiry_wire\":1}\n");
    }
#endif'''
TRUCE_EXPIRY_ACK_BLOCK = r'''#ifdef BRIDGE_TRUCE_EXPIRY_OBSERVATION
    {
        char* end=strrchr(message,'}');
        if (end) snprintf(end,sizeof(message)-static_cast<size_t>(end-message),
            ",\"native_truce_expiry_observation\":true,\"native_truce_expiry_wire\":1,"
            "\"native_truce_expiry_scope\":\"FRA_actor_or_recipient_directional_direct_truce_expiry_returns\"}\n");
    }
#endif'''
CLAIM_EXPIRY_ACK_BLOCK = r'''#ifdef BRIDGE_CLAIM_EXPIRY_OBSERVATION
    {
        char* end=strrchr(message,'}');
        if (end) snprintf(end,sizeof(message)-static_cast<size_t>(end-message),
            ",\"native_claim_expiry_observation\":true,\"native_claim_expiry_wire\":1,"
            "\"native_claim_expiry_scope\":\"FRA_claimant_or_current_owner_at_native_claim_expiry_remove_return\"}\n");
    }
#endif'''
EXPIRY_FEATURES = (
    {"prefix": "information-subsidy-expiry", "define": "BRIDGE_SUBSIDY_EXPIRY_OBSERVATION",
     "capability": "native_subsidy_expiry_observation", "wire": "native_subsidy_expiry_wire",
     "scope_key": "native_subsidy_expiry_scope",
     "scope": "FRA_payer_or_recipient_at_subsidy_expiry_remove_return", "ack": SUBSIDY_EXPIRY_ACK_BLOCK},
    {"prefix": "information-truce-expiry", "define": "BRIDGE_TRUCE_EXPIRY_OBSERVATION",
     "capability": "native_truce_expiry_observation", "wire": "native_truce_expiry_wire",
     "scope_key": "native_truce_expiry_scope",
     "scope": "FRA_actor_or_recipient_directional_direct_truce_expiry_returns", "ack": TRUCE_EXPIRY_ACK_BLOCK},
)
CLAIM_EXPIRY_FEATURE = {
    "prefix": "information-claim-expiry", "define": "BRIDGE_CLAIM_EXPIRY_OBSERVATION",
    "capability": "native_claim_expiry_observation", "wire": "native_claim_expiry_wire",
    "scope_key": "native_claim_expiry_scope",
    "scope": "FRA_claimant_or_current_owner_at_native_claim_expiry_remove_return", "ack": CLAIM_EXPIRY_ACK_BLOCK,
}
LAND_PROMISE_ACK_BLOCK = r'''#ifdef BRIDGE_LAND_PROMISE_OBSERVATION
    {
        char* end=strrchr(message,'}');
        if (end) snprintf(end,sizeof(message)-static_cast<size_t>(end-message),
            ",\"native_land_promise_observation\":true,\"native_land_promise_wire\":1,"
            "\"native_land_promise_scope\":\"FRA_member_in_observed_promise_war\"}\n");
    }
#endif'''
LAND_PROMISE_FEATURE = {
    "prefix": "information-land-promise", "define": "BRIDGE_LAND_PROMISE_OBSERVATION",
    "capability": "native_land_promise_observation", "wire": "native_land_promise_wire",
    "scope_key": "native_land_promise_scope", "scope": "FRA_member_in_observed_promise_war",
    "ack": LAND_PROMISE_ACK_BLOCK, "suffixes": (".h", "-native-guards.h", "-observer.inc"),
}


def _has_rival_record_features(manifest: dict) -> bool:
    records = manifest.get("sources", [])
    return (RIVAL_RECORD_CAPABILITY in manifest
            or "native_rival_record_count_basis" in manifest
            or bool(_compiler_define_values(
                manifest.get("compiler_arguments"), RIVAL_RECORD_DEFINE))
            or (isinstance(records, list) and any(
                isinstance(row, dict) and isinstance(row.get("name"), str)
                and row["name"].startswith("information-rival-record-") for row in records)))


def _v63_source_selector(text: str) -> str:
    """Validate and project the optional v64 selector to its v63 parent."""
    count = text.count(LAND_PROMISE_V64_VERSION_BLOCK)
    if count != text.count(LAND_PROMISE_V64_VERSION_PREFIX) or count > 1:
        raise SystemExit("BUILD_MANIFEST_MISMATCH")
    return text.replace(LAND_PROMISE_V64_VERSION_BLOCK, CLAIM_V63_VERSION_BLOCK)


def _v62_source_selector(text: str) -> str:
    """Validate and project the optional v63 selector to its v62 parent."""
    text = _v63_source_selector(text)
    count = text.count(CLAIM_V63_VERSION_BLOCK)
    if count != text.count(CLAIM_V63_VERSION_PREFIX) or count > 1:
        raise SystemExit("BUILD_MANIFEST_MISMATCH")
    return text.replace(CLAIM_V63_VERSION_BLOCK, EXPIRY_V62_VERSION_BLOCK)


def _legacy_version_selector(text: str, *, required: bool = False) -> str:
    """Project the closed v64 through v61 selectors for inherited ACK checks."""
    text = _v62_source_selector(text)
    expiry_count = text.count(EXPIRY_V62_VERSION_BLOCK)
    if expiry_count != text.count(EXPIRY_V62_VERSION_PREFIX) or expiry_count > 1:
        raise SystemExit("BUILD_MANIFEST_MISMATCH")
    text = text.replace(EXPIRY_V62_VERSION_BLOCK, RIVAL_RECORD_V61_VERSION_BLOCK)
    count = text.count(RIVAL_RECORD_V61_VERSION_BLOCK)
    prefixes = text.count(RIVAL_RECORD_VERSION_PREFIX)
    if count != prefixes or count > 1 or (required and count != 1):
        raise SystemExit("BUILD_MANIFEST_MISMATCH")
    return text.replace(RIVAL_RECORD_V61_VERSION_BLOCK, SUPPORT_SUBJECT_RECORD_V60_VERSION_BLOCK)


def _has_expiry_feature(manifest: dict, feature: dict) -> bool:
    records = manifest.get("sources", [])
    return (any(key in manifest for key in (feature["capability"], feature["wire"], feature["scope_key"]))
            or bool(_compiler_define_values(manifest.get("compiler_arguments"), feature["define"]))
            or (isinstance(records, list) and any(
                isinstance(row, dict) and isinstance(row.get("name"), str)
                and row["name"].startswith(feature["prefix"]) for row in records)))


def _validate_expiry_manifest(manifest: dict, directory: Path) -> None:
    records, arguments = manifest.get("sources"), manifest.get("compiler_arguments")
    if not isinstance(records, list) or not isinstance(arguments, list):
        raise SystemExit("BUILD_MANIFEST_MISMATCH")
    version = manifest.get("version")
    features = {64: (LAND_PROMISE_FEATURE,), 63: (CLAIM_EXPIRY_FEATURE,), 62: EXPIRY_FEATURES}[version]
    parents = {64: (*EXPIRY_FEATURES, CLAIM_EXPIRY_FEATURE), 63: EXPIRY_FEATURES, 62: ()}[version]
    if any(manifest.get(feature["capability"]) is not True for feature in parents):
        raise SystemExit("BUILD_MANIFEST_MISMATCH")
    selected = [feature for feature in features if _has_expiry_feature(manifest, feature)]
    if not selected:
        raise SystemExit("BUILD_MANIFEST_MISMATCH")
    try:
        source = directory / MACRO_EVENT_ACK_SOURCE
        if source.stat().st_size > 4 * 1024 * 1024:
            raise SystemExit("BUILD_MANIFEST_MISMATCH")
        text = source.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        raise SystemExit("BUILD_MANIFEST_MISMATCH")
    selector = {64: LAND_PROMISE_V64_VERSION_BLOCK, 63: CLAIM_V63_VERSION_BLOCK,
                62: EXPIRY_V62_VERSION_BLOCK}[version]
    selector_text = {64: lambda value: value, 63: _v63_source_selector, 62: _v62_source_selector}[version](text)
    if selector_text.count(selector) != 1:
        raise SystemExit("BUILD_MANIFEST_MISMATCH")
    inherited = dict(manifest, version=version - 1)
    inherited["sources"] = list(records)
    inherited["compiler_arguments"] = list(arguments)
    for feature in selected:
        if (manifest.get(feature["capability"]) is not True
                or type(manifest.get(feature["wire"])) is not int or manifest[feature["wire"]] != 1
                or manifest.get(feature["scope_key"]) != feature["scope"]
                or _compiler_define_values(arguments, feature["define"]) != ["1"]
                or text.count(feature["ack"]) != 1
                or text.count('\\"' + feature["capability"] + '\\":true') != 1):
            raise SystemExit("BUILD_MANIFEST_MISMATCH")
        suffixes = feature.get("suffixes", (".h", "-entry-plan.h", "-native-guards.h", "-observer.inc"))
        names = {feature["prefix"] + suffix for suffix in suffixes}
        for name in names:
            rows = [row for row in records if isinstance(row, dict) and row.get("name") == name]
            if (len(rows) != 1 or not _is_sha256(rows[0].get("sha256"))
                    or not (directory / name).is_file()
                    or file_hash(directory / name, refresh=True) != rows[0]["sha256"].lower()):
                raise SystemExit("BUILD_MANIFEST_MISMATCH")
        inherited["sources"] = [row for row in inherited["sources"]
                                if not isinstance(row, dict) or row.get("name") not in names]
        for key in (feature["capability"], feature["wire"], feature["scope_key"]):
            inherited.pop(key)
        inherited_arguments = inherited["compiler_arguments"]
        for index, value in enumerate(inherited_arguments):
            if value == "-D" + feature["define"] + "=1":
                del inherited_arguments[index]
                break
            if (value == "-D" and index + 1 < len(inherited_arguments)
                    and inherited_arguments[index + 1] == feature["define"] + "=1"):
                del inherited_arguments[index:index + 2]
                break
    _validate_information_battle_manifest(inherited, directory)


def _validate_rival_record_manifest(manifest: dict, directory: Path) -> None:
    records = manifest.get("sources")
    arguments = manifest.get("compiler_arguments")
    if (not isinstance(records, list)
            or manifest.get(RIVAL_RECORD_CAPABILITY) is not True
            or type(manifest.get("native_rival_change_wire")) is not int
            or manifest["native_rival_change_wire"] != 2
            or manifest.get("native_rival_change_scope") != RIVAL_RECORD_SCOPE
            or manifest.get("native_rival_record_count_basis") != RIVAL_RECORD_COUNT_BASIS
            or _compiler_define_values(arguments, RIVAL_RECORD_DEFINE) != ["1"]
            or manifest.get("prototype_only") is not False
            or manifest.get("formal_installation_admitted") is not True):
        raise SystemExit("BUILD_MANIFEST_MISMATCH")
    for name in RIVAL_RECORD_SOURCES:
        rows = [row for row in records if isinstance(row, dict) and row.get("name") == name]
        if (len(rows) != 1 or not _is_sha256(rows[0].get("sha256"))
                or not (directory / name).is_file()
                or file_hash(directory / name, refresh=True) != rows[0]["sha256"].lower()):
            raise SystemExit("BUILD_MANIFEST_MISMATCH")
    try:
        source = directory / MACRO_EVENT_ACK_SOURCE
        if source.stat().st_size > 4 * 1024 * 1024:
            raise SystemExit("BUILD_MANIFEST_MISMATCH")
        text = source.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        raise SystemExit("BUILD_MANIFEST_MISMATCH")
    if text.count(RIVAL_RECORD_ACK_BLOCK) != 1 or text.count(RIVAL_RECORD_ACK_PREFIX) != 1:
        raise SystemExit("BUILD_MANIFEST_MISMATCH")
    _legacy_version_selector(text, required=True)
    # The new two-file extension is checked above. The complete v60 contract
    # validates inherited source names/counts, including the registry header,
    # as well as every flag and ACK branch.
    inherited = dict(manifest, version=60, native_rival_change_wire=1,
                     native_rival_change_scope=RIVAL_CHANGE_SCOPE)
    inherited.pop(RIVAL_RECORD_CAPABILITY)
    inherited.pop("native_rival_record_count_basis")
    inherited["sources"] = [row for row in records if not isinstance(row, dict)
                            or row.get("name") not in RIVAL_RECORD_SOURCES]
    inherited_arguments = list(arguments)
    for index, value in enumerate(arguments):
        if value == "-D" + RIVAL_RECORD_DEFINE + "=1":
            del inherited_arguments[index]
            break
        if (value == "-D" and index + 1 < len(arguments)
                and arguments[index + 1] == RIVAL_RECORD_DEFINE + "=1"):
            del inherited_arguments[index:index + 2]
            break
    inherited["compiler_arguments"] = inherited_arguments
    _validate_information_battle_manifest(inherited, directory)
DIRECTED_RECORD_V59_VERSION_BRANCH = r'''#elif defined(BRIDGE_DIRECTED_RECORD_OBSERVATION)
        version_marker[sizeof("\"version\":")-1]='5';
        version_marker[sizeof("\"version\":")]='9';'''
DIRECTED_RECORD_V59_VERSION_BRANCH_PREFIX = (
    "#elif defined(BRIDGE_DIRECTED_RECORD_OBSERVATION)\n"
    "        version_marker")
ROYAL_RECORD_V58_VERSION_BRANCH = r'''#elif defined(BRIDGE_ROYAL_RECORD_OBSERVATION)
        version_marker[sizeof("\"version\":")-1]='5';
        version_marker[sizeof("\"version\":")]='8';'''
ROYAL_RECORD_V58_VERSION_BRANCH_PREFIX = (
    "#elif defined(BRIDGE_ROYAL_RECORD_OBSERVATION)\n"
    "        version_marker")
INFORMATION_BATTLE_NAME_HANDOFF_SOURCES = (
    "information-battle-name-handoff-observer-stub.S",
    "information-battle-name-handoff-entry-plan.h",
    "information-battle-owned-name-handoff.h",
    "information-battle-name-handoff-wire.h",
    "information-battle-name-handoff-callsite-guards.inc",
)
INFORMATION_BATTLE_NAME_HANDOFF_REQUIRED_SOURCES = (
    INFORMATION_BATTLE_DISPLAY_CONTEXT_REQUIRED_SOURCES
    + INFORMATION_DEBT_QUOTE_REQUIRED_SOURCES
    + INFORMATION_BATTLE_NAME_HANDOFF_SOURCES
)
INFORMATION_CURRENT_COUNTRY_CONTROL_ONLY_SOURCES = (
    "information-current-country-control.inc",
    "information-current-country-control-plan.h",
    "information-current-country-control-policy.h",
)
INFORMATION_CURRENT_COUNTRY_CONTROL_REQUIRED_SOURCES = (
    INFORMATION_BATTLE_NATIVE_TITLE_QUERY_REQUIRED_SOURCES
    + INFORMATION_CURRENT_COUNTRY_CONTROL_ONLY_SOURCES
)
_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")


def _is_sha256(value: object) -> bool:
    return (isinstance(value, str) and len(value) == 64
            and all(character in _HEX_DIGITS for character in value))


def _has_compiler_define(arguments: object, macro: str) -> bool:
    if not isinstance(arguments, list):
        return False
    direct = "-D" + macro
    for index, value in enumerate(arguments):
        if not isinstance(value, str):
            continue
        if value == direct or value.startswith(direct + "="):
            return True
        if value == "-D" and index + 1 < len(arguments):
            following = arguments[index + 1]
            if (isinstance(following, str)
                    and (following == macro or following.startswith(macro + "="))):
                return True
    return False


def _compiler_define_values(arguments: object, macro: str) -> list[str | None]:
    """Return every explicit value for one -D macro, including split forms."""
    if not isinstance(arguments, list):
        return []
    result: list[str | None] = []
    prefix = "-D" + macro
    for index, item in enumerate(arguments):
        if not isinstance(item, str):
            continue
        define = item
        if item == "-D" and index + 1 < len(arguments):
            following = arguments[index + 1]
            if isinstance(following, str):
                define = "-D" + following
            else:
                continue
        if define == prefix:
            result.append(None)
        elif define.startswith(prefix + "="):
            result.append(define[len(prefix) + 1:])
    return result


def _validate_information_battle_manifest(manifest: dict, directory: Path) -> None:
    """Require complete, self-pinned source sets through v63.

    Each information-battle version is accepted only when the build explicitly
    declares the research lifecycle and its complete source set is present both
    by name and by hash in the manifest.  This remains a manifest/file check;
    it does not enable business capture or imply B01--B04 availability.
    """
    interest_source = 'territorial-interest-query.inc'
    records = manifest.get('sources', [])
    interest_rows = [row for row in records if isinstance(row, dict)
                     and row.get('name') == interest_source] if isinstance(records, list) else []
    if (interest_rows or 'native_territorial_interest_query' in manifest
            or 'native_territorial_interest_query_wire' in manifest):
        if (len(interest_rows) != 1 or manifest.get('native_territorial_interest_query') is not True
                or type(manifest.get('native_territorial_interest_query_wire')) is not int
                or manifest['native_territorial_interest_query_wire'] != 23
                or not _is_sha256(interest_rows[0].get('sha256'))
                or not (directory / interest_source).is_file()
                or file_hash(directory / interest_source, refresh=True) != interest_rows[0]['sha256'].lower()):
            raise SystemExit('BUILD_MANIFEST_MISMATCH')
        inherited = dict(manifest)
        inherited['sources'] = [row for row in records if row not in interest_rows]
        inherited.pop('native_territorial_interest_query')
        inherited.pop('native_territorial_interest_query_wire')
        _validate_information_battle_manifest(inherited, directory)
        return
    version = manifest.get("version")
    if type(version) is int and version == 64:
        _validate_expiry_manifest(manifest, directory)
        return
    if _has_expiry_feature(manifest, LAND_PROMISE_FEATURE):
        raise SystemExit("BUILD_MANIFEST_MISMATCH")
    if type(version) is int and version == 63:
        _validate_expiry_manifest(manifest, directory)
        return
    if _has_expiry_feature(manifest, CLAIM_EXPIRY_FEATURE):
        raise SystemExit("BUILD_MANIFEST_MISMATCH")
    if type(version) is int and version == 62:
        _validate_expiry_manifest(manifest, directory)
        return
    if any(_has_expiry_feature(manifest, feature) for feature in EXPIRY_FEATURES):
        raise SystemExit("BUILD_MANIFEST_MISMATCH")
    if type(version) is int and version == 61:
        _validate_rival_record_manifest(manifest, directory)
        return
    if _has_rival_record_features(manifest):
        raise SystemExit("BUILD_MANIFEST_MISMATCH")
    if type(version) is not int or version not in (23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 51, 54, 55, 56, 57, 58, 59, 60):
        raise SystemExit("BUILD_MANIFEST_MISMATCH")
    if version == 51 and (
            ("deployment_admission_verified" in manifest
             and manifest["deployment_admission_verified"] is not True)
            or manifest.get("prototype_only", False) is not False):
        raise SystemExit("BUILD_MANIFEST_MISMATCH")
    if manifest.get("information_battle_research_lifecycle") is not True:
        raise SystemExit("BUILD_MANIFEST_MISMATCH")
    required_names = INFORMATION_BATTLE_REQUIRED_SOURCES
    if version in (24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 51, 54, 55, 56, 57, 58, 59, 60):
        if (type(manifest.get("information_battle_context_wire")) is not int
                or manifest["information_battle_context_wire"] != 2
                or manifest.get("information_battle_owned_context") is not True):
            raise SystemExit("BUILD_MANIFEST_MISMATCH")
        arguments = manifest.get("compiler_arguments")
        if (not isinstance(arguments, list)
                or "-DINFORMATION_BATTLE_CONTEXT=1" not in arguments
                or "-DBRIDGE_INFORMATION_BATTLE=1" not in arguments):
            raise SystemExit("BUILD_MANIFEST_MISMATCH")
        required_names = INFORMATION_BATTLE_CONTEXT_REQUIRED_SOURCES
    if version in (25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 51, 54, 55, 56, 57, 58, 59, 60):
        if (manifest.get("information_battle_naval_wire") != 3
                or type(manifest.get("information_battle_naval_wire")) is not int
                or manifest.get("information_battle_owned_naval") is not True
                or "-DINFORMATION_BATTLE_NAVAL=1" not in manifest.get("compiler_arguments", [])):
            raise SystemExit("BUILD_MANIFEST_MISMATCH")
        required_names = INFORMATION_BATTLE_NAVAL_REQUIRED_SOURCES
    if version in (26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 51, 54, 55, 56, 57, 58, 59, 60):
        arguments = manifest.get("compiler_arguments")
        if (type(manifest.get("information_battle_template_wire")) is not int
                or manifest["information_battle_template_wire"] != 4
                or manifest.get("information_battle_owned_template") is not True
                or manifest.get("information_battle_message_scope") is not True
                or not isinstance(arguments, list)
                or "-DINFORMATION_BATTLE_TEMPLATE=1" not in arguments):
            raise SystemExit("BUILD_MANIFEST_MISMATCH")
        required_names = INFORMATION_BATTLE_TEMPLATE_REQUIRED_SOURCES
    if version in (27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 51, 54, 55, 56, 57, 58, 59, 60):
        arguments = manifest.get("compiler_arguments")
        if (manifest.get("information_battle_formatter_container") is not True
                or manifest.get("information_battle_template_extensions") != [1, 2]
                or not isinstance(arguments, list)
                or "-DINFORMATION_BATTLE_CONTAINER=1" not in arguments):
            raise SystemExit("BUILD_MANIFEST_MISMATCH")
        required_names = INFORMATION_BATTLE_CONTAINER_REQUIRED_SOURCES
    if version in (28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 51, 54, 55, 56, 57, 58, 59, 60):
        arguments = manifest.get("compiler_arguments")
        if (manifest.get("information_battle_war_identity") is not True
                or manifest.get("information_battle_war_identity_wire") != 5
                or manifest.get("information_battle_war_identity_scope") != "observer_session"
                or manifest.get("information_battle_war_identity_read_only") is not True
                or manifest.get("information_battle_war_identity_complete") is not False
                or not isinstance(arguments, list)
                or "-DINFORMATION_BATTLE_WAR_IDENTITY=1" not in arguments):
            raise SystemExit("BUILD_MANIFEST_MISMATCH")
        required_names = INFORMATION_BATTLE_WAR_IDENTITY_REQUIRED_SOURCES
    if version in (29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 51, 54, 55, 56, 57, 58, 59, 60):
        arguments = manifest.get("compiler_arguments")
        if (manifest.get("information_battle_native_text") is not True
                or manifest.get("information_battle_native_text_wire") != 6
                or manifest.get("information_battle_native_text_scope") != "observer_session"
                or manifest.get("information_battle_native_text_read_only") is not True
                or manifest.get("information_battle_native_text_complete") is not False
                or not isinstance(arguments, list)
                or "-DINFORMATION_BATTLE_NATIVE_TEXT=1" not in arguments):
            raise SystemExit("BUILD_MANIFEST_MISMATCH")
        required_names = INFORMATION_BATTLE_NATIVE_TEXT_REQUIRED_SOURCES
    if version in (30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 51, 54, 55, 56, 57, 58, 59, 60):
        arguments = manifest.get("compiler_arguments")
        expected_title_query = version not in (38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 51, 54, 55, 56, 57, 58, 59, 60)
        expected_title_mode = ("cached_sources_no_helper_invoke" if version in (38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 51, 54, 55, 56, 57, 58, 59, 60)
                               else "native_helper_owned_output")
        if (manifest.get("information_battle_native_title_query") is not expected_title_query
                or manifest.get("information_battle_native_title_query_mode")
                    != expected_title_mode
                or manifest.get("information_battle_native_title_query_wire") != 6
                or manifest.get("information_battle_native_title_query_complete") is not False
                or not isinstance(arguments, list)
                or "-DINFORMATION_BATTLE_NATIVE_TITLE_QUERY=1" not in arguments):
            raise SystemExit("BUILD_MANIFEST_MISMATCH")
        required_names = INFORMATION_BATTLE_NATIVE_TITLE_QUERY_REQUIRED_SOURCES
    if version == 31:
        arguments = manifest.get("compiler_arguments")
        if (manifest.get("current_country_control_test_only") is not True
                or manifest.get("current_country_control_protocol") != "EU4COUNTRY1"
                or manifest.get("current_country_control_entry_rva") != "0x779360"
                or manifest.get("runtime_verified") is not False
                or not isinstance(arguments, list)
                or "-DBRIDGE_CURRENT_COUNTRY_CONTROL=1" not in arguments
                or _has_compiler_define(arguments, "INFORMATION_CURRENT_COUNTRY_HOST_FIXTURE")):
            raise SystemExit("BUILD_MANIFEST_MISMATCH")
        required_names = INFORMATION_CURRENT_COUNTRY_CONTROL_REQUIRED_SOURCES
    if version in (32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 51, 54, 55, 56, 57, 58, 59, 60):
        arguments = manifest.get("compiler_arguments")
        if (manifest.get("information_battle_gate_trace") is not True
                or manifest.get("information_battle_gate_trace_protocol")
                    != "EU4-BATTLE-GATE-TRACE/1"
                or manifest.get("information_battle_gate_trace_runtime_verified") is not False
                or not isinstance(arguments, list)
                or "-DINFORMATION_BATTLE_GATE_TRACE=1" not in arguments
                or _has_compiler_define(arguments, "BRIDGE_CURRENT_COUNTRY_CONTROL")
                or _has_compiler_define(
                    arguments, "INFORMATION_CURRENT_COUNTRY_HOST_FIXTURE")
                or any(key in manifest for key in (
                    "current_country_control_test_only",
                    "current_country_control_protocol",
                    "current_country_control_entry_rva",
                ))):
            raise SystemExit("BUILD_MANIFEST_MISMATCH")
        required_names = INFORMATION_BATTLE_GATE_TRACE_REQUIRED_SOURCES
    display_keys = (
        "information_battle_display_context", "information_battle_display_context_wire",
        "information_battle_display_context_scope", "information_battle_display_context_stage",
        "information_battle_display_context_read_only", "information_battle_display_context_complete",
    )
    arguments = manifest.get("compiler_arguments")
    if version in (33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 51, 54, 55, 56, 57, 58, 59, 60):
        if (manifest.get(display_keys[0]) is not True
                or type(manifest.get(display_keys[1])) is not int or manifest[display_keys[1]] != 7
                or manifest.get(display_keys[2]) != "same_battle_event"
                or manifest.get(display_keys[3]) != "router_scope_exit"
                or manifest.get(display_keys[4]) is not True
                or manifest.get(display_keys[5]) is not False
                or not isinstance(arguments, list)
                or "-DINFORMATION_BATTLE_DISPLAY_CONTEXT=1" not in arguments):
            raise SystemExit("BUILD_MANIFEST_MISMATCH")
        required_names = INFORMATION_BATTLE_DISPLAY_CONTEXT_REQUIRED_SOURCES
    elif (_has_compiler_define(arguments, "INFORMATION_BATTLE_DISPLAY_CONTEXT")
          or any(key in manifest for key in display_keys)):
        raise SystemExit("BUILD_MANIFEST_MISMATCH")

    debt_quote_keys = (
        "information_debt_quote_query",
        "information_debt_quote_query_wire",
        "information_debt_quote_read_only",
        "information_debt_quote_fp_context",
    )
    debt_quote_defines = _compiler_define_values(arguments, "BRIDGE_DEBT_QUOTE_QUERY")
    if version in (34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 51, 54, 55, 56, 57, 58, 59, 60):
        if (manifest.get(debt_quote_keys[0]) is not True
                or type(manifest.get(debt_quote_keys[1])) is not int
                or manifest[debt_quote_keys[1]] != 1
                or manifest.get(debt_quote_keys[2]) is not True
                or manifest.get(debt_quote_keys[3]) is not True
                or debt_quote_defines != ["1"]):
            raise SystemExit("BUILD_MANIFEST_MISMATCH")
        required_names = INFORMATION_BATTLE_DISPLAY_CONTEXT_REQUIRED_SOURCES + (
            INFORMATION_DEBT_QUOTE_REQUIRED_SOURCES)
    elif debt_quote_defines or any(key in manifest for key in debt_quote_keys):
        raise SystemExit("BUILD_MANIFEST_MISMATCH")
    name_handoff_keys = (
        "information_battle_name_handoff",
        "information_battle_name_handoff_wire",
        "information_battle_name_handoff_stage",
        "information_battle_name_handoff_complete",
    )
    name_handoff_defines = _compiler_define_values(
        arguments, "INFORMATION_BATTLE_NAME_HANDOFF")
    end_state_keys = (
        "information_battle_end_state",
        "information_battle_end_state_wire",
        "information_battle_end_state_complete",
    )
    end_state_defines = _compiler_define_values(
        arguments, "INFORMATION_BATTLE_END_STATE")
    if version in (36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 51, 54, 55, 56, 57, 58, 59, 60):
        arguments = manifest.get("compiler_arguments")
        end_state_define_valid = (
            end_state_defines == ["1"] if version in (37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 51, 54, 55, 56, 57, 58, 59, 60)
            else "-DINFORMATION_BATTLE_END_STATE=1" in arguments
        ) if isinstance(arguments, list) else False
        if (manifest.get(end_state_keys[0]) is not True
                or type(manifest.get(end_state_keys[1])) is not int
                or manifest[end_state_keys[1]] != 9
                or manifest.get(end_state_keys[2]) is not False
                or not end_state_define_valid):
            raise SystemExit("BUILD_MANIFEST_MISMATCH")
        required_names += INFORMATION_BATTLE_END_STATE_SOURCES
    elif end_state_defines or any(key in manifest for key in end_state_keys):
        raise SystemExit("BUILD_MANIFEST_MISMATCH")

    name_handoff_enabled = (version == 35 or
                            (version in (36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 51, 54, 55, 56, 57, 58, 59, 60)
                             and manifest.get(name_handoff_keys[0]) is True))
    if name_handoff_enabled:
        arguments = manifest.get("compiler_arguments")
        if (manifest.get("information_battle_name_handoff") is not True
                or type(manifest.get("information_battle_name_handoff_wire")) is not int
                or manifest["information_battle_name_handoff_wire"] != 8
                or manifest.get("information_battle_name_handoff_stage") != "before_pair_move"
                or manifest.get("information_battle_name_handoff_complete") is not False
                or not isinstance(arguments, list)
                or "-DINFORMATION_BATTLE_NAME_HANDOFF=1" not in arguments):
            raise SystemExit("BUILD_MANIFEST_MISMATCH")
        required_names = INFORMATION_BATTLE_NAME_HANDOFF_REQUIRED_SOURCES
        if version in (36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 51, 54, 55, 56, 57, 58, 59, 60):
            required_names += INFORMATION_BATTLE_END_STATE_SOURCES
        if version in (37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 51, 54, 55, 56, 57, 58, 59, 60):
            required_names += INFORMATION_BATTLE_RETREAT_SOURCES
    elif version in (36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 51, 54, 55, 56, 57, 58, 59, 60):
        name_enabled = manifest.get(name_handoff_keys[0])
        if ((name_enabled is not None and type(name_enabled) is not bool)
                or name_enabled is True
                or name_handoff_defines
                or any(key in manifest for key in name_handoff_keys[1:])):
            raise SystemExit("BUILD_MANIFEST_MISMATCH")
    elif name_handoff_defines or any(key in manifest for key in name_handoff_keys):
        raise SystemExit("BUILD_MANIFEST_MISMATCH")
    retreat_keys = (
        "information_battle_retreat",
        "information_battle_retreat_wire",
        "information_battle_retreat_stage",
        "information_battle_retreat_complete",
    )
    retreat_extension_keys = (
        "information_battle_retreat_unit_removal",
        "information_battle_retreat_max_extension_version",
    )
    retreat_defines = _compiler_define_values(
        arguments, "INFORMATION_BATTLE_RETREAT")
    if version in (37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 51, 54, 55, 56, 57, 58, 59, 60):
        if (manifest.get(retreat_keys[0]) is not True
                or type(manifest.get(retreat_keys[1])) is not int
                or manifest[retreat_keys[1]] != 10
                or manifest.get(retreat_keys[2])
                    != "regular_battle_end_unit_path_callback"
                or manifest.get(retreat_keys[3]) is not False
                or retreat_defines != ["1"]):
            raise SystemExit("BUILD_MANIFEST_MISMATCH")
        extension_presence = [key in manifest for key in retreat_extension_keys]
        if any(extension_presence):
            if (not all(extension_presence)
                    or manifest.get(retreat_extension_keys[0]) is not True
                    or type(manifest.get(retreat_extension_keys[1])) is not int
                    or manifest[retreat_extension_keys[1]] != 2):
                raise SystemExit("BUILD_MANIFEST_MISMATCH")
        required_names += INFORMATION_BATTLE_RETREAT_SOURCES
    elif (retreat_defines or any(key in manifest for key in retreat_keys)
          or any(key in manifest for key in retreat_extension_keys)):
        raise SystemExit("BUILD_MANIFEST_MISMATCH")
    name_source_keys = (
        "information_battle_name_sources", "information_battle_name_sources_wire",
        "information_battle_name_sources_stage", "information_battle_name_sources_read_only",
        "information_battle_name_sources_complete",
    )
    source_defines = _compiler_define_values(arguments, "INFORMATION_BATTLE_NAME_SOURCES")
    no_invoke_defines = _compiler_define_values(arguments, "INFORMATION_BATTLE_NO_TITLE_QUERY_INVOKE")
    if version in (38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 51, 54, 55, 56, 57, 58, 59, 60):
        if (manifest.get(name_source_keys[0]) is not True
                or type(manifest.get(name_source_keys[1])) is not int
                or manifest[name_source_keys[1]] != 11
                or manifest.get(name_source_keys[2]) != "entry_before_client_gate"
                or manifest.get(name_source_keys[3]) is not True
                or manifest.get(name_source_keys[4]) is not False
                or source_defines != ["1"] or no_invoke_defines != ["1"]):
            raise SystemExit("BUILD_MANIFEST_MISMATCH")
        required_names += INFORMATION_BATTLE_NAME_SOURCES_SOURCES
        if not name_handoff_enabled:
            required_names += tuple(INFORMATION_BATTLE_END_STATE_HEADER_DEPENDENCIES)
    elif source_defines or no_invoke_defines or any(key in manifest for key in name_source_keys):
        raise SystemExit("BUILD_MANIFEST_MISMATCH")
    outcome_text_keys = (
        "information_battle_outcome_text",
        "information_battle_outcome_text_wire",
        "information_battle_outcome_text_stage",
        "information_battle_outcome_text_read_only",
        "information_battle_outcome_text_complete",
    )
    outcome_text_defines = _compiler_define_values(
        arguments, "INFORMATION_BATTLE_OUTCOME_TEXT")
    if version in (39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 51, 54, 55, 56, 57, 58, 59, 60):
        if (manifest.get(outcome_text_keys[0]) is not True
                or type(manifest.get(outcome_text_keys[1])) is not int
                or manifest[outcome_text_keys[1]] != 12
                or manifest.get(outcome_text_keys[2]) != "entry_before_client_gate"
                or manifest.get(outcome_text_keys[3]) is not True
                or manifest.get(outcome_text_keys[4]) is not False
                or outcome_text_defines != ["1"]):
            raise SystemExit("BUILD_MANIFEST_MISMATCH")
        required_names += INFORMATION_BATTLE_OUTCOME_TEXT_SOURCES
    elif outcome_text_defines or any(key in manifest for key in outcome_text_keys):
        raise SystemExit("BUILD_MANIFEST_MISMATCH")
    outcome_tail_keys = (
        "information_battle_outcome_tail",
        "information_battle_outcome_tail_wire",
        "information_battle_outcome_tail_stage",
        "information_battle_outcome_tail_read_only",
        "information_battle_outcome_tail_complete",
    )
    outcome_tail_defines = _compiler_define_values(
        arguments, "INFORMATION_BATTLE_OUTCOME_TAIL")
    if version in (40, 41, 42, 43, 44, 45, 46, 47, 48, 51, 54, 55, 56, 57, 58, 59, 60):
        if (manifest.get(outcome_tail_keys[0]) is not True
                or type(manifest.get(outcome_tail_keys[1])) is not int
                or manifest[outcome_tail_keys[1]] != 13
                or manifest.get(outcome_tail_keys[2]) != "entry_before_client_gate"
                or manifest.get(outcome_tail_keys[3]) is not True
                or manifest.get(outcome_tail_keys[4]) is not False
                or outcome_tail_defines != ["1"]):
            raise SystemExit("BUILD_MANIFEST_MISMATCH")
        required_names += INFORMATION_BATTLE_OUTCOME_TAIL_SOURCES
    elif outcome_tail_defines or any(key in manifest for key in outcome_tail_keys):
        raise SystemExit("BUILD_MANIFEST_MISMATCH")
    call_to_arms_keys = (
        "call_to_arms_observation",
        "call_to_arms_ai_response_held",
        "call_to_arms_execution",
    )
    arguments = manifest.get("compiler_arguments")
    call_to_arms_defines = _compiler_define_values(
        arguments, "BRIDGE_CALL_TO_ARMS_OBSERVATION")
    if version in (41, 42, 43, 44, 45, 46, 47, 48, 51, 54, 55, 56, 57, 58, 59, 60):
        if (manifest.get(call_to_arms_keys[0]) is not True
                or manifest.get(call_to_arms_keys[1]) is not False
                or manifest.get(call_to_arms_keys[2]) is not False
                or call_to_arms_defines != ["1"]):
            raise SystemExit("BUILD_MANIFEST_MISMATCH")
        required_names += INFORMATION_BATTLE_CALL_TO_ARMS_SOURCES
    elif call_to_arms_defines or any(key in manifest for key in call_to_arms_keys):
        raise SystemExit("BUILD_MANIFEST_MISMATCH")
    independent_line_keys = (
        "information_battle_independent_line",
        "information_battle_independent_line_wire",
        "information_battle_independent_line_native_formatter",
        "information_battle_independent_line_stage",
        "information_battle_independent_line_actual_popup",
    )
    independent_line_defines = _compiler_define_values(
        arguments, "INFORMATION_BATTLE_INDEPENDENT_LINE")
    if version in (42, 43, 44, 45, 46, 47, 48, 51, 54, 55, 56, 57, 58, 59, 60):
        compiler_standards = [
            item for item in arguments
            if isinstance(item, str) and item.startswith("-std=")
        ] if isinstance(arguments, list) else []
        if (manifest.get(independent_line_keys[0]) is not True
                or type(manifest.get(independent_line_keys[1])) is not int
                or manifest[independent_line_keys[1]] != 14
                or manifest.get(independent_line_keys[2]) is not True
                or manifest.get(independent_line_keys[3]) != "router_scope_exit"
                or manifest.get(independent_line_keys[4]) is not False
                or independent_line_defines != ["1"]
                or compiler_standards != ["-std=c++20"]):
            raise SystemExit("BUILD_MANIFEST_MISMATCH")
        required_names += INFORMATION_BATTLE_INDEPENDENT_LINE_SOURCES
    elif (independent_line_defines
          or any(key in manifest for key in independent_line_keys)):
        raise SystemExit("BUILD_MANIFEST_MISMATCH")
    flag_inputs_keys = (
        "information_battle_flag_inputs",
        "information_battle_flag_inputs_wire",
        "information_battle_flag_inputs_stage",
        "information_battle_flag_inputs_actual_widget",
    )
    flag_inputs_defines = _compiler_define_values(
        arguments, "INFORMATION_BATTLE_FLAG_INPUTS")
    if version in (43, 44, 45, 46, 47, 48, 51, 54, 55, 56, 57, 58, 59, 60):
        if (manifest.get(flag_inputs_keys[0]) is not True
                or type(manifest.get(flag_inputs_keys[1])) is not int
                or manifest[flag_inputs_keys[1]] != 15
                or manifest.get(flag_inputs_keys[2]) != "formatter_container_before_cleanup"
                or manifest.get(flag_inputs_keys[3]) is not False
                or flag_inputs_defines != ["1"]):
            raise SystemExit("BUILD_MANIFEST_MISMATCH")
        required_names += INFORMATION_BATTLE_FLAG_INPUTS_SOURCES
    elif (flag_inputs_defines or any(key in manifest for key in flag_inputs_keys)):
        raise SystemExit("BUILD_MANIFEST_MISMATCH")
    role_defines = _compiler_define_values(arguments, "BRIDGE_SUPPORT_ROLE_CONTEXT")
    if version in (44, 45, 46, 47, 48, 51, 54, 55, 56, 57, 58, 59, 60):
        if (manifest.get(SUPPORT_ROLE_CONTEXT_KEYS[0]) is not True
                or manifest.get(SUPPORT_ROLE_CONTEXT_KEYS[1]) is not True
                or manifest.get(SUPPORT_ROLE_CONTEXT_KEYS[2]) != list(SUPPORT_ROLE_CONTEXT_FIELDS)
                or role_defines != ["1"]):
            raise SystemExit("BUILD_MANIFEST_MISMATCH")
        required_names += SUPPORT_ROLE_CONTEXT_SOURCES
    elif role_defines or any(key in manifest for key in SUPPORT_ROLE_CONTEXT_KEYS):
        raise SystemExit("BUILD_MANIFEST_MISMATCH")
    modifier_defines = _compiler_define_values(arguments, "BRIDGE_COUNTRY_MODIFIER_OBSERVATION")
    if version in (45, 46, 47, 48, 51, 54, 55, 56, 57, 58, 59, 60):
        if (manifest.get(COUNTRY_MODIFIER_OBSERVATION_KEYS[0]) is not True
                or type(manifest.get(COUNTRY_MODIFIER_OBSERVATION_KEYS[1])) is not int
                or manifest[COUNTRY_MODIFIER_OBSERVATION_KEYS[1]] != 1
                or manifest.get(COUNTRY_MODIFIER_OBSERVATION_KEYS[2]) != "FRA_direct_temporary_records"
                or modifier_defines != ["1"]):
            raise SystemExit("BUILD_MANIFEST_MISMATCH")
        required_names += COUNTRY_MODIFIER_OBSERVATION_SOURCES
    elif modifier_defines or any(key in manifest for key in COUNTRY_MODIFIER_OBSERVATION_KEYS):
        raise SystemExit("BUILD_MANIFEST_MISMATCH")
    removal_defines = _compiler_define_values(arguments, "BRIDGE_COUNTRY_MODIFIER_REMOVAL")
    if version in (46, 47, 48, 51, 54, 55, 56, 57, 58, 59, 60):
        if (manifest.get(COUNTRY_MODIFIER_REMOVAL_KEYS[0]) is not True
                or type(manifest.get(COUNTRY_MODIFIER_REMOVAL_KEYS[1])) is not int
                or manifest[COUNTRY_MODIFIER_REMOVAL_KEYS[1]] != 1
                or removal_defines != ["1"]):
            raise SystemExit("BUILD_MANIFEST_MISMATCH")
        required_names += COUNTRY_MODIFIER_REMOVAL_SOURCES
    elif removal_defines or any(key in manifest for key in COUNTRY_MODIFIER_REMOVAL_KEYS):
        raise SystemExit("BUILD_MANIFEST_MISMATCH")
    expiry_defines = _compiler_define_values(arguments, "BRIDGE_COUNTRY_MODIFIER_EXPIRY")
    expiry_stubs = ([value for value in arguments if isinstance(value, str)
                     and Path(value).name == "information-country-modifier-expiry-entry.S"]
                    if isinstance(arguments, list) else [])
    if version in (47, 48, 51, 54, 55, 56, 57, 58, 59, 60):
        if (manifest.get(COUNTRY_MODIFIER_EXPIRY_KEYS[0]) is not True
                or type(manifest.get(COUNTRY_MODIFIER_EXPIRY_KEYS[1])) is not int
                or manifest[COUNTRY_MODIFIER_EXPIRY_KEYS[1]] != 1
                or expiry_defines != ["1"] or len(expiry_stubs) != 1):
            raise SystemExit("BUILD_MANIFEST_MISMATCH")
        required_names += COUNTRY_MODIFIER_EXPIRY_SOURCES
    elif expiry_defines or expiry_stubs or any(key in manifest for key in COUNTRY_MODIFIER_EXPIRY_KEYS):
        raise SystemExit("BUILD_MANIFEST_MISMATCH")
    records = manifest.get("sources")
    if not isinstance(records, list):
        raise SystemExit("BUILD_MANIFEST_MISMATCH")
    rival_defines = _compiler_define_values(arguments, "BRIDGE_RIVAL_OBSERVATION")
    rival_source_present = any(
        isinstance(record, dict) and record.get("name") in RIVAL_CHANGE_SOURCES
        for record in records
    )
    if version in (48, 51, 54, 55, 56, 57, 58, 59, 60):
        if (manifest.get(RIVAL_CHANGE_KEYS[0]) is not True
                or type(manifest.get(RIVAL_CHANGE_KEYS[1])) is not int
                or manifest[RIVAL_CHANGE_KEYS[1]] != 1
                or manifest.get(RIVAL_CHANGE_KEYS[2]) != RIVAL_CHANGE_SCOPE
                or rival_defines != ["1"]):
            raise SystemExit("BUILD_MANIFEST_MISMATCH")
        required_names += RIVAL_CHANGE_SOURCES
    elif rival_defines or any(key in manifest for key in RIVAL_CHANGE_KEYS) or rival_source_present:
        raise SystemExit("BUILD_MANIFEST_MISMATCH")
    macro_event_defines = (
        "BRIDGE_WAR_DECLARATION_OBSERVATION",
        "BRIDGE_RELATION_OBSERVATION",
        "BRIDGE_MISSION_COMPLETION_OBSERVATION",
    )
    macro_event_source_present = any(
        isinstance(record, dict) and record.get("name") in MACRO_EVENT_SOURCE_NAMES
        for record in records
    )
    if version in (51, 54, 55, 56, 57, 58, 59, 60):
        if (manifest.get(WAR_DECLARATION_KEYS[0]) is not True
                or type(manifest.get(WAR_DECLARATION_KEYS[1])) is not int
                or manifest[WAR_DECLARATION_KEYS[1]] != 1
                or manifest.get(WAR_DECLARATION_KEYS[2]) != WAR_DECLARATION_SCOPE
                or _compiler_define_values(arguments, macro_event_defines[0]) != ["1"]):
            raise SystemExit("BUILD_MANIFEST_MISMATCH")
        if version == 51:
            relation_wire, relation_scope = 1, RELATION_CHANGE_SCOPE
            mission_wire, mission_scope = 1, MISSION_COMPLETION_SCOPE
        elif version == 58:
            relation_wire, relation_scope = 3, ROYAL_RECORD_SCOPE
            mission_wire, mission_scope = 2, MISSION_COMPLETED_SET_SCOPE
        elif version == 59:
            relation_wire, relation_scope = 4, DIRECTED_RECORD_SCOPE
            mission_wire, mission_scope = 2, MISSION_COMPLETED_SET_SCOPE
        elif version == 60:
            relation_wire, relation_scope = 5, SUPPORT_SUBJECT_RECORD_SCOPE
            mission_wire, mission_scope = 2, MISSION_COMPLETED_SET_SCOPE
        else:
            relation_wire, relation_scope = 2, ALLIANCE_RECORD_SCOPE
            mission_wire, mission_scope = 2, MISSION_COMPLETED_SET_SCOPE
        if (manifest.get(RELATION_CHANGE_KEYS[0]) is not True
                or type(manifest.get(RELATION_CHANGE_KEYS[1])) is not int
                or manifest[RELATION_CHANGE_KEYS[1]] != relation_wire
                or manifest.get(RELATION_CHANGE_KEYS[2]) != relation_scope
                or _compiler_define_values(arguments, macro_event_defines[1]) != ["1"]
                or manifest.get(MISSION_COMPLETION_KEYS[0]) is not True
                or type(manifest.get(MISSION_COMPLETION_KEYS[1])) is not int
                or manifest[MISSION_COMPLETION_KEYS[1]] != mission_wire
                or manifest.get(MISSION_COMPLETION_KEYS[2]) != mission_scope
                or _compiler_define_values(arguments, macro_event_defines[2]) != ["1"]):
            raise SystemExit("BUILD_MANIFEST_MISMATCH")
        if version in (54, 55, 56, 57, 58, 59, 60) and (
                manifest.get(ALLIANCE_RECORD_CAPABILITY) is not True
                or manifest.get(MISSION_COMPLETED_SET_CAPABILITY) is not True):
            raise SystemExit("BUILD_MANIFEST_MISMATCH")
        required_names += (WAR_DECLARATION_SOURCES + RELATION_CHANGE_SOURCES
                           + MISSION_COMPLETION_SOURCES)
    elif (macro_event_source_present
          or any(key in manifest for key in MACRO_EVENT_KEYS)
          or any(_compiler_define_values(arguments, define)
                 for define in macro_event_defines)):
        raise SystemExit("BUILD_MANIFEST_MISMATCH")
    macro_source_present = any(
        isinstance(record, dict) and record.get("name") in MACRO_SOURCE_NAMES
        for record in records
    )
    if version in (54, 55, 56, 57, 58, 59, 60):
        if (manifest.get(MISSION_AVAILABILITY_KEYS[0]) is not True
                or type(manifest.get(MISSION_AVAILABILITY_KEYS[1])) is not int
                or manifest[MISSION_AVAILABILITY_KEYS[1]] != 1
                or manifest.get(MISSION_AVAILABILITY_KEYS[2]) != MISSION_AVAILABILITY_SCOPE
                or _compiler_define_values(arguments, MACRO_SOURCE_DEFINE_NAMES[0]) != ["1"]
                or _compiler_define_values(arguments, MACRO_SOURCE_DEFINE_NAMES[1]) != ["1"]
                or _compiler_define_values(arguments, MACRO_SOURCE_DEFINE_NAMES[2]) != ["1"]):
            raise SystemExit("BUILD_MANIFEST_MISMATCH")
        required_names += MACRO_SOURCE_SOURCES
        if (("prototype_only" in manifest
             and type(manifest.get("prototype_only")) is not bool)
                or manifest.get("prototype_only") is True
                or ("deployment_admission_verified" in manifest
                    and type(manifest.get("deployment_admission_verified")) is not bool)
                or manifest.get("deployment_admission_verified") is False):
            raise SystemExit("BUILD_MANIFEST_MISMATCH")
    elif (macro_source_present
          or any(key in manifest for key in MACRO_SOURCE_KEYS)
          or any(_compiler_define_values(arguments, define)
                 for define in MACRO_SOURCE_DEFINE_NAMES)):
        raise SystemExit("BUILD_MANIFEST_MISMATCH")
    mission_condition_source_present = any(
        isinstance(record, dict) and record.get("name") in MISSION_CONDITION_SOURCES
        for record in records
    )
    mission_condition_defines = _compiler_define_values(
        arguments, MISSION_CONDITION_DEFINE)
    mission_province_condition_source_present = any(
        isinstance(record, dict)
        and isinstance(record.get("name"), str)
        and (record["name"] in MISSION_PROVINCE_CONDITION_SOURCES
             or record["name"].startswith("information-mission-province-"))
        for record in records
    )
    mission_province_condition_defines = _compiler_define_values(
        arguments, MISSION_PROVINCE_CONDITION_DEFINE)
    if version == 56:
        if (manifest.get(MISSION_CONDITION_KEYS[0]) is not True
                or type(manifest.get(MISSION_CONDITION_KEYS[1])) is not int
                or manifest[MISSION_CONDITION_KEYS[1]] != 1
                or manifest.get(MISSION_CONDITION_KEYS[2]) != MISSION_CONDITION_SCOPE
                or mission_condition_defines != ["1"]
                or mission_province_condition_source_present
                or mission_province_condition_defines
                or MISSION_PROVINCE_CONDITION_CAPABILITY in manifest
                or manifest.get("prototype_only") is not False
                or manifest.get("formal_installation_admitted") is not True):
            raise SystemExit("BUILD_MANIFEST_MISMATCH")
        required_names += MISSION_CONDITION_SOURCES
    elif version in (57, 58, 59, 60):
        if (manifest.get(MISSION_CONDITION_KEYS[0]) is not True
                or type(manifest.get(MISSION_CONDITION_KEYS[1])) is not int
                or manifest[MISSION_CONDITION_KEYS[1]] != 2
                or manifest.get(MISSION_CONDITION_KEYS[2]) != MISSION_PROVINCE_CONDITION_SCOPE
                or manifest.get(MISSION_PROVINCE_CONDITION_CAPABILITY) is not True
                or mission_condition_defines != ["1"]
                or mission_province_condition_defines != ["1"]
                or manifest.get("prototype_only") is not False
                or manifest.get("formal_installation_admitted") is not True):
            raise SystemExit("BUILD_MANIFEST_MISMATCH")
        required_names += MISSION_CONDITION_SOURCES + MISSION_PROVINCE_CONDITION_SOURCES
    elif (mission_condition_source_present
          or any(key in manifest for key in MISSION_CONDITION_KEYS)
          or mission_condition_defines
          or mission_province_condition_source_present
          or MISSION_PROVINCE_CONDITION_CAPABILITY in manifest
          or mission_province_condition_defines):
        raise SystemExit("BUILD_MANIFEST_MISMATCH")
    royal_record_source_present = any(
        isinstance(record, dict)
        and isinstance(record.get("name"), str)
        and (record["name"] in ROYAL_RECORD_SOURCES
             or record["name"].startswith("information-royal-record-"))
        for record in records
    )
    royal_record_defines = _compiler_define_values(arguments, ROYAL_RECORD_DEFINE)
    if version in (58, 59, 60):
        expected_relation_wire, expected_relation_scope = (
            (3, ROYAL_RECORD_SCOPE) if version == 58
            else (4, DIRECTED_RECORD_SCOPE) if version == 59
            else (5, SUPPORT_SUBJECT_RECORD_SCOPE))
        if (manifest.get(RELATION_CHANGE_KEYS[0]) is not True
                or type(manifest.get(RELATION_CHANGE_KEYS[1])) is not int
                or manifest[RELATION_CHANGE_KEYS[1]] != expected_relation_wire
                or manifest.get(RELATION_CHANGE_KEYS[2]) != expected_relation_scope
                or manifest.get(ROYAL_RECORD_CAPABILITY) is not True
                or royal_record_defines != ["1"]
                or manifest.get("prototype_only") is not False
                or manifest.get("formal_installation_admitted") is not True):
            raise SystemExit("BUILD_MANIFEST_MISMATCH")
        required_names += ROYAL_RECORD_SOURCES
    elif (royal_record_source_present
          or ROYAL_RECORD_CAPABILITY in manifest
          or royal_record_defines):
        raise SystemExit("BUILD_MANIFEST_MISMATCH")
    directed_record_source_present = any(
        isinstance(record, dict)
        and isinstance(record.get("name"), str)
        and (record["name"] in DIRECTED_RECORD_SOURCES
             or record["name"].startswith("information-directed-record-"))
        for record in records
    )
    directed_record_defines = _compiler_define_values(
        arguments, DIRECTED_RECORD_DEFINE)
    if version in (59, 60):
        if (manifest.get(DIRECTED_RECORD_CAPABILITY) is not True
                or directed_record_defines != ["1"]
                or manifest.get("prototype_only") is not False
                or manifest.get("formal_installation_admitted") is not True):
            raise SystemExit("BUILD_MANIFEST_MISMATCH")
        required_names += DIRECTED_RECORD_SOURCES
    elif (directed_record_source_present
          or DIRECTED_RECORD_CAPABILITY in manifest
          or directed_record_defines):
        raise SystemExit("BUILD_MANIFEST_MISMATCH")
    support_subject_record_source_present = any(
        isinstance(record, dict)
        and isinstance(record.get("name"), str)
        and (record["name"] in SUPPORT_SUBJECT_RECORD_SOURCES
             or record["name"].startswith("information-support-subject-record-"))
        for record in records
    )
    support_subject_record_defines = _compiler_define_values(
        arguments, SUPPORT_SUBJECT_RECORD_DEFINE)
    if version == 60:
        if (manifest.get(SUPPORT_SUBJECT_RECORD_CAPABILITY) is not True
                or support_subject_record_defines != ["1"]
                or manifest.get("prototype_only") is not False
                or manifest.get("formal_installation_admitted") is not True):
            raise SystemExit("BUILD_MANIFEST_MISMATCH")
        required_names += SUPPORT_SUBJECT_RECORD_SOURCES
    elif (support_subject_record_source_present
          or SUPPORT_SUBJECT_RECORD_CAPABILITY in manifest
          or support_subject_record_defines):
        raise SystemExit("BUILD_MANIFEST_MISMATCH")
    participants = manifest.get("native_war_participants_query", False)
    if type(participants) is not bool:
        raise SystemExit("BUILD_MANIFEST_MISMATCH")
    if version in (34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 51, 54, 55, 56, 57, 58, 59, 60) and participants is not True:
        raise SystemExit("BUILD_MANIFEST_MISMATCH")
    if participants:
        required_names += ("peace-context-query.inc", "peace-war-context-query.inc",
                           "peace-war-side-members.inc")
    registry_source_present = any(isinstance(record, dict)
                                  and record.get("name") == WAR_REGISTRY_SOURCE
                                  for record in records)
    registry_source_required = False
    context_source = directory / "peace-context-query.inc"
    if context_source.is_file():
        try:
            with context_source.open(encoding="utf-8", errors="replace") as stream:
                registry_source_required = any(line.strip() == f'#include "{WAR_REGISTRY_SOURCE}"'
                                               for line in stream)
        except OSError as exc:
            raise SystemExit("BUILD_MANIFEST_MISMATCH") from exc
    if registry_source_present != registry_source_required:
        raise SystemExit("BUILD_MANIFEST_MISMATCH")
    if registry_source_present:
        required_names += (WAR_REGISTRY_SOURCE,)
    expected_source_count = (118 + int(participants) + int(registry_source_present)
                             + (3 if version in (31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 51, 54, 55, 56, 57, 58, 59, 60) else 0)
                             + (3 if version in (33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 51, 54, 55, 56, 57, 58, 59, 60) else 0)
                             + (2 if version in (34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 51, 54, 55, 56, 57, 58, 59, 60) else 0)
                             + (5 if name_handoff_enabled else 0)
                             + (2 if version in (36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 51, 54, 55, 56, 57, 58, 59, 60) else 0)
                             + (4 if version in (37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 51, 54, 55, 56, 57, 58, 59, 60) else 0)
                             + ((3 + (0 if name_handoff_enabled else 2)) if version in (38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 51, 54, 55, 56, 57, 58, 59, 60) else 0)
                             + (3 if version in (39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 51, 54, 55, 56, 57, 58, 59, 60) else 0)
                             + (3 if version in (40, 41, 42, 43, 44, 45, 46, 47, 48, 51, 54, 55, 56, 57, 58, 59, 60) else 0)
                             + (1 if version in (41, 42, 43, 44, 45, 46, 47, 48, 51, 54, 55, 56, 57, 58, 59, 60) else 0)
                             + (5 if version in (42, 43, 44, 45, 46, 47, 48, 51, 54, 55, 56, 57, 58, 59, 60) else 0)
                             + (2 if version in (43, 44, 45, 46, 47, 48, 51, 54, 55, 56, 57, 58, 59, 60) else 0)
                             + (1 if version in (44, 45, 46, 47, 48, 51, 54, 55, 56, 57, 58, 59, 60) else 0)
                             + (3 if version in (45, 46, 47, 48, 51, 54, 55, 56, 57, 58, 59, 60) else 0)
                             + (2 if version in (46, 47, 48, 51, 54, 55, 56, 57, 58, 59, 60) else 0)
                             + (2 if version in (47, 48, 51, 54, 55, 56, 57, 58, 59, 60) else 0)
                              + (2 if version in (48, 51, 54, 55, 56, 57, 58, 59, 60) else 0)
                              + (6 if version in (51, 54, 55, 56, 57, 58, 59, 60) else 0)
                              + (7 if version in (54, 55, 56, 57, 58, 59, 60) else 0)
                              + (3 if version in (56, 57, 58, 59, 60) else 0)
                              + (3 if version in (57, 58, 59, 60) else 0)
                              + (2 if version in (58, 59, 60) else 0)
                              + (2 if version in (59, 60) else 0)
                              + (2 if version == 60 else 0))
    if (version in (30, 31, 32, 33, 34, 35, 42, 43, 44, 45, 46, 47, 48, 51, 54, 55, 56, 57, 58, 59, 60)
            and len(records) != expected_source_count):
        raise SystemExit("BUILD_MANIFEST_MISMATCH")
    if (version in (32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 51, 54, 55, 56, 57, 58, 59, 60)
            and any(isinstance(record, dict)
                    and record.get("name") in INFORMATION_CURRENT_COUNTRY_CONTROL_ONLY_SOURCES
                    for record in records)):
        raise SystemExit("BUILD_MANIFEST_MISMATCH")
    if version in (34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 51, 54, 55, 56, 57, 58, 59, 60):
        seen_names: set[str] = set()
        seen_name_keys: set[str] = set()
        for record in records:
            if not isinstance(record, dict):
                raise SystemExit("BUILD_MANIFEST_MISMATCH")
            name = record.get("name")
            if (not isinstance(name, str) or Path(name).name != name
                    or name in seen_names or name.casefold() in seen_name_keys
                    or not _is_sha256(record.get("sha256"))):
                raise SystemExit("BUILD_MANIFEST_MISMATCH")
            seen_names.add(name)
            seen_name_keys.add(name.casefold())
        expected_names = (INFORMATION_BATTLE_V33_SOURCE_NAMES
                          | set(INFORMATION_DEBT_QUOTE_REQUIRED_SOURCES))
        if registry_source_present:
            expected_names |= {WAR_REGISTRY_SOURCE}
        if version == 35 or name_handoff_enabled:
            expected_names |= set(INFORMATION_BATTLE_NAME_HANDOFF_SOURCES)
        if version in (36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 51, 54, 55, 56, 57, 58, 59, 60):
            expected_names |= set(INFORMATION_BATTLE_END_STATE_SOURCES)
            if not name_handoff_enabled:
                expected_names |= (seen_names
                                   & INFORMATION_BATTLE_END_STATE_HEADER_DEPENDENCIES)
        if version in (37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 51, 54, 55, 56, 57, 58, 59, 60):
            expected_names |= set(INFORMATION_BATTLE_RETREAT_SOURCES)
        if version in (38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 51, 54, 55, 56, 57, 58, 59, 60):
            expected_names |= set(INFORMATION_BATTLE_NAME_SOURCES_SOURCES)
            if not name_handoff_enabled:
                expected_names |= INFORMATION_BATTLE_END_STATE_HEADER_DEPENDENCIES
        if version in (39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 51, 54, 55, 56, 57, 58, 59, 60):
            expected_names |= set(INFORMATION_BATTLE_OUTCOME_TEXT_SOURCES)
        if version in (40, 41, 42, 43, 44, 45, 46, 47, 48, 51, 54, 55, 56, 57, 58, 59, 60):
            expected_names |= set(INFORMATION_BATTLE_OUTCOME_TAIL_SOURCES)
        if version in (41, 42, 43, 44, 45, 46, 47, 48, 51, 54, 55, 56, 57, 58, 59, 60):
            expected_names |= set(INFORMATION_BATTLE_CALL_TO_ARMS_SOURCES)
        if version in (42, 43, 44, 45, 46, 47, 48, 51, 54, 55, 56, 57, 58, 59, 60):
            expected_names |= set(INFORMATION_BATTLE_INDEPENDENT_LINE_SOURCES)
        if version in (43, 44, 45, 46, 47, 48, 51, 54, 55, 56, 57, 58, 59, 60):
            expected_names |= set(INFORMATION_BATTLE_FLAG_INPUTS_SOURCES)
        if version in (44, 45, 46, 47, 48, 51, 54, 55, 56, 57, 58, 59, 60):
            expected_names |= set(SUPPORT_ROLE_CONTEXT_SOURCES)
        if version in (45, 46, 47, 48, 51, 54, 55, 56, 57, 58, 59, 60):
            expected_names |= set(COUNTRY_MODIFIER_OBSERVATION_SOURCES)
        if version in (46, 47, 48, 51, 54, 55, 56, 57, 58, 59, 60):
            expected_names |= set(COUNTRY_MODIFIER_REMOVAL_SOURCES)
        if version in (47, 48, 51, 54, 55, 56, 57, 58, 59, 60):
            expected_names |= set(COUNTRY_MODIFIER_EXPIRY_SOURCES)
        if version in (48, 51, 54, 55, 56, 57, 58, 59, 60):
            expected_names |= set(RIVAL_CHANGE_SOURCES)
        if version in (51, 54, 55, 56, 57, 58, 59, 60):
            expected_names |= MACRO_EVENT_SOURCE_NAMES
        if version in (54, 55, 56, 57, 58, 59, 60):
            expected_names |= MACRO_SOURCE_NAMES
        if version in (56, 57, 58, 59, 60):
            expected_names |= set(MISSION_CONDITION_SOURCES)
        if version in (57, 58, 59, 60):
            expected_names |= set(MISSION_PROVINCE_CONDITION_SOURCES)
        if version in (58, 59, 60):
            expected_names |= set(ROYAL_RECORD_SOURCES)
        if version in (59, 60):
            expected_names |= set(DIRECTED_RECORD_SOURCES)
        if version == 60:
            expected_names |= set(SUPPORT_SUBJECT_RECORD_SOURCES)
        if seen_names != expected_names:
            raise SystemExit("BUILD_MANIFEST_MISMATCH")
        for record in records:
            source = directory / record["name"]
            if (not source.is_file()
                    or file_hash(source, refresh=True) != record["sha256"].lower()):
                raise SystemExit("BUILD_MANIFEST_MISMATCH")
    by_name: dict[str, str] = {}
    required = set(required_names)
    for record in records:
        if not isinstance(record, dict):
            continue
        name = record.get("name")
        digest = record.get("sha256")
        if name in required:
            if name in by_name or not _is_sha256(digest):
                raise SystemExit("BUILD_MANIFEST_MISMATCH")
            by_name[name] = digest
    if set(by_name) != required:
        raise SystemExit("BUILD_MANIFEST_MISMATCH")
    for name in required_names:
        source = directory / name
        if not source.is_file() or file_hash(source, refresh=True) != by_name[name].lower():
            raise SystemExit("BUILD_MANIFEST_MISMATCH")
    ack_source = directory / MACRO_EVENT_ACK_SOURCE
    ack_text = None
    if ack_source.is_file():
        try:
            if ack_source.stat().st_size > 4 * 1024 * 1024:
                raise SystemExit("BUILD_MANIFEST_MISMATCH")
            ack_text = ack_source.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            raise SystemExit("BUILD_MANIFEST_MISMATCH")
    if ack_text is not None:
        ack_text = _legacy_version_selector(ack_text)
        province_ack_count = ack_text.count(MISSION_PROVINCE_CONDITION_ACK_BLOCK)
        province_ack_prefix_count = ack_text.count(
            MISSION_PROVINCE_CONDITION_ACK_BLOCK_PREFIX)
        province_marker_count = ack_text.count(
            MISSION_PROVINCE_CONDITION_V57_VERSION_BLOCK)
        province_marker_prefix_count = ack_text.count(
            MISSION_PROVINCE_CONDITION_VERSION_BLOCK_PREFIX)
        legacy_condition_ack_count = ack_text.count(MISSION_CONDITION_ACK_BLOCK)
        royal_ack_count = ack_text.count(ROYAL_RECORD_RELATION_ACK_BLOCK)
        royal_ack_prefix_count = ack_text.count(ROYAL_RECORD_RELATION_ACK_PREFIX)
        royal_marker_count = ack_text.count(ROYAL_RECORD_V58_VERSION_BLOCK)
        royal_marker_prefix_count = ack_text.count(ROYAL_RECORD_VERSION_BLOCK_PREFIX)
        directed_ack_count = ack_text.count(DIRECTED_RECORD_RELATION_ACK_BLOCK)
        directed_ack_prefix_count = ack_text.count(
            DIRECTED_RECORD_RELATION_ACK_PREFIX)
        directed_marker_count = ack_text.count(
            DIRECTED_RECORD_V59_VERSION_BLOCK)
        directed_marker_prefix_count = ack_text.count(
            DIRECTED_RECORD_VERSION_BLOCK_PREFIX)
        support_subject_ack_count = ack_text.count(
            SUPPORT_SUBJECT_RECORD_RELATION_ACK_BLOCK)
        support_subject_ack_prefix_count = ack_text.count(
            SUPPORT_SUBJECT_RECORD_RELATION_ACK_PREFIX)
        support_subject_marker_count = ack_text.count(
            SUPPORT_SUBJECT_RECORD_V60_VERSION_BLOCK)
        support_subject_marker_prefix_count = ack_text.count(
            SUPPORT_SUBJECT_RECORD_VERSION_BLOCK_PREFIX)
        directed_ack_branch_count = ack_text.count(
            DIRECTED_RECORD_RELATION_ACK_BRANCH)
        directed_ack_branch_prefix_count = ack_text.count(
            DIRECTED_RECORD_RELATION_ACK_BRANCH_PREFIX)
        royal_ack_branch_count = ack_text.count(
            ROYAL_RECORD_RELATION_ACK_BRANCH)
        royal_ack_branch_prefix_count = ack_text.count(
            ROYAL_RECORD_RELATION_ACK_BRANCH_PREFIX)
        directed_marker_branch_count = ack_text.count(
            DIRECTED_RECORD_V59_VERSION_BRANCH)
        directed_marker_branch_prefix_count = ack_text.count(
            DIRECTED_RECORD_V59_VERSION_BRANCH_PREFIX)
        royal_marker_branch_count = ack_text.count(
            ROYAL_RECORD_V58_VERSION_BRANCH)
        royal_marker_branch_prefix_count = ack_text.count(
            ROYAL_RECORD_V58_VERSION_BRANCH_PREFIX)
        if (province_ack_count > 1
                or province_ack_prefix_count != province_ack_count
                or province_marker_count > 1
                or province_marker_prefix_count != province_marker_count
                or royal_ack_count > 1
                or royal_ack_prefix_count != royal_ack_count
                or royal_marker_count > 1
                or royal_marker_prefix_count != royal_marker_count
                or directed_ack_count > 1
                or directed_ack_prefix_count != directed_ack_count
                or directed_marker_count > 1
                or directed_marker_prefix_count != directed_marker_count
                or support_subject_ack_count > 1
                or support_subject_ack_prefix_count != support_subject_ack_count
                or support_subject_marker_count > 1
                or support_subject_marker_prefix_count != support_subject_marker_count
                or directed_ack_branch_count > 1
                or directed_ack_branch_prefix_count != directed_ack_branch_count + directed_marker_branch_count
                or royal_ack_branch_count > 1
                or royal_ack_branch_prefix_count != royal_ack_branch_count + royal_marker_branch_count
                or directed_marker_branch_count > 1
                or directed_marker_branch_prefix_count != directed_marker_branch_count
                or royal_marker_branch_count > 1
                or royal_marker_branch_prefix_count != royal_marker_branch_count):
            raise SystemExit("BUILD_MANIFEST_MISMATCH")
        if support_subject_ack_count and (
                directed_ack_branch_count != 1 or royal_ack_branch_count != 1
                or directed_marker_branch_count != 1
                or royal_marker_branch_count != 1):
            raise SystemExit("BUILD_MANIFEST_MISMATCH")
        if version == 56:
            if legacy_condition_ack_count + province_ack_count != 1:
                raise SystemExit("BUILD_MANIFEST_MISMATCH")
        elif version in (57, 58, 59, 60):
            if (province_ack_count != 1 or legacy_condition_ack_count != 0
                    or province_marker_count != 1):
                raise SystemExit("BUILD_MANIFEST_MISMATCH")
        elif legacy_condition_ack_count != 0:
            raise SystemExit("BUILD_MANIFEST_MISMATCH")
    if version in (51, 54, 55, 56, 57, 58, 59, 60):
        if ack_text is None:
            raise SystemExit("BUILD_MANIFEST_MISMATCH")
        if version == 51:
            relation_ack_count = ack_text.count(MACRO_EVENT_ACK_SOURCE_BLOCKS[1])
            if (relation_ack_count + directed_ack_count
                    + support_subject_ack_count != 1):
                raise SystemExit("BUILD_MANIFEST_MISMATCH")
            expected_ack_blocks = (
                MACRO_EVENT_ACK_SOURCE_BLOCKS[0],
                SUPPORT_SUBJECT_RECORD_RELATION_ACK_BLOCK
                if support_subject_ack_count else
                DIRECTED_RECORD_RELATION_ACK_BLOCK
                if directed_ack_count else MACRO_EVENT_ACK_SOURCE_BLOCKS[1],
                MACRO_EVENT_ACK_SOURCE_BLOCKS[2],
            )
            expected_version_blocks = (MACRO_EVENT_V51_VERSION_BLOCK,)
        else:
            expected_ack_blocks = (
                MACRO_EVENT_ACK_SOURCE_BLOCKS[0],
                MACRO_SOURCE_MISSION_ACK_BLOCK,
                MACRO_SOURCE_AVAILABILITY_ACK_BLOCK,
            )
            if version == 56:
                expected_version_blocks = (MISSION_CONDITION_V56_VERSION_BLOCK,)
            elif version == 57:
                expected_ack_blocks += (MISSION_PROVINCE_CONDITION_ACK_BLOCK,)
                expected_version_blocks = (
                    MISSION_CONDITION_V56_VERSION_BLOCK,
                    MISSION_PROVINCE_CONDITION_V57_VERSION_BLOCK,
                )
            elif version == 58:
                if (royal_ack_count + directed_ack_count
                        + support_subject_ack_count != 1):
                    raise SystemExit("BUILD_MANIFEST_MISMATCH")
                expected_ack_blocks += (
                    MISSION_PROVINCE_CONDITION_ACK_BLOCK,
                    SUPPORT_SUBJECT_RECORD_RELATION_ACK_BLOCK
                    if support_subject_ack_count else
                    DIRECTED_RECORD_RELATION_ACK_BLOCK
                    if directed_ack_count else ROYAL_RECORD_RELATION_ACK_BLOCK,
                )
                expected_version_blocks = (
                    MISSION_CONDITION_V56_VERSION_BLOCK,
                    MISSION_PROVINCE_CONDITION_V57_VERSION_BLOCK,
                    SUPPORT_SUBJECT_RECORD_V60_VERSION_BLOCK
                    if support_subject_marker_count else
                    DIRECTED_RECORD_V59_VERSION_BLOCK
                    if directed_marker_count else ROYAL_RECORD_V58_VERSION_BLOCK,
                )
            elif version == 59:
                if directed_ack_count + support_subject_ack_count != 1:
                    raise SystemExit("BUILD_MANIFEST_MISMATCH")
                expected_ack_blocks += (
                    MISSION_PROVINCE_CONDITION_ACK_BLOCK,
                    SUPPORT_SUBJECT_RECORD_RELATION_ACK_BLOCK
                    if support_subject_ack_count
                    else DIRECTED_RECORD_RELATION_ACK_BLOCK,
                )
                if directed_marker_count + support_subject_marker_count != 1:
                    raise SystemExit("BUILD_MANIFEST_MISMATCH")
                expected_version_blocks = (
                    MISSION_CONDITION_V56_VERSION_BLOCK,
                    MISSION_PROVINCE_CONDITION_V57_VERSION_BLOCK,
                    SUPPORT_SUBJECT_RECORD_V60_VERSION_BLOCK
                    if support_subject_marker_count
                    else DIRECTED_RECORD_V59_VERSION_BLOCK,
                )
            elif version == 60:
                if (support_subject_ack_count != 1
                        or support_subject_marker_count != 1):
                    raise SystemExit("BUILD_MANIFEST_MISMATCH")
                expected_ack_blocks += (
                    MISSION_PROVINCE_CONDITION_ACK_BLOCK,
                    SUPPORT_SUBJECT_RECORD_RELATION_ACK_BLOCK,
                )
                expected_version_blocks = (
                    MISSION_CONDITION_V56_VERSION_BLOCK,
                    MISSION_PROVINCE_CONDITION_V57_VERSION_BLOCK,
                    SUPPORT_SUBJECT_RECORD_V60_VERSION_BLOCK,
                )
            elif version == 54:
                relation_ack_count = ack_text.count(
                    MACRO_SOURCE_RELATION_ACK_BLOCK)
                if (relation_ack_count + directed_ack_count
                        + support_subject_ack_count != 1):
                    raise SystemExit("BUILD_MANIFEST_MISMATCH")
                expected_ack_blocks += (
                    SUPPORT_SUBJECT_RECORD_RELATION_ACK_BLOCK
                    if support_subject_ack_count else
                    DIRECTED_RECORD_RELATION_ACK_BLOCK
                    if directed_ack_count else MACRO_SOURCE_RELATION_ACK_BLOCK,
                )
                expected_version_blocks = (MACRO_SOURCE_V54_VERSION_BLOCK,)
            elif version == 55:
                expected_version_blocks = (MACRO_SOURCE_V55_VERSION_BLOCK,)
            if version in (55, 56, 57):
                # Frozen source trees use either the pre-v58 relation ACK or
                # the inactive v58 branch; current CPP has the directed/v59
                # branch while retaining those older protocol outputs.
                legacy_relation_ack_count = ack_text.count(
                    MACRO_SOURCE_RELATION_ACK_BLOCK)
                if (royal_ack_count + directed_ack_count
                        + support_subject_ack_count
                        + legacy_relation_ack_count != 1):
                    raise SystemExit("BUILD_MANIFEST_MISMATCH")
                relation_ack_block = (
                    SUPPORT_SUBJECT_RECORD_RELATION_ACK_BLOCK
                    if support_subject_ack_count
                    else DIRECTED_RECORD_RELATION_ACK_BLOCK if directed_ack_count
                    else ROYAL_RECORD_RELATION_ACK_BLOCK if royal_ack_count
                    else MACRO_SOURCE_RELATION_ACK_BLOCK)
                expected_ack_blocks += (relation_ack_block,)
        if support_subject_ack_count and version in (51, 54, 55, 56, 57):
            # The current CPP keeps the complete closed relation selector while
            # older manifests choose an earlier branch from it.
            if support_subject_marker_count != 1:
                raise SystemExit("BUILD_MANIFEST_MISMATCH")
            if version in (55, 56, 57):
                expected_ack_blocks += (SUPPORT_SUBJECT_RECORD_RELATION_ACK_BLOCK,)
            expected_version_blocks += (SUPPORT_SUBJECT_RECORD_V60_VERSION_BLOCK,)
        if (any(ack_text.count(block) != 1 for block in expected_ack_blocks)
                or any(ack_text.count(block) != 1
                       for block in expected_version_blocks)):
            raise SystemExit("BUILD_MANIFEST_MISMATCH")
        if version in (58, 59, 60):
            if support_subject_ack_count:
                expected_relation_ack_count = support_subject_ack_count
                expected_marker_count = support_subject_marker_count
                expected_marker_block = SUPPORT_SUBJECT_RECORD_V60_VERSION_BLOCK
            elif version == 59:
                expected_relation_ack_count = directed_ack_count
                expected_marker_count = directed_marker_count
                expected_marker_block = DIRECTED_RECORD_V59_VERSION_BLOCK
            else:
                expected_relation_ack_count = directed_ack_count + royal_ack_count
                expected_marker_count = directed_marker_count + royal_marker_count
                expected_marker_block = (
                    DIRECTED_RECORD_V59_VERSION_BLOCK
                    if directed_marker_count else ROYAL_RECORD_V58_VERSION_BLOCK)
            marker_start = ack_text.find(expected_marker_block)
            last_marker_write = ack_text.rfind("version_marker[sizeof")
            if (expected_relation_ack_count != 1
                    or ack_text.count(MACRO_SOURCE_RELATION_ACK_BLOCK) != 0
                    or (version == 59 and not support_subject_ack_count and (
                        royal_ack_count != 0
                        or royal_marker_count != 0
                        or ack_text.count(MACRO_EVENT_ACK_SOURCE_BLOCKS[1]) != 0))
                    or expected_marker_count != 1
                    or marker_start < ack_text.find(
                        MISSION_PROVINCE_CONDITION_V57_VERSION_BLOCK)
                    or not (marker_start <= last_marker_write
                            < marker_start + len(expected_marker_block))):
                raise SystemExit("BUILD_MANIFEST_MISMATCH")


def _recover_startup_render_window(pid: int) -> dict:
    """Reset one identified game's presentation once; no game data changes."""
    windows = _enumerate_windows_for_pid(pid)
    if len(windows) != 1:
        return {"attempted": False, "reason": "GAME_WINDOW_NOT_UNIQUE"}
    hwnd = windows[0]
    iconic = _is_iconic(hwnd)
    minimized = False
    if not iconic:
        minimized = _show_window_async(hwnd, 6)
        if not minimized:
            return {"attempted": True, "window": hwnd,
                    "minimize_requested": False, "restore_requested": False}
        time.sleep(0.5)
    restored = _show_window_async(hwnd, 4)
    return {"attempted": True, "window": hwnd, "initially_iconic": iconic,
            "minimize_requested": minimized, "restore_requested": restored}


def bounded_wait_ready(value: str) -> int:
    try:
        seconds = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("--wait-ready must be an integer") from error
    if seconds < 1 or seconds > MAX_WAIT_READY:
        raise argparse.ArgumentTypeError(f"--wait-ready must be between 1 and {MAX_WAIT_READY} seconds")
    return seconds


def load_warning_save_name(value: str) -> str:
    """Use the same local filename shape accepted by restart-game.ps1."""
    if len(value) > 255 or re.fullmatch(r"[A-Za-z0-9_-]+\.eu4", value) is None:
        raise argparse.ArgumentTypeError("load-warning save name must be an ASCII .eu4 filename")
    return value


def _waiting(attempt: int, reason: str, started: float, phase: str = "readiness") -> None:
    print(json.dumps({
        "state": "waiting",
        "attempt": attempt,
        "phase": phase,
        "reason": reason,
        "elapsed_seconds": round(time.monotonic() - started, 3),
    }, ensure_ascii=False, sort_keys=True), flush=True)


def _transient_identity_winerror(error: BaseException) -> int | None:
    """Return the explicitly retryable Win32 identity-probe error, if any.

    ``probe_identity`` raises the ctypes ``OSError`` produced by
    ``K32GetModuleFileNameExW``.  The module can briefly be unavailable while
    the process is starting, which is represented by ERROR_INVALID_HANDLE (6)
    or, on some Windows builds, ERROR_PARTIAL_COPY (299).  Keep this check
    narrow so process termination, image/hash mismatches, and arbitrary probe
    failures remain terminal.
    """

    if not isinstance(error, OSError):
        return None
    winerror = getattr(error, "winerror", None)
    return winerror if winerror in TRANSIENT_IDENTITY_WINERRORS else None


def _attempt_directory(directory: Path, attempt: int) -> Path:
    path = directory / f"ready-attempt-{attempt:03d}-{time.time_ns()}"
    path.mkdir(parents=False, exist_ok=False)
    return path


def _write_attempt_error(path: Path, stdout: str = "", stderr: str = "") -> None:
    path.write_text(stdout + stderr, encoding="utf-8")


def _remaining_timeout(deadline: float, maximum: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("READY_WAIT_DEADLINE_EXPIRED")
    return min(maximum, remaining)


def _assert_same_unloaded_process(expected: dict, current: dict, manifest: dict) -> None:
    if current.get("pid") != expected.get("pid"):
        raise RuntimeError("PID_CHANGED_NO_RETRY")
    if current.get("creation_filetime") != expected.get("creation_filetime"):
        raise RuntimeError("PROCESS_CREATION_CHANGED_NO_RETRY")
    if current.get("session_id") != expected.get("session_id"):
        raise RuntimeError("PROCESS_SESSION_CHANGED_NO_RETRY")
    if current.get("game_sha256") != manifest["game_sha256"]:
        raise RuntimeError("GAME_HASH_CHANGED_NO_RETRY")
    if current.get("modules"):
        raise RuntimeError("BRIDGE_ALREADY_LOADED_NO_RETRY")


def _queue_load_warning_shortcut(pid: int, expected: dict, save_name: str,
                                 directory: Path) -> dict:
    """Queue one authorized C key down/up pair for the verified test window."""
    user32 = C.WinDLL("user32", use_last_error=True)
    user32.GetWindowThreadProcessId.argtypes = [W.HWND, C.POINTER(W.DWORD)]
    user32.GetWindowThreadProcessId.restype = W.DWORD
    user32.IsWindowVisible.argtypes = [W.HWND]
    user32.IsWindowVisible.restype = W.BOOL
    user32.GetClassNameW.argtypes = [W.HWND, W.LPWSTR, C.c_int]
    user32.GetClassNameW.restype = C.c_int
    user32.PostMessageW.argtypes = [W.HWND, W.UINT, W.WPARAM, W.LPARAM]
    user32.PostMessageW.restype = W.BOOL

    def matches_game_window(hwnd: int) -> bool:
        owner = W.DWORD()
        class_name = C.create_unicode_buffer(256)
        return bool(user32.GetWindowThreadProcessId(W.HWND(hwnd), C.byref(owner))
                and owner.value == pid and user32.IsWindowVisible(W.HWND(hwnd))
                and user32.GetClassNameW(W.HWND(hwnd), class_name, len(class_name))
                and class_name.value == "SDL_app")

    windows = [hwnd for hwnd in _enumerate_windows_for_pid(pid) if matches_game_window(hwnd)]
    if len(windows) != 1:
        return {"attempted": False, "reason": "UNIQUE_VISIBLE_GAME_WINDOW_NOT_FOUND"}
    current = probe_identity(pid, game_exe())
    _assert_same_unloaded_process(expected, current, {"game_sha256": expected["game_sha256"]})
    record = {
        "schema": "eu4.load_warning_shortcut.v1", "identity": current,
        "save_name": save_name, "hwnd": windows[0],
        "basis": "operator_bound_saved_test_game_startup",
        "visually_confirmed": False, "message": "WM_KEYDOWN/WM_KEYUP", "character": "c",
        "virtual_key": ord("C"), "key_down_queued": None, "key_up_queued": None,
        "attempted": True, "queued": None, "load_verified": False,
    }
    receipt = directory / LOAD_WARNING_SHORTCUT_RECEIPT
    try:
        with receipt.open("x", encoding="utf-8") as stream:
            json.dump(record, stream, indent=2)
            stream.flush()
            os.fsync(stream.fileno())
    except FileExistsError as error:
        raise RuntimeError("LOAD_WARNING_SHORTCUT_ALREADY_ATTEMPTED_NO_RETRY") from error
    except OSError as error:
        raise RuntimeError("LOAD_WARNING_SHORTCUT_RECEIPT_WRITE_FAILED_NO_RETRY") from error
    try:
        for queued_key, message, flags in (
                ("key_down_queued", 0x100, 0x002e0001),
                ("key_up_queued", 0x101, 0xc02e0001)):
            if not matches_game_window(windows[0]):
                raise RuntimeError("GAME_WINDOW_CHANGED_BEFORE_SHORTCUT")
            record[queued_key] = bool(user32.PostMessageW(
                W.HWND(windows[0]), message, ord("C"), flags))
        record["queued"] = record["key_down_queued"] and record["key_up_queued"]
    except Exception as error:
        record["queue_error"] = str(error)
    try:
        receipt.write_text(json.dumps(record, indent=2), encoding="utf-8")
    except OSError as error:
        record["receipt_update_error"] = str(error)
    return record


def _read_scan_cursor(attempt_directory: Path, fallback: int) -> int:
    try:
        report = json.loads((attempt_directory / "startup-dialogs.json").read_text(encoding="utf-8"))
        if report.get("scan_complete"):
            return 0
        return int(report.get("next_scan_address", hex(fallback)), 0)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
        return fallback


def confirmation_request(pid: int, state: dict, attempt_directory: Path,
                         resume_address: int = 0) -> str:
    """Find exactly one verified load-warning button within this attempt."""

    python = get_value("EU4_PYTHON")
    dialogs = attempt_directory / "startup-dialogs.json"
    scan_environment = {**os.environ, "EU4_DIALOG_SCAN_START": hex(max(0, resume_address))}
    attempt_deadline = time.monotonic() + DIALOG_ATTEMPT_TIMEOUT
    try:
        subprocess.run([
            python, "-B", str(ROOT / "work/probe_startup_dialogs.py"),
            "--pid", str(pid), "--output", str(dialogs),
        ], check=True, timeout=min(DIALOG_SCAN_TIMEOUT,
                                  _remaining_timeout(attempt_deadline, DIALOG_SCAN_TIMEOUT)),
            stdout=subprocess.DEVNULL, env=scan_environment)
    except subprocess.TimeoutExpired as error:
        _write_attempt_error(attempt_directory / "startup-dialogs.error.txt", "timeout\n")
        raise RuntimeError("LOAD_WARNING_SCAN_TIMEOUT") from error
    base = int(state["module_base"], 16)
    matches = []
    for dialog_index, obj in enumerate(json.loads(dialogs.read_text(encoding="utf-8"))["dialogs"]):
        if obj["name"] != "DefaultConfirm":
            continue
        details_path = attempt_directory / f"popup-details-{dialog_index}.jsonl"
        try:
            completed = subprocess.run([
                python, "-B", str(ROOT / "work/read_popup_details.py"),
                "--pid", str(pid), "--peace-address", obj["object"],
            ], check=True, capture_output=True, text=True, encoding="utf-8",
                timeout=min(30.0, _remaining_timeout(attempt_deadline, 30.0)),
                env={**os.environ, "PYTHONIOENCODING": "utf-8"})
        except subprocess.TimeoutExpired as error:
            _write_attempt_error(details_path.with_suffix(".error.txt"), "timeout\n")
            raise RuntimeError("POPUP_DETAILS_TIMEOUT") from error
        details_path.write_text(completed.stdout, encoding="utf-8")
        for line in completed.stdout.splitlines():
            child = json.loads(line)
            if child["name"] != "agreebutton" or len(child.get("listeners", [])) != 2:
                continue
            first, second = child["listeners"]
            blob = bytes.fromhex(second["data"])
            owner = int.from_bytes(blob[8:16], "little")
            callback = int.from_bytes(blob[16:24], "little")
            if int(first["listener"], 16) == int(obj["object"], 16) + 0x18 and callback == base + 0x10ef2e0:
                matches.append(f"TEST_ONLY {pid} {int(obj['object'], 16):x} {int(child['child'], 16):x} {owner:x}\n")
    if len(matches) != 1:
        raise RuntimeError("UNIQUE_VERIFIED_LOAD_CONFIRMATION_NOT_FOUND")
    return matches[0]


def _preflight_once(pid: int, python: str, attempt_directory: Path,
                    deadline: float) -> tuple[dict | None, dict]:
    preflight = attempt_directory / "preflight.json"
    command = [python, "-B", str(ROOT / "work/probe_native_state.py"),
               "--pid", str(pid), "--output", str(preflight)]
    try:
        checked = subprocess.run(command, timeout=_remaining_timeout(deadline, PREFLIGHT_TIMEOUT),
                                 capture_output=True, text=True)
    except subprocess.TimeoutExpired:
        _write_attempt_error(attempt_directory / "preflight.error.txt", "timeout\n")
        return None, {"reason": "PREFLIGHT_TIMEOUT", "preflight": str(preflight)}
    if checked.returncode:
        _write_attempt_error(attempt_directory / "preflight.error.txt", checked.stdout, checked.stderr)
        return None, {"reason": f"PREFLIGHT_RETURN_{checked.returncode}", "preflight": str(preflight)}
    try:
        state = json.loads(preflight.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        _write_attempt_error(attempt_directory / "preflight.error.txt", str(error) + "\n")
        return None, {"reason": "PREFLIGHT_OUTPUT_INVALID", "preflight": str(preflight)}
    return state, {"reason": "PREFLIGHT_READY", "preflight": str(preflight)}


def _wait_until_ready(pid: int, manifest: dict, directory: Path, confirm_load_warning: bool,
                      wait_ready: int, *, load_warning_save_name: str | None = None
                      ) -> tuple[dict, dict, str | None, str, list[dict]]:
    """Return identity, ready state, optional confirmation and attempt evidence."""

    started = time.monotonic()
    deadline = started + wait_ready
    attempts: list[dict] = []

    # The first module enumeration can race the game's startup loader.  Keep
    # these narrowly classified identity errors inside the same overall
    # readiness deadline; all other probe failures still propagate.
    expected: dict | None = None
    identity_attempt = 0
    while expected is None:
        if time.monotonic() >= deadline:
            raise SystemExit("WORLD_NOT_READY_TIMEOUT_NO_INSTALLATION_ATTEMPTED")
        identity_attempt += 1
        try:
            candidate = probe_identity(pid, game_exe())
        except OSError as error:
            winerror = _transient_identity_winerror(error)
            if winerror is None:
                raise
            reason = f"IDENTITY_PROBE_TRANSIENT_WINERROR_{winerror}"
            attempts.append({
                "attempt": identity_attempt,
                "phase": "identity_probe",
                "outcome": "waiting",
                "reason": reason,
                "winerror": winerror,
            })
            _waiting(identity_attempt, reason, started, phase="identity_probe")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise SystemExit("WORLD_NOT_READY_TIMEOUT_NO_INSTALLATION_ATTEMPTED")
            time.sleep(min(IDENTITY_POLL_SECONDS, remaining))
            continue
        if candidate["modules"] or candidate["game_sha256"] != manifest["game_sha256"]:
            raise SystemExit("FRESH_VERIFIED_GAME_PROCESS_REQUIRED")
        expected = candidate

    python = get_value("EU4_PYTHON")
    attempt_number = 0
    scan_resume_address = 0
    startup_error_acknowledged = False
    startup_error_attempted = False
    next_startup_error_scan = 0.0
    missing_confirmations = 0
    render_recovery_attempted = False
    shortcut_receipt = directory / LOAD_WARNING_SHORTCUT_RECEIPT
    shortcut = None
    if shortcut_receipt.exists():
        try:
            shortcut = json.loads(shortcut_receipt.read_text(encoding="utf-8"))
            if shortcut.get("attempted") is not True:
                raise ValueError("invalid shortcut receipt")
            _assert_same_unloaded_process(shortcut["identity"], expected, manifest)
        except Exception as error:
            raise SystemExit("LOAD_WARNING_SHORTCUT_RECEIPT_INVALID_NO_RETRY") from error

    def ready_identity() -> dict:
        current = probe_identity(pid, game_exe())
        _assert_same_unloaded_process(expected, current, manifest)
        return current

    while time.monotonic() < deadline:
        if (directory / "installation.json").exists():
            raise SystemExit("EXPERIMENT_ALREADY_ATTEMPTED_USE_NEW_DIRECTORY_AND_PROCESS")
        attempt_number += 1
        attempt_directory = _attempt_directory(directory, attempt_number)
        try:
            current = probe_identity(pid, game_exe())
            _assert_same_unloaded_process(expected, current, manifest)
            state, evidence = _preflight_once(pid, python, attempt_directory, deadline)
            attempt = {"attempt": attempt_number, "directory": str(attempt_directory), **evidence}
            attempts.append(attempt)
            if state is None:
                now = time.monotonic()
                if (not startup_error_acknowledged and not startup_error_attempted
                        and now >= next_startup_error_scan):
                    next_startup_error_scan = now + STARTUP_ERROR_SCAN_SECONDS
                    try:
                        startup_error = acknowledge_startup_error(pid, attempt_directory)
                    except Exception as error:
                        attempt["startup_error_check_error"] = str(error)
                    else:
                        if startup_error is not None:
                            startup_error_attempted = (
                                startup_error.get("attempted") is True
                                or startup_error.get("acknowledged") is True)
                            startup_error_acknowledged = True
                            if startup_error.get("acknowledged") is True:
                                attempt["startup_error_acknowledged"] = True
                            else:
                                startup_error_acknowledged = False
                                attempt["startup_error_acknowledged"] = False
                            attempt["startup_error_ack_evidence"] = startup_error
                            if startup_error.get("terminal") is True:
                                attempt["startup_error_terminal"] = True
                                raise SystemExit(str(
                                    startup_error.get(
                                        "reason", "STARTUP_ERROR_DIALOG_NO_RETRY")))
                _waiting(attempt_number, evidence["reason"], started)
            else:
                player_tag = state.get("player_tag")
                if player_tag not in ("---", "POR"):
                    raise SystemExit("FIXED_CONTROL_REQUIRES_UNLOADED_OR_POR_TEST_SAVE")
                confirmation = None
                if player_tag == "POR":
                    if shortcut is None:
                        attempt.update({"outcome": "ready", "ready_reason": "por_already_loaded"})
                        return ready_identity(), state, confirmation, "por_already_loaded", attempts
                    date = (state.get("fra_send_date_guard") or {}).get("current_raw_date")
                    if type(date) is int and date >= 0:
                        identity = ready_identity()
                        shortcut.update(load_verified=True, loaded_game_date_raw=date)
                        try:
                            shortcut_receipt.write_text(json.dumps(shortcut, indent=2), encoding="utf-8")
                        except OSError as error:
                            shortcut["receipt_update_error"] = str(error)
                        reason = "por_loaded_after_load_warning_shortcut"
                        attempt.update({"outcome": "ready", "ready_reason": reason,
                                        "load_warning_shortcut": shortcut})
                        return identity, state, None, reason, attempts
                if shortcut is not None:
                    reason = ("LOAD_WARNING_SHORTCUT_AWAITING_WORLD_DATE" if player_tag == "POR"
                              else "LOAD_WARNING_SHORTCUT_AWAITING_WORLD")
                    attempt.update({"outcome": "not_ready",
                                    "reason": reason})
                    _waiting(attempt_number, attempt["reason"], started)
                elif not confirm_load_warning:
                    attempt.update({"outcome": "ready", "ready_reason": "unloaded_no_confirmation_requested"})
                    return ready_identity(), state, confirmation, "unloaded_no_confirmation_requested", attempts
                else:
                    try:
                        confirmation = confirmation_request(pid, state, attempt_directory, scan_resume_address)
                    except Exception as error:
                        scan_resume_address = _read_scan_cursor(attempt_directory, scan_resume_address)
                        attempt.update({"outcome": "not_ready", "reason": str(error)})
                        if str(error) == "UNIQUE_VERIFIED_LOAD_CONFIRMATION_NOT_FOUND":
                            if load_warning_save_name is not None:
                                result = _queue_load_warning_shortcut(
                                    pid, expected, load_warning_save_name, directory)
                                attempt["load_warning_shortcut"] = result
                                if result.get("attempted") is True:
                                    shortcut = result
                                    attempt["reason"] = "LOAD_WARNING_SHORTCUT_AWAITING_WORLD"
                            if shortcut is None:
                                missing_confirmations += 1
                                if missing_confirmations >= 3 and not render_recovery_attempted:
                                    render_recovery_attempted = True
                                    attempt["render_window_recovery"] = _recover_startup_render_window(pid)
                        _waiting(attempt_number, attempt["reason"], started)
                    else:
                        scan_resume_address = _read_scan_cursor(attempt_directory, scan_resume_address)
                        attempt.update({"outcome": "ready", "ready_reason": "verified_load_confirmation"})
                        return ready_identity(), state, confirmation, "verified_load_confirmation", attempts
        except SystemExit:
            raise
        except Exception as error:
            # Identity/process failures are terminal; read-only preflight errors
            # are recorded per attempt and may be retried until the deadline.
            if isinstance(error, RuntimeError) and str(error).endswith("NO_RETRY"):
                raise SystemExit(str(error)) from error
            attempt = {"attempt": attempt_number, "directory": str(attempt_directory),
                       "outcome": "not_ready", "reason": str(error)}
            attempts.append(attempt)
            _waiting(attempt_number, str(error), started)
        remaining = deadline - time.monotonic()
        if remaining > 0:
            time.sleep(min(READY_POLL_SECONDS, remaining))
    raise SystemExit("WORLD_NOT_READY_TIMEOUT_NO_INSTALLATION_ATTEMPTED")


def _install_once(pid: int, manifest: dict, directory: Path, dll: Path, python: str,
                  identity: dict, state: dict, confirmation: str | None,
                  ready_reason: str, attempts: list[dict], native_text_codec: str = "utf8") -> None:
    destination = directory / "installation.json"
    if destination.exists():
        raise SystemExit("EXPERIMENT_ALREADY_ATTEMPTED_USE_NEW_DIRECTORY_AND_PROCESS")
    current = probe_identity(pid, game_exe())
    _assert_same_unloaded_process(identity, current, manifest)
    record = {
        **identity,
        "experiment_id": manifest["experiment_id"],
        "dll_sha256": manifest["dll_sha256"],
        "installation_attempted": True,
        "installation_started": True,
        "installation_returncode": None,
        "runtime_verified": False,
        "ready_reason": ready_reason,
        "ready_attempts": attempts,
        "preflight_player_tag": state.get("player_tag"),
        "native_text_codec": native_text_codec,
        "native_text_codec_module_provenance_verified": False,
    }
    destination.write_text(json.dumps(record, indent=2), encoding="utf-8")
    try:
        result = subprocess.run([
            python, "-B", str(ROOT / "work/native/inject_probe.py"),
            "--pid", str(pid), "--dll", str(dll), "--ack-test-save",
        ], capture_output=True, text=True, timeout=65)
    except subprocess.TimeoutExpired:
        record["installation_timeout"] = True
        (directory / "loader-output.txt").write_text("timeout\n", encoding="utf-8")
        destination.write_text(json.dumps(record, indent=2), encoding="utf-8")
        raise SystemExit("INSTALLATION_TIMEOUT_NO_RETRY")
    (directory / "loader-output.txt").write_text(result.stdout + result.stderr, encoding="utf-8")
    record["installation_returncode"] = result.returncode
    destination.write_text(json.dumps(record, indent=2), encoding="utf-8")
    if result.returncode:
        raise SystemExit("INSTALLATION_FAILED_NO_RETRY_IN_THIS_PROCESS")
    record["modules_after_install"] = probe_identity(pid, game_exe())["modules"]
    destination.write_text(json.dumps(record, indent=2), encoding="utf-8")
    if confirmation:
        with (directory / "popup-confirm.request").open("x", encoding="ascii", newline="\n") as stream:
            stream.write(confirmation)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--confirm-load-warning", action="store_true")
    parser.add_argument("--load-warning-save-name", type=load_warning_save_name,
                        help="operator-bound restart SaveName allowing one C shortcut after native lookup misses")
    parser.add_argument("--native-text-codec", choices=("utf8", "eu4_escape"),
                        help="operator-bound decoder; defaults to EU4_NATIVE_TEXT_CODEC or utf8")
    parser.add_argument("--wait-ready", type=bounded_wait_ready, default=120,
                        help="bounded read-only readiness wait in seconds (default: 120, max: 300)")
    args = parser.parse_args(argv)
    if args.load_warning_save_name is not None and not args.confirm_load_warning:
        parser.error("--load-warning-save-name requires --confirm-load-warning")
    if args.native_text_codec is None:
        args.native_text_codec = get_value("EU4_NATIVE_TEXT_CODEC", required=False, default="utf8")
        if args.native_text_codec not in ("utf8", "eu4_escape"):
            parser.error("EU4_NATIVE_TEXT_CODEC must be utf8 or eu4_escape")
    manifest = json.loads(args.manifest.read_text(encoding="utf-8-sig"))
    directory = args.manifest.resolve().parent
    version = manifest.get("version")
    if type(version) is int and version in (61, 62, 63, 64):
        _validate_information_battle_manifest(manifest, directory)
        # Remaining startup switches belong to the inherited v60 family. The
        # original manifest still binds readiness, ACKs and installation.
        version = 60
    elif (_has_rival_record_features(manifest)
          or any(_has_expiry_feature(manifest, feature) for feature in
                 (*EXPIRY_FEATURES, CLAIM_EXPIRY_FEATURE, LAND_PROMISE_FEATURE))):
        raise SystemExit("BUILD_MANIFEST_MISMATCH")
    if type(version) is not int or version not in (10, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 51, 54, 55, 56, 57, 58, 59, 60):
        raise SystemExit("BUILD_MANIFEST_MISMATCH")
    source_records = manifest.get("sources", [])
    royal_source_present = (
        any(isinstance(record, dict)
            and isinstance(record.get("name"), str)
            and (record["name"] in ROYAL_RECORD_SOURCES
                 or record["name"].startswith("information-royal-record-"))
            for record in source_records)
        if isinstance(source_records, list) else True)
    if (version not in (58, 59, 60)
            and (ROYAL_RECORD_CAPABILITY in manifest
                 or royal_source_present
                 or _compiler_define_values(
                     manifest.get("compiler_arguments"), ROYAL_RECORD_DEFINE))):
        raise SystemExit("BUILD_MANIFEST_MISMATCH")
    directed_source_present = (
        any(isinstance(record, dict)
            and isinstance(record.get("name"), str)
            and (record["name"] in DIRECTED_RECORD_SOURCES
                 or record["name"].startswith("information-directed-record-"))
            for record in source_records)
        if isinstance(source_records, list) else True)
    if (version not in (59, 60)
            and (DIRECTED_RECORD_CAPABILITY in manifest
                 or directed_source_present
                 or _compiler_define_values(
                     manifest.get("compiler_arguments"), DIRECTED_RECORD_DEFINE))):
        raise SystemExit("BUILD_MANIFEST_MISMATCH")
    support_subject_record_source_present = (
        any(isinstance(record, dict)
            and isinstance(record.get("name"), str)
            and (record["name"] in SUPPORT_SUBJECT_RECORD_SOURCES
                 or record["name"].startswith("information-support-subject-record-"))
            for record in source_records)
        if isinstance(source_records, list) else True)
    if (version != 60
            and (SUPPORT_SUBJECT_RECORD_CAPABILITY in manifest
                 or support_subject_record_source_present
                 or _compiler_define_values(
                     manifest.get("compiler_arguments"), SUPPORT_SUBJECT_RECORD_DEFINE))):
        raise SystemExit("BUILD_MANIFEST_MISMATCH")
    if (version not in (41, 42, 43, 44, 45, 46, 47, 48, 51, 54, 55, 56, 57, 58, 59, 60)
            and (_compiler_define_values(
                manifest.get("compiler_arguments"), "BRIDGE_CALL_TO_ARMS_OBSERVATION")
                 or any(key in manifest for key in (
                     "call_to_arms_observation",
                     "call_to_arms_ai_response_held",
                     "call_to_arms_execution",
                 )))):
        raise SystemExit("BUILD_MANIFEST_MISMATCH")
    independent_line_keys = (
        "information_battle_independent_line",
        "information_battle_independent_line_wire",
        "information_battle_independent_line_native_formatter",
        "information_battle_independent_line_stage",
        "information_battle_independent_line_actual_popup",
    )
    if (version not in (42, 43, 44, 45, 46, 47, 48, 51, 54, 55, 56, 57, 58, 59, 60)
            and (_compiler_define_values(
                manifest.get("compiler_arguments"), "INFORMATION_BATTLE_INDEPENDENT_LINE")
                 or any(key in manifest for key in independent_line_keys))):
        raise SystemExit("BUILD_MANIFEST_MISMATCH")
    flag_inputs_keys = (
        "information_battle_flag_inputs",
        "information_battle_flag_inputs_wire",
        "information_battle_flag_inputs_stage",
        "information_battle_flag_inputs_actual_widget",
    )
    if (version not in (43, 44, 45, 46, 47, 48, 51, 54, 55, 56, 57, 58, 59, 60)
            and (_compiler_define_values(
                manifest.get("compiler_arguments"), "INFORMATION_BATTLE_FLAG_INPUTS")
                 or any(key in manifest for key in flag_inputs_keys))):
        raise SystemExit("BUILD_MANIFEST_MISMATCH")
    if (version not in (44, 45, 46, 47, 48, 51, 54, 55, 56, 57, 58, 59, 60)
            and (_compiler_define_values(manifest.get("compiler_arguments"), "BRIDGE_SUPPORT_ROLE_CONTEXT")
                 or any(key in manifest for key in SUPPORT_ROLE_CONTEXT_KEYS))):
        raise SystemExit("BUILD_MANIFEST_MISMATCH")
    if (version not in (45, 46, 47, 48, 51, 54, 55, 56, 57, 58, 59, 60)
            and (_compiler_define_values(manifest.get("compiler_arguments"), "BRIDGE_COUNTRY_MODIFIER_OBSERVATION")
                 or any(key in manifest for key in COUNTRY_MODIFIER_OBSERVATION_KEYS))):
        raise SystemExit("BUILD_MANIFEST_MISMATCH")
    if (version not in (46, 47, 48, 51, 54, 55, 56, 57, 58, 59, 60)
            and (_compiler_define_values(manifest.get("compiler_arguments"), "BRIDGE_COUNTRY_MODIFIER_REMOVAL")
                 or any(key in manifest for key in COUNTRY_MODIFIER_REMOVAL_KEYS))):
        raise SystemExit("BUILD_MANIFEST_MISMATCH")
    expiry_arguments = manifest.get("compiler_arguments")
    has_expiry_stub = isinstance(expiry_arguments, list) and any(
        isinstance(value, str) and Path(value).name == "information-country-modifier-expiry-entry.S"
        for value in expiry_arguments)
    if (version not in (47, 48, 51, 54, 55, 56, 57, 58, 59, 60)
            and (_compiler_define_values(manifest.get("compiler_arguments"), "BRIDGE_COUNTRY_MODIFIER_EXPIRY")
                 or any(key in manifest for key in COUNTRY_MODIFIER_EXPIRY_KEYS)
                 or has_expiry_stub)):
        raise SystemExit("BUILD_MANIFEST_MISMATCH")
    rival_source_present = any(
        isinstance(record, dict) and record.get("name") in RIVAL_CHANGE_SOURCES
        for record in manifest.get("sources", [])
    ) if isinstance(manifest.get("sources", []), list) else True
    if (version not in (48, 51, 54, 55, 56, 57, 58, 59, 60)
            and (_compiler_define_values(manifest.get("compiler_arguments"), "BRIDGE_RIVAL_OBSERVATION")
                 or any(key in manifest for key in RIVAL_CHANGE_KEYS)
                 or rival_source_present)):
        raise SystemExit("BUILD_MANIFEST_MISMATCH")
    macro_event_source_present = any(
        isinstance(record, dict) and record.get("name") in MACRO_EVENT_SOURCE_NAMES
        for record in manifest.get("sources", [])
    ) if isinstance(manifest.get("sources", []), list) else True
    if (version not in (51, 54, 55, 56, 57, 58, 59, 60)
            and (any(key in manifest for key in MACRO_EVENT_KEYS)
                 or macro_event_source_present
                 or any(_compiler_define_values(manifest.get("compiler_arguments"), define)
                        for define in (
                            "BRIDGE_WAR_DECLARATION_OBSERVATION",
                            "BRIDGE_RELATION_OBSERVATION",
                            "BRIDGE_MISSION_COMPLETION_OBSERVATION",
                        )))):
        raise SystemExit("BUILD_MANIFEST_MISMATCH")
    macro_source_present = any(
        isinstance(record, dict) and record.get("name") in MACRO_SOURCE_NAMES
        for record in manifest.get("sources", [])
    ) if isinstance(manifest.get("sources", []), list) else True
    if (version not in (54, 55, 56, 57, 58, 59, 60)
            and (any(key in manifest for key in MACRO_SOURCE_KEYS)
                 or macro_source_present
                 or any(_compiler_define_values(manifest.get("compiler_arguments"), define)
                        for define in MACRO_SOURCE_DEFINE_NAMES))):
        raise SystemExit("BUILD_MANIFEST_MISMATCH")
    condition_source_present = any(
        isinstance(record, dict) and record.get("name") in MISSION_CONDITION_SOURCES
        for record in manifest.get("sources", [])
    ) if isinstance(manifest.get("sources", []), list) else True
    if (version not in (56, 57, 58, 59, 60)
            and (any(key in manifest for key in MISSION_CONDITION_KEYS)
                 or condition_source_present
                 or any(_compiler_define_values(manifest.get("compiler_arguments"), define)
                        for define in (MISSION_CONDITION_DEFINE,)))):
        raise SystemExit("BUILD_MANIFEST_MISMATCH")
    province_source_present = any(
        isinstance(record, dict) and record.get("name") in MISSION_PROVINCE_CONDITION_SOURCES
        for record in manifest.get("sources", [])
    ) if isinstance(manifest.get("sources", []), list) else True
    if (version not in (57, 58, 59, 60) and (
            MISSION_PROVINCE_CONDITION_CAPABILITY in manifest or province_source_present
            or _compiler_define_values(manifest.get("compiler_arguments"), MISSION_PROVINCE_CONDITION_DEFINE))):
        raise SystemExit("BUILD_MANIFEST_MISMATCH")
    dll = directory / f"eu4_bridge_diplomacy_observer_v{manifest['version']}.dll"
    if version in (23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 51, 54, 55, 56, 57, 58, 59, 60):
        if not _is_sha256(manifest.get("dll_sha256")):
            raise SystemExit("BUILD_MANIFEST_MISMATCH")
        _validate_information_battle_manifest(manifest, directory)
    if not dll.is_file() or file_hash(dll) != manifest["dll_sha256"]:
        raise SystemExit("BUILD_MANIFEST_MISMATCH")
    if (directory / "installation.json").exists():
        raise SystemExit("EXPERIMENT_ALREADY_ATTEMPTED_USE_NEW_DIRECTORY_AND_PROCESS")
    ready_options = {}
    if args.load_warning_save_name is not None:
        ready_options["load_warning_save_name"] = args.load_warning_save_name
    identity, state, confirmation, ready_reason, attempts = _wait_until_ready(
        args.pid, manifest, directory, args.confirm_load_warning, args.wait_ready, **ready_options)
    _install_once(args.pid, manifest, directory, dll, get_value("EU4_PYTHON"),
                  identity, state, confirmation, ready_reason, attempts, args.native_text_codec)
    print(json.dumps({"installed": True, "experiment_id": manifest["experiment_id"],
                      "session_id": identity["session_id"], "confirmation_queued": bool(confirmation),
                      "ready_reason": ready_reason, "ready_attempts": len(attempts),
                      "diplomacy_runtime_verified": False}), flush=True)


if __name__ == "__main__":
    main()
