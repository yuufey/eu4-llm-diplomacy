// Fixed1374 research source. Included once by the v23/v24/v25 observer only.
// Capture is disabled until a process/DLL/player-bound file command enables it.
// v30 optionally invokes the guarded title helper into a fresh owned string;
// earlier builds only copy. Published code, unwind rows and the containing DLL
// remain alive until process exit, including after disable.
#include "information-battle-entry-plan.h"
#include "information-battle-observation-wire.h"
#ifdef INFORMATION_BATTLE_CONTEXT
#include "information-battle-context-wire.h"
#endif
#ifdef INFORMATION_BATTLE_NAVAL
#include "information-battle-naval-wire.h"
#endif
#ifdef INFORMATION_BATTLE_TEMPLATE
#include "information-battle-template-wire.h"
#include "information-battle-message-entry-plan.h"
#endif
#ifdef INFORMATION_BATTLE_WAR_IDENTITY
#include "information-battle-war-identity-wire.h"
#include "information-battle-war-binding.h"
#endif
#ifdef INFORMATION_BATTLE_NATIVE_TEXT
#include "information-battle-native-text-wire.h"
#include "information-battle-line1-entry-plan.h"
#endif
#ifdef INFORMATION_BATTLE_NATIVE_TITLE_QUERY
#include "information-battle-owned-title-query.h"
#include "information-battle-title-query-plan.h"
#endif
#ifdef INFORMATION_BATTLE_DISPLAY_CONTEXT
#include "information-battle-owned-display-context.h"
#include "information-battle-display-context-wire.h"
#ifndef INFORMATION_BATTLE_GATE_TRACE
#error Display context requires the complete v32 observation path.
#endif
#endif
#ifdef INFORMATION_BATTLE_END_STATE
#ifndef INFORMATION_BATTLE_DISPLAY_CONTEXT
#error End-state copying requires the validated display/context owner path.
#endif
#include "information-battle-owned-end-state.h"
#include "information-battle-end-state-wire.h"
#endif
#ifdef INFORMATION_BATTLE_RETREAT
#ifndef INFORMATION_BATTLE_END_STATE
#error Retreat copying requires the complete v9 battle owner path.
#endif
#include "information-battle-retreat-wire.h"
#include "information-battle-owned-retreat.h"
#include "information-battle-retreat-entry-plan.h"
extern "C" void information_battle_outcome_retreat_hook(void*, void*, void*, unsigned char);
extern "C" void information_battle_unit_retreat_hook(void*, unsigned char, unsigned char);
extern "C" void information_battle_unit_removal_retreat_hook(void*, void*, unsigned char);
extern "C" { void* information_battle_outcome_retreat_original = nullptr;
             void* information_battle_unit_retreat_original = nullptr;
             void* information_battle_unit_removal_retreat_original = nullptr; }
#endif
#ifdef INFORMATION_BATTLE_NAME_SOURCES
#ifndef INFORMATION_BATTLE_RETREAT
#error Name sources require the complete v10 battle owner path.
#endif
#include "information-battle-owned-name-sources.h"
#include "information-battle-owned-name-prefix.h"
#include "information-battle-name-sources-wire.h"
#endif
#ifdef INFORMATION_BATTLE_OUTCOME_TEXT
#ifndef INFORMATION_BATTLE_NAME_SOURCES
#error Outcome text requires the complete v11 source path.
#endif
#ifndef INFORMATION_BATTLE_NO_TITLE_QUERY_INVOKE
#error Outcome text must not invoke the native title helper.
#endif
#include "information-battle-outcome-text-record.h"
#endif
#ifdef INFORMATION_BATTLE_OUTCOME_TAIL
#ifndef INFORMATION_BATTLE_OUTCOME_TEXT
#error Outcome tail requires the complete wire12 outcome source path.
#endif
#include "information-battle-outcome-tail-record.h"
#endif
#ifdef INFORMATION_BATTLE_INDEPENDENT_LINE
#ifndef INFORMATION_BATTLE_OUTCOME_TAIL
#error Independent line formatting requires the complete wire13 input path.
#endif
#include "information-battle-owned-independent-line.h"
#include "information-battle-independent-line-plan.h"
#endif
#ifdef INFORMATION_BATTLE_FLAG_INPUTS
#ifndef INFORMATION_BATTLE_INDEPENDENT_LINE
#error Flag inputs require the complete wire14 path.
#endif
#include "information-battle-owned-flag-inputs.h"
#endif
#include "information-battle-drain.h"
#include "information-battle-log-writer.h"
#include "information-battle-fragment.h"
#ifdef INFORMATION_BATTLE_GATE_TRACE
#include "information-battle-gate-trace.h"
#include "information-battle-gate-marker-entry-plan.h"
#ifndef INFORMATION_BATTLE_NATIVE_TEXT
#error Gate diagnostics require the complete wire6 observation path.
#endif
extern "C" void information_battle_gate_marker_hook();
extern "C" { void* information_battle_gate_marker_original = nullptr; }
#endif
#include <wincrypt.h>
#include <atomic>
#include <climits>
#ifdef INFORMATION_BATTLE_NAME_HANDOFF
#ifndef INFORMATION_BATTLE_DISPLAY_CONTEXT
#error NAME handoff requires the complete v7 observation path.
#endif
#include "information-battle-name-handoff-entry-plan.h"
#include "information-battle-name-handoff-wire.h"
extern "C" void information_battle_name_handoff_hook();
extern "C" { void* information_battle_name_handoff_original = nullptr; }
#endif

extern "C" void information_battle_entry_stub();
extern "C" { void* information_battle_entry_original = nullptr; }
#ifdef INFORMATION_BATTLE_TEMPLATE
extern "C" void information_battle_router_hook(void*, unsigned char);
extern "C" void information_battle_message_hook(void*, void*, void*, void*);
#ifdef INFORMATION_BATTLE_CONTAINER
extern "C" void information_battle_container_hook(void*);
extern "C" { void* information_battle_container_original = nullptr; }
#endif
extern "C" { void* information_battle_router_original = nullptr;
             void* information_battle_message_original = nullptr; }
#endif
#ifdef INFORMATION_BATTLE_NATIVE_TEXT
// The Line1 entry is installed and guarded here, while its capture owner is
// supplied by the observer translation unit.  Keep this declaration-only: the
// ABI stub owns register preservation and passes the original return/RBP to the
// eventual capture implementation.
extern "C" void information_battle_line1_hook(void*, void*, unsigned char);
extern "C" void information_battle_line1_capture(void* widget, void* text,
    unsigned char flag, void* return_pc, uintptr_t original_rbp, uintptr_t original_r13) noexcept;
extern "C" { void* information_battle_line1_original = nullptr; }
#endif

namespace information_battle_source {
namespace battle = information::battle;
namespace entry = battle::entry;
namespace observation = battle::observation;
#ifdef INFORMATION_BATTLE_GATE_TRACE
namespace gate_trace = battle::gate_trace;
namespace gate_inputs = battle::owned_gate_inputs;
namespace gate_marker_plan = battle::gate_marker_entry;
#endif
#ifdef INFORMATION_BATTLE_CONTEXT
namespace context_wire = battle::context_wire;
#ifdef INFORMATION_BATTLE_NAVAL
namespace naval_wire = battle::naval_wire;
#ifdef INFORMATION_BATTLE_TEMPLATE
namespace template_wire = battle::template_wire;
#ifdef INFORMATION_BATTLE_WAR_IDENTITY
namespace war_identity_wire = battle::war_identity_wire;
#ifdef INFORMATION_BATTLE_NATIVE_TEXT
namespace native_text_wire = battle::native_text_wire;
namespace native_text = battle::owned_native_text;
#ifdef INFORMATION_BATTLE_NAME_HANDOFF
namespace name_handoff = battle::owned_name_handoff;
namespace name_entry_plan = battle::name_handoff_entry;
namespace name_wire = battle::name_handoff_wire;
#endif
#ifdef INFORMATION_BATTLE_DISPLAY_CONTEXT
namespace display_context_model = battle::display_context;
namespace display_context_capture = battle::owned_display_context;
namespace display_context_wire = battle::display_context_wire;
#endif
struct Record final {
    war_identity_wire::WarIdentityObservation base{};
    native_text::Snapshot native_text{};
    bool native_text_invalid = false;
    bool line1_invalid = false;
#ifdef INFORMATION_BATTLE_INDEPENDENT_LINE
    battle::independent_line_wire::Snapshot independent_line{};
#ifdef INFORMATION_BATTLE_FLAG_INPUTS
    battle::flag_input_wire::Snapshot flag_inputs{};
#endif
#endif
#ifdef INFORMATION_BATTLE_NAME_SOURCES
    battle::name_sources_wire::Snapshot name_sources{};
#endif
#ifdef INFORMATION_BATTLE_OUTCOME_TEXT
    battle::outcome_text_wire::Snapshot outcome_text{};
#ifdef INFORMATION_BATTLE_OUTCOME_TAIL
    battle::outcome_tail_wire::Snapshot outcome_tail{};
#endif
#endif
#ifdef INFORMATION_BATTLE_RETREAT
    battle::retreat_wire::Snapshot retreat{};
#endif
#ifdef INFORMATION_BATTLE_END_STATE
    battle::owned_end_state::Snapshot end_state{};
    bool end_state_present = false;
#endif
#ifdef INFORMATION_BATTLE_NAME_HANDOFF
    name_handoff::Snapshot name_handoff{};
    bool name_handoff_invalid = false;
#endif
#ifdef INFORMATION_BATTLE_DISPLAY_CONTEXT
    display_context_model::Snapshot display_context{};
#endif
#ifdef INFORMATION_BATTLE_GATE_TRACE
    gate_trace::Snapshot trace{};
#endif
};
#ifdef INFORMATION_BATTLE_DISPLAY_CONTEXT
#ifdef INFORMATION_BATTLE_NAME_HANDOFF
constexpr unsigned kWireVersion =
#ifdef INFORMATION_BATTLE_FLAG_INPUTS
    15;
#elif defined(INFORMATION_BATTLE_INDEPENDENT_LINE)
    14;
#elif defined(INFORMATION_BATTLE_OUTCOME_TAIL)
    13;
#elif defined(INFORMATION_BATTLE_OUTCOME_TEXT)
    12;
#elif defined(INFORMATION_BATTLE_NAME_SOURCES)
    11;
#elif defined(INFORMATION_BATTLE_RETREAT)
    10;
#elif defined(INFORMATION_BATTLE_END_STATE)
    9;
#else
    8;
#endif
static unsigned char encoded_v7[display_context_wire::kMaxWireBytes]{};
static name_handoff::Workspace name_workspace{};
static name_handoff::Snapshot name_scratch{};
static std::atomic<uint64_t> name_candidates{0}, name_copied{0}, name_failed{0}, name_conflicts{0};
#else
constexpr unsigned kWireVersion =
#ifdef INFORMATION_BATTLE_FLAG_INPUTS
    15;
#elif defined(INFORMATION_BATTLE_INDEPENDENT_LINE)
    14;
#elif defined(INFORMATION_BATTLE_OUTCOME_TAIL)
    13;
#elif defined(INFORMATION_BATTLE_OUTCOME_TEXT)
    12;
#elif defined(INFORMATION_BATTLE_NAME_SOURCES)
    11;
#elif defined(INFORMATION_BATTLE_RETREAT)
    10;
#elif defined(INFORMATION_BATTLE_END_STATE)
    9;
#else
    7;
#endif
#endif
static unsigned char encoded_v6[native_text_wire::kMaxWireBytes]{};
static display_context_capture::Workspace display_context_workspace{};
#ifdef INFORMATION_BATTLE_INDEPENDENT_LINE
static battle::owned_independent_line::Workspace independent_line_workspace{};
#ifdef INFORMATION_BATTLE_FLAG_INPUTS
static battle::owned_template::detail::ReadLog flag_input_log{};
static battle::owned_template::Snapshot flag_message_template{};
static battle::owned_flag_inputs::Workspace flag_input_workspace{};
static std::atomic<uint64_t> flag_input_candidates{0}, flag_input_copied{0},
    flag_input_failed{0}, flag_input_encode_failed{0};
#endif
static display_context_model::Snapshot independent_line_context_check{};
static std::atomic<uint64_t> independent_line_candidates{0}, independent_line_invoked{0},
    independent_line_copied{0}, independent_line_failed{0}, independent_line_encode_failed{0};
#endif
static std::atomic<uint64_t> display_context_candidates{0}, display_context_copied{0},
    display_context_failures{0};
static std::atomic<unsigned> display_context_last_failure{0};
#else
constexpr unsigned kWireVersion = 6;
#endif
constexpr size_t kEncodedBytes = native_text_wire::kMaxWireBytes;
static war_identity_wire::WarIdentityObservation& war_values(Record& record) noexcept { return record.base; }
static unsigned char encoded_v5[war_identity_wire::kMaxWireBytes]{};
// Capture runs under capture_lock on the bound frame thread. Keep the
// reusable output off the native frame stack and never expose its pointers.
static native_text::Snapshot native_text_scratch{};
static native_text::Snapshot native_text_joined{};
static battle::owned_template::Snapshot native_popup_message{};
static std::atomic<uint64_t> native_metadata_copied{0}, native_metadata_failed{0};
static std::atomic<uint64_t> line1_candidates{0}, line1_no_scope{0}, line1_binding_rejected{0},
    line1_copied{0}, line1_copy_failed{0};
#ifdef INFORMATION_BATTLE_NATIVE_TITLE_QUERY
namespace title_query = battle::owned_title_query;
namespace title_plan = battle::title_query_plan;
#ifndef INFORMATION_BATTLE_NO_TITLE_QUERY_INVOKE
static title_query::Workspace title_workspace{};
#endif
// Set only during startup after pinning the already-loaded, hash-bound plugin.
// An unchanged helper needs no plugin dependency.
static uintptr_t title_plugin_base = 0;
static size_t title_plugin_image_size = 0;
static HANDLE title_plugin_lease = INVALID_HANDLE_VALUE;
static std::atomic<uint64_t> title_query_candidates{0}, title_query_attempted{0},
    title_query_destroyed{0}, title_query_copied{0}, title_query_failed{0};
#endif
#else
using Record = war_identity_wire::WarIdentityObservation;
constexpr unsigned kWireVersion = 5;
constexpr size_t kEncodedBytes = war_identity_wire::kMaxWireBytes;
static war_identity_wire::WarIdentityObservation& war_values(Record& record) noexcept { return record; }
#endif
static template_wire::TemplateObservation& template_values(Record& record) noexcept { return war_values(record).base; }
static naval_wire::NavalObservation& naval_values(Record& record) noexcept { return war_values(record).base.base; }
static context_wire::ContextObservation& contexts(Record& record) noexcept { return war_values(record).base.base.base; }
static observation::Observation& values(Record& record) noexcept { return war_values(record).base.base.base.inner; }
#else
using Record = template_wire::TemplateObservation;
constexpr unsigned kWireVersion = 4;
constexpr size_t kEncodedBytes = template_wire::kMaxWireBytes;
static naval_wire::NavalObservation& naval_values(Record& record) noexcept { return record.base; }
static context_wire::ContextObservation& contexts(Record& record) noexcept { return record.base.base; }
static observation::Observation& values(Record& record) noexcept { return record.base.base.inner; }
static template_wire::TemplateObservation& template_values(Record& record) noexcept { return record; }
#endif
#else
using Record = naval_wire::NavalObservation;
constexpr unsigned kWireVersion = 3;
constexpr size_t kEncodedBytes = naval_wire::kMaxWireBytes;
static context_wire::ContextObservation& contexts(Record& record) noexcept { return record.base; }
static observation::Observation& values(Record& record) noexcept { return record.base.inner; }
static naval_wire::NavalObservation& naval_values(Record& record) noexcept { return record; }
#endif
#else
using Record = context_wire::ContextObservation;
constexpr unsigned kWireVersion = 2;
constexpr size_t kEncodedBytes = context_wire::kMaxWireBytes;
static context_wire::ContextObservation& contexts(Record& record) noexcept { return record; }
static observation::Observation& values(Record& record) noexcept { return record.inner; }
#endif
static size_t game_image_size = 0;
#else
using Record = observation::Observation;
constexpr unsigned kWireVersion = 1;
constexpr size_t kEncodedBytes = observation::kMaxWireBytes;
static observation::Observation& values(Record& record) noexcept { return record; }
#endif
constexpr char kExeSha[] = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77";
constexpr uintptr_t kEntryRva = 0x238620, kUnwindRva = 0x1de6c98;
constexpr unsigned kSlots = 8;
enum State : long { cold, ready, enabled, disabled, source_changed, fault, restart_required };
static std::atomic<long> state{cold};
static SRWLOCK capture_lock = SRWLOCK_INIT;
static Record slots[kSlots]{};
static Record pending{};
#ifdef INFORMATION_BATTLE_NAME_SOURCES
static battle::owned_name_sources::Workspace name_sources_workspace{};
static battle::owned_name_prefix::Workspace name_prefix_workspace{};
static battle::owned_name_sources::Snapshot name_sources_scratch{};
static battle::owned_name_prefix::Snapshot name_prefix_scratch{};
static std::atomic<uint64_t> name_source_candidates{0}, name_source_copied{0},
    name_prefix_copied{0}, name_source_encode_failed{0};
#endif
#ifdef INFORMATION_BATTLE_OUTCOME_TEXT
static battle::owned_outcome_text::Workspace outcome_text_workspace{};
static battle::owned_outcome_text::Snapshot outcome_text_scratch{};
static std::atomic<uint64_t> outcome_text_candidates{0}, outcome_text_copied{0},
    outcome_text_failed{0}, outcome_text_encode_failed{0};
static std::atomic<unsigned> outcome_text_last_failure{0};
#ifdef INFORMATION_BATTLE_OUTCOME_TAIL
static battle::owned_outcome_tail::Workspace outcome_tail_workspace{};
static battle::owned_outcome_tail::Snapshot outcome_tail_scratch{};
static std::atomic<uint64_t> outcome_tail_candidates{0}, outcome_tail_copied{0},
    outcome_tail_failed{0}, outcome_tail_encode_failed{0};
static std::atomic<unsigned> outcome_tail_last_failure{0};
#endif
#endif
static unsigned head = 0, count = 0;
static bool has_pending = false;
static battle::fragment::FragmentPlan fragment_plan{};
static uint32_t fragment_index = 0;
static unsigned char encoded[kEncodedBytes]{};
#ifdef INFORMATION_BATTLE_END_STATE
static unsigned char encoded_end_state_base[kEncodedBytes]{};
#endif
static size_t encoded_bytes = 0;
static battle::OwnedBattleDrain drain;
static battle::Win32BattleLogIo io;
static battle::CheckedBattleLogWriter writer(io);
static battle::Identity identity{};
static uint64_t creation = 0, player = 0;
static uintptr_t game = 0;
static DWORD bound_thread = 0;
// A date regression invalidates this source generation. Same-address reloads
// at the identical date still require a separate load lifecycle signal.
static int32_t last_date = 0;
static char dll_sha[65]{};
static HANDLE exe_lease=INVALID_HANDLE_VALUE, dll_lease=INVALID_HANDLE_VALUE;
static uintptr_t source_row_address=0;
static wchar_t directory[MAX_PATH]{}, request_path[MAX_PATH]{}, processing_path[MAX_PATH]{}, log_path[MAX_PATH]{};
static entry::Plan plan{};
static bridge_entry_patch::PatchPlan patch{};
static RUNTIME_FUNCTION unwind{};
static unsigned char* trampoline = nullptr;
static bool patched = false, table_registered = false, dll_pinned = false;
#ifdef INFORMATION_BATTLE_TEMPLATE
namespace message_entry = battle::message_entry;
struct MessageEntry final {
    message_entry::Plan plan{};
    RUNTIME_FUNCTION unwind{};
    unsigned char* trampoline = nullptr;
    uintptr_t source_row = 0;
    bool table_registered = false, patched = false;
};
#ifdef INFORMATION_BATTLE_CONTAINER
constexpr unsigned kMessageEntryCount = 3;
#else
constexpr unsigned kMessageEntryCount = 2;
#endif
static MessageEntry message_entries[kMessageEntryCount]{};
#endif
#ifdef INFORMATION_BATTLE_NATIVE_TEXT
namespace line1_entry_plan = battle::line1_entry;
struct Line1Entry final {
    line1_entry_plan::Plan plan{};
    RUNTIME_FUNCTION unwind{};
    unsigned char* trampoline = nullptr;
    uintptr_t source_row = 0;
    bool table_registered = false, patched = false;
};
static Line1Entry line1_entry{};
#endif
#ifdef INFORMATION_BATTLE_NAME_HANDOFF
struct NameEntry final {
    name_entry_plan::Plan plan{};
    RUNTIME_FUNCTION unwind{};
    unsigned char* trampoline = nullptr;
    bool table_registered = false, patched = false;
};
static NameEntry name_entry{};
#endif
#ifdef INFORMATION_BATTLE_GATE_TRACE
struct GateMarkerEntry final {
    gate_marker_plan::Plan plan{};
    RUNTIME_FUNCTION unwind{};
    unsigned char* trampoline = nullptr;
    uintptr_t source_row = 0;
    bool table_registered = false;
};
static GateMarkerEntry gate_marker_entry{};
static std::atomic<uint64_t> trace_observation_drops{0}, trace_records_written{0}, trace_write_failures{0};
static wchar_t trace_log_path[MAX_PATH]{};
static bool trace_file_created = false;
static DWORD trace_volume = 0, trace_file_index_high = 0, trace_file_index_low = 0;
static uint64_t trace_file_bytes = 0;
static DWORD trace_write_error = ERROR_SUCCESS;
#endif
static unsigned publication_stage=0;
static bridge_entry_patch::PatchResult last_patch_result{};
static std::atomic<uint64_t> sequence{0}, accepted{0}, busy{0}, full{0}, foreign_thread{0}, copy_failed{0}, guard_failed{0};
static std::atomic<uint64_t> context_copied{0}, context_copy_failed{0};
static uint64_t last_poll = 0, last_status = 0;
static bool heartbeat_publication_pending = false;
static uint64_t heartbeat_retry_next = 0, heartbeat_retry_deadline = 0;
static unsigned heartbeat_publication_failures = 0;
static const char* last_status_write_stage = "none";
static DWORD last_status_write_error = ERROR_SUCCESS;
#ifdef INFORMATION_BATTLE_TEMPLATE
// Only the bound frame thread can enter this stack. No lock remains held
// while the original router, formatter, callbacks or message consumer run.
// Combat addresses are private scope guards, never serialized identities.
constexpr unsigned kScopeLimit = 8;
struct MessageScope final {
    uintptr_t combat = 0;
    bool has_record = false, ambiguous = false, message_seen = false, container_seen = false;
#ifdef INFORMATION_BATTLE_FLAG_INPUTS
    bool flag_container_seen = false;
#endif
    unsigned slot = 0;
    uint64_t sequence = 0;
#ifdef INFORMATION_BATTLE_GATE_TRACE
    gate_trace::Snapshot trace{};
    uint64_t trace_drops_before = 0;
#endif
#ifdef INFORMATION_BATTLE_NATIVE_TEXT
    // Private synchronous-copy guard: definition pointer plus copied opaque
    // values. Never serialized and cleared before this owner leaves scope.
    std::array<unsigned char,72> message_copy_guard{};
    bool has_message_copy_guard = false;
#endif
};
struct ScopeToken final { unsigned depth = 0; bool suppressed = false; };
static MessageScope scopes[kScopeLimit]{};
static bool slot_ready[kSlots]{};
static unsigned scope_depth = 0, suppressed_scopes = 0;
#ifdef INFORMATION_BATTLE_DISPLAY_CONTEXT
static void capture_display_context(MessageScope&) noexcept;
#ifdef INFORMATION_BATTLE_INDEPENDENT_LINE
static void capture_independent_line(MessageScope&) noexcept;
#endif
#endif
static std::atomic<uint64_t> template_copied{0}, template_copy_failed{0}, template_ambiguous{0}, scope_overflow{0};
#ifdef INFORMATION_BATTLE_GATE_TRACE
static void sample_gate_inputs(MessageScope&,gate_trace::Stage) noexcept;
static bool code_guard() noexcept;
static uint32_t trace_rva(uintptr_t) noexcept;
#endif
#ifdef INFORMATION_BATTLE_RETREAT
static bool retreat_code_guard() noexcept;
static bool retreat_defer_ready_locked(unsigned, uint64_t) noexcept;
#endif
#ifdef INFORMATION_BATTLE_NAME_HANDOFF
static void finalize_name_handoff(MessageScope&) noexcept;
#endif
#ifdef INFORMATION_BATTLE_NAME_SOURCES
static void finalize_name_sources(MessageScope&) noexcept;
#endif
#ifdef INFORMATION_BATTLE_OUTCOME_TEXT
static void finalize_outcome_text(MessageScope&) noexcept;
#ifdef INFORMATION_BATTLE_OUTCOME_TAIL
static void finalize_outcome_tail(MessageScope&) noexcept;
#endif
#endif
#ifdef INFORMATION_BATTLE_CONTAINER
static std::atomic<uint64_t> container_candidates{0}, container_copied{0}, container_copy_failed{0};
#endif
static ScopeToken begin_scope(void* combat, uintptr_t router_return_pc = 0) noexcept {
#ifndef INFORMATION_BATTLE_GATE_TRACE
    (void)router_return_pc;
#endif
    if (state.load(std::memory_order_acquire)!=enabled || GetCurrentThreadId()!=bound_thread) return {};
    AcquireSRWLockExclusive(&capture_lock);
    ScopeToken token{};
    if (state.load(std::memory_order_acquire)==enabled) {
        if (scope_depth==kScopeLimit || suppressed_scopes) {
            ++suppressed_scopes; scope_overflow.fetch_add(1); token.suppressed=true;
#ifdef INFORMATION_BATTLE_GATE_TRACE
            // Suppressed nested work can hide entry observations in every
            // still-open owner. A global incident invalidates all their
            // per-scope zero-count conclusions through the existing baseline.
            trace_observation_drops.fetch_add(1);
#endif
        } else {
            auto& scope=scopes[scope_depth++];
            scope.combat=reinterpret_cast<uintptr_t>(combat);
            scope.has_record=false; scope.ambiguous=false; scope.message_seen=false; scope.container_seen=false;
#ifdef INFORMATION_BATTLE_FLAG_INPUTS
            scope.flag_container_seen=false;
#endif
            scope.slot=0; scope.sequence=0;
#ifdef INFORMATION_BATTLE_GATE_TRACE
            scope.trace={};scope.trace_drops_before=trace_observation_drops.load(std::memory_order_relaxed);
            scope.trace.router_return_rva=trace_rva(router_return_pc);
#endif
#ifdef INFORMATION_BATTLE_NATIVE_TEXT
            scope.message_copy_guard.fill(0);scope.has_message_copy_guard=false;
#endif
            token.depth=scope_depth;
        }
    }
    ReleaseSRWLockExclusive(&capture_lock);
    return token;
}
static void end_scope(ScopeToken token) noexcept {
    if (!token.depth && !token.suppressed) return;
    AcquireSRWLockExclusive(&capture_lock);
    if (token.suppressed) {
        if (suppressed_scopes) --suppressed_scopes;
        else state.store(fault,std::memory_order_release);
    } else if (scope_depth!=token.depth || suppressed_scopes) {
        // Never pair a later callback with an unclosed or mismatched owner.
        // Observation stops; the native call remains forwarded normally.
        state.store(fault,std::memory_order_release);
    } else {
        auto& scope=scopes[--scope_depth];
        const long current=state.load(std::memory_order_acquire);
        if (scope.has_record && (current==enabled || current==disabled)) {
            if (scope.slot>=kSlots || values(slots[scope.slot]).sequence!=scope.sequence
                || slot_ready[scope.slot]) state.store(fault,std::memory_order_release);
            else {
#ifdef INFORMATION_BATTLE_GATE_TRACE
                sample_gate_inputs(scope,gate_trace::Stage::scope_exit);
                scope.trace.scope_guards_after=current==enabled && code_guard();
                scope.trace.scope_completed=true;scope.trace.scope_ambiguous=scope.ambiguous;
                const auto drops=trace_observation_drops.load(std::memory_order_relaxed);
                scope.trace.observation_drops=drops>=scope.trace_drops_before
                    ? drops-scope.trace_drops_before:UINT64_MAX;
                slots[scope.slot].trace=scope.trace;
#endif
#ifdef INFORMATION_BATTLE_DISPLAY_CONTEXT
                capture_display_context(scope);
#endif
#ifdef INFORMATION_BATTLE_NAME_HANDOFF
                finalize_name_handoff(scope);
#endif
#ifdef INFORMATION_BATTLE_NAME_SOURCES
                finalize_name_sources(scope);
#endif
#ifdef INFORMATION_BATTLE_OUTCOME_TEXT
                finalize_outcome_text(scope);
#ifdef INFORMATION_BATTLE_OUTCOME_TAIL
                finalize_outcome_tail(scope);
#endif
#endif
#ifdef INFORMATION_BATTLE_INDEPENDENT_LINE
                capture_independent_line(scope);
#endif
#ifdef INFORMATION_BATTLE_RETREAT
                slot_ready[scope.slot]=!retreat_defer_ready_locked(scope.slot,scope.sequence);
#else
                slot_ready[scope.slot]=true;
#endif
            }
        }
        scope.combat=0; scope.has_record=false;
#ifdef INFORMATION_BATTLE_NATIVE_TEXT
        scope.message_copy_guard.fill(0);scope.has_message_copy_guard=false;
#endif
    }
    ReleaseSRWLockExclusive(&capture_lock);
}
#endif
static void transition(long next) noexcept {
    AcquireSRWLockExclusive(&capture_lock);
    const long current=state.load(std::memory_order_acquire);
    // Preserve the first terminal state for diagnosis. Status/file failures
    // after a patch failure must not hide that a restart was required.
    if (current<source_changed) state.store(next,std::memory_order_release);
    ReleaseSRWLockExclusive(&capture_lock);
}
static void close_startup_leases() noexcept {
    if (exe_lease!=INVALID_HANDLE_VALUE) {CloseHandle(exe_lease);exe_lease=INVALID_HANDLE_VALUE;}
    if (dll_lease!=INVALID_HANDLE_VALUE) {CloseHandle(dll_lease);dll_lease=INVALID_HANDLE_VALUE;}
#ifdef INFORMATION_BATTLE_NATIVE_TITLE_QUERY
    if (title_plugin_lease!=INVALID_HANDLE_VALUE) {
        CloseHandle(title_plugin_lease);title_plugin_lease=INVALID_HANDLE_VALUE;
    }
    title_plugin_base=0;title_plugin_image_size=0;
#endif
}

struct Reader final {
    bool read(uintptr_t address, unsigned char* output, size_t size) noexcept {
        SIZE_T actual = 0;
        return address >= 0x10000 && address < 0x800000000000ull
            && size && size <= 65536 && size <= 0x800000000000ull-address
            && ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<void*>(address), output, size, &actual)
            && actual == size;
    }
};
template<class T> static bool read_value(uintptr_t address, T& output) noexcept {
    Reader reader;
    return reader.read(address,reinterpret_cast<unsigned char*>(&output),sizeof(output));
}
#ifdef INFORMATION_BATTLE_GATE_TRACE
static uint32_t trace_rva(uintptr_t address) noexcept {
    return address>=base && address-base<game_image_size
        ? static_cast<uint32_t>(address-base):0;
}
static void sample_gate_inputs(MessageScope& scope,gate_trace::Stage stage) noexcept {
    const unsigned index=static_cast<unsigned>(stage);
    if (index>=static_cast<unsigned>(gate_trace::Stage::count)
        || (scope.trace.sample_mask&(1u<<index)) || !scope.has_record || scope.slot>=kSlots) return;
    const auto& record=slots[scope.slot];
    if (values(slots[scope.slot]).sequence!=scope.sequence || !record.base.base.base.base.context_present) return;
    const auto kind=record.base.base.base.base.context.kind;
    if (kind!=battle::owned_context::Kind::land && kind!=battle::owned_context::Kind::naval) return;
    Reader reader;
    if (stage==gate_trace::Stage::context_capture)
        scope.trace.scope_guards_before=state.load(std::memory_order_acquire)==enabled && code_guard();
    gate_inputs::capture(reader,game,scope.combat,
        kind==battle::owned_context::Kind::land?gate_inputs::Kind::land:gate_inputs::Kind::naval,
        scope.trace.samples[index]);
    scope.trace.sample_mask|=1u<<index;
}
// Call only under capture_lock. This validates the formatter's saved router
// return and owner without assigning identity from a coincident date/type.
static uint32_t trace_formatter_binding(const MessageScope& scope,uintptr_t frame,bool land) noexcept {
    if (!entry::valid_code_address(frame,0x1e0)) return gate_trace::invalid_frame;
    const uintptr_t offset=land?0x1d8:0x198;
    uintptr_t caller=0,owner=0;
    if (!read_value(frame+offset,caller) || caller!=base+(land?0x23a446:0x23a42a))
        return gate_trace::invalid_caller;
    if (!read_value(frame+offset-0x20,owner) || owner!=scope.combat) return gate_trace::invalid_owner;
    if (!scope.has_record || scope.slot>=kSlots) return gate_trace::no_record;
    if (values(slots[scope.slot]).sequence!=scope.sequence) return gate_trace::wrong_sequence;
    if (!contexts(slots[scope.slot]).context_present) return gate_trace::missing_context;
    const auto expected=land?battle::owned_context::Kind::land:battle::owned_context::Kind::naval;
    return contexts(slots[scope.slot]).context.kind==expected?0u:gate_trace::wrong_kind;
}
static void capture_gate_marker(uintptr_t return_pc,uintptr_t frame) noexcept {
    if (state.load(std::memory_order_acquire)!=enabled || GetCurrentThreadId()!=bound_thread
        || (return_pc!=base+0x2353db && return_pc!=base+0x230b59)) return;
    if (!TryAcquireSRWLockExclusive(&capture_lock)) {trace_observation_drops.fetch_add(1);return;}
    if (state.load(std::memory_order_acquire)==enabled && scope_depth && !suppressed_scopes) {
        auto& scope=scopes[scope_depth-1];auto& trace=scope.trace;
        gate_trace::increment(trace.passed_marker_candidates,trace);
        trace.last_marker_return_rva=trace_rva(return_pc);
        const auto rejected=trace_formatter_binding(scope,frame,return_pc==base+0x2353db);
        trace.marker_reject_mask|=rejected;
        if (!rejected) {
            gate_trace::increment(trace.passed_marker_accepted,trace);
            sample_gate_inputs(scope,gate_trace::Stage::passed_marker);
        }
    }
    ReleaseSRWLockExclusive(&capture_lock);
}
static void trace_message_entry(void* callback,uintptr_t return_pc,uintptr_t frame) noexcept {
    if (state.load(std::memory_order_acquire)!=enabled || GetCurrentThreadId()!=bound_thread) return;
    if (!TryAcquireSRWLockExclusive(&capture_lock)) {trace_observation_drops.fetch_add(1);return;}
    if (state.load(std::memory_order_acquire)==enabled && scope_depth && !suppressed_scopes) {
        auto& scope=scopes[scope_depth-1];auto& trace=scope.trace;
        gate_trace::increment(trace.message_entries,trace);
        trace.last_message_return_rva=trace_rva(return_pc);
        uint32_t rejected=0;
        const bool known_pc=return_pc==base+0x236721 || return_pc==base+0x232a13;
        if (!known_pc) rejected|=gate_trace::wrong_return;
        else rejected|=trace_formatter_binding(scope,frame,return_pc==base+0x236721);
        if (reinterpret_cast<uintptr_t>(callback)!=base+0x2ec0a0) rejected|=gate_trace::wrong_callback;
        if (scope.ambiguous) rejected|=gate_trace::ambiguous_scope;
        if (scope.slot<kSlots && slot_ready[scope.slot]) rejected|=gate_trace::ready_slot;
        if (scope.message_seen) rejected|=gate_trace::duplicate_message;
        trace.message_reject_mask|=rejected;
    }
    ReleaseSRWLockExclusive(&capture_lock);
}
static void trace_line1_entry(unsigned char flag,uintptr_t return_pc,uintptr_t frame,uintptr_t popup) noexcept {
    if (state.load(std::memory_order_acquire)!=enabled || GetCurrentThreadId()!=bound_thread) return;
    if (!TryAcquireSRWLockExclusive(&capture_lock)) {trace_observation_drops.fetch_add(1);return;}
    if (state.load(std::memory_order_acquire)==enabled && scope_depth && !suppressed_scopes) {
        auto& scope=scopes[scope_depth-1];auto& trace=scope.trace;
        gate_trace::increment(trace.line1_entries,trace);
        const bool known_pc=return_pc==base+0x8c9f82 || return_pc==base+0x8cb9d3;
        uint32_t rejected=known_pc?0u:gate_trace::wrong_return;
        if (flag) rejected|=gate_trace::line1_filter_rejected;
        if (!scope.has_record || scope.slot>=kSlots) rejected|=gate_trace::no_record;
        if (scope.ambiguous) rejected|=gate_trace::ambiguous_scope;
        if (!scope.message_seen || !scope.has_message_copy_guard) rejected|=gate_trace::line1_filter_rejected;
        if (known_pc) {
            const bool land=return_pc==base+0x8c9f82;
            uintptr_t parent=0,spilled=0;
            if (!entry::valid_code_address(frame,land?0xae8:0x50) || !entry::valid_code_address(popup,0x250))
                rejected|=gate_trace::invalid_frame;
            else if (!read_value(frame+(land?0xad8:0x48),parent) || parent!=base+(land?0x8c2059:0x8c2068))
                rejected|=gate_trace::invalid_caller;
            else if (land && (!read_value(frame+0xae0,spilled) || spilled!=popup)) rejected|=gate_trace::invalid_owner;
        }
        trace.line1_reject_mask|=rejected;
    }
    ReleaseSRWLockExclusive(&capture_lock);
}
static void trace_cleanup_entry(void* container,uintptr_t return_pc,uintptr_t frame) noexcept {
    if (!TryAcquireSRWLockExclusive(&capture_lock)) {trace_observation_drops.fetch_add(1);return;}
    if (state.load(std::memory_order_acquire)==enabled && scope_depth && !suppressed_scopes) {
        auto& scope=scopes[scope_depth-1];auto& trace=scope.trace;
        gate_trace::increment(trace.cleanup_entries,trace);
        const bool land=return_pc==base+0x236736;
        auto rejected=trace_formatter_binding(scope,frame,land);
        if (frame<(land?0x60u:0x68u)
            || reinterpret_cast<uintptr_t>(container)!=frame-(land?0x60u:0x68u)) rejected|=gate_trace::invalid_frame;
        trace.cleanup_reject_mask|=rejected;
        if (!rejected) sample_gate_inputs(scope,gate_trace::Stage::formatter_cleanup);
    }
    ReleaseSRWLockExclusive(&capture_lock);
}
static bool gate_marker_code_guard() noexcept {
    const auto& spec=gate_marker_plan::spec();Reader reader;
    unsigned char prefix[17]{},metadata[16]{},land[11]{},naval[11]{};
    if (!reader.read(base+spec.entry_rva,prefix,sizeof(prefix))
        || !reader.read(base+spec.unwind_rva,metadata,sizeof(metadata))
        || memcmp(metadata,spec.unwind_expected.data(),sizeof(metadata))
        || memcmp(prefix,patched?gate_marker_entry.plan.patch.data():spec.prefix.data(),sizeof(prefix))
        || !reader.read(base+gate_marker_plan::kLandGateRva,land,sizeof(land))
        || !reader.read(base+gate_marker_plan::kNavalGateRva,naval,sizeof(naval))
        || memcmp(land,gate_marker_plan::kLandGateBytes.data(),sizeof(land))
        || memcmp(naval,gate_marker_plan::kNavalGateBytes.data(),sizeof(naval))) return false;
    if (gate_marker_entry.source_row) {
        RUNTIME_FUNCTION row{};
        if (!read_value(gate_marker_entry.source_row,row) || row.BeginAddress!=spec.entry_rva
            || row.EndAddress!=spec.end_rva || row.UnwindData!=spec.unwind_rva) return false;
    }
    return true;
}
static bool prepare_gate_marker_entry() noexcept {
    const auto& spec=gate_marker_plan::spec();Reader reader;
    unsigned char prefix[17]{},metadata[16]{};
    if (gate_marker_entry.trampoline || patch.count>=bridge_entry_patch::kMaxTargets
        || !reader.read(base+spec.entry_rva,prefix,sizeof(prefix))
        || !reader.read(base+spec.unwind_rva,metadata,sizeof(metadata))
        || gate_marker_plan::prepare(prefix,sizeof(prefix),metadata,sizeof(metadata),base+spec.entry_rva,
            reinterpret_cast<uintptr_t>(&information_battle_gate_marker_hook),gate_marker_entry.plan)
            !=gate_marker_plan::Status::prepared) return false;
    auto& owned=gate_marker_entry;
    owned.trampoline=static_cast<unsigned char*>(VirtualAlloc(nullptr,gate_marker_plan::kMaxImageBytes,
        MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE));
    if (!owned.trampoline) return false;
    memcpy(owned.trampoline,owned.plan.image.data(),owned.plan.image_bytes);
    DWORD old=0;
    if (!VirtualProtect(owned.trampoline,gate_marker_plan::kMaxImageBytes,PAGE_EXECUTE_READ,&old)
        || !FlushInstructionCache(GetCurrentProcess(),owned.trampoline,owned.plan.image_bytes)) return false;
    owned.unwind={owned.plan.runtime.begin,owned.plan.runtime.end,owned.plan.runtime.unwind};
    owned.table_registered=RtlAddFunctionTable(&owned.unwind,1,reinterpret_cast<DWORD64>(owned.trampoline))!=FALSE;
    DWORD64 image_base=0;
    if (!owned.table_registered || RtlLookupFunctionEntry(reinterpret_cast<DWORD64>(owned.trampoline+1),
        &image_base,nullptr)!=&owned.unwind || image_base!=reinterpret_cast<DWORD64>(owned.trampoline)) return false;
    information_battle_gate_marker_original=owned.trampoline;
    patch.targets[patch.count++]={reinterpret_cast<void*>(base+spec.entry_rva),static_cast<unsigned>(owned.plan.patch_bytes),
        spec.prefix.data(),owned.plan.patch.data(),owned.trampoline,owned.plan.runtime.end};
    return true;
}
static bool write_gate_trace(Record& record) noexcept {
    gate_trace::Identity record_identity{};
    record_identity.pid=GetCurrentProcessId();record_identity.creation=creation;
    record_identity.installation=identity.installation;record_identity.generation=identity.generation;
    record_identity.sequence=values(record).sequence;record_identity.native_date=values(record).result.raw_date;
    if (contexts(record).context_present) {
        const auto kind=contexts(record).context.kind;
        if (kind==battle::owned_context::Kind::land) record_identity.kind=gate_inputs::Kind::land;
        else if (kind==battle::owned_context::Kind::naval) record_identity.kind=gate_inputs::Kind::naval;
    }
    memcpy(record_identity.dll_sha256.data(),dll_sha,65);
    char buffer[gate_trace::kMaxJsonBytes]{};size_t bytes=0;
    if (!gate_trace::encode_jsonl(record_identity,record.trace,buffer,sizeof(buffer),bytes)) {
        trace_write_error=ERROR_INVALID_DATA;trace_write_failures.fetch_add(1);return false;
    }
    // Never replace or repair diagnostic evidence. First append must create a
    // new file; each later append verifies the same file and exact byte count.
    // No file I/O occurs in the native formatter/entry callbacks.
    const HANDLE handle=CreateFileW(trace_log_path,GENERIC_READ|GENERIC_WRITE,FILE_SHARE_READ,nullptr,
        trace_file_created?OPEN_EXISTING:CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr);
    if (handle==INVALID_HANDLE_VALUE) {trace_write_error=GetLastError();trace_write_failures.fetch_add(1);return false;}
    BY_HANDLE_FILE_INFORMATION info{};LARGE_INTEGER size{};DWORD error=ERROR_SUCCESS;
    const bool metadata=GetFileInformationByHandle(handle,&info) && GetFileSizeEx(handle,&size);
    if (!metadata) error=GetLastError();
    else if (size.QuadPart<0 || static_cast<uint64_t>(size.QuadPart)!=trace_file_bytes
        || trace_file_bytes>16u*1024u*1024u-bytes) error=ERROR_INVALID_DATA;
    else if (trace_file_created && (info.dwVolumeSerialNumber!=trace_volume
        || info.nFileIndexHigh!=trace_file_index_high || info.nFileIndexLow!=trace_file_index_low)) error=ERROR_INVALID_DATA;
    if (!trace_file_created) {
        trace_file_created=true;trace_volume=info.dwVolumeSerialNumber;
        trace_file_index_high=info.nFileIndexHigh;trace_file_index_low=info.nFileIndexLow;
    }
    if (!error && !SetFilePointerEx(handle,size,nullptr,FILE_BEGIN)) error=GetLastError();
    DWORD actual=0;
    if (!error && (!WriteFile(handle,buffer,static_cast<DWORD>(bytes),&actual,nullptr) || actual!=bytes)) {
        error=GetLastError();if (!error) error=ERROR_WRITE_FAULT;
    }
    if (!error && !FlushFileBuffers(handle)) error=GetLastError();
    if (!CloseHandle(handle) && !error) error=GetLastError();
    if (error) {trace_write_error=error;trace_write_failures.fetch_add(1);return false;}
    trace_file_bytes+=bytes;trace_records_written.fetch_add(1);return true;
}
#endif
#ifdef INFORMATION_BATTLE_NATIVE_TEXT
static bool read_message_copy_guard(Reader& reader,uintptr_t message,
    std::array<unsigned char,72>& output) noexcept {
    output.fill(0);
    // 598DC0 copies these exact bytes. Linked-list pointers, SSO pointers,
    // zeroed bookkeeping and untouched padding are deliberately excluded.
    return entry::valid_code_address(message,0x90)
        && reader.read(message+8,output.data(),8)
        && reader.read(message+0x28,output.data()+8,56)
        && reader.read(message+0x80,output.data()+64,8);
}
#endif
#ifdef INFORMATION_BATTLE_TEMPLATE
static bool message_code_guard() noexcept {
    Reader reader;
    for (unsigned i=0;i<kMessageEntryCount;++i) {
        const auto& spec=message_entry::spec(static_cast<message_entry::EntryKind>(i));
        const auto& owned=message_entries[i];
        unsigned char prefix[message_entry::kMaxPrefixBytes]{}, metadata[message_entry::kMaxUnwindBytes]{};
        if (!reader.read(base+spec.rva,prefix,spec.prefix_bytes)
            || !reader.read(base+spec.unwind_rva,metadata,spec.unwind_bytes)
            || memcmp(metadata,spec.unwind_expected.data(),spec.unwind_bytes)
            || memcmp(prefix,patched?owned.plan.patch.data():spec.prefix.data(),spec.prefix_bytes)) return false;
        if (owned.source_row) {
            RUNTIME_FUNCTION row{};
            if (!read_value(owned.source_row,row) || row.BeginAddress!=spec.rva
                || row.EndAddress!=spec.end_rva || row.UnwindData!=spec.unwind_rva) return false;
        }
    }
    return true;
}
static bool prepare_message_entries() noexcept {
    Reader reader;
    for (unsigned i=0;i<kMessageEntryCount;++i) {
        auto& owned=message_entries[i];
        if (owned.trampoline) return false;
        const auto kind=static_cast<message_entry::EntryKind>(i);
        const auto& spec=message_entry::spec(kind);
        unsigned char prefix[message_entry::kMaxPrefixBytes]{}, metadata[message_entry::kMaxUnwindBytes]{};
        auto hook=i==0?reinterpret_cast<uintptr_t>(&information_battle_router_hook)
            :reinterpret_cast<uintptr_t>(&information_battle_message_hook);
#ifdef INFORMATION_BATTLE_CONTAINER
        if (i==2) hook=reinterpret_cast<uintptr_t>(&information_battle_container_hook);
#endif
        if (!reader.read(base+spec.rva,prefix,spec.prefix_bytes)
            || !reader.read(base+spec.unwind_rva,metadata,spec.unwind_bytes)
            || message_entry::prepare(kind,prefix,spec.prefix_bytes,metadata,spec.unwind_bytes,
                base+spec.rva,hook,owned.plan)!=message_entry::Status::prepared) return false;
        owned.trampoline=static_cast<unsigned char*>(VirtualAlloc(nullptr,message_entry::kMaxImageBytes,
            MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE));
        if (!owned.trampoline) return false;
        memcpy(owned.trampoline,owned.plan.image.data(),owned.plan.image_bytes);
        DWORD old=0;
        if (!VirtualProtect(owned.trampoline,message_entry::kMaxImageBytes,PAGE_EXECUTE_READ,&old)
            || !FlushInstructionCache(GetCurrentProcess(),owned.trampoline,owned.plan.image_bytes)) return false;
        owned.unwind={owned.plan.runtime.begin,owned.plan.runtime.end,owned.plan.runtime.unwind};
        owned.table_registered=RtlAddFunctionTable(&owned.unwind,1,reinterpret_cast<DWORD64>(owned.trampoline))!=FALSE;
        DWORD64 image_base=0;
        if (!owned.table_registered || RtlLookupFunctionEntry(reinterpret_cast<DWORD64>(owned.trampoline+1),
            &image_base,nullptr)!=&owned.unwind || image_base!=reinterpret_cast<DWORD64>(owned.trampoline)) return false;
        if (i==0) information_battle_router_original=owned.trampoline;
        else if (i==1) information_battle_message_original=owned.trampoline;
#ifdef INFORMATION_BATTLE_CONTAINER
        else information_battle_container_original=owned.trampoline;
#endif
        patch.targets[i+1]={reinterpret_cast<void*>(base+spec.rva),static_cast<unsigned>(owned.plan.patch_bytes),
            spec.prefix.data(),owned.plan.patch.data(),owned.trampoline,owned.plan.runtime.end};
    }
    return true;
}
#endif
#ifdef INFORMATION_BATTLE_NATIVE_TEXT
static bool line1_code_guard() noexcept {
    const auto& spec = line1_entry_plan::spec();
    unsigned char code[line1_entry_plan::kMaxPatchBytes]{}, metadata[line1_entry_plan::kUnwindBytes]{};
    Reader reader;
    if (!entry::valid_code_address(base+spec.entry_rva,spec.prefix_bytes)
        || !entry::valid_code_address(base+spec.unwind_rva,spec.unwind_bytes)
        || !reader.read(base+spec.entry_rva,code,spec.prefix_bytes)
        || !reader.read(base+spec.unwind_rva,metadata,spec.unwind_bytes)
        || memcmp(metadata,spec.unwind_expected.data(),spec.unwind_bytes)
        || memcmp(code,line1_entry.patched?line1_entry.plan.patch.data():spec.prefix.data(),spec.prefix_bytes)) return false;
    if (line1_entry.source_row) {
        RUNTIME_FUNCTION current{};
        DWORD64 source_base=0;
        const auto source_row=RtlLookupFunctionEntry(base+spec.entry_rva+1,&source_base,nullptr);
        if (!read_value(line1_entry.source_row,current) || current.BeginAddress!=spec.entry_rva
            || current.EndAddress!=spec.function_end_rva || current.UnwindData!=spec.unwind_rva
            || reinterpret_cast<uintptr_t>(source_row)!=line1_entry.source_row || source_base!=base) return false;
    }
    if (line1_entry.patched || line1_entry.trampoline || line1_entry.table_registered || information_battle_line1_original) {
        DWORD64 image_base=0;
        if (!line1_entry.trampoline || !line1_entry.table_registered
            || information_battle_line1_original!=line1_entry.trampoline
            || RtlLookupFunctionEntry(reinterpret_cast<DWORD64>(line1_entry.trampoline+1),&image_base,nullptr)
                !=&line1_entry.unwind
            || image_base!=reinterpret_cast<DWORD64>(line1_entry.trampoline)) return false;
    }
    if (line1_entry.patched != patched) return false;
    return true;
}
static bool prepare_line1_entry() noexcept {
    Reader reader;
    auto& owned=line1_entry;
    if (owned.trampoline || information_battle_line1_original) return false;
    const auto& spec=line1_entry_plan::spec();
    unsigned char prefix[line1_entry_plan::kMaxPatchBytes]{}, metadata[line1_entry_plan::kUnwindBytes]{};
    if (!reader.read(base+spec.entry_rva,prefix,spec.prefix_bytes)
        || !reader.read(base+spec.unwind_rva,metadata,spec.unwind_bytes)
        || line1_entry_plan::prepare(prefix,spec.prefix_bytes,metadata,spec.unwind_bytes,
            base+spec.entry_rva,reinterpret_cast<uintptr_t>(&information_battle_line1_hook),owned.plan)
                !=line1_entry_plan::Status::prepared) return false;
    owned.trampoline=static_cast<unsigned char*>(VirtualAlloc(nullptr,line1_entry_plan::kMaxImageBytes,
        MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE));
    if (!owned.trampoline) return false;
    memcpy(owned.trampoline,owned.plan.image.data(),owned.plan.image_bytes);
    DWORD old=0;
    if (!VirtualProtect(owned.trampoline,line1_entry_plan::kMaxImageBytes,PAGE_EXECUTE_READ,&old)
        || !FlushInstructionCache(GetCurrentProcess(),owned.trampoline,owned.plan.image_bytes)) return false;
    owned.unwind={owned.plan.runtime.begin,owned.plan.runtime.end,owned.plan.runtime.unwind};
    owned.table_registered=RtlAddFunctionTable(&owned.unwind,1,reinterpret_cast<DWORD64>(owned.trampoline))!=FALSE;
    DWORD64 image_base=0;
    if (!owned.table_registered || RtlLookupFunctionEntry(reinterpret_cast<DWORD64>(owned.trampoline+1),
        &image_base,nullptr)!=&owned.unwind || image_base!=reinterpret_cast<DWORD64>(owned.trampoline)) return false;
    information_battle_line1_original=owned.trampoline;
#ifdef INFORMATION_BATTLE_TEMPLATE
    constexpr unsigned patch_index=1+kMessageEntryCount;
#else
    constexpr unsigned patch_index=1;
#endif
    patch.targets[patch_index]={reinterpret_cast<void*>(base+spec.entry_rva),
        static_cast<unsigned>(owned.plan.patch_bytes),spec.prefix.data(),owned.plan.patch.data(),
        owned.trampoline,owned.plan.runtime.end};
    return true;
}
#endif
#ifdef INFORMATION_BATTLE_NAME_HANDOFF
#include "information-battle-name-handoff-callsite-guards.inc"
static bool name_code_guard() noexcept {
    Reader reader;
    unsigned char actual[name_entry_plan::kFunctionBytes]{};
    if (game_image_size<name_entry_plan::kEndRva
        || !reader.read(base+name_entry_plan::kEntryRva,actual,sizeof(actual))
        || memcmp(actual,name_entry.patched?name_entry.plan.patch.data():name_entry_plan::kExpectedFunction.data(),
            name_entry_plan::kPrefixBytes)
        || memcmp(actual+name_entry_plan::kPrefixBytes,
            name_entry_plan::kExpectedFunction.data()+name_entry_plan::kPrefixBytes,
            sizeof(actual)-name_entry_plan::kPrefixBytes)
        || !name_callsite_guards(reader) || name_entry.patched!=patched) return false;
    // The fixed original is a leaf with no .pdata row. Check both ends;
    // full immutable EXE identity supplies the static metadata contract.
    DWORD64 source_base=0;
    if (RtlLookupFunctionEntry(base+name_entry_plan::kEntryRva,&source_base,nullptr)
        || RtlLookupFunctionEntry(base+name_entry_plan::kEndRva-1,&source_base,nullptr)) return false;
    if (name_entry.trampoline || name_entry.table_registered || information_battle_name_handoff_original) {
        unsigned char image[name_entry_plan::kImageCapacity]{};
        DWORD64 image_base=0;
        if (!name_entry.trampoline || !name_entry.table_registered
            || information_battle_name_handoff_original!=name_entry.trampoline
            || !reader.read(reinterpret_cast<uintptr_t>(name_entry.trampoline),image,name_entry.plan.image_bytes)
            || memcmp(image,name_entry.plan.image.data(),name_entry.plan.image_bytes)
            || RtlLookupFunctionEntry(reinterpret_cast<DWORD64>(name_entry.trampoline+1),&image_base,nullptr)
                !=&name_entry.unwind || image_base!=reinterpret_cast<DWORD64>(name_entry.trampoline)
            || name_entry.unwind.BeginAddress!=name_entry.plan.runtime.begin
            || name_entry.unwind.EndAddress!=name_entry.plan.runtime.end
            || name_entry.unwind.UnwindData!=name_entry.plan.runtime.unwind) return false;
    }
    return true;
}
static bool prepare_name_entry() noexcept {
    auto& owned=name_entry;
    if (owned.trampoline || information_battle_name_handoff_original
        || patch.count>=bridge_entry_patch::kMaxTargets || !name_code_guard()) return false;
    Reader reader; unsigned char body[name_entry_plan::kFunctionBytes]{};
    if (!reader.read(base+name_entry_plan::kEntryRva,body,sizeof(body))
        || name_entry_plan::prepare(body,sizeof(body),base,game_image_size,
            reinterpret_cast<uintptr_t>(&information_battle_name_handoff_hook),true,owned.plan)
                !=name_entry_plan::Status::prepared) return false;
    owned.trampoline=static_cast<unsigned char*>(VirtualAlloc(nullptr,name_entry_plan::kImageCapacity,
        MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE));
    if (!owned.trampoline) return false;
    memcpy(owned.trampoline,owned.plan.image.data(),owned.plan.image_bytes);
    DWORD old=0;
    if (!VirtualProtect(owned.trampoline,name_entry_plan::kImageCapacity,PAGE_EXECUTE_READ,&old)
        || !FlushInstructionCache(GetCurrentProcess(),owned.trampoline,owned.plan.image_bytes)) return false;
    owned.unwind={owned.plan.runtime.begin,owned.plan.runtime.end,owned.plan.runtime.unwind};
    owned.table_registered=RtlAddFunctionTable(&owned.unwind,1,reinterpret_cast<DWORD64>(owned.trampoline))!=FALSE;
    DWORD64 image_base=0;
    if (!owned.table_registered || RtlLookupFunctionEntry(reinterpret_cast<DWORD64>(owned.trampoline+1),
        &image_base,nullptr)!=&owned.unwind || image_base!=reinterpret_cast<DWORD64>(owned.trampoline)) return false;
    information_battle_name_handoff_original=owned.trampoline;
    patch.targets[patch.count++]={reinterpret_cast<void*>(base+name_entry_plan::kEntryRva),
        static_cast<unsigned>(owned.plan.patch_bytes),name_entry_plan::kExpectedFunction.data(),
        owned.plan.patch.data(),owned.trampoline,owned.plan.runtime.end};
    return true;
}
#endif
static bool hash_file(const wchar_t* path, char (&output)[65]) noexcept {
    HCRYPTPROV provider = 0; HCRYPTHASH hash = 0;
    HANDLE file = CreateFileW(path,GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;
    bool ok = CryptAcquireContextW(&provider,nullptr,nullptr,PROV_RSA_AES,CRYPT_VERIFYCONTEXT) != FALSE;
    ok = ok && CryptCreateHash(provider,CALG_SHA_256,0,0,&hash) != FALSE;
    unsigned char buffer[16384]; DWORD size = 0;
    while (ok) {
        if (!ReadFile(file,buffer,sizeof(buffer),&size,nullptr)) { ok=false; break; }
        if (!size) break;
        if (!CryptHashData(hash,buffer,size,0)) ok=false;
    }
    unsigned char digest[32]{}; DWORD bytes = sizeof(digest);
    ok = ok && CryptGetHashParam(hash,HP_HASHVAL,digest,&bytes,0) && bytes == sizeof(digest);
    if (hash && !CryptDestroyHash(hash)) ok=false;
    if (provider && !CryptReleaseContext(provider,0)) ok=false;
    if (!CloseHandle(file)) ok=false;
    if (!ok) return false;
    constexpr char hex[]="0123456789abcdef";
    for (unsigned i=0;i<32;++i) { output[2*i]=hex[digest[i]>>4]; output[2*i+1]=hex[digest[i]&15]; }
    output[64]=0; return true;
}
static bool file_identity() noexcept {
    wchar_t exe[MAX_PATH]{}, dll[MAX_PATH]{}; char exe_hash[65]{}, own_hash[65]{};
    DWORD a=GetModuleFileNameW(nullptr,exe,MAX_PATH), b=GetModuleFileNameW(self_module,dll,MAX_PATH);
    FILETIME c{},e{},k{},u{};
    IMAGE_DOS_HEADER dos{}; IMAGE_NT_HEADERS64 nt{};
    if (base!=reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr)) || !entry::valid_code_address(base,0x233fe60)) return false;
    DWORD64 source_base=0;
    auto source_row=RtlLookupFunctionEntry(base+kEntryRva+1,&source_base,nullptr);
    bool valid=a && a<MAX_PATH && b && b<MAX_PATH
        && base==reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr))
        && entry::valid_code_address(base,0x233fe60)
        && read_value(base,dos) && dos.e_magic==IMAGE_DOS_SIGNATURE && dos.e_lfanew>0 && dos.e_lfanew<0x100000
        && read_value(base+static_cast<unsigned>(dos.e_lfanew),nt)
        && nt.Signature==IMAGE_NT_SIGNATURE && nt.FileHeader.Machine==IMAGE_FILE_MACHINE_AMD64
        && nt.OptionalHeader.Magic==IMAGE_NT_OPTIONAL_HDR64_MAGIC
        && nt.OptionalHeader.SizeOfImage>=0x233fe60 && nt.OptionalHeader.SizeOfImage<=512u*1024u*1024u
        && entry::valid_code_address(base,nt.OptionalHeader.SizeOfImage)
        && source_row && source_base==base && source_row->BeginAddress==kEntryRva
        && source_row->EndAddress==0x23a015 && source_row->UnwindData==kUnwindRva
        && GetProcessTimes(GetCurrentProcess(),&c,&e,&k,&u)
        && (((uint64_t)c.dwHighDateTime<<32)|c.dwLowDateTime)==creation
        && hash_file(exe,exe_hash) && !strcmp(exe_hash,kExeSha)
        && hash_file(dll,own_hash) && !strcmp(own_hash,dll_sha);
#ifdef INFORMATION_BATTLE_TEMPLATE
    if (valid) {
        for (unsigned i=0;i<kMessageEntryCount;++i) {
            const auto& spec=message_entry::spec(static_cast<message_entry::EntryKind>(i));
            DWORD64 image_base=0;
            auto row=RtlLookupFunctionEntry(base+spec.rva+1,&image_base,nullptr);
            if (!row || image_base!=base || row->BeginAddress!=spec.rva
                || row->EndAddress!=spec.end_rva || row->UnwindData!=spec.unwind_rva) {valid=false;break;}
            message_entries[i].source_row=reinterpret_cast<uintptr_t>(row);
        }
    }
#endif
#ifdef INFORMATION_BATTLE_NATIVE_TEXT
    if (valid) {
        const auto& spec=line1_entry_plan::spec();
        DWORD64 image_base=0;
        auto row=RtlLookupFunctionEntry(base+spec.entry_rva+1,&image_base,nullptr);
        if (!row || image_base!=base || row->BeginAddress!=spec.entry_rva
            || row->EndAddress!=spec.function_end_rva || row->UnwindData!=spec.unwind_rva) valid=false;
        else line1_entry.source_row=reinterpret_cast<uintptr_t>(row);
    }
#endif
#ifdef INFORMATION_BATTLE_GATE_TRACE
    if (valid) {
        const auto& spec=gate_marker_plan::spec();DWORD64 image_base=0;
        const auto row=RtlLookupFunctionEntry(base+spec.entry_rva+1,&image_base,nullptr);
        if (!row || image_base!=base || row->BeginAddress!=spec.entry_rva
            || row->EndAddress!=spec.end_rva || row->UnwindData!=spec.unwind_rva) valid=false;
        else gate_marker_entry.source_row=reinterpret_cast<uintptr_t>(row);
    }
#endif
    if (valid) {
        source_row_address=reinterpret_cast<uintptr_t>(source_row);
#ifdef INFORMATION_BATTLE_CONTEXT
        game_image_size=nt.OptionalHeader.SizeOfImage;
#endif
    }
    return valid;
}
#ifdef INFORMATION_BATTLE_NATIVE_TITLE_QUERY
static bool title_query_plugin_identity() noexcept {
    Reader reader;
    // Preserve the original-image path without creating a plugin dependency.
    if (title_plan::guard(reader,base,game_image_size)) return true;
    const HMODULE module=GetModuleHandleW(L"plugin64.dll");
    if (!module) return false;
    const uintptr_t candidate=reinterpret_cast<uintptr_t>(module);
    IMAGE_DOS_HEADER dos{};IMAGE_NT_HEADERS64 nt{};
    if (!entry::valid_code_address(candidate,0x89000u)
        || !read_value(candidate,dos) || dos.e_magic!=IMAGE_DOS_SIGNATURE
        || dos.e_lfanew<=0 || dos.e_lfanew>=0x1000
        || !read_value(candidate+static_cast<unsigned>(dos.e_lfanew),nt)
        || nt.Signature!=IMAGE_NT_SIGNATURE || nt.FileHeader.Machine!=IMAGE_FILE_MACHINE_AMD64
        || nt.OptionalHeader.Magic!=IMAGE_NT_OPTIONAL_HDR64_MAGIC
        || nt.OptionalHeader.SizeOfImage!=0x89000u) return false;
    wchar_t path[MAX_PATH]{};char digest[65]{};
    const DWORD length=GetModuleFileNameW(module,path,MAX_PATH);
    if (!length || length>=MAX_PATH) return false;
    title_plugin_lease=CreateFileW(path,GENERIC_READ,FILE_SHARE_READ,nullptr,
        OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr);
    if (title_plugin_lease==INVALID_HANDLE_VALUE || !hash_file(path,digest)
        || strcmp(digest,title_plan::kPluginSha256)
        || !title_plan::guard(reader,base,game_image_size,candidate,0x89000u)) return false;
    // The bridge and its indirect callee must remain mapped to process exit.
    HMODULE pinned=nullptr;
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS|GET_MODULE_HANDLE_EX_FLAG_PIN,
        reinterpret_cast<LPCWSTR>(candidate),&pinned) || pinned!=module) return false;
    title_plugin_base=candidate;title_plugin_image_size=0x89000u;
    return true;
}
static bool title_query_code_guard() noexcept {
    Reader reader;
    if (!title_plan::guard(reader,base,game_image_size,title_plugin_base,title_plugin_image_size)) return false;
    const uintptr_t starts[]={title_plan::kHelperRva,title_plan::kDestructorRva};
    const uint32_t ends[]={title_plan::kHelperEndRva,title_plan::kDestructorEndRva};
    const uint32_t unwind_rvas[]={title_plan::kHelperUnwindRva,title_plan::kDestructorUnwindRva};
    for (unsigned i=0;i<2;++i) {
        DWORD64 image_base=0;
        const auto row=RtlLookupFunctionEntry(base+starts[i]+1,&image_base,nullptr);
        RUNTIME_FUNCTION actual{};
        if (!row || image_base!=base || !read_value(reinterpret_cast<uintptr_t>(row),actual)
            || actual.BeginAddress!=starts[i] || actual.EndAddress!=ends[i]
            || actual.UnwindData!=unwind_rvas[i]) return false;
    }
    if (title_plugin_base) {
        DWORD64 image_base=0;
        const auto row=RtlLookupFunctionEntry(title_plugin_base+0x373a1u,&image_base,nullptr);
        RUNTIME_FUNCTION actual{};
        if (!row || image_base!=title_plugin_base || !read_value(reinterpret_cast<uintptr_t>(row),actual)
            || actual.BeginAddress!=0x373a0u || actual.EndAddress!=0x375cbu
            || actual.UnwindData!=0x7bbb0u) return false;
    }
    return true;
}
#endif
#ifdef INFORMATION_BATTLE_DISPLAY_CONTEXT
// Fixed profile pins: definition f6457372..., localization 8052f513....
// Shared code-source guards only; this routine never invokes either lookup.
static bool display_context_code_guard() noexcept {
    Reader reader; unsigned char actual[834]{};
    static constexpr unsigned char expected_manager_getter_unpatched_return[]={
        0x48,0x8b,0x5c,0x24,0x38,0x48,0x83,0xc4,0x20,0x5f,0xc3
    };
    if (0x8bf044u>game_image_size || sizeof(expected_manager_getter_unpatched_return)>game_image_size-0x8bf044u
        || !reader.read(base+0x8bf044u,actual,sizeof(expected_manager_getter_unpatched_return))
        || memcmp(actual,expected_manager_getter_unpatched_return,sizeof(expected_manager_getter_unpatched_return))) return false;
    static constexpr unsigned char expected_definition_lookup[]={
        0x48,0x89,0x5c,0x24,0x18,0x48,0x89,0x74,0x24,0x20,0x55,0x57,0x41,0x54,0x41,0x56,0x41,0x57,0x48,0x8d,0x6c,0x24,0xc0,0x48,
        0x81,0xec,0x40,0x01,0x00,0x00,0x48,0x8b,0xfa,0x4c,0x8b,0xd1,0x45,0x33,0xe4,0x44,0x89,0x65,0x70,0x4c,0x8b,0x72,0x18,0x49,
        0x83,0xfe,0x10,0x72,0x03,0x48,0x8b,0x12,0x45,0x8b,0xc4,0x49,0x8b,0xcc,0x4c,0x63,0x4f,0x10,0x4d,0x85,0xc9,0x7e,0x1c,0x66,
        0x0f,0x1f,0x84,0x00,0x00,0x00,0x00,0x00,0x0f,0xbe,0x04,0x11,0x41,0x03,0xc0,0x44,0x6b,0xc0,0x3d,0x48,0xff,0xc1,0x49,0x3b,
        0xc9,0x7c,0xed,0x33,0xd2,0x41,0x8b,0xc0,0x41,0xf7,0x72,0x04,0x49,0x8b,0x42,0x08,0x48,0x8b,0x1c,0xd0,0x48,0x85,0xdb,0x74,
        0x43,0x4c,0x8b,0x7f,0x10,0x0f,0x1f,0x00,0x48,0x8b,0x33,0x48,0x8d,0x4e,0x38,0x48,0x8b,0xd7,0x49,0x83,0xfe,0x10,0x72,0x03,
        0x48,0x8b,0x17,0x4c,0x8b,0x41,0x10,0x48,0x83,0x79,0x18,0x10,0x72,0x03,0x48,0x8b,0x09,0x4d,0x3b,0xc7,0x75,0x0d,0xe8,0x65,
        0x52,0x17,0x01,0x85,0xc0,0x0f,0x84,0x74,0x02,0x00,0x00,0x48,0x8b,0x5b,0x08,0x48,0x85,0xdb,0x75,0xc4,0xe8,0x0f,0x19,0xe5,
        0x00,0x48,0x8b,0xd8,0x48,0x8d,0x05,0x3d,0xf9,0x4f,0x01,0x48,0x89,0x44,0x24,0x40,0x4c,0x89,0x65,0xe8,0x0f,0x57,0xc0,0xf3,
        0x0f,0x7f,0x45,0x10,0x4c,0x89,0x65,0x20,0xc7,0x45,0x70,0x04,0x00,0x00,0x00,0x48,0x8d,0x05,0xe2,0xef,0x35,0x01,0x48,0x89,
        0x45,0xe0,0xc7,0x45,0xdc,0x90,0x00,0x00,0x00,0x45,0x33,0xc0,0x48,0x8d,0x54,0x24,0x48,0x48,0x8d,0x4d,0xe0,0xe8,0x76,0x11,
        0x8e,0xff,0x90,0x48,0x8b,0x44,0x24,0x40,0x48,0x63,0x48,0x04,0x48,0x8d,0x05,0xcd,0xb5,0x3f,0x01,0x48,0x89,0x44,0x0c,0x40,
        0x48,0x8b,0x44,0x24,0x40,0x48,0x63,0x48,0x04,0x8d,0x91,0x78,0xff,0xff,0xff,0x89,0x54,0x0c,0x3c,0x48,0x8d,0x4c,0x24,0x48,
        0xe8,0xb3,0x10,0x8e,0xff,0x48,0x8d,0x05,0x44,0x18,0x38,0x01,0x48,0x89,0x44,0x24,0x48,0x4c,0x89,0x65,0xb0,0xc7,0x45,0xb8,
        0x04,0x00,0x00,0x00,0x48,0x8b,0x44,0x24,0x40,0x48,0x63,0x48,0x04,0x48,0x8d,0x05,0xac,0xf8,0x4f,0x01,0x48,0x89,0x44,0x0c,
        0x40,0x48,0x8b,0x44,0x24,0x40,0x48,0x63,0x48,0x04,0x8d,0x91,0x60,0xff,0xff,0xff,0x89,0x54,0x0c,0x3c,0x48,0x89,0x5d,0xc0,
        0x48,0x8d,0x05,0xb9,0x04,0x40,0x01,0x48,0x89,0x45,0xc8,0xc7,0x45,0xd0,0xeb,0x00,0x00,0x00,0xc7,0x45,0xd4,0x03,0x00,0x01,
        0x00,0x48,0x8d,0x05,0x68,0xb4,0xb6,0x01,0x48,0x89,0x44,0x24,0x20,0x32,0xdb,0x88,0x5c,0x24,0x28,0x38,0x1d,0xc0,0x76,0xa9,
        0x01,0x74,0x1a,0x48,0x8b,0x0d,0x4e,0xb4,0xb6,0x01,0xe8,0x9d,0x34,0x15,0x01,0x85,0xc0,0x0f,0x85,0x74,0x01,0x00,0x00,0xb3,
        0x01,0x88,0x5c,0x24,0x28,0x41,0xb8,0x1d,0x00,0x00,0x00,0x48,0x8d,0x15,0x3e,0x05,0x40,0x01,0x48,0x8d,0x4c,0x24,0x40,0xe8,
        0xac,0xf3,0xe3,0x00,0x90,0x84,0xdb,0x74,0x0c,0x48,0x8b,0x0d,0x18,0xb4,0xb6,0x01,0xe8,0x8b,0x34,0x15,0x01,0x48,0x83,0x7f,
        0x18,0x10,0x72,0x03,0x48,0x8b,0x3f,0x48,0x8b,0xd7,0x48,0x8d,0x4c,0x24,0x40,0xe8,0xd4,0xf5,0x7c,0xff,0x48,0x8b,0xd8,0x48,
        0x8b,0x08,0x48,0x63,0x49,0x04,0x48,0x03,0xc8,0xb2,0x0a,0xe8,0xe0,0xf3,0x7c,0xff,0x0f,0xb6,0xd0,0x48,0x8b,0xcb,0xe8,0x35,
        0xf2,0x7c,0xff,0x48,0x8b,0xcb,0xe8,0x6d,0xf8,0x7c,0xff,0x90,0x48,0x8d,0x4d,0xe0,0xe8,0x13,0x0e,0xe5,0x00,0x90,0x48,0x8d,
        0x05,0x6b,0xed,0x35,0x01,0x48,0x89,0x45,0xe0,0x48,0x8d,0x4d,0xe0,0xe8,0xfe,0xc6,0x14,0x01,0x90,0x48,0x8b,0x1d,0xd6,0xf9,
        0xa7,0x01,0x48,0x85,0xdb,0x0f,0x85,0xa5,0x00,0x00,0x00,0xb9,0xb0,0x00,0x00,0x00,0xe8,0x23,0x2d,0x17,0x01,0x48,0x8b,0xd8,
        0x48,0x89,0x45,0x78,0x48,0xc7,0x44,0x24,0x38,0x0f,0x00,0x00,0x00,0x48,0xc7,0x44,0x24,0x30,0x0c,0x00,0x00,0x00,0xf2,0x0f,
        0x10,0x05,0x7a,0x18,0x40,0x01,0xf2,0x0f,0x11,0x44,0x24,0x20,0x8b,0x05,0x76,0x18,0x40,0x01,0x89,0x44,0x24,0x28,0xc6,0x44,
        0x24,0x2c,0x00,0xc7,0x45,0x70,0x27,0x00,0x00,0x00,0x48,0x8d,0x54,0x24,0x20,0x48,0x8b,0xcb,0xe8,0xc9,0x28,0x01,0x00,0x48,
        0x8d,0x05,0xd2,0x18,0x40,0x01,0x48,0x89,0x03,0x48,0x89,0x1d,0x68,0xf9,0xa7,0x01,0x48,0x8b,0x54,0x24,0x38,0x48,0x83,0xfa,
        0x10,0x72,0x35,0x48,0xff,0xc2,0x48,0x8b,0x4c,0x24,0x20,0x48,0x8b,0xc1,0x48,0x81,0xfa,0x00,0x10,0x00,0x00,0x72,0x15,0x48,
        0x83,0xc2,0x27,0x48,0x8b,0x49,0xf8,0x48,0x2b,0xc1,0x48,0x83,0xc0,0xf8,0x48,0x83,0xf8,0x1f,0x77,0x39,0xe8,0x7f,0x8e,0xe7,
        0x00,0x48,0x8b,0x1d,0x28,0xf9,0xa7,0x01,0x48,0x8b,0xc3,0x4c,0x8d,0x9c,0x24,0x40,0x01,0x00,0x00,0x49,0x8b,0x5b,0x40,0x49,
        0x8b,0x73,0x48,0x49,0x8b,0xe3,0x41,0x5f,0x41,0x5e,0x41,0x5c,0x5f,0x5d,0xc3,0x48,0x85,0xf6,0x0f,0x84,0x8c,0xfd,0xff,0xff,
        0x48,0x8b,0xc6,0xeb,0xd6,0xe8,0xf2,0x15,0x18,0x01,0x90,0x8b,0xc8,0xe8,0xc6,0x2f,0x15,0x01
    };
    if (0x8c02a0u>game_image_size || sizeof(expected_definition_lookup)>game_image_size-0x8c02a0u
        || !reader.read(base+0x8c02a0u,actual,sizeof(expected_definition_lookup))
        || memcmp(actual,expected_definition_lookup,sizeof(expected_definition_lookup))) return false;
    static constexpr unsigned char expected_land_layout_consumer[]={
        0x83,0x78,0x5c,0x00,0x0f,0x84,0x87,0x00,0x00,0x00
    };
    if (0x8c9470u>game_image_size || sizeof(expected_land_layout_consumer)>game_image_size-0x8c9470u
        || !reader.read(base+0x8c9470u,actual,sizeof(expected_land_layout_consumer))
        || memcmp(actual,expected_land_layout_consumer,sizeof(expected_land_layout_consumer))) return false;
    static constexpr unsigned char expected_land_button_consumer[]={
        0x49,0x8b,0x07,0x80,0x78,0x60,0x00,0x0f,0x84,0x25,0x01,0x00,0x00
    };
    if (0x8c9fa2u>game_image_size || sizeof(expected_land_button_consumer)>game_image_size-0x8c9fa2u
        || !reader.read(base+0x8c9fa2u,actual,sizeof(expected_land_button_consumer))
        || memcmp(actual,expected_land_button_consumer,sizeof(expected_land_button_consumer))) return false;
    static constexpr unsigned char expected_key_hash_lookup_body[]={
        0x44,0x89,0x4c,0x24,0x20,0x4c,0x89,0x44,0x24,0x18,0x55,0x56,0x57,0x41,0x54,0x41,0x55,0x41,0x56,0x41,0x57,0x48,0x83,0xec,
        0x30,0x48,0x8d,0x6c,0x24,0x30,0x48,0x8b,0x05,0x3b,0x47,0xea,0x00,0x48,0x8b,0xf1,0x48,0x89,0x5d,0x40,0x48,0x8b,0xfa,0x4c,
        0x8b,0xda,0x41,0xba,0xc5,0x9d,0x1c,0x81,0x48,0x8b,0x08,0x0f,0xb6,0x02,0x84,0xc0,0x74,0x19,0x45,0x69,0xd2,0x93,0x01,0x00,
        0x01,0x4d,0x8d,0x5b,0x01,0x0f,0xbe,0xc0,0x44,0x33,0xd0,0x41,0x0f,0xb6,0x03,0x84,0xc0,0x75,0xe7,0x41,0x8b,0xd2,0xe8,0x5d,
        0x7b,0x24,0x00,0x48,0x8b,0xd8,0x48,0x85,0xc0,0x0f,0x84,0x63,0x01,0x00,0x00,0xb8,0x10,0x00,0x01,0x00,0xe8,0x37,0x03,0x58,
        0x00,0x48,0x2b,0xe0,0xba,0x24,0x00,0x00,0x00,0x48,0x8b,0xcb,0x4c,0x8d,0x7c,0x24,0x30,0x41,0xc7,0x07,0x7e,0xca,0x10,0xa1,
        0x49,0x83,0xc7,0x04,0x41,0xc7,0x87,0x00,0x00,0x01,0x00,0x7e,0xca,0x10,0xa1,0xe8,0xa8,0x1d,0x58,0x00,0x4c,0x8b,0xe8,0x4d,
        0x8b,0xf7,0x48,0x85,0xc0,0x0f,0x84,0x93,0x00,0x00,0x00,0x0f,0x1f,0x40,0x00,0x66,0x0f,0x1f,0x84,0x00,0x00,0x00,0x00,0x00,
        0x49,0x8d,0x4d,0x01,0xba,0x24,0x00,0x00,0x00,0xe8,0x7e,0x1d,0x58,0x00,0x4c,0x8b,0xe0,0x48,0x85,0xc0,0x0f,0x84,0xe4,0x00,
        0x00,0x00,0x41,0x8b,0xcd,0x48,0x8b,0xd3,0x2b,0xcb,0x48,0x63,0xf9,0x49,0x8b,0xce,0x4c,0x8b,0xc7,0xe8,0xe0,0x7e,0x59,0x00,
        0x8b,0x45,0x58,0x4a,0x8d,0x0c,0x37,0x89,0x44,0x24,0x28,0x49,0x8d,0x97,0x00,0x00,0x01,0x00,0x48,0x8b,0x45,0x50,0x4d,0x8b,
        0xcc,0x4d,0x8b,0xc5,0x48,0x89,0x44,0x24,0x20,0xe8,0x8a,0xf6,0xff,0xff,0x48,0x8b,0xc8,0x4c,0x8b,0xf0,0x49,0x2b,0xcf,0x48,
        0x81,0xf9,0x00,0xfc,0x00,0x00,0x7f,0x66,0x49,0x8d,0x5c,0x24,0x01,0xba,0x24,0x00,0x00,0x00,0x48,0x8b,0xcb,0xe8,0x12,0x1d,
        0x58,0x00,0x4c,0x8b,0xe8,0x48,0x85,0xc0,0x0f,0x85,0x7a,0xff,0xff,0xff,0x4c,0x2b,0xf3,0x0f,0x1f,0x80,0x00,0x00,0x00,0x00,
        0x0f,0xb6,0x03,0x41,0x88,0x04,0x1e,0x48,0x8d,0x5b,0x01,0x84,0xc0,0x75,0xf1,0x33,0xc0,0x48,0xc7,0x46,0x18,0x0f,0x00,0x00,
        0x00,0x48,0x89,0x06,0x49,0xc7,0xc0,0xff,0xff,0xff,0xff,0x88,0x06,0x48,0x89,0x46,0x10,0x0f,0x1f,0x80,0x00,0x00,0x00,0x00,
        0x49,0xff,0xc0,0x43,0x38,0x04,0x07,0x75,0xf7,0x49,0x8b,0xd7,0xeb,0x6e,0x33,0xc0,0x48,0xc7,0x46,0x18,0x0f,0x00,0x00,0x00,
        0x48,0x89,0x06,0x49,0xc7,0xc0,0xff,0xff,0xff,0xff,0x88,0x06,0x48,0x89,0x46,0x10,0x0f,0x1f,0x84,0x00,0x00,0x00,0x00,0x00,
        0x49,0xff,0xc0,0x43,0x38,0x04,0x07,0x75,0xf7,0x49,0x8b,0xd7,0xeb,0x3e,0x4c,0x2b,0xf3,0x0f,0xb6,0x03,0x41,0x88,0x04,0x1e,
        0x48,0x8d,0x5b,0x01,0x84,0xc0,0x75,0xf1,0xeb,0x8d,0x48,0x89,0x06,0x49,0xc7,0xc0,0xff,0xff,0xff,0xff,0x88,0x06,0x48,0x89,
        0x46,0x10,0x48,0xc7,0x46,0x18,0x0f,0x00,0x00,0x00,0x66,0x0f,0x1f,0x44,0x00,0x00,0x49,0xff,0xc0,0x42,0x38,0x04,0x07,0x75,
        0xf7,0x48,0x8b,0xd7,0x48,0x8b,0xce,0xe8,0x6c,0x1b,0xbe,0xfe,0x48,0x8b,0x5d,0x40,0x48,0x8b,0xc6,0x48,0x8b,0xe5,0x41,0x5f,
        0x41,0x5e,0x41,0x5d,0x41,0x5c,0x5f,0x5e,0x5d,0xc3
    };
    if (0x14b33a0u>game_image_size || sizeof(expected_key_hash_lookup_body)>game_image_size-0x14b33a0u
        || !reader.read(base+0x14b33a0u,actual,sizeof(expected_key_hash_lookup_body))
        || memcmp(actual,expected_key_hash_lookup_body,sizeof(expected_key_hash_lookup_body))) return false;
    static constexpr unsigned char expected_hash_lookup_helper[]={
        0x4c,0x8b,0x41,0x20,0x4c,0x8b,0xd2,0x48,0x8b,0x41,0x28,0x49,0x2b,0xc0,0x48,0xc1,0xf8,0x04,0x48,0x85,0xc0,0x75,0x01,0xc3,
        0x48,0x63,0xc8,0x4c,0x8b,0xd9,0x49,0xc1,0xe3,0x04,0x4d,0x03,0xd8,0x85,0xc0,0x7e,0x38,0x0f,0x1f,0x80,0x00,0x00,0x00,0x00,
        0x48,0x8b,0xd1,0x48,0xd1,0xea,0x48,0x8b,0xc2,0x48,0x03,0xc0,0x4d,0x39,0x14,0xc0,0x73,0x17,0x4d,0x8d,0x04,0xc0,0x48,0xc7,
        0xc0,0xff,0xff,0xff,0xff,0x48,0x2b,0xc2,0x49,0x83,0xc0,0x10,0x48,0x03,0xc8,0xeb,0x03,0x48,0x8b,0xca,0x48,0x85,0xc9,0x7f,
        0xcf,0x4d,0x3b,0xc3,0x74,0x18,0x4d,0x39,0x10,0x75,0x13,0x48,0x8b,0x05,0x2e,0xcb,0xc5,0x00,0x41,0x8b,0x48,0x08,0x48,0x03,
        0x48,0x20,0x48,0x8b,0xc1,0xc3,0x33,0xc9,0x8b,0xc1,0xc3
    };
    if (0x16faf60u>game_image_size || sizeof(expected_hash_lookup_helper)>game_image_size-0x16faf60u
        || !reader.read(base+0x16faf60u,actual,sizeof(expected_hash_lookup_helper))
        || memcmp(actual,expected_hash_lookup_helper,sizeof(expected_hash_lookup_helper))) return false;
    return true;
}
#endif
static bool code_guard() noexcept {
    unsigned char code[36]{}, metadata[32]{}; Reader reader;
    if (!entry::valid_code_address(base,0x233fe60) || !reader.read(base+kEntryRva,code,sizeof(code))
        || !reader.read(base+kUnwindRva,metadata,sizeof(metadata))
        || memcmp(metadata,entry::kOriginalUnwind.data(),sizeof(metadata))) return false;
    if (source_row_address) {
        RUNTIME_FUNCTION current{};
        if (!read_value(source_row_address,current) || current.BeginAddress!=kEntryRva
            || current.EndAddress!=0x23a015 || current.UnwindData!=kUnwindRva) return false;
    }
#ifdef INFORMATION_BATTLE_TEMPLATE
    if (!message_code_guard()) return false;
#endif
#ifdef INFORMATION_BATTLE_NATIVE_TEXT
    if (!line1_code_guard()) return false;
#endif
#ifdef INFORMATION_BATTLE_NATIVE_TITLE_QUERY
    if (!title_query_code_guard()) return false;
#endif
#ifdef INFORMATION_BATTLE_GATE_TRACE
    if (!gate_marker_code_guard()) return false;
#endif
#ifdef INFORMATION_BATTLE_DISPLAY_CONTEXT
    if (!display_context_code_guard()) return false;
#endif
#ifdef INFORMATION_BATTLE_NAME_HANDOFF
    if (!name_code_guard()) return false;
#endif
#ifdef INFORMATION_BATTLE_RETREAT
    if (!retreat_code_guard()) return false;
#endif
    return patched
        ? !memcmp(code,plan.patch.data(),entry::kPatchBytes)
            && !memcmp(code+entry::kPatchBytes,entry::kOriginalPrologue.data()+entry::kPatchBytes,sizeof(code)-entry::kPatchBytes)
        : !memcmp(code,entry::kOriginalPrologue.data(),sizeof(code));
}
static bool context(uintptr_t& actual_game, uint64_t& actual_player, int32_t& date) noexcept {
    return entry::valid_code_address(base,0x233fe60) && read_value(base+0x233fe58,actual_game) && actual_game>=0x10000
        && actual_game<0x800000000000ull-0x1e68
        && read_value(actual_game+0x1e60,actual_player)
        && read_value(actual_game+0x1dd0,date);
}
#ifdef INFORMATION_BATTLE_RETREAT
#include "information-battle-retreat-observer.inc"
#endif
#ifdef INFORMATION_BATTLE_NAME_HANDOFF
static void finalize_name_handoff(MessageScope& scope) noexcept {
    auto& record=slots[scope.slot];
    if (record.name_handoff.state!=name_handoff::SnapshotState::known) return;
    uintptr_t g=0;uint64_t p=0;int32_t date=0;
    if (scope.ambiguous || record.name_handoff_invalid || !scope.trace.scope_guards_after
        || scope.trace.observation_drops || !code_guard()
        || !context(g,p,date) || g!=game || p!=player || date!=record.name_handoff.raw_date
        || record.name_handoff.sequence!=scope.sequence || state.load()!=enabled) {
        record.name_handoff={};record.name_handoff_invalid=true;name_failed.fetch_add(1);
    }
}
static void capture_name_handoff(void* destination,void* key,void* value,uintptr_t return_pc,
    uintptr_t original_rbp,uintptr_t entry_rsp) noexcept {
    if (state.load(std::memory_order_acquire)!=enabled || GetCurrentThreadId()!=bound_thread
        || (return_pc!=base+name_handoff::kLandReturnRva && return_pc!=base+name_handoff::kNavalReturnRva)) return;
    name_candidates.fetch_add(1);
    if (!TryAcquireSRWLockExclusive(&capture_lock)) {
        busy.fetch_add(1);trace_observation_drops.fetch_add(1);return;
    }
    struct Release final {~Release(){ReleaseSRWLockExclusive(&capture_lock);}} release;
    if (!scope_depth || suppressed_scopes || state.load(std::memory_order_acquire)!=enabled) return;
    auto& scope=scopes[scope_depth-1];
    if (!scope.has_record || scope.slot>=kSlots || slot_ready[scope.slot]) return;
    auto& record=slots[scope.slot];
    const auto kind=return_pc==base+name_handoff::kLandReturnRva?1u:2u;
    const auto& observation=values(record);
    if (scope.ambiguous || !scope.combat || observation.sequence!=scope.sequence
        || !observation.known_router || !contexts(record).context_present
        || static_cast<unsigned>(contexts(record).context.kind)!=kind || record.name_handoff_invalid) {
        record.name_handoff={};record.name_handoff_invalid=true;name_failed.fetch_add(1);return;
    }
    uintptr_t g=0,after_game=0; uint64_t p=0,after_player=0; int32_t date=0,after_date=0;
    Reader reader; name_handoff::Result result{};
    name_scratch={};
    const bool before=code_guard() && context(g,p,date) && g==game && p==player
        && date==observation.result.raw_date;
    const name_handoff::Request request{base,game_image_size,entry_rsp,original_rbp,
        reinterpret_cast<uintptr_t>(destination),reinterpret_cast<uintptr_t>(key),
        reinterpret_cast<uintptr_t>(value),return_pc};
    const name_handoff::ScopeIdentity event{scope.sequence,date,scope.combat,kind,before};
    const bool copied=before && name_handoff::capture(reader,request,event,name_workspace,name_scratch,result)
        && result.observed && name_scratch.state==name_handoff::SnapshotState::known
        && context(after_game,after_player,after_date) && after_game==g && after_player==p && after_date==date
        && code_guard() && state.load(std::memory_order_acquire)==enabled;
    if (!copied) {
        record.name_handoff={};record.name_handoff_invalid=true;name_failed.fetch_add(1);
    } else if (record.name_handoff.state==name_handoff::SnapshotState::known) {
        const auto& old=record.name_handoff;
        if (old.sequence!=name_scratch.sequence || old.raw_date!=name_scratch.raw_date || old.kind!=name_scratch.kind
            || old.length!=name_scratch.length || memcmp(old.bytes.data(),name_scratch.bytes.data(),old.length)) {
            record.name_handoff={};record.name_handoff_invalid=true;name_conflicts.fetch_add(1);
        }
    } else {record.name_handoff=name_scratch;name_copied.fetch_add(1);}
    // Private source addresses never leave this synchronous callback.
    name_scratch={};name_workspace={};
}
#endif
#ifdef INFORMATION_BATTLE_DISPLAY_CONTEXT
static void capture_display_context(MessageScope& scope) noexcept {
    auto& record=slots[scope.slot];
    auto& output=record.display_context;
    display_context_candidates.fetch_add(1);
    display_context_model::clear(output);
    if (scope.ambiguous) {
        display_context_model::clear(output,display_context_model::Failure::ambiguous_scope);
    } else {
        uintptr_t g=0,after_game=0; uint64_t p=0,after_player=0; int32_t date=0,after_date=0;
        const auto kind=static_cast<unsigned>(contexts(record).context.kind);
        const bool before=values(record).known_router && contexts(record).context_present && (kind==1 || kind==2)
            && state.load(std::memory_order_acquire)==enabled && code_guard()
            && context(g,p,date) && g==game && p==player
            && date==values(record).result.raw_date && values(record).sequence==scope.sequence;
        if (before) {
            Reader reader;
            display_context_capture::Result result{};
            const display_context_model::Identity event_identity{
                scope.sequence,date,static_cast<uint8_t>(kind),display_context_model::kRouterScopeExit};
            const bool copied=display_context_capture::capture(reader,base,game_image_size,game,
                event_identity,display_context_workspace,output,result);
            const bool after=context(after_game,after_player,after_date) && after_game==g
                && after_player==p && after_date==date && code_guard()
                && state.load(std::memory_order_acquire)==enabled;
            if (!after) display_context_model::clear(output,display_context_model::Failure::guard);
            else if (!copied && output.failure==display_context_model::Failure::none)
                display_context_model::clear(output,display_context_model::Failure::read_failed);
        } else display_context_model::clear(output,display_context_model::Failure::guard);
    }
    if (!display_context_model::valid(output))
        display_context_model::clear(output,display_context_model::Failure::invalid_input);
    if (output.state==display_context_model::State::observed) display_context_copied.fetch_add(1);
    else display_context_failures.fetch_add(1);
    display_context_last_failure.store(static_cast<unsigned>(output.failure));
}
#endif
#ifdef INFORMATION_BATTLE_NAME_SOURCES
#ifdef INFORMATION_BATTLE_INDEPENDENT_LINE
struct IndependentLineInvoker final {
    bool guard(const display_context_model::Snapshot& expected) noexcept {
        uintptr_t actual_game=0;uint64_t actual_player=0;int32_t date=0;
        Reader reader;
        if (state.load(std::memory_order_acquire)!=enabled || GetCurrentThreadId()!=bound_thread
                || !code_guard() || !context(actual_game,actual_player,date) || actual_game!=game
                || actual_player!=player || date!=expected.identity.date
                || !battle::independent_line_plan::guard(reader,base,game_image_size)) return false;
        display_context_capture::Result result{};
        if (!display_context_capture::capture(reader,base,game_image_size,game,expected.identity,
                display_context_workspace,independent_line_context_check,result)) return false;
        const auto& actual=independent_line_context_check;
        if (actual.state!=expected.state || actual.failure!=expected.failure
                || actual.popup_kind_raw!=expected.popup_kind_raw || actual.layout_raw!=expected.layout_raw
                || actual.button_flag_raw!=expected.button_flag_raw || actual.arena_used!=expected.arena_used)
            return false;
        for (size_t index=0;index<actual.fields.size();++index) {
            const auto& a=actual.fields[index];const auto& b=expected.fields[index];
            if (a.state!=b.state || a.offset!=b.offset || a.length!=b.length) return false;
        }
        return !memcmp(actual.arena.data(),expected.arena.data(),actual.arena_used);
    }
    battle::owned_title_query::String32* invoke(battle::owned_title_query::String32* output,
            const char* key,const battle_format_input::NativeArg104* arguments,int32_t count) noexcept {
        using Format=battle::owned_title_query::String32* (*)(battle::owned_title_query::String32*,
            const char*,const battle_format_input::NativeArg104*,int32_t);
        return reinterpret_cast<Format>(base+battle::independent_line_plan::kFormatterRva)(output,key,arguments,count);
    }
    void destroy(battle::owned_title_query::String32* output) noexcept {
        using Destroy=void (*)(void*);
        reinterpret_cast<Destroy>(base+title_plan::kDestructorRva)(output);
    }
};
static void capture_independent_line(MessageScope& scope) noexcept {
    auto& record=slots[scope.slot];
    const auto& observation=values(record);
    const display_context_model::Identity identity{scope.sequence,observation.result.raw_date,
        static_cast<uint8_t>(contexts(record).context.kind),display_context_model::kRouterScopeExit};
    namespace owned=battle::owned_independent_line;
    owned::clear(record.independent_line,identity,owned::Failure::inputs);
    independent_line_candidates.fetch_add(1);
    if (!scope.ambiguous && record.display_context.state==display_context_model::State::observed
            && observation.sequence==scope.sequence) {
        Reader reader;IndependentLineInvoker invoker;
        if (owned::capture(reader,invoker,record.display_context,record.name_sources,
                independent_line_workspace,record.independent_line)) independent_line_copied.fetch_add(1);
        else independent_line_failed.fetch_add(1);
        if (record.independent_line.flags&1) independent_line_invoked.fetch_add(1);
    } else independent_line_failed.fetch_add(1);
}
#endif
struct NameSourceGuard final {
    MessageScope* owner;
    uintptr_t combat;
    uint64_t sequence;
    int32_t expected_date;
    bool guard() noexcept {
        uintptr_t g=0;uint64_t p=0;int32_t date=0;
        return state.load(std::memory_order_acquire)==enabled
            && GetCurrentThreadId()==bound_thread && scope_depth && !suppressed_scopes
            && owner==&scopes[scope_depth-1] && owner->combat==combat && !owner->ambiguous
            && (!owner->has_record || owner->sequence==sequence)
            && code_guard() && context(g,p,date) && g==game && p==player && date==expected_date;
    }
};
static void copy_name_field(battle::name_sources_wire::Text& target,
                            const battle::owned_name_sources::OwnedText& source) noexcept {
    target.state=battle::name_sources_wire::State::known;
    target.length=source.length;
    memcpy(target.bytes.data(),source.bytes.data(),source.length);
}
static void capture_name_sources(Record& record,MessageScope& scope,
                                  uintptr_t combat,uint64_t next,int32_t date) noexcept {
    auto& output=record.name_sources;
    output={};output.sequence=next;output.raw_date=date;
    output.kind=static_cast<uint8_t>(contexts(record).context.kind);
#ifdef INFORMATION_BATTLE_NATIVE_TITLE_QUERY
    output.transform_mode=title_plugin_base ? 2u : 1u;
#endif
    NameSourceGuard guard{&scope,combat,next,date};
    Reader reader;
    name_source_candidates.fetch_add(1);
    battle::owned_name_sources::Result raw_result{};
    if (battle::owned_name_sources::capture(reader,guard,base,game_image_size,combat,
            next,date,output.kind,name_sources_workspace,name_sources_scratch,raw_result)) {
        output.raw_failure=0;
        copy_name_field(output.fields[0],name_sources_scratch.owner_name);
        copy_name_field(output.fields[1],name_sources_scratch.global_name);
        name_source_copied.fetch_add(1);
    } else output.raw_failure=static_cast<uint8_t>(raw_result.failed_stage);
    name_sources_scratch={};
    battle::owned_name_prefix::Result prefix_result{};
    if (battle::owned_name_prefix::capture(reader,guard,base,game_image_size,game,
            next,date,output.kind,name_prefix_workspace,name_prefix_scratch,prefix_result)) {
        output.prefix_failure=0;
        copy_name_field(output.fields[3],name_prefix_scratch.language);
        if (name_prefix_scratch.template_state==display_context_model::State::observed)
            copy_name_field(output.fields[2],name_prefix_scratch.template_text);
        else output.fields[2].state=battle::name_sources_wire::State::absent;
        name_prefix_copied.fetch_add(1);
    } else output.prefix_failure=static_cast<uint16_t>(prefix_result.failure);
    name_prefix_scratch={};
}
static void finalize_name_sources(MessageScope& scope) noexcept {
    auto& record=slots[scope.slot];
    uintptr_t g=0;uint64_t p=0;int32_t date=0;
    if (scope.ambiguous || state.load(std::memory_order_acquire)!=enabled || !code_guard()
            || !context(g,p,date) || g!=game || p!=player
            || date!=values(record).result.raw_date || values(record).sequence!=scope.sequence) {
        record.name_sources={};
        record.name_sources.raw_failure=static_cast<uint8_t>(battle::owned_name_sources::FailureStage::guard_before);
        record.name_sources.prefix_failure=static_cast<uint16_t>(display_context_model::Failure::guard);
    }
}
#ifdef INFORMATION_BATTLE_OUTCOME_TEXT
static void capture_outcome_text(Record& record,MessageScope& scope,
                                 uintptr_t combat,uint64_t next,int32_t date) noexcept {
    auto& output=record.outcome_text;
    const auto kind=static_cast<uint8_t>(contexts(record).context.kind);
    battle::outcome_text_record::clear(output,next,date,kind);
    NameSourceGuard guard{&scope,combat,next,date};
    Reader reader;
    battle::owned_outcome_text::Result outcome_result{};
    outcome_text_candidates.fetch_add(1);
    const bool captured=battle::owned_outcome_text::capture(reader,guard,base,game_image_size,
        game,next,date,kind,outcome_text_workspace,outcome_text_scratch,outcome_result);
    if (!battle::outcome_text_record::assign(next,date,kind,captured,outcome_text_scratch,
                                            outcome_result,output))
        battle::outcome_text_record::clear(output,next,date,kind,display_context_model::Failure::invalid_input);
    outcome_text_scratch={};
    if (output.failure==0u) outcome_text_copied.fetch_add(1);
    else outcome_text_failed.fetch_add(1);
    outcome_text_last_failure.store(output.failure);
}
static void finalize_outcome_text(MessageScope& scope) noexcept {
    auto& record=slots[scope.slot];
    uintptr_t g=0;uint64_t p=0;int32_t date=0;
    if (scope.ambiguous || state.load(std::memory_order_acquire)!=enabled || !code_guard()
            || !context(g,p,date) || g!=game || p!=player
            || date!=values(record).result.raw_date || values(record).sequence!=scope.sequence) {
        const auto failure=scope.ambiguous ? display_context_model::Failure::ambiguous_scope
                                          : display_context_model::Failure::guard;
        battle::outcome_text_record::clear(record.outcome_text,values(record).sequence,
            values(record).result.raw_date,static_cast<uint8_t>(contexts(record).context.kind),failure);
        outcome_text_last_failure.store(static_cast<unsigned>(failure));
    }
}
#ifdef INFORMATION_BATTLE_OUTCOME_TAIL
static void capture_outcome_tail(Record& record,MessageScope& scope,
                                 uintptr_t combat,uint64_t next,int32_t date) noexcept {
    auto& output=record.outcome_tail;
    const auto kind=static_cast<uint8_t>(contexts(record).context.kind);
    battle::outcome_tail_record::clear(output,next,date,kind);
    NameSourceGuard guard{&scope,combat,next,date};
    Reader reader;
    battle::owned_outcome_tail::Result outcome_result{};
    outcome_tail_candidates.fetch_add(1);
    const bool captured=battle::owned_outcome_tail::capture(reader,guard,base,game_image_size,
        game,next,date,kind,outcome_tail_workspace,outcome_tail_scratch,outcome_result);
    if (!battle::outcome_tail_record::assign(next,date,kind,captured,outcome_tail_scratch,
                                            outcome_result,output))
        battle::outcome_tail_record::clear(output,next,date,kind,display_context_model::Failure::invalid_input);
    outcome_tail_scratch={};
    if (output.failure==0u) outcome_tail_copied.fetch_add(1);
    else outcome_tail_failed.fetch_add(1);
    outcome_tail_last_failure.store(output.failure);
}
static void finalize_outcome_tail(MessageScope& scope) noexcept {
    auto& record=slots[scope.slot];
    uintptr_t g=0;uint64_t p=0;int32_t date=0;
    if (scope.ambiguous || state.load(std::memory_order_acquire)!=enabled || !code_guard()
            || !context(g,p,date) || g!=game || p!=player
            || date!=values(record).result.raw_date || values(record).sequence!=scope.sequence) {
        const auto failure=scope.ambiguous ? display_context_model::Failure::ambiguous_scope
                                          : display_context_model::Failure::guard;
        battle::outcome_tail_record::clear(record.outcome_tail,values(record).sequence,
            values(record).result.raw_date,static_cast<uint8_t>(contexts(record).context.kind),failure);
        outcome_tail_last_failure.store(static_cast<unsigned>(failure));
    }
}
#endif
#endif
#endif
#ifdef INFORMATION_BATTLE_NATIVE_TITLE_QUERY
struct NativeTitleInvoker final {
    int32_t expected_date;
    bool guard() noexcept {
        uintptr_t actual_game=0;uint64_t actual_player=0;int32_t date=0;
        return state.load(std::memory_order_acquire)==enabled
            && GetCurrentThreadId()==bound_thread && code_guard()
            && context(actual_game,actual_player,date) && actual_game==game
            && actual_player==player && date==expected_date;
    }
    title_query::String32* invoke(uintptr_t combat,title_query::String32* output) noexcept {
        using Describe=title_query::String32* (*)(void*,title_query::String32*);
        return reinterpret_cast<Describe>(base+title_plan::kHelperRva)(
            reinterpret_cast<void*>(combat),output);
    }
    void destroy(title_query::String32* output) noexcept {
        using Destroy=void (*)(void*);
        reinterpret_cast<Destroy>(base+title_plan::kDestructorRva)(output);
    }
};
#endif
#ifdef INFORMATION_BATTLE_TEMPLATE
static void capture_message(void* message, void* callback, uintptr_t return_pc,
    uintptr_t formatter_frame) noexcept {
#ifdef INFORMATION_BATTLE_GATE_TRACE
    trace_message_entry(callback,return_pc,formatter_frame);
#endif
    if (state.load(std::memory_order_acquire)!=enabled || GetCurrentThreadId()!=bound_thread
        || (return_pc!=base+0x236721 && return_pc!=base+0x232a13)
        || reinterpret_cast<uintptr_t>(callback)!=base+0x2ec0a0) return;
    // Both native formatters push their caller's RDI at entryRSP-0x20.
    // Their fixed RBP anchors survive until the proven message CALL. The
    // router holds this combat in RDI and calls the formatter directly.
    // Validate both the formatter's caller PC and saved owner, rather than
    // treating a matching date/type or a decompiler local as its identity.
    const bool land=return_pc==base+0x236721;
    const uintptr_t return_offset=land?0x1d8:0x198;
    uintptr_t caller_pc=0, owner=0;
    if (!entry::valid_code_address(formatter_frame,0x1e0)
        || !read_value(formatter_frame+return_offset,caller_pc)
        || caller_pc!=base+(land?0x23a446:0x23a42a)
        || !read_value(formatter_frame+return_offset-0x20,owner)) return;
    if (!TryAcquireSRWLockExclusive(&capture_lock)) {
        busy.fetch_add(1);
#ifdef INFORMATION_BATTLE_GATE_TRACE
        trace_observation_drops.fetch_add(1);
#endif
        return;
    }
    if (state.load(std::memory_order_acquire)==enabled && scope_depth && !suppressed_scopes) {
        auto& scope=scopes[scope_depth-1];
        auto& record=slots[scope.slot];
        auto& context_record=contexts(record);
        const auto expected_kind=return_pc==base+0x236721
            ? battle::owned_context::Kind::land : battle::owned_context::Kind::naval;
        if (scope.has_record && scope.combat==owner && !scope.ambiguous && !slot_ready[scope.slot]
            && values(record).sequence==scope.sequence && context_record.context_present
            && context_record.context.kind==expected_kind) {
            if (scope.message_seen) {
                scope.ambiguous=true; template_values(record).template_present=false;
                template_values(record).template_source_kind=template_wire::kMessageSource; template_ambiguous.fetch_add(1);
#ifdef INFORMATION_BATTLE_NATIVE_TEXT
                native_text::clear(record.native_text); record.native_text_invalid=true;
#endif
            } else {
                scope.message_seen=true;
#ifdef INFORMATION_BATTLE_GATE_TRACE
                gate_trace::increment(scope.trace.message_copy_attempts,scope.trace);
#endif
                uintptr_t g=0;uint64_t p=0;int32_t date=0;
                Reader reader;
#ifdef INFORMATION_BATTLE_NATIVE_TEXT
                std::array<unsigned char,72> guard_before{},guard_after{};
                const bool guard_started=read_message_copy_guard(reader,reinterpret_cast<uintptr_t>(message),guard_before);
                scope.has_message_copy_guard=false;
#endif
                template_values(record).template_source_kind=template_wire::kMessageSource;
                template_values(record).template_present=code_guard() && context(g,p,date) && g==game && p==player
                    && date==values(record).result.raw_date
                    && battle::owned_template::capture(reader,reinterpret_cast<uintptr_t>(message),template_values(record).message)
                    && template_values(record).message.native_date==date && code_guard();
                if (template_values(record).template_present) template_copied.fetch_add(1);
                else template_copy_failed.fetch_add(1);
#ifdef INFORMATION_BATTLE_GATE_TRACE
                if (!template_values(record).template_present) scope.trace.message_reject_mask|=gate_trace::template_copy_failed;
#endif
#ifdef INFORMATION_BATTLE_NATIVE_TEXT
                uintptr_t after_game=0; uint64_t after_player=0; int32_t after_date=0;
                const bool metadata_ok=!record.native_text_invalid && code_guard()
                    && context(g,p,date) && g==game && p==player && date==values(record).result.raw_date
                    && native_text::capture_message(reader,reinterpret_cast<uintptr_t>(message),native_text_scratch)
                    && native_text_scratch.native_date_state==native_text::FieldState::observed
                    && native_text_scratch.native_date==date
                    && context(after_game,after_player,after_date)
                    && after_game==g && after_player==p && after_date==date && code_guard()
                    && state.load(std::memory_order_acquire)==enabled;
                if (metadata_ok && native_text::merge(record.native_text,native_text_scratch,record.native_text))
                {
                    native_metadata_copied.fetch_add(1);
                    scope.has_message_copy_guard=guard_started
                        && read_message_copy_guard(reader,reinterpret_cast<uintptr_t>(message),guard_after)
                        && guard_before==guard_after;
                    if (scope.has_message_copy_guard) scope.message_copy_guard=guard_after;
                }
                else {
                    native_text::clear(record.native_text); record.native_text_invalid=true;
                    native_metadata_failed.fetch_add(1);
#ifdef INFORMATION_BATTLE_GATE_TRACE
                    scope.trace.message_reject_mask|=gate_trace::metadata_copy_failed;
#endif
                }
                native_text::clear(native_text_scratch);
#endif
            }
        }
    }
    ReleaseSRWLockExclusive(&capture_lock);
}
#ifdef INFORMATION_BATTLE_CONTAINER
// The temporary container is destroyed even when the message gate is false.
// Unrelated callers of this shared cleanup helper return before object reads.
static void capture_container(void* container, uintptr_t return_pc,
    uintptr_t formatter_frame) noexcept {
    if (state.load(std::memory_order_acquire)!=enabled || GetCurrentThreadId()!=bound_thread
        || (return_pc!=base+0x236736 && return_pc!=base+0x232a28)) return;
#ifdef INFORMATION_BATTLE_GATE_TRACE
    trace_cleanup_entry(container,return_pc,formatter_frame);
#endif
    container_candidates.fetch_add(1);
    const bool land=return_pc==base+0x236736;
    const uintptr_t return_offset=land?0x1d8:0x198;
    const uintptr_t container_offset=land?0x60:0x68;
    uintptr_t caller_pc=0, owner=0;
    if (!entry::valid_code_address(formatter_frame,0x1e0)
        || reinterpret_cast<uintptr_t>(container)!=formatter_frame-container_offset
        || !read_value(formatter_frame+return_offset,caller_pc)
        || caller_pc!=base+(land?0x23a446:0x23a42a)
        || !read_value(formatter_frame+return_offset-0x20,owner)) return;
    if (!TryAcquireSRWLockExclusive(&capture_lock)) {
        busy.fetch_add(1);
#ifdef INFORMATION_BATTLE_GATE_TRACE
        trace_observation_drops.fetch_add(1);
#endif
        return;
    }
    if (state.load(std::memory_order_acquire)==enabled && scope_depth && !suppressed_scopes) {
        auto& scope=scopes[scope_depth-1];
        auto& record=slots[scope.slot];
        const auto expected_kind=land?battle::owned_context::Kind::land:battle::owned_context::Kind::naval;
#ifdef INFORMATION_BATTLE_FLAG_INPUTS
        if (land && scope.has_record && scope.combat==owner && !scope.ambiguous && !slot_ready[scope.slot]
                && values(record).sequence==scope.sequence && contexts(record).context_present
                && contexts(record).context.kind==expected_kind && scope.message_seen) {
            flag_input_candidates.fetch_add(1);
            if (scope.flag_container_seen) {
                battle::owned_flag_inputs::clear(record.flag_inputs,scope.sequence,values(record).result.raw_date,1,
                    battle::owned_flag_inputs::Failure::input_changed);
                flag_input_failed.fetch_add(1);
            } else {
                scope.flag_container_seen=true;
                battle::owned_flag_inputs::clear(record.flag_inputs,scope.sequence,values(record).result.raw_date,1,
                    battle::owned_flag_inputs::Failure::base_unknown);
                bool copied=false;
                if (template_values(record).template_present) {
                    Reader reader;
                    uintptr_t g=0,after_game=0; uint64_t p=0,after_player=0; int32_t date=0,after_date=0;
                    record.flag_inputs.failure=static_cast<uint8_t>(battle::owned_flag_inputs::Failure::copy_failed);
                    if (code_guard() && context(g,p,date) && g==game && p==player
                            && date==values(record).result.raw_date
                            && battle::owned_template::capture_container(reader,reinterpret_cast<uintptr_t>(container),
                                flag_message_template,&flag_input_log)
                            && battle::owned_flag_inputs::same_pairs(template_values(record).message,flag_message_template))
                        copied=battle::owned_flag_inputs::capture(reader,flag_input_log,flag_message_template,
                            scope.sequence,date,1,flag_input_workspace,record.flag_inputs);
                    if (!context(after_game,after_player,after_date) || after_game!=g || after_player!=p
                            || after_date!=date || !code_guard() || state.load(std::memory_order_acquire)!=enabled) {
                        battle::owned_flag_inputs::clear(record.flag_inputs,scope.sequence,values(record).result.raw_date,1,
                            battle::owned_flag_inputs::Failure::guard);
                        copied=false;
                    }
                }
                if (copied) flag_input_copied.fetch_add(1);
                else flag_input_failed.fetch_add(1);
                flag_input_log={}; flag_message_template={};
            }
        }
#endif
        if (scope.has_record && scope.combat==owner && !scope.ambiguous && !slot_ready[scope.slot]
            && values(record).sequence==scope.sequence && contexts(record).context_present
            && contexts(record).context.kind==expected_kind && !scope.message_seen) {
            if (scope.container_seen) {
                scope.ambiguous=true; template_values(record).template_present=false;
                template_values(record).template_source_kind=template_wire::kMessageSource; template_ambiguous.fetch_add(1);
#ifdef INFORMATION_BATTLE_NATIVE_TEXT
                native_text::clear(record.native_text); record.native_text_invalid=true;
#endif
            } else {
                scope.container_seen=true;
                uintptr_t g=0, after_game=0; uint64_t p=0, after_player=0; int32_t date=0, after_date=0;
                Reader reader;
                template_values(record).template_source_kind=template_wire::kFormatterContainerSource;
                template_values(record).template_present=code_guard() && context(g,p,date) && g==game && p==player
                    && date==values(record).result.raw_date
                    && battle::owned_template::capture_container(reader,reinterpret_cast<uintptr_t>(container),template_values(record).message
#ifdef INFORMATION_BATTLE_FLAG_INPUTS
                        , &flag_input_log
#endif
                        )
                    && context(after_game,after_player,after_date) && after_game==g && after_player==p && after_date==date
                    && code_guard() && state.load(std::memory_order_acquire)==enabled;
                if (template_values(record).template_present) {
                    container_copied.fetch_add(1);
#ifdef INFORMATION_BATTLE_FLAG_INPUTS
                    if (land) {
                        flag_input_candidates.fetch_add(1);
                        bool copied = battle::owned_flag_inputs::capture(reader,flag_input_log,
                            template_values(record).message,scope.sequence,date,static_cast<uint8_t>(expected_kind),
                            flag_input_workspace,record.flag_inputs);
                        if (!context(after_game,after_player,after_date) || after_game!=g || after_player!=p
                                || after_date!=date || !code_guard() || state.load(std::memory_order_acquire)!=enabled) {
                            battle::owned_flag_inputs::clear(record.flag_inputs,scope.sequence,date,
                                static_cast<uint8_t>(expected_kind),battle::owned_flag_inputs::Failure::guard);
                            copied = false;
                        }
                        if (copied) flag_input_copied.fetch_add(1);
                        else flag_input_failed.fetch_add(1);
                    }
#endif
                }
                else {
                    template_values(record).template_source_kind=template_wire::kMessageSource;
                    container_copy_failed.fetch_add(1);
                }
#ifdef INFORMATION_BATTLE_FLAG_INPUTS
                flag_input_log = {};
#endif
            }
        }
    }
    ReleaseSRWLockExclusive(&capture_lock);
}
#endif
#endif
#ifdef INFORMATION_BATTLE_NATIVE_TEXT
// 598DC0 copies message values and ordered template nodes, but does not copy
// the source +20/+24 bookkeeping words. Those unrelated words must not become
// identity prerequisites for a correctly copied popup message.
static bool same_copied_message(const battle::owned_template::Snapshot& expected,
    const battle::owned_template::Snapshot& actual) noexcept {
    if (expected.pair_count!=actual.pair_count || expected.pair_count>battle::owned_template::kMaxPairs
        || expected.native_date!=actual.native_date || expected.raw_flag_8c!=actual.raw_flag_8c
        || expected.raw_flag_8d!=actual.raw_flag_8d) return false;
    const auto same_text=[&](battle::owned_template::TextRange a,battle::owned_template::TextRange b) noexcept {
        constexpr size_t maximum=battle::owned_template::kMaxArenaBytes;
        return a.length==b.length && a.offset<=maximum && b.offset<=maximum
            && a.length<=maximum-a.offset && b.length<=maximum-b.offset
            && !memcmp(expected.arena.data()+a.offset,actual.arena.data()+b.offset,a.length);
    };
    if (!same_text(expected.auxiliary_text,actual.auxiliary_text)) return false;
    for (unsigned i=0;i<expected.pair_count;++i)
        if (!same_text(expected.pairs[i].key,actual.pairs[i].key)
            || !same_text(expected.pairs[i].value,actual.pairs[i].value)) return false;
    return true;
}
static void capture_line1(void* text,unsigned char flag,uintptr_t return_pc,
    uintptr_t formatter_frame,uintptr_t popup) noexcept {
#ifdef INFORMATION_BATTLE_GATE_TRACE
    trace_line1_entry(flag,return_pc,formatter_frame,popup);
#endif
    if (state.load(std::memory_order_acquire)!=enabled || GetCurrentThreadId()!=bound_thread
        || flag || (return_pc!=base+0x8c9f82 && return_pc!=base+0x8cb9d3)) return;
    line1_candidates.fetch_add(1);
    const bool land=return_pc==base+0x8c9f82;
    uintptr_t parent_pc=0,spilled_popup=0;
    if (!entry::valid_code_address(formatter_frame,land?0xae8:0x50)
        || !entry::valid_code_address(popup,0x250)
        || !read_value(formatter_frame+(land?0xad8:0x48),parent_pc)
        || parent_pc!=base+(land?0x8c2059:0x8c2068)
        || (land && (!read_value(formatter_frame+0xae0,spilled_popup) || spilled_popup!=popup))) {
        line1_binding_rejected.fetch_add(1);return;
    }
    if (!TryAcquireSRWLockExclusive(&capture_lock)) {
        busy.fetch_add(1);
#ifdef INFORMATION_BATTLE_GATE_TRACE
        trace_observation_drops.fetch_add(1);
#endif
        return;
    }
    struct Release final {~Release(){ReleaseSRWLockExclusive(&capture_lock);}} release;
    if (state.load(std::memory_order_acquire)!=enabled || !scope_depth || suppressed_scopes) {
        line1_no_scope.fetch_add(1);return;
    }
    auto& scope=scopes[scope_depth-1];
    if (!scope.has_record || scope.slot>=kSlots || scope.ambiguous || !scope.message_seen
        || !scope.has_message_copy_guard
        || slot_ready[scope.slot]) {line1_binding_rejected.fetch_add(1);return;}
    auto& record=slots[scope.slot];
    const auto kind=land?battle::owned_context::Kind::land:battle::owned_context::Kind::naval;
    if (values(record).sequence!=scope.sequence || record.native_text_invalid || record.line1_invalid
        || !contexts(record).context_present || contexts(record).context.kind!=kind
        || !template_values(record).template_present
        || template_values(record).template_source_kind!=template_wire::kMessageSource
        || record.native_text.definition_key.state!=native_text::FieldState::observed) {
        line1_binding_rejected.fetch_add(1);
#ifdef INFORMATION_BATTLE_GATE_TRACE
        scope.trace.line1_reject_mask|=gate_trace::line1_filter_rejected;
#endif
        return;
    }
    Reader reader;
    std::array<unsigned char,72> guard_before{},guard_after{};
    uintptr_t g=0,after_game=0;uint64_t p=0,after_player=0;int32_t date=0,after_date=0;
    const bool bound=code_guard() && context(g,p,date) && g==game && p==player
        && date==values(record).result.raw_date
        && read_message_copy_guard(reader,popup+0x1c0,guard_before) && guard_before==scope.message_copy_guard
        && battle::owned_template::capture(reader,popup+0x1c0,native_popup_message)
        && same_copied_message(template_values(record).message,native_popup_message)
        && native_text::capture_message(reader,popup+0x1c0,native_text_scratch)
        && native_text::merge(record.native_text,native_text_scratch,native_text_joined);
    if (!bound) {
        line1_binding_rejected.fetch_add(1);
#ifdef INFORMATION_BATTLE_GATE_TRACE
        scope.trace.line1_reject_mask|=gate_trace::line1_filter_rejected;
#endif
        return;
    }
    const bool copied=native_text::capture_string(reader,reinterpret_cast<uintptr_t>(text),
            native_text::SourceKind::native_line1,native_text_scratch)
        && context(after_game,after_player,after_date) && after_game==g && after_player==p && after_date==date
        && read_message_copy_guard(reader,popup+0x1c0,guard_after) && guard_after==guard_before
        && code_guard() && state.load(std::memory_order_acquire)==enabled
        && native_text::merge(native_text_joined,native_text_scratch,record.native_text);
    if (copied) line1_copied.fetch_add(1);
    else {
        // The joined metadata was already independently verified. A failed
        // or conflicting Line1 retracts that field only, then repacks the
        // arena so no retired text bytes remain reachable by the encoder.
        record.native_text=native_text_joined;
        record.native_text.native_line1={native_text::FieldState::unknown,native_text::SourceKind::native_line1,{}};
        native_text::clear(native_text_scratch);
        if (!native_text::merge(record.native_text,native_text_scratch,record.native_text)) {
            native_text::clear(record.native_text);record.native_text_invalid=true;
        }
        record.line1_invalid=true;
        line1_copy_failed.fetch_add(1);
#ifdef INFORMATION_BATTLE_GATE_TRACE
        scope.trace.line1_reject_mask|=gate_trace::line1_filter_rejected;
#endif
    }
    native_text::clear(native_text_scratch);native_text::clear(native_text_joined);
}
#endif
static bool country_handle(uint64_t handle) noexcept {
    uintptr_t db=0,rows=0,country=0; uint64_t actual=0;
    unsigned slot=static_cast<unsigned>((handle>>32)&0xffff);
    return handle && slot<4096 && entry::valid_code_address(base,0x233fe60) && read_value(base+0x233d8b0,db) && db>=0x10000 && db<0x800000000000ull-0x120
        && read_value(db+0x118,rows) && rows>=0x10000 && rows<0x800000000000ull-4096*8
        && read_value(rows+slot*8,country) && country>=0x10000 && country<0x800000000000ull-0x28
        && read_value(country+0x20,actual) && actual==handle;
}
static bool install() noexcept {
    if (patched) return code_guard();
    // A failed first publication is terminal. Never replace the immutable
    // original pointer or release an allocation reachable by VEH/unwinding.
    if (trampoline || information_battle_entry_original || !code_guard()) return false;
    if (entry::prepare(entry::kOriginalPrologue.data(),36,entry::kOriginalUnwind.data(),32,
        base+kEntryRva,reinterpret_cast<uintptr_t>(&information_battle_entry_stub),plan)!=entry::Status::prepared) return false;
    HMODULE pinned_module=nullptr;
    dll_pinned=GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS|GET_MODULE_HANDLE_EX_FLAG_PIN,
        reinterpret_cast<LPCWSTR>(&information_battle_entry_stub),&pinned_module)!=FALSE && pinned_module==self_module;
    if (!dll_pinned) return false;
    publication_stage=1;
    trampoline=static_cast<unsigned char*>(VirtualAlloc(nullptr,entry::kImageBytes,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE));
    if (!trampoline) return false;
    publication_stage=2;
    memcpy(trampoline,plan.image.data(),plan.image.size()); DWORD old=0;
    if (!VirtualProtect(trampoline,entry::kImageBytes,PAGE_EXECUTE_READ,&old)
        || !FlushInstructionCache(GetCurrentProcess(),trampoline,entry::kImageBytes)) return false;
    publication_stage=3;
    unwind={plan.runtime.begin,plan.runtime.end,plan.runtime.unwind};
    table_registered=RtlAddFunctionTable(&unwind,1,reinterpret_cast<DWORD64>(trampoline))!=FALSE;
    if (!table_registered) return false;
    publication_stage=4;
    DWORD64 image_base=0;
    if (RtlLookupFunctionEntry(reinterpret_cast<DWORD64>(trampoline+1),&image_base,nullptr)!=&unwind
        || image_base!=reinterpret_cast<DWORD64>(trampoline)) return false;
    information_battle_entry_original=trampoline;
    publication_stage=5;
    patch.count=1;
    patch.targets[0]={reinterpret_cast<void*>(base+kEntryRva),static_cast<unsigned>(entry::kPatchBytes),
        entry::kOriginalPrologue.data(),plan.patch.data(),trampoline,entry::kCodeBytes};
#ifdef INFORMATION_BATTLE_TEMPLATE
    if (!prepare_message_entries()) return false;
    patch.count=1+kMessageEntryCount;
#endif
#ifdef INFORMATION_BATTLE_NATIVE_TEXT
    if (!prepare_line1_entry()) return false;
    ++patch.count;
#endif
#ifdef INFORMATION_BATTLE_GATE_TRACE
    if (!prepare_gate_marker_entry()) return false;
#endif
#ifdef INFORMATION_BATTLE_NAME_HANDOFF
    if (!prepare_name_entry()) return false;
#endif
#ifdef INFORMATION_BATTLE_RETREAT
    if (!prepare_retreat_entries()) return false;
#endif
    publication_stage=6;
    last_patch_result=bridge_entry_patch::guarded_patch_apply(patch);
    const auto& result=last_patch_result;
    unsigned char current[entry::kPatchBytes]{}; Reader reader;
    patched=reader.read(base+kEntryRva,current,sizeof(current)) && !memcmp(current,plan.patch.data(),sizeof(current));
#ifdef INFORMATION_BATTLE_TEMPLATE
    for (unsigned i=0;i<kMessageEntryCount;++i) {
        auto& owned=message_entries[i];
        const auto& spec=message_entry::spec(static_cast<message_entry::EntryKind>(i));
        unsigned char prefix[message_entry::kMaxPrefixBytes]{};
        owned.patched=reader.read(base+spec.rva,prefix,spec.prefix_bytes)
            && !memcmp(prefix,owned.plan.patch.data(),spec.prefix_bytes);
        patched=patched && owned.patched;
    }
#endif
#ifdef INFORMATION_BATTLE_NATIVE_TEXT
    {
        const auto& spec=line1_entry_plan::spec();
        unsigned char prefix[line1_entry_plan::kMaxPatchBytes]{};
        line1_entry.patched=reader.read(base+spec.entry_rva,prefix,spec.prefix_bytes)
            && !memcmp(prefix,line1_entry.plan.patch.data(),spec.prefix_bytes);
        patched=patched && line1_entry.patched;
    }
#endif
#ifdef INFORMATION_BATTLE_NAME_HANDOFF
    {
        unsigned char prefix[name_entry_plan::kPrefixBytes]{};
        name_entry.patched=reader.read(base+name_entry_plan::kEntryRva,prefix,sizeof(prefix))
            && !memcmp(prefix,name_entry.plan.patch.data(),sizeof(prefix));
        patched=patched && name_entry.patched;
    }
#endif
#ifdef INFORMATION_BATTLE_RETREAT
    patched=retreat_mark_patched() && patched;
#endif
    if (!result.success || !result.threads_resumed || !result.protection_restored || result.pending_count) {
        (void)bridge_entry_patch::guarded_patch_retry_pending();
        state.store(restart_required,std::memory_order_release); return false;
    }
    publication_stage=7;
    return code_guard();
}
static const char* state_name(long value) noexcept {
    switch (value) { case cold:return "cold";case ready:return "ready";case enabled:return "enabled";
        case disabled:return "disabled";case source_changed:return "source_changed";case fault:return "fault";
        default:return "restart_required"; }
}
struct StatusFailure final {
    const char* stage = "none";
    DWORD error = ERROR_SUCCESS;
};
static void remember_status_failure(StatusFailure failure) noexcept {
    last_status_write_stage = failure.stage;
    last_status_write_error = failure.error;
}
static bool status_failure(StatusFailure failure,StatusFailure* output) noexcept {
    remember_status_failure(failure);
    if (output) *output=failure;
    return false;
}
static bool write_json(const wchar_t* path,const char* bytes,size_t size,DWORD disposition,
                       StatusFailure* failure=nullptr) noexcept {
    if (failure) *failure=StatusFailure{};
    HANDLE file=CreateFileW(path,GENERIC_WRITE,FILE_SHARE_READ,nullptr,disposition,FILE_ATTRIBUTE_NORMAL,nullptr);
    if (file==INVALID_HANDLE_VALUE) {
        if (failure) { failure->stage="open"; failure->error=GetLastError(); }
        return false;
    }
    DWORD written=0;
    bool ok=true;
    StatusFailure local{};
    if (size>MAXDWORD) {
        local={"size",ERROR_INVALID_PARAMETER};
        ok=false;
    } else if (!WriteFile(file,bytes,static_cast<DWORD>(size),&written,nullptr)) {
        local={"write",GetLastError()};
        ok=false;
    } else if (written!=size) {
        local={"short_write",ERROR_WRITE_FAULT};
        ok=false;
    } else if (!FlushFileBuffers(file)) {
        local={"flush",GetLastError()};
        ok=false;
    }
    const bool closed=CloseHandle(file)!=FALSE;
    if (!closed && ok) { local={"close",GetLastError()}; ok=false; }
    if (failure && !ok) *failure=local;
    return ok && closed;
}
static bool status(const char* nonce,const char* verb,bool ok,const char* reason,bool response,
                   StatusFailure* failure_out=nullptr) noexcept {
    if (failure_out) *failure_out=StatusFailure{};
#ifdef INFORMATION_BATTLE_INDEPENDENT_LINE
    char json[8192]{};
#elif defined(INFORMATION_BATTLE_OUTCOME_TAIL)
    char json[6144]{};
#elif defined(INFORMATION_BATTLE_OUTCOME_TEXT)
    char json[5120]{};
#elif defined(INFORMATION_BATTLE_NAME_SOURCES)
    char json[4608]{};
#else
    char json[4096]{};
#endif
    char title_stats[512]{};
#ifdef INFORMATION_BATTLE_GATE_TRACE
    char gate_stats[512]{};
    const int gate_size=snprintf(gate_stats,sizeof(gate_stats),
        "\"gate_trace_enabled\":true,\"gate_trace_protocol\":\"EU4-BATTLE-GATE-TRACE/1\","
        "\"gate_trace_records\":\"%llu\",\"gate_trace_failures\":\"%llu\","
        "\"gate_trace_observation_drops\":\"%llu\",\"gate_trace_write_error\":%lu,",
        static_cast<unsigned long long>(trace_records_written.load()),
        static_cast<unsigned long long>(trace_write_failures.load()),
        static_cast<unsigned long long>(trace_observation_drops.load()),static_cast<unsigned long>(trace_write_error));
    if (gate_size<=0 || static_cast<size_t>(gate_size)>=sizeof(gate_stats))
        return status_failure({"format_gate_trace",ERROR_INSUFFICIENT_BUFFER},failure_out);
#else
    constexpr const char* gate_stats="";
#endif
#ifdef INFORMATION_BATTLE_DISPLAY_CONTEXT
    char display_stats[384]{};
    const int display_size=snprintf(display_stats,sizeof(display_stats),
        "\"display_context_enabled\":true,\"display_context_stage\":\"router_scope_exit\","
        "\"display_context_candidates\":\"%llu\",\"display_context_copied\":\"%llu\","
        "\"display_context_failures\":\"%llu\",\"display_context_last_failure\":%u,",
        static_cast<unsigned long long>(display_context_candidates.load()),
        static_cast<unsigned long long>(display_context_copied.load()),
        static_cast<unsigned long long>(display_context_failures.load()),display_context_last_failure.load());
    if (display_size<=0 || static_cast<size_t>(display_size)>=sizeof(display_stats))
        return status_failure({"format_display_context",ERROR_INSUFFICIENT_BUFFER},failure_out);
#else
    constexpr const char* display_stats="";
#endif
#ifdef INFORMATION_BATTLE_NATIVE_TITLE_QUERY
    const int title_size=snprintf(title_stats,sizeof(title_stats),
#ifdef INFORMATION_BATTLE_NO_TITLE_QUERY_INVOKE
        "\"native_title_query_enabled\":false,\"native_title_query_mode\":\"cached_sources_no_helper_invoke\","
#else
        "\"native_title_query_enabled\":true,\"native_title_query_mode\":\"native_helper_owned_output\","
#endif
        "\"title_query_candidates\":\"%llu\",\"title_query_attempted\":\"%llu\","
        "\"title_query_destroyed\":\"%llu\",\"title_query_copied\":\"%llu\",\"title_query_failures\":\"%llu\",",
        static_cast<unsigned long long>(title_query_candidates.load()),
        static_cast<unsigned long long>(title_query_attempted.load()),
        static_cast<unsigned long long>(title_query_destroyed.load()),
        static_cast<unsigned long long>(title_query_copied.load()),
        static_cast<unsigned long long>(title_query_failed.load()));
    if (title_size<=0 || static_cast<size_t>(title_size)>=sizeof(title_stats))
        return status_failure({"format_title",ERROR_INSUFFICIENT_BUFFER},failure_out);
#endif
    char name_stats[512]{};
#ifdef INFORMATION_BATTLE_NAME_HANDOFF
    const int name_size=snprintf(name_stats,sizeof(name_stats),
        "\"name_handoff_enabled\":true,\"name_handoff_stage\":\"before_pair_move\","
        "\"name_handoff_candidates\":\"%llu\",\"name_handoff_copied\":\"%llu\","
        "\"name_handoff_failures\":\"%llu\",\"name_handoff_conflicts\":\"%llu\",",
        static_cast<unsigned long long>(name_candidates.load()),static_cast<unsigned long long>(name_copied.load()),
        static_cast<unsigned long long>(name_failed.load()),static_cast<unsigned long long>(name_conflicts.load()));
    if (name_size<=0 || static_cast<size_t>(name_size)>=sizeof(name_stats))
        return status_failure({"format_name_handoff",ERROR_INSUFFICIENT_BUFFER},failure_out);
#endif
    char retreat_stats[384]{};
#ifdef INFORMATION_BATTLE_RETREAT
    const int retreat_size=snprintf(retreat_stats,sizeof(retreat_stats),
        "\"retreat_capture_enabled\":true,\"retreat_capture_stage\":\"regular_battle_end_unit_path_callback\","
        "\"retreat_unit_removal_capture_enabled\":true,\"retreat_max_extension_version\":2,"
        "\"open_retreat_scopes\":%u,\"retreat_observation_drops\":\"%llu\",",
        retreat_depth+retreat_suppressed,static_cast<unsigned long long>(retreat_drops.load()));
    if (retreat_size<=0 || static_cast<size_t>(retreat_size)>=sizeof(retreat_stats))
        return status_failure({"format_retreat",ERROR_INSUFFICIENT_BUFFER},failure_out);
#endif
#ifdef INFORMATION_BATTLE_OUTCOME_TAIL
#ifdef INFORMATION_BATTLE_FLAG_INPUTS
    char sources_stats[2048]{};
#elif defined(INFORMATION_BATTLE_INDEPENDENT_LINE)
    char sources_stats[1664]{};
#else
    char sources_stats[1280]{};
#endif
#elif defined(INFORMATION_BATTLE_OUTCOME_TEXT)
    char sources_stats[832]{};
#else
    char sources_stats[384]{};
#endif
#ifdef INFORMATION_BATTLE_NAME_SOURCES
    const int sources_size=snprintf(sources_stats,sizeof(sources_stats),
        "\"name_sources_enabled\":true,\"name_sources_stage\":\"entry_before_client_gate\","
        "\"name_source_candidates\":\"%llu\",\"name_source_copied\":\"%llu\","
        "\"name_prefix_copied\":\"%llu\",\"name_source_encode_failures\":\"%llu\",",
        static_cast<unsigned long long>(name_source_candidates.load()),
        static_cast<unsigned long long>(name_source_copied.load()),
        static_cast<unsigned long long>(name_prefix_copied.load()),
        static_cast<unsigned long long>(name_source_encode_failed.load()));
    if (sources_size<=0 || static_cast<size_t>(sources_size)>=sizeof(sources_stats))
        return status_failure({"format_name_sources",ERROR_INSUFFICIENT_BUFFER},failure_out);
#endif
#ifdef INFORMATION_BATTLE_OUTCOME_TEXT
    const auto sources_used=strlen(sources_stats);
    const auto outcome_capacity=sizeof(sources_stats)-sources_used;
    const int outcome_size=snprintf(sources_stats+sources_used,outcome_capacity,
        "\"outcome_text_enabled\":true,\"outcome_text_stage\":\"entry_before_client_gate\","
        "\"outcome_text_candidates\":\"%llu\",\"outcome_text_copied\":\"%llu\","
        "\"outcome_text_failures\":\"%llu\",\"outcome_text_encode_failures\":\"%llu\","
        "\"outcome_text_last_failure\":%u,",
        static_cast<unsigned long long>(outcome_text_candidates.load()),
        static_cast<unsigned long long>(outcome_text_copied.load()),
        static_cast<unsigned long long>(outcome_text_failed.load()),
        static_cast<unsigned long long>(outcome_text_encode_failed.load()),outcome_text_last_failure.load());
    if (outcome_size<=0 || static_cast<size_t>(outcome_size)>=outcome_capacity)
        return status_failure({"format_outcome_text",ERROR_INSUFFICIENT_BUFFER},failure_out);
#endif
#ifdef INFORMATION_BATTLE_OUTCOME_TAIL
    const auto tail_sources_used=strlen(sources_stats);
    const auto tail_capacity=sizeof(sources_stats)-tail_sources_used;
    const int tail_size=snprintf(sources_stats+tail_sources_used,tail_capacity,
        "\"outcome_tail_enabled\":true,\"outcome_tail_stage\":\"entry_before_client_gate\","
        "\"outcome_tail_candidates\":\"%llu\",\"outcome_tail_copied\":\"%llu\","
        "\"outcome_tail_failures\":\"%llu\",\"outcome_tail_encode_failures\":\"%llu\","
        "\"outcome_tail_last_failure\":%u,",
        static_cast<unsigned long long>(outcome_tail_candidates.load()),
        static_cast<unsigned long long>(outcome_tail_copied.load()),
        static_cast<unsigned long long>(outcome_tail_failed.load()),
        static_cast<unsigned long long>(outcome_tail_encode_failed.load()),outcome_tail_last_failure.load());
    if (tail_size<=0 || static_cast<size_t>(tail_size)>=tail_capacity)
        return status_failure({"format_outcome_tail",ERROR_INSUFFICIENT_BUFFER},failure_out);
#endif
#ifdef INFORMATION_BATTLE_INDEPENDENT_LINE
    const auto line_used=strlen(sources_stats);
    const auto line_capacity=sizeof(sources_stats)-line_used;
    const int line_size=snprintf(sources_stats+line_used,line_capacity,
        "\"independent_line_enabled\":true,\"independent_line_candidates\":\"%llu\","
        "\"independent_line_invoked\":\"%llu\",\"independent_line_copied\":\"%llu\","
        "\"independent_line_failures\":\"%llu\",\"independent_line_encode_failures\":\"%llu\",",
        static_cast<unsigned long long>(independent_line_candidates.load()),
        static_cast<unsigned long long>(independent_line_invoked.load()),
        static_cast<unsigned long long>(independent_line_copied.load()),
        static_cast<unsigned long long>(independent_line_failed.load()),
        static_cast<unsigned long long>(independent_line_encode_failed.load()));
    if (line_size<=0 || static_cast<size_t>(line_size)>=line_capacity)
        return status_failure({"format_independent_line",ERROR_INSUFFICIENT_BUFFER},failure_out);
#endif
#ifdef INFORMATION_BATTLE_FLAG_INPUTS
    const auto flag_used=strlen(sources_stats);
    const auto flag_capacity=sizeof(sources_stats)-flag_used;
    const int flag_size=snprintf(sources_stats+flag_used,flag_capacity,
        "\"flag_inputs_enabled\":true,\"flag_input_candidates\":\"%llu\",\"flag_input_copied\":\"%llu\","
        "\"flag_input_failures\":\"%llu\",\"flag_input_encode_failures\":\"%llu\",",
        static_cast<unsigned long long>(flag_input_candidates.load()),
        static_cast<unsigned long long>(flag_input_copied.load()),
        static_cast<unsigned long long>(flag_input_failed.load()),
        static_cast<unsigned long long>(flag_input_encode_failed.load()));
    if (flag_size<=0 || static_cast<size_t>(flag_size)>=flag_capacity)
        return status_failure({"format_flag_inputs",ERROR_INSUFFICIENT_BUFFER},failure_out);
#endif
    unsigned long long template_stats[4]{}, container_stats[3]{}, native_stats[7]{}; unsigned open_scopes=0;
#ifdef INFORMATION_BATTLE_NATIVE_TEXT
    native_stats[0]=native_metadata_copied.load(); native_stats[1]=native_metadata_failed.load();
    native_stats[2]=line1_candidates.load();native_stats[3]=line1_no_scope.load();
    native_stats[4]=line1_binding_rejected.load();native_stats[5]=line1_copied.load();native_stats[6]=line1_copy_failed.load();
#endif
#ifdef INFORMATION_BATTLE_CONTAINER
    container_stats[0]=container_candidates.load(); container_stats[1]=container_copied.load();
    container_stats[2]=container_copy_failed.load();
#endif
#ifdef INFORMATION_BATTLE_TEMPLATE
    template_stats[0]=template_copied.load(); template_stats[1]=template_copy_failed.load();
    template_stats[2]=template_ambiguous.load(); template_stats[3]=scope_overflow.load();
    open_scopes=scope_depth+suppressed_scopes;
#endif
    const auto stats=drain.stats();
    int size=snprintf(json,sizeof(json),
        "{\"schema\":\"EU4-BATTLE-SOURCE/1\",\"request_id\":\"%s\",\"command\":\"%s\",\"accepted\":%s,\"reason\":\"%s\","
        "\"state\":\"%s\",\"pid\":%lu,\"creation_filetime\":\"%llu\",\"installation\":\"%llu\",\"generation\":\"%llu\","
        "\"exe_sha256\":\"%s\",\"dll_sha256\":\"%s\",\"code_patch_installed\":%s,\"dll_pinned\":%s,\"unwind_registered\":%s,\"publication_stage\":%u,\"patch_attempt_published\":%s,\"patch_failure_stage\":%u,"
        "\"published_resources_process_lifetime\":true,\"capture_complete\":false,\"visibility_verified\":false,\"business_export_available\":false,\"stats_consistent\":false,\"same_address_reload_verified\":false,"
        "\"last_sequence\":\"%llu\",\"captured\":\"%llu\",\"dropped_busy\":\"%llu\",\"dropped_full\":\"%llu\",\"dropped_foreign_thread\":\"%llu\","
        "\"copy_failures\":\"%llu\",\"guard_failures\":\"%llu\",\"fragment_queued\":\"%llu\",\"fragment_sink_pending\":%s,\"writer_status\":%u,"
        "\"status_publication_pending\":%s,\"status_publication_failures\":%u,\"status_write_stage\":\"%s\",\"status_write_error\":%lu,"
        "\"wire_version\":%u,\"context_copied\":\"%llu\",\"context_copy_failures\":\"%llu\"," 
        "\"template_copied\":\"%llu\",\"template_copy_failures\":\"%llu\",\"template_ambiguous\":\"%llu\","
        "\"scope_overflow\":\"%llu\",\"open_message_scopes\":%u,"
        "\"container_candidates\":\"%llu\",\"container_copied\":\"%llu\",\"container_copy_failures\":\"%llu\","
        "\"native_metadata_copied\":\"%llu\",\"native_metadata_failures\":\"%llu\","
        "\"line1_candidates\":\"%llu\",\"line1_without_scope\":\"%llu\",\"line1_binding_rejected\":\"%llu\","
        "\"line1_copied\":\"%llu\",\"line1_copy_failures\":\"%llu\",%s%s%s%s%s%s\"business_complete\":false}\n",
        nonce,verb,ok?"true":"false",reason,state_name(state.load(std::memory_order_acquire)),
        static_cast<unsigned long>(GetCurrentProcessId()),static_cast<unsigned long long>(creation),
        static_cast<unsigned long long>(identity.installation),static_cast<unsigned long long>(identity.generation),kExeSha,dll_sha,
        patched?"true":"false",dll_pinned?"true":"false",table_registered?"true":"false",publication_stage,
        last_patch_result.published?"true":"false",static_cast<unsigned>(last_patch_result.failure_stage),
        static_cast<unsigned long long>(sequence.load()),static_cast<unsigned long long>(accepted.load()),
        static_cast<unsigned long long>(busy.load()),static_cast<unsigned long long>(full.load()),
        static_cast<unsigned long long>(foreign_thread.load()),static_cast<unsigned long long>(copy_failed.load()),
        static_cast<unsigned long long>(guard_failed.load()),static_cast<unsigned long long>(stats.queued),
        drain.has_pending()?"true":"false",static_cast<unsigned>(writer.status()),
        heartbeat_publication_pending?"true":"false",heartbeat_publication_failures,
        last_status_write_stage,static_cast<unsigned long>(last_status_write_error),kWireVersion,
        static_cast<unsigned long long>(context_copied.load()),static_cast<unsigned long long>(context_copy_failed.load()),
        template_stats[0],template_stats[1],template_stats[2],template_stats[3],open_scopes,
        container_stats[0],container_stats[1],container_stats[2],native_stats[0],native_stats[1],
        native_stats[2],native_stats[3],native_stats[4],native_stats[5],native_stats[6],title_stats,gate_stats,display_stats,name_stats,retreat_stats,sources_stats);
    if (size<=0 || static_cast<size_t>(size)>=sizeof(json))
        return status_failure({"format",ERROR_INSUFFICIENT_BUFFER},failure_out);
    wchar_t target[MAX_PATH]{},temporary[MAX_PATH]{};
    if (response) {
        if (swprintf(target,MAX_PATH,L"%ls\\information-battle-response-%hs.json",directory,nonce)<0)
            return status_failure({"response_path",ERROR_INSUFFICIENT_BUFFER},failure_out);
        StatusFailure failure{};
        if (!write_json(target,json,size,CREATE_NEW,&failure))
            return status_failure(failure,failure_out);
        return true;
    }
    if (swprintf(target,MAX_PATH,L"%ls\\information-battle-status.json",directory)<0
        || swprintf(temporary,MAX_PATH,L"%ls\\information-battle-status.tmp",directory)<0)
        return status_failure({"status_path",ERROR_INSUFFICIENT_BUFFER},failure_out);
    StatusFailure failure{};
    if (!write_json(temporary,json,size,CREATE_ALWAYS,&failure))
        return status_failure(failure,failure_out);
    if (!MoveFileExW(temporary,target,MOVEFILE_REPLACE_EXISTING|MOVEFILE_WRITE_THROUGH))
        return status_failure({"replace",GetLastError()},failure_out);
    return true;
}
enum class HeartbeatPublicationResult : unsigned { published, retry_pending, terminal_failure };
static bool heartbeat_retryable(const StatusFailure& failure) noexcept {
    // A target handle without delete sharing can make MoveFileExW report
    // access denied even though the publication is transient.  Keep
    // ERROR_ACCESS_DENIED fail-closed everywhere else: an ACL/open/write
    // denial must never be mistaken for a replace race.
    return failure.error==ERROR_SHARING_VIOLATION
        || failure.error==ERROR_LOCK_VIOLATION
        || (failure.error==ERROR_ACCESS_DENIED
            && failure.stage!=nullptr
            && std::strcmp(failure.stage,"replace")==0);
}
static HeartbeatPublicationResult heartbeat_status(bool usable,const char* reason,
                                                   uint64_t now) noexcept {
    if (heartbeat_publication_pending && now<heartbeat_retry_next)
        return HeartbeatPublicationResult::retry_pending;
    const bool was_pending=heartbeat_publication_pending;
    heartbeat_publication_pending=false;
    StatusFailure failure{};
    if (status("","heartbeat",usable,reason,false,&failure)) {
        heartbeat_retry_next=0;
        heartbeat_retry_deadline=0;
        return HeartbeatPublicationResult::published;
    }
    ++heartbeat_publication_failures;
    if (!heartbeat_retryable(failure)) {
        heartbeat_retry_next=0;
        heartbeat_retry_deadline=0;
        return HeartbeatPublicationResult::terminal_failure;
    }
    if (!was_pending) heartbeat_retry_deadline=now+3000;
    if (now<heartbeat_retry_deadline) {
        heartbeat_publication_pending=true;
        heartbeat_retry_next=now+100;
        return HeartbeatPublicationResult::retry_pending;
    }
    heartbeat_publication_pending=false;
    heartbeat_retry_next=0;
    last_status_write_stage="heartbeat_publication_timeout";
    return HeartbeatPublicationResult::terminal_failure;
}
static bool decimal(const char* text,uint64_t& value) noexcept {
    value=0; if (!*text) return false;
    for (const char* p=text;*p;++p) { if (*p<'0'||*p>'9'||value>(UINT64_MAX-static_cast<unsigned>(*p-'0'))/10) return false;
        value=value*10+static_cast<unsigned>(*p-'0'); } return true;
}
static bool hex(const char* text,unsigned length,uint64_t* value=nullptr) noexcept {
    if (strlen(text)!=length) return false;
    uint64_t parsed=0;
    for (unsigned i=0;i<length;++i) { unsigned v=text[i]>='0'&&text[i]<='9'?text[i]-'0':text[i]>='a'&&text[i]<='f'?text[i]-'a'+10:16;
        if (v==16) return false;
        if (value) parsed=(parsed<<4)|v; }
    if (value) *value=parsed;
    return true;
}
// Exactly eight ASCII tokens. Files are claimed by rename before parsing.
// No historical or unknown command is automatically resubmitted.
static bool command(char* text,char (&nonce)[33],char (&verb)[9],const char*& reason) noexcept {
    char* tokens[8]{}; unsigned n=0; char* p=text;
    while (*p) { if (n==8) { reason="syntax";return false; } tokens[n++]=p;
        while (*p && *p!=' ' && *p!='\n') { if (*p<'!'||*p>'~') { reason="syntax";return false; } ++p; }
        if (*p) { char separator=*p; *p++=0; if (!*p && separator=='\n') break; if (!*p||*p==' '||*p=='\n') { reason="syntax";return false; } }
    }
    if (n!=8 || strcmp(tokens[0],"EU4BATTLE1") || !hex(tokens[1],32)
        || (strcmp(tokens[2],"enable")&&strcmp(tokens[2],"disable")&&strcmp(tokens[2],"status"))) { reason="syntax";return false; }
    strcpy(nonce,tokens[1]);strcpy(verb,tokens[2]);
    wchar_t previous_response[MAX_PATH]{};
    if (swprintf(previous_response,MAX_PATH,L"%ls\\information-battle-response-%hs.json",directory,nonce)<0) {
        reason="response_path";return false;
    }
    if (GetFileAttributesW(previous_response)!=INVALID_FILE_ATTRIBUTES) {reason="duplicate_request";return false;}
    uint64_t pid=0,created=0,installation=0,expected_player=0;
    if (!decimal(tokens[3],pid)||!decimal(tokens[4],created)||!decimal(tokens[5],installation)||!installation
        ||!hex(tokens[6],64)||!hex(tokens[7],16,&expected_player)) {reason="syntax";return false;}
    if (pid!=GetCurrentProcessId()||created!=creation||strcmp(tokens[6],dll_sha)
        || (identity.valid()&&(identity.installation!=installation || expected_player!=player))) {reason="identity_mismatch";return false;}
    wchar_t nonce_receipt[MAX_PATH]{};
    if (swprintf(nonce_receipt,MAX_PATH,L"%ls\\information-battle-started-%hs.json",directory,nonce)<0) {reason="receipt_path";return false;}
    if (GetFileAttributesW(nonce_receipt)!=INVALID_FILE_ATTRIBUTES) {reason="prior_outcome_unknown_no_retry";return false;}
    char receipt[512]{};
    int receipt_bytes=snprintf(receipt,sizeof(receipt),"{\"request_id\":\"%s\",\"command\":\"%s\",\"pid\":%llu,\"creation\":\"%llu\",\"installation\":\"%llu\",\"dll_sha256\":\"%s\",\"player_ref\":\"%s\",\"result\":\"started_outcome_requires_response\"}\n",
        nonce,verb,static_cast<unsigned long long>(pid),static_cast<unsigned long long>(created),static_cast<unsigned long long>(installation),tokens[6],tokens[7]);
    if (receipt_bytes<=0 || static_cast<size_t>(receipt_bytes)>=sizeof(receipt)) {
        remember_status_failure({"receipt_format",ERROR_INSUFFICIENT_BUFFER});
        reason="receipt_write_failed";return false;
    }
    StatusFailure receipt_failure{};
    if (!write_json(nonce_receipt,receipt,receipt_bytes,CREATE_NEW,&receipt_failure)) {
        remember_status_failure(receipt_failure);
        reason="receipt_write_failed";return false;
    }
    if (!strcmp(verb,"status")) { reason="observed";return true; }
    if (!strcmp(verb,"disable")) {
        if (!identity.valid()) {reason="unbound_source";return false;}
        const long current=state.load(std::memory_order_acquire);
        if (current!=enabled && current!=disabled) {reason="terminal_source_state";return false;}
        transition(disabled);
        reason="capture_disabled_resources_retained";return true;
    }
    long current=state.load(std::memory_order_acquire);
    if (current!=ready && current!=disabled && current!=enabled) {reason="terminal_source_state";return false;}
    uintptr_t current_game=0;uint64_t current_player=0;int32_t date=0;
    if (!frame_thread || frame_thread!=GetCurrentThreadId() || thread_changed || !file_identity() || !code_guard()
        || !context(current_game,current_player,date) || current_player!=expected_player || !country_handle(current_player)) {
        reason="source_guard";return false;
    }
    if (identity.valid() && (current_game!=game || current_player!=player || frame_thread!=bound_thread)) {
        transition(source_changed);reason="source_changed";return false;
    }
    if (current==enabled) {reason="already_enabled";return true;}
    if (!identity.valid()) {
        // Each process owns a fresh stream. Never append a reset sequence to
        // an old file, even when a caller reuses the installation identifier.
        if (GetFileAttributesW(log_path)!=INVALID_FILE_ATTRIBUTES
            || !drain.reset({installation,creation}).succeeded() || !writer.open(log_path,{installation,creation})) {
            transition(fault);reason="transport_open_failed";return false;
        }
        identity={installation,creation};game=current_game;player=current_player;bound_thread=frame_thread;last_date=date;
    }
    if (!install()) {transition(restart_required);reason="patch_install_failed";return false;}
    transition(enabled);reason="capture_enabled";return true;
}
static void poll() noexcept {
    if (GetFileAttributesW(processing_path)!=INVALID_FILE_ATTRIBUTES) {transition(fault);return;}
    if (!MoveFileExW(request_path,processing_path,MOVEFILE_WRITE_THROUGH)) return;
    char buffer[513]{},nonce[33]="00000000000000000000000000000000",verb[9]="invalid";
    HANDLE file=CreateFileW(processing_path,GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr);
    DWORD bytes=0;LARGE_INTEGER size{};
    bool readable=file!=INVALID_HANDLE_VALUE && GetFileSizeEx(file,&size) && size.QuadPart>0 && size.QuadPart<=512
        && ReadFile(file,buffer,static_cast<DWORD>(size.QuadPart),&bytes,nullptr) && bytes==size.QuadPart;
    if (file!=INVALID_HANDLE_VALUE && !CloseHandle(file)) readable=false;
    const char* reason="request_read_failed";
    bool ok=readable && !memchr(buffer,0,bytes) && command(buffer,nonce,verb,reason);
    const bool duplicate=!strcmp(reason,"duplicate_request");
    if (!status(nonce,verb,ok,reason,!duplicate) || !DeleteFileW(processing_path)) transition(fault);
}
static bool drain_fragments() noexcept {
    const auto drained=drain.drain(writer,8);
    if (drained.status!=battle::DrainStatus::sink_rejected && !writer.fault_latched()) return true;
    // Lock contention writes no bytes. The drain retains this fragment for
    // the next frame, preserving its original sequence and acknowledgement.
    if (writer.fault_latched() || writer.status()!=battle::LogStatus::lock_busy)
        state.store(fault,std::memory_order_release);
    return false;
}
static void flush() noexcept {
    if (!TryAcquireSRWLockExclusive(&capture_lock)) return;
    struct Release final {~Release(){ReleaseSRWLockExclusive(&capture_lock);}} release;
    const auto source_state=state.load(std::memory_order_acquire);
    if (!identity.valid() || (source_state!=enabled && source_state!=disabled)) return;
    if (!drain_fragments()) return;
    if (!has_pending) {
        if (count
#ifdef INFORMATION_BATTLE_TEMPLATE
            && slot_ready[head]
#endif
        ) {
            pending=slots[head];
#ifdef INFORMATION_BATTLE_TEMPLATE
            slot_ready[head]=false;
#endif
            head=(head+1)%kSlots;--count;has_pending=true;
        }
        if (!has_pending) return;
#ifdef INFORMATION_BATTLE_GATE_TRACE
        if (!write_gate_trace(pending)) {state.store(fault,std::memory_order_release);return;}
#endif
#ifdef INFORMATION_BATTLE_NATIVE_TEXT
        const auto base_result=war_identity_wire::encode(war_values(pending),encoded_v5,sizeof(encoded_v5));
#ifdef INFORMATION_BATTLE_DISPLAY_CONTEXT
#ifdef INFORMATION_BATTLE_END_STATE
        auto* const base_output=encoded_end_state_base;
#else
        auto* const base_output=encoded;
#endif
        const auto text_result=base_result.succeeded()
            ? native_text_wire::encode(encoded_v5,base_result.written_bytes,pending.native_text,encoded_v6,sizeof(encoded_v6))
            : native_text_wire::EncodeResult{};
#ifdef INFORMATION_BATTLE_NAME_HANDOFF
        const auto display_result=text_result.succeeded()
            ? display_context_wire::encode(encoded_v6,text_result.written_bytes,pending.display_context,encoded_v7,sizeof(encoded_v7))
            : display_context_wire::EncodeResult{};
        auto result=display_result.succeeded()
            ? name_wire::encode(encoded_v7,display_result.written_bytes,pending.name_handoff,base_output,sizeof(encoded))
            : name_wire::EncodeResult{};
#else
        auto result=text_result.succeeded()
            ? display_context_wire::encode(encoded_v6,text_result.written_bytes,pending.display_context,base_output,sizeof(encoded))
            : display_context_wire::EncodeResult{};
#endif
#else
        auto result=base_result.succeeded()
            ? native_text_wire::encode(encoded_v5,base_result.written_bytes,pending.native_text,encoded,sizeof(encoded))
            : native_text_wire::EncodeResult{};
#endif
#ifdef INFORMATION_BATTLE_END_STATE
        if (result.succeeded()) {
            battle::end_state_wire::Snapshot end_snapshot{};
            end_snapshot.sequence=values(pending).sequence;
            end_snapshot.raw_date=values(pending).result.raw_date;
            end_snapshot.kind=static_cast<uint8_t>(contexts(pending).context.kind);
            end_snapshot.present=pending.end_state_present;
            end_snapshot.raw_gates=pending.end_state.raw_gate;
            const auto end_result=battle::end_state_wire::encode(base_output,result.written_bytes,
                end_snapshot,encoded,sizeof(encoded));
            if (end_result.succeeded()) result.written_bytes=end_result.written_bytes;
            else memcpy(encoded,base_output,result.written_bytes);
        }
#endif
#ifdef INFORMATION_BATTLE_RETREAT
        if (result.succeeded()) {
            // v9 has finished using its scratch. Reuse it as the immutable
            // v10 base; failure leaves the existing encoded frame unchanged.
            memcpy(encoded_end_state_base,encoded,result.written_bytes);
            const auto retreat_result=battle::retreat_wire::encode(encoded_end_state_base,
                result.written_bytes,pending.retreat,encoded,sizeof(encoded));
            if (retreat_result.succeeded()) result.written_bytes=retreat_result.written_bytes;
        }
#endif
#ifdef INFORMATION_BATTLE_NAME_SOURCES
        if (result.succeeded()) {
            // The v10 bytes are immutable while the extension is encoded.
            // A bounded extension failure preserves the valid base record.
            memcpy(encoded_end_state_base,encoded,result.written_bytes);
            pending.name_sources.sequence=values(pending).sequence;
            pending.name_sources.raw_date=values(pending).result.raw_date;
            pending.name_sources.kind=static_cast<uint8_t>(contexts(pending).context.kind);
            const auto name_result=battle::name_sources_wire::encode(encoded_end_state_base,
                result.written_bytes,pending.name_sources,encoded,sizeof(encoded));
            if (name_result.succeeded()) result.written_bytes=name_result.written_bytes;
            else name_source_encode_failed.fetch_add(1);
        }
#endif
#ifdef INFORMATION_BATTLE_OUTCOME_TEXT
        if (result.succeeded()) {
            // v11 is immutable during OCTX encoding. No partial overwrite is
            // published if the bounded extension does not fit or validate.
            memcpy(encoded_end_state_base,encoded,result.written_bytes);
            pending.outcome_text.sequence=values(pending).sequence;
            pending.outcome_text.raw_date=values(pending).result.raw_date;
            pending.outcome_text.kind=static_cast<uint8_t>(contexts(pending).context.kind);
            const auto outcome_result=battle::outcome_text_wire::encode(encoded_end_state_base,
                result.written_bytes,pending.outcome_text,encoded,sizeof(encoded));
            if (outcome_result.succeeded()) result.written_bytes=outcome_result.written_bytes;
            else outcome_text_encode_failed.fetch_add(1);
        }
#endif
#ifdef INFORMATION_BATTLE_OUTCOME_TAIL
        if (result.succeeded()) {
            // v12 is immutable during SCTX encoding. No partial overwrite is
            // published if the bounded extension does not fit or validate.
            memcpy(encoded_end_state_base,encoded,result.written_bytes);
            pending.outcome_tail.sequence=values(pending).sequence;
            pending.outcome_tail.raw_date=values(pending).result.raw_date;
            pending.outcome_tail.kind=static_cast<uint8_t>(contexts(pending).context.kind);
            const auto outcome_result=battle::outcome_tail_wire::encode(encoded_end_state_base,
                result.written_bytes,pending.outcome_tail,encoded,sizeof(encoded));
            if (outcome_result.succeeded()) result.written_bytes=outcome_result.written_bytes;
            else outcome_tail_encode_failed.fetch_add(1);
        }
#endif
#ifdef INFORMATION_BATTLE_INDEPENDENT_LINE
        if (result.succeeded()) {
            memcpy(encoded_end_state_base,encoded,result.written_bytes);
            const auto line_result=battle::independent_line_wire::encode(encoded_end_state_base,
                result.written_bytes,pending.independent_line,encoded,sizeof(encoded));
            if (line_result.succeeded()) result.written_bytes=line_result.written_bytes;
            else {independent_line_encode_failed.fetch_add(1);result.written_bytes=0;}
        }
#endif
#ifdef INFORMATION_BATTLE_FLAG_INPUTS
        if (result.succeeded()) {
            const auto kind = static_cast<uint8_t>(contexts(pending).context.kind);
            if (kind == 2) {
                pending.flag_inputs = {};
                pending.flag_inputs.state = battle::flag_input_wire::State::not_applicable;
                pending.flag_inputs.failure = 0;
            } else if (!template_values(pending).template_present) {
                pending.flag_inputs = {};
                pending.flag_inputs.failure = static_cast<uint8_t>(battle::owned_flag_inputs::Failure::base_unknown);
            }
            pending.flag_inputs.sequence = values(pending).sequence;
            pending.flag_inputs.raw_date = values(pending).result.raw_date;
            pending.flag_inputs.kind = kind;
            memcpy(encoded_end_state_base,encoded,result.written_bytes);
            const auto flags_result=battle::flag_input_wire::encode(encoded_end_state_base,
                result.written_bytes,pending.flag_inputs,encoded,sizeof(encoded));
            if (flags_result.succeeded()) result.written_bytes=flags_result.written_bytes;
            else flag_input_encode_failed.fetch_add(1); // The untouched v14 record remains publishable.
        }
#endif
#elif defined(INFORMATION_BATTLE_WAR_IDENTITY)
        auto result=war_identity_wire::encode(pending,encoded,sizeof(encoded));
#elif defined(INFORMATION_BATTLE_TEMPLATE)
        auto result=template_wire::encode(pending,encoded,sizeof(encoded));
#elif defined(INFORMATION_BATTLE_NAVAL)
        auto result=naval_wire::encode(pending,encoded,sizeof(encoded));
#elif defined(INFORMATION_BATTLE_CONTEXT)
        auto result=context_wire::encode(pending,encoded,sizeof(encoded));
#else
        auto result=observation::encode(pending,encoded,sizeof(encoded));
#endif
        if (!result.succeeded() || !battle::fragment::prepare(fragment_plan,values(pending).sequence,encoded,result.written_bytes).succeeded()) {
            state.store(fault,std::memory_order_release);return;
        }
        encoded_bytes=result.written_bytes;fragment_index=0;
    }
    unsigned char fragment[4096]{};
    while (fragment_index<fragment_plan.fragment_count) {
        auto part=battle::fragment::encode(fragment_plan,encoded,encoded_bytes,fragment_index,fragment,sizeof(fragment));
        if (!part.succeeded()) {state.store(fault,std::memory_order_release);return;}
        // Only this frame thread produces and consumes this transport queue.
        auto pushed=drain.push(identity,fragment,part.written_bytes);
        if (!pushed.accepted()) return;
        ++fragment_index;
    }
    has_pending=false;
    (void)drain_fragments();
}
} // namespace information_battle_source

extern "C" void information_battle_entry_capture(void* combat,void* summary,void* result,
    void* original_return,uintptr_t original_rbx) noexcept {
    using namespace information_battle_source;
    if (state.load(std::memory_order_acquire)!=enabled) return;
    uint64_t next=sequence.load(std::memory_order_relaxed);
    do { if (next==UINT64_MAX) {long expected=enabled;state.compare_exchange_strong(expected,fault,std::memory_order_release);return;} }
        while (!sequence.compare_exchange_weak(next,next+1,std::memory_order_relaxed));
    ++next;
    if (GetCurrentThreadId()!=bound_thread) {foreign_thread.fetch_add(1);return;}
    if (!TryAcquireSRWLockExclusive(&capture_lock)) {
        busy.fetch_add(1);
#ifdef INFORMATION_BATTLE_GATE_TRACE
        trace_observation_drops.fetch_add(1);
#endif
        return;
    }
    if (state.load(std::memory_order_acquire)==enabled) {
        uintptr_t g=0;uint64_t p=0;int32_t date=0;
        if (!code_guard() || !context(g,p,date) || g!=game || p!=player || date<last_date) {
            guard_failed.fetch_add(1);state.store(source_changed,std::memory_order_release);
        } else if (count==kSlots) full.fetch_add(1);
        else {
#ifdef INFORMATION_BATTLE_TEMPLATE
            MessageScope* scope=nullptr;
            if (scope_depth && !suppressed_scopes && scopes[scope_depth-1].combat==reinterpret_cast<uintptr_t>(combat)
                && reinterpret_cast<uintptr_t>(original_return)==base+0x23a40d) {
                scope=&scopes[scope_depth-1];
                if (scope->has_record) {
                    scope->ambiguous=true; template_values(slots[scope->slot]).template_present=false;
                    template_values(slots[scope->slot]).template_source_kind=template_wire::kMessageSource; template_ambiguous.fetch_add(1);
#ifdef INFORMATION_BATTLE_NATIVE_TEXT
                    native_text::clear(slots[scope->slot].native_text); slots[scope->slot].native_text_invalid=true;
#endif
                }
            }
            const bool deferred=scope && !scope->has_record;
            const unsigned target_slot=(head+count)%kSlots;
            auto& target=slots[target_slot];
#ifdef INFORMATION_BATTLE_NATIVE_TEXT
            native_text::clear(target.native_text); target.native_text_invalid=false;target.line1_invalid=false;
#ifdef INFORMATION_BATTLE_NAME_SOURCES
            target.name_sources={};
#endif
#ifdef INFORMATION_BATTLE_DISPLAY_CONTEXT
            display_context_model::clear(target.display_context);
#endif
#ifdef INFORMATION_BATTLE_NAME_HANDOFF
            target.name_handoff={};target.name_handoff_invalid=false;
#endif
#endif
            template_values(target).template_present=false;
            template_values(target).template_source_kind=template_wire::kMessageSource;
#else
            auto& target=slots[(head+count)%kSlots];
#endif
            auto& observation=values(target);
            Reader reader;
            bool copied=battle::owned_result::capture(reader,base,reinterpret_cast<uintptr_t>(result),game+0x1dd0,observation.result)
                && battle::owned_summary::capture(reader,reinterpret_cast<uintptr_t>(summary),observation.summary);
            observation.known_router=reinterpret_cast<uintptr_t>(original_return)==base+0x23a40d;
#ifdef INFORMATION_BATTLE_CONTEXT
            // An unsupported or unstable context must not erase a valid raw
            // result. Mark it absent, retaining no previous slot's context.
            auto& context_record=contexts(target);
            context_record.context_present=false;
            context_record.context=battle::owned_context::Snapshot{};
#ifdef INFORMATION_BATTLE_END_STATE
            target.end_state={};target.end_state_present=false;
#endif
#ifdef INFORMATION_BATTLE_RETREAT
            target.retreat={};
#endif
#ifdef INFORMATION_BATTLE_NAVAL
            naval_values(target).naval_present=false;
            naval_values(target).naval=battle::owned_naval::Snapshot{};
#endif
            if (copied) {
#ifdef INFORMATION_BATTLE_END_STATE
                std::array<uintptr_t,2> end_sides_before{},end_sides_after{};
                const auto combat_address=reinterpret_cast<uintptr_t>(combat);
                const bool end_owner_bound=observation.known_router
                    && reader.read(combat_address+0x20u,
                        reinterpret_cast<unsigned char*>(end_sides_before.data()),sizeof(end_sides_before));
#endif
                context_record.context_present=battle::owned_context::capture(reader,base,game_image_size,
                    reinterpret_cast<uintptr_t>(combat),observation.known_router,
                    observation.known_router?original_rbx:0,player,context_record.context);
#ifdef INFORMATION_BATTLE_END_STATE
                if (end_owner_bound && context_record.context_present
                    && reader.read(combat_address+0x20u,
                        reinterpret_cast<unsigned char*>(end_sides_after.data()),sizeof(end_sides_after))
                    && end_sides_before==end_sides_after) {
                    target.end_state_present=battle::owned_end_state::capture(reader,combat_address,
                        context_record.context,end_sides_before,target.end_state);
                }
#endif
#ifdef INFORMATION_BATTLE_NAVAL
                if (context_record.context_present && context_record.context.kind==battle::owned_context::Kind::naval) {
                    naval_values(target).naval_present=battle::owned_naval::capture(reader,reinterpret_cast<uintptr_t>(combat),
                        reinterpret_cast<uintptr_t>(summary),observation.summary,naval_values(target).naval);
                }
#endif
            }
#else
            (void)combat; (void)original_rbx;
#endif
            uintptr_t after_game=0;uint64_t after_player=0;int32_t after_date=0;
            copied=copied && context(after_game,after_player,after_date) && after_game==game && after_player==player
                && after_date==date && observation.result.raw_date==date && code_guard()
                && state.load(std::memory_order_acquire)==enabled;
#ifdef INFORMATION_BATTLE_NAME_SOURCES
            if (copied && deferred && !scope->ambiguous && observation.known_router
                    && contexts(target).context_present
                    && (contexts(target).context.kind==battle::owned_context::Kind::land
                        || contexts(target).context.kind==battle::owned_context::Kind::naval)) {
                capture_name_sources(target,*scope,reinterpret_cast<uintptr_t>(combat),next,date);
#ifdef INFORMATION_BATTLE_OUTCOME_TEXT
                capture_outcome_text(target,*scope,reinterpret_cast<uintptr_t>(combat),next,date);
#ifdef INFORMATION_BATTLE_OUTCOME_TAIL
                capture_outcome_tail(target,*scope,reinterpret_cast<uintptr_t>(combat),next,date);
#endif
#endif
                copied=context(after_game,after_player,after_date) && after_game==game
                    && after_player==player && after_date==date && code_guard()
                    && state.load(std::memory_order_acquire)==enabled;
            }
#endif
#if defined(INFORMATION_BATTLE_NATIVE_TITLE_QUERY) && !defined(INFORMATION_BATTLE_NO_TITLE_QUERY_INVOKE)
            // The router owns this combat through the synchronous formatter
            // call. Generate only a title candidate into our own output; no
            // message builder, dispatch function, popup or game command runs.
            // A title failure never replaces a successfully copied base result.
            if (copied && deferred && !scope->ambiguous && observation.known_router
                && contexts(target).context_present
                && (contexts(target).context.kind==battle::owned_context::Kind::land
                    || contexts(target).context.kind==battle::owned_context::Kind::naval)) {
                title_query_candidates.fetch_add(1);
                NativeTitleInvoker invoker{date};
                title_query::Result title_result{};
                const bool title_copied=title_query::capture(reader,invoker,base,game_image_size,
                    reinterpret_cast<uintptr_t>(combat),
                    static_cast<uint32_t>(contexts(target).context.kind),
                    title_workspace,native_text_scratch,title_result,title_plugin_base ? 2u : 0u);
                if (title_result.attempted) title_query_attempted.fetch_add(1);
                if (title_result.destroyed) title_query_destroyed.fetch_add(1);
                if (title_copied && native_text::merge(target.native_text,native_text_scratch,target.native_text))
                    title_query_copied.fetch_add(1);
                else title_query_failed.fetch_add(1);
                native_text::clear(native_text_scratch);
                // Native formatting was the only extra operation. Recheck the
                // surrounding observation as well as the component's source
                // graph before publishing any part of this record.
                copied=context(after_game,after_player,after_date) && after_game==game
                    && after_player==player && after_date==date && code_guard()
                    && state.load(std::memory_order_acquire)==enabled;
            }
#endif
            if (!copied) copy_failed.fetch_add(1);
            else {observation.sequence=next;observation.thread=bound_thread;
#ifdef INFORMATION_BATTLE_WAR_IDENTITY
                auto register_war=observation_register_battle_war;
                war_values(target).identity=battle::war_binding::capture(reader,base,original_rbx,
                    observation.known_router,contexts(target).context,observation.result,
                    observation_creation,register_war);
#endif
#ifdef INFORMATION_BATTLE_CONTEXT
                if (contexts(target).context_present) context_copied.fetch_add(1);
                else context_copy_failed.fetch_add(1);
#endif
                last_date=date;
#ifdef INFORMATION_BATTLE_TEMPLATE
                slot_ready[target_slot]=!deferred;
                if (deferred) {
                    scope->has_record=true;scope->slot=target_slot;scope->sequence=next;
#ifdef INFORMATION_BATTLE_GATE_TRACE
                    sample_gate_inputs(*scope,gate_trace::Stage::context_capture);
#endif
                }
#ifdef INFORMATION_BATTLE_RETREAT
                retreat_bind_record_locked(reinterpret_cast<uintptr_t>(combat),target_slot,next,deferred);
#endif
                ++count;
#else
                ++count;
#endif
                accepted.fetch_add(1);}
        }
    }
    ReleaseSRWLockExclusive(&capture_lock);
}
#ifdef INFORMATION_BATTLE_TEMPLATE
#ifdef INFORMATION_BATTLE_RETREAT
extern "C" __attribute__((noinline)) void information_battle_outcome_retreat_hook(
    void* combat, void* winning, void* losing, unsigned char direction) {
    const DWORD before=GetLastError();
    const auto token=information_battle_source::begin_retreat_scope(combat,losing);
    SetLastError(before);
    reinterpret_cast<void(*)(void*,void*,void*,unsigned char)>(information_battle_outcome_retreat_original)(
        combat,winning,losing,direction);
    const DWORD after=GetLastError();
    information_battle_source::end_retreat_scope(token);
    SetLastError(after);
}
extern "C" __attribute__((noinline)) void information_battle_unit_retreat_hook(
    void* unit, unsigned char first, unsigned char second) {
    const auto return_pc=reinterpret_cast<uintptr_t>(__builtin_return_address(0));
    const DWORD before=GetLastError();
    information_battle_source::capture_retreat_unit(unit,return_pc);
    SetLastError(before);
    reinterpret_cast<void(*)(void*,unsigned char,unsigned char)>(information_battle_unit_retreat_original)(
        unit,first,second);
}
extern "C" __attribute__((noinline)) void information_battle_unit_removal_retreat_hook(
    void* combat, void* unit, unsigned char reason) {
    const auto return_pc=reinterpret_cast<uintptr_t>(__builtin_return_address(0));
    const DWORD before=GetLastError();
    const auto token=information_battle_source::begin_retreat_scope(combat,nullptr,unit,return_pc);
    SetLastError(before);
    reinterpret_cast<void(*)(void*,void*,unsigned char)>(information_battle_unit_removal_retreat_original)(
        combat,unit,reason);
    const DWORD after=GetLastError();
    information_battle_source::end_retreat_scope(token);
    SetLastError(after);
}
#endif
extern "C" __attribute__((noinline)) void information_battle_router_hook(void* combat, unsigned char direction) {
    const auto return_pc=reinterpret_cast<uintptr_t>(__builtin_return_address(0));
    const DWORD before=GetLastError();
    const auto token=information_battle_source::begin_scope(combat,return_pc);
    SetLastError(before);
    reinterpret_cast<void(*)(void*,unsigned char)>(information_battle_router_original)(combat,direction);
    const DWORD after=GetLastError();
    information_battle_source::end_scope(token);
    SetLastError(after);
}
extern "C" void information_battle_message_capture(void* message, void* callback,
    void* original_return,uintptr_t formatter_frame) noexcept {
    information_battle_source::capture_message(message,callback,
        reinterpret_cast<uintptr_t>(original_return),formatter_frame);
}
#endif
#ifdef INFORMATION_BATTLE_NATIVE_TEXT
#ifdef INFORMATION_BATTLE_NAME_HANDOFF
extern "C" void information_battle_name_handoff_capture(void* destination,void* key,void* value,
    void* original_return,uintptr_t original_rbp,uintptr_t entry_rsp) noexcept {
    information_battle_source::capture_name_handoff(destination,key,value,
        reinterpret_cast<uintptr_t>(original_return),original_rbp,entry_rsp);
}
#endif
extern "C" void information_battle_line1_capture(void* widget,void* text,
    unsigned char flag,void* original_return,uintptr_t original_rbp,uintptr_t original_r13) noexcept {
    (void)widget;
    information_battle_source::capture_line1(text,flag,reinterpret_cast<uintptr_t>(original_return),
        original_rbp,original_r13);
}
#endif
#ifdef INFORMATION_BATTLE_CONTAINER
extern "C" void information_battle_container_capture(void* container, void* original_return,
    uintptr_t formatter_frame) noexcept {
    information_battle_source::capture_container(container,reinterpret_cast<uintptr_t>(original_return),formatter_frame);
}
#endif
#ifdef INFORMATION_BATTLE_GATE_TRACE
extern "C" void information_battle_gate_marker_capture(void* original_return,uintptr_t formatter_frame) noexcept {
    information_battle_source::capture_gate_marker(reinterpret_cast<uintptr_t>(original_return),formatter_frame);
}
#endif
static bool information_battle_start(const wchar_t* path,uint64_t process_creation) {
    using namespace information_battle_source;
    if (state.load()!=cold || !process_creation || !path || wcslen(path)>=MAX_PATH) return false;
    creation=process_creation;wcscpy(directory,path);
    wchar_t dll[MAX_PATH]{},exe[MAX_PATH]{};DWORD size=GetModuleFileNameW(self_module,dll,MAX_PATH);
    DWORD exe_size=GetModuleFileNameW(nullptr,exe,MAX_PATH);
    if (!size || size>=MAX_PATH || !exe_size || exe_size>=MAX_PATH) return false;
    // Deny writes/deletes to both physical files while this source exists.
    // Hashing occurs after leases are opened, so the validated file cannot be
    // replaced between validation and capture. Leases live to process exit.
    exe_lease=CreateFileW(exe,GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr);
    dll_lease=CreateFileW(dll,GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr);
    if (exe_lease==INVALID_HANDLE_VALUE || dll_lease==INVALID_HANDLE_VALUE || !hash_file(dll,dll_sha) || !file_identity()
#ifdef INFORMATION_BATTLE_NATIVE_TITLE_QUERY
        || !title_query_plugin_identity()
#endif
        || !code_guard()
        || swprintf(request_path,MAX_PATH,L"%ls\\information-battle-control.request",directory)<0
        || swprintf(processing_path,MAX_PATH,L"%ls\\information-battle-control.processing",directory)<0
        || swprintf(log_path,MAX_PATH,L"%ls\\information-battle-raw.jsonl",directory)<0
#ifdef INFORMATION_BATTLE_GATE_TRACE
        || swprintf(trace_log_path,MAX_PATH,L"%ls\\information-battle-gate-trace.jsonl",directory)<0
        || GetFileAttributesW(trace_log_path)!=INVALID_FILE_ATTRIBUTES
#endif
        || GetFileAttributesW(request_path)!=INVALID_FILE_ATTRIBUTES
        || GetFileAttributesW(processing_path)!=INVALID_FILE_ATTRIBUTES) {close_startup_leases();transition(fault);return false;}
    if (status("","startup",true,"awaiting_process_bound_enable",false)) {transition(ready);return true;}
    close_startup_leases();transition(fault);return false;
}
static void information_battle_tick() {
    using namespace information_battle_source;
    if (state.load(std::memory_order_acquire)==cold) return;
    if (thread_changed || (bound_thread && GetCurrentThreadId()!=bound_thread)) {
        transition(source_changed);
        // A changed frame thread cannot take over the SPSC transport or
        // process control requests. Preserve pending records for diagnosis.
        if (heartbeat_status(false,"frame_thread_changed",GetTickCount64())
                ==HeartbeatPublicationResult::terminal_failure) transition(fault);
        return;
    }
    if (state.load()==enabled) {
        uintptr_t g=0;uint64_t p=0;int32_t date=0;
        DWORD64 row_base=0;
        auto row=source_row_address?RtlLookupFunctionEntry(base+kEntryRva+1,&row_base,nullptr):nullptr;
        const bool row_ok=!source_row_address || (reinterpret_cast<uintptr_t>(row)==source_row_address && row_base==base);
        if (thread_changed || GetCurrentThreadId()!=bound_thread || !context(g,p,date) || g!=game || p!=player || date<last_date || !code_guard() || !row_ok)
            transition(source_changed);
        else last_date=date;
    }
    uint64_t now=GetTickCount64();
    if (now-last_poll>=100) {last_poll=now;poll();}
    flush();
    const bool retry_due=heartbeat_publication_pending && now>=heartbeat_retry_next;
    const bool regular_due=!heartbeat_publication_pending && now-last_status>=1000;
    if (retry_due || regular_due) {
        if (regular_due) last_status=now;
        const long current=state.load(std::memory_order_acquire);
        const bool usable=current==ready || current==enabled || current==disabled;
        if (heartbeat_status(usable,usable?"observed":"terminal_source_state",now)
                ==HeartbeatPublicationResult::terminal_failure) transition(fault);
    }
}
