#ifndef INFORMATION_BATTLE_GATE_TRACE_H
#define INFORMATION_BATTLE_GATE_TRACE_H

// Private, value-only diagnostics. This is not a B04 field or a new battle
// transport version. No native function, allocation, file or engine state is
// touched by this component. A zero entry count is usable only with a complete
// scope and zero observation drops; it is never a claim about other UI paths.
#include "information-battle-owned-gate-inputs.h"
#include <array>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <limits>
#include <type_traits>

namespace information::battle::gate_trace {
namespace inputs = owned_gate_inputs;
constexpr std::size_t kMaxJsonBytes = 8192;
enum class Stage : unsigned { context_capture, passed_marker, formatter_cleanup, scope_exit, count };
enum Reject : std::uint32_t {
    wrong_return = 1u, wrong_callback = 2u, invalid_frame = 4u,
    invalid_caller = 8u, invalid_owner = 16u, no_record = 32u,
    ambiguous_scope = 64u, ready_slot = 128u, wrong_sequence = 256u,
    missing_context = 512u, wrong_kind = 1024u, duplicate_message = 2048u,
    template_copy_failed = 4096u, metadata_copy_failed = 8192u,
    line1_filter_rejected = 16384u,
};
struct Snapshot final {
    std::array<inputs::Snapshot, static_cast<unsigned>(Stage::count)> samples{};
    std::uint32_t sample_mask = 0;
    std::uint32_t passed_marker_candidates = 0, passed_marker_accepted = 0;
    std::uint32_t message_entries = 0, message_copy_attempts = 0;
    std::uint32_t cleanup_entries = 0, line1_entries = 0;
    std::uint32_t marker_reject_mask = 0, message_reject_mask = 0, line1_reject_mask = 0, cleanup_reject_mask = 0;
    std::uint32_t last_marker_return_rva = 0, last_message_return_rva = 0;
    std::uint32_t router_return_rva = 0;
    std::uint64_t observation_drops = 0;
    bool scope_completed = false, scope_ambiguous = false, counter_overflow = false;
    bool scope_guards_before = false, scope_guards_after = false;
};
struct Identity final {
    std::uint32_t pid = 0;
    std::uint64_t creation = 0, installation = 0, generation = 0, sequence = 0;
    std::int32_t native_date = 0;
    inputs::Kind kind = static_cast<inputs::Kind>(0);
    std::array<char,65> dll_sha256{};
};
static_assert(std::is_trivially_copyable<Snapshot>::value, "trace stays owned and pointer-free");
static_assert(std::is_trivially_copyable<Identity>::value, "trace identity stays owned");
inline void increment(std::uint32_t& value, Snapshot& trace) noexcept {
    if (value == (std::numeric_limits<std::uint32_t>::max)()) trace.counter_overflow = true;
    else ++value;
}
inline bool observation_complete(const Snapshot& value) noexcept {
    return value.scope_completed && !value.scope_ambiguous && !value.counter_overflow
        && value.observation_drops == 0;
}
namespace detail {
inline bool overlaps(const void* a, std::size_t as, const void* b, std::size_t bs) noexcept {
    const auto x=reinterpret_cast<std::uintptr_t>(a), y=reinterpret_cast<std::uintptr_t>(b);
    const auto max=(std::numeric_limits<std::uintptr_t>::max)();
    return as>max-x || bs>max-y || (x<y+bs && y<x+as);
}
struct Json final {
    char* output; std::size_t capacity, used=0; bool ok=true;
    void append(const char* format, ...) noexcept {
        if (!ok || used>=capacity) {ok=false;return;}
        va_list args;va_start(args,format);
        const int n=std::vsnprintf(output+used,capacity-used,format,args);
        va_end(args);
        if (n<0 || static_cast<std::size_t>(n)>=capacity-used) {ok=false;return;}
        used+=static_cast<std::size_t>(n);
    }
};
inline const char* boolean(bool value) noexcept {return value?"true":"false";}
inline void sample(Json& json,const inputs::Snapshot& value) noexcept {
    char raw[33]{};constexpr char hex[]="0123456789abcdef";
    for (unsigned i=0;i<16;++i) {raw[i*2]=hex[value.current_country_raw[i]>>4];raw[i*2+1]=hex[value.current_country_raw[i]&15];}
    json.append("{\"status\":%u,\"failure\":%u,\"kind\":%u,\"current_country_state\":%u,\"current_country_raw\":\"%s\","
        "\"mode\":%u,\"alternate_flag\":%u,\"default_ref_state\":%u,\"default_ref\":\"%016llx\","
        "\"alternate_ref_state\":%u,\"alternate_ref\":\"%016llx\",\"selected_ref_state\":%u,\"selected_ref\":\"%016llx\","
        "\"land_enable_state\":%u,\"land_enable_raw\":%u,\"registry_state\":%u,\"slot_state\":%u,\"combat_state\":%u,"
        "\"equals_current_combat_known\":%s,\"equals_current_combat\":%s,\"ui_override_known\":%s,\"ui_override_value\":%s,"
        "\"read_calls\":%u,\"read_bytes\":%u}",
        static_cast<unsigned>(value.status),static_cast<unsigned>(value.failure),static_cast<unsigned>(value.kind),
        static_cast<unsigned>(value.current_country_state),raw,value.mode,value.alternate_flag,
        static_cast<unsigned>(value.default_ref_state),static_cast<unsigned long long>(value.default_ref),
        static_cast<unsigned>(value.alternate_ref_state),static_cast<unsigned long long>(value.alternate_ref),
        static_cast<unsigned>(value.selected_ref_state),static_cast<unsigned long long>(value.selected_ref),
        static_cast<unsigned>(value.land_enable_state),value.land_enable_raw,static_cast<unsigned>(value.registry_state),
        static_cast<unsigned>(value.slot_state),static_cast<unsigned>(value.combat_state),boolean(value.equals_current_combat_known),
        boolean(value.equals_current_combat),boolean(value.ui_override_known),boolean(value.ui_override_value),value.read_calls,value.read_bytes);
}
} // namespace detail
inline bool encode_jsonl(const Identity& identity,const Snapshot& trace,char* output,
    std::size_t capacity,std::size_t& written) noexcept {
    if (detail::overlaps(&written,sizeof(written),&identity,sizeof(identity))
        || detail::overlaps(&written,sizeof(written),&trace,sizeof(trace))
        || (output && detail::overlaps(&written,sizeof(written),output,capacity))) return false;
    written=0;
    if (!output || capacity==0 || capacity>kMaxJsonBytes
        || detail::overlaps(output,capacity,&identity,sizeof(identity))
        || detail::overlaps(output,capacity,&trace,sizeof(trace))
        || !identity.pid || !identity.creation || !identity.installation || !identity.generation || !identity.sequence
        || (static_cast<unsigned>(identity.kind)>2u)
        || identity.dll_sha256[64]!=0 || (trace.sample_mask&~15u)) return false;
    for (unsigned i=0;i<64;++i) {
        const char c=identity.dll_sha256[i];
        if (!((c>='0'&&c<='9')||(c>='a'&&c<='f'))) return false;
    }
    detail::Json json{output,capacity};
    json.append("{\"schema\":\"EU4-BATTLE-GATE-TRACE/1\",\"pid\":%u,\"creation_filetime\":\"%llu\","
        "\"installation\":\"%016llx\",\"generation\":\"%016llx\",\"sequence\":\"%llu\",\"native_date\":%d,"
        "\"kind\":\"%s\",\"dll_sha256\":\"%s\",\"scope_completed\":%s,\"scope_ambiguous\":%s,"
        "\"counter_overflow\":%s,\"observation_drops\":\"%llu\",\"observation_complete\":%s,"
        "\"scope_guards_before\":%s,\"scope_guards_after\":%s,"
        "\"passed_marker_candidates\":%u,\"passed_marker_accepted\":%u,\"message_entries\":%u,\"message_copy_attempts\":%u,"
        "\"cleanup_entries\":%u,\"line1_entries\":%u,\"marker_reject_mask\":%u,\"message_reject_mask\":%u,"
        "\"line1_reject_mask\":%u,\"cleanup_reject_mask\":%u,\"last_marker_return_rva\":%u,\"last_message_return_rva\":%u,"
        "\"router_return_rva\":%u,\"sample_mask\":%u,\"samples\":[",
        identity.pid,static_cast<unsigned long long>(identity.creation),static_cast<unsigned long long>(identity.installation),
        static_cast<unsigned long long>(identity.generation),static_cast<unsigned long long>(identity.sequence),identity.native_date,
        identity.kind==inputs::Kind::land?"land":identity.kind==inputs::Kind::naval?"naval":"unknown",
        identity.dll_sha256.data(),detail::boolean(trace.scope_completed),
        detail::boolean(trace.scope_ambiguous),detail::boolean(trace.counter_overflow),static_cast<unsigned long long>(trace.observation_drops),
        detail::boolean(observation_complete(trace)),detail::boolean(trace.scope_guards_before),detail::boolean(trace.scope_guards_after),
        trace.passed_marker_candidates,trace.passed_marker_accepted,trace.message_entries,
        trace.message_copy_attempts,trace.cleanup_entries,trace.line1_entries,trace.marker_reject_mask,trace.message_reject_mask,
        trace.line1_reject_mask,trace.cleanup_reject_mask,trace.last_marker_return_rva,trace.last_message_return_rva,
        trace.router_return_rva,trace.sample_mask);
    for (unsigned i=0;i<static_cast<unsigned>(Stage::count);++i) {
        if (i) json.append(",");
        if (trace.sample_mask&(1u<<i)) detail::sample(json,trace.samples[i]); else json.append("null");
    }
    json.append("]}\n");
    if (!json.ok) return false;
    written=json.used;return true;
}
} // namespace information::battle::gate_trace
#endif
