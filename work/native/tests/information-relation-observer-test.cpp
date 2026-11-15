#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "../information-relation-change.h"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <initializer_list>
#include <new>
#include <type_traits>

static constexpr uintptr_t base = UINT64_C(0x140000000);
static constexpr uintptr_t lifecycle_alliance_vtable_rva = 0x101000;
static constexpr uintptr_t lifecycle_royal_vtable_rva = 0x102000;
static constexpr uintptr_t lifecycle_military_access_vtable_rva = 0x103000;
static constexpr uintptr_t lifecycle_guarantee_vtable_rva = 0x104000;
static constexpr uintptr_t lifecycle_support_vtable_rva = 0x105000;
static constexpr uintptr_t lifecycle_vassalization_vtable_rva = 0x106000;
static constexpr uintptr_t kFakeGame = UINT64_C(0x21000000);
static constexpr unsigned kMaxActions = 4;
static constexpr unsigned kMaxPairs = 8;

static uint64_t observation_creation = UINT64_C(0x325001);
static DWORD frame_thread = 0;
static bool thread_changed = false;
static HANDLE log_file = INVALID_HANDLE_VALUE;
static unsigned read_calls = 0;
static unsigned protocol_capture_calls = 0;
static unsigned payload_decode_calls = 0;
static unsigned country_calls = 0;
static unsigned relation_read_calls = 0;
static unsigned support_role_calls = 0;
static unsigned subject_query_calls = 0;

enum class ActionFamily : unsigned char {
    other, alliance, royal_marriage, military_access, guarantee,
    support_independence, vassalization
};

struct AlliancePayload {
    uint64_t actor10 = 0;
    uint64_t recipient20 = 0;
    uint64_t state34 = 0;
    uint64_t variant38 = 0;
    ActionFamily family = ActionFamily::other;
};

struct ProtocolWrapperShape {
    bool identity = false;
    bool readable = false;
    uintptr_t action = 0;
    AlliancePayload payload{};
};

struct VassalQueryState {
    bool active = false;
    bool actor_is_overlord = false;
    bool actor_is_subject = false;
    char subject_type_json[131] = "null";
};

struct SupportRoleSnapshot {
    bool readable = false;
    bool actor_is_subject = false;
    bool recipient_is_subject = false;
};

struct PairFixture {
    bool occupied = false;
    uint64_t actor = 0;
    uint64_t recipient = 0;
    uintptr_t actor_country = 0;
    uintptr_t recipient_country = 0;
    uintptr_t actor_relations = 0;
    uintptr_t recipient_relations = 0;
    uintptr_t actor_owner = 0;
    uintptr_t recipient_owner = 0;
    uintptr_t actor_begin = 0;
    uintptr_t recipient_begin = 0;
    uintptr_t actor_record = 0;
    uintptr_t recipient_record = 0;
    bool guarantee_actor_before = false;
    bool guarantee_recipient_before = false;
    bool guarantee_actor_after = false;
    bool guarantee_recipient_after = false;
    bool identity_changes_actor_after = false;
    bool identity_changes_recipient_after = false;
    bool relation_readable_before = true;
    bool relation_readable_after = true;
    bool before_active = false;
    bool after_active = false;
    SupportRoleSnapshot support_before{true, false, false};
    SupportRoleSnapshot support_after{true, false, false};
    VassalQueryState subject_before{};
    VassalQueryState subject_after{};
};

struct ActionFixture {
    alignas(16) unsigned char wrapper[0x58 + sizeof(uintptr_t)]{};
    alignas(16) unsigned char action[0x100]{};
    uintptr_t table = 0;
    uintptr_t header_action = 0;
    uintptr_t protocol_action = 0;
    unsigned pair_index = 0;
    uint64_t actor = 0;
    uint64_t recipient = 0;
    uint64_t command_state = 0;
    uint64_t command_mode = 1;
    ActionFamily family = ActionFamily::other;
    bool header_readable = true;
    bool table_readable = true;
    bool identity = true;
    bool readable = true;
    bool payload_decodable = true;
    bool command_destroyed = false;
};

struct FixtureArena {
    int32_t date = 1000;
    bool after_phase = false;
    unsigned action_count = 0;
    unsigned pair_count = 0;
    ActionFixture actions[kMaxActions]{};
    PairFixture pairs[kMaxPairs]{};
};

static FixtureArena* arena = nullptr;
static wchar_t log_path[32768]{};
static unsigned checks = 0;
static unsigned failures = 0;
static unsigned scenarios = 0;

static constexpr unsigned char kGuaranteeProof[] = {
    0x48,0x8b,0x11,0x4c,0x8b,0x49,0x10,0x49,0xc1,0xe9,0x20,0x41,0x0f,0xbf,0xc1,
    0x48,0x8b,0x8a,0xa0,0x01,0x00,0x00,0x4c,0x63,0x82,0xac,0x01,0x00,0x00,0x49,
    0xc1,0xe0,0x04,0x4c,0x03,0xc1,0x49,0x3b,0xc8,0x74,0x14,0x0f,0x1f,0x80,0x00,
    0x00,0x00,0x00,0x39,0x01,0x74,0x0c,0x48,0x83,0xc1,0x10,0x49,0x3b,0xc8,0x75,
    0xf3,0x32,0xc0,0xc3,0x48,0x8b,0x41,0x08,0x48,0x85,0xc0,0x74,0xf4,0x48,0x8b,
    0x40,0x18,0x48,0xc1,0xe8,0x20,0x66,0x41,0x3b,0xc1,0x75,0xe6,0xb0,0x01,0xc3
};

#define CHECK(condition, message) do { \
    ++checks; \
    if (!(condition)) { \
        ++failures; \
        std::fprintf(stderr, "FAIL: %s\n", message); \
    } \
} while (0)

static ActionFamily family_for(information::relation_change::Kind kind) noexcept {
    using information::relation_change::Kind;
    switch (kind) {
    case Kind::alliance: return ActionFamily::alliance;
    case Kind::royal_marriage: return ActionFamily::royal_marriage;
    case Kind::military_access: return ActionFamily::military_access;
    case Kind::guarantee: return ActionFamily::guarantee;
    case Kind::support_independence: return ActionFamily::support_independence;
    case Kind::subject: return ActionFamily::vassalization;
    }
    return ActionFamily::other;
}

static uintptr_t table_for(information::relation_change::Kind kind) noexcept {
    using information::relation_change::Kind;
    switch (kind) {
    case Kind::alliance: return base + lifecycle_alliance_vtable_rva;
    case Kind::royal_marriage: return base + lifecycle_royal_vtable_rva;
    case Kind::military_access: return base + lifecycle_military_access_vtable_rva;
    case Kind::guarantee: return base + lifecycle_guarantee_vtable_rva;
    case Kind::support_independence: return base + lifecycle_support_vtable_rva;
    case Kind::subject: return base + lifecycle_vassalization_vtable_rva;
    }
    return 0;
}

static uint64_t fullref(const char* tag, uint32_t generation) noexcept {
    const uint32_t code = static_cast<unsigned char>(tag[0])
        | (static_cast<uint32_t>(static_cast<unsigned char>(tag[1])) << 8)
        | (static_cast<uint32_t>(static_cast<unsigned char>(tag[2])) << 16);
    return (static_cast<uint64_t>(generation) << 32) | code;
}

static PairFixture* find_pair(uint64_t actor, uint64_t recipient) noexcept {
    if (!arena) return nullptr;
    for (unsigned index = 0; index < arena->pair_count; ++index) {
        auto& pair = arena->pairs[index];
        if (pair.occupied && pair.actor == actor && pair.recipient == recipient)
            return &pair;
    }
    return nullptr;
}

static ActionFixture* find_action_by_wrapper(void* wrapper) noexcept {
    if (!arena) return nullptr;
    for (unsigned index = 0; index < arena->action_count; ++index) {
        auto& action = arena->actions[index];
        if (wrapper == action.wrapper) return &action;
    }
    return nullptr;
}

template<class Value>
static bool read(uintptr_t address, Value& value) noexcept {
    ++read_calls;
    if constexpr (std::is_same_v<Value, uintptr_t>) {
        if (!arena) return false;
        if (address == base + 0x233fe58) {
            value = kFakeGame;
            return true;
        }
        for (unsigned index = 0; index < arena->action_count; ++index) {
            auto& action = arena->actions[index];
            if (action.command_destroyed) continue;
            if (address == reinterpret_cast<uintptr_t>(action.wrapper) + 0x50) {
                if (!action.header_readable) return false;
                value = action.header_action;
                return true;
            }
            if (address == reinterpret_cast<uintptr_t>(action.action)) {
                if (!action.table_readable) return false;
                value = action.table;
                return true;
            }
        }
        for (unsigned index = 0; index < arena->pair_count; ++index) {
            auto& pair = arena->pairs[index];
            if (!pair.occupied) continue;
            const auto actor_slot = static_cast<uint16_t>((pair.actor >> 32) & 0xffffu);
            const auto recipient_slot = static_cast<uint16_t>((pair.recipient >> 32) & 0xffffu);
            const uintptr_t actor_row = pair.actor_relations
                + static_cast<uintptr_t>(recipient_slot) * 0x48;
            const uintptr_t recipient_row = pair.recipient_relations
                + static_cast<uintptr_t>(actor_slot) * 0x48;
            if (address == pair.actor_country + 0x1510) {
                value = pair.actor_relations;
                return true;
            }
            if (address == pair.recipient_country + 0x1510) {
                value = pair.recipient_relations;
                return true;
            }
            if (address == actor_row) {
                value = pair.actor_owner;
                return true;
            }
            if (address == actor_row + 0x10) {
                value = pair.recipient;
                return true;
            }
            if (address == recipient_row) {
                value = pair.recipient_owner;
                return true;
            }
            if (address == recipient_row + 0x10) {
                value = pair.actor;
                return true;
            }
            if (address == pair.actor_owner + 0x1a0) {
                value = pair.actor_begin;
                return true;
            }
            if (address == pair.recipient_owner + 0x1a0) {
                value = pair.recipient_begin;
                return true;
            }
            if (address == pair.actor_record + 0x18) {
                const bool granted = arena->after_phase
                    ? pair.guarantee_actor_after : pair.guarantee_actor_before;
                value = granted ? ((static_cast<uint64_t>(recipient_slot) << 32) | 0x415246u)
                    : ((static_cast<uint64_t>(actor_slot) << 32) | 0x415246u);
                return true;
            }
            if (address == pair.recipient_record + 0x18) {
                const bool granted = arena->after_phase
                    ? pair.guarantee_recipient_after : pair.guarantee_recipient_before;
                value = granted ? ((static_cast<uint64_t>(actor_slot) << 32) | 0x415246u)
                    : ((static_cast<uint64_t>(recipient_slot) << 32) | 0x415246u);
                return true;
            }
        }
    } else if constexpr (std::is_array_v<Value>
        && std::is_same_v<std::remove_extent_t<Value>, unsigned char>) {
        if (!arena) return false;
        constexpr size_t length = std::extent_v<Value>;
        if constexpr (length == sizeof(kGuaranteeProof)) {
            if (address == base + 0xa69e00) {
                std::memcpy(value, kGuaranteeProof, length);
                return true;
            }
        }
        if constexpr (length == 16) {
            for (unsigned index = 0; index < arena->pair_count; ++index) {
                auto& pair = arena->pairs[index];
                if (!pair.occupied) continue;
                if (address == pair.actor_begin) {
                    int32_t slot = static_cast<int16_t>((pair.recipient >> 32) & 0xffffu);
                    const uintptr_t record = (arena->after_phase
                        ? pair.guarantee_actor_after : pair.guarantee_actor_before)
                        ? pair.actor_record : 0;
                    std::memset(value, 0, length);
                    std::memcpy(value, &slot, sizeof(slot));
                    std::memcpy(value + 8, &record, sizeof(record));
                    return true;
                }
                if (address == pair.recipient_begin) {
                    int32_t slot = static_cast<int16_t>((pair.actor >> 32) & 0xffffu);
                    const uintptr_t record = (arena->after_phase
                        ? pair.guarantee_recipient_after : pair.guarantee_recipient_before)
                        ? pair.recipient_record : 0;
                    std::memset(value, 0, length);
                    std::memcpy(value, &slot, sizeof(slot));
                    std::memcpy(value + 8, &record, sizeof(record));
                    return true;
                }
            }
        }
    } else if constexpr (std::is_same_v<Value, int32_t>) {
        if (arena && address == kFakeGame + 0x1dd0) {
            value = arena->date;
            return true;
        }
        if (arena) {
            for (unsigned index = 0; index < arena->pair_count; ++index) {
                auto& pair = arena->pairs[index];
                if (address == pair.actor_owner + 0x1ac
                    || address == pair.recipient_owner + 0x1ac) {
                    value = 1;
                    return true;
                }
            }
        }
    } else if constexpr (std::is_integral_v<Value> && sizeof(Value) == sizeof(uint64_t)) {
        if (!arena) return false;
        for (unsigned index = 0; index < arena->pair_count; ++index) {
            auto& pair = arena->pairs[index];
            if (!pair.occupied) continue;
            const auto actor_slot = static_cast<uint16_t>((pair.actor >> 32) & 0xffffu);
            const auto recipient_slot = static_cast<uint16_t>((pair.recipient >> 32) & 0xffffu);
            const uintptr_t actor_row = pair.actor_relations
                + static_cast<uintptr_t>(recipient_slot) * 0x48;
            const uintptr_t recipient_row = pair.recipient_relations
                + static_cast<uintptr_t>(actor_slot) * 0x48;
            if (address == actor_row + 0x10) { value = pair.recipient; return true; }
            if (address == recipient_row + 0x10) { value = pair.actor; return true; }
            if (address == pair.actor_record + 0x18) {
                const bool granted = arena->after_phase
                    ? pair.guarantee_actor_after : pair.guarantee_actor_before;
                value = granted ? ((static_cast<uint64_t>(recipient_slot) << 32) | 0x415246u)
                    : ((static_cast<uint64_t>(actor_slot) << 32) | 0x415246u);
                return true;
            }
            if (address == pair.recipient_record + 0x18) {
                const bool granted = arena->after_phase
                    ? pair.guarantee_recipient_after : pair.guarantee_recipient_before;
                value = granted ? ((static_cast<uint64_t>(actor_slot) << 32) | 0x415246u)
                    : ((static_cast<uint64_t>(recipient_slot) << 32) | 0x415246u);
                return true;
            }
        }
    }
    return false;
}

static ProtocolWrapperShape protocol_capture(void* wrapper) noexcept {
    ++protocol_capture_calls;
    ProtocolWrapperShape result{};
    auto* action = find_action_by_wrapper(wrapper);
    if (!action || action->command_destroyed) return result;
    result.identity = action->identity;
    result.readable = action->readable;
    result.action = action->protocol_action;
    result.payload.actor10 = action->actor;
    result.payload.recipient20 = action->recipient;
    result.payload.state34 = action->command_state;
    result.payload.variant38 = action->command_mode;
    result.payload.family = action->family;
    return result;
}

static bool execution_payload(const AlliancePayload& source,
    AlliancePayload& destination) noexcept {
    ++payload_decode_calls;
    if (!arena) return false;
    // The canonical payload is already owned by the protocol capture. This
    // fixture deliberately does not dereference the command after capture.
    destination = source;
    return true;
}

static bool insult_query_country(uint64_t reference, uintptr_t& country) noexcept {
    ++country_calls;
    if (!arena) return false;
    for (unsigned index = 0; index < arena->pair_count; ++index) {
        auto& pair = arena->pairs[index];
        if (!pair.occupied) continue;
        if (reference == pair.actor) {
            country = pair.actor_country;
            if (arena->after_phase && pair.identity_changes_actor_after) country += 0x20;
            return country != 0;
        }
        if (reference == pair.recipient) {
            country = pair.recipient_country;
            if (arena->after_phase && pair.identity_changes_recipient_after) country += 0x20;
            return country != 0;
        }
    }
    return false;
}

static bool execution_read_after(const AlliancePayload& payload, bool& active) noexcept {
    ++relation_read_calls;
    auto* pair = find_pair(payload.actor10, payload.recipient20);
    if (!pair) return false;
    const bool readable = arena->after_phase
        ? pair->relation_readable_after : pair->relation_readable_before;
    if (!readable) return false;
    active = arena->after_phase ? pair->after_active : pair->before_active;
    return true;
}

static SupportRoleSnapshot support_role_capture(uint64_t actor,
    uint64_t recipient) noexcept {
    ++support_role_calls;
    auto* pair = find_pair(actor, recipient);
    if (!pair) return {};
    return arena->after_phase ? pair->support_after : pair->support_before;
}

static bool vassal_query_relation(uint64_t actor, uint64_t recipient,
    VassalQueryState& result) noexcept {
    ++subject_query_calls;
    auto* pair = find_pair(actor, recipient);
    if (!pair) return false;
    result = arena->after_phase ? pair->subject_after : pair->subject_before;
    return true;
}

#include "../information-relation-observer.inc"

namespace Observer = relation_change_observer;
using Kind = information::relation_change::Kind;

static PairFixture& add_pair(unsigned index, uint64_t actor, uint64_t recipient) {
    auto& pair = arena->pairs[index];
    pair = PairFixture{};
    pair.occupied = true;
    pair.actor = actor;
    pair.recipient = recipient;
    pair.actor_country = static_cast<uintptr_t>(UINT64_C(0x30000000) + index * 0x1000u);
    pair.recipient_country = static_cast<uintptr_t>(UINT64_C(0x30000100) + index * 0x1000u);
    const uintptr_t memory = static_cast<uintptr_t>(UINT64_C(0x40000000)
        + static_cast<uint64_t>(index) * UINT64_C(0x1000000));
    pair.actor_relations = memory + 0x100000;
    pair.recipient_relations = memory + 0x500000;
    pair.actor_owner = memory + 0x600000;
    pair.recipient_owner = memory + 0x610000;
    pair.actor_begin = memory + 0x620000;
    pair.recipient_begin = memory + 0x630000;
    pair.actor_record = memory + 0x640000;
    pair.recipient_record = memory + 0x650000;
    arena->pair_count = (index + 1 > arena->pair_count) ? index + 1 : arena->pair_count;
    return pair;
}

static ActionFixture& add_action(unsigned index, unsigned pair_index,
    Kind kind, uint64_t actor, uint64_t recipient) {
    auto& action = arena->actions[index];
    action = ActionFixture{};
    action.table = table_for(kind);
    action.header_action = reinterpret_cast<uintptr_t>(action.action);
    action.protocol_action = action.header_action;
    action.pair_index = pair_index;
    action.actor = actor;
    action.recipient = recipient;
    action.family = family_for(kind);
    arena->action_count = (index + 1 > arena->action_count) ? index + 1 : arena->action_count;
    return action;
}

static void set_subject(VassalQueryState& state, bool active,
    bool actor_is_overlord, bool actor_is_subject, const char* type) {
    state = VassalQueryState{};
    state.active = active;
    state.actor_is_overlord = actor_is_overlord;
    state.actor_is_subject = actor_is_subject;
    if (active) std::snprintf(state.subject_type_json,
        sizeof(state.subject_type_json), "\"%s\"", type);
}

static void set_relation_states(PairFixture& pair, Kind kind,
    bool before_active, bool after_active) {
    pair.before_active = before_active;
    pair.after_active = after_active;
    pair.support_before = SupportRoleSnapshot{true, false, false};
    pair.support_after = SupportRoleSnapshot{true, false, false};
    set_subject(pair.subject_before, false, false, false, "");
    set_subject(pair.subject_after, false, false, false, "");
    if (kind == Kind::support_independence) {
        pair.support_before = SupportRoleSnapshot{true, false, false};
        pair.support_after = SupportRoleSnapshot{true, false, false};
    }
    if (kind == Kind::guarantee) {
        pair.guarantee_actor_before = false;
        pair.guarantee_recipient_before = false;
        pair.guarantee_actor_after = after_active;
        pair.guarantee_recipient_after = false;
    }
    if (kind == Kind::subject) {
        set_subject(pair.subject_before, before_active, before_active, false,
            before_active ? "vassal" : "");
        set_subject(pair.subject_after, after_active, after_active, false,
            after_active ? "vassal" : "");
    }
}

static void reset_case() {
    arena->after_phase = false;
    arena->action_count = 0;
    arena->pair_count = 0;
    for (unsigned index = 0; index < kMaxActions; ++index)
        arena->actions[index] = ActionFixture{};
    for (unsigned index = 0; index < kMaxPairs; ++index)
        arena->pairs[index] = PairFixture{};
    arena->date = 1000;
    thread_changed = false;
    frame_thread = GetCurrentThreadId();
    Observer::installed.store(true);
    Observer::transport_fault.store(false);
    Observer::active_pair_count = 0;
    Observer::dropped = 0;
    CHECK(Observer::size == 0, "each new scenario starts with an empty queue");
}

static Observer::Pending begin(unsigned action_index) {
    return Observer::begin(arena->actions[action_index].wrapper);
}

static void flush_case() {
    Observer::flush();
    CHECK(Observer::size == 0, "bounded flush drains a small scenario queue");
    CHECK(Observer::dropped == 0, "written gap rows clear the current dropped counter");
}

static void test_each_kind_change_and_noop() {
    ++scenarios;
    constexpr Kind kinds[] = {Kind::alliance, Kind::royal_marriage,
        Kind::military_access, Kind::guarantee,
        Kind::support_independence, Kind::subject};
    for (unsigned index = 0; index < 6; ++index) {
        reset_case();
        const uint64_t actor = fullref("FRA", 0x100u + index);
        const uint64_t recipient = fullref("ENG", 0x200u + index);
        auto& pair = add_pair(0, actor, recipient);
        set_relation_states(pair, kinds[index], false, true);
        add_action(0, 0, kinds[index], actor, recipient);
        const unsigned queued_before = Observer::size;
        auto pending = begin(0);
        CHECK(pending.observed && pending.ready,
            "valid action captures a complete before snapshot");
        arena->after_phase = true;
        Observer::finish(pending);
        CHECK(Observer::size == queued_before + 1,
            "each of the six relation kinds emits an actual state change");
        CHECK(Observer::total_dropped == 0,
            "actual change in each relation kind does not create a gap");
        flush_case();

        reset_case();
        const uint64_t noop_actor = fullref("FRA", 0x300u + index);
        const uint64_t noop_recipient = fullref("ENG", 0x400u + index);
        auto& noop_pair = add_pair(0, noop_actor, noop_recipient);
        set_relation_states(noop_pair, kinds[index], false, false);
        add_action(0, 0, kinds[index], noop_actor, noop_recipient);
        auto noop = begin(0);
        CHECK(noop.observed && noop.ready, "valid no-op has readable before state");
        arena->after_phase = true;
        Observer::finish(noop);
        CHECK(Observer::size == 0, "no-op emits no relation event");
        CHECK(Observer::total_dropped == 0, "no-op is not reported as a capture gap");
        flush_case();
    }
}

static void test_direct_action_payload_and_wrapper_dedup() {
    ++scenarios;
    for (const auto kind : {Kind::support_independence, Kind::subject}) {
        reset_case();
        const auto actor = fullref("FRA", 122);
        const auto recipient = fullref("NOR", 170);
        auto& pair = add_pair(0, actor, recipient);
        set_relation_states(pair, kind, false, true);
        auto& action = add_action(0, 0, kind, actor, recipient);
        AlliancePayload payload{};
        payload.actor10 = actor;
        payload.recipient20 = recipient;
        payload.state34 = 2;
        payload.family = family_for(kind);
        const auto wrapper_reads = protocol_capture_calls;
        auto direct = Observer::begin_payload(action.header_action, payload);
        CHECK(direct.observed && direct.ready, "direct handler captures the canonical action payload");
        CHECK(protocol_capture_calls == wrapper_reads, "direct handler does not require a generic wrapper");
        arena->after_phase = true;
        Observer::finish(direct);
        CHECK(Observer::size == 1, "direct handler captures the complete relation mutation");
        flush_case();

        reset_case();
        auto& nested_pair = add_pair(0, actor, recipient);
        set_relation_states(nested_pair, kind, false, true);
        auto& nested_action = add_action(0, 0, kind, actor, recipient);
        auto outer = begin(0);
        auto inner = Observer::begin_payload(nested_action.header_action, payload);
        CHECK(outer.observed && !inner.observed, "wrapper and direct handler share pair deduplication");
        arena->after_phase = true;
        Observer::finish(inner);
        Observer::finish(outer);
        CHECK(Observer::size == 1, "nested direct handler produces one notification");
        flush_case();
    }
}

static void test_fra_recipient_and_non_fra_exclusion() {
    ++scenarios;
    reset_case();
    const uint64_t actor = fullref("ENG", 0x510u);
    const uint64_t recipient = fullref("FRA", 0x511u);
    auto& pair = add_pair(0, actor, recipient);
    set_relation_states(pair, Kind::alliance, false, true);
    add_action(0, 0, Kind::alliance, actor, recipient);
    auto pending = begin(0);
    CHECK(pending.observed && pending.ready,
        "FRA is accepted when it is the command recipient");
    arena->after_phase = true;
    Observer::finish(pending);
    CHECK(Observer::size == 1, "recipient-side FRA change is queued");
    flush_case();

    reset_case();
    const uint64_t non_fra_actor = fullref("ENG", 0x520u);
    const uint64_t non_fra_recipient = fullref("SPA", 0x521u);
    auto& non_fra_pair = add_pair(0, non_fra_actor, non_fra_recipient);
    set_relation_states(non_fra_pair, Kind::alliance, false, true);
    add_action(0, 0, Kind::alliance, non_fra_actor, non_fra_recipient);
    auto excluded = begin(0);
    CHECK(!excluded.observed && Observer::size == 0,
        "commands with neither endpoint FRA are excluded");
    CHECK(Observer::total_dropped == 0,
        "out-of-scope non-FRA command is not a capture gap");
    flush_case();
}

static void test_subject_type_role_and_support_unreadable() {
    ++scenarios;
    reset_case();
    const uint64_t actor = fullref("FRA", 0x610u);
    const uint64_t recipient = fullref("ENG", 0x611u);
    auto& pair = add_pair(0, actor, recipient);
    pair.before_active = true;
    pair.after_active = true;
    set_subject(pair.subject_before, true, true, false, "vassal");
    set_subject(pair.subject_after, true, false, true, "personal_union");
    add_action(0, 0, Kind::subject, actor, recipient);
    auto pending = begin(0);
    CHECK(pending.observed && pending.ready,
        "active subject relation captures roles and type before execution");
    arena->after_phase = true;
    Observer::finish(pending);
    CHECK(Observer::size == 1,
        "subject type and endpoint role change is emitted with active unchanged");
    flush_case();

    reset_case();
    const uint64_t support_actor = fullref("FRA", 0x620u);
    const uint64_t support_recipient = fullref("ENG", 0x621u);
    auto& support_pair = add_pair(0, support_actor, support_recipient);
    support_pair.before_active = true;
    support_pair.after_active = true;
    support_pair.support_before = SupportRoleSnapshot{true, false, false};
    support_pair.support_after = SupportRoleSnapshot{true, true, false};
    add_action(0, 0, Kind::support_independence, support_actor, support_recipient);
    auto support = begin(0);
    CHECK(support.observed && support.ready,
        "support relation captures its role snapshot before execution");
    const LONG dropped_before = Observer::total_dropped;
    arena->after_phase = true;
    Observer::finish(support);
    CHECK(Observer::size == 0,
        "support role drift with active unchanged is not emitted as a relation change");
    CHECK(Observer::total_dropped == dropped_before + 1,
        "support role drift is retained as unreadable gap");
    flush_case();
}

static void test_guarantee_direction_change_while_active() {
    ++scenarios;
    reset_case();
    const uint64_t actor = fullref("FRA", 0x630u);
    const uint64_t recipient = fullref("ENG", 0x631u);
    auto& pair = add_pair(0, actor, recipient);
    pair.before_active = true;
    pair.after_active = true;
    pair.guarantee_actor_before = true;
    pair.guarantee_recipient_before = false;
    pair.guarantee_actor_after = false;
    pair.guarantee_recipient_after = true;
    add_action(0, 0, Kind::guarantee, actor, recipient);
    auto pending = begin(0);
    CHECK(pending.observed && pending.ready,
        "guarantee fixture reads both directed associations before execution");
    CHECK(pending.value.before.active
            && pending.value.before.guarantee_actor_grants
            && !pending.value.before.guarantee_recipient_grants,
        "before snapshot records actor-to-recipient grant direction");
    arena->after_phase = true;
    Observer::finish(pending);
    CHECK(Observer::size == 1
            && Observer::events[(Observer::head + Observer::size - 1) % Observer::kCapacity]
                .value.after.guarantee_recipient_grants,
        "direction swap is emitted even though guarantee remains active");
    flush_case();
}

static void test_invalid_family_table_action_and_header() {
    ++scenarios;
    reset_case();
    const uint64_t actor = fullref("FRA", 0x710u);
    const uint64_t recipient = fullref("ENG", 0x711u);
    auto& pair = add_pair(0, actor, recipient);
    set_relation_states(pair, Kind::alliance, false, true);
    auto& action = add_action(0, 0, Kind::alliance, actor, recipient);
    const unsigned reads_before = relation_read_calls;
    const LONG drops_before = Observer::total_dropped;

    action.table = base + 0x7fff;
    auto wrong_table = begin(0);
    Observer::finish(wrong_table);
    CHECK(!wrong_table.observed && relation_read_calls == reads_before,
        "unknown action table is rejected before relation reads");

    action.table = table_for(Kind::alliance);
    action.family = ActionFamily::royal_marriage;
    auto wrong_family = begin(0);
    Observer::finish(wrong_family);
    CHECK(!wrong_family.observed && relation_read_calls == reads_before,
        "table and canonical action family must match");
    action.family = ActionFamily::alliance;

    action.header_readable = false;
    auto bad_header = begin(0);
    Observer::finish(bad_header);
    CHECK(!bad_header.observed && relation_read_calls == reads_before,
        "unreadable wrapper action header is rejected");
    action.header_readable = true;

    action.protocol_action += 8;
    auto mismatched_action = begin(0);
    Observer::finish(mismatched_action);
    CHECK(!mismatched_action.observed && relation_read_calls == reads_before,
        "protocol payload must identify the same action as the wrapper header");
    action.protocol_action = action.header_action;

    action.identity = false;
    auto bad_identity = begin(0);
    Observer::finish(bad_identity);
    CHECK(!bad_identity.observed && relation_read_calls == reads_before,
        "noncanonical wrapper identity is rejected");
    action.identity = true;

    action.readable = false;
    auto unreadable_payload = begin(0);
    Observer::finish(unreadable_payload);
    CHECK(!unreadable_payload.observed && relation_read_calls == reads_before,
        "unreadable canonical protocol payload is rejected");
    action.readable = true;

    auto invalid_pointer = Observer::begin(reinterpret_cast<void*>(UINT64_C(0x1000)));
    Observer::finish(invalid_pointer);
    CHECK(!invalid_pointer.observed && relation_read_calls == reads_before,
        "low invalid wrapper address is rejected before memory access");
    CHECK(Observer::total_dropped == drops_before,
        "identity and structure filters do not create capture gaps");
    flush_case();
}

static void test_date_thread_and_identity_gates() {
    ++scenarios;
    reset_case();
    const uint64_t actor = fullref("FRA", 0x810u);
    const uint64_t recipient = fullref("ENG", 0x811u);
    auto& pair = add_pair(0, actor, recipient);
    set_relation_states(pair, Kind::alliance, false, true);
    add_action(0, 0, Kind::alliance, actor, recipient);
    auto crossing = begin(0);
    CHECK(crossing.observed && crossing.ready, "date-crossing fixture begins validly");
    arena->date += 1;
    arena->after_phase = true;
    const LONG before_crossing_drop = Observer::total_dropped;
    Observer::finish(crossing);
    CHECK(Observer::size == 0 && Observer::total_dropped == before_crossing_drop + 1,
        "a command that crosses the observed day is reported as a gap");
    flush_case();

    reset_case();
    auto& thread_pair = add_pair(0, fullref("FRA", 0x820u), fullref("ENG", 0x821u));
    set_relation_states(thread_pair, Kind::alliance, false, true);
    add_action(0, 0, Kind::alliance, thread_pair.actor, thread_pair.recipient);
    thread_changed = true;
    const unsigned captures_before = protocol_capture_calls;
    const LONG before_thread_drop = Observer::total_dropped;
    auto wrong_thread = begin(0);
    Observer::finish(wrong_thread);
    CHECK(!wrong_thread.observed && protocol_capture_calls == captures_before,
        "wrong-thread frame is rejected before protocol capture");
    CHECK(Observer::total_dropped == before_thread_drop + 1,
        "wrong-thread candidate creates a capture gap");
    flush_case();

    reset_case();
    auto& finish_thread_pair = add_pair(0, fullref("FRA", 0x830u), fullref("ENG", 0x831u));
    set_relation_states(finish_thread_pair, Kind::alliance, false, true);
    add_action(0, 0, Kind::alliance, finish_thread_pair.actor, finish_thread_pair.recipient);
    auto finish_wrong_thread = begin(0);
    CHECK(finish_wrong_thread.observed, "finish-thread fixture begins on its owner thread");
    frame_thread = GetCurrentThreadId() + 1;
    arena->after_phase = true;
    const LONG before_finish_thread_drop = Observer::total_dropped;
    Observer::finish(finish_wrong_thread);
    CHECK(Observer::size == 0
            && Observer::total_dropped == before_finish_thread_drop + 1,
        "frame-thread mismatch at command return produces a gap");
    flush_case();

    reset_case();
    auto& identity_pair = add_pair(0, fullref("FRA", 0x840u), fullref("ENG", 0x841u));
    set_relation_states(identity_pair, Kind::alliance, false, true);
    identity_pair.identity_changes_actor_after = true;
    add_action(0, 0, Kind::alliance, identity_pair.actor, identity_pair.recipient);
    auto identity_change = begin(0);
    CHECK(identity_change.observed && identity_change.ready,
        "identity-change fixture captures original country pointers");
    arena->after_phase = true;
    const LONG before_identity_drop = Observer::total_dropped;
    Observer::finish(identity_change);
    CHECK(Observer::size == 0
            && Observer::total_dropped == before_identity_drop + 1,
        "changed canonical country identity is rejected after execution");
    flush_case();
}

static void test_owned_payload_after_command_destruction() {
    ++scenarios;
    reset_case();
    const uint64_t actor = fullref("FRA", 0x910u);
    const uint64_t recipient = fullref("ENG", 0x911u);
    auto& pair = add_pair(0, actor, recipient);
    set_relation_states(pair, Kind::alliance, false, true);
    auto& action = add_action(0, 0, Kind::alliance, actor, recipient);
    action.command_state = 2;
    action.command_mode = 1;
    auto pending = begin(0);
    CHECK(pending.observed && pending.ready,
        "owned-payload fixture captures before destroying the command");
    const unsigned protocol_calls = protocol_capture_calls;
    const unsigned payload_calls = payload_decode_calls;
    action.command_destroyed = true;
    std::memset(action.wrapper, 0, sizeof(action.wrapper));
    std::memset(action.action, 0, sizeof(action.action));
    arena->after_phase = true;
    Observer::finish(pending);
    CHECK(Observer::size == 1,
        "finish can observe and queue a change after source command destruction");
    CHECK(protocol_capture_calls == protocol_calls
            && payload_decode_calls == payload_calls,
        "finish uses the owned payload and never recaptures destroyed command memory");
    CHECK(relation_read_calls >= 2,
        "before and after actual relation states were read through the owned payload");
    flush_case();
}

static void test_nested_pair_dedup_and_distinct_pair_retention() {
    ++scenarios;
    reset_case();
    const uint64_t actor = fullref("FRA", 0xa10u);
    const uint64_t recipient = fullref("ENG", 0xa11u);
    auto& pair = add_pair(0, actor, recipient);
    set_relation_states(pair, Kind::alliance, false, true);
    add_action(0, 0, Kind::alliance, actor, recipient);
    add_action(1, 0, Kind::alliance, actor, recipient);
    auto outer = begin(0);
    auto inner = begin(1);
    CHECK(outer.observed && outer.ready && !inner.observed,
        "nested command for the same kind and pair is suppressed");
    CHECK(Observer::active_pair_count == 1,
        "duplicate nested command does not add another active-pair slot");
    arena->after_phase = true;
    Observer::finish(inner);
    Observer::finish(outer);
    CHECK(Observer::size == 1,
        "same-pair nested command emits only the outer net change");
    flush_case();

    reset_case();
    auto& transient_pair = add_pair(0, fullref("FRA", 0xa20u), fullref("ENG", 0xa21u));
    set_relation_states(transient_pair, Kind::alliance, false, true);
    add_action(0, 0, Kind::alliance, transient_pair.actor, transient_pair.recipient);
    add_action(1, 0, Kind::alliance, transient_pair.actor, transient_pair.recipient);
    const LONG transient_drop_start = Observer::total_dropped;
    auto transient_outer = begin(0);
    auto transient_inner = begin(1);
    arena->after_phase = true;
    Observer::finish(transient_inner);
    arena->after_phase = false;
    Observer::finish(transient_outer);
    CHECK(Observer::size == 0,
        "same-pair nested transient change that reverts is not emitted");
    CHECK(Observer::total_dropped == transient_drop_start,
        "reverted nested change is a no-op rather than a gap");
    flush_case();

    reset_case();
    auto& first = add_pair(0, fullref("FRA", 0xa30u), fullref("ENG", 0xa31u));
    auto& second = add_pair(1, fullref("FRA", 0xa32u), fullref("SPA", 0xa33u));
    set_relation_states(first, Kind::alliance, false, true);
    set_relation_states(second, Kind::alliance, false, true);
    add_action(0, 0, Kind::alliance, first.actor, first.recipient);
    add_action(1, 1, Kind::alliance, second.actor, second.recipient);
    auto first_pending = begin(0);
    auto second_pending = begin(1);
    CHECK(first_pending.observed && second_pending.observed
            && Observer::active_pair_count == 2,
        "different nested pairs both retain independent observations");
    arena->after_phase = true;
    Observer::finish(second_pending);
    Observer::finish(first_pending);
    CHECK(Observer::size == 2,
        "both distinct nested-pair changes are queued");
    CHECK(Observer::active_pair_count == 0,
        "nested pair stack is released after LIFO finishes");
    flush_case();
}

static void test_capacity_per_frame_overflow_and_jsonl() {
    ++scenarios;
    reset_case();
    const LONG drop_start = Observer::total_dropped;
    for (unsigned index = 0; index < 65; ++index) {
        const uint64_t actor = (index & 1u)
            ? fullref("ENG", 0xb00u + index) : fullref("FRA", 0xb00u + index);
        const uint64_t recipient = (index & 1u)
            ? fullref("FRA", 0xc00u + index) : fullref("ENG", 0xc00u + index);
        auto& pair = add_pair(0, actor, recipient);
        set_relation_states(pair, Kind::alliance, false, true);
        add_action(0, 0, Kind::alliance, actor, recipient);
        arena->after_phase = false;
        auto pending = begin(0);
        CHECK(pending.observed && pending.ready,
            "bounded queue input has a valid relation before state");
        arena->after_phase = true;
        Observer::finish(pending);
        CHECK(Observer::active_pair_count == 0,
            "each queued command releases its active-pair slot");
    }
    CHECK(Observer::size == Observer::kCapacity,
        "native relation queue is bounded at 64 events");
    CHECK(Observer::total_dropped == drop_start + 1 && Observer::dropped == 1,
        "one event beyond capacity increments the capture gap count");

    Observer::flush();
    CHECK(Observer::size == 32,
        "one frame flush writes no more than 32 relation events");
    CHECK(Observer::dropped == 0,
        "overflow gap is serialized after the first bounded batch");
    Observer::flush();
    CHECK(Observer::size == 0,
        "second frame flush writes the remaining 32 events");
    Observer::flush();
}

static void test_write_fault_retains_head_and_health() {
    ++scenarios;
    reset_case();
    auto& pair = add_pair(0, fullref("FRA", 0xd10u), fullref("ENG", 0xd11u));
    set_relation_states(pair, Kind::alliance, false, true);
    add_action(0, 0, Kind::alliance, pair.actor, pair.recipient);
    auto pending = begin(0);
    CHECK(pending.observed && pending.ready,
        "write-fault fixture queues a valid event");
    arena->after_phase = true;
    Observer::finish(pending);
    CHECK(Observer::size == 1, "write-fault fixture has one queued head");
    const unsigned original_head = Observer::head;

    CHECK(CloseHandle(log_file) != FALSE, "close writable fixture log before fault test");
    log_file = CreateFileW(log_path, GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, nullptr);
    CHECK(log_file != INVALID_HANDLE_VALUE,
        "reopen fixture log with a read-only handle");
    Observer::flush();
    CHECK(Observer::transport_fault.load(),
        "failed append latches transport fault");
    CHECK(Observer::size == 1 && Observer::head == original_head,
        "write failure leaves the queue head and event retained");
    Observer::flush();
    CHECK(Observer::size == 1 && Observer::head == original_head,
        "latched transport fault does not consume or retry the queue head");

    char health[640] = "{\"event\":\"fixture_health\"}";
    Observer::append_health(health, sizeof(health));
    CHECK(std::strstr(health, "\"installed\":true") != nullptr
            && std::strstr(health, "\"transport_fault\":true") != nullptr,
        "health exposes installed state and latched transport fault");
    CHECK(std::strstr(health, "\"queue_readable\":true") != nullptr
            && std::strstr(health, "\"queued\":1") != nullptr,
        "health exposes readable queue and the retained head");
    std::printf("HEALTH_JSON:%s", health);
}

int main() {
    static_assert(sizeof(uintptr_t) == 8, "EU4 relation fixture requires x64");
    auto* memory = VirtualAlloc(nullptr, sizeof(FixtureArena),
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!memory) return 2;
    arena = new (memory) FixtureArena{};
    const DWORD path_chars = GetEnvironmentVariableW(L"INFORMATION_RELATION_FIXTURE_LOG",
        log_path, static_cast<DWORD>(sizeof(log_path) / sizeof(log_path[0])));
    if (!path_chars || path_chars >= sizeof(log_path) / sizeof(log_path[0])) return 3;
    log_file = CreateFileW(log_path, GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL, nullptr);
    if (log_file == INVALID_HANDLE_VALUE) return 4;

    test_each_kind_change_and_noop();
    test_direct_action_payload_and_wrapper_dedup();
    test_fra_recipient_and_non_fra_exclusion();
    test_subject_type_role_and_support_unreadable();
    test_guarantee_direction_change_while_active();
    test_invalid_family_table_action_and_header();
    test_date_thread_and_identity_gates();
    test_owned_payload_after_command_destruction();
    test_nested_pair_dedup_and_distinct_pair_retention();
    test_capacity_per_frame_overflow_and_jsonl();
    test_write_fault_retains_head_and_health();

    Observer::installed.store(false);
    CHECK(CloseHandle(log_file) != FALSE, "close final fixture log handle");
    log_file = INVALID_HANDLE_VALUE;
    arena->~FixtureArena();
    CHECK(VirtualFree(memory, 0, MEM_RELEASE) != FALSE,
        "release bounded fixture arena");
    std::printf("information relation production observer: %s (%u checks, %u scenarios)\n",
        failures ? "FAIL" : "PASS", checks, scenarios);
    return failures ? 1 : 0;
}
