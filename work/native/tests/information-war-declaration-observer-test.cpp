#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "../information-war-declaration.h"
#include "../information-war-registry.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <initializer_list>
#include <new>
#include <type_traits>

static constexpr uintptr_t base = UINT64_C(0x140000000);
static constexpr uintptr_t lifecycle_declarewar_vtable_rva = 0x1c80d90;
static constexpr uintptr_t kFakeGame = UINT64_C(0x21000000);
static constexpr unsigned kMaxReferences = 32;
static uint64_t observation_creation = UINT64_C(0x323001);
static DWORD frame_thread = 0;
static bool thread_changed = false;
static HANDLE log_file = INVALID_HANDLE_VALUE;
static unsigned read_calls = 0;
static unsigned protocol_capture_calls = 0;
static unsigned payload_decode_calls = 0;
static unsigned country_calls = 0;
static unsigned pair_calls = 0;
static unsigned state_calls = 0;
static unsigned participant_calls = 0;
static unsigned register_calls = 0;

enum class ActionFamily : unsigned char { other, declare_war };

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

struct PeaceWarReferenceList {
    uintptr_t references[kMaxReferences]{};
    unsigned count = 0;
    bool complete = false;
};

struct PeaceWarSideMembers {
    uint64_t handles[256]{};
    unsigned count = 0;
};

using PeaceWarRegistryEntry = information::war_registry::Snapshot;
static information::war_registry::Entry peace_war_registry[256]{};
static unsigned peace_war_registry_size = 0;
static information::war_registry::Registry peace_war_registry_lifetimes{
    peace_war_registry,peace_war_registry_size};

struct PairRefs {
    uintptr_t references[kMaxReferences]{};
    unsigned count = 0;
    bool complete = true;
};

struct FixtureArena {
    alignas(16) unsigned char wrapper[0x58 + sizeof(uintptr_t)]{};
    alignas(16) unsigned char action[0x100]{};
    int32_t date = 100;
    uint64_t actor = 0;
    uint64_t recipient = 0;
    uintptr_t actor_country = 0;
    uintptr_t recipient_country = 0;
    uintptr_t action_vtable = base + lifecycle_declarewar_vtable_rva;
    bool country_readable = true;
    bool identity_changes_after = false;
    bool stable_before = true;
    bool stable_after = true;
    bool use_after = false;
    bool symmetric = true;
    bool payload_readable = true;
    ActionFamily family = ActionFamily::declare_war;
    PairRefs before{};
    PairRefs after{};
    uint64_t side_a[256]{};
    unsigned side_a_count = 0;
    uint64_t side_b[256]{};
    unsigned side_b_count = 0;
    bool sides_readable = true;
};

static FixtureArena* arena = nullptr;
static wchar_t log_path[32768]{};

static bool same_refs(const PeaceWarReferenceList& left,
    const PeaceWarReferenceList& right) noexcept {
    if (!left.complete || !right.complete || left.count != right.count) return false;
    for (unsigned i = 0; i < left.count; ++i) {
        if (left.references[i] != right.references[i]) return false;
    }
    return true;
}

template<class Value>
static bool read(uintptr_t address, Value& value) noexcept {
    ++read_calls;
    if constexpr (std::is_same_v<Value, uintptr_t>) {
        if (!arena) return false;
        if (address == reinterpret_cast<uintptr_t>(arena->wrapper) + 0x50) {
            value = reinterpret_cast<uintptr_t>(arena->action);
            return true;
        }
        if (address == reinterpret_cast<uintptr_t>(arena->action)) {
            value = arena->action_vtable;
            return true;
        }
        if (address == base + 0x233fe58) {
            value = kFakeGame;
            return true;
        }
    } else if constexpr (std::is_same_v<Value, int32_t>) {
        if (address == kFakeGame + 0x1dd0 && arena) {
            value = arena->date;
            return true;
        }
    }
    return false;
}

static ProtocolWrapperShape protocol_capture(void* wrapper) noexcept {
    ++protocol_capture_calls;
    ProtocolWrapperShape result{};
    if (!arena || wrapper != arena->wrapper) return result;
    result.identity = true;
    result.readable = arena->payload_readable;
    result.action = reinterpret_cast<uintptr_t>(arena->action);
    result.payload.actor10 = arena->actor;
    result.payload.recipient20 = arena->recipient;
    result.payload.state34 = 0;
    result.payload.variant38 = 1;
    result.payload.family = arena->family;
    return result;
}

static bool execution_payload(const AlliancePayload& source,
    AlliancePayload& destination) noexcept {
    ++payload_decode_calls;
    if (!arena || !arena->payload_readable) return false;
    destination = source;
    return true;
}

static bool peace_query_country_pointer(uint64_t reference,
    uintptr_t& country) noexcept {
    ++country_calls;
    if (!arena || !arena->country_readable) return false;
    if (reference == arena->actor) {
        country = arena->actor_country;
        if (arena->use_after && arena->identity_changes_after) country += 0x20;
        return country != 0;
    }
    if (reference == arena->recipient) {
        country = arena->recipient_country;
        return country != 0;
    }
    return false;
}

static bool peace_query_pair_references(uintptr_t owner, unsigned other_slot,
    PeaceWarReferenceList& result) noexcept {
    ++pair_calls;
    result = PeaceWarReferenceList{};
    if (!arena) return false;
    const auto actor_slot = static_cast<unsigned>((arena->actor >> 32) & 0xffffu);
    const auto recipient_slot = static_cast<unsigned>((arena->recipient >> 32) & 0xffffu);
    const bool known_owner = owner == arena->actor_country
        || owner == arena->actor_country + 0x20 || owner == arena->recipient_country;
    if (!known_owner || (owner != arena->recipient_country && other_slot != recipient_slot)
        || (owner == arena->recipient_country && other_slot != actor_slot)) return false;
    const PairRefs& selected = arena->use_after ? arena->after : arena->before;
    if (!selected.complete && selected.count == 0) return false;
    result.count = selected.count;
    result.complete = selected.complete;
    for (unsigned i = 0; i < result.count && i < kMaxReferences; ++i)
        result.references[i] = selected.references[i];
    if (!arena->symmetric && owner == arena->recipient_country && result.count < kMaxReferences) {
        result.references[result.count++] = 0x7f000001;
    }
    return true;
}

static bool peace_query_reference_sets_equal(const PeaceWarReferenceList& left,
    const PeaceWarReferenceList& right) noexcept {
    return same_refs(left, right);
}

static bool peace_query_context_state_stable(uint64_t, uint64_t, uintptr_t,
    uintptr_t, const PeaceWarReferenceList&, const PeaceWarReferenceList&) noexcept {
    ++state_calls;
    return arena && (arena->use_after ? arena->stable_after : arena->stable_before);
}

static unsigned side_for(const uint64_t* values, unsigned count,
    uint64_t reference) noexcept {
    for (unsigned index = 0; index < count; ++index)
        if (values[index] == reference) return 1;
    return 0;
}

static bool peace_war_capture_participant_sides(uintptr_t, uint64_t actor,
    uint64_t recipient, PeaceWarSideMembers& side_a, PeaceWarSideMembers& side_b,
    const char*& reason) noexcept {
    ++participant_calls;
    side_a = PeaceWarSideMembers{};
    side_b = PeaceWarSideMembers{};
    reason = nullptr;
    if (!arena || !arena->sides_readable || arena->side_a_count > 256
        || arena->side_b_count > 256) {
        reason = "FIXTURE_SIDE_READ_FAILED";
        return false;
    }
    side_a.count = arena->side_a_count;
    side_b.count = arena->side_b_count;
    for (unsigned index = 0; index < side_a.count; ++index)
        side_a.handles[index] = arena->side_a[index];
    for (unsigned index = 0; index < side_b.count; ++index)
        side_b.handles[index] = arena->side_b[index];
    const unsigned actor_side = side_for(side_a.handles, side_a.count, actor)
        ? 1u : side_for(side_b.handles, side_b.count, actor) ? 2u : 0u;
    const unsigned recipient_side = side_for(side_a.handles, side_a.count, recipient)
        ? 1u : side_for(side_b.handles, side_b.count, recipient) ? 2u : 0u;
    if (!actor_side || !recipient_side || actor_side == recipient_side) {
        reason = "FIXTURE_SIDE_MEMBERSHIP_INVALID";
        return false;
    }
    return true;
}

static unsigned peace_war_side_for_handle(const PeaceWarSideMembers& side_a,
    const PeaceWarSideMembers& side_b, uint64_t handle) noexcept {
    const bool in_a = side_for(side_a.handles, side_a.count, handle) != 0;
    const bool in_b = side_for(side_b.handles, side_b.count, handle) != 0;
    return in_a == in_b ? 0u : in_a ? 1u : 2u;
}

static bool peace_war_participants_json(const PeaceWarSideMembers& side_a,
    const PeaceWarSideMembers& side_b, uint64_t actor, uint64_t recipient,
    const char* reason, char* output, size_t capacity) noexcept {
    if (!output || !capacity || reason || !side_a.count || !side_b.count
        || side_a.count > 256 || side_b.count > 256) return false;
    char side_a_json[2048]{}, side_b_json[2048]{};
    auto encode_side = [](const PeaceWarSideMembers& side, char* buffer,
        size_t buffer_size) noexcept {
        size_t used = 0;
        int written = std::snprintf(buffer, buffer_size, "[");
        if (written < 0 || static_cast<size_t>(written) >= buffer_size) return false;
        used = static_cast<size_t>(written);
        for (unsigned index = 0; index < side.count; ++index) {
            const uint64_t handle = side.handles[index];
            written = std::snprintf(buffer + used, buffer_size - used,
                "%s\"%c%c%c\"", index ? "," : "",
                static_cast<char>(handle & 0xffu),
                static_cast<char>((handle >> 8) & 0xffu),
                static_cast<char>((handle >> 16) & 0xffu));
            if (written < 0 || static_cast<size_t>(written) >= buffer_size - used)
                return false;
            used += static_cast<size_t>(written);
        }
        written = std::snprintf(buffer + used, buffer_size - used, "]");
        return written >= 0 && static_cast<size_t>(written) < buffer_size - used;
    };
    const unsigned actor_side = peace_war_side_for_handle(side_a, side_b, actor);
    const unsigned recipient_side = peace_war_side_for_handle(side_a, side_b, recipient);
    if (!actor_side || !recipient_side || actor_side == recipient_side
        || !encode_side(side_a, side_a_json, sizeof(side_a_json))
        || !encode_side(side_b, side_b_json, sizeof(side_b_json))) return false;
    const int written = std::snprintf(output, capacity,
        "{\"source\":\"native_war_side_vectors\",\"status\":\"available\","
        "\"complete\":true,\"side_a\":%s,\"side_b\":%s,\"actor_side\":\"%s\","
        "\"recipient_side\":\"%s\",\"reason\":null}",
        side_a_json, side_b_json, actor_side == 1 ? "side_a" : "side_b",
        recipient_side == 1 ? "side_a" : "side_b");
    return written >= 0 && static_cast<size_t>(written) < capacity;
}

static std::optional<PeaceWarRegistryEntry> peace_query_register_war(uintptr_t reference) noexcept {
    ++register_calls;
    return peace_war_registry_lifetimes.register_war(reference,observation_creation,
        peace_war_registry_lifetimes.sequence());
}
static void peace_query_reconcile_war_registry() noexcept {}

#include "../information-war-declaration-observer.inc"

namespace source = war_declaration_observer;
namespace owned = information::war_declaration;

static unsigned checks = 0;
static unsigned failures = 0;
static unsigned scenarios = 0;

static void check(bool okay, const char* name) {
    ++checks;
    if (!okay) {
        ++failures;
        std::printf("FAIL %s\n", name);
    }
}

#define CHECK_ONE(expression) check((expression), #expression)
#define CHECK_TWO(expression, name) check((expression), name)
#define CHECK_SELECT(_1, _2, NAME, ...) NAME
#define CHECK(...) CHECK_SELECT(__VA_ARGS__, CHECK_TWO, CHECK_ONE)(__VA_ARGS__)

static uint64_t make_reference(const char* tag, uint16_t slot) {
    return (static_cast<uint64_t>(slot) << 32)
        | static_cast<unsigned char>(tag[0])
        | (static_cast<uint64_t>(static_cast<unsigned char>(tag[1])) << 8)
        | (static_cast<uint64_t>(static_cast<unsigned char>(tag[2])) << 16);
}

static void set_list(PairRefs& output, std::initializer_list<uintptr_t> values,
    bool complete = true) {
    output = PairRefs{};
    output.complete = complete;
    for (const auto value : values) output.references[output.count++] = value;
}

static void set_sides(std::initializer_list<uint64_t> side_a,
    std::initializer_list<uint64_t> side_b) {
    arena->side_a_count = 0;
    arena->side_b_count = 0;
    for (const auto handle : side_a) arena->side_a[arena->side_a_count++] = handle;
    for (const auto handle : side_b) arena->side_b[arena->side_b_count++] = handle;
}

static uintptr_t war_reference(unsigned index) {
    return static_cast<uintptr_t>(UINT64_C(0x50000000) + index * 0x1000u);
}

static void reset_observer() {
    source::installed.store(true);
    source::transport_fault.store(false);
    source::sequence = 0;
    source::dropped = 0;
    source::total_dropped = 0;
    source::head = 0;
    source::size = 0;
    for (auto& event : source::events) event = source::Event{};
}

static void reset_registry() {
    peace_war_registry_size = 0;
    for (auto& item : peace_war_registry) {
        item.native_reference.store(0);
        std::memset(item.public_id,0,sizeof(item.public_id));
    }
    peace_war_registry_lifetimes.~Registry();
    new (&peace_war_registry_lifetimes) information::war_registry::Registry{
        peace_war_registry,peace_war_registry_size};
    register_calls = 0;
}

static void reset_fixture(const char* actor_tag = "FRA", const char* recipient_tag = "ENG") {
    *arena = FixtureArena{};
    arena->actor = make_reference(actor_tag, 1);
    arena->recipient = make_reference(recipient_tag, 2);
    const auto memory = reinterpret_cast<uintptr_t>(arena);
    arena->actor_country = memory + 0x800;
    arena->recipient_country = memory + 0x1000;
    set_sides({arena->actor}, {arena->recipient});
    set_list(arena->before, {});
    set_list(arena->after, {});
    frame_thread = GetCurrentThreadId();
    thread_changed = false;
    read_calls = protocol_capture_calls = payload_decode_calls = 0;
    country_calls = pair_calls = state_calls = participant_calls = 0;
    reset_registry();
    reset_observer();
}

static void begin_after_state(const source::Pending& pending,
    std::initializer_list<uintptr_t> refs, bool constructed = false) {
    if (constructed) for (const auto reference : refs) {
        const auto birth = peace_war_registry_lifetimes.begin(reference,arena->actor,arena->recipient,true);
        CHECK(peace_war_registry_lifetimes.complete(birth,true));
    }
    set_list(arena->after, refs);
    arena->use_after = true;
    (void)pending;
}

static source::Pending begin_observation() {
    return source::begin(arena->wrapper);
}

static void clear_log() {
    LARGE_INTEGER zero{};
    CHECK(log_file != INVALID_HANDLE_VALUE);
    CHECK(SetFilePointerEx(log_file, zero, nullptr, FILE_BEGIN) != FALSE);
    CHECK(SetEndOfFile(log_file) != FALSE);
}

static bool open_log_reader(char* output, DWORD capacity, DWORD& bytes) {
    HANDLE input = CreateFileW(log_path, GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, nullptr);
    if (input == INVALID_HANDLE_VALUE) return false;
    const bool okay = ReadFile(input, output, capacity - 1, &bytes, nullptr) != FALSE;
    CloseHandle(input);
    if (okay) output[bytes] = '\0';
    return okay;
}

static void test_fast_filters_and_owned_new_war_event() {
    ++scenarios;
    reset_fixture();
    source::installed.store(false);
    auto pending = begin_observation();
    CHECK(!pending.observed && read_calls == 0 && protocol_capture_calls == 0);

    source::installed.store(true);
    arena->action_vtable = base + 0x123456;
    pending = begin_observation();
    CHECK(!pending.observed && read_calls == 2 && protocol_capture_calls == 0
        && payload_decode_calls == 0 && country_calls == 0);

    reset_fixture();
    pending = begin_observation();
    CHECK(pending.observed && pending.ready && payload_decode_calls == 1);
    begin_after_state(pending, {war_reference(1)}, true);
    source::finish(pending);
    CHECK(source::size == 1 && source::total_dropped == 0);
    const auto saved = source::events[source::head];
    CHECK(saved.value.actor == arena->actor && saved.value.recipient == arena->recipient);
    CHECK(saved.value.observer == arena->actor && saved.value.actor_side == 1
        && saved.value.recipient_side == 2 && saved.value.observer_side == 1);
    CHECK(std::strcmp(saved.value.war_id, peace_war_registry[0].public_id) == 0
        && std::strlen(saved.value.war_id) == 29);
    arena->actor = 0;
    arena->recipient = 0;
    CHECK(source::events[source::head].value.actor != 0,
        "queued event owns actor and recipient values");
    source::finish(pending);
    CHECK(source::size == 1 && source::total_dropped == 0,
        "finish on consumed pending is idempotent");
}

static void test_fra_as_third_party_and_no_fra_case() {
    ++scenarios;
    reset_fixture("ENG", "CAS");
    const auto fra = make_reference("FRA", 9);
    const auto por = make_reference("POR", 10);
    set_sides({arena->recipient, fra}, {arena->actor, por});
    auto pending = begin_observation();
    begin_after_state(pending, {war_reference(2)}, true);
    source::finish(pending);
    CHECK(source::size == 1);
    CHECK(source::events[source::head].value.actor_side == 2
        && source::events[source::head].value.recipient_side == 1);
    CHECK(source::events[source::head].value.observer == fra
        && source::events[source::head].value.observer_side == 1);
    CHECK(std::strstr(source::events[source::head].value.participants,
        "\"actor_side\":\"side_b\"") != nullptr);

    reset_fixture("ENG", "CAS");
    set_sides({arena->actor}, {arena->recipient, make_reference("POR", 10)});
    pending = begin_observation();
    begin_after_state(pending, {war_reference(3)}, true);
    source::finish(pending);
    CHECK(source::size == 0 && source::total_dropped == 0
        && peace_war_registry_size == 0,
        "observer outside both participant sides produces no event");
}

static void test_noop_and_unreadable_snapshot() {
    ++scenarios;
    reset_fixture();
    const auto existing = war_reference(4);
    set_list(arena->before, {existing});
    set_list(arena->after, {existing});
    auto pending = begin_observation();
    arena->use_after = true;
    source::finish(pending);
    CHECK(source::size == 0 && source::total_dropped == 0,
        "same pair set is a no-op");

    reset_fixture();
    set_list(arena->before, {}, false);
    pending = begin_observation();
    CHECK(pending.observed && !pending.ready);
    source::finish(pending);
    CHECK(source::size == 0 && source::total_dropped == 1,
        "unreadable before snapshot records one gap");
}

static void test_identity_date_and_frame_gates() {
    ++scenarios;
    reset_fixture();
    auto pending = begin_observation();
    begin_after_state(pending, {war_reference(5)}, true);
    arena->identity_changes_after = true;
    source::finish(pending);
    CHECK(source::size == 0 && source::total_dropped == 1,
        "changed country identity records a gap");

    reset_fixture();
    pending = begin_observation();
    begin_after_state(pending, {war_reference(6)}, true);
    ++arena->date;
    source::finish(pending);
    CHECK(source::size == 0 && source::total_dropped == 1,
        "changed date records a gap");

    reset_fixture();
    pending = begin_observation();
    begin_after_state(pending, {war_reference(7)}, true);
    thread_changed = true;
    source::finish(pending);
    CHECK(source::size == 0 && source::total_dropped == 1,
        "non-frame completion records a gap");
}

static void test_existing_registry_and_ambiguous_new_pairs() {
    ++scenarios;
    reset_fixture();
    const auto existing = war_reference(8);
    peace_query_register_war(existing);
    auto pending = begin_observation();
    begin_after_state(pending, {existing});
    source::finish(pending);
    CHECK(source::size == 0 && source::total_dropped == 1,
        "war identity already registered before command is not reused");

    reset_fixture();
    pending = begin_observation();
    begin_after_state(pending, {war_reference(9), war_reference(10)});
    source::finish(pending);
    CHECK(source::size == 0 && source::total_dropped == 1,
        "two newly observed references are ambiguous");
}

static void test_announced_nested_duplicate() {
    ++scenarios;
    reset_fixture();
    auto first = begin_observation();
    auto nested = begin_observation();
    begin_after_state(first, {war_reference(11)}, true);
    source::finish(first);
    source::finish(nested);
    CHECK(source::size == 1 && peace_war_registry_size == 1);
    const auto registered=peace_query_register_war(war_reference(11));
    CHECK(source::total_dropped == 0 && registered
        && peace_war_registry_lifetimes.claim_announcement(*registered)
            ==information::war_registry::Announcement::duplicate,
        "nested pending for already announced new identity is suppressed");
}

static void add_one_event(uintptr_t reference) {
    set_list(arena->before, {});
    arena->use_after = false;
    auto pending = begin_observation();
    set_list(arena->after, {reference});
    const auto birth = peace_war_registry_lifetimes.begin(reference,arena->actor,arena->recipient,true);
    CHECK(peace_war_registry_lifetimes.complete(birth,true));
    arena->use_after = true;
    source::finish(pending);
}

static void test_reused_address_has_new_id_and_nested_delivery_once() {
    ++scenarios;
    reset_fixture();
    const auto reference = war_reference(8);
    const auto old = peace_query_register_war(reference);
    char old_id[30]{};
    std::memcpy(old_id,old->public_id,sizeof(old_id));
    auto outer = begin_observation();
    auto inner = begin_observation();
    begin_after_state(inner,{reference},true);
    CHECK(!peace_war_registry_lifetimes.current(*old) && !std::strcmp(old->public_id,old_id));
    const auto current=peace_query_register_war(reference);
    CHECK(current && current->slot==old->slot && current->serial>old->serial,
        "normal query may register the new lifetime before command observation finishes");
    source::finish(inner);
    source::finish(outer);
    CHECK(source::size == 1 && source::total_dropped == 0 && peace_war_registry_size == 1);
    CHECK(std::strcmp(source::events[source::head].value.war_id,old_id) != 0);
    CHECK(std::strcmp(source::events[source::head].value.war_id,
        current->public_id) == 0);

    reset_fixture();
    peace_query_register_war(reference);
    set_list(arena->before,{reference});
    auto pending = begin_observation();
    begin_after_state(pending,{reference},true);
    source::finish(pending);
    CHECK(source::size == 1 && peace_war_registry_size == 1,
        "same address in both pair snapshots still detects a new constructed lifetime");
}

static void test_birth_scope_completion_and_frame_failures() {
    ++scenarios;
    const auto reference = war_reference(9);
    reset_fixture();
    auto prior = peace_war_registry_lifetimes.begin(reference,arena->actor,arena->recipient,true);
    CHECK(peace_war_registry_lifetimes.complete(prior,true));
    auto pending = begin_observation();
    begin_after_state(pending,{reference});
    source::finish(pending);
    CHECK(source::size == 0 && peace_war_registry_size == 0,
        "an already constructed war gaining a new opponent pair is not a declaration");

    reset_fixture();
    auto old = peace_query_register_war(reference);
    pending = begin_observation();
    peace_war_registry_lifetimes.begin(reference,arena->actor,arena->recipient,true);
    begin_after_state(pending,{reference});
    source::finish(pending);
    CHECK(source::size == 0 && source::total_dropped == 1 && !peace_war_registry_lifetimes.current(*old));
    CHECK(!peace_query_register_war(reference),
        "unfinished construction cannot acquire or reuse a public ID");

    reset_fixture();
    old = peace_query_register_war(reference);
    pending = begin_observation();
    const auto other_thread = peace_war_registry_lifetimes.begin(
        reference,arena->actor,arena->recipient,false);
    CHECK(!peace_war_registry_lifetimes.complete(other_thread,true));
    begin_after_state(pending,{reference});
    source::finish(pending);
    CHECK(source::size == 0 && source::total_dropped == 1 && !peace_war_registry_lifetimes.current(*old));
    CHECK(!peace_query_register_war(reference));

    reset_fixture();
    pending = begin_observation();
    const auto unrelated = peace_war_registry_lifetimes.begin(
        reference,make_reference("CAS",7),arena->recipient,true);
    CHECK(peace_war_registry_lifetimes.complete(unrelated,true));
    begin_after_state(pending,{reference});
    source::finish(pending);
    CHECK(source::size == 0,
        "a different constructor's endpoints cannot authenticate this command");
}

static void test_bounded_queue_and_real_file_flush() {
    ++scenarios;
    clear_log();
    reset_fixture();
    for (unsigned index = 1; index <= 65; ++index)
        add_one_event(war_reference(100 + index));
    CHECK(source::size == source::kCapacity && source::total_dropped == 1
        && source::dropped == 1, "64 events plus one overflow gap");
    source::flush();
    CHECK(source::size == 32 && source::dropped == 0 && !source::transport_fault,
        "first bounded file flush writes events and gap");
    source::flush();
    CHECK(source::size == 0 && source::total_dropped == 1);
    char output[65536]{};
    DWORD bytes = 0;
    CHECK(open_log_reader(output, sizeof(output), bytes));
    unsigned lines = 0;
    for (DWORD index = 0; index < bytes; ++index) if (output[index] == '\n') ++lines;
    CHECK(lines == 65 && std::strstr(output, "\"event\":\"native_war_declared\"") != nullptr);
    CHECK(std::strstr(output, "\"source\":\"declare_war_command_return_new_pair_reference\"")
        != nullptr);
    CHECK(std::strstr(output, "\"participants\":{\"source\":\"native_war_side_vectors\"")
        != nullptr);
}

static void test_read_only_handle_fault_retains_queue_head() {
    ++scenarios;
    reset_fixture();
    add_one_event(war_reference(200));
    CHECK(source::size == 1 && source::head == 0);
    CloseHandle(log_file);
    log_file = CreateFileW(log_path, GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, nullptr);
    CHECK(log_file != INVALID_HANDLE_VALUE);
    source::flush();
    CHECK(source::transport_fault && source::size == 1 && source::head == 0,
        "read-only write fault retains queue head");
    source::flush();
    CHECK(source::transport_fault && source::size == 1 && source::head == 0,
        "latched fault does not consume or retry the event");
    char health[640] = "{\"event\":\"fixture_health\"}\n";
    source::append_health(health, sizeof(health));
    CHECK(std::strstr(health, "\"transport_fault\":true") != nullptr
        && std::strstr(health, "\"queued\":1") != nullptr);
}

int main() {
    static_assert(sizeof(uintptr_t) == 8, "EU4 fixture requires x64");
    auto memory = VirtualAlloc(nullptr, sizeof(FixtureArena), MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE);
    if (!memory) return 2;
    arena = new (memory) FixtureArena{};
    const DWORD path_chars = GetEnvironmentVariableW(L"WAR_DECLARATION_FIXTURE_LOG",
        log_path, static_cast<DWORD>(sizeof(log_path) / sizeof(log_path[0])));
    if (!path_chars || path_chars >= sizeof(log_path) / sizeof(log_path[0])) return 3;
    log_file = CreateFileW(log_path, GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (log_file == INVALID_HANDLE_VALUE) return 4;

    test_fast_filters_and_owned_new_war_event();
    test_fra_as_third_party_and_no_fra_case();
    test_noop_and_unreadable_snapshot();
    test_identity_date_and_frame_gates();
    test_existing_registry_and_ambiguous_new_pairs();
    test_announced_nested_duplicate();
    test_reused_address_has_new_id_and_nested_delivery_once();
    test_birth_scope_completion_and_frame_failures();
    test_bounded_queue_and_real_file_flush();
    test_read_only_handle_fault_retains_queue_head();

    if (log_file != INVALID_HANDLE_VALUE) CloseHandle(log_file);
    log_file = INVALID_HANDLE_VALUE;
    source::installed.store(false);
    arena->~FixtureArena();
    CHECK(VirtualFree(memory, 0, MEM_RELEASE) != FALSE);
    std::printf("war declaration production observer: %s (%u checks, %u scenarios)\n",
        failures ? "FAIL" : "PASS", checks, scenarios);
    return failures ? 1 : 0;
}
