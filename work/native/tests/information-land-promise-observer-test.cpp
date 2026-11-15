#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <new>
#include "../information-land-promise.h"
#include "../information-war-registry.h"
#include "../declarewar-payload.h"

static uintptr_t base = 0;
static DWORD frame_thread = 0;
static bool thread_changed = false, payload_readable = true;
static uint64_t observation_creation = 1;
static HANDLE log_file = INVALID_HANDLE_VALUE;
static constexpr uintptr_t lifecycle_declarewar_vtable_rva = 0x1c80d90;
static constexpr uint64_t fra = UINT64_C(0x100007a00415246), sav = UINT64_C(0x10000d200564153);
static constexpr uint64_t bur = UINT64_C(0x100004200525542), por = UINT64_C(0x10000bd00524f50);
static constexpr uint64_t gen = UINT64_C(0x1000080004e4547);
static constexpr int32_t date = 56692920;
static unsigned checks = 0;
#define CHECK(expression) do { ++checks; if (!(expression)) { std::printf("FAIL line %u %s\n", __LINE__, #expression); std::exit(1); } } while (false)
template<class Value> static bool read(uintptr_t address, Value& value) {
    SIZE_T count = 0;
    return ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<void*>(address), &value,
                             sizeof(value), &count) && count == sizeof(value);
}
template<class Value> static void put(uintptr_t address, Value value) {
    std::memcpy(reinterpret_cast<void*>(address), &value, sizeof(value));
}
static uintptr_t country(uint64_t reference) {
    if (reference == fra) return base + 0x40000;
    if (reference == sav) return base + 0x44000;
    if (reference == bur) return base + 0x48000;
    if (reference == por) return base + 0x4c000;
    if (reference == gen) return base + 0x50000;
    return 0;
}
static bool peace_query_country_pointer(uint64_t reference, uintptr_t& pointer) {
    pointer = country(reference);
    uint64_t canonical = 0;
    return pointer && read(pointer + 0x20, canonical) && canonical == reference;
}
#include "../peace-war-side-members.inc"

struct PeaceWarReferenceList {
    uintptr_t references[32]{};
    unsigned count = 0;
    bool complete = false;
};
static bool peace_query_pair_references(uintptr_t pointer, unsigned slot, PeaceWarReferenceList& result) {
    result = {};
    uintptr_t rows = 0;
    int32_t count = 0;
    if (!read(pointer + 0x1548, rows) || !read(pointer + 0x1554, count) || count < 0 || count > 32) return false;
    for (int32_t index = 0; index < count; ++index) {
        int32_t enemy = -1;
        uintptr_t war = 0;
        if (!read(rows + index * 16, enemy) || !read(rows + index * 16 + 8, war)) return false;
        if (enemy == static_cast<int32_t>(slot)) result.references[result.count++] = war;
    }
    result.complete = true;
    return true;
}
static bool peace_query_reference_sets_equal(const PeaceWarReferenceList& left, const PeaceWarReferenceList& right) {
    return left.complete && right.complete && left.count == right.count
        && std::equal(left.references, left.references + left.count, right.references);
}
static bool peace_query_context_state_stable(uint64_t actor, uint64_t recipient, uintptr_t left, uintptr_t right,
                                            const PeaceWarReferenceList&, const PeaceWarReferenceList&) {
    uintptr_t current_left = 0, current_right = 0;
    return peace_query_country_pointer(actor, current_left) && peace_query_country_pointer(recipient, current_right)
        && left == current_left && right == current_right;
}
static information::war_registry::Entry registry_entries[256]{};
static unsigned registry_size = 0;
static information::war_registry::Registry peace_war_registry_lifetimes{registry_entries, registry_size};
static std::optional<information::war_registry::Snapshot> peace_query_register_war(uintptr_t pointer) {
    return peace_war_registry_lifetimes.register_war(pointer, observation_creation);
}
enum class ActionFamily { other, declare_war };
struct AlliancePayload {
    uint64_t actor10 = 0, recipient20 = 0;
    unsigned state34 = 0, variant38 = 1;
    ActionFamily family = ActionFamily::declare_war;
    bridge::declarewar_payload::WarPayloadExtension war{};
};
static AlliancePayload current_payload{};
static AlliancePayload lifecycle_capture_shape(void*) { return current_payload; }
static bool execution_payload(const AlliancePayload& shape, AlliancePayload& payload) {
    payload = shape;
    return payload_readable;
}
#include "../information-land-promise-observer.inc"
namespace source = land_promise_observer;
namespace owned = information::land_promise;

static uintptr_t action() { return base + 0x60000; }
static uintptr_t wrapper() { return base + 0x61000; }
static uintptr_t war(unsigned index) { return base + 0x80000 + index * 0x10000; }
static void set_associations(uint64_t actor, std::initializer_list<std::pair<uint64_t, uintptr_t>> pairs) {
    const uintptr_t pointer = country(actor), rows = pointer + 0x2000;
    put(pointer + 0x1548, rows);
    put(pointer + 0x1554, static_cast<int32_t>(pairs.size()));
    unsigned index = 0;
    for (const auto& pair : pairs) {
        put(rows + index * 16, static_cast<int32_t>((pair.first >> 32) & 0xffff));
        put(rows + index * 16 + 8, pair.second);
        ++index;
    }
}
static void set_war(unsigned index, std::initializer_list<uint64_t> allies,
                    uint64_t enemy, uint64_t beneficiary, unsigned char promised = 0) {
    const uintptr_t pointer = war(index), left = pointer + 0x1000, right = pointer + 0x1800;
    put(pointer + 0x48, left); put(pointer + 0x50, left + allies.size() * 8);
    put(pointer + 0x58, left + allies.size() * 8);
    unsigned member = 0;
    for (auto value : allies) put(left + member++ * 8, value);
    put(pointer + 0x78, right); put(pointer + 0x80, right + 8); put(pointer + 0x88, right + 8);
    put(right, enemy);
    const uintptr_t records = pointer + 0x2000;
    put(pointer + 0xc0, records); put(pointer + 0xc8, records + 0x90); put(pointer + 0xd0, records + 0x90);
    put(records, base + 0x1d1f6b0); put(records + 0x10, beneficiary); put(records + 0x1c, promised);
}
static void birth(unsigned index, uint64_t actor = sav, uint64_t enemy = bur) {
    const auto token = peace_war_registry_lifetimes.begin(war(index), actor, enemy, true);
    CHECK(peace_war_registry_lifetimes.complete(token, true));
}
static void reset(bool declaration = false) {
    source::installed = true; source::transport_fault = false;
    source::dropped = source::total_dropped = 0;
    source::head = source::size = 0; source::sequence = 0;
    frame_thread = GetCurrentThreadId(); thread_changed = false; payload_readable = true;
    registry_size = 0;
    for (auto& row : registry_entries) { row.native_reference = 0; row.public_id[0] = 0; }
    peace_war_registry_lifetimes.~Registry();
    new (&peace_war_registry_lifetimes) information::war_registry::Registry(registry_entries, registry_size);
    put(base + 0x233fe58, base + 0x30000); put(base + 0x31dd0, date);
    for (auto reference : {fra, sav, bur, por, gen}) {
        put(country(reference) + 0x20, reference);
        set_associations(reference, {});
    }
    put(wrapper() + 0x50, action());
    put(action(), base + (declaration ? lifecycle_declarewar_vtable_rva : source::kCallVtable));
    put(action() + 8, int32_t{0x165}); put(action() + 0x10, sav); put(action() + 0x20, fra);
    put(action() + 0x34, int32_t{2}); put(action() + 0x53, static_cast<unsigned char>(0));
    current_payload = {};
    current_payload.actor10 = fra; current_payload.recipient20 = bur;
    current_payload.war.container50.count = current_payload.war.container68.count = 1;
    current_payload.war.container50.values[0] = current_payload.war.container68.values[0] = sav;
    if (!declaration) {
        birth(0); set_war(0, {sav}, bur, fra);
        set_associations(sav, {{bur, war(0)}});
    }
}
static void join(unsigned index = 0, uint64_t beneficiary = fra, unsigned char flag = 0) {
    set_war(index, {sav, beneficiary}, index ? por : bur, beneficiary, flag);
    if (!index) set_associations(beneficiary, {{bur, war(0)}});
    else set_associations(beneficiary, {{bur, war(0)}, {por, war(1)}});
}
static void check_finish(source::Pending& pending, unsigned expected, unsigned gaps = 0) {
    SetLastError(0x7799);
    source::finish(pending);
    CHECK(GetLastError() == 0x7799);
    CHECK(source::size == expected && static_cast<unsigned>(source::total_dropped) == gaps);
    source::finish(pending);
    CHECK(source::size == expected && static_cast<unsigned>(source::total_dropped) == gaps);
}

int main() {
    base = reinterpret_cast<uintptr_t>(VirtualAlloc(nullptr, 0x2341000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    CHECK(base != 0);
    reset();
    SetLastError(0x4466);
    auto pending = source::begin(reinterpret_cast<void*>(wrapper()));
    CHECK(GetLastError() == 0x4466 && pending.ready);
    join(); check_finish(pending, 1);
    CHECK(source::events[0].value.promisor == sav && source::events[0].value.beneficiary == fra);
    CHECK(source::events[0].value.observer == fra && source::events[0].value.kind == owned::Kind::call);
    reset(); pending = source::begin(reinterpret_cast<void*>(wrapper())); check_finish(pending, 0);
    reset(); put(action() + 0x53, static_cast<unsigned char>(1));
    pending = source::begin_action(action()); join(); check_finish(pending, 0);
    reset(); put(action() + 0x34, int32_t{1}); pending = source::begin_action(action()); join(); check_finish(pending, 0);
    reset(); pending = source::begin_action(action()); join(0, fra, 1); check_finish(pending, 0);
    reset(); pending = source::begin_action(action()); join(); put(base + 0x31dd0, date + 24); check_finish(pending, 0, 1);
    reset(); pending = source::begin_action(action()); join(); put(country(sav) + 0x20, sav + 1); check_finish(pending, 0, 1);
    reset(); pending = source::begin_action(action()); join(); put(war(0) + 0xc8, war(0) + 0x2001); check_finish(pending, 0, 1);
    reset(); join(); pending = source::begin_action(action()); check_finish(pending, 0);
    reset(); pending = source::begin_action(action());
    auto retirement = peace_war_registry_lifetimes.retire(war(0));
    CHECK(peace_war_registry_lifetimes.complete_retirement(retirement));
    birth(0); join(); check_finish(pending, 0);
    reset(); put(action() + 0x20, gen); pending = source::begin_action(action()); join(0, gen); check_finish(pending, 0);
    reset(); birth(1, sav, por); set_war(1, {sav}, por, fra);
    set_associations(sav, {{bur, war(0)}, {por, war(1)}});
    pending = source::begin_action(action()); join(); join(1); check_finish(pending, 2);
    reset(true); pending = source::begin_action(action());
    auto duplicate = source::begin(reinterpret_cast<void*>(wrapper()));
    birth(0, fra, bur); set_war(0, {fra, sav}, bur, sav);
    set_associations(fra, {{bur, war(0)}}); set_associations(bur, {{fra, war(0)}});
    check_finish(pending, 1); check_finish(duplicate, 1);
    CHECK(source::events[0].value.promisor == fra && source::events[0].value.beneficiary == sav);
    reset(true); pending = source::begin_action(action());
    birth(0, fra, bur); set_war(0, {fra}, bur, sav);
    set_associations(fra, {{bur, war(0)}}); set_associations(bur, {{fra, war(0)}});
    check_finish(pending, 0);
    reset(true); current_payload.war.container50.count = 0;
    pending = source::begin_action(action()); check_finish(pending, 0, 1);
    reset(); source::installed = false; pending = source::begin_action(action()); join(); check_finish(pending, 0);
    reset(); source::transport_fault = true; pending = source::begin_action(action()); join(); check_finish(pending, 0);
    reset(); thread_changed = true; pending = source::begin_action(action()); check_finish(pending, 0, 1);
    reset();
    std::memcpy(reinterpret_cast<void*>(base + 0x53f9c6), owned::native_guards::kGuard0.data(), owned::native_guards::kGuard0.size());
    std::memcpy(reinterpret_cast<void*>(base + 0xd8a028), owned::native_guards::kGuard1.data(), owned::native_guards::kGuard1.size());
    std::memcpy(reinterpret_cast<void*>(base + 0xd95526), owned::native_guards::kGuard2.data(), owned::native_guards::kGuard2.size());
    put(base + source::kCallVtable + 0x48, base + 0x53e130);
    source::installed = false; CHECK(source::install()); CHECK(!source::install());
    source::installed = false; put(base + 0xd8a028, static_cast<unsigned char>(0)); CHECK(!source::install());
    reset();
    const char* path = std::getenv("LAND_PROMISE_FIXTURE_LOG");
    CHECK(path != nullptr);
    log_file = CreateFileA(path, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    CHECK(log_file != INVALID_HANDLE_VALUE);
    pending = source::begin_action(action()); join(); source::finish(pending); source::flush();
    reset(true); source::sequence = 1; pending = source::begin_action(action()); birth(0, fra, bur);
    set_war(0, {fra, sav}, bur, sav); set_associations(fra, {{bur, war(0)}}); set_associations(bur, {{fra, war(0)}});
    source::finish(pending); source::flush();
    CHECK(CloseHandle(log_file)); log_file = INVALID_HANDLE_VALUE;
    CHECK(VirtualFree(reinterpret_cast<void*>(base), 0, MEM_RELEASE));
    std::printf("land_promise checks=%u\n", checks);
}
