// Compile the exact production entry body with owned command objects and
// counting stand-ins for its dependencies. No game process is opened.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

enum class RivalEntryKind : unsigned char { set = 1, replace = 2, remove = 3 };
using RivalHandler = void(*)(void*);
static uintptr_t base = 0x140000000;
static const uintptr_t rival_vtable_rvas[]{0x1c55138, 0x1c54b10, 0x1c54a68};
static const uint32_t rival_selectors[]{0x2fae, 0x3005, 0x2faf};
static volatile LONG rival_blocked_calls = 0;
static int binding = -1;
static unsigned native_calls = 0, begin_calls = 0, finish_calls = 0, ledger_calls = 0;
static unsigned checks = 0, failures = 0;
static bool verified = false;
static std::vector<int> order;

template<class Value>
static bool read(uintptr_t address, Value& value) {
    std::memcpy(&value, reinterpret_cast<void*>(address), sizeof(value));
    return true;
}
static bool observation_country_handle(uint64_t value) { return value != 0; }
static bool rival_actor_is_france(uint64_t value) { return (value & 0xffffffu) == 0x415246; }
static const char* rival_reason_for(bool, bool, bool, bool) { return "fixture"; }
static void rival_record(RivalEntryKind, uint32_t, uint64_t, uint64_t, uint64_t,
    bool, bool, bool, const char*, uintptr_t) {}
static int rival_execution_begin(void*, unsigned) { return binding; }
static void rival_execution_finish(unsigned) { ++ledger_calls; order.push_back(4); }
namespace rival_change_observer {
struct Pending {};
static Pending begin(unsigned, uint64_t, uint64_t, uint64_t, bool eligible) {
    ++begin_calls;
    verified = eligible;
    order.push_back(1);
    return {};
}
static void finish(Pending&) { ++finish_calls; order.push_back(3); }
}

#include "rival-authority-forward-body.inc"

static void original(void*) { ++native_calls; order.push_back(2); }
static void check(bool okay, const char* name) {
    ++checks;
    if (!okay) { ++failures; std::printf("FAIL %s\n", name); }
}
template<class Value>
static void put(unsigned char* command, unsigned offset, Value value) {
    std::memcpy(command + offset, &value, sizeof(value));
}

int main() {
#ifdef BRIDGE_RIVAL_OBSERVATION
    constexpr bool observing = true;
#else
    constexpr bool observing = false;
#endif
    for (unsigned index = 0; index < 3; ++index) {
        alignas(8) unsigned char command[0x68]{};
        put(command, 0, base + rival_vtable_rvas[index]);
        put(command, 0x44, rival_selectors[index]);
        put(command, 0x50, UINT64_C(0x100474e45)); // ENG
        put(command, 0x58, UINT64_C(0x200415246)); // FRA
        put(command, 0x60, UINT64_C(0x300545341)); // AST
        const auto kind = static_cast<RivalEntryKind>(index + 1);
        native_calls = begin_calls = finish_calls = ledger_calls = 0;
        binding = -1;
        order.clear();
        rival_authority_entry(command, kind, original, 0);
        check(native_calls == 1 && ledger_calls == 0, "non-FRA native original exactly once");
        check(begin_calls == static_cast<unsigned>(observing) && finish_calls == begin_calls,
            "balanced observation around forwarded call");
        check(!observing || (verified && order == std::vector<int>{1, 2, 3}), "normal return order");

        native_calls = begin_calls = finish_calls = 0;
        rival_authority_entry(command, kind, nullptr, 0);
        check(native_calls == 0 && begin_calls == 0 && finish_calls == 0, "missing original is not observed");

        put(command, 0x44, uint32_t{0});
        native_calls = begin_calls = finish_calls = 0;
        rival_authority_entry(command, kind, original, 0);
        check(native_calls == 1 && (!observing || !verified), "malformed non-FRA still forwarded but unverified");
        put(command, 0x44, rival_selectors[index]);

        put(command, 0x50, UINT64_C(0x200415246));
        put(command, 0x58, UINT64_C(0x100474e45));
        native_calls = begin_calls = finish_calls = 0;
        const LONG blocked = rival_blocked_calls;
        rival_authority_entry(command, kind, original, 0);
        check(native_calls == 0 && begin_calls == 0 && finish_calls == 0
            && rival_blocked_calls == blocked + 1, "ungranted FRA call remains blocked");

        binding = 7;
        native_calls = begin_calls = finish_calls = ledger_calls = 0;
        order.clear();
        rival_authority_entry(command, kind, original, 0);
        check(native_calls == 1 && ledger_calls == 1, "granted FRA native and ledger called once");
        check(!observing || order == std::vector<int>{1, 2, 3, 4}, "observation precedes existing result finalizer");
    }
    std::printf("{\"checks\":%u,\"failures\":%u,\"observation_enabled\":%s}\n",
        checks, failures, observing ? "true" : "false");
    return failures ? 1 : 0;
}
