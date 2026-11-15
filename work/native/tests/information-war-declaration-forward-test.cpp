#include <cstdint>
#include <cstdio>
#include <vector>

static unsigned char* execution_entry_original = nullptr;
static void* bridge_response_original = nullptr;
static unsigned primary_calls = 0, fallback_calls = 0, begins = 0, finishes = 0;
static unsigned checks = 0, failures = 0;
static void* last_argument = nullptr;
static std::vector<int> order;
namespace war_declaration_observer {
struct Pending {};
static Pending begin(void* value) { ++begins; last_argument = value; order.push_back(1); return {}; }
static void finish(Pending&) { ++finishes; order.push_back(3); }
}
#include "original-call-body.inc"

static void primary(void* value) { ++primary_calls; last_argument = value; order.push_back(2); }
static void fallback(void* value) { ++fallback_calls; last_argument = value; order.push_back(2); }
static void check(bool okay, const char* name) {
    ++checks;
    if (!okay) { ++failures; std::printf("FAIL %s\n", name); }
}
int main() {
#ifdef BRIDGE_WAR_DECLARATION_OBSERVATION
    constexpr bool observing = true;
#else
    constexpr bool observing = false;
#endif
    int object = 0;
    for (unsigned mode = 0; mode < 4; ++mode) {
        primary_calls = fallback_calls = begins = finishes = 0;
        order.clear();
        last_argument = nullptr;
        execution_entry_original = mode & 1 ? reinterpret_cast<unsigned char*>(&primary) : nullptr;
        bridge_response_original = mode & 2 ? reinterpret_cast<void*>(&fallback) : nullptr;
        const bool returned = execution_call_original(&object);
        check(returned == (mode != 0), "original availability result preserved");
        check(primary_calls == ((mode & 1) ? 1u : 0u), "primary called exactly once when available");
        check(fallback_calls == (mode == 2 ? 1u : 0u), "fallback used only without primary");
        const unsigned observed = mode && observing ? 1u : 0u;
        check(begins == observed && finishes == observed, "begin and finish balanced only around native call");
        check(!mode || last_argument == &object, "original argument preserved");
        check(!mode || order == (observing ? std::vector<int>{1, 2, 3} : std::vector<int>{2}),
            "normal return observation order");
    }
    std::printf("{\"checks\":%u,\"failures\":%u,\"observation_enabled\":%s}\n",
        checks, failures, observing ? "true" : "false");
    return failures ? 1 : 0;
}
