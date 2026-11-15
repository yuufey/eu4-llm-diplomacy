#include <cstdint>
#include <cstdio>
#include <vector>

static unsigned char* execution_entry_original = nullptr;
static void* bridge_response_original = nullptr;
static unsigned primary_calls = 0, fallback_calls = 0;
static unsigned war_begins = 0, war_finishes = 0, relation_begins = 0, relation_finishes = 0;
static unsigned checks = 0, failures = 0;
static void* last_argument = nullptr;
static std::vector<int> order;
namespace war_declaration_observer {
struct Pending {};
static Pending begin(void* value) { ++war_begins; last_argument = value; order.push_back(1); return {}; }
static void finish(Pending&) { ++war_finishes; order.push_back(4); }
}
namespace relation_change_observer {
struct Pending {};
static Pending begin(void* value) { ++relation_begins; last_argument = value; order.push_back(2); return {}; }
static void finish(Pending&) { ++relation_finishes; order.push_back(5); }
}
#include "original-call-body.inc"

static void primary(void* value) { ++primary_calls; last_argument = value; order.push_back(3); }
static void fallback(void* value) { ++fallback_calls; last_argument = value; order.push_back(3); }
static void check(bool okay, const char* name) {
    ++checks;
    if (!okay) { ++failures; std::printf("FAIL %s\n", name); }
}
int main() {
    unsigned war_enabled = 0, relation_enabled = 0;
    std::vector<int> expected;
#ifdef BRIDGE_WAR_DECLARATION_OBSERVATION
    war_enabled = 1;
    expected.push_back(1);
#endif
#ifdef BRIDGE_RELATION_OBSERVATION
    relation_enabled = 1;
    expected.push_back(2);
#endif
    expected.push_back(3);
#ifdef BRIDGE_WAR_DECLARATION_OBSERVATION
    expected.push_back(4);
#endif
#ifdef BRIDGE_RELATION_OBSERVATION
    expected.push_back(5);
#endif
    int object = 0;
    for (unsigned mode = 0; mode < 4; ++mode) {
        primary_calls = fallback_calls = war_begins = war_finishes = relation_begins = relation_finishes = 0;
        order.clear();
        last_argument = nullptr;
        execution_entry_original = mode & 1 ? reinterpret_cast<unsigned char*>(&primary) : nullptr;
        bridge_response_original = mode & 2 ? reinterpret_cast<void*>(&fallback) : nullptr;
        const bool returned = execution_call_original(&object);
        check(returned == (mode != 0), "original availability result preserved");
        check(primary_calls == ((mode & 1) ? 1u : 0u), "primary called exactly once when available");
        check(fallback_calls == (mode == 2 ? 1u : 0u), "fallback used only without primary");
        check(war_begins == (mode ? war_enabled : 0) && war_finishes == war_begins, "war observers balanced");
        check(relation_begins == (mode ? relation_enabled : 0) && relation_finishes == relation_begins,
            "relation observers balanced");
        check(!mode || last_argument == &object, "original argument preserved");
        check(mode ? order == expected : order.empty(), "all observers wrap exactly one original call");
    }
    std::printf("{\"checks\":%u,\"failures\":%u,\"war_enabled\":%u,\"relation_enabled\":%u}\n",
        checks, failures, war_enabled, relation_enabled);
    return failures ? 1 : 0;
}
