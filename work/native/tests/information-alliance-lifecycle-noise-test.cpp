// Private fixture for the production lifecycle destructor decision.
// The 310 runner extracts the exact production function into the marker below,
// replacing only __builtin_return_address(0) with fake_caller.

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

using DWORD = std::uint32_t;
using LONG = std::int32_t;
using LONG64 = std::int64_t;

enum LifecycleEventKind : unsigned char {
    lifecycle_clone_event = 1,
    lifecycle_wrapper_event = 2,
    lifecycle_destructor_event = 3,
    lifecycle_serialization_event = 4,
    lifecycle_destructor_return_event = 5,
};

struct LifecycleActionShape {
    std::uintptr_t address = 0;
    std::uintptr_t vtable = 0;
    std::int32_t state34 = 0;
    unsigned char variant38 = 0;
    std::int32_t proposal3c = 0;
    bool readable = false;
    bool handles_canonical = false;
    bool matched = false;
    bool tracked = false;
};

struct LifecycleEvent {
    std::uint64_t sequence = 0;
    std::uintptr_t caller_return = 0;
    std::int32_t observed_game_date_raw = 0;
    bool observed_game_date_verified = false;
    std::uint64_t source_event_id = 0;
    std::uint64_t target_event_id = 0;
    DWORD thread = 0;
    LifecycleEventKind kind = lifecycle_clone_event;
    LifecycleActionShape source{};
    std::uintptr_t native_result = 0;
    unsigned native_flags = 0;
    char query_id[65]{};
};

using LifecycleDestructorMethod = void* (*)(void*, unsigned);

static constexpr std::uintptr_t base = UINT64_C(0x140000000);
static constexpr std::uintptr_t lifecycle_destructor_vtable_rva = 0x1000;
static constexpr std::uintptr_t lifecycle_peace_vtable_rva = 0x2000;
static constexpr std::uintptr_t lifecycle_declarewar_vtable_rva = 0x3000;
static constexpr std::uintptr_t lifecycle_royal_vtable_rva = 0x4000;
static constexpr std::uintptr_t lifecycle_insult_vtable_rva = 0x5000;
static constexpr std::uintptr_t lifecycle_favor_trust_vtable_rva = 0x6000;
static constexpr std::uintptr_t lifecycle_gift_vtable_rva = 0x7000;
static constexpr std::uintptr_t source_address = UINT64_C(0x230000000);
static constexpr std::uintptr_t fake_game_address = UINT64_C(0x240000000);
static constexpr std::uintptr_t fake_result = UINT64_C(0xfeedface12345678);
static constexpr std::int32_t fake_game_date = 56657472;
static constexpr DWORD default_thread = 77;

static DWORD current_thread = default_thread;
static DWORD frame_thread = default_thread;
static const char* observation_active_query = nullptr;
static std::uintptr_t fake_caller = base + 0xf0bf77;
static LifecycleActionShape fake_shape{};
static bool source_released = false;
static unsigned capture_calls = 0;
static unsigned post_release_reads = 0;
static unsigned original_calls = 0;
static unsigned callback_calls = 0;
static unsigned callback_flags = 0;
static std::vector<std::string> call_order;
static std::vector<LifecycleEvent> events;
static volatile LONG64 lifecycle_temporary_ui_cleanup_suppressed = 0;
static volatile LONG64 observation_callback_sequence = 0;

static LifecycleDestructorMethod lifecycle_destructor_original = nullptr;
static LifecycleDestructorMethod lifecycle_peace_destructor_original = nullptr;
static LifecycleDestructorMethod lifecycle_declarewar_destructor_original = nullptr;
static LifecycleDestructorMethod lifecycle_royal_destructor_original = nullptr;
static LifecycleDestructorMethod lifecycle_insult_destructor_original = nullptr;
static LifecycleDestructorMethod lifecycle_favor_trust_destructor_original = nullptr;
static LifecycleDestructorMethod lifecycle_gift_destructor_original = nullptr;

static inline LONG64 InterlockedIncrement64(volatile LONG64* value) noexcept {
    return ++(*value);
}

static inline DWORD GetCurrentThreadId() noexcept { return current_thread; }

template <typename T>
static bool read(std::uintptr_t address, T& output) noexcept {
    if (address == source_address) {
        output = static_cast<T>(base + lifecycle_destructor_vtable_rva);
        return true;
    }
    if (address == base + 0x233fe58) {
        output = static_cast<T>(fake_game_address);
        return true;
    }
    if (address == fake_game_address + 0x1dd0) {
        output = static_cast<T>(fake_game_date);
        return true;
    }
    return false;
}

static LifecycleActionShape lifecycle_capture_shape(void* source) {
    ++capture_calls;
    if (source_released) ++post_release_reads;
    LifecycleActionShape result = fake_shape;
    result.address = reinterpret_cast<std::uintptr_t>(source);
    return result;
}

static std::uint64_t lifecycle_next_sequence() {
    return static_cast<std::uint64_t>(InterlockedIncrement64(
        &observation_callback_sequence));
}

static void lifecycle_enqueue(const LifecycleEvent& event) {
    call_order.emplace_back(event.kind == lifecycle_destructor_event
                                ? "enqueue:destructor"
                                : "enqueue:destructor_return");
    events.push_back(event);
}

static void lifecycle_copy_query(char (&destination)[65]) {
    destination[0] = 0;
    if (GetCurrentThreadId() != frame_thread || observation_active_query == nullptr) {
        return;
    }
    std::strncpy(destination, observation_active_query, 64);
    destination[64] = 0;
}

static void execution_lifecycle_source_destroyed(
    void*, const LifecycleActionShape&, unsigned flags) {
    ++callback_calls;
    callback_flags = flags;
    call_order.emplace_back("callback");
}

static void* fake_original(void*, unsigned flags) {
    ++original_calls;
    call_order.emplace_back("original");
    if (flags == 0xdeadbeefu) return nullptr;
    source_released = true;
    return reinterpret_cast<void*>(fake_result);
}

// __EXTRACTED_PRODUCTION_DESTRUCTOR__

struct CaseSpec {
    const char* name;
    std::uintptr_t caller;
    DWORD thread;
    const char* query;
    unsigned flags;
    LifecycleActionShape shape;
    bool suppressed;
};

static bool equal_shape(const LifecycleActionShape& left,
                        const LifecycleActionShape& right) {
    return left.state34 == right.state34
        && left.variant38 == right.variant38
        && left.proposal3c == right.proposal3c
        && left.readable == right.readable
        && left.handles_canonical == right.handles_canonical
        && left.matched == right.matched
        && left.tracked == right.tracked;
}

static bool run_case(const CaseSpec& spec, std::string& failure) {
    fake_caller = spec.caller;
    current_thread = spec.thread;
    observation_active_query = spec.query;
    fake_shape = spec.shape;
    capture_calls = post_release_reads = original_calls = callback_calls = 0;
    callback_flags = 0;
    source_released = false;
    call_order.clear();
    events.clear();
    lifecycle_temporary_ui_cleanup_suppressed = 0;
    observation_callback_sequence = 0;
    lifecycle_destructor_original = &fake_original;
    lifecycle_peace_destructor_original = nullptr;
    lifecycle_declarewar_destructor_original = nullptr;
    lifecycle_royal_destructor_original = nullptr;
    lifecycle_insult_destructor_original = nullptr;
    lifecycle_favor_trust_destructor_original = nullptr;
    lifecycle_gift_destructor_original = nullptr;

    void* result = lifecycle_destructor_observe(
        reinterpret_cast<void*>(source_address), spec.flags);
    const unsigned expected_events = spec.shape.tracked && !spec.suppressed ? 2u : 0u;
    const unsigned expected_callback = spec.shape.tracked ? 1u : 0u;
    const LONG64 expected_suppressed = spec.suppressed ? 1 : 0;
    const bool result_ok = reinterpret_cast<std::uintptr_t>(result) == fake_result;
    const bool order_ok = spec.shape.tracked
        ? (spec.suppressed
            ? call_order == std::vector<std::string>{"callback", "original"}
            : call_order == std::vector<std::string>{
                "callback", "enqueue:destructor", "original",
                "enqueue:destructor_return"})
        : call_order == std::vector<std::string>{"original"};
    bool events_ok = events.size() == expected_events;
    if (events_ok && !events.empty()) {
        events_ok = events[0].kind == lifecycle_destructor_event
            && events[1].kind == lifecycle_destructor_return_event
            && events[0].caller_return == spec.caller
            && events[1].caller_return == spec.caller
            && events[1].native_result == fake_result
            && equal_shape(events[0].source, spec.shape)
            && equal_shape(events[1].source, spec.shape);
    }
    const bool ok = result_ok
        && original_calls == 1u
        && callback_calls == expected_callback
        && callback_flags == (spec.shape.tracked ? spec.flags : 0u)
        && events_ok
        && order_ok
        && capture_calls == 1u
        && post_release_reads == 0u
        && lifecycle_temporary_ui_cleanup_suppressed == expected_suppressed;
    if (!ok) {
        failure = spec.name;
        return false;
    }
    return true;
}

int main() {
    const LifecycleActionShape eligible{0, 0, 0, 1, 0, true, true, true, true};
    const std::uintptr_t expected_caller = base + 0xf0bf77;
    const std::uintptr_t expiry_caller = base + 0x2f04b9;
    const std::vector<CaseSpec> cases = {
        {"all_guards_match_suppresses_two_rows", expected_caller, default_thread,
         nullptr, 1u, eligible, true},
        {"caller_guard_broken", base + 0x1234, default_thread, nullptr, 1u,
         eligible, false},
        {"expiry_caller_is_not_ui_cleanup", expiry_caller, default_thread,
         nullptr, 1u, eligible, false},
        {"frame_thread_guard_broken", expected_caller, default_thread + 1u,
         nullptr, 1u, eligible, false},
        {"active_query_retains_rows", expected_caller, default_thread, "q-1", 1u,
         eligible, false},
        {"flags_guard_broken", expected_caller, default_thread, nullptr, 2u,
         eligible, false},
        {"readable_guard_broken", expected_caller, default_thread, nullptr, 1u,
         LifecycleActionShape{0, 0, 0, 1, 0, false, true, true, true}, false},
        {"matched_guard_broken", expected_caller, default_thread, nullptr, 1u,
         LifecycleActionShape{0, 0, 0, 1, 0, true, true, false, true}, false},
        {"canonical_guard_broken", expected_caller, default_thread, nullptr, 1u,
         LifecycleActionShape{0, 0, 0, 1, 0, true, false, true, true}, false},
        {"state_guard_broken", expected_caller, default_thread, nullptr, 1u,
         LifecycleActionShape{0, 0, 1, 1, 0, true, true, true, true}, false},
        {"variant_guard_broken", expected_caller, default_thread, nullptr, 1u,
         LifecycleActionShape{0, 0, 0, 0, 0, true, true, true, true}, false},
        {"proposal_guard_broken", expected_caller, default_thread, nullptr, 1u,
         LifecycleActionShape{0, 0, 0, 1, 7, true, true, true, true}, false},
        {"untracked_preserves_original_only", expected_caller, default_thread,
         nullptr, 1u,
         LifecycleActionShape{0, 0, 0, 1, 0, true, true, true, false}, false},
    };
    unsigned passed = 0;
    std::vector<std::string> failures;
    for (const CaseSpec& spec : cases) {
        std::string failure;
        if (run_case(spec, failure)) {
            ++passed;
        } else {
            failures.push_back(failure);
        }
    }
    std::printf(
        "{\"passed\":%s,\"case_count\":%u,\"passed_cases\":%u,"
        "\"failures\":%u,\"production_function\":\"lifecycle_destructor_observe\","
        "\"fake_caller_seam\":true,\"game_access\":false,"
        "\"dll_build\":false,\"rea_or_rpm\":false}\n",
        failures.empty() ? "true" : "false",
        static_cast<unsigned>(cases.size()), passed,
        static_cast<unsigned>(failures.size()));
    for (const std::string& failure : failures) {
        std::fprintf(stderr, "FAILED:%s\n", failure.c_str());
    }
    return failures.empty() ? 0 : 1;
}

