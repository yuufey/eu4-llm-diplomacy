#define WIN32_LEAN_AND_MEAN
#define INFORMATION_BATTLE_NATIVE_TEXT 1
#include <windows.h>

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>

#include "entry-patch-transaction.inc"

namespace {

#if defined(INFORMATION_BATTLE_RETREAT) \
        && defined(INFORMATION_BATTLE_NAME_HANDOFF)
constexpr unsigned kTargetCount = 10;
#elif defined(INFORMATION_BATTLE_RETREAT)
constexpr unsigned kTargetCount = 9;
#elif defined(INFORMATION_BATTLE_NAME_HANDOFF)
constexpr unsigned kTargetCount = 7;
#elif defined(INFORMATION_BATTLE_GATE_TRACE)
constexpr unsigned kTargetCount = 6;
#else
constexpr unsigned kTargetCount = 5;
#endif
constexpr unsigned kFixtureTargetCapacity = 10;
constexpr unsigned kPatchSize = 15;
constexpr unsigned kTrampolineSize = 29;
constexpr SIZE_T kPageBytes = 0x1000u;

static_assert(bridge_entry_patch::kMaxTargets == kTargetCount,
              "transaction target capacity must match the selected build");
static_assert(bridge_entry_patch::kMaxPages == 2u * kTargetCount,
              "native text page bound must be two pages per target");
static_assert(kTargetCount <= kFixtureTargetCapacity,
              "fixture function tables must cover every selected target");
#if defined(INFORMATION_BATTLE_RETREAT) \
        && defined(INFORMATION_BATTLE_NAME_HANDOFF)
static_assert(bridge_entry_patch::kMaxTargets >= 10u,
              "retreat plus name handoff needs capacity for ten targets");
#elif defined(INFORMATION_BATTLE_RETREAT)
static_assert(bridge_entry_patch::kMaxTargets >= 9u,
              "retreat build needs capacity for nine targets");
#endif

const unsigned char kExpected[kPatchSize] = {
    0x48, 0x89, 0x5c, 0x24, 0x08,
    0x48, 0x89, 0x6c, 0x24, 0x10,
    0x48, 0x89, 0x74, 0x24, 0x18,
};

using TargetFunction = std::uint64_t (*)(std::uint64_t, std::uint64_t,
    std::uint64_t, std::uint64_t, std::uint64_t, std::uint64_t);

struct TargetSlot {
    unsigned char* target = nullptr;
    unsigned char* trampoline = nullptr;
    void* forward = nullptr;
    unsigned char replacement[kPatchSize]{};
};

TargetSlot g_slots[kFixtureTargetCapacity]{};
volatile LONG64 g_forward_hits[kFixtureTargetCapacity]{};
volatile LONG64 g_body_hits[kFixtureTargetCapacity]{};
volatile LONG64 g_worker_ticks = 0;
volatile LONG g_stop_worker = 0;
unsigned g_failures = 0;

void check(bool condition, const char* label) {
    std::printf("CHECK %s %s\n", label, condition ? "PASS" : "FAIL");
    if (!condition) {
        ++g_failures;
    }
}

void check_target(bool condition, const char* suffix) {
    const char* prefix = kTargetCount == 5u ? "five_target"
        : (kTargetCount == 9u ? "nine_target"
           : (kTargetCount == 10u ? "ten_target" : "multi_target"));
    char label[80]{};
    std::snprintf(label, sizeof(label), "%s_%s", prefix, suffix);
    check(condition, label);
}

std::uint64_t expected_result(unsigned index, std::uint64_t a,
                              std::uint64_t b, std::uint64_t c,
                              std::uint64_t d, std::uint64_t e,
                              std::uint64_t f) {
    return UINT64_C(0xa000000000000000)
        + static_cast<std::uint64_t>(index) * UINT64_C(0x100)
        + a + b * UINT64_C(3) + c * UINT64_C(5) + d * UINT64_C(7)
        + e * UINT64_C(11) + f * UINT64_C(13);
}

std::uint64_t body_impl(unsigned index, std::uint64_t a, std::uint64_t b,
                        std::uint64_t c, std::uint64_t d,
                        std::uint64_t e, std::uint64_t f) {
    InterlockedIncrement64(&g_body_hits[index]);
    return expected_result(index, a, b, c, d, e, f);
}

std::uint64_t forward_impl(unsigned index, std::uint64_t a,
                           std::uint64_t b, std::uint64_t c,
                           std::uint64_t d, std::uint64_t e,
                           std::uint64_t f) {
    InterlockedIncrement64(&g_forward_hits[index]);
    const auto original = reinterpret_cast<TargetFunction>(
        g_slots[index].trampoline);
    return original(a, b, c, d, e, f);
}

extern "C" std::uint64_t body0(std::uint64_t a, std::uint64_t b,
    std::uint64_t c, std::uint64_t d, std::uint64_t e, std::uint64_t f) {
    return body_impl(0, a, b, c, d, e, f);
}
extern "C" std::uint64_t body1(std::uint64_t a, std::uint64_t b,
    std::uint64_t c, std::uint64_t d, std::uint64_t e, std::uint64_t f) {
    return body_impl(1, a, b, c, d, e, f);
}
extern "C" std::uint64_t body2(std::uint64_t a, std::uint64_t b,
    std::uint64_t c, std::uint64_t d, std::uint64_t e, std::uint64_t f) {
    return body_impl(2, a, b, c, d, e, f);
}
extern "C" std::uint64_t body3(std::uint64_t a, std::uint64_t b,
    std::uint64_t c, std::uint64_t d, std::uint64_t e, std::uint64_t f) {
    return body_impl(3, a, b, c, d, e, f);
}
extern "C" std::uint64_t body4(std::uint64_t a, std::uint64_t b,
    std::uint64_t c, std::uint64_t d, std::uint64_t e, std::uint64_t f) {
    return body_impl(4, a, b, c, d, e, f);
}
extern "C" std::uint64_t body5(std::uint64_t a, std::uint64_t b,
    std::uint64_t c, std::uint64_t d, std::uint64_t e, std::uint64_t f) {
    return body_impl(5, a, b, c, d, e, f);
}
extern "C" std::uint64_t body6(std::uint64_t a, std::uint64_t b,
    std::uint64_t c, std::uint64_t d, std::uint64_t e, std::uint64_t f) {
    return body_impl(6, a, b, c, d, e, f);
}
extern "C" std::uint64_t body7(std::uint64_t a, std::uint64_t b,
    std::uint64_t c, std::uint64_t d, std::uint64_t e, std::uint64_t f) {
    return body_impl(7, a, b, c, d, e, f);
}
extern "C" std::uint64_t body8(std::uint64_t a, std::uint64_t b,
    std::uint64_t c, std::uint64_t d, std::uint64_t e, std::uint64_t f) {
    return body_impl(8, a, b, c, d, e, f);
}
extern "C" std::uint64_t body9(std::uint64_t a, std::uint64_t b,
    std::uint64_t c, std::uint64_t d, std::uint64_t e, std::uint64_t f) {
    return body_impl(9, a, b, c, d, e, f);
}

extern "C" std::uint64_t forward0(std::uint64_t a, std::uint64_t b,
    std::uint64_t c, std::uint64_t d, std::uint64_t e, std::uint64_t f) {
    return forward_impl(0, a, b, c, d, e, f);
}
extern "C" std::uint64_t forward1(std::uint64_t a, std::uint64_t b,
    std::uint64_t c, std::uint64_t d, std::uint64_t e, std::uint64_t f) {
    return forward_impl(1, a, b, c, d, e, f);
}
extern "C" std::uint64_t forward2(std::uint64_t a, std::uint64_t b,
    std::uint64_t c, std::uint64_t d, std::uint64_t e, std::uint64_t f) {
    return forward_impl(2, a, b, c, d, e, f);
}
extern "C" std::uint64_t forward3(std::uint64_t a, std::uint64_t b,
    std::uint64_t c, std::uint64_t d, std::uint64_t e, std::uint64_t f) {
    return forward_impl(3, a, b, c, d, e, f);
}
extern "C" std::uint64_t forward4(std::uint64_t a, std::uint64_t b,
    std::uint64_t c, std::uint64_t d, std::uint64_t e, std::uint64_t f) {
    return forward_impl(4, a, b, c, d, e, f);
}
extern "C" std::uint64_t forward5(std::uint64_t a, std::uint64_t b,
    std::uint64_t c, std::uint64_t d, std::uint64_t e, std::uint64_t f) {
    return forward_impl(5, a, b, c, d, e, f);
}
extern "C" std::uint64_t forward6(std::uint64_t a, std::uint64_t b,
    std::uint64_t c, std::uint64_t d, std::uint64_t e, std::uint64_t f) {
    return forward_impl(6, a, b, c, d, e, f);
}
extern "C" std::uint64_t forward7(std::uint64_t a, std::uint64_t b,
    std::uint64_t c, std::uint64_t d, std::uint64_t e, std::uint64_t f) {
    return forward_impl(7, a, b, c, d, e, f);
}
extern "C" std::uint64_t forward8(std::uint64_t a, std::uint64_t b,
    std::uint64_t c, std::uint64_t d, std::uint64_t e, std::uint64_t f) {
    return forward_impl(8, a, b, c, d, e, f);
}
extern "C" std::uint64_t forward9(std::uint64_t a, std::uint64_t b,
    std::uint64_t c, std::uint64_t d, std::uint64_t e, std::uint64_t f) {
    return forward_impl(9, a, b, c, d, e, f);
}

using CodeFunction = std::uint64_t (*)(std::uint64_t, std::uint64_t,
    std::uint64_t, std::uint64_t, std::uint64_t, std::uint64_t);

const CodeFunction kBodies[kFixtureTargetCapacity] = {
    &body0, &body1, &body2, &body3, &body4,
    &body5, &body6, &body7, &body8, &body9,
};
const CodeFunction kForwards[kFixtureTargetCapacity] = {
    &forward0, &forward1, &forward2, &forward3, &forward4,
    &forward5, &forward6, &forward7, &forward8, &forward9,
};

void write_absolute_jump(unsigned char* destination, const void* target,
                         unsigned capacity) {
    if (capacity < 12u) {
        return;
    }
    const std::uint64_t address = reinterpret_cast<std::uint64_t>(target);
    destination[0] = 0x48;
    destination[1] = 0xb8;
    std::memcpy(destination + 2, &address, sizeof(address));
    destination[10] = 0xff;
    destination[11] = 0xe0;
    for (unsigned index = 12; index != capacity; ++index) {
        destination[index] = 0x90;
    }
}

bool make_rx_code(void* body, unsigned char*& output) {
    output = static_cast<unsigned char*>(VirtualAlloc(
        nullptr, kPageBytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!output) {
        return false;
    }
    std::memcpy(output, kExpected, kPatchSize);
    write_absolute_jump(output + kPatchSize, body,
                        kTrampolineSize - kPatchSize);
    DWORD old_protection = 0;
    if (!VirtualProtect(output, kPageBytes, PAGE_EXECUTE_READ,
                        &old_protection)) {
        return false;
    }
    return FlushInstructionCache(GetCurrentProcess(), output, kPageBytes)
        != FALSE;
}

void make_replacement(unsigned char* replacement, const void* forward) {
    write_absolute_jump(replacement, forward, kPatchSize);
}

bool is_rx(void* address) {
    MEMORY_BASIC_INFORMATION info{};
    return VirtualQuery(address, &info, sizeof(info)) == sizeof(info)
        && info.State == MEM_COMMIT && info.Protect == PAGE_EXECUTE_READ;
}

bool bytes_equal(const void* address, const unsigned char* expected,
                 std::size_t size) {
    return std::memcmp(address, expected, size) == 0;
}

DWORD WINAPI recovery_worker(void*) {
    while (InterlockedCompareExchange(&g_stop_worker, 0, 0) == 0) {
        InterlockedIncrement64(&g_worker_ticks);
        Sleep(1);
    }
    return 0;
}

void cleanup_worker(HANDLE worker) {
    InterlockedExchange(&g_stop_worker, 1);
    if (worker) {
        WaitForSingleObject(worker, 5000);
        CloseHandle(worker);
    }
}

}  // namespace

int main() {
    if (kTargetCount == 5u) {
        std::printf("TEST information-battle-entry-patch-five-targets\n");
    } else {
        std::printf("TEST information-battle-entry-patch-%u-targets\n",
                    kTargetCount);
    }

    bool allocations_ok = true;
    for (unsigned index = 0; index != kTargetCount; ++index) {
        allocations_ok = make_rx_code(
            reinterpret_cast<void*>(kBodies[index]), g_slots[index].target)
            && allocations_ok;
        allocations_ok = make_rx_code(
            reinterpret_cast<void*>(kBodies[index]), g_slots[index].trampoline)
            && allocations_ok;
        g_slots[index].forward = reinterpret_cast<void*>(kForwards[index]);
        make_replacement(g_slots[index].replacement, g_slots[index].forward);
    }
    if (kTargetCount == 5u) {
        check(allocations_ok,
              "five_private_rx_targets_and_trampolines_allocated");
    } else {
        check_target(allocations_ok,
                     "private_rx_targets_and_trampolines_allocated");
    }
    if (!allocations_ok) {
        std::printf("SUMMARY checks_failed=%u status=FAIL\n", g_failures);
        std::printf("RESULT FAIL\n");
        return 1;
    }

    for (unsigned index = 0; index != kTargetCount; ++index) {
        check(g_slots[index].target != g_slots[index + 0].trampoline,
              "target_and_trampoline_distinct");
        check(is_rx(g_slots[index].target), "target_private_rx");
        check(is_rx(g_slots[index].trampoline), "trampoline_private_rx");
    }

    const auto call_target = [](unsigned index, std::uint64_t seed) {
        const auto target = reinterpret_cast<TargetFunction>(
            g_slots[index].target);
        return target(seed + 1, seed + 2, seed + 3, seed + 4,
                      seed + 5, seed + 6);
    };
    for (unsigned index = 0; index != kTargetCount; ++index) {
        const std::uint64_t seed = UINT64_C(0x1000) + index * 0x100;
        const std::uint64_t actual = call_target(index, seed);
        check(actual == expected_result(index, seed + 1, seed + 2,
                                        seed + 3, seed + 4, seed + 5,
                                        seed + 6), "pre_patch_original_body");
    }

    bridge_entry_patch::PatchPlan plan{};
    plan.count = kTargetCount;
    for (unsigned index = 0; index != kTargetCount; ++index) {
        plan.targets[index].address = g_slots[index].target;
        plan.targets[index].size = kPatchSize;
        plan.targets[index].expected = kExpected;
        plan.targets[index].replacement = g_slots[index].replacement;
        plan.targets[index].original_trampoline = g_slots[index].trampoline;
        plan.targets[index].original_trampoline_size = kTrampolineSize;
    }

    InterlockedExchange(&g_stop_worker, 0);
    HANDLE worker = CreateThread(nullptr, 0, recovery_worker, nullptr, 0,
                                 nullptr);
    check(worker != nullptr, "recovery_worker_created");
    Sleep(25);
    const LONG64 worker_before = InterlockedCompareExchange64(
        &g_worker_ticks, 0, 0);

    const bridge_entry_patch::PatchResult applied =
        bridge_entry_patch::guarded_patch_apply(plan);
    check_target(applied.status == bridge_entry_patch::PatchStatus::success,
                 "apply_status_success");
    check_target(applied.published && applied.success,
                 "apply_published_success");
    check_target(applied.pending_count == 0 && applied.threads_resumed,
                 "apply_no_pending_threads_resumed");
    check_target(applied.protection_restored,
                 "apply_protection_restored");
    check_target(applied.thread_count >= 1 && applied.suspended_count >= 1,
                 "apply_observed_worker_suspend");

    Sleep(25);
    const LONG64 worker_after = InterlockedCompareExchange64(
        &g_worker_ticks, 0, 0);
    check(worker_after > worker_before, "recovery_worker_progress_after_apply");
    for (unsigned index = 0; index != kTargetCount; ++index) {
        check_target(bytes_equal(g_slots[index].target,
                                 g_slots[index].replacement, kPatchSize),
                     "replacement_published");
        check_target(is_rx(g_slots[index].target),
                     "protection_after_apply");
    }

    for (unsigned index = 0; index != kTargetCount; ++index) {
        const std::uint64_t seed = UINT64_C(0x2000) + index * 0x100;
        const LONG64 old_forward = InterlockedCompareExchange64(
            &g_forward_hits[index], 0, 0);
        const LONG64 old_body = InterlockedCompareExchange64(
            &g_body_hits[index], 0, 0);
        const std::uint64_t actual = call_target(index, seed);
        check(actual == expected_result(index, seed + 1, seed + 2,
                                        seed + 3, seed + 4, seed + 5,
                                        seed + 6), "patched_original_forward_result");
        check(InterlockedCompareExchange64(&g_forward_hits[index], 0, 0)
                  == old_forward + 1,
              "patched_forward_shim_hit");
        check(InterlockedCompareExchange64(&g_body_hits[index], 0, 0)
                  == old_body + 1,
              "patched_original_trampoline_body_hit");
    }

    const bridge_entry_patch::PatchResult rolled =
        bridge_entry_patch::guarded_patch_rollback(plan);
    check_target(rolled.status == bridge_entry_patch::PatchStatus::rollback_complete,
                 "rollback_status_complete");
    check_target(rolled.rollback_complete && rolled.success,
                 "rollback_complete_success");
    check_target(rolled.pending_count == 0 && rolled.threads_resumed,
                 "rollback_no_pending_threads_resumed");
    check_target(rolled.protection_restored,
                 "rollback_protection_restored");
    for (unsigned index = 0; index != kTargetCount; ++index) {
        check_target(bytes_equal(g_slots[index].target, kExpected, kPatchSize),
                     "source_restored");
        check_target(is_rx(g_slots[index].target),
                     "protection_after_rollback");
    }

    cleanup_worker(worker);
    const bridge_entry_patch::PatchResult pending_retry =
        bridge_entry_patch::guarded_patch_retry_pending();
    check(pending_retry.pending_count == 0, "pending_retry_empty");
    std::printf("SUMMARY checks_failed=%u status=%s\n", g_failures,
                g_failures == 0 ? "PASS" : "FAIL");
    std::printf(
        "{\"passed\":%s,\"target_count\":%u,\"max_targets\":%u,"
        "\"max_pages\":%u,\"apply_status\":%u,"
        "\"apply_pending\":%u,\"apply_threads_resumed\":%s,"
        "\"apply_protection_restored\":%s,\"rollback_status\":%u,"
        "\"rollback_pending\":%u,\"rollback_threads_resumed\":%s,"
        "\"rollback_protection_restored\":%s,\"worker_before\":%lld,"
        "\"worker_after\":%lld,\"checks_failed\":%u}\n",
        g_failures == 0 ? "true" : "false", kTargetCount,
        bridge_entry_patch::kMaxTargets, bridge_entry_patch::kMaxPages,
        static_cast<unsigned>(applied.status), applied.pending_count,
        applied.threads_resumed ? "true" : "false",
        applied.protection_restored ? "true" : "false",
        static_cast<unsigned>(rolled.status), rolled.pending_count,
        rolled.threads_resumed ? "true" : "false",
        rolled.protection_restored ? "true" : "false",
        static_cast<long long>(worker_before), static_cast<long long>(worker_after),
        g_failures);
    std::printf("RESULT %s\n", g_failures == 0 ? "PASS" : "FAIL");
    return g_failures == 0 ? 0 : 1;
}
