#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "information-battle-entry-plan.h"
#include "information-battle-owned-result.h"

// The transaction is deliberately included in this one-process fixture.  It
// owns no game-specific address and is exercised only against the private
// VirtualAlloc source below.
#include "entry-patch-transaction.inc"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <limits>

extern "C" {
void information_battle_entry_stub(void*, void*, void*, void*,
                                   std::uintptr_t, std::uintptr_t);
void* information_battle_entry_original = nullptr;
}

namespace {

namespace entry = information::battle::entry;
namespace owned = information::battle::owned_result;

constexpr std::size_t kPageBytes = 0x1000u;
constexpr std::size_t kSourceBytes = 0x1000u;
constexpr std::size_t kTrampolineCodeBytes = entry::kCodeBytes;
constexpr std::size_t kSourceUnwindOffset = 0x100u;
constexpr std::size_t kSourceCodeBytes = 72u;
constexpr std::size_t kContinuationOffset = entry::kOriginalPrologue.size();
constexpr std::uintptr_t kSyntheticModuleBase = UINT64_C(0x0000000140000000);
constexpr std::uint32_t kDate = 0x12345678u;
constexpr std::uintptr_t kCombat = UINT64_C(0x1111222233334444);
constexpr std::uintptr_t kSummary = UINT64_C(0x2222333344445555);
constexpr std::uintptr_t kFourthArgument = UINT64_C(0x4444555566667777);
constexpr std::uintptr_t kStackArgument6 = UINT64_C(0x5555666677778888);
constexpr std::uintptr_t kNativeReturn = UINT64_C(0x13579bdf2468ace0);
constexpr DWORD kInitialLastError = 0x13572468u;
constexpr DWORD kCallbackLastError = 0xdead4321u;
constexpr std::size_t kResultOffset = 0x100u;
constexpr std::size_t kProvinceOffset = 0x300u;
constexpr std::size_t kNameHeapOffset = 0x400u;
constexpr std::size_t kCommanderHeapOffset = 0x500u;
constexpr std::size_t kDateOffset = 0x600u;
constexpr std::size_t kResultRegionBytes = 0x1000u;

using NativeFunction = std::uintptr_t (*)(void*, void*, void*, void*,
                                           std::uintptr_t, std::uintptr_t);

struct LocalReader final {
    const unsigned char* begin = nullptr;
    std::size_t size = 0;
    bool fail = false;

    bool read(std::uintptr_t address, unsigned char* destination,
              std::size_t bytes) noexcept {
        if (fail || destination == nullptr || begin == nullptr || bytes == 0u) {
            return false;
        }
        const std::uintptr_t start = reinterpret_cast<std::uintptr_t>(begin);
        const std::uintptr_t maximum =
            std::numeric_limits<std::uintptr_t>::max();
        if (address < start || bytes > maximum - address) {
            return false;
        }
        const std::uintptr_t end = address + bytes;
        if (end < address || end > start + size || start + size < start) {
            return false;
        }
        std::memcpy(destination, reinterpret_cast<const void*>(address), bytes);
        return true;
    }
};

unsigned g_failures = 0;
unsigned g_body_calls = 0;
unsigned g_callback_calls = 0;
unsigned g_copy_failures = 0;
bool g_capture_fail = false;
bool g_snapshot_valid = false;
bool g_tables_registered = false;
bool g_installed = false;
unsigned char* g_source = nullptr;
unsigned char* g_trampoline = nullptr;
unsigned char* g_result_region = nullptr;
std::uintptr_t g_result_pointer = 0;
std::uintptr_t g_date_pointer = 0;
std::uintptr_t g_callback_caller_return = 0;
std::uintptr_t g_callback_original_rbx = 0;
std::uintptr_t g_callback_result = 0;
std::uintptr_t g_callback_combat = 0;
std::uintptr_t g_callback_summary = 0;
owned::Snapshot g_snapshot{};
LocalReader g_reader{};
entry::Plan g_plan{};
RUNTIME_FUNCTION g_source_function{};
RUNTIME_FUNCTION g_trampoline_function{};

void check(bool condition, const char* name) noexcept {
    std::printf("CHECK %s %s\n", name, condition ? "PASS" : "FAIL");
    if (!condition) {
        ++g_failures;
    }
}

void write_u64(unsigned char* destination, std::uint64_t value) noexcept {
    std::memcpy(destination, &value, sizeof(value));
}

void write_i32(unsigned char* destination, std::int32_t value) noexcept {
    std::memcpy(destination, &value, sizeof(value));
}

void set_inline_string(unsigned char* destination, const char* text,
                       std::size_t length) noexcept {
    std::memset(destination, 0, 0x20u);
    std::memcpy(destination, text, length);
    destination[length] = 0;
    write_u64(destination + 0x10u, static_cast<std::uint64_t>(length));
    write_u64(destination + 0x18u, static_cast<std::uint64_t>(length));
}

void set_heap_string(unsigned char* destination, unsigned char* heap,
                     const char* text, std::size_t length,
                     std::size_t capacity) noexcept {
    std::memset(destination, 0, 0x20u);
    std::memcpy(heap, text, length);
    heap[length] = 0;
    write_u64(destination, reinterpret_cast<std::uintptr_t>(heap));
    write_u64(destination + 0x10u, static_cast<std::uint64_t>(length));
    write_u64(destination + 0x18u, static_cast<std::uint64_t>(capacity));
}

void initialize_fake_result() noexcept {
    std::memset(g_result_region, 0, kResultRegionBytes);
    unsigned char* result = g_result_region + kResultOffset;
    const std::uintptr_t result_vtable =
        kSyntheticModuleBase + owned::kResultVtableRva;
    const std::uintptr_t side_vtable =
        kSyntheticModuleBase + owned::kSideVtableRva;
    write_u64(result, result_vtable);
    write_u64(result + owned::kResultSideAOffset, side_vtable);
    write_u64(result + owned::kResultSideBOffset, side_vtable);

    unsigned char* side_a = result + owned::kResultSideAOffset;
    unsigned char* side_b = result + owned::kResultSideBOffset;
    write_u64(side_a + owned::kSideCountryOffset, UINT64_C(0x465241));
    write_u64(side_b + owned::kSideCountryOffset, UINT64_C(0x454e47));
    set_inline_string(side_a + owned::kSideCommanderOffset,
                      "A-CMD", 5u);
    set_heap_string(side_b + owned::kSideCommanderOffset,
                    g_result_region + kCommanderHeapOffset,
                    "B-HEAP-COMMANDER", 16u, 32u);
    for (std::size_t index = 0; index < owned::kSideRawFieldOffsets.size();
         ++index) {
        write_i32(side_a + owned::kSideRawFieldOffsets[index],
                  static_cast<std::int32_t>(100 + index));
        write_i32(side_b + owned::kSideRawFieldOffsets[index],
                  static_cast<std::int32_t>(200 + index));
    }

    write_i32(result + owned::kResultAux100Offset, -17);
    write_i32(result + owned::kResultAux104Offset, 23);
    result[owned::kResultFlag108Offset] = 1u;
    const std::uintptr_t province =
        reinterpret_cast<std::uintptr_t>(g_result_region + kProvinceOffset);
    write_u64(result + owned::kResultProvincePointerOffset, province);
    write_i32(g_result_region + kProvinceOffset + owned::kProvinceIdOffset,
              1285);
    set_heap_string(result + owned::kResultNameOffset,
                    g_result_region + kNameHeapOffset,
                    "synthetic-battle-name", 21u, 32u);
    write_i32(g_result_region + kDateOffset,
              static_cast<std::int32_t>(kDate));
}

bool snapshot_matches_fixture(const owned::Snapshot& snapshot) noexcept {
    static constexpr unsigned char kName[] = "synthetic-battle-name";
    static constexpr unsigned char kCommander[] = "B-HEAP-COMMANDER";
    if (snapshot.raw_date != static_cast<std::int32_t>(kDate)
        || snapshot.flag108 != 1u || snapshot.aux100 != -17
        || snapshot.aux104 != 23 || snapshot.province_id != 1285
        || snapshot.name.length != 21u || snapshot.name.capacity != 32u
        || std::memcmp(snapshot.name.bytes.data(), kName, 21u) != 0
        || snapshot.sides[0].country != UINT64_C(0x465241)
        || snapshot.sides[1].country != UINT64_C(0x454e47)
        || snapshot.sides[1].commander.length != 16u
        || snapshot.sides[1].commander.capacity != 32u
        || std::memcmp(snapshot.sides[1].commander.bytes.data(),
                       kCommander, 16u) != 0) {
        return false;
    }
    for (std::size_t index = 0; index < owned::kSideRawFieldOffsets.size();
         ++index) {
        if (snapshot.sides[0].raw_fields[index]
                != static_cast<std::int32_t>(100 + index)
            || snapshot.sides[1].raw_fields[index]
                != static_cast<std::int32_t>(200 + index)) {
            return false;
        }
    }
    return snapshot.sides[0].commander.length == 5u
        && std::memcmp(snapshot.sides[0].commander.bytes.data(), "A-CMD", 5u)
               == 0;
}

extern "C" std::uintptr_t native_body() noexcept {
    ++g_body_calls;
    // Deliberately destroy the observed object and both heap strings after
    // the callback.  The callback's value object must remain self-contained.
    std::memset(g_result_region + kResultOffset, 0xa5,
                owned::kResultObjectBytes);
    std::memset(g_result_region + kNameHeapOffset, 0xdd, 64u);
    std::memset(g_result_region + kCommanderHeapOffset, 0xee, 64u);
    return kNativeReturn;
}

extern "C" void information_battle_entry_capture(
    void* combat, void* summary, void* result,
    std::uintptr_t caller_return, std::uintptr_t original_rbx) noexcept {
    ++g_callback_calls;
    g_callback_combat = reinterpret_cast<std::uintptr_t>(combat);
    g_callback_summary = reinterpret_cast<std::uintptr_t>(summary);
    g_callback_result = reinterpret_cast<std::uintptr_t>(result);
    g_callback_caller_return = caller_return;
    g_callback_original_rbx = original_rbx;
    SetLastError(kCallbackLastError);
    owned::Snapshot candidate{};
    g_reader.fail = g_capture_fail;
    if (!g_capture_fail
        && owned::capture(g_reader, kSyntheticModuleBase, g_result_pointer,
                          g_date_pointer, candidate)) {
        g_snapshot = candidate;
        g_snapshot_valid = true;
    } else {
        ++g_copy_failures;
    }
}

void append_u64(unsigned char* destination, std::size_t& cursor,
                std::uint64_t value) noexcept {
    std::memcpy(destination + cursor, &value, sizeof(value));
    cursor += sizeof(value);
}

void build_source_body(unsigned char* source) noexcept {
    std::memcpy(source, entry::kOriginalPrologue.data(),
                entry::kOriginalPrologue.size());
    std::size_t cursor = kContinuationOffset;
    source[cursor++] = 0x48u;
    source[cursor++] = 0xb8u;  // movabs rax, native_body
    append_u64(source, cursor,
               reinterpret_cast<std::uintptr_t>(&native_body));
    source[cursor++] = 0xffu;
    source[cursor++] = 0xd0u;  // call rax
    source[cursor++] = 0x48u;
    source[cursor++] = 0x81u;
    source[cursor++] = 0xc4u;
    source[cursor++] = 0xa0u;
    source[cursor++] = 0x05u;
    source[cursor++] = 0x00u;
    source[cursor++] = 0x00u;  // add rsp, 0x5a0
    source[cursor++] = 0x41u;
    source[cursor++] = 0x5fu;
    source[cursor++] = 0x41u;
    source[cursor++] = 0x5eu;
    source[cursor++] = 0x41u;
    source[cursor++] = 0x5du;
    source[cursor++] = 0x41u;
    source[cursor++] = 0x5cu;  // pop r15..r12
    source[cursor++] = 0x5fu;
    source[cursor++] = 0x5eu;
    source[cursor++] = 0x5du;  // pop rdi/rsi/rbp
    source[cursor++] = 0x48u;
    source[cursor++] = 0x8bu;
    source[cursor++] = 0x5cu;
    source[cursor++] = 0x24u;
    source[cursor++] = 0x10u;  // mov rbx,[entry_rsp+10h]
    source[cursor++] = 0xc3u;
    check(cursor == kSourceCodeBytes, "source_body_size");
}

void build_source_no_handler_unwind(unsigned char* destination) noexcept {
    // Copy all eleven original unwind codes but remove the EHANDLER flag and
    // handler RVA.  The source is a synthetic copy and has no handler.
    std::memset(destination, 0, entry::kOriginalUnwind.size());
    std::memcpy(destination, entry::kOriginalUnwind.data(), 28u);
    destination[0] = 0x01u;
}

bool protect_code(unsigned char* address, std::size_t bytes) noexcept {
    DWORD old_protection = 0;
    if (!VirtualProtect(address, bytes, PAGE_EXECUTE_READ, &old_protection)) {
        return false;
    }
    return FlushInstructionCache(GetCurrentProcess(), address, bytes) != FALSE;
}

__attribute__((noinline)) std::uintptr_t call_source_direct() noexcept {
    const NativeFunction target = reinterpret_cast<NativeFunction>(g_source);
    const std::uintptr_t result = target(
        reinterpret_cast<void*>(kCombat), reinterpret_cast<void*>(kSummary),
        reinterpret_cast<void*>(g_result_pointer),
        reinterpret_cast<void*>(kFourthArgument),
        kStackArgument6, UINT64_C(0x6666777788889999));
    asm volatile("" : : "a"(result) : "memory");
    return result;
}

__attribute__((noinline)) std::uintptr_t call_source_indirect() noexcept {
    volatile NativeFunction target =
        reinterpret_cast<NativeFunction>(g_source);
    const std::uintptr_t result = target(
        reinterpret_cast<void*>(kCombat), reinterpret_cast<void*>(kSummary),
        reinterpret_cast<void*>(g_result_pointer),
        reinterpret_cast<void*>(kFourthArgument),
        kStackArgument6, UINT64_C(0x6666777788889999));
    asm volatile("" : : "a"(result) : "memory");
    return result;
}

bool register_unwind_tables() noexcept {
    g_source_function.BeginAddress = 0;
    g_source_function.EndAddress = static_cast<DWORD>(kSourceCodeBytes);
    g_source_function.UnwindData = static_cast<DWORD>(kSourceUnwindOffset);
    g_trampoline_function = {};
    g_trampoline_function.BeginAddress = g_plan.runtime.begin;
    g_trampoline_function.EndAddress = g_plan.runtime.end;
    g_trampoline_function.UnwindData = g_plan.runtime.unwind;
    if (RtlAddFunctionTable(&g_source_function, 1,
                            reinterpret_cast<DWORD64>(g_source)) == FALSE) {
        return false;
    }
    if (RtlAddFunctionTable(&g_trampoline_function, 1,
                            reinterpret_cast<DWORD64>(g_trampoline)) == FALSE) {
        (void)RtlDeleteFunctionTable(&g_source_function);
        return false;
    }
    g_tables_registered = true;
    return true;
}

bool lookup_tables() noexcept {
    DWORD64 source_base = 0;
    DWORD64 trampoline_base = 0;
    return RtlLookupFunctionEntry(reinterpret_cast<DWORD64>(g_source + 1),
                                  &source_base, nullptr) != nullptr
        && RtlLookupFunctionEntry(
               reinterpret_cast<DWORD64>(g_trampoline + 1),
               &trampoline_base, nullptr) != nullptr
        && source_base == reinterpret_cast<DWORD64>(g_source)
        && trampoline_base == reinterpret_cast<DWORD64>(g_trampoline);
}

void reset_observation() noexcept {
    g_capture_fail = false;
    g_snapshot_valid = false;
    g_callback_caller_return = 0;
    g_callback_original_rbx = 0;
    g_callback_result = 0;
    g_callback_combat = 0;
    g_callback_summary = 0;
    std::memset(&g_snapshot, 0, sizeof(g_snapshot));
    initialize_fake_result();
}

}  // namespace

int main() {
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    std::printf("TEST information-battle-entry-integration\n");

    g_result_region = static_cast<unsigned char*>(VirtualAlloc(
        nullptr, kResultRegionBytes, MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE));
    g_source = static_cast<unsigned char*>(VirtualAlloc(
        nullptr, kSourceBytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    g_trampoline = static_cast<unsigned char*>(VirtualAlloc(
        nullptr, kPageBytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    check(g_result_region != nullptr && g_source != nullptr
              && g_trampoline != nullptr,
          "private_buffers_allocated");
    check(g_source != nullptr && g_trampoline != nullptr
              && g_source != g_trampoline,
          "source_and_trampoline_are_separate_allocations");
    if (!g_result_region || !g_source || !g_trampoline) {
        std::printf("{\"passed\":false,\"reason\":\"allocation\"}\n");
        return 1;
    }

    g_result_pointer = reinterpret_cast<std::uintptr_t>(
        g_result_region + kResultOffset);
    g_date_pointer = reinterpret_cast<std::uintptr_t>(
        g_result_region + kDateOffset);
    g_reader.begin = g_result_region;
    g_reader.size = kResultRegionBytes;
    reset_observation();

    build_source_body(g_source);
    std::array<unsigned char, entry::kOriginalUnwind.size()> source_unwind{};
    build_source_no_handler_unwind(source_unwind.data());
    std::memcpy(g_source + kSourceUnwindOffset, source_unwind.data(),
                source_unwind.size());
    check(source_unwind[0] == 0x01u && source_unwind[1] == 0x24u
              && std::memcmp(g_source + kSourceUnwindOffset,
                             source_unwind.data(), source_unwind.size()) == 0,
          "source_original_11_code_no_handler_unwind");
    check(std::memcmp(g_source, entry::kOriginalPrologue.data(),
                      entry::kOriginalPrologue.size()) == 0,
          "source_first_36_bytes_match_fixed_prefix");

    const auto prepare_status = entry::prepare(
        entry::kOriginalPrologue.data(), entry::kOriginalPrologue.size(),
        entry::kOriginalUnwind.data(), entry::kOriginalUnwind.size(),
        reinterpret_cast<std::uintptr_t>(g_source),
        reinterpret_cast<std::uintptr_t>(&information_battle_entry_stub),
        g_plan);
    check(prepare_status == entry::Status::prepared,
          "entry_plan_prepared");
    if (prepare_status != entry::Status::prepared) {
        std::printf("{\"passed\":false,\"reason\":\"plan\"}\n");
        return 1;
    }
    std::memcpy(g_trampoline, g_plan.image.data(), g_plan.image.size());
    check(std::memcmp(g_trampoline, entry::kOriginalPrologue.data(),
                      entry::kPatchBytes) == 0,
          "trampoline_original_prefix");
    check(std::memcmp(g_trampoline + entry::kUnwindOffset,
                      entry::kProjectedUnwind.data(),
                      entry::kProjectedUnwind.size()) == 0,
          "trampoline_projected_unwind");

    check(protect_code(g_source, kSourceBytes), "source_rx_protection");
    check(protect_code(g_trampoline, kPageBytes), "trampoline_rx_protection");
    check(register_unwind_tables(), "dynamic_unwind_tables_registered");
    check(g_tables_registered && lookup_tables(),
          "dynamic_unwind_tables_lookup");
    if (!g_tables_registered) {
        std::printf("{\"passed\":false,\"reason\":\"unwind\"}\n");
        return 1;
    }
    const bridge_entry_patch::PatchResult no_pending =
        bridge_entry_patch::guarded_patch_retry_pending();
    check(no_pending.success && no_pending.pending_count == 0u,
          "no_pending_transaction_cleanup");

    const std::uint32_t body_before = g_body_calls;
    SetLastError(kInitialLastError);
    check(call_source_direct() == kNativeReturn,
          "preinstall_direct_body_return");
    check(g_body_calls == body_before + 1u && g_callback_calls == 0u,
          "preinstall_body_once_without_callback");
    check(GetLastError() == kInitialLastError, "preinstall_lasterror");

    reset_observation();
    information_battle_entry_original = g_trampoline;
    const void* published_original = information_battle_entry_original;
    bridge_entry_patch::PatchPlan patch_plan{};
    patch_plan.count = 1;
    patch_plan.targets[0].address = g_source;
    patch_plan.targets[0].size = static_cast<unsigned>(entry::kPatchBytes);
    patch_plan.targets[0].expected = entry::kOriginalPrologue.data();
    patch_plan.targets[0].replacement = g_plan.patch.data();
    patch_plan.targets[0].original_trampoline = g_trampoline;
    patch_plan.targets[0].original_trampoline_size =
        kTrampolineCodeBytes;

    const bridge_entry_patch::PatchResult applied =
        bridge_entry_patch::guarded_patch_apply(patch_plan);
    g_installed = applied.success;
    check(applied.success && applied.status == bridge_entry_patch::PatchStatus::success,
          "transaction_install_success");
    check(applied.pending_count == 0u, "transaction_install_no_pending_threads");
    check(std::memcmp(g_source, g_plan.patch.data(), entry::kPatchBytes) == 0,
          "replacement_published");
    check(information_battle_entry_original == published_original,
          "published_original_pointer_immutable");

    if (g_installed) {
        reset_observation();
        SetLastError(kInitialLastError);
        check(call_source_direct() == kNativeReturn,
              "patched_direct_return_marker");
        const bool first_callback = g_callback_calls == 1u
            && g_body_calls == body_before + 2u
            && g_callback_result == g_result_pointer
            && g_callback_combat == kCombat
            && g_callback_summary == kSummary
            && g_callback_caller_return != 0u
            && g_callback_original_rbx != 0u
            && g_snapshot_valid && snapshot_matches_fixture(g_snapshot)
            && GetLastError() == kInitialLastError;
        check(first_callback, "patched_direct_capture_and_lasterror");
        check(g_result_region[kResultOffset] == 0xa5u,
              "native_body_mutated_result_after_snapshot");

        initialize_fake_result();
        SetLastError(kInitialLastError);
        check(call_source_indirect() == kNativeReturn,
              "patched_indirect_return_marker");
        check(g_callback_calls == 2u && g_body_calls == body_before + 3u
                  && g_snapshot_valid && snapshot_matches_fixture(g_snapshot)
                  && GetLastError() == kInitialLastError,
              "patched_indirect_capture_and_body_once");

        initialize_fake_result();
        g_capture_fail = true;
        SetLastError(kInitialLastError);
        check(call_source_direct() == kNativeReturn,
              "copy_failure_still_returns_body_marker");
        check(g_callback_calls == 3u && g_copy_failures == 1u
                  && g_body_calls == body_before + 4u
                  && g_snapshot_valid && snapshot_matches_fixture(g_snapshot)
                  && GetLastError() == kInitialLastError,
              "copy_failure_does_not_block_native_body");

        const bridge_entry_patch::PatchResult rolled_back =
            bridge_entry_patch::guarded_patch_rollback(patch_plan);
        g_installed = false;
        check(rolled_back.success
                  && rolled_back.status
                         == bridge_entry_patch::PatchStatus::rollback_complete
                  && rolled_back.rollback_complete,
              "transaction_uninstall_success");
        check(rolled_back.pending_count == 0u,
              "transaction_uninstall_no_pending_threads");
        check(std::memcmp(g_source, entry::kOriginalPrologue.data(),
                          entry::kPatchBytes) == 0
                  && std::memcmp(g_source, entry::kOriginalPrologue.data(),
                                 entry::kOriginalPrologue.size()) == 0,
              "original_21_and_36_bytes_restored");

        initialize_fake_result();
        SetLastError(kInitialLastError);
        check(call_source_direct() == kNativeReturn,
              "postuninstall_direct_body_return");
        check(g_callback_calls == 3u && g_body_calls == body_before + 5u
                  && GetLastError() == kInitialLastError,
              "postuninstall_no_callback_and_body_once");
    }

    const bool passed = g_failures == 0u && !g_installed
        && g_tables_registered;
    std::printf(
        "{\"passed\":%s,\"cases\":5,\"install_success\":%s,"
        "\"uninstall_success\":%s,\"callback_count\":%u,"
        "\"body_count\":%u,\"copy_failures\":%u,"
        "\"snapshot_retained\":%s,\"bytes_restored\":%s,"
        "\"unwind_tables_registered\":%s,"
        "\"published_original_immutable\":%s,"
        "\"callback_caller_return_nonzero\":%s,"
        "\"callback_original_rbx_nonzero\":%s,"
        "\"native_body_is_fixture\":true}\n",
        passed ? "true" : "false", applied.success ? "true" : "false",
        (!g_installed && applied.success) ? "true" : "false",
        g_callback_calls, g_body_calls, g_copy_failures,
        g_snapshot_valid ? "true" : "false",
        (!g_installed && std::memcmp(g_source, entry::kOriginalPrologue.data(),
                                     entry::kPatchBytes) == 0)
            ? "true" : "false",
        g_tables_registered ? "true" : "false",
        information_battle_entry_original == published_original ? "true"
                                                                : "false",
        g_callback_caller_return != 0u ? "true" : "false",
        g_callback_original_rbx != 0u ? "true" : "false");
    return passed ? 0 : 1;
}

