#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "information-battle-entry-plan.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>

namespace {

namespace entry = information::battle::entry;

constexpr std::uintptr_t kOriginalEntry = UINT64_C(0x0000000140238620);
constexpr std::uintptr_t kObservationStub = UINT64_C(0x0000000140012340);
constexpr std::size_t kStackBytes = 0x10000;
constexpr std::size_t kImageAllocationBytes = 0x1000;
constexpr std::size_t kPushCount = 7;
constexpr std::array<unsigned, kPushCount> kPushOffsets{{
    10, 11, 12, 13, 15, 17, 19
}};
constexpr std::array<std::uint64_t, kPushCount> kSavedValues{{
    UINT64_C(0x1111111111111111), UINT64_C(0x2222222222222222),
    UINT64_C(0x3333333333333333), UINT64_C(0x4444444444444444),
    UINT64_C(0x5555555555555555), UINT64_C(0x6666666666666666),
    UINT64_C(0x7777777777777777)
}};
constexpr std::uint64_t kReturnAddress = UINT64_C(0x1122334455667788);
constexpr std::uint64_t kRbx = UINT64_C(0x8888888888888888);
constexpr std::uint64_t kCurrentRbp = UINT64_C(0xa1a1a1a1a1a1a1a1);
constexpr std::uint64_t kCurrentRsi = UINT64_C(0xa2a2a2a2a2a2a2a2);
constexpr std::uint64_t kCurrentRdi = UINT64_C(0xa3a3a3a3a3a3a3a3);
constexpr std::uint64_t kCurrentR12 = UINT64_C(0xa4a4a4a4a4a4a4a4);
constexpr std::uint64_t kCurrentR13 = UINT64_C(0xa5a5a5a5a5a5a5a5);
constexpr std::uint64_t kCurrentR14 = UINT64_C(0xa6a6a6a6a6a6a6a6);
constexpr std::uint64_t kCurrentR15 = UINT64_C(0xa7a7a7a7a7a7a7a7);

unsigned g_failures = 0;

void check(bool condition, const char* name) {
    std::printf("CHECK %s %s\n", name, condition ? "PASS" : "FAIL");
    if (!condition) {
        ++g_failures;
    }
}

bool same_bytes(const void* left, const void* right, std::size_t size) {
    return std::memcmp(left, right, size) == 0;
}

bool same_plan(const entry::Plan& left, const entry::Plan& right) {
    return same_bytes(&left, &right, sizeof(entry::Plan));
}

void initialize_sentinel(entry::Plan& plan, unsigned char value) {
    plan = entry::Plan{};
    plan.image.fill(value);
    plan.patch.fill(value);
    plan.runtime.begin = 0xa1a1a1a1U;
    plan.runtime.end = 0xb2b2b2b2U;
    plan.runtime.unwind = 0xc3c3c3c3U;
    plan.original_entry = UINT64_C(0x1111222233334444);
    plan.continuation = UINT64_C(0x5555666677778888);
    plan.observation_stub = UINT64_C(0x9999aaaabbbbcccc);
}

bool status_is(entry::Status actual, entry::Status expected) {
    return actual == expected;
}

void check_unchanged_prepare(const char* name, entry::Status actual,
                             entry::Status expected,
                             const entry::Plan& before,
                             const entry::Plan& after) {
    check(status_is(actual, expected), name);
    char unchanged_name[96]{};
    std::snprintf(unchanged_name, sizeof(unchanged_name), "%s_output_unchanged",
                  name);
    check(same_plan(before, after), unchanged_name);
}

void test_prepare_contract() {
    std::array<unsigned char, entry::kOriginalPrologue.size()> prologue =
        entry::kOriginalPrologue;
    std::array<unsigned char, entry::kOriginalUnwind.size()> unwind =
        entry::kOriginalUnwind;
    const auto prologue_before = prologue;
    const auto unwind_before = unwind;

    entry::Plan plan{};
    const entry::Status prepared = entry::prepare(
        prologue.data(), prologue.size(), unwind.data(), unwind.size(),
        kOriginalEntry, kObservationStub, plan);
    check(status_is(prepared, entry::Status::prepared),
          "prepare_full_signature");
    check(same_bytes(prologue.data(), prologue_before.data(), prologue.size()),
          "prepare_preserves_prologue_source");
    check(same_bytes(unwind.data(), unwind_before.data(), unwind.size()),
          "prepare_preserves_unwind_source");

    std::array<unsigned char, entry::kJumpBytes> continuation_jump{};
    entry::absolute_jump(continuation_jump.data(),
                         kOriginalEntry + entry::kPatchBytes);
    std::array<unsigned char, entry::kJumpBytes> observation_jump{};
    entry::absolute_jump(observation_jump.data(), kObservationStub);

    check(same_bytes(plan.image.data(), prologue.data(), entry::kPatchBytes),
          "image_copies_exact_21_byte_prefix");
    check(same_bytes(plan.image.data() + entry::kPatchBytes,
                     continuation_jump.data(), continuation_jump.size()),
          "image_continuation_absolute_jump");
    const std::array<unsigned char, 29> zero_tail{};
    check(same_bytes(plan.image.data() + entry::kCodeBytes,
                     zero_tail.data(), zero_tail.size()),
          "image_code_tail_is_zero");
    check(same_bytes(plan.image.data() + entry::kUnwindOffset,
                     entry::kProjectedUnwind.data(),
                     entry::kProjectedUnwind.size()),
          "image_uses_projected_seven_push_unwind");
    check(plan.runtime.begin == 0 && plan.runtime.end == entry::kCodeBytes
              && plan.runtime.unwind == entry::kUnwindOffset,
          "runtime_function_relative_layout");
    check(same_bytes(plan.patch.data(), observation_jump.data(),
                     observation_jump.size()),
          "patch_observation_absolute_jump");
    bool nops = true;
    for (std::size_t index = entry::kJumpBytes; index < plan.patch.size();
         ++index) {
        nops = nops && plan.patch[index] == 0x90;
    }
    check(nops, "patch_21_byte_nop_boundary");
    check(plan.original_entry == kOriginalEntry
              && plan.continuation == kOriginalEntry + entry::kPatchBytes
              && plan.observation_stub == kObservationStub,
          "plan_addresses_are_owned_values");

    entry::Plan before{};
    entry::Plan after{};
    initialize_sentinel(before, 0xa5);
    after = before;
    const entry::Status null_prologue = entry::prepare(
        nullptr, prologue.size(), unwind.data(), unwind.size(),
        kOriginalEntry, kObservationStub, after);
    check_unchanged_prepare("null_prologue", null_prologue,
                            entry::Status::invalid_buffer, before, after);

    before = after;
    const entry::Status null_unwind = entry::prepare(
        prologue.data(), prologue.size(), nullptr, unwind.size(),
        kOriginalEntry, kObservationStub, after);
    check_unchanged_prepare("null_unwind", null_unwind,
                            entry::Status::invalid_buffer, before, after);

    before = after;
    const entry::Status short_prologue = entry::prepare(
        prologue.data(), prologue.size() - 1, unwind.data(), unwind.size(),
        kOriginalEntry, kObservationStub, after);
    check_unchanged_prepare("short_prologue", short_prologue,
                            entry::Status::invalid_buffer, before, after);

    before = after;
    const entry::Status long_unwind = entry::prepare(
        prologue.data(), prologue.size(), unwind.data(), unwind.size() + 1,
        kOriginalEntry, kObservationStub, after);
    check_unchanged_prepare("long_unwind", long_unwind,
                            entry::Status::invalid_buffer, before, after);

    before = after;
    const entry::Status bad_entry = entry::prepare(
        prologue.data(), prologue.size(), unwind.data(), unwind.size(),
        UINT64_C(0xffff), kObservationStub, after);
    check_unchanged_prepare("invalid_entry_address", bad_entry,
                            entry::Status::invalid_address, before, after);

    before = after;
    const entry::Status overflowing_entry = entry::prepare(
        prologue.data(), prologue.size(), unwind.data(), unwind.size(),
        entry::kMaxUserAddress - 34, kObservationStub, after);
    check_unchanged_prepare("entry_extent_overflow", overflowing_entry,
                            entry::Status::invalid_address, before, after);

    before = after;
    const entry::Status bad_stub = entry::prepare(
        prologue.data(), prologue.size(), unwind.data(), unwind.size(),
        kOriginalEntry, entry::kMaxUserAddress, after);
    check_unchanged_prepare("invalid_observation_address", bad_stub,
                            entry::Status::invalid_address, before, after);

    before = after;
    auto bad_prologue = prologue;
    bad_prologue[20] ^= 0x01;
    const auto bad_prologue_before = bad_prologue;
    const entry::Status mismatched_prologue = entry::prepare(
        bad_prologue.data(), bad_prologue.size(), unwind.data(), unwind.size(),
        kOriginalEntry, kObservationStub, after);
    check_unchanged_prepare("prologue_signature_mismatch", mismatched_prologue,
                            entry::Status::prologue_mismatch, before, after);
    check(same_bytes(bad_prologue.data(), bad_prologue_before.data(),
                     bad_prologue.size()),
          "mismatch_prologue_input_not_mutated");

    before = after;
    auto bad_unwind = unwind;
    bad_unwind[31] ^= 0x01;
    const auto bad_unwind_before = bad_unwind;
    const entry::Status mismatched_unwind = entry::prepare(
        prologue.data(), prologue.size(), bad_unwind.data(), bad_unwind.size(),
        kOriginalEntry, kObservationStub, after);
    check_unchanged_prepare("unwind_signature_mismatch", mismatched_unwind,
                            entry::Status::unwind_mismatch, before, after);
    check(same_bytes(bad_unwind.data(), bad_unwind_before.data(),
                     bad_unwind.size()),
          "mismatch_unwind_input_not_mutated");

    entry::Plan alias{};
    initialize_sentinel(alias, 0xcc);
    const entry::Plan alias_before = alias;
    const entry::Status alias_status = entry::prepare(
        alias.image.data(), entry::kOriginalPrologue.size(), unwind.data(),
        unwind.size(), kOriginalEntry, kObservationStub, alias);
    check_unchanged_prepare("output_alias", alias_status,
                            entry::Status::output_alias, alias_before, alias);
}

struct UnwindObservation final {
    bool lookup = false;
    bool metadata = false;
    bool handler_null = false;
    bool restored = false;
    bool exact_registers = false;
    std::uint64_t actual_rbx = 0;
    std::uint64_t actual_rip = 0;
    std::uint64_t actual_rsp = 0;
    std::uint64_t expected_rsp = 0;
    std::uint64_t actual_rbp = 0;
    std::uint64_t actual_rsi = 0;
    std::uint64_t actual_rdi = 0;
    std::uint64_t actual_r12 = 0;
    std::uint64_t actual_r13 = 0;
    std::uint64_t actual_r14 = 0;
    std::uint64_t actual_r15 = 0;
};

unsigned pushes_before(unsigned pc_offset) {
    unsigned count = 0;
    for (const unsigned offset : kPushOffsets) {
        if (offset < pc_offset) {
            ++count;
        }
    }
    return count;
}

void write_qword(unsigned char* address, std::uint64_t value) {
    std::memcpy(address, &value, sizeof(value));
}

UnwindObservation unwind_at(unsigned char* image, PRUNTIME_FUNCTION function,
                            DWORD64 image_base, unsigned pc_offset,
                            unsigned char* stack) {
    UnwindObservation observation{};
    const unsigned count = pushes_before(pc_offset);
    const auto caller_rsp_value = (reinterpret_cast<std::uintptr_t>(
        stack + 0x8000) & ~static_cast<std::uintptr_t>(0x0f));
    auto* caller_rsp = reinterpret_cast<unsigned char*>(caller_rsp_value);
    write_qword(caller_rsp, kReturnAddress);
    for (unsigned index = 0; index < count; ++index) {
        write_qword(caller_rsp - 8 * (index + 1), kSavedValues[index]);
    }

    CONTEXT context{};
    context.ContextFlags = CONTEXT_FULL;
    context.Rip = reinterpret_cast<DWORD64>(image + pc_offset);
    context.Rsp = reinterpret_cast<DWORD64>(caller_rsp - 8 * count);
    context.Rbx = kRbx;
    context.Rbp = kCurrentRbp;
    context.Rsi = kCurrentRsi;
    context.Rdi = kCurrentRdi;
    context.R12 = kCurrentR12;
    context.R13 = kCurrentR13;
    context.R14 = kCurrentR14;
    context.R15 = kCurrentR15;
    PVOID handler_data = nullptr;
    DWORD64 establisher_frame = 0;
    KNONVOLATILE_CONTEXT_POINTERS nonvolatile{};
    DWORD64 lookup_base = 0;
    PRUNTIME_FUNCTION found = RtlLookupFunctionEntry(
        context.Rip, &lookup_base, nullptr);
    observation.lookup = found != nullptr && lookup_base == image_base
        && found->BeginAddress == function->BeginAddress
        && found->EndAddress == function->EndAddress
        && found->UnwindData == function->UnwindData;
    check(observation.lookup, "lookup_function_entry");
    if (observation.lookup) {
        const EXCEPTION_ROUTINE* handler = RtlVirtualUnwind(
            UNW_FLAG_NHANDLER, image_base, context.Rip, found, &context,
            &handler_data, &establisher_frame, &nonvolatile);
        observation.handler_null = handler == nullptr && handler_data == nullptr;
        observation.actual_rip = context.Rip;
        observation.actual_rsp = context.Rsp;
        // RtlVirtualUnwind loads the caller return address from [RSP] and
        // leaves RSP immediately above it, as a real RET would.
        observation.expected_rsp = reinterpret_cast<DWORD64>(caller_rsp + 8);
        observation.actual_rbx = context.Rbx;
        observation.actual_rbp = context.Rbp;
        observation.actual_rsi = context.Rsi;
        observation.actual_rdi = context.Rdi;
        observation.actual_r12 = context.R12;
        observation.actual_r13 = context.R13;
        observation.actual_r14 = context.R14;
        observation.actual_r15 = context.R15;
        observation.metadata = function->UnwindData == entry::kUnwindOffset;
        observation.restored = context.Rip == kReturnAddress
            && context.Rsp == reinterpret_cast<DWORD64>(caller_rsp + 8)
            && context.Rbx == kRbx;
        const std::uint64_t expected_rbp = count > 0
            ? kSavedValues[0] : kCurrentRbp;
        const std::uint64_t expected_rsi = count > 1
            ? kSavedValues[1] : kCurrentRsi;
        const std::uint64_t expected_rdi = count > 2
            ? kSavedValues[2] : kCurrentRdi;
        const std::uint64_t expected_r12 = count > 3
            ? kSavedValues[3] : kCurrentR12;
        const std::uint64_t expected_r13 = count > 4
            ? kSavedValues[4] : kCurrentR13;
        const std::uint64_t expected_r14 = count > 5
            ? kSavedValues[5] : kCurrentR14;
        const std::uint64_t expected_r15 = count > 6
            ? kSavedValues[6] : kCurrentR15;
        observation.exact_registers = context.Rbp == expected_rbp
            && context.Rsi == expected_rsi
            && context.Rdi == expected_rdi
            && context.R12 == expected_r12
            && context.R13 == expected_r13
            && context.R14 == expected_r14
            && context.R15 == expected_r15;
    }
    std::printf(
        "UNWIND pc=%u pushes=%u lookup=%s metadata=%s handler_null=%s "
        "restored=%s registers=%s rip=%llx rsp=%llx rbp=%llx rsi=%llx "
        "rdi=%llx r12=%llx r13=%llx r14=%llx r15=%llx rbx=%llx "
        "expected_rsp=%llx\n",
        pc_offset, count, observation.lookup ? "PASS" : "FAIL",
        observation.metadata ? "PASS" : "FAIL",
        observation.handler_null ? "PASS" : "FAIL",
        observation.restored ? "PASS" : "FAIL",
        observation.exact_registers ? "PASS" : "FAIL",
        static_cast<unsigned long long>(observation.actual_rip),
        static_cast<unsigned long long>(observation.actual_rsp),
        static_cast<unsigned long long>(observation.actual_rbp),
        static_cast<unsigned long long>(observation.actual_rsi),
        static_cast<unsigned long long>(observation.actual_rdi),
        static_cast<unsigned long long>(observation.actual_r12),
        static_cast<unsigned long long>(observation.actual_r13),
        static_cast<unsigned long long>(observation.actual_r14),
        static_cast<unsigned long long>(observation.actual_r15),
        static_cast<unsigned long long>(observation.actual_rbx),
        static_cast<unsigned long long>(observation.expected_rsp));
    check(observation.metadata, "unwind_metadata_offset");
    check(observation.handler_null, "unwind_handler_is_null");
    check(observation.restored, "unwind_restores_rip_rsp_rbx");
    check(observation.exact_registers, "unwind_restores_all_saved_nonvolatiles");
    return observation;
}

void test_registered_unwind() {
    std::array<unsigned char, entry::kOriginalPrologue.size()> prologue =
        entry::kOriginalPrologue;
    std::array<unsigned char, entry::kOriginalUnwind.size()> unwind =
        entry::kOriginalUnwind;
    entry::Plan plan{};
    const entry::Status status = entry::prepare(
        prologue.data(), prologue.size(), unwind.data(), unwind.size(),
        kOriginalEntry, kObservationStub, plan);
    check(status == entry::Status::prepared, "runtime_test_prepare");
    if (status != entry::Status::prepared) {
        return;
    }

    auto* image = static_cast<unsigned char*>(VirtualAlloc(
        nullptr, kImageAllocationBytes, MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE));
    auto* stack = static_cast<unsigned char*>(VirtualAlloc(
        nullptr, kStackBytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    check(image != nullptr, "virtual_alloc_image");
    check(stack != nullptr, "virtual_alloc_synthetic_stack");
    if (!image || !stack) {
        if (image) {
            (void)VirtualFree(image, 0, MEM_RELEASE);
        }
        if (stack) {
            (void)VirtualFree(stack, 0, MEM_RELEASE);
        }
        return;
    }
    std::memcpy(image, plan.image.data(), plan.image.size());
    check(image[entry::kUnwindOffset + 1]
              == static_cast<unsigned char>(entry::kCodeBytes),
          "projected_unwind_size_of_prolog_covers_full_code");
    RUNTIME_FUNCTION function{};
    function.BeginAddress = plan.runtime.begin;
    function.EndAddress = plan.runtime.end;
    function.UnwindData = plan.runtime.unwind;
    const DWORD64 image_base = reinterpret_cast<DWORD64>(image);
    const BOOLEAN registered = RtlAddFunctionTable(&function, 1, image_base);
    check(registered != FALSE, "register_dynamic_function_table");
    if (registered != FALSE) {
        constexpr std::array<unsigned, 18> kPcOffsets{{
            0, 5, 10, 11, 12, 13, 15, 17, 19, 21,
            22, 23, 24, 25, 26, 27, 28, 34
        }};
        for (const unsigned pc_offset : kPcOffsets) {
            (void)unwind_at(image, &function, image_base, pc_offset, stack);
        }
        const BOOLEAN deleted = RtlDeleteFunctionTable(&function);
        check(deleted != FALSE, "delete_dynamic_function_table");
        DWORD64 after_delete_base = 0;
        PRUNTIME_FUNCTION after_delete = RtlLookupFunctionEntry(
            image_base + 21, &after_delete_base, nullptr);
        check(after_delete == nullptr, "lookup_after_delete_is_absent");
    }
    check(VirtualFree(stack, 0, MEM_RELEASE) != FALSE,
          "free_synthetic_stack");
    check(VirtualFree(image, 0, MEM_RELEASE) != FALSE,
          "free_owned_image");
}

}  // namespace

int main() {
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    std::printf("TEST information-battle-entry-prefix-unwind\n");
    test_prepare_contract();
    test_registered_unwind();
    std::printf("SUMMARY checks_failed=%u status=%s\n", g_failures,
                g_failures == 0 ? "PASS" : "FAIL");
    std::printf("RESULT %s\n", g_failures == 0 ? "PASS" : "FAIL");
    return g_failures == 0 ? 0 : 1;
}
