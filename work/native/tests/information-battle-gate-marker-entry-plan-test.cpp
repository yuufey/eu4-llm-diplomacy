#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "../information-battle-gate-marker-entry-plan.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <limits>

namespace {

namespace plan = information::battle::gate_marker_entry;

constexpr std::size_t kPageBytes = 0x1000u;
constexpr std::size_t kStackBytes = 0x10000u;
constexpr std::size_t kSyntheticModuleBytes = 0x02430000u;
constexpr std::uint64_t kReturnAddress = UINT64_C(0x1122334455667788);
constexpr std::uint64_t kCallerRbx = UINT64_C(0x0123456789abcdef);
constexpr std::uint64_t kCallerRdi = UINT64_C(0xfedcba9876543210);

extern "C" {
volatile std::uint64_t g_continuation_rax = 0u;
volatile std::uint32_t g_continuation_hits = 0u;
volatile std::uint64_t g_after_rbx = 0u;
volatile std::uint64_t g_after_rdi = 0u;
}

extern "C" __attribute__((naked, noinline)) void invoke_trampoline(void*) {
    __asm__ volatile(
        "pushq %rbx\n\t"
        "pushq %rdi\n\t"
        "subq $0x28, %rsp\n\t"
        "movq %rcx, %r10\n\t"
        "movabsq $0x0123456789abcdef, %rbx\n\t"
        "movabsq $0xfedcba9876543210, %rdi\n\t"
        "callq *%r10\n\t"
        "movq %rbx, g_after_rbx(%rip)\n\t"
        "movq %rdi, g_after_rdi(%rip)\n\t"
        "addq $0x28, %rsp\n\t"
        "popq %rdi\n\t"
        "popq %rbx\n\t"
        "retq\n\t");
}

struct Checks final {
    unsigned passed = 0u;
    unsigned failed = 0u;

    void expect(const char* label, bool condition) {
        std::printf("CHECK %s %s\n", label, condition ? "PASS" : "FAIL");
        if (condition) ++passed;
        else ++failed;
    }
};

bool same_bytes(const void* left, const void* right, std::size_t size) {
    return std::memcmp(left, right, size) == 0;
}

std::uint64_t read_u64(const unsigned char* bytes) {
    std::uint64_t value = 0u;
    std::memcpy(&value, bytes, sizeof(value));
    return value;
}

void write_u64(unsigned char* bytes, std::uint64_t value) {
    std::memcpy(bytes, &value, sizeof(value));
}

void write_u32(unsigned char* bytes, std::uint32_t value) {
    std::memcpy(bytes, &value, sizeof(value));
}

std::array<unsigned char, plan::kPrefixBytes> prefix_bytes() {
    return plan::spec().prefix;
}

std::array<unsigned char, plan::kUnwindBytes> unwind_bytes() {
    return plan::spec().unwind_expected;
}

plan::Address hook_address() {
    return reinterpret_cast<plan::Address>(&invoke_trampoline);
}

void fill_plan_sentinel(plan::Plan& output) {
    output.image.fill(0xa5u);
    output.patch.fill(0x5au);
    output.runtime.begin = 0xa5a5a5a5u;
    output.runtime.end = 0x5a5a5a5au;
    output.runtime.unwind = 0xaaaaaaaa;
    output.image_bytes = 0xa5u;
    output.patch_bytes = 0x5au;
    output.original_entry = UINT64_C(0x123456789abcdef0);
    output.continuation = UINT64_C(0x0fedcba987654321);
    output.hook = UINT64_C(0x1122334455667788);
}

bool prepare_failure_unchanged(const unsigned char* prefix,
                               std::size_t prefix_size,
                               const unsigned char* unwind,
                               std::size_t unwind_size,
                               plan::Address original_entry,
                               plan::Address hook,
                               plan::Status expected_status) {
    plan::Plan output{};
    fill_plan_sentinel(output);
    std::array<unsigned char, sizeof(plan::Plan)> before{};
    std::memcpy(before.data(), &output, sizeof(output));
    const plan::Status result = plan::prepare(
        prefix, prefix_size, unwind, unwind_size, original_entry, hook, output);
    return result == expected_status
        && same_bytes(before.data(), &output, sizeof(output));
}

std::array<unsigned char, plan::kHomeSlotJumpBytes> expected_home_jump(
        plan::Address continuation) {
    std::array<unsigned char, plan::kHomeSlotJumpBytes> bytes{};
    bytes[0] = 0xc7u; bytes[1] = 0x84u; bytes[2] = 0x24u;
    write_u32(bytes.data() + 3u, plan::kHomeSlotJumpDisplacement);
    const std::uint64_t target = static_cast<std::uint64_t>(continuation);
    write_u32(bytes.data() + 7u, static_cast<std::uint32_t>(target));
    bytes[11] = 0xc7u; bytes[12] = 0x84u; bytes[13] = 0x24u;
    write_u32(bytes.data() + 14u,
              plan::kHomeSlotJumpDisplacement + 4u);
    write_u32(bytes.data() + 18u,
              static_cast<std::uint32_t>(target >> 32u));
    bytes[22] = 0xffu; bytes[23] = 0xa4u; bytes[24] = 0x24u;
    write_u32(bytes.data() + 25u, plan::kHomeSlotJumpDisplacement);
    return bytes;
}

void test_fixed_contract(Checks& checks) {
    const plan::Spec& selected = plan::spec();
    checks.expect("fixed_executable_sha_pin",
        std::strcmp(plan::kTargetExeSha256,
            "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77") == 0);
    checks.expect("fixed_entry_function_unwind_rvas",
        selected.entry_rva == 0x8befa0u
            && selected.end_rva == 0x8bf04fu
            && selected.unwind_rva == 0x1e6d894u);
    checks.expect("fixed_sizes_and_layout",
        selected.prefix.size() == 17u
            && selected.unwind_expected.size() == 16u
            && plan::kImageBytes == 76u
            && plan::kCodeBytes == 52u
            && plan::kHomeSlotJumpDisplacement == 0x40u);

    const std::array<unsigned char, 17> expected_prefix{{
        0x48u,0x89u,0x5cu,0x24u,0x10u,0x57u,0x48u,0x83u,0xecu,
        0x20u,0x48u,0x8bu,0x05u,0x27u,0xcdu,0xb6u,0x01u,
    }};
    const std::array<unsigned char, 16> expected_unwind{{
        0x11u,0x0au,0x04u,0x00u,0x0au,0x34u,0x07u,0x00u,
        0x0au,0x32u,0x06u,0x70u,0x9cu,0x4du,0xa3u,0x01u,
    }};
    checks.expect("fixed_17_byte_entry_signature",
        same_bytes(selected.prefix.data(), expected_prefix.data(),
                   expected_prefix.size()));
    checks.expect("fixed_16_byte_unwind_signature",
        same_bytes(selected.unwind_expected.data(), expected_unwind.data(),
                   expected_unwind.size()));
}

void test_gate_windows(Checks& checks) {
    checks.expect("fixed_gate_rvas",
        plan::kLandGateRva == 0x2353d0u
            && plan::kNavalGateRva == 0x230b4eu);
    checks.expect("fixed_gate_windows_match",
        plan::validate_gate_windows(
            plan::kLandGateBytes.data(), plan::kLandGateBytes.size(),
            plan::kNavalGateBytes.data(), plan::kNavalGateBytes.size()));
    checks.expect("gate_windows_reject_wrong_land_byte", [&] {
        auto changed = plan::kLandGateBytes;
        changed[2] ^= 1u;
        return !plan::validate_gate_windows(
            changed.data(), changed.size(),
            plan::kNavalGateBytes.data(), plan::kNavalGateBytes.size());
    }());
    checks.expect("gate_windows_reject_wrong_naval_byte", [&] {
        auto changed = plan::kNavalGateBytes;
        changed[10] ^= 1u;
        return !plan::validate_gate_windows(
            plan::kLandGateBytes.data(), plan::kLandGateBytes.size(),
            changed.data(), changed.size());
    }());
    checks.expect("gate_windows_reject_wrong_sizes",
        !plan::validate_gate_windows(
            plan::kLandGateBytes.data(), plan::kLandGateBytes.size() - 1u,
            plan::kNavalGateBytes.data(), plan::kNavalGateBytes.size()));
    checks.expect("gate_windows_reject_null",
        !plan::validate_gate_windows(nullptr, plan::kLandGateBytes.size(),
            plan::kNavalGateBytes.data(), plan::kNavalGateBytes.size()));
}

void test_prepare_and_rejections(Checks& checks) {
    const auto prefix = prefix_bytes();
    const auto unwind = unwind_bytes();
    const plan::Address hook = hook_address();

    const plan::Address preferred_entry = plan::kStaticImageBase
        + plan::spec().entry_rva;
    plan::Plan output{};
    const plan::Status status = plan::prepare(
        prefix.data(), prefix.size(), unwind.data(), unwind.size(),
        preferred_entry, hook, output);
    checks.expect("prepare_preferred_base", status == plan::Status::prepared);
    if (status == plan::Status::prepared) {
        const plan::Address expected_continuation = preferred_entry
            + plan::kPatchBytes;
        const plan::Address expected_cell = plan::kStaticImageBase
            + plan::kGlobalCellRva;
        const auto expected_jump = expected_home_jump(expected_continuation);
        checks.expect("plan_lengths_and_runtime_row",
            output.image_bytes == plan::kImageBytes
                && output.patch_bytes == plan::kPatchBytes
                && output.runtime.begin == 0u
                && output.runtime.end == plan::kCodeBytes
                && output.runtime.unwind == plan::kUnwindOffset);
        checks.expect("plan_continuation_and_hook",
            output.original_entry == preferred_entry
                && output.continuation == expected_continuation
                && output.hook == hook);
        checks.expect("plan_copies_only_original_ten_byte_prologue",
            same_bytes(output.image.data(), prefix.data(),
                       plan::kOriginalPrologueBytes));
        checks.expect("plan_relocates_absolute_global_cell_load",
            output.image[10] == 0x48u && output.image[11] == 0xb8u
                && read_u64(output.image.data() + 12u) == expected_cell
                && output.image[20] == 0x48u
                && output.image[21] == 0x8bu
                && output.image[22] == 0x00u);
        checks.expect("plan_home_slot_jump_uses_third_slot_offset_40",
            same_bytes(output.image.data() + 23u, expected_jump.data(),
                       expected_jump.size()));
        checks.expect("plan_projects_unwind_without_original_handler",
            output.image[plan::kUnwindOffset] == 0x01u
                && output.image[plan::kUnwindOffset + 1u] == 0x0au
                && same_bytes(output.image.data() + plan::kUnwindOffset + 1u,
                    unwind.data() + 1u, plan::kProjectedUnwindBytes - 1u));
        checks.expect("plan_patch_absolute_14_plus_three_nops",
            output.patch[0] == 0xffu && output.patch[1] == 0x25u
                && output.patch[2] == 0u && output.patch[5] == 0u
                && read_u64(output.patch.data() + 6u) == hook
                && output.patch[14] == 0x90u
                && output.patch[15] == 0x90u
                && output.patch[16] == 0x90u);
    }

    const plan::Address shifted_base = UINT64_C(0x0000018000000000);
    const plan::Address shifted_entry = shifted_base + plan::spec().entry_rva;
    plan::Plan shifted{};
    const plan::Status shifted_status = plan::prepare(
        prefix.data(), prefix.size(), unwind.data(), unwind.size(),
        shifted_entry, hook, shifted);
    checks.expect("prepare_shifted_aslr_base", shifted_status == plan::Status::prepared);
    if (shifted_status == plan::Status::prepared) {
        checks.expect("aslr_cell_address_uses_derived_module_base",
            read_u64(shifted.image.data() + 12u)
                == shifted_base + plan::kGlobalCellRva);
        checks.expect("aslr_continuation_uses_shifted_entry",
            shifted.continuation == shifted_entry + plan::kPatchBytes);
    }

    auto bad_prefix = prefix;
    bad_prefix[13] ^= 1u;
    checks.expect("one_byte_prefix_mutation_rejected_output_unchanged",
        prepare_failure_unchanged(bad_prefix.data(), bad_prefix.size(),
            unwind.data(), unwind.size(), preferred_entry, hook,
            plan::Status::prefix_mismatch));
    auto bad_unwind = unwind;
    bad_unwind[15] ^= 1u;
    checks.expect("one_byte_unwind_mutation_rejected_output_unchanged",
        prepare_failure_unchanged(prefix.data(), prefix.size(),
            bad_unwind.data(), bad_unwind.size(), preferred_entry, hook,
            plan::Status::unwind_mismatch));
    checks.expect("short_prefix_rejected_output_unchanged",
        prepare_failure_unchanged(prefix.data(), prefix.size() - 1u,
            unwind.data(), unwind.size(), preferred_entry, hook,
            plan::Status::invalid_buffer));
    checks.expect("null_input_rejected_output_unchanged",
        prepare_failure_unchanged(nullptr, prefix.size(),
            unwind.data(), unwind.size(), preferred_entry, hook,
            plan::Status::invalid_buffer));
    const auto near_address_end = reinterpret_cast<const unsigned char*>(
        (std::numeric_limits<plan::Address>::max)() - 8u);
    checks.expect("input_pointer_range_overflow_rejected_output_unchanged",
        prepare_failure_unchanged(near_address_end, prefix.size(),
            unwind.data(), unwind.size(), preferred_entry, hook,
            plan::Status::invalid_buffer));

    checks.expect("underflowing_original_entry_rejected_output_unchanged",
        prepare_failure_unchanged(prefix.data(), prefix.size(),
            unwind.data(), unwind.size(), plan::kEntryRva - 1u, hook,
            plan::Status::invalid_address));
    checks.expect("unaligned_aslr_base_rejected_output_unchanged",
        prepare_failure_unchanged(prefix.data(), prefix.size(),
            unwind.data(), unwind.size(), preferred_entry + 1u, hook,
            plan::Status::invalid_address));
    checks.expect("noncanonical_aslr_base_rejected_output_unchanged",
        prepare_failure_unchanged(prefix.data(), prefix.size(),
            unwind.data(), unwind.size(),
            plan::kMaxUserAddress + plan::spec().entry_rva, hook,
            plan::Status::invalid_address));
    checks.expect("overflowing_aslr_image_range_rejected_output_unchanged",
        prepare_failure_unchanged(prefix.data(), prefix.size(),
            unwind.data(), unwind.size(),
            (std::numeric_limits<plan::Address>::max)() - 0x1000u,
            hook, plan::Status::invalid_address));
    checks.expect("bad_hook_rejected_output_unchanged",
        prepare_failure_unchanged(prefix.data(), prefix.size(),
            unwind.data(), unwind.size(), preferred_entry, 0x1000u,
            plan::Status::invalid_address));
    checks.expect("same_hook_and_entry_rejected_output_unchanged",
        prepare_failure_unchanged(prefix.data(), prefix.size(),
            unwind.data(), unwind.size(), preferred_entry, preferred_entry,
            plan::Status::invalid_identity));

    std::array<unsigned char, plan::kPrefixBytes + plan::kUnwindBytes> overlap{};
    std::memcpy(overlap.data(), prefix.data(), prefix.size());
    std::memcpy(overlap.data() + 8u, unwind.data(), unwind.size());
    checks.expect("overlapping_input_windows_rejected_output_unchanged",
        prepare_failure_unchanged(overlap.data(), prefix.size(),
            overlap.data() + 8u, unwind.size(), preferred_entry, hook,
            plan::Status::input_alias));

    plan::Plan aliased_output{};
    fill_plan_sentinel(aliased_output);
    std::array<unsigned char, sizeof(plan::Plan)> aliased_before{};
    std::memcpy(aliased_before.data(), &aliased_output, sizeof(aliased_output));
    const plan::Status alias_status = plan::prepare(
        reinterpret_cast<const unsigned char*>(&aliased_output),
        prefix.size(), unwind.data(), unwind.size(), preferred_entry, hook,
        aliased_output);
    checks.expect("output_alias_rejected_without_change",
        alias_status == plan::Status::output_alias
            && same_bytes(aliased_before.data(), &aliased_output,
                          sizeof(aliased_output)));

    plan::Plan aliased_unwind_output{};
    fill_plan_sentinel(aliased_unwind_output);
    std::array<unsigned char, sizeof(plan::Plan)> aliased_unwind_before{};
    std::memcpy(aliased_unwind_before.data(), &aliased_unwind_output,
                sizeof(aliased_unwind_output));
    const plan::Status unwind_alias_status = plan::prepare(
        prefix.data(), prefix.size(),
        reinterpret_cast<const unsigned char*>(&aliased_unwind_output),
        unwind.size(), preferred_entry, hook, aliased_unwind_output);
    checks.expect("output_alias_with_unwind_rejected_without_change",
        unwind_alias_status == plan::Status::output_alias
            && same_bytes(aliased_unwind_before.data(), &aliased_unwind_output,
                          sizeof(aliased_unwind_output)));
}

void append_mov_r11_imm64(unsigned char*& cursor, std::uint64_t value) {
    *cursor++ = 0x49u;
    *cursor++ = 0xbbu;
    write_u64(cursor, value);
    cursor += sizeof(value);
}

std::size_t build_synthetic_continuation(unsigned char* destination) {
    unsigned char* cursor = destination;
    append_mov_r11_imm64(cursor,
        reinterpret_cast<std::uint64_t>(&g_continuation_rax));
    *cursor++ = 0x49u; *cursor++ = 0x89u; *cursor++ = 0x03u; // mov [r11],rax
    append_mov_r11_imm64(cursor,
        reinterpret_cast<std::uint64_t>(&g_continuation_hits));
    *cursor++ = 0x41u; *cursor++ = 0xffu; *cursor++ = 0x03u; // inc dword [r11]
    const unsigned char epilogue[] = {
        0x48u,0x83u,0xc4u,0x20u,       // add rsp,20h
        0x5fu,                         // pop rdi
        0x48u,0x8bu,0x5cu,0x24u,0x10u, // mov rbx,[rsp+10h]
        0xc3u,                         // ret
    };
    std::memcpy(cursor, epilogue, sizeof(epilogue));
    cursor += sizeof(epilogue);
    return static_cast<std::size_t>(cursor - destination);
}

bool unwind_at(unsigned char* image, const plan::Plan& selected,
               const RUNTIME_FUNCTION& function, DWORD64 image_base,
               unsigned pc, unsigned char* stack) {
    const auto aligned = reinterpret_cast<std::uintptr_t>(stack + 0x8000u)
        & ~static_cast<std::uintptr_t>(0x0fu);
    auto* const entry_rsp = reinterpret_cast<unsigned char*>(aligned + 8u);
    std::memset(entry_rsp - 0x40u, 0, 0x100u);
    std::memcpy(entry_rsp, &kReturnAddress, sizeof(kReturnAddress));
    std::memcpy(entry_rsp + 0x10u, &kCallerRbx, sizeof(kCallerRbx));
    if (pc >= 6u) {
        std::memcpy(entry_rsp - 8u, &kCallerRdi, sizeof(kCallerRdi));
    }

    CONTEXT context{};
    context.ContextFlags = CONTEXT_FULL;
    context.Rip = reinterpret_cast<DWORD64>(image + pc);
    if (pc >= 10u) {
        context.Rsp = reinterpret_cast<DWORD64>(entry_rsp - 0x28u);
        context.Rbx = UINT64_C(0xa1a1a1a1a1a1a1a1);
        context.Rdi = UINT64_C(0xd4d4d4d4d4d4d4d4);
    } else if (pc >= 6u) {
        context.Rsp = reinterpret_cast<DWORD64>(entry_rsp - 8u);
        context.Rbx = kCallerRbx;
        context.Rdi = kCallerRdi;
    } else {
        context.Rsp = reinterpret_cast<DWORD64>(entry_rsp);
        context.Rbx = kCallerRbx;
        context.Rdi = kCallerRdi;
    }
    PVOID handler_data = nullptr;
    DWORD64 establisher_frame = 0u;
    KNONVOLATILE_CONTEXT_POINTERS nonvolatile{};
    DWORD64 lookup_base = 0u;
    PRUNTIME_FUNCTION found = RtlLookupFunctionEntry(
        context.Rip, &lookup_base, nullptr);
    bool restored = false;
    bool handlerless = false;
    bool row_matches = false;
    if (found != nullptr && lookup_base == image_base) {
        row_matches = found->BeginAddress == function.BeginAddress
            && found->EndAddress == function.EndAddress
            && found->UnwindData == function.UnwindData;
        const EXCEPTION_ROUTINE* handler = RtlVirtualUnwind(
            UNW_FLAG_NHANDLER, image_base, context.Rip, found, &context,
            &handler_data, &establisher_frame, &nonvolatile);
        handlerless = handler == nullptr && handler_data == nullptr
            && image[selected.runtime.unwind] == 0x01u;
        restored = context.Rip == kReturnAddress
            && context.Rsp == reinterpret_cast<DWORD64>(entry_rsp + 8u)
            && context.Rbx == kCallerRbx
            && context.Rdi == kCallerRdi;
    }
    std::printf("UNWIND pc=%u row=%s handlerless=%s restored=%s\n", pc,
        row_matches ? "PASS" : "FAIL", handlerless ? "PASS" : "FAIL",
        restored ? "PASS" : "FAIL");
    return row_matches && handlerless && restored;
}

bool run_synthetic_case(Checks& checks, unsigned index,
                        unsigned char* module) {
    const auto module_base = reinterpret_cast<plan::Address>(module);
    const auto original_entry = module_base + plan::spec().entry_rva;
    const auto continuation = original_entry + plan::kPatchBytes;
    const auto cell_address = module_base + plan::kGlobalCellRva;
    const std::uint64_t cell_value = index == 0u
        ? UINT64_C(0x1122334455667788)
        : UINT64_C(0x8877665544332211);
    std::memcpy(reinterpret_cast<void*>(cell_address), &cell_value,
                sizeof(cell_value));
    const std::size_t continuation_size = build_synthetic_continuation(
        reinterpret_cast<unsigned char*>(continuation));

    auto* trampoline = static_cast<unsigned char*>(VirtualAlloc(
        nullptr, kPageBytes, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    auto* stack = static_cast<unsigned char*>(VirtualAlloc(
        nullptr, kStackBytes, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    checks.expect(index == 0u ? "case_a_owned_allocations"
                              : "case_b_owned_allocations",
        trampoline != nullptr && stack != nullptr);
    if (trampoline == nullptr || stack == nullptr) {
        if (trampoline != nullptr) (void)VirtualFree(trampoline, 0u, MEM_RELEASE);
        if (stack != nullptr) (void)VirtualFree(stack, 0u, MEM_RELEASE);
        return false;
    }

    const auto prefix = prefix_bytes();
    const auto unwind = unwind_bytes();
    plan::Plan selected{};
    const plan::Status prepared = plan::prepare(
        prefix.data(), prefix.size(), unwind.data(), unwind.size(),
        original_entry, hook_address(), selected);
    checks.expect(index == 0u ? "case_a_prepare" : "case_b_prepare",
                  prepared == plan::Status::prepared);
    if (prepared != plan::Status::prepared) {
        (void)VirtualFree(stack, 0u, MEM_RELEASE);
        (void)VirtualFree(trampoline, 0u, MEM_RELEASE);
        return false;
    }
    checks.expect(index == 0u ? "case_a_relocated_cell_base"
                              : "case_b_relocated_cell_base",
        read_u64(selected.image.data() + 12u) == cell_address);
    checks.expect(index == 0u ? "case_a_continuation_address"
                              : "case_b_continuation_address",
        selected.continuation == continuation
            && continuation_size >= 1u);

    std::memcpy(trampoline, selected.image.data(), selected.image_bytes);
    DWORD old_protection = 0u;
    const auto continuation_page = reinterpret_cast<void*>(
        reinterpret_cast<std::uintptr_t>(continuation)
            & ~static_cast<std::uintptr_t>(kPageBytes - 1u));
    const bool continuation_rx = VirtualProtect(
        continuation_page, kPageBytes, PAGE_EXECUTE_READ,
        &old_protection) != FALSE;
    checks.expect(index == 0u ? "case_a_continuation_rx"
                              : "case_b_continuation_rx", continuation_rx);
    const bool trampoline_rx = VirtualProtect(
        trampoline, kPageBytes, PAGE_EXECUTE_READ, &old_protection) != FALSE;
    checks.expect(index == 0u ? "case_a_trampoline_rx"
                              : "case_b_trampoline_rx", trampoline_rx);
    if (continuation_rx && trampoline_rx) {
        FlushInstructionCache(GetCurrentProcess(),
                              reinterpret_cast<void*>(continuation),
                              continuation_size);
        FlushInstructionCache(GetCurrentProcess(), trampoline,
                              selected.image_bytes);

        RUNTIME_FUNCTION function{};
        function.BeginAddress = selected.runtime.begin;
        function.EndAddress = selected.runtime.end;
        function.UnwindData = selected.runtime.unwind;
        const DWORD64 image_base = reinterpret_cast<DWORD64>(trampoline);
        const bool registered = RtlAddFunctionTable(&function, 1u, image_base)
            != FALSE;
        checks.expect(index == 0u ? "case_a_register_unwind"
                                  : "case_b_register_unwind", registered);
        if (registered) {
            bool unwind_ok = true;
            for (const unsigned pc : {0u,5u,6u,10u,20u,23u,34u,45u}) {
                unwind_ok = unwind_at(trampoline, selected, function,
                    image_base, pc, stack) && unwind_ok;
            }
            checks.expect(index == 0u ? "case_a_rtl_virtual_unwind_boundaries"
                                      : "case_b_rtl_virtual_unwind_boundaries",
                          unwind_ok);

            DWORD64 end_lookup_base = 0u;
            const PRUNTIME_FUNCTION at_end = RtlLookupFunctionEntry(
                reinterpret_cast<DWORD64>(trampoline + selected.runtime.end),
                &end_lookup_base, nullptr);
            checks.expect(index == 0u ? "case_a_runtime_end_exclusive"
                                      : "case_b_runtime_end_exclusive",
                          at_end == nullptr);

            g_continuation_rax = 0u;
            g_continuation_hits = 0u;
            g_after_rbx = 0u;
            g_after_rdi = 0u;
            invoke_trampoline(trampoline);
            checks.expect(index == 0u ? "case_a_relocated_load_and_continue"
                                      : "case_b_relocated_load_and_continue",
                g_continuation_hits == 1u
                    && g_continuation_rax == cell_value);
            checks.expect(index == 0u ? "case_a_nonvolatile_restore"
                                      : "case_b_nonvolatile_restore",
                g_after_rbx == kCallerRbx && g_after_rdi == kCallerRdi);
            checks.expect(index == 0u ? "case_a_delete_unwind_table"
                                      : "case_b_delete_unwind_table",
                RtlDeleteFunctionTable(&function) != FALSE);
        }
    }

    checks.expect(index == 0u ? "case_a_free_stack"
                              : "case_b_free_stack",
        VirtualFree(stack, 0u, MEM_RELEASE) != FALSE);
    checks.expect(index == 0u ? "case_a_free_trampoline"
                              : "case_b_free_trampoline",
        VirtualFree(trampoline, 0u, MEM_RELEASE) != FALSE);
    return continuation_rx && trampoline_rx;
}

void test_owned_aslr_execution(Checks& checks) {
    auto* module_a = static_cast<unsigned char*>(VirtualAlloc(
        nullptr, kSyntheticModuleBytes,
        MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    auto* module_b = static_cast<unsigned char*>(VirtualAlloc(
        nullptr, kSyntheticModuleBytes,
        MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    checks.expect("two_owned_aslr_module_regions_allocated",
        module_a != nullptr && module_b != nullptr);
    if (module_a == nullptr || module_b == nullptr) {
        if (module_a != nullptr) (void)VirtualFree(module_a, 0u, MEM_RELEASE);
        if (module_b != nullptr) (void)VirtualFree(module_b, 0u, MEM_RELEASE);
        return;
    }
    const auto base_a = reinterpret_cast<plan::Address>(module_a);
    const auto base_b = reinterpret_cast<plan::Address>(module_b);
    checks.expect("owned_module_bases_are_distinct_and_aligned",
        base_a != base_b && (base_a & 0xffffu) == 0u
            && (base_b & 0xffffu) == 0u);
    if (base_a != base_b) {
        (void)run_synthetic_case(checks, 0u, module_a);
        (void)run_synthetic_case(checks, 1u, module_b);
    }
    checks.expect("free_module_a", VirtualFree(module_a, 0u, MEM_RELEASE) != FALSE);
    checks.expect("free_module_b", VirtualFree(module_b, 0u, MEM_RELEASE) != FALSE);
}

}  // namespace

int main() {
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    Checks checks;
    std::printf("TEST information-battle-gate-marker-entry-plan\n");
    test_fixed_contract(checks);
    test_gate_windows(checks);
    test_prepare_and_rejections(checks);
    test_owned_aslr_execution(checks);
    std::printf("SUMMARY passed=%u failed=%u\n", checks.passed, checks.failed);
    std::printf("RESULT %s\n", checks.failed == 0u ? "PASS" : "FAIL");
    return checks.failed == 0u ? 0 : 1;
}
