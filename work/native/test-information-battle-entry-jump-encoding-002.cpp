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
constexpr std::size_t kPageBytes = 0x1000;
constexpr std::size_t kStackBytes = 0x10000;
constexpr std::size_t kSourceBytes = 0x100;
constexpr std::size_t kMemoryCodeBytes = 41;
constexpr std::size_t kMemoryJumpBytes = 20;
constexpr std::size_t kContinuationOffset = 36;
constexpr std::size_t kSourceUnwindOffset = 80;
constexpr std::uint32_t kReturnMarker = 0x13579bdfU;

constexpr std::array<unsigned, 7> kPushOffsets{{10, 11, 12, 13, 15, 17, 19}};
constexpr std::array<std::uint64_t, 7> kSavedValues{{
    UINT64_C(0x1111111111111111), UINT64_C(0x2222222222222222),
    UINT64_C(0x3333333333333333), UINT64_C(0x4444444444444444),
    UINT64_C(0x5555555555555555), UINT64_C(0x6666666666666666),
    UINT64_C(0x7777777777777777)
}};
constexpr std::uint64_t kRbx = UINT64_C(0x0102030405060708);
constexpr std::uint64_t kRbp = UINT64_C(0x1112131415161718);
constexpr std::uint64_t kRsi = UINT64_C(0x2122232425262728);
constexpr std::uint64_t kRdi = UINT64_C(0x3132333435363738);
constexpr std::uint64_t kR12 = UINT64_C(0x4142434445464748);
constexpr std::uint64_t kR13 = UINT64_C(0x5152535455565758);
constexpr std::uint64_t kR14 = UINT64_C(0x6162636465666768);
constexpr std::uint64_t kR15 = UINT64_C(0x7172737475767878);
constexpr std::uint64_t kStackArgument5 = UINT64_C(0x5555666677778888);
constexpr std::uint64_t kStackArgument6 = UINT64_C(0x9999aaaabbbbcccc);
constexpr std::uint64_t kExpectedRflags = UINT64_C(0x202);
constexpr std::uint64_t kReturnAddress = UINT64_C(0x1122334455667788);

extern "C" {
volatile std::uint64_t g_after_rax = 0;
volatile std::uint64_t g_after_rbx = 0;
volatile std::uint64_t g_after_rbp = 0;
volatile std::uint64_t g_after_rsi = 0;
volatile std::uint64_t g_after_rdi = 0;
volatile std::uint64_t g_after_r12 = 0;
volatile std::uint64_t g_after_r13 = 0;
volatile std::uint64_t g_after_r14 = 0;
volatile std::uint64_t g_after_r15 = 0;
volatile std::uint64_t g_before_rflags = 0;
volatile std::uint64_t g_after_rflags = 0;
volatile std::uint64_t g_after_stack_argument5 = 0;
volatile std::uint64_t g_after_stack_argument6 = 0;
}

// This fixture is an ordinary caller-side assembly wrapper.  It saves the
// caller's nonvolatiles, installs deterministic markers, calls an executable
// candidate, records the post-return state, then restores the outer caller.
// The candidate itself is still only an owned VirtualAlloc image.
extern "C" __attribute__((naked, noinline)) void fixture_call_candidate(
    void*) {
    __asm__ volatile(
        "pushq %r15\n\t"
        "pushq %r14\n\t"
        "pushq %r13\n\t"
        "pushq %r12\n\t"
        "pushq %rdi\n\t"
        "pushq %rsi\n\t"
        "pushq %rbx\n\t"
        "pushq %rbp\n\t"
        "subq $0x38, %rsp\n\t"
        "movabsq $0x0000000000000202, %rax\n\t"
        "pushq %rax\n\t"
        "popfq\n\t"
        "pushfq\n\t"
        "popq g_before_rflags(%rip)\n\t"
        "movabsq $0x5555666677778888, %rax\n\t"
        "movq %rax, 0x20(%rsp)\n\t"
        "movabsq $0x9999aaaabbbbcccc, %rax\n\t"
        "movq %rax, 0x28(%rsp)\n\t"
        "movq %rcx, %r10\n\t"
        "movabsq $0x0102030405060708, %rbx\n\t"
        "movabsq $0x1112131415161718, %rbp\n\t"
        "movabsq $0x2122232425262728, %rsi\n\t"
        "movabsq $0x3132333435363738, %rdi\n\t"
        "movabsq $0x4142434445464748, %r12\n\t"
        "movabsq $0x5152535455565758, %r13\n\t"
        "movabsq $0x6162636465666768, %r14\n\t"
        "movabsq $0x7172737475767878, %r15\n\t"
        "movabsq $0x1111222233334444, %rcx\n\t"
        "movabsq $0x2222333344445555, %rdx\n\t"
        "movabsq $0x3333444455556666, %r8\n\t"
        "movabsq $0x4444555566667777, %r9\n\t"
        "callq *%r10\n\t"
        "pushfq\n\t"
        "popq g_after_rflags(%rip)\n\t"
        "movq 0x20(%rsp), %r11\n\t"
        "movq %r11, g_after_stack_argument5(%rip)\n\t"
        "movq 0x28(%rsp), %r11\n\t"
        "movq %r11, g_after_stack_argument6(%rip)\n\t"
        "movq %rax, g_after_rax(%rip)\n\t"
        "movq %rbx, g_after_rbx(%rip)\n\t"
        "movq %rbp, g_after_rbp(%rip)\n\t"
        "movq %rsi, g_after_rsi(%rip)\n\t"
        "movq %rdi, g_after_rdi(%rip)\n\t"
        "movq %r12, g_after_r12(%rip)\n\t"
        "movq %r13, g_after_r13(%rip)\n\t"
        "movq %r14, g_after_r14(%rip)\n\t"
        "movq %r15, g_after_r15(%rip)\n\t"
        "addq $0x38, %rsp\n\t"
        "popq %rbp\n\t"
        "popq %rbx\n\t"
        "popq %rsi\n\t"
        "popq %rdi\n\t"
        "popq %r12\n\t"
        "popq %r13\n\t"
        "popq %r14\n\t"
        "popq %r15\n\t"
        "retq\n\t");
}

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

void write_qword(unsigned char* destination, std::uint64_t value) {
    std::memcpy(destination, &value, sizeof(value));
}

unsigned pushes_before(unsigned pc) {
    unsigned result = 0;
    for (const unsigned offset : kPushOffsets) {
        if (offset < pc) {
            ++result;
        }
    }
    return result;
}

void build_no_handler_unwind(unsigned char* destination, unsigned prolog_size) {
    std::memcpy(destination, entry::kProjectedUnwind.data(),
                entry::kProjectedUnwind.size());
    destination[1] = static_cast<unsigned char>(prolog_size);
}

void build_continuation(unsigned char* source) {
    static constexpr unsigned char continuation[] = {
        0xb8, 0xdf, 0x9b, 0x57, 0x13,                    // mov eax, marker
        0x48, 0x81, 0xc4, 0xa0, 0x05, 0x00, 0x00,        // add rsp, 0x5a0
        0x41, 0x5f, 0x41, 0x5e, 0x41, 0x5d, 0x41, 0x5c,  // pop r15..r12
        0x5f, 0x5e, 0x5d,                                // pop rdi/rsi/rbp
        0x48, 0x8b, 0x5c, 0x24, 0x10,                    // restore rbx
        0x49, 0xbb, 0x02, 0x02, 0x00, 0x00, 0x00, 0x00,  // mov r11, 0x202
        0x00, 0x00,
        0x41, 0x53,                                        // push r11
        0x9d,                                               // popfq
        0xc3                                               // ret
    };
    std::memcpy(source + kContinuationOffset, continuation,
                sizeof(continuation));
}

void build_memory_indirect_jump(unsigned char* trampoline,
                                std::uintptr_t target) {
    unsigned char* destination = trampoline + entry::kPatchBytes;
    const std::uint64_t value = static_cast<std::uint64_t>(target);
    const std::uint32_t low = static_cast<std::uint32_t>(value);
    const std::uint32_t high = static_cast<std::uint32_t>(value >> 32);
    destination[0] = 0xc7;
    destination[1] = 0x44;
    destination[2] = 0x24;
    destination[3] = 0x50;
    std::memcpy(destination + 4, &low, sizeof(low));
    destination[8] = 0xc7;
    destination[9] = 0x44;
    destination[10] = 0x24;
    destination[11] = 0x54;
    std::memcpy(destination + 12, &high, sizeof(high));
    destination[16] = 0xff;
    destination[17] = 0x64;
    destination[18] = 0x24;
    destination[19] = 0x50;
}

bool valid_actual_return(const char* variant) {
    const bool result = g_after_rax == kReturnMarker
        && g_after_rbx == kRbx && g_after_rbp == kRbp
        && g_after_rsi == kRsi && g_after_rdi == kRdi
        && g_after_r12 == kR12 && g_after_r13 == kR13
        && g_after_r14 == kR14 && g_after_r15 == kR15
        && g_before_rflags == kExpectedRflags
        && g_after_rflags == g_before_rflags
        && g_after_stack_argument5 == kStackArgument5
        && g_after_stack_argument6 == kStackArgument6;
    std::printf(
        "EXEC variant=%s return=%llx rbx=%llx rbp=%llx rsi=%llx "
        "rdi=%llx r12=%llx r13=%llx r14=%llx r15=%llx "
        "rflags_before=%llx rflags_after=%llx arg5=%llx arg6=%llx status=%s\n",
        variant, static_cast<unsigned long long>(g_after_rax),
        static_cast<unsigned long long>(g_after_rbx),
        static_cast<unsigned long long>(g_after_rbp),
        static_cast<unsigned long long>(g_after_rsi),
        static_cast<unsigned long long>(g_after_rdi),
        static_cast<unsigned long long>(g_after_r12),
        static_cast<unsigned long long>(g_after_r13),
        static_cast<unsigned long long>(g_after_r14),
        static_cast<unsigned long long>(g_after_r15),
        static_cast<unsigned long long>(g_before_rflags),
        static_cast<unsigned long long>(g_after_rflags),
        static_cast<unsigned long long>(g_after_stack_argument5),
        static_cast<unsigned long long>(g_after_stack_argument6),
        result ? "PASS" : "FAIL");
    return result;
}

struct UnwindObservation final {
    bool lookup = false;
    bool metadata = false;
    bool handler_null = false;
    bool restored = false;
    bool registers = false;
};

UnwindObservation unwind_at(const char* variant, const char* region,
                            unsigned char* image, PRUNTIME_FUNCTION function,
                            DWORD64 image_base, unsigned pc, bool legal,
                            unsigned char* stack) {
    UnwindObservation observation{};
    const unsigned count = pushes_before(pc);
    const auto caller_value = reinterpret_cast<std::uintptr_t>(
        stack + 0x8000) & ~static_cast<std::uintptr_t>(0x0f);
    auto* caller_rsp = reinterpret_cast<unsigned char*>(caller_value);
    write_qword(caller_rsp, kReturnAddress);
    for (unsigned index = 0; index < count; ++index) {
        write_qword(caller_rsp - 8 * (index + 1), kSavedValues[index]);
    }

    CONTEXT context{};
    context.ContextFlags = CONTEXT_FULL;
    context.Rip = reinterpret_cast<DWORD64>(image + pc);
    context.Rsp = reinterpret_cast<DWORD64>(caller_rsp - 8 * count);
    context.Rbx = kRbx;
    context.Rbp = UINT64_C(0xa1a1a1a1a1a1a1a1);
    context.Rsi = UINT64_C(0xa2a2a2a2a2a2a2a2);
    context.Rdi = UINT64_C(0xa3a3a3a3a3a3a3a3);
    context.R12 = UINT64_C(0xa4a4a4a4a4a4a4a4);
    context.R13 = UINT64_C(0xa5a5a5a5a5a5a5a5);
    context.R14 = UINT64_C(0xa6a6a6a6a6a6a6a6);
    context.R15 = UINT64_C(0xa7a7a7a7a7a7a7a7);
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
    if (observation.lookup) {
        const EXCEPTION_ROUTINE* handler = RtlVirtualUnwind(
            UNW_FLAG_NHANDLER, image_base, context.Rip, found, &context,
            &handler_data, &establisher_frame, &nonvolatile);
        observation.handler_null = handler == nullptr && handler_data == nullptr;
        const auto unwind_offset = function->UnwindData;
        observation.metadata = image[unwind_offset] == 0x01
            && image[unwind_offset + 1] == entry::kPatchBytes
            && image[unwind_offset + 2] == 0x07;
        const std::uint64_t expected_rbp = count > 0
            ? kSavedValues[0] : UINT64_C(0xa1a1a1a1a1a1a1a1);
        const std::uint64_t expected_rsi = count > 1
            ? kSavedValues[1] : UINT64_C(0xa2a2a2a2a2a2a2a2);
        const std::uint64_t expected_rdi = count > 2
            ? kSavedValues[2] : UINT64_C(0xa3a3a3a3a3a3a3a3);
        const std::uint64_t expected_r12 = count > 3
            ? kSavedValues[3] : UINT64_C(0xa4a4a4a4a4a4a4a4);
        const std::uint64_t expected_r13 = count > 4
            ? kSavedValues[4] : UINT64_C(0xa5a5a5a5a5a5a5a5);
        const std::uint64_t expected_r14 = count > 5
            ? kSavedValues[5] : UINT64_C(0xa6a6a6a6a6a6a6a6);
        const std::uint64_t expected_r15 = count > 6
            ? kSavedValues[6] : UINT64_C(0xa7a7a7a7a7a7a7a7);
        observation.restored = context.Rip == kReturnAddress
            && context.Rsp == reinterpret_cast<DWORD64>(caller_rsp + 8)
            && context.Rbx == kRbx;
        observation.registers = context.Rbp == expected_rbp
            && context.Rsi == expected_rsi && context.Rdi == expected_rdi
            && context.R12 == expected_r12 && context.R13 == expected_r13
            && context.R14 == expected_r14 && context.R15 == expected_r15;
    }
    std::printf(
        "UNWIND variant=%s region=%s pc=%u legal=%s lookup=%s metadata=%s "
        "handler_null=%s restored=%s registers=%s diagnostic_only=%s\n",
        variant, region, pc, legal ? "yes" : "no",
        observation.lookup ? "PASS" : "FAIL",
        observation.metadata ? "PASS" : "FAIL",
        observation.handler_null ? "PASS" : "FAIL",
        observation.restored ? "PASS" : "FAIL",
        observation.registers ? "PASS" : "FAIL",
        legal ? "no" : "yes");
    if (legal) {
        check(observation.lookup, "unwind_lookup");
        check(observation.metadata, "unwind_projected_metadata");
        check(observation.handler_null, "unwind_handler_null");
        check(observation.restored, "unwind_restores_rip_rsp_rbx");
        check(observation.registers, "unwind_restores_prefix_nonvolatiles");
    }
    return observation;
}

bool register_pair(unsigned char* source, unsigned char* trampoline,
                   unsigned code_bytes, RUNTIME_FUNCTION& source_function,
                   RUNTIME_FUNCTION& trampoline_function) {
    source_function.BeginAddress = 0;
    source_function.EndAddress = static_cast<DWORD>(entry::kPatchBytes);
    source_function.UnwindData = static_cast<DWORD>(kSourceUnwindOffset);
    trampoline_function.BeginAddress = 0;
    trampoline_function.EndAddress = static_cast<DWORD>(code_bytes);
    trampoline_function.UnwindData = static_cast<DWORD>(entry::kUnwindOffset);
    if (RtlAddFunctionTable(&source_function, 1,
                            reinterpret_cast<DWORD64>(source)) == FALSE) {
        return false;
    }
    if (RtlAddFunctionTable(&trampoline_function, 1,
                            reinterpret_cast<DWORD64>(trampoline)) == FALSE) {
        (void)RtlDeleteFunctionTable(&source_function);
        return false;
    }
    return true;
}

void run_variant(const char* name, unsigned char* source, unsigned char* stack) {
    auto* trampoline = static_cast<unsigned char*>(VirtualAlloc(
        nullptr, kPageBytes, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    check(trampoline != nullptr, "virtual_alloc_candidate_trampoline");
    if (!trampoline) {
        return;
    }
    std::memcpy(trampoline, entry::kOriginalPrologue.data(),
                entry::kPatchBytes);
    const std::uintptr_t target = reinterpret_cast<std::uintptr_t>(source + 21);
    build_memory_indirect_jump(trampoline, target);
    const std::uint64_t target_value = static_cast<std::uint64_t>(target);
    std::uint32_t target_low = 0;
    std::uint32_t target_high = 0;
    std::memcpy(&target_low, &target_value, sizeof(target_low));
    std::memcpy(&target_high,
                reinterpret_cast<const unsigned char*>(&target_value) + 4,
                sizeof(target_high));
    check(trampoline[21] == 0xc7 && trampoline[22] == 0x44
              && trampoline[23] == 0x24 && trampoline[24] == 0x50,
          "memory_indirect_low_store_opcode");
    check(std::memcmp(trampoline + 25, &target_low, sizeof(target_low)) == 0,
          "memory_indirect_low_store_target");
    check(trampoline[29] == 0xc7 && trampoline[30] == 0x44
              && trampoline[31] == 0x24 && trampoline[32] == 0x54,
          "memory_indirect_high_store_opcode");
    check(std::memcmp(trampoline + 33, &target_high, sizeof(target_high)) == 0,
          "memory_indirect_high_store_target");
    check(trampoline[37] == 0xff && trampoline[38] == 0x64
              && trampoline[39] == 0x24 && trampoline[40] == 0x50,
          "memory_indirect_mod01_jump_opcode");
    const unsigned code_bytes = kMemoryCodeBytes;
    build_no_handler_unwind(trampoline + entry::kUnwindOffset,
                            static_cast<unsigned>(entry::kPatchBytes));

    RUNTIME_FUNCTION source_function{};
    RUNTIME_FUNCTION trampoline_function{};
    const bool registered = register_pair(source, trampoline, code_bytes,
                                          source_function, trampoline_function);
    check(registered, "register_source_and_candidate_tables");
    if (registered) {
        g_after_rax = g_after_rbx = g_after_rbp = g_after_rsi = 0;
        g_after_rdi = g_after_r12 = g_after_r13 = g_after_r14 = g_after_r15 = 0;
        g_before_rflags = g_after_rflags = 0;
        g_after_stack_argument5 = g_after_stack_argument6 = 0;
        std::printf("EXEC invoking variant=%s target=%p trampoline=%p source=%p\n",
                    name, reinterpret_cast<void*>(target), trampoline, source);
        fixture_call_candidate(trampoline);
        std::printf("EXEC returned variant=%s\n", name);
        check(valid_actual_return(name), "actual_candidate_return_and_registers");

        constexpr std::array<unsigned, 12> kLegal{{
            0, 5, 10, 11, 12, 13, 15, 17, 19, 21, 29, 37
        }};
        for (const unsigned pc : kLegal) {
            (void)unwind_at(name, "trampoline", trampoline,
                            &trampoline_function,
                            reinterpret_cast<DWORD64>(trampoline), pc, true,
                            stack);
        }
        check(RtlDeleteFunctionTable(&trampoline_function) != FALSE,
              "delete_candidate_table");
        check(RtlDeleteFunctionTable(&source_function) != FALSE,
              "delete_source_table");
        DWORD64 unused_base = 0;
        check(RtlLookupFunctionEntry(reinterpret_cast<DWORD64>(trampoline + 1),
                                     &unused_base, nullptr) == nullptr,
              "candidate_lookup_after_delete_absent");
        check(RtlLookupFunctionEntry(reinterpret_cast<DWORD64>(source + 1),
                                     &unused_base, nullptr) == nullptr,
              "source_lookup_after_delete_absent");
    }
    check(VirtualFree(trampoline, 0, MEM_RELEASE) != FALSE,
          "free_candidate_trampoline");
}

}  // namespace

int main() {
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    std::printf("TEST information-battle-entry-jump-encoding\n");

    auto* source = static_cast<unsigned char*>(VirtualAlloc(
        nullptr, kPageBytes, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    auto* stack = static_cast<unsigned char*>(VirtualAlloc(
        nullptr, kStackBytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    check(source != nullptr, "virtual_alloc_native_source");
    check(stack != nullptr, "virtual_alloc_candidate_stack");
    if (!source || !stack) {
        if (source) {
            (void)VirtualFree(source, 0, MEM_RELEASE);
        }
        if (stack) {
            (void)VirtualFree(stack, 0, MEM_RELEASE);
        }
        std::printf("SUMMARY checks_failed=%u status=FAIL\n", ++g_failures);
        std::printf("RESULT FAIL\n");
        return 1;
    }

    std::memcpy(source, entry::kOriginalPrologue.data(),
                entry::kOriginalPrologue.size());
    build_continuation(source);
    check(same_bytes(source, entry::kOriginalPrologue.data(),
                     entry::kOriginalPrologue.size()),
          "native_source_preserves_full_36_byte_prefix");
    check(source[kContinuationOffset] == 0xb8
              && source[kContinuationOffset + 5] == 0x48
              && source[kContinuationOffset + 28] == 0x49
              && source[kContinuationOffset + 40] == 0x9d
              && source[kContinuationOffset + 41] == 0xc3,
          "native_source_continuation_shape");

    // Register a separate source prefix table for the old and new candidate
    // runs.  Its 21-byte range deliberately ends before the continuation.
    build_no_handler_unwind(source + kSourceUnwindOffset,
                            static_cast<unsigned>(entry::kPatchBytes));
    run_variant("memory_indirect_rsp50", source, stack);

    check(VirtualFree(stack, 0, MEM_RELEASE) != FALSE,
          "free_candidate_stack");
    check(VirtualFree(source, 0, MEM_RELEASE) != FALSE,
          "free_native_source");
    std::printf("SUMMARY checks_failed=%u status=%s\n", g_failures,
                g_failures == 0 ? "PASS" : "FAIL");
    std::printf("RESULT %s\n", g_failures == 0 ? "PASS" : "FAIL");
    return g_failures == 0 ? 0 : 1;
}
