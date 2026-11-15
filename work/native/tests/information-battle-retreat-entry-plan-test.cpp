#define NOMINMAX
#include <windows.h>

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <initializer_list>
#include <limits>

#include "information-battle-retreat-entry-plan.h"

namespace plan = information::battle::retreat_entry;
static unsigned checks = 0;

extern "C" {
void fixture_retreat_removal_call(const void* entry);
void fixture_retreat_removal_continuation();
volatile std::uint64_t fixture_retreat_continuation_calls = 0u;
volatile std::uint64_t fixture_retreat_continuation_rcx = 0u;
volatile std::uint64_t fixture_retreat_continuation_rdx = 0u;
volatile std::uint64_t fixture_retreat_continuation_r8 = 0u;
volatile std::uint64_t fixture_retreat_continuation_r9 = 0u;
volatile std::uint64_t fixture_retreat_continuation_rsp = 0u;
volatile std::uint64_t fixture_retreat_continuation_stack5 = 0u;
volatile std::uint64_t fixture_retreat_continuation_stack6 = 0u;
volatile std::uint64_t fixture_retreat_call_rsp = 0u;
volatile std::uint64_t fixture_retreat_after_rsp = 0u;
volatile std::uint64_t fixture_retreat_return_value = 0u;
volatile std::uint64_t fixture_retreat_after_rbx = 0u;
volatile std::uint64_t fixture_retreat_after_rbp = 0u;
volatile std::uint64_t fixture_retreat_after_rsi = 0u;
volatile std::uint64_t fixture_retreat_after_rdi = 0u;
volatile std::uint64_t fixture_retreat_after_r12 = 0u;
volatile std::uint64_t fixture_retreat_after_r13 = 0u;
volatile std::uint64_t fixture_retreat_after_r14 = 0u;
volatile std::uint64_t fixture_retreat_after_r15 = 0u;
}

static void check(bool value, const char* label) {
    ++checks;
    if (!value) {
        std::fprintf(stderr, "FAILED %s\n", label);
        std::exit(1);
    }
}

static std::uint32_t read_u32(const unsigned char* input) {
    std::uint32_t value = 0u;
    for (unsigned i = 0u; i != 4u; ++i) {
        value |= static_cast<std::uint32_t>(input[i]) << (i * 8u);
    }
    return value;
}

static std::uint64_t read_u64(const unsigned char* input) {
    std::uint64_t value = 0u;
    for (unsigned i = 0u; i != 8u; ++i) {
        value |= static_cast<std::uint64_t>(input[i]) << (i * 8u);
    }
    return value;
}

static std::uintptr_t absolute_target(const unsigned char* jump) {
    return static_cast<std::uintptr_t>(read_u64(jump + 6u));
}

static bool same_bytes(const void* left, const void* right,
                       std::size_t bytes) {
    return std::memcmp(left, right, bytes) == 0;
}

static void expect_failure(plan::Kind kind,
                           const unsigned char* prefix,
                           std::size_t prefix_bytes,
                           const unsigned char* unwind,
                           std::size_t unwind_bytes,
                           plan::Address entry,
                           plan::Address hook,
                           plan::Status expected,
                           const char* label) {
    plan::Plan output;
    unsigned char* const output_bytes =
        reinterpret_cast<unsigned char*>(&output);
    for (std::size_t i = 0u; i != sizeof(output); ++i) {
        output_bytes[i] = 0x5au;
    }
    std::array<unsigned char, sizeof(plan::Plan)> before{};
    std::memcpy(before.data(), &output, before.size());
    check(plan::prepare(kind, prefix, prefix_bytes, unwind, unwind_bytes,
                        entry, hook, output) == expected, label);
    check(same_bytes(before.data(), &output, before.size()),
          "failure leaves output byte-for-byte unchanged");
}

static bool spec_matches(plan::Kind kind,
                         std::uint32_t rva,
                         std::uint32_t end_rva,
                         std::uint32_t unwind_rva,
                         std::uint32_t stack_delta,
                         const unsigned char (&expected_prefix)[28],
                         const unsigned char (&expected_unwind)[32],
                         const char* label) {
    const plan::Spec& value = plan::spec(kind);
    check(value.kind == kind, label);
    check(value.rva == rva && value.end_rva == end_rva
              && value.unwind_rva == unwind_rva,
          "spec keeps PE RVA boundaries");
    check(value.prefix_bytes == 28u && value.unwind_bytes == 32u
              && value.projected_unwind_bytes == 28u
              && value.stack_delta == stack_delta,
          "spec sizes and stack delta");
    check(same_bytes(value.prefix.data(), expected_prefix, 28u),
          "exact complete entry prefix");
    check(same_bytes(value.unwind_expected.data(), expected_unwind, 32u),
          "exact source PE UNWIND_INFO");
    return true;
}

struct SavedRegisters final {
    DWORD64 rbx = 0x1111222233334444ull;
    DWORD64 rbp = 0x2222333344445555ull;
    DWORD64 rsi = 0x3333444455556666ull;
    DWORD64 rdi = 0x4444555566667777ull;
    DWORD64 r12 = 0x5555666677778888ull;
    DWORD64 r13 = 0x6666777788889999ull;
    DWORD64 r14 = 0x777788889999aaaauLL;
    DWORD64 r15 = 0x88889999aaaabbbbull;
    DWORD64 rip = 0x0000000123456789ull;
};

static void store_qword(unsigned char* stack, std::size_t offset,
                        DWORD64 value) {
    std::memcpy(stack + offset, &value, sizeof(value));
}

static void exercise_registered_unwind(plan::Kind kind,
                                       plan::Address entry,
                                       plan::Address hook) {
    const plan::Spec& selected = plan::spec(kind);
    plan::Plan value{};
    check(plan::prepare(kind, selected.prefix.data(), selected.prefix_bytes,
                        selected.unwind_expected.data(), selected.unwind_bytes,
                        entry, hook, value) == plan::Status::prepared,
          "prepare plan for Windows unwind test");

    auto* image = static_cast<unsigned char*>(VirtualAlloc(
        nullptr, 4096u, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    auto* stack = static_cast<unsigned char*>(VirtualAlloc(
        nullptr, 4096u, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    check(image != nullptr && stack != nullptr,
          "allocate owned trampoline and synthetic stack memory");
    std::memcpy(image, value.image.data(), value.image_bytes);

    RUNTIME_FUNCTION runtime{};
    runtime.BeginAddress = value.runtime.begin;
    runtime.EndAddress = value.runtime.end;
    runtime.UnwindData = value.runtime.unwind;
    const DWORD64 image_base = reinterpret_cast<DWORD64>(image);
    check(RtlAddFunctionTable(&runtime, 1u, image_base) != 0,
          "register only the test-owned runtime function");

    const SavedRegisters saved{};
    constexpr std::size_t kStackOffset = 512u;
    unsigned char* const prologue_rsp = stack + kStackOffset;
    if (kind == plan::Kind::outcome) {
        store_qword(prologue_rsp, 32u, saved.r15);
        store_qword(prologue_rsp, 40u, saved.r14);
        store_qword(prologue_rsp, 48u, saved.r13);
        store_qword(prologue_rsp, 56u, saved.r12);
        store_qword(prologue_rsp, 64u, saved.rdi);
        store_qword(prologue_rsp, 72u, saved.rip);
        store_qword(prologue_rsp, 88u, saved.rbx);
        store_qword(prologue_rsp, 96u, saved.rbp);
        store_qword(prologue_rsp, 104u, saved.rsi);
    } else if (kind == plan::Kind::unit_path) {
        store_qword(prologue_rsp, 224u, saved.r15);
        store_qword(prologue_rsp, 232u, saved.r14);
        store_qword(prologue_rsp, 240u, saved.r13);
        store_qword(prologue_rsp, 248u, saved.r12);
        store_qword(prologue_rsp, 256u, saved.rdi);
        store_qword(prologue_rsp, 264u, saved.rsi);
        store_qword(prologue_rsp, 272u, saved.rbp);
        store_qword(prologue_rsp, 280u, saved.rip);
        store_qword(prologue_rsp, 296u, saved.rbx);
    } else {
        store_qword(prologue_rsp, 32u, saved.rdi);
        store_qword(prologue_rsp, 40u, saved.rip);
        store_qword(prologue_rsp, 48u, saved.rbx);
        store_qword(prologue_rsp, 56u, saved.rbp);
        store_qword(prologue_rsp, 72u, saved.rsi);
    }

    const DWORD64 control_base = reinterpret_cast<DWORD64>(image);
    for (DWORD64 offset : {28ull, 50ull}) {
        DWORD64 lookup_base = 0u;
        PRUNTIME_FUNCTION found = RtlLookupFunctionEntry(
            control_base + offset, &lookup_base, nullptr);
        check(found != nullptr && lookup_base == control_base,
              "RtlLookupFunctionEntry finds test function at offset 28 and 50");
        check(found->BeginAddress == 0u
                  && found->EndAddress == selected.prefix_bytes + 29u
                  && found->UnwindData == 64u,
              "lookup sees bounded trampoline runtime row");

        CONTEXT context{};
        context.ContextFlags = CONTEXT_FULL;
        context.Rip = control_base + offset;
        context.Rsp = reinterpret_cast<DWORD64>(prologue_rsp);
        context.Rbx = context.Rbp = context.Rsi = context.Rdi = 0xdeaddeadull;
        context.R12 = context.R13 = context.R14 = context.R15 = 0xdeaddeadull;
        if (kind == plan::Kind::unit_removal) {
            context.R12 = saved.r12;
            context.R13 = saved.r13;
            context.R14 = saved.r14;
            context.R15 = saved.r15;
        }
        PVOID handler_data = nullptr;
        DWORD64 establisher_frame = 0u;
        RtlVirtualUnwind(UNW_FLAG_NHANDLER, lookup_base, context.Rip, found,
                         &context, &handler_data, &establisher_frame, nullptr);

        check(context.Rip == saved.rip, "unwind restores synthetic return RIP");
        check(context.Rsp == reinterpret_cast<DWORD64>(prologue_rsp)
                                     + selected.stack_delta + 8u,
              "unwind restores caller RSP");
        check(context.Rbx == saved.rbx && context.Rbp == saved.rbp
                  && context.Rsi == saved.rsi && context.Rdi == saved.rdi
                  && context.R12 == saved.r12 && context.R13 == saved.r13
                  && context.R14 == saved.r14 && context.R15 == saved.r15,
              "unwind restores every saved nonvolatile GPR");
        check(handler_data == nullptr,
              "projected v1 UNWIND_INFO has no copied game handler");
    }

    check(RtlDeleteFunctionTable(&runtime) != 0,
          "remove the test-owned runtime function");
    check(VirtualFree(stack, 0u, MEM_RELEASE) != 0,
          "release synthetic stack memory");
    check(VirtualFree(image, 0u, MEM_RELEASE) != 0,
          "release trampoline memory");
}

static void test_unit_removal_spec_and_generated_code_execution() {
    constexpr unsigned char removal_prefix[27] = {
        0x48,0x89,0x5c,0x24,0x08,0x48,0x89,0x6c,
        0x24,0x10,0x48,0x89,0x74,0x24,0x20,0x57,
        0x48,0x83,0xec,0x20,0x41,0x0f,0xb6,0xe8,
        0x48,0x8b,0xfa,
    };
    constexpr unsigned char removal_unwind[32] = {
        0x11,0x14,0x08,0x00,0x14,0x64,0x09,0x00,
        0x14,0x54,0x07,0x00,0x14,0x34,0x06,0x00,
        0x14,0x32,0x10,0x70,0x9c,0x4d,0xa3,0x01,
        0x3c,0x6f,0xde,0x01,0x28,0xdd,0x9a,0xdd,
    };

    const plan::Spec& selected = plan::spec(plan::Kind::unit_removal);
    check(selected.kind == plan::Kind::unit_removal
              && selected.rva == 0x23b200u
              && selected.end_rva == 0x23b397u
              && selected.unwind_rva == 0x1de6f20u,
          "unit-removal PE RVA and exclusive end");
    check(selected.prefix_bytes == 27u && selected.unwind_bytes == 32u
              && selected.projected_unwind_bytes == 20u
              && selected.stack_delta == 0x28u
              && selected.home_slot_offset == 0x18u,
          "unit-removal prefix, unwind, stack, and home slot sizes");
    check(same_bytes(selected.prefix.data(), removal_prefix,
                     sizeof(removal_prefix)),
          "unit-removal exact complete 27-byte entry prefix");
    check(selected.prefix[27] == 0u,
          "unit-removal spec does not claim a 28th prefix byte");
    check(same_bytes(selected.unwind_expected.data(), removal_unwind,
                     sizeof(removal_unwind)),
          "unit-removal exact source PE UNWIND_INFO");

    const plan::Address continuation = reinterpret_cast<plan::Address>(
        &fixture_retreat_removal_continuation);
    const plan::Address entry = continuation
        - selected.prefix_bytes;
    const plan::Address hook = entry + 0x1000u;
    plan::Plan result{};
    check(plan::prepare(plan::Kind::unit_removal,
                        selected.prefix.data(), selected.prefix_bytes,
                        selected.unwind_expected.data(), selected.unwind_bytes,
                        entry, hook, result) == plan::Status::prepared,
          "unit-removal plan prepares from the exact copied inputs");
    check(result.kind == plan::Kind::unit_removal
              && result.image_bytes == 84u
              && result.patch_bytes == 27u
              && result.prologue_bytes == 20u
              && result.unwind_bytes == 20u,
          "unit-removal plan projects only the 20-byte unwind prefix");
    check(result.original_entry == entry
              && result.continuation == continuation
              && result.hook == hook
              && result.runtime.begin == 0u
              && result.runtime.end == 56u
              && result.runtime.unwind == 64u,
          "unit-removal plan preserves continuation and bounded runtime row");
    check(same_bytes(result.image.data(), removal_prefix,
                     sizeof(removal_prefix)),
          "unit-removal generated image starts with 27 exact bytes");
    check(result.image[64] == 1u
              && same_bytes(result.image.data() + 65u,
                            removal_unwind + 1u, 19u)
              && result.image[84] == 0u,
          "unit-removal projected unwind clears flags and stops at 20 bytes");

    const unsigned char* const jump = result.image.data() + 27u;
    check(jump[0] == 0xc7u && jump[1] == 0x84u && jump[2] == 0x24u
              && jump[11] == 0xc7u && jump[12] == 0x84u
              && jump[13] == 0x24u
              && jump[22] == 0xffu && jump[23] == 0xa4u
              && jump[24] == 0x24u,
          "unit-removal generated tail is the full home-slot jump");
    check(read_u32(jump + 3u) == 0x40u
              && read_u32(jump + 14u) == 0x44u
              && read_u32(jump + 25u) == 0x40u,
          "unit-removal tail uses original RSP plus 0x18 home slot");
    check((static_cast<std::uint64_t>(read_u32(jump + 7u))
                | (static_cast<std::uint64_t>(read_u32(jump + 18u)) << 32u))
              == continuation,
          "unit-removal tail returns to byte 27 continuation");
    check(absolute_target(result.patch.data()) == hook
              && result.patch[0] == 0xffu && result.patch[1] == 0x25u,
          "unit-removal entry patch targets the requested hook");
    for (std::size_t byte = 14u; byte != result.patch.size(); ++byte) {
        check(result.patch[byte] == 0x90u,
              "unit-removal patch tail is NOP padded");
    }

    auto* executable = static_cast<unsigned char*>(VirtualAlloc(
        nullptr, 4096u, MEM_RESERVE | MEM_COMMIT,
        PAGE_EXECUTE_READWRITE));
    check(executable != nullptr,
          "allocate test-owned executable plan image");
    std::memcpy(executable, result.image.data(), result.image_bytes);
    check(FlushInstructionCache(GetCurrentProcess(), executable,
                                result.image_bytes) != 0,
          "flush test-owned plan image before execution");

    fixture_retreat_continuation_calls = 0u;
    fixture_retreat_continuation_rcx = 0u;
    fixture_retreat_continuation_rdx = 0u;
    fixture_retreat_continuation_r8 = 0u;
    fixture_retreat_continuation_r9 = 0u;
    fixture_retreat_continuation_rsp = 0u;
    fixture_retreat_continuation_stack5 = 0u;
    fixture_retreat_continuation_stack6 = 0u;
    fixture_retreat_call_rsp = 0u;
    fixture_retreat_after_rsp = 0u;
    fixture_retreat_return_value = 0u;
    fixture_retreat_after_rbx = 0u;
    fixture_retreat_after_rbp = 0u;
    fixture_retreat_after_rsi = 0u;
    fixture_retreat_after_rdi = 0u;
    fixture_retreat_after_r12 = 0u;
    fixture_retreat_after_r13 = 0u;
    fixture_retreat_after_r14 = 0u;
    fixture_retreat_after_r15 = 0u;

    fixture_retreat_removal_call(executable);
    check(fixture_retreat_continuation_calls == 1u,
          "unit-removal copied prefix and generated jump reached continuation");
    check(fixture_retreat_continuation_rcx
                  == UINT64_C(0x0102030405060708)
              && fixture_retreat_continuation_rdx
                  == UINT64_C(0x1112131415161718)
              && fixture_retreat_continuation_r8
                  == UINT64_C(0x2122232425262728)
              && fixture_retreat_continuation_r9
                  == UINT64_C(0x3132333435363738),
          "unit-removal prologue leaves four register arguments intact");
    check(fixture_retreat_continuation_stack5
                  == UINT64_C(0x4142434445464748)
              && fixture_retreat_continuation_stack6
                  == UINT64_C(0x5152535455565758),
          "unit-removal jump leaves stack arguments intact");
    check(fixture_retreat_continuation_rsp % 16u == 0u,
          "unit-removal prologue keeps body stack 16-byte aligned");
    check(fixture_retreat_call_rsp != 0u
              && fixture_retreat_after_rsp == fixture_retreat_call_rsp,
          "unit-removal generated return restores caller stack pointer");
    check(fixture_retreat_return_value == UINT64_C(0x0fedcba987654321),
          "unit-removal generated return chain preserves continuation result");
    check(fixture_retreat_after_rbx == UINT64_C(0x6162636465666768)
              && fixture_retreat_after_rbp == UINT64_C(0x7172737475767778)
              && fixture_retreat_after_rsi == UINT64_C(0x8182838485868788)
              && fixture_retreat_after_rdi == UINT64_C(0x9192939495969798)
              && fixture_retreat_after_r12 == UINT64_C(0xa1a2a3a4a5a6a7a8)
              && fixture_retreat_after_r13 == UINT64_C(0xb1b2b3b4b5b6b7b8)
              && fixture_retreat_after_r14 == UINT64_C(0xc1c2c3c4c5c6c7c8)
              && fixture_retreat_after_r15 == UINT64_C(0xd1d2d3d4d5d6d7d8),
          "unit-removal prologue and continuation preserve nonvolatile GPRs");
    check(VirtualFree(executable, 0u, MEM_RELEASE) != 0,
          "release test-owned executable plan image");

    exercise_registered_unwind(plan::Kind::unit_removal, entry, hook);
}

int main() {
    static_assert(sizeof(void*) == 8u,
                  "this test requires the configured Win64 compiler");

    constexpr unsigned char outcome_prefix[28] = {
        0x48,0x89,0x5c,0x24,0x10,0x48,0x89,0x6c,
        0x24,0x18,0x48,0x89,0x74,0x24,0x20,0x57,
        0x41,0x54,0x41,0x55,0x41,0x56,0x41,0x57,
        0x48,0x83,0xec,0x20,
    };
    constexpr unsigned char outcome_unwind[32] = {
        0x11,0x1c,0x0c,0x00,0x1c,0x64,0x0d,0x00,
        0x1c,0x54,0x0c,0x00,0x1c,0x34,0x0b,0x00,
        0x1c,0x32,0x18,0xf0,0x16,0xe0,0x14,0xd0,
        0x12,0xc0,0x10,0x70,0x9c,0x4d,0xa3,0x01,
    };
    constexpr unsigned char unit_path_prefix[28] = {
        0x48,0x89,0x5c,0x24,0x10,0x55,0x56,0x57,
        0x41,0x54,0x41,0x55,0x41,0x56,0x41,0x57,
        0x48,0x8d,0x6c,0x24,0xd9,0x48,0x81,0xec,
        0xe0,0x00,0x00,0x00,
    };
    constexpr unsigned char unit_path_unwind[32] = {
        0x11,0x1c,0x0b,0x00,0x1c,0x34,0x25,0x00,
        0x1c,0x01,0x1c,0x00,0x10,0xf0,0x0e,0xe0,
        0x0c,0xd0,0x0a,0xc0,0x08,0x70,0x07,0x60,
        0x06,0x50,0x00,0x00,0x9c,0x4d,0xa3,0x01,
    };

    spec_matches(plan::Kind::outcome, 0x22bed0u, 0x22c0a6u,
                 0x1de6084u, 0x48u, outcome_prefix, outcome_unwind,
                 "outcome spec");
    spec_matches(plan::Kind::unit_path, 0xd4fb20u, 0xd501a3u,
                 0x1ebb0a4u, 0x118u, unit_path_prefix, unit_path_unwind,
                 "unit-path spec preserves PE end exclusive RVA");
    check(plan::spec(plan::Kind::unit_path).end_rva != 0xd501a2u,
          "unit-path PE end remains distinct from REA body end");

    constexpr plan::Address kEntryBase = 0x00007ff600100000ull;
    constexpr plan::Address kHook = 0x00007ff700200000ull;
    const std::array<const plan::Spec*, 2> specs{{
        &plan::spec(plan::Kind::outcome), &plan::spec(plan::Kind::unit_path),
    }};
    const std::array<plan::Kind, 2> kinds{{
        plan::Kind::outcome, plan::Kind::unit_path,
    }};
    for (std::size_t index = 0u; index != kinds.size(); ++index) {
        const plan::Kind kind = kinds[index];
        const plan::Spec& selected = *specs[index];
        const plan::Address entry = kEntryBase + selected.rva;
        plan::Plan result{};
        check(plan::prepare(kind, selected.prefix.data(),
                            selected.prefix_bytes,
                            selected.unwind_expected.data(),
                            selected.unwind_bytes, entry, kHook, result)
                  == plan::Status::prepared,
              "valid retreat entry plan prepared");

        check(result.kind == kind && result.image_bytes == 92u
                  && result.patch_bytes == 28u && result.prologue_bytes == 28u
                  && result.unwind_bytes == 28u,
              "plan bounded sizes and full prologue");
        check(result.original_entry == entry
                  && result.continuation == entry + 28u
                  && result.hook == kHook,
              "plan carries input entry, continuation and hook");
        check(result.runtime.begin == 0u && result.runtime.end == 57u
                  && result.runtime.unwind == 64u,
              "runtime range covers copied prefix and 29-byte tail jump");
        check(same_bytes(result.image.data(), selected.prefix.data(), 28u),
              "image begins with exact copied prologue");
        check(result.image[64] == 1u
                  && same_bytes(result.image.data() + 65u,
                                selected.unwind_expected.data() + 1u, 27u),
              "projection keeps 28 bytes and clears all UNWIND_INFO flags");
        check(result.image[92] == 0u,
              "source language handler RVA is not copied");

        const unsigned char* const jump = result.image.data() + 28u;
        check(jump[0] == 0xc7u && jump[1] == 0x84u && jump[2] == 0x24u
                  && jump[11] == 0xc7u && jump[12] == 0x84u
                  && jump[13] == 0x24u,
              "tail jump uses caller-owned home slot stores");
        check(read_u32(jump + 3u) == selected.stack_delta + 8u
                  && read_u32(jump + 14u) == selected.stack_delta + 12u
                  && read_u32(jump + 25u) == selected.stack_delta + 8u,
              "tail jump uses unoccupied home slot +8");
        check(read_u32(jump + 7u)
                  == static_cast<std::uint32_t>(result.continuation)
                  && read_u32(jump + 18u)
                  == static_cast<std::uint32_t>(result.continuation >> 32u),
              "tail jump embeds full continuation address");
        check(jump[22] == 0xffu && jump[23] == 0xa4u && jump[24] == 0x24u,
              "tail jump returns through the home slot, not an epilogue jump");
        check(absolute_target(result.patch.data()) == kHook
                  && result.patch[0] == 0xffu && result.patch[1] == 0x25u,
              "entry patch jumps to requested hook");
        for (std::size_t byte = 14u; byte != result.patch.size(); ++byte) {
            check(result.patch[byte] == 0x90u,
                  "unused patch tail is NOP padded");
        }

        std::array<unsigned char, 64> overlapping_inputs{};
        expect_failure(kind, selected.prefix.data(), 27u,
                       selected.unwind_expected.data(), 32u,
                       entry, kHook, plan::Status::invalid_buffer,
                       "short prefix rejected");
        expect_failure(kind, selected.prefix.data(), 28u,
                       selected.unwind_expected.data(), 31u,
                       entry, kHook, plan::Status::invalid_buffer,
                       "short unwind rejected");
        expect_failure(kind, selected.prefix.data(), 28u,
                       selected.unwind_expected.data(), 32u,
                       entry, entry, plan::Status::invalid_identity,
                       "entry cannot hook itself");
        expect_failure(kind, selected.prefix.data(), 28u,
                       selected.unwind_expected.data(), 32u,
                       0x8000u, kHook, plan::Status::invalid_address,
                       "low noncanonical entry rejected");
        expect_failure(kind, selected.prefix.data(), 28u,
                       selected.unwind_expected.data(), 32u,
                       entry, 0xffff800000000000ull,
                       plan::Status::invalid_address,
                       "upper non-user hook rejected");
        expect_failure(kind, selected.prefix.data(), 28u,
                       selected.unwind_expected.data(), 32u,
                       std::numeric_limits<plan::Address>::max() - 20u,
                       kHook, plan::Status::invalid_address,
                       "overflowing entry range rejected");
        expect_failure(kind, selected.prefix.data(), 28u,
                       selected.unwind_expected.data(), 32u,
                       information::battle::message_entry::kMaxUserAddress
                           - 10u,
                       kHook, plan::Status::invalid_address,
                       "entry extent crossing canonical user bound rejected");

        auto changed_prefix = selected.prefix;
        changed_prefix[27] ^= 1u;
        expect_failure(kind, changed_prefix.data(), 28u,
                       selected.unwind_expected.data(), 32u,
                       entry, kHook, plan::Status::prologue_mismatch,
                       "changed prologue byte rejected");
        auto changed_unwind = selected.unwind_expected;
        changed_unwind[31] ^= 1u;
        expect_failure(kind, selected.prefix.data(), 28u,
                       changed_unwind.data(), 32u,
                       entry, kHook, plan::Status::unwind_mismatch,
                       "changed source unwind byte rejected");

        expect_failure(kind, overlapping_inputs.data(), 28u,
                       overlapping_inputs.data() + 16u, 32u,
                       entry, kHook, plan::Status::input_alias,
                       "overlapping source windows rejected");

        plan::Plan output_alias{};
        std::memcpy(output_alias.image.data(), selected.prefix.data(), 28u);
        std::memcpy(output_alias.image.data() + 64u,
                    selected.unwind_expected.data(), 32u);
        std::array<unsigned char, sizeof(plan::Plan)> before_alias{};
        std::memcpy(before_alias.data(), &output_alias, before_alias.size());
        check(plan::prepare(kind, output_alias.image.data(), 28u,
                            output_alias.image.data() + 64u, 32u,
                            entry, kHook, output_alias)
                  == plan::Status::output_alias,
              "output alias rejected");
        check(same_bytes(before_alias.data(), &output_alias,
                         before_alias.size()),
              "output alias rejection leaves output unchanged");

        exercise_registered_unwind(kind, entry, kHook);
    }

    test_unit_removal_spec_and_generated_code_execution();

    expect_failure(static_cast<plan::Kind>(0xffu), outcome_prefix, 28u,
                   outcome_unwind, 32u, kEntryBase + 0x22bed0u, kHook,
                   plan::Status::invalid_kind, "unknown kind rejected");
    check(plan::spec(static_cast<plan::Kind>(0xffu)).kind
              == plan::Kind::outcome,
          "unknown spec query has stable outcome fallback");
    expect_failure(plan::Kind::outcome, nullptr, 28u,
                   outcome_unwind, 32u, kEntryBase + 0x22bed0u, kHook,
                   plan::Status::invalid_buffer, "null input rejected");

    std::printf("retreat entry-plan checks=%u; game_calls=0; game_code_executed=0; patches=0\n",
                checks);
    return 0;
}
