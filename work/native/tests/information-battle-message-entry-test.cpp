#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "../information-battle-message-entry-plan.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>

namespace {

namespace entry = information::battle::message_entry;

constexpr std::size_t kPageBytes = 0x1000u;
constexpr std::size_t kStackBytes = 0x10000u;
constexpr std::size_t kSourceBytes = 0x1000u;
constexpr std::uint64_t kReturnAddress = UINT64_C(0x1122334455667788);
constexpr std::uint64_t kRbx = UINT64_C(0x0102030405060708);
constexpr std::uint64_t kRbp = UINT64_C(0x1112131415161718);
constexpr std::uint64_t kRsi = UINT64_C(0x2122232425262728);
constexpr std::uint64_t kRdi = UINT64_C(0x3132333435363738);
constexpr std::uint64_t kR12 = UINT64_C(0x4142434445464748);
constexpr std::uint64_t kR13 = UINT64_C(0x5152535455565758);
constexpr std::uint64_t kR14 = UINT64_C(0x6162636465666768);
constexpr std::uint64_t kR15 = UINT64_C(0x7172737475767878);
constexpr std::uint64_t kExpectedFlags = UINT64_C(0x202);

extern "C" {
volatile std::uint64_t g_after_rsp = 0;
volatile std::uint64_t g_after_rbx = 0;
volatile std::uint64_t g_after_rbp = 0;
volatile std::uint64_t g_after_rsi = 0;
volatile std::uint64_t g_after_rdi = 0;
volatile std::uint64_t g_after_r12 = 0;
volatile std::uint64_t g_after_r13 = 0;
volatile std::uint64_t g_after_r14 = 0;
volatile std::uint64_t g_after_r15 = 0;
volatile std::uint64_t g_before_flags = 0;
volatile std::uint64_t g_after_flags = 0;
volatile std::uint32_t g_body_hits = 0;
}

// The wrapper gives the candidate a normal Win64 caller frame, deterministic
// nonvolatile values, and an explicit home area.  The candidate's tail jumps
// into a self-owned continuation body, which performs the matching epilogue.
extern "C" __attribute__((naked, noinline)) void invoke_candidate(void*) {
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
        "movq %rcx, %r10\n\t"
        "movabsq $0x0000000000000202, %rax\n\t"
        "pushq %rax\n\t"
        "popfq\n\t"
        "pushfq\n\t"
        "popq g_before_flags(%rip)\n\t"
        "movabsq $0x0102030405060708, %rbx\n\t"
        "movabsq $0x1112131415161718, %rbp\n\t"
        "movabsq $0x2122232425262728, %rsi\n\t"
        "movabsq $0x3132333435363738, %rdi\n\t"
        "movabsq $0x4142434445464748, %r12\n\t"
        "movabsq $0x5152535455565758, %r13\n\t"
        "movabsq $0x6162636465666768, %r14\n\t"
        "movabsq $0x7172737475767878, %r15\n\t"
        "callq *%r10\n\t"
        "pushfq\n\t"
        "popq g_after_flags(%rip)\n\t"
        "movq %rsp, g_after_rsp(%rip)\n\t"
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

unsigned g_failures = 0u;

void check(bool condition, const char* label) {
    std::printf("CHECK %s %s\n", label, condition ? "PASS" : "FAIL");
    if (!condition) ++g_failures;
}

const char* kind_label(entry::EntryKind kind, const char* router_label,
                       const char* message_label,
                       const char* cleanup_label) {
    if (kind == entry::EntryKind::router) return router_label;
    if (kind == entry::EntryKind::message) return message_label;
    return cleanup_label;
}

bool same_bytes(const void* left, const void* right, std::size_t size) {
    return std::memcmp(left, right, size) == 0;
}

std::uint64_t read_u64(const unsigned char* input) {
    std::uint64_t value = 0u;
    std::memcpy(&value, input, sizeof(value));
    return value;
}

std::array<unsigned char, entry::kMaxPrefixBytes> prefix_for(
        const entry::Spec& selected) {
    std::array<unsigned char, entry::kMaxPrefixBytes> result{};
    std::memcpy(result.data(), selected.prefix.data(), selected.prefix_bytes);
    return result;
}

std::array<unsigned char, entry::kMaxUnwindBytes> unwind_for(
        const entry::Spec& selected) {
    std::array<unsigned char, entry::kMaxUnwindBytes> result{};
    std::memcpy(result.data(), selected.unwind_expected.data(),
                selected.unwind_bytes);
    return result;
}

void expected_home_slot_jump(unsigned char* output, std::uint32_t displacement,
                             entry::Address target) {
    output[0] = 0xc7u; output[1] = 0x84u; output[2] = 0x24u;
    std::memcpy(output + 3u, &displacement, sizeof(displacement));
    const auto value = static_cast<std::uint64_t>(target);
    const auto low = static_cast<std::uint32_t>(value);
    const auto high = static_cast<std::uint32_t>(value >> 32u);
    std::memcpy(output + 7u, &low, sizeof(low));
    output[11] = 0xc7u; output[12] = 0x84u; output[13] = 0x24u;
    const std::uint32_t high_displacement = displacement + 4u;
    std::memcpy(output + 14u, &high_displacement, sizeof(high_displacement));
    std::memcpy(output + 18u, &high, sizeof(high));
    output[22] = 0xffu; output[23] = 0xa4u; output[24] = 0x24u;
    std::memcpy(output + 25u, &displacement, sizeof(displacement));
}

bool status_is(entry::Status actual, entry::Status expected) {
    return actual == expected;
}

void test_specs() {
    const entry::EntryKind invalid = static_cast<entry::EntryKind>(3u);
    check(entry::spec(invalid).kind == entry::EntryKind::router,
          "invalid_kind_spec_falls_back_safely");
    const entry::Spec& router = entry::spec(entry::EntryKind::router);
    const entry::Spec& message = entry::spec(entry::EntryKind::message);
    const entry::Spec& cleanup = entry::spec(entry::EntryKind::cleanup);
    check(router.rva == 0x23a020u && router.end_rva == 0x23a6b8u
              && router.prefix_bytes == 26u && router.stack_delta == 184u,
          "router_fixed_spec");
    check(message.rva == 0x244630u && message.end_rva == 0x2446eeu
              && message.prefix_bytes == 16u && message.stack_delta == 264u,
          "message_fixed_spec");
    check(message.prefix[13] == 0x48u && message.prefix[14] == 0x8bu
              && message.prefix[15] == 0xdau,
          "message_exact_pe_16_byte_tail");
    check(cleanup.rva == 0x1af740u && cleanup.end_rva == 0x1af755u
              && cleanup.unwind_rva == 0x1dcad04u
              && cleanup.prefix_bytes == 16u
              && cleanup.stack_delta == 40u
              && cleanup.unwind_bytes == 12u
              && cleanup.projected_unwind_bytes == 12u
              && cleanup.unwind_code_count == 4u,
          "cleanup_fixed_spec");
    const std::array<unsigned char, 16> cleanup_prefix{{
        0x48u,0x89u,0x5cu,0x24u,0x10u,0x56u,0x48u,0x83u,
        0xecu,0x20u,0x48u,0x8bu,0x19u,0x48u,0x8bu,0xf1u,
    }};
    check(same_bytes(cleanup.prefix.data(), cleanup_prefix.data(),
                     cleanup_prefix.size()),
          "cleanup_exact_pe_16_byte_prefix");
    check(router.unwind_bytes == 28u && message.unwind_bytes == 16u
              && router.unwind_expected[24] == 0x9cu
              && message.unwind_expected[12] == 0x9cu,
          "unwind_prefix_and_handler_are_pinned");
    const std::array<unsigned char, 12> cleanup_unwind{{
        0x01u,0x0au,0x04u,0x00u,0x0au,0x34u,
        0x07u,0x00u,0x0au,0x32u,0x06u,0x60u,
    }};
    check(same_bytes(cleanup.unwind_expected.data(), cleanup_unwind.data(),
                     cleanup_unwind.size()),
          "cleanup_exact_unwind_without_handler");
    std::printf("SPEC router rva=%x end=%x prefix=%u unwind=%u delta=%u\n",
                router.rva, router.end_rva, router.prefix_bytes,
                router.unwind_bytes, router.stack_delta);
    std::printf("SPEC message rva=%x end=%x prefix=%u unwind=%u delta=%u\n",
                message.rva, message.end_rva, message.prefix_bytes,
                message.unwind_bytes, message.stack_delta);
    std::printf("SPEC cleanup rva=%x end=%x prefix=%u unwind=%u delta=%u\n",
                cleanup.rva, cleanup.end_rva, cleanup.prefix_bytes,
                cleanup.unwind_bytes, cleanup.stack_delta);
}

void initialize_sentinel(entry::Plan& plan, unsigned char value) {
    plan = entry::Plan{};
    plan.image.fill(value);
    plan.patch.fill(value);
    plan.runtime.begin = 0xa1a1a1a1u;
    plan.runtime.end = 0xb2b2b2b2u;
    plan.runtime.unwind = 0xc3c3c3c3u;
    plan.image_bytes = 17u;
    plan.patch_bytes = 19u;
    plan.prologue_bytes = 23u;
    plan.unwind_bytes = 29u;
    plan.original_entry = UINT64_C(0x1111222233334444);
    plan.continuation = UINT64_C(0x5555666677778888);
    plan.hook = UINT64_C(0x9999aaaabbbbcccc);
}

void test_prepare_one(entry::EntryKind kind) {
    const entry::Spec& selected = entry::spec(kind);
    auto prefix = prefix_for(selected);
    auto unwind = unwind_for(selected);
    const entry::Address original = entry::kStaticImageBase
        + static_cast<entry::Address>(selected.rva);
    const entry::Address hook = original + 0x10000u;
    entry::Plan plan{};
    const entry::Status status = entry::prepare(
        kind, prefix.data(), selected.prefix_bytes,
        unwind.data(), selected.unwind_bytes, original, hook, plan);
    check(status_is(status, entry::Status::prepared),
          kind_label(kind, "prepare_router", "prepare_message",
                     "prepare_cleanup"));
    if (status != entry::Status::prepared) return;

    check(same_bytes(plan.image.data(), selected.prefix.data(),
                     selected.prefix_bytes),
          kind_label(kind, "router_prefix_copied", "message_prefix_copied",
                     "cleanup_prefix_copied"));
    std::array<unsigned char, entry::kHomeSlotJumpBytes> tail{};
    expected_home_slot_jump(
        tail.data(), selected.stack_delta + entry::kHomeSlotOffset,
        plan.continuation);
    check(same_bytes(plan.image.data() + selected.prefix_bytes,
                     tail.data(), tail.size()),
          kind_label(kind, "router_disp32_tail", "message_disp32_tail",
                     "cleanup_disp32_tail"));
    std::array<unsigned char, entry::kMaxUnwindBytes> projected{};
    std::memcpy(projected.data(), selected.unwind_expected.data(),
                selected.projected_unwind_bytes);
    projected[0] = static_cast<unsigned char>(projected[0] & 0x07u);
    check(same_bytes(plan.image.data() + entry::kUnwindOffset,
                     projected.data(), selected.projected_unwind_bytes),
          kind_label(kind, "router_handler_cleared_unwind",
                     "message_handler_cleared_unwind",
                     "cleanup_handler_cleared_unwind"));
    check(plan.runtime.begin == 0u
              && plan.runtime.end == selected.prefix_bytes
                    + entry::kHomeSlotJumpBytes
              && plan.runtime.unwind == entry::kUnwindOffset
              && plan.prologue_bytes == selected.unwind_expected[1]
              && plan.image_bytes == entry::kUnwindOffset
                    + selected.projected_unwind_bytes,
          kind_label(kind, "router_runtime_row", "message_runtime_row",
                     "cleanup_runtime_row"));
    check(plan.patch[0] == 0xffu && plan.patch[1] == 0x25u
              && plan.patch[2] == 0u && plan.patch[5] == 0u
              && read_u64(plan.patch.data() + 6u) == hook,
          kind_label(kind, "router_absolute_patch", "message_absolute_patch",
                     "cleanup_absolute_patch"));
    bool nops = true;
    for (std::size_t index = entry::kAbsoluteJumpBytes;
         index < selected.prefix_bytes; ++index) {
        nops = nops && plan.patch[index] == 0x90u;
    }
    check(nops, kind_label(kind, "router_patch_nop_fill",
                           "message_patch_nop_fill",
                           "cleanup_patch_nop_fill"));

    entry::Plan before{};
    entry::Plan after{};
    initialize_sentinel(before, 0xa5u);
    after = before;
    check(status_is(entry::prepare(
              kind, nullptr, selected.prefix_bytes, unwind.data(),
              selected.unwind_bytes, original, hook, after),
              entry::Status::invalid_buffer)
              && same_bytes(&before, &after, sizeof(before)),
          "null_prefix_output_unchanged");

    before = after;
    check(status_is(entry::prepare(
              kind, prefix.data(), selected.prefix_bytes - 1u,
              unwind.data(), selected.unwind_bytes, original, hook, after),
              entry::Status::invalid_buffer)
              && same_bytes(&before, &after, sizeof(before)),
          "short_prefix_output_unchanged");

    before = after;
    check(status_is(entry::prepare(
              kind, prefix.data(), selected.prefix_bytes,
              unwind.data(), selected.unwind_bytes, original, original, after),
              entry::Status::invalid_identity)
              && same_bytes(&before, &after, sizeof(before)),
          "same_entry_hook_output_unchanged");

    before = after;
    auto bad_prefix = prefix;
    bad_prefix[0] ^= 1u;
    check(status_is(entry::prepare(
              kind, bad_prefix.data(), selected.prefix_bytes,
              unwind.data(), selected.unwind_bytes, original, hook, after),
              entry::Status::prologue_mismatch)
              && same_bytes(&before, &after, sizeof(before)),
          "bad_prefix_output_unchanged");

    before = after;
    auto bad_unwind = unwind;
    bad_unwind[0] ^= 1u;
    check(status_is(entry::prepare(
              kind, prefix.data(), selected.prefix_bytes,
              bad_unwind.data(), selected.unwind_bytes, original, hook, after),
              entry::Status::unwind_mismatch)
              && same_bytes(&before, &after, sizeof(before)),
          "bad_unwind_output_unchanged");

    before = after;
    std::array<unsigned char, 64> overlapping{};
    std::memcpy(overlapping.data(), prefix.data(), selected.prefix_bytes);
    std::memcpy(overlapping.data() + 8u, unwind.data(), selected.unwind_bytes);
    check(status_is(entry::prepare(
              kind, overlapping.data(), selected.prefix_bytes,
              overlapping.data() + 8u, selected.unwind_bytes,
              original, hook, after), entry::Status::input_alias)
              && same_bytes(&before, &after, sizeof(before)),
          "input_alias_output_unchanged");

    before = after;
    check(status_is(entry::prepare(
              kind, after.image.data(), selected.prefix_bytes,
              unwind.data(), selected.unwind_bytes, original, hook, after),
              entry::Status::output_alias)
              && same_bytes(&before, &after, sizeof(before)),
          "output_alias_output_unchanged");
}

void test_invalid_kind_prepare() {
    const entry::EntryKind invalid = static_cast<entry::EntryKind>(3u);
    const auto prefix = prefix_for(entry::spec(entry::EntryKind::router));
    const auto unwind = unwind_for(entry::spec(entry::EntryKind::router));
    entry::Plan before{};
    entry::Plan after{};
    initialize_sentinel(before, 0x5au);
    after = before;
    const entry::Status status = entry::prepare(
        invalid, prefix.data(), 26u, unwind.data(), 28u,
        entry::kStaticImageBase + 0x23a020u,
        entry::kStaticImageBase + 0x33a020u, after);
    check(status == entry::Status::invalid_kind
              && same_bytes(&before, &after, sizeof(before)),
          "invalid_kind_prepare_output_unchanged");
}

void write_qword(unsigned char* address, std::uint64_t value) {
    std::memcpy(address, &value, sizeof(value));
}

unsigned router_pushes_before(unsigned pc) {
    constexpr std::array<unsigned, 7> offsets{{5u, 6u, 7u, 8u, 10u, 12u, 14u}};
    unsigned count = 0u;
    for (const unsigned offset : offsets) if (offset < pc) ++count;
    return count;
}

unsigned pushes_before(entry::EntryKind kind, unsigned pc) {
    if (kind == entry::EntryKind::router) return router_pushes_before(pc);
    return pc > 5u ? 1u : 0u;
}

std::size_t stack_adjust_before(entry::EntryKind kind, unsigned pc) {
    if (kind == entry::EntryKind::router) return pc > 19u ? 0x80u : 0u;
    if (kind == entry::EntryKind::cleanup) return pc > 6u ? 0x20u : 0u;
    return pc > 6u ? 0x100u : 0u;
}

bool unwind_one(entry::EntryKind kind, unsigned char* image,
                const entry::Plan& plan, const RUNTIME_FUNCTION& function,
                DWORD64 image_base, unsigned pc, unsigned char* stack) {
    const unsigned pushes = pushes_before(kind, pc);
    const std::size_t adjustment = stack_adjust_before(kind, pc);
    auto caller_rsp = reinterpret_cast<unsigned char*>(
        (reinterpret_cast<std::uintptr_t>(stack + 0x8000u)
         & ~static_cast<std::uintptr_t>(0x0fu)));
    write_qword(caller_rsp, kReturnAddress);
    // The router's first home-store is part of the copied prefix and the
    // projected unwind therefore restores RBX from the caller home slot.
    write_qword(caller_rsp + 0x10u, kRbx);
    const std::array<std::uint64_t, 7> saved{{
        kind == entry::EntryKind::router
            ? kRbp
            : (kind == entry::EntryKind::message ? kRbx : kRsi),
        kind == entry::EntryKind::router
            ? kRsi
            : (kind == entry::EntryKind::message ? kRbp : kRsi),
        kind == entry::EntryKind::router
            ? kRdi
            : (kind == entry::EntryKind::message ? kRsi : kRsi),
        kind == entry::EntryKind::router
            ? kR12
            : (kind == entry::EntryKind::message ? kRdi : kRsi),
        kind == entry::EntryKind::router
            ? kR13
            : (kind == entry::EntryKind::message ? kR12 : kRsi),
        kind == entry::EntryKind::router
            ? kR14
            : (kind == entry::EntryKind::message ? kR13 : kRsi),
        kind == entry::EntryKind::router
            ? kR15
            : (kind == entry::EntryKind::message ? kR14 : kRsi),
    }};
    for (unsigned index = 0u; index < pushes; ++index) {
        write_qword(caller_rsp - 8u * (index + 1u), saved[index]);
    }

    CONTEXT context{};
    context.ContextFlags = CONTEXT_FULL;
    context.Rip = reinterpret_cast<DWORD64>(image + pc);
    context.Rsp = reinterpret_cast<DWORD64>(caller_rsp
        - 8u * pushes - adjustment);
    context.Rbx = kRbx;
    context.Rbp = kRbp;
    context.Rsi = kRsi;
    context.Rdi = kRdi;
    context.R12 = kR12;
    context.R13 = kR13;
    context.R14 = kR14;
    context.R15 = kR15;
    PVOID handler_data = nullptr;
    DWORD64 establisher_frame = 0u;
    KNONVOLATILE_CONTEXT_POINTERS nonvolatile{};
    DWORD64 lookup_base = 0u;
    PRUNTIME_FUNCTION found = RtlLookupFunctionEntry(
        context.Rip, &lookup_base, nullptr);
    bool restored = false;
    bool handler_null = false;
    bool metadata = false;
    if (found != nullptr && lookup_base == image_base
            && found->BeginAddress == function.BeginAddress
            && found->EndAddress == function.EndAddress
            && found->UnwindData == function.UnwindData) {
        const EXCEPTION_ROUTINE* handler = RtlVirtualUnwind(
            UNW_FLAG_NHANDLER, image_base, context.Rip, found, &context,
            &handler_data, &establisher_frame, &nonvolatile);
        handler_null = handler == nullptr && handler_data == nullptr;
        metadata = image[function.UnwindData] == 0x01u
            && image[function.UnwindData + 1u]
                == static_cast<unsigned char>(plan.prologue_bytes);
        restored = context.Rip == kReturnAddress
            && context.Rsp == reinterpret_cast<DWORD64>(caller_rsp + 8u)
            && context.Rbx == kRbx
            && context.Rbp == kRbp && context.Rsi == kRsi
            && context.Rdi == kRdi && context.R12 == kR12
            && context.R13 == kR13 && context.R14 == kR14
            && context.R15 == kR15;
    }
    const bool lookup = found != nullptr && lookup_base == image_base;
    std::printf("UNWIND kind=%s pc=%u lookup=%s metadata=%s handler_null=%s "
                "restored=%s\n",
                kind == entry::EntryKind::router
                    ? "router"
                    : (kind == entry::EntryKind::message ? "message"
                                                         : "cleanup"), pc,
                lookup ? "PASS" : "FAIL", metadata ? "PASS" : "FAIL",
                handler_null ? "PASS" : "FAIL", restored ? "PASS" : "FAIL");
    return lookup && metadata && handler_null && restored;
}

void append_body(unsigned char* destination, std::size_t& cursor) {
    // mov r11, &g_body_hits; mov dword ptr [r11], 1
    destination[cursor++] = 0x49u;
    destination[cursor++] = 0xbbu;
    write_qword(destination + cursor,
                reinterpret_cast<std::uintptr_t>(&g_body_hits));
    cursor += 8u;
    destination[cursor++] = 0x41u;
    destination[cursor++] = 0xc7u;
    destination[cursor++] = 0x03u;
    destination[cursor++] = 0x01u;
    destination[cursor++] = 0x00u;
    destination[cursor++] = 0x00u;
    destination[cursor++] = 0x00u;
}

void append_epilogue(entry::EntryKind kind, unsigned char* destination,
                     std::size_t& cursor) {
    if (kind == entry::EntryKind::router) {
        const unsigned char bytes[] = {
            0x48u,0x81u,0xc4u,0x80u,0x00u,0x00u,0x00u,
            0x41u,0x5fu,0x41u,0x5eu,0x41u,0x5du,0x41u,0x5cu,
            0x5fu,0x5eu,0x5du,0x48u,0x8bu,0x5cu,0x24u,0x10u,
            0xc3u,
        };
        std::memcpy(destination + cursor, bytes, sizeof(bytes));
        cursor += sizeof(bytes);
    } else if (kind == entry::EntryKind::message) {
        const unsigned char bytes[] = {
            0x48u,0x81u,0xc4u,0x00u,0x01u,0x00u,0x00u,
            0x5bu,0xc3u,
        };
        std::memcpy(destination + cursor, bytes, sizeof(bytes));
        cursor += sizeof(bytes);
    } else {
        const unsigned char bytes[] = {
            0x48u,0x83u,0xc4u,0x20u,0x5eu,
            0x48u,0x8bu,0x5cu,0x24u,0x10u,0xc3u,
        };
        std::memcpy(destination + cursor, bytes, sizeof(bytes));
        cursor += sizeof(bytes);
    }
}

bool run_real_case(entry::EntryKind kind) {
    const entry::Spec& selected = entry::spec(kind);
    auto* source = static_cast<unsigned char*>(VirtualAlloc(
        nullptr, kSourceBytes, MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE));
    auto* trampoline = static_cast<unsigned char*>(VirtualAlloc(
        nullptr, kPageBytes, MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE));
    auto* stack = static_cast<unsigned char*>(VirtualAlloc(
        nullptr, kStackBytes, MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE));
    check(source != nullptr && trampoline != nullptr && stack != nullptr,
          kind_label(kind, "router_virtual_alloc", "message_virtual_alloc",
                     "cleanup_virtual_alloc"));
    if (source == nullptr || trampoline == nullptr || stack == nullptr) {
        if (source) (void)VirtualFree(source, 0, MEM_RELEASE);
        if (trampoline) (void)VirtualFree(trampoline, 0, MEM_RELEASE);
        if (stack) (void)VirtualFree(stack, 0, MEM_RELEASE);
        return false;
    }

    auto prefix = prefix_for(selected);
    auto unwind = unwind_for(selected);
    std::memcpy(source, prefix.data(), selected.prefix_bytes);
    std::size_t body_cursor = selected.prefix_bytes;
    append_body(source, body_cursor);
    append_epilogue(kind, source, body_cursor);
    entry::Plan plan{};
    const entry::Address original = reinterpret_cast<entry::Address>(source);
    const entry::Address hook = reinterpret_cast<entry::Address>(source + 0x300u);
    const entry::Status status = entry::prepare(
        kind, prefix.data(), selected.prefix_bytes,
        unwind.data(), selected.unwind_bytes, original, hook, plan);
    check(status == entry::Status::prepared,
          kind_label(kind, "router_real_prepare", "message_real_prepare",
                     "cleanup_real_prepare"));
    if (status != entry::Status::prepared) {
        (void)VirtualFree(source, 0, MEM_RELEASE);
        (void)VirtualFree(trampoline, 0, MEM_RELEASE);
        (void)VirtualFree(stack, 0, MEM_RELEASE);
        return false;
    }
    std::memcpy(trampoline, plan.image.data(), plan.image_bytes);
    DWORD old_protection = 0u;
    check(VirtualProtect(trampoline, kPageBytes, PAGE_EXECUTE_READ,
                         &old_protection) != FALSE,
          kind_label(kind, "router_rx_trampoline", "message_rx_trampoline",
                     "cleanup_rx_trampoline"));
    check(VirtualProtect(source, kSourceBytes, PAGE_EXECUTE_READ,
                         &old_protection) != FALSE,
          kind_label(kind, "router_rx_native_body", "message_rx_native_body",
                     "cleanup_rx_native_body"));
    FlushInstructionCache(GetCurrentProcess(), trampoline, plan.image_bytes);
    FlushInstructionCache(GetCurrentProcess(), source, body_cursor);

    RUNTIME_FUNCTION function{};
    function.BeginAddress = plan.runtime.begin;
    function.EndAddress = plan.runtime.end;
    function.UnwindData = plan.runtime.unwind;
    const DWORD64 image_base = reinterpret_cast<DWORD64>(trampoline);
    const bool registered = RtlAddFunctionTable(&function, 1, image_base) != FALSE;
    check(registered,
          kind_label(kind, "router_register_runtime",
                     "message_register_runtime", "cleanup_register_runtime"));
    if (registered) {
        const std::array<unsigned, 14> router_pcs{{
            0u,5u,6u,7u,8u,10u,12u,14u,16u,19u,26u,37u,48u,54u,
        }};
        const std::array<unsigned, 8> message_pcs{{
            0u,5u,6u,13u,16u,27u,38u,44u,
        }};
        const std::array<unsigned, 8> cleanup_pcs{{
            0u,5u,6u,10u,13u,16u,27u,44u,
        }};
        bool unwind_ok = true;
        if (kind == entry::EntryKind::router) {
            for (const unsigned pc : router_pcs) {
                unwind_ok = unwind_one(kind, trampoline, plan, function,
                                       image_base, pc, stack) && unwind_ok;
            }
        } else if (kind == entry::EntryKind::message) {
            for (const unsigned pc : message_pcs) {
                unwind_ok = unwind_one(kind, trampoline, plan, function,
                                       image_base, pc, stack) && unwind_ok;
            }
        } else {
            for (const unsigned pc : cleanup_pcs) {
                unwind_ok = unwind_one(kind, trampoline, plan, function,
                                       image_base, pc, stack) && unwind_ok;
            }
        }
        check(unwind_ok,
              kind_label(kind, "router_unwind_boundaries",
                         "message_unwind_boundaries",
                         "cleanup_unwind_boundaries"));
        g_body_hits = 0u;
        g_after_rsp = g_after_rbx = g_after_rbp = g_after_rsi = 0u;
        g_after_rdi = g_after_r12 = g_after_r13 = g_after_r14 = g_after_r15 = 0u;
        g_before_flags = g_after_flags = 0u;
        invoke_candidate(trampoline);
        const bool execution_ok = g_body_hits == 1u
            && g_after_rbx == kRbx && g_after_rbp == kRbp
            && g_after_rsi == kRsi && g_after_rdi == kRdi
            && g_after_r12 == kR12 && g_after_r13 == kR13
            && g_after_r14 == kR14 && g_after_r15 == kR15;
        check(execution_ok,
              kind_label(kind, "router_rx_execution", "message_rx_execution",
                         "cleanup_rx_execution"));
        check(RtlDeleteFunctionTable(&function) != FALSE,
              kind_label(kind, "router_delete_runtime",
                         "message_delete_runtime", "cleanup_delete_runtime"));
    }
    check(VirtualFree(stack, 0, MEM_RELEASE) != FALSE,
          kind_label(kind, "router_free_stack", "message_free_stack",
                     "cleanup_free_stack"));
    check(VirtualFree(trampoline, 0, MEM_RELEASE) != FALSE,
          kind_label(kind, "router_free_trampoline", "message_free_trampoline",
                     "cleanup_free_trampoline"));
    check(VirtualFree(source, 0, MEM_RELEASE) != FALSE,
          kind_label(kind, "router_free_source", "message_free_source",
                     "cleanup_free_source"));
    return true;
}

}  // namespace

int main() {
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    std::printf("TEST information-battle-message-entry-plan\n");
    test_specs();
    test_invalid_kind_prepare();
    test_prepare_one(entry::EntryKind::router);
    test_prepare_one(entry::EntryKind::message);
    test_prepare_one(entry::EntryKind::cleanup);
    (void)run_real_case(entry::EntryKind::router);
    (void)run_real_case(entry::EntryKind::message);
    (void)run_real_case(entry::EntryKind::cleanup);
    std::printf("SUMMARY checks_failed=%u status=%s\n", g_failures,
                g_failures == 0u ? "PASS" : "FAIL");
    std::printf("RESULT %s\n", g_failures == 0u ? "PASS" : "FAIL");
    return g_failures == 0u ? 0 : 1;
}
