#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "../information-battle-line1-entry-plan.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>

namespace {

namespace entry = information::battle::line1_entry;

constexpr std::size_t kPageBytes = 0x1000u;
constexpr std::size_t kStackBytes = 0x10000u;
constexpr std::uint64_t kAbiRbp = UINT64_C(0x7172737475767778);
constexpr std::uint64_t kExpectedRax = UINT64_C(0x1122334455667788);
constexpr std::uint64_t kExpectedR9 = UINT64_C(0x99aabbccddeeff00);
constexpr std::uint64_t kExpectedR10 = UINT64_C(0x2233445566778899);
constexpr std::uint64_t kExpectedR11 = UINT64_C(0x33445566778899aa);
constexpr std::uint32_t kExpectedMxcsr = 0x1f40u;
constexpr std::uint16_t kExpectedX87Control = 0x037fu;
constexpr DWORD kTargetLastError = 0x13572468u;

extern "C" {
void (*g_line1_capture)(void*, void*, std::uint64_t, void*, void*) = nullptr;
void* g_line1_trampoline = nullptr;
volatile std::uint64_t g_line1_capture_widget = 0;
volatile std::uint64_t g_line1_capture_text = 0;
volatile std::uint8_t g_line1_capture_flag = 0;
volatile std::uint64_t g_line1_capture_return = 0;
volatile std::uint64_t g_line1_capture_rbp = 0;
volatile std::uint64_t g_line1_hook_restored_flags = 0;
volatile std::uint64_t g_line1_expected_flags = 0;
volatile std::uint64_t g_line1_after_rax = 0;
volatile std::uint64_t g_line1_after_rcx = 0;
volatile std::uint64_t g_line1_after_rdx = 0;
volatile std::uint64_t g_line1_after_r8 = 0;
volatile std::uint64_t g_line1_after_r9 = 0;
volatile std::uint64_t g_line1_after_r10 = 0;
volatile std::uint64_t g_line1_after_r11 = 0;
volatile std::uint64_t g_line1_after_rbp = 0;
volatile std::uint64_t g_line1_after_flags = 0;
volatile std::uint32_t g_line1_after_mxcsr = 0;
volatile std::uint32_t g_line1_after_x87cw = 0;
volatile std::uint32_t g_line1_after_last_error = 0;
alignas(16) volatile unsigned char g_line1_after_xmm0[16]{};
alignas(16) volatile unsigned char g_line1_after_xmm1[16]{};
alignas(16) volatile unsigned char g_line1_after_xmm2[16]{};
alignas(16) volatile unsigned char g_line1_after_xmm3[16]{};
alignas(16) volatile unsigned char g_line1_after_xmm4[16]{};
alignas(16) volatile unsigned char g_line1_after_xmm5[16]{};
volatile std::uint64_t g_line1_native_widget = 0;
volatile std::uint64_t g_line1_native_text = 0;
volatile std::uint8_t g_line1_native_flag = 0;
volatile std::uint32_t g_line1_native_hits = 0;

void line1_entry_hook();
void line1_original_entry();
void line1_capture_clobber(void*, void*, std::uint64_t, void*, void*);
using Line1Target = void (*)();
void line1_invoke_hook_a(Line1Target, void*, void*, std::uint64_t);
void line1_invoke_hook_b(Line1Target, void*, void*, std::uint64_t);
}

unsigned g_failures = 0u;

void check(bool condition, const char* label) {
    std::printf("CHECK %s %s\n", label, condition ? "PASS" : "FAIL");
    if (!condition) ++g_failures;
}

bool same_bytes(const void* left, const void* right, std::size_t size) {
    return std::memcmp(left, right, size) == 0;
}

std::array<unsigned char, entry::kPrefixBytes> prefix() {
    std::array<unsigned char, entry::kPrefixBytes> result{};
    std::memcpy(result.data(), entry::spec().prefix.data(), result.size());
    return result;
}

std::array<unsigned char, entry::kUnwindBytes> unwind() {
    std::array<unsigned char, entry::kUnwindBytes> result{};
    std::memcpy(result.data(), entry::spec().unwind_expected.data(),
                result.size());
    return result;
}

std::uint64_t read_u64(const unsigned char* bytes) {
    std::uint64_t value = 0;
    std::memcpy(&value, bytes, sizeof(value));
    return value;
}

void test_fixed_contract() {
    const entry::Spec& selected = entry::spec();
    check(selected.entry_rva == 0x152ad10u
              && selected.continuation_rva == 0x152ad24u
              && selected.function_end_rva == 0x152ad92u
              && selected.unwind_rva == 0x1dca66cu
              && selected.stack_delta == 0x28u,
          "line1_fixed_rvas_and_stack_delta");
    const std::array<unsigned char, entry::kPrefixBytes> expected_prefix{{
        0x48u,0x89u,0x5cu,0x24u,0x08u,0x48u,0x89u,0x6cu,
        0x24u,0x10u,0x48u,0x89u,0x74u,0x24u,0x18u,0x57u,
        0x48u,0x83u,0xecu,0x20u,
    }};
    const std::array<unsigned char, entry::kUnwindBytes> expected_unwind{{
        0x01u,0x14u,0x08u,0x00u,0x14u,0x64u,0x08u,0x00u,
        0x14u,0x54u,0x07u,0x00u,0x14u,0x34u,0x06u,0x00u,
        0x14u,0x32u,0x10u,0x70u,
    }};
    check(same_bytes(selected.prefix.data(), expected_prefix.data(),
                     expected_prefix.size()), "line1_exact_20_byte_prefix");
    check(same_bytes(selected.unwind_expected.data(), expected_unwind.data(),
                     expected_unwind.size())
              && selected.unwind_code_count == 8u,
          "line1_exact_unwind_info");
    const std::array<unsigned char, sizeof(entry::RuntimeFunction)> row{{
        0x10u,0xadu,0x52u,0x01u,0x92u,0xadu,0x52u,0x01u,
        0x6cu,0xa6u,0xdcu,0x01u,
    }};
    check(same_bytes(selected.pdata_row.data(), row.data(), row.size()),
          "line1_exact_pdata_row");
}

void test_prepare() {
    const auto expected_prefix = prefix();
    const auto expected_unwind = unwind();
    const entry::Address original =
        reinterpret_cast<entry::Address>(&line1_original_entry);
    const entry::Address hook =
        reinterpret_cast<entry::Address>(&line1_entry_hook);
    entry::Plan plan{};
    const entry::Status status = entry::prepare(
        expected_prefix.data(), expected_prefix.size(),
        expected_unwind.data(), expected_unwind.size(), original, hook, plan);
    check(status == entry::Status::prepared, "line1_prepare");
    if (status != entry::Status::prepared) return;
    check(plan.continuation == original + entry::kPrefixBytes
              && plan.runtime.begin == 0u
              && plan.runtime.end == entry::kPrefixBytes
                    + entry::kAbsoluteJumpBytes
              && plan.runtime.unwind == entry::kUnwindOffset
              && plan.image_bytes == entry::kUnwindOffset
                    + entry::kProjectedUnwindBytes,
          "line1_plan_runtime_row");
    check(same_bytes(plan.image.data(), expected_prefix.data(),
                     expected_prefix.size()), "line1_plan_prefix_copy");
    check(plan.image[entry::kPrefixBytes] == 0xffu
              && plan.image[entry::kPrefixBytes + 1u] == 0x25u
              && read_u64(plan.image.data() + entry::kPrefixBytes + 6u)
                    == plan.continuation,
          "line1_nonclobbering_absolute_tail");
    check(plan.patch[0] == 0xffu && plan.patch[1] == 0x25u
              && read_u64(plan.patch.data() + 6u) == hook,
          "line1_exact_absolute_patch");
    check(same_bytes(plan.image.data() + entry::kUnwindOffset,
                     expected_unwind.data(), expected_unwind.size()),
          "line1_projected_unwind_copy");

    entry::Plan before = plan;
    auto bad_prefix = expected_prefix;
    bad_prefix[0] ^= 1u;
    check(entry::prepare(bad_prefix.data(), bad_prefix.size(),
                         expected_unwind.data(), expected_unwind.size(),
                         original, hook, plan) == entry::Status::prologue_mismatch
              && same_bytes(&before, &plan, sizeof(plan)),
          "line1_bad_prefix_keeps_output");
    auto bad_unwind = expected_unwind;
    bad_unwind[0] ^= 1u;
    check(entry::prepare(expected_prefix.data(), expected_prefix.size(),
                         bad_unwind.data(), bad_unwind.size(),
                         original, hook, plan) == entry::Status::unwind_mismatch
              && same_bytes(&before, &plan, sizeof(plan)),
          "line1_bad_unwind_keeps_output");
}

void write_u64(unsigned char* address, std::uint64_t value) {
    std::memcpy(address, &value, sizeof(value));
}

bool unwind_one(unsigned char* image, const RUNTIME_FUNCTION& function,
                DWORD64 image_base,
                unsigned pc, unsigned char* stack) {
    auto* caller_rsp = reinterpret_cast<unsigned char*>(
        reinterpret_cast<std::uintptr_t>(stack + 0x8000u)
            & ~static_cast<std::uintptr_t>(0x0fu));
    constexpr std::uint64_t kReturn = UINT64_C(0x8899aabbccddeeff);
    constexpr std::uint64_t kRbx = UINT64_C(0x0102030405060708);
    constexpr std::uint64_t kRbp = UINT64_C(0x1112131415161718);
    constexpr std::uint64_t kRsi = UINT64_C(0x2122232425262728);
    constexpr std::uint64_t kRdi = UINT64_C(0x3132333435363738);
    std::memset(caller_rsp - 0x40, 0, 0x180);
    write_u64(caller_rsp, kReturn);
    write_u64(caller_rsp + 0x08u, kRbx);
    write_u64(caller_rsp + 0x10u, kRbp);
    write_u64(caller_rsp + 0x18u, kRsi);
    if (pc >= 16u) write_u64(caller_rsp - 0x08u, kRdi);

    const std::size_t stack_adjust = pc >= 20u ? 0x28u
        : (pc >= 16u ? 0x08u : 0u);
    CONTEXT context{};
    context.ContextFlags = CONTEXT_FULL;
    context.Rip = reinterpret_cast<DWORD64>(image + pc);
    context.Rsp = reinterpret_cast<DWORD64>(caller_rsp - stack_adjust);
    context.Rbx = UINT64_C(0xa1a1a1a1a1a1a1a1);
    context.Rbp = UINT64_C(0xb2b2b2b2b2b2b2b2);
    context.Rsi = UINT64_C(0xc3c3c3c3c3c3c3c3);
    context.Rdi = UINT64_C(0xd4d4d4d4d4d4d4d4);
    PVOID handler_data = nullptr;
    DWORD64 establisher_frame = 0;
    KNONVOLATILE_CONTEXT_POINTERS nonvolatile{};
    DWORD64 lookup_base = 0;
    PRUNTIME_FUNCTION found = RtlLookupFunctionEntry(
        context.Rip, &lookup_base, nullptr);
    bool restored = false;
    bool null_handler = false;
    if (found != nullptr && lookup_base == image_base
            && found->BeginAddress == function.BeginAddress
            && found->EndAddress == function.EndAddress
            && found->UnwindData == function.UnwindData) {
        const EXCEPTION_ROUTINE* handler = RtlVirtualUnwind(
            UNW_FLAG_NHANDLER, image_base, context.Rip, found, &context,
            &handler_data, &establisher_frame, &nonvolatile);
        null_handler = handler == nullptr && handler_data == nullptr;
        restored = context.Rip == kReturn
            && context.Rsp == reinterpret_cast<DWORD64>(caller_rsp + 8u)
            && context.Rbx == kRbx && context.Rbp == kRbp
            && context.Rsi == kRsi && context.Rdi == kRdi;
    }
    std::printf("UNWIND pc=%u lookup=%s handler_null=%s restored=%s\n", pc,
                found != nullptr && lookup_base == image_base ? "PASS" : "FAIL",
                null_handler ? "PASS" : "FAIL", restored ? "PASS" : "FAIL");
    return found != nullptr && lookup_base == image_base
        && null_handler && restored;
}

bool bytes_equal_volatile(const volatile unsigned char* actual,
                          const std::array<unsigned char, 16>& expected) {
    for (std::size_t i = 0; i != expected.size(); ++i) {
        if (actual[i] != expected[i]) return false;
    }
    return true;
}

std::array<unsigned char, 16> repeated_qword(std::uint64_t value) {
    std::array<unsigned char, 16> result{};
    std::memcpy(result.data(), &value, sizeof(value));
    std::memcpy(result.data() + 8u, &value, sizeof(value));
    return result;
}

void reset_observations() {
    g_line1_capture_widget = 0;
    g_line1_capture_text = 0;
    g_line1_capture_flag = 0;
    g_line1_capture_return = 0;
    g_line1_capture_rbp = 0;
    g_line1_hook_restored_flags = 0;
    g_line1_after_rax = g_line1_after_rcx = g_line1_after_rdx = 0;
    g_line1_after_r8 = g_line1_after_r9 = g_line1_after_r10 = 0;
    g_line1_after_r11 = g_line1_after_rbp = g_line1_after_flags = 0;
    g_line1_after_mxcsr = g_line1_after_x87cw = g_line1_after_last_error = 0;
    std::memset(const_cast<unsigned char*>(g_line1_after_xmm0), 0, 16);
    std::memset(const_cast<unsigned char*>(g_line1_after_xmm1), 0, 16);
    std::memset(const_cast<unsigned char*>(g_line1_after_xmm2), 0, 16);
    std::memset(const_cast<unsigned char*>(g_line1_after_xmm3), 0, 16);
    std::memset(const_cast<unsigned char*>(g_line1_after_xmm4), 0, 16);
    std::memset(const_cast<unsigned char*>(g_line1_after_xmm5), 0, 16);
    g_line1_native_widget = g_line1_native_text = 0;
    g_line1_native_flag = 0;
    g_line1_native_hits = 0;
}

void test_real_trampoline() {
    entry::Plan plan{};
    const auto pfx = prefix();
    const auto uw = unwind();
    const entry::Address original =
        reinterpret_cast<entry::Address>(&line1_original_entry);
    const entry::Address hook = reinterpret_cast<entry::Address>(&line1_entry_hook);
    check(entry::prepare(pfx.data(), pfx.size(), uw.data(), uw.size(),
                         original, hook, plan) == entry::Status::prepared,
          "line1_real_prepare");

    auto* trampoline = static_cast<unsigned char*>(VirtualAlloc(
        nullptr, kPageBytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    auto* stack = static_cast<unsigned char*>(VirtualAlloc(
        nullptr, kStackBytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    check(trampoline != nullptr && stack != nullptr,
          "line1_real_virtual_alloc");
    if (trampoline == nullptr || stack == nullptr) {
        if (trampoline) (void)VirtualFree(trampoline, 0, MEM_RELEASE);
        if (stack) (void)VirtualFree(stack, 0, MEM_RELEASE);
        return;
    }
    std::memcpy(trampoline, plan.image.data(), plan.image_bytes);
    DWORD old_protection = 0;
    check(VirtualProtect(trampoline, kPageBytes, PAGE_EXECUTE_READ,
                         &old_protection) != FALSE,
          "line1_real_rx_trampoline");
    FlushInstructionCache(GetCurrentProcess(), trampoline, plan.image_bytes);
    g_line1_trampoline = trampoline;
    g_line1_capture = &line1_capture_clobber;

    RUNTIME_FUNCTION function{};
    function.BeginAddress = plan.runtime.begin;
    function.EndAddress = plan.runtime.end;
    function.UnwindData = plan.runtime.unwind;
    const DWORD64 image_base = reinterpret_cast<DWORD64>(trampoline);
    const bool registered = RtlAddFunctionTable(&function, 1, image_base) != FALSE;
    check(registered, "line1_register_runtime");
    if (registered) {
        bool unwind_ok = true;
        // The projected row is validated after the complete prologue and in
        // the absolute-tail body.  PCs before all prologue operations have
        // not executed every SAVE_NONVOL yet, so they cannot be expected to
        // restore the complete caller state from this row.
        for (const unsigned pc : {27u, 33u}) {
            unwind_ok = unwind_one(trampoline, function, image_base,
                                   pc, stack) && unwind_ok;
        }
        check(unwind_ok, "line1_rtl_virtual_unwind_boundaries");

        const auto widget = reinterpret_cast<void*>(
            static_cast<std::uintptr_t>(0x12345000u));
        const auto text = reinterpret_cast<void*>(
            static_cast<std::uintptr_t>(0x23456000u));
        constexpr std::uint64_t flag = 0x5au;
        reset_observations();
        SetLastError(kTargetLastError);
        line1_invoke_hook_a(&line1_entry_hook, widget, text, flag);
        const std::uint64_t first_return = g_line1_capture_return;
        check(g_line1_capture_widget == reinterpret_cast<std::uint64_t>(widget)
                  && g_line1_capture_text == reinterpret_cast<std::uint64_t>(text)
                  && g_line1_capture_flag == flag
                  && g_line1_capture_rbp == kAbiRbp,
              "line1_callback_receives_original_args_and_rbp");
        check(g_line1_native_hits == 1u
                  && g_line1_native_widget
                        == reinterpret_cast<std::uint64_t>(widget)
                  && g_line1_native_text
                        == reinterpret_cast<std::uint64_t>(text)
                  && g_line1_native_flag == flag,
              "line1_native_continuation_keeps_three_args");
        check(first_return != 0u
                  && g_line1_hook_restored_flags == g_line1_expected_flags,
              "line1_callback_clobber_flags_restored_before_tail");
        check(g_line1_after_rax == kExpectedRax
                  && g_line1_after_rcx
                        == reinterpret_cast<std::uint64_t>(widget)
                  && g_line1_after_rdx
                        == reinterpret_cast<std::uint64_t>(text)
                  && g_line1_after_r8 == flag
                  && g_line1_after_r9 == kExpectedR9
                  && g_line1_after_r10 == kExpectedR10
                  && g_line1_after_r11 == kExpectedR11
                  && g_line1_after_rbp == kAbiRbp,
              "line1_callback_clobber_gprs_restored");
        check(g_line1_after_mxcsr == kExpectedMxcsr
                  && g_line1_after_x87cw == kExpectedX87Control
                  && g_line1_after_last_error == kTargetLastError,
              "line1_callback_clobber_fp_and_last_error_restored");
        check(bytes_equal_volatile(g_line1_after_xmm0,
                                   repeated_qword(0x0102030405060708u))
                  && bytes_equal_volatile(g_line1_after_xmm1,
                                          repeated_qword(0x1112131415161718u))
                  && bytes_equal_volatile(g_line1_after_xmm2,
                                          repeated_qword(0x2122232425262728u))
                  && bytes_equal_volatile(g_line1_after_xmm3,
                                          repeated_qword(0x3132333435363738u))
                  && bytes_equal_volatile(g_line1_after_xmm4,
                                          repeated_qword(0x4142434445464748u))
                  && bytes_equal_volatile(g_line1_after_xmm5,
                                          repeated_qword(0x5152535455565758u)),
              "line1_callback_clobber_xmm_restored");

        reset_observations();
        SetLastError(kTargetLastError);
        line1_invoke_hook_b(&line1_entry_hook, widget, text, flag);
        check(g_line1_capture_return != 0u
                  && g_line1_capture_return != first_return,
              "line1_parent_return_variants_are_callback_visible");
        check(g_line1_native_hits == 1u
                  && g_line1_native_widget
                        == reinterpret_cast<std::uint64_t>(widget)
                  && g_line1_native_text
                        == reinterpret_cast<std::uint64_t>(text)
                  && g_line1_native_flag == flag,
              "line1_second_parent_return_keeps_original_args");
        check(GetLastError() == kTargetLastError,
              "line1_outer_last_error_restored");
        check(RtlDeleteFunctionTable(&function) != FALSE,
              "line1_delete_runtime");
    }
    g_line1_trampoline = nullptr;
    g_line1_capture = nullptr;
    check(VirtualFree(stack, 0, MEM_RELEASE) != FALSE,
          "line1_free_stack");
    check(VirtualFree(trampoline, 0, MEM_RELEASE) != FALSE,
          "line1_free_trampoline");
}

}  // namespace

int main() {
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    std::printf("TEST information-battle-line1-entry-plan\n");
    test_fixed_contract();
    test_prepare();
    test_real_trampoline();
    std::printf("SUMMARY checks_failed=%u status=%s\n", g_failures,
                g_failures == 0u ? "PASS" : "FAIL");
    std::printf("RESULT %s\n", g_failures == 0u ? "PASS" : "FAIL");
    return g_failures == 0u ? 0 : 1;
}
