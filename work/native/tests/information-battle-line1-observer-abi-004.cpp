#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>

// This executable is an owned-RX ABI fixture for the production observer stub.
// None of these globals or the continuation below belong to the production
// stub; they exist only to make the callback and tail jump observable in this
// fixture process.
extern "C" {
void* information_battle_line1_original = nullptr;

volatile std::uint64_t observer_capture_widget = 0;
volatile std::uint64_t observer_capture_text = 0;
volatile std::uint8_t observer_capture_flag = 0;
volatile std::uint64_t observer_capture_return = 0;
volatile std::uint64_t observer_capture_rbp = 0;
volatile std::uint64_t observer_capture_r13 = 0;

volatile std::uint64_t observer_native_widget = 0;
volatile std::uint64_t observer_native_text = 0;
volatile std::uint8_t observer_native_flag = 0;
volatile std::uint32_t observer_native_hits = 0;

volatile std::uint64_t observer_after_rax = 0;
volatile std::uint64_t observer_after_rcx = 0;
volatile std::uint64_t observer_after_rdx = 0;
volatile std::uint64_t observer_after_r8 = 0;
volatile std::uint64_t observer_after_r9 = 0;
volatile std::uint64_t observer_after_r10 = 0;
volatile std::uint64_t observer_after_r11 = 0;
volatile std::uint64_t observer_after_rbp = 0;
volatile std::uint64_t observer_after_r13 = 0;
volatile std::uint64_t observer_after_flags = 0;
volatile std::uint32_t observer_after_mxcsr = 0;
volatile std::uint32_t observer_after_x87cw = 0;
volatile std::uint32_t observer_after_last_error = 0;
alignas(16) volatile unsigned char observer_after_xmm0[16]{};
alignas(16) volatile unsigned char observer_after_xmm1[16]{};
alignas(16) volatile unsigned char observer_after_xmm2[16]{};
alignas(16) volatile unsigned char observer_after_xmm3[16]{};
alignas(16) volatile unsigned char observer_after_xmm4[16]{};
alignas(16) volatile unsigned char observer_after_xmm5[16]{};
volatile std::uint64_t observer_expected_flags = 0;

void information_battle_line1_hook();
void information_battle_line1_body();
void information_battle_line1_before_add();
void information_battle_line1_restore_flags();
void information_battle_line1_tail();
void observer_native_continuation();
void observer_invoke_a(void (*target)(), void* widget, void* text,
                       std::uint64_t flag);
void observer_invoke_b(void (*target)(), void* widget, void* text,
                       std::uint64_t flag);
}

namespace {

constexpr std::size_t kPageBytes = 0x1000u;
constexpr std::uint64_t kAbiRbp = UINT64_C(0x7172737475767778);
constexpr std::uint64_t kAbiR13 = UINT64_C(0x445566778899aabb);
constexpr std::uint64_t kExpectedRax = UINT64_C(0x1122334455667788);
constexpr std::uint64_t kExpectedR9 = UINT64_C(0x99aabbccddeeff00);
constexpr std::uint64_t kExpectedR10 = UINT64_C(0x2233445566778899);
constexpr std::uint64_t kExpectedR11 = UINT64_C(0x33445566778899aa);
constexpr std::uint32_t kExpectedMxcsr = 0x1f40u;
constexpr std::uint32_t kExpectedX87Control = 0x037fu;
constexpr DWORD kTargetLastError = 0x13572468u;

constexpr std::array<std::uint64_t, 6> kExpectedXmm = {{
    UINT64_C(0x0102030405060708),
    UINT64_C(0x1112131415161718),
    UINT64_C(0x2122232425262728),
    UINT64_C(0x3132333435363738),
    UINT64_C(0x4142434445464748),
    UINT64_C(0x5152535455565758),
}};

unsigned g_failures = 0u;

void check(bool condition, const char* label) {
    std::printf("CHECK %s %s\n", label, condition ? "PASS" : "FAIL");
    if (!condition) {
        ++g_failures;
    }
}

void clear_observations() {
    observer_capture_widget = 0;
    observer_capture_text = 0;
    observer_capture_flag = 0;
    observer_capture_return = 0;
    observer_capture_rbp = 0;
    observer_capture_r13 = 0;
    observer_native_widget = 0;
    observer_native_text = 0;
    observer_native_flag = 0;
    observer_native_hits = 0;
    observer_after_rax = 0;
    observer_after_rcx = 0;
    observer_after_rdx = 0;
    observer_after_r8 = 0;
    observer_after_r9 = 0;
    observer_after_r10 = 0;
    observer_after_r11 = 0;
    observer_after_rbp = 0;
    observer_after_r13 = 0;
    observer_after_flags = 0;
    observer_after_mxcsr = 0;
    observer_after_x87cw = 0;
    observer_after_last_error = 0;
    observer_expected_flags = 0;
    std::memset(const_cast<unsigned char*>(observer_after_xmm0), 0, 16);
    std::memset(const_cast<unsigned char*>(observer_after_xmm1), 0, 16);
    std::memset(const_cast<unsigned char*>(observer_after_xmm2), 0, 16);
    std::memset(const_cast<unsigned char*>(observer_after_xmm3), 0, 16);
    std::memset(const_cast<unsigned char*>(observer_after_xmm4), 0, 16);
    std::memset(const_cast<unsigned char*>(observer_after_xmm5), 0, 16);
}

bool xmm_equals(const volatile unsigned char* actual, std::uint64_t value) {
    for (unsigned index = 0; index != 16; ++index) {
        const unsigned shift = (index & 7u) * 8u;
        const unsigned char expected = static_cast<unsigned char>(
            (value >> shift) & UINT64_C(0xff));
        if (actual[index] != expected) {
            return false;
        }
    }
    return true;
}

struct OwnedTrampoline {
    unsigned char* page = nullptr;

    bool create() {
        page = static_cast<unsigned char*>(VirtualAlloc(
            nullptr, kPageBytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
        if (page == nullptr) {
            return false;
        }
        const unsigned char jump[] = {
            0xffu, 0x25u, 0x00u, 0x00u, 0x00u, 0x00u,
        };
        std::memcpy(page, jump, sizeof(jump));
        const auto target = reinterpret_cast<std::uintptr_t>(
            &observer_native_continuation);
        std::memcpy(page + sizeof(jump), &target, sizeof(target));
        DWORD old_protect = 0;
        if (!VirtualProtect(page, kPageBytes, PAGE_EXECUTE_READ,
                            &old_protect)) {
            VirtualFree(page, 0, MEM_RELEASE);
            page = nullptr;
            return false;
        }
        FlushInstructionCache(GetCurrentProcess(), page, kPageBytes);
        information_battle_line1_original = page;
        return true;
    }

    void destroy() {
        information_battle_line1_original = nullptr;
        if (page != nullptr) {
            VirtualFree(page, 0, MEM_RELEASE);
            page = nullptr;
        }
    }
};

void check_trampoline(const OwnedTrampoline& trampoline) {
    check(trampoline.page != nullptr, "owned_rx_allocated");
    if (trampoline.page == nullptr) {
        return;
    }
    const unsigned char expected[] = {
        0xffu, 0x25u, 0x00u, 0x00u, 0x00u, 0x00u,
    };
    check(std::memcmp(trampoline.page, expected, sizeof(expected)) == 0,
          "owned_rx_absolute_jump_opcode");
    std::uintptr_t target = 0;
    std::memcpy(&target, trampoline.page + sizeof(expected),
                sizeof(target));
    check(target == reinterpret_cast<std::uintptr_t>(
                       &observer_native_continuation),
          "owned_rx_absolute_jump_target");
    MEMORY_BASIC_INFORMATION info{};
    const SIZE_T queried = VirtualQuery(trampoline.page, &info, sizeof(info));
    check(queried == sizeof(info) && info.Protect == PAGE_EXECUTE_READ,
          "owned_rx_page_execute_read");
}

using HookAddress = void (*)();

PRUNTIME_FUNCTION lookup_function(HookAddress address,
                                  DWORD64* image_base) {
    return RtlLookupFunctionEntry(
        reinterpret_cast<DWORD64>(address), image_base, nullptr);
}

void check_lookup_metadata() {
    DWORD64 hook_image_base = 0;
    DWORD64 body_image_base = 0;
    DWORD64 before_add_image_base = 0;
    DWORD64 restore_image_base = 0;
    DWORD64 tail_image_base = 0;
    const PRUNTIME_FUNCTION hook_entry = lookup_function(
        &information_battle_line1_hook, &hook_image_base);
    const PRUNTIME_FUNCTION body_entry = lookup_function(
        &information_battle_line1_body, &body_image_base);
    const PRUNTIME_FUNCTION before_add_entry = lookup_function(
        &information_battle_line1_before_add, &before_add_image_base);
    const PRUNTIME_FUNCTION restore_entry = lookup_function(
        &information_battle_line1_restore_flags, &restore_image_base);
    const PRUNTIME_FUNCTION tail_entry = lookup_function(
        &information_battle_line1_tail, &tail_image_base);
    check(hook_entry != nullptr, "rtl_lookup_hook_body_entry");
    check(body_entry != nullptr, "rtl_lookup_hook_body_entry_at_body");
    check(before_add_entry != nullptr, "rtl_lookup_hook_body_entry_before_add");
    check(restore_entry != nullptr, "rtl_lookup_restore_flags_entry");
    check(tail_entry != nullptr, "rtl_lookup_tail_entry");
    if (hook_entry == nullptr || body_entry == nullptr
        || before_add_entry == nullptr || restore_entry == nullptr
        || tail_entry == nullptr) {
        return;
    }
    const auto hook_rva = static_cast<DWORD>(
        reinterpret_cast<DWORD64>(&information_battle_line1_hook)
        - hook_image_base);
    const auto restore_rva = static_cast<DWORD>(
        reinterpret_cast<DWORD64>(&information_battle_line1_restore_flags)
        - restore_image_base);
    const auto tail_rva = static_cast<DWORD>(
        reinterpret_cast<DWORD64>(&information_battle_line1_tail)
        - tail_image_base);
    check(hook_image_base == body_image_base
              && hook_image_base == before_add_image_base,
          "rtl_lookup_hook_image_base_consistent");
    check(restore_image_base == tail_image_base
              && restore_image_base == hook_image_base,
          "rtl_lookup_all_image_bases_consistent");
    check(body_entry == hook_entry && before_add_entry == hook_entry,
          "rtl_lookup_body_ranges_share_hook_entry");
    check(hook_entry->BeginAddress == hook_rva,
          "rtl_hook_entry_begin_rva");
    check(restore_entry->BeginAddress == restore_rva,
          "rtl_restore_entry_begin_rva");
    check(tail_entry->BeginAddress == tail_rva,
          "rtl_tail_entry_begin_rva");
    check(restore_entry != hook_entry && tail_entry != restore_entry,
          "rtl_restore_and_tail_are_separate_ranges");
    check(hook_entry->UnwindData != 0u && restore_entry->UnwindData != 0u,
          "rtl_hook_and_restore_have_unwind_data");
    check(tail_entry->UnwindData != 0u,
          "rtl_tail_has_unwind_data");
}

bool virtual_unwind_at(HookAddress address, DWORD64 rsp,
                       DWORD64 return_pc, DWORD64 image_base,
                       PRUNTIME_FUNCTION entry, CONTEXT* context) {
    PVOID handler_data = nullptr;
    DWORD64 establisher_frame = 0;
    KNONVOLATILE_CONTEXT_POINTERS nonvolatile{};
    RtlVirtualUnwind(UNW_FLAG_NHANDLER, image_base,
                     reinterpret_cast<DWORD64>(address), entry, context,
                     &handler_data, &establisher_frame, &nonvolatile);
    return context->Rip == return_pc
           && context->Rsp == rsp
           && establisher_frame != 0;
}

void check_virtual_unwind() {
    alignas(16) std::array<std::uint64_t, 0x80> storage{};
    auto* frame = storage.data() + 8;
    const auto frame_address = reinterpret_cast<DWORD64>(frame);
    constexpr DWORD64 kCallerReturn = UINT64_C(0x123456789abcdef0);
    constexpr DWORD64 kSavedRbx = UINT64_C(0x1111111122222222);
    constexpr DWORD64 kSavedRbp = UINT64_C(0x3333333344444444);
    constexpr DWORD64 kSavedRsi = UINT64_C(0x5555555566666666);
    constexpr DWORD64 kSavedRdi = UINT64_C(0x7777777788888888);
    constexpr DWORD64 kSavedR12 = UINT64_C(0x99999999aaaabbbb);
    constexpr DWORD64 kSavedR13 = UINT64_C(0xccccccccddddeeee);
    constexpr DWORD64 kSavedR14 = UINT64_C(0xffff000011112222);
    constexpr DWORD64 kSavedR15 = UINT64_C(0x3333444455556666);
    frame[0xd8u / 8u] = kSavedR15;
    frame[0xe0u / 8u] = kSavedR14;
    frame[0xe8u / 8u] = kSavedR13;
    frame[0xf0u / 8u] = kSavedR12;
    frame[0xf8u / 8u] = kSavedRdi;
    frame[0x100u / 8u] = kSavedRsi;
    frame[0x108u / 8u] = kSavedRbp;
    frame[0x110u / 8u] = kSavedRbx;
    frame[0x158u / 8u] = kCallerReturn;

    auto check_hook_unwind = [&](HookAddress address, const char* suffix) {
        DWORD64 image_base = 0;
        const PRUNTIME_FUNCTION entry = lookup_function(address, &image_base);
        check(entry != nullptr, suffix);
        if (entry == nullptr) {
            return;
        }
        CONTEXT context{};
        context.ContextFlags = CONTEXT_FULL;
        context.Rip = reinterpret_cast<DWORD64>(address);
        context.Rsp = frame_address;
        context.Rbx = 1;
        context.Rbp = 2;
        context.Rsi = 3;
        context.Rdi = 4;
        context.R12 = 5;
        context.R13 = 6;
        context.R14 = 7;
        context.R15 = 8;
        const bool okay = virtual_unwind_at(
            address, frame_address + 0x160u, kCallerReturn, image_base,
            entry, &context);
        const std::string rsp_label = std::string(suffix) + "_rsp_rip";
        check(okay, rsp_label.c_str());
        std::string label = std::string(suffix) + "_nonvolatile";
        check(context.Rbx == kSavedRbx && context.Rbp == kSavedRbp
                  && context.Rsi == kSavedRsi && context.Rdi == kSavedRdi
                  && context.R12 == kSavedR12 && context.R13 == kSavedR13
                  && context.R14 == kSavedR14 && context.R15 == kSavedR15,
              label.c_str());
    };
    check_hook_unwind(&information_battle_line1_body,
                      "rtl_virtual_unwind_hook_body");
    check_hook_unwind(&information_battle_line1_before_add,
                      "rtl_virtual_unwind_hook_before_add");

    constexpr DWORD64 kSavedFlags = UINT64_C(0x202);
    frame[0x150u / 8u] = kSavedFlags;
    frame[0x158u / 8u] = kCallerReturn;
    {
        DWORD64 image_base = 0;
        const PRUNTIME_FUNCTION entry = lookup_function(
            &information_battle_line1_restore_flags, &image_base);
        check(entry != nullptr, "rtl_virtual_unwind_restore_entry");
        if (entry != nullptr) {
            CONTEXT context{};
            context.ContextFlags = CONTEXT_FULL;
            context.Rip = reinterpret_cast<DWORD64>(
                &information_battle_line1_restore_flags);
            context.Rsp = frame_address + 0x150u;
            const bool okay = virtual_unwind_at(
                &information_battle_line1_restore_flags,
                frame_address + 0x160u, kCallerReturn, image_base, entry,
                &context);
            check(okay, "rtl_virtual_unwind_restore_flags_rsp_rip");
        }
    }
    {
        DWORD64 image_base = 0;
        const PRUNTIME_FUNCTION entry = lookup_function(
            &information_battle_line1_tail, &image_base);
        check(entry != nullptr, "rtl_virtual_unwind_tail_entry");
        if (entry != nullptr) {
            CONTEXT context{};
            context.ContextFlags = CONTEXT_FULL;
            context.Rip = reinterpret_cast<DWORD64>(&information_battle_line1_tail);
            context.Rsp = frame_address + 0x158u;
            const bool okay = virtual_unwind_at(
                &information_battle_line1_tail, frame_address + 0x160u,
                kCallerReturn, image_base, entry, &context);
            check(okay, "rtl_virtual_unwind_tail_rsp_rip");
        }
    }
}

void check_state(std::uint64_t widget, std::uint64_t text,
                 std::uint64_t flag, std::uint64_t capture_return,
                 const char* suffix) {
    char label[96]{};
    auto expect = [&](bool value, const char* name) {
        std::snprintf(label, sizeof(label), "%s_%s", name, suffix);
        check(value, label);
    };

    expect(observer_capture_widget == widget, "capture_widget");
    expect(observer_capture_text == text, "capture_text");
    expect(observer_capture_flag == static_cast<std::uint8_t>(flag),
           "capture_flag");
    expect(observer_capture_return == capture_return, "capture_return");
    expect(observer_capture_rbp == kAbiRbp, "capture_original_rbp");
    expect(observer_capture_r13 == kAbiR13, "capture_original_r13");
    expect(observer_native_hits == 1u, "continuation_hit");
    expect(observer_native_widget == widget, "continuation_widget");
    expect(observer_native_text == text, "continuation_text");
    expect(observer_native_flag == static_cast<std::uint8_t>(flag),
           "continuation_flag");

    expect(observer_after_rax == kExpectedRax, "restored_rax");
    expect(observer_after_rcx == widget, "restored_rcx");
    expect(observer_after_rdx == text, "restored_rdx");
    expect(observer_after_r8 == flag, "restored_r8");
    expect(observer_after_r9 == kExpectedR9, "restored_r9");
    expect(observer_after_r10 == kExpectedR10, "restored_r10");
    expect(observer_after_r11 == kExpectedR11, "restored_r11");
    expect(observer_after_rbp == kAbiRbp, "restored_rbp");
    expect(observer_after_r13 == kAbiR13, "restored_r13");
    expect(observer_after_flags == observer_expected_flags,
           "restored_rflags");
    expect(observer_after_mxcsr == kExpectedMxcsr, "restored_mxcsr");
    expect(observer_after_x87cw == kExpectedX87Control, "restored_x87cw");
    expect(observer_after_last_error == kTargetLastError,
           "restored_last_error");
    expect(xmm_equals(observer_after_xmm0, kExpectedXmm[0]), "restored_xmm0");
    expect(xmm_equals(observer_after_xmm1, kExpectedXmm[1]), "restored_xmm1");
    expect(xmm_equals(observer_after_xmm2, kExpectedXmm[2]), "restored_xmm2");
    expect(xmm_equals(observer_after_xmm3, kExpectedXmm[3]), "restored_xmm3");
    expect(xmm_equals(observer_after_xmm4, kExpectedXmm[4]), "restored_xmm4");
    expect(xmm_equals(observer_after_xmm5, kExpectedXmm[5]), "restored_xmm5");
}

void run_fixture() {
    OwnedTrampoline trampoline{};
    check(trampoline.create(), "owned_rx_create_and_bind_original");
    check_trampoline(trampoline);
    if (trampoline.page == nullptr) {
        return;
    }

    const std::uint64_t widget_a = UINT64_C(0x1111222233334444);
    const std::uint64_t text_a = UINT64_C(0x5555666677778888);
    const std::uint64_t flag_a = UINT64_C(0x7f);
    const std::uint64_t widget_b = UINT64_C(0x9999aaaabbbbcccc);
    const std::uint64_t text_b = UINT64_C(0xddddeeeeffff0001);
    const std::uint64_t flag_b = UINT64_C(0x02);

    clear_observations();
    SetLastError(kTargetLastError);
    observer_invoke_a(&information_battle_line1_hook,
                      reinterpret_cast<void*>(widget_a),
                      reinterpret_cast<void*>(text_a), flag_a);
    const std::uint64_t return_a = observer_capture_return;
    check_state(widget_a, text_a, flag_a, return_a, "a");

    clear_observations();
    SetLastError(kTargetLastError);
    observer_invoke_b(&information_battle_line1_hook,
                      reinterpret_cast<void*>(widget_b),
                      reinterpret_cast<void*>(text_b), flag_b);
    const std::uint64_t return_b = observer_capture_return;
    check_state(widget_b, text_b, flag_b, return_b, "b");
    check(return_a != 0 && return_b != 0 && return_a != return_b,
          "distinct_original_return_pc");

    check_lookup_metadata();
    check_virtual_unwind();

    trampoline.destroy();
    check(information_battle_line1_original == nullptr,
          "owned_rx_cleanup_original_pointer");
}

}  // namespace

int main() {
    std::printf("TEST information-battle-line1-observer-abi\n");
    run_fixture();
    std::printf("SUMMARY checks_failed=%u status=%s\n", g_failures,
                g_failures == 0u ? "PASS" : "FAIL");
    std::printf("RESULT %s\n", g_failures == 0u ? "PASS" : "FAIL");
    return g_failures == 0u ? 0 : 1;
}
