#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>

extern "C" {
void* information_battle_name_handoff_original = nullptr;

void information_battle_name_handoff_hook();
void information_battle_name_handoff_body();
void information_battle_name_handoff_before_add();
void information_battle_name_handoff_restore_flags();
void information_battle_name_handoff_tail();
void information_battle_name_handoff_fake_original();
void information_battle_name_handoff_invoke(
    void (*target)(), void* dest, void* key, void* value);

volatile std::uint64_t observer_capture_dest = 0;
volatile std::uint64_t observer_capture_key = 0;
volatile std::uint64_t observer_capture_value = 0;
volatile std::uint64_t observer_capture_return_pc = 0;
volatile std::uint64_t observer_capture_rbp = 0;
volatile std::uint64_t observer_capture_rsp = 0;
volatile std::uint64_t observer_capture_rsp_value = 0;
volatile std::uint64_t observer_capture_dest_word0 = 0;
volatile std::uint64_t observer_capture_dest_word1 = 0;
volatile std::uint32_t observer_capture_last_error = 0;
volatile std::uint32_t observer_capture_hits = 0;

volatile std::uint64_t observer_native_rcx = 0;
volatile std::uint64_t observer_native_rdx = 0;
volatile std::uint64_t observer_native_r8 = 0;
volatile std::uint64_t observer_native_r9 = 0;
volatile std::uint64_t observer_native_r10 = 0;
volatile std::uint64_t observer_native_r11 = 0;
volatile std::uint64_t observer_native_rax = 0;
volatile std::uint64_t observer_native_rbp = 0;
volatile std::uint64_t observer_native_rbx = 0;
volatile std::uint64_t observer_native_rsi = 0;
volatile std::uint64_t observer_native_rdi = 0;
volatile std::uint64_t observer_native_r12 = 0;
volatile std::uint64_t observer_native_r13 = 0;
volatile std::uint64_t observer_native_r14 = 0;
volatile std::uint64_t observer_native_r15 = 0;
volatile std::uint64_t observer_native_flags = 0;
volatile std::uint32_t observer_native_mxcsr = 0;
volatile std::uint32_t observer_native_x87cw = 0;
volatile std::uint32_t observer_native_last_error = 0;
alignas(16) volatile unsigned char observer_native_xmm0[16]{};
alignas(16) volatile unsigned char observer_native_xmm1[16]{};
alignas(16) volatile unsigned char observer_native_xmm2[16]{};
alignas(16) volatile unsigned char observer_native_xmm3[16]{};
alignas(16) volatile unsigned char observer_native_xmm4[16]{};
alignas(16) volatile unsigned char observer_native_xmm5[16]{};
volatile std::uint64_t observer_native_entry_rsp = 0;
volatile std::uint64_t observer_native_return_slot = 0;
volatile std::uint64_t observer_native_home0 = 0;
volatile std::uint64_t observer_native_home1 = 0;
volatile std::uint64_t observer_native_home2 = 0;
volatile std::uint64_t observer_native_home3 = 0;

volatile std::uint64_t observer_expected_flags = 0;
volatile std::uint64_t observer_expected_original_rsp = 0;
volatile std::uint64_t observer_expected_return_pc = 0;
volatile std::uint64_t observer_invoke_return_rax = 0;
volatile std::uint64_t observer_invoke_home0 = 0;
volatile std::uint64_t observer_invoke_home1 = 0;
volatile std::uint64_t observer_invoke_home2 = 0;
volatile std::uint64_t observer_invoke_home3 = 0;
}

namespace {

constexpr std::uint64_t kExpectedRax = UINT64_C(0x1122334455667788);
constexpr std::uint64_t kExpectedR9 = UINT64_C(0x99aabbccddeeff00);
constexpr std::uint64_t kExpectedR10 = UINT64_C(0x2233445566778899);
constexpr std::uint64_t kExpectedR11 = UINT64_C(0x33445566778899aa);
constexpr std::uint64_t kExpectedRbp = UINT64_C(0x7172737475767778);
constexpr std::uint64_t kExpectedRbx = UINT64_C(0x0102030405060708);
constexpr std::uint64_t kExpectedRsi = UINT64_C(0x1112131415161718);
constexpr std::uint64_t kExpectedRdi = UINT64_C(0x2122232425262728);
constexpr std::uint64_t kExpectedR12 = UINT64_C(0x3132333435363738);
constexpr std::uint64_t kExpectedR13 = UINT64_C(0x4142434445464748);
constexpr std::uint64_t kExpectedR14 = UINT64_C(0x5152535455565758);
constexpr std::uint64_t kExpectedR15 = UINT64_C(0x6162636465666768);
constexpr std::uint32_t kExpectedMxcsr = 0x1f40u;
constexpr std::uint32_t kExpectedX87Control = 0x037fu;
constexpr DWORD kTargetLastError = 0x13572468u;
constexpr DWORD kCallbackLastError = 0x5a5aa5a5u;
constexpr std::array<std::uint64_t, 6> kExpectedXmm = {{
    UINT64_C(0x0102030405060708),
    UINT64_C(0x1112131415161718),
    UINT64_C(0x2122232425262728),
    UINT64_C(0x3132333435363738),
    UINT64_C(0x4142434445464748),
    UINT64_C(0x5152535455565758),
}};
constexpr std::array<std::uint64_t, 4> kHome = {{
    UINT64_C(0x1111111111111111),
    UINT64_C(0x2222222222222222),
    UINT64_C(0x3333333333333333),
    UINT64_C(0x4444444444444444),
}};

unsigned g_failures = 0;

void check(bool condition, const char* label) {
    std::printf("CHECK %s %s\n", label, condition ? "PASS" : "FAIL");
    if (!condition) {
        ++g_failures;
    }
}

void check_eq(std::uint64_t actual, std::uint64_t expected,
              const char* label) {
    check(actual == expected, label);
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

void clear_observations() {
    observer_capture_dest = 0;
    observer_capture_key = 0;
    observer_capture_value = 0;
    observer_capture_return_pc = 0;
    observer_capture_rbp = 0;
    observer_capture_rsp = 0;
    observer_capture_rsp_value = 0;
    observer_capture_dest_word0 = 0;
    observer_capture_dest_word1 = 0;
    observer_capture_last_error = 0;
    observer_capture_hits = 0;
    observer_native_rcx = 0;
    observer_native_rdx = 0;
    observer_native_r8 = 0;
    observer_native_r9 = 0;
    observer_native_r10 = 0;
    observer_native_r11 = 0;
    observer_native_rax = 0;
    observer_native_rbp = 0;
    observer_native_rbx = 0;
    observer_native_rsi = 0;
    observer_native_rdi = 0;
    observer_native_r12 = 0;
    observer_native_r13 = 0;
    observer_native_r14 = 0;
    observer_native_r15 = 0;
    observer_native_flags = 0;
    observer_native_mxcsr = 0;
    observer_native_x87cw = 0;
    observer_native_last_error = 0;
    observer_native_entry_rsp = 0;
    observer_native_return_slot = 0;
    observer_native_home0 = 0;
    observer_native_home1 = 0;
    observer_native_home2 = 0;
    observer_native_home3 = 0;
    observer_expected_flags = 0;
    observer_expected_original_rsp = 0;
    observer_expected_return_pc = 0;
    observer_invoke_return_rax = 0;
    observer_invoke_home0 = 0;
    observer_invoke_home1 = 0;
    observer_invoke_home2 = 0;
    observer_invoke_home3 = 0;
    std::memset(const_cast<unsigned char*>(observer_native_xmm0), 0, 16);
    std::memset(const_cast<unsigned char*>(observer_native_xmm1), 0, 16);
    std::memset(const_cast<unsigned char*>(observer_native_xmm2), 0, 16);
    std::memset(const_cast<unsigned char*>(observer_native_xmm3), 0, 16);
    std::memset(const_cast<unsigned char*>(observer_native_xmm4), 0, 16);
    std::memset(const_cast<unsigned char*>(observer_native_xmm5), 0, 16);
}

void check_state(void* dest, void* key, void* value,
                 std::uint64_t initial0, std::uint64_t initial1,
                 const char* suffix) {
    auto expect = [&](bool condition, const char* name) {
        char label[96]{};
        std::snprintf(label, sizeof(label), "%s_%s", name, suffix);
        check(condition, label);
    };
    const auto dest_value = reinterpret_cast<std::uint64_t>(dest);
    const auto key_value = reinterpret_cast<std::uint64_t>(key);
    const auto value_value = reinterpret_cast<std::uint64_t>(value);

    expect(observer_capture_hits == 1u, "capture_called_once");
    check_eq(observer_capture_dest, dest_value, "capture_dest");
    check_eq(observer_capture_key, key_value, "capture_key");
    check_eq(observer_capture_value, value_value, "capture_value");
    check_eq(observer_capture_rbp, kExpectedRbp, "capture_original_rbp");
    check_eq(observer_capture_rsp, observer_expected_original_rsp,
             "capture_original_entry_rsp");
    check_eq(observer_capture_return_pc, observer_expected_return_pc,
             "capture_return_pc");
    check_eq(observer_capture_rsp_value, observer_expected_return_pc,
             "capture_stack_return_slot_unchanged");
    check_eq(observer_capture_dest_word0, initial0, "capture_dest_before_native_write_0");
    check_eq(observer_capture_dest_word1, initial1, "capture_dest_before_native_write_1");
    check_eq(observer_capture_last_error, kCallbackLastError,
             "callback_changed_last_error");

    check_eq(observer_native_rcx, dest_value, "native_original_arg_dest");
    check_eq(observer_native_rdx, key_value, "native_original_arg_key");
    check_eq(observer_native_r8, value_value, "native_original_arg_value");
    check_eq(observer_native_r9, kExpectedR9, "native_original_r9");
    check_eq(observer_native_r10, kExpectedR10, "native_original_r10");
    check_eq(observer_native_r11, kExpectedR11, "native_original_r11");
    check_eq(observer_native_rax, kExpectedRax, "native_original_rax");
    check_eq(observer_native_rbp, kExpectedRbp, "native_original_rbp");
    check_eq(observer_native_rbx, kExpectedRbx, "native_original_rbx");
    check_eq(observer_native_rsi, kExpectedRsi, "native_original_rsi");
    check_eq(observer_native_rdi, kExpectedRdi, "native_original_rdi");
    check_eq(observer_native_r12, kExpectedR12, "native_original_r12");
    check_eq(observer_native_r13, kExpectedR13, "native_original_r13");
    check_eq(observer_native_r14, kExpectedR14, "native_original_r14");
    check_eq(observer_native_r15, kExpectedR15, "native_original_r15");
    check_eq(observer_native_flags, observer_expected_flags,
             "native_original_rflags");
    check_eq(observer_native_mxcsr, kExpectedMxcsr, "native_original_mxcsr");
    check_eq(observer_native_x87cw, kExpectedX87Control, "native_original_x87cw");
    check_eq(observer_native_last_error, kTargetLastError,
             "native_original_last_error_restored");
    expect(xmm_equals(observer_native_xmm0, kExpectedXmm[0]), "native_original_xmm0");
    expect(xmm_equals(observer_native_xmm1, kExpectedXmm[1]), "native_original_xmm1");
    expect(xmm_equals(observer_native_xmm2, kExpectedXmm[2]), "native_original_xmm2");
    expect(xmm_equals(observer_native_xmm3, kExpectedXmm[3]), "native_original_xmm3");
    expect(xmm_equals(observer_native_xmm4, kExpectedXmm[4]), "native_original_xmm4");
    expect(xmm_equals(observer_native_xmm5, kExpectedXmm[5]), "native_original_xmm5");

    check_eq(observer_native_entry_rsp, observer_expected_original_rsp,
             "native_original_rsp_unchanged");
    check_eq(observer_native_return_slot, observer_expected_return_pc,
             "native_original_return_slot_unchanged");
    for (unsigned index = 0; index != kHome.size(); ++index) {
        const volatile std::uint64_t native_home[] = {
            observer_native_home0, observer_native_home1,
            observer_native_home2, observer_native_home3,
        };
        const volatile std::uint64_t invoke_home[] = {
            observer_invoke_home0, observer_invoke_home1,
            observer_invoke_home2, observer_invoke_home3,
        };
        char label[96]{};
        std::snprintf(label, sizeof(label), "native_caller_home_%u_%s", index, suffix);
        check_eq(native_home[index], kHome[index], label);
        std::snprintf(label, sizeof(label), "invoke_caller_home_%u_%s", index, suffix);
        check_eq(invoke_home[index], kHome[index], label);
    }
    check_eq(observer_invoke_return_rax, dest_value, "native_return_value");
    expect(*static_cast<const std::uint64_t*>(dest) == key_value,
           "native_constructed_key_after_capture");
    expect(*(static_cast<const std::uint64_t*>(dest) + 1) == value_value,
           "native_constructed_value_after_capture");
}

void run_hook_fixture() {
    information_battle_name_handoff_original =
        reinterpret_cast<void*>(&information_battle_name_handoff_fake_original);
    clear_observations();

    alignas(16) std::array<std::uint64_t, 2> destination_a = {{
        UINT64_C(0xa1a2a3a4a5a6a7a8), UINT64_C(0xb1b2b3b4b5b6b7b8),
    }};
    void* key_a = reinterpret_cast<void*>(UINT64_C(0x1111222233334444));
    void* value_a = reinterpret_cast<void*>(UINT64_C(0x5555666677778888));
    SetLastError(kTargetLastError);
    information_battle_name_handoff_invoke(
        &information_battle_name_handoff_hook,
        destination_a.data(), key_a, value_a);
    check_state(destination_a.data(), key_a, value_a,
                UINT64_C(0xa1a2a3a4a5a6a7a8), UINT64_C(0xb1b2b3b4b5b6b7b8), "a");

    clear_observations();
    alignas(16) std::array<std::uint64_t, 2> destination_b = {{
        UINT64_C(0xc1c2c3c4c5c6c7c8), UINT64_C(0xd1d2d3d4d5d6d7d8),
    }};
    void* key_b = reinterpret_cast<void*>(UINT64_C(0x9999aaaabbbbcccc));
    void* value_b = reinterpret_cast<void*>(UINT64_C(0xddddeeeeffff0001));
    SetLastError(kTargetLastError);
    information_battle_name_handoff_invoke(
        &information_battle_name_handoff_hook,
        destination_b.data(), key_b, value_b);
    check_state(destination_b.data(), key_b, value_b,
                UINT64_C(0xc1c2c3c4c5c6c7c8), UINT64_C(0xd1d2d3d4d5d6d7d8), "b");

    information_battle_name_handoff_original = nullptr;
}

using HookAddress = void (*)();

PRUNTIME_FUNCTION lookup_function(HookAddress address, DWORD64* image_base) {
    return RtlLookupFunctionEntry(
        reinterpret_cast<DWORD64>(address), image_base, nullptr);
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

void check_unwind_metadata() {
    DWORD64 hook_base = 0;
    DWORD64 body_base = 0;
    DWORD64 before_add_base = 0;
    DWORD64 restore_base = 0;
    DWORD64 tail_base = 0;
    const PRUNTIME_FUNCTION hook_entry = lookup_function(
        &information_battle_name_handoff_hook, &hook_base);
    const PRUNTIME_FUNCTION body_entry = lookup_function(
        &information_battle_name_handoff_body, &body_base);
    const PRUNTIME_FUNCTION before_add_entry = lookup_function(
        &information_battle_name_handoff_before_add, &before_add_base);
    const PRUNTIME_FUNCTION restore_entry = lookup_function(
        &information_battle_name_handoff_restore_flags, &restore_base);
    const PRUNTIME_FUNCTION tail_entry = lookup_function(
        &information_battle_name_handoff_tail, &tail_base);
    check(hook_entry != nullptr, "rtl_lookup_hook_entry");
    check(body_entry != nullptr, "rtl_lookup_body_entry");
    check(before_add_entry != nullptr, "rtl_lookup_before_add_entry");
    check(restore_entry != nullptr, "rtl_lookup_restore_flags_entry");
    check(tail_entry != nullptr, "rtl_lookup_tail_entry");
    if (hook_entry == nullptr || body_entry == nullptr || before_add_entry == nullptr
        || restore_entry == nullptr || tail_entry == nullptr) {
        return;
    }
    const DWORD hook_rva = static_cast<DWORD>(
        reinterpret_cast<DWORD64>(&information_battle_name_handoff_hook) - hook_base);
    const DWORD restore_rva = static_cast<DWORD>(
        reinterpret_cast<DWORD64>(&information_battle_name_handoff_restore_flags) - restore_base);
    const DWORD tail_rva = static_cast<DWORD>(
        reinterpret_cast<DWORD64>(&information_battle_name_handoff_tail) - tail_base);
    check(hook_base == body_base && hook_base == before_add_base
              && hook_base == restore_base && hook_base == tail_base,
          "rtl_unwind_image_base_consistent");
    check(hook_entry == body_entry && hook_entry == before_add_entry,
          "rtl_hook_body_and_pre_add_share_span");
    check(hook_entry->BeginAddress == hook_rva, "rtl_hook_span_begin");
    check(restore_entry->BeginAddress == restore_rva, "rtl_restore_span_begin");
    check(tail_entry->BeginAddress == tail_rva, "rtl_tail_span_begin");
    check(restore_entry != hook_entry && tail_entry != restore_entry,
          "rtl_restore_and_tail_are_separate_spans");
    check(hook_entry->UnwindData != 0u && restore_entry->UnwindData != 0u
              && tail_entry->UnwindData != 0u,
          "rtl_all_stub_spans_have_unwind_data");

    alignas(16) std::array<std::uint64_t, 0x80> storage{};
    auto* frame = storage.data() + 8;
    const DWORD64 frame_address = reinterpret_cast<DWORD64>(frame);
    constexpr DWORD64 kCallerReturn = UINT64_C(0x123456789abcdef0);
    frame[0xd8u / 8u] = UINT64_C(0x1111111122222222);
    frame[0xe0u / 8u] = UINT64_C(0x3333333344444444);
    frame[0xe8u / 8u] = UINT64_C(0x5555555566666666);
    frame[0xf0u / 8u] = UINT64_C(0x7777777788888888);
    frame[0xf8u / 8u] = UINT64_C(0x99999999aaaabbbb);
    frame[0x100u / 8u] = UINT64_C(0xccccccccddddeeee);
    frame[0x108u / 8u] = UINT64_C(0xffff000011112222);
    frame[0x110u / 8u] = UINT64_C(0x3333444455556666);
    frame[0x158u / 8u] = kCallerReturn;

    auto check_hook_span = [&](HookAddress address, const char* suffix) {
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
            address, frame_address + 0x160u, kCallerReturn,
            image_base, entry, &context);
        std::string label = std::string(suffix) + "_rsp_rip";
        check(okay, label.c_str());
        label = std::string(suffix) + "_nonvolatile";
        check(context.Rbx == UINT64_C(0x3333444455556666)
                  && context.Rbp == UINT64_C(0xffff000011112222)
                  && context.Rsi == UINT64_C(0xccccccccddddeeee)
                  && context.Rdi == UINT64_C(0x99999999aaaabbbb)
                  && context.R12 == UINT64_C(0x7777777788888888)
                  && context.R13 == UINT64_C(0x5555555566666666)
                  && context.R14 == UINT64_C(0x3333333344444444)
                  && context.R15 == UINT64_C(0x1111111122222222),
              label.c_str());
    };
    check_hook_span(&information_battle_name_handoff_body, "rtl_unwind_body");
    check_hook_span(&information_battle_name_handoff_before_add,
                    "rtl_unwind_before_add");

    frame[0x150u / 8u] = UINT64_C(0x202);
    frame[0x158u / 8u] = kCallerReturn;
    {
        DWORD64 image_base = 0;
        const PRUNTIME_FUNCTION entry = lookup_function(
            &information_battle_name_handoff_restore_flags, &image_base);
        check(entry != nullptr, "rtl_unwind_restore_lookup");
        if (entry != nullptr) {
            CONTEXT context{};
            context.ContextFlags = CONTEXT_FULL;
            context.Rip = reinterpret_cast<DWORD64>(
                &information_battle_name_handoff_restore_flags);
            context.Rsp = frame_address + 0x150u;
            check(virtual_unwind_at(
                      &information_battle_name_handoff_restore_flags,
                      frame_address + 0x160u, kCallerReturn,
                      image_base, entry, &context),
                  "rtl_unwind_restore_rsp_rip");
        }
    }
    {
        DWORD64 image_base = 0;
        const PRUNTIME_FUNCTION entry = lookup_function(
            &information_battle_name_handoff_tail, &image_base);
        check(entry != nullptr, "rtl_unwind_tail_lookup");
        if (entry != nullptr) {
            CONTEXT context{};
            context.ContextFlags = CONTEXT_FULL;
            context.Rip = reinterpret_cast<DWORD64>(&information_battle_name_handoff_tail);
            context.Rsp = frame_address + 0x158u;
            check(virtual_unwind_at(
                      &information_battle_name_handoff_tail,
                      frame_address + 0x160u, kCallerReturn,
                      image_base, entry, &context),
                  "rtl_unwind_tail_rsp_rip");
        }
    }
}

}  // namespace

int main() {
    std::printf("TEST information-battle-name-handoff-observer-abi\n");
    check_unwind_metadata();
    run_hook_fixture();
    std::printf("SUMMARY checks_failed=%u status=%s\n", g_failures,
                g_failures == 0u ? "PASS" : "FAIL");
    std::printf("RESULT %s\n", g_failures == 0u ? "PASS" : "FAIL");
    return g_failures == 0u ? 0 : 1;
}
