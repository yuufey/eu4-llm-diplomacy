#include <windows.h>

#include <cstddef>
#include <cstdint>
#include <cstdio>

extern "C" {
void information_battle_message_hook(void*, void*, void*, void*);
void information_battle_entry_capture(void*, void*, void*, void*,
                                       std::uintptr_t) noexcept;
void information_battle_message_capture(void*, void*, void*,
                                         std::uintptr_t) noexcept;
void* information_battle_entry_original;
void* information_battle_message_original;
void fixture_message_capture_mutate();
void fixture_message_call();
void fixture_message_original();
extern const unsigned char fixture_message_call_after[];

volatile std::uint32_t fixture_msg_capture_call_count = 0;
volatile std::uintptr_t fixture_msg_capture_message = 0;
volatile std::uintptr_t fixture_msg_capture_callback = 0;
volatile std::uintptr_t fixture_msg_capture_return = 0;
volatile std::uintptr_t fixture_msg_capture_rbp = 0;

volatile std::uint32_t fixture_msg_original_call_count = 0;
volatile std::uintptr_t fixture_msg_original_manager = 0;
volatile std::uintptr_t fixture_msg_original_message = 0;
volatile std::uintptr_t fixture_msg_original_context = 0;
volatile std::uintptr_t fixture_msg_original_callback = 0;
volatile std::uintptr_t fixture_msg_original_rax = 0;
volatile std::uintptr_t fixture_msg_original_r10 = 0;
volatile std::uintptr_t fixture_msg_original_r11 = 0;
volatile std::uintptr_t fixture_msg_original_rbp = 0;
volatile std::uintptr_t fixture_msg_original_return = 0;
volatile std::uintptr_t fixture_msg_original_rsp = 0;
volatile std::uintptr_t fixture_msg_original_rsp_mod16 = 0;
volatile std::uintptr_t fixture_msg_original_stack5 = 0;
volatile std::uintptr_t fixture_msg_original_stack6 = 0;
volatile std::uint64_t fixture_msg_original_flags = 0;
volatile std::uint32_t fixture_msg_original_mxcsr = 0;
volatile std::uint16_t fixture_msg_original_x87 = 0;
volatile std::uint64_t fixture_msg_original_xmm0[2]{};
volatile std::uint64_t fixture_msg_original_xmm1[2]{};
volatile std::uint64_t fixture_msg_original_xmm2[2]{};
volatile std::uint64_t fixture_msg_original_xmm3[2]{};
volatile std::uint64_t fixture_msg_original_xmm4[2]{};
volatile std::uint64_t fixture_msg_original_xmm5[2]{};
volatile std::uint32_t fixture_msg_original_last_error = 0;

volatile std::uint64_t fixture_msg_return_rax = 0;
volatile std::uint64_t fixture_msg_return_xmm0[2]{};
volatile std::uint64_t fixture_msg_after_rbx = 0;
volatile std::uint64_t fixture_msg_after_rbp = 0;
volatile std::uint64_t fixture_msg_after_rsi = 0;
volatile std::uint64_t fixture_msg_after_rdi = 0;
volatile std::uint64_t fixture_msg_after_r12 = 0;
volatile std::uint64_t fixture_msg_after_r13 = 0;
volatile std::uint64_t fixture_msg_after_r14 = 0;
volatile std::uint64_t fixture_msg_after_r15 = 0;
volatile std::uint64_t fixture_msg_after_xmm6[2]{};
volatile std::uint64_t fixture_msg_after_xmm7[2]{};
volatile std::uint64_t fixture_msg_after_xmm8[2]{};
volatile std::uint64_t fixture_msg_after_xmm9[2]{};
volatile std::uint64_t fixture_msg_after_xmm10[2]{};
volatile std::uint64_t fixture_msg_after_xmm11[2]{};
volatile std::uint64_t fixture_msg_after_xmm12[2]{};
volatile std::uint64_t fixture_msg_after_xmm13[2]{};
volatile std::uint64_t fixture_msg_after_xmm14[2]{};
volatile std::uint64_t fixture_msg_after_xmm15[2]{};
volatile std::uint64_t fixture_msg_after_stack5 = 0;
volatile std::uint64_t fixture_msg_after_stack6 = 0;
volatile std::uint64_t fixture_msg_expected_flags = 0;
}

namespace {

constexpr std::uintptr_t kManager = UINT64_C(0x1111222233334444);
constexpr std::uintptr_t kMessage = UINT64_C(0x2222333344445555);
constexpr std::uintptr_t kCallbackContext = UINT64_C(0x3333444455556666);
constexpr std::uintptr_t kCallbackFunction = UINT64_C(0x4444555566667777);
constexpr std::uintptr_t kStack5 = UINT64_C(0x5555666677778888);
constexpr std::uintptr_t kStack6 = UINT64_C(0x6666777788889999);
constexpr std::uintptr_t kInputRax = UINT64_C(0xaaaabbbbccccdddd);
constexpr std::uintptr_t kInputR10 = UINT64_C(0x1011121314151617);
constexpr std::uintptr_t kInputR11 = UINT64_C(0x18191a1b1c1d1e1f);
constexpr std::uintptr_t kInputRbp = UINT64_C(0x1112131415161718);
constexpr std::uintptr_t kReturnRax = UINT64_C(0x7f6e5d4c3b2a1908);
constexpr std::uint32_t kIncomingLastError = 0x13572468u;
constexpr std::uint32_t kCallbackLastError = 0x0badf00du;
constexpr std::uint32_t kInitialMxcsr = 0x1f80u;
constexpr std::uint16_t kInitialX87 = 0x037fu;

constexpr std::uint64_t kVolatileXmmLow[6]={
    UINT64_C(0x8081828384858688), UINT64_C(0x9091929394959698),
    UINT64_C(0xa0a1a2a3a4a5a6a7), UINT64_C(0xb0b1b2b3b4b5b6b7),
    UINT64_C(0xc0c1c2c3c4c5c6c7), UINT64_C(0xd0d1d2d3d4d5d6d7),
};
constexpr std::uint64_t kVolatileXmmHigh[6]={
    UINT64_C(0x0807060504030201), UINT64_C(0x1817161514131211),
    UINT64_C(0x2827262524232211), UINT64_C(0x3837363534333221),
    UINT64_C(0x4847464544434231), UINT64_C(0x5857565554535241),
};
constexpr std::uint64_t kNonvolatileGpr[8]={
    UINT64_C(0x0102030405060708), UINT64_C(0x1112131415161718),
    UINT64_C(0x2122232425262728), UINT64_C(0x3132333435363738),
    UINT64_C(0x4142434445464748), UINT64_C(0x5152535455565758),
    UINT64_C(0x6162636465666768), UINT64_C(0x7172737475767878),
};
constexpr std::uint64_t kNonvolatileXmmLow[10]={
    UINT64_C(0xe0e1e2e3e4e5e6e7), UINT64_C(0xf0f1f2f3f4f5f6f7),
    UINT64_C(0x0123456789abcdef), UINT64_C(0x1021324354657687),
    UINT64_C(0x8899aabbccddeeff), UINT64_C(0x0f1e2d3c4b5a6978),
    UINT64_C(0x8877665544332211), UINT64_C(0x7766554433221100),
    UINT64_C(0xdeadbeefcafebabe), UINT64_C(0xfeedface12345678),
};
constexpr std::uint64_t kNonvolatileXmmHigh[10]={
    UINT64_C(0xe8e7e6e5e4e3e2e1), UINT64_C(0xf8f7f6f5f4f3f2f1),
    UINT64_C(0x1122334455667788), UINT64_C(0x8877665544332211),
    UINT64_C(0x1020304050607080), UINT64_C(0x9080706050403020),
    UINT64_C(0x123456789abcdef0), UINT64_C(0x0fedcba987654321),
    UINT64_C(0x13579bdf2468ace0), UINT64_C(0x2468ace013579bdf),
};
constexpr std::uint64_t kReturnXmmLow = UINT64_C(0x1234abcd5678ef90);
constexpr std::uint64_t kReturnXmmHigh = UINT64_C(0xfedcba9876543210);

unsigned failures = 0;

void check(bool passed, const char* name) noexcept {
    std::printf("CHECK %s %s\n", name, passed ? "PASS" : "FAIL");
    if (!passed) ++failures;
}

template <std::size_t N>
void clear_array(volatile std::uint64_t (&values)[N]) noexcept {
    for (std::size_t index=0; index<N; ++index) values[index]=0;
}

bool xmm_pair_equal(const volatile std::uint64_t* actual,
                    std::uint64_t low, std::uint64_t high) noexcept {
    return actual[0]==low && actual[1]==high;
}

void reset_observations() noexcept {
    fixture_msg_capture_call_count=0;
    fixture_msg_capture_message=0;
    fixture_msg_capture_callback=0;
    fixture_msg_capture_return=0;
    fixture_msg_capture_rbp=0;
    fixture_msg_original_call_count=0;
    fixture_msg_original_manager=0;
    fixture_msg_original_message=0;
    fixture_msg_original_context=0;
    fixture_msg_original_callback=0;
    fixture_msg_original_rax=0;
    fixture_msg_original_r10=0;
    fixture_msg_original_r11=0;
    fixture_msg_original_rbp=0;
    fixture_msg_original_return=0;
    fixture_msg_original_rsp=0;
    fixture_msg_original_rsp_mod16=0;
    fixture_msg_original_stack5=0;
    fixture_msg_original_stack6=0;
    fixture_msg_original_flags=0;
    fixture_msg_original_mxcsr=0;
    fixture_msg_original_x87=0;
    clear_array(fixture_msg_original_xmm0);
    clear_array(fixture_msg_original_xmm1);
    clear_array(fixture_msg_original_xmm2);
    clear_array(fixture_msg_original_xmm3);
    clear_array(fixture_msg_original_xmm4);
    clear_array(fixture_msg_original_xmm5);
    fixture_msg_original_last_error=0;
    fixture_msg_return_rax=0;
    clear_array(fixture_msg_return_xmm0);
    fixture_msg_after_rbx=0;
    fixture_msg_after_rbp=0;
    fixture_msg_after_rsi=0;
    fixture_msg_after_rdi=0;
    fixture_msg_after_r12=0;
    fixture_msg_after_r13=0;
    fixture_msg_after_r14=0;
    fixture_msg_after_r15=0;
    clear_array(fixture_msg_after_xmm6);
    clear_array(fixture_msg_after_xmm7);
    clear_array(fixture_msg_after_xmm8);
    clear_array(fixture_msg_after_xmm9);
    clear_array(fixture_msg_after_xmm10);
    clear_array(fixture_msg_after_xmm11);
    clear_array(fixture_msg_after_xmm12);
    clear_array(fixture_msg_after_xmm13);
    clear_array(fixture_msg_after_xmm14);
    clear_array(fixture_msg_after_xmm15);
    fixture_msg_after_stack5=0;
    fixture_msg_after_stack6=0;
    fixture_msg_expected_flags=0;
}

bool check_original_volatile_xmm() noexcept {
    const volatile std::uint64_t* actual[]={
        fixture_msg_original_xmm0,fixture_msg_original_xmm1,
        fixture_msg_original_xmm2,fixture_msg_original_xmm3,
        fixture_msg_original_xmm4,fixture_msg_original_xmm5,
    };
    for (std::size_t index=0; index<6; ++index) {
        if (!xmm_pair_equal(actual[index],kVolatileXmmLow[index],
                            kVolatileXmmHigh[index])) return false;
    }
    return true;
}

bool check_after_nonvolatile() noexcept {
    const volatile std::uint64_t actual_gpr[]={
        fixture_msg_after_rbx,fixture_msg_after_rbp,fixture_msg_after_rsi,
        fixture_msg_after_rdi,fixture_msg_after_r12,fixture_msg_after_r13,
        fixture_msg_after_r14,fixture_msg_after_r15,
    };
    for (std::size_t index=0; index<8; ++index)
        if (actual_gpr[index]!=kNonvolatileGpr[index]) return false;
    const volatile std::uint64_t* actual_xmm[]={
        fixture_msg_after_xmm6,fixture_msg_after_xmm7,fixture_msg_after_xmm8,
        fixture_msg_after_xmm9,fixture_msg_after_xmm10,fixture_msg_after_xmm11,
        fixture_msg_after_xmm12,fixture_msg_after_xmm13,fixture_msg_after_xmm14,
        fixture_msg_after_xmm15,
    };
    for (std::size_t index=0; index<10; ++index) {
        if (!xmm_pair_equal(actual_xmm[index],kNonvolatileXmmLow[index],
                            kNonvolatileXmmHigh[index])) return false;
    }
    return true;
}

void run_message_abi_case() noexcept {
    reset_observations();
    information_battle_message_original=reinterpret_cast<void*>(
        reinterpret_cast<std::uintptr_t>(&fixture_message_original));
    SetLastError(kIncomingLastError);
    fixture_message_call();

    const std::uintptr_t call_after=reinterpret_cast<std::uintptr_t>(
        fixture_message_call_after);
    check(fixture_msg_capture_call_count==1u
              && fixture_msg_capture_message==kMessage
              && fixture_msg_capture_callback==kCallbackFunction
              && fixture_msg_capture_return==call_after
              && fixture_msg_capture_rbp==kInputRbp,
          "message_capture_four_arg_mapping");
    check(fixture_msg_original_call_count==1u,
          "message_native_original_called_once");
    const bool original_arguments_ok=fixture_msg_original_manager==kManager
              && fixture_msg_original_message==kMessage
              && fixture_msg_original_context==kCallbackContext
              && fixture_msg_original_callback==kCallbackFunction
              && fixture_msg_original_rax==kInputRax
              && fixture_msg_original_r10==kInputR10
              && fixture_msg_original_r11==kInputR11
              && fixture_msg_original_rbp==kInputRbp
              && fixture_msg_original_return==call_after
              && fixture_msg_original_stack5==kStack5
              && fixture_msg_original_stack6==kStack6
              && fixture_msg_original_rsp_mod16==8u;
    if (!original_arguments_ok) {
        std::fprintf(stderr,
                     "original args manager=%llx message=%llx context=%llx callback=%llx rax=%llx r10=%llx r11=%llx rbp=%llx return=%llx expected_return=%llx stack5=%llx stack6=%llx rsp=%llx rspmod=%llx\n",
                     static_cast<unsigned long long>(fixture_msg_original_manager),
                     static_cast<unsigned long long>(fixture_msg_original_message),
                     static_cast<unsigned long long>(fixture_msg_original_context),
                     static_cast<unsigned long long>(fixture_msg_original_callback),
                     static_cast<unsigned long long>(fixture_msg_original_rax),
                     static_cast<unsigned long long>(fixture_msg_original_r10),
                     static_cast<unsigned long long>(fixture_msg_original_r11),
                     static_cast<unsigned long long>(fixture_msg_original_rbp),
                     static_cast<unsigned long long>(fixture_msg_original_return),
                     static_cast<unsigned long long>(call_after),
                     static_cast<unsigned long long>(fixture_msg_original_stack5),
                     static_cast<unsigned long long>(fixture_msg_original_stack6),
                     static_cast<unsigned long long>(fixture_msg_original_rsp),
                     static_cast<unsigned long long>(fixture_msg_original_rsp_mod16));
    }
    check(original_arguments_ok,"message_original_args_rbp_return_and_stack");
    check(fixture_msg_after_stack5==kStack5
              && fixture_msg_after_stack6==kStack6,
          "message_stack_canaries_unchanged");
    check(fixture_msg_original_last_error==kIncomingLastError
              && GetLastError()==kIncomingLastError,
          "message_last_error_restored_before_original_and_return");
    const bool volatile_state_ok=fixture_msg_original_flags==fixture_msg_expected_flags
              && fixture_msg_original_mxcsr==kInitialMxcsr
              && fixture_msg_original_x87==kInitialX87
              && check_original_volatile_xmm();
    if (!volatile_state_ok) {
        std::fprintf(stderr,"volatile state flags=%llx expected=%llx mxcsr=%x x87=%x xmm0=%llx/%llx\n",
                     static_cast<unsigned long long>(fixture_msg_original_flags),
                     static_cast<unsigned long long>(fixture_msg_expected_flags),
                     static_cast<unsigned>(fixture_msg_original_mxcsr),
                     static_cast<unsigned>(fixture_msg_original_x87),
                     static_cast<unsigned long long>(fixture_msg_original_xmm0[0]),
                     static_cast<unsigned long long>(fixture_msg_original_xmm0[1]));
    }
    check(volatile_state_ok,"message_volatile_flags_xmm_and_fp_state_restored");
    check(check_after_nonvolatile(),
          "message_nonvolatile_gpr_and_xmm_state_preserved");
    check(fixture_msg_return_rax==kReturnRax
              && xmm_pair_equal(fixture_msg_return_xmm0,kReturnXmmLow,
                                kReturnXmmHigh),
          "message_native_return_values_untouched");
}

struct UnwindPoint final {
    const char* name;
    DWORD64 pc;
    std::uintptr_t frame_bytes;
    PRUNTIME_FUNCTION expected_function;
};

bool check_message_unwind() noexcept {
    const DWORD64 hook=reinterpret_cast<DWORD64>(&information_battle_message_hook);
    DWORD64 image_base=0;
    PRUNTIME_FUNCTION main_function=RtlLookupFunctionEntry(
        hook,&image_base,nullptr);
    if (!main_function || image_base>hook
            || image_base+main_function->BeginAddress!=hook) {
        check(false,"message_unwind_main_row");
        return false;
    }
    const DWORD64 main_end=image_base+main_function->EndAddress;
    DWORD64 restore_image=0;
    PRUNTIME_FUNCTION restore_function=RtlLookupFunctionEntry(
        main_end,&restore_image,nullptr);
    const bool restore_ok=restore_function && restore_image==image_base
        && image_base+restore_function->BeginAddress==main_end;
    if (!restore_ok) {
        check(false,"message_unwind_restore_row");
        return false;
    }
    const DWORD64 restore_end=image_base+restore_function->EndAddress;
    DWORD64 tail_image=0;
    PRUNTIME_FUNCTION tail_function=RtlLookupFunctionEntry(
        restore_end,&tail_image,nullptr);
    const bool tail_ok=tail_function && tail_image==image_base
        && image_base+tail_function->BeginAddress==restore_end;
    if (!tail_ok) {
        check(false,"message_unwind_tail_row");
        return false;
    }
    check(true,"message_unwind_three_runtime_rows");

    const UnwindPoint points[]={
        {"entry",hook,0u,main_function},
        {"after_push",hook+1u,8u,main_function},
        {"after_sub",hook+8u,0x1e8u,main_function},
        {"body",hook+9u,0x1e8u,main_function},
        {"before_add",main_end-1u,0x1e8u,main_function},
        {"after_add",main_end,8u,restore_function},
        {"after_pop_tail",restore_end,0u,tail_function},
    };
    unsigned point_failures=0;
    unsigned char* stack=static_cast<unsigned char*>(VirtualAlloc(
        nullptr,0x1000,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE));
    if (!stack) {
        check(false,"message_unwind_synthetic_stack");
        return false;
    }
    constexpr std::uint64_t kReturn=UINT64_C(0x1020304050607080);
    for (const UnwindPoint& point : points) {
        DWORD64 point_image=0;
        PRUNTIME_FUNCTION function=RtlLookupFunctionEntry(
            point.pc,&point_image,nullptr);
        unsigned char* entry_rsp=stack+0x400;
        *reinterpret_cast<std::uint64_t*>(entry_rsp)=kReturn;
        CONTEXT context{};
        context.ContextFlags=CONTEXT_CONTROL;
        context.Rip=point.pc;
        context.Rsp=reinterpret_cast<DWORD64>(entry_rsp-point.frame_bytes);
        PVOID handler_data=nullptr;
        DWORD64 establisher=0;
        KNONVOLATILE_CONTEXT_POINTERS nonvolatile{};
        if (!function || function!=point.expected_function
                || point_image!=image_base) {
            ++point_failures;
            std::fprintf(stderr,"message unwind row mismatch at %s\n",
                         point.name);
            continue;
        }
        (void)RtlVirtualUnwind(UNW_FLAG_NHANDLER,point_image,context.Rip,
            function,&context,&handler_data,&establisher,&nonvolatile);
        if (context.Rip!=kReturn
                || context.Rsp!=reinterpret_cast<DWORD64>(entry_rsp+8)) {
            ++point_failures;
            std::fprintf(stderr,"message unwind mismatch at %s\n",point.name);
        }
    }
    VirtualFree(stack,0,MEM_RELEASE);
    check(point_failures==0u,"message_unwind_push_sub_body_add_pop_tail_boundaries");
    return point_failures==0u;
}

}  // namespace

// Seam for the unused legacy entry half of the production assembly.  This
// test calls only the template message hook, but the production stub keeps
// both entry symbols in the same object file.
extern "C" void information_battle_entry_capture(
    void*,void*,void*,void*,std::uintptr_t) noexcept {}

extern "C" void information_battle_message_capture(
    void* message, void* callback, void* original_return,
    std::uintptr_t formatter_frame) noexcept {
    ++fixture_msg_capture_call_count;
    fixture_msg_capture_message=reinterpret_cast<std::uintptr_t>(message);
    fixture_msg_capture_callback=reinterpret_cast<std::uintptr_t>(callback);
    fixture_msg_capture_return=reinterpret_cast<std::uintptr_t>(original_return);
    fixture_msg_capture_rbp=formatter_frame;
    SetLastError(kCallbackLastError);
    fixture_message_capture_mutate();
}

int main() {
    information_battle_entry_original=nullptr;
    information_battle_message_original=reinterpret_cast<void*>(
        reinterpret_cast<std::uintptr_t>(&fixture_message_original));
    run_message_abi_case();
    check_message_unwind();
    const bool passed=failures==0u;
    std::printf(
        "{\"passed\":%s,\"capture_calls\":%u,\"original_calls\":%u,"
        "\"production_stub_template\":true,\"game_access\":false,"
        "\"rea_or_rpm\":false}\n",
        passed ? "true" : "false",
        static_cast<unsigned>(fixture_msg_capture_call_count),
        static_cast<unsigned>(fixture_msg_original_call_count));
    return passed ? 0 : 1;
}
