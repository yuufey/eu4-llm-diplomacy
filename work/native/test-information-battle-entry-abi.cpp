#include <windows.h>

#include <cstdint>
#include <cstdio>

extern "C" {
std::uintptr_t information_battle_entry_stub(void*, void*, void*, void*,
    std::uintptr_t, std::uintptr_t);
void* information_battle_entry_original;
void* information_battle_entry_stub_pointer;
void fixture_callback_mutate_volatile();
std::uintptr_t fixture_original_target();
std::uintptr_t fixture_call_direct();
std::uintptr_t fixture_call_indirect();
extern const unsigned char information_battle_entry_unwind_entry[];
extern const unsigned char information_battle_entry_unwind_after_push[];
extern const unsigned char information_battle_entry_unwind_after_sub[];
extern const unsigned char information_battle_entry_unwind_before_call[];
extern const unsigned char information_battle_entry_unwind_before_add[];
extern const unsigned char information_battle_entry_unwind_after_add[];
extern const unsigned char information_battle_entry_unwind_after_popfq[];

volatile std::uint32_t fixture_target_call_count=0;
volatile std::uint64_t fixture_seen_rax[8]{};
volatile std::uint64_t fixture_seen_rcx[8]{};
volatile std::uint64_t fixture_seen_rdx[8]{};
volatile std::uint64_t fixture_seen_r8[8]{};
volatile std::uint64_t fixture_seen_r9[8]{};
volatile std::uint64_t fixture_seen_rbx[8]{};
volatile std::uint64_t fixture_seen_r10[8]{};
volatile std::uint64_t fixture_seen_r11[8]{};
volatile std::uint64_t fixture_seen_return_address[8]{};
volatile std::uint64_t fixture_seen_rsp[8]{};
volatile std::uint64_t fixture_seen_rsp_mod16[8]{};
volatile std::uint64_t fixture_seen_stack5[8]{};
volatile std::uint64_t fixture_seen_stack6[8]{};
volatile std::uint64_t fixture_seen_flags[8]{};
volatile std::uint32_t fixture_seen_mxcsr[8]{};
volatile std::uint16_t fixture_seen_x87_control[8]{};
volatile std::uint64_t fixture_seen_xmm0[8]{};
volatile std::uint64_t fixture_seen_xmm0_hi[8]{};
volatile std::uint64_t fixture_seen_xmm1[8]{};
volatile std::uint64_t fixture_seen_xmm1_hi[8]{};
volatile std::uint64_t fixture_seen_xmm2[8]{};
volatile std::uint64_t fixture_seen_xmm2_hi[8]{};
volatile std::uint64_t fixture_seen_xmm3[8]{};
volatile std::uint64_t fixture_seen_xmm3_hi[8]{};
volatile std::uint64_t fixture_seen_xmm4[8]{};
volatile std::uint64_t fixture_seen_xmm4_hi[8]{};
volatile std::uint64_t fixture_seen_xmm5[8]{};
volatile std::uint64_t fixture_seen_xmm5_hi[8]{};
volatile std::uint64_t fixture_seen_xmm6[8]{};
volatile std::uint64_t fixture_seen_xmm6_hi[8]{};
volatile std::uint64_t fixture_seen_xmm7[8]{};
volatile std::uint64_t fixture_seen_xmm7_hi[8]{};
volatile std::uint64_t fixture_seen_xmm8[8]{};
volatile std::uint64_t fixture_seen_xmm8_hi[8]{};
volatile std::uint64_t fixture_seen_xmm9[8]{};
volatile std::uint64_t fixture_seen_xmm9_hi[8]{};
volatile std::uint64_t fixture_seen_xmm10[8]{};
volatile std::uint64_t fixture_seen_xmm10_hi[8]{};
volatile std::uint64_t fixture_seen_xmm11[8]{};
volatile std::uint64_t fixture_seen_xmm11_hi[8]{};
volatile std::uint64_t fixture_seen_xmm12[8]{};
volatile std::uint64_t fixture_seen_xmm12_hi[8]{};
volatile std::uint64_t fixture_seen_xmm13[8]{};
volatile std::uint64_t fixture_seen_xmm13_hi[8]{};
volatile std::uint64_t fixture_seen_xmm14[8]{};
volatile std::uint64_t fixture_seen_xmm14_hi[8]{};
volatile std::uint64_t fixture_seen_xmm15[8]{};
volatile std::uint64_t fixture_seen_xmm15_hi[8]{};

volatile std::uint64_t fixture_after_rbx=0;
volatile std::uint64_t fixture_after_rbp=0;
volatile std::uint64_t fixture_after_rsi=0;
volatile std::uint64_t fixture_after_rdi=0;
volatile std::uint64_t fixture_after_r12=0;
volatile std::uint64_t fixture_after_r13=0;
volatile std::uint64_t fixture_after_r14=0;
volatile std::uint64_t fixture_after_r15=0;
volatile std::uint64_t fixture_after_xmm6=0;
volatile std::uint64_t fixture_after_xmm7=0;
volatile std::uint64_t fixture_after_xmm8=0;
volatile std::uint64_t fixture_after_xmm9=0;
volatile std::uint64_t fixture_after_xmm10=0;
volatile std::uint64_t fixture_after_xmm11=0;
volatile std::uint64_t fixture_after_xmm12=0;
volatile std::uint64_t fixture_after_xmm13=0;
volatile std::uint64_t fixture_after_xmm14=0;
volatile std::uint64_t fixture_after_xmm15=0;
volatile std::uint64_t fixture_last_return_xmm=0;
volatile std::uint64_t fixture_expected_flags=0;
volatile std::uint64_t fixture_callback_mutated_flags=0;
volatile std::uint64_t fixture_original_entry_flags=0;

volatile std::uint32_t fixture_callback_count=0;
volatile std::uint32_t fixture_callback_depth=0;
volatile std::uint32_t fixture_nested_enabled=0;
volatile std::uint32_t fixture_nested_started=0;
volatile std::uint64_t fixture_callback_combat[8]{};
volatile std::uint64_t fixture_callback_summary[8]{};
volatile std::uint64_t fixture_callback_result[8]{};
volatile std::uint64_t fixture_callback_caller_return[8]{};
volatile std::uint64_t fixture_callback_rbx[8]{};
volatile std::uint64_t fixture_nested_return=0;
}

namespace {

constexpr std::uint64_t kCombat=UINT64_C(0x1111222233334444);
constexpr std::uint64_t kSummary=UINT64_C(0x2222333344445555);
constexpr std::uint64_t kResult=UINT64_C(0x3333444455556666);
constexpr std::uint64_t kFourth=UINT64_C(0x4444555566667777);
constexpr std::uint64_t kStack5=UINT64_C(0x5555666677778888);
constexpr std::uint64_t kStack6=UINT64_C(0x6666777788889999);
constexpr std::uint64_t kRax=UINT64_C(0xaaaabbbbccccdddd);
constexpr std::uint64_t kR10=UINT64_C(0x1011121314151617);
constexpr std::uint64_t kR11=UINT64_C(0x18191a1b1c1d1e1f);
constexpr std::uint64_t kReturnRax=UINT64_C(0x7f6e5d4c3b2a1908);
constexpr std::uint64_t kReturnXmm=UINT64_C(0x1234abcd5678ef90);
constexpr std::uint32_t kInitialMxcsr=0x1f80u;
constexpr std::uint16_t kInitialX87Control=0x037fu;
constexpr std::uint32_t kIncomingLastError=0x13572468u;

constexpr std::uint64_t kNonvolatile[8]={
    UINT64_C(0x0102030405060708), UINT64_C(0x1112131415161718),
    UINT64_C(0x2122232425262728), UINT64_C(0x3132333435363738),
    UINT64_C(0x4142434445464748), UINT64_C(0x5152535455565758),
    UINT64_C(0x6162636465666768), UINT64_C(0x7172737475767878),
};

constexpr std::uint64_t kVolatileXmm[6]={
    UINT64_C(0x8081828384858688), UINT64_C(0x9091929394959698),
    UINT64_C(0xa0a1a2a3a4a5a6a7), UINT64_C(0xb0b1b2b3b4b5b6b7),
    UINT64_C(0xc0c1c2c3c4c5c6c7), UINT64_C(0xd0d1d2d3d4d5d6d7),
};

constexpr std::uint64_t kVolatileXmmHigh[6]={
    UINT64_C(0x0807060504030201), UINT64_C(0x1817161514131211),
    UINT64_C(0x2827262524232211), UINT64_C(0x3837363534333221),
    UINT64_C(0x4847464544434231), UINT64_C(0x5857565554535241),
};

constexpr std::uint64_t kNonvolatileXmm[10]={
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

constexpr std::uint64_t kNestedCombat=UINT64_C(0xabc0000000000001);
constexpr std::uint64_t kNestedSummary=UINT64_C(0xabc0000000000002);
constexpr std::uint64_t kNestedResult=UINT64_C(0xabc0000000000003);
constexpr std::uint64_t kNestedFourth=UINT64_C(0xabc0000000000004);

using EntryFunction=std::uintptr_t (*)(void*,void*,void*,void*,
    std::uintptr_t,std::uintptr_t);

template <typename T, std::size_t N>
void clear_array(volatile T (&array)[N]) noexcept {
    for (std::size_t i=0; i<N; ++i) array[i]=0;
}

void reset_observations(bool nested) noexcept {
    fixture_target_call_count=0;
    fixture_callback_count=0;
    fixture_callback_depth=0;
    fixture_nested_enabled=nested ? 1u : 0u;
    fixture_nested_started=0;
    fixture_nested_return=0;
    fixture_expected_flags=0;
    fixture_callback_mutated_flags=0;
    fixture_last_return_xmm=0;
    clear_array(fixture_seen_rax);
    clear_array(fixture_seen_rcx);
    clear_array(fixture_seen_rdx);
    clear_array(fixture_seen_r8);
    clear_array(fixture_seen_r9);
    clear_array(fixture_seen_rbx);
    clear_array(fixture_seen_r10);
    clear_array(fixture_seen_r11);
    clear_array(fixture_seen_return_address);
    clear_array(fixture_seen_rsp);
    clear_array(fixture_seen_rsp_mod16);
    clear_array(fixture_seen_stack5);
    clear_array(fixture_seen_stack6);
    clear_array(fixture_seen_flags);
    clear_array(fixture_seen_mxcsr);
    clear_array(fixture_seen_x87_control);
    clear_array(fixture_seen_xmm0);
    clear_array(fixture_seen_xmm0_hi);
    clear_array(fixture_seen_xmm1);
    clear_array(fixture_seen_xmm1_hi);
    clear_array(fixture_seen_xmm2);
    clear_array(fixture_seen_xmm2_hi);
    clear_array(fixture_seen_xmm3);
    clear_array(fixture_seen_xmm3_hi);
    clear_array(fixture_seen_xmm4);
    clear_array(fixture_seen_xmm4_hi);
    clear_array(fixture_seen_xmm5);
    clear_array(fixture_seen_xmm5_hi);
    clear_array(fixture_seen_xmm6);
    clear_array(fixture_seen_xmm6_hi);
    clear_array(fixture_seen_xmm7);
    clear_array(fixture_seen_xmm7_hi);
    clear_array(fixture_seen_xmm8);
    clear_array(fixture_seen_xmm8_hi);
    clear_array(fixture_seen_xmm9);
    clear_array(fixture_seen_xmm9_hi);
    clear_array(fixture_seen_xmm10);
    clear_array(fixture_seen_xmm10_hi);
    clear_array(fixture_seen_xmm11);
    clear_array(fixture_seen_xmm11_hi);
    clear_array(fixture_seen_xmm12);
    clear_array(fixture_seen_xmm12_hi);
    clear_array(fixture_seen_xmm13);
    clear_array(fixture_seen_xmm13_hi);
    clear_array(fixture_seen_xmm14);
    clear_array(fixture_seen_xmm14_hi);
    clear_array(fixture_seen_xmm15);
    clear_array(fixture_seen_xmm15_hi);
    clear_array(fixture_callback_combat);
    clear_array(fixture_callback_summary);
    clear_array(fixture_callback_result);
    clear_array(fixture_callback_caller_return);
    clear_array(fixture_callback_rbx);
    fixture_after_rbx=0;
    fixture_after_rbp=0;
    fixture_after_rsi=0;
    fixture_after_rdi=0;
    fixture_after_r12=0;
    fixture_after_r13=0;
    fixture_after_r14=0;
    fixture_after_r15=0;
    fixture_after_xmm6=0;
    fixture_after_xmm7=0;
    fixture_after_xmm8=0;
    fixture_after_xmm9=0;
    fixture_after_xmm10=0;
    fixture_after_xmm11=0;
    fixture_after_xmm12=0;
    fixture_after_xmm13=0;
    fixture_after_xmm14=0;
    fixture_after_xmm15=0;
}

bool fail(const char* message) noexcept {
    std::fprintf(stderr,"information-battle-entry ABI failure: %s\n",message);
    return false;
}

bool check_pair(std::size_t target_index,std::size_t callback_index) noexcept {
    if (fixture_seen_rcx[target_index]!=fixture_callback_combat[callback_index]
        || fixture_seen_rdx[target_index]!=fixture_callback_summary[callback_index]
        || fixture_seen_r8[target_index]!=fixture_callback_result[callback_index]
        || fixture_callback_rbx[callback_index]!=fixture_seen_rbx[target_index]
        || fixture_seen_r9[target_index]!=(
            callback_index==0 ? kFourth : kNestedFourth)
        || fixture_seen_return_address[target_index]
            !=fixture_callback_caller_return[callback_index]
        || fixture_seen_rsp_mod16[target_index]!=8) {
        std::fprintf(stderr,
            "pair target=%zu callback=%zu rcx=%llx/%llx rdx=%llx/%llx r8=%llx/%llx r9=%llx/%llx rbx=%llx/%llx ret=%llx/%llx rspmod=%llx\n",
            target_index,callback_index,
            static_cast<unsigned long long>(fixture_seen_rcx[target_index]),
            static_cast<unsigned long long>(fixture_callback_combat[callback_index]),
            static_cast<unsigned long long>(fixture_seen_rdx[target_index]),
            static_cast<unsigned long long>(fixture_callback_summary[callback_index]),
            static_cast<unsigned long long>(fixture_seen_r8[target_index]),
            static_cast<unsigned long long>(fixture_callback_result[callback_index]),
            static_cast<unsigned long long>(fixture_seen_r9[target_index]),
            static_cast<unsigned long long>(callback_index==0 ? kFourth : kNestedFourth),
            static_cast<unsigned long long>(fixture_callback_rbx[callback_index]),
            static_cast<unsigned long long>(fixture_seen_rbx[target_index]),
            static_cast<unsigned long long>(fixture_seen_return_address[target_index]),
            static_cast<unsigned long long>(fixture_callback_caller_return[callback_index]),
            static_cast<unsigned long long>(fixture_seen_rsp_mod16[target_index]));
        return fail("callback/target arguments, return address, or RSP alignment");
    }
    return true;
}

bool check_full_outer_state() noexcept {
    if (fixture_seen_rax[0]!=kRax || fixture_seen_r10[0]!=kR10
        || fixture_seen_r11[0]!=kR11
        || fixture_seen_rbx[0]!=kNonvolatile[0]
        || fixture_seen_stack5[0]!=kStack5 || fixture_seen_stack6[0]!=kStack6
        || fixture_seen_flags[0]!=fixture_expected_flags
        || fixture_seen_mxcsr[0]!=kInitialMxcsr
        || fixture_seen_x87_control[0]!=kInitialX87Control) {
        return fail("volatile GPR, stack arguments, flags, or FP control state");
    }
    const volatile std::uint64_t* volatile_xmm[]={
        fixture_seen_xmm0,fixture_seen_xmm1,fixture_seen_xmm2,
        fixture_seen_xmm3,fixture_seen_xmm4,fixture_seen_xmm5,
    };
    const volatile std::uint64_t* volatile_xmm_high[]={
        fixture_seen_xmm0_hi,fixture_seen_xmm1_hi,fixture_seen_xmm2_hi,
        fixture_seen_xmm3_hi,fixture_seen_xmm4_hi,fixture_seen_xmm5_hi,
    };
    for (std::size_t i=0; i<6; ++i) {
        if (volatile_xmm[i][0]!=kVolatileXmm[i])
            return fail("volatile XMM0-XMM5 state");
        if (volatile_xmm_high[i][0]!=kVolatileXmmHigh[i])
            return fail("volatile XMM0-XMM5 upper 64-bit state");
    }
    const volatile std::uint64_t* nonvolatile_xmm[]={
        fixture_seen_xmm6,fixture_seen_xmm7,fixture_seen_xmm8,
        fixture_seen_xmm9,fixture_seen_xmm10,fixture_seen_xmm11,
        fixture_seen_xmm12,fixture_seen_xmm13,fixture_seen_xmm14,
        fixture_seen_xmm15,
    };
    const volatile std::uint64_t* nonvolatile_xmm_high[]={
        fixture_seen_xmm6_hi,fixture_seen_xmm7_hi,fixture_seen_xmm8_hi,
        fixture_seen_xmm9_hi,fixture_seen_xmm10_hi,fixture_seen_xmm11_hi,
        fixture_seen_xmm12_hi,fixture_seen_xmm13_hi,fixture_seen_xmm14_hi,
        fixture_seen_xmm15_hi,
    };
    for (std::size_t i=0; i<10; ++i) {
        if (nonvolatile_xmm[i][0]!=kNonvolatileXmm[i])
            return fail("nonvolatile XMM6-XMM15 state");
        if (nonvolatile_xmm_high[i][0]!=kNonvolatileXmmHigh[i])
            return fail("nonvolatile XMM6-XMM15 upper 64-bit state");
    }
    if (fixture_after_rbx!=kNonvolatile[0]
        || fixture_after_rbp!=kNonvolatile[1]
        || fixture_after_rsi!=kNonvolatile[2]
        || fixture_after_rdi!=kNonvolatile[3]
        || fixture_after_r12!=kNonvolatile[4]
        || fixture_after_r13!=kNonvolatile[5]
        || fixture_after_r14!=kNonvolatile[6]
        || fixture_after_r15!=kNonvolatile[7]) {
        return fail("nonvolatile GPR state after tail-jump/original");
    }
    const volatile std::uint64_t after_xmm[]={
        fixture_after_xmm6,fixture_after_xmm7,fixture_after_xmm8,
        fixture_after_xmm9,fixture_after_xmm10,fixture_after_xmm11,
        fixture_after_xmm12,fixture_after_xmm13,fixture_after_xmm14,
        fixture_after_xmm15,
    };
    for (std::size_t i=0; i<10; ++i) {
        if (after_xmm[i]!=kNonvolatileXmm[i])
            return fail("nonvolatile XMM6-XMM15 after return");
    }
    if (fixture_last_return_xmm!=kReturnXmm)
        return fail("original XMM0 return value");
    return true;
}

bool run_case(bool indirect,bool nested) noexcept {
    reset_observations(nested);
    ::SetLastError(kIncomingLastError);
    const std::uintptr_t returned=indirect
        ? fixture_call_indirect() : fixture_call_direct();
    const unsigned expected_calls=nested ? 2u : 1u;
    if (returned!=kReturnRax) return fail("original RAX return value");
    if (fixture_target_call_count!=expected_calls
        || fixture_callback_count!=expected_calls)
        return fail("original/callback call count");
    if (::GetLastError()!=kIncomingLastError)
        return fail("GetLastError was not restored");
    if (nested) {
        if (!check_pair(1,0) || !check_pair(0,1)) return false;
        if (fixture_nested_return!=kReturnRax)
            return fail("nested original return value");
        return true;
    }
    if (!check_pair(0,0)) return false;
    if (fixture_callback_combat[0]!=kCombat
        || fixture_callback_summary[0]!=kSummary
        || fixture_callback_result[0]!=kResult)
        return fail("outer callback argument capture");
    return check_full_outer_state();
}

bool check_stub_unwind_metadata() noexcept {
    struct UnwindPoint final {
        const char* name;
        const unsigned char* pc;
        std::uintptr_t frame_bytes;
    };
    const UnwindPoint points[]={
        {"entry",information_battle_entry_unwind_entry,0},
        {"after_pushfq",information_battle_entry_unwind_after_push,8},
        {"after_sub",information_battle_entry_unwind_after_sub,0x1e8},
        {"before_callback_call",information_battle_entry_unwind_before_call,0x1e8},
        {"before_add",information_battle_entry_unwind_before_add,0x1e8},
        {"after_add_before_popfq",information_battle_entry_unwind_after_add,8},
        {"after_popfq_before_jmp",information_battle_entry_unwind_after_popfq,0},
    };
    auto stack=static_cast<unsigned char*>(VirtualAlloc(
        nullptr,0x1000,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE));
    if (!stack) return fail("unwind synthetic stack allocation");
    constexpr std::uint64_t kReturn=UINT64_C(0x1020304050607080);
    unsigned failures=0;
    for (const UnwindPoint& point : points) {
        DWORD64 image_base=0;
        PRUNTIME_FUNCTION function=RtlLookupFunctionEntry(
            reinterpret_cast<DWORD64>(point.pc),&image_base,nullptr);
        if (!function) {
            ++failures;
            std::fprintf(stderr,"unwind point %s has no runtime function\\n",
                point.name);
            continue;
        }
        unsigned char* entry_rsp=stack+0x400;
        *reinterpret_cast<std::uint64_t*>(entry_rsp)=kReturn;
        unsigned char* current=entry_rsp-point.frame_bytes;
        CONTEXT context{};
        context.ContextFlags=CONTEXT_CONTROL;
        context.Rip=reinterpret_cast<DWORD64>(point.pc);
        context.Rsp=reinterpret_cast<DWORD64>(current);
        PVOID handler_data=nullptr;
        DWORD64 establisher=0;
        KNONVOLATILE_CONTEXT_POINTERS nonvolatile{};
        (void)RtlVirtualUnwind(UNW_FLAG_NHANDLER,image_base,context.Rip,
            function,&context,&handler_data,&establisher,&nonvolatile);
        const bool point_passed=context.Rip==kReturn
            && context.Rsp==reinterpret_cast<DWORD64>(entry_rsp+8);
        if (!point_passed) {
            ++failures;
            std::fprintf(stderr,
                "unwind point %s rip=%llx rsp=%llx expected_rsp=%llx\\n",
                point.name,static_cast<unsigned long long>(context.Rip),
                static_cast<unsigned long long>(context.Rsp),
                static_cast<unsigned long long>(
                    reinterpret_cast<DWORD64>(entry_rsp+8)));
        }
    }
    VirtualFree(stack,0,MEM_RELEASE);
    return failures==0 ? true : fail("RtlVirtualUnwind entry-stub boundary");
}

}  // namespace

extern "C" void information_battle_entry_capture(
    void* combat,void* summary,void* result,std::uintptr_t caller_return,
    std::uintptr_t original_rbx) noexcept {
    const std::uint32_t index=fixture_callback_count;
    if (index<8) {
        fixture_callback_combat[index]=reinterpret_cast<std::uintptr_t>(combat);
        fixture_callback_summary[index]=reinterpret_cast<std::uintptr_t>(summary);
        fixture_callback_result[index]=reinterpret_cast<std::uintptr_t>(result);
        fixture_callback_caller_return[index]=caller_return;
        fixture_callback_rbx[index]=original_rbx;
    }
    fixture_callback_count=index+1;
    const std::uint32_t depth=fixture_callback_depth+1;
    fixture_callback_depth=depth;
    ::SetLastError(0x0badf00du);
    fixture_callback_mutate_volatile();
    if (depth==1 && fixture_nested_enabled && !fixture_nested_started) {
        fixture_nested_started=1;
        const EntryFunction nested=&information_battle_entry_stub;
        fixture_nested_return=nested(
            reinterpret_cast<void*>(kNestedCombat),
            reinterpret_cast<void*>(kNestedSummary),
            reinterpret_cast<void*>(kNestedResult),
            reinterpret_cast<void*>(kNestedFourth),
            UINT64_C(0xabc0000000000005),UINT64_C(0xabc0000000000006));
    }
    fixture_callback_depth=depth-1;
}

int main() {
    information_battle_entry_original=reinterpret_cast<void*>(
        reinterpret_cast<std::uintptr_t>(&fixture_original_target));
    information_battle_entry_stub_pointer=reinterpret_cast<void*>(
        reinterpret_cast<std::uintptr_t>(&information_battle_entry_stub));
    if (!information_battle_entry_original || !information_battle_entry_stub_pointer)
        return 2;

    bool passed=check_stub_unwind_metadata();
    passed=run_case(false,false) && passed;
    passed=run_case(true,false) && passed;
    passed=run_case(false,true) && passed;
    passed=run_case(true,true) && passed;
    std::printf("{\"passed\":%s,\"cases\":4,\"nested_cases\":2,"
        "\"original_pointer_published\":true,\"callback_is_observer_only\":true}\n",
        passed ? "true" : "false");
    return passed ? 0 : 1;
}
