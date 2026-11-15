#include <windows.h>

#include <cstddef>
#include <cstdint>
#include <cstdio>

extern "C" {
void information_battle_gate_marker_hook();
void information_battle_gate_marker_capture(std::uintptr_t,
                                             std::uintptr_t) noexcept;
void fixture_gate_marker_original();
void fixture_gate_marker_call();
void fixture_gate_marker_mutate();
extern const unsigned char fixture_gate_marker_call_after[];

void* information_battle_gate_marker_original = nullptr;
void* information_battle_entry_original = nullptr;

volatile std::uint32_t fixture_gate_callback_calls = 0u;
volatile std::uintptr_t fixture_gate_callback_return_pc = 0u;
volatile std::uintptr_t fixture_gate_callback_rbp = 0u;
volatile std::uint64_t fixture_gate_callback_expected_flags = 0u;
volatile std::uintptr_t fixture_gate_marker_expected_rsp = 0u;
volatile std::uint32_t fixture_gate_mutation_calls = 0u;

volatile std::uint32_t fixture_gate_marker_original_calls = 0u;
volatile std::uint64_t fixture_gate_original_rax = 0u;
volatile std::uint64_t fixture_gate_original_rbx = 0u;
volatile std::uint64_t fixture_gate_original_rcx = 0u;
volatile std::uint64_t fixture_gate_original_rdx = 0u;
volatile std::uint64_t fixture_gate_original_rsi = 0u;
volatile std::uint64_t fixture_gate_original_rdi = 0u;
volatile std::uint64_t fixture_gate_original_rbp = 0u;
volatile std::uint64_t fixture_gate_original_r8 = 0u;
volatile std::uint64_t fixture_gate_original_r9 = 0u;
volatile std::uint64_t fixture_gate_original_r10 = 0u;
volatile std::uint64_t fixture_gate_original_r11 = 0u;
volatile std::uint64_t fixture_gate_original_r12 = 0u;
volatile std::uint64_t fixture_gate_original_r13 = 0u;
volatile std::uint64_t fixture_gate_original_r14 = 0u;
volatile std::uint64_t fixture_gate_original_r15 = 0u;
volatile std::uintptr_t fixture_gate_original_rsp = 0u;
volatile std::uintptr_t fixture_gate_original_return_pc = 0u;
volatile std::uint64_t fixture_gate_original_rflags = 0u;
volatile std::uint32_t fixture_gate_original_mxcsr = 0u;
volatile std::uint16_t fixture_gate_original_x87 = 0u;
volatile std::uint32_t fixture_gate_original_last_error = 0u;
volatile std::uint64_t fixture_gate_original_xmm0[2]{};
volatile std::uint64_t fixture_gate_original_xmm1[2]{};
volatile std::uint64_t fixture_gate_original_xmm2[2]{};
volatile std::uint64_t fixture_gate_original_xmm3[2]{};
volatile std::uint64_t fixture_gate_original_xmm4[2]{};
volatile std::uint64_t fixture_gate_original_xmm5[2]{};

volatile std::uint64_t fixture_gate_marker_return_rax = 0u;
volatile std::uint64_t fixture_gate_marker_return_xmm0[2]{};
volatile std::uint64_t fixture_gate_marker_after_rbp = 0u;
}

namespace {

constexpr DWORD kIncomingLastError = 0x13572468u;
constexpr DWORD kCallbackLastError = 0x0badf00du;
constexpr std::uint64_t kReturnRax = UINT64_C(0x7f6e5d4c3b2a1908);
constexpr std::uintptr_t kIncomingRax = UINT64_C(0x1111222233334444);
constexpr std::uintptr_t kIncomingRbx = UINT64_C(0x2222333344445555);
constexpr std::uintptr_t kIncomingRcx = UINT64_C(0xaaaabbbbccccdddd);
constexpr std::uintptr_t kIncomingRdx = UINT64_C(0x9999888877776666);
constexpr std::uintptr_t kIncomingRsi = UINT64_C(0x2122232425262728);
constexpr std::uintptr_t kIncomingRdi = UINT64_C(0x3132333435363738);
constexpr std::uintptr_t kIncomingRbp = UINT64_C(0x1112131415161718);
constexpr std::uintptr_t kIncomingR8 = UINT64_C(0x8888777766665555);
constexpr std::uintptr_t kIncomingR9 = UINT64_C(0x7777666655554444);
constexpr std::uintptr_t kIncomingR10 = UINT64_C(0x1011121314151617);
constexpr std::uintptr_t kIncomingR11 = UINT64_C(0x18191a1b1c1d1e1f);
constexpr std::uintptr_t kIncomingR12 = UINT64_C(0x4142434445464748);
constexpr std::uintptr_t kIncomingR13 = UINT64_C(0x5152535455565758);
constexpr std::uintptr_t kIncomingR14 = UINT64_C(0x6162636465666768);
constexpr std::uintptr_t kIncomingR15 = UINT64_C(0x7172737475767878);

constexpr std::uint64_t kInputXmm[6][2] = {
    {UINT64_C(0x0102030405060708), UINT64_C(0x1112131415161718)},
    {UINT64_C(0x2122232425262728), UINT64_C(0x3132333435363738)},
    {UINT64_C(0x4142434445464748), UINT64_C(0x5152535455565758)},
    {UINT64_C(0x6162636465666768), UINT64_C(0x7172737475767878)},
    {UINT64_C(0x8182838485868788), UINT64_C(0x9192939495969798)},
    {UINT64_C(0xa1a2a3a4a5a6a7a8), UINT64_C(0xb1b2b3b4b5b6b7b8)},
};
constexpr std::uint32_t kInitialMxcsr = 0x1f80u;
constexpr std::uint16_t kInitialX87 = 0x037fu;
constexpr std::uint64_t kReturnXmm0[2] = {
    UINT64_C(0x1234abcd5678ef90), UINT64_C(0xfedcba9876543210),
};

int failures = 0;
int checks = 0;

void check(bool condition, const char* label) {
    ++checks;
    if (!condition) {
        ++failures;
        std::fprintf(stderr, "FAIL: %s\n", label);
    }
}

void check_xmm(const volatile std::uint64_t* observed,
               const std::uint64_t* expected, const char* label) {
    check(observed[0] == expected[0] && observed[1] == expected[1], label);
}

}  // namespace

// The primary entry stub is present in the same production .S object.  These
// symbols satisfy its link references; the test never executes that stub.
extern "C" void information_battle_entry_capture(
        void*, void*, void*, void*, std::uintptr_t) noexcept {}

extern "C" void information_battle_gate_marker_capture(
        std::uintptr_t original_return_pc,
        std::uintptr_t original_rbp) noexcept {
    ++fixture_gate_callback_calls;
    fixture_gate_callback_return_pc = original_return_pc;
    fixture_gate_callback_rbp = original_rbp;
    SetLastError(kCallbackLastError);
    ++fixture_gate_mutation_calls;
    fixture_gate_marker_mutate();
}

int main() {
    information_battle_entry_original = nullptr;
    information_battle_gate_marker_original =
        reinterpret_cast<void*>(
            reinterpret_cast<std::uintptr_t>(&fixture_gate_marker_original));
    SetLastError(kIncomingLastError);
    fixture_gate_marker_call();
    const DWORD caller_last_error = GetLastError();

    check(fixture_gate_callback_calls == 1u,
          "marker callback called exactly once");
    check(fixture_gate_mutation_calls == 1u,
          "callback deliberately mutates volatile state");
    check(fixture_gate_marker_original_calls == 1u,
          "original function called exactly once");
    const std::uintptr_t expected_pc = reinterpret_cast<std::uintptr_t>(
        fixture_gate_marker_call_after);
    check(fixture_gate_callback_return_pc == expected_pc,
          "callback receives actual call return PC");
    check(fixture_gate_callback_rbp == kIncomingRbp,
          "callback receives incoming RBP");
    check(fixture_gate_original_return_pc == expected_pc,
          "tail-jumped original sees original caller return PC");
    check(fixture_gate_original_rsp + sizeof(std::uintptr_t)
              == fixture_gate_marker_expected_rsp,
          "original sees unchanged caller stack position");

    check(fixture_gate_original_rax == kIncomingRax, "original RAX restored");
    check(fixture_gate_original_rbx == kIncomingRbx, "original RBX preserved");
    check(fixture_gate_original_rcx == kIncomingRcx, "original RCX restored");
    check(fixture_gate_original_rdx == kIncomingRdx, "original RDX restored");
    check(fixture_gate_original_rsi == kIncomingRsi, "original RSI preserved");
    check(fixture_gate_original_rdi == kIncomingRdi, "original RDI preserved");
    check(fixture_gate_original_rbp == kIncomingRbp, "original RBP preserved");
    check(fixture_gate_original_r8 == kIncomingR8, "original R8 restored");
    check(fixture_gate_original_r9 == kIncomingR9, "original R9 restored");
    check(fixture_gate_original_r10 == kIncomingR10, "original R10 restored");
    check(fixture_gate_original_r11 == kIncomingR11, "original R11 restored");
    check(fixture_gate_original_r12 == kIncomingR12, "original R12 preserved");
    check(fixture_gate_original_r13 == kIncomingR13, "original R13 preserved");
    check(fixture_gate_original_r14 == kIncomingR14, "original R14 preserved");
    check(fixture_gate_original_r15 == kIncomingR15, "original R15 preserved");
    check(fixture_gate_original_rflags == fixture_gate_callback_expected_flags,
          "original sees exact incoming RFLAGS");

    check_xmm(fixture_gate_original_xmm0, kInputXmm[0], "original XMM0 restored");
    check_xmm(fixture_gate_original_xmm1, kInputXmm[1], "original XMM1 restored");
    check_xmm(fixture_gate_original_xmm2, kInputXmm[2], "original XMM2 restored");
    check_xmm(fixture_gate_original_xmm3, kInputXmm[3], "original XMM3 restored");
    check_xmm(fixture_gate_original_xmm4, kInputXmm[4], "original XMM4 restored");
    check_xmm(fixture_gate_original_xmm5, kInputXmm[5], "original XMM5 restored");
    check(fixture_gate_original_mxcsr == kInitialMxcsr,
          "original MXCSR restored");
    check(fixture_gate_original_x87 == kInitialX87,
          "original x87 control word restored");
    check(fixture_gate_original_last_error == kIncomingLastError,
          "original observes incoming GetLastError value");
    check(caller_last_error == kIncomingLastError,
          "incoming LastError survives through original return");

    check(fixture_gate_marker_return_rax == kReturnRax,
          "original RAX return value reaches caller");
    check_xmm(fixture_gate_marker_return_xmm0, kReturnXmm0,
              "original XMM0 return value reaches caller");
    check(fixture_gate_marker_after_rbp == kIncomingRbp,
          "RBP remains intact after returning to caller");

    const bool passed = failures == 0;
    std::printf(
        "{\"passed\":%s,\"checks\":%d,\"failures\":%d,"
        "\"callbacks\":%u,\"original_calls\":%u}\n",
        passed ? "true" : "false", checks, failures,
        static_cast<unsigned>(fixture_gate_callback_calls),
        static_cast<unsigned>(fixture_gate_marker_original_calls));
    return passed ? 0 : 1;
}
