#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <cstdint>
#include <cstdio>

extern "C" {
void information_country_modifier_expiry_abi_invoke(void*, void*, void*);
void information_country_modifier_expiry_abi_after_call();

volatile std::uint64_t information_country_modifier_expiry_abi_entry_rsp = 0;
volatile std::uint64_t information_country_modifier_expiry_abi_entry_r13 = 0;
volatile std::uint64_t information_country_modifier_expiry_abi_pre_call_rsp = 0;
volatile std::uint64_t information_country_modifier_expiry_abi_post_call_rsp = 0;
volatile std::uint64_t information_country_modifier_expiry_abi_post_call_r13 = 0;
volatile std::uint64_t information_country_modifier_expiry_abi_outgoing_r13 = 0;
volatile std::uint64_t information_country_modifier_expiry_abi_post_restore_rsp = 0;
volatile std::uint64_t information_country_modifier_expiry_abi_observer_rcx = 0;
volatile std::uint64_t information_country_modifier_expiry_abi_observer_rdx = 0;
volatile std::uint64_t information_country_modifier_expiry_abi_observer_r8 = 0;
volatile std::uint64_t information_country_modifier_expiry_abi_observer_r13 = 0;
volatile std::uint64_t information_country_modifier_expiry_abi_observer_rsp = 0;
volatile std::uint64_t information_country_modifier_expiry_abi_observer_return_pc = 0;
}

namespace {

unsigned failures = 0;

void check(bool okay, const char* label) {
    std::printf("CHECK %s %s\n", label, okay ? "PASS" : "FAIL");
    if (!okay) ++failures;
}

} // namespace

int main() {
    auto* first = reinterpret_cast<void*>(UINT64_C(0x1111222233334444));
    auto* second = reinterpret_cast<void*>(UINT64_C(0x5555666677778888));
    auto* function_context = reinterpret_cast<void*>(UINT64_C(0x9999aaaabbbbcccc));
    information_country_modifier_expiry_abi_invoke(first, second, function_context);

    check(information_country_modifier_expiry_abi_observer_rcx
        == reinterpret_cast<std::uint64_t>(first), "RCX country argument preserved");
    check(information_country_modifier_expiry_abi_observer_rdx
        == reinterpret_cast<std::uint64_t>(second), "RDX instance argument preserved");
    check(information_country_modifier_expiry_abi_observer_r8
        == reinterpret_cast<std::uint64_t>(function_context), "R13 copied into R8");
    check(information_country_modifier_expiry_abi_observer_r13
        == reinterpret_cast<std::uint64_t>(function_context), "R13 retained at observer entry");
    check(information_country_modifier_expiry_abi_observer_return_pc
        == reinterpret_cast<std::uint64_t>(
            &information_country_modifier_expiry_abi_after_call),
        "tail jump preserves original return PC");
    check(information_country_modifier_expiry_abi_observer_rsp + 8
        == information_country_modifier_expiry_abi_pre_call_rsp,
        "observer sees original call stack layout");
    check(information_country_modifier_expiry_abi_post_call_rsp
        == information_country_modifier_expiry_abi_pre_call_rsp,
        "RSP restored after observer returns");
    check(information_country_modifier_expiry_abi_post_call_r13
        == reinterpret_cast<std::uint64_t>(function_context), "R13 preserved through tail call");
    check(information_country_modifier_expiry_abi_outgoing_r13
        == information_country_modifier_expiry_abi_entry_r13,
        "caller nonvolatile R13 restored");
    check(information_country_modifier_expiry_abi_post_restore_rsp
        == information_country_modifier_expiry_abi_entry_rsp,
        "caller RSP restored");

    std::printf("expiry ABI regression: %s (10 checks, 1 scenario)\n",
        failures ? "FAIL" : "PASS");
    return failures ? 1 : 0;
}
