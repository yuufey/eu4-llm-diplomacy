#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include "../information-claim-expiry-entry-plan.h"
namespace plan = information::claim_expiry::entry;
static unsigned checks = 0, calls = 0;
#define CHECK(expression) do { ++checks; if (!(expression)) { std::printf("FAIL line %u %s\n", __LINE__, #expression); std::exit(1); } } while (false)
using Call = uintptr_t(*)(uintptr_t, uint64_t, unsigned char);
static Call original = nullptr;
static uintptr_t hook(uintptr_t value, uint64_t claimant, unsigned char record_history) {
    ++calls;
    return original(value, claimant, record_history);
}
extern "C" void claim_entry_registers(Call function, uint64_t* result, uintptr_t value);
constexpr std::array<uint64_t, 8> sentinels{{UINT64_C(0x1111111122222222), UINT64_C(0x3333333344444444),
    UINT64_C(0x5555555566666666), UINT64_C(0x7777777788888888), UINT64_C(0x99999999aaaaaaaa),
    UINT64_C(0xbbbbbbbbcccccccc), UINT64_C(0xddddddddeeeeeeee), UINT64_C(0x123456789abcdef0)}};
static void verify_call(Call function) {
    uint64_t result[9]{};
    claim_entry_registers(function, result, 0x12345678);
    CHECK(result[0] == UINT64_C(0x100007a00415246) + 0x12345678 + 0xa5);
    for (unsigned index = 0; index < sentinels.size(); ++index) CHECK(result[index + 1] == sentinels[index]);
}
int main() {
    auto* source = static_cast<unsigned char*>(VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    auto* copied = static_cast<unsigned char*>(VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    CHECK(source && copied);
    const auto entry = reinterpret_cast<uintptr_t>(source);
    std::memcpy(source, plan::kPrefix.data(), plan::kPrefix.size());
    const unsigned char tail[] = {0x48,0x89,0xc8,0x48,0x01,0xd0,0x4c,0x01,0xc0,
        0x48,0x8b,0x5c,0x24,0x18,0x48,0x8b,0x74,0x24,0x20,0xc3};
    std::memcpy(source + plan::kPrefix.size(), tail, sizeof(tail));
    plan::Plan image{};
    CHECK(plan::prepare(plan::kPrefix, plan::kSourceUnwind, entry, reinterpret_cast<uintptr_t>(&hook), image));
    CHECK(image.image[64] == 1 && image.runtime.end == 44);
    std::memcpy(copied, image.image.data(), image.image.size());
    DWORD previous = 0;
    CHECK(VirtualProtect(source, 4096, PAGE_EXECUTE_READ, &previous));
    CHECK(VirtualProtect(copied, 4096, PAGE_EXECUTE_READ, &previous));
    CHECK(FlushInstructionCache(GetCurrentProcess(), source, 4096));
    CHECK(FlushInstructionCache(GetCurrentProcess(), copied, 4096));
    RUNTIME_FUNCTION function{image.runtime.begin, image.runtime.end, image.runtime.unwind};
    CHECK(RtlAddFunctionTable(&function, 1, reinterpret_cast<DWORD64>(copied)));
    verify_call(reinterpret_cast<Call>(source));
    original = reinterpret_cast<Call>(copied);
    verify_call(original);
    CHECK(VirtualProtect(source, 4096, PAGE_READWRITE, &previous));
    std::memcpy(source, image.patch.data(), image.patch.size());
    CHECK(VirtualProtect(source, 4096, PAGE_EXECUTE_READ, &previous));
    CHECK(FlushInstructionCache(GetCurrentProcess(), source, 4096));
    verify_call(reinterpret_cast<Call>(source));
    CHECK(calls == 1);
    for (unsigned offset : {0,5,10,15,26,37,43}) {
        alignas(16) uint64_t stack[32]{};
        auto* initial = stack + 16;
        initial[0] = 0x12345678;
        initial[3] = sentinels[0];
        initial[4] = sentinels[2];
        CONTEXT context{};
        context.ContextFlags = CONTEXT_FULL;
        context.Rip = reinterpret_cast<DWORD64>(copied) + offset;
        context.Rbx = offset >= 15 ? 0 : sentinels[0];
        context.Rsi = offset >= 15 ? 0 : sentinels[2];
        context.Rsp = reinterpret_cast<DWORD64>(initial);
        void* data = nullptr;
        DWORD64 establisher = 0;
        KNONVOLATILE_CONTEXT_POINTERS pointers{};
        CHECK(RtlVirtualUnwind(UNW_FLAG_EHANDLER, reinterpret_cast<DWORD64>(copied), context.Rip,
            &function, &context, &data, &establisher, &pointers) == nullptr);
        CHECK(context.Rsp == reinterpret_cast<DWORD64>(initial) + 8 && context.Rip == initial[0]);
        CHECK(context.Rbx == sentinels[0] && context.Rsi == sentinels[2]);
    }
    auto changed = plan::kPrefix;
    changed[0] ^= 1;
    const auto saved = image.image;
    CHECK(!plan::prepare(changed, plan::kSourceUnwind, entry, reinterpret_cast<uintptr_t>(&hook), image));
    CHECK(image.image == saved);
    auto metadata = plan::kSourceUnwind;
    metadata[0] = 1;
    CHECK(!plan::prepare(plan::kPrefix, metadata, entry, reinterpret_cast<uintptr_t>(&hook), image));
    CHECK(!plan::prepare(plan::kPrefix, plan::kSourceUnwind, entry, entry + 20, image));
    CHECK(RtlDeleteFunctionTable(&function));
    CHECK(VirtualFree(copied, 0, MEM_RELEASE));
    CHECK(VirtualFree(source, 0, MEM_RELEASE));
    std::printf("%u claim trampoline ABI and unwind checks passed\n", checks);
}
