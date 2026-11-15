#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include "../information-truce-expiry-entry-plan.h"
namespace plan = information::truce_expiry::entry;
static unsigned checks = 0, calls = 0;
#define CHECK(expression) do { ++checks; if (!(expression)) { std::printf("FAIL line %u %s\n", __LINE__, #expression); std::exit(1); } } while (false)
using Call = uintptr_t(*)(uintptr_t);
static Call original = nullptr;
static uintptr_t hook(uintptr_t value) { ++calls; return original(value); }
extern "C" void truce_entry_registers(Call function, uint64_t* result, uintptr_t value);
constexpr std::array<uint64_t, 8> sentinels{{UINT64_C(0x1111111122222222), UINT64_C(0x3333333344444444),
    UINT64_C(0x5555555566666666), UINT64_C(0x7777777788888888), UINT64_C(0x99999999aaaaaaaa),
    UINT64_C(0xbbbbbbbbcccccccc), UINT64_C(0xddddddddeeeeeeee), UINT64_C(0x123456789abcdef0)}};
static void verify_call(Call function) {
    uint64_t result[9]{};
    truce_entry_registers(function, result, 0x12345678);
    CHECK(result[0] == 0x12345678);
    for (unsigned index = 0; index < sentinels.size(); ++index) CHECK(result[index + 1] == sentinels[index]);
}
int main() {
    auto* source = static_cast<unsigned char*>(VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    auto* copied = static_cast<unsigned char*>(VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    CHECK(source && copied);
    const auto entry = reinterpret_cast<uintptr_t>(source);
    std::memcpy(source, plan::kPrefix.data(), plan::kPrefix.size());
    const unsigned char tail[] = {0x48,0x89,0xc8,0x41,0x5e,0x41,0x5d,0x41,0x5c,0x5f,0x5e,0x5d,
        0x48,0x8b,0x5c,0x24,0x18,0xc3};
    std::memcpy(source + plan::kPrefix.size(), tail, sizeof(tail));
    plan::Plan image{};
    CHECK(plan::prepare(plan::kPrefix, plan::kSourceUnwind, entry, reinterpret_cast<uintptr_t>(&hook), image));
    CHECK(image.image[64] == 1 && image.runtime.end == 43);
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
    for (unsigned offset : {0,5,6,7,8,10,12,14,25,36,42}) {
        alignas(16) uint64_t stack[40]{};
        auto* initial = stack + 16;
        initial[0] = 0x12345678;
        initial[3] = sentinels[0];
        for (unsigned index = 1; index <= 6; ++index) initial[-static_cast<int>(index)] = sentinels[index];
        CONTEXT context{};
        context.ContextFlags = CONTEXT_FULL;
        context.Rip = reinterpret_cast<DWORD64>(copied) + offset;
        context.Rbx = sentinels[0]; context.Rbp = sentinels[1]; context.Rsi = sentinels[2];
        context.Rdi = sentinels[3]; context.R12 = sentinels[4]; context.R13 = sentinels[5];
        context.R14 = sentinels[6]; context.R15 = sentinels[7];
        if (offset >= 14) {
            context.Rbx = context.Rbp = context.Rsi = context.Rdi = context.R12 = context.R13 = context.R14 = 0;
        }
        const unsigned pushes = (offset >= 6) + (offset >= 7) + (offset >= 8)
            + (offset >= 10) + (offset >= 12) + (offset >= 14);
        context.Rsp = reinterpret_cast<DWORD64>(initial) - pushes * 8;
        void* data = nullptr;
        DWORD64 establisher = 0;
        KNONVOLATILE_CONTEXT_POINTERS pointers{};
        CHECK(RtlVirtualUnwind(UNW_FLAG_EHANDLER, reinterpret_cast<DWORD64>(copied), context.Rip,
            &function, &context, &data, &establisher, &pointers) == nullptr);
        CHECK(context.Rsp == reinterpret_cast<DWORD64>(initial) + 8 && context.Rip == initial[0]);
        CHECK(context.Rbx == sentinels[0] && context.Rbp == sentinels[1] && context.Rsi == sentinels[2]);
        CHECK(context.Rdi == sentinels[3] && context.R12 == sentinels[4] && context.R13 == sentinels[5]);
        CHECK(context.R14 == sentinels[6] && context.R15 == sentinels[7]);
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
    std::printf("%u truce trampoline ABI and unwind checks passed\n", checks);
}
