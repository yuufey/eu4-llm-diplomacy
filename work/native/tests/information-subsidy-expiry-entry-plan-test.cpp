#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include "../information-subsidy-expiry-entry-plan.h"
namespace plan = information::subsidy_expiry::entry;
static unsigned checks = 0, calls = 0;
#define CHECK(expression) do { ++checks; if (!(expression)) { std::printf("FAIL line %u %s\n", __LINE__, #expression); std::exit(1); } } while (false)
using Call = uintptr_t(*)(uintptr_t);
static Call original = nullptr;
static uintptr_t hook(uintptr_t value) { ++calls; return original(value); }
extern "C" void subsidy_entry_registers(Call function, uint64_t* result, uintptr_t value);
static uint64_t home_value = 0;
static void verify_call(Call function, bool check_home = true) {
    uint64_t result[2]{};
    subsidy_entry_registers(function, result, 0x12345678);
    CHECK(result[0] == 0x12345678);
    CHECK(result[1] == UINT64_C(0x1111111122222222));
    if (check_home) CHECK(home_value == UINT64_C(0x3333333344444444));
}
int main() {
    auto* source = static_cast<unsigned char*>(VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    auto* copied = static_cast<unsigned char*>(VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    CHECK(source && copied);
    const auto entry = reinterpret_cast<uintptr_t>(source);
    std::memcpy(source, plan::kPrefix.data(), plan::kPrefix.size());
    // Observe the native RDX output home before any native write uses it.
    const unsigned char tail[] = {0x48,0x8b,0x02,0x49,0xbb,0,0,0,0,0,0,0,0,
        0x49,0x89,0x03,0x48,0x89,0xd8,0x48,0x83,0xc4,0x20,0x5b,0xc3};
    std::memcpy(source + plan::kPrefix.size(), tail, sizeof(tail));
    const auto output = reinterpret_cast<uintptr_t>(&home_value);
    std::memcpy(source + plan::kPrefix.size() + 5, &output, 8);
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
    verify_call(reinterpret_cast<Call>(source), false);
    CHECK(calls == 1);
    for (unsigned offset : {0,2,6,9,14,25,36,42}) {
        alignas(16) uint64_t stack[32]{};
        auto* initial = stack + 16;
        initial[0] = 0x12345678;
        initial[-1] = 0xabcdef;
        CONTEXT context{};
        context.ContextFlags = CONTEXT_FULL;
        context.Rip = reinterpret_cast<DWORD64>(copied) + offset;
        context.Rbx = 0xabcdef;
        const unsigned displacement = (offset >= 2 ? 8 : 0) + (offset >= 6 ? 32 : 0);
        context.Rsp = reinterpret_cast<DWORD64>(initial) - displacement;
        void* data = nullptr;
        DWORD64 establisher = 0;
        KNONVOLATILE_CONTEXT_POINTERS pointers{};
        CHECK(RtlVirtualUnwind(UNW_FLAG_EHANDLER, reinterpret_cast<DWORD64>(copied), context.Rip,
            &function, &context, &data, &establisher, &pointers) == nullptr);
        CHECK(context.Rsp == reinterpret_cast<DWORD64>(initial) + 8 && context.Rip == initial[0]);
        CHECK(context.Rbx == 0xabcdef);
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
    std::printf("%u subsidy trampoline ABI and unwind checks passed\n", checks);
}
