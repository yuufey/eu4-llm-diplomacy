#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "../information-country-modifier-entry-plan.h"

#include <array>
#include <cstdio>
#include <cstring>

namespace entry = information::country_modifier::entry;

int main() {
    entry::Plan plan{};
    if (!entry::prepare(entry::kPrefix, entry::kUnwind,
        0x1403283f0, 0x140001000, plan)) return 1;
    auto image = static_cast<unsigned char*>(VirtualAlloc(nullptr, 4096,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!image) return 2;
    std::memcpy(image, plan.image.data(), plan.image.size());
    DWORD old = 0;
    if (!VirtualProtect(image, 4096, PAGE_EXECUTE_READ, &old)) return 3;
    RUNTIME_FUNCTION function{plan.runtime.begin, plan.runtime.end, plan.runtime.unwind};
    const auto image_base = reinterpret_cast<DWORD64>(image);
    if (!RtlAddFunctionTable(&function, 1, image_base)) return 4;
    constexpr std::uint64_t saved_rsi = 0x1111222233334444;
    constexpr std::uint64_t saved_r14 = 0x5555666677778888;
    constexpr std::uint64_t saved_rbx = 0x2222333344445555;
    constexpr std::uint64_t return_address = 0x140001234;
    constexpr std::array<unsigned, 9> offsets{{0, 2, 4, 8, 12, 15, 26, 37, 43}};
    unsigned failures = 0;
    for (const auto offset : offsets) {
        alignas(16) std::array<std::uint64_t, 64> stack{};
        stack[33] = return_address;
        stack[32] = saved_rsi;
        stack[31] = saved_r14;
        stack[34] = 0x1403283ff;
        const auto entry_rsp = reinterpret_cast<DWORD64>(&stack[33]);
        const unsigned consumed = offset >= 8 ? 0x38 : offset >= 4 ? 16 : offset >= 2 ? 8 : 0;
        CONTEXT context{};
        context.ContextFlags = CONTEXT_FULL;
        context.Rip = image_base + offset;
        context.Rsp = entry_rsp - consumed;
        context.Rsi = offset >= 15 ? 0x9999888877776666 : saved_rsi;
        context.R14 = saved_r14;
        context.Rbx = saved_rbx;
        DWORD64 found_base = 0;
        auto found = RtlLookupFunctionEntry(context.Rip, &found_base, nullptr);
        if (found != &function || found_base != image_base) ++failures;
        void* handler_data = nullptr;
        DWORD64 establisher = 0;
        RtlVirtualUnwind(UNW_FLAG_NHANDLER, image_base, context.Rip, &function,
            &context, &handler_data, &establisher, nullptr);
        const bool okay = context.Rip == return_address && context.Rsp == entry_rsp + 8
            && context.Rsi == saved_rsi && context.R14 == saved_r14 && context.Rbx == saved_rbx;
        std::printf("offset %u %s\n", offset, okay ? "PASS" : "FAIL");
        if (!okay) ++failures;
    }
    if (!RtlDeleteFunctionTable(&function)) ++failures;
    if (!VirtualFree(image, 0, MEM_RELEASE)) ++failures;
    std::printf("9 unwind positions, failures=%u\n", failures);
    return failures ? 1 : 0;
}
