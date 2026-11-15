#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "../information-country-modifier-remove-entry-plan.h"

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>

namespace entry = information::country_modifier::removal_entry;

int main() {
    entry::Plan plan{};
    if (!entry::prepare(entry::kPrefix, entry::kUnwind,
        0x140328710, 0x140001000, plan)) return 1;

    auto image = static_cast<unsigned char*>(VirtualAlloc(nullptr, 4096,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!image) return 2;
    std::memcpy(image, plan.image.data(), plan.image.size());
    DWORD old = 0;
    if (!VirtualProtect(image, 4096, PAGE_EXECUTE_READ, &old)) return 3;

    RUNTIME_FUNCTION function{plan.runtime.begin, plan.runtime.end, plan.runtime.unwind};
    const auto image_base = reinterpret_cast<DWORD64>(image);
    if (!RtlAddFunctionTable(&function, 1, image_base)) return 4;

    constexpr std::uint64_t saved_rbx = 0x1111222233334444;
    constexpr std::uint64_t saved_rdi = 0x5555666677778888;
    constexpr std::uint64_t clobbered = 0x9999aaaabbbbcccc;
    constexpr std::uint64_t return_address = 0x140001234;
    // Prologue instruction boundaries, then the three instruction starts in
    // the generated 29-byte continuation stub and its final in-range byte.
    constexpr std::array<unsigned, 8> offsets{{0, 5, 6, 10, 14, 25, 36, 42}};
    unsigned failures = 0;
    for (const auto offset : offsets) {
        alignas(16) std::array<std::uint64_t, 64> stack{};
        stack[33] = return_address;
        stack[32] = saved_rdi;
        stack[34] = saved_rbx;
        const auto entry_rsp = reinterpret_cast<DWORD64>(&stack[33]);
        const unsigned consumed = offset >= 10 ? 0x28u : offset >= 6 ? 8u : 0u;

        CONTEXT context{};
        context.ContextFlags = CONTEXT_FULL;
        context.Rip = image_base + offset;
        context.Rsp = entry_rsp - consumed;
        context.Rbx = offset >= 10 ? clobbered : saved_rbx;
        context.Rdi = offset >= 6 ? clobbered : saved_rdi;
        DWORD64 found_base = 0;
        auto found = RtlLookupFunctionEntry(context.Rip, &found_base, nullptr);
        if (found != &function || found_base != image_base) ++failures;

        void* handler_data = nullptr;
        DWORD64 establisher = 0;
        RtlVirtualUnwind(UNW_FLAG_NHANDLER, image_base, context.Rip, &function,
            &context, &handler_data, &establisher, nullptr);
        const bool okay = context.Rip == return_address && context.Rsp == entry_rsp + 8
            && context.Rbx == saved_rbx && context.Rdi == saved_rdi;
        std::printf("offset %u %s\n", offset, okay ? "PASS" : "FAIL");
        if (!okay) ++failures;
    }

    if (!RtlDeleteFunctionTable(&function)) ++failures;
    if (!VirtualFree(image, 0, MEM_RELEASE)) ++failures;
    std::printf("8 removal unwind positions, failures=%u\n", failures);
    return failures ? 1 : 0;
}
