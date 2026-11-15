#ifndef INFORMATION_BATTLE_INDEPENDENT_LINE_PLAN_H
#define INFORMATION_BATTLE_INDEPENDENT_LINE_PLAN_H
// Fixed B23 ordinary PE prefix. The existing retained ABI contract supplies
// the String32/key/104-byte argument/count calling convention.
#include "information-battle-title-query-plan.h"
namespace information::battle::independent_line_plan {
inline constexpr std::uintptr_t kFormatterRva = 0x14b33a0;
inline constexpr std::array<unsigned char, 32> kFormatterPrefix{{0x44,0x89,0x4c,0x24,0x20,0x4c,0x89,0x44,0x24,0x18,0x55,0x56,0x57,0x41,0x54,0x41,0x55,0x41,0x56,0x41,0x57,0x48,0x83,0xec,0x30,0x48,0x8d,0x6c,0x24,0x30,0x48,0x8b}};
template <typename Reader>
bool guard(Reader& reader, std::uintptr_t base, std::size_t image_size) noexcept {
    constexpr std::uintptr_t maximum = UINT64_C(0x800000000000);
    if (base < 0x10000 || image_size > maximum || base > maximum - image_size
            || image_size < kFormatterRva + kFormatterPrefix.size()) return false;
    std::array<unsigned char, kFormatterPrefix.size()> actual{};
    return reader.read(base + kFormatterRva, actual.data(), actual.size())
        && actual == kFormatterPrefix;
}
}
#endif
