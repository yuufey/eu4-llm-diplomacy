#ifndef INFORMATION_COUNTRY_MODIFIER_ENTRY_PLAN_H
#define INFORMATION_COUNTRY_MODIFIER_ENTRY_PLAN_H

#include "information-battle-message-entry-plan.h"

// Ordinary B23 PE metadata in 315 modifier-entry-bytes.json. The first native
// runtime-function row covers [3283f0,3283ff), not the whole Ghidra body.
namespace information::country_modifier::entry {

namespace jumps = information::battle::message_entry;
inline constexpr std::uint32_t kEntryRva = 0x3283f0;
inline constexpr std::uint32_t kSourceEndRva = 0x3283ff;
inline constexpr std::uint32_t kUnwindRva = 0x1df67a8;
inline constexpr std::size_t kPatchBytes = 15;
inline constexpr std::size_t kUnwindOffset = 64;
inline constexpr std::array<unsigned char, kPatchBytes> kPrefix{{
    0x40,0x56,0x41,0x56,0x48,0x83,0xec,0x28,
    0x48,0x8b,0x42,0x30,0x48,0x8b,0xf2,
}};
inline constexpr std::array<unsigned char, 12> kUnwind{{
    0x01,0x08,0x03,0x00,0x08,0x42,0x04,0xe0,0x02,0x60,0x00,0x00,
}};

struct RuntimeFunction final {
    std::uint32_t begin = 0;
    std::uint32_t end = kPatchBytes + jumps::kHomeSlotJumpBytes;
    std::uint32_t unwind = kUnwindOffset;
};
static_assert(sizeof(RuntimeFunction) == 12);

struct Plan final {
    std::array<unsigned char, 80> image{};
    std::array<unsigned char, kPatchBytes> patch{};
    RuntimeFunction runtime{};
};

inline bool prepare(const std::array<unsigned char, kPatchBytes>& prefix,
                    const std::array<unsigned char, 12>& unwind,
                    std::uintptr_t entry, std::uintptr_t hook, Plan& output) noexcept {
    if (prefix != kPrefix || unwind != kUnwind || entry == hook
        || !jumps::detail::valid_code_address(entry, kPatchBytes)
        || !jumps::detail::valid_code_address(hook)) return false;
    Plan candidate{};
    std::memcpy(candidate.image.data(), prefix.data(), prefix.size());
    // RSI/R14 pushes plus0x28 allocation consume0x38. Use original RSP+8,
    // a volatile home slot. RBX is saved later to original RSP+0x10.
    jumps::detail::home_slot_jump(candidate.image.data() + kPatchBytes,
                                  0x40, entry + kPatchBytes);
    std::memcpy(candidate.image.data() + kUnwindOffset, unwind.data(), unwind.size());
    candidate.patch.fill(0x90);
    jumps::detail::absolute_jump(candidate.patch.data(), hook);
    output = candidate;
    return true;
}

} // namespace information::country_modifier::entry
#endif
