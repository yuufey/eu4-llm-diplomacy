#pragma once
#include "information-battle-message-entry-plan.h"

namespace information::truce_expiry::entry {
namespace jumps = information::battle::message_entry;
inline constexpr std::uint32_t kEntryRva = 0xa67420;
inline constexpr std::uint32_t kSourceEndRva = 0xa68447;
inline constexpr std::uint32_t kUnwindRva = 0x1e8cf6c;
inline constexpr std::array<unsigned char, 14> kPrefix{{
    0x48,0x89,0x5c,0x24,0x18,0x55,0x56,0x57,0x41,0x54,0x41,0x55,0x41,0x56}};
inline constexpr std::array<unsigned char, 32> kSourceUnwind{{
    0x11,0x1c,0x0b,0x00,0x1c,0x34,0x36,0x00,0x1c,0x01,0x2c,0x00,0x10,0xf0,0x0e,0xe0,
    0x0c,0xd0,0x0a,0xc0,0x08,0x70,0x07,0x60,0x06,0x50,0x00,0x00,0x9c,0x4d,0xa3,0x01}};
inline constexpr std::array<unsigned char, 20> kProjectedUnwind{{
    0x01,0x0e,0x08,0x00,0x0e,0x34,0x09,0x00,0x0e,0xe0,0x0c,0xd0,0x0a,0xc0,0x08,0x70,
    0x07,0x60,0x06,0x50}};
struct RuntimeFunction final { std::uint32_t begin = 0, end = 0, unwind = 64; };
struct Plan final {
    std::array<unsigned char, 96> image{};
    std::array<unsigned char, 14> patch{};
    RuntimeFunction runtime{};
};

inline bool prepare(const std::array<unsigned char, 14>& prefix,
                    const std::array<unsigned char, 32>& unwind,
                    std::uintptr_t entry, std::uintptr_t hook, Plan& output) noexcept {
    if (prefix != kPrefix || unwind != kSourceUnwind || entry < kEntryRva
        || !jumps::detail::valid_code_address(entry, kSourceEndRva - kEntryRva)
        || !jumps::detail::valid_code_address(hook)
        || (hook >= entry && hook < entry + kSourceEndRva - kEntryRva)) return false;
    Plan candidate{};
    std::memcpy(candidate.image.data(), prefix.data(), prefix.size());
    // Six PUSH instructions leave original RSP+8 at current RSP+0x38.
    jumps::detail::home_slot_jump(candidate.image.data() + prefix.size(), 0x38, entry + prefix.size());
    std::memcpy(candidate.image.data() + 64, kProjectedUnwind.data(), kProjectedUnwind.size());
    candidate.patch.fill(0x90);
    jumps::detail::absolute_jump(candidate.patch.data(), hook);
    candidate.runtime.end = prefix.size() + jumps::kHomeSlotJumpBytes;
    output = candidate;
    return true;
}
} // namespace information::truce_expiry::entry
