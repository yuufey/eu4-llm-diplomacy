#pragma once
#include "information-battle-message-entry-plan.h"

namespace information::claim_expiry::entry {
namespace jumps = information::battle::message_entry;
inline constexpr std::uint32_t kEntryRva = 0xa06cc0;
inline constexpr std::uint32_t kSourceEndRva = 0xa070ff;
inline constexpr std::uint32_t kUnwindRva = 0x1e8648c;
inline constexpr std::array<unsigned char, 15> kPrefix{{
    0x48,0x89,0x5c,0x24,0x18,0x48,0x89,0x74,0x24,0x20,0x48,0x89,0x54,0x24,0x10}};
inline constexpr std::array<unsigned char, 32> kSourceUnwind{{
    0x11,0x26,0x0b,0x00,0x26,0x64,0x53,0x00,0x26,0x34,0x52,0x00,0x26,0x01,0x4a,0x00,
    0x17,0xf0,0x15,0xe0,0x13,0xc0,0x11,0x70,0x10,0x50,0x00,0x00,0x9c,0x4d,0xa3,0x01}};
inline constexpr std::array<unsigned char, 12> kProjectedUnwind{{
    0x01,0x0f,0x04,0x00,0x0f,0x64,0x04,0x00,0x0f,0x34,0x03,0x00}};
struct RuntimeFunction final { std::uint32_t begin = 0, end = 0, unwind = 64; };
struct Plan final {
    std::array<unsigned char, 80> image{};
    std::array<unsigned char, 15> patch{};
    RuntimeFunction runtime{};
};

inline bool prepare(const std::array<unsigned char, 15>& prefix,
                    const std::array<unsigned char, 32>& unwind,
                    std::uintptr_t entry, std::uintptr_t hook, Plan& output) noexcept {
    if (prefix != kPrefix || unwind != kSourceUnwind || entry < kEntryRva
        || !jumps::detail::valid_code_address(entry, kSourceEndRva - kEntryRva)
        || !jumps::detail::valid_code_address(hook)
        || (hook >= entry && hook < entry + kSourceEndRva - kEntryRva)) return false;
    Plan candidate{};
    std::memcpy(candidate.image.data(), prefix.data(), prefix.size());
    // Original RSP+8 is free, while +16/+24/+32 hold native saved arguments/registers.
    jumps::detail::home_slot_jump(candidate.image.data() + prefix.size(), 8, entry + prefix.size());
    std::memcpy(candidate.image.data() + 64, kProjectedUnwind.data(), kProjectedUnwind.size());
    candidate.patch.fill(0x90);
    jumps::detail::absolute_jump(candidate.patch.data(), hook);
    candidate.runtime.end = prefix.size() + jumps::kHomeSlotJumpBytes;
    output = candidate;
    return true;
}
} // namespace information::claim_expiry::entry
