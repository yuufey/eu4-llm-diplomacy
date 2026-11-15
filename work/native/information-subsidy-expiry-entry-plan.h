#pragma once
#include "information-battle-message-entry-plan.h"

namespace information::subsidy_expiry::entry {
namespace jumps = information::battle::message_entry;
inline constexpr std::uint32_t kEntryRva = 0xa62df0;
inline constexpr std::uint32_t kSourceEndRva = 0xa62f23;
inline constexpr std::uint32_t kUnwindRva = 0x1e8cb74;
inline constexpr std::array<unsigned char,14> kPrefix{{
    0x40,0x53,0x48,0x83,0xec,0x20,0x48,0x8b,0xd9,0x48,0x8d,0x54,0x24,0x30}};
inline constexpr std::array<unsigned char,8> kSourceUnwind{{0x11,0x06,0x02,0x00,0x06,0x32,0x02,0x30}};
struct RuntimeFunction final { std::uint32_t begin = 0, end = 0, unwind = 64; };
struct Plan final {
    std::array<unsigned char,80> image{};
    std::array<unsigned char,14> patch{};
    RuntimeFunction runtime{};
};

inline bool prepare(const std::array<unsigned char,14>& prefix,
                    const std::array<unsigned char,8>& unwind,
                    std::uintptr_t entry, std::uintptr_t hook, Plan& output) noexcept {
    if (prefix != kPrefix || unwind != kSourceUnwind || entry < kEntryRva
        || !jumps::detail::valid_code_address(entry, kSourceEndRva - kEntryRva)
        || !jumps::detail::valid_code_address(hook)
        || (hook >= entry && hook < entry + kSourceEndRva - kEntryRva)) return false;
    Plan candidate{};
    std::memcpy(candidate.image.data(), prefix.data(), prefix.size());
    // Native RDX points to original RSP+8. Use original RSP+16 for the jump.
    jumps::detail::home_slot_jump(candidate.image.data() + prefix.size(), 0x38, entry + prefix.size());
    std::memcpy(candidate.image.data() + 64, unwind.data(), unwind.size());
    // The copied prefix has no native cleanup region or associated handler data.
    candidate.image[64] = 0x01;
    candidate.patch.fill(0x90);
    jumps::detail::absolute_jump(candidate.patch.data(), hook);
    candidate.runtime.end = prefix.size() + jumps::kHomeSlotJumpBytes;
    output = candidate;
    return true;
}
} // namespace information::subsidy_expiry::entry
