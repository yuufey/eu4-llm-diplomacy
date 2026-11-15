#ifndef INFORMATION_COUNTRY_MODIFIER_REMOVE_ENTRY_PLAN_H
#define INFORMATION_COUNTRY_MODIFIER_REMOVE_ENTRY_PLAN_H

#include "information-battle-message-entry-plan.h"

// B23 ordinary PE removal entry and metadata, recorded in317 remove-callers.
namespace information::country_modifier::removal_entry {

namespace jumps = information::battle::message_entry;
inline constexpr std::uint32_t kEntryRva = 0x328710;
inline constexpr std::uint32_t kSourceEndRva = 0x32885d;
inline constexpr std::uint32_t kUnwindRva = 0x1dc9798;
inline constexpr std::size_t kPatchBytes = 14;
inline constexpr std::size_t kUnwindOffset = 64;
inline constexpr std::array<unsigned char, kPatchBytes> kPrefix{{
    0x48,0x89,0x5c,0x24,0x08,0x57,0x48,0x83,0xec,0x20,0x48,0x8b,0x42,0x30,
}};
inline constexpr std::array<unsigned char, 12> kUnwind{{
    0x01,0x0a,0x04,0x00,0x0a,0x34,0x06,0x00,0x0a,0x32,0x06,0x70,
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
    // PUSH RDI and0x20 allocation consume0x28. RBX occupies original RSP+8.
    // Use original RSP+16 as the volatile continuation slot, displaced0x38.
    jumps::detail::home_slot_jump(candidate.image.data() + kPatchBytes, 0x38, entry + kPatchBytes);
    std::memcpy(candidate.image.data() + kUnwindOffset, unwind.data(), unwind.size());
    candidate.patch.fill(0x90);
    jumps::detail::absolute_jump(candidate.patch.data(), hook);
    output = candidate;
    return true;
}

} // namespace information::country_modifier::removal_entry
#endif
