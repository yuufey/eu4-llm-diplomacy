#pragma once

#include "information-battle-message-entry-plan.h"

namespace information::mission_availability::entry {

namespace jumps = information::battle::message_entry;
constexpr uint32_t kEntryRva = 0x8d4e00;
constexpr uint32_t kSourceEndRva = 0x8d5061;
constexpr uint32_t kUnwindRva = 0x1e6ee14;
constexpr size_t kPatchBytes = 15;
constexpr size_t kUnwindOffset = 64;
constexpr std::array<unsigned char, kPatchBytes> kPrefix{{
    0x48,0x89,0x5c,0x24,0x08,0x48,0x89,0x74,0x24,0x10,0x48,0x89,0x7c,0x24,0x18,
}};
constexpr std::array<unsigned char, 28> kSourceUnwind{{
    0x11,0x1c,0x09,0x00,0x1c,0x74,0x22,0x00,0x1c,0x64,0x21,0x00,0x1c,0x34,
    0x20,0x00,0x1c,0x01,0x1e,0x00,0x10,0x50,0x00,0x00,0x9c,0x4d,0xa3,0x01,
}};
// The copied prefix only saves RBX/RSI/RDI in original caller home slots.
// It has no stack allocation, frame pointer or language-specific handler.
constexpr std::array<unsigned char, 16> kProjectedUnwind{{
    0x01,0x0f,0x06,0x00,0x0f,0x74,0x03,0x00,0x0a,0x64,0x02,0x00,0x05,0x34,0x01,0x00,
}};
struct RuntimeFunction final {
    uint32_t begin = 0, end = kPatchBytes + jumps::kHomeSlotJumpBytes, unwind = kUnwindOffset;
};
struct Plan final {
    std::array<unsigned char, 80> image{};
    std::array<unsigned char, kPatchBytes> patch{};
    RuntimeFunction runtime{};
};

inline bool prepare(const std::array<unsigned char, kPatchBytes>& prefix,
                    const std::array<unsigned char, 28>& unwind,
                    uintptr_t entry, uintptr_t hook, Plan& output) noexcept {
    if (prefix != kPrefix || unwind != kSourceUnwind || entry == hook
        || !jumps::detail::valid_code_address(entry, kPatchBytes)
        || !jumps::detail::valid_code_address(hook)) return false;
    Plan candidate{};
    std::memcpy(candidate.image.data(), prefix.data(), prefix.size());
    // Original RSP+0x20 is the unused fourth home slot for this two-argument
    // predicate. The first three slots contain the copied nonvolatile saves.
    jumps::detail::home_slot_jump(candidate.image.data()+kPatchBytes, 0x20, entry+kPatchBytes);
    std::memcpy(candidate.image.data()+kUnwindOffset, kProjectedUnwind.data(), kProjectedUnwind.size());
    candidate.patch.fill(0x90);
    jumps::detail::absolute_jump(candidate.patch.data(), hook);
    output = candidate;
    return true;
}

} // namespace information::mission_availability::entry
