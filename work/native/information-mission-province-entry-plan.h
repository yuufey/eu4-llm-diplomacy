#pragma once

#include "information-battle-message-entry-plan.h"

namespace information::mission_province_condition::entry {

namespace jumps = information::battle::message_entry;
constexpr uint32_t kEntryRva = 0xbe9300;
constexpr uint32_t kSourceEndRva = 0xbe96b0;
constexpr uint32_t kUnwindRva = 0x1ea5bc4;
constexpr size_t kPatchBytes = 15;
constexpr size_t kUnwindOffset = 64;
constexpr std::array<unsigned char, kPatchBytes> kPrefix{{
    0x48,0x89,0x5c,0x24,0x08,0x48,0x89,0x74,0x24,0x18,0x48,0x89,0x7c,0x24,0x20,
}};
constexpr std::array<unsigned char, 28> kSourceUnwind{{
    0x11,0x1c,0x09,0x00,0x1c,0x74,0x35,0x00,0x1c,0x64,0x34,0x00,0x1c,0x34,
    0x32,0x00,0x1c,0x01,0x30,0x00,0x10,0x50,0x00,0x00,0x9c,0x4d,0xa3,0x01,
}};
// The copied prefix only saves RBX/RSI/RDI in original caller home slots.
// It has no stack allocation, frame pointer or language-specific handler.
constexpr std::array<unsigned char, 16> kProjectedUnwind{{
    0x01,0x0f,0x06,0x00,0x0f,0x74,0x04,0x00,0x0a,0x64,0x03,0x00,0x05,0x34,0x01,0x00,
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
    if (prefix != kPrefix || unwind != kSourceUnwind
        || !jumps::detail::valid_code_address(entry, kPatchBytes)
        || !jumps::detail::valid_code_address(hook)
        || (hook >= entry && hook-entry < kSourceEndRva-kEntryRva)) return false;
    Plan candidate{};
    std::memcpy(candidate.image.data(), prefix.data(), prefix.size());
    // Original RSP+0x10 is the unused second home slot for this two-argument
    // predicate. The other three home slots contain the copied nonvolatile saves.
    jumps::detail::home_slot_jump(candidate.image.data()+kPatchBytes, 0x10, entry+kPatchBytes);
    std::memcpy(candidate.image.data()+kUnwindOffset, kProjectedUnwind.data(), kProjectedUnwind.size());
    candidate.patch.fill(0x90);
    jumps::detail::absolute_jump(candidate.patch.data(), hook);
    output = candidate;
    return true;
}

} // namespace information::mission_province_condition::entry
