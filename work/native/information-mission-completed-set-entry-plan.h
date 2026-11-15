#pragma once

#include "information-battle-message-entry-plan.h"

namespace information::mission_completed_set::entry {

namespace jumps = information::battle::message_entry;
constexpr uint32_t kEntryRva = 0x429b00;
constexpr uint32_t kSourceEndRva = 0x429dfa;
constexpr uint32_t kUnwindRva = 0x1e0a3e0;
constexpr size_t kPatchBytes = 15, kUnwindOffset = 64;
constexpr uint32_t kCommandReturnRva = 0x8d7b16, kEffectReturnRva = 0x6b94a6;
enum class Path { none, command, effect };

inline Path classify(uintptr_t image_base, uintptr_t caller) noexcept {
    if (caller == image_base+kCommandReturnRva) return Path::command;
    if (caller == image_base+kEffectReturnRva) return Path::effect;
    return Path::none;
}

constexpr std::array<unsigned char, kPatchBytes> kPrefix{{
    0x48,0x89,0x5c,0x24,0x08,0x48,0x89,0x6c,0x24,0x10,0x48,0x89,0x74,0x24,0x18,
}};
constexpr std::array<unsigned char, 32> kSourceUnwind{{
    0x11,0x1e,0x0c,0x00,0x1e,0x74,0x0d,0x00,0x1e,0x64,0x0c,0x00,0x1e,0x54,0x0b,0x00,
    0x1e,0x34,0x0a,0x00,0x1e,0x52,0x1a,0xf0,0x18,0xe0,0x16,0xc0,0x9c,0x4d,0xa3,0x01,
}};
constexpr std::array<unsigned char, 16> kProjectedUnwind{{
    0x01,0x0f,0x06,0x00,0x0f,0x64,0x03,0x00,0x0a,0x54,0x02,0x00,0x05,0x34,0x01,0x00,
}};
struct RuntimeFunction final {
    uint32_t begin = 0, end = kPatchBytes+jumps::kHomeSlotJumpBytes, unwind = kUnwindOffset;
};
struct Plan final {
    std::array<unsigned char, 80> image{};
    std::array<unsigned char, kPatchBytes> patch{};
    RuntimeFunction runtime{};
};

inline bool prepare(const std::array<unsigned char, kPatchBytes>& prefix,
                    const std::array<unsigned char, 32>& unwind,
                    uintptr_t entry, uintptr_t hook, Plan& output) noexcept {
    if (prefix != kPrefix || unwind != kSourceUnwind || entry == hook
        || !jumps::detail::valid_code_address(entry, kPatchBytes)
        || !jumps::detail::valid_code_address(hook)) return false;
    Plan candidate{};
    std::memcpy(candidate.image.data(), prefix.data(), prefix.size());
    // The continuation immediately saves RDI at original RSP+0x20. Its prior
    // contents are unused. All four argument registers stay intact.
    jumps::detail::home_slot_jump(candidate.image.data()+kPatchBytes, 0x20, entry+kPatchBytes);
    std::memcpy(candidate.image.data()+kUnwindOffset, kProjectedUnwind.data(), kProjectedUnwind.size());
    candidate.patch.fill(0x90);
    jumps::detail::absolute_jump(candidate.patch.data(), hook);
    output = candidate;
    return true;
}

} // namespace information::mission_completed_set::entry
