#pragma once

#include "information-battle-message-entry-plan.h"

namespace information::directed_record::entry {
namespace jumps = information::battle::message_entry;
enum class Kind : unsigned { guarantee_enable, guarantee_disable, military_enable, military_disable };
struct Spec final {
    uint32_t rva, end_rva;
    unsigned prefix_bytes;
    bool relocate_game_load;
    std::array<unsigned char,17> prefix;
};
inline constexpr uint32_t kUnwindRva = 0x1dc9790;
inline constexpr uint32_t kGamePointerRva = 0x233fe58;
inline constexpr std::array<unsigned char,8> kUnwind{{0x01,0x06,0x02,0x00,0x06,0x32,0x02,0x30}};
inline constexpr std::array<Spec,4> kSpecs{{
    {0xa5f0a0,0xa5f135,17,false,
     {{0x40,0x53,0x48,0x83,0xec,0x20,0x48,0x8b,0x41,0x10,0x48,0x8b,0xd9,0x4c,0x8b,0x51,0x18}}},
    {0xa5f140,0xa5f1e9,16,true,
     {{0x40,0x53,0x48,0x83,0xec,0x20,0x48,0x8b,0xd9,0x48,0x8b,0x0d,0x08,0x0d,0x8e,0x01}}},
    {0xa700e0,0xa70175,17,false,
     {{0x40,0x53,0x48,0x83,0xec,0x20,0x48,0x8b,0x41,0x10,0x48,0x8b,0xd9,0x4c,0x8b,0x51,0x18}}},
    {0xa70180,0xa70229,16,true,
     {{0x40,0x53,0x48,0x83,0xec,0x20,0x48,0x8b,0xd9,0x48,0x8b,0x0d,0xc8,0xfc,0x8c,0x01}}},
}};
struct RuntimeFunction final { uint32_t begin = 0, end = 0, unwind = 64; };
struct Plan final {
    std::array<unsigned char,80> image{};
    std::array<unsigned char,17> patch{};
    RuntimeFunction runtime{};
};

inline bool prepare(Kind kind, const std::array<unsigned char,17>& prefix,
                    const std::array<unsigned char,8>& unwind,
                    uintptr_t entry, uintptr_t hook, Plan& output) noexcept {
    const unsigned index = static_cast<unsigned>(kind);
    if (index >= kSpecs.size()) return false;
    const auto& source = kSpecs[index];
    if (entry < source.rva || unwind != kUnwind
        || std::memcmp(prefix.data(),source.prefix.data(),source.prefix_bytes)
        || !jumps::detail::valid_code_address(entry,source.end_rva-source.rva)
        || !jumps::detail::valid_code_address(hook)
        || (hook >= entry && hook < entry+source.end_rva-source.rva)) return false;
    Plan candidate{};
    unsigned copied_bytes = source.prefix_bytes;
    if (source.relocate_game_load) {
        const auto target = entry-source.rva+kGamePointerRva;
        if (!jumps::detail::valid_code_address(target,8)) return false;
        std::memcpy(candidate.image.data(),prefix.data(),9);
        // Replace the fixed RIP-relative MOV RCX,[game] with two MOVs that
        // preserve the same final RCX and flags at the original continuation.
        candidate.image[9] = 0x48;
        candidate.image[10] = 0xb9;
        std::memcpy(candidate.image.data()+11,&target,sizeof(target));
        candidate.image[19] = 0x48;
        candidate.image[20] = 0x8b;
        candidate.image[21] = 0x09;
        copied_bytes = 22;
    } else {
        std::memcpy(candidate.image.data(),prefix.data(),source.prefix_bytes);
    }
    // PUSH RBX and SUB RSP,0x20 move original RSP+8 to current RSP+0x30.
    // Neither source uses that caller-owned home as a nonvolatile save.
    jumps::detail::home_slot_jump(candidate.image.data()+copied_bytes,0x30,entry+source.prefix_bytes);
    std::memcpy(candidate.image.data()+64,kUnwind.data(),kUnwind.size());
    candidate.patch.fill(0x90);
    jumps::detail::absolute_jump(candidate.patch.data(),hook);
    candidate.runtime.end = copied_bytes+jumps::kHomeSlotJumpBytes;
    output = candidate;
    return true;
}
} // namespace information::directed_record::entry
