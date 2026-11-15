#pragma once

#include "information-battle-message-entry-plan.h"

namespace information::rival_record::entry {

namespace jumps = information::battle::message_entry;
enum class Kind { add, remove };
struct Spec final {
    uint32_t rva, end_rva, unwind_rva;
    unsigned unwind_bytes, jump_slot, projected_bytes;
    std::array<unsigned char, 15> prefix;
    std::array<unsigned char, 28> unwind;
    std::array<unsigned char, 16> projected;
};
inline constexpr Spec kAdd{
    0x3d2350,0x3d25c5,0x1e03010,28,0x20,16,
    {{0x48,0x89,0x5c,0x24,0x08,0x48,0x89,0x6c,0x24,0x10,0x48,0x89,0x74,0x24,0x18}},
    {{0x11,0x1a,0x0a,0x00,0x1a,0x74,0x11,0x00,0x1a,0x64,0x10,0x00,0x1a,0x54,0x0f,0x00,
      0x1a,0x34,0x0e,0x00,0x1a,0xb2,0x16,0xe0,0x9c,0x4d,0xa3,0x01}},
    {{0x01,0x0f,0x06,0x00,0x0f,0x64,0x03,0x00,0x0a,0x54,0x02,0x00,0x05,0x34,0x01,0x00}}
};
inline constexpr Spec kRemove{
    0x3d25d0,0x3d25f6,0x1e03044,12,0x60,12,
    {{0x40,0x53,0x56,0x41,0x56,0x48,0x83,0xec,0x40,0x48,0x8b,0xf1,0x48,0x8b,0xda}},
    {{0x01,0x09,0x04,0x00,0x09,0x72,0x05,0xe0,0x03,0x60,0x02,0x30}},
    {{0x01,0x09,0x04,0x00,0x09,0x72,0x05,0xe0,0x03,0x60,0x02,0x30}}
};
inline const Spec& spec(Kind kind) noexcept { return kind == Kind::add ? kAdd : kRemove; }
struct RuntimeFunction final { uint32_t begin = 0, end = 0, unwind = 64; };
struct Plan final {
    std::array<unsigned char, 96> image{};
    std::array<unsigned char, 15> patch{};
    RuntimeFunction runtime{};
};
inline bool prepare(Kind kind, const std::array<unsigned char,15>& prefix,
                    const std::array<unsigned char,28>& unwind,
                    uintptr_t entry, uintptr_t hook, Plan& output) noexcept {
    if (kind != Kind::add && kind != Kind::remove) return false;
    const auto& source = spec(kind);
    if (prefix != source.prefix || unwind != source.unwind || entry == hook
        || !jumps::detail::valid_code_address(entry,prefix.size())
        || !jumps::detail::valid_code_address(hook)) return false;
    Plan candidate{};
    std::memcpy(candidate.image.data(),prefix.data(),prefix.size());
    // Add has saved three registers in +8/+16/+24. Its +32 home is written
    // by the next original instruction. Remove's +96 is original RSP+8.
    jumps::detail::home_slot_jump(candidate.image.data()+prefix.size(),source.jump_slot,entry+prefix.size());
    std::memcpy(candidate.image.data()+64,source.projected.data(),source.projected_bytes);
    candidate.patch.fill(0x90);
    jumps::detail::absolute_jump(candidate.patch.data(),hook);
    candidate.runtime.end = static_cast<uint32_t>(prefix.size())+jumps::kHomeSlotJumpBytes;
    output = candidate;
    return true;
}
} // namespace information::rival_record::entry
