#pragma once

#include "information-battle-message-entry-plan.h"

namespace information::royal_record::entry {

namespace jumps = information::battle::message_entry;
enum class Kind { enable, disable };
struct Spec final {
    uint32_t rva, end_rva, unwind_rva;
    unsigned prefix_bytes, unwind_bytes, jump_slot, projected_bytes;
    std::array<unsigned char, 15> prefix;
    std::array<unsigned char, 32> unwind;
    std::array<unsigned char, 20> projected;
};
inline constexpr Spec kEnable{
    0xa5e0e0, 0xa5e90e, 0x1e8c7f8, 14, 28, 0x20, 20,
    {{0x48,0x89,0x5c,0x24,0x10,0x48,0x89,0x74,0x24,0x18,0x55,0x57,0x41,0x56}},
    {{0x11,0x1d,0x09,0x00,0x1d,0x64,0x42,0x00,0x1d,0x34,0x41,0x00,0x1d,0x01,0x3c,0x00,
      0x0e,0xe0,0x0c,0x70,0x0b,0x50,0x00,0x00,0x9c,0x4d,0xa3,0x01}},
    // Original RSP+8 remains unused. Three pushes move that slot to RSP+0x20.
    {{0x01,0x0e,0x07,0x00,0x0e,0x64,0x06,0x00,0x0e,0x34,0x05,0x00,
      0x0e,0xe0,0x0c,0x70,0x0b,0x50,0x00,0x00}}
};
inline constexpr Spec kDisable{
    0xa5e910, 0xa5eea9, 0x1e8c84c, 15, 32, 0x20, 16,
    {{0x48,0x89,0x5c,0x24,0x08,0x48,0x89,0x74,0x24,0x10,0x48,0x89,0x7c,0x24,0x18}},
    {{0x11,0x24,0x0b,0x00,0x24,0xe4,0x3d,0x00,0x24,0x74,0x3c,0x00,0x24,0x64,0x3b,0x00,
      0x24,0x34,0x3a,0x00,0x24,0x01,0x38,0x00,0x15,0x50,0x00,0x00,0x9c,0x4d,0xa3,0x01}},
    // The next original instruction saves R14 into +0x20 after continuation.
    // The trampoline consumes this slot before that original store executes.
    {{0x01,0x0f,0x06,0x00,0x0f,0x74,0x03,0x00,0x0a,0x64,0x02,0x00,0x05,0x34,0x01,0x00}}
};
inline const Spec& spec(Kind kind) noexcept {
    return kind == Kind::enable ? kEnable : kDisable;
}
struct RuntimeFunction final { uint32_t begin = 0, end = 0, unwind = 64; };
struct Plan final {
    std::array<unsigned char, 96> image{};
    std::array<unsigned char, 15> patch{};
    RuntimeFunction runtime{};
};
inline bool prepare(Kind kind, const std::array<unsigned char,15>& prefix,
                    const std::array<unsigned char,32>& unwind,
                    uintptr_t entry, uintptr_t hook, Plan& output) noexcept {
    if (kind != Kind::enable && kind != Kind::disable) return false;
    const auto& source = spec(kind);
    if (std::memcmp(prefix.data(), source.prefix.data(), source.prefix_bytes)
        || unwind != source.unwind
        || !jumps::detail::valid_code_address(entry, source.end_rva - source.rva)
        || !jumps::detail::valid_code_address(hook)
        || (hook >= entry && hook < entry + source.end_rva - source.rva)) return false;
    Plan candidate{};
    std::memcpy(candidate.image.data(), prefix.data(), source.prefix_bytes);
    jumps::detail::home_slot_jump(candidate.image.data() + source.prefix_bytes,
                                  source.jump_slot, entry + source.prefix_bytes);
    std::memcpy(candidate.image.data() + 64, source.projected.data(), source.projected_bytes);
    candidate.patch.fill(0x90);
    jumps::detail::absolute_jump(candidate.patch.data(), hook);
    candidate.runtime.end = source.prefix_bytes + jumps::kHomeSlotJumpBytes;
    output = candidate;
    return true;
}
} // namespace information::royal_record::entry
