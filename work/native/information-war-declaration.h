#ifndef INFORMATION_WAR_DECLARATION_H
#define INFORMATION_WAR_DECLARATION_H

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include "information-battle-message-entry-plan.h"

namespace information::war_declaration {

constexpr std::size_t kMaxReferences = 32;
struct References final {
    std::array<std::uintptr_t, kMaxReferences> values{};
    std::array<std::uint64_t, kMaxReferences> births{};
    unsigned count = 0;
    bool complete = false;
};
enum class Outcome : unsigned char { unreadable, unchanged, single_added, ambiguous };
struct Difference final {
    Outcome outcome = Outcome::unreadable;
    std::uintptr_t reference = 0;
    std::uint64_t birth = 0;
};

inline bool valid(const References& value) noexcept {
    if (!value.complete || value.count > kMaxReferences) return false;
    for (unsigned index = 0; index < value.count; ++index) {
        if (!value.values[index] || std::find(value.values.begin(), value.values.begin() + index,
            value.values[index]) != value.values.begin() + index) return false;
    }
    return true;
}

// These are private, short-lived association values. No pointer is exported.
inline Difference difference(const References& before, const References& after) noexcept {
    if (!valid(before) || !valid(after)) return {};
    Difference result{Outcome::unchanged, 0};
    for (unsigned index = 0; index < after.count; ++index) {
        const auto reference = after.values[index];
        bool same = false;
        for (unsigned prior = 0; prior < before.count; ++prior)
            same = same || (before.values[prior] == reference
                && before.births[prior] == after.births[index]);
        if (same) continue;
        if (result.reference) return {Outcome::ambiguous, 0};
        result = {Outcome::single_added, reference, after.births[index]};
    }
    return result;
}

namespace entry {
namespace jumps = information::battle::message_entry;
constexpr uint32_t kRva = 0x5012c0, kEndRva = 0x502ea8, kUnwindRva = 0x1e24758;
constexpr unsigned kPrefixBytes = 15, kUnwindBytes = 28;
inline constexpr std::array<unsigned char,17> kPrefix{{
    0x48,0x89,0x4c,0x24,0x08,0x55,0x53,0x56,0x57,0x41,0x54,0x41,0x55,0x41,0x56}};
inline constexpr std::array<unsigned char,40> kUnwind{{
    0x11,0x20,0x0a,0x00,0x20,0x01,0xf5,0x00,0x11,0xf0,0x0f,0xe0,0x0d,0xd0,0x0b,0xc0,
    0x09,0x70,0x08,0x60,0x07,0x30,0x06,0x50,0x9c,0x4d,0xa3,0x01}};
inline constexpr std::array<unsigned char,20> kProjected{{
    0x01,0x0f,0x07,0x00,0x0f,0xe0,0x0d,0xd0,0x0b,0xc0,0x09,0x70,0x08,0x60,0x07,0x30,
    0x06,0x50,0x00,0x00}};
struct RuntimeFunction final { uint32_t begin = 0, end = 0, unwind = 64; };
struct Plan final {
    std::array<unsigned char,96> image{};
    std::array<unsigned char,17> patch{};
    RuntimeFunction runtime{};
};
inline bool prepare(const std::array<unsigned char,17>& prefix,
                    const std::array<unsigned char,40>& unwind,
                    uintptr_t address,uintptr_t hook,Plan& output) noexcept {
    if (address < kRva || unwind != kUnwind
        || std::memcmp(prefix.data(),kPrefix.data(),kPrefixBytes)
        || !jumps::detail::valid_code_address(address,kEndRva-kRva)
        || !jumps::detail::valid_code_address(hook)
        || (hook >= address && hook < address+kEndRva-kRva)) return false;
    Plan candidate{};
    std::memcpy(candidate.image.data(),prefix.data(),kPrefixBytes);
    // Seven pushes leave original RSP+16 at +0x48. The handler overwrites
    // that scratch home before reading it. Its saved RCX at +8 is preserved.
    jumps::detail::home_slot_jump(candidate.image.data()+kPrefixBytes,0x48,address+kPrefixBytes);
    std::memcpy(candidate.image.data()+64,kProjected.data(),kProjected.size());
    candidate.patch.fill(0x90);
    jumps::detail::absolute_jump(candidate.patch.data(),hook);
    candidate.runtime.end = kPrefixBytes+jumps::kHomeSlotJumpBytes;
    output = candidate;
    return true;
}
} // namespace entry

namespace birth_entry {
namespace jumps = information::battle::message_entry;
constexpr uint32_t kRva = 0xd85820, kEndRva = 0xd85aa9, kUnwindRva = 0x1ebf0bc;
constexpr unsigned kPrefixBytes = 15, kUnwindBytes = 20;
inline constexpr std::array<unsigned char,17> kPrefix{{
    0x48,0x89,0x5c,0x24,0x18,0x48,0x89,0x74,0x24,0x20,0x48,0x89,0x4c,0x24,0x08}};
inline constexpr std::array<unsigned char,40> kUnwind{{
    0x11,0x14,0x06,0x00,0x14,0x64,0x09,0x00,0x14,0x34,0x08,0x00,0x14,0x32,0x10,0x70,
    0x9c,0x4d,0xa3,0x01}};
inline constexpr std::array<unsigned char,12> kProjected{{
    0x01,0x0a,0x04,0x00,0x0a,0x64,0x04,0x00,0x05,0x34,0x03,0x00}};
using Plan = entry::Plan;
inline bool prepare(const std::array<unsigned char,17>& prefix,
                    const std::array<unsigned char,40>& unwind,
                    uintptr_t address,uintptr_t hook,Plan& output) noexcept {
    if (address < kRva || unwind != kUnwind
        || std::memcmp(prefix.data(),kPrefix.data(),kPrefixBytes)
        || !jumps::detail::valid_code_address(address,kEndRva-kRva)
        || !jumps::detail::valid_code_address(hook)
        || (hook >= address && hook < address+kEndRva-kRva)) return false;
    Plan candidate{};
    std::memcpy(candidate.image.data(),prefix.data(),kPrefixBytes);
    // The constructor overwrites its RSP+16 scratch slot before reading it.
    // Its RCX/RBX/RSI home saves at +8/+24/+32 remain intact.
    jumps::detail::home_slot_jump(candidate.image.data()+kPrefixBytes,0x10,address+kPrefixBytes);
    std::memcpy(candidate.image.data()+64,kProjected.data(),kProjected.size());
    candidate.patch.fill(0x90);
    jumps::detail::absolute_jump(candidate.patch.data(),hook);
    candidate.runtime.end = kPrefixBytes+jumps::kHomeSlotJumpBytes;
    output = candidate;
    return true;
}
} // namespace birth_entry

namespace retirement_entry {
namespace jumps = information::battle::message_entry;
constexpr uint32_t kRva = 0xd85ab0, kEndRva = 0xd85cbd, kUnwindRva = 0x1ebf0e8;
constexpr unsigned kPrefixBytes = 13, kUnwindBytes = 16;
inline constexpr std::array<unsigned char,17> kPrefix{{
    0x48,0x89,0x5c,0x24,0x08,0x57,0x48,0x83,0xec,0x20,0x48,0x8b,0xd9}};
inline constexpr std::array<unsigned char,40> kUnwind{{
    0x19,0x0a,0x04,0x00,0x0a,0x34,0x06,0x00,0x0a,0x32,0x06,0x70,0x9c,0x4d,0xa3,0x01}};
inline constexpr std::array<unsigned char,12> kProjected{{
    0x01,0x0a,0x04,0x00,0x0a,0x34,0x06,0x00,0x0a,0x32,0x06,0x70}};
using Plan = entry::Plan;
inline bool prepare(const std::array<unsigned char,17>& prefix,
                    const std::array<unsigned char,40>& unwind,
                    uintptr_t address,uintptr_t hook,Plan& output) noexcept {
    if (address<kRva || unwind!=kUnwind
        || std::memcmp(prefix.data(),kPrefix.data(),kPrefixBytes)
        || !jumps::detail::valid_code_address(address,kEndRva-kRva)
        || !jumps::detail::valid_code_address(hook)
        || (hook>=address && hook<address+kEndRva-kRva)) return false;
    Plan candidate{};
    std::memcpy(candidate.image.data(),prefix.data(),kPrefixBytes);
    jumps::detail::home_slot_jump(candidate.image.data()+kPrefixBytes,0x38,address+kPrefixBytes);
    std::memcpy(candidate.image.data()+64,kProjected.data(),kProjected.size());
    candidate.patch.fill(0x90);
    // RAX is first defined by the native LEA at +13. This 12-byte jump avoids
    // relocating that RIP-relative instruction and preserves every argument.
    candidate.patch[0]=0x48; candidate.patch[1]=0xb8;
    std::memcpy(candidate.patch.data()+2,&hook,sizeof(hook));
    candidate.patch[10]=0xff; candidate.patch[11]=0xe0;
    candidate.runtime.end=kPrefixBytes+jumps::kHomeSlotJumpBytes;
    output=candidate;
    return true;
}
} // namespace retirement_entry

} // namespace information::war_declaration
#endif
