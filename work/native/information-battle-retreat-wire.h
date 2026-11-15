#ifndef INFORMATION_BATTLE_RETREAT_WIRE_H
#define INFORMATION_BATTLE_RETREAT_WIRE_H

// Value-only IBOW v10/RETR codec. A complete v9 frame remains byte-for-byte
// embedded. No source pointer is serialized; raw unit flags stay uninterpreted.
#include "information-battle-end-state-wire.h"
#include <array>
#include <cstdint>
#include <cstring>
#include <limits>
#include <type_traits>

namespace information::battle::retreat_wire {
namespace end_wire = information::battle::end_state_wire;
namespace bytes = end_wire::detail;
using Address = std::uintptr_t;
inline constexpr std::uint16_t kVersion = 10u;
inline constexpr std::uint16_t kExtensionVersion = 1u;
inline constexpr std::uint16_t kUnitRemovalExtensionVersion = 2u;
inline constexpr std::array<unsigned char, 4> kExtensionMagic{{'R','E','T','R'}};
inline constexpr std::uint8_t kCaptureSourceRegular = 0u;
inline constexpr std::uint8_t kCaptureSourceUnitRemovalState = 1u;
inline constexpr std::size_t kMaxUnits = 128u;
inline constexpr std::size_t kFixedBodyBytes = 20u;
inline constexpr std::size_t kUnitBytes = 14u;
inline constexpr std::size_t kOuterHeaderBytes = 10u;
inline constexpr std::size_t kExtensionHeaderBytes = 10u;
inline constexpr std::size_t kMaxWireBytes = end_wire::kMaxWireBytes;

struct Unit final {
    std::uint16_t ordinal = 0;
    std::uint64_t owner_full_ref = 0;
    // +0x201, +0x203, +0x204, +0x205, in that order.
    std::array<std::uint8_t, 4> raw_flags{};
};

struct Snapshot final {
    std::uint64_t sequence = 0;
    std::int32_t raw_date = 0;
    std::uint8_t kind = 0;
    bool present = false;
    std::uint8_t combat_side_index = 0;
    std::uint8_t capture_source = kCaptureSourceRegular;
    std::uint16_t initial_unit_count = 0;
    std::uint16_t observed_count = 0;
    std::array<Unit, kMaxUnits> units{};
};
static_assert(std::is_trivially_copyable<Snapshot>::value, "owned values only");
using EncodeResult = end_wire::EncodeResult;

namespace detail {
using BaseIdentity = bytes::BaseIdentity;

inline bool base_identity(const unsigned char* base, std::size_t size,
                          BaseIdentity& identity) noexcept {
    if (!base || size < kOuterHeaderBytes || size > kMaxWireBytes
        || std::memcmp(base, end_wire::kMagic.data(), 4) != 0
        || bytes::get_u16(base + 4) != 9) return false;
    const std::size_t inner_size = bytes::get_u32(base + 6);
    if (!inner_size || inner_size > size - kOuterHeaderBytes) return false;
    const std::size_t extension_offset = kOuterHeaderBytes + inner_size;
    if (size - extension_offset != end_wire::kExtensionHeaderBytes + end_wire::kBodyBytes) return false;
    std::uint16_t version = 0;
    if (!bytes::base_identity(base + kOuterHeaderBytes, inner_size, version, identity)) return false;
    const auto* extension = base + extension_offset;
    if (std::memcmp(extension, end_wire::kExtensionMagic.data(), 4) != 0
        || bytes::get_u16(extension + 4) != end_wire::kExtensionVersion
        || bytes::get_u32(extension + 6) != end_wire::kBodyBytes) return false;
    const auto* body = extension + end_wire::kExtensionHeaderBytes;
    if (body[13] == 0) {
        for (std::size_t i = 0; i < end_wire::kBodyBytes; ++i) if (body[i] != 0) return false;
        return true;
    }
    std::int32_t date = 0;
    const auto raw_date = bytes::get_u32(body + 8);
    std::memcpy(&date, &raw_date, sizeof(date));
    return body[13] == 1 && bytes::get_u64(body) == identity.sequence
        && date == identity.raw_date && body[12] == identity.kind;
}

inline bool snapshot_valid(const Snapshot& snapshot, const BaseIdentity& identity) noexcept {
    if (!snapshot.present) return true;
    if (!snapshot.sequence || snapshot.sequence != identity.sequence
        || snapshot.raw_date != identity.raw_date || snapshot.kind != identity.kind
        || (snapshot.kind != 1 && snapshot.kind != 2) || snapshot.combat_side_index > 1
        || snapshot.capture_source > kCaptureSourceUnitRemovalState
        || snapshot.initial_unit_count > kMaxUnits || snapshot.observed_count > snapshot.initial_unit_count)
        return false;
    for (std::size_t i = 0; i < snapshot.observed_count; ++i) {
        if (snapshot.units[i].ordinal >= snapshot.initial_unit_count
            || (i && snapshot.units[i - 1].ordinal >= snapshot.units[i].ordinal)) return false;
    }
    return true;
}

inline std::size_t size(const unsigned char* base, std::size_t base_size,
                        const Snapshot& snapshot) noexcept {
    BaseIdentity identity{};
    if (!base_identity(base, base_size, identity) || !snapshot_valid(snapshot, identity)) return 0;
    const std::size_t count = snapshot.present ? snapshot.observed_count : 0;
    const std::size_t extra = kOuterHeaderBytes + kExtensionHeaderBytes + kFixedBodyBytes + count * kUnitBytes;
    if (base_size > kMaxWireBytes - extra) return 0;
    return base_size + extra;
}

inline bool disjoint(const unsigned char* base, std::size_t base_size, const Snapshot& snapshot,
                     unsigned char* output, std::size_t size) noexcept {
    Address b = 0, be = 0, s = 0, se = 0, o = 0, oe = 0;
    return bytes::pointer_range(base, base_size, b, be)
        && bytes::pointer_range(&snapshot, sizeof(snapshot), s, se)
        && bytes::pointer_range(output, size, o, oe)
        && !bytes::overlaps(b, be, s, se) && !bytes::overlaps(b, be, o, oe)
        && !bytes::overlaps(s, se, o, oe);
}
} // namespace detail

inline std::size_t encoded_size(const unsigned char* base, std::size_t base_size,
                               const Snapshot& snapshot) noexcept {
    return detail::size(base, base_size, snapshot);
}

inline EncodeResult encode(const unsigned char* base, std::size_t base_size,
                           const Snapshot& snapshot, unsigned char* output,
                           std::size_t capacity) noexcept {
    const auto size = detail::size(base, base_size, snapshot);
    if (!size || !output || capacity < size || !detail::disjoint(base, base_size, snapshot, output, size)) return {};
    auto* cursor = output;
    std::memcpy(cursor, end_wire::kMagic.data(), 4); cursor += 4;
    bytes::put_u16(cursor, kVersion);
    bytes::put_u32(cursor, static_cast<std::uint32_t>(base_size));
    std::memcpy(cursor, base, base_size); cursor += base_size;
    std::memcpy(cursor, kExtensionMagic.data(), 4); cursor += 4;
    const auto extension_version = snapshot.present
        && snapshot.capture_source == kCaptureSourceUnitRemovalState
        ? kUnitRemovalExtensionVersion : kExtensionVersion;
    bytes::put_u16(cursor, extension_version);
    const auto count = snapshot.present ? snapshot.observed_count : 0;
    bytes::put_u32(cursor, static_cast<std::uint32_t>(kFixedBodyBytes + count * kUnitBytes));
    if (!snapshot.present) {
        std::memset(cursor, 0, kFixedBodyBytes);
    } else {
        bytes::put_u64(cursor, snapshot.sequence);
        bytes::put_u32(cursor, static_cast<std::uint32_t>(snapshot.raw_date));
        *cursor++ = snapshot.kind;
        *cursor++ = 1;
        *cursor++ = snapshot.combat_side_index;
        *cursor++ = snapshot.capture_source == kCaptureSourceUnitRemovalState ? 1 : 0;
        bytes::put_u16(cursor, snapshot.initial_unit_count);
        bytes::put_u16(cursor, snapshot.observed_count);
        for (std::size_t i = 0; i < snapshot.observed_count; ++i) {
            bytes::put_u16(cursor, snapshot.units[i].ordinal);
            bytes::put_u64(cursor, snapshot.units[i].owner_full_ref);
            std::memcpy(cursor, snapshot.units[i].raw_flags.data(), 4); cursor += 4;
        }
    }
    return {size};
}
} // namespace information::battle::retreat_wire
#endif
