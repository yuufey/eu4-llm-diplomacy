#ifndef INFORMATION_BATTLE_END_STATE_WIRE_H
#define INFORMATION_BATTLE_END_STATE_WIRE_H

// IBOW v9/EOST appends copied end-state bytes to one complete v7/v8 frame.
// It retains raw gate bytes without interpreting them and never calls engine
// code, allocates, performs I/O, or retains source pointers.

#include "information-battle-name-handoff-wire.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>

namespace information::battle::end_state_wire {

namespace name_wire = information::battle::name_handoff_wire;
namespace display_wire = information::battle::display_context_wire;
using Address = std::uintptr_t;

inline constexpr std::array<unsigned char, 4u> kMagic{{'I', 'B', 'O', 'W'}};
inline constexpr std::array<unsigned char, 4u> kExtensionMagic{{'E', 'O', 'S', 'T'}};
inline constexpr std::uint16_t kVersion = 9u;
inline constexpr std::uint16_t kBaseV7Version = 7u;
inline constexpr std::uint16_t kBaseV8Version = 8u;
inline constexpr std::uint16_t kExtensionVersion = 1u;
inline constexpr std::size_t kMaxWireBytes = name_wire::kMaxWireBytes;
inline constexpr std::size_t kOuterHeaderBytes = 10u;
inline constexpr std::size_t kExtensionHeaderBytes = 10u;
inline constexpr std::size_t kBodyBytes = 16u;

struct Snapshot final {
    std::uint64_t sequence = 0u;
    std::int32_t raw_date = 0;
    std::uint8_t kind = 0u;
    bool present = false;
    std::array<std::uint8_t, 2u> raw_gates{};
};

struct EncodeResult final {
    std::size_t written_bytes = 0u;

    bool succeeded() const noexcept { return written_bytes != 0u; }
};

static_assert(sizeof(EncodeResult) == sizeof(std::size_t),
              "wire encode result must remain a value type");

namespace detail {

using BaseIdentity = name_wire::detail::BaseIdentity;

inline bool checked_add(std::size_t left, std::size_t right,
                        std::size_t& result) noexcept {
    if (left > (std::numeric_limits<std::size_t>::max)() - right) return false;
    result = left + right;
    return true;
}

inline bool pointer_range(const void* pointer, std::size_t size,
                          Address& begin, Address& end) noexcept {
    if (pointer == nullptr || size == 0u) return false;
    begin = reinterpret_cast<Address>(pointer);
    if (begin > (std::numeric_limits<Address>::max)()
            - static_cast<Address>(size)) return false;
    end = begin + static_cast<Address>(size);
    return end > begin;
}

inline bool overlaps(Address left_begin, Address left_end,
                     Address right_begin, Address right_end) noexcept {
    return left_begin < right_end && right_begin < left_end;
}

inline std::uint16_t get_u16(const unsigned char* bytes) noexcept {
    return static_cast<std::uint16_t>(bytes[0])
        | static_cast<std::uint16_t>(static_cast<std::uint16_t>(bytes[1]) << 8u);
}

inline std::uint32_t get_u32(const unsigned char* bytes) noexcept {
    return static_cast<std::uint32_t>(bytes[0])
        | (static_cast<std::uint32_t>(bytes[1]) << 8u)
        | (static_cast<std::uint32_t>(bytes[2]) << 16u)
        | (static_cast<std::uint32_t>(bytes[3]) << 24u);
}

inline std::uint64_t get_u64(const unsigned char* bytes) noexcept {
    std::uint64_t result = 0u;
    for (unsigned index = 0u; index < 8u; ++index) {
        result |= static_cast<std::uint64_t>(bytes[index]) << (index * 8u);
    }
    return result;
}

inline void put_u16(unsigned char*& cursor, std::uint16_t value) noexcept {
    cursor[0] = static_cast<unsigned char>(value & 0xffu);
    cursor[1] = static_cast<unsigned char>((value >> 8u) & 0xffu);
    cursor += 2u;
}

inline void put_u32(unsigned char*& cursor, std::uint32_t value) noexcept {
    for (unsigned index = 0u; index < 4u; ++index) {
        cursor[index] = static_cast<unsigned char>(
            (value >> (index * 8u)) & 0xffu);
    }
    cursor += 4u;
}

inline void put_u64(unsigned char*& cursor, std::uint64_t value) noexcept {
    for (unsigned index = 0u; index < 8u; ++index) {
        cursor[index] = static_cast<unsigned char>(
            (value >> (index * 8u)) & 0xffu);
    }
    cursor += 8u;
}

inline bool valid_base7(const unsigned char* base7, std::size_t base7_bytes,
                        BaseIdentity& identity) noexcept {
    if (!name_wire::detail::valid_base7(base7, base7_bytes)) return false;
    const std::size_t base6_bytes = get_u32(base7 + 6u);
    if (base6_bytes > base7_bytes - name_wire::kOuterHeaderBytes) return false;
    return name_wire::detail::nested_base_identity(
        base7 + name_wire::kOuterHeaderBytes, base6_bytes, identity);
}

inline bool valid_base8(const unsigned char* base8, std::size_t base8_bytes,
                        BaseIdentity& identity) noexcept {
    if (base8 == nullptr || base8_bytes < kOuterHeaderBytes
            || base8_bytes > kMaxWireBytes
            || std::memcmp(base8, kMagic.data(), kMagic.size()) != 0
            || get_u16(base8 + 4u) != kBaseV8Version) return false;

    const std::size_t base7_bytes = get_u32(base8 + 6u);
    if (base7_bytes == 0u
            || base7_bytes > base8_bytes - kOuterHeaderBytes) return false;
    const unsigned char* base7 = base8 + kOuterHeaderBytes;
    if (!valid_base7(base7, base7_bytes, identity)) return false;

    const std::size_t base7_end = kOuterHeaderBytes + base7_bytes;
    if (base7_end > base8_bytes
            || base8_bytes - base7_end < name_wire::kExtensionHeaderBytes) {
        return false;
    }
    const unsigned char* extension = base8 + base7_end;
    if (std::memcmp(extension, name_wire::kExtensionMagic.data(),
                     name_wire::kExtensionMagic.size()) != 0
            || get_u16(extension + 4u) != name_wire::kExtensionVersion) {
        return false;
    }
    const std::size_t body_bytes = get_u32(extension + 6u);
    const std::size_t body_offset = base7_end + name_wire::kExtensionHeaderBytes;
    if (body_offset > base8_bytes || body_bytes != base8_bytes - body_offset
            || body_bytes < name_wire::kFixedBodyBytes) return false;
    const unsigned char* body = base8 + body_offset;
    const std::uint8_t state_id = body[0];
    const std::uint8_t kind = body[1];
    const std::uint16_t reserved = get_u16(body + 2u);
    const std::uint64_t sequence = get_u64(body + 4u);
    const std::int64_t raw_date = static_cast<std::int64_t>(
        get_u64(body + 12u));
    const std::uint32_t value_bytes = get_u32(body + 20u);
    if (reserved != 0u || value_bytes > name_wire::owned::kMaxValueBytes
            || body_bytes != name_wire::kFixedBodyBytes + value_bytes) {
        return false;
    }
    name_wire::owned::Snapshot snapshot{};
    snapshot.state = static_cast<name_wire::owned::SnapshotState>(state_id);
    snapshot.sequence = sequence;
    snapshot.raw_date = raw_date;
    snapshot.kind = kind;
    snapshot.length = value_bytes;
    if (value_bytes != 0u) {
        const unsigned char* value = body + name_wire::kFixedBodyBytes;
        if (std::memchr(value, 0, value_bytes) != nullptr) return false;
        std::memcpy(snapshot.bytes.data(), value, value_bytes);
    }
    if (!name_wire::detail::valid_snapshot(snapshot)
            || !name_wire::detail::base_identity_matches(base7, base7_bytes,
                                                         snapshot)) {
        return false;
    }
    return true;
}

inline bool base_identity(const unsigned char* base, std::size_t base_bytes,
                          std::uint16_t& version,
                          BaseIdentity& identity) noexcept {
    if (base == nullptr || base_bytes < 6u || base_bytes > kMaxWireBytes
            || std::memcmp(base, kMagic.data(), kMagic.size()) != 0) return false;
    version = get_u16(base + 4u);
    if (version == kBaseV7Version) {
        return valid_base7(base, base_bytes, identity);
    }
    if (version == kBaseV8Version) {
        return valid_base8(base, base_bytes, identity);
    }
    // In particular, a v9 frame is never accepted as its own base.
    return false;
}

inline bool snapshot_valid(const Snapshot& snapshot,
                           const BaseIdentity& identity) noexcept {
    if (!snapshot.present) return true;
    return snapshot.sequence != 0u
        && snapshot.sequence == identity.sequence
        && snapshot.raw_date == identity.raw_date
        && snapshot.kind == identity.kind
        && (snapshot.kind == 1u || snapshot.kind == 2u);
}

inline bool encoded_size(const unsigned char* base, std::size_t base_bytes,
                         const Snapshot& snapshot,
                         std::size_t& required,
                         std::uint16_t& base_version) noexcept {
    BaseIdentity identity{};
    if (!base_identity(base, base_bytes, base_version, identity)
            || !snapshot_valid(snapshot, identity)) return false;
    required = kOuterHeaderBytes;
    return checked_add(required, base_bytes, required)
        && checked_add(required, kExtensionHeaderBytes, required)
        && checked_add(required, kBodyBytes, required)
        && required <= kMaxWireBytes
        && base_bytes <= (std::numeric_limits<std::uint32_t>::max)();
}

inline bool disjoint_ranges(const unsigned char* base, std::size_t base_bytes,
                            const Snapshot& snapshot, unsigned char* output,
                            std::size_t output_bytes) noexcept {
    Address base_begin = 0u, base_end = 0u;
    Address snapshot_begin = 0u, snapshot_end = 0u;
    Address output_begin = 0u, output_end = 0u;
    if (!pointer_range(base, base_bytes, base_begin, base_end)
            || !pointer_range(&snapshot, sizeof(snapshot), snapshot_begin,
                              snapshot_end)
            || !pointer_range(output, output_bytes, output_begin, output_end)) {
        return false;
    }
    return !overlaps(base_begin, base_end, snapshot_begin, snapshot_end)
        && !overlaps(base_begin, base_end, output_begin, output_end)
        && !overlaps(snapshot_begin, snapshot_end, output_begin, output_end);
}

}  // namespace detail

inline bool validate(const unsigned char* base, std::size_t base_bytes,
                     const Snapshot& snapshot) noexcept {
    std::size_t required = 0u;
    std::uint16_t base_version = 0u;
    return detail::encoded_size(base, base_bytes, snapshot, required,
                                base_version);
}

inline std::size_t encoded_size(const unsigned char* base,
                                std::size_t base_bytes,
                                const Snapshot& snapshot) noexcept {
    std::size_t required = 0u;
    std::uint16_t base_version = 0u;
    return detail::encoded_size(base, base_bytes, snapshot, required,
                                base_version) ? required : 0u;
}

inline EncodeResult encode(const unsigned char* base, std::size_t base_bytes,
                           const Snapshot& snapshot, unsigned char* output,
                           std::size_t capacity) noexcept {
    // Validate the full embedded frame, identity, arithmetic, capacity, and
    // all alias ranges before writing any output byte.
    std::size_t required = 0u;
    std::uint16_t base_version = 0u;
    if (output == nullptr
            || !detail::encoded_size(base, base_bytes, snapshot, required,
                                     base_version)
            || capacity < required
            || !detail::disjoint_ranges(base, base_bytes, snapshot, output,
                                        required)) {
        return {};
    }

    unsigned char* cursor = output;
    std::memcpy(cursor, kMagic.data(), kMagic.size());
    cursor += kMagic.size();
    detail::put_u16(cursor, kVersion);
    detail::put_u32(cursor, static_cast<std::uint32_t>(base_bytes));
    std::memcpy(cursor, base, base_bytes);
    cursor += base_bytes;
    std::memcpy(cursor, kExtensionMagic.data(), kExtensionMagic.size());
    cursor += kExtensionMagic.size();
    detail::put_u16(cursor, kExtensionVersion);
    detail::put_u32(cursor, static_cast<std::uint32_t>(kBodyBytes));
    if (snapshot.present) {
        detail::put_u64(cursor, snapshot.sequence);
        detail::put_u32(cursor, static_cast<std::uint32_t>(snapshot.raw_date));
        *cursor++ = snapshot.kind;
        *cursor++ = 1u;
        *cursor++ = snapshot.raw_gates[0];
        *cursor++ = snapshot.raw_gates[1];
    } else {
        // Unknown state is canonical zero and never leaks stale identity or
        // stale gate bytes from an incomplete observation.
        detail::put_u64(cursor, 0u);
        detail::put_u32(cursor, 0u);
        *cursor++ = 0u;
        *cursor++ = 0u;
        *cursor++ = 0u;
        *cursor++ = 0u;
    }
    return EncodeResult{required};
}

}  // namespace information::battle::end_state_wire

#endif  // INFORMATION_BATTLE_END_STATE_WIRE_H
