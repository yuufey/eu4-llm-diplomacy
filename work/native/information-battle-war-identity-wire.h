#ifndef INFORMATION_BATTLE_WAR_IDENTITY_WIRE_H
#define INFORMATION_BATTLE_WAR_IDENTITY_WIRE_H

// Version-5 pointer-free envelope for an already-owned v4 battle/template
// observation and an optional-quality observer-session war binding.  The WARI
// extension contains only copied scalar fields and an opaque 29-byte ID.  It
// never serializes a native pointer and makes no cross-session or cross-save
// identity claim.  Versions 1 through 4 are emitted by the older headers and
// are not changed by this component.

#include "information-battle-template-wire.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <type_traits>

namespace information::battle::war_identity_wire {

namespace template_wire = information::battle::template_wire;
using Address = std::uintptr_t;

constexpr std::array<unsigned char, 4> kMagic{{'I', 'B', 'O', 'W'}};
constexpr std::array<unsigned char, 4> kExtensionMagic{{'W', 'A', 'R', 'I'}};
constexpr std::uint16_t kVersion = 5u;
constexpr std::uint16_t kBaseVersion = 4u;
constexpr std::size_t kMaxWireBytes = 512u * 1024u;
constexpr std::size_t kMaxBaseV4Bytes = template_wire::kMaxWireBytes;
constexpr std::size_t kMaxWarIdBytes = 29u;
constexpr std::size_t kWarIdStorageBytes = 30u;
constexpr std::size_t kExtensionHeaderBytes = 4u;
// status, reason, flags, creation FILETIME, date, two full refs, id length.
constexpr std::size_t kIdentityFixedBytes = 1u + 1u + 4u + 8u + 4u
    + 8u + 8u + 1u;
constexpr std::size_t kMaxIdentityBytes = kIdentityFixedBytes
    + kMaxWarIdBytes;
constexpr std::uint32_t kBindingFlags = 63u;
constexpr std::uint8_t kStatusAbsent = 0u;
constexpr std::uint8_t kStatusBound = 1u;
constexpr std::uint8_t kStatusInvalid = 2u;

struct Identity final {
    std::uint8_t status = kStatusAbsent;
    std::uint8_t reason = 0u;
    std::uint32_t binding_flags = 0u;
    std::uint64_t process_creation_filetime = 0u;
    std::int32_t raw_date = 0;
    std::array<std::uint64_t, 2> pair_full_refs{};
    std::array<char, kWarIdStorageBytes> war_id{};
};

struct WarIdentityObservation final {
    template_wire::TemplateObservation base{};
    Identity identity{};
};

struct EncodeResult final {
    std::size_t written_bytes = 0u;

    bool succeeded() const noexcept { return written_bytes != 0u; }
};

static_assert(std::is_trivially_copyable<Identity>::value,
              "war identity must remain a value-only object");
static_assert(std::is_trivially_copyable<WarIdentityObservation>::value,
              "war identity observation must remain value-only");

namespace detail {

inline bool checked_add(std::size_t left, std::size_t right,
                        std::size_t& result) noexcept {
    if (left > (std::numeric_limits<std::size_t>::max)() - right) {
        return false;
    }
    result = left + right;
    return true;
}

inline bool pointer_range(const unsigned char* pointer, std::size_t size,
                          Address& begin, Address& end) noexcept {
    if (pointer == nullptr || size == 0u) {
        return false;
    }
    begin = reinterpret_cast<Address>(pointer);
    if (begin > (std::numeric_limits<Address>::max)()
            - static_cast<Address>(size)) {
        return false;
    }
    end = begin + static_cast<Address>(size);
    return end > begin;
}

inline bool overlaps(Address left_begin, Address left_end,
                     Address right_begin, Address right_end) noexcept {
    return left_begin < right_end && right_begin < left_end;
}

inline bool ascii_alnum(unsigned char value) noexcept {
    return (value >= static_cast<unsigned char>('0')
                && value <= static_cast<unsigned char>('9'))
        || (value >= static_cast<unsigned char>('A')
                && value <= static_cast<unsigned char>('Z'));
}

inline bool valid_full_ref(std::uint64_t value) noexcept {
    if (value == 0u) {
        return false;
    }
    for (unsigned shift = 0u; shift < 24u; shift += 8u) {
        if (!ascii_alnum(static_cast<unsigned char>(
                (value >> shift) & UINT64_C(0xff)))) {
            return false;
        }
    }
    return true;
}

inline bool id_storage_empty(const Identity& identity) noexcept {
    for (const char value : identity.war_id) {
        if (value != '\0') {
            return false;
        }
    }
    return true;
}

inline bool id_storage_bound(const Identity& identity) noexcept {
    if (identity.war_id[0] != 'w' || identity.war_id[1] != 'a'
            || identity.war_id[2] != 'r' || identity.war_id[3] != '_'
            || identity.war_id[20] != '_'
            || identity.war_id[kMaxWarIdBytes] != '\0') {
        return false;
    }
    for (std::size_t index = 4u; index < kMaxWarIdBytes; ++index) {
        if (index == 20u) {
            continue;
        }
        const auto value = static_cast<unsigned char>(identity.war_id[index]);
        if (!((value >= static_cast<unsigned char>('0')
                   && value <= static_cast<unsigned char>('9'))
              || (value >= static_cast<unsigned char>('a')
                   && value <= static_cast<unsigned char>('f')))) {
            return false;
        }
    }
    return true;
}

inline bool identity_valid(const WarIdentityObservation& input,
                           std::size_t& id_length) noexcept {
    const auto& identity = input.identity;
    switch (identity.status) {
    case kStatusAbsent:
        if (identity.binding_flags != 0u
                || identity.pair_full_refs[0] != 0u
                || identity.pair_full_refs[1] != 0u
                || !id_storage_empty(identity)) {
            return false;
        }
        id_length = 0u;
        return true;
    case kStatusBound:
        if (identity.reason != 0u
                || identity.binding_flags != kBindingFlags
                || identity.process_creation_filetime == 0u
                || identity.raw_date
                    != input.base.base.base.inner.result.raw_date
                || !valid_full_ref(identity.pair_full_refs[0])
                || !valid_full_ref(identity.pair_full_refs[1])
                || identity.pair_full_refs[0] == identity.pair_full_refs[1]
                || !id_storage_bound(identity)) {
            return false;
        }
        id_length = kMaxWarIdBytes;
        return true;
    case kStatusInvalid:
        // An invalid observation carries no public ID.  Its diagnostic scalar
        // fields are preserved, while the fixed-size in-memory ID remains
        // canonical and empty on the wire.
        if (!id_storage_empty(identity)) {
            return false;
        }
        id_length = 0u;
        return true;
    default:
        return false;
    }
}

inline void put_u8(unsigned char*& cursor, std::uint8_t value) noexcept {
    *cursor++ = value;
}

inline void put_u16(unsigned char*& cursor, std::uint16_t value) noexcept {
    *cursor++ = static_cast<unsigned char>(value & 0xffu);
    *cursor++ = static_cast<unsigned char>((value >> 8u) & 0xffu);
}

inline void put_u32(unsigned char*& cursor, std::uint32_t value) noexcept {
    for (unsigned shift = 0u; shift < 32u; shift += 8u) {
        *cursor++ = static_cast<unsigned char>((value >> shift) & 0xffu);
    }
}

inline void put_i32(unsigned char*& cursor, std::int32_t value) noexcept {
    put_u32(cursor, static_cast<std::uint32_t>(value));
}

inline void put_u64(unsigned char*& cursor, std::uint64_t value) noexcept {
    for (unsigned shift = 0u; shift < 64u; shift += 8u) {
        *cursor++ = static_cast<unsigned char>((value >> shift) & UINT64_C(0xff));
    }
}

inline void put_bytes(unsigned char*& cursor, const unsigned char* source,
                      std::size_t size) noexcept {
    if (size != 0u) {
        std::memcpy(cursor, source, size);
        cursor += size;
    }
}

inline bool build_base_v4(
        const WarIdentityObservation& input,
        std::array<unsigned char, kMaxBaseV4Bytes>& buffer,
        std::size_t& base_bytes) noexcept {
    const template_wire::EncodeResult encoded = template_wire::encode(
        input.base, buffer.data(), buffer.size());
    if (!encoded.succeeded() || encoded.written_bytes > kMaxBaseV4Bytes) {
        return false;
    }
    base_bytes = encoded.written_bytes;
    return true;
}

inline bool total_size(const WarIdentityObservation& input,
                       std::size_t base_bytes, std::size_t id_length,
                       std::size_t& required) noexcept {
    std::size_t size = 4u + 2u + 4u;
    if (base_bytes == 0u || base_bytes > kMaxBaseV4Bytes
            || id_length > kMaxWarIdBytes
            || !checked_add(size, base_bytes, size)
            || !checked_add(size, kExtensionHeaderBytes, size)
            || !checked_add(size, kIdentityFixedBytes, size)
            || !checked_add(size, id_length, size)
            || size > kMaxWireBytes) {
        return false;
    }
    (void)input;
    required = size;
    return true;
}

}  // namespace detail

// Returns zero for an invalid base/identity or a frame over the 512 KiB
// envelope bound.  No caller output is written by this calculation.
inline std::size_t encoded_size(const WarIdentityObservation& input) noexcept {
    std::array<unsigned char, kMaxBaseV4Bytes> base_wire{};
    std::size_t base_bytes = 0u;
    std::size_t id_length = 0u;
    std::size_t required = 0u;
    if (!detail::build_base_v4(input, base_wire, base_bytes)
            || !detail::identity_valid(input, id_length)
            || !detail::total_size(input, base_bytes, id_length, required)) {
        return 0u;
    }
    return required;
}

inline EncodeResult encode(const WarIdentityObservation& input,
                           unsigned char* output,
                           std::size_t capacity) noexcept {
    std::array<unsigned char, kMaxBaseV4Bytes> base_wire{};
    std::size_t base_bytes = 0u;
    std::size_t id_length = 0u;
    std::size_t required = 0u;
    if (!detail::build_base_v4(input, base_wire, base_bytes)
            || !detail::identity_valid(input, id_length)
            || !detail::total_size(input, base_bytes, id_length, required)
            || output == nullptr || capacity < required) {
        return EncodeResult{};
    }

    Address output_begin = 0u;
    Address output_end = 0u;
    Address input_begin = 0u;
    Address input_end = 0u;
    if (!detail::pointer_range(output, required, output_begin, output_end)
            || !detail::pointer_range(
                reinterpret_cast<const unsigned char*>(&input),
                sizeof(input), input_begin, input_end)
            || detail::overlaps(output_begin, output_end,
                                input_begin, input_end)) {
        return EncodeResult{};
    }

    unsigned char* cursor = output;
    detail::put_bytes(cursor, kMagic.data(), kMagic.size());
    detail::put_u16(cursor, kVersion);
    detail::put_u32(cursor, static_cast<std::uint32_t>(base_bytes));
    detail::put_bytes(cursor, base_wire.data(), base_bytes);
    detail::put_bytes(cursor, kExtensionMagic.data(), kExtensionMagic.size());
    detail::put_u8(cursor, input.identity.status);
    detail::put_u8(cursor, input.identity.reason);
    detail::put_u32(cursor, input.identity.binding_flags);
    detail::put_u64(cursor, input.identity.process_creation_filetime);
    detail::put_i32(cursor, input.identity.raw_date);
    detail::put_u64(cursor, input.identity.pair_full_refs[0]);
    detail::put_u64(cursor, input.identity.pair_full_refs[1]);
    detail::put_u8(cursor, static_cast<std::uint8_t>(id_length));
    detail::put_bytes(cursor,
                      reinterpret_cast<const unsigned char*>(
                          input.identity.war_id.data()),
                      id_length);
    return EncodeResult{required};
}

}  // namespace information::battle::war_identity_wire

#endif  // INFORMATION_BATTLE_WAR_IDENTITY_WIRE_H
