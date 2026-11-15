#ifndef INFORMATION_BATTLE_OBSERVATION_WIRE_H
#define INFORMATION_BATTLE_OBSERVATION_WIRE_H

// Pointer-free, deterministic encoding of one bounded battle observation.
//
// This is a transport fixture for an already-owned result/summary snapshot.
// It never calls EU4 code, allocates, performs I/O, or retains a native
// pointer.  The wire deliberately carries raw values only; it does not assign
// kind, winner, side, scale, visibility, or a public war/battle identity.

#include "information-battle-owned-result.h"
#include "information-battle-owned-summary.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <type_traits>

namespace information::battle::observation {

namespace owned_result = information::battle::owned_result;
namespace owned_summary = information::battle::owned_summary;
using Address = std::uintptr_t;

constexpr std::array<unsigned char, 4> kMagic{{'I', 'B', 'O', 'W'}};
constexpr std::uint16_t kVersion = 1u;
constexpr std::size_t kMaxWireBytes = 16384u;
constexpr std::size_t kHeaderBytes = 19u;
constexpr std::size_t kMaxStringBytes = owned_result::kMaxOwnedStringBytes;
constexpr std::size_t kSideCount = owned_result::kSideCount;
constexpr std::size_t kSummaryRawCount = owned_summary::kRawFieldOffsets.size();

struct Observation {
    std::uint64_t sequence = 0;
    std::uint32_t thread = 0;
    bool known_router = false;
    owned_result::Snapshot result{};
    owned_summary::Snapshot summary{};
};

struct EncodeResult {
    std::size_t written_bytes = 0;

    bool succeeded() const noexcept { return written_bytes != 0u; }
};

static_assert(std::is_trivially_copyable<Observation>::value,
              "observation is a value-only capture record");

namespace detail {

inline bool checked_add(std::size_t left, std::size_t right,
                        std::size_t& result) noexcept {
    if (left > std::numeric_limits<std::size_t>::max() - right) {
        return false;
    }
    result = left + right;
    return true;
}

inline bool checked_pointer_range(const unsigned char* pointer,
                                  std::size_t size,
                                  Address& begin,
                                  Address& end) noexcept {
    if (pointer == nullptr) {
        return false;
    }
    begin = reinterpret_cast<Address>(pointer);
    if (begin > std::numeric_limits<Address>::max()
            - static_cast<Address>(size)) {
        return false;
    }
    end = begin + static_cast<Address>(size);
    return end > begin;
}

inline bool ranges_overlap(Address left_begin, Address left_end,
                           Address right_begin, Address right_end) noexcept {
    return left_begin < right_end && right_begin < left_end;
}

inline bool valid_bytes(const owned_result::OwnedBytes& value) noexcept {
    // Capacity is not put on the wire, but a malformed owned snapshot must
    // not be silently normalized into a different observation.
    return value.length <= kMaxStringBytes
        && value.capacity >= value.length
        && value.capacity <= owned_result::kMaxStringCapacity;
}

inline bool valid_observation(const Observation& input,
                              std::size_t& required) noexcept {
    if (input.sequence == 0u || input.thread == 0u
            || !valid_bytes(input.result.name)) {
        return false;
    }
    for (const auto& side : input.result.sides) {
        if (!valid_bytes(side.commander)) {
            return false;
        }
    }

    // Fixed scalar portion: header, result date/flag/aux/province, summary,
    // and each side's country plus nine raw signed fields.
    std::size_t size = kHeaderBytes;
    if (!checked_add(size, 4u + 1u + 4u + 4u + 4u, size)
            || !checked_add(size, 4u + input.result.name.length, size)) {
        return false;
    }
    for (const auto& side : input.result.sides) {
        if (!checked_add(size, 8u + 4u * side.raw_fields.size(), size)
                || !checked_add(size, 4u + side.commander.length, size)) {
            return false;
        }
    }
    if (!checked_add(size, 4u * input.summary.raw_i32.size() + 1u, size)
            || size > kMaxWireBytes) {
        return false;
    }
    required = size;
    return true;
}

inline void put_u16(unsigned char* output, std::uint16_t value) noexcept {
    output[0] = static_cast<unsigned char>(value & 0xffu);
    output[1] = static_cast<unsigned char>((value >> 8u) & 0xffu);
}

inline void put_u32(unsigned char* output, std::uint32_t value) noexcept {
    for (unsigned index = 0; index < 4u; ++index) {
        output[index] = static_cast<unsigned char>((value >> (index * 8u)) & 0xffu);
    }
}

inline void put_u64(unsigned char* output, std::uint64_t value) noexcept {
    for (unsigned index = 0; index < 8u; ++index) {
        output[index] = static_cast<unsigned char>((value >> (index * 8u)) & 0xffu);
    }
}

inline void put_i32(unsigned char* output, std::int32_t value) noexcept {
    put_u32(output, static_cast<std::uint32_t>(value));
}

inline void put_bytes(unsigned char*& cursor,
                      const unsigned char* source,
                      std::size_t size) noexcept {
    if (size != 0u) {
        std::memcpy(cursor, source, size);
        cursor += size;
    }
}

inline void put_string(unsigned char*& cursor,
                       const owned_result::OwnedBytes& value) noexcept {
    put_u32(cursor, value.length);
    cursor += 4u;
    put_bytes(cursor, value.bytes.data(), value.length);
}

}  // namespace detail

inline EncodeResult encode(const Observation& input, unsigned char* output,
                           std::size_t capacity) noexcept {
    std::size_t required = 0;
    if (!detail::valid_observation(input, required)
            || output == nullptr || capacity < required) {
        return EncodeResult{};
    }

    Address output_begin = 0;
    Address output_end = 0;
    Address input_begin = 0;
    Address input_end = 0;
    if (!detail::checked_pointer_range(output, required,
                                      output_begin, output_end)
            || !detail::checked_pointer_range(
                reinterpret_cast<const unsigned char*>(&input),
                sizeof(input), input_begin, input_end)
            || detail::ranges_overlap(output_begin, output_end,
                                      input_begin, input_end)) {
        return EncodeResult{};
    }

    // Every validation and alias check is complete before this cursor is
    // allowed to write.  The calculated required size makes the following
    // sequence infallible and deterministic.
    unsigned char* cursor = output;
    for (unsigned char byte : kMagic) {
        *cursor++ = byte;
    }
    detail::put_u16(cursor, kVersion);
    cursor += 2u;
    detail::put_u64(cursor, input.sequence);
    cursor += 8u;
    detail::put_u32(cursor, input.thread);
    cursor += 4u;
    *cursor++ = input.known_router ? 1u : 0u;

    detail::put_i32(cursor, input.result.raw_date);
    cursor += 4u;
    *cursor++ = input.result.flag108;
    detail::put_i32(cursor, input.result.aux100);
    cursor += 4u;
    detail::put_i32(cursor, input.result.aux104);
    cursor += 4u;
    detail::put_i32(cursor, input.result.province_id);
    cursor += 4u;
    detail::put_string(cursor, input.result.name);

    for (const auto& side : input.result.sides) {
        detail::put_u64(cursor, side.country);
        cursor += 8u;
        for (const auto value : side.raw_fields) {
            detail::put_i32(cursor, value);
            cursor += 4u;
        }
        detail::put_string(cursor, side.commander);
    }

    for (const auto value : input.summary.raw_i32) {
        detail::put_i32(cursor, value);
        cursor += 4u;
    }
    *cursor++ = input.summary.control_byte;

    // ``required`` was calculated from exactly these fields before the first
    // write.  There is no fallible operation after the commit begins.
    return EncodeResult{required};
}

}  // namespace information::battle::observation

#endif  // INFORMATION_BATTLE_OBSERVATION_WIRE_H
