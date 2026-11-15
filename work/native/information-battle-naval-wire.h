#ifndef INFORMATION_BATTLE_NAVAL_WIRE_H
#define INFORMATION_BATTLE_NAVAL_WIRE_H

// Version-3 pointer-free envelope for the bounded naval loss/remaining inputs.
//
// This component only serializes value snapshots supplied by its caller.  It
// never calls game code, allocates, performs I/O, or retains a native pointer.
// The unchanged v2 context frame is embedded as a byte-for-byte base.  The
// NAVL extension carries only the newly read raw loss/gate/row values; initial
// lanes and summary +0x4c/+0x44/+0x48 remain in the base v1 payload.

#include "information-battle-context-wire.h"
#include "information-battle-owned-naval.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <type_traits>

namespace information::battle::naval_wire {

namespace context_wire = information::battle::context_wire;
namespace owned_context = information::battle::owned_context;
namespace owned_naval = information::battle::owned_naval;
using Address = std::uintptr_t;

constexpr std::array<unsigned char, 4> kMagic{{'I', 'B', 'O', 'W'}};
constexpr std::array<unsigned char, 4> kExtensionMagic{{'N', 'A', 'V', 'L'}};
constexpr std::uint16_t kVersion = 3u;
constexpr std::uint16_t kExtensionVersion = 1u;
constexpr std::size_t kMaxWireBytes = 65536u;
constexpr std::size_t kMaxBaseV2Bytes = context_wire::kMaxWireBytes;
constexpr std::size_t kSideCount = 2u;
constexpr std::size_t kRawLossCount = 4u;
constexpr std::size_t kExtensionHeaderBytes = 4u + 2u + 4u;
constexpr std::size_t kExtensionFixedBodyBytes = 4u + 2u * (4u * 4u + 1u);

struct NavalObservation final {
    context_wire::ContextObservation base{};
    bool naval_present = false;
    owned_naval::Snapshot naval{};
};

struct EncodeResult final {
    std::size_t written_bytes = 0u;

    bool succeeded() const noexcept { return written_bytes != 0u; }
};

static_assert(std::is_trivially_copyable<NavalObservation>::value,
              "naval observation must remain a value-only object");

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

inline void put_bytes(unsigned char*& cursor, const unsigned char* source,
                      std::size_t size) noexcept {
    if (size != 0u) {
        std::memcpy(cursor, source, size);
        cursor += size;
    }
}

inline bool base_is_naval_complete(
    const context_wire::ContextObservation& base) noexcept {
    if (!base.context_present
            || base.context.kind != owned_context::Kind::naval) {
        return false;
    }
    for (const auto& side : base.context.sides) {
        if (!side.present || !side.participants.complete) {
            return false;
        }
    }
    return true;
}

inline bool extension_body_size(const NavalObservation& input,
                                std::size_t& body_bytes) noexcept {
    if (input.naval.row_count > owned_naval::kMaxRows) {
        return false;
    }
    std::size_t size = kExtensionFixedBodyBytes;
    if (!checked_add(size,
                     static_cast<std::size_t>(input.naval.row_count) * 4u,
                     size)) {
        return false;
    }
    body_bytes = size;
    return true;
}

inline bool build_base_v2(const NavalObservation& input,
                          std::array<unsigned char, kMaxBaseV2Bytes>& buffer,
                          std::size_t& base_bytes) noexcept {
    const context_wire::EncodeResult encoded = context_wire::encode(
        input.base, buffer.data(), buffer.size());
    if (!encoded.succeeded() || encoded.written_bytes > kMaxBaseV2Bytes) {
        return false;
    }
    base_bytes = encoded.written_bytes;
    return true;
}

inline bool total_size(const NavalObservation& input, std::size_t base_bytes,
                       std::size_t& required) noexcept {
    std::size_t size = 4u + 2u + 4u;
    if (!checked_add(size, base_bytes, size)
            || !checked_add(size, 1u, size)) {
        return false;
    }
    if (input.naval_present) {
        std::size_t body = 0u;
        if (!extension_body_size(input, body)
                || !base_is_naval_complete(input.base)
                || !checked_add(size, kExtensionHeaderBytes, size)
                || !checked_add(size, body, size)) {
            return false;
        }
    }
    if (size > kMaxWireBytes) {
        return false;
    }
    required = size;
    return true;
}

}  // namespace detail

// Returns zero for an invalid snapshot.  The calculation is bounded and does
// not write the caller's output; it validates the base v2 object as well.
inline std::size_t encoded_size(const NavalObservation& input) noexcept {
    std::array<unsigned char, kMaxBaseV2Bytes> base_wire{};
    std::size_t base_bytes = 0u;
    std::size_t required = 0u;
    if (!detail::build_base_v2(input, base_wire, base_bytes)
            || !detail::total_size(input, base_bytes, required)) {
        return 0u;
    }
    return required;
}

inline EncodeResult encode(const NavalObservation& input,
                           unsigned char* output,
                           std::size_t capacity) noexcept {
    std::array<unsigned char, kMaxBaseV2Bytes> base_wire{};
    std::size_t base_bytes = 0u;
    std::size_t required = 0u;
    if (!detail::build_base_v2(input, base_wire, base_bytes)
            || !detail::total_size(input, base_bytes, required)
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
    *cursor++ = input.naval_present ? 1u : 0u;
    if (!input.naval_present) {
        return EncodeResult{required};
    }

    std::size_t body_bytes = 0u;
    if (!detail::extension_body_size(input, body_bytes)) {
        return EncodeResult{};
    }
    detail::put_bytes(cursor, kExtensionMagic.data(), kExtensionMagic.size());
    detail::put_u16(cursor, kExtensionVersion);
    detail::put_u32(cursor, static_cast<std::uint32_t>(body_bytes));
    detail::put_u32(cursor, input.naval.row_count);
    for (std::size_t index = 0u; index < input.naval.row_count; ++index) {
        detail::put_i32(cursor, input.naval.row_types[index]);
    }
    for (const auto& side : input.naval.sides) {
        for (const auto value : side.raw_loss_i32) {
            detail::put_i32(cursor, value);
        }
        *cursor++ = side.raw_gate;
    }
    return EncodeResult{required};
}

}  // namespace information::battle::naval_wire

#endif  // INFORMATION_BATTLE_NAVAL_WIRE_H
