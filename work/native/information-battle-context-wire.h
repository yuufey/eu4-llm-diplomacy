#ifndef INFORMATION_BATTLE_CONTEXT_WIRE_H
#define INFORMATION_BATTLE_CONTEXT_WIRE_H

// Version-2 context envelope for an already-owned battle observation.
//
// The inner result/summary bytes are the unchanged version-1 IBOW payload.
// This component only serializes value objects supplied by its caller.  It
// never calls game code, allocates, performs I/O, or retains a native pointer.
// All fields have explicit little-endian widths; C++ object padding is never
// placed on the wire.

#include "information-battle-observation-wire.h"
#include "information-battle-owned-context.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <type_traits>

namespace information::battle::context_wire {

namespace observation = information::battle::observation;
namespace owned_context = information::battle::owned_context;
using Address = std::uintptr_t;

constexpr std::array<unsigned char, 4> kMagic{{'I', 'B', 'O', 'W'}};
constexpr std::uint16_t kVersion = 2u;
constexpr std::size_t kMaxInnerV1Bytes = observation::kMaxWireBytes;
constexpr std::size_t kMaxWireBytes = 32768u;
constexpr std::size_t kPrefixBytes = 4u + 2u + 4u;
constexpr std::size_t kContextPresentBytes = 1u;
constexpr std::size_t kSelectorCodeBytes = 6u;
constexpr std::size_t kSideRawFieldCount = 6u;

struct ContextObservation {
    observation::Observation inner{};
    bool context_present = false;
    owned_context::Snapshot context{};
};

struct EncodeResult final {
    std::size_t written_bytes = 0u;

    bool succeeded() const noexcept { return written_bytes != 0u; }
};

static_assert(std::is_trivially_copyable<ContextObservation>::value,
              "context envelope must remain a value-only object");

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

inline std::uint8_t raw_bool(const bool& value) noexcept {
    std::uint8_t raw = 0u;
    std::memcpy(&raw, &value, sizeof(raw));
    return raw;
}

inline bool valid_bool(const bool& value) noexcept {
    const std::uint8_t raw = raw_bool(value);
    return raw == 0u || raw == 1u;
}

inline bool ascii_alnum(unsigned char value) noexcept {
    return (value >= static_cast<unsigned char>('0')
                && value <= static_cast<unsigned char>('9'))
        || (value >= static_cast<unsigned char>('A')
                && value <= static_cast<unsigned char>('Z'));
}

// EU4 full references carry a three-character ASCII country tag in the low
// three bytes.  The remaining native identity bytes, including byte 3, are
// deliberately kept opaque and are not assigned a meaning here.
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
        *cursor++ = static_cast<unsigned char>((value >> shift) & 0xffu);
    }
}

inline void put_bytes(unsigned char*& cursor, const unsigned char* source,
                      std::size_t size) noexcept {
    if (size != 0u) {
        std::memcpy(cursor, source, size);
        cursor += size;
    }
}

template <std::size_t N>
inline bool all_zero(const std::array<std::uint64_t, N>& values,
                     std::size_t begin) noexcept {
    for (std::size_t index = begin; index < values.size(); ++index) {
        if (values[index] != 0u) {
            return false;
        }
    }
    return true;
}

inline bool side_refs_valid(const owned_context::CombatSide& side) noexcept {
    if (!valid_bool(side.present)
            || !valid_bool(side.participants.complete)
            || side.participants.count > owned_context::kMaxParticipants) {
        return false;
    }
    if (!side.present) {
        if (side.participants.complete || side.participants.count != 0u) {
            return false;
        }
        for (const auto value : side.raw_fields) {
            if (value != 0) {
                return false;
            }
        }
        return all_zero(side.participants.full_refs, 0u);
    }
    // A present side comes from an owned-context observation.  Its participant
    // vector is therefore either complete or the whole context must be
    // withheld; an observed side with an incomplete vector is ambiguous.
    if (!side.participants.complete) {
        return false;
    }
    for (std::size_t index = 0u;
         index < side.participants.count; ++index) {
        if (!valid_full_ref(side.participants.full_refs[index])) {
            return false;
        }
    }
    return all_zero(side.participants.full_refs,
                    side.participants.count);
}

inline bool duplicate_or_overlap(
    const std::array<std::uint64_t, owned_context::kMaxWarMembers>& left,
    std::size_t left_count,
    const std::array<std::uint64_t, owned_context::kMaxWarMembers>& right,
    std::size_t right_count) noexcept {
    for (std::size_t i = 0u; i < left_count; ++i) {
        for (std::size_t j = i + 1u; j < left_count; ++j) {
            if (left[i] == left[j]) {
                return true;
            }
        }
        for (std::size_t j = 0u; j < right_count; ++j) {
            if (left[i] == right[j]) {
                return true;
            }
        }
    }
    for (std::size_t i = 0u; i < right_count; ++i) {
        for (std::size_t j = i + 1u; j < right_count; ++j) {
            if (right[i] == right[j]) {
                return true;
            }
        }
    }
    return false;
}

inline bool war_members_zero(
    const owned_context::WarMembers& members) noexcept {
    return members.side_a_count == 0u && members.side_b_count == 0u
        && !members.vectors_complete
        && !members.physical_player_membership_known
        && !members.physical_player_is_war_member
        && all_zero(members.side_a_full_refs, 0u)
        && all_zero(members.side_b_full_refs, 0u);
}

inline bool war_members_valid(const owned_context::Snapshot& context) noexcept {
    const auto status = static_cast<std::uint8_t>(context.war_context_status);
    if (status > static_cast<std::uint8_t>(
            owned_context::WarContextStatus::invalid)
            || !valid_bool(context.war_members.vectors_complete)
            || !valid_bool(context.war_members.physical_player_membership_known)
            || !valid_bool(context.war_members.physical_player_is_war_member)) {
        return false;
    }
    if (status != static_cast<std::uint8_t>(
            owned_context::WarContextStatus::observed)) {
        return war_members_zero(context.war_members);
    }
    if (!context.known_router
            || context.war_members.side_a_count > owned_context::kMaxWarMembers
            || context.war_members.side_b_count > owned_context::kMaxWarMembers) {
        return false;
    }
    for (std::size_t index = 0u;
         index < context.war_members.side_a_count; ++index) {
        if (!valid_full_ref(context.war_members.side_a_full_refs[index])) {
            return false;
        }
    }
    for (std::size_t index = 0u;
         index < context.war_members.side_b_count; ++index) {
        if (!valid_full_ref(context.war_members.side_b_full_refs[index])) {
            return false;
        }
    }
    if (!all_zero(context.war_members.side_a_full_refs,
                  context.war_members.side_a_count)
            || !all_zero(context.war_members.side_b_full_refs,
                         context.war_members.side_b_count)
            || duplicate_or_overlap(context.war_members.side_a_full_refs,
                                     context.war_members.side_a_count,
                                     context.war_members.side_b_full_refs,
                                     context.war_members.side_b_count)) {
        return false;
    }
    // WarContextStatus::observed is emitted only after the source has copied
    // both vectors and computed membership from those complete vectors.  A
    // partial or unknown observed value must use context_present=false (or an
    // invalid/absent status), never a false claim embedded in an observed
    // context.
    if (!context.war_members.vectors_complete
            || !context.war_members.physical_player_membership_known) {
        return false;
    }
    bool contains = false;
    for (std::size_t index = 0u;
         index < context.war_members.side_a_count; ++index) {
        contains = contains
            || context.war_members.side_a_full_refs[index]
                == context.physical_player_full_ref;
    }
    for (std::size_t index = 0u;
         index < context.war_members.side_b_count; ++index) {
        contains = contains
            || context.war_members.side_b_full_refs[index]
                == context.physical_player_full_ref;
    }
    return contains == context.war_members.physical_player_is_war_member;
}

inline bool context_valid(const ContextObservation& input) noexcept {
    const auto& context = input.context;
    if (!valid_bool(input.context_present)
            || !valid_bool(input.inner.known_router)) {
        return false;
    }
    if (!input.context_present) {
        return true;
    }
    if (!valid_bool(context.known_router)
            || !valid_bool(context.selector_code_verified)
            || context.known_router != input.inner.known_router
            || !valid_full_ref(context.physical_player_full_ref)
            || (context.raw_selector != 1u
                && context.raw_selector != 2u)
            || !context.selector_code_verified) {
        return false;
    }
    const auto kind = static_cast<std::uint8_t>(context.kind);
    if ((context.raw_selector == 1u
            && kind != static_cast<std::uint8_t>(owned_context::Kind::land))
            || (context.raw_selector == 2u
            && kind != static_cast<std::uint8_t>(owned_context::Kind::naval))) {
        return false;
    }
    const std::array<unsigned char, 6> expected{{
        0xb8u,
        static_cast<unsigned char>(context.raw_selector & 0xffu),
        static_cast<unsigned char>((context.raw_selector >> 8u) & 0xffu),
        static_cast<unsigned char>((context.raw_selector >> 16u) & 0xffu),
        static_cast<unsigned char>((context.raw_selector >> 24u) & 0xffu),
        0xc3u,
    }};
    if (context.selector_code != expected) {
        return false;
    }
    if (!side_refs_valid(context.sides[0])
            || !side_refs_valid(context.sides[1])
            || !war_members_valid(context)) {
        return false;
    }
    return true;
}

inline bool checked_wire_size(const ContextObservation& input,
                              std::size_t inner_length,
                              std::size_t& required) noexcept {
    std::size_t size = kPrefixBytes;
    if (!checked_add(size, inner_length, size)
            || !checked_add(size, kContextPresentBytes, size)) {
        return false;
    }
    if (input.context_present) {
        const auto& context = input.context;
        if (!checked_add(size, 1u + 4u + kSelectorCodeBytes + 1u + 1u + 8u,
                         size)) {
            return false;
        }
        for (const auto& side : context.sides) {
            if (!checked_add(size, 1u + 1u + 4u, size)
                    || !checked_add(size,
                                    static_cast<std::size_t>(
                                        side.participants.count) * 8u,
                                    size)
                    || !checked_add(size, kSideRawFieldCount * 4u, size)) {
                return false;
            }
        }
        if (!checked_add(size, 1u, size)) {
            return false;
        }
        if (static_cast<std::uint8_t>(context.war_context_status)
                == static_cast<std::uint8_t>(
                    owned_context::WarContextStatus::observed)) {
            if (!checked_add(size, 4u, size)
                    || !checked_add(size,
                                    static_cast<std::size_t>(
                                        context.war_members.side_a_count) * 8u,
                                    size)
                    || !checked_add(size, 4u, size)
                    || !checked_add(size,
                                    static_cast<std::size_t>(
                                        context.war_members.side_b_count) * 8u,
                                    size)
                    || !checked_add(size, 3u, size)) {
                return false;
            }
        }
    }
    if (size > kMaxWireBytes) {
        return false;
    }
    required = size;
    return true;
}

inline void write_side(unsigned char*& cursor,
                       const owned_context::CombatSide& side) noexcept {
    put_u8(cursor, raw_bool(side.present));
    put_u8(cursor, raw_bool(side.participants.complete));
    put_u32(cursor, side.participants.count);
    for (std::size_t index = 0u;
         index < side.participants.count; ++index) {
        put_u64(cursor, side.participants.full_refs[index]);
    }
    for (const auto value : side.raw_fields) {
        put_i32(cursor, value);
    }
}

}  // namespace detail

inline EncodeResult encode(const ContextObservation& input,
                           unsigned char* output,
                           std::size_t capacity) noexcept {
    if (!detail::valid_bool(input.context_present)
            || !detail::valid_bool(input.inner.known_router)
            || !detail::context_valid(input)) {
        return EncodeResult{};
    }

    // Reuse the existing v1 encoder into a private bounded scratch buffer.
    // No caller output is touched until all v2 validation and range checks
    // have completed, so every failure is atomic from the caller's view.
    std::array<unsigned char, kMaxInnerV1Bytes> inner_wire{};
    const observation::EncodeResult inner = observation::encode(
        input.inner, inner_wire.data(), inner_wire.size());
    if (!inner.succeeded() || inner.written_bytes > kMaxInnerV1Bytes) {
        return EncodeResult{};
    }

    std::size_t required = 0u;
    if (!detail::checked_wire_size(input, inner.written_bytes, required)
            || output == nullptr || capacity < required) {
        return EncodeResult{};
    }

    Address output_begin = 0;
    Address output_end = 0;
    Address input_begin = 0;
    Address input_end = 0;
    if (!detail::pointer_range(output, required, output_begin, output_end)
            || !detail::pointer_range(
                reinterpret_cast<const unsigned char*>(&input),
                sizeof(input), input_begin, input_end)
            || detail::overlaps(output_begin, output_end,
                                input_begin, input_end)) {
        return EncodeResult{};
    }

    unsigned char* cursor = output;
    for (const auto byte : kMagic) {
        *cursor++ = byte;
    }
    detail::put_u16(cursor, kVersion);
    detail::put_u32(cursor, static_cast<std::uint32_t>(inner.written_bytes));
    detail::put_bytes(cursor, inner_wire.data(), inner.written_bytes);
    detail::put_u8(cursor, detail::raw_bool(input.context_present));
    if (!input.context_present) {
        return EncodeResult{required};
    }

    const auto& context = input.context;
    detail::put_u8(cursor, detail::raw_bool(context.known_router));
    detail::put_u32(cursor, context.raw_selector);
    detail::put_bytes(cursor, context.selector_code.data(),
                      context.selector_code.size());
    detail::put_u8(cursor, detail::raw_bool(context.selector_code_verified));
    detail::put_u8(cursor, static_cast<std::uint8_t>(context.kind));
    detail::put_u64(cursor, context.physical_player_full_ref);
    detail::write_side(cursor, context.sides[0]);
    detail::write_side(cursor, context.sides[1]);
    detail::put_u8(cursor, static_cast<std::uint8_t>(
        context.war_context_status));
    if (context.war_context_status
            == owned_context::WarContextStatus::observed) {
        detail::put_u32(cursor, context.war_members.side_a_count);
        for (std::size_t index = 0u;
             index < context.war_members.side_a_count; ++index) {
            detail::put_u64(cursor, context.war_members.side_a_full_refs[index]);
        }
        detail::put_u32(cursor, context.war_members.side_b_count);
        for (std::size_t index = 0u;
             index < context.war_members.side_b_count; ++index) {
            detail::put_u64(cursor, context.war_members.side_b_full_refs[index]);
        }
        detail::put_u8(cursor, detail::raw_bool(
            context.war_members.vectors_complete));
        detail::put_u8(cursor, detail::raw_bool(
            context.war_members.physical_player_membership_known));
        detail::put_u8(cursor, detail::raw_bool(
            context.war_members.physical_player_is_war_member));
    }
    return EncodeResult{required};
}

}  // namespace information::battle::context_wire

#endif  // INFORMATION_BATTLE_CONTEXT_WIRE_H
