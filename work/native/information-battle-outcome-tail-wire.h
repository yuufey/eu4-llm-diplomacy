#ifndef INFORMATION_BATTLE_OUTCOME_TAIL_WIRE_H
#define INFORMATION_BATTLE_OUTCOME_TAIL_WIRE_H

// Value-only IBOW v13/SCTX codec. The complete v12 frame is embedded intact.
// Text remains raw bytes; this layer neither formats nor interprets outcomes.
#include "information-battle-outcome-text-wire.h"
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <type_traits>

namespace information::battle::outcome_tail_wire {
namespace outcome_wire = information::battle::outcome_text_wire;
namespace names_wire = outcome_wire::names_wire;
namespace end_wire = names_wire::end_wire;
namespace bytes = names_wire::bytes;
using Address = std::uintptr_t;

inline constexpr std::uint16_t kVersion = 13u;
inline constexpr std::uint16_t kExtensionVersion = 1u;
inline constexpr std::array<unsigned char, 4u> kExtensionMagic{{'S','C','T','X'}};
inline constexpr std::size_t kFieldCount = 5u;
inline constexpr std::size_t kMaxTextBytes = 8192u;
inline constexpr std::size_t kMaxLanguageBytes = 256u;
inline constexpr std::size_t kTextStorageBytes = kMaxTextBytes;
inline constexpr std::size_t kFixedBodyBytes = 27u;
inline constexpr std::size_t kTextHeaderBytes = 3u;
inline constexpr std::size_t kOuterHeaderBytes = 10u;
inline constexpr std::size_t kExtensionHeaderBytes = 10u;
inline constexpr std::size_t kMaxWireBytes = names_wire::kMaxWireBytes;

enum class State : std::uint8_t {
    unknown = 0u,
    known = 1u,
    absent = 2u,
};

enum TextFieldIndex : std::size_t {
    language = 0u,
    COMBAT_FLEE = 1u,
    COMBAT_TRIUMPH = 2u,
    COMBAT_WINNERTYPE_OUR = 3u,
    COMBAT_WINNERTYPE_THEIR = 4u,
};

struct Text final {
    State state = State::unknown;
    std::uint32_t length = 0u;
    std::array<unsigned char, kTextStorageBytes> bytes{};
};

struct Snapshot final {
    std::uint64_t sequence = 0u;
    std::int32_t raw_date = 0;
    std::uint8_t kind = 0u;
    std::uint16_t failure = 1u;
    std::array<std::int32_t, 3u> reserved_slots{};
    std::array<Text, kFieldCount> fields{};
};

static_assert(std::is_trivially_copyable<Snapshot>::value,
              "outcome text snapshot must contain owned values only");
using EncodeResult = end_wire::EncodeResult;

namespace detail {
using BaseIdentity = names_wire::detail::BaseIdentity;

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

inline bool identity_valid(const BaseIdentity& identity) noexcept {
    return identity.sequence != 0u && identity.raw_date >= 0
        && (identity.kind == 1u || identity.kind == 2u);
}

inline bool language_valid(const unsigned char* raw, std::size_t length) noexcept {
    if (raw == nullptr || length < 3u || length > kMaxLanguageBytes
            || raw[0] != static_cast<unsigned char>('l')
            || raw[1] != static_cast<unsigned char>('_')) return false;
    for (std::size_t i = 2u; i < length; ++i) {
        const unsigned char ch = raw[i];
        if (!((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z')
                || (ch >= '0' && ch <= '9') || ch == '_')) return false;
    }
    return true;
}

inline bool wire_text_valid(std::uint8_t state, const unsigned char* raw,
                            std::size_t length, std::size_t maximum,
                            bool allow_absent, bool is_language) noexcept {
    if (state > static_cast<std::uint8_t>(State::absent)) return false;
    if (state == static_cast<std::uint8_t>(State::unknown)
            || state == static_cast<std::uint8_t>(State::absent)) {
        return length == 0u
            && (state != static_cast<std::uint8_t>(State::absent) || allow_absent);
    }
    if (length > maximum || (length != 0u && raw == nullptr)) return false;
    for (std::size_t i = 0u; i < length; ++i) if (raw[i] == 0u) return false;
    return !is_language || language_valid(raw, length);
}

inline bool old_groups_valid(std::uint8_t raw_failure,
                             std::uint16_t prefix_failure,
                             const std::array<std::uint8_t, 4u>& states) noexcept {
    const bool raw_known = states[0] == static_cast<std::uint8_t>(names_wire::State::known)
        && states[1] == static_cast<std::uint8_t>(names_wire::State::known);
    const bool raw_unknown = states[0] == static_cast<std::uint8_t>(names_wire::State::unknown)
        && states[1] == static_cast<std::uint8_t>(names_wire::State::unknown);
    const bool prefix_known = states[3] == static_cast<std::uint8_t>(names_wire::State::known)
        && (states[2] == static_cast<std::uint8_t>(names_wire::State::known)
            || states[2] == static_cast<std::uint8_t>(names_wire::State::absent));
    const bool prefix_unknown = states[3] == static_cast<std::uint8_t>(names_wire::State::unknown)
        && states[2] == static_cast<std::uint8_t>(names_wire::State::unknown);
    return raw_failure <= 12u && prefix_failure <= 9u
        && (raw_failure == 0u ? raw_known : raw_unknown)
        && (prefix_failure == 0u ? prefix_known : prefix_unknown);
}

// Validate the complete embedded IBOW12/OCTX and extract its base identity.
inline bool base_identity(const unsigned char* base, std::size_t size,
                          BaseIdentity& identity) noexcept {
    if (base == nullptr || size < kOuterHeaderBytes + kExtensionHeaderBytes
                                      + outcome_wire::kFixedBodyBytes
                                      + outcome_wire::kFieldCount * kTextHeaderBytes
            || size > kMaxWireBytes
            || std::memcmp(base, end_wire::kMagic.data(), 4u) != 0
            || bytes::get_u16(base + 4u) != outcome_wire::kVersion
            || !outcome_wire::validate(base, size)) return false;
    const std::size_t inner_size = bytes::get_u32(base + 6u);
    return inner_size != 0u && inner_size <= size - kOuterHeaderBytes
        && outcome_wire::detail::base_identity(base + kOuterHeaderBytes,
                                               inner_size, identity)
        && identity_valid(identity);
}

inline bool text_valid(const Text& text, std::size_t index) noexcept {
    const auto state = static_cast<std::uint8_t>(text.state);
    const bool is_language = index == language;
    const std::size_t maximum = is_language ? kMaxLanguageBytes : kMaxTextBytes;
    if (state > static_cast<std::uint8_t>(State::absent)
            || text.length > maximum || text.length > text.bytes.size()) return false;
    if (state == static_cast<std::uint8_t>(State::unknown)
            || state == static_cast<std::uint8_t>(State::absent)) {
        if ((state == static_cast<std::uint8_t>(State::absent) && is_language)
                || text.length != 0u) return false;
    } else {
        for (std::size_t i = 0u; i < text.length; ++i) {
            if (text.bytes[i] == 0u) return false;
        }
        if (is_language && !language_valid(text.bytes.data(), text.length)) return false;
    }
    for (std::size_t i = text.length; i < text.bytes.size(); ++i) {
        if (text.bytes[i] != 0u) return false;
    }
    return true;
}

inline bool groups_valid(std::uint16_t failure,
                         const std::array<Text, kFieldCount>& fields) noexcept {
    if (failure > 9u) return false;
    if (failure != 0u) {
        for (const auto& field : fields) if (field.state != State::unknown) return false;
        return true;
    }
    if (fields[language].state != State::known) return false;
    for (std::size_t i = 1u; i < kFieldCount; ++i) {
        if (fields[i].state != State::known && fields[i].state != State::absent) return false;
    }
    return true;
}

inline bool snapshot_valid(const Snapshot& snapshot,
                           const BaseIdentity& identity) noexcept {
    if (!identity_valid(identity) || snapshot.sequence != identity.sequence
            || snapshot.raw_date != identity.raw_date || snapshot.kind != identity.kind
            || snapshot.failure > 9u) return false;
    for (std::size_t i = 0u; i < kFieldCount; ++i) {
        if (!text_valid(snapshot.fields[i], i)) return false;
    }
    if (!groups_valid(snapshot.failure, snapshot.fields)) return false;
    if (snapshot.failure != 0u) {
        for (const auto slot : snapshot.reserved_slots) if (slot != 0) return false;
    }
    return true;
}

inline bool body_valid(const unsigned char* body, std::size_t body_size,
                       const BaseIdentity& identity) noexcept {
    constexpr std::size_t minimum = kFixedBodyBytes + kFieldCount * kTextHeaderBytes;
    if (body == nullptr || body_size < minimum || !identity_valid(identity)) return false;
    std::int32_t raw_date = 0;
    const std::uint32_t raw_date_bits = bytes::get_u32(body + 8u);
    std::memcpy(&raw_date, &raw_date_bits, sizeof(raw_date));
    const std::uint16_t failure = bytes::get_u16(body + 13u);
    if (bytes::get_u64(body) != identity.sequence || raw_date != identity.raw_date
            || body[12u] != identity.kind || failure > 9u) return false;
    if (failure != 0u && (bytes::get_u32(body + 15u) != 0u
            || bytes::get_u32(body + 19u) != 0u
            || bytes::get_u32(body + 23u) != 0u)) return false;

    std::array<std::uint8_t, kFieldCount> states{};
    std::size_t position = kFixedBodyBytes;
    for (std::size_t i = 0u; i < kFieldCount; ++i) {
        if (body_size - position < kTextHeaderBytes) return false;
        const std::uint8_t state = body[position];
        const std::size_t length = bytes::get_u16(body + position + 1u);
        position += kTextHeaderBytes;
        if (length > body_size - position) return false;
        if (!wire_text_valid(state, body + position, length,
                             i == language ? kMaxLanguageBytes : kMaxTextBytes,
                             i != language, i == language)) return false;
        states[i] = state;
        position += length;
    }
    if (position != body_size) return false;
    if (failure != 0u) {
        for (auto state : states) if (state != static_cast<std::uint8_t>(State::unknown)) return false;
        return true;
    }
    if (states[language] != static_cast<std::uint8_t>(State::known)) return false;
    for (std::size_t i = 1u; i < kFieldCount; ++i) {
        if (states[i] != static_cast<std::uint8_t>(State::known)
                && states[i] != static_cast<std::uint8_t>(State::absent)) return false;
    }
    return true;
}

inline bool encoded_size(const unsigned char* base, std::size_t base_size,
                         const Snapshot& snapshot, std::size_t& required,
                         std::size_t& body_size) noexcept {
    BaseIdentity identity{};
    if (!base_identity(base, base_size, identity)
            || !snapshot_valid(snapshot, identity)) return false;
    body_size = kFixedBodyBytes + kFieldCount * kTextHeaderBytes;
    for (const auto& field : snapshot.fields) {
        if (!checked_add(body_size, field.length, body_size)) return false;
    }
    required = kOuterHeaderBytes;
    return checked_add(required, base_size, required)
        && checked_add(required, kExtensionHeaderBytes, required)
        && checked_add(required, body_size, required)
        && required <= kMaxWireBytes
        && body_size <= (std::numeric_limits<std::uint32_t>::max)()
        && base_size <= (std::numeric_limits<std::uint32_t>::max)();
}

inline bool disjoint(const unsigned char* base, std::size_t base_size,
                     const Snapshot& snapshot, unsigned char* output,
                     std::size_t output_size) noexcept {
    Address b = 0u, be = 0u, s = 0u, se = 0u, o = 0u, oe = 0u;
    return pointer_range(base, base_size, b, be)
        && pointer_range(&snapshot, sizeof(snapshot), s, se)
        && pointer_range(output, output_size, o, oe)
        && !overlaps(b, be, s, se) && !overlaps(b, be, o, oe)
        && !overlaps(s, se, o, oe);
}
} // namespace detail

inline std::size_t encoded_size(const unsigned char* base, std::size_t base_size,
                                const Snapshot& snapshot) noexcept {
    std::size_t required = 0u, body_size = 0u;
    return detail::encoded_size(base, base_size, snapshot, required, body_size)
        ? required : 0u;
}

inline EncodeResult encode(const unsigned char* base, std::size_t base_size,
                           const Snapshot& snapshot, unsigned char* output,
                           std::size_t capacity) noexcept {
    std::size_t required = 0u, body_size = 0u;
    if (!detail::encoded_size(base, base_size, snapshot, required, body_size)
            || output == nullptr || capacity < required
            || !detail::disjoint(base, base_size, snapshot, output, required)) {
        return {};
    }
    auto* cursor = output;
    std::memcpy(cursor, end_wire::kMagic.data(), 4u); cursor += 4u;
    bytes::put_u16(cursor, kVersion);
    bytes::put_u32(cursor, static_cast<std::uint32_t>(base_size));
    std::memcpy(cursor, base, base_size); cursor += base_size;
    std::memcpy(cursor, kExtensionMagic.data(), 4u); cursor += 4u;
    bytes::put_u16(cursor, kExtensionVersion);
    bytes::put_u32(cursor, static_cast<std::uint32_t>(body_size));
    bytes::put_u64(cursor, snapshot.sequence);
    bytes::put_u32(cursor, static_cast<std::uint32_t>(snapshot.raw_date));
    *cursor++ = snapshot.kind;
    bytes::put_u16(cursor, snapshot.failure);
    for (const auto slot : snapshot.reserved_slots) {
        bytes::put_u32(cursor, static_cast<std::uint32_t>(slot));
    }
    for (const auto& field : snapshot.fields) {
        *cursor++ = static_cast<unsigned char>(field.state);
        bytes::put_u16(cursor, static_cast<std::uint16_t>(field.length));
        if (field.length != 0u) {
            std::memcpy(cursor, field.bytes.data(), field.length);
            cursor += field.length;
        }
    }
    return {required};
}

inline bool validate(const unsigned char* frame, std::size_t frame_size) noexcept {
    if (frame == nullptr || frame_size < kOuterHeaderBytes + kExtensionHeaderBytes
                                      + kFixedBodyBytes + kFieldCount * kTextHeaderBytes
            || frame_size > kMaxWireBytes
            || std::memcmp(frame, end_wire::kMagic.data(), 4u) != 0
            || bytes::get_u16(frame + 4u) != kVersion) return false;
    const std::size_t base_size = bytes::get_u32(frame + 6u);
    if (base_size == 0u || base_size > frame_size - kOuterHeaderBytes) return false;
    const std::size_t extension_offset = kOuterHeaderBytes + base_size;
    if (frame_size - extension_offset < kExtensionHeaderBytes) return false;
    detail::BaseIdentity identity{};
    if (!detail::base_identity(frame + kOuterHeaderBytes, base_size, identity)) return false;
    const unsigned char* extension = frame + extension_offset;
    if (std::memcmp(extension, kExtensionMagic.data(), 4u) != 0
            || bytes::get_u16(extension + 4u) != kExtensionVersion) return false;
    const std::size_t body_size = bytes::get_u32(extension + 6u);
    if (body_size != frame_size - extension_offset - kExtensionHeaderBytes) return false;
    return detail::body_valid(extension + kExtensionHeaderBytes, body_size, identity);
}
} // namespace information::battle::outcome_tail_wire
#endif
