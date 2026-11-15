#ifndef INFORMATION_BATTLE_NAME_SOURCES_WIRE_H
#define INFORMATION_BATTLE_NAME_SOURCES_WIRE_H

// Value-only IBOW v11/NSRC codec. The complete v10 frame is embedded without
// changes. Text remains raw bytes; this layer does not decode a game codec.
#include "information-battle-retreat-wire.h"
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <type_traits>

namespace information::battle::name_sources_wire {
namespace retreat_wire = information::battle::retreat_wire;
namespace end_wire = retreat_wire::end_wire;
namespace bytes = retreat_wire::bytes;
using Address = std::uintptr_t;

inline constexpr std::uint16_t kVersion = 11u;
inline constexpr std::uint16_t kExtensionVersion = 1u;
inline constexpr std::array<unsigned char, 4u> kExtensionMagic{{'N','S','R','C'}};
inline constexpr std::size_t kTextFieldCount = 4u;
inline constexpr std::size_t kMaxTextBytes = 8192u;
inline constexpr std::size_t kMaxLanguageBytes = 256u;
inline constexpr std::size_t kTextStorageBytes = kMaxTextBytes + 1u;
inline constexpr std::size_t kFixedBodyBytes = 29u;
inline constexpr std::size_t kTextHeaderBytes = 3u;
inline constexpr std::size_t kOuterHeaderBytes = 10u;
inline constexpr std::size_t kExtensionHeaderBytes = 10u;
inline constexpr std::size_t kMaxWireBytes = retreat_wire::kMaxWireBytes;

enum class State : std::uint8_t {
    unknown = 0u,
    known = 1u,
    absent = 2u,
};

enum TextFieldIndex : std::size_t {
    owner_name = 0u,
    global_name = 1u,
    battle_of_template = 2u,
    language = 3u,
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
    std::uint8_t raw_failure = 12u;
    std::uint16_t prefix_failure = 1u;
    std::uint8_t transform_mode = 0u;
    std::array<Text, kTextFieldCount> fields{};
};

static_assert(std::is_trivially_copyable<Snapshot>::value,
              "name source snapshot must contain owned values only");
using EncodeResult = end_wire::EncodeResult;

namespace detail {
using BaseIdentity = bytes::BaseIdentity;

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

inline bool identity_valid(std::uint64_t sequence, std::int32_t raw_date,
                           std::uint8_t kind) noexcept {
    return sequence != 0u && raw_date >= 0
        && (kind == 1u || kind == 2u);
}

inline bool valid_v10_base(const unsigned char* base, std::size_t size,
                           BaseIdentity& identity) noexcept {
    if (base == nullptr || size < kOuterHeaderBytes
            || size > kMaxWireBytes
            || std::memcmp(base, end_wire::kMagic.data(), 4u) != 0
            || bytes::get_u16(base + 4u) != 10u) return false;
    const std::size_t inner_size = bytes::get_u32(base + 6u);
    if (inner_size == 0u || inner_size > size - kOuterHeaderBytes) return false;
    const std::size_t extension_offset = kOuterHeaderBytes + inner_size;
    if (size - extension_offset < kExtensionHeaderBytes) return false;
    if (!retreat_wire::detail::base_identity(
            base + kOuterHeaderBytes, inner_size, identity)) return false;

    const unsigned char* extension = base + extension_offset;
    const auto extension_version = bytes::get_u16(extension + 4u);
    if (std::memcmp(extension, retreat_wire::kExtensionMagic.data(), 4u) != 0
            || (extension_version != retreat_wire::kExtensionVersion
                && extension_version != retreat_wire::kUnitRemovalExtensionVersion)) {
        return false;
    }
    const std::size_t body_bytes = bytes::get_u32(extension + 6u);
    if (body_bytes != size - extension_offset - kExtensionHeaderBytes
            || body_bytes < retreat_wire::kFixedBodyBytes) return false;
    const unsigned char* body = extension + kExtensionHeaderBytes;
    const std::uint8_t state = body[13u];
    const std::uint8_t side = body[14u];
    const std::uint8_t source_marker = body[15u];
    const std::uint8_t expected_source_marker =
        extension_version == retreat_wire::kUnitRemovalExtensionVersion ? 1u : 0u;
    const std::uint16_t initial = bytes::get_u16(body + 16u);
    const std::uint16_t observed = bytes::get_u16(body + 18u);
    const std::uint32_t raw_date_bits = bytes::get_u32(body + 8u);
    std::int32_t body_date = 0;
    std::memcpy(&body_date, &raw_date_bits, sizeof(body_date));
    if (state == 0u) {
        if (extension_version != retreat_wire::kExtensionVersion
                || body_bytes != retreat_wire::kFixedBodyBytes) return false;
        for (std::size_t i = 0u; i < body_bytes; ++i) {
            if (body[i] != 0u) return false;
        }
        return identity_valid(identity.sequence, identity.raw_date, identity.kind);
    }
    if (state != 1u || source_marker != expected_source_marker || side > 1u
            || initial > retreat_wire::kMaxUnits || observed > initial
            || bytes::get_u64(body) != identity.sequence
            || body_date != identity.raw_date
            || body[12u] != identity.kind
            || !identity_valid(identity.sequence, identity.raw_date, identity.kind)) {
        return false;
    }
    std::size_t entries_bytes = 0u;
    std::size_t expected_body_bytes = 0u;
    if (!checked_add(0u, static_cast<std::size_t>(observed)
                          * retreat_wire::kUnitBytes, entries_bytes)
            || !checked_add(retreat_wire::kFixedBodyBytes, entries_bytes,
                            expected_body_bytes)
            || body_bytes != expected_body_bytes) return false;
    std::uint16_t previous = 0u;
    for (std::size_t i = 0u; i < observed; ++i) {
        const auto ordinal = bytes::get_u16(
            body + retreat_wire::kFixedBodyBytes + i * retreat_wire::kUnitBytes);
        if (ordinal >= initial || (i != 0u && ordinal <= previous)) return false;
        previous = ordinal;
    }
    return true;
}

inline bool base_identity(const unsigned char* base, std::size_t size,
                          BaseIdentity& identity) noexcept {
    return valid_v10_base(base, size, identity);
}

inline bool text_valid(const Text& text, std::size_t maximum,
                       bool allow_absent, bool is_language) noexcept {
    const auto state = static_cast<std::uint8_t>(text.state);
    if (state > static_cast<std::uint8_t>(State::absent)) return false;
    if (state == static_cast<std::uint8_t>(State::unknown)
            || state == static_cast<std::uint8_t>(State::absent)) {
        if (state == static_cast<std::uint8_t>(State::absent) && !allow_absent) {
            return false;
        }
        if (text.length != 0u) return false;
        for (unsigned char byte : text.bytes) if (byte != 0u) return false;
        return true;
    }
    if (text.length > maximum || text.length > text.bytes.size()) return false;
    for (std::size_t i = 0u; i < text.length; ++i) {
        if (text.bytes[i] == 0u) return false;
    }
    for (std::size_t i = text.length; i < text.bytes.size(); ++i) {
        if (text.bytes[i] != 0u) return false;
    }
    if (!is_language) return true;
    if (text.length < 3u || text.bytes[0] != static_cast<unsigned char>('l')
            || text.bytes[1] != static_cast<unsigned char>('_')) return false;
    for (std::size_t i = 2u; i < text.length; ++i) {
        const unsigned char ch = text.bytes[i];
        if (!((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z')
                || (ch >= '0' && ch <= '9') || ch == '_')) return false;
    }
    return true;
}

inline bool snapshot_valid(const Snapshot& snapshot,
                           const BaseIdentity& identity) noexcept {
    if (!identity_valid(snapshot.sequence, snapshot.raw_date, snapshot.kind)
            || snapshot.sequence != identity.sequence
            || snapshot.raw_date != identity.raw_date
            || snapshot.kind != identity.kind
            || snapshot.raw_failure > 12u || snapshot.prefix_failure > 9u
            || snapshot.transform_mode > 2u) {
        return false;
    }
    const auto& owner = snapshot.fields[owner_name];
    const auto& global = snapshot.fields[global_name];
    const bool raw_known = owner.state == State::known
        && global.state == State::known;
    const bool raw_unknown = owner.state == State::unknown
        && global.state == State::unknown;
    if ((snapshot.raw_failure == 0u && !raw_known)
            || (snapshot.raw_failure != 0u && !raw_unknown)) return false;

    const auto& templ = snapshot.fields[battle_of_template];
    const auto& lang = snapshot.fields[language];
    const bool prefix_known = lang.state == State::known
        && (templ.state == State::known || templ.state == State::absent);
    const bool prefix_unknown = lang.state == State::unknown
        && templ.state == State::unknown;
    if ((snapshot.prefix_failure == 0u && !prefix_known)
            || (snapshot.prefix_failure != 0u && !prefix_unknown)) return false;

    return text_valid(owner, kMaxTextBytes, false, false)
        && text_valid(global, kMaxTextBytes, false, false)
        && text_valid(templ, kMaxTextBytes, true, false)
        && text_valid(lang, kMaxLanguageBytes, false, true);
}

inline bool encoded_size(const unsigned char* base, std::size_t base_size,
                         const Snapshot& snapshot, std::size_t& required,
                         std::size_t& body_size) noexcept {
    BaseIdentity identity{};
    if (!base_identity(base, base_size, identity)
            || !snapshot_valid(snapshot, identity)) return false;
    body_size = kFixedBodyBytes;
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
    *cursor++ = snapshot.raw_failure;
    bytes::put_u16(cursor, snapshot.prefix_failure);
    *cursor++ = snapshot.transform_mode;
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
} // namespace information::battle::name_sources_wire
#endif
