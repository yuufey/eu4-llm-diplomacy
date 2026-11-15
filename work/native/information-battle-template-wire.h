#ifndef INFORMATION_BATTLE_TEMPLATE_WIRE_H
#define INFORMATION_BATTLE_TEMPLATE_WIRE_H

// Version-4 pointer-free envelope for an already-owned v3 battle
// observation and an optional copied message/template snapshot.  BTXT
// extension 1 is the message object; extension 2 is the formatter's
// standalone pre-cleanup container and deliberately carries no message
// metadata.
//
// The v3 bytes are embedded unchanged.  The BTXT block contains only bounded
// value fields and raw string bytes copied from owned_template::Snapshot; it
// keeps pair order and duplicate keys and assigns no text semantics.

#include "information-battle-naval-wire.h"
#include "information-battle-owned-template.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <type_traits>

namespace information::battle::template_wire {

namespace naval_wire = information::battle::naval_wire;
namespace owned_template = information::battle::owned_template;
using Address = std::uintptr_t;

constexpr std::array<unsigned char, 4> kMagic{{'I', 'B', 'O', 'W'}};
constexpr std::array<unsigned char, 4> kExtensionMagic{{'B', 'T', 'X', 'T'}};
constexpr std::uint16_t kVersion = 4u;
constexpr std::uint16_t kExtensionVersion = 1u;
constexpr std::uint16_t kContainerExtensionVersion = 2u;
constexpr std::uint8_t kMessageSource = 1u;
constexpr std::uint8_t kFormatterContainerSource = 2u;
constexpr std::size_t kMaxWireBytes = 256u * 1024u;
constexpr std::size_t kMaxBaseV3Bytes = naval_wire::kMaxWireBytes;
constexpr std::size_t kExtensionHeaderBytes = 4u + 2u + 4u;
constexpr std::size_t kFixedBodyBytes = 4u + 1u + 1u + 4u + 1u + 4u + 4u;
constexpr std::size_t kFormatterContainerFixedBodyBytes = 1u + 4u + 1u + 4u;

struct TemplateObservation final {
    naval_wire::NavalObservation base{};
    bool template_present = false;
    std::uint8_t template_source_kind = kMessageSource;
    owned_template::Snapshot message{};
};

struct EncodeResult final {
    std::size_t written_bytes = 0u;

    bool succeeded() const noexcept { return written_bytes != 0u; }
};

static_assert(std::is_trivially_copyable<TemplateObservation>::value,
              "template observation must remain a value-only object");

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

inline std::size_t range_end(owned_template::TextRange range) noexcept {
    return static_cast<std::size_t>(range.offset)
        + static_cast<std::size_t>(range.length);
}

inline bool valid_range(owned_template::TextRange range,
                        std::size_t maximum) noexcept {
    return static_cast<std::size_t>(range.offset) <= maximum
        && static_cast<std::size_t>(range.length)
            <= maximum - static_cast<std::size_t>(range.offset);
}

inline bool snapshot_valid(const owned_template::Snapshot& snapshot) noexcept {
    if (snapshot.pair_count > owned_template::kMaxPairs
            || snapshot.auxiliary_text.length
                > owned_template::kMaxAuxiliaryTextBytes
            || !valid_range(snapshot.auxiliary_text,
                            owned_template::kMaxArenaBytes)) {
        return false;
    }
    std::size_t arena_bytes = snapshot.auxiliary_text.length;
    for (std::size_t index = 0u; index < snapshot.pair_count; ++index) {
        const auto& pair = snapshot.pairs[index];
        if (pair.key.length > owned_template::kMaxKeyBytes
                || pair.value.length > owned_template::kMaxValueBytes
                || !valid_range(pair.key, owned_template::kMaxArenaBytes)
                || !valid_range(pair.value, owned_template::kMaxArenaBytes)) {
            return false;
        }
        if (pair.key.length > owned_template::kMaxArenaBytes - arena_bytes) {
            return false;
        }
        arena_bytes += pair.key.length;
        if (pair.value.length > owned_template::kMaxArenaBytes - arena_bytes) {
            return false;
        }
        arena_bytes += pair.value.length;
    }
    return true;
}

inline bool source_kind_valid(std::uint8_t source_kind,
                              bool template_present) noexcept {
    if (!template_present) {
        // The absent form has no source byte on the wire.  Keep its in-memory
        // default canonical so a caller cannot smuggle an unencoded kind.
        return source_kind == kMessageSource;
    }
    return source_kind == kMessageSource
        || source_kind == kFormatterContainerSource;
}

inline bool formatter_container_snapshot_valid(
        const owned_template::Snapshot& snapshot) noexcept {
    if (!snapshot_valid(snapshot)
            || snapshot.native_date != 0
            || snapshot.raw_flag_8c != 0u
            || snapshot.raw_flag_8d != 0u
            || snapshot.auxiliary_text.offset != 0u
            || snapshot.auxiliary_text.length != 0u) {
        return false;
    }
    return true;
}

inline bool extension_body_size(const TemplateObservation& input,
                                std::size_t& body_bytes) noexcept {
    const auto& message = input.message;
    std::size_t size = 0u;
    if (input.template_source_kind == kMessageSource) {
        if (!snapshot_valid(message)) {
            return false;
        }
        size = kFixedBodyBytes;
        if (!checked_add(size,
                         static_cast<std::size_t>(message.auxiliary_text.length),
                         size)) {
            return false;
        }
    } else if (input.template_source_kind == kFormatterContainerSource) {
        if (!formatter_container_snapshot_valid(message)) {
            return false;
        }
        size = kFormatterContainerFixedBodyBytes;
    } else {
        return false;
    }
    for (std::size_t index = 0u; index < message.pair_count; ++index) {
        const auto& pair = message.pairs[index];
        if (!checked_add(size, 4u, size)
                || !checked_add(size, pair.key.length, size)
                || !checked_add(size, 4u, size)
                || !checked_add(size, pair.value.length, size)) {
            return false;
        }
    }
    body_bytes = size;
    return body_bytes <= kMaxWireBytes;
}

inline bool total_size(const TemplateObservation& input,
                       std::size_t base_bytes,
                       std::size_t& required) noexcept {
    std::size_t size = 4u + 2u + 4u;
    if (base_bytes == 0u
            || base_bytes > kMaxBaseV3Bytes
            || !checked_add(size, base_bytes, size)
            || !checked_add(size, 1u, size)) {
        return false;
    }
    if (input.template_present) {
        std::size_t body = 0u;
        if (!extension_body_size(input, body)
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

inline void put_bytes(unsigned char*& cursor, const unsigned char* source,
                      std::size_t size) noexcept {
    if (size != 0u) {
        std::memcpy(cursor, source, size);
        cursor += size;
    }
}

}  // namespace detail

// Returns zero for an invalid v3 base, invalid snapshot, noncanonical bool,
// or a frame that would exceed the 256 KiB envelope limit.
inline std::size_t encoded_size(const TemplateObservation& input) noexcept {
    if (!detail::valid_bool(input.template_present)
            || !detail::source_kind_valid(input.template_source_kind,
                                          input.template_present)) {
        return 0u;
    }
    std::array<unsigned char, kMaxBaseV3Bytes> base_wire{};
    const naval_wire::EncodeResult base = naval_wire::encode(
        input.base, base_wire.data(), base_wire.size());
    if (!base.succeeded()) {
        return 0u;
    }
    std::size_t required = 0u;
    if (!detail::total_size(input, base.written_bytes, required)) {
        return 0u;
    }
    return required;
}

inline EncodeResult encode(const TemplateObservation& input,
                           unsigned char* output,
                           std::size_t capacity) noexcept {
    if (!detail::valid_bool(input.template_present)
            || !detail::source_kind_valid(input.template_source_kind,
                                          input.template_present)) {
        return EncodeResult{};
    }

    std::array<unsigned char, kMaxBaseV3Bytes> base_wire{};
    const naval_wire::EncodeResult base = naval_wire::encode(
        input.base, base_wire.data(), base_wire.size());
    std::size_t required = 0u;
    std::size_t body_bytes = 0u;
    if (!base.succeeded()
            || !detail::total_size(input, base.written_bytes, required)
            || (input.template_present
                && !detail::extension_body_size(input, body_bytes))
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
    detail::put_u32(cursor, static_cast<std::uint32_t>(base.written_bytes));
    detail::put_bytes(cursor, base_wire.data(), base.written_bytes);
    detail::put_u8(cursor, detail::raw_bool(input.template_present));
    if (!input.template_present) {
        return EncodeResult{required};
    }

    detail::put_bytes(cursor, kExtensionMagic.data(),
                      kExtensionMagic.size());
    const std::uint16_t extension_version =
        input.template_source_kind == kFormatterContainerSource
        ? kContainerExtensionVersion : kExtensionVersion;
    detail::put_u16(cursor, extension_version);
    detail::put_u32(cursor, static_cast<std::uint32_t>(body_bytes));
    const auto& message = input.message;
    if (input.template_source_kind == kFormatterContainerSource) {
        detail::put_u8(cursor, kFormatterContainerSource);
        detail::put_u32(cursor, message.raw_header_word_20);
        detail::put_u8(cursor, message.raw_header_flag_24);
        detail::put_u32(cursor, message.pair_count);
        for (std::size_t index = 0u; index < message.pair_count; ++index) {
            const auto& pair = message.pairs[index];
            detail::put_u32(cursor, pair.key.length);
            detail::put_bytes(cursor, message.arena.data() + pair.key.offset,
                              pair.key.length);
            detail::put_u32(cursor, pair.value.length);
            detail::put_bytes(cursor,
                              message.arena.data() + pair.value.offset,
                              pair.value.length);
        }
        return EncodeResult{required};
    }
    detail::put_i32(cursor, message.native_date);
    detail::put_u8(cursor, message.raw_flag_8c);
    detail::put_u8(cursor, message.raw_flag_8d);
    detail::put_u32(cursor, message.raw_header_word_20);
    detail::put_u8(cursor, message.raw_header_flag_24);
    detail::put_u32(cursor, message.pair_count);
    detail::put_u32(cursor, message.auxiliary_text.length);
    detail::put_bytes(cursor,
                      message.arena.data() + message.auxiliary_text.offset,
                      message.auxiliary_text.length);
    for (std::size_t index = 0u; index < message.pair_count; ++index) {
        const auto& pair = message.pairs[index];
        detail::put_u32(cursor, pair.key.length);
        detail::put_bytes(cursor, message.arena.data() + pair.key.offset,
                          pair.key.length);
        detail::put_u32(cursor, pair.value.length);
        detail::put_bytes(cursor, message.arena.data() + pair.value.offset,
                          pair.value.length);
    }
    return EncodeResult{required};
}

}  // namespace information::battle::template_wire

#endif  // INFORMATION_BATTLE_TEMPLATE_WIRE_H
