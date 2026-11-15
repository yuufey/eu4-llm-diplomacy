#ifndef INFORMATION_BATTLE_NAME_HANDOFF_WIRE_H
#define INFORMATION_BATTLE_NAME_HANDOFF_WIRE_H

// IBOW v8 value-only extension.  The complete v7 display-context frame is
// embedded byte-for-byte and NHND carries only the copied logical NAME value.
// This codec performs no native call, allocation, I/O, or pointer retention.

#include "information-battle-display-context-wire.h"
#include "information-battle-owned-name-handoff.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>

namespace information::battle::name_handoff_wire {

namespace display_wire = information::battle::display_context_wire;
namespace owned = information::battle::owned_name_handoff;
using Address = std::uintptr_t;

inline constexpr std::array<unsigned char, 4u> kMagic{{'I', 'B', 'O', 'W'}};
inline constexpr std::array<unsigned char, 4u> kExtensionMagic{{'N', 'H', 'N', 'D'}};
inline constexpr std::uint16_t kVersion = 8u;
inline constexpr std::uint16_t kBaseVersion = 7u;
inline constexpr std::uint16_t kExtensionVersion = 1u;
inline constexpr std::size_t kMaxWireBytes = display_wire::kMaxWireBytes;
inline constexpr std::size_t kMaxBaseV7Bytes = kMaxWireBytes;
inline constexpr std::size_t kOuterHeaderBytes = 10u;
inline constexpr std::size_t kExtensionHeaderBytes = 10u;
inline constexpr std::size_t kFixedBodyBytes = 24u;

struct EncodeResult final {
    std::size_t written_bytes = 0u;

    bool succeeded() const noexcept { return written_bytes != 0u; }
};

static_assert(sizeof(EncodeResult) == sizeof(std::size_t),
              "wire encode result must remain a value type");

namespace detail {

inline bool checked_add(std::size_t left, std::size_t right,
                        std::size_t& result) noexcept {
    if (left > (std::numeric_limits<std::size_t>::max)() - right) {
        return false;
    }
    result = left + right;
    return true;
}

inline bool pointer_range(const void* pointer, std::size_t size,
                          Address& begin, Address& end) noexcept {
    if (pointer == nullptr || size == 0u) return false;
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

inline std::uint16_t get_u16(const unsigned char* bytes) noexcept {
    return static_cast<std::uint16_t>(bytes[0])
        | static_cast<std::uint16_t>(bytes[1] << 8u);
}

inline std::uint32_t get_u32(const unsigned char* bytes) noexcept {
    return static_cast<std::uint32_t>(bytes[0])
        | (static_cast<std::uint32_t>(bytes[1]) << 8u)
        | (static_cast<std::uint32_t>(bytes[2]) << 16u)
        | (static_cast<std::uint32_t>(bytes[3]) << 24u);
}

inline std::uint64_t get_u64(const unsigned char* bytes) noexcept {
    std::uint64_t value = 0u;
    for (unsigned index = 0u; index < 8u; ++index) {
        value |= static_cast<std::uint64_t>(bytes[index]) << (index * 8u);
    }
    return value;
}

struct BaseIdentity final {
    std::uint64_t sequence = 0u;
    std::int32_t raw_date = 0;
    std::uint8_t kind = 0u;
};

inline bool unwrap_base(const unsigned char* frame, std::size_t frame_bytes,
                        std::uint16_t expected_version,
                        const unsigned char*& nested,
                        std::size_t& nested_bytes) noexcept {
    if (frame == nullptr || frame_bytes < display_wire::kOuterHeaderBytes
            || std::memcmp(frame, display_wire::kMagic.data(),
                           display_wire::kMagic.size()) != 0
            || get_u16(frame + 4u) != expected_version) {
        return false;
    }
    nested_bytes = get_u32(frame + 6u);
    if (nested_bytes == 0u
            || nested_bytes > frame_bytes - display_wire::kOuterHeaderBytes) {
        return false;
    }
    nested = frame + display_wire::kOuterHeaderBytes;
    return true;
}

inline bool nested_base_identity(const unsigned char* base6,
                                 std::size_t base6_bytes,
                                 BaseIdentity& identity) noexcept {
    const unsigned char* base5 = nullptr;
    const unsigned char* base4 = nullptr;
    const unsigned char* base3 = nullptr;
    const unsigned char* base2 = nullptr;
    const unsigned char* base1 = nullptr;
    std::size_t base5_bytes = 0u;
    std::size_t base4_bytes = 0u;
    std::size_t base3_bytes = 0u;
    std::size_t base2_bytes = 0u;
    std::size_t base1_bytes = 0u;
    if (!unwrap_base(base6, base6_bytes, 6u, base5, base5_bytes)
            || !unwrap_base(base5, base5_bytes, 5u, base4, base4_bytes)
            || !unwrap_base(base4, base4_bytes, 4u, base3, base3_bytes)
            || !unwrap_base(base3, base3_bytes, 3u, base2, base2_bytes)
            || !unwrap_base(base2, base2_bytes, 2u, base1, base1_bytes)
            || base1_bytes < 23u || base1[18u] != 1u) {
        return false;
    }
    identity.sequence = get_u64(base1 + 6u);
    identity.raw_date = static_cast<std::int32_t>(get_u32(base1 + 19u));
    if (identity.sequence == 0u) return false;

    const std::size_t context_offset = display_wire::kOuterHeaderBytes
        + base1_bytes;
    if (context_offset > base2_bytes
            || base2_bytes - context_offset < 14u
            || base2[context_offset] != 1u
            || base2[context_offset + 1u] != 1u
            || base2[context_offset + 12u] != 1u) {
        return false;
    }
    const std::uint32_t selector = get_u32(base2 + context_offset + 2u);
    identity.kind = base2[context_offset + 13u];
    if ((identity.kind != 1u && identity.kind != 2u)
            || selector != identity.kind) {
        return false;
    }
    const std::array<unsigned char, 6u> expected_selector{{
        0xb8u,
        static_cast<unsigned char>(selector & 0xffu),
        static_cast<unsigned char>((selector >> 8u) & 0xffu),
        static_cast<unsigned char>((selector >> 16u) & 0xffu),
        static_cast<unsigned char>((selector >> 24u) & 0xffu),
        0xc3u,
    }};
    return std::memcmp(base2 + context_offset + 6u,
                       expected_selector.data(), expected_selector.size()) == 0;
}

inline void put_u8(unsigned char*& cursor, std::uint8_t value) noexcept {
    *cursor++ = value;
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

inline void put_i64(unsigned char*& cursor, std::int64_t value) noexcept {
    put_u64(cursor, static_cast<std::uint64_t>(value));
}

// The v8 wrapper must carry a complete, valid v7 frame, not merely a v7
// header followed by bytes that happen to fit.  Keep this bounded mirror of
// display_context::valid here because the v7 header intentionally exposes no
// public validator for its pointer-free body.
inline bool valid_display_context_body(const unsigned char* body,
                                       std::size_t body_bytes) noexcept {
    constexpr std::size_t minimum_body = display_wire::kFixedBodyBytes
        + display_wire::kEntryHeaderBytes * display_wire::kEntryCount;
    if (body == nullptr || body_bytes < minimum_body
            || body_bytes > minimum_body + display_wire::kMaxExtensionArenaBytes) {
        return false;
    }
    const std::uint8_t state = body[0];
    const std::uint8_t stage = body[1];
    const std::uint16_t failure = get_u16(body + 2u);
    const std::uint64_t sequence = get_u64(body + 4u);
    const std::int32_t date = static_cast<std::int32_t>(get_u32(body + 12u));
    const std::uint8_t kind = body[16u];
    const std::int32_t popup_kind = static_cast<std::int32_t>(
        get_u32(body + 17u));
    const std::int32_t layout = static_cast<std::int32_t>(
        get_u32(body + 21u));
    const std::uint8_t button_flag = body[25u];
    if (body[26u] != display_wire::kEntryCount || state > 1u || failure > 9u) {
        return false;
    }
    if (state == 0u) {
        if (failure == 0u || stage != 0u || sequence != 0u || date != 0
                || kind != 0u || popup_kind != 0 || layout != 0
                || button_flag != 0u) {
            return false;
        }
    } else if (failure != 0u || sequence == 0u
               || (kind != 1u && kind != 2u)
               || stage < 1u || stage > display_wire::layout::kRouterScopeExit) {
        return false;
    }

    std::size_t cursor = display_wire::kFixedBodyBytes;
    std::size_t arena_used = 0u;
    const unsigned char* key_value = nullptr;
    const unsigned char* language_value = nullptr;
    std::uint32_t key_length = 0u;
    std::uint32_t language_length = 0u;
    for (std::size_t index = 0u; index < display_wire::kEntryCount; ++index) {
        if (cursor > body_bytes
                || body_bytes - cursor < display_wire::kEntryHeaderBytes) {
            return false;
        }
        const unsigned char* entry = body + cursor;
        const std::uint8_t id = entry[0];
        const std::uint8_t field_state = entry[1];
        const std::uint16_t reserved = get_u16(entry + 2u);
        const std::uint32_t length = get_u32(entry + 4u);
        if (id != index + 1u || reserved != 0u) return false;
        cursor += display_wire::kEntryHeaderBytes;
        if (state == 0u) {
            if (field_state != 0u || length != 0u) return false;
            continue;
        }
        if (field_state == 0u || field_state == 2u) {
            if (length != 0u) return false;
            continue;
        }
        if (field_state != 1u) return false;
        const std::size_t limit = index == 0u
            ? display_wire::layout::kMaxDefinitionKeyBytes
            : index == 1u ? display_wire::layout::kMaxLanguageBytes
                          : display_wire::layout::kMaxTextBytes;
        if (length > limit || cursor > body_bytes
                || length > body_bytes - cursor
                || std::memchr(body + cursor, 0, length) != nullptr) {
            return false;
        }
        if (length > display_wire::kMaxExtensionArenaBytes - arena_used) {
            return false;
        }
        if (index == 0u) {
            key_value = body + cursor;
            key_length = length;
        } else if (index == 1u) {
            language_value = body + cursor;
            language_length = length;
        }
        arena_used += length;
        cursor += length;
    }
    if (cursor != body_bytes || arena_used > display_wire::kMaxExtensionArenaBytes) {
        return false;
    }
    if (state == 0u) return true;

    const char* expected = kind == 1u ? "LANDBATTLEOVER" : "NAVALBATTLEOVER";
    const std::size_t expected_length = std::strlen(expected);
    if (key_value == nullptr || language_value == nullptr
            || key_length != expected_length
            || std::memcmp(key_value, expected, expected_length) != 0) {
        return false;
    }
    if (language_length < 3u || language_length > display_wire::layout::kMaxLanguageBytes
            || language_value[0] != 'l' || language_value[1] != '_') {
        return false;
    }
    for (std::size_t index = 2u; index < language_length; ++index) {
        const unsigned char value = language_value[index];
        if (!((value >= 'A' && value <= 'Z')
              || (value >= 'a' && value <= 'z')
              || (value >= '0' && value <= '9') || value == '_')) {
            return false;
        }
    }
    return true;
}

inline bool display_context_identity_matches(const unsigned char* body,
                                             std::size_t body_bytes,
                                             const BaseIdentity& identity) noexcept {
    if (body == nullptr || body_bytes < display_wire::kFixedBodyBytes) {
        return false;
    }
    // Unknown DCTX is a legitimate partial capture and carries no identity;
    // the nested v6 observation remains the authoritative NAME binding.
    if (body[0] == 0u) return true;
    return get_u64(body + 4u) == identity.sequence
        && static_cast<std::int32_t>(get_u32(body + 12u))
            == identity.raw_date
        && body[16u] == identity.kind;
}

inline bool valid_base7(const unsigned char* base7,
                        std::size_t base7_bytes) noexcept {
    if (base7 == nullptr || base7_bytes < kOuterHeaderBytes
            || base7_bytes > kMaxBaseV7Bytes
            || std::memcmp(base7, kMagic.data(), kMagic.size()) != 0
            || get_u16(base7 + 4u) != kBaseVersion) {
        return false;
    }
    const std::size_t base6_bytes = get_u32(base7 + 6u);
    std::size_t base6_end = 0u;
    BaseIdentity identity{};
    if (base6_bytes == 0u
            || !checked_add(kOuterHeaderBytes, base6_bytes, base6_end)
            || base6_end > base7_bytes
            || !display_wire::detail::valid_base6(base7 + kOuterHeaderBytes,
                                                   base6_bytes)
            || !nested_base_identity(base7 + kOuterHeaderBytes, base6_bytes,
                                     identity)) {
        return false;
    }
    if (base7_bytes - base6_end < kExtensionHeaderBytes
            || std::memcmp(base7 + base6_end, display_wire::kExtensionMagic.data(),
                           display_wire::kExtensionMagic.size()) != 0
            || get_u16(base7 + base6_end + 4u)
                   != display_wire::kExtensionVersion) {
        return false;
    }
    const std::size_t body_bytes = get_u32(base7 + base6_end + 6u);
    const std::size_t body_offset = base6_end + kExtensionHeaderBytes;
    const std::size_t minimum_body = display_wire::kFixedBodyBytes
        + display_wire::kEntryHeaderBytes * display_wire::kEntryCount;
    return body_bytes == base7_bytes - body_offset
        && body_bytes >= minimum_body
        && body_bytes <= kMaxWireBytes
        && valid_display_context_body(base7 + body_offset, body_bytes)
        && display_context_identity_matches(base7 + body_offset, body_bytes,
                                             identity);
}

inline bool valid_snapshot(const owned::Snapshot& snapshot) noexcept {
    if (snapshot.state == owned::SnapshotState::unknown) {
        if (snapshot.sequence != 0u || snapshot.raw_date != 0
                || snapshot.kind != 0u || snapshot.length != 0u) {
            return false;
        }
        for (unsigned char byte : snapshot.bytes) {
            if (byte != 0u) return false;
        }
        return true;
    }
    if (snapshot.state != owned::SnapshotState::known
            || snapshot.sequence == 0u || snapshot.raw_date < 0
            || (snapshot.kind != owned::kLandKind
                && snapshot.kind != owned::kNavalKind)
            || snapshot.length > owned::kMaxValueBytes
            || snapshot.bytes[snapshot.length] != 0u) {
        return false;
    }
    for (std::size_t index = 0u; index < snapshot.length; ++index) {
        if (snapshot.bytes[index] == 0u) return false;
    }
    return true;
}

inline bool base_identity_matches(const unsigned char* base7,
                                  std::size_t base7_bytes,
                                  const owned::Snapshot& snapshot) noexcept {
    if (snapshot.state == owned::SnapshotState::unknown) return true;
    const std::size_t base6_bytes = get_u32(base7 + 6u);
    BaseIdentity identity{};
    if (base6_bytes == 0u
            || base6_bytes > base7_bytes - kOuterHeaderBytes
            || !nested_base_identity(base7 + kOuterHeaderBytes, base6_bytes,
                                     identity)) {
        return false;
    }
    return snapshot.sequence == identity.sequence
        && snapshot.raw_date == static_cast<std::int64_t>(identity.raw_date)
        && snapshot.kind == identity.kind;
}

inline bool body_size(const owned::Snapshot& snapshot,
                      std::size_t& body_bytes) noexcept {
    if (!valid_snapshot(snapshot)) return false;
    return checked_add(kFixedBodyBytes,
                       static_cast<std::size_t>(snapshot.length),
                       body_bytes)
        && body_bytes <= static_cast<std::size_t>(
            (std::numeric_limits<std::uint32_t>::max)());
}

inline bool total_size(const unsigned char* base7, std::size_t base7_bytes,
                       const owned::Snapshot& snapshot,
                       std::size_t& required,
                       std::size_t& body_bytes) noexcept {
    if (!valid_base7(base7, base7_bytes)
            || !body_size(snapshot, body_bytes)
            || !base_identity_matches(base7, base7_bytes, snapshot)) {
        return false;
    }
    required = kOuterHeaderBytes;
    return checked_add(required, base7_bytes, required)
        && checked_add(required, kExtensionHeaderBytes, required)
        && checked_add(required, body_bytes, required)
        && required <= kMaxWireBytes;
}

inline bool disjoint_ranges(const unsigned char* base7,
                            std::size_t base7_bytes,
                            const owned::Snapshot& snapshot,
                            unsigned char* output,
                            std::size_t output_bytes) noexcept {
    Address base_begin = 0u, base_end = 0u;
    Address snapshot_begin = 0u, snapshot_end = 0u;
    Address output_begin = 0u, output_end = 0u;
    if (!pointer_range(base7, base7_bytes, base_begin, base_end)
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

inline bool validate(const unsigned char* base7, std::size_t base7_bytes,
                     const owned::Snapshot& snapshot) noexcept {
    return detail::valid_base7(base7, base7_bytes)
        && detail::valid_snapshot(snapshot)
        && detail::base_identity_matches(base7, base7_bytes, snapshot);
}

inline std::size_t encoded_size(const unsigned char* base7,
                                std::size_t base7_bytes,
                                const owned::Snapshot& snapshot) noexcept {
    std::size_t required = 0u;
    std::size_t body_bytes = 0u;
    return detail::total_size(base7, base7_bytes, snapshot, required,
                              body_bytes)
        ? required : 0u;
}

inline EncodeResult encode(const unsigned char* base7,
                           std::size_t base7_bytes,
                           const owned::Snapshot& snapshot,
                           unsigned char* output,
                           std::size_t capacity) noexcept {
    // Validate all inputs and alias ranges before writing a single byte.
    std::size_t required = 0u;
    std::size_t body_bytes = 0u;
    if (output == nullptr
            || !detail::total_size(base7, base7_bytes, snapshot, required,
                                   body_bytes)
            || capacity < required
            || !detail::disjoint_ranges(base7, base7_bytes, snapshot,
                                        output, required)) {
        return {};
    }

    unsigned char* cursor = output;
    std::memcpy(cursor, kMagic.data(), kMagic.size());
    cursor += kMagic.size();
    detail::put_u16(cursor, kVersion);
    detail::put_u32(cursor, static_cast<std::uint32_t>(base7_bytes));
    std::memcpy(cursor, base7, base7_bytes);
    cursor += base7_bytes;
    std::memcpy(cursor, kExtensionMagic.data(), kExtensionMagic.size());
    cursor += kExtensionMagic.size();
    detail::put_u16(cursor, kExtensionVersion);
    detail::put_u32(cursor, static_cast<std::uint32_t>(body_bytes));
    detail::put_u8(cursor, static_cast<std::uint8_t>(snapshot.state));
    detail::put_u8(cursor, static_cast<std::uint8_t>(snapshot.kind));
    detail::put_u16(cursor, 0u);
    detail::put_u64(cursor, snapshot.sequence);
    detail::put_i64(cursor, snapshot.raw_date);
    detail::put_u32(cursor, snapshot.length);
    if (snapshot.length != 0u) {
        std::memcpy(cursor, snapshot.bytes.data(), snapshot.length);
        cursor += snapshot.length;
    }
    return EncodeResult{required};
}

}  // namespace information::battle::name_handoff_wire

#endif  // INFORMATION_BATTLE_NAME_HANDOFF_WIRE_H
