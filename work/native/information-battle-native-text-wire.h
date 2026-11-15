#ifndef INFORMATION_BATTLE_NATIVE_TEXT_WIRE_H
#define INFORMATION_BATTLE_NATIVE_TEXT_WIRE_H

// Version-6 value-only envelope for native battle-text inputs.  The complete
// version-5 IBOW frame is embedded byte-for-byte; this header never parses or
// calls the native engine and never serializes a pointer.

#include "information-battle-owned-native-text.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <type_traits>

namespace information::battle::native_text_wire {

namespace owned = information::battle::owned_native_text;
using Address = std::uintptr_t;

constexpr std::array<unsigned char, 4> kMagic{{'I', 'B', 'O', 'W'}};
constexpr std::array<unsigned char, 4> kExtensionMagic{{'N', 'T', 'X', 'T'}};
constexpr std::uint16_t kVersion = 6u;
constexpr std::uint16_t kBaseVersion = 5u;
constexpr std::uint16_t kExtensionVersion = 1u;
constexpr std::uint16_t kExtensionFlags = 0u;
constexpr std::size_t kMaxWireBytes = 512u * 1024u;
constexpr std::size_t kMaxBaseV5Bytes = kMaxWireBytes;
constexpr std::size_t kOuterHeaderBytes = 4u + 2u + 4u;
constexpr std::size_t kExtensionHeaderBytes = 4u + 2u + 4u;
constexpr std::size_t kExtensionFixedBodyBytes = 16u;
constexpr std::size_t kEntryHeaderBytes = 8u;
constexpr std::size_t kEntryCount = 4u;

constexpr std::uint8_t kStateUnknown =
    static_cast<std::uint8_t>(owned::FieldState::unknown);
constexpr std::uint8_t kStateObserved =
    static_cast<std::uint8_t>(owned::FieldState::observed);
constexpr std::uint8_t kStateAbsent =
    static_cast<std::uint8_t>(owned::FieldState::absent);
constexpr std::uint8_t kSourceMessageMetadata =
    static_cast<std::uint8_t>(owned::SourceKind::message_metadata);
constexpr std::uint8_t kSourceTitleHelperCandidate =
    static_cast<std::uint8_t>(owned::SourceKind::title_helper_candidate);
constexpr std::uint8_t kSourceNativeLine1 =
    static_cast<std::uint8_t>(owned::SourceKind::native_line1);

enum class FieldId : std::uint8_t {
    definition_key = 1u,
    auxiliary_text = 2u,
    title_helper_candidate = 3u,
    line1_text = 4u,
};

struct EncodeResult final {
    std::size_t written_bytes = 0u;

    bool succeeded() const noexcept { return written_bytes != 0u; }
};

static_assert(std::is_trivially_copyable<EncodeResult>::value,
              "encode result must remain a value object");

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

inline std::uint16_t load_u16(const unsigned char* data) noexcept {
    return static_cast<std::uint16_t>(data[0])
        | (static_cast<std::uint16_t>(data[1]) << 8u);
}

inline std::uint32_t load_u32(const unsigned char* data) noexcept {
    return static_cast<std::uint32_t>(data[0])
        | (static_cast<std::uint32_t>(data[1]) << 8u)
        | (static_cast<std::uint32_t>(data[2]) << 16u)
        | (static_cast<std::uint32_t>(data[3]) << 24u);
}

inline std::int32_t load_i32(const unsigned char* data) noexcept {
    return static_cast<std::int32_t>(load_u32(data));
}

inline void put_u16(unsigned char*& output, std::uint16_t value) noexcept {
    output[0] = static_cast<unsigned char>(value & 0xffu);
    output[1] = static_cast<unsigned char>((value >> 8u) & 0xffu);
    output += 2u;
}

inline void put_u32(unsigned char*& output, std::uint32_t value) noexcept {
    for (unsigned index = 0u; index < 4u; ++index) {
        output[index] = static_cast<unsigned char>((value >> (index * 8u))
                                                    & 0xffu);
    }
    output += 4u;
}

inline void put_i32(unsigned char*& output, std::int32_t value) noexcept {
    put_u32(output, static_cast<std::uint32_t>(value));
}

inline bool equal_magic(const unsigned char* data,
                        const std::array<unsigned char, 4>& magic) noexcept {
    return std::memcmp(data, magic.data(), magic.size()) == 0;
}

inline bool valid_state(std::uint8_t value) noexcept {
    return value == kStateUnknown || value == kStateObserved
        || value == kStateAbsent;
}

inline bool valid_source(std::uint8_t value) noexcept {
    return value == kSourceMessageMetadata
        || value == kSourceTitleHelperCandidate
        || value == kSourceNativeLine1;
}

inline bool valid_base_v5(const unsigned char* data,
                          std::size_t size) noexcept {
    // This is an envelope check, not a second v5 semantic decoder.  The v5
    // decoder remains the owner of WARI identity semantics.
    if (data == nullptr || size < kOuterHeaderBytes + 4u + 35u
            || size > kMaxBaseV5Bytes
            || !equal_magic(data, kMagic)
            || load_u16(data + 4u) != kBaseVersion) {
        return false;
    }
    const std::size_t base_v4_bytes = load_u32(data + 6u);
    if (base_v4_bytes == 0u || base_v4_bytes > 256u * 1024u
            || base_v4_bytes > size - kOuterHeaderBytes) {
        return false;
    }
    const std::size_t base_v4 = kOuterHeaderBytes;
    if (base_v4_bytes < kOuterHeaderBytes
            || !equal_magic(data + base_v4, kMagic)
            || load_u16(data + base_v4 + 4u) != 4u) {
        return false;
    }
    const std::size_t wari = base_v4 + base_v4_bytes;
    if (wari > size || size - wari < 4u + 35u
            || !equal_magic(data + wari, std::array<unsigned char, 4>{{'W', 'A', 'R', 'I'}})) {
        return false;
    }
    const unsigned char* identity = data + wari + 4u;
    const std::uint8_t status = identity[0];
    if (status > 2u) {
        return false;
    }
    const std::uint8_t id_length = identity[34u];
    if (id_length > 29u) {
        return false;
    }
    const std::size_t expected = wari + 4u + 35u
        + static_cast<std::size_t>(id_length);
    return expected == size;
}

struct FieldView final {
    std::uint8_t id = 0u;
    std::uint8_t source = 0u;
    const owned::TextField* field = nullptr;
};

inline FieldView field_view(const owned::Snapshot& snapshot,
                            std::size_t index) noexcept {
    switch (index) {
    case 0u:
        return {static_cast<std::uint8_t>(FieldId::definition_key),
                kSourceMessageMetadata, &snapshot.definition_key};
    case 1u:
        return {static_cast<std::uint8_t>(FieldId::auxiliary_text),
                kSourceMessageMetadata, &snapshot.auxiliary_text};
    case 2u:
        return {static_cast<std::uint8_t>(FieldId::title_helper_candidate),
                kSourceTitleHelperCandidate,
                &snapshot.title_helper_candidate};
    case 3u:
        return {static_cast<std::uint8_t>(FieldId::line1_text),
                kSourceNativeLine1, &snapshot.native_line1};
    }
    return {};
}

inline bool snapshot_valid(const owned::Snapshot& snapshot,
                           std::size_t& arena_used) noexcept {
    if (!valid_state(static_cast<std::uint8_t>(snapshot.native_date_state))
            || !valid_state(static_cast<std::uint8_t>(snapshot.raw_flags_state))) {
        return false;
    }
    if (snapshot.native_date_state != owned::FieldState::observed
            && snapshot.native_date != 0) {
        return false;
    }
    if (snapshot.raw_flags_state != owned::FieldState::observed
            && (snapshot.raw_flag_8c != 0u || snapshot.raw_flag_8d != 0u)) {
        return false;
    }

    arena_used = 0u;
    for (std::size_t index = 0u; index < kEntryCount; ++index) {
        const FieldView view = field_view(snapshot, index);
        if (view.field == nullptr
                || static_cast<std::uint8_t>(view.field->source_kind)
                    != view.source
                || !valid_state(static_cast<std::uint8_t>(view.field->state))) {
            return false;
        }
        const std::size_t length = view.field->bytes.length;
        const std::size_t offset = view.field->bytes.offset;
        const std::size_t max_length = index == 0u
            ? owned::kMaxKeyBytes : owned::kMaxTextBytes;
        if (length > max_length
                || offset > owned::kMaxArenaBytes
                || length > owned::kMaxArenaBytes - offset) {
            return false;
        }
        if (view.field->state != owned::FieldState::observed
                && (offset != 0u || length != 0u)) {
            return false;
        }
        const std::size_t end = offset + length;
        if (end > arena_used) {
            arena_used = end;
        }
    }
    return true;
}

inline bool extension_body_size(const owned::Snapshot& snapshot,
                                std::size_t& body_size) noexcept {
    std::size_t used = 0u;
    if (!snapshot_valid(snapshot, used)) {
        return false;
    }
    body_size = kExtensionFixedBodyBytes;
    for (std::size_t index = 0u; index < kEntryCount; ++index) {
        const FieldView view = field_view(snapshot, index);
        std::size_t next = 0u;
        if (!checked_add(body_size, kEntryHeaderBytes, next)
                || !checked_add(next, view.field->bytes.length, body_size)) {
            return false;
        }
    }
    return body_size <= static_cast<std::size_t>(
        (std::numeric_limits<std::uint32_t>::max)());
}

inline bool total_size(const unsigned char* base_v5,
                       std::size_t base_v5_bytes,
                       const owned::Snapshot& snapshot,
                       std::size_t& required) noexcept {
    std::size_t body = 0u;
    if (!valid_base_v5(base_v5, base_v5_bytes)
            || !extension_body_size(snapshot, body)) {
        return false;
    }
    required = kOuterHeaderBytes;
    if (!checked_add(required, base_v5_bytes, required)
            || !checked_add(required, kExtensionHeaderBytes, required)
            || !checked_add(required, body, required)
            || required > kMaxWireBytes) {
        return false;
    }
    return true;
}

}  // namespace detail

inline std::size_t encoded_size(const unsigned char* base_v5,
                                std::size_t base_v5_bytes,
                                const owned::Snapshot& snapshot) noexcept {
    std::size_t required = 0u;
    return detail::total_size(base_v5, base_v5_bytes, snapshot, required)
        ? required : 0u;
}

inline EncodeResult encode(const unsigned char* base_v5,
                           std::size_t base_v5_bytes,
                           const owned::Snapshot& snapshot,
                           unsigned char* output,
                           std::size_t capacity) noexcept {
    // The native path accepts a producer-constructed raw v5 base and checks
    // only its bounded framing.  It is not a semantic v5 decoder; callers
    // that expose a public composed result must validate the base through the
    // established v5 decoder before invoking this encoder.
    std::size_t required = 0u;
    if (!detail::total_size(base_v5, base_v5_bytes, snapshot, required)
            || output == nullptr || capacity < required) {
        return {};
    }
    Address output_begin = 0u, output_end = 0u;
    Address base_begin = 0u, base_end = 0u;
    Address snapshot_begin = 0u, snapshot_end = 0u;
    if (!detail::pointer_range(output, required, output_begin, output_end)
            || !detail::pointer_range(base_v5, base_v5_bytes,
                                      base_begin, base_end)
            || !detail::pointer_range(&snapshot, sizeof(snapshot),
                                      snapshot_begin, snapshot_end)
            || detail::overlaps(output_begin, output_end, base_begin, base_end)
            || detail::overlaps(output_begin, output_end,
                                snapshot_begin, snapshot_end)) {
        return {};
    }

    std::size_t body_bytes = 0u;
    if (!detail::extension_body_size(snapshot, body_bytes)) {
        return {};
    }
    unsigned char* cursor = output;
    std::memcpy(cursor, kMagic.data(), kMagic.size());
    cursor += kMagic.size();
    detail::put_u16(cursor, kVersion);
    detail::put_u32(cursor, static_cast<std::uint32_t>(base_v5_bytes));
    std::memcpy(cursor, base_v5, base_v5_bytes);
    cursor += base_v5_bytes;
    std::memcpy(cursor, kExtensionMagic.data(), kExtensionMagic.size());
    cursor += kExtensionMagic.size();
    detail::put_u16(cursor, kExtensionVersion);
    detail::put_u32(cursor, static_cast<std::uint32_t>(body_bytes));
    detail::put_u16(cursor, kExtensionFlags);
    detail::put_u16(cursor, 0u);  // reserved
    *cursor++ = static_cast<unsigned char>(snapshot.native_date_state);
    *cursor++ = static_cast<unsigned char>(snapshot.raw_flags_state);
    *cursor++ = static_cast<unsigned char>(kEntryCount);
    *cursor++ = 0u;  // reserved
    detail::put_i32(cursor, snapshot.native_date_state
        == owned::FieldState::observed ? snapshot.native_date : 0);
    *cursor++ = snapshot.raw_flags_state == owned::FieldState::observed
        ? snapshot.raw_flag_8c : 0u;
    *cursor++ = snapshot.raw_flags_state == owned::FieldState::observed
        ? snapshot.raw_flag_8d : 0u;
    detail::put_u16(cursor, 0u);  // reserved
    for (std::size_t index = 0u; index < kEntryCount; ++index) {
        const detail::FieldView view = detail::field_view(snapshot, index);
        *cursor++ = view.id;
        *cursor++ = static_cast<unsigned char>(view.field->state);
        *cursor++ = view.source;
        *cursor++ = 0u;
        detail::put_u32(cursor, view.field->bytes.length);
        if (view.field->bytes.length != 0u) {
            std::memcpy(cursor, snapshot.arena.data()
                            + view.field->bytes.offset,
                        view.field->bytes.length);
            cursor += view.field->bytes.length;
        }
    }
    return EncodeResult{required};
}

inline bool validate(const unsigned char* data, std::size_t size) noexcept {
    if (data == nullptr || size < kOuterHeaderBytes + kExtensionHeaderBytes
            || size > kMaxWireBytes || !detail::equal_magic(data, kMagic)
            || detail::load_u16(data + 4u) != kVersion) {
        return false;
    }
    const std::size_t base_bytes = detail::load_u32(data + 6u);
    if (base_bytes == 0u || base_bytes > size - kOuterHeaderBytes) {
        return false;
    }
    const std::size_t extension = kOuterHeaderBytes + base_bytes;
    if (!detail::valid_base_v5(data + kOuterHeaderBytes, base_bytes)
            || extension > size
            || size - extension < kExtensionHeaderBytes
            || !detail::equal_magic(data + extension, kExtensionMagic)) {
        return false;
    }
    const std::size_t version = detail::load_u16(data + extension + 4u);
    const std::size_t body_bytes = detail::load_u32(data + extension + 6u);
    const std::size_t body = extension + kExtensionHeaderBytes;
    if (version != kExtensionVersion || body_bytes != size - body
            || body_bytes < kExtensionFixedBodyBytes) {
        return false;
    }
    const unsigned char* cursor = data + body;
    const unsigned char* end = cursor + body_bytes;
    if (detail::load_u16(cursor) != kExtensionFlags
            || detail::load_u16(cursor + 2u) != 0u
            || !detail::valid_state(cursor[4u])
            || !detail::valid_state(cursor[5u])
            || cursor[6u] != kEntryCount || cursor[7u] != 0u
            || detail::load_u16(cursor + 14u) != 0u) {
        return false;
    }
    const std::uint8_t date_state = cursor[4u];
    const std::uint8_t flags_state = cursor[5u];
    const std::int32_t date = detail::load_i32(cursor + 8u);
    const std::uint8_t flag_8c = cursor[12u];
    const std::uint8_t flag_8d = cursor[13u];
    if ((date_state != kStateObserved && date != 0)
            || (flags_state != kStateObserved
                && (flag_8c != 0u || flag_8d != 0u))) {
        return false;
    }
    cursor += kExtensionFixedBodyBytes;
    for (std::size_t index = 0u; index < kEntryCount; ++index) {
        if (static_cast<std::size_t>(end - cursor) < kEntryHeaderBytes) {
            return false;
        }
        const std::uint8_t id = cursor[0u];
        const std::uint8_t state = cursor[1u];
        const std::uint8_t source = cursor[2u];
        if (id != static_cast<std::uint8_t>(index + 1u)
                || !detail::valid_state(state)
                || !detail::valid_source(source)
                || cursor[3u] != 0u) {
            return false;
        }
        const std::uint8_t expected_source = index < 2u
            ? kSourceMessageMetadata
            : (index == 2u ? kSourceTitleHelperCandidate
                           : kSourceNativeLine1);
        if (source != expected_source) {
            return false;
        }
        const std::size_t length = detail::load_u32(cursor + 4u);
        const std::size_t max_length = index == 0u
            ? owned::kMaxKeyBytes : owned::kMaxTextBytes;
        if (length > max_length
                || (state != kStateObserved && length != 0u)
                || length > static_cast<std::size_t>(end - cursor - kEntryHeaderBytes)) {
            return false;
        }
        cursor += kEntryHeaderBytes + length;
    }
    return cursor == end;
}

}  // namespace information::battle::native_text_wire

#endif  // INFORMATION_BATTLE_NATIVE_TEXT_WIRE_H
