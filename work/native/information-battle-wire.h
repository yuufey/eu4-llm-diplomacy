#ifndef INFORMATION_BATTLE_WIRE_H
#define INFORMATION_BATTLE_WIRE_H

#include "information-battle-buffer.h"

#include <cstddef>
#include <cstdint>
#include <limits>

// Deterministic JSONL transport for one opaque OwnedByteQueue::Record.
//
// The encoder never allocates, never interprets the payload, and never calls
// a game/native function.  The output buffer is caller-owned.  A successful
// call writes one complete JSON object, a newline, and a trailing NUL.  The
// returned written_bytes includes the newline but excludes that NUL.  The
// required capacity therefore is written_bytes + 1.
//
// This is only a byte transport.  payload_hex is an opaque copy of Record's
// bytes; it is not a claim that the bytes form a complete battle report, a
// decoded text value, or a pointer-free native object.
namespace information::battle {

enum class WireError : std::uint8_t {
    ok,
    invalid_identity,
    invalid_sequence,
    empty_payload,
    oversize_payload,
    null_output,
    insufficient_capacity,
    output_range_overflow,
    overlapping_input,
};

struct WireResult final {
    std::size_t written_bytes = 0; // excludes the trailing NUL
    WireError error = WireError::ok;

    constexpr bool succeeded() const noexcept {
        return error == WireError::ok;
    }
};

namespace wire_detail {

constexpr char kStart[] =
    "{\"event\":\"information_owned_battle_record\",\"wire_version\":1,\"installation\":\"";
constexpr char kAfterInstallation[] =
    "\",\"world_generation\":\"";
constexpr char kAfterGeneration[] =
    "\",\"attempt_sequence\":\"";
constexpr char kAfterSequence[] =
    "\",\"payload_encoding\":\"hex\",\"payload_bytes\":";
constexpr char kAfterPayloadBytes[] =
    ",\"payload_hex\":\"";
constexpr char kEnd[] = "\"}\n";
constexpr char kHex[] = "0123456789abcdef";

template <std::size_t N>
constexpr std::size_t literal_bytes(const char (&)[N]) noexcept {
    return N - 1;
}

inline std::size_t decimal_digits(std::uint64_t value) noexcept {
    std::size_t result = 1;
    while (value >= 10) {
        value /= 10;
        ++result;
    }
    return result;
}

inline WireError validate(const Record& record) noexcept {
    if (!record.identity.valid()) {
        return WireError::invalid_identity;
    }
    if (record.attempt_sequence == 0) {
        return WireError::invalid_sequence;
    }
    if (record.size == 0) {
        return WireError::empty_payload;
    }
    if (record.size > OwnedByteQueue::max_payload_bytes) {
        return WireError::oversize_payload;
    }
    return WireError::ok;
}

// The encoder reads Record while it writes the caller buffer.  Treat any
// overlap with the complete input Record as an error, including an output
// pointer into payload.  Integer ranges are used instead of relational
// comparisons on unrelated C++ pointers; both additions are checked before
// they are performed.
inline WireError check_output_range(const Record& record, const char* output,
                                    std::size_t bytes) noexcept {
    const std::uintptr_t maximum =
        (std::numeric_limits<std::uintptr_t>::max)();
    const std::uintptr_t output_begin =
        reinterpret_cast<std::uintptr_t>(output);
    const std::uintptr_t record_begin =
        reinterpret_cast<std::uintptr_t>(&record);
    const std::uintptr_t record_size =
        static_cast<std::uintptr_t>(sizeof(Record));
    const std::size_t maximum_size = static_cast<std::size_t>(maximum);
    if (bytes > maximum_size || sizeof(Record) > maximum_size
        || static_cast<std::uintptr_t>(bytes) > maximum - output_begin
        || record_size > maximum - record_begin) {
        return WireError::output_range_overflow;
    }
    const std::uintptr_t output_end =
        output_begin + static_cast<std::uintptr_t>(bytes);
    const std::uintptr_t record_end = record_begin + record_size;
    if (output_begin < record_end && record_begin < output_end) {
        return WireError::overlapping_input;
    }
    return WireError::ok;
}

inline std::size_t written_bytes_for_valid(const Record& record) noexcept {
    return literal_bytes(kStart)
        + 16
        + literal_bytes(kAfterInstallation)
        + 16
        + literal_bytes(kAfterGeneration)
        + decimal_digits(record.attempt_sequence)
        + literal_bytes(kAfterSequence)
        + decimal_digits(record.size)
        + literal_bytes(kAfterPayloadBytes)
        + static_cast<std::size_t>(record.size) * 2
        + literal_bytes(kEnd);
}

inline std::size_t append_literal(char* output, std::size_t cursor,
                                  const char* literal,
                                  std::size_t length) noexcept {
    for (std::size_t index = 0; index < length; ++index) {
        output[cursor++] = literal[index];
    }
    return cursor;
}

template <std::size_t N>
inline std::size_t append_literal(char* output, std::size_t cursor,
                                  const char (&literal)[N]) noexcept {
    return append_literal(output, cursor, literal, N - 1);
}

inline std::size_t append_fixed_hex(char* output, std::size_t cursor,
                                    std::uint64_t value) noexcept {
    for (unsigned shift = 60; ; shift -= 4) {
        output[cursor++] = kHex[(value >> shift) & 0x0fU];
        if (shift == 0) {
            break;
        }
    }
    return cursor;
}

inline std::size_t append_decimal(char* output, std::size_t cursor,
                                  std::uint64_t value) noexcept {
    char digits[20]{};
    std::size_t count = 0;
    do {
        digits[count++] = static_cast<char>('0' + (value % 10));
        value /= 10;
    } while (value != 0);
    while (count != 0) {
        output[cursor++] = digits[--count];
    }
    return cursor;
}

inline std::size_t append_payload_hex(char* output, std::size_t cursor,
                                      const Record& record) noexcept {
    for (std::size_t index = 0; index < record.size; ++index) {
        const std::uint8_t value = record.payload[index];
        output[cursor++] = kHex[(value >> 4) & 0x0fU];
        output[cursor++] = kHex[value & 0x0fU];
    }
    return cursor;
}

} // namespace wire_detail

constexpr std::size_t kBattleWireMaxWrittenBytes =
    (sizeof(wire_detail::kStart) - 1)
    + 16
    + (sizeof(wire_detail::kAfterInstallation) - 1)
    + 16
    + (sizeof(wire_detail::kAfterGeneration) - 1)
    + 20
    + (sizeof(wire_detail::kAfterSequence) - 1)
    + 4
    + (sizeof(wire_detail::kAfterPayloadBytes) - 1)
    + (OwnedByteQueue::max_payload_bytes * 2)
    + (sizeof(wire_detail::kEnd) - 1);

// Includes the trailing NUL required by encode_jsonl().
constexpr std::size_t kBattleWireMaxCapacity =
    kBattleWireMaxWrittenBytes + 1;

static_assert(kBattleWireMaxCapacity < 16384,
              "wire output must remain a small fixed budget");

// Returns the exact caller-buffer capacity for this record, including the
// trailing NUL.  Invalid records return zero.
inline std::size_t required_capacity(const Record& record) noexcept {
    if (wire_detail::validate(record) != WireError::ok) {
        return 0;
    }
    return wire_detail::written_bytes_for_valid(record) + 1;
}

constexpr std::size_t max_required_capacity() noexcept {
    return kBattleWireMaxCapacity;
}

inline WireResult encode_jsonl(const Record& record, char* output,
                               std::size_t capacity) noexcept {
    const WireError validation = wire_detail::validate(record);
    if (validation != WireError::ok) {
        return {0, validation};
    }
    if (output == nullptr) {
        return {0, WireError::null_output};
    }

    const std::size_t required = required_capacity(record);
    const WireError range_error = wire_detail::check_output_range(
        record, output, required);
    if (range_error != WireError::ok) {
        return {0, range_error};
    }
    if (capacity < required) {
        // No output byte is touched before this check, so a short buffer
        // cannot contain a partially usable JSON line.
        return {0, WireError::insufficient_capacity};
    }

    std::size_t cursor = 0;
    cursor = wire_detail::append_literal(output, cursor,
                                         wire_detail::kStart);
    cursor = wire_detail::append_fixed_hex(output, cursor,
                                           record.identity.installation);
    cursor = wire_detail::append_literal(output, cursor,
                                         wire_detail::kAfterInstallation);
    cursor = wire_detail::append_fixed_hex(output, cursor,
                                           record.identity.generation);
    cursor = wire_detail::append_literal(output, cursor,
                                         wire_detail::kAfterGeneration);
    cursor = wire_detail::append_decimal(output, cursor,
                                         record.attempt_sequence);
    cursor = wire_detail::append_literal(output, cursor,
                                         wire_detail::kAfterSequence);
    cursor = wire_detail::append_decimal(output, cursor, record.size);
    cursor = wire_detail::append_literal(output, cursor,
                                         wire_detail::kAfterPayloadBytes);
    cursor = wire_detail::append_payload_hex(output, cursor, record);
    cursor = wire_detail::append_literal(output, cursor, wire_detail::kEnd);

    // The preflight calculation makes this assertion a fixed arithmetic
    // invariant.  Keep the output contract explicit at the write boundary.
    output[cursor] = '\0';
    return {cursor, WireError::ok};
}

inline const char* wire_error_name(WireError error) noexcept {
    switch (error) {
    case WireError::ok: return "ok";
    case WireError::invalid_identity: return "invalid_identity";
    case WireError::invalid_sequence: return "invalid_sequence";
    case WireError::empty_payload: return "empty_payload";
    case WireError::oversize_payload: return "oversize_payload";
    case WireError::null_output: return "null_output";
    case WireError::insufficient_capacity: return "insufficient_capacity";
    case WireError::output_range_overflow: return "output_range_overflow";
    case WireError::overlapping_input: return "overlapping_input";
    }
    return "unknown";
}

} // namespace information::battle

#endif // INFORMATION_BATTLE_WIRE_H
