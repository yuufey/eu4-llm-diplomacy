#ifndef INFORMATION_BATTLE_FRAGMENT_H
#define INFORMATION_BATTLE_FRAGMENT_H

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>

// Fixed, allocation-free multipart framing for an opaque owned byte payload.
//
// The codec does not retain the input pointer and does not call game/native
// code.  The caller must keep the complete immutable payload alive while it
// encodes every fragment.  The CRC is an accidental-integrity check only; it
// is not a cryptographic authentication code and does not make a group
// atomic.  A receiver must retain a group gap until every canonical index is
// present and validated.
namespace information::battle::fragment {

constexpr std::size_t kHeaderBytes = 64;
constexpr std::size_t kChunkBytes = 4032;
constexpr std::size_t kMaxMessageBytes = 1024 * 1024;
constexpr std::size_t kMaxFragmentWireBytes = kHeaderBytes + kChunkBytes;
constexpr std::uint16_t kHeaderSize = 64;
constexpr std::uint16_t kReservedFlags = 0;
constexpr std::uint32_t kChunkCapacity = 4032;

constexpr char kMagic[8] = {'E', 'U', '4', 'B', 'F', 'R', 'G', '1'};

static_assert(kHeaderBytes == kHeaderSize,
              "wire header size must remain fixed at 64 bytes");
static_assert(kChunkBytes == kChunkCapacity,
              "wire chunk capacity must remain fixed at 4032 bytes");
static_assert(kMaxFragmentWireBytes <= 4096,
              "one fragment must fit the existing Record payload");

enum class PrepareStatus : std::uint8_t {
    ok,
    invalid_message_id,
    null_input,
    empty_input,
    oversize_input,
    input_range_overflow,
    plan_input_overlap,
};

struct FragmentPlan final {
    std::uint64_t message_id = 0;
    std::uint32_t total_bytes = 0;
    std::uint32_t fragment_count = 0;
    std::uint32_t chunk_capacity = kChunkCapacity;
    std::uint32_t whole_message_crc32 = 0;
};

struct PrepareResult final {
    PrepareStatus status = PrepareStatus::invalid_message_id;

    constexpr bool succeeded() const noexcept {
        return status == PrepareStatus::ok;
    }
};

enum class EncodeStatus : std::uint8_t {
    ok,
    invalid_plan,
    size_mismatch,
    null_input,
    null_output,
    invalid_index,
    insufficient_capacity,
    input_range_overflow,
    output_range_overflow,
    plan_output_overlap,
    input_output_overlap,
};

struct EncodeResult final {
    std::size_t written_bytes = 0;
    EncodeStatus status = EncodeStatus::invalid_plan;

    constexpr bool succeeded() const noexcept {
        return status == EncodeStatus::ok;
    }
};

namespace detail {

inline bool fits_uintptr(std::size_t value) noexcept {
    return static_cast<std::uintmax_t>(value)
        <= static_cast<std::uintmax_t>(
            (std::numeric_limits<std::uintptr_t>::max)());
}

inline bool pointer_range(const void* pointer, std::size_t bytes,
                          std::uintptr_t& begin,
                          std::uintptr_t& end) noexcept {
    if (pointer == nullptr || !fits_uintptr(bytes)) {
        return false;
    }
    begin = reinterpret_cast<std::uintptr_t>(pointer);
    const std::uintptr_t span = static_cast<std::uintptr_t>(bytes);
    const std::uintptr_t maximum =
        (std::numeric_limits<std::uintptr_t>::max)();
    if (span > maximum - begin) {
        return false;
    }
    end = begin + span;
    return true;
}

inline bool ranges_overlap(std::uintptr_t left_begin,
                           std::uintptr_t left_end,
                           std::uintptr_t right_begin,
                           std::uintptr_t right_end) noexcept {
    return left_begin < right_end && right_begin < left_end;
}

inline std::uint32_t fragment_count_for(std::uint32_t total) noexcept {
    return (total + kChunkCapacity - 1U) / kChunkCapacity;
}

inline std::uint32_t fragment_bytes_for(std::uint32_t total,
                                        std::uint32_t index) noexcept {
    const std::uint32_t offset = index * kChunkCapacity;
    const std::uint32_t remaining = total - offset;
    return remaining < kChunkCapacity ? remaining : kChunkCapacity;
}

inline std::uint32_t crc32(const std::uint8_t* bytes,
                           std::size_t size) noexcept {
    std::uint32_t value = 0xffffffffU;
    for (std::size_t index = 0; index < size; ++index) {
        value ^= bytes[index];
        for (unsigned bit = 0; bit < 8; ++bit) {
            const std::uint32_t mask =
                static_cast<std::uint32_t>(-(value & 1U));
            value = (value >> 1U) ^ (0xedb88320U & mask);
        }
    }
    return value ^ 0xffffffffU;
}

inline bool canonical_plan(const FragmentPlan& plan) noexcept {
    if (plan.message_id == 0
        || plan.total_bytes == 0
        || plan.total_bytes > kMaxMessageBytes
        || plan.chunk_capacity != kChunkCapacity) {
        return false;
    }
    const std::uint32_t expected_count =
        fragment_count_for(plan.total_bytes);
    return plan.fragment_count == expected_count
        && plan.fragment_count != 0;
}

inline void put_u16(std::uint8_t* output, std::size_t offset,
                    std::uint16_t value) noexcept {
    output[offset] = static_cast<std::uint8_t>(value & 0xffU);
    output[offset + 1] = static_cast<std::uint8_t>((value >> 8U) & 0xffU);
}

inline void put_u32(std::uint8_t* output, std::size_t offset,
                    std::uint32_t value) noexcept {
    for (unsigned byte = 0; byte < 4; ++byte) {
        output[offset + byte] = static_cast<std::uint8_t>(
            (value >> (byte * 8U)) & 0xffU);
    }
}

inline void put_u64(std::uint8_t* output, std::size_t offset,
                    std::uint64_t value) noexcept {
    for (unsigned byte = 0; byte < 8; ++byte) {
        output[offset + byte] = static_cast<std::uint8_t>(
            (value >> (byte * 8U)) & 0xffU);
    }
}

} // namespace detail

// Computes the whole-message CRC in one bounded pass and publishes a plan
// only after all validation succeeds.  The plan contains no source pointer.
inline PrepareResult prepare(FragmentPlan& output, std::uint64_t message_id,
                             const void* full_input,
                             std::size_t total_bytes) noexcept {
    if (message_id == 0) {
        return {PrepareStatus::invalid_message_id};
    }
    if (full_input == nullptr) {
        return {PrepareStatus::null_input};
    }
    if (total_bytes == 0) {
        return {PrepareStatus::empty_input};
    }
    if (total_bytes > kMaxMessageBytes) {
        return {PrepareStatus::oversize_input};
    }

    std::uintptr_t input_begin = 0;
    std::uintptr_t input_end = 0;
    if (!detail::pointer_range(full_input, total_bytes, input_begin,
                               input_end)) {
        return {PrepareStatus::input_range_overflow};
    }
    std::uintptr_t plan_begin = 0;
    std::uintptr_t plan_end = 0;
    if (!detail::pointer_range(&output, sizeof(output), plan_begin, plan_end)) {
        return {PrepareStatus::input_range_overflow};
    }
    if (detail::ranges_overlap(input_begin, input_end, plan_begin, plan_end)) {
        return {PrepareStatus::plan_input_overlap};
    }

    // This is deliberately the only whole-input traversal performed by
    // prepare().  encode() uses the stored CRC and never recomputes it.
    const auto* bytes = static_cast<const std::uint8_t*>(full_input);
    const std::uint32_t crc = detail::crc32(bytes, total_bytes);
    FragmentPlan candidate{};
    candidate.message_id = message_id;
    candidate.total_bytes = static_cast<std::uint32_t>(total_bytes);
    candidate.fragment_count = detail::fragment_count_for(candidate.total_bytes);
    candidate.chunk_capacity = kChunkCapacity;
    candidate.whole_message_crc32 = crc;
    output = candidate;
    return {PrepareStatus::ok};
}

inline EncodeResult encode(const FragmentPlan& plan, const void* full_input,
                           std::size_t total_bytes, std::uint32_t index,
                           void* output, std::size_t output_capacity) noexcept {
    // Copy the plan before any output mutation and reject output overlap with
    // the caller-owned plan object.  This makes aliasing deterministic and
    // keeps every failure path at written_bytes == 0.
    const FragmentPlan snapshot = plan;
    if (!detail::canonical_plan(snapshot)) {
        return {0, EncodeStatus::invalid_plan};
    }
    if (total_bytes != snapshot.total_bytes) {
        return {0, EncodeStatus::size_mismatch};
    }
    if (index >= snapshot.fragment_count) {
        return {0, EncodeStatus::invalid_index};
    }
    if (full_input == nullptr) {
        return {0, EncodeStatus::null_input};
    }

    const std::uint32_t fragment_bytes =
        detail::fragment_bytes_for(snapshot.total_bytes, index);
    const std::size_t required = kHeaderBytes
        + static_cast<std::size_t>(fragment_bytes);
    if (output_capacity < required) {
        return {0, EncodeStatus::insufficient_capacity};
    }
    if (output == nullptr) {
        return {0, EncodeStatus::null_output};
    }

    std::uintptr_t input_begin = 0;
    std::uintptr_t input_end = 0;
    if (!detail::pointer_range(full_input, total_bytes, input_begin,
                               input_end)) {
        return {0, EncodeStatus::input_range_overflow};
    }
    std::uintptr_t output_begin = 0;
    std::uintptr_t output_end = 0;
    if (!detail::pointer_range(output, required, output_begin, output_end)) {
        return {0, EncodeStatus::output_range_overflow};
    }
    std::uintptr_t plan_begin = 0;
    std::uintptr_t plan_end = 0;
    if (!detail::pointer_range(&plan, sizeof(plan), plan_begin, plan_end)) {
        return {0, EncodeStatus::output_range_overflow};
    }
    if (detail::ranges_overlap(output_begin, output_end,
                               plan_begin, plan_end)) {
        return {0, EncodeStatus::plan_output_overlap};
    }
    if (detail::ranges_overlap(output_begin, output_end,
                               input_begin, input_end)) {
        return {0, EncodeStatus::input_output_overlap};
    }

    auto* bytes = static_cast<std::uint8_t*>(output);
    std::memset(bytes, 0, required);
    std::memcpy(bytes, kMagic, sizeof(kMagic));
    detail::put_u16(bytes, 8, kHeaderSize);
    detail::put_u16(bytes, 10, kReservedFlags);
    detail::put_u64(bytes, 12, snapshot.message_id);
    detail::put_u32(bytes, 20, snapshot.total_bytes);
    detail::put_u32(bytes, 24, index);
    detail::put_u32(bytes, 28, snapshot.fragment_count);
    detail::put_u32(bytes, 32, fragment_bytes);
    detail::put_u32(bytes, 36, kChunkCapacity);
    detail::put_u32(bytes, 40, snapshot.whole_message_crc32);

    const auto* source = static_cast<const std::uint8_t*>(full_input);
    const std::size_t offset = static_cast<std::size_t>(index)
        * kChunkCapacity;
    std::memcpy(bytes + kHeaderBytes, source + offset, fragment_bytes);
    return {required, EncodeStatus::ok};
}

} // namespace information::battle::fragment

#endif // INFORMATION_BATTLE_FRAGMENT_H
