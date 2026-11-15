#ifndef INFORMATION_BATTLE_OWNED_SUMMARY_H
#define INFORMATION_BATTLE_OWNED_SUMMARY_H

// Research-only bounded copy of the summary bytes observed by the fixed-build
// static field survey.  The component does not call game code, allocate, do
// I/O, retain a source pointer, or assign units/roles/visibility semantics.
// The caller supplies a safe read seam for its execution context.

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <type_traits>

namespace information::battle::owned_summary {

using Address = std::uintptr_t;

constexpr Address kMinCanonicalAddress = UINT64_C(0x10000);
constexpr Address kMaxCanonicalExclusive = UINT64_C(0x800000000000);
constexpr std::size_t kMaxSingleReadBytes = 256u;
constexpr std::size_t kMaxReadBudgetBytes = 256u;
constexpr std::size_t kSummaryBaseOffset = 0x20u;
constexpr std::size_t kSummaryControlOffset = 0x4cu;
constexpr std::size_t kSummaryReadBytes = 0x2du;  // [0x20, 0x4d)

constexpr std::array<std::size_t, 11> kRawFieldOffsets{{
    0x20u, 0x24u, 0x28u, 0x2cu, 0x30u, 0x34u,
    0x38u, 0x3cu, 0x40u, 0x44u, 0x48u,
}};

static_assert(kRawFieldOffsets.size() == 11u,
              "the surveyed summary has eleven signed raw integers");
static_assert(kRawFieldOffsets.front() == kSummaryBaseOffset,
              "summary copy must begin at the surveyed base offset");
static_assert(kRawFieldOffsets.back() + sizeof(std::int32_t)
                  == kSummaryControlOffset,
              "the control byte must follow the last surveyed integer");
static_assert(kSummaryControlOffset - kSummaryBaseOffset + 1u
                  == kSummaryReadBytes,
              "contiguous read span must end after the surveyed control byte");
static_assert(kSummaryReadBytes <= kMaxReadBudgetBytes,
              "summary copy must remain inside the total read budget");

struct Snapshot {
    // These are raw native values.  No unit, side, visibility, kind, or
    // business-event interpretation is represented here.
    std::array<std::int32_t, kRawFieldOffsets.size()> raw_i32{};
    std::uint8_t control_byte = 0;
};

static_assert(std::is_trivially_copyable<Snapshot>::value,
              "snapshot must remain a plain value object");

namespace detail {

inline bool checked_range(Address begin, std::size_t size,
                          Address& end) noexcept {
    if (size == 0u || size > kMaxSingleReadBytes) {
        return false;
    }
    const Address max_value = std::numeric_limits<Address>::max();
    if (begin > max_value - static_cast<Address>(size)) {
        return false;
    }
    end = begin + static_cast<Address>(size);
    return begin >= kMinCanonicalAddress
        && end <= kMaxCanonicalExclusive
        && end > begin;
}

inline bool checked_add(Address left, Address right,
                        Address& result) noexcept {
    const Address max_value = std::numeric_limits<Address>::max();
    if (left > max_value - right) {
        return false;
    }
    result = left + right;
    return true;
}

inline bool ranges_overlap(Address left_begin, Address left_end,
                           Address right_begin, Address right_end) noexcept {
    return left_begin < right_end && right_begin < left_end;
}

inline bool output_range(const Snapshot& output, Address& begin,
                         Address& end) noexcept {
    begin = reinterpret_cast<Address>(&output);
    const Address max_value = std::numeric_limits<Address>::max();
    if (begin > max_value - static_cast<Address>(sizeof(output))) {
        return false;
    }
    end = begin + static_cast<Address>(sizeof(output));
    return end > begin;
}

inline std::int32_t load_i32(const unsigned char* data) noexcept {
    std::int32_t value = 0;
    std::memcpy(&value, data, sizeof(value));
    return value;
}

}  // namespace detail

template <typename Reader, typename = void>
struct reader_contract : std::false_type {};

template <typename Reader>
struct reader_contract<Reader, std::void_t<decltype(&Reader::read)>>
    : std::is_same<decltype(&Reader::read),
                   bool (Reader::*)(Address, unsigned char*, std::size_t) noexcept> {};

// Reader must expose exactly:
//   bool read(uintptr_t, unsigned char*, size_t) noexcept;
// A successful capture performs one 45-byte copy.  The local byte buffer and
// candidate snapshot are bounded automatic storage; only the raw values above
// are committed to the caller's output after every check succeeds.
template <typename Reader>
bool capture(Reader& reader, Address summary_ptr,
             Snapshot& output) noexcept {
    static_assert(reader_contract<Reader>::value,
                  "Reader::read must be bool(Address,unsigned char*,size_t) noexcept");

    Address output_begin = 0;
    Address output_end = 0;
    if (!detail::output_range(output, output_begin, output_end)) {
        return false;
    }

    Address summary_end = 0;
    if (!detail::checked_range(summary_ptr, kSummaryControlOffset + 1u,
                               summary_end)) {
        return false;
    }

    Address source_begin = 0;
    if (!detail::checked_add(summary_ptr, kSummaryBaseOffset, source_begin)) {
        return false;
    }
    Address source_end = 0;
    if (!detail::checked_range(source_begin, kSummaryReadBytes, source_end)) {
        return false;
    }
    if (detail::ranges_overlap(source_begin, source_end,
                               output_begin, output_end)) {
        return false;
    }

    if (kSummaryReadBytes > kMaxReadBudgetBytes) {
        return false;
    }

    std::array<unsigned char, kSummaryReadBytes> bytes{};
    if (!reader.read(source_begin, bytes.data(), bytes.size())) {
        return false;
    }

    Snapshot candidate{};
    for (std::size_t index = 0; index < kRawFieldOffsets.size(); ++index) {
        const std::size_t local_offset =
            kRawFieldOffsets[index] - kSummaryBaseOffset;
        candidate.raw_i32[index] = detail::load_i32(bytes.data() + local_offset);
    }
    // Keep the control byte as an independent raw value.  It is deliberately
    // read from the final byte rather than inferred from a branch condition.
    candidate.control_byte = bytes[kSummaryControlOffset - kSummaryBaseOffset];
    output = candidate;
    return true;
}

}  // namespace information::battle::owned_summary

#endif  // INFORMATION_BATTLE_OWNED_SUMMARY_H
