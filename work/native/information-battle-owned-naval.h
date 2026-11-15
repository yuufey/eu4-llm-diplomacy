#ifndef INFORMATION_BATTLE_OWNED_NAVAL_H
#define INFORMATION_BATTLE_OWNED_NAVAL_H

// Research-only bounded copy of the raw naval loss lanes and participant type
// rows observed by the fixed-build static survey.  This component never calls
// game code, allocates, performs I/O, or keeps a source pointer.  The caller
// supplies a safe read seam for its execution context.  The values remain raw:
// no ship, side, visibility, winner, or business-event meaning is assigned.

#include "information-battle-owned-summary.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <type_traits>

namespace information::battle::owned_naval {

using Address = std::uintptr_t;

constexpr Address kMinCanonicalAddress = UINT64_C(0x10000);
constexpr Address kMaxCanonicalExclusive = UINT64_C(0x800000000000);
constexpr std::size_t kMaxRows = 256u;
constexpr std::size_t kMaxSingleReadBytes = 64u * 1024u;
constexpr std::size_t kMaxReadBudgetBytes = 64u * 1024u;
constexpr std::size_t kCombatSidePointerOffset = 0x20u;
constexpr std::size_t kCombatSidePointerBytes = 0x10u;
constexpr std::size_t kSideLossOffset = 0x140u;
constexpr std::size_t kSideLossBytes = 0x2au;  // includes raw gate at +0x169
constexpr std::size_t kSideGateOffset = 0x169u - kSideLossOffset;
constexpr std::size_t kSummaryBeginOffset = 0x00u;
constexpr std::size_t kSummaryEndOffset = 0x08u;
constexpr std::size_t kSummaryHeaderBytes = 0x10u;
constexpr std::size_t kSummaryBaseOffset = 0x20u;
constexpr std::size_t kSummaryBaseBytes = 0x2du;  // [0x20, 0x4d)
constexpr std::size_t kRowPointerBytes = sizeof(Address);
constexpr std::size_t kRowDefinitionOffset = 0x20u;
constexpr std::size_t kDefinitionTypeOffset = 0x10u;
constexpr std::size_t kDefinitionTypeBytes = sizeof(std::int32_t);

static_assert(kSideGateOffset + 1u <= kSideLossBytes,
              "side read span must include the raw gate byte");
static_assert(kSummaryBaseBytes == 45u,
              "the summary comparison span is the surveyed 11*i32 plus gate");

struct Side {
    std::array<std::int32_t, 4> raw_loss_i32{};
    std::uint8_t raw_gate = 0;
};

struct Snapshot {
    std::array<Side, 2> sides{};
    std::uint32_t row_count = 0;
    std::array<std::int32_t, kMaxRows> row_types{};
};

static_assert(std::is_trivially_copyable<Side>::value,
              "side must remain a plain raw-value object");
static_assert(std::is_trivially_copyable<Snapshot>::value,
              "snapshot must remain a plain raw-value object");

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

inline std::uint64_t load_u64(const unsigned char* bytes) noexcept {
    std::uint64_t value = 0;
    std::memcpy(&value, bytes, sizeof(value));
    return value;
}

inline std::int32_t load_i32(const unsigned char* bytes) noexcept {
    std::int32_t value = 0;
    std::memcpy(&value, bytes, sizeof(value));
    return value;
}

inline void store_u64(unsigned char* bytes, Address value) noexcept {
    std::memcpy(bytes, &value, sizeof(value));
}

template <typename Reader>
class BoundedReader {
public:
    BoundedReader(Reader& reader, Address output_begin, Address output_end)
        noexcept
        : reader_(reader), output_begin_(output_begin),
          output_end_(output_end) {}

    bool read(Address address, unsigned char* destination,
              std::size_t size) noexcept {
        Address end = 0;
        if (destination == nullptr || !checked_range(address, size, end)) {
            return false;
        }
        if (bytes_read_ > kMaxReadBudgetBytes - size) {
            return false;
        }
        if (ranges_overlap(address, end, output_begin_, output_end_)) {
            return false;
        }
        if (!reader_.read(address, destination, size)) {
            return false;
        }
        bytes_read_ += size;
        return true;
    }

    std::size_t bytes_read() const noexcept { return bytes_read_; }

private:
    Reader& reader_;
    Address output_begin_;
    Address output_end_;
    std::size_t bytes_read_ = 0;
};

template <typename Reader, typename = void>
struct reader_contract : std::false_type {};

template <typename Reader>
struct reader_contract<Reader, std::void_t<decltype(&Reader::read)>>
    : std::is_same<decltype(&Reader::read),
                   bool (Reader::*)(Address, unsigned char*, std::size_t) noexcept> {};

struct Pass {
    Address side_ptrs[2]{};
    Side sides[2]{};
    Address summary_begin = 0;
    Address summary_end = 0;
    std::array<std::int32_t, 11> summary_raw_i32{};
    std::uint8_t summary_control = 0;
    std::uint32_t row_count = 0;
    std::array<Address, kMaxRows> row_ptrs{};
    std::array<Address, kMaxRows> definition_ptrs{};
    std::array<std::int32_t, kMaxRows> row_types{};
};

static_assert(std::is_trivially_copyable<Pass>::value,
              "pass storage must remain bounded plain value storage");

inline bool valid_pointer(Address value, std::size_t bytes,
                          bool aligned) noexcept {
    Address end = 0;
    return value != 0u && (!aligned || value % alignof(Address) == 0u)
        && checked_range(value, bytes, end);
}

inline bool validate_vector(Address begin, Address end,
                            std::uint32_t& count) noexcept {
    count = 0;
    if (begin == 0u || end == 0u) {
        return begin == 0u && end == 0u;
    }
    if (begin % alignof(Address) != 0u || end % alignof(Address) != 0u
            || begin < kMinCanonicalAddress
            || end < kMinCanonicalAddress
            || end < begin) {
        return false;
    }
    const Address span = end - begin;
    if (span % sizeof(Address) != 0u
            || span / sizeof(Address) > kMaxRows) {
        return false;
    }
    Address ignored_end = 0;
    if (!checked_range(begin, static_cast<std::size_t>(span), ignored_end)) {
        return false;
    }
    count = static_cast<std::uint32_t>(span / sizeof(Address));
    return true;
}

inline bool same_side(const Side& left, const Side& right) noexcept {
    return left.raw_loss_i32 == right.raw_loss_i32
        && left.raw_gate == right.raw_gate;
}

inline bool same_pass(const Pass& left, const Pass& right) noexcept {
    if (left.side_ptrs[0] != right.side_ptrs[0]
            || left.side_ptrs[1] != right.side_ptrs[1]
            || !same_side(left.sides[0], right.sides[0])
            || !same_side(left.sides[1], right.sides[1])
            || left.summary_begin != right.summary_begin
            || left.summary_end != right.summary_end
            || left.summary_raw_i32 != right.summary_raw_i32
            || left.summary_control != right.summary_control
            || left.row_count != right.row_count) {
        return false;
    }
    for (std::size_t index = 0; index < left.row_count; ++index) {
        if (left.row_ptrs[index] != right.row_ptrs[index]
                || left.definition_ptrs[index] != right.definition_ptrs[index]
                || left.row_types[index] != right.row_types[index]) {
            return false;
        }
    }
    return true;
}

inline bool same_summary_base(const Pass& pass,
                              const owned_summary::Snapshot& base) noexcept {
    for (std::size_t index = 0; index < pass.summary_raw_i32.size(); ++index) {
        if (pass.summary_raw_i32[index] != base.raw_i32[index]) {
            return false;
        }
    }
    return pass.summary_control == base.control_byte;
}


template <typename Reader>
bool read_pass(BoundedReader<Reader>& reader, Address combat_ptr,
               Address summary_ptr, Pass& pass) noexcept {
    std::array<unsigned char, kSummaryHeaderBytes> summary_header{};
    std::array<unsigned char, kSummaryBaseBytes> summary_base{};
    std::array<unsigned char, kCombatSidePointerBytes> side_pointer_bytes{};
    std::array<unsigned char, kSideLossBytes> side_bytes{};
    std::array<unsigned char, kRowPointerBytes> row_pointer_bytes{};
    std::array<unsigned char, kRowPointerBytes> definition_pointer_bytes{};
    std::array<unsigned char, kDefinitionTypeBytes> type_bytes{};

    Address address = 0;
    if (!checked_add(summary_ptr, kSummaryBeginOffset, address)
            || !reader.read(address, summary_header.data(), summary_header.size())
            || !checked_add(summary_ptr, kSummaryBaseOffset, address)
            || !reader.read(address, summary_base.data(), summary_base.size())
            || !checked_add(combat_ptr, kCombatSidePointerOffset, address)
            || !reader.read(address, side_pointer_bytes.data(),
                            side_pointer_bytes.size())) {
        return false;
    }

    pass.summary_begin = load_u64(summary_header.data());
    pass.summary_end = load_u64(summary_header.data() + sizeof(Address));
    if (!validate_vector(pass.summary_begin, pass.summary_end,
                         pass.row_count)) {
        return false;
    }
    for (std::size_t index = 0; index < pass.summary_raw_i32.size(); ++index) {
        pass.summary_raw_i32[index] = load_i32(
            summary_base.data() + index * sizeof(std::int32_t));
    }
    pass.summary_control = summary_base[0x2cu];

    pass.side_ptrs[0] = load_u64(side_pointer_bytes.data());
    pass.side_ptrs[1] = load_u64(side_pointer_bytes.data() + sizeof(Address));
    for (std::size_t side_index = 0; side_index < 2u; ++side_index) {
        if (!valid_pointer(pass.side_ptrs[side_index],
                           kSideLossOffset + kSideLossBytes, true)
                || !checked_add(pass.side_ptrs[side_index], kSideLossOffset,
                                address)
                || !reader.read(address, side_bytes.data(), side_bytes.size())) {
            return false;
        }
        for (std::size_t field_index = 0; field_index < 4u; ++field_index) {
            pass.sides[side_index].raw_loss_i32[field_index] = load_i32(
                side_bytes.data() + field_index * sizeof(std::int32_t));
        }
        pass.sides[side_index].raw_gate = side_bytes[kSideGateOffset];
    }

    for (std::size_t index = 0; index < pass.row_count; ++index) {
        if (!checked_add(pass.summary_begin,
                         static_cast<Address>(index * sizeof(Address)),
                         address)
                || !reader.read(address, row_pointer_bytes.data(),
                                row_pointer_bytes.size())) {
            return false;
        }
        const Address row_ptr = load_u64(row_pointer_bytes.data());
        if (!valid_pointer(row_ptr, kRowDefinitionOffset + sizeof(Address),
                           true)
                || !checked_add(row_ptr, kRowDefinitionOffset, address)
                || !reader.read(address, definition_pointer_bytes.data(),
                                definition_pointer_bytes.size())) {
            return false;
        }
        const Address definition_ptr = load_u64(definition_pointer_bytes.data());
        if (!valid_pointer(definition_ptr,
                           kDefinitionTypeOffset + kDefinitionTypeBytes,
                           true)
                || !checked_add(definition_ptr, kDefinitionTypeOffset,
                                address)
                || !reader.read(address, type_bytes.data(), type_bytes.size())) {
            return false;
        }
        pass.row_ptrs[index] = row_ptr;
        pass.definition_ptrs[index] = definition_ptr;
        pass.row_types[index] = load_i32(type_bytes.data());
    }
    return true;
}

}  // namespace detail

using detail::reader_contract;

template <typename Reader>
bool capture(Reader& reader, Address combat_ptr, Address summary_ptr,
             const owned_summary::Snapshot& base_summary,
             Snapshot& output) noexcept {
    static_assert(reader_contract<Reader>::value,
                  "Reader::read must be bool(Address,unsigned char*,size_t) noexcept");
    Address output_begin = 0;
    Address output_end = 0;
    if (!detail::output_range(output, output_begin, output_end)
            || !detail::valid_pointer(combat_ptr,
                                      kCombatSidePointerOffset
                                          + kCombatSidePointerBytes,
                                      false)
            || !detail::valid_pointer(summary_ptr, kSummaryBaseOffset
                                          + kSummaryBaseBytes, false)) {
        return false;
    }

    detail::BoundedReader<Reader> bounded(reader, output_begin, output_end);
    detail::Pass first{};
    detail::Pass second{};
    if (!detail::read_pass(bounded, combat_ptr, summary_ptr, first)
            || !detail::same_summary_base(first, base_summary)
            || !detail::read_pass(bounded, combat_ptr, summary_ptr, second)
            || !detail::same_summary_base(second, base_summary)
            || !detail::same_pass(first, second)) {
        return false;
    }

    Snapshot candidate{};
    candidate.row_count = first.row_count;
    for (std::size_t side_index = 0; side_index < 2u; ++side_index) {
        candidate.sides[side_index] = first.sides[side_index];
    }
    for (std::size_t index = 0; index < first.row_count; ++index) {
        candidate.row_types[index] = first.row_types[index];
    }
    output = candidate;
    return true;
}

}  // namespace information::battle::owned_naval

#endif  // INFORMATION_BATTLE_OWNED_NAVAL_H

