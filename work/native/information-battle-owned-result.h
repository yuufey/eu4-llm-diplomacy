#ifndef INFORMATION_BATTLE_OWNED_RESULT_H
#define INFORMATION_BATTLE_OWNED_RESULT_H

// Research-only, pre-participant-callback result copy.
//
// This header never calls an EU4 function, allocates, performs I/O, or keeps
// a pointer into the observed object.  The caller supplies the read seam and
// is responsible for making that seam safe for its execution context.  No
// world/thread atomicity is implied by this bounded copy.

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <type_traits>
#include <utility>

namespace information::battle::owned_result {

using Address = std::uintptr_t;

constexpr Address kMinCanonicalAddress = UINT64_C(0x10000);
constexpr Address kMaxCanonicalExclusive = UINT64_C(0x800000000000);
constexpr std::size_t kMaxSingleReadBytes = 64u * 1024u;
constexpr std::size_t kMaxReadBudgetBytes = 64u * 1024u;
constexpr std::size_t kMaxOwnedStringBytes = 4096u;
constexpr Address kMaxStringCapacity = UINT64_C(128) * 1024u;
constexpr std::size_t kStringObjectBytes = 0x20u;
constexpr std::size_t kResultObjectBytes = 0x138u;
constexpr std::size_t kSideObjectBytes = 0x78u;
constexpr std::size_t kSideCount = 2u;

constexpr Address kResultVtableRva = UINT64_C(0x1c448d0);
constexpr Address kSideVtableRva = UINT64_C(0x1c44910);

constexpr std::size_t kResultSideAOffset = 0x10u;
constexpr std::size_t kResultSideBOffset = 0x88u;
constexpr std::size_t kResultAux100Offset = 0x100u;
constexpr std::size_t kResultAux104Offset = 0x104u;
constexpr std::size_t kResultFlag108Offset = 0x108u;
constexpr std::size_t kResultProvincePointerOffset = 0x110u;
constexpr std::size_t kResultNameOffset = 0x118u;
constexpr std::size_t kSideCountryOffset = 0x10u;
constexpr std::size_t kSideCommanderOffset = 0x18u;
constexpr std::size_t kProvinceIdOffset = 0x20u;

constexpr std::array<std::size_t, 9> kSideRawFieldOffsets{{
    0x38u, 0x3cu, 0x40u, 0x44u, 0x48u,
    0x4cu, 0x50u, 0x54u, 0x74u,
}};

static_assert(kResultNameOffset + kStringObjectBytes == kResultObjectBytes,
              "result object bound must include the embedded name object");
static_assert(kResultSideAOffset + kSideObjectBytes <= kResultNameOffset,
              "side A must remain inside the bounded result prefix");
static_assert(kResultSideBOffset + kSideObjectBytes <= kResultNameOffset,
              "side B must remain inside the bounded result prefix");

struct OwnedBytes {
    // Only bytes [0, length) are owned text bytes.  The terminator read from
    // the source is validated but is intentionally not retained as a claim.
    std::array<unsigned char, kMaxOwnedStringBytes> bytes;
    std::uint32_t length;
    std::uint32_t capacity;
};

struct Side {
    std::uint64_t country;
    std::array<std::int32_t, kSideRawFieldOffsets.size()> raw_fields;
    OwnedBytes commander;
};

struct Snapshot {
    std::int32_t raw_date;
    unsigned char flag108;
    // These are deliberate native signed values; no game-unit conversion is
    // performed by this component.
    std::int32_t aux100;
    std::int32_t aux104;
    std::int32_t province_id;
    OwnedBytes name;
    std::array<Side, kSideCount> sides;
};

static_assert(std::is_trivially_copyable<OwnedBytes>::value,
              "owned bytes must be a plain value object");
static_assert(std::is_trivially_copyable<Side>::value,
              "side must be a plain value object");
static_assert(std::is_trivially_copyable<Snapshot>::value,
              "snapshot must be a plain value object");

namespace detail {

inline bool checked_range(Address begin, std::size_t size,
                          Address& end) noexcept {
    if (size == 0 || size > kMaxSingleReadBytes) {
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

inline bool ranges_overlap(Address left_begin, Address left_end,
                           Address right_begin, Address right_end) noexcept {
    return left_begin < right_end && right_begin < left_end;
}

inline bool checked_add(Address left, Address right, Address& result) noexcept {
    const Address max_value = std::numeric_limits<Address>::max();
    if (left > max_value - right) {
        return false;
    }
    result = left + right;
    return true;
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
        bytes_read_ += size;
        return reader_.read(address, destination, size);
    }

    std::size_t bytes_read() const noexcept { return bytes_read_; }

private:
    Reader& reader_;
    Address output_begin_;
    Address output_end_;
    std::size_t bytes_read_ = 0;
};

inline std::uint64_t load_u64(const unsigned char* data) noexcept {
    std::uint64_t value = 0;
    std::memcpy(&value, data, sizeof(value));
    return value;
}

inline std::int32_t load_i32(const unsigned char* data) noexcept {
    std::int32_t value = 0;
    std::memcpy(&value, data, sizeof(value));
    return value;
}

inline std::uint64_t load_size(const unsigned char* data) noexcept {
    return load_u64(data);
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

template <typename Reader>
bool read_owned_bytes(BoundedReader<Reader>& reader,
                      const unsigned char* header,
                      OwnedBytes& output,
                      unsigned char* heap_scratch) noexcept {
    const std::uint64_t length = load_size(header + 0x10u);
    const std::uint64_t capacity = load_size(header + 0x18u);
    if (length > kMaxOwnedStringBytes
            || capacity > kMaxStringCapacity
            || capacity < length
            || capacity > std::numeric_limits<std::uint32_t>::max()) {
        return false;
    }

    const std::size_t owned_length = static_cast<std::size_t>(length);
    if (capacity < 16u) {
        if (length > 15u || header[length] != 0) {
            return false;
        }
        for (std::size_t index = 0; index < owned_length; ++index) {
            if (header[index] == 0) {
                return false;
            }
        }
        if (owned_length != 0) {
            std::memcpy(output.bytes.data(), header, owned_length);
        }
    } else {
        const Address heap = static_cast<Address>(load_u64(header));
        Address ignored_end = 0;
        if (!checked_range(heap, owned_length + 1u, ignored_end)) {
            return false;
        }
        // Even a zero-length heap string must read its terminator.  The
        // scratch buffer is caller-owned and never becomes part of output.
        if (!reader.read(heap, heap_scratch, owned_length + 1u)) {
            return false;
        }
        if (heap_scratch[owned_length] != 0) {
            return false;
        }
        for (std::size_t index = 0; index < owned_length; ++index) {
            if (heap_scratch[index] == 0) {
                return false;
            }
        }
        if (owned_length != 0) {
            std::memcpy(output.bytes.data(), heap_scratch, owned_length);
        }
    }

    output.length = static_cast<std::uint32_t>(length);
    output.capacity = static_cast<std::uint32_t>(capacity);
    return true;
}

}  // namespace detail

template <typename Reader, typename = void>
struct reader_contract : std::false_type {};

template <typename Reader>
struct reader_contract<Reader, std::void_t<decltype(
    static_cast<bool (Reader::*)(Address, unsigned char*, std::size_t) noexcept>(
        &Reader::read))>> : std::true_type {};

// Reader must expose only this seam:
//   bool read(uintptr_t address, unsigned char* destination,
//             size_t size) noexcept;
// Optional source_range_overlaps_output/overlaps_output/overlaps_source lets
// a bounded test or process seam reject a known source/output alias.
template <typename Reader>
bool capture(Reader& reader, Address module_base, Address result_ptr,
             Address raw_date_address, Snapshot& output) noexcept {
    static_assert(reader_contract<Reader>::value,
                  "Reader::read must be bool(Address,unsigned char*,size_t) noexcept");
    Address output_begin = 0;
    Address output_end = 0;
    if (!detail::output_range(output, output_begin, output_end)) {
        return false;
    }

    Address result_vtable = 0;
    Address side_vtable = 0;
    Address ignored_end = 0;
    if (!detail::checked_range(module_base, 1u, ignored_end)
            || !detail::checked_add(module_base, kResultVtableRva,
                                    result_vtable)
            || !detail::checked_add(module_base, kSideVtableRva, side_vtable)
            || !detail::checked_range(result_vtable, sizeof(Address),
                                      ignored_end)
            || !detail::checked_range(side_vtable, sizeof(Address),
                                      ignored_end)
            || result_ptr % alignof(std::uint64_t) != 0u
            || !detail::checked_range(result_ptr, kResultObjectBytes,
                                      ignored_end)
            || !detail::checked_range(raw_date_address, sizeof(std::int32_t),
                                      ignored_end)) {
        return false;
    }

    detail::BoundedReader<Reader> bounded(reader, output_begin, output_end);
    Snapshot candidate;
    std::memset(&candidate, 0, sizeof(candidate));
    std::array<unsigned char, kResultObjectBytes> result_raw{};
    std::array<unsigned char, sizeof(std::int32_t)> date_raw{};
    std::array<unsigned char, sizeof(std::int32_t)> province_raw{};
    std::array<unsigned char, kStringObjectBytes> name_header{};
    std::array<std::array<unsigned char, kStringObjectBytes>, kSideCount>
        commander_headers{};
    std::array<unsigned char, kMaxOwnedStringBytes + 1u> heap_scratch{};

    if (!bounded.read(raw_date_address, date_raw.data(), date_raw.size())
            || !bounded.read(result_ptr, result_raw.data(), result_raw.size())) {
        return false;
    }

    const Address expected_result_vtable = result_vtable;
    const Address expected_side_vtable = side_vtable;
    if (detail::load_u64(result_raw.data()) != expected_result_vtable) {
        return false;
    }
    const unsigned char* side_a = result_raw.data() + kResultSideAOffset;
    const unsigned char* side_b = result_raw.data() + kResultSideBOffset;
    if (detail::load_u64(side_a) != expected_side_vtable
            || detail::load_u64(side_b) != expected_side_vtable) {
        return false;
    }

    const Address province_ptr = detail::load_u64(
        result_raw.data() + kResultProvincePointerOffset);
    Address province_field = 0;
    if (!detail::checked_add(province_ptr, kProvinceIdOffset, province_field)
            || province_ptr % 8u != 0u
            || !bounded.read(province_field, province_raw.data(),
                             province_raw.size())) {
        return false;
    }

    std::memcpy(name_header.data(), result_raw.data() + kResultNameOffset,
                name_header.size());
    std::memcpy(commander_headers[0].data(),
                side_a + kSideCommanderOffset, kStringObjectBytes);
    std::memcpy(commander_headers[1].data(),
                side_b + kSideCommanderOffset, kStringObjectBytes);

    if (!detail::read_owned_bytes(bounded, name_header.data(), candidate.name,
                                  heap_scratch.data())
            || !detail::read_owned_bytes(bounded, commander_headers[0].data(),
                                         candidate.sides[0].commander,
                                         heap_scratch.data())
            || !detail::read_owned_bytes(bounded, commander_headers[1].data(),
                                         candidate.sides[1].commander,
                                         heap_scratch.data())) {
        return false;
    }

    candidate.raw_date = detail::load_i32(date_raw.data());
    candidate.flag108 = result_raw[kResultFlag108Offset];
    candidate.aux100 = detail::load_i32(result_raw.data() + kResultAux100Offset);
    candidate.aux104 = detail::load_i32(result_raw.data() + kResultAux104Offset);
    candidate.province_id = detail::load_i32(province_raw.data());

    for (std::size_t side_index = 0; side_index < kSideCount; ++side_index) {
        const unsigned char* side = side_index == 0u ? side_a : side_b;
        candidate.sides[side_index].country = detail::load_u64(
            side + kSideCountryOffset);
        for (std::size_t field_index = 0;
             field_index < kSideRawFieldOffsets.size(); ++field_index) {
            candidate.sides[side_index].raw_fields[field_index] =
                detail::load_i32(side + kSideRawFieldOffsets[field_index]);
        }
    }

    // Commit only after every read and validation succeeds.  Candidate has
    // zeroed padding, so a successful commit cannot expose indeterminate bytes.
    std::memcpy(&output, &candidate, sizeof(candidate));
    return true;
}

// Convenience form for callers that keep the reader seam as the last
// argument.  Both overloads perform exactly the same bounded operation.
template <typename Reader>
bool capture(Address module_base, Address result_ptr, Address raw_date_address,
             Snapshot& output, Reader& reader) noexcept {
    return capture(reader, module_base, result_ptr, raw_date_address, output);
}

}  // namespace information::battle::owned_result

#endif  // INFORMATION_BATTLE_OWNED_RESULT_H
