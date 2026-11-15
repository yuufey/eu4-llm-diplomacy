#ifndef INFORMATION_BATTLE_OWNED_TEMPLATE_H
#define INFORMATION_BATTLE_OWNED_TEMPLATE_H

// Research-only bounded copy of the message/template object observed in the
// fixed 1.37.4 build.  This component never calls game code, allocates,
// performs I/O, or retains a source pointer.  The Reader seam is supplied by
// the caller and must already be safe for its execution context.

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <type_traits>

namespace information::battle::owned_template {

using Address = std::uintptr_t;

constexpr Address kMinCanonicalAddress = UINT64_C(0x10000);
constexpr Address kMaxCanonicalExclusive = UINT64_C(0x800000000000);

constexpr std::size_t kMaxPairs = 128u;
constexpr std::size_t kMaxKeyBytes = 128u;
constexpr std::size_t kMaxValueBytes = 8192u;
constexpr std::size_t kMaxAuxiliaryTextBytes = 8192u;
constexpr std::size_t kMaxArenaBytes = 64u * 1024u;

// A pass reads the message header, node records, and the raw bytes behind
// heap SSO strings.  Two passes are admitted within this combined budget.
constexpr std::size_t kMaxSingleReadBytes = 64u * 1024u;
constexpr std::size_t kMaxPerPassReadBytes = 128u * 1024u;
constexpr std::size_t kMaxReadBudgetBytes = 256u * 1024u;
constexpr Address kMaxStringCapacity = UINT64_C(128) * 1024u;

constexpr std::size_t kMessageHeaderBytes = 0x90u;
constexpr std::size_t kNodeBytes = 0x70u;
constexpr std::size_t kNodeNextOffset = 0x60u;
// The message owns the formatter container at these offsets.  Keep the
// historical names below as aliases because existing callers use them.
constexpr std::size_t kMessageHeadOffset = 0x10u;
constexpr std::size_t kMessageTailOffset = 0x18u;
constexpr std::size_t kMessageRawWord20Offset = 0x20u;
constexpr std::size_t kMessageRawFlag24Offset = 0x24u;
constexpr std::size_t kContainerHeadOffset = kMessageHeadOffset;
constexpr std::size_t kContainerTailOffset = kMessageTailOffset;
constexpr std::size_t kContainerRawWord20Offset = kMessageRawWord20Offset;
constexpr std::size_t kContainerRawFlag24Offset = kMessageRawFlag24Offset;
// The formatter's linked container is a standalone 0x18-byte object.  It
// has no message date/flags/auxiliary string, so this path must never read a
// 0x90-byte message header or infer the missing metadata.
constexpr std::size_t kFormatterContainerHeaderBytes = 0x18u;
constexpr std::size_t kFormatterContainerHeadOffset = 0x00u;
constexpr std::size_t kFormatterContainerTailOffset = 0x08u;
constexpr std::size_t kFormatterContainerRawWord10Offset = 0x10u;
constexpr std::size_t kFormatterContainerRawFlag14Offset = 0x14u;
constexpr std::size_t kAuxiliaryTextOffset = 0x60u;
constexpr std::size_t kAuxiliaryTextLengthOffset = 0x70u;
constexpr std::size_t kAuxiliaryTextCapacityOffset = 0x78u;
constexpr std::size_t kNativeDateOffset = 0x88u;
constexpr std::size_t kRawFlag8COffset = 0x8cu;
constexpr std::size_t kRawFlag8DOffset = 0x8du;

constexpr std::size_t kKeyOffset = 0x00u;
constexpr std::size_t kValueOffset = 0x20u;
constexpr std::size_t kKeyLengthOffset = 0x10u;
constexpr std::size_t kKeyCapacityOffset = 0x18u;
constexpr std::size_t kValueLengthOffset = 0x30u;
constexpr std::size_t kValueCapacityOffset = 0x38u;

// The constructor/copy evidence shows +0x18 being the append tail pointer
// and +0x20 being incremented on insertion.  The latter is intentionally
// preserved as a raw word; this component does not name it "count".
struct TextRange {
    std::uint32_t offset = 0;
    std::uint32_t length = 0;
};

struct Pair {
    TextRange key{};
    TextRange value{};
};

struct Snapshot {
    // pair_count is the number of nodes observed by this bounded traversal;
    // it is not a claim about the native +0x20 word.
    std::uint32_t pair_count = 0;
    std::array<Pair, kMaxPairs> pairs{};
    std::array<unsigned char, kMaxArenaBytes> arena{};
    TextRange auxiliary_text{};
    std::int32_t native_date = 0;
    std::uint8_t raw_flag_8c = 0;
    std::uint8_t raw_flag_8d = 0;
    std::uint32_t raw_header_word_20 = 0;
    std::uint8_t raw_header_flag_24 = 0;
};

static_assert(std::is_trivially_copyable<TextRange>::value,
              "text ranges must remain plain value objects");
static_assert(std::is_trivially_copyable<Pair>::value,
              "pairs must remain plain value objects");
static_assert(std::is_trivially_copyable<Snapshot>::value,
              "snapshot must remain a plain value object");
static_assert(kMessageHeaderBytes > kRawFlag8DOffset,
              "message read must include both raw flag bytes");
static_assert(kNodeBytes > kNodeNextOffset + sizeof(Address),
              "node read must include the next pointer");

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

inline bool checked_add(Address left, Address right, Address& result) noexcept {
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
    return begin >= kMinCanonicalAddress && end <= kMaxCanonicalExclusive
        && end > begin;
}

inline std::uint64_t load_u64(const unsigned char* data) noexcept {
    std::uint64_t value = 0;
    std::memcpy(&value, data, sizeof(value));
    return value;
}

inline std::uint32_t load_u32(const unsigned char* data) noexcept {
    std::uint32_t value = 0;
    std::memcpy(&value, data, sizeof(value));
    return value;
}

inline std::int32_t load_i32(const unsigned char* data) noexcept {
    std::int32_t value = 0;
    std::memcpy(&value, data, sizeof(value));
    return value;
}

inline bool valid_pointer(Address value) noexcept {
    return value >= kMinCanonicalAddress
        && value < kMaxCanonicalExclusive
        && (value % alignof(Address)) == 0u;
}

inline std::size_t range_end(TextRange range) noexcept {
    return static_cast<std::size_t>(range.offset)
        + static_cast<std::size_t>(range.length);
}

inline bool same_range(TextRange left, TextRange right) noexcept {
    return left.offset == right.offset && left.length == right.length;
}

inline bool same_snapshot(const Snapshot& left,
                          const Snapshot& right) noexcept {
    if (left.pair_count != right.pair_count
            || !same_range(left.auxiliary_text, right.auxiliary_text)
            || left.native_date != right.native_date
            || left.raw_flag_8c != right.raw_flag_8c
            || left.raw_flag_8d != right.raw_flag_8d
            || left.raw_header_word_20 != right.raw_header_word_20
            || left.raw_header_flag_24 != right.raw_header_flag_24) {
        return false;
    }
    for (std::size_t index = 0; index < left.pair_count; ++index) {
        if (!same_range(left.pairs[index].key, right.pairs[index].key)
                || !same_range(left.pairs[index].value,
                               right.pairs[index].value)) {
            return false;
        }
    }
    const std::size_t used = range_end(left.auxiliary_text);
    for (std::size_t index = 0; index < left.pair_count; ++index) {
        const std::size_t key_end = range_end(left.pairs[index].key);
        const std::size_t value_end = range_end(left.pairs[index].value);
        if (key_end > kMaxArenaBytes || value_end > kMaxArenaBytes) {
            return false;
        }
    }
    std::size_t max_end = used;
    for (std::size_t index = 0; index < left.pair_count; ++index) {
        if (range_end(left.pairs[index].key) > max_end) {
            max_end = range_end(left.pairs[index].key);
        }
        if (range_end(left.pairs[index].value) > max_end) {
            max_end = range_end(left.pairs[index].value);
        }
    }
    return std::memcmp(left.arena.data(), right.arena.data(), max_end) == 0;
}

}  // namespace detail

template <typename Reader, typename = void>
struct reader_contract : std::false_type {};

template <typename Reader>
struct reader_contract<Reader, std::void_t<decltype(&Reader::read)>>
    : std::is_same<decltype(&Reader::read),
                   bool (Reader::*)(Address, unsigned char*,
                                     std::size_t) noexcept> {};

namespace detail {

struct ReadRecord {
    Address address = 0;
    std::uint32_t offset = 0;
    std::uint32_t size = 0;
};

constexpr std::size_t kMaxReadRecords = 512u;

struct ReadLog {
    std::array<unsigned char, kMaxPerPassReadBytes> bytes{};
    std::array<ReadRecord, kMaxReadRecords> records{};
    std::size_t bytes_used = 0;
    std::size_t record_count = 0;
};

template <typename Reader>
class PassReader {
public:
    PassReader(Reader& reader, Address output_begin, Address output_end,
               ReadLog* writer, const ReadLog* expected) noexcept
        : reader_(reader), output_begin_(output_begin),
          output_end_(output_end), writer_(writer), expected_(expected) {}

    bool read(Address address, unsigned char* destination,
              std::size_t size) noexcept {
        Address end = 0;
        if (destination == nullptr
                || !checked_range(address, size, end)
                || ranges_overlap(address, end, output_begin_, output_end_)
                || bytes_used_ > kMaxPerPassReadBytes - size) {
            return false;
        }
        if (writer_ != nullptr) {
            if (writer_->record_count >= kMaxReadRecords
                    || writer_->bytes_used > kMaxPerPassReadBytes - size) {
                return false;
            }
        }
        if (expected_ != nullptr) {
            if (record_index_ >= expected_->record_count) {
                return false;
            }
            const ReadRecord& record = expected_->records[record_index_];
            if (record.address != address || record.size != size
                    || record.offset > expected_->bytes_used
                    || size > expected_->bytes_used - record.offset) {
                return false;
            }
        }
        if (!reader_.read(address, destination, size)) {
            return false;
        }
        if (expected_ != nullptr) {
            const ReadRecord& record = expected_->records[record_index_];
            if (std::memcmp(destination, expected_->bytes.data()
                                      + record.offset, size) != 0) {
                return false;
            }
        }
        if (writer_ != nullptr) {
            ReadRecord& record = writer_->records[writer_->record_count++];
            record.address = address;
            record.offset = static_cast<std::uint32_t>(writer_->bytes_used);
            record.size = static_cast<std::uint32_t>(size);
            std::memcpy(writer_->bytes.data() + writer_->bytes_used,
                        destination, size);
            writer_->bytes_used += size;
        }
        bytes_used_ += size;
        ++record_index_;
        return true;
    }

    bool complete() const noexcept {
        if (expected_ == nullptr) {
            return writer_ != nullptr;
        }
        return record_index_ == expected_->record_count
            && bytes_used_ == expected_->bytes_used;
    }

    std::size_t bytes_used() const noexcept { return bytes_used_; }

private:
    Reader& reader_;
    Address output_begin_;
    Address output_end_;
    ReadLog* writer_;
    const ReadLog* expected_;
    std::size_t bytes_used_ = 0;
    std::size_t record_index_ = 0;
};

template <typename Pass>
bool read_string(Pass& pass, const unsigned char* object,
                 std::size_t length_offset, std::size_t capacity_offset,
                 std::size_t max_length, Snapshot& snapshot,
                 std::size_t& cursor, TextRange& output,
                 std::array<unsigned char, kMaxValueBytes + 1u>& scratch)
    noexcept {
    const std::uint64_t length = load_u64(object + length_offset);
    const std::uint64_t capacity = load_u64(object + capacity_offset);
    if (length > max_length || capacity < length
            || capacity > kMaxStringCapacity
            || length > std::numeric_limits<std::uint32_t>::max()) {
        return false;
    }

    const std::size_t text_length = static_cast<std::size_t>(length);
    const bool heap = capacity >= 16u;
    const unsigned char* source = object;
    if (!heap) {
        if (length > 15u || object[text_length] != 0u) {
            return false;
        }
        for (std::size_t index = 0; index < text_length; ++index) {
            if (object[index] == 0u) {
                return false;
            }
        }
    } else {
        const Address pointer = load_u64(object);
        Address ignored_end = 0;
        if (!valid_pointer(pointer)
                || !checked_range(pointer, text_length + 1u, ignored_end)
                || !pass.read(pointer, scratch.data(), text_length + 1u)
                || scratch[text_length] != 0u) {
            return false;
        }
        for (std::size_t index = 0; index < text_length; ++index) {
            if (scratch[index] == 0u) {
                return false;
            }
        }
        source = scratch.data();
    }

    if (cursor > kMaxArenaBytes || text_length > kMaxArenaBytes - cursor) {
        return false;
    }
    output.offset = static_cast<std::uint32_t>(cursor);
    output.length = static_cast<std::uint32_t>(text_length);
    if (text_length != 0u) {
        std::memcpy(snapshot.arena.data() + cursor, source, text_length);
    }
    cursor += text_length;
    return true;
}

template <typename Pass>
bool capture_one(Pass& pass, Address message_ptr, Snapshot& output) noexcept {
    std::array<unsigned char, kMessageHeaderBytes> header{};
    if (!pass.read(message_ptr, header.data(), header.size())) {
        return false;
    }

    Snapshot candidate{};
    candidate.raw_header_word_20 =
        load_u32(header.data() + kContainerRawWord20Offset);
    candidate.raw_header_flag_24 = header[kContainerRawFlag24Offset];
    candidate.native_date =
        load_i32(header.data() + kNativeDateOffset);
    candidate.raw_flag_8c = header[kRawFlag8COffset];
    candidate.raw_flag_8d = header[kRawFlag8DOffset];

    const Address head = load_u64(header.data() + kContainerHeadOffset);
    const Address tail = load_u64(header.data() + kContainerTailOffset);
    if ((head != 0u && !valid_pointer(head))
            || (tail != 0u && !valid_pointer(tail))
            || (head == 0u && tail != 0u)) {
        return false;
    }

    std::array<unsigned char, kMaxValueBytes + 1u> scratch{};
    std::size_t cursor = 0;
    if (!read_string(pass, header.data() + kAuxiliaryTextOffset,
                     kAuxiliaryTextLengthOffset - kAuxiliaryTextOffset,
                     kAuxiliaryTextCapacityOffset - kAuxiliaryTextOffset,
                     kMaxAuxiliaryTextBytes, candidate, cursor,
                     candidate.auxiliary_text, scratch)) {
        return false;
    }

    std::array<Address, kMaxPairs> seen{};
    Address current = head;
    Address last = 0;
    while (current != 0u) {
        if (!valid_pointer(current) || candidate.pair_count >= kMaxPairs) {
            return false;
        }
        for (std::size_t index = 0; index < candidate.pair_count; ++index) {
            if (seen[index] == current) {
                return false;
            }
        }
        seen[candidate.pair_count] = current;

        std::array<unsigned char, kNodeBytes> node{};
        if (!pass.read(current, node.data(), node.size())) {
            return false;
        }
        Pair& pair = candidate.pairs[candidate.pair_count];
        if (!read_string(pass, node.data() + kKeyOffset,
                         kKeyLengthOffset, kKeyCapacityOffset,
                         kMaxKeyBytes, candidate, cursor, pair.key, scratch)
                || !read_string(pass, node.data() + kValueOffset,
                                kValueLengthOffset - kValueOffset,
                                kValueCapacityOffset - kValueOffset,
                                kMaxValueBytes, candidate, cursor,
                                pair.value, scratch)) {
            return false;
        }
        ++candidate.pair_count;
        last = current;
        current = load_u64(node.data() + kNodeNextOffset);
        if (current != 0u && !valid_pointer(current)) {
            return false;
        }
    }

    if ((head == 0u && last != 0u) || (head != 0u && tail != last)) {
        return false;
    }
    output = candidate;
    return true;
}

template <typename Pass>
bool capture_container_one(Pass& pass, Address container_ptr,
                           Snapshot& output) noexcept {
    std::array<unsigned char, kFormatterContainerHeaderBytes> header{};
    if (!pass.read(container_ptr, header.data(), header.size())) {
        return false;
    }

    // A formatter container has only the linked-list header.  Value
    // initialization intentionally leaves the message-only metadata and
    // auxiliary range unavailable/empty; the two raw container fields share
    // the existing Snapshot carriers for the value-only wire layer.
    Snapshot candidate{};
    candidate.raw_header_word_20 =
        load_u32(header.data() + kFormatterContainerRawWord10Offset);
    candidate.raw_header_flag_24 =
        header[kFormatterContainerRawFlag14Offset];

    const Address head =
        load_u64(header.data() + kFormatterContainerHeadOffset);
    const Address tail =
        load_u64(header.data() + kFormatterContainerTailOffset);
    if ((head != 0u && !valid_pointer(head))
            || (tail != 0u && !valid_pointer(tail))
            || (head == 0u && tail != 0u)) {
        return false;
    }

    std::array<unsigned char, kMaxValueBytes + 1u> scratch{};
    std::size_t cursor = 0;
    std::array<Address, kMaxPairs> seen{};
    Address current = head;
    Address last = 0;
    while (current != 0u) {
        if (!valid_pointer(current) || candidate.pair_count >= kMaxPairs) {
            return false;
        }
        for (std::size_t index = 0; index < candidate.pair_count; ++index) {
            if (seen[index] == current) {
                return false;
            }
        }
        seen[candidate.pair_count] = current;

        std::array<unsigned char, kNodeBytes> node{};
        if (!pass.read(current, node.data(), node.size())) {
            return false;
        }
        Pair& pair = candidate.pairs[candidate.pair_count];
        if (!read_string(pass, node.data() + kKeyOffset,
                         kKeyLengthOffset, kKeyCapacityOffset,
                         kMaxKeyBytes, candidate, cursor, pair.key, scratch)
                || !read_string(pass, node.data() + kValueOffset,
                                kValueLengthOffset - kValueOffset,
                                kValueCapacityOffset - kValueOffset,
                                kMaxValueBytes, candidate, cursor,
                                pair.value, scratch)) {
            return false;
        }
        ++candidate.pair_count;
        last = current;
        current = load_u64(node.data() + kNodeNextOffset);
        if (current != 0u && !valid_pointer(current)) {
            return false;
        }
    }

    if ((head == 0u && last != 0u) || (head != 0u && tail != last)) {
        return false;
    }
    output = candidate;
    return true;
}

}  // namespace detail

// Reader must expose exactly:
//   bool read(uintptr_t, unsigned char*, size_t) noexcept;
// The source is read twice.  Every header, node record, SSO decision, heap
// string byte, and chain address must match; otherwise output is untouched.
template <typename Reader>
bool capture(Reader& reader, Address message_ptr, Snapshot& output) noexcept {
    static_assert(reader_contract<Reader>::value,
                  "Reader::read must be bool(Address,unsigned char*,size_t) noexcept");

    Address output_begin = 0;
    Address output_end = 0;
    if (!detail::output_range(output, output_begin, output_end)
            || !detail::valid_pointer(message_ptr)) {
        return false;
    }

    detail::ReadLog first_log{};
    Snapshot first{};
    detail::PassReader<Reader> first_reader(
        reader, output_begin, output_end, &first_log, nullptr);
    if (!detail::capture_one(first_reader, message_ptr, first)
            || !first_reader.complete()) {
        return false;
    }

    Snapshot second{};
    detail::PassReader<Reader> second_reader(
        reader, output_begin, output_end, nullptr, &first_log);
    if (!detail::capture_one(second_reader, message_ptr, second)
            || !second_reader.complete()
            || first_log.bytes_used + second_reader.bytes_used()
                > kMaxReadBudgetBytes
            || !detail::same_snapshot(first, second)) {
        return false;
    }

    output = first;
    return true;
}

// Copy the formatter's standalone 0x18-byte linked container.  It uses the
// same two-pass read log, bounded traversal, alias/cycle checks, and atomic
// output commit as capture(), while keeping message-only metadata unavailable.
template <typename Reader>
bool capture_container(Reader& reader, Address container_ptr,
                       Snapshot& output
#ifdef INFORMATION_BATTLE_FLAG_INPUTS
                       , detail::ReadLog* copied_log = nullptr
#endif
                       ) noexcept {
    static_assert(reader_contract<Reader>::value,
                  "Reader::read must be bool(Address,unsigned char*,size_t) noexcept");

    Address output_begin = 0;
    Address output_end = 0;
    if (!detail::output_range(output, output_begin, output_end)
            || !detail::valid_pointer(container_ptr)) {
        return false;
    }

    detail::ReadLog first_log{};
    Snapshot first{};
    detail::PassReader<Reader> first_reader(
        reader, output_begin, output_end, &first_log, nullptr);
    if (!detail::capture_container_one(first_reader, container_ptr, first)
            || !first_reader.complete()) {
        return false;
    }

    Snapshot second{};
    detail::PassReader<Reader> second_reader(
        reader, output_begin, output_end, nullptr, &first_log);
    if (!detail::capture_container_one(second_reader, container_ptr, second)
            || !second_reader.complete()
            || first_log.bytes_used + second_reader.bytes_used()
                > kMaxReadBudgetBytes
            || !detail::same_snapshot(first, second)) {
        return false;
    }

#ifdef INFORMATION_BATTLE_FLAG_INPUTS
    if (copied_log != nullptr) {
        const Address log_begin = reinterpret_cast<Address>(copied_log);
        if (log_begin < kMinCanonicalAddress || log_begin > kMaxCanonicalExclusive - sizeof(*copied_log)) return false;
        const Address log_end = log_begin + sizeof(*copied_log);
        if (detail::ranges_overlap(log_begin, log_end, output_begin, output_end)) return false;
        for (std::size_t index = 0; index < first_log.record_count; ++index) {
            const auto& record = first_log.records[index];
            if (detail::ranges_overlap(log_begin, log_end, record.address, record.address + record.size)) return false;
        }
        *copied_log = first_log;
    }
#endif
    output = first;
    return true;
}

}  // namespace information::battle::owned_template

#endif  // INFORMATION_BATTLE_OWNED_TEMPLATE_H
