#ifndef INFORMATION_BATTLE_OWNED_NATIVE_TEXT_H
#define INFORMATION_BATTLE_OWNED_NATIVE_TEXT_H

// Bounded, value-only copies of native battle-message text objects.  This
// header deliberately contains no engine calls, allocation, I/O, or source
// pointers.  The caller supplies a read-only Reader seam.

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <type_traits>

namespace information::battle::owned_native_text {

using Address = std::uintptr_t;

constexpr Address kMinCanonicalAddress = UINT64_C(0x10000);
constexpr Address kMaxCanonicalExclusive = UINT64_C(0x800000000000);

constexpr std::size_t kStringObjectBytes = 0x20u;
constexpr std::size_t kStringLengthOffset = 0x10u;
constexpr std::size_t kStringCapacityOffset = 0x18u;
constexpr std::size_t kInlineCapacity = 0x0fu;
constexpr std::size_t kHeapThreshold = 0x10u;
constexpr std::size_t kMaxKeyBytes = 256u;
constexpr std::size_t kMaxTextBytes = 8192u;
constexpr std::size_t kMaxArenaBytes =
    kMaxKeyBytes + 3u * kMaxTextBytes;
static_assert(kMaxArenaBytes < 32u * 1024u,
              "owned native text arena must remain below 32 KiB");

constexpr std::size_t kMessageDefinitionPointerOffset = 0x08u;
constexpr std::size_t kMessageAuxiliaryOffset = 0x60u;
constexpr std::size_t kMessageDateOffset = 0x88u;
constexpr std::size_t kMessageFlag8cOffset = 0x8cu;
constexpr std::size_t kMessageFlag8dOffset = 0x8du;
constexpr std::size_t kMessageHeaderBytes = 0x90u;

constexpr std::size_t kDefinitionKeyOffset = 0x38u;
constexpr std::size_t kMaxSingleReadBytes = 32u * 1024u;
constexpr std::size_t kMaxTotalReadBytes = 64u * 1024u;
constexpr std::size_t kMaxReadRecords = 16u;
constexpr std::uint64_t kMaxStringCapacity = UINT64_C(128) * 1024u;

enum class FieldState : std::uint8_t {
    unknown = 0u,
    observed = 1u,
    absent = 2u,
};

// These are intentionally distinct.  In particular, a native line-1 value
// must not be silently presented as a title or as message auxiliary text.
enum class SourceKind : std::uint8_t {
    message_metadata = 1u,
    title_helper_candidate = 2u,
    native_line1 = 3u,
};

struct TextRange {
    std::uint32_t offset = 0u;
    std::uint32_t length = 0u;
};

struct TextField {
    FieldState state = FieldState::unknown;
    SourceKind source_kind = SourceKind::message_metadata;
    TextRange bytes{};
};

struct Snapshot {
    // The first two fields are populated by capture(message,...).  The last
    // two are populated only by capture_string(...).  Unrequested fields stay
    // unknown, rather than being reported as absent.
    TextField definition_key{};
    TextField auxiliary_text{};
    TextField title_helper_candidate{};
    TextField native_line1{};

    FieldState native_date_state = FieldState::unknown;
    std::int32_t native_date = 0;
    FieldState raw_flags_state = FieldState::unknown;
    std::uint8_t raw_flag_8c = 0u;
    std::uint8_t raw_flag_8d = 0u;

    std::array<unsigned char, kMaxArenaBytes> arena{};
};

static_assert(std::is_trivially_copyable<TextRange>::value,
              "text ranges must remain plain value objects");
static_assert(std::is_trivially_copyable<TextField>::value,
              "text fields must remain plain value objects");
static_assert(std::is_trivially_copyable<Snapshot>::value,
              "native text snapshot must remain a plain value object");

namespace detail {

inline Snapshot empty_snapshot() noexcept {
    Snapshot result{};
    result.definition_key.source_kind = SourceKind::message_metadata;
    result.auxiliary_text.source_kind = SourceKind::message_metadata;
    result.title_helper_candidate.source_kind =
        SourceKind::title_helper_candidate;
    result.native_line1.source_kind = SourceKind::native_line1;
    return result;
}

inline void clear_snapshot(Snapshot& output) noexcept {
    output = empty_snapshot();
}

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

inline bool valid_pointer(Address value) noexcept {
    return value >= kMinCanonicalAddress
        && value < kMaxCanonicalExclusive
        && (value % alignof(Address)) == 0u;
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
    std::uint64_t value = 0u;
    std::memcpy(&value, data, sizeof(value));
    return value;
}

inline std::uint32_t load_u32(const unsigned char* data) noexcept {
    std::uint32_t value = 0u;
    std::memcpy(&value, data, sizeof(value));
    return value;
}

inline std::int32_t load_i32(const unsigned char* data) noexcept {
    std::int32_t value = 0;
    std::memcpy(&value, data, sizeof(value));
    return value;
}

inline TextField* field_for(Snapshot& snapshot,
                            SourceKind kind) noexcept {
    switch (kind) {
    case SourceKind::message_metadata:
        return &snapshot.auxiliary_text;
    case SourceKind::title_helper_candidate:
        return &snapshot.title_helper_candidate;
    case SourceKind::native_line1:
        return &snapshot.native_line1;
    }
    return nullptr;
}

inline const TextField* field_for(const Snapshot& snapshot,
                                  SourceKind kind) noexcept {
    switch (kind) {
    case SourceKind::message_metadata:
        return &snapshot.auxiliary_text;
    case SourceKind::title_helper_candidate:
        return &snapshot.title_helper_candidate;
    case SourceKind::native_line1:
        return &snapshot.native_line1;
    }
    return nullptr;
}

inline std::size_t range_end(TextRange range) noexcept {
    return static_cast<std::size_t>(range.offset)
        + static_cast<std::size_t>(range.length);
}

inline bool same_field(const TextField& left,
                       const TextField& right) noexcept {
    return left.state == right.state
        && left.source_kind == right.source_kind
        && left.bytes.offset == right.bytes.offset
        && left.bytes.length == right.bytes.length;
}

inline bool same_snapshot(const Snapshot& left,
                          const Snapshot& right) noexcept {
    if (!same_field(left.definition_key, right.definition_key)
            || !same_field(left.auxiliary_text, right.auxiliary_text)
            || !same_field(left.title_helper_candidate,
                           right.title_helper_candidate)
            || !same_field(left.native_line1, right.native_line1)
            || left.native_date_state != right.native_date_state
            || left.native_date != right.native_date
            || left.raw_flags_state != right.raw_flags_state
            || left.raw_flag_8c != right.raw_flag_8c
            || left.raw_flag_8d != right.raw_flag_8d) {
        return false;
    }

    std::size_t used = 0u;
    const TextField* fields[] = {
        &left.definition_key, &left.auxiliary_text,
        &left.title_helper_candidate, &left.native_line1,
    };
    for (const TextField* field : fields) {
        if (range_end(field->bytes) > kMaxArenaBytes) {
            return false;
        }
        if (range_end(field->bytes) > used) {
            used = range_end(field->bytes);
        }
    }
    return std::memcmp(left.arena.data(), right.arena.data(), used) == 0;
}

inline bool valid_field_state(FieldState state) noexcept {
    return state == FieldState::unknown
        || state == FieldState::observed
        || state == FieldState::absent;
}

inline bool valid_source_kind(SourceKind kind) noexcept {
    return kind == SourceKind::message_metadata
        || kind == SourceKind::title_helper_candidate
        || kind == SourceKind::native_line1;
}

inline bool field_valid(const TextField& field, SourceKind expected,
                        std::size_t max_length) noexcept {
    if (field.source_kind != expected
            || !valid_source_kind(field.source_kind)
            || !valid_field_state(field.state)) {
        return false;
    }
    if (field.state != FieldState::observed) {
        return field.bytes.offset == 0u && field.bytes.length == 0u;
    }
    if (field.bytes.length > max_length
            || field.bytes.offset > kMaxArenaBytes
            || field.bytes.length > kMaxArenaBytes - field.bytes.offset) {
        return false;
    }
    return range_end(field.bytes) <= kMaxArenaBytes;
}

inline bool ranges_disjoint(const TextField& left,
                            const TextField& right) noexcept {
    if (left.state != FieldState::observed
            || right.state != FieldState::observed
            || left.bytes.length == 0u || right.bytes.length == 0u) {
        return true;
    }
    const std::size_t left_begin = left.bytes.offset;
    const std::size_t left_end = range_end(left.bytes);
    const std::size_t right_begin = right.bytes.offset;
    const std::size_t right_end = range_end(right.bytes);
    return left_end <= right_begin || right_end <= left_begin;
}

inline bool snapshot_valid(const Snapshot& snapshot) noexcept {
    if (!field_valid(snapshot.definition_key, SourceKind::message_metadata,
                     kMaxKeyBytes)
            || !field_valid(snapshot.auxiliary_text,
                            SourceKind::message_metadata, kMaxTextBytes)
            || !field_valid(snapshot.title_helper_candidate,
                            SourceKind::title_helper_candidate, kMaxTextBytes)
            || !field_valid(snapshot.native_line1,
                            SourceKind::native_line1, kMaxTextBytes)
            || !valid_field_state(snapshot.native_date_state)
            || !valid_field_state(snapshot.raw_flags_state)) {
        return false;
    }
    if (!ranges_disjoint(snapshot.definition_key, snapshot.auxiliary_text)
            || !ranges_disjoint(snapshot.definition_key,
                                snapshot.title_helper_candidate)
            || !ranges_disjoint(snapshot.definition_key,
                                snapshot.native_line1)
            || !ranges_disjoint(snapshot.auxiliary_text,
                                snapshot.title_helper_candidate)
            || !ranges_disjoint(snapshot.auxiliary_text,
                                snapshot.native_line1)
            || !ranges_disjoint(snapshot.title_helper_candidate,
                                snapshot.native_line1)) {
        return false;
    }
    if (snapshot.native_date_state != FieldState::observed
            && snapshot.native_date != 0) {
        return false;
    }
    if (snapshot.raw_flags_state != FieldState::observed
            && (snapshot.raw_flag_8c != 0u || snapshot.raw_flag_8d != 0u)) {
        return false;
    }
    return true;
}

inline bool text_bytes_equal(const Snapshot& left, const TextField& left_field,
                             const Snapshot& right,
                             const TextField& right_field) noexcept {
    if (left_field.bytes.length != right_field.bytes.length) {
        return false;
    }
    if (left_field.bytes.length == 0u) {
        return true;
    }
    return std::memcmp(left.arena.data() + left_field.bytes.offset,
                       right.arena.data() + right_field.bytes.offset,
                       left_field.bytes.length) == 0;
}

inline bool append_field(const Snapshot& source, const TextField& input,
                         Snapshot& output, TextField& result,
                         std::size_t& cursor) noexcept {
    result.state = input.state;
    result.source_kind = input.source_kind;
    result.bytes = TextRange{};
    if (input.state != FieldState::observed) {
        return true;
    }
    if (cursor > kMaxArenaBytes
            || input.bytes.length > kMaxArenaBytes - cursor) {
        return false;
    }
    result.bytes.offset = static_cast<std::uint32_t>(cursor);
    result.bytes.length = input.bytes.length;
    if (input.bytes.length != 0u) {
        std::memcpy(output.arena.data() + cursor,
                    source.arena.data() + input.bytes.offset,
                    input.bytes.length);
    }
    cursor += input.bytes.length;
    return true;
}

inline bool merge_field(const Snapshot& existing,
                        const TextField& existing_field,
                        const Snapshot& incoming,
                        const TextField& incoming_field,
                        Snapshot& output, TextField& result,
                        std::size_t& cursor) noexcept {
    const bool existing_known = existing_field.state != FieldState::unknown;
    const bool incoming_known = incoming_field.state != FieldState::unknown;
    if (!existing_known) {
        return append_field(incoming, incoming_field, output, result, cursor);
    }
    if (!incoming_known) {
        return append_field(existing, existing_field, output, result, cursor);
    }
    if (existing_field.state != incoming_field.state) {
        return false;
    }
    if (existing_field.state == FieldState::observed
            && !text_bytes_equal(existing, existing_field,
                                 incoming, incoming_field)) {
        return false;
    }
    return append_field(existing, existing_field, output, result, cursor);
}

template <typename Value>
inline bool merge_metadata(Value existing_value, FieldState existing_state,
                           Value incoming_value, FieldState incoming_state,
                           FieldState& output_state,
                           Value& output_value) noexcept {
    if (!valid_field_state(existing_state)
            || !valid_field_state(incoming_state)) {
        return false;
    }
    const bool existing_known = existing_state != FieldState::unknown;
    const bool incoming_known = incoming_state != FieldState::unknown;
    if (!existing_known) {
        output_state = incoming_state;
        output_value = incoming_value;
        return true;
    }
    if (!incoming_known) {
        output_state = existing_state;
        output_value = existing_value;
        return true;
    }
    if (existing_state != incoming_state) {
        return false;
    }
    if (existing_state == FieldState::observed
            && existing_value != incoming_value) {
        return false;
    }
    output_state = existing_state;
    output_value = existing_value;
    return true;
}

inline bool merge_flags(const Snapshot& existing,
                        const Snapshot& incoming, Snapshot& output) noexcept {
    const std::uint16_t existing_value =
        static_cast<std::uint16_t>(existing.raw_flag_8c) << 8u
        | static_cast<std::uint16_t>(existing.raw_flag_8d);
    const std::uint16_t incoming_value =
        static_cast<std::uint16_t>(incoming.raw_flag_8c) << 8u
        | static_cast<std::uint16_t>(incoming.raw_flag_8d);
    std::uint16_t merged_value = 0u;
    if (!merge_metadata(existing_value, existing.raw_flags_state,
                        incoming_value, incoming.raw_flags_state,
                        output.raw_flags_state, merged_value)) {
        return false;
    }
    output.raw_flag_8c = static_cast<std::uint8_t>(merged_value >> 8u);
    output.raw_flag_8d = static_cast<std::uint8_t>(merged_value & 0xffu);
    return true;
}

struct ReadRecord {
    Address address = 0u;
    std::uint32_t offset = 0u;
    std::uint32_t size = 0u;
};

struct ReadLog {
    std::array<unsigned char, kMaxSingleReadBytes> bytes{};
    std::array<ReadRecord, kMaxReadRecords> records{};
    std::size_t bytes_used = 0u;
    std::size_t record_count = 0u;
};

struct ReadBudget {
    std::size_t remaining = kMaxSingleReadBytes;

    bool reserve(std::size_t size) noexcept {
        if (size == 0u || size > remaining) {
            return false;
        }
        remaining -= size;
        return true;
    }
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
        Address end = 0u;
        // Reserve before touching the source reader.  A failed source read
        // cannot consume a later budget slot or leave a partial value.
        if (destination == nullptr
                || !checked_range(address, size, end)
                || ranges_overlap(address, end, output_begin_, output_end_)
                || !budget_.reserve(size)) {
            return false;
        }
        if (writer_ != nullptr
                && (writer_->record_count >= kMaxReadRecords
                    || writer_->bytes_used > kMaxSingleReadBytes - size)) {
            return false;
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
        ++record_index_;
        return true;
    }

    bool complete() const noexcept {
        if (expected_ == nullptr) {
            return writer_ != nullptr;
        }
        return record_index_ == expected_->record_count
            && bytes_used() == expected_->bytes_used;
    }

    std::size_t bytes_used() const noexcept {
        return kMaxSingleReadBytes - budget_.remaining;
    }

private:
    Reader& reader_;
    Address output_begin_;
    Address output_end_;
    ReadLog* writer_;
    const ReadLog* expected_;
    ReadBudget budget_{};
    std::size_t record_index_ = 0u;
};

template <typename Pass>
bool copy_string(Pass& pass, const unsigned char* object,
                 std::size_t max_length, Snapshot& snapshot,
                 std::size_t& cursor, TextField& field,
                 std::array<unsigned char, kMaxTextBytes + 1u>& scratch)
    noexcept {
    const std::uint64_t length = load_u64(object + kStringLengthOffset);
    const std::uint64_t capacity = load_u64(object + kStringCapacityOffset);
    if (length > max_length || capacity < length
            || capacity > kMaxStringCapacity
            || length > std::numeric_limits<std::uint32_t>::max()) {
        return false;
    }

    const std::size_t text_length = static_cast<std::size_t>(length);
    const unsigned char* source = object;
    if (capacity < kHeapThreshold) {
        if (length > kInlineCapacity || object[text_length] != 0u) {
            return false;
        }
        for (std::size_t index = 0u; index < text_length; ++index) {
            if (object[index] == 0u) {
                return false;
            }
        }
    } else {
        const Address pointer = load_u64(object);
        Address ignored_end = 0u;
        if (!valid_pointer(pointer)
                || !checked_range(pointer, text_length + 1u, ignored_end)
                || !pass.read(pointer, scratch.data(), text_length + 1u)
                || scratch[text_length] != 0u) {
            return false;
        }
        for (std::size_t index = 0u; index < text_length; ++index) {
            if (scratch[index] == 0u) {
                return false;
            }
        }
        source = scratch.data();
    }

    if (cursor > kMaxArenaBytes
            || text_length > kMaxArenaBytes - cursor) {
        return false;
    }
    field.state = FieldState::observed;
    field.bytes.offset = static_cast<std::uint32_t>(cursor);
    field.bytes.length = static_cast<std::uint32_t>(text_length);
    if (text_length != 0u) {
        std::memcpy(snapshot.arena.data() + cursor, source, text_length);
    }
    cursor += text_length;
    return true;
}

template <typename Pass>
bool read_string_at(Pass& pass, Address object_address,
                    std::size_t max_length, Snapshot& snapshot,
                    std::size_t& cursor, TextField& field) noexcept {
    std::array<unsigned char, kStringObjectBytes> object{};
    if (!pass.read(object_address, object.data(), object.size())) {
        return false;
    }
    std::array<unsigned char, kMaxTextBytes + 1u> scratch{};
    return copy_string(pass, object.data(), max_length, snapshot, cursor,
                       field, scratch);
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

// Kept separate from capture_message_one's definition so no dynamic storage
// is ever required for the auxiliary SSO scratch buffer.
template <typename Pass>
bool capture_message_one_bounded(Pass& pass, Address message_ptr,
                                 Snapshot& output) noexcept {
    std::array<unsigned char, kMessageHeaderBytes> header{};
    if (!pass.read(message_ptr, header.data(), header.size())) {
        return false;
    }

    Snapshot candidate = empty_snapshot();
    candidate.native_date_state = FieldState::observed;
    candidate.native_date = load_i32(header.data() + kMessageDateOffset);
    candidate.raw_flags_state = FieldState::observed;
    candidate.raw_flag_8c = header[kMessageFlag8cOffset];
    candidate.raw_flag_8d = header[kMessageFlag8dOffset];

    const Address definition =
        load_u64(header.data() + kMessageDefinitionPointerOffset);
    std::size_t cursor = 0u;
    if (definition == 0u) {
        candidate.definition_key.state = FieldState::absent;
    } else {
        if (!valid_pointer(definition)) {
            return false;
        }
        Address key_address = 0u;
        if (!checked_add(definition, kDefinitionKeyOffset, key_address)
                || !read_string_at(pass, key_address, kMaxKeyBytes,
                                    candidate, cursor,
                                    candidate.definition_key)) {
            return false;
        }
    }

    std::array<unsigned char, kMaxTextBytes + 1u> scratch{};
    if (!copy_string(pass, header.data() + kMessageAuxiliaryOffset,
                     kMaxTextBytes, candidate, cursor,
                     candidate.auxiliary_text, scratch)) {
        return false;
    }
    output = candidate;
    return true;
}

template <typename Pass>
bool capture_string_one(Pass& pass, Address string_object,
                        SourceKind source_kind, Snapshot& output) noexcept {
    TextField* field = field_for(output, source_kind);
    if (field == nullptr) {
        return false;
    }
    field->source_kind = source_kind;
    if (string_object == 0u) {
        field->state = FieldState::absent;
        return true;
    }
    if (!valid_pointer(string_object)) {
        return false;
    }
    std::size_t cursor = 0u;
    return read_string_at(pass, string_object, kMaxTextBytes, output,
                          cursor, *field);
}

template <typename Reader>
bool capture_two_pass(Reader& reader, Address source,
                      SourceKind source_kind, bool message_mode,
                      Snapshot& output) noexcept {
    static_assert(reader_contract<Reader>::value,
                  "Reader::read must be bool(Address,unsigned char*,size_t) noexcept");

    clear_snapshot(output);
    Address output_begin = 0u;
    Address output_end = 0u;
    if (!output_range(output, output_begin, output_end)
            || (message_mode && !valid_pointer(source))) {
        clear_snapshot(output);
        return false;
    }

    if (!message_mode && source == 0u) {
        TextField* field = field_for(output, source_kind);
        if (field == nullptr) {
            clear_snapshot(output);
            return false;
        }
        field->state = FieldState::absent;
        return true;
    }
    if (!message_mode && !valid_pointer(source)) {
        clear_snapshot(output);
        return false;
    }

    ReadLog first_log{};
    Snapshot first = empty_snapshot();
    PassReader<Reader> first_reader(reader, output_begin, output_end,
                                    &first_log, nullptr);
    const bool first_ok = message_mode
        ? capture_message_one_bounded(first_reader, source, first)
        : capture_string_one(first_reader, source, source_kind, first);
    if (!first_ok || !first_reader.complete()
            || first_reader.bytes_used() > kMaxSingleReadBytes) {
        clear_snapshot(output);
        return false;
    }

    Snapshot second = empty_snapshot();
    PassReader<Reader> second_reader(reader, output_begin, output_end,
                                     nullptr, &first_log);
    const bool second_ok = message_mode
        ? capture_message_one_bounded(second_reader, source, second)
        : capture_string_one(second_reader, source, source_kind, second);
    if (!second_ok || !second_reader.complete()
            || first_reader.bytes_used() + second_reader.bytes_used()
                > kMaxTotalReadBytes
            || !same_snapshot(first, second)) {
        clear_snapshot(output);
        return false;
    }

    output = first;
    return true;
}

}  // namespace detail

inline bool valid_snapshot(const Snapshot& snapshot) noexcept {
    return detail::snapshot_valid(snapshot);
}

// Merge is value-only and alias-safe: output may be either input snapshot.
// A known contradiction (observed/absent state or differing observed bytes,
// date, or flags) clears output and returns false.  Unknown fields do not
// erase a known value.  The result always owns a freshly packed arena.
inline bool merge(const Snapshot& existing, const Snapshot& incoming,
                  Snapshot& output) noexcept {
    if (!detail::snapshot_valid(existing)
            || !detail::snapshot_valid(incoming)) {
        detail::clear_snapshot(output);
        return false;
    }

    Snapshot candidate = detail::empty_snapshot();
    std::size_t cursor = 0u;
    if (!detail::merge_field(existing, existing.definition_key,
                             incoming, incoming.definition_key,
                             candidate, candidate.definition_key, cursor)
            || !detail::merge_field(existing, existing.auxiliary_text,
                                    incoming, incoming.auxiliary_text,
                                    candidate, candidate.auxiliary_text,
                                    cursor)
            || !detail::merge_field(existing,
                                    existing.title_helper_candidate,
                                    incoming,
                                    incoming.title_helper_candidate,
                                    candidate,
                                    candidate.title_helper_candidate,
                                    cursor)
            || !detail::merge_field(existing, existing.native_line1,
                                    incoming, incoming.native_line1,
                                    candidate, candidate.native_line1,
                                    cursor)
            || !detail::merge_metadata(existing.native_date,
                                       existing.native_date_state,
                                       incoming.native_date,
                                       incoming.native_date_state,
                                       candidate.native_date_state,
                                       candidate.native_date)
            || !detail::merge_flags(existing, incoming, candidate)) {
        detail::clear_snapshot(output);
        return false;
    }

    if (!detail::snapshot_valid(candidate)) {
        detail::clear_snapshot(output);
        return false;
    }
    output = candidate;
    return true;
}

template <typename Reader>
bool capture(Reader& reader, Address message_ptr, Snapshot& output) noexcept {
    return detail::capture_two_pass(reader, message_ptr,
                                    SourceKind::message_metadata, true,
                                    output);
}

template <typename Reader>
bool capture_message(Reader& reader, Address message_ptr,
                     Snapshot& output) noexcept {
    return capture(reader, message_ptr, output);
}

template <typename Reader>
bool capture_string(Reader& reader, Address string_object,
                    SourceKind source_kind, Snapshot& output) noexcept {
    if (source_kind == SourceKind::message_metadata) {
        // Message metadata has two distinct fields (definition key and
        // auxiliary text) and is captured atomically by capture(message,...).
        detail::clear_snapshot(output);
        return false;
    }
    return detail::capture_two_pass(reader, string_object, source_kind, false,
                                    output);
}

inline void clear(Snapshot& output) noexcept {
    detail::clear_snapshot(output);
}

}  // namespace information::battle::owned_native_text

#endif  // INFORMATION_BATTLE_OWNED_NATIVE_TEXT_H
