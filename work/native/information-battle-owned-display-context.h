#ifndef INFORMATION_BATTLE_OWNED_DISPLAY_CONTEXT_H
#define INFORMATION_BATTLE_OWNED_DISPLAY_CONTEXT_H

// Pure, bounded read-only copy of the current battle definition and
// localization-cache inputs. It does not call game code, perform lookup
// fallbacks, mutate source memory, decode text, or claim that a popup was
// rendered or visible.

#include "information-battle-display-context-layout.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <type_traits>

namespace information::battle::owned_display_context {

namespace model = display_context;
using Address = std::uintptr_t;

static_assert(sizeof(Address) == 8u, "the pinned process is x64");

constexpr Address kMinCanonicalAddress = UINT64_C(0x10000);
constexpr Address kMaxCanonicalExclusive = UINT64_C(0x800000000000);

constexpr std::size_t kGameDateOffset = 0x1dd0u;
constexpr std::size_t kDefinitionManagerCellRva = 0x242bcd8u;
constexpr std::size_t kLocalizationCellRva = 0x2357b00u;

constexpr std::size_t kManagerBucketCountOffset = 0x4u;
constexpr std::size_t kManagerBucketArrayOffset = 0x8u;
constexpr std::size_t kManagerHeaderBytes = 0x10u;
constexpr std::size_t kNodeDefinitionOffset = 0x0u;
constexpr std::size_t kNodeNextOffset = 0x8u;
constexpr std::size_t kNodeBytes = 0x10u;
constexpr std::size_t kDefinitionKeyOffset = 0x38u;
constexpr std::size_t kDefinitionKeyHeaderBytes = 0x20u;
constexpr std::size_t kDefinitionPopupKindOffset = 0x58u;
constexpr std::size_t kDefinitionLayoutOffset = 0x5cu;
constexpr std::size_t kDefinitionButtonFlagOffset = 0x60u;
constexpr std::size_t kDefinitionScalarsBytes = 0x9u;

constexpr std::size_t kLocalizationOuterInnerOffset = 0x0u;
constexpr std::size_t kLocalizationPoolBeginOffset = 0x20u;
constexpr std::size_t kLocalizationPoolEndOffset = 0x28u;
constexpr std::size_t kLocalizationPoolCapacityEndOffset = 0x30u;
constexpr std::size_t kLocalizationOuterHeaderBytes = 0x38u;
constexpr std::size_t kLocalizationLanguageOffset = 0x0u;
constexpr std::size_t kLocalizationTableBeginOffset = 0x20u;
constexpr std::size_t kLocalizationTableEndOffset = 0x28u;
constexpr std::size_t kLocalizationTableCapacityOffset = 0x30u;
constexpr std::size_t kLocalizationInnerHeaderBytes = 0x38u;
constexpr std::size_t kString32Bytes = 0x20u;
constexpr std::size_t kString32LengthOffset = 0x10u;
constexpr std::size_t kString32CapacityOffset = 0x18u;
constexpr std::size_t kLocalizationEntryStride = 16u;
constexpr std::size_t kLocalizationEntryHashOffset = 0x0u;
constexpr std::size_t kLocalizationEntryValueOffset = 0x8u;

constexpr std::size_t kMaxBucketCount = 65536u;
constexpr std::size_t kMaxDefinitionNodesPerBucket = 64u;
constexpr std::size_t kMaxDefinitionStringCapacity = 8192u;
constexpr std::size_t kMaxLanguageStringCapacity = 4096u;
constexpr std::size_t kMaxLocalizationTableEntries = 1048576u;
constexpr std::size_t kMaxLocalizationTableBytes = 16777216u;
constexpr std::size_t kMaxLocalizationPoolBytes = 134217728u;

constexpr std::size_t kMaxTotalReadCalls = 4096u;
constexpr std::size_t kMaxTotalReadBytes = 512u * 1024u;
constexpr std::size_t kMaxReadCallsPerPass = kMaxTotalReadCalls / 2u;
constexpr std::size_t kMaxReadBytesPerPass = kMaxTotalReadBytes / 2u;
constexpr std::size_t kMaxSingleReadBytes = 8193u;

struct Result final {
    bool attempted = false;
    bool observed = false;
    bool two_pass_consistent = false;
    model::Failure failure = model::Failure::not_captured;
    std::uint32_t read_calls = 0u;
    std::uint32_t bytes_read = 0u;
    std::array<std::uint32_t, 2u> pass_read_calls{};
    std::array<std::uint32_t, 2u> pass_bytes_read{};
    std::uint32_t largest_read = 0u;
};

namespace detail {

struct AddressRange final {
    Address begin = 0u;
    Address end = 0u;
};

struct ReadRecord final {
    Address address = 0u;
    std::uint32_t offset = 0u;
    std::uint32_t size = 0u;
};

struct ReadLog final {
    std::array<unsigned char, kMaxReadBytesPerPass> bytes{};
    std::array<ReadRecord, kMaxReadCallsPerPass> records{};
    std::size_t bytes_used = 0u;
    std::size_t record_count = 0u;
};

inline bool checked_range(Address address, std::size_t size,
                          Address& end) noexcept {
    if (size == 0u || address < kMinCanonicalAddress
            || address >= kMaxCanonicalExclusive
            || size > static_cast<std::size_t>(
                          std::numeric_limits<Address>::max() - address)) {
        return false;
    }
    end = address + static_cast<Address>(size);
    return end > address && end <= kMaxCanonicalExclusive;
}

inline bool checked_add(Address base, std::size_t offset,
                        Address& address) noexcept {
    if (offset > static_cast<std::size_t>(
                     std::numeric_limits<Address>::max())
            || base > std::numeric_limits<Address>::max()
                           - static_cast<Address>(offset)) {
        return false;
    }
    address = base + static_cast<Address>(offset);
    return true;
}

inline bool valid_pointer(Address value) noexcept {
    return value >= kMinCanonicalAddress
        && value < kMaxCanonicalExclusive
        && (value % alignof(Address)) == 0u;
}

inline bool valid_unaligned_address(Address value) noexcept {
    return value >= kMinCanonicalAddress
        && value < kMaxCanonicalExclusive;
}

inline bool ranges_overlap(AddressRange left, AddressRange right) noexcept {
    return left.begin < right.end && right.begin < left.end;
}

inline bool object_range(const void* object, std::size_t bytes,
                         AddressRange& range) noexcept {
    const Address begin = reinterpret_cast<Address>(object);
    Address end = 0u;
    if (object == nullptr || !checked_range(begin, bytes, end)) {
        return false;
    }
    range = {begin, end};
    return true;
}

inline bool image_address(Address base, std::size_t image_size,
                          std::size_t rva, std::size_t bytes,
                          Address& address) noexcept {
    Address image_end = 0u;
    if (!checked_range(base, image_size, image_end)
            || rva > image_size || bytes > image_size - rva
            || !checked_add(base, rva, address)) {
        return false;
    }
    Address range_end = 0u;
    return checked_range(address, bytes, range_end)
        && range_end <= image_end;
}

inline bool load_u64(const unsigned char* bytes, std::size_t length,
                     std::size_t offset, std::uint64_t& value) noexcept {
    if (offset > length || sizeof(value) > length - offset) return false;
    std::memcpy(&value, bytes + offset, sizeof(value));
    return true;
}

inline bool load_u32(const unsigned char* bytes, std::size_t length,
                     std::size_t offset, std::uint32_t& value) noexcept {
    if (offset > length || sizeof(value) > length - offset) return false;
    std::memcpy(&value, bytes + offset, sizeof(value));
    return true;
}

inline bool load_i32(const unsigned char* bytes, std::size_t length,
                     std::size_t offset, std::int32_t& value) noexcept {
    if (offset > length || sizeof(value) > length - offset) return false;
    std::memcpy(&value, bytes + offset, sizeof(value));
    return true;
}

inline std::uint32_t definition_hash(const char* key) noexcept {
    std::uint32_t hash = 0u;
    for (const unsigned char* byte =
             reinterpret_cast<const unsigned char*>(key);
         *byte != 0u; ++byte) {
        hash = static_cast<std::uint32_t>(
            (static_cast<std::uint64_t>(hash) + *byte) * 61u);
    }
    return hash;
}

inline std::uint32_t localization_hash(const char* key) noexcept {
    std::uint32_t hash = UINT32_C(0x811c9dc5);
    for (const unsigned char* byte =
             reinterpret_cast<const unsigned char*>(key);
         *byte != 0u; ++byte) {
        hash = static_cast<std::uint32_t>(
            static_cast<std::uint64_t>(hash) * UINT32_C(0x01000193));
        hash ^= *byte;
    }
    return hash;
}

inline bool same_snapshot(const model::Snapshot& left,
                          const model::Snapshot& right) noexcept {
    if (left.state != right.state || left.failure != right.failure
            || left.identity.sequence != right.identity.sequence
            || left.identity.date != right.identity.date
            || left.identity.kind != right.identity.kind
            || left.identity.stage != right.identity.stage
            || left.popup_kind_raw != right.popup_kind_raw
            || left.layout_raw != right.layout_raw
            || left.button_flag_raw != right.button_flag_raw
            || left.arena_used != right.arena_used) {
        return false;
    }
    for (std::size_t index = 0u; index < model::kFieldCount; ++index) {
        const model::Text& a = left.fields[index];
        const model::Text& b = right.fields[index];
        if (a.state != b.state || a.offset != b.offset || a.length != b.length) {
            return false;
        }
    }
    return left.arena_used <= model::kArenaBytes
        && std::memcmp(left.arena.data(), right.arena.data(),
                       left.arena_used) == 0;
}

inline void set_failure(model::Failure& current,
                        model::Failure failure) noexcept {
    if (current == model::Failure::none) current = failure;
}

template <typename Reader, typename WorkspaceType>
class PassReader final {
public:
    PassReader(Reader& source, WorkspaceType& workspace, Result& result,
               std::size_t pass_index, AddressRange workspace_range,
               AddressRange snapshot_range, AddressRange result_range,
               ReadLog* writer, const ReadLog* expected) noexcept
        : source_(source), workspace_(workspace), result_(result),
          pass_index_(pass_index), workspace_range_(workspace_range),
          snapshot_range_(snapshot_range), result_range_(result_range),
          writer_(writer), expected_(expected) {}

    bool read(Address address, std::size_t size) noexcept {
        if (result_.failure != model::Failure::none) return false;
        Address end = 0u;
        if (size == 0u || size > kMaxSingleReadBytes
                || !checked_range(address, size, end)) {
            set_failure(result_.failure, model::Failure::cache_invalid);
            return false;
        }
        const AddressRange source_range{address, end};
        if (ranges_overlap(source_range, workspace_range_)
                || ranges_overlap(source_range, snapshot_range_)
                || ranges_overlap(source_range, result_range_)) {
            set_failure(result_.failure, model::Failure::invalid_input);
            return false;
        }
        if (result_.read_calls >= kMaxTotalReadCalls
                || result_.bytes_read > kMaxTotalReadBytes - size
                || result_.pass_read_calls[pass_index_] >= kMaxReadCallsPerPass
                || result_.pass_bytes_read[pass_index_]
                       > kMaxReadBytesPerPass - size) {
            set_failure(result_.failure, model::Failure::budget);
            return false;
        }
        if (writer_ != nullptr
                && (writer_->record_count >= writer_->records.size()
                    || writer_->bytes_used > writer_->bytes.size() - size)) {
            set_failure(result_.failure, model::Failure::budget);
            return false;
        }
        if (expected_ != nullptr) {
            if (record_index_ >= expected_->record_count) {
                set_failure(result_.failure, model::Failure::source_changed);
                return false;
            }
            const ReadRecord& expected = expected_->records[record_index_];
            if (expected.address != address || expected.size != size
                    || expected.offset > expected_->bytes_used
                    || size > expected_->bytes_used - expected.offset) {
                set_failure(result_.failure, model::Failure::source_changed);
                return false;
            }
        }

        ++result_.read_calls;
        result_.bytes_read += static_cast<std::uint32_t>(size);
        ++result_.pass_read_calls[pass_index_];
        result_.pass_bytes_read[pass_index_] += static_cast<std::uint32_t>(size);
        if (size > result_.largest_read) {
            result_.largest_read = static_cast<std::uint32_t>(size);
        }

        if (!source_.read(address, workspace_.scratch.data(), size)) {
            set_failure(result_.failure, model::Failure::read_failed);
            return false;
        }
        if (expected_ != nullptr) {
            const ReadRecord& expected = expected_->records[record_index_];
            if (std::memcmp(workspace_.scratch.data(),
                            expected_->bytes.data() + expected.offset,
                            size) != 0) {
                set_failure(result_.failure, model::Failure::source_changed);
                return false;
            }
        }
        if (writer_ != nullptr) {
            ReadRecord& record = writer_->records[writer_->record_count++];
            record.address = address;
            record.offset = static_cast<std::uint32_t>(writer_->bytes_used);
            record.size = static_cast<std::uint32_t>(size);
            std::memcpy(writer_->bytes.data() + writer_->bytes_used,
                        workspace_.scratch.data(), size);
            writer_->bytes_used += size;
        }
        ++record_index_;
        return true;
    }

    bool complete() noexcept {
        if (result_.failure != model::Failure::none) return false;
        if (expected_ == nullptr) return writer_ != nullptr;
        if (record_index_ != expected_->record_count
                || result_.pass_bytes_read[pass_index_]
                       != expected_->bytes_used) {
            set_failure(result_.failure, model::Failure::source_changed);
            return false;
        }
        return true;
    }

    void fail(model::Failure failure) noexcept {
        set_failure(result_.failure, failure);
    }

    unsigned char* scratch() noexcept { return workspace_.scratch.data(); }
    model::Failure failure() const noexcept { return result_.failure; }

private:
    Reader& source_;
    // WorkspaceType is dependent so this helper can be defined before the
    // caller-owned Workspace storage declaration.
    WorkspaceType& workspace_;
    Result& result_;
    std::size_t pass_index_;
    AddressRange workspace_range_;
    AddressRange snapshot_range_;
    AddressRange result_range_;
    ReadLog* writer_;
    const ReadLog* expected_;
    std::size_t record_index_ = 0u;
};

inline bool append_field(model::Snapshot& snapshot, std::size_t field_index,
                         const unsigned char* bytes,
                         std::size_t length) noexcept {
    if (field_index >= model::kFieldCount
            || (bytes == nullptr && length != 0u)
            || length > model::field_limit(field_index)
            || snapshot.arena_used > model::kArenaBytes
            || length > model::kArenaBytes - snapshot.arena_used
            || (length != 0u && std::memchr(bytes, 0, length) != nullptr)) {
        return false;
    }
    model::Text& field = snapshot.fields[field_index];
    field.state = model::State::observed;
    field.offset = snapshot.arena_used;
    field.length = static_cast<std::uint32_t>(length);
    if (length != 0u) {
        std::memcpy(snapshot.arena.data() + snapshot.arena_used, bytes, length);
    }
    snapshot.arena_used += static_cast<std::uint32_t>(length);
    return true;
}

inline bool set_absent(model::Snapshot& snapshot,
                       std::size_t field_index) noexcept {
    if (field_index >= model::kFieldCount) return false;
    snapshot.fields[field_index] = model::Text{};
    snapshot.fields[field_index].state = model::State::absent;
    return true;
}

inline bool valid_language(const unsigned char* bytes,
                           std::size_t length) noexcept;
inline bool validate_pool(Address begin, Address end,
                          Address capacity_end) noexcept;
inline bool validate_table(Address begin, Address end,
                           std::size_t& count) noexcept;

template <typename Pass>
bool read_definition_key(Pass& pass, Address definition,
                         const char* expected_key, std::size_t expected_length,
                         model::Snapshot& snapshot,
                         bool& matches) noexcept {
    Address header_address = 0u;
    if (!checked_add(definition, kDefinitionKeyOffset, header_address)
            || !valid_pointer(definition)
            || !pass.read(header_address, kDefinitionKeyHeaderBytes)) {
        pass.fail(model::Failure::cache_invalid);
        return false;
    }
    const unsigned char* header = pass.scratch();
    std::uint64_t length_raw = 0u;
    std::uint64_t capacity = 0u;
    if (!load_u64(header, kDefinitionKeyHeaderBytes,
                  kString32LengthOffset, length_raw)
            || !load_u64(header, kDefinitionKeyHeaderBytes,
                         kString32CapacityOffset, capacity)
            || length_raw > model::kMaxDefinitionKeyBytes
            || capacity < length_raw
            || capacity > kMaxDefinitionStringCapacity) {
        pass.fail(model::Failure::cache_invalid);
        return false;
    }
    const std::size_t length = static_cast<std::size_t>(length_raw);
    const unsigned char* value = header;
    if (capacity < 16u) {
        if (length > 15u || length > capacity || header[length] != 0u) {
            pass.fail(model::Failure::cache_invalid);
            return false;
        }
    } else {
        std::uint64_t pointer_raw = 0u;
        if (!load_u64(header, kDefinitionKeyHeaderBytes, 0u, pointer_raw)
                || !valid_pointer(static_cast<Address>(pointer_raw))) {
            pass.fail(model::Failure::cache_invalid);
            return false;
        }
        if (!pass.read(static_cast<Address>(pointer_raw), length + 1u)) {
            return false;
        }
        value = pass.scratch();
        if (value[length] != 0u) {
            pass.fail(model::Failure::cache_invalid);
            return false;
        }
    }
    if (length != 0u && std::memchr(value, 0, length) != nullptr) {
        pass.fail(model::Failure::cache_invalid);
        return false;
    }
    matches = length == expected_length
        && std::memcmp(value, expected_key, expected_length) == 0;
    if (matches && !append_field(snapshot, 0u, value, length)) {
        pass.fail(model::Failure::cache_invalid);
        return false;
    }
    return true;
}

template <typename Pass>
bool capture_definition(Pass& pass, Address base, std::size_t image_size,
                        std::uint8_t kind,
                        model::Snapshot& snapshot) noexcept {
    const char* expected_key = kind == 1u
        ? "LANDBATTLEOVER" : "NAVALBATTLEOVER";
    const std::size_t expected_length = kind == 1u ? 14u : 15u;

    Address cell = 0u;
    if (!image_address(base, image_size, kDefinitionManagerCellRva,
                       sizeof(Address), cell)
            || !pass.read(cell, sizeof(Address))) {
        pass.fail(model::Failure::invalid_input);
        return false;
    }
    std::uint64_t manager_raw = 0u;
    if (!load_u64(pass.scratch(), sizeof(Address), 0u, manager_raw)) {
        pass.fail(model::Failure::cache_invalid);
        return false;
    }
    const Address manager = static_cast<Address>(manager_raw);
    if (!valid_pointer(manager)) {
        pass.fail(model::Failure::cache_invalid);
        return false;
    }
    Address manager_header_address = 0u;
    if (!checked_add(manager, 0u, manager_header_address)
            || !pass.read(manager_header_address, kManagerHeaderBytes)) {
        pass.fail(model::Failure::cache_invalid);
        return false;
    }
    const unsigned char* manager_header = pass.scratch();
    std::uint32_t bucket_count_raw = 0u;
    std::uint64_t bucket_array_raw = 0u;
    if (!load_u32(manager_header, kManagerHeaderBytes,
                  kManagerBucketCountOffset, bucket_count_raw)
            || !load_u64(manager_header, kManagerHeaderBytes,
                         kManagerBucketArrayOffset, bucket_array_raw)
            || bucket_count_raw == 0u
            || bucket_count_raw > kMaxBucketCount
            || !valid_pointer(static_cast<Address>(bucket_array_raw))) {
        pass.fail(model::Failure::cache_invalid);
        return false;
    }
    const std::size_t bucket_array_bytes =
        static_cast<std::size_t>(bucket_count_raw) * sizeof(Address);
    Address bucket_array_end = 0u;
    if (!checked_range(static_cast<Address>(bucket_array_raw),
                       bucket_array_bytes, bucket_array_end)) {
        pass.fail(model::Failure::cache_invalid);
        return false;
    }
    (void)bucket_array_end;

    const std::uint32_t hash = definition_hash(expected_key);
    const std::size_t bucket_index = hash % bucket_count_raw;
    Address bucket_head_address = 0u;
    if (!checked_add(static_cast<Address>(bucket_array_raw),
                     bucket_index * sizeof(Address), bucket_head_address)
            || !pass.read(bucket_head_address, sizeof(Address))) {
        pass.fail(model::Failure::cache_invalid);
        return false;
    }
    std::uint64_t head_raw = 0u;
    if (!load_u64(pass.scratch(), sizeof(Address), 0u, head_raw)) {
        pass.fail(model::Failure::cache_invalid);
        return false;
    }
    Address current = static_cast<Address>(head_raw);
    if (current != 0u && !valid_pointer(current)) {
        pass.fail(model::Failure::cache_invalid);
        return false;
    }

    std::array<Address, kMaxDefinitionNodesPerBucket> seen_nodes{};
    std::array<Address, kMaxDefinitionNodesPerBucket> seen_definitions{};
    std::size_t node_count = 0u;
    std::size_t matches = 0u;
    while (current != 0u) {
        if (!valid_pointer(current)
                || node_count >= kMaxDefinitionNodesPerBucket) {
            pass.fail(model::Failure::cache_invalid);
            return false;
        }
        for (std::size_t index = 0u; index < node_count; ++index) {
            if (seen_nodes[index] == current) {
                pass.fail(model::Failure::cache_invalid);
                return false;
            }
        }
        seen_nodes[node_count] = current;
        if (!pass.read(current, kNodeBytes)) return false;
        const unsigned char* node = pass.scratch();
        std::uint64_t definition_raw = 0u;
        std::uint64_t next_raw = 0u;
        if (!load_u64(node, kNodeBytes, kNodeDefinitionOffset, definition_raw)
                || !load_u64(node, kNodeBytes, kNodeNextOffset, next_raw)) {
            pass.fail(model::Failure::cache_invalid);
            return false;
        }
        const Address definition = static_cast<Address>(definition_raw);
        const Address next = static_cast<Address>(next_raw);
        if (!valid_pointer(definition)
                || (next != 0u && !valid_pointer(next))) {
            pass.fail(model::Failure::cache_invalid);
            return false;
        }
        for (std::size_t index = 0u; index < node_count; ++index) {
            if (seen_definitions[index] == definition) {
                pass.fail(model::Failure::ambiguous_scope);
                return false;
            }
        }
        seen_definitions[node_count] = definition;

        bool key_matches = false;
        if (!read_definition_key(pass, definition, expected_key,
                                 expected_length, snapshot, key_matches)) {
            return false;
        }
        if (key_matches) {
            ++matches;
            if (matches > 1u) {
                pass.fail(model::Failure::ambiguous_scope);
                return false;
            }
            Address scalars_address = 0u;
            if (!checked_add(definition, kDefinitionPopupKindOffset,
                             scalars_address)
                    || !pass.read(scalars_address,
                                  kDefinitionScalarsBytes)) {
                pass.fail(model::Failure::cache_invalid);
                return false;
            }
            const unsigned char* scalars = pass.scratch();
            if (!load_i32(scalars, kDefinitionScalarsBytes, 0u,
                          snapshot.popup_kind_raw)
                    || !load_i32(scalars, kDefinitionScalarsBytes, 4u,
                                 snapshot.layout_raw)) {
                pass.fail(model::Failure::cache_invalid);
                return false;
            }
            snapshot.button_flag_raw = scalars[8u];
        }
        ++node_count;
        current = next;
    }
    if (matches == 0u) {
        pass.fail(model::Failure::definition_missing);
        return false;
    }
    return true;
}

template <typename Pass>
bool read_string32(Pass& pass, std::size_t maximum_length,
                   std::size_t maximum_capacity, bool language,
                   const unsigned char* header,
                   model::Snapshot& snapshot, std::size_t field_index) noexcept {
    std::uint64_t length_raw = 0u;
    std::uint64_t capacity = 0u;
    if (!load_u64(header, kString32Bytes, kString32LengthOffset, length_raw)
            || !load_u64(header, kString32Bytes,
                         kString32CapacityOffset, capacity)
            || length_raw > maximum_length || capacity < length_raw
            || capacity > maximum_capacity) {
        pass.fail(model::Failure::cache_invalid);
        return false;
    }
    const std::size_t length = static_cast<std::size_t>(length_raw);
    const unsigned char* value = header;
    if (capacity < 16u) {
        if (length > 15u || length > capacity || header[length] != 0u) {
            pass.fail(model::Failure::cache_invalid);
            return false;
        }
    } else if (length != 0u) {
        std::uint64_t pointer_raw = 0u;
        if (!load_u64(header, kString32Bytes, 0u, pointer_raw)
                || !valid_pointer(static_cast<Address>(pointer_raw))
                || !pass.read(static_cast<Address>(pointer_raw), length + 1u)) {
            if (pass.failure() == model::Failure::none) {
                pass.fail(model::Failure::cache_invalid);
            }
            return false;
        }
        value = pass.scratch();
        if (value[length] != 0u) {
            pass.fail(model::Failure::cache_invalid);
            return false;
        }
    }
    if ((length != 0u && std::memchr(value, 0, length) != nullptr)
            || (language && !valid_language(value, length))) {
        pass.fail(model::Failure::cache_invalid);
        return false;
    }
    if (!append_field(snapshot, field_index, value, length)) {
        pass.fail(model::Failure::cache_invalid);
        return false;
    }
    return true;
}

inline bool valid_language(const unsigned char* bytes,
                           std::size_t length) noexcept {
    if (bytes == nullptr || length < 3u || length > model::kMaxLanguageBytes
            || bytes[0] != 'l' || bytes[1] != '_') {
        return false;
    }
    for (std::size_t index = 0u; index < length; ++index) {
        const unsigned char byte = bytes[index];
        if (!((byte >= 'A' && byte <= 'Z')
                || (byte >= 'a' && byte <= 'z')
                || (byte >= '0' && byte <= '9') || byte == '_')) {
            return false;
        }
    }
    return true;
}

struct LocalizationSource final {
    Address pool_begin = 0u;
    Address pool_end = 0u;
    Address pool_capacity_end = 0u;
    Address table_begin = 0u;
    Address table_end = 0u;
    std::size_t table_count = 0u;
    std::uint64_t raw_table_capacity = 0u;
};

template <typename Pass>
bool capture_localization_headers(Pass& pass, Address base,
                                  std::size_t image_size,
                                  LocalizationSource& source,
                                  model::Snapshot& snapshot) noexcept {
    Address cell = 0u;
    if (!image_address(base, image_size, kLocalizationCellRva,
                       sizeof(Address), cell)
            || !pass.read(cell, sizeof(Address))) {
        pass.fail(model::Failure::invalid_input);
        return false;
    }
    std::uint64_t outer_raw = 0u;
    if (!load_u64(pass.scratch(), sizeof(Address), 0u, outer_raw)) {
        pass.fail(model::Failure::cache_invalid);
        return false;
    }
    const Address outer = static_cast<Address>(outer_raw);
    if (!valid_pointer(outer)) {
        pass.fail(model::Failure::cache_invalid);
        return false;
    }
    if (!pass.read(outer, kLocalizationOuterHeaderBytes)) return false;
    const unsigned char* outer_header = pass.scratch();
    std::uint64_t inner_raw = 0u;
    std::uint64_t pool_begin_raw = 0u;
    std::uint64_t pool_end_raw = 0u;
    std::uint64_t pool_capacity_raw = 0u;
    if (!load_u64(outer_header, kLocalizationOuterHeaderBytes,
                  kLocalizationOuterInnerOffset, inner_raw)
            || !load_u64(outer_header, kLocalizationOuterHeaderBytes,
                         kLocalizationPoolBeginOffset, pool_begin_raw)
            || !load_u64(outer_header, kLocalizationOuterHeaderBytes,
                         kLocalizationPoolEndOffset, pool_end_raw)
            || !load_u64(outer_header, kLocalizationOuterHeaderBytes,
                         kLocalizationPoolCapacityEndOffset,
                         pool_capacity_raw)) {
        pass.fail(model::Failure::cache_invalid);
        return false;
    }
    const Address inner = static_cast<Address>(inner_raw);
    source.pool_begin = static_cast<Address>(pool_begin_raw);
    source.pool_end = static_cast<Address>(pool_end_raw);
    source.pool_capacity_end = static_cast<Address>(pool_capacity_raw);
    if (!valid_pointer(inner)
            || !validate_pool(source.pool_begin, source.pool_end,
                              source.pool_capacity_end)) {
        pass.fail(model::Failure::cache_invalid);
        return false;
    }

    if (!pass.read(inner, kLocalizationInnerHeaderBytes)) return false;
    const unsigned char* inner_header = pass.scratch();
    std::uint64_t table_begin_raw = 0u;
    std::uint64_t table_end_raw = 0u;
    if (!load_u64(inner_header, kLocalizationInnerHeaderBytes,
                  kLocalizationTableBeginOffset, table_begin_raw)
            || !load_u64(inner_header, kLocalizationInnerHeaderBytes,
                         kLocalizationTableEndOffset, table_end_raw)
            || !load_u64(inner_header, kLocalizationInnerHeaderBytes,
                         kLocalizationTableCapacityOffset,
                         source.raw_table_capacity)) {
        pass.fail(model::Failure::cache_invalid);
        return false;
    }
    source.table_begin = static_cast<Address>(table_begin_raw);
    source.table_end = static_cast<Address>(table_end_raw);
    if (!validate_table(source.table_begin, source.table_end,
                        source.table_count)) {
        pass.fail(model::Failure::cache_invalid);
        return false;
    }
    if (!read_string32(pass, model::kMaxLanguageBytes,
                       kMaxLanguageStringCapacity, true,
                       inner_header + kLocalizationLanguageOffset,
                       snapshot, 1u)) {
        return false;
    }
    return true;
}

inline bool validate_pool(Address begin, Address end,
                          Address capacity_end) noexcept {
    if (begin == 0u && end == 0u && capacity_end == 0u) return true;
    if (!valid_pointer(begin) || !valid_unaligned_address(end)
            || !valid_unaligned_address(capacity_end)
            || end < begin || capacity_end < end) {
        return false;
    }
    const Address length = end - begin;
    const Address capacity_length = capacity_end - begin;
    Address ignored = 0u;
    return length <= kMaxLocalizationPoolBytes
        && capacity_length <= kMaxLocalizationPoolBytes
        && capacity_length >= length
        && (capacity_length == 0u
            || checked_range(begin,
                             static_cast<std::size_t>(capacity_length),
                             ignored));
}

inline bool validate_table(Address begin, Address end,
                           std::size_t& count) noexcept {
    count = 0u;
    if (begin == 0u && end == 0u) return true;
    if (!valid_pointer(begin) || !valid_unaligned_address(end) || end < begin) {
        return false;
    }
    const Address span = end - begin;
    if (span % kLocalizationEntryStride != 0u
            || span > kMaxLocalizationTableBytes) {
        return false;
    }
    count = static_cast<std::size_t>(span / kLocalizationEntryStride);
    if (count > kMaxLocalizationTableEntries) return false;
    if (span != 0u) {
        Address ignored = 0u;
        if (!checked_range(begin, static_cast<std::size_t>(span), ignored)) {
            return false;
        }
    }
    return true;
}

template <typename Pass>
bool read_table_entry(Pass& pass, const LocalizationSource& source,
                      std::size_t index, std::uint64_t& hash,
                      std::uint32_t& offset) noexcept {
    if (index >= source.table_count) {
        pass.fail(model::Failure::cache_invalid);
        return false;
    }
    Address entry_address = 0u;
    if (!checked_add(source.table_begin,
                     index * kLocalizationEntryStride, entry_address)
            || !pass.read(entry_address, kLocalizationEntryStride)) {
        pass.fail(model::Failure::cache_invalid);
        return false;
    }
    const unsigned char* entry = pass.scratch();
    if (!load_u64(entry, kLocalizationEntryStride,
                  kLocalizationEntryHashOffset, hash)
            || !load_u32(entry, kLocalizationEntryStride,
                         kLocalizationEntryValueOffset, offset)) {
        pass.fail(model::Failure::cache_invalid);
        return false;
    }
    return true;
}

template <typename Pass>
bool lookup_localization(Pass& pass, const LocalizationSource& source,
                         const char* key, model::Snapshot& snapshot,
                         std::size_t field_index) noexcept {
    const std::uint64_t target_hash = localization_hash(key);
    std::size_t low = 0u;
    std::size_t high = source.table_count;
    while (low < high) {
        const std::size_t middle = low + (high - low) / 2u;
        std::uint64_t observed_hash = 0u;
        std::uint32_t ignored_offset = 0u;
        if (!read_table_entry(pass, source, middle,
                              observed_hash, ignored_offset)) {
            return false;
        }
        if (observed_hash < target_hash) low = middle + 1u;
        else high = middle;
    }

    if (low == source.table_count) {
        return set_absent(snapshot, field_index);
    }

    std::uint64_t lower_hash = 0u;
    std::uint32_t value_offset = 0u;
    if (!read_table_entry(pass, source, low, lower_hash, value_offset)) {
        return false;
    }
    if (low > 0u) {
        std::uint64_t previous_hash = 0u;
        std::uint32_t ignored_offset = 0u;
        if (!read_table_entry(pass, source, low - 1u,
                              previous_hash, ignored_offset)) {
            return false;
        }
        if (previous_hash >= lower_hash) {
            pass.fail(model::Failure::cache_invalid);
            return false;
        }
    }
    if (low + 1u < source.table_count) {
        std::uint64_t next_hash = 0u;
        std::uint32_t ignored_offset = 0u;
        if (!read_table_entry(pass, source, low + 1u,
                              next_hash, ignored_offset)) {
            return false;
        }
        if (next_hash <= lower_hash) {
            pass.fail(model::Failure::cache_invalid);
            return false;
        }
    }
    if (lower_hash != target_hash) {
        return set_absent(snapshot, field_index);
    }

    const Address pool_length = source.pool_end - source.pool_begin;
    if (source.pool_begin == 0u || value_offset >= pool_length) {
        pass.fail(model::Failure::cache_invalid);
        return false;
    }
    Address value_address = 0u;
    if (!checked_add(source.pool_begin, value_offset, value_address)
            || !valid_unaligned_address(value_address)
            || value_address >= source.pool_end) {
        pass.fail(model::Failure::cache_invalid);
        return false;
    }
    const Address remaining = source.pool_end - value_address;
    std::size_t requested = static_cast<std::size_t>(
        remaining < 256u ? remaining : 256u);
    for (;;) {
        if (requested == 0u || requested > kMaxSingleReadBytes
                || !pass.read(value_address, requested)) {
            if (pass.failure() == model::Failure::none) {
                pass.fail(model::Failure::cache_invalid);
            }
            return false;
        }
        const unsigned char* bytes = pass.scratch();
        std::size_t length = 0u;
        while (length < requested && bytes[length] != 0u) ++length;
        if (length < requested) {
            if (length > model::kMaxTextBytes
                    || !append_field(snapshot, field_index, bytes, length)) {
                pass.fail(model::Failure::cache_invalid);
                return false;
            }
            return true;
        }
        if (requested >= model::kMaxTextBytes + 1u
                || requested >= remaining) {
            pass.fail(model::Failure::cache_invalid);
            return false;
        }
        const std::size_t doubled = requested > (model::kMaxTextBytes + 1u) / 2u
            ? model::kMaxTextBytes + 1u : requested * 2u;
        const std::size_t remaining_size = static_cast<std::size_t>(remaining);
        requested = doubled < remaining_size ? doubled : remaining_size;
    }
}

inline const char* body_key(std::uint8_t kind) noexcept {
    return kind == 1u ? "LANDBATTLEOVER_1" : "NAVALBATTLEOVER_1";
}
inline const char* button1_key(std::uint8_t kind) noexcept {
    return kind == 1u ? "LANDBATTLEOVER_BTN1" : "NAVALBATTLEOVER_BTN1";
}
inline const char* button2_key(std::uint8_t kind) noexcept {
    return kind == 1u ? "LANDBATTLEOVER_BTN2" : "NAVALBATTLEOVER_BTN2";
}
inline const char* button3_key(std::uint8_t kind) noexcept {
    return kind == 1u ? "LANDBATTLEOVER_BTN3" : "NAVALBATTLEOVER_BTN3";
}

template <typename Pass>
bool capture_one(Pass& pass, Address base, std::size_t image_size,
                 Address game, const model::Identity& identity,
                 model::Snapshot& snapshot) noexcept {
    Address date_address = 0u;
    if (!checked_add(game, kGameDateOffset, date_address)
            || !pass.read(date_address, sizeof(std::int32_t))) {
        pass.fail(model::Failure::invalid_input);
        return false;
    }
    std::int32_t date = 0;
    if (!load_i32(pass.scratch(), sizeof(std::int32_t), 0u, date)) {
        pass.fail(model::Failure::cache_invalid);
        return false;
    }
    if (date != identity.date) {
        pass.fail(model::Failure::guard);
        return false;
    }

    snapshot.identity = identity;
    if (!capture_definition(pass, base, image_size, identity.kind, snapshot)) {
        return false;
    }

    LocalizationSource localization{};
    if (!capture_localization_headers(pass, base, image_size,
                                     localization, snapshot)) {
        return false;
    }

    const char* const keys[5] = {
        body_key(identity.kind), button1_key(identity.kind),
        button2_key(identity.kind), button3_key(identity.kind),
        "COMPACT_BATTLE_RESULT_LOSSES",
    };
    for (std::size_t index = 0u; index < 5u; ++index) {
        if (!lookup_localization(pass, localization, keys[index], snapshot,
                                 index + 2u)) {
            return false;
        }
    }

    snapshot.state = model::State::observed;
    snapshot.failure = model::Failure::none;
    if (!model::valid(snapshot)) {
        pass.fail(model::Failure::cache_invalid);
        return false;
    }
    return true;
}

inline bool valid_identity(const model::Identity& identity) noexcept {
    return identity.sequence != 0u
        && (identity.kind == 1u || identity.kind == 2u)
        && identity.stage >= 1u && identity.stage <= model::kRouterScopeExit;
}

} // namespace detail

struct Workspace final {
    model::Snapshot first_snapshot{};
    detail::ReadLog first_pass{};
    std::array<unsigned char, kMaxSingleReadBytes> scratch{};

    void clear() noexcept {
        first_snapshot = model::Snapshot{};
        first_pass = detail::ReadLog{};
        scratch.fill(0u);
    }
};

static_assert(std::is_trivially_copyable<Workspace>::value,
              "the caller-owned workspace must remain fixed value storage");
static_assert(sizeof(Workspace) < 384u * 1024u,
              "workspace remains bounded for static caller storage");

template <typename Reader, typename = void>
struct reader_contract : std::false_type {};

template <typename Reader>
struct reader_contract<Reader, std::void_t<decltype(&Reader::read)>>
    : std::is_same<decltype(&Reader::read),
          bool (Reader::*)(Address, unsigned char*, std::size_t) noexcept> {};

template <typename Reader>
bool capture(Reader& reader, Address base, std::size_t image_size,
             Address game, const model::Identity& identity,
             Workspace& workspace, model::Snapshot& snapshot,
             Result& result) noexcept {
    static_assert(reader_contract<Reader>::value,
                  "Reader::read must be bool(Address,unsigned char*,size_t) noexcept");

    detail::AddressRange workspace_range{};
    detail::AddressRange snapshot_range{};
    detail::AddressRange result_range{};
    if (!detail::object_range(&workspace, sizeof(workspace), workspace_range)
            || !detail::object_range(&snapshot, sizeof(snapshot), snapshot_range)
            || !detail::object_range(&result, sizeof(result), result_range)
            || detail::ranges_overlap(workspace_range, snapshot_range)
            || detail::ranges_overlap(workspace_range, result_range)
            || detail::ranges_overlap(snapshot_range, result_range)) {
        result = Result{};
        result.failure = model::Failure::invalid_input;
        model::clear(snapshot, model::Failure::invalid_input);
        workspace.clear();
        return false;
    }

    workspace.clear();
    model::clear(snapshot);
    result = Result{};
    result.attempted = true;
    result.failure = model::Failure::none;

    Address image_end = 0u;
    Address game_date_address = 0u;
    Address game_date_end = 0u;
    if (!detail::valid_identity(identity)
            || !detail::checked_range(base, image_size, image_end)
            || !detail::valid_pointer(game)
            || !detail::checked_add(game, kGameDateOffset,
                                    game_date_address)
            || !detail::checked_range(game_date_address,
                                      sizeof(std::int32_t), game_date_end)) {
        result.failure = model::Failure::invalid_input;
        model::clear(snapshot, result.failure);
        workspace.clear();
        return false;
    }

    detail::PassReader<Reader, Workspace> first_reader(
        reader, workspace, result, 0u, workspace_range, snapshot_range,
        result_range, &workspace.first_pass, nullptr);
    if (!detail::capture_one(first_reader, base, image_size, game, identity,
                             workspace.first_snapshot)
            || !first_reader.complete()) {
        if (result.failure == model::Failure::none) {
            result.failure = model::Failure::cache_invalid;
        }
        model::clear(snapshot, result.failure);
        workspace.clear();
        return false;
    }

    detail::PassReader<Reader, Workspace> second_reader(
        reader, workspace, result, 1u, workspace_range, snapshot_range,
        result_range, nullptr, &workspace.first_pass);
    if (!detail::capture_one(second_reader, base, image_size, game, identity,
                             snapshot)
            || !second_reader.complete()
            || !detail::same_snapshot(workspace.first_snapshot, snapshot)) {
        if (result.failure == model::Failure::none) {
            result.failure = model::Failure::source_changed;
        }
        model::clear(snapshot, result.failure);
        workspace.clear();
        return false;
    }

    snapshot = workspace.first_snapshot;
    result.observed = true;
    result.two_pass_consistent = true;
    result.failure = model::Failure::none;
    workspace.clear();
    return true;
}

} // namespace information::battle::owned_display_context

#endif // INFORMATION_BATTLE_OWNED_DISPLAY_CONTEXT_H
