#include "../information-battle-owned-native-text.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>

namespace owned = information::battle::owned_native_text;

struct MemoryReader {
    static constexpr std::size_t kBytes = 2u * 1024u * 1024u;

    owned::Address base = UINT64_C(0x20000);
    owned::Address message = base + 0x1000u;
    owned::Address definition = base + 0x3000u;
    owned::Address title = base + 0x6000u;
    owned::Address line1 = base + 0x7000u;
    std::array<unsigned char, kBytes> bytes{};
    std::size_t read_calls = 0u;
    std::size_t header_reads = 0u;
    bool fail = false;
    bool mutate_second_header = false;

    bool read(owned::Address address, unsigned char* destination,
              std::size_t size) noexcept {
        ++read_calls;
        if (fail || destination == nullptr || size == 0u
                || address < base || address - base > bytes.size()
                || size > bytes.size() - (address - base)) {
            return false;
        }
        if (mutate_second_header && address == message
                && size == owned::kMessageHeaderBytes
                && header_reads == 1u) {
            const std::int32_t changed = 0x13572468;
            std::memcpy(bytes.data() + (message - base)
                            + owned::kMessageDateOffset,
                        &changed, sizeof(changed));
        }
        std::memcpy(destination, bytes.data() + (address - base), size);
        if (address == message && size == owned::kMessageHeaderBytes) {
            ++header_reads;
        }
        return true;
    }

    void reset() noexcept {
        bytes.fill(0u);
        read_calls = 0u;
        header_reads = 0u;
        fail = false;
        mutate_second_header = false;
    }

    void put_u64(owned::Address address, std::uint64_t value) noexcept {
        std::memcpy(bytes.data() + (address - base), &value, sizeof(value));
    }

    void put_i32(owned::Address address, std::int32_t value) noexcept {
        std::memcpy(bytes.data() + (address - base), &value, sizeof(value));
    }

    void put_bytes(owned::Address address, const unsigned char* data,
                   std::size_t size) noexcept {
        if (size != 0u) {
            std::memcpy(bytes.data() + (address - base), data, size);
        }
    }

    void put_sso(owned::Address object, const unsigned char* data,
                 std::size_t length, bool heap,
                 owned::Address heap_address) noexcept {
        std::memset(bytes.data() + (object - base), 0,
                    owned::kStringObjectBytes);
        if (heap) {
            put_u64(object, heap_address);
            put_u64(object + owned::kStringLengthOffset, length);
            put_u64(object + owned::kStringCapacityOffset,
                    length < owned::kHeapThreshold
                        ? owned::kHeapThreshold : length);
            put_bytes(heap_address, data, length);
            bytes[(heap_address - base) + length] = 0u;
        } else {
            put_bytes(object, data, length);
            put_u64(object + owned::kStringLengthOffset, length);
            put_u64(object + owned::kStringCapacityOffset,
                    owned::kInlineCapacity);
            bytes[(object - base) + length] = 0u;
        }
    }

    void put_definition(const unsigned char* key, std::size_t key_length,
                        bool key_heap = false,
                        owned::Address key_heap_address = 0u) noexcept {
        put_sso(definition + owned::kDefinitionKeyOffset, key, key_length,
                key_heap, key_heap_address);
    }

    void put_message(owned::Address definition_pointer,
                     const unsigned char* auxiliary,
                     std::size_t auxiliary_length,
                     bool auxiliary_heap = false,
                     owned::Address auxiliary_heap_address = 0u) noexcept {
        std::memset(bytes.data() + (message - base), 0,
                    owned::kMessageHeaderBytes);
        put_u64(message + owned::kMessageDefinitionPointerOffset,
                definition_pointer);
        put_sso(message + owned::kMessageAuxiliaryOffset, auxiliary,
                auxiliary_length, auxiliary_heap, auxiliary_heap_address);
        put_i32(message + owned::kMessageDateOffset,
                static_cast<std::int32_t>(0x11223344));
        bytes[(message - base) + owned::kMessageFlag8cOffset] = 0xa1u;
        bytes[(message - base) + owned::kMessageFlag8dOffset] = 0x5eu;
    }
};

struct BadReader {
    bool read(owned::Address, unsigned char*, std::size_t) { return true; }
};

static_assert(owned::reader_contract<MemoryReader>::value,
              "fixture reader must satisfy the noexcept contract");
static_assert(!owned::reader_contract<BadReader>::value,
              "throwing-capable reader must be rejected");
static_assert(sizeof(owned::Snapshot) < 32u * 1024u,
              "snapshot must remain below the owned-text bound");

namespace {

int failures = 0;

void check(bool condition, const char* label) {
    std::printf("CHECK %s %s\n", label, condition ? "PASS" : "FAIL");
    if (!condition) {
        ++failures;
    }
}

owned::Snapshot sentinel() {
    owned::Snapshot output{};
    output.definition_key.state = owned::FieldState::observed;
    output.definition_key.bytes = owned::TextRange{2u, 3u};
    output.native_date_state = owned::FieldState::observed;
    output.native_date = -77;
    output.raw_flags_state = owned::FieldState::observed;
    output.raw_flag_8c = 0xf1u;
    output.raw_flag_8d = 0xf2u;
    output.arena[2] = 's';
    output.arena[3] = 'e';
    output.arena[4] = 'n';
    return output;
}

bool is_clear(const owned::Snapshot& value) {
    owned::Snapshot cleared{};
    owned::clear(cleared);
    return std::memcmp(&value, &cleared, sizeof(value)) == 0;
}

bool range_equals(const owned::Snapshot& snapshot, owned::TextRange range,
                  const char* text) {
    const std::size_t length = std::strlen(text);
    return range.length == length
        && std::memcmp(snapshot.arena.data() + range.offset, text, length) == 0;
}

void test_message_metadata_and_raw_fields() {
    std::printf("TEST message_metadata_and_raw_fields\n");
    static MemoryReader reader;
    reader.reset();
    const unsigned char key[] = "LANDBATTLEOVER";
    const unsigned char auxiliary[] = "auxiliary-text";
    reader.put_definition(key, sizeof(key) - 1u);
    reader.put_message(reader.definition, auxiliary, sizeof(auxiliary) - 1u,
                       true, reader.base + 0x12000u);

    owned::Snapshot output{};
    check(owned::capture(reader, reader.message, output),
          "message_capture_passed");
    check(output.definition_key.state == owned::FieldState::observed
              && output.definition_key.source_kind
                   == owned::SourceKind::message_metadata,
          "definition_key_observed");
    check(range_equals(output, output.definition_key.bytes,
                       "LANDBATTLEOVER"), "definition_key_value");
    check(output.auxiliary_text.state == owned::FieldState::observed
              && output.auxiliary_text.source_kind
                   == owned::SourceKind::message_metadata,
          "auxiliary_observed");
    check(range_equals(output, output.auxiliary_text.bytes,
                       "auxiliary-text"), "auxiliary_value");
    check(output.native_date_state == owned::FieldState::observed
              && output.native_date == static_cast<std::int32_t>(0x11223344),
          "native_date_value");
    check(output.raw_flags_state == owned::FieldState::observed
              && output.raw_flag_8c == 0xa1u && output.raw_flag_8d == 0x5eu,
          "raw_flags_preserved");
    check(output.title_helper_candidate.state == owned::FieldState::unknown
              && output.native_line1.state == owned::FieldState::unknown,
          "unrequested_sources_unknown");
    check(reader.header_reads == 2u, "message_header_double_pass");
}

void test_source_kinds_and_empty_values() {
    std::printf("TEST source_kinds_and_empty_values\n");
    static MemoryReader reader;
    reader.reset();
    const unsigned char title_text[] = "BATTLE_OF_PARIS";
    const unsigned char line_text[] = "Line1 heap value";
    reader.put_sso(reader.title, title_text, sizeof(title_text) - 1u,
                   false, 0u);
    reader.put_sso(reader.line1, line_text, sizeof(line_text) - 1u,
                   true, reader.base + 0x13000u);

    owned::Snapshot title{};
    check(owned::capture_string(reader, reader.title,
                               owned::SourceKind::title_helper_candidate,
                               title), "title_capture_passed");
    check(title.title_helper_candidate.state == owned::FieldState::observed
              && title.title_helper_candidate.source_kind
                   == owned::SourceKind::title_helper_candidate,
          "title_source_kind");
    check(range_equals(title, title.title_helper_candidate.bytes,
                       "BATTLE_OF_PARIS"), "title_value");
    check(title.auxiliary_text.state == owned::FieldState::unknown,
          "title_does_not_become_auxiliary");

    owned::Snapshot line;
    check(owned::capture_string(reader, reader.line1,
                               owned::SourceKind::native_line1, line),
          "line1_capture_passed");
    check(line.native_line1.state == owned::FieldState::observed
              && line.native_line1.source_kind
                   == owned::SourceKind::native_line1,
          "line1_source_kind");
    check(range_equals(line, line.native_line1.bytes,
                       "Line1 heap value"), "line1_value");

    owned::Snapshot empty;
    check(owned::capture_string(reader, 0u,
                               owned::SourceKind::title_helper_candidate,
                               empty), "null_title_is_absent");
    check(empty.title_helper_candidate.state == owned::FieldState::absent
              && empty.title_helper_candidate.bytes.length == 0u,
          "absent_title_has_no_bytes");

    reader.put_sso(reader.title, nullptr, 0u, false, 0u);
    check(owned::capture_string(reader, reader.title,
                               owned::SourceKind::title_helper_candidate,
                               empty), "empty_inline_title_passed");
    check(empty.title_helper_candidate.state == owned::FieldState::observed
              && empty.title_helper_candidate.bytes.length == 0u,
          "empty_inline_is_observed");
}

void test_length_boundaries() {
    std::printf("TEST length_boundaries\n");
    static MemoryReader reader;
    reader.reset();
    std::array<unsigned char, owned::kMaxKeyBytes> key{};
    std::array<unsigned char, owned::kMaxTextBytes> auxiliary{};
    key.fill('K');
    auxiliary.fill('A');
    reader.put_definition(key.data(), key.size(), true,
                          reader.base + 0x16000u);
    reader.put_message(reader.definition, auxiliary.data(), auxiliary.size(),
                       true, reader.base + 0x18000u);

    owned::Snapshot output{};
    check(owned::capture(reader, reader.message, output),
          "maximum_lengths_passed");
    check(output.definition_key.bytes.length == owned::kMaxKeyBytes
              && output.auxiliary_text.bytes.length == owned::kMaxTextBytes,
          "maximum_lengths_preserved");
    check(output.auxiliary_text.bytes.offset
              + output.auxiliary_text.bytes.length <= owned::kMaxArenaBytes,
          "arena_bound_preserved");

    reader.reset();
    reader.put_definition(key.data(), key.size(), true,
                          reader.base + 0x16000u);
    reader.put_message(reader.definition, auxiliary.data(), auxiliary.size(),
                       true, reader.base + 0x18000u);
    // The definition key limit is 256, so a declared 257-byte key is rejected
    // before any value is committed.
    reader.put_u64(reader.definition + owned::kDefinitionKeyOffset
                       + owned::kStringLengthOffset,
                   owned::kMaxKeyBytes + 1u);
    owned::Snapshot rejected = sentinel();
    check(!owned::capture(reader, reader.message, rejected),
          "key_overflow_rejected");
    check(is_clear(rejected), "key_overflow_clears_output");
}

void test_double_pass_reader_failure_and_alias() {
    std::printf("TEST double_pass_reader_failure_and_alias\n");
    static MemoryReader reader;
    reader.reset();
    const unsigned char key[] = "LANDBATTLEOVER";
    const unsigned char auxiliary[] = "aux";
    reader.put_definition(key, sizeof(key) - 1u);
    reader.put_message(reader.definition, auxiliary, sizeof(auxiliary) - 1u);

    reader.mutate_second_header = true;
    owned::Snapshot output = sentinel();
    check(!owned::capture(reader, reader.message, output),
          "second_pass_mutation_rejected");
    check(is_clear(output), "second_pass_failure_clears_output");

    reader.reset();
    reader.put_definition(key, sizeof(key) - 1u);
    reader.put_message(reader.definition, auxiliary, sizeof(auxiliary) - 1u);
    reader.fail = true;
    output = sentinel();
    check(!owned::capture(reader, reader.message, output),
          "reader_failure_rejected");
    check(is_clear(output), "reader_failure_clears_output");

    reader.reset();
    output = sentinel();
    const owned::Address alias =
        reinterpret_cast<owned::Address>(&output);
    const std::size_t reads_before_alias = reader.read_calls;
    check(!owned::capture_string(reader, alias,
                                owned::SourceKind::title_helper_candidate,
                                output), "output_alias_rejected");
    check(reader.read_calls == reads_before_alias,
          "alias_rejected_before_reader");
    check(is_clear(output), "alias_failure_clears_output");

    output = sentinel();
    check(!owned::capture_string(reader, UINT64_C(0xfff0),
                                owned::SourceKind::native_line1, output),
          "noncanonical_source_rejected");
    check(is_clear(output), "noncanonical_failure_clears_output");
}

void test_merge_repack_unknown_and_alias() {
    std::printf("TEST merge_repack_unknown_and_alias\n");
    static MemoryReader reader;
    reader.reset();
    const unsigned char key[] = "LANDBATTLEOVER";
    const unsigned char auxiliary[] = "auxiliary-text";
    const unsigned char title_text[] = "BATTLE_OF_PARIS";
    const unsigned char line_text[] = "Line1 heap value";
    reader.put_definition(key, sizeof(key) - 1u);
    reader.put_message(reader.definition, auxiliary, sizeof(auxiliary) - 1u);
    reader.put_sso(reader.title, title_text, sizeof(title_text) - 1u,
                   false, 0u);
    reader.put_sso(reader.line1, line_text, sizeof(line_text) - 1u,
                   true, reader.base + 0x13000u);

    owned::Snapshot metadata{};
    owned::Snapshot title{};
    owned::Snapshot line{};
    check(owned::capture(reader, reader.message, metadata),
          "merge_metadata_source_captured");
    check(owned::capture_string(reader, reader.title,
                                owned::SourceKind::title_helper_candidate,
                                title), "merge_title_source_captured");
    check(owned::capture_string(reader, reader.line1,
                                owned::SourceKind::native_line1, line),
          "merge_line_source_captured");

    owned::Snapshot combined{};
    check(owned::merge(metadata, title, combined),
          "merge_metadata_and_title_passed");
    check(owned::valid_snapshot(combined), "merged_snapshot_valid");
    check(combined.definition_key.bytes.offset == 0u
              && combined.auxiliary_text.bytes.offset
                   == combined.definition_key.bytes.length
              && combined.title_helper_candidate.bytes.offset
                   == combined.auxiliary_text.bytes.offset
                        + combined.auxiliary_text.bytes.length,
          "merged_fields_repacked_in_order");
    check(range_equals(combined, combined.definition_key.bytes,
                       "LANDBATTLEOVER")
              && range_equals(combined, combined.auxiliary_text.bytes,
                              "auxiliary-text")
              && range_equals(combined,
                              combined.title_helper_candidate.bytes,
                              "BATTLE_OF_PARIS"),
          "merged_values_owned");
    check(combined.native_line1.state == owned::FieldState::unknown,
          "unavailable_line_stays_unknown");

    check(owned::merge(combined, line, combined),
          "merge_output_alias_passed");
    check(combined.native_line1.state == owned::FieldState::observed
              && combined.native_line1.bytes.offset
                   == combined.title_helper_candidate.bytes.offset
                        + combined.title_helper_candidate.bytes.length
              && range_equals(combined, combined.native_line1.bytes,
                              "Line1 heap value"),
          "aliased_merge_repacked_line");

    owned::Snapshot unknown{};
    owned::clear(unknown);
    owned::Snapshot unchanged{};
    check(owned::merge(combined, unknown, unchanged),
          "unknown_incoming_does_not_erase_known");
    check(std::memcmp(&unchanged, &combined, sizeof(combined)) == 0,
          "unknown_merge_preserves_snapshot");

    owned::Snapshot duplicate{};
    check(owned::merge(title, title, duplicate),
          "matching_duplicate_allowed");
    check(duplicate.title_helper_candidate.state == owned::FieldState::observed
              && owned::valid_snapshot(duplicate),
          "matching_duplicate_is_valid");
}

void test_merge_conflicts_and_validation() {
    std::printf("TEST merge_conflicts_and_validation\n");
    static MemoryReader reader;
    reader.reset();
    const unsigned char key[] = "LANDBATTLEOVER";
    const unsigned char auxiliary[] = "auxiliary-text";
    const unsigned char title_text[] = "BATTLE_OF_PARIS";
    reader.put_definition(key, sizeof(key) - 1u);
    reader.put_message(reader.definition, auxiliary, sizeof(auxiliary) - 1u);
    reader.put_sso(reader.title, title_text, sizeof(title_text) - 1u,
                   false, 0u);

    owned::Snapshot metadata{};
    owned::Snapshot title{};
    check(owned::capture(reader, reader.message, metadata),
          "conflict_metadata_source_captured");
    check(owned::capture_string(reader, reader.title,
                                owned::SourceKind::title_helper_candidate,
                                title), "conflict_title_source_captured");

    owned::Snapshot changed = title;
    changed.arena[changed.title_helper_candidate.bytes.offset] ^= 0x01u;
    owned::Snapshot output = sentinel();
    check(!owned::merge(title, changed, output),
          "different_observed_text_rejected");
    check(is_clear(output), "text_conflict_clears_output");

    changed = metadata;
    ++changed.native_date;
    output = sentinel();
    check(!owned::merge(metadata, changed, output),
          "different_observed_date_rejected");
    check(is_clear(output), "date_conflict_clears_output");

    changed = metadata;
    changed.raw_flag_8c ^= 0x01u;
    output = sentinel();
    check(!owned::merge(metadata, changed, output),
          "different_observed_flags_rejected");
    check(is_clear(output), "flags_conflict_clears_output");

    owned::Snapshot absent{};
    owned::clear(absent);
    absent.definition_key.state = owned::FieldState::absent;
    output = sentinel();
    check(!owned::merge(metadata, absent, output),
          "observed_absent_conflict_rejected");
    check(is_clear(output), "state_conflict_clears_output");

    changed = title;
    changed.title_helper_candidate.source_kind =
        owned::SourceKind::message_metadata;
    output = sentinel();
    check(!owned::merge(title, changed, output),
          "invalid_source_kind_rejected");
    check(is_clear(output), "invalid_source_clears_output");

    changed = title;
    changed.title_helper_candidate.bytes.offset =
        static_cast<std::uint32_t>(owned::kMaxArenaBytes);
    changed.title_helper_candidate.bytes.length = 1u;
    output = sentinel();
    check(!owned::merge(title, changed, output),
          "out_of_range_field_rejected");
    check(is_clear(output), "out_of_range_clears_output");

    changed = metadata;
    changed.definition_key.bytes.length =
        static_cast<std::uint32_t>(owned::kMaxKeyBytes + 1u);
    check(!owned::valid_snapshot(changed), "key_limit_validated_on_merge_input");
}

}  // namespace

int main() {
    std::printf("TEST information-battle-owned-native-text\n");
    test_message_metadata_and_raw_fields();
    test_source_kinds_and_empty_values();
    test_length_boundaries();
    test_double_pass_reader_failure_and_alias();
    test_merge_repack_unknown_and_alias();
    test_merge_conflicts_and_validation();
    std::printf("SUMMARY checks_failed=%d status=%s\n", failures,
                failures == 0 ? "PASS" : "FAIL");
    std::printf("RESULT %s\n", failures == 0 ? "PASS" : "FAIL");
    return failures == 0 ? 0 : 1;
}
