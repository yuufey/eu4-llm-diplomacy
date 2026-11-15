#include "../information-battle-owned-template.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <limits>
#include <string>

namespace owned = information::battle::owned_template;

struct MemoryReader {
    static constexpr std::size_t kBytes = 2u * 1024u * 1024u;

    owned::Address base = UINT64_C(0x20000);
    owned::Address message = base + 0x1000u;
    owned::Address container = base + 0x9000u;
    std::array<unsigned char, kBytes> bytes{};
    std::size_t read_calls = 0;
    std::size_t header_reads = 0;
    std::size_t container_header_reads = 0;
    bool fail = false;
    bool mutate_second_header = false;
    bool mutate_second_container_header = false;
    bool container_bad_header_read = false;

    bool read(owned::Address address, unsigned char* destination,
              std::size_t size) noexcept {
        ++read_calls;
        if (fail || destination == nullptr || size == 0u
                || address < base || address - base > bytes.size()
                || size > bytes.size() - (address - base)) {
            return false;
        }
        if (address == container
                && size != owned::kFormatterContainerHeaderBytes) {
            container_bad_header_read = true;
            return false;
        }
        if (mutate_second_header && address == message
                && size == owned::kMessageHeaderBytes
                && header_reads == 1u) {
            const std::int32_t changed = 0x13572468;
            std::memcpy(bytes.data() + (message - base)
                            + owned::kNativeDateOffset,
                        &changed, sizeof(changed));
        }
        if (mutate_second_container_header && address == container
                && size == owned::kFormatterContainerHeaderBytes
                && container_header_reads == 1u) {
            const std::uint32_t changed = UINT32_C(0x24681357);
            std::memcpy(bytes.data() + (container - base)
                            + owned::kFormatterContainerRawWord10Offset,
                        &changed, sizeof(changed));
        }
        std::memcpy(destination, bytes.data() + (address - base), size);
        if (address == message && size == owned::kMessageHeaderBytes) {
            ++header_reads;
        }
        if (address == container
                && size == owned::kFormatterContainerHeaderBytes) {
            ++container_header_reads;
        }
        return true;
    }

    void reset() noexcept {
        bytes.fill(0);
        read_calls = 0;
        header_reads = 0;
        container_header_reads = 0;
        fail = false;
        mutate_second_header = false;
        mutate_second_container_header = false;
        container_bad_header_read = false;
    }

    void put_u64(owned::Address address, std::uint64_t value) noexcept {
        std::memcpy(bytes.data() + (address - base), &value, sizeof(value));
    }

    void put_u32(owned::Address address, std::uint32_t value) noexcept {
        std::memcpy(bytes.data() + (address - base), &value, sizeof(value));
    }

    void put_i32(owned::Address address, std::int32_t value) noexcept {
        std::memcpy(bytes.data() + (address - base), &value, sizeof(value));
    }

    void put_bytes(owned::Address address, const unsigned char* data,
                   std::size_t size) noexcept {
        std::memcpy(bytes.data() + (address - base), data, size);
    }

    void put_sso(owned::Address object, const unsigned char* data,
                 std::size_t length, bool heap,
                 owned::Address heap_address) noexcept {
        std::memset(bytes.data() + (object - base), 0, 0x20u);
        if (heap) {
            put_u64(object, heap_address);
            put_u64(object + 0x10u, length);
            put_u64(object + 0x18u, length < 16u ? 16u : length);
            put_bytes(heap_address, data, length);
            bytes[(heap_address - base) + length] = 0;
        } else {
            std::memcpy(bytes.data() + (object - base), data, length);
            put_u64(object + 0x10u, length);
            put_u64(object + 0x18u, length);
            bytes[(object - base) + length] = 0;
        }
    }

    void put_message(owned::Address head, owned::Address tail,
                     std::uint32_t raw_word20,
                     unsigned char raw_flag24,
                     const unsigned char* auxiliary, std::size_t auxiliary_len,
                     bool auxiliary_heap = false,
                     owned::Address auxiliary_heap_address = 0) noexcept {
        std::memset(bytes.data() + (message - base), 0,
                    owned::kMessageHeaderBytes);
        put_u64(message + owned::kContainerHeadOffset, head);
        put_u64(message + owned::kContainerTailOffset, tail);
        put_u32(message + owned::kContainerRawWord20Offset, raw_word20);
        bytes[(message - base) + owned::kContainerRawFlag24Offset] = raw_flag24;
        put_sso(message + owned::kAuxiliaryTextOffset, auxiliary,
                auxiliary_len, auxiliary_heap, auxiliary_heap_address);
        put_i32(message + owned::kNativeDateOffset, 0x11223344);
        bytes[(message - base) + owned::kRawFlag8COffset] = 0xa1u;
        bytes[(message - base) + owned::kRawFlag8DOffset] = 0x5eu;
    }

    void put_container(owned::Address head, owned::Address tail,
                       std::uint32_t raw_word10,
                       unsigned char raw_flag14) noexcept {
        std::memset(bytes.data() + (container - base), 0,
                    owned::kFormatterContainerHeaderBytes);
        put_u64(container + owned::kFormatterContainerHeadOffset, head);
        put_u64(container + owned::kFormatterContainerTailOffset, tail);
        put_u32(container + owned::kFormatterContainerRawWord10Offset,
                raw_word10);
        bytes[(container - base) + owned::kFormatterContainerRawFlag14Offset]
            = raw_flag14;
    }

    void put_node(owned::Address node, owned::Address next,
                  const unsigned char* key, std::size_t key_len,
                  bool key_heap, owned::Address key_heap_address,
                  const unsigned char* value, std::size_t value_len,
                  bool value_heap, owned::Address value_heap_address) noexcept {
        std::memset(bytes.data() + (node - base), 0, owned::kNodeBytes);
        put_sso(node + owned::kKeyOffset, key, key_len, key_heap,
                key_heap_address);
        put_sso(node + owned::kValueOffset, value, value_len, value_heap,
                value_heap_address);
        put_u64(node + 0x40u, UINT64_C(0x1111000000000000) + node);
        put_u64(node + 0x48u, UINT64_C(0x2222000000000000) + node);
        put_u64(node + 0x50u, UINT64_C(0x3333000000000000) + node);
        put_u64(node + owned::kNodeNextOffset, next);
    }
};

struct BadReader {
    bool read(owned::Address, unsigned char*, std::size_t) { return true; }
};

static_assert(owned::reader_contract<MemoryReader>::value,
              "fixture reader must satisfy the noexcept contract");
static_assert(!owned::reader_contract<BadReader>::value,
              "a throwing-capable reader must be rejected");
static_assert(std::is_trivially_copyable<owned::Snapshot>::value,
              "snapshot must remain a plain value object");

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
    output.pair_count = 7u;
    output.auxiliary_text = owned::TextRange{123u, 9u};
    output.native_date = -77;
    output.raw_flag_8c = 0xf1u;
    output.raw_flag_8d = 0xf2u;
    output.raw_header_word_20 = UINT32_C(0xfeedbeef);
    output.raw_header_flag_24 = 0x7au;
    output.pairs[0].key = owned::TextRange{2u, 3u};
    output.pairs[0].value = owned::TextRange{8u, 5u};
    output.arena[2] = 's';
    output.arena[3] = 'e';
    output.arena[4] = 'n';
    return output;
}

bool same_snapshot(const owned::Snapshot& left,
                   const owned::Snapshot& right) {
    return std::memcmp(&left, &right, sizeof(left)) == 0;
}

bool range_equals(const owned::Snapshot& snapshot, owned::TextRange range,
                  const char* text) {
    const std::size_t length = std::strlen(text);
    return range.length == length
        && std::memcmp(snapshot.arena.data() + range.offset, text, length) == 0;
}

void build_simple(MemoryReader& reader) {
    reader.reset();
    const unsigned char aux[] = {'a', 'u', 'x', '-', 'h', 'e', 'a', 'p'};
    const unsigned char key1[] = {'d', 'u', 'p'};
    const unsigned char value1[] = {'o', 'n', 'e'};
    const unsigned char value2[] = {'t', 'w', 'o', '-', 'v', 'a', 'l', 'u', 'e'};
    const unsigned char key3[] = {'l', 'a', 's', 't'};
    const unsigned char value3[] = {'3'};
    const owned::Address node1 = reader.base + 0x2000u;
    const owned::Address node2 = reader.base + 0x2100u;
    const owned::Address node3 = reader.base + 0x2200u;
    reader.put_node(node1, node2, key1, sizeof(key1), false, 0,
                    value1, sizeof(value1), false, 0);
    reader.put_node(node2, node3, key1, sizeof(key1), false, 0,
                    value2, sizeof(value2), true, reader.base + 0x12000u);
    reader.put_node(node3, 0, key3, sizeof(key3), false, 0,
                    value3, sizeof(value3), false, 0);
    reader.put_message(node1, node3, UINT32_C(0xabcdef01), 0x5au,
                       aux, sizeof(aux), true, reader.base + 0x11000u);
}

void test_empty_and_raw_fields() {
    std::printf("TEST empty_and_raw_fields\n");
    static MemoryReader reader;
    reader.reset();
    const unsigned char auxiliary[] = {'e', 'm', 'p', 't', 'y'};
    reader.put_message(0, 0, UINT32_C(0x10203040), 0x91u,
                       auxiliary, sizeof(auxiliary));
    owned::Snapshot output{};
    check(owned::capture(reader, reader.message, output), "empty_capture");
    check(output.pair_count == 0u, "empty_pair_count");
    check(range_equals(output, output.auxiliary_text, "empty"),
          "auxiliary_text_copied");
    check(output.native_date == 0x11223344, "native_date_copied");
    check(output.raw_flag_8c == 0xa1u && output.raw_flag_8d == 0x5eu,
          "raw_flags_copied");
    check(output.raw_header_word_20 == UINT32_C(0x10203040),
          "header_word_preserved_without_count_claim");
    check(output.raw_header_flag_24 == 0x91u, "header_flag_preserved");
}

void test_sso_heap_duplicate_order_and_lifetime() {
    std::printf("TEST sso_heap_duplicate_order_and_lifetime\n");
    static MemoryReader reader;
    build_simple(reader);
    owned::Snapshot output{};
    check(owned::capture(reader, reader.message, output), "mixed_capture");
    check(output.pair_count == 3u, "three_ordered_pairs");
    check(range_equals(output, output.pairs[0].key, "dup"), "first_key");
    check(range_equals(output, output.pairs[0].value, "one"), "first_value");
    check(range_equals(output, output.pairs[1].key, "dup"), "duplicate_key_kept");
    check(range_equals(output, output.pairs[1].value, "two-value"),
          "heap_value_copied");
    check(range_equals(output, output.pairs[2].key, "last")
              && range_equals(output, output.pairs[2].value, "3"),
          "third_pair_order");
    const owned::Snapshot preserved = output;
    reader.bytes[(reader.base + 0x12000u - reader.base)] = 'X';
    reader.bytes[(reader.base + 0x11000u - reader.base)] = 'Y';
    check(same_snapshot(output, preserved), "source_mutation_not_borrowed");
}

void test_empty_heap_and_boundaries() {
    std::printf("TEST empty_heap_and_boundaries\n");
    static MemoryReader reader;
    reader.reset();
    const owned::Address heap = reader.base + 0x16000u;
    const unsigned char empty[] = {};
    reader.put_message(0, 0, 1u, 2u, empty, 0u, true, heap);
    owned::Snapshot empty_output{};
    check(owned::capture(reader, reader.message, empty_output),
          "empty_heap_string_reads_terminator");
    check(empty_output.auxiliary_text.length == 0u,
          "empty_heap_length_zero");

    std::array<unsigned char, owned::kMaxKeyBytes> key{};
    std::array<unsigned char, owned::kMaxValueBytes> value{};
    key.fill('K');
    value.fill('V');
    const owned::Address node = reader.base + 0x3000u;
    reader.put_node(node, 0, key.data(), key.size(), true,
                    reader.base + 0x17000u, value.data(), value.size(), true,
                    reader.base + 0x18000u);
    reader.put_message(node, node, 3u, 4u, empty, 0u, false, 0);
    owned::Snapshot boundary{};
    check(owned::capture(reader, reader.message, boundary),
          "key128_value8192_capture");
    check(boundary.pair_count == 1u
              && boundary.pairs[0].key.length == owned::kMaxKeyBytes
              && boundary.pairs[0].value.length == owned::kMaxValueBytes,
          "boundary_lengths_preserved");
    check(boundary.pairs[0].value.offset
              + boundary.pairs[0].value.length <= owned::kMaxArenaBytes,
          "boundary_arena_bounded");
}

void test_cycle_and_capacity_rejection() {
    std::printf("TEST cycle_and_capacity_rejection\n");
    static MemoryReader reader;
    reader.reset();
    const unsigned char key[] = {'k', 'x', 'y'};
    const unsigned char value[] = {'v'};
    const owned::Address node1 = reader.base + 0x4000u;
    const owned::Address node2 = reader.base + 0x4100u;
    reader.put_node(node1, node2, key, sizeof(key), false, 0,
                    value, sizeof(value), false, 0);
    reader.put_node(node2, node1, key, sizeof(key), false, 0,
                    value, sizeof(value), false, 0);
    reader.put_message(node1, node2, 5u, 6u, key, sizeof(key));
    owned::Snapshot output = sentinel();
    const owned::Snapshot before = output;
    check(!owned::capture(reader, reader.message, output), "cycle_rejected");
    check(same_snapshot(output, before), "cycle_output_unchanged");

    build_simple(reader);
    reader.put_u64(reader.message + owned::kContainerTailOffset,
                   reader.base + 0x2100u);
    output = sentinel();
    const owned::Snapshot before_tail = output;
    check(!owned::capture(reader, reader.message, output),
          "header_tail_mismatch_rejected");
    check(same_snapshot(output, before_tail),
          "header_tail_mismatch_output_unchanged");

    reader.reset();
    std::array<unsigned char, owned::kMaxValueBytes> large{};
    large.fill('L');
    owned::Address first = reader.base + 0x5000u;
    owned::Address last = 0;
    for (std::size_t index = 0; index < 9u; ++index) {
        const owned::Address node = reader.base + 0x5000u
            + static_cast<owned::Address>(index) * 0x100u;
        const owned::Address next = index == 8u ? 0
            : node + 0x100u;
        reader.put_node(node, next, key, sizeof(key), false, 0,
                        large.data(), large.size(), true,
                        reader.base + 0x20000u
                            + static_cast<owned::Address>(index) * 0x3000u);
        last = node;
    }
    reader.put_message(first, last, 7u, 8u, key, sizeof(key));
    output = sentinel();
    const owned::Snapshot before_overflow = output;
    check(!owned::capture(reader, reader.message, output),
          "arena_overflow_rejected_without_truncation");
    check(same_snapshot(output, before_overflow),
          "arena_overflow_output_unchanged");
}

void test_invalid_string_and_node_limit() {
    std::printf("TEST invalid_string_and_node_limit\n");
    static MemoryReader reader;
    reader.reset();
    const unsigned char key[] = {'k', 'x', 'y'};
    const unsigned char value[] = {'v'};
    const owned::Address node = reader.base + 0x6000u;
    reader.put_node(node, 0, key, sizeof(key), false, 0,
                    value, sizeof(value), false, 0);
    reader.put_message(node, node, 9u, 10u, key, sizeof(key));
    // A NUL inside the declared inline key is not a valid raw string.
    reader.bytes[(node - reader.base) + 1u] = 0;
    reader.bytes[(node - reader.base) + 2u] = 'x';
    owned::Snapshot output = sentinel();
    const owned::Snapshot before = output;
    check(!owned::capture(reader, reader.message, output),
          "interior_inline_nul_rejected");
    check(same_snapshot(output, before), "bad_string_output_unchanged");

    reader.reset();
    const owned::Address first = reader.base + 0x8000u;
    for (std::size_t index = 0; index < owned::kMaxPairs + 1u; ++index) {
        const owned::Address node_address = first
            + static_cast<owned::Address>(index) * 0x100u;
        const owned::Address next = index + 1u < owned::kMaxPairs + 1u
            ? node_address + 0x100u : 0;
        reader.put_node(node_address, next, key, sizeof(key), false, 0,
                        value, sizeof(value), false, 0);
    }
    const owned::Address last = first
        + static_cast<owned::Address>(owned::kMaxPairs) * 0x100u;
    reader.put_message(first, last, 11u, 12u, key, sizeof(key));
    output = sentinel();
    const owned::Snapshot before_limit = output;
    check(!owned::capture(reader, reader.message, output),
          "node_limit_rejected");
    check(same_snapshot(output, before_limit), "node_limit_output_unchanged");
}

void test_doublepass_failure_and_reader_failure() {
    std::printf("TEST doublepass_failure_and_reader_failure\n");
    static MemoryReader reader;
    build_simple(reader);
    reader.mutate_second_header = true;
    owned::Snapshot output = sentinel();
    const owned::Snapshot before = output;
    check(!owned::capture(reader, reader.message, output),
          "doublepass_mutation_rejected");
    check(same_snapshot(output, before), "doublepass_output_unchanged");

    build_simple(reader);
    reader.fail = true;
    output = sentinel();
    const owned::Snapshot before_read_failure = output;
    check(!owned::capture(reader, reader.message, output),
          "read_failure_rejected");
    check(same_snapshot(output, before_read_failure),
          "read_failure_output_unchanged");
}

void test_formatter_container_capture() {
    std::printf("TEST formatter_container_capture\n");
    static MemoryReader reader;
    build_simple(reader);
    const owned::Address node1 = reader.base + 0x2000u;
    const owned::Address node3 = reader.base + 0x2200u;
    reader.put_container(node1, node3, UINT32_C(0x10203040), 0x91u);
    owned::Snapshot output = sentinel();
    check(owned::capture_container(reader, reader.container, output),
          "formatter_container_capture");
    check(!reader.container_bad_header_read
              && reader.container_header_reads == 2u,
          "formatter_container_reads_only_24_byte_header_twice");
    check(output.pair_count == 3u
              && range_equals(output, output.pairs[0].key, "dup")
              && range_equals(output, output.pairs[1].value, "two-value"),
          "formatter_container_ordered_pairs");
    check(output.raw_header_word_20 == UINT32_C(0x10203040)
              && output.raw_header_flag_24 == 0x91u,
          "formatter_container_raw_fields");
    check(output.native_date == 0
              && output.raw_flag_8c == 0u && output.raw_flag_8d == 0u
              && output.auxiliary_text.offset == 0u
              && output.auxiliary_text.length == 0u,
          "formatter_container_message_metadata_unavailable");

    build_simple(reader);
    reader.put_container(node1, node3, UINT32_C(0x10203040), 0x91u);
    reader.mutate_second_container_header = true;
    output = sentinel();
    const owned::Snapshot before_mutation = output;
    check(!owned::capture_container(reader, reader.container, output),
          "formatter_container_doublepass_mutation_rejected");
    check(same_snapshot(output, before_mutation),
          "formatter_container_mutation_output_unchanged");

    build_simple(reader);
    reader.put_container(node1, node3, UINT32_C(0x10203040), 0x91u);
    reader.fail = true;
    output = sentinel();
    const owned::Snapshot before_failure = output;
    check(!owned::capture_container(reader, reader.container, output),
          "formatter_container_read_failure_rejected");
    check(same_snapshot(output, before_failure),
          "formatter_container_failure_output_unchanged");
}

void test_source_output_alias_and_bad_addresses() {
    std::printf("TEST source_output_alias_and_bad_addresses\n");
    static MemoryReader reader;
    build_simple(reader);
    owned::Snapshot output = sentinel();
    const owned::Snapshot before = output;
    const owned::Address alias = reinterpret_cast<owned::Address>(&output);
    check(!owned::capture(reader, alias, output), "source_output_alias_rejected");
    check(reader.read_calls == 0u, "alias_rejected_before_reader");
    check(same_snapshot(output, before), "alias_output_unchanged");

    output = sentinel();
    const owned::Snapshot before_bad = output;
    check(!owned::capture(reader, UINT64_C(0xfff0), output),
          "noncanonical_message_rejected");
    check(same_snapshot(output, before_bad), "bad_address_output_unchanged");
}

}  // namespace

int main() {
    std::printf("TEST information-battle-owned-template\n");
    test_empty_and_raw_fields();
    test_sso_heap_duplicate_order_and_lifetime();
    test_empty_heap_and_boundaries();
    test_cycle_and_capacity_rejection();
    test_invalid_string_and_node_limit();
    test_doublepass_failure_and_reader_failure();
    test_formatter_container_capture();
    test_source_output_alias_and_bad_addresses();
    std::printf("SUMMARY checks_failed=%d status=%s\n", failures,
                failures == 0 ? "PASS" : "FAIL");
    std::printf("RESULT %s\n", failures == 0 ? "PASS" : "FAIL");
    return failures == 0 ? 0 : 1;
}
