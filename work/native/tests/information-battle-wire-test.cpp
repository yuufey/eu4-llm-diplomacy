#include "../information-battle-wire.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <limits>
#include <string_view>
#include <utility>

namespace {

using information::battle::Identity;
using information::battle::Record;
using information::battle::WireError;
using information::battle::WireResult;
using information::battle::encode_jsonl;
using information::battle::max_required_capacity;
using information::battle::required_capacity;

constexpr char kHex[] = "0123456789abcdef";
constexpr Identity kIdentity{1, 2};

void require(bool condition, const char* message) {
    if (!condition) {
        std::cerr << "FAIL: " << message << '\n';
        std::abort();
    }
}

Record one_byte_record() {
    Record record{};
    record.identity = kIdentity;
    record.attempt_sequence = 1;
    record.size = 1;
    record.payload[0] = 0xab;
    return record;
}

bool all_bytes_equal(const char* bytes, std::size_t count,
                     char expected) {
    for (std::size_t index = 0; index < count; ++index) {
        if (bytes[index] != expected) {
            return false;
        }
    }
    return true;
}

bool same_record(const Record& left, const Record& right) {
    if (left.identity != right.identity
        || left.attempt_sequence != right.attempt_sequence
        || left.size != right.size) {
        return false;
    }
    for (std::size_t index = 0; index < left.payload.size(); ++index) {
        if (left.payload[index] != right.payload[index]) {
            return false;
        }
    }
    return true;
}

void require_unchanged(const std::array<char, max_required_capacity()>& buffer,
                       char expected, const char* message) {
    require(all_bytes_equal(buffer.data(), buffer.size(), expected), message);
}

void test_one_byte_and_exact_buffer() {
    const Record record = one_byte_record();
    constexpr std::string_view expected =
        "{\"event\":\"information_owned_battle_record\",\"wire_version\":1,\"installation\":\"0000000000000001\",\"world_generation\":\"0000000000000002\",\"attempt_sequence\":\"1\",\"payload_encoding\":\"hex\",\"payload_bytes\":1,\"payload_hex\":\"ab\"}\n";

    const std::size_t capacity = required_capacity(record);
    require(capacity == expected.size() + 1,
            "required capacity includes exactly one trailing NUL");
    require(capacity <= max_required_capacity(),
            "small record fits the fixed maximum budget");

    std::array<char, max_required_capacity()> buffer{};
    buffer.fill(static_cast<char>(0xa5));
    const WireResult short_result = encode_jsonl(record, buffer.data(),
                                                  capacity - 1);
    require(short_result.error == WireError::insufficient_capacity,
            "one-byte record rejects a buffer short by one");
    require_unchanged(buffer, static_cast<char>(0xa5),
                      "short buffer remains untouched");

    buffer.fill(static_cast<char>(0xa5));
    const WireResult result = encode_jsonl(record, buffer.data(), capacity);
    require(result.succeeded() && result.written_bytes == expected.size(),
            "one-byte record encodes with exact byte count");
    require(std::string_view(buffer.data(), result.written_bytes) == expected,
            "one-byte JSONL wire output is exact and deterministic");
    require(buffer[result.written_bytes] == '\0',
            "successful output is NUL terminated");
}

void test_invalid_records_and_no_partial_output() {
    Record record = one_byte_record();
    std::array<char, max_required_capacity()> buffer{};
    buffer.fill(static_cast<char>(0x5a));

    record.identity.installation = 0;
    require(required_capacity(record) == 0,
            "invalid installation has no required capacity");
    require(encode_jsonl(record, buffer.data(), buffer.size()).error
                == WireError::invalid_identity,
            "zero installation is rejected");
    require_unchanged(buffer, static_cast<char>(0x5a),
                      "invalid identity does not write partial JSON");

    record = one_byte_record();
    record.identity.generation = 0;
    require(encode_jsonl(record, buffer.data(), buffer.size()).error
                == WireError::invalid_identity,
            "zero generation is rejected");

    record = one_byte_record();
    record.attempt_sequence = 0;
    require(encode_jsonl(record, buffer.data(), buffer.size()).error
                == WireError::invalid_sequence,
            "zero attempt sequence is rejected");

    record = one_byte_record();
    record.size = 0;
    require(encode_jsonl(record, buffer.data(), buffer.size()).error
                == WireError::empty_payload,
            "empty payload is rejected");

    record = one_byte_record();
    record.size = static_cast<std::uint32_t>(
        information::battle::OwnedByteQueue::max_payload_bytes + 1);
    require(encode_jsonl(record, buffer.data(), buffer.size()).error
                == WireError::oversize_payload,
            "oversize payload is rejected");

    record = one_byte_record();
    require(encode_jsonl(record, nullptr, buffer.size()).error
                == WireError::null_output,
            "null output is rejected");
}

void test_input_output_overlap_guard() {
    Record record = one_byte_record();
    Record before = record;
    const auto assert_overlap = [&](char* output, const char* message) {
        const WireResult result = encode_jsonl(record, output,
                                               max_required_capacity());
        require(result.error == WireError::overlapping_input, message);
        require(same_record(record, before),
                "overlap rejection leaves the complete Record unchanged");
    };

    assert_overlap(reinterpret_cast<char*>(&record),
                   "output at Record start is rejected");
    assert_overlap(reinterpret_cast<char*>(record.payload.data()),
                   "output at payload start is rejected");
    assert_overlap(reinterpret_cast<char*>(record.payload.data()) + 1,
                   "partially overlapping payload output is rejected");

    std::array<char, max_required_capacity()> independent{};
    const WireResult result = encode_jsonl(record, independent.data(),
                                           independent.size());
    require(result.succeeded(), "non-overlapping output remains valid");
    require(same_record(record, before),
            "non-overlapping encoding does not alter the input Record");
}

void test_max_payload_and_uint64_values() {
    Record record{};
    record.identity = {0x0123456789abcdefULL,
                       std::numeric_limits<std::uint64_t>::max()};
    record.attempt_sequence = std::numeric_limits<std::uint64_t>::max();
    record.size = static_cast<std::uint32_t>(
        information::battle::OwnedByteQueue::max_payload_bytes);
    for (std::size_t index = 0; index < record.size; ++index) {
        record.payload[index] = static_cast<std::uint8_t>(index & 0xffU);
    }

    std::array<char, max_required_capacity()> first{};
    std::array<char, max_required_capacity()> second{};
    const std::size_t capacity = required_capacity(record);
    require(capacity == max_required_capacity(),
            "maximum record uses the published fixed capacity");
    const WireResult first_result = encode_jsonl(record, first.data(),
                                                 first.size());
    const WireResult second_result = encode_jsonl(record, second.data(),
                                                  second.size());
    require(first_result.succeeded() && second_result.succeeded(),
            "maximum record encodes successfully");
    require(first_result.written_bytes == second_result.written_bytes,
            "same record has deterministic written length");
    require(std::memcmp(first.data(), second.data(),
                        first_result.written_bytes + 1) == 0,
            "same identity and sequence produce identical wire bytes");

    const std::string_view output(first.data(), first_result.written_bytes);
    require(output.find("\"installation\":\"0123456789abcdef\"")
                != std::string_view::npos,
            "installation is fixed-width lowercase hexadecimal");
    require(output.find("\"world_generation\":\"ffffffffffffffff\"")
                != std::string_view::npos,
            "UINT64_MAX generation is fixed-width lowercase hexadecimal");
    require(output.find("\"attempt_sequence\":\"18446744073709551615\"")
                != std::string_view::npos,
            "UINT64_MAX sequence is decimal without a leading zero");
    require(output.find("\"payload_bytes\":4096") != std::string_view::npos,
            "maximum payload byte count is encoded as decimal");

    const std::string_view marker = "\"payload_hex\":\"";
    const std::size_t payload_start = output.find(marker);
    require(payload_start != std::string_view::npos,
            "payload hex marker is present");
    const std::size_t hex_start = payload_start + marker.size();
    for (std::size_t index = 0; index < record.size; ++index) {
        const std::uint8_t value = record.payload[index];
        require(first[hex_start + index * 2] == kHex[(value >> 4) & 0x0fU]
                    && first[hex_start + index * 2 + 1]
                           == kHex[value & 0x0fU],
                "all payload byte values are lowerhex encoded");
    }
    require(first[first_result.written_bytes - 1] == '\n'
                && first[first_result.written_bytes] == '\0',
            "maximum output has newline then NUL");
}

struct VectorCase final {
    const char* name;
    Record record;
};

void write_hex(std::ostream& output, const char* bytes, std::size_t count) {
    for (std::size_t index = 0; index < count; ++index) {
        const unsigned char value = static_cast<unsigned char>(bytes[index]);
        output << kHex[(value >> 4) & 0x0fU] << kHex[value & 0x0fU];
    }
}

void write_payload_hex(std::ostream& output, const Record& record) {
    for (std::size_t index = 0; index < record.size; ++index) {
        const std::uint8_t value = record.payload[index];
        output << kHex[(value >> 4) & 0x0fU] << kHex[value & 0x0fU];
    }
}

void write_fixed_hex(std::ostream& output, std::uint64_t value) {
    char buffer[16]{};
    for (unsigned shift = 60; ; shift -= 4) {
        buffer[15 - (shift / 4)] = kHex[(value >> shift) & 0x0fU];
        if (shift == 0) {
            break;
        }
    }
    output.write(buffer, sizeof(buffer));
}

void write_vectors(const char* path) {
    Record one = one_byte_record();
    Record maximum{};
    maximum.identity = {0x0123456789abcdefULL,
                        std::numeric_limits<std::uint64_t>::max()};
    maximum.attempt_sequence = std::numeric_limits<std::uint64_t>::max();
    maximum.size = static_cast<std::uint32_t>(
        information::battle::OwnedByteQueue::max_payload_bytes);
    for (std::size_t index = 0; index < maximum.size; ++index) {
        maximum.payload[index] = static_cast<std::uint8_t>(index & 0xffU);
    }

    const VectorCase cases[] = {{"one_byte", one},
                                {"max_payload_max_ids", maximum}};
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    require(output.good(), "vector output file opens");
    for (const VectorCase& test_case : cases) {
        std::array<char, max_required_capacity()> wire{};
        const WireResult result = encode_jsonl(test_case.record, wire.data(),
                                               wire.size());
        require(result.succeeded(), "compiled encoder emits each vector");
        output << "{\"case\":\"" << test_case.name
               << "\",\"installation\":\"";
        write_fixed_hex(output, test_case.record.identity.installation);
        output << "\",\"world_generation\":\"";
        write_fixed_hex(output, test_case.record.identity.generation);
        output << "\",\"attempt_sequence\":\"";
        // The vector metadata keeps the sequence as a string; its exact
        // decimal spelling is also present in wire_hex for independent checks.
        char decimal[20]{};
        std::size_t count = 0;
        std::uint64_t value = test_case.record.attempt_sequence;
        do {
            decimal[count++] = static_cast<char>('0' + value % 10);
            value /= 10;
        } while (value != 0);
        while (count != 0) {
            output << decimal[--count];
        }
        output << "\",\"payload_bytes\":" << test_case.record.size
               << ",\"payload_hex\":\"";
        write_payload_hex(output, test_case.record);
        output << "\",\"written_bytes\":" << result.written_bytes
               << ",\"wire_hex\":\"";
        write_hex(output, wire.data(), result.written_bytes);
        output << "\"}\n";
    }
    require(output.good(), "vector output is complete");
}

} // namespace

int main(int argc, char** argv) {
    static_assert(noexcept(information::battle::encode_jsonl(
                      std::declval<const Record&>(), nullptr, 0)),
                  "encoder must be noexcept");
    static_assert(noexcept(information::battle::required_capacity(
                      std::declval<const Record&>())),
                  "capacity calculation must be noexcept");

    test_one_byte_and_exact_buffer();
    test_invalid_records_and_no_partial_output();
    test_input_output_overlap_guard();
    test_max_payload_and_uint64_values();

    if (argc == 3 && std::strcmp(argv[1], "--vectors") == 0) {
        write_vectors(argv[2]);
    } else {
        require(argc == 1, "usage: test [--vectors path]");
    }
    std::cout << "information-battle-wire-test: passed\n";
    return 0;
}
