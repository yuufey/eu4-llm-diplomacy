#include "../information-battle-native-text-wire.h"

#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <limits>
#include <string>
#include <vector>

namespace owned = information::battle::owned_native_text;
namespace wire = information::battle::native_text_wire;

namespace {

constexpr owned::Address kMemoryBase = UINT64_C(0x20000);
constexpr std::size_t kMemoryBytes = 2u * 1024u * 1024u;
constexpr owned::Address kMessage = kMemoryBase + 0x1000u;
constexpr owned::Address kDefinition = kMemoryBase + 0x3000u;
constexpr owned::Address kTitle = kMemoryBase + 0x6000u;
constexpr owned::Address kLine1 = kMemoryBase + 0x7000u;
constexpr owned::Address kTitleHeap = kMemoryBase + 0x9000u;

constexpr char kDefinitionKey[] = "LANDBATTLEOVER";
constexpr char kAuxiliary[] = "";
constexpr char kTitleText[] = "Fixture battle title";
constexpr char kLine1Text[] = "Fixture line 1";
constexpr std::uint8_t kRawFlag8c = 0xa1u;
constexpr std::uint8_t kRawFlag8d = 0x5eu;

static_assert(owned::kDefinitionKeyOffset == 0x38u,
              "fixture must use the proven definition +38 key object");
static_assert(owned::kMessageAuxiliaryOffset == 0x60u,
              "fixture must use the proven message +60 string object");
static_assert(owned::kMessageDateOffset == 0x88u,
              "fixture must use the proven message +88 date");

struct SyntheticReader final {
    std::array<unsigned char, kMemoryBytes> bytes{};
    std::size_t read_calls = 0u;

    bool read(owned::Address address, unsigned char* destination,
              std::size_t size) noexcept {
        ++read_calls;
        if (destination == nullptr || size == 0u || address < kMemoryBase) {
            return false;
        }
        const owned::Address offset = address - kMemoryBase;
        if (offset > bytes.size() || size > bytes.size() - offset) {
            return false;
        }
        std::memcpy(destination, bytes.data() + offset, size);
        return true;
    }

    void put_u64(owned::Address address, std::uint64_t value) noexcept {
        std::memcpy(bytes.data() + (address - kMemoryBase), &value,
                    sizeof(value));
    }

    void put_i32(owned::Address address, std::int32_t value) noexcept {
        std::memcpy(bytes.data() + (address - kMemoryBase), &value,
                    sizeof(value));
    }

    void put_bytes(owned::Address address, const unsigned char* data,
                   std::size_t size) noexcept {
        if (size != 0u) {
            std::memcpy(bytes.data() + (address - kMemoryBase), data, size);
        }
    }

    void put_sso(owned::Address object, const unsigned char* data,
                 std::size_t length, bool heap,
                 owned::Address heap_address = 0u) noexcept {
        std::memset(bytes.data() + (object - kMemoryBase), 0,
                    owned::kStringObjectBytes);
        if (heap) {
            put_u64(object, heap_address);
            put_u64(object + owned::kStringLengthOffset, length);
            put_u64(object + owned::kStringCapacityOffset,
                    length < owned::kHeapThreshold
                        ? owned::kHeapThreshold : length);
            put_bytes(heap_address, data, length);
            bytes[(heap_address - kMemoryBase) + length] = 0u;
        } else {
            put_bytes(object, data, length);
            put_u64(object + owned::kStringLengthOffset, length);
            put_u64(object + owned::kStringCapacityOffset,
                    owned::kInlineCapacity);
            bytes[(object - kMemoryBase) + length] = 0u;
        }
    }

    void build(std::int32_t raw_date) noexcept {
        bytes.fill(0u);
        read_calls = 0u;
        put_sso(kDefinition + owned::kDefinitionKeyOffset,
                reinterpret_cast<const unsigned char*>(kDefinitionKey),
                sizeof(kDefinitionKey) - 1u, false);
        put_sso(kMessage + owned::kMessageAuxiliaryOffset,
                reinterpret_cast<const unsigned char*>(kAuxiliary),
                sizeof(kAuxiliary) - 1u, false);
        put_u64(kMessage + owned::kMessageDefinitionPointerOffset,
                kDefinition);
        put_i32(kMessage + owned::kMessageDateOffset, raw_date);
        bytes[(kMessage - kMemoryBase) + owned::kMessageFlag8cOffset]
            = kRawFlag8c;
        bytes[(kMessage - kMemoryBase) + owned::kMessageFlag8dOffset]
            = kRawFlag8d;
        put_sso(kTitle, reinterpret_cast<const unsigned char*>(kTitleText),
                sizeof(kTitleText) - 1u, true, kTitleHeap);
        put_sso(kLine1, reinterpret_cast<const unsigned char*>(kLine1Text),
                sizeof(kLine1Text) - 1u, false);
    }
};

static_assert(owned::reader_contract<SyntheticReader>::value,
              "synthetic reader must satisfy the owned capture contract");

int failures = 0;

void check(bool condition, const char* label) {
    std::printf("CHECK %s %s\n", label, condition ? "PASS" : "FAIL");
    if (!condition) {
        ++failures;
    }
}

bool read_file(const std::string& path, std::vector<unsigned char>& output) {
    std::ifstream stream(path, std::ios::binary | std::ios::ate);
    if (!stream) {
        return false;
    }
    const std::streamoff end = stream.tellg();
    if (end <= 0 || static_cast<std::uint64_t>(end) > wire::kMaxBaseV5Bytes) {
        return false;
    }
    output.resize(static_cast<std::size_t>(end));
    stream.seekg(0, std::ios::beg);
    return static_cast<bool>(stream.read(
        reinterpret_cast<char*>(output.data()),
        static_cast<std::streamsize>(output.size())));
}

bool write_new_file(const std::string& path,
                    const std::vector<unsigned char>& bytes) {
    std::ifstream existing(path, std::ios::binary);
    if (existing.good()) {
        return false;
    }
    std::ofstream stream(path, std::ios::binary | std::ios::trunc);
    if (!stream) {
        return false;
    }
    stream.write(reinterpret_cast<const char*>(bytes.data()),
                 static_cast<std::streamsize>(bytes.size()));
    return static_cast<bool>(stream);
}

bool parse_i32(const char* text, std::int32_t& output) {
    if (text == nullptr || *text == '\0') {
        return false;
    }
    errno = 0;
    char* end = nullptr;
    const long long value = std::strtoll(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0'
            || value < std::numeric_limits<std::int32_t>::min()
            || value > std::numeric_limits<std::int32_t>::max()) {
        return false;
    }
    output = static_cast<std::int32_t>(value);
    return true;
}

struct Arguments final {
    std::string base_v5;
    std::string output;
    std::int32_t raw_date = 0;
    bool has_base = false;
    bool has_date = false;
    bool has_output = false;
};

bool parse_arguments(int argc, char** argv, Arguments& output) {
    for (int index = 1; index < argc; ++index) {
        const std::string option(argv[index]);
        if (option == "--base-v5" || option == "--raw-date"
                || option == "--output") {
            if (index + 1 >= argc) {
                return false;
            }
            const std::string value(argv[++index]);
            if (option == "--base-v5") {
                output.base_v5 = value;
                output.has_base = true;
            } else if (option == "--raw-date") {
                if (!parse_i32(value.c_str(), output.raw_date)) {
                    return false;
                }
                output.has_date = true;
            } else {
                output.output = value;
                output.has_output = true;
            }
        } else {
            return false;
        }
    }
    return output.has_base && output.has_date && output.has_output;
}

bool range_equals(const owned::Snapshot& snapshot, owned::TextRange range,
                  const char* text) {
    const std::size_t length = std::strlen(text);
    return range.length == length
        && std::memcmp(snapshot.arena.data() + range.offset, text, length) == 0;
}

}  // namespace

int main(int argc, char** argv) {
    if (argc == 2 && std::string(argv[1]) == "--help") {
        std::printf("usage: information-battle-native-text-chain "
                    "--base-v5 PATH --raw-date INT32 --output PATH\n");
        return 0;
    }

    Arguments arguments{};
    if (!parse_arguments(argc, argv, arguments)) {
        std::fprintf(stderr, "invalid arguments; pass --help for usage\n");
        return 2;
    }

    std::vector<unsigned char> base_v5;
    check(read_file(arguments.base_v5, base_v5), "read_real_v5_payload");
    if (failures != 0) {
        std::printf("RESULT FAIL\n");
        return 1;
    }

    static SyntheticReader reader{};
    reader.build(arguments.raw_date);
    owned::Snapshot metadata{};
    owned::Snapshot title{};
    owned::Snapshot line1{};
    owned::Snapshot merged_title{};
    owned::Snapshot composed{};
    check(owned::capture_message(reader, kMessage, metadata),
          "capture_message_definition_and_auxiliary");
    check(metadata.definition_key.state == owned::FieldState::observed
              && range_equals(metadata, metadata.definition_key.bytes,
                              kDefinitionKey),
          "definition_key_is_exact");
    check(metadata.auxiliary_text.state == owned::FieldState::observed
              && metadata.auxiliary_text.bytes.length == 0u,
          "auxiliary_is_observed_empty");
    check(metadata.native_date_state == owned::FieldState::observed
              && metadata.native_date == arguments.raw_date
              && metadata.raw_flags_state == owned::FieldState::observed
              && metadata.raw_flag_8c == kRawFlag8c
              && metadata.raw_flag_8d == kRawFlag8d,
          "date_and_raw_flags_are_captured");
    check(owned::capture_string(reader, kTitle,
                                owned::SourceKind::title_helper_candidate,
                                title),
          "capture_title_helper_string");
    check(title.title_helper_candidate.state == owned::FieldState::observed
              && range_equals(title, title.title_helper_candidate.bytes,
                              kTitleText),
          "title_helper_bytes_are_owned");
    check(owned::capture_string(reader, kLine1,
                                owned::SourceKind::native_line1, line1),
          "capture_line1_string");
    check(line1.native_line1.state == owned::FieldState::observed
              && range_equals(line1, line1.native_line1.bytes, kLine1Text),
          "line1_bytes_are_owned");
    check(owned::merge(metadata, title, merged_title),
          "merge_metadata_and_title");
    check(owned::merge(merged_title, line1, composed),
          "merge_line1_into_composed_snapshot");
    check(owned::valid_snapshot(composed), "composed_snapshot_valid");
    check(composed.title_helper_candidate.state == owned::FieldState::observed
              && composed.native_line1.state == owned::FieldState::observed,
          "composed_snapshot_has_both_text_sources");
    check(reader.read_calls >= 8u, "reader_used_bounded_two_pass_captures");

    const std::size_t encoded_bytes = wire::encoded_size(
        base_v5.data(), base_v5.size(), composed);
    check(encoded_bytes != 0u, "native_encode_size_available");
    std::vector<unsigned char> output(encoded_bytes, 0xa5u);
    const wire::EncodeResult encoded = wire::encode(
        base_v5.data(), base_v5.size(), composed,
        output.data(), output.size());
    check(encoded.succeeded() && encoded.written_bytes == encoded_bytes,
          "native_encode_writes_exact_size");
    check(wire::validate(output.data(), output.size()),
          "native_v6_wire_validates");
    const std::size_t base_offset = wire::kOuterHeaderBytes;
    check(output.size() >= base_offset + base_v5.size()
              && std::memcmp(output.data() + base_offset, base_v5.data(),
                             base_v5.size()) == 0,
          "v5_bytes_are_embedded_without_change");
    check(write_new_file(arguments.output, output),
          "write_new_v6_output_once");
    check(failures == 0, "all_native_chain_checks");
    std::printf("V6_BYTES %zu\n", output.size());
    std::printf("RESULT %s\n", failures == 0 ? "PASS" : "FAIL");
    return failures == 0 ? 0 : 1;
}
