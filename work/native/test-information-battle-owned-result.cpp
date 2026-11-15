#include "information-battle-owned-result.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <limits>

namespace {

namespace owned = information::battle::owned_result;

constexpr owned::Address kModuleBase = UINT64_C(0x140000000);
constexpr owned::Address kResult = UINT64_C(0x200000000);
constexpr owned::Address kProvince = UINT64_C(0x210000000);
constexpr owned::Address kDate = UINT64_C(0x220000001);
constexpr owned::Address kNameHeap = UINT64_C(0x230000000);
constexpr owned::Address kCommanderAHeap = UINT64_C(0x240000000);
constexpr owned::Address kCommanderBHeap = UINT64_C(0x250000000);
constexpr std::size_t kSegmentBytes = 8192u;
constexpr std::size_t kMaxSegments = 32u;

constexpr std::uint64_t kFraCountry = UINT64_C(0x0100007a00415246);
constexpr std::uint64_t kBurCountry = UINT64_C(0x0100007500525542);
constexpr std::array<unsigned char, 15> kBattleName{{
    0x11, 0x31, 0x57, 0x10, 0x54, 0x4e, 0x10, 0xbb,
    0x6c, 0x10, 0x77, 0x6d, 0x12, 0xe1, 0x53,
}};
constexpr std::array<unsigned char, 22> kBurCommander{{
    0x10, 0x81, 0x9c, 0x10, 0x53, 0x90, 0x10, 0x2b,
    0x59, 0x20, 0x56, 0x61, 0x6c, 0x6b, 0x65, 0x6e,
    0x73, 0x77, 0x61, 0x61, 0x72, 0x64,
}};

struct Segment {
    owned::Address address = 0;
    std::size_t size = 0;
    std::array<unsigned char, kSegmentBytes> bytes{};
};

struct SparseReader {
    std::array<Segment, kMaxSegments> segments{};
    std::size_t count = 0;
    std::size_t read_calls = 0;
    std::size_t bytes_requested = 0;
    std::size_t read_limit = std::numeric_limits<std::size_t>::max();
    bool short_first_read = false;

    void clear() noexcept {
        *this = SparseReader{};
        read_limit = std::numeric_limits<std::size_t>::max();
    }

    bool add(owned::Address address, const void* source,
             std::size_t size) noexcept {
        if (source == nullptr || size == 0 || size > kSegmentBytes
                || count >= segments.size()) {
            return false;
        }
        Segment& segment = segments[count++];
        segment.address = address;
        segment.size = size;
        std::memcpy(segment.bytes.data(), source, size);
        return true;
    }

    bool write(owned::Address address, const void* source,
               std::size_t size) noexcept {
        if (source == nullptr || size == 0) {
            return false;
        }
        for (std::size_t index = 0; index < count; ++index) {
            Segment& segment = segments[index];
            if (address < segment.address
                    || address - segment.address > segment.size
                    || size > segment.size - (address - segment.address)) {
                continue;
            }
            std::memcpy(segment.bytes.data() + (address - segment.address),
                        source, size);
            return true;
        }
        return false;
    }

    bool read(owned::Address address, unsigned char* destination,
              std::size_t size) noexcept {
        ++read_calls;
        if (destination == nullptr || size == 0 || bytes_requested > read_limit
                || size > read_limit - bytes_requested) {
            return false;
        }
        ++bytes_requested;
        if (short_first_read && read_calls == 1u) {
            for (std::size_t index = 0; index < count; ++index) {
                const Segment& segment = segments[index];
                if (address >= segment.address
                        && address - segment.address < segment.size
                        && size <= segment.size - (address - segment.address)) {
                    const std::size_t partial = size > 1u ? size - 1u : 0u;
                    std::memcpy(destination,
                                segment.bytes.data()
                                    + (address - segment.address),
                                partial);
                    return false;
                }
            }
            return false;
        }
        for (std::size_t index = 0; index < count; ++index) {
            const Segment& segment = segments[index];
            if (address < segment.address
                    || address - segment.address > segment.size
                    || size > segment.size - (address - segment.address)) {
                continue;
            }
            std::memcpy(destination,
                        segment.bytes.data() + (address - segment.address),
                        size);
            return true;
        }
        return false;
    }

};

unsigned g_failures = 0;
unsigned g_checks = 0;

void check(bool condition, const char* name) noexcept {
    ++g_checks;
    std::printf("CHECK %s %s\n", name, condition ? "PASS" : "FAIL");
    if (!condition) {
        ++g_failures;
    }
}

void put_u64(unsigned char* destination, std::uint64_t value) noexcept {
    std::memcpy(destination, &value, sizeof(value));
}

void put_i32(unsigned char* destination, std::int32_t value) noexcept {
    std::memcpy(destination, &value, sizeof(value));
}

bool set_sso(SparseReader& reader, owned::Address address,
             const unsigned char* bytes, std::size_t length,
             std::size_t capacity, owned::Address heap_address = 0) noexcept {
    std::array<unsigned char, owned::kStringObjectBytes> header{};
    if (length > owned::kMaxOwnedStringBytes || capacity < length
            || capacity > owned::kMaxStringCapacity
            || (capacity < 16u && length > 15u)) {
        return false;
    }
    if (length != 0u && bytes == nullptr) {
        return false;
    }
    if (capacity < 16u) {
        if (length != 0u) {
            std::memcpy(header.data(), bytes, length);
        }
        header[length] = 0;
    } else {
        if (heap_address == 0u) {
            return false;
        }
        put_u64(header.data(), heap_address);
        std::array<unsigned char, owned::kMaxOwnedStringBytes + 1u> payload{};
        if (length != 0u) {
            std::memcpy(payload.data(), bytes, length);
        }
        payload[length] = 0;
        if (!reader.add(heap_address, payload.data(), length + 1u)) {
            return false;
        }
    }
    put_u64(header.data() + 0x10u, static_cast<std::uint64_t>(length));
    put_u64(header.data() + 0x18u, static_cast<std::uint64_t>(capacity));
    return reader.write(address, header.data(), header.size());
}

bool build_fixture(SparseReader& reader, bool heap_name,
                   bool empty_heap_commander) noexcept {
    reader.clear();
    std::array<unsigned char, owned::kResultObjectBytes> result{};
    std::array<unsigned char, sizeof(std::int32_t)> province{};
    std::array<unsigned char, sizeof(std::int32_t)> date{};
    put_u64(result.data(), kModuleBase + owned::kResultVtableRva);
    put_u64(result.data() + owned::kResultSideAOffset,
            kModuleBase + owned::kSideVtableRva);
    put_u64(result.data() + owned::kResultSideBOffset,
            kModuleBase + owned::kSideVtableRva);
    result[owned::kResultFlag108Offset] = 0;
    put_i32(result.data() + owned::kResultAux100Offset, 142000);
    put_i32(result.data() + owned::kResultAux104Offset, 147000);
    put_u64(result.data() + owned::kResultProvincePointerOffset, kProvince);
    put_i32(province.data(), 1285);
    put_i32(date.data(), 56552232);

    unsigned char* side_a = result.data() + owned::kResultSideAOffset;
    unsigned char* side_b = result.data() + owned::kResultSideBOffset;
    put_u64(side_a + owned::kSideCountryOffset, kFraCountry);
    put_u64(side_b + owned::kSideCountryOffset, kBurCountry);
    put_i32(side_a + 0x48u, 3);
    put_i32(side_a + 0x54u, 3);
    put_i32(side_b + 0x44u, 3);
    put_i32(side_b + 0x48u, 6);
    put_i32(side_b + 0x50u, 13);

    if (!reader.add(kResult, result.data(), result.size())
            || !reader.add(kProvince + owned::kProvinceIdOffset,
                           province.data(), province.size())
            || !reader.add(kDate, date.data(), date.size())) {
        return false;
    }

    if (heap_name) {
        if (!set_sso(reader, kResult + owned::kResultNameOffset,
                     kBattleName.data(), kBattleName.size(), 31u,
                     kNameHeap)) {
            return false;
        }
    } else if (!set_sso(reader, kResult + owned::kResultNameOffset,
                       kBattleName.data(), kBattleName.size(),
                       kBattleName.size())) {
        return false;
    }
    if (empty_heap_commander) {
        if (!set_sso(reader, kResult + owned::kResultSideAOffset
                         + owned::kSideCommanderOffset,
                     nullptr, 0u, 16u, kCommanderAHeap)) {
            return false;
        }
    } else if (!set_sso(reader, kResult + owned::kResultSideAOffset
                            + owned::kSideCommanderOffset,
                        nullptr, 0u, 15u)) {
        return false;
    }
    return set_sso(reader, kResult + owned::kResultSideBOffset
                         + owned::kSideCommanderOffset,
                   kBurCommander.data(), kBurCommander.size(), 31u,
                   kCommanderBHeap);
}

bool same_snapshot(const owned::Snapshot& left,
                   const owned::Snapshot& right) noexcept {
    return std::memcmp(&left, &right, sizeof(left)) == 0;
}

void test_recorded_fixture() noexcept {
    SparseReader reader;
    check(build_fixture(reader, false, false), "fixture_build");
    owned::Snapshot snapshot{};
    const bool captured = owned::capture(reader, kModuleBase, kResult, kDate,
                                         snapshot);
    check(captured, "recorded_fra_bur_capture");
    check(snapshot.raw_date == 56552232, "recorded_raw_date");
    check(snapshot.province_id == 1285, "recorded_province_id");
    check(snapshot.aux100 == 142000 && snapshot.aux104 == 147000,
          "recorded_aux_values");
    check(snapshot.sides[0].country == kFraCountry
              && snapshot.sides[1].country == kBurCountry,
          "recorded_country_handles");
    check(snapshot.sides[0].raw_fields[4] == 3
              && snapshot.sides[0].raw_fields[7] == 3
              && snapshot.sides[1].raw_fields[3] == 3
              && snapshot.sides[1].raw_fields[4] == 6
              && snapshot.sides[1].raw_fields[6] == 13,
          "recorded_raw_side_fields");
    check(snapshot.name.length == kBattleName.size()
              && std::memcmp(snapshot.name.bytes.data(), kBattleName.data(),
                             kBattleName.size()) == 0,
          "recorded_battle_name_bytes");
    check(snapshot.sides[0].commander.length == 0u
              && snapshot.sides[1].commander.length == kBurCommander.size()
              && std::memcmp(snapshot.sides[1].commander.bytes.data(),
                             kBurCommander.data(), kBurCommander.size()) == 0,
          "recorded_commander_bytes");

    owned::Snapshot alternate_snapshot{};
    check(owned::capture(kModuleBase, kResult, kDate, alternate_snapshot,
                         reader),
          "capture_reader_last_overload");
    check(same_snapshot(snapshot, alternate_snapshot),
          "capture_overloads_same_snapshot");

    const owned::Snapshot before = snapshot;
    const std::array<unsigned char, 1> changed{{0x7f}};
    check(reader.write(kResult + owned::kResultNameOffset, changed.data(), 1u),
          "source_mutation_setup");
    check(same_snapshot(snapshot, before), "snapshot_owns_copy_after_source_change");
}

void test_heap_empty() noexcept {
    SparseReader reader;
    check(build_fixture(reader, true, true), "heap_empty_fixture_build");
    owned::Snapshot snapshot{};
    check(owned::capture(reader, kModuleBase, kResult, kDate, snapshot),
          "heap_name_and_empty_commander_capture");
    check(snapshot.name.length == kBattleName.size()
              && snapshot.name.capacity == 31u,
          "heap_name_length_capacity");
    check(snapshot.sides[0].commander.length == 0u
              && snapshot.sides[0].commander.capacity == 16u,
          "heap_empty_commander_terminator_read");
}

void test_failure_unchanged(const char* name, SparseReader& reader,
                            owned::Address result = kResult,
                            owned::Address date = kDate,
                            owned::Address module_base = kModuleBase) noexcept {
    owned::Snapshot output;
    std::array<unsigned char, sizeof(output)> sentinel{};
    sentinel.fill(0xa5);
    std::memcpy(&output, sentinel.data(), sizeof(output));
    const owned::Snapshot before = output;
    const bool captured = owned::capture(reader, module_base, result, date,
                                         output);
    check(!captured, name);
    check(same_snapshot(before, output), "failure_output_unchanged");
}

void test_failures() noexcept {
    SparseReader reader;
    check(build_fixture(reader, false, false), "failure_fixture_build");

    std::array<unsigned char, owned::kStringObjectBytes> header{};
    check(reader.read(kResult + owned::kResultNameOffset, header.data(),
                      header.size()), "oversize_header_read");
    put_u64(header.data() + 0x10u, 4097u);
    put_u64(header.data() + 0x18u, 4097u);
    check(reader.write(kResult + owned::kResultNameOffset, header.data(),
                      header.size()), "oversize_header_write");
    test_failure_unchanged("oversize_rejected", reader);

    check(build_fixture(reader, false, false), "capacity_fixture_build");
    check(reader.read(kResult + owned::kResultNameOffset, header.data(),
                      header.size()), "capacity_header_read");
    put_u64(header.data() + 0x18u, 14u);
    check(reader.write(kResult + owned::kResultNameOffset, header.data(),
                      header.size()), "capacity_header_write");
    test_failure_unchanged("capacity_below_length_rejected", reader);

    check(build_fixture(reader, false, false), "capacity_limit_fixture_build");
    check(reader.read(kResult + owned::kResultNameOffset, header.data(),
                      header.size()), "capacity_limit_header_read");
    put_u64(header.data() + 0x18u, owned::kMaxStringCapacity + 1u);
    check(reader.write(kResult + owned::kResultNameOffset, header.data(),
                      header.size()), "capacity_limit_header_write");
    test_failure_unchanged("capacity_above_limit_rejected", reader);

    check(build_fixture(reader, false, false), "nul_fixture_build");
    std::array<unsigned char, 1> bad_nul{{0x7f}};
    check(reader.write(kResult + owned::kResultNameOffset + 15u,
                      bad_nul.data(), bad_nul.size()), "nul_mutation_write");
    test_failure_unchanged("inline_nul_rejected", reader);

    check(build_fixture(reader, true, false), "heap_nul_fixture_build");
    std::array<unsigned char, 32> heap_header{};
    check(reader.read(kResult + owned::kResultSideBOffset
                          + owned::kSideCommanderOffset,
                      heap_header.data(), heap_header.size()),
          "heap_nul_header_read");
    const owned::Address commander_heap = [&heap_header]() noexcept {
        std::uint64_t value = 0;
        std::memcpy(&value, heap_header.data(), sizeof(value));
        return static_cast<owned::Address>(value);
    }();
    std::array<unsigned char, 1> bad_heap_nul{{0x7f}};
    check(reader.write(commander_heap + kBurCommander.size(),
                       bad_heap_nul.data(), bad_heap_nul.size()),
          "heap_nul_mutation_write");
    test_failure_unchanged("heap_nul_rejected", reader);

    check(build_fixture(reader, true, false), "short_fixture_build");
    reader.short_first_read = true;
    test_failure_unchanged("short_read_rejected", reader);

    check(build_fixture(reader, false, false), "vtable_fixture_build");
    std::array<unsigned char, 8> bad_vtable{};
    put_u64(bad_vtable.data(), 0x12345678u);
    check(reader.write(kResult, bad_vtable.data(), bad_vtable.size()),
          "vtable_mutation_write");
    test_failure_unchanged("result_vtable_rejected", reader);

    check(build_fixture(reader, false, false), "side_vtable_fixture_build");
    put_u64(bad_vtable.data(), 0x12345678u);
    check(reader.write(kResult + owned::kResultSideBOffset,
                      bad_vtable.data(), bad_vtable.size()),
          "side_vtable_mutation_write");
    test_failure_unchanged("side_vtable_rejected", reader);

    check(build_fixture(reader, false, false), "address_fixture_build");
    test_failure_unchanged("result_address_rejected", reader,
                           owned::kMaxCanonicalExclusive - 0x100u);
    test_failure_unchanged("result_alignment_rejected", reader, kResult + 1u);
    test_failure_unchanged("module_base_noncanonical_rejected", reader,
                           kResult, kDate, 0x8000u);
    test_failure_unchanged("expected_vtable_noncanonical_rejected", reader,
                           kResult, kDate,
                           owned::kMaxCanonicalExclusive - 0x1000u);

    check(build_fixture(reader, false, false), "province_alignment_fixture_build");
    std::array<unsigned char, 8> bad_province_pointer{};
    put_u64(bad_province_pointer.data(), kProvince + 1u);
    check(reader.write(kResult + owned::kResultProvincePointerOffset,
                       bad_province_pointer.data(), bad_province_pointer.size()),
          "province_alignment_mutation_write");
    test_failure_unchanged("province_alignment_rejected", reader);

    check(build_fixture(reader, false, false), "read_budget_fixture_build");
    reader.read_limit = 100u;
    test_failure_unchanged("reader_budget_rejected", reader);

    check(build_fixture(reader, false, false), "alias_fixture_build");
    {
        owned::Snapshot output;
        std::array<unsigned char, sizeof(output)> sentinel{};
        sentinel.fill(0xa5);
        std::memcpy(&output, sentinel.data(), sizeof(output));
        const owned::Snapshot before = output;
        const owned::Address output_address =
            reinterpret_cast<owned::Address>(&output);
        const bool captured = owned::capture(
            reader, kModuleBase, output_address, kDate, output);
        check(!captured, "source_output_alias_rejected");
        check(same_snapshot(before, output),
              "source_output_alias_failure_unchanged");
    }

    check(build_fixture(reader, true, false), "heap_alias_fixture_build");
    {
        owned::Snapshot output;
        std::array<unsigned char, sizeof(output)> sentinel{};
        sentinel.fill(0xa5);
        std::memcpy(&output, sentinel.data(), sizeof(output));
        const owned::Snapshot before = output;
        const owned::Address output_address =
            reinterpret_cast<owned::Address>(&output);
        std::array<unsigned char, owned::kStringObjectBytes> commander_header{};
        check(reader.read(kResult + owned::kResultSideBOffset
                              + owned::kSideCommanderOffset,
                          commander_header.data(), commander_header.size()),
              "heap_alias_header_read");
        put_u64(commander_header.data(), output_address);
        check(reader.write(kResult + owned::kResultSideBOffset
                               + owned::kSideCommanderOffset,
                           commander_header.data(), commander_header.size()),
              "heap_alias_header_write");
        const bool captured = owned::capture(
            reader, kModuleBase, kResult, kDate, output);
        check(!captured, "heap_output_alias_rejected");
        check(same_snapshot(before, output),
              "heap_output_alias_failure_unchanged");
    }

    check(build_fixture(reader, false, false), "date_address_fixture_build");
    test_failure_unchanged("raw_date_overflow_rejected", reader, kResult,
                           owned::kMaxCanonicalExclusive - 1u);
}

}  // namespace

int main() {
    test_recorded_fixture();
    test_heap_empty();
    test_failures();
    std::printf("SUMMARY checks=%u failures=%u\n", g_checks, g_failures);
    std::printf("RESULT %s\n", g_failures == 0u ? "PASS" : "FAIL");
    return g_failures == 0u ? 0 : 1;
}
