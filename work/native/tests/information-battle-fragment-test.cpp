#include <windows.h>

#include "../information-battle-fragment.h"
#include "../information-battle-drain.h"
#include "../information-battle-log-writer.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <iostream>
#include <limits>
#include <string>
#include <vector>

namespace {

using information::battle::CheckedBattleLogWriter;
using information::battle::Identity;
using information::battle::OwnedBattleDrain;
using information::battle::PushStatus;
using information::battle::Record;
namespace fragment = information::battle::fragment;

constexpr Identity kIdentity{0x1111222233334444ULL, 0xfeedbeefULL};
constexpr std::uint64_t kDuplicateMessageId = 2;

void require(bool condition, const char* message) {
    if (!condition) {
        std::cerr << "FAIL: " << message << '\n';
        std::abort();
    }
}

std::uint32_t read_u32(const std::uint8_t* bytes) noexcept {
    return static_cast<std::uint32_t>(bytes[0])
        | (static_cast<std::uint32_t>(bytes[1]) << 8U)
        | (static_cast<std::uint32_t>(bytes[2]) << 16U)
        | (static_cast<std::uint32_t>(bytes[3]) << 24U);
}

std::uint64_t read_u64(const std::uint8_t* bytes) noexcept {
    std::uint64_t result = 0;
    for (unsigned byte = 0; byte < 8; ++byte) {
        result |= static_cast<std::uint64_t>(bytes[byte]) << (byte * 8U);
    }
    return result;
}

std::vector<std::uint8_t> make_payload(std::size_t size) {
    std::vector<std::uint8_t> payload(size);
    for (std::size_t index = 0; index < size; ++index) {
        payload[index] = static_cast<std::uint8_t>(
            (index * 37U + 11U) & 0xffU);
    }
    return payload;
}

void test_known_crc_and_validation() {
    const std::array<std::uint8_t, 9> known{
        {'1', '2', '3', '4', '5', '6', '7', '8', '9'}};
    fragment::FragmentPlan plan{};
    auto prepared = fragment::prepare(plan, (std::numeric_limits<std::uint64_t>::max)(),
                                       known.data(), known.size());
    require(prepared.succeeded(), "known CRC vector prepares");
    require(plan.message_id == (std::numeric_limits<std::uint64_t>::max)(),
            "maximum message ID is retained");
    require(plan.fragment_count == 1 && plan.total_bytes == 9,
            "known CRC vector has one canonical fragment");
    require(plan.whole_message_crc32 == 0xcbf43926U,
            "CRC32 known vector matches zlib polynomial");

    std::array<std::uint8_t, fragment::kMaxFragmentWireBytes> output{};
    const auto encoded = fragment::encode(plan, known.data(), known.size(),
                                          0, output.data(), output.size());
    require(encoded.succeeded() && encoded.written_bytes == 73,
            "known CRC vector encodes exact header plus bytes");
    require(std::memcmp(output.data(), fragment::kMagic,
                        sizeof(fragment::kMagic)) == 0,
            "fragment magic is exact");
    require(read_u32(output.data() + 40) == 0xcbf43926U,
            "encoded CRC is little endian known value");
    require(read_u32(output.data() + 32) == 9U,
            "encoded fragment byte count is exact");

    fragment::FragmentPlan unchanged{
        9, 9, 1, fragment::kChunkCapacity, 0x12345678U};
    const auto before = unchanged;
    const auto alias_prepare = fragment::prepare(
        unchanged, 10, &unchanged, sizeof(unchanged));
    require(alias_prepare.status == fragment::PrepareStatus::plan_input_overlap,
            "prepare rejects plan/input overlap");
    require(std::memcmp(&unchanged, &before, sizeof(before)) == 0,
            "failed prepare leaves aliased plan unchanged");

    const auto invalid_id = fragment::prepare(
        unchanged, 0, known.data(), known.size());
    require(invalid_id.status == fragment::PrepareStatus::invalid_message_id,
            "zero message ID is rejected");
    const auto null_input = fragment::prepare(
        unchanged, 1, nullptr, known.size());
    require(null_input.status == fragment::PrepareStatus::null_input,
            "null full input is rejected");
    const auto empty_input = fragment::prepare(
        unchanged, 1, known.data(), 0);
    require(empty_input.status == fragment::PrepareStatus::empty_input,
            "empty full input is rejected");
    const auto oversize = fragment::prepare(
        unchanged, 1, known.data(), fragment::kMaxMessageBytes + 1);
    require(oversize.status == fragment::PrepareStatus::oversize_input,
            "oversized full input is rejected");

    std::array<std::uint8_t, fragment::kMaxFragmentWireBytes> untouched{};
    untouched.fill(0xa5U);
    const auto short_capacity = fragment::encode(
        plan, known.data(), known.size(), 0, untouched.data(), 72);
    require(short_capacity.status == fragment::EncodeStatus::insufficient_capacity
                && short_capacity.written_bytes == 0,
            "one-byte-short output capacity is rejected");
    for (const auto byte : untouched) {
        require(byte == 0xa5U,
                "capacity failure leaves the complete output buffer unchanged");
    }

    const auto wrong_size = fragment::encode(
        plan, known.data(), known.size() - 1, 0, output.data(), output.size());
    require(wrong_size.status == fragment::EncodeStatus::size_mismatch,
            "source size mismatch is rejected");
    const auto bad_index = fragment::encode(
        plan, known.data(), known.size(), 1, output.data(), output.size());
    require(bad_index.status == fragment::EncodeStatus::invalid_index,
            "out of range fragment index is rejected");
    const auto bad_plan = [&]() noexcept {
        fragment::FragmentPlan mutated = plan;
        ++mutated.fragment_count;
        return fragment::encode(mutated, known.data(), known.size(), 0,
                                output.data(), output.size());
    }();
    require(bad_plan.status == fragment::EncodeStatus::invalid_plan,
            "noncanonical plan is rejected");

    const auto plan_before_output_alias = plan;
    const auto output_plan_alias = fragment::encode(
        plan, known.data(), known.size(), 0, &plan,
        fragment::kMaxFragmentWireBytes);
    require(output_plan_alias.status == fragment::EncodeStatus::plan_output_overlap,
            "encode rejects output overlapping the plan object");
    require(std::memcmp(&plan, &plan_before_output_alias,
                        sizeof(plan)) == 0,
            "plan-output overlap failure leaves the plan unchanged");
    const std::vector<std::uint8_t> separate_input(known.begin(), known.end());
    const auto input_before_output_alias = separate_input;
    const auto output_input_alias = fragment::encode(
        plan, separate_input.data(), separate_input.size(), 0,
        const_cast<std::uint8_t*>(separate_input.data()), output.size());
    require(output_input_alias.status == fragment::EncodeStatus::input_output_overlap,
            "encode rejects output overlapping full input");
    require(separate_input == input_before_output_alias,
            "input-output overlap failure leaves the source unchanged");

    std::array<std::uint8_t, 256> partial_alias_storage{};
    for (std::size_t index = 0; index < partial_alias_storage.size(); ++index) {
        partial_alias_storage[index] = static_cast<std::uint8_t>(index);
    }
    fragment::FragmentPlan partial_plan{};
    require(fragment::prepare(partial_plan, 3, partial_alias_storage.data(),
                              partial_alias_storage.size()).succeeded(),
            "partial alias source prepares");
    const auto partial_alias = fragment::encode(
        partial_plan, partial_alias_storage.data(), partial_alias_storage.size(),
        0, partial_alias_storage.data() + 1, output.size());
    require(partial_alias.status == fragment::EncodeStatus::input_output_overlap,
            "partial input/output overlap is rejected");
}

void test_sizes_and_headers() {
    const std::array<std::size_t, 5> sizes{
        1, 4032, 4033, 10037, fragment::kMaxMessageBytes};
    for (std::size_t size : sizes) {
        const auto payload = make_payload(size);
        fragment::FragmentPlan plan{};
        require(fragment::prepare(plan, static_cast<std::uint64_t>(size),
                                  payload.data(), payload.size()).succeeded(),
                "boundary payload prepares");
        const std::uint32_t expected_count = static_cast<std::uint32_t>(
            (size + fragment::kChunkBytes - 1) / fragment::kChunkBytes);
        require(plan.fragment_count == expected_count,
                "fragment count uses canonical ceiling");

        std::array<std::uint8_t, fragment::kMaxFragmentWireBytes> first{};
        std::array<std::uint8_t, fragment::kMaxFragmentWireBytes> second{};
        for (std::uint32_t index = 0; index < plan.fragment_count; ++index) {
            first.fill(0xccU);
            second.fill(0xddU);
            const auto encoded = fragment::encode(
                plan, payload.data(), payload.size(), index, first.data(),
                first.size());
            require(encoded.succeeded(), "boundary fragment encodes");
            const std::uint32_t fragment_bytes = read_u32(first.data() + 32);
            require(fragment_bytes ==
                        static_cast<std::uint32_t>(
                            std::min<std::size_t>(fragment::kChunkBytes,
                                size - static_cast<std::size_t>(index)
                                    * fragment::kChunkBytes)),
                    "fragment byte count is canonical");
            require(read_u32(first.data() + 20) == size,
                    "total bytes is little endian and exact");
            require(read_u32(first.data() + 24) == index
                        && read_u32(first.data() + 28) == plan.fragment_count,
                    "index and count are exact");
            require(read_u32(first.data() + 36) == fragment::kChunkCapacity,
                    "chunk capacity is exact");
            for (std::size_t offset = 44; offset < 64; ++offset) {
                require(first[offset] == 0,
                        "reserved header bytes remain zero");
            }
            require(std::memcmp(first.data() + 64,
                                payload.data() + static_cast<std::size_t>(index)
                                    * fragment::kChunkBytes,
                                fragment_bytes) == 0,
                    "fragment data is the exact source slice");

            const auto deterministic = fragment::encode(
                plan, payload.data(), payload.size(), index, second.data(),
                second.size());
            require(deterministic.succeeded()
                        && deterministic.written_bytes == encoded.written_bytes
                        && std::memcmp(first.data(), second.data(),
                                       encoded.written_bytes) == 0,
                    "same inputs produce byte-identical fragments");
        }
    }
}

struct LossAckSink final {
    CheckedBattleLogWriter* writer = nullptr;
    bool lost_ack = false;
    bool retry_ack = false;
    std::size_t attempts = 0;

    bool operator()(const Record& record) noexcept {
        ++attempts;
        const bool written = (*writer)(record);
        if (!written) {
            return false;
        }
        const bool is_target = record.size >= 20
            && read_u64(record.payload.data() + 12) == kDuplicateMessageId;
        if (is_target && !lost_ack) {
            lost_ack = true;
            return false;
        }
        if (is_target && lost_ack) {
            retry_ack = true;
        }
        return true;
    }
};

void test_real_fragmented_log(const wchar_t* log_path) {
    information::battle::Win32BattleLogIo io;
    CheckedBattleLogWriter writer(io);
    require(writer.open(log_path, kIdentity), "real fragmented log opens");
    OwnedBattleDrain drain(kIdentity);
    LossAckSink sink{&writer};
    const std::array<std::size_t, 5> sizes{
        1, 4032, 4033, 10037, fragment::kMaxMessageBytes};

    std::size_t fragment_total = 0;
    for (std::size_t message_index = 0; message_index < sizes.size();
         ++message_index) {
        const std::uint64_t message_id =
            static_cast<std::uint64_t>(message_index + 1);
        const auto payload = make_payload(sizes[message_index]);
        fragment::FragmentPlan plan{};
        require(fragment::prepare(plan, message_id, payload.data(),
                                  payload.size()).succeeded(),
                "real message prepares");
        fragment_total += plan.fragment_count;

        std::array<std::uint8_t, fragment::kMaxFragmentWireBytes> frame{};
        for (std::uint32_t index = 0; index < plan.fragment_count; ++index) {
            const auto encoded = fragment::encode(
                plan, payload.data(), payload.size(), index, frame.data(),
                frame.size());
            require(encoded.succeeded() && encoded.written_bytes <= 4096,
                    "encoded fragment fits one existing Record");
            const auto pushed = drain.push(kIdentity, frame.data(),
                                           encoded.written_bytes);
            require(pushed.status == PushStatus::accepted,
                    "fragment enters the existing owned queue");
            const auto first = drain.drain(sink, 1);
            require(first.sink_attempts == 1,
                    "each fragment is drained with one sink budget");
            if (message_id == kDuplicateMessageId && index == 0) {
                require(first.stopped_on_rejection && drain.has_pending(),
                        "lost acknowledgement leaves the same outer record pending");
                const auto retry = drain.drain(sink, 1);
                require(retry.delivered == 1 && !drain.has_pending(),
                        "same pending outer record is acknowledged on retry");
            } else {
                require(first.delivered == 1 && !drain.has_pending(),
                        "ordinary fragment is acknowledged");
            }
        }
    }

    require(sink.lost_ack && sink.retry_ack,
            "exactly one target record exercised lost acknowledgement retry");
    require(sink.attempts == fragment_total + 1,
            "one duplicate sink attempt was added without a new queue record");
    const auto stats = drain.stats();
    require(stats.accepted == fragment_total && stats.popped == fragment_total,
            "queue accepted and popped only canonical fragments");
    require(writer.close(), "real fragmented log closes cleanly");
    std::cout << "fragment_total=" << fragment_total
              << " sink_attempts=" << sink.attempts << '\n';
}

} // namespace

int wmain(int argc, wchar_t** argv) {
    require(argc == 2, "usage: information-battle-fragment-test <log path>");
    test_known_crc_and_validation();
    test_sizes_and_headers();
    test_real_fragmented_log(argv[1]);
    std::cout << "information-battle-fragment-test: passed\n";
    return 0;
}
