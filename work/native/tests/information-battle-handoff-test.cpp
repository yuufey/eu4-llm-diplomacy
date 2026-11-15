#include "../information-battle-drain.h"
#include "../information-battle-wire.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>

namespace {

using information::battle::DrainStatus;
using information::battle::Identity;
using information::battle::OwnedBattleDrain;
using information::battle::Record;
using information::battle::WireResult;
using information::battle::encode_jsonl;
using information::battle::max_required_capacity;

constexpr Identity kIdentity{0x1111222233334444ULL, 0xfeedbeefULL};

void require(bool condition, const char* message) {
    if (!condition) {
        std::cerr << "FAIL: " << message << '\n';
        std::abort();
    }
}

Record make_a() {
    Record record{};
    record.identity = kIdentity;
    record.attempt_sequence = 1;
    record.size = 4;
    record.payload[0] = 0xde;
    record.payload[1] = 0xad;
    record.payload[2] = 0xbe;
    record.payload[3] = 0xef;
    return record;
}

Record make_b() {
    Record record{};
    record.identity = kIdentity;
    record.attempt_sequence = 2;
    record.size = static_cast<std::uint32_t>(
        information::battle::OwnedByteQueue::max_payload_bytes);
    for (std::size_t index = 0; index < record.size; ++index) {
        record.payload[index] = static_cast<std::uint8_t>(index & 0xffU);
    }
    return record;
}

std::string encoded_line(const Record& record) {
    std::array<char, max_required_capacity()> buffer{};
    const WireResult result = encode_jsonl(record, buffer.data(), buffer.size());
    require(result.succeeded(), "expected opaque record encodes successfully");
    return std::string(buffer.data(), result.written_bytes);
}

void test_handoff(const char* output_path) {
    const std::array<std::uint8_t, 4> payload_a{{0xde, 0xad, 0xbe, 0xef}};
    const Record expected_a = make_a();
    const Record expected_b = make_b();
    OwnedBattleDrain drain(kIdentity);

    require(drain.push(kIdentity, payload_a.data(), payload_a.size()).accepted(),
            "A is accepted by the owned drain queue");
    require(drain.push(kIdentity, expected_b.payload.data(), expected_b.size)
                .accepted(),
            "4096-byte B is accepted by the owned drain queue");

    std::ofstream output(output_path, std::ios::binary | std::ios::trunc);
    require(output.good(), "handoff JSONL output opens");
    std::size_t sink_calls = 0;
    std::size_t confirmations = 0;
    std::array<std::string, 3> observed{};

    const auto sink = [&](const Record& record) noexcept -> bool {
        std::array<char, max_required_capacity()> wire{};
        const WireResult result = encode_jsonl(record, wire.data(), wire.size());
        if (!result.succeeded()) {
            return false;
        }
        output.write(wire.data(), static_cast<std::streamsize>(result.written_bytes));
        output.flush();
        if (!output.good() || sink_calls >= observed.size()) {
            return false;
        }
        observed[sink_calls] = std::string(wire.data(), result.written_bytes);
        ++sink_calls;
        if (sink_calls == 1) {
            // The complete A line has been written and flushed, but the
            // acknowledgement is intentionally lost.  OwnedBattleDrain must
            // keep the exact pending copy for the next call.
            return false;
        }
        ++confirmations;
        return true;
    };

    const auto first = drain.drain(sink, 1);
    require(first.status == DrainStatus::sink_rejected
                && first.sink_attempts == 1
                && first.delivered == 0
                && first.pending_after,
            "first complete write is an unconfirmed A delivery");

    const auto retry = drain.drain(sink, 1);
    require(retry.status == DrainStatus::budget_exhausted
                && retry.sink_attempts == 1
                && retry.delivered == 1
                && !retry.pending_after
                && retry.budget_exhausted,
            "next drain confirms the same pending A");

    const auto second = drain.drain(sink, 1);
    require(second.status == DrainStatus::completed
                && second.sink_attempts == 1
                && second.delivered == 1
                && !second.pending_after,
            "following drain confirms B");

    output.close();
    require(output.good(), "handoff JSONL output closes successfully");
    require(sink_calls == 3 && confirmations == 2,
            "sink observes three attempts and two confirmations");
    require(drain.stats().popped == 2 && drain.stats().queued == 0
                && !drain.has_pending(),
            "queue pops exactly A and B and has no pending record");
    require(observed[0] == observed[1],
            "the unconfirmed A retry has identical wire bytes and ID");
    require(observed[2] == encoded_line(expected_b),
            "B wire line contains the complete 4096-byte all-value pattern");

    std::ifstream input(output_path, std::ios::binary);
    require(input.good(), "handoff JSONL output reopens");
    const std::string actual((std::istreambuf_iterator<char>(input)),
                             std::istreambuf_iterator<char>());
    input.close();
    const std::string expected = encoded_line(expected_a)
        + encoded_line(expected_a) + encoded_line(expected_b);
    require(actual == expected,
            "handoff file contains exactly three raw JSONL frames with no metadata");
    std::size_t newline_count = 0;
    for (const char byte : actual) {
        if (byte == '\n') {
            ++newline_count;
        }
    }
    require(newline_count == 3,
            "handoff file contains exactly three newline-terminated frames");
}

} // namespace

int main(int argc, char** argv) {
    require(argc == 2, "usage: test <handoff-frames-001.jsonl>");
    test_handoff(argv[1]);
    std::cout << "information-battle-handoff-test: passed\n";
    return 0;
}
