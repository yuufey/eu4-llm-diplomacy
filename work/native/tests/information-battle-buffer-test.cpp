#include "../information-battle-buffer.h"

#include <array>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <thread>

namespace {

using information::battle::Identity;
using information::battle::OwnedByteQueue;
using information::battle::PushStatus;
using information::battle::Record;
using information::battle::ResetStatus;

constexpr Identity kIdentity{0x1111222233334444ULL, 1};

void require(bool condition, const char* message) {
    if (!condition) {
        std::cerr << "FAIL: " << message << '\n';
        std::terminate();
    }
}

void test_owning_copy_and_order() {
    OwnedByteQueue queue(kIdentity);
    std::array<std::uint8_t, 6> source{{1, 2, 3, 4, 5, 6}};
    const auto pushed = queue.push(kIdentity, source.data(), source.size());
    require(pushed.status == PushStatus::accepted, "first payload accepted");
    require(pushed.attempt_sequence == 1, "first sequence is one");

    source.fill(0xee);
    Record record{};
    require(queue.pop(record), "record is available");
    require(record.identity == kIdentity, "record identity copied");
    require(record.attempt_sequence == 1, "record sequence preserved");
    require(record.size == 6, "record size preserved");
    require(record.payload[0] == 1 && record.payload[5] == 6,
            "payload is owned rather than caller-backed");
    require(queue.empty(), "queue empty after pop");

    const auto stats = queue.stats();
    require(!stats.consistent, "multi-field stats advertise non-linearizable snapshot");
    require(stats.accepted == 1 && stats.popped == 1,
            "accepted and popped counters are visible");
}

void test_capacity_full_gap_and_no_overwrite() {
    OwnedByteQueue queue(kIdentity);
    for (std::size_t i = 0; i < OwnedByteQueue::capacity; ++i) {
        const auto value = static_cast<std::uint8_t>(i);
        const auto result = queue.push(kIdentity, &value, sizeof(value));
        require(result.status == PushStatus::accepted, "capacity slot accepted");
        require(result.attempt_sequence == i + 1, "capacity sequence is ordered");
    }

    const std::uint8_t rejected = 0xa5;
    const auto full = queue.push(kIdentity, &rejected, sizeof(rejected));
    require(full.status == PushStatus::full, "full queue rejects without overwrite");
    require(full.attempt_sequence == OwnedByteQueue::capacity + 1,
            "full attempt consumes a visible sequence");

    Record record{};
    for (std::size_t i = 0; i < OwnedByteQueue::capacity; ++i) {
        require(queue.pop(record), "every original record remains available");
        require(record.size == 1 && record.payload[0] == i,
                "full rejection did not overwrite an older record");
        require(record.attempt_sequence == i + 1,
                "records retain FIFO attempt sequence");
    }
    require(!queue.pop(record), "queue empty after draining capacity");

    const std::uint8_t after_gap = 0x5a;
    const auto accepted = queue.push(kIdentity, &after_gap, sizeof(after_gap));
    require(accepted.status == PushStatus::accepted, "queue accepts after drain");
    require(accepted.attempt_sequence == OwnedByteQueue::capacity + 2,
            "post-full sequence exposes the gap");
    require(queue.pop(record) && record.payload[0] == after_gap,
            "post-full payload is delivered");

    const auto stats = queue.stats();
    require(stats.attempts == OwnedByteQueue::capacity + 2,
            "attempt count includes the full attempt");
    require(stats.accepted == OwnedByteQueue::capacity + 1,
            "accepted count excludes the full attempt");
    require(stats.dropped_full == 1 && stats.dropped_total() == 1,
            "full loss is explicitly accounted");
    require(stats.last_attempt_sequence == OwnedByteQueue::capacity + 2,
            "last attempt sequence identifies the gap");
}

void test_invalid_and_oversize_inputs() {
    OwnedByteQueue queue(kIdentity);
    const std::uint8_t one = 1;
    const auto empty = queue.push(kIdentity, nullptr, 0);
    require(empty.status == PushStatus::empty_payload && empty.attempt_sequence == 1,
            "empty input is rejected and sequenced");
    const auto null_payload = queue.push(kIdentity, nullptr, 1);
    require(null_payload.status == PushStatus::null_payload
                && null_payload.attempt_sequence == 2,
            "null non-empty input is invalid");

    std::array<std::uint8_t, OwnedByteQueue::max_payload_bytes + 1> oversized{};
    const auto too_large = queue.push(kIdentity, oversized.data(), oversized.size());
    require(too_large.status == PushStatus::oversize && too_large.attempt_sequence == 3,
            "oversize input is rejected");

    std::array<std::uint8_t, OwnedByteQueue::max_payload_bytes> maximum{};
    maximum.fill(0x7c);
    const auto boundary = queue.push(kIdentity, maximum.data(), maximum.size());
    require(boundary.status == PushStatus::accepted && boundary.attempt_sequence == 4,
            "maximum payload boundary is accepted");
    Record record{};
    require(queue.pop(record), "maximum payload is readable");
    require(record.size == maximum.size() && record.payload[0] == 0x7c
                && record.payload.back() == 0x7c,
            "maximum payload bytes are copied");

    const auto stats = queue.stats();
    require(stats.dropped_empty == 1 && stats.dropped_invalid == 1
                && stats.dropped_oversize == 1,
            "invalid categories are separately accounted");
    require(stats.dropped_total() == 3, "all rejected input is accounted");
    (void)one;
}

void test_identity_isolation_and_quiescent_reset() {
    const Identity next_generation{kIdentity.installation, 2};
    const Identity third_generation{kIdentity.installation, 3};
    const Identity other_installation{0x9999888877776666ULL, 7};
    const Identity invalid_installation{0, 7};
    OwnedByteQueue queue(kIdentity);
    const std::uint8_t value = 0x31;

    const auto stale = queue.push(other_installation, &value, 1);
    require(stale.status == PushStatus::stale_identity && stale.attempt_sequence == 0,
            "stale identity cannot allocate current-session sequence");
    require(queue.stats().dropped_stale_identity == 1,
            "stale identity is explicitly counted");

    require(queue.push(kIdentity, &value, 1).accepted(),
            "current identity payload accepted");
    require(queue.reset(other_installation).status == ResetStatus::not_quiescent,
            "reset while non-empty is rejected");
    Record record{};
    require(queue.pop(record) && record.identity == kIdentity,
            "old identity record drains before reset");
    require(queue.reset(kIdentity).status == ResetStatus::same_identity,
            "same identity cannot reset its sequence");
    require(queue.reset(invalid_installation).status == ResetStatus::invalid_identity,
            "invalid identity cannot activate a session");

    require(queue.reset(next_generation).status == ResetStatus::reset,
            "new generation can reset a quiescent queue");
    require(queue.push(kIdentity, &value, 1).status == PushStatus::stale_identity,
            "old generation is rejected after reset");
    const auto new_record = queue.push(next_generation, &value, 1);
    require(new_record.status == PushStatus::accepted
                && new_record.attempt_sequence == 1,
            "new generation starts its own identity-scoped sequence");
    require(queue.pop(record) && record.identity == next_generation
                && record.attempt_sequence == 1,
            "new identity cannot receive old-session records");
    require(queue.reset(kIdentity).status == ResetStatus::stale_generation,
            "older generation cannot reset a newer generation");

    require(queue.reset(third_generation).status == ResetStatus::reset,
            "same installation can advance generation after quiescence");
    require(queue.stats().attempts == 0 && queue.stats().accepted == 0,
            "successful reset starts per-identity counters cleanly");
    require(queue.reset(other_installation).status
                == ResetStatus::different_installation,
            "one queue object cannot switch to another installation");
    require(queue.reset(kIdentity).status == ResetStatus::stale_generation,
            "A-to-B-to-A cannot reuse an old identity or sequence");

    // A different installation gets a fresh queue object, rather than a
    // reset that could reintroduce an old identity/sequence pair.
    OwnedByteQueue reconstructed(other_installation);
    require(reconstructed.push(other_installation, &value, 1).accepted(),
            "new queue object accepts a different installation");
    require(reconstructed.pop(record) && record.identity == other_installation
                && record.attempt_sequence == 1,
            "reconstructed queue starts its own identity-scoped sequence");
}

void test_inactive_queue() {
    OwnedByteQueue queue;
    const std::uint8_t value = 1;
    const auto result = queue.push(kIdentity, &value, 1);
    require(result.status == PushStatus::inactive && result.attempt_sequence == 0,
            "invalid initial identity leaves queue inactive");
    require(queue.stats().dropped_inactive == 1,
            "inactive push is explicitly accounted");
    require(queue.reset(kIdentity).succeeded(), "inactive queue can activate once");
}

void test_two_thread_checksum_order_and_accounting() {
    constexpr std::uint64_t kCount = 20000;
    constexpr std::size_t kPayloadSize = 128;
    const Identity identity{0xabcddcba12344321ULL, 11};
    OwnedByteQueue queue(identity);
    std::atomic<bool> producer_done{false};
    std::atomic<bool> bad{false};
    std::uint64_t producer_full = 0;

    std::thread producer([&] {
        std::array<std::uint8_t, kPayloadSize> payload{};
        std::uint64_t previous_sequence = 0;
        for (std::uint64_t index = 0; index < kCount; ++index) {
            std::memcpy(payload.data(), &index, sizeof(index));
            for (std::size_t byte = sizeof(index); byte < payload.size(); ++byte) {
                payload[byte] = static_cast<std::uint8_t>(
                    (index * 31U + byte * 17U + 0x5dU) & 0xffU);
            }
            for (;;) {
                const auto result = queue.push(identity, payload.data(), payload.size());
                if (result.status == PushStatus::full) {
                    ++producer_full;
                    std::this_thread::yield();
                    continue;
                }
                if (!result.accepted() || result.attempt_sequence <= previous_sequence) {
                    bad.store(true, std::memory_order_relaxed);
                }
                previous_sequence = result.attempt_sequence;
                break;
            }
        }
        producer_done.store(true, std::memory_order_release);
    });

    std::thread consumer([&] {
        Record record{};
        std::uint64_t expected_index = 0;
        std::uint64_t previous_sequence = 0;
        while (!producer_done.load(std::memory_order_acquire) || !queue.empty()) {
            if (!queue.pop(record)) {
                std::this_thread::yield();
                continue;
            }
            if (record.identity != identity || record.size != kPayloadSize
                || record.attempt_sequence <= previous_sequence) {
                bad.store(true, std::memory_order_relaxed);
            }
            previous_sequence = record.attempt_sequence;
            std::uint64_t index = 0;
            std::memcpy(&index, record.payload.data(), sizeof(index));
            if (index != expected_index) {
                bad.store(true, std::memory_order_relaxed);
            }
            for (std::size_t byte = sizeof(index); byte < record.size; ++byte) {
                const auto expected = static_cast<std::uint8_t>(
                    (index * 31U + byte * 17U + 0x5dU) & 0xffU);
                if (record.payload[byte] != expected) {
                    bad.store(true, std::memory_order_relaxed);
                    break;
                }
            }
            ++expected_index;
        }
        if (expected_index != kCount) {
            bad.store(true, std::memory_order_relaxed);
        }
    });

    producer.join();
    consumer.join();
    require(!bad.load(std::memory_order_relaxed),
            "SPSC payload checksum and FIFO order remain intact");

    const auto stats = queue.stats();
    require(stats.accepted == kCount && stats.popped == kCount
                && stats.queued == 0,
            "two-thread test has no lost or stranded records");
    require(stats.dropped_full == producer_full,
            "every producer retry is accounted as a full drop");
    require(stats.dropped_total() == producer_full,
            "no unclassified loss occurs in the SPSC run");
    require(stats.attempts == kCount + producer_full,
            "attempt count includes only accepted pushes and accounted retries");
    require(stats.last_attempt_sequence == stats.attempts,
            "last attempt sequence exposes all full gaps");
    require(!stats.consistent, "concurrent multi-field stats remain marked inconsistent");
}

} // namespace

int main() {
    test_owning_copy_and_order();
    test_capacity_full_gap_and_no_overwrite();
    test_invalid_and_oversize_inputs();
    test_identity_isolation_and_quiescent_reset();
    test_inactive_queue();
    test_two_thread_checksum_order_and_accounting();
    std::cout << "information_battle_buffer_tests: PASS\n";
    return 0;
}
