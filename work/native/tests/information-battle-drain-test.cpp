#include "../information-battle-drain.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <type_traits>
#include <utility>

namespace {

using information::battle::DrainResult;
using information::battle::DrainStatus;
using information::battle::Identity;
using information::battle::OwnedBattleDrain;
using information::battle::OwnedByteQueue;
using information::battle::PushStatus;
using information::battle::Record;
using information::battle::ResetResult;
using information::battle::ResetStatus;

constexpr Identity kIdentity{0x1111222233334444ULL, 1};

struct NoexceptSink final {
    bool operator()(const Record&) const noexcept { return true; }
};

struct ThrowingSink final {
    bool operator()(const Record&) const { return true; }
};

struct ConstOnlySink final {
    bool operator()(const Record&) const noexcept { return true; }
};

struct DualOverloadSink final {
    std::size_t const_calls = 0;
    std::size_t mutable_calls = 0;
    Record first{};
    Record second{};

    bool operator()(const Record& record) noexcept {
        if (const_calls == 0) {
            first = record;
        } else {
            second = record;
        }
        ++const_calls;
        return false;
    }

    bool operator()(Record& record) noexcept {
        ++mutable_calls;
        record.payload[0] ^= 0xff;
        return true;
    }
};

static_assert(std::is_nothrow_invocable_v<NoexceptSink&, const Record&>,
              "the positive sink fixture must be non-throwing");
static_assert(!std::is_nothrow_invocable_v<ThrowingSink&, const Record&>,
              "the negative sink fixture must be throwing in its type");
static_assert(std::is_same_v<
                  std::invoke_result_t<ConstOnlySink&, const Record&>, bool>,
              "the positive sink fixture returns exactly bool");
static_assert(noexcept(std::declval<OwnedBattleDrain&>().drain(
                  NoexceptSink{}, 1)),
              "a valid sink keeps the drain path noexcept");

void require(bool condition, const char* message) {
    if (!condition) {
        std::cerr << "FAIL: " << message << '\n';
        std::terminate();
    }
}

bool same_record(const Record& left, const Record& right) {
    if (left.identity != right.identity
        || left.attempt_sequence != right.attempt_sequence
        || left.size != right.size) {
        return false;
    }
    for (std::size_t index = 0; index < left.size; ++index) {
        if (left.payload[index] != right.payload[index]) {
            return false;
        }
    }
    return true;
}

void test_failed_retry_keeps_exact_record_and_order() {
    OwnedBattleDrain drain(kIdentity);
    const std::array<std::uint8_t, 3> first{{0x11, 0x22, 0x33}};
    const std::array<std::uint8_t, 3> second{{0x44, 0x55, 0x66}};
    require(drain.push(kIdentity, first.data(), first.size()).accepted(),
            "first record is accepted");
    require(drain.push(kIdentity, second.data(), second.size()).accepted(),
            "second record is accepted");

    Record rejected_copy{};
    Record retry_copy{};
    std::size_t calls = 0;
    const auto reject_once = [&](const Record& record) noexcept -> bool {
        if (calls++ == 0) {
            rejected_copy = record;
            return false;
        }
        retry_copy = record;
        return true;
    };

    const DrainResult rejected = drain.drain(reject_once, 4);
    require(rejected.sink_attempts == 1 && rejected.delivered == 0,
            "a rejected sink call consumes exactly one attempt");
    require(rejected.stopped_on_rejection && rejected.pending_after,
            "rejection stops the round and retains the pending copy");
    require(drain.has_pending(), "pending record is visible after rejection");
    require(drain.stats().popped == 1,
            "underlying queue is popped only once before retry");

    const DrainResult retried = drain.drain(reject_once, 1);
    require(retried.sink_attempts == 1 && retried.delivered == 1,
            "retry consumes one budget unit and delivers once");
    require(!retried.stopped_on_rejection && !retried.pending_after,
            "successful retry clears pending");
    require(same_record(rejected_copy, retry_copy),
            "retry has the same identity, sequence and payload");
    require(retry_copy.attempt_sequence == 1,
            "retry does not allocate a new sequence");
    require(retried.budget_exhausted,
            "a successful one-record round reports remaining queue work");

    Record delivered_second{};
    const auto accept_second = [&](const Record& record) noexcept -> bool {
        delivered_second = record;
        return true;
    };
    const DrainResult final = drain.drain(accept_second, 1);
    require(final.sink_attempts == 1 && final.delivered == 1,
            "next round attempts the second record");
    require(delivered_second.attempt_sequence == 2
                && delivered_second.payload[0] == second[0],
            "FIFO order is preserved after a failed first delivery");
    require(!drain.has_pending() && drain.stats().queued == 0,
            "successful drain leaves no pending or queued record");
}

void test_repeated_failure_and_external_write_duplicate() {
    OwnedBattleDrain drain(kIdentity);
    const std::array<std::uint8_t, 4> payload{{9, 8, 7, 6}};
    require(drain.push(kIdentity, payload.data(), payload.size()).accepted(),
            "record accepted for repeated failure test");

    std::array<Record, 2> observations{};
    std::size_t calls = 0;
    const auto write_then_reject = [&](const Record& record) noexcept -> bool {
        if (calls < observations.size()) {
            observations[calls] = record;
        }
        ++calls;
        return false;
    };
    require(drain.drain(write_then_reject, 1).stopped_on_rejection,
            "first external write can be unconfirmed");
    require(drain.drain(write_then_reject, 1).stopped_on_rejection,
            "second failed attempt remains stoppable");
    require(calls == 2 && same_record(observations[0], observations[1]),
            "repeated failures preserve the exact duplicate event ID and bytes");
    require(drain.has_pending(), "repeated failures do not lose pending data");

    Record confirmed{};
    const auto confirm = [&](const Record& record) noexcept -> bool {
        confirmed = record;
        return true;
    };
    require(drain.drain(confirm, 1).delivered == 1,
            "pending record eventually confirms");
    require(same_record(observations[0], confirmed),
            "confirmation is for the same record written by the sink");
}

void test_const_sink_view_and_retry_bytes() {
    OwnedBattleDrain drain(kIdentity);
    const std::array<std::uint8_t, 5> payload{{0x12, 0x34, 0x56, 0x78, 0x9a}};
    require(drain.push(kIdentity, payload.data(), payload.size()).accepted(),
            "const-view fixture accepted");

    DualOverloadSink sink;
    const DrainResult first = drain.drain(sink, 1);
    const DrainResult second = drain.drain(sink, 1);
    require(first.status == DrainStatus::sink_rejected
                && second.status == DrainStatus::sink_rejected,
            "const overload rejection remains visible on retry");
    require(sink.const_calls == 2 && sink.mutable_calls == 0,
            "mutable overload is never selected for a pending record");
    require(same_record(sink.first, sink.second),
            "const-view retry receives unchanged identity, sequence and bytes");
    require(sink.first.attempt_sequence == 1
                && sink.first.payload[0] == payload[0],
            "mutable overload cannot modify pending bytes");
    require(drain.has_pending(), "const-view rejection retains pending record");

    const auto confirm = [](const Record&) noexcept -> bool { return true; };
    require(drain.drain(confirm, 1).status == DrainStatus::completed,
            "const-view pending record can still be confirmed");
}

void test_reentrant_drain_and_reset_are_rejected() {
    const Identity next{kIdentity.installation, 2};
    OwnedBattleDrain drain(kIdentity);
    const std::uint8_t value = 0x4c;
    require(drain.push(kIdentity, &value, sizeof(value)).accepted(),
            "reentrancy fixture accepted");

    DrainResult nested{};
    ResetResult nested_reset{};
    std::size_t nested_sink_calls = 0;
    const auto outer_sink = [&](const Record&) noexcept -> bool {
        const auto nested_sink = [&](const Record&) noexcept -> bool {
            ++nested_sink_calls;
            return true;
        };
        nested = drain.drain(nested_sink, 1);
        nested_reset = drain.reset(next);
        return false;
    };
    const DrainResult outer = drain.drain(outer_sink, 1);
    require(outer.status == DrainStatus::sink_rejected
                && outer.stopped_on_rejection,
            "outer sink rejection remains the final round status");
    require(nested.status == DrainStatus::reentrant
                && nested.sink_attempts == 0
                && nested.delivered == 0
                && nested.pending_after,
            "recursive drain is rejected without a nested sink call");
    require(nested_sink_calls == 0,
            "reentrant drain never invokes the nested sink");
    require(nested_reset.status == ResetStatus::not_quiescent,
            "reset during drain is rejected as non-quiescent");
    require(drain.identity() == kIdentity && drain.has_pending(),
            "reentrancy attempts cannot change identity or clear pending");

    const auto confirm = [](const Record&) noexcept -> bool { return true; };
    require(drain.drain(confirm, 1).status == DrainStatus::completed,
            "record survives reentrant drain and reset attempts");
}

void test_budget_zero_and_upper_bound() {
    OwnedBattleDrain drain(kIdentity);
    const std::uint8_t value = 0xa1;
    require(drain.push(kIdentity, &value, sizeof(value)).accepted(),
            "budget fixture accepted");
    std::size_t calls = 0;
    const auto sink = [&](const Record&) noexcept -> bool {
        ++calls;
        return true;
    };

    const DrainResult zero = drain.drain(sink, 0);
    require(zero.sink_attempts == 0 && zero.delivered == 0
                && zero.budget_exhausted,
            "zero budget performs no sink call but reports retained work");
    require(calls == 0 && drain.stats().popped == 0,
            "zero budget does not pop a record");

    const DrainResult too_large = drain.drain(sink, OwnedByteQueue::capacity + 1);
    require(too_large.invalid_budget && too_large.sink_attempts == 0,
            "budget above the fixed 64-record limit is rejected");
    require(calls == 0 && drain.stats().popped == 0,
            "invalid budget does not call the sink or pop a record");

    const DrainResult accepted = drain.drain(sink, 1);
    require(accepted.sink_attempts == 1 && accepted.delivered == 1
                && calls == 1,
            "valid budget delivers the retained record");
}

void test_pending_blocks_reset_until_confirmation() {
    const Identity next{kIdentity.installation, 2};
    OwnedBattleDrain drain(kIdentity);
    const std::uint8_t value = 0x31;
    require(drain.push(kIdentity, &value, sizeof(value)).accepted(),
            "reset fixture accepted");

    const auto reject = [](const Record&) noexcept -> bool { return false; };
    require(drain.drain(reject, 1).stopped_on_rejection,
            "reset fixture has an unconfirmed pending record");
    require(drain.reset(next).status == ResetStatus::not_quiescent,
            "pending copy blocks reset even after queue pop");

    const auto accept = [](const Record&) noexcept -> bool { return true; };
    require(drain.drain(accept, 1).delivered == 1,
            "pending record can be confirmed before reset");
    require(drain.reset(next).status == ResetStatus::reset,
            "quiescent confirmed drain can advance generation");
    require(drain.push(kIdentity, &value, sizeof(value)).status
                == PushStatus::stale_identity,
            "old identity cannot bypass reset generation");
    require(drain.push(next, &value, sizeof(value)).accepted(),
            "new identity is accepted after reset");
    require(drain.drain(accept, 1).delivered == 1,
            "new generation record drains normally");
}

void test_full_queue_gap_and_recovery() {
    OwnedBattleDrain drain(kIdentity);
    for (std::size_t index = 0; index < OwnedByteQueue::capacity; ++index) {
        const auto value = static_cast<std::uint8_t>(index);
        const auto result = drain.push(kIdentity, &value, sizeof(value));
        require(result.status == PushStatus::accepted
                    && result.attempt_sequence == index + 1,
                "full queue fixture preserves accepted sequence");
    }
    const std::uint8_t rejected = 0xee;
    const auto full = drain.push(kIdentity, &rejected, sizeof(rejected));
    require(full.status == PushStatus::full
                && full.attempt_sequence == OwnedByteQueue::capacity + 1,
            "full queue rejection exposes a sequence gap");

    std::size_t count = 0;
    std::uint64_t previous = 0;
    const auto accept = [&](const Record& record) noexcept -> bool {
        require(record.attempt_sequence == previous + 1,
                "drain remains fair and FIFO across the full queue");
        require(record.payload[0] == static_cast<std::uint8_t>(count),
                "full queue rejection did not overwrite payload");
        previous = record.attempt_sequence;
        ++count;
        return true;
    };
    const DrainResult first = drain.drain(accept, OwnedByteQueue::capacity);
    require(first.sink_attempts == OwnedByteQueue::capacity
                && first.delivered == OwnedByteQueue::capacity
                && count == OwnedByteQueue::capacity,
            "bounded drain delivers every accepted full-queue record");

    const std::uint8_t after_gap = 0x5a;
    const auto after = drain.push(kIdentity, &after_gap, sizeof(after_gap));
    require(after.status == PushStatus::accepted
                && after.attempt_sequence == OwnedByteQueue::capacity + 2,
            "queue recovers after a visible full rejection gap");
    Record final{};
    const auto final_sink = [&](const Record& record) noexcept -> bool {
        final = record;
        return true;
    };
    require(drain.drain(final_sink, 1).delivered == 1
                && final.payload[0] == after_gap,
            "post-gap record is delivered without being skipped");
    const auto stats = drain.stats();
    require(stats.dropped_full == 1 && stats.accepted == OwnedByteQueue::capacity + 1
                && stats.popped == OwnedByteQueue::capacity + 1,
            "queue drop and accepted/pop accounting remain visible");
}

void test_maximum_payload_is_retained_and_copied() {
    OwnedBattleDrain drain(kIdentity);
    std::array<std::uint8_t, OwnedByteQueue::max_payload_bytes> payload{};
    for (std::size_t index = 0; index < payload.size(); ++index) {
        payload[index] = static_cast<std::uint8_t>((index * 17U) & 0xffU);
    }
    const auto expected = payload;
    require(drain.push(kIdentity, payload.data(), payload.size()).accepted(),
            "maximum payload is accepted");

    Record first{};
    Record second{};
    std::size_t calls = 0;
    const auto sink = [&](const Record& record) noexcept -> bool {
        if (calls++ == 0) {
            first = record;
            return false;
        }
        second = record;
        return true;
    };
    const DrainResult rejected = drain.drain(sink, 1);
    require(rejected.status == DrainStatus::sink_rejected
                && rejected.pending_after,
            "maximum payload remains pending after the first failure");
    payload.fill(0xee);

    const DrainResult confirmed = drain.drain(sink, 1);
    require(confirmed.status == DrainStatus::completed
                && confirmed.delivered == 1 && !drain.has_pending(),
            "maximum payload confirms and clears pending state");
    require(same_record(first, second)
                && first.identity == kIdentity
                && first.attempt_sequence == 1
                && first.size == expected.size(),
            "maximum payload retry keeps the same record identity");
    for (std::size_t index = 0; index < expected.size(); ++index) {
        require(first.payload[index] == expected[index]
                    && second.payload[index] == expected[index],
                "maximum payload bytes survive source mutation and retry");
    }
}

} // namespace

#ifdef INFORMATION_BATTLE_DRAIN_NEGATIVE_COMPILE

// This branch is compiled by the test command with the macro below.  It must
// fail at the drain() static assertion, proving the API rejects a throwing
// sink rather than merely checking a standalone type trait.
int main() {
    OwnedBattleDrain drain(kIdentity);
    ThrowingSink sink;
    (void)drain.drain(sink, 1);
    return 0;
}

#else

int main() {
    test_failed_retry_keeps_exact_record_and_order();
    test_repeated_failure_and_external_write_duplicate();
    test_const_sink_view_and_retry_bytes();
    test_reentrant_drain_and_reset_are_rejected();
    test_budget_zero_and_upper_bound();
    test_pending_blocks_reset_until_confirmation();
    test_full_queue_gap_and_recovery();
    test_maximum_payload_is_retained_and_copied();
    std::cout << "information_battle_drain_tests: PASS\n";
    return 0;
}

#endif
