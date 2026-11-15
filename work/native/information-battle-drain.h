#ifndef INFORMATION_BATTLE_DRAIN_H
#define INFORMATION_BATTLE_DRAIN_H

#include "information-battle-buffer.h"

#include <cstddef>
#include <cstdint>
#include <type_traits>

// A fixed-memory, at-least-once consumer wrapper for OwnedByteQueue.
//
// The wrapper owns the queue and one pending Record.  OwnedByteQueue::pop()
// releases its slot after copying; the wrapper therefore keeps that copy until
// the sink returns true.  A rejected sink call leaves the exact same identity,
// attempt_sequence and payload for the next drain() call.  A sink must be a
// non-throwing callable returning bool.  This makes the no-allocation drain
// path explicit: an exception cannot escape after a pop and accidentally lose
// the pending record.  A sink that has written externally and then returns
// false may be called again with the same record, so external sinks need a
// stable event ID (identity + attempt_sequence) for deduplication.  The
// wrapper itself performs no allocation; a sink remains free to allocate in
// its own implementation.
namespace information::battle {

constexpr std::size_t kBattleDrainMaxRecords = OwnedByteQueue::capacity;

static_assert(kBattleDrainMaxRecords <= 64,
              "battle drain budget must remain at most 64 records");

enum class DrainStatus : std::uint8_t {
    completed,
    no_work,
    budget_exhausted,
    sink_rejected,
    invalid_budget,
    reentrant
};

struct DrainResult final {
    // Every invocation of the sink, including a false return, consumes one
    // unit of the caller-provided budget.
    std::size_t sink_attempts = 0;
    std::size_t delivered = 0;
    DrainStatus status = DrainStatus::no_work;
    bool stopped_on_rejection = false;
    bool budget_exhausted = false;
    bool invalid_budget = false;
    bool pending_after = false;
};

namespace detail {

template <typename Sink, typename = void>
struct exact_nothrow_bool_sink : std::false_type {};

template <typename Sink>
struct exact_nothrow_bool_sink<
    Sink,
    std::void_t<std::invoke_result_t<Sink&, const Record&>>>
    : std::bool_constant<
          std::is_same_v<std::invoke_result_t<Sink&, const Record&>, bool>
          && std::is_nothrow_invocable_v<Sink&, const Record&>> {};

} // namespace detail

class OwnedBattleDrain final {
public:
    explicit OwnedBattleDrain(Identity identity = {}) noexcept
        : queue_(identity) {}

    OwnedBattleDrain(const OwnedBattleDrain&) = delete;
    OwnedBattleDrain& operator=(const OwnedBattleDrain&) = delete;
    OwnedBattleDrain(OwnedBattleDrain&&) = delete;
    OwnedBattleDrain& operator=(OwnedBattleDrain&&) = delete;

    // The producer-facing surface is deliberately limited to the wrapper;
    // callers cannot obtain or bypass the owned queue's reset discipline.
    PushResult push(Identity source, const void* bytes,
                    std::size_t size) noexcept {
        return queue_.push(source, bytes, size);
    }

    // A pending record has already left the underlying queue but has not been
    // acknowledged by the sink.  It makes reset non-quiescent even when the
    // underlying queue is empty.  A sink callback is also a non-quiescent
    // drain interval, so a recursive or callback-side reset is rejected.
    ResetResult reset(Identity next) noexcept {
        if (draining_ || pending_) {
            return {ResetStatus::not_quiescent};
        }
        return queue_.reset(next);
    }

    Stats stats() const noexcept { return queue_.stats(); }
    Identity identity() const noexcept { return queue_.identity(); }
    bool active() const noexcept { return queue_.active(); }
    bool has_pending() const noexcept { return pending_; }

    // Drain at most max_records sink attempts.  max_records > 64 is rejected
    // without popping or calling the sink.  max_records == 0 is valid and
    // performs no attempt.  Returning false stops this round immediately and
    // retains the pending copy for a later retry.
    template <typename Sink>
    DrainResult drain(Sink&& sink, std::size_t max_records) noexcept {
        using SinkType = std::remove_reference_t<Sink>;
        static_assert(detail::exact_nothrow_bool_sink<SinkType>::value,
                      "battle drain sink must be noexcept bool(const Record&)");

        DrainResult result{};
        if (draining_) {
            result.status = DrainStatus::reentrant;
            result.pending_after = pending_;
            return result;
        }
        if (max_records > kBattleDrainMaxRecords) {
            result.status = DrainStatus::invalid_budget;
            result.invalid_budget = true;
            result.pending_after = pending_;
            return result;
        }

        draining_ = true;
        while (result.sink_attempts < max_records) {
            if (!pending_) {
                if (!queue_.pop(pending_record_)) {
                    break;
                }
                pending_ = true;
            }

            ++result.sink_attempts;
            const Record& pending_view = pending_record_;
            if (!sink(pending_view)) {
                result.stopped_on_rejection = true;
                break;
            }

            pending_ = false;
            ++result.delivered;
        }

        draining_ = false;
        result.pending_after = pending_;
        const bool work_remaining = pending_ || !queue_.empty();
        result.budget_exhausted = work_remaining
            && !result.stopped_on_rejection
            && (max_records == 0 || result.sink_attempts == max_records);
        if (result.stopped_on_rejection) {
            result.status = DrainStatus::sink_rejected;
        } else if (result.budget_exhausted) {
            result.status = DrainStatus::budget_exhausted;
        } else if (result.sink_attempts == 0) {
            result.status = DrainStatus::no_work;
        } else {
            result.status = DrainStatus::completed;
        }
        return result;
    }

private:
    OwnedByteQueue queue_;
    Record pending_record_{};
    bool pending_ = false;
    // The consumer contract is single-threaded, so a plain flag is sufficient
    // and avoids adding synchronization or allocation to drain().
    bool draining_ = false;
};

} // namespace information::battle

#endif // INFORMATION_BATTLE_DRAIN_H
