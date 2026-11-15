#ifndef INFORMATION_BATTLE_BUFFER_H
#define INFORMATION_BATTLE_BUFFER_H

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>

// Fixed-memory transport seam for a future native battle-result hook.
//
// Contract:
//   * Exactly one producer thread calls push() and exactly one consumer thread
//     calls pop(). This is an SPSC queue; violating that contract is undefined
//     at the caller boundary.
//   * push() copies bytes before publishing the slot. No caller pointer is
//     retained and payload bytes are never interpreted here.
//   * reset() is quiescent-only: producer and consumer must be stopped and the
//     queue must be empty. A successful reset must install a new identity. A
//     same installation/generation pair cannot reset its sequence to zero.
//     The queue object is permanently bound to its first installation. A
//     different installation must construct a new queue object; reset() cannot
//     turn A into B and then back into A.
//   * sequence is strictly increasing for attempts belonging to one identity.
//     Rejected current-identity attempts consume a sequence and therefore make
//     a visible gap. A stale identity is rejected before sequence allocation.
//   * Stats are atomic fields but their multi-field snapshot is not a single
//     instant; Stats::consistent is therefore always false for snapshot().
//   * identity(), active(), and stats() are safe to read while push()/pop()
//     run because the active identity is immutable and counters are atomic,
//     but the identity/metadata tuple is coherent only at a quiescent boundary.
//     reset() must never run concurrently with any queue or metadata access.
//
// This header has no native/game permissions, hooks, allocation, or I/O.
namespace information::battle {

constexpr std::size_t kBattleBufferCapacity = 64;
constexpr std::size_t kBattleMaxPayloadBytes = 4096;

static_assert(kBattleBufferCapacity > 0, "battle buffer must have capacity");
static_assert(kBattleMaxPayloadBytes <= 4096, "battle payload must remain bounded");

struct Identity final {
    std::uint64_t installation = 0;
    std::uint64_t generation = 0;

    constexpr bool valid() const noexcept {
        return installation != 0 && generation != 0;
    }

    friend constexpr bool operator==(Identity left, Identity right) noexcept {
        return left.installation == right.installation
            && left.generation == right.generation;
    }

    friend constexpr bool operator!=(Identity left, Identity right) noexcept {
        return !(left == right);
    }
};

enum class PushStatus : std::uint8_t {
    accepted,
    inactive,
    stale_identity,
    empty_payload,
    null_payload,
    oversize,
    full,
    sequence_exhausted
};

struct PushResult final {
    PushStatus status = PushStatus::inactive;
    std::uint64_t attempt_sequence = 0;

    constexpr bool accepted() const noexcept {
        return status == PushStatus::accepted;
    }
};

enum class ResetStatus : std::uint8_t {
    reset,
    invalid_identity,
    not_quiescent,
    same_identity,
    stale_generation,
    different_installation
};

struct ResetResult final {
    ResetStatus status = ResetStatus::invalid_identity;

    constexpr bool succeeded() const noexcept {
        return status == ResetStatus::reset;
    }
};

struct Record final {
    Identity identity{};
    std::uint64_t attempt_sequence = 0;
    std::uint32_t size = 0;
    std::array<std::uint8_t, kBattleMaxPayloadBytes> payload{};
};

struct Stats final {
    Identity identity{};
    bool active = false;
    // A snapshot reads independent atomics and is not a linearizable tuple.
    bool consistent = false;
    std::uint64_t queued = 0;
    std::uint64_t attempts = 0;
    std::uint64_t accepted = 0;
    std::uint64_t popped = 0;
    std::uint64_t last_attempt_sequence = 0;
    std::uint64_t dropped_full = 0;
    std::uint64_t dropped_oversize = 0;
    std::uint64_t dropped_empty = 0;
    std::uint64_t dropped_invalid = 0;
    std::uint64_t dropped_stale_identity = 0;
    std::uint64_t dropped_inactive = 0;
    std::uint64_t dropped_sequence_exhausted = 0;

    std::uint64_t dropped_total() const noexcept {
        return dropped_full + dropped_oversize + dropped_empty
            + dropped_invalid + dropped_stale_identity + dropped_inactive
            + dropped_sequence_exhausted;
    }
};

class OwnedByteQueue final {
public:
    static constexpr std::size_t capacity = kBattleBufferCapacity;
    static constexpr std::size_t max_payload_bytes = kBattleMaxPayloadBytes;

    explicit OwnedByteQueue(Identity identity = {}) noexcept
        : identity_(identity), active_(identity.valid()),
          bound_installation_(identity.valid() ? identity.installation : 0) {}

    OwnedByteQueue(const OwnedByteQueue&) = delete;
    OwnedByteQueue& operator=(const OwnedByteQueue&) = delete;
    OwnedByteQueue(OwnedByteQueue&&) = delete;
    OwnedByteQueue& operator=(OwnedByteQueue&&) = delete;

    // The source identity must match the active identity exactly. The source
    // buffer is read only during this call and is copied before publication.
    PushResult push(Identity source, const void* bytes, std::size_t size) noexcept {
        attempts_.fetch_add(1, std::memory_order_relaxed);

        if (!active_) {
            dropped_inactive_.fetch_add(1, std::memory_order_relaxed);
            return {PushStatus::inactive, 0};
        }
        if (source != identity_) {
            dropped_stale_identity_.fetch_add(1, std::memory_order_relaxed);
            return {PushStatus::stale_identity, 0};
        }

        const std::uint64_t sequence = reserve_attempt();
        if (sequence == 0) {
            dropped_sequence_exhausted_.fetch_add(1, std::memory_order_relaxed);
            return {PushStatus::sequence_exhausted, 0};
        }
        if (size == 0) {
            dropped_empty_.fetch_add(1, std::memory_order_relaxed);
            return {PushStatus::empty_payload, sequence};
        }
        if (bytes == nullptr) {
            dropped_invalid_.fetch_add(1, std::memory_order_relaxed);
            return {PushStatus::null_payload, sequence};
        }
        if (size > max_payload_bytes) {
            dropped_oversize_.fetch_add(1, std::memory_order_relaxed);
            return {PushStatus::oversize, sequence};
        }

        // The producer owns head; acquire tail only after validating the
        // payload. The consumer releases tail after copying a slot out.
        const std::uint64_t head = head_.load(std::memory_order_relaxed);
        const std::uint64_t tail = tail_.load(std::memory_order_acquire);
        if (head - tail >= capacity) {
            dropped_full_.fetch_add(1, std::memory_order_relaxed);
            return {PushStatus::full, sequence};
        }

        Slot& slot = slots_[static_cast<std::size_t>(head % capacity)];
        std::memcpy(slot.payload, bytes, size);
        slot.size = static_cast<std::uint32_t>(size);
        slot.attempt_sequence = sequence;
        accepted_.fetch_add(1, std::memory_order_relaxed);
        // Release publishes the copied bytes and metadata to the consumer.
        head_.store(head + 1, std::memory_order_release);
        return {PushStatus::accepted, sequence};
    }

    // Returns false when the queue is empty. The output is fully owned by the
    // caller and is copied before this method releases the slot.
    bool pop(Record& output) noexcept {
        const std::uint64_t tail = tail_.load(std::memory_order_relaxed);
        const std::uint64_t head = head_.load(std::memory_order_acquire);
        if (tail == head) {
            return false;
        }

        const Slot& slot = slots_[static_cast<std::size_t>(tail % capacity)];
        output.identity = identity_;
        output.attempt_sequence = slot.attempt_sequence;
        output.size = slot.size;
        if (output.size > max_payload_bytes) {
            // This cannot be produced by push(), but do not expose an
            // out-of-bounds size if memory is corrupted.
            output.size = 0;
            std::memset(output.payload.data(), 0, output.payload.size());
        } else {
            if (output.size != 0) {
                std::memcpy(output.payload.data(), slot.payload, output.size);
            }
            if (output.size < max_payload_bytes) {
                std::memset(output.payload.data() + output.size, 0,
                            max_payload_bytes - output.size);
            }
        }
        // Release permits the producer to reuse this slot only after the
        // consumer has finished copying every byte.
        tail_.store(tail + 1, std::memory_order_release);
        popped_.fetch_add(1, std::memory_order_relaxed);
        return true;
    }

    // Successful reset requires a stopped producer/consumer and an empty
    // queue. Callers must not invoke reset concurrently with push/pop.
    ResetResult reset(Identity next) noexcept {
        if (!next.valid()) {
            return {ResetStatus::invalid_identity};
        }
        const std::uint64_t head = head_.load(std::memory_order_acquire);
        const std::uint64_t tail = tail_.load(std::memory_order_acquire);
        if (head != tail) {
            return {ResetStatus::not_quiescent};
        }
        if (bound_installation_ != 0
            && next.installation != bound_installation_) {
            return {ResetStatus::different_installation};
        }
        if (active_ && next == identity_) {
            return {ResetStatus::same_identity};
        }
        if (active_ && next.installation == identity_.installation
            && next.generation <= identity_.generation) {
            return {ResetStatus::stale_generation};
        }

        identity_ = next;
        active_ = true;
        if (bound_installation_ == 0) {
            bound_installation_ = next.installation;
        }
        head_.store(0, std::memory_order_relaxed);
        tail_.store(0, std::memory_order_relaxed);
        next_attempt_.store(1, std::memory_order_relaxed);
        last_attempt_sequence_.store(0, std::memory_order_relaxed);
        clear_counters();
        return {ResetStatus::reset};
    }

    Identity identity() const noexcept { return identity_; }
    bool active() const noexcept { return active_; }

    // These methods are race-free but, like stats(), are not a linearizable
    // multi-field view while a producer/consumer is running.
    bool empty() const noexcept {
        return head_.load(std::memory_order_acquire)
            == tail_.load(std::memory_order_acquire);
    }

    std::size_t size() const noexcept {
        const std::uint64_t head = head_.load(std::memory_order_acquire);
        const std::uint64_t tail = tail_.load(std::memory_order_acquire);
        if (head < tail) {
            return 0;
        }
        const std::uint64_t count = head - tail;
        return static_cast<std::size_t>(count > capacity ? capacity : count);
    }

    Stats stats() const noexcept {
        Stats result{};
        result.identity = identity_;
        result.active = active_;
        result.consistent = false;
        const std::uint64_t head = head_.load(std::memory_order_acquire);
        const std::uint64_t tail = tail_.load(std::memory_order_acquire);
        result.queued = head >= tail
            ? (head - tail > capacity ? capacity : head - tail) : 0;
        result.attempts = attempts_.load(std::memory_order_relaxed);
        result.accepted = accepted_.load(std::memory_order_relaxed);
        result.popped = popped_.load(std::memory_order_relaxed);
        result.last_attempt_sequence = last_attempt_sequence_.load(
            std::memory_order_relaxed);
        result.dropped_full = dropped_full_.load(std::memory_order_relaxed);
        result.dropped_oversize = dropped_oversize_.load(std::memory_order_relaxed);
        result.dropped_empty = dropped_empty_.load(std::memory_order_relaxed);
        result.dropped_invalid = dropped_invalid_.load(std::memory_order_relaxed);
        result.dropped_stale_identity = dropped_stale_identity_.load(
            std::memory_order_relaxed);
        result.dropped_inactive = dropped_inactive_.load(std::memory_order_relaxed);
        result.dropped_sequence_exhausted = dropped_sequence_exhausted_.load(
            std::memory_order_relaxed);
        return result;
    }

private:
    struct Slot final {
        std::uint64_t attempt_sequence = 0;
        std::uint32_t size = 0;
        std::uint8_t payload[max_payload_bytes]{};
    };

    std::uint64_t reserve_attempt() noexcept {
        std::uint64_t current = next_attempt_.load(std::memory_order_relaxed);
        while (current != 0) {
            const std::uint64_t next = current == std::numeric_limits<std::uint64_t>::max()
                ? 0 : current + 1;
            if (next_attempt_.compare_exchange_weak(
                    current, next, std::memory_order_relaxed,
                    std::memory_order_relaxed)) {
                last_attempt_sequence_.store(current, std::memory_order_relaxed);
                return current;
            }
        }
        return 0;
    }

    void clear_counters() noexcept {
        attempts_.store(0, std::memory_order_relaxed);
        accepted_.store(0, std::memory_order_relaxed);
        popped_.store(0, std::memory_order_relaxed);
        dropped_full_.store(0, std::memory_order_relaxed);
        dropped_oversize_.store(0, std::memory_order_relaxed);
        dropped_empty_.store(0, std::memory_order_relaxed);
        dropped_invalid_.store(0, std::memory_order_relaxed);
        dropped_stale_identity_.store(0, std::memory_order_relaxed);
        dropped_inactive_.store(0, std::memory_order_relaxed);
        dropped_sequence_exhausted_.store(0, std::memory_order_relaxed);
    }

    Identity identity_{};
    bool active_ = false;
    // A queue object cannot be reused across installations. This is set by a
    // valid constructor identity or by the first successful reset from an
    // inactive queue and is never cleared for the object's lifetime.
    std::uint64_t bound_installation_ = 0;
    alignas(64) std::atomic<std::uint64_t> head_{0};
    alignas(64) std::atomic<std::uint64_t> tail_{0};
    std::array<Slot, capacity> slots_{};

    std::atomic<std::uint64_t> next_attempt_{1};
    std::atomic<std::uint64_t> last_attempt_sequence_{0};
    std::atomic<std::uint64_t> attempts_{0};
    std::atomic<std::uint64_t> accepted_{0};
    std::atomic<std::uint64_t> popped_{0};
    std::atomic<std::uint64_t> dropped_full_{0};
    std::atomic<std::uint64_t> dropped_oversize_{0};
    std::atomic<std::uint64_t> dropped_empty_{0};
    std::atomic<std::uint64_t> dropped_invalid_{0};
    std::atomic<std::uint64_t> dropped_stale_identity_{0};
    std::atomic<std::uint64_t> dropped_inactive_{0};
    std::atomic<std::uint64_t> dropped_sequence_exhausted_{0};
};

} // namespace information::battle

#endif // INFORMATION_BATTLE_BUFFER_H
