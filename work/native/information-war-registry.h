#ifndef INFORMATION_WAR_REGISTRY_H
#define INFORMATION_WAR_REGISTRY_H

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <immintrin.h>
#include <optional>
#include <utility>

namespace information::war_registry {

constexpr unsigned kCapacity = 256;
struct Entry final {
    std::atomic<std::uintptr_t> native_reference{0};
    char public_id[30]{};
};
static_assert(sizeof(Entry) == 40);
static_assert(offsetof(Entry, native_reference) == 0 && offsetof(Entry, public_id) == 8);
static_assert(std::atomic<std::uintptr_t>::is_always_lock_free);

struct Snapshot final {
    std::uintptr_t native_reference = 0;
    char public_id[30]{};
    unsigned slot = 0, serial = 0;
};
struct RosterStamp final {
    std::uint64_t sequence=0;
    unsigned serial=0;
};
inline bool operator==(const RosterStamp& left,const RosterStamp& right) noexcept {
    return left.sequence==right.sequence && left.serial==right.serial;
}
enum class Announcement : unsigned char { stale, duplicate, fresh };

enum class BirthState : unsigned char { constructing, complete, retiring, retired, gap };
struct Birth final {
    std::uintptr_t reference = 0;
    std::uint64_t sequence = 0, actor = 0, recipient = 0;
    BirthState state = BirthState::gap;
};
struct Retirement final {
    Birth birth{};
    bool pending=false;
    Retirement() noexcept = default;
    explicit Retirement(Birth value) noexcept : birth(value),pending(true) {}
    Retirement(const Retirement&)=delete;
    Retirement& operator=(const Retirement&)=delete;
    Retirement(Retirement&& other) noexcept
        : birth(other.birth),pending(std::exchange(other.pending,false)) {}
};

class Registry final {
    Entry (&entries_)[kCapacity];
    unsigned& size_;
    Birth births_[kCapacity]{};
    unsigned serials_[kCapacity]{}, announced_[kCapacity]{};
    unsigned next_serial_ = 0;
    std::uint64_t sequence_ = 0;
    unsigned retirement_depth_ = 0;
    std::atomic<std::uint64_t>* revision_;
    mutable std::atomic_flag lock_ = ATOMIC_FLAG_INIT;

    struct Guard final {
        std::atomic_flag& lock;
        explicit Guard(std::atomic_flag& value) noexcept : lock(value) {
            while (lock.test_and_set(std::memory_order_acquire)) _mm_pause();
        }
        ~Guard() noexcept { lock.clear(std::memory_order_release); }
    };
    struct Mutation final {
        std::atomic<std::uint64_t>* revision;
        explicit Mutation(std::atomic<std::uint64_t>* value) noexcept : revision(value) {
            if (revision) revision->fetch_add(1,std::memory_order_acq_rel);
        }
        ~Mutation() noexcept {
            if (revision) revision->fetch_add(1,std::memory_order_release);
        }
    };
    Birth* find(std::uintptr_t reference) noexcept {
        for (auto& birth : births_) if (birth.reference == reference) return &birth;
        return nullptr;
    }
    bool registered(std::uintptr_t reference) const noexcept {
        for (unsigned index = 0; index < size_; ++index)
            if (entries_[index].native_reference == reference) return true;
        return false;
    }
    Birth* reserve(std::uintptr_t reference) noexcept {
        auto* slot=find(reference);
        if (slot) return slot;
        for (auto& value:births_) {
            if (!value.reference) return &value;
            if (value.state!=BirthState::constructing && value.state!=BirthState::retiring
                && !registered(value.reference) && (!slot || value.sequence<slot->sequence)) slot=&value;
        }
        return slot;
    }
    void retire_entries(std::uintptr_t reference) noexcept {
        for (unsigned index=0;index<size_;++index) {
            if (entries_[index].native_reference!=reference) continue;
            Mutation mutation(revision_);
            entries_[index].native_reference=0;
        }
    }
    Snapshot snapshot(unsigned index) const noexcept {
        Snapshot value{};
        value.native_reference=entries_[index].native_reference;
        std::memcpy(value.public_id,entries_[index].public_id,sizeof(value.public_id));
        value.slot=index;
        value.serial=serials_[index];
        return value;
    }
    bool matches(const Snapshot& value) const noexcept {
        return value.native_reference && value.slot<size_
            && serials_[value.slot]==value.serial
            && entries_[value.slot].native_reference==value.native_reference
            && !std::strcmp(entries_[value.slot].public_id,value.public_id);
    }
public:
    Registry(Entry (&entries)[kCapacity], unsigned& size,
             std::atomic<std::uint64_t>* revision=nullptr) noexcept
        : entries_(entries), size_(size), revision_(revision) {}

    std::optional<Snapshot> find_id(const char* public_id) noexcept {
        Guard guard(lock_);
        if (!public_id) return std::nullopt;
        for (unsigned index=0;index<size_;++index)
            if (entries_[index].native_reference
                && !std::strcmp(entries_[index].public_id,public_id)) return snapshot(index);
        return std::nullopt;
    }
    std::optional<Snapshot> find_reference(std::uintptr_t reference) noexcept {
        Guard guard(lock_);
        if (!reference) return std::nullopt;
        for (unsigned index=0;index<size_;++index)
            if (entries_[index].native_reference==reference) return snapshot(index);
        return std::nullopt;
    }
    bool current(const Snapshot& value) noexcept {
        Guard guard(lock_);
        return matches(value);
    }
    RosterStamp roster_stamp() const noexcept {
        Guard guard(lock_);
        return {sequence_,next_serial_};
    }
    std::optional<RosterStamp> reconcile_active(const std::uintptr_t* references,
        unsigned count,const RosterStamp& expected) noexcept {
        Guard guard(lock_);
        if ((count && !references) || retirement_depth_
            || !(expected==RosterStamp{sequence_,next_serial_})) return std::nullopt;
        for (unsigned index=0;index<size_;++index) {
            const std::uintptr_t reference=entries_[index].native_reference;
            if (!reference) continue;
            bool active=false;
            for (unsigned member=0;member<count;++member)
                if (references[member]==reference) { active=true; break; }
            if (active) continue;
            retire_entries(reference);
            auto* value=reserve(reference);
            ++sequence_;
            if (value && sequence_) *value={reference,sequence_,0,0,BirthState::retired};
        }
        return RosterStamp{sequence_,next_serial_};
    }
    Announcement claim_announcement(const Snapshot& value) noexcept {
        Guard guard(lock_);
        if (!matches(value)) return Announcement::stale;
        if (announced_[value.slot]==value.serial) return Announcement::duplicate;
        announced_[value.slot]=value.serial;
        return Announcement::fresh;
    }
    Retirement retire(std::uintptr_t reference) noexcept {
        Guard guard(lock_);
        if (!reference) return {};
        retire_entries(reference);
        auto* value=reserve(reference);
        ++sequence_;
        ++retirement_depth_;
        const Birth token{reference,sequence_,0,0,BirthState::retiring};
        if (value && sequence_) *value=token;
        return Retirement{token};
    }
    bool complete_retirement(Retirement& retirement) noexcept {
        Guard guard(lock_);
        if (!retirement.pending) return false;
        retirement.pending=false;
        --retirement_depth_;
        ++sequence_;
        const auto& token=retirement.birth;
        auto* value=find(token.reference);
        if (!value || value->sequence!=token.sequence || value->state!=BirthState::retiring) return false;
        value->state=BirthState::retired;
        return true;
    }

    std::uint64_t sequence() const noexcept {
        Guard guard(lock_);
        return sequence_;
    }
    Birth birth(std::uintptr_t reference) noexcept {
        Guard guard(lock_);
        const auto* value = find(reference);
        return value ? *value : Birth{};
    }
    Birth begin(std::uintptr_t reference, std::uint64_t actor,
                std::uint64_t recipient, bool frame_thread) noexcept {
        Guard guard(lock_);
        if (!reference) return {};
        retire_entries(reference);
        auto* slot = reserve(reference);
        ++sequence_;
        if (!slot || !sequence_) return {};
        *slot = {reference, sequence_, actor, recipient,
                 frame_thread ? BirthState::constructing : BirthState::gap};
        return *slot;
    }
    bool complete(const Birth& token, bool verified) noexcept {
        Guard guard(lock_);
        auto* value = find(token.reference);
        if (!value || value->sequence != token.sequence) return false;
        value->state = verified && value->state == BirthState::constructing
            ? BirthState::complete : BirthState::gap;
        return value->state == BirthState::complete;
    }
    std::optional<Snapshot> register_war(std::uintptr_t reference, std::uint64_t creation,
        std::optional<std::uint64_t> verified_live_sequence=std::nullopt) noexcept {
        Guard guard(lock_);
        if (!reference || size_ > kCapacity) return std::nullopt;
        const auto* value = find(reference);
        if (value && value->state != BirthState::complete) return std::nullopt;
        unsigned index=0,available=kCapacity;
        for (;index<size_;++index) {
            if (entries_[index].native_reference==reference) return snapshot(index);
            if (!entries_[index].native_reference && available==kCapacity) available=index;
        }
        if ((!value && (!verified_live_sequence || *verified_live_sequence!=sequence_
                        || retirement_depth_)) || next_serial_==UINT32_MAX) return std::nullopt;
        if (available==kCapacity) available=size_;
        if (available==kCapacity) return std::nullopt;
        std::uint64_t epoch = creation + UINT64_C(0x9e3779b97f4a7c15);
        epoch = (epoch ^ (epoch >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
        epoch = (epoch ^ (epoch >> 27)) * UINT64_C(0x94d049bb133111eb);
        epoch ^= epoch >> 31;
        Mutation mutation(revision_);
        auto& entry = entries_[available];
        serials_[available]=++next_serial_;
        std::snprintf(entry.public_id, sizeof(entry.public_id), "war_%016llx_%08x",
            static_cast<unsigned long long>(epoch), next_serial_);
        entry.native_reference.store(reference, std::memory_order_release);
        if (available==size_) ++size_;
        return snapshot(available);
    }
};

} // namespace information::war_registry
#endif
