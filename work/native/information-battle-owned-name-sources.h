#ifndef INFORMATION_BATTLE_OWNED_NAME_SOURCES_H
#define INFORMATION_BATTLE_OWNED_NAME_SOURCES_H

// Value-only copies of the two raw name inputs read by the battle title
// helper.  This component never invokes, destroys, or otherwise calls an
// engine object.  In particular, owner_name/global_name are source bytes only;
// this does not observe the final NAME or Line1 text.
#include "information-battle-owned-title-query.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <type_traits>
#include <utility>

namespace information::battle::owned_name_sources {

namespace title_query = information::battle::owned_title_query;
using Address = information::battle::owned_native_text::Address;
using GraphFingerprint = title_query::GraphFingerprint;
using String32 = title_query::String32;

constexpr std::size_t kMaxTextBytes = title_query::kMaxTextBytes;
constexpr std::size_t kMaxReadBytes = 128u * 1024u;
constexpr std::uint32_t kMaxReadCalls = 64u;

struct OwnedText final {
    std::uint32_t length = 0u;
    std::array<unsigned char, kMaxTextBytes + 1u> bytes{};
};

// Pointer-free copy of the raw source values.  bytes[length] is NUL; bytes
// after that terminator remain zero.  No final display name is inferred.
struct Snapshot final {
    std::uint64_t sequence = 0u;
    std::int32_t raw_date = 0;
    std::uint8_t kind = 0u;
    OwnedText owner_name{};
    OwnedText global_name{};
};

static_assert(std::is_standard_layout<OwnedText>::value,
              "OwnedText must remain a plain value type");
static_assert(std::is_trivially_copyable<OwnedText>::value,
              "OwnedText must remain trivially copyable");
static_assert(std::is_standard_layout<Snapshot>::value,
              "Snapshot must remain a plain value type");
static_assert(std::is_trivially_copyable<Snapshot>::value,
              "Snapshot must remain trivially copyable");

// These are source-acquisition failures only; there is no invoke/destroy
// phase in this reader.
enum class FailureStage : std::uint8_t {
    none = 0u,
    invalid_kind = 1u,
    invalid_sequence = 2u,
    invalid_date = 3u,
    invalid_base_or_image = 4u,
    invalid_combat = 5u,
    guard_before = 6u,
    source_before = 7u,
    guard_between = 8u,
    source_after = 9u,
    guard_after = 10u,
    source_changed = 11u,
};

struct Result final {
    FailureStage failed_stage = FailureStage::none;
    std::uint32_t read_calls = 0u;
    std::size_t bytes_read = 0u;
};

struct Workspace final {
    GraphFingerprint before{};
    GraphFingerprint after{};
};

template <typename Reader, typename = void>
struct reader_contract : std::false_type {};

template <typename Reader>
struct reader_contract<Reader, std::void_t<decltype(&Reader::read)>>
    : std::is_same<decltype(&Reader::read),
                   bool (Reader::*)(Address, unsigned char*,
                                     std::size_t) noexcept> {};

template <typename Guard, typename = void>
struct guard_contract : std::false_type {};

template <typename Guard>
struct guard_contract<Guard, std::void_t<decltype(&Guard::guard)>>
    : std::is_same<decltype(&Guard::guard), bool (Guard::*)() noexcept> {};

namespace detail {

struct AddressRange final {
    Address begin = 0u;
    Address end = 0u;
};

struct StorageRanges final {
    AddressRange workspace{};
    AddressRange output{};
    AddressRange result{};
};

inline bool object_range(const void* object, std::size_t size,
                         AddressRange& range) noexcept {
    if (object == nullptr) return false;
    range.begin = reinterpret_cast<Address>(object);
    return title_query::detail::checked_range(range.begin, size, range.end);
}

inline bool overlaps(const AddressRange& left,
                     const AddressRange& right) noexcept {
    return left.begin < right.end && right.begin < left.end;
}

inline bool independent_storage(Workspace& workspace, Snapshot& output,
                               Result& result,
                               StorageRanges& ranges) noexcept {
    if (!object_range(&workspace, sizeof(workspace), ranges.workspace)
            || !object_range(&output, sizeof(output), ranges.output)
            || !object_range(&result, sizeof(result), ranges.result)) {
        return false;
    }
    return !overlaps(ranges.workspace, ranges.output)
        && !overlaps(ranges.workspace, ranges.result)
        && !overlaps(ranges.output, ranges.result);
}

inline void clear_workspace(Workspace& workspace) noexcept {
    workspace.before = GraphFingerprint{};
    workspace.after = GraphFingerprint{};
}

inline void clear_snapshot(Snapshot& output) noexcept {
    output = Snapshot{};
}

inline void fail(Result& result, FailureStage stage) noexcept {
    if (result.failed_stage == FailureStage::none) {
        result.failed_stage = stage;
    }
}

template <typename Reader>
class BudgetReader final {
public:
    BudgetReader(Reader& reader, Result& result,
                 const StorageRanges& storage) noexcept
        : reader_(reader), result_(result), storage_(storage) {}

    bool read(Address address, unsigned char* destination,
              std::size_t size) noexcept {
        // Reserve before touching the source reader.  A Reader failure still
        // consumes this slot and its bytes, keeping both passes under one cap.
        if (remaining_calls_ == 0u || size > remaining_bytes_
                || size > std::numeric_limits<std::size_t>::max()
                              - result_.bytes_read) {
            return false;
        }
        --remaining_calls_;
        remaining_bytes_ -= size;
        ++result_.read_calls;
        result_.bytes_read += size;

        Address end = 0u;
        if (destination == nullptr
                || !title_query::detail::checked_range(address, size, end)) {
            return false;
        }
        const AddressRange source{address, end};
        if (overlaps(source, storage_.workspace)
                || overlaps(source, storage_.output)
                || overlaps(source, storage_.result)) {
            return false;
        }
        return reader_.read(address, destination, size);
    }

private:
    Reader& reader_;
    Result& result_;
    StorageRanges storage_{};
    std::uint32_t remaining_calls_ = kMaxReadCalls;
    std::size_t remaining_bytes_ = kMaxReadBytes;
};

inline void copy_text(const title_query::StringFingerprint& source,
                      OwnedText& destination) noexcept {
    destination.length = source.length;
    std::memcpy(destination.bytes.data(), source.bytes.data(),
                static_cast<std::size_t>(source.length) + 1u);
}

}  // namespace detail

// The caller's Guard owns all game-specific checks (executable identity,
// thread, date, and object lifetime).  This component only samples that
// caller-provided guard before, between, and after its two read-only passes.
template <typename Reader, typename Guard>
bool capture(Reader& reader, Guard& guard, Address base,
             std::size_t image_size, Address combat,
             std::uint64_t sequence, std::int32_t raw_date,
             std::uint8_t kind, Workspace& workspace, Snapshot& output,
             Result& result) noexcept {
    static_assert(reader_contract<Reader>::value,
                  "Reader::read must be bool(Address,unsigned char*,size_t) noexcept");
    static_assert(guard_contract<Guard>::value,
                  "Guard::guard must be bool() noexcept");

    // If these references alias, even writing a failure result could corrupt
    // one of the other caller-owned objects.  Detect that case before any
    // object is cleared or otherwise modified.
    detail::StorageRanges storage{};
    if (!detail::independent_storage(workspace, output, result, storage)) {
        return false;
    }

    result = Result{};
    detail::clear_snapshot(output);
    detail::clear_workspace(workspace);

    if (kind != 1u && kind != 2u) {
        detail::fail(result, FailureStage::invalid_kind);
        return false;
    }
    if (sequence == 0u) {
        detail::fail(result, FailureStage::invalid_sequence);
        return false;
    }
    if (raw_date < 0) {
        detail::fail(result, FailureStage::invalid_date);
        return false;
    }

    Address image_end = 0u;
    Address global_string = 0u;
    if (!title_query::detail::checked_range(base, image_size, image_end)
            || !title_query::detail::image_address(
                base, image_size, title_query::kGlobalStringRva,
                title_query::kStringObjectBytes, global_string)) {
        detail::fail(result, FailureStage::invalid_base_or_image);
        return false;
    }
    if (!title_query::detail::valid_pointer(combat)) {
        detail::fail(result, FailureStage::invalid_combat);
        return false;
    }

    if (!guard.guard()) {
        detail::fail(result, FailureStage::guard_before);
        return false;
    }

    detail::BudgetReader<Reader> budget_reader(reader, result, storage);
    if (!title_query::detail::read_graph(
            budget_reader, base, image_size, combat,
            static_cast<std::uint32_t>(kind), workspace.before)) {
        detail::fail(result, FailureStage::source_before);
        detail::clear_workspace(workspace);
        return false;
    }

    if (!guard.guard()) {
        detail::fail(result, FailureStage::guard_between);
        detail::clear_workspace(workspace);
        return false;
    }

    const bool second_read_ok = title_query::detail::read_graph(
        budget_reader, base, image_size, combat,
        static_cast<std::uint32_t>(kind), workspace.after);
    if (!second_read_ok) {
        detail::fail(result, FailureStage::source_after);
    }

    const bool guard_after_ok = guard.guard();
    if (!guard_after_ok) {
        detail::fail(result, FailureStage::guard_after);
    }
    if (!second_read_ok || !guard_after_ok) {
        detail::clear_workspace(workspace);
        return false;
    }

    if (!title_query::detail::same_graph(workspace.before,
                                         workspace.after)) {
        detail::fail(result, FailureStage::source_changed);
        detail::clear_workspace(workspace);
        return false;
    }

    output.sequence = sequence;
    output.raw_date = raw_date;
    output.kind = kind;
    detail::copy_text(workspace.before.owner_name, output.owner_name);
    detail::copy_text(workspace.before.global_name, output.global_name);
    detail::clear_workspace(workspace);
    return true;
}

}  // namespace information::battle::owned_name_sources

#endif  // INFORMATION_BATTLE_OWNED_NAME_SOURCES_H
