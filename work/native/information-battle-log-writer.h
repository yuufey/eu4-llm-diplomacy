#ifndef INFORMATION_BATTLE_LOG_WRITER_H
#define INFORMATION_BATTLE_LOG_WRITER_H

#ifndef _WIN32
#error "information-battle-log-writer.h requires Windows"
#endif

#include "information-battle-wire.h"

#include <windows.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>

// A single-consumer, checked Win32 file sink for OwnedBattleDrain.  The sink
// owns one exclusive writer handle and one stream identity.  It never claims
// SQLite durability or external/LLM consumption: true means only that this
// file accepted the complete wire line and FlushFileBuffers succeeded.
namespace information::battle {

constexpr std::size_t kBattleLogTailReadBytes = 16 * 1024;
constexpr char kBattleLogHeaderPrefix[] = "EU4_OWNED_BATTLE_WIRE_V1 ";
constexpr std::size_t kBattleLogHeaderBytes =
    (sizeof(kBattleLogHeaderPrefix) - 1) + 16 + 1 + 16 + 1;

static_assert(kBattleLogHeaderBytes < 128,
              "the stream header must remain a small fixed record");

enum class LogStatus : std::uint8_t {
    closed,
    ready,
    invalid_identity,
    null_path,
    already_open,
    open_failed,
    lock_busy,
    unlock_failed,
    size_failed,
    header_write_failed,
    header_read_failed,
    header_truncated,
    header_mismatch,
    tail_read_failed,
    tail_boundary_unknown,
    tail_repair_failed,
    identity_mismatch,
    encode_failed,
    seek_failed,
    write_failed,
    partial_write,
    flush_failed,
    rollback_fault,
    close_failed,
};

inline const char* log_status_name(LogStatus status) noexcept {
    switch (status) {
    case LogStatus::closed: return "closed";
    case LogStatus::ready: return "ready";
    case LogStatus::invalid_identity: return "invalid_identity";
    case LogStatus::null_path: return "null_path";
    case LogStatus::already_open: return "already_open";
    case LogStatus::open_failed: return "open_failed";
    case LogStatus::lock_busy: return "lock_busy";
    case LogStatus::unlock_failed: return "unlock_failed";
    case LogStatus::size_failed: return "size_failed";
    case LogStatus::header_write_failed: return "header_write_failed";
    case LogStatus::header_read_failed: return "header_read_failed";
    case LogStatus::header_truncated: return "header_truncated";
    case LogStatus::header_mismatch: return "header_mismatch";
    case LogStatus::tail_read_failed: return "tail_read_failed";
    case LogStatus::tail_boundary_unknown: return "tail_boundary_unknown";
    case LogStatus::tail_repair_failed: return "tail_repair_failed";
    case LogStatus::identity_mismatch: return "identity_mismatch";
    case LogStatus::encode_failed: return "encode_failed";
    case LogStatus::seek_failed: return "seek_failed";
    case LogStatus::write_failed: return "write_failed";
    case LogStatus::partial_write: return "partial_write";
    case LogStatus::flush_failed: return "flush_failed";
    case LogStatus::rollback_fault: return "rollback_fault";
    case LogStatus::close_failed: return "close_failed";
    }
    return "unknown";
}

// The default implementation is deliberately a very small Win32 seam.  The
// writer template below accepts a fake with the same methods for deterministic
// failure tests without changing the production path.
struct Win32BattleLogIo final {
    using Handle = HANDLE;

    static Handle invalid_handle() noexcept { return INVALID_HANDLE_VALUE; }

    static bool valid(Handle handle) noexcept {
        return handle != nullptr && handle != INVALID_HANDLE_VALUE;
    }

    Handle open_exclusive(const wchar_t* path) noexcept {
        if (path == nullptr) {
            return invalid_handle();
        }
        return CreateFileW(path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ,
                           nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL,
                           nullptr);
    }

    bool close(Handle handle) noexcept {
        return valid(handle) && CloseHandle(handle) != FALSE;
    }

    bool size(Handle handle, std::uint64_t& result) noexcept {
        LARGE_INTEGER value{};
        if (!GetFileSizeEx(handle, &value) || value.QuadPart < 0) {
            return false;
        }
        result = static_cast<std::uint64_t>(value.QuadPart);
        return true;
    }

    bool seek(Handle handle, std::uint64_t offset) noexcept {
        if (offset > static_cast<std::uint64_t>(
                         (std::numeric_limits<LONGLONG>::max)())) {
            return false;
        }
        LARGE_INTEGER distance{};
        distance.QuadPart = static_cast<LONGLONG>(offset);
        return SetFilePointerEx(handle, distance, nullptr, FILE_BEGIN)
            != FALSE;
    }

    bool read(Handle handle, void* buffer, std::size_t requested,
              std::size_t& actual) noexcept {
        actual = 0;
        if (requested > static_cast<std::size_t>((std::numeric_limits<DWORD>::max)())) {
            return false;
        }
        DWORD count = 0;
        if (!ReadFile(handle, buffer, static_cast<DWORD>(requested), &count,
                      nullptr)) {
            return false;
        }
        actual = static_cast<std::size_t>(count);
        return true;
    }

    bool write(Handle handle, const void* buffer, std::size_t requested,
               std::size_t& actual) noexcept {
        actual = 0;
        if (requested > static_cast<std::size_t>((std::numeric_limits<DWORD>::max)())) {
            return false;
        }
        DWORD count = 0;
        if (!WriteFile(handle, buffer, static_cast<DWORD>(requested), &count,
                       nullptr)) {
            actual = static_cast<std::size_t>(count);
            return false;
        }
        actual = static_cast<std::size_t>(count);
        return true;
    }

    bool set_eof(Handle handle) noexcept {
        return SetEndOfFile(handle) != FALSE;
    }

    bool flush(Handle handle) noexcept {
        return FlushFileBuffers(handle) != FALSE;
    }

    bool lock_exclusive(Handle handle) noexcept {
        OVERLAPPED overlapped{};
        return LockFileEx(handle, LOCKFILE_EXCLUSIVE_LOCK
                                   | LOCKFILE_FAIL_IMMEDIATELY,
                          0, MAXDWORD, MAXDWORD, &overlapped) != FALSE;
    }

    bool unlock(Handle handle) noexcept {
        OVERLAPPED overlapped{};
        return UnlockFileEx(handle, 0, MAXDWORD, MAXDWORD, &overlapped)
            != FALSE;
    }
};

template <typename Io>
class BasicCheckedBattleLogWriter final {
public:
    using Handle = typename Io::Handle;

    explicit BasicCheckedBattleLogWriter(Io& io) noexcept
        : io_(&io), handle_(Io::invalid_handle()) {}

    BasicCheckedBattleLogWriter(const BasicCheckedBattleLogWriter&) = delete;
    BasicCheckedBattleLogWriter& operator=(
        const BasicCheckedBattleLogWriter&) = delete;
    BasicCheckedBattleLogWriter(BasicCheckedBattleLogWriter&&) = delete;
    BasicCheckedBattleLogWriter& operator=(BasicCheckedBattleLogWriter&&) = delete;

    ~BasicCheckedBattleLogWriter() noexcept {
        // Callers should close explicitly to observe close_failed.  Destruction
        // still closes an abandoned handle, without throwing.
        if (Io::valid(handle_)) {
            if (lock_held_) {
                (void)io_->unlock(handle_);
                lock_held_ = false;
            }
            (void)io_->close(handle_);
            handle_ = Io::invalid_handle();
        }
    }

    bool open(const wchar_t* path, Identity identity) noexcept {
        if (Io::valid(handle_)) {
            status_ = LogStatus::already_open;
            return false;
        }
        if (path == nullptr) {
            status_ = LogStatus::null_path;
            return false;
        }
        if (!identity.valid()) {
            status_ = LogStatus::invalid_identity;
            return false;
        }

        identity_ = identity;
        fault_latched_ = false;
        handle_ = io_->open_exclusive(path);
        if (!Io::valid(handle_)) {
            status_ = LogStatus::open_failed;
            return false;
        }
        if (!io_->lock_exclusive(handle_)) {
            return abort_open(LogStatus::lock_busy);
        }
        lock_held_ = true;

        std::uint64_t file_size = 0;
        if (!io_->size(handle_, file_size)) {
            return abort_open(LogStatus::size_failed);
        }

        if (file_size == 0) {
            std::array<char, kBattleLogHeaderBytes> header{};
            const std::size_t header_size = make_header(header.data());
            if (!write_full(header.data(), header_size)) {
                const LogStatus primary = status_;
                if (!rollback_to(0)) {
                    return abort_open(LogStatus::rollback_fault);
                }
                return abort_open(primary);
            }
            if (!io_->flush(handle_)) {
                if (!rollback_to(0)) {
                    return abort_open(LogStatus::rollback_fault);
                }
                return abort_open(LogStatus::flush_failed);
            }
            if (!seek_end()) {
                return abort_open(LogStatus::seek_failed);
            }
            return release_lock(LogStatus::ready);
        }

        if (file_size < kBattleLogHeaderBytes) {
            return abort_open(LogStatus::header_truncated);
        }
        std::array<char, kBattleLogHeaderBytes> expected{};
        std::array<char, kBattleLogHeaderBytes> actual{};
        (void)make_header(expected.data());
        if (!read_at(0, actual.data(), actual.size())) {
            return abort_open(LogStatus::header_read_failed);
        }
        if (std::memcmp(expected.data(), actual.data(), actual.size()) != 0) {
            return abort_open(LogStatus::header_mismatch);
        }

        if (!repair_trailing_fragment(file_size)) {
            const LogStatus failure = status_;
            return abort_open(failure);
        }
        if (!seek_end()) {
            return abort_open(LogStatus::seek_failed);
        }
        return release_lock(LogStatus::ready);
    }

    bool append(const Record& record) noexcept {
        if (!Io::valid(handle_)) {
            status_ = LogStatus::closed;
            return false;
        }
        if (fault_latched_) {
            status_ = LogStatus::rollback_fault;
            return false;
        }
        if (record.identity != identity_) {
            status_ = LogStatus::identity_mismatch;
            return false;
        }

        std::array<char, kBattleWireMaxCapacity> wire{};
        const WireResult encoded = encode_jsonl(record, wire.data(), wire.size());
        if (!encoded.succeeded()) {
            status_ = LogStatus::encode_failed;
            return false;
        }

        if (!io_->lock_exclusive(handle_)) {
            status_ = LogStatus::lock_busy;
            return false;
        }
        lock_held_ = true;

        std::uint64_t eof = 0;
        if (!io_->size(handle_, eof) || !io_->seek(handle_, eof)) {
            (void)release_lock(LogStatus::seek_failed);
            return false;
        }
        std::size_t written = 0;
        if (!io_->write(handle_, wire.data(), encoded.written_bytes, written)
            || written != encoded.written_bytes) {
            const LogStatus primary = written == 0
                ? LogStatus::write_failed : LogStatus::partial_write;
            if (!rollback_to(eof)) {
                (void)release_lock(LogStatus::rollback_fault);
                return false;
            }
            (void)release_lock(primary);
            return false;
        }
        if (!io_->flush(handle_)) {
            if (!rollback_to(eof)) {
                (void)release_lock(LogStatus::rollback_fault);
                return false;
            }
            (void)release_lock(LogStatus::flush_failed);
            return false;
        }
        return release_lock(LogStatus::ready);
    }

    // This is the drain-compatible sink surface.  It is intentionally a
    // thin alias for append(): a true result acknowledges only the checked
    // file write and flush performed by this object.
    bool operator()(const Record& record) noexcept { return append(record); }

    bool close() noexcept {
        if (!Io::valid(handle_)) {
            status_ = LogStatus::closed;
            return true;
        }
        if (lock_held_) {
            if (!io_->unlock(handle_)) {
                lock_held_ = false;
                fault_latched_ = true;
                (void)io_->close(handle_);
                handle_ = Io::invalid_handle();
                status_ = LogStatus::unlock_failed;
                return false;
            }
            lock_held_ = false;
        }
        const bool closed = io_->close(handle_);
        handle_ = Io::invalid_handle();
        status_ = closed ? LogStatus::closed : LogStatus::close_failed;
        return closed;
    }

    Identity identity() const noexcept { return identity_; }
    LogStatus status() const noexcept { return status_; }
    bool ready() const noexcept {
        return Io::valid(handle_) && !fault_latched_;
    }
    bool fault_latched() const noexcept { return fault_latched_; }

private:
    static std::size_t append_fixed_hex(char* output, std::size_t cursor,
                                        std::uint64_t value) noexcept {
        constexpr char hex[] = "0123456789abcdef";
        for (unsigned shift = 60; ; shift -= 4) {
            output[cursor++] = hex[(value >> shift) & 0x0fU];
            if (shift == 0) {
                break;
            }
        }
        return cursor;
    }

    std::size_t make_header(char* output) const noexcept {
        std::size_t cursor = 0;
        for (std::size_t index = 0;
             index < sizeof(kBattleLogHeaderPrefix) - 1; ++index) {
            output[cursor++] = kBattleLogHeaderPrefix[index];
        }
        cursor = append_fixed_hex(output, cursor, identity_.installation);
        output[cursor++] = ' ';
        cursor = append_fixed_hex(output, cursor, identity_.generation);
        output[cursor++] = '\n';
        return cursor;
    }

    bool seek_end() noexcept {
        std::uint64_t ignored = 0;
        return io_->size(handle_, ignored) && io_->seek(handle_, ignored);
    }

    bool write_full(const void* bytes, std::size_t length) noexcept {
        std::size_t written = 0;
        if (!io_->write(handle_, bytes, length, written)) {
            status_ = written == 0 ? LogStatus::header_write_failed
                                   : LogStatus::partial_write;
            return false;
        }
        if (written != length) {
            status_ = LogStatus::partial_write;
            return false;
        }
        return true;
    }

    bool read_at(std::uint64_t offset, void* bytes, std::size_t length) noexcept {
        if (!io_->seek(handle_, offset)) {
            return false;
        }
        std::size_t completed = 0;
        while (completed < length) {
            std::size_t actual = 0;
            if (!io_->read(handle_, static_cast<char*>(bytes) + completed,
                           length - completed, actual)
                || actual == 0 || actual > length - completed) {
                return false;
            }
            completed += actual;
        }
        return true;
    }

    bool rollback_to(std::uint64_t eof) noexcept {
        if (!io_->seek(handle_, eof) || !io_->set_eof(handle_)
            || !io_->flush(handle_)) {
            fault_latched_ = true;
            status_ = LogStatus::rollback_fault;
            return false;
        }
        return true;
    }

    bool repair_trailing_fragment(std::uint64_t file_size) noexcept {
        const std::uint64_t data_start = kBattleLogHeaderBytes;
        if (file_size == data_start) {
            return true;
        }
        const std::uint64_t data_size = file_size - data_start;
        const std::size_t tail_size = static_cast<std::size_t>(
            data_size < kBattleLogTailReadBytes
                ? data_size : kBattleLogTailReadBytes);
        const std::uint64_t tail_start = file_size - tail_size;
        std::array<char, kBattleLogTailReadBytes> tail{};
        if (!read_at(tail_start, tail.data(), tail_size)) {
            status_ = LogStatus::tail_read_failed;
            return false;
        }

        std::size_t last_lf = tail_size;
        for (std::size_t index = tail_size; index != 0; --index) {
            if (tail[index - 1] == '\n') {
                last_lf = index - 1;
                break;
            }
        }
        if (last_lf == tail_size) {
            if (data_size > kBattleLogTailReadBytes) {
                // The last complete line boundary is outside the bounded
                // tail; refusing is safer than truncating an unproven prefix.
                status_ = LogStatus::tail_boundary_unknown;
                return false;
            }
            // With no LF in the first bounded data bytes, the fixed header is
            // the only proven stream boundary.  This covers a first frame
            // interrupted before its terminating LF.
            last_lf = static_cast<std::size_t>(-1);
        }
        std::uint64_t repaired_size = data_start;
        if (last_lf != static_cast<std::size_t>(-1)) {
            const std::uint64_t last_line_bytes =
                static_cast<std::uint64_t>(last_lf) + 1;
            if (tail_start > (std::numeric_limits<std::uint64_t>::max)()
                    - last_line_bytes) {
                status_ = LogStatus::tail_repair_failed;
                return false;
            }
            repaired_size = tail_start + last_line_bytes;
        }
        if (repaired_size < data_start || repaired_size > file_size) {
            status_ = LogStatus::tail_repair_failed;
            return false;
        }
        if (repaired_size < file_size) {
            if (!io_->seek(handle_, repaired_size)
                || !io_->set_eof(handle_)
                || !io_->flush(handle_)) {
                status_ = LogStatus::tail_repair_failed;
                return false;
            }
        }
        return true;
    }

    bool release_lock(LogStatus final_status) noexcept {
        if (!lock_held_) {
            status_ = final_status;
            return true;
        }
        if (io_->unlock(handle_)) {
            lock_held_ = false;
            status_ = final_status;
            return true;
        }
        // Closing a Win32 handle releases its byte-range locks.  The stream
        // is therefore closed and latched instead of leaving an ambiguous
        // lock or allowing a later append after an unconfirmed unlock.
        lock_held_ = false;
        fault_latched_ = true;
        (void)io_->close(handle_);
        handle_ = Io::invalid_handle();
        status_ = LogStatus::unlock_failed;
        return false;
    }

    bool abort_open(LogStatus status) noexcept {
        if (lock_held_) {
            if (!io_->unlock(handle_)) {
                lock_held_ = false;
                (void)io_->close(handle_);
                handle_ = Io::invalid_handle();
                status_ = LogStatus::unlock_failed;
                return false;
            }
            lock_held_ = false;
        }
        const bool closed = io_->close(handle_);
        handle_ = Io::invalid_handle();
        if (!closed && status != LogStatus::rollback_fault) {
            status_ = LogStatus::close_failed;
        } else {
            status_ = status;
        }
        return false;
    }

    Io* io_;
    Handle handle_;
    Identity identity_{};
    LogStatus status_ = LogStatus::closed;
    bool fault_latched_ = false;
    bool lock_held_ = false;
};

using CheckedBattleLogWriter = BasicCheckedBattleLogWriter<Win32BattleLogIo>;

} // namespace information::battle

#endif // INFORMATION_BATTLE_LOG_WRITER_H
