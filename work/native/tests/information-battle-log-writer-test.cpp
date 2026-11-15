#include "../information-battle-log-writer.h"

#include <windows.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <iostream>
#include <limits>
#include <string>

namespace {

using information::battle::BasicCheckedBattleLogWriter;
using information::battle::CheckedBattleLogWriter;
using information::battle::Identity;
using information::battle::LogStatus;
using information::battle::Record;
using information::battle::encode_jsonl;
using information::battle::kBattleLogHeaderBytes;
using information::battle::kBattleLogTailReadBytes;
using information::battle::max_required_capacity;

constexpr Identity kIdentity{0x1111222233334444ULL, 0xfeedbeefULL};
constexpr Identity kOtherIdentity{0x1111222233334444ULL, 0xfeedbef0ULL};
constexpr std::size_t kFakeCapacity = 128 * 1024;

void require(bool condition, const char* message) {
    if (!condition) {
        std::cerr << "FAIL: " << message << '\n';
        std::abort();
    }
}

struct FakeIo final {
    using Handle = int;

    enum class WriteMode : std::uint8_t { normal, fail, partial };

    static Handle invalid_handle() noexcept { return -1; }

    static bool valid(Handle handle) noexcept { return handle == 1; }

    std::array<std::uint8_t, kFakeCapacity> storage{};
    std::size_t size_bytes = 0;
    std::size_t position = 0;
    std::size_t write_calls = 0;
    std::size_t flush_calls = 0;
    std::size_t close_calls = 0;
    std::size_t lock_calls = 0;
    std::size_t unlock_calls = 0;
    bool opened = false;
    bool lock_held = false;
    bool lock_busy = false;
    bool unlock_fail = false;
    bool fail_open = false;
    bool fail_size = false;
    bool fail_seek = false;
    bool fail_set_eof = false;
    bool fail_close = false;
    std::size_t fail_flush_call = 0;
    std::size_t read_chunk = 0;
    WriteMode write_mode = WriteMode::normal;

    Handle open_exclusive(const wchar_t*) noexcept {
        if (fail_open || opened) {
            return invalid_handle();
        }
        opened = true;
        position = 0;
        return 1;
    }

    bool close(Handle handle) noexcept {
        ++close_calls;
        if (!valid(handle) || fail_close) {
            return false;
        }
        opened = false;
        lock_held = false;
        return true;
    }

    bool size(Handle handle, std::uint64_t& result) noexcept {
        if (!valid(handle) || !opened || fail_size) {
            return false;
        }
        result = static_cast<std::uint64_t>(size_bytes);
        return true;
    }

    bool seek(Handle handle, std::uint64_t offset) noexcept {
        if (!valid(handle) || !opened || fail_seek
            || offset > static_cast<std::uint64_t>(kFakeCapacity)) {
            return false;
        }
        position = static_cast<std::size_t>(offset);
        return true;
    }

    bool read(Handle handle, void* output, std::size_t requested,
              std::size_t& actual) noexcept {
        actual = 0;
        if (!valid(handle) || !opened || output == nullptr
            || position > size_bytes) {
            return false;
        }
        const std::size_t available = size_bytes - position;
        actual = requested < available ? requested : available;
        if (read_chunk != 0 && actual > read_chunk) {
            actual = read_chunk;
        }
        if (actual != 0) {
            std::memcpy(output, storage.data() + position, actual);
            position += actual;
        }
        return true;
    }

    bool write(Handle handle, const void* input, std::size_t requested,
               std::size_t& actual) noexcept {
        actual = 0;
        ++write_calls;
        if (!valid(handle) || !opened || input == nullptr
            || position > kFakeCapacity || requested > kFakeCapacity - position) {
            return false;
        }
        if (write_mode == WriteMode::fail) {
            return false;
        }
        actual = requested;
        if (write_mode == WriteMode::partial && requested != 0) {
            actual = requested - 1;
        }
        if (actual != 0) {
            std::memcpy(storage.data() + position, input, actual);
            position += actual;
            if (position > size_bytes) {
                size_bytes = position;
            }
        }
        return true;
    }

    bool set_eof(Handle handle) noexcept {
        if (!valid(handle) || !opened || fail_set_eof || position > kFakeCapacity) {
            return false;
        }
        size_bytes = position;
        return true;
    }

    bool flush(Handle handle) noexcept {
        ++flush_calls;
        if (!valid(handle) || !opened) {
            return false;
        }
        return fail_flush_call == 0 || flush_calls != fail_flush_call;
    }

    bool lock_exclusive(Handle handle) noexcept {
        ++lock_calls;
        if (!valid(handle) || !opened || lock_busy || lock_held) {
            return false;
        }
        lock_held = true;
        return true;
    }

    bool unlock(Handle handle) noexcept {
        ++unlock_calls;
        if (!valid(handle) || !opened || !lock_held || unlock_fail) {
            return false;
        }
        lock_held = false;
        return true;
    }
};

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
    const auto result = encode_jsonl(record, buffer.data(), buffer.size());
    require(result.succeeded(), "record encodes for test oracle");
    return std::string(buffer.data(), result.written_bytes);
}

std::string hex16(std::uint64_t value) {
    constexpr char hex[] = "0123456789abcdef";
    std::string result(16, '0');
    for (unsigned shift = 60; ; shift -= 4) {
        result[15U - (shift / 4U)] = hex[(value >> shift) & 0x0fU];
        if (shift == 0) {
            break;
        }
    }
    return result;
}

std::string expected_header(Identity identity) {
    return std::string("EU4_OWNED_BATTLE_WIRE_V1 ")
        + hex16(identity.installation) + " "
        + hex16(identity.generation) + "\n";
}

void test_fake_failure_seam() {
    const Record record = make_a();

    {
        FakeIo io;
        io.lock_busy = true;
        BasicCheckedBattleLogWriter<FakeIo> writer(io);
        require(!writer.open(L"fake-lock-busy", kIdentity),
                "busy fake lock refuses open without mutation");
        require(writer.status() == LogStatus::lock_busy
                    && io.size_bytes == 0 && !io.opened,
                "busy lock has explicit status and closes cleanly");
    }

    {
        FakeIo io;
        BasicCheckedBattleLogWriter<FakeIo> writer(io);
        require(writer.open(L"fake-append-lock-busy", kIdentity),
                "fake writer opens before append lock test");
        const std::size_t size_before = io.size_bytes;
        io.lock_busy = true;
        require(!writer.append(record),
                "busy fake lock refuses append without mutation");
        require(writer.status() == LogStatus::lock_busy
                    && io.size_bytes == size_before,
                "append lock busy leaves bytes unchanged");
        require(writer.close(), "append lock-busy fake closes");
    }

    {
        FakeIo io;
        BasicCheckedBattleLogWriter<FakeIo> writer(io);
        require(writer.open(L"fake-unlock-fault", kIdentity),
                "fake writer opens before unlock test");
        io.unlock_fail = true;
        require(!writer.append(record),
                "unlock failure refuses the file acknowledgement");
        require(writer.status() == LogStatus::unlock_failed
                    && writer.fault_latched() && !writer.ready()
                    && !io.opened,
                "unlock failure latches and closes the writer");
    }

    {
        FakeIo io;
        BasicCheckedBattleLogWriter<FakeIo> writer(io);
        require(writer.open(L"fake-partial", kIdentity),
                "fake writer opens for partial-write test");
        const std::size_t header_size = io.size_bytes;
        io.write_mode = FakeIo::WriteMode::partial;
        require(!writer.append(record), "partial write is rejected");
        require(writer.status() == LogStatus::partial_write,
                "partial write has explicit status");
        require(!writer.fault_latched() && io.size_bytes == header_size,
                "successful rollback restores the pre-write EOF");
        io.write_mode = FakeIo::WriteMode::normal;
        require(writer.append(record), "partial-write stream can retry");
        require(writer.close(), "partial-write fake closes");
    }

    {
        FakeIo io;
        BasicCheckedBattleLogWriter<FakeIo> writer(io);
        require(writer.open(L"fake-write-false", kIdentity),
                "fake writer opens for false-write test");
        const std::size_t header_size = io.size_bytes;
        io.write_mode = FakeIo::WriteMode::fail;
        require(!writer.append(record), "false write is rejected");
        require(writer.status() == LogStatus::write_failed,
                "zero-byte write has write_failed status");
        require(!writer.fault_latched() && io.size_bytes == header_size,
                "zero-byte write rolls back cleanly");
        io.write_mode = FakeIo::WriteMode::normal;
        require(writer.append(record), "false-write stream can retry");
        require(writer.close(), "false-write fake closes");
    }

    {
        FakeIo io;
        BasicCheckedBattleLogWriter<FakeIo> writer(io);
        require(writer.open(L"fake-flush-false", kIdentity),
                "fake writer opens for flush test");
        const std::size_t header_size = io.size_bytes;
        io.fail_flush_call = 2; // header flush was call 1.
        require(!writer.append(record), "flush failure is rejected");
        require(writer.status() == LogStatus::flush_failed,
                "flush failure has explicit status");
        require(!writer.fault_latched() && io.size_bytes == header_size,
                "flush failure rolls back after the failed flush");
        io.fail_flush_call = 0;
        require(writer.append(record), "flush-failure stream can retry");
        require(writer.close(), "flush-failure fake closes");
    }

    {
        FakeIo io;
        BasicCheckedBattleLogWriter<FakeIo> writer(io);
        require(writer.open(L"fake-rollback-fault", kIdentity),
                "fake writer opens for rollback-fault test");
        io.write_mode = FakeIo::WriteMode::partial;
        io.fail_set_eof = true;
        const std::size_t writes_before = io.write_calls;
        require(!writer.append(record), "rollback failure rejects append");
        require(writer.status() == LogStatus::rollback_fault
                    && writer.fault_latched(),
                "rollback failure latches the writer fault");
        io.write_mode = FakeIo::WriteMode::normal;
        require(!writer.append(record), "latched writer rejects later append");
        require(io.write_calls == writes_before + 1,
                "latched writer does not issue another write");
        require(writer.close(), "rollback-fault fake closes");
    }

    {
        FakeIo io;
        BasicCheckedBattleLogWriter<FakeIo> writer(io);
        require(writer.open(L"fake-identity", kIdentity),
                "fake writer opens for identity test");
        const std::size_t writes_before = io.write_calls;
        Record wrong = record;
        wrong.identity = kOtherIdentity;
        require(!writer.append(wrong), "wrong stream identity is rejected");
        require(writer.status() == LogStatus::identity_mismatch
                    && io.write_calls == writes_before,
                "identity rejection does not write bytes");
        require(writer.close(), "identity fake closes");
    }
}

void require_absent(const wchar_t* path) {
    const DWORD attributes = GetFileAttributesW(path);
    if (attributes != INVALID_FILE_ATTRIBUTES) {
        require(false, "test path must be absent before it is owned");
    }
    require(GetLastError() == ERROR_FILE_NOT_FOUND,
            "test path absence has a concrete not-found error");
}

void require_delete_owned(const wchar_t* path) {
    if (!DeleteFileW(path)) {
        require(GetLastError() == ERROR_FILE_NOT_FOUND,
                "owned temporary file deletes or is already absent");
    }
}

bool write_all(HANDLE handle, const char* data, std::size_t length) {
    while (length != 0) {
        const DWORD request = static_cast<DWORD>(
            length < static_cast<std::size_t>((std::numeric_limits<DWORD>::max)())
                ? length : static_cast<std::size_t>((std::numeric_limits<DWORD>::max)()));
        DWORD written = 0;
        if (!WriteFile(handle, data, request, &written, nullptr)
            || written == 0) {
            return false;
        }
        data += written;
        length -= written;
    }
    return true;
}

void create_file_with_bytes(const std::wstring& path, const std::string& bytes) {
    require_absent(path.c_str());
    HANDLE handle = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr,
                                CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
    require(handle != INVALID_HANDLE_VALUE, "test creates an owned file");
    const bool written = write_all(handle, bytes.data(), bytes.size());
    const bool flushed = written && FlushFileBuffers(handle) != FALSE;
    const bool closed = CloseHandle(handle) != FALSE;
    require(written && flushed && closed, "test writes and flushes owned file");
}

void append_file_bytes(const std::wstring& path, const std::string& bytes) {
    HANDLE handle = CreateFileW(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ,
                                nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL,
                                nullptr);
    require(handle != INVALID_HANDLE_VALUE, "test reopens its owned file");
    LARGE_INTEGER end{};
    const bool sought = SetFilePointerEx(handle, end, nullptr, FILE_END) != FALSE;
    const bool written = sought && write_all(handle, bytes.data(), bytes.size());
    const bool flushed = written && FlushFileBuffers(handle) != FALSE;
    const bool closed = CloseHandle(handle) != FALSE;
    require(sought && written && flushed && closed,
            "test appends and flushes owned bytes");
}

HANDLE open_shared_reader(const std::wstring& path) {
    HANDLE handle = CreateFileW(path.c_str(), GENERIC_READ,
                                FILE_SHARE_READ | FILE_SHARE_WRITE,
                                nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL,
                                nullptr);
    require(handle != INVALID_HANDLE_VALUE,
            "test opens a shared reader handle");
    return handle;
}

void lock_shared_reader(HANDLE handle) {
    OVERLAPPED overlapped{};
    require(LockFileEx(handle, LOCKFILE_FAIL_IMMEDIATELY,
                       0, MAXDWORD, MAXDWORD, &overlapped) != FALSE,
            "test obtains the shared reader lock");
}

void unlock_shared_reader(HANDLE handle) {
    OVERLAPPED overlapped{};
    require(UnlockFileEx(handle, 0, MAXDWORD, MAXDWORD, &overlapped) != FALSE,
            "test releases the shared reader lock");
}

std::string read_file_bytes(const std::wstring& path) {
    HANDLE handle = CreateFileW(path.c_str(), GENERIC_READ,
                                FILE_SHARE_READ | FILE_SHARE_WRITE
                                    | FILE_SHARE_DELETE,
                                nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL,
                                nullptr);
    require(handle != INVALID_HANDLE_VALUE, "test reads an owned file");
    LARGE_INTEGER size{};
    require(GetFileSizeEx(handle, &size) != FALSE && size.QuadPart >= 0
                && size.QuadPart <= 1024 * 1024,
            "test file size stays bounded");
    std::string result(static_cast<std::size_t>(size.QuadPart), '\0');
    std::size_t offset = 0;
    bool read_ok = true;
    while (offset < result.size()) {
        const DWORD request = static_cast<DWORD>(
            (result.size() - offset) < static_cast<std::size_t>((std::numeric_limits<DWORD>::max)())
                ? result.size() - offset
                : static_cast<std::size_t>((std::numeric_limits<DWORD>::max)()));
        DWORD actual = 0;
        if (!ReadFile(handle, result.data() + offset, request, &actual, nullptr)
            || actual == 0) {
            read_ok = false;
            break;
        }
        offset += actual;
    }
    const bool closed = CloseHandle(handle) != FALSE;
    require(read_ok && offset == result.size() && closed,
            "test reads the complete bounded file");
    return result;
}

void test_real_files(const wchar_t* final_path) {
    require_absent(final_path);
    const std::wstring final(final_path);
    const std::wstring foreign = final + L".foreign";
    const std::wstring tail = final + L".tail";
    const std::wstring unknown = final + L".unknown";
    const std::wstring first_partial = final + L".first-partial";
    const std::wstring reader_lock = final + L".reader-lock";
    require_absent(foreign.c_str());
    require_absent(tail.c_str());
    require_absent(unknown.c_str());
    require_absent(first_partial.c_str());
    require_absent(reader_lock.c_str());

    const Record a = make_a();
    const Record b = make_b();
    const std::string header = expected_header(kIdentity);

    {
        information::battle::Win32BattleLogIo io;
        CheckedBattleLogWriter writer(io);
        require(writer.open(final_path, kIdentity),
                "real writer creates the checked log");
        require(writer(a) && writer(a) && writer(b),
                "real writer appends two A attempts and a complete B payload");
        require(writer.close(), "real writer closes the checked log");
    }

    {
        information::battle::Win32BattleLogIo io;
        CheckedBattleLogWriter writer(io);
        require(writer.open(final_path, kIdentity),
                "real writer reopens a matching header");
        require(writer.close(), "real writer closes after matching reopen");
    }

    const std::string final_bytes = read_file_bytes(final);
    const std::string expected = header + encoded_line(a) + encoded_line(a)
        + encoded_line(b);
    require(final_bytes == expected,
            "real log has exact header and three raw JSONL frames");
    require(final_bytes.substr(0, header.size()) == header,
            "header is exact ASCII identity metadata");
    std::size_t newline_count = 0;
    for (const char byte : final_bytes) {
        if (byte == '\n') {
            ++newline_count;
        }
    }
    require(newline_count == 4,
            "header plus three frames have four LF boundaries");

    {
        information::battle::Win32BattleLogIo io;
        CheckedBattleLogWriter writer(io);
        require(writer.open(first_partial.c_str(), kIdentity),
                "first-partial file opens initially");
        require(writer.close(), "first-partial file closes at header boundary");
    }
    append_file_bytes(first_partial, "{\"first_frame_interrupted\"");
    {
        information::battle::Win32BattleLogIo io;
        CheckedBattleLogWriter writer(io);
        require(writer.open(first_partial.c_str(), kIdentity),
                "reopen truncates a partial first frame to the header");
        require(writer.close(), "first-partial repaired writer closes");
    }
    require(read_file_bytes(first_partial) == header,
            "partial first frame leaves the proven header boundary");
    require_delete_owned(first_partial.c_str());

    {
        information::battle::Win32BattleLogIo io;
        CheckedBattleLogWriter writer(io);
        require(writer.open(reader_lock.c_str(), kIdentity),
                "reader-lock file opens initially");
        require(writer.append(a), "reader-lock file receives a baseline frame");
        HANDLE reader = open_shared_reader(reader_lock);
        lock_shared_reader(reader);
        const std::string before = read_file_bytes(reader_lock);
        require(!writer.append(a),
                "exclusive append lock refuses an active shared reader");
        require(writer.status() == LogStatus::lock_busy,
                "active shared reader produces lock_busy");
        require(read_file_bytes(reader_lock) == before,
                "busy append does not mutate the file");
        unlock_shared_reader(reader);
        require(CloseHandle(reader) != FALSE,
                "shared reader handle closes after unlock");
        require(writer.append(a), "append resumes after reader unlock");
        require(writer.close(), "reader-lock writer closes");
    }
    require_delete_owned(reader_lock.c_str());

    create_file_with_bytes(
        foreign,
        "FOREIGN_HEADER____________________________________________________________\n");
    const std::string foreign_before = read_file_bytes(foreign);
    {
        information::battle::Win32BattleLogIo io;
        CheckedBattleLogWriter writer(io);
        require(!writer.open(foreign.c_str(), kIdentity),
                "foreign header is refused");
        require(writer.status() == LogStatus::header_mismatch,
                "foreign header has explicit mismatch status");
    }
    require(read_file_bytes(foreign) == foreign_before,
            "foreign file is unchanged after refusal");
    require_delete_owned(foreign.c_str());

    {
        information::battle::Win32BattleLogIo io;
        CheckedBattleLogWriter writer(io);
        require(writer.open(tail.c_str(), kIdentity),
                "tail-repair file opens initially");
        require(writer.append(a) && writer.close(),
                "tail-repair file receives a complete frame");
    }
    append_file_bytes(tail, "{\"incomplete\"");
    {
        information::battle::Win32BattleLogIo io;
        CheckedBattleLogWriter writer(io);
        require(writer.open(tail.c_str(), kIdentity),
                "reopen repairs an incomplete trailing fragment");
        require(writer.close(), "tail-repair writer closes");
    }
    require(read_file_bytes(tail) == header + encoded_line(a),
            "tail repair truncates only bytes after the last LF");
    require_delete_owned(tail.c_str());

    {
        information::battle::Win32BattleLogIo io;
        CheckedBattleLogWriter writer(io);
        require(writer.open(unknown.c_str(), kIdentity),
                "tail-boundary file opens initially");
        require(writer.append(a) && writer.close(),
                "tail-boundary file receives a complete frame");
    }
    append_file_bytes(unknown,
                      std::string(kBattleLogTailReadBytes, 'x'));
    const std::string unknown_before = read_file_bytes(unknown);
    {
        information::battle::Win32BattleLogIo io;
        CheckedBattleLogWriter writer(io);
        require(!writer.open(unknown.c_str(), kIdentity),
                "reopen refuses an unbounded trailing fragment");
        require(writer.status() == LogStatus::tail_boundary_unknown,
                "unbounded tail has explicit boundary status");
    }
    require(read_file_bytes(unknown) == unknown_before,
            "unbounded tail is not blindly truncated");
    require_delete_owned(unknown.c_str());
}

} // namespace

int wmain(int argc, wchar_t** argv) {
    require(argc == 2, "usage: information-battle-log-writer-test <log path>");
    test_fake_failure_seam();
    test_real_files(argv[1]);
    std::cout << "information-battle-log-writer-test: passed\n";
    return 0;
}
