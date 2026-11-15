#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iterator>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
void* g_owned_reservation = nullptr;
const char* g_current_case = "setup";

LONG WINAPI owned_exception_filter(EXCEPTION_POINTERS* info) {
    char line[512]{};
    const auto code = info && info->ExceptionRecord ? info->ExceptionRecord->ExceptionCode : 0;
    const auto address = info && info->ExceptionRecord ?
        reinterpret_cast<std::uintptr_t>(info->ExceptionRecord->ExceptionAddress) : 0;
    const auto rip = info && info->ContextRecord ? info->ContextRecord->Rip : 0;
    const auto access = info && info->ExceptionRecord && info->ExceptionRecord->NumberParameters > 1 ?
        info->ExceptionRecord->ExceptionInformation[1] : 0;
    const int length = std::snprintf(line, sizeof(line),
        "{\"kind\":\"unhandled_exception\",\"code\":\"0x%08lx\",\"exception_address\":\"0x%llx\",\"rip\":\"0x%llx\",\"access_address\":\"0x%llx\",\"case\":\"%s\"}\n",
        static_cast<unsigned long>(code), static_cast<unsigned long long>(address),
        static_cast<unsigned long long>(rip), static_cast<unsigned long long>(access), g_current_case);
    DWORD written = 0;
    const HANDLE err = GetStdHandle(STD_ERROR_HANDLE);
    if (length > 0 && err && err != INVALID_HANDLE_VALUE)
        WriteFile(err, line, static_cast<DWORD>(length), &written, nullptr);
    if (g_owned_reservation) {
        const BOOL freed = VirtualFree(g_owned_reservation, 0, MEM_RELEASE);
        const int cleanup_length = std::snprintf(line, sizeof(line),
            "{\"kind\":\"exception_cleanup\",\"virtual_free_return\":%s}\n", freed ? "true" : "false");
        if (cleanup_length > 0 && err && err != INVALID_HANDLE_VALUE)
            WriteFile(err, line, static_cast<DWORD>(cleanup_length), &written, nullptr);
        if (freed) g_owned_reservation = nullptr;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}
}  // namespace

struct AgeCase {
    const char* label;
    std::int32_t birth_raw;
    std::int32_t current_raw;
    std::int32_t expected;
};

#include "age_cases.inc"

namespace {
constexpr std::uintptr_t kReserveBytes = 0x02341000;
constexpr std::uintptr_t kWorldRva = 0x0233e000;
constexpr std::uintptr_t kWorldGlobalCellRva = 0x0233fe58;
constexpr std::uintptr_t kWorldDateOffset = 0x1dd0;
constexpr std::uintptr_t kAgeGetterRva = 0x00a4e140;
constexpr std::uintptr_t kPersonBirthOffset = 0x70;
constexpr std::size_t kPersonBytes = 0x80;
constexpr std::size_t kPageBytes = 0x1000;

using AgeGetter = std::int32_t(__fastcall*)(const void* person);

std::vector<std::uint8_t> read_small_file(const char* path, std::size_t limit) {
    std::ifstream in(path, std::ios::binary);
    if (!in) throw std::runtime_error(std::string("open failed: ") + path);
    in.seekg(0, std::ios::end);
    const auto end = in.tellg();
    if (end < 0 || static_cast<std::uint64_t>(end) > limit)
        throw std::runtime_error(std::string("bounded file length rejected: ") + path);
    in.seekg(0, std::ios::beg);
    std::vector<std::uint8_t> bytes(static_cast<std::size_t>(end));
    if (!bytes.empty()) in.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    if (!in || static_cast<std::size_t>(in.gcount()) != bytes.size())
        throw std::runtime_error(std::string("short read: ") + path);
    return bytes;
}

void commit_page(std::uintptr_t base, std::uintptr_t rva) {
    if (VirtualAlloc(reinterpret_cast<void*>(base + rva), kPageBytes, MEM_COMMIT, PAGE_READWRITE) !=
        reinterpret_cast<void*>(base + rva))
        throw std::runtime_error("MEM_COMMIT failed");
}

void copy_segment(std::uintptr_t base, std::uintptr_t rva, const char* path,
                  std::size_t expected_bytes) {
    const auto bytes = read_small_file(path, expected_bytes);
    if (bytes.size() != expected_bytes) throw std::runtime_error(std::string("segment size mismatch: ") + path);
    std::memcpy(reinterpret_cast<void*>(base + rva), bytes.data(), bytes.size());
}

void protect_page(std::uintptr_t base, std::uintptr_t rva, DWORD protection) {
    DWORD previous = 0;
    if (!VirtualProtect(reinterpret_cast<void*>(base + rva), kPageBytes, protection, &previous))
        throw std::runtime_error("VirtualProtect failed");
}

void record_page(std::uintptr_t base, std::uintptr_t rva) {
    MEMORY_BASIC_INFORMATION mbi{};
    if (VirtualQuery(reinterpret_cast<void*>(base + rva), &mbi, sizeof(mbi)) != sizeof(mbi))
        throw std::runtime_error("VirtualQuery failed");
    const char* protection = "other";
    switch (mbi.Protect & 0xffu) {
        case PAGE_READWRITE: protection = "PAGE_READWRITE"; break;
        case PAGE_READONLY: protection = "PAGE_READONLY"; break;
        case PAGE_EXECUTE_READ: protection = "PAGE_EXECUTE_READ"; break;
        default: break;
    }
    std::printf("{\"kind\":\"page\",\"rva\":\"0x%08llx\",\"state\":\"%s\",\"protect\":\"%s\"}\n",
                static_cast<unsigned long long>(rva),
                mbi.State == MEM_COMMIT ? "MEM_COMMIT" : "not-committed", protection);
}

bool release_region(void* base) {
    return base == nullptr || VirtualFree(base, 0, MEM_RELEASE) != FALSE;
}

void write_cleanup(bool freed) {
    std::printf("{\"kind\":\"cleanup\",\"virtual_free_called\":true,\"virtual_free_return\":%s,\"owned_region_released\":%s}\n",
                freed ? "true" : "false", freed ? "true" : "false");
}
}  // namespace

int main() {
    SetUnhandledExceptionFilter(owned_exception_filter);
    SYSTEM_INFO system_info{};
    GetSystemInfo(&system_info);
    if (system_info.dwPageSize != kPageBytes) {
        std::printf("{\"kind\":\"setup\",\"ok\":false,\"reason\":\"unexpected_page_size\",\"page_size\":%lu}\n",
                    system_info.dwPageSize);
        return 2;
    }
    void* reservation = VirtualAlloc(nullptr, kReserveBytes, MEM_RESERVE, PAGE_NOACCESS);
    if (!reservation) {
        std::printf("{\"kind\":\"setup\",\"ok\":false,\"reason\":\"MEM_RESERVE_failed\",\"winerror\":%lu}\n",
                    GetLastError());
        return 2;
    }
    g_owned_reservation = reservation;
    const auto base = reinterpret_cast<std::uintptr_t>(reservation);
    std::size_t committed_pages = 0;
    bool completed = false;
    int return_code = 2;
    try {
        const std::set<std::uintptr_t> code_pages = {0x00a4e000, 0x000cf000, 0x014c8000};
        const std::set<std::uintptr_t> data_pages = {0x01c3a000, 0x0233e000, 0x0233f000};
        for (const auto page : code_pages) { commit_page(base, page); ++committed_pages; }
        for (const auto page : data_pages) { commit_page(base, page); ++committed_pages; }

        copy_segment(base, 0x00a4e140, "code/a4e140.bin", 0xd0);
        copy_segment(base, 0x000cfd70, "code/cfd70-to-cfe10.bin", 0xa0);
        copy_segment(base, 0x000cfe10, "code/cfe10.bin", 0x67);
        copy_segment(base, 0x014c8020, "code/14c8020.bin", 0x11f);
        copy_segment(base, 0x01c3a5c8, "code/month-table.bin", 48);

        const std::uintptr_t world = base + kWorldRva;
        std::memcpy(reinterpret_cast<void*>(base + kWorldGlobalCellRva), &world, sizeof(world));
        const std::uintptr_t current_date = world + kWorldDateOffset;

        for (const auto page : code_pages) protect_page(base, page, PAGE_EXECUTE_READ);
        protect_page(base, 0x01c3a000, PAGE_READONLY);
        if (!FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<void*>(base + 0x00a4e000), kPageBytes) ||
            !FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<void*>(base + 0x000cf000), kPageBytes) ||
            !FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<void*>(base + 0x014c8000), kPageBytes))
            throw std::runtime_error("FlushInstructionCache failed");

        std::printf("{\"kind\":\"setup\",\"ok\":true,\"owned_fixture_pid\":%lu,\"game_process_opened\":false,\"game_function_called\":false,\"reservation_base\":\"0x%llx\",\"reserve_bytes\":%llu,\"committed_bytes\":%llu,\"committed_pages\":%llu,\"global_cell_rva\":\"0x%08llx\",\"world_buffer_rva\":\"0x%08llx\",\"world_date_rva\":\"0x%08llx\",\"getter_rva\":\"0x%08llx\"}\n",
                    GetCurrentProcessId(), static_cast<unsigned long long>(base),
                    static_cast<unsigned long long>(kReserveBytes),
                    static_cast<unsigned long long>(committed_pages * kPageBytes),
                    static_cast<unsigned long long>(committed_pages),
                    static_cast<unsigned long long>(kWorldGlobalCellRva),
                    static_cast<unsigned long long>(kWorldRva),
                    static_cast<unsigned long long>(kWorldRva + kWorldDateOffset),
                    static_cast<unsigned long long>(kAgeGetterRva));
        std::fflush(stdout);
        for (const auto page : code_pages) { record_page(base, page); std::fflush(stdout); }
        for (const auto page : data_pages) { record_page(base, page); std::fflush(stdout); }

        const auto getter = reinterpret_cast<AgeGetter>(base + kAgeGetterRva);
        std::size_t passed = 0;
        for (const auto& item : kCases) {
            g_current_case = item.label;
            std::printf("{\"kind\":\"invoke\",\"label\":\"%s\"}\n", item.label);
            std::fflush(stdout);
            std::array<std::uint8_t, kPersonBytes> person{};
            std::memcpy(person.data() + kPersonBirthOffset, &item.birth_raw, sizeof(item.birth_raw));
            std::memcpy(reinterpret_cast<void*>(current_date), &item.current_raw, sizeof(item.current_raw));
            const auto actual = getter(person.data());
            const bool ok = actual == item.expected;
            passed += ok ? 1u : 0u;
            std::printf("{\"kind\":\"case\",\"label\":\"%s\",\"birth_raw\":%d,\"current_raw\":%d,\"expected\":%d,\"actual\":%d,\"pass\":%s}\n",
                        item.label, item.birth_raw, item.current_raw, item.expected, actual, ok ? "true" : "false");
            std::fflush(stdout);
        }
        const std::size_t failed = sizeof(kCases) / sizeof(kCases[0]) - passed;
        std::printf("{\"kind\":\"summary\",\"cases\":%llu,\"passed\":%llu,\"failed\":%llu,\"all_pairs_reported\":true}\n",
                    static_cast<unsigned long long>(sizeof(kCases) / sizeof(kCases[0])),
                    static_cast<unsigned long long>(passed), static_cast<unsigned long long>(failed));
        completed = failed == 0;
        return_code = completed ? 0 : 1;
    } catch (const std::exception& exc) {
        std::printf("{\"kind\":\"fixture_error\",\"message\":\"%s\"}\n", exc.what());
        completed = false;
        return_code = 2;
    }

    const bool freed = release_region(reservation);
    if (freed) g_owned_reservation = nullptr;
    write_cleanup(freed);
    if (!freed) return 3;
    return completed ? 0 : return_code;
}
