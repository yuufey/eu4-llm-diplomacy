// Owned-file test of the actual production writer. No game attachment or hooks.
#define BRIDGE_DIAGNOSTIC_LOG_LIMIT_BYTES 512ULL
#include "../control-probe.cpp"
#include <fstream>
#include <iterator>
#include <string>
#include <thread>
#include <vector>

extern "C" void bridge_frame_stub() {}
extern "C" void bridge_response_stub() {}

int main(int argc, char** argv) {
    if (argc != 2) return 1;
    log_file = CreateFileA(argv[1], GENERIC_WRITE, FILE_SHARE_READ, nullptr,
                           CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (log_file == INVALID_HANDLE_VALUE) return 2;
    const char* expiry = "{\"event\":\"native_alliance_lifecycle\",\"kind\":\"destructor_return\",\"caller_return_rva\":\"0x2f04b9\",\"readable\":false}\n";
    const char* token_removal = "{\"event\":\"native_alliance_lifecycle\",\"kind\":\"destructor_return\",\"caller_return_rva\":\"0x3609ed\"}\n";
    const char* recheck = "{\"event\":\"native_alliance_lifecycle\",\"kind\":\"destructor_return\",\"caller_return_rva\":\"0x36087a\"}\n";
    const char* clear = "{\"event\":\"native_alliance_lifecycle\",\"kind\":\"destructor_return\",\"caller_return_rva\":\"0x360940\"}\n";
    const char* const proposal_ends[] = {expiry, token_removal, recheck, clear};
    const char* diagnostic = "{\"event\":\"native_alliance_lifecycle\",\"kind\":\"destructor_return\",\"caller_return_rva\":\"0x123456\"}\n";
    for (const char* record : proposal_ends) {
        if (is_budgeted_diagnostic(record)) return 3;
    }
    if (!is_budgeted_diagnostic(diagnostic)
        || !is_budgeted_diagnostic("{\"event\":\"native_alliance_lifecycle\",\"kind\":\"destructor\",\"caller_return_rva\":\"0x360940\"}\n")) return 9;
    line("{\"event\":\"diplomacy_observer_installed\"}\n");
    std::vector<std::thread> writers;
    for (int index = 0; index < 4; ++index) {
        writers.emplace_back([diagnostic]() {
            for (int row = 0; row < 1000; ++row) line(diagnostic);
        });
    }
    for (auto& writer : writers) writer.join();
    if (diagnostic_log_bytes > BRIDGE_DIAGNOSTIC_LOG_LIMIT_BYTES) return 4;
    SetLastError(1234);
    for (const char* record : proposal_ends) line(record);
    if (GetLastError() != 1234) return 5;
    line("{\"event\":\"native_alliance_inbound_offer\",\"business_result\":\"pending_observed\"}\n");
    line("{\"event\":\"control_console_result\",\"success\":true}\n");
    line("{\"event\":\"diplomacy_observer_health\",\"transport_fault\":true}\n");
    line("{\"event\":\"native_alliance_lifecycle_drop\",\"dropped\":3}\n");
    CloseHandle(log_file);
    log_file = INVALID_HANDLE_VALUE;
    std::ifstream input(argv[1], std::ios::binary);
    const std::string text((std::istreambuf_iterator<char>(input)), {});
    const std::string notice = "\"event\":\"diagnostic_log_budget_exhausted\"";
    const auto first = text.find(notice);
    if (first == std::string::npos || text.find(notice, first + 1) != std::string::npos) return 6;
    for (const char* record : proposal_ends) {
        if (text.find(record) == std::string::npos) return 10;
    }
    if (text.find("pending_observed") == std::string::npos
        || text.find("control_console_result") == std::string::npos
        || text.find("\"transport_fault\":true") == std::string::npos
        || text.find("\"dropped\":3") == std::string::npos) return 7;
    if (text.size() > 1600) return 8;
    std::printf("budget, concurrency, one notice, all proposal ends, business, health, drop and LastError passed\n");
    return 0;
}
