// Owned-process CRT reference cases; no game, target memory, or GUI access.
#include <cerrno>
#include <climits>
#include <clocale>
#include <cstdlib>
#include <iostream>
#include <string>
#include <utility>
#include <vector>

int main() {
    static_assert(sizeof(long) == 4, "the reference must use the Windows long32 model");
    static_assert(LONG_MAX == 2147483647L, "unexpected signed range");
    if (std::setlocale(LC_ALL, "C") == nullptr) return 2;
    const std::vector<std::pair<std::string, std::string>> cases{
        {"zero", "0"}, {"one", "1"}, {"six", "6"}, {"twelve", "12"},
        {"negative", "-1"}, {"plus", "+6"}, {"negative_zero", "-000"},
        {"leading_zeroes", "000012"}, {"spaces", "  3"}, {"tab", "\t4"},
        {"all_ascii_space", " \t\n\v\f\r-5"}, {"suffix", "6suffix"},
        {"trailing_space", "12 "}, {"hex_is_decimal_zero", "0x10"},
        {"no_digits", "abc"}, {"empty", ""}, {"space_only", " \t\r"},
        {"plus_only", "+"}, {"minus_only", "-"}, {"second_sign", "--1"},
        {"sign_space", "+ 2"}, {"maximum", "2147483647"},
        {"positive_signed_overflow", "2147483648"},
        {"positive_unsigned_edge", "4294967295"},
        {"positive_unsigned_overflow", "4294967296"},
        {"minimum", "-2147483648"}, {"negative_signed_overflow", "-2147483649"},
        {"negative_large", "-4294967296tail"},
        {"nul_first", std::string("\0junk", 5)},
        {"nul_after_digit", std::string("6\0junk", 6)},
        {"nul_after_space", std::string(" \t\0junk", 7)},
        {"ascii_control_prefix", std::string("\x01" "6", 2)},
        {"nonascii_after_digits", std::string("6\xa0", 2)},
        {"long_positive", std::string(8192, '9')},
        {"long_negative", std::string("-") + std::string(8191, '9')},
        {"long_zeroes", std::string(8191, '0') + "6"},
    };
    constexpr char digits[] = "0123456789abcdef";
    for (const auto& entry : cases) {
        errno = 0;
        char* end = nullptr;
        const long value = std::strtol(entry.second.c_str(), &end, 10);
        const bool clamped = errno == ERANGE;
        std::cout << entry.first << '\t';
        for (unsigned char ch : entry.second) {
            std::cout << digits[ch >> 4] << digits[ch & 15];
        }
        std::cout << '\t' << value << '\t' << (clamped ? 1 : 0) << '\t'
                  << (end == entry.second.c_str() ? 1 : 0) << '\n';
    }
    return std::cout.good() ? 0 : 3;
}
