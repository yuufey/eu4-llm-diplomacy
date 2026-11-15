#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>

namespace information::mission_completion {

constexpr unsigned kMaxName = 256;
constexpr unsigned kMaxCompleted = 4096;
struct Name final { char text[kMaxName + 1]{}; unsigned length = 0; };

inline bool range(uintptr_t address, size_t bytes) noexcept {
    return address >= 0x10000 && bytes <= 4096 && address < UINT64_C(0x800000000000)
        && bytes <= UINT64_C(0x800000000000) - address;
}

inline bool valid(const Name& name) noexcept {
    if (!name.length || name.length > kMaxName || name.text[name.length]) return false;
    for (unsigned index = 0; index < name.length; ++index) {
        const auto byte = static_cast<unsigned char>(name.text[index]);
        if (byte < 0x20 || byte > 0x7e) return false;
    }
    return true;
}

inline bool equal(const Name& left, const Name& right) noexcept {
    return left.length == right.length && !std::memcmp(left.text, right.text, left.length);
}

template <typename Reader>
bool name(Reader& reader, uintptr_t address, Name& result) noexcept {
    result = {};
    unsigned char header[32]{};
    if (!range(address, sizeof(header)) || !reader.read(address, header, sizeof(header))) return false;
    uint64_t length = 0, capacity = 0;
    std::memcpy(&length, header + 16, 8);
    std::memcpy(&capacity, header + 24, 8);
    if (!length || length > kMaxName || capacity < length || capacity > 4096) return false;
    uintptr_t text = address;
    if (capacity < 16) {
        if (capacity != 15) return false;
    } else std::memcpy(&text, header, 8);
    if (!range(text, length + 1) || !reader.read(text, result.text, length + 1)) return false;
    result.length = static_cast<unsigned>(length);
    return valid(result);
}

template <typename Reader>
bool membership(Reader& reader, uintptr_t country, const Name& wanted, bool& found) noexcept {
    found = false;
    if (!valid(wanted) || !range(country, 0x20) || !range(country + 0x99a0, 8)) return false;
    uintptr_t sentinel = 0, node = 0;
    if (!reader.read(country + 0x99a0, &sentinel, 8) || !range(sentinel, 8)
        || !reader.read(sentinel, &node, 8)) return false;
    for (unsigned index = 0; index <= kMaxCompleted; ++index) {
        if (node == sentinel) return true;
        if (index == kMaxCompleted || !range(node, 24)) return false;
        unsigned char bytes[24]{};
        if (!reader.read(node, bytes, sizeof(bytes))) return false;
        uintptr_t definition = 0;
        std::memcpy(&definition, bytes + 16, 8);
        Name current{};
        if (!range(definition, 0x30) || !name(reader, definition + 0x10, current)) return false;
        if (equal(current, wanted)) { found = true; return true; }
        std::memcpy(&node, bytes, 8);
    }
    return false;
}

template <typename Reader>
bool definition_membership(Reader& reader, uintptr_t country, uintptr_t wanted, bool& found) noexcept {
    found = false;
    if (!range(wanted, 0x30) || !range(country, 0x20) || !range(country+0x99a0, 8)) return false;
    uintptr_t sentinel = 0, node = 0;
    if (!reader.read(country+0x99a0, &sentinel, 8) || !range(sentinel, 8)
        || !reader.read(sentinel, &node, 8)) return false;
    for (unsigned index = 0; index <= kMaxCompleted; ++index) {
        if (node == sentinel) return true;
        if (index == kMaxCompleted || !range(node, 24)) return false;
        unsigned char bytes[24]{};
        if (!reader.read(node, bytes, sizeof(bytes))) return false;
        uintptr_t definition = 0;
        std::memcpy(&definition, bytes+16, 8);
        if (definition == wanted) { found = true; return true; }
        std::memcpy(&node, bytes, 8);
    }
    return false;
}

} // namespace information::mission_completion
