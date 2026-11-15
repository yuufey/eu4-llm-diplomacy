#include "../support-role-state.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iostream>

namespace roles = bridge::support_role_state;

constexpr std::uintptr_t kMemoryBase = 0x20000u;
constexpr std::size_t kMemorySize = 0x5000u;
constexpr std::uintptr_t kActorCountry = 0x20000u;
constexpr std::uintptr_t kRecipientCountry = 0x21000u;
constexpr std::uintptr_t kActorOverlordCountry = 0x22000u;
constexpr std::uintptr_t kRecipientOverlordCountry = 0x23000u;
constexpr std::uintptr_t kChangedActorCountry = 0x24000u;

constexpr std::uint64_t kActorRef = UINT64_C(0x0100000000000001);
constexpr std::uint64_t kRecipientRef = UINT64_C(0x0200000000000002);
constexpr std::uint64_t kActorOverlordRef = UINT64_C(0x0300000000000003);
constexpr std::uint64_t kRecipientOverlordRef = UINT64_C(0x0400000000000004);

struct Checks {
    int passed = 0;
    int failed = 0;

    void expect(const char* name, bool actual, bool wanted = true) {
        if (actual == wanted) {
            ++passed;
            std::cout << "PASS " << name << "\n";
        } else {
            ++failed;
            std::cout << "FAIL " << name << " actual=" << (actual ? "true" : "false")
                      << " wanted=" << (wanted ? "true" : "false") << "\n";
        }
    }
};

struct MemoryReader {
    struct Resolution {
        std::uint64_t fullref = 0;
        std::uintptr_t country = 0;
    };

    std::array<unsigned char, kMemorySize> bytes{};
    std::array<Resolution, 8> resolutions{};
    std::size_t resolution_count = 0;
    std::size_t resolve_calls = 0;
    std::size_t read_calls = 0;
    std::size_t actor_resolve_calls = 0;
    std::uint64_t failed_fullref = 0;
    std::uintptr_t missing_read_address = 0;
    std::uintptr_t short_read_address = 0;
    std::uintptr_t changing_read_address = 0;
    unsigned changing_read_byte = 0;
    unsigned changing_read_count = 0;
    bool change_actor_pointer_after_first_resolve = false;

    void add_resolution(std::uint64_t fullref, std::uintptr_t country) {
        for (std::size_t index = 0; index < resolution_count; ++index) {
            if (resolutions[index].fullref == fullref) {
                resolutions[index].country = country;
                return;
            }
        }
        if (resolution_count < resolutions.size()) {
            resolutions[resolution_count++] = Resolution{fullref, country};
        }
    }

    bool resolve(std::uint64_t fullref, std::uintptr_t& country) noexcept {
        ++resolve_calls;
        if (fullref == failed_fullref) return false;

        if (fullref == kActorRef) {
            ++actor_resolve_calls;
            if (change_actor_pointer_after_first_resolve && actor_resolve_calls > 1) {
                country = kChangedActorCountry;
                return true;
            }
        }

        for (std::size_t index = 0; index < resolution_count; ++index) {
            if (resolutions[index].fullref == fullref) {
                country = resolutions[index].country;
                return true;
            }
        }
        return false;
    }

    bool read(std::uintptr_t address, void* output, std::size_t size) noexcept {
        ++read_calls;
        if (!output || address < kMemoryBase) return false;

        const auto offset = address - kMemoryBase;
        if (offset > bytes.size() || size > bytes.size() - offset) return false;
        if (address == missing_read_address) return false;

        auto* destination = static_cast<unsigned char*>(output);
        const auto* source = bytes.data() + static_cast<std::size_t>(offset);
        if (address == short_read_address) {
            if (size > 1u) std::memcpy(destination, source, size - 1u);
            return false;
        }

        std::memcpy(destination, source, size);
        if (address == changing_read_address) {
            ++changing_read_count;
            if (changing_read_count == 2u && changing_read_byte < size) {
                destination[changing_read_byte] ^= 1u;
            }
        }
        return true;
    }

    template <typename Value>
    void put(std::uintptr_t address, Value value) {
        const auto offset = address - kMemoryBase;
        if (offset <= bytes.size() && sizeof(value) <= bytes.size() - offset) {
            std::memcpy(bytes.data() + static_cast<std::size_t>(offset), &value, sizeof(value));
        }
    }

    void seed() {
        bytes.fill(0);
        resolution_count = 0;
        resolve_calls = 0;
        read_calls = 0;
        actor_resolve_calls = 0;
        failed_fullref = 0;
        missing_read_address = 0;
        short_read_address = 0;
        changing_read_address = 0;
        changing_read_byte = 0;
        changing_read_count = 0;
        change_actor_pointer_after_first_resolve = false;

        add_resolution(kActorRef, kActorCountry);
        add_resolution(kRecipientRef, kRecipientCountry);
        add_resolution(kActorOverlordRef, kActorOverlordCountry);
        add_resolution(kRecipientOverlordRef, kRecipientOverlordCountry);

        put(kActorCountry + 0x20u, kActorRef);
        put(kActorCountry + 0x18F0u, UINT64_C(0));
        put(kRecipientCountry + 0x20u, kRecipientRef);
        put(kRecipientCountry + 0x18F0u, UINT64_C(0));
        put(kActorOverlordCountry + 0x20u, kActorOverlordRef);
        put(kRecipientOverlordCountry + 0x20u, kRecipientOverlordRef);
    }
};

bool is_default(const roles::Snapshot& snapshot) {
    return !snapshot.readable && !snapshot.actor_is_subject && !snapshot.recipient_is_subject;
}

void expect_capture(Checks& checks, const char* name, MemoryReader& reader,
                    std::uint64_t actor, std::uint64_t recipient,
                    bool wanted_actor_subject, bool wanted_recipient_subject) {
    roles::Snapshot output{};
    const bool captured = roles::capture(reader, actor, recipient, output);
    checks.expect(name, captured && output.readable
                  && output.actor_is_subject == wanted_actor_subject
                  && output.recipient_is_subject == wanted_recipient_subject);
}

void expect_failure(Checks& checks, const char* name, MemoryReader& reader,
                    std::uint64_t actor = kActorRef,
                    std::uint64_t recipient = kRecipientRef) {
    roles::Snapshot output{true, true, true};
    const bool captured = roles::capture(reader, actor, recipient, output);
    checks.expect(name, !captured && is_default(output));
}

int main() {
    Checks checks;
    MemoryReader reader;

    reader.seed();
    reader.put(kActorCountry + 0x18F0u, kActorOverlordRef);
    expect_capture(checks, "actor-is-subject-recipient-independent", reader,
                   kActorRef, kRecipientRef, true, false);
    checks.expect("independent-role-read-count-is-bounded",
                  reader.resolve_calls == 5u && reader.read_calls == 8u);

    reader.seed();
    reader.put(kRecipientCountry + 0x18F0u, kRecipientOverlordRef);
    expect_capture(checks, "recipient-is-subject-actor-independent", reader,
                   kActorRef, kRecipientRef, false, true);

    reader.seed();
    reader.put(kActorCountry + 0x18F0u, UINT64_C(0x00FFFFFFFFFFFFFF));
    expect_capture(checks, "both-independent-high-byte-zero-means-no-overlord", reader,
                   kActorRef, kRecipientRef, false, false);
    checks.expect("independent-capture-has-fixed-endpoint-resolution-count",
                  reader.resolve_calls == 4u && reader.read_calls == 8u);

    reader.seed();
    reader.put(kActorCountry + 0x18F0u, kActorOverlordRef);
    reader.put(kRecipientCountry + 0x18F0u, kRecipientOverlordRef);
    expect_capture(checks, "both-endpoints-have-resolvable-overlords", reader,
                   kActorRef, kRecipientRef, true, true);
    checks.expect("two-subject-capture-has-bounded-resolution-count",
                  reader.resolve_calls == 6u && reader.read_calls == 8u);

    reader.seed();
    reader.missing_read_address = kActorCountry + 0x20u;
    expect_failure(checks, "missing-field-read-clears-output", reader);

    reader.seed();
    reader.short_read_address = kRecipientCountry + 0x18F0u;
    expect_failure(checks, "short-field-read-clears-output", reader);

    reader.seed();
    reader.add_resolution(kActorRef, 0x800000000000u);
    expect_failure(checks, "reject-pointer-at-user-space-upper-bound", reader);

    reader.seed();
    reader.add_resolution(kActorRef, kActorCountry + 1u);
    expect_failure(checks, "reject-unaligned-endpoint-pointer", reader);

    std::uintptr_t field = 0;
    checks.expect("reject-field-crossing-canonical-upper-bound",
                  !roles::detail::field_address(0x7FFFFFFFFFF8u, 0x20u, field));

    reader.seed();
    reader.put(kActorCountry + 0x18F0u, kActorRef);
    expect_failure(checks, "reject-self-overlord-reference", reader);

    reader.seed();
    reader.put(kActorCountry + 0x20u, kRecipientRef);
    expect_failure(checks, "reject-endpoint-fullref-mismatch", reader);

    reader.seed();
    reader.put(kActorCountry + 0x18F0u, kActorOverlordRef);
    reader.add_resolution(kActorOverlordRef, kActorCountry);
    expect_failure(checks, "reject-self-overlord", reader);

    reader.seed();
    reader.put(kActorCountry + 0x18F0u, kActorOverlordRef);
    reader.failed_fullref = kActorOverlordRef;
    expect_failure(checks, "reject-unresolvable-overlord", reader);

    reader.seed();
    reader.put(kActorCountry + 0x18F0u, kActorOverlordRef);
    reader.add_resolution(kActorOverlordRef, 0x22001u);
    expect_failure(checks, "reject-unaligned-overlord-pointer", reader);

    reader.seed();
    reader.put(kActorCountry + 0x18F0u, kActorOverlordRef);
    reader.changing_read_address = kActorCountry + 0x18F0u;
    reader.changing_read_byte = 7u;
    expect_failure(checks, "reject-second-pass-overlord-change", reader);

    reader.seed();
    reader.change_actor_pointer_after_first_resolve = true;
    expect_failure(checks, "reject-endpoint-pointer-change-between-passes", reader);
    checks.expect("pointer-change-detected-before-second-field-pass",
                  reader.resolve_calls == 4u && reader.read_calls == 4u);

    reader.seed();
    expect_failure(checks, "reject-zero-endpoint-reference", reader, 0, kRecipientRef);

    reader.seed();
    expect_failure(checks, "reject-endpoints-with-same-reference", reader, kActorRef, kActorRef);

    reader.seed();
    expect_failure(checks, "reject-endpoint-reference-with-zero-high-byte", reader,
                   UINT64_C(0x00FFFFFFFFFFFFFF), kRecipientRef);

    std::cout << "SUMMARY passed=" << checks.passed << " failed=" << checks.failed << "\n";
    return checks.failed == 0 ? 0 : 1;
}
