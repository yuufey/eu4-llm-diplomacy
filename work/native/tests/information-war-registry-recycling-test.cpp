#include "../information-war-registry.h"

#include <cstdio>
#include <cstring>
#include <set>
#include <string>
#include <thread>

int main() {
    using namespace information::war_registry;
    Entry entries[kCapacity]{};
    unsigned count=0;
    std::atomic<std::uint64_t> revision{0};
    Registry registry{entries,count,&revision};
    std::set<std::string> identifiers;
    constexpr std::uintptr_t reference=0x71000000;
    for (unsigned generation=1;generation<=600;++generation) {
        const auto birth=registry.begin(reference,1,2,true);
        if (!registry.complete(birth,true)) return 2;
        const auto record=registry.register_war(reference,1234);
        if (!record) {
            std::printf("FAIL cumulative generation %u rejected after %u allocated slots\n",
                generation,count);
            return 1;
        }
        if (!identifiers.emplace(record->public_id).second) return 3;
    }
    std::printf("registry cumulative recycling: PASS (600 distinct IDs, %u slots)\n",count);
    if (count>1 || (revision.load()&1)) return 4;
    const auto old=registry.find_reference(reference);
    const std::string old_id=old->public_id;
    std::thread destructor([&] {
        auto token=registry.retire(reference);
        registry.complete_retirement(token);
    });
    destructor.join();
    if (registry.current(*old) || registry.find_id(old_id.c_str())) return 5;
    for (unsigned generation=1;generation<=600;++generation) {
        const auto address=reference+generation*0x1000;
        const auto birth=registry.begin(address,1,2,true);
        if (!registry.complete(birth,true)) return 6;
        const auto current=registry.register_war(address,1234);
        if (!current || current->serial!=600+generation || count!=1) return 7;
        if (registry.claim_announcement(*current)!=Announcement::fresh
            || registry.claim_announcement(*current)!=Announcement::duplicate) return 8;
        auto token=registry.retire(address);
        if (registry.register_war(address,1234) || registry.find_id(current->public_id)) return 9;
        if (!registry.complete_retirement(token) || registry.register_war(address,1234)) return 9;
        if (registry.current(*current) || registry.find_id(current->public_id)) return 9;
    }
    if (old_id!=old->public_id) return 10;

    Entry full_entries[kCapacity]{};
    unsigned full_count=0;
    Registry full{full_entries,full_count};
    for (unsigned index=0;index<kCapacity;++index)
        if (!full.register_war(reference+index*0x1000,1234,full.sequence())) return 11;
    const auto first=full.find_reference(reference);
    if (full.register_war(reference+0x200000,1234,full.sequence())) return 12;
    auto retirement=full.retire(reference);
    if (full.register_war(reference,1234)) return 13;
    if (!full.complete_retirement(retirement) || full.register_war(reference,1234)) return 13;
    const auto replacement=full.register_war(reference+0x200000,1234,full.sequence());
    if (!replacement || replacement->serial!=257 || full_count!=kCapacity
        || full.current(*first) || full.find_id(first->public_id)) return 13;
    const auto initial=registry.begin(reference,1,2,true);
    if (!registry.complete(initial,true) || !registry.register_war(reference,1234)) return 14;
    std::atomic<bool> done{false}, corrupted{false};
    std::atomic<unsigned> reads{0};
    std::thread reader([&] {
        while (!done.load()) {
            const auto value=registry.find_reference(reference);
            if (!value) continue;
            const std::string frozen=value->public_id;
            ++reads;
            std::this_thread::yield();
            if (frozen!=value->public_id) corrupted.store(true);
            registry.current(*value);
        }
    });
    while (!reads.load()) std::this_thread::yield();
    for (unsigned generation=0;generation<600;++generation) {
        auto token=registry.retire(reference);
        registry.complete_retirement(token);
        const auto birth=registry.begin(reference,1,2,true);
        if (!registry.complete(birth,true) || !registry.register_war(reference,1234)) corrupted.store(true);
    }
    done.store(true);
    reader.join();
    if (corrupted.load() || (revision.load()&1)) return 15;
    Entry crowded_entries[kCapacity]{};
    unsigned crowded_count=0;
    Registry crowded{crowded_entries,crowded_count};
    for (unsigned index=0;index<kCapacity;++index)
        crowded.begin(reference+index*0x1000,1,2,true);
    const auto untracked=reference+0x500000;
    auto untracked_retirement=crowded.retire(untracked);
    if (crowded.birth(untracked).reference
        || crowded.register_war(untracked,1234,crowded.sequence())) return 16;
    crowded.complete_retirement(untracked_retirement);
    const auto loaded=reference+0x600000;
    const auto old_sequence=crowded.sequence();
    auto other_retirement=crowded.retire(reference);
    crowded.complete_retirement(other_retirement);
    if (crowded.register_war(loaded,1234,old_sequence)
        || !crowded.register_war(loaded,1234,crowded.sequence())) return 17;
    const auto before=crowded.roster_stamp();
    const auto fresh=crowded.register_war(loaded+0x1000,1234,crowded.sequence());
    const std::uintptr_t active[]={loaded};
    if (!fresh || crowded.reconcile_active(active,1,before) || !crowded.current(*fresh)) return 18;
    const auto reconciled=crowded.reconcile_active(active,1,crowded.roster_stamp());
    if (!reconciled || crowded.current(*fresh) || crowded.find_id(fresh->public_id)) return 19;
    std::printf("destructor recycling: PASS (1200 IDs, one physical slot; active-capacity recovery)\n");
    std::printf("concurrent snapshot reuse: PASS (%u reader copies, 600 retire/register cycles)\n",reads.load());
    std::printf("untracked destruction and live-proof sequence barrier: PASS\n");
    std::printf("active-roster removal and concurrent registration barrier: PASS\n");
    return 0;
}
