// Deterministic fixture for the read-only peace-war participant producer.
// It supplies only bounded fake memory; it never opens the game or dispatches
// a native action.
#include <cstdint>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <map>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

struct FakeMemory {
    std::map<uintptr_t,std::vector<unsigned char>> cells;
    std::map<uintptr_t,unsigned> reads;
    uintptr_t fail_address=0;
    uintptr_t mutate_address=0;
    uint64_t mutate_value=0;
    unsigned mutate_on=0;

    template<typename T> void put(uintptr_t address,T value) {
        std::vector<unsigned char> bytes(sizeof(T));
        memcpy(bytes.data(),&value,sizeof(T));
        cells[address]=bytes;
    }

    void reset_reads() { reads.clear(); }
    void reset_faults() {
        fail_address=0; mutate_address=0; mutate_value=0; mutate_on=0;
    }
};

static FakeMemory* fake_memory=nullptr;
static void (*read_hook)(uintptr_t,unsigned)=nullptr;

template<typename T> static bool read(uintptr_t address,T& output) {
    if (!fake_memory) return false;
    const unsigned read_number=++fake_memory->reads[address];
    if (read_hook) read_hook(address,read_number);
    if (address==fake_memory->fail_address) return false;
    const auto found=fake_memory->cells.find(address);
    if (found==fake_memory->cells.end() || found->second.size()!=sizeof(T)) return false;
    memcpy(&output,found->second.data(),sizeof(T));
    if (fake_memory->mutate_address==address
        && fake_memory->mutate_on==read_number) {
        memcpy(&output,&fake_memory->mutate_value,sizeof(T));
    }
    return true;
}

static uintptr_t base=0x10000000;
static uint64_t observation_creation=0x123456789abcdef0ull;
static std::vector<std::string> emitted_lines;
static std::vector<std::string> failures;

static unsigned long GetCurrentProcessId() { return 41; }
static unsigned long GetCurrentThreadId() { return 42; }
static void line(const char* value) { emitted_lines.emplace_back(value?value:""); }
static void alliance_query_failure(const char*,const char* code) {
    failures.emplace_back(code?code:"");
}

#include "peace-context-query.inc"

static void require_true(bool value,const char* message) {
    if (!value) throw std::runtime_error(message);
}

static uint64_t make_handle(unsigned slot,const char* tag) {
    return (static_cast<uint64_t>(slot)<<32)
        | static_cast<uint64_t>(static_cast<unsigned char>(tag[0]))
        | (static_cast<uint64_t>(static_cast<unsigned char>(tag[1]))<<8)
        | (static_cast<uint64_t>(static_cast<unsigned char>(tag[2]))<<16);
}

static std::string generated_tag(char prefix,unsigned index) {
    char output[4]={prefix,'A','A',0};
    output[1]=static_cast<char>('A'+((index/26)%26));
    output[2]=static_cast<char>('A'+(index%26));
    return std::string(output);
}

struct FixtureWorld {
    FakeMemory memory;
    uintptr_t database=0x41000000;
    uintptr_t country_table=0x42000000;
    uintptr_t game=0x44000000,global_wars=0x45000000;
    uintptr_t actor_country=0;
    uintptr_t recipient_country=0;
    uint64_t actor=make_handle(1,"FRA");
    uint64_t recipient=make_handle(2,"BUR");
    std::vector<uint64_t> side_a;
    std::vector<uint64_t> side_b;
    std::vector<uintptr_t> wars;
    uintptr_t actor_rows=0x43000000;
    uintptr_t recipient_rows=0x43100000;

    void register_country(uint64_t handle) {
        const unsigned slot=static_cast<unsigned>((handle>>32)&0xffffu);
        const uintptr_t country=0x20000000+static_cast<uintptr_t>(slot)*0x1000;
        memory.put(country+0x20,handle);
        memory.put(country+0x1548,static_cast<uintptr_t>(0));
        memory.put(country+0x1554,static_cast<int32_t>(0));
        memory.put(country_table+static_cast<uintptr_t>(slot)*8,country);
    }

    void set_vector(uintptr_t war,uintptr_t begin_offset,uintptr_t end_offset,
        uintptr_t capacity_offset,unsigned side_index,
        const std::vector<uint64_t>& values) {
        const uintptr_t begin=0x60000000
            +static_cast<uintptr_t>(war-0x50000000)*2
            +static_cast<uintptr_t>(side_index)*0x10000;
        const uintptr_t end=begin+static_cast<uintptr_t>(values.size())*8;
        memory.put(war+begin_offset,begin);
        memory.put(war+end_offset,end);
        memory.put(war+capacity_offset,end);
        for (unsigned i=0;i<values.size();++i)
            memory.put(begin+static_cast<uintptr_t>(i)*8,values[i]);
    }

    void set_pair_refs(unsigned war_count) {
        memory.put(actor_country+0x1548,actor_rows);
        memory.put(actor_country+0x1554,static_cast<int32_t>(war_count));
        memory.put(recipient_country+0x1548,recipient_rows);
        memory.put(recipient_country+0x1554,static_cast<int32_t>(war_count));
        for (unsigned i=0;i<war_count;++i) {
            memory.put(actor_rows+static_cast<uintptr_t>(i)*16,
                static_cast<int32_t>(2));
            memory.put(actor_rows+static_cast<uintptr_t>(i)*16+8,wars[i]);
            memory.put(recipient_rows+static_cast<uintptr_t>(i)*16,
                static_cast<int32_t>(1));
            memory.put(recipient_rows+static_cast<uintptr_t>(i)*16+8,wars[i]);
        }
    }

    void setup(unsigned war_count,unsigned member_count) {
        memory=FakeMemory{};
        fake_memory=&memory;
        side_a.clear(); side_b.clear(); wars.clear();
        memory.put(base+0x233d8b0,database);
        memory.put(base+0x233fe58,game);
        memory.put(game+0x1dd0,static_cast<int32_t>(1512));
        memory.put(game+0x1e30,global_wars);
        memory.put(game+0x1e3c,static_cast<int32_t>(war_count));
        memory.put(database+0x118,country_table);
        register_country(actor); register_country(recipient);
        side_a.push_back(actor); side_b.push_back(recipient);
        for (unsigned i=1;i<member_count;++i) {
            const std::string tag_a=generated_tag('A',i);
            const std::string tag_b=generated_tag('B',i);
            const uint64_t handle_a=make_handle(100+i,tag_a.c_str());
            const uint64_t handle_b=make_handle(1000+i,tag_b.c_str());
            register_country(handle_a); register_country(handle_b);
            side_a.push_back(handle_a); side_b.push_back(handle_b);
        }
        for (unsigned i=0;i<war_count;++i) {
            const uintptr_t war=0x50000000+static_cast<uintptr_t>(i)*0x100000;
            wars.push_back(war);
            memory.put(war,base+0x1d1f6f0);
            memory.put(war+8,static_cast<int32_t>(0x165));
            memory.put(global_wars+static_cast<uintptr_t>(i)*8,war);
            set_vector(war,0x48,0x50,0x58,0,side_a);
            set_vector(war,0x78,0x80,0x88,1,side_b);
        }
        actor_country=0x20000000+0x1000;
        recipient_country=0x20000000+0x2000;
        set_pair_refs(war_count);
        memory.reset_reads();
        memory.reset_faults();
    }
};

static size_t occurrences(const std::string& value,const char* needle) {
    size_t count=0,offset=0; const size_t length=strlen(needle);
    while (length && (offset=value.find(needle,offset))!=std::string::npos) {
        ++count; offset+=length;
    }
    return count;
}

static void test_participant_edges(FixtureWorld& world) {
    const uintptr_t war=world.wars[0];
    PeaceWarSideMembers side_a{},side_b{};
    const char* reason=nullptr;
    char json[4096]{};
    require_true(peace_war_capture_participant_sides(war,world.actor,
        world.recipient,side_a,side_b,reason),"available participant capture failed");
    require_true(reason==nullptr,"available participant reason was set");
    require_true(peace_war_participants_json(side_a,side_b,world.actor,
        world.recipient,reason,json,sizeof(json)),"available JSON failed");
    require_true(strstr(json,"\"status\":\"available\"")
        && strstr(json,"\"complete\":true"),"available JSON shape failed");

    world.set_vector(war,0x48,0x50,0x58,0,{});
    world.set_vector(war,0x78,0x80,0x88,1,{});
    world.memory.reset_reads();
    require_true(!peace_war_capture_participant_sides(war,world.actor,
        world.recipient,side_a,side_b,reason)
        && !strcmp(reason,"PARTICIPANT_EMPTY"),"empty boundary failed");
    memset(json,0,sizeof(json));
    require_true(peace_war_participants_json(side_a,side_b,world.actor,
        world.recipient,reason,json,sizeof(json)),"unknown JSON failed");
    require_true(strstr(json,"\"status\":\"unknown\"")
        && strstr(json,"\"complete\":false")
        && strstr(json,"\"side_a\":[]")
        && strstr(json,"\"side_b\":[]")
        && strstr(json,"\"actor_side\":null")
        && strstr(json,"\"recipient_side\":null")
        && strstr(json,"\"reason\":\"PARTICIPANT_EMPTY\""),
        "unknown JSON shape failed");

    std::vector<uint64_t> over=world.side_a;
    const uint64_t extra=make_handle(3500,"ZZZ");
    world.register_country(extra); over.push_back(extra);
    world.set_vector(war,0x48,0x50,0x58,0,over);
    world.set_vector(war,0x78,0x80,0x88,1,world.side_b);
    world.memory.reset_reads();
    require_true(!peace_war_capture_participant_sides(war,world.actor,
        world.recipient,side_a,side_b,reason)
        && !strcmp(reason,"PARTICIPANT_VECTOR_LIMIT"),"257 boundary failed");

    world.set_vector(war,0x48,0x50,0x58,0,world.side_a);
    world.set_vector(war,0x78,0x80,0x88,1,world.side_b);
    world.memory.reset_reads();
    const uintptr_t begin_a=0x60000000
        +static_cast<uintptr_t>(war-0x50000000)*2;
    world.memory.fail_address=begin_a;
    require_true(!peace_war_capture_participant_sides(war,world.actor,
        world.recipient,side_a,side_b,reason)
        && !strcmp(reason,"PARTICIPANT_ELEMENT_READ_FAILED"),"read failure failed");
    world.memory.reset_faults(); world.memory.reset_reads();

    const uint64_t lowercase=make_handle(3600,"fra");
    world.register_country(lowercase);
    std::vector<uint64_t> lowercase_side=world.side_a;
    lowercase_side[1]=lowercase;
    world.set_vector(war,0x48,0x50,0x58,0,lowercase_side);
    world.set_vector(war,0x78,0x80,0x88,1,world.side_b);
    world.memory.reset_reads();
    require_true(!peace_war_capture_participant_sides(war,world.actor,
        world.recipient,side_a,side_b,reason)
        && !strcmp(reason,"PARTICIPANT_TAG_INVALID"),
        "lowercase participant tag was accepted");
    world.set_vector(war,0x48,0x50,0x58,0,world.side_a);
    world.memory.reset_reads();

    std::vector<uint64_t> duplicate=world.side_a;
    duplicate[1]=world.actor;
    world.set_vector(war,0x48,0x50,0x58,0,duplicate);
    world.set_vector(war,0x78,0x80,0x88,1,world.side_b);
    require_true(!peace_war_capture_participant_sides(war,world.actor,
        world.recipient,side_a,side_b,reason)
        && !strcmp(reason,"PARTICIPANT_DUPLICATE"),"same-side duplicate failed");

    world.set_vector(war,0x48,0x50,0x58,0,world.side_a);
    std::vector<uint64_t> cross=world.side_b;
    cross[1]=world.actor;
    world.set_vector(war,0x78,0x80,0x88,1,cross);
    require_true(!peace_war_capture_participant_sides(war,world.actor,
        world.recipient,side_a,side_b,reason)
        && !strcmp(reason,"PARTICIPANT_CROSS_SIDE_DUPLICATE"),"cross duplicate failed");

    world.set_vector(war,0x78,0x80,0x88,1,world.side_b);
    world.memory.reset_reads();
    const uintptr_t stale_element=begin_a+8;
    world.memory.mutate_address=stale_element;
    world.memory.mutate_on=2;
    world.memory.mutate_value=world.side_b[1];
    require_true(!peace_war_capture_participant_sides(war,world.actor,
        world.recipient,side_a,side_b,reason)
        && !strcmp(reason,"PARTICIPANT_VECTOR_CHANGED"),"stale vector failed");
    world.memory.reset_faults(); world.memory.reset_reads();
}

static void test_query_budget_and_barrier(FixtureWorld& world) {
    world.setup(32,256);
    emitted_lines.clear(); failures.clear();
    peace_context_query_run("q-budget","white_peace","FRA","BUR",
        world.actor,world.recipient,1512);
    require_true(failures.empty(),"budget query unexpectedly failed");
    require_true(emitted_lines.size()==33,"budget query line count failed");
    const std::string& public_line=emitted_lines.back();
    require_true(public_line.find("native_peace_context_inspection")!=std::string::npos,
        "public context line missing");
    require_true(occurrences(public_line,"\"participants\":")==32,
        "participant row count failed");
    require_true(public_line.find("PARTICIPANT_OUTPUT_LIMIT")!=std::string::npos,
        "budget did not downgrade participant output");

    emitted_lines.clear(); failures.clear();
    world.memory.reset_reads();
    world.memory.mutate_address=world.actor_country+0x1548;
    world.memory.mutate_on=2;
    world.memory.mutate_value=0;
    peace_context_query_run("q-barrier","white_peace","FRA","BUR",
        world.actor,world.recipient,1512);
    require_true(emitted_lines.empty(),"changed context emitted a public/private line");
    require_true(!failures.empty()
        && failures.back()=="QUERY_PEACE_WAR_CONTEXT_CHANGED",
        "changed context barrier reason failed");
}

static void test_registry_generations_preserve_query_battle_and_peace_binding(FixtureWorld& world) {
    world.setup(1,2);
    const auto reference = world.wars[0];
    const auto first = peace_query_register_war(reference);
    require_true(first.has_value(),"old war registration failed");
    const std::string old_id = first->public_id;
    const auto birth = peace_war_registry_lifetimes.begin(reference,world.actor,world.recipient,true);
    require_true(!peace_query_find_registered_war(old_id.c_str()),"retired peace selector still resolves");
    char battle_id[30]{};
    require_true(!peace_query_copy_war_id(reference,battle_id,sizeof(battle_id)),
        "unfinished war was registered by battle capture");
    require_true(peace_war_registry_lifetimes.complete(birth,true),"constructor completion failed");
    require_true(peace_query_copy_war_id(reference,battle_id,sizeof(battle_id)),"battle ID unavailable");
    for (unsigned generation=0;generation<600;++generation) {
        const auto next=peace_war_registry_lifetimes.begin(reference,world.actor,world.recipient,true);
        require_true(peace_war_registry_lifetimes.complete(next,true),"recycled constructor failed");
        require_true(peace_query_copy_war_id(reference,battle_id,sizeof(battle_id)),
            "battle ID exhausted after cumulative recycling");
    }
    require_true(old_id != battle_id,"new lifetime reused the old ID");
    require_true(peace_query_find_registered_war(battle_id)->native_reference == reference,
        "current peace selector does not bind new lifetime");
    emitted_lines.clear(); failures.clear();
    peace_context_query_run("query-new-lifetime","white_peace","FRA","BUR",
        world.actor,world.recipient,1512);
    require_true(failures.empty() && !emitted_lines.empty(),"current W01 query failed");
    const auto& output = emitted_lines.back();
    require_true(output.find(battle_id) != std::string::npos,"query and battle IDs differ");
    require_true(output.find(old_id) == std::string::npos,"W01 published the retired ID");
    std::cout << "normal W01/B01 identity after 600 recycled registrations: PASS\n";

    information::war_registry::Entry unused_entries[256]{};
    unsigned unused_count = 0;
    information::war_registry::Registry unused{unused_entries,unused_count};
    for (unsigned index = 1; index <= 600; ++index) {
        const auto token = unused.begin(0x70000000+index*0x1000,world.actor,world.recipient,true);
        require_true(unused.complete(token,true),"unregistered constructor tracking exhausted");
    }
    require_true(unused_count == 0,"unrelated constructors consumed public registry capacity");
}

static uintptr_t retirement_reference=0;
static void retire_during_participant_read(uintptr_t address,unsigned) {
    if (address!=retirement_reference+0x48) return;
    read_hook=nullptr;
    std::thread constructor([] {
        peace_war_registry_lifetimes.begin(retirement_reference,0,0,false);
    });
    constructor.join();
}
static void test_non_frame_retirement_retracts_inflight_query(FixtureWorld& world) {
    world.setup(1,2);
    retirement_reference=world.wars[0];
    const auto birth=peace_war_registry_lifetimes.begin(retirement_reference,world.actor,world.recipient,true);
    require_true(peace_war_registry_lifetimes.complete(birth,true),"fixture birth unavailable");
    const auto old=peace_query_register_war(retirement_reference);
    require_true(old.has_value(),"fixture ID unavailable");
    emitted_lines.clear(); failures.clear();
    read_hook=retire_during_participant_read;
    peace_context_query_run("query-retired-concurrently","white_peace","FRA","BUR",
        world.actor,world.recipient,1512);
    read_hook=nullptr;
    require_true(!peace_war_registry_lifetimes.current(*old),"non-frame retirement was not published");
    require_true(emitted_lines.empty() && !failures.empty()
        && failures.back()=="QUERY_PEACE_WAR_CONTEXT_CHANGED",
        "inflight W01 query emitted the retired ID");
    require_true(!peace_query_find_registered_war(old->public_id),"retired ID lookup succeeded");
}

static void test_destructor_window_rejects_registration_and_battle_copy(FixtureWorld& world) {
    world.setup(1,2);
    const auto reference=world.wars[0];
    const auto birth=peace_war_registry_lifetimes.begin(reference,world.actor,world.recipient,true);
    require_true(peace_war_registry_lifetimes.complete(birth,true),"fixture constructor incomplete");
    const auto old=peace_query_register_war(reference);
    require_true(old.has_value(),"fixture current ID unavailable");
    std::atomic<bool> entered{false},finish{false},completed{false};
    std::optional<information::war_registry::Retirement> retirement;
    std::thread destructor([&] {
        retirement.emplace(peace_war_registry_lifetimes.retire(reference));
        entered.store(true);
        while (!finish.load()) std::this_thread::yield();
        completed.store(peace_war_registry_lifetimes.complete_retirement(*retirement));
    });
    while (!entered.load()) std::this_thread::yield();
    char output[30]{};
    const bool registered_during=peace_query_register_war(reference).has_value();
    const bool copied_during=peace_query_copy_war_id(reference,output,sizeof(output));
    emitted_lines.clear(); failures.clear();
    peace_context_query_run("query-during-destruction","white_peace","FRA","BUR",
        world.actor,world.recipient,1512);
    const bool query_rejected=emitted_lines.empty() && !failures.empty();
    finish.store(true);
    destructor.join();
    require_true(completed.load() && !registered_during && !copied_during && query_rejected,
        "destructor window revived an old registry reference");
    require_true(!peace_query_register_war(reference)
        && !peace_query_copy_war_id(reference,output,sizeof(output)),
        "completed retirement was mistaken for a loaded object");
    const auto next=peace_war_registry_lifetimes.begin(reference,world.actor,world.recipient,true);
    require_true(peace_war_registry_lifetimes.complete(next,true),"new lifetime did not complete");
    require_true(!peace_war_registry_lifetimes.complete_retirement(*retirement),
        "old destructor token modified a new lifetime");
    require_true(peace_query_copy_war_id(reference,output,sizeof(output))
        && std::strcmp(output,old->public_id)!=0 && !peace_query_find_registered_war(old->public_id),
        "new lifetime did not get an independent current ID");
    std::cout << "destructor in-progress and retired W01/B01 rejection: PASS\n";
}

static void test_loaded_live_war_after_retirement_cache_recycling(FixtureWorld& world) {
    world.setup(1,2);
    const uintptr_t loaded=0x7a000000;
    world.wars[0]=loaded;
    world.set_pair_refs(1);
    world.memory.put(world.global_wars,loaded);
    world.memory.put(loaded,base+0x1d1f6f0);
    world.memory.put(loaded+8,static_cast<int32_t>(0x165));
    world.set_vector(loaded,0x48,0x50,0x58,0,world.side_a);
    world.set_vector(loaded,0x78,0x80,0x88,1,world.side_b);
    for (unsigned index=0;index<600;++index) {
        auto token=peace_war_registry_lifetimes.retire(0x7b000000+index*0x1000);
        require_true(peace_war_registry_lifetimes.complete_retirement(token),"fixture retirement failed");
    }
    require_true(!peace_war_registry_lifetimes.birth(loaded).reference,
        "loaded fixture unexpectedly has constructor evidence");
    emitted_lines.clear(); failures.clear();
    peace_context_query_run("query-loaded-after-history-recycling","white_peace","FRA","BUR",
        world.actor,world.recipient,1512);
    const auto registered=peace_query_register_war(loaded);
    require_true(registered.has_value(),"loaded global member was not registered");
    const auto current=peace_query_find_registered_war(registered->public_id);
    require_true(failures.empty() && !emitted_lines.empty() && current
        && emitted_lines.back().find(current->public_id)!=std::string::npos,
        "live loaded war was permanently blocked after retirement history recycling");

    const uintptr_t unseen=0x7c000000;
    world.memory.put(world.global_wars,unseen);
    world.memory.put(unseen,base+0x1d1f6f0);
    world.memory.put(unseen+8,static_cast<int32_t>(0x165));
    require_true(!peace_war_registry_lifetimes.birth(unseen).reference,
        "unseen destruction fixture already has lifetime evidence");
    auto retirement=peace_war_registry_lifetimes.retire(unseen);
    char battle_id[30]{};
    const bool rejected=!peace_query_register_war(unseen)
        && !peace_query_copy_war_id(unseen,battle_id,sizeof(battle_id));
    peace_war_registry_lifetimes.complete_retirement(retirement);
    require_true(rejected,"unregistered object revived before global-table removal");
    world.memory.put(world.game+0x1e3c,static_cast<int32_t>(0));
    require_true(!peace_query_register_war(unseen),"removed global member was revived");
    std::cout << "loaded W01 after 600 retired records and unseen destructor rejection: PASS\n";
}

static void test_frame_reclaims_completed_war_while_object_is_retained(FixtureWorld& world) {
    world.setup(2,2);
    std::optional<PeaceWarRegistryEntry> records[2];
    for (unsigned index=0;index<2;++index) {
        const auto token=peace_war_registry_lifetimes.begin(world.wars[index],world.actor,world.recipient,true);
        require_true(peace_war_registry_lifetimes.complete(token,true),"fixture constructor failed");
        records[index]=peace_query_register_war(world.wars[index]);
        require_true(records[index].has_value(),"fixture registration failed");
    }
    peace_query_reconcile_war_registry();
    world.set_pair_refs(1);
    peace_query_reconcile_war_registry();
    require_true(peace_war_registry_lifetimes.current(*records[1]),
        "leaving one country pair retired a still-active global war");

    world.set_vector(world.wars[1],0x48,0x50,0x58,0,{});
    world.set_vector(world.wars[1],0x78,0x80,0x88,1,{});
    world.memory.put(world.game+0x1e3c,static_cast<int32_t>(1));
    world.memory.put(world.game+0x1dd0,static_cast<int32_t>(1513));
    peace_query_reconcile_war_registry();
    require_true(!peace_query_find_registered_war(records[1]->public_id)
        && peace_war_registry_lifetimes.current(*records[0]),
        "active-roster removal did not retire only the completed war");
    uintptr_t retained_table=0;
    require_true(read(world.wars[1],retained_table) && retained_table==base+0x1d1f6f0,
        "fixture lost the retained historical object");
    const auto reads=world.memory.reads[world.global_wars];
    peace_query_reconcile_war_registry();
    require_true(world.memory.reads[world.global_wars]==reads,
        "unchanged frame repeated the full global-roster scan");

    const uintptr_t reference=0x7e000000;
    const auto allocated_slots=peace_war_registry_size;
    const auto next=peace_war_registry_lifetimes.begin(reference,world.actor,world.recipient,true);
    require_true(peace_war_registry_lifetimes.complete(next,true),"replacement constructor failed");
    const auto replacement=peace_query_register_war(reference);
    require_true(replacement && peace_war_registry_size==allocated_slots
        && replacement->serial>records[1]->serial,
        "completed retained object did not release its physical slot");
    std::cout << "frame retirement after active-roster removal with historical object retained: PASS\n";
}

int main() {
    try {
        FixtureWorld world;
        world.setup(1,256);
        test_participant_edges(world);
        test_query_budget_and_barrier(world);
        test_registry_generations_preserve_query_battle_and_peace_binding(world);
        test_non_frame_retirement_retracts_inflight_query(world);
        test_destructor_window_rejects_registration_and_battle_copy(world);
        test_loaded_live_war_after_retirement_cache_recycling(world);
        test_frame_reclaims_completed_war_while_object_is_retained(world);
        std::cout << "native participants fixture: PASS\n";
        std::cout << "cases: empty, unknown-json, 256, 257, readfail, lowercase, duplicate, cross, stale, budget, barrier\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "native participants fixture: FAIL: " << error.what() << "\n";
        return 1;
    }
}
