// Native war-context discovery. This reads the verified country/opponent
// association arrays; it does not construct, send, or execute a peace offer.
// The registry gives the public interface an opaque session-scoped identifier.
// Native object references remain private and are never used as integer IDs.

static constexpr const char* peace_query_actions[]={
    "cede_province","full_annexation","return_core","release_nation",
    "revoke_core","force_vassalization","form_personal_union",
    "release_subject","transfer_subject","grant_independence","demand_ducats",
    "war_reparations","transfer_trade_power","annul_treaties","humiliate_rival",
    "show_strength","force_religion","concede_defeat","white_peace"};

static bool peace_query_action(const char* action) noexcept {
    for (const char* item:peace_query_actions) if (!strcmp(item,action)) return true;
    return false;
}

#include "information-war-registry.h"
using PeaceWarRegistryEntry = information::war_registry::Snapshot;
static information::war_registry::Entry peace_war_registry[256]{};
static unsigned peace_war_registry_size=0;
static std::atomic<uint64_t> peace_war_registry_revision{0};
static information::war_registry::Registry peace_war_registry_lifetimes{
    peace_war_registry,peace_war_registry_size,&peace_war_registry_revision};

[[maybe_unused]] static void peace_query_reconcile_war_registry() noexcept {
    struct Cache final {
        uintptr_t game=0,rows=0;
        int32_t count=0,date=0;
        information::war_registry::RosterStamp stamp{};
        bool observed=false;
    };
    static Cache cache{};
    const auto stamp=peace_war_registry_lifetimes.roster_stamp();
    if (!stamp.serial) return;
    Cache captured{};
    if (!read(base+0x233fe58,captured.game) || !captured.game
        || !read(captured.game+0x1dd0,captured.date) || captured.date<=0
        || !read(captured.game+0x1e30,captured.rows)
        || !read(captured.game+0x1e3c,captured.count)
        || captured.count<0 || captured.count>4096
        || (captured.count && (captured.rows<0x10000 || (captured.rows&7)
            || captured.rows>UINT64_C(0x00007fffffffffff)-static_cast<uintptr_t>(captured.count)*8))) return;
    if (cache.observed && cache.game==captured.game && cache.rows==captured.rows
        && cache.count==captured.count && cache.date==captured.date && cache.stamp==stamp) return;
    uintptr_t references[4096]{};
    for (int32_t index=0;index<captured.count;++index) {
        if (!read(captured.rows+static_cast<uintptr_t>(index)*8,references[index])
            || references[index]<0x10000 || (references[index]&7)) return;
    }
    // A second pass rejects changes within the same data/count allocation.
    for (int32_t index=0;index<captured.count;++index) {
        uintptr_t current=0;
        if (!read(captured.rows+static_cast<uintptr_t>(index)*8,current)
            || current!=references[index]) return;
    }
    uintptr_t game=0,rows=0;
    int32_t count=0,date=0;
    if (!read(base+0x233fe58,game) || game!=captured.game
        || !read(game+0x1dd0,date) || date!=captured.date
        || !read(game+0x1e30,rows) || rows!=captured.rows
        || !read(game+0x1e3c,count) || count!=captured.count) return;
    const auto after=peace_war_registry_lifetimes.reconcile_active(
        references,static_cast<unsigned>(captured.count),stamp);
    if (after) {
        captured.stamp=*after;
        captured.observed=true;
        cache=captured;
    }
}

static bool peace_query_live_war_member(uintptr_t reference) noexcept {
    uintptr_t game=0,rows=0,table=0;
    int32_t count=0,date=0,marker=0;
    if (!reference || !read(base+0x233fe58,game) || !game
        || !read(game+0x1dd0,date) || date<=0
        || !read(game+0x1e30,rows) || !read(game+0x1e3c,count)
        || count<=0 || count>4096 || rows<0x10000 || (rows&7)
        || rows>UINT64_C(0x00007fffffffffff)-static_cast<uintptr_t>(count)*8
        || !read(reference,table) || table!=base+0x1d1f6f0
        || !read(reference+8,marker) || marker!=0x165) return false;
    unsigned matches=0;
    for (int32_t index=0;index<count;++index) {
        uintptr_t value=0;
        if (!read(rows+static_cast<uintptr_t>(index)*8,value)) return false;
        if (value==reference) ++matches;
    }
    uintptr_t after_game=0,after_rows=0;
    int32_t after_count=0,after_date=0;
    return matches==1 && read(base+0x233fe58,after_game) && after_game==game
        && read(game+0x1dd0,after_date) && after_date==date
        && read(game+0x1e30,after_rows) && after_rows==rows
        && read(game+0x1e3c,after_count) && after_count==count;
}

static std::optional<PeaceWarRegistryEntry> peace_query_register_war(uintptr_t reference) noexcept {
    auto result=peace_war_registry_lifetimes.register_war(reference,observation_creation);
    if (result || peace_war_registry_lifetimes.birth(reference).reference) return result;
    const auto sequence=peace_war_registry_lifetimes.sequence();
    if (!peace_query_live_war_member(reference)) return std::nullopt;
    return peace_war_registry_lifetimes.register_war(reference,observation_creation,sequence);
}

static std::optional<PeaceWarRegistryEntry> peace_query_find_registered_war(const char* public_id) noexcept {
    return peace_war_registry_lifetimes.find_id(public_id);
}

static bool peace_query_copy_war_id(uintptr_t reference,char* output,size_t capacity) noexcept {
    const auto entry=peace_query_register_war(reference);
    if (!entry || !output || capacity<sizeof(entry->public_id)) return false;
    memcpy(output,entry->public_id,sizeof(entry->public_id));
    if (!peace_war_registry_lifetimes.current(*entry)) { output[0]=0; return false; }
    return true;
}

struct PeaceWarReferenceList {
    uintptr_t references[32]{};
    unsigned count=0;
    bool complete=false,truncated=false;
};

static bool peace_query_country_pointer(uint64_t handle,uintptr_t& country) noexcept {
    uintptr_t database=0,array=0; uint64_t identity=0;
    const unsigned slot=static_cast<unsigned>((handle>>32)&0xffffu);
    return read(base+0x233d8b0,database) && read(database+0x118,array)
        && read(array+static_cast<uintptr_t>(slot)*8,country)
        && read(country+0x20,identity) && identity==handle;
}

#include "peace-war-side-members.inc"

static bool peace_query_pair_references(uintptr_t country,unsigned other,
    PeaceWarReferenceList& output) noexcept {
    output=PeaceWarReferenceList{};
    uintptr_t rows=0; int32_t count=0;
    if (!read(country+0x1548,rows) || !read(country+0x1554,count)
        || count<0 || count>256 || (count && !rows)) return false;
    for (int32_t i=0;i<count;++i) {
        int32_t slot=-1; uintptr_t reference=0;
        const uintptr_t row=rows+static_cast<uintptr_t>(i)*16;
        if (!read(row,slot) || !read(row+8,reference)) return false;
        if (slot!=static_cast<int32_t>(other)) continue;
        if (!reference) return false;
        bool duplicate=false;
        for (unsigned j=0;j<output.count;++j)
            duplicate=duplicate || output.references[j]==reference;
        if (duplicate) continue;
        if (output.count>=32) { output.truncated=true; continue; }
        output.references[output.count++]=reference;
    }
    output.complete=!output.truncated;
    return true;
}

static bool peace_query_reference_sets_equal(const PeaceWarReferenceList& left,
    const PeaceWarReferenceList& right) noexcept {
    if (!left.complete || !right.complete || left.count!=right.count) return false;
    for (unsigned i=0;i<left.count;++i) {
        bool found=false;
        for (unsigned j=0;j<right.count;++j)
            found=found || left.references[i]==right.references[j];
        if (!found) return false;
    }
    return true;
}

static bool peace_query_context_state_stable(uint64_t actor,uint64_t recipient,
    uintptr_t actor_country,uintptr_t recipient_country,
    const PeaceWarReferenceList& expected_left,
    const PeaceWarReferenceList& expected_right) noexcept {
    uintptr_t current_actor_country=0,current_recipient_country=0;
    PeaceWarReferenceList current_left{},current_right{};
    return peace_query_country_pointer(actor,current_actor_country)
        && peace_query_country_pointer(recipient,current_recipient_country)
        && current_actor_country==actor_country
        && current_recipient_country==recipient_country
        && peace_query_pair_references(current_actor_country,
            static_cast<unsigned>((recipient>>32)&0xffffu),current_left)
        && peace_query_pair_references(current_recipient_country,
            static_cast<unsigned>((actor>>32)&0xffffu),current_right)
        && peace_query_reference_sets_equal(current_left,expected_left)
        && peace_query_reference_sets_equal(current_right,expected_right);
}

static bool peace_context_war_row_json(unsigned index,
    const PeaceWarRegistryEntry& entry,const char* actor_tag,
    const char* recipient_tag,const char* participants,
    char* output,size_t capacity) noexcept {
    if (!output || !capacity || !participants) return false;
    const int written=snprintf(output,capacity,
        "%s{\"war_id\":\"%s\",\"identity_scope\":\"observer_session\",\"actor\":\"%.3s\",\"recipient\":\"%.3s\",\"pair_at_war\":true,\"actor_war_role\":null,\"recipient_war_role\":null,\"roles_verified\":false,\"actor_is_war_leader\":null,\"recipient_is_war_leader\":null,\"leaders_verified\":false,\"context_complete\":false,\"participants\":%s}",
        index?",":"",entry.public_id,actor_tag,recipient_tag,participants);
    return written>=0 && static_cast<size_t>(written)<capacity;
}

static void peace_context_query_run(const char* id,const char* action_id,
    const char* actor_tag,const char* recipient_tag,uint64_t actor,
    uint64_t recipient,int32_t date) noexcept {
    uintptr_t actor_country=0,recipient_country=0;
    PeaceWarReferenceList left{},right{};
    if (!peace_query_country_pointer(actor,actor_country)
        || !peace_query_country_pointer(recipient,recipient_country)
        || !peace_query_pair_references(actor_country,
            static_cast<unsigned>((recipient>>32)&0xffffu),left)
        || !peace_query_pair_references(recipient_country,
            static_cast<unsigned>((actor>>32)&0xffffu),right)
        || !peace_query_reference_sets_equal(left,right)) {
        alliance_query_failure(id,"QUERY_PEACE_WAR_ASSOCIATIONS_UNAVAILABLE"); return;
    }
    std::optional<PeaceWarRegistryEntry> entries[32]{};
    size_t base_lengths[32]{};
    char unknown_participants[512]{};
    PeaceWarSideMembers empty_a{},empty_b{};
    // Reserve the longest bounded unknown reason so a later read failure
    // cannot consume space promised to the remaining base rows.
    if (!peace_war_participants_json(empty_a,empty_b,actor,recipient,
        "PARTICIPANT_COUNTRY_IDENTITY_INVALID",unknown_participants,
        sizeof(unknown_participants))) {
        alliance_query_failure(id,"QUERY_PEACE_WAR_OUTPUT_LIMIT"); return;
    }
    size_t reserved_base=0;
    for (unsigned i=0;i<left.count;++i) {
        entries[i]=peace_query_register_war(left.references[i]);
        if (!entries[i]) {
            alliance_query_failure(id,"QUERY_PEACE_WAR_REGISTRY_FULL"); return;
        }
        char base_row[2048]{};
        if (!peace_context_war_row_json(i,*entries[i],actor_tag,recipient_tag,
            unknown_participants,base_row,sizeof(base_row))) {
            alliance_query_failure(id,"QUERY_PEACE_WAR_OUTPUT_LIMIT"); return;
        }
        base_lengths[i]=strlen(base_row);
        const size_t max_size=static_cast<size_t>(-1);
        if (reserved_base>max_size-base_lengths[i]) {
            alliance_query_failure(id,"QUERY_PEACE_WAR_OUTPUT_LIMIT"); return;
        }
        reserved_base+=base_lengths[i];
    }
    char wars[24576]{}; size_t used=0;
    for (unsigned i=0;i<left.count;++i) {
        reserved_base-=base_lengths[i];
        PeaceWarSideMembers side_a{},side_b{};
        const char* participant_reason=nullptr;
        const bool captured=peace_war_capture_participant_sides(
            entries[i]->native_reference,actor,recipient,side_a,side_b,
            participant_reason);
        char participants[4096]{};
        const char* effective_reason=captured?nullptr:participant_reason;
        if (!peace_war_participants_json(side_a,side_b,actor,recipient,
            effective_reason,participants,sizeof(participants))) {
            alliance_query_failure(id,"QUERY_PEACE_WAR_OUTPUT_LIMIT"); return;
        }
        char row[8192]{};
        if (!peace_context_war_row_json(i,*entries[i],actor_tag,recipient_tag,
            participants,row,sizeof(row))) {
            alliance_query_failure(id,"QUERY_PEACE_WAR_OUTPUT_LIMIT"); return;
        }
        size_t row_length=strlen(row);
        const size_t available=(used<=sizeof(wars)-1
            && reserved_base<=sizeof(wars)-1-used)
            ? sizeof(wars)-1-used-reserved_base : 0;
        const bool room=row_length<=available;
        if (captured && !room) {
            participant_reason="PARTICIPANT_OUTPUT_LIMIT";
            if (!peace_war_participants_json(side_a,side_b,actor,recipient,
                participant_reason,participants,sizeof(participants))
                || !peace_context_war_row_json(i,*entries[i],actor_tag,
                    recipient_tag,participants,row,sizeof(row))) {
                alliance_query_failure(id,"QUERY_PEACE_WAR_OUTPUT_LIMIT"); return;
            }
            row_length=strlen(row);
        }
        if (used>sizeof(wars)-1 || reserved_base>sizeof(wars)-1-used
            || row_length>sizeof(wars)-1-used-reserved_base) {
            alliance_query_failure(id,"QUERY_PEACE_WAR_OUTPUT_LIMIT"); return;
        }
        memcpy(wars+used,row,row_length);
        used+=row_length;
    }
    if (!peace_query_context_state_stable(actor,recipient,actor_country,
        recipient_country,left,right)) {
        alliance_query_failure(id,"QUERY_PEACE_WAR_CONTEXT_CHANGED"); return;
    }
    for (unsigned i=0;i<left.count;++i) {
        if (!peace_war_registry_lifetimes.current(*entries[i])) {
            alliance_query_failure(id,"QUERY_PEACE_WAR_CONTEXT_CHANGED"); return;
        }
    }
    for (unsigned i=0;i<left.count;++i) {
        char detail[600];
        const int written=snprintf(detail,sizeof(detail),
            "{\"event\":\"native_peace_context_private\",\"private\":true,\"session_id\":\"%lu-%llx\",\"query_id\":\"%s\",\"war_id\":\"%s\",\"native_war_reference\":\"0x%llx\",\"actor\":\"%.3s\",\"recipient\":\"%.3s\",\"association_verified\":true}\n",
            static_cast<unsigned long>(GetCurrentProcessId()),
            static_cast<unsigned long long>(observation_creation),id,
            entries[i]->public_id,
            static_cast<unsigned long long>(entries[i]->native_reference),
            actor_tag,recipient_tag);
        if (written<0 || static_cast<size_t>(written)>=sizeof(detail)) {
            alliance_query_failure(id,"QUERY_PEACE_WAR_OUTPUT_LIMIT"); return;
        }
        line(detail);
    }
    char message[26000];
    const int written=snprintf(message,sizeof(message),
        "{\"event\":\"native_peace_context_inspection\",\"family\":\"peace\",\"session_id\":\"%lu-%llx\",\"query_id\":\"%s\",\"action_id\":\"%s\",\"actor\":\"%.3s\",\"recipient\":\"%.3s\",\"phase\":\"initiate\",\"date_raw\":%d,\"discovery\":true,\"query_complete\":true,\"enumeration_complete\":true,\"native_offer_inspected\":false,\"full_rules_complete\":false,\"wars\":[%s],\"submitted\":false,\"frame_thread\":%lu}\n",
        static_cast<unsigned long>(GetCurrentProcessId()),
        static_cast<unsigned long long>(observation_creation),id,action_id,
        actor_tag,recipient_tag,date,wars,
        static_cast<unsigned long>(GetCurrentThreadId()));
    if (written<0 || static_cast<size_t>(written)>=sizeof(message)) {
        alliance_query_failure(id,"QUERY_PEACE_WAR_OUTPUT_LIMIT"); return;
    }
    line(message);
}
