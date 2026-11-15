// Read-only relationship state for the Vassalization UI action family.
// Include after insult-query.inc for the bounded canonical country resolver.
// The relation reader is kept separate from action visibility and validity:
// a blocked cancellation must still describe the existing relation.
struct VassalQueryState {
    bool active=false;
    bool actor_is_overlord=false;
    bool actor_is_subject=false;
    char subject_type_json[131]="null";
    int32_t prestige_raw=0;
    int32_t cancel_prestige_delta_raw=0;
    bool cancel_prestige_effect_allowed=false;
    uintptr_t descriptor=0;
};

// a697e0 searches the owning country's subject associations. The relation row
// starts with its owner pointer; it is not a virtual table. Each 16-byte array
// item stores the other country's slot at +0 and the association pointer at +8.
static bool vassal_query_entry(uintptr_t country,uint64_t other,uintptr_t& entry) {
    uintptr_t database=0,rows=0,owner=0,begin=0;
    uint32_t country_count=0; uint64_t actual=0; int32_t count=0;
    const unsigned slot=static_cast<unsigned>((other>>32)&0xffffu);
    // Use the live CountryDB count instead of the legacy 256-slot bridge
    // bound. The relation-row handle check below remains mandatory.
    if (!read(base+0x233d8b0,database) || !read(database+0x124,country_count)
        || country_count>4096 || slot>=country_count
        || !read(country+0x1510,rows) || !rows) return false;
    const uintptr_t row=rows+static_cast<uintptr_t>(slot)*0x48;
    if (!read(row+0x10,actual) || actual!=other || !read(row,owner) || !owner
        || !read(owner+0x128,begin) || !read(owner+0x134,count)
        || count<0 || count>4096 || (count && !begin)) return false;
    entry=0;
    for (int32_t index=0;index<count;++index) {
        unsigned char bytes[16]{};
        if (!read(begin+static_cast<uintptr_t>(index)*16,bytes)) return false;
        int32_t item_slot=0; uintptr_t association=0;
        memcpy(&item_slot,bytes,4); memcpy(&association,bytes+8,8);
        if (item_slot!=static_cast<int32_t>(slot)) continue;
        if (entry || !association) return false;
        entry=association;
    }
    return true;
}

static bool vassal_query_relation(uint64_t actor,uint64_t recipient,
    VassalQueryState& state) {
    state=VassalQueryState{};
    uintptr_t source=0,target=0,forward=0,reverse=0;
    if (!insult_query_country(actor,source) || !insult_query_country(recipient,target)
        || !vassal_query_entry(source,recipient,forward)
        || !vassal_query_entry(target,actor,reverse) || forward!=reverse
        || !read(source+0xcf8,state.prestige_raw)
        || !read(base+0x233dd98,state.cancel_prestige_delta_raw)) return false;
    // This is the read-only predicate used by the cancellation confirmation
    // and handler. The prestige-changing function (333680) is never called.
    state.cancel_prestige_effect_allowed=reinterpret_cast<bool (*)(void*)>(base+0x3ed410)(
        reinterpret_cast<void*>(source));
    if (!forward) return true;
    // a6ac50 identifies the subject endpoint by association+18. Checking both
    // directions distinguishes an overlord's subject from its own overlord.
    uint64_t subject=0; uintptr_t descriptor=0;
    NativeShortString name{};
    if (!read(forward+0x18,subject) || (subject!=actor && subject!=recipient)
        || !read(forward+0x40,descriptor) || !descriptor
        || !read(descriptor+0x10,name) || !name.size || name.size>64
        || name.capacity<name.size || name.capacity>65536) return false;
    uintptr_t text=descriptor+0x10;
    if (name.capacity>=16) memcpy(&text,name.text,8);
    char identifier[65]{}; SIZE_T copied=0;
    if (!ReadProcessMemory(GetCurrentProcess(),reinterpret_cast<void*>(text),
            identifier,static_cast<SIZE_T>(name.size),&copied) || copied!=name.size) return false;
    // Native subject-type identifiers are ASCII keys. Validate every byte
    // before placing the key in JSON; no localized text is interpreted here.
    for (uint64_t index=0;index<name.size;++index) {
        const unsigned char ch=static_cast<unsigned char>(identifier[index]);
        if (ch<0x20 || ch>0x7e || ch=='"' || ch=='\\') return false;
    }
    snprintf(state.subject_type_json,sizeof(state.subject_type_json),"\"%s\"",identifier);
    state.active=true;
    state.descriptor=descriptor;
    state.actor_is_overlord=subject==recipient;
    state.actor_is_subject=subject==actor;
    return true;
}

// These are read-only UI action checks. The factory owns initialization and
// each temporary action is destroyed without invoking its execution method.
static bool vassal_query_integration(uint64_t overlord,uint64_t subject,
    uintptr_t descriptor,char* output,size_t capacity) {
    snprintf(output,capacity,"{\"verified\":false}");
    unsigned char annex=0,integrate=0;
    if (!read(descriptor+0x149,annex) || !read(descriptor+0x13f,integrate)) return false;
    if (!annex && !integrate) {
        snprintf(output,capacity,"{\"verified\":true,\"applicable\":false}");
        return true;
    }
    static const unsigned char expected_cost[20]={
        0x40,0x53,0x55,0x56,0x57,0x41,0x56,0x48,0x83,0xec,
        0x20,0x48,0x8b,0xd9,0x48,0x8b,0x0d,0x2b,0xc6,0x8c};
    unsigned char actual[20]{};
    if (!read(base+0xa71270,actual)
        || memcmp(actual,expected_cost,sizeof(actual))!=0) return false;
    const int32_t total=reinterpret_cast<int32_t (*)(uint64_t,uint64_t)>(base+0xa71270)(
        overlord,subject);
    if (total<0) return false;
    static constexpr FactoryActionQueryMethods families[2]={
        {0x293f,0x1c7f910,0x519460,0x519dc0,0xf8,0x4e4d80,"annex_vassal",true},
        {0x2a9c,0x1c7f7e0,0x51bff0,0x51caa0,0xf8,0x4e4d80,"integrate_union",true}};
    unsigned available=0;
    if (!alliance_query_diplomats(overlord,available)) return false;
    NativeShortString diagnostic{}; diagnostic.capacity=15;
    bool can_start=false,verified=true;
    for (unsigned index=0;index<2;++index) {
        if (!(index?integrate:annex)) continue;
        const auto& family=families[index];
        uintptr_t validity=0,display=0,destructor=0,diplomat=0;
        const uintptr_t table=base+family.vtable_rva;
        if (!read(table+0x80,validity) || validity!=base+family.validity_rva
            || !read(table+0x88,display) || display!=base+family.display_rva
            || !read(table,destructor) || destructor!=base+0x129450
            || !read(table+family.diplomat_slot,diplomat)
            || diplomat!=base+family.diplomat_rva) { verified=false; break; }
        bool visible=false;
        if (!factory_query_visibility(overlord,subject,true,visible,family)) {
            verified=false; break;
        }
        void* action=factory_query_create(overlord,subject,true,family);
        if (!action) { verified=false; break; }
        using Predicate=bool (*)(void*,void*,unsigned char);
        const bool common=reinterpret_cast<Predicate>(display)(action,nullptr,0);
        const bool valid=reinterpret_cast<Predicate>(validity)(action,&diagnostic,0);
        const bool needs_diplomat=reinterpret_cast<bool (*)(void*)>(diplomat)(action);
        can_start=can_start || (visible && common && valid && (!needs_diplomat || available>0));
        reinterpret_cast<void* (*)(void*,unsigned)>(destructor)(action,1);
    }
    char hex[1025]{}; unsigned char bytes[512]{}; SIZE_T copied=0;
    const size_t length=static_cast<size_t>(diagnostic.size<=512?diagnostic.size:512);
    uintptr_t address=reinterpret_cast<uintptr_t>(diagnostic.text);
    if (diagnostic.capacity>=16) memcpy(&address,diagnostic.text,8);
    const bool readable=!length || (diagnostic.size<=65536 && diagnostic.capacity<=131072
        && ReadProcessMemory(GetCurrentProcess(),reinterpret_cast<void*>(address),bytes,length,&copied)
        && copied==length);
    if (readable) for (size_t index=0;index<length;++index)
        snprintf(hex+index*2,3,"%02x",bytes[index]);
    const bool truncated=diagnostic.size>512;
    reinterpret_cast<void (*)(void*)>(base+0x95660)(&diagnostic);
    if (!verified) return false;
    snprintf(output,capacity,"{\"verified\":true,\"applicable\":true,\"can_start\":%s,"
        "\"total_diplomatic_power\":%d,\"conditions_hex\":\"%s\","
        "\"conditions_readable\":%s,\"conditions_truncated\":%s}",
        can_start?"true":"false",total,hex,readable?"true":"false",truncated?"true":"false");
    return true;
}

// The displayed liberty desire is calculated by the native 3ca160 wrapper.
// The saved +22a8 value and +28d0 processor cache are individual inputs.
// This runs inside the existing frame-thread inspection, with no submission.
static void vassal_query_subject_state(uint64_t country_ref,char* output,size_t capacity) {
    snprintf(output,capacity,"{\"verified\":false}");
    uintptr_t country=0; uint64_t overlord=0;
    if (!insult_query_country(country_ref,country)
        || !read(country+0x18f0,overlord)) return;
    if (!(overlord>>56)) {
        snprintf(output,capacity,"{\"verified\":true,\"is_subject\":false,"
            "\"overlord\":null,\"subject_type\":null,\"liberty_desire_raw\":null,\"scale\":1000}");
        return;
    }
    VassalQueryState relationship{};
    if (!vassal_query_relation(country_ref,overlord,relationship)
        || !relationship.active || !relationship.actor_is_subject) return;
    static const unsigned char expected_liberty_desire[20]={
        0x48,0x89,0x5c,0x24,0x08,0x48,0x89,0x6c,0x24,0x10,
        0x48,0x89,0x74,0x24,0x18,0x57,0x48,0x83,0xec,0x30};
    unsigned char actual[20]{};
    if (!read(base+0x3ca160,actual)
        || memcmp(actual,expected_liberty_desire,sizeof(actual))!=0) return;
    int32_t liberty_desire=0;
    using LibertyDesireQuery=int32_t* (*)(void*,int32_t*,void*,int32_t,bool);
    int32_t* result=reinterpret_cast<LibertyDesireQuery>(base+0x3ca160)(
        reinterpret_cast<void*>(country),&liberty_desire,nullptr,0,true);
    if (result!=&liberty_desire) return;
    char integration[1280]{};
    vassal_query_integration(overlord,country_ref,relationship.descriptor,
        integration,sizeof(integration));
    char overlord_tag[4]{}; memcpy(overlord_tag,&overlord,3);
    snprintf(output,capacity,"{\"verified\":true,\"is_subject\":true,"
        "\"overlord\":\"%.3s\",\"subject_type\":%s,\"liberty_desire_raw\":%d,\"scale\":1000,\"integration\":%s}",
        overlord_tag,relationship.subject_type_json,liberty_desire,integration);
}
