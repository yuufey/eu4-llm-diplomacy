// B23 public interest map predicates, called on the existing frame thread.
// The explicit country lists omit dynamically computed AI interests.
static bool territorial_interest_parse(const char* csv,unsigned (&ids)[32],unsigned& count) {
    count=0;
    const char* cursor=csv;
    while (*cursor) {
        if (count==32 || *cursor<'1' || *cursor>'9') return false;
        unsigned value=0;
        do {
            value=value*10+static_cast<unsigned>(*cursor-'0');
            if (value>65535) return false;
            ++cursor;
        } while (*cursor>='0' && *cursor<='9');
        for (unsigned index=0;index<count;++index) if (ids[index]==value) return false;
        ids[count++]=value;
        if (!*cursor) break;
        if (*cursor++!=',' || !*cursor) return false;
    }
    return count>0;
}

static bool territorial_interest_discovery(uintptr_t province,unsigned slot,bool& discovered) {
    uintptr_t vtable=0,words=0;
    int32_t capacity=0,length=0;
    uint32_t word=0;
    if (!read(province+0x5d8,vtable) || vtable!=base+0x1c57270
        || !read(province+0x5e0,words) || !words || (words&3)
        || !read(province+0x5e8,capacity) || !read(province+0x5ec,length)
        || length<0 || length>capacity || capacity>128
        || slot/32>=static_cast<unsigned>(length)
        || !read(words+(slot/32)*4,word)) return false;
    discovered=(word&(1u<<(slot%32)))!=0;
    return true;
}

static void territorial_interest_query(const char* id,const char* actor_tag,
    const char* recipient_tag,const char* observer_tag,const char* csv,int expected_date) {
    unsigned ids[32]{},count=0;
    uint64_t observer=0,actor=0,recipient=0;
    if (!territorial_interest_parse(csv,ids,count)
        || (strcmp(actor_tag,observer_tag) && strcmp(recipient_tag,observer_tag))
        || !alliance_query_country(observer_tag,observer)
        || !alliance_query_country(actor_tag,actor)
        || !alliance_query_country(recipient_tag,recipient) || actor==recipient) {
        alliance_query_failure(id,"QUERY_INTEREST_SCOPE_INVALID"); return;
    }
    // The two native getter entries belong to the B23 executable. Their UI
    // call sites are recorded with the bounded static source evidence.
    static constexpr unsigned char vital_entry[]={0x48,0x89,0x5c,0x24,0x10,0x48,0x89,0x74,
        0x24,0x18,0x57,0x48,0x83,0xec,0x20,0x48,0x8b,0x81,0x68,0x04,0x00,0x00,0x48,0x8b};
    static constexpr unsigned char strategic_entry[]={0x48,0x89,0x5c,0x24,0x10,0x48,0x89,0x74,
        0x24,0x18,0x48,0x89,0x7c,0x24,0x20,0x41,0x56,0x48,0x83,0xec,0x20,0x48,0x8b,0x81};
    unsigned char actual[24]{};
    SIZE_T copied=0;
    if (!ReadProcessMemory(GetCurrentProcess(),reinterpret_cast<void*>(base+0xa0ee60),actual,24,&copied)
        || copied!=24 || memcmp(actual,vital_entry,24)
        || !ReadProcessMemory(GetCurrentProcess(),reinterpret_cast<void*>(base+0xa0ec90),actual,24,&copied)
        || copied!=24 || memcmp(actual,strategic_entry,24)) {
        alliance_query_failure(id,"QUERY_INTEREST_CODE_MISMATCH"); return;
    }
    uintptr_t world=0,controllers=0,begin=0,end=0,records=0,database=0,countries=0;
    uint32_t country_count=0;
    int32_t humans=0,controller=0,date=0;
    const unsigned slot=static_cast<unsigned>((observer>>32)&0xffff);
    if (!read(base+0x233fe58,world) || !world
        || !read(world+0xa60,humans) || humans!=1
        || !read(world+0x1d48,controllers) || !controllers
        || !read(controllers+slot*4,controller) || controller!=0
        || !read(world+0x1dd0,date) || date!=expected_date
        || !read(world+0x1c90,begin) || !read(world+0x1c98,end)
        || end<=begin || (end-begin)%8 || (end-begin)/8>65536
        || !read(base+0x233d8b0,database) || !read(database+0x118,countries) || !countries
        || !read(database+0x124,country_count) || !country_count || country_count>4096
        || !read(world+0x1ca8,records) || !records) {
        alliance_query_failure(id,"QUERY_INTEREST_CONTEXT_UNAVAILABLE"); return;
    }
    uintptr_t provinces[32]{};
    bool discovered[32]{};
    bool owner_resolved[32]{};
    for (unsigned index=0;index<count;++index) {
        int32_t actual_id=0;
        provinces[index]=records+static_cast<uintptr_t>(ids[index])*0x2e10;
        if (ids[index]>=(end-begin)/8
            || !read(provinces[index]+0x20,actual_id) || actual_id!=static_cast<int32_t>(ids[index])
            || !territorial_interest_discovery(provinces[index],slot,discovered[index])) {
            alliance_query_failure(id,"QUERY_INTEREST_PROVINCE_UNAVAILABLE"); return;
        }
        uint64_t owner=0,actual_owner=0;
        uintptr_t owner_country=0;
        if (discovered[index] && read(provinces[index]+0x468,owner)) {
            const unsigned owner_slot=static_cast<unsigned>((owner>>32)&0xffff);
            owner_resolved[index]=owner_slot<country_count
                && read(countries+owner_slot*8,owner_country) && owner_country
                && read(owner_country+0x20,actual_owner) && actual_owner==owner;
        }
    }
    using Predicate=bool (*)(void*,uint64_t);
    auto vital=reinterpret_cast<Predicate>(base+0xa0ee60);
    auto strategic=reinterpret_cast<Predicate>(base+0xa0ec90);
    char rows[6144]{};
    size_t used=0;
    for (unsigned index=0;index<count;++index) {
        // Hidden provinces never enter either native interest predicate.
        const bool available=discovered[index] && owner_resolved[index];
        const bool actor_vital=available && vital(reinterpret_cast<void*>(provinces[index]),actor);
        const bool actor_strategic=available && !actor_vital
            && strategic(reinterpret_cast<void*>(provinces[index]),actor);
        const bool recipient_vital=available && vital(reinterpret_cast<void*>(provinces[index]),recipient);
        const bool recipient_strategic=available && !recipient_vital
            && strategic(reinterpret_cast<void*>(provinces[index]),recipient);
        const int written=snprintf(rows+used,sizeof(rows)-used,
            "%s{\"province_id\":%u,\"visible\":%s,\"actor\":\"%s\",\"recipient\":\"%s\"}",
            index?",":"",ids[index],discovered[index]?"true":"false",
            !available?"unknown":actor_vital?"vital":actor_strategic?"strategic":"none",
            !available?"unknown":recipient_vital?"vital":recipient_strategic?"strategic":"none");
        if (written<0 || static_cast<size_t>(written)>=sizeof(rows)-used) {
            alliance_query_failure(id,"QUERY_INTEREST_RESULT_OVERFLOW"); return;
        }
        used+=static_cast<size_t>(written);
    }
    uintptr_t after_world=0;
    int32_t after_date=0;
    if (!read(base+0x233fe58,after_world) || after_world!=world
        || !read(world+0x1dd0,after_date) || after_date!=date) {
        alliance_query_failure(id,"QUERY_INTEREST_DATE_CHANGED"); return;
    }
    char message[7168]{};
    snprintf(message,sizeof(message),
        "{\"event\":\"native_territorial_interest_query\",\"session_id\":\"%lu-%llx\",\"query_id\":\"%s\","
        "\"actor\":\"%.3s\",\"recipient\":\"%.3s\",\"observer\":\"%.3s\",\"date_raw\":%d,"
        "\"provinces\":[%s],\"submitted\":false,\"frame_thread\":%lu}\n",
        static_cast<unsigned long>(GetCurrentProcessId()),static_cast<unsigned long long>(observation_creation),
        id,actor_tag,recipient_tag,observer_tag,date,rows,static_cast<unsigned long>(GetCurrentThreadId()));
    line(message);
}
