#ifndef BRIDGE_PEACE_WAR_SIDE_MEMBERS_INCLUDED
#define BRIDGE_PEACE_WAR_SIDE_MEMBERS_INCLUDED

// Shared, read-only country-vector capture used by the peace-context query,
// the already constructed-offer inspection, and the live war-score query.
// Handles are native evidence only.  Public callers receive bounded country
// tags after the database identity check below has succeeded.
struct PeaceWarSideMembers {
    uint64_t handles[256]{};
    uintptr_t country_objects[256]{};
    char tags[256][4]{};
    uintptr_t begin=0,end=0,capacity=0;
    unsigned count=0;
    bool readable=false;
    bool complete=false;
    bool tags_complete=false;
    bool canonical=true;
};

static bool peace_war_ascii_alnum(unsigned char value) noexcept {
    return (value>='A' && value<='Z')
        || (value>='a' && value<='z')
        || (value>='0' && value<='9');
}

static bool peace_war_ascii_upper_or_digit(unsigned char value) noexcept {
    return (value>='A' && value<='Z') || (value>='0' && value<='9');
}

static bool peace_war_tags_equal(const char* left,const char* right) noexcept {
    return left && right && left[0]==right[0] && left[1]==right[1]
        && left[2]==right[2];
}

static bool peace_war_capture_vector_reason(uintptr_t object,
    uintptr_t begin_offset,uintptr_t end_offset,uintptr_t capacity_offset,
    PeaceWarSideMembers& output,const char*& reason) noexcept {
    output=PeaceWarSideMembers{};
    reason=nullptr;
    if (!object) { reason="PARTICIPANT_OBJECT_INVALID"; return false; }
    uintptr_t begin=0,end=0,capacity=0;
    if (!read(object+begin_offset,begin) || !read(object+end_offset,end)
        || !read(object+capacity_offset,capacity)) {
        reason="PARTICIPANT_HEADER_READ_FAILED"; return false;
    }
    if (end<begin || capacity<end || (end-begin)%8) {
        reason="PARTICIPANT_HEADER_INVALID"; return false;
    }
    const uintptr_t bytes=end-begin;
    if (bytes/8>256) { reason="PARTICIPANT_VECTOR_LIMIT"; return false; }
    if (bytes && !begin) { reason="PARTICIPANT_HEADER_INVALID"; return false; }
    output.begin=begin;
    output.end=end;
    output.capacity=capacity;
    output.count=static_cast<unsigned>(bytes/8);
    output.readable=true;
    for (unsigned i=0;i<output.count;++i) {
        uint64_t handle=0; uintptr_t country=0;
        if (!read(begin+static_cast<uintptr_t>(i)*8,handle)) {
            output.complete=false;
            reason="PARTICIPANT_ELEMENT_READ_FAILED";
            return false;
        }
        if (!handle || !peace_query_country_pointer(handle,country)) {
            output.canonical=false;
            output.complete=false;
            reason="PARTICIPANT_COUNTRY_IDENTITY_INVALID";
            return false;
        }
        const unsigned char tag0=static_cast<unsigned char>(handle&0xffu);
        const unsigned char tag1=static_cast<unsigned char>((handle>>8)&0xffu);
        const unsigned char tag2=static_cast<unsigned char>((handle>>16)&0xffu);
        if (!peace_war_ascii_alnum(tag0) || !peace_war_ascii_alnum(tag1)
            || !peace_war_ascii_alnum(tag2)) {
            output.canonical=false;
            output.tags_complete=false;
            output.complete=false;
            reason="PARTICIPANT_TAG_INVALID";
            return false;
        }
        char tag[4]={static_cast<char>(tag0),static_cast<char>(tag1),
            static_cast<char>(tag2),0};
        for (unsigned j=0;j<i;++j) {
            if (output.handles[j]==handle || output.country_objects[j]==country
                || peace_war_tags_equal(output.tags[j],tag)) {
                output.canonical=false;
                output.complete=false;
                reason="PARTICIPANT_DUPLICATE";
                return false;
            }
        }
        output.handles[i]=handle;
        output.country_objects[i]=country;
        memcpy(output.tags[i],tag,sizeof(tag));
    }
    output.tags_complete=true;
    output.complete=true;
    return true;
}

static bool peace_war_capture_vector(uintptr_t object,uintptr_t begin_offset,
    uintptr_t end_offset,uintptr_t capacity_offset,
    PeaceWarSideMembers& output) noexcept {
    const char* reason=nullptr;
    return peace_war_capture_vector_reason(object,begin_offset,end_offset,
        capacity_offset,output,reason);
}

static bool peace_war_vector_content_equal(const PeaceWarSideMembers& left,
    const PeaceWarSideMembers& right) noexcept {
    if (!left.readable || !left.complete || !left.tags_complete
        || !right.readable || !right.complete || !right.tags_complete
        || left.begin!=right.begin || left.end!=right.end
        || left.capacity!=right.capacity || left.count!=right.count)
        return false;
    for (unsigned i=0;i<left.count;++i) {
        if (left.handles[i]!=right.handles[i]
            || left.country_objects[i]!=right.country_objects[i]
            || !peace_war_tags_equal(left.tags[i],right.tags[i])) return false;
    }
    return true;
}

// A pair is captured twice.  Header identity and every canonical country
// identity must agree before either side is exposed to the caller.
static bool peace_war_capture_vectors_stable(uintptr_t object,
    uintptr_t a_begin,uintptr_t a_end,uintptr_t a_capacity,
    uintptr_t b_begin,uintptr_t b_end,uintptr_t b_capacity,
    PeaceWarSideMembers& side_a,PeaceWarSideMembers& side_b,
    const char*& reason) noexcept {
    reason=nullptr;
    PeaceWarSideMembers first_a{},first_b{},second_a{},second_b{};
    if (!peace_war_capture_vector_reason(object,a_begin,a_end,a_capacity,
        first_a,reason) || !peace_war_capture_vector_reason(object,b_begin,
        b_end,b_capacity,first_b,reason)) return false;
    if (!peace_war_capture_vector_reason(object,a_begin,a_end,a_capacity,
        second_a,reason) || !peace_war_capture_vector_reason(object,b_begin,
        b_end,b_capacity,second_b,reason)) return false;
    if (!peace_war_vector_content_equal(first_a,second_a)
        || !peace_war_vector_content_equal(first_b,second_b)) {
        reason="PARTICIPANT_VECTOR_CHANGED";
        return false;
    }
    side_a=second_a;
    side_b=second_b;
    return true;
}

static bool peace_war_side_contains(const PeaceWarSideMembers& side,
    uint64_t handle) noexcept {
    for (unsigned i=0;i<side.count;++i)
        if (side.handles[i]==handle) return true;
    return false;
}

static bool peace_war_side_contains_slot(const PeaceWarSideMembers& side,
    uint64_t handle) noexcept {
    const unsigned slot=static_cast<unsigned>((handle>>32)&0xffffu);
    for (unsigned i=0;i<side.count;++i)
        if (static_cast<unsigned>((side.handles[i]>>32)&0xffffu)==slot) return true;
    return false;
}

static unsigned peace_war_side_for_handle(const PeaceWarSideMembers& side_a,
    const PeaceWarSideMembers& side_b,uint64_t handle) noexcept {
    const bool in_a=peace_war_side_contains(side_a,handle);
    const bool in_b=peace_war_side_contains(side_b,handle);
    return in_a==in_b?0u:(in_a?1u:2u);
}

static bool peace_war_participant_tags_canonical(
    const PeaceWarSideMembers& side) noexcept {
    for (unsigned i=0;i<side.count;++i)
        for (unsigned j=0;j<3;++j)
            if (!peace_war_ascii_upper_or_digit(
                    static_cast<unsigned char>(side.tags[i][j]))) return false;
    return true;
}

static bool peace_war_members_equal(const PeaceWarSideMembers& left,
    const PeaceWarSideMembers& right) noexcept {
    if (!left.readable || !left.complete || !left.tags_complete
        || !right.readable || !right.complete || !right.tags_complete
        || left.count!=right.count) return false;
    for (unsigned i=0;i<left.count;++i)
        if (left.handles[i]!=right.handles[i]
            || left.country_objects[i]!=right.country_objects[i]
            || !peace_war_tags_equal(left.tags[i],right.tags[i])) return false;
    return true;
}

static bool peace_war_capture_participant_sides(uintptr_t war,
    uint64_t actor,uint64_t recipient,PeaceWarSideMembers& side_a,
    PeaceWarSideMembers& side_b,const char*& reason) noexcept {
    side_a=PeaceWarSideMembers{};
    side_b=PeaceWarSideMembers{};
    if (!peace_war_capture_vectors_stable(war,0x48,0x50,0x58,0x78,0x80,
        0x88,side_a,side_b,reason)) return false;
    if (!side_a.count || !side_b.count) {
        reason="PARTICIPANT_EMPTY";
        return false;
    }
    // Existing offer/live-score consumers retain the historical alphanumeric
    // reader.  QUERY1's public participant contract is stricter: only
    // canonical uppercase country tags (or digits) are available.
    if (!peace_war_participant_tags_canonical(side_a)
        || !peace_war_participant_tags_canonical(side_b)) {
        reason="PARTICIPANT_TAG_INVALID";
        return false;
    }
    for (unsigned i=0;i<side_a.count;++i) {
        if (peace_war_side_contains(side_b,side_a.handles[i])) {
            reason="PARTICIPANT_CROSS_SIDE_DUPLICATE";
            return false;
        }
        for (unsigned j=0;j<side_b.count;++j)
            if (side_a.country_objects[i]==side_b.country_objects[j]
                || peace_war_tags_equal(side_a.tags[i],side_b.tags[j])) {
                reason="PARTICIPANT_CROSS_SIDE_DUPLICATE";
                return false;
            }
    }
    const unsigned actor_side=peace_war_side_for_handle(side_a,side_b,actor);
    const unsigned recipient_side=peace_war_side_for_handle(side_a,side_b,recipient);
    if (!actor_side || !recipient_side || actor_side==recipient_side) {
        reason="PARTICIPANT_SIDE_MEMBERSHIP_INVALID";
        return false;
    }
    reason=nullptr;
    return true;
}

static bool peace_war_side_tags_json(const PeaceWarSideMembers& side,
    char* output,size_t capacity) noexcept {
    if (!output || !capacity || !side.tags_complete || side.count>256) return false;
    size_t used=0;
    if (used+1>=capacity) return false;
    output[used++]='[';
    for (unsigned i=0;i<side.count;++i) {
        if (i && used+1>=capacity) return false;
        if (i) output[used++]=',';
        if (used+5>=capacity) return false;
        output[used++]='"';
        output[used++]=side.tags[i][0];
        output[used++]=side.tags[i][1];
        output[used++]=side.tags[i][2];
        output[used++]='"';
    }
    if (used+2>capacity) return false;
    output[used++]=']';
    output[used]=0;
    return true;
}

static bool peace_war_participants_json(const PeaceWarSideMembers& side_a,
    const PeaceWarSideMembers& side_b,uint64_t actor,uint64_t recipient,
    const char* reason,char* output,size_t capacity) noexcept {
    if (!output || !capacity) return false;
    char side_a_json[2048]{},side_b_json[2048]{};
    const bool available=!reason && side_a.complete && side_b.complete
        && side_a.tags_complete && side_b.tags_complete && side_a.count
        && side_b.count && peace_war_side_for_handle(side_a,side_b,actor)
        && peace_war_side_for_handle(side_a,side_b,recipient)
        && peace_war_participant_tags_canonical(side_a)
        && peace_war_participant_tags_canonical(side_b);
    const char* effective_reason=reason;
    const char* actor_side="null";
    const char* recipient_side="null";
    char reason_json[160]{};
    if (available) {
        if (!peace_war_side_tags_json(side_a,side_a_json,sizeof(side_a_json))
            || !peace_war_side_tags_json(side_b,side_b_json,sizeof(side_b_json)))
            return false;
        actor_side=peace_war_side_for_handle(side_a,side_b,actor)==1
            ?"\"side_a\"":"\"side_b\"";
        recipient_side=peace_war_side_for_handle(side_a,side_b,recipient)==1
            ?"\"side_a\"":"\"side_b\"";
    } else {
        strcpy(side_a_json,"[]");
        strcpy(side_b_json,"[]");
        if (!effective_reason) effective_reason="PARTICIPANT_CAPTURE_FAILED";
    }
    const int reason_written=snprintf(reason_json,sizeof(reason_json),
        available?"null":"\"%s\"",effective_reason?effective_reason:"");
    if (reason_written<0 || static_cast<size_t>(reason_written)>=sizeof(reason_json))
        return false;
    const int written=snprintf(output,capacity,
        "{\"source\":\"native_war_side_vectors\",\"status\":\"%s\","
        "\"complete\":%s,\"side_a\":%s,\"side_b\":%s,"
        "\"actor_side\":%s,\"recipient_side\":%s,\"reason\":%s}",
        available?"available":"unknown",available?"true":"false",
        side_a_json,side_b_json,actor_side,recipient_side,reason_json);
    return written>=0 && static_cast<size_t>(written)<capacity;
}

#endif // BRIDGE_PEACE_WAR_SIDE_MEMBERS_INCLUDED
