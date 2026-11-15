// Read-only quote inspection for the native Take On Debt action family.
// This file is included by the observer only when BRIDGE_DEBT_QUOTE_QUERY is
// enabled. It never invokes validity, display, send, AI-owner, or execution
// methods; the only native calls are the selector visibility predicate, the
// factory creator, the per-loan interest helper, the +0x70 description method,
// and the documented destructors.
#if defined(BRIDGE_DEBT_QUOTE_QUERY)
#include <xmmintrin.h>
#include "debt-quote-native-guards.h"

static constexpr FactoryActionQueryMethods debt_quote_query_methods{
    0x3469,0x1cb3bc8,0x7c2a00,0x7c2e00,0,0,"take_on_debt",false,0x129450};

struct DebtQuoteLoanInput {
    uintptr_t node=0;
    uintptr_t record=0;
    int32_t stored_rate_i32=0;
    int32_t principal_i32=0;
    int32_t expiry_raw_i32=0;
};

struct DebtQuoteContext {
    uintptr_t game=0;
    uintptr_t database=0;
    uintptr_t country_table=0;
    uintptr_t actor_country=0;
    uintptr_t recipient_country=0;
    uintptr_t physical_country=0;
    uintptr_t actor_relations=0;
    uintptr_t target_relation_row=0;
    uintptr_t target_relation_owner=0;
    uint32_t country_count=0;
    uint64_t actor=0;
    uint64_t recipient=0;
    uint64_t physical_player=0;
    uint64_t relation_recipient=0;
    int32_t date_raw=0;
};

struct DebtQuoteObservation {
    bool guards_verified=false;
    bool context_stable=false;
    bool visibility_read=false;
    bool native_visibility=false;
    bool financial_inputs_read=false;
    bool complete=false;
    bool mxcsr_available=false;
    bool mxcsr_after_helpers_available=false;
    bool mxcsr_before_description_available=false;
    bool mxcsr_model_compatible=false;
    bool mxcsr_controls_stable=false;
    bool daz_enabled=false;
    bool ftz_enabled=false;
    uint32_t mxcsr_before=0;
    uint32_t mxcsr_after_helpers=0;
    uint32_t mxcsr_before_description=0;
    uint32_t mxcsr_after=0;
    bool total_raw_available=false;
    int32_t total_raw_i32=0;
    DebtQuoteLoanInput loans[64]{};
    int32_t interest_raw_i32[64]{};
    unsigned loan_count=0;
    bool description_readable=false;
    bool description_truncated=false;
    bool description_cleanup_performed=false;
    bool description_cleanup_skipped=false;
    bool action_cleanup_performed=false;
    char description_hex[1025]{};
};

static bool debt_quote_pointer(uintptr_t value) noexcept {
    return value>=0x10000u && value<0x0000800000000000ull;
}

static bool debt_quote_add(uintptr_t base_address,uintptr_t offset,
    uintptr_t& output) noexcept {
    output=0;
    if (!debt_quote_pointer(base_address)
        || offset>=0x0000800000000000ull-base_address) return false;
    output=base_address+offset;
    return debt_quote_pointer(output);
}

template<typename T>
static bool debt_quote_read_at(uintptr_t address,uintptr_t offset,T& output) noexcept {
    uintptr_t resolved=0;
    return debt_quote_add(address,offset,resolved) && read(resolved,output);
}

static uint32_t debt_quote_tag_value(const char* tag) noexcept {
    return static_cast<uint32_t>(static_cast<unsigned char>(tag[0]))
        | (static_cast<uint32_t>(static_cast<unsigned char>(tag[1]))<<8)
        | (static_cast<uint32_t>(static_cast<unsigned char>(tag[2]))<<16);
}

static bool debt_quote_exact_tag(const char* tag,const char* expected) noexcept {
    return tag && expected && tag[0] && tag[1] && tag[2] && tag[3]=='\0'
        && tag[0]==expected[0] && tag[1]==expected[1]
        && tag[2]==expected[2] && expected[3]=='\0';
}

static bool debt_quote_lookup_country(uintptr_t table,uint32_t country_count,
    uint64_t expected_ref,uintptr_t& country) noexcept {
    country=0;
    const unsigned slot=static_cast<unsigned>((expected_ref>>32)&0xffffu);
    uintptr_t entry=0;
    uint64_t actual=0;
    uintptr_t entry_address=0;
    if (!country_count || country_count>4096 || slot>=country_count
        || !debt_quote_pointer(table)
        || slot> (0x0000800000000000ull-table)/sizeof(uintptr_t)
        || !debt_quote_add(table,static_cast<uintptr_t>(slot)*sizeof(uintptr_t),entry_address)
        || !read(entry_address,entry) || !debt_quote_pointer(entry)
        || !debt_quote_read_at(entry,0x20,actual) || actual!=expected_ref
        || static_cast<unsigned>((actual>>32)&0xffffu)!=slot) return false;
    country=entry;
    return true;
}

static bool debt_quote_context_read(const char* actor_tag,const char* recipient_tag,
    uint64_t actor,uint64_t recipient,int32_t expected_date,
    DebtQuoteContext& output) noexcept {
    output=DebtQuoteContext{};
    if (!debt_quote_exact_tag(actor_tag,"FRA")
        || !recipient_tag || recipient_tag[0]=='\0' || recipient_tag[1]=='\0'
        || recipient_tag[2]=='\0' || recipient_tag[3]!='\0'
        || debt_quote_exact_tag(recipient_tag,"POR")
        || debt_quote_exact_tag(recipient_tag,"FRA")
        || actor==recipient || (actor&0xffffffu)!=debt_quote_tag_value(actor_tag)
        || (recipient&0xffffffu)!=debt_quote_tag_value(recipient_tag)) return false;

    uintptr_t world_slot=0;
    if (!debt_quote_add(base,0x233fe58,world_slot)
        || !read(world_slot,output.game) || !debt_quote_pointer(output.game)
        || !debt_quote_read_at(output.game,0x1dd0,output.date_raw)
        || output.date_raw!=expected_date
        || !debt_quote_read_at(output.game,0x1e60,output.physical_player)
        || (output.physical_player&0xffffffu)!=0x524f50u
        || output.physical_player==actor) return false;

    uintptr_t database_slot=0;
    if (!debt_quote_add(base,0x233d8b0,database_slot)
        || !read(database_slot,output.database) || !debt_quote_pointer(output.database)
        || !debt_quote_read_at(output.database,0x118,output.country_table)
        || !debt_quote_pointer(output.country_table)
        || !debt_quote_read_at(output.database,0x124,output.country_count)
        || !output.country_count || output.country_count>4096
        || !debt_quote_lookup_country(output.country_table,output.country_count,
            actor,output.actor_country)
        || !debt_quote_lookup_country(output.country_table,output.country_count,
            recipient,output.recipient_country)
        || !debt_quote_lookup_country(output.country_table,output.country_count,
            output.physical_player,output.physical_country)
        || output.actor_country==output.recipient_country
        || output.actor_country==output.physical_country
        || output.recipient_country==output.physical_country) return false;
    const unsigned recipient_slot=static_cast<unsigned>((recipient>>32)&0xffffu);
    uintptr_t row_offset=0;
    if (recipient_slot>=output.country_count
        || !debt_quote_read_at(output.actor_country,0x1510,output.actor_relations)
        || !debt_quote_pointer(output.actor_relations)
        || recipient_slot>0x0000800000000000ull/0x48u
        || !debt_quote_add(output.actor_relations,
            static_cast<uintptr_t>(recipient_slot)*0x48u,row_offset)
        || !read(row_offset,output.target_relation_owner)
        || !debt_quote_read_at(row_offset,0x10,output.relation_recipient)
        || output.relation_recipient!=recipient) return false;
    output.target_relation_row=row_offset;
    output.actor=actor;
    output.recipient=recipient;
    return true;
}

static bool debt_quote_context_equal(const DebtQuoteContext& left,
    const DebtQuoteContext& right) noexcept {
    return left.game==right.game && left.database==right.database
        && left.country_table==right.country_table
        && left.actor_country==right.actor_country
        && left.recipient_country==right.recipient_country
        && left.physical_country==right.physical_country
        && left.actor_relations==right.actor_relations
        && left.target_relation_row==right.target_relation_row
        && left.target_relation_owner==right.target_relation_owner
        && left.country_count==right.country_count
        && left.actor==right.actor && left.recipient==right.recipient
        && left.relation_recipient==right.relation_recipient
        && left.physical_player==right.physical_player
        && left.date_raw==right.date_raw;
}

static bool debt_quote_family_slots_valid() noexcept {
    const uintptr_t table=base+debt_quote_query_methods.vtable_rva;
    uintptr_t description=0,validity=0,display=0;
    return debt_quote_pointer(table)
        && debt_quote_read_at(table,0x70,description) && description==base+0x7c2eb0
        && debt_quote_read_at(table,0x80,validity) && validity==base+0x7c2a00
        && debt_quote_read_at(table,0x88,display) && display==base+0x7c2e00;
}

static bool debt_quote_capture_loans(uintptr_t recipient_country,
    DebtQuoteLoanInput (&loans)[64],unsigned& count) noexcept {
    for (unsigned i=0;i<64;++i) loans[i]=DebtQuoteLoanInput{};
    count=0;
    uintptr_t head=0;
    int32_t native_count=0;
    if (!debt_quote_read_at(recipient_country,0xde8,head)
        || !debt_quote_read_at(recipient_country,0xdf8,native_count)
        || native_count<0 || native_count>64
        || (native_count==0 && head!=0)
        || (native_count>0 && !debt_quote_pointer(head))) return false;

    uintptr_t node=head;
    for (int32_t index=0;index<native_count;++index) {
        if (!debt_quote_pointer(node)) return false;
        for (int32_t prior=0;prior<index;++prior)
            if (loans[prior].node==node) return false;
        DebtQuoteLoanInput& loan=loans[static_cast<unsigned>(index)];
        loan.node=node;
        if (!debt_quote_read_at(node,0,loan.record)
            || !debt_quote_pointer(loan.record)) return false;
        for (int32_t prior=0;prior<index;++prior)
            if (loans[prior].record==loan.record) return false;
        if (!debt_quote_read_at(loan.record,0x28,loan.stored_rate_i32)
            || !debt_quote_read_at(loan.record,0x2c,loan.principal_i32)
            || !debt_quote_read_at(loan.record,0x30,loan.expiry_raw_i32)) return false;
        uintptr_t next_address=0,next=0;
        if (!debt_quote_add(node,0x10,next_address) || !read(next_address,next)) return false;
        node=next;
    }
    if (node!=0) return false;
    count=static_cast<unsigned>(native_count);
    return true;
}

static bool debt_quote_loans_equal(const DebtQuoteLoanInput (&left)[64],
    unsigned left_count,const DebtQuoteLoanInput (&right)[64],
    unsigned right_count) noexcept {
    if (left_count!=right_count || left_count>64) return false;
    for (unsigned index=0;index<left_count;++index) {
        if (left[index].node!=right[index].node
            || left[index].record!=right[index].record
            || left[index].stored_rate_i32!=right[index].stored_rate_i32
            || left[index].principal_i32!=right[index].principal_i32
            || left[index].expiry_raw_i32!=right[index].expiry_raw_i32) return false;
    }
    return true;
}

static bool debt_quote_mxcsr_supported(uint32_t value) noexcept {
    return (value&0x6000u)==0 && (value&0x1f80u)==0x1f80u;
}

static bool debt_quote_description_shape_valid(const NativeShortString& value) noexcept {
    if (value.size>value.capacity || value.capacity>131072
        || (value.capacity<16 && value.capacity!=15)
        || value.size>65536) return false;
    if (value.capacity>=16) {
        uintptr_t source=0;
        memcpy(&source,value.text,sizeof(source));
        if (!debt_quote_pointer(source)) return false;
        unsigned char probe=0;
        SIZE_T copied=0;
        if (!ReadProcessMemory(GetCurrentProcess(),reinterpret_cast<void*>(source),
                &probe,sizeof(probe),&copied) || copied!=sizeof(probe)) return false;
    }
    return true;
}

static bool debt_quote_hex_description(const NativeShortString& value,
    char (&hex)[1025],bool& truncated) noexcept {
    hex[0]='\0';
    truncated=false;
    if (!debt_quote_description_shape_valid(value)) return false;
    const unsigned length=static_cast<unsigned>(value.size<=512?value.size:512);
    truncated=value.size>512;
    uintptr_t source=reinterpret_cast<uintptr_t>(value.text);
    if (value.capacity>=16) memcpy(&source,value.text,sizeof(source));
    if (length && !debt_quote_pointer(source)) return false;
    unsigned char raw[512]{};
    if (length) {
        SIZE_T copied=0;
        if (!ReadProcessMemory(GetCurrentProcess(),reinterpret_cast<void*>(source),
                raw,length,&copied) || copied!=length) return false;
    }
    static const char digits[]="0123456789abcdef";
    for (unsigned index=0;index<length;++index) {
        hex[index*2]=digits[(raw[index]>>4)&0xf];
        hex[index*2+1]=digits[raw[index]&0xf];
    }
    hex[length*2]='\0';
    return true;
}

static void debt_quote_append_loans(const DebtQuoteObservation& result,
    bool complete,char (&json)[8192]) noexcept {
    json[0]='\0';
    size_t used=0;
    const unsigned count=complete?result.loan_count:0;
    for (unsigned index=0;index<count;++index) {
        const DebtQuoteLoanInput& loan=result.loans[index];
        const int written=snprintf(json+used,sizeof(json)-used,
            "%s{\"principal_i32\":%d,\"stored_rate_i32\":%d,\"expiry_raw_i32\":%d,\"interest_raw_i32\":%d}",
            index?",":"",loan.principal_i32,loan.stored_rate_i32,
            loan.expiry_raw_i32,result.interest_raw_i32[index]);
        if (written<0 || static_cast<size_t>(written)>=sizeof(json)-used) {
            json[0]='\0';
            return;
        }
        used+=static_cast<size_t>(written);
    }
}

static void debt_quote_emit(const char* id,const char* actor_tag,
    const char* recipient_tag,int32_t date,const DebtQuoteObservation& result,
    const char* reason_code) noexcept {
    const bool output_complete=result.complete && result.total_raw_available;
    char loans_json[8192]{};
    debt_quote_append_loans(result,output_complete,loans_json);
    const char* visibility=result.visibility_read
        ?(result.native_visibility?"true":"false"):"null";
    const char* total_json=output_complete?nullptr:"null";
    char total_buffer[32]{};
    if (output_complete) {
        snprintf(total_buffer,sizeof(total_buffer),"%d",result.total_raw_i32);
        total_json=total_buffer;
    }
    char mxcsr_before[32]="null",mxcsr_after_helpers[32]="null";
    char mxcsr_before_description[32]="null",mxcsr_after[32]="null";
    if (result.mxcsr_available)
        snprintf(mxcsr_before,sizeof(mxcsr_before),"%u",result.mxcsr_before);
    if (result.mxcsr_after_helpers_available)
        snprintf(mxcsr_after_helpers,sizeof(mxcsr_after_helpers),"%u",result.mxcsr_after_helpers);
    if (result.mxcsr_before_description_available)
        snprintf(mxcsr_before_description,sizeof(mxcsr_before_description),"%u",result.mxcsr_before_description);
    if (result.mxcsr_available)
        snprintf(mxcsr_after,sizeof(mxcsr_after),"%u",result.mxcsr_after);
    char message[14000]{};
    snprintf(message,sizeof(message),
        "{\"event\":\"native_alliance_inspection\",\"session_id\":\"%lu-%llx\","
        "\"query_id\":\"%.64s\",\"action_id\":\"take_on_debt\",\"family\":\"debt_quote\","
        "\"actor\":\"%.3s\",\"recipient\":\"%.3s\",\"phase\":\"initiate\","
        "\"date_raw\":%d,\"ui_selection_checked\":true,\"native_visibility\":%s,"
        "\"ui_enabled_gate_checked\":false,\"validity_called\":false,"
        "\"submitted\":false,\"full_rules_complete\":false,\"complete\":%s,"
        "\"reason_code\":\"%s\",\"native_debt_quote\":{"
        "\"schema\":\"native.debt_quote.v1\",\"read_only\":true,\"complete\":%s,"
        "\"context_stable\":%s,\"guards_verified\":%s,\"financial_inputs_read\":%s,"
        "\"mxcsr_before\":%s,\"mxcsr_after_helpers\":%s,"
        "\"mxcsr_before_description\":%s,\"mxcsr_after\":%s,"
        "\"mxcsr_model_compatible\":%s,\"mxcsr_controls_stable\":%s,"
        "\"mxcsr_daz_enabled\":%s,\"mxcsr_ftz_enabled\":%s,"
        "\"total_raw_i32\":%s,\"scale\":1000,"
        "\"basis\":\"native_take_on_debt_description_fold\",\"loans\":[%s],"
        "\"description_readable\":%s,\"description_truncated\":%s,"
        "\"description_encoding_known\":false,\"description_hex\":\"%s\","
        "\"description_cleanup_performed\":%s,\"description_cleanup_skipped\":%s,"
        "\"action_cleanup_performed\":%s}"
        ",\"frame_thread\":%lu}\n",
        static_cast<unsigned long>(GetCurrentProcessId()),
        static_cast<unsigned long long>(observation_creation),id?id:"",
        actor_tag?actor_tag:"",recipient_tag?recipient_tag:"",date,visibility,
        output_complete?"true":"false",reason_code?reason_code:"UNKNOWN",
        output_complete?"true":"false",result.context_stable?"true":"false",
        result.guards_verified?"true":"false",result.financial_inputs_read?"true":"false",
        mxcsr_before,mxcsr_after_helpers,mxcsr_before_description,mxcsr_after,
        result.mxcsr_model_compatible?"true":"false",
        result.mxcsr_controls_stable?"true":"false",
        result.daz_enabled?"true":"false",result.ftz_enabled?"true":"false",
        total_json,loans_json,result.description_readable?"true":"false",
        result.description_truncated?"true":"false",
        result.description_readable?result.description_hex:"",
        result.description_cleanup_performed?"true":"false",
        result.description_cleanup_skipped?"true":"false",
        result.action_cleanup_performed?"true":"false",
        static_cast<unsigned long>(GetCurrentThreadId()));
    line(message);
}

struct DebtQuoteActiveQueryScope {
    const char* previous;
    explicit DebtQuoteActiveQueryScope(const char* id) noexcept
        : previous(observation_active_query) { observation_active_query=id; }
    ~DebtQuoteActiveQueryScope() { observation_active_query=previous; }
};

static void debt_quote_query_run(const char* id,const char* actor_tag,
    const char* recipient_tag,uint64_t actor,uint64_t recipient,int32_t date) {
    DebtQuoteObservation result{};
    const char* reason="UNKNOWN";
    DebtQuoteContext before{},after_visibility{};
    DebtQuoteLoanInput before_loans[64]{};
    unsigned before_count=0;
    void* action=nullptr;
    NativeShortString description{};
    bool description_initialized=false;
    bool description_call_attempted=false;
    bool description_abi_returned=false;
    bool keep_quote=false;

    result.guards_verified=debt_quote_native_guards();
    if (!result.guards_verified) {
        reason="NATIVE_ROM_GUARD_FAILED";
        debt_quote_emit(id,actor_tag,recipient_tag,date,result,reason);
        return;
    }
    if (!debt_quote_context_read(actor_tag,recipient_tag,actor,recipient,date,before)) {
        reason="ACTOR_TARGET_OR_GAME_CONTEXT_INVALID";
        debt_quote_emit(id,actor_tag,recipient_tag,date,result,reason);
        return;
    }
    if (!debt_quote_family_slots_valid()) {
        result.guards_verified=false;
        reason="NATIVE_FAMILY_METHODS_CHANGED";
        debt_quote_emit(id,actor_tag,recipient_tag,date,result,reason);
        return;
    }

    DebtQuoteActiveQueryScope active_query_scope(id);
    if (!factory_query_visibility(actor,recipient,true,result.native_visibility,
            debt_quote_query_methods)) {
        reason="NATIVE_VISIBILITY_UNAVAILABLE";
        debt_quote_emit(id,actor_tag,recipient_tag,date,result,reason);
        return;
    }
    result.visibility_read=true;
    if (!debt_quote_context_read(actor_tag,recipient_tag,actor,recipient,date,after_visibility)
        || !debt_quote_context_equal(before,after_visibility)) {
        result.context_stable=false;
        reason="CONTEXT_CHANGED_DURING_VISIBILITY";
        debt_quote_emit(id,actor_tag,recipient_tag,date,result,reason);
        return;
    }
    result.context_stable=true;
    if (!result.native_visibility) {
        // A false selector result is terminal: no factory object or financial
        // field is read on this path.
        reason="NATIVE_VISIBILITY_FALSE";
        debt_quote_emit(id,actor_tag,recipient_tag,date,result,reason);
        return;
    }

    action=factory_query_create(actor,recipient,true,debt_quote_query_methods);
    if (!action) {
        reason="NATIVE_FACTORY_UNAVAILABLE";
        debt_quote_emit(id,actor_tag,recipient_tag,date,result,reason);
        return;
    }

    do {
        const uintptr_t action_address=reinterpret_cast<uintptr_t>(action);
        uintptr_t action_vtable=0;
        int32_t action_marker=0;
        uint64_t action_actor=0,action_actor_copy=0,action_recipient=0;
        unsigned char action_mode=0;
        const bool action_bound=debt_quote_read_at(action_address,0,action_vtable)
            && action_vtable==base+debt_quote_query_methods.vtable_rva
            && debt_quote_read_at(action_address,8,action_marker) && action_marker==0x165
            && debt_quote_read_at(action_address,0x10,action_actor) && action_actor==actor
            && debt_quote_read_at(action_address,0x18,action_actor_copy) && action_actor_copy==actor
            && debt_quote_read_at(action_address,0x20,action_recipient) && action_recipient==recipient
            && debt_quote_read_at(action_address,0x38,action_mode) && action_mode==1;
        DebtQuoteContext after_create{};
        if (!action_bound
            || !debt_quote_context_read(actor_tag,recipient_tag,actor,recipient,date,after_create)
            || !debt_quote_context_equal(before,after_create)) {
            result.context_stable=false;
            reason=action_bound?"CONTEXT_CHANGED_DURING_FACTORY":"FACTORY_OBJECT_BINDING_MISMATCH";
            break;
        }

        result.mxcsr_before=_mm_getcsr();
        result.mxcsr_available=true;
        result.mxcsr_controls_stable=true;
        result.daz_enabled=(result.mxcsr_before&0x0040u)!=0;
        result.ftz_enabled=(result.mxcsr_before&0x8000u)!=0;
        result.mxcsr_model_compatible=debt_quote_mxcsr_supported(result.mxcsr_before);
        if (!result.mxcsr_model_compatible) {
            reason="MXCSR_MODE_UNSUPPORTED";
            result.mxcsr_after=result.mxcsr_before;
            break;
        }

        // Mark the path as financially sampled before attempting the bounded
        // list read, so failures never appear equivalent to visibility=false.
        result.financial_inputs_read=true;
        if (!debt_quote_capture_loans(before.recipient_country,before_loans,before_count)) {
            reason="LOAN_LIST_UNREADABLE_OR_INVALID";
            result.mxcsr_after=_mm_getcsr();
            result.mxcsr_controls_stable=((result.mxcsr_before^result.mxcsr_after)&0xffc0u)==0;
            break;
        }

        uint32_t total_bits=0;
        bool interest_complete=true;
        using Interest=uint32_t* (*)(void*,uint32_t*);
        const auto interest_function=reinterpret_cast<Interest>(base+0x86b4e0);
        for (unsigned index=0;index<before_count;++index) {
            uint32_t interest_bits=0;
            uint32_t* output=&interest_bits;
            uint32_t* returned=interest_function(
                reinterpret_cast<void*>(before_loans[index].record),output);
            if (returned!=output) { interest_complete=false; break; }
            memcpy(&result.interest_raw_i32[index],&interest_bits,sizeof(interest_bits));
            uint32_t principal_bits=0;
            memcpy(&principal_bits,&before_loans[index].principal_i32,sizeof(principal_bits));
            const uint32_t row_raw=principal_bits*1000u+interest_bits;
            total_bits+=row_raw;
        }
        result.mxcsr_after_helpers=_mm_getcsr();
        result.mxcsr_after_helpers_available=true;
        result.mxcsr_controls_stable=((result.mxcsr_before^result.mxcsr_after_helpers)&0xffc0u)==0;
        if (!interest_complete || !result.mxcsr_controls_stable) {
            reason=interest_complete?"MXCSR_CHANGED_DURING_INTEREST_HELPERS":"INTEREST_HELPER_FAILED";
            result.mxcsr_after=result.mxcsr_after_helpers;
            break;
        }

        description.capacity=15;
        description_initialized=true;
        result.mxcsr_before_description=_mm_getcsr();
        result.mxcsr_before_description_available=true;
        if (((result.mxcsr_before_description^result.mxcsr_before)&0xffc0u)!=0) {
            reason="MXCSR_CHANGED_BEFORE_DESCRIPTION";
            result.mxcsr_after=_mm_getcsr();
            break;
        }
        using Description=NativeShortString* (*)(void*,NativeShortString*);
        const auto description_function=reinterpret_cast<Description>(base+0x7c2eb0);
        description_call_attempted=true;
        NativeShortString* description_result=description_function(action,&description);
        description_abi_returned=description_result==&description;
        result.mxcsr_after=_mm_getcsr();
        result.mxcsr_controls_stable=result.mxcsr_controls_stable
            && (((result.mxcsr_before_description^result.mxcsr_after)&0xffc0u)==0);
        if (description_abi_returned
            && debt_quote_description_shape_valid(description))
            result.description_readable=debt_quote_hex_description(description,
                result.description_hex,result.description_truncated);
        if (description_result!=&description || !result.description_readable
            || !result.mxcsr_controls_stable) {
            reason=description_result!=&description?"DESCRIPTION_ABI_MISMATCH":
                !result.mxcsr_controls_stable?"MXCSR_CHANGED_DURING_DESCRIPTION":"DESCRIPTION_UNREADABLE";
            break;
        }

        uintptr_t action_vtable_after=0;
        int32_t action_marker_after=0;
        uint64_t action_actor_after=0,action_actor_copy_after=0,action_recipient_after=0;
        unsigned char action_mode_after=0;
        if (!debt_quote_read_at(action_address,0,action_vtable_after)
            || action_vtable_after!=base+debt_quote_query_methods.vtable_rva
            || !debt_quote_read_at(action_address,8,action_marker_after)
            || action_marker_after!=0x165
            || !debt_quote_read_at(action_address,0x10,action_actor_after)
            || action_actor_after!=actor
            || !debt_quote_read_at(action_address,0x18,action_actor_copy_after)
            || action_actor_copy_after!=actor
            || !debt_quote_read_at(action_address,0x20,action_recipient_after)
            || action_recipient_after!=recipient
            || !debt_quote_read_at(action_address,0x38,action_mode_after)
            || action_mode_after!=1) {
            reason="FACTORY_OBJECT_CHANGED_DURING_QUERY";
            break;
        }

        DebtQuoteLoanInput after_loans[64]{};
        unsigned after_count=0;
        DebtQuoteContext after_native{};
        if (!debt_quote_capture_loans(before.recipient_country,after_loans,after_count)
            || !debt_quote_loans_equal(before_loans,before_count,after_loans,after_count)
            || !debt_quote_context_read(actor_tag,recipient_tag,actor,recipient,date,after_native)
            || !debt_quote_context_equal(before,after_native)) {
            result.context_stable=false;
            reason="CONTEXT_OR_LOAN_INPUTS_CHANGED";
            break;
        }
        result.context_stable=true;
        result.loan_count=before_count;
        for (unsigned index=0;index<before_count;++index)
            result.loans[index]=before_loans[index];
        memcpy(&result.total_raw_i32,&total_bits,sizeof(total_bits));
        result.total_raw_available=true;
        result.complete=true;
        reason="COMPLETE_READ_ONLY_QUOTE";
        keep_quote=true;
    } while (false);

    if (description_initialized
        && (!description_call_attempted || description_abi_returned)
        && debt_quote_description_shape_valid(description)) {
        reinterpret_cast<void (*)(void*)>(base+0x95660)(&description);
        result.description_cleanup_performed=true;
    } else if (description_initialized) {
        // Do not pass a malformed size/capacity/heap-pointer representation to
        // the native string destructor. Ownership cleanup for corrupted
        // native return objects cannot be proven safe without SEH/allocator
        // provenance, so this fail-closed branch records the skipped cleanup.
        result.description_cleanup_skipped=true;
    }
    if (action) {
        reinterpret_cast<void* (*)(void*,unsigned)>(base+0x129450)(action,1);
        result.action_cleanup_performed=true;
    }

    if (action) {
        DebtQuoteContext final_context{};
        DebtQuoteLoanInput final_loans[64]{};
        unsigned final_count=0;
        const bool final_stable=debt_quote_context_read(actor_tag,recipient_tag,
                actor,recipient,date,final_context)
            && debt_quote_context_equal(before,final_context)
            && (!result.financial_inputs_read
                || (debt_quote_capture_loans(before.recipient_country,final_loans,final_count)
                    && debt_quote_loans_equal(before_loans,before_count,final_loans,final_count)));
        result.context_stable=result.context_stable && final_stable;
        if (!final_stable) {
            result.complete=false;
            result.total_raw_available=false;
            result.loan_count=0;
            result.description_readable=false;
            result.description_truncated=false;
            result.description_hex[0]='\0';
            keep_quote=false;
            reason="CONTEXT_CHANGED_DURING_CLEANUP";
        }
    }
    if (!keep_quote) {
        result.complete=false;
        result.total_raw_available=false;
        result.loan_count=0;
        result.description_readable=false;
        result.description_truncated=false;
        result.description_hex[0]='\0';
    }
    if (result.mxcsr_available) {
        result.mxcsr_after=_mm_getcsr();
        result.mxcsr_controls_stable=result.mxcsr_controls_stable
            && (((result.mxcsr_before^result.mxcsr_after)&0xffc0u)==0);
        if (!result.mxcsr_controls_stable && result.complete) {
            result.complete=false;
            result.total_raw_available=false;
            result.loan_count=0;
            result.description_readable=false;
            result.description_truncated=false;
            result.description_hex[0]='\0';
            keep_quote=false;
            reason="MXCSR_CHANGED_DURING_CLEANUP";
        }
    }
    if (!result.complete && result.visibility_read && result.native_visibility
        && result.financial_inputs_read) {
        // No partial loan or amount values escape an incomplete observation.
        result.total_raw_available=false;
        result.loan_count=0;
    }
    debt_quote_emit(id,actor_tag,recipient_tag,date,result,reason);
}
#endif // BRIDGE_DEBT_QUOTE_QUERY
