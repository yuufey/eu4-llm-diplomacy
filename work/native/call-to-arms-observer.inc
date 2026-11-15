// Copy incoming CallAction values before the generic executor consumes them.
// The existing executor owns native forwarding. This observer only reads and queues.
#pragma once

#include "declarewar-payload.h"

namespace bridge_call_to_arms {

constexpr uintptr_t kVtableRva=0x1c800b0;
constexpr unsigned kCapacity=64;
struct Event {
    uint64_t sequence=0,actor=0,recipient=0,versus=0;
    int32_t observed_date=0,date28=0,date2c=0,token3c=0,call_type=0;
    unsigned char flags[7]{};
    bridge::declarewar_payload::WarPayloadVector enemies{};
    bool versus_verified=false,enemies_verified=true;
};
static SRWLOCK queue_lock=SRWLOCK_INIT;
static Event events[kCapacity]{};
static unsigned head=0,size=0;
static volatile LONG64 sequence=0;
static volatile LONG dropped=0;

static void observe(const ProtocolWrapperShape& wrapper) noexcept {
    if (!wrapper.identity || !wrapper.readable) return;
    const uintptr_t action=wrapper.action;
    uintptr_t table=0;
    if (!read(action,table) || table!=base+kVtableRva) return;
    Event event{};
    int32_t state=0,discriminator=0;
    uintptr_t country=0;
    if (!read(action+0x08,discriminator) || discriminator!=0x165
        || !read(action+0x10,event.actor) || !read(action+0x20,event.recipient)
        || !read(action+0x34,state) || state!=0
        || !observation_country_handle(event.actor)
        || !bridge_alliance_inbound_detail::inbound_read_country(event.actor,country)
        || !bridge_alliance_inbound_detail::inbound_is_controlled(event.recipient,country)
        || event.actor==event.recipient) return;
    uintptr_t game=0;
    if (!read(base+0x233fe58,game) || !read(game+0x1dd0,event.observed_date)
        || !read(action+0x28,event.date28) || !read(action+0x2c,event.date2c)
        || !read(action+0x3c,event.token3c) || !read(action+0x40,event.versus)
        || !read(action+0x4c,event.call_type)) {
        InterlockedIncrement(&dropped); return;
    }
    constexpr uintptr_t offsets[]={0x48,0x49,0x50,0x51,0x52,0x53,0x56};
    for (unsigned index=0;index<7;++index) {
        if (!read(action+offsets[index],event.flags[index])) {
            InterlockedIncrement(&dropped); return;
        }
    }
    auto reader=[](uintptr_t address,auto& value)->bool { return read(address,value); };
    // Only begin/end are needed by the native writer. Reuse the existing
    // bounded vector reader with end as its upper capacity boundary.
    constexpr bridge::declarewar_payload::WarNativeVectorLayout layout{0x58,0x60,0x60};
    if (!bridge::declarewar_payload::war_capture_native_u64_vector(reader,action,layout,event.enemies)) {
        InterlockedIncrement(&dropped); return;
    }
    event.versus_verified=observation_country_handle(event.versus)
        && bridge_alliance_inbound_detail::inbound_read_country(event.versus,country);
    for (uint32_t index=0;index<event.enemies.count;++index) {
        if (!observation_country_handle(event.enemies.values[index])
            || !bridge_alliance_inbound_detail::inbound_read_country(event.enemies.values[index],country)) {
            event.enemies_verified=false;
        }
    }
    event.sequence=static_cast<uint64_t>(InterlockedIncrement64(&sequence));
    if (!TryAcquireSRWLockExclusive(&queue_lock)) {
        InterlockedIncrement(&dropped); return;
    }
    if (size==kCapacity) {
        ReleaseSRWLockExclusive(&queue_lock);
        InterlockedIncrement(&dropped); return;
    }
    events[(head+size)%kCapacity]=event;
    ++size;
    ReleaseSRWLockExclusive(&queue_lock);
}

static void flush() noexcept {
    for (unsigned index=0;index<kCapacity;++index) {
        Event event{};
        if (!TryAcquireSRWLockExclusive(&queue_lock)) return;
        if (!size) { ReleaseSRWLockExclusive(&queue_lock); break; }
        event=events[head]; head=(head+1)%kCapacity; --size;
        ReleaseSRWLockExclusive(&queue_lock);
        char actor[4]{},recipient[4]{},versus[4]="---";
        bridge_alliance_inbound_detail::inbound_tag(actor,event.actor);
        bridge_alliance_inbound_detail::inbound_tag(recipient,event.recipient);
        if (event.versus_verified) bridge_alliance_inbound_detail::inbound_tag(versus,event.versus);
        char enemies[1024]{};
        size_t used=0;
        if (event.enemies_verified) {
            for (uint32_t i=0;i<event.enemies.count;++i) {
                char tag[4]{};
                bridge_alliance_inbound_detail::inbound_tag(tag,event.enemies.values[i]);
                const int written=snprintf(enemies+used,sizeof(enemies)-used,"%s\"%.3s\"",i?",":"",tag);
                if (written<0 || static_cast<size_t>(written)>=sizeof(enemies)-used) break;
                used+=static_cast<size_t>(written);
            }
        }
        char message[4096]{};
        snprintf(message,sizeof(message),
            "{\"event\":\"native_call_to_arms_observed\",\"session_id\":\"%lu-%llx\",\"observation_id\":%llu,\"action_id\":\"call_to_arms\",\"actor\":\"%.3s\",\"recipient\":\"%.3s\",\"date_raw\":%d,\"native_date28\":%d,\"native_date2c\":%d,\"native_token3c\":%d,\"versus\":\"%.3s\",\"versus_verified\":%s,\"call_type_raw\":%d,\"flags_raw\":[%u,%u,%u,%u,%u,%u,%u],\"specific_enemies\":[%s],\"specific_enemies_count\":%u,\"specific_enemies_verified\":%s,\"capture_stage\":\"before_native_executor\",\"recipient_verified\":true,\"ai_response_held\":false}\n",
            static_cast<unsigned long>(GetCurrentProcessId()),static_cast<unsigned long long>(observation_creation),
            static_cast<unsigned long long>(event.sequence),actor,recipient,event.observed_date,event.date28,event.date2c,event.token3c,
            versus,event.versus_verified?"true":"false",event.call_type,
            static_cast<unsigned>(event.flags[0]),static_cast<unsigned>(event.flags[1]),static_cast<unsigned>(event.flags[2]),
            static_cast<unsigned>(event.flags[3]),static_cast<unsigned>(event.flags[4]),static_cast<unsigned>(event.flags[5]),
            static_cast<unsigned>(event.flags[6]),enemies,event.enemies.count,event.enemies_verified?"true":"false");
        line(message);
    }
    const LONG lost=InterlockedExchange(&dropped,0);
    if (lost) {
        char message[256]{};
        snprintf(message,sizeof(message),"{\"event\":\"native_call_to_arms_drop\",\"session_id\":\"%lu-%llx\",\"dropped\":%ld}\n",
            static_cast<unsigned long>(GetCurrentProcessId()),static_cast<unsigned long long>(observation_creation),static_cast<long>(lost));
        line(message);
    }
}
} // namespace bridge_call_to_arms
