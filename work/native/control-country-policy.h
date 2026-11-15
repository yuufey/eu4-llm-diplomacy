#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>

namespace bridge::control_country_policy {

constexpr std::size_t kMaxCountries=32;
constexpr std::size_t kTagLength=3;
constexpr std::size_t kMaxSessionIdLength=27;
constexpr std::size_t kMaxWireBytes=384;

inline bool valid_tag(const char* value) noexcept {
    if (!value || value[0]==0 || value[1]==0 || value[2]==0 || value[3]!=0)
        return false;
    for (std::size_t index=0;index<kTagLength;++index) {
        const char current=value[index];
        if (!((current>='A' && current<='Z') || (current>='0' && current<='9')))
            return false;
    }
    return true;
}

inline bool tag_matches_handle(const char* tag,std::uint64_t handle) noexcept {
    return valid_tag(tag)
        && static_cast<unsigned char>(tag[0])==static_cast<unsigned char>(handle&0xffu)
        && static_cast<unsigned char>(tag[1])==static_cast<unsigned char>((handle>>8)&0xffu)
        && static_cast<unsigned char>(tag[2])==static_cast<unsigned char>((handle>>16)&0xffu);
}

inline bool tag_from_handle(std::uint64_t handle,char (&tag)[4]) noexcept {
    tag[0]=static_cast<char>(handle&0xffu);
    tag[1]=static_cast<char>((handle>>8)&0xffu);
    tag[2]=static_cast<char>((handle>>16)&0xffu);
    tag[3]=0;
    return valid_tag(tag);
}

struct CountrySet {
    char values[kMaxCountries][4]{};
    std::size_t count=0;

    void clear() noexcept {
        std::memset(values,0,sizeof(values));
        count=0;
    }

    bool contains(const char* tag) const noexcept {
        if (!valid_tag(tag)) return false;
        for (std::size_t index=0;index<count;++index)
            if (std::memcmp(values[index],tag,4)==0) return true;
        return false;
    }

    bool add(const char* tag) noexcept {
        if (!valid_tag(tag) || count>=kMaxCountries || contains(tag)) return false;
        std::memcpy(values[count++],tag,4);
        return true;
    }

    const char* at(std::size_t index) const noexcept {
        return index<count?values[index]:nullptr;
    }
};

struct Request {
    char session_id[kMaxSessionIdLength+1]{};
    std::uint64_t revision=0;
    CountrySet countries{};
};

enum class ParseError : std::uint8_t {
    ok,
    null_input,
    invalid_length,
    invalid_line_ending,
    invalid_field_count,
    invalid_prefix,
    invalid_session,
    invalid_revision,
    invalid_country_list,
    invalid_country,
    duplicate_country,
    too_many_countries
};

struct ParseResult {
    ParseError error=ParseError::ok;
    constexpr bool ok() const noexcept { return error==ParseError::ok; }
};

inline const char* parse_error_name(ParseError error) noexcept {
    switch (error) {
    case ParseError::ok: return "ok";
    case ParseError::null_input: return "null_input";
    case ParseError::invalid_length: return "invalid_length";
    case ParseError::invalid_line_ending: return "invalid_line_ending";
    case ParseError::invalid_field_count: return "invalid_field_count";
    case ParseError::invalid_prefix: return "invalid_prefix";
    case ParseError::invalid_session: return "invalid_session";
    case ParseError::invalid_revision: return "invalid_revision";
    case ParseError::invalid_country_list: return "invalid_country_list";
    case ParseError::invalid_country: return "invalid_country";
    case ParseError::duplicate_country: return "duplicate_country";
    case ParseError::too_many_countries: return "too_many_countries";
    }
    return "unknown";
}

struct Field {
    const char* data=nullptr;
    std::size_t size=0;
};

inline bool equals(Field field,const char* expected) noexcept {
    if (!field.data || !expected) return false;
    const std::size_t length=std::strlen(expected);
    return length==field.size && std::memcmp(field.data,expected,length)==0;
}

inline bool copy_field(char* destination,std::size_t capacity,Field field) noexcept {
    if (!destination || !capacity || !field.data || field.size>=capacity) return false;
    std::memcpy(destination,field.data,field.size);
    destination[field.size]=0;
    return true;
}

inline bool parse_session(Field field,char (&session)[kMaxSessionIdLength+1]) noexcept {
    if (!field.data || field.size==0 || field.size>kMaxSessionIdLength) return false;
    std::size_t dash=field.size;
    for (std::size_t index=0;index<field.size;++index) {
        const char value=field.data[index];
        if (value=='-') {
            if (dash!=field.size) return false;
            dash=index;
        }
    }
    if (dash==0 || dash>10 || dash==field.size || dash+1>=field.size
        || field.size-dash-1>16) return false;
    std::uint32_t pid=0;
    for (std::size_t index=0;index<dash;++index) {
        const char value=field.data[index];
        if (value<'0' || value>'9') return false;
        const unsigned digit=static_cast<unsigned>(value-'0');
        if (pid>(std::numeric_limits<std::uint32_t>::max()-digit)/10u)
            return false;
        pid=pid*10u+digit;
    }
    std::uint64_t creation=0;
    for (std::size_t index=dash+1;index<field.size;++index) {
        const char value=field.data[index];
        unsigned digit=0;
        if (value>='0' && value<='9') digit=static_cast<unsigned>(value-'0');
        else if (value>='a' && value<='f') digit=static_cast<unsigned>(value-'a'+10);
        else return false;
        if (creation>(std::numeric_limits<std::uint64_t>::max()-digit)/16u)
            return false;
        creation=creation*16u+digit;
    }
    if (!pid || !creation) return false;
    return copy_field(session,sizeof(session),field);
}

inline bool parse_revision(Field field,std::uint64_t& revision) noexcept {
    if (!field.data || field.size==0) return false;
    std::uint64_t result=0;
    for (std::size_t index=0;index<field.size;++index) {
        const char value=field.data[index];
        if (value<'0' || value>'9') return false;
        const unsigned digit=static_cast<unsigned>(value-'0');
        if (result>(std::numeric_limits<std::uint64_t>::max()-digit)/10u)
            return false;
        result=result*10u+digit;
    }
    if (result==0) return false;
    revision=result;
    return true;
}

inline ParseResult parse_request(const char* bytes,std::size_t length,
    Request& output) noexcept {
    output=Request{};
    if (!bytes) return ParseResult{ParseError::null_input};
    if (length==0 || length>kMaxWireBytes) return ParseResult{ParseError::invalid_length};
    if (bytes[length-1]!='\n') return ParseResult{ParseError::invalid_line_ending};
    std::size_t end=length-1;
    for (std::size_t index=0;index<end;++index)
        if (bytes[index]=='\0' || bytes[index]=='\n' || bytes[index]=='\r')
            return ParseResult{ParseError::invalid_line_ending};

    Field fields[4]{};
    std::size_t field_count=0,start=0;
    for (std::size_t index=0;index<=end;++index) {
        if (index!=end && bytes[index]!='\t') continue;
        if (field_count>=4) return ParseResult{ParseError::invalid_field_count};
        fields[field_count++]={bytes+start,index-start};
        start=index+1;
    }
    if (field_count!=4) return ParseResult{ParseError::invalid_field_count};
    if (!equals(fields[0],"EU4CONTROL1")) return ParseResult{ParseError::invalid_prefix};
    if (!parse_session(fields[1],output.session_id)) return ParseResult{ParseError::invalid_session};
    if (!parse_revision(fields[2],output.revision)) return ParseResult{ParseError::invalid_revision};
    if (equals(fields[3],"-")) return ParseResult{ParseError::ok};
    if (!fields[3].size) return ParseResult{ParseError::invalid_country_list};

    std::size_t country_start=0;
    for (std::size_t index=0;index<=fields[3].size;++index) {
        if (index!=fields[3].size && fields[3].data[index]!=',') continue;
        const std::size_t country_length=index-country_start;
        if (country_length!=kTagLength) return ParseResult{ParseError::invalid_country};
        char tag[4]{};
        std::memcpy(tag,fields[3].data+country_start,kTagLength);
        if (!valid_tag(tag)) return ParseResult{ParseError::invalid_country};
        if (output.countries.count>=kMaxCountries)
            return ParseResult{ParseError::too_many_countries};
        if (output.countries.contains(tag)) return ParseResult{ParseError::duplicate_country};
        if (!output.countries.add(tag)) return ParseResult{ParseError::invalid_country};
        country_start=index+1;
    }
    return ParseResult{ParseError::ok};
}

enum class ApplyError : std::uint8_t {
    ok,
    invalid_session,
    stale_revision
};

struct PolicyState {
    CountrySet countries{};
    std::uint64_t revision=0;

    PolicyState() noexcept { countries.add("FRA"); }

    ApplyError apply(const Request& request,const char* expected_session) noexcept {
        if (!expected_session || std::strcmp(request.session_id,expected_session)!=0)
            return ApplyError::invalid_session;
        if (!request.revision || request.revision<=revision)
            return ApplyError::stale_revision;
        countries=request.countries;
        revision=request.revision;
        return ApplyError::ok;
    }
};

} // namespace bridge::control_country_policy
