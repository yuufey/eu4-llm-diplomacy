#include "../information-current-country-control-plan.h"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

namespace plan=information::battle::current_country_control_plan;

struct SparseReader {
    struct Region {
        plan::Address rva{};
        std::vector<unsigned char> bytes;
    };

    plan::Address base=UINT64_C(0x140000000);
    std::vector<Region> regions;

    template<class Range>
    void add(plan::Address rva,const Range& bytes) {
        regions.push_back(Region{rva,std::vector<unsigned char>(bytes.begin(),bytes.end())});
    }

    bool read(plan::Address address,unsigned char* out,std::size_t size) noexcept {
        if (size==0) return true;
        if (address<base) return false;
        const auto rva=address-base;
        for (const auto& region:regions) {
            if (rva<region.rva) continue;
            const auto offset=rva-region.rva;
            if (offset<=region.bytes.size() && size<=region.bytes.size()-offset) {
                std::memcpy(out,region.bytes.data()+static_cast<std::size_t>(offset),size);
                return true;
            }
        }
        return false;
    }

    void seed() {
        regions.clear();
        add(plan::kNativeGuardRva,plan::kNativeGuardBytes);
        add(plan::kPdataRowRva,plan::kPdataRowBytes);
        add(plan::kUnwindInfoRva,plan::kUnwindInfoBytes);
    }

    bool flip(plan::Address rva,std::size_t offset=0) {
        for (auto& region:regions) {
            if (rva<region.rva) continue;
            const auto index=rva-region.rva+offset;
            if (index<region.bytes.size()) {
                region.bytes[static_cast<std::size_t>(index)]^=0x01u;
                return true;
            }
        }
        return false;
    }
};

struct Checks {
    int passed=0;
    int failed=0;

    void expect(const char* name,bool actual,bool wanted=true) {
        if (actual==wanted) {
            ++passed;
            std::cout<<"PASS "<<name<<"\n";
        } else {
            ++failed;
            std::cout<<"FAIL "<<name<<" actual="<<(actual?"true":"false")
                     <<" wanted="<<(wanted?"true":"false")<<"\n";
        }
    }
};

int main() {
    Checks checks;
    SparseReader reader;
    reader.seed();
    checks.expect("valid-preferred-base",
                  plan::guard(reader,reader.base,plan::kSizeOfImage));

    reader.seed();
    checks.expect("bad-base-too-low",
                  plan::guard(reader,0x1000u,plan::kSizeOfImage),false);
    checks.expect("bad-base-overflow",
                  plan::guard(reader,UINT64_C(0x7ffffffff000),plan::kSizeOfImage),false);
    checks.expect("bad-image-zero",
                  plan::guard(reader,reader.base,0),false);
    checks.expect("bad-image-truncated",
                  plan::guard(reader,reader.base,plan::kSizeOfImage-1u),false);
    checks.expect("bad-image-larger",
                  plan::guard(reader,reader.base,plan::kSizeOfImage+1u),false);

    reader.seed();
    checks.expect("one-byte-code-change-is-rejected",reader.flip(plan::kNativeGuardRva,777)
                  && !plan::guard(reader,reader.base,plan::kSizeOfImage));
    reader.seed();
    checks.expect("pdata-begin-mismatch-is-rejected",reader.flip(plan::kPdataRowRva)
                  && !plan::guard(reader,reader.base,plan::kSizeOfImage));
    reader.seed();
    checks.expect("pdata-end-mismatch-is-rejected",reader.flip(plan::kPdataRowRva,4)
                  && !plan::guard(reader,reader.base,plan::kSizeOfImage));
    reader.seed();
    checks.expect("pdata-unwind-rva-mismatch-is-rejected",reader.flip(plan::kPdataRowRva,8)
                  && !plan::guard(reader,reader.base,plan::kSizeOfImage));
    reader.seed();
    checks.expect("unwind-byte-change-is-rejected",reader.flip(plan::kUnwindInfoRva,31)
                  && !plan::guard(reader,reader.base,plan::kSizeOfImage));
    reader.seed();
    checks.expect("pdata-only-tail-byte-is-guarded",reader.flip(plan::kNativeGuardEndRva-1u)
                  && !plan::guard(reader,reader.base,plan::kSizeOfImage));

    reader.seed();
    reader.base=UINT64_C(0x180000000);
    checks.expect("aslr-shifted-base-keeps-rva-bytes-valid",
                  plan::guard(reader,reader.base,plan::kSizeOfImage));

    reader.seed();
    reader.regions.erase(reader.regions.begin());
    checks.expect("missing-guard-region-is-rejected",
                  plan::guard(reader,reader.base,plan::kSizeOfImage),false);

    std::cout<<"SUMMARY passed="<<checks.passed<<" failed="<<checks.failed<<"\n";
    return checks.failed==0?0:1;
}
