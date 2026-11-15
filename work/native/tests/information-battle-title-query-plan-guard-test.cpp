#include "../information-battle-title-query-plan.h"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

namespace plan=information::battle::title_query_plan;

struct BoundedReader {
    plan::Address game_base=UINT64_C(0x100000000);
    plan::Address plugin_base=UINT64_C(0x200000000);
    std::vector<unsigned char> game;
    std::vector<unsigned char> plugin;

    BoundedReader():game(0x03000000u,0),plugin(plan::kPluginSize,0) {}

    bool read(plan::Address address,unsigned char* out,std::size_t size) noexcept {
        if (size==0) return true;
        if (address>=game_base) {
            const auto offset=address-game_base;
            if (offset<=game.size() && size<=game.size()-offset) {
                std::memcpy(out,game.data()+static_cast<std::size_t>(offset),size);
                return true;
            }
        }
        if (address>=plugin_base) {
            const auto offset=address-plugin_base;
            if (offset<=plugin.size() && size<=plugin.size()-offset) {
                std::memcpy(out,plugin.data()+static_cast<std::size_t>(offset),size);
                return true;
            }
        }
        return false;
    }

    template<class Container>
    void copy_game(plan::Address rva,const Container& bytes) {
        std::copy(bytes.begin(),bytes.end(),game.begin()+static_cast<std::size_t>(rva));
    }

    template<class Container>
    void copy_plugin(plan::Address rva,const Container& bytes) {
        std::copy(bytes.begin(),bytes.end(),plugin.begin()+static_cast<std::size_t>(rva));
    }

    template<class T>
    void put_game(plan::Address rva,const T& value) {
        std::memcpy(game.data()+static_cast<std::size_t>(rva),&value,sizeof(value));
    }

    template<class T>
    void put_plugin(plan::Address rva,const T& value) {
        std::memcpy(plugin.data()+static_cast<std::size_t>(rva),&value,sizeof(value));
    }

    void vanilla() {
        std::fill(game.begin(),game.end(),0);
        std::fill(plugin.begin(),plugin.end(),0);
        copy_game(plan::kHelperRva,plan::kHelperBytes);
        copy_game(plan::kDestructorRva,plan::kDestructorBytes);
    }

    void plugin_image() {
        vanilla();
        copy_plugin(plan::kPluginBridgeRva,plan::kPluginBridgeBytes);
        copy_plugin(plan::kPluginHelperRva,plan::kPluginHelperBytes);
        copy_plugin(plan::kPluginUnwindRva,plan::kPluginUnwindBytes);

        const plan::Address target=plugin_base+plan::kPluginTargetRva;
        const plan::Address continuation=game_base+plan::kPluginReturnGameRva;
        put_game(plan::kHelperRva+plan::kHelperPluginPatchOffset+0u,0xffu);
        put_game(plan::kHelperRva+plan::kHelperPluginPatchOffset+1u,0x25u);
        const std::uint32_t zero=0;
        put_game(plan::kHelperRva+plan::kHelperPluginPatchOffset+2u,zero);
        std::memcpy(game.data()+static_cast<std::size_t>(plan::kHelperRva+
                    plan::kHelperPluginPatchOffset+6u),&target,sizeof(target));
        put_game(plan::kHelperRva+plan::kHelperPluginPatchOffset+6u,target);
        put_game(plan::kHelperRva+plan::kHelperPluginPatchOffset+0u,0xffu);
        put_game(plan::kHelperRva+plan::kHelperPluginPatchOffset+1u,0x25u);
        put_plugin(plan::kPluginCallSlotRva,plugin_base+plan::kPluginHelperRva);
        put_plugin(plan::kPluginReturnSlotRva,continuation);
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
    BoundedReader reader;
    Checks checks;
    const auto base=reader.game_base;
    const auto plugin=reader.plugin_base;
    const auto image_size=reader.game.size();

    reader.vanilla();
    checks.expect("vanilla",plan::guard(reader,base,image_size));
    checks.expect("vanilla-explicit-no-plugin",plan::guard(reader,base,image_size,0,0));
    checks.expect("zero-image",plan::guard(reader,base,0),false);
    checks.expect("small-image",plan::guard(reader,base,plan::kDestructorRva+plan::kDestructorBytes.size()-1u),false);
    checks.expect("bad-game-base",plan::guard(reader,0x1000u,image_size),false);
    checks.expect("plugin-size-without-base",plan::guard(reader,base,image_size,0,plan::kPluginSize),false);

    reader.plugin_image();
    checks.expect("known-plugin",plan::guard(reader,base,image_size,plugin,plan::kPluginSize));
    reader.copy_game(plan::kHelperRva,plan::kHelperBytes);
    checks.expect("plugin-bound-vanilla-helper",plan::guard(reader,base,image_size,plugin,plan::kPluginSize),false);
    reader.plugin_image();
    checks.expect("wrong-plugin-size",plan::guard(reader,base,image_size,plugin,plan::kPluginSize-1u),false);
    checks.expect("bad-plugin-base",plan::guard(reader,base,image_size,0x1000u,plan::kPluginSize),false);
    checks.expect("plugin-address-overflow",plan::guard(reader,base,image_size,
                                                        UINT64_C(0x7ffffffff000),plan::kPluginSize),false);

    reader.game[static_cast<std::size_t>(plan::kHelperRva)]^=1u;
    checks.expect("wrong-helper-prefix",plan::guard(reader,base,image_size,plugin,plan::kPluginSize),false);
    reader.plugin_image();
    reader.game[static_cast<std::size_t>(plan::kHelperRva+plan::kHelperPluginPatchOffset+6u)]^=1u;
    checks.expect("wrong-helper-plugin-target",plan::guard(reader,base,image_size,plugin,plan::kPluginSize),false);
    reader.plugin_image();
    reader.game[static_cast<std::size_t>(plan::kDestructorRva)]^=1u;
    checks.expect("wrong-destructor",plan::guard(reader,base,image_size,plugin,plan::kPluginSize),false);
    reader.plugin_image();

    reader.plugin[static_cast<std::size_t>(plan::kPluginBridgeRva)]^=1u;
    checks.expect("wrong-plugin-bridge",plan::guard(reader,base,image_size,plugin,plan::kPluginSize),false);
    reader.plugin_image();
    reader.plugin[static_cast<std::size_t>(plan::kPluginHelperRva)]^=1u;
    checks.expect("wrong-plugin-helper",plan::guard(reader,base,image_size,plugin,plan::kPluginSize),false);
    reader.plugin_image();
    reader.plugin[static_cast<std::size_t>(plan::kPluginUnwindRva)]^=1u;
    checks.expect("wrong-plugin-unwind",plan::guard(reader,base,image_size,plugin,plan::kPluginSize),false);
    reader.plugin_image();
    ++reader.plugin[static_cast<std::size_t>(plan::kPluginCallSlotRva)];
    checks.expect("wrong-plugin-call-slot",plan::guard(reader,base,image_size,plugin,plan::kPluginSize),false);
    reader.plugin_image();
    ++reader.plugin[static_cast<std::size_t>(plan::kPluginReturnSlotRva)];
    checks.expect("wrong-plugin-return-slot",plan::guard(reader,base,image_size,plugin,plan::kPluginSize),false);

    std::cout<<"SUMMARY passed="<<checks.passed<<" failed="<<checks.failed<<"\n";
    return checks.failed==0?0:1;
}
