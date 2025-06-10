#include <cstdint>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>
#include <memory>
#include <stdio.h>
#include <unordered_map>

#define NOMINMAX
#if defined(_WIN32)
#include <windows.h>
#elif defined(__linux__)
#include <dlfcn.h>
#include <sys/mman.h>
#endif

#pragma comment (lib, "../luajit/src/lua51.lib")
#include "luajit/src/lua.hpp"

#pragma comment (lib, "PolyHook_2.lib")
#include "polyhook2/Detour/x64Detour.hpp"
#include "polyhook2/Detour/x86Detour.hpp"

#pragma comment (lib, "tier0.lib")
#pragma comment (lib, "tier1.lib")
#include "eiface.h"
#include "tier1/interface.h"
#include "engine/iserverplugin.h"

namespace Framework {
    typedef void* (*CreateInterface_fn)(const char* name, int* returncode);

    void** VTable(void* instance)
    {
        return *reinterpret_cast<void***>(instance);
    }

    template<typename T>
    T Interface(std::string module, std::string name)
    {
    #if defined(_WIN32)
        HMODULE handle = GetModuleHandle(module.c_str());

        if (!handle)
            return nullptr;

        static CreateInterface_fn CreateInterface = (CreateInterface_fn)GetProcAddress(handle, "CreateInterface");

        if (!CreateInterface)
            return nullptr;

        return (T)CreateInterface(name.c_str(), 0);
    #elif defined(__linux)
        void* handle = dlopen(module.c_str(), RTLD_LAZY);
        if (!handle) {
            return nullptr;
        }

        CreateInterface_fn CreateInterface = (CreateInterface_fn)dlsym(handle, "CreateInterface");
        if (!CreateInterface) {
            dlclose(handle);
            return nullptr;
        }

        T result = (T)CreateInterface(name.c_str(), 0);

        dlclose(handle);
        return result;
    #endif
    }

    #ifdef __linux
    #define UMODULE void*
        static UMODULE mopen(const char* name)
        {
            return dlopen(name, RTLD_LAZY);
        }

        static void* n2p(UMODULE hndle, const char* name)
        {
            return dlsym(hndle, name);
        }
    #else
    #define UMODULE HMODULE
        static UMODULE mopen(const char* name)
        {
            return GetModuleHandleA(name);
        }

        static void* n2p(UMODULE hndle, const char* name)
        {
            return GetProcAddress(hndle, name);
        }
    #endif

    bool is_writable(void* addr) {
        #if defined(__linux__)
            int current_prot;
            if (!get_page_permissions(addr, current_prot)) return false;
            return (current_prot & PROT_WRITE) == PROT_WRITE;
        #elif defined(_WIN32)
            MEMORY_BASIC_INFORMATION mbi;
            if (VirtualQuery(addr, &mbi, sizeof(mbi)) == 0) return false;

            DWORD protect = mbi.Protect;
            if (protect & PAGE_GUARD || protect & PAGE_NOACCESS) return false;

            return (protect & PAGE_READWRITE) || (protect & PAGE_EXECUTE_READWRITE) || (protect & PAGE_WRITECOPY) || (protect & PAGE_EXECUTE_WRITECOPY);
        #endif
    }

    bool is_readable(void* addr) {
        #if defined(__linux__)
            int current_prot;
            if (!get_page_permissions(addr, current_prot)) return false;
            return (current_prot & PROT_READ) == PROT_READ;
        #elif defined(_WIN32)
            MEMORY_BASIC_INFORMATION mbi;
            if (VirtualQuery(addr, &mbi, sizeof(mbi)) == 0) return false;

            DWORD protect = mbi.Protect;
            if (protect & PAGE_GUARD || protect & PAGE_NOACCESS) return false;

            return (protect & PAGE_READONLY) || (protect & PAGE_READWRITE) || (protect & PAGE_EXECUTE_READ) || (protect & PAGE_EXECUTE_READWRITE);
        #endif
    }

    bool make_writeable(void* addr, bool writeable, size_t size = 1) {
        #if defined(__linux__)
            uintptr_t page_size = sysconf(_SC_PAGESIZE);
            uintptr_t addr_start = reinterpret_cast<uintptr_t>(addr);
            uintptr_t page_start = addr_start & ~(page_size - 1);
            uintptr_t page_end = (addr_start + size + page_size - 1) & ~(page_size - 1);
            size_t total_size = page_end - page_start;

            int current_prot;
            if (!get_page_permissions(reinterpret_cast<void*>(addr_start), current_prot)) return false;

            if (readable)
                current_prot |= PROT_WRITE;
            else
                current_prot &= ~PROT_WRITE;

            return mprotect(reinterpret_cast<void*>(page_start), total_size, current_prot) == 0;
        #elif defined(_WIN32)
            DWORD oldProtect;
            MEMORY_BASIC_INFORMATION mbi;

            if (VirtualQuery(addr, &mbi, sizeof(mbi)) == 0) return false;

            DWORD newProtect = mbi.Protect;

            if (writeable) {
                if (newProtect & PAGE_EXECUTE_READ) newProtect = PAGE_EXECUTE_READWRITE;
                else if (newProtect & PAGE_READONLY) newProtect = PAGE_READWRITE;
                else if (newProtect & PAGE_EXECUTE) newProtect = PAGE_EXECUTE_READWRITE;
                else newProtect = PAGE_READWRITE;
            } else {
                if (newProtect & PAGE_EXECUTE_READWRITE) newProtect = PAGE_EXECUTE_READ;
                else if (newProtect & PAGE_READWRITE) newProtect = PAGE_READONLY;
                else if (newProtect & PAGE_EXECUTE_READWRITE) newProtect = PAGE_EXECUTE_READ;
                else newProtect = PAGE_READONLY;
            }

            return VirtualProtect(addr, size, newProtect, &oldProtect) != 0;
        #endif
    }

    bool make_readable(void* addr, bool readable, size_t size = 1) {
        #if defined(__linux__)
            uintptr_t page_size = sysconf(_SC_PAGESIZE);
            uintptr_t addr_start = reinterpret_cast<uintptr_t>(addr);
            uintptr_t page_start = addr_start & ~(page_size - 1);
            uintptr_t page_end = (addr_start + size + page_size - 1) & ~(page_size - 1);
            size_t total_size = page_end - page_start;

            int current_prot;
            if (!get_page_permissions(reinterpret_cast<void*>(addr_start), current_prot)) return false;

            if (readable)
                current_prot |= PROT_READ;
            else
                current_prot &= ~PROT_READ;

            return mprotect(reinterpret_cast<void*>(page_start), total_size, current_prot) == 0;
        #elif defined(_WIN32)
            DWORD oldProtect;
            MEMORY_BASIC_INFORMATION mbi;

            if (VirtualQuery(addr, &mbi, sizeof(mbi)) == 0) return false;

            DWORD newProtect = mbi.Protect;

            if (readable) {
                if (newProtect & PAGE_EXECUTE) newProtect = PAGE_EXECUTE_READ;
                else if (newProtect == PAGE_NOACCESS) newProtect = PAGE_READONLY;
                else if (newProtect & PAGE_READWRITE) newProtect = PAGE_READWRITE;
                else if (newProtect & PAGE_EXECUTE_READWRITE) newProtect = PAGE_EXECUTE_READWRITE;
                else newProtect = PAGE_READONLY;
            } else {
                if (newProtect & PAGE_READWRITE) newProtect = PAGE_NOACCESS;
                else if (newProtect & PAGE_READONLY) newProtect = PAGE_NOACCESS;
                else if (newProtect & PAGE_EXECUTE_READWRITE) newProtect = PAGE_EXECUTE;
                else if (newProtect & PAGE_EXECUTE_READ) newProtect = PAGE_EXECUTE;
                else return false;
            }

            return VirtualProtect(addr, size, newProtect, &oldProtect) != 0;
        #endif
    }

    // TODO: make this multi-module compatible
    namespace Routines {
        // doing this so that later on if we need any specific signatures, we can expand this.
        struct routine_data {
            std::string name; // name of target routine
            void* routine; // the routine to act as replacement
            size_t size; // size of the routine (if not provided will not overwrite)

            void* target; // targeted routine
            std::vector<char> store; // original storage of instructions
            #if defined(__x86_64__) || defined(_M_X64)
                PLH::x64Detour* hook; // hook storage of routine
            #elif defined(__i386__) || defined(_M_IX86)
                PLH::x86Detour* hook; // hook storage of routine
            #endif
        };

        std::vector<routine_data*>& get_routines() {
            static std::vector<routine_data*> routines = std::vector<routine_data*>();
            return routines;
        }

        std::unordered_map<std::string, routine_data*>& get_routines_cache() {
            static std::unordered_map<std::string, routine_data*> mappings = std::unordered_map<std::string, routine_data*>();
            return mappings;
        }

        size_t count()
        {
            return get_routines().size();
        }

        void add(std::string name, void* routine, size_t size = 0)
        {
            auto& cache = get_routines_cache();

            if (cache.find(name) != cache.end()) {
                routine_data* data = cache[name];
                data->name = name;
                data->routine = routine;
                data->size = size;
                return;
            }

            routine_data* data = new routine_data();
            data->name = name;
            data->routine = routine;
            data->size = size;
            data->target = nullptr;
            data->store = std::vector<char>();
            data->hook = nullptr;

            auto& routines = get_routines();
            cache.emplace(name, data);
            routines.push_back(data);
        }

        bool override(void* target, routine_data* data) {
            static void* nothing = nullptr;

            #if defined(__x86_64__) || defined(_M_X64)
                auto detour = new PLH::x64Detour(
                    (uint64_t)target,
                    (uint64_t)data->routine,
                    (uint64_t*)&nothing
                );
            #elif defined(__i386__) || defined(_M_IX86)
                auto detour = new PLH::x86Detour(
                    (uint64_t)target,
                    (uint64_t)data->routine,
                    (uint64_t*)&nothing
                );
            #endif

            if (!detour->hook()) {
                detour->unHook();
                return false;
            }

            data->hook = detour;
            nothing = nullptr;

            return true;
        }

        // only use this if polyhook fails
        // this overwrites the whole function by replacing every instruction
        // last resort as we cannot accurately determine if we are overwriting into other sections
        // and also if its offset based stuff we are kinda screwed
        bool overwrite(void* target, routine_data* data, size_t size) {
            bool writeable = Framework::is_writable(target);

            if (!writeable) {
                if (!Framework::make_writeable(target, true, size)) {
                    return false;
                }
            }

            std::memcpy(target, data->routine, size);

            if (!writeable) {
                Framework::make_writeable(target, false, size);
            }

            return true;
        }

        size_t load(UMODULE module)
        {
            size_t count = 0;
            auto& routines = get_routines();
            for (auto& entry : routines) {
                void* target = Framework::n2p(module, entry->name.c_str());
                if (target == nullptr) {
                    std::cout << "[LJPatch] [WARNING] Couldn't locate " << entry->name << "!" << std::endl;
                }
                else if (!override(target, entry)) {
                    if (entry->size > 0) {
                        std::cout << "[LJPatch] [WARNING] Couldn't modify " << entry->name << ", resorting to overwrite!" << std::endl;
                        for (unsigned int i = 0; i < entry->size; ++i) {
                            entry->store.push_back(((char*)entry->routine)[i]);
                        }
                        if (!overwrite(target, entry, entry->size)) {
                            std::cout << "[LJPatch] [WARNING] Couldn't overwrite " << entry->name << "!" << std::endl;
                        }
                        else {
                            count++;
                        }
                    }
                    else {
                        std::cout << "[LJPatch] [WARNING] Couldn't modify " << entry->name << "!" << std::endl;
                    }
                }
                else {
                    count++;
                }
            }
            return count;
        }

        void unload()
        {
            auto& list = get_routines();
            for (auto& entry : list) {
                if (entry->hook) {
                    entry->hook->unHook();
                    delete entry->hook;
                    entry->hook = nullptr;
                }
                else if (entry->size > 0 && entry->store.size() > 0) {
                    bool writeable = Framework::is_writable(entry->target);

                    if (!writeable) {
                        Framework::make_writeable(entry->target, true, entry->size);
                    }

                    for (unsigned int i = 0; i < entry->size; ++i) {
                        ((char*)entry->target)[i] = entry->store[i];
                    }

                    if (!writeable) {
                        Framework::make_writeable(entry->target, false, entry->size);
                    }

                    entry->store.clear();
                }
            }
        }
    }
}

class LJPatchPlugin : public IServerPluginCallbacks
{
public:
    LJPatchPlugin();
    ~LJPatchPlugin();

    // IServerPluginCallbacks methods
    virtual bool			Load(CreateInterfaceFn interfaceFactory, CreateInterfaceFn gameServerFactory);
    virtual void			Unload(void);
    virtual void			Pause(void);
    virtual void			UnPause(void);
    virtual const char* GetPluginDescription(void);
    virtual void			LevelInit(char const* pMapName);
    virtual void			ServerActivate(edict_t* pEdictList, int edictCount, int clientMax);
    virtual void			GameFrame(bool simulating);
    virtual void			LevelShutdown(void);
    virtual void			ClientActive(edict_t* pEntity);
    virtual void			ClientDisconnect(edict_t* pEntity);
    virtual void			ClientPutInServer(edict_t* pEntity, char const* playername);
    virtual void			SetCommandClient(int index);
    virtual void			ClientSettingsChanged(edict_t* pEdict);
    virtual PLUGIN_RESULT	ClientConnect(bool* bAllowConnect, edict_t* pEntity, const char* pszName, const char* pszAddress, char* reject, int maxrejectlen);
    virtual PLUGIN_RESULT	ClientCommand(edict_t* pEntity, const CCommand& args);
    virtual PLUGIN_RESULT	NetworkIDValidated(const char* pszUserName, const char* pszNetworkID);
    virtual void			OnQueryCvarValueFinished(QueryCvarCookie_t iCookie, edict_t* pPlayerEntity, EQueryCvarValueStatus eStatus, const char* pCvarName, const char* pCvarValue);
    virtual void			OnEdictAllocated(edict_t* edict);
    virtual void			OnEdictFreed(const edict_t* edict);
private:
};

//---------------------------------------------------------------------------------
// Purpose: constructor/destructor
//---------------------------------------------------------------------------------
LJPatchPlugin::LJPatchPlugin()
{
}

LJPatchPlugin::~LJPatchPlugin()
{
}

//---------------------------------------------------------------------------------
// Purpose: called when the plugin is loaded, load the interface we need from the engine
//---------------------------------------------------------------------------------

#include "glua/Interface.h"
#include "glua/LuaInterface.h"
#include "glua/LuaShared.h"
GarrysMod::Lua::ILuaShared* lua_shared_interface;

// For some reason GetTypeName and type don't use the same alpha-cases
static const char* type_mapping[] = {
    "none",
    "nil",
    "bool",
    "lightuserdata",
    "number",
    "string",
    "table",
    "function",
    "UserData",
    "thread",
    "Entity",
    "Vector",
    "Angle",
    "PhysObj",
    "Save",
    "Restore",
    "DamageInfo",
    "EffectData",
    "MoveData",
    "RecipientFilter",
    "UserCmd",
    "ScriptedVehicle",
    "Material",
    "Panel",
    "Particle",
    "ParticleEmitter",
    "Texture",
    "UserMsg",
    "ConVar",
    "IMesh",
    "Matrix",
    "Sound",
    "PixelVisHandle",
    "DLight",
    "Video",
    "File",
    "Locomotion",
    "Path",
    "NavArea",
    "SoundHandle",
    "NavLadder",
    "ParticleSystem",
    "ProjectedTexture",
    "PhysCollide",
    "SurfaceInfo",
};

// types break since we are restoring luajit
static int lua_func_type(lua_State* L)
{
    GarrysMod::lua_State* gL = (GarrysMod::lua_State*)L;
    GarrysMod::Lua::CLuaInterface* iL = (GarrysMod::Lua::CLuaInterface*)gL->luabase;
    int type = iL->GetType(1)+1;
    const char* type_name = iL->GetTypeName(type-1);
    if (type < 45) {
        type_name = type_mapping[type];
    }
    lua_pushstring(L, type_name);
    return 1;
}

// Exposure of extra libraries to LJ
void luaL_openlibs_dt(lua_State* L)
{
    luaL_openlibs(L);

    lua_pushcfunction(L, luaopen_ffi);
    lua_pushstring(L, LUA_FFILIBNAME);
    lua_call(L, 1, 1);
    lua_setfield(L, LUA_GLOBALSINDEX, LUA_FFILIBNAME);

    lua_getfield(L, LUA_GLOBALSINDEX, "require");
    lua_setfield(L, LUA_GLOBALSINDEX, "acquire");

    lua_getfield(L, LUA_GLOBALSINDEX, "jit");
        lua_getfield(L, LUA_GLOBALSINDEX, "require");
        lua_pushstring(L, "jit.profile");
        lua_call(L, 1, 1);
        lua_setfield(L, -2, "profile");

        lua_getfield(L, LUA_GLOBALSINDEX, "require");
        lua_pushstring(L, "jit.util");
        lua_call(L, 1, 1);
        lua_setfield(L, -2, "util");
    lua_pop(L, 1);

    lua_pushcfunction(L, lua_func_type);
    lua_setfield(L, LUA_GLOBALSINDEX, "type");
}

bool LJPatchPlugin::Load(CreateInterfaceFn interfaceFactory, CreateInterfaceFn gameServerFactory)
{
    #ifdef __linux
        #if defined(__x86_64__) || defined(_M_X64)
            #define BINARY "bin/linux64/lua_shared.so"
        #elif defined(__i386__) || defined(_M_IX86)
            #define BINARY "bin/linux32/lua_shared.so"
            #define BINARY2 "garrysmod/bin/lua_shared_srv.so"
        #endif
    #else
        #if defined(__x86_64__) || defined(_M_X64)
            #define BINARY "bin/win64/lua_shared.dll"
        #elif defined(__i386__) || defined(_M_IX86)
            #define BINARY "bin/lua_shared.dll"
            #define BINARY2 "garrysmod/bin/lua_shared.dll"
        #endif
    #endif

    std::cout << "LJPatch - ";

    #if defined(_WIN32)
        std::cout << "Windows ";
    #elif defined(__linux__)
        std::cout << "Linux ";
    #endif

    #if defined(__x86_64__) || defined(_M_X64)
        std::cout << "x64";
    #elif defined(__i386__) || defined(_M_IX86)
        std::cout << "x86";
    #endif

    std::cout << " - " __TIME__ " " __DATE__;
    std::cout << std::endl;
    std::cout << "Rolling Back LuaJIT & Feature Restoration" << std::endl;

    std::cout << "[LJPatch] Adding Registry..." << std::endl;
    {
        using Framework::Routines::add;

        add("luaJIT_setmode", luaJIT_setmode);

        add("luaopen_base", luaopen_base);
        add("luaopen_bit", luaopen_bit);
        add("luaopen_debug", luaopen_debug);
        add("luaopen_jit", luaopen_jit);
        add("luaopen_math", luaopen_math);
        add("luaopen_os", luaopen_os);
        add("luaopen_package", luaopen_package);
        add("luaopen_string", luaopen_string);
        add("luaopen_table", luaopen_table);

        add("luaL_addlstring", luaL_addlstring);
        add("luaL_addstring", luaL_addstring);
        add("luaL_addvalue", luaL_addvalue);
        add("luaL_argerror", luaL_argerror);
        add("luaL_buffinit", luaL_buffinit);
        add("luaL_callmeta", luaL_callmeta);
        add("luaL_checkany", luaL_checkany);
        add("luaL_checkinteger", luaL_checkinteger);
        add("luaL_checklstring", luaL_checklstring);
        add("luaL_checknumber", luaL_checknumber);
        add("luaL_checkoption", luaL_checkoption);
        add("luaL_checkstack", luaL_checkstack);
        add("luaL_checktype", luaL_checktype);
        add("luaL_checkudata", luaL_checkudata);
        add("luaL_error", luaL_error);
        add("luaL_execresult", luaL_execresult);
        add("luaL_fileresult", luaL_fileresult);
        add("luaL_findtable", luaL_findtable);
        add("luaL_getmetafield", luaL_getmetafield);
        add("luaL_gsub", luaL_gsub);
        add("luaL_loadbuffer", luaL_loadbuffer);
        add("luaL_loadbufferx", luaL_loadbufferx);
        add("luaL_loadfile", luaL_loadfile);
        add("luaL_loadfilex", luaL_loadfilex);
        add("luaL_loadstring", luaL_loadstring);
        add("luaL_newmetatable", luaL_newmetatable);
        add("luaL_newstate", luaL_newstate);
        add("luaL_openlib", luaL_openlib);
        add("luaL_openlibs", luaL_openlibs_dt);
        add("luaL_optinteger", luaL_optinteger);
        add("luaL_optlstring", luaL_optlstring);
        add("luaL_optnumber", luaL_optnumber);
        add("luaL_prepbuffer", luaL_prepbuffer);
        add("luaL_pushmodule", luaL_pushmodule);
        add("luaL_pushresult", luaL_pushresult);
        add("luaL_ref", luaL_ref);
        add("luaL_register", luaL_register);
        add("luaL_setfuncs", luaL_setfuncs);
        add("luaL_setmetatable", luaL_setmetatable);
        add("luaL_testudata", luaL_testudata);
        add("luaL_traceback", luaL_traceback);
        add("luaL_typerror", luaL_typerror);
        add("luaL_unref", luaL_unref);
        add("luaL_where", luaL_where);

        add("lua_atpanic", lua_atpanic);
        add("lua_call", lua_call);
        add("lua_checkstack", lua_checkstack);
        add("lua_close", lua_close);
        add("lua_concat", lua_concat);
        add("lua_copy", lua_copy);
        add("lua_cpcall", lua_cpcall);
        add("lua_createtable", lua_createtable);
        add("lua_dump", lua_dump);
        add("lua_equal", lua_equal);
        add("lua_error", lua_error);
        add("lua_gc", lua_gc);
        add("lua_getallocf", lua_getallocf);
        add("lua_getfenv", lua_getfenv);
        add("lua_getfield", lua_getfield);
        add("lua_gethook", lua_gethook);
        add("lua_gethookcount", lua_gethookcount);
        add("lua_gethookmask", lua_gethookmask);
        add("lua_getinfo", lua_getinfo);
        add("lua_getlocal", lua_getlocal);
        add("lua_getmetatable", lua_getmetatable);
        add("lua_getstack", lua_getstack);
        add("lua_gettable", lua_gettable);
        add("lua_gettop", lua_gettop);
        add("lua_getupvalue", lua_getupvalue);
        add("lua_insert", lua_insert);
        add("lua_iscfunction", lua_iscfunction);
        add("lua_isnumber", lua_isnumber);
        add("lua_isstring", lua_isstring);
        add("lua_isuserdata", lua_isuserdata);
        add("lua_isyieldable", lua_isyieldable);
        add("lua_lessthan", lua_lessthan);
        add("lua_load", lua_load);
        add("lua_loadx", lua_loadx);
        add("lua_newstate", lua_newstate);
        add("lua_newthread", lua_newthread);
        add("lua_newuserdata", lua_newuserdata);
        add("lua_next", lua_next);
        add("lua_objlen", lua_objlen);
        add("lua_pcall", lua_pcall);
        add("lua_pushboolean", lua_pushboolean);
        add("lua_pushcclosure", lua_pushcclosure);
        add("lua_pushfstring", lua_pushfstring);
        add("lua_pushinteger", lua_pushinteger);
        add("lua_pushlightuserdata", lua_pushlightuserdata);
        add("lua_pushlstring", lua_pushlstring);
        add("lua_pushnil", lua_pushnil);
        add("lua_pushnumber", lua_pushnumber);
        add("lua_pushstring", lua_pushstring);
        add("lua_pushthread", lua_pushthread);
        add("lua_pushvalue", lua_pushvalue);
        add("lua_pushvfstring", lua_pushvfstring);
        add("lua_rawequal", lua_rawequal);
        add("lua_rawget", lua_rawget);
        add("lua_rawgeti", lua_rawgeti);
        add("lua_rawset", lua_rawset);
        add("lua_rawseti", lua_rawseti);
        add("lua_remove", lua_remove);
        add("lua_replace", lua_replace);
        add("lua_setallocf", lua_setallocf);
        add("lua_setfenv", lua_setfenv);
        add("lua_setfield", lua_setfield);
        add("lua_sethook", lua_sethook);
        add("lua_setlocal", lua_setlocal);
        add("lua_setmetatable", lua_setmetatable);
        add("lua_settable", lua_settable);
        add("lua_settop", lua_settop);
        add("lua_setupvalue", lua_setupvalue);
        add("lua_status", lua_status);
        add("lua_toboolean", lua_toboolean);
        add("lua_tocfunction", lua_tocfunction);
        add("lua_tointeger", lua_tointeger);
        add("lua_tointegerx", lua_tointegerx);
        add("lua_tolstring", lua_tolstring);
        add("lua_tonumber", lua_tonumber);
        add("lua_tonumberx", lua_tonumberx);
        add("lua_topointer", lua_topointer);
        add("lua_tothread", lua_tothread);
        add("lua_touserdata", lua_touserdata);
        add("lua_type", lua_type);
        add("lua_typename", lua_typename);
        add("lua_upvalueid", lua_upvalueid);
        add("lua_upvaluejoin", lua_upvaluejoin);
        add("lua_version", lua_version);
        add("lua_xmove", lua_xmove);
        add("lua_yield", lua_yield);

        // Linux x64 PLH incompatibility:
        // lua_isuserdata, lua_toboolean, lua_tocfunction, lua_tothread, lua_touserdata
        #if defined(__linux) && (defined(__x86_64__) || defined(_M_X64))
            add("lua_isuserdata", lua_isuserdata, 0x1D);
            add("lua_toboolean", lua_toboolean, 0x15);
            add("lua_tocfunction", lua_tocfunction, 0x47);
            add("lua_tothread", lua_tothread, 0x23);
            add("lua_isyieldable", lua_touserdata, 0x41);
        #endif

        // Windows x64 PLH incompatibility:
        // lua_status, lua_isyieldable
        #if defined(_WIN32) && (defined(__x86_64__) || defined(_M_X64))
            add("lua_status", lua_status, 0x4);
            add("lua_isyieldable", lua_isyieldable, 0x6);
        #endif
    }

    #ifdef BINARY2
        const char* binary = BINARY2;
        auto lua_shared = Framework::mopen(BINARY2);
        if (!lua_shared) {
            binary = BINARY;
            lua_shared = Framework::mopen(BINARY);
        }
    #else
        const char* binary = BINARY;
        auto lua_shared = Framework::mopen(BINARY);
    #endif

    if (!lua_shared) {
        std::cout << "[LJPatch] [ERROR] Couldn't initialize properly, couldn't find lua_shared." << std::endl;
        return false;
    }

    lua_shared_interface = Framework::Interface<GarrysMod::Lua::ILuaShared*>(binary, GMOD_LUASHARED_INTERFACE);

    if (!lua_shared_interface) {
        std::cout << "[LJPatch] [ERROR] Couldn't initialize properly, couldn't find lua interface." << std::endl;
        return 0;
    }

    std::cout << "[LJPatch] Patching..." << std::endl;
    size_t count = Framework::Routines::load(lua_shared);
    std::cout << "[LJPatch] Restored: " << count << " / " << Framework::Routines::count() << " APIs" << std::endl;

    return true;
}

//---------------------------------------------------------------------------------
// Purpose: called when the plugin is unloaded (turned off)
//---------------------------------------------------------------------------------
void LJPatchPlugin::Unload(void)
{
    std::cout << "[LJPatch] Unloading..." << std::endl;
    Framework::Routines::unload();
    std::cout << "[LJPatch] Complete." << std::endl;
}

//---------------------------------------------------------------------------------
// Purpose: called when the plugin is paused (i.e should stop running but isn't unloaded)
//---------------------------------------------------------------------------------
void LJPatchPlugin::Pause(void)
{
}

//---------------------------------------------------------------------------------
// Purpose: called when the plugin is unpaused (i.e should start executing again)
//---------------------------------------------------------------------------------
void LJPatchPlugin::UnPause(void)
{
}

//---------------------------------------------------------------------------------
// Purpose: the name of this plugin, returned in "plugin_print" command
//---------------------------------------------------------------------------------
const char* LJPatchPlugin::GetPluginDescription(void)
{
    return "LJPatch";
}

//---------------------------------------------------------------------------------
// Purpose: called on level start
//---------------------------------------------------------------------------------
void LJPatchPlugin::LevelInit(char const* pMapName)
{
}

//---------------------------------------------------------------------------------
// Purpose: called on level start, when the server is ready to accept client connections
//		edictCount is the number of entities in the level, clientMax is the max client count
//---------------------------------------------------------------------------------
void LJPatchPlugin::ServerActivate(edict_t* pEdictList, int edictCount, int clientMax)
{
}

//---------------------------------------------------------------------------------
// Purpose: called once per server frame, do recurring work here (like checking for timeouts)
//---------------------------------------------------------------------------------
void LJPatchPlugin::GameFrame(bool simulating)
{
}

//---------------------------------------------------------------------------------
// Purpose: called on level end (as the server is shutting down or going to a new map)
//---------------------------------------------------------------------------------
void LJPatchPlugin::LevelShutdown(void) // !!!!this can get called multiple times per map change
{
}

//---------------------------------------------------------------------------------
// Purpose: called when a client spawns into a server (i.e as they begin to play)
//---------------------------------------------------------------------------------
void LJPatchPlugin::ClientActive(edict_t* pEntity)
{
}

//---------------------------------------------------------------------------------
// Purpose: called when a client leaves a server (or is timed out)
//---------------------------------------------------------------------------------
void LJPatchPlugin::ClientDisconnect(edict_t* pEntity)
{
}

//---------------------------------------------------------------------------------
// Purpose: called on 
//---------------------------------------------------------------------------------
void LJPatchPlugin::ClientPutInServer(edict_t* pEntity, char const* playername)
{
}

//---------------------------------------------------------------------------------
// Purpose: called on level start
//---------------------------------------------------------------------------------
void LJPatchPlugin::SetCommandClient(int index)
{
}

//---------------------------------------------------------------------------------
// Purpose: called on level start
//---------------------------------------------------------------------------------
void LJPatchPlugin::ClientSettingsChanged(edict_t* pEdict)
{
}

//---------------------------------------------------------------------------------
// Purpose: called when a client joins a server
//---------------------------------------------------------------------------------
PLUGIN_RESULT LJPatchPlugin::ClientConnect(bool* bAllowConnect, edict_t* pEntity, const char* pszName, const char* pszAddress, char* reject, int maxrejectlen)
{
    return PLUGIN_CONTINUE;
}

//---------------------------------------------------------------------------------
// Purpose: called when a client types in a command (only a subset of commands however, not CON_COMMAND's)
//---------------------------------------------------------------------------------
PLUGIN_RESULT LJPatchPlugin::ClientCommand(edict_t* pEntity, const CCommand& args)
{
    return PLUGIN_CONTINUE;
}

//---------------------------------------------------------------------------------
// Purpose: called when a client is authenticated
//---------------------------------------------------------------------------------
PLUGIN_RESULT LJPatchPlugin::NetworkIDValidated(const char* pszUserName, const char* pszNetworkID)
{
    return PLUGIN_CONTINUE;
}

//---------------------------------------------------------------------------------
// Purpose: called when a cvar value query is finished
//---------------------------------------------------------------------------------
void LJPatchPlugin::OnQueryCvarValueFinished(QueryCvarCookie_t iCookie, edict_t* pPlayerEntity, EQueryCvarValueStatus eStatus, const char* pCvarName, const char* pCvarValue)
{
}
void LJPatchPlugin::OnEdictAllocated(edict_t* edict)
{
}
void LJPatchPlugin::OnEdictFreed(const edict_t* edict)
{
}

LJPatchPlugin g_LJPatchPlugin;
EXPOSE_SINGLE_INTERFACE_GLOBALVAR(LJPatchPlugin, IServerPluginCallbacks, INTERFACEVERSION_ISERVERPLUGINCALLBACKS, g_LJPatchPlugin);