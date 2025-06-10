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
#include <psapi.h>
#include <iostream>
#include <windows.h>
#elif defined(__linux)
#include <dlfcn.h>
#include <sys/mman.h>
#include <unistd.h>
#include <link.h>
#include <cstddef>
#include <stdint.h>
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


    #if defined(__linux__)
        static bool get_page_permissions(void* addr, int& out_prot) {
            std::ifstream maps("/proc/self/maps");
            if (!maps.is_open()) return false;

            std::string line;
            uintptr_t target = reinterpret_cast<uintptr_t>(addr);

            while (std::getline(maps, line)) {
                uintptr_t start, end;
                char perms[5] = {0};

                std::istringstream iss(line);
                iss >> std::hex >> start;
                iss.ignore(1);
                iss >> std::hex >> end;
                iss >> perms;

                if (target >= start && target < end) {
                    int prot = 0;
                    if (perms[0] == 'r') prot |= PROT_READ;
                    if (perms[1] == 'w') prot |= PROT_WRITE;
                    if (perms[2] == 'x') prot |= PROT_EXEC;

                    out_prot = prot;
                    return true;
                }
            }

            return false;
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

        add("luaJIT_setmode", (void*)luaJIT_setmode);

        add("luaopen_base", (void*)luaopen_base);
        add("luaopen_bit", (void*)luaopen_bit);
        add("luaopen_debug", (void*)luaopen_debug);
        add("luaopen_jit", (void*)luaopen_jit);
        add("luaopen_math", (void*)luaopen_math);
        add("luaopen_os", (void*)luaopen_os);
        add("luaopen_package", (void*)luaopen_package);
        add("luaopen_string", (void*)luaopen_string);
        add("luaopen_table", (void*)luaopen_table);

        add("luaL_addlstring", (void*)luaL_addlstring);
        add("luaL_addstring", (void*)luaL_addstring);
        add("luaL_addvalue", (void*)luaL_addvalue);
        add("luaL_argerror", (void*)luaL_argerror);
        add("luaL_buffinit", (void*)luaL_buffinit);
        add("luaL_callmeta", (void*)luaL_callmeta);
        add("luaL_checkany", (void*)luaL_checkany);
        add("luaL_checkinteger", (void*)luaL_checkinteger);
        add("luaL_checklstring", (void*)luaL_checklstring);
        add("luaL_checknumber", (void*)luaL_checknumber);
        add("luaL_checkoption", (void*)luaL_checkoption);
        add("luaL_checkstack", (void*)luaL_checkstack);
        add("luaL_checktype", (void*)luaL_checktype);
        add("luaL_checkudata", (void*)luaL_checkudata);
        add("luaL_error", (void*)luaL_error);
        add("luaL_execresult", (void*)luaL_execresult);
        add("luaL_fileresult", (void*)luaL_fileresult);
        add("luaL_findtable", (void*)luaL_findtable);
        add("luaL_getmetafield", (void*)luaL_getmetafield);
        add("luaL_gsub", (void*)luaL_gsub);
        add("luaL_loadbuffer", (void*)luaL_loadbuffer);
        add("luaL_loadbufferx", (void*)luaL_loadbufferx);
        add("luaL_loadfile", (void*)luaL_loadfile);
        add("luaL_loadfilex", (void*)luaL_loadfilex);
        add("luaL_loadstring", (void*)luaL_loadstring);
        add("luaL_newmetatable", (void*)luaL_newmetatable);
        add("luaL_newstate", (void*)luaL_newstate);
        add("luaL_openlib", (void*)luaL_openlib);
        add("luaL_openlibs", (void*)luaL_openlibs_dt);
        add("luaL_optinteger", (void*)luaL_optinteger);
        add("luaL_optlstring", (void*)luaL_optlstring);
        add("luaL_optnumber", (void*)luaL_optnumber);
        add("luaL_prepbuffer", (void*)luaL_prepbuffer);
        add("luaL_pushmodule", (void*)luaL_pushmodule);
        add("luaL_pushresult", (void*)luaL_pushresult);
        add("luaL_ref", (void*)luaL_ref);
        add("luaL_register", (void*)luaL_register);
        add("luaL_setfuncs", (void*)luaL_setfuncs);
        add("luaL_setmetatable", (void*)luaL_setmetatable);
        add("luaL_testudata", (void*)luaL_testudata);
        add("luaL_traceback", (void*)luaL_traceback);
        add("luaL_typerror", (void*)luaL_typerror);
        add("luaL_unref", (void*)luaL_unref);
        add("luaL_where", (void*)luaL_where);

        add("lua_atpanic", (void*)lua_atpanic);
        add("lua_call", (void*)lua_call);
        add("lua_checkstack", (void*)lua_checkstack);
        add("lua_close", (void*)lua_close);
        add("lua_concat", (void*)lua_concat);
        add("lua_copy", (void*)lua_copy);
        add("lua_cpcall", (void*)lua_cpcall);
        add("lua_createtable", (void*)lua_createtable);
        add("lua_dump", (void*)lua_dump);
        add("lua_equal", (void*)lua_equal);
        add("lua_error", (void*)lua_error);
        add("lua_gc", (void*)lua_gc);
        add("lua_getallocf", (void*)lua_getallocf);
        add("lua_getfenv", (void*)lua_getfenv);
        add("lua_getfield", (void*)lua_getfield);
        add("lua_gethook", (void*)lua_gethook);
        add("lua_gethookcount", (void*)lua_gethookcount);
        add("lua_gethookmask", (void*)lua_gethookmask);
        add("lua_getinfo", (void*)lua_getinfo);
        add("lua_getlocal", (void*)lua_getlocal);
        add("lua_getmetatable", (void*)lua_getmetatable);
        add("lua_getstack", (void*)lua_getstack);
        add("lua_gettable", (void*)lua_gettable);
        add("lua_gettop", (void*)lua_gettop);
        add("lua_getupvalue", (void*)lua_getupvalue);
        add("lua_insert", (void*)lua_insert);
        add("lua_iscfunction", (void*)lua_iscfunction);
        add("lua_isnumber", (void*)lua_isnumber);
        add("lua_isstring", (void*)lua_isstring);
        add("lua_isuserdata", (void*)lua_isuserdata);
        add("lua_isyieldable", (void*)lua_isyieldable);
        add("lua_lessthan", (void*)lua_lessthan);
        add("lua_load", (void*)lua_load);
        add("lua_loadx", (void*)lua_loadx);
        add("lua_newstate", (void*)lua_newstate);
        add("lua_newthread", (void*)lua_newthread);
        add("lua_newuserdata", (void*)lua_newuserdata);
        add("lua_next", (void*)lua_next);
        add("lua_objlen", (void*)lua_objlen);
        add("lua_pcall", (void*)lua_pcall);
        add("lua_pushboolean", (void*)lua_pushboolean);
        add("lua_pushcclosure", (void*)lua_pushcclosure);
        add("lua_pushfstring", (void*)lua_pushfstring);
        add("lua_pushinteger", (void*)lua_pushinteger);
        add("lua_pushlightuserdata", (void*)lua_pushlightuserdata);
        add("lua_pushlstring", (void*)lua_pushlstring);
        add("lua_pushnil", (void*)lua_pushnil);
        add("lua_pushnumber", (void*)lua_pushnumber);
        add("lua_pushstring", (void*)lua_pushstring);
        add("lua_pushthread", (void*)lua_pushthread);
        add("lua_pushvalue", (void*)lua_pushvalue);
        add("lua_pushvfstring", (void*)lua_pushvfstring);
        add("lua_rawequal", (void*)lua_rawequal);
        add("lua_rawget", (void*)lua_rawget);
        add("lua_rawgeti", (void*)lua_rawgeti);
        add("lua_rawset", (void*)lua_rawset);
        add("lua_rawseti", (void*)lua_rawseti);
        add("lua_remove", (void*)lua_remove);
        add("lua_replace", (void*)lua_replace);
        add("lua_setallocf", (void*)lua_setallocf);
        add("lua_setfenv", (void*)lua_setfenv);
        add("lua_setfield", (void*)lua_setfield);
        add("lua_sethook", (void*)lua_sethook);
        add("lua_setlocal", (void*)lua_setlocal);
        add("lua_setmetatable", (void*)lua_setmetatable);
        add("lua_settable", (void*)lua_settable);
        add("lua_settop", (void*)lua_settop);
        add("lua_setupvalue", (void*)lua_setupvalue);
        add("lua_status", (void*)lua_status);
        add("lua_toboolean", (void*)lua_toboolean);
        add("lua_tocfunction", (void*)lua_tocfunction);
        add("lua_tointeger", (void*)lua_tointeger);
        add("lua_tointegerx", (void*)lua_tointegerx);
        add("lua_tolstring", (void*)lua_tolstring);
        add("lua_tonumber", (void*)lua_tonumber);
        add("lua_tonumberx", (void*)lua_tonumberx);
        add("lua_topointer", (void*)lua_topointer);
        add("lua_tothread", (void*)lua_tothread);
        add("lua_touserdata", (void*)lua_touserdata);
        add("lua_type", (void*)lua_type);
        add("lua_typename", (void*)lua_typename);
        add("lua_upvalueid", (void*)lua_upvalueid);
        add("lua_upvaluejoin", (void*)lua_upvaluejoin);
        add("lua_version", (void*)lua_version);
        add("lua_xmove", (void*)lua_xmove);
        add("lua_yield", (void*)lua_yield);

        // Linux x64 PLH incompatibility:
        // lua_isuserdata, lua_toboolean, lua_tocfunction, lua_tothread, lua_touserdata
        #if defined(__linux) && (defined(__x86_64__) || defined(_M_X64))
            add("lua_isuserdata", (void*)lua_isuserdata, 0x1D);
            add("lua_toboolean", (void*)lua_toboolean, 0x15);
            add("lua_tocfunction", (void*)lua_tocfunction, 0x47);
            add("lua_tothread", (void*)lua_tothread, 0x23);
            add("lua_isyieldable", (void*)lua_touserdata, 0x41);
        #endif

        // Windows x64 PLH incompatibility:
        // lua_status, lua_isyieldable
        #if defined(_WIN32) && (defined(__x86_64__) || defined(_M_X64))
            add("lua_status", (void*)lua_status, 0x4);
            add("lua_isyieldable", (void*)lua_isyieldable, 0x6);
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