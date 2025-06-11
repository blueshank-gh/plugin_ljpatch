#include <cstdint>
#include <cstring>
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <memory>
#include <stdio.h>
#include <unordered_map>

#define NOMINMAX
#if defined(_WIN32)
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

            if (writeable)
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

            auto& routines = get_routines();
            cache.emplace(name, data);
            routines.push_back(data);
        }

        bool redirect(void* target, routine_data* data)
        {
            bool writeable = Framework::is_writable(target);

            if (!writeable) {
                if (!Framework::make_writeable(target, true)) {
                    return false;
                }
            }

            #if defined(__x86_64__) || defined(_M_X64)
                // SIZE: 12
                // mov rax, imm64 -> 48 B8 XX XX XX XX XX XX XX XX
                // jmp rax -> FF E0
                char* buffer = (char*)target;
                for (unsigned int i = 0; i < 12; ++i) {
                    data->store.push_back(buffer[i]);
                }
                buffer[0] = 0x48; buffer[1] = 0xB8;
                *(void**)(buffer + 2) = data->routine;
                buffer[10] = 0xFF; buffer[11] = 0xE0;
            #elif defined(__i386__) || defined(_M_IX86)
                // SIZE: 5
                // jmp -> E9 XX XX XX XX (offset from PC)
                char* buffer = (char*)target;
                for (unsigned int i = 0; i < 5; ++i) {
                    data->store.push_back(buffer[i]);
                }
                buffer[0] = 0xE9;
                intptr_t relative = (intptr_t)(data->routine) - ((intptr_t)buffer + 5);
                *(int32_t*)(buffer + 1) = (int32_t)relative;
            #endif

            #ifdef __linux
                __builtin___clear_cache(buffer, buffer + 16);
            #endif

            if (!writeable) {
                Framework::make_writeable(target, false);
            }

            return true;
        }

        size_t load(UMODULE module)
        {
            size_t count = 0;
            auto& routines = get_routines();
            for (auto& entry : routines) {
                void* target = Framework::n2p(module, entry->name.c_str());
                entry->target = target;
                if (target == nullptr) {
                    std::cout << "[LJPatch] [WARNING] Couldn't locate " << entry->name << "!" << std::endl;
                }
                else if (!redirect(target, entry)) {
                    std::cout << "[LJPatch] [ERROR] Couldn't redirect " << entry->name << "!" << std::endl;
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
                if (entry->target != nullptr) {
                    if (entry->store.size() > 0) {
                        size_t sz = entry->store.size();

                        bool writeable = Framework::is_writable(entry->target);

                        if (!writeable) {
                            Framework::make_writeable(entry->target, true, sz);
                        }

                        for (size_t i = 0; i < sz; ++i) {
                            ((char*)entry->target)[i] = entry->store[i];
                        }

                        if (!writeable) {
                            Framework::make_writeable(entry->target, false, sz);
                        }

                        entry->store.clear();
                    }
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


namespace Overrides {
    // This section holds all the functions we want to override.
    // Its important that optimization techniques are disabled here.
    // Otherwise you would have deviations & corruptions on overwrite

    #if defined(_MSC_VER)
        #define BEGIN_NOOPT __pragma(optimize("", off))
        #define END_NOOPT   __pragma(optimize("", on))
    #elif defined(__GNUC__) || defined(__clang__)
        #define BEGIN_NOOPT _Pragma("GCC push_options") \
                            _Pragma("GCC optimize(\"O0\")")
        #define END_NOOPT   _Pragma("GCC pop_options")
    #else
        #define BEGIN_NOOPT
        #define END_NOOPT
    #endif

    #if defined(_MSC_VER)
        #define NOINLINE __declspec(noinline)
    #elif defined(__GNUC__) || defined(__clang__)
        #define NOINLINE __attribute__((noinline))
    #else
        #define NOINLINE
    #endif

    BEGIN_NOOPT

    NOINLINE int luaJIT_setmode_dt(lua_State* L, int idx, int mode) { return luaJIT_setmode(L, idx, mode); }

    NOINLINE int luaopen_base_dt(lua_State* L) { return luaopen_base(L); }
    NOINLINE int luaopen_bit_dt(lua_State* L) { return luaopen_bit(L); }
    NOINLINE int luaopen_debug_dt(lua_State* L) { return luaopen_debug(L); }
    NOINLINE int luaopen_jit_dt(lua_State* L) { return luaopen_jit(L); }
    NOINLINE int luaopen_math_dt(lua_State* L) { return luaopen_math(L); }
    NOINLINE int luaopen_os_dt(lua_State* L) { return luaopen_os(L); }
    NOINLINE int luaopen_package_dt(lua_State* L) { return luaopen_package(L); }
    NOINLINE int luaopen_string_dt(lua_State* L) { return luaopen_string(L); }
    NOINLINE int luaopen_table_dt(lua_State* L) { return luaopen_table(L); }

    NOINLINE void luaL_addlstring_dt(luaL_Buffer* B, const char* s, size_t l) { return luaL_addlstring(B, s, l); }
    NOINLINE void luaL_addstring_dt(luaL_Buffer* B, const char* s) { return luaL_addstring(B, s); }
    NOINLINE void luaL_addvalue_dt(luaL_Buffer* B) { return luaL_addvalue(B); }
    NOINLINE int luaL_argerror_dt(lua_State* L, int numarg, const char* extramsg) { return luaL_argerror(L, numarg, extramsg); }
    NOINLINE void luaL_buffinit_dt(lua_State* L, luaL_Buffer* B) { return luaL_buffinit(L, B); }
    NOINLINE int luaL_callmeta_dt(lua_State* L, int idx, const char* e) { return luaL_callmeta(L, idx, e); }
    NOINLINE void luaL_checkany_dt(lua_State* L, int narg) { return luaL_checkany(L, narg); }
    NOINLINE lua_Integer luaL_checkinteger_dt(lua_State* L, int numArg) { return luaL_checkinteger(L, numArg); }
    NOINLINE const char* luaL_checklstring_dt(lua_State* L, int numArg, size_t* l) { return luaL_checklstring(L, numArg, l); }
    NOINLINE lua_Number luaL_checknumber_dt(lua_State* L, int numArg) { return luaL_checknumber(L, numArg); }
    NOINLINE int luaL_checkoption_dt(lua_State* L, int narg, const char* def, const char* const lst[]) { return luaL_checkoption(L, narg, def, lst); }
    NOINLINE void luaL_checkstack_dt(lua_State* L, int sz, const char* msg) { return luaL_checkstack(L, sz, msg); }
    NOINLINE void luaL_checktype_dt(lua_State* L, int narg, int t) { return luaL_checktype(L, narg, t); }
    NOINLINE void* luaL_checkudata_dt(lua_State* L, int ud, const char* tname) { return luaL_checkudata(L, ud, tname); }
    NOINLINE int luaL_error_dt(lua_State* L, const char* fmt, ...) {
        va_list args;
        va_start(args, fmt);
        int result = luaL_error(L, fmt, args);
        va_end(args);
        return result;
    }
    NOINLINE int luaL_execresult_dt(lua_State* L, int stat) { return luaL_execresult(L, stat); }
    NOINLINE int luaL_fileresult_dt(lua_State* L, int stat, const char* fname) { return luaL_fileresult(L, stat, fname); }
    NOINLINE const char* luaL_findtable_dt(lua_State* L, int idx, const char* fname, int szhint) { return luaL_findtable(L, idx, fname, szhint); }
    NOINLINE int luaL_getmetafield_dt(lua_State* L, int idx, const char* field) { return luaL_getmetafield(L, idx, field); }
    NOINLINE const char* luaL_gsub_dt(lua_State* L, const char* s, const char* p, const char* r) { return luaL_gsub(L, s, p, r); }
    NOINLINE int luaL_loadbuffer_dt(lua_State* L, const char* buff, size_t sz, const char* name) { return luaL_loadbuffer(L, buff, sz, name); }
    NOINLINE int luaL_loadbufferx_dt(lua_State* L, const char* buff, size_t sz, const char* name, const char* mode) { return luaL_loadbufferx(L, buff, sz, name, mode); }
    NOINLINE int luaL_loadfile_dt(lua_State* L, const char* filename) { return luaL_loadfile(L, filename); }
    NOINLINE int luaL_loadfilex_dt(lua_State* L, const char* filename, const char* mode) { return luaL_loadfilex(L, filename, mode); }
    NOINLINE int luaL_loadstring_dt(lua_State* L, const char* s) { return luaL_loadstring(L, s); }
    NOINLINE int luaL_newmetatable_dt(lua_State* L, const char* tname) { return luaL_newmetatable(L, tname); }
    NOINLINE lua_State* luaL_newstate_dt(void) { return luaL_newstate(); }
    NOINLINE void luaL_openlib_dt(lua_State* L, const char* libname, const luaL_Reg* l, int nup) { return luaL_openlib(L, libname, l, nup); }
    NOINLINE void luaL_openlibs_dt(lua_State* L) { return luaL_openlibs(L); }
    NOINLINE lua_Integer luaL_optinteger_dt(lua_State* L, int nArg, lua_Integer def) { return luaL_optinteger(L, nArg, def); }
    NOINLINE const char* luaL_optlstring_dt(lua_State* L, int numArg, const char* def, size_t* l) { return luaL_optlstring(L, numArg, def, l); }
    NOINLINE lua_Number luaL_optnumber_dt(lua_State* L, int nArg, lua_Number def) { return luaL_optnumber(L, nArg, def); }
    NOINLINE char* luaL_prepbuffer_dt(luaL_Buffer* B) { return luaL_prepbuffer(B); }
    NOINLINE void luaL_pushmodule_dt(lua_State* L, const char* modname, int sizehint) { return luaL_pushmodule(L, modname, sizehint); }
    NOINLINE void luaL_pushresult_dt(luaL_Buffer* B) { return luaL_pushresult(B); }
    NOINLINE int luaL_ref_dt(lua_State* L, int t) { return luaL_ref(L, t); }
    NOINLINE void luaL_register_dt(lua_State* L, const char* libname, const luaL_Reg* l) { return luaL_register(L, libname, l); }
    NOINLINE void luaL_setfuncs_dt(lua_State* L, const luaL_Reg* l, int nup) { return luaL_setfuncs(L, l, nup); }
    NOINLINE void luaL_setmetatable_dt(lua_State* L, const char* tname) { return luaL_setmetatable(L, tname); }
    NOINLINE void* luaL_testudata_dt(lua_State* L, int ud, const char* tname) { return luaL_testudata(L, ud, tname); }
    NOINLINE void luaL_traceback_dt(lua_State* L, lua_State* L1, const char* msg, int level) { return luaL_traceback(L, L1, msg, level); }
    NOINLINE int luaL_typerror_dt(lua_State* L, int narg, const char* tname) { return luaL_typerror(L, narg, tname); }
    NOINLINE void luaL_unref_dt(lua_State* L, int t, int ref) { return luaL_unref(L, t, ref); }
    NOINLINE void luaL_where_dt(lua_State* L, int lvl) { return luaL_where(L, lvl); }

    NOINLINE lua_CFunction lua_atpanic_dt(lua_State* L, lua_CFunction panicf) { return lua_atpanic(L, panicf); }
    NOINLINE void lua_call_dt(lua_State* L, int nargs, int nresults) { return lua_call(L, nargs, nresults); }
    NOINLINE int lua_checkstack_dt(lua_State* L, int size) { return lua_checkstack(L, size); }
    NOINLINE void lua_close_dt(lua_State* L) { return lua_close(L); }
    NOINLINE void lua_concat_dt(lua_State* L, int n) { return lua_concat(L, n); }
    NOINLINE void lua_copy_dt(lua_State* L, int fromidx, int toidx) { return lua_copy(L, fromidx, toidx); }
    NOINLINE int lua_cpcall_dt(lua_State* L, lua_CFunction func, void* ud) { return lua_cpcall(L, func, ud); }
    NOINLINE void lua_createtable_dt(lua_State* L, int narray, int nrec) { return lua_createtable(L, narray, nrec); }
    NOINLINE int lua_dump_dt(lua_State* L, lua_Writer writer, void* data) { return lua_dump(L, writer, data); }
    NOINLINE int lua_equal_dt(lua_State* L, int idx1, int idx2) { return lua_equal(L, idx1, idx2); }
    NOINLINE int lua_error_dt(lua_State* L) { return lua_error(L); }
    NOINLINE int lua_gc_dt(lua_State* L, int what, int data) { return lua_gc(L, what, data); }
    NOINLINE lua_Alloc lua_getallocf_dt(lua_State* L, void** ud) { return lua_getallocf(L, ud); }
    NOINLINE void lua_getfenv_dt(lua_State* L, int idx) { return lua_getfenv(L, idx); }
    NOINLINE void lua_getfield_dt(lua_State* L, int idx, const char* k) { return lua_getfield(L, idx, k); }
    NOINLINE lua_Hook lua_gethook_dt(lua_State* L) { return lua_gethook(L); }
    NOINLINE int lua_gethookcount_dt(lua_State* L) { return lua_gethookcount(L); }
    NOINLINE int lua_gethookmask_dt(lua_State* L) { return lua_gethookmask(L); }
    NOINLINE int lua_getinfo_dt(lua_State* L, const char* what, lua_Debug* ar) { return lua_getinfo(L, what, ar); }
    NOINLINE const char* lua_getlocal_dt(lua_State* L, const lua_Debug* ar, int n) { return lua_getlocal(L, ar, n); }
    NOINLINE int lua_getmetatable_dt(lua_State* L, int idx) { return lua_getmetatable(L, idx); }
    NOINLINE int lua_getstack_dt(lua_State* L, int level, lua_Debug* ar) { return lua_getstack(L, level, ar); }
    NOINLINE void lua_gettable_dt(lua_State* L, int idx) { return lua_gettable(L, idx); }
    NOINLINE int lua_gettop_dt(lua_State* L) { return lua_gettop(L); }
    NOINLINE const char* lua_getupvalue_dt(lua_State* L, int idx, int n) { return lua_getupvalue(L, idx, n); }
    NOINLINE void lua_insert_dt(lua_State* L, int idx) { return lua_insert(L, idx); }
    NOINLINE int lua_iscfunction_dt(lua_State* L, int idx) { return lua_iscfunction(L, idx); }
    NOINLINE int lua_isnumber_dt(lua_State* L, int idx) { return lua_isnumber(L, idx); }
    NOINLINE int lua_isstring_dt(lua_State* L, int idx) { return lua_isstring(L, idx); }
    NOINLINE int lua_isuserdata_dt(lua_State* L, int idx) { return lua_isuserdata(L, idx); }
    NOINLINE int lua_isyieldable_dt(lua_State* L) { return lua_isyieldable(L); }
    NOINLINE int lua_lessthan_dt(lua_State* L, int idx1, int idx2) { return lua_lessthan(L, idx1, idx2); }
    NOINLINE int lua_load_dt(lua_State* L, lua_Reader reader, void* data, const char* chunkname) { return lua_load(L, reader, data, chunkname); }
    NOINLINE int lua_loadx_dt(lua_State* L, lua_Reader reader, void* data, const char* chunkname, const char* mode) { return lua_loadx(L, reader, data, chunkname, mode); }
    NOINLINE lua_State* lua_newstate_dt(lua_Alloc f, void* ud) { return lua_newstate(f, ud); }
    NOINLINE lua_State* lua_newthread_dt(lua_State* L) { return lua_newthread(L); }
    NOINLINE void* lua_newuserdata_dt(lua_State* L, size_t size) { return lua_newuserdata(L, size); }
    NOINLINE int lua_next_dt(lua_State* L, int idx) { return lua_next(L, idx); }
    NOINLINE size_t lua_objlen_dt(lua_State* L, int idx) { return lua_objlen(L, idx); }
    NOINLINE int lua_pcall_dt(lua_State* L, int nargs, int nresults, int errfunc) { return lua_pcall(L, nargs, nresults, errfunc); }
    NOINLINE void lua_pushboolean_dt(lua_State* L, int b) { return lua_pushboolean(L, b); }
    NOINLINE void lua_pushcclosure_dt(lua_State* L, lua_CFunction f, int n) { return lua_pushcclosure(L, f, n); }
    NOINLINE const char* lua_pushfstring_dt(lua_State* L, const char* fmt, ...) {
        va_list args;
        va_start(args, fmt);
        const char* result = lua_pushvfstring(L, fmt, args);
        va_end(args);
        return result;
    }
    NOINLINE void lua_pushinteger_dt(lua_State* L, lua_Integer n) { return lua_pushinteger(L, n); }
    NOINLINE void lua_pushlightuserdata_dt(lua_State* L, void* p) { return lua_pushlightuserdata(L, p); }
    NOINLINE void lua_pushlstring_dt(lua_State* L, const char* str, size_t len) { return lua_pushlstring(L, str, len); }
    NOINLINE void lua_pushnil_dt(lua_State* L) { return lua_pushnil(L); }
    NOINLINE void lua_pushnumber_dt(lua_State* L, lua_Number n) { return lua_pushnumber(L, n); }
    NOINLINE void lua_pushstring_dt(lua_State* L, const char* str) { return lua_pushstring(L, str); }
    NOINLINE int lua_pushthread_dt(lua_State* L) { return lua_pushthread(L); }
    NOINLINE void lua_pushvalue_dt(lua_State* L, int idx) { return lua_pushvalue(L, idx); }
    NOINLINE const char* lua_pushvfstring_dt(lua_State* L, const char* fmt, va_list argp) { return lua_pushvfstring(L, fmt, argp); }
    NOINLINE int lua_rawequal_dt(lua_State* L, int idx1, int idx2) { return lua_rawequal(L, idx1, idx2); }
    NOINLINE void lua_rawget_dt(lua_State* L, int idx) { return lua_rawget(L, idx); }
    NOINLINE void lua_rawgeti_dt(lua_State* L, int idx, int n) { return lua_rawgeti(L, idx, n); }
    NOINLINE void lua_rawset_dt(lua_State* L, int idx) { return lua_rawset(L, idx); }
    NOINLINE void lua_rawseti_dt(lua_State* L, int idx, int n) { return lua_rawseti(L, idx, n); }
    NOINLINE void lua_remove_dt(lua_State* L, int idx) { return lua_remove(L, idx); }
    NOINLINE void lua_replace_dt(lua_State* L, int idx) { return lua_replace(L, idx); }
    NOINLINE void lua_setallocf_dt(lua_State* L, lua_Alloc f, void* ud) { return lua_setallocf(L, f, ud); }
    NOINLINE int lua_setfenv_dt(lua_State* L, int idx) { return lua_setfenv(L, idx); }
    NOINLINE void lua_setfield_dt(lua_State* L, int idx, const char* k) { return lua_setfield(L, idx, k); }
    NOINLINE int lua_sethook_dt(lua_State* L, lua_Hook func, int mask, int count) { return lua_sethook(L, func, mask, count); }
    NOINLINE const char* lua_setlocal_dt(lua_State* L, const lua_Debug* ar, int n) { return lua_setlocal(L, ar, n); }
    NOINLINE int lua_setmetatable_dt(lua_State* L, int idx) { return lua_setmetatable(L, idx); }
    NOINLINE void lua_settable_dt(lua_State* L, int idx) { return lua_settable(L, idx); }
    NOINLINE void lua_settop_dt(lua_State* L, int idx) { return lua_settop(L, idx); }
    NOINLINE const char* lua_setupvalue_dt(lua_State* L, int idx, int n) { return lua_setupvalue(L, idx, n); }
    NOINLINE int lua_status_dt(lua_State* L) { return lua_status(L); }
    NOINLINE int lua_toboolean_dt(lua_State* L, int idx) { return lua_toboolean(L, idx); }
    NOINLINE lua_CFunction lua_tocfunction_dt(lua_State* L, int idx) { return lua_tocfunction(L, idx); }
    NOINLINE lua_Integer lua_tointeger_dt(lua_State* L, int idx) { return lua_tointeger(L, idx); }
    NOINLINE lua_Integer lua_tointegerx_dt(lua_State* L, int idx, int* ok) { return lua_tointegerx(L, idx, ok); }
    NOINLINE const char* lua_tolstring_dt(lua_State* L, int idx, size_t* len) { return lua_tolstring(L, idx, len); }
    NOINLINE lua_Number lua_tonumber_dt(lua_State* L, int idx) { return lua_tonumber(L, idx); }
    NOINLINE lua_Number lua_tonumberx_dt(lua_State* L, int idx, int* ok) { return lua_tonumberx(L, idx, ok); }
    NOINLINE const void* lua_topointer_dt(lua_State* L, int idx) { return lua_topointer(L, idx); }
    NOINLINE lua_State* lua_tothread_dt(lua_State* L, int idx) { return lua_tothread(L, idx); }
    NOINLINE void* lua_touserdata_dt(lua_State* L, int idx) { return lua_touserdata(L, idx); }
    NOINLINE int lua_type_dt(lua_State* L, int idx) { return lua_type(L, idx); }
    NOINLINE const char* lua_typename_dt(lua_State* L, int t) { return lua_typename(L, t); }
    NOINLINE void* lua_upvalueid_dt(lua_State* L, int idx, int n) { return lua_upvalueid(L, idx, n); }
    NOINLINE void lua_upvaluejoin_dt(lua_State* L, int idx1, int n1, int idx2, int n2) { return lua_upvaluejoin(L, idx1, n1, idx2, n2); }
    NOINLINE const lua_Number* lua_version_dt(lua_State* L) { return lua_version(L); }
    NOINLINE void lua_xmove_dt(lua_State* from, lua_State* to, int n) { return lua_xmove(from, to, n); }
    NOINLINE int lua_yield_dt(lua_State* L, int nresults) { return lua_yield(L, nresults); }

    // Exposure of extra libraries to LJ
    NOINLINE void luaL_openlibs_dtr(lua_State* L)
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

    END_NOOPT
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
        using namespace Overrides;

        add("luaJIT_setmode", (void*)luaJIT_setmode_dt);

        add("luaopen_base", (void*)luaopen_base_dt);
        add("luaopen_bit", (void*)luaopen_bit_dt);
        add("luaopen_debug", (void*)luaopen_debug_dt);
        add("luaopen_jit", (void*)luaopen_jit_dt);
        add("luaopen_math", (void*)luaopen_math_dt);
        add("luaopen_os", (void*)luaopen_os_dt);
        add("luaopen_package", (void*)luaopen_package_dt);
        add("luaopen_string", (void*)luaopen_string_dt);
        add("luaopen_table", (void*)luaopen_table_dt);

        add("luaL_addlstring", (void*)luaL_addlstring_dt);
        add("luaL_addstring", (void*)luaL_addstring_dt);
        add("luaL_addvalue", (void*)luaL_addvalue_dt);
        add("luaL_argerror", (void*)luaL_argerror_dt);
        add("luaL_buffinit", (void*)luaL_buffinit_dt);
        add("luaL_callmeta", (void*)luaL_callmeta_dt);
        add("luaL_checkany", (void*)luaL_checkany_dt);
        add("luaL_checkinteger", (void*)luaL_checkinteger_dt);
        add("luaL_checklstring", (void*)luaL_checklstring_dt);
        add("luaL_checknumber", (void*)luaL_checknumber_dt);
        add("luaL_checkoption", (void*)luaL_checkoption_dt);
        add("luaL_checkstack", (void*)luaL_checkstack_dt);
        add("luaL_checktype", (void*)luaL_checktype_dt);
        add("luaL_checkudata", (void*)luaL_checkudata_dt);
        add("luaL_error", (void*)luaL_error_dt);
        add("luaL_execresult", (void*)luaL_execresult_dt);
        add("luaL_fileresult", (void*)luaL_fileresult_dt);
        add("luaL_findtable", (void*)luaL_findtable_dt);
        add("luaL_getmetafield", (void*)luaL_getmetafield_dt);
        add("luaL_gsub", (void*)luaL_gsub_dt);
        add("luaL_loadbuffer", (void*)luaL_loadbuffer_dt);
        add("luaL_loadbufferx", (void*)luaL_loadbufferx_dt);
        add("luaL_loadfile", (void*)luaL_loadfile_dt);
        add("luaL_loadfilex", (void*)luaL_loadfilex_dt);
        add("luaL_loadstring", (void*)luaL_loadstring_dt);
        add("luaL_newmetatable", (void*)luaL_newmetatable_dt);
        add("luaL_newstate", (void*)luaL_newstate_dt);
        add("luaL_openlib", (void*)luaL_openlib_dt);
        add("luaL_openlibs", (void*)luaL_openlibs_dtr);
        add("luaL_optinteger", (void*)luaL_optinteger_dt);
        add("luaL_optlstring", (void*)luaL_optlstring_dt);
        add("luaL_optnumber", (void*)luaL_optnumber_dt);
        add("luaL_prepbuffer", (void*)luaL_prepbuffer_dt);
        add("luaL_pushmodule", (void*)luaL_pushmodule_dt);
        add("luaL_pushresult", (void*)luaL_pushresult_dt);
        add("luaL_ref", (void*)luaL_ref_dt);
        add("luaL_register", (void*)luaL_register_dt);
        add("luaL_setfuncs", (void*)luaL_setfuncs_dt);
        add("luaL_setmetatable", (void*)luaL_setmetatable_dt);
        add("luaL_testudata", (void*)luaL_testudata_dt);
        add("luaL_traceback", (void*)luaL_traceback_dt);
        add("luaL_typerror", (void*)luaL_typerror_dt);
        add("luaL_unref", (void*)luaL_unref_dt);
        add("luaL_where", (void*)luaL_where_dt);

        add("lua_atpanic", (void*)lua_atpanic_dt);
        add("lua_call", (void*)lua_call_dt);
        add("lua_checkstack", (void*)lua_checkstack_dt);
        add("lua_close", (void*)lua_close_dt);
        add("lua_concat", (void*)lua_concat_dt);
        add("lua_copy", (void*)lua_copy_dt);
        add("lua_cpcall", (void*)lua_cpcall_dt);
        add("lua_createtable", (void*)lua_createtable_dt);
        add("lua_dump", (void*)lua_dump_dt);
        add("lua_equal", (void*)lua_equal_dt);
        add("lua_error", (void*)lua_error_dt);
        add("lua_gc", (void*)lua_gc_dt);
        add("lua_getallocf", (void*)lua_getallocf_dt);
        add("lua_getfenv", (void*)lua_getfenv_dt);
        add("lua_getfield", (void*)lua_getfield_dt);
        add("lua_gethook", (void*)lua_gethook_dt);
        add("lua_gethookcount", (void*)lua_gethookcount_dt);
        add("lua_gethookmask", (void*)lua_gethookmask_dt);
        add("lua_getinfo", (void*)lua_getinfo_dt);
        add("lua_getlocal", (void*)lua_getlocal_dt);
        add("lua_getmetatable", (void*)lua_getmetatable_dt);
        add("lua_getstack", (void*)lua_getstack_dt);
        add("lua_gettable", (void*)lua_gettable_dt);
        add("lua_gettop", (void*)lua_gettop_dt);
        add("lua_getupvalue", (void*)lua_getupvalue_dt);
        add("lua_insert", (void*)lua_insert_dt);
        add("lua_iscfunction", (void*)lua_iscfunction_dt);
        add("lua_isnumber", (void*)lua_isnumber_dt);
        add("lua_isstring", (void*)lua_isstring_dt);
        add("lua_isuserdata", (void*)lua_isuserdata_dt);
        add("lua_isyieldable", (void*)lua_isyieldable_dt);
        add("lua_lessthan", (void*)lua_lessthan_dt);
        add("lua_load", (void*)lua_load_dt);
        add("lua_loadx", (void*)lua_loadx_dt);
        add("lua_newstate", (void*)lua_newstate_dt);
        add("lua_newthread", (void*)lua_newthread_dt);
        add("lua_newuserdata", (void*)lua_newuserdata_dt);
        add("lua_next", (void*)lua_next_dt);
        add("lua_objlen", (void*)lua_objlen_dt);
        add("lua_pcall", (void*)lua_pcall_dt);
        add("lua_pushboolean", (void*)lua_pushboolean_dt);
        add("lua_pushcclosure", (void*)lua_pushcclosure_dt);
        add("lua_pushfstring", (void*)lua_pushfstring_dt);
        add("lua_pushinteger", (void*)lua_pushinteger_dt);
        add("lua_pushlightuserdata", (void*)lua_pushlightuserdata_dt);
        add("lua_pushlstring", (void*)lua_pushlstring_dt);
        add("lua_pushnil", (void*)lua_pushnil_dt);
        add("lua_pushnumber", (void*)lua_pushnumber_dt);
        add("lua_pushstring", (void*)lua_pushstring_dt);
        add("lua_pushthread", (void*)lua_pushthread_dt);
        add("lua_pushvalue", (void*)lua_pushvalue_dt);
        add("lua_pushvfstring", (void*)lua_pushvfstring_dt);
        add("lua_rawequal", (void*)lua_rawequal_dt);
        add("lua_rawget", (void*)lua_rawget_dt);
        add("lua_rawgeti", (void*)lua_rawgeti_dt);
        add("lua_rawset", (void*)lua_rawset_dt);
        add("lua_rawseti", (void*)lua_rawseti_dt);
        add("lua_remove", (void*)lua_remove_dt);
        add("lua_replace", (void*)lua_replace_dt);
        add("lua_setallocf", (void*)lua_setallocf_dt);
        add("lua_setfenv", (void*)lua_setfenv_dt);
        add("lua_setfield", (void*)lua_setfield_dt);
        add("lua_sethook", (void*)lua_sethook_dt);
        add("lua_setlocal", (void*)lua_setlocal_dt);
        add("lua_setmetatable", (void*)lua_setmetatable_dt);
        add("lua_settable", (void*)lua_settable_dt);
        add("lua_settop", (void*)lua_settop_dt);
        add("lua_setupvalue", (void*)lua_setupvalue_dt);
        add("lua_status", (void*)lua_status_dt);
        add("lua_toboolean", (void*)lua_toboolean_dt);
        add("lua_tocfunction", (void*)lua_tocfunction_dt);
        add("lua_tointeger", (void*)lua_tointeger_dt);
        add("lua_tointegerx", (void*)lua_tointegerx_dt);
        add("lua_tolstring", (void*)lua_tolstring_dt);
        add("lua_tonumber", (void*)lua_tonumber_dt);
        add("lua_tonumberx", (void*)lua_tonumberx_dt);
        add("lua_topointer", (void*)lua_topointer_dt);
        add("lua_tothread", (void*)lua_tothread_dt);
        add("lua_touserdata", (void*)lua_touserdata_dt);
        add("lua_type", (void*)lua_type_dt);
        add("lua_typename", (void*)lua_typename_dt);
        add("lua_upvalueid", (void*)lua_upvalueid_dt);
        add("lua_upvaluejoin", (void*)lua_upvaluejoin_dt);
        add("lua_version", (void*)lua_version_dt);
        add("lua_xmove", (void*)lua_xmove_dt);
        add("lua_yield", (void*)lua_yield_dt);
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