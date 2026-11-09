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

static bool LJPatchFFIEnabled()
{
    static int enabled = -1;
    if (enabled >= 0)
        return enabled != 0;

    bool found = false;
    #if defined(_WIN32)
        const char* cmdline = GetCommandLineA();
        const char* p = cmdline;
        while (p && *p) {
            while (*p == ' ' || *p == '\t')
                p++;
            if (!*p)
                break;

            bool quoted = (*p == '"');
            if (quoted)
                p++;
            const char* start = p;
            if (quoted) {
                while (*p && *p != '"')
                    p++;
            } else {
                while (*p && *p != ' ' && *p != '\t')
                    p++;
            }

            size_t len = (size_t)(p - start);
            if (len == 4) {
                bool match = true;
                const char* pat = "-ffi";
                for (size_t i = 0; i < 4; i++) {
                    char c = start[i];
                    if (c >= 'A' && c <= 'Z')
                        c = (char)(c - 'A' + 'a');
                    if (c != pat[i]) {
                        match = false;
                        break;
                    }
                }
                if (match) {
                    found = true;
                    break;
                }
            }
            if (quoted && *p == '"')
                p++;
        }
    #else
        FILE* f = fopen("/proc/self/cmdline", "rb");
        if (f) {
            std::string args;
            char buf[4096];
            size_t n;
            while ((n = fread(buf, 1, sizeof(buf), f)) > 0)
                args.append(buf, n);
            fclose(f);

            size_t pos = 0;
            while (pos < args.size()) {
                size_t end = args.find('\0', pos);
                if (end == std::string::npos)
                    end = args.size();
                if (end - pos == 4 && args.compare(pos, 4, "-ffi") == 0) {
                    found = true;
                    break;
                }
                pos = end + 1;
            }
        }
    #endif

    enabled = found ? 1 : 0;
    std::cout << "[LJPatch] FFI: " << (found ? "enabled (-ffi)" : "disabled (pass -ffi to enable)") << std::endl;
    return found;
}

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
                if (!Framework::make_writeable(target, true, 16)) {
                    return false;
                }
            }

            char* buffer = (char*)target;

            #if defined(__x86_64__) || defined(_M_X64)
                intptr_t relative = (intptr_t)data->routine - ((intptr_t)buffer + 5);

                if (relative >= INT32_MIN && relative <= INT32_MAX) {
                    // SIZE: 5
                    // jmp -> E9 XX XX XX XX (offset from PC)
                    data->store.assign(buffer, buffer + 5);
                    buffer[0] = (char)0xE9;
                    int32_t offset = (int32_t)relative;
                    memcpy(buffer + 1, &offset, sizeof(offset));
                }
                else {
                    // SIZE: 12
                    // mov rax, imm64 -> 48 B8 XX XX XX XX XX XX XX XX
                    // jmp rax -> FF E0
                    data->store.assign(buffer, buffer + 12);
                    buffer[0] = (char)0x48; buffer[1] = (char)0xB8;
                    void* routine = data->routine;
                    memcpy(buffer + 2, &routine, sizeof(routine));
                    buffer[10] = (char)0xFF; buffer[11] = (char)0xE0;
                }
            #elif defined(__i386__) || defined(_M_IX86)
                // SIZE: 5
                // jmp -> E9 XX XX XX XX (offset from PC)
                data->store.assign(buffer, buffer + 5);
                buffer[0] = (char)0xE9;
                int32_t offset = (int32_t)((intptr_t)data->routine - ((intptr_t)buffer + 5));
                memcpy(buffer + 1, &offset, sizeof(offset));
            #endif

            #if defined(_WIN32)
                FlushInstructionCache(GetCurrentProcess(), buffer, data->store.size());
            #elif defined(__linux)
                __builtin___clear_cache(buffer, buffer + data->store.size());
            #endif

            if (!writeable) {
                Framework::make_writeable(target, false, data->store.size());
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

#ifdef INTERFACE_PLUGIN
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
#endif

//---------------------------------------------------------------------------------
// Purpose: called when the plugin is loaded, load the interface we need from the engine
//---------------------------------------------------------------------------------

#include "glua/Interface.h"
#include "glua/LuaInterface.h"
#include "glua/LuaShared.h"

namespace Overrides {
    int lua_resume_real_dt(lua_State* L, int nargs) { return lua_resume(L, nargs); }

    static bool DropLuaGlobal(lua_State* L, const char* name)
    {
        lua_getfield(L, LUA_GLOBALSINDEX, name);
        bool present = !lua_isnil(L, -1);
        lua_pop(L, 1);
        lua_pushnil(L);
        lua_setfield(L, LUA_GLOBALSINDEX, name);
        return present;
    }

    static bool DropLuaField(lua_State* L, const char* tableName, const char* field)
    {
        bool present = false;
        lua_getfield(L, LUA_GLOBALSINDEX, tableName);
        if (lua_istable(L, -1)) {
            lua_getfield(L, -1, field);
            present = !lua_isnil(L, -1);
            lua_pop(L, 1);
            lua_pushnil(L);
            lua_setfield(L, -2, field);
        }
        lua_pop(L, 1);
        return present;
    }

    static bool DropNativeLoaders(lua_State* L)
    {
        bool removed = false;
        lua_getfield(L, LUA_GLOBALSINDEX, "package");
        if (lua_istable(L, -1)) {
            lua_getfield(L, -1, "loaders");
            if (lua_istable(L, -1)) {
                for (int i = 3; ; ++i) {
                    lua_rawgeti(L, -1, i);
                    bool present = !lua_isnil(L, -1);
                    lua_pop(L, 1);
                    if (!present)
                        break;
                    lua_pushnil(L);
                    lua_rawseti(L, -2, i);
                    removed = true;
                }
            }
            lua_pop(L, 1);
        }
        lua_pop(L, 1);
        return removed;
    }

    static void SanitizeLua(lua_State* L)
    {
        bool dropped = false;
        dropped |= DropLuaGlobal(L, "io");
        dropped |= DropLuaGlobal(L, "dofile");
        dropped |= DropLuaField(L, "os", "execute");
        dropped |= DropLuaField(L, "os", "getenv");
        dropped |= DropLuaField(L, "os", "remove");
        dropped |= DropLuaField(L, "os", "rename");
        dropped |= DropLuaField(L, "os", "tmpname");
        dropped |= DropLuaField(L, "os", "exit");
        dropped |= DropLuaField(L, "os", "setlocale");
        dropped |= DropLuaField(L, "package", "loadlib");
        dropped |= DropNativeLoaders(L);
        if (dropped)
            std::cout << "[LJPatch] [WARNING] Removed unsafe Lua APIs from state" << std::endl;
    }

    void luaL_openlibs_dtr(lua_State* L)
    {
        luaL_openlibs(L);

        if (LJPatchFFIEnabled()) {
            lua_pushcfunction(L, luaopen_ffi);
            lua_pushstring(L, LUA_FFILIBNAME);
            lua_call(L, 1, 1);
            lua_setfield(L, LUA_GLOBALSINDEX, LUA_FFILIBNAME);
        } else {
            lua_pushnil(L);
            lua_setfield(L, LUA_GLOBALSINDEX, LUA_FFILIBNAME);

            lua_getfield(L, LUA_GLOBALSINDEX, "package");
            if (lua_istable(L, -1)) {
                lua_getfield(L, -1, "loaded");
                if (lua_istable(L, -1)) {
                    lua_pushnil(L);
                    lua_setfield(L, -2, LUA_FFILIBNAME);
                }
                lua_pop(L, 1);

                lua_getfield(L, -1, "preload");
                if (lua_istable(L, -1)) {
                    lua_pushnil(L);
                    lua_setfield(L, -2, LUA_FFILIBNAME);
                }
                lua_pop(L, 1);
            }
            lua_pop(L, 1);
        }

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

        lua_getfield(L, LUA_GLOBALSINDEX, "require");
        lua_pushstring(L, "jit.stat");
        lua_call(L, 1, 1);
        lua_setfield(L, -2, "stat");
        lua_pop(L, 1);

        SanitizeLua(L);
    }
}

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

namespace LJPatch {
    bool Load() {
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

            add("luaJIT_setmode", (void*)luaJIT_setmode);
            add("luaJIT_profile_start", (void*)luaJIT_profile_start);
            add("luaJIT_profile_stop", (void*)luaJIT_profile_stop);
            add("luaJIT_profile_dumpstack", (void*)luaJIT_profile_dumpstack);
            add("lua_resume_real", (void*)lua_resume_real_dt);

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
            add("luaL_newmetatable_type", (void*)luaL_newmetatable_type);
            add("luaL_newstate", (void*)luaL_newstate);
            add("luaL_openlib", (void*)luaL_openlib);
            add("luaL_openlibs", (void*)luaL_openlibs_dtr);
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

        std::cout << "[LJPatch] Patching..." << std::endl;
        size_t count = Framework::Routines::load(lua_shared);
        std::cout << "[LJPatch] Restored: " << count << " / " << Framework::Routines::count() << " APIs" << std::endl;

        return true;
    }
}

#ifdef INTERFACE_PLUGIN
bool LJPatchPlugin::Load(CreateInterfaceFn interfaceFactory, CreateInterfaceFn gameServerFactory)
{
    return LJPatch::Load();
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
#endif

#ifdef INTERFACE_PRELOAD
#include "mimic.h"

#if defined(_WIN32)
#include <guiddef.h>

static const char LJPatchMimicAnchor = 0;

static HMODULE LJPatchMimicTarget()
{
    static HMODULE target = []() -> HMODULE {
        const wchar_t* name = L"winhttp.dll";

        HMODULE self = nullptr;
        if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, reinterpret_cast<LPCWSTR>(&LJPatchMimicAnchor), &self)) {
            wchar_t path[MAX_PATH];
            DWORD length = GetModuleFileNameW(self, path, MAX_PATH);
            if (length > 0 && length < MAX_PATH) {
                const wchar_t* file = wcsrchr(path, L'\\');
                file = file ? file + 1 : path;
                if (_wcsicmp(file, L"wininet.dll") == 0)
                    name = L"wininet.dll";
            }
        }

        wchar_t directory[MAX_PATH];
        UINT directoryLength = GetSystemDirectoryW(directory, MAX_PATH);
        if (directoryLength == 0 || directoryLength >= MAX_PATH)
            return nullptr;

        std::wstring full(directory);
        full += L"\\";
        full += name;
        return LoadLibraryW(full.c_str());
    }();
    return target;
}

extern "C" HRESULT WINAPI LJPatchDllCanUnloadNow()
{
    typedef HRESULT (WINAPI* routine_t)();
    static routine_t routine = []() -> routine_t {
        HMODULE module = LJPatchMimicTarget();
        return module ? reinterpret_cast<routine_t>(GetProcAddress(module, "DllCanUnloadNow")) : nullptr;
    }();
    return routine ? routine() : S_FALSE;
}

extern "C" HRESULT WINAPI LJPatchDllGetClassObject(const GUID* rclsid, const GUID* riid, void** ppv)
{
    typedef HRESULT (WINAPI* routine_t)(const GUID*, const GUID*, void**);
    static routine_t routine = []() -> routine_t {
        HMODULE module = LJPatchMimicTarget();
        return module ? reinterpret_cast<routine_t>(GetProcAddress(module, "DllGetClassObject")) : nullptr;
    }();
    return routine ? routine(rclsid, riid, ppv) : CLASS_E_CLASSNOTAVAILABLE;
}
#endif

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH: {
        auto binary = LoadLibraryA(BINARY);
#ifdef BINARY2
        if (!binary) {
            binary = LoadLibraryA(BINARY2);
        }
#endif

        if (!binary) {
            std::cout << "[LJPatch] Failed to preload lua_shared.dll!" << std::endl;
        }
        else LJPatch::Load();

        break;
    }
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
#endif