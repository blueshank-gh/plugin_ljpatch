#include <cstdint>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>
#include <memory>
#include <stdio.h>

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

    #if defined(__x86_64__) || defined(_M_X64)
        std::vector<PLH::x64Detour*>& get_tracking() {
            static std::vector<PLH::x64Detour*> tracking;
            return tracking;
        }
    #elif defined(__i386__) || defined(_M_IX86)
        std::vector<PLH::x86Detour*>& get_tracking() {
            static std::vector<PLH::x86Detour*> tracking;
            return tracking;
        }
    #endif

    bool override(void* target, void* hook) {
        static void* nothing = nullptr;

        #if defined(__x86_64__) || defined(_M_X64)
            auto detour = new PLH::x64Detour(
                (uint64_t)target,
                (uint64_t)hook,
                (uint64_t*)&nothing
            );
        #elif defined(__i386__) || defined(_M_IX86)
            auto detour = new PLH::x86Detour(
                (uint64_t)target,
                (uint64_t)hook,
                (uint64_t*)&nothing
            );
        #endif

        if (!detour->hook()) {
            detour->unHook();
            return false;
        }

        get_tracking().push_back(detour);
        nothing = nullptr;

        return true;
    }

    void unload() {
        auto& list = get_tracking();
        for (auto& entry : list) {
            entry->unHook();
        }
        list.clear();
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

    std::vector<std::pair<std::string, void*>> apis = {
        { "luaJIT_setmode", luaJIT_setmode },

        { "luaopen_base", luaopen_base },
        { "luaopen_bit", luaopen_bit },
        { "luaopen_debug", luaopen_debug },
        { "luaopen_jit", luaopen_jit },
        { "luaopen_math", luaopen_math },
        { "luaopen_os", luaopen_os },
        { "luaopen_package", luaopen_package },
        { "luaopen_string", luaopen_string },
        { "luaopen_table", luaopen_table },

        { "luaL_addlstring", luaL_addlstring },
        { "luaL_addstring", luaL_addstring },
        { "luaL_addvalue", luaL_addvalue },
        { "luaL_argerror", luaL_argerror },
        { "luaL_buffinit", luaL_buffinit },
        { "luaL_callmeta", luaL_callmeta },
        { "luaL_checkany", luaL_checkany },
        { "luaL_checkinteger", luaL_checkinteger },
        { "luaL_checklstring", luaL_checklstring },
        { "luaL_checknumber", luaL_checknumber },
        { "luaL_checkoption", luaL_checkoption },
        { "luaL_checkstack", luaL_checkstack },
        { "luaL_checktype", luaL_checktype },
        { "luaL_checkudata", luaL_checkudata },
        { "luaL_error", luaL_error },
        { "luaL_execresult", luaL_execresult },
        { "luaL_fileresult", luaL_fileresult },
        { "luaL_findtable", luaL_findtable },
        { "luaL_getmetafield", luaL_getmetafield },
        { "luaL_gsub", luaL_gsub },
        { "luaL_loadbuffer", luaL_loadbuffer },
        { "luaL_loadbufferx", luaL_loadbufferx },
        { "luaL_loadfile", luaL_loadfile },
        { "luaL_loadfilex", luaL_loadfilex },
        { "luaL_loadstring", luaL_loadstring },
        { "luaL_newmetatable", luaL_newmetatable },
        { "luaL_newstate", luaL_newstate },
        { "luaL_openlib", luaL_openlib },
        { "luaL_openlibs", luaL_openlibs_dt },
        { "luaL_optinteger", luaL_optinteger },
        { "luaL_optlstring", luaL_optlstring },
        { "luaL_optnumber", luaL_optnumber },
        { "luaL_prepbuffer", luaL_prepbuffer },
        { "luaL_pushmodule", luaL_pushmodule },
        { "luaL_pushresult", luaL_pushresult },
        { "luaL_ref", luaL_ref },
        { "luaL_register", luaL_register },
        { "luaL_setfuncs", luaL_setfuncs },
        { "luaL_setmetatable", luaL_setmetatable },
        { "luaL_testudata", luaL_testudata },
        { "luaL_traceback", luaL_traceback },
        { "luaL_typerror", luaL_typerror },
        { "luaL_unref", luaL_unref },
        { "luaL_where", luaL_where },

        { "lua_atpanic", lua_atpanic },
        { "lua_call", lua_call },
        { "lua_checkstack", lua_checkstack },
        { "lua_close", lua_close },
        { "lua_concat", lua_concat },
        { "lua_copy", lua_copy },
        { "lua_cpcall", lua_cpcall },
        { "lua_createtable", lua_createtable },
        { "lua_dump", lua_dump },
        { "lua_equal", lua_equal },
        { "lua_error", lua_error },
        { "lua_gc", lua_gc },
        { "lua_getallocf", lua_getallocf },
        { "lua_getfenv", lua_getfenv },
        { "lua_getfield", lua_getfield },
        { "lua_gethook", lua_gethook },
        { "lua_gethookcount", lua_gethookcount },
        { "lua_gethookmask", lua_gethookmask },
        { "lua_getinfo", lua_getinfo },
        { "lua_getlocal", lua_getlocal },
        { "lua_getmetatable", lua_getmetatable },
        { "lua_getstack", lua_getstack },
        { "lua_gettable", lua_gettable },
        { "lua_gettop", lua_gettop },
        { "lua_getupvalue", lua_getupvalue },
        { "lua_insert", lua_insert },
        { "lua_iscfunction", lua_iscfunction },
        { "lua_isnumber", lua_isnumber },
        { "lua_isstring", lua_isstring },
        { "lua_isuserdata", lua_isuserdata },
        { "lua_isyieldable", lua_isyieldable },
        { "lua_lessthan", lua_lessthan },
        { "lua_load", lua_load },
        { "lua_loadx", lua_loadx },
        { "lua_newstate", lua_newstate },
        { "lua_newthread", lua_newthread },
        { "lua_newuserdata", lua_newuserdata },
        { "lua_next", lua_next },
        { "lua_objlen", lua_objlen },
        { "lua_pcall", lua_pcall },
        { "lua_pushboolean", lua_pushboolean },
        { "lua_pushcclosure", lua_pushcclosure },
        { "lua_pushfstring", lua_pushfstring },
        { "lua_pushinteger", lua_pushinteger },
        { "lua_pushlightuserdata", lua_pushlightuserdata },
        { "lua_pushlstring", lua_pushlstring },
        { "lua_pushnil", lua_pushnil },
        { "lua_pushnumber", lua_pushnumber },
        { "lua_pushstring", lua_pushstring },
        { "lua_pushthread", lua_pushthread },
        { "lua_pushvalue", lua_pushvalue },
        { "lua_pushvfstring", lua_pushvfstring },
        { "lua_rawequal", lua_rawequal },
        { "lua_rawget", lua_rawget },
        { "lua_rawgeti", lua_rawgeti },
        { "lua_rawset", lua_rawset },
        { "lua_rawseti", lua_rawseti },
        { "lua_remove", lua_remove },
        { "lua_replace", lua_replace },
        { "lua_setallocf", lua_setallocf },
        { "lua_setfenv", lua_setfenv },
        { "lua_setfield", lua_setfield },
        { "lua_sethook", lua_sethook },
        { "lua_setlocal", lua_setlocal },
        { "lua_setmetatable", lua_setmetatable },
        { "lua_settable", lua_settable },
        { "lua_settop", lua_settop },
        { "lua_setupvalue", lua_setupvalue },
        { "lua_status", lua_status },
        { "lua_toboolean", lua_toboolean },
        { "lua_tocfunction", lua_tocfunction },
        { "lua_tointeger", lua_tointeger },
        { "lua_tointegerx", lua_tointegerx },
        { "lua_tolstring", lua_tolstring },
        { "lua_tonumber", lua_tonumber },
        { "lua_tonumberx", lua_tonumberx },
        { "lua_topointer", lua_topointer },
        { "lua_tothread", lua_tothread },
        { "lua_touserdata", lua_touserdata },
        { "lua_type", lua_type },
        { "lua_typename", lua_typename },
        { "lua_upvalueid", lua_upvalueid },
        { "lua_upvaluejoin", lua_upvaluejoin },
        { "lua_version", lua_version },
        { "lua_xmove", lua_xmove },
        { "lua_yield", lua_yield }
    };

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

    size_t count = 0;
    std::cout << "[LJPatch] Patching..." << std::endl;
    for (const auto& entry : apis) {
        void* target = Framework::n2p(lua_shared, entry.first.c_str());
        if (target == nullptr) {
            std::cout << "[LJPatch] [WARNING] Couldn't locate " << entry.first << "!" << std::endl;
        } else if (!Framework::override(target, entry.second)) {
            std::cout << "[LJPatch] [WARNING] Couldn't modify " << entry.first << "!" << std::endl;
        } else {
            count++;
        }
    }
    std::cout << "[LJPatch] Restored: " << count << " / " << apis.size() << " APIs" << std::endl;

    return true;
}

//---------------------------------------------------------------------------------
// Purpose: called when the plugin is unloaded (turned off)
//---------------------------------------------------------------------------------
void LJPatchPlugin::Unload(void)
{
    std::cout << "[LJPatch] Unloading..." << std::endl;
    Framework::unload();
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