<div align="center">
  <picture>
  <img width="590" height="159" src="./logo.png">
  </picture>


</div>

## Dangers
**FFI is disabled by default.**\
Add `-ffi` to the server or client launch command line to enable it, without that flag the `ffi` module is not exposed to Lua.

## Installation
### Server
Place the binary you need in a reachable place, such as `garrysmod/lua/bin/*`.\
After which under `garrysmod/addons/*` create a new `.vdf` file, like `plugin_ljpatch.vdf`.\
Inside this file you write plugin target information, for example for x64 windows:
```
Plugin
{
    file "lua/bin/plugin_ljpatch_win64.dll"
}
```
And thats it!

### Client
Clients don't load plugins, so we have to preload the patcher instead.\
The module mimics the full export table of `version.dll`, `winmm.dll`, `winhttp.dll`, and `wininet.dll`, so it can be copied under any of those names.

Currently, linux client is being looked into for support at some point, just not right now, but it's on the roadmap.

## Modifications
This plugin isn't strictly made to just rollback LuaJIT but to also allow you to modify LuaJIT itself with your own features.\
Just make sure that the exposed API's under `LUA_API` directive is all supported, as changing their parameters and returns can cause problems.\
You can modify LuaJIT itself by changing the submodule under the `luajit` folder.
