<div align="center">
  <picture>
  <img width="590" height="159" src="./logo.png">
  </picture>


</div>

## Dangers
This restores dangerous API's such as FFI to LuaJIT, you have been warned.

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
After building, rename your module to `version.dll` (as that's what it mimics), and put it in the same folder as `gmod.exe` of the respective bitness.\
i.e. `GarrysMod/bin/win64/version.dll` for `x86-64` 64-bit client.

Currently, only windows is supported for clients; it shouldn't be hard to add linux support via LD_PRELOAD, so we'll be happy if someone makes a PR.

## Modifications
This plugin isn't strictly made to just rollback LuaJIT but to also allow you to modify LuaJIT itself with your own features.\
Just make sure that the exposed API's under `LUA_API` directive is all supported, as changing their parameters and returns can cause problems.\
You can modify LuaJIT itself by changing the submodule under the `luajit` folder.
