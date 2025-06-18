<div align="center">
  <picture>
  <img width="590" height="159" src="./logo.png">
  </picture>


</div>

## Dangers
This restores dangerous API's such as FFI to LuaJIT, you have been warned.

## Installation
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

## Modifications
This plugin isn't strictly made to just rollback LuaJIT but to also allow you to modify LuaJIT itself with your own features.\
Just make sure that the exposed API's under `LUA_API` directive is all supported, as changing their parameters and returns can cause problems.\
You can modify LuaJIT itself by changing the submodule under the `luajit` folder.
