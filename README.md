# LJ Patch
A rollback to LuaJIT in Garry's Mod.\
This was made to undo certain changes that has been applied to LuaJIT.\
With improvements to LuaJIT itself can now be made possible.

Currently only x64 builds appear to work due to some oddities in x86 lua_shared.\
Feel free to contribute to fully supporting this on all architectures and platforms.

## Dangers
This restores dangerous API's such as FFI to LuaJIT, you have been warned.