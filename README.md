# LJ Patch
A rollback to LuaJIT in Garry's Mod.\
This was made to undo certain changes that has been applied to LuaJIT.\
With improvements to LuaJIT itself can now be made possible.

Feel free to contribute to fully supporting this on all architectures and platforms.

## Issues
Currently on x86_64 branch it seems sdk minimal doesn't notice on x86 that "libtier0_srv.so" doesn't exist.\
To fix this simply change "serverside" in the premake to false, this doesn't apply to x64.

## Dangers
This restores dangerous API's such as FFI to LuaJIT, you have been warned.
