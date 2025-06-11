# LJ Patch
A rollback to LuaJIT in Garry's Mod.\
This was made to undo certain changes that has been applied to LuaJIT.\
With improvements to LuaJIT itself can now be made possible.

Currently only x64 builds appear to work due to some oddities in x86 lua_shared.\
Feel free to contribute to fully supporting this on all architectures and platforms.

## Dangers
This restores dangerous API's such as FFI to LuaJIT, you have been warned.

## Checklist
- [x] Windows - x64 Support
- [ ] Windows - x86 Support
  - Failures from lua_shared.dll
- [ ] Linux - x64 Support
  - Failures from CBaseLuaInterface::GetType
  - On case 7u (userdata), *a1 + 216LL (CBaseLuaInterface::GetUserData) is null (this really shouldn't happen...)
- [ ] Linux - x86 Support
  - Failures from lua_shared.dll
