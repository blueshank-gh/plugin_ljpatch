<div align="center">
  <picture>
  <img width="590" height="159" src="./logo.png">
  </picture>


</div>

## Issues
Currently on x86_64 branch it seems sdk minimal doesn't notice on x86 that "libtier0_srv.so" doesn't exist.\
To fix this simply change "serverside" in the premake to false, this doesn't apply to x64.

## Dangers
This restores dangerous API's such as FFI to LuaJIT, you have been warned.
