local handle = io.popen("vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath")
local vsc = handle:read("*a")
handle:close()

if vsc then
    vsc32 = (vsc:sub(0, -2) .. "\\VC\\Auxiliary\\Build\\vcvars32.bat"):gsub('%W\\:','')
    vsc64 = (vsc:sub(0, -2) .. "\\VC\\Auxiliary\\Build\\vcvars64.bat"):gsub('%W\\:','')
else vsc = "" end


function HasIncludedPackage(name)
	local _project = project()
	_project.packages = _project.packages or {}
	return _project.packages[name] == true
end

function IncludePackage(name)
	assert(not HasIncludedPackage(name), "a package with the name '" .. name .. "' already exists!")

	local _project = project()
	local _workspace = _project.workspace

	_project.packages[name] = true

	if _workspace.packages == nil then
		_workspace.packages = {}
	end

	local refcount = (_workspace.packages[name] or 0) + 1
	_workspace.packages[name] = refcount
	return refcount
end

include ( "sdk32/premake5.lua" )

workspace "plugin_ljpatch32"
    configurations { "Debug", "Release" }
    platforms { "x86" }
    location "build"
    characterset "MBCS"
    staticruntime "on"
    pic "On"

    filter "platforms:x86"
        architecture "x86"

    filter "configurations:Debug"
        defines { "DEBUG" }
        symbols "On"

    filter "configurations:Release"
        defines { "NDEBUG" }
        optimize "On"

    project "plugin_ljpatch32"
        kind "SharedLib"
        language "C++"
        cppdialect "C++20"

        project().serverside = true

        targetdir ("bin/%{cfg.platform}/%{cfg.buildcfg}")
        objdir ("bin-int/%{cfg.platform}/%{cfg.buildcfg}")

        files { "entry_point.cpp", "luajit/src/**.h", "glua/**.h", "sdk32/**.hpp", "sdk32/**.h", "sdk32/**.lib" }

        IncludeSDKCommon()
        IncludeSDKTier0()
        IncludeSDKTier1()

        removefiles {
            "sdk32/public/tier0/memoverride.cpp",
            "sdk32/tier1/processor_detect.cpp",
            "sdk32/tier1/processor_detect_linux.cpp",
            "sdk32/public/tier0/valve_off.cpp",
            "sdk32/public/tier0/valve_on.cpp"
        }

        filter { "system:linux", "platforms:x86" }
            links { "luajit/src/luajit" }
            prebuildcommands {
                "cd ../luajit/src && make clean && make CC=\"gcc -m32 -fPIC\" BUILDMODE=static LUAJIT_ENABLE_LUA52=0 BUILD_SHARED_LIBS=OFF"
            }

        filter { "system:windows", "platforms:x86" }
            links { "luajit/src/lua51" }
            prebuildcommands {
                [[cmd /C "call "]] .. vsc32 .. [[" && cd ..\luajit\src && msvcbuild.bat static x86 )"]]
            }

        filter "system:windows"
            systemversion "latest"
            defines { "COMPILER_MSVC", "WIN32", "_WINDOWS" }

            filter { "system:windows", "platforms:x86" }
                defines { "COMPILER_MSVC32" }
                targetname ("plugin_ljpatch_win32")

        filter "system:linux"
            defines { "COMPILER_GCC" }

            filter { "system:linux", "platforms:x86" }
                pic "On"
                includedirs { (os.getenv("HOME") or "") .. "/vcpkg/installed/x86-linux/include" }
                libdirs { (os.getenv("HOME") or "") .. "/vcpkg/installed/x86-linux/lib" }
                targetname ("plugin_ljpatch_linux")
                targetprefix ""

include ( "sdk64/premake5.lua" )

workspace "plugin_ljpatch64"
    configurations { "Debug", "Release" }
    platforms { "x64" }
    location "build"
    characterset "MBCS"
    staticruntime "on"
    pic "On"

    filter "platforms:x64"
        architecture "x86_64"

    filter "configurations:Debug"
        defines { "DEBUG" }
        symbols "On"

    filter "configurations:Release"
        defines { "NDEBUG" }
        optimize "On"
        
    project "plugin_ljpatch64"
        kind "SharedLib"
        language "C++"
        cppdialect "C++20"

        project().serverside = true

        targetdir ("bin/%{cfg.platform}/%{cfg.buildcfg}")
        objdir ("bin-int/%{cfg.platform}/%{cfg.buildcfg}")

        files { "entry_point.cpp", "luajit/src/**.h", "glua/**.h", "sdk64/**.hpp", "sdk64/**.h", "sdk64/**.lib" }

        IncludeSDKCommon()
        IncludeSDKTier0()
        IncludeSDKTier1()

        removefiles {
            "sdk64/public/tier0/memoverride.cpp",
            "sdk64/tier1/processor_detect.cpp",
            "sdk64/tier1/processor_detect_linux.cpp",
            "sdk64/public/tier0/valve_off.cpp",
            "sdk64/public/tier0/valve_on.cpp"
        }

        filter { "system:linux", "platforms:x64" }
            links { "luajit/src/luajit" }
            prebuildcommands {
                "cd ../luajit/src && make clean && make CC=\"gcc -m64 -fPIC\" XCFLAGS=\"-DLUAJIT_ENABLE_GC64\" BUILDMODE=static LUAJIT_ENABLE_LUA52=0 BUILD_SHARED_LIBS=OFF"
            }

        filter { "system:windows", "platforms:x64" }
            links { "luajit/src/lua51" }
            prebuildcommands {
                [[cmd /C "call "]] .. vsc64 .. [[" && cd ..\luajit\src && msvcbuild.bat static x64 )"]]
            }

        filter "system:windows"
            systemversion "latest"
            defines { "COMPILER_MSVC", "WIN32", "_WINDOWS" }

            filter { "system:windows", "platforms:x64" }
                defines { "COMPILER_MSVC64" }
                targetname ("plugin_ljpatch_win64")

        filter "system:linux"
            defines { "COMPILER_GCC" }

            filter { "system:linux", "platforms:x64" }
                pic "On"
                includedirs { (os.getenv("HOME") or "") .. "/vcpkg/installed/x64-linux/include" }
                libdirs { (os.getenv("HOME") or "") .. "/vcpkg/installed/x64-linux/lib" }
                targetname ("plugin_ljpatch_linux64")
                targetprefix ""

require('vstudio')

premake.override(premake.vstudio.vc2010.elements, "project", function(base, prj)
	local calls = base(prj)
	table.insertafter(calls, premake.vstudio.vc2010.project, function(prj)
        premake.w([[<PropertyGroup Label="Vcpkg" Condition="'$(Configuration)|$(Platform)'=='Debug|Win32'">
    <VcpkgUseStatic>true</VcpkgUseStatic>
  </PropertyGroup>
  <PropertyGroup Label="Vcpkg" Condition="'$(Configuration)|$(Platform)'=='Release|Win32'">
    <VcpkgUseStatic>true</VcpkgUseStatic>
  </PropertyGroup>
  <PropertyGroup Label="Vcpkg" Condition="'$(Configuration)|$(Platform)'=='Debug|x64'">
    <VcpkgUseStatic>true</VcpkgUseStatic>
  </PropertyGroup>
  <PropertyGroup Label="Vcpkg" Condition="'$(Configuration)|$(Platform)'=='Release|x64'">
    <VcpkgUseStatic>true</VcpkgUseStatic>
  </PropertyGroup>]])
    end)
	return calls
end)