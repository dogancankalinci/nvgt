set(VCPKG_TARGET_ARCHITECTURE arm64)
set(VCPKG_CRT_LINKAGE dynamic)
if(PORT STREQUAL "sdl3" OR PORT MATCHES "libarchive" OR PORT MATCHES "libgit2")
	set(VCPKG_LIBRARY_LINKAGE dynamic)
else()
	set(VCPKG_LIBRARY_LINKAGE static)
endif()
set(VCPKG_CMAKE_SYSTEM_NAME Android)
set(VCPKG_CMAKE_SYSTEM_VERSION 21)
set(VCPKG_MAKE_BUILD_TRIPLET "--host=aarch64-linux-android")
# Both of these give 16 KB ELF segment alignment, required by Google Play for apps targeting Android 15+: the NDK toolchain
# option for CMake's own link lines, and the linker flag for the ports that don't build through the toolchain file.
set(VCPKG_CMAKE_CONFIGURE_OPTIONS -DANDROID_ABI=arm64-v8a -DANDROID_STL=c++_shared -DCMAKE_POLICY_VERSION_MINIMUM=3.15 -DANDROID_SUPPORT_FLEXIBLE_PAGE_SIZES=ON)
set(VCPKG_LINKER_FLAGS "-Wl,-z,max-page-size=16384 -Wl,-z,common-page-size=16384")
