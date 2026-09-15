set(VCPKG_TARGET_ARCHITECTURE arm64)
set(VCPKG_CRT_LINKAGE dynamic)
# libgit2 stays a shared library here as on every other platform: it ships beside the plugin that uses it (in the app's
# Frameworks directory) instead of being compiled into a stub or a plugin dylib.
if(PORT MATCHES "libgit2")
	set(VCPKG_LIBRARY_LINKAGE dynamic)
else()
	set(VCPKG_LIBRARY_LINKAGE static)
endif()
set(VCPKG_CMAKE_SYSTEM_NAME iOS)
set(VCPKG_OSX_SYSROOT iphonesimulator)
if(NOT PORT MATCHES "libffi")
	set(VCPKG_CMAKE_CONFIGURE_OPTIONS_RELEASE -DCMAKE_BUILD_TYPE=MinSizeRel)
endif()
