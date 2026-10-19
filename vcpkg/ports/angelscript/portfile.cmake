vcpkg_from_github(
    OUT_SOURCE_PATH SOURCE_PATH
    REPO anjo76/angelscript
    REF 3fc00a6abc07c7ad2dec4ed14ff6018a194a54d6
    SHA512 9a70378733240d4236cd2b1e8a0c297650e117862ea792546728c34c9204ac5a68deb26ffb3dc545fc94bec66bdd103c14168cea374594890e44114738ba03c6
    HEAD_REF master
    PATCHES
        mark-threads-private.patch
        fix-dependency.patch
        fix-double-literal-precision.patch
        fix-x64-gcc-callfunc-unwind.patch
        fix-arm64-xcode-stack-copy.patch
        fix-arm64-gcc-callfunc-unwind.patch
        fix-android-arm32-callfunc.patch
        fix-callfunc-subword-args.patch
        fix-callfunc-functor-arg-cleanup.patch
        fix-x64-gcc-composite-args.patch
        fix-arm64-composite-args.patch
        fix-x64-msvc-odd-size-objects.patch
        fix-callfunc-by-value-checks.patch
        fix-thiscall1-functor-methods.patch
        fix-functor-behaviour-calls.patch
        fix-app-float-args.patch
        fix-system-call-arg-ownership.patch
        fix-delegate-return-value.patch
        fix-refcast-script-methods.patch
        fix-global-behaviour-callconvs.patch
        fix-copy-behaviour-calls.patch
        fix-variadic-behaviours.patch
        fix-functor-object-offset.patch
        fix-funcdef-autohandle-return.patch
        fix-thiscall1-variadic-methods.patch
        fix-refused-callback-convs.patch
)

vcpkg_cmake_configure(
    SOURCE_PATH "${SOURCE_PATH}/sdk/angelscript/projects/cmake"
    OPTIONS
        "-DCMAKE_CXX_STANDARD=11"
)

vcpkg_cmake_install()
vcpkg_copy_pdbs()

file(REMOVE_RECURSE "${CURRENT_PACKAGES_DIR}/debug/include")
vcpkg_cmake_config_fixup(CONFIG_PATH lib/cmake/Angelscript)

# Copy the addon files
if("addons" IN_LIST FEATURES)
    file(INSTALL "${SOURCE_PATH}/sdk/add_on/" DESTINATION "${CURRENT_PACKAGES_DIR}/include/angelscript" FILES_MATCHING PATTERN "*.h" PATTERN "*.cpp")
endif()
