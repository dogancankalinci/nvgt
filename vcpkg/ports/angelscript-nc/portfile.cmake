vcpkg_from_github(
    OUT_SOURCE_PATH SOURCE_PATH
    REPO anjo76/angelscript
    REF 3fc00a6abc07c7ad2dec4ed14ff6018a194a54d6
    SHA512 9a70378733240d4236cd2b1e8a0c297650e117862ea792546728c34c9204ac5a68deb26ffb3dc545fc94bec66bdd103c14168cea374594890e44114738ba03c6
    HEAD_REF master
    PATCHES
        add-no-compiler.patch
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
        fix-value-template-constructor-stubs.patch
        fix-callptr-import-bound-to-system.patch
        fix-copy-behaviour-argument-leak.patch
        fix-nested-call-pending-requests.patch
        fix-generic-variadic-arg-access.patch
        fix-prepare-stack-overflow-cleanup.patch
        fix-failed-prepare-object-release.patch
        fix-nested-marker-stack-walk.patch
        fix-exception-before-suspend.patch
        fix-call-stack-overflow-args.patch
        fix-copy-behaviour-handle-return.patch
        fix-template-constructor-failure.patch
        fix-factory-autohandle-return.patch
        fix-stack-overflow-frame-position.patch
        fix-abort-after-exception-cleanup.patch
        fix-unstarted-function-args.patch
        fix-getargonstack-bounds.patch
        fix-nested-exception-catch.patch
        fix-abort-after-last-suspend.patch
        fix-pushstate-capacity-check.patch
        fix-return-object-reference.patch
        fix-callptr-suspend.patch
        fix-release-after-store.patch
        fix-format-va-copy.patch
        fix-try-catch-slot-reuse.patch
        fix-bytecode-copy-constructor.patch
        fix-exception-position.patch
        fix-exception-frame-stale.patch
        fix-cleanup-block-tail.patch
        fix-exception-line.patch
        fix-nested-marker-frame.patch
        fix-bytecode-inherited-opassign.patch
        fix-return-location-clean-up.patch
        fix-jitentry-stop-position.patch
        fix-call-stack-growth.patch
        fix-unstarted-function-position.patch
        fix-raised-handle-return.patch
        fix-derived-copy-constructor.patch
        fix-member-copy-temporary.patch
        fix-handle-copy-constructor.patch
        fix-foreach-item-clean-up.patch
        fix-init-before-argument-release.patch
        fix-reference-return-in-try.patch
)

vcpkg_cmake_configure(
    SOURCE_PATH "${SOURCE_PATH}/sdk/angelscript/projects/cmake"
    OPTIONS
        "-DAS_NO_COMPILER=ON" "-DCMAKE_CXX_STANDARD=11"
)

vcpkg_cmake_install()
vcpkg_copy_pdbs()

file(REMOVE_RECURSE "${CURRENT_PACKAGES_DIR}/debug/include")
vcpkg_cmake_config_fixup(CONFIG_PATH lib/cmake/Angelscript)

# Copy the addon files
if("addons" IN_LIST FEATURES)
    file(INSTALL "${SOURCE_PATH}/sdk/add_on/" DESTINATION "${CURRENT_PACKAGES_DIR}/include/angelscript" FILES_MATCHING PATTERN "*.h" PATTERN "*.cpp")
endif()
file(REMOVE "${CURRENT_PACKAGES_DIR}/include/angelscript.h")
