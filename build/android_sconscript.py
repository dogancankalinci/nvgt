# NDK detection and toolchain/environment setup for building nvgt targeting Android. Included from SConstruct when NVGT_TARGET is android.

import os, platform

Import("env")

if "ANDROID_NDK_HOME" not in os.environ:
	print("ANDROID_NDK_HOME not set, cannot build for android")
	Exit(1)
env["NDK_HOME"] = os.environ["ANDROID_NDK_HOME"]
host_os = platform.system().lower()
if host_os == "windows":
	env["NDK_HOST_TAG"] = "windows-x86_64"
	cmd_ext = ".cmd"
	exe_ext = ".exe"
	env["GRADLE_CMD"] = ["cmd.exe", "/c", "gradlew.bat"]
elif host_os == "darwin":
	env["NDK_HOST_TAG"] = "darwin-x86_64"
	cmd_ext = ""
	exe_ext = ""
	env["GRADLE_CMD"] = ["./gradlew"]
else:
	env["NDK_HOST_TAG"] = "linux-x86_64"
	cmd_ext = ""
	exe_ext = ""
	env["GRADLE_CMD"] = ["./gradlew"]
# NVGT ships multiple Android ABIs; `scons target=android` builds all of them (each is compiled separately in
# SConstruct's android build loop). Map: ABI -> (compiler triple, sysroot/libc++ dir name).
# Note the armv7 compiler triple (armv7a-linux-androideabi) differs from its libc++ dir name (arm-linux-androideabi).
env["ANDROID_ABIS"] = {"arm64-v8a": ("aarch64-linux-android21", "aarch64-linux-android"), "armeabi-v7a": ("armv7a-linux-androideabi21", "arm-linux-androideabi")}
env["NDK_TOOLCHAIN_BIN"] = os.path.join(env["NDK_HOME"], "toolchains", "llvm", "prebuilt", env["NDK_HOST_TAG"], "bin")
env["NDK_CMD_EXT"] = cmd_ext
env["NDK_EXE_EXT"] = exe_ext
toolchain_bin = env["NDK_TOOLCHAIN_BIN"]
# Default toolchain (arm64) so any env.Object() defined before the per-ABI loop has a valid compiler; the loop overrides CC/CXX/LINK per ABI.
env["CC"] = os.path.join(toolchain_bin, f"aarch64-linux-android21-clang{cmd_ext}")
env["CXX"] = os.path.join(toolchain_bin, f"aarch64-linux-android21-clang++{cmd_ext}")
env["LINK"] = os.path.join(toolchain_bin, f"aarch64-linux-android21-clang++{cmd_ext}")
env["AR"] = os.path.join(toolchain_bin, f"llvm-ar{exe_ext}")
env["RANLIB"] = os.path.join(toolchain_bin, f"llvm-ranlib{exe_ext}")
env["SHLINKCOM"] = "$LINK -o $TARGET $LINKFLAGS -shared $__RPATH $SOURCES $_LIBDIRFLAGS $_LIBFLAGS"
env.Append(CCFLAGS = ["-fPIC"])
# -faligned-allocation: clang marks C++17 aligned operator new unavailable below android-28, but the
# operators live in libc++_shared.so which ships inside the APK, so they exist on every device.
env.Append(CXXFLAGS = ["-DAS_USE_STLNAMES=1", "-ffunction-sections", "-O2", "-faligned-allocation", "-Wno-deprecated-array-compare", "-Wno-implicit-const-int-float-conversion", "-Wno-deprecated-enum-enum-conversion", "-Wno-absolute-value"])
# -Wl,-z,max-page-size=16384 -> 16KB-aligned ELF LOAD segments, required by Google Play's 16 KB page size rule (Android 15+, Nov 2025).
# -Wl,--no-rosegment -> keep .text in the first LOAD segment at vaddr==offset. lld's default separate
# read-only segment shifts the exec segment's vaddr 16KB past its file offset, and the stack unwinder on
# devices below API 30 omits that load bias, so every Play Console crash report from Android <=10 comes back
# with all libgame.so frames shifted (observed: constant 0x4000, symbolicated as nonsense). The NDK's own
# CMake/ndk-build wrappers add this flag whenever minSdk < 30 (ndk#1196, ndk#1589); we drive clang directly,
# so we must add it ourselves. vcpkg-built libs (SDL3) already get it via the NDK CMake toolchain.
env.Append(LINKFLAGS = ["-Wl,--no-fatal-warnings", "-Wl,--no-undefined", "-Wl,--gc-sections", "-Wl,--no-rosegment", "-Wl,-z,max-page-size=16384", "-Wl,-z,common-page-size=16384"])
env["PROGSUFFIX"] = ".so"
env["SHLIBSUFFIX"] = ".so"
