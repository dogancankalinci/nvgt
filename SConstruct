# Build script for NVGT using the scons build system.
# NVGT - NonVisual Gaming Toolkit (https://nvgt.dev)
# Copyright (c) 2022-2026 Sam Tupy
# license: zlib

import os, multiprocessing, tempfile

Help("""
	Available custom build switches for NVGT:
		copylibs=0 or 1 (default 1): Copy shared libraries to release/lib after building?
		debug=0 or 1 (default 0): Include debug symbols in the resulting binaries?
		deps=build, download, or unmanaged (default download): How to fetch dependencies required to build NVGT? build = use vcpkg to build from source, download = download prebuilt binaries from nvgt.dev if newer than existing, unmanaged = assume dependencies are in place.
		deps_path=path: Optional location where dependencies are stored? Defaults to a folder named after the platform in the repository root.
		no_upx=0 or 1 (default 1): Disable UPX stubs?
		no_plugins=0 or 1 (default 0): Disable the plugin system entirely?
		no_shared_plugins=0 or 1 (default 0): Only compile plugins statically?
		no_stubs=0 or 1 (default 0): Disable compilation of all stubs?
		no_user=0 or 1 (default 0): Pretend that the user directory doesn't exist?
		no_<plugname>_plugin=1: Disable a plugin by name.
		static_<plugname>_plugin=1: Cause the given plugin to be linked statically if possible.
		stub_obfuscation=0 or 1 (default 0): Obfuscate some Angelscript function registration strings in the resulting stubs? Could make them bigger.
		warnings (0 or 1, default 0): enable compiler warnings?
		warnings_as_errors (0 or 1, default 0): treat compiler warnings as errors?
	You can also run scons install (for now only on windows) to install the build into C:/nvgt. STILL WIP!
	Note that custom switches or targets may be added by any plugin SConscript and may not be documented here.
""")

# setup
if ARGUMENTS.get("target", "") == "android":
	env = Environment(tools=['mingw'])
else:
	env = Environment()
# Prevent scons from wiping out the environment for certain tools, e.g. scan-build
env["CC"] = os.getenv("CC") or env["CC"]
env["CXX"] = os.getenv("CXX") or env["CXX"]
env["ENV"].update(x for x in os.environ.items() if x[0].startswith("CCC_"))
Decider('content-timestamp')
env.Alias("install", "c:/nvgt")
SConscript("build/upx_sconscript.py", exports = ["env"])
SConscript("build/version_sconscript.py", exports = ["env"])
env.SetOption("num_jobs", multiprocessing.cpu_count())
SConscript("build/osdev_sconscript.py", exports = ["env"])
SConscript("vcpkg/_SConscript", exports = ["env"])
if ARGUMENTS.get("debug", "0") == "1":
	env.Tool('compilation_db')
	cdb = env.CompilationDatabase()
	Alias('cdb', cdb)

# Platform setup and system libraries
common_libs = ["PocoJSON", "PocoNet", "PocoNetSSL", "PocoUtil", "PocoXML", "PocoCrypto", "PocoFoundation", "expat", "angelscript", "SDL3_ttf", "freetype", "bz2", "enet", "reactphysics3d", "ssl", "crypto", "utf8proc", "pcre2-8", "vorbisfile", "vorbisenc", "vorbis", "ogg", "opusfile", "opusenc", "opus", "tinyexpr", "tiny-aes-c", "ffi"]
if env["NVGT_TARGET"] == "windows":
	deb_rel_flags = ["/MTd", "/Od", "/Z7"] if ARGUMENTS.get("debug", "0") == "1" else ["/MT", "/O2"]
	env.Append(CCFLAGS = ["/EHsc", "/J", "/utf-8", "/Gy", "/std:c++20", "/GF", "/Zc:inline", "/bigobj", "/permissive-", "/W3" if ARGUMENTS.get("warnings", "0") == "1" else "", "/WX" if ARGUMENTS.get("warnings_as_errors", "0") == "1" else ""] + deb_rel_flags)
	env.Append(LINKFLAGS = ["/NOEXP", "/NOIMPLIB"], no_import_lib = 1)
	env.Append(LIBS = ["Kernel32", "User32", "imm32", "OneCoreUAP", "dinput8", "dxguid", "gdi32", "winspool", "shell32", "iphlpapi", "ole32", "oleaut32", "delayimp", "uuid", "comdlg32", "advapi32", "netapi32", "winmm", "version", "crypt32", "bcrypt", "normaliz", "wldap32", "ws2_32", "ntdll", "wbemuuid"])
	env.Append(CPPDEFINES = ["NVGT_NO_IAP"])
else:
	env.Append(CXXFLAGS = ["-fms-extensions", "-std=c++20", "-fpermissive", "-O0" if ARGUMENTS.get("debug", 0) == "1" else "-O3", "-Wno-narrowing", "-Wno-int-to-pointer-cast", "-Wno-delete-incomplete", "-Wno-unused-result", "-g" if ARGUMENTS.get("debug", 0) == "1" else "", "-Wall" if ARGUMENTS.get("warnings", "0") == "1" else "", "-Wextra" if ARGUMENTS.get("warnings", "0") == "1" else "", "-Werror" if ARGUMENTS.get("warnings_as_errors", "0") == "1" else ""], LIBS = ["m"])
if env["NVGT_TARGET"] == "macos":
	# homebrew paths and other libraries/flags for MacOS
	env.Append(CCFLAGS = ["-mmacosx-version-min=12.0", "-arch", "arm64", "-arch", "x86_64"], LINKFLAGS = ["-arch", "arm64", "-arch", "x86_64"])
	env["FRAMEWORKPREFIX"] = "-weak_framework"
elif env["NVGT_TARGET"] == "ios":
	import subprocess
	env["ENV"]["SDKROOT"] = subprocess.check_output(["xcrun", "-sdk", "iphoneos", "--show-sdk-path"]).decode().strip()
	env.Append(CCFLAGS = ["-arch", "arm64", "-xobjective-c++"], LINKFLAGS = ["-arch", "arm64"], LIBS=["mysofa", "pffft"])
	env["FRAMEWORKPREFIX"] = "-weak_framework"
elif env["NVGT_TARGET"] == "linux":
	# enable the gold linker, strip the resulting binaries, and add /usr/local/lib to the libpath because it seems we aren't finding libraries unless we do manually.
	env.Append(CPPPATH = ["lindev/include", "/usr/local/include"], LIBPATH = ["lindev/lib", "/usr/local/lib", "/usr/lib/x86_64-linux-gnu"], LINKFLAGS = ["-fuse-ld=gold", "-g" if ARGUMENTS.get("debug", 0) == "1" else "-s"])
	env.Append(CPPDEFINES = ["NVGT_NO_IAP"])
elif env["NVGT_TARGET"] == "android":
	SConscript("build/android_sconscript.py", exports = ["env"])
	env.Append(LIBS = common_libs + ["z", "GLESv1_CM", "GLESv2", "OpenSLES", "log", "android"])
env.Append(CPPDEFINES = ["POCO_STATIC", "POCO_NO_AUTOMATIC_LIBS", "UNIVERSAL_SPEECH_STATIC", "DEBUG" if ARGUMENTS.get("debug", "0") == "1" else "NDEBUG", "UNICODE"])
env.Append(CPPPATH = ["#ASAddon/include", "#dep"], LIBPATH = ["#build/lib"])
# Output directory for NVGT's own static libs (deps, ASAddon, per-plugin). The android build overrides this per ABI so the
# plugin static libs from each ABI's SConscript pass don't collide on one hardcoded path.
env["NVGT_LIB_DIR"] = "#build/lib"
env["PLUGIN_DEST_DIR"] = "#release/lib_android/arm64-v8a" if env["NVGT_TARGET"] == "android" else "#release/lib"

# plugins
static_plugins = []
static_plugins_object = None
if  ARGUMENTS.get("no_plugins", "0") == "0":
	try:
		# First, read the list of static plugins we wish to link if available.
		with open(os.path.join("user", "static_plugins"), "r") as f:
			lines = f.readlines()
			for l in lines:
				if not l or l.startswith("#"): continue
				static_plugins.append(l.strip())
	except FileNotFoundError: pass
	plugin_env = env.Clone()
	env["CPPDEFINES"] = list(env["CPPDEFINES"])
	plugin_env["CPPDEFINES"] = list(plugin_env["CPPDEFINES"])
	if env["NVGT_TARGET"] == "android":
		plugin_env.Append(CXXFLAGS = ["-fPIC"])
		plugin_env["SHLIBPREFIX"] = ""
	# Then loop through all known plugins and build them.
	# Android skips the top-level (arm64/base-env) plugin build entirely: each plugin must be compiled per ABI against its
	# own droidev/<abi> headers, which the android build loop does separately. Building them here with the base env would
	# fail (there is no flat droidev/include once deps are laid out per-ABI) and produce arm64-only libs anyway.
	plugin_scripts = [] if env["NVGT_TARGET"] == "android" else Glob("plugin/*/_SConscript") + Glob("plugin/*/SConscript") + Glob("extra/plugin/integrated/*/_SConscript") + Glob("extra/plugin/integrated/*/SConscript")
	for s in plugin_scripts:
		plugname = str(s).split(os.path.sep)[-2]
		if ARGUMENTS.get(f"no_{plugname}_plugin", "0") == "1": continue
		if ARGUMENTS.get(f"static_{plugname}_plugin", "0") == "1" and not plugname in static_plugins: static_plugins.append(plugname)
		# Build the plugin.
		# A list of static libraries NVGT should link with is returned if the plugin generates any.
		plug = SConscript(s, variant_dir = f"build/obj_plugin/{plugname}", duplicate = 0, exports = {"env": plugin_env, "nvgt_env": env})
		if plug and plugname in static_plugins: env.Append(LIBS = plug)
	# Finally generate nvgt_plugins.cpp
	static_plugins_path = os.path.join(tempfile.gettempdir(), "nvgt_plugins")
	if len(static_plugins) > 0:
		with open(static_plugins_path + ".cpp", "w") as f:
			f.write("#define NVGT_LOAD_STATIC_PLUGINS\n#include <nvgt_plugin.h>\n")
			for plugin in static_plugins: f.write(f"static_plugin({plugin})" + "\n")
			static_plugins_object = env.Object(static_plugins_path, static_plugins_path + ".cpp", CPPPATH = env["CPPPATH"] + ["#src"])

# Project libraries
# Android does not use NVGT's own prebuilt static libs (deps/ASAddon) or the shared libpath here — its build loop compiles
# those sources directly per ABI and replaces LIBS/LIBPATH with a clean per-ABI set. Everyone else links them as usual.
if env["NVGT_TARGET"] != "android":
	env.Append(LIBS = ["deps"] + common_libs + ["zs" if env["NVGT_TARGET"] == "windows" else "z", "SDL3", "phonon", "ASAddon"])
if env["NVGT_TARGET"] == "windows": env.Append(LIBS = ["UniversalSpeechStatic"])

# nvgt itself
sources = [str(i)[4:] for i in Glob("src/*.cpp")]
if env["NVGT_TARGET"] != "android" and "android.cpp" in sources:
	sources.remove("android.cpp")
if env["NVGT_TARGET"] != "windows" and "win.cpp" in sources: sources.remove("win.cpp")
if env["NVGT_TARGET"] != "linux" and "linux.cpp" in sources: sources.remove("linux.cpp")
if "version.cpp" in sources: sources.remove("version.cpp")
env.Command(target = "src/version.cpp", source = ["src/" + i for i in sources], action = env["generate_version"])
version_object = env.Object("build/obj_src/version", "src/version.cpp") # Things get weird if we do this after VariantDir.
VariantDir("build/obj_src", "src", duplicate = 0)
env.Append(CPPDEFINES = ["NVGT_BUILDING", "NO_OBFUSCATE"])
if env["NVGT_TARGET"] == "windows":
	deb_rel_flags = ["/DEBUG", "/INCREMENTAL:NO"] if ARGUMENTS.get("debug", "0") == "1" else ["/OPT:ICF=3"]
	env.Append(CPPDEFINES = ["_SILENCE_CXX20_OLD_SHARED_PTR_ATOMIC_SUPPORT_DEPRECATION_WARNING"], LINKFLAGS = ["/ignore:4099", "/delayload:phonon.dll"] + deb_rel_flags)
elif env["NVGT_TARGET"] in ("macos", "ios"):
	sources.append("apple.mm")
	# We must link Apple frameworks here rather than above in the system libraries section to insure that they don't get linked with random plugins.
	env.Append(FRAMEWORKS = ["AudioToolbox", "AVFoundation", "CoreAudio", "CoreFoundation", "CoreHaptics", "CoreMedia", "CoreVideo", "GameController", "IOKit", "Metal", "QuartzCore", "Security"])
	if env["NVGT_TARGET"] == "macos":
		env.Append(CPPDEFINES = ["NVGT_NO_IAP"])
		env.Append(FRAMEWORKS = ["AppKit", "Carbon", "Cocoa", "ForceFeedback", "UniformTypeIdentifiers"])
		env.Append(LINKFLAGS = ["-Wl,-rpath,'@loader_path',-rpath,'@loader_path/lib',-rpath,'@loader_path/../Frameworks',-dead_strip_dylibs", "-mmacosx-version-min=14.0"])
	else:
		sources.append("iap_apple.mm")
		env.Append(FRAMEWORKS = ["CoreBluetooth", "CoreGraphics", "CoreMotion", "Foundation", "OpenGLES", "StoreKit", "UIKit"])
		env.Append(CCFLAGS = ["-miphoneos-version-min=16.0"], LINKFLAGS = ["-miphoneos-version-min=16.0"])
	env.Append(LIBS = ["objc"])
elif env["NVGT_TARGET"] == "linux":
	env.Append(LINKFLAGS = ["-Wl,-rpath,'$$ORIGIN/.',-rpath,'$$ORIGIN/lib'"])
if ARGUMENTS.get("no_user", "0") == "0":
	if os.path.isfile("user/nvgt_config.h"):
		env.Append(CPPDEFINES = ["NVGT_USER_CONFIG"])
	for s in ["_SConscript", "SConscript"]:
		if os.path.isfile(f"user/{s}"):
			SConscript(f"user/{s}", exports = {"plugin_env": plugin_env, "nvgt_env": env})
			break # only execute one script from here
# Non-android links ASAddon/dep as prebuilt static libs. Android instead compiles their sources directly into each
# per-ABI native lib (see the android build loop), so skip the base-env (arm64, no per-ABI headers) build here.
if env["NVGT_TARGET"] != "android":
	SConscript("ASAddon/_SConscript", variant_dir = "build/obj_ASAddon", duplicate = 0, exports = "env")
	SConscript("dep/_SConscript", variant_dir = "build/obj_dep", duplicate = 0, exports = "env")
# We'll clone the environment for stubs now so that we can then add any extra libraries that are not needed for stubs to the main nvgt environment.
stub_env = env.Clone(PROGSUFFIX = ".bin")
if env["NVGT_TARGET"] == "windows":
	env.Append(LINKFLAGS = ["/delayload:plist-2.0.dll", "/delayload:archive.dll"])
	env.Append(LIBS = ["plist-2.0", "archive"])
	env["no_import_lib"] = 0
elif env["NVGT_TARGET"] == "android":
	env["no_import_lib"] = 1
else: # linux and macos
	env.Append(LIBS = ["plist-2.0", "archive"])
extra_objects = [version_object]
if static_plugins_object: extra_objects.append(static_plugins_object)
# LZFSE encoder sources, compiled into the main nvgt binary (the iOS Assets.car generator in bundling.cpp uses it).
# Android compiles these per-ABI inside its own build loop below, so exclude them from the shared extra_objects here.
lzfse_srcs = ["lzfse_encode", "lzfse_encode_base", "lzfse_fse", "lzvn_encode_base"]
if env["NVGT_TARGET"] not in ("ios", "android"):
	extra_objects += [env.Object("build/obj_lzfse/" + s, "dep/lzfse/" + s + ".c") for s in lzfse_srcs]
if env["NVGT_TARGET"] == "windows":
	# MASM (ml64) stub for the anti-cheat's VMware backdoor probe: MSVC has no x64 inline
	# assembly, so src/anticheat.cpp calls this hand-written object instead. Added to
	# extra_objects so it links into nvgt, nvgtw and every stub. The masm tool defaults
	# to the 32-bit "ml"; force the 64-bit assembler, which lives beside cl.exe.
	env.Tool("masm")
	env["AS"] = "ml64"
	extra_objects.append(env.Object("build/obj_src/vmware_backdoor", "src/vmware_backdoor.asm"))
if env["NVGT_TARGET"] not in ("ios", "android"):
	if ARGUMENTS.get("debug", "0") == "1": env["PDB"] = "#build/debug/nvgt.pdb"
	nvgt = env.Program("release/nvgt", env.Object([os.path.join("build/obj_src", s) for s in sources]) + extra_objects)
	if env["NVGT_TARGET"] == "macos":
		# On Mac OS, we need to run install_name_tool to modify the paths of any dynamic libraries we link.
		for lib in ["plist-2.0", "archive"]: env.AddPostAction(nvgt, lambda target, source, env: env.Execute(f"install_name_tool -change lib/lib{lib}.dylib @rpath/lib{lib}.dylib " + str(target[0])))
	if env["NVGT_TARGET"] == "windows":
		# Only on windows we must go through the frustrating hastle of compiling a version of nvgt with no console E. the windows subsystem.
		# It is at least set up so that we only need to recompile one object
		if "nvgt.cpp" in sources: sources.remove("nvgt.cpp")
		if ARGUMENTS.get("debug", "0") == "1": env["PDB"] = "#build/debug/nvgtw.pdb"
		nvgtw = env.Program("release/nvgtw", env.Object([os.path.join("build/obj_src", s) for s in sources]) + [env.Object("build/obj_src/nvgtw", "build/obj_src/nvgt.cpp", CPPDEFINES = ["$CPPDEFINES", "NVGT_WIN_APP"]), extra_objects], LINKFLAGS = ["$LINKFLAGS", "/subsystem:windows"])
		sources.append("nvgt.cpp")
		# Todo: Properly implement the install target on other platforms
		env.Install("c:/nvgt", nvgt)
		env.Install("c:/nvgt", nvgtw)
		env.Install("c:/nvgt", "#release/include")
		env.Install("c:/nvgt", "#release/lib")
elif env["NVGT_TARGET"] == "android":
	# Build the runner + both stubs (regular and IAP) for EVERY Android ABI in a single `scons target=android`.
	# Each ABI is compiled independently (its own toolchain, deps and object dirs). IAP is toggled purely by the
	# NVGT_NO_IAP define, matching the old ndk-build: runner + regular stub disable IAP; the IAP stub enables it
	# (Google Play Billing via src/iap/java on the gradle side).
	android_deps = []
	osdev_base = str(Dir("#" + env["NVGT_OSDEV_NAME"]))  # droidev; holds one self-contained subdir per ABI (arm64-v8a, armeabi-v7a)
	tb = env["NDK_TOOLCHAIN_BIN"]; ce = env["NDK_CMD_EXT"]
	# Dynamic plugins are compiled once per ABI into release/lib_android/<abi>. The plugin SConscripts (some in the read-only
	# `extra` submodule) hardcode a single #build/lib/<x> static-lib target and, for a few, implicit-target objects from
	# absolute #-rooted sources; both would clash when a plugin is built for more than one ABI in one scons run. Rather than
	# editing any plugin file, we hand each per-ABI plugin build an env whose StaticLibrary/Object/SharedObject builders are
	# transparently redirected to per-ABI output paths (the static libs themselves are unused on Android — only the shared
	# libs ship — but they must still not collide). Shared libs already honour the per-ABI PLUGIN_DEST_DIR we set below.
	def android_plugin_env(base_env, abi):
		pe = base_env.Clone()
		# Normalise CPPDEFINES to a plain list (SCons keeps it as a deque after Append): some plugin SConscripts do
		# `env["CPPDEFINES"] + [...]`, which throws "can only concatenate deque (not list)". Also drop the defines that only
		# apply to building NVGT itself — crucially NVGT_BUILDING: nvgt_plugin.h wraps the entire plugin-side API
		# (plugin_main / prepare_plugin) in `#ifndef NVGT_BUILDING`, so a plugin compiled with it set fails to declare its
		# own entry point. The desktop plugin_env avoids this by being cloned before these defines are appended.
		_nvgt_only_defines = {"NVGT_BUILDING", "NO_OBFUSCATE", "NVGT_USER_CONFIG"}
		pe["CPPDEFINES"] = [d for d in list(pe["CPPDEFINES"]) if (d[0] if isinstance(d, (tuple, list)) else d) not in _nvgt_only_defines]
		pe["PLUGIN_DEST_DIR"] = "#release/lib_android/" + abi
		pe.Append(CXXFLAGS = ["-fPIC"])
		libdir = "#build/lib_android/" + abi
		orig_static = pe["BUILDERS"]["StaticLibrary"]
		def static_redir(environment, target, source, *a, **kw):
			if isinstance(target, str): target = target.replace("#build/lib/", libdir + "/")
			return orig_static(environment, target, source, *a, **kw)
		pe.AddMethod(static_redir, "StaticLibrary")
		for bname in ("SharedObject", "Object"):
			orig_obj = pe["BUILDERS"][bname]
			def make(orig):
				def obj_redir(environment, target, source = None, *a, **kw):
					if source is None: source, target = target, None
					if target is not None: return orig(environment, target, source, *a, **kw)
					# implicit target: give each source a relative basename target so absolute #-rooted sources land in this
					# plugin's per-ABI variant dir instead of one shared path next to the source (which collides across ABIs).
					srcs = source if isinstance(source, list) else [source]
					out = []
					for s in srcs: out += orig(environment, os.path.splitext(os.path.basename(str(s)))[0], s, *a, **kw)
					return out
				return obj_redir
			pe.AddMethod(make(orig_obj), bname)
		# SharedLibrary compiles any raw source passed to it directly; an absolute #-rooted source (e.g. unicode's
		# "#extra/plugin/dep/uni_algo/data.cpp") would be built to an object next to the source, outside the per-ABI variant
		# dir, and collide across ABIs. Pre-compile such sources into per-ABI shared objects (via the redirected SharedObject).
		orig_shlib = pe["BUILDERS"]["SharedLibrary"]
		def shlib_redir(environment, target, source, *a, **kw):
			srcs = source if isinstance(source, list) else [source]
			new_srcs = []
			for s in srcs:
				ss = str(s)
				if isinstance(s, str) and ss.startswith("#") and ss.rsplit(".", 1)[-1].lower() in ("c", "cpp", "cc", "cxx", "mm"):
					new_srcs += environment.SharedObject(os.path.splitext(os.path.basename(ss))[0], s)
				else: new_srcs.append(s)
			return orig_shlib(environment, target, new_srcs, *a, **kw)
		pe.AddMethod(shlib_redir, "SharedLibrary")
		return pe
	android_plugin_scripts = Glob("plugin/*/_SConscript") + Glob("plugin/*/SConscript") + Glob("extra/plugin/integrated/*/_SConscript") + Glob("extra/plugin/integrated/*/SConscript")
	# BASS is a dynamic dependency of the legacy_sound plugin: its shared libs must ship in lib_android/<abi> so the bundler
	# can drop them next to legacy_sound.so (which links -lbass). The stub itself never links BASS.
	android_plugin_shared_deps = {"legacy_sound": ["libbass.so", "libbass_fx.so", "libbassmix.so"]}
	# NVGT's own code compiled directly into every native lib (the old ndk-build LOCAL_SRC_FILES_COMMON): AngelScript addons,
	# a selected set of dep/ C/C++ sources, and all of src/. It is NOT linked as prebuilt static libs (those are arm64-only);
	# only the per-ABI droidev deps + SDL3/phonon + Android system libs are linked below.
	asaddon_srcs = [str(f).replace(os.path.sep, "/") for f in Glob("ASAddon/src/*.cpp")]
	dep_srcs = ["dep/" + s for s in ["cmp.c", "entities.cpp", "ma_reverb_node.c", "micropather.cpp", "miniaudio_libopus.c", "miniaudio_libvorbis.c", "miniaudio_phonon.c", "miniaudio_wdl_resampler.cpp", "monocypher.c", "resample.cpp", "rng_get_bytes.c", "singleheader.cpp", "sonic.c", "tonar.c", "uncompr.c"]]
	# Clean per-ABI link set: droidev static deps + SDL3/phonon shared + Android system libs. No NVGT static libs, no plugins.
	android_link_libs = common_libs + ["z", "SDL3", "phonon", "GLESv1_CM", "GLESv2", "OpenSLES", "log", "android", "m"]
	for abi, (clang_triple, libcxx_dir) in env["ANDROID_ABIS"].items():
		abi_dev = os.path.join(osdev_base, abi)
		abi_env = env.Clone()
		abi_env["CC"] = os.path.join(tb, f"{clang_triple}-clang{ce}")
		abi_env["CXX"] = os.path.join(tb, f"{clang_triple}-clang++{ce}")
		abi_env["LINK"] = os.path.join(tb, f"{clang_triple}-clang++{ce}")
		abi_env["SHLIBPREFIX"] = ""  # lib names below already carry the "lib" prefix -> emit libmain.so / libgame.so verbatim
		# Each ABI builds strictly against ITS OWN droidev/<abi> tree — nothing flat, never another ABI's headers/libs.
		# These MUST be top-relative ("#..."): the per-plugin SConscript calls below run under a variant_dir, and SCons
		# rewrites any *relative* CPPPATH/LIBPATH entry against that variant dir (yielding bogus paths like
		# build/obj_plugin_android/<abi>/<plug>/droidev/<abi>/include). A "#" anchor keeps them at the project root.
		abi_env.Replace(CPPPATH = ["#" + abi_dev + "/include", "#ASAddon/include", "#dep"])
		abi_env.Replace(LIBPATH = ["#" + abi_dev + "/lib"])
		abi_env.Replace(LIBS = android_link_libs)
		libcxx_path = os.path.join(env["NDK_HOME"], "toolchains", "llvm", "prebuilt", env["NDK_HOST_TAG"], "sysroot", "usr", "lib", libcxx_dir, "libc++_shared.so")
		# Dynamic plugins for this ABI -> release/lib_android/<abi>/*.so (shipped alongside nvgt; the bundler drops the ones a
		# script actually uses into the APK's lib/<abi>/). Built through the sandbox env so per-ABI runs never collide.
		lib_android_dest = f"#release/lib_android/{abi}"
		for s in android_plugin_scripts:
			plugname = str(s).split(os.path.sep)[-2]
			if ARGUMENTS.get(f"no_{plugname}_plugin", "0") == "1": continue
			SConscript(s, variant_dir = f"build/obj_plugin_android/{abi}/{plugname}", duplicate = 0, exports = {"env": android_plugin_env(abi_env, abi), "nvgt_env": abi_env})
			# Ship each plugin's dynamic dependencies (e.g. BASS for legacy_sound) next to it so the bundler can include them.
			for dep_so in android_plugin_shared_deps.get(plugname, []):
				android_deps.extend(env.Install(lib_android_dest, os.path.join(abi_dev, "lib", dep_so)))
		# version + lzfse (bundling.cpp's Assets.car encoder) are arch-specific but variant-independent: build once per ABI.
		shared_objs = [abi_env.Object(f"build/obj_android/{abi}/version", "src/version.cpp")]
		shared_objs += [abi_env.Object(f"build/obj_android/{abi}/lzfse/{s}", "dep/lzfse/" + s + ".c") for s in lzfse_srcs]
		# The three variants differ only by their defines: runner + regular stub disable IAP, the IAP stub enables it.
		for variant, extra_defines in [("runner", ["NVGT_NO_IAP"]), ("stub", ["NVGT_STUB", "NVGT_NO_IAP"]), ("stub_iap", ["NVGT_STUB"])]:
			venv = abi_env.Clone()
			venv.Append(CPPDEFINES = extra_defines)
			obj_root = f"build/obj_android/{abi}/{variant}"
			objs = [venv.Object(f"{obj_root}/src/{os.path.splitext(s)[0]}", "src/" + s) for s in sources]
			objs += [venv.Object(f"{obj_root}/asaddon/{os.path.splitext(os.path.basename(s))[0]}", s) for s in asaddon_srcs]
			objs += [venv.Object(f"{obj_root}/dep/{os.path.splitext(os.path.basename(s))[0]}", s) for s in dep_srcs]
			objs += shared_objs
			dest = f"jni/libs/{variant}/{abi}"
			libname = "libmain" if variant == "runner" else "libgame"
			lib = venv.SharedLibrary(os.path.join(dest, libname), objs)
			android_deps.append(lib)
			android_deps.extend(env.Install(dest, libcxx_path))
			android_deps.extend(env.Install(dest, os.path.join(abi_dev, "lib/libSDL3.so")))
			android_deps.extend(env.Install(dest, os.path.join(abi_dev, "lib/libphonon.so")))
	# `scons android_apk` groups the native libs; gradle packaging (assemble*Release) stays a separate manual/CI step (see d260d85).
	def run_gradle(target, source, env):
		import subprocess
		original_dir = os.getcwd()
		os.chdir("jni")
		try:
			subprocess.check_call(env["GRADLE_CMD"] + ["assembleStubRelease", "assembleStubIapRelease", "assembleRunnerRelease"])
		finally:
			os.chdir(original_dir)
	apk_alias = env.Alias("android_apk", android_deps)
	#env.AddPostAction(apk_alias, Action(run_gradle, "Packaging Android Stub and Runner..."))
	#env.Default(apk_alias)

# stubs
def fix_stub(target, source, env):
	"""On windows, we replace the first 2 bytes of a stub with 'NV' to stop some sort of antivirus scan upon script compile that makes it take a bit longer. We do the same on MacOS because otherwise 
	apple's notarization service detects the stub as an unsigned binary and fails.
	Stubs must be unsigned until the nvgt scripter signs their compiled games."""
	for t in target:
		if not str(t).endswith(".bin"): continue
		with open(str(t), "rb+") as f:
			f.seek(0)
			f.write(b"NV")
			f.close()

if ARGUMENTS.get("no_stubs", "0") == "0" and env["NVGT_TARGET"] not in ("ios", "android"):
	stub_platform = env["NVGT_TARGET"] if env["NVGT_TARGET"] != "macos" else "mac"
	stub_env.Append(CPPDEFINES = ["NVGT_STUB"])
	if env["NVGT_TARGET"] == "windows": stub_env.Append(LINKFLAGS = ["/subsystem:windows"])
	if ARGUMENTS.get("stub_obfuscation", "0") == "1": stub_env["CPPDEFINES"].remove("NO_OBFUSCATE")
	if env["NVGT_TARGET"] in ("macos", "ios"):
		# Apple platforms: produce separate IAP and non-IAP stub variants.
		# IAP stub: full sources including iap_apple.mm, StoreKit linked.
		VariantDir("build/obj_stub_iap", "src", duplicate = 0)
		stub_iap_env = stub_env.Clone()
		stub_iap_sources = list(sources)
		if env["NVGT_TARGET"] == "macos":
			stub_iap_sources.append("iap_apple.mm")
			stub_iap_env["CPPDEFINES"] = [d for d in stub_iap_env.get("CPPDEFINES", []) if d != "NVGT_NO_IAP"]
			stub_iap_env.Append(FRAMEWORKS = ["StoreKit"])
		stub_iap_objects = stub_iap_env.Object([os.path.join("build/obj_stub_iap", s) for s in stub_iap_sources]) + extra_objects
		stub_iap = stub_iap_env.Program(f"release/stub/nvgt_{stub_platform}_iap", stub_iap_objects)
		stub_iap_env.AddPostAction(stub_iap, fix_stub)
		stublibs_iap = list(stub_iap_env["LIBS"])
		if "angelscript" in stublibs_iap:
			stublibs_iap[stublibs_iap.index("angelscript")] = "angelscript_nc"
			stub_nc_iap = stub_iap_env.Program(f"release/stub/nvgt_{stub_platform}_nc_iap", stub_iap_objects, LIBS = stublibs_iap)
			stub_iap_env.AddPostAction(stub_nc_iap, fix_stub)
		# Non-IAP stub: exclude iap_apple.mm, remove StoreKit, define NVGT_NO_IAP.
		sources_no_iap = [s for s in sources if s != "iap_apple.mm"]
		VariantDir("build/obj_stub", "src", duplicate = 0)
		no_iap_stub_env = stub_env.Clone()
		no_iap_stub_env.Append(CPPDEFINES = ["NVGT_NO_IAP"])
		no_iap_stub_env["FRAMEWORKS"] = [f for f in no_iap_stub_env.get("FRAMEWORKS", []) if f != "StoreKit"]
		stub_objects = no_iap_stub_env.Object([os.path.join("build/obj_stub", s) for s in sources_no_iap]) + extra_objects
		stub = no_iap_stub_env.Program(f"release/stub/nvgt_{stub_platform}", stub_objects)
		no_iap_stub_env.AddPostAction(stub, fix_stub)
		stublibs = list(no_iap_stub_env["LIBS"])
		if "angelscript" in stublibs:
			stublibs[stublibs.index("angelscript")] = "angelscript_nc"
			stub_nc = no_iap_stub_env.Program(f"release/stub/nvgt_{stub_platform}_nc", stub_objects, LIBS = stublibs)
			no_iap_stub_env.AddPostAction(stub_nc, fix_stub)
	else:
		VariantDir("build/obj_stub", "src", duplicate = 0)
		stub_objects = stub_env.Object([os.path.join("build/obj_stub", s) for s in sources]) + extra_objects
		if ARGUMENTS.get("debug", "0") == "1": stub_env["PDB"] = f"#build/debug/nvgt_{stub_platform}.pdb"
		stub = stub_env.Program(f"release/stub/nvgt_{stub_platform}", stub_objects)
		stub_env.AddPostAction(stub, fix_stub)
		if env["NVGT_TARGET"] == "windows":
			env.Install("c:/nvgt/stub", stub)
			if "upx" in env:
				stub_u = stub_env.UPX(f"release/stub/nvgt_{stub_platform}_upx.bin", stub)
				stub_env.AddPostAction(stub_u, fix_stub)
				env.Install("c:/nvgt/stub", stub_u)
		stublibs = list(stub_env["LIBS"])
		if "angelscript" in stublibs:
			stublibs[stublibs.index("angelscript")] = "angelscript_nc"
			if ARGUMENTS.get("debug", "0") == "1": stub_env["PDB"] = f"#build/debug/nvgt_{stub_platform}_nc.pdb"
			stub_nc = stub_env.Program(f"release/stub/nvgt_{stub_platform}_nc", stub_objects, LIBS = stublibs)
			stub_env.AddPostAction(stub_nc, fix_stub)
			if env["NVGT_TARGET"] == "windows":
				env.Install("c:/nvgt/stub", stub_nc)
				if "upx" in env:
					stub_nc_u = stub_env.UPX(f"release/stub/nvgt_{stub_platform}_nc_upx.bin", stub_nc)
					stub_env.AddPostAction(stub_nc_u, fix_stub)
					env.Install("c:/nvgt/stub", stub_nc_u)

if ARGUMENTS.get("copylibs", "1") == "1":
	env["NVGT_OSDEV_COPY_LIBS"](env)
