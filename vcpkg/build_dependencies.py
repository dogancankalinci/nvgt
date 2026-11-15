# Script to build all of NVGT's dependencies with vcpkg, setting them up for NVGT builds and optionally creating redistributable archives for the dependencies.
# This only supports the triplets that we currently use as well as IOS.
# NVGT - NonVisual Gaming Toolkit (https://nvgt.dev)
# Copyright (c) 2022-2026 Sam Tupy
# license: zlib
import os
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import urllib.error
import urllib.request

# Bump a platform's number whenever a change to this script alters what its package contains or how it is laid out (a
# new library rename, a different directory structure, another duplicate removed). CI keys each platform's dependency
# cache by this number rather than by this file's content, so an edit made for one platform does not throw away the
# packages of the others. A change to code every platform runs through (fix_debug, the copy layout) needs every number bumped.
PACKAGE_LAYOUT_VERSION = {"windev": 1, "macosdev": 1, "lindev": 1, "droidev": 1, "iosdev": 2}

vcpkg_path = Path(__file__, "..", "bin", "vcpkg" if sys.platform != "win32" else "vcpkg.exe").resolve()
vcpkg_installed_path = Path(__file__, "..", "vcpkg_installed").resolve()
repo_path = Path(__file__).parents[1]

def bootstrap_vcpkg():
	if vcpkg_path.exists() and vcpkg_path.is_file():
		return
	if sys.platform == "win32":
		subprocess.check_output(vcpkg_path.parent / "bootstrap-vcpkg.bat")
	else:
		subprocess.check_output(vcpkg_path.parent / "bootstrap-vcpkg.sh")
def prefetch_github_api_downloads():
	"""Fetches the files that ports download from api.github.com, using the CI's token, before vcpkg asks for them itself.
	vcpkg sends those requests without credentials, and GitHub answers an address only 60 of them an hour. The hosted
	runners share their addresses, so the pcre2 port's lookup of its sljit submodule came back 403 and stopped the whole
	build. A file is written only when it has the exact SHA512 the port expects, which makes vcpkg take it as already
	downloaded; without a token, or when the port no longer looks like this, vcpkg downloads it as before."""
	token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
	if not token: return
	port = vcpkg_path.parent / "ports" / "pcre2"
	try:
		version = json.loads((port / "vcpkg.json").read_text(encoding = "utf-8"))["version"]
		portfile = (port / "portfile.cmake").read_text(encoding = "utf-8")
	except (OSError, KeyError, ValueError): return
	expected = re.search(r"set\(sljit_gitlink_hash SHA512 ([0-9a-f]{128})\)", portfile)
	shape = ['set(pcre2_ref "pcre2-${VERSION}")', 'URLS "https://api.github.com/repos/PCRE2Project/pcre2/contents/deps/sljit?ref=${pcre2_ref}"', 'FILENAME "pcre2-${pcre2_ref}-sljit-gitlink.json"']
	if not expected or not all(line in portfile for line in shape): return
	ref = f"pcre2-{version}"
	target = Path(os.environ.get("VCPKG_DOWNLOADS") or vcpkg_path.parent / "downloads") / f"pcre2-{ref}-sljit-gitlink.json"
	if target.exists(): return
	# The API indents its JSON for a curl user agent and compacts it for others, and the port's hash is of what curl, which
	# vcpkg downloads with, receives.
	request = urllib.request.Request(f"https://api.github.com/repos/PCRE2Project/pcre2/contents/deps/sljit?ref={ref}", headers = {"Authorization": f"Bearer {token}", "User-Agent": "curl/8"})
	try:
		with urllib.request.urlopen(request, timeout = 60) as response: data = response.read()
	except (urllib.error.URLError, OSError) as e:
		print(f"note: could not prefetch {target.name} ({e}), leaving it to vcpkg")
		return
	if hashlib.sha512(data).hexdigest() != expected.group(1):
		print(f"note: {target.name} from the GitHub API does not have the hash the pcre2 port expects, leaving it to vcpkg")
		return
	target.parent.mkdir(parents = True, exist_ok = True)
	partial = target.with_name(target.name + ".part")
	partial.write_bytes(data)
	partial.replace(target)
def build(triplet = "", do_archive = False, out_dir = ""):
	if not triplet:
		# Try to determine, logic probably could be improved
		if sys.platform == "win32": triplet = "x64-windows"
		elif sys.platform == "darwin": triplet = "arm64-osx"
		elif sys.platform == "linux":
                    if(os.uname().machine.__contains__("x86")):
                        triplet = "x64-linux"
                    elif(os.uname().machine.__contains__("aarch64")):
                        triplet = "arm64-linux"
		else: sys.exit("unable to determine platform, please pass a triplet explicitly.")
	bootstrap_vcpkg()
	prefetch_github_api_downloads()
	try: subprocess.run([vcpkg_path, "install", "--triplet", triplet, "--x-manifest-root", vcpkg_path.parents[1]], check=True)
	except subprocess.CalledProcessError as cpe: sys.exit(f"Building packages for {triplet} failed with error code {cpe.returncode}.")
	dev_basename = ""
	abi_subdir = ""
	if "-windows" in triplet: dev_basename = "windev"
	elif "-osx" in triplet: dev_basename = "macosdev"
	elif "-linux" in triplet: dev_basename = "lindev"
	# Android deps are always laid out per-ABI: droidev/arm64-v8a and droidev/armeabi-v7a, each self-contained (include + lib).
	# scons builds each ABI against only its own subdir; there is no flat droidev/lib for Android.
	elif "armv7-android" in triplet: dev_basename = "droidev"; abi_subdir = "armeabi-v7a"
	elif "-android" in triplet: dev_basename = "droidev"; abi_subdir = "arm64-v8a"
	elif "-ios" in triplet: dev_basename = "iosdev"
	archive_base = repo_path / dev_basename if dev_basename else None
	if not out_dir:
		out_dir = archive_base / abi_subdir if abi_subdir else archive_base
	else:
		out_dir = Path(out_dir)
		archive_base = out_dir
	out_dir.mkdir(parents=True, exist_ok=True)
	if (vcpkg_installed_path / triplet / "bin").exists(): shutil.copytree(vcpkg_installed_path / triplet / "bin", out_dir / "bin", dirs_exist_ok = True)
	if (vcpkg_installed_path / triplet / "debug" / "bin").exists(): shutil.copytree(vcpkg_installed_path / triplet / "debug" / "bin", out_dir / "debug" / "bin", dirs_exist_ok = True)
	shutil.copytree(vcpkg_installed_path / triplet / "debug" / "lib", out_dir / "debug" / "lib", dirs_exist_ok = True)
	shutil.copytree(vcpkg_installed_path / triplet / "include", out_dir / "include", dirs_exist_ok = True)
	shutil.copytree(vcpkg_installed_path / triplet / "lib", out_dir / "lib", dirs_exist_ok = True)
	fix_debug(out_dir)
	if triplet == "arm64-osx": macos_fat_binaries(out_dir)
	elif triplet == "x64-windows": windows_lib_rename(out_dir)
	if triplet.endswith("osx") or triplet.endswith("linux") or "-ios" in triplet: remove_duplicates(out_dir, ios = "-ios" in triplet)
	try:
		shutil.rmtree(out_dir / "lib" / "cmake")
		shutil.rmtree(out_dir / "lib" / "pkgconfig")
		shutil.rmtree(out_dir / "debug" / "lib" / "cmake")
		shutil.rmtree(out_dir / "debug" / "lib" / "pkgconfig")
	except FileNotFoundError: pass
	if do_archive:
		shutil.make_archive(archive_base, format = "zip", root_dir = archive_base)
		with archive_base.with_suffix(".zip").open("rb") as f, archive_base.with_suffix(".zip.blake2b").open("w") as hf:
			h = hashlib.blake2b()
			h.update(f.read())
			hf.write(h.hexdigest())
def macos_fat_binaries(out_dir):
	"""We must manually build Angelscript, Steam Audio, libffi and openssl for x64 as well and then run lipo on both of our builds to create universal binaries for them. This is meant to be run after the macosdev directory is created. We basically need to do this for libraries that contain assembly instructions, because the Clang fat builds of such libraries either fail or break down when running NVGT."""
	try: subprocess.check_output([vcpkg_path, "install", "--classic", "--triplet", "x64-osx", "--overlay-ports=" + str(Path(__file__).parent / "ports"), "--overlay-triplets=" + str(Path(__file__).parent / "triplets"), "angelscript", "angelscript-nc", "libffi", "openssl", "steam-audio"])
	except subprocess.CalledProcessError as cpe: sys.exit(f"Building angelscript libffi and openssl for x64-osx failed with error code {cpe.returncode}.\n{cpe.output.decode()}")
	for f in ["libangelscript.a", "libangelscript_nc.a", "libcrypto.a", "libffi.a", "libphonon.a", "libssl.a"]:
		(out_dir / "debug" / "lib" / f).unlink()
		(out_dir / "lib" / f).unlink()
		subprocess.check_output(["lipo", "-create", vcpkg_path.parent / "installed" / "x64-osx" / "debug" / "lib" / f, vcpkg_installed_path / "arm64-osx" / "debug" / "lib" / f, "-output", out_dir / "debug" / "lib" / f])
		subprocess.check_output(["lipo", "-create", vcpkg_path.parent / "installed" / "x64-osx" / "lib" / f, vcpkg_installed_path / "arm64-osx" / "lib" / f, "-output", out_dir / "lib" / f])
def fix_debug(out_dir):
	"""Several debug libraries frustratingly have different filenames to their release counterparts, which just makes build scripts more complicated. We'll just fix it here. Usually a d is just tacked on to the end of the filename which we'll get rid of as well as a hifen that sometimes appears."""
	excludes = ["reactphysics3d", "zstd"]
	for f in (out_dir / "debug" / "lib").iterdir():
		if not f.stem.lower().endswith("d"): continue
		exclude = f.stem if not f.stem.startswith("lib") else f.stem[3:]
		if exclude in excludes: continue
		count = 1 if not f.stem.lower().endswith("-d") else 2
		f.replace(f.with_stem(f.stem[:-count]))
def windows_lib_rename(out_dir):
	"""Sometimes windows libraries get built with annoying names that complicate build scripts. We have to handle them somewhere, may as well be here."""
	renames = [
		("libcrypto", "crypto"),
		("libcurl", "curl"),
		("libexpatMT", "expat"),
		("libexpatdMT", "expat"),
		("libssl", "ssl"),
		("pocoCryptomt", "pocoCrypto"),
		("pocoEncodingsmt", "pocoEncodings"),
		("pocoFoundationmt", "pocoFoundation"),
		("pocoJSONmt", "pocoJSON"),
		("pocoJWTmt", "pocoJWT"),
		("pocoMongoDBmt", "pocoMongoDB"),
		("pocoNetmt", "pocoNet"),
		("pocoNetSSLmt", "pocoNetSSL"),
		("pocoPrometheusmt", "pocoPrometheus"),
		("pocoRedismt", "pocoRedis"),
		("pocoSevenZipmt", "pocoSevenZip"),
		("pocoUtilmt", "pocoUtil"),
		("pocoXMLmt", "pocoXML"),
		("pocoZipmt", "pocoZip"),
		("SDL3-static", "SDL3"),
		("SDL3_image-static", "SDL3_image"),
		("SDL3_ttf-static", "SDL3_ttf"),
		("utf8proc_static", "utf8proc"),
		("zlib", "z")
	] # end renames list
	for lib in ["debug/lib", "lib"]:
		for r in renames:
			if (out_dir / lib / (r[0] + ".lib")).exists(): (out_dir / lib / (r[0] + ".lib")).replace(out_dir / lib / (r[1] + ".lib"))
def remove_duplicates(out_dir, ios = False):
	"""A couple libraries on Linux and MacOS might have created duplicate versions of themselves because of symlinks, lets get rid of them. We'll also perform install_name_tool fixes on MacOS.
	On iOS a dynamic library can only ship inside a framework bundle, so the install name already points where scons will wrap it: @rpath/<lib>.framework/<lib>."""
	for lib in ["libarchive", "libgit2"]:
		for libdir in ["debug/lib", "lib"]:
			versions = list((out_dir / libdir).glob(lib + "*"))
			if len(versions) < 2: continue
			versions.sort(key = lambda v: len(v.name))
			for v in versions[1:]: v.unlink()
			if sys.platform == "darwin": subprocess.check_output(["install_name_tool", "-id", f"@rpath/{lib}.framework/{lib}" if ios else f"@rpath/{versions[0].name}", str(versions[0])])

if __name__ == "__main__":
	triplets = []
	do_archive = False
	if len(sys.argv) > 1:
		for arg in sys.argv[1:]:
			if arg == "--archive": do_archive = True
			else: triplets.append(arg)
	if len(triplets) < 1: triplets.append("")
	for t in triplets: build(t, do_archive)
