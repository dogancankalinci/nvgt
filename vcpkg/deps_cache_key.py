# deps_cache_key.py - Digest of everything that can change one platform's prebuilt dependency package.
# NVGT - NonVisual Gaming Toolkit (https://nvgt.dev)
# Copyright (c) 2022-2026 Sam Tupy
# license: zlib
#
# CI caches each platform's dependency package (windev, macosdev, iosdev, lindev, droidev) under a key that used to
# hash the whole vcpkg manifest, so a dependency change made for one platform, such as adding a library that only iOS
# needs, threw away every other platform's cache and rebuilt hours of dependencies for nothing. This prints a digest
# of only what can reach the given triplets: the manifest as vcpkg itself would read it for them (dependencies whose
# "platform" expression excludes the triplet are dropped), the overlay ports those dependencies pull in, the triplet
# files actually built, the registry configuration, the vcpkg tool revision and the platform's package layout version
# from build_dependencies.py (an explicit per-platform number, so an edit to that script for one platform leaves the
# other platforms' keys alone).
#
# usage: deps_cache_key.py <triplet> [<triplet>...] [--manifest path] [--extra text]
# Prints a hex digest; the workflow prefixes it with the package name.

import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

here = Path(__file__).resolve().parent
repo = here.parent

# The vcpkg platform-expression identifiers each triplet we build satisfies (vcpkg derives these from the triplet's
# target architecture and system name; every triplet here links statically by default).
TRIPLET_IDENTIFIERS = {
	"x64-windows": {"windows", "x64", "static"}, "arm64-windows": {"windows", "arm64", "static"},
	"x64-osx": {"osx", "x64", "static"}, "arm64-osx": {"osx", "arm64", "static"},
	"x64-linux": {"linux", "x64", "static"}, "arm64-linux": {"linux", "arm64", "static"},
	"arm64-android": {"android", "arm64", "static"}, "armv7-android": {"android", "arm", "static"},
	"arm64-ios": {"ios", "arm64", "static"}, "arm64-ios-simulator": {"ios", "arm64", "static"},
}

def evaluate(expression, identifiers):
	"""Evaluates a vcpkg platform expression ("!ios", "windows|osx", "(linux & x64), arm64") against a triplet's identifiers."""
	tokens = re.findall(r"[A-Za-z0-9_]+|[!&|,()]", expression)
	pos = 0
	def peek(): return tokens[pos] if pos < len(tokens) else None
	def take():
		nonlocal pos
		pos += 1
		return tokens[pos - 1]
	def primary():
		t = take()
		if t == "!": return not primary()
		if t == "(":
			v = disjunction()
			if take() != ")": raise ValueError(f"unbalanced parentheses in platform expression {expression!r}")
			return v
		if t is None or not re.fullmatch(r"[A-Za-z0-9_]+", t): raise ValueError(f"unexpected {t!r} in platform expression {expression!r}")
		return t in identifiers
	def conjunction():
		v = primary()
		while peek() == "&":
			take()
			v = primary() and v
		return v
	def disjunction():
		v = conjunction()
		while peek() in ("|", ","):
			take()
			v = conjunction() or v
		return v
	result = disjunction()
	if pos != len(tokens): raise ValueError(f"trailing tokens in platform expression {expression!r}")
	return result

def dependency_entries(dependencies, identifiers):
	"""Normalises a vcpkg dependency list to the entries that apply to a triplet, in a canonical form."""
	out = []
	for d in dependencies or []:
		if isinstance(d, str): d = {"name": d}
		if "platform" in d and not evaluate(d["platform"], identifiers): continue
		features = []
		for f in d.get("features", []):
			if isinstance(f, str): features.append(f)
			elif "platform" not in f or evaluate(f["platform"], identifiers): features.append(f["name"])
		out.append({"name": d["name"], "default-features": d.get("default-features", True), "features": sorted(features), "host": d.get("host", False)})
	out.sort(key = lambda e: json.dumps(e, sort_keys = True))
	return out

def project_manifest(manifest, identifiers):
	return {"dependencies": dependency_entries(manifest.get("dependencies"), identifiers), "builtin-baseline": manifest.get("builtin-baseline"), "overrides": manifest.get("overrides", [])}

def overlay_ports():
	"""name -> (port directory, port manifest) for every overlay port in vcpkg/ports."""
	ports = {}
	for d in sorted((here / "ports").iterdir()):
		m = d / "vcpkg.json"
		if not d.is_dir() or not m.is_file(): continue
		try: pm = json.loads(m.read_text(encoding = "utf-8"))
		except ValueError: pm = {}
		ports[pm.get("name", d.name)] = (d, pm)
	return ports

def reachable_ports(roots, ports, identifiers):
	"""Overlay ports a set of top-level dependencies reaches, following overlay ports' own dependency lists."""
	seen, todo = set(), [r for r in roots if r in ports]
	while todo:
		name = todo.pop()
		if name in seen: continue
		seen.add(name)
		for dep in dependency_entries(ports[name][1].get("dependencies"), identifiers):
			if dep["name"] in ports and dep["name"] not in seen: todo.append(dep["name"])
	return seen

def file_digests(root):
	"""(relative path, sha256) for every file under root, sorted, so a port is digested by content rather than mtime."""
	out = []
	for p in sorted(root.rglob("*")):
		if p.is_file(): out.append([p.relative_to(root).as_posix(), hashlib.sha256(p.read_bytes()).hexdigest()])
	return out

def package_name(triplet):
	"""The dependency package a triplet is exported into, mirroring build_dependencies.build."""
	if "-windows" in triplet: return "windev"
	if "-osx" in triplet: return "macosdev"
	if "-linux" in triplet: return "lindev"
	if "-android" in triplet: return "droidev"
	if "-ios" in triplet: return "iosdev"
	sys.exit(f"cannot tell which package {triplet} belongs to")

def package_layout_version(name):
	import importlib.util
	spec = importlib.util.spec_from_file_location("build_dependencies", here / "build_dependencies.py")
	module = importlib.util.module_from_spec(spec)
	spec.loader.exec_module(module)
	return module.PACKAGE_LAYOUT_VERSION[name]

def vcpkg_tool_revision():
	try: return subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD:vcpkg/bin"], stderr = subprocess.DEVNULL).decode().strip()
	except Exception: pass
	head = repo / ".git" / "modules" / "vcpkg" / "bin" / "HEAD"
	return head.read_text().strip() if head.is_file() else "unknown"

def main(argv):
	triplets, manifest_path, extra = [], here / "vcpkg.json", ""
	args = list(argv)
	while args:
		a = args.pop(0)
		if a == "--manifest": manifest_path = Path(args.pop(0))
		elif a == "--extra": extra = args.pop(0)
		else: triplets.append(a)
	if not triplets: sys.exit("usage: deps_cache_key.py <triplet> [<triplet>...] [--manifest path] [--extra text]")
	manifest = json.loads(manifest_path.read_text(encoding = "utf-8"))
	ports = overlay_ports()
	material = {"version": 1, "extra": extra, "triplets": {}, "ports": {}, "vcpkg_tool": vcpkg_tool_revision(), "files": {}}
	used_ports = set()
	for t in triplets:
		if t not in TRIPLET_IDENTIFIERS: sys.exit(f"unknown triplet {t}; add it to TRIPLET_IDENTIFIERS")
		identifiers = TRIPLET_IDENTIFIERS[t]
		projection = project_manifest(manifest, identifiers)
		triplet_file = here / "triplets" / f"{t}.cmake"
		material["triplets"][t] = {"manifest": projection, "triplet": hashlib.sha256(triplet_file.read_bytes()).hexdigest() if triplet_file.is_file() else None}
		used_ports |= reachable_ports([d["name"] for d in projection["dependencies"]], ports, identifiers)
	for name in sorted(used_ports): material["ports"][name] = file_digests(ports[name][0])
	p = here / "vcpkg-configuration.json"
	material["files"]["vcpkg-configuration.json"] = hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else None
	packages = {package_name(t) for t in triplets}
	if len(packages) != 1: sys.exit(f"triplets {triplets} belong to different packages {sorted(packages)}")
	material["package_layout"] = {next(iter(packages)): package_layout_version(next(iter(packages)))}
	print(hashlib.sha256(json.dumps(material, sort_keys = True, separators = (",", ":")).encode()).hexdigest())

if __name__ == "__main__":
	main(sys.argv[1:])
