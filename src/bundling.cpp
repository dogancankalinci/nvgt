/* bundling.cpp - Routines for creating final application packages or bundles on various platforms
 * On Android, this allows games to be compiled to .apk packages.
 * on MacOS and IOS, this will allow .app bundles to be generated.
 * on Windows, this will add version information to the executable and optionally copy libraries and other assets into a package that can be installed/zipped/whatever.
 * It should be understood that these bundling facilities in particular are not standalone and may have limited functionality when compiling on platforms other than their intended targets. For example the NVGT user needs the android development tools to bundle an Android app, it's best to bundle a .app on a mac because nvgt can then go as far as to create a .dmg for you which is not possible on other platforms etc.
 *
 * NVGT - NonVisual Gaming Toolkit
 * Copyright (c) 2022-2026 Sam Tupy
 * https://nvgt.dev
 * This software is provided "as-is", without any express or implied warranty. In no event will the authors be held liable for any damages arising from the use of this software.
 * Permission is granted to anyone to use this software for any purpose, including commercial applications, and to alter it and redistribute it freely, subject to the following restrictions:
 * 1. The origin of this software must not be misrepresented; you must not claim that you wrote the original software. If you use this software in a product, an acknowledgment in the product documentation would be appreciated but is not required.
 * 2. Altered source versions must be plainly marked as such, and must not be misrepresented as being the original software.
 * 3. This notice may not be removed or altered from any source distribution.
*/

// This entire module is only needed assuming that NVGT is not being compiled as a stub, and also assuming that the runner application is not being built on mobile. It's perfectly fine to just not build bundling.cpp at all as long as NVGT_STUB is defined, but lets not error or risk including code in case of inclusion into a stub so that we can laisily feed the build system a wildcard to the src directory.
#include "xplatform.h"
#if !defined(NVGT_STUB) && !defined(NVGT_MOBILE)
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <sstream>
#include <utility>
#include <Poco/BinaryReader.h>
#include <Poco/BinaryWriter.h>
#include <Poco/Base64Encoder.h>
#include <Poco/Clock.h>
#include <Poco/Environment.h>
#include <Poco/File.h>
#include <Poco/FileStream.h>
#include <Poco/Format.h>
#include <Poco/Glob.h>
#include <Poco/Mutex.h>
#include <Poco/Path.h>
#include <Poco/PipeStream.h>
#include <Poco/Process.h>
#include <Poco/StreamCopier.h>
#include <Poco/String.h>
#include <Poco/StringTokenizer.h>
#include <Poco/TemporaryFile.h>
#include <Poco/Timestamp.h>
#include <Poco/UnicodeConverter.h>
#include <Poco/Util/Application.h>
#include <archive.h>
#include <archive_entry.h>
#include <openssl/cms.h>
#include <openssl/err.h>
#include <openssl/pkcs12.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <plist/plist.h>
#ifdef _WIN32
#include <windows.h>
#include <vs_version.h>
#endif
#include "bundling.h"
#include "lzfse/lzfse.h"        // LZFSE encoder for the iOS Assets.car bitmap renditions
#include "ios_appicon_template.h" // embedded actool-produced catalog structure (bitmaps replaced at build time)
#include "ios_signing_certs.h"  // bundled Apple WWDR + Root certs for byte-identical code signing
#include <openssl/pkcs12.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include "filesystem.h"
#include "misc_functions.h" // parse_float
#include "nvgt.h"
#ifndef NVGT_USER_CONFIG
	#include "nvgt_config.h"
#else
	#include "../user/nvgt_config.h"
#endif
#include "pack.h" // write_embedded_packs
#include "UI.h"
using namespace std;
using namespace Poco;

// Storage and routines for defining game assets that should be included.
class game_asset {
public:
	std::string filesystem_path;
	std::string bundled_path;
	int flags;
	game_asset(const std::string& filesystem_path, const std::string& bundled_path, int flags = 0) : filesystem_path(filesystem_path), bundled_path(bundled_path), flags(flags) {
		if (bundled_path.empty()) this->bundled_path = Path(filesystem_path).getFileName();
	}
};
vector<game_asset> g_game_assets;
void add_game_asset_to_bundle(const string& filesystem_path, const string& bundled_path, int flags) {
	g_game_assets.push_back(game_asset(filesystem_path, bundled_path, flags));
}
void add_game_asset_to_bundle(const string& path, int flags) {
	// In this case the filesystem path and the bundled path are in the same string, separated by semicolon.
	size_t semi = path.find_first_of(';');
	while (semi && semi != string::npos && path[semi -1] == '\\' ) semi = path.find_first_of(';', semi + 1);
	return add_game_asset_to_bundle(path.substr(0, semi), path.substr(semi +1 ), flags);
}
set<string> g_bundle_libraries = {"nvdaControllerClient64", "phonon", "SAAPI64", "zdsrapi"};
void nvgt_bundle_shared_library(const string& libname) {
	g_bundle_libraries.insert(libname);
}

// Helper function to run a shell command that returns true if that command returns 0, false otherwise. Specifically intended for programatic use, this makes no attempt to print output or errors from the given command to the real stdout stream and instead captures all output for use in our program.
bool system_command(const std::string& command, const Process::Args& args, const std::string& initial_directory, string& std_out, string& std_err) {
	Pipe p_out, p_err;
	int rc;
	if (initial_directory.empty()) rc = Process::wait(Process::launch(command, args, nullptr, &p_out, &p_err));
	else rc = Process::wait(Process::launch(command, args, initial_directory, nullptr, &p_out, &p_err));
	if (rc < 0) return false;
	StreamCopier::copyToString(*SharedPtr<PipeInputStream>(new PipeInputStream(p_out)), std_out);
	StreamCopier::copyToString(*SharedPtr<PipeInputStream>(new PipeInputStream(p_err)), std_err);
	return rc == 0;
}
bool system_command(const std::string& command, const Process::Args& args, string& std_out, string& std_err) {
	return system_command(command, args, "", std_out, std_err);
}
bool system_command(const string& command, const Process::Args& args = {}) {
	string std_out, std_err;
	return system_command(command, args, std_out, std_err);
}
// Similar to above, but this function handles a single command string intended to come from the user and does not redirect pipes.
bool user_command(const std::string& command) {
	string appname, current_arg;
	vector<string> args;
	bool in_quotes = false;
	for (size_t i = 0; i <= command.length(); i++) {
		if (i == command.length() || command[i] == ' ' && !in_quotes) {
			if (appname.empty()) appname = current_arg;
			else args.push_back(current_arg);
			current_arg = "";
		} else if (command[i] == '"') in_quotes = !in_quotes;
		else current_arg += command[i];
	}
	return Process::wait(Process::launch(appname, args)) == 0;
}

// Extract all entries from an archive file to a destination directory using libarchive.
static void libarchive_extract(const string& arc_path, const string& dest) {
	struct archive* a = archive_read_new();
	archive_read_support_format_all(a);
	archive_read_support_filter_all(a);
	if (archive_read_open_filename(a, arc_path.c_str(), 65536) != ARCHIVE_OK) throw Exception(format("Failed to open archive %s: %s", arc_path, string(archive_error_string(a))));
	struct archive* disk = archive_write_disk_new();
	archive_write_disk_set_options(disk, ARCHIVE_EXTRACT_PERM | ARCHIVE_EXTRACT_TIME);
	struct archive_entry* entry;
	string dest_base = dest;
	if (!dest_base.empty() && dest_base.back() != '/' && dest_base.back() != '\\') dest_base += '/';
	while (archive_read_next_header(a, &entry) == ARCHIVE_OK) {
		string full = dest_base + archive_entry_pathname(entry);
		archive_entry_set_pathname(entry, full.c_str());
		archive_write_header(disk, entry);
		const void* buf; size_t size; la_int64_t offset;
		while (archive_read_data_block(a, &buf, &size, &offset) == ARCHIVE_OK) archive_write_data_block(disk, buf, size, offset);
		archive_write_finish_entry(disk);
	}
	archive_read_free(a);
	archive_write_free(disk);
}
// Recursively add all files in disk_dir to an open libarchive write handle.
// arc_prefix: path prefix in archive (empty for root). exec_paths: archive paths that should get 0755.
// store_paths: archive paths that should be stored without compression (zip only). zip: true if format is zip.
// no_dir_entries: when true, skip directory ZIP entries (required for Android App Bundles —
// bundletool rejects any bundle that contains directory entries in the ZIP).
static void archive_write_dir(struct archive* a, const string& disk_dir, const string& arc_prefix, const set<string>& exec_paths, const set<string>& store_paths, bool zip, bool no_dir_entries = false) {
	vector<File> entries;
	File(disk_dir).list(entries);
	for (const File& f : entries) {
		string name = Path(f.path()).makeFile().getFileName();
		string arc = arc_prefix.empty() ? name : arc_prefix + "/" + name;
		struct archive_entry* e = archive_entry_new();
		archive_entry_set_pathname(e, arc.c_str());
		archive_entry_set_mtime(e, f.getLastModified().epochTime(), 0);
		if (f.isDirectory()) {
			if (!no_dir_entries) {
				archive_entry_set_filetype(e, AE_IFDIR);
				archive_entry_set_perm(e, 0755);
				archive_entry_set_size(e, 0);
				archive_write_header(a, e);
			}
			archive_entry_free(e);
			archive_write_dir(a, f.path(), arc, exec_paths, store_paths, zip, no_dir_entries);
		} else {
			if (zip) {
				if (store_paths.count(arc)) archive_write_zip_set_compression_store(a);
				else archive_write_zip_set_compression_deflate(a);
			}
			archive_entry_set_filetype(e, AE_IFREG);
			archive_entry_set_perm(e, exec_paths.count(arc) ? 0755 : 0644);
			archive_entry_set_size(e, (la_int64_t)f.getSize());
			archive_write_header(a, e);
			archive_entry_free(e);
			FileInputStream fis(f.path());
			char buf[65536];
			while (fis.good()) {
				fis.read(buf, sizeof(buf));
				la_ssize_t n = fis.gcount();
				if (n > 0) archive_write_data(a, buf, n);
			}
		}
	}
}
// Write a single file on disk into an open libarchive write handle under a custom archive path.
static void archive_write_memory(struct archive* a, const string& arc_path, const void* data, size_t size) {
	struct archive_entry* e = archive_entry_new();
	archive_entry_set_pathname(e, arc_path.c_str());
	archive_entry_set_filetype(e, AE_IFREG);
	archive_entry_set_perm(e, 0644);
	archive_entry_set_size(e, (la_int64_t)size);
	archive_write_header(a, e);
	archive_entry_free(e);
	if (size > 0) archive_write_data(a, data, size);
}
static void archive_write_single_file(struct archive* a, const string& disk_path, const string& arc_path) {
	File f(disk_path);
	if (!f.exists() || !f.isFile()) return;
	struct archive_entry* e = archive_entry_new();
	archive_entry_set_pathname(e, arc_path.c_str());
	archive_entry_set_filetype(e, AE_IFREG);
	archive_entry_set_perm(e, 0644);
	archive_entry_set_size(e, (la_int64_t)f.getSize());
	archive_write_header(a, e);
	archive_entry_free(e);
	FileInputStream fis(disk_path);
	char buf[65536];
	while (fis.good()) {
		fis.read(buf, sizeof(buf));
		la_ssize_t n = fis.gcount();
		if (n > 0) archive_write_data(a, buf, n);
	}
}
static void collect_relative_files_recursive(const string& root_dir, const string& relative_dir, vector<string>& out_files) {
	vector<File> entries;
	File(relative_dir.empty() ? root_dir : Path(root_dir).append(relative_dir).toString()).list(entries);
	for (const File& f : entries) {
		string name = Path(f.path()).makeFile().getFileName();
		string rel = relative_dir.empty() ? name : relative_dir + "/" + name;
		if (f.isDirectory()) collect_relative_files_recursive(root_dir, rel, out_files);
		else out_files.push_back(rel);
	}
}
	static bool string_has_suffix(const string& value, const string& suffix) {
		return value.size() >= suffix.size() && value.compare(value.size() - suffix.size(), suffix.size(), suffix) == 0;
	}
static string make_unique_temp_path(const string& suffix) {
	TemporaryFile tmp;
	string path = tmp.path() + suffix;
	if (File(tmp.path()).exists()) File(tmp.path()).remove();
	if (File(path).exists()) File(path).remove(true);
	return path;
}
// --- Custom application icon helpers (shared by every platform bundler) ---
// Read the whole file at path into a string (raw bytes).
static string read_file_bytes(const string& path) {
	FileInputStream f(path);
	string data;
	StreamCopier::copyToString(f, data);
	return data;
}
// Read a PNG's pixel dimensions straight from its IHDR chunk without decoding the image. The PNG
// spec fixes the layout: 8-byte signature, then the IHDR chunk whose 4-byte big-endian width and
// height start at byte offsets 16 and 20 respectively. Returns false if the file is not a PNG.
static bool read_png_size(const string& path, uint32_t& width, uint32_t& height) {
	FileInputStream f(path);
	unsigned char hdr[24];
	f.read((char*)hdr, sizeof(hdr));
	if (f.gcount() < (streamsize)sizeof(hdr)) return false;
	static const unsigned char sig[8] = {0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A};
	if (memcmp(hdr, sig, 8) != 0 || memcmp(hdr + 12, "IHDR", 4) != 0) return false;
	width  = (uint32_t(hdr[16]) << 24) | (uint32_t(hdr[17]) << 16) | (uint32_t(hdr[18]) << 8) | hdr[19];
	height = (uint32_t(hdr[20]) << 24) | (uint32_t(hdr[21]) << 16) | (uint32_t(hdr[22]) << 8) | hdr[23];
	return true;
}
// Append a 32-bit big-endian integer to a byte string.
static void append_be32(string& out, uint32_t v) {
	out.push_back(char((v >> 24) & 0xff));
	out.push_back(char((v >> 16) & 0xff));
	out.push_back(char((v >> 8) & 0xff));
	out.push_back(char(v & 0xff));
}
// Build an Apple .icns file that wraps a single PNG. The .icns container is a magic ('icns'),
// a big-endian total length, then a series of {4-char OSType, big-endian length incl. header,
// data} chunks. Modern macOS accepts PNG data directly under the ic07..ic10 / icp4..icp6 types,
// so we pick the OSType whose nominal size best fits the source PNG and embed it as-is; Finder
// scales the single representation to the sizes it needs. Returns the .icns bytes.
static string build_icns_from_png(const string& png_path) {
	uint32_t w = 0, h = 0;
	if (!read_png_size(png_path, w, h)) throw Exception(format("custom icon %s is not a valid PNG", png_path));
	string png = read_file_bytes(png_path);
	uint32_t dim = w > h ? w : h; // use the larger edge to avoid ever labeling the icon smaller than it is.
	const char* ostype;
	if (dim <= 16) ostype = "icp4";
	else if (dim <= 32) ostype = "icp5";
	else if (dim <= 64) ostype = "icp6";
	else if (dim <= 128) ostype = "ic07";
	else if (dim <= 256) ostype = "ic08";
	else if (dim <= 512) ostype = "ic09";
	else ostype = "ic10";
	string body;
	body.append(ostype, 4);
	append_be32(body, uint32_t(8 + png.size())); // chunk length includes the 8-byte chunk header.
	body += png;
	string icns;
	icns.append("icns", 4);
	append_be32(icns, uint32_t(8 + body.size())); // file length includes the 8-byte file header.
	icns += body;
	return icns;
}
// Resize the source PNG to exactly w x h pixels and write it as a PNG to out_path, using SDL's
// built-in PNG loader/scaler/saver (already linked into nvgt). Returns false on any failure. Used to
// emit the exact-size loose iOS icons Apple's validator demands (e.g. 120x120, 152x152).
static string write_resized_png(const string& src_png, int w, int h, const string& out_path) {
	SDL_Surface* s = SDL_LoadPNG(src_png.c_str());
	if (!s) return format("SDL_LoadPNG(%s) failed: %s", src_png, string(SDL_GetError()));
	SDL_Surface* scaled = SDL_ScaleSurface(s, w, h, SDL_SCALEMODE_LINEAR);
	SDL_DestroySurface(s);
	if (!scaled) return format("SDL_ScaleSurface failed: %s", string(SDL_GetError()));
	bool ok = SDL_SavePNG(scaled, out_path.c_str());
	SDL_DestroySurface(scaled);
	if (!ok) return format("SDL_SavePNG(%s) failed: %s", out_path, string(SDL_GetError()));
	return "";
}
// Load an icon PNG, scale to 1024x1024, and return its premultiplied BGRA bytes (4194304) — the pixel
// format Apple's CoreUI stores app-icon renditions in. Returns empty string on failure.
static string load_icon_bgra_1024(const string& png) {
	SDL_Surface* s = SDL_LoadPNG(png.c_str());
	if (!s) return "";
	if (s->w != 1024 || s->h != 1024) {
		SDL_Surface* r = SDL_ScaleSurface(s, 1024, 1024, SDL_SCALEMODE_LINEAR);
		SDL_DestroySurface(s); s = r;
		if (!s) return "";
	}
	SDL_Surface* rgba = SDL_ConvertSurface(s, SDL_PIXELFORMAT_RGBA32); // memory order R,G,B,A on any endian
	SDL_DestroySurface(s);
	if (!rgba) return "";
	string out; out.resize(1024u * 1024 * 4);
	for (int y = 0; y < 1024; y++) {
		const unsigned char* row = (const unsigned char*)rgba->pixels + (size_t)y * rgba->pitch;
		for (int x = 0; x < 1024; x++) {
			unsigned char R = row[x*4+0], G = row[x*4+1], B = row[x*4+2], A = row[x*4+3];
			unsigned char* o = (unsigned char*)&out[((size_t)y*1024 + x) * 4];
			o[0] = (B*A + 127) / 255; o[1] = (G*A + 127) / 255; o[2] = (R*A + 127) / 255; o[3] = A; // premultiplied BGRA
		}
	}
	SDL_DestroySurface(rgba);
	return out;
}
// Generate an Apple compiled asset catalog (Assets.car) containing the given icon as its AppIcon,
// which the App Store requires for iOS apps (ITMS-90713). We start from an embedded actool-produced
// catalog (ios_appicon_template) whose every structural block is byte-identical to Xcode's output,
// and replace only the two 1024x1024 image renditions' bitmaps with the user's icon (BGRA, split into
// the same 341-row LZFSE chunks CoreUI uses), then rebuild the BOM block table. See bundling notes:
// the exact byte format was reverse-engineered from a real actool Assets.car.
static string build_assets_car(const string& icon_png) {
	string bgra = load_icon_bgra_1024(icon_png);
	if (bgra.size() != 1024u * 1024 * 4) throw Exception(format("failed to load icon %s for asset catalog", icon_png));
	const unsigned char* T = ios_appicon_template;
	auto be32 = [](const unsigned char* p){ return (uint32_t)p[0]<<24 | (uint32_t)p[1]<<16 | (uint32_t)p[2]<<8 | p[3]; };
	auto le32 = [](const unsigned char* p){ return (uint32_t)p[0] | (uint32_t)p[1]<<8 | (uint32_t)p[2]<<16 | (uint32_t)p[3]<<24; };
	uint32_t ver = be32(T+8), btrail = be32(T+12), indexOff = be32(T+16), varsOff = be32(T+24);
	// vars
	const unsigned char* vp = T + varsOff; uint32_t vc = be32(vp); vp += 4;
	vector<pair<string,uint32_t>> vars;
	for (uint32_t i = 0; i < vc; i++) { uint32_t idx = be32(vp); vp += 4; uint8_t ln = *vp++; vars.push_back({string((const char*)vp, ln), idx}); vp += ln; }
	// block table
	const unsigned char* ip = T + indexOff; uint32_t bc = be32(ip); ip += 4;
	vector<pair<uint32_t,uint32_t>> blocks(bc);
	for (uint32_t i = 0; i < bc; i++) { blocks[i] = {be32(ip), be32(ip+4)}; ip += 8; }
	// The two image renditions are the CSI ('ISTC') value blocks whose stored width is 1024.
	vector<int> img;
	for (uint32_t i = 0; i < bc; i++)
		if (blocks[i].second >= 304 && memcmp(T + blocks[i].first, "ISTC", 4) == 0 && le32(T + blocks[i].first + 12) == 1024) img.push_back(i);
	if (img.size() != 2) throw Exception("asset catalog template is malformed (expected 2 image renditions)");
	// LZFSE-compress the bitmap in the same 341-row chunks CoreUI uses.
	static const int rows[4] = {341, 341, 341, 1};
	string scratch; scratch.resize(lzfse_encode_scratch_size());
	string chunks[4]; size_t roff = 0; uint32_t sumcomp = 0;
	for (int i = 0; i < 4; i++) {
		size_t seglen = (size_t)rows[i] * 1024 * 4;
		string dst; dst.resize(seglen + 4096);
		size_t n = lzfse_encode_buffer((uint8_t*)&dst[0], dst.size(), (const uint8_t*)bgra.data() + roff*1024*4, seglen, (uint8_t*)&scratch[0]);
		if (n == 0) throw Exception("LZFSE encode failed while building asset catalog");
		dst.resize(n); chunks[i] = dst; roff += rows[i]; sumcomp += (uint32_t)n;
	}
	// Rebuild the image CSI: copy the template header, patch the one size field (offset 180 = 96 + sum
	// of compressed lengths), then append each chunk framed by its 20-byte KCBC header.
	const unsigned char* tc = T + blocks[img[0]].first;
	auto app_le = [](string& s, uint32_t v){ unsigned char b[4] = {(unsigned char)v, (unsigned char)(v>>8), (unsigned char)(v>>16), (unsigned char)(v>>24)}; s.append((char*)b, 4); };
	string new_csi;
	new_csi.append((const char*)tc, 180);
	app_le(new_csi, 96 + sumcomp);
	new_csi.append((const char*)tc + 184, 304 - 184);
	for (int i = 0; i < 4; i++) {
		new_csi.append("KCBC", 4); new_csi.append(8, '\0');
		app_le(new_csi, (uint32_t)rows[i]); app_le(new_csi, (uint32_t)chunks[i].size());
		new_csi += chunks[i];
	}
	for (int bi : img) blocks[bi].second = (uint32_t)new_csi.size();
	// Reassemble the file: keep the 512-byte header region, re-lay-out every non-empty block (4-byte
	// aligned, original address order), then write the vars and block index and patch the header.
	string out; out.append((const char*)T, 512);
	vector<pair<uint32_t,uint32_t>> newblk(bc, {0, 0});
	vector<int> order;
	for (uint32_t i = 0; i < bc; i++) if (blocks[i].second > 0) order.push_back(i);
	sort(order.begin(), order.end(), [&](int a, int b){ return blocks[a].first < blocks[b].first; });
	for (int idx : order) {
		while (out.size() % 16) out.push_back(0);
		uint32_t addr = (uint32_t)out.size();
		bool isimg = (idx == img[0] || idx == img[1]);
		if (isimg) out += new_csi;
		else out.append((const char*)T + blocks[idx].first, blocks[idx].second);
		newblk[idx] = {addr, isimg ? (uint32_t)new_csi.size() : blocks[idx].second};
	}
	auto app_be = [](string& s, uint32_t v){ unsigned char b[4] = {(unsigned char)(v>>24), (unsigned char)(v>>16), (unsigned char)(v>>8), (unsigned char)v}; s.append((char*)b, 4); };
	while (out.size() % 16) out.push_back(0);
	uint32_t vo2 = (uint32_t)out.size();
	app_be(out, (uint32_t)vars.size());
	for (auto& pr : vars) { app_be(out, pr.second); out.push_back((char)pr.first.size()); out += pr.first; }
	uint32_t vl = (uint32_t)out.size() - vo2;
	while (out.size() % 16) out.push_back(0);
	uint32_t io2 = (uint32_t)out.size();
	app_be(out, bc);
	for (auto& bl : newblk) { app_be(out, bl.first); app_be(out, bl.second); }
	out.append(20, '\0'); // empty BOM free list (count 0 + reserved), matching actool byte-for-byte
	uint32_t il = (uint32_t)out.size() - io2;
	auto put_be = [&](size_t off, uint32_t v){ out[off]=(char)(v>>24); out[off+1]=(char)(v>>16); out[off+2]=(char)(v>>8); out[off+3]=(char)v; };
	put_be(8, ver); put_be(12, btrail); put_be(16, io2); put_be(20, il); put_be(24, vo2); put_be(28, vl);
	return out;
}

// ===================== iOS code signing (byte-identical to Apple's codesign) =====================
// Reverse-engineered from a real codesign output. Every blob (CodeResources, Entitlements, DER
// entitlements, designated Requirements, CodeDirectory, and the CMS signature) is reproduced byte
// for byte; the CMS is deterministic because Apple RSA certs sign with PKCS#1 v1.5 (no random) and
// codesign includes only a signingTime attribute (which we control).
namespace ioscs {
static string sha256b(const string& d){ unsigned char h[32]; SHA256((const unsigned char*)d.data(), d.size(), h); return string((char*)h, 32); }
static string sha1b(const string& d){ unsigned char h[20]; SHA1((const unsigned char*)d.data(), d.size(), h); return string((char*)h, 20); }
static string b64(const string& d){ if (d.empty()) return ""; string out; out.resize(4*((d.size()+2)/3)+1); int n = EVP_EncodeBlock((unsigned char*)&out[0], (const unsigned char*)d.data(), (int)d.size()); out.resize(n); return out; }
static void be32(string& s, uint32_t v){ char b[4]={(char)(v>>24),(char)(v>>16),(char)(v>>8),(char)v}; s.append(b,4); }
static void le32(string& s, uint32_t v){ char b[4]={(char)v,(char)(v>>8),(char)(v>>16),(char)(v>>24)}; s.append(b,4); }
static void le64(string& s, uint64_t v){ for (int i=0;i<8;i++) s.push_back((char)(v>>(8*i))); }
// DER length + TLV
static string der_len(size_t n){ string s; if (n<0x80) s.push_back((char)n); else if (n<0x100){ s.push_back((char)0x81); s.push_back((char)n);} else if (n<0x10000){ s.push_back((char)0x82); s.push_back((char)(n>>8)); s.push_back((char)n);} else { s.push_back((char)0x83); s.push_back((char)(n>>16)); s.push_back((char)(n>>8)); s.push_back((char)n);} return s; }
static string der(unsigned char tag, const string& v){ return string(1,(char)tag)+der_len(v.size())+v; }
// CS requirement length-prefixed padded string
static string csstr(const string& s){ string out; be32(out,(uint32_t)s.size()); out+=s; while (out.size()%4) out.push_back(0); return out; }
static string xmlesc(const string& s){ string o; for(char c:s){ if(c=='&')o+="&amp;"; else if(c=='<')o+="&lt;"; else if(c=='>')o+="&gt;"; else o+=c; } return o; }
static const char* PLIST_HEADER="<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n";

// Read a whole file.
static string slurp(const string& p){ FileInputStream f(p); string d; StreamCopier::copyToString(f,d); return d; }

// Serialize an entitlements dict (sorted keys) exactly like Python plistlib (tabs, <true/>, arrays).
static string entitlements_xml(const vector<pair<string,plist_t>>& items){
	string x=PLIST_HEADER; x+="<dict>\n";
	// caller passes items already sorted by key
	for (auto& kv : items){
		x+="\t<key>"+xmlesc(kv.first)+"</key>\n";
		plist_t v=kv.second; plist_type t=plist_get_node_type(v);
		if (t==PLIST_STRING){ char* s=nullptr; plist_get_string_val(v,&s); x+="\t<string>"+xmlesc(s?s:"")+"</string>\n"; free(s); }
		else if (t==PLIST_BOOLEAN){ uint8_t b=0; plist_get_bool_val(v,&b); x+= b?"\t<true/>\n":"\t<false/>\n"; }
		else if (t==PLIST_ARRAY){ x+="\t<array>\n"; uint32_t n=plist_array_get_size(v); for(uint32_t i=0;i<n;i++){ char* s=nullptr; plist_get_string_val(plist_array_get_item(v,i),&s); x+="\t\t<string>"+xmlesc(s?s:"")+"</string>\n"; free(s);} x+="\t</array>\n"; }
	}
	x+="</dict>\n</plist>\n"; return x;
}
// Apple DER entitlements: [16]{ INTEGER 1, [16]{ SEQ{UTF8 key, value} ... } }
static string der_entitlements(const vector<pair<string,plist_t>>& items){
	string entries;
	for (auto& kv : items){
		string key=der(0x0c, kv.first);
		plist_t v=kv.second; plist_type t=plist_get_node_type(v); string val;
		if (t==PLIST_STRING){ char* s=nullptr; plist_get_string_val(v,&s); val=der(0x0c, string(s?s:"")); free(s);}
		else if (t==PLIST_BOOLEAN){ uint8_t b=0; plist_get_bool_val(v,&b); val=der(0x01, string(1,(char)(b?0xff:0x00))); }
		else if (t==PLIST_ARRAY){ string inner; uint32_t n=plist_array_get_size(v); for(uint32_t i=0;i<n;i++){ char* s=nullptr; plist_get_string_val(plist_array_get_item(v,i),&s); inner+=der(0x0c,string(s?s:"")); free(s);} val=der(0x30, inner); }
		entries+=der(0x30, key+val);
	}
	string ver=der(0x02, string(1,(char)1));
	return der(0x70, ver + der(0xb0, entries));
}
// Designated requirement blob for (bundle id, leaf common name).
static string requirements(const string& bundleid, const string& cn){
	auto opIdent=[&](const string& s){ string o; be32(o,2); o+=csstr(s); return o; };
	auto opAppleGeneric=[&](){ string o; be32(o,15); return o; };
	auto opAnd=[&](const string& a, const string& b){ string o; be32(o,6); o+=a; o+=b; return o; };
	auto opCertField=[&](uint32_t idx,const string& field,uint32_t m,const string& val){ string o; be32(o,11); be32(o,idx); o+=csstr(field); be32(o,m); o+=csstr(val); return o; };
	static const unsigned char oidb[]={0x2a,0x86,0x48,0x86,0xf7,0x63,0x64,0x06,0x02,0x01};
	auto opCertGeneric=[&](uint32_t idx,uint32_t m){ string o; be32(o,14); be32(o,idx); o+=csstr(string((const char*)oidb,sizeof(oidb))); be32(o,m); return o; };
	string expr=opAnd(opIdent(bundleid), opAnd(opAppleGeneric(), opAnd(opCertField(0,"subject.CN",1,cn), opCertGeneric(1,0))));
	string reqblob; reqblob.append("\xfa\xde\x0c\x00",4); be32(reqblob,(uint32_t)(12+expr.size())); be32(reqblob,1); reqblob+=expr;
	string inner; be32(inner,1); be32(inner,3); be32(inner,20); inner+=reqblob;
	string sup; sup.append("\xfa\xde\x0c\x01",4); be32(sup,(uint32_t)(8+inner.size())); sup+=inner;
	return sup;
}
// CodeResources plist. `files` maps each bundle resource to its base64 SHA-1; `files2` maps each
// (except Info.plist) to its base64 SHA-256 under hash2. The rules/rules2 are codesign's fixed
// defaults, reproduced verbatim. `entries` is the sorted list of (name, file bytes).
static string code_resources(const vector<pair<string,string>>& entries){
	string x=PLIST_HEADER; x+="<dict>\n";
	x+="\t<key>files</key>\n\t<dict>\n";
	for (auto& e : entries){ x+="\t\t<key>"+e.first+"</key>\n\t\t<data>\n\t\t"+b64(sha1b(e.second))+"\n\t\t</data>\n"; }
	x+="\t</dict>\n\t<key>files2</key>\n\t<dict>\n";
	for (auto& e : entries){ if (e.first=="Info.plist") continue; x+="\t\t<key>"+e.first+"</key>\n\t\t<dict>\n\t\t\t<key>hash2</key>\n\t\t\t<data>\n\t\t\t"+b64(sha256b(e.second))+"\n\t\t\t</data>\n\t\t</dict>\n"; }
	x+="\t</dict>\n";
	x+="\t<key>rules</key>\n\t<dict>\n\t\t<key>^.*</key>\n\t\t<true/>\n\t\t<key>^.*\\.lproj/</key>\n\t\t<dict>\n\t\t\t<key>optional</key>\n\t\t\t<true/>\n\t\t\t<key>weight</key>\n\t\t\t<real>1000</real>\n\t\t</dict>\n\t\t<key>^.*\\.lproj/locversion.plist$</key>\n\t\t<dict>\n\t\t\t<key>omit</key>\n\t\t\t<true/>\n\t\t\t<key>weight</key>\n\t\t\t<real>1100</real>\n\t\t</dict>\n\t\t<key>^Base\\.lproj/</key>\n\t\t<dict>\n\t\t\t<key>weight</key>\n\t\t\t<real>1010</real>\n\t\t</dict>\n\t\t<key>^version.plist$</key>\n\t\t<true/>\n\t</dict>\n";
	x+="\t<key>rules2</key>\n\t<dict>\n\t\t<key>.*\\.dSYM($|/)</key>\n\t\t<dict>\n\t\t\t<key>weight</key>\n\t\t\t<real>11</real>\n\t\t</dict>\n\t\t<key>^(.*/)?\\.DS_Store$</key>\n\t\t<dict>\n\t\t\t<key>omit</key>\n\t\t\t<true/>\n\t\t\t<key>weight</key>\n\t\t\t<real>2000</real>\n\t\t</dict>\n\t\t<key>^.*</key>\n\t\t<true/>\n\t\t<key>^.*\\.lproj/</key>\n\t\t<dict>\n\t\t\t<key>optional</key>\n\t\t\t<true/>\n\t\t\t<key>weight</key>\n\t\t\t<real>1000</real>\n\t\t</dict>\n\t\t<key>^.*\\.lproj/locversion.plist$</key>\n\t\t<dict>\n\t\t\t<key>omit</key>\n\t\t\t<true/>\n\t\t\t<key>weight</key>\n\t\t\t<real>1100</real>\n\t\t</dict>\n\t\t<key>^Base\\.lproj/</key>\n\t\t<dict>\n\t\t\t<key>weight</key>\n\t\t\t<real>1010</real>\n\t\t</dict>\n\t\t<key>^Info\\.plist$</key>\n\t\t<dict>\n\t\t\t<key>omit</key>\n\t\t\t<true/>\n\t\t\t<key>weight</key>\n\t\t\t<real>20</real>\n\t\t</dict>\n\t\t<key>^PkgInfo$</key>\n\t\t<dict>\n\t\t\t<key>omit</key>\n\t\t\t<true/>\n\t\t\t<key>weight</key>\n\t\t\t<real>20</real>\n\t\t</dict>\n\t\t<key>^embedded\\.provisionprofile$</key>\n\t\t<dict>\n\t\t\t<key>weight</key>\n\t\t\t<real>20</real>\n\t\t</dict>\n\t\t<key>^version\\.plist$</key>\n\t\t<dict>\n\t\t\t<key>weight</key>\n\t\t\t<real>20</real>\n\t\t</dict>\n\t</dict>\n";
	x+="</dict>\n</plist>\n"; return x;
}
// Build the CodeDirectory blob. `tbs` is the to-be-signed Mach-O image (0..codeLimit, with the
// LC_CODE_SIGNATURE load command already present). specials are slot hashes -1..-7 (empty => zero).
static string code_directory(const string& tbs, const string& identifier, const string& team,
		uint64_t execBase, uint64_t execLim, uint64_t execFlags,
		const string& infoHash, const string& reqHash, const string& resHash, const string& entHash, const string& derHash){
	const uint32_t codeLimit=(uint32_t)tbs.size(); const uint32_t PS=16384;
	uint32_t nCode=(codeLimit+PS-1)/PS; const uint32_t nSpecial=7;
	string identb=identifier; identb.push_back(0); string teamb=team; teamb.push_back(0);
	uint32_t identOff=88; uint32_t teamOff=identOff+(uint32_t)identb.size();
	uint32_t hashOff=teamOff+(uint32_t)teamb.size()+nSpecial*32;
	uint32_t length=hashOff+nCode*32;
	string cd; cd.append("\xfa\xde\x0c\x02",4); be32(cd,length); be32(cd,0x20400); be32(cd,0);
	be32(cd,hashOff); be32(cd,identOff); be32(cd,nSpecial); be32(cd,nCode); be32(cd,codeLimit);
	cd.push_back(32); cd.push_back(2); cd.push_back(0); cd.push_back(14); // hashSize, hashType, platform, pageSize(log2)
	be32(cd,0); be32(cd,0); be32(cd,teamOff); be32(cd,0); // spare2, scatterOffset, teamOffset, spare3
	auto be64=[&](uint64_t v){ for(int i=7;i>=0;i--) cd.push_back((char)(v>>(8*i))); };
	be64(0);                       // codeLimit64 (8 bytes, 0 for a 32-bit codeLimit)
	be64(execBase); be64(execLim); be64(execFlags); // execSegBase/Limit/Flags (version 0x20400)
	cd+=identb; cd+=teamb;
	string Z(32,'\0');
	// special slots order in file is -7..-1: DER, (unused), Entitlements, (unused app), CodeResources, Requirements, Info.plist
	cd+= (derHash.empty()?Z:derHash); cd+=Z; cd+=(entHash.empty()?Z:entHash); cd+=Z; cd+=(resHash.empty()?Z:resHash); cd+=(reqHash.empty()?Z:reqHash); cd+=(infoHash.empty()?Z:infoHash);
	for (uint32_t i=0;i<nCode;i++){ uint32_t s=i*PS, e=s+PS; if (e>codeLimit) e=codeLimit; cd+=sha256b(tbs.substr(s,e-s)); }
	return cd;
}
static string oid(std::initializer_list<int> parts){ // DER OID content bytes (no tag/len)
	string s; auto it=parts.begin(); int first=*it++, second=*it++; s.push_back((char)(first*40+second));
	while (it!=parts.end()){ unsigned v=*it++; unsigned char buf[5]; int n=0; buf[n++]=v&0x7f; v>>=7; while(v){ buf[n++]=(v&0x7f)|0x80; v>>=7; } for(int i=n-1;i>=0;i--) s.push_back((char)buf[i]); }
	return s;
}
// Build the CMS SignedData (byte-identical to codesign) over the CodeDirectory.
static string cms_sign(const string& cd, EVP_PKEY* pkey, const string& leafDer, const string& issuerDer, const string& serialDer, uint64_t signtime){
	string cdsha=sha256b(cd);
	auto SEQ=[&](const string& v){ return der(0x30,v); };
	auto SET=[&](const string& v){ return der(0x31,v); };
	auto OIDT=[&](const string& o){ return der(0x06,o); };
	string oid_ct=oid({1,2,840,113549,1,9,3}), oid_data=oid({1,2,840,113549,1,7,1});
	string oid_st=oid({1,2,840,113549,1,9,5}), oid_md=oid({1,2,840,113549,1,9,4});
	string oid_91=oid({1,2,840,113635,100,9,1}), oid_92=oid({1,2,840,113635,100,9,2});
	string oid_sha256=oid({2,16,840,1,101,3,4,2,1}), oid_rsa=oid({1,2,840,113549,1,1,11});
	string oid_sd=oid({1,2,840,113549,1,7,2});
	// UTCTime YYMMDDHHMMSSZ
	time_t t=(time_t)signtime; struct tm g;
#ifdef _WIN32
	gmtime_s(&g,&t);
#else
	gmtime_r(&t,&g);
#endif
	char tb[16]; snprintf(tb,sizeof(tb),"%02d%02d%02d%02d%02d%02dZ", g.tm_year%100, g.tm_mon+1, g.tm_mday, g.tm_hour, g.tm_min, g.tm_sec);
	string utctime=der(0x17, string(tb));
	// attributes
	string aCT = SEQ(OIDT(oid_ct)+SET(OIDT(oid_data)));
	string aST = SEQ(OIDT(oid_st)+SET(utctime));
	string aMD = SEQ(OIDT(oid_md)+SET(der(0x04,cdsha)));
	string a92 = SEQ(OIDT(oid_92)+SET(SEQ(OIDT(oid_sha256)+der(0x04,cdsha))));
	string p91=PLIST_HEADER; p91+="<dict>\n\t<key>cdhashes</key>\n\t<array>\n\t\t<data>\n\t\t"+b64(cdsha.substr(0,20))+"\n\t\t</data>\n\t</array>\n</dict>\n</plist>\n";
	string a91 = SEQ(OIDT(oid_91)+SET(der(0x04,p91)));
	string attrs = aCT+aST+aMD+a92+a91;
	string signedAttrsForSig = der(0x31, attrs); // SET tag for signing
	// RSA sign
	string sig; sig.resize(EVP_PKEY_size(pkey)); size_t siglen=sig.size();
	EVP_MD_CTX* mc=EVP_MD_CTX_new();
	EVP_DigestSignInit(mc,nullptr,EVP_sha256(),nullptr,pkey);
	EVP_DigestSign(mc,(unsigned char*)&sig[0],&siglen,(const unsigned char*)signedAttrsForSig.data(),signedAttrsForSig.size());
	EVP_MD_CTX_free(mc); sig.resize(siglen);
	// SignerInfo (definite DER)
	string digalg=SEQ(OIDT(oid_sha256)+der(0x05,""));
	string sigalg=SEQ(OIDT(oid_rsa)+der(0x05,""));
	string sid=SEQ(issuerDer+serialDer);
	string signedAttrsImplicit = der(0xa0, attrs); // [0] IMPLICIT for the SignerInfo
	string si=SEQ(der(0x02,string(1,(char)1))+sid+digalg+signedAttrsImplicit+sigalg+der(0x04,sig));
	string sinfos=SET(si);
	string dalgs=SET(digalg);
	string certs=der(0xa0, string(ios_cert_wwdr,ios_cert_wwdr+ios_cert_wwdr_len)+string(ios_cert_root,ios_cert_root+ios_cert_root_len)+leafDer);
	// BER indefinite wrapping for the 4 outer nodes
	auto indef=[&](const string& inner){ return string("\x30\x80",2)+inner+string("\x00\x00",2); };
	string eci=string("\x30\x80",2)+OIDT(oid_data)+string("\x00\x00",2);
	string sdcontent=indef(der(0x02,string(1,(char)1))+dalgs+eci+certs+sinfos);
	string content=string("\xa0\x80",2)+sdcontent+string("\x00\x00",2);
	return indef(OIDT(oid_sd)+content);
}
// Sign a built .app directory in place (modifies the Mach-O, writes _CodeSignature/CodeResources and
// embedded.mobileprovision), producing output byte-identical to Apple's codesign.
static void sign_app(const string& app_dir, const string& exe_name, const string& bundle_id,
		const string& p12_data, const string& password, const string& provision_data, uint64_t signtime){
	using ioscs::be32; using ioscs::sha256b; using ioscs::slurp;
	// --- load .p12 (works with the developer's original file via OpenSSL) ---
	BIO* bio=BIO_new_mem_buf(p12_data.data(),(int)p12_data.size());
	PKCS12* p12=d2i_PKCS12_bio(bio,nullptr); BIO_free(bio);
	if(!p12) throw Exception("could not read signing .p12");
	EVP_PKEY* pkey=nullptr; X509* leaf=nullptr; STACK_OF(X509)* ca=nullptr;
	if(!PKCS12_parse(p12,password.c_str(),&pkey,&leaf,&ca)) throw Exception("could not decrypt .p12 (wrong password?)");
	unsigned char* dp=nullptr; int dl=i2d_X509(leaf,&dp); string leafDer((char*)dp,dl); OPENSSL_free(dp);
	dp=nullptr; dl=i2d_X509_NAME(X509_get_issuer_name(leaf),&dp); string issuerDer((char*)dp,dl); OPENSSL_free(dp);
	dp=nullptr; dl=i2d_ASN1_INTEGER(X509_get_serialNumber(leaf),&dp); string serialDer((char*)dp,dl); OPENSSL_free(dp);
	char cn[256]={0}; X509_NAME_get_text_by_NID(X509_get_subject_name(leaf),NID_commonName,cn,sizeof(cn));
	// --- entitlements from the provisioning profile ---
	size_t xs=provision_data.find("<?xml"), xe=provision_data.find("</plist>");
	if(xs==string::npos||xe==string::npos) throw Exception("invalid provisioning profile");
	string pplist=provision_data.substr(xs,xe-xs+8);
	plist_t prov=nullptr; plist_from_xml(pplist.data(),(uint32_t)pplist.size(),&prov);
	plist_t entd=plist_dict_get_item(prov,"Entitlements");
	vector<pair<string,plist_t>> items;
	{ plist_dict_iter di=nullptr; plist_dict_new_iter(entd,&di); for(;;){ char* k=nullptr; plist_t v=nullptr; plist_dict_next_item(entd,di,&k,&v); if(!v){ if(k) free(k); break;} items.push_back({string(k),v}); free(k);} free(di); }
	sort(items.begin(),items.end(),[](const pair<string,plist_t>&a,const pair<string,plist_t>&b){return a.first<b.first;});
	string team;
	for(auto& kv: items){ if(kv.first=="com.apple.developer.team-identifier"){ char* s=nullptr; plist_get_string_val(kv.second,&s); if(s){ team=s; free(s);} } }
	// --- blobs that don't depend on the Mach-O ---
	string entxml=ioscs::entitlements_xml(items);
	string entBlob; entBlob.append("\xfa\xde\x71\x71",4); be32(entBlob,(uint32_t)(8+entxml.size())); entBlob+=entxml;
	string derent=ioscs::der_entitlements(items);
	string derBlob; derBlob.append("\xfa\xde\x71\x72",4); be32(derBlob,(uint32_t)(8+derent.size())); derBlob+=derent;
	string reqBlob=ioscs::requirements(bundle_id,string(cn));
	// --- write embedded.mobileprovision + build CodeResources over the bundle files ---
	FileOutputStream(app_dir+"/embedded.mobileprovision").write(provision_data.data(),provision_data.size());
	vector<pair<string,string>> entries; // (name, bytes) sorted, excluding the executable and _CodeSignature
	{ vector<File> fl; File(app_dir).list(fl); vector<string> names;
	  for(const File& f: fl){ string n=Path(f.path()).makeFile().getFileName(); if(f.isDirectory()||n==exe_name||n=="_CodeSignature") continue; names.push_back(n);} sort(names.begin(),names.end());
	  for(const string& n: names) entries.push_back({n, slurp(app_dir+"/"+n)}); }
	string cr=ioscs::code_resources(entries);
	File(app_dir+"/_CodeSignature").createDirectories();
	FileOutputStream(app_dir+"/_CodeSignature/CodeResources").write(cr.data(),cr.size());
	// --- parse the Mach-O, build the to-be-signed image (insert LC_CODE_SIGNATURE) ---
	string exe=slurp(app_dir+"/"+exe_name);
	auto rd32=[&](const string& b,size_t o){ return (uint32_t)(unsigned char)b[o]|((uint32_t)(unsigned char)b[o+1]<<8)|((uint32_t)(unsigned char)b[o+2]<<16)|((uint32_t)(unsigned char)b[o+3]<<24); };
	auto rd64=[&](const string& b,size_t o){ uint64_t v=0; for(int i=7;i>=0;i--) v=(v<<8)|(unsigned char)b[o+i]; return v; };
	uint32_t ncmds=rd32(exe,16), szcmds=rd32(exe,20);
	uint64_t execBase=0,execLim=0,execFlags=0; size_t linkeditCmd=0; uint64_t leFileSize=0;
	{ size_t o=32; for(uint32_t i=0;i<ncmds;i++){ uint32_t cmd=rd32(exe,o),cs=rd32(exe,o+8-8+4); cs=rd32(exe,o+4);
		string seg=exe.substr(o+8,16); size_t z=seg.find('\0'); if(z!=string::npos) seg=seg.substr(0,z);
		if(cmd==0x19 && seg=="__TEXT"){ execBase=rd64(exe,o+40); execLim=rd64(exe,o+48); execFlags=1; } // fileoff, filesize
		if(cmd==0x19 && seg=="__LINKEDIT"){ linkeditCmd=o; leFileSize=rd64(exe,o+48); }
		o+=cs; } }
	uint32_t codeLimit=(uint32_t)exe.size();
	string infoplist=slurp(app_dir+"/Info.plist");
	uint32_t supsize=0;
	auto build_signed=[&](uint32_t datasize)->string{
		string tbs(exe); // to-be-signed with LC_CODE_SIGNATURE inserted
		auto wr32=[&](string& b,size_t o,uint32_t v){ b[o]=(char)v;b[o+1]=(char)(v>>8);b[o+2]=(char)(v>>16);b[o+3]=(char)(v>>24); };
		auto wr64=[&](string& b,size_t o,uint64_t v){ for(int i=0;i<8;i++) b[o+i]=(char)(v>>(8*i)); };
		wr32(tbs,16,ncmds+1); wr32(tbs,20,szcmds+16);
		uint64_t newfs=leFileSize+datasize, newvs=((newfs+16383)/16384)*16384;
		wr64(tbs,linkeditCmd+32,newvs); wr64(tbs,linkeditCmd+48,newfs);
		size_t lc=32+szcmds; wr32(tbs,lc,0x1d); wr32(tbs,lc+4,16); wr32(tbs,lc+8,codeLimit); wr32(tbs,lc+12,datasize);
		string tbsimg=tbs.substr(0,codeLimit);
		string cd=ioscs::code_directory(tbsimg,bundle_id,team,execBase,execLim,execFlags,
			sha256b(infoplist),sha256b(reqBlob),sha256b(cr),sha256b(entBlob),sha256b(derBlob));
		string cmsb=ioscs::cms_sign(cd,pkey,leafDer,issuerDer,serialDer,signtime);
		string cmsBlob; cmsBlob.append("\xfa\xde\x0b\x01",4); be32(cmsBlob,(uint32_t)(8+cmsb.size())); cmsBlob+=cmsb;
		vector<pair<uint32_t,string>> blobs={{0,cd},{2,reqBlob},{5,entBlob},{7,derBlob},{0x10000,cmsBlob}};
		uint32_t idxsz=12+(uint32_t)blobs.size()*8, cur=idxsz; string body; vector<pair<uint32_t,uint32_t>> idx;
		for(auto&b:blobs){ idx.push_back({b.first,cur}); body+=b.second; cur+=(uint32_t)b.second.size(); }
		string sup; sup.append("\xfa\xde\x0c\xc0",4); be32(sup,idxsz+(uint32_t)body.size()); be32(sup,(uint32_t)blobs.size());
		for(auto&e:idx){ be32(sup,e.first); be32(sup,e.second);} sup+=body;
		supsize=(uint32_t)sup.size();
		if(sup.size()<datasize) sup.append(datasize-sup.size(),'\0');
		return tbsimg+sup;
	};
	// codesign reserves the superblob size plus a fixed 13242-byte slot (space for an optional RFC3161
	// timestamp it does not add), leaving that many trailing zero bytes. Measure the superblob (its size
	// is independent of the datasize value), then reserve that plus the slot.
	build_signed(0);
	string signed_exe=build_signed(supsize+13242);
	FileOutputStream(app_dir+"/"+exe_name).write(signed_exe.data(),signed_exe.size());
	if(ca) sk_X509_pop_free(ca,X509_free); if(leaf) X509_free(leaf); if(pkey) EVP_PKEY_free(pkey); PKCS12_free(p12);
}
} // namespace ioscs
// Thread-safe message box for use from the compilation worker thread. Dispatches message_box() onto the main thread via SDL_RunOnMainThread and blocks until the result is available. Returns -1 without showing anything for multi-button dialogs when quiet mode is active or a console is available, since the user cannot answer interactive questions in those conditions. Single-button alerts in console mode are printed to stdout.
struct bundler_msgbox_args { const string& title; const string& text; const vector<string>& buttons; int result; };
static void bundler_msgbox_callback(void* userdata) {
	bundler_msgbox_args* a = static_cast<bundler_msgbox_args*>(userdata);
	a->result = message_box(a->title, a->text, a->buttons);
}
int nvgt_compile_message_box(const string& title, const string& text, const vector<string>& buttons) {
	auto& config = Util::Application::instance().config();
	bool quiet = config.hasOption("application.quiet") || config.hasOption("application.QUIET");
	bool console = is_console_available();
	if (buttons.size() > 1 && (quiet || console)) return -1;
	if (quiet) return -1;
	if (console) { printf("%s: %s\n", title.c_str(), text.c_str()); return 1; }
	bundler_msgbox_args args{title, text, buttons, -1};
	SDL_RunOnMainThread(bundler_msgbox_callback, &args, true);
	return args.result;
}

// Build the set of archive paths that should receive executable permissions.
// main_exec: archive path of the primary executable. asset_prefix: prefix prepended to each binary asset's bundled_path.
static set<string> build_exec_paths(const string& main_exec, const string& asset_prefix) {
	set<string> paths;
	if (!main_exec.empty()) paths.insert(main_exec);
	for (const game_asset& g : g_game_assets)
		if (g.flags & GAME_ASSET_BINARY) paths.insert(asset_prefix.empty() ? g.bundled_path : asset_prefix + "/" + g.bundled_path);
	return paths;
}

class nvgt_compilation_output_impl : public virtual nvgt_compilation_output {
	string platform, stub, input_file, output_file;
	string stub_location, error_text, status_text;
	UInt64 stub_size;
	Path outpath;
	Mutex status_text_mtx;
	void error(const exception& exc, const std::string& error) {
		error_text = error;
		throw;
	}
public:
	nvgt_compilation_output_impl(const string& input_file) : input_file(input_file), platform(g_platform), stub(g_stub), stub_size(0), config(Util::Application::instance().config()) {}
	const string& get_error_text() {
		return error_text;
	}
	const string& get_input_file() {
		return input_file;
	}
	const string& get_output_file() {
		return output_file;
	}
	void set_status(const std::string& message) {
		{
			Mutex::ScopedLock l(status_text_mtx);
			status_text = message;
		}
	}
	std::string get_status() {
		string result;
		{
			Mutex::ScopedLock l(status_text_mtx);
			result = status_text;
			status_text = "";
		}
		return result;
	}
	void prepare() {
		set_status("initializing...");
		stub = g_stub; // We must do this now because script should be compiled at this point and thus stub selected from pragma should be stored in g_stub.
		string app_dir = config.getString("application.dir", "");
		if (app_dir.empty()) app_dir = Path(Util::Application::instance().commandPath()).makeParent().toString();
		Path stubpath = app_dir;
		stubpath.pushDirectory("stub");
		xplatform_correct_path_to_stubs(stubpath);
		alter_stub_path(stubpath);
		stubpath = format("%snvgt_%s%s%s.bin", stubpath.toString(), platform, (stub != "" ? string("_") + stub : ""), (g_script_uses_iap ? string("_iap") : string("")));
		string outpath_str = config.getString("build.output_basename", format("%s", Path(input_file).setExtension("").makeAbsolute().toString()));
		replaceInPlace(outpath_str, "$platform"s, platform);
		outpath_str = Path(outpath_str).makeAbsolute().toString();
		if (DirectoryExists(outpath_str)) File(outpath_str).remove(true);
		outpath = outpath_str;
		File(outpath.parent()).createDirectories();
		alter_output_path(outpath);
		string precommand = config.getString("build.precommand_" + g_platform + "_"s + (g_debug? "debug" : "release"), config.getString("build.precommand_" + g_platform, config.getString("build.precommand", "")));
		if (!precommand.empty()) {
			set_status("executing prebuild command...");
			if (!user_command(precommand)) throw Exception("prebuild command failed");
		}
		set_status("copying stub...");
		try {
			copy_stub(stubpath, outpath);
		} catch(exception& e) { error(e, format("failed to copy %s to %s", stubpath.toString(), outpath.toString())); }
		open_output_stream(outpath);
		output_file = outpath.toString();
		fs.seekp(0, std::ios::end);
	}
	void write_payload(const unsigned char* payload, unsigned int size) {
		if (!fs.good()) error(Exception("stream is not ready"), "error writing payload");
		set_status("writing payload...");
		BinaryWriter bw(fs);
		write_embedded_packs(bw);
		bw.write7BitEncoded(size ^ NVGT_BYTECODE_NUMBER_XOR);
		bw.writeRaw((const char*)payload, size);
	}
	void finalize() {
		if (!fs.good()) return; // This shouldn't be called in this condition!
		set_status("finalizing product...");
		finalize_output_stream();
		fs.close();
		string prepack_command = config.getString("build.prepack_command_" + g_platform + "_"s + (g_debug? "debug" : "release"), config.getString("build.prepack_command_" + g_platform, config.getString("build.prepack_command", "")));
		if (!prepack_command.empty()) {
			set_status("executing prepackage command...");
			if (!user_command(prepack_command)) throw Exception("prepackage command failed");
		}
		finalize_product(outpath);
		output_file = outpath.toString();
		string postcommand = config.getString("build.postcommand_" + g_platform + "_"s + (g_debug? "debug" : "release"), config.getString("build.postcommand_" + g_platform, config.getString("build.postcommand", "")));
		if (!postcommand.empty()) {
			set_status("executing postbuild command...");
			if (!user_command(postcommand)) throw Exception("postbuild command failed");
		}
		if (!config.hasOption("application.quiet") && !config.hasOption("application.QUIET") && !config.hasOption("build.no_success_message"))
			nvgt_compile_message_box("Success!", format("%s build succeeded in %?ums, saved to %s", string(g_debug ? "Debug" : "Release"), Util::Application::instance().uptime().totalMilliseconds(), output_file), {"`OK"});
	}
protected:
	FileStream fs;
	Util::LayeredConfiguration& config;
	// Returns the absolute path to the icon requested via `#pragma icon` (build.icon), resolved
	// relative to the script being compiled like the asset/embed pragmas, or an empty string if no
	// custom icon was requested. Throws if a path was given but the file does not exist.
	string get_custom_icon_path() {
		string icon_cfg = config.getString("build.icon", "");
		if (icon_cfg.empty()) return "";
		Path p = Path(icon_cfg).makeAbsolute(Path(get_input_file()).makeParent());
		// Every target's icon container (Windows RT_ICON, Apple .icns, iOS/Android/Linux) expects PNG
		// data, and we have no image transcoder, so reject anything that isn't a .png up front. This
		// fails fast on all platforms with one clear message instead of an obscure per-platform error.
		string ext = Poco::toLower(p.getExtension());
		if (ext != "png") throw Exception(format("custom icon must be a PNG file, but '%s' has extension '%s'", p.toString(), ext.empty()? "(none)" : ext));
		if (!File(p).exists()) throw Exception(format("custom icon file %s does not exist", p.toString()));
		return p.toString();
	}
	string make_product_id() {
		// If the user does not specify a product ID such as com.developer.mygame for platforms that require such a thing, we'll generate one using the script basename.
		string output;
		string bn = Path(get_input_file()).getBaseName();
		for (char i : bn) {
			if (i == '-' || i == '_') continue;
			if (i >= 'A' && i <= 'Z' || i >= 'a' && i <= 'z' || i >= '0' && i <= '9') output += i;
			else output += (output.empty()? "g" : format("%d", int(i)));
		}
		return format("%s.%s", config.getString("build.product_identifier_domain", "com.NVGTUser"), output);
	}
	void bundle_assets(const Path& resource_path, const Path& document_path) {
		set_status("bundling assets...");
		for (const game_asset& g : g_game_assets) {
			Path p = Path(g.bundled_path).makeAbsolute(g.flags & GAME_ASSET_DOCUMENT? document_path : resource_path);
			if (File(p).exists()) File(p).remove(true);
			if (!File(p.parent()).exists()) File(p.parent()).createDirectories();
			File(Path(g.filesystem_path).makeAbsolute(Path(get_input_file()).makeParent()).toString()).copyTo(p.toString());
		}
	}
	void copy_shared_libraries(const Path& libpath) {
		// Copy any needed shared libraries to the output package, handling excludes and already existent files.
		set_status("copying libraries...");
		File libpathF(libpath);
		// Determine whether to create, replace, or update shared libraries.
		if (!libpathF.exists()) libpathF.createDirectories();
		else if(config.hasOption("build.shared_library_recopy")) libpathF.remove(true);
		string source = get_nvgt_lib_directory(g_platform);
		set<string> libs;
		Glob::glob(Path(source).append("*").toString(), libs, Glob::GLOB_DOT_SPECIAL | Glob::GLOB_FOLLOW_SYMLINKS | Glob::GLOB_CASELESS);
		for (const string& library : libs) {
			// First check if we wish to include this library.
			bool included = false;
			for (const string& l : g_bundle_libraries) {
				if (Path(library).getBaseName().find(l) == string::npos) continue;
				included = true;
				break;
			}
			if (!included) continue;
			// Now check if the same or a newer version of this library has already been copied and skip it if so, in order to save time.
			File lib = library;
			File destF = Path(libpath).append(Path(library).getFileName()).toString();
			if (destF.exists() && destF.getLastModified() >= lib.getLastModified()) continue;
			lib.copyTo(libpath.toString());
		}
	}
	virtual void alter_stub_path(Path& stubpath) {
		// This method can be overwritten by subclasses to modify the location that stubs are selected from. Throw an exception to abort the compilation.
	}
	virtual void alter_output_path(Path& output_path) {
		// This method can be overwritten by subclasses to change the output location of the final binary containing the byte code. The overwritten method is typically responsible for creating any directories needed unless copy_stub is also overridden in which case it's up to the subclass. Throw an exception to abort the compilation.
	}
	virtual void copy_stub(const Path& stubpath, const Path& outpath) {
		// This base method assumes that the stub is a direct executable for the target platform and should be overridden  whenever this is not the case.
		File(stubpath).copyTo(outpath.toString());
		File(outpath).setExecutable();
	}
	virtual void open_output_stream(const Path& output_path) {
		// This base method just opens the copied stub binary for output and seeks to the location at which bytecode and other information should be written, also setting the stub_size variable. It is the last step of the preparation process prior to NVGT writing it's compiled platform-agnostic game payload. Derived methods will usually call this and then perform any per-platform modifications needed on the copied stub that was just opened.
		fs.open(outpath.toString(), std::ios::in | std::ios::out | std::ios::ate);
		stub_size = fs.size();
	}
	virtual void finalize_output_stream() {
		// This method is called from the public finalize method prior to closing the output stream, the default implementation just writes the stub size to it's current position after bytecode has been written. Subclasses implementing platforms where this is not the case should override this method.
		BinaryWriter(fs) << int(stub_size);
	}
	virtual void finalize_product(Path& outpath) {
		// Subclasses can override this method as a final hook into the bundling process after bytecode has been written to the stub but before build success is reported to the user. If any final packaging steps performed here modify the final output path, update the outpath parameter accordingly so that the correct path of the final product package will be shown to the user.
	}
};
class nvgt_compilation_output_windows : public nvgt_compilation_output_impl {
	SharedPtr<File> workplace_tmp;
	File workplace;
	Path final_output_path;
	int bundle_mode;
	using nvgt_compilation_output_impl::nvgt_compilation_output_impl;
protected:
	void alter_output_path(Path& output_path) override {
		bundle_mode = config.getInt("build.windows_bundle", 2); // 0 no bundle, 1 folder, 2 .zip, 3 both folder and .zip.
		if (bundle_mode == 2) {
			workplace_tmp = new TemporaryFile();
			workplace = *workplace_tmp;
		} else if(bundle_mode > 0) workplace = Path(output_path).makeFile().setExtension("");
		else output_path.setExtension("exe");
		if (bundle_mode) {
			workplace.createDirectories();
			Path tmp = Path(workplace.path()).append(output_path.getBaseName()).makeFile().setExtension("exe");
			final_output_path = output_path;
			output_path = tmp;
		}
	}
	void open_output_stream(const Path& output_path) override {
		nvgt_compilation_output_impl::open_output_stream(output_path);
		BinaryReader br(fs);
		BinaryWriter bw(fs);
		// NVGT distributes windows stubs with the first 2 bytes of the PE header modified so that they are not recognised as executables, this avoids an extra AV scan when the stub is copied which may add a few hundred ms to compile times. Fix them now in the copied file.
		fs.seekp(0);
		bw.writeRaw("MZ");
		if (config.hasOption("build.windows_console")) { // The user wants to compile their app without /subsystem:windows
			int subsystem_offset;
			fs.seekg(60); // position of new PE header address.
			br >> subsystem_offset;
			subsystem_offset += 92; // offset in new PE header containing subsystem word. 2 for GUI, 3 for console.
			fs.seekp(subsystem_offset);
			bw << UInt16(3);
		}
	}
	void finalize_output_stream() override {} // Don't write payload offset on this platform.
	// Embed a custom launcher icon (via #pragma icon) into the compiled .exe's PE resource table.
	// Windows stores icons as an RT_GROUP_ICON directory plus one RT_ICON per image; Explorer shows
	// the group with the lowest resource id, so overwriting id 1 makes our icon win. Vista+ accepts
	// PNG data directly as an RT_ICON, so no bitmap conversion is needed. Rewriting PE resources
	// portably is impractical, so this uses the Win32 UpdateResource API and therefore only takes
	// effect when the Windows build is produced on Windows (much like Android needs the Android SDK).
	void apply_windows_icon(const string& exe_path) {
		string icon = get_custom_icon_path();
		if (icon.empty()) return;
		set_status("applying custom app icon...");
#ifdef _WIN32
		uint32_t iw = 0, ih = 0;
		if (!read_png_size(icon, iw, ih)) throw Exception(format("custom icon %s is not a valid PNG", icon));
		string png = read_file_bytes(icon);
		#pragma pack(push, 1)
		struct GRPICONDIRENTRY { BYTE bWidth, bHeight, bColorCount, bReserved; WORD wPlanes, wBitCount; DWORD dwBytesInRes; WORD nID; };
		struct GRPICONDIR { WORD idReserved, idType, idCount; GRPICONDIRENTRY entry; };
		#pragma pack(pop)
		GRPICONDIR dir{};
		dir.idType = 1; // 1 = icon
		dir.idCount = 1;
		dir.entry.bWidth = iw >= 256 ? 0 : BYTE(iw); // 0 encodes 256 (or larger) per the icon format.
		dir.entry.bHeight = ih >= 256 ? 0 : BYTE(ih);
		dir.entry.wPlanes = 1;
		dir.entry.wBitCount = 32;
		dir.entry.dwBytesInRes = DWORD(png.size());
		dir.entry.nID = 1;
		wstring wexe;
		Poco::UnicodeConverter::toUTF16(exe_path, wexe);
		HANDLE upd = BeginUpdateResourceW(wexe.c_str(), FALSE);
		if (!upd) throw Exception(format("unable to open %s to embed its icon", exe_path));
		WORD lang = MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL);
		// Use the numeric resource-type ids as wide strings (RT_ICON=3, RT_GROUP_ICON=14) so this
		// compiles whether or not the project defines UNICODE (RT_ICON itself would pick the ANSI type).
		bool ok = UpdateResourceW(upd, MAKEINTRESOURCEW(3), MAKEINTRESOURCEW(1), lang, (LPVOID)png.data(), DWORD(png.size()))
			&& UpdateResourceW(upd, MAKEINTRESOURCEW(14), MAKEINTRESOURCEW(1), lang, &dir, sizeof(dir));
		if (!ok) { EndUpdateResourceW(upd, TRUE); throw Exception(format("failed to write icon resources into %s", exe_path)); }
		if (!EndUpdateResourceW(upd, FALSE)) throw Exception(format("failed to commit icon resources into %s", exe_path));
#else
		set_status("custom icon skipped: Windows icons can only be embedded when compiling on Windows");
#endif
	}
	void finalize_product(Path& output_path) override {
		apply_windows_icon(output_path.toString()); // Applies to the .exe whether or not we go on to build a bundle.
		if (!bundle_mode) return; // We are not creating a bundle in this condition.
		bundle_assets(workplace.path(), workplace.path());
		copy_shared_libraries(Path(workplace.path()).append("lib"));
		if (bundle_mode > 1) {
			set_status("packaging product...");
			File zip_out = Path(final_output_path).makeFile().setExtension("zip").toString();
			set<string> store_paths;
			for (const game_asset& g : g_game_assets)
				if (g.flags & GAME_ASSET_UNCOMPRESSED) store_paths.insert(g.bundled_path);
			struct archive* a = archive_write_new();
			archive_write_set_format_zip(a);
			archive_write_zip_set_compression_deflate(a);
			archive_write_open_filename(a, zip_out.path().c_str());
			archive_write_dir(a, workplace.path(), "", build_exec_paths("", ""), store_paths, true);
			archive_write_close(a);
			archive_write_free(a);
			output_path = zip_out.path();
		} else output_path = workplace.path();
	}
};
class nvgt_compilation_output_mac : public nvgt_compilation_output_impl {
	SharedPtr<File> workplace_tmp;
	File workplace;
	Path final_output_path;
	int bundle_mode;
	using nvgt_compilation_output_impl::nvgt_compilation_output_impl;
protected:
	void alter_output_path(Path& output_path) override {
		bundle_mode = config.getInt("build.mac_bundle", 2); // 0 no bundle, 1 .app, 2 .dmg/.zip, 3 both .app and .dmg/.zip.
		if (bundle_mode == 2) {
			workplace_tmp = new TemporaryFile();
			workplace = Path(workplace_tmp->path()).append(Path(output_path).makeFile().getFileName()).setExtension("app");
		} else if(bundle_mode > 0) {
			workplace = Path(output_path).makeFile().setExtension("app");
			if (workplace.exists() && workplace.isDirectory()) workplace.remove(true); // both MacOS and IOS create .app bundles, if we don't construct them from scratch and someone compiles for IOS after MacOS, the bundles might clash without valid output basename set.
		}
		if (bundle_mode) {
			Path tmp = Path(workplace.path()).append("Contents/Resources");
			File(tmp).createDirectories();
			tmp = Path(workplace.path()).append("Contents/MacOS");
			File(tmp).createDirectories();
			tmp.append(output_path.getBaseName()).makeFile();
			final_output_path = output_path;
			output_path = tmp;
		}
	}
	void open_output_stream(const Path& output_path) override {
		nvgt_compilation_output_impl::open_output_stream(output_path);
		BinaryWriter bw(fs);
		// NVGT distributes MacOS stubs with the first 2 bytes of the header modified so that they are not recognised as executables by the apple notarization service. Stubs must be distributed unsigned leaving it up to the scripter to sign their games, and any unsigned executables in an app bundle cause notarization to fail even if they are resources. Correct the header here.
		fs.seekp(0);
		bw.writeRaw("\xCA\xFE");
		if (bundle_mode) {
			fs.close();
			fs.open(Path(workplace.path()).append("Contents/resources/exec").toString(), std::ios::out | std::ios::trunc); // App bundles must store their embedded packs and bytecode as a resource so the app bundle can be signed.
		}
	}
	void finalize_output_stream() override {
		if (!bundle_mode) nvgt_compilation_output_impl::finalize_output_stream();
		else BinaryWriter(fs) << int(0); // assets are being read from Resources/exec file, for code compatibility we make the last 4 bytes a data location like other platforms, 0 for the beginning of the file.
	}
	void finalize_product(Path& output_path) override {
		if (!bundle_mode) return; // We are not creating a bundle in this condition.
		string product_name = config.getString("build.product_name", Path(get_input_file()).getBaseName());
		string product_identifier = config.getString("build.product_identifier", make_product_id());
		// Write out info.plist.
		plist_t plist = plist_new_dict();
		plist_dict_set_item(plist, "CFBundleDisplayName", plist_new_string(product_name.c_str()));
		plist_dict_set_item(plist, "CFBundleExecutable", plist_new_string(format("MacOS/%s", output_path.getFileName()).c_str()));
		plist_dict_set_item(plist, "CFBundleIdentifier", plist_new_string(product_identifier.c_str()));
		plist_dict_set_item(plist, "CFBundleInfoDictionaryVersion", plist_new_string("6.0"));
		plist_dict_set_item(plist, "CFBundleName", plist_new_string(product_name.c_str()));
		plist_dict_set_item(plist, "CFBundlePackageType", plist_new_string("APPL"));
		plist_t plist_env_block = plist_new_dict();
		plist_dict_set_item(plist_env_block, "MACOS_BUNDLED_APP", plist_new_string("1"));
		plist_dict_set_item(plist, "LSEnvironment", plist_env_block);
		string mic_usage = config.getString("build.microphone_usage_description", "");
		if (!mic_usage.empty()) plist_dict_set_item(plist, "NSMicrophoneUsageDescription", plist_new_string(mic_usage.c_str()));
		// Custom application icon (via #pragma icon). macOS reads it from an .icns in Resources named
		// by CFBundleIconFile. On a real Mac we let sips build a proper multi-resolution .icns; on
		// other hosts (cross-compiling) we wrap the PNG directly, which Finder scales as needed.
		string mac_icon = get_custom_icon_path();
		if (!mac_icon.empty()) {
			set_status("applying custom app icon...");
			string icns_out = Path(workplace.path()).append("Contents/Resources/AppIcon.icns").toString();
			bool wrote = false;
			#ifdef __APPLE__
				string isout, iserr;
				wrote = system_command("sips", {"-s", "format", "icns", mac_icon, "--out", icns_out}, isout, iserr);
			#endif
			if (!wrote) {
				string icns = build_icns_from_png(mac_icon);
				FileOutputStream icns_f(icns_out);
				icns_f.write(icns.data(), icns.size());
				icns_f.close();
			}
			plist_dict_set_item(plist, "CFBundleIconFile", plist_new_string("AppIcon"));
		}
		char* plist_xml;
		uint32_t plist_len;
		if (plist_to_xml(plist, &plist_xml, &plist_len) != PLIST_ERR_SUCCESS) throw Exception("Unable to create info.plist");
		FileOutputStream plist_out(Path(workplace.path()).append("Contents/Info.plist").toString());
		plist_out.write(plist_xml, plist_len);
		plist_out.close();
		plist_mem_free(plist_xml);
		plist_free(plist);
		// Bundle assets and copy shared libraries.
		bundle_assets(Path(workplace.path()).append("Contents/Resources"), bundle_mode == 2? Path(workplace.path()).makeParent() : Path(workplace.path()).append("Contents/Resources"));
		copy_shared_libraries(Path(workplace.path()).append("Contents/Frameworks"));
		if (bundle_mode > 1) {
			// On the mac, we can execute the hdiutil command to create a .dmg file. Otherwise, we must create a .zip instead, as it can portably store unix file attributes.
			set_status("packaging product...");
			#ifdef __APPLE__
				string sout, serr;
				File dmg_out = Path(final_output_path).makeFile().setExtension("dmg").toString();
				if (dmg_out.exists()) dmg_out.remove(true);
				if (!system_command("hdiutil", {"create", "-srcfolder", bundle_mode != 2? workplace.path() : Path(workplace.path()).makeParent().toString(), "-volname", Path(workplace.path()).makeFile().getBaseName(), dmg_out.path()}, sout, serr)) throw Exception(format("Unable to execute hdiutil for .dmg generation: %s", serr));
				output_path = dmg_out.path();
			#else
				File iso_out = Path(final_output_path).makeFile().setExtension("iso").toString();
				string appname = Path(workplace.path()).makeFile().getFileName();
				string mac_exec = format("%s/Contents/MacOS/%s", appname, output_path.getFileName());
				set<string> mac_execs = build_exec_paths(mac_exec, appname + "/Contents/Resources");
				struct archive* a = archive_write_new();
				archive_write_set_format_iso9660(a);
				archive_write_set_option(a, nullptr, "rockridge", "1");
				archive_write_add_filter_none(a);
				archive_write_open_filename(a, iso_out.path().c_str());
				if (bundle_mode == 2) archive_write_dir(a, Path(workplace.path()).makeParent().toString(), "", mac_execs, {}, false);
				else {
					// Add .app explicitly, then add document assets at ISO root from their source paths.
					struct archive_entry* de = archive_entry_new();
					archive_entry_set_pathname(de, appname.c_str());
					archive_entry_set_filetype(de, AE_IFDIR);
					archive_entry_set_perm(de, 0755);
					archive_entry_set_mtime(de, Timestamp().epochTime(), 0);
					archive_entry_set_size(de, 0);
					archive_write_header(a, de);
					archive_entry_free(de);
					archive_write_dir(a, workplace.path(), appname, mac_execs, {}, false);
					Path input_dir = Path(get_input_file()).makeParent();
					for (const game_asset& g : g_game_assets) {
						if (!(g.flags & GAME_ASSET_DOCUMENT)) continue;
						File src(Path(g.filesystem_path).makeAbsolute(input_dir).toString());
						struct archive_entry* fe = archive_entry_new();
						archive_entry_set_pathname(fe, Path(g.bundled_path).makeFile().getFileName().c_str());
						archive_entry_set_filetype(fe, AE_IFREG);
						archive_entry_set_perm(fe, 0644);
						archive_entry_set_size(fe, (la_int64_t)src.getSize());
						archive_entry_set_mtime(fe, src.getLastModified().epochTime(), 0);
						archive_write_header(a, fe);
						archive_entry_free(fe);
						FileInputStream fis(src.path());
						char buf[65536];
						while (fis.good()) {
							fis.read(buf, sizeof(buf));
							la_ssize_t n = fis.gcount();
							if (n > 0) archive_write_data(a, buf, n);
						}
					}
				}
				archive_write_close(a);
				archive_write_free(a);
				output_path = iso_out.path();
			#endif
		} else output_path = workplace.path();
	}
};
class nvgt_compilation_output_ios : public nvgt_compilation_output_impl {
	SharedPtr<File> workplace_tmp;
	File workplace;
	Path final_output_path;
	int bundle_mode;
	using nvgt_compilation_output_impl::nvgt_compilation_output_impl;
protected:
	void alter_output_path(Path& output_path) override {
		bundle_mode = config.getInt("build.ios_bundle", 2); // 0 no bundle, 1 .app, 2 .ipa, 3 both .app and .ipa.
		if (bundle_mode == 2) {
			workplace_tmp = new TemporaryFile();
			workplace = Path(workplace_tmp->path()).append("Payload").append(Path(output_path).makeFile().getFileName()).setExtension("app");
		} else if(bundle_mode > 0) {
			workplace = Path(output_path).makeFile().setExtension("app");
			if (workplace.exists() && workplace.isDirectory()) workplace.remove(true); // both MacOS and IOS create .app bundles, if we don't construct them from scratch and someone compiles for IOS after MacOS, the bundles might clash without valid output basename set.
		}
		if (bundle_mode) {
			File(workplace.path()).createDirectories();
			Path tmp = Path(workplace.path()).append(output_path.getBaseName()).makeFile();
			final_output_path = output_path;
			output_path = tmp;
		}
	}
	void open_output_stream(const Path& output_path) override {
		nvgt_compilation_output_impl::open_output_stream(output_path);
		BinaryWriter bw(fs);
		// Restore the iOS arm64 Mach-O magic bytes (first 2 bytes were replaced with NV by fix_stub).
		fs.seekp(0);
		bw.writeRaw("\xCF\xFA");
		if (bundle_mode) {
			fs.close();
			fs.open(Path(workplace.path()).append("exec").toString(), std::ios::out | std::ios::trunc); // Store payload as a resource so the app bundle can be signed.
		}
	}
	void finalize_output_stream() override {
		if (!bundle_mode) nvgt_compilation_output_impl::finalize_output_stream();
		else BinaryWriter(fs) << int(0); // Payload is read from the exec resource file; 0 means read from the beginning.
	}
	void finalize_product(Path& output_path) override {
		if (!bundle_mode) return;
		string product_name = config.getString("build.product_name", Path(get_input_file()).getBaseName());
		string product_identifier = config.getString("build.product_identifier", make_product_id());
		string product_version = config.getString("build.product_version", "1.0");
		// Write Info.plist in XML format.
		plist_t plist = plist_new_dict();
		plist_dict_set_item(plist, "CFBundleDevelopmentRegion", plist_new_string("en"));
		plist_dict_set_item(plist, "CFBundleName", plist_new_string(product_name.c_str()));
		plist_t platforms = plist_new_array();
		plist_array_append_item(platforms, plist_new_string("iPhoneOS"));
		plist_dict_set_item(plist, "CFBundleSupportedPlatforms", platforms);
		plist_dict_set_item(plist, "CFBundleExecutable", plist_new_string(output_path.getFileName().c_str()));
		plist_dict_set_item(plist, "CFBundleInfoDictionaryVersion", plist_new_string("6.0"));
		plist_dict_set_item(plist, "CFBundleDisplayName", plist_new_string(product_name.c_str()));
		plist_dict_set_item(plist, "CFBundlePackageType", plist_new_string("APPL"));
		plist_dict_set_item(plist, "CFBundleShortVersionString", plist_new_string(config.getString("build.product_version", "1.0").c_str()));
		plist_dict_set_item(plist, "CFBundleVersion", plist_new_string(config.getString("build.product_version_code", "1.0").c_str()));
		// Required by the App Store (missing -> ITMS-90360). Hardcoded to match the iOS stub's
		// LC_BUILD_VERSION deployment target (16.0); a mismatch makes App Store reject with
		// "bundle does not support the minimum OS version specified in the Info.plist", so this is
		// NOT configurable unless the stubs are rebuilt with a different target.
		plist_dict_set_item(plist, "MinimumOSVersion", plist_new_string("16.0"));
		plist_dict_set_item(plist, "CFBundleIdentifier", plist_new_string(product_identifier.c_str()));
		plist_dict_set_item(plist, "LSRequiresIPhoneOS", plist_new_bool(1));
		// App Store requires DTPlatformName (ITMS-90507) and, for 64-bit binaries, the arm64
		// device capability (ITMS-90502).
		plist_dict_set_item(plist, "DTPlatformName", plist_new_string("iphoneos"));
		{
			// DT* build-environment keys are HARD-CODED here — NOT read from config, NOT derived
			// from the local Xcode — so every bundle is stamped with the exact GM (public,
			// non-beta) Xcode that built the SHIPPED iOS stub (nvgt_ios*.bin). NVGT ships a
			// prebuilt stub, so the developer's local Xcode (old, absent, or a beta/RC) is
			// irrelevant and MUST NOT drive these values: App Store review rejects apps whose
			// build environment looks non-GM, and a plist-vs-stub mismatch is worse. This holds
			// on every host, macOS included (many NVGT users' Macs have an old Xcode or none).
			// Verified 2026-07-01 from a real minimal app built with GM Xcode 26.5 (the GitHub
			// macos-26 runner's DEFAULT Xcode): xcodebuild Build 17F42, iOS SDK 26.5, SDK build
			// 23F73. Xcode 26.5 is a public GM (released May 2026), not a beta/RC, and macos-26's
			// default Xcode IS 26.5, so a stub built there already matches these values.
			// Bump ALL of these in lockstep whenever the stub is rebuilt with a newer GM Xcode.
			const string dt_compiler       = "com.apple.compilers.llvm.clang.1_0";
			const string dt_xcode          = "2650";          // Xcode 26.5
			const string dt_xcode_build    = "17F42";         // xcodebuild Build version
			const string dt_platform_ver   = "26.5";          // iOS SDK version (not the Xcode string)
			const string dt_platform_build = "23F73";         // iOS SDK build (DISTINCT from DTXcodeBuild)
			const string dt_sdk_build      = "23F73";         // same SDK build id
			const string dt_sdk_name       = "iphoneos26.5";
			// BuildMachineOSBuild is also HARD-CODED (not read from the local Mac via sw_vers):
			// a developer bundling on their own Mac would otherwise stamp whatever macOS build
			// they happen to run, which need not match the runner that actually compiled the
			// stub. Value = the macOS build of the GitHub macos-26 runner that builds the stub
			// (verified 2026-07-01 from a real Xcode-26.5 app on that runner). Bump with the DTs.
			const string dt_build_machine  = "25E246";
			plist_dict_set_item(plist, "BuildMachineOSBuild", plist_new_string(dt_build_machine.c_str()));
			plist_dict_set_item(plist, "DTCompiler",          plist_new_string(dt_compiler.c_str()));
			plist_dict_set_item(plist, "DTPlatformBuild",     plist_new_string(dt_platform_build.c_str()));
			plist_dict_set_item(plist, "DTPlatformVersion",   plist_new_string(dt_platform_ver.c_str()));
			plist_dict_set_item(plist, "DTSDKBuild",          plist_new_string(dt_sdk_build.c_str()));
			plist_dict_set_item(plist, "DTSDKName",           plist_new_string(dt_sdk_name.c_str()));
			plist_dict_set_item(plist, "DTXcode",             plist_new_string(dt_xcode.c_str()));
			plist_dict_set_item(plist, "DTXcodeBuild",        plist_new_string(dt_xcode_build.c_str()));
		}
		plist_t req_caps = plist_new_array();
		plist_array_append_item(req_caps, plist_new_string("arm64"));
		plist_dict_set_item(plist, "UIRequiredDeviceCapabilities", req_caps);
		plist_t scene_manifest = plist_new_dict();
		plist_dict_set_item(scene_manifest, "UIApplicationSupportsMultipleScenes", plist_new_bool(0));
		plist_dict_set_item(scene_manifest, "UISceneConfigurations", plist_new_dict());
		plist_dict_set_item(plist, "UIApplicationSceneManifest", scene_manifest);
		plist_dict_set_item(plist, "UIRequiresFullScreen", plist_new_bool(1));
		plist_t orientations = plist_new_array();
		plist_array_append_item(orientations, plist_new_string("UIInterfaceOrientationPortrait"));
		plist_array_append_item(orientations, plist_new_string("UIInterfaceOrientationPortraitUpsideDown"));
		plist_array_append_item(orientations, plist_new_string("UIInterfaceOrientationLandscapeLeft"));
		plist_array_append_item(orientations, plist_new_string("UIInterfaceOrientationLandscapeRight"));
		plist_dict_set_item(plist, "UISupportedInterfaceOrientations", orientations);
		plist_dict_set_item(plist, "UIApplicationSupportsIndirectInputEvents", plist_new_bool(1));
		plist_t device_family = plist_new_array();
		plist_array_append_item(device_family, plist_new_uint(1));
		plist_array_append_item(device_family, plist_new_uint(2));
		plist_dict_set_item(plist, "UIDeviceFamily", device_family);
		plist_dict_set_item(plist, "UILaunchScreen", plist_new_dict());
		string mic_usage = config.getString("build.microphone_usage_description", "");
		if (!mic_usage.empty()) plist_dict_set_item(plist, "NSMicrophoneUsageDescription", plist_new_string(mic_usage.c_str()));
		// ITMS-90683: SDL3's camera subsystem links AVCaptureDevice, so Apple's static
		// analysis REQUIRES NSCameraUsageDescription on upload even though the game never
		// opens a camera. Default ON with generic engine-appropriate text; a developer can
		// override via build.camera_usage_description, or set it empty to omit (e.g. a custom
		// SDL build with -DSDL_CAMERA=OFF). NSBluetoothAlwaysUsageDescription is only a
		// non-blocking warning, so it is intentionally not set.
		string camera_usage = config.getString("build.camera_usage_description", "This app is built with a game engine that includes camera support. The camera is only accessed if a game feature explicitly uses it.");
		if (!camera_usage.empty()) plist_dict_set_item(plist, "NSCameraUsageDescription", plist_new_string(camera_usage.c_str()));
		// Custom application icon (via #pragma icon). A full App-Store-valid iOS icon needs BOTH the
		// exact-size loose PNGs (below) AND a compiled asset catalog (Assets.car) named by
		// CFBundleIconName; we generate both, matching what Xcode/actool produces.
		string ios_icon = get_custom_icon_path();
		if (!ios_icon.empty()) {
			set_status("applying custom app icon...");
			// Apple's App Store validator requires physical, EXACT-size PNG icons in the bundle root
			// (outside the asset catalog): 120x120 for iPhone (ITMS-90022) and 152x152 for iPad
			// (ITMS-90023). A real Xcode/actool single-size build emits exactly these two flattened
			// files, so we match it byte-for-byte in layout: resize the source PNG to each exact size
			// (copying it unchanged is rejected) and reference them via CFBundleIconFiles.
			struct { const char* file; int size; } ios_icons[] = {
				{"AppIcon60x60@2x.png", 120},      // iPhone @2x
				{"AppIcon76x76@2x~ipad.png", 152}, // iPad @2x
			};
			for (const auto& ic : ios_icons) {
				string err = write_resized_png(ios_icon, ic.size, ic.size, Path(workplace.path()).append(ic.file).toString());
				if (!err.empty()) throw Exception(format("failed to generate iOS icon %s: %s", string(ic.file), err));
			}
			// CFBundleIconFiles lists base names; iPhone uses 60pt, iPad adds 76pt (matches Xcode output).
			for (int ipad = 0; ipad <= 1; ++ipad) {
				plist_t icon_files = plist_new_array();
				plist_array_append_item(icon_files, plist_new_string("AppIcon60x60"));
				if (ipad) plist_array_append_item(icon_files, plist_new_string("AppIcon76x76"));
				plist_t primary_icon = plist_new_dict();
				plist_dict_set_item(primary_icon, "CFBundleIconFiles", icon_files);
				plist_dict_set_item(primary_icon, "CFBundleIconName", plist_new_string("AppIcon"));
				plist_t icons = plist_new_dict();
				plist_dict_set_item(icons, "CFBundlePrimaryIcon", primary_icon);
				plist_dict_set_item(plist, ipad? "CFBundleIcons~ipad" : "CFBundleIcons", icons);
			}
			// Compiled asset catalog + top-level CFBundleIconName, required by App Store upload
			// (ITMS-90713). Generated from the user's icon; see build_assets_car.
			set_status("building icon asset catalog...");
			string car = build_assets_car(ios_icon);
			FileOutputStream car_out(Path(workplace.path()).append("Assets.car").toString());
			car_out.write(car.data(), car.size());
			car_out.close();
			plist_dict_set_item(plist, "CFBundleIconName", plist_new_string("AppIcon"));
		}
		char* plist_xml;
		uint32_t plist_len;
		if (plist_to_xml(plist, &plist_xml, &plist_len) != PLIST_ERR_SUCCESS) throw Exception("Unable to create Info.plist");
		FileOutputStream plist_out(Path(workplace.path()).append("Info.plist").toString());
		plist_out.write(plist_xml, plist_len);
		plist_out.close();
		plist_mem_free(plist_xml);
		plist_free(plist);
		// On iOS, resources and documents both live at the root of the app bundle (no Contents/ hierarchy).
		bundle_assets(workplace.path(), workplace.path());
		// Code-sign the app in place if a signing identity (.p12 + provisioning profile) was provided,
		// producing a signature byte-identical to Apple's codesign.
		string sign_p12 = config.getString("build.ios_signing_p12", "");
		if (!sign_p12.empty()) {
			set_status("code signing...");
			Path inparent = Path(get_input_file()).makeParent();
			string p12 = ioscs::slurp(Path(sign_p12).makeAbsolute(inparent).toString());
			string prov = ioscs::slurp(Path(config.getString("build.ios_provisioning_profile", "")).makeAbsolute(inparent).toString());
			uint64_t signtime = (uint64_t)config.getInt64("build.ios_signing_time", (Poco::Int64)Timestamp().epochTime());
			ioscs::sign_app(workplace.path(), output_path.getFileName(), product_identifier, p12, config.getString("build.ios_signing_password", ""), prov, signtime);
		}
		if (bundle_mode > 1) {
			set_status("packaging product...");
			// For mode 2 the workplace is already under a temp/Payload/ tree; for mode 3 we stage into a temp dir.
			SharedPtr<TemporaryFile> ipa_staging_tmp;
			Path ipa_root;
			if (bundle_mode == 2) ipa_root = Path(workplace_tmp->path());
			else {
				ipa_staging_tmp = new TemporaryFile();
				ipa_root = Path(ipa_staging_tmp->path());
				File(Path(ipa_root).append("Payload").toString()).createDirectories();
				File(workplace.path()).copyTo(Path(ipa_root).append("Payload").toString());
			}
			// iTunesMetadata.plist intentionally NOT written: App Store / Transporter rejects it
			// as a disallowed path (ITMS-90047). It was only useful for legacy iTunes / ad-hoc .ipa
			// installs, which no longer apply.
			string appbundle = Path(workplace.path()).makeFile().getFileName();
			string ios_exec = format("Payload/%s/%s", appbundle, output_path.getFileName());
			set<string> store_paths;
			for (const game_asset& g : g_game_assets)
				if (g.flags & GAME_ASSET_UNCOMPRESSED) store_paths.insert(format("Payload/%s/%s", appbundle, g.bundled_path));
			File ipa_out = Path(final_output_path).makeFile().setExtension("ipa").toString();
			struct archive* a = archive_write_new();
			archive_write_set_format_zip(a);
			archive_write_zip_set_compression_deflate(a);
			archive_write_open_filename(a, ipa_out.path().c_str());
			archive_write_dir(a, ipa_root.toString(), "", build_exec_paths(ios_exec, format("Payload/%s", appbundle)), store_paths, true);
			archive_write_close(a);
			archive_write_free(a);
			output_path = ipa_out.path();
		} else output_path = workplace.path();
	}
};
class nvgt_compilation_output_linux : public nvgt_compilation_output_impl {
	SharedPtr<File> workplace_tmp;
	File workplace;
	Path final_output_path;
	int bundle_mode;
	using nvgt_compilation_output_impl::nvgt_compilation_output_impl;
protected:
	void alter_output_path(Path& output_path) override {
		bundle_mode = config.getInt("build.linux_bundle", 2); // 0 no bundle, 1 folder, 2 .zip, 3 both folder and .zip.
		if (bundle_mode == 2) {
			workplace_tmp = new TemporaryFile();
			workplace = *workplace_tmp;
		} else if(bundle_mode > 0) workplace = Path(output_path).makeFile().setExtension("");
		if (bundle_mode) {
			workplace.createDirectories();
			Path tmp = Path(workplace.path()).append(output_path.getBaseName()).makeFile();
			final_output_path = output_path;
			output_path = tmp;
		}
	}
	void finalize_product(Path& output_path) override {
		if (!bundle_mode) return; // We are not creating a bundle in this condition.
		bundle_assets(workplace.path(), workplace.path());
		copy_shared_libraries(Path(workplace.path()).append("lib"));
		// Custom application icon (via #pragma icon). Linux executables carry no embedded icon, so the
		// portable convention is to ship the image plus a .desktop launcher entry that points at it.
		// We place both alongside the binary; a user can install them into the standard XDG locations
		// (or the icon is picked up when the folder is used as a self-contained app directory).
		string linux_icon = get_custom_icon_path();
		if (!linux_icon.empty()) {
			set_status("applying custom app icon...");
			string appbase = output_path.getBaseName();
			File(linux_icon).copyTo(Path(workplace.path()).append(appbase + ".png").toString());
			string product_name = config.getString("build.product_name", appbase);
			string desktop = format("[Desktop Entry]\nType=Application\nName=%s\nExec=./%s\nIcon=%s\nTerminal=false\nCategories=Game;\n", product_name, output_path.getFileName(), appbase);
			FileOutputStream desktop_f(Path(workplace.path()).append(appbase + ".desktop").toString());
			desktop_f.write(desktop.data(), desktop.size());
			desktop_f.close();
		}
		if (bundle_mode > 1) {
			set_status("packaging product...");
			File tgz_out = Path(final_output_path).makeFile().setExtension("tar.gz").toString();
			struct archive* a = archive_write_new();
			archive_write_set_format_pax_restricted(a);
			archive_write_add_filter_gzip(a);
			archive_write_open_filename(a, tgz_out.path().c_str());
			archive_write_dir(a, workplace.path(), "", build_exec_paths(output_path.getFileName(), ""), {}, false);
			archive_write_close(a);
			archive_write_free(a);
			output_path = tgz_out.path();
		} else output_path = workplace.path();
	}
	void open_output_stream(const Path& output_path) override {
		nvgt_compilation_output_impl::open_output_stream(output_path);
		BinaryWriter bw(fs);
		fs.seekp(0);
		bw.writeRaw("\x7f\x45"); // \x7fE — start of \x7fELF
	}
};
class nvgt_compilation_output_android : public nvgt_compilation_output_impl {
	TemporaryFile workplace;
	Path final_output_path, android_jar, apksigner_jar;
	bool is_aab = false;
	int do_install; // 0 no, 1 ask, 2 always.
	unsigned int install_transport_id; // ADB transport ID of device to install to.
	string install_device_name; // Used for UI display to report device installed to.
	string sign_cert, sign_password;
	string java_command, keytool_command, jarsigner_command;
	using nvgt_compilation_output_impl::nvgt_compilation_output_impl;
	string exe(const std::string& path) const {
		return Environment::isWindows()? path + ".exe" : path;
	}
	static void add_tool_dir_candidates(vector<string>& dirs, const string& root) {
		if (root.empty()) return;
		set<string> candidates = {
			root,
			Path(root).append("bin").toString(),
			Path(root).append("jre/bin").toString(),
			Path(root).append("Contents/Home/bin").toString()
		};
		for (const string& candidate : candidates)
			if (File(candidate).exists()) dirs.push_back(candidate);
	}
	vector<string> get_java_tool_search_dirs() const {
		vector<string> dirs;
		auto add_root = [&](const string& root) {
			add_tool_dir_candidates(dirs, Path::expand(root));
		};
		add_root(Path(config.getString("application.dir")).append("android-tools").toString());
		add_root(Path(config.getString("application.dir")).append("android-tools/java17").toString());
		add_root(Path(config.getString("application.dir")).append("android-tools/jbr").toString());
		add_root(Path(config.getString("application.dir")).append("android-tools/jdk").toString());
		add_root(config.getString("build.android_java_home", ""));
		add_root(Environment::get("JAVA_HOME", ""));
		add_root(Environment::get("JDK_HOME", ""));
		// Android SDK ships its own JDK under openjdk/ but does not set JAVA_HOME.
		// The JDK may live inside the SDK root or as a sibling directory (e.g. ANDROID_HOME=C:\android\sdk, JDK=C:\android\openjdk\jdk-x).
		auto add_android_sdk_jdk = [&](const string& sdk_root) {
			if (sdk_root.empty()) return;
			auto glob_jdks = [&](const string& base) {
				set<string> matches;
				Glob::glob(Path(base).append("openjdk/jdk-*").toString(), matches);
				for (const string& match : matches)
					if (File(match).exists() && File(match).isDirectory()) add_root(match);
			};
			glob_jdks(sdk_root);
			glob_jdks(Path(sdk_root).parent().toString());
		};
		add_android_sdk_jdk(Environment::get("ANDROID_HOME", ""));
		add_android_sdk_jdk(Environment::get("ANDROID_SDK_ROOT", ""));
		add_android_sdk_jdk(Environment::get("ANDROID_SDK_HOME", ""));
		if (Environment::isWindows()) {
			vector<string> patterns = {
				Environment::get("ProgramFiles", "C:\\Program Files") + "\\Java\\*",
				Environment::get("ProgramFiles(X86)", "C:\\Program Files (x86)") + "\\Java\\*",
				Environment::get("ProgramFiles", "C:\\Program Files") + "\\Eclipse Adoptium\\*",
				Environment::get("ProgramFiles", "C:\\Program Files") + "\\Microsoft\\jdk*",
				Path::dataHome() + "Programs\\Eclipse Adoptium\\*",
				Path::dataHome() + "Android\\Android Studio\\jbr",
				Path::dataHome() + "AppData\\Local\\Android\\Sdk\\openjdk\\jdk-*"
			};
			for (const string& pattern : patterns) {
				set<string> matches;
				Glob::glob(pattern, matches);
				for (const string& match : matches)
					if (File(match).exists() && File(match).isDirectory()) add_root(match);
			}
		} else if (Environment::os() == POCO_OS_MAC_OS_X) {
			vector<string> patterns = {
				"/Library/Java/JavaVirtualMachines/*",
				"/Applications/Android Studio.app/Contents/jbr",
				Path::expand("~/Applications/Android Studio.app/Contents/jbr"),
				Path::expand("~/Library/Android/sdk/openjdk/jdk-*")
			};
			for (const string& pattern : patterns) {
				set<string> matches;
				Glob::glob(pattern, matches);
				for (const string& match : matches)
					if (File(match).exists() && File(match).isDirectory()) add_root(match);
			}
		} else {
			vector<string> patterns = {
				"/usr/lib/jvm/*",
				"/usr/java/*",
				"/opt/android-studio/jbr",
				Path::expand("~/android-studio/jbr"),
				"/snap/android-studio/current/android-studio/jbr",
				Path::expand("~/Android/Sdk/openjdk/jdk-*")
			};
			for (const string& pattern : patterns) {
				set<string> matches;
				Glob::glob(pattern, matches);
				for (const string& match : matches)
					if (File(match).exists() && File(match).isDirectory()) add_root(match);
			}
		}
		return dirs;
	}
	string resolve_java_tool(const string& tool_name) const {
		vector<string> dirs = get_java_tool_search_dirs();
		string tool = exe(tool_name);
		for (const string& dir : dirs) {
			string candidate = Path(dir).append(tool).toString();
			if (File(candidate).exists()) return candidate;
		}
		string located;
		string search_path;
		for (const string& dir : dirs) {
			if (!search_path.empty()) search_path += Path::pathSeparator();
			search_path += dir;
		}
		Path located_path;
		if (!search_path.empty() && Path::find(search_path + Path::pathSeparator() + Environment::get("PATH", ""), tool, located_path))
			return located_path.toString();
		return tool;
	}
	string get_keytool_password() const {
		size_t sep = sign_password.find(':');
		return sep == string::npos ? sign_password : sign_password.substr(sep + 1);
	}
	bool sign_android_aab_with_jarsigner(const string& aab_path, string& std_out, string& std_err) {
		return system_command(jarsigner_command, {"-keystore", sign_cert, "-storepass", get_keytool_password(), "-keypass", get_keytool_password(), aab_path, "game"}, std_out, std_err);
	}
	bool sign_android_aab_with_java_module(const string& aab_path, string& std_out, string& std_err) {
		Process::Args args = {
			"-m", "jdk.jartool/sun.security.tools.jarsigner.Main",
			"-keystore", sign_cert,
			"-storepass", get_keytool_password(),
			"-keypass", get_keytool_password(),
			aab_path,
			"game"
		};
		return system_command(java_command, args, std_out, std_err);
	}
	static string base64_encode(const unsigned char* data, size_t size) {
		ostringstream out;
		Base64Encoder enc(out);
		enc.write(reinterpret_cast<const char*>(data), static_cast<std::streamsize>(size));
		enc.close();
		string result = out.str();
		while (!result.empty() && (result.back() == '\n' || result.back() == '\r')) result.pop_back();
		return result;
	}
	static string sha256_base64(const string& data) {
		unsigned char digest[SHA256_DIGEST_LENGTH];
		SHA256(reinterpret_cast<const unsigned char*>(data.data()), data.size(), digest);
		return base64_encode(digest, sizeof(digest));
	}
	static string read_binary_file(const string& path) {
		FileInputStream in(path, ios::in | ios::binary);
		ostringstream out;
		StreamCopier::copyStream(in, out);
		return out.str();
	}
	static void write_binary_file(const string& path, const string& data) {
		File(Path(path).parent()).createDirectories();
		FileOutputStream out(path, ios::out | ios::binary | ios::trunc);
		out.write(data.data(), static_cast<std::streamsize>(data.size()));
	}
	// Patch a signed AAB's ZIP metadata so that every byte is covered by the JAR signature.
	// JAR/v1 signing only hashes file content, not ZIP headers. libarchive writes Unix mode bits
	// into the central directory external-file-attributes field and timestamp/uid-gid data into
	// local-file-header extra fields. jarsigner leaves these unprotected and warns about them;
	// Google Play then rejects the bundle as having an "invalid signature".
	// This function zeroes those fields AFTER signing so the content hashes remain valid.
	static void strip_zip_posix_attrs(const string& path) {
		string data = read_binary_file(path);
		if (data.size() < 22) return;
		auto u16 = [&](size_t o) -> uint16_t {
			return (uint8_t)data[o] | ((uint8_t)data[o + 1] << 8);
		};
		auto u32 = [&](size_t o) -> uint32_t {
			return (uint8_t)data[o] | ((uint8_t)data[o+1] << 8) | ((uint8_t)data[o+2] << 16) | ((uint8_t)data[o+3] << 24);
		};
		// Locate the End of Central Directory record.
		size_t eocd = string::npos;
		for (size_t i = data.size() - 22; ; --i) {
			if (u32(i) == 0x06054b50) { eocd = i; break; }
			if (i == 0) break;
		}
		if (eocd == string::npos) return;
		uint32_t cd_off = u32(eocd + 16);
		uint16_t cd_count = u16(eocd + 10);
		size_t cd_pos = cd_off;
		for (uint16_t n = 0; n < cd_count && cd_pos + 46 <= data.size(); ++n) {
			if (u32(cd_pos) != 0x02014b50) break;
			uint16_t fname_len = u16(cd_pos + 28);
			uint16_t extra_len = u16(cd_pos + 30);
			uint16_t comment_len = u16(cd_pos + 32);
			uint32_t lfh_off = u32(cd_pos + 42);
			// Clear the Unix platform indicator in "version made by" (high byte: 3=Unix -> 0=DOS).
			data[cd_pos + 5] = 0;
			// Zero external file attributes so no Unix mode bits remain.
			data[cd_pos + 38] = data[cd_pos + 39] = data[cd_pos + 40] = data[cd_pos + 41] = 0;
			// Zero the extra field data in the matching local file header.
			// We keep extra_len unchanged to preserve file-data offsets; zeroed bytes become
			// null (type 0x0000) extra-field entries that ZIP readers silently skip.
			if (lfh_off + 30 <= data.size() && u32(lfh_off) == 0x04034b50) {
				uint16_t lfname_len = u16(lfh_off + 26);
				uint16_t lextra_len = u16(lfh_off + 28);
				size_t lextra_off = lfh_off + 30 + lfname_len;
				if (lextra_len > 0 && lextra_off + lextra_len <= data.size())
					for (size_t b = lextra_off; b < lextra_off + lextra_len; ++b) data[b] = 0;
			}
			cd_pos += 46 + fname_len + extra_len + comment_len;
		}
		write_binary_file(path, data);
	}
	static string wrap_manifest_line(const string& line) {
		string wrapped;
		size_t pos = 0;
		while (pos < line.size()) {
			// JAR spec: max 72 bytes per line including CRLF.
			// First line: 70 content + CRLF = 72. Continuation: 1 space + 69 content + CRLF = 72.
			size_t chunk = min(pos == 0 ? size_t(70) : size_t(69), line.size() - pos);
			if (pos == 0) wrapped += line.substr(pos, chunk) + "\r\n";
			else wrapped += " " + line.substr(pos, chunk) + "\r\n";
			pos += chunk;
		}
		if (line.empty()) wrapped = "\r\n";
		return wrapped;
	}
	static string make_manifest_section(const string& entry_name, const string& entry_digest_base64) {
		string section;
		section += wrap_manifest_line("Name: " + entry_name);
		section += wrap_manifest_line("SHA-256-Digest: " + entry_digest_base64);
		section += "\r\n";
		return section;
	}
	static bool should_skip_jar_signature_entry(const string& entry_name) {
		if (entry_name == "META-INF/MANIFEST.MF") return true;
		if (entry_name.rfind("META-INF/", 0) != 0) return false;
		string leaf = Path(entry_name).makeFile().getFileName();
		string upper = toUpper(leaf);
		return upper.size() > 3 && (string_has_suffix(upper, ".SF") || string_has_suffix(upper, ".RSA") || string_has_suffix(upper, ".DSA") || string_has_suffix(upper, ".EC"));
	}
	bool export_keystore_to_pkcs12(const string& pkcs12_path, const string& pkcs12_password, string& std_out, string& std_err) {
		Process::Args args = {
			"-importkeystore",
			"-srckeystore", sign_cert,
			"-srcstorepass", get_keytool_password(),
			"-srcalias", "game",
			"-destkeystore", pkcs12_path,
			"-deststoretype", "PKCS12",
			"-deststorepass", pkcs12_password,
			"-destkeypass", pkcs12_password,
			"-destalias", "game",
			"-noprompt"
		};
		return system_command(keytool_command, args, std_out, std_err);
	}
	bool load_signing_identity(EVP_PKEY** out_key, X509** out_cert, STACK_OF(X509)** out_chain, string& std_err) {
		*out_key = nullptr;
		*out_cert = nullptr;
		*out_chain = nullptr;
		auto load_pkcs12 = [&](const string& path, const string& password) -> bool {
			FILE* fp = fopen(path.c_str(), "rb");
			if (!fp) {
				std_err = format("Unable to open signing keystore %s", path);
				return false;
			}
			PKCS12* p12 = d2i_PKCS12_fp(fp, nullptr);
			fclose(fp);
			if (!p12) return false;
			bool ok = PKCS12_parse(p12, password.c_str(), out_key, out_cert, out_chain) == 1;
			if (!ok) {
				unsigned long err = ERR_get_error();
				std_err = err ? ERR_error_string(err, nullptr) : "Unable to parse PKCS12 keystore";
			}
			PKCS12_free(p12);
			return ok;
		};
		string password = get_keytool_password();
		string lower_cert = toLower(sign_cert);
		if (string_has_suffix(lower_cert, ".p12") || string_has_suffix(lower_cert, ".pfx")) return load_pkcs12(sign_cert, password);
		if (load_pkcs12(sign_cert, password)) return true;
		TemporaryFile tmp_pkcs12;
		string export_out, export_err;
		string temp_password = format("nvgt_%u", uint32_t(Timestamp().epochMicroseconds()));
		if (!export_keystore_to_pkcs12(tmp_pkcs12.path(), temp_password, export_out, export_err)) {
			std_err = format("Failed to export keystore to PKCS12, %s%s", export_out, export_err);
			return false;
		}
		if (!load_pkcs12(tmp_pkcs12.path(), temp_password)) return false;
		return true;
	}
	bool sign_android_aab_in_process(const string& aab_path, string& std_out, string& std_err) {
		string stage = "initializing temporary directory";
		try {
			string extracted_dir = make_unique_temp_path(".aabdir");
			File(extracted_dir).createDirectories();
			stage = format("extracting AAB %s", aab_path);
			libarchive_extract(aab_path, extracted_dir);
			stage = "enumerating bundle entries";
			vector<string> entry_names;
			collect_relative_files_recursive(extracted_dir, "", entry_names);
			sort(entry_names.begin(), entry_names.end());
			string manifest = "Manifest-Version: 1.0\r\nCreated-By: NVGT\r\n\r\n";
			vector<pair<string, string>> manifest_sections;
			stage = "building manifest digests";
			for (const string& entry_name : entry_names) {
				if (should_skip_jar_signature_entry(entry_name)) {
					File(Path(extracted_dir).append(entry_name)).remove();
					continue;
				}
				string entry_path = Path(extracted_dir).append(entry_name).toString();
				string data = read_binary_file(entry_path);
				string section = make_manifest_section(entry_name, sha256_base64(data));
				manifest += section;
				manifest_sections.push_back({entry_name, section});
			}
			string sf = "Signature-Version: 1.0\r\nCreated-By: NVGT\r\n";
			sf += wrap_manifest_line("SHA-256-Digest-Manifest: " + sha256_base64(manifest));
			sf += "\r\n";
			for (const auto& section : manifest_sections) {
				sf += wrap_manifest_line("Name: " + section.first);
				sf += wrap_manifest_line("SHA-256-Digest: " + sha256_base64(section.second));
				sf += "\r\n";
			}
			EVP_PKEY* pkey = nullptr;
			X509* cert = nullptr;
			STACK_OF(X509)* chain = nullptr;
			ERR_clear_error();
			stage = format("loading signing identity from %s", sign_cert);
			if (!load_signing_identity(&pkey, &cert, &chain, std_err)) return false;
			stage = "generating CMS signature";
			BIO* sf_bio = BIO_new_mem_buf(sf.data(), static_cast<int>(sf.size()));
			CMS_ContentInfo* cms = sf_bio ? CMS_sign(cert, pkey, chain, sf_bio, CMS_BINARY | CMS_DETACHED) : nullptr;
			if (sf_bio) BIO_free(sf_bio);
			if (!cms) {
				unsigned long err = ERR_get_error();
				std_err = err ? ERR_error_string(err, nullptr) : "Unable to generate CMS signature";
				if (chain) sk_X509_pop_free(chain, X509_free);
				if (cert) X509_free(cert);
				if (pkey) EVP_PKEY_free(pkey);
				return false;
			}
			stage = "encoding CMS signature";
			BIO* der_bio = BIO_new(BIO_s_mem());
			if (!der_bio || i2d_CMS_bio(der_bio, cms) != 1) {
				unsigned long err = ERR_get_error();
				std_err = err ? ERR_error_string(err, nullptr) : "Unable to encode CMS signature";
				if (der_bio) BIO_free(der_bio);
				CMS_ContentInfo_free(cms);
				if (chain) sk_X509_pop_free(chain, X509_free);
				if (cert) X509_free(cert);
				if (pkey) EVP_PKEY_free(pkey);
				return false;
			}
			BUF_MEM* der_mem = nullptr;
			BIO_get_mem_ptr(der_bio, &der_mem);
			string sig_block = der_mem && der_mem->data && der_mem->length ? string(der_mem->data, der_mem->length) : string();
			BIO_free(der_bio);
			CMS_ContentInfo_free(cms);
			if (chain) sk_X509_pop_free(chain, X509_free);
			if (cert) X509_free(cert);
			if (pkey) EVP_PKEY_free(pkey);
			stage = "writing META-INF signature files";
			write_binary_file(Path(extracted_dir).append("META-INF/MANIFEST.MF").toString(), manifest);
			write_binary_file(Path(extracted_dir).append("META-INF/GAME.SF").toString(), sf);
			write_binary_file(Path(extracted_dir).append("META-INF/GAME.RSA").toString(), sig_block);
			stage = "repacking signed AAB";
			string signed_out = make_unique_temp_path(".signed.aab");
			struct archive* out_arc = archive_write_new();
			archive_write_set_format_zip(out_arc);
			archive_write_zip_set_compression_deflate(out_arc);
			if (archive_write_open_filename(out_arc, signed_out.c_str()) != ARCHIVE_OK) {
				string arc_err = archive_error_string(out_arc) ? archive_error_string(out_arc) : "unknown archive error";
				archive_write_free(out_arc);
				std_err = format("Unable to open temporary signed bundle %s: %s", signed_out, arc_err);
				return false;
			}
			archive_write_dir(out_arc, extracted_dir, "", {}, {}, true, true);
			archive_write_close(out_arc);
			archive_write_free(out_arc);
			if (!File(signed_out).exists()) {
				std_err = format("Signed AAB temporary output was not created at %s", signed_out);
				return false;
			}
			stage = format("replacing final AAB %s", aab_path);
			if (File(aab_path).exists()) File(aab_path).remove();
			File(signed_out).copyTo(aab_path);
			std_out = "AAB signed with internal PKCS7 fallback";
			std_err.clear();
			return true;
		} catch (const exception& e) {
			std_err = format("%s: %s", stage, e.what());
			return false;
		}
	}
	bool sign_android_aab(const string& aab_path, string& std_out, string& std_err) {
		string out1, err1, out2, err2, out3, err3;
		try {
			if (sign_android_aab_with_jarsigner(aab_path, out1, err1)) {
				std_out = out1;
				std_err = err1;
				return true;
			}
		} catch (const exception& e) {
			err1 = e.what();
		}
		try {
			if (sign_android_aab_with_java_module(aab_path, out2, err2)) {
				std_out = out2;
				std_err = err2;
				return true;
			}
		} catch (const exception& e) {
			err2 = e.what();
		}
		try {
			if (sign_android_aab_in_process(aab_path, out3, err3)) {
				std_out = out3;
				std_err = err3;
				return true;
			}
		} catch (const exception& e) {
			err3 = e.what();
		}
		std_out.clear();
		std_err = format("jarsigner failed: %s%s\njava module signing failed: %s%s\ninternal signing failed: %s%s", out1, err1, out2, err2, out3, err3);
		return false;
	}
	void ensure_android_keystore() {
		if (sign_cert.empty() || sign_password.empty() || File(sign_cert).exists()) return;
		set_status("creating signature keystore...");
		string sout, serr;
		if (!system_command(keytool_command, {"-genkey", "-keyalg", "RSA", "-keysize", "2048", "-v", "-keystore", sign_cert, "-dname", config.getString("build.android_signature_info", "cn=NVGT"), "-storepass", get_keytool_password(), "-validity", "10000", "-alias", "game"}, sout, serr))
			throw Exception(format("Failed to run keytool, %s%s", sout, serr));
	}
	bool android_sdk_tools_exist(const std::string& path) {
		// This will also set the path to android.jar and apksigner.jar if build tools are found.
		Path located;
		bool has_java = sign_cert.empty() || sign_password.empty() || File(java_command).exists() || Path::find(path, exe("java"), located);
		bool found = Path::find(path, exe("zipalign"), located) && has_java && (!do_install || Path::find(path, exe("adb"), located)) && Path::find(path, exe("aapt2"), located);
		if (!found) return false;
		// Since this particular search was last in the Path::find calls above, located now contains a path to aapt2.exe, hopefully we can locate android.jar from it.
		located.setFileName("");
		if (File(Path(located).setFileName("android.jar")).exists()) {
			android_jar = Path(located).setFileName("android.jar"); // This is likely from NVGT's minified set of Android tools provided for ease of use for beginners.
			apksigner_jar = Path(located).setFileName("apksigner.jar");
			return true;
		}
		apksigner_jar = Path(located).append("lib/apksigner.jar");
		float buildtools_version = parse_float(located[located.depth() -1]);
		if (buildtools_version < 1 || located[located.depth() -2] != "build-tools") return false; // Finding android.jar is hopeless given this non-standard location to aapt.
		located.makeParent().makeParent().append("platforms");
		if (File(Path(located).append(format("android-%d", int(buildtools_version)))).exists()) {
			android_jar = located.append(format("android-%d/android.jar", int(buildtools_version)));
			return true;
		}
		throw Exception(format("unable to locate android.jar in %s", located.toString())); // For now we'll assume that the build tools version is the same as the platform directory containing android.jar, if we get reports that this isn't the case for people we can update this code to glob the platforms directory to find one instead.
	}
	void find_android_sdk_tools() {
		sign_cert = config.getString("build.android_signature_cert", Path::home() + ".nvgt_android.keystore");
		sign_password = config.getString("build.android_signature_password", "pass:android");
		java_command = resolve_java_tool("java");
		keytool_command = resolve_java_tool("keytool");
		jarsigner_command = resolve_java_tool("jarsigner");
		do_install = config.getInt("build.android_install", 1);
		string path = Path(config.getString("application.dir")).append("android-tools").toString() + Path::pathSeparator();
		path += Path(config.getString("application.dir")).append("android-tools/java17/bin").toString() + Path::pathSeparator();
		path += config.getString(Path::expand("build.android_path"), Environment::get("PATH"));
		if (android_sdk_tools_exist(path)) {
			Environment::set("PATH", path); // Encase the tools were in any of the custom paths we've just added.
			return;
		}
		string android_home = Path::expand(config.getString("build.android_home", Environment::get("ANDROID_HOME", Environment::get("ANDROID_SDK_HOME", ""))));
		// If we've still failed, maybe we can continue based on some default install locations?
		if (android_home.empty() && Environment::isWindows()) {
			File tmp = Environment::get("ProgramFiles(X86)", "C:\\Program Files (x86)") + "\\Android\\android-sdk"s; // Visual Studio installs android tools here as part of mobile development workload
			if (!tmp.exists()) tmp = Path::dataHome() + "Android\\sdk"; // Android Studio's default sdk install location
			if (tmp.exists()) android_home = tmp.path();
		} else if (android_home.empty() && Environment::os() == POCO_OS_MAC_OS_X) {
			File tmp = Path::expand("~/Library/Android/sdk"); // Android Studio's default sdk install location
			if (tmp.exists()) android_home = tmp.path();
		}
		if (android_home.empty()) throw Exception("unable to locate android development tools");
		// Unfortunately the android SDK might have multiple versions of the build tools, lets try selecting one. For now hopefully the newest, and if that breaks for people we can make it more restrictive.
		set<string> buildtools;
		Glob::glob(android_home + "/build-tools/*/aapt2*", buildtools);
		if (buildtools.empty()) throw Exception(format("Unable to find build-tools for android installation at %s", android_home));
		float selected_version = 0;
		string buildtools_bin;
		for (const std::string& i : buildtools) {
			Path tmp(i);
			tmp.makeParent();
			float ver = parse_float(tmp[tmp.depth() -1]);
			if (ver <= selected_version) continue; // newer already selected
			buildtools_bin = tmp.toString();
			selected_version = ver;
		}
		buildtools_bin += Path::pathSeparator();
		if (do_install) buildtools_bin += Path(android_home).append("platform-tools").toString() + Path::pathSeparator();
		if (!sign_cert.empty() && !sign_password.empty()) {
			Path tmp;
			string java_home = Path::expand(config.getString("build.android_java_home", Environment::get("JAVA_HOME", "")));
			if (!java_home.empty() && !File(java_command).exists() && !Path::find(path, exe("java"), tmp)) buildtools_bin += Path(java_home).append("bin").toString() + Path::pathSeparator();
		}
		path.insert(0, buildtools_bin);
		Environment::set("PATH", path);
		// For better or worse, we've done what we can and if we haven't found build tools by now the end user must have some real whacked out system or Android SDK installation.
		if (!android_sdk_tools_exist(path)) throw Exception(format("unable to find all Android development tools in detected SDK installation directories %s", buildtools_bin));
	}
	unsigned int parse_adb_devices_l(const string& line, string& device_description) {
		// Parses a line of output from `adb devices -l` and returns important information.
		StringTokenizer parts(line, " ");
		string host, model, product;
		unsigned int transport_id = 0;
		for (const string& part : parts) {
			if (host.empty()) host = part;
				else if (trim(part) == "offline") return 0;
			else if (part.starts_with("product:")) product = trim(part.substr(8));
			else if (part.starts_with("model:")) model = trim(part.substr(6));
			else if (part.starts_with("transport_id:")) transport_id = parse_float(trim(part.substr(13)));
		}
		if (!transport_id) return 0;
		if (product.empty() && model.empty()) device_description = host;
		else if (!product.empty() && !model.empty()) device_description = format("%s (%s)", model, product);
		else device_description = !product.empty()? product : model;
		return transport_id;
	}
	unsigned int get_install_device() {
		// Determine a device to install the generated APK to. If multiple devices are connected in debug mode, choose one if we can or else let the user select one.
		install_transport_id = 0;
		install_device_name.clear();
		string sout, serr;
		if (!system_command(exe("adb"), {"devices", "-l"}, sout, serr)) return 0;
		StringTokenizer cout_lines(sout, "\n");
		if (cout_lines.count() < 2) return 0; // no devices
		unsigned int transport_id;
		string device_description;
		vector<pair<string, unsigned int>> devices;
		for (const string& line : cout_lines) {
			transport_id = parse_adb_devices_l(line, device_description);
			if (!transport_id) continue;
			devices.push_back(make_pair(device_description, transport_id));
		}
		if (devices.empty()) return 0; // no available devices
		bool quiet = config.hasOption("application.quiet") || config.hasOption("application.QUIET");
		vector<string> buttons;
		for (auto d : devices) buttons.push_back(buttons.empty()? "`"s + d.first : d.first);
		buttons.push_back("~skip installation");
		int result = devices.size() == 1 && (do_install == 2 || quiet) ? 0 : nvgt_compile_message_box("install app", "1 or more Android devices are connected to this computer in debug mode. Would you like to install the generated APK on to one of these devices?", buttons) - 1;
		if (result < 0 || result >= (int)devices.size()) return 0; // installation skipped
		install_device_name = devices[result].first;
		return install_transport_id = devices[result].second;
	}
	// If the script requested a custom launcher icon via `#pragma icon`, replace the stub's
	// built-in ic_launcher resources inside res.zip before aapt2 link consumes it. Because
	// aapt2 link regenerates resources.arsc entirely from the flats we feed it, swapping the
	// compiled icon flats is enough — no need to touch the binary resources.arsc or manifest.
	void apply_custom_icon() {
		string icon_str = get_custom_icon_path();
		if (icon_str.empty()) return;
		Path icon_path = icon_str;
		set_status("applying custom app icon...");
		// aapt2 derives a resource's type and density from its parent directory name, so the icon
		// must live in a properly-named bucket. We use the highest density (xxxhdpi) as the single
		// source: it becomes the only mipmap/ic_launcher variant, so Android always downscales it
		// for lower-density screens (never upscales), keeping the icon crisp everywhere.
		string icon_src_dir = make_unique_temp_path(".iconsrc");
		Path bucket = Path(icon_src_dir).append("mipmap-xxxhdpi");
		File(bucket).createDirectories();
		string staged_icon = Path(bucket).append("ic_launcher.png").toString();
		File(icon_path).copyTo(staged_icon);
		// Compile the icon into an aapt2 .flat container.
		string flat_out = make_unique_temp_path(".iconflat");
		File(flat_out).createDirectories();
		string sout, serr;
		if (!system_command(exe("aapt2"), {"compile", staged_icon, "-o", flat_out}, sout, serr)) throw Exception(format("Failed to compile custom icon %s, %s%s", icon_path.toString(), sout, serr));
		// Rewrite res.zip: drop the stub's ic_launcher flats, add the freshly compiled one(s).
		string res_zip = Path(workplace.path()).append("res.zip").toString();
		string res_dir = make_unique_temp_path(".reszip");
		File(res_dir).createDirectories();
		libarchive_extract(res_zip, res_dir);
		vector<File> existing;
		File(res_dir).list(existing);
		for (const File& f : existing) {
			string name = Path(f.path()).makeFile().getFileName();
			if (name.find("ic_launcher") != string::npos && string_has_suffix(name, ".flat")) File(f.path()).remove();
		}
		vector<File> new_flats;
		File(flat_out).list(new_flats);
		for (const File& f : new_flats) File(f.path()).copyTo(Path(res_dir).append(Path(f.path()).makeFile().getFileName()).toString());
		File(res_zip).remove();
		struct archive* res_arc = archive_write_new();
		archive_write_set_format_zip(res_arc);
		archive_write_zip_set_compression_deflate(res_arc);
		archive_write_open_filename(res_arc, res_zip.c_str());
		archive_write_dir(res_arc, res_dir, "", {}, {}, true, true);
		archive_write_close(res_arc);
		archive_write_free(res_arc);
	}
protected:
	void alter_output_path(Path& output_path) override {
		is_aab = config.getString("build.android_format", "apk") == "aab";
		final_output_path = output_path;
		final_output_path.setExtension(is_aab ? "aab" : "apk");
		output_path = workplace.path();
		output_path.append("assets/bytecode.bin");
	}
	void copy_stub(const Path& stubpath, const Path& outpath) override {
		find_android_sdk_tools();
		workplace.createDirectories();
		libarchive_extract(stubpath.toString(), workplace.path());
		File(Path(workplace.path()).append("assets")).createDirectories();
		// Move root/ contents up one level so they sit at the APK zip root.
		// For AAB the root/ directory stays in place; it is packed under base/root/ in the AAB zip.
		if (!is_aab) {
			File root_dir(Path(workplace.path()).append("root"));
			if (root_dir.exists()) {
				vector<File> entries;
				root_dir.list(entries);
				for (const File& entry : entries)
					File(entry.path()).renameTo(Path(workplace.path()).append(Path(entry.path()).getFileName()).toString());
				root_dir.remove();
			}
		}
		// libgame.so already lives inside the extracted stub at lib/<abi>/ — the IAP stub (nvgt_android_iap.bin) carries
		// its IAP-enabled build under the very same name, so nothing here touches libgame. lib_android holds the dynamic
		// PLUGINS plus any shared libs those plugins register via nvgt_bundle_shared_library (e.g. BASS for legacy_sound).
		// Pick the ones this script actually uses out of lib_android/<abi>/ into the APK's lib/<abi>/, matching by substring
		// on the base name exactly like copy_shared_libraries() on desktop — so a registered name like "bass" also matches
		// its real file "libbass.so". Done for every ABI so each abi dir in the APK gets its own copies.
		string plugin_src_base = get_nvgt_lib_directory("android"); // .../lib_android; plugins + their shared deps live per-ABI beneath it.
		for (const string& abi : {"arm64-v8a", "armeabi-v7a"}) {
			Path plugin_dest = Path(workplace.path()).append(format("lib/%s", abi));
			if (plugin_src_base.empty() || !File(plugin_dest).exists()) continue;
			Path plugin_src = Path(plugin_src_base).append(abi);
			if (!File(plugin_src).exists()) continue;
			set<string> libs;
			Glob::glob(Path(plugin_src).append("*").toString(), libs, Glob::GLOB_DOT_SPECIAL | Glob::GLOB_FOLLOW_SYMLINKS | Glob::GLOB_CASELESS);
			for (const string& library : libs) {
				bool included = false;
				for (const string& l : g_bundle_libraries) if (Path(library).getBaseName().find(l) != string::npos) { included = true; break; }
				if (included) File(library).copyTo(plugin_dest.toString());
			}
		}
	}
	void open_output_stream(const Path& output_path) override {
		// bytecode.bin is a standalone file, not appended to a stub — open fresh.
		fs.open(output_path.toString(), std::ios::out | std::ios::trunc);
	}
	void finalize_output_stream() override {
		// bytecode.bin starts at offset 0, write 0 as the data location marker.
		BinaryWriter(fs) << int(0);
	}
	void finalize_product(Path& output_path) override {
		output_path = final_output_path;
		bundle_assets(Path(workplace.path()).append("assets"), Path(workplace.path()).append("assets"));
		// Prepare app label, package ID, and manifest substitution — common for both APK and AAB.
		string product_name = config.getString("build.product_name", Path(get_input_file()).getBaseName());
		config.setString("build.product_name", product_name);
		string product_identifier = config.getString("build.product_identifier", make_product_id());
		config.setString("build.product_identifier", product_identifier);
		FileInputStream input_manifest(config.getString("build.android_manifest", Path(workplace.path()).append("AndroidManifest.xml").toString()));
		string manifest;
		StreamCopier::copyToString(input_manifest, manifest);
		input_manifest.close();
		replaceInPlace(manifest, "%APP_LABEL%"s, product_name);
		if (g_script_uses_microphone && manifest.find("RECORD_AUDIO") == string::npos)
			replaceInPlace(manifest, "</manifest>"s, "    <uses-permission android:name=\"android.permission.RECORD_AUDIO\"/>\n</manifest>"s);
		FileOutputStream output_manifest(Path(workplace.path()).append("AndroidManifest.xml").toString());
		output_manifest.write(manifest.c_str(), manifest.size());
		output_manifest.close();
		string sout, serr;
		string version_code = config.getString("build.product_version_code", format("%u", uint32_t(Timestamp().epochTime()) / 60));
		string version_name = config.getString("build.product_version", "1.0");
		bool custom_manifest = !config.getString("build.android_manifest", "").empty();
		apply_custom_icon(); // swap the stub's launcher icon if #pragma icon was set; consumed by both the APK and AAB aapt2 link steps below.
		if (is_aab) {
			// --- Android App Bundle (AAB) path ---
			// 1. Run aapt2 link with --proto-format to create proto-format APK (contains resources.pb).
			set_status("creating AAB resources...");
			vector<string> aapt2args = {"link", "--proto-format", "-I", android_jar.toString(), "--manifest", "AndroidManifest.xml", "--rename-manifest-package", product_identifier, "--rename-resources-package", product_identifier, "--version-code", version_code, "--version-name", version_name, "res.zip", "-o", "proto.apk"};
			if (!custom_manifest) aapt2args.push_back("--replace-version");
			if (!system_command(exe("aapt2"), aapt2args, workplace.path(), sout, serr)) throw Exception(format("Failed to run aapt2 for AAB, %s%s", sout, serr));
			File(Path(workplace.path()).append("AndroidManifest.xml")).remove();
			File(Path(workplace.path()).append("res.zip")).remove();
			// 2. Extract proto.apk to get resources.pb and the proto-format manifest.
			string proto_dir = Path(workplace.path()).append("proto_extracted").toString();
			File(proto_dir).createDirectories();
			libarchive_extract(Path(workplace.path()).append("proto.apk").toString(), proto_dir);
			File(Path(workplace.path()).append("proto.apk")).remove();
			// 3. Build the AAB directly — a zip with BundleConfig.pb and all module content under base/.
			set_status("building AAB...");
			struct archive* aab_arc = archive_write_new();
			archive_write_set_format_zip(aab_arc);
			archive_write_zip_set_compression_deflate(aab_arc);
			archive_write_open_filename(aab_arc, output_path.toString().c_str());
			// BundleConfig.pb matching gradle/bundletool 1.18.1 output:
			//   field 1 (bundletool { version: "1.18.1" }), field 2 (compression defaults),
			//   field 3 (optimizations with uncompressed-file globs for media types).
			static const uint8_t bundle_config_pb[] = {
				0x0a,0x08,0x12,0x06,0x31,0x2e,0x31,0x38,0x2e,0x31,0x12,0x0a,0x0a,0x00,0x12,0x02,
				0x10,0x02,0x32,0x02,0x08,0x01,0x1a,0xf5,0x04,0x0a,0x09,0x2a,0x2a,0x2e,0x33,0x5b,
				0x67,0x47,0x5d,0x32,0x0a,0x0c,0x2a,0x2a,0x2e,0x33,0x5b,0x67,0x47,0x5d,0x5b,0x70,
				0x50,0x5d,0x0a,0x10,0x2a,0x2a,0x2e,0x33,0x5b,0x67,0x47,0x5d,0x5b,0x70,0x50,0x5d,
				0x5b,0x70,0x50,0x5d,0x0a,0x11,0x2a,0x2a,0x2e,0x33,0x5b,0x67,0x47,0x5d,0x5b,0x70,
				0x50,0x5d,0x5b,0x70,0x50,0x5d,0x32,0x0a,0x0f,0x2a,0x2a,0x2e,0x5b,0x61,0x41,0x5d,
				0x5b,0x61,0x41,0x5d,0x5b,0x63,0x43,0x5d,0x0a,0x0f,0x2a,0x2a,0x2e,0x5b,0x61,0x41,
				0x5d,0x5b,0x6d,0x4d,0x5d,0x5b,0x72,0x52,0x5d,0x0a,0x0f,0x2a,0x2a,0x2e,0x5b,0x61,
				0x41,0x5d,0x5b,0x77,0x57,0x5d,0x5b,0x62,0x42,0x5d,0x0a,0x0f,0x2a,0x2a,0x2e,0x5b,
				0x67,0x47,0x5d,0x5b,0x69,0x49,0x5d,0x5b,0x66,0x46,0x5d,0x0a,0x0f,0x2a,0x2a,0x2e,
				0x5b,0x69,0x49,0x5d,0x5b,0x6d,0x4d,0x5d,0x5b,0x79,0x59,0x5d,0x0a,0x0f,0x2a,0x2a,
				0x2e,0x5b,0x6a,0x4a,0x5d,0x5b,0x65,0x45,0x5d,0x5b,0x74,0x54,0x5d,0x0a,0x13,0x2a,
				0x2a,0x2e,0x5b,0x6a,0x4a,0x5d,0x5b,0x70,0x50,0x5d,0x5b,0x65,0x45,0x5d,0x5b,0x67,
				0x47,0x5d,0x0a,0x0f,0x2a,0x2a,0x2e,0x5b,0x6a,0x4a,0x5d,0x5b,0x70,0x50,0x5d,0x5b,
				0x67,0x47,0x5d,0x0a,0x0c,0x2a,0x2a,0x2e,0x5b,0x6d,0x4d,0x5d,0x34,0x5b,0x61,0x41,
				0x5d,0x0a,0x0c,0x2a,0x2a,0x2e,0x5b,0x6d,0x4d,0x5d,0x34,0x5b,0x76,0x56,0x5d,0x0a,
				0x0f,0x2a,0x2a,0x2e,0x5b,0x6d,0x4d,0x5d,0x5b,0x69,0x49,0x5d,0x5b,0x64,0x44,0x5d,
				0x0a,0x13,0x2a,0x2a,0x2e,0x5b,0x6d,0x4d,0x5d,0x5b,0x69,0x49,0x5d,0x5b,0x64,0x44,
				0x5d,0x5b,0x69,0x49,0x5d,0x0a,0x0f,0x2a,0x2a,0x2e,0x5b,0x6d,0x4d,0x5d,0x5b,0x6b,
				0x4b,0x5d,0x5b,0x76,0x56,0x5d,0x0a,0x0c,0x2a,0x2a,0x2e,0x5b,0x6d,0x4d,0x5d,0x5b,
				0x70,0x50,0x5d,0x32,0x0a,0x0c,0x2a,0x2a,0x2e,0x5b,0x6d,0x4d,0x5d,0x5b,0x70,0x50,
				0x5d,0x33,0x0a,0x0c,0x2a,0x2a,0x2e,0x5b,0x6d,0x4d,0x5d,0x5b,0x70,0x50,0x5d,0x34,
				0x0a,0x13,0x2a,0x2a,0x2e,0x5b,0x6d,0x4d,0x5d,0x5b,0x70,0x50,0x5d,0x5b,0x65,0x45,
				0x5d,0x5b,0x67,0x47,0x5d,0x0a,0x0f,0x2a,0x2a,0x2e,0x5b,0x6d,0x4d,0x5d,0x5b,0x70,
				0x50,0x5d,0x5b,0x67,0x47,0x5d,0x0a,0x0f,0x2a,0x2a,0x2e,0x5b,0x6f,0x4f,0x5d,0x5b,
				0x67,0x47,0x5d,0x5b,0x67,0x47,0x5d,0x0a,0x13,0x2a,0x2a,0x2e,0x5b,0x6f,0x4f,0x5d,
				0x5b,0x70,0x50,0x5d,0x5b,0x75,0x55,0x5d,0x5b,0x73,0x53,0x5d,0x0a,0x0f,0x2a,0x2a,
				0x2e,0x5b,0x70,0x50,0x5d,0x5b,0x6e,0x4e,0x5d,0x5b,0x67,0x47,0x5d,0x0a,0x17,0x2a,
				0x2a,0x2e,0x5b,0x72,0x52,0x5d,0x5b,0x74,0x54,0x5d,0x5b,0x74,0x54,0x5d,0x5b,0x74,
				0x54,0x5d,0x5b,0x6c,0x4c,0x5d,0x0a,0x0f,0x2a,0x2a,0x2e,0x5b,0x73,0x53,0x5d,0x5b,
				0x6d,0x4d,0x5d,0x5b,0x66,0x46,0x5d,0x0a,0x1b,0x2a,0x2a,0x2e,0x5b,0x74,0x54,0x5d,
				0x5b,0x66,0x46,0x5d,0x5b,0x6c,0x4c,0x5d,0x5b,0x69,0x49,0x5d,0x5b,0x74,0x54,0x5d,
				0x5b,0x65,0x45,0x5d,0x0a,0x0f,0x2a,0x2a,0x2e,0x5b,0x77,0x57,0x5d,0x5b,0x61,0x41,
				0x5d,0x5b,0x76,0x56,0x5d,0x0a,0x13,0x2a,0x2a,0x2e,0x5b,0x77,0x57,0x5d,0x5b,0x65,
				0x45,0x5d,0x5b,0x62,0x42,0x5d,0x5b,0x6d,0x4d,0x5d,0x0a,0x13,0x2a,0x2a,0x2e,0x5b,
				0x77,0x57,0x5d,0x5b,0x65,0x45,0x5d,0x5b,0x62,0x42,0x5d,0x5b,0x70,0x50,0x5d,0x0a,
				0x0f,0x2a,0x2a,0x2e,0x5b,0x77,0x57,0x5d,0x5b,0x6d,0x4d,0x5d,0x5b,0x61,0x41,0x5d,
				0x0a,0x0f,0x2a,0x2a,0x2e,0x5b,0x77,0x57,0x5d,0x5b,0x6d,0x4d,0x5d,0x5b,0x76,0x56,
				0x5d,0x0a,0x0f,0x2a,0x2a,0x2e,0x5b,0x78,0x58,0x5d,0x5b,0x6d,0x4d,0x5d,0x5b,0x66,
				0x46,0x5d,0x0a,0x1a,0x2a,0x2a,0x5b,0x74,0x54,0x5d,0x5b,0x66,0x46,0x5d,0x5b,0x6c,
				0x4c,0x5d,0x5b,0x69,0x49,0x5d,0x5b,0x74,0x54,0x5d,0x5b,0x65,0x45,0x5d
			};
			archive_write_memory(aab_arc, "BundleConfig.pb", bundle_config_pb, sizeof(bundle_config_pb));
			archive_write_single_file(aab_arc, Path(proto_dir).append("AndroidManifest.xml").toString(), "base/manifest/AndroidManifest.xml");
			archive_write_single_file(aab_arc, Path(proto_dir).append("resources.pb").toString(), "base/resources.pb");
			File proto_res(Path(proto_dir).append("res"));
			if (proto_res.exists())
				archive_write_dir(aab_arc, proto_res.path(), "base/res", {}, {}, true, true);
			{
				vector<File> root_entries;
				File(workplace.path()).list(root_entries);
				for (const File& f : root_entries) {
					string fname = Path(f.path()).makeFile().getFileName();
					if (fname.rfind("classes", 0) == 0 && fname.size() > 4 && fname.substr(fname.size()-4) == ".dex")
						archive_write_single_file(aab_arc, f.path(), "base/dex/" + fname);
				}
			}
			File lib_dir(Path(workplace.path()).append("lib"));
			if (lib_dir.exists())
				archive_write_dir(aab_arc, lib_dir.path(), "base/lib", {}, {}, true, true);
			archive_write_dir(aab_arc, Path(workplace.path()).append("assets").toString(), "base/assets", {}, {}, true, true);
			File root_dir(Path(workplace.path()).append("root"));
			if (root_dir.exists())
				archive_write_dir(aab_arc, root_dir.path(), "base/root", {}, {}, true, true);
			archive_write_close(aab_arc);
			archive_write_free(aab_arc);
			if (!sign_cert.empty() && !sign_password.empty()) {
				ensure_android_keystore();
				set_status("signing AAB...");
				sout = serr = "";
				if (!sign_android_aab(output_path.toString(), sout, serr))
					throw Exception(format("Failed to sign AAB, %s%s", sout, serr));
				strip_zip_posix_attrs(output_path.toString());
			}
		} else {
			// --- APK path ---
			set_status("creating APK structure...");
			vector<string> aapt2args = {"link", "-I", android_jar.toString(), "--manifest", "AndroidManifest.xml", "--rename-manifest-package", product_identifier, "--rename-resources-package", product_identifier, "--version-code", version_code, "--version-name", version_name, "res.zip", "-o", "tmp.apk"};
			if (!custom_manifest) aapt2args.push_back("--replace-version");
			if (!system_command(exe("aapt2"), aapt2args, workplace.path(), sout, serr)) throw Exception(format("Failed to run aapt2, %s%s", sout, serr));
			File(Path(workplace.path()).append("AndroidManifest.xml")).remove();
			File(Path(workplace.path()).append("res.zip")).remove();
			string tmp_apk_path = Path(workplace.path()).append("tmp.apk").toString();
			libarchive_extract(tmp_apk_path, workplace.path());
			File(tmp_apk_path).remove();
			set_status("packaging APK...");
			TemporaryFile zip_out_location;
			set<string> apk_store_arcs = {"resources.arsc"};
			for (const game_asset& g : g_game_assets)
				if (g.flags & GAME_ASSET_UNCOMPRESSED) apk_store_arcs.insert("assets/" + g.bundled_path);
			struct archive* apk_arc = archive_write_new();
			archive_write_set_format_zip(apk_arc);
			archive_write_zip_set_compression_deflate(apk_arc);
			archive_write_open_filename(apk_arc, zip_out_location.path().c_str());
			archive_write_dir(apk_arc, workplace.path(), "", {}, apk_store_arcs, true);
			archive_write_close(apk_arc);
			archive_write_free(apk_arc);
			set_status("aligning APK...");
			sout = serr = "";
			if (!system_command(exe("zipalign"), {"-f", "-p", "16", zip_out_location.path(), output_path.toString()}, sout, serr)) throw Exception(format("failed to run zipalign on %s", zip_out_location.path()));
			if (!sign_cert.empty() && !sign_password.empty()) {
				ensure_android_keystore();
				set_status("signing APK...");
				sout = serr = "";
				if (!system_command(java_command, {"-jar", apksigner_jar.toString(), "sign", "-ks", sign_cert, "--ks-pass", sign_password, "--key-pass", sign_password, output_path.toString()}, sout, serr)) throw Exception(format("Failed to run apksigner, %s%s", sout, serr));
			}
		}
	}
	void finalize() override {
		nvgt_compilation_output_impl::finalize(); // packages APK and shows success message
		if (is_aab || !do_install || !get_install_device()) return;
		set_status("installing APK...");
		Clock install_clock;
		string sout, serr;
		if (!system_command(exe("adb"), {"-t", format("%u", install_transport_id), "install", "-r", "-f", get_output_file()}, sout, serr)) throw Exception(format("Unable to install APK onto %s, %s", install_device_name, serr));
		nvgt_compile_message_box("Success!", format("The application %s (%s) was installed on %s in %ums.", config.getString("build.product_name"), config.getString("build.product_identifier"), install_device_name, uint32_t(install_clock.elapsed() / 1000)), {"`OK"});
	}
};
nvgt_compilation_output* nvgt_init_compilation(const string& input_file, bool auto_prepare) {
	nvgt_compilation_output* output;
	if (g_platform == "windows") output = new nvgt_compilation_output_windows(input_file);
	else if (g_platform == "mac") output = new nvgt_compilation_output_mac(input_file);
	else if (g_platform == "linux") output = new nvgt_compilation_output_linux(input_file);
	else if (g_platform == "android") output = new nvgt_compilation_output_android(input_file);
	else if (g_platform == "ios") output = new nvgt_compilation_output_ios(input_file);
	else output = new nvgt_compilation_output_impl(input_file);
	
	// Ensure stubs can be found in development environments.
	if (!File(Path(Util::Application::instance().config().getString("application.dir", "")).append("stub")).exists()) {
		Path dev_stub = Path(Util::Application::instance().commandPath()).makeParent().append("stub");
		if (File(dev_stub).exists()) Util::Application::instance().config().setString("application.dir", dev_stub.makeParent().toString());
	}

	if (auto_prepare) output->prepare();
	return output;
}

#elif defined(NVGT_MOBILE)
void add_game_asset_to_bundle(const std::string& path, int flags) {} // Make this a linkable no-op on mobile.
#endif // !NVGT_STUB
