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
#include <vs_version.h>
#endif
#include "bundling.h"
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
static void archive_write_dir(struct archive* a, const string& disk_dir, const string& arc_prefix, const set<string>& exec_paths, const set<string>& store_paths, bool zip) {
	vector<File> entries;
	File(disk_dir).list(entries);
	for (const File& f : entries) {
		string name = Path(f.path()).makeFile().getFileName();
		string arc = arc_prefix.empty() ? name : arc_prefix + "/" + name;
		struct archive_entry* e = archive_entry_new();
		archive_entry_set_pathname(e, arc.c_str());
		archive_entry_set_mtime(e, f.getLastModified().epochTime(), 0);
		if (f.isDirectory()) {
			archive_entry_set_filetype(e, AE_IFDIR);
			archive_entry_set_perm(e, 0755);
			archive_entry_set_size(e, 0);
			archive_write_header(a, e);
			archive_entry_free(e);
			archive_write_dir(a, f.path(), arc, exec_paths, store_paths, zip);
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
		Path stubpath = config.getString("application.dir");
		stubpath.pushDirectory("stub");
		xplatform_correct_path_to_stubs(stubpath);
		alter_stub_path(stubpath);
		stubpath = format("%snvgt_%s%s%s.bin", stubpath.toString(), platform, (stub != "" ? string("_") + stub : ""), (g_script_uses_iap ? string("_iap") : string("")));
		string outpath_str = config.getString("build.output_basename", format("%s", Path(input_file).setExtension("").makeAbsolute().toString()));
		replaceInPlace(outpath_str, "$platform"s, platform);
		if (DirectoryExists(outpath_str)) File(outpath_str).remove(true); // Though some platforms must do indipendantly after extra modification, we still attempt to clean previous builds for generic outputs here so that a linux build won't output overtop a windows one leaving both an elf and an executable binary in the same place, for example.
		outpath = outpath_str;
		if (outpath.isRelative()) outpath.makeAbsolute();
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
	void finalize_product(Path& output_path) override {
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
		string mic_usage = config.getString("build.NSMicrophoneUsageDescription", "");
		if (!mic_usage.empty()) plist_dict_set_item(plist, "NSMicrophoneUsageDescription", plist_new_string(mic_usage.c_str()));
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
		plist_dict_set_item(plist, "CFBundleIdentifier", plist_new_string(product_identifier.c_str()));
		plist_dict_set_item(plist, "LSRequiresIPhoneOS", plist_new_bool(1));
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
		string mic_usage = config.getString("build.NSMicrophoneUsageDescription", "");
		if (!mic_usage.empty()) plist_dict_set_item(plist, "NSMicrophoneUsageDescription", plist_new_string(mic_usage.c_str()));
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
			// Write iTunesMetadata.plist to the IPA root.
			plist_t meta = plist_new_dict();
			plist_dict_set_item(meta, "bundleDisplayName", plist_new_string(product_name.c_str()));
			plist_dict_set_item(meta, "bundleShortVersionString", plist_new_string(config.getString("build.product_version", "1.0").c_str()));
			plist_dict_set_item(meta, "bundleVersion", plist_new_string(config.getString("build.product_version_code", "1.0").c_str()));
			plist_dict_set_item(meta, "fileExtension", plist_new_string(".app"));
			plist_dict_set_item(meta, "itemName", plist_new_string(product_name.c_str()));
			plist_dict_set_item(meta, "product-type", plist_new_string("ios-app"));
			plist_dict_set_item(meta, "softwareVersionBundleId", plist_new_string(product_identifier.c_str()));
			char* meta_xml; uint32_t meta_len;
			if (plist_to_xml(meta, &meta_xml, &meta_len) != PLIST_ERR_SUCCESS) throw Exception("Unable to create iTunesMetadata.plist");
			plist_free(meta);
			FileOutputStream meta_out(Path(ipa_root).append("iTunesMetadata.plist").toString());
			meta_out.write(meta_xml, meta_len);
			meta_out.close();
			plist_mem_free(meta_xml);
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
			archive_write_dir(out_arc, extracted_dir, "", {}, {}, true);
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
		// Rename libgame_iap.so → libgame.so (IAP stub uses a different module name during NDK build to avoid conflicts).
		for (const string& abi : {"arm64-v8a", "armeabi-v7a"}) {
			File iap_lib(Path(workplace.path()).append(format("lib/%s/libgame_iap.so", abi)));
			if (iap_lib.exists())
				iap_lib.renameTo(Path(workplace.path()).append(format("lib/%s/libgame.so", abi)).toString());
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
		FileOutputStream output_manifest(Path(workplace.path()).append("AndroidManifest.xml").toString());
		output_manifest.write(manifest.c_str(), manifest.size());
		output_manifest.close();
		string sout, serr;
		string version_code = config.getString("build.product_version_code", format("%u", uint32_t(Timestamp().epochTime()) / 60));
		string version_name = config.getString("build.product_version", "1.0");
		bool custom_manifest = !config.getString("build.android_manifest", "").empty();
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
				archive_write_dir(aab_arc, proto_res.path(), "base/res", {}, {}, true);
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
				archive_write_dir(aab_arc, lib_dir.path(), "base/lib", {}, {}, true);
			archive_write_dir(aab_arc, Path(workplace.path()).append("assets").toString(), "base/assets", {}, {}, true);
			File root_dir(Path(workplace.path()).append("root"));
			if (root_dir.exists())
				archive_write_dir(aab_arc, root_dir.path(), "base/root", {}, {}, true);
			archive_write_close(aab_arc);
			archive_write_free(aab_arc);
			if (!sign_cert.empty() && !sign_password.empty()) {
				ensure_android_keystore();
				set_status("signing AAB...");
				sout = serr = "";
				if (!sign_android_aab(output_path.toString(), sout, serr))
					throw Exception(format("Failed to sign AAB, %s%s", sout, serr));
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
	if (auto_prepare) output->prepare();
	return output;
}

#elif defined(NVGT_MOBILE)
void add_game_asset_to_bundle(const std::string& path, int flags) {} // Make this a linkable no-op on mobile.
#endif // !NVGT_STUB
