/* sound_service.cpp - sound service implementation code written by Caturria
 * This is responsible for providing miniaudio with data to play from various sources, from an encrypted pack file to a custom stream from the internet.
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

#include "sound_service.h"
#include "xplatform.h" // NVGT_MOBILE
#include <Poco/Exception.h>
#include <new> // std::bad_alloc
#include <Poco/Net/NetException.h>
#include <Poco/UnicodeConverter.h>
#include <SDL3/SDL_filesystem.h>
#include <SDL3/SDL_system.h>
#ifdef _WIN32
#include <Poco/UnWindows.h>
#else
#include <cerrno>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif
#include <Poco/URIStreamOpener.h>
#include <vector>
#include <cctype>
#include <cassert>
#include <miniaudio.h>
#include "crypto.h"
#include "datastreams.h" // sdl_file_stream, prebuffer_istream
#include "misc_functions.h" // is_valid_utf8
#include "pack.h"
#include <Poco/StringTokenizer.h>
#include <Poco/NumberFormatter.h>
#include <Poco/MemoryStream.h>
#include <Poco/NumberParser.h>
#include <sstream>
#include <iostream>
#include <unordered_map>
#include <mutex>
#include <atomic>
#include <functional>

/**
 * The VFS is the glue between the sound service and MiniAudio.
 * We have an opaque structure -- in this case a pointer to the sound_service implementation -- and a series of callbacks which provide MiniAudio an interface to it.
 */
struct sound_service_vfs {
	ma_vfs_callbacks callbacks;
	sound_service *service;
};
#define vfs_cast(x) \
	sound_service_vfs *vfs = static_cast<sound_service_vfs *>(x); \
	if (vfs == NULL) \
	{ \
		return MA_ERROR; \
	}
#define file_cast(x) \
	std::istream *stream = static_cast<std::istream *>(x); \
	if (stream == NULL) \
	{ \
		return MA_ERROR; \
	}

#ifdef _WIN32
quiet_file_errors::quiet_file_errors() {
	DWORD was = 0;
	set = SetThreadErrorMode(SEM_FAILCRITICALERRORS | SEM_NOOPENFILEERRORBOX, &was);
	previous = was;
}
quiet_file_errors::~quiet_file_errors() {
	if (set) SetThreadErrorMode(previous, nullptr);
}
#else
quiet_file_errors::quiet_file_errors() {}
quiet_file_errors::~quiet_file_errors() {}
#endif
// Why a protocol couldn't open what it was asked for, for the VFS open to report, on the thread that opens it.
static thread_local ma_result t_open_error = MA_ERROR;
// Why a file couldn't be opened to read, as the encoders tell for the files they write: SDL, which opens it, keeps no errno, so that every failure but a missing file read "Unknown error". It's opened again as SDL opens it, where SDL looked for it, for the system's error; a directory is told first, as POSIX opens one to read. Opened through Poco instead, which shares writing, a file another program was writing opened there, and read as unknown again.
static ma_result read_open_failure(const char* uri) {
	std::string path = uri;
	if (path.empty()) return MA_INVALID_ARGS;
#if defined(__ANDROID__)
	// SDL looks for a relative name in the app's internal storage, then among its packaged assets, which can't be asked why: not in the current directory, which is the root there.
	if (path[0] != '/') {
		if (path.compare(0, 10, "content://") == 0) return MA_ERROR;
		const char* internal = SDL_GetAndroidInternalStoragePath();
		if (!internal) return MA_DOES_NOT_EXIST;
		path = std::string(internal) + "/" + path;
	}
#elif defined(__APPLE__)
	// SDL opens a name from the app's resources should it be there, and as given otherwise.
	if (const char* resources = SDL_GetBasePath()) {
		std::string bundled = std::string(resources) + path;
		struct stat st;
		if (stat(bundled.c_str(), &st) == 0) path = bundled;
	}
#endif
#ifdef _WIN32
	std::wstring wide;
	try {
		Poco::UnicodeConverter::toUTF16(path, wide);
	} catch (const std::exception&) {
		return MA_ERROR;
	}
	quiet_file_errors quiet; // As SDL opens files: the box held the loading thread, a load job's or one holding the cache's lock.
	const DWORD attributes = GetFileAttributesW(wide.c_str());
	if (attributes == INVALID_FILE_ATTRIBUTES) return system_error_result(int(GetLastError()));
	if (attributes & FILE_ATTRIBUTE_DIRECTORY) return MA_IS_DIRECTORY;
	HANDLE file = CreateFileW(wide.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr); // SDL's access and sharing: a file another program writes, which SDL shares no writing with, reads as access denied.
	if (file == INVALID_HANDLE_VALUE) return system_error_result(int(GetLastError()));
	CloseHandle(file);
#else
	struct stat st;
	if (stat(path.c_str(), &st) != 0) return system_error_result(errno); // A directory the process may not search reads as access denied rather than missing.
	if (S_ISDIR(st.st_mode)) return MA_IS_DIRECTORY;
	if (!S_ISREG(st.st_mode) && !S_ISFIFO(st.st_mode)) return MA_INVALID_ARGS; // A device or socket, which SDL refuses once it opens it: a name that isn't of a file, and not INVALID_FILE (see onOpen).
	const int file = open(path.c_str(), O_RDONLY | O_NONBLOCK | O_CLOEXEC); // Not waiting for a writer to a FIFO.
	if (file < 0) return system_error_result(errno);
	close(file);
#endif
	return MA_ERROR; // It opens now: what stopped SDL is gone, or wasn't the file.
}
class sound_service_impl : public sound_service {
	/**
	 * Default protocol which loads files directly from the file system.
	 */
	class fs_protocol : public sound_service::protocol {
		static const fs_protocol instance;

	public:
		static const protocol *get_instance() {
			return &instance;
		}
		virtual std::istream *open_uri(const char *uri, const directive_t directive) const {
			sdl_file_input_stream* stream;
			try {
				stream = new sdl_file_input_stream(uri);
#ifdef _WIN32
				// A device, such as CON, which "con.ogg" in any folder names too on Windows 10: SDL checks for one only on other platforms, and a load then waited on console input, on the script's thread or a load job's, for good. Refused as SDL refuses one there.
				if (HANDLE handle = (HANDLE)SDL_GetPointerProperty(SDL_GetIOProperties(stream->nativeHandle()), SDL_PROP_IOSTREAM_WINDOWS_HANDLE_POINTER, nullptr)) {
					if (GetFileType(handle) == FILE_TYPE_CHAR) {
						delete stream;
						t_open_error = MA_INVALID_ARGS; // As a device on other platforms (see read_open_failure()), not INVALID_FILE (see onOpen).
						return NULL;
					}
				}
#endif
				return stream;
			} catch (std::exception &) {
				t_open_error = read_open_failure(uri); // Why, for the load to report: MiniAudio's VFS open had only MA_ERROR, "Unknown error", even for the most common failure, a file that isn't there.
				return NULL;
			}
		}
		virtual const std::string get_suffix(const directive_t &directive) const {
			return "fs";
		}
	};
	/**
	 * Default filter which performs no filtering at all and just passes its input through untouched.
	 */
	class null_filter : public filter {
		static const null_filter instance;

	public:
		static const filter *get_instance() {
			return &instance;
		}
		virtual std::istream *wrap(std::istream &source, const directive_t directive) const {
			return &source;
		}
	};

	// A template for registering protocols and filters with the sound service, along with directives and other metadata.
	template <class t>
	class service_registration {
		const t *item;
		directive_t directive; // Arbitrary data that will be sent to the filter or protocol (such as a decryption key), always use atomic operations to access.
		size_t slot;

	public:
		service_registration(const t *item, size_t slot)
			: directive() {
			this->item = item;
			this->slot = slot;
		}
		inline const t *get() const {
			return item;
		}
		inline const directive_t get_directive() const {
			return std::atomic_load_explicit(&directive, std::memory_order_acquire);
		}
		inline void set_directive(const directive_t &directive) {
			std::atomic_store_explicit(&this->directive, directive, std::memory_order_release);
		}
		inline const size_t get_slot() const {
			return slot;
		}
	};
	typedef service_registration<protocol> protocol_reg_t;
	typedef std::shared_ptr<protocol_reg_t> protocol_registration;
	typedef service_registration<filter> filter_reg_t;
	typedef std::shared_ptr<filter_reg_t> filter_registration;
	std::vector<protocol_registration> protocols;
	protocol_registration default_protocol; // Always access with atomic operations!
	typedef std::vector<filter_registration> filter_array;
	filter_array filters;
	filter_registration default_filter; // Always access with atomic operations!
	sound_service_vfs vfs;
	// Each load that prepares a triplet cleans it up once; several loading the same file at once share one entry, which only the last cleanup removes, so it isn't gone while another of them still opens the file.
	struct temp_args_entry {
		vfs_args args;
		int users;
	};
	typedef std::unordered_map<std::string, temp_args_entry> temp_args_t;
	temp_args_t temp_args;
	std::mutex temp_args_mtx;
	std::atomic<unsigned long long> own_entries{0}; // Numbers the triplets prepared with own_entry.
	bool set_temp_args(const std::string &triplet, const vfs_args &args) {
		std::unique_lock<std::mutex> lock(temp_args_mtx);
		auto added = temp_args.try_emplace(triplet, temp_args_entry{args, 0});
		added.first->second.users++;
		return added.second;
	}
	bool get_temp_args(const std::string &triplet, vfs_args &dest) {
		std::unique_lock<std::mutex> lock(temp_args_mtx);
		temp_args_t::iterator i = temp_args.find(triplet);
		if (i == temp_args.end())
			return false;
		dest = i->second.args;
		return true;
	}
public:
	sound_service_impl()
		: protocols(),
		  filters() {
		// Protocol slot zero means use default, so insert a fake/ null registration there to force real slots to start at one.
		protocols.push_back(nullptr);
		size_t slot = 0;
		register_protocol(fs_protocol::get_instance(), slot);
		set_default_protocol(slot);
		assert(slot == fs_protocol_slot);
		// Filters also have a special null slot at zero:
		filters.push_back(nullptr);
		register_filter(null_filter::get_instance(), slot);
		set_default_filter(slot);
		assert(slot == null_filter_slot);
		// Assemble the VFS, which gets passed to MiniAudio so that it can interface with this.
		vfs.service = this;
		vfs.callbacks.onClose = onClose;
		vfs.callbacks.onInfo = onInfo;
		vfs.callbacks.onOpen = onOpen;
		vfs.callbacks.onOpenW = NULL; // Todo: do we need this?
		vfs.callbacks.onRead = onRead;
		vfs.callbacks.onSeek = onSeek;
		vfs.callbacks.onTell = onTell;
		vfs.callbacks.onWrite = NULL;
	}
	virtual ~sound_service_impl() {
	}
	bool register_protocol(const sound_service::protocol *proto, size_t &slot) {
		try {
			protocols.push_back(std::make_shared<protocol_reg_t>(proto, protocols.size()));
			slot = protocols.size() - 1;
			return true;
		} catch (const std::exception&) {
			return false;
		}
	}
	bool register_filter(const sound_service::filter *the_filter, size_t &slot) {
		try {
			filters.push_back(std::make_shared<filter_reg_t>(the_filter, filters.size()));
			slot = filters.size() - 1;
			return true;
		} catch (std::exception &) {
			return false;
		}
	}

	bool set_default_protocol(size_t slot) {
		if (slot >= protocols.size())
			return false;
		std::atomic_store(&default_protocol, protocols[slot]);
		return true;
	}
	const protocol *get_protocol(size_t slot) {
		if (slot < 0 || slot >= protocols.size())
			return nullptr;
		return protocols[slot]->get();
	}
	const protocol *get_default_protocol() {
		return std::atomic_load(&default_protocol)->get();
	}
	bool is_default_protocol(size_t slot) {
		if (slot < 0 || slot >= protocols.size())
			return false;
		return protocols[slot] == std::atomic_load(&default_protocol);
	}
	bool set_default_filter(size_t slot) {
		if (slot < 0 || slot >= filters.size())
			return false;
		std::atomic_store(&default_filter, filters[slot]);
		return true;
	}
	bool is_default_filter(size_t slot) {
		if (slot < 0 || slot >= filters.size())
			return false;
		return filters[slot] == std::atomic_load(&default_filter);
	}
	bool set_protocol_directive(size_t slot, const directive_t &new_directive) {
		if (slot < 0 || slot >= protocols.size())
			return false;
		protocols[slot]->set_directive(new_directive);
		return true;
	}
	const directive_t get_protocol_directive(size_t slot) const {
		if (slot < 0 || slot >= protocols.size())
			return nullptr;
		return protocols[slot]->get_directive();
	}
	bool set_filter_directive(size_t slot, const directive_t &new_directive) {
		if (slot < 0 || slot >= filters.size())
			return false;
		filters[slot]->set_directive(new_directive);
		return true;
	}
	std::string prepare_triplet(const std::string &name, const size_t protocol_slot, const directive_t protocol_directive, const size_t filter_slot, directive_t filter_directive, bool own_entry, unsigned salt) {
		if (protocol_slot >= protocols.size())
			return "";
		if (name.empty()) // No name, which the file protocol took as the current directory, refused as one that isn't valid UTF-8 is.
			return "";
		if (!is_valid_utf8(name) || name.find('\x1e') != std::string::npos) // Nor the separator itself, so that every triplet stands for one name, slot and suffix.
			return "";
		vfs_args args;
		protocol_registration preg;
		// Slot zero means use default:
		preg = (protocol_slot == 0 ? std::atomic_load(&default_protocol) : protocols[protocol_slot]);
		args.name = name;
		args.protocol_slot = preg->get_slot();
		args.protocol_directive = protocol_directive == nullptr ? preg->get_directive() : protocol_directive;
		// Filter selection.
		filter_registration freg;
		// Filter slot zero means use default:
		freg = (filter_slot == 0 ? std::atomic_load(&default_filter) : filters[filter_slot]);
		args.filter_slot = freg->get_slot();
		args.filter_directive = (filter_directive == nullptr ? freg->get_directive() : filter_directive);
		// Build our triplet. This is the name that will actually be remembered by MiniAudio's resource manager.
		std::stringstream triplet;
		const std::string suffix = preg->get()->get_suffix(args.protocol_directive);
		// A file from the file system stands for the file the name reaches from the current directory: its name alone made a relative name loaded from another directory share the buffer MiniAudio cached for the file it reached before while that buffer was held, playing the wrong file. A file rewritten while a sound loaded from it lives still shares that sound's buffer, as before: telling it apart would cost every load, cached ones included, a look at the file.
		const bool from_fs = preg->get() == fs_protocol::get_instance();
		const std::string key_name = from_fs? absolute_file_name(name) : name;
		if (key_name.find('\x1e') != std::string::npos) // As for the name: a current directory holding the separator.
			return "";
#ifndef NVGT_MOBILE
		if (from_fs) args.name = key_name; // The file opened is the one the key names, should another thread change the current directory before it is opened. Not on Android and iOS, whose files packaged with the app SDL finds by their relative name, in the package or the app bundle.
#endif
		const std::string filter_suffix = freg->get()->get_suffix(args.filter_directive);
		if (filter_suffix.find('\x1e') != std::string::npos)
			return "";
		if (suffix.find('\x1e') != std::string::npos) // As for the name, so that the parts after it, an own entry's number or a salt, can't be read as part of it.
			return "";
		triplet << key_name
		        << "\x1e"
		        << args.protocol_slot
		        << "\x1e"
		        << suffix;
		if (!filter_suffix.empty()) triplet << "\x1e#" << args.filter_slot << ":" << filter_suffix; // A file decoded through one key shares nothing with a load through another, which would otherwise have played it without its key being checked.
		if (own_entry) triplet << "\x1e" << ++own_entries;
		if (salt) triplet << "\x1e~" << salt;
		std::string made = triplet.str(); // Once: a second copy, returned after the entry was made, could throw, as on running out of memory, with nobody given the name to clean the entry up by.
		set_temp_args(made, args);

		return made;
	}
	std::istream *open_triplet(const char *triplet, size_t filter_slot = 0, const directive_t filter_directive = nullptr) {
		// Get our VFS args back.
		vfs_args args;
		if (!get_temp_args(triplet, args))
			return nullptr;
		const protocol *proto = protocols[args.protocol_slot]->get();
		std::istream *result = proto->open_uri(args.name.c_str(), args.protocol_directive);

		if (!result) return nullptr;
		try {
			return apply_filter(result, args.filter_slot, args.filter_directive);
		} catch (...) { // Not taken by a filter that threw making its own stream.
			delete result;
			throw;
		}
	}
	bool cleanup_triplet(const std::string &triplet) {
		std::unique_lock<std::mutex> lock(temp_args_mtx);
		temp_args_t::iterator i = temp_args.find(triplet);
		if (i == temp_args.end())
			return false;
		if (--i->second.users <= 0) temp_args.erase(i);
		return true;
	}
	std::istream *apply_filter(std::istream *source, size_t filter_slot = 0, const directive_t filter_directive = nullptr) {
		if (source == NULL)
			return NULL;
		const filter *f = filters[filter_slot]->get();
		std::istream *filtered = f->wrap(*source, filter_directive);
		// For now just return the raw source if the filter rejects it.
		// Todo: decide how we want to handle filter rejection. Should it pass through? reject the source outright? Make this configurable globally at the sound service level? Or let filters handle it case by case via directive?
		if (filtered == nullptr) {
			source->clear(); // The filter's probe may have read past the end of a short file, which leaves seekg() doing nothing.
			source->seekg(0);
			return source;
		}
		return filtered;
	}

	sound_service_vfs *get_vfs() {
		return &vfs;
	}

private:
	// Callbacks that glue MiniAudio to the sound service.

	static ma_result onOpen(ma_vfs *pVFS, const char *pFilePath, ma_uint32 openMode, ma_vfs_file *pFile) {
		vfs_cast(pVFS);
		t_open_error = MA_ERROR;
		std::istream *file = nullptr;
		// Nothing thrown back into MiniAudio, which calls this on its job threads for an asynchronous load or a stream, where a throw, as on running out of memory or from a plugin's pack, ended the program.
		try {
			file = vfs->service->open_triplet(pFilePath);
		} catch (const std::bad_alloc&) {
			return MA_OUT_OF_MEMORY;
		} catch (...) {
			return MA_ERROR;
		}
		if (file == NULL) {
			// Not found, as the file protocol tells, or not permitted, etc. Never as a decoder's failure, INVALID_FILE or NO_BACKEND: a load takes those as said of a file it read, retries it without flags and unregisters the name from MiniAudio's cache, which for a name never read in returns without unlocking that cache, so that every later load hung.
			return t_open_error == MA_INVALID_FILE || t_open_error == MA_NO_BACKEND? MA_ERROR : t_open_error;
		}
		*pFile = file;

		return MA_SUCCESS;
	}
	static ma_result onClose(ma_vfs *pVFS, ma_vfs_file file) {

		file_cast(file);
		delete stream;

		return MA_SUCCESS;
	}
	static ma_result onRead(ma_vfs *pVFS, ma_vfs_file file, void *pDst, size_t sizeInBytes, size_t *pBytesRead) {
		if (pBytesRead) *pBytesRead = 0;
		file_cast(file);
		// Only a real end of stream stops a read; a failbit left behind by a refused seek (a live stream refuses seeks it can't satisfy) must not be mistaken for one.
		if (stream->eof()) return MA_AT_END;
		if (!stream->good()) stream->clear();
		stream->read((char *)pDst, sizeInBytes);
		if (pBytesRead) *pBytesRead = stream->gcount();
		return stream->gcount() > 0? MA_SUCCESS : MA_AT_END;
	}
	static ma_result onSeek(ma_vfs *pVFS, ma_vfs_file file, ma_int64 offset, ma_seek_origin origin) {
		file_cast(file);
		stream->clear();
		std::ios_base::seekdir dir;
		switch (origin) {
			case ma_seek_origin_start:
				dir = stream->beg;
				break;
			case ma_seek_origin_current:
				dir = stream->cur;
				break;
			case ma_seek_origin_end:
				dir = stream->end;
				break;
			default: // Should never get here.
				return MA_ERROR;
		}
		stream->seekg(offset, dir);
		if (stream->fail()) {
			stream->clear(); // the reads that follow still need this stream, so leave it usable
			return MA_NOT_IMPLEMENTED;
		}
		return MA_SUCCESS;
	}
	static ma_result onTell(ma_vfs *pVFS, ma_vfs_file file, ma_int64 *pCursor) {
		file_cast(file);
		stream->clear(); // tellg refuses to answer on a failed stream, and the failure may not be its own
		ma_int64 result = stream->tellg();
		*pCursor = result != -1? result : 0;
		if (result == -1) {
			stream->clear();
			return MA_NOT_IMPLEMENTED;
		}
		return MA_SUCCESS;
	}
	static ma_result onInfo(ma_vfs *pVFS, ma_vfs_file file, ma_file_info *pInfo) {
		file_cast(file);
		stream->clear();
		pInfo->sizeInBytes = 0;
		std::streampos cursor = stream->tellg();
		if (cursor == std::streampos(-1)) return MA_NOT_IMPLEMENTED; // A stream that can't tell where it is couldn't be put back there after finding its end, and -1 read as a size near 2^64.
		stream->seekg(0, stream->end);
		std::streampos end = stream->fail()? std::streampos(-1) : stream->tellg();
		stream->clear();
		stream->seekg(cursor); // Back where it was, whether or not that worked, should a stream have moved before failing the seek.
		stream->clear();
		if (end == std::streampos(-1)) return MA_NOT_IMPLEMENTED;
		pInfo->sizeInBytes = static_cast<ma_uint64>(std::streamoff(end));
		return MA_SUCCESS;
	}
};

std::unique_ptr<sound_service> sound_service::make() {
	try {
		return std::make_unique<sound_service_impl>();
	} catch (std::exception &) {
		throw std::runtime_error("Unable to create the sound service.");
	}
}
sound_service::sound_service() {
}
sound_service::~sound_service() {
}
const sound_service_impl::fs_protocol sound_service_impl::fs_protocol::instance;
const sound_service_impl::null_filter sound_service_impl::null_filter::instance;

// ChaCha encryption sound service filter
const sound_service::filter *encryption_filter::get_instance() {
	return &instance;
}
encryption_filter::encryption_filter() {
}
std::string encryption_filter::get_suffix(const directive_t &directive) const {
	const std::shared_ptr<const std::string> key = std::static_pointer_cast<const std::string>(directive);
	if (key == nullptr || key->empty()) return "";
	// A hash of the key, not the key, as the triplet is kept in MiniAudio's tables: FNV-1a, 64 bits on every build, where std::hash is 32 where size_t is, so that two keys shared a decrypted buffer once in 2^32 pairs.
	Poco::UInt64 hash = 14695981039346656037ull;
	for (unsigned char c : *key) {
		hash ^= c;
		hash *= 1099511628211ull;
	}
	return Poco::NumberFormatter::formatHex(hash);
}
std::istream *encryption_filter::wrap(std::istream &source, const directive_t directive) const {
	// Key is expected to have been passed in through the directive interface.
	const std::shared_ptr<const std::string> key = std::static_pointer_cast<const std::string>(directive);
	if (key == nullptr)
		return &source;
	try {
		return &(new chacha_istream(source, *key))->own_source(true);
	} catch (std::exception &) {
		// Not encrypted or not valid.
		return nullptr;
	}
}
std::istream *encryption_filter::source_of(std::istream *stream) {
	const chacha_istream *decrypted = dynamic_cast<const chacha_istream *>(stream);
	return decrypted? decrypted->get_source() : stream;
}
encryption_filter encryption_filter::instance;

// Memory buffer sound service protocol implementation
static std::atomic<uint64_t> next_memory_id = 0;
struct memory_args {
	const void *data;
	size_t size;
	uint64_t id; // Prevents caching by resource manager.
};

std::istream *memory_protocol::open_uri(const char *uri, const directive_t directive) const {
	// This proto doesn't care about the URI itself.
	std::shared_ptr<const memory_args> args = std::static_pointer_cast<const memory_args>(directive);
	if (args == nullptr)
		return nullptr;
	return new Poco::MemoryInputStream((const char *)args->data, args->size);
}
const std::string memory_protocol::get_suffix(const directive_t &directive) const {
	std::shared_ptr<const memory_args> args = std::static_pointer_cast<const memory_args>(directive);
	if (args == nullptr)
		return "error"; // As open_uri() refuses it, and the pack protocol names it.
	return Poco::NumberFormatter::format(args->id);
}
directive_t memory_protocol::directive(const void *data, size_t size) {
	std::shared_ptr<memory_args> args = std::make_shared<memory_args>();
	args->data = data;
	args->size = size;
	args->id = next_memory_id++;
	return args;
}
const memory_protocol memory_protocol::instance;
const sound_service::protocol *memory_protocol::get_instance() {
	return &instance;
}

// pack file sound service protocol
std::istream *pack_protocol::open_uri(const char *uri, const directive_t directive) const {
	std::shared_ptr<const pack_interface> obj = std::static_pointer_cast<const pack_interface>(directive);
	if (obj == nullptr)
		return nullptr;
	std::istream *item = obj->get_file(uri);
	if (!item) { // A name an NVGT pack doesn't hold, for the load to report as the file protocol reports a missing file; not one it holds whose file couldn't be opened again, nor whatever a plugin's pack, which can't be asked, failed for.
		const pack* nvgt_pack = dynamic_cast<const pack*>(obj.get());
		if (nvgt_pack && nvgt_pack->get_is_active() && !nvgt_pack->file_exists(uri)) t_open_error = MA_DOES_NOT_EXIST;
	}
	return item;
}
// What tells the pack's contents apart: an NVGT pack's identity, which its name alone, as given to open(), didn't for a pack of that name in another directory or rewritten since, nor for two packs embedded in one file; a plugin's pack's name, and for one that gives none, a suffix no other load gets, so its loads share no buffer with any other.
const std::string pack_protocol::get_suffix(const directive_t &directive) const {
	std::shared_ptr<const pack_interface> obj = std::static_pointer_cast<const pack_interface>(directive);
	if (obj == nullptr)
		return "error";
	if (const pack* own = dynamic_cast<const pack*>(obj.get())) return own->get_identity();
	const std::string name = obj->get_pack_name();
	if (!name.empty()) return absolute_file_name(name); // As a file's: two packs of one relative name in different directories shared buffers.
	static std::atomic<uint64_t> unnamed_packs{0};
	return "\x1f" + std::to_string(++unnamed_packs);
}
const pack_protocol pack_protocol::instance;
const sound_service::protocol *pack_protocol::get_instance() {
	return &instance;
}

// internet stream sound service protocol, combining Poco::UriStreamOpener with our prebuffer_istream.
// Why a URL couldn't be opened, where every failure read "Unknown error".
static ma_result url_open_failure(const Poco::Exception& e) {
	if (dynamic_cast<const Poco::Net::ConnectionRefusedException*>(&e)) return MA_CONNECTION_REFUSED;
	if (dynamic_cast<const Poco::Net::DNSException*>(&e)) return MA_NO_HOST;
	if (dynamic_cast<const Poco::TimeoutException*>(&e)) return MA_TIMEOUT;
	if (dynamic_cast<const Poco::UnknownURISchemeException*>(&e)) return MA_PROTOCOL_NOT_SUPPORTED;
	if (dynamic_cast<const Poco::Net::HTTPException*>(&e)) { // By the reason, which is what Poco keeps of the response, at the start of its message, the URL following it: searched for in the whole message, a URL with one of these words in it gave that error for any response. In any case and wording, as servers phrase it their own way, "File not found" among them.
		std::string reason = e.message().substr(0, e.message().find(": "));
		for (char& c : reason) c = (char)std::tolower((unsigned char)c);
		auto says = [&reason](const char* words) { return reason.find(words) != std::string::npos; };
		if (says("not found") || says("gone")) return MA_DOES_NOT_EXIST;
		if (says("forbidden") || says("unauthorized") || says("denied")) return MA_ACCESS_DENIED;
	}
	return MA_ERROR;
}
std::istream *netstream_protocol::open_uri(const char *uri, const directive_t directive) const {
	try {
		std::istream *stream = Poco::URIStreamOpener::defaultOpener().open(uri);
		if (!stream) return nullptr; // Likely invalid URI. Figure out how to provide info about this to user?
		try {
			return &(new prebuffer_istream(*stream))->own_source();
		} catch (...) { // Nothing else owns it yet.
			delete stream;
			throw;
		}
	} catch (const Poco::Exception& e) {
		t_open_error = url_open_failure(e);
	} catch (std::exception&) {} // Again figure out how to let user see exception details.
	return nullptr;
}
const std::string netstream_protocol::get_suffix(const directive_t &directive) const { return "URI"; }
const netstream_protocol netstream_protocol::instance;
const sound_service::protocol *netstream_protocol::get_instance() { return &instance; }
