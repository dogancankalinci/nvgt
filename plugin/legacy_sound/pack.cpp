/* pack.cpp - legacy pack file implementation code
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

#include <errno.h>
#include <obfuscate.h>
#include <Poco/FileStream.h>
#include <Poco/Format.h>
#include <Poco/StreamCopier.h>
#include <Poco/Thread.h>
#include <Poco/Util/Application.h>
#ifndef _WIN32
	#include <sys/stat.h>
	#include <unistd.h>
#else
	#include <windows.h>
	#include <io.h>
#endif
#include "config.h"
#define NVGT_PLUGIN_INCLUDE
#include "../../src/nvgt_plugin.h"
#include "pack.h"

using namespace std;

// A global property that allows a scripter to set the pack identifier for all subsequently created packs.
static std::string g_pack_ident = "NVPK";

#ifdef _WIN32
// A path as UTF-16. NVGT's strings are UTF-8, and fopen/CreateFileA read a path in the ANSI code page: one with any other character (a
// user folder with a Turkish or German name, say) didn't open, and a new pack got a garbled name. The fixed 1024-character buffer this
// replaces was left without its terminator by a longer path, which GetFileAttributesW then read past.
static std::wstring pack_wide_path(const string& path) {
	int n = path.empty() ? 0 : MultiByteToWideChar(CP_UTF8, 0, path.data(), (int)path.size(), NULL, 0);
	std::wstring result(n > 0 ? n : 0, L'\0');
	if (n > 0) MultiByteToWideChar(CP_UTF8, 0, path.data(), (int)path.size(), &result[0], n);
	return result;
}
#endif
static FILE* pack_fopen(const string& path, const char* mode) {
	if (path.empty()) return NULL;
	#ifdef _WIN32
	std::wstring wide_mode(mode, mode + strlen(mode));
	FILE* f = _wfopen(pack_wide_path(path).c_str(), wide_mode.c_str());
	// An existing file found by its ANSI name, as before (only to open one: a new file gets its right name).
	if (!f && mode[0] == 'r') f = fopen(path.c_str(), mode);
	return f;
	#else
	return fopen(path.c_str(), mode);
	#endif
}

bool NVGTFileExists(const string& path) {
	#ifdef _WIN32
	// Check if the path exists and is a directory
	DWORD attrib = GetFileAttributesW(pack_wide_path(path).c_str());
	if (attrib == INVALID_FILE_ATTRIBUTES || (attrib & FILE_ATTRIBUTE_DIRECTORY))
		return false;
	return true;
	#else
	// Check if the path exists and is a file
	struct stat st;
	if (stat(path.c_str(), &st) == -1)
		return false;
	if ((st.st_mode & S_IFDIR) != 0)
		return false;
	return true;
	#endif
	return false;
}

legacy_pack::legacy_pack() {
	fptr = NULL;
	mptr = NULL;
	pack_items.clear();
	pack_filenames.clear();
	pack_streams.clear();
	current_filename = "";
	set_pack_identifier(g_pack_ident);
	next_stream_idx = 0;
	open_mode = PACK_OPEN_MODE_NONE;
	delay_close = false;
	file_offset = 0;
	mptr_size = 0;
	RefCount = 1;
}
void legacy_pack::AddRef() {
	asAtomicInc(RefCount);
}
void legacy_pack::Release() {
	if (asAtomicDec(RefCount) < 1) {
		close();
		delete this;
	}
}

// Sets the 8 byte header used when loading and saving packs.
bool legacy_pack::set_pack_identifier(const std::string& ident) {
	if (ident == "") return false;
	pack_ident = ident;
	if (pack_ident.size() > 8) pack_ident.resize(8);
	while (pack_ident.size() < 8) pack_ident += '\0';
	return true;
}
// Loads or creates the given pack file based on mode.
bool legacy_pack::open(const string& filename_in, pack_open_mode mode, bool memload) {
	if (fptr || mptr) {
			if (!close()) return false; // A pack file is already opened and was unable to close, maybe some sounds are actively playing from it.
		}
	if (mode <= PACK_OPEN_MODE_NONE || mode >= PACK_OPEN_MODES_TOTAL)
		return false; // Invalid mode.
	// Every failure leaves the pack closed. The handle was closed but kept: is_active() was true after a failed open, the next open or
	// the pack's release closed it again (a double fclose: heap corruption where fclose frees the FILE, and on Windows, where the CRT
	// reuses it, the closing of whichever file was opened next, another pack's for one), and the offset of an embedded pack stayed for
	// the next open.
	auto fail = [this]() {
		if (fptr) fclose(fptr);
		fptr = NULL;
		pack_items.clear();
		pack_filenames.clear();
		file_offset = 0;
		return false;
	};
	string filename = filename_in;
	uint64_t pack_size;
	file_offset = 0;
	if (find_embedded_pack(filename, file_offset, pack_size) && mode != PACK_OPEN_MODE_READ) return fail();
	if (mode == PACK_OPEN_MODE_APPEND && !NVGTFileExists(filename))
		mode = PACK_OPEN_MODE_CREATE;
	if (mode == PACK_OPEN_MODE_CREATE) {
		// Read and write: delete_file() reads the items after the one it removes to move them, which a "wb" handle couldn't, so in a
		// pack being created it (and add_file()/add_memory() replacing an item) failed after forgetting the item, and the pack closed
		// with the last item's place given to the deleted one.
		fptr = pack_fopen(filename, "wb+");
		if (fptr == NULL)
			return fail();
		pack_header h;
		memset(&h, 0, sizeof(pack_header));
		memcpy(&h, &pack_ident[0], 8);
		h.filecount = 0;
		if (fwrite(&h, sizeof(pack_header), 1, fptr) != 1)
			return fail();
		current_filename = filename;
		open_mode = mode;
		return true;
	} else if (mode == PACK_OPEN_MODE_APPEND || mode == PACK_OPEN_MODE_READ) {
		fptr = pack_fopen(filename, mode == PACK_OPEN_MODE_APPEND ? "rb+" : "rb");
		if (!fptr)
			return fail();
		unsigned int total_size = 0;
		#ifdef _WIN32
		total_size = filelength(fileno(fptr));
		#else
		struct stat st;
		if (fstat(fileno(fptr), &st) == 0)
			total_size = st.st_size;
		#endif
		fseek(fptr, file_offset, SEEK_SET);
		if (file_offset > 0) { // Embedded pack, size provided.
			total_size = pack_size;
		}
		pack_header h;
		if (!fread(&h, sizeof(pack_header), 1, fptr))
			return fail();
		if (memcmp(h.ident, &pack_ident[0], 8) != 0)
			return fail();
		for (unsigned int c = 0; c < h.filecount; c++) {
			pack_item i;
			memset(&i, 0, sizeof(pack_item));
			if (fread(&i, sizeof(unsigned int), 3, fptr) < 3)
				return fail();
			// The sizes are checked before the name gets room: a damaged header's length allocated up to 4 GB first.
			if ((i.filesize * i.namelen * 2) != i.magic || i.namelen > total_size || i.filesize > total_size)
				return fail();
			string fn(i.namelen, '\0');
			if (fread(&fn[0], 1, i.namelen, fptr) < i.namelen)
				return fail();
			i.offset = ftell(fptr) - file_offset;
			pack_items[fn] = i;
			pack_filenames.push_back(fn);
			fseek(fptr, i.filesize, SEEK_CUR);
		}
		// Perform any extra read/append initialization
		if (mode == PACK_OPEN_MODE_READ && memload) {
			mptr = (unsigned char*)malloc(total_size);
			// Read only ("rb+" left a read-only pack out of memory), and only what was read counts: the reads from memory stop there
			// as the reads from the file stop at its end.
			FILE* mtmp = mptr ? pack_fopen(filename, "rb") : NULL;
			if (mtmp) {
				fseek(mtmp, file_offset, SEEK_SET);
				mptr_size = fread(mptr, 1, total_size, mtmp);
				fclose(mtmp);
			} else {
				free(mptr);
				mptr = NULL;
			}
		}
	}
	current_filename = filename;
	open_mode = mode;
	return true;
}

bool legacy_pack::close() {
	while (delay_close) Poco::Thread::sleep(5);
	delay_close = false;
	// Held for the whole teardown: a sound being cached on another thread reads through
	// read_file_locked(), which takes this same lock, so the handle cannot be closed underneath
	// a read in progress.
	std::lock_guard<std::mutex> g(streams_mutex);
	bool ret = false;
	if (fptr && (open_mode == PACK_OPEN_MODE_APPEND || open_mode == PACK_OPEN_MODE_CREATE)) {
		pack_header h;
		memset(&h, 0, sizeof(pack_header));
		memcpy(h.ident, &pack_ident[0], 8);
		h.filecount = pack_items.size();
		fseek(fptr, 0, SEEK_SET);
		ret = fwrite(&h, sizeof(pack_header), 1, fptr) == 1;
	} else
		ret = true;
	// For a pack being written, what was left in the FILE's buffer reaches the disk here (a full disk fails only now).
	if (fptr && fclose(fptr) != 0 && open_mode != PACK_OPEN_MODE_READ)
		ret = false;
	pack_items.clear();
	pack_filenames.clear();
	pack_streams.clear();
	current_filename = "";
	file_offset = 0;
	//next_stream_idx=0;
	open_mode = PACK_OPEN_MODE_NONE;
	fptr = NULL;
	if (mptr)
		free(mptr);
	mptr = NULL;
	mptr_size = 0;
	return ret;
}

// Adds a file from disk to the pack. Returns false if disk filename doesn't exist or can't be read, pack_filename is already an item in the pack and allow_replace is false, or this object is not opened in append/create mode.
bool legacy_pack::add_file(const string& disk_filename, const string& pack_filename, bool allow_replace) {
	if (!fptr || file_offset > 0)
		return false;
	if (open_mode != PACK_OPEN_MODE_APPEND && open_mode != PACK_OPEN_MODE_CREATE)
		return false;
	if (!NVGTFileExists(disk_filename))
		return false;
	if (file_exists(pack_filename)) {
		if (allow_replace)
			delete_file(pack_filename);
		else
			return false;
	}
	FILE* dptr = pack_fopen(disk_filename, "rb");
	if (!dptr)
		return false;
	unsigned int cur_pos = ftell(fptr);
	pack_item i;
	memset(&i, 0, sizeof(pack_item));
	i.namelen = pack_filename.size();
	i.offset = cur_pos + i.namelen + (sizeof(unsigned int) * 3);
	if (fwrite(&i, sizeof(unsigned int), 3, fptr) < 3) {
		fseek(fptr, cur_pos, SEEK_SET);
		fclose(dptr);
		return false;
	}
	if (fwrite(pack_filename.c_str(), sizeof(char), i.namelen, fptr) < i.namelen) {
		fseek(fptr, cur_pos, SEEK_SET);
		fclose(dptr);
		return false;
	}
	unsigned char read_buffer[4096];
	while (true) {
		unsigned int dataread = fread(read_buffer, 1, 4096, dptr);
		if (dataread < 1)
			break;
		for (unsigned int j = 0; j < dataread; j++)
			read_buffer[j] = pack_char_encrypt(read_buffer[j], i.filesize + j, i.namelen);
		if (fwrite(read_buffer, 1, dataread, fptr) != dataread) { // a full disk: the item would claim data that isn't there
			fclose(dptr);
			fseek(fptr, cur_pos, SEEK_SET);
			return false;
		}
		i.filesize += dataread;
		if (dataread < 4096)
			break;
	}
	fclose(dptr);
	fseek(fptr, cur_pos, SEEK_SET);
	i.magic = i.filesize * i.namelen * 2;
	if (fwrite(&i, sizeof(unsigned int), 3, fptr) < 3) {
		fseek(fptr, cur_pos, SEEK_SET);
		return false; // dptr is closed already (it was closed a second time here)
	}
	fseek(fptr, 0, SEEK_END);
	pack_items[pack_filename] = i;
	pack_filenames.push_back(pack_filename);
	return true;
}

bool legacy_pack::add_memory(const string& pack_filename, unsigned char* data, unsigned int size, bool allow_replace) {
	if ((open_mode != PACK_OPEN_MODE_APPEND && open_mode != PACK_OPEN_MODE_CREATE) || !fptr || file_offset > 0)
		return false;
	if (file_exists(pack_filename)) {
		if (allow_replace)
			delete_file(pack_filename);
		else
			return false;
	}
	unsigned int cur_pos = ftell(fptr);
	pack_item i;
	memset(&i, 0, sizeof(pack_item));
	i.filesize = size;
	i.namelen = pack_filename.size();
	i.magic = i.filesize * i.namelen * 2;
	i.offset = cur_pos + i.namelen + (sizeof(unsigned int) * 3);
	if (fwrite(&i, sizeof(unsigned int), 3, fptr) < 3) {
		fseek(fptr, cur_pos, SEEK_SET);
		return false;
	}
	if (fwrite(pack_filename.c_str(), sizeof(char), i.namelen, fptr) < i.namelen) {
		fseek(fptr, cur_pos, SEEK_SET);
		return false;
	}
	char tmp[1024];
	int bufsize = 1024; // Keep at multiple of 16 for encryption.
	for (uint64_t p = 0; p < size; p += bufsize) {
		if (p + bufsize >= size) bufsize = size - p;
		for (unsigned int j = 0; j < bufsize; j++)
			tmp[j] = pack_char_encrypt(data[p + j], p + j, i.namelen);
		if (fwrite(tmp, 1, bufsize, fptr) != bufsize) {
			fseek(fptr, cur_pos, SEEK_SET);
			return false;
		}
	}
	fseek(fptr, 0, SEEK_END);
	pack_items[pack_filename] = i;
	pack_filenames.push_back(pack_filename);
	return true;
}
// Adds memory, but getting data from a C++ string.
bool legacy_pack::add_memory(const string& pack_filename, const string& data, bool allow_replace) {
	return add_memory(pack_filename, (unsigned char*)data.c_str(), data.size(), allow_replace);
}

// Deletes a file from the pack if it exists, and returns true on success. This operation is usually highly intensive, and if you must do it over and over again, it's best to just recompile your pack. If this function returns false, and you are sure your arguments are correct, you can consider that your pack file is now probably corrupt. This should only happen if the pack contains invalid headers or incomplete file data in the first place.
bool legacy_pack::delete_file(const string& pack_filename) {
	if (open_mode != PACK_OPEN_MODE_APPEND && open_mode != PACK_OPEN_MODE_CREATE || !fptr || file_offset > 0)
		return false;
	unsigned int idx = 0;
	for (idx = 0; idx < pack_filenames.size(); idx++) {
		if (pack_filenames[idx] == pack_filename)
			break;
	}
	if (idx >= pack_filenames.size())
		return false;
	unsigned int oldblock = pack_items[pack_filename].namelen + pack_items[pack_filename].filesize + (sizeof(unsigned int) * 3);
	unsigned int oldnlen = pack_items[pack_filename].namelen;
	unsigned int oldoff = pack_items[pack_filename].offset;
	pack_items.erase(pack_filename);
	pack_filenames.erase(pack_filenames.begin() + idx);
	unsigned char tmp[4096];
	unsigned int new_eof = oldoff - oldnlen - (sizeof(unsigned int) * 3);
	for (unsigned int i = idx; i < pack_filenames.size(); i++) {
		pack_item item = pack_items[pack_filenames[i]];
		unsigned int total_bytesread = 0;
		while (total_bytesread < item.filesize) {
			fseek(fptr, item.offset + total_bytesread, SEEK_SET);
			unsigned int bytes_to_read = 4096;
			if (item.filesize - total_bytesread < 4096)
				bytes_to_read = item.filesize - total_bytesread;
			unsigned int bytesread = fread(tmp, sizeof(unsigned char), bytes_to_read, fptr);
			if (bytesread < bytes_to_read)
				return false; // something went really wrong!
			fseek(fptr, item.offset + total_bytesread - oldblock, SEEK_SET);
			fwrite(tmp, sizeof(unsigned char), bytesread, fptr);
			total_bytesread += bytesread;
		}
		new_eof = ftell(fptr);
		pack_items[pack_filenames[i]].offset -= oldblock;
		item.offset -= oldblock;
		fseek(fptr, item.offset - item.namelen - (sizeof(unsigned int) * 3), SEEK_SET);
		fwrite(&item, sizeof(unsigned int), 3, fptr);
		fwrite(pack_filenames[i].c_str(), 1, item.namelen, fptr);
		char tmp_idx[3];
		//new_eof+=total_bytesread+item.namelen+(sizeof(unsigned int)*3);
	}
	// This sucks...
	//new_eof-=oldblock-oldsize;
	fflush(fptr); // the moved items are in the file before it is cut
	#ifdef _WIN32
	HANDLE hFile = CreateFileW(pack_wide_path(current_filename).c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) // what CreateFile returns on failure (this tested for NULL)
		return true; // At this point the operation has completed, but we couldn't set the new eof. Hopefully a new file being added to the pack gets a chance to overwrite the new existing deleted data...
	SetFilePointer(hFile, new_eof, NULL, FILE_BEGIN);
	SetEndOfFile(hFile);
	CloseHandle(hFile);
	fclose(fptr);
	fptr = pack_fopen(current_filename, "rb+");
	if (!fptr) {
		close(); // We couldn't reopen the file after delete, and so we must entirely close the pack in this unfortunate case.
		return false;
	}
	#else
	ftruncate(fileno(fptr), new_eof);
	#endif
	fseek(fptr, 0, SEEK_END);
	return true;
}

bool legacy_pack::file_exists(const string& pack_filename) {
	return pack_items.find(pack_filename) != pack_items.end();
}

unsigned int legacy_pack::get_file_name(int idx, char* buffer, unsigned int size) {
	if (idx < 0 || idx >= pack_filenames.size())
		return 0;
	if (!buffer || size <= pack_filenames[idx].size())
		return pack_filenames[idx].size() + 1;
	size = pack_filenames[idx].size();
	strncpy(buffer, pack_filenames[idx].c_str(), size);
	buffer[size] = '\0';
	return size;
}
string legacy_pack::get_file_name(int idx) {
	if (idx < 0 || idx >= pack_filenames.size())
		return "";
	return pack_filenames[idx];
}
// The type of the string arrays list_files() returns, looked up once when the plugin registers its functions. Looked up on every
// call, the lookup ran on the script's thread with no lock while a build on another thread could add template instances to the
// engine's list it walks (NVGT's own lookups take its build lock, see get_array_type(), which a plugin can't reach). Plugins are
// loaded only while the engine is set up, before any script runs, and the declarations registered below made the type.
static asITypeInfo* g_pack_string_array_type = nullptr;
CScriptArray* legacy_pack::list_files() {
	unsigned int count = pack_filenames.size();
	CScriptArray* array = CScriptArray::Create(g_pack_string_array_type);
	array->Reserve(count);
	for (int i = 0; i < count; i++)
		array->InsertLast(&pack_filenames[i]);
	return array;
}

unsigned int legacy_pack::get_file_size(const string& pack_filename) {
	if (pack_items.find(pack_filename) != pack_items.end())
		return pack_items[pack_filename].filesize;
	else
		return 0;
}

unsigned int legacy_pack::get_file_offset(const string& pack_filename) {
	if (pack_items.find(pack_filename) != pack_items.end())
		return file_offset + pack_items[pack_filename].offset;
	else
		return 0;
}

unsigned int legacy_pack::read_file(const string& pack_filename, unsigned int offset, unsigned char* buffer, unsigned int size, FILE* reader) {
	if (pack_items.find(pack_filename) == pack_items.end()) return 0;
	unsigned int item_size = pack_items[pack_filename].filesize;
	if (offset >= item_size)
		return 0;
	unsigned int bytes_to_read = size;
	if (size > item_size - offset) // not offset + size > item_size, which wrapped for a size near 4 GB and read past the item
		bytes_to_read = item_size - offset;
	if (!buffer)
		return bytes_to_read;
	if (open_mode == PACK_OPEN_MODE_READ && mptr) {
		// A pack shorter than its items say (cut off while it was copied) has less in memory than they claim, and the copy read past
		// the end of the allocation: only what is there, as a read from the file gives.
		uint64_t start = (uint64_t)pack_items[pack_filename].offset + offset;
		if (start >= mptr_size) return 0;
		if (bytes_to_read > mptr_size - start) bytes_to_read = (unsigned int)(mptr_size - start);
		memcpy(buffer, mptr + start, bytes_to_read);
		for (unsigned int i = 0; i < bytes_to_read; i++)
			buffer[i] = pack_char_decrypt(buffer[i], offset + i, pack_items[pack_filename].namelen);
		return bytes_to_read;
	}
	if (!reader)
		reader = fptr;
	if (open_mode != PACK_OPEN_MODE_READ || !reader || pack_items.find(pack_filename) == pack_items.end())
		return 0;
	fseek(reader, file_offset + pack_items[pack_filename].offset + offset, SEEK_SET);
	unsigned int dataread = fread(buffer, 1, bytes_to_read, reader);
	for (unsigned int i = 0; i < dataread; i++)
		buffer[i] = pack_char_decrypt(buffer[i], offset + i, pack_items[pack_filename].namelen);
	return dataread;
}
// Reads from the pack's own file handle under the streams lock, so several threads loading
// sounds at once cannot interleave their seeks and reads on the shared FILE*.
unsigned int legacy_pack::read_file_locked(const string& pack_filename, unsigned int offset, unsigned char* buffer, unsigned int size) {
	std::lock_guard<std::mutex> g(streams_mutex);
	return read_file(pack_filename, offset, buffer, size, NULL);
}
std::string legacy_pack::read_file_string(const string& pack_filename, unsigned int offset, unsigned int size) {
	// Only as much room as can be read (a count of 0xffffffff, "the rest", allocated 4 GB first).
	std::string result(read_file_locked(pack_filename, offset, nullptr, size), '\0');
	if (result.empty()) return result;
	result.resize(read_file_locked(pack_filename, offset, (unsigned char*)&result[0], (unsigned int)result.size()));
	return result;
}

// Function to force the file pointer for the open pack to seek by a relative position either from the beginning or the end of the file. This function should only be used if you are absolutely sure you know what you are doing, incorrect usage will lead to corrupt packs. If offset is negative, seek from the end, else from the beginning.
bool legacy_pack::raw_seek(int offset) {
	if (!fptr)
		return false;
	if (offset < 0)
		return fseek(fptr, offset, SEEK_END) == 0;
	else
		return fseek(fptr, offset, SEEK_SET) == 0; // fseek's 0 is success: this returned false for every seek that worked
}

// Closes an opened stream, basically freeing it's structure of data.
bool legacy_pack::stream_close(pack_stream* stream, bool while_reading) {
	if (stream->reading) {
		stream->close = true;
		std::lock_guard<std::mutex> g(streams_mutex);
		pack_streams.find(stream->stridx) != pack_streams.end()&&pack_streams.erase(stream->stridx);
		return true;
	}
	bool ret;
	{
		std::lock_guard<std::mutex> g(streams_mutex);
		ret = !while_reading & pack_streams.find(stream->stridx) != pack_streams.end() && pack_streams.erase(stream->stridx);
	}
	stream->stridx = 0;
	if (stream->reader)
		fclose(stream->reader);
	delete stream;
	Release();
	return ret;
}
// The script's calls find their stream under the streams lock: stream_open() and stream_close() change the map from the threads that
// load and free sounds, and a lookup during that walked it unlocked.
pack_stream* legacy_pack::find_stream(unsigned int idx) {
	std::lock_guard<std::mutex> g(streams_mutex);
	auto it = pack_streams.find(idx);
	return it == pack_streams.end() ? NULL : it->second;
}
bool legacy_pack::stream_close_script(unsigned int idx) {
	pack_stream* stream = find_stream(idx);
	if (!stream)
		return false;
	return stream_close(stream);
}

// Creates a pack_stream structure for the given filename at the given offset. Pack streams are simple structures meant to expidite the process of sequentially reading from a file in the pack. Returns 0xffffffff on failure.
pack_stream* legacy_pack::stream_open(const string& pack_filename, unsigned int offset) {
	if (pack_filename == "")
		return NULL;
	auto item = pack_items.find(pack_filename);
	if (item == pack_items.end())
		return NULL;
	unsigned int size = item->second.filesize;
	pack_stream* s = new pack_stream();
	s->filename = pack_filename;
	s->offset = offset;
	s->filesize = size;
	s->item_offset = item->second.offset;
	s->namelen = item->second.namelen;
	s->read_pos = -1;
	s->reading = false;
	s->close = false;
	if (!mptr) {
		s->reader = pack_fopen(current_filename, "rb");
		if (!s->reader) {
			delete s; // was left allocated
			return NULL;
		}
	} else
		s->reader = NULL;
	{
		std::lock_guard<std::mutex> g(streams_mutex);
		pack_streams[next_stream_idx] = s;
		s->stridx = next_stream_idx;
		next_stream_idx += 1;
	}
	AddRef();
	return s;
}
unsigned int legacy_pack::stream_open_script(const string& pack_filename, unsigned int offset) {
	pack_stream* stream = stream_open(pack_filename, offset);
	if (stream) return stream->stridx;
	else return 0xffffffff;
}

// Reads bytes from a stream and increments it's offset by the number of bytes read. Returns the number of bytes read on success, 0xffffffff (-1) on failure either do to end of file or invalid stream.
unsigned int legacy_pack::stream_read(pack_stream* stream, unsigned char* buffer, unsigned int size) {
	stream->reading = true;
	unsigned int bytesread = stream_read_fast(stream, buffer, size);
	stream->reading = false;
	bool close = stream->close;
	if (stream->close)
		stream_close(stream);
	if (bytesread == 0xffffffff)
		return 0xffffffff;
	if (!close)
		stream->offset += bytesread;
	return bytesread;
}
// Hot path for BASS file reads: uses the offset/namelen cached at stream_open time (no
// per-read filename hashing) and skips the fseek on sequential reads - each stream owns its
// FILE*, so its position is entirely ours to track. Decryption goes through the regular
// pack_char_decrypt interface so this works with any config.h implementation.
unsigned int legacy_pack::stream_read_fast(pack_stream* stream, unsigned char* buffer, unsigned int size) {
	unsigned int offset = stream->offset;
	if (offset >= stream->filesize)
		return 0;
	unsigned int bytes_to_read = size;
	if (size > stream->filesize - offset) // not offset + size > filesize, which wrapped for a size near 4 GB and read past the item
		bytes_to_read = stream->filesize - offset;
	if (!buffer)
		return bytes_to_read;
	unsigned int dataread = 0;
	if (open_mode == PACK_OPEN_MODE_READ && mptr) {
		uint64_t start = (uint64_t)stream->item_offset + offset; // only what is in memory, as in read_file()
		if (start >= mptr_size) return 0;
		if (bytes_to_read > mptr_size - start) bytes_to_read = (unsigned int)(mptr_size - start);
		memcpy(buffer, mptr + start, bytes_to_read);
		dataread = bytes_to_read;
	} else {
		// Only ever the stream's own handle: this path runs without the streams lock, while
		// read_file_locked() seeks the pack's shared fptr under it, so borrowing that handle
		// here would let two reads interleave their seeks and return another member's bytes.
		FILE* reader = stream->reader;
		if (open_mode != PACK_OPEN_MODE_READ || !reader)
			return 0;
		long want = (long)(file_offset + stream->item_offset + offset);
		if (stream->read_pos != want)
			fseek(reader, want, SEEK_SET);
		dataread = fread(buffer, 1, bytes_to_read, reader);
		stream->read_pos = want + (long)dataread;
	}
	for (unsigned int i = 0; i < dataread; i++)
		buffer[i] = pack_char_decrypt(buffer[i], offset + i, stream->namelen);
	return dataread;
}
unsigned int legacy_pack::stream_read_script(unsigned int idx, unsigned char* buffer, unsigned int size) {
	pack_stream* stream = find_stream(idx);
	if (!stream)
		return 0xffffffff;
	return stream_read(stream, buffer, size);
}
std::string legacy_pack::stream_read_string(unsigned int idx, unsigned int size) {
	pack_stream* stream = find_stream(idx);
	if (!stream)
		return ""; // nothing for a stream that isn't open
	// Only as much room as is left in the stream (a count of 0xffffffff, "the rest", allocated 4 GB first).
	unsigned int left = stream->offset < stream->filesize ? stream->filesize - stream->offset : 0;
	std::string result(size < left ? size : left, '\0');
	unsigned int actual_size = stream_read(stream, (unsigned char*)result.data(), (unsigned int)result.size());
	result.resize(actual_size == 0xffffffff ? 0 : actual_size); // only what was read
	return result;
}

// Seeks within a stream. We're using the exact same argument convention actually as fseek here, origin means the same thing. In this case though, we return true on success, not 0.
// The offset is relative to the origin and can be negative, as fseek's is. It was unsigned: SEEK_END, which needs a negative offset,
// never succeeded, and SEEK_CUR couldn't go back. The position reached must be within the item, as before.
bool legacy_pack::stream_seek(pack_stream* stream, long long offset, int origin) {
	long long base;
	if (origin == SEEK_SET)
		base = 0;
	else if (origin == SEEK_CUR)
		base = stream->offset;
	else if (origin == SEEK_END)
		base = stream->filesize;
	else
		return false;
	long long target = base + offset;
	if (target < 0 || target >= (long long)stream->filesize)
		return false;
	stream->offset = (unsigned int)target;
	if (!mptr && stream->reader)
		stream->read_pos = -1; // The next read repositions itself (the old fseek here missed item_offset anyway).
	return true;
}
bool legacy_pack::stream_seek_script(unsigned int idx, int offset, int origin) {
	pack_stream* stream = find_stream(idx);
	if (!stream)
		return false;
	return stream_seek(stream, offset, origin);
}

bool pack_set_global_identifier(const std::string& identifier) {
	if (identifier == "") return false;
	g_pack_ident = identifier;
	return true; // Further validation will be performed in legacy_pack::set_pack_identifier.
}

legacy_pack* ScriptPack_Factory() {
	return new legacy_pack();
}

int packmode1 = PACK_OPEN_MODE_NONE, packmode2 = PACK_OPEN_MODE_APPEND, packmode3 = PACK_OPEN_MODE_CREATE, packmode4 = PACK_OPEN_MODE_READ;
// stream_seek is a uint in the script; the C++ returns a bool, of whose register the script would read 4 bytes.
static unsigned int pack_stream_seek(legacy_pack* pack, unsigned int idx, int offset, int origin) {
	return pack->stream_seek_script(idx, offset, origin) ? 1 : 0;
}
void RegisterScriptLegacyPack(asIScriptEngine* engine) {
	// engine->SetDefaultNamespace("legacy");
	engine->RegisterGlobalProperty(_O("const int PACK_OPEN_MODE_NONE"), &packmode1);
	engine->RegisterGlobalProperty(_O("const int PACK_OPEN_MODE_APPEND"), &packmode2);
	engine->RegisterGlobalProperty(_O("const int PACK_OPEN_MODE_CREATE"), &packmode3);
	engine->RegisterGlobalProperty(_O("const int PACK_OPEN_MODE_READ"), &packmode4);
	engine->RegisterGlobalProperty(_O("const string pack_global_identifier"), &g_pack_ident);
	engine->RegisterGlobalFunction(_O("bool pack_set_global_identifier(const string&in)"), asFUNCTION(pack_set_global_identifier), asCALL_CDECL);
	engine->RegisterObjectType(_O("pack"), 0, asOBJ_REF);
	engine->RegisterObjectBehaviour(_O("pack"), asBEHAVE_FACTORY, _O("pack @p()"), asFUNCTION(ScriptPack_Factory), asCALL_CDECL);
	engine->RegisterObjectBehaviour(_O("pack"), asBEHAVE_ADDREF, _O("void f()"), asMETHOD(legacy_pack, AddRef), asCALL_THISCALL);
	engine->RegisterObjectBehaviour(_O("pack"), asBEHAVE_RELEASE, _O("void f()"), asMETHOD(legacy_pack, Release), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("pack"), _O("bool set_pack_identifier(const string&in)"), asMETHOD(legacy_pack, set_pack_identifier), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("pack"), _O("bool open(const string &in, uint = PACK_OPEN_MODE_READ, bool = false)"), asMETHOD(legacy_pack, open), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("pack"), _O("bool close()"), asMETHOD(legacy_pack, close), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("pack"), _O("bool add_file(const string &in disc_filename, const string& in pack_filename, bool allow_replace = false)"), asMETHOD(legacy_pack, add_file), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("pack"), _O("bool add_memory(const string &in pack_filename, const string& in data, bool allow_replace = false)"), asMETHODPR(legacy_pack, add_memory, (const string&, const string&, bool), bool), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("pack"), _O("bool delete_file(const string &in pack_filename)"), asMETHOD(legacy_pack, delete_file), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("pack"), _O("bool file_exists(const string &in pack_filename) const"), asMETHOD(legacy_pack, file_exists), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("pack"), _O("string get_file_name(int index) const"), asMETHODPR(legacy_pack, get_file_name, (int), string), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("pack"), _O("string[]@ list_files() const"), asMETHODPR(legacy_pack, list_files, (), CScriptArray*), asCALL_THISCALL);
	g_pack_string_array_type = engine->GetTypeInfoByDecl("array<string>");
	engine->RegisterObjectMethod(_O("pack"), _O("uint get_file_size(const string &in pack_filename) const"), asMETHOD(legacy_pack, get_file_size), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("pack"), _O("uint get_file_offset(const string &in pack_filename) const"), asMETHOD(legacy_pack, get_file_offset), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("pack"), _O("string read_file(const string &in pack_filename, uint offset_in_file, uint read_byte_count) const"), asMETHOD(legacy_pack, read_file_string), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("pack"), _O("bool raw_seek(int offset)"), asMETHOD(legacy_pack, raw_seek), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("pack"), _O("bool stream_close(uint index)"), asMETHOD(legacy_pack, stream_close_script), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("pack"), _O("uint stream_open(const string &in pack_filename, uint offset_in_file) const"), asMETHOD(legacy_pack, stream_open_script), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("pack"), _O("string stream_read(uint index, uint read_byte_count) const"), asMETHOD(legacy_pack, stream_read_string), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("pack"), _O("uint stream_pos(uint index) const"), asMETHOD(legacy_pack, stream_pos_script), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("pack"), _O("uint stream_seek(uint index, int offset, int origin) const"), asFUNCTION(pack_stream_seek), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(_O("pack"), _O("uint stream_size(uint index) const"), asMETHOD(legacy_pack, stream_size_script), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("pack"), _O("bool get_active() const property"), asMETHOD(legacy_pack, is_active), asCALL_THISCALL);
	engine->RegisterObjectMethod(_O("pack"), _O("uint get_size() const property"), asMETHOD(legacy_pack, size), asCALL_THISCALL);
	// engine->SetDefaultNamespace("");
}
