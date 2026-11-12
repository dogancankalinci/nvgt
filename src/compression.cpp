/* compression.cpp - string_deflate and string_inflate functions
 * original gist copyright 2007 Timo Bingmann <tb@panthema.net> under the boost license: https://gist.github.com/gomons/9d446024fbb7ccb6536ab984e29e154a
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

#include <string>
#include <cstring>
#include <stdexcept>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <Poco/InflatingStream.h>
#include <Poco/DeflatingStream.h>
#include <Poco/Exception.h>
#include <Poco/zlib.h> // as nvgt_angelscript.cpp
#include "compression.h"
#include <istream>
#include <ostream>

std::string string_deflate(const std::string& str, int compressionlevel = -1) {
	std::stringstream ostr;
	Poco::DeflatingOutputStream stream(ostr, Poco::DeflatingStreamBuf::STREAM_ZLIB, compressionlevel);
	stream << str;
	stream.close();
	return ostr.str();
}

// Inflated with zlib directly, so that data whose stream doesn't end is refused: Poco's inflating stream gave what it had decoded
// of a truncated stream (half of a deflated text gave the first part of the text, and one without its last 4 bytes, the checksum,
// all of it unchecked) with no error, so a cut-off download or file read as complete. Empty data still gives an empty string.
std::string string_inflate(const std::string& str) {
	if (str.empty()) return "";
	z_stream zs;
	memset(&zs, 0, sizeof(zs));
	if (inflateInit2(&zs, 15) != Z_OK) throw Poco::IOException("zlib initialization failed"); // 15: the zlib format, as Poco's STREAM_ZLIB
	std::string out;
	char buffer[32768];
	zs.next_in = (Bytef*)str.data();
	size_t left = str.size();
	int rc = Z_OK;
	while (rc != Z_STREAM_END) {
		if (zs.avail_in == 0 && left > 0) {
			uInt chunk = left > 0x40000000 ? 0x40000000 : uInt(left); // avail_in is 32 bits
			zs.avail_in = chunk;
			left -= chunk;
		}
		zs.next_out = (Bytef*)buffer;
		zs.avail_out = sizeof(buffer);
		rc = inflate(&zs, Z_NO_FLUSH);
		if (rc != Z_OK && rc != Z_STREAM_END && !(rc == Z_BUF_ERROR && (zs.avail_in > 0 || left > 0))) {
			std::string why = rc == Z_BUF_ERROR ? "unexpected end of data" : (zs.msg ? zs.msg : zError(rc));
			inflateEnd(&zs);
			throw Poco::IOException(why);
		}
		try {
			out.append(buffer, sizeof(buffer) - zs.avail_out);
		} catch (...) {
			inflateEnd(&zs);
			throw;
		}
	}
	inflateEnd(&zs);
	return out;
}

void RegisterScriptCompression(asIScriptEngine* engine) {
	engine->RegisterGlobalFunction("string string_deflate(const string& in data, int compression_level = 9)", asFUNCTION(string_deflate), asCALL_CDECL);
	engine->RegisterGlobalFunction("string string_inflate(const string& in deflated)", asFUNCTION(string_inflate), asCALL_CDECL);
}
