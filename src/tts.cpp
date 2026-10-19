/* tts.cpp - code for engine based text to speech system
 * On windows this is SAPI, on macOS it is NSSpeech/AVSpeechSynthesizer, on linux speech dispatcher etc.
 * If no OS based speech system can be found for a given platform, a derivative of RSynth that is built into NVGT will be used instead.
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

#include <cmath>
#include <limits>
#include <type_traits>
#include <algorithm>
#include <unordered_map>
#include <unordered_set>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <thread>
#include <miniaudio.h>
#include <Poco/FileStream.h>
#include <Poco/Format.h>
#include <Poco/String.h>
#include <Poco/StringTokenizer.h>
#include <obfuscate.h>
#include "nvgt_angelscript.h"
#include "tts.h"
#include "misc_functions.h"
#include "UI.h"
#include "xplatform.h"
using namespace std;

// Trim prenormalized TTS based on minimum thresholds in dB. Size is in frames. A sample's level is its distance from silence, which is 128 for unsigned 8-bit samples and 0 for signed ones, relative to the largest such distance. Audio with no frame at the beginning threshold is left whole and reported as quiet.
template <class t> static t *tts_trim_internal(t *data, unsigned int* size_in_frames, int channels, float begin_db, float end_db, bool *quiet, double silence = 0, double peak = numeric_limits<t>::max()) {
	double min_begin_sample = ma_volume_db_to_linear(begin_db) * peak;
	double min_end_sample = ma_volume_db_to_linear(end_db) * peak;
	if constexpr (!std::is_floating_point_v<t>) { // Whole sample steps for integer samples.
		min_begin_sample = ceil(min_begin_sample);
		min_end_sample = ceil(min_end_sample);
	}
	*quiet = true;
	for (unsigned long i = 0; i < *size_in_frames; i++) {
		double mean = 0;
		for (int c = 0; c < channels; c++)
			mean += fabs(data[(i * channels) + c] - silence);
		mean /= channels;
		if (mean >= min_begin_sample) {
			*size_in_frames -= i;
			data += i * channels;
			*quiet = false;
			break;
		}
	}
	for (int i = *size_in_frames -1; i >= 0; i--) {
		double mean = 0;
		for (int c = 0; c < channels; c++)
			mean += fabs(data[(i * channels) + c] - silence);
		mean /= channels;
		if (mean > min_end_sample) {
			*size_in_frames = i + 1; // Up to and including the last frame that is loud enough.
			break;
		}
	}
	return data;
}

// The level of the loudest sample in dB relative to full scale, measured as tts_trim_internal measures levels.
template <class t> static float tts_peak_db_internal(const t *data, size_t count, double silence = 0, double peak = numeric_limits<t>::max()) {
	double loudest = 0;
	for (size_t i = 0; i < count; i++) loudest = max(loudest, fabs(data[i] - silence));
	return loudest > 0? 20 * log10(loudest / peak) : -200;
}
static float tts_peak_db(const tts_audio_data* data) {
	switch (data->bitsize) {
		case 16: return tts_peak_db_internal<int16_t>((const int16_t*)data->data, data->size_in_bytes / 2);
		case 8: return tts_peak_db_internal<uint8_t>((const uint8_t*)data->data, data->size_in_bytes, 128, 127);
		case 32: return tts_peak_db_internal<float>((const float*)data->data, data->size_in_bytes / 4, 0, 1);
		default: return 0;
	}
}

static void* tts_trim(tts_audio_data* data, bool *quiet, float begin_db = -60, float end_db = -60) {
	unsigned int size_in_frames;
	void* trimmed_data;
	*quiet = false;
	switch (data->bitsize) {
		case 16:
			size_in_frames = data->size_in_bytes / 2 / data->channels;
			trimmed_data = tts_trim_internal<int16_t>((int16_t*)data->data, &size_in_frames, data->channels, begin_db, end_db, quiet);
			data->size_in_bytes = size_in_frames * 2 * data->channels;
			return trimmed_data;
		case 8:
			size_in_frames = data->size_in_bytes / data->channels;
			trimmed_data = tts_trim_internal<uint8_t>((uint8_t*)data->data, &size_in_frames, data->channels, begin_db, end_db, quiet, 128, 127);
			data->size_in_bytes = size_in_frames * data->channels;
			return trimmed_data;
		case 32: // Floats from Android engines, with 1 at full scale.
			size_in_frames = data->size_in_bytes / 4 / data->channels;
			trimmed_data = tts_trim_internal<float>((float*)data->data, &size_in_frames, data->channels, begin_db, end_db, quiet, 0, 1);
			data->size_in_bytes = size_in_frames * 4 * data->channels;
			return trimmed_data;
		default:
			return data->data;
	}
}

// Whether a voice of the given language serves a request for a language: any voice when none is requested, one with the same code in any letter case and with "-" or "_" before the region, or, since not every engine reports a region and a request need not name one, one whose code names the same language where only one of the two codes names a region ("en" serves "en-us" and the other way around).
static bool tts_language_matches(const string &voice_language, const string &requested) {
	if (requested.empty()) return true;
	string voice = Poco::toLower(voice_language), request = Poco::toLower(requested);
	replace(voice.begin(), voice.end(), '_', '-');
	replace(request.begin(), request.end(), '_', '-');
	if (voice == request) return true;
	if (voice.empty()) return false;
	const string &language = voice.size() < request.size()? voice : request, &regional = voice.size() < request.size()? request : voice;
	if (language.find('-') != string::npos || regional.size() <= language.size()) return false;
	return regional.compare(0, language.size(), language) == 0 && regional[language.size()] == '-';
}
// Finds an engine's voice in a voice list: the same engine index, name and language first, then the same name and language, as indices move when voices are installed or removed while the program runs. The name alone doesn't do, as names repeat on Apple platforms, which list some voices once per language. Failing both, a voice at the same index whose name no other listed voice of the engine has is taken, as only its language changed: Speech Dispatcher's follows the server, which can also be unreachable for a moment.
static int find_listed_voice(const vector<voice_info> &voices, const string &engine_name, int engine_voice_index, const string &name, const string &language) {
	for (int pass = 0; pass < 2; pass++) {
		for (size_t i = 0; i < voices.size(); i++) {
			const voice_info &voice = voices[i];
			if (voice.engine_name != engine_name || voice.name != name || voice.language != language) continue;
			if (pass == 0 && voice.engine_voice_index != engine_voice_index) continue;
			return i;
		}
	}
	int found = -1, named = 0;
	for (size_t i = 0; i < voices.size(); i++) {
		if (voices[i].engine_name != engine_name || voices[i].name != name) continue;
		named++;
		if (voices[i].engine_voice_index == engine_voice_index) found = i;
	}
	return named == 1? found : -1;
}

// Text as valid UTF-8: each malformed sequence (a stray or truncated byte run, an overlong form, an encoded surrogate or a value past U+10FFFF) becomes one U+FFFD, and decoding resumes at the first byte that can't belong to it, as Android's conversion to UTF-16 does. Engines handle malformed text badly: SAPI refuses the whole text, Apple's speech throws an Objective-C exception, Speech Dispatcher rejects it. A string cut in the middle of a character, by substr for instance, is enough to produce it.
string tts_valid_utf8(const string &text) {
	const unsigned char *s = (const unsigned char *)text.data();
	size_t n = text.size(), i = 0;
	string out;
	bool copying = false; // Only once something had to be replaced; valid text is returned as it is.
	while (i < n) {
		unsigned char lead = s[i];
		if (lead == 0) { // Engines that take a C string would end the text there.
			if (!copying) {
				out.reserve(n + 2);
				out.assign(text, 0, i);
				copying = true;
			}
			out += ' ';
			i++;
			continue;
		}
		uint32_t c;
		size_t length;
		if (lead < 0x80) c = lead, length = 1;
		else if (lead >= 0xC2 && lead <= 0xDF) c = lead & 0x1F, length = 2;
		else if (lead >= 0xE0 && lead <= 0xEF) c = lead & 0x0F, length = 3;
		else if (lead >= 0xF0 && lead <= 0xF4) c = lead & 0x07, length = 4;
		else c = 0, length = 0;
		size_t used = 1;
		if (length > 1) while (used < length && i + used < n && (s[i + used] & 0xC0) == 0x80) c = (c << 6) | (s[i + used++] & 0x3F);
		bool valid = length != 0 && used == length && !(length == 3 && c < 0x800) && !(length == 4 && (c < 0x10000 || c > 0x10FFFF)) && !(c >= 0xD800 && c <= 0xDFFF);
		if (!valid && !copying) {
			out.reserve(n + 2);
			out.assign(text, 0, i);
			copying = true;
		}
		if (copying) {
			if (valid) out.append(text, i, used);
			else out += "\xEF\xBF\xBD";
		}
		i += used;
	}
	return copying? out : text;
}

// The sample format of the PCM an engine produced. 32-bit samples come only from Android engines that synthesize floats.
static ma_format tts_pcm_format(const tts_audio_data* data) {
	if (data->bitsize == 16) return ma_format_s16;
	if (data->bitsize == 32) return ma_format_f32;
	return ma_format_u8;
}

tts_audio_data::tts_audio_data(tts_engine* eng, void* dat, unsigned int size, unsigned int rate, unsigned int chans, unsigned int bits, void* ctx) : engine(eng), data(dat), size_in_bytes(size), sample_rate(rate), channels(chans), bitsize(bits), context(ctx) {}
void tts_audio_data::free() { if (engine) engine->free_pcm(this); }

// The builtin synthesizer knows ASCII only, and spells out a word with any other byte in it letter by letter, naming each byte as the ASCII character it masks to: "café" came out as "C A F C close parenthesis". So the text it gets has each Latin letter and ligature as its base letters, fullwidth characters as their ASCII forms, guillemets as quotation marks, typographic quotes, hyphens, the minus sign and the multiplication sign as their ASCII forms, dashes as pauses, apostrophes only within words, square brackets and control characters as spaces, symbols such as currency signs, fractions and powers as words, combining marks and invisible characters left out, as they belong to the letters around them, and everything else outside ASCII as a space. The text is valid UTF-8 by then, see tts_valid_utf8.
static string tts_fallback_ascii(const string &text) {
	static const char *const latin[] = { // U+00C0 to U+024F.
		"A", "A", "A", "A", "A", "A", "AE", "C", "E", "E", "E", "E", "I", "I", "I", "I",
		"D", "N", "O", "O", "O", "O", "O", " ", "O", "U", "U", "U", "U", "Y", "Th", "ss",
		"a", "a", "a", "a", "a", "a", "ae", "c", "e", "e", "e", "e", "i", "i", "i", "i",
		"d", "n", "o", "o", "o", "o", "o", " ", "o", "u", "u", "u", "u", "y", "th", "y",
		"A", "a", "A", "a", "A", "a", "C", "c", "C", "c", "C", "c", "C", "c", "D", "d",
		"D", "d", "E", "e", "E", "e", "E", "e", "E", "e", "E", "e", "G", "g", "G", "g",
		"G", "g", "G", "g", "H", "h", "H", "h", "I", "i", "I", "i", "I", "i", "I", "i",
		"I", "i", "IJ", "ij", "J", "j", "K", "k", "k", "L", "l", "L", "l", "L", "l", "L",
		"l", "L", "l", "N", "n", "N", "n", "N", "n", "n", "Ng", "ng", "O", "o", "O", "o",
		"O", "o", "OE", "oe", "R", "r", "R", "r", "R", "r", "S", "s", "S", "s", "S", "s",
		"S", "s", "T", "t", "T", "t", "T", "t", "U", "u", "U", "u", "U", "u", "U", "u",
		"U", "u", "U", "u", "W", "w", "Y", "y", "Y", "Z", "z", "Z", "z", "Z", "z", "s",
		"b", "B", "B", "b", " ", " ", "O", "C", "c", "D", "D", "D", "d", "d", "E", "E",
		"E", "F", "f", "G", "G", "hv", "I", "I", "K", "k", "l", "l", "M", "N", "n", "O",
		"O", "o", "OI", "oi", "P", "p", "R", " ", " ", "Sh", " ", "t", "T", "t", "T", "U",
		"u", "U", "V", "Y", "y", "Z", "z", "Z", "Z", "z", "z", " ", " ", " ", " ", "w",
		" ", " ", " ", " ", "DZ", "Dz", "dz", "LJ", "Lj", "lj", "NJ", "Nj", "nj", "A", "a", "I",
		"i", "O", "o", "U", "u", "U", "u", "U", "u", "U", "u", "U", "u", "e", "A", "a",
		"A", "a", "AE", "ae", "G", "g", "G", "g", "K", "k", "O", "o", "O", "o", "Z", "z",
		"j", "DZ", "Dz", "dz", "G", "g", "Hw", "W", "N", "n", "A", "a", "AE", "ae", "O", "o",
		"A", "a", "A", "a", "E", "e", "E", "e", "I", "i", "I", "i", "O", "o", "O", "o",
		"R", "r", "R", "r", "U", "u", "U", "u", "S", "s", "T", "t", "Y", "y", "H", "h",
		"N", "d", "OU", "ou", "Z", "z", "A", "a", "E", "e", "O", "o", "O", "o", "O", "o",
		"O", "o", "Y", "y", "l", "n", "t", "j", " ", " ", "A", "C", "c", "L", "T", "s",
		"z", " ", " ", "B", "U", "V", "E", "e", "J", "j", "Q", "q", "R", "r", "Y", "y"
	};
	static const char *const latin_additional[] = { // U+1E00 to U+1EFF.
		"A", "a", "B", "b", "B", "b", "B", "b", "C", "c", "D", "d", "D", "d", "D", "d",
		"D", "d", "D", "d", "E", "e", "E", "e", "E", "e", "E", "e", "E", "e", "F", "f",
		"G", "g", "H", "h", "H", "h", "H", "h", "H", "h", "H", "h", "I", "i", "I", "i",
		"K", "k", "K", "k", "K", "k", "L", "l", "L", "l", "L", "l", "L", "l", "M", "m",
		"M", "m", "M", "m", "N", "n", "N", "n", "N", "n", "N", "n", "O", "o", "O", "o",
		"O", "o", "O", "o", "P", "p", "P", "p", "R", "r", "R", "r", "R", "r", "R", "r",
		"S", "s", "S", "s", "S", "s", "S", "s", "S", "s", "T", "t", "T", "t", "T", "t",
		"T", "t", "U", "u", "U", "u", "U", "u", "U", "u", "U", "u", "V", "v", "V", "v",
		"W", "w", "W", "w", "W", "w", "W", "w", "W", "w", "X", "x", "X", "x", "Y", "y",
		"Z", "z", "Z", "z", "Z", "z", "h", "t", "w", "y", "a", "s", "s", "s", "SS", "d",
		"A", "a", "A", "a", "A", "a", "A", "a", "A", "a", "A", "a", "A", "a", "A", "a",
		"A", "a", "A", "a", "A", "a", "A", "a", "E", "e", "E", "e", "E", "e", "E", "e",
		"E", "e", "E", "e", "E", "e", "E", "e", "I", "i", "I", "i", "O", "o", "O", "o",
		"O", "o", "O", "o", "O", "o", "O", "o", "O", "o", "O", "o", "O", "o", "O", "o",
		"O", "o", "O", "o", "U", "u", "U", "u", "U", "u", "U", "u", "U", "u", "U", "u",
		"U", "u", "Y", "y", "Y", "y", "Y", "y", "Y", "y", "LL", "ll", "V", "v", "Y", "y"
	};
	// The base letters of a Latin letter, or null for anything else outside ASCII.
	auto latin_letters = [&](uint32_t c) -> const char * {
		if (c >= 0xC0 && c < 0x250) return latin[c - 0xC0];
		if (c >= 0x1E00 && c < 0x1F00) return latin_additional[c - 0x1E00];
		return nullptr;
	};
	auto is_letter = [&](uint32_t c, bool lowercase) {
		if (c < 0x80) return lowercase? islower((int)c) != 0 : isalpha((int)c) != 0;
		const char *letters = latin_letters(c);
		return letters && (lowercase? islower((unsigned char)letters[0]) : isalpha((unsigned char)letters[0]));
	};
	// The code point starting at a byte, and how many bytes it takes; none at the end.
	auto decode = [&](size_t at, uint32_t &c) -> size_t {
		if (at >= text.size()) return 0;
		unsigned char lead = text[at];
		size_t length = lead < 0x80? 1 : lead >= 0xF0? 4 : lead >= 0xE0? 3 : 2;
		if (at + length > text.size()) return 0;
		c = length == 1? lead : lead & (length == 2? 0x1F : length == 3? 0x0F : 0x07);
		for (size_t k = 1; k < length; k++) c = (c << 6) | (text[at + k] & 0x3F);
		if (c >= 0xFF01 && c <= 0xFF5E) c -= 0xFEE0; // Fullwidth forms of ASCII characters, as those.
		return length;
	};
	// Symbols with no ASCII form are read as words, which the synthesizer would otherwise say nothing for.
	static const struct { uint32_t code; const char *words; } symbols[] = {
		{0xA2, " cent "}, {0xA3, " pound "}, {0xA5, " yen "}, {0xA7, " section "}, {0xA9, " copyright "}, {0xAE, " registered "}, {0xB0, " degrees "}, {0xB1, " plus or minus "}, {0xB5, " micro "}, {0xB6, " paragraph "}, {0xF7, " divided by "},
		{0x2022, ", "}, {0x2030, " per mille "}, {0x20A9, " won "}, {0x20AC, " euro "}, {0x20B9, " rupee "}, {0x20BA, " lira "}, {0x20BD, " ruble "}, {0x2122, " trademark "},
		{0x2190, " left "}, {0x2191, " up "}, {0x2192, " right "}, {0x2193, " down "}, {0x221A, " square root of "}, {0x221E, " infinity "}, {0x2248, " approximately "}, {0x2260, " not equal to "}, {0x2264, " less than or equal to "}, {0x2265, " greater than or equal to "}
	};
	// Fractions, as words joined to a whole number written before them ("1½", one and a half) or on their own.
	static const struct { uint32_t code; const char *after_number, *alone; } fractions[] = {
		{0xBC, " and a quarter ", " one quarter "}, {0xBD, " and a half ", " one half "}, {0xBE, " and three quarters ", " three quarters "},
		{0x2153, " and a third ", " one third "}, {0x2154, " and two thirds ", " two thirds "}, {0x215B, " and an eighth ", " one eighth "}
	};
	// Superscripts are a power, "10⁻³" ten to the power of minus three, and a lone superscript 2 or 3 "squared" or "cubed"; subscripts are the characters they stand for.
	auto superscript = [](uint32_t c) -> const char * {
		static const char *const digits[] = {"0", "1", "2", "3", "4", "5", "6", "7", "8", "9"};
		switch (c) {
			case 0xB9: return "1";
			case 0xB2: return "2";
			case 0xB3: return "3";
			case 0x2071: return " i ";
			case 0x207A: return " plus ";
			case 0x207B: return " minus ";
			case 0x207C: return " equals ";
			case 0x207D: case 0x207E: return " ";
			case 0x207F: return " n ";
		}
		return c == 0x2070 || (c >= 0x2074 && c <= 0x2079)? digits[c - 0x2070] : nullptr;
	};
	string out;
	out.reserve(text.size());
	uint32_t previous = 0;
	for (size_t i = 0; i < text.size();) {
		uint32_t c, next = 0;
		size_t length = decode(i, c);
		if (!length) break;
		i += length;
		decode(i, next);
		uint32_t before = previous;
		previous = c;
		if (const char *power = superscript(c)) {
			bool first = !superscript(before), last = !superscript(next);
			if (first && last && (c == 0xB2 || c == 0xB3)) out += c == 0xB2? " squared " : " cubed ";
			else {
				if (first) out += " to the power of ";
				out += power;
				if (last) out += ' ';
			}
			continue;
		}
		if (c >= 0x2080 && c <= 0x208E) {
			out += "0123456789+-=()"[c - 0x2080];
			continue;
		}
		bool symbol = false;
		for (const auto &entry : symbols) if (entry.code == c) { out += entry.words; symbol = true; break; }
		for (const auto &entry : fractions) if (entry.code == c) { out += !out.empty() && isdigit((unsigned char)out.back())? entry.after_number : entry.alone; symbol = true; break; }
		if (symbol) continue;
		if (c == '\'' || c == '`' || c == 0xB4 || c == 0x2BC || c == 0x2018 || c == 0x2019 || c == 0x201A || c == 0x201B || c == 0x2032) {
			// An apostrophe, or an accent typed for one, is kept only between letters, as in "it's": as a quotation mark, outside a word, the synthesizer says "quote".
			out += !out.empty() && isalpha((unsigned char)out.back()) && is_letter(next, false)? '\'' : ' ';
		} else if (c < 0x80) {
			if (c == '[' || c == ']') out += ' '; // The synthesizer reads text in brackets as its own phoneme codes.
			else if ((c < 0x20 && !isspace((int)c)) || c == 0x7F) out += ' '; // It spells out the word around a control character, naming it.
			else out += (char)c;
		} else if (c == 0xD7) out += 'x'; // The multiplication sign, read as "3x4" is.
		else if (const char *letters = latin_letters(c)) {
			// A capital such as Æ or Œ in a word going on in lowercase gives one capital, "Ae": the synthesizer spells out a word with a capital after its first letter.
			if (letters[0] && letters[1] && isupper((unsigned char)letters[0]) && is_letter(next, true)) {
				out += letters[0];
				for (const char *letter = letters + 1; *letter; letter++) out += (char)tolower((unsigned char)*letter);
			} else out += letters;
		}
		else if ((c >= 0x201C && c <= 0x201F) || c == 0x2033 || c == 0xAB || c == 0xBB || c == 0x2039 || c == 0x203A) out += '"';
		else if (c == 0x2010 || c == 0x2011 || c == 0x2212) out += '-'; // Hyphens, and the minus sign, which the synthesizer reads before a number.
		else if (c >= 0x2013 && c <= 0x2015) out += ", "; // Dashes, as a pause: a hyphen between numbers would read "minus".
		else if (c >= 0xFB00 && c <= 0xFB06) {
			static const char *const ligatures[] = {"ff", "fi", "fl", "ffi", "ffl", "st", "st"};
			out += ligatures[c - 0xFB00];
		}
		else if (c == 0x2026) out += "...";
		else if ((c >= 0x300 && c < 0x370) || c == 0xAD || (c >= 0x200B && c <= 0x200D) || c == 0x2060 || c == 0xFEFF) continue;
		else out += ' ';
	}
	return out;
}

// Fallback voice engine using RSynth
class fallback_voice_engine : public tts_engine_impl {
	float rate, pitch, volume;
public:
	fallback_voice_engine() : tts_engine_impl("fallback"), rate(10), pitch(1330), volume(60) {}
	tts_pcm_generation_state get_pcm_generation_state() override { return PCM_PREFERRED; }
	tts_audio_data* speak_to_pcm(const string &text) override {
		if (text.empty()) return nullptr;
		string ascii = tts_fallback_ascii(text);
		int samples;
		// The synthesizer's own gain does nothing, as every frame takes its voicing amplitude from the phoneme tables, so the speech is made at its normal level and the volume is applied to the samples below.
		short *data = speech_gen(&samples, ascii.c_str(), 20 - rate, pitch, 60, NULL); // smaller rate values mean faster so we must reverse the rate value here.
		if (!data) return nullptr;
		// Text with nothing to say, punctuation alone for instance, comes out as pauses of digital silence, which is empty audio rather than silence of that length, as with the other engines.
		if (samples > 0 && silent(data, samples)) samples = 0;
		float gain = apply_volume(data, samples * 2);
		tts_audio_data *block = new tts_audio_data(this, data, samples * 4, 44100, 2, 16);
		block->gain_db = gain > 0? 20 * log10f(gain) : -200; // So the quiet starts and ends of speech made quieter aren't trimmed off as silence.
		return block;
	}
	static bool silent(const short *data, int samples) {
		for (int i = 0; i < samples * 2; i++) if (data[i]) return false;
		return true;
	}
	// The volume on the synthesizer's decibel scale, where 60 is its normal level: lower settings are quieter down to 0, which is silence, and higher ones louder as far as the loudest sample allows without clipping. Gives the gain applied.
	float apply_volume(short *data, int count) {
		float gain = volume <= 0? 0 : powf(10.0f, (volume - 60) / 20);
		if (gain > 1) {
			int peak = 1;
			for (int i = 0; i < count; i++) peak = max(peak, abs((int)data[i]));
			gain = min(gain, 32767.0f / peak);
		}
		if (gain == 1) return gain;
		for (int i = 0; i < count; i++) data[i] = (short)clamp(lrintf(data[i] * gain), -32767L, 32767L);
		return gain;
	}
	void free_pcm(tts_audio_data* data) override {
		if (data && data->data) {
			speech_free((short *)data->data, NULL);
			data->data = nullptr;
		}
		tts_engine_impl::free_pcm(data);
	}
	float get_rate() override { return rate; }
	float get_pitch() override { return pitch; }
	float get_volume() override { return volume; }
	void set_rate(float rate) override { this->rate = rate; }
	void set_pitch(float pitch) override { this->pitch = pitch; }
	void set_volume(float volume) override { this->volume = volume; }
	bool get_rate_range(float& minimum, float& midpoint, float& maximum) override { minimum = 3; midpoint = 10; maximum = 17; return true; }
	bool get_pitch_range(float& minimum, float& midpoint, float& maximum) override { minimum = 400; midpoint = 1330; maximum = 4000; return true; }
	bool get_volume_range(float& minimum, float& midpoint, float& maximum) override { minimum = 0; midpoint = 30; maximum = 70; return true; }
	string get_voice_name(int index) override { return index == 0? "builtin fallback voice" : ""; }
};

// Engine factory registry
static std::recursive_mutex g_tts_registry_mutex; // guards engine_registry and engine_names: tts_voice objects are created and used from any script thread and lazily populate them
static vector<string> engine_names;
static unordered_map<string, tts_engine_factory> engine_registry;
static string preferred_engine_name;
static std::function<string()> preferred_engine_reader;
static vector<string> engine_ranking; // Engines in the order the platform falls back through them, set where it has such an order; voices keep the registration order.
bool tts_engine_register(const string &name, tts_engine_factory factory) {
	std::lock_guard<std::recursive_mutex> lock(g_tts_registry_mutex); // recursive: register_builtin_engines() calls this while the constructor already holds the lock
	if (engine_registry.find(name) != engine_registry.end()) return false;
	engine_registry[name] = factory;
	engine_names.push_back(name);
	return true;
}

vector<string> tts_get_engine_names() { std::lock_guard<std::recursive_mutex> lock(g_tts_registry_mutex); return engine_names; }
void tts_set_preferred_engine(const string &name) { preferred_engine_name = name; }
void tts_set_preferred_engine_reader(std::function<string()> reader) {
	std::lock_guard<std::recursive_mutex> lock(g_tts_registry_mutex);
	preferred_engine_reader = std::move(reader);
}
// The engine the platform prefers as the user has it set now, where they can change it while the program runs; empty elsewhere and when it can't be read.
static string tts_live_preferred_engine() {
	std::function<string()> reader;
	{
		std::lock_guard<std::recursive_mutex> lock(g_tts_registry_mutex);
		reader = preferred_engine_reader;
	}
	return reader? reader() : "";
}
// The engine the platform prefers: as it is set now, otherwise as it was when the engines were registered.
static string tts_preferred_engine() {
	string name = tts_live_preferred_engine();
	if (!name.empty()) return name;
	std::lock_guard<std::recursive_mutex> lock(g_tts_registry_mutex);
	return preferred_engine_name;
}
void tts_set_engine_ranking(const vector<string> &names) {
	std::lock_guard<std::recursive_mutex> lock(g_tts_registry_mutex);
	engine_ranking = names;
}
static vector<string> tts_engine_ranking() {
	std::lock_guard<std::recursive_mutex> lock(g_tts_registry_mutex);
	return engine_ranking;
}

shared_ptr<tts_engine> tts_create_engine(const string &name) {
	tts_engine_factory factory;
	{
		std::lock_guard<std::recursive_mutex> lock(g_tts_registry_mutex);
		auto it = engine_registry.find(name);
		if (it == engine_registry.end()) return nullptr;
		factory = it->second;
	}
	try { return factory(); }
	catch (...) { return nullptr; }
}

// Engines are bound for each tts_voice (see engine_entry). One that couldn't be bound is remembered and never tried again, and the engines of a tts_voice that goes away are kept, put back to the platform's settings, for the next tts_voice that wants them, since binding one can take long and costs a connection to the platform's speech service. Both under g_engine_pool_mutex. Binding takes g_engine_binding_mutex instead, so an engine slow to bind, which on Android can take seconds, holds up only other binding, as it always has, and not the creation or release of tts_voice objects.
static std::mutex g_engine_pool_mutex;
static std::mutex g_engine_binding_mutex;
static unordered_set<string> g_unusable_engines;
static unordered_set<string> g_bound_engines; // Engines bound at least once.
static unordered_map<string, vector<shared_ptr<tts_engine>>> g_idle_engines;
static bool g_engine_pool_closed = false; // Set at shutdown; the engines of a tts_voice released after that are destroyed at once instead of waiting in the pool for static destruction.
// Set at shutdown, after which speech is no longer held (see tts_voice::hold), so no thread is started to start it.
static std::mutex g_held_speech_mutex;
static bool g_held_speech_closed = false;
void tts_release_idle_engines() {
	{
		std::lock_guard<std::mutex> lock(g_held_speech_mutex);
		g_held_speech_closed = true;
	}
	unordered_map<string, vector<shared_ptr<tts_engine>>> idle;
	{
		std::lock_guard<std::mutex> lock(g_engine_pool_mutex);
		idle.swap(g_idle_engines);
		g_engine_pool_closed = true;
	}
}
// The index the voice an engine had when it was bound has now: found by its name, or the old index when it had none.
static int tts_engine_init_voice_index(engine_entry &entry) {
	if (entry.init_voice_name.empty()) return entry.init_voice;
	int count = entry.engine->get_voice_count();
	for (int i = 0; i < count; i++) if (entry.engine->get_voice_name(i) == entry.init_voice_name) return i;
	return -1;
}
// Puts back the voice an engine had before the object set one: through the engine when it can reset it, otherwise by finding that voice again. False when neither worked.
static bool tts_engine_restore_voice(engine_entry &entry) {
	if (entry.engine->reset_voice()) return true;
	int index = tts_engine_init_voice_index(entry);
	return index >= 0 && entry.engine->set_voice(index);
}
// The engine's own default voice: its current voice, unless the object set one on it, in which case the voice it had when it was bound, which is also what resetting it restores.
static int tts_engine_default_voice(engine_entry &entry) {
	if (!entry.engine) return -1;
	return entry.voice_changed? tts_engine_init_voice_index(entry) : entry.engine->get_current_voice();
}
// Puts back what an object set on an engine, so the engine speaks with the platform's settings again. False when the voice could not be put back, so the engine still speaks with the one the object chose.
static bool tts_engine_restore_defaults(engine_entry &entry) {
	tts_engine *engine = entry.engine.get();
	if (!engine) return false;
	bool voice_restored = !entry.voice_changed || tts_engine_restore_voice(entry);
	if (entry.rate_changed && !engine->reset_rate()) engine->set_rate(entry.init_rate);
	if (entry.pitch_changed && !engine->reset_pitch()) engine->set_pitch(entry.init_pitch);
	if (entry.volume_changed && !engine->reset_volume()) engine->set_volume(entry.init_volume);
	entry.voice_changed = entry.rate_changed = entry.pitch_changed = entry.volume_changed = false;
	return voice_restored;
}
static std::atomic<uint64_t> g_next_tts_voice_id{0};
// The end of each queued utterance is handled by a resource manager job, which can run after the tts_voice that queued it has been released. Jobs therefore carry the voice's id and find the voice here, under the lock; a voice removes itself before it is destroyed, so it is never freed while a job is using it, and a job that comes after finds nothing. On 32-bit platforms the id is truncated to the width of a pointer.
static std::mutex g_live_tts_voices_mutex;
static unordered_map<uintptr_t, tts_voice*> g_live_tts_voices;

static void register_builtin_engines() {
	tts_engine_register("fallback", []() -> shared_ptr<tts_engine> { return make_shared<fallback_voice_engine>(); });
	register_native_tts();
}

// tts_voice implementation
tts_voice::tts_voice(const string &engine_list) : RefCount(1), all_engines(engine_list.empty()), voice_state(VOICES_NONE), current_voice_index(-1), nvgt_rate(0), nvgt_pitch(0), nvgt_volume(0), rate_set(false), pitch_set(false), volume_set(false), voice_set(false), id(++g_next_tts_voice_id) {
	{
		std::lock_guard<std::recursive_mutex> lock(g_tts_registry_mutex);
		if (engine_registry.empty()) register_builtin_engines();
	}
	speaking.clear();
	if (engine_list.empty()) engine_names = tts_get_engine_names();
	else {
		Poco::StringTokenizer tokens(engine_list, ",");
		for (const string& e : tokens) {
			string name = Poco::trim(e);
			if (find(engine_names.begin(), engine_names.end(), name) == engine_names.end()) engine_names.push_back(name); // An engine named twice would list its voices twice.
		}
	}
	// Engines are bound lazily. We deliberately do NOT instantiate any engine here, nor enumerate voices yet: a tts_voice that is created but never used (e.g. a global object on a device where a screen reader handles speech instead) must never bind to any TTS engine. This is what avoids the "bind to every installed engine at startup" problem, including crashing on restricted engines like Sao Mai Myanmar TTS.
	std::lock_guard<std::mutex> lock(g_live_tts_voices_mutex);
	g_live_tts_voices[(uintptr_t)id] = this;
}
tts_voice::~tts_voice() {
	{
		std::lock_guard<std::recursive_mutex> chain(chain_mtx);
		held.clear();
		held_starter_stop = true;
	}
	if (held_starter.joinable()) held_starter.join(); // It ends as soon as it sees the stop, after an engine call under way.
	{
		std::lock_guard<std::mutex> lock(g_live_tts_voices_mutex);
		g_live_tts_voices.erase((uintptr_t)id);
	}
	// The engines go to the next tts_voice that wants them, silent and with the platform's settings; one whose voice can't be put back is let go instead, so it can't hand that voice on.
	for (auto &[name, entry] : engines) {
		if (!entry.engine) continue;
		entry.engine->stop();
		if (!tts_engine_restore_defaults(entry)) continue;
		std::lock_guard<std::mutex> lock(g_engine_pool_mutex);
		if (!g_engine_pool_closed) g_idle_engines[name].push_back(entry.engine);
	}
}
engine_entry &tts_voice::get_engine_entry(const string &name) {
	auto it = engines.find(name);
	if (it != engines.end()) return it->second;
	engine_entry entry;
	auto take_idle = [&]() {
		std::lock_guard<std::mutex> lock(g_engine_pool_mutex);
		auto idle = g_idle_engines.find(name);
		if (idle != g_idle_engines.end() && !idle->second.empty()) {
			entry.engine = idle->second.back();
			idle->second.pop_back();
			return true;
		}
		return g_unusable_engines.count(name) > 0;
	};
	if (!take_idle()) {
		std::lock_guard<std::mutex> binding(g_engine_binding_mutex);
		if (!take_idle()) { // Another object may have released one, or found the engine unusable, while this one waited.
			shared_ptr<tts_engine> engine = tts_create_engine(name);
			std::lock_guard<std::mutex> lock(g_engine_pool_mutex);
			if (engine && engine->is_available()) {
				entry.engine = engine;
				g_bound_engines.insert(name);
			} else if (!g_bound_engines.count(name)) g_unusable_engines.insert(name); // An engine that has worked can fail for a while, while it restarts for instance, so only one that never bound is given up for good.
		}
	}
	if (entry.engine) {
		entry.voices_generation = entry.engine->voices_generation();
		entry.init_rate = entry.engine->get_rate();
		entry.init_pitch = entry.engine->get_pitch();
		entry.init_volume = entry.engine->get_volume();
		entry.init_voice = entry.engine->get_current_voice();
		if (entry.init_voice >= 0) entry.init_voice_name = entry.engine->get_voice_name(entry.init_voice);
	}
	return engines.emplace(name, std::move(entry)).first->second;
}
void tts_voice::AddRef() { asAtomicInc(RefCount); }
void tts_voice::Release() { if (asAtomicDec(RefCount) < 1) delete this; }
voice_info *tts_voice::get_voice_info(int voice_index) {
	if (voice_index < 0 || voice_index >= static_cast<int>(voices.size())) return nullptr;
	return &voices[voice_index];
}
void tts_voice::ensure_default() {
	if (voice_state != VOICES_NONE) {
		follow_installed_voices();
		follow_preferred_engine();
		return;
	}
	string preferred = tts_preferred_engine();
	followed_engine = preferred;
	if (all_engines) engine_names = tts_get_engine_names(); // The preferred engine can be one installed since.
	// Fast path for the common case (speak with the default voice): bind engines one at a time, the preferred/default engine first and then the others in the platform's own order, and select the default voice of the first one that can speak, so we never instantiate or bind every installed engine just to start speaking. Only engines in this object's list count, and the fallback voice is left to refresh() unless it is all the list holds. Full cross-engine enumeration is deferred until the script actually lists or selects voices.
	vector<string> candidates;
	auto consider = [&](const string &name) {
		if (name.empty() || name == "fallback" || find(engine_names.begin(), engine_names.end(), name) == engine_names.end() || find(candidates.begin(), candidates.end(), name) != candidates.end()) return;
		candidates.push_back(name);
	};
	consider(preferred);
	for (const string &name : tts_engine_ranking()) consider(name);
	for (const string &name : engine_names) consider(name);
	if (candidates.empty() && !engine_names.empty()) candidates.push_back(engine_names.front());
	for (const string &name : candidates) {
		engine_entry &entry = get_engine_entry(name);
		if (!entry.engine || !entry.engine->is_available()) continue;
		tts_engine *engine = entry.engine.get();
		voices.clear();
		int default_voice = tts_engine_default_voice(entry);
		int voice_count = engine->get_voice_count();
		for (int i = 0; i < voice_count; i++) {
			string lang = engine->get_voice_language(i);
			if (tts_language_matches(lang, current_language)) voices.emplace_back(voice_info{name, i, engine->get_voice_name(i), lang});
		}
		if (voices.empty()) continue; // e.g. a language filter excluded everything from this engine
		current_voice_index = 0;
		for (size_t i = 0; i < voices.size(); i++) if (voices[i].engine_voice_index == default_voice) { current_voice_index = i; break; }
		current_engine = entry.engine;
		current_engine_name = name;
		voice_state = VOICES_DEFAULT_ONLY;
		entry.synced = false; // An engine the object goes back to, after following the user's settings away from it, still carries the settings of then.
		return;
	}
	voices.clear();
	list_voices_again(false, true); // No candidate could speak: fall back to a full search for anything usable.
}
void tts_voice::ensure_enumerated() {
	if (voice_state != VOICES_FULL) list_voices_again(false, true);
	else {
		follow_installed_voices();
		follow_preferred_engine();
	}
}
// The user can install, remove and update voices and engines while the program runs. Engines that can tell report it through voices_generation(), and one whose app was removed reports itself unavailable, so the object then lists its voices again, as refresh() does: a removed voice leaves the list, one the script chose included, which then gives way to the platform's voice, and the voice numbers can change.
void tts_voice::follow_installed_voices() {
	if (voice_state == VOICES_NONE) return;
	bool changed = false;
	for (auto &[name, entry] : engines) {
		if (!entry.engine) continue;
		uint64_t generation = entry.engine->voices_generation();
		if (generation == entry.voices_generation) continue;
		entry.voices_generation = generation;
		changed = true;
	}
	if (!changed) return;
	if (voice_state == VOICES_FULL) {
		list_voices_again(false, false); // The engines that reported the change list their voices again by themselves.
		return;
	}
	voice_state = VOICES_NONE;
	ensure_default();
}
// The user can change the preferred engine while the program runs, as Android's preferred engine setting. Without a voice the script chose, the object then moves to that engine's default voice, as it would have started with it, once, so that an engine that can't speak is not tried again on every call.
void tts_voice::follow_preferred_engine() {
	if (voice_set || voice_state == VOICES_NONE) return;
	string preferred = tts_live_preferred_engine();
	if (preferred.empty() || preferred == followed_engine) return; // An engine setting that can't be read now changes nothing.
	if (voice_state == VOICES_FULL) {
		list_voices_again(false, false); // Lists any engine installed since too, and picks the preferred engine's default voice.
		return;
	}
	voice_state = VOICES_NONE;
	ensure_default();
}
bool tts_voice::sync_engine(engine_entry &entry, bool force) {
	tts_engine *engine = entry.engine.get();
	if (!engine) return false;
	if (!force && entry.synced) return true;
	// Push only what the script set on this object. Anything else is left alone, or, if the object stopped using a value it set, returned to the platform default, so a script that never sets a parameter always hears the user's own TTS settings.
	voice_info *voice = get_voice_info(current_voice_index);
	bool voice_applied = true;
	if (voice_set && voice) {
		// The index the list was built with names another voice once voices are installed or removed while the program runs, as SAPI lists them again on every call, so the voice is then found again by its name and language (names repeat on Apple platforms, which list some voices once per language), or, as in find_listed_voice, kept when only its language changed and no other voice of the engine has its name.
		int index = voice->engine_voice_index;
		if (engine->get_voice_name(index) != voice->name || engine->get_voice_language(index) != voice->language) {
			int count = engine->get_voice_count(), named = 0, found = -1;
			for (int i = 0; i < count; i++) {
				if (engine->get_voice_name(i) != voice->name) continue;
				named++;
				if (found < 0 && engine->get_voice_language(i) == voice->language) found = i;
			}
			if (found < 0 && named == 1 && engine->get_voice_name(index) == voice->name) found = index;
			index = found;
			if (index >= 0) voice->engine_voice_index = index;
		}
		voice_applied = index >= 0 && engine->set_voice(index);
		if (voice_applied) entry.voice_changed = true;
	} else if (entry.voice_changed) {
		entry.voice_changed = !tts_engine_restore_voice(entry); // A voice that couldn't be put back still counts as changed, so the engine isn't handed on with it.
	}
	float lo, mid, hi;
	if (rate_set) {
		if (engine->get_rate_range(lo, mid, hi)) engine->set_rate(range_convert_midpoint(nvgt_rate, -10.0f, 0.0f, 10.0f, lo, mid, hi));
		entry.rate_changed = true;
	} else if (entry.rate_changed) {
		if (!engine->reset_rate()) engine->set_rate(entry.init_rate);
		entry.rate_changed = false;
	}
	if (pitch_set) {
		if (engine->get_pitch_range(lo, mid, hi)) engine->set_pitch(range_convert_midpoint(nvgt_pitch, -10.0f, 0.0f, 10.0f, lo, mid, hi));
		entry.pitch_changed = true;
	} else if (entry.pitch_changed) {
		if (!engine->reset_pitch()) engine->set_pitch(entry.init_pitch);
		entry.pitch_changed = false;
	}
	if (volume_set) {
		if (engine->get_volume_range(lo, mid, hi)) engine->set_volume(range_convert_midpoint(nvgt_volume, -100.0f, -50.0f, 0.0f, lo, mid, hi));
		entry.volume_changed = true;
	} else if (entry.volume_changed) {
		if (!engine->reset_volume()) engine->set_volume(entry.init_volume);
		entry.volume_changed = false;
	}
	entry.synced = voice_applied; // A refused voice leaves the engine as it was, so the next use syncs it again.
	return voice_applied;
}
tts_engine *tts_voice::active_engine(bool force_sync, bool *voice_applied) {
	voice_info *voice = get_voice_info(current_voice_index);
	if (!voice) return nullptr;
	// Resolve this object's engine for the voice, binding it on first use. If it can't be bound (e.g. a restricted engine), report failure so the caller can fall back.
	engine_entry &entry = get_engine_entry(voice->engine_name);
	if (!entry.engine) return nullptr;
	current_engine = entry.engine;
	current_engine_name = voice->engine_name;
	// Puts the object's settings on the engine when they changed, and costs nothing otherwise.
	bool applied = sync_engine(entry, force_sync);
	if (voice_applied) *voice_applied = applied;
	return entry.engine.get();
}
int tts_voice::platform_voice_index() {
	for (int attempt = 0; attempt < 2; attempt++) {
		tts_engine *engine = active_engine();
		voice_info *voice = get_voice_info(current_voice_index);
		if (!engine || !voice) return -1;
		int engine_voice = engine->get_current_voice();
		if (engine_voice < 0) return -1;
		string name = engine->get_voice_name(engine_voice), language = engine->get_voice_language(engine_voice);
		int index = find_listed_voice(voices, voice->engine_name, engine_voice, name, language);
		if (index >= 0) {
			current_voice_index = index;
			return index;
		}
		// The user's settings can select a voice the list was made without, one installed while the program runs for instance, or on Android a voice of the language the user chose since that needs a network connection. Without a voice the script chose, the list is made again, once for each such voice, as a language filter can leave it out for good.
		string unlisted = voice->engine_name + '\n' + name + '\n' + language;
		if (voice_set || voice_state != VOICES_FULL || unlisted == relisted_for) return -1;
		relisted_for = unlisted;
		list_voices_again(false, false);
	}
	return -1;
}
void *tts_voice::speak_to_pcm(const string &text, tts_audio_data** datablock) {
	ensure_default();
	tts_engine *engine = active_engine();
	if (!datablock || !engine || engine->get_pcm_generation_state() == PCM_UNSUPPORTED) return nullptr;
	*datablock = engine->speak_to_pcm(tts_valid_utf8(text));
	if (!*datablock) return nullptr;
	// The engines check the format of their audio, so this only catches one that didn't: audio without data or channels, or with a sample size NVGT doesn't play, fails here with its block freed, rather than dividing by zero when trimmed or playing as noise.
	tts_audio_data *block = *datablock;
	if (!block->data || block->channels < 1 || block->sample_rate < 1 || (block->bitsize != 8 && block->bitsize != 16 && block->bitsize != 32)) {
		block->free();
		*datablock = nullptr;
		return nullptr;
	}
	bool quiet;
	float threshold = -60 + block->gain_db; // Measured against the engine's normal level, so speech an engine already made quieter keeps its quiet starts and ends.
	if (std::isnan(block->gain_db)) { // Turned down by an amount the engine can't tell, as each SAPI voice does in its own way.
		float peak = tts_peak_db(block);
		threshold = peak >= -60? min(-60.0f, peak - 60) : -60; // Measured against the speech's own loudest sample instead; audio never as loud as -60 dB is quiet, as at full volume.
	}
	void *trimmed = tts_trim(*datablock, &quiet, threshold, threshold);
	// Audio with nothing at the trimming threshold, -60 dB from the engine's normal level, is what some voices give for text with nothing to say, which is empty audio, as with the other voices. Speech is far louder at any volume from -40 up; below that, where speech could be that quiet too, the audio keeps its length.
	if (quiet && get_volume() >= -40) (*datablock)->size_in_bytes = 0;
	return trimmed;
}
// Speech that doesn't interrupt follows the object's earlier speech, whichever engine spoke it. Each path keeps its own speech in order, the sound system's queue and each engine that plays its own speech, so speech for one path is held while the object speaks on another, or while earlier speech is held, and started when its turn comes, by the object's start_held_speech() thread or a speak_wait() waiting for its own turn. Held speech counts as speaking, and interrupting speech or stop() drops it.
bool tts_voice::speak(const string &text, bool interrupt) {
	std::lock_guard<std::recursive_mutex> chain(chain_mtx);
	ensure_default();
	tts_engine *engine = active_engine();
	if (!engine) return false;
	if (engine->get_pcm_generation_state() == PCM_PREFERRED) {
		tts_audio_data* datablock = nullptr;
		void *trimmed_data = speak_to_pcm(text, &datablock);
		if (!trimmed_data || !datablock) return false;
		soundptr s;
		// Past sound_default_mixer, so a game that pauses or turns down its sounds there doesn't silence the speech too. The sound system starts on first use and can fail to; the speech then fails, its audio freed, rather than throwing at the script.
		try { s.reset(new_global_sound_unmixed()); } catch (...) {}
		ma_format format = tts_pcm_format(datablock);
		bool loaded = false;
		try { loaded = s && s->load_pcm(trimmed_data, datablock->size_in_bytes, format, datablock->sample_rate, datablock->channels); } catch (...) {} // Copying the audio into a wave file can run out of memory with long speech; that fails too, with the engine's audio freed.
		datablock->free();
		if (!loaded) return false;
		if (interrupt) interrupt_other_speech(engine);
		else if ((!held.empty() || other_path_speaking(nullptr)) && hold({s, nullptr, ""})) return true;
		return schedule(s, interrupt);
	}
	if (interrupt && !text.empty()) interrupt_other_speech(engine);
	else if (!interrupt && !text.empty() && (!held.empty() || other_path_speaking(engine)) && hold({nullptr, current_engine, tts_valid_utf8(text)})) return true;
	bool spoken = engine->speak(tts_valid_utf8(text), interrupt, false);
	if (!text.empty()) remember_native_engine(current_engine); // Even when it failed, as part of a long text can have been queued.
	return spoken;
}
bool tts_voice::speak_to_file(const string &filename, const string &text) {
	std::lock_guard<std::recursive_mutex> chain(chain_mtx);
	tts_audio_data* datablock;
	void *trimmed_data = speak_to_pcm(text, &datablock);
	if (!trimmed_data || !datablock) return false;
	try {
		string output;
		ma_format format = tts_pcm_format(datablock);
		if (!sound::pcm_to_wav(trimmed_data, datablock->size_in_bytes, format, datablock->sample_rate, datablock->channels, output)) {
			datablock->free();
			return false;
		}
		Poco::FileOutputStream file(filename, ios::binary | ios::trunc); // Without trunc, Poco opens an existing file without cutting it, and a longer old file kept its tail.
		file.write(output.data(), output.size());
		file.close();
		datablock->free();
		return file.good();
	} catch (...) {
		datablock->free();
		return false;
	}
}
string tts_voice::speak_to_memory(const string &text) {
	std::lock_guard<std::recursive_mutex> chain(chain_mtx);
	tts_audio_data* datablock;
	void *trimmed_data = speak_to_pcm(text, &datablock);
	if (!trimmed_data || !datablock) return "";
	string output;
	ma_format format = tts_pcm_format(datablock);
	bool converted = false;
	try { converted = sound::pcm_to_wav(trimmed_data, datablock->size_in_bytes, format, datablock->sample_rate, datablock->channels, output); } catch (...) {} // See speak().
	datablock->free();
	if (!converted) return "";
	return output;
}
// The lock is not held while this waits, so held speech can be started meanwhile and another script thread can stop the speech.
bool tts_voice::speak_wait(const string &text, bool interrupt) {
	std::unique_lock<std::recursive_mutex> chain(chain_mtx);
	ensure_default();
	tts_engine *engine = active_engine();
	if (!engine) return false;
	bool pcm = engine->get_pcm_generation_state() == PCM_PREFERRED;
	// Without interrupting, the text waits for its turn after the object's speech on other paths, starting held speech as its turn comes rather than leaving that to start_held_speech(). The lock is kept from the last look to the speech, so it can't be held after all.
	if (!interrupt && !text.empty()) {
		while (release_held() || other_path_speaking(pcm? nullptr : engine)) {
			chain.unlock();
			wait(10);
			chain.lock();
			// Another thread can have chosen another voice, or the voices can have been listed again, meanwhile.
			engine = active_engine();
			if (!engine) return false;
			pcm = engine->get_pcm_generation_state() == PCM_PREFERRED;
		}
	}
	if (pcm) {
		if (!speak(text, interrupt)) return false;
		chain.unlock();
		while (queue_speaking()) wait(10);
		return true;
	}
	if (interrupt && !text.empty()) interrupt_other_speech(engine);
	shared_ptr<tts_engine> speaking_engine = current_engine;
	if (!text.empty()) remember_native_engine(speaking_engine); // Before it speaks, so speech the object is given meanwhile waits for it, and even when it fails, as part of a long text can have been queued.
	chain.unlock();
	return speaking_engine->speak(tts_valid_utf8(text), interrupt, true);
}
sound *tts_voice::speak_to_sound(const string &text) {
	std::lock_guard<std::recursive_mutex> chain(chain_mtx);
	tts_audio_data* datablock;
	void *trimmed_data = speak_to_pcm(text, &datablock);
	if (!trimmed_data || !datablock) return nullptr;
	sound *s = nullptr;
	try { s = new_global_sound(); } catch (...) {} // See speak().
	ma_format format = tts_pcm_format(datablock);
	bool loaded = false;
	try { loaded = s && s->load_pcm(trimmed_data, datablock->size_in_bytes, format, datablock->sample_rate, datablock->channels); } catch (...) {}
	datablock->free();
	if (!loaded) {
		if (s) s->release();
		return nullptr;
	}
	return s;
}
// A parameter the script never set is read from the engine each time, so it reports the platform's current value (on Android the user's own speech settings, on Apple platforms the values a new utterance starts with) rather than a copy taken at startup.
float tts_voice::get_rate() {
	std::lock_guard<std::recursive_mutex> chain(chain_mtx);
	if (rate_set) return fRound(nvgt_rate, 3);
	ensure_default();
	tts_engine *engine = active_engine();
	float lo, mid, hi;
	if (!engine || !engine->get_rate_range(lo, mid, hi)) return 0;
	return fRound(range_convert_midpoint(engine->get_rate(), lo, mid, hi, -10.0f, 0.0f, 10.0f), 3);
}
float tts_voice::get_pitch() {
	std::lock_guard<std::recursive_mutex> chain(chain_mtx);
	if (pitch_set) return fRound(nvgt_pitch, 3);
	ensure_default();
	tts_engine *engine = active_engine();
	float lo, mid, hi;
	if (!engine || !engine->get_pitch_range(lo, mid, hi)) return 0;
	return fRound(range_convert_midpoint(engine->get_pitch(), lo, mid, hi, -10.0f, 0.0f, 10.0f), 3);
}
float tts_voice::get_volume() {
	std::lock_guard<std::recursive_mutex> chain(chain_mtx);
	if (volume_set) return fRound(nvgt_volume, 3);
	ensure_default();
	tts_engine *engine = active_engine();
	float lo, mid, hi;
	if (!engine || !engine->get_volume_range(lo, mid, hi)) return 0;
	return fRound(range_convert_midpoint(engine->get_volume(), lo, mid, hi, -100.0f, -50.0f, 0.0f), 3);
}
int tts_voice::get_voice_count() {
	std::lock_guard<std::recursive_mutex> chain(chain_mtx);
	ensure_enumerated();
	return voices.size();
}
string tts_voice::get_voice_name(int index) {
	std::lock_guard<std::recursive_mutex> chain(chain_mtx);
	ensure_enumerated();
	voice_info *voice = get_voice_info(index);
	return voice? voice->name : "";
}
int tts_voice::get_current_voice() {
	std::lock_guard<std::recursive_mutex> chain(chain_mtx);
	ensure_enumerated();
	return voice_set? current_voice_index : platform_voice_index();
}
void tts_voice::set_rate(float rate) {
	std::lock_guard<std::recursive_mutex> chain(chain_mtx);
	if (std::isnan(rate)) return; // See set_volume().
	ensure_default();
	nvgt_rate = clamp(rate, -10.0f, 10.0f);
	rate_set = true;
	active_engine(true); // push the new parameter onto the engine
}
void tts_voice::set_pitch(float pitch) {
	std::lock_guard<std::recursive_mutex> chain(chain_mtx);
	if (std::isnan(pitch)) return; // See set_volume().
	ensure_default();
	nvgt_pitch = clamp(pitch, -10.0f, 10.0f);
	pitch_set = true;
	active_engine(true);
}
// NaN is no value: clamp lets it through, and the builtin synthesizer crashes on it, so it leaves the setting as it was.
void tts_voice::set_volume(float volume) {
	std::lock_guard<std::recursive_mutex> chain(chain_mtx);
	if (std::isnan(volume)) return;
	ensure_default();
	nvgt_volume = clamp(volume, -100.0f, 0.0f);
	volume_set = true;
	active_engine(true);
}
CScriptArray *tts_voice::list_voices() {
	std::lock_guard<std::recursive_mutex> chain(chain_mtx);
	ensure_enumerated();
	asIScriptContext *ctx = asGetActiveContext();
	asIScriptEngine *engine = ctx->GetEngine();
	asITypeInfo *arrayType = engine->GetTypeInfoByDecl("array<string>");
	CScriptArray *array = CScriptArray::Create(arrayType);
	array->Reserve(voices.size());
	for (const auto &voice : voices) {
		string voice_name = voice.name;
		array->InsertLast(&voice_name);
	}
	return array;
}
bool tts_voice::set_voice(int voice) {
	std::lock_guard<std::recursive_mutex> chain(chain_mtx);
	ensure_enumerated();
	if (voice < 0 || voice >= static_cast<int>(voices.size())) return false;
	if (!get_voice_info(voice)) return false;
	int previous_voice_index = current_voice_index;
	bool previous_voice_set = voice_set;
	shared_ptr<tts_engine> previous_engine = current_engine;
	string previous_engine_name = current_engine_name;
	current_voice_index = voice;
	voice_set = true;
	// Binding happens here, lazily, via active_engine(), which also applies whatever rate/pitch/volume the script set to the newly selected engine. If the engine backing this voice can't be bound (e.g. a restricted Android engine like Sao Mai Myanmar TTS), or refuses the voice (one it can't load), stay on whatever was selected before and report failure rather than leaving the object pointing at an unusable voice.
	bool applied = false;
	if (!active_engine(true, &applied) || !applied) {
		current_voice_index = previous_voice_index;
		voice_set = previous_voice_set;
		current_engine = previous_engine;
		current_engine_name = previous_engine_name;
		return false;
	}
	voice_remembered = false; // A voice chosen now replaces one that left the list.
	return true;
}
// The queue of speech played through the sound system belongs to this object rather than to an engine, so it is reported and stopped whichever voice is selected now, as is speech on engines this object spoke on before another voice was selected.
bool tts_voice::get_rate_set() { std::lock_guard<std::recursive_mutex> chain(chain_mtx); return rate_set; }
bool tts_voice::get_pitch_set() { std::lock_guard<std::recursive_mutex> chain(chain_mtx); return pitch_set; }
bool tts_voice::get_volume_set() { std::lock_guard<std::recursive_mutex> chain(chain_mtx); return volume_set; }
bool tts_voice::get_voice_set() { std::lock_guard<std::recursive_mutex> chain(chain_mtx); return voice_set; }
bool tts_voice::get_speaking() {
	std::lock_guard<std::recursive_mutex> chain(chain_mtx);
	if (!held.empty() || queue_speaking()) return true;
	if (current_engine && current_engine->get_pcm_generation_state() != PCM_PREFERRED && current_engine->is_speaking()) return true;
	for (const auto &engine : native_engines) if (engine != current_engine && engine->is_speaking()) return true;
	return false;
}
bool tts_voice::refresh() { return list_voices_again(true, true); }
// The object's list made again. Only refresh() as the script calls it has the engines list their voices again, which costs a call to the platform's speech service each, as a change an engine reports it takes up by itself. Engines that couldn't be bound for this object, which can each take as long as binding waits to fail again, are tried again by refresh(), set_language() and the first full list, as they always were, but not when the list is made again to follow the user's settings or installed voices.
bool tts_voice::list_voices_again(bool relist_engines, bool retry_unbound) {
	std::lock_guard<std::recursive_mutex> chain(chain_mtx);
	// An engine this object couldn't bind is tried again, unless it never bound anywhere: one that has worked can fail for a while, while it restarts for instance, and the object would otherwise go without it for good.
	if (retry_unbound) {
		std::lock_guard<std::mutex> lock(g_engine_pool_mutex);
		for (auto it = engines.begin(); it != engines.end();) {
			if (!it->second.engine && !g_unusable_engines.count(it->first)) it = engines.erase(it);
			else ++it;
		}
	}
	voice_state = VOICES_FULL;
	string preferred = tts_preferred_engine();
	followed_engine = preferred;
	if (all_engines) engine_names = tts_get_engine_names(); // Including any registered since, as an engine installed while the program runs is when it becomes the preferred one.
	voice_info old_voice{};
	bool had_voice = false;
	if (current_voice_index >= 0 && current_voice_index < static_cast<int>(voices.size())) {
		old_voice = voices[current_voice_index];
		had_voice = true;
	}
	voices.clear();
	// Track each engine's own current/default voice index so we can preserve the platform default voice when picking an initial selection.
	unordered_map<string, int> engine_default_voice;
	for (const string &name : engine_names) {
		// An engine that refuses to bind is remembered as unusable and simply contributes no voices instead of taking down the whole list.
		engine_entry &entry = get_engine_entry(name);
		tts_engine *engine = entry.engine.get();
		if (!engine || !engine->is_available()) continue;
		entry.voices_generation = engine->voices_generation();
		if (relist_engines) engine->refresh_voices();
		engine_default_voice[name] = tts_engine_default_voice(entry);
		int voice_count = engine->get_voice_count();
		for (int i = 0; i < voice_count; i++) {
			std::string lang = engine->get_voice_language(i);
			if (tts_language_matches(lang, current_language)) voices.emplace_back(voice_info{name, i, engine->get_voice_name(i), lang});
		}
	}
	current_voice_index = -1;
	// Only a voice the script chose is carried over. Without a choice the selection must keep following the platform default, which the block below picks.
	if (had_voice && voice_set) {
		current_voice_index = find_listed_voice(voices, old_voice.engine_name, old_voice.engine_voice_index, old_voice.name, old_voice.language);
		// A chosen voice can leave the list for good or only for a moment, as while an installer replaces it, so it is remembered and chosen again once a list holds it again, unless the script chooses a voice or a language first.
		if (current_voice_index < 0) {
			remembered_voice = old_voice;
			voice_remembered = true;
		}
	} else if (voice_remembered) {
		current_voice_index = find_listed_voice(voices, remembered_voice.engine_name, remembered_voice.engine_voice_index, remembered_voice.name, remembered_voice.language);
		if (current_voice_index >= 0) {
			voice_set = true;
			voice_remembered = false;
		}
	}
	if (current_voice_index < 0) voice_set = false; // The chosen voice is gone, so fall back to the platform default rather than forcing whichever voice lands on its old index.
	if (current_voice_index < 0 && !voices.empty()) {
		// Pick an initial voice: prefer the configured/default engine, then the platform's own order, then the first non-fallback engine, then anything, as ensure_default() does. Only an engine with a voice in the list counts: one that could not be bound, or whose voices the language filter left out, would match nothing below and leave the selection on the first voice, the builtin fallback.
		auto has_voice = [&](const string &name) { for (const auto &v : voices) if (v.engine_name == name) return true; return false; };
		string chosen_engine;
		if (!preferred.empty() && has_voice(preferred)) chosen_engine = preferred;
		if (chosen_engine.empty()) for (const string &name : tts_engine_ranking()) if (name != "fallback" && has_voice(name)) { chosen_engine = name; break; }
		if (chosen_engine.empty()) for (const auto &v : voices) if (v.engine_name != "fallback") { chosen_engine = v.engine_name; break; }
		if (chosen_engine.empty()) chosen_engine = voices.front().engine_name;
		int target = engine_default_voice.count(chosen_engine)? engine_default_voice[chosen_engine] : -1;
		for (size_t i = 0; i < voices.size(); i++) {
			if (voices[i].engine_name != chosen_engine) continue;
			if (current_voice_index < 0) current_voice_index = i; // The engine's first voice, kept when its own default isn't in the list, for example because the language filter left it out.
			if (target < 0 || voices[i].engine_voice_index == target) { current_voice_index = i; break; }
		}
	}
	// If our cached active-engine pointer no longer matches the selected voice, drop it so the next use resolves it again. (This does not unbind anything; the object's engine entries keep the engine.)
	voice_info *sel = get_voice_info(current_voice_index);
	if (current_engine && (!sel || current_engine_name != sel->engine_name)) { current_engine.reset(); current_engine_name.clear(); }
	// The list was rebuilt, so our selection may now sit on a different engine index; make the next use sync the engine again instead of assuming it already carries our settings.
	if (sel) get_engine_entry(sel->engine_name).synced = false;
	return !voices.empty();
}
bool tts_voice::stop() {
	std::lock_guard<std::recursive_mutex> chain(chain_mtx);
	held.clear();
	sound_queue removed; // Released after the lock, see clear().
	{
		unique_lock<mutex> lock(queue_mtx);
		removed = clear();
	}
	bool stopped = true;
	// An engine that couldn't be stopped is kept while it goes on speaking, so the object still reports that speech and holds later speech behind it.
	native_engines.erase(remove_if(native_engines.begin(), native_engines.end(), [&](const shared_ptr<tts_engine> &engine) {
		if (engine == current_engine || engine->stop()) return true;
		stopped = false;
		return !engine->is_speaking();
	}), native_engines.end());
	if (current_engine && current_engine->get_pcm_generation_state() != PCM_PREFERRED && !current_engine->stop()) {
		stopped = false;
		if (current_engine->is_speaking()) native_engines.push_back(current_engine); // So it is still followed once another voice is selected.
	}
	return stopped;
}
string tts_voice::get_engine_name() {
	std::lock_guard<std::recursive_mutex> chain(chain_mtx);
	ensure_default();
	voice_info *voice = get_voice_info(current_voice_index);
	return voice? voice->engine_name : "";
}
int tts_voice::get_engine_count() { return engine_names.size(); }
string tts_voice::get_engine_name(int index) {
	if (index < 0 || index >= static_cast<int>(engine_names.size())) return "";
	return engine_names[index];
}
string tts_voice::get_voice_language(int index) {
	std::lock_guard<std::recursive_mutex> chain(chain_mtx);
	ensure_enumerated();
	if (index < 0 || index >= static_cast<int>(voices.size())) return "";
	return voices[index].language;
}
bool tts_voice::set_language(const string& language) {
	std::lock_guard<std::recursive_mutex> chain(chain_mtx);
	// A language no voice serves, or whose voices the engines all refuse, leaves the object as it was, as a failed set_voice() does, rather than without voices and unable to speak.
	string previous_language = current_language, previous_engine_name = current_engine_name;
	vector<voice_info> previous_voices = voices;
	voice_enum_state previous_state = voice_state;
	int previous_voice_index = current_voice_index;
	bool previous_voice_set = voice_set;
	shared_ptr<tts_engine> previous_engine = current_engine;
	string previous_followed_engine = followed_engine;
	unordered_map<string, uint64_t> previous_generations;
	for (auto &[name, entry] : engines) previous_generations[name] = entry.voices_generation;
	bool previous_voice_remembered = voice_remembered;
	auto restore = [&]() {
		current_language = previous_language;
		voice_remembered = previous_voice_remembered;
		// The list put back is the one made before, so a preferred engine or a change of the voices the new list already took up is still to be followed.
		followed_engine = previous_followed_engine;
		for (auto &[name, generation] : previous_generations) {
			auto entry = engines.find(name);
			if (entry != engines.end()) entry->second.voices_generation = generation;
		}
		voices = previous_voices;
		voice_state = previous_state;
		current_voice_index = previous_voice_index;
		voice_set = previous_voice_set;
		current_engine = previous_engine;
		current_engine_name = previous_engine_name;
		return false;
	};
	current_language = language;
	list_voices_again(false, true);
	if (!language.empty()) voice_remembered = false; // A language chosen now replaces a voice that left the list, and the filter leaving out the chosen voice is no voice leaving. An empty one only lifts the filter.
	if (voices.empty()) return restore();
	// Asking for a language is asking for one of its voices, so the voice refresh() picked from the filtered list is pushed onto the engine like a set_voice() call, and when the engine refuses it, the other voices of the language are tried in turn. An empty language only lifts the filter and changes nothing about the selection.
	if (!language.empty() && get_voice_info(current_voice_index)) {
		voice_set = true;
		int picked = current_voice_index;
		for (size_t i = 0; i < voices.size(); i++) {
			current_voice_index = (picked + i) % voices.size();
			bool applied = false;
			if (active_engine(true, &applied) && applied) return true;
		}
		return restore();
	}
	return true;
}
// The language filter the script set, or, without one, the language of the voice actually in use.
string tts_voice::get_language() {
	std::lock_guard<std::recursive_mutex> chain(chain_mtx);
	if (!current_language.empty()) return current_language;
	ensure_default();
	voice_info *voice = get_voice_info(voice_set? current_voice_index : platform_voice_index());
	return voice? voice->language : "";
}

bool tts_voice::schedule(soundptr &s, bool interrupt) {
	try {
		cleanup_completed_fades();
		ma_sound_set_end_callback(s->get_ma_sound(), at_end, (void*)(uintptr_t)id); // The id rather than this, see g_live_tts_voices.
		sound_queue removed; // Released after the lock, see clear().
		unique_lock<mutex> lock(queue_mtx);
		if (interrupt) removed = clear();
		else {
			advance_queue(); // See queue_speaking().
			removed.swap(finished);
		}
		queue.push(s);
		speaking.test_and_set();
		if (queue.size() == 1) s->play();
		return true;
	} catch (exception &) { return false; }
}
// Interrupting speech also silences what this object started on another path: the queue played through the sound system when the engine about to speak plays its own speech, and an engine selected before.
void tts_voice::interrupt_other_speech(tts_engine *engine) {
	held.clear();
	sound_queue removed; // Released after the lock, see clear().
	if (engine->get_pcm_generation_state() != PCM_PREFERRED) {
		unique_lock<mutex> lock(queue_mtx);
		if (!queue.empty()) removed = clear();
	}
	native_engines.erase(remove_if(native_engines.begin(), native_engines.end(), [engine](const shared_ptr<tts_engine> &other) { return other.get() != engine && (other->stop() || !other->is_speaking()); }), native_engines.end()); // As in stop(), one that couldn't be stopped is kept while it speaks.
}
// Remembers the engine that just spoke, leaving out engines whose speech has ended.
void tts_voice::remember_native_engine(const shared_ptr<tts_engine> &spoke) {
	native_engines.erase(remove_if(native_engines.begin(), native_engines.end(), [&](const shared_ptr<tts_engine> &engine) { return engine != current_engine && engine != spoke && !engine->is_speaking(); }), native_engines.end());
	if (spoke && find(native_engines.begin(), native_engines.end(), spoke) == native_engines.end()) native_engines.push_back(spoke);
}
// Whether the object speaks on a path other than the given engine's: the sound system's queue, unless the engine is null, which stands for that queue, and engines that play their own speech.
bool tts_voice::other_path_speaking(tts_engine *engine) {
	if (engine && queue_speaking()) return true;
	for (const auto &other : native_engines) if (other.get() != engine && other->is_speaking()) return true;
	return false;
}
// Holds speech for start_held_speech() to start, starting that thread when it isn't running. False, holding nothing, at shutdown or when no thread can be started, so the speech is started at once instead. Expects chain_mtx held.
bool tts_voice::hold(held_speech &&speech) {
	{
		std::lock_guard<std::mutex> lock(g_held_speech_mutex);
		if (g_held_speech_closed) return false;
	}
	held.push_back(std::move(speech));
	if (held_starter_running) return true;
	if (held_starter.joinable()) held_starter.join(); // A starter that has stopped takes the lock no more, so it is waited for under the lock.
	try {
		held_starter = std::thread(&tts_voice::start_held_speech, this);
	} catch (const std::system_error &) {
		held.pop_back();
		return false;
	}
	held_starter_running = true; // Before the thread can look, as it waits for the lock held here.
	return true;
}
// Starts held speech whose turn has come, in order: speech for a path once the object no longer speaks on any other. True while some is still held. Expects chain_mtx held.
bool tts_voice::release_held() {
	while (!held.empty()) {
		tts_engine *engine = held.front().sound? nullptr : held.front().engine.get();
		if (other_path_speaking(engine)) return true;
		held_speech speech = std::move(held.front());
		held.pop_front();
		if (speech.sound) schedule(speech.sound, false);
		else {
			speech.engine->speak(speech.text, false, false);
			remember_native_engine(speech.engine);
		}
	}
	return false;
}
// Each object with held speech has a thread of its own starting it, every 20 milliseconds while some is held, so an engine call that takes long, as when an engine reconnects, holds up only this object's speech. The thread ends once none is held or the object is being destroyed, deciding so under the object's lock, and takes the lock no more after that, so hold() can wait for it to end while holding the lock, and the destructor waits for it before anything of the object goes.
void tts_voice::start_held_speech() {
	while (true) {
		{
			std::lock_guard<std::recursive_mutex> chain(chain_mtx);
			if (held_starter_stop || !release_held()) {
				held_starter_running = false;
				return;
			}
		}
		std::this_thread::sleep_for(std::chrono::milliseconds(20));
	}
}
// Moves the queue past its front utterance once that has played to its end, into finished. Expects queue_mtx held.
void tts_voice::advance_queue() {
	if (queue.empty() || !ma_sound_at_end(queue.front()->get_ma_sound())) return;
	finished.push(queue.front());
	queue.pop();
	if (queue.empty()) speaking.clear();
	else queue.front()->play();
}
// Whether speech queued through the sound system is still playing. The end of each utterance is handled by a job that its end callback posts, and also here, so the queue still moves on when the resource manager's job queue was full and the job was lost.
bool tts_voice::queue_speaking() {
	if (!speaking.test()) return false;
	sound_queue done; // Released after the lock, see clear().
	unique_lock<mutex> lock(queue_mtx);
	advance_queue();
	done.swap(finished);
	return speaking.test();
}
// Empties the queue, fading out what plays, and hands the removed sounds to the caller to release once it has let go of queue_mtx: a sound still loading waits for the resource manager's job thread when it is destroyed, and that thread can be waiting for the lock in job_proc. Expects queue_mtx held.
tts_voice::sound_queue tts_voice::clear() {
	if (!queue.empty() && queue.front()->get_playing()) fade(queue.front());
	sound_queue removed;
	removed.swap(queue);
	for (; !finished.empty(); finished.pop()) removed.push(finished.front());
	speaking.clear();
	return removed;
}
// Fades interrupted speech out over 20 ms and stops it then, rather than letting it play on silently to its end.
bool tts_voice::fade(soundptr &item) {
	ma_sound_stop_with_fade_in_milliseconds(item->get_ma_sound(), 20);
	try {
		fade_queue.push(item);
		return true;
	} catch (const exception &) { return false; }
}
// Releases the faded sounds that are silent, wherever they are in the queue: one whose engine no longer processes audio, stopped or without a device, never finishes its fade, and must not keep those faded after it. The fade volume is read from miniaudio, linear whatever units the sound reports its attributes in: with the percentage attributes of the default engine, the sound's own getter reports decibels, never above 0.
void tts_voice::cleanup_completed_fades() {
	for (size_t i = fade_queue.size(); i > 0; i--) {
		soundptr item = std::move(fade_queue.front());
		fade_queue.pop();
		if (!item->is_load_completed() || (item->get_playing() && ma_sound_get_current_fade_volume(item->get_ma_sound()) > 0)) fade_queue.push(std::move(item));
	}
}
void tts_voice::at_end(void *pUserData, ma_sound *pSound) {
	ma_job job = ma_job_init(MA_JOB_TYPE_CUSTOM);
	job.data.custom.data0 = (ma_uintptr)pUserData; // The voice's id.
	job.data.custom.data1 = (ma_uintptr)pSound;
	job.data.custom.proc = job_proc;
	ma_engine *engine = ma_sound_get_engine(pSound); // Rather than g_audio_engine, which is cleared when sound shuts down while sounds still hold the engine.
	if (engine && engine->pResourceManager && ma_resource_manager_post_job(engine->pResourceManager, &job) == MA_SUCCESS) return;
	// The job queue is full, as it can be while many sounds load. Rather than leave the next utterance waiting for the script's next call on the object, the queue moves on here, on the audio thread, when the locks are free: starting the next sound only marks it started, and the finished one is closed on a script thread as ever. When they aren't, queue_speaking() makes up for it.
	unique_lock<mutex> live_lock(g_live_tts_voices_mutex, try_to_lock);
	if (!live_lock.owns_lock()) return;
	auto live = g_live_tts_voices.find((uintptr_t)pUserData);
	if (live == g_live_tts_voices.end()) return;
	tts_voice *voice = live->second;
	unique_lock<mutex> lock(voice->queue_mtx, try_to_lock);
	if (!lock.owns_lock() || voice->queue.empty() || voice->queue.front()->get_ma_sound() != pSound) return;
	voice->advance_queue();
}
ma_result tts_voice::job_proc(ma_job *pJob) {
	// Held until the voice's queue lock below is released, so the voice can't be destroyed in between.
	std::lock_guard<std::mutex> live_lock(g_live_tts_voices_mutex);
	auto live = g_live_tts_voices.find((uintptr_t)pJob->data.custom.data0);
	if (live == g_live_tts_voices.end()) return MA_CANCELLED;
	tts_voice *voice = live->second;
	ma_sound *expected_front = (ma_sound *)pJob->data.custom.data1;
	unique_lock<mutex> lock(voice->queue_mtx);
	// The utterance can already be gone, removed by stop() or by an interrupting speak(), and the sound now at the front can sit at its freed address, so only one that has played to its end is moved past.
	if (voice->queue.empty() || voice->queue.front()->get_ma_sound() != expected_front) return MA_CANCELLED;
	voice->advance_queue();
	return MA_SUCCESS;
}

CScriptArray *tts_get_engines() {
	asIScriptContext *ctx = asGetActiveContext();
	asIScriptEngine *engine = ctx->GetEngine();
	asITypeInfo *arrayType = engine->GetTypeInfoByDecl("array<string>");
	CScriptArray *array = CScriptArray::Create(arrayType);
	vector<string> names;
	{
		std::lock_guard<std::recursive_mutex> lock(g_tts_registry_mutex); // As in the tts_voice constructor, the engines register on first use.
		if (engine_registry.empty()) register_builtin_engines();
		names = engine_names;
	}
	array->Reserve(names.size());
	for (string &name : names) array->InsertLast(&name);
	return array;
}

tts_voice* new_tts_voice(const string& engines) { return new tts_voice(engines); }
void RegisterTTSVoice(asIScriptEngine *engine) {
	engine->RegisterObjectType("tts_voice", 0, asOBJ_REF);
	engine->RegisterObjectBehaviour("tts_voice", asBEHAVE_FACTORY, _O("tts_voice @t(const string&in engines = \"\")"), asFUNCTION(new_tts_voice), asCALL_CDECL);
	engine->RegisterObjectBehaviour("tts_voice", asBEHAVE_ADDREF, "void f()", asMETHOD(tts_voice, AddRef), asCALL_THISCALL);
	engine->RegisterObjectBehaviour("tts_voice", asBEHAVE_RELEASE, "void f()", asMETHOD(tts_voice, Release), asCALL_THISCALL);
	engine->RegisterObjectMethod("tts_voice", "bool speak(const string &in text, bool interrupt = false)", asMETHOD(tts_voice, speak), asCALL_THISCALL);
	engine->RegisterObjectMethod("tts_voice", "bool speak_interrupt(const string &in text)", asMETHOD(tts_voice, speak_interrupt), asCALL_THISCALL);
	engine->RegisterObjectMethod("tts_voice", "bool speak_to_file(const string& in filename, const string &in text)", asMETHOD(tts_voice, speak_to_file), asCALL_THISCALL);
	engine->RegisterObjectMethod("tts_voice", "bool speak_wait(const string &in text, bool interrupt = false)", asMETHOD(tts_voice, speak_wait), asCALL_THISCALL);
	engine->RegisterObjectMethod("tts_voice", "string speak_to_memory(const string &in text)", asMETHOD(tts_voice, speak_to_memory), asCALL_THISCALL);
	engine->RegisterObjectMethod("tts_voice", Poco::format("%s::sound@ speak_to_sound(const string &in text)", get_system_namespace("sound")).c_str(), asMETHOD(tts_voice, speak_to_sound), asCALL_THISCALL);
	engine->RegisterObjectMethod("tts_voice", "bool speak_interrupt_wait(const string &in text)", asMETHOD(tts_voice, speak_interrupt_wait), asCALL_THISCALL);
	engine->RegisterObjectMethod("tts_voice", "bool refresh()", asMETHOD(tts_voice, refresh), asCALL_THISCALL);
	engine->RegisterObjectMethod("tts_voice", "bool stop()", asMETHOD(tts_voice, stop), asCALL_THISCALL);
	engine->RegisterObjectMethod("tts_voice", "array<string>@ list_voices() const", asMETHOD(tts_voice, list_voices), asCALL_THISCALL);
	// Alias the above as get_voice_names() for legacy BGT code.
	engine->RegisterObjectMethod("tts_voice", "array<string>@ get_voice_names() const", asMETHOD(tts_voice, list_voices), asCALL_THISCALL);
	engine->RegisterObjectMethod("tts_voice", "bool set_voice(int index)", asMETHOD(tts_voice, set_voice), asCALL_THISCALL);
	// Alias the above as set_current_voice() for legacy BGT code.
	engine->RegisterObjectMethod("tts_voice", "bool set_current_voice(int index)", asMETHOD(tts_voice, set_voice), asCALL_THISCALL);
	engine->RegisterObjectMethod("tts_voice", "float get_rate() const property", asMETHOD(tts_voice, get_rate), asCALL_THISCALL);
	engine->RegisterObjectMethod("tts_voice", "void set_rate(float rate) property", asMETHOD(tts_voice, set_rate), asCALL_THISCALL);
	engine->RegisterObjectMethod("tts_voice", "float get_pitch() const property", asMETHOD(tts_voice, get_pitch), asCALL_THISCALL);
	engine->RegisterObjectMethod("tts_voice", "void set_pitch(float pitch) property", asMETHOD(tts_voice, set_pitch), asCALL_THISCALL);
	engine->RegisterObjectMethod("tts_voice", "float get_volume() const property", asMETHOD(tts_voice, get_volume), asCALL_THISCALL);
	engine->RegisterObjectMethod("tts_voice", "void set_volume(float volume) property", asMETHOD(tts_voice, set_volume), asCALL_THISCALL);
	engine->RegisterObjectMethod("tts_voice", "int get_voice_count() const property", asMETHOD(tts_voice, get_voice_count), asCALL_THISCALL);
	engine->RegisterObjectMethod("tts_voice", "string get_voice_name(int index) const", asMETHOD(tts_voice, get_voice_name), asCALL_THISCALL);
	engine->RegisterObjectMethod("tts_voice", "string get_voice_language(int index) const", asMETHOD(tts_voice, get_voice_language), asCALL_THISCALL);
	engine->RegisterObjectMethod("tts_voice", "bool set_language(const string& in language)", asMETHOD(tts_voice, set_language), asCALL_THISCALL);
	engine->RegisterObjectMethod("tts_voice", "string get_language() const property", asMETHOD(tts_voice, get_language), asCALL_THISCALL);
	engine->RegisterObjectMethod("tts_voice", "bool get_speaking() const property", asMETHOD(tts_voice, get_speaking), asCALL_THISCALL);
	engine->RegisterObjectMethod("tts_voice", "bool get_rate_set() const property", asMETHOD(tts_voice, get_rate_set), asCALL_THISCALL);
	engine->RegisterObjectMethod("tts_voice", "bool get_pitch_set() const property", asMETHOD(tts_voice, get_pitch_set), asCALL_THISCALL);
	engine->RegisterObjectMethod("tts_voice", "bool get_volume_set() const property", asMETHOD(tts_voice, get_volume_set), asCALL_THISCALL);
	engine->RegisterObjectMethod("tts_voice", "bool get_voice_set() const property", asMETHOD(tts_voice, get_voice_set), asCALL_THISCALL);
	engine->RegisterObjectMethod("tts_voice", "int get_voice() const property", asMETHOD(tts_voice, get_current_voice), asCALL_THISCALL);
	engine->RegisterGlobalFunction("bool get_SCREEN_READER_AVAILABLE() property", asFUNCTION(screen_reader_load), asCALL_CDECL);
	engine->RegisterGlobalFunction("string screen_reader_detect()", asFUNCTION(screen_reader_detect), asCALL_CDECL);
	engine->RegisterGlobalFunction("bool screen_reader_has_speech()", asFUNCTION(screen_reader_has_speech), asCALL_CDECL);
	engine->RegisterGlobalFunction("bool screen_reader_has_braille()", asFUNCTION(screen_reader_has_braille), asCALL_CDECL);
	engine->RegisterGlobalFunction("bool screen_reader_is_speaking()", asFUNCTION(screen_reader_is_speaking), asCALL_CDECL);
	engine->RegisterGlobalFunction("bool screen_reader_output(const string &in text, bool interrupt = true)", asFUNCTION(screen_reader_output), asCALL_CDECL);
	engine->RegisterGlobalFunction("bool screen_reader_speak(const string &in text, bool interrupt = true)", asFUNCTION(screen_reader_speak), asCALL_CDECL);
	engine->RegisterGlobalFunction("bool screen_reader_braille(const string &in text)", asFUNCTION(screen_reader_braille), asCALL_CDECL);
	engine->RegisterGlobalFunction("bool screen_reader_silence()", asFUNCTION(screen_reader_silence), asCALL_CDECL);
}
