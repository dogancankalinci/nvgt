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
#include <algorithm>
#include <unordered_map>
#include <unordered_set>
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

// Trim prenormalized TTS based on minimum thresholds in dB. Size is in frames. A sample's level is its distance from silence, which is 128 for unsigned 8-bit samples and 0 for signed ones, relative to the largest such distance.
template <class t> static t *tts_trim_internal(t *data, unsigned int* size_in_frames, int channels, float begin_db, float end_db, double silence = 0, double peak = numeric_limits<t>::max()) {
	double min_begin_sample = ceil(ma_volume_db_to_linear(begin_db) * peak);
	double min_end_sample = ceil(ma_volume_db_to_linear(end_db) * peak);
	for (unsigned long i = 0; i < *size_in_frames; i++) {
		double mean = 0;
		for (int c = 0; c < channels; c++)
			mean += fabs(data[(i * channels) + c] - silence);
		mean /= channels;
		if (mean >= min_begin_sample) {
			*size_in_frames -= i;
			data += i * channels;
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

static void* tts_trim(tts_audio_data* data, float begin_db = -60, float end_db = -60) {
	unsigned int size_in_frames;
	void* trimmed_data;
	switch (data->bitsize) {
		case 16:
			size_in_frames = data->size_in_bytes / 2 / data->channels;
			trimmed_data = tts_trim_internal<int16_t>((int16_t*)data->data, &size_in_frames, data->channels, begin_db, end_db);
			data->size_in_bytes = size_in_frames * 2 * data->channels;
			return trimmed_data;
		case 8:
			size_in_frames = data->size_in_bytes / data->channels;
			trimmed_data = tts_trim_internal<uint8_t>((uint8_t*)data->data, &size_in_frames, data->channels, begin_db, end_db, 128, 127);
			data->size_in_bytes = size_in_frames * data->channels;
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

// Fallback voice engine using RSynth
class fallback_voice_engine : public tts_engine_impl {
	float rate, pitch, volume;
public:
	fallback_voice_engine() : tts_engine_impl("fallback"), rate(10), pitch(1330), volume(60) {}
	tts_pcm_generation_state get_pcm_generation_state() override { return PCM_PREFERRED; }
	tts_audio_data* speak_to_pcm(const string &text) override {
		if (text.empty()) return nullptr;
		int samples;
		char *data = (char *)speech_gen(&samples, text.c_str(), 20 - rate, pitch, volume, NULL); // smaller rate values mean faster so we must reverse the rate value here.
		if (!data) return nullptr;
		return new tts_audio_data(this, data, samples * 4, 44100, 2, 16);
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
void tts_set_engine_ranking(const vector<string> &names) { engine_ranking = names; }

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
void tts_release_idle_engines() {
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
tts_voice::tts_voice(const string &engine_list) : RefCount(1), voice_state(VOICES_NONE), current_voice_index(-1), nvgt_rate(0), nvgt_pitch(0), nvgt_volume(0), rate_set(false), pitch_set(false), volume_set(false), voice_set(false), id(++g_next_tts_voice_id) {
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
	if (voice_state != VOICES_NONE) return;
	// Fast path for the common case (speak with the default voice): bind engines one at a time, the preferred/default engine first and then the others in the platform's own order, and select the default voice of the first one that can speak, so we never instantiate or bind every installed engine just to start speaking. Only engines in this object's list count, and the fallback voice is left to refresh() unless it is all the list holds. Full cross-engine enumeration is deferred until the script actually lists or selects voices.
	vector<string> candidates;
	auto consider = [&](const string &name) {
		if (name.empty() || name == "fallback" || find(engine_names.begin(), engine_names.end(), name) == engine_names.end() || find(candidates.begin(), candidates.end(), name) != candidates.end()) return;
		candidates.push_back(name);
	};
	consider(preferred_engine_name);
	for (const string &name : engine_ranking) consider(name);
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
		return;
	}
	voices.clear();
	refresh(); // No candidate could speak: fall back to a full search for anything usable.
}
void tts_voice::ensure_enumerated() { if (voice_state != VOICES_FULL) refresh(); }
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
	tts_engine *engine = active_engine();
	voice_info *voice = get_voice_info(current_voice_index);
	if (!engine || !voice) return -1;
	int engine_voice = engine->get_current_voice();
	if (engine_voice < 0) return -1;
	int index = find_listed_voice(voices, voice->engine_name, engine_voice, engine->get_voice_name(engine_voice), engine->get_voice_language(engine_voice));
	if (index >= 0) current_voice_index = index;
	return index;
}
void *tts_voice::speak_to_pcm(const string &text, tts_audio_data** datablock) {
	ensure_default();
	tts_engine *engine = active_engine();
	if (!datablock || !engine || engine->get_pcm_generation_state() == PCM_UNSUPPORTED) return nullptr;
	*datablock = engine->speak_to_pcm(tts_valid_utf8(text));
	if (!*datablock) return nullptr;
	return tts_trim(*datablock);
}
bool tts_voice::speak(const string &text, bool interrupt) {
	ensure_default();
	tts_engine *engine = active_engine();
	if (!engine) return false;
	if (engine->get_pcm_generation_state() == PCM_PREFERRED) {
		tts_audio_data* datablock = nullptr;
		void *trimmed_data = speak_to_pcm(text, &datablock);
		if (!trimmed_data || !datablock) return false;
		soundptr s;
		try { s.reset(new_global_sound()); } catch (...) {} // The sound system starts on first use and can fail to; the speech then fails, its audio freed, rather than throwing at the script.
		ma_format format = tts_pcm_format(datablock);
		if (!s || !s->load_pcm(trimmed_data, datablock->size_in_bytes, format, datablock->sample_rate, datablock->channels)) {
			datablock->free();
			return false;
		}
		datablock->free();
		if (interrupt) interrupt_other_speech(engine);
		return schedule(s, interrupt);
	}
	if (interrupt && !text.empty()) interrupt_other_speech(engine);
	bool spoken = engine->speak(tts_valid_utf8(text), interrupt, false);
	if (!text.empty()) remember_native_engine(); // Even when it failed, as part of a long text can have been queued.
	return spoken;
}
bool tts_voice::speak_to_file(const string &filename, const string &text) {
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
	tts_audio_data* datablock;
	void *trimmed_data = speak_to_pcm(text, &datablock);
	if (!trimmed_data || !datablock) return "";
	string output;
	ma_format format = tts_pcm_format(datablock);
	if (!sound::pcm_to_wav(trimmed_data, datablock->size_in_bytes, format, datablock->sample_rate, datablock->channels, output)) {
		datablock->free();
		return "";
	}
	datablock->free();
	return output;
}
bool tts_voice::speak_wait(const string &text, bool interrupt) {
	ensure_default();
	tts_engine *engine = active_engine();
	if (!engine) return false;
	if (engine->get_pcm_generation_state() == PCM_PREFERRED) {
		if (!speak(text, interrupt)) return false;
		while (queue_speaking()) wait(10);
		return true;
	}
	if (interrupt && !text.empty()) interrupt_other_speech(engine);
	bool spoken = engine->speak(tts_valid_utf8(text), interrupt, true);
	if (!text.empty()) remember_native_engine(); // Even when it failed, as part of a long text can have been queued.
	return spoken;
}
sound *tts_voice::speak_to_sound(const string &text) {
	tts_audio_data* datablock;
	void *trimmed_data = speak_to_pcm(text, &datablock);
	if (!trimmed_data || !datablock) return nullptr;
	sound *s = nullptr;
	try { s = new_global_sound(); } catch (...) {} // See speak().
	ma_format format = tts_pcm_format(datablock);
	if (!s || !s->load_pcm(trimmed_data, datablock->size_in_bytes, format, datablock->sample_rate, datablock->channels)) {
		datablock->free();
		if (s) s->release();
		return nullptr;
	}
	datablock->free();
	return s;
}
// A parameter the script never set is read from the engine each time, so it reports the platform's current value (on Android the user's own speech settings, on Apple platforms the values a new utterance starts with) rather than a copy taken at startup.
float tts_voice::get_rate() {
	if (rate_set) return fRound(nvgt_rate, 3);
	ensure_default();
	tts_engine *engine = active_engine();
	float lo, mid, hi;
	if (!engine || !engine->get_rate_range(lo, mid, hi)) return 0;
	return fRound(range_convert_midpoint(engine->get_rate(), lo, mid, hi, -10.0f, 0.0f, 10.0f), 3);
}
float tts_voice::get_pitch() {
	if (pitch_set) return fRound(nvgt_pitch, 3);
	ensure_default();
	tts_engine *engine = active_engine();
	float lo, mid, hi;
	if (!engine || !engine->get_pitch_range(lo, mid, hi)) return 0;
	return fRound(range_convert_midpoint(engine->get_pitch(), lo, mid, hi, -10.0f, 0.0f, 10.0f), 3);
}
float tts_voice::get_volume() {
	if (volume_set) return fRound(nvgt_volume, 3);
	ensure_default();
	tts_engine *engine = active_engine();
	float lo, mid, hi;
	if (!engine || !engine->get_volume_range(lo, mid, hi)) return 0;
	return fRound(range_convert_midpoint(engine->get_volume(), lo, mid, hi, -100.0f, -50.0f, 0.0f), 3);
}
int tts_voice::get_voice_count() { ensure_enumerated(); return voices.size(); }
string tts_voice::get_voice_name(int index) {
	ensure_enumerated();
	voice_info *voice = get_voice_info(index);
	return voice? voice->name : "";
}
int tts_voice::get_current_voice() {
	ensure_enumerated();
	return voice_set? current_voice_index : platform_voice_index();
}
void tts_voice::set_rate(float rate) {
	if (std::isnan(rate)) return; // See set_volume().
	ensure_default();
	nvgt_rate = clamp(rate, -10.0f, 10.0f);
	rate_set = true;
	active_engine(true); // push the new parameter onto the engine
}
void tts_voice::set_pitch(float pitch) {
	if (std::isnan(pitch)) return; // See set_volume().
	ensure_default();
	nvgt_pitch = clamp(pitch, -10.0f, 10.0f);
	pitch_set = true;
	active_engine(true);
}
// NaN is no value: clamp lets it through, and the builtin synthesizer crashes on it, so it leaves the setting as it was.
void tts_voice::set_volume(float volume) {
	if (std::isnan(volume)) return;
	ensure_default();
	nvgt_volume = clamp(volume, -100.0f, 0.0f);
	volume_set = true;
	active_engine(true);
}
CScriptArray *tts_voice::list_voices() {
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
	return true;
}
// The queue of speech played through the sound system belongs to this object rather than to an engine, so it is reported and stopped whichever voice is selected now, as is speech on engines this object spoke on before another voice was selected.
bool tts_voice::get_speaking() {
	if (queue_speaking()) return true;
	if (current_engine && current_engine->get_pcm_generation_state() != PCM_PREFERRED && current_engine->is_speaking()) return true;
	for (const auto &engine : native_engines) if (engine != current_engine && engine->is_speaking()) return true;
	return false;
}
bool tts_voice::refresh() {
	voice_state = VOICES_FULL;
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
		engine_default_voice[name] = tts_engine_default_voice(entry);
		int voice_count = engine->get_voice_count();
		for (int i = 0; i < voice_count; i++) {
			std::string lang = engine->get_voice_language(i);
			if (tts_language_matches(lang, current_language)) voices.emplace_back(voice_info{name, i, engine->get_voice_name(i), lang});
		}
	}
	current_voice_index = -1;
	// Only a voice the script chose is carried over. Without a choice the selection must keep following the platform default, which the block below picks.
	if (had_voice && voice_set) current_voice_index = find_listed_voice(voices, old_voice.engine_name, old_voice.engine_voice_index, old_voice.name, old_voice.language);
	if (current_voice_index < 0) voice_set = false; // The chosen voice is gone, so fall back to the platform default rather than forcing whichever voice lands on its old index.
	if (current_voice_index < 0 && !voices.empty()) {
		// Pick an initial voice: prefer the configured/default engine, then the platform's own order, then the first non-fallback engine, then anything, as ensure_default() does. Only an engine with a voice in the list counts: one that could not be bound, or whose voices the language filter left out, would match nothing below and leave the selection on the first voice, the builtin fallback.
		auto has_voice = [&](const string &name) { for (const auto &v : voices) if (v.engine_name == name) return true; return false; };
		string chosen_engine;
		if (!preferred_engine_name.empty() && has_voice(preferred_engine_name)) chosen_engine = preferred_engine_name;
		if (chosen_engine.empty()) for (const string &name : engine_ranking) if (name != "fallback" && has_voice(name)) { chosen_engine = name; break; }
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
	sound_queue removed; // Released after the lock, see clear().
	{
		unique_lock<mutex> lock(queue_mtx);
		removed = clear();
	}
	bool stopped = true;
	for (const auto &engine : native_engines) if (engine != current_engine && !engine->stop()) stopped = false;
	native_engines.clear();
	if (current_engine && current_engine->get_pcm_generation_state() != PCM_PREFERRED) stopped = current_engine->stop() && stopped;
	return stopped;
}
string tts_voice::get_engine_name() {
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
	ensure_enumerated();
	if (index < 0 || index >= static_cast<int>(voices.size())) return "";
	return voices[index].language;
}
bool tts_voice::set_language(const string& language) {
	// A language no voice serves, or whose voices the engines all refuse, leaves the object as it was, as a failed set_voice() does, rather than without voices and unable to speak.
	string previous_language = current_language, previous_engine_name = current_engine_name;
	vector<voice_info> previous_voices = voices;
	voice_enum_state previous_state = voice_state;
	int previous_voice_index = current_voice_index;
	bool previous_voice_set = voice_set;
	shared_ptr<tts_engine> previous_engine = current_engine;
	auto restore = [&]() {
		current_language = previous_language;
		voices = previous_voices;
		voice_state = previous_state;
		current_voice_index = previous_voice_index;
		voice_set = previous_voice_set;
		current_engine = previous_engine;
		current_engine_name = previous_engine_name;
		return false;
	};
	current_language = language;
	refresh();
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
	sound_queue removed; // Released after the lock, see clear().
	if (engine->get_pcm_generation_state() != PCM_PREFERRED) {
		unique_lock<mutex> lock(queue_mtx);
		if (!queue.empty()) removed = clear();
	}
	for (const auto &other : native_engines) if (other.get() != engine) other->stop();
	native_engines.erase(remove_if(native_engines.begin(), native_engines.end(), [engine](const shared_ptr<tts_engine> &other) { return other.get() != engine; }), native_engines.end());
}
// Remembers the engine that just spoke, leaving out engines whose speech has ended.
void tts_voice::remember_native_engine() {
	native_engines.erase(remove_if(native_engines.begin(), native_engines.end(), [this](const shared_ptr<tts_engine> &engine) { return engine != current_engine && !engine->is_speaking(); }), native_engines.end());
	if (current_engine && find(native_engines.begin(), native_engines.end(), current_engine) == native_engines.end()) native_engines.push_back(current_engine);
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
// Releases faded sounds from the front of the queue once they are silent. The fade volume is read from miniaudio, linear whatever units the sound reports its attributes in: with the percentage attributes of the default engine, the sound's own getter reports decibels, never above 0.
void tts_voice::cleanup_completed_fades() {
	while (!fade_queue.empty()) {
		sound *front = fade_queue.front().get();
		if (!front->is_load_completed() || (front->get_playing() && ma_sound_get_current_fade_volume(front->get_ma_sound()) > 0)) break;
		fade_queue.pop();
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
