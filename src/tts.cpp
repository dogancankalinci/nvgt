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

#include <limits>
#include <algorithm>
#include <unordered_map>
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

// Trim prenormalized TTS based on minimum thresholds in dB. Size is in frames.
template <class t> static t *tts_trim_internal(t *data, unsigned int* size_in_frames, int channels, float begin_db, float end_db) {
	t min_begin_sample = ceil(ma_volume_db_to_linear(begin_db) * (double)numeric_limits<t>::max());
	t min_end_sample = ceil(ma_volume_db_to_linear(end_db) * (double)numeric_limits<t>::max());
	for (unsigned long i = 0; i < *size_in_frames; i++) {
		double mean = 0;
		for (int c = 0; c < channels; c++)
			mean += abs(data[(i * channels) + c]);
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
			mean += abs(data[(i * channels) + c]);
		mean /= channels;
		if (mean > min_end_sample) {
			if (i < *size_in_frames - 1) i++;
			*size_in_frames -= (*size_in_frames - i);
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
			trimmed_data = tts_trim_internal<char>((char*)data->data, &size_in_frames, data->channels, begin_db, end_db);
			data->size_in_bytes = size_in_frames * data->channels;
			return trimmed_data;
		default:
			return data->data;
	}
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
static std::recursive_mutex g_tts_registry_mutex; // guards engine_registry, engine_names and g_shared_engines: tts_voice objects are created and used from any script thread and lazily populate all three
static vector<string> engine_names;
static unordered_map<string, tts_engine_factory> engine_registry;
static string preferred_engine_name;
bool tts_engine_register(const string &name, tts_engine_factory factory) {
	std::lock_guard<std::recursive_mutex> lock(g_tts_registry_mutex); // recursive: register_builtin_engines() calls this while the constructor already holds the lock
	if (engine_registry.find(name) != engine_registry.end()) return false;
	engine_registry[name] = factory;
	engine_names.push_back(name);
	return true;
}

vector<string> tts_get_engine_names() { std::lock_guard<std::recursive_mutex> lock(g_tts_registry_mutex); return engine_names; }
void tts_set_preferred_engine(const string &name) { preferred_engine_name = name; }

shared_ptr<tts_engine> tts_create_engine(const string &name) {
	auto it = engine_registry.find(name);
	if (it == engine_registry.end()) return nullptr;
	try { return it->second(); }
	catch (...) { return nullptr; }
}

// Program-wide cache of engine instances. Each engine is instantiated (and therefore bound to its OS service) AT MOST ONCE for the entire lifetime of the program; every tts_voice shares these instances. A failed bind is remembered as a null entry so it is never retried. Because the instance is shared, the entry also records whose settings the engine currently carries and which of them replace the engine's own defaults, so that a tts_voice which never set anything can put the engine back before it speaks.
struct shared_engine_entry {
	shared_ptr<tts_engine> engine; // null if this engine could not be bound (cached so we never retry).
	float init_rate = 0, init_pitch = 0, init_volume = 0; // In engine units, as reported at first bind. Used to undo a change on engines that cannot reset themselves.
	int init_voice = -1;
	bool rate_changed = false, pitch_changed = false, volume_changed = false, voice_changed = false; // Whether a value some tts_voice set is currently on the engine in place of its default.
	uint64_t owner = 0; // id of the tts_voice whose settings the engine currently carries, 0 if none has synced yet.
};
static unordered_map<string, shared_engine_entry> g_shared_engines;
static shared_engine_entry& tts_get_shared_engine(const string &name) {
	std::lock_guard<std::recursive_mutex> lock(g_tts_registry_mutex);
	auto it = g_shared_engines.find(name);
	if (it != g_shared_engines.end()) return it->second;
	shared_engine_entry entry;
	shared_ptr<tts_engine> engine = tts_create_engine(name);
	if (engine && !engine->is_available()) engine = nullptr;
	entry.engine = engine;
	if (engine) {
		entry.init_rate = engine->get_rate();
		entry.init_pitch = engine->get_pitch();
		entry.init_volume = engine->get_volume();
		entry.init_voice = engine->get_current_voice();
	}
	return g_shared_engines.emplace(name, std::move(entry)).first->second;
}
static std::atomic<uint64_t> g_next_tts_voice_id{0};

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
		for (const string& e : tokens) engine_names.push_back(Poco::trim(e));
	}
	// Engines are bound lazily. We deliberately do NOT instantiate any engine here, nor enumerate voices yet: a tts_voice that is created but never used (e.g. a global object on a device where a screen reader handles speech instead) must never bind to any TTS engine. This is what avoids the "bind to every installed engine at startup" problem, including crashing on restricted engines like Sao Mai Myanmar TTS.
}
void tts_voice::AddRef() { asAtomicInc(RefCount); }
void tts_voice::Release() { if (asAtomicDec(RefCount) < 1) delete this; }
voice_info *tts_voice::get_voice_info(int voice_index) {
	if (voice_index < 0 || voice_index >= static_cast<int>(voices.size())) return nullptr;
	return &voices[voice_index];
}
void tts_voice::ensure_default() {
	if (voice_state != VOICES_NONE) return;
	// Fast path for the common case (speak with the default voice): bind ONLY the preferred/default engine and select its default voice, so we never instantiate or bind every installed engine just to start speaking. Full cross-engine enumeration is deferred until the script actually lists or selects voices.
	string pref = preferred_engine_name;
	if (pref.empty()) for (const string &name : engine_names) if (name != "fallback") { pref = name; break; }
	if (pref.empty() && !engine_names.empty()) pref = engine_names.front();
	shared_engine_entry *entry = pref.empty()? nullptr : &tts_get_shared_engine(pref);
	if (!entry || !entry->engine || !entry->engine->is_available()) { refresh(); return; } // Preferred engine unavailable: fall back to a full search for anything usable.
	tts_engine *engine = entry->engine.get();
	voices.clear();
	int default_voice = engine->get_current_voice();
	int voice_count = engine->get_voice_count();
	for (int i = 0; i < voice_count; i++) {
		string lang = engine->get_voice_language(i);
		if (current_language.empty() || lang == current_language) voices.emplace_back(voice_info{pref, i, engine->get_voice_name(i), lang});
	}
	if (voices.empty()) { refresh(); return; } // e.g. a language filter excluded everything from this engine; search the rest.
	current_voice_index = 0;
	for (size_t i = 0; i < voices.size(); i++) if (voices[i].engine_voice_index == default_voice) { current_voice_index = i; break; }
	current_engine = entry->engine;
	current_engine_name = pref;
	voice_state = VOICES_DEFAULT_ONLY;
}
void tts_voice::ensure_enumerated() { if (voice_state != VOICES_FULL) refresh(); }
void tts_voice::sync_engine(shared_engine_entry &entry, bool force) {
	std::lock_guard<std::recursive_mutex> lock(g_tts_registry_mutex); // The entry is shared by every tts_voice, which may run on different script threads.
	tts_engine *engine = entry.engine.get();
	if (!engine || (!force && entry.owner == id)) return;
	// Push only what the script set on this object. Anything else is left alone, or, if another tts_voice changed it on this shared engine, returned to the platform default, so a script that never sets a parameter always hears the user's own TTS settings.
	voice_info *voice = get_voice_info(current_voice_index);
	if (voice_set && voice) {
		engine->set_voice(voice->engine_voice_index);
		entry.voice_changed = true;
	} else if (entry.voice_changed) {
		if (!engine->reset_voice() && entry.init_voice >= 0) engine->set_voice(entry.init_voice);
		entry.voice_changed = false;
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
	entry.owner = id;
}
tts_engine *tts_voice::active_engine(bool force_sync) {
	voice_info *voice = get_voice_info(current_voice_index);
	if (!voice) return nullptr;
	// Resolve the program-wide shared engine (binds it at most once, ever). If it can't be bound (e.g. a restricted engine), report failure so the caller can fall back.
	shared_engine_entry &entry = tts_get_shared_engine(voice->engine_name);
	if (!entry.engine) return nullptr;
	current_engine = entry.engine;
	current_engine_name = voice->engine_name;
	// Because engines are shared, another tts_voice may have left this one carrying its own voice or parameters; this puts ours back only when that happened, and costs nothing otherwise.
	sync_engine(entry, force_sync);
	return entry.engine.get();
}
int tts_voice::platform_voice_index() {
	tts_engine *engine = active_engine();
	voice_info *voice = get_voice_info(current_voice_index);
	if (!engine || !voice) return -1;
	int engine_voice = engine->get_current_voice();
	if (engine_voice < 0) return -1;
	string engine_name = voice->engine_name;
	for (size_t i = 0; i < voices.size(); i++) {
		if (voices[i].engine_name != engine_name || voices[i].engine_voice_index != engine_voice) continue;
		current_voice_index = i;
		return i;
	}
	return -1;
}
void *tts_voice::speak_to_pcm(const string &text, tts_audio_data** datablock) {
	ensure_default();
	tts_engine *engine = active_engine();
	if (!datablock || !engine || engine->get_pcm_generation_state() == PCM_UNSUPPORTED) return nullptr;
	*datablock = engine->speak_to_pcm(text);
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
		soundptr s(new_global_sound());
		ma_format format = (datablock->bitsize == 16) ? ma_format_s16 : ma_format_u8;
		if (!s->load_pcm(trimmed_data, datablock->size_in_bytes, format, datablock->sample_rate, datablock->channels)) {
			datablock->free();
			return false;
		}
		datablock->free();
		return schedule(s, interrupt);
	} else return engine->speak(text, interrupt, false);
}
bool tts_voice::speak_to_file(const string &filename, const string &text) {
	tts_audio_data* datablock;
	void *trimmed_data = speak_to_pcm(text, &datablock);
	if (!trimmed_data || !datablock) return false;
	try {
		string output;
		output.resize(datablock->size_in_bytes + 44);
		ma_format format = (datablock->bitsize == 16)? ma_format_s16 : ma_format_u8;
		if (!sound::pcm_to_wav(trimmed_data, datablock->size_in_bytes, format, datablock->sample_rate, datablock->channels, &output[0])) {
			datablock->free();
			return false;
		}
		Poco::FileOutputStream file(filename, ios::binary);
		file.write(output.data(), output.size());
		file.close();
		datablock->free();
		return true;
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
	output.resize(datablock->size_in_bytes + 44);
	ma_format format = (datablock->bitsize == 16)? ma_format_s16 : ma_format_u8;
	if (!sound::pcm_to_wav(trimmed_data, datablock->size_in_bytes, format, datablock->sample_rate, datablock->channels, &output[0])) {
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
		while (get_speaking()) wait(10);
		return true;
	} else return engine->speak(text, interrupt, true);
}
sound *tts_voice::speak_to_sound(const string &text) {
	tts_audio_data* datablock;
	void *trimmed_data = speak_to_pcm(text, &datablock);
	if (!trimmed_data || !datablock) return nullptr;
	sound *s = new_global_sound();
	ma_format format = (datablock->bitsize == 16)? ma_format_s16 : ma_format_u8;
	if (!s->load_pcm(trimmed_data, datablock->size_in_bytes, format, datablock->sample_rate, datablock->channels)) {
		datablock->free();
		s->release();
		return nullptr;
	}
	datablock->free();
	return s;
}
// A parameter the script never set is read from the engine each time, so it reports the platform's current value (on Android and Apple platforms, the user's own speech settings) rather than a copy taken at startup.
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
	ensure_default();
	nvgt_rate = clamp(rate, -10.0f, 10.0f);
	rate_set = true;
	active_engine(true); // push the new parameter onto the (shared) engine
}
void tts_voice::set_pitch(float pitch) {
	ensure_default();
	nvgt_pitch = clamp(pitch, -10.0f, 10.0f);
	pitch_set = true;
	active_engine(true);
}
void tts_voice::set_volume(float volume) {
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
	current_voice_index = voice;
	voice_set = true;
	// Binding happens here, lazily, via active_engine(), which also applies whatever rate/pitch/volume the script set to the newly selected engine. If the engine backing this voice can't be bound (e.g. a restricted Android engine like Sao Mai Myanmar TTS), stay on whatever was selected before and report failure rather than leaving the object pointing at an unusable voice.
	if (!active_engine(true)) {
		current_voice_index = previous_voice_index;
		voice_set = previous_voice_set;
		return false;
	}
	return true;
}
bool tts_voice::get_speaking() {
	if (!current_engine) return false; // Nothing has been bound/spoken yet.
	if (current_engine->get_pcm_generation_state() == PCM_PREFERRED) return speaking.test();
	else return current_engine->is_speaking();
}
bool tts_voice::refresh() {
	voice_state = VOICES_FULL;
	string old_voice_name, old_engine_name;
	bool had_voice = false;
	if (current_voice_index >= 0 && current_voice_index < static_cast<int>(voices.size())) {
		old_voice_name = voices[current_voice_index].name;
		old_engine_name = voices[current_voice_index].engine_name;
		had_voice = true;
	}
	voices.clear();
	// Track each engine's own current/default voice index so we can preserve the platform default voice when picking an initial selection.
	unordered_map<string, int> engine_default_voice;
	for (const string &name : engine_names) {
		// Resolve through the program-wide cache: each engine is bound at most once, ever, and reused here. An engine that refuses to bind is cached as unavailable and simply contributes no voices instead of taking down the whole list.
		tts_engine *engine = tts_get_shared_engine(name).engine.get();
		if (!engine || !engine->is_available()) continue;
		engine_default_voice[name] = engine->get_current_voice();
		int voice_count = engine->get_voice_count();
		for (int i = 0; i < voice_count; i++) {
			std::string lang = engine->get_voice_language(i);
			if (current_language.empty() || lang == current_language) voices.emplace_back(voice_info{name, i, engine->get_voice_name(i), lang});
		}
	}
	current_voice_index = -1;
	// Only a voice the script chose is carried over by name. Without a choice the selection must keep following the platform default, which the block below picks.
	if (had_voice && voice_set) {
		for (size_t i = 0; i < voices.size(); i++) {
			if (voices[i].engine_name != old_engine_name || voices[i].name != old_voice_name) continue;
			current_voice_index = i;
			break;
		}
	}
	if (current_voice_index < 0) voice_set = false; // The chosen voice is gone, so fall back to the platform default rather than forcing whichever voice lands on its old index.
	if (current_voice_index < 0 && !voices.empty()) {
		// Pick an initial voice: prefer the configured/default engine, then the first non-fallback engine, then anything.
		string chosen_engine;
		if (!preferred_engine_name.empty()) {
			for (const string &name : engine_names) if (name == preferred_engine_name) { chosen_engine = name; break; }
		}
		if (chosen_engine.empty()) for (const auto &v : voices) if (v.engine_name != "fallback") { chosen_engine = v.engine_name; break; }
		if (chosen_engine.empty()) chosen_engine = voices.front().engine_name;
		int target = engine_default_voice.count(chosen_engine)? engine_default_voice[chosen_engine] : -1;
		current_voice_index = 0;
		for (size_t i = 0; i < voices.size(); i++) {
			if (voices[i].engine_name != chosen_engine) continue;
			if (target < 0 || voices[i].engine_voice_index == target) { current_voice_index = i; break; }
		}
	}
	// If our cached active-engine pointer no longer matches the selected voice, drop it so the next use re-resolves through the shared cache. (This does not unbind anything; the program-wide cache keeps the engine alive.)
	voice_info *sel = get_voice_info(current_voice_index);
	if (current_engine && (!sel || current_engine_name != sel->engine_name)) { current_engine.reset(); current_engine_name.clear(); }
	// The list was rebuilt, so our selection may now sit on a different engine index; make the next use sync the engine again instead of assuming it already carries our settings.
	if (sel) {
		std::lock_guard<std::recursive_mutex> lock(g_tts_registry_mutex);
		shared_engine_entry &entry = tts_get_shared_engine(sel->engine_name);
		if (entry.owner == id) entry.owner = 0;
	}
	return !voices.empty();
}
bool tts_voice::stop() {
	if (!current_engine) return true; // Nothing bound yet, so nothing to stop.
	if (current_engine->get_pcm_generation_state() == PCM_PREFERRED) {
		unique_lock<mutex> lock(queue_mtx);
		clear();
		return true;
	} else return current_engine->stop();
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
	current_language = language;
	refresh();
	// Asking for a language is asking for one of its voices, so the voice refresh() picked from the filtered list is pushed onto the engine like a set_voice() call. An empty language only lifts the filter and changes nothing about the selection.
	if (!language.empty() && get_voice_info(current_voice_index)) {
		voice_set = true;
		active_engine(true);
	}
	return !voices.empty();
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
		ma_sound_set_end_callback(s->get_ma_sound(), at_end, this);
		unique_lock<mutex> lock(queue_mtx);
		if (interrupt) clear();
		queue.push(s);
		speaking.test_and_set();
		if (queue.size() == 1) s->play();
		return true;
	} catch (exception &) { return false; }
}
void tts_voice::clear() {
	if (!queue.empty() && queue.front()->get_playing()) fade(queue.front());
	while (!queue.empty()) queue.pop();
	speaking.clear();
}
bool tts_voice::fade(soundptr &item) {
	ma_sound_set_fade_in_milliseconds(item->get_ma_sound(), -1, 0, 20);
	try {
		fade_queue.push(item);
		return true;
	} catch (const exception &) { return false; }
}
void tts_voice::cleanup_completed_fades() {
	if (fade_queue.empty()) return;
	if ((fade_queue.front()->get_playing() && fade_queue.front()->get_current_fade_volume() > 0)) return;
	while (!fade_queue.empty() && fade_queue.front()->is_load_completed()) fade_queue.pop();
}
void tts_voice::at_end(void *pUserData, ma_sound *pSound) {
	tts_voice *voice = static_cast<tts_voice *>(pUserData);
	ma_job job = ma_job_init(MA_JOB_TYPE_CUSTOM);
	job.data.custom.data0 = (ma_uintptr)voice;
	job.data.custom.data1 = (ma_uintptr)pSound;
	job.data.custom.proc = job_proc;
	ma_resource_manager_post_job(g_audio_engine->get_ma_engine()->pResourceManager, &job);
}
ma_result tts_voice::job_proc(ma_job *pJob) {
	tts_voice *voice = (tts_voice *)pJob->data.custom.data0;
	ma_sound *expected_front = (ma_sound *)pJob->data.custom.data1;
	unique_lock<mutex> lock(voice->queue_mtx);
	if (voice->queue.empty() || voice->queue.front()->get_ma_sound() != expected_front) return MA_CANCELLED;
	voice->queue.pop();
	if (voice->queue.size() == 0) {
		voice->speaking.clear();
		return MA_SUCCESS;
	}
	voice->queue.front()->play();
	return MA_SUCCESS;
}

CScriptArray *tts_get_engines() {
	asIScriptContext *ctx = asGetActiveContext();
	asIScriptEngine *engine = ctx->GetEngine();
	asITypeInfo *arrayType = engine->GetTypeInfoByDecl("array<string>");
	CScriptArray *array = CScriptArray::Create(arrayType);
	array->Reserve(engine_names.size());
	for (const string &name : engine_names) array->InsertLast(&const_cast<string&>(name));
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
