/* tts.h - header for engine-based text to speech system
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

#pragma once
#include <speech.h>
#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <deque>
#include <queue>
#include <unordered_map>
#include <mutex>
#include <thread>
#include <atomic>
#include <cstdint>
#include <sstream>
#include <cstdlib>
#include <angelscript.h>
#include <scriptarray.h>
#include "sound.h"

class sound;
class tts_engine_impl;
class tts_engine;

enum tts_pcm_generation_state { PCM_UNSUPPORTED, PCM_SUPPORTED, PCM_PREFERRED };
struct tts_audio_data {
	void* data;
	unsigned int size_in_bytes;
	unsigned int sample_rate;
	unsigned int channels;
	unsigned int bitsize;
	void* context;
	tts_engine* engine;
	tts_audio_data(tts_engine* eng, void* dat, unsigned int size, unsigned int rate, unsigned int chans, unsigned int bits, void* ctx = nullptr);
	void free();
};

class tts_engine {
public:
	virtual ~tts_engine() = default;
	virtual bool is_available() = 0;
	virtual tts_pcm_generation_state get_pcm_generation_state() = 0;
	virtual bool speak(const std::string &text, bool interrupt = false, bool blocking = false) = 0;
	virtual tts_audio_data* speak_to_pcm(const std::string &text) = 0;
	virtual void free_pcm(tts_audio_data* data) = 0;
	virtual bool is_speaking() = 0;
	virtual bool stop() = 0;
	virtual float get_rate() = 0;
	virtual float get_pitch() = 0;
	virtual float get_volume() = 0;
	virtual void set_rate(float rate) = 0;
	virtual void set_pitch(float pitch) = 0;
	virtual void set_volume(float volume) = 0;
	virtual bool get_rate_range(float& minimum, float& midpoint, float& maximum) = 0;
	virtual bool get_pitch_range(float& minimum, float& midpoint, float& maximum) = 0;
	virtual bool get_volume_range(float& minimum, float& midpoint, float& maximum) = 0;
	virtual int get_voice_count() = 0;
	virtual std::string get_voice_name(int index) = 0;
	virtual std::string get_voice_language(int index) = 0;
	virtual bool set_voice(int voice) = 0;
	virtual int get_current_voice() = 0;
	virtual std::string get_engine_name() = 0;
	// Return a parameter or the voice to whatever the platform itself would use (usually the user's system TTS settings), undoing an earlier set_* call. This is needed when a tts_voice stops using a voice it chose, and when it lets go of an engine, which then goes to the next tts_voice that wants one. Returning false means the engine cannot do this itself; the caller then restores the value the engine reported when it was first bound.
	virtual bool reset_rate() { return false; }
	virtual bool reset_pitch() { return false; }
	virtual bool reset_volume() { return false; }
	virtual bool reset_voice() { return false; }
};

class tts_engine_impl : public tts_engine {
protected:
	std::string engine_name;
public:
	tts_engine_impl(const std::string &name) : engine_name(name) {}
	virtual ~tts_engine_impl() = default;
	virtual bool is_available() override { return true; }
	virtual tts_pcm_generation_state get_pcm_generation_state() override { return PCM_UNSUPPORTED; }
	virtual bool speak(const std::string &text, bool interrupt = false, bool blocking = false) override { return false; }
	virtual tts_audio_data* speak_to_pcm(const std::string &text) override { return nullptr; }
	virtual void free_pcm(tts_audio_data* data) override { if (!data) return; if (data->data) free(data->data); delete data; }
	virtual bool is_speaking() override { return false; }
	virtual bool stop() override { return true; }
	virtual float get_rate() override { return 0; }
	virtual float get_pitch() override { return 0; }
	virtual float get_volume() override { return 0; }
	virtual void set_rate(float rate) override { }
	virtual void set_pitch(float pitch) override { }
	virtual void set_volume(float volume) override { }
	virtual bool get_rate_range(float& minimum, float& midpoint, float& maximum) override { return false; }
	virtual bool get_pitch_range(float& minimum, float& midpoint, float& maximum) override { return false; }
	virtual bool get_volume_range(float& minimum, float& midpoint, float& maximum) override { return false; }
	virtual int get_voice_count() override { return 1; }
	virtual std::string get_voice_name(int index) override { return index == 0? get_engine_name() : ""; }
	virtual std::string get_voice_language(int index) override { return "en-us"; }
	virtual bool set_voice(int voice) override { return voice == 0; }
	virtual int get_current_voice() override { return 0; }
	virtual std::string get_engine_name() override { return engine_name; }
};

// Engine factory system
typedef std::function<std::shared_ptr<tts_engine>()> tts_engine_factory;
bool tts_engine_register(const std::string &name, tts_engine_factory factory);
std::vector<std::string> tts_get_engine_names();
std::shared_ptr<tts_engine> tts_create_engine(const std::string &name);
void tts_set_preferred_engine(const std::string &name);
std::string tts_valid_utf8(const std::string &text); // The text with every malformed UTF-8 sequence replaced by U+FFFD and every NUL by a space.
void tts_set_engine_ranking(const std::vector<std::string> &names); // The order a platform falls back through its engines when the preferred one can't be used.

struct voice_info {
	std::string engine_name; // Which registered engine this voice belongs to; the engine object itself is created lazily (see tts_voice::active_engine).
	int engine_voice_index;
	std::string name;
	std::string language;
};

// One engine bound for one tts_voice. Each object has engines of its own, so that its speech, interruptions and stops stay its own: Android keeps a queue per TextToSpeech, Apple platforms per synthesizer, Speech Dispatcher per connection. The entry records which of the values the object set replace the engine's defaults, so they can be put back.
struct engine_entry {
	std::shared_ptr<tts_engine> engine; // Null if this engine could not be bound.
	float init_rate = 0, init_pitch = 0, init_volume = 0; // In engine units, as reported when bound. Used to undo a change on engines that cannot reset themselves.
	int init_voice = -1;
	std::string init_voice_name; // Of init_voice, which is found again by name, since indices move when voices are installed or removed while the program runs.
	bool rate_changed = false, pitch_changed = false, volume_changed = false, voice_changed = false; // Whether a value the object set is on the engine in place of its default.
	bool synced = false; // Whether the engine carries the object's current settings.
};

class tts_voice {
	int RefCount;
	std::vector<std::string> engine_names; // Candidate engines this voice may draw from. Engine objects are NOT instantiated here; binding is deferred until a voice is actually selected/used.
	std::unordered_map<std::string, engine_entry> engines; // This object's engines by name, bound as they are first needed; see engine_entry.
	std::shared_ptr<tts_engine> current_engine; // The single live (bound) engine backing the currently selected voice, or null if nothing has been used yet.
	std::string current_engine_name;
	enum voice_enum_state { VOICES_NONE, VOICES_DEFAULT_ONLY, VOICES_FULL }; // How much of the voice list has been built so far.
	voice_enum_state voice_state; // Binding/enumeration is deferred: nothing until first use, then only the default engine for a plain speak(), and the full cross-engine list only when the script actually lists or selects voices.
	std::vector<voice_info> voices;
	int current_voice_index;
	std::string current_language;
	float nvgt_rate, nvgt_pitch, nvgt_volume; // Speech parameters the script set on this tts_voice, in NVGT units. Only meaningful while the matching *_set flag is true.
	bool rate_set, pitch_set, volume_set, voice_set; // Whether the script explicitly set each of these. Anything not set is never pushed onto the engine, so the platform keeps using the user's own TTS settings, and the getters report those settings.
	uint64_t id; // Identifies this object to the end-of-utterance jobs, see g_live_tts_voices. A counter rather than the pointer, so an object allocated at a freed address is never mistaken for the old one.
	typedef std::shared_ptr<sound> soundptr;
	typedef std::queue<soundptr> sound_queue;
	sound_queue queue;
	std::mutex queue_mtx;
	sound_queue fade_queue;
	sound_queue finished; // Utterances that played to their end, released on a script thread: the end-of-utterance job's thread must not close a sound, which takes the node graph lock a script thread can hold while it waits for that very thread.
	std::atomic_flag speaking;
	std::vector<std::shared_ptr<tts_engine>> native_engines; // Engines this object spoke on without the sound system, so that their speech can still be reported and stopped once another voice is selected.
	// Speech that waits for the object's speech on another path to end: a sound for the sound system's queue, or text for an engine that plays its own speech. See speak().
	struct held_speech {
		soundptr sound;
		std::shared_ptr<tts_engine> engine;
		std::string text;
	};
	std::deque<held_speech> held;
	std::recursive_mutex chain_mtx; // Taken by every method that uses the engines, held or native_engines, and by the thread that starts held speech, so that thread's engine calls never run beside the script's.
	std::thread held_starter; // Starts this object's held speech as its turn comes, while there is any; see start_held_speech().
	bool held_starter_running = false; // Under chain_mtx: whether held_starter still goes on. Once it has stopped, it takes the lock no more.
	std::atomic<bool> held_starter_stop{false}; // Set as the object is destroyed.
	voice_info *get_voice_info(int voice_index);
	void ensure_default(); // Bind only the default/preferred engine and select its default voice (enough to speak); does not touch other engines.
	void ensure_enumerated(); // Build the full flattened voice list across all engines (needed to list or select voices).
	engine_entry &get_engine_entry(const std::string &name); // This object's entry for an engine, binding the engine the first time.
	bool sync_engine(engine_entry &entry, bool force); // Make the engine carry exactly this object's settings: the values the script set, and the platform defaults for everything else. Does nothing when the engine already carries them, unless forced. False when the engine refused the voice this object chose.
	tts_engine *active_engine(bool force_sync = false, bool *voice_applied = nullptr); // Resolves this object's engine for the current voice, syncs our settings onto it, and returns it (or null on failure); voice_applied receives whether the engine took the chosen voice.
	int platform_voice_index(); // When the script has not chosen a voice: the index in voices of the voice the engine is actually speaking with, or -1 if the engine cannot say or that voice is not in the list.
	void *speak_to_pcm(const std::string &text, tts_audio_data** datablock); // Returns pointer to trimmed sample.
	bool schedule(soundptr &s, bool interrupt);
	sound_queue clear();
	void remember_native_engine(const std::shared_ptr<tts_engine> &spoke);
	bool other_path_speaking(tts_engine *engine);
	bool hold(held_speech &&speech);
	bool release_held();
	void start_held_speech();
	void advance_queue();
	bool queue_speaking();
	void interrupt_other_speech(tts_engine *engine);
	bool fade(soundptr &item);
	void cleanup_completed_fades();
	static void at_end(void *pUserData, ma_sound *pSound);
	static ma_result job_proc(ma_job *pJob);
public:
	tts_voice(const std::string &engine_list = "");
	~tts_voice();
	void AddRef();
	void Release();
	bool speak(const std::string &text, bool interrupt = false);
	bool speak_to_file(const std::string &filename, const std::string &text);
	std::string speak_to_memory(const std::string &text);
	bool speak_wait(const std::string &text, bool interrupt = false);
	sound *speak_to_sound(const std::string &text);
	bool speak_interrupt(const std::string &text) { return speak(text, true); }
	bool speak_interrupt_wait(const std::string &text) { return speak_wait(text, true); }
	float get_rate();
	float get_pitch();
	float get_volume();
	int get_voice_count();
	std::string get_voice_name(int index);
	std::string get_voice_language(int index);
	void set_rate(float rate);
	void set_pitch(float pitch);
	void set_volume(float volume);
	CScriptArray *list_voices();
	bool set_voice(int voice);
	int get_current_voice();
	bool get_speaking();
	bool refresh();
	bool stop();
	std::string get_engine_name();
	int get_engine_count();
	std::string get_engine_name(int index);
	bool set_language(const std::string& language);
	std::string get_language();
};

// Global functions
CScriptArray *tts_get_engines();
bool screen_reader_load();
void screen_reader_unload();
std::string screen_reader_detect();
bool screen_reader_has_speech();
bool screen_reader_has_braille();
bool screen_reader_is_speaking();
bool screen_reader_output(const std::string& text, bool interrupt);
bool screen_reader_speak(const std::string& text, bool interrupt);
bool screen_reader_braille(const std::string& text);
bool screen_reader_silence();

void tts_release_idle_engines(); // Destroys the engines kept for later tts_voice objects, while the program shuts down and the services they use are still there.
void RegisterTTSVoice(asIScriptEngine *engine);
