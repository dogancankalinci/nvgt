/* sound.cpp - sound system implementation code
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

#define NOMINMAX
#include <memory>
#include <string>
#include <thread>
#include <chrono>
#ifdef _MSC_VER
#include <intrin.h> // _InterlockedCompareExchange
#endif
#include <algorithm>
#include <condition_variable>
#include <mutex>
#include <shared_mutex>
#include <cmath>
#include <cstring>
#include <initializer_list>
#include <vector>
#include <Poco/FileStream.h>
#include <Poco/Format.h>
#include <Poco/MemoryStream.h>
#include <Poco/UnicodeConverter.h>
#include <reactphysics3d/collision/shapes/AABB.h>
#include <angelscript.h>
#include <scriptarray.h>
#include <scripthandle.h>
#include "filesystem.h" // FileExists
#include "misc_functions.h" // script_memory_buffer
#include "nvgt.h" // g_ScriptEngine
#include "nvgt_angelscript.h" // get_array_type
#include "nvgt_plugin.h"      // pack_interface
#include "sound.h"
#include <opus/opus.h>
#include <opus/opusenc.h>
#include "sound_nodes.h"
#include "pack.h"
#include "datastreams.h"
#include <miniaudio_wdl_resampler.h>
#include <atomic>
#include <map>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <cstdint>
#include <miniaudio_libvorbis.h>
#include <miniaudio_libopus.h>
#include <iostream>
#ifdef __APPLE__
#include <TargetConditionals.h>
#endif
#if TARGET_OS_IPHONE
#import <AVFoundation/AVFoundation.h>
#import <Foundation/Foundation.h>
#endif
#ifdef __linux__
#include <SDL3/SDL_loadso.h>
static void quiet_alsa_handler(const char *file, int line, const char *function, int err, const char *fmt, ...) {}
#endif
using namespace std;

class sound_impl;
void wait(int ms);
// Globals, currently NVGT does not support instanciating multiple miniaudio contexts and NVGT provides a global sound engine.
static ma_context g_sound_context;
audio_engine *g_audio_engine = nullptr;
// The lowest sample rate taken for an engine, a decoder's or an encoder's output or a script's PCM. MiniAudio's resource manager decodes in pages of 1000 * (rate / 1000) frames, none below it, and rates of a few hertz made a source decode thousands of frames for each it gave, or a second of PCM take gigabytes, while rates between it and 8000, the lowest MiniAudio names, are found in old recordings and in sounds scripts make, and worked.
static constexpr ma_uint32 min_sample_rate = 1000;
mixer* g_audio_mixer = nullptr; // sound_default_mixer, under g_audio_mixer_mutex.
static std::mutex g_audio_mixer_mutex;
// sound_default_mixer with a reference of the caller's own, as sound_default_engine is handed out: read without one while another thread's assignment let go of the old mixer's last reference, a new sound was put on a mixer being destroyed.
static mixer* acquire_default_mixer() {
	std::lock_guard<std::mutex> lock(g_audio_mixer_mutex);
	if (g_audio_mixer) g_audio_mixer->duplicate();
	return g_audio_mixer;
}
mixer* get_sound_default_mixer() { return acquire_default_mixer(); } // The reference goes to the script.
void set_sound_default_mixer(mixer* mix) { // Takes the script's reference.
	mixer* old;
	{
		std::lock_guard<std::mutex> lock(g_audio_mixer_mutex);
		old = g_audio_mixer;
		g_audio_mixer = mix;
	}
	if (old) old->release(); // After the lock: it can be the last reference.
}
static std::atomic_flag g_soundsystem_initialized; // The context, the sound service and the device lists are set up, see init_sound_context().
static std::atomic_flag g_soundsystem_ready; // The engine exists. Set last so that no other thread can be told "initialized" while g_audio_engine is still null.
static std::recursive_mutex g_soundsystem_init_mutex; // Recursive because setting up re-enters init_sound() and init_sound_context() on this same thread.
static std::atomic_flag g_soundsystem_shut_down; // uninit_sound() ran: script threads still running are refused rather than given the default engine it let go.
// Sources being freed off the script's thread, by resource manager (see sound_impl::reap()), so that an engine, before its resource manager goes, and uninit_sound() can wait for them.
static std::mutex g_reaps_mutex;
static std::condition_variable g_reaps_done;
static std::unordered_map<ma_resource_manager*, int> g_reaps; // Under g_reaps_mutex.
// At most this many of a resource manager's at once; close() waits for another itself, so that sounds loaded and let go of faster than they decode don't pile up decodes nobody plays, each holding its whole decoded file and the job threads.
static constexpr int max_reaps = 2;
// Takes a place among those of a resource manager, if there is one, or past them for a caller that mustn't wait, as an audio thread: none once uninit_sound() shut the sound system down, the process's exit following.
static bool reserve_reap(ma_resource_manager* manager, bool past_max = false) {
	std::lock_guard<std::mutex> lock(g_reaps_mutex);
	if (g_soundsystem_shut_down.test()) return false;
	auto it = g_reaps.find(manager);
	if (!past_max && it != g_reaps.end() && it->second >= max_reaps) return false;
	g_reaps[manager]++;
	return true;
}
// Gives it back, notified under the lock, so that nothing of a thread freeing a source runs once a waiter goes on, as to the process's exit.
static void end_reap(ma_resource_manager* manager) {
	std::lock_guard<std::mutex> lock(g_reaps_mutex);
	if (--g_reaps[manager] == 0) g_reaps.erase(manager);
	g_reaps_done.notify_all();
}
// Waits for those of a resource manager, or for all of them.
static void wait_for_reaps(ma_resource_manager* manager = nullptr) {
	std::unique_lock<std::mutex> lock(g_reaps_mutex);
	g_reaps_done.wait(lock, [manager]() { return manager? !g_reaps.count(manager) : g_reaps.empty(); });
}
// Engines and microphones being destroyed on threads of their own, let go of on an audio thread (see audio_engine_impl::release()), which sound_stop_script_callbacks() waits for, so that none releases a script function or closes a device once the script's module, or SDL, went.
static std::mutex g_detached_deletes_mutex;
static std::condition_variable g_detached_deletes_done;
static int g_detached_deletes = 0; // Under g_detached_deletes_mutex.
template<class T> static void delete_detached(T* object) {
	{
		std::lock_guard<std::mutex> lock(g_detached_deletes_mutex);
		g_detached_deletes++;
	}
	try {
		std::thread([object]() {
			delete object;
			std::lock_guard<std::mutex> lock(g_detached_deletes_mutex); // Notified under the lock, so that nothing of this thread runs once the waiter goes on.
			if (--g_detached_deletes == 0) g_detached_deletes_done.notify_all();
		}).detach();
	} catch (...) { // Left to the process's exit, as it can't be destroyed here.
		std::lock_guard<std::mutex> lock(g_detached_deletes_mutex);
		if (--g_detached_deletes == 0) g_detached_deletes_done.notify_all();
	}
}
static bool g_soundsystem_starting = false; // Under g_soundsystem_init_mutex: this thread is setting up, so a call re-entering from there is answered at once.
static std::atomic<bool> g_script_callbacks_stopped{false}; // See sound_stop_script_callbacks().
static std::atomic<int> g_script_callbacks_running{0}; // Processing callbacks calling the script right now.
thread_local ma_result g_soundsystem_last_error = MA_SUCCESS;
// Whether a time in milliseconds can be counted in frames at a rate, refusing with MA_INVALID_ARGS one whose frame count would overflow 64 bits and wrap, in NVGT's conversions and MiniAudio's alike, to a short time.
static bool frames_fit(unsigned long long milliseconds, ma_uint32 sample_rate) {
	if (!sample_rate || milliseconds <= UINT64_MAX / sample_rate) return true;
	g_soundsystem_last_error = MA_INVALID_ARGS;
	return false;
}
// Whether every value is a finite number, refusing with MA_INVALID_ARGS otherwise: a NaN or infinite volume, gain, distance or the like on one sound made every sample its engine mixed NaN, and a filter after it kept them NaN for good.
static bool finite_values(std::initializer_list<float> values) {
	for (float value : values) {
		if (!std::isfinite(value)) {
			g_soundsystem_last_error = MA_INVALID_ARGS;
			return false;
		}
	}
	return true;
}
static unordered_map<ma_data_source*, audio_data_source*> g_data_sources_map; // Only allow one audio_data_source wrapper per ma_data_source, should never be populated enough to be a performance hit.
static std::mutex g_data_sources_map_mutex; // Every decoder open/close inserts into or erases from this map, from whichever script thread does it; an unlocked unordered_map rehashing under a concurrent erase corrupts the heap.
static std::unique_ptr<sound_service> g_sound_service;
// These slots are what you use to refer to protocols (which are data sources like archives) and filters (which are transformations like encryption) after they've been plugged into the sound service.
static size_t g_encryption_filter_slot = 0;
static size_t g_pack_protocol_slot = 0;
static size_t g_memory_protocol_slot = 0;
static size_t g_netstream_protocol_slot = 0;
static std::vector<ma_decoding_backend_vtable *> g_decoders;
bool add_decoder(ma_decoding_backend_vtable *vtable) {
	try {
		g_decoders.push_back(vtable);
		return true;
	} catch (std::exception &) {
		return false;
	}
}
#ifdef MA_SUPPORT_AAUDIO
// MiniAudio's AAudio error callback reads the device's tear-down flag and then queues a reroute job. A callback that read the flag just before drain_aaudio_reroutes() raised it, and was then held up past the drain until the device was gone, still queued a job for freed memory. So the callback MiniAudio registers runs inside one that holds g_aaudio_error_mutex, which the drain also holds while it raises the flag: a callback either sees the flag or has queued its job before the drain starts waiting.
typedef void (*aaudio_error_callback)(void* stream, void* user_data, int32_t error);
static std::mutex g_aaudio_error_mutex;
static std::atomic<aaudio_error_callback> g_ma_aaudio_error_callback{nullptr};
static ma_proc g_aaudio_builder_set_error_callback = nullptr;
static void aaudio_error_callback_locked(void* stream, void* user_data, int32_t error) {
	std::lock_guard<std::mutex> lock(g_aaudio_error_mutex);
	g_ma_aaudio_error_callback.load()(stream, user_data, error);
}
static void set_aaudio_error_callback_locked(void* builder, aaudio_error_callback callback, void* user_data) {
	g_ma_aaudio_error_callback = callback;
	((void (*)(void*, aaudio_error_callback, void*))g_aaudio_builder_set_error_callback)(builder, aaudio_error_callback_locked, user_data);
}
static void lock_aaudio_error_callbacks(ma_context* context) {
	if (context->backend != ma_backend_aaudio || !context->aaudio.AAudioStreamBuilder_setErrorCallback || context->aaudio.AAudioStreamBuilder_setErrorCallback == (ma_proc)set_aaudio_error_callback_locked) return;
	g_aaudio_builder_set_error_callback = context->aaudio.AAudioStreamBuilder_setErrorCallback;
	context->aaudio.AAudioStreamBuilder_setErrorCallback = (ma_proc)set_aaudio_error_callback_locked;
}
// AAudio's error callback hands a disconnected or rerouted stream to the context's job thread as a reroute job that holds a raw pointer to the device, and ma_device_uninit only waits for a reroute that is already running, not for one still sitting in the queue. Such a job then runs after the device is gone: it locks the destroyed reroute mutex and reopens streams through freed memory. So before a device is uninitialized, raise its tear-down flag (the error callback then queues nothing new and a queued reroute returns at once), and wait until the job thread has worked through what is already queued. The thread runs its jobs one at a time in order, so once a job posted now has run, every reroute queued before it has finished. The second pass covers a context whose error callback could not be wrapped, where a callback that read the flag just before it was raised can post its job just after the first marker.
static ma_result aaudio_job_queue_marker(ma_job* job) {
	ma_event_signal((ma_event*)job->data.custom.data0);
	return MA_SUCCESS;
}
static void drain_aaudio_reroutes(ma_device* device) {
	if (!device || !device->pContext || device->pContext->backend != ma_backend_aaudio || ma_device_get_state(device) == ma_device_state_uninitialized) return;
	{
		std::lock_guard<std::mutex> lock(g_aaudio_error_mutex);
		__atomic_store_n(&device->aaudio.isTearingDown.value, MA_TRUE, __ATOMIC_SEQ_CST);
	}
	for (int pass = 0; pass < 2; pass++) {
		ma_event done;
		if (ma_event_init(&done) != MA_SUCCESS) return;
		ma_job job = ma_job_init(MA_JOB_TYPE_CUSTOM);
		job.data.custom.proc = aaudio_job_queue_marker;
		job.data.custom.data0 = (ma_uintptr)&done;
		if (ma_device_job_thread_post(&device->pContext->aaudio.jobThread, &job) == MA_SUCCESS) ma_event_wait(&done);
		ma_event_uninit(&done);
	}
}
// AAudio's framework callbacks run on binder threads and can still be under way when a stream is closed: a device update that finds the stream disconnected goes on using it after calling the error callback, whose reroute job closes it on the job thread, and the audio service can be setting its volume meanwhile. Android 11 and 12 then crash inside libaaudio on the freed stream. Oboe, Google's AAudio library, stops a stream and sleeps for one burst, 10 to 100 ms, before closing it for this reason. MiniAudio closes every stream, its reroutes included, through the context's pointer, so the context gets one that does the same.
static ma_proc g_aaudio_stream_close = nullptr, g_aaudio_stream_request_stop = nullptr, g_aaudio_stream_get_sample_rate = nullptr, g_aaudio_stream_get_frames_per_burst = nullptr;
static int32_t close_aaudio_stream_after_callbacks(void* stream) {
	typedef int32_t (*aaudio_stream_function)(void*);
	((aaudio_stream_function)g_aaudio_stream_request_stop)(stream);
	long long rate = ((aaudio_stream_function)g_aaudio_stream_get_sample_rate)(stream), burst = ((aaudio_stream_function)g_aaudio_stream_get_frames_per_burst)(stream);
	std::this_thread::sleep_for(std::chrono::milliseconds(std::clamp(rate > 0 && burst > 0? 1 + burst * 1000 / rate : 0LL, 10LL, 100LL)));
	return ((aaudio_stream_function)g_aaudio_stream_close)(stream);
}
static void delay_aaudio_stream_closes(ma_context* context) {
	if (context->backend != ma_backend_aaudio || context->aaudio.AAudioStream_close == (ma_proc)close_aaudio_stream_after_callbacks) return;
	if (!context->aaudio.AAudioStream_close || !context->aaudio.AAudioStream_requestStop || !context->aaudio.AAudioStream_getSampleRate || !context->aaudio.AAudioStream_getFramesPerBurst) return;
	g_aaudio_stream_close = context->aaudio.AAudioStream_close;
	g_aaudio_stream_request_stop = context->aaudio.AAudioStream_requestStop;
	g_aaudio_stream_get_sample_rate = context->aaudio.AAudioStream_getSampleRate;
	g_aaudio_stream_get_frames_per_burst = context->aaudio.AAudioStream_getFramesPerBurst;
	context->aaudio.AAudioStream_close = (ma_proc)close_aaudio_stream_after_callbacks;
}
#endif
static void uninit_device(ma_device* device) {
	#ifdef MA_SUPPORT_AAUDIO
	drain_aaudio_reroutes(device);
	#endif
	ma_device_uninit(device);
}
// Marks the setup under way for as long as it runs, also when it throws.
struct soundsystem_starting {
	soundsystem_starting() { g_soundsystem_starting = true; }
	~soundsystem_starting() { g_soundsystem_starting = false; }
};
// The context, the sound service and the device lists, which every engine needs, while init_sound() also builds the default engine. An engine of the script's own, such as one without a device, so doesn't depend on the default engine being buildable. False when the context can't start.
bool init_sound_context() {
	if (g_soundsystem_initialized.test()) return true;
	std::lock_guard<std::recursive_mutex> lock(g_soundsystem_init_mutex);
	if (g_soundsystem_initialized.test() || g_soundsystem_starting) return true; // set up by another thread while we waited for the lock, or a re-entrant call from the setup below on this one
	soundsystem_starting starting;
	#ifdef __linux__
	// Attempt to silence ALSA's verbose error output on headless servers; libasound may not be present so load it dynamically and ignore failure.
	typedef int (*snd_lib_error_set_handler_t)(void (*)(const char*, int, const char*, int, const char*, ...));
	if (SDL_SharedObject* alsa = SDL_LoadObject("libasound.so.2")) {
		if (auto set_handler = (snd_lib_error_set_handler_t)SDL_LoadFunction(alsa, "snd_lib_error_set_handler")) set_handler(quiet_alsa_handler);
	}
	#endif
	ma_context_config cfg = ma_context_config_init();
	cfg.coreaudio.sessionCategory = ma_ios_session_category_play_and_record;
	cfg.coreaudio.sessionCategoryOptions =
		ma_ios_session_category_option_default_to_speaker |
		ma_ios_session_category_option_allow_bluetooth |
		ma_ios_session_category_option_allow_bluetooth_a2dp |
		ma_ios_session_category_option_allow_air_play |
		ma_ios_session_category_option_mix_with_others;
	if ((g_soundsystem_last_error = ma_context_init(nullptr, 0, &cfg, &g_sound_context)) != MA_SUCCESS)
		return false;
	#ifdef MA_SUPPORT_AAUDIO
	delay_aaudio_stream_closes(&g_sound_context);
	lock_aaudio_error_callbacks(&g_sound_context);
	#endif
	g_sound_service = sound_service::make();
	if (g_sound_service == nullptr) {
		ma_context_uninit(&g_sound_context);
		return false;
	}
	// Register encryption support:
	g_sound_service->register_filter(encryption_filter::get_instance(), g_encryption_filter_slot);
	// And access to packs, et al:
	g_sound_service->register_protocol(pack_protocol::get_instance(), g_pack_protocol_slot);
	g_sound_service->register_protocol(memory_protocol::get_instance(), g_memory_protocol_slot);
	g_sound_service->register_protocol(netstream_protocol::get_instance(), g_netstream_protocol_slot);
	// Install default decoders into miniaudio.
	add_decoder(ma_decoding_backend_libvorbis);
	add_decoder(ma_decoding_backend_libopus);
	refresh_audio_devices();
	g_soundsystem_initialized.test_and_set(); // only now may other threads use what is set up here
	return true;
}
bool init_sound() {
	if (g_soundsystem_ready.test()) return true;
	// Everything below runs under the lock: a second thread must wait for the engine to exist rather than be told the system is ready while it is still being built.
	std::lock_guard<std::recursive_mutex> lock(g_soundsystem_init_mutex);
	if (g_soundsystem_ready.test()) return true; // another thread finished initializing while we waited for the lock
	if (g_soundsystem_shut_down.test()) throw runtime_error("the sound system has shut down");
	if (g_soundsystem_starting) return true; // re-entrant call from the setup, on this very thread; the engine is not assigned yet but everything it needs already is
	if (!init_sound_context()) return false;
	// An engine that can't be built, as on a machine without an output device, throws here, and again on each later call, which tries anew, rather than letting later calls report the system ready with g_audio_engine null.
	{
		soundsystem_starting starting;
		g_audio_engine = new_audio_engine(audio_engine::PERCENTAGE_ATTRIBUTES | audio_engine::NO_CLIP);
	}
	g_soundsystem_ready.test_and_set(); // only now may other threads use the default engine
	return true;
}
void uninit_sound() {
	if (!g_soundsystem_initialized.test())
		return;
	// Before the garbage collection, which can let go of a script's own engine for the last time, as a finished sound played from it does: once shut down, that engine is left to the process's exit (see audio_engine_impl::release()) rather than destroyed after SDL took down what its device needs.
	g_soundsystem_shut_down.test_and_set();
	garbage_collect_inline_sounds();
	wait_for_reaps(); // Sources a closed sound left still decoding are freed before the process's exit, as closing them did; none are handed over once shut down.
	std::lock_guard<std::recursive_mutex> lock(g_soundsystem_init_mutex);
	g_soundsystem_ready.clear(); // So that init_sound() refuses later calls instead of reporting a ready system whose engine is gone.
	if (g_audio_engine != nullptr) {
		g_audio_engine->release();
		g_audio_engine = nullptr;
	}
}

// audio device enumeration, we'll just maintain a global list of available devices, vectors of ma_device_info structures for the c++ side and CScriptArrays of device names on the Angelscript side. It is important that the data in these arrays is index aligned.
// Devices come and go while a program runs, so the lists are taken anew whenever a script reads one, and when a device in use isn't in them. Each taking makes new arrays, so an array a script holds never changes under it. g_devices_mutex covers the lists and the arrays' pointers.
static std::mutex g_devices_mutex;
static vector<ma_device_info> g_sound_input_devices, g_sound_output_devices;
static CScriptArray *g_sound_script_input_devices = nullptr, *g_sound_script_output_devices = nullptr;
struct audio_device_lists {
	vector<ma_device_info> inputs, outputs;
	CScriptArray *input_names = nullptr, *output_names = nullptr;
};
ma_bool32 ma_device_enum_callback(ma_context * /*ctx*/, ma_device_type type, const ma_device_info *info, void *user) {
	audio_device_lists *lists = (audio_device_lists*)user;
	string devname = info->name;
	if (type == ma_device_type_playback) {
		lists->outputs.push_back(*info);
		lists->output_names->InsertLast(&devname);
	} else if (type == ma_device_type_capture) {
		lists->inputs.push_back(*info);
		lists->input_names->InsertLast(&devname);
	}
	return MA_TRUE;
}
bool refresh_audio_devices() {
	if (!init_sound_context())
		return false;
	audio_device_lists lists;
	lists.input_names = CScriptArray::Create(get_array_type("array<string>"));
	lists.output_names = CScriptArray::Create(get_array_type("array<string>"));
	ma_result result = ma_context_enumerate_devices(&g_sound_context, ma_device_enum_callback, &lists);
	if (result == MA_SUCCESS) { // Otherwise the lists taken before stay.
		std::lock_guard<std::mutex> lock(g_devices_mutex);
		g_sound_input_devices.swap(lists.inputs);
		g_sound_output_devices.swap(lists.outputs);
		std::swap(g_sound_script_input_devices, lists.input_names);
		std::swap(g_sound_script_output_devices, lists.output_names);
	}
	// The arrays not kept, after the lock: those taken before, which scripts may still hold, or these new ones.
	if (lists.input_names) lists.input_names->Release();
	if (lists.output_names) lists.output_names->Release();
	g_soundsystem_last_error = result;
	return result == MA_SUCCESS;
}
// Copies the id of the device at index in its list, for opening it; false for an index the list doesn't have.
static bool audio_device_id(ma_device_type type, int index, ma_device_id &id) {
	std::lock_guard<std::mutex> lock(g_devices_mutex);
	const vector<ma_device_info> &list = type == ma_device_type_capture? g_sound_input_devices : g_sound_output_devices;
	if (index < 0 || index >= int(list.size())) return false;
	id = list[index].id;
	return true;
}
// The index of an open device in its list, or -1. A device that isn't there, as one plugged in after the lists were taken, has them taken anew once; one still missing then isn't looked for anew until another device goes missing.
static int audio_device_index(ma_device_type type, const ma_device_id &id) {
	static ma_device_id unlisted[2];
	static bool has_unlisted[2] = {false, false};
	const int t = type == ma_device_type_capture? 1 : 0;
	for (int attempt = 0;; attempt++) {
		{
			std::lock_guard<std::mutex> lock(g_devices_mutex);
			const vector<ma_device_info> &list = t? g_sound_input_devices : g_sound_output_devices;
			for (std::size_t i = 0; i < list.size(); i++) {
				if (ma_device_id_equal(&list[i].id, &id)) return int(i);
			}
			if (attempt > 0) {
				unlisted[t] = id;
				has_unlisted[t] = true;
				return -1;
			}
			if (has_unlisted[t] && ma_device_id_equal(&unlisted[t], &id)) return -1;
		}
		if (!refresh_audio_devices()) return -1;
	}
}
// Better to return an empty array instead of null for now. A single one, as the script adds its own reference to what these return, so a new array each time was never let go.
static CScriptArray *empty_device_list() {
	static CScriptArray *empty = CScriptArray::Create(get_array_type("array<string>"));
	return empty;
}
// Each with a reference of the caller's own, taken under the lock, as a list taken anew on another thread lets go of the one before.
CScriptArray *get_sound_input_devices() {
	if (!refresh_audio_devices() && !g_sound_script_input_devices) {
		empty_device_list()->AddRef();
		return empty_device_list();
	}
	std::lock_guard<std::mutex> lock(g_devices_mutex);
	g_sound_script_input_devices->AddRef();
	return g_sound_script_input_devices;
}
CScriptArray *get_sound_output_devices() {
	if (!refresh_audio_devices() && !g_sound_script_output_devices) {
		empty_device_list()->AddRef();
		return empty_device_list();
	}
	std::lock_guard<std::mutex> lock(g_devices_mutex);
	g_sound_script_output_devices->AddRef();
	return g_sound_script_output_devices;
}

reactphysics3d::Vector3 ma_vec3_to_rp_vec3(const ma_vec3f &v) { return reactphysics3d::Vector3(v.x, v.y, v.z); }
ma_format ma_format_from_angelscript_type(int type_id) {
	if (type_id == asTYPEID_FLOAT)
		return ma_format_f32;
	else if (type_id == asTYPEID_INT32)
		return ma_format_s32;
	else if (type_id == asTYPEID_INT16)
		return ma_format_s16;
	else if (type_id == asTYPEID_UINT8)
		return ma_format_u8;
	else
		return ma_format_unknown;
}

// The following function based on ma_sound_get_direction_to_listener.
// A sound's position relative to its listener, as MiniAudio's ma_spatializer_get_relative_position_and_direction() works it out, but in double: in float the listener's transform overflowed for positions about 1e19 or more apart, giving an infinite position with no direction to pan by, and a NaN one for positions near the float's limit. False without an engine.
static bool sound_relative_position(const ma_sound* sound, double relative[3]) {
	const ma_spatializer* spatializer = &sound->engineNode.spatializer;
	ma_vec3f position = ma_spatializer_get_position(spatializer);
	ma_engine* engine = ma_sound_get_engine(sound);
	if (!engine) return false;
	if (ma_spatializer_get_positioning(spatializer) == ma_positioning_relative) {
		relative[0] = position.x;
		relative[1] = position.y;
		relative[2] = position.z;
		return true;
	}
	const ma_spatializer_listener* listener = &engine->listeners[ma_sound_get_listener_index(sound)];
	ma_vec3f listener_position = ma_spatializer_listener_get_position(listener), forward = ma_spatializer_listener_get_direction(listener), up = listener->config.worldUp;
	auto normalize = [](double v[3]) {
		double length = sqrt(v[0] * v[0] + v[1] * v[1] + v[2] * v[2]);
		if (length > 0) for (int i = 0; i < 3; i++) v[i] /= length;
	};
	double axis_z[3] = {forward.x, forward.y, forward.z};
	normalize(axis_z);
	double axis_x[3] = {axis_z[1] * up.z - axis_z[2] * up.y, axis_z[2] * up.x - axis_z[0] * up.z, axis_z[0] * up.y - axis_z[1] * up.x};
	normalize(axis_x);
	if (axis_x[0] == 0 && axis_x[1] == 0 && axis_x[2] == 0) axis_x[0] = 1; // Looking along the world's up, as MiniAudio falls back.
	double axis_y[3] = {axis_x[1] * axis_z[2] - axis_x[2] * axis_z[1], axis_x[2] * axis_z[0] - axis_x[0] * axis_z[2], axis_x[0] * axis_z[1] - axis_x[1] * axis_z[0]};
	if (listener->config.handedness == ma_handedness_left) for (double& component : axis_x) component = -component;
	double offset[3] = {(double)position.x - listener_position.x, (double)position.y - listener_position.y, (double)position.z - listener_position.z};
	relative[0] = axis_x[0] * offset[0] + axis_x[1] * offset[1] + axis_x[2] * offset[2];
	relative[1] = axis_y[0] * offset[0] + axis_y[1] * offset[1] + axis_y[2] * offset[2];
	relative[2] = -(axis_z[0] * offset[0] + axis_z[1] * offset[1] + axis_z[2] * offset[2]);
	return true;
}
MA_API float ma_sound_get_distance_to_listener(const ma_sound *pSound) {
	double relative[3];
	if (pSound == NULL || !sound_relative_position(pSound, relative))
		return 0;
	return (float)sqrt(relative[0] * relative[0] + relative[1] * relative[1] + relative[2] * relative[2]); // Infinite only past the float's range.
}

template <class A, class B>
static B *op_cast(A *from) {
	B *casted = dynamic_cast<B *>(from);
	if (!casted)
		return nullptr;
	casted->duplicate();
	return casted;
}

// BGT seems to have used db for it's pan, we need to emulate that if the user chooses to enable backward compatibility options.
float pan_linear_to_db(float linear) {
	linear = clamp(linear, -1.0f, 1.0f);
	float db = ma_volume_linear_to_db(linear > 0 ? 1.0f - linear : linear + 1.0f);
	return linear > 0 ? db * -1.0f : db;
}
float pan_db_to_linear(float db) {
	db = clamp(db, -100.0f, 100.0f);
	float l = ma_volume_db_to_linear(fabs(db) * -1.0f);
	return db > 0 ? 1.0f - l : -1.0f + l;
}
// Callbacks for MiniAudio to write raw PCM to wav in memory. A write the stream didn't take is reported as such.
ma_result wav_write_proc(ma_encoder *pEncoder, const void *pBufferIn, size_t bytesToWrite, size_t *pBytesWritten) {
	std::ostream *stream = static_cast<std::ostream *>(pEncoder->pUserData);
	stream->write((const char *)pBufferIn, bytesToWrite);
	if (!stream->good()) {
		*pBytesWritten = 0;
		return MA_ERROR;
	}
	*pBytesWritten = bytesToWrite;
	return MA_SUCCESS;
}
ma_result wav_seek_proc(ma_encoder *pEncoder, ma_int64 offset, ma_seek_origin origin) {
	if (origin != ma_seek_origin_start)
		return MA_NOT_IMPLEMENTED;
	std::ostream *stream = static_cast<std::ostream *>(pEncoder->pUserData);
	stream->seekp(offset);
	if (!stream->good())
		return MA_ERROR;
	return MA_SUCCESS;
}

// The following code manages inlined, one-shot sounds. While miniaudio does provide support for this, it is subpar when considering what NVGT users wish for, namely it cannot return the ma_sound that was created.
unordered_set<sound*> g_inlined_sounds;
mutex g_inlined_sounds_mutex;
static bool sound_due_to_play(sound* s); // After sound_impl.
void garbage_collect_inline_sounds() {
	vector<sound*> finished;
	{
		unique_lock<mutex> lock(g_inlined_sounds_mutex); // For the whole walk, as sounds that start playing on other threads are added meanwhile.
		for (auto it = g_inlined_sounds.begin(); it != g_inlined_sounds.end();) {
			if (sound_due_to_play(*it)) ++it;
			else {
				finished.push_back(*it);
				it = g_inlined_sounds.erase(it);
			}
		}
	}
	for (sound *s : finished) s->release(); // Not under the lock, which closing a sound could need.
}

// Sound shapes let mixer/sound::set_position_3d position the sound as though it was more than one tile wide in each direction.
typedef sound_shape* sound_shape_setup_callback(mixer* connected_sound, CScriptHandle* shape_reference);
std::unordered_map<int, sound_shape_setup_callback*> g_sound_shape_setup_callbacks;
// A shaped sound or mixer is placed from where its listener is, so each move of a listener places those of its engine again, on the thread that moved it. Taken before a mixer's spatialization_params_mutex.
class mixer_impl;
static std::mutex g_shaped_mixers_mutex;
static std::unordered_set<mixer_impl*> g_shaped_mixers;
static void place_shaped_mixers(audio_engine* engine);
sound_shape* sound_shape_builtin_standard_setup(mixer* snd, CScriptHandle* shape_ref) {
	// This assumes that the shape object has already been created by the scripter and is contained within the CScriptHandle we've received.
	sound_shape* shape = (sound_shape*)(shape_ref->GetRef());
	shape->duplicate();
	return shape;
}
class sound_aabb_shape : public sound_shape {
public:
	int left_range, right_range, backward_range, forward_range, lower_range, upper_range;
	sound_aabb_shape(int left_range, int right_range, int backward_range, int forward_range, int lower_range, int upper_range) : sound_shape(), left_range(left_range), right_range(right_range), backward_range(backward_range), forward_range(forward_range), lower_range(lower_range), upper_range(upper_range) {}
	bool contains(const reactphysics3d::Vector3& listener_position, reactphysics3d::Vector3& sound_position) override {
		// The box between the two corners the ranges make, whichever way round: ranges whose sum is negative on an axis crossed its corners over, which std::clamp() below is undefined for, and the sound played from the box's far edge.
		reactphysics3d::Vector3 low_corner = sound_position - reactphysics3d::Vector3(left_range, backward_range, lower_range), high_corner = sound_position + reactphysics3d::Vector3(right_range, forward_range, upper_range);
		reactphysics3d::AABB bounds(reactphysics3d::Vector3::min(low_corner, high_corner), reactphysics3d::Vector3::max(low_corner, high_corner));
		if (bounds.contains(listener_position)) return true;
		sound_position.x = clamp(listener_position.x, bounds.getMin().x, bounds.getMax().x);
		sound_position.y = clamp(listener_position.y, bounds.getMin().y, bounds.getMax().y);
		sound_position.z = clamp(listener_position.z, bounds.getMin().z, bounds.getMax().z);
		return false;
	}
};
sound_aabb_shape* create_sound_aabb_shape(int left_range, int right_range, int backward_range, int forward_range, int lower_range, int upper_range) { return new sound_aabb_shape(left_range, right_range, backward_range, forward_range, lower_range, upper_range); }

// An engine's endpoint, which lives exactly as long as its engine: its references are the engine's, so a script holding the endpoint keeps the engine, while the engine, which deletes it, isn't kept alive by it. A reference of its own on the engine made the two hold each other, and no engine was ever destroyed.
class audio_engine_endpoint final : public audio_node_impl {
public:
	audio_engine_endpoint(ma_node_base *endpoint, audio_engine *e) : audio_node_impl(endpoint, e) { engine->release(); } // Gives back the reference the node took; the engine's own keeps it alive.
	~audio_engine_endpoint() { engine = nullptr; } // So the node doesn't give it back a second time.
	void duplicate() override { engine->duplicate(); }
	void release() override { engine->release(); }
	// Nothing reads an endpoint's output but a loop back into the endpoint, which MiniAudio reads without end through a passthrough node such as a chain or an encoder. An engine is mixed into another through its own node instead.
	bool attach_output_bus(unsigned int output_bus, audio_node *destination, unsigned int destination_input_bus) override {
		g_soundsystem_last_error = MA_INVALID_OPERATION;
		return false;
	}
};
// Miniaudio objects must be allocated on the heap as nvgt's API introduces the concept of an uninitialized sound, which a stack based system would make more difficult to implement.
class audio_engine_impl final : public audio_node_impl, public virtual audio_engine {
	std::unique_ptr<ma_engine> engine;
	std::unique_ptr<ma_resource_manager> resource_manager;
	std::unique_ptr<ma_device> device;
	bool device_follows_default = true; // Whether the device was opened as the system's default rather than by its id, as the constructor and assigning -1 do.
	std::atomic<bool> started{false}; // Whether the engine is meant to run: started by the constructor or start(), until stop(). set_device() starts the new device only then.
	// set_device(), start() and stop() of the engine, one at a time: two threads changing its device at once, as by assigning sound_output_device, uninitialised and opened its one ma_device under each other, and both waited for good.
	mutable std::mutex device_mutex;
	std::atomic<asIScriptFunction*> script_data_callback;
	audio_engine_endpoint *engine_endpoint; // Upon engine creation we'll call ma_engine_get_endpoint once so as to avoid creating more than one of our wrapper objects when our engine->get_endpoint() function is called.
	std::mutex callback_mutex; // Lets the device's thread take a reference of its own to script_data_callback before set_processing_callback() can let it go.
	asITypeInfo *script_data_buffer_type = nullptr; // memory_buffer<float>, the type of the callback's buffer, looked up by set_processing_callback() on the script's thread and read under callback_mutex.
	inline static thread_local audio_engine_impl *processing = nullptr; // The engine whose device this thread is running the data callback of, see release().
	struct processing_scope {
		processing_scope(audio_engine_impl *engine) { audio_engine_impl::processing = engine; }
		~processing_scope() { audio_engine_impl::processing = nullptr; }
	};
	// A reference for the data callback, unless the last one is already gone and the engine is being destroyed on another thread, which waits for the callback to return; a plain duplicate() would bring it back for a second destruction.
	bool duplicate_if_alive() {
		for (int count = refcount; count > 0;) {
			#ifdef _MSC_VER
			int seen = _InterlockedCompareExchange(reinterpret_cast<volatile long*>(&refcount), count + 1, count);
			#else
			int seen = __sync_val_compare_and_swap(&refcount, count, count + 1);
			#endif
			if (seen == count) return true;
			count = seen;
		}
		return false;
	}
	// Mixing needs no reference: destroying the engine stops the device first, which waits for this call to return. Calling the script does, as the engine is its argument, which takes a reference and gives it back.
	static void data_callback(ma_device *pDevice, void *pOutput, const void *pInput, ma_uint32 frameCount) {
		audio_engine_impl* engine = reinterpret_cast<audio_engine_impl*>(pDevice->pUserData);
		processing_scope scope(engine); // Outlasts every reference let go below.
		ma_uint64 frames_read;
		engine->read(pOutput, frameCount, &frames_read);
		// The script is given the device's whole block, which MiniAudio silenced before the engine mixed into it: the engine reports only the frames its graph gave, none while nothing is attached to it, so that a script making its audio itself got no block to fill, and part of one when a node ended within it.
		if (!engine->script_data_callback) return;
		// Counted before looking at the flag and before taking the engine's reference, and given back after letting that go, which can destroy the engine on a thread of its own, counted then (see delete_detached()): so sound_stop_script_callbacks() either sees this call, waiting for it and for such a deletion, or this call sees the flag and takes no reference. Given back before letting the reference go, a deletion it started could come after the waiter saw no call running.
		g_script_callbacks_running++;
		if (g_script_callbacks_stopped || !engine->duplicate_if_alive()) {
			g_script_callbacks_running--;
			return;
		}
		asIScriptFunction *callback = nullptr;
		asITypeInfo *buffer_type = nullptr;
		{
			std::lock_guard<std::mutex> lock(engine->callback_mutex);
			callback = engine->script_data_callback;
			if (callback) callback->AddRef();
			buffer_type = engine->script_data_buffer_type;
		}
		if (callback) {
			asIScriptContext* ctx = g_ScriptEngine->RequestContext();
			if (ctx && ctx->Prepare(callback) >= 0) { // Todo: Maybe find a way to log error state here?
				// The type set_processing_callback() looked up: GetTypeInfoByDecl here, on the device's thread for every buffer, searched the engine's template instances while a script thread's build could be adding to them. get_array_type() isn't used here, as it can wait for the build lock, which a thread destroying this engine may hold while it waits for this callback to return.
				script_memory_buffer buf(buffer_type, pOutput, pDevice->playback.channels * frameCount); // Todo: Support all data formats.
				if (ctx->SetArgObject(0, static_cast<audio_engine*>(engine)) >= 0 && ctx->SetArgObject(1, &buf) >= 0 && ctx->SetArgQWord(2, frameCount) >= 0)
					ctx->Execute(); // Really not sure what to do about exceptions and errors taking place in the audio thread yet as we don't have a fully established logging facility set up.
			}
			if (ctx) g_ScriptEngine->ReturnContext(ctx);
			callback->Release();
		}
		engine->release(); // Can be the last reference, see release().
		g_script_callbacks_running--;
	}

public:
	std::shared_ptr<std::atomic<ma_uint64>> time_sets = std::make_shared<std::atomic<ma_uint64>>(0); // Times the script set this engine's time, which voids the blocks its sounds and groups recorded (see held_sound::block_set); shared with them, as they can outlive it.
	static bool on_audio_thread() { return processing; } // This thread runs a device's data callback, as a processing callback does.
	bool meant_to_run() const { return started; } // Started, by the constructor or start(), and not stopped since.
	engine_flags flags;
	audio_engine_impl(int flags, int sample_rate, int channels) : audio_node_impl(nullptr, this), engine(nullptr), resource_manager(nullptr), script_data_callback(nullptr), engine_endpoint(nullptr), flags(static_cast<engine_flags>(flags)) {
		if (channels > MA_MAX_CHANNELS) throw runtime_error(Poco::format("exceeded maximum channel count of %d", MA_MAX_CHANNELS));
		if (sample_rate < 0) sample_rate = 0; // As 0, the device's own rate or the default without a device, rather than a rate of over four billion, which a negative one became in MiniAudio's unsigned fields.
		if (sample_rate > ma_standard_sample_rate_max) throw runtime_error(Poco::format("exceeded maximum sample rate of %d", int(ma_standard_sample_rate_max))); // At a higher one, the highest MiniAudio has a name for, a device's every period needed many times the frames it plays resampled, more than the audio thread could keep up with.
		if (sample_rate && sample_rate < int(min_sample_rate)) throw runtime_error(Poco::format("below minimum sample rate of %d", int(min_sample_rate))); // Below it, the resource manager's pages held no frames, and every sound loaded or streamed on the engine played silence while its load succeeded.
		if (!init_sound_context()) throw runtime_error(Poco::format("failed to initialize sound context %d", int(g_soundsystem_last_error)));
		engine = std::make_unique<ma_engine>();
		// We need a self-managed device because at least on Windows, we can't meet low-latency requirements without specific configurations.
		if ((flags & NO_DEVICE) == 0) {
			device = std::make_unique<ma_device>();
			ma_device_config cfg = ma_device_config_init(ma_device_type_playback);
			cfg.playback.channels = channels > 0? channels : 2;
			cfg.playback.format = ma_format_f32;
			cfg.sampleRate = sample_rate;
			cfg.noClip = (flags & engine_flags::NO_CLIP)? MA_TRUE : MA_FALSE;
			cfg.periodSizeInFrames = SOUNDSYSTEM_FRAMESIZE;

			// Hook up high quality resampling, because we want the app to accommodate the device's sample rate, not the other way around.
			cfg.resampling.algorithm = ma_resample_algorithm_custom;
			cfg.resampling.pBackendVTable = &wdl_resampler_backend_vtable;
			cfg.wasapi.noAutoConvertSRC = true;

			cfg.dataCallback = data_callback;
			cfg.pUserData = this;
			g_soundsystem_last_error = ma_device_init(&g_sound_context, &cfg, &*device);
			if (g_soundsystem_last_error != MA_SUCCESS) {
				engine.reset();
				device.reset();
				throw runtime_error(Poco::format("failed to initialize sound engine device %d", int(g_soundsystem_last_error)));
			}
		}

		// We need a self managed resource manager because we need to plug decoders in and configure the job thread count.
		{
			ma_resource_manager_config cfg = ma_resource_manager_config_init();
			// Attach the resource manager to the sound service so that it can receive audio from custom sources.
			cfg.pVFS = g_sound_service->get_vfs();
			// This is the sample rate that sounds will be resampled to if necessary during loading. We set this equal to whatever sample rate the device got. This is maximally efficient as long as the user doesn't switch devices to one that runs at a different rate. When they do, a single resampler kicks in.
			cfg.decodedSampleRate = device && !sample_rate? device->playback.internalSampleRate : sample_rate;
			// Set the resampler used during decoding to a high quality one. At the time of writing this, this is relying on support that I added to MiniAudio myself and has not yet been merged upstream.
			cfg.resampling.algorithm = ma_resample_algorithm_custom;
			cfg.resampling.pBackendVTable = &wdl_resampler_backend_vtable;
			if (!g_decoders.empty()) {
				cfg.ppCustomDecodingBackendVTables = &g_decoders[0];
				cfg.customDecodingBackendCount = g_decoders.size();
			}
			// MiniAudio takes at most MA_RESOURCE_MANAGER_MAX_JOB_THREAD_COUNT job threads and won't start with more, and hardware_concurrency() reports 0 when it can't tell, which would leave asynchronous loads no thread to finish them.
			cfg.jobThreadCount = std::clamp(std::thread::hardware_concurrency(), 1u, (unsigned int)MA_RESOURCE_MANAGER_MAX_JOB_THREAD_COUNT);
			resource_manager = std::make_unique<ma_resource_manager>();
			if ((g_soundsystem_last_error = ma_resource_manager_init(&cfg, &*resource_manager)) != MA_SUCCESS) {
				if (device) uninit_device(&*device); // None for an engine without a device.
				device.reset();
				engine.reset();
				resource_manager.reset();
				throw runtime_error(Poco::format("failed to initialize sound engine resource manager %d", int(g_soundsystem_last_error)));
			}
		}
		ma_engine_config cfg = ma_engine_config_init();
		cfg.pContext = &g_sound_context;
		cfg.pResourceManager = &*resource_manager;
		cfg.noAutoStart = (flags & NO_AUTO_START) ? MA_TRUE : MA_FALSE;
		cfg.periodSizeInFrames = SOUNDSYSTEM_FRAMESIZE; // Steam Audio requires fixed sized updates. We can make this not be a magic constant if anyone has some reason for wanting to change it.
		if ((flags & NO_DEVICE) == 0) cfg.pDevice = &*device;
		else {
			cfg.noDevice = MA_TRUE;
			cfg.channels = channels > 0? channels : 2;
			cfg.sampleRate = sample_rate > 0? sample_rate : 48000;
		}
		if ((g_soundsystem_last_error = ma_engine_init(&cfg, &*engine)) != MA_SUCCESS) {
			engine.reset();
			if (resource_manager) { ma_resource_manager_uninit(&*resource_manager); resource_manager.reset(); }
			if (device) { uninit_device(&*device); device.reset(); }
			throw runtime_error(Poco::format("failed to initialize sound engine %d", int(g_soundsystem_last_error)));
		}
		node = (ma_node_base*)&*engine;
		started = (flags & NO_AUTO_START) == 0;
		// Set some default properties for spatialization.
		set_listener_direction(0, 0, 1, 0); // Y forward
		set_listener_world_up(0, 0, 0, 1);  // Z up
		engine_endpoint = new audio_engine_endpoint(reinterpret_cast<ma_node_base *>(ma_engine_get_endpoint(&*engine)), this);
	}
	~audio_engine_impl() {
		if (device) {
			ma_device_stop(&*device);
			uninit_device(&*device);
		}
		if (script_data_callback) {
			script_data_callback.load()->Release();
			script_data_callback = nullptr;
		}
		delete engine_endpoint;
		if (engine) {
			std::lock_guard<std::recursive_mutex> graph_lock(g_node_graph_mutex); // The engine's node can be attached in another engine's graph, which uninitializing detaches it from.
			ma_engine_uninit(&*engine);
			engine = nullptr;
		}
		if (resource_manager) {
			wait_for_reaps(&*resource_manager); // Its sources a closed sound left decoding, freed through it.
			ma_resource_manager_uninit(&*resource_manager);
		}
	}
	// The last reference can go on the engine's own device thread, as the data callback holds one while it calls the script. Destroying the engine stops its device, which from that thread would wait for itself forever, so the engine is destroyed on a thread of its own then, or kept if none can be started.
	void release() override {
		if (asAtomicDec(refcount) >= 1) return;
		if (g_soundsystem_shut_down.test()) return; // Once the sound system shut down, engines are left to the process's exit, as they always were: destroying one closes its device, which by then can come after SDL took down what the backend needs, COM on Windows.
		if (!processing) {
			delete this;
			return;
		}
		// Not on another engine's device thread either, whose audio would be held up while this engine's device stops and closes and its closed sounds' decoding is waited out, a hundred milliseconds or more.
		delete_detached(this);
	}
	ma_engine *get_ma_engine() const override { return engine.get(); }
	audio_node *get_endpoint() const override { return engine_endpoint; }
	int get_flags() const override { return flags; }
	int get_device() const override {
		if (!engine || flags & NO_DEVICE)
			return -1;
		// Not while set_device() on another thread uninitialises and opens the device again, which zeroes it, so that asking MiniAudio about it then could reach a null context. Not taken on the device's own callback, which set_device() waits for, and during which the device isn't being opened; only tried on another engine's, which mustn't wait for a set_device() that waits for this engine's callback, as two callbacks reading each other's engines while both engines changed device did, for good: -1 then, as while a device is being opened.
		std::unique_lock<std::mutex> lock(device_mutex, std::defer_lock);
		if (processing && processing != this && !lock.try_lock()) {
			g_soundsystem_last_error = MA_BUSY;
			return -1;
		}
		if (!processing) lock.lock();
		ma_device *dev = ma_engine_get_device(&*engine);
		ma_device_info info;
		// A device that set_device couldn't open again is left uninitialized, and asking miniaudio about it would reach its backend.
		if (!dev || ma_device_get_state(dev) == ma_device_state_uninitialized || ma_device_get_info(dev, ma_device_type_playback, &info) != MA_SUCCESS)
			return -1;
		return audio_device_index(ma_device_type_playback, info.id);
	}
	bool set_device(int device) override {
		if (processing || !engine || flags & NO_DEVICE) { // Closing the device from its own thread would wait for that thread, see release(); from another engine's, it could wait for a callback waiting for this one, see stop().
			g_soundsystem_last_error = MA_INVALID_OPERATION;
			return false;
		}
		ma_device_id requested_id; // Copied: the list can be taken anew while the device opens.
		if (device < -1 || device > -1 && !audio_device_id(ma_device_type_playback, device, requested_id)) {
			g_soundsystem_last_error = MA_INVALID_ARGS;
			return false;
		}
		std::lock_guard<std::mutex> lock(device_mutex);
		ma_device *old_dev = ma_engine_get_device(&*engine);
		bool old_open = old_dev && ma_device_get_state(old_dev) != ma_device_state_uninitialized;
		if (!old_dev) return false;
		// Nothing to change: the default asked for while following it, or a device asked for that is open as that device, and running if the engine is. A device open as the default follows the system's default, even while it is the device asked for by its index, so that one is opened anew as the device itself; and one the backend stopped, as after a reroute that failed, is opened anew too, which asking for it again is a script's way to recover.
		if (old_open && (!started || ma_device_is_started(old_dev)) && (device == -1? device_follows_default : !device_follows_default && ma_device_id_equal(&old_dev->playback.id, &requested_id))) return true;
		ma_engine_stop(&*engine);
		// As the constructor opens the device, with the engine's own format, which stays the same whichever device it is on and is still known after a device couldn't be opened.
		ma_device_config cfg = ma_device_config_init(ma_device_type_playback);
		if (device > -1) cfg.playback.pDeviceID = &requested_id;
		cfg.playback.channels = ma_engine_get_channels(&*engine);
		cfg.playback.format = ma_format_f32;
		cfg.sampleRate = ma_engine_get_sample_rate(&*engine);
		cfg.noClip = (flags & engine_flags::NO_CLIP)? MA_TRUE : MA_FALSE;
		cfg.periodSizeInFrames = SOUNDSYSTEM_FRAMESIZE;
		cfg.resampling.algorithm = ma_resample_algorithm_custom;
		cfg.resampling.pBackendVTable = &wdl_resampler_backend_vtable;
		cfg.wasapi.noAutoConvertSRC = true;
		cfg.dataCallback = data_callback;
		cfg.pUserData = this;
		ma_device_id previous_id = old_dev->playback.id;
		bool previous_default = device_follows_default;
		ma_device_stop(old_dev);
		uninit_device(old_dev);
		if ((g_soundsystem_last_error = ma_device_init(&g_sound_context, &cfg, old_dev)) == MA_SUCCESS) {
			device_follows_default = device == -1;
			return !started || (g_soundsystem_last_error = ma_engine_start(&*engine)) == MA_SUCCESS; // An engine that was never started, or that the script stopped, stays stopped on the new device.
		}
		// The device asked for couldn't be opened: the one in use before is opened again, so that assigning it changes nothing, or failing that the system's default, so as not to leave the engine without a device. The error reported stays that of the device asked for.
		ma_result error = g_soundsystem_last_error;
		bool reopened = false;
		if (old_open) {
			cfg.playback.pDeviceID = previous_default? nullptr : &previous_id;
			reopened = ma_device_init(&g_sound_context, &cfg, old_dev) == MA_SUCCESS;
		}
		if (!reopened && !(old_open && previous_default)) {
			cfg.playback.pDeviceID = nullptr;
			reopened = ma_device_init(&g_sound_context, &cfg, old_dev) == MA_SUCCESS;
			if (reopened) device_follows_default = true;
		}
		if (reopened && started) ma_engine_start(&*engine);
		g_soundsystem_last_error = error;
		return false;
	}
	bool read(void *buffer, unsigned long long frame_count, unsigned long long *frames_read) override { return engine ? (g_soundsystem_last_error = ma_engine_read_pcm_frames(&*engine, buffer, frame_count, frames_read)) == MA_SUCCESS : false; }
	CScriptArray *read_script(unsigned long long frame_count) override {
		if (!engine)
			return nullptr;
		if ((flags & NO_DEVICE) == 0) { // Its device reads it on its own thread, and MiniAudio's engine can't be read from two at once.
			g_soundsystem_last_error = MA_INVALID_OPERATION;
			return CScriptArray::Create(get_array_type("array<float>"));
		}
		if (output_attached()) { // Mixed into another engine, whose audio thread reads it there.
			g_soundsystem_last_error = MA_INVALID_OPERATION;
			return CScriptArray::Create(get_array_type("array<float>"));
		}
		unsigned int channels = ma_engine_get_channels(&*engine);
		if (frame_count > 0xFFFFFFFF / channels) throw runtime_error("too many frames requested");
		CScriptArray *result = CScriptArray::Create(get_array_type("array<float>"), frame_count * channels);
		asIScriptContext* ctx = asGetActiveContext();
		if (ctx && ctx->GetState() == asEXECUTION_EXCEPTION) {
			result->Release();
			return nullptr;
		}
		// Whether the engine's endpoint runs for the whole read, so that a short one comes of nothing being attached: one the script stopped, or scheduled to start or stop within the read (set_state_time()), reads short too, and holds the engine's time as on a device, for what was scheduled on it.
		ma_node* endpoint = ma_engine_get_endpoint(&*engine);
		const ma_uint64 now = ma_engine_get_time_in_pcm_frames(&*engine), endpoint_stop = ma_node_get_state_time(endpoint, ma_node_state_stopped);
		const bool endpoint_runs = ma_node_get_state(endpoint) == ma_node_state_started && ma_node_get_state_time(endpoint, ma_node_state_started) <= now && endpoint_stop > now && endpoint_stop - now >= frame_count;
		unsigned long long frames_read;
		if (!read(result->GetBuffer(), frame_count, &frames_read)) {
			result->Resize(0);
			return result;
		}
		// With nothing attached to it, MiniAudio's engine reads no frames and its time stands still, so a script reading it for a time or a number of frames, as before attaching anything, read nothing for good: it reads the silence MiniAudio wrote for the frames asked, and its time moves on by them, as with anything attached.
		if (endpoint_runs && frames_read < frame_count) {
			ma_engine_set_time_in_pcm_frames(&*engine, ma_engine_get_time_in_pcm_frames(&*engine) + (frame_count - frames_read));
			frames_read = frame_count;
		}
		result->Resize(frames_read * ma_engine_get_channels(&*engine));
		return result;
	}
	void set_processing_callback(asIScriptFunction* cb) override {
		asIScriptFunction *old;
		asITypeInfo *buffer_type = cb ? get_array_type("memory_buffer<float>") : nullptr; // See data_callback().
		{
			std::lock_guard<std::mutex> lock(callback_mutex);
			old = script_data_callback.exchange(cb);
			if (buffer_type) script_data_buffer_type = buffer_type;
		}
		if (old) old->Release(); // The device's thread holds a reference of its own to one it is calling.
	}
	asIScriptFunction* get_processing_callback() const override { return script_data_callback; }
	unsigned long long get_time() const override { return engine ? (flags & DURATIONS_IN_FRAMES ? get_time_in_frames() : get_time_in_milliseconds()) : 0; }
	bool set_time(unsigned long long time) override { return engine ? (flags & DURATIONS_IN_FRAMES) ? set_time_in_frames(time) : set_time_in_milliseconds(time) : false; }
	unsigned long long get_time_in_frames() const override { return engine ? ma_engine_get_time_in_pcm_frames(&*engine) : 0; }
	bool set_time_in_frames(unsigned long long time) override {
		if (!engine || (g_soundsystem_last_error = ma_engine_set_time_in_pcm_frames(&*engine, time)) != MA_SUCCESS) return false;
		time_sets->fetch_add(1); // A block a sound of this engine recorded is no longer the one under way (see held_sound::block_set).
		return true;
	}
	unsigned long long get_time_in_milliseconds() const override { return engine ? ma_engine_get_time_in_milliseconds(&*engine) : 0; }
	bool set_time_in_milliseconds(unsigned long long time) override {
		if (!engine || !frames_fit(time, ma_engine_get_sample_rate(&*engine)) || (g_soundsystem_last_error = ma_engine_set_time_in_milliseconds(&*engine, time)) != MA_SUCCESS) return false;
		time_sets->fetch_add(1);
		return true;
	}
	int get_channels() const override { return engine ? ma_engine_get_channels(&*engine) : 0; }
	int get_sample_rate() const override { return engine ? ma_engine_get_sample_rate(&*engine) : 0; }
	bool start() override {
		if (!engine) return false;
		if (processing == this) return true; // Its device runs, this being its callback; waiting for device_mutex here could be for set_device() on another thread, which waits for this callback to return.
		std::unique_lock<std::mutex> lock(device_mutex, std::defer_lock);
		if (!processing) lock.lock();
		else if (!lock.try_lock()) { // Only tried on another engine's callback, see get_device().
			g_soundsystem_last_error = MA_BUSY;
			return false;
		}
		if ((g_soundsystem_last_error = ma_engine_start(&*engine)) != MA_SUCCESS) return false;
		started = true;
		return true;
	}
	bool stop() override {
		// Stopping a device waits for its callback: from its own thread that would wait for that thread, see release(), and from another engine's callback it waited for good when that device's callback stopped this engine in turn.
		if (processing) {
			g_soundsystem_last_error = MA_INVALID_OPERATION;
			return false;
		}
		if (!engine) return false;
		std::lock_guard<std::mutex> lock(device_mutex);
		if ((g_soundsystem_last_error = ma_engine_stop(&*engine)) != MA_SUCCESS) return false;
		started = false;
		return true;
	}
	bool set_volume(float volume) override { return engine && finite_values({volume})? (g_soundsystem_last_error = ma_engine_set_volume(&*engine, volume)) == MA_SUCCESS : false; }
	float get_volume() const override { return engine ? ma_engine_get_volume(&*engine) : 0; }
	bool set_gain(float db) override { return engine && finite_values({db, ma_volume_db_to_linear(db)})? (g_soundsystem_last_error = ma_engine_set_gain_db(&*engine, db)) == MA_SUCCESS : false; }
	float get_gain() const override { return engine ? ma_engine_get_gain_db(&*engine) : 0; }
	unsigned int get_listener_count() const override { return engine ? ma_engine_get_listener_count(&*engine) : 0; }
	int find_closest_listener(float x, float y, float z) const override { return engine ? ma_engine_find_closest_listener(&*engine, x, y, z) : -1; }
	int find_closest_listener_vector(const reactphysics3d::Vector3 &position) const override { return engine ? ma_engine_find_closest_listener(&*engine, position.x, position.y, position.z) : -1; }
	void set_listener_position(unsigned int index, float x, float y, float z) override {
		if (engine && finite_values({x, y, z}))
			ma_engine_listener_set_position(&*engine, index, x, y, z);
		place_shaped_mixers(this);
	}
	void set_listener_position_vector(unsigned int index, const reactphysics3d::Vector3 &position) override {
		if (engine && finite_values({position.x, position.y, position.z}))
			ma_engine_listener_set_position(&*engine, index, position.x, position.y, position.z);
		place_shaped_mixers(this);
	}
	reactphysics3d::Vector3 get_listener_position(unsigned int index) const override { return engine ? ma_vec3_to_rp_vec3(ma_engine_listener_get_position(&*engine, index)) : reactphysics3d::Vector3(); }
	void set_listener_direction(unsigned int index, float x, float y, float z) override {
		if (engine && finite_values({x, y, z}))
			ma_engine_listener_set_direction(&*engine, index, x, y, z);
	}
	void set_listener_direction_vector(unsigned int index, const reactphysics3d::Vector3 &direction) override {
		if (engine && finite_values({direction.x, direction.y, direction.z}))
			ma_engine_listener_set_direction(&*engine, index, direction.x, direction.y, direction.z);
	}
	reactphysics3d::Vector3 get_listener_direction(unsigned int index) const override { return engine ? ma_vec3_to_rp_vec3(ma_engine_listener_get_direction(&*engine, index)) : reactphysics3d::Vector3(); }
	void set_listener_velocity(unsigned int index, float x, float y, float z) override {
		if (engine && finite_values({x, y, z}))
			ma_engine_listener_set_velocity(&*engine, index, x, y, z);
	}
	void set_listener_velocity_vector(unsigned int index, const reactphysics3d::Vector3 &velocity) override {
		if (engine && finite_values({velocity.x, velocity.y, velocity.z}))
			ma_engine_listener_set_velocity(&*engine, index, velocity.x, velocity.y, velocity.z);
	}
	reactphysics3d::Vector3 get_listener_velocity(unsigned int index) const override { return engine ? ma_vec3_to_rp_vec3(ma_engine_listener_get_velocity(&*engine, index)) : reactphysics3d::Vector3(); }
	// A listener's cone, which NVGT's attenuators apply (see mixer_impl::get_cone_volume()), MiniAudio's own left at its default, which applies nothing.
	struct listener_cone {
		std::atomic<float> inner{6.283185f}, outer{6.283185f}, outer_gain{0};
	} listener_cones[MA_ENGINE_MAX_LISTENERS];
	void set_listener_cone(unsigned int index, float inner_radians, float outer_radians, float outer_gain) override {
		if (engine && index < ma_engine_get_listener_count(&*engine) && finite_values({inner_radians, outer_radians, outer_gain})) {
			listener_cones[index].inner = inner_radians;
			listener_cones[index].outer = outer_radians;
			listener_cones[index].outer_gain = outer_gain;
		}
	}
	void get_listener_cone(unsigned int index, float *inner_radians, float *outer_radians, float *outer_gain) const override {
		if (!engine) return;
		bool listening = index < ma_engine_get_listener_count(&*engine); // MiniAudio gave 0 for a listener it doesn't have.
		if (inner_radians) *inner_radians = listening? listener_cones[index].inner.load() : 0;
		if (outer_radians) *outer_radians = listening? listener_cones[index].outer.load() : 0;
		if (outer_gain) *outer_gain = listening? listener_cones[index].outer_gain.load() : 0;
	}
	void set_listener_world_up(unsigned int index, float x, float y, float z) override {
		if (engine && finite_values({x, y, z}))
			ma_engine_listener_set_world_up(&*engine, index, x, y, z);
	}
	void set_listener_world_up_vector(unsigned int index, const reactphysics3d::Vector3 &world_up) override {
		if (engine && finite_values({world_up.x, world_up.y, world_up.z}))
			ma_engine_listener_set_world_up(&*engine, index, world_up.x, world_up.y, world_up.z);
	}
	reactphysics3d::Vector3 get_listener_world_up(unsigned int index) const override { return engine ? ma_vec3_to_rp_vec3(ma_engine_listener_get_world_up(&*engine, index)) : reactphysics3d::Vector3(); }
	void set_listener_enabled(unsigned int index, bool enabled) override {
		if (engine)
			ma_engine_listener_set_enabled(&*engine, index, enabled);
	}
	bool get_listener_enabled(unsigned int index) const override { return ma_engine_listener_is_enabled(&*engine, index); }
	sound* play(const string& path, const reactphysics3d::Vector3& position, float volume, float pan, float pitch, mixer* mix, const pack_interface* pack_file, bool autoplay) override {
		garbage_collect_inline_sounds();
		sound* snd = new_sound();
		if (!snd) return nullptr;
		try { // A load can throw, as for a pack open for writing: the sound is let go of, rather than left holding its engine, and the default mixer, for good.
			if (!snd->load(path, pack_file)) {
				snd->release();
				return nullptr;
			}
			if (mix) snd->set_mixer(mix);
			if (position.x != FLT_MAX || position.y != FLT_MAX || position.z != FLT_MAX) snd->set_position_3d_vector(position);
			// As for the position, FLT_MAX leaves the sound's own default, which is right whether or not the engine takes these as percentages and decibels.
			if (volume != FLT_MAX) snd->set_volume(volume);
			if (pan != FLT_MAX) snd->set_pan(pan);
			if (pitch != FLT_MAX) snd->set_pitch(pitch);
			if (autoplay) snd->play();
		} catch (...) {
			snd->release();
			throw;
		}
		snd->set_autoclose();
		return snd;
	}
	mixer *new_mixer() override { return ::new_mixer(this); }
	sound *new_sound() override {
		sound *s = ::new_sound(this);
		if (s && this == g_audio_engine) { // The default engine's sounds go on sound_default_mixer, as those of sound() do; play() moves them to a mixer it is given.
			if (mixer* mix = acquire_default_mixer()) {
				s->set_mixer(mix);
				mix->release();
			}
		}
		return s;
	}
};
class audio_data_source_impl;
audio_data_source* audio_data_source_get(ma_data_source* ptr, audio_engine* engine);
// The next source for one linked to itself, which MiniAudio is given as its next callback rather than as a link to itself: the source again, unless its last pass read no frames, when the chain ends. MiniAudio moves on through a link and seeks the next source to its start without checking that a pass read anything, so a source linked to itself that gave no frames, empty or emptied by its range, held whatever read it in a loop for good: a device's audio thread, with every sound of that engine, and a sound's close() waiting on it.
static bool decoder_finished(ma_data_source* source); // See held_decoder_seek().
static ma_data_source* next_of_self_linked(ma_data_source* source) {
	ma_uint64 cursor = 0;
	if (decoder_finished(source)) return nullptr; // Read to its end, it can't seek back to its start.
	return ma_data_source_get_cursor_in_pcm_frames(source, &cursor) == MA_SUCCESS && !cursor? nullptr : source;
}
// The source after source in its chain: itself for one linked to itself.
static ma_data_source* next_in_chain(ma_data_source* source) { return ma_data_source_get_next_callback(source) == next_of_self_linked? source : ma_data_source_get_next(source); }
static ma_result seek_or_keep_place(ma_data_source* source, ma_uint64 frame); // See held_file.
class audio_data_source_impl : public audio_node_impl, public virtual audio_data_source {
	unique_ptr<ma_data_source_node> src;
	audio_data_source* src_cur;
	audio_data_source* src_next;
protected:
	std::atomic<int> users{0}; // Sounds playing this source, sources chaining to it and heads on it (see hold_current()), which read its MiniAudio data source directly, so close() and open() mustn't free it under them.
	std::atomic<bool> sound_owned{false}; // The source of a sound, wrapped for sound.datasource, which that sound plays at any time and frees when it closes.
	audio_data_source* held_current = nullptr; // Under held_mutex, see hold_current().
	std::mutex held_mutex;
	// Whether this source's own node is in the graph, whose audio thread then reads the source.
	bool node_attached() const {
		if (!node) return false;
		std::lock_guard<std::recursive_mutex> graph_lock(g_node_graph_mutex); // As attachments change under it.
		for (audio_node *n : output_connections) if (n) return true;
		return false;
	}
	// A sound playing this source, a chain including it, a head on it or the graph through its node reads it on the audio thread or through that chain, and MiniAudio's data sources can't be read, sought or relinked from two places at once; a sound's own source can be played at any time. Calls that do so are refused then. read() takes the node off the graph instead, so it leaves that out.
	bool in_use(bool count_node = true) const {
		if (!users && !sound_owned && !(count_node && node_attached())) return false;
		g_soundsystem_last_error = MA_INVALID_OPERATION;
		return true;
	}
	// Lets go of a reference this object held to a source it used, after handing the source to any head now on it.
	static void let_go(audio_data_source* source) {
		remove_user(source);
		hand_over_to_heads(source);
		source->release();
	}
	// A head reading through a chain moves its MiniAudio current source along the chain, which no link holds once it is let go of. Any head now on the source being let go of takes a reference to it, so it reads on to that source's end rather than reading freed memory, and the source can't be closed meanwhile.
	static void hand_over_to_heads(audio_data_source* source) {
		ma_data_source *target = source->get_ma_data_source();
		if (!target) return;
		std::vector<audio_data_source_impl*> heads;
		{
			std::lock_guard<std::mutex> lock(g_data_sources_map_mutex);
			for (auto &entry : g_data_sources_map) {
				if (entry.second == source || ma_data_source_get_current(entry.first) != target) continue;
				auto head = dynamic_cast<audio_data_source_impl*>(entry.second);
				if (head && head->duplicate_if_alive()) heads.push_back(head);
			}
		}
		for (audio_data_source_impl *head : heads) {
			head->hold_current(source);
			head->release();
		}
	}
	void hold_current(audio_data_source* source) {
		audio_data_source *previous;
		{
			std::lock_guard<std::mutex> lock(held_mutex);
			if (held_current == source) return;
			source->duplicate();
			add_user(source);
			previous = held_current;
			held_current = source;
		}
		if (previous) let_go(previous); // Not under held_mutex: letting go can free that source, whose own links are then handed over.
	}
	// One script thread may be reading from or closing this object while another opens it (a shared decoder handle, or a wrapper destroyed by its owner mid-read). The members below are unique_ptrs that get reset on close, so those paths must not interleave. Recursive because open() re-enters close(), and set_ma_data_source() re-enters reset().
	mutable std::recursive_mutex source_mutex;
	bool set_ma_data_source(ma_data_source* new_src) {
		std::lock_guard<std::recursive_mutex> guard(source_mutex);
		reset();
		if (!new_src) return true;
		src = make_unique<ma_data_source_node>();
		ma_format format;
		ma_data_source_get_data_format(new_src, &format, nullptr, nullptr, nullptr, 0);
		ma_data_source_node_config cfg = ma_data_source_node_config_init(new_src);
		if (format != ma_format_f32) {
			// Node doesn't provide samples in floatingpoint, we can still get and set info on it but can't read it or turn it into a node without a bit of extra work that is yet to be done.
			src->pDataSource = new_src; // Note that all other members of src are null/uninitialized, that's fine so long as continuing awareness of the possibility is maintained.
		} else if ((g_soundsystem_last_error = ma_data_source_node_init((ma_node_graph*)get_engine()->get_ma_engine(), &cfg, nullptr, &*src)) != MA_SUCCESS) {
			reset();
			return false;
		}
		if (format == ma_format_f32) node = (ma_node_base*)&*src;
		{
			std::lock_guard<std::mutex> lock(g_data_sources_map_mutex);
			g_data_sources_map[new_src] = this;
		}
		return true;
	}
	void reset() {
		std::lock_guard<std::recursive_mutex> guard(source_mutex);
		if (src) {
			{
				std::lock_guard<std::mutex> lock(g_data_sources_map_mutex);
				auto it = g_data_sources_map.find(src->pDataSource);
				if (it != g_data_sources_map.end() && it->second == this) g_data_sources_map.erase(it);
			}
			std::vector<audio_node*> attached;
			{
				std::lock_guard<std::recursive_mutex> graph_lock(g_node_graph_mutex);
				if (node) {
					ma_data_source_node_uninit(&*src, nullptr);
					drop_rate_bridges();
				}
				attached.swap(output_connections); // Under the graph lock, as attachments are changed and followed under it (see audio_node_impl::reaches_node()); what they held is let go of after it, as it can be the last reference.
			}
			node = nullptr;
			// Uninitializing the node took it off the graph, so what it was attached to is no longer held either; a node made for a source opened later starts unattached.
			for (audio_node* n : attached) if (n) n->release();
			src.reset();
		}
		if (src_cur) let_go(src_cur);
		if (src_next) let_go(src_next);
		src_cur = src_next = nullptr;
		audio_data_source *held;
		{
			std::lock_guard<std::mutex> lock(held_mutex);
			held = held_current;
			held_current = nullptr;
		}
		if (held) let_go(held);
	}
public:
	audio_data_source_impl(audio_engine* e, ma_data_source* initial_src = nullptr) : audio_node_impl(nullptr, e), src_cur(nullptr), src_next(nullptr), src(nullptr) { if (initial_src) set_ma_data_source(initial_src); }
	~audio_data_source_impl() { reset(); }
	static void add_user(audio_data_source* ds) {
		if (auto impl = dynamic_cast<audio_data_source_impl*>(ds)) impl->users++;
	}
	static void remove_user(audio_data_source* ds) {
		if (auto impl = dynamic_cast<audio_data_source_impl*>(ds)) impl->users--;
	}
	// Lets go of the MiniAudio data source wrapped, for a wrapper of a sound's own source when the sound frees it; the wrapper stays, empty.
	void forget_source() { set_ma_data_source(nullptr); }
protected:
	// MiniAudio's length of the source: its range's when the range has an end, else the whole source's, the range's start included; 0 when unknown.
	unsigned long long ma_length() const {
		ma_uint64 length;
		return (g_soundsystem_last_error = ma_data_source_get_length_in_pcm_frames(get_ma_data_source(), &length)) == MA_SUCCESS? length : 0;
	}
	// The part of a source whole frames long, 0 when unknown, within its range. MiniAudio counts a range without an end as the whole source, its start included, and one ending past the source's end as reaching past it, so the length, and the seeks and chains it bounds, went past what plays.
	unsigned long long within_range(unsigned long long whole) const {
		ma_uint64 begin = 0, end = 0;
		ma_data_source_get_range_in_pcm_frames(get_ma_data_source(), &begin, &end);
		if (!whole) return end != ~(ma_uint64)0 && end > begin? end - begin : 0; // Unknown: the range's own, as MiniAudio counts it.
		if (end > whole) end = whole;
		return end > begin? end - begin : 0;
	}
public:
	void mark_sound_owned() { sound_owned = true; }
	// A reference, unless the last one is already gone and this wrapper is being destroyed on another thread, before its destructor took it out of g_data_sources_map; a plain duplicate() would bring it back for a second destruction.
	bool duplicate_if_alive() {
		for (int count = refcount; count > 0;) {
			#ifdef _MSC_VER
			int seen = _InterlockedCompareExchange(reinterpret_cast<volatile long*>(&refcount), count + 1, count);
			#else
			int seen = __sync_val_compare_and_swap(&refcount, count, count + 1);
			#endif
			if (seen == count) return true;
			count = seen;
		}
		return false;
	}
	static bool is_sound_owned(audio_data_source* ds) {
		auto impl = dynamic_cast<audio_data_source_impl*>(ds);
		return impl && impl->sound_owned;
	}
	// Whether another sound, chain link, head or the graph already reads the source, so a second reader would read it alongside.
	static bool is_used(audio_data_source* ds) {
		auto impl = dynamic_cast<audio_data_source_impl*>(ds);
		return impl && (impl->users > 0 || impl->node_attached());
	}
	unsigned int output_sample_rate() const override { return get_sample_rate(); } // The source's frames as they are, which a graph of another rate takes through a group that resamples them (see audio_node_impl::attach_output_bus()).
	// The graph's audio thread reads the source once its node is attached, so not while a sound, chain or head reads it, nor a sound's own source.
	bool attach_output_bus(unsigned int output_bus, audio_node *destination, unsigned int destination_input_bus) override {
		if (in_use(false)) return false;
		prepare_length();
		return audio_node_impl::attach_output_bus(output_bus, destination, destination_input_bus);
	}
	ma_data_source* get_ma_data_source() const override { return src? src->pDataSource : nullptr; }
	unsigned int get_advised_read_frame_count() const override { return SOUNDSYSTEM_FRAMESIZE; }
	// Frames a reader was asked to drop, which this thread, reading the source itself, drops first; see audio_ring_buffer_impl.
	virtual void drop_pending_frames() {}
	// Works out, while nothing else reads the source yet, what a later read of its length needs; see audio_decoder_impl. Called as a sound, a chain or the graph starts reading it.
	virtual void prepare_length() {}
	static void prepare_length_of(audio_data_source* ds) {
		if (auto impl = dynamic_cast<audio_data_source_impl*>(ds)) impl->prepare_length();
	}
	// How many of frame_count frames the script's own read or skip takes: all of them, except from a ring buffer, which has only what is queued.
	virtual unsigned long long frames_to_take(unsigned long long frame_count) { return frame_count; }
	// Under source_mutex: takes the source's own node off the graph, so that this thread is the only reader, and drops what it is to drop. False when the source can't be read here now.
	bool ready_to_read() {
		if (!src || in_use(false) || node && !detach_all_output_buses()) return false; // A source in another format was never made a node.
		drop_pending_frames();
		return true;
	}
	// Reads frame_count frames of frame_size bytes into buffer, adding to frames_read. MiniAudio ends a read of a looping source after it met the source's end twice with nothing read between, as a source shorter than half the read does, though the source would go on: a looping decoder of 1000 frames gave 2000 of 4096, then 1000 a read. So a looping source is read again for the rest while each read gives frames.
	void read_whole(void* buffer, ma_uint64 frame_count, ma_uint32 frame_size, ma_uint64& frames_read) {
		bool looping = ma_data_source_is_looping(src->pDataSource);
		do {
			ma_uint64 got = 0;
			g_soundsystem_last_error = ma_data_source_read_pcm_frames(src->pDataSource, (char*)buffer + frames_read * frame_size, frame_count - frames_read, &got);
			frames_read += got;
			if (!got) break;
		} while (looping && g_soundsystem_last_error == MA_SUCCESS && frames_read < frame_count);
	}
	// Reads 32-bit float samples into buffer, as read_script() makes them.
	unsigned long long read(void* buffer, unsigned long long frame_count) override {
		std::lock_guard<std::recursive_mutex> guard(source_mutex);
		if (!ready_to_read()) return 0;
		if (!frame_count) frame_count = get_advised_read_frame_count();
		if (!(frame_count = frames_to_take(frame_count))) return 0;
		ma_format format = ma_format_f32;
		ma_uint32 channels = 0;
		ma_data_source_get_data_format(src->pDataSource, &format, &channels, nullptr, nullptr, 0);
		// The frames read are returned even with an error, which g_soundsystem_last_error keeps: MiniAudio reports one with the frames it read before it, as when a chain's next source refuses to be sought to its start.
		ma_uint64 frames_read = 0;
		if (format == ma_format_f32) {
			read_whole(buffer, frame_count, ma_get_bytes_per_frame(format, channels), frames_read);
			return frames_read;
		}
		// Another format, such as a 16-bit file the resource manager keeps as it is, is read as it is and converted.
		std::vector<char> raw(frame_count * ma_get_bytes_per_frame(format, channels));
		read_whole(raw.data(), frame_count, ma_get_bytes_per_frame(format, channels), frames_read);
		ma_pcm_convert(buffer, ma_format_f32, raw.data(), format, frames_read * channels, ma_dither_mode_none);
		return frames_read;
	}
	CScriptArray* read_script(unsigned long long frame_count) override {
		std::lock_guard<std::recursive_mutex> guard(source_mutex);
		unsigned int channels = get_channels(); // Asked once, before the read: asking reads the source's format, which sets the error the read or a refusal to read set.
		if (!frame_count && ready_to_read()) frame_count = get_advised_read_frame_count(); // Counted once what was to be dropped is gone, which an advised count leaves out.
		if (channels && frame_count > 0xFFFFFFFF / channels) throw runtime_error("too many frames requested");
		CScriptArray* array = CScriptArray::Create(get_array_type("array<float>"), frame_count * channels);
		asIScriptContext* ctx = asGetActiveContext();
		if (ctx && ctx->GetState() == asEXECUTION_EXCEPTION) {
			array->Release();
			return nullptr;
		}
		if (!frame_count) return array;
		unsigned long long frames_read = read(array->GetBuffer(), frame_count);
		array->Resize(frames_read * channels);
		return array;
	}
	// Skips by reading into a scratch buffer: MiniAudio's seek by a frame count reads too, but once it reaches the source's end it reports no frames skipped, though the source moved there.
	unsigned long long skip_by_reading(unsigned long long frame_count) {
		ma_format format = ma_format_unknown;
		ma_uint32 channels = 0;
		if ((g_soundsystem_last_error = ma_data_source_get_data_format(src->pDataSource, &format, &channels, nullptr, nullptr, 0)) != MA_SUCCESS) return 0;
		ma_uint32 frame_size = ma_get_bytes_per_frame(format, channels);
		if (!frame_size) return 0;
		const ma_uint64 chunk_frames = 4096;
		std::vector<char> scratch(chunk_frames * frame_size);
		unsigned long long skipped = 0;
		bool looping = ma_data_source_is_looping(src->pDataSource);
		while (skipped < frame_count) {
			ma_uint64 chunk = std::min<unsigned long long>(frame_count - skipped, chunk_frames), got = 0;
			g_soundsystem_last_error = ma_data_source_read_pcm_frames(src->pDataSource, scratch.data(), chunk, &got);
			skipped += got;
			if (g_soundsystem_last_error != MA_SUCCESS || got < chunk && !(looping && got)) break; // At the end, MA_AT_END tells it; a looping source cut short is read on, as by read_whole().
		}
		return skipped;
	}
	unsigned long long skip_frames(unsigned long long frame_count) override {
		if (!src || in_use()) return 0;
		drop_pending_frames(); // As read() does: the script is the only reader here.
		return skip_by_reading(frames_to_take(frame_count));
	}
	float skip_milliseconds(float ms) override {
		if (!src || in_use()) return 0;
		ma_uint32 sample_rate = 0;
		if ((g_soundsystem_last_error = ma_data_source_get_data_format(src->pDataSource, nullptr, nullptr, &sample_rate, nullptr, 0)) != MA_SUCCESS || !sample_rate) return 0;
		if (!(ms > 0 && ms <= FLT_MAX)) return 0; // Nothing to skip, or NaN or infinite, whose frame count no integer holds.
		drop_pending_frames();
		double frames = (double)ms / 1000 * sample_rate;
		return skip_by_reading(frames_to_take(frames < 9e18? (unsigned long long)frames : 9000000000000000000ULL)) * 1000.0f / sample_rate;
	}
	bool seek_frames(unsigned long long frame_index) override {
		if (!src || in_use()) return false;
		unsigned long long length = get_length_frames(); // 0 when unknown, as for a ring buffer or a stream that can't seek.
		if (length && frame_index > length) { // As sound.seek(): MiniAudio's decoders take such a seek and then read nothing.
			g_soundsystem_last_error = MA_INVALID_ARGS;
			return false;
		}
		return (g_soundsystem_last_error = seek_or_keep_place(src->pDataSource, frame_index)) == MA_SUCCESS;
	}
	bool seek_milliseconds(float ms) override {
		if (!src || in_use()) return false;
		if (!(ms >= 0 && ms <= FLT_MAX)) { // Negative, infinite or not a number: MiniAudio turns it into a frame index near 2^64, or one no integer holds.
			g_soundsystem_last_error = MA_INVALID_ARGS;
			return false;
		}
		ma_uint32 sample_rate = 0;
		if ((g_soundsystem_last_error = ma_data_source_get_data_format(src->pDataSource, nullptr, nullptr, &sample_rate, nullptr, 0)) != MA_SUCCESS || !sample_rate) return false;
		double frames = (double)ms / 1000 * sample_rate; // As MiniAudio's seek to a second counts it, in double so that a huge time can't overflow.
		if (frames >= 9e18) {
			g_soundsystem_last_error = MA_INVALID_ARGS;
			return false;
		}
		return seek_frames((unsigned long long)frames);
	}
	unsigned long long get_cursor_frames() const override {
		ma_uint64 cursor;
		if (!src) return 0;
		return (g_soundsystem_last_error = ma_data_source_get_cursor_in_pcm_frames(src->pDataSource, &cursor)) == MA_SUCCESS? cursor : 0;
	}
	float get_cursor_milliseconds() const override {
		float cursor;
		if (!src) return 0;
		return (g_soundsystem_last_error = ma_data_source_get_cursor_in_seconds(src->pDataSource, &cursor)) == MA_SUCCESS? cursor * 1000 : 0;
	}
	unsigned long long get_length_frames() const override {
		if (!src) return 0;
		ma_length(); // For its error, a source with no length at all reading none.
		if (g_soundsystem_last_error != MA_SUCCESS) return 0;
		return within_range(audio_data_source_impl::whole_length_frames()); // Unknown whole, as a ring buffer's: the range's own, as MiniAudio counts it, rather than the range's length taken for the whole and cut by its start again.
	}
	// The whole source's length, whatever its range, 0 when unknown or empty. A chain counts a source's length within its range only when the whole is known (see chain_source()).
	virtual unsigned long long whole_length_frames() const {
		if (!src) return 0;
		ma_data_source_base* base = (ma_data_source_base*)src->pDataSource;
		ma_uint64 whole = 0;
		return base->vtable->onGetLength && base->vtable->onGetLength(src->pDataSource, &whole) == MA_SUCCESS? whole : 0;
	}
	float get_length_milliseconds() const override {
		ma_uint32 sample_rate = 0;
		if (!src || (g_soundsystem_last_error = ma_data_source_get_data_format(src->pDataSource, nullptr, nullptr, &sample_rate, nullptr, 0)) != MA_SUCCESS || !sample_rate) return 0;
		return get_length_frames() * 1000.0f / sample_rate; // As counted within the range.
	}
	bool set_looping(bool looping) override { return src && !in_use()? (g_soundsystem_last_error = ma_data_source_set_looping(src->pDataSource, looping)) == MA_SUCCESS : false; }
	bool get_looping() const override { return src? ma_data_source_is_looping(src->pDataSource) : false; }
	bool set_range(unsigned long long start_frame, unsigned long long end_frame) override { return src && !in_use()? (g_soundsystem_last_error = ma_data_source_set_range_in_pcm_frames(src->pDataSource, start_frame, end_frame)) == MA_SUCCESS : false; }
	// Without a source, 0 for both, as AngelScript leaves &out values unset.
	void get_range(unsigned long long* start_frame, unsigned long long* end_frame) const override {
		*start_frame = *end_frame = 0;
		if (src) ma_data_source_get_range_in_pcm_frames(src->pDataSource, start_frame, end_frame);
	}
	bool set_loop_point(unsigned long long start_frame, unsigned long long end_frame) override { return src && !in_use()? (g_soundsystem_last_error = ma_data_source_set_loop_point_in_pcm_frames(src->pDataSource, start_frame, end_frame)) == MA_SUCCESS : false; }
	void get_loop_point(unsigned long long* start_frame, unsigned long long* end_frame) const override {
		*start_frame = *end_frame = 0;
		if (src) ma_data_source_get_loop_point_in_pcm_frames(src->pDataSource, start_frame, end_frame);
	}
	// A queue that something else fills as it is read, as a ring buffer or microphone, rather than a source with a start.
	virtual bool is_live_queue() const { return false; }
	// A source chained to this one is read into buffers sized for this one's format and channel count, by the audio thread and by read(), and is played at this one's sample rate, so it must match in all three.
	// Nor a live queue: moving on to the next source seeks it to its start, which a queue has none of, and a queue pads every read with silence, which a script reading the chain would get as frames read.
	bool can_chain(audio_data_source* other) const {
		if (auto impl = dynamic_cast<audio_data_source_impl*>(other); impl && impl->is_live_queue()) return false;
		ma_data_source *theirs = other->get_ma_data_source();
		ma_format format, their_format;
		ma_uint32 channels, their_channels, sample_rate, their_sample_rate;
		if (!theirs || ma_data_source_get_data_format(src->pDataSource, &format, &channels, &sample_rate, nullptr, 0) != MA_SUCCESS || ma_data_source_get_data_format(theirs, &their_format, &their_channels, &their_sample_rate, nullptr, 0) != MA_SUCCESS) return false;
		return format == their_format && channels == their_channels && sample_rate == their_sample_rate;
	}
	bool set_current(audio_data_source* new_current) override {
		if (!src || in_use()) return false;
		bool self = new_current == static_cast<audio_data_source*>(this); // Back to this head, as a chain is rewound in MiniAudio. Nothing needs holding for that, and a reference to itself would keep this alive and in use for good.
		if (new_current && !self && is_live_queue()) { // Nor a head, as for can_chain(): a queue never ends, so it never moves on, and its reads are capped at what it has queued, not what another source holds.
			g_soundsystem_last_error = MA_INVALID_ARGS;
			return false;
		}
		if (new_current && !self && new_current != src_cur && new_current != src_next && new_current != held_current && (!can_chain(new_current) || is_sound_owned(new_current) || is_used(new_current))) { // A sound frees its own source when it closes, whatever else reads it, and one already read elsewhere would be read from two places.
			g_soundsystem_last_error = MA_INVALID_ARGS;
			return false;
		}
		if (new_current && !self) prepare_length_of(new_current);
		if ((g_soundsystem_last_error = ma_data_source_set_current(src->pDataSource, new_current? new_current->get_ma_data_source() : nullptr)) != MA_SUCCESS) return false;
		if (src_cur) let_go(src_cur);
		audio_data_source *held; // This head is on new_current now, off a source it was holding.
		{
			std::lock_guard<std::mutex> lock(held_mutex);
			held = held_current;
			held_current = nullptr;
		}
		if (held) let_go(held);
		src_cur = self? nullptr : new_current;
		if (src_cur) {
			src_cur->duplicate();
			add_user(src_cur);
		}
		return true;
	}
	// The source MiniAudio is on, which reading moves along the chain past one set_current() gave.
	audio_data_source* get_current() const override { return src? audio_data_source_get(ma_data_source_get_current(src->pDataSource), get_engine()) : nullptr; }
	bool set_next(audio_data_source* new_next) override {
		if (!src || in_use()) return false;
		bool self = new_next == static_cast<audio_data_source*>(this); // Looping this source on itself; as for set_current(), without a reference to itself.
		if (new_next && !self && is_live_queue()) { // As set_current() refuses.
			g_soundsystem_last_error = MA_INVALID_ARGS;
			return false;
		}
		if (new_next && !self && new_next != src_next && new_next != src_cur && new_next != held_current && (!can_chain(new_next) || is_sound_owned(new_next) || is_used(new_next))) {
			g_soundsystem_last_error = MA_INVALID_ARGS;
			return false;
		}
		if (new_next && !self) prepare_length_of(new_next);
		if ((g_soundsystem_last_error = ma_data_source_set_next(src->pDataSource, new_next && !self? new_next->get_ma_data_source() : nullptr)) != MA_SUCCESS) return false;
		ma_data_source_set_next_callback(src->pDataSource, self? next_of_self_linked : nullptr); // Linked to itself through the callback, which ends an empty loop.
		if (src_next) let_go(src_next);
		src_next = self? nullptr : new_next;
		if (src_next) {
			src_next->duplicate();
			add_user(src_next);
		}
		return true;
	}
	audio_data_source* get_next() const override {
		if (src_next) {
			src_next->duplicate();
			return src_next;
		}
		if (src && ma_data_source_get_next_callback(src->pDataSource) == next_of_self_linked) { // Linked to itself (see set_next()).
			audio_data_source_impl* self = const_cast<audio_data_source_impl*>(this);
			self->duplicate();
			return self;
		}
		return src? audio_data_source_get(ma_data_source_get_next(src->pDataSource), get_engine()) : nullptr;
	}
	bool get_data_format(ma_format *format, unsigned int *channels, unsigned int *sample_rate) const override {
		if (format) *format = ma_format_unknown; // As MiniAudio sets them when it fails, for a source there isn't.
		if (channels) *channels = 0;
		if (sample_rate) *sample_rate = 0;
		return src? (g_soundsystem_last_error = ma_data_source_get_data_format(src->pDataSource, format, channels, sample_rate, nullptr, 0)) == MA_SUCCESS : false;
	}
	unsigned int get_channels() const override {
		unsigned int channels;
		return get_data_format(nullptr, &channels, nullptr)? channels : 0;
	}
	unsigned int get_sample_rate() const override {
		unsigned int sample_rate;
		return get_data_format(nullptr, nullptr, &sample_rate)? sample_rate : 0;
	}
	bool get_active() const override { return src != nullptr; }
};
audio_data_source* audio_data_source_get(ma_data_source* ptr, audio_engine* engine) {
	if (!ptr) return nullptr; // Without an engine, the node takes the default one, see audio_node_impl.
	{
		// The reference is taken while still holding the lock, so a concurrent reset() cannot erase and free the wrapper between our lookup and our duplicate().
		std::lock_guard<std::mutex> lock(g_data_sources_map_mutex);
		auto it = g_data_sources_map.find(ptr);
		if (it != g_data_sources_map.end()) {
			auto impl = dynamic_cast<audio_data_source_impl*>(it->second);
			if (impl && !impl->duplicate_if_alive()) return nullptr; // Being destroyed, along with what it wraps for a decoder, so not wrapped anew either.
			if (!impl) it->second->duplicate();
			return it->second;
		}
	}
	return new audio_data_source_impl(engine, ptr);
}
// A ring buffer that the audio thread reads as a data source, as a stream_pcm() sound's and a microphone's are. A ring buffer has one writer and one reader, so dropping what is queued, as starting such a sound or microphone again does, is left to the reader: discard() has the next read skip what is queued now. Resetting the ring buffer from the script's thread moved its positions under the audio thread's read, which then played old frames again.
struct pcm_queue {
	ma_data_source_base base; // First: MiniAudio passes this struct as the data source.
	ma_pcm_rb rb;
	// Frames written into the ring buffer and read out of it since it began, and the frame up to which the reader drops what it reads: a discard is a position rather than a count of what is queued, which, taken while the reader was copying frames out, as MiniAudio's ring buffer copies before it commits the read, still held those, so that the next read dropped as many frames written after the discard.
	std::atomic<ma_uint64> written{0}, taken{0}, discard_to{0};
	ma_result init(ma_format format, ma_uint32 channels, ma_uint32 frames) {
		ma_result result = ma_pcm_rb_init(format, channels, frames, nullptr, nullptr, &rb);
		if (result != MA_SUCCESS) return result;
		ma_data_source_config config = ma_data_source_config_init();
		config.vtable = &vtable;
		if ((result = ma_data_source_init(&config, &base)) != MA_SUCCESS) ma_pcm_rb_uninit(&rb);
		return result;
	}
	void uninit() {
		ma_data_source_uninit(&base);
		ma_pcm_rb_uninit(&rb);
	}
	// By the writer, or with it held off: what was written so far goes.
	void discard() { discard_to.store(written.load()); }
	// By the writer, once frames are committed.
	void wrote(ma_uint32 frames) { written += frames; }
	// With neither the writer nor the reader at it, once the ring buffer was reset: nothing queued, nothing to drop.
	void emptied() { taken.store(written.load()); }
	ma_uint64 pending_discard() {
		ma_uint64 to = discard_to.load(), done = taken.load();
		return to > done? to - done : 0;
	}
	// What a read can still get: what is queued, less what the next read drops.
	ma_uint32 readable() {
		ma_uint32 available = ma_pcm_rb_available_read(&rb);
		ma_uint64 skipping = pending_discard();
		return available > skipping? available - (ma_uint32)skipping : 0;
	}
	// By the reader only.
	void drop_pending() {
		if (ma_uint64 n = pending_discard()) {
			ma_uint32 available = ma_pcm_rb_available_read(&rb), dropped = n < available? (ma_uint32)n : available;
			ma_pcm_rb_seek_read(&rb, dropped);
			taken += dropped;
		}
	}
	// As MiniAudio's ring buffer reads as a data source, padding with silence what isn't queued, as a reader in the graph needs so that a sound doesn't end at a buffer empty for a moment, but counting the frames it took.
	static ma_result on_read(ma_data_source* ds, void* frames_out, ma_uint64 frame_count, ma_uint64* frames_read) {
		pcm_queue* queue = (pcm_queue*)ds;
		queue->drop_pending();
		ma_format format = queue->rb.format;
		ma_uint32 channels = queue->rb.channels;
		ma_uint64 total = 0;
		while (total < frame_count) {
			ma_uint32 frames = (ma_uint32)std::min<ma_uint64>(frame_count - total, 0xFFFFFFFF);
			void* mapped = nullptr;
			if (ma_pcm_rb_acquire_read(&queue->rb, &frames, &mapped) != MA_SUCCESS || !frames) break;
			if (frames_out) ma_copy_pcm_frames(ma_offset_pcm_frames_ptr(frames_out, total, format, channels), mapped, frames, format, channels);
			if (ma_pcm_rb_commit_read(&queue->rb, frames) != MA_SUCCESS) break;
			queue->taken += frames;
			total += frames;
		}
		if (frames_out && total < frame_count) ma_silence_pcm_frames(ma_offset_pcm_frames_ptr(frames_out, total, format, channels), frame_count - total, format, channels);
		if (frames_read) *frames_read = frame_count;
		return MA_SUCCESS;
	}
	static ma_result on_get_data_format(ma_data_source* ds, ma_format* format, ma_uint32* channels, ma_uint32* sample_rate, ma_channel* channel_map, size_t channel_map_cap) {
		return ma_data_source_get_data_format(&((pcm_queue*)ds)->rb, format, channels, sample_rate, channel_map, channel_map_cap);
	}
	static inline ma_data_source_vtable vtable = {on_read, nullptr, on_get_data_format, nullptr, nullptr, nullptr, 0};
};
class audio_ring_buffer_impl : public audio_data_source_impl, public virtual audio_ring_buffer {
	unique_ptr<pcm_queue> queue;
	ma_pcm_rb *rb = nullptr; // The queue's.
protected:
	void discard_queued() { if (queue) queue->discard(); }
	void drop_pending_frames() override { if (queue) queue->drop_pending(); }
	bool is_live_queue() const override { return true; }
	// The script's reads and skips take only what is queued: the ring buffer's data source pads a read with silence, which the graph's reader needs so that a sound doesn't end at a buffer empty for a moment, but which a script's read(n) returned as n frames read, as if they had been written.
	unsigned long long frames_to_take(unsigned long long frame_count) override { return queue? std::min<unsigned long long>(frame_count, queue->readable()) : 0; }
public:
	audio_ring_buffer_impl(unsigned int channels, unsigned int size, audio_engine * e) : audio_data_source_impl(e, nullptr), queue(make_unique<pcm_queue>()) {
		if (channels > MA_MAX_CHANNELS) throw runtime_error(Poco::format("exceeded maximum channel count of %d", MA_MAX_CHANNELS)); // A node's channel count is kept in 8 bits, as for an engine.
		if (queue->init(ma_format_f32, channels, size) != MA_SUCCESS) throw std::runtime_error("failed to initialize ring buffer");
		rb = &queue->rb;
		ma_pcm_rb_set_sample_rate(rb, get_engine()->get_sample_rate()); // Frames are written at the engine's rate, as the microphone records them; MiniAudio leaves it 0.
		set_ma_data_source((ma_data_source*)&queue->base);
	}
	~audio_ring_buffer_impl() {
		audio_data_source_impl::reset(); // Qualified: audio_ring_buffer_impl::reset() below overrides a different (ring-buffer-clearing) virtual and would otherwise hide this one.
		if (rb) queue->uninit();
	}
	void reset() override {
		if (!rb) return;
		// While the graph, a sound or a chain reads it on the audio thread, what is queued is dropped by that reader (see pcm_queue): resetting the ring buffer under it had it play old frames again. Either way get_available_read() reads 0 at once and what is written after this is kept.
		if (is_used(this)) {
			queue->discard();
			return;
		}
		ma_pcm_rb_reset(&*rb);
		queue->emptied(); // What was queued is gone already; skipping it later would drop frames written after this.
	}
	unsigned int get_advised_read_frame_count() const override { return get_available_read(); }
	unsigned int write(const float* frames_in, unsigned int frame_count) override {
		if (!rb) return 0;
		// ma_pcm_rb_acquire_write only returns the CONTIGUOUS free region up to the end of the
		// backing buffer; near the wrap point that region is smaller than the total free space.
		// The old single-shot code silently dropped whatever didn't fit in that first region,
		// which for the microphone meant a chunk of samples lost at every ring wrap (measured
		// 2.6-6% of all captured audio depending on device timing, audible as periodic clicks
		// and a production rate below realtime in voice chat). Loop until everything is written
		// or the ring is genuinely full - same pattern stream_pcm below already uses.
		unsigned int total = 0;
		while (total < frame_count) {
			ma_uint32 chunk = frame_count - total;
			void* pWriteBuffer;
			if (ma_pcm_rb_acquire_write(&*rb, &chunk, &pWriteBuffer) != MA_SUCCESS) break;
			if (!chunk) break; // ring genuinely full
			ma_copy_pcm_frames(pWriteBuffer, frames_in + (size_t)total * rb->channels, chunk, rb->format, rb->channels);
			ma_pcm_rb_commit_write(&*rb, chunk);
			queue->wrote(chunk);
			total += chunk;
		}
		return total;
	}
	unsigned int write_script_array(CScriptArray *frames) override {
		if (!frames || !get_channels()) return 0;
		return write((float*)frames->GetBuffer(), frames->GetSize() / get_channels());
	}
	unsigned int write_script_memory_buffer(script_memory_buffer* frames) override {
		if (!frames || !get_channels()) return false;
		return write((float*)frames->ptr, frames->size / get_channels());
	}
	unsigned int get_available_read() const override { return rb? queue->readable() : 0; }
	unsigned int get_available_write() const override { return rb? ma_pcm_rb_available_write(&*rb) : 0; }
	unsigned int get_channels() const override { return rb? ma_pcm_rb_get_channels(&*rb) : 0; }
	unsigned int get_sample_rate() const override { return rb? ma_pcm_rb_get_sample_rate(&*rb) : 0; }
};
audio_ring_buffer* audio_ring_buffer::create(unsigned int channels, unsigned int size, audio_engine* e) { return new audio_ring_buffer_impl(channels, size, e); }
// MiniAudio's decoder reads a file of another rate through a resampler, NVGT's WDL one, with faults its data source functions are wrapped for in NVGT's decoders and streams (see hold_decoder()). The resampler gives what it holds at the input's end only on a second call without input, and MiniAudio's read makes one such call, returning no frames and its end if that gives none: a read starting where only those frames were left got none, ending a sound, a chain's link or a pass of a loop, or a script's reading, tens of frames early; such a read is made once more. Raising the channel count while resampling up, MiniAudio's converter resamples in chunks of its stack buffer, asking the resampler for the input each chunk needs, a count WDL's doesn't add up over chunks, and the decoder drops the input the converter didn't take, so that a read of more than a chunk lost frames of the file; reads are made in parts no larger than a chunk. A seek resets the resampler, and with it the counts its flush at the input's end is capped by (see wdl_resampler_set_counts()), so that they counted from the seek's frame and allowed a frame or two more than the decoder's length; the first read after a reset sets them to where the decoder is, on the thread that reads it, a stream's job thread too.
static ma_data_source_vtable g_held_decoder_vtable;
static ma_result (*g_ma_decoder_read)(ma_data_source*, void*, ma_uint64, ma_uint64*) = nullptr;
static ma_result (*g_ma_decoder_seek)(ma_data_source*, ma_uint64) = nullptr;
static constexpr ma_uint64 converter_chunk_bytes = 4096; // MiniAudio's MA_DATA_CONVERTER_STACK_BUFFER_SIZE, which its header doesn't give.
// MiniAudio skips a decoder's seek, the converter's reset with it, when the file's cursor is already where the frame maps to, which a resampler reading ahead leaves it at for one frame some tens of frames on, so that the read went on from where it was; a stream, which seeks its decoder with MiniAudio's own function on its job thread, then played on from earlier in its file and stopped short of its end. That cursor is read for nothing else, so a decoder's file is given functions of its own, which for a source that can seek give a cursor no frame maps to, and the decoder always seeks; the file's own cursor is kept for counting the resampling (see file_cursor()). Not for a source that can't seek, as a URL, which refuses every seek, even to where it is, which MiniAudio's skip made nothing of; a decoder of one, read to its end, can't seek back to its start or its loop's, which MiniAudio took for no end, so that a sound looping it or a chain played silence for good; it ends there instead (see held_decoder_seek()).
// A file whose header gives more frames than it holds, as a truncated FLAC or MP3, ended its decoder early, so that a looping stream wrapped its position at that length and its file before it, and refused a seek past what it holds though within that length, after which the decoder read on from where it was while a stream's position read the frame sought. Such a file now gives silence from its end, or from the frame of a seek it refused until it makes one, to the decoder's length, as a sound loaded whole plays the part of such a file that isn't there.
struct held_file {
	ma_data_source_vtable vtable; // First, as the file's base points to it, which leads back here.
	const ma_data_source_vtable* original;
	bool can_seek;
	std::atomic<ma_uint64> length{0}; // The decoder's, once known without reading it whole; 0 before.
	std::atomic<int> refused{MA_SUCCESS}; // The error of the last seek a file that can seek refused, until it makes one.
	std::atomic<bool> ended{false}; // The decoder's last read of its file gave nothing at its end.
	std::atomic<bool> finished{false}; // The decoder can't read on, nor its file seek back (see held_decoder_seek()), until a seek its file makes.
};
static thread_local bool t_script_seek = false; // A script's call is seeking, which is told when a file can't seek back rather than finishing its decoder (see held_decoder_seek()).
struct script_seek {
	bool was = t_script_seek;
	script_seek() { t_script_seek = true; }
	~script_seek() { t_script_seek = was; }
};
static ma_result held_file_seek(ma_data_source* backend, ma_uint64 frame);
static ma_result cursor_no_frame_maps_to(ma_data_source* source, ma_uint64* cursor) {
	*cursor = ~(ma_uint64)0;
	return MA_SUCCESS;
}
static held_file* file_held(ma_data_source* backend) {
	const ma_data_source_vtable* vtable = backend? ((ma_data_source_base*)backend)->vtable : nullptr;
	return vtable && vtable->onSeek == held_file_seek? const_cast<held_file*>(reinterpret_cast<const held_file*>(vtable)) : nullptr;
}
static ma_result held_file_seek(ma_data_source* backend, ma_uint64 frame) {
	held_file* file = file_held(backend);
	ma_result result = file->original->onSeek(backend, frame);
	if (result == MA_SUCCESS || !file->can_seek || !file->length.load()) {
		file->refused.store(MA_SUCCESS);
		return result;
	}
	file->refused.store(result);
	return MA_SUCCESS; // So that MiniAudio places the decoder's read point at the frame sought, from which held_decoder_read() gives silence.
}
// A decoder's file's own cursor.
static bool file_cursor(ma_data_source* backend, ma_uint64* cursor) {
	held_file* file = file_held(backend);
	const ma_data_source_vtable* vtable = file? file->original : ((ma_data_source_base*)backend)->vtable;
	return vtable->onGetCursor && vtable->onGetCursor(backend, cursor) == MA_SUCCESS;
}
// Sets the counts of a decoder's WDL resampler to where the decoder is, its file's cursor and its read point.
static void count_resampling_from_here(ma_decoder* decoder) {
	ma_uint64 cursor = 0;
	if (decoder->converter.hasResampler && decoder->converter.resampler.pBackendVTable == &wdl_resampler_backend_vtable && file_cursor(decoder->pBackend, &cursor)) wdl_resampler_set_counts(decoder->converter.resampler.pBackend, cursor, decoder->readPointerInPCMFrames);
}
// Whether a decoder can't read on from where it is: read to its end, or to its range's or, looping, its loop's.
static bool at_its_end(ma_decoder* decoder, held_file* file) {
	if (file->ended.load()) return true;
	ma_data_source_base* base = &decoder->ds;
	ma_uint64 end = base->rangeEndInFrames;
	if (ma_data_source_is_looping(decoder) && base->loopEndInFrames != ~(ma_uint64)0) end = std::min(end, base->rangeBegInFrames + base->loopEndInFrames);
	return end != ~(ma_uint64)0 && decoder->readPointerInPCMFrames >= end;
}
static ma_result held_decoder_read(ma_data_source* source, void* frames_out, ma_uint64 frame_count, ma_uint64* frames_read) {
	ma_decoder* decoder = (ma_decoder*)source;
	held_file* file = file_held(decoder->pBackend);
	if (file && file->finished.load()) {
		if (at_its_end(decoder, file)) {
			if (frames_read) *frames_read = 0;
			return MA_AT_END;
		}
		file->finished.store(false); // Its loop or range changed since, as by a script that turned its looping off, so that it reads on.
	}
	const ma_uint32 frame_size = ma_get_bytes_per_frame(decoder->outputFormat, decoder->outputChannels);
	ma_uint64 total = 0;
	ma_result result = MA_AT_END;
	if (!file || file->refused.load() == MA_SUCCESS) {
		if (decoder->converter.hasResampler && decoder->converter.resampler.pBackendVTable == &wdl_resampler_backend_vtable && wdl_resampler_take_reset(decoder->converter.resampler.pBackend)) count_resampling_from_here(decoder);
		const ma_uint64 part = std::max<ma_uint64>(1, converter_chunk_bytes / (sizeof(float) * std::max(decoder->outputChannels, decoder->converter.channelsIn)));
		result = MA_SUCCESS;
		bool again = false; // The read just made gave nothing at the end, and is being made once more.
		while (total < frame_count) {
			ma_uint64 got = 0;
			result = g_ma_decoder_read(source, frames_out? (ma_uint8*)frames_out + total * frame_size : nullptr, std::min(part, frame_count - total), &got);
			total += got;
			if (result != MA_SUCCESS && result != MA_AT_END) break; // Given with the frames got, as MiniAudio's read gives it.
			if (got) again = false;
			else if (result == MA_AT_END && !again) again = true;
			else break;
		}
	}
	if (file && result == MA_AT_END && total < frame_count) { // The file's end, or a seek it refused, short of the decoder's length; a file that can't seek is given its length only once worked out without consuming it (see get_length_frames()).
		const ma_uint64 length = file->length.load(), at = decoder->readPointerInPCMFrames;
		const ma_uint64 count = length > at? std::min(frame_count - total, length - at) : 0;
		if (frames_out && count) ma_silence_pcm_frames((ma_uint8*)frames_out + total * frame_size, count, decoder->outputFormat, decoder->outputChannels);
		decoder->readPointerInPCMFrames += count;
		total += count;
	}
	if (file) file->ended.store(!total && result == MA_AT_END);
	if (frames_read) *frames_read = total;
	return result != MA_SUCCESS && result != MA_AT_END? result : total? MA_SUCCESS : result;
}
// A decoder's file is sought here rather than by MiniAudio's seek, which resets the converter even when the file refuses the seek, dropping the input the resampler held, so that a script's decoder whose seek failed didn't read on from where it was. A file that can't seek isn't sought to where its cursor already is, as MiniAudio skips such a seek (see held_file), the converter then reset and the read point placed when the decoder isn't there.
// One a file that can't seek refuses, of a decoder that can't read on, as to its loop's start, to a chain's link's start or to that of a source linked to itself, finishes the decoder: it gives nothing until a seek its file makes, and the seek reports success, so that MiniAudio's loop, which ends once a pass gives nothing twice, ends there, as a chain does, rather than taking the error for no end, playing silence for good, and so that no end is given from a seek, which MiniAudio asserts against once frames were read. A finished decoder not looping, sought again without having given anything, as in a ring of links that all finished, gives the error, which ends MiniAudio's move through them. A script's call is told the error (see script_seek).
static ma_result held_decoder_seek(ma_data_source* source, ma_uint64 frame) {
	ma_decoder* decoder = (ma_decoder*)source;
	held_file* file = file_held(decoder->pBackend);
	ma_result result;
	if (!file) { // A file without a seek of its own, which MiniAudio's seek handles.
		result = g_ma_decoder_seek(source, frame);
		if (result == MA_SUCCESS && decoder->readPointerInPCMFrames != frame) {
			ma_data_converter_reset(&decoder->converter);
			decoder->readPointerInPCMFrames = frame;
		}
		return result;
	}
	ma_uint32 file_rate = 0;
	if ((result = ma_data_source_get_data_format(decoder->pBackend, nullptr, nullptr, &file_rate, nullptr, 0)) != MA_SUCCESS) return result;
	const ma_uint64 file_frame = file_rate == decoder->outputSampleRate? frame : wdl_frames_after_resampling(file_rate, decoder->outputSampleRate, frame);
	ma_uint64 cursor = 0;
	const bool there = !file->can_seek && file_cursor(decoder->pBackend, &cursor) && cursor == file_frame;
	result = there? MA_SUCCESS : ma_data_source_seek_to_pcm_frame(decoder->pBackend, file_frame);
	if (result == MA_SUCCESS && t_script_seek && file->refused.load() != MA_SUCCESS) return (ma_result)file->refused.exchange(MA_SUCCESS); // Refused by a file that can seek, which a script is told, the decoder reading on from where it was rather than giving silence from the frame (see held_file_seek()).
	if (result == MA_SUCCESS) {
		if (!there || decoder->readPointerInPCMFrames != frame) {
			ma_data_converter_reset(&decoder->converter);
			decoder->readPointerInPCMFrames = frame;
		}
		file->finished.store(false);
		file->ended.store(false);
		return result;
	}
	if (file->can_seek || t_script_seek || !at_its_end(decoder, file)) return result;
	if (file->finished.load() && !ma_data_source_is_looping(source)) return result;
	file->finished.store(true);
	return MA_SUCCESS;
}
static bool decoder_finished(ma_data_source* source) {
	if (!source || ((ma_data_source_base*)source)->vtable != &g_held_decoder_vtable) return false;
	held_file* file = file_held(((ma_decoder*)source)->pBackend);
	return file && file->finished.load();
}
// Seeks a source to its start for a chain about to play it again, telling whether it can be: not a decoder whose file can't seek back once read.
static ma_result start_again(ma_data_source* source) {
	if (((ma_data_source_base*)source)->vtable == &g_held_decoder_vtable) {
		ma_decoder* decoder = (ma_decoder*)source;
		held_file* file = file_held(decoder->pBackend);
		if (file && !file->can_seek && (decoder->readPointerInPCMFrames || file->finished.load())) {
			script_seek told;
			return ma_data_source_seek_to_pcm_frame(source, 0);
		}
	}
	return MA_SUCCESS;
}
// A seek a script makes of a source, which it is told failed when a decoder's file refused it, the decoder then reading on from where it was rather than giving silence from the frame sought, as after a sound's seek, which can't tell (see held_decoder_seek()).
static ma_result seek_or_keep_place(ma_data_source* source, ma_uint64 frame) {
	script_seek told;
	return ma_data_source_seek_to_pcm_frame(source, frame);
}
// Gives a decoder made the functions above, and its file its own (see held_file), with the decoder's length when known, before anything reads or seeks it. What it makes is freed by let_go_of_decoder() or uninit_resource_source().
static void hold_decoder(ma_decoder* decoder, bool can_seek, ma_uint64 length = 0) {
	static std::once_flag made;
	std::call_once(made, [decoder]() {
		g_held_decoder_vtable = *decoder->ds.vtable;
		g_ma_decoder_read = g_held_decoder_vtable.onRead;
		g_ma_decoder_seek = g_held_decoder_vtable.onSeek;
		g_held_decoder_vtable.onRead = held_decoder_read;
		g_held_decoder_vtable.onSeek = held_decoder_seek;
	});
	decoder->ds.vtable = &g_held_decoder_vtable;
	if (!decoder->pBackend || !((ma_data_source_base*)decoder->pBackend)->vtable->onSeek) return;
	ma_data_source_base* base = (ma_data_source_base*)decoder->pBackend;
	held_file* file = new held_file();
	file->original = base->vtable;
	file->vtable = *base->vtable;
	file->vtable.onSeek = held_file_seek;
	file->can_seek = can_seek;
	if (can_seek) file->vtable.onGetCursor = cursor_no_frame_maps_to;
	file->length.store(length);
	base->vtable = &file->vtable;
}
// The decoder's length once worked out (see held_file).
static void set_held_length(ma_decoder* decoder, ma_uint64 length) {
	held_file* file = file_held(decoder->pBackend);
	if (file) file->length.store(length);
}
// Uninitialises a decoder hold_decoder() was given, and then frees what it made, which the uninit still reads.
static ma_result let_go_of_decoder(ma_decoder* decoder) {
	held_file* file = file_held(decoder->pBackend);
	ma_result result = ma_decoder_uninit(decoder);
	if (result == MA_SUCCESS) delete file;
	return result;
}
// Uninitialises a resource manager source, and for a stream frees what hold_decoder() made for its decoder once that is uninitialised.
static void uninit_resource_source(ma_resource_manager_data_source* source) {
	held_file* file = (source->flags & MA_RESOURCE_MANAGER_DATA_SOURCE_FLAG_STREAM) && source->backend.stream.isDecoderInitialized? file_held(source->backend.stream.decoder.pBackend) : nullptr;
	ma_resource_manager_data_source_uninit(source);
	delete file;
}
class audio_decoder_impl : public audio_data_source_impl, public virtual audio_decoder {
	unique_ptr<ma_decoder> decoder;
	// The decoder's own length in frames once worked out, -1 before. Some formats count it by reading the whole file, as an MP3 without a header giving it does, from the start and back, which a read of the length while a sound or the graph read the decoder did at the same time, corrupting what was played or hanging the audio thread. So it is worked out only while nothing else reads the decoder, as a reader starts (prepare_length()) or when the script asks before then, and kept.
	mutable std::atomic<long long> length_frames{-1}; // -2 once known to be unknowable without consuming a stream that can't seek.
	// Whether the stream decoded can seek, which a file can. Counting the length of one that can't, as a live stream, by reading it to its end consumed it, as it couldn't seek back; so its length is asked for only within what the stream_cursor kept, which a format that knows it from a header answers, and is otherwise unknown.
	bool seekable = true;
	datastream* datastream_ref; // If the user opens a datastream, we must maintain a reference to it encase the user drops their handle.
	// Rewind window so a datastream that can't seek (a live socket) can still be probed and decoded; answers rewinds from memory instead of the stream until the window outgrows CAP or a real seek moves the stream.
	struct stream_cursor {
		static const size_t CAP = 256 * 1024;
		datastream* ds = nullptr;
		std::string window;      // every byte served so far, until CAP
		size_t pos = 0;          // logical read position, which is where the decoder believes it is
		bool window_full = false;   // hit CAP, so it no longer holds everything read
		bool window_moved = false;  // a real seek happened, so it no longer starts at byte 0
		std::streamoff base = 0;    // where the stream was when the decoder opened it, which the decoder's positions count from
		bool mirrors_stream() const { return !window_full && !window_moved; }
		// While the decoder's length is asked for on a stream that can't seek: only what the window holds is read or sought in, and anything past it is refused and noted, so a format that counts its length by reading to the end leaves the stream as it was rather than consuming it.
		bool length_query = false;
		bool length_query_refused = false;
	};
	// The cursor is handed to the decoder through a VFS rather than ma_decoder_init's raw read/seek pair, because that form leaves
	// the decoder's onTell null (ma_decoder_init passes NULL where ma_decoder_init_vfs passes ma_decoder__on_tell_vfs). The custom
	// vorbis/opus backends call tell while opening (dep/miniaudio_libvorbis.c), so without it only wav decodes from a datastream.
	struct ds_vfs_t { ma_vfs_callbacks cb; stream_cursor* sc; };
	unique_ptr<stream_cursor> cursor;
	unique_ptr<ds_vfs_t> ds_vfs;
	static ma_result vfs_read(ma_vfs*, ma_vfs_file f, void *pDst, size_t sizeInBytes, size_t *pBytesRead) {
		if (pBytesRead) *pBytesRead = 0;
		stream_cursor* sc = (stream_cursor*)f;
		if (!sc || !sc->ds) return MA_ERROR;
		istream* stream = sc->ds->get_istr();
		if (!stream) return MA_ERROR;
		char* out = static_cast<char*>(pDst);
		size_t total = 0;
		// Anything still inside the window is replayed from memory rather than pulled again.
		if (sc->mirrors_stream() && sc->pos < sc->window.size()) {
			size_t n = std::min(sc->window.size() - sc->pos, sizeInBytes);
			memcpy(out, sc->window.data() + sc->pos, n);
			sc->pos += n;
			out += n;
			total += n;
			sizeInBytes -= n;
		}
		if (sizeInBytes > 0 && sc->length_query) {
			sc->length_query_refused = true;
			if (pBytesRead) *pBytesRead = total;
			return total ? MA_SUCCESS : MA_AT_END;
		}
		if (sizeInBytes > 0) {
			if (!stream->good()) {
				if (pBytesRead) *pBytesRead = total;
				return total ? MA_SUCCESS : MA_AT_END;
			}
			stream->read(out, sizeInBytes);
			size_t got = static_cast<size_t>(stream->gcount());
			// Keeps every byte read so far so the window's end tracks the stream's real position; once full it can never answer a seek again, so it's freed immediately rather than held for the rest of the decoder's life.
			if (sc->mirrors_stream() && got) {
				size_t room = stream_cursor::CAP - sc->window.size();
				sc->window.append(out, std::min(room, got));
				if (sc->window.size() >= stream_cursor::CAP) {
					sc->window_full = true;
					std::string().swap(sc->window);
				}
			}
			sc->pos += got;
			total += got;
		}
		if (pBytesRead) *pBytesRead = total;
		return total ? MA_SUCCESS : MA_AT_END;
	}
	static ma_result vfs_seek(ma_vfs*, ma_vfs_file f, ma_int64 offset, ma_seek_origin origin) {
		stream_cursor* sc = (stream_cursor*)f;
		if (!sc || !sc->ds) return MA_ERROR;
		istream* stream = sc->ds->get_istr();
		if (!stream) return MA_ERROR;
		// Where this wants to land, when that can be worked out; a seek from the end is left for the stream to accept or refuse, since a live stream's length is unknown.
		ma_int64 target = -1;
		if (origin == ma_seek_origin_start) target = offset;
		else if (origin == ma_seek_origin_current) target = static_cast<ma_int64>(sc->pos) + offset;
		if (origin != ma_seek_origin_end && target < 0) return MA_INVALID_ARGS; // Before the start, which the stream would otherwise be sought by from where it really is, the window's end, landing inside the data.
		// Only answer from the window while it still mirrors the stream, otherwise a rewind to 0 after a real seek would wrongly report success without moving the stream.
		if (sc->mirrors_stream() && target >= 0 && static_cast<size_t>(target) <= sc->window.size()) {
			sc->pos = static_cast<size_t>(target); // inside the window, so no real seek is needed
			return MA_SUCCESS;
		}
		if (sc->length_query) {
			sc->length_query_refused = true;
			return MA_NOT_IMPLEMENTED;
		}
		// Past the window while it mirrors the stream: the stream sits at the window's end, which the decoder can be behind after a rewind, as after probing formats, so a seek from the current position would be counted from the wrong place. The stream is sought from its start instead, or, when it can't seek, read forward up to the target, which the window keeps while it can.
		if (sc->mirrors_stream() && target >= 0) {
			stream->clear();
			stream->seekg(sc->base + target, stream->beg);
			if (stream->fail()) {
				stream->clear();
				sc->pos = sc->window.size();
				char skipped[4096];
				for (size_t left = static_cast<size_t>(target) - sc->pos; left;) {
					size_t got = 0;
					vfs_read(nullptr, f, skipped, std::min(left, sizeof(skipped)), &got);
					if (!got) return MA_AT_END;
					left -= got;
				}
				return MA_SUCCESS;
			}
			sc->pos = static_cast<size_t>(target);
			std::string().swap(sc->window);
			sc->window_moved = true;
			return MA_SUCCESS;
		}
		std::ios_base::seekdir dir;
		switch (origin) {
			case ma_seek_origin_start:
				dir = stream->beg;
				offset += sc->base;
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
		stream->clear();
		stream->seekg(offset, dir);
		if (stream->fail()) {
			stream->clear(); // genuinely unseekable and outside what was kept; say so instead of claiming a seek that didn't happen
			return MA_NOT_IMPLEMENTED;
		}
		// The stream really moved, so the window no longer describes where the decoder is; from here the stream answers for itself. It can never mirror again, so free it rather than just clearing it.
		std::streamoff at = stream->tellg();
		sc->pos = at > sc->base? static_cast<size_t>(at - sc->base) : 0;
		std::string().swap(sc->window);
		sc->window_moved = true;
		return MA_SUCCESS;
	}
	static ma_result vfs_tell(ma_vfs*, ma_vfs_file f, ma_int64 *pCursor) {
		// The logical position, not the stream's, since the two differ while the window is being replayed.
		stream_cursor* sc = (stream_cursor*)f;
		if (!sc || !sc->ds) return MA_ERROR;
		*pCursor = static_cast<ma_int64>(sc->pos);
		return MA_SUCCESS;
	}
	static ma_result vfs_open(ma_vfs* v, const char*, ma_uint32, ma_vfs_file* f) {
		*f = (ma_vfs_file)((ds_vfs_t*)v)->sc;
		return MA_SUCCESS;
	}
	static ma_result vfs_close(ma_vfs*, ma_vfs_file) { return MA_SUCCESS; }
	// Deliberately left unanswered: the decoder never asks for it (only ma_vfs_open_and_read_file does), and measuring a length
	// means seeking to the end, which a live stream refuses and which would desync the rewind window from the decoder's position.
	static ma_result vfs_info(ma_vfs*, ma_vfs_file, ma_file_info*) { return MA_NOT_IMPLEMENTED; }
	ma_decoder_config decoder_config_init(unsigned int sample_rate, unsigned int channels) {
		init_sound_context();
		ma_decoder_config cfg = ma_decoder_config_init(ma_format_f32, channels, sample_rate);
		cfg.resampling.algorithm = ma_resample_algorithm_custom;
		cfg.resampling.pBackendVTable = &wdl_resampler_backend_vtable;
		if (!g_decoders.empty()) {
			cfg.ppCustomBackendVTables = &g_decoders[0];
			cfg.customBackendCount = g_decoders.size();
		}
		if (!decoder) decoder = make_unique<ma_decoder>();
		return cfg;
	}
public:
	audio_decoder_impl(audio_engine* e) : audio_data_source_impl(e, nullptr), decoder(nullptr), datastream_ref(nullptr) {}
	~audio_decoder_impl() { close(); }
	// A sample rate below min_sample_rate or above the highest MiniAudio names, 0 aside, which keeps the file's: at a few hertz the decoder resampled down to it, so a source read at the engine's rate decoded many thousands of frames for each it gave, slower than the audio played, and above the highest it resampled up to it, as slowly, as many frames for each. And a channel count past MA_MAX_CHANNELS, which MiniAudio refused only once the decoder open had been closed.
	static bool output_format_in_range(unsigned int sample_rate, unsigned int channels) {
		if ((!sample_rate || (sample_rate >= min_sample_rate && sample_rate <= ma_standard_sample_rate_max)) && channels <= MA_MAX_CHANNELS) return true;
		g_soundsystem_last_error = MA_INVALID_ARGS;
		return false;
	}
	virtual bool open(const std::string& filename, const pack_interface* pack_file, unsigned int sample_rate, unsigned int channels) override {
		if (!output_format_in_range(sample_rate, channels)) return false;
		// The pack's copy made first, which throws for a pack open for writing: the decoder open before stays open, as for other refusals, rather than closed by a call that then threw.
		std::shared_ptr<const pack_interface> pack = pack_file && pack_file->get_is_active()? std::shared_ptr<const pack_interface>(pack_file->make_immutable()) : nullptr;
		std::lock_guard<std::recursive_mutex> guard(source_mutex);
		if (decoder && !close()) return false;
		seekable = true;
		ma_decoder_config cfg = decoder_config_init(sample_rate, channels);
		std::string triplet = g_sound_service->prepare_triplet(filename, pack? g_pack_protocol_slot : sound_service::fs_protocol_slot, pack, 0, nullptr); // Without a pack, from disk, as sound.load() reads, rather than from the default protocol, which can be a pack.
		if ((g_soundsystem_last_error = ma_decoder_init_vfs(g_sound_service->get_vfs(), triplet.c_str(), &cfg, &*decoder)) != MA_SUCCESS) decoder.reset();
		else {
			hold_decoder(&*decoder, true);
			set_ma_data_source((ma_data_source*)&*decoder);
		}
		g_sound_service->cleanup_triplet(triplet);
		return g_soundsystem_last_error == MA_SUCCESS;
	}
	virtual bool open_stream(datastream* ds, unsigned int sample_rate = 0, unsigned int channels = 0) override {
		std::lock_guard<std::recursive_mutex> guard(source_mutex);
		if (!ds || !ds->get_istr() || !output_format_in_range(sample_rate, channels) || decoder && !close()) {
			if (ds) ds->release();
			return false;
		}
		ma_decoder_config cfg = decoder_config_init(sample_rate, channels);
		cursor = make_unique<stream_cursor>();
		cursor->ds = ds;
		std::istream* in = ds->get_istr();
		in->clear(); // A stream an earlier call left failed, as a seek it refused, would report no position.
		std::streampos at = in->tellg(); // A stream partly read already, as after the script read a header from it, is decoded from where it is.
		if (at >= 0) cursor->base = at;
		in->clear();
		seekable = false;
		if (at >= 0) { // Tried by seeking to its end and back, before anything else reads it.
			in->seekg(0, std::ios_base::end);
			seekable = !in->fail();
			in->clear();
			in->seekg(at); // Back whether or not that worked: a stream can fail a seek after it moved, as an encrypted one whose payload is a whole number of blocks does.
			if (in->fail()) seekable = false;
			in->clear();
		}
		ds_vfs = make_unique<ds_vfs_t>();
		ds_vfs->cb.onOpen  = vfs_open;  ds_vfs->cb.onOpenW = nullptr;
		ds_vfs->cb.onClose = vfs_close; ds_vfs->cb.onRead  = vfs_read;
		ds_vfs->cb.onWrite = nullptr;   ds_vfs->cb.onSeek  = vfs_seek;
		ds_vfs->cb.onTell  = vfs_tell;  ds_vfs->cb.onInfo  = vfs_info;
		ds_vfs->sc = &*cursor;
		if ((g_soundsystem_last_error = ma_decoder_init_vfs(ds_vfs.get(), "stream", &cfg, &*decoder)) != MA_SUCCESS) {
			decoder.reset();
			ds_vfs.reset();
			cursor.reset();
			ds->release();
		} else {
			datastream_ref = ds;
			hold_decoder(&*decoder, seekable);
			set_ma_data_source((ma_data_source*)&*decoder);
		}
		return g_soundsystem_last_error == MA_SUCCESS;
	}
	virtual bool close() override {
		std::lock_guard<std::recursive_mutex> guard(source_mutex);
		if (users) { // A sound plays it, or another source chains to it, both reading its decoder directly. open() closes first, so it refuses too.
			g_soundsystem_last_error = MA_INVALID_OPERATION;
			return false;
		}
		reset();
		length_frames = -1;
		if (!decoder) return false;
		if (datastream_ref) {
			datastream_ref->release();
			datastream_ref = nullptr;
		}
		if ((g_soundsystem_last_error = let_go_of_decoder(&*decoder)) != MA_SUCCESS) return false;
		decoder.reset();
		// Both after uninit, since the callbacks read through them.
		ds_vfs.reset();
		cursor.reset();
		return true;
	}
	virtual unsigned int get_sample_rate() const override { return decoder? decoder->outputSampleRate : 0; }
	virtual unsigned int get_channels() const override { return decoder? decoder->outputChannels : 0; }
	void prepare_length() override { get_length_frames(); }
	unsigned long long get_length_frames() const override {
		std::lock_guard<std::recursive_mutex> guard(source_mutex);
		ma_data_source* source = get_ma_data_source();
		if (!decoder || !source) return 0;
		long long known = length_frames; // The whole decoder's, whatever its range.
		if (known >= 0) return within_range(known);
		if (known == -2 || users || node_attached()) return within_range(0); // Read elsewhere, and not worked out before: unknown rather than counted under that reader, but for a range with an end.
		if (cursor && !seekable) {
			cursor->length_query = true;
			cursor->length_query_refused = false;
		}
		// The whole decoder's, worked out as when it has no range: MiniAudio counts a range with an end without asking the decoder, so a range set before the length was first asked for was taken whole, ending past the decoder's end, as it was once asked for no more.
		ma_data_source_base* base = (ma_data_source_base*)source;
		ma_uint64 whole = 0;
		g_soundsystem_last_error = base->vtable->onGetLength? base->vtable->onGetLength(source, &whole) : MA_NOT_IMPLEMENTED;
		unsigned long long length = g_soundsystem_last_error == MA_SUCCESS? whole : 0;
		bool refused = cursor && cursor->length_query_refused;
		if (cursor) cursor->length_query = false;
		if (refused) {
			length_frames = -2;
			return within_range(0); // As every later ask, which the -2 above answers: the first read 0 for a range with an end.
		}
		if (g_soundsystem_last_error == MA_SUCCESS) {
			length_frames = length;
			set_held_length(&*decoder, length);
		}
		return within_range(length);
	}
	unsigned long long whole_length_frames() const override { // As worked out, without asking the decoder again.
		long long known = length_frames;
		return known > 0? known : 0;
	}
	float get_length_milliseconds() const override {
		unsigned int sample_rate = get_sample_rate();
		return sample_rate? get_length_frames() * 1000.0f / sample_rate : 0;
	}
};
audio_decoder* audio_decoder::create(audio_engine* e) { return new audio_decoder_impl(e); }
class audio_encoder_impl : public effect_node_impl, public virtual audio_encoder {
	unique_ptr<ma_data_converter> dc;
	// The format write_impl() takes, converted to from float once any change of channels or rate is done, in float: MiniAudio's converter mixes channels in its output format when that is s16, and its mixing down to one channel there divides a signed sum by an unsigned count, so every negative sample of 3, 5, 6 or 7 channels came out as a wrong, large value.
	ma_format output_format = ma_format_f32;
	unsigned int sample_rate, channels;
	unsigned long long frames_written;
	unsigned long long frames_converted = 0; // Frames the converter gave the encoder, at the encoder's rate.
	// The resampler keeps the last frames written until it is told no more come, which it takes to be calls without input. It is drained up to the length the frames written make at the encoder's rate.
	void drain_converter() {
		unsigned long long expected = frames_written * dc->sampleRateOut / dc->sampleRateIn;
		vector<char> buffer(1024 * ma_get_bytes_per_frame(dc->formatOut, dc->channelsOut));
		for (int idle = 0; idle < 3 && frames_converted < expected;) {
			ma_uint64 frame_count_in = 0, frame_count_out = std::min<unsigned long long>(1024, expected - frames_converted);
			if (ma_data_converter_process_pcm_frames(&*dc, nullptr, &frame_count_in, buffer.data(), &frame_count_out) != MA_SUCCESS) break;
			if (!frame_count_out) {
				idle++;
				continue;
			}
			idle = 0;
			frames_converted += frame_count_out;
			write_converted(buffer.data(), frame_count_out);
		}
	}
protected:
	mutex write_mtx; // Taken by everything that uses the encoder, which the audio thread writes to through process() when the encoder is in the graph.
	datastream* output_stream; // Child classes need not manage the stream's refcount.
	datastream* pull_stream; // Convenience feature which queues newly encoded data to be pulled by the user in a threadsafe manner.
	bool streamable_pulling; // If true read can be called any time in pull mode, otherwise only once after stream is closed.
	virtual bool open_impl(const string& filename, datastream* ds, unsigned int sample_rate, unsigned int channels, unsigned int flags) { return false; } // Override in subclasses to initialize encoder state, one of either ds or filename will be set.
	virtual unsigned int write_impl(const void* buffer, unsigned int size) { return 0; } // Override in subclasses, send given buffer to encoder.
	// Frames in float, at the encoder's channels and rate, given to write_impl() in its format.
	vector<char> converted, dc_buffer; // Scratch for write_converted() and write_locked(), under write_mtx.
	unsigned int write_converted(const void* frames, unsigned int frame_count) {
		if (output_format == ma_format_f32) return write_impl(frames, frame_count);
		converted.resize((size_t)frame_count * ma_get_bytes_per_frame(output_format, channels)); // Kept, so that an encoder in the graph doesn't allocate on the audio thread every block.
		ma_pcm_convert(converted.data(), output_format, frames, ma_format_f32, (ma_uint64)frame_count * channels, ma_dither_mode_none);
		return write_impl(converted.data(), frame_count);
	}
	virtual bool close_impl() { return true; } // override in subclasses, free any encoder state.
	bool postsetup(unsigned int target_sample_rate, unsigned int target_channels, ma_format target_format = ma_format_f32) {
		// Encoder subclasses should usually return from open overrides by calling this funcction.
		if (get_active()) return false;
		sample_rate = target_sample_rate;
		channels = target_channels;
		output_format = target_format;
		if (!dc && (sample_rate != get_engine()->get_sample_rate() || channels != get_engine()->get_channels())) {
			dc = make_unique<ma_data_converter>();
			ma_data_converter_config cfg = ma_data_converter_config_init(ma_format_f32, ma_format_f32, get_engine()->get_channels(), target_channels, get_engine()->get_sample_rate(), target_sample_rate);
			cfg.resampling.algorithm = ma_resample_algorithm_custom;
			cfg.resampling.pBackendVTable = &wdl_resampler_backend_vtable;
			if ((g_soundsystem_last_error = ma_data_converter_init(&cfg, nullptr, &*dc)) != MA_SUCCESS) {
				// Not close(), which takes write_mtx; the open call that got here holds it.
				dc.reset();
				close_impl();
				sample_rate = channels = 0;
				return false;
			}
		}
		return true;
	}
	ma_format get_output_format() const { return output_format; }
public:
	audio_encoder_impl(audio_engine* e, bool streamable_pulling = true) : effect_node_impl(e, 0, 0, 1, 1, MA_NODE_FLAG_PASSTHROUGH), output_stream(nullptr), pull_stream(nullptr), streamable_pulling(streamable_pulling), sample_rate(0), channels(0), frames_written(0) {}
	~audio_encoder_impl() {
		destroy_node(); // Off the graph before anything process() uses goes; the subclasses' destructors do so first.
		close();
		if (pull_stream) pull_stream->release();
	}
	unsigned int get_default_open_flags() const override { return ENCODER_OVERWRITE; }
	// The most channels the encoder's format takes.
	virtual unsigned int max_output_channels() const { return MA_MAX_CHANNELS; }
	// Refused as an engine refuses them, before an open encoder is closed: past the highest sample rate MiniAudio names, encoding a block in the graph took longer than the block lasts, below min_sample_rate the resampler reserved memory for the engine's rate over this one times its output, hundreds of megabytes at 1 Hz, and dr_wav keeps a channel count in 16 bits, cutting a higher one while the open succeeded. No channels, or more than the format takes, the encoders refused themselves only once the encoder open had been closed.
	// Whether the open flags, defaults filled in, give the encoder what it needs, as a PCM format for WAV.
	virtual bool flags_in_range(unsigned int flags) const { return true; }
	// Flags among which an open makes one choice, as a WAV encoder's PCM formats.
	virtual unsigned int open_flag_choices() const { return 0; }
	// The flags an open goes by: AUDIO_ENCODER_DEFAULTS replaced by the defaults, less a choice the flags given make themselves, which the default format overrode before.
	unsigned int open_flags(unsigned int flags) const {
		if (!(flags & ENCODER_DEFAULTS)) return flags;
		flags &= ~ENCODER_DEFAULTS;
		unsigned int defaults = get_default_open_flags();
		if (flags & open_flag_choices()) defaults &= ~open_flag_choices();
		return flags | defaults;
	}
	bool output_in_range(unsigned int sample_rate, unsigned int channels, unsigned int flags) const {
		if (sample_rate >= min_sample_rate && sample_rate <= ma_standard_sample_rate_max && channels >= 1 && channels <= max_output_channels() && flags_in_range(flags)) return true;
		g_soundsystem_last_error = MA_INVALID_ARGS;
		return false;
	}
	bool open_file(const string& filename, unsigned int sample_rate, unsigned int channels, unsigned int flags) override {
		flags = open_flags(flags);
		if (!output_in_range(sample_rate, channels, flags)) return false;
		if (filename.empty()) { // No output to open, which a WAV encoder threw for after closing the one open.
			g_soundsystem_last_error = MA_INVALID_ARGS;
			return false;
		}
		if (!(flags & ENCODER_OVERWRITE) && FileExists(filename)) { // The encoders would replace it. Refused before the encoder open is closed, as the other arguments are.
			g_soundsystem_last_error = MA_ALREADY_EXISTS;
			return false;
		}
		if (get_active()) close();
		unique_lock<mutex> lock(write_mtx);
		return open_impl(filename, nullptr, sample_rate, channels, flags); // The encoders create the file anew, replacing one there, once their arguments check out; deleting it first lost it to an open that then failed.
	}
	bool open_stream(datastream* ds, unsigned int sample_rate, unsigned int channels, unsigned int flags) override {
		if (!ds) return false;
		flags = open_flags(flags);
		bool writable = ds->can_write();
		if (!writable) g_soundsystem_last_error = MA_INVALID_ARGS; // Nothing to write to, which a WAV encoder threw for after closing the one open.
		if (!writable || !output_in_range(sample_rate, channels, flags)) {
			ds->release();
			return false;
		}
		if (get_active()) close();
		unique_lock<mutex> lock(write_mtx);
		bool opened;
		try {
			opened = open_impl("", ds, sample_rate, channels, flags);
		} catch (...) { // The script's reference to the stream, given to this function, isn't kept then either.
			ds->release();
			throw;
		}
		if (!opened) {
			ds->release();
			return false;
		}
		output_stream = ds;
		return true;
	}
	bool open_pull(unsigned int sample_rate, unsigned int channels, unsigned int flags) override {
		if (!output_in_range(sample_rate, channels, open_flags(flags))) return false;
		if (get_active()) close();
		if (pull_stream) pull_stream->release();
		pull_stream = new datastream(new stringstream());
		bool opened;
		try {
			opened = open_stream(pull_stream, sample_rate, channels, flags);
		} catch (...) { // open_stream() released the stream then too.
			pull_stream = nullptr;
			throw;
		}
		if (opened) return true;
		pull_stream = nullptr;
		return false;
	}
	bool close() override {
		unique_lock<mutex> lock(write_mtx);
		if (dc && get_active()) drain_converter();
		if (!close_impl()) return false;
		if (dc) {
			ma_data_converter_uninit(&*dc, nullptr);
			dc.reset();
		}
		if (output_stream && output_stream != pull_stream) output_stream->release();
		output_stream = nullptr;
		frames_written = frames_converted = sample_rate = channels = 0;
		return true;
	}
	bool get_active() const override { return sample_rate && channels; }
	unsigned long long get_frames_written() const override { return frames_written; }
	// Takes frames in the engine's format, as process() is given them when the encoder is a node, and returns how many of those it wrote, which is what frames_written counts.
	unsigned int write(const float* frames_in, unsigned int frame_count) override {
		unique_lock<mutex> lock(write_mtx);
		return write_locked(frames_in, frame_count);
	}
	// write(), with write_mtx held.
	unsigned int write_locked(const float* frames_in, unsigned int frame_count) {
		if (!frames_in || !frame_count || !get_active()) return 0;
		if (!dc) {
			unsigned int frames = write_converted(frames_in, frame_count);
			frames_written += frames;
			return frames;
		}
		unsigned int dc_bufsize = 1024; // frames
		dc_buffer.resize(dc_bufsize * ma_get_bytes_per_frame(dc->formatOut, dc->channelsOut));
		ma_uint64 total_processed = 0;
		while (total_processed < frame_count) {
			ma_uint64 frame_count_in = frame_count - total_processed, frame_count_out = dc_bufsize;
			if (ma_data_converter_process_pcm_frames(&*dc, ma_offset_pcm_frames_ptr_f32((float*)frames_in, total_processed, dc->channelsIn), &frame_count_in, &dc_buffer[0], &frame_count_out) != MA_SUCCESS) break;
			if (!frame_count_in && !frame_count_out) break;
			if (frame_count_out && write_converted(dc_buffer.data(), frame_count_out) < frame_count_out) break; // The encoder failed; these frames didn't make it.
			frames_converted += frame_count_out;
			total_processed += frame_count_in;
			frames_written += frame_count_in;
		}
		return total_processed;
	}
	// The engine's channel count makes a frame of the script's samples, as write() takes them.
	unsigned int write_script_array(CScriptArray *frames) override {
		unsigned int engine_channels = get_engine()->get_channels();
		if (!frames || !engine_channels) return 0;
		return write((float*)frames->GetBuffer(), frames->GetSize() / engine_channels);
	}
	unsigned int write_script_memory_buffer(script_memory_buffer* frames) override {
		unsigned int engine_channels = get_engine()->get_channels();
		if (!frames || !engine_channels) return 0;
		return write((float*)frames->ptr, frames->size / engine_channels);
	}
	// On the audio thread, which mustn't wait while a script thread opens, closes or writes to the encoder under write_mtx; that block isn't encoded then, and the audio goes on through this node either way.
	void process(const float** frames_in, unsigned int* frame_count_in, float** frames_out, unsigned int* frame_count_out) override {
		unique_lock<mutex> lock(write_mtx, try_to_lock);
		if (lock.owns_lock()) write_locked(*frames_in, *frame_count_in);
	}
	string read() override {
		unique_lock<mutex> lock(write_mtx);
		if (!pull_stream) return "";
		if (!streamable_pulling && get_active()) return "";
		stringstream* pull_stringstream = dynamic_cast<stringstream*>(pull_stream->stream());
		if (!pull_stringstream) return "";
		string data = pull_stringstream->str();
		if (get_active()) pull_stringstream->str("");
		else {
			pull_stream->release();
			pull_stream = nullptr;
		}
		return data;
	}
	string get_format() const override { return ""; }
	unsigned int get_sample_rate() const override { return sample_rate; }
	unsigned int get_channels() const override { return channels; }
};
class audio_wav_encoder_impl : public audio_encoder_impl, public virtual audio_wav_encoder {
	unique_ptr<ma_encoder> encoder;
	// Where a stream's output goes. The stream is looked up on every call, as closing the datastream deletes it while the encoder still holds the datastream, and offsets count from where the stream was when the encoder opened, as it can already hold data.
	struct stream_output {
		datastream *ds = nullptr;
		std::streamoff base = 0;
		std::string header; // What the encoder writes while it opens, held until then: see open_impl().
		bool holding_header = false;
	} output;
	// A WAV's header gives the RIFF and data chunk sizes, which the encoder writes as nothing at first and over that when it closes, by seeking back to them. A stream that can't seek, such as an encrypting, encoding or compressing one, kept the first ones, so that its WAV read as holding no audio. They are written as 0xFFFFFFFF instead, a length unknown, as a WAV streamed out is written, which readers take as running to the file's end; closing writes the real ones over them where it can.
	static void mark_sizes_unknown(std::string& header) {
		if (header.size() < 12 || header.compare(0, 4, "RIFF") || header.compare(8, 4, "WAVE")) return;
		header.replace(4, 4, 4, '\xff');
		for (size_t at = 12; at + 8 <= header.size();) {
			if (!header.compare(at, 4, "data")) {
				header.replace(at + 4, 4, 4, '\xff');
				return;
			}
			ma_uint32 size = ma_uint32(ma_uint8(header[at + 4])) | ma_uint32(ma_uint8(header[at + 5])) << 8 | ma_uint32(ma_uint8(header[at + 6])) << 16 | ma_uint32(ma_uint8(header[at + 7])) << 24;
			if (size > header.size()) return;
			at += 8 + size + (size & 1);
		}
	}
	static ma_result stream_write(ma_encoder *pEncoder, const void *pBufferIn, size_t bytesToWrite, size_t *pBytesWritten) {
		stream_output *out = static_cast<stream_output *>(pEncoder->pUserData);
		*pBytesWritten = 0;
		if (out->holding_header) {
			out->header.append(static_cast<const char*>(pBufferIn), bytesToWrite);
			*pBytesWritten = bytesToWrite;
			return MA_SUCCESS;
		}
		std::ostream *stream = out->ds? out->ds->get_ostr() : nullptr;
		if (!stream) return MA_ERROR;
		stream->write((const char *)pBufferIn, bytesToWrite);
		if (!stream->good()) return MA_ERROR;
		*pBytesWritten = bytesToWrite;
		return MA_SUCCESS;
	}
	static ma_result stream_seek(ma_encoder *pEncoder, ma_int64 offset, ma_seek_origin origin) {
		if (origin != ma_seek_origin_start) return MA_NOT_IMPLEMENTED;
		stream_output *out = static_cast<stream_output *>(pEncoder->pUserData);
		std::ostream *stream = out->ds? out->ds->get_ostr() : nullptr;
		if (!stream || out->holding_header) return MA_ERROR;
		std::ios_base::iostate was = stream->rdstate();
		stream->seekp(out->base + offset);
		if (stream->good()) return MA_SUCCESS;
		stream->clear(was); // A stream that can't seek is left as good as it was, for what the script writes to it after the encoder.
		return MA_ERROR;
	}
protected:
	bool open_impl(const string& filename, datastream* ds, unsigned int sample_rate, unsigned int channels, unsigned int flags) override {
		ma_format target_format;
		if (flags & WAV_S16) target_format = ma_format_s16;
		else if (flags & WAV_S24) target_format = ma_format_s24;
		else if (flags & WAV_U8) target_format = ma_format_u8;
		else if (flags & WAV_S32) target_format = ma_format_s32;
		else if (flags & WAV_F32) target_format = ma_format_f32;
		else { // flags_in_range() refuses this before the opens close anything.
			g_soundsystem_last_error = MA_INVALID_ARGS;
			return false;
		}
		encoder = make_unique<ma_encoder>();
		ma_encoder_config cfg = ma_encoder_config_init(ma_encoding_format_wav, target_format, channels, sample_rate);
		if (ds && ds->can_write()) {
			output.ds = ds;
			std::streampos start = ds->get_ostr()->tellp();
			output.base = start == std::streampos(-1)? 0 : std::streamoff(start);
			output.header.clear();
			output.holding_header = true;
			g_soundsystem_last_error = ma_encoder_init(stream_write, stream_seek, &output, &cfg, &*encoder);
			output.holding_header = false;
			if (g_soundsystem_last_error == MA_SUCCESS) {
				mark_sizes_unknown(output.header);
				size_t written;
				if ((g_soundsystem_last_error = stream_write(&*encoder, output.header.data(), output.header.size(), &written)) != MA_SUCCESS) ma_encoder_uninit(&*encoder);
			}
			output.header = std::string();
		}
		else if (!filename.empty()) {
#ifdef _WIN32
			// MiniAudio opens a narrow path in the ANSI code page, which named a file other than the UTF-8 one the script gave, and the overwrite check looked at.
			std::wstring wide_filename;
			Poco::UnicodeConverter::toUTF16(filename, wide_filename);
			g_soundsystem_last_error = ma_encoder_init_file_w(wide_filename.c_str(), &cfg, &*encoder);
#else
			g_soundsystem_last_error = ma_encoder_init_file(filename.c_str(), &cfg, &*encoder);
#endif
		}
		else { // The opens refuse this before closing anything.
			encoder.reset();
			g_soundsystem_last_error = MA_INVALID_ARGS;
			return false;
		}
		if (g_soundsystem_last_error != MA_SUCCESS) {
			encoder.reset();
			return false;
		}
		return postsetup(sample_rate, channels, target_format);
	}
	unsigned int write_impl(const void* buffer, unsigned int size) override {
		ma_uint64 frames_written;
		if (!encoder || (g_soundsystem_last_error = ma_encoder_write_pcm_frames(&*encoder, buffer, size, &frames_written)) != MA_SUCCESS) return 0;
		return frames_written;
	}
	bool close_impl() override {
		if (!encoder) return false;
		ma_encoder_uninit(&*encoder);
		encoder.reset();
		return true;
	}
public:
	audio_wav_encoder_impl(audio_engine* e) : audio_encoder_impl(e, false), encoder(nullptr) {}
	~audio_wav_encoder_impl() {
		destroy_node(); // An encoder in the graph has its process() called by the audio thread until then.
		close();
	}
	unsigned int get_default_open_flags() const override { return audio_encoder_impl::get_default_open_flags() | WAV_S16; }
	unsigned int open_flag_choices() const override { return WAV_S16 | WAV_S24 | WAV_U8 | WAV_S32 | WAV_F32; }
	bool flags_in_range(unsigned int flags) const override { return flags & open_flag_choices(); }
	string get_format() const override { return "wav"; }
	ma_format get_wav_format() const override { return !get_active()? ma_format_unknown : get_output_format(); } // Unknown while not open, rather than float, which a closed encoder wrote no more than any other format.
};
audio_wav_encoder* audio_wav_encoder::create(audio_engine* e) { return new audio_wav_encoder_impl(e); }
class audio_opus_encoder_impl : public audio_encoder_impl, public virtual audio_opus_encoder {
	OggOpusEnc* encoder;
	OggOpusComments* comments;
	int bitrate, complexity, signal_type, application, packet_loss_percent;
	bool vbr, cvbr, dtx;
	static int write_callback(void* user_data, const unsigned char* ptr, opus_int32 len) {
		datastream* ds = static_cast<datastream*>(user_data);
		ostream* ostr = ds? ds->get_ostr() : nullptr; // Looked up each time, as closing the datastream deletes it while the encoder still holds the datastream.
		if (!ostr) return 1;
		ostr->write((const char*)ptr, len);
		return ostr->good()? 0 : 1;
	}
	static int close_callback(void* user_data) { return 0; }
protected:
	unsigned int max_output_channels() const override { return 2; } // Mapping family 0, which open_impl() asks libopusenc for, takes mono and stereo only.
	bool open_impl(const string& filename, datastream* ds, unsigned int sample_rate, unsigned int channels, unsigned int flags) override {
		int error = OPE_BAD_ARG; // As when there is no output to open.
		comments = ope_comments_create();
		if (!comments) {
			g_soundsystem_last_error = MA_OUT_OF_MEMORY;
			return false;
		}
		if (ds && ds->can_write()) {
			OpusEncCallbacks callbacks = {write_callback, close_callback};
			encoder = ope_encoder_create_callbacks(&callbacks, ds, comments, sample_rate, channels, 0, &error);
		} else if (!filename.empty()) encoder = ope_encoder_create_file(filename.c_str(), comments, sample_rate, channels, 0, &error);
		if (!encoder) {
			// close_impl() only runs its cleanup for an open encoder, so the comments made above would never be freed.
			ope_comments_destroy(comments);
			comments = nullptr;
			g_soundsystem_last_error = error == OPE_ALLOC_FAIL? MA_OUT_OF_MEMORY : error == OPE_BAD_ARG || error == OPE_UNIMPLEMENTED? MA_INVALID_ARGS : MA_ERROR; // Rather than leave SOUNDSYSTEM_LAST_ERROR reading success.
			return false;
		}
		ope_encoder_ctl(encoder, OPUS_SET_BITRATE(bitrate));
		ope_encoder_ctl(encoder, OPUS_SET_COMPLEXITY(complexity));
		ope_encoder_ctl(encoder, OPUS_SET_SIGNAL(signal_type));
		ope_encoder_ctl(encoder, OPUS_SET_APPLICATION(application));
		ope_encoder_ctl(encoder, OPUS_SET_PACKET_LOSS_PERC(packet_loss_percent));
		ope_encoder_ctl(encoder, OPUS_SET_VBR(vbr ? 1 : 0));
		ope_encoder_ctl(encoder, OPUS_SET_VBR_CONSTRAINT(cvbr ? 1 : 0));
		ope_encoder_ctl(encoder, OPUS_SET_DTX(dtx ? 1 : 0));
		return postsetup(sample_rate, channels, ma_format_f32);
	}
	unsigned int write_impl(const void* buffer, unsigned int frame_count) override {
		if (!encoder) return 0;
		int result = ope_encoder_write_float(encoder, (const float*)buffer, frame_count);
		return (result == OPE_OK) ? frame_count : 0;
	}
	bool close_impl() override {
		if (!encoder) return false;
		ope_encoder_drain(encoder);
		ope_encoder_destroy(encoder);
		encoder = nullptr;
		if (comments) {
			ope_comments_destroy(comments);
			comments = nullptr;
		}
		return true;
	}
public:
	audio_opus_encoder_impl(audio_engine* e) : audio_encoder_impl(e), encoder(nullptr), comments(nullptr), bitrate(128000), complexity(10), signal_type(OPUS_AUTO), application(OPUS_APPLICATION_AUDIO), packet_loss_percent(0), vbr(true), cvbr(false), dtx(false) {}
	~audio_opus_encoder_impl() {
		destroy_node();
		close();
	}
	string get_format() const override { return "opus"; }
	int get_bitrate() const override { return bitrate; }
	bool set_bitrate(int new_bitrate) override {
		if (new_bitrate < 6000 || new_bitrate > 510000) return false;
		unique_lock<mutex> lock(write_mtx); // As the audio thread writes to the encoder under it; the value is kept only once the encoder took it, or for the next encoder opened.
		if (encoder && ope_encoder_ctl(encoder, OPUS_SET_BITRATE(new_bitrate)) != OPE_OK) return false;
		bitrate = new_bitrate;
		return true;
	}
	int get_complexity() const override { return complexity; }
	bool set_complexity(int new_complexity) override {
		if (new_complexity < 0 || new_complexity > 10) return false;
		unique_lock<mutex> lock(write_mtx);
		if (encoder && ope_encoder_ctl(encoder, OPUS_SET_COMPLEXITY(new_complexity)) != OPE_OK) return false;
		complexity = new_complexity;
		return true;
	}
	int get_signal_type() const override { return signal_type; }
	bool set_signal_type(int new_signal_type) override {
		if (new_signal_type != OPUS_AUTO && new_signal_type != OPUS_SIGNAL_VOICE && new_signal_type != OPUS_SIGNAL_MUSIC) return false;
		unique_lock<mutex> lock(write_mtx);
		if (encoder && ope_encoder_ctl(encoder, OPUS_SET_SIGNAL(new_signal_type)) != OPE_OK) return false;
		signal_type = new_signal_type;
		return true;
	}
	int get_application() const override { return application; }
	bool set_application(int new_application) override {
		if (new_application != OPUS_APPLICATION_VOIP && new_application != OPUS_APPLICATION_AUDIO && new_application != OPUS_APPLICATION_RESTRICTED_LOWDELAY) return false;
		unique_lock<mutex> lock(write_mtx);
		if (encoder && ope_encoder_ctl(encoder, OPUS_SET_APPLICATION(new_application)) != OPE_OK) return false;
		application = new_application;
		return true;
	}
	int get_packet_loss_percent() const override { return packet_loss_percent; }
	bool set_packet_loss_percent(int percent) override {
		if (percent < 0 || percent > 100) return false;
		unique_lock<mutex> lock(write_mtx);
		if (encoder && ope_encoder_ctl(encoder, OPUS_SET_PACKET_LOSS_PERC(percent)) != OPE_OK) return false;
		packet_loss_percent = percent;
		return true;
	}
	bool get_vbr() const override { return vbr; }
	bool set_vbr(bool enabled) override {
		unique_lock<mutex> lock(write_mtx);
		if (encoder && ope_encoder_ctl(encoder, OPUS_SET_VBR(enabled ? 1 : 0)) != OPE_OK) return false;
		vbr = enabled;
		return true;
	}
	bool get_cvbr() const override { return cvbr; }
	bool set_cvbr(bool enabled) override {
		unique_lock<mutex> lock(write_mtx);
		if (encoder && ope_encoder_ctl(encoder, OPUS_SET_VBR_CONSTRAINT(enabled ? 1 : 0)) != OPE_OK) return false;
		cvbr = enabled;
		return true;
	}
	bool get_dtx() const override { return dtx; }
	bool set_dtx(bool enabled) override {
		unique_lock<mutex> lock(write_mtx);
		if (encoder && ope_encoder_ctl(encoder, OPUS_SET_DTX(enabled ? 1 : 0)) != OPE_OK) return false;
		dtx = enabled;
		return true;
	}
};
audio_opus_encoder* audio_opus_encoder::create(audio_engine* e) { return new audio_opus_encoder_impl(e); }
// The highest rate, as a ratio, which a sound or mixer plays at, and a higher pitch is held at. There even a sound's lowest audible component, at 20 Hz, plays at 20 kHz, the top of hearing, so a higher rate can't be heard to rise any more, and past half the engine's sample rate its components fold back down instead, sounding lower. MiniAudio's work grows with the rate, and with no limit a pitch of a million kept the audio thread from returning at all.
static constexpr float max_pitch_ratio = 1000;
// The lowest rate MiniAudio's resampler takes, and a lower pitch is held at: it refuses one whose ratio times 1000 is below 1 and keeps the rate it had, which could be far faster than hold_rate() then allows.
static constexpr float min_pitch_ratio = 1.0f / 1000;
// A MiniAudio sound or group as sounds and mixers make them, whose rate MiniAudio is given held by hold_rate().
struct held_sound : ma_sound {
	std::atomic<float> pitch{1}; // The pitch the script set, which MiniAudio is given only held.
	float given = 1; // The pitch MiniAudio was last given; only the thread reading the engine uses it.
	std::atomic<float> rate{1}; // The rate MiniAudio last applied, by which a group multiplies those of the nodes it reads (see downstream_rate()).
	ma_resource_manager_data_stream* stream = nullptr; // The resource manager's stream the sound plays, if it plays one, set before the sound is attached (see held_sound_process()).
	float rate_pitch = 1, rate_doppler = 1; // The pitch and doppler ratio hold_rate() last set the resampler for, as MiniAudio made it; only the thread reading the engine uses them.
	// Giving what the resampler still owed at the source's end (see give_end()): none yet, under way or given, and whether it took the silent frame fed it; only the thread reading the engine uses these.
	enum class end_flush : unsigned char { none, giving, given };
	end_flush end_state = end_flush::none;
	bool end_silence_taken = false;
	ma_uint32 cache_cap = 0; // The capacity MiniAudio gave the sound's cache, which held_sound_process() lowers for each call (see bound_read()).
	ma_uint64 restart_cursor = ~(ma_uint64)0; // The source's cursor when held_sound_process() last played the sound on from its loop's start at its end.
	// play() came at the sound's end before MiniAudio stopped it, which held_sound_process() starts it again from (see sound_impl::restart_if_ending()): restart_asked, then restart_taking while the audio thread starts it, which stop() and pause() wait out, so that the sound isn't started after they stopped it.
	static constexpr int restart_none = 0, restart_asked = 1, restart_taking = 2;
	std::atomic<int> restart{restart_none};
	std::atomic<bool> flushing{false}; // give_end() runs MiniAudio's processing at the sound's end with its end flag off, which another thread is to take for the end still (see at_end_seen()).
	std::atomic<ma_uint32> processed{0}; // Calls of held_sound_process(), by which play() tells whether the audio thread still processes the sound (see sound_impl::still_ending()).
	std::atomic<ma_uint64> block_at{~(ma_uint64)0}; // The engine's time when held_sound_process() or held_group_process() last ran, the start of that block; ~0 before it ran (see sound_impl::schedule_stop_and_fade()).
	std::atomic<ma_uint64> block_done{~(ma_uint64)0}; // block_at once that processing returned for that block.
	std::atomic<ma_uint64> block_set{0}; // *time_sets when block_at was recorded: a block recorded before the script set the engine's time says nothing of the block under way, which a time set back by less than a block would otherwise take it for.
	std::shared_ptr<std::atomic<ma_uint64>> time_sets; // The engine's count of times its time was set (see audio_engine_impl::time_sets), kept from when the sound or group was made.
	std::atomic<ma_uint64> seek_target{~(ma_uint64)0}; // The frame a seek asked for, ~0 for none, made by held_sound_process() in place of MiniAudio's seekTarget.
	// A fade scheduled ahead, by set_timed_fade() or a stop with a fade, kept here rather than given to MiniAudio, which takes a fade's settings into the sound's only fader at its next block and plays the sound unfaded until the fade begins, so that a sound at a fade of its own jumped to full volume and back: held_sound_process() gives it in the first block starting at or past fade_at, ~0 for none. Under fade_locked, which the audio thread only tries.
	std::atomic<bool> fade_locked{false}, fade_pending{false};
	ma_uint64 fade_at = ~(ma_uint64)0, fade_length = 0;
	float fade_beg = -1, fade_end = 0; // A negative beginning is the volume the fader is at when the fade begins, as for MiniAudio.
	// Given to MiniAudio in the block under way, with this length, but kept until MiniAudio took it (see take_back_fade()).
	std::atomic<bool> fade_given{false};
	std::atomic<bool> given_stale{false}; // That fade was replaced by one scheduled since, before MiniAudio took it: take_back_fade() removes it, not to be given again.
	ma_uint64 given_length = 0;
	// A fade set to begin at once, by set_fade() or as a stop's fade is undone, which give_fades() writes into MiniAudio's settings at the start of the next block, as the script's thread wrote it before: MiniAudio reads the settings and then marks them taken, on the audio thread, so that a fade written by another thread in between was lost, or taken half old and half new. Under fade_locked.
	std::atomic<bool> now_pending{false};
	float now_beg = 0, now_end = 1;
	ma_uint64 now_length = 0;
	float now_given_volume = -1; // The volume the fade set at once last given puts the sound at, while MiniAudio hasn't taken it, which a fade scheduled ahead replacing it begins from; -1 for none.
	// Sequentially consistent, as the audio thread's tries are, so that a script thread finding after its unlock that the block it holds the lock in started reads that block's time (see sound_impl::schedule_stop_and_fade()).
	void lock_fade() { while (fade_locked.exchange(true)) std::this_thread::yield(); }
	void unlock_fade() { fade_locked.store(false); }
};
struct held_sound_delete {
	void operator()(ma_sound* s) const { delete static_cast<held_sound*>(s); }
};
using held_sound_ptr = unique_ptr<ma_sound, held_sound_delete>;
static held_sound* held(ma_sound* s) { return static_cast<held_sound*>(s); }
static void (*g_ma_sound_process)(ma_node*, const float**, ma_uint32*, float**, ma_uint32*) = nullptr;
static void (*g_ma_group_process)(ma_node*, const float**, ma_uint32*, float**, ma_uint32*) = nullptr;
static ma_node_vtable g_held_sound_vtable, g_held_group_vtable;
// How many times faster than its own rate a node is read: the product of the rates of the groups the engine reads it through. Only output buses being read at that moment are followed, as MiniAudio's detach waits for such a read to end, so the node reading one can't be detached or freed meanwhile; of a splitter's buses, that is the one whose read reached this node. An engine's endpoint is read by its graph rather than through a bus, and that graph is a node another engine reads through a bus, so the walk goes on from it into the engine an engine plays into.
static float downstream_rate(ma_node_base* node) {
	float rate = 1;
	for (int depth = 0; node && depth < 1000; depth++) {
		ma_node_base* next = nullptr;
		for (ma_uint32 i = 0; i < ma_node_get_output_bus_count(node) && !next; i++) {
			ma_node_output_bus* bus = &node->pOutputBuses[i];
			if (*(volatile ma_uint32*)&bus->refCount > 0) next = (ma_node_base*)*(ma_node* volatile*)&bus->pInputNode;
		}
		if (!next && node->pNodeGraph && node == &node->pNodeGraph->endpoint) next = &node->pNodeGraph->base;
		if (next && next->vtable == &g_held_group_vtable) rate *= held((ma_sound*)next)->rate.load(std::memory_order_relaxed);
		node = next;
	}
	return rate;
}
// The rate a pitch's resampler is given a ratio over, which a ratio up to max_pitch_ratio, as hold_rate() keeps it, keeps within 32 bits: a fine enough step even for a source far below the engine's rate, as one at 1000 Hz on a 48 kHz engine, whose ratio is 1/48.
static constexpr ma_uint32 pitch_rate_scale = 4000000;
// Sets the rate of a sound's or group's linear resampler. Moving its timing to the new rate, MiniAudio multiplies the fraction of the input frame it is at, under the old output rate, by the new one in 32 bits, which a fine rate overflows, sending the read to an arbitrary point between two frames: it is moved here in 64 bits instead, the fraction cleared for MiniAudio's move. Rounded to the nearest step of the new rate, which for an exact rate, reduced, as 1 over 1 for a source at the engine's rate, can be a whole frame: cut down, as MiniAudio's is, each return to such a rate moved the read back, so that a pitch changed to and from 1 every block lagged.
static void set_pitch_rate(ma_resampler* resampler, ma_uint32 rate_in, ma_uint32 rate_out) {
	ma_linear_resampler& linear = resampler->state.linear;
	ma_uint64 fraction = linear.inTimeFrac, old_out = linear.config.sampleRateOut;
	linear.inTimeFrac = 0;
	if (ma_resampler_set_rate(resampler, rate_in, rate_out) != MA_SUCCESS || !old_out) {
		linear.inTimeFrac = (ma_uint32)fraction;
		return;
	}
	ma_uint64 moved = (fraction * linear.config.sampleRateOut * 2 + old_out) / (old_out * 2);
	linear.inTimeInt += (ma_uint32)(moved / linear.config.sampleRateOut);
	linear.inTimeFrac = (ma_uint32)(moved % linear.config.sampleRateOut);
}
// MiniAudio works a sound's or group's rate out at the start of each block, from its source's sample rate over the engine's, its pitch and the doppler ratio its spatializer worked out in the block before, (c - f*vl) / (c - f*vs) along the line from the listener, with c the speed of sound, f the doppler factor and vl and vs the listener's and the sound's velocities each held at c / f. That ratio has no bound, and is infinite for a sound coming at c / f or faster, or NaN if the listener also goes away that fast; while spatialization is off none is worked out, and MiniAudio kept applying the last one for good. The rate then went far past max_pitch_ratio, or wasn't a number, and the audio thread took seconds per block or didn't return. A sound is moreover read as many times faster as the mixers it plays through, which with each at max_pitch_ratio went past it too. Just before MiniAudio works the rate out, an infinite ratio is held at max_pitch_ratio, a NaN one or one while spatialization is off is set to 1, and the pitch MiniAudio is given is held so that neither the rate nor the rate times those of the groups the node is read through goes past max_pitch_ratio. A group's rate rising takes effect on the nodes it reads from their next read, a block's first read of them having come before the group's own processing. On the thread reading the engine.
static void hold_rate(ma_node* node) {
	held_sound* s = held((ma_sound*)node);
	float pitch = ma_sound_get_pitch(s);
	if (pitch != s->given && pitch > 0) s->pitch.store(std::clamp(pitch, min_pitch_ratio, max_pitch_ratio), std::memory_order_relaxed); // Given through MiniAudio by code that has the ma_sound, as a plugin may.
	float& doppler = s->engineNode.spatializer.dopplerPitch;
	if (!ma_sound_is_spatialization_enabled(s) || doppler != doppler) doppler = 1;
	else if (doppler > max_pitch_ratio) doppler = max_pitch_ratio;
	float base = (float)s->engineNode.sampleRate / ma_engine_get_sample_rate(s->engineNode.pEngine), limit = max_pitch_ratio / std::max(downstream_rate((ma_node_base*)node), 1.0f);
	pitch = s->pitch.load(std::memory_order_relaxed);
	if (base * pitch * doppler > limit) pitch = limit / (base * doppler);
	if (pitch > 0) ma_sound_set_pitch(s, s->given = pitch);
	float rate = base * s->given * doppler; // As MiniAudio works it out.
	if (rate * 1000 < 1) { // Below min_pitch_ratio, as with a doppler ratio near 0 for a listener going away at the speed of sound, the doppler ratio is raised to where the rate is just at it.
		doppler = min_pitch_ratio / (base * s->given) * 1.0001f;
		rate = base * s->given * doppler;
	}
	s->rate.store(rate, std::memory_order_relaxed);
	// MiniAudio sets the resampler from these at the start of the block, on a change, to a ratio it keeps to a thousandth, cut down: a sound played up to a thousandth slow and flat, and a doppler ratio, changed each block, was always rounded down. Set here instead, which MiniAudio, finding them unchanged, keeps: exactly at a pitch and doppler ratio of 1, as the sound started, and otherwise over pitch_rate_scale, rounded. Only for MiniAudio's linear resampler, the engine's for pitch, whose timing set_pitch_rate() moves; another is left to MiniAudio.
	// Compared with those it was last set for here rather than with MiniAudio's, which C++ code setting the pitch through MiniAudio between this and MiniAudio's processing has MiniAudio change to its own.
	ma_engine_node& node_state = s->engineNode;
	float given = ma_sound_get_pitch(s); // As MiniAudio reads it.
	if ((given != s->rate_pitch || doppler != s->rate_doppler || node_state.oldPitch != s->rate_pitch || node_state.oldDopplerPitch != s->rate_doppler) && node_state.resampler.pBackend == &node_state.resampler.state.linear) {
		node_state.oldPitch = s->rate_pitch = given;
		node_state.oldDopplerPitch = s->rate_doppler = doppler;
		ma_uint32 engine_rate = ma_engine_get_sample_rate(node_state.pEngine);
		if (given == 1 && doppler == 1) set_pitch_rate(&node_state.resampler, node_state.sampleRate, engine_rate);
		else set_pitch_rate(&node_state.resampler, (ma_uint32)std::clamp<double>(std::round((double)node_state.sampleRate / engine_rate * given * doppler * pitch_rate_scale), 1, 0xFFFFFFFF), pitch_rate_scale);
	}
}
// MiniAudio reads a sound's source a whole cache at a time, past what its resampler takes, and a looping source wraps within such a read: looping turned off then, the sound played the next pass it had read, to its end, and below a rate of 1 many passes of a short loop. So each call is held to what the resampler takes: the output asked lowered to what one cache can feed, and the cache's load to what that output needs beyond the frames cached, an output of one frame needing more taken in as loads of equal size. The source is then read no further than the sound plays it, and a change of looping acts where the sound is. Returns the load, lowering count.
static ma_uint32 bound_read(ma_sound* s, ma_uint32& count) {
	held_sound* h = held(s);
	if (!h->cache_cap) h->cache_cap = s->processingCacheCap;
	const ma_uint64 cap = h->cache_cap, cached = s->processingCacheFramesRemaining;
	if (!cap || !count) return (ma_uint32)cap;
	ma_resampler* resampler = &s->engineNode.resampler;
	auto needed = [resampler, cached](ma_uint64 out) -> ma_uint64 {
		ma_uint64 in = 0;
		if (ma_resampler_get_required_input_frame_count(resampler, out, &in) != MA_SUCCESS) return ~(ma_uint64)0;
		return in > cached? in - cached : 0;
	};
	ma_uint64 need = needed(count);
	if (need == ~(ma_uint64)0) return (ma_uint32)cap; // Not known: as MiniAudio reads.
	if (need > cap) {
		ma_uint64 fits = 0, past = count; // The most output one cache feeds, found between them.
		while (past - fits > 1) {
			ma_uint64 middle = fits + (past - fits) / 2;
			if (needed(middle) <= cap) fits = middle;
			else past = middle;
		}
		count = fits? (ma_uint32)fits : 1;
		need = needed(count);
	}
	if (!need) return 1; // Fed from the frames cached.
	if (need <= cap) return (ma_uint32)need;
	ma_uint64 loads = (need + cap - 1) / cap;
	return (ma_uint32)((need + loads - 1) / loads);
}
// MiniAudio reads every sound through its linear resampler, at a rate of 1 too, which gives a frame out only once the frame after it comes in, so what it owed at the source's end, which no frame follows, was never played: the last frame, and below a rate of 1 the frames on the way to it, so that a sound of one frame was silent and every sound lost its end, below a rate of 1 cut off at full level. Once the source's end is read, this feeds the resampler one silent frame after it and gives what it owes, as much as the block has room for, over as many blocks as that takes, before MiniAudio stops the sound in its processing after, calling its end callback then, as without this. Owed is as much as it gives out with no frame in but that silent one, and once it took that, with none, counted by MiniAudio's own count of the frames in it needs, so that the source isn't read past its end and the sound's end isn't drawn out with silence. Returns the frames given.
static ma_uint32 give_end(ma_node* node, const float** frames_in, ma_uint32* frame_count_in, float* out, ma_uint32 room) {
	ma_sound* s = (ma_sound*)node;
	held_sound* h = held(s);
	h->end_state = held_sound::end_flush::given;
	hold_rate(node); // As before each later call in a block, so that MiniAudio doesn't set the resampler itself, from the doppler ratio its spatializer worked out unheld.
	ma_resampler* resampler = &s->engineNode.resampler;
	ma_uint32 source_channels = 0;
	if (!s->pProcessingCache || !s->processingCacheCap || reinterpret_cast<std::atomic<ma_bool32>*>(&s->engineNode.isPitchDisabled)->load() || ma_data_source_get_data_format(s->pDataSource, nullptr, &source_channels, nullptr, nullptr, 0) != MA_SUCCESS || !source_channels) return 0;
	const ma_uint64 frames_in_left = h->end_silence_taken? 0 : 1;
	auto fits = [resampler, frames_in_left](ma_uint64 count) {
		ma_uint64 needed = 0;
		return ma_resampler_get_required_input_frame_count(resampler, count, &needed) == MA_SUCCESS && needed <= frames_in_left;
	};
	ma_uint64 owed = 0, past = 1; // The most that fit, found between them.
	while (past < 0x100000000ull && fits(past)) {
		owed = past;
		past *= 2;
	}
	while (past - owed > 1) {
		ma_uint64 middle = owed + (past - owed) / 2;
		if (fits(middle)) owed = middle;
		else past = middle;
	}
	if (!owed) return 0;
	std::fill_n(s->pProcessingCache, source_channels, 0.0f); // Fed again once taken, so that MiniAudio's processing runs the resampler, which then takes none.
	s->processingCacheFramesRemaining = 1;
	std::atomic<ma_bool32>& at_end = *reinterpret_cast<std::atomic<ma_bool32>*>(&s->atEnd);
	h->flushing.store(true);
	at_end.store(MA_FALSE);
	ma_uint32 count = (ma_uint32)std::min<ma_uint64>(room, owed);
	g_ma_sound_process(node, frames_in, frame_count_in, &out, &count);
	if (!h->end_silence_taken && !s->processingCacheFramesRemaining) h->end_silence_taken = true;
	s->processingCacheFramesRemaining = 0;
	at_end.store(MA_TRUE);
	h->flushing.store(false);
	if (count < owed) h->end_state = held_sound::end_flush::giving; // The rest in the next block.
	return count;
}
// MiniAudio's processing of a sound plays first from a cache of the source's frames it read and converted to float but hadn't played yet, up to a block of them. A seek, made there from seekTarget, moved the source but kept the cache, so a sound not read in whole blocks, at a pitch other than 1 or a source rate other than the engine's, played up to that many frames from where it had been, at a pitch of 0.3 for 18 ms; the seek is made here, from the sound's own target, the cache emptied with it, and the target cleared only after it, as MiniAudio does, as the sound's position reads the target until then. MiniAudio's seekTarget is left unset: taken over from there, a seek stored just after the takeover looked was still made by MiniAudio's own code in the call that followed. A sound at its end is stopped in the block first, and a seek kept for when it plays again, as MiniAudio keeps it. And when a read that refills the cache returns MA_BUSY with frames, as a stream does while its next page is being decoded or a seek is being made, MiniAudio ends the call before playing them, so the rest of the block was silent while they waited a block; it is called again then, for the rest of the block, playing the cache first. On the thread reading the engine.
// Whether a sound is at its end, as another thread than the audio thread sees it: give_end() turns the end flag off while it flushes the end (see held_sound::flushing), which then read as a sound playing on, so that play() was left by ma_sound_start() to a sound about to stop, and at_end read false. Read so that the flag turned back on between the reads is seen.
static bool at_end_seen(ma_sound* s) { return ma_sound_at_end(s) || held(s)->flushing.load() || ma_sound_at_end(s); }
// Plays a sound at its end on from its start, as ma_sound_start() does, by a seek made in held_sound_process(), one made meanwhile standing.
static void start_from_start(ma_sound* s) {
	ma_uint64 none = ~(ma_uint64)0;
	held(s)->seek_target.compare_exchange_strong(none, 0);
	reinterpret_cast<std::atomic<ma_bool32>*>(&s->atEnd)->store(MA_FALSE);
}
// MiniAudio's fader stops at 2^32 - 1 frames from where its fade was set, processing no frames after, so a sound or group played on unfaded from there, part of a block first: a sound held at a fade of its own, or faded to silence, came back at full volume some 25 hours on at 48 kHz. One whose cursor passed 2^31 is set afresh from where it got to, its cursor back at 0: at its end volume past its fade, the rest of its fade from the volume it reached otherwise. Only the thread reading the engine writes the fader; the script's fades reach it through MiniAudio's fade settings.
static void keep_fader_in_range(ma_sound* s) {
	ma_fader& fader = s->engineNode.fader;
	if (fader.cursorInFrames <= (ma_int64)INT_MAX) return;
	if ((ma_uint64)fader.cursorInFrames >= fader.lengthInFrames) {
		fader.volumeBeg = fader.volumeEnd;
		fader.lengthInFrames = 0;
	} else {
		fader.volumeBeg = ma_fader_get_current_volume(&fader);
		fader.lengthInFrames -= (ma_uint64)fader.cursorInFrames;
	}
	fader.cursorInFrames = 0;
}
// MiniAudio places a fade given an absolute start, as ma_sound_stop_with_fade_in_*() gives one, by setting its fader's cursor to how far the engine's time is past that start when it takes the fade: with the engine's time moved on past 2^32 frames meanwhile, as set_time_in_frames() can, that cursor overran MiniAudio's fader processing, which wrote past the block. NVGT's own fades wait in the sound instead (see held_sound::fade_at); one C++ code or a plugin gave MiniAudio itself, more than 2^31 frames behind, is taken here from the current frame, over what is left, as give_deferred_fade() gives one. One less far behind is left to MiniAudio, which counts the time since its start whenever it takes it. It narrows rather than closes the window, as MiniAudio reads the engine's time again later in the block.
static void take_past_fade(ma_sound* s) {
	auto& settings = s->engineNode.fadeSettings;
	std::atomic<ma_uint64>& length_field = *reinterpret_cast<std::atomic<ma_uint64>*>(&settings.fadeLengthInFrames);
	std::atomic<ma_uint64>& at_field = *reinterpret_cast<std::atomic<ma_uint64>*>(&settings.absoluteGlobalTimeInFrames);
	const ma_uint64 length = length_field.load();
	if (length == ~(ma_uint64)0) return; // None waiting.
	const ma_uint64 at = at_field.load(), now = ma_engine_get_time_in_pcm_frames(ma_sound_get_engine(s));
	if (at == ~(ma_uint64)0 || at >= now || now - at <= (ma_uint64)INT_MAX) return; // Now, ahead, or near enough for MiniAudio to place itself.
	std::atomic<float>& beg_field = *reinterpret_cast<std::atomic<float>*>(&settings.volumeBeg);
	const float end = reinterpret_cast<std::atomic<float>*>(&settings.volumeEnd)->load();
	const ma_uint64 elapsed = now - at;
	const float beg = beg_field.load();
	if (elapsed < length) {
		if (beg >= 0) beg_field.store(beg + (end - beg) * (float)((double)elapsed / (double)length)); // A negative beginning is the volume the sound is at, which it fades from over what is left, as give_deferred_fade() gives it.
		length_field.store(length - elapsed);
	} else {
		beg_field.store(end);
		length_field.store(0);
	}
	at_field.store(~(ma_uint64)0);
}
// Gives MiniAudio the fade scheduled ahead in the sound in the block of frames its time falls in (see held_sound::fade_at), before MiniAudio's processing, which takes it in the same block. Under fade_locked.
static void give_deferred_fade(ma_sound* s, ma_uint32 frames) {
	held_sound* h = held(s);
	if (!h->fade_pending.load(std::memory_order_relaxed)) return;
	// The block's first frame the sound plays, which is its start when that is scheduled within the block, MiniAudio then processing it from there.
	ma_uint64 now = ma_engine_get_time_in_pcm_frames(ma_sound_get_engine(s)), start = ma_node_get_state_time(s, ma_node_state_started);
	if (start > now) now = start;
	const ma_uint64 at = h->fade_at;
	if (at != ~(ma_uint64)0 && (at <= now || at - now < frames)) {
		// Given in the block it begins in, from the sound's first frame there, rather than in the first block starting past it: a stop's fade beginning and ending within one block, as a short one did more often than not, was never given, the sound stopped before the next, and cut off unfaded. It may begin up to a block early, still ending when it would have.
		// Given at the volume it got to by then, never with its past start, from which MiniAudio would count its fader's cursor: past 2^32 frames that cursor overran the fader's processing, which wrote past the block.
		const ma_uint64 length = h->fade_length, elapsed = at < now? now - at : 0;
		// One from the volume the sound is at, replacing in MiniAudio's settings a fade set at once that MiniAudio hasn't taken, begins at the volume that fade puts the sound at, also when given again: from the fader's own, a stop's fade after play() reset a sound pause_fade() had faded to 0 began at 0, cut to silence rather than fading.
		if (h->fade_beg < 0 && h->now_given_volume >= 0) h->fade_beg = h->now_given_volume;
		h->now_given_volume = -1;
		float beg = h->fade_beg, end = h->fade_end;
		ma_uint64 given = 0;
		if (elapsed < length) {
			if (beg >= 0) beg += (end - beg) * (float)((double)elapsed / (double)length); // A negative beginning is the volume the sound is at.
			const ma_uint64 early = at > now? at - now : 0, left = length - elapsed;
			given = left >= UINT_MAX - early? UINT_MAX : left + early; // MiniAudio's own limit, under its ~0 for no fade, which lost a fade that long.
		} else beg = end;
		ma_sound_set_fade_start_in_pcm_frames(s, beg, end, given, ~(ma_uint64)0);
		h->fade_given = true;
		h->given_length = given;
		h->fade_pending.store(false, std::memory_order_relaxed);
	}
}
// Gives MiniAudio, before its processing and under one try of the fade lock, the fade set at once (see held_sound::now_pending), then the fade scheduled ahead if it begins in this block, which replaces it in MiniAudio's settings, as when the script's thread wrote the one and the audio thread gave the other. A scheduled fade is given only once no fade set at once still waits, which would otherwise be given in a later block and replace the fade the script scheduled after it: a stop's fade lost, the sound back at full volume and cut at the stop. When the lock is busy, as while the script sets a fade, both wait for the next block.
static void give_fades(ma_sound* s, ma_uint32 frames) {
	held_sound* h = held(s);
	if (!h->now_pending.load(std::memory_order_acquire) && !h->fade_pending.load(std::memory_order_acquire)) return;
	if (h->fade_locked.exchange(true)) return;
	// Once MiniAudio took the fade set at once, it marked its settings so, and a fade replacing them begins from the fader's own volume.
	if (h->now_given_volume >= 0 && reinterpret_cast<std::atomic<ma_uint64>*>(&s->engineNode.fadeSettings.fadeLengthInFrames)->load() == ~(ma_uint64)0) h->now_given_volume = -1;
	if (h->now_pending.load(std::memory_order_relaxed) && !h->fade_given && !h->given_stale) { // Not before take_back_fade() dealt with a fade given before, which it would take this one for.
		ma_sound_set_fade_start_in_pcm_frames(s, h->now_beg, h->now_end, h->now_length, ~(ma_uint64)0);
		h->now_pending.store(false, std::memory_order_relaxed);
		h->now_given_volume = h->now_length? h->now_beg : h->now_end;
	}
	if (!h->now_pending.load(std::memory_order_relaxed)) give_deferred_fade(s, frames);
	h->unlock_fade();
}
// After the sound's processing: a fade given in this block that MiniAudio didn't take, as it takes one only when it has frames to process, none while a stream seeks or waits for data, is taken back to be given again with the time since counted, rather than taken later from where it was given and cut off by its stop; one it took is done with. A fade the script replaced meanwhile, or one MiniAudio was given since by other code, is left alone.
// Removes from MiniAudio's settings a fade the sound gave it, this long, that MiniAudio hasn't taken: whether it did. Under fade_locked.
static bool remove_untaken_fade(ma_sound* s, ma_uint64 given) {
	std::atomic<ma_uint64>& length_field = *reinterpret_cast<std::atomic<ma_uint64>*>(&s->engineNode.fadeSettings.fadeLengthInFrames);
	return length_field.load() == given && reinterpret_cast<std::atomic<ma_uint64>*>(&s->engineNode.fadeSettings.absoluteGlobalTimeInFrames)->load() == ~(ma_uint64)0 && length_field.compare_exchange_strong(given, ~(ma_uint64)0);
}
static void take_back_fade(ma_sound* s) {
	held_sound* h = held(s);
	if ((!h->fade_given && !h->given_stale) || h->fade_locked.exchange(true)) return; // Only the audio thread sets fade_given; under the lock, the script only clears it, or turns it into given_stale.
	if (h->fade_given || h->given_stale) {
		const bool untaken = remove_untaken_fade(s, h->given_length);
		// A replaced one MiniAudio didn't take is removed, never heard, as one replaced after it was taken back is dropped; the one scheduled since stays.
		if (h->fade_given) {
			if (untaken) h->fade_pending.store(true, std::memory_order_release);
			else h->fade_at = ~(ma_uint64)0;
		}
		h->fade_given = false;
		h->given_stale = false;
	}
	h->unlock_fade();
}
static void held_sound_process(ma_node* node, const float** frames_in, ma_uint32* frame_count_in, float** frames_out, ma_uint32* frame_count_out) {
	hold_rate(node);
	ma_sound* s = (ma_sound*)node;
	held(s)->processed.fetch_add(1, std::memory_order_relaxed);
	held(s)->block_set.store(held(s)->time_sets? held(s)->time_sets->load() : 0);
	held(s)->block_at.store(ma_engine_get_time_in_pcm_frames(ma_sound_get_engine(s))); // Before the fade's lock is tried, in the order a script thread holding it reads them (see sound_impl::schedule_stop_and_fade()).
	take_back_fade(s); // One the end of the block before couldn't, the script holding the fade's lock then.
	keep_fader_in_range(s);
	std::atomic<ma_uint64>& seek_target = held(s)->seek_target;
	// A seek given to MiniAudio itself, as by C++ code holding the ma_sound, is moved to the sound's target, to be made as the script's are; MiniAudio's own processing would keep the cache and seek a stream every block.
	std::atomic<ma_uint64>& given_target = *reinterpret_cast<std::atomic<ma_uint64>*>(&s->seekTarget);
	if (given_target.load() != ~(ma_uint64)0) {
		ma_uint64 given = given_target.exchange(~(ma_uint64)0);
		if (given != ~(ma_uint64)0) seek_target.store(given);
	}
	// A stream seeks on the resource manager's job thread, taking a place in its job queue and in the stream's order of execution before it posts the job; when the queue was full, MiniAudio kept both, and the stream returned MA_BUSY for good and couldn't be closed. A sound seeked every block, read faster than it plays, filled it. While a stream's seek is still being made, so that it would only return MA_BUSY and play nothing, the block is left silent without making the next seek, which waits for the stream.
	ma_resource_manager_data_stream* stream = held(s)->stream;
	if (stream && seek_target.load() != ~(ma_uint64)0 && reinterpret_cast<std::atomic<ma_bool32>*>(&stream->seekCounter)->load() > 0) {
		*frame_count_out = 0;
		held(s)->block_done.store(held(s)->block_at.load());
		return;
	}
	give_fades(s, *frame_count_out);
	take_past_fade(s);
	held_sound* h = held(s);
	int asked = held_sound::restart_asked;
	if (h->restart.compare_exchange_strong(asked, held_sound::restart_taking)) {
		if (ma_sound_at_end(s)) start_from_start(s);
		h->restart.store(held_sound::restart_none);
	}
	// Looping turned on at the source's end, while what the resampler owed was being given or before MiniAudio stopped the sound for it: it plays on from the loop's start, as from a looping source's end, rather than stopping, as play_looped() says it plays. Before a seek made meanwhile, which then is made. Not when the source can't seek there, nor when its pass gave nothing since the last such start, as for a source with no frames, which MiniAudio stops at its end, rather than started over every block.
	if (ma_sound_at_end(s) && ma_data_source_is_looping(s->pDataSource)) {
		ma_uint64 loop_begin = 0, loop_end = 0, cursor = ~(ma_uint64)0;
		ma_data_source_get_loop_point_in_pcm_frames(s->pDataSource, &loop_begin, &loop_end);
		ma_data_source_get_cursor_in_pcm_frames(s->pDataSource, &cursor);
		if (cursor != h->restart_cursor && ma_data_source_seek_to_pcm_frame(s->pDataSource, loop_begin) == MA_SUCCESS) {
			h->restart_cursor = loop_begin;
			ma_data_source_get_cursor_in_pcm_frames(s->pDataSource, &h->restart_cursor); // Where the seek left it, as a decoder that finished stays at its end (see held_decoder_seek()), started over every block otherwise.
			s->processingCacheFramesRemaining = 0;
			reinterpret_cast<std::atomic<ma_bool32>*>(&s->atEnd)->store(MA_FALSE);
		}
	}
	ma_uint64 target = seek_target.load();
	if (target != ~(ma_uint64)0 && !ma_sound_at_end(s)) { // ~0 is "no seek", as for MiniAudio.
		ma_data_source_seek_to_pcm_frame(s->pDataSource, target);
		ma_node_set_time(s, target);
		s->processingCacheFramesRemaining = 0;
		seek_target.compare_exchange_strong(target, ~(ma_uint64)0); // A seek made meanwhile stays for the next block.
	}
	ma_uint32 wanted = *frame_count_out, done = 0, channels = ma_node_get_output_channels(node, 0);
	if (!ma_sound_at_end(s)) { // Playing since its last end, if any.
		h->end_state = held_sound::end_flush::none;
		h->end_silence_taken = false;
	}
	bool ending = ma_sound_at_end(s) && h->end_state != held_sound::end_flush::given; // The source's end read in an earlier block, what the resampler owed then not all given yet.
	for (bool first = true; !ending; first = false) {
		if (!first) hold_rate(node); // The doppler ratio MiniAudio's spatializer worked out in the call before, which it applies in this one, held as for the first. A seek made during the block is made at the start of the next.
		ma_uint32 cached = s->processingCacheFramesRemaining;
		float* out = frames_out[0] + (size_t)done * channels;
		ma_uint32 count = wanted - done;
		s->processingCacheCap = bound_read(s, count);
		g_ma_sound_process(node, frames_in, frame_count_in, &out, &count);
		s->processingCacheCap = h->cache_cap;
		done += count;
		// Again while the block has room, the sound isn't at its end and the call got somewhere, as it doesn't on a source not ready.
		if (done >= wanted || ma_sound_at_end(s) || !count && s->processingCacheFramesRemaining == cached) break;
	}
	if (ma_sound_at_end(s) && h->end_state != held_sound::end_flush::given && done < wanted) done += give_end(node, frames_in, frame_count_in, frames_out[0] + (size_t)done * channels, wanted - done);
	asked = held_sound::restart_asked;
	if (!ma_sound_is_playing(s) && ma_sound_at_end(s) && h->restart.compare_exchange_strong(asked, held_sound::restart_taking)) { // Stopped by MiniAudio at its end in this block, after play() came.
		start_from_start(s);
		ma_node_set_state(s, ma_node_state_started);
		h->restart.store(held_sound::restart_none);
	}
	take_back_fade(s);
	*frame_count_out = done;
	h->block_done.store(h->block_at.load());
}
// MiniAudio's buffer of a sound it decodes asynchronously gives, while its job threads decode it, as many frames as the buffer holds rather than as were decoded, the rest the silence it was filled with before the decode or a page half written, and moves its cursor past them: a sound read ahead of the decode, as by an engine without a device read at once, or by any engine after a seek made just after loading or while the job threads were busy, skipped what wasn't decoded yet. Read through this, a buffer still decoding gives no frame past those decoded, returning MA_BUSY, as MiniAudio's buffer of unknown length does, so that a sound at that point waits for them; once decoded, reads go straight through. A count of decoded frames, which MiniAudio stores without ordering the frames before it, is trusted only once the job that may have been writing it is done, so that the frames are seen with it: up to a page behind the decode. A stream, which MiniAudio holds to what it decoded, is read through this too, which ends it at the end of the pass being played when it isn't looping (see decode_front_read()).
struct decode_front_view {
	ma_data_source_base base;
	ma_resource_manager_data_source* inner;
	// The decode as last seen, on the thread reading the sound: the buffer's execution pointer, the count of decoded frames read then, and the count trusted.
	ma_uint32 seen_job = 0;
	ma_uint64 seen_frames = 0, ready_frames = 0;
	bool seen = false;
	// Where a stream played to, its cursor before its last read that gave frames and those frames, unwrapped: a looping stream wraps its cursor at its end, as one of unknown length, a URL's, does at the length it learns there, even when its source can't go back to its start, which then reads nothing more, so that the sound ended with its position at the loop's start rather than where it played to (see sound_impl::get_cursor()).
	std::atomic<ma_uint64> played_to{~(ma_uint64)0};
	~decode_front_view() { ma_data_source_uninit(&base); } // Only views made in full are kept.
};
static ma_result decode_front_read(ma_data_source* source, void* frames_out, ma_uint64 frame_count, ma_uint64* frames_read) {
	decode_front_view* view = (decode_front_view*)source;
	// A stream decodes its pages ahead, looping while it loops, so once looping is turned off its pages can hold its next pass already: read to the end of the pass being played, its end then, which MiniAudio wraps its cursor at.
	if (view->inner->flags & MA_RESOURCE_MANAGER_DATA_SOURCE_FLAG_STREAM) {
		ma_uint64 cursor = 0, length = 0;
		if (!ma_data_source_is_looping(source) && ma_data_source_get_length_in_pcm_frames((ma_data_source*)view->inner, &length) == MA_SUCCESS && length && ma_data_source_get_cursor_in_pcm_frames((ma_data_source*)view->inner, &cursor) == MA_SUCCESS) {
			if (cursor >= length) {
				if (frames_read) *frames_read = 0;
				return MA_AT_END;
			}
			frame_count = std::min(frame_count, length - cursor);
		}
		ma_uint64 before = 0, got = 0;
		bool placed = ma_data_source_get_cursor_in_pcm_frames((ma_data_source*)view->inner, &before) == MA_SUCCESS;
		ma_result result = ma_data_source_read_pcm_frames((ma_data_source*)view->inner, frames_out, frame_count, &got);
		if (got && placed) view->played_to.store(before + got);
		if (frames_read) *frames_read = got;
		return result;
	}
	ma_resource_manager_data_buffer* buffer = &view->inner->backend.buffer;
	ma_resource_manager_data_buffer_node* node = buffer->pNode;
	bool held_back = false;
	// The node's result, which its last page's job sets once its frames are written, rather than the buffer's, set only when the buffer's own job runs again after that.
	if (node && reinterpret_cast<std::atomic<ma_result>*>(&node->result)->load() == MA_BUSY && reinterpret_cast<std::atomic<ma_resource_manager_data_supply_type>*>(&node->data.type)->load() == ma_resource_manager_data_supply_type_decoded) {
		std::atomic<ma_uint32>& pointer = *reinterpret_cast<std::atomic<ma_uint32>*>(&node->executionPointer);
		ma_uint32 job = pointer.load(std::memory_order_acquire);
		if (!view->seen || job != view->seen_job) {
			ma_uint64 frames = reinterpret_cast<std::atomic<ma_uint64>*>(&node->data.backend.decoded.decodedFrameCount)->load(std::memory_order_acquire);
			// Kept only when the pointer hasn't moved meanwhile, so that the count is from the job it was at or an earlier one: a count the next job stored, before it moved the pointer past itself, would otherwise be taken for one of a job done.
			if (pointer.load(std::memory_order_acquire) == job) {
				if (view->seen) view->ready_frames = view->seen_frames; // Written by a job done since.
				view->seen = true;
				view->seen_job = job;
				view->seen_frames = frames;
			}
		}
		ma_uint64 cursor = 0;
		ma_resource_manager_data_buffer_get_cursor_in_pcm_frames(buffer, &cursor);
		ma_uint64 ready = view->ready_frames > cursor? view->ready_frames - cursor : 0;
		if (frame_count > ready) {
			frame_count = ready;
			held_back = true;
		}
		if (!frame_count) {
			if (frames_read) *frames_read = 0;
			return MA_BUSY;
		}
	}
	ma_result result = ma_data_source_read_pcm_frames((ma_data_source*)view->inner, frames_out, frame_count, frames_read);
	return held_back && result == MA_SUCCESS? MA_BUSY : result;
}
static ma_result decode_front_seek(ma_data_source* source, ma_uint64 frame) { return ma_data_source_seek_to_pcm_frame((ma_data_source*)((decode_front_view*)source)->inner, frame); }
static ma_result decode_front_get_data_format(ma_data_source* source, ma_format* format, ma_uint32* channels, ma_uint32* sample_rate, ma_channel* channel_map, size_t channel_map_capacity) { return ma_data_source_get_data_format((ma_data_source*)((decode_front_view*)source)->inner, format, channels, sample_rate, channel_map, channel_map_capacity); }
static ma_result decode_front_get_cursor(ma_data_source* source, ma_uint64* cursor) { return ma_data_source_get_cursor_in_pcm_frames((ma_data_source*)((decode_front_view*)source)->inner, cursor); }
static ma_result decode_front_get_length(ma_data_source* source, ma_uint64* length) { return ma_data_source_get_length_in_pcm_frames((ma_data_source*)((decode_front_view*)source)->inner, length); }
static ma_result decode_front_set_looping(ma_data_source* source, ma_bool32 looping) { return ma_data_source_set_looping((ma_data_source*)((decode_front_view*)source)->inner, looping); }
static ma_data_source_vtable g_decode_front_vtable = {decode_front_read, decode_front_seek, decode_front_get_data_format, decode_front_get_cursor, decode_front_get_length, decode_front_set_looping, 0};
// The source a sound reads a resource manager's source through: a decode_front_view of it made in view, which for a stream, which MiniAudio already holds to what it decoded, only ends it at its pass's end when not looping.
static ma_data_source* decode_front(ma_resource_manager_data_source* source, unique_ptr<decode_front_view>& view) {
	view.reset();
	view = make_unique<decode_front_view>();
	ma_data_source_config cfg = ma_data_source_config_init();
	cfg.vtable = &g_decode_front_vtable;
	if (ma_data_source_init(&cfg, &view->base) != MA_SUCCESS) {
		view.reset();
		return (ma_data_source*)source;
	}
	view->inner = source;
	return &view->base;
}
// MiniAudio converts a sound's source that isn't in float in steps, the last of which reads its end and marks the sound at it, ending the block, while that read's frames are still in its cache, so the sound stopped before playing them: sounds from 16-bit files, PCM, tones and speech lost up to a block at their end, a sound shorter than a block played nothing, and the lost part played first when the sound played again. A source in float is read whole, with no such step. So a sound reads a source in another format through this, which reads it and gives its frames in float, everything else passing through: MiniAudio's end then comes with nothing left unplayed in that cache, and the frame its resampler holds is given by held_sound_process(). The sound's own source stays what scripts see, by sound.datasource and in the format sound.get_data_format() gives.
struct float_view {
	ma_data_source_base base;
	ma_data_source* inner;
	ma_format format;
	ma_uint32 channels;
	~float_view() { ma_data_source_uninit(&base); } // Only views made in full are kept.
};
static ma_result float_view_read(ma_data_source* source, void* frames_out, ma_uint64 frame_count, ma_uint64* frames_read) {
	float_view* view = (float_view*)source;
	ma_uint8 temp[4096];
	ma_uint64 capacity = sizeof(temp) / ma_get_bytes_per_frame(view->format, view->channels), total = 0;
	ma_result result = MA_SUCCESS;
	while (total < frame_count) {
		ma_uint64 wanted = std::min(capacity, frame_count - total), got = 0;
		result = ma_data_source_read_pcm_frames(view->inner, temp, wanted, &got);
		ma_convert_pcm_frames_format((float*)frames_out + total * view->channels, ma_format_f32, temp, view->format, got, view->channels, ma_dither_mode_none);
		total += got;
		if (result != MA_SUCCESS || got < wanted) break;
	}
	if (frames_read) *frames_read = total;
	return total? MA_SUCCESS : result;
}
static ma_result float_view_seek(ma_data_source* source, ma_uint64 frame) { return ma_data_source_seek_to_pcm_frame(((float_view*)source)->inner, frame); }
static ma_result float_view_get_data_format(ma_data_source* source, ma_format* format, ma_uint32* channels, ma_uint32* sample_rate, ma_channel* channel_map, size_t channel_map_capacity) {
	ma_result result = ma_data_source_get_data_format(((float_view*)source)->inner, nullptr, channels, sample_rate, channel_map, channel_map_capacity);
	if (format) *format = ma_format_f32;
	return result;
}
static ma_result float_view_get_cursor(ma_data_source* source, ma_uint64* cursor) { return ma_data_source_get_cursor_in_pcm_frames(((float_view*)source)->inner, cursor); }
static ma_result float_view_get_length(ma_data_source* source, ma_uint64* length) { return ma_data_source_get_length_in_pcm_frames(((float_view*)source)->inner, length); }
static ma_result float_view_set_looping(ma_data_source* source, ma_bool32 looping) { return ma_data_source_set_looping(((float_view*)source)->inner, looping); } // A stream loops seamlessly only when it loops itself.
static ma_data_source_vtable g_float_view_vtable = {float_view_read, float_view_seek, float_view_get_data_format, float_view_get_cursor, float_view_get_length, float_view_set_looping, 0};
// The source a sound reads: the one given if it is in float, or else a float_view of it made in view.
static ma_data_source* float_source(ma_data_source* source, unique_ptr<float_view>& view) {
	view.reset();
	ma_format format = ma_format_unknown;
	ma_uint32 channels = 0;
	if (ma_data_source_get_data_format(source, &format, &channels, nullptr, nullptr, 0) != MA_SUCCESS || format == ma_format_f32 || format == ma_format_unknown || !channels) return source;
	view = make_unique<float_view>();
	ma_data_source_config cfg = ma_data_source_config_init();
	cfg.vtable = &g_float_view_vtable;
	if (ma_data_source_init(&cfg, &view->base) != MA_SUCCESS) {
		view.reset();
		return source;
	}
	view->inner = source;
	view->format = format;
	view->channels = channels;
	return &view->base;
}
// A chain of sources a sound plays, from the one its head was on when the sound opened it, read as one source: its length is the chain's, its cursor the place in the whole chain, a seek moves the head onto the source the frame falls in, and its end is the chain's, so MiniAudio loops the whole chain and plays it again from its start once it ended. MiniAudio's own seek, restart and looping reached only the head's own source, while the head read on from wherever the chain had got to: a seek to 0 read 0 and played on in the second source, and a looped chain looped its first source. The links can't change while a sound plays the head, so they are taken once.
struct chain_view {
	ma_data_source_base base;
	ma_data_source* head;
	static constexpr ma_uint64 unknown = ~(ma_uint64)0; // A link's length until known: 0 told an empty source from one not yet known no more, so a chain with an empty source never had a length.
	std::vector<std::pair<ma_data_source*, ma_uint64>> links; // Each source in order, with its length, unknown until known (see learn_lengths()).
	// A link's length, which the audio thread learns as it plays while a script thread reads it.
	std::atomic<ma_uint64>& length_of(size_t index) { return *reinterpret_cast<std::atomic<ma_uint64>*>(&links[index].second); }
	// A source of unknown length that was played through is as long as its cursor reached at its end, which the cursor and length count from then on, rather than as nothing, so the position went back once the chain passed it, and seeks past it were refused for good.
	std::atomic<size_t> last_on{~(size_t)0}; // The link the head was last seen on, none before it was on one.
	void learn_lengths(bool chain_ended, bool was_on_one) {
		ma_data_source* current = ma_data_source_get_current(head);
		size_t on = 0, passed;
		while (on < links.size() && links[on].first != current) on++;
		if (on < links.size()) {
			passed = chain_ended? on + 1 : on; // The links before the one it is on, and that one once the chain ended on it, as MiniAudio leaves a chain's last source current: past the last, it was never learned.
			last_on.store(on, std::memory_order_relaxed);
		} else if (!current && was_on_one && !links.empty()) { // Put on no source by this read, which only an empty pass of the last source, linked to itself, does, once every source from the one it was on played through: all were passed, the last included, rather than only up to the one it was on as the read began. MiniAudio ends such a read with success for the frames it gave.
			passed = links.size();
			last_on.store(links.size() - 1, std::memory_order_relaxed);
		} else {
			size_t last = last_on.load(std::memory_order_relaxed);
			passed = last == ~(size_t)0? 0 : last + 1; // Put on no source or another from outside: passed up to the one it was last on, and none before it was on one, whose cursors at 0 would be learned as empty sources.
		}
		for (size_t index = 0; index < passed; index++) {
			ma_uint64 cursor = 0;
			if (length_of(index).load(std::memory_order_relaxed) == unknown && ma_data_source_get_cursor_in_pcm_frames(links[index].first, &cursor) == MA_SUCCESS) length_of(index).store(cursor, std::memory_order_relaxed); // Passed, so as long as it reached, nothing for an empty one.
		}
	}
	bool endless = false; // The last source links back into the chain, as one set as its own next does, so the chain never ends.
	bool read_through = false; // The last read gave the chain's end.
	bool exhausted = false; // Ended by chain_view_seek(), its links unable to all play again, until a seek it makes.
	std::vector<ma_data_source*> looping_set_aside; // Sources whose own looping is off while the sound plays the chain (see chain_source()), given back after.
	~chain_view() { // Only views made in full are kept.
		for (ma_data_source* source : looping_set_aside) ma_data_source_set_looping(source, MA_TRUE);
		ma_data_source_uninit(&base);
	}
};
static ma_result chain_view_read(ma_data_source* source, void* frames_out, ma_uint64 frame_count, ma_uint64* frames_read) {
	chain_view* view = (chain_view*)source;
	if (view->exhausted) {
		if (frames_read) *frames_read = 0;
		return MA_AT_END;
	}
	bool was_on_one = ma_data_source_get_current(view->head) != nullptr;
	ma_result result = ma_data_source_read_pcm_frames(view->head, frames_out, frame_count, frames_read);
	if (result != MA_SUCCESS && result != MA_AT_END && result != MA_BUSY && decoder_finished(ma_data_source_get_current(view->head))) result = frames_read && *frames_read? MA_SUCCESS : MA_AT_END; // A ring of links that finished (see held_decoder_seek()): the chain's end.
	view->read_through = result == MA_AT_END;
	view->learn_lengths(result == MA_AT_END, was_on_one);
	return result;
}
static ma_result chain_view_seek(ma_data_source* source, ma_uint64 frame) {
	chain_view* view = (chain_view*)source;
	size_t index = 0;
	ma_uint64 offset = 0;
	for (ma_uint64 length; index + 1 < view->links.size() && (length = view->length_of(index).load(std::memory_order_relaxed)) != chain_view::unknown && frame >= offset + length; index++) offset += length; // The source the frame falls in, past empty ones, or the last.
	// A chain read to its end, as when its loop or play() starts it again, whose links from the one sought can't all play again, as one that played through a source that can't seek: exhausted, which ends it where it is, rather than playing for good only the links that can; a script's call is told the error. Not by putting the head on no source, which MiniAudio reads as the head itself when it has no next of its own, and which would undo a head's set_current().
	if (view->read_through) {
		for (size_t later = index; later < view->links.size(); later++) {
			ma_result again = start_again(view->links[later].first);
			if (again == MA_SUCCESS) continue;
			if (t_script_seek) return again;
			view->exhausted = true;
			return MA_SUCCESS;
		}
	}
	ma_result result = ma_data_source_seek_to_pcm_frame(view->links[index].first, frame - offset);
	if (result == MA_SUCCESS) {
		view->read_through = false;
		view->exhausted = false;
		ma_data_source_set_current(view->head, view->links[index].first);
		view->last_on.store(index, std::memory_order_relaxed);
	}
	return result;
}
static ma_result chain_view_get_data_format(ma_data_source* source, ma_format* format, ma_uint32* channels, ma_uint32* sample_rate, ma_channel* channel_map, size_t channel_map_capacity) { return ma_data_source_get_data_format(((chain_view*)source)->head, format, channels, sample_rate, channel_map, channel_map_capacity); } // A chain's sources all have the head's (see audio_data_source_impl::can_chain()).
static ma_result chain_view_get_cursor(ma_data_source* source, ma_uint64* cursor) {
	chain_view* view = (chain_view*)source;
	ma_data_source* current = ma_data_source_get_current(view->head);
	ma_uint64 offset = 0;
	for (size_t index = 0; index < view->links.size(); index++) {
		if (view->links[index].first == current) {
			ma_uint64 within = 0;
			ma_result result = ma_data_source_get_cursor_in_pcm_frames(current, &within);
			*cursor = offset + within;
			return result;
		}
		ma_uint64 length = view->length_of(index).load(std::memory_order_relaxed);
		if (length != chain_view::unknown) offset += length; // One not yet known is ahead of the current source, which passing it learns.
	}
	// On no source: past the one it was last on, the last once an empty pass ended the chain, or at the start before it was on one, rather than past every source.
	offset = 0;
	size_t last = view->last_on.load(std::memory_order_relaxed);
	for (size_t index = 0; last != ~(size_t)0 && index <= last && index < view->links.size(); index++) {
		ma_uint64 length = view->length_of(index).load(std::memory_order_relaxed);
		if (length != chain_view::unknown) offset += length;
	}
	*cursor = offset;
	return MA_SUCCESS;
}
static ma_result chain_view_get_length(ma_data_source* source, ma_uint64* length) {
	chain_view* view = (chain_view*)source;
	*length = 0;
	if (view->endless && view->links.size() > 1) return MA_NOT_IMPLEMENTED; // A single source linked to itself has its own length.
	for (size_t index = 0; index < view->links.size(); index++) {
		ma_uint64 link_length = view->length_of(index).load(std::memory_order_relaxed);
		if (link_length == chain_view::unknown) {
			*length = 0;
			return MA_NOT_IMPLEMENTED;
		}
		*length += link_length;
	}
	return MA_SUCCESS;
}
static ma_data_source_vtable g_chain_view_vtable = {chain_view_read, chain_view_seek, chain_view_get_data_format, chain_view_get_cursor, chain_view_get_length, nullptr, 0}; // Looping is the view's own, which MiniAudio keeps, rather than the head's, which loops only the source it is on.
// The source a sound opening head reads: a chain_view made in view when head is in a chain, or is on another source, else head itself.
static ma_data_source* chain_source(ma_data_source* head, audio_engine* engine, unique_ptr<chain_view>& view) {
	view.reset();
	ma_data_source* start = ma_data_source_get_current(head);
	if (!start) { // On no source, as after set_current(null) or an empty pass that ended it, which reads as the chain's end: put back on itself and at its start, as a rewind does, so the first play plays the chain from the head rather than ending at once, or playing nothing from the end a pass left the head at.
		ma_data_source_set_current(head, head);
		ma_data_source_seek_to_pcm_frame(head, 0);
		start = head;
	}
	std::vector<std::pair<ma_data_source*, ma_uint64>> links;
	bool endless = false;
	for (ma_data_source* link = start; link; link = next_in_chain(link)) {
		if (std::any_of(links.begin(), links.end(), [link](const auto& known) { return known.first == link; })) {
			endless = true;
			break;
		}
		ma_uint64 length = 0;
		if (audio_data_source* wrapper = audio_data_source_get(link, engine)) { // Its length worked out, as a decoder's is only while nothing reads it.
			auto impl = dynamic_cast<audio_data_source_impl*>(wrapper);
			length = !impl || impl->whole_length_frames()? wrapper->get_length_frames() : 0; // With its whole length unknown or 0, a range with an end counts as its own length, which may run past what the source holds: unknown instead, learned once passed.
			wrapper->release();
		} else if (ma_data_source_get_length_in_pcm_frames(link, &length) != MA_SUCCESS) length = 0;
		links.emplace_back(link, length? length : chain_view::unknown); // 0 is also unknown, which an empty source is learned as once passed.
	}
	if (start == head && links.size() < 2 && !endless) return head; // No chain: read as it is. A source linked to itself is read through a view, whose seek puts it back on itself once an empty pass ended it (see next_of_self_linked()).
	view = make_unique<chain_view>();
	ma_data_source_config cfg = ma_data_source_config_init();
	cfg.vtable = &g_chain_view_vtable;
	if (ma_data_source_init(&cfg, &view->base) != MA_SUCCESS) {
		view.reset();
		return head;
	}
	view->head = head;
	view->links = std::move(links);
	view->endless = endless;
	// The sound's looping alone decides, as play() and play_looped() set a single source's own: a head's own looping looped only the source it was on, so the chain never got past it while the sound read as not looping, and a source's own looping ended its part at its loop point. Set aside while the sound plays the chain and given back after; the sources can't be changed meanwhile.
	auto set_aside = [&view](ma_data_source* source) {
		if (!ma_data_source_is_looping(source) || std::find(view->looping_set_aside.begin(), view->looping_set_aside.end(), source) != view->looping_set_aside.end()) return;
		view->looping_set_aside.push_back(source);
		ma_data_source_set_looping(source, MA_FALSE);
	};
	set_aside(head);
	for (const auto& link : view->links) set_aside(link.first);
	return &view->base;
}
static void held_group_process(ma_node* node, const float** frames_in, ma_uint32* frame_count_in, float** frames_out, ma_uint32* frame_count_out) {
	held_sound* h = held((ma_sound*)node);
	h->block_set.store(h->time_sets? h->time_sets->load() : 0);
	h->block_at.store(ma_engine_get_time_in_pcm_frames(ma_sound_get_engine((ma_sound*)node))); // As for a sound, by which a stop within the block a mixer played past counts as come (see mixer_impl::heard_until()).
	hold_rate(node);
	keep_fader_in_range((ma_sound*)node);
	give_fades((ma_sound*)node, *frame_count_out);
	take_past_fade((ma_sound*)node);
	g_ma_group_process(node, frames_in, frame_count_in, frames_out, frame_count_out);
	h->block_done.store(h->block_at.load());
}
// Gives a sound or group that was made but isn't attached to anything yet hold_rate()'s processing: a copy of MiniAudio's node vtable for its kind, whose processing holds the rate first.
static void hold_rate_of(ma_sound* s, audio_engine* engine) {
	if (audio_engine_impl* impl = dynamic_cast<audio_engine_impl*>(engine)) held(s)->time_sets = impl->time_sets; // Per engine: another engine's time set leaves this one's records alone.
	static std::mutex vtables_mutex;
	std::lock_guard<std::mutex> lock(vtables_mutex);
	ma_node_base* node = (ma_node_base*)s;
	bool group = ma_node_get_input_bus_count(node) > 0; // Sounds read their source and have no input.
	ma_node_vtable& vtable = group? g_held_group_vtable : g_held_sound_vtable;
	auto& process = group? g_ma_group_process : g_ma_sound_process;
	if (!process) {
		vtable = *node->vtable;
		process = vtable.onProcess;
		vtable.onProcess = group? held_group_process : held_sound_process;
	}
	node->vtable = &vtable;
}
ma_sound* rate_bridge_create(audio_engine* engine, unsigned int channels, unsigned int sample_rate) {
	held_sound_ptr bridge(new held_sound());
	ma_sound_group_config cfg = ma_sound_group_config_init_2(engine->get_ma_engine());
	cfg.flags = MA_SOUND_FLAG_NO_DEFAULT_ATTACHMENT | MA_SOUND_FLAG_NO_SPATIALIZATION;
	cfg.channelsIn = cfg.channelsOut = channels;
	if ((g_soundsystem_last_error = ma_sound_group_init_ex(engine->get_ma_engine(), &cfg, &*bridge)) != MA_SUCCESS) return nullptr;
	// Its input at the given rate, as a sound's source of another rate: resampled from it exactly, at a pitch of 1, rather than at a pitch of the ratio, which MiniAudio keeps to a thousandth, cut down.
	bridge->engineNode.sampleRate = sample_rate;
	if ((g_soundsystem_last_error = ma_resampler_set_rate(&bridge->engineNode.resampler, sample_rate, ma_engine_get_sample_rate(engine->get_ma_engine()))) != MA_SUCCESS) {
		ma_sound_group_uninit(&*bridge);
		return nullptr;
	}
	hold_rate_of(&*bridge, engine); // As a mixer's group, so that what is read through it is held to max_pitch_ratio with its rate counted.
	return bridge.release();
}
void rate_bridge_destroy(ma_sound* bridge) {
	ma_sound_group_uninit(bridge);
	held_sound_delete()(bridge);
}
class mixer_impl : public audio_node_impl, public virtual mixer {
	friend class audio_node_impl;
	// In miniaudio, a sound_group is really just a sound. A typical ma_sound_group_x function looks like float ma_sound_group_get_pan(const ma_sound_group* pGroup) { return ma_sound_get_pan(pGroup); }.
	// Furthermore ma_sound_group is just a typedef for ma_sound. As such, for the sake of less code and better inheritance, we will directly call the ma_sound APIs in this class even though it deals with sound groups and not sounds.
protected:
	held_sound_ptr snd;
	mixer *parent_mixer;
	sound_shape* shape;
	CScriptHandle shape_handle;
	// With a shape, the position the script set, which MiniAudio's is moved from to the shape's point nearest the listener. Kept here rather than in the shape, as one shape can be given to several sounds.
	reactphysics3d::Vector3 shape_anchor;
	mutable audio_spatializer *spatializer;
	mutex spatialization_params_mutex;
	audio_node_chain* node_chain;
	audio_node_chain* effects_chain;
public:
	mixer_impl(audio_engine *e, bool sound_group = true) : audio_node_impl(nullptr, e), snd(nullptr), shape(nullptr), node_chain(audio_node_chain::create(nullptr, nullptr, e)), effects_chain(nullptr), parent_mixer(nullptr), spatializer(nullptr) {
		init_sound_context();
		node_chain->set_endpoint(e->get_endpoint());
		if (!sound_group) return;
		snd = held_sound_ptr(new held_sound());
		// Not attached by MiniAudio, which would attach a group without a parent to the endpoint at once, while it still had MiniAudio's own processing; it is attached to its chain below.
		{
			std::lock_guard<std::recursive_mutex> graph_lock(g_node_graph_mutex);
			if ((g_soundsystem_last_error = ma_sound_group_init(e->get_ma_engine(), MA_SOUND_FLAG_NO_DEFAULT_ATTACHMENT, nullptr, &*snd)) != MA_SUCCESS) {
				snd.reset(); // Not uninitialised by the destructor, which the constructor throwing doesn't run, nor configured, attached and played as before.
				if (node_chain) node_chain->release();
				throw std::runtime_error("failed to create mixer");
			}
			hold_rate_of(&*snd, e);
		}
		node = (ma_node_base *)&*snd;
		set_max_distance(70);
		ma_sound_group_set_rolloff(&*snd, 0); // Our own spatializer controls attenuation.
		// With MiniAudio's attenuation linear, which a rolloff of 0 leaves at 1: its default inverse model divided 0 by 0 for a min_distance of 0, and the NaN, clamped to the maximum gain, turned the cones off and raised the sound by a maximum gain above 1.
		ma_sound_group_set_attenuation_model(&*snd, ma_attenuation_model_linear);
		ma_sound_group_set_directional_attenuation_factor(&*snd, 0); // Our spatializer also controls panning.
		attach_output_bus(0, node_chain, 0);
		play();
	}
	~mixer_impl() {
		track_shape(false);
		stop();
		unique_lock<mutex> lock(spatialization_params_mutex);
		if (spatializer) {
			spatializer->forget_mixer(); // A spatializer the script kept must not read this mixer once it is gone.
			node_chain->remove_node(spatializer);
			spatializer->release();
		}
		if (node_chain)
			node_chain->release();
		if (effects_chain)
			effects_chain->release();
		if (parent_mixer)
			parent_mixer->release();
		if (shape) shape->release();
		if (snd) { std::lock_guard<std::recursive_mutex> graph_lock(g_node_graph_mutex); ma_sound_group_uninit(&*snd); } // a sound group is a graph node: its uninit edits the endpoint's input list
	}
	audio_spatializer* get_spatializer() const {
		if (!spatializer) {
			audio_spatializer* made = audio_spatializer::create(const_cast<mixer_impl*>(this), get_engine());
			// After the effects chain, which runs first wherever it is made, so that a mixer's effects are positioned with it rather than applied to it once positioned, whichever was made first; a chain the script took out of internal_node_chain leaves the spatializer first.
			if (!effects_chain || !node_chain->add_node(made, effects_chain)) node_chain->add_node(made);
			// Published once made, as the loop check reads it from other threads (see get_reverb3d_sent_to()), which must not see the pointer before what it points to.
			reinterpret_cast<std::atomic<audio_spatializer*>&>(spatializer).store(made, std::memory_order_release);
		}
		return spatializer;
	}
	inline void duplicate() override { audio_node_impl::duplicate(); }
	inline void release() override { audio_node_impl::release(); }
	bool set_mixer(mixer *mix) override {
		if (mix && mix->get_engine() != get_engine()) return false; // Another engine's mixer is in that engine's graph, which would play this one's sound.
		mixer* old;
		{
			std::lock_guard<std::recursive_mutex> topology(g_audio_topology_mutex);
			if (mix == parent_mixer)
				return true; // Already where it was asked to go.
			// Not into itself, nor into a mixer that already goes into this one, through parents or a reverb3d's send: that loop never reaches the engine, and its references to each other keep it all alive.
			if (mix && mixer_reaches(mix, [this](mixer* m) { return m == static_cast<mixer*>(this); })) {
				g_soundsystem_last_error = MA_INVALID_ARGS;
				return false;
			}
			audio_node *target = mix? mix : get_engine()->get_endpoint();
			node_chain->set_endpoint(target);
			if (node_chain->get_endpoint() != target) return false; // It couldn't attach, as to a node without an input, which leaves this where it was.
			// Held by this mixer too, not only through the chain, whose endpoint the rewiring above let go of and a script can change through internal_node_chain.
			if (mix) mix->duplicate();
			old = parent_mixer;
			parent_mixer = mix;
		}
		if (old) old->release(); // After the topology lock: it can be the last reference.
		return true;
	}
	mixer *get_mixer() const override { return parent_mixer; }
	void set_3d_panner(int panner_id) override {
		get_spatializer()->set_panner_by_id(panner_id);
	}
	int get_3d_panner() const override { return get_spatializer()->get_current_panner_id(); }
	void set_3d_attenuator(int attenuator_id) override {
		get_spatializer()->set_attenuator_by_id(attenuator_id);
	}
	int get_3d_attenuator() const override { return get_spatializer()->get_current_attenuator_id(); }
	int get_preferred_3d_panner() const override { return get_spatializer()->get_preferred_panner_id(); }
	int get_preferred_3d_attenuator() const override { return get_spatializer()->get_preferred_attenuator_id(); }
	void set_hrtf(bool enabled) override {
		if (enabled) {
			get_spatializer()->set_panner_by_id(g_audio_phonon_hrtf_panner);
			get_spatializer()->set_attenuator_by_id(g_audio_phonon_attenuator);
		} else {
			get_spatializer()->set_panner_by_id(g_audio_basic_panner);
			get_spatializer()->set_attenuator_by_id(g_audio_basic_attenuator);
		}
	}
	bool get_hrtf() const override { return get_spatializer()->get_preferred_panner_id() == g_audio_phonon_hrtf_panner && get_spatializer()->get_preferred_attenuator_id() == g_audio_phonon_attenuator; }
	bool set_shape(CScriptHandle new_shape) override {
		// A type no shape is made from leaves the old shape in place.
		int ot = new_shape.GetTypeId() ^ asTYPEID_OBJHANDLE;
		if (new_shape.GetRef() && !g_sound_shape_setup_callbacks.contains(ot)) return false;
		// The position the script set, kept with the old shape; MiniAudio's is the one the shape moved to its edge.
		reactphysics3d::Vector3 position = get_position_3d();
		// release old shape, swapped out under the lock the audio thread reads the shape under, through get_spatialization_parameters().
		sound_shape* old_shape;
		{
			unique_lock<mutex> lock(spatialization_params_mutex);
			old_shape = shape;
			shape = nullptr;
		}
		shape_handle = CScriptHandle();
		if (old_shape) old_shape->release();
		if (!new_shape.GetRef()) { // A null shape clears it, which is done, back at the position the script set.
			track_shape(false);
			if (snd && get_spatialization_enabled()) set_position_3d(position.x, position.y, position.z);
			else if (snd) { // Back at the script's position without spatializing it, rather than left at the shape's point, which the position read and the sound played from once spatialized.
				unique_lock<mutex> lock(spatialization_params_mutex);
				ma_sound_set_position(&*snd, position.x, position.y, position.z);
			}
			return true;
		}
		sound_shape* new_shape_obj = g_sound_shape_setup_callbacks[ot](this, &new_shape);
		if (!new_shape_obj) {
			track_shape(false);
			return false;
		}
		new_shape_obj->set_position(position);
		{
			unique_lock<mutex> lock(spatialization_params_mutex);
			shape = new_shape_obj;
			shape_anchor = position;
		}
		shape_handle = new_shape;
		track_shape(true);
		if (snd && get_spatialization_enabled()) set_position_3d(position.x, position.y, position.z); // Applied now rather than at the next set_position_3d(), for a sound already placed, which set_position_3d() would otherwise make spatialized.
		return true;
	}
	CScriptHandle get_shape() const override {
		if (!shape) return CScriptHandle();
		return shape_handle;
	}
	sound_shape* get_shape_object() const override { return shape; }
	void set_reverb3d(reverb3d* verb) override { get_spatializer()->set_reverb3d(verb); }
	void set_reverb3d_at(reverb3d* verb, audio_spatializer_reverb3d_placement placement) override { get_spatializer()->set_reverb3d(verb, placement); }
	reverb3d* get_reverb3d() const override { return get_spatializer()->get_reverb3d(); }
	reverb3d* get_reverb3d_sent_to() const override { // Read by the loop check of another thread, under the topology lock, which close() clears this under (see get_spatializer()).
		audio_spatializer* sending = reinterpret_cast<std::atomic<audio_spatializer*>&>(spatializer).load(std::memory_order_acquire);
		return sending? sending->get_reverb3d() : nullptr;
	}
	splitter_node* get_reverb3d_attachment() const override { return get_spatializer()->get_reverb3d_attachment(); }
	audio_spatializer_reverb3d_placement get_reverb3d_placement() const override { return get_spatializer()->get_reverb3d_placement(); }
	audio_node_chain* get_effects_chain() override {
		if (!effects_chain) {
			effects_chain = audio_node_chain::create(nullptr, nullptr, get_engine());
			node_chain->add_node(effects_chain); // First, before the spatializer: see get_spatializer().
		}
		return effects_chain;
	}
	audio_node_chain* get_internal_node_chain() override { return node_chain; }
	// The cone and the gain range the script set, which NVGT's attenuators apply with the distance's volume, clamping the two together once (see get_cone_volume()). MiniAudio's own are left at their defaults, which apply nothing: it applied the cone's volume clamped to the gain range, smoothed, and the attenuators clamping again applied max_gain twice, while dividing MiniAudio's part back out couldn't follow its smoothing.
	std::atomic<float> cone_inner{6.283185f}, cone_outer{6.283185f}, cone_outer_gain{0}, min_gain{0}, max_gain{1};
	void reset_cone_and_gain_range() { cone_inner = 6.283185f; cone_outer = 6.283185f; cone_outer_gain = 0; min_gain = 0; max_gain = 1; } // MiniAudio's defaults, which a newly made sound had.
	bool last_parameters_valid = false; // What get_spatialization_parameters() last answered; only the audio thread reads and writes it.
	bool get_spatialization_parameters(audio_spatialization_parameters& params) override {
		// The audio thread mustn't wait for the lock, which a script thread holds briefly, as set_position_3d() does at each call. While it is busy the spatializer keeps the parameters it was last given, which params still holds, rather than playing that block unattenuated and unpanned, as answering that there were none did.
		if (!spatialization_params_mutex.try_lock()) return last_parameters_valid;
		// Checked under the lock a sound's loads hand snd over and close() lets go of the spatializer under; without a spatializer there is no rolloff to give, and get_spatializer() would make one, which the audio thread mustn't.
		if (!snd || !spatializer || !get_spatialization_enabled()) {
			spatialization_params_mutex.unlock();
			return last_parameters_valid = false;
		}
		reactphysics3d::Vector3 listener_pos = get_engine()->get_listener_position(get_listener()), listener_dir = get_direction_to_listener();
		ma_vec3f pos = ma_sound_get_position(&*snd); // Where the sound plays from, which the distance and direction above are from too: a shaped sound's get_position_3d() is the position the script set, not the shape's point it plays from.
		params.listener_x = listener_pos.x;
		params.listener_y = listener_pos.y;
		params.listener_z = listener_pos.z;
		params.listener_direction_x = listener_dir.x * -1;
		params.listener_direction_y = listener_dir.y * -1;
		params.listener_direction_z = listener_dir.z * -1;
		params.listener_distance = get_distance_to_listener();
		params.sound_x = pos.x;
		params.sound_y = pos.y;
		params.sound_z = pos.z;
		params.min_distance = get_min_distance();
		params.max_distance = get_max_distance();
		params.min_volume = get_min_gain();
		params.max_volume = get_max_gain();
		params.rolloff = spatializer->get_rolloff();
		params.cone_volume = get_cone_volume();
		params.distance_model = linear;
		spatialization_params_mutex.unlock();
		return last_parameters_valid = true;
	}
	// The gain MiniAudio's spatializer gives the sound for its cone and its listener's, worked out as ma_spatializer_process_pcm_frames() does with the listener it uses, before it clamps that to the minimum and maximum gain.
	float get_cone_volume() const {
		ma_engine* e = get_engine()->get_ma_engine();
		ma_uint32 listener = ma_sound_get_listener_index(&*snd);
		if (listener >= ma_engine_get_listener_count(e)) return 1;
		float listener_inner, listener_outer, listener_outer_gain;
		get_engine()->get_listener_cone(listener, &listener_inner, &listener_outer, &listener_outer_gain);
		const ma_spatializer* spatializer_of_sound = &snd->engineNode.spatializer;
		const ma_spatializer_listener* l = &e->listeners[listener];
		ma_vec3f direction; // The sound's, relative to the listener.
		ma_spatializer_get_relative_position_and_direction(spatializer_of_sound, l, nullptr, &direction);
		double position[3];
		if (!sound_relative_position(&*snd, position)) return 1;
		double distance = sqrt(position[0] * position[0] + position[1] * position[1] + position[2] * position[2]);
		if (!(distance > 0.001)) return 1; // As MiniAudio, which has no direction to the listener then.
		ma_vec3f to_sound{(float)(position[0] / distance), (float)(position[1] / distance), (float)(position[2] / distance)}, from_sound{-to_sound.x, -to_sound.y, -to_sound.z};
		float gain = angular_gain(direction, from_sound, cone_inner.load(std::memory_order_relaxed), cone_outer.load(std::memory_order_relaxed), cone_outer_gain.load(std::memory_order_relaxed));
		if (listener_inner < 6.283185f) gain *= angular_gain(l->config.handedness == ma_handedness_right? ma_vec3f{0, 0, -1} : ma_vec3f{0, 0, 1}, to_sound, listener_inner, listener_outer, listener_outer_gain);
		return gain;
	}
	// MiniAudio's ma_calculate_angular_gain(), which it keeps to itself.
	static float angular_gain(ma_vec3f a, ma_vec3f b, float inner_radians, float outer_radians, float outer_gain) {
		if (inner_radians >= 6.283185f) return 1;
		float cutoff_inner = (float)cos(inner_radians * 0.5f), cutoff_outer = (float)cos(outer_radians * 0.5f), d = a.x * b.x + a.y * b.y + a.z * b.z;
		if (d > cutoff_inner) return 1;
		if (d > cutoff_outer) {
			float t = (d - cutoff_outer) / (cutoff_inner - cutoff_outer);
			return outer_gain * (1 - t) + t;
		}
		return outer_gain;
	}
	bool fade_from_stop = false; // The fade is one a stop with a fade set, as pause_fade() does, rather than one the script set since.
	// Decibels to the linear volumes MiniAudio fades between, on an engine with PERCENTAGE_ATTRIBUTES; FLT_MAX starts from the current volume.
	void fade_volumes_to_linear(float &start_volume, float &end_volume) const {
		if (!(get_engine()->get_flags() & audio_engine::PERCENTAGE_ATTRIBUTES)) return;
		start_volume = start_volume == FLT_MAX ? -1 : ma_volume_db_to_linear(start_volume < -100? -100 : start_volume); // No lower than -100 dB, as volumes are set and read.
		end_volume = ma_volume_db_to_linear(end_volume < -100? -100 : end_volume);
	}
	// MiniAudio keeps a sound or group stopped once its scheduled stop has come, and its fade where the stop left it, until both are cleared, so starting it clears them then. With pending, a stop still to come is cleared too, as one pause_fade() scheduled. The fade is cleared only when that stop set it, so a fade the script set since, such as one to fade back in, is kept.
	void clear_stop_for_restart(bool pending = false) {
		ma_uint64 stop_time = ma_node_get_state_time(&*snd, ma_node_state_stopped);
		if (stop_time == ~(ma_uint64)0) return;
		if (!pending && stop_time > heard_until()) return;
		ma_sound_reset_stop_time(&*snd);
		reset_stop_fade();
	}
	// The engine's time up to which the sound has been played, by which a stop has come: while the audio thread processes a block, the engine's time is that block's start, but a sound processed in it already played to its end, so that a stop within it came, MiniAudio stopping the sound there, though it read as still to come: play() then left it, and the sound didn't play, and a later stop played it again. A race of the few instructions between reading this and acting on it remains.
	ma_uint64 heard_until() const {
		const ma_uint64 now = ma_engine_get_time_in_pcm_frames(ma_sound_get_engine(&*snd)), block = current_block(now);
		return block != ~(ma_uint64)0? block + SOUNDSYSTEM_FRAMESIZE : now;
	}
	// The block the sound was last processed in when that is the one under way at now, or the next should the audio thread have moved on: an older one, or one from before the engine's time was set back, which lies ahead of it, says nothing of the block under way. ~0 for none.
	ma_uint64 current_block(ma_uint64 now) const {
		const ma_uint64 sets = held(&*snd)->time_sets? held(&*snd)->time_sets->load() : 0, block = held(&*snd)->block_at.load();
		if (held(&*snd)->block_set.load() != sets) return ~(ma_uint64)0;
		return block != ~(ma_uint64)0 && block >= now && now <= ~(ma_uint64)0 - 2 * SOUNDSYSTEM_FRAMESIZE && block <= now + SOUNDSYSTEM_FRAMESIZE? block : ~(ma_uint64)0;
	}
	// Schedules a fade from volume_beg to volume_end over length frames, beginning at the engine's time at, which the sound gives MiniAudio when that time comes (see held_sound::fade_at), replacing one scheduled before.
	void defer_fade(float volume_beg, float volume_end, ma_uint64 length, ma_uint64 at) {
		held_sound* h = held(&*snd);
		h->lock_fade();
		h->fade_beg = volume_beg;
		h->fade_end = volume_end;
		h->fade_length = length;
		h->fade_at = at;
		if (h->fade_given) h->given_stale = true; // Given to MiniAudio in the block under way but replaced: removed if MiniAudio didn't take it (see take_back_fade()).
		h->fade_given = false;
		h->fade_pending.store(true, std::memory_order_release);
		h->unlock_fade();
	}
	// Sets a fade to begin at once, as ma_sound_set_fade_in_pcm_frames() does, given to MiniAudio by the audio thread at its next block (see held_sound::now_pending).
	void set_fade_now(float volume_beg, float volume_end, ma_uint64 length) {
		held_sound* h = held(&*snd);
		h->lock_fade();
		h->now_beg = volume_beg;
		h->now_end = volume_end;
		h->now_length = length;
		h->now_pending.store(true, std::memory_order_release);
		h->unlock_fade();
	}
	// Drops a fade scheduled ahead that hasn't begun, which left the sound's fader as it was: whether there was one.
	bool drop_deferred_fade() {
		if (!snd) return false;
		held_sound* h = held(&*snd);
		h->lock_fade();
		bool dropped = h->fade_at != ~(ma_uint64)0 && !h->fade_given; // One given to MiniAudio in the block under way may have begun.
		// One given to MiniAudio that it hasn't taken is removed there, before a fade the caller sets, if it does, is given: left, MiniAudio took it once it had frames, untracked. The audio thread removes it (see take_back_fade()), as only that thread writes MiniAudio's fade settings.
		if (h->fade_given) h->given_stale = true;
		h->fade_at = ~(ma_uint64)0;
		h->fade_given = false;
		h->fade_pending.store(false, std::memory_order_relaxed);
		h->unlock_fade();
		return dropped;
	}
	// Undoes the fade a stop with a fade set, as pause_fade()'s, putting the sound back at full volume, unless that fade was still waiting for its time, which left the fader at whatever fade the script set.
	void reset_stop_fade() {
		if (fade_from_stop && !drop_deferred_fade()) set_fade_now(0, 1, 0); // As ma_sound_reset_fade() sets it.
		fade_from_stop = false;
	}
	bool play(bool reset_loop_state = true) override {
		if (snd == nullptr)
			return false;
		if (reset_loop_state)
			ma_sound_set_looping(&*snd, MA_FALSE);
		clear_stop_for_restart();
		script_seek told; // MiniAudio seeks a sound at its end to its start here.
		return (g_soundsystem_last_error = ma_sound_start(&*snd)) == MA_SUCCESS;
	}
	bool play_looped() override {
		if (snd == nullptr)
			return false;
		ma_sound_set_looping(&*snd, true);
		clear_stop_for_restart();
		script_seek told; // As in play().
		return (g_soundsystem_last_error = ma_sound_start(&*snd)) == MA_SUCCESS;
	}
	ma_sound *get_ma_sound() const override { return &*snd; }
	audio_engine *get_engine() const override { return engine; }
	bool stop() override { return snd ? (g_soundsystem_last_error = ma_sound_stop(&*snd)) == MA_SUCCESS : false; }
	void set_volume(float volume) override {
		if (!snd || !finite_values({volume})) return;
		const bool db = get_engine()->get_flags() & audio_engine::PERCENTAGE_ATTRIBUTES;
		if (db && volume < -100) volume = -100; // As it reads back (see readable_db()): below, a volume set read back louder than it was set, so that a loop fading down to a lower one never ended.
		float linear = db? ma_volume_db_to_linear(volume) : volume;
		if (finite_values({linear}))
			ma_sound_set_volume(&*snd, linear);
	}
	float get_volume() const override { return snd ? (get_engine()->get_flags() & audio_engine::PERCENTAGE_ATTRIBUTES ? readable_db(ma_sound_get_volume(&*snd)) : ma_sound_get_volume(&*snd)) : NAN; }
	// A linear volume in decibels no lower than -100, as sound_master_volume reads: a volume of 0, as a pause_fade() ends at or a setting of -1000 dB underflows to, read -inf, which a script adding to it then had refused.
	static float readable_db(float linear) {
		const float db = ma_volume_linear_to_db(linear);
		return db >= -100? db : -100;
	}
	void set_pan(float pan) override {
		if (snd && finite_values({pan})) // MiniAudio's clamp turns NaN into 1, all the way right.
			ma_sound_set_pan(&*snd, get_engine()->get_flags() & audio_engine::PERCENTAGE_ATTRIBUTES ? pan_db_to_linear(pan) : pan);
	}
	float get_pan() const override {
		return snd ? (get_engine()->get_flags() & audio_engine::PERCENTAGE_ATTRIBUTES ? pan_linear_to_db(ma_sound_get_pan(&*snd)) : ma_sound_get_pan(&*snd)) : NAN;
	}
	void set_pan_mode(ma_pan_mode mode) override {
		if (snd)
			ma_sound_set_pan_mode(&*snd, mode);
	}
	ma_pan_mode get_pan_mode() const override {
		return snd ? ma_sound_get_pan_mode(&*snd) : ma_pan_mode_balance;
	}
	void set_pitch(float pitch) override {
		if (!snd || !finite_values({pitch})) return;
		float ratio = get_engine()->get_flags() & audio_engine::PERCENTAGE_ATTRIBUTES ? pitch / 100.0f : pitch;
		if (ratio <= 0) { // MiniAudio ignores it, keeping the pitch the sound had.
			g_soundsystem_last_error = MA_INVALID_ARGS;
			return;
		}
		held(&*snd)->pitch.store(std::clamp(ratio, min_pitch_ratio, max_pitch_ratio)); // MiniAudio is given it held, by hold_rate().
	}
	float get_pitch() const override {
		if (!snd) return NAN;
		float pitch = held(&*snd)->pitch.load(); // The one set, rather than the one MiniAudio was given (see hold_rate()).
		return get_engine()->get_flags() & audio_engine::PERCENTAGE_ATTRIBUTES ? pitch * 100 : pitch;
	}
	void set_spatialization_enabled(bool enabled) override {
		if (!snd) return;
		ma_sound_set_spatialization_enabled(&*snd, enabled);
		if (!enabled) return;
		// With the default panner and attenuator unless the sound has its own, as set_position_3d() gives them: spatialization turned on by hand, as after a load, which lets go of them, left the sound placed but neither panned nor attenuated.
		if (sound_get_default_3d_panner() >= 0 && get_preferred_3d_panner() < 0) set_3d_panner(sound_get_default_3d_panner());
		if (sound_get_default_3d_attenuator() >= 0 && get_preferred_3d_attenuator() < 0) set_3d_attenuator(sound_get_default_3d_attenuator());
		place_in_shape(); // A shaped sound isn't placed while not spatialized, as a listener moves or the sound loads anew: placed in its shape once it is, rather than played from where it was last placed or from the origin.
	}
	bool get_spatialization_enabled() const override {
		if (snd)
			return ma_sound_is_spatialization_enabled(&*snd);
		return false;
	}
	void set_pinned_listener(unsigned int index) override {
		if (snd)
			ma_sound_set_pinned_listener_index(&*snd, index);
	}
	unsigned int get_pinned_listener() const override {
		return snd ? ma_sound_get_pinned_listener_index(&*snd) : 0;
	}
	unsigned int get_listener() const override {
		return snd ? ma_sound_get_listener_index(&*snd) : 0;
	}
	reactphysics3d::Vector3 get_direction_to_listener() const override {
		if (!snd)
			return reactphysics3d::Vector3();
		double relative[3];
		if (!sound_relative_position(&*snd, relative)) return reactphysics3d::Vector3(0, 0, -1); // As MiniAudio's ma_sound_get_direction_to_listener() without an engine.
		double length = sqrt(relative[0] * relative[0] + relative[1] * relative[1] + relative[2] * relative[2]);
		if (length == 0) return reactphysics3d::Vector3(0, 0, 0);
		return reactphysics3d::Vector3(-relative[0] / length, -relative[1] / length, -relative[2] / length);
	}
	float get_distance_to_listener() const override { return snd && get_spatialization_enabled()? ma_sound_get_distance_to_listener(&*snd) : 0.0; }
	void set_position_3d(float x, float y, float z) override {
		if (!snd || !finite_values({x, y, z})) // A NaN or infinite position or direction poisoned a Steam Audio panner's or attenuator's state for good.
			return;
		set_spatialization_enabled(true); // With the default panner and attenuator, the first time.
		unique_lock<mutex> lock(spatialization_params_mutex); // Which a listener's move places a shaped sound under.
		if (shape) {
			shape_anchor = reactphysics3d::Vector3(x, y, z);
			place_in_shape_locked();
		} else ma_sound_set_position(&*snd, x, y, z);
	}
	// Under spatialization_params_mutex, with snd and shape set: plays the sound from the shape's point nearest the listener, or from the listener within the shape. A sound positioned relative to the listener has its shape in the listener's space, where the listener is at the origin: tested against the listener's place in the world, and played from it as an offset from the listener, a shape attached to the listener moved with it through the world.
	void place_in_shape_locked() {
		reactphysics3d::Vector3 pos = shape_anchor, listener = ma_sound_get_positioning(&*snd) == ma_positioning_relative? reactphysics3d::Vector3(0, 0, 0) : get_engine()->get_listener_position(get_listener());
		if (shape->contains(listener, pos)) pos = listener;
		ma_sound_set_position(&*snd, pos.x, pos.y, pos.z);
	}
	// After a listener of this mixer's engine moved, on the thread that moved it.
	void place_in_shape() {
		unique_lock<mutex> lock(spatialization_params_mutex);
		if (snd && shape && ma_sound_is_spatialization_enabled(&*snd)) place_in_shape_locked();
	}
	// Whether a listener's move places this mixer again; taken out first by its destructors, before anything they free.
	void track_shape(bool shaped) {
		std::lock_guard<std::mutex> lock(g_shaped_mixers_mutex);
		if (shaped) g_shaped_mixers.insert(this);
		else g_shaped_mixers.erase(this);
	}
	void set_position_3d_vector(const reactphysics3d::Vector3& position) override { set_position_3d(position.x, position.y, position.z); }
	reactphysics3d::Vector3 get_position_3d() const override {
		if (!snd)
			return reactphysics3d::Vector3();
		if (shape) return shape_anchor; // The position the script set, as MiniAudio's may have been moved by the shape.
		const auto pos = ma_sound_get_position(&*snd);
		reactphysics3d::Vector3 res;
		res.setAllValues(pos.x, pos.y, pos.z);
		return res;
	}
	void set_direction(float x, float y, float z) override {
		if (!snd || !finite_values({x, y, z}))
			return;
		return ma_sound_set_direction(&*snd, x, y, z);
	}
	void set_direction_vector(const reactphysics3d::Vector3& direction) override { set_direction(direction.x, direction.y, direction.z); }
	reactphysics3d::Vector3 get_direction() const override {
		if (!snd)
			return reactphysics3d::Vector3();
		const auto dir = ma_sound_get_direction(&*snd);
		reactphysics3d::Vector3 res;
		res.setAllValues(dir.x, dir.y, dir.z);
		return res;
	}
	void set_velocity(float x, float y, float z) override {
		if (!snd || !finite_values({x, y, z}))
			return;
		return ma_sound_set_velocity(&*snd, x, y, z);
	}
	void set_velocity_vector(const reactphysics3d::Vector3& velocity) override { set_velocity(velocity.x, velocity.y, velocity.z); }
	reactphysics3d::Vector3 get_velocity() const override {
		if (!snd)
			return reactphysics3d::Vector3();
		const auto vel = ma_sound_get_velocity(&*snd);
		reactphysics3d::Vector3 res;
		res.setAllValues(vel.x, vel.y, vel.z);
		return res;
	}
	void set_positioning(ma_positioning positioning) override {
		if (!snd) return;
		ma_sound_set_positioning(&*snd, positioning);
		place_in_shape(); // A shape's point is found in the space the positioning gives.
	}
	ma_positioning get_positioning() const override {
		return snd ? ma_sound_get_positioning(&*snd) : ma_positioning_absolute;
	}
	void set_rolloff(float rolloff) override { get_spatializer()->set_rolloff(rolloff); }
	float get_rolloff() const override { return get_spatializer()->get_rolloff(); }
	void set_min_gain(float gain) override {
		if (snd && finite_values({gain}))
			min_gain = gain;
	}
	float get_min_gain() const override {
		return snd ? min_gain.load() : NAN;
	}
	void set_max_gain(float gain) override {
		if (snd && finite_values({gain}))
			max_gain = gain;
	}
	float get_max_gain() const override {
		return snd ? max_gain.load() : NAN;
	}
	void set_min_distance(float distance) override {
		if (snd && finite_values({distance}))
			ma_sound_set_min_distance(&*snd, distance);
	}
	float get_min_distance() const override {
		return snd ? ma_sound_get_min_distance(&*snd) : NAN;
	}
	void set_max_distance(float distance) override {
		if (snd && finite_values({distance}))
			ma_sound_set_max_distance(&*snd, distance);
	}
	float get_max_distance() const override {
		return snd ? ma_sound_get_max_distance(&*snd) : NAN;
	}
	void set_cone(float inner_radians, float outer_radians, float outer_gain) override {
		if (snd && finite_values({inner_radians, outer_radians, outer_gain})) {
			cone_inner = inner_radians;
			cone_outer = outer_radians;
			cone_outer_gain = outer_gain;
		}
	}
	void get_cone(float *inner_radians, float *outer_radians, float *outer_gain) const override {
		if (snd) {
			if (inner_radians) *inner_radians = cone_inner;
			if (outer_radians) *outer_radians = cone_outer;
			if (outer_gain) *outer_gain = cone_outer_gain;
		} else {
			if (inner_radians)
				*inner_radians = NAN;
			if (outer_radians)
				*outer_radians = NAN;
			if (outer_gain)
				*outer_gain = NAN;
		}
	}
	void set_doppler_factor(float factor) override {
		if (snd && finite_values({factor}))
			ma_sound_set_doppler_factor(&*snd, factor);
	}
	float get_doppler_factor() const override {
		return snd ? ma_sound_get_doppler_factor(&*snd) : NAN;
	}
	void set_directional_attenuation_factor(float factor) override { get_spatializer()->set_directional_attenuation_factor(factor); }
	float get_directional_attenuation_factor() const override { return get_spatializer()->get_directional_attenuation_factor(); }
	void set_fade(float start_volume, float end_volume, ma_uint64 length) override {
		if (!snd)
			return;
		if (get_engine()->get_flags() & audio_engine::DURATIONS_IN_FRAMES)
			set_fade_in_frames(start_volume, end_volume, length);
		else
			set_fade_in_milliseconds(start_volume, end_volume, length);
	}
	void set_fade_in_frames(float start_volume, float end_volume, ma_uint64 frames) override {
		if (!snd)
			return;
		fade_volumes_to_linear(start_volume, end_volume);
		if (!finite_values({start_volume, end_volume})) return;
		drop_deferred_fade(); // A fade set now replaces one scheduled ahead, as in MiniAudio's only fader.
		fade_from_stop = false;
		set_fade_now(start_volume, end_volume, std::min<ma_uint64>(frames, UINT_MAX)); // MiniAudio's own limit, under its ~0 for no fade, which lost a fade that long.
	}
	void set_fade_in_milliseconds(float start_volume, float end_volume, ma_uint64 milliseconds) override {
		if (!snd)
			return;
		fade_volumes_to_linear(start_volume, end_volume);
		if (!finite_values({start_volume, end_volume}) || !frames_fit(milliseconds, ma_engine_get_sample_rate(ma_sound_get_engine(&*snd)))) return;
		drop_deferred_fade();
		fade_from_stop = false;
		set_fade_now(start_volume, end_volume, milliseconds * snd->engineNode.fader.config.sampleRate / 1000); // As ma_sound_set_fade_in_milliseconds() converts it.
	}
	float get_current_fade_volume() const override {
		return snd ? (get_engine()->get_flags() & audio_engine::PERCENTAGE_ATTRIBUTES ? readable_db(ma_sound_get_current_fade_volume(&*snd)) : ma_sound_get_current_fade_volume(&*snd)) : NAN;
	}
	void set_start_time(ma_uint64 absolute_time) override {
		if (!snd)
			return;
		if (get_engine()->get_flags() & audio_engine::DURATIONS_IN_FRAMES)
			set_start_time_in_frames(absolute_time);
		else
			set_start_time_in_milliseconds(absolute_time);
	}
	void set_start_time_in_frames(ma_uint64 absolute_time) override {
		if (snd)
			ma_sound_set_start_time_in_pcm_frames(&*snd, absolute_time);
	}
	void set_start_time_in_milliseconds(ma_uint64 absolute_time) override {
		if (snd && frames_fit(absolute_time, ma_engine_get_sample_rate(ma_sound_get_engine(&*snd))))
			ma_sound_set_start_time_in_milliseconds(&*snd, absolute_time);
	}
	void set_stop_time(ma_uint64 absolute_time) override {
		if (!snd)
			return;
		if (get_engine()->get_flags() & audio_engine::DURATIONS_IN_FRAMES)
			set_stop_time_in_frames(absolute_time);
		else
			set_stop_time_in_milliseconds(absolute_time);
	}
	// MiniAudio leaves a sound or group started once its scheduled stop has come, reading it stopped only while that stop is past, so a later stop given to it played it again without play(), where it reads as stopped everywhere else. It is stopped first, as stop() leaves it, and play() starts it on until the new stop.
	void stop_if_stop_came() {
		if (!snd || ma_node_get_state(&*snd) != ma_node_state_started) return;
		ma_uint64 stop_time = ma_node_get_state_time(&*snd, ma_node_state_stopped);
		if (stop_time != ~(ma_uint64)0 && stop_time <= heard_until()) ma_sound_stop(&*snd);
	}
	void set_stop_time_in_frames(ma_uint64 absolute_time) override {
		if (!snd) return;
		stop_if_stop_came();
		ma_sound_set_stop_time_in_pcm_frames(&*snd, absolute_time);
	}
	void set_stop_time_in_milliseconds(ma_uint64 absolute_time) override {
		if (!snd || !frames_fit(absolute_time, ma_engine_get_sample_rate(ma_sound_get_engine(&*snd)))) return;
		stop_if_stop_came();
		ma_sound_set_stop_time_in_milliseconds(&*snd, absolute_time);
	}
	ma_uint64 get_time() const override {
		return snd ? ((get_engine()->get_flags() & audio_engine::DURATIONS_IN_FRAMES) ? get_time_in_frames() : get_time_in_milliseconds()) : 0;
	}
	// In the unit get_time() reads, milliseconds unless the engine counts durations in frames.
	bool set_time(unsigned long long time) override {
		if (!snd) return false;
		if (!(get_engine()->get_flags() & audio_engine::DURATIONS_IN_FRAMES)) {
			ma_uint32 rate = ma_engine_get_sample_rate(ma_sound_get_engine(&*snd));
			if (!frames_fit(time, rate)) return false;
			time = time * rate / 1000;
		}
		return (g_soundsystem_last_error = ma_node_set_time(&*snd, time)) == MA_SUCCESS;
	}
	ma_uint64 get_time_in_frames() const override {
		return snd ? ma_sound_get_time_in_pcm_frames(&*snd) : 0;
	}
	ma_uint64 get_time_in_milliseconds() const override {
		return snd ? ma_sound_get_time_in_milliseconds(&*snd) : 0ULL;
	}
	bool get_playing() const override {
		return snd ? ma_sound_is_playing(&*snd) : false;
	}
};
// MiniAudio's resource manager takes a buffer whose synchronous load failed out of its cache without the cache's own lock, which its asynchronous loads take for that. Every buffer is therefore loaded asynchronously, except by load_special()'s retry without flags, which loads synchronously as only that leaves the cached file it unregisters reliably. That retry and its unregister hold this exclusively; every other making and freeing of a source in the cache holds it shared, so those wait only for such a retry and not for one another's loading. Streams don't use the cache.
static std::shared_mutex g_resource_tree_mutex;
// The names claimed in each resource manager by their hash: see sound_impl::claim_buffer_name().
struct buffer_name_claim {
	std::string name;
	unsigned users; // Loads and sounds holding the claim.
};
static std::mutex g_buffer_names_mutex;
static std::map<std::pair<ma_resource_manager*, ma_uint32>, buffer_name_claim> g_buffer_names;
static void place_shaped_mixers(audio_engine* engine) {
	std::lock_guard<std::mutex> lock(g_shaped_mixers_mutex);
	for (mixer_impl* m : g_shaped_mixers) {
		if (m->get_engine() == engine) m->place_in_shape();
	}
}
class sound_impl final : public mixer_impl, public virtual sound {
	// Tracks an asynchronous load, which MiniAudio reports done through a notification, the last thing its job thread does with it. A fence won't do: miniaudio still touches one after its counter reaches zero, which is all a waiter sees, so a sound destroyed just as its load finished had its memory written after it was freed. The state therefore lives on the heap, and whichever of the sound and the job thread lets go of it last frees it. Only asynchronous loads get one; the others complete before they return and are given no notification.
	struct async_load_state;
	struct async_load_notification {
		ma_async_notification_callbacks cb; // First, as MiniAudio passes this struct as the notification.
		async_load_state *state;
	};
	struct async_load_state {
		async_load_notification notification;
		std::mutex mtx;
		std::condition_variable cv;
		sound_impl *owner; // Under mtx; cleared when the sound lets go of the state.
		bool done = false; // Under mtx.
		std::atomic<int> refs{2}; // The sound's and the pending notification's.
		async_load_state(sound_impl *o) : owner(o) { notification.cb.onSignal = &async_notification_callback; notification.state = this; }
		void release() { if (--refs == 0) delete this; }
		void abandon() {
			{
				std::lock_guard<std::mutex> lock(mtx);
				owner = nullptr;
			}
			release();
		}
	};
	async_load_state *load_state; // Of the current load while it is asynchronous, else null.
	// The resource manager source a sound loaded through load_special() plays. Made here and the sound made from it, rather than both made by MiniAudio from the file's name, so that a source can be freed only once MiniAudio's jobs let go of it: see free_failed_source().
	unique_ptr<ma_resource_manager_data_source> source;
	// MiniAudio's job threads keep touching a resource manager buffer after reporting it done: the job that loaded it, the one that decoded the last page of its node and the one that frees a buffer whose load failed each count themselves finished in the object after signalling. Freeing the sound in between had that count written to freed memory. These read and write those fields as MiniAudio's jobs do, atomically.
	static ma_uint32 load_job_field(const ma_uint32 *field) {
		#ifdef _MSC_VER
		return (ma_uint32)_InterlockedCompareExchange((volatile long *)field, 0, 0);
		#else
		return __atomic_load_n(field, __ATOMIC_SEQ_CST);
		#endif
	}
	static void store_job_field(ma_result *field, ma_result value) {
		#ifdef _MSC_VER
		_InterlockedExchange((volatile long *)field, value);
		#else
		__atomic_store_n(field, value, __ATOMIC_SEQ_CST);
		#endif
	}
	// Each job takes a number from the counter when posted and advances the pointer when it is done, so they match once none is left. Yielding a while, then sleeping: a buffer's load job posts itself again until its node is decoded, so a wait for a buffer still decoding lasts the decode, through which yielding alone kept a processor busy, slowing the decode it waited for.
	static void wait_for_jobs(const ma_uint32 *counter, const ma_uint32 *pointer) {
		for (int tries = 0; load_job_field(pointer) != load_job_field(counter); tries++) {
			if (tries < 64) std::this_thread::yield();
			else std::this_thread::sleep_for(std::chrono::milliseconds(1));
		}
	}
	// Called once the load is done, before the source is freed. Returns the source's buffer if its load failed: such a buffer is freed through a job that counts itself finished after the sound frees it, so the caller frees it on this thread instead, as that job would, with free_failed_buffer().
	static ma_resource_manager_data_buffer *finish_load_jobs(ma_resource_manager_data_source *src) {
		if (!src || (src->flags & MA_RESOURCE_MANAGER_DATA_SOURCE_FLAG_STREAM)) return nullptr; // A stream is freed through a job ordered after its others, which signals last.
		ma_resource_manager_data_buffer *buffer = &src->backend.buffer;
		wait_for_jobs(&buffer->executionCounter, &buffer->executionPointer);
		if (ma_resource_manager_data_buffer_node *node = buffer->pNode) {
			// The buffer's load is done once the node is decoded, unless the buffer failed first; the node's decoding then ends on its own.
			while ((ma_result)load_job_field((const ma_uint32 *)&node->result) == MA_BUSY) std::this_thread::sleep_for(std::chrono::milliseconds(1));
			wait_for_jobs(&node->executionCounter, &node->executionPointer);
		}
		return ma_resource_manager_data_buffer_result(buffer) == MA_SUCCESS? nullptr : buffer;
	}
	// With the sound already taken off the graph, which waited for the audio thread to stop reading it, so nothing reads the failed buffer once it is marked loaded, which makes ma_resource_manager_data_source_uninit() free it at once.
	static void free_failed_buffer(ma_resource_manager_data_buffer *buffer) { store_job_field(&buffer->result, MA_SUCCESS); }
	// Frees a source whose making failed. The job that loads or opens a source reports its failure and only then counts itself finished in the source, which MiniAudio, making the source itself, had already freed by then; so the source is freed once that count shows the job finished. A job that was never posted, as when the job queue was full, never counts, so a source whose count hasn't caught up soon is left allocated rather than freed under a job that may still run.
	static void free_failed_source(unique_ptr<ma_resource_manager_data_source> &src) {
		const bool stream = src->flags & MA_RESOURCE_MANAGER_DATA_SOURCE_FLAG_STREAM;
		const ma_uint32 *counter = stream? &src->backend.stream.executionCounter : &src->backend.buffer.executionCounter;
		const ma_uint32 *pointer = stream? &src->backend.stream.executionPointer : &src->backend.buffer.executionPointer;
		for (int waited = 0; load_job_field(pointer) != load_job_field(counter); waited++) {
			if (waited == 100) {
				src.release();
				return;
			}
			std::this_thread::sleep_for(std::chrono::milliseconds(1));
		}
		src.reset();
	}
	// Frees a source that was made, whether or not it loaded, once its jobs are done, as close() frees a sound's; no sound may be playing it. tree_held tells that the caller holds g_resource_tree_mutex already.
	static void discard_source(unique_ptr<ma_resource_manager_data_source> &src, bool tree_held = false) {
		ma_resource_manager_data_buffer *failed_buffer = finish_load_jobs(&*src);
		if (failed_buffer) free_failed_buffer(failed_buffer);
		{
			std::shared_lock<std::shared_mutex> tree_lock(g_resource_tree_mutex, std::defer_lock);
			if (!tree_held && !(src->flags & MA_RESOURCE_MANAGER_DATA_SOURCE_FLAG_STREAM)) tree_lock.lock();
			uninit_resource_source(&*src);
		}
		src.reset();
	}
	// Whether MiniAudio's jobs still decode a source's buffer, which freeing it waits for (see finish_load_jobs()).
	static bool decoding(ma_resource_manager_data_source *src) {
		if (!src || (src->flags & MA_RESOURCE_MANAGER_DATA_SOURCE_FLAG_STREAM)) return false;
		ma_resource_manager_data_buffer *buffer = &src->backend.buffer;
		if ((ma_result)load_job_field((const ma_uint32 *)&buffer->result) == MA_BUSY) return true;
		ma_resource_manager_data_buffer_node *node = buffer->pNode;
		return node && (ma_result)load_job_field((const ma_uint32 *)&node->result) == MA_BUSY;
	}
	// A source close() let go of while its buffer was still being decoded, with what the decoding reads and the name it was claimed under.
	struct source_reap {
		unique_ptr<ma_resource_manager_data_source> source;
		std::string pcm_buffer; // The memory a source loaded from memory decodes from.
		ma_resource_manager *manager = nullptr; // The source's.
		std::string claimed_name; // Claimed in manager, if not empty.
	};
	// Frees it once MiniAudio's jobs are done with it, as close() frees a source.
	static void free_reaped(source_reap &r) {
		ma_resource_manager_data_buffer *failed_buffer = finish_load_jobs(&*r.source);
		if (failed_buffer) free_failed_buffer(failed_buffer);
		{
			std::shared_lock<std::shared_mutex> tree_lock(g_resource_tree_mutex, std::defer_lock);
			if (!(r.source->flags & MA_RESOURCE_MANAGER_DATA_SOURCE_FLAG_STREAM)) tree_lock.lock(); // As close() frees one: a stream isn't in the tree, and freeing it waits for its reads.
			uninit_resource_source(&*r.source);
		}
		r.source.reset();
		if (!r.claimed_name.empty()) let_go_of_buffer_name(r.manager, r.claimed_name);
	}
	// Frees it on a thread of its own, in a place reserve_reap() gave: freed by close(), it held the script closing, reloading or letting go of a sound just loaded for as long as its file took to decode, 80 ms for 30 seconds of speech, as an interrupting speak let go of. Freed here when no thread can be made.
	static void reap(unique_ptr<source_reap> r) {
		ma_resource_manager *manager = r->manager;
		source_reap *handed = r.release();
		try {
			std::thread([handed, manager]() {
				unique_ptr<source_reap> owned(handed);
				free_reaped(*owned);
				owned.reset();
				end_reap(manager);
			}).detach();
			return;
		} catch (const std::exception &) {
			r.reset(handed);
		}
		free_reaped(*r);
		end_reap(manager);
	}
	std::string pcm_buffer;      // When loading from raw PCM (like TTS) we store the intermediate wav data here so we can take advantage of async loading to return quickly. Makes a substantial difference in the responsiveness of TTS calls.
	std::string claimed_name; // The name the sound's source was loaded under, claimed in claimed_manager until the source is freed, else empty.
	ma_resource_manager* claimed_manager = nullptr;
	std::string loaded_filename; // Contains the loaded filename as passed in the load/stream method, used just for convenience.
	mutable std::atomic_flag load_completed;
	unique_ptr<pcm_queue> pcm_stream;
	unique_ptr<float_view> view; // What the sound reads its source through when that isn't in float, freed after the sound.
	unique_ptr<decode_front_view> front; // What the sound reads a source it loaded through, under view, freed after the sound and view.
	unique_ptr<chain_view> chain; // What a sound playing a chain of sources reads it through, freed after the sound and view.
	unsigned long long chain_length_frames() const { // The length of the chain chain reads, 0 when unknown.
		ma_uint64 length = 0;
		return chain_view_get_length((ma_data_source*)&chain->base, &length) == MA_SUCCESS? length : 0;
	}
	ma_data_source* own_source() const { return front? (ma_data_source*)front->inner : view? view->inner : snd->pDataSource; } // With snd set.
	bool paused;
	bool fade_paused = false; // Paused by pause_fade(), whose stop is still scheduled, unlike one the script scheduled itself.
	bool should_autoclose; // If this is true, the release method defers sound destruction until playback has complete.
	mutable audio_data_source* datasource; // Avoid the need to keep looking up the pointer to the c++ ma_data_source wrapper associated with this sound.
	bool datasource_opened = false; // datasource is one open() was given and plays, rather than a wrapper of the sound's own source.
	void adopt_sound(held_sound_ptr made) {
		hold_rate_of(&*made, get_engine()); // Before it is attached, by postload().
		unique_lock<mutex> lock(spatialization_params_mutex);
		snd = std::move(made);
		reset_cone_and_gain_range(); // As a sound loaded anew had MiniAudio's defaults.
	}
	inline void postload(const string& filename, bool async_load = false) {
		loaded_filename = filename;
		node = (ma_node_base *)&*snd;
		set_spatialization_enabled(false);                  // The user must call set_position_3d or manually enable spatialization or else their ambience and UI sounds will be spatialized.
		set_max_distance(70);
		ma_sound_set_rolloff(&*snd, 0);
		ma_sound_set_attenuation_model(&*snd, ma_attenuation_model_linear); // As for a mixer.
		ma_sound_set_directional_attenuation_factor(&*snd, 0);
		attach_output_bus(0, node_chain, 0);
		// If we didn't load our sound asynchronously or if we streamed it, then we simply mark it as load_completed or we'll end up with a deadlock at destruction time.
		if (!async_load) load_completed.test_and_set();
	}
public:
	static void async_notification_callback(ma_async_notification *pNotification) {
		async_load_state *state = ((async_load_notification *)pNotification)->state;
		{
			std::lock_guard<std::mutex> lock(state->mtx);
			if (state->owner) state->owner->load_completed.test_and_set();
			state->done = true;
		}
		state->cv.notify_all();
		state->release();
	}
	sound_impl(audio_engine *e) : paused(false), should_autoclose(false), datasource(nullptr), pcm_stream(nullptr), mixer_impl(dynamic_cast <audio_engine_impl*> (e), false), load_state(nullptr), pcm_buffer() {
		init_sound_context();
		snd = nullptr;
		garbage_collect_inline_sounds(); // Autoclosed sounds that finished are freed whenever sounds are made or loaded, which scripts do all the time, not only by engine.play().
	}
	~sound_impl() {
		track_shape(false);
		close();
	}
	inline void release() override {
		if (asAtomicDec(refcount) < 1) {
			if (!should_autoclose || !started_to_play()) delete this; // Kept while due to start too, its start scheduled ahead: get_playing() reads false until then, and the sound was freed unplayed.
			else {
				should_autoclose = false;
				duplicate();
				unique_lock<mutex> lock(g_inlined_sounds_mutex);
				g_inlined_sounds.insert(this); // Freed with garbage_collect_inline_sounds();
			}
		}
	}
	// MiniAudio's hash of a resource's name, ma_hash_string_32(), which isn't exported: MurmurHash3 x86_32 of the name up to its first NUL, read in little-endian blocks, with MiniAudio's seed, 42. Its resource manager keys loaded buffers by it alone.
	static ma_uint32 resource_name_hash(const char* name) {
		auto rotl = [](ma_uint32 x, int r) { return (x << r) | (x >> (32 - r)); };
		const ma_uint8* data = (const ma_uint8*)name;
		int len = (int)strlen(name), blocks = len / 4;
		ma_uint32 h1 = 42, c1 = 0xcc9e2d51, c2 = 0x1b873593, k1;
		for (int i = 0; i < blocks; i++) {
			k1 = data[i * 4] | data[i * 4 + 1] << 8 | data[i * 4 + 2] << 16 | (ma_uint32)data[i * 4 + 3] << 24;
			k1 *= c1; k1 = rotl(k1, 15); k1 *= c2;
			h1 ^= k1; h1 = rotl(h1, 13); h1 = h1 * 5 + 0xe6546b64;
		}
		const ma_uint8* tail = data + blocks * 4;
		k1 = 0;
		switch (len & 3) {
			case 3: k1 ^= tail[2] << 16; [[fallthrough]];
			case 2: k1 ^= tail[1] << 8; [[fallthrough]];
			case 1: k1 ^= tail[0]; k1 *= c1; k1 = rotl(k1, 15); k1 *= c2; h1 ^= k1;
		}
		h1 ^= len;
		h1 ^= h1 >> 16; h1 *= 0x85ebca6b; h1 ^= h1 >> 13; h1 *= 0xc2b2ae35; h1 ^= h1 >> 16;
		return h1;
	}
	// Whether the resource manager holds a buffer under the name already, which a load then shares rather than decoding the source again; searched as MiniAudio searches its tree, under its lock.
	static bool resource_cached(ma_resource_manager* manager, const std::string& name) {
		ma_uint32 hash = resource_name_hash(name.c_str());
		ma_mutex_lock(&manager->dataBufferBSTLock);
		ma_resource_manager_data_buffer_node* node = manager->pRootDataBufferNode;
		while (node && node->hashedName32 != hash) node = hash < node->hashedName32? node->pChildLo : node->pChildHi;
		ma_mutex_unlock(&manager->dataBufferBSTLock);
		return node != nullptr;
	}
	// MiniAudio's resource manager knows a cached buffer only by its name's 32-bit hash, so a load whose name hashed as a live buffer of another name's played that buffer instead, and each load of a name of its own, as every speech utterance gets, did so by about one in 4 million per buffer cached. Each load claims its name's hash in the resource manager until its source is freed; a hash claimed under another name, or cached with no claim, makes the load try its name with the next salt, which a name always gets in the same order, so loads of one name still share their buffer.
	static bool claim_buffer_name(ma_resource_manager* manager, const std::string& name) {
		std::pair<ma_resource_manager*, ma_uint32> key(manager, resource_name_hash(name.c_str()));
		std::lock_guard<std::mutex> lock(g_buffer_names_mutex);
		auto claim = g_buffer_names.find(key);
		if (claim != g_buffer_names.end()) {
			if (claim->second.name != name) return false;
			claim->second.users++;
			return true;
		}
		if (resource_cached(manager, name)) return false; // Kept with no claim, as by a source something else still holds, whose name isn't known.
		g_buffer_names.emplace(key, buffer_name_claim{name, 1});
		return true;
	}
	static void let_go_of_buffer_name(ma_resource_manager* manager, const std::string& name) {
		std::lock_guard<std::mutex> lock(g_buffer_names_mutex);
		auto claim = g_buffer_names.find({manager, resource_name_hash(name.c_str())});
		if (claim != g_buffer_names.end() && claim->second.name == name && !--claim->second.users) g_buffer_names.erase(claim);
	}
	// A source's own sample rate, from its header read by a decoder of its own through the sound service, or 0 when none could read it.
	static ma_uint32 native_sample_rate(const std::string& triplet) {
		ma_decoder_config cfg = ma_decoder_config_init(ma_format_unknown, 0, 0); // No conversion, so the decoder's output is the source's own format.
		if (!g_decoders.empty()) {
			cfg.ppCustomBackendVTables = &g_decoders[0];
			cfg.customBackendCount = g_decoders.size();
		}
		ma_decoder decoder;
		if (ma_decoder_init_vfs(g_sound_service->get_vfs(), triplet.c_str(), &cfg, &decoder) != MA_SUCCESS) return 0;
		ma_uint32 rate = decoder.outputSampleRate;
		ma_decoder_uninit(&decoder);
		return rate;
	}
	bool load_special(const std::string &filename, const size_t protocol_slot = 0, directive_t protocol_directive = nullptr, const size_t filter_slot = 0, directive_t filter_directive = nullptr, ma_uint32 ma_flags = MA_SOUND_FLAG_DECODE) override {
		return load_source(filename, protocol_slot, protocol_directive, filter_slot, filter_directive, ma_flags, false);
	}
	// whole_in_pages is set for a stream loaded again as a buffer because it fitted in its two pages (see below), whose rate isn't checked again: the buffer takes no more than the pages it filled, and the stream itself wasn't refused. Its buffer is shared with no other sound, so the file is read as it is now, as a stream reads it, rather than taken as another sound loaded it before it changed.
	bool load_source(const std::string &filename, const size_t protocol_slot, directive_t protocol_directive, const size_t filter_slot, directive_t filter_directive, ma_uint32 ma_flags, bool whole_in_pages) {
		garbage_collect_inline_sounds();
		if (snd)
			close();
		// Made here and handed to snd only once it loaded, under the lock the audio thread reads snd under, so the audio thread never reads a sound half made or freed after a failed load.
		held_sound_ptr made(new held_sound());
		// The sound service converts our file name into a "tripplet" which includes information about the origin an asset is expected to come from. This guarantees that we don't mistake assets from different origins as the same just because they have the same name.
		ma_resource_manager* manager = ma_engine_get_resource_manager(engine->get_ma_engine());
		std::string triplet;
		for (unsigned salt = 0;; salt++) { // See claim_buffer_name().
			triplet = g_sound_service->prepare_triplet(filename, protocol_slot, protocol_directive, filter_slot, filter_directive, whole_in_pages, salt);
			if (triplet.empty()) { // A name the sound service can't make one of, such as one that isn't valid UTF-8.
				g_soundsystem_last_error = MA_INVALID_ARGS;
				return false;
			}
			if (claim_buffer_name(manager, triplet)) break;
			g_sound_service->cleanup_triplet(triplet);
		}
		// A buffer is decoded at the resource manager's rate, the engine's unless an engine without a device was made without one, when buffers keep their own. So one whose own rate was far below it, as a header could claim 1 Hz, came out that many times larger: a 4 KB file took 192 MB and seconds to decode, and one of 400 KB more memory than there was. A source below min_sample_rate, which PCM and decoders are refused under too, is refused; from it on, what a buffer takes follows the sound's length, as for any file, rather than a ratio to the engine's rate, which refused rates PCM and decoders take on an engine above 48000 Hz. The resource manager gives a source's own rate no way out, so the file's header is read first by a decoder of its own, unless the resource manager holds the buffer already, as for a sound played again by its name, which that cost many times over; a source of unknown length isn't, as opening it twice would read it from its start again. Where the resource manager keeps a source's own rate instead, it decodes buffers and streams alike in pages of 1000 * (rate / 1000) frames of it, none below 1000 Hz, so those played silence while their load succeeded: there they are refused below 1000 Hz.
		ma_uint32 decoded_rate = manager->config.decodedSampleRate;
		bool buffered = (ma_flags & MA_SOUND_FLAG_DECODE) && !(ma_flags & MA_SOUND_FLAG_STREAM), streamed = (ma_flags & MA_SOUND_FLAG_STREAM) != 0;
		if (!whole_in_pages && !(ma_flags & MA_SOUND_FLAG_UNKNOWN_LENGTH) && (buffered? !resource_cached(manager, triplet) : streamed && !decoded_rate)) {
			ma_uint32 own_rate = native_sample_rate(triplet);
			if (own_rate && own_rate < min_sample_rate) {
				let_go_of_buffer_name(manager, triplet);
				g_sound_service->cleanup_triplet(triplet);
				g_soundsystem_last_error = MA_FORMAT_NOT_SUPPORTED;
				return false;
			}
		}
		// A buffer MiniAudio would load synchronously, as for load_memory(), is loaded asynchronously and waited for: see g_resource_tree_mutex.
		bool wait_for_load = !(ma_flags & (MA_SOUND_FLAG_ASYNC | MA_SOUND_FLAG_STREAM));
		ma_uint32 flags = ma_flags | (wait_for_load? MA_SOUND_FLAG_ASYNC : 0);
		unique_ptr<ma_resource_manager_data_source> made_source;
		unique_ptr<decode_front_view> made_front;
		unique_ptr<float_view> made_view;
		bool tree_held = false; // The retry below holds g_resource_tree_mutex around its attempt.
		// Each attempt gets its own load state, so one a failed attempt left with MiniAudio can't be mistaken for the next. It makes the source and then the sound from it, as ma_sound_init_ex() would from the file's name, but keeps the source: see source.
		auto attempt_init = [&]() {
			// Not for a stream, whose done notification MiniAudio signals only when its load fails early: made with WAIT_INIT, a stream has its decoder open and its pages filled once it is made.
			async_load_state *state = (flags & MA_SOUND_FLAG_ASYNC) && !(flags & MA_SOUND_FLAG_STREAM)? new async_load_state(this) : nullptr;
			ma_resource_manager_pipeline_notifications notifications = ma_resource_manager_pipeline_notifications_init();
			if (state) notifications.done.pNotification = &state->notification;
			ma_resource_manager_data_source_config source_cfg = ma_resource_manager_data_source_config_init();
			source_cfg.pFilePath = triplet.c_str();
			source_cfg.flags = flags | MA_RESOURCE_MANAGER_DATA_SOURCE_FLAG_WAIT_INIT; // A sound's loading flags are the resource manager's; the sound needs its source's format, so the source is waited for that far, as ma_sound_init_ex() does.
			source_cfg.pNotifications = &notifications;
			made_source = make_unique<ma_resource_manager_data_source>();
			{
				std::shared_lock<std::shared_mutex> shared_tree_lock(g_resource_tree_mutex, std::defer_lock);
				std::unique_lock<std::shared_mutex> tree_lock(g_resource_tree_mutex, std::defer_lock);
				if (!tree_held && !(flags & MA_SOUND_FLAG_STREAM)) {
					if (flags & MA_SOUND_FLAG_ASYNC) shared_tree_lock.lock();
					else tree_lock.lock();
				}
				g_soundsystem_last_error = ma_resource_manager_data_source_init_ex(ma_engine_get_resource_manager(engine->get_ma_engine()), &source_cfg, &*made_source);
			}
			if (g_soundsystem_last_error != MA_SUCCESS) free_failed_source(made_source);
			else {
				ma_sound_config cfg = ma_sound_config_init();
				// Not attached to the endpoint by MiniAudio, as postload() attaches it to its chain; so making it changes no node's lists and needs no graph lock.
				cfg.flags = flags | MA_SOUND_FLAG_NO_DEFAULT_ATTACHMENT;
				cfg.pDataSource = float_source(decode_front(&*made_source, made_front), made_view);
				if ((g_soundsystem_last_error = ma_sound_init_ex(engine->get_ma_engine(), &cfg, &*made)) != MA_SUCCESS) discard_source(made_source, tree_held);
				else if (wait_for_load) {
					{
						std::unique_lock<std::mutex> lock(state->mtx);
						state->cv.wait(lock, [state]() { return state->done; });
					}
					ma_result loaded = ma_resource_manager_data_source_result(&*made_source);
					if (loaded != MA_SUCCESS) {
						ma_sound_uninit(&*made);
						discard_source(made_source);
						g_soundsystem_last_error = loaded;
					}
				}
			}
			if (!state) return;
			if (g_soundsystem_last_error == MA_SUCCESS && !wait_for_load) load_state = state;
			else state->abandon(); // The notification's reference stays with MiniAudio in case it still signals.
		};
		/*
		MiniAudio currently returns an error code of MA_OUT_OF_MEMORY (-4) if sound initialization fails due to the job queue being at capacity.
		IMHO this is a poor choice of error code; MA_BUSY would be better as it conveys the temporary nature of the situation.
		I'll raise an issue with MA to see if he'd be okay with this change. For now we'll just wait a few milliseconds for the backlog to clear and fail permanently if we see multiple MA_OUT_OF_MEMORY conditions back  to back. This should give the job queue time
		*/
		for (int i = 0; i < 10; i++) {
			attempt_init();
			if (g_soundsystem_last_error == MA_OUT_OF_MEMORY) {
				// See above; this is probably job queue backlog rather than an actual out of memory. Take a break and try again. Not the script's wait(), which can collect garbage, whose destructors could load this very sound meanwhile, its sound then overwritten here while attached to the graph.
				std::this_thread::sleep_for(std::chrono::milliseconds(5));
				continue;
			}
			break; // Don't retry any other failure case.
		}
		// For the time being, give it one more try without any flags if we got -10 (MA_INVALID_FILE) because MA's support for loading mp3 is limited.
		// Not for a source of unknown length, such as a URL: loading without flags reads the source in whole, which needs its size, so it only opened the source again to fail with an error in place of the decoder's.
		if (g_soundsystem_last_error == MA_INVALID_FILE && !(ma_flags & MA_SOUND_FLAG_UNKNOWN_LENGTH)) {
			// Synchronously: an asynchronous load leaves the cached file below only at times, and unregistering a name MiniAudio doesn't find hangs every later load. Under the cache's lock throughout, with the unregister: another thread's load of that name in between found the cached file, failed on it too and kept it cached for good.
			std::lock_guard<std::shared_mutex> tree_lock(g_resource_tree_mutex);
			tree_held = true;
			flags = 0;
			wait_for_load = false;
			attempt_init();
			// Loading without flags reads the file in whole and then decodes it; when the decoding fails, MiniAudio keeps the file it read, cached under the file's name with nothing holding it, so each later load of that name failed on those bytes even once the file changed. That cached entry is let go here.
			// Only for the decoder's own failures, which come after the file was read and cached: a file that couldn't be read, such as an empty one, leaves no entry, and MiniAudio's unregister of a name it doesn't find returns without unlocking its cache, hanging every later load.
			if (g_soundsystem_last_error == MA_INVALID_FILE || g_soundsystem_last_error == MA_NO_BACKEND)
				ma_resource_manager_unregister_file(ma_engine_get_resource_manager(get_engine()->get_ma_engine()), triplet.c_str());
		}

		// A stream fills two pages, of about a second each, before it is made, its decoder not yet looping, and MiniAudio's page fill ends after meeting a looping decoder's end twice with nothing read between; a stream wholly read into its pages so went silent where it looped, at its first loop and, under half a page, every second one. Such a source, its decoder at its end once the pages are filled, is loaded as a buffer instead, which loops seamlessly in no more memory; one of unknown length isn't, as loading it again would read it from its start again.
		if (g_soundsystem_last_error == MA_SUCCESS && (made_source->flags & MA_RESOURCE_MANAGER_DATA_SOURCE_FLAG_STREAM) && !(ma_flags & MA_SOUND_FLAG_UNKNOWN_LENGTH) && reinterpret_cast<std::atomic<ma_bool32>*>(&made_source->backend.stream.isDecoderAtEnd)->load()) {
			ma_sound_uninit(&*made);
			made_view.reset();
			made_front.reset();
			discard_source(made_source, tree_held);
			let_go_of_buffer_name(manager, triplet);
			g_sound_service->cleanup_triplet(triplet);
			return load_source(filename, protocol_slot, protocol_directive, filter_slot, filter_directive, (ma_flags & ~MA_SOUND_FLAG_STREAM) | MA_SOUND_FLAG_DECODE, true);
		}
		if (g_soundsystem_last_error == MA_SUCCESS) {
			if (made_source->flags & MA_RESOURCE_MANAGER_DATA_SOURCE_FLAG_STREAM) {
				held(&*made)->stream = &made_source->backend.stream;
				// The stream's job thread fills its pages through its decoder's data source functions, and seeks the decoder, so that NVGT's (see hold_decoder()) make the read at its end that gave nothing once more, count the resampling from where a seek left it and, for a source that can seek, keep the seek from being skipped and give silence for what the file lacks of its length. Given here, before the sound first reads the stream, which no job touches until then.
				hold_decoder(&made_source->backend.stream.decoder, !(ma_flags & MA_SOUND_FLAG_UNKNOWN_LENGTH), made_source->backend.stream.totalLengthInPCMFrames); // A URL's source can't seek.
			}
			source = std::move(made_source);
			view = std::move(made_view);
			front = std::move(made_front);
			claimed_name = triplet;
			claimed_manager = manager;
			adopt_sound(std::move(made));
			postload(filename, (flags & MA_SOUND_FLAG_ASYNC) && !(flags & MA_SOUND_FLAG_STREAM) && !wait_for_load);
		}
		else let_go_of_buffer_name(manager, triplet);
		// Sound service has to store data pertaining to our triplet, and this is the earliest point at which it's safe to clean that up.
		g_sound_service->cleanup_triplet(triplet);
		return g_soundsystem_last_error == MA_SUCCESS;
	}
	bool load(const string &filename, const pack_interface* pack_file) override {
		return load_special(filename, pack_file && pack_file->get_is_active()? g_pack_protocol_slot : sound_service::fs_protocol_slot, pack_file && pack_file->get_is_active()? std::shared_ptr < const pack_interface > (pack_file->make_immutable()) : nullptr, 0, nullptr, MA_SOUND_FLAG_DECODE | MA_SOUND_FLAG_ASYNC);
	}
	bool stream(const std::string &filename, const pack_interface* pack_file) override {
		return load_special(filename, pack_file && pack_file->get_is_active()? g_pack_protocol_slot : sound_service::fs_protocol_slot, pack_file && pack_file->get_is_active()? std::shared_ptr < const pack_interface > (pack_file->make_immutable()) : nullptr, 0, nullptr, MA_SOUND_FLAG_STREAM);
	}
	bool stream_url(const std::string &url) override {
		return load_special(url, g_netstream_protocol_slot, nullptr, 0, nullptr, MA_SOUND_FLAG_STREAM | MA_SOUND_FLAG_UNKNOWN_LENGTH);
	}
	bool load_string(const std::string &data) override { return load_memory(data.data(), data.size()); }
	bool load_string_async(const std::string &data) override {
		// Same as load_pcm, but without the setup. A loaded sound is closed first, since closing empties pcm_buffer, which the directive points into.
		if (snd) close();
		pcm_buffer = data;
		return load_special(":quickstring", g_memory_protocol_slot, memory_protocol::directive(&pcm_buffer[0], pcm_buffer.size()), sound_service::null_filter_slot, nullptr, MA_SOUND_FLAG_DECODE | MA_SOUND_FLAG_ASYNC);
	}
	bool load_memory(const void *buffer, unsigned int size) override {
		return load_special("::memory", g_memory_protocol_slot, memory_protocol::directive(buffer, size));
	}
	bool load_pcm(void *buffer, unsigned int size, ma_format format, int samplerate, int channels) override {
		if (snd)
			close();
		pcm_buffer.clear();
		// At least for now, the strat here is just to write the PCM to wav and then load it the normal way.
		// Should optimization become necessary (this does result in a couple of copies), a protocol could be written that simulates its input having a RIFF header on it.
		if (!pcm_to_wav(buffer, size, format, samplerate, channels, pcm_buffer))
			return false;
		// At this point we can just use the sound service to load this. We use the low level API though because we need to be clear that no filters apply.
		// Also, our PCM buffer is a permanent class property so we can enjoy the speed of async loading.
		return load_special(":pcm", g_memory_protocol_slot, memory_protocol::directive(&pcm_buffer[0], pcm_buffer.size()), sound_service::null_filter_slot, nullptr, MA_SOUND_FLAG_DECODE | MA_SOUND_FLAG_ASYNC);
	}
	// A script's PCM at a sample rate of a few hertz was resampled up to the engine's as it loaded, so that a second at 1 Hz took gigabytes: below min_sample_rate, it is refused. Above the highest, and with a channel count past MA_MAX_CHANNELS, it was refused only once the sound already loaded had been closed, and dr_wav keeps the count in 16 bits, so one past 65535 loaded other audio, or at a multiple of 65536 divided by zero.
	static bool pcm_format_in_range(int samplerate, int channels) {
		if (samplerate >= int(min_sample_rate) && samplerate <= ma_standard_sample_rate_max && channels >= 1 && channels <= MA_MAX_CHANNELS) return true;
		g_soundsystem_last_error = MA_INVALID_ARGS;
		return false;
	}
	bool load_pcm_script_array(CScriptArray *buffer, int samplerate, int channels) override {
		if (!buffer)
			return false;
		ma_format format = ma_format_from_angelscript_type(buffer->GetElementTypeId());
		if (format == ma_format_unknown || !pcm_format_in_range(samplerate, channels)) return false;
		return load_pcm(buffer->GetBuffer(), buffer->GetSize() * buffer->GetElementSize(), format, samplerate, channels);
	}
	bool load_pcm_script_memory_buffer(script_memory_buffer* buffer, int samplerate, int channels) override {
		if (!buffer)
			return false;
		ma_format format = ma_format_from_angelscript_type(buffer->subtypeid);
		if (format == ma_format_unknown || !pcm_format_in_range(samplerate, channels)) return false;
		return load_pcm(buffer->ptr, buffer->size * buffer->get_element_size(), format, samplerate, channels);
	}
	bool stream_pcm(const void* data, unsigned int size_in_frames, ma_format format, unsigned int sample_rate, unsigned int channels, unsigned int buffer_size) override {
		if (format != ma_format_unknown) {
			if (!buffer_size) buffer_size = size_in_frames * 2;
			if (!channels) channels = get_engine()->get_channels();
			if (!buffer_size || channels > MA_MAX_CHANNELS) { // Nothing to size a buffer by, or more channels than a node can describe, as for a ring buffer: refused before the sound loaded already goes.
				g_soundsystem_last_error = MA_INVALID_ARGS;
				return false;
			}
			if (snd) close();
			if (!sample_rate) sample_rate = get_engine()->get_sample_rate();
			pcm_stream = make_unique<pcm_queue>();
			if ((g_soundsystem_last_error = pcm_stream->init(format, channels, buffer_size)) != MA_SUCCESS) {
				pcm_stream.reset();
				return false;
			}
			ma_pcm_rb_set_sample_rate(&pcm_stream->rb, sample_rate);
			// As load_special() makes a sound: not attached by MiniAudio, so without the graph lock, and handed to snd once made.
			held_sound_ptr made(new held_sound());
			if ((g_soundsystem_last_error = ma_sound_init_from_data_source(get_engine()->get_ma_engine(), float_source(&pcm_stream->base, view), MA_SOUND_FLAG_NO_DEFAULT_ATTACHMENT, nullptr, &*made)) != MA_SUCCESS) {
				view.reset();
				pcm_stream->uninit();
				pcm_stream.reset();
				return false;
			}
			adopt_sound(std::move(made));
			postload(":pcm", false);
			play(true);
		}
		if (!pcm_stream) { // No sample type to start one with, as for an array of a type that isn't one.
			g_soundsystem_last_error = MA_INVALID_ARGS;
			return false;
		}
		// All of it or none where nothing can be waited on for room: on an audio thread (see below), and for a sound not playing, paused or stopped, which nothing reads until play(), or fading out to a pause_fade() stop, after which the rest waited on would be given up. A part queued before giving up the rest left the script unable to tell what was taken, to send the rest again, and play() resuming a paused sound played that part. The audio thread only makes room meanwhile.
		if ((audio_engine_impl::on_audio_thread() || fade_paused || !(snd && ma_sound_is_playing(&*snd))) && ma_pcm_rb_available_write(&pcm_stream->rb) < size_in_frames) {
			g_soundsystem_last_error = size_in_frames > ma_pcm_rb_get_subbuffer_size(&pcm_stream->rb)? MA_TOO_BIG : MA_BUSY; // More than the whole queue holds, which no later call can take either, to be sent in parts.
			return false;
		}
		const char* input = (const char*)data;
		unsigned int frames_written = 0;
		unsigned int frame_size = ma_get_bytes_per_frame(ma_pcm_rb_get_format(&pcm_stream->rb), ma_pcm_rb_get_channels(&pcm_stream->rb));
		// A full buffer is waited on while the sound plays it out; when nothing has made room for a second, as when the sound was stopped meanwhile or its engine is never read, the rest is given up rather than waited on forever.
		std::chrono::steady_clock::time_point waiting_since;
		bool waiting = false;
		while (size_in_frames) {
			void* buffer_ptr = nullptr;
			unsigned int frames_requested = size_in_frames;
			if ((g_soundsystem_last_error = ma_pcm_rb_acquire_write(&pcm_stream->rb, &frames_requested, &buffer_ptr)) != MA_SUCCESS || !buffer_ptr) return false;
			if (!frames_requested) {
				ma_pcm_rb_commit_write(&pcm_stream->rb, 0);
				if (audio_engine_impl::on_audio_thread()) { // Not waited on an audio thread, as in a processing callback, which held its engine up for that second, and its own engine, which makes the room, for good.
					g_soundsystem_last_error = MA_BUSY;
					return false;
				}
				if (!waiting) {
					waiting = true;
					waiting_since = std::chrono::steady_clock::now();
				} else if (std::chrono::steady_clock::now() - waiting_since >= std::chrono::seconds(1)) {
					g_soundsystem_last_error = MA_TIMEOUT;
					return false;
				}
				std::this_thread::sleep_for(std::chrono::milliseconds(1));
				continue;
			}
			waiting = false;
			memcpy(buffer_ptr, input + (frames_written * frame_size), frames_requested * frame_size);
			if ((g_soundsystem_last_error = ma_pcm_rb_commit_write(&pcm_stream->rb, frames_requested)) != MA_SUCCESS) return false;
			pcm_stream->wrote(frames_requested);
			frames_written += frames_requested;
			size_in_frames -= frames_requested;
		}
		return true;
	}
	bool stream_pcm_script_array(CScriptArray *buffer, unsigned int sample_rate, unsigned int channels, unsigned int buffer_size) override {
		if (!buffer)
			return false;
		ma_format format = ma_format_from_angelscript_type(buffer->GetElementTypeId());
		if (pcm_stream) {
			if (format != ma_pcm_rb_get_format(&pcm_stream->rb)) return (g_soundsystem_last_error = MA_INVALID_ARGS) == MA_SUCCESS; // Not the sample type the stream was started with.
			format = ma_format_unknown;
		}
		int nchannels = pcm_stream? ma_pcm_rb_get_channels(&pcm_stream->rb) : channels? channels : get_engine()->get_channels();
		return stream_pcm(buffer->GetBuffer(), buffer->GetSize() / nchannels, format, sample_rate, channels, buffer_size);
	}
	bool stream_pcm_script_memory_buffer(script_memory_buffer* buffer, unsigned int sample_rate, unsigned int channels, unsigned int buffer_size) override {
		if (!buffer)
			return false;
		ma_format format = ma_format_from_angelscript_type(buffer->subtypeid);
		if (pcm_stream) {
			if (format != ma_pcm_rb_get_format(&pcm_stream->rb)) return (g_soundsystem_last_error = MA_INVALID_ARGS) == MA_SUCCESS;
			format = ma_format_unknown;
		}
		int nchannels = pcm_stream? ma_pcm_rb_get_channels(&pcm_stream->rb) : channels? channels : get_engine()->get_channels();
		return stream_pcm(buffer->ptr, buffer->size / nchannels, format, sample_rate, channels, buffer_size);
	}
	bool open(audio_data_source* ds) override {
		if (!ds) return false;
		// A sound's own source is freed by that sound when it closes, as this one does to open it, and one another sound or chain reads would be read from two places.
		if (!ds->get_active() || audio_data_source_impl::is_sound_owned(ds) || audio_data_source_impl::is_used(ds)) {
			g_soundsystem_last_error = ds->get_active()? MA_INVALID_OPERATION : MA_INVALID_ARGS;
			ds->release();
			return false;
		}
		if (snd) close();
		audio_data_source_impl::prepare_length_of(ds); // Before the sound reads it.
		held_sound_ptr made(new held_sound()); // As load_special() makes a sound.
		if ((g_soundsystem_last_error = ma_sound_init_from_data_source(get_engine()->get_ma_engine(), float_source(chain_source(ds->get_ma_data_source(), get_engine(), chain), view), MA_SOUND_FLAG_NO_DEFAULT_ATTACHMENT, nullptr, &*made)) != MA_SUCCESS) {
			view.reset();
			chain.reset();
			ds->release();
			return false;
		}
		adopt_sound(std::move(made));
		datasource = ds;
		datasource_opened = true;
		audio_data_source_impl::add_user(ds); // So it can't be closed while this sound reads it.
		postload(":datasource", false);
		return true;
	}
	bool is_load_completed() const override {
		return load_completed.test();
	}
	// It's possible that this sound could still be loading in a job thread when we let go of its load. Unfortunately there isn't a way to cancel this, so we have to just wait.
	void let_go_of_load_state() {
		if (!load_state) return;
		{
			std::unique_lock<std::mutex> lock(load_state->mtx);
			load_state->cv.wait(lock, [this]() { return load_state->done; });
		}
		load_state->abandon();
		load_state = nullptr;
	}
	bool close() override {
		// A source still being decoded is handed to reap() once the sound is off it, when reserve_reap() gives it a place, rather than waited for here, and its load state let go of without waiting for its end. The memory a source loaded from memory decodes from goes with it, at the same place: a string that kept it within itself, which no file's header is small enough for, would move it, and then the source is waited for here.
		unique_ptr<source_reap> reaped;
		ma_resource_manager *source_manager = source? (claimed_manager? claimed_manager : ma_engine_get_resource_manager(get_engine()->get_ma_engine())) : nullptr;
		// On an audio thread, as when a processing callback lets a sound go, which mustn't wait out the rest of a decode, nor a stream's last read, a stalled network read included, a stream too, and past the places reserve_reap() otherwise gives.
		const bool audio_thread = audio_engine_impl::on_audio_thread();
		if ((decoding(source.get()) || audio_thread && source && (source->flags & MA_RESOURCE_MANAGER_DATA_SOURCE_FLAG_STREAM)) && reserve_reap(source_manager, audio_thread)) {
			reaped = make_unique<source_reap>();
			reaped->manager = source_manager;
			const char *decoded_from = pcm_buffer.data();
			reaped->pcm_buffer = std::move(pcm_buffer);
			if (!reaped->pcm_buffer.empty() && reaped->pcm_buffer.data() != decoded_from) {
				pcm_buffer = std::move(reaped->pcm_buffer);
				reaped.reset();
				end_reap(source_manager);
			}
		}
		if (reaped && load_state) {
			load_state->abandon();
			load_state = nullptr;
		} else let_go_of_load_state();
		if (!snd) return false;
		if (spatializer) {
			// Not under this sound's lock, which no chain's lock is taken inside: forgetting the mixer takes the spatializer's, and taking it out of the chain rewires the chains around it, and each of these, like letting go of the spatializer itself, can let go of the last reference to a mixer, such as one a reverb3d made or one the script pointed a chain at. A mixer's destructor takes g_shaped_mixers_mutex, which a listener's move holds while it waits for this sound's lock.
			// The spatializer forgets this sound before the sound lets go of it, so that it stops asking the sound for its parameters first.
			audio_spatializer *forgotten = spatializer;
			forgotten->forget_mixer();
			{
				std::lock_guard<std::recursive_mutex> topology(g_audio_topology_mutex); // A loop check walking mixers reads this spatializer (see mixer_reaches()).
				unique_lock<mutex> lock(spatialization_params_mutex);
				spatializer = nullptr;
			}
			node_chain->remove_node(forgotten);
			forgotten->release();
		}
		// Taken out of snd under the lock a listener's move and the audio thread read snd under, so neither reads the sound while it is freed.
		held_sound_ptr closing;
		{
			unique_lock<mutex> lock(spatialization_params_mutex);
			closing = std::move(snd);
		}
		ma_resource_manager_data_buffer *failed_buffer = reaped? nullptr : finish_load_jobs(source.get());
		// Off the graph first, which waits for the audio thread to stop reading the sound, so nothing reads what is let go of below.
		{
			std::lock_guard<std::recursive_mutex> graph_lock(g_node_graph_mutex);
			ma_node_detach_all_output_buses(&*closing);
		}
		// A wrapper the script got of the sound's own source is emptied before the source is freed with the sound, rather than left pointing at it; this also lets go of sources chained to it. Not under the graph lock, which the wrapper takes after its own.
		if (datasource && !datasource_opened) {
			if (auto impl = dynamic_cast<audio_data_source_impl*>(datasource)) impl->forget_source();
		}
		// Already off the graph, and a sound takes no input, so uninitializing it changes no node's lists: the graph lock isn't held across it, nor across freeing its source, as freeing a stream waits for its reads, a stalled network read included. A buffer in the resource cache is freed under the cache's lock, as it is made.
		if (failed_buffer) free_failed_buffer(failed_buffer);
		ma_sound_uninit(&*closing); // The sound doesn't own its source, which is freed after it.
		view.reset();
		front.reset();
		chain.reset();
		if (reaped) {
			reaped->source = std::move(source);
			if (claimed_manager) {
				reaped->claimed_name = std::move(claimed_name);
				claimed_manager = nullptr;
				claimed_name.clear();
			}
			reap(std::move(reaped));
		} else if (source) {
			std::shared_lock<std::shared_mutex> tree_lock(g_resource_tree_mutex, std::defer_lock);
			bool tree_held = true;
			if (!(source->flags & MA_RESOURCE_MANAGER_DATA_SOURCE_FLAG_STREAM)) {
				if (!audio_thread) tree_lock.lock();
				else tree_held = tree_lock.try_lock();
			}
			// On an audio thread the tree's lock is only tried: a load holding the tree whole, as one tried again without flags for a file that couldn't be decoded, held a processing callback letting a sound go for as long, 100 ms for a large file; the source is then freed on a thread of its own. Its jobs are done (see finish_load_jobs() above), so it no longer reads memory this sound keeps.
			if (!tree_held && reserve_reap(source_manager, true)) {
				unique_ptr<source_reap> late = make_unique<source_reap>();
				late->manager = source_manager;
				late->source = std::move(source);
				if (claimed_manager) {
					late->claimed_name = std::move(claimed_name);
					claimed_manager = nullptr;
					claimed_name.clear();
				}
				reap(std::move(late));
			} else {
				if (!tree_held) tree_lock.lock();
				uninit_resource_source(&*source);
				if (tree_lock.owns_lock()) tree_lock.unlock();
				source.reset();
			}
		}
		if (claimed_manager) {
			let_go_of_buffer_name(claimed_manager, claimed_name);
			claimed_manager = nullptr;
			claimed_name.clear();
		}
		closing.reset();
		if (datasource) {
			if (datasource_opened) audio_data_source_impl::remove_user(datasource);
			datasource->release();
			datasource = nullptr;
		}
		datasource_opened = false;
		node = nullptr;
		if (pcm_stream) pcm_stream->uninit();
		pcm_stream.reset();
		pcm_buffer.resize(0);
		loaded_filename.clear();
		load_completed.clear();
		paused = fade_paused = fade_from_stop = should_autoclose = false;
		return true;
	}
	void set_autoclose(bool enabled) override { should_autoclose = enabled; }
	bool get_autoclose() const override { return should_autoclose; }
	const std::string &get_loaded_filename() const override { return loaded_filename; }
	audio_data_source* get_datasource() const override {
		if (!datasource && snd) {
			if ((datasource = audio_data_source_get(own_source(), get_engine())) == nullptr) return nullptr;
			if (auto impl = dynamic_cast<audio_data_source_impl*>(datasource)) impl->mark_sound_owned();
		}
		return datasource;
	}
	bool get_active() override {
		return snd ? true : false;
	}
	// Not once it played to its end, as one does while pause_fade() fades it out, as its page says a sound that isn't playing doesn't read as paused: play() then starts it from its start rather than resuming it.
	bool get_paused() override {
		return snd ? !ma_sound_is_playing(&*snd) && paused && !at_end_seen(&*snd) : false;
	}
	// Playing, or started and due to play, its start scheduled ahead with set_start_time(), which ma_sound_is_playing() reads as stopped until then: not a sound stopped, played to its end or never started, nor one whose scheduled stop has come, which MiniAudio leaves started (see clear_stop_for_restart()).
	bool started_to_play() {
		if (!snd || ma_node_get_state(&*snd) != ma_node_state_started) return false;
		return ma_node_get_state_time(&*snd, ma_node_state_stopped) > heard_until();
	}
	bool play(bool reset_loop_state = true) override {
		const bool resuming = paused; // Paused by pause() or pause_fade().
		if (fade_paused && snd) clear_stop_for_restart(true); // A pause_fade() still fading out is called off.
		paused = fade_paused = false;
		// A sound that isn't playing drops what was queued before it is started again, through its reader: see pcm_queue. One already playing or due to start keeps its queue, as does one resumed from a pause.
		if (pcm_stream && !resuming && !started_to_play()) pcm_stream->discard();
		wait_out_flush();
		bool looping = snd && ma_sound_is_looping(&*snd);
		if (still_ending() && restart_if_ending()) {
			if (reset_loop_state) ma_sound_set_looping(&*snd, MA_FALSE);
			clear_stop_for_restart();
			g_soundsystem_last_error = MA_SUCCESS;
			return true;
		}
		return started_or_undone(mixer_impl::play(reset_loop_state), looping);
	}
	bool play_looped() override {
		if (pcm_stream) return (g_soundsystem_last_error = MA_INVALID_OPERATION) == MA_SUCCESS; // Fed by stream_pcm(), it has no end to loop from, as play_wait() says.
		if (fade_paused && snd) clear_stop_for_restart(true);
		paused = fade_paused = false;
		wait_out_flush();
		bool looping = snd && ma_sound_is_looping(&*snd);
		if (still_ending() && restart_if_ending()) {
			ma_sound_set_looping(&*snd, MA_TRUE);
			clear_stop_for_restart();
			g_soundsystem_last_error = MA_SUCCESS;
			return true;
		}
		return started_or_undone(mixer_impl::play_looped(), looping);
	}
	// A sound that read its end in a block of the audio thread, which stops it in its next, counts as playing until then, so that ma_sound_start() left it to be stopped while play() returned true. play() waits that stop out, a block or two at most, and then starts the sound as any at its end: from its start, or not, with the error, when its source can't go back there. Whether the sound is still in that window: so it is with no audio thread to wait for, as for an engine without a device, which the script reads, or on the audio thread itself, as in a processing callback, or once the wait ran out, as for a device not running, when the audio thread is asked to start it instead (see restart_if_ending()).
	bool still_ending() {
		if (!snd || !at_end_seen(&*snd) || !ma_sound_is_playing(&*snd)) return false;
		held_sound* h = held(&*snd);
		if ((get_engine()->get_flags() & audio_engine::NO_DEVICE) || audio_engine_impl::on_audio_thread() || h->restart.load() == held_sound::restart_asked) return true; // An ask left by an earlier call stands.
		// Waited out only while the audio thread goes on processing the sound, as it does in each block it reads the engine, however far apart a device asks for its blocks: not for an engine stopped, nor once the engine's time moved 50 ms without a call of the sound's processing, as for a mixer stopped, nor for longer than 200 ms, as for a device lost.
		audio_engine_impl* engine_impl = dynamic_cast<audio_engine_impl*>(get_engine());
		if (engine_impl && !engine_impl->meant_to_run()) return true;
		ma_engine* engine = ma_sound_get_engine(&*snd);
		const ma_uint64 idle_frames = std::max<ma_uint64>(1, ma_engine_get_sample_rate(engine) / 20);
		const auto give_up = std::chrono::steady_clock::now() + std::chrono::milliseconds(200);
		ma_uint32 calls = h->processed.load();
		ma_uint64 processed_at = ma_engine_get_time_in_pcm_frames(engine);
		while (at_end_seen(&*snd) && ma_sound_is_playing(&*snd) && std::chrono::steady_clock::now() < give_up && !(engine_impl && !engine_impl->meant_to_run())) {
			std::this_thread::sleep_for(std::chrono::microseconds(500));
			const ma_uint32 now_calls = h->processed.load();
			const ma_uint64 now_time = ma_engine_get_time_in_pcm_frames(engine);
			if (now_calls != calls) {
				calls = now_calls;
				processed_at = now_time;
			} else if (now_time - processed_at > idle_frames) break;
		}
		return at_end_seen(&*snd) && ma_sound_is_playing(&*snd);
	}
	// MiniAudio's ma_sound_start() reads the end flag itself, which give_end() turns off while it flushes the end (see held_sound::flushing), so that a play() of a sound stopped during that flush started it without going back to its start, and the audio thread stopped it at its end again: waited out first, one call of the sound's processing at most, which never waits on this thread.
	void wait_out_flush() {
		while (snd && held(&*snd)->flushing.load()) std::this_thread::yield();
	}
	// The audio thread is asked to play a sound still in that window on from its start, which it does in its next block, or once it stopped it in the block under way; a sound stopped meanwhile is taken back and started as any at its end. Whether the audio thread was asked. Its seek can't tell play() that a source can't go back to its start, which then reads nothing more and ends.
	bool restart_if_ending() {
		if (!snd || !at_end_seen(&*snd) || !ma_sound_is_playing(&*snd)) return false;
		held_sound* h = held(&*snd);
		ma_uint64 none = ~(ma_uint64)0;
		h->seek_target.compare_exchange_strong(none, 0); // Its position reads its start at once, as after ma_sound_start(); made once the audio thread clears its end.
		h->restart.store(held_sound::restart_asked);
		if (ma_sound_is_playing(&*snd)) return true;
		int asked = held_sound::restart_asked;
		return !h->restart.compare_exchange_strong(asked, held_sound::restart_none); // Stopped meanwhile: unless the block that stopped it took the ask, started by MiniAudio.
	}
	// Calls off a play() at the sound's end the audio thread hasn't started it for, and waits out one it is starting it for, before the sound is stopped.
	void call_off_restart() {
		if (!snd) return;
		std::atomic<int>& restart = held(&*snd)->restart;
		int asked = held_sound::restart_asked;
		restart.compare_exchange_strong(asked, held_sound::restart_none);
		while (restart.load() == held_sound::restart_taking) std::this_thread::yield(); // A few atomic operations on the audio thread, which never waits on this one.
	}
	// A sound at its end makes a seek once started again (see held_sound_process()); one that can't start again, its source unable to go back to its start, can't make it either, and its position read the seek's frame for good: the seek is dropped, the position reading its end again. Its looping is put back as it was, rather than left as the failed call set it.
	bool started_or_undone(bool started, bool looping) {
		if (started || !snd) return started;
		ma_sound_set_looping(&*snd, looping);
		if (ma_sound_at_end(&*snd)) held(&*snd)->seek_target.store(~(ma_uint64)0);
		return started;
	}
	bool play_wait() override {
		if (audio_engine_impl::on_audio_thread()) { // Waiting for the sound to be played out on an audio thread, as in a processing callback, waited for good on its own engine's, which plays nothing while it waits, and held another's up for the sound's length.
			g_soundsystem_last_error = MA_INVALID_OPERATION;
			return false;
		}
		if (pcm_stream) // Fed by stream_pcm(), it has no end to wait for.
			return (g_soundsystem_last_error = MA_INVALID_OPERATION) == MA_SUCCESS;
		if (!play())
			return false;
		while (started_to_play()) // Due to start too, its start scheduled ahead, which get_playing() reads as not playing until then, so play_wait() returned before it played.
			wait(5);
		return true;
	}
	bool stop() override {
		if (fade_paused && snd) clear_stop_for_restart(true); // Stopped now, so the pause_fade() stop still to come would stop the sound once it plays again.
		paused = fade_paused = false;
		call_off_restart(); // A play() just before, at the sound's end, isn't made after it.
		if (!mixer_impl::stop()) return false;
		return !chain && get_length_in_frames() == 0 || seek(0); // A stream without a length, such as PCM or a URL, has no start to go back to; a chain always has (see seek_in_frames()).
	}
	// A stream_pcm() sound too, whose queue play() resumes, as after pause_fade(): refused, it read as not paused while pause_fade() paused it.
	// Only a sound playing or due to start is made paused: one stopped, finished or never started read as paused, and play() then resumed what stop() had ended, a stream_pcm() sound's queue included, where it starts such a sound again.
	bool pause() override {
		if (snd) {
			call_off_restart(); // As in stop().
			const bool playing = started_to_play();
			g_soundsystem_last_error = ma_sound_stop(&*snd);
			if (g_soundsystem_last_error == MA_SUCCESS && playing)
				paused = true;
			return g_soundsystem_last_error == MA_SUCCESS;
		}
		return false;
	}
	bool pause_fade(unsigned long long length) override {
		return (get_engine()->get_flags() & audio_engine::DURATIONS_IN_FRAMES) ? pause_fade_in_frames(length) : pause_fade_in_milliseconds(length);
	}
	bool pause_fade_in_frames(unsigned long long frames) override {
		if (snd) {
			if (!started_to_play()) return (g_soundsystem_last_error = MA_SUCCESS) == MA_SUCCESS; // As pause() leaves a sound that isn't playing, with no stop scheduled for it either, which play() wouldn't have called off.
			if (drop_deferred_fade()) fade_from_stop = false; // Its fade, which begins now, replaces one scheduled ahead; a stop's that never began left the fader as it was, the script's own fade, which pause_fade(0), a plain stop, then kept.
			stop_fade_set(schedule_pause_fade(frames));
			paused = fade_paused = true; // As pause() does, so play() resumes it.
			return (g_soundsystem_last_error = MA_SUCCESS) == MA_SUCCESS;
		}
		return false;
	}
	bool pause_fade_in_milliseconds(unsigned long long frames) override {
		if (snd && frames_fit(frames, ma_engine_get_sample_rate(ma_sound_get_engine(&*snd)))) {
			if (!started_to_play()) return (g_soundsystem_last_error = MA_SUCCESS) == MA_SUCCESS; // As above.
			if (drop_deferred_fade()) fade_from_stop = false;
			stop_fade_set(schedule_pause_fade(frames * ma_engine_get_sample_rate(ma_sound_get_engine(&*snd)) / 1000)); // As MiniAudio counts the fade's frames.
			paused = fade_paused = true;
			return (g_soundsystem_last_error = MA_SUCCESS) == MA_SUCCESS;
		}
		return false;
	}
	void set_timed_fade(float start_volume, float end_volume, unsigned long long length, unsigned long long absolute_time) override {
		return (get_engine()->get_flags() & audio_engine::DURATIONS_IN_FRAMES) ? set_timed_fade_in_frames(start_volume, end_volume, length, absolute_time) : set_timed_fade_in_milliseconds(start_volume, end_volume, length, absolute_time);
	}
	// The volumes are decibels on an engine with PERCENTAGE_ATTRIBUTES, as set_fade() takes them.
	void set_timed_fade_in_frames(float start_volume, float end_volume, unsigned long long frames, unsigned long long absolute_time_in_frames) override {
		if (!snd) return;
		fade_volumes_to_linear(start_volume, end_volume);
		if (!finite_values({start_volume, end_volume})) return;
		reset_stop_fade(); // It replaces a stop's fade, as in MiniAudio's only fader.
		if (absolute_time_in_frames == ~(ma_uint64)0) return set_timed_fade_now(start_volume, end_volume, frames);
		defer_fade(start_volume, end_volume, frames, absolute_time_in_frames);
	}
	// ~0 is now to MiniAudio, which then begins the fade where it takes it, over its whole length, as a fade set at once: counted from the engine's time instead, which is the start of the block under way while the audio thread processes one, a fade shorter than a block given in the next jumped to its end.
	void set_timed_fade_now(float start_volume, float end_volume, ma_uint64 frames) {
		drop_deferred_fade(); // It replaces one scheduled ahead, as set_fade() does.
		set_fade_now(start_volume, end_volume, std::min<ma_uint64>(frames, UINT_MAX));
	}
	void set_timed_fade_in_milliseconds(float start_volume, float end_volume, unsigned long long frames, unsigned long long absolute_time_in_frames) override {
		if (!snd) return;
		fade_volumes_to_linear(start_volume, end_volume);
		if (!finite_values({start_volume, end_volume})) return;
		ma_uint32 rate = ma_engine_get_sample_rate(ma_sound_get_engine(&*snd));
		const bool now = absolute_time_in_frames == ~(ma_uint64)0; // Now, as in frames, rather than refused for its size.
		if (!frames_fit(frames, rate) || !now && !frames_fit(absolute_time_in_frames, rate)) return;
		reset_stop_fade();
		if (now) return set_timed_fade_now(start_volume, end_volume, frames * rate / 1000);
		defer_fade(start_volume, end_volume, frames * rate / 1000, absolute_time_in_frames * rate / 1000); // As MiniAudio converts both.
	}
	void set_stop_time_with_fade(unsigned long long absolute_time, unsigned long long fade_length) override {
		return (get_engine()->get_flags() & audio_engine::DURATIONS_IN_FRAMES) ? set_stop_time_with_fade_in_frames(absolute_time, fade_length) : set_stop_time_with_fade_in_milliseconds(absolute_time, fade_length);
	}
	// A stop the script schedules replaces one pause_fade() scheduled, which play() then keeps.
	void set_stop_time_with_fade_in_frames(unsigned long long absolute_time, unsigned long long fade_length) override {
		if (!snd) return;
		stop_if_stop_came();
		pause_called_off();
		stop_fade_set(schedule_stop_with_fade(absolute_time, fade_length));
		fade_paused = false;
	}
	// The stop is MiniAudio's, its fade waits in the sound for its time (see held_sound::fade_at), to fade from the volume the sound is at then. It replaces the fade of a stop before it, which goes back to full volume if it began, as a sound pause_fade() stopped is at 0 though it plays on at full volume once started.
	// pause_fade()'s stop, now and the fade's length on, as ma_sound_stop_with_fade_in_pcm_frames() makes it, its fade waiting in the sound as a stop's does rather than given to MiniAudio with that absolute start, from which MiniAudio counted its fader's cursor: with the engine's time moved on past 2^32 frames before it took the fade, as set_time_in_frames() can, the cursor overran its fader's processing, which wrote past the block. The length is cut to MiniAudio's limit for fades, so that the stop can't wrap past 2^64 to now, or to ~0, which is no stop at all. Returns that length.
	ma_uint64 schedule_pause_fade(ma_uint64 frames) {
		frames = std::min<ma_uint64>(frames, UINT_MAX);
		const ma_uint64 now = ma_engine_get_time_in_pcm_frames(ma_sound_get_engine(&*snd)), stop = now < ~(ma_uint64)0 - frames? now + frames : ~(ma_uint64)0 - 1;
		if (frames > 0) schedule_stop_and_fade(stop, frames, now);
		else ma_node_set_state_time(&*snd, ma_node_state_stopped, stop);
		return frames;
	}
	// Returns the fade's length as limited, none for a stop at 0, which is a plain stop.
	ma_uint64 schedule_stop_with_fade(ma_uint64 stop, ma_uint64 fade) {
		reset_stop_fade();
		if (fade > stop) fade = stop; // As MiniAudio limits it.
		if (fade > 0) schedule_stop_and_fade(stop, fade);
		else ma_node_set_state_time(&*snd, ma_node_state_stopped, stop);
		return fade;
	}
	// A stop at stop with a fade of fade frames before it, from the volume the sound is at. The fade waits in the sound before the stop is set, so the audio thread never takes the stop without it. While the audio thread processes a block, the engine's time is that block's start, and the sound may have been processed in it already, without the fade, which it then gives in its next block: a stop before that block was taken there without processing the sound, the fade never heard and the sound cut at full volume, as a pause_fade() or a TTS interruption shorter than a block mostly were with the engine read on another thread, and a fade beginning before it was heard only in part. The fade then begins at that next block, the stop its length after. The audio thread records the block before it tries the fade's lock, so a block it gave nothing in, the script holding the lock, is seen too.
	// from: the engine's time a fade from now, as pause_fade()'s, whose length counts, was counted from; ~0 for a stop at an absolute time, which counts, and which is moved only when it would come before the sound could be processed with its fade, a stop that had come already being taken at once without one, as before. The block under way is judged at the time the stop was counted from: judged at a time read later, it could already be past the block that played the sound without the fade.
	void schedule_stop_and_fade(ma_uint64 stop, ma_uint64 fade, ma_uint64 from = ~(ma_uint64)0) {
		const bool relative = from != ~(ma_uint64)0;
		const ma_uint64 now = relative? from : ma_engine_get_time_in_pcm_frames(ma_sound_get_engine(&*snd)), at = stop - fade;
		defer_fade(-1, 0, fade, at);
		ma_node_set_state_time(&*snd, ma_node_state_stopped, stop);
		held_sound* h = held(&*snd);
		const ma_uint64 block = current_block(now); // The block under way, if the sound was processed in it.
		if (block == ~(ma_uint64)0 || !h->fade_pending.load()) return; // Given in time in the next block the sound is processed in.
		const ma_uint64 next = block + SOUNDSYSTEM_FRAMESIZE;
		// From now, the fade begins in that block, which played the sound already; at a time, a stop from that block's end on lets the next give what is left of the fade, from the volume the sound is at, as for a fade given late.
		if (relative? at >= next : stop >= next || stop < block) return; // A stop before the block that played the sound came already, as audio past it was played.
		// Whether that block gave it is known once the audio thread is done with the sound there, a few microseconds at most: in it after the fade waited, it gives it, unless the lock was held, and then read the stop only after it was set, as MiniAudio reads a sound's state before processing it, so that the stop is moved before MiniAudio took it. A sound the audio thread is held up in, as by a slow datastream, isn't waited for past a few milliseconds.
		if (!audio_engine_impl::on_audio_thread()) {
			const auto give_up = std::chrono::steady_clock::now() + std::chrono::milliseconds(5);
			while (h->block_done.load() != block && h->block_at.load() == block && std::chrono::steady_clock::now() < give_up) std::this_thread::yield();
		}
		h->lock_fade();
		if (h->fade_pending.load() && !h->fade_given && h->fade_at == at) { // Not given since, nor replaced.
			// The block after it, or after the one under way should the audio thread have moved on, or the engine's time been set back, meanwhile, its stop passing before it could process the sound.
			const ma_uint64 time = ma_engine_get_time_in_pcm_frames(ma_sound_get_engine(&*snd)), still = current_block(time);
			const ma_uint64 later = still != ~(ma_uint64)0? std::max(still, time) : time;
			const ma_uint64 moved = later <= ~(ma_uint64)0 - SOUNDSYSTEM_FRAMESIZE? later + SOUNDSYSTEM_FRAMESIZE : later;
			h->fade_at = moved;
			ma_node_set_state_time(&*snd, ma_node_state_stopped, moved < ~(ma_uint64)0 - fade && moved + fade > stop? moved + fade : stop);
		}
		h->unlock_fade();
	}
	void set_stop_time_with_fade_in_milliseconds(unsigned long long absolute_time, unsigned long long fade_length) override {
		if (!snd) return;
		ma_uint32 rate = ma_engine_get_sample_rate(ma_sound_get_engine(&*snd));
		if (!frames_fit(absolute_time, rate) || !frames_fit(fade_length, rate)) return;
		stop_if_stop_came();
		pause_called_off();
		stop_fade_set(schedule_stop_with_fade(absolute_time * rate / 1000, fade_length * rate / 1000)); // As MiniAudio converts both.
		fade_paused = false;
	}
	// A plain stop replaces a stop with a fade too, so that stop's fade goes with it rather than leaving the sound silent until the new stop.
	void set_stop_time_in_frames(ma_uint64 absolute_time) override {
		mixer_impl::set_stop_time_in_frames(absolute_time);
		pause_called_off();
		forget_stop_fade();
	}
	void set_stop_time_in_milliseconds(ma_uint64 absolute_time) override {
		if (snd && !frames_fit(absolute_time, ma_engine_get_sample_rate(ma_sound_get_engine(&*snd)))) return; // Refused, so the stop set before stays.
		mixer_impl::set_stop_time_in_milliseconds(absolute_time);
		pause_called_off();
		forget_stop_fade();
	}
	// A pause_fade() whose stop hasn't come, which a stop the script schedules replaces: the sound plays on, so it is no longer paused, which play() took for a resume after that stop came, a stream_pcm() sound keeping its queue as no other stopped sound does. One whose pause came, which stop_if_stop_came() stopped, or which pause() stopped since, stays paused.
	void pause_called_off() {
		if (fade_paused && snd && ma_node_get_state(&*snd) == ma_node_state_started) paused = false;
	}
	void forget_stop_fade() {
		if (!snd) return;
		reset_stop_fade();
		fade_paused = false;
	}
	// After a stop with a fade was scheduled, its fade being this many frames long. MiniAudio sets no fade of no length, so such a stop is a plain one, after which play() mustn't reset the script's own fade, and which replaced a stop with a fade along with that stop's fade, as set_stop_time() does.
	void stop_fade_set(ma_uint64 fade_frames) {
		if (!fade_frames) forget_stop_fade();
		fade_from_stop = fade_frames > 0;
	}
	void set_looping(bool looping) override {
		if (snd)
			ma_sound_set_looping(&*snd, looping);
	}
	bool get_looping() override {
		return snd ? ma_sound_is_looping(&*snd) : false;
	}
	bool get_at_end() override {
		return snd ? at_end_seen(&*snd) : false;
	}
	bool seek(unsigned long long position) override { return get_engine()->get_flags() & audio_engine::DURATIONS_IN_FRAMES? seek_in_frames(position) : seek_in_milliseconds(position); }
	bool seek_in_frames(unsigned long long position) override {
		unsigned long long length = get_length_in_frames();
		if (!length && !(chain && !position)) { // A chain of unknown length can still be sought to its start, which its view always finds.
			g_soundsystem_last_error = MA_INVALID_OPERATION; // A stream without a length, which left no error.
			return false;
		}
		if (length && position > length) { // MiniAudio takes such a seek and then ignores it on the audio thread, while the position reads as the target.
			g_soundsystem_last_error = MA_INVALID_ARGS;
			return false;
		}
		if (!snd->pDataSource) { // As ma_sound_seek_to_pcm_frame() refuses it.
			g_soundsystem_last_error = MA_INVALID_OPERATION;
			return false;
		}
		held(&*snd)->seek_target.store(position); // Made on the thread reading the engine, at the start of a block (see held_sound_process()).
		g_soundsystem_last_error = MA_SUCCESS;
		return true;
	}
	bool seek_in_milliseconds(unsigned long long offset) override {
		ma_uint32 sample_rate = 0; // The sound's own, which its frames count in; the engine's differs for a file at another rate, and is 0 for an engine without a device.
		if (!snd || ma_sound_get_data_format(&*snd, nullptr, nullptr, &sample_rate, nullptr, 0) != MA_SUCCESS || !sample_rate || !frames_fit(offset, sample_rate)) return false;
		return seek_in_frames((offset * sample_rate) / 1000);
	}
	unsigned long long get_position() override {
		if (!snd) return 0;
		if (get_engine()->get_flags() & audio_engine::DURATIONS_IN_FRAMES)
			return get_position_in_frames();
		else
			return get_position_in_milliseconds();
	}
	// The frame a seek not yet made asked for, as MiniAudio reports its own, or the source's cursor, which is the length once the sound played to its end: a resampling decoder gives a few frames more or fewer than the length it reports, and MiniAudio's stream counts its cursor modulo that length, so a stream that played to its end read a position near 0.
	ma_result get_cursor(ma_uint64& pos) {
		ma_uint64 target = held(&*snd)->seek_target.load();
		if (target != ~(ma_uint64)0) {
			pos = target;
			return MA_SUCCESS;
		}
		ma_result result = ma_sound_get_cursor_in_pcm_frames(&*snd, &pos);
		if (result == MA_SUCCESS && at_end_seen(&*snd) && front) { // A stream ended where it played to, rather than where a looping one that couldn't go back wrapped its cursor (see decode_front_view::played_to).
			ma_uint64 to = front->played_to.load();
			if (to != ~(ma_uint64)0) pos = to;
		}
		if (result == MA_SUCCESS && at_end_seen(&*snd) && !ma_sound_is_looping(&*snd)) {
			unsigned long long length = get_length_in_frames();
			if (length) pos = length;
		}
		return result;
	}
	unsigned long long get_position_in_frames() override {
		if (snd) {
			ma_uint64 pos = 0;
			g_soundsystem_last_error = get_cursor(pos);
			return g_soundsystem_last_error == MA_SUCCESS ? pos : 0;
		}
		return 0;
	}
	unsigned long long get_position_in_milliseconds() override {
		if (snd) {
			ma_uint64 frames = 0;
			ma_uint32 sample_rate = 0;
			if ((g_soundsystem_last_error = get_cursor(frames)) != MA_SUCCESS || (g_soundsystem_last_error = ma_sound_get_data_format(&*snd, nullptr, nullptr, &sample_rate, nullptr, 0)) != MA_SUCCESS) return 0;
			return frames_to_milliseconds(frames, sample_rate);
		}
		return 0;
	}
	unsigned long long get_length() override {
		if (!snd)
			return 0;
		if (get_engine()->get_flags() & audio_engine::DURATIONS_IN_FRAMES)
			return get_length_in_frames();
		else
			return get_length_in_milliseconds();
	}
	unsigned long long get_length_in_frames() override {
		if (snd && chain) return chain_length_frames(); // The whole chain's.
		if (snd && datasource_opened && datasource) return datasource->get_length_frames(); // The source the script opened answers for itself, as a decoder's length is worked out only while nothing reads it.
		if (snd) {
			ma_uint64 len;
			g_soundsystem_last_error = ma_sound_get_length_in_pcm_frames(&*snd, &len);
			return g_soundsystem_last_error == MA_SUCCESS ? len : 0;
		}
		return 0;
	}
	unsigned long long get_length_in_milliseconds() override {
		if (snd && chain) {
			ma_uint32 sample_rate = 0;
			return ma_data_source_get_data_format(chain->head, nullptr, nullptr, &sample_rate, nullptr, 0) == MA_SUCCESS && sample_rate? chain_length_frames() * 1000 / sample_rate : 0;
		}
		if (snd && datasource_opened && datasource) { // As get_length_in_frames(), counted exactly as below rather than through the source's float milliseconds.
			ma_uint32 sample_rate = 0;
			if ((g_soundsystem_last_error = ma_sound_get_data_format(&*snd, nullptr, nullptr, &sample_rate, nullptr, 0)) != MA_SUCCESS) return 0;
			return frames_to_milliseconds(datasource->get_length_frames(), sample_rate);
		}
		if (snd) {
			ma_uint64 len = 0;
			ma_uint32 sample_rate = 0;
			if ((g_soundsystem_last_error = ma_sound_get_length_in_pcm_frames(&*snd, &len)) != MA_SUCCESS || (g_soundsystem_last_error = ma_sound_get_data_format(&*snd, nullptr, nullptr, &sample_rate, nullptr, 0)) != MA_SUCCESS) return 0;
			return frames_to_milliseconds(len, sample_rate);
		}
		return 0;
	}
	// Exactly, as seek_in_milliseconds() counts the other way: through a float, as MiniAudio's seconds go, a position or length past about 2^24 frames, six minutes at 48 kHz, came out rounded, by milliseconds after an hour, so that a position read and sought back drifted.
	static unsigned long long frames_to_milliseconds(ma_uint64 frames, ma_uint32 sample_rate) {
		if (!sample_rate) return 0;
		return frames <= ~(ma_uint64)0 / 1000? frames * 1000 / sample_rate : (unsigned long long)((double)frames / sample_rate * 1000);
	}
	bool get_data_format(ma_format *format, unsigned int *channels, unsigned int *sample_rate) override {
		if (format) *format = ma_format_unknown; // As MiniAudio sets them when it fails, for a sound without anything loaded.
		if (channels) *channels = 0;
		if (sample_rate) *sample_rate = 0;
		if (snd) {
			g_soundsystem_last_error = ma_data_source_get_data_format(own_source(), format, channels, sample_rate, nullptr, 0); // The source's own, which a float_view gives in float.
			return g_soundsystem_last_error == MA_SUCCESS;
		}
		return false;
	}
	// A completely pointless API here, but needed for code that relies on legacy BGT includes. Always returns 0.
	double get_pitch_lower_limit() override {
		return 0;
	}
};
// Whether an autoclosed sound is kept: playing, or due to start (see sound_impl::started_to_play()).
static bool sound_due_to_play(sound* s) {
	sound_impl* impl = dynamic_cast<sound_impl*>(s);
	return impl? impl->started_to_play() : s->get_playing();
}

class microphone_impl : public audio_ring_buffer_impl, public virtual microphone {
	unique_ptr<ma_device> capture_device;
	std::mutex capture_write_mutex; // See reset().
	bool follows_default = true; // Opened as the system's default, which reads as -1, rather than as a device of the list.
	ma_device_id device_id{}; // The device of the list it was opened as, whose index is looked up in the list as it is now.
	static void capture_data_callback(ma_device* pDevice, void* pOutput, const void* pInput, ma_uint32 frameCount) {
		microphone_impl* node = (microphone_impl*)pDevice->pUserData;
		if (!node || !pInput || !frameCount) return;
		std::unique_lock<std::mutex> lock(node->capture_write_mutex, std::try_to_lock);
		if (lock.owns_lock()) node->audio_ring_buffer_impl::write((float*)pInput, frameCount); // Not write(), which takes this lock.
	}
public:
	// set_device(), set_state() and the volume, one at a time, with capture_device, which set_device() opens anew: two threads changing the device at once uninitialised and opened it under each other.
	mutable std::mutex device_mutex;
	std::atomic<float> volume_db{0}; // The volume the script set, which MiniAudio's ma_device_init() sets back to 0 dB on each device opened, so that set_device() lost it.
	bool wants_recording = true; // Whether the microphone is meant to record: by the constructor and set_state(); the node's state, which reads stopped while no device records, left one that set_device() couldn't open a device for stopped once a later one could. Under device_mutex.
	// device_mutex, which an audio thread, as in a processing callback, only tries, as it mustn't wait while another thread opens a device; MA_BUSY then, and a lock not held.
	std::unique_lock<std::mutex> lock_device() const {
		std::unique_lock<std::mutex> lock(device_mutex, std::defer_lock);
		if (!audio_engine_impl::on_audio_thread()) lock.lock();
		else if (!lock.try_lock()) g_soundsystem_last_error = MA_BUSY;
		return lock;
	}
	// Opens capture_device on the device with that id, or the system's default for null, without starting it, at the volume the script set.
	bool open_capture(const ma_device_id* id) {
		ma_device_config device_config = ma_device_config_init(ma_device_type_capture);
		device_config.capture.format = ma_format_f32;
		device_config.capture.channels = get_engine()->get_channels();
		device_config.sampleRate = get_engine()->get_sample_rate();
		device_config.dataCallback = capture_data_callback;
		device_config.pUserData = this;
		device_config.periodSizeInFrames = SOUNDSYSTEM_FRAMESIZE * 2;
		device_config.capture.pDeviceID = id;
		capture_device = make_unique<ma_device>();
		if ((g_soundsystem_last_error = ma_device_init(&g_sound_context, &device_config, &*capture_device)) != MA_SUCCESS) {
			capture_device.reset();
			return false;
		}
		if (volume_db.load() != 0) ma_device_set_master_volume_db(&*capture_device, volume_db.load());
		return true;
	}
	// An index out of range opens the default device, as -1 does, and reads as -1 then.
	microphone_impl(audio_engine* e, int device) : audio_ring_buffer_impl(e->get_channels(), 8192, e) {
		follows_default = !(device >= 0 && audio_device_id(ma_device_type_capture, device, device_id));
		if (!open_capture(follows_default? nullptr : &device_id)) throw std::runtime_error("failed to initialize capture device");
		if ((g_soundsystem_last_error = ma_device_start(&*capture_device)) != MA_SUCCESS) audio_node_impl::set_state(ma_node_state_stopped);
	}
	~microphone_impl() {
		if (capture_device) uninit_device(&*capture_device);
	}
	// The last reference let go on an audio thread, as in a processing callback, whose audio would be held up while the capture device closes, about 200 ms: destroyed on a thread of its own then, as an engine is (see audio_engine_impl::release()). Once the sound system shut down it is left to the process's exit on any thread, as an engine is: closing its capture device then can come after SDL took down what the backend needs.
	void release() override {
		if (asAtomicDec(refcount) >= 1) return;
		if (g_soundsystem_shut_down.test()) return;
		if (!audio_engine_impl::on_audio_thread()) {
			delete this;
			return;
		}
		delete_detached(this);
	}
	bool set_device(int device) override {
		if (audio_engine_impl::on_audio_thread()) { // Opening a device on an audio thread, as in a processing callback, would hold that thread up; refused there, as an engine's set_device() is.
			g_soundsystem_last_error = MA_INVALID_OPERATION;
			return false;
		}
		ma_device_id requested_id; // Copied: the list can be taken anew while the device opens.
		if (device < -1 || device > -1 && !audio_device_id(ma_device_type_capture, device, requested_id)) {
			g_soundsystem_last_error = MA_INVALID_ARGS;
			return false;
		}
		std::lock_guard<std::mutex> lock(device_mutex);
		// Without a device open, as after one failed to, or with one the backend stopped while the microphone is meant to record, it is opened anew.
		if (capture_device && (!wants_recording || ma_device_is_started(&*capture_device)) && (device == -1? follows_default : !follows_default && ma_device_id_equal(&requested_id, &device_id))) return true;
		const bool had_device = capture_device != nullptr;
		if (had_device) {
			ma_device_stop(&*capture_device);
			uninit_device(&*capture_device);
		}
		ma_result error;
		if (open_capture(device > -1? &requested_id : nullptr)) {
			// A microphone the script stopped stays stopped on the new device, as set_state() starts it, dropping what it held then; one meant to record records on it, as again after a spell without a device.
			if (!wants_recording || (error = ma_device_start(&*capture_device)) == MA_SUCCESS) {
				follows_default = device == -1;
				if (!follows_default) device_id = requested_id;
				if (wants_recording && get_state() != ma_node_state_started) {
					discard_queued();
					audio_node_impl::set_state(ma_node_state_started);
				}
				g_soundsystem_last_error = MA_SUCCESS;
				return true;
			}
			uninit_device(&*capture_device);
			capture_device.reset();
		} else error = g_soundsystem_last_error;
		// The device asked for couldn't be opened or started: the one in use before is opened again, as an engine's set_device() does, so that asking for it changes nothing. The error reported stays that of the device asked for. Without a device that records, the node reads stopped, the microphone still meant to record once a set_device() opens one.
		const bool recording = had_device && open_capture(follows_default? nullptr : &device_id) && wants_recording && ma_device_start(&*capture_device) == MA_SUCCESS;
		if (wants_recording) audio_node_impl::set_state(recording? ma_node_state_started : ma_node_state_stopped);
		g_soundsystem_last_error = error;
		return false;
	}
	int get_device() const override {
		std::unique_lock<std::mutex> lock = lock_device();
		if (!lock) return -1;
		return !capture_device || follows_default? -1 : audio_device_index(ma_device_type_capture, device_id);
	}
	// A ring buffer has one writer and one reader, and resetting it moves both positions: reset() while the capture thread wrote into it could leave that writer writing past its end. reset() therefore holds this, which the capture thread only tries for, dropping what it captured meanwhile rather than waiting.
	void reset() override {
		std::lock_guard<std::mutex> lock(capture_write_mutex);
		audio_ring_buffer_impl::reset();
	}
	// The script's writes, which the capture thread's would otherwise overlap as a second writer, the two then committing over each other and leaving later writes granted space past the buffer's end. They take turns as reset() does.
	unsigned int write(const float* frames_in, unsigned int frame_count) override {
		std::lock_guard<std::mutex> lock(capture_write_mutex);
		return audio_ring_buffer_impl::write(frames_in, frame_count);
	}
	bool set_state(ma_node_state state) override {
		std::unique_lock<std::mutex> lock = lock_device();
		if (!lock) return false;
		if (state == ma_node_state_started && !capture_device) { // Nothing to record from, as after set_device() could open no device.
			g_soundsystem_last_error = MA_INVALID_OPERATION;
			return false;
		}
		if (state == ma_node_state_started || state == ma_node_state_stopped) wants_recording = state == ma_node_state_started;
		// A microphone started again drops what it recorded before it stopped, through its reader (see pcm_queue), before its node is read again; one already recording keeps its queue.
		if (capture_device && state == ma_node_state_started && !ma_device_is_started(&*capture_device)) discard_queued();
		bool ret = audio_node_impl::set_state(state);
		if (!capture_device || !ret) return ret;
		if (state == ma_node_state_stopped) return (g_soundsystem_last_error = ma_device_stop(&*capture_device)) == MA_SUCCESS;
		if (state != ma_node_state_started) return false;
		ma_result result = ma_device_start(&*capture_device);
		if (result != MA_SUCCESS) audio_node_impl::set_state(ma_node_state_stopped); // A device that didn't start leaves the microphone stopped, as the constructor and set_device() do, rather than reading started.
		g_soundsystem_last_error = result;
		return result == MA_SUCCESS;
	}
	void set_volume(float volume) override {
		if (!finite_values({volume, ma_volume_db_to_linear(volume)}) || volume > 0) { // A device's volume goes no higher than 0 dB, which MiniAudio refuses, so that it was kept and read back while no device took it.
			g_soundsystem_last_error = MA_INVALID_ARGS;
			return;
		}
		std::unique_lock<std::mutex> lock = lock_device();
		if (!lock) return;
		volume_db = volume; // Kept for a device opened later, as without one now (see open_capture()).
		g_soundsystem_last_error = capture_device? ma_device_set_master_volume_db(&*capture_device, volume) : MA_SUCCESS;
	}
	float get_volume() const override { return volume_db.load(); }
};
microphone* microphone::create(int device, audio_engine* engine) {
	if (engine) return new microphone_impl(engine, device);
	audio_engine *default_engine = acquire_default_engine(); // Without an engine, the default one, as other nodes take; the constructor needs its format first.
	if (!default_engine) throw runtime_error("no audio engine available");
	try {
		microphone *result = new microphone_impl(default_engine, device);
		default_engine->release();
		return result;
	} catch (...) {
		default_engine->release();
		throw;
	}
}

audio_engine *new_audio_engine(int flags, int sample_rate, int channels) { return new audio_engine_impl(flags, sample_rate, channels); }
mixer *new_mixer(audio_engine *engine) { return new mixer_impl(engine); }
sound *new_sound(audio_engine *engine) { return new sound_impl(engine); }
// The default engine with a reference of the caller's own: another thread making a different engine the default lets go of the old one, which could otherwise be destroyed while it is used. Null when the sound system couldn't start.
audio_engine *acquire_default_engine() {
	if (!init_sound()) return nullptr;
	std::lock_guard<std::recursive_mutex> lock(g_soundsystem_init_mutex); // Which set_sound_default_engine() swaps the engine under.
	if (g_audio_engine) g_audio_engine->duplicate();
	return g_audio_engine;
}
// Holds such a reference for as long as a function uses the default engine.
struct default_engine_ref {
	audio_engine *engine = acquire_default_engine();
	default_engine_ref() = default;
	default_engine_ref(const default_engine_ref &) = delete;
	default_engine_ref &operator=(const default_engine_ref &) = delete;
	~default_engine_ref() { if (engine) engine->release(); }
	explicit operator bool() const { return engine != nullptr; }
	audio_engine *operator->() const { return engine; }
};
// Stops engines' processing callbacks from calling the script and waits for calls under way, so the script's module can go away while engines, which a script can keep past that, still run.
void sound_stop_script_callbacks() {
	g_script_callbacks_stopped = true;
	while (g_script_callbacks_running) std::this_thread::sleep_for(std::chrono::milliseconds(1));
	// And for engines and microphones let go of on an audio thread, which could otherwise release a callback once the module is gone, or close a device once SDL is (see delete_detached()).
	std::unique_lock<std::mutex> lock(g_detached_deletes_mutex);
	g_detached_deletes_done.wait(lock, []() { return g_detached_deletes == 0; });
}
mixer *new_global_mixer() {
	default_engine_ref engine;
	if (!engine) throw runtime_error("no audio engine available");
	return new mixer_impl(engine.engine);
}
// A sound on the default engine that isn't attached to sound_default_mixer, which the script can pause or turn down, but plays straight to the engine's endpoint, as speech does.
sound *new_global_sound_unmixed() {
	default_engine_ref engine;
	if (!engine) return nullptr; // The sound system couldn't start.
	return new sound_impl(engine.engine);
}
sound *new_global_sound() {
	sound* s = new_global_sound_unmixed();
	if (mixer* mix = s? acquire_default_mixer() : nullptr) { // Refused for a sound_default_mixer of an engine other than the default one, which leaves the sound on the default engine's endpoint.
		s->set_mixer(mix);
		mix->release();
	}
	return s;
}
int get_sound_output_device() {
	default_engine_ref engine;
	return engine? engine->get_device() : -1;
}
void set_sound_output_device(int device) {
	default_engine_ref engine;
	if (engine) engine->set_device(device);
}
sound* sound_play(const string& path, const reactphysics3d::Vector3& position, float volume, float pan, float pitch, mixer* mix, const pack_interface* pack_file, bool autoplay) {
	default_engine_ref engine;
	if (!engine) return nullptr;
	mixer* default_mix = mix? nullptr : acquire_default_mixer();
	sound* s;
	try {
		s = engine->play(path, position, volume, pan, pitch, mix? mix : default_mix, pack_file, autoplay); // Without a mixer of its own, on sound_default_mixer as other new sounds are, unless that mixer is of another engine.
	} catch (...) { // As when the load throws.
		if (default_mix) default_mix->release();
		throw;
	}
	if (default_mix) default_mix->release();
	return s;
}
reactphysics3d::Vector3 sound_get_listener_position(unsigned int listener_index = 0) {
	default_engine_ref engine;
	if (!engine) return reactphysics3d::Vector3(0, 0, 0);
	return engine->get_listener_position(listener_index);
}
bool sound_set_listener_position(float x, float y, float z, unsigned int listener_index = 0) {
	default_engine_ref engine;
	if (!engine) return false;
	engine->set_listener_position(listener_index, x, y, z);
	return true;
}
bool sound_set_listener_position_vector(const reactphysics3d::Vector3& position, unsigned int listener_index = 0) {
	default_engine_ref engine;
	if (!engine) return false;
	engine->set_listener_position_vector(listener_index, position);
	return true;
}
// Encryption.
void set_default_decryption_key(const std::string &key) {
	if (!init_sound_context())
		return;
	g_sound_service->set_filter_directive(g_encryption_filter_slot, std::make_shared < std::string > (key));
	g_sound_service->set_default_filter(key.empty() ? sound_service::null_filter_slot : g_encryption_filter_slot);
}
// Set default pack storage for future sounds. Null means go back to local file system.
// Note: a pack must be marked immutable in order to be used with sound service.
void set_sound_default_storage(pack_interface *obj) {
	if (!init_sound_context())
		return;
	if (obj == nullptr) {
		g_sound_service->set_default_protocol(sound_service::fs_protocol_slot);
		g_sound_service->set_protocol_directive(g_pack_protocol_slot, nullptr);
		return;
	}
	g_sound_service->set_protocol_directive(g_pack_protocol_slot, std::shared_ptr < const pack_interface > (obj->make_immutable()));
	g_sound_service->set_default_protocol(g_pack_protocol_slot);
}
const pack_interface *get_sound_default_storage() {
	if (!init_sound_context() || !g_sound_service->is_default_protocol(g_pack_protocol_slot))
		return nullptr;
	std::shared_ptr < const pack_interface > obj = std::static_pointer_cast < const pack_interface>(g_sound_service->get_protocol_directive(g_pack_protocol_slot));
	if (!obj) return nullptr;
	return obj->get_mutable();
}
int get_soundsystem_last_error() { return g_soundsystem_last_error; }
string get_soundsystem_last_error_text() {
	const char* msg = ma_result_description(g_soundsystem_last_error);
	return msg? msg : "";
}
void set_sound_master_volume(float db) {
	default_engine_ref engine;
	if (!engine)
		return;
	if (!(db <= 0 && db >= -100)) // NaN fails both, and is ignored as other values out of range are.
		return;
	ma_engine_set_volume(engine->get_ma_engine(), ma_volume_db_to_linear(db));
}
float get_sound_master_volume() {
	default_engine_ref engine;
	if (!engine)
		return 0;
	const float db = ma_volume_linear_to_db(ma_engine_get_volume(engine->get_ma_engine()));
	return db >= -100? db : -100; // As quiet as it can be set, also for a volume of 0 set on the engine itself, which is -inf dB, outside the range it is read in.
}
audio_engine* get_sound_default_engine() { return acquire_default_engine(); } // The reference goes to the script.
// Whether there is a default engine, starting the sound system to build it if need be; unlike sound_default_engine, it reports one that can't be built, as on a machine without an output device, rather than throwing.
bool get_sound_system_available() {
	try {
		audio_engine *engine = acquire_default_engine();
		if (!engine) return false;
		engine->release();
		return true;
	} catch (const std::exception &) {
		return false;
	}
}
void set_sound_default_engine(audio_engine* engine) {
	if (!engine) throw runtime_error("a default audio engine must exist");
	if (!g_soundsystem_initialized.test()) {
		engine->release(); // The script's reference, given to this function.
		throw runtime_error("soundsystem not initialized");
	}
	audio_engine *old;
	{
		std::lock_guard<std::recursive_mutex> lock(g_soundsystem_init_mutex); // Not while init_sound() builds the default engine on another thread.
		if (g_soundsystem_shut_down.test()) { // Which a script thread still running at shutdown could otherwise mark ready again.
			engine->release();
			throw runtime_error("the sound system has shut down");
		}
		old = g_audio_engine;
		g_audio_engine = engine;
		g_soundsystem_ready.test_and_set(); // The script's engine is the default now, possibly before init_sound() ever built one, which it then doesn't do over it.
	}
	if (old) old->release(); // After the lock: destroying the engine waits for its processing callback, which can be asking for the default engine.
}
// The bytes in one frame of PCM, 0 for a format pcm_to_wav() can't write.
static int pcm_frame_size(ma_format format, int channels) {
	int frame_size = 0;
	switch (format) {
		case ma_format_u8:
			frame_size = 1;
			break;
		case ma_format_s16:
			frame_size = 2;
			break;
		case ma_format_s24:
			frame_size = 3;
			break;
		case ma_format_s32:
			frame_size = 4;
			break;
		case ma_format_f32:
			frame_size = 4;
			break;
		default:
			return 0;
	}
	return channels > 0? frame_size * channels : 0;
}
// Writes PCM as a wav file into output, which holds capacity bytes. The encoder completes the header when it is closed, so the stream is checked after that.
static bool write_pcm_as_wav(const void *buffer, unsigned int size, ma_format format, int samplerate, int channels, void *output, size_t capacity) {
	int frame_size = pcm_frame_size(format, channels);
	if (!frame_size)
		return false;
	Poco::MemoryOutputStream stream((char *)output, capacity);
	ma_encoder_config cfg = ma_encoder_config_init(ma_encoding_format_wav, format, channels, samplerate);
	ma_encoder encoder;
	std::ostream *output_stream = &stream; // The callbacks take the std::ostream, which isn't the first base of a MemoryOutputStream.
	g_soundsystem_last_error = ma_encoder_init(wav_write_proc, wav_seek_proc, output_stream, &cfg, &encoder);
	if (g_soundsystem_last_error != MA_SUCCESS)
		return false;
	// Should be okay to push the content in one go:
	ma_uint64 frames_written;
	g_soundsystem_last_error = ma_encoder_write_pcm_frames(&encoder, buffer, size / frame_size, &frames_written);
	ma_encoder_uninit(&encoder);
	if (g_soundsystem_last_error != MA_SUCCESS)
		return false;
	return stream.good();
}
bool sound::pcm_to_wav(const void *buffer, unsigned int size, ma_format format, int samplerate, int channels, std::string &output) {
	if (channels < 1 || channels > MA_MAX_CHANNELS) return false; // dr_wav keeps the count in 16 bits, and divided by it cut to 0.
	int frame_size = pcm_frame_size(format, channels);
	if (!frame_size)
		return false;
	unsigned int data_size = size - size % frame_size; // Whole frames only.
	output.resize(44 + data_size + data_size % 2); // RIFF pads an odd number of data bytes with one more.
	if (write_pcm_as_wav(buffer, data_size, format, samplerate, channels, &output[0], output.size()))
		return true;
	output.clear();
	return false;
}

template < class T, auto Function, typename ReturnType, typename... Args >
ReturnType virtual_call(T *object, Args... args) {
	return (object->*Function)(std::forward < Args > (args)...);
}
template < class T > inline void RegisterSoundsystemAudioNode(asIScriptEngine *engine, const std::string &type) {
	engine->RegisterObjectType(type.c_str(), 0, asOBJ_REF);
	engine->RegisterObjectBehaviour(type.c_str(), asBEHAVE_ADDREF, "void f()", asFUNCTION((virtual_call < T, &T::duplicate, void >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectBehaviour(type.c_str(), asBEHAVE_RELEASE, "void f()", asFUNCTION((virtual_call < T, &T::release, void >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "uint get_input_bus_count() const property", asFUNCTION((virtual_call < T, &T::get_input_bus_count, unsigned int >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "uint get_output_bus_count() const property", asFUNCTION((virtual_call < T, &T::get_output_bus_count, unsigned int >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "uint get_input_channels(uint bus) const", asFUNCTION((virtual_call < T, &T::get_input_channels, unsigned int, unsigned int >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "uint get_output_channels(uint bus) const", asFUNCTION((virtual_call < T, &T::get_output_channels, unsigned int, unsigned int >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "bool attach_output_bus(uint output_bus, audio_node@+ destination, uint destination_input_bus)", asFUNCTION((virtual_call < T, &T::attach_output_bus, bool, unsigned int, audio_node *, unsigned int >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "bool detach_output_bus(uint bus)", asFUNCTION((virtual_call < T, &T::detach_output_bus, bool, unsigned int >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "bool detach_all_output_buses()", asFUNCTION((virtual_call < T, &T::detach_all_output_buses, bool >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "bool set_output_bus_volume(uint bus, float volume)", asFUNCTION((virtual_call < T, &T::set_output_bus_volume, bool, unsigned int, float >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "float get_output_bus_volume(uint bus)", asFUNCTION((virtual_call < T, &T::get_output_bus_volume, float, unsigned int >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "bool set_state(audio_node_state state)", asFUNCTION((virtual_call < T, &T::set_state, bool, ma_node_state >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "audio_node_state get_state()", asFUNCTION((virtual_call < T, &T::get_state, ma_node_state >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "bool set_state_time(audio_node_state state, uint64 time)", asFUNCTION((virtual_call < T, &T::set_state_time, bool, ma_node_state, unsigned long long >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "uint64 get_state_time(audio_node_state state)", asFUNCTION((virtual_call < T, &T::get_state_time, unsigned long long, ma_node_state >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "audio_node_state get_state_by_time(uint64 global_time)", asFUNCTION((virtual_call < T, &T::get_state_by_time, ma_node_state, unsigned long long >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "audio_node_state get_state_by_time_range(uint64 global_time_begin, uint64 global_time_end)", asFUNCTION((virtual_call < T, &T::get_state_by_time_range, ma_node_state, unsigned long long, unsigned long long >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "uint64 get_time() const", asFUNCTION((virtual_call < T, &T::get_time, unsigned long long >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "bool set_time(uint64 local_time)", asFUNCTION((virtual_call < T, &T::set_time, bool, unsigned long long >)), asCALL_CDECL_OBJFIRST);
	if constexpr (!std::is_same < T, audio_node >::value) {
		engine->RegisterObjectMethod(type.c_str(), "audio_node@ opImplCast()", asFUNCTION((op_cast < T, audio_node >)), asCALL_CDECL_OBJFIRST);
		if constexpr (!std::is_same < T, plugin_node >::value) engine->RegisterObjectMethod("audio_node", Poco::format("%s@ opCast()", type).c_str(), asFUNCTION((op_cast < audio_node, T >)), asCALL_CDECL_OBJFIRST); // A plugin's node types are cast by plugin_node_cast().
	}
}
template <class T> inline void RegisterSoundsystemDataSource(asIScriptEngine *engine, const std::string &type) {
	RegisterSoundsystemAudioNode<T>(engine, type);
	engine->RegisterObjectMethod(type.c_str(), "uint get_advised_read_frame_count() const property", asFUNCTION((virtual_call<T, &T::get_advised_read_frame_count, unsigned int>)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "float[]@ read(uint64 frame_count = 0)", asFUNCTION((virtual_call<T, &T::read_script, CScriptArray*, unsigned long long >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "uint64 skip_frames(uint64 frame_count)", asFUNCTION((virtual_call<T, &T::skip_frames, unsigned long long, unsigned long long>)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "float skip_milliseconds(float ms)", asFUNCTION((virtual_call<T, &T::skip_milliseconds, float, float>)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "bool seek_frames(uint64 frame_index)", asFUNCTION((virtual_call<T, &T::seek_frames, bool, unsigned long long >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "uint64 get_cursor_frames() const property", asFUNCTION((virtual_call<T, &T::get_cursor_frames, unsigned long long >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "bool seek_milliseconds(float ms)", asFUNCTION((virtual_call<T, &T::seek_milliseconds, bool, float>)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "float get_cursor_milliseconds() const property", asFUNCTION((virtual_call<T, &T::get_cursor_milliseconds, float>)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "uint64 get_length_frames() const property", asFUNCTION((virtual_call<T, &T::get_length_frames, unsigned long long>)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "float get_length_milliseconds() const property", asFUNCTION((virtual_call<T, &T::get_length_milliseconds, float>)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "bool set_looping(bool looping)", asFUNCTION((virtual_call<T, &T::set_looping, bool, bool>)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "bool get_looping() const property", asFUNCTION((virtual_call<T, &T::get_looping, bool>)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "bool set_range(uint64 start_frame, uint64 end_frame)", asFUNCTION((virtual_call<T, &T::set_range, bool, unsigned long long, unsigned long long>)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "void get_range(uint64&out start_frame, uint64&out end_frame) const", asFUNCTION((virtual_call<T, &T::get_range, void, unsigned long long*, unsigned long long*>)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "bool set_loop_point(uint64 start_frame, uint64 end_frame)", asFUNCTION((virtual_call<T, &T::set_loop_point, bool, unsigned long long, unsigned long long>)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "void get_loop_point(uint64&out start_frame, uint64&out end_frame) const", asFUNCTION((virtual_call<T, &T::get_loop_point, void, unsigned long long*, unsigned long long*>)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "bool set_current(audio_data_source@+ new_current)", asFUNCTION((virtual_call<T, &T::set_current, bool, audio_data_source*>)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "audio_data_source@ get_current() const property", asFUNCTION((virtual_call<T, &T::get_current, audio_data_source*>)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "bool set_next(audio_data_source@+ new_next)", asFUNCTION((virtual_call<T, &T::set_next, bool, audio_data_source*>)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "audio_data_source@ get_next() const property", asFUNCTION((virtual_call<T, &T::get_next, audio_data_source*>)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "uint get_channels() const property", asFUNCTION((virtual_call<T, &T::get_channels, unsigned int>)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "uint get_sample_rate() const property", asFUNCTION((virtual_call<T, &T::get_sample_rate, unsigned int>)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "bool get_active() const property", asFUNCTION((virtual_call<T, &T::get_active, bool>)), asCALL_CDECL_OBJFIRST);
	if constexpr (!std::is_same < T, audio_data_source >::value) {
		engine->RegisterObjectMethod(type.c_str(), "audio_data_source@ opImplCast()", asFUNCTION((op_cast<T, audio_data_source>)), asCALL_CDECL_OBJFIRST);
		engine->RegisterObjectMethod("audio_data_source", Poco::format("%s@ opCast()", type).c_str(), asFUNCTION((op_cast<audio_data_source, T>)), asCALL_CDECL_OBJFIRST);
	}
}
template<class T> inline void RegisterSoundsystemRingBuffer(asIScriptEngine* engine, const std::string& type) {
	RegisterSoundsystemDataSource<T>(engine, type);
	engine->RegisterObjectMethod(type.c_str(), "void reset()", asFUNCTION((virtual_call<T, &T::reset, void>)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "uint write(const float[]@+ frames)", asFUNCTION((virtual_call<T, &T::write_script_array, unsigned int, CScriptArray*>)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "uint write(const memory_buffer<float>& frames)", asFUNCTION((virtual_call<T, &T::write_script_memory_buffer, unsigned int, script_memory_buffer*>)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "uint get_available_read() const property", asFUNCTION((virtual_call<T, &T::get_available_read, unsigned int>)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "uint get_available_write() const property", asFUNCTION((virtual_call<T, &T::get_available_write, unsigned int>)), asCALL_CDECL_OBJFIRST);
	if constexpr (!std::is_same < T, audio_ring_buffer >::value) {
		engine->RegisterObjectMethod(type.c_str(), "audio_ring_buffer@ opImplCast()", asFUNCTION((op_cast<T, audio_ring_buffer>)), asCALL_CDECL_OBJFIRST);
		engine->RegisterObjectMethod("audio_ring_buffer", Poco::format("%s@ opCast()", type).c_str(), asFUNCTION((op_cast<audio_ring_buffer, T>)), asCALL_CDECL_OBJFIRST);
	}
}
void RegisterSoundsystemEngine(asIScriptEngine *engine) {
	RegisterSoundsystemAudioNode<audio_engine>(engine, "audio_engine");
	engine->RegisterFuncdef("void audio_engine_processing_callback(audio_engine@ engine, memory_buffer<float>& data, uint64 frames)");
	engine->RegisterObjectBehaviour("audio_engine", asBEHAVE_FACTORY, "audio_engine@ e(int flags, int sample_rate = 0, int channels = 0)", asFUNCTION(new_audio_engine), asCALL_CDECL);
	engine->RegisterObjectMethod("audio_engine", "int get_flags() const property", asFUNCTION((virtual_call < audio_engine, &audio_engine::get_flags, int >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("audio_engine", "int get_device() const", asFUNCTION((virtual_call < audio_engine, &audio_engine::get_device, int >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("audio_engine", "bool set_device(int device)", asFUNCTION((virtual_call < audio_engine, &audio_engine::set_device, bool, int >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("audio_engine", "audio_node@+ get_endpoint() const property", asFUNCTION((virtual_call < audio_engine, &audio_engine::get_endpoint, audio_node * >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("audio_engine", "float[]@ read(uint64 frame_count)", asFUNCTION((virtual_call < audio_engine, &audio_engine::read_script, CScriptArray *, unsigned long long >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("audio_engine", "void set_processing_callback(audio_engine_processing_callback@ cb) property", asFUNCTION((virtual_call < audio_engine, &audio_engine::set_processing_callback, void, asIScriptFunction*>)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("audio_engine", "audio_engine_processing_callback@+ get_processing_callback() const property", asFUNCTION((virtual_call < audio_engine, &audio_engine::get_processing_callback, asIScriptFunction* >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("audio_engine", "uint64 get_time_in_frames() const property", asFUNCTION((virtual_call < audio_engine, &audio_engine::get_time_in_frames, unsigned long long >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("audio_engine", "bool set_time_in_frames(uint64 time_frames)", asFUNCTION((virtual_call < audio_engine, &audio_engine::set_time_in_frames, bool, unsigned long long >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("audio_engine", "uint64 get_time_in_milliseconds() const property", asFUNCTION((virtual_call < audio_engine, &audio_engine::get_time_in_milliseconds, unsigned long long >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("audio_engine", "bool set_time_in_milliseconds(uint64 time_ms)", asFUNCTION((virtual_call < audio_engine, &audio_engine::set_time_in_milliseconds, bool, unsigned long long >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("audio_engine", "int get_channels() const property", asFUNCTION((virtual_call < audio_engine, &audio_engine::get_channels, int >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("audio_engine", "int get_sample_rate() const property", asFUNCTION((virtual_call < audio_engine, &audio_engine::get_sample_rate, int >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("audio_engine", "bool start()", asFUNCTION((virtual_call < audio_engine, &audio_engine::start, bool >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("audio_engine", "bool stop()", asFUNCTION((virtual_call < audio_engine, &audio_engine::stop, bool >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("audio_engine", "bool set_volume(float volume)", asFUNCTION((virtual_call < audio_engine, &audio_engine::set_volume, bool, float >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("audio_engine", "float get_volume() const property", asFUNCTION((virtual_call < audio_engine, &audio_engine::get_volume, float >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("audio_engine", "bool set_gain(float gain)", asFUNCTION((virtual_call < audio_engine, &audio_engine::set_gain, bool, float >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("audio_engine", "float get_gain() const property", asFUNCTION((virtual_call < audio_engine, &audio_engine::get_gain, float >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("audio_engine", "uint get_listener_count() const property", asFUNCTION((virtual_call < audio_engine, &audio_engine::get_listener_count, unsigned int >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("audio_engine", "int find_closest_listener(float x, float y, float z) const", asFUNCTION((virtual_call < audio_engine, &audio_engine::find_closest_listener, int, float, float, float >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("audio_engine", "int find_closest_listener(const vector&in position) const", asFUNCTION((virtual_call < audio_engine, &audio_engine::find_closest_listener_vector, int, const reactphysics3d::Vector3 & >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("audio_engine", "void set_listener_position(int index, float x, float y, float z)", asFUNCTION((virtual_call < audio_engine, &audio_engine::set_listener_position, void, int, float, float, float >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("audio_engine", "void set_listener_position(int index, const vector&in position)", asFUNCTION((virtual_call < audio_engine, &audio_engine::set_listener_position_vector, void, int, const reactphysics3d::Vector3 & >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("audio_engine", "vector get_listener_position(int index) const", asFUNCTION((virtual_call < audio_engine, &audio_engine::get_listener_position, reactphysics3d::Vector3, int >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("audio_engine", "void set_listener_direction(int index, float x, float y, float z)", asFUNCTION((virtual_call < audio_engine, &audio_engine::set_listener_direction, void, int, float, float, float >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("audio_engine", "void set_listener_direction(int index, const vector&in direction)", asFUNCTION((virtual_call < audio_engine, &audio_engine::set_listener_direction_vector, void, int, const reactphysics3d::Vector3 & >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("audio_engine", "vector get_listener_direction(int index) const", asFUNCTION((virtual_call < audio_engine, &audio_engine::get_listener_direction, reactphysics3d::Vector3, int >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("audio_engine", "void set_listener_velocity(int index, float x, float y, float z)", asFUNCTION((virtual_call < audio_engine, &audio_engine::set_listener_velocity, void, int, float, float, float >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("audio_engine", "void set_listener_velocity(int index, const vector&in velocity)", asFUNCTION((virtual_call < audio_engine, &audio_engine::set_listener_velocity_vector, void, int, const reactphysics3d::Vector3 & >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("audio_engine", "vector get_listener_velocity(int index) const", asFUNCTION((virtual_call < audio_engine, &audio_engine::get_listener_velocity, reactphysics3d::Vector3, int >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("audio_engine", "void set_listener_cone(int index, float inner_radians, float outer_radians, float outer_gain)", asFUNCTION((virtual_call < audio_engine, &audio_engine::set_listener_cone, void, int, float, float, float >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("audio_engine", "void get_listener_cone(int index, float&out inner_radians, float&out outer_radians, float&out outer_gain) const", asFUNCTION((virtual_call < audio_engine, &audio_engine::get_listener_cone, void, int, float *, float *, float * >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("audio_engine", "void set_listener_world_up(int index, float x, float y, float z)", asFUNCTION((virtual_call < audio_engine, &audio_engine::set_listener_world_up, void, int, float, float, float >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("audio_engine", "void set_listener_world_up(int index, const vector&in world_up)", asFUNCTION((virtual_call < audio_engine, &audio_engine::set_listener_world_up_vector, void, int, const reactphysics3d::Vector3 & >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("audio_engine", "vector get_listener_world_up(int index) const", asFUNCTION((virtual_call < audio_engine, &audio_engine::get_listener_world_up, reactphysics3d::Vector3, int >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("audio_engine", "void set_listener_enabled(int index, bool enabled)", asFUNCTION((virtual_call < audio_engine, &audio_engine::set_listener_enabled, void, int, bool >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("audio_engine", "bool get_listener_enabled(int index) const", asFUNCTION((virtual_call < audio_engine, &audio_engine::get_listener_enabled, bool, int >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterGlobalFunction("void set_sound_default_engine(audio_engine@ engine) property", asFUNCTION(set_sound_default_engine), asCALL_CDECL);
	engine->RegisterGlobalFunction("audio_engine@ get_sound_default_engine() property", asFUNCTION(get_sound_default_engine), asCALL_CDECL);
	engine->RegisterGlobalFunction("bool get_sound_system_available() property", asFUNCTION(get_sound_system_available), asCALL_CDECL);
}
void RegisterSoundsystemDataSources(asIScriptEngine* engine) {
	RegisterSoundsystemDataSource<audio_data_source>(engine, "audio_data_source");
	RegisterSoundsystemDataSource<audio_decoder>(engine, "audio_decoder");
	engine->RegisterObjectBehaviour("audio_decoder", asBEHAVE_FACTORY, "audio_decoder@ d(audio_engine@+ engine = sound_default_engine)", asFUNCTION(audio_decoder::create), asCALL_CDECL);
	engine->RegisterObjectMethod("audio_decoder", "bool open(const string&in filename, const pack_interface@+ pack_file = sound_default_pack, uint sample_rate = 0, uint channels = 0)", asFUNCTION((virtual_call < audio_decoder, &audio_decoder::open, bool, const string&, const pack_interface*, unsigned int, unsigned int >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("audio_decoder", "bool open(datastream@ stream, uint sample_rate = 0, uint channels = 0)", asFUNCTION((virtual_call < audio_decoder, &audio_decoder::open_stream, bool, datastream*, unsigned int, unsigned int >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("audio_decoder", "bool close()", asFUNCTION((virtual_call < audio_decoder, &audio_decoder::close, bool >)), asCALL_CDECL_OBJFIRST);
	RegisterSoundsystemRingBuffer<audio_ring_buffer>(engine, "audio_ring_buffer");
	engine->RegisterObjectBehaviour("audio_ring_buffer", asBEHAVE_FACTORY, "audio_ring_buffer@ r(uint channels, uint size, audio_engine@+ engine = sound_default_engine)", asFUNCTION(audio_ring_buffer::create), asCALL_CDECL);
	RegisterSoundsystemRingBuffer<microphone>(engine, "microphone");
	engine->RegisterObjectBehaviour("microphone", asBEHAVE_FACTORY, "microphone@ m(int device = -1, audio_engine@+ engine = sound_default_engine)", asFUNCTION(microphone::create), asCALL_CDECL);
	engine->RegisterObjectMethod("microphone", "bool set_device(int device)", asFUNCTION((virtual_call < microphone, &microphone::set_device, bool, int>)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("microphone", "int get_device() const property", asFUNCTION((virtual_call < microphone, &microphone::get_device, int>)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("microphone", "void set_volume(float volume) property", asFUNCTION((virtual_call < microphone, &microphone::set_volume, void, float>)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("microphone", "float get_volume() const property", asFUNCTION((virtual_call < microphone, &microphone::get_volume, float>)), asCALL_CDECL_OBJFIRST);
}
template <class T> void RegisterSoundsystemEncoder(asIScriptEngine* engine, const std::string& type) {
	RegisterSoundsystemAudioNode<T>(engine, type);
	engine->RegisterObjectMethod(type.c_str(), "uint get_default_open_flags() const property", asFUNCTION((virtual_call<T, &T::get_default_open_flags, unsigned int>)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "bool open(uint sample_rate, uint channels, uint flags = AUDIO_ENCODER_DEFAULTS)", asFUNCTION((virtual_call<T, &T::open_pull, bool, unsigned int, unsigned int, unsigned int>)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "bool open(const string&in filename, uint sample_rate, uint channels, uint flags = AUDIO_ENCODER_DEFAULTS)", asFUNCTION((virtual_call<T, &T::open_file, bool, const string&, unsigned int, unsigned int, unsigned int>)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "bool open(datastream@ stream, uint sample_rate, uint channels, uint flags = AUDIO_ENCODER_DEFAULTS)", asFUNCTION((virtual_call<T, &T::open_stream, bool, datastream*, unsigned int, unsigned int, unsigned int>)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "bool close()", asFUNCTION((virtual_call<T, &T::close, bool>)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "bool get_active() const property", asFUNCTION((virtual_call<T, &T::get_active, bool>)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "uint64 get_frames_written() const property", asFUNCTION((virtual_call<T, &T::get_frames_written, unsigned long long>)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "uint write(const float[]@+ frames)", asFUNCTION((virtual_call<T, &T::write_script_array, unsigned int, CScriptArray*>)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "uint write(const memory_buffer<float>& frames)", asFUNCTION((virtual_call<T, &T::write_script_memory_buffer, unsigned int, script_memory_buffer*>)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "string read()", asFUNCTION((virtual_call<T, &T::read, string>)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "string get_format() const property", asFUNCTION((virtual_call<T, &T::get_format, string>)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "uint get_sample_rate() const property", asFUNCTION((virtual_call<T, &T::get_sample_rate, unsigned int>)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "uint get_channels() const property", asFUNCTION((virtual_call<T, &T::get_channels, unsigned int>)), asCALL_CDECL_OBJFIRST);
	if constexpr (!std::is_same < T, audio_encoder >::value) {
		engine->RegisterObjectMethod(type.c_str(), "audio_encoder@ opImplCast()", asFUNCTION((op_cast<T, audio_encoder>)), asCALL_CDECL_OBJFIRST);
		engine->RegisterObjectMethod("audio_encoder", Poco::format("%s@ opCast()", type).c_str(), asFUNCTION((op_cast<audio_encoder, T>)), asCALL_CDECL_OBJFIRST);
	}
}
void RegisterSoundsystemEncoders(asIScriptEngine* engine) {
	engine->RegisterEnum("audio_encoder_flags");
	engine->RegisterEnumValue("audio_encoder_flags", "AUDIO_ENCODER_OVERWRITE", audio_encoder::ENCODER_OVERWRITE);
	engine->RegisterEnumValue("audio_encoder_flags", "AUDIO_ENCODER_DEFAULTS", audio_encoder::ENCODER_DEFAULTS);
	RegisterSoundsystemEncoder<audio_encoder>(engine, "audio_encoder");
	engine->RegisterEnum("audio_wav_encoder_flags");
	engine->RegisterEnumValue("audio_wav_encoder_flags", "AUDIO_ENCODER_WAV_U8", audio_wav_encoder::WAV_U8);
	engine->RegisterEnumValue("audio_wav_encoder_flags", "AUDIO_ENCODER_WAV_S16", audio_wav_encoder::WAV_S16);
	engine->RegisterEnumValue("audio_wav_encoder_flags", "AUDIO_ENCODER_WAV_S24", audio_wav_encoder::WAV_S24);
	engine->RegisterEnumValue("audio_wav_encoder_flags", "AUDIO_ENCODER_WAV_S32", audio_wav_encoder::WAV_S32);
	engine->RegisterEnumValue("audio_wav_encoder_flags", "AUDIO_ENCODER_WAV_F32", audio_wav_encoder::WAV_F32);
	RegisterSoundsystemEncoder<audio_wav_encoder>(engine, "audio_wav_encoder");
	engine->RegisterObjectBehaviour("audio_wav_encoder", asBEHAVE_FACTORY, "audio_wav_encoder@ e(audio_engine@+ engine = sound_default_engine)", asFUNCTION(audio_wav_encoder::create), asCALL_CDECL);
	engine->RegisterObjectMethod("audio_wav_encoder", "audio_format get_wav_format() const property", asFUNCTION((virtual_call<audio_wav_encoder, &audio_wav_encoder::get_wav_format, ma_format>)), asCALL_CDECL_OBJFIRST);
	engine->RegisterEnum("opus_signal_type");
	engine->RegisterEnumValue("opus_signal_type", "OPUS_AUTO", OPUS_AUTO);
	engine->RegisterEnumValue("opus_signal_type", "OPUS_SIGNAL_VOICE", OPUS_SIGNAL_VOICE);
	engine->RegisterEnumValue("opus_signal_type", "OPUS_SIGNAL_MUSIC", OPUS_SIGNAL_MUSIC);
	engine->RegisterEnum("opus_application_type");
	engine->RegisterEnumValue("opus_application_type", "OPUS_APPLICATION_VOIP", OPUS_APPLICATION_VOIP);
	engine->RegisterEnumValue("opus_application_type", "OPUS_APPLICATION_AUDIO", OPUS_APPLICATION_AUDIO);
	engine->RegisterEnumValue("opus_application_type", "OPUS_APPLICATION_RESTRICTED_LOWDELAY", OPUS_APPLICATION_RESTRICTED_LOWDELAY);
	RegisterSoundsystemEncoder<audio_opus_encoder>(engine, "audio_opus_encoder");
	engine->RegisterObjectBehaviour("audio_opus_encoder", asBEHAVE_FACTORY, "audio_opus_encoder@ e(audio_engine@+ engine = sound_default_engine)", asFUNCTION(audio_opus_encoder::create), asCALL_CDECL);
	engine->RegisterObjectMethod("audio_opus_encoder", "int get_bitrate() const property", asFUNCTION((virtual_call<audio_opus_encoder, &audio_opus_encoder::get_bitrate, int>)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("audio_opus_encoder", "void set_bitrate(int bitrate) property", asFUNCTION((virtual_call<audio_opus_encoder, &audio_opus_encoder::set_bitrate, bool, int>)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("audio_opus_encoder", "int get_complexity() const property", asFUNCTION((virtual_call<audio_opus_encoder, &audio_opus_encoder::get_complexity, int>)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("audio_opus_encoder", "void set_complexity(int complexity) property", asFUNCTION((virtual_call<audio_opus_encoder, &audio_opus_encoder::set_complexity, bool, int>)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("audio_opus_encoder", "int get_signal_type() const property", asFUNCTION((virtual_call<audio_opus_encoder, &audio_opus_encoder::get_signal_type, int>)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("audio_opus_encoder", "void set_signal_type(int signal_type) property", asFUNCTION((virtual_call<audio_opus_encoder, &audio_opus_encoder::set_signal_type, bool, int>)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("audio_opus_encoder", "int get_application() const property", asFUNCTION((virtual_call<audio_opus_encoder, &audio_opus_encoder::get_application, int>)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("audio_opus_encoder", "void set_application(int application) property", asFUNCTION((virtual_call<audio_opus_encoder, &audio_opus_encoder::set_application, bool, int>)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("audio_opus_encoder", "int get_packet_loss_percent() const property", asFUNCTION((virtual_call<audio_opus_encoder, &audio_opus_encoder::get_packet_loss_percent, int>)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("audio_opus_encoder", "void set_packet_loss_percent(int percent) property", asFUNCTION((virtual_call<audio_opus_encoder, &audio_opus_encoder::set_packet_loss_percent, bool, int>)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("audio_opus_encoder", "bool get_vbr() const property", asFUNCTION((virtual_call<audio_opus_encoder, &audio_opus_encoder::get_vbr, bool>)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("audio_opus_encoder", "void set_vbr(bool enabled) property", asFUNCTION((virtual_call<audio_opus_encoder, &audio_opus_encoder::set_vbr, bool, bool>)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("audio_opus_encoder", "bool get_cvbr() const property", asFUNCTION((virtual_call<audio_opus_encoder, &audio_opus_encoder::get_cvbr, bool>)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("audio_opus_encoder", "void set_cvbr(bool enabled) property", asFUNCTION((virtual_call<audio_opus_encoder, &audio_opus_encoder::set_cvbr, bool, bool>)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("audio_opus_encoder", "bool get_dtx() const property", asFUNCTION((virtual_call<audio_opus_encoder, &audio_opus_encoder::get_dtx, bool>)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("audio_opus_encoder", "void set_dtx(bool enabled) property", asFUNCTION((virtual_call<audio_opus_encoder, &audio_opus_encoder::set_dtx, bool, bool>)), asCALL_CDECL_OBJFIRST);
}
template<class T> void RegisterSoundsystemMixer(asIScriptEngine *engine, const string &type) {
	RegisterSoundsystemAudioNode < T > (engine, type);
	engine->RegisterObjectMethod(type.c_str(), "audio_engine@+ get_engine() const property", asFUNCTION((virtual_call < T, &T::get_engine, audio_engine * >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "bool set_mixer(mixer@+ parent_mixer)", asFUNCTION((virtual_call < T, &T::set_mixer, bool, mixer * >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "mixer@+ get_mixer() const", asFUNCTION((virtual_call < T, &T::get_mixer, mixer * >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "void set_3d_panner(int panner_id)", asFUNCTION((virtual_call < T, &T::set_3d_panner, void, int >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "int get_3d_panner() const property", asFUNCTION((virtual_call < T, &T::get_3d_panner, int >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "void set_3d_attenuator(int attenuator_id)", asFUNCTION((virtual_call < T, &T::set_3d_attenuator, void, int >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "int get_3d_attenuator() const property", asFUNCTION((virtual_call < T, &T::get_3d_attenuator, int >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "int get_preferred_3d_panner() const property", asFUNCTION((virtual_call < T, &T::get_preferred_3d_panner, int >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "int get_preferred_3d_attenuator() const property", asFUNCTION((virtual_call < T, &T::get_preferred_3d_attenuator, int >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "void set_hrtf(bool enabled) property", asFUNCTION((virtual_call < T, &T::set_hrtf, void, bool >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "bool get_hrtf() const property", asFUNCTION((virtual_call < T, &T::get_hrtf, bool >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "bool set_shape(ref@ shape)", asFUNCTION((virtual_call < T, &T::set_shape, bool, CScriptHandle>)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "ref@ get_shape() const property", asFUNCTION((virtual_call < T, &T::get_shape, CScriptHandle>)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "void set_reverb3d(reverb3d@+ reverb) property", asFUNCTION((virtual_call < T, &T::set_reverb3d, void, reverb3d*>)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "void set_reverb3d_at(reverb3d@+ reverb, reverb3d_placement placement)", asFUNCTION((virtual_call < T, &T::set_reverb3d_at, void, reverb3d*, audio_spatializer_reverb3d_placement>)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "reverb3d@+ get_reverb3d() const property", asFUNCTION((virtual_call < T, &T::get_reverb3d, reverb3d*>)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "audio_splitter_node@+ get_reverb3d_attachment() const property", asFUNCTION((virtual_call < T, &T::get_reverb3d_attachment, splitter_node*>)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "reverb3d_placement get_reverb3d_placement() const property", asFUNCTION((virtual_call < T, &T::get_reverb3d_placement, audio_spatializer_reverb3d_placement>)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "audio_node_chain@+ get_effects_chain() property", asFUNCTION((virtual_call < T, &T::get_effects_chain, audio_node_chain*>)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "audio_node_chain@+ get_internal_node_chain() property", asFUNCTION((virtual_call < T, &T::get_internal_node_chain, audio_node_chain*>)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "bool play(bool reset_loop_state = true)", asFUNCTION((virtual_call < T, &T::play, bool, bool >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "bool play_looped()", asFUNCTION((virtual_call < T, &T::play_looped, bool >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "bool stop()", asFUNCTION((virtual_call < T, &T::stop, bool >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "void set_volume(float volume) property", asFUNCTION((virtual_call < T, &T::set_volume, void, float >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "float get_volume() const property", asFUNCTION((virtual_call < T, &T::get_volume, float >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "void set_pan(float pan) property", asFUNCTION((virtual_call < T, &T::set_pan, void, float >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "float get_pan() const property", asFUNCTION((virtual_call < T, &T::get_pan, float >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "void set_pan_mode(audio_pan_mode mode) property", asFUNCTION((virtual_call < T, &T::set_pan_mode, void, ma_pan_mode >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "audio_pan_mode get_pan_mode() const property", asFUNCTION((virtual_call < T, &T::get_pan_mode, ma_pan_mode >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "void set_pitch(float pitch) property", asFUNCTION((virtual_call < T, &T::set_pitch, void, float >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "float get_pitch() const property", asFUNCTION((virtual_call < T, &T::get_pitch, float >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "void set_spatialization_enabled(bool enabled) property", asFUNCTION((virtual_call < T, &T::set_spatialization_enabled, void, bool >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "bool get_spatialization_enabled() const property", asFUNCTION((virtual_call < T, &T::get_spatialization_enabled, bool >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "void set_pinned_listener(uint index) property", asFUNCTION((virtual_call < T, &T::set_pinned_listener, void, unsigned int >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "uint get_pinned_listener() const property", asFUNCTION((virtual_call < T, &T::get_pinned_listener, unsigned int >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "uint get_listener() const property", asFUNCTION((virtual_call < T, &T::get_listener, unsigned int >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "vector get_direction_to_listener() const", asFUNCTION((virtual_call < T, &T::get_direction_to_listener, reactphysics3d::Vector3 >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "float get_distance_to_listener() const", asFUNCTION((virtual_call < T, &T::get_distance_to_listener, float >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "void set_position_3d(float x, float y, float z)", asFUNCTION((virtual_call < T, &T::set_position_3d, void, float, float, float >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "void set_position_3d(const vector&in position)", asFUNCTION((virtual_call < T, &T::set_position_3d_vector, void, const reactphysics3d::Vector3&>)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "vector get_position_3d() const", asFUNCTION((virtual_call < T, &T::get_position_3d, reactphysics3d::Vector3 >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "void set_direction(float x, float y, float z)", asFUNCTION((virtual_call < T, &T::set_direction, void, float, float, float >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "void set_direction(const vector&in direction)", asFUNCTION((virtual_call < T, &T::set_direction_vector, void, const reactphysics3d::Vector3&>)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "vector get_direction() const", asFUNCTION((virtual_call < T, &T::get_direction, reactphysics3d::Vector3 >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "void set_velocity(float x, float y, float z)", asFUNCTION((virtual_call < T, &T::set_velocity, void, float, float, float >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "void set_velocity(const vector&in velocity)", asFUNCTION((virtual_call < T, &T::set_velocity_vector, void, const reactphysics3d::Vector3&>)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "vector get_velocity() const", asFUNCTION((virtual_call < T, &T::get_velocity, reactphysics3d::Vector3 >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "void set_positioning(audio_positioning_mode mode) property", asFUNCTION((virtual_call < T, &T::set_positioning, void, ma_positioning >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "audio_positioning_mode get_positioning() const property", asFUNCTION((virtual_call < T, &T::get_positioning, ma_positioning >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "void set_rolloff(float rolloff) property", asFUNCTION((virtual_call < T, &T::set_rolloff, void, float >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "float get_rolloff() const property", asFUNCTION((virtual_call < T, &T::get_rolloff, float >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "void set_min_gain(float gain) property", asFUNCTION((virtual_call < T, &T::set_min_gain, void, float >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "float get_min_gain() const property", asFUNCTION((virtual_call < T, &T::get_min_gain, float >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "void set_max_gain(float gain) property", asFUNCTION((virtual_call < T, &T::set_max_gain, void, float >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "float get_max_gain() const property", asFUNCTION((virtual_call < T, &T::get_max_gain, float >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "void set_min_distance(float distance) property", asFUNCTION((virtual_call < T, &T::set_min_distance, void, float >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "float get_min_distance() const property", asFUNCTION((virtual_call < T, &T::get_min_distance, float >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "void set_max_distance(float distance) property", asFUNCTION((virtual_call < T, &T::set_max_distance, void, float >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "float get_max_distance() const property", asFUNCTION((virtual_call < T, &T::get_max_distance, float >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "void set_cone(float inner_radians, float outer_radians, float outer_gain)", asFUNCTION((virtual_call < T, &T::set_cone, void, float, float, float >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "void get_cone(float &out inner_radians, float &out outer_radians, float &out outer_gain)", asFUNCTION((virtual_call < T, &T::get_cone, void, float *, float *, float * >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "void set_doppler_factor(float factor) property", asFUNCTION((virtual_call < T, &T::set_doppler_factor, void, float >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "float get_doppler_factor() const property", asFUNCTION((virtual_call < T, &T::get_doppler_factor, float >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "void set_directional_attenuation_factor(float factor) property", asFUNCTION((virtual_call < T, &T::set_directional_attenuation_factor, void, float >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "float get_directional_attenuation_factor() const property", asFUNCTION((virtual_call < T, &T::get_directional_attenuation_factor, float >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "void set_fade(float start_volume, float end_volume, uint64 length)", asFUNCTION((virtual_call < T, &T::set_fade, void, float, float, ma_uint64 >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "void set_fade_in_frames(float start_volume, float end_volume, uint64 length_frames)", asFUNCTION((virtual_call < T, &T::set_fade_in_frames, void, float, float, ma_uint64 >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "void set_fade_in_milliseconds(float start_volume, float end_volume, uint64 length_ms)", asFUNCTION((virtual_call < T, &T::set_fade_in_milliseconds, void, float, float, ma_uint64 >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "float get_current_fade_volume() const property", asFUNCTION((virtual_call < T, &T::get_current_fade_volume, float >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "void set_start_time(uint64 absolute_time) property", asFUNCTION((virtual_call < T, &T::set_start_time, void, ma_uint64 >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "void set_stop_time(uint64 absolute_time)", asFUNCTION((virtual_call < T, &T::set_stop_time, void, ma_uint64 >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod(type.c_str(), "bool get_playing() const property", asFUNCTION((virtual_call < T, &T::get_playing, bool >)), asCALL_CDECL_OBJFIRST);
}
void RegisterSoundsystemNodes(asIScriptEngine *engine) {
	engine->RegisterObjectBehaviour("audio_node_chain", asBEHAVE_FACTORY, "audio_node_chain@ c(audio_node@+ source = null, audio_node@+ endpoint = null, audio_engine@+ engine = sound_default_engine)", asFUNCTION(audio_node_chain::create), asCALL_CDECL);
	engine->RegisterObjectMethod("audio_node_chain", "bool add_node(audio_node@+ node, audio_node@+ after = null, uint input_bus_index = 0)", asFUNCTION((virtual_call < audio_node_chain, &audio_node_chain::add_node, bool, audio_node*, audio_node*, unsigned int>)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("audio_node_chain", "bool add_node(audio_node@+ node, int after, uint input_bus_index = 0)", asFUNCTION((virtual_call < audio_node_chain, &audio_node_chain::add_node_at, bool, audio_node*, int, unsigned int>)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("audio_node_chain", "bool remove_node(audio_node@+ node)", asFUNCTION((virtual_call < audio_node_chain, &audio_node_chain::remove_node, bool, audio_node*>)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("audio_node_chain", "bool remove_node(uint index)", asFUNCTION((virtual_call < audio_node_chain, &audio_node_chain::remove_node_at, bool, unsigned int>)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("audio_node_chain", "bool clear(bool detach_nodes = true)", asFUNCTION((virtual_call < audio_node_chain, &audio_node_chain::clear, bool, bool>)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("audio_node_chain", "void set_endpoint(audio_node@+ endpoint, uint input_bus_index = 0)", asFUNCTION((virtual_call < audio_node_chain, &audio_node_chain::set_endpoint, void, audio_node*, unsigned int>)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("audio_node_chain", "audio_node@+ get_endpoint() const property", asFUNCTION((virtual_call < audio_node_chain, &audio_node_chain::get_endpoint, audio_node*>)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("audio_node_chain", "audio_node@+ get_first() const property", asFUNCTION((virtual_call < audio_node_chain, &audio_node_chain::first, audio_node*>)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("audio_node_chain", "audio_node@+ get_last() const property", asFUNCTION((virtual_call < audio_node_chain, &audio_node_chain::last, audio_node*>)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("audio_node_chain", "audio_node@+ opIndex(uint index) const", asFUNCTION((virtual_call < audio_node_chain, &audio_node_chain::operator[], audio_node*, unsigned int>)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("audio_node_chain", "int find(audio_node@+ node) const", asFUNCTION((virtual_call < audio_node_chain, &audio_node_chain::index_of, int, audio_node*>)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("audio_node_chain", "uint get_node_count() const property", asFUNCTION((virtual_call < audio_node_chain, &audio_node_chain::get_node_count, unsigned int >)), asCALL_CDECL_OBJFIRST);
	RegisterSoundsystemAudioNode < phonon_binaural_node > (engine, "phonon_binaural_node");
	engine->RegisterObjectBehaviour("phonon_binaural_node", asBEHAVE_FACTORY, "phonon_binaural_node@ n(audio_engine@+ engine, int channels, int sample_rate, int frame_size = 0)", asFUNCTION(phonon_binaural_node::create), asCALL_CDECL);
	engine->RegisterObjectMethod("phonon_binaural_node", "void set_direction(float x, float y, float z, float distance)", asFUNCTION((virtual_call < phonon_binaural_node, &phonon_binaural_node::set_direction, void, float, float, float, float >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("phonon_binaural_node", "void set_direction(const vector&in direction, float distance)", asFUNCTION((virtual_call < phonon_binaural_node, &phonon_binaural_node::set_direction_vector, void, const reactphysics3d::Vector3 &, float >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("phonon_binaural_node", "void set_spatial_blend_max_distance(float max_distance)", asFUNCTION((virtual_call < phonon_binaural_node, &phonon_binaural_node::set_spatial_blend_max_distance, void, float >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterGlobalFunction("bool set_sound_global_hrtf(bool enabled)", asFUNCTION(set_global_hrtf), asCALL_CDECL);
	engine->RegisterGlobalFunction("bool get_sound_global_hrtf() property", asFUNCTION(get_global_hrtf), asCALL_CDECL);
	engine->RegisterObjectBehaviour("audio_splitter_node", asBEHAVE_FACTORY, "audio_splitter_node@ n(audio_engine@+ engine, int channels)", asFUNCTION(splitter_node::create), asCALL_CDECL);
	RegisterSoundsystemAudioNode <low_pass_filter_node> (engine, "audio_low_pass_filter");
	engine->RegisterObjectBehaviour("audio_low_pass_filter", asBEHAVE_FACTORY, "audio_low_pass_filter@ f(double cutoff_frequency, uint order, audio_engine@+ engine = sound_default_engine)", asFUNCTION(low_pass_filter_node::create), asCALL_CDECL);
	engine->RegisterObjectMethod("audio_low_pass_filter", "void set_cutoff_frequency(double frequency) property", asFUNCTION((virtual_call < low_pass_filter_node, &low_pass_filter_node::set_cutoff_frequency, void, double >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("audio_low_pass_filter", "double get_cutoff_frequency() const property", asFUNCTION((virtual_call < low_pass_filter_node, &low_pass_filter_node::get_cutoff_frequency, double >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("audio_low_pass_filter", "void set_order(uint order) property", asFUNCTION((virtual_call < low_pass_filter_node, &low_pass_filter_node::set_order, void, unsigned int>)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("audio_low_pass_filter", "uint get_order() const property", asFUNCTION((virtual_call < low_pass_filter_node, &low_pass_filter_node::get_order, unsigned int >)), asCALL_CDECL_OBJFIRST);
	RegisterSoundsystemAudioNode <high_pass_filter_node> (engine, "audio_high_pass_filter");
	engine->RegisterObjectBehaviour("audio_high_pass_filter", asBEHAVE_FACTORY, "audio_high_pass_filter@ f(double cutoff_frequency, uint order, audio_engine@+ engine = sound_default_engine)", asFUNCTION(high_pass_filter_node::create), asCALL_CDECL);
	engine->RegisterObjectMethod("audio_high_pass_filter", "void set_cutoff_frequency(double frequency) property", asFUNCTION((virtual_call < high_pass_filter_node, &high_pass_filter_node::set_cutoff_frequency, void, double >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("audio_high_pass_filter", "double get_cutoff_frequency() const property", asFUNCTION((virtual_call < high_pass_filter_node, &high_pass_filter_node::get_cutoff_frequency, double >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("audio_high_pass_filter", "void set_order(uint order) property", asFUNCTION((virtual_call < high_pass_filter_node, &high_pass_filter_node::set_order, void, unsigned int>)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("audio_high_pass_filter", "uint get_order() const property", asFUNCTION((virtual_call < high_pass_filter_node, &high_pass_filter_node::get_order, unsigned int >)), asCALL_CDECL_OBJFIRST);
	RegisterSoundsystemAudioNode <band_pass_filter_node> (engine, "audio_band_pass_filter");
	engine->RegisterObjectBehaviour("audio_band_pass_filter", asBEHAVE_FACTORY, "audio_band_pass_filter@ f(double cutoff_frequency, uint order, audio_engine@+ engine = sound_default_engine)", asFUNCTION(band_pass_filter_node::create), asCALL_CDECL);
	engine->RegisterObjectMethod("audio_band_pass_filter", "void set_cutoff_frequency(double frequency) property", asFUNCTION((virtual_call < band_pass_filter_node, &band_pass_filter_node::set_cutoff_frequency, void, double >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("audio_band_pass_filter", "double get_cutoff_frequency() const property", asFUNCTION((virtual_call < band_pass_filter_node, &band_pass_filter_node::get_cutoff_frequency, double >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("audio_band_pass_filter", "void set_order(uint order) property", asFUNCTION((virtual_call < band_pass_filter_node, &band_pass_filter_node::set_order, void, unsigned int>)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("audio_band_pass_filter", "uint get_order() const property", asFUNCTION((virtual_call < band_pass_filter_node, &band_pass_filter_node::get_order, unsigned int >)), asCALL_CDECL_OBJFIRST);
	RegisterSoundsystemAudioNode <notch_filter_node> (engine, "audio_notch_filter");
	engine->RegisterObjectBehaviour("audio_notch_filter", asBEHAVE_FACTORY, "audio_notch_filter@ f(double q, double frequency, audio_engine@+ engine = sound_default_engine)", asFUNCTION(notch_filter_node::create), asCALL_CDECL);
	engine->RegisterObjectMethod("audio_notch_filter", "void set_q(double q) property", asFUNCTION((virtual_call < notch_filter_node, &notch_filter_node::set_q, void, double >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("audio_notch_filter", "double get_q() const property", asFUNCTION((virtual_call < notch_filter_node, &notch_filter_node::get_q, double >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("audio_notch_filter", "void set_frequency(double frequency) property", asFUNCTION((virtual_call < notch_filter_node, &notch_filter_node::set_frequency, void, double >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("audio_notch_filter", "double get_frequency() const property", asFUNCTION((virtual_call < notch_filter_node, &notch_filter_node::get_frequency, double >)), asCALL_CDECL_OBJFIRST);
	RegisterSoundsystemAudioNode <peak_filter_node> (engine, "audio_peak_filter");
	engine->RegisterObjectBehaviour("audio_peak_filter", asBEHAVE_FACTORY, "audio_peak_filter@ f(double gain_db, double q, double frequency, audio_engine@+ engine = sound_default_engine)", asFUNCTION(peak_filter_node::create), asCALL_CDECL);
	engine->RegisterObjectMethod("audio_peak_filter", "void set_gain(double gain) property", asFUNCTION((virtual_call < peak_filter_node, &peak_filter_node::set_gain, void, double >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("audio_peak_filter", "double get_gain() const property", asFUNCTION((virtual_call < peak_filter_node, &peak_filter_node::get_gain, double >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("audio_peak_filter", "void set_q(double q) property", asFUNCTION((virtual_call < peak_filter_node, &peak_filter_node::set_q, void, double >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("audio_peak_filter", "double get_q() const property", asFUNCTION((virtual_call < peak_filter_node, &peak_filter_node::get_q, double >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("audio_peak_filter", "void set_frequency(double frequency) property", asFUNCTION((virtual_call < peak_filter_node, &peak_filter_node::set_frequency, void, double >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("audio_peak_filter", "double get_frequency() const property", asFUNCTION((virtual_call < peak_filter_node, &peak_filter_node::get_frequency, double >)), asCALL_CDECL_OBJFIRST);
	RegisterSoundsystemAudioNode <low_shelf_filter_node> (engine, "audio_low_shelf_filter");
	engine->RegisterObjectBehaviour("audio_low_shelf_filter", asBEHAVE_FACTORY, "audio_low_shelf_filter@ f(double gain_db, double q, double frequency, audio_engine@+ engine = sound_default_engine)", asFUNCTION(low_shelf_filter_node::create), asCALL_CDECL);
	engine->RegisterObjectMethod("audio_low_shelf_filter", "void set_gain(double gain) property", asFUNCTION((virtual_call < low_shelf_filter_node, &low_shelf_filter_node::set_gain, void, double >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("audio_low_shelf_filter", "double get_gain() const property", asFUNCTION((virtual_call < low_shelf_filter_node, &low_shelf_filter_node::get_gain, double >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("audio_low_shelf_filter", "void set_q(double q) property", asFUNCTION((virtual_call < low_shelf_filter_node, &low_shelf_filter_node::set_q, void, double >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("audio_low_shelf_filter", "double get_q() const property", asFUNCTION((virtual_call < low_shelf_filter_node, &low_shelf_filter_node::get_q, double >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("audio_low_shelf_filter", "void set_frequency(double frequency) property", asFUNCTION((virtual_call < low_shelf_filter_node, &low_shelf_filter_node::set_frequency, void, double >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("audio_low_shelf_filter", "double get_frequency() const property", asFUNCTION((virtual_call < low_shelf_filter_node, &low_shelf_filter_node::get_frequency, double >)), asCALL_CDECL_OBJFIRST);
	RegisterSoundsystemAudioNode <high_shelf_filter_node> (engine, "audio_high_shelf_filter");
	engine->RegisterObjectBehaviour("audio_high_shelf_filter", asBEHAVE_FACTORY, "audio_high_shelf_filter@ f(double gain_db, double q, double frequency, audio_engine@+ engine = sound_default_engine)", asFUNCTION(high_shelf_filter_node::create), asCALL_CDECL);
	engine->RegisterObjectMethod("audio_high_shelf_filter", "void set_gain(double gain) property", asFUNCTION((virtual_call < high_shelf_filter_node, &high_shelf_filter_node::set_gain, void, double >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("audio_high_shelf_filter", "double get_gain() const property", asFUNCTION((virtual_call < high_shelf_filter_node, &high_shelf_filter_node::get_gain, double >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("audio_high_shelf_filter", "void set_q(double q) property", asFUNCTION((virtual_call < high_shelf_filter_node, &high_shelf_filter_node::set_q, void, double >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("audio_high_shelf_filter", "double get_q() const property", asFUNCTION((virtual_call < high_shelf_filter_node, &high_shelf_filter_node::get_q, double >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("audio_high_shelf_filter", "void set_frequency(double frequency) property", asFUNCTION((virtual_call < high_shelf_filter_node, &high_shelf_filter_node::set_frequency, void, double >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("audio_high_shelf_filter", "double get_frequency() const property", asFUNCTION((virtual_call < high_shelf_filter_node, &high_shelf_filter_node::get_frequency, double >)), asCALL_CDECL_OBJFIRST);
	RegisterSoundsystemAudioNode <delay_node> (engine, "audio_delay_node");
	engine->RegisterObjectBehaviour("audio_delay_node", asBEHAVE_FACTORY, "audio_delay_node@ d(uint delay_in_frames, float decay, audio_engine@+ engine = sound_default_engine)", asFUNCTION(delay_node::create), asCALL_CDECL);
	engine->RegisterObjectMethod("audio_delay_node", "void set_wet(float wet) property", asFUNCTION((virtual_call < delay_node, &delay_node::set_wet, void, float >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("audio_delay_node", "float get_wet() const property", asFUNCTION((virtual_call < delay_node, &delay_node::get_wet, float >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("audio_delay_node", "void set_dry(float dry) property", asFUNCTION((virtual_call < delay_node, &delay_node::set_dry, void, float >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("audio_delay_node", "float get_dry() const property", asFUNCTION((virtual_call < delay_node, &delay_node::get_dry, float >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("audio_delay_node", "void set_decay(float decay) property", asFUNCTION((virtual_call < delay_node, &delay_node::set_decay, void, float >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("audio_delay_node", "float get_decay() const property", asFUNCTION((virtual_call < delay_node, &delay_node::get_decay, float >)), asCALL_CDECL_OBJFIRST);
	RegisterSoundsystemAudioNode <freeverb_node> (engine, "audio_freeverb_node");
	engine->RegisterObjectBehaviour("audio_freeverb_node", asBEHAVE_FACTORY, "audio_freeverb_node@ n(audio_engine@+ engine = sound_default_engine)", asFUNCTION(freeverb_node::create), asCALL_CDECL);
	engine->RegisterObjectMethod("audio_freeverb_node", "void set_room_size(float size) property", asFUNCTION((virtual_call < freeverb_node, &freeverb_node::set_room_size, void, float >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("audio_freeverb_node", "float get_room_size() const property", asFUNCTION((virtual_call < freeverb_node, &freeverb_node::get_room_size, float >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("audio_freeverb_node", "void set_damping(float damping) property", asFUNCTION((virtual_call < freeverb_node, &freeverb_node::set_damping, void, float >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("audio_freeverb_node", "float get_damping() const property", asFUNCTION((virtual_call < freeverb_node, &freeverb_node::get_damping, float >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("audio_freeverb_node", "void set_width(float width) property", asFUNCTION((virtual_call < freeverb_node, &freeverb_node::set_width, void, float >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("audio_freeverb_node", "float get_width() const property", asFUNCTION((virtual_call < freeverb_node, &freeverb_node::get_width, float >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("audio_freeverb_node", "void set_wet(float wet) property", asFUNCTION((virtual_call < freeverb_node, &freeverb_node::set_wet, void, float >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("audio_freeverb_node", "float get_wet() const property", asFUNCTION((virtual_call < freeverb_node, &freeverb_node::get_wet, float >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("audio_freeverb_node", "void set_dry(float dry) property", asFUNCTION((virtual_call < freeverb_node, &freeverb_node::set_dry, void, float >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("audio_freeverb_node", "float get_dry() const property", asFUNCTION((virtual_call < freeverb_node, &freeverb_node::get_dry, float >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("audio_freeverb_node", "void set_input_width(float width) property", asFUNCTION((virtual_call < freeverb_node, &freeverb_node::set_input_width, void, float >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("audio_freeverb_node", "float get_input_width() const property", asFUNCTION((virtual_call < freeverb_node, &freeverb_node::get_input_width, float >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("audio_freeverb_node", "void set_frozen(bool frozen) property", asFUNCTION((virtual_call < freeverb_node, &freeverb_node::set_frozen, void, bool >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("audio_freeverb_node", "bool get_frozen() const property", asFUNCTION((virtual_call < freeverb_node, &freeverb_node::get_frozen, bool >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectBehaviour("reverb3d", asBEHAVE_FACTORY, "reverb3d@ n(audio_node@+ reverb, mixer@+ destination = null, audio_engine@+ engine = sound_default_engine)", asFUNCTION(reverb3d::create), asCALL_CDECL);
	engine->RegisterObjectMethod("reverb3d", "void set_reverb(audio_node@+ reverb) property", asFUNCTION((virtual_call < reverb3d, &reverb3d::set_reverb, void, audio_node*>)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("reverb3d", "audio_node@+ get_reverb() const property", asFUNCTION((virtual_call < reverb3d, &reverb3d::get_reverb, audio_node*>)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("reverb3d", "void set_mixer(mixer@+ mix) property", asFUNCTION((virtual_call < reverb3d, &reverb3d::set_mixer, void, mixer*>)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("reverb3d", "mixer@+ get_mixer() const property", asFUNCTION((virtual_call < reverb3d, &reverb3d::get_mixer, mixer*>)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("reverb3d", "void set_min_volume(float min_volume) property", asFUNCTION((virtual_call < reverb3d, &reverb3d::set_min_volume, void, float >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("reverb3d", "float get_min_volume() const property", asFUNCTION((virtual_call < reverb3d, &reverb3d::get_min_volume, float >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("reverb3d", "void set_max_volume(float max_volume) property", asFUNCTION((virtual_call < reverb3d, &reverb3d::set_max_volume, void, float >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("reverb3d", "float get_max_volume() const property", asFUNCTION((virtual_call < reverb3d, &reverb3d::get_max_volume, float >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("reverb3d", "void set_max_volume_distance(float distance) property", asFUNCTION((virtual_call < reverb3d, &reverb3d::set_max_volume_distance, void, float >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("reverb3d", "float get_max_volume_distance() const property", asFUNCTION((virtual_call < reverb3d, &reverb3d::get_max_volume_distance, float >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("reverb3d", "void set_max_audible_distance(float distance) property", asFUNCTION((virtual_call < reverb3d, &reverb3d::set_max_audible_distance, void, float >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("reverb3d", "float get_max_audible_distance() const property", asFUNCTION((virtual_call < reverb3d, &reverb3d::get_max_audible_distance, float >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("reverb3d", "void set_volume_curve(float volume_curve) property", asFUNCTION((virtual_call < reverb3d, &reverb3d::set_volume_curve, void, float >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("reverb3d", "float get_volume_curve() const property", asFUNCTION((virtual_call < reverb3d, &reverb3d::get_volume_curve, float >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("reverb3d", "float get_volume_at(float distance) const", asFUNCTION((virtual_call < reverb3d, &reverb3d::get_volume_at, float, float>)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("reverb3d", "audio_splitter_node@ create_attachment(audio_node@+ dry_input = null, audio_node@+ dry_output = null)", asFUNCTION((virtual_call < reverb3d, &reverb3d::create_attachment, splitter_node*, audio_node*, audio_node*>)), asCALL_CDECL_OBJFIRST);
}
void RegisterSoundsystemShapes(asIScriptEngine* engine) {
	int ot = engine->RegisterObjectType("sound_aabb_shape", 0, asOBJ_REF); assert(ot >= 0);
	g_sound_shape_setup_callbacks[ot] = sound_shape_builtin_standard_setup;
	engine->RegisterObjectBehaviour("sound_aabb_shape", asBEHAVE_FACTORY, "sound_aabb_shape@ s(int left_range, int right_range, int backward_range, int forward_range, int lower_range, int upper_range)", asFUNCTION(create_sound_aabb_shape), asCALL_CDECL);
	engine->RegisterObjectBehaviour("sound_aabb_shape", asBEHAVE_ADDREF, "void f()", asMETHOD(sound_aabb_shape, duplicate), asCALL_THISCALL);
	engine->RegisterObjectBehaviour("sound_aabb_shape", asBEHAVE_RELEASE, "void f()", asMETHOD(sound_aabb_shape, release), asCALL_THISCALL);
	engine->RegisterObjectProperty("sound_aabb_shape", "int left_range", asOFFSET(sound_aabb_shape, left_range));
	engine->RegisterObjectProperty("sound_aabb_shape", "int right_range", asOFFSET(sound_aabb_shape, right_range));
	engine->RegisterObjectProperty("sound_aabb_shape", "int backward_range", asOFFSET(sound_aabb_shape, backward_range));
	engine->RegisterObjectProperty("sound_aabb_shape", "int forward_range", asOFFSET(sound_aabb_shape, forward_range));
	engine->RegisterObjectProperty("sound_aabb_shape", "int lower_range", asOFFSET(sound_aabb_shape, lower_range));
	engine->RegisterObjectProperty("sound_aabb_shape", "int upper_range", asOFFSET(sound_aabb_shape, upper_range));
}
void RegisterSoundsystem(asIScriptEngine *engine) {
	engine->RegisterEnum("audio_error_state");
	engine->RegisterEnumValue("audio_error_state", "AUDIO_ERROR_STATE_SUCCESS", MA_SUCCESS);
	engine->RegisterEnumValue("audio_error_state", "AUDIO_ERROR_STATE_ERROR", MA_ERROR);
	engine->RegisterEnumValue("audio_error_state", "AUDIO_ERROR_STATE_INVALID_ARGS", MA_INVALID_ARGS);
	engine->RegisterEnumValue("audio_error_state", "AUDIO_ERROR_STATE_INVALID_OPERATION", MA_INVALID_OPERATION);
	engine->RegisterEnumValue("audio_error_state", "AUDIO_ERROR_STATE_OUT_OF_MEMORY", MA_OUT_OF_MEMORY);
	engine->RegisterEnumValue("audio_error_state", "AUDIO_ERROR_STATE_OUT_OF_RANGE", MA_OUT_OF_RANGE);
	engine->RegisterEnumValue("audio_error_state", "AUDIO_ERROR_STATE_ACCESS_DENIED", MA_ACCESS_DENIED);
	engine->RegisterEnumValue("audio_error_state", "AUDIO_ERROR_STATE_DOES_NOT_EXIST", MA_DOES_NOT_EXIST);
	engine->RegisterEnumValue("audio_error_state", "AUDIO_ERROR_STATE_ALREADY_EXISTS", MA_ALREADY_EXISTS);
	engine->RegisterEnumValue("audio_error_state", "AUDIO_ERROR_STATE_TOO_MANY_OPEN_FILES", MA_TOO_MANY_OPEN_FILES);
	engine->RegisterEnumValue("audio_error_state", "AUDIO_ERROR_STATE_INVALID_FILE", MA_INVALID_FILE);
	engine->RegisterEnumValue("audio_error_state", "AUDIO_ERROR_STATE_TOO_BIG", MA_TOO_BIG);
	engine->RegisterEnumValue("audio_error_state", "AUDIO_ERROR_STATE_PATH_TOO_LONG", MA_PATH_TOO_LONG);
	engine->RegisterEnumValue("audio_error_state", "AUDIO_ERROR_STATE_NAME_TOO_LONG", MA_NAME_TOO_LONG);
	engine->RegisterEnumValue("audio_error_state", "AUDIO_ERROR_STATE_NOT_DIRECTORY", MA_NOT_DIRECTORY);
	engine->RegisterEnumValue("audio_error_state", "AUDIO_ERROR_STATE_IS_DIRECTORY", MA_IS_DIRECTORY);
	engine->RegisterEnumValue("audio_error_state", "AUDIO_ERROR_STATE_DIRECTORY_NOT_EMPTY", MA_DIRECTORY_NOT_EMPTY);
	engine->RegisterEnumValue("audio_error_state", "AUDIO_ERROR_STATE_AT_END", MA_AT_END);
	engine->RegisterEnumValue("audio_error_state", "AUDIO_ERROR_STATE_NO_SPACE", MA_NO_SPACE);
	engine->RegisterEnumValue("audio_error_state", "AUDIO_ERROR_STATE_BUSY", MA_BUSY);
	engine->RegisterEnumValue("audio_error_state", "AUDIO_ERROR_STATE_IO_ERROR", MA_IO_ERROR);
	engine->RegisterEnumValue("audio_error_state", "AUDIO_ERROR_STATE_INTERRUPT", MA_INTERRUPT);
	engine->RegisterEnumValue("audio_error_state", "AUDIO_ERROR_STATE_UNAVAILABLE", MA_UNAVAILABLE);
	engine->RegisterEnumValue("audio_error_state", "AUDIO_ERROR_STATE_ALREADY_IN_USE", MA_ALREADY_IN_USE);
	engine->RegisterEnumValue("audio_error_state", "AUDIO_ERROR_STATE_BAD_ADDRESS", MA_BAD_ADDRESS);
	engine->RegisterEnumValue("audio_error_state", "AUDIO_ERROR_STATE_BAD_SEEK", MA_BAD_SEEK);
	engine->RegisterEnumValue("audio_error_state", "AUDIO_ERROR_STATE_BAD_PIPE", MA_BAD_PIPE);
	engine->RegisterEnumValue("audio_error_state", "AUDIO_ERROR_STATE_DEADLOCK", MA_DEADLOCK);
	engine->RegisterEnumValue("audio_error_state", "AUDIO_ERROR_STATE_TOO_MANY_LINKS", MA_TOO_MANY_LINKS);
	engine->RegisterEnumValue("audio_error_state", "AUDIO_ERROR_STATE_NOT_IMPLEMENTED", MA_NOT_IMPLEMENTED);
	engine->RegisterEnumValue("audio_error_state", "AUDIO_ERROR_STATE_NO_MESSAGE", MA_NO_MESSAGE);
	engine->RegisterEnumValue("audio_error_state", "AUDIO_ERROR_STATE_BAD_MESSAGE", MA_BAD_MESSAGE);
	engine->RegisterEnumValue("audio_error_state", "AUDIO_ERROR_STATE_NO_DATA_AVAILABLE", MA_NO_DATA_AVAILABLE);
	engine->RegisterEnumValue("audio_error_state", "AUDIO_ERROR_STATE_INVALID_DATA", MA_INVALID_DATA);
	engine->RegisterEnumValue("audio_error_state", "AUDIO_ERROR_STATE_TIMEOUT", MA_TIMEOUT);
	engine->RegisterEnumValue("audio_error_state", "AUDIO_ERROR_STATE_NO_NETWORK", MA_NO_NETWORK);
	engine->RegisterEnumValue("audio_error_state", "AUDIO_ERROR_STATE_NOT_UNIQUE", MA_NOT_UNIQUE);
	engine->RegisterEnumValue("audio_error_state", "AUDIO_ERROR_STATE_NOT_SOCKET", MA_NOT_SOCKET);
	engine->RegisterEnumValue("audio_error_state", "AUDIO_ERROR_STATE_NO_ADDRESS", MA_NO_ADDRESS);
	engine->RegisterEnumValue("audio_error_state", "AUDIO_ERROR_STATE_BAD_PROTOCOL", MA_BAD_PROTOCOL);
	engine->RegisterEnumValue("audio_error_state", "AUDIO_ERROR_STATE_PROTOCOL_UNAVAILABLE", MA_PROTOCOL_UNAVAILABLE);
	engine->RegisterEnumValue("audio_error_state", "AUDIO_ERROR_STATE_PROTOCOL_NOT_SUPPORTED", MA_PROTOCOL_NOT_SUPPORTED);
	engine->RegisterEnumValue("audio_error_state", "AUDIO_ERROR_STATE_PROTOCOL_FAMILY_NOT_SUPPORTED", MA_PROTOCOL_FAMILY_NOT_SUPPORTED);
	engine->RegisterEnumValue("audio_error_state", "AUDIO_ERROR_STATE_ADDRESS_FAMILY_NOT_SUPPORTED", MA_ADDRESS_FAMILY_NOT_SUPPORTED);
	engine->RegisterEnumValue("audio_error_state", "AUDIO_ERROR_STATE_SOCKET_NOT_SUPPORTED", MA_SOCKET_NOT_SUPPORTED);
	engine->RegisterEnumValue("audio_error_state", "AUDIO_ERROR_STATE_CONNECTION_RESET", MA_CONNECTION_RESET);
	engine->RegisterEnumValue("audio_error_state", "AUDIO_ERROR_STATE_ALREADY_CONNECTED", MA_ALREADY_CONNECTED);
	engine->RegisterEnumValue("audio_error_state", "AUDIO_ERROR_STATE_NOT_CONNECTED", MA_NOT_CONNECTED);
	engine->RegisterEnumValue("audio_error_state", "AUDIO_ERROR_STATE_CONNECTION_REFUSED", MA_CONNECTION_REFUSED);
	engine->RegisterEnumValue("audio_error_state", "AUDIO_ERROR_STATE_NO_HOST", MA_NO_HOST);
	engine->RegisterEnumValue("audio_error_state", "AUDIO_ERROR_STATE_IN_PROGRESS", MA_IN_PROGRESS);
	engine->RegisterEnumValue("audio_error_state", "AUDIO_ERROR_STATE_CANCELLED", MA_CANCELLED);
	engine->RegisterEnumValue("audio_error_state", "AUDIO_ERROR_STATE_MEMORY_ALREADY_MAPPED", MA_MEMORY_ALREADY_MAPPED);
	engine->RegisterEnumValue("audio_error_state", "AUDIO_ERROR_STATE_CRC_MISMATCH", MA_CRC_MISMATCH);
	engine->RegisterEnumValue("audio_error_state", "AUDIO_ERROR_STATE_FORMAT_NOT_SUPPORTED", MA_FORMAT_NOT_SUPPORTED);
	engine->RegisterEnumValue("audio_error_state", "AUDIO_ERROR_STATE_DEVICE_TYPE_NOT_SUPPORTED", MA_DEVICE_TYPE_NOT_SUPPORTED);
	engine->RegisterEnumValue("audio_error_state", "AUDIO_ERROR_STATE_SHARE_MODE_NOT_SUPPORTED", MA_SHARE_MODE_NOT_SUPPORTED);
	engine->RegisterEnumValue("audio_error_state", "AUDIO_ERROR_STATE_NO_BACKEND", MA_NO_BACKEND);
	engine->RegisterEnumValue("audio_error_state", "AUDIO_ERROR_STATE_NO_DEVICE", MA_NO_DEVICE);
	engine->RegisterEnumValue("audio_error_state", "AUDIO_ERROR_STATE_API_NOT_FOUND", MA_API_NOT_FOUND);
	engine->RegisterEnumValue("audio_error_state", "AUDIO_ERROR_STATE_INVALID_DEVICE_CONFIG", MA_INVALID_DEVICE_CONFIG);
	engine->RegisterEnumValue("audio_error_state", "AUDIO_ERROR_STATE_LOOP", MA_LOOP);
	engine->RegisterEnumValue("audio_error_state", "AUDIO_ERROR_STATE_BACKEND_NOT_ENABLED", MA_BACKEND_NOT_ENABLED);
	engine->RegisterEnumValue("audio_error_state", "AUDIO_ERROR_STATE_DEVICE_NOT_INITIALIZED", MA_DEVICE_NOT_INITIALIZED);
	engine->RegisterEnumValue("audio_error_state", "AUDIO_ERROR_STATE_DEVICE_ALREADY_INITIALIZED", MA_DEVICE_ALREADY_INITIALIZED);
	engine->RegisterEnumValue("audio_error_state", "AUDIO_ERROR_STATE_DEVICE_NOT_STARTED", MA_DEVICE_NOT_STARTED);
	engine->RegisterEnumValue("audio_error_state", "AUDIO_ERROR_STATE_DEVICE_NOT_STOPPED", MA_DEVICE_NOT_STOPPED);
	engine->RegisterEnumValue("audio_error_state", "AUDIO_ERROR_STATE_FAILED_TO_INIT_BACKEND", MA_FAILED_TO_INIT_BACKEND);
	engine->RegisterEnumValue("audio_error_state", "AUDIO_ERROR_STATE_FAILED_TO_OPEN_BACKEND_DEVICE", MA_FAILED_TO_OPEN_BACKEND_DEVICE);
	engine->RegisterEnumValue("audio_error_state", "AUDIO_ERROR_STATE_FAILED_TO_START_BACKEND_DEVICE", MA_FAILED_TO_START_BACKEND_DEVICE);
	engine->RegisterEnumValue("audio_error_state", "AUDIO_ERROR_STATE_FAILED_TO_STOP_BACKEND_DEVICE", MA_FAILED_TO_STOP_BACKEND_DEVICE);
	engine->RegisterEnum("audio_node_state");
	engine->RegisterEnumValue("audio_node_state", "AUDIO_NODE_STATE_STARTED", ma_node_state_started);
	engine->RegisterEnumValue("audio_node_state", "AUDIO_NODE_STATE_STOPPED", ma_node_state_stopped);
	engine->RegisterEnum("audio_format");
	engine->RegisterEnumValue("audio_format", "AUDIO_FORMAT_UNKNOWN", ma_format_unknown);
	engine->RegisterEnumValue("audio_format", "AUDIO_FORMAT_U8", ma_format_u8);
	engine->RegisterEnumValue("audio_format", "AUDIO_FORMAT_S16", ma_format_s16);
	engine->RegisterEnumValue("audio_format", "AUDIO_FORMAT_S24", ma_format_s24);
	engine->RegisterEnumValue("audio_format", "AUDIO_FORMAT_S32", ma_format_s32);
	engine->RegisterEnumValue("audio_format", "AUDIO_FORMAT_F32", ma_format_f32);
	engine->RegisterEnum("audio_pan_mode");
	engine->RegisterEnumValue("audio_pan_mode", "AUDIO_PAN_MODE_BALANCE", ma_pan_mode_balance);
	engine->RegisterEnumValue("audio_pan_mode", "AUDIO_PAN_MODE_PAN", ma_pan_mode_pan);
	engine->RegisterEnum("audio_positioning_mode");
	engine->RegisterEnumValue("audio_positioning_mode", "AUDIO_POSITIONING_ABSOLUTE", ma_positioning_absolute);
	engine->RegisterEnumValue("audio_positioning_mode", "AUDIO_POSITIONING_RELATIVE", ma_positioning_relative);
	engine->RegisterEnum("audio_engine_flags");
	engine->RegisterEnumValue("audio_engine_flags", "AUDIO_ENGINE_DURATIONS_IN_FRAMES", audio_engine::DURATIONS_IN_FRAMES);
	engine->RegisterEnumValue("audio_engine_flags", "AUDIO_ENGINE_NO_AUTO_START", audio_engine::NO_AUTO_START);
	engine->RegisterEnumValue("audio_engine_flags", "AUDIO_ENGINE_NO_DEVICE", audio_engine::NO_DEVICE);
	engine->RegisterEnumValue("audio_engine_flags", "AUDIO_ENGINE_NO_CLIP", audio_engine::NO_CLIP);
	engine->RegisterEnumValue("audio_engine_flags", "AUDIO_ENGINE_PERCENTAGE_ATTRIBUTES", audio_engine::PERCENTAGE_ATTRIBUTES);
	engine->RegisterEnum("audio_panner");
	engine->RegisterEnumValue("audio_panner", "audio_panner_basic", g_audio_basic_panner);
	engine->RegisterEnumValue("audio_panner", "audio_panner_phonon_hrtf", g_audio_phonon_hrtf_panner);
	engine->RegisterEnum("audio_attenuator");
	engine->RegisterEnumValue("audio_attenuator", "audio_attenuator_basic", g_audio_basic_attenuator);
	engine->RegisterEnumValue("audio_attenuator", "audio_attenuator_phonon", g_audio_phonon_attenuator);
	engine->RegisterEnum("reverb3d_placement");
	engine->RegisterEnumValue("reverb3d_placement", "reverb3d_prepan", prepan);
	engine->RegisterEnumValue("reverb3d_placement", "reverb3d_postpan", postpan);
	engine->RegisterEnumValue("reverb3d_placement", "reverb3d_postattenuate", postattenuate);
	RegisterSoundsystemAudioNode < audio_node > (engine, "audio_node");
	RegisterSoundsystemEngine(engine);
	RegisterSoundsystemAudioNode < audio_node_chain > (engine, "audio_node_chain");
	RegisterSoundsystemAudioNode < splitter_node > (engine, "audio_splitter_node");
	RegisterSoundsystemAudioNode <reverb3d> (engine, "reverb3d");
	RegisterSoundsystemMixer < mixer > (engine, "mixer");
	engine->RegisterObjectBehaviour("mixer", asBEHAVE_FACTORY, "mixer@ m()", asFUNCTION(new_global_mixer), asCALL_CDECL);
	RegisterSoundsystemMixer < sound > (engine, "sound");
	engine->RegisterObjectMethod("audio_engine", "sound@ play(const string&in path, const vector&in position = vector(FLOAT_MAX, FLOAT_MAX, FLOAT_MAX), float volume = FLOAT_MAX, float pan = FLOAT_MAX, float pitch = FLOAT_MAX, mixer@+ mix = null, const pack_interface@+ pack_file = sound_default_pack, bool autoplay = true)", asFUNCTION((virtual_call < audio_engine, &audio_engine::play, sound*, const string &, const reactphysics3d::Vector3&, float, float, float, mixer*, const pack_interface*, bool>)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("audio_engine", "mixer@ mixer()", asFUNCTION((virtual_call < audio_engine, &audio_engine::new_mixer, mixer * >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("audio_engine", "sound@ sound()", asFUNCTION((virtual_call < audio_engine, &audio_engine::new_sound, sound * >)), asCALL_CDECL_OBJFIRST);
	RegisterSoundsystemDataSources(engine);
	RegisterSoundsystemNodes(engine);
	RegisterSoundsystemEncoders(engine);
	RegisterSoundsystemShapes(engine);
	engine->RegisterObjectBehaviour("sound", asBEHAVE_FACTORY, "sound@ s()", asFUNCTION(new_global_sound), asCALL_CDECL);
	engine->RegisterObjectMethod("sound", "bool load(const string&in filename, const pack_interface@+ pack = sound_default_pack)", asFUNCTION((virtual_call < sound, &sound::load, bool, const string &, pack_interface * >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("sound", "bool stream(const string&in filename, const pack_interface@+ pack = sound_default_pack)", asFUNCTION((virtual_call < sound, &sound::stream, bool, const string &, pack_interface * >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("sound", "bool stream_url(const string&in url)", asFUNCTION((virtual_call < sound, &sound::stream_url, bool, const string&>)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("sound", "bool load_memory(const string&in data)", asFUNCTION((virtual_call < sound, &sound::load_string, bool, const string & >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("sound", "bool load_pcm(const float[]@+ data, int samplerate, int channels)", asFUNCTION((virtual_call < sound, &sound::load_pcm_script_array, bool, CScriptArray *, int, int >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("sound", "bool load_pcm(const int[]@+ data, int samplerate, int channels)", asFUNCTION((virtual_call < sound, &sound::load_pcm_script_array, bool, CScriptArray *, int, int >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("sound", "bool load_pcm(const int16[]@+ data, int samplerate, int channels)", asFUNCTION((virtual_call < sound, &sound::load_pcm_script_array, bool, CScriptArray *, int, int >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("sound", "bool load_pcm(const uint8[]@+ data, int samplerate, int channels)", asFUNCTION((virtual_call < sound, &sound::load_pcm_script_array, bool, CScriptArray *, int, int >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("sound", "bool load_pcm(const memory_buffer<float>&in data, int samplerate, int channels)", asFUNCTION((virtual_call < sound, &sound::load_pcm_script_memory_buffer, bool, script_memory_buffer*, int, int>)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("sound", "bool load_pcm(const memory_buffer<int>&in data, int samplerate, int channels)", asFUNCTION((virtual_call < sound, &sound::load_pcm_script_memory_buffer, bool, script_memory_buffer*, int, int>)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("sound", "bool load_pcm(const memory_buffer<int16>&in data, int samplerate, int channels)", asFUNCTION((virtual_call < sound, &sound::load_pcm_script_memory_buffer, bool, script_memory_buffer*, int, int>)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("sound", "bool load_pcm(const memory_buffer<uint8>&in data, int samplerate, int channels)", asFUNCTION((virtual_call < sound, &sound::load_pcm_script_memory_buffer, bool, script_memory_buffer*, int, int>)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("sound", "bool stream_pcm(const float[]@+ data, uint sample_rate = 0, uint channels = 0, uint buffer_size = 0)", asFUNCTION((virtual_call < sound, &sound::stream_pcm_script_array, bool, CScriptArray*, unsigned int, unsigned int, unsigned int>)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("sound", "bool stream_pcm(const int[]@+ data, uint sample_rate = 0, uint channels = 0, uint buffer_size = 0)", asFUNCTION((virtual_call < sound, &sound::stream_pcm_script_array, bool, CScriptArray*, unsigned int, unsigned int, unsigned int>)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("sound", "bool stream_pcm(const int16[]@+ data, uint sample_rate = 0, uint channels = 0, uint buffer_size = 0)", asFUNCTION((virtual_call < sound, &sound::stream_pcm_script_array, bool, CScriptArray*, unsigned int, unsigned int, unsigned int>)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("sound", "bool stream_pcm(const uint8[]@+ data, uint sample_rate = 0, uint channels = 0, uint buffer_size = 0)", asFUNCTION((virtual_call < sound, &sound::stream_pcm_script_array, bool, CScriptArray*, unsigned int, unsigned int, unsigned int>)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("sound", "bool stream_pcm(const memory_buffer<float>&in data, uint sample_rate = 0, uint channels = 0, uint buffer_size = 0)", asFUNCTION((virtual_call < sound, &sound::stream_pcm_script_memory_buffer, bool, script_memory_buffer*, unsigned int, unsigned int, unsigned int>)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("sound", "bool stream_pcm(const memory_buffer<int>&in data, uint sample_rate = 0, uint channels = 0, uint buffer_size = 0)", asFUNCTION((virtual_call < sound, &sound::stream_pcm_script_memory_buffer, bool, script_memory_buffer*, unsigned int, unsigned int, unsigned int>)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("sound", "bool stream_pcm(const memory_buffer<int16>&in data, uint sample_rate = 0, uint channels = 0, uint buffer_size = 0)", asFUNCTION((virtual_call < sound, &sound::stream_pcm_script_memory_buffer, bool, script_memory_buffer*, unsigned int, unsigned int, unsigned int>)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("sound", "bool stream_pcm(const memory_buffer<uint8>&in data, uint sample_rate = 0, uint channels = 0, uint buffer_size = 0)", asFUNCTION((virtual_call < sound, &sound::stream_pcm_script_memory_buffer, bool, script_memory_buffer*, unsigned int, unsigned int, unsigned int>)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("sound", "bool open(audio_data_source@ datasource)", asFUNCTION((virtual_call<sound, &sound::open, bool, audio_data_source*>)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("sound", "bool close()", asFUNCTION((virtual_call < sound, &sound::close, bool >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("sound", "void set_autoclose(bool enabled = true) property", asFUNCTION((virtual_call < sound, &sound::set_autoclose, void, bool >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("sound", "bool get_autoclose() const property", asFUNCTION((virtual_call < sound, &sound::get_autoclose, bool >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("sound", "const string& get_loaded_filename() const property", asFUNCTION((virtual_call < sound, &sound::get_loaded_filename, const std::string & >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("sound", "audio_data_source@+ get_datasource() const property", asFUNCTION((virtual_call < sound, &sound::get_datasource, audio_data_source*>)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("sound", "bool get_load_complete() const property", asFUNCTION((virtual_call < sound, &sound::is_load_completed, bool >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("sound", "bool get_active() const property", asFUNCTION((virtual_call < sound, &sound::get_active, bool >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("sound", "bool get_paused() const property", asFUNCTION((virtual_call < sound, &sound::get_paused, bool >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("sound", "bool play_wait()", asFUNCTION((virtual_call < sound, &sound::play_wait, bool >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("sound", "bool pause()", asFUNCTION((virtual_call < sound, &sound::pause, bool >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("sound", "bool pause_fade(const uint64 length)", asFUNCTION((virtual_call < sound, &sound::pause_fade, bool, unsigned long long >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("sound", "bool pause_fade_in_frames(const uint64 length_in_frames)", asFUNCTION((virtual_call < sound, &sound::pause_fade_in_frames, bool, unsigned long long >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("sound", "bool pause_fade_in_milliseconds(const uint64 length_in_milliseconds)", asFUNCTION((virtual_call < sound, &sound::pause_fade_in_milliseconds, bool, unsigned long long >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("sound", "void set_timed_fade(float start_volume, float end_volume, uint64 length, uint64 absolute_time)", asFUNCTION((virtual_call < sound, &sound::set_timed_fade, void, float, float, unsigned long long, unsigned long long >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("sound", "void set_timed_fade_in_frames(float start_volume, float end_volume, uint64 length, uint64 absolute_time)", asFUNCTION((virtual_call < sound, &sound::set_timed_fade_in_frames, void, float, float, unsigned long long, unsigned long long >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("sound", "void set_timed_fade_in_milliseconds(float start_volume, float end_volume, uint64 length, uint64 absolute_time)", asFUNCTION((virtual_call < sound, &sound::set_timed_fade_in_milliseconds, void, float, float, unsigned long long, unsigned long long >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("sound", "void set_stop_time_with_fade(uint64 absolute_time, uint64 fade_length)", asFUNCTION((virtual_call < sound, &sound::set_stop_time_with_fade, void, unsigned long long, unsigned long long >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("sound", "void set_stop_time_with_fade_in_frames(uint64 absolute_time, uint64 fade_length)", asFUNCTION((virtual_call < sound, &sound::set_stop_time_with_fade_in_frames, void, unsigned long long, unsigned long long >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("sound", "void set_stop_time_with_fade_in_milliseconds(uint64 absolute_time, uint64 fade_length)", asFUNCTION((virtual_call < sound, &sound::set_stop_time_with_fade_in_milliseconds, void, unsigned long long, unsigned long long >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("sound", "void set_looping(bool looping) property", asFUNCTION((virtual_call < sound, &sound::set_looping, void, bool >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("sound", "bool get_looping() const property", asFUNCTION((virtual_call < sound, &sound::get_looping, bool >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("sound", "bool get_at_end() const property", asFUNCTION((virtual_call < sound, &sound::get_at_end, bool >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("sound", "bool seek(const uint64 position)", asFUNCTION((virtual_call < sound, &sound::seek, bool, unsigned long long >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("sound", "bool seek_in_frames(const uint64 position)", asFUNCTION((virtual_call < sound, &sound::seek_in_frames, bool, unsigned long long >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("sound", "bool seek_in_milliseconds(const uint64 position)", asFUNCTION((virtual_call < sound, &sound::seek_in_milliseconds, bool, unsigned long long >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("sound", "uint64 get_position() property", asFUNCTION((virtual_call < sound, &sound::get_position, unsigned long long >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("sound", "uint64 get_position_in_frames() const property", asFUNCTION((virtual_call < sound, &sound::get_position_in_frames, unsigned long long >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("sound", "uint64 get_position_in_milliseconds() const property", asFUNCTION((virtual_call < sound, &sound::get_position_in_milliseconds, unsigned long long >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("sound", "uint64 get_length() property", asFUNCTION((virtual_call < sound, &sound::get_length, unsigned long long >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("sound", "uint64 get_length_in_frames( ) const property", asFUNCTION((virtual_call < sound, &sound::get_length_in_frames, unsigned long long >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("sound", "uint64 get_length_in_ms() const property", asFUNCTION((virtual_call < sound, &sound::get_length_in_milliseconds, unsigned long long >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("sound", "uint64 get_length_in_milliseconds() const property", asFUNCTION((virtual_call < sound, &sound::get_length_in_milliseconds, unsigned long long >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("sound", "bool get_data_format(audio_format&out format, uint32&out channels, uint32&out sample_rate)", asFUNCTION((virtual_call < sound, &sound::get_data_format, bool, ma_format *, unsigned int *, unsigned int * >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterObjectMethod("sound", "double get_pitch_lower_limit() const property", asFUNCTION((virtual_call < sound, &sound::get_pitch_lower_limit, double >)), asCALL_CDECL_OBJFIRST);
	engine->RegisterGlobalFunction("const string[]@ get_sound_input_devices() property", asFUNCTION(get_sound_input_devices), asCALL_CDECL);
	engine->RegisterGlobalFunction("const string[]@ get_sound_output_devices() property", asFUNCTION(get_sound_output_devices), asCALL_CDECL);
	engine->RegisterGlobalFunction("int get_sound_output_device() property", asFUNCTION(get_sound_output_device), asCALL_CDECL);
	engine->RegisterGlobalFunction("mixer@ get_sound_default_mixer() property", asFUNCTION(get_sound_default_mixer), asCALL_CDECL);
	engine->RegisterGlobalFunction("void set_sound_default_mixer(mixer@ mix) property", asFUNCTION(set_sound_default_mixer), asCALL_CDECL);
	engine->RegisterGlobalFunction("void set_sound_output_device(int device) property", asFUNCTION(set_sound_output_device), asCALL_CDECL);
	engine->RegisterGlobalFunction("sound@ sound_play(const string&in path, const vector&in position = vector(FLOAT_MAX, FLOAT_MAX, FLOAT_MAX), float volume = FLOAT_MAX, float pan = FLOAT_MAX, float pitch = FLOAT_MAX, mixer@+ mix = null, const pack_interface@+ pack_file = sound_default_pack, bool autoplay = true)", asFUNCTION(sound_play), asCALL_CDECL);
	engine->RegisterGlobalFunction("vector sound_get_listener_position(uint listener_index = 0)", asFUNCTION(sound_get_listener_position), asCALL_CDECL);
	engine->RegisterGlobalFunction("bool sound_set_listener_position(float x, float y, float z, uint listener_index = 0)", asFUNCTION(sound_set_listener_position), asCALL_CDECL);
	engine->RegisterGlobalFunction("bool sound_set_listener_position(const vector&in position, uint listener_index = 0)", asFUNCTION(sound_set_listener_position_vector), asCALL_CDECL);
	engine->RegisterGlobalFunction("void set_sound_default_decryption_key(const string& in key) property", asFUNCTION(set_default_decryption_key), asCALL_CDECL);
	engine->RegisterGlobalFunction("void set_sound_default_pack(pack_interface@+ storage) property", asFUNCTION(set_sound_default_storage), asCALL_CDECL);
	engine->RegisterGlobalFunction("pack_interface@ get_sound_default_pack() property", asFUNCTION(get_sound_default_storage), asCALL_CDECL);
	engine->RegisterGlobalFunction("void set_sound_master_volume(float db) property", asFUNCTION(set_sound_master_volume), asCALL_CDECL);
	engine->RegisterGlobalFunction("float get_sound_master_volume() property", asFUNCTION(get_sound_master_volume), asCALL_CDECL);
	engine->RegisterGlobalFunction("audio_error_state get_SOUNDSYSTEM_LAST_ERROR() property", asFUNCTION(get_soundsystem_last_error), asCALL_CDECL);
	engine->RegisterGlobalFunction("string get_SOUNDSYSTEM_LAST_ERROR_TEXT() property", asFUNCTION(get_soundsystem_last_error_text), asCALL_CDECL);
	engine->RegisterGlobalFunction("void set_sound_default_3d_panner(int panner_id)", asFUNCTION(sound_set_default_3d_panner), asCALL_CDECL);
	engine->RegisterGlobalFunction("int get_sound_default_3d_panner() property", asFUNCTION(sound_get_default_3d_panner), asCALL_CDECL);
	engine->RegisterGlobalFunction("void set_sound_default_3d_attenuator(int attenuator_id)", asFUNCTION(sound_set_default_3d_attenuator), asCALL_CDECL);
	engine->RegisterGlobalFunction("int get_sound_default_3d_attenuator() property", asFUNCTION(sound_get_default_3d_attenuator), asCALL_CDECL);
	engine->RegisterGlobalFunction("void set_sound_3d_panner_enabled(int panner_id, bool enabled)", asFUNCTION(set_audio_panner_enabled), asCALL_CDECL);
	engine->RegisterGlobalFunction("bool get_sound_3d_panner_enabled(int panner_id)", asFUNCTION(get_audio_panner_enabled), asCALL_CDECL);
	engine->RegisterGlobalFunction("void set_sound_3d_attenuator_enabled(int attenuator_id, bool enabled)", asFUNCTION(set_audio_attenuator_enabled), asCALL_CDECL);
	engine->RegisterGlobalFunction("bool get_sound_3d_attenuator_enabled(int attenuator_id)", asFUNCTION(get_audio_attenuator_enabled), asCALL_CDECL);
	engine->RegisterGlobalFunction("bool sound_set_spatialization(int panner, int attenuator, bool disable_previous = false, bool set_default = true)", asFUNCTION(sound_set_spatialization), asCALL_CDECL);
}
// The script types plugins registered as audio node types. Every plugin node is one C++ class, plugin_node_impl, so a dynamic_cast took a node of any of them for any other, and a cast to one plugin's type handed a node of another plugin's to that plugin's methods, which then took its implementation for their own.
static std::mutex g_plugin_node_types_mutex;
static std::unordered_set<int> g_plugin_node_types;
// The cast from audio_node to a plugin's node type: null for a node made as another of those types, as known from the call that made it (see nvgt_audio_plugin_node_create()); a node whose type isn't known is cast as before.
static void plugin_node_cast(asIScriptGeneric* gen) {
	audio_node* node = (audio_node*)gen->GetObject();
	plugin_node* result = node? dynamic_cast<plugin_node*>(node) : nullptr;
	if (result) {
		int made_as = result->get_script_type_id();
		asITypeInfo* target = gen->GetEngine()->GetTypeInfoById(gen->GetFunction()->GetReturnTypeId());
		if (made_as && target && target->GetTypeId() != made_as) result = nullptr;
	}
	gen->SetReturnObject(result);
}
void nvgt_audio_plugin_node_register(const string& nodename) {
	RegisterSoundsystemAudioNode<plugin_node>(g_ScriptEngine, nodename);
	g_ScriptEngine->RegisterObjectMethod("audio_node", Poco::format("%s@ opCast()", nodename).c_str(), asFUNCTION(plugin_node_cast), asCALL_GENERIC);
	if (asITypeInfo* type = g_ScriptEngine->GetTypeInfoByName(nodename.c_str())) {
		std::lock_guard<std::mutex> lock(g_plugin_node_types_mutex);
		g_plugin_node_types.insert(type->GetTypeId());
	}
}
// The node is made as the plugin's node type the script function calling the plugin returns, as its factory does; a node made otherwise, as outside a call from a script, has no type known.
// A node that can't be made gives null rather than an exception, which a plugin built apart from NVGT can't reliably catch; impl then stays the plugin's, release() never being called for it.
plugin_node* nvgt_audio_plugin_node_create(audio_plugin_node_interface* impl, unsigned char input_bus_count, unsigned char output_bus_count, unsigned int flags, audio_engine* engine) {
	if (!engine) { // The node is made in that engine's graph, which the constructor reads.
		g_soundsystem_last_error = MA_INVALID_ARGS;
		return nullptr;
	}
	plugin_node* node;
	try {
		node = plugin_node::create(impl, input_bus_count, output_bus_count, flags, engine);
	} catch (...) {
		return nullptr;
	}
	asIScriptContext* ctx = asGetActiveContext();
	asIScriptFunction* calling = ctx? ctx->GetSystemFunction() : nullptr;
	asITypeInfo* type = calling? g_ScriptEngine->GetTypeInfoById(calling->GetReturnTypeId()) : nullptr;
	if (node && type) {
		std::lock_guard<std::mutex> lock(g_plugin_node_types_mutex);
		if (g_plugin_node_types.count(type->GetTypeId())) node->set_script_type_id(type->GetTypeId());
	}
	return node;
}
audio_plugin_node_interface* nvgt_audio_plugin_node_get(plugin_node* node) { return node->get_plugin_interface(); }
