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
#include <vector>
#include <Poco/FileStream.h>
#include <Poco/Format.h>
#include <Poco/MemoryStream.h>
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
mixer* g_audio_mixer = nullptr;
static std::atomic_flag g_soundsystem_initialized; // The context, the sound service and the device lists are set up, see init_sound_context().
static std::atomic_flag g_soundsystem_ready; // The engine exists. Set last so that no other thread can be told "initialized" while g_audio_engine is still null.
static std::recursive_mutex g_soundsystem_init_mutex; // Recursive because setting up re-enters init_sound() and init_sound_context() on this same thread.
static std::atomic_flag g_soundsystem_shut_down; // uninit_sound() ran: script threads still running are refused rather than given the default engine it let go.
static bool g_soundsystem_starting = false;
static std::atomic<bool> g_script_callbacks_stopped{false}; // See sound_stop_script_callbacks().
static std::atomic<int> g_script_callbacks_running{0}; // Processing callbacks calling the script right now. // Under g_soundsystem_init_mutex: this thread is setting up, so a call re-entering from there is answered at once.
thread_local ma_result g_soundsystem_last_error = MA_SUCCESS;
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
// AAudio's error callback hands a disconnected or rerouted stream to the context's job thread as a reroute job that holds a raw pointer to the device, and ma_device_uninit only waits for a reroute that is already running, not for one still sitting in the queue. Such a job then runs after the device is gone: it locks the destroyed reroute mutex and reopens streams through freed memory. So before a device is uninitialized, raise its tear-down flag (the error callback then queues nothing new and a queued reroute returns at once), and wait until the job thread has worked through what is already queued. The thread runs its jobs one at a time in order, so once a job posted now has run, every reroute queued before it has finished. The second pass covers an error callback that read the flag just before it was raised and posted its job just after the first marker.
static ma_result aaudio_job_queue_marker(ma_job* job) {
	ma_event_signal((ma_event*)job->data.custom.data0);
	return MA_SUCCESS;
}
static void drain_aaudio_reroutes(ma_device* device) {
	if (!device || !device->pContext || device->pContext->backend != ma_backend_aaudio || ma_device_get_state(device) == ma_device_state_uninitialized) return;
	__atomic_store_n(&device->aaudio.isTearingDown.value, MA_TRUE, __ATOMIC_SEQ_CST);
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
	garbage_collect_inline_sounds();
	std::lock_guard<std::recursive_mutex> lock(g_soundsystem_init_mutex);
	g_soundsystem_shut_down.test_and_set();
	g_soundsystem_ready.clear(); // So that init_sound() refuses later calls instead of reporting a ready system whose engine is gone.
	if (g_audio_engine != nullptr) {
		g_audio_engine->release();
		g_audio_engine = nullptr;
	}
}

// audio device enumeration, we'll just maintain a global list of available devices, vectors of ma_device_info structures for the c++ side and CScriptArrays of device names on the Angelscript side. It is important that the data in these arrays is index aligned.
static vector<ma_device_info> g_sound_input_devices, g_sound_output_devices;
static CScriptArray *g_sound_script_input_devices = nullptr, *g_sound_script_output_devices = nullptr;
ma_bool32 ma_device_enum_callback(ma_context * /*ctx*/, ma_device_type type, const ma_device_info *info, void * /*user*/) {
	string devname;
	if (type == ma_device_type_playback) {
		g_sound_output_devices.push_back(*info);
		g_sound_script_output_devices->InsertLast(&(devname = info->name));
	} else if (type == ma_device_type_capture) {
		g_sound_input_devices.push_back(*info);
		g_sound_script_input_devices->InsertLast(&(devname = info->name));
	}
	return MA_TRUE;
}
bool refresh_audio_devices() {
	if (!init_sound_context())
		return false;
	g_sound_output_devices.clear();
	g_sound_input_devices.clear();
	if (!g_sound_script_output_devices)
		g_sound_script_output_devices = CScriptArray::Create(get_array_type("array<string>"));
	else
		g_sound_script_output_devices->Resize(0);
	if (!g_sound_script_input_devices)
		g_sound_script_input_devices = CScriptArray::Create(get_array_type("array<string>"));
	else
		g_sound_script_input_devices->Resize(0);
	return (g_soundsystem_last_error = ma_context_enumerate_devices(&g_sound_context, ma_device_enum_callback, nullptr)) == MA_SUCCESS;
}
// Better to return an empty array instead of null for now. A single one, as the script adds its own reference to what these return, so a new array each time was never let go.
static CScriptArray *empty_device_list() {
	static CScriptArray *empty = CScriptArray::Create(get_array_type("array<string>"));
	return empty;
}
CScriptArray *get_sound_input_devices() {
	if (!init_sound_context())
		return empty_device_list();
	return g_sound_script_input_devices;
}
CScriptArray *get_sound_output_devices() {
	if (!init_sound_context())
		return empty_device_list();
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
MA_API float ma_sound_get_distance_to_listener(const ma_sound *pSound) {
	ma_vec3f relativePos;
	if (pSound == NULL)
		return 0;
	ma_engine *pEngine = ma_sound_get_engine(pSound);
	if (pEngine == NULL)
		return 0;
	ma_spatializer_get_relative_position_and_direction(&pSound->engineNode.spatializer, &pEngine->listeners[ma_sound_get_listener_index(pSound)], &relativePos, NULL);
	return sqrt(pow(relativePos.x, 2) + pow(relativePos.y, 2) + pow(relativePos.z, 2));
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
void garbage_collect_inline_sounds() {
	vector<sound*> finished;
	{
		unique_lock<mutex> lock(g_inlined_sounds_mutex); // For the whole walk, as sounds that start playing on other threads are added meanwhile.
		for (auto it = g_inlined_sounds.begin(); it != g_inlined_sounds.end();) {
			if ((*it)->get_playing()) ++it;
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
		reactphysics3d::AABB bounds(reactphysics3d::Vector3(sound_position - reactphysics3d::Vector3(left_range, backward_range, lower_range)), reactphysics3d::Vector3(sound_position + reactphysics3d::Vector3(right_range, forward_range, upper_range)));
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
	std::atomic<asIScriptFunction*> script_data_callback;
	audio_engine_endpoint *engine_endpoint; // Upon engine creation we'll call ma_engine_get_endpoint once so as to avoid creating more than one of our wrapper objects when our engine->get_endpoint() function is called.
	std::mutex callback_mutex; // Lets the device's thread take a reference of its own to script_data_callback before set_processing_callback() can let it go.
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
		if (!engine->script_data_callback || !engine->duplicate_if_alive()) return;
		g_script_callbacks_running++; // Before looking at the flag, so sound_stop_script_callbacks() either sees this call or this call sees the flag.
		asIScriptFunction *callback = nullptr;
		if (!g_script_callbacks_stopped) {
			std::lock_guard<std::mutex> lock(engine->callback_mutex);
			callback = engine->script_data_callback;
			if (callback) callback->AddRef();
		}
		if (callback) {
			asIScriptContext* ctx = g_ScriptEngine->RequestContext();
			if (ctx && ctx->Prepare(callback) >= 0) { // Todo: Maybe find a way to log error state here?
				script_memory_buffer buf(g_ScriptEngine->GetTypeInfoByDecl("memory_buffer<float>"), pOutput, pDevice->playback.channels * frames_read); // Todo: Support all data formats.
				if (ctx->SetArgObject(0, static_cast<audio_engine*>(engine)) >= 0 && ctx->SetArgObject(1, &buf) >= 0 && ctx->SetArgQWord(2, frames_read) >= 0)
					ctx->Execute(); // Really not sure what to do about exceptions and errors taking place in the audio thread yet as we don't have a fully established logging facility set up.
			}
			if (ctx) g_ScriptEngine->ReturnContext(ctx);
			callback->Release();
		}
		g_script_callbacks_running--;
		engine->release(); // Can be the last reference, see release().
	}

public:
	engine_flags flags;
	audio_engine_impl(int flags, int sample_rate, int channels) : audio_node_impl(nullptr, this), engine(nullptr), resource_manager(nullptr), script_data_callback(nullptr), engine_endpoint(nullptr), flags(static_cast<engine_flags>(flags)) {
		if (channels > MA_MAX_CHANNELS) throw runtime_error(Poco::format("exceeded maximum channel count of %d", MA_MAX_CHANNELS));
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
		if (resource_manager)
			ma_resource_manager_uninit(&*resource_manager);
	}
	// The last reference can go on the engine's own device thread, as the data callback holds one while it calls the script. Destroying the engine stops its device, which from that thread would wait for itself forever, so the engine is destroyed on a thread of its own then, or kept if none can be started.
	void release() override {
		if (asAtomicDec(refcount) >= 1) return;
		if (g_soundsystem_shut_down.test()) return; // Once the sound system shut down, engines are left to the process's exit, as they always were: destroying one closes its device, which by then can come after SDL took down what the backend needs, COM on Windows.
		if (processing != this) {
			delete this;
			return;
		}
		try { std::thread([this] { delete this; }).detach(); } catch (...) {}
	}
	ma_engine *get_ma_engine() const override { return engine.get(); }
	audio_node *get_endpoint() const override { return engine_endpoint; }
	int get_flags() const override { return flags; }
	int get_device() const override {
		if (!engine || flags & NO_DEVICE)
			return -1;
		ma_device *dev = ma_engine_get_device(&*engine);
		ma_device_info info;
		// A device that set_device couldn't open again is left uninitialized, and asking miniaudio about it would reach its backend.
		if (!dev || ma_device_get_state(dev) == ma_device_state_uninitialized || ma_device_get_info(dev, ma_device_type_playback, &info) != MA_SUCCESS)
			return -1;
		for (std::size_t i = 0; i < g_sound_output_devices.size(); i++) {
			if (memcmp(&g_sound_output_devices[i].id, &info.id, sizeof(ma_device_id)) == 0)
				return i;
		}
		return -1; // couldn't determine device?
	}
	bool set_device(int device) override {
		if (processing == this || !engine || flags & NO_DEVICE) { // Closing the device from its own thread would wait for that thread, see release().
			g_soundsystem_last_error = MA_INVALID_OPERATION;
			return false;
		}
		if (device < -1 || device >= int(g_sound_output_devices.size())) {
			g_soundsystem_last_error = MA_INVALID_ARGS;
			return false;
		}
		ma_device *old_dev = ma_engine_get_device(&*engine);
		bool old_open = old_dev && ma_device_get_state(old_dev) != ma_device_state_uninitialized;
		if (!old_dev || old_open && device > -1 && ma_device_id_equal(&old_dev->playback.id, &g_sound_output_devices[device].id)) return false;
		ma_engine_stop(&*engine);
		// As the constructor opens the device, with the engine's own format, which stays the same whichever device it is on and is still known after a device couldn't be opened.
		ma_device_config cfg = ma_device_config_init(ma_device_type_playback);
		if (device > -1) cfg.playback.pDeviceID = &g_sound_output_devices[device].id;
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
		if ((flags & NO_DEVICE) == 0) return CScriptArray::Create(get_array_type("array<float>")); // Its device reads it on its own thread, and MiniAudio's engine can't be read from two at once.
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
		unsigned long long frames_read;
		if (!read(result->GetBuffer(), frame_count, &frames_read)) {
			result->Resize(0);
			return result;
		}
		result->Resize(frames_read * ma_engine_get_channels(&*engine));
		return result;
	}
	void set_processing_callback(asIScriptFunction* cb) override {
		asIScriptFunction *old;
		{
			std::lock_guard<std::mutex> lock(callback_mutex);
			old = script_data_callback.exchange(cb);
		}
		if (old) old->Release(); // The device's thread holds a reference of its own to one it is calling.
	}
	asIScriptFunction* get_processing_callback() const override { return script_data_callback; }
	unsigned long long get_time() const override { return engine ? (flags & DURATIONS_IN_FRAMES ? get_time_in_frames() : get_time_in_milliseconds()) : 0; }
	bool set_time(unsigned long long time) override { return engine ? (flags & DURATIONS_IN_FRAMES) ? set_time_in_frames(time) : set_time_in_milliseconds(time) : false; }
	unsigned long long get_time_in_frames() const override { return engine ? ma_engine_get_time_in_pcm_frames(&*engine) : 0; }
	bool set_time_in_frames(unsigned long long time) override { return engine ? (g_soundsystem_last_error = ma_engine_set_time_in_pcm_frames(&*engine, time)) == MA_SUCCESS : false; }
	unsigned long long get_time_in_milliseconds() const override { return engine ? ma_engine_get_time_in_milliseconds(&*engine) : 0; }
	bool set_time_in_milliseconds(unsigned long long time) override { return engine ? (g_soundsystem_last_error = ma_engine_set_time_in_milliseconds(&*engine, time)) == MA_SUCCESS : false; }
	int get_channels() const override { return engine ? ma_engine_get_channels(&*engine) : 0; }
	int get_sample_rate() const override { return engine ? ma_engine_get_sample_rate(&*engine) : 0; }
	bool start() override {
		if (!engine || ma_engine_start(&*engine) != MA_SUCCESS) return false;
		started = true;
		return true;
	}
	bool stop() override {
		if (processing == this) return false; // Stopping the device from its own thread would wait for that thread, see release().
		if (!engine || ma_engine_stop(&*engine) != MA_SUCCESS) return false;
		started = false;
		return true;
	}
	bool set_volume(float volume) override { return engine ? (g_soundsystem_last_error = ma_engine_set_volume(&*engine, volume)) == MA_SUCCESS : false; }
	float get_volume() const override { return engine ? ma_engine_get_volume(&*engine) : 0; }
	bool set_gain(float db) override { return engine ? (g_soundsystem_last_error = ma_engine_set_gain_db(&*engine, db)) == MA_SUCCESS : false; }
	float get_gain() const override { return engine ? ma_engine_get_gain_db(&*engine) : 0; }
	unsigned int get_listener_count() const override { return engine ? ma_engine_get_listener_count(&*engine) : 0; }
	int find_closest_listener(float x, float y, float z) const override { return engine ? ma_engine_find_closest_listener(&*engine, x, y, z) : -1; }
	int find_closest_listener_vector(const reactphysics3d::Vector3 &position) const override { return engine ? ma_engine_find_closest_listener(&*engine, position.x, position.y, position.z) : -1; }
	void set_listener_position(unsigned int index, float x, float y, float z) override {
		if (engine)
			ma_engine_listener_set_position(&*engine, index, x, y, z);
		place_shaped_mixers(this);
	}
	void set_listener_position_vector(unsigned int index, const reactphysics3d::Vector3 &position) override {
		if (engine)
			ma_engine_listener_set_position(&*engine, index, position.x, position.y, position.z);
		place_shaped_mixers(this);
	}
	reactphysics3d::Vector3 get_listener_position(unsigned int index) const override { return engine ? ma_vec3_to_rp_vec3(ma_engine_listener_get_position(&*engine, index)) : reactphysics3d::Vector3(); }
	void set_listener_direction(unsigned int index, float x, float y, float z) override {
		if (engine)
			ma_engine_listener_set_direction(&*engine, index, x, y, z);
	}
	void set_listener_direction_vector(unsigned int index, const reactphysics3d::Vector3 &direction) override {
		if (engine)
			ma_engine_listener_set_direction(&*engine, index, direction.x, direction.y, direction.z);
	}
	reactphysics3d::Vector3 get_listener_direction(unsigned int index) const override { return engine ? ma_vec3_to_rp_vec3(ma_engine_listener_get_direction(&*engine, index)) : reactphysics3d::Vector3(); }
	void set_listener_velocity(unsigned int index, float x, float y, float z) override {
		if (engine)
			ma_engine_listener_set_velocity(&*engine, index, x, y, z);
	}
	void set_listener_velocity_vector(unsigned int index, const reactphysics3d::Vector3 &velocity) override {
		if (engine)
			ma_engine_listener_set_velocity(&*engine, index, velocity.x, velocity.y, velocity.z);
	}
	reactphysics3d::Vector3 get_listener_velocity(unsigned int index) const override { return engine ? ma_vec3_to_rp_vec3(ma_engine_listener_get_velocity(&*engine, index)) : reactphysics3d::Vector3(); }
	void set_listener_cone(unsigned int index, float inner_radians, float outer_radians, float outer_gain) override {
		if (engine)
			ma_engine_listener_set_cone(&*engine, index, inner_radians, outer_radians, outer_gain);
	}
	void get_listener_cone(unsigned int index, float *inner_radians, float *outer_radians, float *outer_gain) const override {
		if (engine)
			ma_engine_listener_get_cone(&*engine, index, inner_radians, outer_radians, outer_gain);
	}
	void set_listener_world_up(unsigned int index, float x, float y, float z) override {
		if (engine)
			ma_engine_listener_set_world_up(&*engine, index, x, y, z);
	}
	void set_listener_world_up_vector(unsigned int index, const reactphysics3d::Vector3 &world_up) override {
		if (engine)
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
		snd->set_autoclose();
		return snd;
	}
	mixer *new_mixer() override { return ::new_mixer(this); }
	sound *new_sound() override {
		sound *s = ::new_sound(this);
		if (s && g_audio_mixer && this == g_audio_engine) s->set_mixer(g_audio_mixer); // The default engine's sounds go on sound_default_mixer, as those of sound() do; play() moves them to a mixer it is given.
		return s;
	}
};
class audio_data_source_impl;
audio_data_source* audio_data_source_get(ma_data_source* ptr, audio_engine* engine);
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
			if (node) { std::lock_guard<std::recursive_mutex> graph_lock(g_node_graph_mutex); ma_data_source_node_uninit(&*src, nullptr); }
			node = nullptr;
			// Uninitializing the node took it off the graph, so what it was attached to is no longer held either; a node made for a source opened later starts unattached.
			for (audio_node *&n : output_connections) {
				if (n) n->release();
				n = nullptr;
			}
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
	// The graph's audio thread reads the source once its node is attached, so not while a sound, chain or head reads it, nor a sound's own source.
	bool attach_output_bus(unsigned int output_bus, audio_node *destination, unsigned int destination_input_bus) override {
		if (in_use(false)) return false;
		return audio_node_impl::attach_output_bus(output_bus, destination, destination_input_bus);
	}
	ma_data_source* get_ma_data_source() const override { return src? src->pDataSource : nullptr; }
	unsigned int get_advised_read_frame_count() const override { return SOUNDSYSTEM_FRAMESIZE; }
	// Reads 32-bit float samples into buffer, as read_script() makes them.
	unsigned long long read(void* buffer, unsigned long long frame_count) override {
		std::lock_guard<std::recursive_mutex> guard(source_mutex);
		if (!src || in_use(false) || node && !detach_all_output_buses()) return 0; // A source in another format was never made a node.
		if (!frame_count) frame_count = get_advised_read_frame_count();
		if (!frame_count) return 0;
		ma_format format = ma_format_f32;
		ma_uint32 channels = 0;
		ma_data_source_get_data_format(src->pDataSource, &format, &channels, nullptr, nullptr, 0);
		ma_uint64 frames_read = 0;
		if (format == ma_format_f32) {
			if ((g_soundsystem_last_error = ma_data_source_read_pcm_frames(src->pDataSource, buffer, frame_count, &frames_read)) != MA_SUCCESS) return 0;
			return frames_read;
		}
		// Another format, such as a 16-bit file the resource manager keeps as it is, is read as it is and converted.
		std::vector<char> raw(frame_count * ma_get_bytes_per_frame(format, channels));
		if ((g_soundsystem_last_error = ma_data_source_read_pcm_frames(src->pDataSource, raw.data(), frame_count, &frames_read)) != MA_SUCCESS) return 0;
		ma_pcm_convert(buffer, ma_format_f32, raw.data(), format, frames_read * channels, ma_dither_mode_none);
		return frames_read;
	}
	CScriptArray* read_script(unsigned long long frame_count) override {
		std::lock_guard<std::recursive_mutex> guard(source_mutex);
		if (!frame_count) frame_count = get_advised_read_frame_count();
		unsigned int channels = get_channels();
		if (channels && frame_count > 0xFFFFFFFF / channels) throw runtime_error("too many frames requested");
		CScriptArray* array = CScriptArray::Create(get_array_type("array<float>"), frame_count * channels);
		asIScriptContext* ctx = asGetActiveContext();
		if (ctx && ctx->GetState() == asEXECUTION_EXCEPTION) {
			array->Release();
			return nullptr;
		}
		if (!frame_count) return array;
		unsigned long long frames_read = read(array->GetBuffer(), frame_count);
		array->Resize(frames_read * get_channels());
		return array;
	}
	unsigned long long skip_frames(unsigned long long frame_count) override {
		ma_uint64 frames_skipped;
		if (!src || in_use()) return 0;
		if ((g_soundsystem_last_error = ma_data_source_seek_pcm_frames(src->pDataSource, frame_count, &frames_skipped)) != MA_SUCCESS) return 0;
		return frames_skipped;
	}
	float skip_milliseconds(float ms) override {
		float skipped;
		if (!src || in_use()) return 0;
		if ((g_soundsystem_last_error = ma_data_source_seek_seconds(src->pDataSource, ms / 1000, &skipped)) != MA_SUCCESS) return 0;
		return skipped * 1000;
	}
	bool seek_frames(unsigned long long frame_index) override { return src && !in_use()? (g_soundsystem_last_error = ma_data_source_seek_to_pcm_frame(src->pDataSource, frame_index)) == MA_SUCCESS : false; }
	bool seek_milliseconds(float ms) override { return src && !in_use()? (g_soundsystem_last_error = ma_data_source_seek_to_second(src->pDataSource, ms / 1000)) == MA_SUCCESS : false; }
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
		ma_uint64 length;
		if (!src) return 0;
		return (g_soundsystem_last_error = ma_data_source_get_length_in_pcm_frames(src->pDataSource, &length)) == MA_SUCCESS? length : 0;
	}
	float get_length_milliseconds() const override {
		float length;
		if (!src) return 0;
		return (g_soundsystem_last_error = ma_data_source_get_length_in_seconds(src->pDataSource, &length)) == MA_SUCCESS? length * 1000 : 0;
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
	// A source chained to this one is read into buffers sized for this one's format and channel count, by the audio thread and by read(), and is played at this one's sample rate, so it must match in all three.
	bool can_chain(audio_data_source* other) const {
		ma_data_source *theirs = other->get_ma_data_source();
		ma_format format, their_format;
		ma_uint32 channels, their_channels, sample_rate, their_sample_rate;
		if (!theirs || ma_data_source_get_data_format(src->pDataSource, &format, &channels, &sample_rate, nullptr, 0) != MA_SUCCESS || ma_data_source_get_data_format(theirs, &their_format, &their_channels, &their_sample_rate, nullptr, 0) != MA_SUCCESS) return false;
		return format == their_format && channels == their_channels && sample_rate == their_sample_rate;
	}
	bool set_current(audio_data_source* new_current) override {
		if (!src || in_use()) return false;
		bool self = new_current == static_cast<audio_data_source*>(this); // Back to this head, as a chain is rewound in MiniAudio. Nothing needs holding for that, and a reference to itself would keep this alive and in use for good.
		if (new_current && !self && new_current != src_cur && new_current != src_next && new_current != held_current && (!can_chain(new_current) || is_sound_owned(new_current) || is_used(new_current))) { // A sound frees its own source when it closes, whatever else reads it, and one already read elsewhere would be read from two places.
			g_soundsystem_last_error = MA_INVALID_ARGS;
			return false;
		}
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
		if (new_next && !self && new_next != src_next && new_next != src_cur && new_next != held_current && (!can_chain(new_next) || is_sound_owned(new_next) || is_used(new_next))) {
			g_soundsystem_last_error = MA_INVALID_ARGS;
			return false;
		}
		if ((g_soundsystem_last_error = ma_data_source_set_next(src->pDataSource, new_next? new_next->get_ma_data_source() : nullptr)) != MA_SUCCESS) return false;
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
class audio_ring_buffer_impl : public audio_data_source_impl, public virtual audio_ring_buffer {
	unique_ptr<ma_pcm_rb> rb;
public:
	audio_ring_buffer_impl(unsigned int channels, unsigned int size, audio_engine * e) : audio_data_source_impl(e, nullptr), rb(make_unique<ma_pcm_rb>()) {
		if (ma_pcm_rb_init(ma_format_f32, channels, size, nullptr, nullptr, &*rb) != MA_SUCCESS) throw std::runtime_error("failed to initialize ring buffer");
		ma_pcm_rb_set_sample_rate(&*rb, get_engine()->get_sample_rate()); // Frames are written at the engine's rate, as the microphone records them; MiniAudio leaves it 0.
		set_ma_data_source((ma_data_source*)&*rb);
	}
	~audio_ring_buffer_impl() {
		audio_data_source_impl::reset(); // Qualified: audio_ring_buffer_impl::reset() below overrides a different (ring-buffer-clearing) virtual and would otherwise hide this one.
		if (rb) ma_pcm_rb_uninit(&*rb);
	}
	void reset() override { if (rb) ma_pcm_rb_reset(&*rb); }
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
	unsigned int get_available_read() const override { return rb? ma_pcm_rb_available_read(&*rb) : 0; }
	unsigned int get_available_write() const override { return rb? ma_pcm_rb_available_write(&*rb) : 0; }
	unsigned int get_channels() const override { return rb? ma_pcm_rb_get_channels(&*rb) : 0; }
	unsigned int get_sample_rate() const override { return rb? ma_pcm_rb_get_sample_rate(&*rb) : 0; }
};
audio_ring_buffer* audio_ring_buffer::create(unsigned int channels, unsigned int size, audio_engine* e) { return new audio_ring_buffer_impl(channels, size, e); }
class audio_decoder_impl : public audio_data_source_impl, public virtual audio_decoder {
	unique_ptr<ma_decoder> decoder;
	datastream* datastream_ref; // If the user opens a datastream, we must maintain a reference to it encase the user drops their handle.
	// Rewind window so a datastream that can't seek (a live socket) can still be probed and decoded; answers rewinds from memory instead of the stream until the window outgrows CAP or a real seek moves the stream.
	struct stream_cursor {
		static const size_t CAP = 256 * 1024;
		datastream* ds = nullptr;
		std::string window;      // every byte served so far, until CAP
		size_t pos = 0;          // logical read position, which is where the decoder believes it is
		bool window_full = false;   // hit CAP, so it no longer holds everything read
		bool window_moved = false;  // a real seek happened, so it no longer starts at byte 0
		bool mirrors_stream() const { return !window_full && !window_moved; }
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
		// Only answer from the window while it still mirrors the stream, otherwise a rewind to 0 after a real seek would wrongly report success without moving the stream.
		if (sc->mirrors_stream() && target >= 0 && static_cast<size_t>(target) <= sc->window.size()) {
			sc->pos = static_cast<size_t>(target); // inside the window, so no real seek is needed
			return MA_SUCCESS;
		}
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
		stream->clear();
		stream->seekg(offset, dir);
		if (stream->fail()) {
			stream->clear(); // genuinely unseekable and outside what was kept; say so instead of claiming a seek that didn't happen
			return MA_NOT_IMPLEMENTED;
		}
		// The stream really moved, so the window no longer describes where the decoder is; from here the stream answers for itself. It can never mirror again, so free it rather than just clearing it.
		sc->pos = static_cast<size_t>(stream->tellg());
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
	virtual bool open(const std::string& filename, const pack_interface* pack_file, unsigned int sample_rate, unsigned int channels) override {
		std::lock_guard<std::recursive_mutex> guard(source_mutex);
		if (decoder && !close()) return false;
		ma_decoder_config cfg = decoder_config_init(sample_rate, channels);
		std::string triplet = g_sound_service->prepare_triplet(filename, pack_file && pack_file->get_is_active()? g_pack_protocol_slot : sound_service::fs_protocol_slot, pack_file && pack_file->get_is_active()? std::shared_ptr < const pack_interface > (pack_file->make_immutable()) : nullptr, 0, nullptr); // Without a pack, from disk, as sound.load() reads, rather than from the default protocol, which can be a pack.
		if ((g_soundsystem_last_error = ma_decoder_init_vfs(g_sound_service->get_vfs(), triplet.c_str(), &cfg, &*decoder)) != MA_SUCCESS) decoder.reset();
		else set_ma_data_source((ma_data_source*)&*decoder);
		g_sound_service->cleanup_triplet(triplet);
		return g_soundsystem_last_error == MA_SUCCESS;
	}
	virtual bool open_stream(datastream* ds, unsigned int sample_rate = 0, unsigned int channels = 0) override {
		std::lock_guard<std::recursive_mutex> guard(source_mutex);
		if (!ds || !ds->get_istr() || decoder && !close()) {
			if (ds) ds->release();
			return false;
		}
		ma_decoder_config cfg = decoder_config_init(sample_rate, channels);
		cursor = make_unique<stream_cursor>();
		cursor->ds = ds;
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
		if (!decoder) return false;
		if (datastream_ref) {
			datastream_ref->release();
			datastream_ref = nullptr;
		}
		if ((g_soundsystem_last_error = ma_decoder_uninit(&*decoder)) != MA_SUCCESS) return false;
		decoder.reset();
		// Both after uninit, since the callbacks read through them.
		ds_vfs.reset();
		cursor.reset();
		return true;
	}
	virtual unsigned int get_sample_rate() const override { return decoder? decoder->outputSampleRate : 0; }
	virtual unsigned int get_channels() const override { return decoder? decoder->outputChannels : 0; }
};
audio_decoder* audio_decoder::create(audio_engine* e) { return new audio_decoder_impl(e); }
class audio_encoder_impl : public effect_node_impl, public virtual audio_encoder {
	unique_ptr<ma_data_converter> dc;
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
			write_impl(buffer.data(), frame_count_out);
		}
	}
protected:
	mutex write_mtx; // Taken by everything that uses the encoder, which the audio thread writes to through process() when the encoder is in the graph.
	datastream* output_stream; // Child classes need not manage the stream's refcount.
	datastream* pull_stream; // Convenience feature which queues newly encoded data to be pulled by the user in a threadsafe manner.
	bool streamable_pulling; // If true read can be called any time in pull mode, otherwise only once after stream is closed.
	virtual bool open_impl(const string& filename, datastream* ds, unsigned int sample_rate, unsigned int channels, unsigned int flags) { return false; } // Override in subclasses to initialize encoder state, one of either ds or filename will be set.
	virtual unsigned int write_impl(const void* buffer, unsigned int size) { return 0; } // Override in subclasses, send given buffer to encoder.
	virtual bool close_impl() { return true; } // override in subclasses, free any encoder state.
	bool postsetup(unsigned int target_sample_rate, unsigned int target_channels, ma_format target_format = ma_format_f32) {
		// Encoder subclasses should usually return from open overrides by calling this funcction.
		if (get_active()) return false;
		sample_rate = target_sample_rate;
		channels = target_channels;
		if (!dc && (target_format != ma_format_f32 || sample_rate != get_engine()->get_sample_rate() || channels != get_engine()->get_channels())) {
			dc = make_unique<ma_data_converter>();
			ma_data_converter_config cfg = ma_data_converter_config_init(ma_format_f32, target_format, get_engine()->get_channels(), target_channels, get_engine()->get_sample_rate(), target_sample_rate);
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
	ma_data_converter* get_dc() const { return &*dc; }
public:
	audio_encoder_impl(audio_engine* e, bool streamable_pulling = true) : effect_node_impl(e, 0, 0, 1, 1, MA_NODE_FLAG_PASSTHROUGH), output_stream(nullptr), pull_stream(nullptr), streamable_pulling(streamable_pulling), sample_rate(0), channels(0), frames_written(0) {}
	~audio_encoder_impl() {
		destroy_node(); // Off the graph before anything process() uses goes; the subclasses' destructors do so first.
		close();
		if (pull_stream) pull_stream->release();
	}
	unsigned int get_default_open_flags() const override { return ENCODER_OVERWRITE; }
	bool open_file(const string& filename, unsigned int sample_rate, unsigned int channels, unsigned int flags) override {
		if (get_active()) close();
		unique_lock<mutex> lock(write_mtx);
		if (flags & ENCODER_DEFAULTS) flags = (flags & ~ENCODER_DEFAULTS) | get_default_open_flags();
		if (!(flags & ENCODER_OVERWRITE) && FileExists(filename)) { // The encoders would replace it.
			g_soundsystem_last_error = MA_ALREADY_EXISTS;
			return false;
		}
		return open_impl(filename, nullptr, sample_rate, channels, flags); // The encoders create the file anew, replacing one there, once their arguments check out; deleting it first lost it to an open that then failed.
	}
	bool open_stream(datastream* ds, unsigned int sample_rate, unsigned int channels, unsigned int flags) override {
		if (!ds) return false;
		if (get_active()) close();
		unique_lock<mutex> lock(write_mtx);
		if (flags & ENCODER_DEFAULTS) flags = (flags & ~ENCODER_DEFAULTS) | get_default_open_flags();
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
			unsigned int frames = write_impl(frames_in, frame_count);
			frames_written += frames;
			return frames;
		}
		unsigned int dc_bufsize = 1024; // frames
		vector<char> dc_buffer(dc_bufsize * ma_get_bytes_per_frame(dc->formatOut, dc->channelsOut));
		ma_uint64 total_processed = 0;
		while (total_processed < frame_count) {
			ma_uint64 frame_count_in = frame_count - total_processed, frame_count_out = dc_bufsize;
			if (ma_data_converter_process_pcm_frames(&*dc, ma_offset_pcm_frames_ptr_f32((float*)frames_in, total_processed, dc->channelsIn), &frame_count_in, &dc_buffer[0], &frame_count_out) != MA_SUCCESS) break;
			if (!frame_count_in && !frame_count_out) break;
			if (frame_count_out && write_impl(dc_buffer.data(), frame_count_out) < frame_count_out) break; // The encoder failed; these frames didn't make it.
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
	} output;
	static ma_result stream_write(ma_encoder *pEncoder, const void *pBufferIn, size_t bytesToWrite, size_t *pBytesWritten) {
		stream_output *out = static_cast<stream_output *>(pEncoder->pUserData);
		std::ostream *stream = out->ds? out->ds->get_ostr() : nullptr;
		*pBytesWritten = 0;
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
		if (!stream) return MA_ERROR;
		stream->seekp(out->base + offset);
		return stream->good()? MA_SUCCESS : MA_ERROR;
	}
protected:
	bool open_impl(const string& filename, datastream* ds, unsigned int sample_rate, unsigned int channels, unsigned int flags) override {
		ma_format target_format;
		if (flags & WAV_S16) target_format = ma_format_s16;
		else if (flags & WAV_S24) target_format = ma_format_s24;
		else if (flags & WAV_U8) target_format = ma_format_u8;
		else if (flags & WAV_S32) target_format = ma_format_s32;
		else if (flags & WAV_F32) target_format = ma_format_f32;
		else throw runtime_error("pcm format not given");
		encoder = make_unique<ma_encoder>();
		ma_encoder_config cfg = ma_encoder_config_init(ma_encoding_format_wav, target_format, channels, sample_rate);
		if (ds && ds->can_write()) {
			output.ds = ds;
			std::streampos start = ds->get_ostr()->tellp();
			output.base = start == std::streampos(-1)? 0 : std::streamoff(start);
			g_soundsystem_last_error = ma_encoder_init(stream_write, stream_seek, &output, &cfg, &*encoder);
		}
		else if (!filename.empty()) g_soundsystem_last_error = ma_encoder_init_file(filename.c_str(), &cfg, &*encoder);
		else throw runtime_error("no encoding output source provided");
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
	string get_format() const override { return "wav"; }
	ma_format get_wav_format() const override { return get_dc()? get_dc()->formatOut : ma_format_f32; }
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
	bool open_impl(const string& filename, datastream* ds, unsigned int sample_rate, unsigned int channels, unsigned int flags) override {
		int error;
		comments = ope_comments_create();
		if (!comments) return false;
		if (ds && ds->can_write()) {
			OpusEncCallbacks callbacks = {write_callback, close_callback};
			encoder = ope_encoder_create_callbacks(&callbacks, ds, comments, sample_rate, channels, 0, &error);
		} else if (!filename.empty()) encoder = ope_encoder_create_file(filename.c_str(), comments, sample_rate, channels, 0, &error);
		if (!encoder) {
			// close_impl() only runs its cleanup for an open encoder, so the comments made above would never be freed.
			ope_comments_destroy(comments);
			comments = nullptr;
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
class mixer_impl : public audio_node_impl, public virtual mixer {
	friend class audio_node_impl;
	// In miniaudio, a sound_group is really just a sound. A typical ma_sound_group_x function looks like float ma_sound_group_get_pan(const ma_sound_group* pGroup) { return ma_sound_get_pan(pGroup); }.
	// Furthermore ma_sound_group is just a typedef for ma_sound. As such, for the sake of less code and better inheritance, we will directly call the ma_sound APIs in this class even though it deals with sound groups and not sounds.
protected:
	unique_ptr<ma_sound> snd;
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
		snd = make_unique<ma_sound>();
		{ std::lock_guard<std::recursive_mutex> graph_lock(g_node_graph_mutex); ma_sound_group_init(e->get_ma_engine(), 0, nullptr, &*snd); } // with no parent group miniaudio attaches the new group to the endpoint here, editing the same input list as every concurrent attach/detach
		node = (ma_node_base *)&*snd;
		set_max_distance(70);
		ma_sound_group_set_rolloff(&*snd, 0); // Our own spatializer controls attenuation.
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
			spatializer = audio_spatializer::create(const_cast<mixer_impl*>(this), get_engine());
			node_chain->add_node(spatializer);
		}
		return spatializer;
	}
	inline void duplicate() override { audio_node_impl::duplicate(); }
	inline void release() override { audio_node_impl::release(); }
	bool set_mixer(mixer *mix) override {
		if (mix == parent_mixer)
			return false;
		if (mix && mix->get_engine() != get_engine()) return false; // Another engine's mixer is in that engine's graph, which would play this one's sound.
		// Not into itself, nor into a mixer that already goes into this one: that loop never reaches the engine, and its references to each other keep both alive.
		for (mixer *above = mix; above; above = above->get_mixer()) {
			if (above == static_cast<mixer*>(this)) {
				g_soundsystem_last_error = MA_INVALID_ARGS;
				return false;
			}
		}
		audio_node *target = mix? mix : get_engine()->get_endpoint();
		node_chain->set_endpoint(target);
		if (node_chain->get_endpoint() != target) return false; // It couldn't attach, as to a node without an input, which leaves this where it was.
		// Held by this mixer too, not only through the chain, whose endpoint the rewiring above let go of and a script can change through internal_node_chain.
		if (mix) mix->duplicate();
		if (parent_mixer) parent_mixer->release();
		parent_mixer = mix;
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
	splitter_node* get_reverb3d_attachment() const override { return get_spatializer()->get_reverb3d_attachment(); }
	audio_spatializer_reverb3d_placement get_reverb3d_placement() const override { return get_spatializer()->get_reverb3d_placement(); }
	audio_node_chain* get_effects_chain() override {
		if (!effects_chain) {
			effects_chain = audio_node_chain::create(nullptr, nullptr, get_engine());
			node_chain->add_node(effects_chain);
		}
		return effects_chain;
	}
	audio_node_chain* get_internal_node_chain() override { return node_chain; }
	bool get_spatialization_parameters(audio_spatialization_parameters& params) override {
		if (!spatialization_params_mutex.try_lock()) return false;
		// Checked under the lock a sound's loads hand snd over and close() lets go of the spatializer under; without a spatializer there is no rolloff to give, and get_spatializer() would make one, which the audio thread mustn't.
		if (!snd || !spatializer || !get_spatialization_enabled()) {
			spatialization_params_mutex.unlock();
			return false;
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
		params.distance_model = linear;
		spatialization_params_mutex.unlock();
		return true;
	}
	bool fade_from_stop = false; // The fade is one a stop with a fade set, as pause_fade() does, rather than one the script set since.
	// Decibels to the linear volumes MiniAudio fades between, on an engine with PERCENTAGE_ATTRIBUTES; FLT_MAX starts from the current volume.
	void fade_volumes_to_linear(float &start_volume, float &end_volume) const {
		if (!(get_engine()->get_flags() & audio_engine::PERCENTAGE_ATTRIBUTES)) return;
		start_volume = start_volume == FLT_MAX ? -1 : ma_volume_db_to_linear(start_volume);
		end_volume = ma_volume_db_to_linear(end_volume);
	}
	// MiniAudio keeps a sound or group stopped once its scheduled stop has come, and its fade where the stop left it, until both are cleared, so starting it clears them then. With pending, a stop still to come is cleared too, as one pause_fade() scheduled. The fade is cleared only when that stop set it, so a fade the script set since, such as one to fade back in, is kept.
	void clear_stop_for_restart(bool pending = false) {
		ma_uint64 stop_time = ma_node_get_state_time(&*snd, ma_node_state_stopped);
		if (stop_time == ~(ma_uint64)0) return;
		if (!pending && stop_time > ma_engine_get_time_in_pcm_frames(ma_sound_get_engine(&*snd))) return;
		ma_sound_reset_stop_time(&*snd);
		if (fade_from_stop) ma_sound_reset_fade(&*snd);
		fade_from_stop = false;
	}
	bool play(bool reset_loop_state = true) override {
		if (snd == nullptr)
			return false;
		if (reset_loop_state)
			ma_sound_set_looping(&*snd, MA_FALSE);
		clear_stop_for_restart();
		return (g_soundsystem_last_error = ma_sound_start(&*snd)) == MA_SUCCESS;
	}
	bool play_looped() override {
		if (snd == nullptr)
			return false;
		ma_sound_set_looping(&*snd, true);
		clear_stop_for_restart();
		return (g_soundsystem_last_error = ma_sound_start(&*snd)) == MA_SUCCESS;
	}
	ma_sound *get_ma_sound() const override { return &*snd; }
	audio_engine *get_engine() const override { return engine; }
	bool stop() override { return snd ? (g_soundsystem_last_error = ma_sound_stop(&*snd)) == MA_SUCCESS : false; }
	void set_volume(float volume) override {
		if (snd)
			ma_sound_set_volume(&*snd, get_engine()->get_flags() & audio_engine::PERCENTAGE_ATTRIBUTES? ma_volume_db_to_linear(volume) : volume);
	}
	float get_volume() const override { return snd ? (get_engine()->get_flags() & audio_engine::PERCENTAGE_ATTRIBUTES ? ma_volume_linear_to_db(ma_sound_get_volume(&*snd)) : ma_sound_get_volume(&*snd)) : NAN; }
	void set_pan(float pan) override {
		if (snd)
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
		if (snd)
			ma_sound_set_pitch(&*snd, get_engine()->get_flags() & audio_engine::PERCENTAGE_ATTRIBUTES ? pitch / 100.0f : pitch);
	}
	float get_pitch() const override {
		return snd ? (get_engine()->get_flags() & audio_engine::PERCENTAGE_ATTRIBUTES ? ma_sound_get_pitch(&*snd) * 100 : ma_sound_get_pitch(&*snd)) : NAN;
	}
	void set_spatialization_enabled(bool enabled) override {
		if (snd)
			ma_sound_set_spatialization_enabled(&*snd, enabled);
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
		const auto dir = ma_sound_get_direction_to_listener(&*snd);
		reactphysics3d::Vector3 res;
		res.setAllValues(dir.x, dir.y, dir.z);
		return res;
	}
	float get_distance_to_listener() const override { return snd && get_spatialization_enabled()? ma_sound_get_distance_to_listener(&*snd) : 0.0; }
	void set_position_3d(float x, float y, float z) override {
		if (!snd)
			return;
		set_spatialization_enabled(true);
		if (sound_get_default_3d_panner() >= 0 && get_preferred_3d_panner() < 0) set_3d_panner(sound_get_default_3d_panner());
		if (sound_get_default_3d_attenuator() >= 0 && get_preferred_3d_attenuator() < 0) set_3d_attenuator(sound_get_default_3d_attenuator());
		unique_lock<mutex> lock(spatialization_params_mutex); // Which a listener's move places a shaped sound under.
		if (shape) {
			shape_anchor = reactphysics3d::Vector3(x, y, z);
			place_in_shape_locked();
		} else ma_sound_set_position(&*snd, x, y, z);
	}
	// Under spatialization_params_mutex, with snd and shape set: plays the sound from the shape's point nearest the listener, or from the listener within the shape.
	void place_in_shape_locked() {
		reactphysics3d::Vector3 pos = shape_anchor, listener = get_engine()->get_listener_position(get_listener());
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
		if (!snd)
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
		if (!snd)
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
		if (snd)
			ma_sound_set_positioning(&*snd, positioning);
	}
	ma_positioning get_positioning() const override {
		return snd ? ma_sound_get_positioning(&*snd) : ma_positioning_absolute;
	}
	void set_rolloff(float rolloff) override { get_spatializer()->set_rolloff(rolloff); }
	float get_rolloff() const override { return get_spatializer()->get_rolloff(); }
	void set_min_gain(float gain) override {
		if (snd)
			ma_sound_set_min_gain(&*snd, gain);
	}
	float get_min_gain() const override {
		return snd ? ma_sound_get_min_gain(&*snd) : NAN;
	}
	void set_max_gain(float gain) override {
		if (snd)
			ma_sound_set_max_gain(&*snd, gain);
	}
	float get_max_gain() const override {
		return snd ? ma_sound_get_max_gain(&*snd) : NAN;
	}
	void set_min_distance(float distance) override {
		if (snd)
			ma_sound_set_min_distance(&*snd, distance);
	}
	float get_min_distance() const override {
		return snd ? ma_sound_get_min_distance(&*snd) : NAN;
	}
	void set_max_distance(float distance) override {
		if (snd)
			ma_sound_set_max_distance(&*snd, distance);
	}
	float get_max_distance() const override {
		return snd ? ma_sound_get_max_distance(&*snd) : NAN;
	}
	void set_cone(float inner_radians, float outer_radians, float outer_gain) override {
		if (snd)
			ma_sound_set_cone(&*snd, inner_radians, outer_radians, outer_gain);
	}
	void get_cone(float *inner_radians, float *outer_radians, float *outer_gain) const override {
		if (snd)
			ma_sound_get_cone(&*snd, inner_radians, outer_radians, outer_gain);
		else {
			if (inner_radians)
				*inner_radians = NAN;
			if (outer_radians)
				*outer_radians = NAN;
			if (outer_gain)
				*outer_gain = NAN;
		}
	}
	void set_doppler_factor(float factor) override {
		if (snd)
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
		fade_from_stop = false;
		ma_sound_set_fade_in_pcm_frames(&*snd, start_volume, end_volume, frames);
	}
	void set_fade_in_milliseconds(float start_volume, float end_volume, ma_uint64 milliseconds) override {
		if (!snd)
			return;
		fade_volumes_to_linear(start_volume, end_volume);
		fade_from_stop = false;
		ma_sound_set_fade_in_milliseconds(&*snd, start_volume, end_volume, milliseconds);
	}
	float get_current_fade_volume() const override {
		return snd ? (get_engine()->get_flags() & audio_engine::PERCENTAGE_ATTRIBUTES ? ma_volume_linear_to_db(ma_sound_get_current_fade_volume(&*snd)) : ma_sound_get_current_fade_volume(&*snd)) : NAN;
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
		if (snd)
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
	void set_stop_time_in_frames(ma_uint64 absolute_time) override {
		if (snd)
			ma_sound_set_stop_time_in_pcm_frames(&*snd, absolute_time);
	}
	void set_stop_time_in_milliseconds(ma_uint64 absolute_time) override {
		if (snd)
			ma_sound_set_stop_time_in_milliseconds(&*snd, absolute_time);
	}
	ma_uint64 get_time() const override {
		return snd ? ((get_engine()->get_flags() & audio_engine::DURATIONS_IN_FRAMES) ? get_time_in_frames() : get_time_in_milliseconds()) : 0;
	}
	// In the unit get_time() reads, milliseconds unless the engine counts durations in frames.
	bool set_time(unsigned long long time) override {
		if (!snd) return false;
		if (!(get_engine()->get_flags() & audio_engine::DURATIONS_IN_FRAMES)) time = time * ma_engine_get_sample_rate(ma_sound_get_engine(&*snd)) / 1000;
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
	// Each job takes a number from the counter when posted and advances the pointer when it is done, so they match once none is left.
	static void wait_for_jobs(const ma_uint32 *counter, const ma_uint32 *pointer) {
		while (load_job_field(pointer) != load_job_field(counter)) std::this_thread::yield();
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
			ma_resource_manager_data_source_uninit(&*src);
		}
		src.reset();
	}
	std::string pcm_buffer;      // When loading from raw PCM (like TTS) we store the intermediate wav data here so we can take advantage of async loading to return quickly. Makes a substantial difference in the responsiveness of TTS calls.
	std::string loaded_filename; // Contains the loaded filename as passed in the load/stream method, used just for convenience.
	mutable std::atomic_flag load_completed;
	unique_ptr<ma_pcm_rb> pcm_stream;
	bool paused;
	bool fade_paused = false; // Paused by pause_fade(), whose stop is still scheduled, unlike one the script scheduled itself.
	bool should_autoclose; // If this is true, the release method defers sound destruction until playback has complete.
	mutable audio_data_source* datasource; // Avoid the need to keep looking up the pointer to the c++ ma_data_source wrapper associated with this sound.
	bool datasource_opened = false; // datasource is one open() was given and plays, rather than a wrapper of the sound's own source.
	void adopt_sound(unique_ptr<ma_sound> made) {
		unique_lock<mutex> lock(spatialization_params_mutex);
		snd = std::move(made);
	}
	inline void postload(const string& filename, bool async_load = false) {
		loaded_filename = filename;
		node = (ma_node_base *)&*snd;
		set_spatialization_enabled(false);                  // The user must call set_position_3d or manually enable spatialization or else their ambience and UI sounds will be spatialized.
		set_max_distance(70);
		ma_sound_set_rolloff(&*snd, 0);
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
			if (!should_autoclose || !get_playing()) delete this;
			else {
				should_autoclose = false;
				duplicate();
				unique_lock<mutex> lock(g_inlined_sounds_mutex);
				g_inlined_sounds.insert(this); // Freed with garbage_collect_inline_sounds();
			}
		}
	}
	bool load_special(const std::string &filename, const size_t protocol_slot = 0, directive_t protocol_directive = nullptr, const size_t filter_slot = 0, directive_t filter_directive = nullptr, ma_uint32 ma_flags = MA_SOUND_FLAG_DECODE) override {
		garbage_collect_inline_sounds();
		if (snd)
			close();
		// Made here and handed to snd only once it loaded, under the lock the audio thread reads snd under, so the audio thread never reads a sound half made or freed after a failed load.
		unique_ptr<ma_sound> made = make_unique<ma_sound>();
		// The sound service converts our file name into a "tripplet" which includes information about the origin an asset is expected to come from. This guarantees that we don't mistake assets from different origins as the same just because they have the same name.
		std::string triplet = g_sound_service->prepare_triplet(filename, protocol_slot, protocol_directive, filter_slot, filter_directive);
		if (triplet.empty()) { // A name the sound service can't make one of, such as one that isn't valid UTF-8.
			g_soundsystem_last_error = MA_INVALID_ARGS;
			return false;
		}
		// A buffer MiniAudio would load synchronously, as for load_memory(), is loaded asynchronously and waited for: see g_resource_tree_mutex.
		bool wait_for_load = !(ma_flags & (MA_SOUND_FLAG_ASYNC | MA_SOUND_FLAG_STREAM));
		ma_uint32 flags = ma_flags | (wait_for_load? MA_SOUND_FLAG_ASYNC : 0);
		unique_ptr<ma_resource_manager_data_source> made_source;
		bool tree_held = false; // The retry below holds g_resource_tree_mutex around its attempt.
		// Each attempt gets its own load state, so one a failed attempt left with MiniAudio can't be mistaken for the next. It makes the source and then the sound from it, as ma_sound_init_ex() would from the file's name, but keeps the source: see source.
		auto attempt_init = [&]() {
			async_load_state *state = (flags & MA_SOUND_FLAG_ASYNC)? new async_load_state(this) : nullptr;
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
				cfg.pDataSource = &*made_source;
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
				// See above; this is probably job queue backlog rather than an actual out of memory. Take a break and try again.
				wait(5);
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

		if (g_soundsystem_last_error == MA_SUCCESS) {
			source = std::move(made_source);
			adopt_sound(std::move(made));
			postload(filename, (flags & MA_SOUND_FLAG_ASYNC) && !wait_for_load);
		}
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
	bool load_pcm_script_array(CScriptArray *buffer, int samplerate, int channels) override {
		if (!buffer)
			return false;
		ma_format format = ma_format_from_angelscript_type(buffer->GetElementTypeId());
		if (format == ma_format_unknown) return false;
		return load_pcm(buffer->GetBuffer(), buffer->GetSize() * buffer->GetElementSize(), format, samplerate, channels);
	}
	bool load_pcm_script_memory_buffer(script_memory_buffer* buffer, int samplerate, int channels) override {
		if (!buffer)
			return false;
		ma_format format = ma_format_from_angelscript_type(buffer->subtypeid);
		if (format == ma_format_unknown) return false;
		return load_pcm(buffer->ptr, buffer->size * buffer->get_element_size(), format, samplerate, channels);
	}
	bool stream_pcm(const void* data, unsigned int size_in_frames, ma_format format, unsigned int sample_rate, unsigned int channels, unsigned int buffer_size) override {
		if (format != ma_format_unknown) {
			if (snd) close();
			if (!buffer_size) buffer_size = size_in_frames * 2;
			if (!buffer_size) return false;
			if (!channels) channels = get_engine()->get_channels();
			if (!sample_rate) sample_rate = get_engine()->get_sample_rate();
			pcm_stream = make_unique<ma_pcm_rb>();
			if ((g_soundsystem_last_error = ma_pcm_rb_init(format, channels, buffer_size, nullptr, nullptr, &*pcm_stream)) != MA_SUCCESS) {
				pcm_stream.reset();
				return false;
			}
			ma_pcm_rb_set_sample_rate(&*pcm_stream, sample_rate);
			// As load_special() makes a sound: not attached by MiniAudio, so without the graph lock, and handed to snd once made.
			unique_ptr<ma_sound> made = make_unique<ma_sound>();
			if ((g_soundsystem_last_error = ma_sound_init_from_data_source(get_engine()->get_ma_engine(), &*pcm_stream, MA_SOUND_FLAG_NO_DEFAULT_ATTACHMENT, nullptr, &*made)) != MA_SUCCESS) {
				ma_pcm_rb_uninit(&*pcm_stream);
				pcm_stream.reset();
				return false;
			}
			adopt_sound(std::move(made));
			postload(":pcm", false);
			play(true);
		}
		if (!pcm_stream) return false;
		const char* input = (const char*)data;
		unsigned int frames_written = 0;
		unsigned int frame_size = ma_get_bytes_per_frame(ma_pcm_rb_get_format(&*pcm_stream), ma_pcm_rb_get_channels(&*pcm_stream));
		// A full buffer is waited on while the sound plays it out; when nothing has made room for a second, as when the sound was stopped or its engine is never read, the rest is given up rather than waited on forever.
		std::chrono::steady_clock::time_point waiting_since;
		bool waiting = false;
		while (size_in_frames) {
			void* buffer_ptr = nullptr;
			unsigned int frames_requested = size_in_frames;
			if ((g_soundsystem_last_error = ma_pcm_rb_acquire_write(&*pcm_stream, &frames_requested, &buffer_ptr)) != MA_SUCCESS || !buffer_ptr) return false;
			if (!frames_requested) {
				ma_pcm_rb_commit_write(&*pcm_stream, 0);
				if (!waiting) {
					waiting = true;
					waiting_since = std::chrono::steady_clock::now();
				} else if (std::chrono::steady_clock::now() - waiting_since >= std::chrono::seconds(1)) return false;
				std::this_thread::sleep_for(std::chrono::milliseconds(1));
				continue;
			}
			waiting = false;
			memcpy(buffer_ptr, input + (frames_written * frame_size), frames_requested * frame_size);
			if ((g_soundsystem_last_error = ma_pcm_rb_commit_write(&*pcm_stream, frames_requested)) != MA_SUCCESS) return false;
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
			if (format != ma_pcm_rb_get_format(&*pcm_stream)) return false;
			format = ma_format_unknown;
		}
		int nchannels = pcm_stream? ma_pcm_rb_get_channels(&*pcm_stream) : channels? channels : get_engine()->get_channels();
		return stream_pcm(buffer->GetBuffer(), buffer->GetSize() / nchannels, format, sample_rate, channels, buffer_size);
	}
	bool stream_pcm_script_memory_buffer(script_memory_buffer* buffer, unsigned int sample_rate, unsigned int channels, unsigned int buffer_size) override {
		if (!buffer)
			return false;
		ma_format format = ma_format_from_angelscript_type(buffer->subtypeid);
		if (pcm_stream) {
			if (format != ma_pcm_rb_get_format(&*pcm_stream)) return false;
			format = ma_format_unknown;
		}
		int nchannels = pcm_stream? ma_pcm_rb_get_channels(&*pcm_stream) : channels? channels : get_engine()->get_channels();
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
		unique_ptr<ma_sound> made = make_unique<ma_sound>(); // As load_special() makes a sound.
		if ((g_soundsystem_last_error = ma_sound_init_from_data_source(get_engine()->get_ma_engine(), ds->get_ma_data_source(), MA_SOUND_FLAG_NO_DEFAULT_ATTACHMENT, nullptr, &*made)) != MA_SUCCESS) {
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
	bool close() override {
		// It's possible that this sound could still be loading in a job thread when we try to destroy it. Unfortunately there isn't a way to cancel this, so we have to just wait.
		if (load_state) {
			{
				std::unique_lock<std::mutex> lock(load_state->mtx);
				load_state->cv.wait(lock, [this]() { return load_state->done; });
			}
			load_state->abandon();
			load_state = nullptr;
		}
		if (!snd) return false;
		if (spatializer) {
			// Not under this sound's lock, which no chain's lock is taken inside: forgetting the mixer takes the spatializer's, and taking it out of the chain rewires the chains around it, and each of these, like letting go of the spatializer itself, can let go of the last reference to a mixer, such as one a reverb3d made or one the script pointed a chain at. A mixer's destructor takes g_shaped_mixers_mutex, which a listener's move holds while it waits for this sound's lock.
			// The spatializer forgets this sound before the sound lets go of it, so that it stops asking the sound for its parameters first.
			audio_spatializer *forgotten = spatializer;
			forgotten->forget_mixer();
			{
				unique_lock<mutex> lock(spatialization_params_mutex);
				spatializer = nullptr;
			}
			node_chain->remove_node(forgotten);
			forgotten->release();
		}
		// Taken out of snd under the lock a listener's move and the audio thread read snd under, so neither reads the sound while it is freed.
		unique_ptr<ma_sound> closing;
		{
			unique_lock<mutex> lock(spatialization_params_mutex);
			closing = std::move(snd);
		}
		ma_resource_manager_data_buffer *failed_buffer = finish_load_jobs(source.get());
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
		if (source) {
			{
				std::shared_lock<std::shared_mutex> tree_lock(g_resource_tree_mutex, std::defer_lock);
				if (!(source->flags & MA_RESOURCE_MANAGER_DATA_SOURCE_FLAG_STREAM)) tree_lock.lock();
				ma_resource_manager_data_source_uninit(&*source);
			}
			source.reset();
		}
		closing.reset();
		if (datasource) {
			if (datasource_opened) audio_data_source_impl::remove_user(datasource);
			datasource->release();
			datasource = nullptr;
		}
		datasource_opened = false;
		node = nullptr;
		if (pcm_stream) ma_pcm_rb_uninit(&*pcm_stream);
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
			if ((datasource = audio_data_source_get(snd->pDataSource, get_engine())) == nullptr) return nullptr;
			if (auto impl = dynamic_cast<audio_data_source_impl*>(datasource)) impl->mark_sound_owned();
		}
		return datasource;
	}
	bool get_active() override {
		return snd ? true : false;
	}
	bool get_paused() override {
		return snd ? !ma_sound_is_playing(&*snd) && paused : false;
	}
	bool play(bool reset_loop_state = true) override {
		if (fade_paused && snd) clear_stop_for_restart(true); // A pause_fade() still fading out is called off.
		paused = fade_paused = false;
		if (pcm_stream) ma_pcm_rb_reset(&*pcm_stream);
		return mixer_impl::play(reset_loop_state);
	}
	bool play_looped() override {
		if (pcm_stream) return false;
		if (fade_paused && snd) clear_stop_for_restart(true);
		paused = fade_paused = false;
		return mixer_impl::play_looped();
	}
	bool play_wait() override {
		if (pcm_stream || !play())
			return false;
		while (get_playing())
			wait(5);
		return true;
	}
	bool stop() override {
		if (fade_paused && snd) clear_stop_for_restart(true); // Stopped now, so the pause_fade() stop still to come would stop the sound once it plays again.
		paused = fade_paused = false;
		if (!mixer_impl::stop()) return false;
		return get_length_in_frames() == 0 || seek(0); // A stream without a length, such as PCM or a URL, has no start to go back to.
	}
	bool pause() override {
		if (snd && !pcm_stream) {
			g_soundsystem_last_error = ma_sound_stop(&*snd);
			if (g_soundsystem_last_error == MA_SUCCESS)
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
			g_soundsystem_last_error = ma_sound_stop_with_fade_in_pcm_frames(&*snd, frames);
			if (g_soundsystem_last_error == MA_SUCCESS) paused = fade_paused = fade_from_stop = true; // As pause() does, so play() resumes it.
			return g_soundsystem_last_error == MA_SUCCESS;
		}
		return false;
	}
	bool pause_fade_in_milliseconds(unsigned long long frames) override {
		if (snd) {
			g_soundsystem_last_error = ma_sound_stop_with_fade_in_milliseconds(&*snd, frames);
			if (g_soundsystem_last_error == MA_SUCCESS) paused = fade_paused = fade_from_stop = true;
			return g_soundsystem_last_error == MA_SUCCESS;
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
		fade_from_stop = false;
		ma_sound_set_fade_start_in_pcm_frames(&*snd, start_volume, end_volume, frames, absolute_time_in_frames);
	}
	void set_timed_fade_in_milliseconds(float start_volume, float end_volume, unsigned long long frames, unsigned long long absolute_time_in_frames) override {
		if (!snd) return;
		fade_volumes_to_linear(start_volume, end_volume);
		fade_from_stop = false;
		ma_sound_set_fade_start_in_milliseconds(&*snd, start_volume, end_volume, frames, absolute_time_in_frames);
	}
	void set_stop_time_with_fade(unsigned long long absolute_time, unsigned long long fade_length) override {
		return (get_engine()->get_flags() & audio_engine::DURATIONS_IN_FRAMES) ? set_stop_time_with_fade_in_frames(absolute_time, fade_length) : set_stop_time_with_fade_in_milliseconds(absolute_time, fade_length);
	}
	// A stop the script schedules replaces one pause_fade() scheduled, which play() then keeps.
	void set_stop_time_with_fade_in_frames(unsigned long long absolute_time, unsigned long long fade_length) override {
		if (!snd) return;
		ma_sound_set_stop_time_with_fade_in_pcm_frames(&*snd, absolute_time, fade_length);
		fade_from_stop = true;
		fade_paused = false;
	}
	void set_stop_time_with_fade_in_milliseconds(unsigned long long absolute_time, unsigned long long fade_length) override {
		if (!snd) return;
		ma_sound_set_stop_time_with_fade_in_milliseconds(&*snd, absolute_time, fade_length);
		fade_from_stop = true;
		fade_paused = false;
	}
	// A plain stop replaces a stop with a fade too, so that stop's fade goes with it rather than leaving the sound silent until the new stop.
	void set_stop_time_in_frames(ma_uint64 absolute_time) override {
		mixer_impl::set_stop_time_in_frames(absolute_time);
		forget_stop_fade();
	}
	void set_stop_time_in_milliseconds(ma_uint64 absolute_time) override {
		mixer_impl::set_stop_time_in_milliseconds(absolute_time);
		forget_stop_fade();
	}
	void forget_stop_fade() {
		if (!snd) return;
		if (fade_from_stop) ma_sound_reset_fade(&*snd);
		fade_from_stop = fade_paused = false;
	}
	void set_looping(bool looping) override {
		if (snd)
			ma_sound_set_looping(&*snd, looping);
	}
	bool get_looping() override {
		return snd ? ma_sound_is_looping(&*snd) : false;
	}
	bool get_at_end() override {
		return snd ? ma_sound_at_end(&*snd) : false;
	}
	bool seek(unsigned long long position) override { return get_engine()->get_flags() & audio_engine::DURATIONS_IN_FRAMES? seek_in_frames(position) : seek_in_milliseconds(position); }
	bool seek_in_frames(unsigned long long position) override { return get_length_in_frames() && (g_soundsystem_last_error = ma_sound_seek_to_pcm_frame(&*snd, position)) == MA_SUCCESS; }
	bool seek_in_milliseconds(unsigned long long offset) override {
		ma_uint32 sample_rate = 0; // The sound's own, which its frames count in; the engine's differs for a file at another rate, and is 0 for an engine without a device.
		if (!snd || ma_sound_get_data_format(&*snd, nullptr, nullptr, &sample_rate, nullptr, 0) != MA_SUCCESS || !sample_rate) return false;
		return seek_in_frames((offset * sample_rate) / 1000);
	}
	unsigned long long get_position() override {
		if (!snd) return 0;
		if (get_engine()->get_flags() & audio_engine::DURATIONS_IN_FRAMES)
			return get_position_in_frames();
		else
			return get_position_in_milliseconds();
	}
	unsigned long long get_position_in_frames() override {
		if (snd) {
			ma_uint64 pos = 0;
			g_soundsystem_last_error = ma_sound_get_cursor_in_pcm_frames(&*snd, &pos);
			return g_soundsystem_last_error == MA_SUCCESS ? pos : 0;
		}
		return 0;
	}
	unsigned long long get_position_in_milliseconds() override {
		if (snd) {
			float pos = 0.0f;
			g_soundsystem_last_error = ma_sound_get_cursor_in_seconds(&*snd, &pos);
			return g_soundsystem_last_error == MA_SUCCESS ? pos * 1000.0f : 0;
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
		if (snd) {
			ma_uint64 len;
			g_soundsystem_last_error = ma_sound_get_length_in_pcm_frames(&*snd, &len);
			return g_soundsystem_last_error == MA_SUCCESS ? len : 0;
		}
		return 0;
	}
	unsigned long long get_length_in_milliseconds() override {
		if (snd) {
			float len;
			g_soundsystem_last_error = ma_sound_get_length_in_seconds(&*snd, &len);
			return g_soundsystem_last_error == MA_SUCCESS ? len * 1000.0f : 0;
		}
		return 0;
	}
	bool get_data_format(ma_format *format, unsigned int *channels, unsigned int *sample_rate) override {
		if (format) *format = ma_format_unknown; // As MiniAudio sets them when it fails, for a sound without anything loaded.
		if (channels) *channels = 0;
		if (sample_rate) *sample_rate = 0;
		if (snd) {
			g_soundsystem_last_error = ma_sound_get_data_format(&*snd, format, channels, sample_rate, nullptr, 0);
			return g_soundsystem_last_error == MA_SUCCESS;
		}
		return false;
	}
	// A completely pointless API here, but needed for code that relies on legacy BGT includes. Always returns 0.
	double get_pitch_lower_limit() override {
		return 0;
	}
};

class microphone_impl : public audio_ring_buffer_impl, public virtual microphone {
	unique_ptr<ma_device> capture_device;
	int device_index;
	static void capture_data_callback(ma_device* pDevice, void* pOutput, const void* pInput, ma_uint32 frameCount) {
		microphone_impl* node = (microphone_impl*)pDevice->pUserData;
		if (node && pInput && frameCount > 0) node->write((float*)pInput, frameCount);
	}
public:
	// An index out of range opens the default device, as -1 does, and reads as -1 then.
	microphone_impl(audio_engine* e, int device) : audio_ring_buffer_impl(e->get_channels(), 8192, e), capture_device(make_unique<ma_device>()), device_index(device >= 0 && device < int(g_sound_input_devices.size())? device : -1) {
		ma_device_config device_config = ma_device_config_init(ma_device_type_capture);
		device_config.capture.format = ma_format_f32;
		device_config.capture.channels = e->get_channels();
		device_config.sampleRate = e->get_sample_rate();
		device_config.dataCallback = capture_data_callback;
		device_config.pUserData = this;
		device_config.periodSizeInFrames = SOUNDSYSTEM_FRAMESIZE * 2;
		device_config.capture.pDeviceID = device_index >= 0? &g_sound_input_devices[device_index].id : nullptr;
		if ((g_soundsystem_last_error = ma_device_init(&g_sound_context, &device_config, &*capture_device)) != MA_SUCCESS) throw std::runtime_error("failed to initialize capture device");
		if ((g_soundsystem_last_error = ma_device_start(&*capture_device)) != MA_SUCCESS) audio_node_impl::set_state(ma_node_state_stopped);
	}
	~microphone_impl() {
		if (capture_device) uninit_device(&*capture_device);
	}
	bool set_device(int device) override {
		if (device == device_index && capture_device) return true; // Without a device open, as after one failed to, it is opened anew.
		if (device < -1 || device >= int(g_sound_input_devices.size())) {
			g_soundsystem_last_error = MA_INVALID_ARGS;
			return false;
		}
		if (capture_device) {
			ma_device_stop(&*capture_device);
			uninit_device(&*capture_device);
		}
		ma_device_config device_config = ma_device_config_init(ma_device_type_capture);
		device_config.capture.format = ma_format_f32;
		device_config.capture.channels = get_engine()->get_channels();
		device_config.sampleRate = get_engine()->get_sample_rate();
		device_config.dataCallback = capture_data_callback;
		device_config.pUserData = this;
		device_config.periodSizeInFrames = SOUNDSYSTEM_FRAMESIZE * 2; // As the constructor opens it.
		device_config.capture.pDeviceID = (device >= 0 && device < int(g_sound_input_devices.size())) ? &g_sound_input_devices[device].id : nullptr;
		capture_device = make_unique<ma_device>();
		if ((g_soundsystem_last_error = ma_device_init(&g_sound_context, &device_config, &*capture_device)) != MA_SUCCESS) {
			capture_device.reset();
			return false;
		}
		device_index = device;
		if ((g_soundsystem_last_error = ma_device_start(&*capture_device)) != MA_SUCCESS) {
			audio_node_impl::set_state(ma_node_state_stopped);
			device_index = -1;
			uninit_device(&*capture_device);
			capture_device.reset();
			return false;
		}
		return true;
	}
	int get_device() const override { return device_index; }
	bool set_state(ma_node_state state) override {
		bool ret = audio_node_impl::set_state(state);
		if (!capture_device) return ret;
		if (!ret) return false;
		if (state == ma_node_state_stopped) return ma_device_stop(&*capture_device) == MA_SUCCESS;
		else if (state == ma_node_state_started) {
			this->reset();
			return ma_device_start(&*capture_device) == MA_SUCCESS;
		}
		return false;
	}
	void set_volume(float volume) override { if (capture_device) g_soundsystem_last_error = ma_device_set_master_volume_db(&*capture_device, volume); }
	float get_volume() const override { float result; return capture_device && (g_soundsystem_last_error = ma_device_get_master_volume_db(&*capture_device, &result)) == MA_SUCCESS? result : 0; }
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
	if (s && g_audio_mixer) s->set_mixer(g_audio_mixer); // Refused for a sound_default_mixer of an engine other than the default one, which leaves the sound on the default engine's endpoint.
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
	return engine->play(path, position, volume, pan, pitch, mix? mix : g_audio_mixer, pack_file, autoplay); // Without a mixer of its own, on sound_default_mixer as other new sounds are, unless that mixer is of another engine.
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
	return ma_volume_linear_to_db(ma_engine_get_volume(engine->get_ma_engine()));
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
		engine->RegisterObjectMethod("audio_node", Poco::format("%s@ opCast()", type).c_str(), asFUNCTION((op_cast < audio_node, T >)), asCALL_CDECL_OBJFIRST);
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
	engine->RegisterObjectMethod("microphone", "void set_volume(float volume)", asFUNCTION((virtual_call < microphone, &microphone::set_volume, void, float>)), asCALL_CDECL_OBJFIRST);
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
	engine->RegisterGlobalFunction("const string[]@+ get_sound_input_devices() property", asFUNCTION(get_sound_input_devices), asCALL_CDECL);
	engine->RegisterGlobalFunction("const string[]@+ get_sound_output_devices() property", asFUNCTION(get_sound_output_devices), asCALL_CDECL);
	engine->RegisterGlobalFunction("int get_sound_output_device() property", asFUNCTION(get_sound_output_device), asCALL_CDECL);
	engine->RegisterGlobalProperty("mixer@ sound_default_mixer", (void*)&g_audio_mixer);
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
void nvgt_audio_plugin_node_register(const string& nodename) { RegisterSoundsystemAudioNode<plugin_node>(g_ScriptEngine, nodename); }
plugin_node* nvgt_audio_plugin_node_create(audio_plugin_node_interface* impl, unsigned char input_bus_count, unsigned char output_bus_count, unsigned int flags, audio_engine* engine) { return plugin_node::create(impl, input_bus_count, output_bus_count, flags, engine); }
audio_plugin_node_interface* nvgt_audio_plugin_node_get(plugin_node* node) { return node->get_plugin_interface(); }
