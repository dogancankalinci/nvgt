/* sound.cpp - sound system implementation code
 * Please note that the beginnings of this file were written way back in 2021 before the NVGT project even really started, and there has been a lot of learning that has taken place since then. This could have been written better putting it kindly, but it does provide the expected functionality.
 * You should only use this plugin if you cannot upgrade to the new miniaudio based sound system NVGT now offers in it's core. This legacy sound system is now unsupported and contains known bugs that will very likely not be patched unless by a contributor.
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

//#define SOUND_DEBUG
#include <string>
#include <algorithm>
#include <unordered_set>
#include <vector>
#ifdef _WIN32
	#define WIN32_LEAN_AND_MEAN
	#define NOMINMAX
	#include <windows.h>
	#include <timeapi.h>
#endif
#include <math.h>
#include <unordered_map>
#include <mutex>
#ifndef NVGT_PLUGIN_STATIC
	#define THREAD_IMPLEMENTATION
#endif
#include <thread.h>
#include <bass.h>
#include <bass_fx.h>
#include <bassmix.h>
#include <obfuscate.h>
#include <Poco/Thread.h>
#include <Poco/UnicodeConverter.h>
#include <phonon.h>
#include "../../src/nvgt_plugin.h"
#include "config.h"
#include "pack.h"
#define riffheader_impl
#include "riffheader.h"
#include "sound.h"
#include <scriptarray.h>
#include <system_error>
#include <fast_float/fast_float.h>
#include <Poco/StringTokenizer.h>
#include <array>
#include <algorithm>

#ifndef _WIN32
	#define strnicmp strncasecmp
#endif

// Mobile (Android/iOS) detection for the platform-specific audio tuning below.
#ifdef __APPLE__
	#include <TargetConditionals.h>
#endif
#if defined(__ANDROID__) || (defined(TARGET_OS_IPHONE) && TARGET_OS_IPHONE)
	#define LEGACY_SOUND_MOBILE 1
#else
	#define LEGACY_SOUND_MOBILE 0
#endif
#if defined(__APPLE__) && TARGET_OS_IPHONE && defined(NVGT_PLUGIN_STATIC)
	#include <dlfcn.h> // see plugin_main
#endif
#include <new>
#include <thread>
#include <sys/types.h>
#include <sys/stat.h>

using namespace std;
using namespace fast_float;

static inline float ff(const std::string& s) noexcept {
	float v = 0.0f;
	fast_float::from_chars(s.data(), s.data() + s.size(), v);
	return v;
}

static asIScriptEngine* g_ScriptEngine;
static BOOL sound_initialized = FALSE;
static legacy_mixer* output;
static legacy_mixer* g_default_mixer = NULL;
// The mixer graph (every mixer's child sets, plus the parent pointers that index into them) is reachable from any script thread: a game can create, attach or close sounds on a worker thread while the main thread does the same through the shared mixer everything hangs off. std::unordered_set is not thread safe, so one thread's insert rehashing the bucket array under another thread's erase corrupts the heap. Every graph mutation therefore runs under this lock, and it is recursive because these operations legitimately re-enter each other (set_mixer -> remove_mixer, destructor -> set_mixer -> add_mixer).
static std::recursive_mutex g_mixer_graph_mutex;
#define LOCK_MIXER_GRAPH() std::lock_guard<std::recursive_mutex> mixer_graph_lock(g_mixer_graph_mutex)
static bool hrtf = TRUE;
#define hrtf_framesize 512
static IPLContext phonon_context = NULL;
static IPLAudioSettings phonon_audio_settings{44100, hrtf_framesize};
static IPLHRTFSettings phonon_hrtfSettings{};
static IPLHRTF phonon_hrtf = NULL;
static IPLHRTF phonon_hrtf_reflections = NULL;
static thread_mutex_t preload_mutex;
static legacy_pack* g_sound_default_pack = nullptr;

hstream_entry* last_channel = NULL;
// Every load registers a node here and every close unregisters one, so this list is edited from whatever thread happens to be creating or freeing a sound. Unsynchronized, two threads linking at the same time lose a node and leave stale neighbour pointers, and the next unlink then writes through them into memory that has already been freed -- the allocator only notices later, aborting inside an unrelated free().
static std::mutex g_hstream_mutex;
hstream_entry* register_hstream(unsigned int channel) {
	if (!channel) return NULL;
	hstream_entry* e = (hstream_entry*)malloc(sizeof(hstream_entry));
	if (!e) return NULL;
	std::lock_guard<std::mutex> lock(g_hstream_mutex);
	e->p = last_channel;
	e->channel = channel;
	e->n = NULL;
	if (last_channel) last_channel->n = e;
	last_channel = e;
	return e;
}
void unregister_hstream(hstream_entry* e) {
	if (!e) return;
	{
		std::lock_guard<std::mutex> lock(g_hstream_mutex);
		if (last_channel == e) last_channel = e->p;
		if (e->p) e->p->n = e->n;
		if (e->n) e->n->p = e->p;
	}
	free(e);
}

BOOL sound_available() {
	#ifdef _MSC_VER
	__try {
		return init_sound();
	} __except (1) {
		return FALSE;
	}
	#else
	return init_sound();
	#endif
}
static std::atomic<bool> g_reaper_stopped{false};
static std::atomic<bool> g_fill_stopped{false};
BOOL init_sound(unsigned int dev) {
	if (sound_initialized)
		return TRUE;
	// A previous shutdown_sound() parked the reaper and the cache filler; sound is coming back,
	// so let them work again instead of falling back to the game thread for every free.
	g_reaper_stopped.store(false);
	g_fill_stopped.store(false);
	BASS_SetConfig(BASS_CONFIG_DEV_DEFAULT, TRUE);
	// The 128-sample device period is requested on desktop only. Windows ignores it (the
	// device reports a 10ms period regardless - measured), so desktop has always run with
	// ~441-frame blocks. Android honours it: BASS drives AAudio in callback mode and takes the
	// frames-per-callback from this setting, so the whole mix - every decode and every
	// spatialisation - ran inside a 2.9ms callback in 128-frame pieces. The spatialiser's cost is
	// per call, not per frame (measured 6.4us for 128 frames against 8.0us for 512), so those
	// small blocks made every positional source cost about three times what it costs on
	// desktop for identical audio, and the mixer's own per-callback overhead scaled the same
	// way. That is the platform difference behind stuttering on phones that never appears on
	// Windows. Mobile now uses BASS's 10ms default, which is what Windows effectively runs at;
	// a sound's start is still bounded by one period, so nothing waits longer than it does on
	// desktop.
	#if !LEGACY_SOUND_MOBILE
	BASS_SetConfig(BASS_CONFIG_DEV_PERIOD, -128);
	#endif
	BASS_SetConfig(BASS_CONFIG_CURVE_PAN, TRUE);
	BASS_SetConfig(BASS_CONFIG_CURVE_VOL, TRUE);
	BASS_SetConfig(BASS_CONFIG_FLOAT, TRUE);
	BASS_SetConfig(BASS_CONFIG_FLOATDSP, TRUE);
	BASS_SetConfig(BASS_CONFIG_BUFFER, 1000);
	BASS_SetConfig(BASS_CONFIG_MIXER_BUFFER, 5);
	BASS_SetConfig(BASS_CONFIG_UPDATEPERIOD, 50);
	BASS_SetConfig(BASS_CONFIG_UPDATETHREADS, 8);
	BASS_SetConfig(BASS_CONFIG_UNICODE, TRUE);
	#if defined(__APPLE__) && TARGET_OS_IPHONE
	// NVGT's own audio engine already configures the app's AVAudioSession (play and record, mixing with other apps).
	// Left to its defaults BASS would reconfigure that shared session on its own terms whenever a device is initialised.
	BASS_SetConfig(BASS_CONFIG_IOS_SESSION, BASS_IOS_SESSION_DISABLE);
	#endif
	if (BASS_Init(dev, 44100, 0, NULL, NULL))
		sound_initialized = TRUE;
	if (sound_initialized) {
		if (!BASS_PluginLoad("lib\\bassflac", 0))
			BASS_PluginLoad("bassflac", 0);
		if (!BASS_PluginLoad("lib\\bassopus", 0))
			BASS_PluginLoad("bassopus", 0);
		BASS_GetVersion();
		BASS_FX_GetVersion();
		output = new legacy_mixer(NULL);
		/* HFX reverb=BASS_ChannelSetFX(output->channel, BASS_FX_BFX_FREEVERB, 0);
		BASS_BFX_FREEVERB freeverb;
		freeverb.fDryMix=1.0;
		freeverb.fWetMix=0.8;
		freeverb.fRoomSize=0.3;
		freeverb.fDamp=0.5;
		freeverb.fWidth=1.0;
		freeverb.lChannel=BASS_BFX_CHANALL;
		BASS_FXSetParameters(reverb, &freeverb);
		*/
		thread_mutex_init(&preload_mutex);
	}
	return sound_initialized;
}
static void sound_reaper_drain();
static void sound_fill_drain();
BOOL shutdown_sound() {
	if (!sound_initialized)
		return TRUE;
	sound_fill_drain();
	sound_reaper_drain();
	while (last_channel) {
		BASS_StreamFree(last_channel->channel);
		unregister_hstream(last_channel);
	}
	BASS_Free();
	BASS_RecordFree();
	sound_initialized = FALSE;
	return !sound_initialized;
}

// A microclass for locking mutexes in scope, could likely do with error handling.
class lock_mutex {
	thread_mutex_t* mtx;
public:
	lock_mutex(thread_mutex_t* mtx) : mtx(mtx) {
		thread_mutex_lock(mtx);
	}
	~lock_mutex() {
		thread_mutex_unlock(mtx);
	}
};

// no hrtf positional dsp
void basic_positioning_dsp(void* buffer, unsigned int length, float x, float y, float z, float pan_step, float volume_step) {
	if (!buffer || length < 2)
		return;
	float volume = 1.0 - (floorf(sqrtf(pow(fabs(x), 2) + pow(fabs(y), 2) + pow(fabs(z), 2)))) / (125.0 / volume_step);
	float pan = x / (125.0 / pan_step);
	if (pan < -1.0) pan = -1.0;
	else if (pan > 1.0) pan = 1.0;
	if (volume < 0.0) volume = 0.0;
	else if (volume > 1.0) volume = 1.0;
	// volume and pan hold still for the whole block, so their decibel conversions do too. These
	// pow() calls used to sit inside the loop, which meant several hundred double-precision calls
	// per block for every positional sound - more than the spatialisation itself costs. The
	// arithmetic is unchanged: the same expressions, the same double result feeding the same
	// multiplications, just evaluated once. A missing pan factor is a multiply by exactly 1.
	if (volume <= 0) {
		// Everything here multiplies by an amplitude of zero, and this path keeps no state
		// between blocks, so the result is a block of silence: write it and skip the work.
		memset(buffer, 0, length);
		return;
	}
	float amp = 0;
	if (volume > 0)
		amp = pow(10.0f, (volume * 100 - 100) / 20.0);
	double pan_left = 1.0, pan_right = 1.0;
	if (pan < 0)
		pan_right = pow(10.0f, ((1 + pan) * 100 - 100) / 20.0);
	else if (pan > 0)
		pan_left = pow(10.0f, ((1 - pan) * 100 - 100) / 20.0);
	float* f = (float*)buffer;
	for (; length; length -= 8, f += 2) {
		f[0] *= amp;
		f[1] *= amp;
		f[1] = f[1] * pan_right;
		f[0] = f[0] * pan_left;
	}
}

// Uses steam audio to position the sound and add other effects to it such as reverb and occlusion. Sorry if this is a bit messy, this function has seen some evolution to say the least as different things were tested and so as to not break compatibility with existing code, this should probably be cleaned up as time goes on.
void phonon_dsp(void* buffer, unsigned int length, float x, float y, float z, sound_base& s) {
	if (!buffer || length < 2 || !hrtf || !s.hrtf_effect)
		return;
	float blend = (fabs(x * s.pan_step) + fabs(y * s.pan_step) + fabs(z * s.pan_step)) / 3;
	if (blend > 1.0)
		blend = 1.0;
	if (blend < 0.0)
		blend = 0.0;
	// Todo: Maybe we should allocate these differently?
	static thread_local float in_left[hrtf_framesize * 2], in_right[hrtf_framesize * 2], out_left[hrtf_framesize * 2], out_right[hrtf_framesize * 2], tmp_mono[hrtf_framesize * 2], in_mono[hrtf_framesize * 2], reflections1[hrtf_framesize * 2], reflections2[hrtf_framesize * 2], reflections3[hrtf_framesize * 2], reflections4[hrtf_framesize * 2], reflections5[hrtf_framesize * 2], reflections6[hrtf_framesize * 2], reflections7[hrtf_framesize * 2], reflections8[hrtf_framesize * 2], reflections9[hrtf_framesize * 2], reflections_downmix_left[hrtf_framesize * 2], reflections_downmix_right[hrtf_framesize * 2];
	float* in_data[] = {in_left, in_right};
	float* out_data[] = {out_left, out_right};
	float* tmp_mono_data[] = {tmp_mono};
	float* in_mono_data[] = {in_mono};
	float* reflections_data[] = {reflections1, reflections2, reflections3, reflections4, reflections5, reflections6, reflections7, reflections8, reflections9};
	float* reflections_downmix_data[] = {reflections_downmix_left, reflections_downmix_right};
	int samples = length / sizeof(float) / 2;
	IPLAudioBuffer inbuffer {2, samples, in_data };
	IPLAudioBuffer outbuffer {2, samples, out_data };
	IPLAudioBuffer mono_tmp_buffer {1, samples, tmp_mono_data};
	IPLAudioBuffer mono_inbuffer {1, samples, in_mono_data};
	IPLAudioBuffer reflections_outbuffer{ 9, samples, reflections_data };
	IPLAudioBuffer reflections_downmix_buffer {2, samples, reflections_downmix_data};
	if (!s.env) {
		// simple distance rolloff in the case of no set sound_environment
		float volume = 1.0 - (floorf(sqrtf(pow(fabs(x), 2) + pow(fabs(y), 2) + pow(fabs(z), 2)))) / (125.0 / s.volume_step);
		// Same as in basic_positioning_dsp: the level is constant across the block, so its
		// decibel conversion is hoisted out of the loop rather than recomputed per sample.
		if (volume <= 0) {
			// Too far away to be heard at all: the samples below would be multiplied by zero, so
			// the only thing the spatialiser could still contribute is the tail it carries over
			// from earlier input. Let one frame's worth of silence (hrtf_framesize samples, the
			// effect's own frame) run through it to flush that tail, and from then on the output
			// is zeros either way, so it is written directly and the whole chain is skipped. A
			// crowded scene is full of sources like this, each otherwise costing as much as one
			// standing next to the listener. Counted in frames so the flush does not depend on
			// how large the device's blocks happen to be.
			memset(buffer, 0, length);
			if (s.silent_frames >= hrtf_framesize)
				return;
			s.silent_frames += samples;
		} else
			s.silent_frames = 0;
		float amp = 0;
		if (volume > 0)
			amp = pow(10.0f, (volume * 100 - 100) / 20.0);
		float* f = (float*)buffer;
		for (; length; length -= 8, f += 2) {
			f[0] *= amp;
			f[1] *= amp;
		}
	}
	IPLSimulationOutputs src_out{};
	if (s.env) iplSourceGetOutputs(s.source, IPLSimulationFlags(IPL_SIMULATIONFLAGS_DIRECT | IPL_SIMULATIONFLAGS_REFLECTIONS), &src_out);
	iplAudioBufferDeinterleave(phonon_context, (IPLfloat32*)buffer, &inbuffer);
	iplAudioBufferDownmix(phonon_context, &inbuffer, &mono_inbuffer);
	if (s.env) {
		IPLDirectEffectParams dir_params = src_out.direct;
		dir_params.flags = IPLDirectEffectFlags(IPL_DIRECTEFFECTFLAGS_APPLYDISTANCEATTENUATION | IPL_DIRECTEFFECTFLAGS_APPLYAIRABSORPTION | IPL_DIRECTEFFECTFLAGS_APPLYOCCLUSION);
		iplDirectEffectApply(s.direct_effect, &dir_params, &mono_inbuffer, &mono_tmp_buffer);
	}
	if ((x != 0 || y != 0 || z != 0) && s.hrtf_effect) {
		IPLBinauralEffectParams effect_args{};
		effect_args.direction = iplCalculateRelativeDirection(phonon_context, IPLVector3{s.x, s.y, s.z}, s.env ? IPLVector3{s.env->listener_x, s.env->listener_y, s.env->listener_z} : IPLVector3{s.listener_x, s.listener_y, s.listener_z}, s.env ? IPLVector3{sin(s.env->listener_rotation), cos(s.env->listener_rotation), 0} : IPLVector3{sin(s.rotation), cos(s.rotation), 0}, IPLVector3{0, 0, 1});
		effect_args.interpolation = IPL_HRTFINTERPOLATION_BILINEAR;
		effect_args.spatialBlend = blend;
		effect_args.hrtf = phonon_hrtf;
		iplBinauralEffectApply(s.hrtf_effect, &effect_args, s.env ? &mono_tmp_buffer : &inbuffer, &outbuffer);
	} else { // Sound is at the same position as the listener, direct copy to output buffer
		memcpy(out_left, in_left, sizeof(float) * hrtf_framesize * 2);
		memcpy(out_right, in_right, sizeof(float) * hrtf_framesize * 2);
	}
	if (s.env) { // reflections
		IPLReflectionEffectParams reflect_params = src_out.reflections;
		reflect_params.numChannels = 9;
		reflect_params.irSize = 88200;
		iplReflectionEffectApply(s.reflection_effect, &reflect_params, &mono_inbuffer, &reflections_outbuffer, NULL);
		// spacialize reflections
		// IPLCoordinateSpace3{IPLVector3{1, 0, 0}, IPLVector3{0, 0, 1}, IPLVector3{0, 1, 0}, IPLVector3{s.x, s.y, s.z}}
		IPLAmbisonicsDecodeEffectParams dec_params{2, phonon_hrtf_reflections, s.env->sim_inputs.listener, IPL_TRUE};
		iplAmbisonicsDecodeEffectApply(s.reflection_decode_effect, &dec_params, &reflections_outbuffer, &reflections_downmix_buffer);
		iplAudioBufferMix(phonon_context, &reflections_downmix_buffer, &outbuffer);
	}
	iplAudioBufferInterleave(phonon_context, &outbuffer, (IPLfloat32*)buffer);
}

void CALLBACK positioning_dsp(HDSP handle, DWORD channel, void* buffer, DWORD length, void* user) {
	if (!buffer || length < 1 || !user)
		return;
	sound_base* s = (sound_base*)user;
	float x = s->x - s->listener_x;
	float y = s->y - s->listener_y;
	float z = s->z - s->listener_z;
	if (x == 0 && y == 0 && z == 0) {
		if (s->hrtf_effect)
			iplBinauralEffectReset(s->hrtf_effect);
		//if(!s->env) return;
	}
	float rotational_x = x;
	float rotational_y = y;
	if (s->rotation > 0.0) {
		rotational_x = (cosf(s->rotation) * (x)) - (sinf(s->rotation) * (y));
		rotational_y = (sinf(s->rotation) * (x)) + (cosf(s->rotation) * (y));
		x = rotational_x;
		y = rotational_y;
	}
	// The binaural effect is created in postload() and released in close(); this callback only
	// decides whether to use it. Creating or freeing it here meant malloc/free on the audio thread.
	// Work in pieces of at most hrtf_framesize frames: the spatialiser's scratch buffers are that
	// size, and the device block is whatever the platform chose - the requested period is only a
	// request, and a device rounding it up past 23ms would otherwise overrun them. Blocks at or
	// below that size (every desktop block, and mobile at the default period) pass through whole.
	const DWORD piece = hrtf_framesize * 2 * sizeof(float);
	BYTE* p = (BYTE*)buffer;
	while (length > 0) {
		DWORD n = length > piece ? piece : length;
		if (hrtf && s->hrtf_effect && s->use_hrtf)
			phonon_dsp(p, n, x, y, z, *s);
		else
			basic_positioning_dsp(p, n, x, y, z, s->pan_step, s->volume_step);
		p += n;
		length -= n;
	}
}

// Bass fileprocs
// pack
void CALLBACK bass_closeproc_pack(void* user) {
	if (!user)
		return;
	packed_sound snd = (*(packed_sound*)user);
	if (!snd.p)
		return;
	snd.p->stream_close(snd.s);
	free(user);
}
QWORD CALLBACK bass_lenproc_pack(void* user) {
	if (!user)
		return 0xffffffff;
	packed_sound snd = (*(packed_sound*)user);
	if (!snd.p || !snd.p->next_stream_idx)
		return 0xffffffff;
	return snd.p->stream_size(snd.s);
}
DWORD CALLBACK bass_readproc_pack(void* buffer, DWORD length, void* user) {
	if (!user)
		return 0;
	packed_sound* snd = (packed_sound*)user;
	if (!snd->p || !snd->p->next_stream_idx)
		return 0;
	// This path is only used for pack members too large for the in-memory cache. No lock is
	// taken here: close() flips `closing` before it detaches the channel, and the stream's
	// own FILE* is only closed once BASS has released the channel (in the close callback).
	if (snd->snd && snd->snd->closing.load(std::memory_order_acquire))
		return 0;
	return snd->p->stream_read(snd->s, (BYTE *)buffer, length);
}
BOOL CALLBACK bass_seekproc_pack(QWORD offset, void* user) {
	if (!user)
		return FALSE;
	packed_sound* snd = (packed_sound*)user;
	if (!snd->p || !snd->p->next_stream_idx)
		return FALSE;
	return snd->p->stream_seek(snd->s, offset, SEEK_SET);
}
// push
void CALLBACK bass_closeproc_push(void* user) {
	return;
}
QWORD CALLBACK bass_lenproc_push(void* user) {
	legacy_sound* s = (legacy_sound*) user;
	if (s->memstream && s->memstream_size == s->memstream->size())
		return s->memstream_size;
	return 0;
}
DWORD CALLBACK bass_readproc_push(void* buffer, DWORD length, void* user) {
	if (!buffer || !user)
		return 0;
	legacy_sound* s = (legacy_sound*)user;
	thread_mutex_lock(&s->close_mutex);
	if (s->memstream) {
		if (!s->channel && !s->script_loading) {
			thread_mutex_unlock(&s->close_mutex);
			return -1;
		}
		DWORD l = length;
		DWORD S = s->memstream->size();
		if (s->memstream_pos + l >= s->memstream_size)
			l = s->memstream_size - s->memstream_pos;
		if (l < 1) {
			thread_mutex_unlock(&s->close_mutex);
			return -1;
		}
		if (s->memstream_pos + l >= S)
			l = S - s->memstream_pos;
		if (l < 1) {
			thread_mutex_unlock(&s->close_mutex);
			return 0;
		}
		DWORD bufsize = 128;
		s->AddRef();
		for (DWORD pos = 0; pos < l; pos += bufsize) {
			if (!s->script_loading && !s->output_mixer) {
				thread_mutex_unlock(&s->close_mutex);
				s->Release();
				return -1;
			}
			int size = bufsize;
			if (l - pos < bufsize)
				size = l - pos;
			if (size > l) size = l;
			std::string data;
			try {
				data = s->memstream->substr(s->memstream_pos + pos, size);
				if (s->memstream_legacy_encrypt) {
					for (int i = 0; i < data.size(); i ++) data[i] = sound_data_char_decrypt(data[i], s->memstream_pos + pos + i, s->memstream_size);
				}
				BYTE* ptr = ((BYTE*)buffer) + pos;
				memcpy(ptr, &data[0], size);
			} catch (...) {
				thread_mutex_unlock(&s->close_mutex);
				return -1;
			}
		}
		s->memstream_pos += l;
		thread_mutex_unlock(&s->close_mutex);
		s->Release();
		return l;
	}
	if (s->push_prebuff.size() < length)
		length = s->push_prebuff.size();
	if (length < 1) {
		thread_mutex_unlock(&s->close_mutex);
		return 0;
	}
	copy(s->push_prebuff.begin(), s->push_prebuff.begin() + length, (BYTE*)buffer);
	s->push_prebuff.erase(s->push_prebuff.begin(), s->push_prebuff.begin() + length);
	thread_mutex_unlock(&s->close_mutex);
	return length;
}
BOOL CALLBACK bass_seekproc_push(QWORD offset, void* user) {
	legacy_sound* s = (legacy_sound*) user;
	if (s->memstream) {
		if (offset >= s->memstream_size)
			return FALSE;
		s->memstream_pos = offset;
		return TRUE;
	}
	return FALSE;
}
// script
void CALLBACK bass_closeproc_script(void* user) {
	if (!user)
		return;
	legacy_sound* s = (legacy_sound*)user;
	if (!s->close_callback)
		return;
	asIScriptContext* ctx = g_ScriptEngine->RequestContext();
	if (!ctx) return;
	if (ctx->Prepare(s->close_callback) < 0)
		goto finish;
	if (ctx->SetArgObject(0, &s->callback_data) < 0)
		goto finish;
	ctx->Execute();
finish:
	g_ScriptEngine->ReturnContext(ctx);
	asThreadCleanup();
}
QWORD CALLBACK bass_lenproc_script(void* user) {
	if (!user)
		return 0;
	legacy_sound* s = (legacy_sound*)user;
	unsigned long long ret = 0;
	if (!s->len_callback)
		return 0;
	asIScriptContext* ctx = g_ScriptEngine->RequestContext();
	if (!ctx) return 0;
	if (!ctx || ctx->Prepare(s->len_callback) < 0)
		goto finish;
	if (ctx->SetArgObject(0, &s->callback_data) < 0)
		goto finish;
	if (ctx->Execute() != asEXECUTION_FINISHED)
		goto finish;
	ret = ctx->GetReturnDWord();
finish:
	g_ScriptEngine->ReturnContext(ctx);
	asThreadCleanup();
	return ret;
}
DWORD CALLBACK bass_readproc_script(void* buffer, DWORD length, void* user) {
	if (!user)
		return -1;
	legacy_sound* s = (legacy_sound*)user;
	int ret = -1;
	std::string data;
	if (!s->read_callback)
		return -1;
	asIScriptContext* ctx = g_ScriptEngine->RequestContext();
	if (!ctx) return -1;
	if (ctx->Prepare(s->read_callback) < 0) goto finish;
	if (ctx->SetArgObject(0, &data) < 0 || ctx->SetArgDWord(1, length) < 0 || ctx->SetArgObject(2, &s->callback_data) < 0)
		goto finish;
	if (ctx->Execute() != asEXECUTION_FINISHED) goto finish;
	ret = ctx->GetReturnDWord();
	if (data.size() > length) data.resize(length);
	if (data.size() > 0)
		memcpy(buffer, &data[0], data.size());
finish:
	g_ScriptEngine->ReturnContext(ctx);
	asThreadCleanup();
	return ret;
}
BOOL CALLBACK bass_seekproc_script(QWORD offset, void* user) {
	if (!user)
		return false;
	legacy_sound* s = (legacy_sound*)user;
	bool ret = false;
	if (!s->seek_callback)
		return false;
	asIScriptContext* ctx = g_ScriptEngine->RequestContext();
	if (!ctx) return false;
	if (ctx->Prepare(s->seek_callback) < 0)
		goto finish;
	if (ctx->SetArgDWord(0, offset) < 0 || ctx->SetArgObject(1, &s->callback_data) < 0) goto finish;
	if (ctx->Execute() != asEXECUTION_FINISHED) goto finish;
	ret = ctx->GetReturnByte();
finish:
	g_ScriptEngine->ReturnContext(ctx);
	asThreadCleanup();
	return ret;
}

std::unordered_map<std::string, sound_preload*> sound_preloads;
// The cache now holds each file's COMPRESSED bytes (an OGG is ~100-200KB), not decoded PCM
// (which is ~10x larger). Two things follow: the budget below covers far more sounds, and a
// cache entry is produced by a single read on the loading thread instead of a background
// decode thread - there is no decode thread at all any more. Mobile stays small so the cache
// can never contribute to an LMK kill or (z)swap pressure.
static size_t sound_preload_total = 0;
#if LEGACY_SOUND_MOBILE
	#define SOUND_PRELOAD_MAX_TOTAL (32u * 1024 * 1024)
	#define SOUND_PRELOAD_MAX_ITEM (3u * 1024 * 1024)
#else
	#define SOUND_PRELOAD_MAX_TOTAL (256u * 1024 * 1024)
	#define SOUND_PRELOAD_MAX_ITEM (24u * 1024 * 1024)
#endif
// How much a first play may read on the thread that called load(). Reading a file's bytes costs
// about 11us/KB here (measured: it is the per-byte de-obfuscation, not the disk - a repeated read
// of the same member costs the same), and a low-end phone core is several times slower, so this
// keeps that one-off cost inside a frame. Anything larger keeps the streaming path, where the
// same work is spread thinly across playback instead of landing in one lump on the game thread;
// in a typical pack over 90% of members are below this size, and the ones above it are ambience
// and music, which are started once and played for minutes.
#if LEGACY_SOUND_MOBILE
	#define SOUND_PRELOAD_SYNC_MAX (128u * 1024)
#else
	#define SOUND_PRELOAD_SYNC_MAX (512u * 1024)
#endif
// Short sounds are kept DECODED. Every playing source is decoded inside the device callback, so
// a crowded scene runs dozens of Vorbis decoders there at once - by far the largest per-source
// cost, and the only one that can be paid once in advance instead. Decoding a short sound when
// it is first loaded costs a millisecond or two on the loading thread and removes the codec from
// every later play of it. The limit is on the DECODED size, so this only catches footsteps, hits
// and interface sounds; music and ambience stay compressed, where the codec cost is negligible
// because there are only a couple of them and they run for minutes.
// Mobile keeps this tight: decoding is the one-off price of the saving, and on a slow core the
// limit below is about ten milliseconds of work, still inside a frame. 256KB of float samples is
// roughly a second and a half of mono audio, which is what a footstep, a hit or a menu sound is.
#if LEGACY_SOUND_MOBILE
	#define SOUND_PRELOAD_PCM_MAX (256u * 1024)
#else
	#define SOUND_PRELOAD_PCM_MAX (2u * 1024 * 1024)
#endif
// Frees a cache entry and returns the iterator to the next one. Caller must hold preload_mutex.
static std::unordered_map<std::string, sound_preload*>::iterator sound_preload_destroy_locked(std::unordered_map<std::string, sound_preload*>::iterator it) {
	sound_preload* p = it->second;
	if (p->size <= sound_preload_total) sound_preload_total -= p->size;
	else sound_preload_total = 0;
	free(p->data);
	p->fn.~string();
	free(p);
	return sound_preloads.erase(it);
}
// Evicts least-recently-used idle entries until need extra bytes fit under the budget.
// Caller must hold preload_mutex. Returns false if the space cannot be made.
static bool sound_preload_make_room(size_t need) {
	if (need > SOUND_PRELOAD_MAX_ITEM) return false;
	while (sound_preload_total + need > SOUND_PRELOAD_MAX_TOTAL) {
		auto lru = sound_preloads.end();
		for (auto it = sound_preloads.begin(); it != sound_preloads.end(); it++) {
			if (it->second->ref > 0) continue;
			if (lru == sound_preloads.end() || it->second->t < lru->second->t) lru = it;
		}
		if (lru == sound_preloads.end()) return false;
		sound_preload_destroy_locked(lru);
	}
	return true;
}
// Looks up a cache entry and takes a reference on it while still holding the lock, so the
// cleanup/eviction paths can never free an entry between lookup and use.
sound_preload* get_sound_preload(const std::string& filename) {
	lock_mutex scopelock(&preload_mutex);
	auto it = sound_preloads.find(filename);
	if (it == sound_preloads.end()) return NULL;
	it->second->ref += 1;
	it->second->t = ticks(false);
	return it->second;
}
// Reads an entire pack member (de-obfuscated) into memory. Returns NULL if it does not fit the
// per-item limit or cannot be read. This is the ONLY place a sound's file data is read from
// disk; it runs on whichever thread called load(), never on the audio thread.
static unsigned char* sound_read_pack_member(legacy_pack* p, const std::string& filename, unsigned int& size_out, unsigned int max_size) {
	size_out = 0;
	if (!p || !p->is_active()) return NULL;
	unsigned int size = p->get_file_size(filename);
	if (!size || size > max_size) return NULL;
	unsigned char* data = (unsigned char*)malloc(size);
	if (!data) return NULL;
	// One read on the pack's own file handle (no per-load fopen/fclose); the pack serialises it.
	unsigned int got = p->read_file_locked(filename, 0, data, size);
	if (got != size) { free(data); return NULL; }
	size_out = size;
	return data;
}
// Inserts (or finds) a cache entry for filename holding the given bytes and takes a reference
// on it. Ownership of data passes to the cache on success; on failure it is freed and NULL is
// returned so the caller can fall back to plain streaming.
static sound_preload* sound_preload_insert(const std::string& filename, unsigned char* data, unsigned int size, bool from_file = false, unsigned long long mtime = 0, unsigned int fsize = 0) {
	lock_mutex scopelock(&preload_mutex);
	auto it = sound_preloads.find(filename);
	if (it != sound_preloads.end()) {
		// Another thread cached it in the meantime: use theirs, drop ours.
		free(data);
		it->second->ref += 1;
		it->second->t = ticks(false);
		return it->second;
	}
	if (!sound_preload_make_room(size)) { free(data); return NULL; }
	sound_preload* pre = (sound_preload*)malloc(sizeof(sound_preload));
	if (!pre) { free(data); return NULL; }
	memset(pre, 0, sizeof(sound_preload));
	new (&pre->fn) std::string(filename);
	pre->data = data;
	pre->size = size;
	pre->from_file = from_file;
	pre->mtime = mtime;
	pre->fsize = fsize;
	pre->ref = 1;
	pre->t = ticks(false);
	sound_preloads[filename] = pre;
	sound_preload_total += size;
	return pre;
}
void sound_preload_release(sound_preload* p) {
	lock_mutex scopelock(&preload_mutex);
	if (p->ref > 0)
		p->ref -= 1;
	// Entries are kept after release so the next play of the same sound is free; the LRU
	// budget in sound_preload_make_room is what eventually retires them.
}
// Drops the caller's reference and, if nothing else holds the entry, takes it out of the cache.
// Used when the disk file an entry was read from has been replaced since.
static void sound_preload_invalidate(sound_preload* p) {
	lock_mutex scopelock(&preload_mutex);
	if (p->ref > 0)
		p->ref -= 1;
	if (p->ref > 0) return; // still playing somewhere: leave that copy be, it will retire on its own
	auto it = sound_preloads.find(p->fn);
	if (it != sound_preloads.end() && it->second == p) sound_preload_destroy_locked(it);
}
// Reads a disk file's identity. A cached copy is only reused while both of these still match, so
// a game that rewrites a file under the same name (temporary speech files, downloaded clips)
// never hears the previous contents.
static bool sound_file_stamp(const std::string& path, unsigned long long& mtime, unsigned int& size) {
	#ifdef _WIN32
	std::wstring wpath;
	Poco::UnicodeConverter::convert(path, wpath); // the rest of this file takes the same care with UTF-8 paths
	struct _stat64 st;
	if (_wstat64(wpath.c_str(), &st) != 0) return false;
	#else
	struct stat st;
	if (stat(path.c_str(), &st) != 0) return false;
	#endif
	if (st.st_size <= 0 || (unsigned long long)st.st_size > 0xffffffffull) return false;
	size = (unsigned int)st.st_size;
	mtime = (unsigned long long)st.st_mtime; // seconds; paired with the size, which is what a rewrite almost always changes
	return true;
}
// Reads a plain file into memory on the calling thread, the same way pack members are read, so
// sounds loaded from disk are cached and replayed without touching the filesystem again.
static unsigned char* sound_read_disk_file(const std::string& path, unsigned int& size_out, unsigned long long& mtime_out, unsigned int max_size) {
	size_out = 0;
	unsigned int size = 0;
	if (!sound_file_stamp(path, mtime_out, size)) return NULL;
	if (!size || size > max_size) return NULL;
	unsigned char* data = (unsigned char*)malloc(size);
	if (!data) return NULL;
	#ifdef _WIN32
	std::wstring wpath;
	Poco::UnicodeConverter::convert(path, wpath);
	FILE* f = _wfopen(wpath.c_str(), L"rb");
	#else
	FILE* f = fopen(path.c_str(), "rb");
	#endif
	if (!f) { free(data); return NULL; }
	size_t got = fread(data, 1, size, f);
	fclose(f);
	if (got != size) { free(data); return NULL; }
	size_out = size;
	return data;
}
// Decodes a short sound in full and returns it as a WAV blob the cache can serve directly, or
// NULL when it decodes to more than the limit above (or cannot be decoded at all), in which case
// the caller keeps the compressed bytes.
static unsigned char* sound_decode_short(const unsigned char* bytes, unsigned int size, unsigned int& out_size) {
	out_size = 0;
	HSTREAM d = BASS_StreamCreateFile(TRUE, (void*)bytes, 0, size, BASS_STREAM_DECODE | BASS_SAMPLE_FLOAT);
	if (!d) return NULL;
	QWORD len = BASS_ChannelGetLength(d, BASS_POS_BYTE);
	BASS_CHANNELINFO ci;
	if (!len || len == (QWORD) -1 || len + 44 > SOUND_PRELOAD_PCM_MAX || !BASS_ChannelGetInfo(d, &ci)) {
		BASS_StreamFree(d);
		return NULL;
	}
	unsigned char* out = (unsigned char*)malloc((size_t)len + 44);
	if (!out) { BASS_StreamFree(d); return NULL; }
	DWORD got = BASS_ChannelGetData(d, out + 44, (DWORD)len | BASS_DATA_FLOAT);
	BASS_StreamFree(d); // freed before the caller releases the bytes it was reading from
	if (got == (DWORD) -1 || !got) { free(out); return NULL; }
	wav_header h = make_wav_header(got + 44, ci.freq, 32, ci.chans, 3);
	memcpy(out, &h, 44);
	out_size = got + 44;
	return out;
}
// Replaces just-read file bytes with their decoded form when the sound is short enough to be
// worth keeping that way. Takes ownership either way: on success the compressed bytes are freed.
static unsigned char* sound_promote_short(unsigned char* data, unsigned int& size) {
	unsigned int pcm_size = 0;
	unsigned char* pcm = sound_decode_short(data, size, pcm_size);
	if (!pcm) return data;
	free(data);
	size = pcm_size;
	return pcm;
}
// Sources with no file behind them (script callbacks, memory streams) are cached by decoding the
// stream once and keeping the result as a WAV blob, which the cache can hand to BASS like any
// other file. The decode happens here, on the loading thread, exactly where it used to.
static void sound_preload_capture_pcm(HSTREAM channel, const std::string& filename) {
	if (!channel || filename.empty()) return;
	sound_preload* existing = get_sound_preload(filename);
	if (existing) { // already cached by an earlier load
		sound_preload_release(existing);
		return;
	}
	BASS_CHANNELINFO ci;
	if (!BASS_ChannelGetInfo(channel, &ci)) return;
	QWORD len = BASS_ChannelGetLength(channel, BASS_POS_BYTE);
	if (!len || len == (QWORD) -1 || len + 44 > SOUND_PRELOAD_MAX_ITEM) return;
	unsigned char* samples = (unsigned char*)malloc((size_t)len + 44);
	if (!samples) return;
	DWORD got = BASS_ChannelGetData(channel, samples + 44, (DWORD)len | BASS_DATA_FLOAT);
	BASS_ChannelSetPosition(channel, 0, BASS_POS_BYTE); // hand the stream back at the start
	if (got == (DWORD) -1 || !got) { free(samples); return; }
	wav_header h = make_wav_header(got + 44, ci.freq, 32, ci.chans, 3);
	memcpy(samples, &h, 44);
	sound_preload* pre = sound_preload_insert(filename, samples, got + 44);
	if (pre) sound_preload_release(pre); // this sound plays from its own stream; the cache keeps the copy
}
// Reads a large member for the background filler in pieces, releasing the pack's lock between
// them. A multi-megabyte read costs tens of milliseconds (hundreds on a phone) and the same lock
// is what a sound about to play needs to register its stream, so holding it for the whole read
// would stall the game thread exactly as the audio thread used to be stalled.
// Small pieces with a real pause between them on mobile: the filler is never urgent, and a phone
// with four cores cannot afford a background thread that runs flat out next to the audio callback.
#if LEGACY_SOUND_MOBILE
	#define SOUND_PRELOAD_FILL_CHUNK (32u * 1024)
	#define SOUND_PRELOAD_FILL_PAUSE 10
#else
	#define SOUND_PRELOAD_FILL_CHUNK (128u * 1024)
	#define SOUND_PRELOAD_FILL_PAUSE 1
#endif
static unsigned char* sound_read_pack_member_chunked(legacy_pack* p, const std::string& filename, unsigned int& size_out) {
	size_out = 0;
	if (!p || !p->is_active()) return NULL;
	unsigned int size = p->get_file_size(filename);
	if (!size || size > SOUND_PRELOAD_MAX_ITEM) return NULL;
	unsigned char* data = (unsigned char*)malloc(size);
	if (!data) return NULL;
	for (unsigned int off = 0; off < size; off += SOUND_PRELOAD_FILL_CHUNK) {
		unsigned int want = size - off < SOUND_PRELOAD_FILL_CHUNK ? size - off : SOUND_PRELOAD_FILL_CHUNK;
		if (p->read_file_locked(filename, off, data + off, want) != want) { // pack closed under us, or a short read
			free(data);
			return NULL;
		}
		Poco::Thread::sleep(SOUND_PRELOAD_FILL_PAUSE); // hand the lock back, and the core with it
	}
	size_out = size;
	return data;
}

// Background cache filler. A sound too large to read on the loading thread (see
// SOUND_PRELOAD_SYNC_MAX) would otherwise stream on every play, which puts the read and the
// de-obfuscation loop back on the mixing thread - the very thing this file is arranged to avoid.
// So the first play streams, and exactly one background thread reads the bytes into the cache
// meanwhile; every later play comes from memory. One worker, one member at a time, with a pause
// between them: it can never become the thread-per-sound storm that starved audio on few-core
// devices, and it never touches BASS.
typedef struct {
	std::string filename;
	legacy_pack* p; // referenced while queued so it cannot be freed under the read; NULL for a plain file
} preload_fill_job;
static std::mutex g_fill_mutex;
static std::vector<preload_fill_job> g_fill_queue;
static thread_signal_t g_fill_signal;
static std::atomic<bool> g_fill_started{false};
#define SOUND_PRELOAD_FILL_QUEUE_MAX 64
static int sound_fill_thread(void*) {
	while (true) {
		thread_signal_wait(&g_fill_signal, 500);
		while (true) {
			preload_fill_job job;
			{
				std::lock_guard<std::mutex> g(g_fill_mutex);
				if (g_fill_queue.empty()) break;
				job = g_fill_queue.front();
				g_fill_queue.erase(g_fill_queue.begin());
			}
			if (!g_fill_stopped.load()) {
				sound_preload* have = get_sound_preload(job.filename);
				if (have) sound_preload_release(have); // someone cached it first
				else {
					unsigned int size = 0;
					unsigned long long mtime = 0;
					unsigned char* data = job.p ? sound_read_pack_member_chunked(job.p, job.filename, size)
					                            : sound_read_disk_file(job.filename, size, mtime, SOUND_PRELOAD_MAX_ITEM);
					if (data) {
						sound_preload* pre = sound_preload_insert(job.filename, data, size, job.p == NULL, mtime, size);
						if (pre) sound_preload_release(pre); // nobody is holding it; it is there for the next play
					}
				}
			}
			if (job.p) job.p->Release();
			Poco::Thread::sleep(SOUND_PRELOAD_FILL_PAUSE * 5); // breathe between members too
		}
	}
	return 0;
}
static void sound_preload_fill_later(const std::string& filename, legacy_pack* p) {
	if (g_fill_stopped.load()) return;
	{
		std::lock_guard<std::mutex> g(g_fill_mutex);
		if (g_fill_queue.size() >= SOUND_PRELOAD_FILL_QUEUE_MAX) return; // a backlog this deep means the cache is not the bottleneck
		for (size_t i = 0; i < g_fill_queue.size(); i++)
			if (g_fill_queue[i].filename == filename) return; // already waiting
		if (p) p->AddRef();
		preload_fill_job job;
		job.filename = filename;
		job.p = p;
		g_fill_queue.push_back(job);
	}
	if (!g_fill_started.exchange(true)) {
		thread_signal_init(&g_fill_signal);
		thread_create(sound_fill_thread, NULL, THREAD_STACK_SIZE_DEFAULT);
	}
	thread_signal_raise(&g_fill_signal);
}
// Stops the filler from starting new reads and hands back the packs it was holding.
static void sound_fill_drain() {
	g_fill_stopped.store(true);
	std::vector<preload_fill_job> batch;
	{
		std::lock_guard<std::mutex> g(g_fill_mutex);
		batch.swap(g_fill_queue);
	}
	for (size_t i = 0; i < batch.size(); i++)
		if (batch[i].p) batch[i].p->Release();
}
static int sound_preloads_clean_counter = 0;
void sound_preloads_clean() {
	if (sound_preloads_clean_counter < 250) {
		sound_preloads_clean_counter += 1;
		return;
	}
	sound_preloads_clean_counter = 0;
	lock_mutex scopelock(&preload_mutex);
	std::unordered_map<std::string, sound_preload*>::iterator i = sound_preloads.begin();
	while (i != sound_preloads.end()) {
		// Idle for 10 minutes: hand the memory back even if the budget is not under pressure.
		if (i->second->ref > 0 || ticks(false) - i->second->t < 600000) {
			i++;
			continue;
		}
		i = sound_preload_destroy_locked(i);
	}
}

// Deferred BASS teardown. BASS_StreamFree/BASS_ChannelRemoveDSP synchronise with the audio
// thread and can take a whole mixing period each; doing that inline in close() stalled the
// game thread and, through the shared lock, everything else. close() now detaches the
// channel from its mixer (which is what silences it) and hands the handles to this thread.
static std::mutex g_reaper_mutex;
// A stream created from a cache entry's memory keeps that entry referenced until BASS has
// actually freed the stream: BASS documents the memory as having to stay valid for the life
// of the stream, so releasing the reference in close() (which returns before the reaper has
// run) would let the LRU hand those bytes to another sound first.
struct reaper_item { HSTREAM h; sound_preload* pre; };
static std::vector<reaper_item> g_reaper_queue;
static thread_signal_t g_reaper_signal;
static std::atomic<bool> g_reaper_started{false};
static int sound_reaper_thread(void*) {
	std::vector<reaper_item> batch;
	while (true) {
		thread_signal_wait(&g_reaper_signal, 250);
		{
			std::lock_guard<std::mutex> g(g_reaper_mutex);
			batch.swap(g_reaper_queue);
		}
		if (g_reaper_stopped.load()) { batch.clear(); continue; }
		for (reaper_item& it : batch) {
			if (it.h) BASS_StreamFree(it.h);
			if (it.pre) sound_preload_release(it.pre);
		}
		batch.clear();
	}
	return 0;
}
// Frees everything still queued, synchronously, and stops the reaper from touching BASS again.
// Called before BASS_Free so no stream is freed after its device is gone.
static void sound_reaper_drain() {
	g_reaper_stopped.store(true);
	std::vector<reaper_item> batch;
	{
		std::lock_guard<std::mutex> g(g_reaper_mutex);
		batch.swap(g_reaper_queue);
	}
	for (reaper_item& it : batch) {
		if (it.h) BASS_StreamFree(it.h);
		if (it.pre) sound_preload_release(it.pre);
	}
}
static void sound_reaper_push(HSTREAM h, sound_preload* pre = NULL) {
	if (!h && !pre) return;
	if (g_reaper_stopped.load()) {
		if (h) BASS_StreamFree(h);
		if (pre) sound_preload_release(pre);
		return;
	}
	if (!g_reaper_started.exchange(true)) {
		thread_signal_init(&g_reaper_signal);
		thread_create(sound_reaper_thread, NULL, THREAD_STACK_SIZE_DEFAULT);
	}
	{
		std::lock_guard<std::mutex> g(g_reaper_mutex);
		g_reaper_queue.push_back(reaper_item{h, pre});
	}
	thread_signal_raise(&g_reaper_signal);
}

int sound_environment_thread(void* args) {
	sound_environment* e = (sound_environment*)args;
	while (e->ref_count > 0)
		e->background_update();
	e->_detach_all();
	return 0;
}
sound_environment::sound_environment() : ref_count(1), sim_inputs({}), scene_needs_commit(false), listener_modified(false) {
	set_global_hrtf(true);
	IPLSimulationSettings simulation_settings{};
	simulation_settings.flags = IPLSimulationFlags(IPL_SIMULATIONFLAGS_DIRECT | IPL_SIMULATIONFLAGS_REFLECTIONS);
	simulation_settings.sceneType = IPL_SCENETYPE_DEFAULT;
	simulation_settings.reflectionType = IPL_REFLECTIONEFFECTTYPE_CONVOLUTION;
	simulation_settings.maxNumRays = 2048;
	simulation_settings.numDiffuseSamples = 128;
	simulation_settings.maxDuration = 2.0f;
	simulation_settings.maxOrder = 2;
	simulation_settings.maxNumSources = 64;
	simulation_settings.numThreads = 16;
	simulation_settings.samplingRate = phonon_audio_settings.samplingRate;
	simulation_settings.frameSize = phonon_audio_settings.frameSize;
	iplSimulatorCreate(phonon_context, &simulation_settings, &sim);
	IPLSceneSettings scene_settings{};
	scene_settings.type = IPL_SCENETYPE_DEFAULT;
	iplSceneCreate(phonon_context, &scene_settings, &scene);
	sim_inputs.numRays = 2048;
	sim_inputs.numBounces = 32;
	sim_inputs.duration = 2.0f;
	sim_inputs.order = 2;
	sim_inputs.irradianceMinDistance = 1.0f;
	add_material("air", 0, 0, 0, 0, 1, 1, 1);
	add_material("generic", 0.10f, 0.20f, 0.30f, 0.05f, 0.100f, 0.050f, 0.030f);
	add_material("brick", 0.03f, 0.04f, 0.07f, 0.05f, 0.015f, 0.015f, 0.015f);
	add_material("concrete", 0.05f, 0.07f, 0.08f, 0.05f, 0.015f, 0.002f, 0.001f);
	add_material("ceramic", 0.01f, 0.02f, 0.02f, 0.05f, 0.060f, 0.044f, 0.011f);
	add_material("gravel", 0.60f, 0.70f, 0.80f, 0.05f, 0.031f, 0.012f, 0.008f);
	add_material("carpet", 0.24f, 0.69f, 0.73f, 0.05f, 0.020f, 0.005f, 0.003f);
	add_material("glass", 0.06f, 0.03f, 0.02f, 0.05f, 0.060f, 0.044f, 0.011f);
	add_material("plaster", 0.12f, 0.06f, 0.04f, 0.05f, 0.056f, 0.056f, 0.004f);
	add_material("wood", 0.11f, 0.07f, 0.06f, 0.05f, 0.070f, 0.014f, 0.005f);
	add_material("metal", 0.20f, 0.07f, 0.06f, 0.05f, 0.200f, 0.025f, 0.010f);
	add_material("rock", 0.13f, 0.20f, 0.24f, 0.05f, 0.015f, 0.002f, 0.001f);
	iplSimulatorSetScene(sim, scene);
	iplSimulatorCommit(sim);
	env_thread = thread_create(sound_environment_thread, this, THREAD_STACK_SIZE_DEFAULT);
}
sound_environment::~sound_environment() {
	asAtomicDec(ref_count); // ref_count < 0 shuts down thread.
	thread_join(env_thread);
	iplSceneRelease(&scene);
	iplSimulatorRelease(&sim);
}
void sound_environment::add_ref() {
	asAtomicInc(ref_count);
}
void sound_environment::release() {
	if (asAtomicDec(ref_count) < 1)
		delete this;
}
bool sound_environment::add_material(const std::string& name, float absorption_low, float absorption_mid, float absorption_high, float scattering, float transmission_low, float transmission_mid, float transmission_high, bool replace_if_existing) {
	if (!replace_if_existing && materials.find(name) != materials.end()) return false;
	materials[name] = IPLMaterial{{absorption_low, absorption_mid, absorption_high}, scattering, {transmission_low, transmission_mid, transmission_high}};
	return true;
}
bool sound_environment::add_box(const std::string& material, float minx, float maxx, float miny, float maxy, float minz, float maxz) {
	if (materials.find(material) == materials.end()) return false;
	IPLVector3 vertices[8] = {
		{minx, miny, minz},
		{maxx, miny, minz},
		{maxx, maxy, minz},
		{minx, maxy, minz},
		{minx, miny, maxz},
		{maxx, miny, maxz},
		{maxx, maxy, maxz},
		{minx, maxy, maxz}
	};
	IPLTriangle triangles[12] = {
		// floor
		{0, 1, 2},
		{0, 2, 3},
		// back wall
		{0, 1, 5},
		{0, 5, 4},
		// right wall
		{1, 5, 6},
		{1, 6, 2},
		// front wall
		{2, 6, 7},
		{2, 7, 3},
		// left wall
		{3, 7, 0},
		{3, 0, 4},
		// roof
		{4, 5, 6},
		{4, 6, 7},
	};
	IPLint32 material_indexes[12] = {0};
	IPLStaticMeshSettings mesh_settings{8, 12, 1, vertices, triangles, material_indexes, & materials[material]};
	IPLStaticMesh mesh = NULL;
	iplStaticMeshCreate(scene, &mesh_settings, &mesh);
	iplStaticMeshAdd(mesh, scene);
	scene_needs_commit = true;
	return true;
}
bool sound_environment::attach(sound_base* s) {
	if (!s || s->env) return false;
	IPLDirectEffectSettings direct_effect_settings{1};
	iplDirectEffectCreate(phonon_context, &phonon_audio_settings, &direct_effect_settings, &s->direct_effect);
	IPLReflectionEffectSettings reflection_effect_settings{IPL_REFLECTIONEFFECTTYPE_CONVOLUTION, 88200, 9};
	iplReflectionEffectCreate(phonon_context, &phonon_audio_settings, &reflection_effect_settings, &s->reflection_effect);
	IPLAmbisonicsDecodeEffectSettings dec_settings{};
	dec_settings.maxOrder = 2;
	dec_settings.hrtf = phonon_hrtf_reflections;
	dec_settings.speakerLayout = IPLSpeakerLayout{IPL_SPEAKERLAYOUTTYPE_STEREO};
	iplAmbisonicsDecodeEffectCreate(phonon_context, &phonon_audio_settings, &dec_settings, &s->reflection_decode_effect);
	IPLSourceSettings source_settings{IPLSimulationFlags(IPL_SIMULATIONFLAGS_DIRECT | IPL_SIMULATIONFLAGS_REFLECTIONS)};
	iplSourceCreate(sim, &source_settings, &s->source);
	IPLSimulationInputs inputs{};
	inputs.flags = IPLSimulationFlags(IPL_SIMULATIONFLAGS_DIRECT | IPL_SIMULATIONFLAGS_REFLECTIONS);
	inputs.directFlags = IPLDirectSimulationFlags(IPL_DIRECTSIMULATIONFLAGS_DISTANCEATTENUATION | IPL_DIRECTSIMULATIONFLAGS_AIRABSORPTION | IPL_DIRECTSIMULATIONFLAGS_OCCLUSION | IPL_DIRECTSIMULATIONFLAGS_TRANSMISSION);
	inputs.distanceAttenuationModel = IPLDistanceAttenuationModel{IPL_DISTANCEATTENUATIONTYPE_DEFAULT};
	inputs.airAbsorptionModel = IPLAirAbsorptionModel{IPL_AIRABSORPTIONTYPE_DEFAULT};
	inputs.source = IPLCoordinateSpace3{IPLVector3{1, 0, 0}, IPLVector3{0, 0, 1}, IPLVector3{0, 1, 0}, IPLVector3{s->x, s->y, s->z}};
	inputs.occlusionType = IPL_OCCLUSIONTYPE_RAYCAST;
	iplSourceSetInputs(s->source, IPLSimulationFlags(IPL_SIMULATIONFLAGS_DIRECT | IPL_SIMULATIONFLAGS_REFLECTIONS), &inputs);
	iplSourceAdd(s->source, sim);
	iplSimulatorCommit(sim);
	s->env = this;
	this->add_ref();
	attached.push_back(s);
	return true;
}
bool sound_environment::_detach(sound_base* s) {
	iplSourceRemove(s->source, sim);
	iplSimulatorCommit(sim);
	iplAmbisonicsDecodeEffectRelease(&s->reflection_decode_effect);
	iplReflectionEffectRelease(&s->reflection_effect);
	iplDirectEffectRelease(&s->direct_effect);
	iplSourceRelease(&s->source);
	s->source = NULL;
	s->reflection_decode_effect = NULL;
	s->reflection_effect = NULL;
	s->direct_effect = NULL;
	s->env = NULL;
	// Todo: Consider switching to some sort of map for faster removal?
	auto it = std::find(attached.begin(), attached.end(), s);
	if (it != attached.end()) attached.erase(it);
	if (ref_count > 0) s->env_detaching.set();
	return true;
}
void sound_environment::_detach_all() {
	for (sound_base * s : attached) _detach(s);
}
bool sound_environment::detach(sound_base* s) {
	if (!s || s->env != this) return false;
	s->env = NULL;
	detaching.push_back(s);
	s->env_detaching.wait();
	if (ref_count > 0) this->release();
	return true;
}
legacy_mixer* sound_environment::new_mixer() {
	legacy_mixer* s = new legacy_mixer();
	s->use_hrtf = true;
	attach(s);
	if (!s->pos_effect) s->pos_effect = BASS_ChannelSetDSP(s->channel, positioning_dsp, s, 0);
	return s;
}
legacy_sound* sound_environment::new_sound() {
	legacy_sound* s = new legacy_sound();
	attach(s);
	return s;
}
void sound_environment::update() {
	iplSimulatorRunDirect(sim);
}
void sound_environment::background_update() {
	for (sound_base * s : detaching) {
		_detach(s);
		if (ref_count < 1) return;
	}
	detaching.clear();
	if (scene_needs_commit) {
		iplSceneCommit(scene);
		iplSimulatorCommit(sim);
		scene_needs_commit = false;
	}
	if (listener_modified) {
		sim_inputs.listener.right = IPLVector3{1, 0, 0};
		sim_inputs.listener.up = IPLVector3{0, 0, 1};
		sim_inputs.listener.ahead = IPLVector3{sin(listener_rotation), cos(listener_rotation), 0};
		sim_inputs.listener.origin = IPLVector3{listener_x, listener_y, listener_z};
		iplSimulatorSetSharedInputs(sim, IPLSimulationFlags(IPL_SIMULATIONFLAGS_DIRECT | IPL_SIMULATIONFLAGS_REFLECTIONS), &sim_inputs);
		iplSimulatorCommit(sim);
		listener_modified = false;
		iplSimulatorRunReflections(sim);
	}
	iplSimulatorRunReflections(sim);
}
void sound_environment::set_listener(float x, float y, float z, float rotation) {
	listener_x = x;
	listener_y = y;
	listener_z = z;
	listener_rotation = rotation;
	listener_modified = true;
}


legacy_sound::legacy_sound() {
	RefCount = 1;
	channel = 0;
	memset(&channel_info, 0, sizeof(BASS_CHANNELINFO));
	pitch = 1.0;
	length = 0.0;
	x = 0.0;
	y = 0.0;
	z = 0.0;
	listener_x = 0.0;
	listener_y = 0.0;
	listener_z = 0.0;
	rotation = 0.0;
	last_x = 1.0;
	last_y = 1.0;
	last_z = 1.0;
	last_rotation = 0.0;
	pan_step = 1;
	volume_step = 1;
	hrtf_effect = NULL;
	pos_effect = 0;
	use_hrtf = TRUE;
	output_mixer = NULL;
	parent_mixer = NULL;
	preload_ref = NULL;
	close_callback = NULL;
	len_callback = NULL;
	read_callback = NULL;
	seek_callback = NULL;
	callback_data = "";
	script_loading = FALSE;
	closing.store(false);
	thread_mutex_init(&close_mutex);
	memstream = NULL;
	memstream_size = 0;
	memstream_pos = 0;
	memstream_legacy_encrypt = false;
}
legacy_sound::~legacy_sound() {
	if (!sound_initialized)
		return;
	close();
}
void sound_base::AddRef() {
	asAtomicInc(RefCount);
}
void sound_base::Release() {
	if (asAtomicDec(RefCount) < 1) delete this;
}
void legacy_sound::Release() {
	if (asAtomicDec(RefCount) < 1) {
		close();
		thread_mutex_term(&close_mutex);
		delete this;
	}
}

BOOL legacy_sound::load(const string& filename, legacy_pack* containing_pack, BOOL allow_preloads) {
	if (!sound_initialized)
		init_sound();
	if (!sound_initialized)
		return FALSE;
	if (channel)
		close();
	if (strnicmp(filename.c_str(), "http://", 7) == 0 || strnicmp(filename.c_str(), "https:///", 8) == 0 || strnicmp(filename.c_str(), "ftp://", 6) == 0)
		return load_url(filename);
	channel = 0;
	closing.store(false);
	sound_preload* pre = (allow_preloads ? get_sound_preload(filename) : NULL);
	if (pre != NULL && pre->from_file) {
		// Cached from a plain file: only reuse it while that file is still the one we read.
		unsigned long long mtime = 0;
		unsigned int fsize = 0;
		if (!sound_file_stamp(filename, mtime, fsize) || mtime != pre->mtime || fsize != pre->fsize) {
			sound_preload_invalidate(pre);
			pre = NULL;
		}
	}
	if (pre != NULL) {
		preload_ref = pre; // get_sound_preload already took a reference for us
		if (pre->data && pre->size)
			channel = BASS_StreamCreateFile(TRUE, pre->data, 0, pre->size, BASS_SAMPLE_FLOAT | BASS_STREAM_DECODE);
		if (!channel) {
			sound_preload_release(pre);
			preload_ref = NULL;
		}
	}
	if (!channel && allow_preloads && containing_pack && containing_pack->is_active()) {
		// First play of a pack member: read its bytes once, here, on the loading thread, and
		// play from memory. The audio thread then never touches the pack, its FILE*, or the
		// de-obfuscation loop, and the very same bytes become the cache entry for next time.
		// A member too large to read inside a frame is handed to the background filler: this
		// play streams, and the one after it comes from memory like everything else.
		unsigned int member_size = containing_pack->get_file_size(filename);
		if (member_size > SOUND_PRELOAD_SYNC_MAX && member_size <= SOUND_PRELOAD_MAX_ITEM)
			sound_preload_fill_later(filename, containing_pack);
		unsigned int size = 0;
		unsigned char* data = sound_read_pack_member(containing_pack, filename, size, SOUND_PRELOAD_SYNC_MAX);
		if (data) {
			data = sound_promote_short(data, size);
			pre = sound_preload_insert(filename, data, size);
			if (pre) {
				preload_ref = pre;
				channel = BASS_StreamCreateFile(TRUE, pre->data, 0, pre->size, BASS_SAMPLE_FLOAT | BASS_STREAM_DECODE);
				if (!channel) {
					sound_preload_release(pre);
					preload_ref = NULL;
				}
			}
		}
	}
	if (!channel && allow_preloads && (!containing_pack || !containing_pack->is_active() || !containing_pack->file_exists(filename))) {
		// Not a pack member: read the file from disk once, here, and play it from memory. Without
		// this a sound loaded by path would be re-read by the audio thread on every single play.
		unsigned int stamp_size = 0;
		unsigned long long stamp_mtime = 0;
		if (sound_file_stamp(filename, stamp_mtime, stamp_size) && stamp_size > SOUND_PRELOAD_SYNC_MAX && stamp_size <= SOUND_PRELOAD_MAX_ITEM)
			sound_preload_fill_later(filename, NULL);
		unsigned int size = 0;
		unsigned long long mtime = 0;
		unsigned char* data = sound_read_disk_file(filename, size, mtime, SOUND_PRELOAD_SYNC_MAX);
		if (data) {
			unsigned int on_disk = size;
			data = sound_promote_short(data, size);
			pre = sound_preload_insert(filename, data, size, true, mtime, on_disk);
			if (pre) {
				preload_ref = pre;
				channel = BASS_StreamCreateFile(TRUE, pre->data, 0, pre->size, BASS_SAMPLE_FLOAT | BASS_STREAM_DECODE);
				if (!channel) {
					sound_preload_release(pre);
					preload_ref = NULL;
				}
			}
		}
	}
	if (!channel) {
		pack_stream* stream = NULL;
		if (!containing_pack || !containing_pack->is_active() || (stream = containing_pack->stream_open(filename, 0)) == NULL) {
			#ifdef WIN32
			// aww I guess bass decided to contribute to the pain of the no UTF8 paths on windows rather than helping developers work around it like everyone else seems to do, so manually convert the UTF8 sound path to UTF16 here. Ugh ugh!
			std::wstring filename_u;
			Poco::UnicodeConverter::convert(filename, filename_u);
			channel = BASS_StreamCreateFile(FALSE, filename_u.c_str(), 0, 0, BASS_STREAM_DECODE | BASS_SAMPLE_FLOAT | BASS_UNICODE);
			#else
			channel = BASS_StreamCreateFile(FALSE, filename.c_str(), 0, 0, BASS_STREAM_DECODE | BASS_SAMPLE_FLOAT);
			#endif
		} else {
			// Too large for the cache (or caching disabled): stream it straight from the pack.
			script_loading = TRUE;
			BASS_FILEPROCS prox;
			prox.close = bass_closeproc_pack;
			prox.length = bass_lenproc_pack;
			prox.read = bass_readproc_pack;
			prox.seek = bass_seekproc_pack;
			packed_sound* s = (packed_sound*)malloc(sizeof(packed_sound));
			s->p = containing_pack;
			s->s = stream;
			s->snd = this;
			channel = BASS_StreamCreateFileUser(STREAMFILE_NOBUFFER, BASS_STREAM_DECODE | BASS_SAMPLE_FLOAT, &prox, s);
		}
	}
	if (containing_pack) containing_pack->Release();
	return postload(filename);
}

BOOL legacy_sound::load_script(asIScriptFunction* close, asIScriptFunction* len, asIScriptFunction* read, asIScriptFunction* seek, const std::string& data, const std::string& preload_filename) {
	if (!sound_initialized)
		init_sound();
	if (!sound_initialized)
		return FALSE;
	if (channel)
		this->close();
	sound_preload* pre = (preload_filename != "" ? get_sound_preload(preload_filename) : NULL);
	if (pre != NULL) {
		preload_ref = pre; // get_sound_preload already took a reference for us
		if (pre->data && pre->size)
			channel = BASS_StreamCreateFile(TRUE, pre->data, 0, pre->size, BASS_SAMPLE_FLOAT | BASS_STREAM_DECODE);
		if (!channel) {
			sound_preload_release(pre);
			preload_ref = NULL;
		}
		if (channel) {
			if (close) close->Release();
			if (len) len->Release();
			if (read) read->Release();
			if (seek) seek->Release();
		}
	}
	if (!channel) {
		if (close_callback) close_callback->Release();
		if (len_callback) len_callback->Release();
		if (read_callback) read_callback->Release();
		if (seek_callback) seek_callback->Release();
		close_callback = close;
		len_callback = len;
		read_callback = read;
		seek_callback = seek;
		BASS_FILEPROCS prox;
		prox.close = bass_closeproc_script;
		prox.length = bass_lenproc_script;
		prox.read = bass_readproc_script;
		prox.seek = bass_seekproc_script;
		script_loading = TRUE;
		channel = BASS_StreamCreateFileUser(STREAMFILE_NOBUFFER, BASS_STREAM_DECODE | BASS_SAMPLE_FLOAT, &prox, this);
		if (preload_filename != "" && channel && !pre)
			sound_preload_capture_pcm(channel, preload_filename);
	}
	return postload(preload_filename != "" ? preload_filename : "script_stream");
}

BOOL legacy_sound::load_memstream(string& data, unsigned int size, const std::string& preload_filename, bool legacy_encrypt) {
	if (!sound_initialized)
		init_sound();
	if (!sound_initialized)
		return FALSE;
	if (channel)
		this->close();
	sound_preload* pre = (preload_filename != "" ? get_sound_preload(preload_filename) : NULL);
	if (pre != NULL) {
		preload_ref = pre; // get_sound_preload already took a reference for us
		if (pre->data && pre->size)
			channel = BASS_StreamCreateFile(TRUE, pre->data, 0, pre->size, BASS_SAMPLE_FLOAT | BASS_STREAM_DECODE);
		if (!channel) {
			sound_preload_release(pre);
			preload_ref = NULL;
		}
	}
	if (!channel) {
		BASS_FILEPROCS prox;
		prox.close = bass_closeproc_push;
		prox.length = bass_lenproc_push;
		prox.read = bass_readproc_push;
		prox.seek = bass_seekproc_push;
		memstream = &data;
		memstream_size = size;
		memstream_pos = 0;
		memstream_legacy_encrypt = legacy_encrypt;
		script_loading = TRUE;
		channel = BASS_StreamCreateFileUser(STREAMFILE_NOBUFFER, BASS_STREAM_DECODE | BASS_SAMPLE_FLOAT, &prox, this);
		if (preload_filename != "" && channel && !pre)
			sound_preload_capture_pcm(channel, preload_filename);
	}
	return postload(preload_filename != "" ? preload_filename : "script_stream");
}

BOOL legacy_sound::load_url(const string& url) {
	if (!sound_initialized)
		init_sound();
	if (!sound_initialized)
		return FALSE;
	if (channel)
		this->close();
	channel = BASS_StreamCreateURL(url.c_str(), 0, BASS_STREAM_DECODE | BASS_SAMPLE_FLOAT, NULL, NULL);
	return postload(url);
}

BOOL legacy_sound::push_memory(unsigned char* buffer, unsigned int length, BOOL stream_end, int pcm_rate, int pcm_chans) {
	if (!sound_initialized)
		init_sound();
	if (!sound_initialized || !stream_end && length < 1)
		return FALSE;
	if (loaded_filename != "") {
		if (length > 0)
			close();
		else
			return FALSE;
	}
	if (!buffer || !channel && length < 768)
		return FALSE;
	if (!channel) {
		if (!pcm_rate) {
			BASS_FILEPROCS prox;
			prox.close = bass_closeproc_push;
			prox.length = bass_lenproc_push;
			prox.read = bass_readproc_push;
			prox.seek = bass_seekproc_push;
			push_prebuff.insert(push_prebuff.end(), buffer, buffer + length);
			channel = BASS_StreamCreateFileUser(STREAMFILE_BUFFER, BASS_STREAM_DECODE | BASS_SAMPLE_FLOAT, &prox, this);
			BASS_ChannelSetAttribute(channel, BASS_ATTRIB_NET_RESUME, 20);
		} else {
			push_prebuff.insert(push_prebuff.end(), buffer, buffer + length);
			channel = BASS_StreamCreate(pcm_rate, pcm_chans, BASS_STREAM_DECODE | BASS_SAMPLE_FLOAT, STREAMPROC_PUSH, NULL);
		}
		if (!postload())
			return FALSE;
		if (push_prebuff.size() > 0 && pcm_rate) {
			BASS_StreamPutData(channel, buffer + (length - push_prebuff.size()), push_prebuff.size());
			push_prebuff.clear();
			if (stream_end)
				BASS_StreamPutData(channel, NULL, BASS_STREAMPROC_END);
		}
		return TRUE;
	}
	bool ret = true;
	if (!pcm_rate)
		push_prebuff.insert(push_prebuff.end(), buffer, buffer + length);
	else {
			ret = BASS_StreamPutData(channel, buffer, length) > 0;
			if (stream_end)
				BASS_StreamPutData(channel, NULL, BASS_STREAMPROC_END);
	}
	return ret;
}
BOOL legacy_sound::push_string(const std::string& buffer, BOOL stream_end, int pcm_rate, int pcm_chans) {
	return push_memory((unsigned char*)&buffer[0], buffer.size(), stream_end, pcm_rate, pcm_chans);
}

BOOL legacy_sound::postload(const string& filename) {
	LOCK_MIXER_GRAPH();
	if (!channel)
		return FALSE;
	closing.store(false, std::memory_order_release); // every load path ends here, so a reused object is live again
	silent_frames = 0;
	BASS_ChannelGetInfo(channel, &channel_info);
	loaded_filename = filename;
	if (hrtf && phonon_context && !hrtf_effect) {
		IPLBinauralEffectSettings effect_settings{};
		effect_settings.hrtf = phonon_hrtf;
		iplBinauralEffectCreate(phonon_context, &phonon_audio_settings, &effect_settings, &hrtf_effect);
	}
	if (!parent_mixer)
		parent_mixer = g_default_mixer? g_default_mixer : output;
	if (!output_mixer) {
		output_mixer = new legacy_mixer(parent_mixer, !env);
		if (listener_x != x || listener_y != y || listener_z != z || env)
			pos_effect = BASS_ChannelSetDSP(output_mixer->channel, positioning_dsp, this, 0);
	} else if (!pos_effect && (listener_x != x || listener_y != y || listener_z != z || env))
		pos_effect = BASS_ChannelSetDSP(output_mixer->channel, positioning_dsp, this, 0);
	store_channel = register_hstream(channel);
	output_mixer->add_sound(*this, TRUE);
	script_loading = FALSE;
	return TRUE;
}

BOOL legacy_sound::close() {
	LOCK_MIXER_GRAPH();
	if (close_callback) close_callback->Release();
	if (len_callback) len_callback->Release();
	if (read_callback) read_callback->Release();
	if (seek_callback) seek_callback->Release();
	close_callback = NULL;
	len_callback = NULL;
	read_callback = NULL;
	seek_callback = NULL;
	if (channel) {
		closing.store(true, std::memory_order_release);
		stop();
		thread_mutex_lock(&close_mutex);
		HSTREAM dead_mixer = 0;
		if (output_mixer) {
			// Detaching from the parent mixer is what actually silences the sound, and BASSmix
			// synchronises that with its own processing, so after this point the audio thread
			// no longer runs this sound's DSP and the effect below can be released safely.
			// Internal removal: the non-internal path would re-attach the about-to-be-deleted mixer to the global output, leaving a dangling entry there.
			if (parent_mixer)
				parent_mixer->remove_mixer(output_mixer, TRUE);
			output_mixer->remove_sound(*this, TRUE);
			BASS_Mixer_ChannelRemove(channel);
			dead_mixer = output_mixer->channel;
			output_mixer->channel = 0;
			delete output_mixer;
			output_mixer = NULL;
		}
		pos_effect = 0; // dies with the mixer stream it was set on
		if (hrtf_effect) {
			iplBinauralEffectReset(hrtf_effect);
			iplBinauralEffectRelease(&hrtf_effect);
		}
		hrtf_effect = NULL;
		if (env) env->detach(this);
		// Freeing the BASS streams waits for the audio thread; do it off the game thread.
		sound_reaper_push(dead_mixer);
		sound_reaper_push(channel, preload_ref);
		preload_ref = NULL; // released by the reaper once the stream that reads it is gone
		unregister_hstream(store_channel);
		store_channel = NULL; // that node is freed now: leaving the pointer behind lets a close() landing before the next postload re-registers free the very same node a second time, which corrupts the heap and takes down some later, unrelated free()
		channel = 0;
		thread_mutex_unlock(&close_mutex);
		length = 0;
		memset(&channel_info, 0, sizeof(BASS_CHANNELINFO));
		loaded_filename = "";
		push_prebuff.clear();
		memstream = NULL;
		memstream_size = 0;
		memstream_pos = 0;
		memstream_legacy_encrypt = false;
		pitch = 1.0;
		sound_preloads_clean();
		return TRUE;
	}
	return false;
}

int legacy_sound::set_fx(const std::string& fx, int idx) {
	LOCK_MIXER_GRAPH();
	if (!output_mixer)
		output_mixer = new legacy_mixer(parent_mixer, TRUE);
	if (!output_mixer)
		return -1;
	return output_mixer->set_fx(fx, idx);
}

BOOL legacy_sound::set_mixer(legacy_mixer* m) {
	LOCK_MIXER_GRAPH();
	if (!m)
		m = output;
	if (output_mixer) {
		if (parent_mixer)
			parent_mixer->remove_mixer(output_mixer, TRUE);
		if (m && m->add_mixer(output_mixer))
			parent_mixer = m;
		else
			parent_mixer = output; // the attach failed: fall back to the root mixer rather than keeping a link to one that no longer holds us and may be destroyed first
		return parent_mixer == m;
	}
	parent_mixer = m;
	return m != NULL;
}

void sound_base::set_hrtf(BOOL enable) {
	use_hrtf = enable;
	// The binaural effect must exist before the audio thread wants it (creating it there meant a
	// malloc inside the callback), so make it here, on the caller's thread, if it is being enabled
	// after the sound was loaded - which is exactly what sound_pool does.
	if (enable && hrtf && phonon_context && !hrtf_effect) {
		IPLBinauralEffectSettings effect_settings{};
		effect_settings.hrtf = phonon_hrtf;
		iplBinauralEffectCreate(phonon_context, &phonon_audio_settings, &effect_settings, &hrtf_effect);
	}
}
BOOL sound_base::set_position(float listener_x, float listener_y, float listener_z, float sound_x, float sound_y, float sound_z, float rotation, float pan_step, float volume_step) {
	this->listener_x = listener_x;
	this->listener_y = listener_y;
	this->listener_z = listener_z;
	this->x = sound_x;
	this->y = sound_y;
	this->z = sound_z;
	this->rotation = rotation;
	this->pan_step = pan_step;
	this->volume_step = volume_step;
	if (x == listener_x && y == listener_y && z == listener_z && !env) {
		if (pos_effect) {
			BASS_ChannelRemoveDSP(output_mixer ? output_mixer->channel : channel, pos_effect);
			if (hrtf_effect)
				iplBinauralEffectReset(hrtf_effect);
			pos_effect = 0;
		}
	} else if (!pos_effect)
		pos_effect = BASS_ChannelSetDSP(output_mixer ? output_mixer->channel : channel, positioning_dsp, this, 0);
	if (source && env->sim) {
		IPLSimulationInputs inputs{};
		inputs.flags = IPLSimulationFlags(IPL_SIMULATIONFLAGS_DIRECT | IPL_SIMULATIONFLAGS_REFLECTIONS);
		inputs.directFlags = IPLDirectSimulationFlags(IPL_DIRECTSIMULATIONFLAGS_DISTANCEATTENUATION | IPL_DIRECTSIMULATIONFLAGS_AIRABSORPTION | IPL_DIRECTSIMULATIONFLAGS_OCCLUSION | IPL_DIRECTSIMULATIONFLAGS_TRANSMISSION);
		inputs.distanceAttenuationModel = IPLDistanceAttenuationModel{IPL_DISTANCEATTENUATIONTYPE_DEFAULT};
		inputs.airAbsorptionModel = IPLAirAbsorptionModel{IPL_AIRABSORPTIONTYPE_DEFAULT};
		inputs.source = IPLCoordinateSpace3{IPLVector3{1, 0, 0}, IPLVector3{0, 0, 1}, IPLVector3{0, 1, 0}, IPLVector3{sound_x, sound_y, sound_z}};
		inputs.occlusionType = IPL_OCCLUSIONTYPE_RAYCAST;
		iplSourceSetInputs(source, IPLSimulationFlags(IPL_SIMULATIONFLAGS_DIRECT | IPL_SIMULATIONFLAGS_REFLECTIONS), &inputs);
		iplSimulatorCommit(env->sim);
	}
	return TRUE;
}

BOOL legacy_sound::play(bool reset_loop_state) {
	if (!channel)
		return FALSE;
	if (loaded_filename != "" && is_playing())
		return FALSE;
	if (BASS_ChannelIsActive(channel) != BASS_ACTIVE_PLAYING)
		BASS_Mixer_ChannelSetPosition(channel, 0, BASS_POS_BYTE);
	if (reset_loop_state) BASS_ChannelFlags(channel, 0, BASS_SAMPLE_LOOP);
	return !(BASS_Mixer_ChannelFlags(channel, 0, BASS_MIXER_CHAN_PAUSE)&BASS_MIXER_CHAN_PAUSE);
}

BOOL legacy_sound::play_wait() {
	if (!play())
		return FALSE;
	QWORD pos = BASS_Mixer_ChannelGetPosition(channel, BASS_POS_BYTE);
	QWORD len = BASS_ChannelGetLength(channel, BASS_POS_BYTE);
	if (len - pos < 0)
		return FALSE;
	double time_to_sleep = BASS_ChannelBytes2Seconds(channel, len - pos) / get_pitch();
	nvgt_wait(time_to_sleep * 1000);
	return TRUE;
}

BOOL legacy_sound::play_looped() {
	if (!play())
		return FALSE;
	BASS_ChannelFlags(channel, BASS_SAMPLE_LOOP, BASS_SAMPLE_LOOP);
	return TRUE;
}

BOOL legacy_sound::pause() {
	if (!channel)
		return FALSE;
	if (!is_playing())
		return FALSE;
	BOOL ret = (BASS_Mixer_ChannelFlags(channel, BASS_MIXER_CHAN_PAUSE, BASS_MIXER_CHAN_PAUSE)&BASS_MIXER_CHAN_PAUSE) > 0;
	if (ret && hrtf && hrtf_effect)
		iplBinauralEffectReset(hrtf_effect);
	return ret;
}

BOOL legacy_sound::seek(float offset) {
	if (!channel)
		return FALSE;
	QWORD bytes = BASS_ChannelSeconds2Bytes(channel, offset / 1000);
	BOOL ret = BASS_Mixer_ChannelSetPosition(channel, bytes, BASS_POS_BYTE);
	if (ret && hrtf && hrtf_effect)
		iplBinauralEffectReset(hrtf_effect);
	return ret;
}

BOOL legacy_sound::stop() {
	if (!channel)
		return FALSE;
	BOOL ret = (BASS_Mixer_ChannelFlags(channel, BASS_MIXER_CHAN_PAUSE, BASS_MIXER_CHAN_PAUSE)&BASS_MIXER_CHAN_PAUSE) > 0;
	BASS_Mixer_ChannelSetPosition(channel, 0, BASS_POS_BYTE);
	if (ret && hrtf && hrtf_effect)
		iplBinauralEffectReset(hrtf_effect);
	return ret;
}

BOOL legacy_sound::is_active() {
	return channel > 0 && parent_mixer != NULL;
}

BOOL legacy_sound::is_paused() {
	return channel > 0 && parent_mixer && (BASS_Mixer_ChannelFlags(channel, BASS_MIXER_CHAN_PAUSE, 0)&BASS_MIXER_CHAN_PAUSE) > 0;
}

BOOL legacy_sound::is_playing() {
	return channel > 0 && parent_mixer && output_mixer && BASS_ChannelIsActive(channel) == BASS_ACTIVE_PLAYING && BASS_Mixer_ChannelGetMixer(channel) == output_mixer->channel && BASS_Mixer_ChannelGetMixer(output_mixer->channel) == parent_mixer->channel && !(BASS_Mixer_ChannelFlags(channel, 0, 0)&BASS_MIXER_CHAN_PAUSE);
}

BOOL legacy_sound::is_sliding() {
	return channel > 0 && BASS_ChannelIsSliding(channel, 0) || output_mixer && output_mixer->channel && BASS_ChannelIsSliding(output_mixer->channel, 0);
}

BOOL legacy_sound::is_pan_sliding() {
	return channel > 0 && BASS_ChannelIsSliding(channel, BASS_ATTRIB_PAN);
}

BOOL legacy_sound::is_pitch_sliding() {
	return channel > 0 && BASS_ChannelIsSliding(channel, BASS_ATTRIB_FREQ);
}

BOOL legacy_sound::is_volume_sliding() {
	return channel > 0 && output_mixer && BASS_ChannelIsSliding(output_mixer->channel, BASS_ATTRIB_VOL);
}

float legacy_sound::get_length() {
	if (!channel)
		return -1;
	if (length > 0) return length / 1000.0;
	QWORD length;
	if (loaded_filename != "")
		length = BASS_ChannelGetLength(channel, BASS_POS_BYTE);
	else
		length = BASS_ChannelGetData(channel, NULL, BASS_DATA_AVAILABLE);
	if (length > 0)
		return BASS_ChannelBytes2Seconds(channel, length);
	else
		return -1;
}
float legacy_sound::get_length_ms() {
	float v = get_length();
	if (v > -1) v *= 1000;
	return v;
}

float legacy_sound::get_position() {
	if (!channel)
		return -1;
	QWORD pos = BASS_ChannelGetPosition(channel, BASS_POS_BYTE);
	if (pos > 0)
		return BASS_ChannelBytes2Seconds(channel, pos);
	else
		return -1;
}
float legacy_sound::get_position_ms() {
	float v = get_position();
	if (v > -1) v *= 1000;
	return v;
}

float legacy_sound::get_pan() {
	if (!channel)
		return 0;
	float pan = 0;
	BASS_ChannelGetAttribute(channel, BASS_ATTRIB_PAN, &pan);
	return pan;
}
float legacy_sound::get_pan_alt() {
	return get_pan() * 100;
}

float legacy_sound::get_pitch() {
	if (!channel)
		return 0;
	float pitch = 0.0;
	if (!BASS_ChannelGetAttribute(channel, BASS_ATTRIB_FREQ, &pitch))
		return 0.0;
	pitch /= channel_info.freq;
	return pitch;
}
float legacy_sound::get_pitch_alt() {
	return get_pitch() * 100;
}

float legacy_sound::get_volume() {
	if (!channel)
		return 0;
	float volume = 0;
	if (output_mixer)
		return output_mixer->get_volume();
	BASS_ChannelGetAttribute(channel, BASS_ATTRIB_VOL, &volume);
	return volume;
}
float legacy_sound::get_volume_alt() {
	return (get_volume() * 100) - 100;
}

BOOL legacy_sound::set_pan(float pan) {
	if (!channel)
		return FALSE;
	if (pan < -1.0 || pan > 1.0)
		return FALSE;
	return BASS_ChannelSetAttribute(channel, BASS_ATTRIB_PAN, pan);
}
BOOL legacy_sound::set_pan_alt(float pan) {
	return set_pan(pan / 100);
}

BOOL legacy_sound::slide_pan(float pan, unsigned int time) {
	if (!channel)
		return FALSE;
	if (pan < -1.0 || pan > 1.0)
		return FALSE;
	return BASS_ChannelSlideAttribute(channel, BASS_ATTRIB_PAN, pan, time);
}
BOOL legacy_sound::slide_pan_alt(float pan, unsigned int time) {
	return slide_pan(pan / 100, time);
}

BOOL legacy_sound::set_pitch(float pitch) {
	if (!channel)
		return FALSE;
	if (pitch < 0.05 || pitch > 5.0) return false;
	BASS_ChannelLock(channel, TRUE);
	BOOL r = BASS_ChannelSetAttribute(channel, BASS_ATTRIB_FREQ, channel_info.freq * pitch);
	BASS_ChannelLock(channel, FALSE);
	return r;
}
BOOL legacy_sound::set_pitch_alt(float pitch) {
	return set_pitch(pitch / 100);
}

BOOL legacy_sound::slide_pitch(float pitch, unsigned int time) {
	if (!channel)
		return FALSE;
	if (pitch < 0.05 || pitch > 5.0) return false;
	return BASS_ChannelSlideAttribute(channel, BASS_ATTRIB_FREQ, channel_info.freq * pitch, time);
}
BOOL legacy_sound::slide_pitch_alt(float pitch, unsigned int time) {
	return slide_pitch(pitch / 100, time);
}

BOOL legacy_sound::set_volume(float volume) {
	if (!channel)
		return FALSE;
	if (volume < 0) volume = 0.0;
	if (volume > 1) volume = 1.0;
	if (output_mixer)
		return output_mixer->set_volume(volume);
	else
		return BASS_ChannelSetAttribute(channel, BASS_ATTRIB_VOL, volume);
}
BOOL legacy_sound::set_volume_alt(float volume) {
	return set_volume((volume + 100) / 100);
}

BOOL legacy_sound::slide_volume(float volume, unsigned int time) {
	if (!channel)
		return FALSE;
	if (volume < 0.0 || volume > 1.0)
		return FALSE;
	if (output_mixer)
		return output_mixer->slide_volume(volume, time);
	else
		return BASS_ChannelSlideAttribute(channel, BASS_ATTRIB_VOL, volume, time);
}
BOOL legacy_sound::slide_volume_alt(float volume, unsigned int time) {
	return slide_volume((volume + 100) / 100, time);
}
/**
 * A dummy version of sound.pitch_lower_limit that just returns const 0 all the time.
 * Since this is not using legacy DirectSound there's no need for this API except for BGT compat.
 */
const double legacy_sound::pitch_lower_limit()
{
	return 0;
}

int legacy_mixer::get_effect_index(const std::string& id) {
	if (id.size() < 2) return -1;
	for (DWORD i = 0; i < effects.size(); i++) {
		if (effects[i].id == id) return i;
	}
	return -1;
}

legacy_mixer::legacy_mixer(legacy_mixer* parent, BOOL for_single_sound, BOOL for_decode, BOOL floatingpoint) {
	LOCK_MIXER_GRAPH();
	if (!sound_initialized)
		init_sound();
	RefCount = 1;
	if (!parent)
		parent = output;
	parent_mixer = NULL; // only add_mixer may claim us; pre-assigning would leave a link to a mixer we never got stored in if the attach below fails

	if (!parent) {
		channel = BASS_Mixer_StreamCreate(44100, 2, BASS_MIXER_NONSTOP | (floatingpoint ? BASS_SAMPLE_FLOAT : 0));
		// No playback buffering on any platform: sounds start the instant they are played.
		BASS_ChannelSetAttribute(channel, BASS_ATTRIB_BUFFER, 0);
		// Do NOT enable BASS_ATTRIB_MIXER_THREADS here. With the buffer at 0 this mixer is
		// generated inside the output device's real-time callback, and that attribute makes the
		// callback hand its sources to ordinary-priority worker threads and then wait for them.
		// On a phone one of those workers only has to be preempted or scheduled onto a little
		// core for the callback to miss its deadline, which is a dropout - and the more sources
		// are playing, the likelier that is. Tried on Android: quiet areas were fine while busy
		// ones (a crowded map, several instruments at once) cut out on devices that had never
		// stuttered before, including where the audio work itself was nowhere near the limit.
		// Splitting mixing across cores is only safe for a mixer that is NOT generated in the
		// device callback, so it would have to come with buffering, which costs start latency.
		BASS_ChannelPlay(channel, TRUE);
		store_channel = register_hstream(channel);
	} else {
		if (!for_single_sound)
			channel = BASS_Mixer_StreamCreate(44100, 2, BASS_STREAM_DECODE | BASS_MIXER_NONSTOP | (floatingpoint ? BASS_SAMPLE_FLOAT : 0));
		else
			channel = BASS_Mixer_StreamCreate(44100, 2, BASS_STREAM_DECODE | (floatingpoint ? BASS_SAMPLE_FLOAT : 0));
		if (!for_decode)
			set_mixer(parent);
		else
			parent_mixer = NULL;
	}
	output_mixer = NULL;
	hrtf_effect = NULL;
	pos_effect = 0;
}

legacy_mixer::~legacy_mixer() {
	LOCK_MIXER_GRAPH();
	// Detach from our parent first, otherwise its child set keeps a dangling pointer that its own destructor will later call set_mixer on.
	if (parent_mixer) {
		parent_mixer->remove_mixer(this, TRUE);
		parent_mixer = NULL;
	}
	if (this != output) {
		// Drain pop-style: set_mixer re-enters remove_mixer which erases from these sets, so a range-for iterator here would be invalidated by its own loop body.
		while (!mixers.empty()) {
			legacy_mixer* m = *mixers.begin();
			mixers.erase(mixers.begin());
			BASS_Mixer_ChannelRemove(m->channel);
			m->parent_mixer = NULL;
			m->set_mixer(output);
			// Sounds route through an internal single-sound mixer but keep their own raw parent pointer; retarget any still aimed at this dying mixer.
			for (auto s : m->sounds) {
				if (s->parent_mixer == this)
					s->parent_mixer = output;
			}
		}
		while (!sounds.empty()) {
			legacy_sound* s = *sounds.begin();
			sounds.erase(sounds.begin());
			s->set_mixer(output);
		}
	}
	mixers.clear();
	sounds.clear();
}

void legacy_mixer::AddRef() {
	asAtomicInc(RefCount);
}
void legacy_mixer::Release() {
	LOCK_MIXER_GRAPH();
	if (asAtomicDec(RefCount) < 1) {
		if (channel) {
			BASS_StreamFree(channel); // Apparently I was having a problem with extraneous calls to BASS_StreamFree when trying to do it in mixer destructor years ago, since miniaudio switch iminent we'll just leave this here rather than figuring out what I was doing wrong back then.
			channel = 0;
		}
		delete this;
	}
}

int legacy_mixer::get_data(const unsigned char* buffer, int bufsize) {
	if (!channel) return 0;
	return BASS_ChannelGetData(channel, (void*)buffer, bufsize);
}

BOOL legacy_mixer::add_mixer(legacy_mixer* m) {
	LOCK_MIXER_GRAPH();
	if (!sound_initialized)
		init_sound();
	if (find(mixers.begin(), mixers.end(), m) != mixers.end())
		return FALSE;
	if (!channel || !m->channel)
		return FALSE;
	if (BASS_Mixer_ChannelGetMixer(m->channel) == channel)
		return FALSE;
	else if (BASS_Mixer_ChannelGetMixer(m->channel) == output->channel)
		return FALSE;
	else if (BASS_Mixer_ChannelGetMixer(m->channel) > 0)
		return FALSE;
	BOOL ret = BASS_Mixer_StreamAddChannel(channel, m->channel, BASS_MIXER_CHAN_NORAMPIN);
	if (ret) {
		m->parent_mixer = this;
		mixers.insert(m);
	}
	return ret;
}
BOOL legacy_mixer::remove_mixer(legacy_mixer* m, BOOL internal) {
	LOCK_MIXER_GRAPH();
	auto i = find(mixers.begin(), mixers.end(), m);
	if (i == mixers.end())
		return FALSE;
	mixers.erase(i);
	BASS_Mixer_ChannelRemove(m->channel);
	// Drop the back link as well: a child that still names a parent it is no longer stored in is exactly what lets a later teardown walk a set that does not contain it, or a parent that has already been freed.
	if (m->parent_mixer == this)
		m->parent_mixer = NULL;
	if (internal)
		return TRUE;
	m->set_mixer(NULL);
	return TRUE;
}
BOOL legacy_mixer::add_sound(legacy_sound& s, BOOL internal) {
	LOCK_MIXER_GRAPH();
	if (!sound_initialized)
		init_sound();
	if (sounds.find(&s) != sounds.end())
		return FALSE;
	BOOL ret = BASS_Mixer_StreamAddChannel(channel, s.channel, BASS_MIXER_CHAN_NORAMPIN | BASS_MIXER_CHAN_PAUSE);
	if (ret) {
		if (!internal)
			s.parent_mixer = this;
		sounds.insert(&s);
	}
	return ret;
}
BOOL legacy_mixer::remove_sound(legacy_sound& s, BOOL internal) {
	LOCK_MIXER_GRAPH();
	auto i = find(sounds.begin(), sounds.end(), &s);
	if (i == sounds.end())
		return FALSE;
	sounds.erase(i);
	if (internal)
		return TRUE;
	s.parent_mixer = NULL;
	BASS_Mixer_ChannelRemove(s.channel);
	s.set_mixer(NULL);
	return TRUE;
}

int legacy_mixer::set_fx(const std::string& fx, int idx) {
	if(fx.size()<1) {
		if(idx>=0&&idx<effects.size()) {
			for(DWORD i=idx+1; i<effects.size(); i++)
				BASS_FXSetPriority(effects[i].hfx, i);
			BASS_ChannelRemoveFX(channel, effects[idx].hfx);
			effects.erase(effects.begin()+idx);
			return TRUE;
		} else if(idx==-1) {
			for(DWORD i=0; i<effects.size(); i++) {
				BASS_ChannelRemoveFX(channel, effects[i].hfx);
			}
			effects.clear();
			return TRUE;
		} else
			return -1;
	}
	vector<string> args;
	string fxt=fx;
	char* arg=strtok(&fxt.front(), ":");
	while(arg) {
		args.push_back(arg);
		arg=strtok(NULL, ":");
	}
	if(args.size()<1)
		return -1;
	else if(args.size()==1&&args[0].size()>0&&args[0][0]=='$') {
		for(DWORD idx=0; idx<effects.size(); idx++) {
			if(strncmp(effects[idx].id, args[0].c_str(), args[0].size())==0) {
				for(DWORD i=idx+1; i<effects.size(); i++)
					BASS_FXSetPriority(effects[i].hfx, i);
				BASS_ChannelRemoveFX(channel, effects[idx].hfx);
				effects.erase(effects.begin()+idx);
				idx-=1;
			}
		}
		return 1;
	}
	string effect_id;
	if(args[0].size()>0&&args[0][0]=='$') {
		effect_id=args[0];
		args.erase(args.begin());
	}
	mixer_effect e;
	e.type=0;
	e.id[0]=0;
	if(effect_id!="")
		strncpy(e.id, effect_id.c_str(), 32);
	BYTE effect_settings[512];
	// effects
	if(args[0]=="i3DL2reverb"&&args.size()>12) {
		e.type=BASS_FX_DX8_I3DL2REVERB;
		BASS_DX8_I3DL2REVERB settings= {strtol(args[1].c_str(), NULL, 10), strtol(args[2].c_str(), NULL, 10), ff(args[3]), ff(args[4]), ff(args[5]), strtol(args[6].c_str(), NULL, 10), ff(args[7]), strtol(args[8].c_str(), NULL, 10), ff(args[9]), ff(args[10]), ff(args[11]), ff(args[12])};
		memcpy(&effect_settings, &settings, sizeof(BASS_DX8_I3DL2REVERB));
	} else if(args[0]=="reverb"&&args.size()>4) {
		e.type=BASS_FX_DX8_REVERB;
		BASS_DX8_REVERB settings= {ff(args[1]), ff(args[2]), ff(args[3]), ff(args[4])};
		memcpy(&effect_settings, &settings, sizeof(BASS_DX8_REVERB));
	} else if(args[0]=="rotate"&&args.size()>1) {
		e.type=BASS_FX_BFX_ROTATE;
		BASS_BFX_ROTATE settings= {ff(args[1]), -1};
		memcpy(&effect_settings, &settings, sizeof(BASS_BFX_ROTATE));
	} else if(args[0]=="volume"&&args.size()>1) {
		float volume=ff(args[1]);
		float amp=pow(10.0f, (volume*100.0-100)/20.0);
		e.type=BASS_FX_BFX_VOLUME;
		BASS_BFX_VOLUME settings= {-1, amp};
		memcpy(&effect_settings, &settings, sizeof(BASS_BFX_VOLUME));
	} else if(args[0]=="lvolume"&&args.size()>1) {
		e.type=BASS_FX_BFX_VOLUME;
		BASS_BFX_VOLUME settings= {-1, ff(args[1])};
		memcpy(&effect_settings, &settings, sizeof(BASS_BFX_VOLUME));
	} else if(args[0]=="highpass"&&args.size()>3) {
		e.type=BASS_FX_BFX_BQF;
		BASS_BFX_BQF settings= {BASS_BFX_BQF_HIGHPASS, ff(args[1]), 0, ff(args[2]), ff(args[3]), 0, -1};
		memcpy(&effect_settings, &settings, sizeof(BASS_BFX_BQF));
	} else if(args[0]=="lowpass"&&args.size()>3) {
		e.type=BASS_FX_BFX_BQF;
		BASS_BFX_BQF settings= {BASS_BFX_BQF_LOWPASS, ff(args[1]), 0, ff(args[2]), ff(args[3]), 0, -1};
		memcpy(&effect_settings, &settings, sizeof(BASS_BFX_BQF));
	} else if(args[0]=="bandpass"&&args.size()>3) {
		e.type=BASS_FX_BFX_BQF;
		BASS_BFX_BQF settings= {BASS_BFX_BQF_BANDPASS, ff(args[1]), 0, ff(args[2]), ff(args[3]), 0, -1};
		memcpy(&effect_settings, &settings, sizeof(BASS_BFX_BQF));
	} else if(args[0]=="damp"&&args.size()>5) {
		e.type=BASS_FX_BFX_DAMP;
		BASS_BFX_DAMP settings= {ff(args[1]), ff(args[2]), ff(args[3]), ff(args[4]), ff(args[5]), -1};
		memcpy(&effect_settings, &settings, sizeof(BASS_BFX_DAMP));
	} else if(args[0]=="autowah"&&args.size()>6) {
		e.type=BASS_FX_BFX_AUTOWAH;
		BASS_BFX_AUTOWAH settings= {ff(args[1]), ff(args[2]), ff(args[3]), ff(args[4]), ff(args[5]), ff(args[6]), -1};
		memcpy(&effect_settings, &settings, sizeof(BASS_BFX_AUTOWAH));
	} else if(args[0]=="phaser"&&args.size()>6) {
		e.type=BASS_FX_BFX_PHASER;
		BASS_BFX_PHASER settings= {ff(args[1]), ff(args[2]), ff(args[3]), ff(args[4]), ff(args[5]), ff(args[6]), -1};
		memcpy(&effect_settings, &settings, sizeof(BASS_BFX_PHASER));
	} else if(args[0]=="chorus"&&args.size()>6) {
		e.type=BASS_FX_BFX_CHORUS;
		BASS_BFX_CHORUS settings= {ff(args[1]), ff(args[2]), ff(args[3]), ff(args[4]), ff(args[5]), ff(args[6]), -1};
		memcpy(&effect_settings, &settings, sizeof(BASS_BFX_CHORUS));
	} else if(args[0]=="distortion"&&args.size()>5) {
		e.type=BASS_FX_BFX_DISTORTION;
		BASS_BFX_DISTORTION settings= {ff(args[1]), ff(args[2]), ff(args[3]), ff(args[4]), ff(args[5]), -1};
		memcpy(&effect_settings, &settings, sizeof(BASS_BFX_DISTORTION));
	} else if(args[0]=="compressor2"&&args.size()>5) {
		e.type=BASS_FX_BFX_COMPRESSOR2;
		BASS_BFX_COMPRESSOR2 settings= {ff(args[1]), ff(args[2]), ff(args[3]), ff(args[4]), ff(args[5]), -1};
		memcpy(&effect_settings, &settings, sizeof(BASS_BFX_COMPRESSOR2));
	} else if(args[0]=="echo4"&&args.size()>5) {
		e.type=BASS_FX_BFX_ECHO4;
		BASS_BFX_ECHO4 settings= {ff(args[1]), ff(args[2]), ff(args[3]), ff(args[4]), args[5]=="1", -1};
		memcpy(&effect_settings, &settings, sizeof(BASS_BFX_ECHO4));
	} else if(args[0]=="pitchshift"&&args.size()>1) {
		e.type=BASS_FX_BFX_PITCHSHIFT;
		BASS_BFX_PITCHSHIFT settings= {ff(args[1]), (args.size()>2? ff(args[2]) : 0.0f), 2048, 16, -1};
		memcpy(&effect_settings, &settings, sizeof(BASS_BFX_PITCHSHIFT));
	} else if(args[0]=="freeverb"&&args.size()>5) {
		e.type=BASS_FX_BFX_FREEVERB;
		BASS_BFX_FREEVERB settings= {ff(args[1]), ff(args[2]), ff(args[3]), ff(args[4]), ff(args[5]), (DWORD)(args.size()>6&&args[6]=="1"? BASS_BFX_FREEVERB_MODE_FREEZE : 0), -1};
		memcpy(&effect_settings, &settings, sizeof(BASS_BFX_FREEVERB));
	} else
		return -1;
	int id_idx=get_effect_index(e.id);
	if(id_idx==-1&&idx>=0&&idx<effects.size()) {
		for(DWORD i=idx; i<effects.size(); i++) {
			if(effects[i].hfx)
				BASS_FXSetPriority(effects[i].hfx, i+1);
		}
	}
	if(id_idx<0) {
		e.hfx=BASS_ChannelSetFX(channel, e.type, (idx>=0&&idx<effects.size()? idx+1 : effects.size()+1));
		if(!e.hfx)
			return -1;
	} else {
		if(effects[id_idx].type!=e.type)
			return -1;
		e.hfx=effects[id_idx].hfx;
	}
	BASS_FXSetParameters(e.hfx, effect_settings);
	if(id_idx>-1) return id_idx;
	if(idx>=0&&idx<effects.size()) {
		effects.insert(effects.begin()+idx, e);
		return idx;
	}
	effects.push_back(e);
	return effects.size()-1;
}

BOOL legacy_mixer::set_mixer(legacy_mixer* m) {
	LOCK_MIXER_GRAPH();
	if (!m)
		m = output;
	if (this == output)
		return FALSE;
	if (parent_mixer)
		parent_mixer->remove_mixer(this, TRUE);
	if (m)
		return m->add_mixer(this);
	return false;
}

BOOL legacy_mixer::is_sliding() {
	return channel > 0 && BASS_ChannelIsSliding(channel, 0);
}

BOOL legacy_mixer::is_pan_sliding() {
	return channel > 0 && BASS_ChannelIsSliding(channel, BASS_ATTRIB_PAN);
}

BOOL legacy_mixer::is_pitch_sliding() {
	return channel > 0 && BASS_ChannelIsSliding(channel, BASS_ATTRIB_FREQ);
}

BOOL legacy_mixer::is_volume_sliding() {
	return channel > 0 && BASS_ChannelIsSliding(channel, BASS_ATTRIB_VOL);
}

float legacy_mixer::get_pan() {
	if (!channel)
		return 0;
	float pan = 0;
	BASS_ChannelGetAttribute(channel, BASS_ATTRIB_PAN, &pan);
	return pan;
}
float legacy_mixer::get_pan_alt() {
	return get_pan() * 100;
}

float legacy_mixer::get_pitch() {
	if (!channel)
		return 0;
	float pitch = 0.0;
	if (!BASS_ChannelGetAttribute(channel, BASS_ATTRIB_FREQ, &pitch))
		return 0.0;
	pitch /= 44100;
	return pitch;
}
float legacy_mixer::get_pitch_alt() {
	return get_pitch() * 100;
}

float legacy_mixer::get_volume() {
	if (!channel)
		return 0;
	float volume = 0;
	BASS_ChannelGetAttribute(channel, BASS_ATTRIB_VOL, &volume);
	return volume;
}
float legacy_mixer::get_volume_alt() {
	return (get_volume() * 100) - 100;
}

BOOL legacy_mixer::set_pan(float pan) {
	if (!channel)
		return FALSE;
	if (pan < -1.0 || pan > 1.0)
		return FALSE;
	return BASS_ChannelSetAttribute(channel, BASS_ATTRIB_PAN, pan);
}
BOOL legacy_mixer::set_pan_alt(float pan) {
	return set_pan(pan / 100);
}

BOOL legacy_mixer::slide_pan(float pan, unsigned int time) {
	if (!channel)
		return FALSE;
	if (pan < -1.0 || pan > 1.0)
		return FALSE;
	return BASS_ChannelSlideAttribute(channel, BASS_ATTRIB_PAN, pan, time);
}
BOOL legacy_mixer::slide_pan_alt(float pan, unsigned int time) {
	return slide_pan(pan / 100, time);
}

BOOL legacy_mixer::set_pitch(float pitch) {
	if (!channel)
		return FALSE;
	if (pitch < 0.05 || pitch > 5.0)
		return FALSE;
	return BASS_ChannelSetAttribute(channel, BASS_ATTRIB_FREQ, 44100 * pitch);
}
BOOL legacy_mixer::set_pitch_alt(float pitch) {
	return set_pitch(pitch / 100);
}

BOOL legacy_mixer::slide_pitch(float pitch, unsigned int time) {
	if (!channel)
		return FALSE;
	if (pitch < 0.05 || pitch > 5.0)
		return FALSE;
	return BASS_ChannelSlideAttribute(channel, BASS_ATTRIB_FREQ, 44100 * pitch, time);
}
BOOL legacy_mixer::slide_pitch_alt(float pitch, unsigned int time) {
	return slide_pitch(pitch / 100, time);
}

BOOL legacy_mixer::set_volume(float volume) {
	if (!channel)
		return FALSE;
	if (volume < 0) volume = 0.0;
	if (volume > 1) volume = 1.0;
	return BASS_ChannelSetAttribute(channel, BASS_ATTRIB_VOL, volume);
}
BOOL legacy_mixer::set_volume_alt(float volume) {
	return set_volume((volume + 100) / 100);
}

BOOL legacy_mixer::slide_volume(float volume, unsigned int time) {
	if (!channel)
		return FALSE;
	if (volume < 0.0 || volume > 1.0)
		return FALSE;
	return BASS_ChannelSlideAttribute(channel, BASS_ATTRIB_VOL, volume, time);
}
BOOL legacy_mixer::slide_volume_alt(float volume, unsigned int time) {
	return slide_volume((volume + 100) / 100, time);
}



float get_master_volume() {
	if (!sound_initialized)
		init_sound();
	return BASS_GetConfig(BASS_CONFIG_GVOL_STREAM) / 10000.0;
}
float get_master_volume_r() {
	float v = get_master_volume() - 1.0;
	return v * 100;
}
BOOL set_master_volume(float volume) {
	if (!sound_initialized)
		init_sound();
	return BASS_SetConfig(BASS_CONFIG_GVOL_STREAM, volume * 10000);
}
BOOL set_master_volume_r(float volume) {
	volume /= 100.0;
	return set_master_volume(volume + 1.0);
}
unsigned int get_input_device() {
	if (!sound_initialized)
		init_sound();
	return BASS_RecordGetDevice();
}
unsigned int get_input_device_count() {
	if (!sound_initialized)
		init_sound();
	BASS_DEVICEINFO inf;
	DWORD count = 0;
	for (DWORD i = 0; BASS_RecordGetDeviceInfo(i, &inf); i++) {
		if (!(inf.flags & BASS_DEVICE_LOOPBACK) && inf.flags & BASS_DEVICE_ENABLED)
			count++;
	}
	return count;
}
unsigned int get_input_device_name(unsigned int device, char* buffer, unsigned int bufsize) {
	if (!sound_initialized)
		init_sound();
	BASS_DEVICEINFO i;
	if (!BASS_RecordGetDeviceInfo(device, &i))
		return 0;
	DWORD namelen = strlen(i.name);
	if (bufsize < namelen)
		return namelen;
	strncpy(buffer, i.name, namelen);
	return namelen;
}
CScriptArray* list_input_devices() {
	DWORD count = get_input_device_count();
	asIScriptContext* ctx = asGetActiveContext();
	asIScriptEngine* engine = ctx->GetEngine();
	asITypeInfo* arrayType = engine->GetTypeInfoByDecl("array<string>");
	CScriptArray* array = CScriptArray::Create(arrayType, count);
	for (int i = 0; i < count; i++) {
		char devname[512];
		int r = get_input_device_name(i, devname, 512);
		devname[r] = 0;
		((string*)(array->At(i)))->assign(devname);
	}
	return array;
}
BOOL set_input_device(unsigned int device) {
	if (!sound_initialized)
		init_sound();
	if (!BASS_RecordInit(device))
		return FALSE;
	return BASS_RecordSetDevice(device);
}
unsigned int get_output_device() {
	if (!sound_initialized)
		init_sound();
	return BASS_GetDevice();
}
unsigned int get_output_device_count() {
	if (!sound_initialized)
		init_sound();
	BASS_DEVICEINFO inf;
	DWORD count = 0;
	for (DWORD i = 0; BASS_GetDeviceInfo(i, &inf); i++)
		count++;
	return count;
}
unsigned int get_output_device_name(unsigned int device, char* buffer, unsigned int bufsize) {
	if (!sound_initialized)
		init_sound();
	BASS_DEVICEINFO i;
	if (!BASS_GetDeviceInfo(device, &i))
		return 0;
	DWORD namelen = strlen(i.name);
	if (bufsize < namelen)
		return namelen;
	strncpy(buffer, i.name, namelen);
	return namelen;
}
CScriptArray* list_output_devices() {
	DWORD count = get_output_device_count();
	asIScriptContext* ctx = asGetActiveContext();
	asIScriptEngine* engine = ctx->GetEngine();
	asITypeInfo* arrayType = engine->GetTypeInfoByDecl("array<string>");
	CScriptArray* array = CScriptArray::Create(arrayType, count);
	for (int i = 0; i < count; i++) {
		char devname[512];
		int r = get_output_device_name(i, devname, 512);
		devname[r] = 0;
		((string*)(array->At(i)))->assign(devname);
	}
	return array;
}
BOOL set_output_device(unsigned int device) {
	if (!sound_initialized)
		init_sound(device);
	else
		BASS_Init(device, 44100, 0, NULL, NULL);
	BOOL ret = BASS_SetDevice(device);
	if (ret) {
		for (hstream_entry * e = last_channel; e; e = e->p)
			BASS_ChannelSetDevice(e->channel, device);
	}
	return ret;
}

static BOOL get_global_hrtf() {
	return hrtf;
}
static BOOL set_global_hrtf(BOOL enable) {
	init_sound();
	if (enable && !phonon_context) {
		IPLContextSettings phonon_context_settings{};
		phonon_context_settings.version = STEAMAUDIO_VERSION;
		iplContextCreate(&phonon_context_settings, &phonon_context);
		IPLHRTFSettings phonon_hrtf_settings{};
		phonon_hrtf_settings.type = IPL_HRTFTYPE_DEFAULT;
		phonon_hrtf_settings.volume = 1.0;
		iplHRTFCreate(phonon_context, &phonon_audio_settings, &phonon_hrtf_settings, &phonon_hrtf);
		iplHRTFCreate(phonon_context, &phonon_audio_settings, &phonon_hrtf_settings, &phonon_hrtf_reflections);
		BASS_ChannelSetAttribute(output->channel, BASS_ATTRIB_GRANULE, hrtf_framesize);
	} else if (!enable && phonon_context) {
		iplHRTFRelease(&phonon_hrtf);
		iplContextRelease(&phonon_context);
		phonon_hrtf = NULL;
		phonon_context = NULL;
		BASS_ChannelSetAttribute(output->channel, BASS_ATTRIB_GRANULE, 0);
	}
	hrtf = enable;
	return TRUE;
}

legacy_mixer* ScriptMixer_Factory() {
	return new legacy_mixer();
}
legacy_sound* ScriptSound_Factory() {
	return new legacy_sound();
}
sound_environment* ScriptSound_Environment_Factory() {
	return new sound_environment();
}
void RegisterScriptSound(asIScriptEngine* engine) {
	// engine->SetDefaultNamespace("legacy");
	engine->RegisterGlobalProperty("pack@ sound_default_pack", &g_sound_default_pack);
	engine->RegisterFuncdef(_O("void sound_close_callback(string)"));
	engine->RegisterFuncdef(_O("uint sound_length_callback(string)"));
	engine->RegisterFuncdef(_O("int sound_read_callback(string &out, uint, string)"));
	engine->RegisterFuncdef(_O("bool sound_seek_callback(uint, string)"));
	engine->RegisterObjectType("mixer", 0, asOBJ_REF);
	engine->RegisterObjectBehaviour("mixer", asBEHAVE_FACTORY, "mixer @m()", asFUNCTION(ScriptMixer_Factory), asCALL_CDECL);
	engine->RegisterObjectBehaviour("mixer", asBEHAVE_ADDREF, "void f()", asMETHOD(legacy_mixer, AddRef), asCALL_THISCALL);
	engine->RegisterObjectBehaviour("mixer", asBEHAVE_RELEASE, "void f()", asMETHOD(legacy_mixer, Release), asCALL_THISCALL);
	engine->RegisterObjectType("sound", 0, asOBJ_REF);
	engine->RegisterObjectBehaviour("sound", asBEHAVE_FACTORY, "sound @s()", asFUNCTION(ScriptSound_Factory), asCALL_CDECL);
	engine->RegisterObjectBehaviour("sound", asBEHAVE_ADDREF, "void f()", asMETHOD(legacy_sound, AddRef), asCALL_THISCALL);
	engine->RegisterObjectBehaviour("sound", asBEHAVE_RELEASE, "void f()", asMETHOD(legacy_sound, Release), asCALL_THISCALL);
	engine->RegisterObjectProperty("sound", "const string loaded_filename", asOFFSET(legacy_sound, loaded_filename));
	engine->RegisterObjectMethod("sound", "bool close()", asMETHOD(legacy_sound, close), asCALL_THISCALL);
	engine->RegisterObjectMethod("sound", "bool load(const string &in filename, pack@ packfile = @sound_default_pack, bool allow_preloads = true)", asMETHOD(legacy_sound, load), asCALL_THISCALL);
	engine->RegisterObjectMethod("sound", "bool load(sound_close_callback@, sound_length_callback@, sound_read_callback@, sound_seek_callback@, const string &in, const string&in = \"\")", asMETHOD(legacy_sound, load_script), asCALL_THISCALL);
	engine->RegisterObjectMethod("sound", "bool load(string& data, uint size, const string&in preload_filename = \"\", bool legacy_encrypt = false)", asMETHOD(legacy_sound, load_memstream), asCALL_THISCALL);
	engine->RegisterObjectMethod("sound", "bool load_url(const string &in url)", asMETHOD(legacy_sound, load_url), asCALL_THISCALL);
	engine->RegisterObjectMethod("sound", "bool stream(const string &in filename, pack@ containing_pack = sound_default_pack)", asMETHOD(legacy_sound, stream), asCALL_THISCALL);
	engine->RegisterObjectMethod("sound", "bool push_memory(const string &in data, bool end_stream = false, int pcm_rate = 0, int pcm_channels = 0)", asMETHOD(legacy_sound, push_string), asCALL_THISCALL);
	engine->RegisterObjectMethod("sound", "bool set_position(float listener_x, float listener_y, float listener_z, float sound_x, float sound_y, float sound_z, float rotation = 0.0, float pan_step = 1.0, float volume_step = 1.0)", asMETHOD(legacy_sound, set_position), asCALL_THISCALL);
	engine->RegisterObjectMethod("sound", "bool set_mixer(mixer@+ mixer = null)", asMETHOD(legacy_sound, set_mixer), asCALL_THISCALL);
	engine->RegisterObjectMethod("sound", "void set_hrtf(bool enable = true)", asMETHOD(legacy_sound, set_hrtf), asCALL_THISCALL);
	engine->RegisterObjectMethod("sound", "void set_length(float length = 0.0)", asMETHOD(legacy_sound, set_length), asCALL_THISCALL);
	engine->RegisterObjectMethod("sound", "bool set_fx(const string &in fx, int index = -1)", asMETHOD(legacy_sound, set_fx), asCALL_THISCALL);
	engine->RegisterObjectMethod("sound", "bool play(bool reset_loop_state = true)", asMETHOD(legacy_sound, play), asCALL_THISCALL);
	engine->RegisterObjectMethod("sound", "bool play_wait()", asMETHOD(legacy_sound, play_wait), asCALL_THISCALL);
	engine->RegisterObjectMethod("sound", "bool play_looped()", asMETHOD(legacy_sound, play_looped), asCALL_THISCALL);
	engine->RegisterObjectMethod("sound", "bool pause()", asMETHOD(legacy_sound, pause), asCALL_THISCALL);
	engine->RegisterObjectMethod("sound", "bool stop()", asMETHOD(legacy_sound, stop), asCALL_THISCALL);
	engine->RegisterObjectMethod("sound", "bool seek(float position)", asMETHOD(legacy_sound, seek), asCALL_THISCALL);
	engine->RegisterObjectMethod("sound", "bool get_active() const property", asMETHOD(legacy_sound, is_active), asCALL_THISCALL);
	engine->RegisterObjectMethod("sound", "bool get_playing() const property", asMETHOD(legacy_sound, is_playing), asCALL_THISCALL);
	engine->RegisterObjectMethod("sound", "bool get_paused() const property", asMETHOD(legacy_sound, is_paused), asCALL_THISCALL);
	engine->RegisterObjectMethod("sound", "bool get_sliding() const property", asMETHOD(legacy_sound, is_sliding), asCALL_THISCALL);
	engine->RegisterObjectMethod("sound", "bool get_pan_sliding() const property", asMETHOD(legacy_sound, is_pan_sliding), asCALL_THISCALL);
	engine->RegisterObjectMethod("sound", "bool get_pitch_sliding() const property", asMETHOD(legacy_sound, is_pitch_sliding), asCALL_THISCALL);
	engine->RegisterObjectMethod("sound", "bool get_volume_sliding() const property", asMETHOD(legacy_sound, is_volume_sliding), asCALL_THISCALL);
	engine->RegisterObjectMethod("sound", "float get_length() const property", asMETHOD(legacy_sound, get_length_ms), asCALL_THISCALL);
	engine->RegisterObjectMethod("sound", "float get_position() const property", asMETHOD(legacy_sound, get_position_ms), asCALL_THISCALL);
	engine->RegisterObjectMethod("sound", "float get_pitch() const property", asMETHOD(legacy_sound, get_pitch_alt), asCALL_THISCALL);
	engine->RegisterObjectMethod("sound", "void set_pitch(float) property", asMETHOD(legacy_sound, set_pitch_alt), asCALL_THISCALL);
	engine->RegisterObjectMethod("sound", "bool slide_pitch(float, uint)", asMETHOD(legacy_sound, slide_pitch_alt), asCALL_THISCALL);
	engine->RegisterObjectMethod("sound", "float get_pan() const property", asMETHOD(legacy_sound, get_pan_alt), asCALL_THISCALL);
	engine->RegisterObjectMethod("sound", "void set_pan(float) property", asMETHOD(legacy_sound, set_pan_alt), asCALL_THISCALL);
	engine->RegisterObjectMethod("sound", "bool slide_pan(float, uint)", asMETHOD(legacy_sound, slide_pan_alt), asCALL_THISCALL);
	engine->RegisterObjectMethod("sound", "float get_volume() const property", asMETHOD(legacy_sound, get_volume_alt), asCALL_THISCALL);
	engine->RegisterObjectMethod("sound", "void set_volume(float) property", asMETHOD(legacy_sound, set_volume_alt), asCALL_THISCALL);
	engine->RegisterObjectMethod("sound", "bool slide_volume(float, uint)", asMETHOD(legacy_sound, slide_volume_alt), asCALL_THISCALL);
	engine->RegisterObjectMethod("sound", "double get_pitch_lower_limit() const property", asMETHOD(legacy_sound, pitch_lower_limit), asCALL_THISCALL);
	engine->RegisterObjectMethod("mixer", "bool set_fx(const string &in, int = -1)", asMETHOD(legacy_mixer, set_fx), asCALL_THISCALL);
	engine->RegisterObjectMethod("mixer", "bool set_position(float, float, float, float, float, float, float, float, float)", asMETHOD(legacy_mixer, set_position), asCALL_THISCALL);
	engine->RegisterObjectMethod("mixer", "bool set_mixer(mixer@+ = null)", asMETHOD(legacy_mixer, set_mixer), asCALL_THISCALL);
	engine->RegisterObjectMethod("mixer", "void set_hrtf(bool = true)", asMETHOD(legacy_mixer, set_hrtf), asCALL_THISCALL);
	engine->RegisterObjectMethod("mixer", "bool get_sliding() const property", asMETHOD(legacy_mixer, is_sliding), asCALL_THISCALL);
	engine->RegisterObjectMethod("mixer", "bool get_pan_sliding() const property", asMETHOD(legacy_mixer, is_pan_sliding), asCALL_THISCALL);
	engine->RegisterObjectMethod("mixer", "bool get_pitch_sliding() const property", asMETHOD(legacy_mixer, is_pitch_sliding), asCALL_THISCALL);
	engine->RegisterObjectMethod("mixer", "bool get_volume_sliding() const property", asMETHOD(legacy_mixer, is_volume_sliding), asCALL_THISCALL);
	engine->RegisterObjectMethod("mixer", "float get_pitch() const property", asMETHOD(legacy_mixer, get_pitch_alt), asCALL_THISCALL);
	engine->RegisterObjectMethod("mixer", "void set_pitch(float) property", asMETHOD(legacy_mixer, set_pitch_alt), asCALL_THISCALL);
	engine->RegisterObjectMethod("mixer", "bool slide_pitch(float, uint)", asMETHOD(legacy_mixer, slide_pitch_alt), asCALL_THISCALL);
	engine->RegisterObjectMethod("mixer", "float get_pan() const property", asMETHOD(legacy_mixer, get_pan_alt), asCALL_THISCALL);
	engine->RegisterObjectMethod("mixer", "void set_pan(float) property", asMETHOD(legacy_mixer, set_pan_alt), asCALL_THISCALL);
	engine->RegisterObjectMethod("mixer", "bool slide_pan(float, uint)", asMETHOD(legacy_mixer, slide_pan_alt), asCALL_THISCALL);
	engine->RegisterObjectMethod("mixer", "float get_volume() const property", asMETHOD(legacy_mixer, get_volume_alt), asCALL_THISCALL);
	engine->RegisterObjectMethod("mixer", "void set_volume(float) property", asMETHOD(legacy_mixer, set_volume_alt), asCALL_THISCALL);
	engine->RegisterObjectMethod("mixer", "bool slide_volume(float, uint)", asMETHOD(legacy_mixer, slide_volume_alt), asCALL_THISCALL);

	engine->RegisterObjectType("sound_environment", 0, asOBJ_REF);
	engine->RegisterObjectBehaviour("sound_environment", asBEHAVE_FACTORY, "sound_environment @s()", asFUNCTION(ScriptSound_Environment_Factory), asCALL_CDECL);
	engine->RegisterObjectBehaviour("sound_environment", asBEHAVE_ADDREF, "void f()", asMETHOD(sound_environment, add_ref), asCALL_THISCALL);
	engine->RegisterObjectBehaviour("sound_environment", asBEHAVE_RELEASE, "void f()", asMETHOD(sound_environment, release), asCALL_THISCALL);
	engine->RegisterObjectMethod("sound_environment", "bool add_material(const string&in, float, float, float, float, float, float, float, bool = false)", asMETHOD(sound_environment, add_material), asCALL_THISCALL);
	engine->RegisterObjectMethod("sound_environment", "bool add_box(const string&in, float, float, float, float, float, float)", asMETHOD(sound_environment, add_box), asCALL_THISCALL);
	engine->RegisterObjectMethod("sound_environment", "mixer@ new_mixer()", asMETHOD(sound_environment, new_mixer), asCALL_THISCALL);
	engine->RegisterObjectMethod("sound_environment", "sound@ new_sound()", asMETHOD(sound_environment, new_sound), asCALL_THISCALL);
	engine->RegisterObjectMethod("sound_environment", "void update()", asMETHOD(sound_environment, update), asCALL_THISCALL);
	engine->RegisterObjectMethod("sound_environment", "void set_listener(float, float, float, float)", asMETHOD(sound_environment, set_listener), asCALL_THISCALL);

	engine->RegisterGlobalFunction("bool get_SOUND_AVAILABLE() property", asFUNCTION(sound_available), asCALL_CDECL);
	engine->RegisterGlobalFunction("float get_sound_master_volume() property", asFUNCTION(get_master_volume_r), asCALL_CDECL);
	engine->RegisterGlobalFunction("void set_sound_master_volume(float) property", asFUNCTION(set_master_volume_r), asCALL_CDECL);
	engine->RegisterGlobalFunction("uint get_sound_input_device() property", asFUNCTION(get_input_device), asCALL_CDECL);
	engine->RegisterGlobalFunction("void set_sound_input_device(uint) property", asFUNCTION(set_input_device), asCALL_CDECL);
	engine->RegisterGlobalFunction("uint get_sound_input_device_count() property", asFUNCTION(get_input_device_count), asCALL_CDECL);
	engine->RegisterGlobalFunction("array<string>@ get_sound_input_devices() property", asFUNCTION(list_input_devices), asCALL_CDECL);
	engine->RegisterGlobalFunction("uint get_sound_output_device() property", asFUNCTION(get_output_device), asCALL_CDECL);
	engine->RegisterGlobalFunction("void set_sound_output_device(uint) property", asFUNCTION(set_output_device), asCALL_CDECL);
	engine->RegisterGlobalFunction("uint get_sound_output_device_count() property", asFUNCTION(get_output_device_count), asCALL_CDECL);
	engine->RegisterGlobalFunction("array<string>@ get_sound_output_devices() property", asFUNCTION(list_output_devices), asCALL_CDECL);
	engine->RegisterGlobalFunction("bool get_sound_global_hrtf() property", asFUNCTION(get_global_hrtf), asCALL_CDECL);
	engine->RegisterGlobalFunction("void set_sound_global_hrtf(bool) property", asFUNCTION(set_global_hrtf), asCALL_CDECL);
	engine->RegisterGlobalProperty("mixer@ sound_default_mixer", &g_default_mixer);
	// engine->SetDefaultNamespace("");
}
plugin_main(nvgt_plugin_shared* shared) {
	prepare_plugin(shared);
	#if defined(__APPLE__) && TARGET_OS_IPHONE && defined(NVGT_PLUGIN_STATIC)
	// A stub that embeds this plugin links BASS weakly, since the frameworks are only bundled with games that load the
	// plugin. A package that lacks them must fail here, with a message, rather than at the first call into nothing.
	if (!dlsym(RTLD_DEFAULT, "BASS_GetVersion")) return false;
	#endif
	g_ScriptEngine = shared->script_engine;
	CScriptArray::SetMemoryFunctions(std::malloc, std::free);
	#ifdef _WIN32
	setlocale(LC_ALL, ".UTF8");
	#endif
	RegisterScriptLegacyPack(shared->script_engine);
	RegisterScriptSound(shared->script_engine);
	nvgt_bundle_shared_library("bass");
	nvgt_bundle_shared_library("bass_fx");
	nvgt_bundle_shared_library("bassmix");
	return true;
}
