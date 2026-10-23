/* sound_nodes.cpp - audio nodes implementation
 * This contains code for hooking all effects and other nodes up to miniaudio, from hrtf to reverb to filters to tone synthesis and more.
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

#include <exception>
#include <memory>
#include <unordered_set>
#include <mutex>
#include <atomic>
#include <limits>
#include <Poco/NotificationQueue.h>
#include <Poco/Thread.h>
#include <ma_reverb_node.h>
#include "misc_functions.h" // range_convert
#include "sound_nodes.h"

using namespace std;

// A volume clamped to the range a script set, as MiniAudio's ma_clamp() clamps a sound's gain, the floor winning over a ceiling set below it: std::clamp() with such a range is undefined.
static float clamp_volume(float volume, float floor, float ceiling) { return volume > ceiling? (ceiling < floor? floor : ceiling) : volume < floor? floor : volume; }
// A panning amount, or none for one that isn't a number, as an infinite distance times a directional factor of 0 makes, which MiniAudio's clamp turned into hard right.
static float pan_amount(float amount) { return amount == amount? amount : 0; }
// What an attenuator applies for its distance's volume: that and the cones' volume clamped together to min_volume and max_volume, once, as MiniAudio's spatializer clamps them when it attenuates.
static float volume_with_cones(float distance_volume, const audio_spatialization_parameters& params) { return clamp_volume(distance_volume * params.cone_volume, params.min_volume, params.max_volume); }

// This node allows easy creation of miniaudio nodes in C++.
static void ma_effect_node_process_pcm_frames(ma_node* pNode, const float** ppFramesIn, ma_uint32* pFrameCountIn, float** ppFramesOut, ma_uint32* pFrameCountOut) {
	ma_effect_node* node = (ma_effect_node*)pNode;
	if (!node->node) return;
	node->node->process(ppFramesIn, pFrameCountIn, ppFramesOut, pFrameCountOut);
}
static ma_result ma_effect_node_get_required_input_frame_count(ma_node* pNode, ma_uint32 outputFrameCount, ma_uint32* input_frame_count) {
	ma_effect_node* node = (ma_effect_node*)pNode;
	if (!node->node) return MA_ERROR;
	*input_frame_count = node->node->required_input_frame_count(outputFrameCount);
	return MA_SUCCESS;
}
effect_node_impl::effect_node_impl(audio_engine* e, ma_uint8 input_channel_count, ma_uint8 output_channel_count, ma_uint8 input_bus_count, ma_uint8 output_bus_count, unsigned int flags) : n(make_unique<ma_effect_node>()), audio_node_impl(nullptr, e), vtable({&ma_effect_node_process_pcm_frames, &ma_effect_node_get_required_input_frame_count, input_bus_count, output_bus_count, flags}) {
	if (!input_channel_count) input_channel_count = get_engine()->get_channels();
	if (!output_channel_count) output_channel_count = get_engine()->get_channels();
	ma_node_config cfg = ma_node_config_init();
	vector<ma_uint32> channels_in(input_bus_count, input_channel_count), channels_out(output_bus_count, output_channel_count);
	cfg.vtable          = &vtable;
	if (input_bus_count > 0) cfg.pInputChannels  = &channels_in[0];
	if (output_bus_count > 0) cfg.pOutputChannels = &channels_out[0];
	if ((g_soundsystem_last_error = ma_node_init(ma_engine_get_node_graph(get_engine()->get_ma_engine()), &cfg, nullptr, (ma_node_base*)&*n)) != MA_SUCCESS) throw std::runtime_error("failed to create effect node");
	n->node = this;
	node = (ma_node_base*)&*n;
}
effect_node_impl::~effect_node_impl() { destroy_node(); }
void effect_node_impl::destroy_node() {
	
	// ma_node_uninit detaches from every input bus it is attached to, editing the same lists a concurrent attach on another script thread is editing; keep it under the graph lock like the attach/detach wrappers.
	std::lock_guard<std::recursive_mutex> graph_lock(g_node_graph_mutex);
	
	if (n) ma_node_uninit((ma_node_base*)&*n, nullptr);
	
	n.reset();
	node = nullptr; // Freed with n; a destroyed node attaches to nothing, rather than through what is left of it.
}
void effect_node_impl::process(const float** frames_in, unsigned int* frame_count_in, float** frames_out, unsigned int* frame_count_out) {} // override in subclasses.
unsigned int effect_node_impl::required_input_frame_count(unsigned int output_frame_count) const { return output_frame_count; }

// The following node acts as a simple passthrough, with a callback that does nothing. The purpose is for any object that exists between or in any way handles nodes to be able to exist in the node graph.
// For example a reverb3d node acts as a high level API to applying reverb to 3d sounds. We want the user to be able to swap underlying reverb effect nodes that all sounds attached to the reverb3d objects are using, but prefferably without keeping track of sounds to reattach. Therefor, reverb3d acts as a passthrough node which all connected sounds are attached to, allowing us to swap the underlying reverb effect in one place rather than for all connected sounds.
// Whether every value is a finite number, refusing with MA_INVALID_ARGS otherwise: a NaN or infinite filter, delay or reverb setting made every sample its node passed NaN, which the filters and the delay then kept in their state after a good value was set again.
static bool finite_node_values(std::initializer_list<double> values) {
	for (double value : values) {
		if (!std::isfinite(value)) {
			g_soundsystem_last_error = MA_INVALID_ARGS;
			return false;
		}
	}
	return true;
}
// Settings MiniAudio's filters and verblib take without a word but can't work with: a cutoff or center frequency at or past half the sample rate, a q of 0 or less or a gain beyond 100 dB either way made a filter's output NaN, which its state kept after a good value came back, and a delay's decay or a reverb's room size or damping past 1 made the output grow without bound. A frequency, gain or such a value out of range is taken as the nearest usable one (see clamped_gain() and usable_frequency()); a q of 0 or less, a frequency of 0 or less and settings no frequency makes stable are refused with MA_INVALID_ARGS, the node keeping what it had.
static bool node_value_in_range(bool in_range) {
	if (!in_range) g_soundsystem_last_error = MA_INVALID_ARGS;
	return in_range;
}
static bool q_in_range(double q) { return node_value_in_range(q > 0); }
// A finite gain beyond 100 dB either way, or a delay's decay or a reverb's room size or damping outside 0 to 1, is taken as the nearest value in range, as NVGT takes a volume or pitch out of range, rather than refused, which kept the old setting or made a constructor throw.
static double clamped_gain(double gain_db) { return std::clamp(gain_db, -100.0, 100.0); }
static float clamped_unit(float value) { return std::clamp(value, 0.0f, 1.0f); }
// MiniAudio divides a biquad filter's coefficients by a0 and keeps them as floats, and one that wasn't finite there made the filter's output NaN for good, as above: a q so near 0 that sin(w) / 2q overflowed did that. At a frequency so low that w is tiny, the poles lie so close to 1 that rounding a1 and a2 to floats could put one outside the unit circle: below about 1.35 Hz at 48 kHz, about half the frequencies made the output grow from the first sample until it was infinite, then NaN for good. And a pole the rounding left just inside it, within a fraction of a hertz of 0 or of half the sample rate, no longer had its zeros cancel it, so the filter's own rounding was amplified to hundreds of times full scale. Settings are refused unless MiniAudio's coefficients, worked out as it does, all come out finite, and the float filter's poles, the roots of z^2 + a1 z + a2, both lie at least 1e-5 inside the unit circle.
static constexpr double filter_pi = 3.14159265358979323846264; // MiniAudio's MA_PI_D.
static bool biquad_in_range(double b0, double b1, double b2, double a0, double a1, double a2) {
	for (double coefficient : {b0, b1, b2, a1, a2}) {
		if (!std::isfinite((float)(coefficient / a0))) return node_value_in_range(false);
	}
	double a1f = (float)(a1 / a0), a2f = (float)(a2 / a0), discriminant = a1f * a1f - 4 * a2f; // Exact in double, as the coefficients are floats.
	double radius = discriminant < 0? std::sqrt(a2f) : (std::fabs(a1f) + std::sqrt(discriminant)) / 2; // Of the pole farthest out.
	return node_value_in_range(radius <= 1 - 1e-5);
}
// The second-order sections MiniAudio makes a low-, high- or band-pass filter of, a first-order one being stable at any frequency.
enum class pass_filter { low, high, band };
static bool sections_in_range(pass_filter kind, double frequency, int order, ma_uint32 sample_rate) {
	if (order < 1 || order > MA_MAX_FILTER_ORDER) return true; // MiniAudio refuses it itself.
	double w = 2 * filter_pi * frequency / sample_rate, s = std::sin(w), c = std::cos(w);
	for (int i = 0; i < order / 2; i++) {
		double q = 0.707107;
		if (kind != pass_filter::band) q = 1 / (2 * std::cos(order % 2? (1 + i * 1) * (filter_pi / (order * 1)) : (1 + i * 2) * (filter_pi / (order * 2)))); // Butterworth, as MiniAudio has it.
		double a = s / (2 * q);
		bool in_range = kind == pass_filter::low? biquad_in_range((1 - c) / 2, 1 - c, (1 - c) / 2, 1 + a, -2 * c, 1 - a) : kind == pass_filter::high? biquad_in_range((1 + c) / 2, -(1 + c), (1 + c) / 2, 1 + a, -2 * c, 1 - a) : biquad_in_range(q * a, 0, -q * a, 1 + a, -2 * c, 1 - a);
		if (!in_range) return false;
	}
	return true;
}
static bool notch_in_range(double q, double frequency, ma_uint32 sample_rate) {
	double w = 2 * filter_pi * frequency / sample_rate, c = std::cos(w), a = std::sin(w) / (2 * q);
	return biquad_in_range(1, -2 * c, 1, 1 + a, -2 * c, 1 - a);
}
static bool peak_in_range(double gain_db, double q, double frequency, ma_uint32 sample_rate) {
	double w = 2 * filter_pi * frequency / sample_rate, c = std::cos(w), a = std::sin(w) / (2 * q), A = std::pow(10.0, gain_db / 40);
	return biquad_in_range(1 + (a * A), -2 * c, 1 - (a * A), 1 + (a / A), -2 * c, 1 - (a / A));
}
// A shelf filter's q is its slope S, which MiniAudio puts under a square root, sqrt((A + 1/A) * (1/S - 1) + 2) with A = 10^(gain/40): a slope above 1 makes that negative once the gain is far enough from 0, and the filter's output NaN for good, as above. The pair is refused while the root's argument isn't clearly above 0, so rounding can't take MiniAudio's below it, and the coefficients are then checked as the other filters' are.
static bool shelf_in_range(bool high, double gain_db, double slope, double frequency, ma_uint32 sample_rate) {
	double A = std::pow(10.0, gain_db / 40), spread = (A + 1 / A) * (1 / slope - 1);
	if (!node_value_in_range(spread + 2 > 1e-12 * (std::fabs(spread) + 2))) return false;
	double w = 2 * filter_pi * frequency / sample_rate, s = std::sin(w), c = std::cos(w), a = s / 2 * std::sqrt(spread + 2), sqrtA = 2 * std::sqrt(A) * a;
	if (high) return biquad_in_range(A * ((A + 1) + (A - 1) * c + sqrtA), -2 * A * ((A - 1) + (A + 1) * c), A * ((A + 1) + (A - 1) * c - sqrtA), (A + 1) - (A - 1) * c + sqrtA, 2 * ((A - 1) - (A + 1) * c), (A + 1) - (A - 1) * c - sqrtA);
	return biquad_in_range(A * ((A + 1) - (A - 1) * c + sqrtA), 2 * A * ((A - 1) - (A + 1) * c), A * ((A + 1) - (A - 1) * c - sqrtA), (A + 1) + (A - 1) * c + sqrtA, -2 * ((A - 1) + (A + 1) * c), (A + 1) + (A - 1) * c - sqrtA);
}
// A cutoff or center frequency at or past half the sample rate, or so near it or 0 that rounding the filter's coefficients to floats would put a pole on or past the unit circle, is taken as the nearest frequency at which the filter stays stable, rather than refused: half the sample rate is the engine's, which is the output device's unless a script chose one, so a frequency that worked on one machine was refused on another, the filter keeping its old setting or not being made at all. 0 when there is none: the frequency was 0 or less, or the filter's other settings leave it unstable at any.
template <class stable_at> static double usable_frequency(double frequency, ma_uint32 sample_rate, stable_at stable) {
	if (!node_value_in_range(frequency > 0)) return 0;
	double nyquist = sample_rate / 2.0, wanted = std::min(frequency, std::nextafter(nyquist, 0.0));
	if (stable(wanted)) return wanted;
	double good = nyquist / 2, bad = wanted; // Stable in the middle of the band if anywhere: rounding unsettles a filter near its edges.
	if (!stable(good)) return 0;
	for (int i = 0; i < 64; i++) {
		double middle = (good + bad) / 2;
		(stable(middle)? good : bad) = middle;
	}
	return good;
}

class passthrough_node_impl : public effect_node_impl, public virtual passthrough_node {
	public:
	passthrough_node_impl(audio_engine* e) : effect_node_impl(e, 0, 0, 1, 1, MA_NODE_FLAG_PASSTHROUGH | MA_NODE_FLAG_CONTINUOUS_PROCESSING | MA_NODE_FLAG_ALLOW_NULL_INPUT) {}
};
passthrough_node* passthrough_node::create(audio_engine* engine) { return new passthrough_node_impl(engine); }

class audio_node_chain_impl : public passthrough_node_impl, public virtual audio_node_chain {
	std::vector<audio_node*> nodes;
	std::vector<unsigned int> input_buses; // For each node, the input bus the node before it feeds, which every rewiring attaches to again.
	audio_node* endpoint;
	unsigned int endpoint_input_bus_index = 0; // The endpoint's input bus the chain feeds, which every rewiring attaches to again.
	// The input bus the node at index takes the chain on, index being nodes.size() for the endpoint.
	unsigned int bus_at(size_t index) const { return index < nodes.size()? input_buses[index] : endpoint_input_bus_index; }
protected:
	// Every change and read of the chain's nodes and endpoint takes this, as one script thread can change a sound's chain while another changes it too, such as a global panner change rewiring every spatializer. Recursive because the changes call one another; never taken on the audio thread, which only reads the MiniAudio graph.
	mutable std::recursive_mutex chain_mutex;
public:
	audio_node_chain_impl(audio_node* source, audio_node* endpoint, audio_engine* e) : passthrough_node_impl(e), endpoint(nullptr) {
		if (source) source->attach_output_bus(0, this, 0);
		if (endpoint) attach_output_bus(0, endpoint, 0);
	}
	~audio_node_chain_impl() {
		// We only release references, all attachments are kept in tact. Call clear(true) to detach all known nodes instead.
		for (audio_node* node: nodes) node->release();
		if (endpoint) endpoint->release();
	}
	bool attach_output_bus(unsigned int bus_index, audio_node* node, unsigned int input_bus_index) override {
		std::lock_guard<std::recursive_mutex> chain_lock(chain_mutex);
		set_endpoint(node, input_bus_index);
		return endpoint == node;
	}
	bool detach_output_bus(unsigned int bus_index) override {
		std::lock_guard<std::recursive_mutex> chain_lock(chain_mutex);
		set_endpoint(nullptr, 0);
		return endpoint == nullptr;
	}
	bool detach_all_output_buses() override { return detach_output_bus(0); }
	bool add_node(audio_node* node, audio_node* after, unsigned int input_bus_index) override {
		std::lock_guard<std::recursive_mutex> chain_lock(chain_mutex);
		if (!node) return false;
		if (node == static_cast<audio_node*>(this) || node == endpoint || index_of(node) != -1) { // The chain itself, its endpoint or a node already in it, which would loop the chain.
			g_soundsystem_last_error = MA_INVALID_ARGS;
			return false;
		}
		unsigned int new_idx = 0;
		if (after) {
			new_idx = index_of(after);
			if (new_idx == -1) return false;
			else new_idx += 1; // Be sure to insert after this position rather than before.
		}
		audio_node* prev = new_idx? nodes[new_idx -1] : nullptr;
		audio_node* next = new_idx? (new_idx < nodes.size()? nodes[new_idx] : endpoint) : (!nodes.empty()? first() : endpoint);
		// The node before is attached to the new one first, on the new node's input_bus_index, which a node that takes no input, as a sound or data source, refuses with nothing changed; the new node is then attached to the next one on the bus the next one was fed on, and when the new node can't feed it, as with another channel count, the node before goes back to it.
		unsigned int next_bus = bus_at(new_idx);
		if (prev && !prev->attach_output_bus(0, node, input_bus_index)) return false;
		else if (!prev && !audio_node_impl::attach_output_bus(0, node, input_bus_index)) return false;
		if (next && !node->attach_output_bus(0, next, next_bus)) {
			ma_result error = g_soundsystem_last_error;
			if (prev) prev->attach_output_bus(0, next, next_bus);
			else audio_node_impl::attach_output_bus(0, next, next_bus);
			g_soundsystem_last_error = error;
			return false;
		}
		nodes.insert(nodes.begin() + new_idx, node);
		input_buses.insert(input_buses.begin() + new_idx, input_bus_index);
		node->duplicate();
		return true;
	}
	bool add_node_at(audio_node* node, int after, unsigned int input_bus_index) override {
		std::lock_guard<std::recursive_mutex> chain_lock(chain_mutex);
		if (after < -1 || after >= int(nodes.size())) return false;
		audio_node* insert_after = after > -1? nodes[after] : nullptr;
		return add_node(node, insert_after, input_bus_index);
	}
	bool remove_node(audio_node* node) override {
		std::lock_guard<std::recursive_mutex> chain_lock(chain_mutex);
		if (!node) return false;
		auto it = find(nodes.begin(), nodes.end(), node);
		if (it == nodes.end()) return false;
		audio_node* prev = (*it) != nodes.front()? *(it -1) : nullptr;
		audio_node* next = (*it) != nodes.back()? *(it + 1) : endpoint;
		size_t index = it - nodes.begin();
		unsigned int next_bus = bus_at(index + 1);
		if (prev && next && !prev->attach_output_bus(0, next, next_bus)) return false;
		else if (!prev && next && !audio_node_impl::attach_output_bus(0, next, next_bus)) return false;
		else if (!next) { // The last node of a chain without an endpoint: what fed it no longer leads anywhere, nor holds it.
			if (prev) prev->detach_output_bus(0);
			else audio_node_impl::detach_output_bus(0);
		}
		nodes.erase(it);
		input_buses.erase(input_buses.begin() + index);
		bool success = node->detach_output_bus(0);
		node->release();
		return success;
	}
	bool remove_node_at(unsigned int index) override {
		std::lock_guard<std::recursive_mutex> chain_lock(chain_mutex);
		if (index >= nodes.size()) return false;
		return remove_node(nodes[index]);
	}
	bool clear(bool detach_nodes) override {
		std::lock_guard<std::recursive_mutex> chain_lock(chain_mutex);
		bool success = audio_node_impl::detach_output_bus(0);
		for (audio_node* node : nodes) {
			if (success && detach_nodes) success = node->detach_output_bus(0);
			node->release();
		}
		if (success && endpoint) success = audio_node_impl::attach_output_bus(0, endpoint, endpoint_input_bus_index);
		nodes.clear();
		input_buses.clear();
		return success;
	}
	// The chain holds a reference of its own to the endpoint. The attachment to it, whichever node it is from, holds another, but every insert, removal or clear rewires that attachment, which let go of the endpoint's only reference before the endpoint was attached to again, and a script can detach a node of the chain through the audio_node API.
	// Under the chain's lock only, which keeps the detach and attach together. The graph lock is taken by each of them, after the lock of any chain they go into, such as a spatializer at the end of this one: taking it here first, as before, was the opposite order to a global panner change, which locks a spatializer and then the graph, and the two deadlocked.
	// A new endpoint is attached in place of the old one, so an attach MiniAudio refuses, as to another channel count or a missing input bus, leaves the old one attached, as it leaves any other node's attachment: detaching the old one first left the chain, and any chain it is the last node of, leading nowhere.
	void set_endpoint(audio_node* node, unsigned int input_bus_index) override {
		std::lock_guard<std::recursive_mutex> chain_lock(chain_mutex);
		audio_node *old = endpoint;
		if (node) {
			bool attached = !nodes.empty()? last()->attach_output_bus(0, node, input_bus_index) : audio_node_impl::attach_output_bus(0, node, input_bus_index);
			if (!attached) return; // get_endpoint() tells the attach failed.
			endpoint = node;
			endpoint->duplicate();
			endpoint_input_bus_index = input_bus_index;
		} else if (old) {
			if (!nodes.empty()) last()->detach_output_bus(0);
			else audio_node_impl::detach_output_bus(0);
			endpoint = nullptr;
		}
		if (old) old->release(); // Last, as it can be the node just attached again.
	}
	audio_node* get_endpoint() const override {
		std::lock_guard<std::recursive_mutex> chain_lock(chain_mutex);
		return endpoint;
	}
	audio_node* first() const override {
		std::lock_guard<std::recursive_mutex> chain_lock(chain_mutex);
		if (nodes.empty()) return nullptr;
		return nodes[0];
	}
	audio_node* last() const override {
		std::lock_guard<std::recursive_mutex> chain_lock(chain_mutex);
		if (nodes.empty()) return nullptr;
		return nodes[nodes.size() -1];
	}
	audio_node* operator[](unsigned int index) const override {
		std::lock_guard<std::recursive_mutex> chain_lock(chain_mutex);
		if (nodes.size() <= index) return nullptr;
		return nodes[index];
	}
	int index_of(audio_node* node) const override {
		std::lock_guard<std::recursive_mutex> chain_lock(chain_mutex);
		auto it = find(nodes.begin(), nodes.end(), node);
		if (it == nodes.end()) return -1;
		return distance(nodes.begin(), it);
	}
	unsigned int get_node_count() const override {
		std::lock_guard<std::recursive_mutex> chain_lock(chain_mutex);
		return nodes.size();
	}
};
audio_node_chain* audio_node_chain::create(audio_node* source, audio_node* endpoint, audio_engine* engine) { return new audio_node_chain_impl(source, endpoint, engine); }

static IPLAudioSettings g_phonon_audio_settings {44100, SOUNDSYSTEM_FRAMESIZE}; // We will update samplerate later in phonon_init.
static IPLContext g_phonon_context = nullptr;
static IPLHRTF g_phonon_hrtf = nullptr;

// Under a lock, as the first Steam Audio components can be made on several threads at once, each of which would otherwise make a context, or find the context made but not yet the HRTF.
static std::mutex g_phonon_init_mutex;
bool phonon_init() {
	std::lock_guard<std::mutex> lock(g_phonon_init_mutex);
	if (g_phonon_context) return true;
	audio_engine *engine = acquire_default_engine();
	if (!engine) return false;
	g_phonon_audio_settings = {engine->get_sample_rate(), SOUNDSYSTEM_FRAMESIZE};
	engine->release();
	IPLContextSettings phonon_context_settings{};
	phonon_context_settings.version = STEAMAUDIO_VERSION;
	if (iplContextCreate(&phonon_context_settings, &g_phonon_context) != IPL_STATUS_SUCCESS) return false;
	IPLHRTFSettings phonon_hrtf_settings{};
	phonon_hrtf_settings.type = IPL_HRTFTYPE_DEFAULT;
	phonon_hrtf_settings.volume = 1.0;
	if (iplHRTFCreate(g_phonon_context, &g_phonon_audio_settings, &phonon_hrtf_settings, &g_phonon_hrtf) != IPL_STATUS_SUCCESS) {
		iplContextRelease(&g_phonon_context);
		g_phonon_context = nullptr;
		return false;
	}
	return true;
}

// Sets the defaults and the enabled components each time, as the docs say it does, whatever get_global_hrtf() read before: enabling both components by hand left the defaults as they were.
bool set_global_hrtf(bool enabled) {
	if (enabled) {
		if (!phonon_init()) return false;
		if (!sound_set_spatialization(g_audio_phonon_hrtf_panner, g_audio_phonon_attenuator)) return false;
	} else {
		// Basic panning and attenuation first, which the docs say false uses: a script that made HRTF exclusive with sound_set_spatialization() had disabled them, and disabling the phonon components below then left every positioned sound with neither, playing centred at full volume.
		if (!get_audio_panner_enabled(g_audio_basic_panner)) set_audio_panner_enabled(g_audio_basic_panner, true);
		if (!get_audio_attenuator_enabled(g_audio_basic_attenuator)) set_audio_attenuator_enabled(g_audio_basic_attenuator, true);
		if (sound_get_default_3d_panner() == g_audio_phonon_hrtf_panner) sound_set_default_3d_panner(g_audio_basic_panner);
		if (sound_get_default_3d_attenuator() == g_audio_phonon_attenuator) sound_set_default_3d_attenuator(g_audio_basic_attenuator);
		set_audio_panner_enabled(g_audio_phonon_hrtf_panner, false);
		set_audio_attenuator_enabled(g_audio_phonon_attenuator, false);
	}
	return true;
}
// Whether sounds are positioned with HRTF: its panner and attenuator enabled, and the defaults new sounds take.
bool get_global_hrtf() { return get_audio_panner_enabled(g_audio_phonon_hrtf_panner) && get_audio_attenuator_enabled(g_audio_phonon_attenuator) && sound_get_default_3d_panner() == g_audio_phonon_hrtf_panner && sound_get_default_3d_attenuator() == g_audio_phonon_attenuator; }

class phonon_binaural_node_impl : public audio_node_impl, public virtual phonon_binaural_node {
	unique_ptr<ma_phonon_binaural_node> bn;
	public:
		phonon_binaural_node_impl(audio_engine* e, int channels, int sample_rate, int frame_size = 0) : bn(make_unique<ma_phonon_binaural_node>()), audio_node_impl(nullptr, e) {
			if (!e) throw std::invalid_argument("no engine provided");
			if (!phonon_init()) throw std::runtime_error("Steam Audio was not initialized");
			// The HRTF's own settings, whatever sample_rate and frame_size say: Steam Audio applied the HRTF, made for blocks of SOUNDSYSTEM_FRAMESIZE frames, at the frame size given, which past it made the output wrong, then garbage at many times full scale, and at 65536 crashed; the sample rate changed nothing.
			(void)sample_rate;
			(void)frame_size;
			ma_phonon_binaural_node_config cfg = ma_phonon_binaural_node_config_init(channels, g_phonon_audio_settings, g_phonon_context, g_phonon_hrtf);
			if ((g_soundsystem_last_error = ma_phonon_binaural_node_init(ma_engine_get_node_graph(e->get_ma_engine()), &cfg, nullptr, &*bn)) != MA_SUCCESS) throw std::runtime_error("phonon_binaural_node was not created");
			node = (ma_node_base*)&*bn;
		}
		~phonon_binaural_node_impl() {
			if (bn) {
				std::lock_guard<std::recursive_mutex> graph_lock(g_node_graph_mutex); // Uninitializing detaches it from the nodes it is attached to, the same lists other threads attach to and detach from under this lock.
				ma_phonon_binaural_node_uninit(&*bn, nullptr);
			}
		}
		void set_direction(float x, float y, float z, float distance) override {
			if (!finite_node_values({x, y, z, distance})) return;
			// A negative distance made a negative spatial blend, which Steam Audio amplified exponentially: 24 times at -2, then to infinity and NaN, which spoiled the engine's whole mix. It is taken as 0, at the listener, as a negative min_distance is, so that the direction is still set, as one worked out a little under 0 by rounding needs.
			ma_phonon_binaural_node_set_direction(&*bn, x, y, z, distance < 0? 0 : distance);
		}
		void set_direction_vector(const reactphysics3d::Vector3& direction, float distance) override { set_direction(direction.x, direction.y, direction.z, distance); }
		void set_spatial_blend_max_distance(float max_distance) override { if (finite_node_values({max_distance})) ma_phonon_binaural_node_set_spatial_blend_max_distance(&*bn, max_distance); }
};
phonon_binaural_node* phonon_binaural_node::create(audio_engine* e, int channels, int sample_rate, int frame_size) { return new phonon_binaural_node_impl(e, channels, sample_rate, frame_size); }

class splitter_node_impl : public audio_node_impl, public virtual splitter_node {
	unique_ptr<ma_splitter_node> sn;
	public:
	splitter_node_impl(audio_engine* e, int channels) : sn(make_unique<ma_splitter_node>()), audio_node_impl(nullptr, e) {
		if (channels < 1 || channels > MA_MAX_CHANNELS) throw std::runtime_error("invalid channel count"); // A node's channel count is kept in 8 bits.
		ma_splitter_node_config cfg = ma_splitter_node_config_init(channels);
		if ((g_soundsystem_last_error = ma_splitter_node_init(ma_engine_get_node_graph(get_engine()->get_ma_engine()), &cfg, nullptr, &*sn)) != MA_SUCCESS) throw std::runtime_error("ma_splitter_node was not initialized");
		node = (ma_node_base*)&*sn;
	}
	~splitter_node_impl() {
		if (sn) {
			std::lock_guard<std::recursive_mutex> graph_lock(g_node_graph_mutex); // Uninitializing detaches it from the nodes it is attached to, the same lists other threads attach to and detach from under this lock.
			ma_splitter_node_uninit(&*sn, nullptr);
		}
	}
};
splitter_node* splitter_node::create(audio_engine* e, int channels) { return new splitter_node_impl(e, channels); }

class low_pass_filter_node_impl : public audio_node_impl, public virtual low_pass_filter_node {
	unique_ptr<ma_lpf_node> fn;
	ma_lpf_node_config cfg;
	public:
	low_pass_filter_node_impl(double cutoff_frequency, int order, audio_engine* e) : fn(make_unique<ma_lpf_node>()), audio_node_impl(nullptr, e) {
		if (!finite_node_values({cutoff_frequency}) || !(cutoff_frequency = usable_frequency(cutoff_frequency, get_engine()->get_sample_rate(), [&](double f) { return sections_in_range(pass_filter::low, f, order, get_engine()->get_sample_rate()); }))) throw std::invalid_argument("filter setting out of range");
		cfg = ma_lpf_node_config_init(get_engine()->get_channels(), get_engine()->get_sample_rate(), cutoff_frequency, order);
		if ((g_soundsystem_last_error = ma_lpf_node_init(ma_engine_get_node_graph(get_engine()->get_ma_engine()), &cfg, nullptr, &*fn)) != MA_SUCCESS) throw std::runtime_error("ma_low_pass_filter_node was not initialized");
		node = (ma_node_base*)&*fn;
	}
	~low_pass_filter_node_impl() {
		if (fn) {
			std::lock_guard<std::recursive_mutex> graph_lock(g_node_graph_mutex); // Uninitializing detaches it from the nodes it is attached to, the same lists other threads attach to and detach from under this lock.
			ma_lpf_node_uninit(&*fn, nullptr);
		}
	}
	void set_cutoff_frequency(double freq) override {
		if (!finite_node_values({freq})) return;
		if (!(freq = usable_frequency(freq, cfg.lpf.sampleRate, [&](double f) { return sections_in_range(pass_filter::low, f, cfg.lpf.order, cfg.lpf.sampleRate); }))) return;
		auto previous = cfg.lpf.cutoffFrequency;
		cfg.lpf.cutoffFrequency = freq;
		if ((g_soundsystem_last_error = ma_lpf_node_reinit(&cfg.lpf, &*fn)) != MA_SUCCESS) cfg.lpf.cutoffFrequency = previous; // MiniAudio refuses some changes, as of a filter's order, which is fixed when it is made; the filter then keeps what it had, and so does this.
	}
	double get_cutoff_frequency() const override { return cfg.lpf.cutoffFrequency; }
	void set_order(unsigned int order) override {
		auto previous = cfg.lpf.order;
		cfg.lpf.order = order;
		if ((g_soundsystem_last_error = ma_lpf_node_reinit(&cfg.lpf, &*fn)) != MA_SUCCESS) cfg.lpf.order = previous;
	}
	unsigned int get_order() const override { return cfg.lpf.order; }
};
low_pass_filter_node* low_pass_filter_node::create(double cutoff_frequency, unsigned int order, audio_engine* engine) { return new low_pass_filter_node_impl(cutoff_frequency, order, engine); }

class high_pass_filter_node_impl : public audio_node_impl, public virtual high_pass_filter_node {
	unique_ptr<ma_hpf_node> fn;
	ma_hpf_node_config cfg;
	public:
	high_pass_filter_node_impl(double cutoff_frequency, int order, audio_engine* e) : fn(make_unique<ma_hpf_node>()), audio_node_impl(nullptr, e) {
		if (!finite_node_values({cutoff_frequency}) || !(cutoff_frequency = usable_frequency(cutoff_frequency, get_engine()->get_sample_rate(), [&](double f) { return sections_in_range(pass_filter::high, f, order, get_engine()->get_sample_rate()); }))) throw std::invalid_argument("filter setting out of range");
		cfg = ma_hpf_node_config_init(get_engine()->get_channels(), get_engine()->get_sample_rate(), cutoff_frequency, order);
		if ((g_soundsystem_last_error = ma_hpf_node_init(ma_engine_get_node_graph(get_engine()->get_ma_engine()), &cfg, nullptr, &*fn)) != MA_SUCCESS) throw std::runtime_error("ma_high_pass_filter_node was not initialized");
		node = (ma_node_base*)&*fn;
	}
	~high_pass_filter_node_impl() {
		if (fn) {
			std::lock_guard<std::recursive_mutex> graph_lock(g_node_graph_mutex); // Uninitializing detaches it from the nodes it is attached to, the same lists other threads attach to and detach from under this lock.
			ma_hpf_node_uninit(&*fn, nullptr);
		}
	}
	void set_cutoff_frequency(double freq) override {
		if (!finite_node_values({freq})) return;
		if (!(freq = usable_frequency(freq, cfg.hpf.sampleRate, [&](double f) { return sections_in_range(pass_filter::high, f, cfg.hpf.order, cfg.hpf.sampleRate); }))) return;
		auto previous = cfg.hpf.cutoffFrequency;
		cfg.hpf.cutoffFrequency = freq;
		if ((g_soundsystem_last_error = ma_hpf_node_reinit(&cfg.hpf, &*fn)) != MA_SUCCESS) cfg.hpf.cutoffFrequency = previous;
	}
	double get_cutoff_frequency() const override { return cfg.hpf.cutoffFrequency; }
	void set_order(unsigned int order) override {
		auto previous = cfg.hpf.order;
		cfg.hpf.order = order;
		if ((g_soundsystem_last_error = ma_hpf_node_reinit(&cfg.hpf, &*fn)) != MA_SUCCESS) cfg.hpf.order = previous;
	}
	unsigned int get_order() const override { return cfg.hpf.order; }
};
high_pass_filter_node* high_pass_filter_node::create(double cutoff_frequency, unsigned int order, audio_engine* engine) { return new high_pass_filter_node_impl(cutoff_frequency, order, engine); }

class band_pass_filter_node_impl : public audio_node_impl, public virtual band_pass_filter_node {
	unique_ptr<ma_bpf_node> fn;
	ma_bpf_node_config cfg;
	public:
	band_pass_filter_node_impl(double cutoff_frequency, int order, audio_engine* e) : fn(make_unique<ma_bpf_node>()), audio_node_impl(nullptr, e) {
		if (!finite_node_values({cutoff_frequency}) || !(cutoff_frequency = usable_frequency(cutoff_frequency, get_engine()->get_sample_rate(), [&](double f) { return sections_in_range(pass_filter::band, f, order, get_engine()->get_sample_rate()); }))) throw std::invalid_argument("filter setting out of range");
		cfg = ma_bpf_node_config_init(get_engine()->get_channels(), get_engine()->get_sample_rate(), cutoff_frequency, order);
		if ((g_soundsystem_last_error = ma_bpf_node_init(ma_engine_get_node_graph(get_engine()->get_ma_engine()), &cfg, nullptr, &*fn)) != MA_SUCCESS) throw std::runtime_error("ma_band_pass_filter_node was not initialized");
		node = (ma_node_base*)&*fn;
	}
	~band_pass_filter_node_impl() {
		if (fn) {
			std::lock_guard<std::recursive_mutex> graph_lock(g_node_graph_mutex); // Uninitializing detaches it from the nodes it is attached to, the same lists other threads attach to and detach from under this lock.
			ma_bpf_node_uninit(&*fn, nullptr);
		}
	}
	void set_cutoff_frequency(double freq) override {
		if (!finite_node_values({freq})) return;
		if (!(freq = usable_frequency(freq, cfg.bpf.sampleRate, [&](double f) { return sections_in_range(pass_filter::band, f, cfg.bpf.order, cfg.bpf.sampleRate); }))) return;
		auto previous = cfg.bpf.cutoffFrequency;
		cfg.bpf.cutoffFrequency = freq;
		if ((g_soundsystem_last_error = ma_bpf_node_reinit(&cfg.bpf, &*fn)) != MA_SUCCESS) cfg.bpf.cutoffFrequency = previous;
	}
	double get_cutoff_frequency() const override { return cfg.bpf.cutoffFrequency; }
	void set_order(unsigned int order) override {
		auto previous = cfg.bpf.order;
		cfg.bpf.order = order;
		if ((g_soundsystem_last_error = ma_bpf_node_reinit(&cfg.bpf, &*fn)) != MA_SUCCESS) cfg.bpf.order = previous;
	}
	unsigned int get_order() const override { return cfg.bpf.order; }
};
band_pass_filter_node* band_pass_filter_node::create(double cutoff_frequency, unsigned int order, audio_engine* engine) { return new band_pass_filter_node_impl(cutoff_frequency, order, engine); }

class notch_filter_node_impl : public audio_node_impl, public virtual notch_filter_node {
	unique_ptr<ma_notch_node> fn;
	ma_notch_node_config cfg;
	public:
	notch_filter_node_impl(double q, double frequency, audio_engine* e) : fn(make_unique<ma_notch_node>()), audio_node_impl(nullptr, e) {
		if (!finite_node_values({q, frequency}) || !q_in_range(q) || !(frequency = usable_frequency(frequency, get_engine()->get_sample_rate(), [&](double f) { return notch_in_range(q, f, get_engine()->get_sample_rate()); }))) throw std::invalid_argument("filter setting out of range");
		cfg = ma_notch_node_config_init(get_engine()->get_channels(), get_engine()->get_sample_rate(), q, frequency);
		if ((g_soundsystem_last_error = ma_notch_node_init(ma_engine_get_node_graph(get_engine()->get_ma_engine()), &cfg, nullptr, &*fn)) != MA_SUCCESS) throw std::runtime_error("ma_notch_filter_node was not initialized");
		node = (ma_node_base*)&*fn;
	}
	~notch_filter_node_impl() {
		if (fn) {
			std::lock_guard<std::recursive_mutex> graph_lock(g_node_graph_mutex); // Uninitializing detaches it from the nodes it is attached to, the same lists other threads attach to and detach from under this lock.
			ma_notch_node_uninit(&*fn, nullptr);
		}
	}
	void set_q(double q) override {
		if (!finite_node_values({q})) return;
		if (!q_in_range(q) || !notch_in_range(q, cfg.notch.frequency, cfg.notch.sampleRate)) return;
		auto previous = cfg.notch.q;
		cfg.notch.q = q;
		if ((g_soundsystem_last_error = ma_notch_node_reinit(&cfg.notch, &*fn)) != MA_SUCCESS) cfg.notch.q = previous;
	}
	double get_q() const override { return cfg.notch.q; }
	void set_frequency(double freq) override {
		if (!finite_node_values({freq})) return;
		if (!(freq = usable_frequency(freq, cfg.notch.sampleRate, [&](double f) { return notch_in_range(cfg.notch.q, f, cfg.notch.sampleRate); }))) return;
		auto previous = cfg.notch.frequency;
		cfg.notch.frequency = freq;
		if ((g_soundsystem_last_error = ma_notch_node_reinit(&cfg.notch, &*fn)) != MA_SUCCESS) cfg.notch.frequency = previous;
	}
	double get_frequency() const override { return cfg.notch.frequency; }
};
notch_filter_node* notch_filter_node::create(double q, double frequency, audio_engine* engine) { return new notch_filter_node_impl(q, frequency, engine); }

class peak_filter_node_impl : public audio_node_impl, public virtual peak_filter_node {
	unique_ptr<ma_peak_node> fn;
	ma_peak_node_config cfg;
	public:
	peak_filter_node_impl(double gain_db, double q, double frequency, audio_engine* e) : fn(make_unique<ma_peak_node>()), audio_node_impl(nullptr, e) {
		if (std::isfinite(gain_db)) gain_db = clamped_gain(gain_db);
		if (!finite_node_values({gain_db, q, frequency}) || !q_in_range(q) || !(frequency = usable_frequency(frequency, get_engine()->get_sample_rate(), [&](double f) { return peak_in_range(gain_db, q, f, get_engine()->get_sample_rate()); }))) throw std::invalid_argument("filter setting out of range");
		cfg = ma_peak_node_config_init(get_engine()->get_channels(), get_engine()->get_sample_rate(), gain_db, q, frequency);
		if ((g_soundsystem_last_error = ma_peak_node_init(ma_engine_get_node_graph(get_engine()->get_ma_engine()), &cfg, nullptr, &*fn)) != MA_SUCCESS) throw std::runtime_error("ma_peak_filter_node was not initialized");
		node = (ma_node_base*)&*fn;
	}
	~peak_filter_node_impl() {
		if (fn) {
			std::lock_guard<std::recursive_mutex> graph_lock(g_node_graph_mutex); // Uninitializing detaches it from the nodes it is attached to, the same lists other threads attach to and detach from under this lock.
			ma_peak_node_uninit(&*fn, nullptr);
		}
	}
	void set_gain(double gain) override {
		if (!finite_node_values({gain})) return;
		gain = clamped_gain(gain);
		if (!peak_in_range(gain, cfg.peak.q, cfg.peak.frequency, cfg.peak.sampleRate)) return;
		auto previous = cfg.peak.gainDB;
		cfg.peak.gainDB = gain;
		if ((g_soundsystem_last_error = ma_peak_node_reinit(&cfg.peak, &*fn)) != MA_SUCCESS) cfg.peak.gainDB = previous;
	}
	double get_gain() const override { return cfg.peak.gainDB; }
	void set_q(double q) override {
		if (!finite_node_values({q})) return;
		if (!q_in_range(q) || !peak_in_range(cfg.peak.gainDB, q, cfg.peak.frequency, cfg.peak.sampleRate)) return;
		auto previous = cfg.peak.q;
		cfg.peak.q = q;
		if ((g_soundsystem_last_error = ma_peak_node_reinit(&cfg.peak, &*fn)) != MA_SUCCESS) cfg.peak.q = previous;
	}
	double get_q() const override { return cfg.peak.q; }
	void set_frequency(double freq) override {
		if (!finite_node_values({freq})) return;
		if (!(freq = usable_frequency(freq, cfg.peak.sampleRate, [&](double f) { return peak_in_range(cfg.peak.gainDB, cfg.peak.q, f, cfg.peak.sampleRate); }))) return;
		auto previous = cfg.peak.frequency;
		cfg.peak.frequency = freq;
		if ((g_soundsystem_last_error = ma_peak_node_reinit(&cfg.peak, &*fn)) != MA_SUCCESS) cfg.peak.frequency = previous;
	}
	double get_frequency() const override { return cfg.peak.frequency; }
};
peak_filter_node* peak_filter_node::create(double gain_db, double q, double frequency, audio_engine* engine) { return new peak_filter_node_impl(gain_db, q, frequency, engine); }

class low_shelf_filter_node_impl : public audio_node_impl, public virtual low_shelf_filter_node {
	unique_ptr<ma_loshelf_node> fn;
	ma_loshelf_node_config cfg;
	public:
	low_shelf_filter_node_impl(double gain_db, double q, double frequency, audio_engine* e) : fn(make_unique<ma_loshelf_node>()), audio_node_impl(nullptr, e) {
		if (std::isfinite(gain_db)) gain_db = clamped_gain(gain_db);
		if (!finite_node_values({gain_db, q, frequency}) || !q_in_range(q) || !(frequency = usable_frequency(frequency, get_engine()->get_sample_rate(), [&](double f) { return shelf_in_range(false, gain_db, q, f, get_engine()->get_sample_rate()); }))) throw std::invalid_argument("filter setting out of range");
		cfg = ma_loshelf_node_config_init(get_engine()->get_channels(), get_engine()->get_sample_rate(), gain_db, q, frequency);
		if ((g_soundsystem_last_error = ma_loshelf_node_init(ma_engine_get_node_graph(get_engine()->get_ma_engine()), &cfg, nullptr, &*fn)) != MA_SUCCESS) throw std::runtime_error("ma_low_shelf_filter_node was not initialized");
		node = (ma_node_base*)&*fn;
	}
	~low_shelf_filter_node_impl() {
		if (fn) {
			std::lock_guard<std::recursive_mutex> graph_lock(g_node_graph_mutex); // Uninitializing detaches it from the nodes it is attached to, the same lists other threads attach to and detach from under this lock.
			ma_loshelf_node_uninit(&*fn, nullptr);
		}
	}
	void set_gain(double gain) override {
		if (!finite_node_values({gain})) return;
		gain = clamped_gain(gain);
		if (!shelf_in_range(false, gain, cfg.loshelf.shelfSlope, cfg.loshelf.frequency, cfg.loshelf.sampleRate)) return;
		auto previous = cfg.loshelf.gainDB;
		cfg.loshelf.gainDB = gain;
		if ((g_soundsystem_last_error = ma_loshelf_node_reinit(&cfg.loshelf, &*fn)) != MA_SUCCESS) cfg.loshelf.gainDB = previous;
	}
	double get_gain() const override { return cfg.loshelf.gainDB; }
	void set_q(double q) override {
		if (!finite_node_values({q})) return;
		if (!q_in_range(q) || !shelf_in_range(false, cfg.loshelf.gainDB, q, cfg.loshelf.frequency, cfg.loshelf.sampleRate)) return;
		auto previous = cfg.loshelf.shelfSlope;
		cfg.loshelf.shelfSlope = q;
		if ((g_soundsystem_last_error = ma_loshelf_node_reinit(&cfg.loshelf, &*fn)) != MA_SUCCESS) cfg.loshelf.shelfSlope = previous;
	}
	double get_q() const override { return cfg.loshelf.shelfSlope; }
	void set_frequency(double freq) override {
		if (!finite_node_values({freq})) return;
		if (!(freq = usable_frequency(freq, cfg.loshelf.sampleRate, [&](double f) { return shelf_in_range(false, cfg.loshelf.gainDB, cfg.loshelf.shelfSlope, f, cfg.loshelf.sampleRate); }))) return;
		auto previous = cfg.loshelf.frequency;
		cfg.loshelf.frequency = freq;
		if ((g_soundsystem_last_error = ma_loshelf_node_reinit(&cfg.loshelf, &*fn)) != MA_SUCCESS) cfg.loshelf.frequency = previous;
	}
	double get_frequency() const override { return cfg.loshelf.frequency; }
};
low_shelf_filter_node* low_shelf_filter_node::create(double gain_db, double q, double frequency, audio_engine* engine) { return new low_shelf_filter_node_impl(gain_db, q, frequency, engine); }

class high_shelf_filter_node_impl : public audio_node_impl, public virtual high_shelf_filter_node {
	unique_ptr<ma_hishelf_node> fn;
	ma_hishelf_node_config cfg;
	public:
	high_shelf_filter_node_impl(double gain_db, double q, double frequency, audio_engine* e) : fn(make_unique<ma_hishelf_node>()), audio_node_impl(nullptr, e) {
		if (std::isfinite(gain_db)) gain_db = clamped_gain(gain_db);
		if (!finite_node_values({gain_db, q, frequency}) || !q_in_range(q) || !(frequency = usable_frequency(frequency, get_engine()->get_sample_rate(), [&](double f) { return shelf_in_range(true, gain_db, q, f, get_engine()->get_sample_rate()); }))) throw std::invalid_argument("filter setting out of range");
		cfg = ma_hishelf_node_config_init(get_engine()->get_channels(), get_engine()->get_sample_rate(), gain_db, q, frequency);
		if ((g_soundsystem_last_error = ma_hishelf_node_init(ma_engine_get_node_graph(get_engine()->get_ma_engine()), &cfg, nullptr, &*fn)) != MA_SUCCESS) throw std::runtime_error("ma_high_shelf_filter_node was not initialized");
		node = (ma_node_base*)&*fn;
	}
	~high_shelf_filter_node_impl() {
		if (fn) {
			std::lock_guard<std::recursive_mutex> graph_lock(g_node_graph_mutex); // Uninitializing detaches it from the nodes it is attached to, the same lists other threads attach to and detach from under this lock.
			ma_hishelf_node_uninit(&*fn, nullptr);
		}
	}
	void set_gain(double gain) override {
		if (!finite_node_values({gain})) return;
		gain = clamped_gain(gain);
		if (!shelf_in_range(true, gain, cfg.hishelf.shelfSlope, cfg.hishelf.frequency, cfg.hishelf.sampleRate)) return;
		auto previous = cfg.hishelf.gainDB;
		cfg.hishelf.gainDB = gain;
		if ((g_soundsystem_last_error = ma_hishelf_node_reinit(&cfg.hishelf, &*fn)) != MA_SUCCESS) cfg.hishelf.gainDB = previous;
	}
	double get_gain() const override { return cfg.hishelf.gainDB; }
	void set_q(double q) override {
		if (!finite_node_values({q})) return;
		if (!q_in_range(q) || !shelf_in_range(true, cfg.hishelf.gainDB, q, cfg.hishelf.frequency, cfg.hishelf.sampleRate)) return;
		auto previous = cfg.hishelf.shelfSlope;
		cfg.hishelf.shelfSlope = q;
		if ((g_soundsystem_last_error = ma_hishelf_node_reinit(&cfg.hishelf, &*fn)) != MA_SUCCESS) cfg.hishelf.shelfSlope = previous;
	}
	double get_q() const override { return cfg.hishelf.shelfSlope; }
	void set_frequency(double freq) override {
		if (!finite_node_values({freq})) return;
		if (!(freq = usable_frequency(freq, cfg.hishelf.sampleRate, [&](double f) { return shelf_in_range(true, cfg.hishelf.gainDB, cfg.hishelf.shelfSlope, f, cfg.hishelf.sampleRate); }))) return;
		auto previous = cfg.hishelf.frequency;
		cfg.hishelf.frequency = freq;
		if ((g_soundsystem_last_error = ma_hishelf_node_reinit(&cfg.hishelf, &*fn)) != MA_SUCCESS) cfg.hishelf.frequency = previous;
	}
	double get_frequency() const override { return cfg.hishelf.frequency; }
};
high_shelf_filter_node* high_shelf_filter_node::create(double gain_db, double q, double frequency, audio_engine* engine) { return new high_shelf_filter_node_impl(gain_db, q, frequency, engine); }

class delay_node_impl : public audio_node_impl, public virtual delay_node {
	unique_ptr<ma_delay_node> dn;
	public:
	delay_node_impl(unsigned int delay_in_frames, float decay, audio_engine* e) : dn(make_unique<ma_delay_node>()), audio_node_impl(nullptr, e) {
		// MiniAudio takes neither a delay of 0, by which it divides while processing, nor one whose buffer size overflows 32 bits, which it then allocates too small and overruns.
		if (delay_in_frames == 0 || uint64_t(delay_in_frames) * get_engine()->get_channels() * sizeof(float) > UINT32_MAX) throw std::invalid_argument("delay out of range");
		if (!finite_node_values({decay})) throw std::invalid_argument("decay out of range");
		decay = clamped_unit(decay);
		ma_delay_node_config cfg = ma_delay_node_config_init(get_engine()->get_channels(), get_engine()->get_sample_rate(), delay_in_frames, decay);
		if ((g_soundsystem_last_error = ma_delay_node_init(ma_engine_get_node_graph(get_engine()->get_ma_engine()), &cfg, nullptr, &*dn)) != MA_SUCCESS) throw std::runtime_error("ma_delay_node was not initialized");
		node = (ma_node_base*)&*dn;
	}
	~delay_node_impl() {
		if (dn) {
			std::lock_guard<std::recursive_mutex> graph_lock(g_node_graph_mutex); // Uninitializing detaches it from the nodes it is attached to, the same lists other threads attach to and detach from under this lock.
			ma_delay_node_uninit(&*dn, nullptr);
		}
	}
	void set_wet(float wet) override { if (finite_node_values({wet})) ma_delay_node_set_wet(&*dn, wet); }
	float get_wet() const override { return ma_delay_node_get_wet(&*dn); }
	void set_dry(float dry) override { if (finite_node_values({dry})) ma_delay_node_set_dry(&*dn, dry); }
	float get_dry() const override { return ma_delay_node_get_dry(&*dn); }
	void set_decay(float decay) override { if (finite_node_values({decay})) ma_delay_node_set_decay(&*dn, clamped_unit(decay)); }
	float get_decay() const override { return ma_delay_node_get_decay(&*dn); }
};
delay_node* delay_node::create(unsigned int delay_in_frames, float decay, audio_engine* engine) { return new delay_node_impl(delay_in_frames, decay, engine); }

class freeverb_node_impl : public audio_node_impl, public virtual freeverb_node {
	unique_ptr<ma_reverb_node> rn;
	public:
	freeverb_node_impl(audio_engine* e) : rn(make_unique<ma_reverb_node>()), audio_node_impl(nullptr, e) {
		ma_reverb_node_config cfg = ma_reverb_node_config_init(get_engine()->get_channels(), get_engine()->get_sample_rate());
		if ((g_soundsystem_last_error = ma_reverb_node_init(ma_engine_get_node_graph(get_engine()->get_ma_engine()), &cfg, nullptr, &*rn)) != MA_SUCCESS) throw std::runtime_error("ma_reverb_node was not initialized");
		node = (ma_node_base*)&*rn;
	}
	~freeverb_node_impl() {
		if (rn) {
			std::lock_guard<std::recursive_mutex> graph_lock(g_node_graph_mutex); // Uninitializing detaches it from the nodes it is attached to, the same lists other threads attach to and detach from under this lock.
			ma_reverb_node_uninit(&*rn, nullptr);
		}
	}
	void set_room_size(float size) override { if (rn && finite_node_values({size})) verblib_set_room_size(&rn->reverb, clamped_unit(size)); }
	float get_room_size() const override { return rn? verblib_get_room_size(&rn->reverb) : -1; }
	void set_damping(float damping) override { if (rn && finite_node_values({damping})) verblib_set_damping(&rn->reverb, clamped_unit(damping)); }
	float get_damping() const override { return rn? verblib_get_damping(&rn->reverb) : -1; }
	void set_width(float width) override { if (rn && finite_node_values({width})) verblib_set_width(&rn->reverb, width); }
	float get_width() const override { return rn? verblib_get_width(&rn->reverb) : -1; }
	void set_wet(float wet) override { if (rn && finite_node_values({wet})) verblib_set_wet(&rn->reverb, wet); }
	float get_wet() const override { return rn? verblib_get_wet(&rn->reverb) : -1; }
	void set_dry(float dry) override { if (rn && finite_node_values({dry})) verblib_set_dry(&rn->reverb, dry); }
	float get_dry() const override { return rn? verblib_get_dry(&rn->reverb) : -1; }
	void set_input_width(float width) override { if (rn && finite_node_values({width})) verblib_set_input_width(&rn->reverb, width); }
	float get_input_width() const override { return rn? verblib_get_input_width(&rn->reverb) : -1; }
	void set_frozen(bool frozen) override { if (rn) verblib_set_mode(&rn->reverb, frozen? 1 : 0); }
	bool get_frozen() const override { return rn? verblib_get_mode(&rn->reverb) >= 0.5 : false; }
};
freeverb_node* freeverb_node::create(audio_engine* e) { return new freeverb_node_impl(e); }

class reverb3d_impl : public passthrough_node_impl, public virtual reverb3d {
	audio_node* reverb;
	mixer* output_mixer;
	float min_volume, max_volume, max_volume_distance, max_audible_distance, volume_curve;
public:
	reverb3d_impl(audio_engine* e, audio_node* reverb, mixer* destination) : passthrough_node_impl(e), output_mixer(destination), reverb(reverb), min_volume(-7), max_volume(-5), max_volume_distance(7), max_audible_distance(60), volume_curve(0.4) {
		if (output_mixer) output_mixer->duplicate(); // reverb owns its own reference to output_mixer via attach_output_bus below; this is reverb3d_impl's separate reference for get_mixer().
		if (reverb) wire_reverb(reverb);
	}
	// Attaches this node to the reverb and the reverb to the destination, keeping the reverb only when it took this node's output, as for one of another channel count it wouldn't. The reverb3d holds a reference of its own to the reverb, as a script can detach this node, which is an audio_node, from it.
	void wire_reverb(audio_node* verb) {
		reverb = nullptr;
		if (!attach_output_bus(0, verb, 0)) return;
		reverb = verb;
		reverb->duplicate();
		reverb->attach_output_bus(0, output_mixer? static_cast<audio_node*>(output_mixer) : get_engine()->get_endpoint(), 0);
	}
	~reverb3d_impl() {
		if (reverb) reverb->release();
		if (output_mixer) output_mixer->release();
	}
	void set_reverb(audio_node* verb) override {
		if (reverb) {
			reverb->detach_output_bus(0); // From the mixer or, without one, the engine's endpoint, which the reverb was attached to alike.
			detach_output_bus(0);
			reverb->release();
		}
		reverb = nullptr;
		if (verb) wire_reverb(verb);
	}
	audio_node* get_reverb() const override { return reverb; }
	void set_mixer(mixer* mix) override {
		if (mix && mix->get_engine() != get_engine()) { // As for a sound's mixer: another engine's mixer is read by that engine's audio thread too.
			g_soundsystem_last_error = MA_INVALID_ARGS;
			return;
		}
		mixer* old;
		{
			std::lock_guard<std::recursive_mutex> topology(g_audio_topology_mutex);
			if (mix && mixer_reaches(mix, [this](mixer* m) { return m->get_reverb3d_sent_to() == static_cast<reverb3d*>(this); })) { // Not into a mixer that sends to this reverb3d, nor one that goes into such a mixer (see mixer_reaches()).
				g_soundsystem_last_error = MA_INVALID_ARGS;
				return;
			}
			// Attached to the new destination before the old one goes, which attaching replaces: one without an input, as a sound, is refused, the reverb staying where it was, rather than left going nowhere while mixer read the sound.
			if (reverb && !reverb->attach_output_bus(0, mix? static_cast<audio_node*>(mix) : get_engine()->get_endpoint(), 0)) return;
			old = output_mixer;
			output_mixer = mix;
			if (output_mixer) output_mixer->duplicate();
		}
		if (old) old->release();
	}
	mixer* get_mixer() const override { return output_mixer; }
	// Not a value that isn't finite, as for other nodes: the volume read NaN or infinite, and the send, which refuses such a volume, stopped following the distance.
	void set_min_volume(float value) override { if (finite_node_values({value, ma_volume_db_to_linear(value)})) min_volume = value; } // Nor one whose linear volume isn't, from about 770 dB, as other decibel settings.
	float get_min_volume() const override { return min_volume; }
	void set_max_volume(float value) override { if (finite_node_values({value, ma_volume_db_to_linear(value)})) max_volume = value; }
	float get_max_volume() const override { return max_volume; }
	void set_max_volume_distance(float value) override { if (finite_node_values({value})) max_volume_distance = value; }
	float get_max_volume_distance() const override { return max_volume_distance; }
	void set_max_audible_distance(float value) override { if (finite_node_values({value})) max_audible_distance = value; }
	float get_max_audible_distance() const override { return max_audible_distance; }
	void set_volume_curve(float value) override { if (finite_node_values({value})) volume_curve = value; }
	float get_volume_curve() const override { return volume_curve; }
	float get_volume_at(float distance) const override {
		if (distance > max_audible_distance) distance = max_audible_distance;
		float v;
		if (distance <= max_volume_distance) v = max_volume_distance > 0? range_convert(distance, 0, max_volume_distance, min_volume, max_volume) : max_volume; // A range of no width would divide by zero; its one point is max_volume_distance itself.
		else {
			if (volume_curve <= 0) return ma_volume_db_to_linear(max_volume);
			else if (volume_curve >= 1) return ma_volume_db_to_linear(min_volume);
			v = range_convert(distance, max_volume_distance, max_audible_distance, 1, 0);
			v = (1.0 - volume_curve) * ((v <= volume_curve? v : volume_curve) / volume_curve) + volume_curve * ((v > volume_curve? v - volume_curve : 0) / (1 - volume_curve));
			v = range_convert(v, 0, 1, -60, max_volume);
		}
		return ma_volume_db_to_linear(clamp_volume(v, max_volume < -70.0f? max_volume : -70.0f, max_volume)); // Not below -70 dB, unless the script set the loudest lower.
	}
	splitter_node* create_attachment(audio_node* dry_input, audio_node* dry_output) override {
		if (dry_input && dry_input->get_engine() != get_engine() || dry_output && dry_output->get_engine() != get_engine()) { // Both engines' audio threads would read the splitter.
			g_soundsystem_last_error = MA_INVALID_ARGS;
			return nullptr;
		}
		splitter_node* splitter = splitter_node::create(get_engine(), get_output_channels(0));
		if (dry_output && !splitter->attach_output_bus(0, dry_output, 0)) {
			splitter->release();
			return nullptr;
		}
		if (!splitter->attach_output_bus(1, this, 0)) {
			splitter->release();
			return nullptr;
		}
		if (dry_input && !dry_input->attach_output_bus(0, splitter, 0)) {
			splitter->release();
			return nullptr;
		}
		return splitter;
	}
};
// Without a destination, a new mixer of the reverb3d's own engine, as a reverb3d of the default engine always got one; a mixer of another engine is refused, as both engines' audio threads would read the reverb3d then.
std::recursive_mutex g_audio_topology_mutex;
bool mixer_reaches(mixer* from, const std::function<bool(mixer*)>& is_target) {
	std::vector<mixer*> pending{from};
	std::unordered_set<mixer*> seen;
	while (!pending.empty() && seen.size() < 100000) {
		mixer* m = pending.back();
		pending.pop_back();
		if (!m || !seen.insert(m).second) continue;
		if (is_target(m)) return true;
		pending.push_back(m->get_mixer());
		if (reverb3d* verb = m->get_reverb3d_sent_to()) pending.push_back(verb->get_mixer());
	}
	return false;
}
reverb3d* reverb3d::create(audio_node* reverb, mixer* destination, audio_engine* e) {
	if (!e) throw std::runtime_error("no audio engine available");
	if (destination && destination->get_engine() != e) throw std::runtime_error("the destination mixer belongs to another audio engine");
	if (destination && ma_node_get_input_bus_count(destination->get_ma_node()) == 0) throw std::runtime_error("the destination takes no input"); // A sound given as a mixer: the reverb would go nowhere, as reverb3d.mixer refuses it.
	if (destination) return new reverb3d_impl(e, reverb, destination);
	mixer *own = new_mixer(e);
	try {
		reverb3d *result = new reverb3d_impl(e, reverb, own);
		own->release(); // The reverb3d holds its own reference.
		return result;
	} catch (...) {
		own->release();
		throw;
	}
}

typedef struct {
	ma_node_base base;
	plugin_node* impl;
} ma_plugin_node;
static void ma_plugin_node_process_pcm_frames(ma_node* pNode, const float** ppFramesIn, ma_uint32* pFrameCountIn, float** ppFramesOut, ma_uint32* pFrameCountOut) {
	ma_plugin_node* n = (ma_plugin_node*)pNode;
	if (n->impl) n->impl->process(ppFramesIn, pFrameCountIn, ppFramesOut, pFrameCountOut);
}
class plugin_node_impl : public audio_node_impl, public virtual plugin_node {
	unique_ptr<ma_plugin_node> pn;
	audio_plugin_node_interface* impl;
	bool release_impl; // The plugin asked for release() (see NVGT_AUDIO_PLUGIN_NODE_RELEASE): an implementation built before it existed has no such function to call.
	std::atomic<int> script_type_id{0};
	ma_node_vtable vtable; // The user should be able to configure custom settings.
	public:
	plugin_node_impl(audio_plugin_node_interface* impl, unsigned char input_bus_count, unsigned char output_bus_count, unsigned int flags, audio_engine* engine) : pn(make_unique<ma_plugin_node>()), audio_node_impl(nullptr, engine), impl(impl), release_impl((flags & NVGT_AUDIO_PLUGIN_NODE_RELEASE) != 0) {
		vtable = { ma_plugin_node_process_pcm_frames, nullptr, input_bus_count, output_bus_count, flags & ~NVGT_AUDIO_PLUGIN_NODE_RELEASE };
		ma_node_config cfg = ma_node_config_init();
		// MiniAudio reads a channel count for each bus, as effect_node_impl gives it.
		vector<ma_uint32> channels_in(input_bus_count, get_engine()->get_channels()), channels_out(output_bus_count, get_engine()->get_channels());
		cfg.vtable          = &vtable;
		if (input_bus_count > 0) cfg.pInputChannels = &channels_in[0];
		if (output_bus_count > 0) cfg.pOutputChannels = &channels_out[0];
		if ((g_soundsystem_last_error = ma_node_init(ma_engine_get_node_graph(get_engine()->get_ma_engine()), &cfg, nullptr, (ma_node_base*)&*pn)) != MA_SUCCESS) throw std::runtime_error("failed to create plugin_node");
		node = (ma_node_base*)&*pn;
		pn->impl = this;
	}
	~plugin_node_impl() {
		{
			std::lock_guard<std::recursive_mutex> graph_lock(g_node_graph_mutex);
			if (pn) ma_node_uninit(&*pn, nullptr);
		}
		if (impl && release_impl) impl->release(); // Uninitialized, the node is read no more, so the plugin may free its implementation, which it otherwise had no way to know.
	}
	audio_plugin_node_interface* get_plugin_interface() const override { return impl; }
	int get_script_type_id() const override { return script_type_id; }
	void set_script_type_id(int type_id) override { script_type_id = type_id; }
	virtual void process(const float** frames_in, unsigned int* frame_count_in, float** frames_out, unsigned int* frame_count_out) override {
		if (impl) impl->process(impl, frames_in, frame_count_in, frames_out, frame_count_out);
	}
};
plugin_node* plugin_node::create(audio_plugin_node_interface* impl, unsigned char input_bus_count, unsigned char output_bus_count, unsigned int flags,audio_engine* engine) { return new plugin_node_impl(impl, input_bus_count, output_bus_count, flags, engine); }

static std::unordered_map<int, spatializer_component> g_audio_panners;
static std::unordered_map<int, spatializer_component> g_audio_attenuators;
static int g_next_panner_id = 0;
static int g_next_attenuator_id = 0;
static int g_default_3d_panner = -1;
static int g_default_3d_attenuator = -1;
std::recursive_mutex g_node_graph_mutex;
static std::unordered_set<audio_spatializer*> g_tracked_spatializers;
static std::mutex g_tracked_spatializers_mutex; // every mixer/sound constructs a spatializer on whatever script thread creates it, while sound_set_spatialization iterates the set from another

int register_audio_panner(spatializer_component_node_factory factory, bool default_enabled) {
	int id = g_next_panner_id++;
	g_audio_panners[id] = {factory, default_enabled};
	return id;
}

int register_audio_attenuator(spatializer_component_node_factory factory, bool default_enabled) {
	int id = g_next_attenuator_id++;
	g_audio_attenuators[id] = {factory, default_enabled};
	return id;
}

spatializer_component_node* create_audio_panner(int id, audio_spatializer* spatializer, audio_engine* engine) {
	auto it = g_audio_panners.find(id);
	if (it == g_audio_panners.end() || !it->second.enabled) return nullptr;
	return it->second.factory(spatializer, engine);
}

spatializer_component_node* create_audio_attenuator(int id, audio_spatializer* spatializer, audio_engine* engine) {
	auto it = g_audio_attenuators.find(id);
	if (it == g_audio_attenuators.end() || !it->second.enabled) return nullptr;
	return it->second.factory(spatializer, engine);
}

void set_audio_panner_enabled(int id, bool enabled) {
	auto it = g_audio_panners.find(id);
	if (it != g_audio_panners.end()) {
		bool was_enabled = it->second.enabled;
		it->second.enabled = enabled;
		if (was_enabled != enabled) {
			std::lock_guard<std::mutex> lock(g_tracked_spatializers_mutex);
			for (auto* spatializer : g_tracked_spatializers) {
				if (spatializer) spatializer->on_panner_enabled_changed(id, enabled);
			}
		}
	}
}

void set_audio_attenuator_enabled(int id, bool enabled) {
	auto it = g_audio_attenuators.find(id);
	if (it != g_audio_attenuators.end()) {
		bool was_enabled = it->second.enabled;
		it->second.enabled = enabled;
		if (was_enabled != enabled) {
			std::lock_guard<std::mutex> lock(g_tracked_spatializers_mutex);
			for (auto* spatializer : g_tracked_spatializers) {
				if (spatializer) spatializer->on_attenuator_enabled_changed(id, enabled);
			}
		}
	}
}

bool get_audio_panner_enabled(int id) {
	auto it = g_audio_panners.find(id);
	return it != g_audio_panners.end() && it->second.enabled;
}

bool get_audio_attenuator_enabled(int id) {
	auto it = g_audio_attenuators.find(id);
	return it != g_audio_attenuators.end() && it->second.enabled;
}

void sound_set_default_3d_panner(int panner_id) {
	g_default_3d_panner = panner_id;
}

int sound_get_default_3d_panner() {
	return g_default_3d_panner;
}

void sound_set_default_3d_attenuator(int attenuator_id) {
	g_default_3d_attenuator = attenuator_id;
}

int sound_get_default_3d_attenuator() {
	return g_default_3d_attenuator;
}

// Global  spatializer component registrations
int g_audio_basic_panner = g_default_3d_panner = register_audio_panner(basic_panner::create, true);
int g_audio_phonon_hrtf_panner = register_audio_panner(phonon_hrtf_panner::create, false);
int g_audio_basic_attenuator = g_default_3d_attenuator = register_audio_attenuator(basic_attenuator::create, true);
int g_audio_phonon_attenuator = register_audio_attenuator(phonon_attenuator::create, false);

bool sound_set_spatialization(int panner, int attenuator, bool disable_previous, bool set_default) {
	bool panner_success = false, attenuator_success = false;
	int prev_panner = g_default_3d_panner, prev_attenuator = g_default_3d_attenuator;
	auto panner_it = g_audio_panners.find(panner);
	if (panner_it != g_audio_panners.end()) {
		if (!panner_it->second.enabled) set_audio_panner_enabled(panner, true);
		if (set_default) sound_set_default_3d_panner(panner);
		panner_success = true;
		if (panner != prev_panner && disable_previous) set_audio_panner_enabled(prev_panner, false);
	}
	auto attenuator_it = g_audio_attenuators.find(attenuator);
	if (attenuator_it != g_audio_attenuators.end()) {
		if (!attenuator_it->second.enabled) set_audio_attenuator_enabled(attenuator, true);
		if (set_default) sound_set_default_3d_attenuator(attenuator);
		attenuator_success = true;
		if (attenuator != prev_attenuator && disable_previous) set_audio_attenuator_enabled(prev_attenuator, false);
	}
	return panner_success && attenuator_success;
}

class audio_spatializer_impl : public audio_node_chain_impl, public virtual audio_spatializer {
private:
	spatializer_component_node* panner;
	spatializer_component_node* attenuator;
	reverb3d* reverb;
	splitter_node* reverb_attachment;
	audio_spatializer_reverb3d_placement reverb_placement;
	mixer* attached_mixer;
	audio_spatialization_parameters spatialization_params; // Written by the audio thread, in process(), once made.
	// What the script set, copied into spatialization_params by process(): written there by the script too, a rolloff set while the audio thread wrote the parameters back, as the mixer filling them in does, was overwritten with the one before, for good.
	std::atomic<float> rolloff_set{1.0f}, directional_attenuation_factor_set{1.0f};
	bool parameters_valid;
	int preferred_panner_id, preferred_attenuator_id;
	int current_panner_id, current_attenuator_id;
	// The rewiring below runs under the chain lock, and what it lets go of is released only once the outermost rewiring ends, after that lock: letting go of a reverb3d can free its mixer and that mixer's spatializer, whose destructor takes g_tracked_spatializers_mutex, which a global panner change takes before a spatializer's chain lock.
	int rewire_depth = 0; // Under chain_mutex.
	std::vector<audio_node*> deferred_releases; // Under chain_mutex.
	struct rewire_scope {
		audio_spatializer_impl &spatializer;
		rewire_scope(audio_spatializer_impl &s) : spatializer(s) {
			spatializer.chain_mutex.lock();
			spatializer.rewire_depth++;
		}
		~rewire_scope() {
			std::vector<audio_node*> releasing;
			if (--spatializer.rewire_depth == 0) releasing.swap(spatializer.deferred_releases);
			spatializer.chain_mutex.unlock();
			for (audio_node *n : releasing) n->release();
		}
	};
	void release_later(audio_node *n) { deferred_releases.push_back(n); }
	void position_reverb() {
		rewire_scope scope(*this);
		if (!reverb_attachment) return;
		remove_node(reverb_attachment);
		switch (reverb_placement) {
			case prepan:
				add_node(reverb_attachment, nullptr, 0);
				break;
			case postpan:
				if (panner) add_node(reverb_attachment, panner, 0);
				else add_node(reverb_attachment, nullptr, 0);
				break;
			case postattenuate:
				if (attenuator) add_node(reverb_attachment, attenuator, 0);
				else if (panner) add_node(reverb_attachment, panner, 0);
				else add_node(reverb_attachment, nullptr, 0);
				break;
		}
	}
	// The reverb's send for the current parameters. Placed before the attenuator, which applies the cones and the gain range, it takes those too, as when MiniAudio's spatializer applied them ahead of the whole chain, so a sound turned away or silenced by max_gain sends none; after it, it has them from the attenuator, and with no attenuator there are none.
	float reverb_send_volume(reverb3d* verb) const {
		float volume = verb->get_volume_at(spatialization_params.listener_distance);
		if (attenuator && reverb_placement != postattenuate) volume *= clamp_volume(spatialization_params.cone_volume, spatialization_params.min_volume, spatialization_params.max_volume);
		return volume;
	}
	bool set_fallback_panner() {
		rewire_scope scope(*this);
		for (const auto& pair : g_audio_panners) {
			if (!pair.second.enabled) continue;
			spatializer_component_node* fallback_panner = create_audio_panner(pair.first, this, get_engine());
			if (!fallback_panner) continue;
			current_panner_id = pair.first;
			set_panner(fallback_panner);
			return true;
		}
		return false;
	}
	bool set_fallback_attenuator() {
		rewire_scope scope(*this);
		for (const auto& pair : g_audio_attenuators) {
			if (!pair.second.enabled) continue;
			spatializer_component_node* fallback_attenuator = create_audio_attenuator(pair.first, this, get_engine());
			if (!fallback_attenuator) continue;
			current_attenuator_id = pair.first;
			set_attenuator(fallback_attenuator);
			return true;
		}
		return false;
	}
public:
	audio_spatializer_impl(mixer* mixer, audio_engine* engine) : audio_node_chain_impl(nullptr, nullptr, engine), panner(nullptr), attenuator(nullptr), reverb(nullptr), reverb_attachment(nullptr), reverb_placement(postpan), attached_mixer(mixer), spatialization_params{}, parameters_valid(true), preferred_panner_id(-1), preferred_attenuator_id(-1), current_panner_id(-1), current_attenuator_id(-1) {
		if (!mixer) throw std::invalid_argument("mixer cannot be null");
		spatialization_params.rolloff = 1.0f;
		spatialization_params.directional_attenuation_factor = 1.0f;
		spatialization_params.cone_volume = 1.0f;
		{ std::lock_guard<std::mutex> lock(g_tracked_spatializers_mutex); g_tracked_spatializers.insert(this); }
	}
	~audio_spatializer_impl() {
		// Out of the set first: a global panner or attenuator change rewires every spatializer in it under that lock, so once this one is out, none is rewiring it as its node goes.
		{ std::lock_guard<std::mutex> lock(g_tracked_spatializers_mutex); g_tracked_spatializers.erase(this); }
		// A component the script kept goes on without this spatializer: off the graph first, which waits for the audio thread to stop processing it, then without its pointer back here, so it passes audio through if used again.
		for (spatializer_component_node *component : {panner, attenuator}) {
			if (!component) continue;
			component->detach_all_output_buses();
			component->forget_spatializer();
		}
		destroy_node();
		if (panner) panner->release();
		if (attenuator) attenuator->release();
		if (reverb_attachment) reverb_attachment->release();
		if (reverb) reverb->release();
	}
	void set_panner(spatializer_component_node* new_panner) override {
		rewire_scope scope(*this);
		if (panner) {
			remove_node(panner); // Which takes it off the graph and waits for the audio thread, so it can lose its pointer back here: a replaced component the script kept passes audio through.
			panner->forget_spatializer();
			release_later(panner);
		}
		panner = new_panner;
		if (panner) {
			if (reverb_attachment && reverb_placement == prepan) add_node(panner, reverb_attachment, 0);
			else add_node(panner, nullptr, 0);
		}
	}
	void set_attenuator(spatializer_component_node* new_attenuator) override {
		rewire_scope scope(*this);
		if (attenuator) {
			remove_node(attenuator);
			attenuator->forget_spatializer();
			release_later(attenuator);
		}
		attenuator = new_attenuator;
		if (attenuator) {
			if (panner && (!reverb_attachment || reverb_placement != postpan)) add_node(attenuator, panner, 0);
			else if (reverb_attachment && reverb_placement == postpan) add_node(attenuator, reverb_attachment, 0);
			else if (!panner && reverb_attachment && reverb_placement == prepan) add_node(attenuator, reverb_attachment, 0);
			else add_node(attenuator, nullptr, 0);
		}
	}
	void set_reverb3d(reverb3d* new_reverb, audio_spatializer_reverb3d_placement placement = postpan) override {
		if (new_reverb && new_reverb->get_engine() != get_engine()) { // Another engine's audio thread reads that reverb3d, which two threads can't read at once.
			g_soundsystem_last_error = MA_INVALID_ARGS;
			return;
		}
		// Not a reverb3d whose mixer is this one, or goes into it (see mixer_reaches()). Asked before this spatializer's chain lock is taken: mixer_reaches() takes other spatializers' chain locks, one at a time, so a thread holding this one while another, holding one of those, set a reverb3d sending back here deadlocked with it. The topology lock is held through the change.
		std::lock_guard<std::recursive_mutex> topology(g_audio_topology_mutex);
		mixer* owner = get_mixer();
		if (new_reverb && owner && new_reverb != get_reverb3d() && new_reverb->get_mixer() && mixer_reaches(new_reverb->get_mixer(), [owner](mixer* m) { return m == owner; })) {
			g_soundsystem_last_error = MA_INVALID_ARGS;
			return;
		}
		rewire_scope scope(*this);
		if (new_reverb == reverb) {
			if (reverb && placement != reverb_placement) { // Only moved: the same attachment goes to its new place in the chain.
				reverb_placement = placement;
				position_reverb();
			}
			return;
		}
		if (reverb) {
			release_later(reverb);
			reverb = nullptr;
			if (reverb_attachment) {
				remove_node(reverb_attachment);
				release_later(reverb_attachment);
				reverb_attachment = nullptr;
			}
		}
		if (new_reverb) {
			reverb_attachment = new_reverb->create_attachment();
			if (!reverb_attachment) return;
			reverb_placement = placement;
			if (attached_mixer && parameters_valid) reverb_attachment->set_output_bus_volume(1, reverb_send_volume(new_reverb));
			position_reverb();
			new_reverb->duplicate();
		}
		reverb = new_reverb;
	}
	spatializer_component_node* get_panner() const override {
		std::lock_guard<std::recursive_mutex> chain_lock(chain_mutex);
		return panner;
	}
	spatializer_component_node* get_attenuator() const override {
		std::lock_guard<std::recursive_mutex> chain_lock(chain_mutex);
		return attenuator;
	}
	reverb3d* get_reverb3d() const override {
		std::lock_guard<std::recursive_mutex> chain_lock(chain_mutex);
		return reverb;
	}
	splitter_node* get_reverb3d_attachment() const override {
		std::lock_guard<std::recursive_mutex> chain_lock(chain_mutex);
		return reverb_attachment;
	}
	audio_spatializer_reverb3d_placement get_reverb3d_placement() const override { return reverb_placement; }
	mixer* get_mixer() const override {
		std::lock_guard<std::recursive_mutex> chain_lock(chain_mutex);
		return attached_mixer;
	}
	// The update on the audio thread reads attached_mixer under the chain lock, which it only tries, so after this it reads no mixer, as for a spatializer the script kept past its mixer.
	void forget_mixer() override {
		rewire_scope scope(*this);
		attached_mixer = nullptr;
		parameters_valid = false;
	}
	void set_panner_by_id(int panner_id) override {
		rewire_scope scope(*this);
		preferred_panner_id = panner_id;
		spatializer_component_node* new_panner = create_audio_panner(panner_id, this, get_engine());
		if (new_panner) {
			current_panner_id = panner_id;
			set_panner(new_panner);
		} else if (!set_fallback_panner()) {
			current_panner_id = -1;
			set_panner(nullptr);
		}
	}
	void set_attenuator_by_id(int attenuator_id) override {
		rewire_scope scope(*this);
		preferred_attenuator_id = attenuator_id;
		spatializer_component_node* new_attenuator = create_audio_attenuator(attenuator_id, this, get_engine());
		if (new_attenuator) {
			current_attenuator_id = attenuator_id;
			set_attenuator(new_attenuator);
		} else if (!set_fallback_attenuator()) {
			current_attenuator_id = -1;
			set_attenuator(nullptr);
		}
	}
	int get_current_panner_id() const override { return current_panner_id; }
	int get_current_attenuator_id() const override { return current_attenuator_id; }
	int get_preferred_panner_id() const override { return preferred_panner_id; }
	int get_preferred_attenuator_id() const override { return preferred_attenuator_id; }
	void set_rolloff(float rolloff) override { if (!std::isnan(rolloff)) rolloff_set.store(clamp(rolloff, 0.0f, 100.0f)); } // clamp() passes NaN through, which made every sample NaN.
	float get_rolloff() const override { return rolloff_set.load(); }
	void set_directional_attenuation_factor(float factor) override { if (!std::isnan(factor)) directional_attenuation_factor_set.store(clamp(factor, 0.0f, 100.0f)); } // As set_rolloff().
	float get_directional_attenuation_factor() const override { return directional_attenuation_factor_set.load(); }
	bool get_parameters(audio_spatialization_parameters& params) override {
		if (!parameters_valid) return false;
		params = spatialization_params;
		return true;
	}
	void process(const float** frames_in, unsigned int* frame_count_in, float** frames_out, unsigned int* frame_count_out) override {
		// On the audio thread, which mustn't wait: while a script thread rewires this spatializer, freeing the reverb or its attachment read below, the parameters keep their last values for this block.
		std::unique_lock<std::recursive_mutex> chain_lock(chain_mutex, std::try_to_lock);
		if (!chain_lock.owns_lock()) return;
		if (attached_mixer && (panner || attenuator || reverb)) {
			parameters_valid = attached_mixer->get_spatialization_parameters(spatialization_params);
			spatialization_params.rolloff = rolloff_set.load(std::memory_order_relaxed);
			spatialization_params.directional_attenuation_factor = directional_attenuation_factor_set.load(std::memory_order_relaxed);
			if (parameters_valid && reverb) reverb_attachment->set_output_bus_volume(1, reverb_send_volume(reverb));
		} else parameters_valid = false;
	}
	void on_panner_enabled_changed(int panner_id, bool enabled) override {
		rewire_scope scope(*this);
		if (enabled) {
			// The preferred panner replaces a fallback; and one asked for while none was enabled takes this one, as set_fallback_panner() would have given it, rather than staying without one.
			if (preferred_panner_id == panner_id && preferred_panner_id != current_panner_id || current_panner_id == -1 && preferred_panner_id >= 0) {
				spatializer_component_node* new_panner = create_audio_panner(panner_id, this, get_engine());
				if (new_panner) {
					current_panner_id = panner_id;
					set_panner(new_panner);
				}
			}
		} else {
			if (current_panner_id == panner_id && !set_fallback_panner()) {
				current_panner_id = -1;
				set_panner(nullptr);
			}
		}
	}
	void on_attenuator_enabled_changed(int attenuator_id, bool enabled) override {
		rewire_scope scope(*this);
		if (enabled) {
			// As for panners.
			if (preferred_attenuator_id == attenuator_id && preferred_attenuator_id != current_attenuator_id || current_attenuator_id == -1 && preferred_attenuator_id >= 0) {
				spatializer_component_node* new_attenuator = create_audio_attenuator(attenuator_id, this, get_engine());
				if (new_attenuator) {
					current_attenuator_id = attenuator_id;
					set_attenuator(new_attenuator);
				}
			}
		} else {
			if (current_attenuator_id == attenuator_id && !set_fallback_attenuator()) {
				current_attenuator_id = -1;
				set_attenuator(nullptr);
			}
		}
	}
};
audio_spatializer* audio_spatializer::create(mixer* mixer, audio_engine* engine) { return new audio_spatializer_impl(mixer, engine); }

class spatializer_component_node_impl : public effect_node_impl, public virtual spatializer_component_node {
protected:
	audio_spatializer* spatializer;
public:
	spatializer_component_node_impl(audio_spatializer* spatializer, audio_engine* e, unsigned int input_channels = 0, unsigned int output_channels = 0, unsigned int input_bus_count = 1, unsigned int output_bus_count = 1, unsigned int flags = MA_NODE_FLAG_CONTINUOUS_PROCESSING) : effect_node_impl(e, input_channels, output_channels, input_bus_count, output_bus_count, flags), spatializer(spatializer) {
		if (!spatializer) throw std::invalid_argument("spatializer cannot be null");
	}
	audio_spatializer* get_spatializer() const override { return spatializer; }
	void forget_spatializer() override { spatializer = nullptr; }
};

class basic_panner_impl : public spatializer_component_node_impl, public virtual basic_panner {
	ma_panner panner;
public:
	// In and out at the engine's channel count, which the next node takes: MiniAudio's panner pans stereo and passes other channel counts through, where a fixed stereo output left the sound attached to nothing on any other engine.
	basic_panner_impl(audio_spatializer* spatializer, audio_engine* e) : spatializer_component_node_impl(spatializer, e, 0, 0) {
		ma_panner_config panner_config = ma_panner_config_init(ma_format_f32, get_engine()->get_channels());
		if (ma_panner_init(&panner_config, &panner) != MA_SUCCESS) throw std::runtime_error("Failed to initialize panner");
	}
	~basic_panner_impl() { destroy_node(); }
	void process(const float** frames_in, unsigned int* frame_count_in, float** frames_out, unsigned int* frame_count_out) override {
		ma_uint32 frameCount = *frame_count_out;
		if (!spatializer) goto fail;
		audio_spatialization_parameters params;
		if (!spatializer->get_parameters(params)) goto fail;
		ma_panner_set_pan(&panner, pan_db_to_linear(pan_amount((params.listener_direction_x * params.listener_distance) * params.directional_attenuation_factor * 1.75)));
		if (frameCount > *frame_count_in) frameCount = *frame_count_in;
		ma_panner_process_pcm_frames(&panner, frames_out[0], frames_in[0], frameCount);
		return;
		fail:
			ma_copy_pcm_frames(frames_out[0], frames_in[0], *frame_count_in, ma_format_f32, get_engine()->get_channels());
	}
};
spatializer_component_node* basic_panner::create(audio_spatializer* spatializer, audio_engine* engine) { return new basic_panner_impl(spatializer, engine); }

class phonon_hrtf_panner_impl : public spatializer_component_node_impl, public virtual phonon_hrtf_panner {
	IPLBinauralEffect iplEffect;
	IPLBinauralEffectParams iplEffectParams;
	IPLAudioBuffer inputBuffer;
	IPLAudioBuffer outputBuffer;
public:
	phonon_hrtf_panner_impl(audio_spatializer* spatializer, audio_engine* e) : spatializer_component_node_impl(spatializer, e, 0, 2), iplEffect(nullptr) {
		if (!phonon_init()) throw std::runtime_error("Steam Audio initialization failed");
		IPLBinauralEffectSettings effectSettings{};
		effectSettings.hrtf = g_phonon_hrtf;
		iplEffectParams = {};
		iplEffectParams.interpolation = IPL_HRTFINTERPOLATION_NEAREST;
		iplEffectParams.spatialBlend = 1.0;
		iplEffectParams.hrtf = g_phonon_hrtf;
		if (iplBinauralEffectCreate(g_phonon_context, &g_phonon_audio_settings, &effectSettings, &iplEffect) != IPL_STATUS_SUCCESS) throw std::runtime_error("Failed to create binaural effect");
		ma_uint32 channelsIn = e->get_channels();
		if (iplAudioBufferAllocate(g_phonon_context, channelsIn, g_phonon_audio_settings.frameSize, &inputBuffer) != IPL_STATUS_SUCCESS) {
			iplBinauralEffectRelease(&iplEffect);
			throw std::runtime_error("Failed to allocate input audio buffer");
		}
		if (iplAudioBufferAllocate(g_phonon_context, 2, g_phonon_audio_settings.frameSize, &outputBuffer) != IPL_STATUS_SUCCESS) {
			iplAudioBufferFree(g_phonon_context, &inputBuffer);
			iplBinauralEffectRelease(&iplEffect);
			throw std::runtime_error("Failed to allocate output audio buffer");
		}
	}
	~phonon_hrtf_panner_impl() {	
		destroy_node();
		if (iplEffect) iplBinauralEffectRelease(&iplEffect);
		iplAudioBufferFree(g_phonon_context, &inputBuffer);
		iplAudioBufferFree(g_phonon_context, &outputBuffer);
	}
	void process(const float** frames_in, unsigned int* frame_count_in, float** frames_out, unsigned int* frame_count_out) override {
		ma_uint32 totalFramesToProcess = *frame_count_out;
		ma_uint32 totalFramesProcessed = 0;
		float fully_spatialized_distance = 5; // Make this configurable once spatializer components have a property system.
		if (fully_spatialized_distance < 0.1) fully_spatialized_distance = 0.1;
		if (!spatializer || !iplEffect) goto fail;
		audio_spatialization_parameters params;
		if (!spatializer->get_parameters(params)) goto fail;
		iplEffectParams.direction.x = params.listener_direction_x * params.directional_attenuation_factor;
		iplEffectParams.direction.y = params.listener_direction_y * params.directional_attenuation_factor;
		iplEffectParams.direction.z = params.listener_direction_z * params.directional_attenuation_factor;
		iplEffectParams.spatialBlend = params.listener_distance * (params.directional_attenuation_factor / fully_spatialized_distance);
		// Steam Audio given a NaN made the engine's whole mix NaN, kept until the sound closed, or for good through a reverb after it: clamp() passed a NaN blend through, as a distance too great for a float times a factor of 0 makes, and positions near the float's limit gave a NaN distance and direction. A blend that isn't a number, or a direction that isn't finite, spatializes nothing.
		iplEffectParams.spatialBlend = iplEffectParams.spatialBlend > 1? 1 : iplEffectParams.spatialBlend > 0? iplEffectParams.spatialBlend : 0;
		if (!std::isfinite(iplEffectParams.direction.x) || !std::isfinite(iplEffectParams.direction.y) || !std::isfinite(iplEffectParams.direction.z)) {
			iplEffectParams.direction = {0, 0, -1};
			iplEffectParams.spatialBlend = 0;
		}
		while (totalFramesProcessed < totalFramesToProcess) {
			ma_uint32 framesToProcessThisIteration = totalFramesToProcess - totalFramesProcessed;
			if (framesToProcessThisIteration > (ma_uint32)g_phonon_audio_settings.frameSize) framesToProcessThisIteration = (ma_uint32)g_phonon_audio_settings.frameSize;
			inputBuffer.numSamples = framesToProcessThisIteration;
			outputBuffer.numSamples = framesToProcessThisIteration;
			iplAudioBufferDeinterleave(g_phonon_context, (float*)ma_offset_pcm_frames_const_ptr_f32(frames_in[0], totalFramesProcessed, inputBuffer.numChannels), &inputBuffer);
			iplBinauralEffectApply(iplEffect, &iplEffectParams, &inputBuffer, &outputBuffer);
			iplAudioBufferInterleave(g_phonon_context, &outputBuffer, ma_offset_pcm_frames_ptr_f32(frames_out[0], totalFramesProcessed, 2));
			totalFramesProcessed += framesToProcessThisIteration;
		}
		return;
		fail:
			ma_copy_pcm_frames(frames_out[0], frames_in[0], *frame_count_in, ma_format_f32, get_engine()->get_channels());
	}
};
// HRTF renders two ears, so an engine of another channel count, which couldn't take its output, gets none, and the spatializer falls back to another panner.
spatializer_component_node* phonon_hrtf_panner::create(audio_spatializer* spatializer, audio_engine* engine) {
	if (!engine || engine->get_channels() != 2) return nullptr;
	return new phonon_hrtf_panner_impl(spatializer, engine);
}

class basic_attenuator_impl : public spatializer_component_node_impl, public virtual basic_attenuator {
	// The volume applied, ramped to each new one over the frames MiniAudio's spatializer smooths its gain over, as MiniAudio did the cones' when it applied them, rather than stepping at each block. Not with ma_gainer, whose stereo path in MiniAudio 0.11.25 advances its ramp once every two frames while counting each, so a block covered half its ramp and the next began with a step. Only the audio thread uses these.
	ma_uint32 channels, ramp_frames, ramp_position = 0;
	float ramp_from = 0, ramp_to = 0;
	bool ramp_started = false;
	float ramped_volume() const { return ramp_position >= ramp_frames? ramp_to : ramp_from + (ramp_to - ramp_from) * ((float)ramp_position / ramp_frames); }
public:
	basic_attenuator_impl(audio_spatializer* spatializer, audio_engine* e) : spatializer_component_node_impl(spatializer, e), channels(e->get_channels()), ramp_frames(e->get_ma_engine()->gainSmoothTimeInFrames) {}
	~basic_attenuator_impl() {
		destroy_node();
	}
	void process(const float** frames_in, unsigned int* frame_count_in, float** frames_out, unsigned int* frame_count_out) override {
		float distance = 0, volume = 0;
		ma_uint32 frameCount = *frame_count_out;
		if (!spatializer) goto fail;
		audio_spatialization_parameters params;
		if (!spatializer->get_parameters(params)) goto fail;
		if (params.min_distance < 0) params.min_distance = 0; // As the Steam Audio attenuator takes it, the floor winning: a negative one was added to every distance, playing a sound at the listener as if that far away.
		distance = params.listener_distance - params.min_distance; // Within min_distance a sound is at full volume, as at min_distance itself, rather than attenuated by its whole distance.
		if (distance < 0) distance = 0;
		// A max_distance below min_distance counts as min_distance, the floor winning as for volumes: otherwise no distance was within the range, and a sound at the listener played nothing.
		volume = volume_with_cones(distance <= (params.max_distance > params.min_distance? params.max_distance - params.min_distance : 0)? ma_volume_db_to_linear(-distance * params.rolloff * 1.75) : 0, params);
		if (!ramp_started) { // The first volume at once, as for a sound starting.
			ramp_from = ramp_to = volume;
			ramp_position = ramp_frames;
			ramp_started = true;
		} else if (volume != ramp_to) {
			ramp_from = ramped_volume();
			ramp_to = volume;
			ramp_position = 0;
		}
		if (frameCount > *frame_count_in) frameCount = *frame_count_in;
		for (ma_uint32 frame = 0; frame < frameCount; frame++) {
			float gain = ramped_volume();
			if (ramp_position < ramp_frames) ramp_position++;
			for (ma_uint32 channel = 0; channel < channels; channel++) frames_out[0][frame * channels + channel] = frames_in[0][frame * channels + channel] * gain;
		}
		return;
		fail:
			ma_copy_pcm_frames(frames_out[0], frames_in[0], *frame_count_in, ma_format_f32, get_engine()->get_channels());
	}
};
spatializer_component_node* basic_attenuator::create(audio_spatializer* spatializer, audio_engine* engine) { return new basic_attenuator_impl(spatializer, engine); }

class phonon_attenuator_impl : public spatializer_component_node_impl, public virtual phonon_attenuator {
	IPLDirectEffect iplEffect;
	IPLDirectEffectParams iplEffectParams;
	IPLAudioBuffer inputBuffer;
	IPLAudioBuffer outputBuffer;
	IPLDistanceAttenuationModel distanceModel;
	IPLAirAbsorptionModel airAbsorptionModel;
public:
	phonon_attenuator_impl(audio_spatializer* spatializer, audio_engine* e) : spatializer_component_node_impl(spatializer, e), iplEffect(nullptr) {
		if (!phonon_init()) throw std::runtime_error("Steam Audio initialization failed");
		distanceModel = {};
		distanceModel.type = IPL_DISTANCEATTENUATIONTYPE_INVERSEDISTANCE;
		distanceModel.minDistance = 1.0f;
		airAbsorptionModel = {};
		airAbsorptionModel.type = IPL_AIRABSORPTIONTYPE_DEFAULT;
		IPLDirectEffectSettings effectSettings{};
		effectSettings.numChannels = e->get_channels();
		iplEffectParams = {};
		iplEffectParams.flags = static_cast<IPLDirectEffectFlags>(IPL_DIRECTEFFECTFLAGS_APPLYDISTANCEATTENUATION | IPL_DIRECTEFFECTFLAGS_APPLYAIRABSORPTION);
		iplEffectParams.directivity = 1.0f;
		if (iplDirectEffectCreate(g_phonon_context, &g_phonon_audio_settings, &effectSettings, &iplEffect) != IPL_STATUS_SUCCESS) throw std::runtime_error("Failed to create direct effect");
		ma_uint32 channelsIn = e->get_channels();
		if (iplAudioBufferAllocate(g_phonon_context, channelsIn, g_phonon_audio_settings.frameSize, &inputBuffer) != IPL_STATUS_SUCCESS) {
			iplDirectEffectRelease(&iplEffect);
			throw std::runtime_error("Failed to allocate input audio buffer");
		}
		if (iplAudioBufferAllocate(g_phonon_context, channelsIn, g_phonon_audio_settings.frameSize, &outputBuffer) != IPL_STATUS_SUCCESS) {
			iplAudioBufferFree(g_phonon_context, &inputBuffer);
			iplDirectEffectRelease(&iplEffect);
			throw std::runtime_error("Failed to allocate output audio buffer");
		}
	}
	~phonon_attenuator_impl() {
		destroy_node();
		if (iplEffect) iplDirectEffectRelease(&iplEffect);
		iplAudioBufferFree(g_phonon_context, &inputBuffer);
		iplAudioBufferFree(g_phonon_context, &outputBuffer);
	}
	void process(const float** frames_in, unsigned int* frame_count_in, float** frames_out, unsigned int* frame_count_out) override {
		IPLVector3 sourcePos, listenerPos;
		float distance; // How far past min_distance the sound is, scaled by the rolloff, for Steam Audio.
		ma_uint32 totalFramesToProcess = *frame_count_out;
		ma_uint32 totalFramesProcessed = 0;
		if (!spatializer || !iplEffect) goto fail;
		audio_spatialization_parameters params;
		if (!spatializer->get_parameters(params)) goto fail;
		// Attenuation starts at min_distance, as for the basic attenuator. Steam Audio's inverse distance model gives 1 / max(distance, minDistance), so a min_distance above 1 made a sound quieter, by 20 dB at the listener for 10, and changed nothing beyond it; the model's minimum is 1, the most the volume could be before.
		distanceModel.minDistance = 1;
		distanceModel.type = IPL_DISTANCEATTENUATIONTYPE_INVERSEDISTANCE;
		if (params.min_distance < 0) params.min_distance = 0; // As for the basic attenuator, for max_distance's cut-off too.
		params.rolloff *= 0.7; // Attenuators apply internal factors sometimes to try making it so that rolloff at a constant value will cause a similar volume reduction regardless of the attenuator in use.
		// The model and the air absorption depend only on the distance between the positions they are given, so the listener is put at the origin and the source that far along one axis. The parameters' positions couldn't be subtracted for it: a sound positioned relative to the listener has its position relative to the listener, and was attenuated by its distance from the listener's position in the world; listener_distance, which MiniAudio works out, is right either way.
		distance = (params.min_distance > 0? (params.listener_distance > params.min_distance? params.listener_distance - params.min_distance : 0) : params.listener_distance) * params.rolloff;
		if (std::isnan(distance)) distance = 0; // A rolloff of 0 at an infinite distance, which attenuates nothing.
		else if (std::isinf(distance)) distance = std::numeric_limits<float>::max(); // Positions too far apart for a float: as far as one goes.
		sourcePos = {distance, 0, 0};
		listenerPos = {0, 0, 0};
		iplEffectParams.distanceAttenuation = params.listener_distance <= (params.max_distance > params.min_distance? params.max_distance : params.min_distance)? volume_with_cones(iplDistanceAttenuationCalculate(g_phonon_context, sourcePos, listenerPos, &distanceModel), params) : volume_with_cones(0, params);
		iplAirAbsorptionCalculate(g_phonon_context, sourcePos, listenerPos, &airAbsorptionModel, iplEffectParams.airAbsorption);
		while (totalFramesProcessed < totalFramesToProcess) {
			ma_uint32 framesToProcessThisIteration = totalFramesToProcess - totalFramesProcessed;
			if (framesToProcessThisIteration > (ma_uint32)g_phonon_audio_settings.frameSize) framesToProcessThisIteration = (ma_uint32)g_phonon_audio_settings.frameSize;
			inputBuffer.numSamples = framesToProcessThisIteration;
			outputBuffer.numSamples = framesToProcessThisIteration;
			iplAudioBufferDeinterleave(g_phonon_context, (float*)ma_offset_pcm_frames_const_ptr_f32(frames_in[0], totalFramesProcessed, inputBuffer.numChannels), &inputBuffer);
			iplDirectEffectApply(iplEffect, &iplEffectParams, &inputBuffer, &outputBuffer);
			iplAudioBufferInterleave(g_phonon_context, &outputBuffer, ma_offset_pcm_frames_ptr_f32(frames_out[0], totalFramesProcessed, outputBuffer.numChannels));
			totalFramesProcessed += framesToProcessThisIteration;
		}
		return;
		fail:
			ma_copy_pcm_frames(frames_out[0], frames_in[0], *frame_count_in, ma_format_f32, get_engine()->get_channels());
	}
};
spatializer_component_node* phonon_attenuator::create(audio_spatializer* spatializer, audio_engine* engine) { return new phonon_attenuator_impl(spatializer, engine); }
