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
// Gains a node applies to its samples: finite, and no louder than max_volume_gain, as volumes are (see playable_volumes() in sound.cpp), and, as they are, not negative, which inverted the signal, unless negative means something, as a reverb's width swapping its channels. MA_INVALID_ARGS otherwise.
static bool playable_node_gains(std::initializer_list<double> gains, bool negative_too = false) {
	if (!finite_node_values(gains)) return false;
	for (double gain : gains) {
		if (std::fabs(gain) > max_volume_gain || gain < 0 && !negative_too) {
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
	if (order < 1) return node_value_in_range(false); // MiniAudio makes a filter of no sections then, which filters nothing.
	if (order > MA_MAX_FILTER_ORDER) return true; // MiniAudio refuses it itself.
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

// What rewiring lets go of on this thread, released once its outermost release_scope ends, after every lock taken within it: a reference let go of can be the last, as to a reverb3d's mixer, whose spatializer lets go of reverb3ds that take a reverb node's send lock, which a reverb3d's set_reverb() holds while it takes a chain's lock. Per thread rather than per chain, so that a chain rewired within another chain's rewiring, or under a send lock, releases only after those locks too.
static thread_local int t_release_depth = 0;
static thread_local std::vector<audio_node*> t_deferred_releases;
// Where a release is deferred to when the list can't grow, as on running out of memory: let go of at once instead, a reference released under the very locks the deferral keeps it from, as a reverb3d's destructor under a chain's lock taking a send lock another thread holds while it waits for that chain, deadlocked.
static constexpr int deferred_release_spares = 64;
static thread_local audio_node* t_deferred_spares[deferred_release_spares];
static thread_local int t_deferred_spare_count = 0;
struct release_scope {
	release_scope() { t_release_depth++; }
	~release_scope() {
		if (--t_release_depth > 0) return;
		std::vector<audio_node*> releasing;
		releasing.swap(t_deferred_releases);
		audio_node* spares[deferred_release_spares];
		int spare_count = t_deferred_spare_count;
		for (int i = 0; i < spare_count; i++) spares[i] = t_deferred_spares[i];
		t_deferred_spare_count = 0;
		for (audio_node* n : releasing) n->release(); // Any a release lets go of in turn go through scopes of their own.
		for (int i = 0; i < spare_count; i++) spares[i]->release();
	}
	release_scope(const release_scope&) = delete;
	release_scope& operator=(const release_scope&) = delete;
};
static void release_later(audio_node* n) {
	if (!n) return;
	if (t_release_depth > 0) {
		try {
			t_deferred_releases.push_back(n);
		} catch (...) { // Out of memory: deferred to a spare slot, never thrown out of a rewiring that already made its change; with none left, kept for good rather than released under the locks (see t_deferred_spares).
			if (t_deferred_spare_count < deferred_release_spares) t_deferred_spares[t_deferred_spare_count++] = n;
		}
		return;
	}
	n->release();
}
// A hold claimed (see claim_node_hold()), dropped again when the change it was claimed for doesn't go through, a throw included, as on running out of memory: left, the record outlived the node, which a later loop check stepped into once it was freed.
struct hold_claim {
	const audio_node* holder;
	const audio_node* held;
	bool kept = false;
	~hold_claim() { if (!kept) drop_node_hold(holder, held); }
};
// The holds of claim_node_hold(), a leaf lock: nothing else is taken under it.
static std::mutex g_node_holds_mutex;
static std::unordered_map<const audio_node*, std::vector<const audio_node*>> g_node_holds;
bool claim_node_hold(const audio_node* holder, const audio_node* held) {
	if (!holder || !held) return true;
	// Under the graph lock, as the graph's own loop check, which follows these holds too: holds and attachments are each checked and made one at a time, so two that close a loop between them can't both pass.
	std::lock_guard<std::recursive_mutex> graph_lock(g_node_graph_mutex);
	if (audio_node_impl::reaches_node(const_cast<audio_node*>(held), holder)) return false;
	std::lock_guard<std::mutex> lock(g_node_holds_mutex);
	g_node_holds[holder].push_back(held);
	return true;
}
std::unique_lock<std::mutex> node_holds_lock() { return std::unique_lock<std::mutex>(g_node_holds_mutex); }
void append_node_holds(const audio_node* n, std::vector<audio_node*>& out) {
	auto it = g_node_holds.find(n);
	if (it == g_node_holds.end()) return;
	for (const audio_node* held : it->second) out.push_back(const_cast<audio_node*>(held));
}
void record_node_hold(const audio_node* holder, const audio_node* held) {
	if (!holder || !held) return;
	std::lock_guard<std::mutex> lock(g_node_holds_mutex);
	g_node_holds[holder].push_back(held);
}
void drop_node_hold(const audio_node* holder, const audio_node* held) {
	if (!holder || !held) return;
	std::lock_guard<std::mutex> lock(g_node_holds_mutex);
	auto it = g_node_holds.find(holder);
	if (it == g_node_holds.end()) return;
	auto at = find(it->second.begin(), it->second.end(), held);
	if (at != it->second.end()) it->second.erase(at);
	if (it->second.empty()) g_node_holds.erase(it);
}
void drop_node_holds(const audio_node* holder) {
	std::lock_guard<std::mutex> lock(g_node_holds_mutex);
	g_node_holds.erase(holder);
}
// Who a node's output belongs to, under g_node_holds_mutex: the chain the node is in, which wires its output to the next node, the reverb3ds using it as their reverb, which send it on together (see reverb_free_for()), or what wires it itself, as a mixer its group's output and its chain's, and a reverb3d its own (see own_output()). A node one already rewires is refused to another with MA_ALREADY_IN_USE: a node in two chains, or in a chain and a reverb3d's reverb, had its single output fought over, each rewiring of one taking it from the other, so that a sound went silent for good or played where another was placed.
struct output_owner {
	const audio_node* chain = nullptr; // Null for a reverb.
	int reverb_uses = 0;
};
static std::unordered_map<const audio_node*, output_owner> g_output_owners;
static bool claim_output_for_chain(const audio_node* node, const audio_node* chain) {
	std::lock_guard<std::mutex> lock(g_node_holds_mutex);
	if (g_output_owners.count(node)) return false;
	g_output_owners[node].chain = chain;
	return true;
}
static void drop_output_for_chain(const audio_node* node, const audio_node* chain) {
	std::lock_guard<std::mutex> lock(g_node_holds_mutex);
	auto it = g_output_owners.find(node);
	if (it != g_output_owners.end() && it->second.chain == chain) g_output_owners.erase(it);
}
void own_output(const audio_node* node, const audio_node* owner) {
	if (!node) return;
	std::lock_guard<std::mutex> lock(g_node_holds_mutex);
	output_owner& entry = g_output_owners[node];
	entry.chain = owner;
	entry.reverb_uses = 0;
}
void disown_output(const audio_node* node, const audio_node* owner) {
	if (node) drop_output_for_chain(node, owner);
}
static bool claim_output_for_reverb(const audio_node* node) {
	std::lock_guard<std::mutex> lock(g_node_holds_mutex);
	auto it = g_output_owners.find(node);
	if (it != g_output_owners.end() && it->second.chain) return false;
	g_output_owners[node].reverb_uses++;
	return true;
}
static void drop_output_for_reverb(const audio_node* node) {
	std::lock_guard<std::mutex> lock(g_node_holds_mutex);
	auto it = g_output_owners.find(node);
	if (it == g_output_owners.end() || it->second.chain) return;
	if (--it->second.reverb_uses <= 0) g_output_owners.erase(it);
}
// Refuses with MA_ALREADY_IN_USE a node whose output a chain, reverb3ds or the node itself rewires (see g_output_owners), for what attaches that output once to its own input, a chain's source and a reverb3d attachment's dry input: taken, a sound or mixer skipped its effects, spatializer and parent, and the owner's next rewiring took the output back, leaving the taker without input for good. A chain that is no other's node is not refused, as attaching its output sets its endpoint, which it keeps.
static bool refuse_owned_output(const audio_node* node) {
	std::lock_guard<std::mutex> lock(g_node_holds_mutex);
	if (!g_output_owners.count(node)) return false;
	g_soundsystem_last_error = MA_ALREADY_IN_USE;
	return true;
}
// Drops a claim of a node's output unless the change it was made for goes through (see hold_claim).
struct output_claim {
	const audio_node* node;
	const audio_node* chain; // Null for a reverb's.
	bool kept = false;
	~output_claim() {
		if (kept || !node) return;
		if (chain) drop_output_for_chain(node, chain);
		else drop_output_for_reverb(node);
	}
};
class audio_node_chain_impl : public passthrough_node_impl, public virtual audio_node_chain {
	std::vector<audio_node*> nodes;
	std::vector<unsigned int> input_buses; // For each node, the input bus the node before it feeds, which every rewiring attaches to again.
	// Each node and the endpoint are claimed (see claim_node_hold()) before the chain calls into them and dropped only after its last call: a chain is never added to one it is already in at any depth, which the graph's loop check can't tell once a script detaches a node of the outer chain by hand, and which looped every rewiring of either chain through the other forever. A chain so takes a nested chain's lock under its own only while it holds it, which keeps every chain lock taken outer first.
	audio_node* endpoint;
	unsigned int endpoint_input_bus_index = 0; // The endpoint's input bus the chain feeds, which every rewiring attaches to again.
	// The input bus the node at index takes the chain on, index being nodes.size() for the endpoint.
	unsigned int bus_at(size_t index) const { return index < nodes.size()? input_buses[index] : endpoint_input_bus_index; }
protected:
	// Every change and read of the chain's nodes and endpoint takes this, as one script thread can change a sound's chain while another changes it too, such as a global panner change rewiring every spatializer. Recursive because the changes call one another; never taken on the audio thread, which only reads the MiniAudio graph.
	mutable std::recursive_mutex chain_mutex;
	// A chain's rewiring runs under its lock, and what it lets go of is released once the thread's outermost release_scope ends, after every lock it took (see release_scope).
	struct rewire_scope {
		audio_node_chain_impl &chain;
		release_scope releases; // Ends after the destructor's unlock.
		rewire_scope(audio_node_chain_impl &c) : chain(c) { chain.chain_mutex.lock(); }
		~rewire_scope() { chain.chain_mutex.unlock(); }
	};
	// Holds what a node's output goes into until the rewiring ends, as attaching or detaching that output lets go of it, which a node the script attached elsewhere by hand could hold the last reference to.
	void hold_destination(audio_node *n) {
		if (!n) return;
		if (n == static_cast<audio_node*>(this)) release_later(audio_node_impl::acquire_output_destination(0));
		else if (dynamic_cast<audio_node_chain_impl*>(n)) return; // A chain's output changes only through its own put_endpoint(), which holds what it lets go of until this thread's outermost release_scope ends; taking its lock here as well only added a nested chain lock.
		else if (auto impl = dynamic_cast<audio_node_impl*>(n)) release_later(impl->acquire_output_destination(0));
	}
public:
	audio_node_chain_impl(audio_node* source, audio_node* to, audio_engine* e) : passthrough_node_impl(e), endpoint(nullptr) {
		bool fed = source && !refuse_owned_output(source) && source->attach_output_bus(0, this, 0); // One refused leaves the chain unfed, as one whose attach fails.
		const ma_result unfed = g_soundsystem_last_error; // Why, when it is: the endpoint's attach that succeeds read as success after it.
		bool ended = true;
		// A throw attaching the endpoint, as on running out of memory, runs no destructor and frees this chain, which the source's attachment holds: taken off it first, and what the endpoint took let go of.
		try {
			if (to) ended = attach_output_bus(0, to, 0);
		} catch (...) {
			last_error_kept kept;
			if (fed) source->detach_output_bus(0);
			drop_node_holds(static_cast<audio_node*>(this));
			if (endpoint) endpoint->release();
			endpoint = nullptr;
			throw;
		}
		if (source && !fed && ended) g_soundsystem_last_error = unfed;
	}
	~audio_node_chain_impl() {
		drop_node_holds(static_cast<audio_node*>(this));
		for (audio_node* node : nodes) drop_output_for_chain(node, static_cast<audio_node*>(this));
		// We only release references, all attachments are kept in tact. Call clear(true) to detach all known nodes instead.
		for (audio_node* node: nodes) node->release();
		if (endpoint) endpoint->release();
	}
	// A chain has one output bus, 0, its endpoint: another is refused, with MiniAudio's errors for other nodes, rather than taken for it.
	bool attach_output_bus(unsigned int bus_index, audio_node* node, unsigned int input_bus_index) override {
		if (bus_index != 0) {
			g_soundsystem_last_error = MA_INVALID_OPERATION;
			return false;
		}
		if (!node) { // As every other node refuses it, rather than taken for set_endpoint(null), which detached the chain and gave true for a handle that happened to be null; set_endpoint(null) and detach_output_bus() detach it.
			g_soundsystem_last_error = MA_INVALID_ARGS;
			return false;
		}
		return put_endpoint(node, input_bus_index); // Whether it attached: one refused keeps the endpoint, which can be that same node.
	}
	bool detach_output_bus(unsigned int bus_index) override {
		if (bus_index != 0) {
			g_soundsystem_last_error = MA_INVALID_ARGS;
			return false;
		}
		set_endpoint(nullptr, 0);
		if (get_endpoint()) return false;
		return (g_soundsystem_last_error = MA_SUCCESS) == MA_SUCCESS; // Detached, or with nothing to detach, as a call that succeeded reads.
	}
	bool detach_all_output_buses() override { return detach_output_bus(0); }
	bool add_node(audio_node* node, audio_node* after, unsigned int input_bus_index) override {
		rewire_scope scope(*this);
		if (!node) return (g_soundsystem_last_error = MA_INVALID_ARGS) == MA_SUCCESS; // As every refusal here says why; these said nothing.
		if (node == static_cast<audio_node*>(this) || node == endpoint || index_of(node) != -1) { // The chain itself, its endpoint or a node already in it, which would loop the chain.
			g_soundsystem_last_error = MA_INVALID_ARGS;
			return false;
		}
		unsigned int new_idx = 0;
		if (after) {
			new_idx = index_of(after);
			if (new_idx == -1) return (g_soundsystem_last_error = MA_INVALID_ARGS) == MA_SUCCESS;
			else new_idx += 1; // Be sure to insert after this position rather than before.
		}
		audio_node* prev = new_idx? nodes[new_idx -1] : nullptr;
		audio_node* next = new_idx? (new_idx < nodes.size()? nodes[new_idx] : endpoint) : (!nodes.empty()? first() : endpoint);
		if (!claim_node_hold(static_cast<audio_node*>(this), node)) { // Checked and recorded together, before any call into the node, so that two threads nesting two chains into each other at once can't both pass.
			g_soundsystem_last_error = MA_INVALID_ARGS;
			return false;
		}
		hold_claim claim{static_cast<audio_node*>(this), node}; // Dropped unless the node goes in.
		if (!claim_output_for_chain(node, static_cast<audio_node*>(this))) { // Its output another chain or a reverb3d rewires (see g_output_owners).
			g_soundsystem_last_error = MA_ALREADY_IN_USE;
			return false;
		}
		output_claim owning{node, static_cast<audio_node*>(this)};
		// The node before is attached to the new one first, on the new node's input_bus_index, which a node that takes no input, as a sound or data source, refuses with nothing changed; the new node is then attached to the next one on the bus the next one was fed on, and when the new node can't feed it, as with another channel count, the node before goes back to it.
		unsigned int next_bus = bus_at(new_idx);
		// Room for the node first, so that recording it once wired can't throw, as on running out of memory, leaving it wired but not in the chain, or in nodes but not input_buses.
		nodes.reserve(nodes.size() + 1);
		input_buses.reserve(input_buses.size() + 1);
		hold_destination(prev? prev : this);
		if ((prev && !prev->attach_output_bus(0, node, input_bus_index)) || (!prev && !audio_node_impl::attach_output_bus(0, node, input_bus_index))) return false;
		hold_destination(node); // Once the node was taken, as its output is changed only from here on.
		bool fed = true;
		try {
			fed = !next || node->attach_output_bus(0, next, next_bus);
		} catch (...) { // As refused: the node before goes back to the next one.
			last_error_kept kept;
			if (prev) prev->attach_output_bus(0, next, next_bus);
			else audio_node_impl::attach_output_bus(0, next, next_bus);
			throw;
		}
		if (!fed) {
			ma_result error = g_soundsystem_last_error;
			if (prev) prev->attach_output_bus(0, next, next_bus);
			else audio_node_impl::attach_output_bus(0, next, next_bus);
			g_soundsystem_last_error = error;
			return false;
		}
		claim.kept = true;
		owning.kept = true;
		nodes.insert(nodes.begin() + new_idx, node);
		input_buses.insert(input_buses.begin() + new_idx, input_bus_index);
		node->duplicate();
		return true;
	}
	bool add_node_at(audio_node* node, int after, unsigned int input_bus_index) override {
		rewire_scope scope(*this);
		if (after < -1 || after >= int(nodes.size())) return (g_soundsystem_last_error = MA_INVALID_ARGS) == MA_SUCCESS;
		audio_node* insert_after = after > -1? nodes[after] : nullptr;
		return add_node(node, insert_after, input_bus_index);
	}
	// The removed nodes are let go of once the chain's lock is: the last reference to a node, such as a reverb3d's mixer, can take the send lock of the reverb node its sends go to, which a reverb3d's set_reverb() holds while it takes that node's chain lock, should the reverb node be this chain.
	bool remove_node(audio_node* node) override {
		rewire_scope scope(*this);
		audio_node* removed = nullptr;
		bool success = take_out(node, removed);
		release_later(removed);
		return success;
	}
	// Takes a node out of the chain under its lock, handing its reference back to let go of after (see remove_node()).
	bool take_out(audio_node* node, audio_node*& removed) {
		if (!node) return (g_soundsystem_last_error = MA_INVALID_ARGS) == MA_SUCCESS;
		auto it = find(nodes.begin(), nodes.end(), node);
		if (it == nodes.end()) return (g_soundsystem_last_error = MA_INVALID_ARGS) == MA_SUCCESS;
		audio_node* prev = (*it) != nodes.front()? *(it -1) : nullptr;
		audio_node* next = (*it) != nodes.back()? *(it + 1) : endpoint;
		size_t index = it - nodes.begin();
		unsigned int next_bus = bus_at(index + 1);
		hold_destination(prev? prev : this);
		hold_destination(node);
		if (prev && next && !prev->attach_output_bus(0, next, next_bus)) return false;
		else if (!prev && next && !audio_node_impl::attach_output_bus(0, next, next_bus)) return false;
		else if (!next) { // The last node of a chain without an endpoint: what fed it no longer leads anywhere, nor holds it.
			if (prev) prev->detach_output_bus(0);
			else audio_node_impl::detach_output_bus(0);
		}
		nodes.erase(it);
		input_buses.erase(input_buses.begin() + index);
		removed = node;
		bool detached = node->detach_output_bus(0);
		drop_node_hold(static_cast<audio_node*>(this), node); // After the last call into it (see nodes).
		drop_output_for_chain(node, static_cast<audio_node*>(this));
		return detached;
	}
	bool remove_node_at(unsigned int index) override {
		rewire_scope scope(*this);
		if (index >= nodes.size()) return (g_soundsystem_last_error = MA_INVALID_ARGS) == MA_SUCCESS;
		audio_node* removed = nullptr;
		bool success = take_out(nodes[index], removed);
		release_later(removed); // As remove_node().
		return success;
	}
	bool clear(bool detach_nodes) override {
		rewire_scope scope(*this);
		hold_destination(this);
		bool success = audio_node_impl::detach_output_bus(0);
		for (audio_node* node : nodes) {
			if (success && detach_nodes) {
				hold_destination(node);
				success = node->detach_output_bus(0);
			}
		}
		if (success && endpoint) success = audio_node_impl::attach_output_bus(0, endpoint, endpoint_input_bus_index);
		for (audio_node* node : nodes) {
			drop_node_hold(static_cast<audio_node*>(this), node);
			drop_output_for_chain(node, static_cast<audio_node*>(this));
			release_later(node); // As remove_node().
		}
		nodes.clear();
		input_buses.clear();
		return success;
	}
	// The chain holds a reference of its own to the endpoint. The attachment to it, whichever node it is from, holds another, but every insert, removal or clear rewires that attachment, which let go of the endpoint's only reference before the endpoint was attached to again, and a script can detach a node of the chain through the audio_node API.
	// Under the chain's lock only, which keeps the detach and attach together. The graph lock is taken by each of them, after the lock of any chain they go into, such as a spatializer at the end of this one: taking it here first, as before, was the opposite order to a global panner change, which locks a spatializer and then the graph, and the two deadlocked.
	// A new endpoint is attached in place of the old one, so an attach MiniAudio refuses, as to another channel count or a missing input bus, leaves the old one attached, as it leaves any other node's attachment: detaching the old one first left the chain, and any chain it is the last node of, leading nowhere.
	void set_endpoint(audio_node* node, unsigned int input_bus_index) override { put_endpoint(node, input_bus_index); }
	// set_endpoint(), telling whether it attached the node or detached the chain.
	bool put_endpoint(audio_node* node, unsigned int input_bus_index) {
		rewire_scope scope(*this);
		audio_node *old = endpoint;
		// Not the chain itself, one of its nodes, nor one that holds it at any depth, which loop it: the graph's check refuses them only while the chain's attachments are as it made them (see nodes).
		if (node && (index_of(node) != -1 || !claim_node_hold(static_cast<audio_node*>(this), node))) {
			g_soundsystem_last_error = MA_INVALID_ARGS;
			return false;
		}
		hold_claim claim{static_cast<audio_node*>(this), node}; // Dropped unless it becomes the endpoint.
		{
			hold_destination(!nodes.empty()? last() : this);
			if (node) {
				bool attached = !nodes.empty()? last()->attach_output_bus(0, node, input_bus_index) : audio_node_impl::attach_output_bus(0, node, input_bus_index);
				if (!attached) return false; // get_endpoint() tells the attach failed.
				claim.kept = true;
				endpoint = node;
				endpoint->duplicate();
				endpoint_input_bus_index = input_bus_index;
			} else if (old) {
				if (!nodes.empty()) last()->detach_output_bus(0);
				else audio_node_impl::detach_output_bus(0);
				endpoint = nullptr;
			}
		}
		drop_node_hold(static_cast<audio_node*>(this), old); // One record of it: the node attached again was claimed once more above.
		release_later(old); // After the chain's lock, as remove_node() lets go of a node, and after the reference just taken, as it can be the node just attached again.
		return true;
	}
	audio_node* get_endpoint() const override {
		std::lock_guard<std::recursive_mutex> chain_lock(chain_mutex);
		return endpoint;
	}
	// The endpoint, with a reference the caller lets go of, or null.
	audio_node* acquire_endpoint() const {
		std::lock_guard<std::recursive_mutex> chain_lock(chain_mutex);
		if (endpoint) endpoint->duplicate();
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
	if (iplContextCreate(&phonon_context_settings, &g_phonon_context) != IPL_STATUS_SUCCESS) return (g_soundsystem_last_error = MA_ERROR) == MA_SUCCESS; // Which said nothing, as the HRTF's failure below didn't.
	IPLHRTFSettings phonon_hrtf_settings{};
	phonon_hrtf_settings.type = IPL_HRTFTYPE_DEFAULT;
	phonon_hrtf_settings.volume = 1.0;
	if (iplHRTFCreate(g_phonon_context, &g_phonon_audio_settings, &phonon_hrtf_settings, &g_phonon_hrtf) != IPL_STATUS_SUCCESS) {
		iplContextRelease(&g_phonon_context);
		g_phonon_context = nullptr;
		return (g_soundsystem_last_error = MA_FORMAT_NOT_SUPPORTED) == MA_SUCCESS; // Its HRTF works at some rates only, as 44100 and 48000 Hz, and not at others, as 16000 or 96000: the default engine's is then one it can't take.
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
		g_soundsystem_last_error = MA_SUCCESS; // As the true path reads through sound_set_spatialization().
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
			if (!e) throw_refusal(MA_INVALID_ARGS, "no engine provided");
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
		if (channels < 1 || channels > MA_MAX_CHANNELS) { // A node's channel count is kept in 8 bits.
			g_soundsystem_last_error = MA_INVALID_ARGS;
			throw std::runtime_error("invalid channel count");
		}
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

// MiniAudio's first-order high-pass section has its pole on the wrong side, so that it passes DC: an odd order took 2 dB rather than 20 off 100 Hz at a 1 kHz cutoff, order 3 18 dB too little, and dipped in its pass band. Its section is left passing everything, and a Butterworth one, from the bilinear transform as the rest are, runs after the others.
struct held_hpf_node {
	ma_hpf_node hpf; // First, as MiniAudio takes this for one.
	std::atomic<float> gain{1}, pole{0};
	std::vector<float> last_in, last_out; // A frame each.
};
static void held_hpf_process(ma_node* node, const float** frames_in, ma_uint32* frame_count_in, float** frames_out, ma_uint32* frame_count_out) {
	held_hpf_node* held = (held_hpf_node*)node;
	if (held->hpf.hpf.hpf1Count) held->hpf.hpf.pHPF1[0].a.f32 = 1; // Here too, as a retune on the script's thread writes MiniAudio's value before putting this back.
	ma_hpf_process_pcm_frames(&held->hpf.hpf, frames_out[0], frames_in[0], *frame_count_out);
	if (!held->hpf.hpf.hpf1Count) return;
	const float gain = held->gain.load(std::memory_order_relaxed), pole = held->pole.load(std::memory_order_relaxed);
	const ma_uint32 channels = held->hpf.hpf.channels;
	float* sample = frames_out[0];
	for (ma_uint32 frame = 0; frame < *frame_count_out; frame++) {
		for (ma_uint32 channel = 0; channel < channels; channel++, sample++) {
			const float in = *sample;
			*sample = gain * (in - held->last_in[channel]) + pole * held->last_out[channel];
			held->last_in[channel] = in;
			held->last_out[channel] = *sample;
		}
	}
}
class high_pass_filter_node_impl : public audio_node_impl, public virtual high_pass_filter_node {
	unique_ptr<held_hpf_node> fn;
	ma_hpf_node_config cfg;
	// Once MiniAudio set the filter up, its first-order section passing everything (see held_hpf_node).
	void tune_first_order() {
		if (fn->hpf.hpf.hpf1Count) fn->hpf.hpf.pHPF1[0].a.f32 = 1;
		const double tangent = std::tan(3.14159265358979323846 * cfg.hpf.cutoffFrequency / cfg.hpf.sampleRate);
		fn->pole.store((float)((1 - tangent) / (1 + tangent)), std::memory_order_relaxed);
		fn->gain.store((float)(1 / (1 + tangent)), std::memory_order_relaxed);
	}
	public:
	high_pass_filter_node_impl(double cutoff_frequency, int order, audio_engine* e) : fn(make_unique<held_hpf_node>()), audio_node_impl(nullptr, e) {
		if (!finite_node_values({cutoff_frequency}) || !(cutoff_frequency = usable_frequency(cutoff_frequency, get_engine()->get_sample_rate(), [&](double f) { return sections_in_range(pass_filter::high, f, order, get_engine()->get_sample_rate()); }))) throw std::invalid_argument("filter setting out of range");
		cfg = ma_hpf_node_config_init(get_engine()->get_channels(), get_engine()->get_sample_rate(), cutoff_frequency, order);
		fn->last_in.assign(cfg.hpf.channels, 0);
		fn->last_out.assign(cfg.hpf.channels, 0);
		if ((g_soundsystem_last_error = ma_hpf_node_init(ma_engine_get_node_graph(get_engine()->get_ma_engine()), &cfg, nullptr, &fn->hpf)) != MA_SUCCESS) throw std::runtime_error("ma_high_pass_filter_node was not initialized");
		static ma_node_vtable held_vtable = *((ma_node_base*)&fn->hpf)->vtable;
		held_vtable.onProcess = held_hpf_process;
		((ma_node_base*)&fn->hpf)->vtable = &held_vtable;
		tune_first_order();
		node = (ma_node_base*)&fn->hpf;
	}
	~high_pass_filter_node_impl() {
		if (fn) {
			std::lock_guard<std::recursive_mutex> graph_lock(g_node_graph_mutex); // Uninitializing detaches it from the nodes it is attached to, the same lists other threads attach to and detach from under this lock.
			ma_hpf_node_uninit(&fn->hpf, nullptr);
		}
	}
	void set_cutoff_frequency(double freq) override {
		if (!finite_node_values({freq})) return;
		if (!(freq = usable_frequency(freq, cfg.hpf.sampleRate, [&](double f) { return sections_in_range(pass_filter::high, f, cfg.hpf.order, cfg.hpf.sampleRate); }))) return;
		auto previous = cfg.hpf.cutoffFrequency;
		cfg.hpf.cutoffFrequency = freq;
		if ((g_soundsystem_last_error = ma_hpf_node_reinit(&cfg.hpf, &fn->hpf)) != MA_SUCCESS) cfg.hpf.cutoffFrequency = previous;
		tune_first_order();
	}
	double get_cutoff_frequency() const override { return cfg.hpf.cutoffFrequency; }
	void set_order(unsigned int order) override {
		auto previous = cfg.hpf.order;
		cfg.hpf.order = order;
		if ((g_soundsystem_last_error = ma_hpf_node_reinit(&cfg.hpf, &fn->hpf)) != MA_SUCCESS) cfg.hpf.order = previous;
		tune_first_order();
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
		if (delay_in_frames == 0 || uint64_t(delay_in_frames) * get_engine()->get_channels() * sizeof(float) > UINT32_MAX) {
			g_soundsystem_last_error = MA_INVALID_ARGS; // As the filters' constructors say it.
			throw std::invalid_argument("delay out of range");
		}
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
	void set_wet(float wet) override { if (playable_node_gains({wet})) ma_delay_node_set_wet(&*dn, wet); }
	float get_wet() const override { return ma_delay_node_get_wet(&*dn); }
	void set_dry(float dry) override { if (playable_node_gains({dry})) ma_delay_node_set_dry(&*dn, dry); }
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
		if (cfg.channels < 1 || cfg.channels > 2 || cfg.sampleRate < 22050 || cfg.sampleRate > 44100 * verblib_max_sample_rate_multiplier) { // What verblib reverbs, which failed with nothing said of why.
			g_soundsystem_last_error = MA_FORMAT_NOT_SUPPORTED;
			throw std::runtime_error("a freeverb works on engines of 1 or 2 channels at 22050 to 396900 Hz");
		}
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
	float get_room_size() const override { return rn? clamped_unit(verblib_get_room_size(&rn->reverb)) : -1; } // verblib's scale can read just past 1.
	void set_damping(float damping) override { if (rn && finite_node_values({damping})) verblib_set_damping(&rn->reverb, clamped_unit(damping)); }
	float get_damping() const override { return rn? verblib_get_damping(&rn->reverb) : -1; }
	// The gain the wet level and width make together as verblib multiplies them, which each alone kept to the limit passed by far.
	static bool wet_gain_fits(float wet, float width) {
		if (std::fabs((double)wet * verblib_scalewet * (std::fabs((double)width) + 1) / 2) <= max_volume_gain) return true;
		g_soundsystem_last_error = MA_INVALID_ARGS;
		return false;
	}
	void set_width(float width) override { if (rn && playable_node_gains({width}, true) && wet_gain_fits(verblib_get_wet(&rn->reverb), width)) verblib_set_width(&rn->reverb, width); } // Each a gain on the samples, as the wet and dry levels are.
	float get_width() const override { return rn? verblib_get_width(&rn->reverb) : -1; }
	void set_wet(float wet) override { if (rn && playable_node_gains({wet}) && wet_gain_fits(wet, verblib_get_width(&rn->reverb))) verblib_set_wet(&rn->reverb, wet); }
	float get_wet() const override { return rn? verblib_get_wet(&rn->reverb) : -1; }
	void set_dry(float dry) override { if (rn && playable_node_gains({(double)dry * verblib_scaledry})) verblib_set_dry(&rn->reverb, dry); }
	float get_dry() const override { return rn? verblib_get_dry(&rn->reverb) : -1; }
	void set_input_width(float width) override { if (rn && playable_node_gains({width}, true)) verblib_set_input_width(&rn->reverb, width < 0? 0 : width); } // 0 for a negative one, which verblib takes as 0 while it read back as set.
	float get_input_width() const override { return rn? verblib_get_input_width(&rn->reverb) : -1; }
	void set_frozen(bool frozen) override { if (rn) verblib_set_mode(&rn->reverb, frozen? 1 : 0); }
	bool get_frozen() const override { return rn? verblib_get_mode(&rn->reverb) >= 0.5 : false; }
};
freeverb_node* freeverb_node::create(audio_engine* e) { return new freeverb_node_impl(e); }

// How many reverb3ds use each reverb node, and the lock under which one that isn't a mixer is sent on and taken off: a node shared by several is taken from its destination only once the last of them lets go of it, as one replacing its reverb cut the others' off before. g_reverb_users_mutex is a leaf, nothing taken inside it. A node's send lock is taken on its own or under the topology lock, and only what sending or detaching that node takes, as a chain's lock and the graph lock, is taken inside it, nothing being let go of there: a chain lets go of its nodes under its own lock, which can destroy a reverb3d and take these locks.
struct reverb_use {
	int users = 0;
	std::shared_ptr<std::recursive_mutex> send = std::make_shared<std::recursive_mutex>();
};
static std::mutex g_reverb_users_mutex;
static std::unordered_map<audio_node*, reverb_use> g_reverb_users;
// A reverb3d counts itself among a node's users, before it sends the node on, under the lock returned for one that isn't a mixer.
static std::shared_ptr<std::recursive_mutex> reverb_used(audio_node* verb) {
	std::lock_guard<std::mutex> lock(g_reverb_users_mutex);
	reverb_use& use = g_reverb_users[verb];
	use.users++;
	return use.send;
}
// Takes back a count reverb_used() made for a reverb3d that then couldn't send the node on, which left the node where it went: unlike reverb_let_go(), nothing is taken off. Its entry stays, read as unused at 0.
static void reverb_uncount(audio_node* verb) {
	std::lock_guard<std::mutex> lock(g_reverb_users_mutex);
	auto it = g_reverb_users.find(verb);
	if (it != g_reverb_users.end() && it->second.users > 0) it->second.users--;
}
// Makes a node's users entry ahead of counting a reverb3d into it, so that the count, made once the reverb3d has changed over to the node, can't throw, as on running out of memory, leaving it a reverb it never counted, whose let-go later took another user's count to 0. An entry left without users reads as none.
static bool reverb_entry_made(audio_node* verb) {
	std::lock_guard<std::mutex> lock(g_reverb_users_mutex);
	return g_reverb_users.try_emplace(verb).second;
}
// Forgets an entry a refused reverb3d left without users, which was kept for good, unless something still holds its send lock, as another reverb3d's let-go in progress does.
static void reverb_entry_forget(audio_node* verb) {
	std::lock_guard<std::mutex> lock(g_reverb_users_mutex);
	auto it = g_reverb_users.find(verb);
	if (it != g_reverb_users.end() && it->second.users == 0 && it->second.send.use_count() == 1) g_reverb_users.erase(it);
}
// What a reverb node that isn't a mixer goes into now, with a reference the caller lets go of after the node's send lock: sending the node elsewhere or detaching it lets go of the one it held, whose destructor, as a mixer's letting go of a reverb3d of its own, takes the reverb locks.
static audio_node* reverb_destination(audio_node* verb) {
	if (auto chain = dynamic_cast<audio_node_chain_impl*>(verb)) return chain->acquire_endpoint();
	if (auto impl = dynamic_cast<audio_node_impl*>(verb)) return impl->acquire_output_destination(0);
	return nullptr;
}
// How many reverb3ds use a node as their reverb.
static int reverb_users_of(audio_node* verb) {
	std::lock_guard<std::mutex> lock(g_reverb_users_mutex);
	auto it = g_reverb_users.find(verb);
	return it == g_reverb_users.end()? 0 : it->second.users;
}
// Where a reverb node goes now: the mixer a mixer goes into or the engine's endpoint, or what a node is attached to. For comparing only: no reference is kept.
static audio_node* reverb_goes_into(audio_node* verb) {
	if (mixer* m = dynamic_cast<mixer*>(verb)) {
		mixer* parent = m->get_mixer();
		return parent? static_cast<audio_node*>(parent) : m->get_engine()->get_endpoint();
	}
	audio_node* into = reverb_destination(verb);
	if (into) into->release();
	return into;
}
// A node has one output: one other reverb3ds use goes into their destination, which a reverb3d sending it elsewhere took from them, their mixers reading none of it, nor getting it back once that reverb3d went. Whether a reverb3d going into target, counted own_uses times among the node's users, can send verb there.
static bool reverb_free_for(audio_node* verb, audio_node* target, int own_uses) {
	return reverb_users_of(verb) <= own_uses || reverb_goes_into(verb) == target;
}
// A reverb3d lets go of its reverb. The last of them takes a node that isn't a mixer off its destination under the node's send lock, the count's entry kept until then, so that a reverb3d taking the node up meanwhile counts itself into that entry and sends under the same lock, after, rather than being cut off. A let-go finding the entry gone or made anew has nothing to take off: the one before took the node off, or a new user sends it now. A mixer keeps its parent, as a mixer of the script's.
static void reverb_let_go(audio_node* verb) {
	release_scope releases; // What a chain taken off its destination lets go of, after the send lock.
	std::shared_ptr<std::recursive_mutex> send;
	{
		std::lock_guard<std::mutex> lock(g_reverb_users_mutex);
		auto it = g_reverb_users.find(verb);
		if (it == g_reverb_users.end() || --it->second.users > 0) return;
		if (dynamic_cast<mixer*>(verb)) {
			g_reverb_users.erase(it);
			return;
		}
		send = it->second.send;
	}
	struct holding { audio_node* node = nullptr; ~holding() { if (node) node->release(); } } destination; // Let go of after the send lock, and should taking the node off throw, as on running out of memory, too: kept, a mixer a reverb3d made stayed alive and mixed for good.
	{
		std::lock_guard<std::recursive_mutex> send_lock(*send);
		auto unused = [&]() {
			auto it = g_reverb_users.find(verb);
			return it != g_reverb_users.end() && it->second.users == 0 && it->second.send == send? it : g_reverb_users.end();
		};
		bool take_off;
		{
			std::lock_guard<std::mutex> lock(g_reverb_users_mutex);
			take_off = unused() != g_reverb_users.end();
		}
		if (take_off) {
			destination.node = reverb_destination(verb);
			verb->detach_output_bus(0);
			std::lock_guard<std::mutex> lock(g_reverb_users_mutex);
			auto it = unused();
			if (it != g_reverb_users.end()) g_reverb_users.erase(it);
		}
	}
}
class reverb3d_impl : public passthrough_node_impl, public virtual reverb3d {
	audio_node* reverb;
	mixer* output_mixer;
	float min_volume, max_volume, max_volume_distance, max_audible_distance, volume_curve;
public:
	reverb3d_impl(audio_engine* e, audio_node* verb, mixer* destination) : passthrough_node_impl(e), output_mixer(destination), reverb(nullptr), min_volume(-7), max_volume(-5), max_volume_distance(7), max_audible_distance(60), volume_curve(0.4) {
		if (output_mixer) output_mixer->duplicate(); // reverb owns its own reference to output_mixer via attach_output_bus below; this is reverb3d_impl's separate reference for get_mixer().
		bool counted = false;
		try {
			own_output(static_cast<audio_node*>(this), static_cast<audio_node*>(this)); // Its output goes into its reverb, which no chain or other reverb3d may take: taken, the sends skipped the reverb, and once let go of went nowhere for good.
			record_node_hold(static_cast<audio_node*>(this), output_mixer); // Nothing holds a reverb3d being made.
			if (verb) wire_reverb(verb, counted);
		} catch (...) { // As on running out of memory. The destructor doesn't run, so what it lets go of is let go of here: a hold left behind was taken by a node made later at the same address for its own, and the mixer a reverb3d made for itself, attached to the engine, and the reverb, counted among its users for good, stayed alive.
			last_error_kept kept;
			drop_node_holds(static_cast<audio_node*>(this));
			disown_output(static_cast<audio_node*>(this), static_cast<audio_node*>(this));
			if (counted) reverb_let_go(reverb);
			if (reverb) {
				drop_output_for_reverb(reverb);
				reverb->release();
			}
			if (output_mixer) output_mixer->release();
			throw;
		}
	}
	// Attaches this node to the reverb and the reverb to the destination, keeping the reverb only when it took this node's output, as for one of another channel count it wouldn't. The reverb3d holds a reference of its own to the reverb, as a script can detach this node, which is an audio_node, from it.
	// counted tells, should it throw, whether it counted itself among the reverb's users.
	void wire_reverb(audio_node* verb, bool& counted) {
		reverb = nullptr;
		const bool verb_mixer = dynamic_cast<mixer*>(verb) != nullptr; // Sent on through its set_mixer(), which its own output stays with: not claimed.
		if (!verb_mixer && !claim_output_for_reverb(verb)) throw_refusal(MA_ALREADY_IN_USE, "the reverb's output belongs to a chain or another node"); // Whose output a chain or the node itself rewires (see g_output_owners).
		output_claim owning{verb_mixer? nullptr : verb, nullptr};
		if (!attach_output_bus(0, verb, 0)) return;
		reverb = verb;
		reverb->duplicate();
		owning.kept = true; // Dropped by the destructor, or the constructor's catch, from here.
		record_node_hold(static_cast<audio_node*>(this), reverb);
		std::shared_ptr<std::recursive_mutex> send = reverb_used(reverb);
		counted = true;
		// Refused when it can't be sent on, as reverb3d.reverb refuses it: made, the sends went wherever the node already went, with an error left behind the reverb3d made.
		if (!(verb_mixer? send_onward(reverb, output_mixer) : send_counted(reverb, send))) {
			const ma_result error = g_soundsystem_last_error;
			send.reset();
			reverb_uncount(reverb);
			reverb_entry_forget(reverb);
			counted = false;
			throw_refusal(error != MA_SUCCESS? error : MA_INVALID_OPERATION, "the reverb can't be sent on to the destination");
		}
	}
	// Sends a reverb that isn't a mixer, counted, on under its send lock (see reverb_let_go()), letting go of what it went into before after that lock (see reverb_destination()).
	// Whether it was sent on: one that wasn't, as the engine's endpoint or a node whose attach there would loop, stays where it went.
	bool send_counted(audio_node* verb, const std::shared_ptr<std::recursive_mutex>& send) {
		release_scope releases; // What a chain sent on lets go of, after the send lock.
		struct holding { audio_node* node = nullptr; ~holding() { if (node) node->release(); } } previous; // Let go of after the send lock, and should sending the reverb on throw, as on running out of memory, too: what the reverb went into, as a mixer a reverb3d made, stayed alive for good.
		bool sent;
		{
			std::lock_guard<std::recursive_mutex> send_lock(*send);
			previous.node = reverb_destination(verb);
			sent = send_onward(verb, output_mixer);
		}
		return sent;
	}
	// The reverb into the destination, the engine's output without one. A mixer given as the reverb goes there as a mixer, through its chain, effects and spatializer, and with the link a parent the loop check follows, rather than having its group's output taken from its chain, which skipped them and, once the reverb was replaced, left the mixer silent for good.
	bool send_onward(audio_node* verb, mixer* destination) {
		if (mixer* mix = dynamic_cast<mixer*>(verb)) return mix->set_mixer(destination);
		return verb->attach_output_bus(0, destination? static_cast<audio_node*>(destination) : get_engine()->get_endpoint(), 0);
	}
	~reverb3d_impl() {
		last_error_kept kept;
		drop_node_holds(static_cast<audio_node*>(this));
		if (reverb) {
			try {
				reverb_let_go(reverb); // A node the script keeps no longer goes on into the destination, which kept a reverb3d's own mixer alive and processed with it.
			} catch (...) {} // Out of memory taking it off: left where it goes rather than ending the program from a destructor.
			drop_output_for_reverb(reverb);
			reverb->release();
		}
		disown_output(static_cast<audio_node*>(this), static_cast<audio_node*>(this));
		if (output_mixer) output_mixer->release();
	}
	void set_reverb(audio_node* verb) override {
		if (verb == reverb) return;
		if (verb && verb->get_engine() != get_engine()) { // As for its mixer: another engine's audio thread reads that node.
			g_soundsystem_last_error = MA_INVALID_ARGS;
			return;
		}
		if (verb && !reverb_fits(verb, output_mixer? static_cast<audio_node*>(output_mixer) : get_engine()->get_endpoint(), ma_node_get_output_channels(get_ma_node(), 0))) { // Refused, the old reverb kept, rather than kept going nowhere.
			g_soundsystem_last_error = MA_INVALID_OPERATION;
			return;
		}
		std::lock_guard<std::recursive_mutex> topology(g_audio_topology_mutex);
		if (verb && !reverb_free_for(verb, output_mixer? static_cast<audio_node*>(output_mixer) : get_engine()->get_endpoint(), 0)) { // Used by other reverb3ds going elsewhere (see reverb_free_for()).
			g_soundsystem_last_error = MA_INVALID_OPERATION;
			return;
		}
		mixer* verb_mixer = verb? dynamic_cast<mixer*>(verb) : nullptr;
		// Not a mixer that sends to this reverb3d, or goes into one that does (see mixer_reaches()): this feeds the mixer, which would feed it back.
		if (verb_mixer && mixer_reaches(verb_mixer, [this](mixer* m) { return m->get_reverb3d_sent_to() == static_cast<reverb3d*>(this); })) {
			g_soundsystem_last_error = MA_INVALID_ARGS;
			return;
		}
		// Nor a node that holds this reverb3d at any depth, as a chain it is in, whose loop the graph refuses only while the chain's attachments are as it made them (see claim_node_hold()).
		if (!claim_node_hold(static_cast<audio_node*>(this), verb)) {
			g_soundsystem_last_error = MA_INVALID_ARGS;
			return;
		}
		hold_claim claim{static_cast<audio_node*>(this), verb}; // Dropped unless it becomes the reverb.
		if (verb && !verb_mixer && !claim_output_for_reverb(verb)) { // A node whose output a chain or the node itself rewires (see g_output_owners); a mixer is sent on through its set_mixer(), its own output staying with it.
			g_soundsystem_last_error = MA_ALREADY_IN_USE;
			return;
		}
		output_claim owning{verb_mixer? nullptr : verb, nullptr};
		struct entry_kept { audio_node* node; bool made; bool kept = false; ~entry_kept() { if (!kept && made) reverb_entry_forget(node); } } entry{verb, verb && reverb_entry_made(verb)}; // Before anything changes (see reverb_entry_made()); one made here is forgotten again on a refusal, rather than kept for good.
		// A mixer goes into the destination first, which refuses a loop, and then this node into the new reverb, which replaces the link to the old one: either refused leaves the old reverb as it was, rather than let go of before the new one was refused.
		// A mixer given as the reverb is moved to the destination before this node is attached to it: should the attach or the count then be refused or throw, as on running out of memory, it goes back to the parent it had, rather than left moved with that parent let go of.
		struct parent_kept {
			mixer* mix;
			mixer* parent;
			bool kept = false;
			parent_kept(mixer* m) : mix(m), parent(m? m->get_mixer() : nullptr) { if (parent) parent->duplicate(); }
			~parent_kept() {
				last_error_kept error; // The refusal's: putting back a mixer that never left its parent, or one moved, succeeds, which read as success after the refused set_reverb(), a property with no other way to tell.
				if (mix && !kept) {
					try {
						mix->set_mixer(parent);
					} catch (...) {}
				}
				if (parent) parent->release();
			}
		} moved{verb_mixer};
		if ((verb_mixer && !send_onward(verb, output_mixer)) || (verb? !attach_output_bus(0, verb, 0) : !detach_output_bus(0))) return;
		// Counted and, for a node that isn't a mixer, sent on before the old one is let go of: one that can't be sent on, as the engine's endpoint or a node whose attach there loops, is refused with this node back on the old reverb, rather than taken with the sends going wherever it already went and success read from the old one's let-go.
		std::shared_ptr<std::recursive_mutex> send;
		if (verb) {
			bool sent = true, counted = false;
			try {
				send = reverb_used(verb); // Its entry is made, but another reverb3d's let-go can take it out meanwhile, outside the topology lock, after which counting makes it anew and can run out of memory: within the try, which puts this node back on the old reverb.
				counted = true;
				if (!verb_mixer) sent = send_counted(verb, send);
			} catch (...) {
				last_error_kept kept;
				if (counted) reverb_uncount(verb); // Only a count this made: one that threw counted nothing, and taking one back took another reverb3d's.
				if (reverb) attach_output_bus(0, reverb, 0);
				else detach_output_bus(0);
				throw;
			}
			if (!sent) {
				const ma_result error = g_soundsystem_last_error;
				send.reset(); // So that the entry, with nothing else holding its send lock, can be forgotten.
				reverb_uncount(verb);
				if (reverb) attach_output_bus(0, reverb, 0);
				else detach_output_bus(0);
				g_soundsystem_last_error = error != MA_SUCCESS? error : MA_INVALID_OPERATION;
				return;
			}
		}
		claim.kept = true;
		owning.kept = true;
		entry.kept = true;
		moved.kept = true;
		// The old one is let go of once the new one is in, should counting or sending the new one throw, as on running out of memory, too: left, it stayed counted, attached and mixing for good.
		struct letting_go {
			reverb3d_impl* self;
			audio_node* node;
			~letting_go() {
				if (!node) return;
				drop_node_hold(static_cast<audio_node*>(self), node);
				try {
					reverb_let_go(node); // Still sent on for the reverb3ds that use it too.
				} catch (...) {} // Left where it goes rather than thrown from a destructor.
				drop_output_for_reverb(node);
				node->release();
			}
		} old{this, reverb};
		reverb = verb;
		if (reverb) reverb->duplicate();
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
			// Attached to the new destination before the old one goes, which attaching replaces: one the reverb can't go into, or without an input, as a sound, for a reverb3d that has no reverb yet, is refused, staying where it was, rather than left going nowhere while mixer read the sound.
			audio_node* target = mix? static_cast<audio_node*>(mix) : get_engine()->get_endpoint();
			if (reverb? !reverb_fits(reverb, target, ma_node_get_output_channels(get_ma_node(), 0)) : ma_node_get_input_bus_count(target->get_ma_node()) == 0) {
				g_soundsystem_last_error = MA_INVALID_OPERATION;
				return;
			}
			if (reverb && !reverb_free_for(reverb, target, 1)) { // Its reverb, which other reverb3ds use too, goes into theirs (see reverb_free_for()).
				g_soundsystem_last_error = MA_INVALID_OPERATION;
				return;
			}
			if (!claim_node_hold(static_cast<audio_node*>(this), mix)) { // A mixer that holds this reverb3d at any depth (see claim_node_hold()).
				g_soundsystem_last_error = MA_INVALID_ARGS;
				return;
			}
			hold_claim claim{static_cast<audio_node*>(this), mix}; // Dropped unless it becomes the mixer, a throw sending the reverb on included.
			if (reverb && !send_onward(reverb, mix)) return;
			claim.kept = true;
			old = output_mixer;
			output_mixer = mix;
			if (output_mixer) output_mixer->duplicate();
			drop_node_hold(static_cast<audio_node*>(this), old);
		}
		if (old) old->release();
	}
	mixer* get_mixer() const override { return output_mixer; }
	// Not a value that isn't finite, as for other nodes: the volume read NaN or infinite, and the send, which refuses such a volume, stopped following the distance.
	void set_min_volume(float value) override { if (finite_node_values({value}) && playable_node_gains({ma_volume_db_to_linear(value)})) min_volume = value; } // Nor one louder than +100 dB, whose send the reverb's attachment refuses, as other volumes.
	float get_min_volume() const override { return min_volume; }
	void set_max_volume(float value) override { if (finite_node_values({value}) && playable_node_gains({ma_volume_db_to_linear(value)})) max_volume = value; }
	float get_max_volume() const override { return max_volume; }
	void set_max_volume_distance(float value) override { if (finite_node_values({value})) max_volume_distance = value; }
	float get_max_volume_distance() const override { return max_volume_distance; }
	void set_max_audible_distance(float value) override { if (finite_node_values({value})) max_audible_distance = value; }
	float get_max_audible_distance() const override { return max_audible_distance; }
	void set_volume_curve(float value) override { if (finite_node_values({value})) volume_curve = value; }
	float get_volume_curve() const override { return volume_curve; }
	float get_volume_at(float distance) const override {
		float v;
		// Past the audible distance, the quietest send, told from the distance as given: clamped to the audible distance first, a sound past it took the loudest range whenever that reached so far, as with max_volume_distance at or past the audible distance, sent the loudest at every distance.
		if (!(distance <= max_audible_distance)) v = -60;
		else if (distance <= max_volume_distance) v = max_volume_distance > 0? range_convert(distance, 0, max_volume_distance, min_volume, max_volume) : max_volume; // A range of no width would divide by zero; its one point is max_volume_distance itself.
		else {
			v = range_convert(distance, max_volume_distance, max_audible_distance, 1, 0);
			// A curve of 0 or less, or 1 or more, takes the curve's own limit there, which the formula would reach dividing by zero: the loudest short of the audible distance, or the quietest past the loudest's distance. They gave max_volume or min_volume at every distance past max_volume_distance instead, the audible distance's -60 dB never reached, so that a sound far beyond it was still sent at about full level.
			if (volume_curve <= 0) v = v > 0? 1 : 0;
			else if (volume_curve >= 1) v = v >= 1? 1 : 0;
			else v = (1.0 - volume_curve) * ((v <= volume_curve? v : volume_curve) / volume_curve) + volume_curve * ((v > volume_curve? v - volume_curve : 0) / (1 - volume_curve));
			v = range_convert(v, 0, 1, -60, max_volume);
		}
		return ma_volume_db_to_linear(clamp_volume(v, max_volume < -70.0f? max_volume : -70.0f, max_volume)); // Not below -70 dB, unless the script set the loudest lower.
	}
	splitter_node* create_attachment(audio_node* dry_input, audio_node* dry_output) override {
		if (dry_input && dry_input->get_engine() != get_engine() || dry_output && dry_output->get_engine() != get_engine()) { // Both engines' audio threads would read the splitter.
			g_soundsystem_last_error = MA_INVALID_ARGS;
			return nullptr;
		}
		if (dry_input && refuse_owned_output(dry_input)) return nullptr;
		splitter_node* splitter = splitter_node::create(get_engine(), get_output_channels(0));
		try { // A throw attaching it, as on running out of memory, lets go of it too: kept, it held this reverb3d and the dry output, mixing for good.
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
		} catch (...) {
			last_error_kept kept;
			splitter->release();
			throw;
		}
		return splitter;
	}
};
// Without a destination, a new mixer of the reverb3d's own engine, as a reverb3d of the default engine always got one; a mixer of another engine is refused, as both engines' audio threads would read the reverb3d then.
std::recursive_mutex g_audio_topology_mutex;
// Whether a reverb can sit between a reverb3d giving the given channels and a destination: MiniAudio attaches a node's output only to an input of the same channel count, so a reverb of other channels, or a destination without an input, as a sound given as a mixer, left the reverb going nowhere.
bool reverb_fits(audio_node* verb, audio_node* destination, ma_uint32 channels_in) {
	ma_node* v = verb->get_ma_node();
	ma_node* d = destination->get_ma_node();
	return v && d && ma_node_get_input_bus_count(v) > 0 && ma_node_get_output_bus_count(v) > 0 && ma_node_get_input_bus_count(d) > 0 && ma_node_get_input_channels(v, 0) == channels_in && ma_node_get_output_channels(v, 0) == ma_node_get_input_channels(d, 0);
}
bool mixer_reaches(mixer* from, const std::function<bool(mixer*)>& is_target) {
	std::vector<mixer*> pending{from};
	std::unordered_set<mixer*> seen;
	while (!pending.empty() && seen.size() < 100000) {
		mixer* m = pending.back();
		pending.pop_back();
		if (!m || !seen.insert(m).second) continue;
		if (is_target(m)) return true;
		pending.push_back(m->get_mixer());
		if (reverb3d* verb = m->get_reverb3d_sent_to()) {
			pending.push_back(verb->get_mixer());
			if (audio_node* through = verb->get_reverb()) pending.push_back(dynamic_cast<mixer*>(through)); // A mixer used as its reverb, which it feeds.
		}
	}
	return false;
}
bool reverb3d_reaches(reverb3d* verb, const std::function<bool(mixer*)>& is_target) {
	mixer* into = verb->get_mixer();
	audio_node* through = verb->get_reverb();
	mixer* through_mixer = through? dynamic_cast<mixer*>(through) : nullptr;
	return (into && mixer_reaches(into, is_target)) || (through_mixer && mixer_reaches(through_mixer, is_target));
}
reverb3d* reverb3d::create(audio_node* reverb, mixer* destination, audio_engine* e) {
	if (!e) throw_refusal(MA_INVALID_ARGS, "no audio engine available");
	if (destination && destination->get_engine() != e) throw_refusal(MA_INVALID_ARGS, "the destination mixer belongs to another audio engine");
	if (reverb && reverb->get_engine() != e) throw_refusal(MA_INVALID_ARGS, "the reverb belongs to another audio engine");
	audio_node* target = destination? static_cast<audio_node*>(destination) : e->get_endpoint();
	if (reverb? !reverb_fits(reverb, target, e->get_channels()) : ma_node_get_input_bus_count(target->get_ma_node()) == 0) throw_refusal(MA_INVALID_OPERATION, "the destination takes no input from the reverb"); // A sound given as a mixer, or a reverb of another channel count: the reverb would go nowhere, as reverb3d.mixer and reverb3d.reverb refuse them.
	std::lock_guard<std::recursive_mutex> topology(g_audio_topology_mutex);
	// A mixer given as the reverb goes into the destination as a mixer, which a destination going into that mixer would loop: refused, as reverb3d.reverb refuses it, rather than made with the reverb going where the mixer went before.
	if (mixer* verb_mixer = reverb? dynamic_cast<mixer*>(reverb) : nullptr) {
		if (destination && mixer_reaches(destination, [verb_mixer](mixer* m) { return m == verb_mixer; })) throw_refusal(MA_INVALID_ARGS, "the destination goes into the reverb mixer");
	}
	if (destination && reverb && !reverb_free_for(reverb, destination, 0)) throw_refusal(MA_INVALID_OPERATION, "the reverb goes into another destination for another reverb3d already");
	if (destination) return new reverb3d_impl(e, reverb, destination);
	// Without a destination, a reverb other reverb3ds use goes on where they send it, rather than into a mixer of this one's own that took it from them (see reverb_free_for()).
	if (reverb && reverb_users_of(reverb) > 0) {
		// A reverb that isn't a mixer goes where its attachment does, which the last other reverb3d sharing it can let go of on another thread meanwhile, outside the topology lock: held until the new reverb3d holds its own.
		struct holding { audio_node* node; ~holding() { if (node) node->release(); } } destination_held{dynamic_cast<mixer*>(reverb)? nullptr : reverb_destination(reverb)};
		audio_node* into = destination_held.node? destination_held.node : reverb_goes_into(reverb);
		if (mixer* theirs = dynamic_cast<mixer*>(into)) return new reverb3d_impl(e, reverb, theirs);
		if (into == e->get_endpoint()) return new reverb3d_impl(e, reverb, nullptr);
		// Gone elsewhere by hand, or nowhere: taken into a mixer of this one's own, it was taken from the reverb3ds using it without the check a destination gets above.
		throw_refusal(MA_INVALID_OPERATION, "the reverb goes into another destination for another reverb3d already");
	}
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
static std::atomic<int> g_default_3d_panner{-1}; // Set by one script thread, read by spatializers made on any.
static std::atomic<int> g_default_3d_attenuator{-1};
std::recursive_mutex g_node_graph_mutex;
class audio_spatializer_impl;
static std::unordered_set<audio_spatializer_impl*> g_tracked_spatializers;
static std::mutex g_tracked_spatializers_mutex; // a mixer or sound makes its spatializer, when first needed, on whatever script thread that is, while sound_set_spatialization iterates the set from another
static std::mutex g_spatializer_sweep_mutex; // One panner or attenuator change at a time rewires the spatializers, so that two don't reach each in different orders.
// The spatializers a panner or attenuator change took a reference to, let go of as it goes out of scope. Declared before the change's lock, so after that lock, as letting go of a last reference can run a teardown ending in script code that makes such a change again; and on an exception, as a component that can't be made throws, rather than kept for good with their engines.
struct swept_spatializers {
	std::vector<audio_spatializer_impl*> taken;
	~swept_spatializers(); // After audio_spatializer_impl.
};
static void sweep_tracked_spatializers(swept_spatializers &swept, bool panner, int id, bool enabled); // After audio_spatializer_impl.

int register_audio_panner(spatializer_component_node_factory factory, bool default_enabled) {
	int id = g_next_panner_id++;
	spatializer_component& component = g_audio_panners[id];
	component.factory = factory;
	component.enabled = default_enabled;
	return id;
}

int register_audio_attenuator(spatializer_component_node_factory factory, bool default_enabled) {
	int id = g_next_attenuator_id++;
	spatializer_component& component = g_audio_attenuators[id];
	component.factory = factory;
	component.enabled = default_enabled;
	return id;
}

spatializer_component_node* create_audio_panner(int id, audio_spatializer* spatializer, audio_engine* engine) {
	auto it = g_audio_panners.find(id);
	if (it == g_audio_panners.end() || !it->second.enabled) return nullptr;
	// A component that can't be made, as Steam Audio's when it can't start, gives none, as a disabled one does, so that the spatializer falls back to another (see set_fallback_panner()) rather than every positioning call throwing.
	try {
		return it->second.factory(spatializer, engine);
	} catch (const std::exception&) {
		return nullptr;
	}
}

spatializer_component_node* create_audio_attenuator(int id, audio_spatializer* spatializer, audio_engine* engine) {
	auto it = g_audio_attenuators.find(id);
	if (it == g_audio_attenuators.end() || !it->second.enabled) return nullptr;
	try { // As create_audio_panner().
		return it->second.factory(spatializer, engine);
	} catch (const std::exception&) {
		return nullptr;
	}
}

void set_audio_panner_enabled(int id, bool enabled) {
	swept_spatializers swept;
	std::lock_guard<std::mutex> sweep(g_spatializer_sweep_mutex);
	auto it = g_audio_panners.find(id);
	if (it == g_audio_panners.end()) g_soundsystem_last_error = MA_INVALID_ARGS; // As set_sound_default_3d_panner() refuses it, which said nothing here.
	if (it != g_audio_panners.end()) {
		bool was_enabled = it->second.enabled;
		it->second.enabled = enabled;
		if (was_enabled != enabled) sweep_tracked_spatializers(swept, true, id, enabled);
	}
}

void set_audio_attenuator_enabled(int id, bool enabled) {
	swept_spatializers swept;
	std::lock_guard<std::mutex> sweep(g_spatializer_sweep_mutex);
	auto it = g_audio_attenuators.find(id);
	if (it == g_audio_attenuators.end()) g_soundsystem_last_error = MA_INVALID_ARGS;
	if (it != g_audio_attenuators.end()) {
		bool was_enabled = it->second.enabled;
		it->second.enabled = enabled;
		if (was_enabled != enabled) sweep_tracked_spatializers(swept, false, id, enabled);
	}
}

bool audio_panner_exists(int id) { return g_audio_panners.find(id) != g_audio_panners.end(); }
bool audio_attenuator_exists(int id) { return g_audio_attenuators.find(id) != g_audio_attenuators.end(); }
bool get_audio_panner_enabled(int id) {
	auto it = g_audio_panners.find(id);
	return it != g_audio_panners.end() && it->second.enabled;
}

bool get_audio_attenuator_enabled(int id) {
	auto it = g_audio_attenuators.find(id);
	return it != g_audio_attenuators.end() && it->second.enabled;
}

// An id no panner or attenuator has is refused with MA_INVALID_ARGS: it was kept and read back, while every positioned sound fell back to another.
void sound_set_default_3d_panner(int panner_id) {
	if (g_audio_panners.find(panner_id) == g_audio_panners.end()) {
		g_soundsystem_last_error = MA_INVALID_ARGS;
		return;
	}
	g_default_3d_panner = panner_id;
}

int sound_get_default_3d_panner() {
	return g_default_3d_panner;
}

void sound_set_default_3d_attenuator(int attenuator_id) {
	if (g_audio_attenuators.find(attenuator_id) == g_audio_attenuators.end()) {
		g_soundsystem_last_error = MA_INVALID_ARGS;
		return;
	}
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
	if (panner_it == g_audio_panners.end() || g_audio_attenuators.find(attenuator) == g_audio_attenuators.end()) { // Both checked before either is applied: an unknown attenuator left the panner applied while this returned false.
		g_soundsystem_last_error = MA_INVALID_ARGS;
		return false;
	}
	if (panner_it != g_audio_panners.end()) {
		if (!panner_it->second.enabled) set_audio_panner_enabled(panner, true);
		if (set_default) sound_set_default_3d_panner(panner);
		panner_success = true;
		if (panner != prev_panner && disable_previous && set_default) set_audio_panner_enabled(prev_panner, false); // Only one this replaced as the default: kept the default, a disabled one left newly positioned sounds on whichever enabled component came first.
	}
	auto attenuator_it = g_audio_attenuators.find(attenuator);
	if (attenuator_it != g_audio_attenuators.end()) {
		if (!attenuator_it->second.enabled) set_audio_attenuator_enabled(attenuator, true);
		if (set_default) sound_set_default_3d_attenuator(attenuator);
		attenuator_success = true;
		if (attenuator != prev_attenuator && disable_previous && set_default) set_audio_attenuator_enabled(prev_attenuator, false); // As above.
	}
	if (panner_success && attenuator_success) g_soundsystem_last_error = MA_SUCCESS; // As a call that succeeded reads.
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
	// Its rewiring runs in the chain's rewire_scope, what it lets go of released once the thread's outermost release_scope ends (see release_scope).
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
		return std::min(volume, max_volume_gain); // As the attachment's bus volume takes it, which refused a louder send, so that the send stopped following the distance.
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
		spatialization_params.max_volume = 1.0f; // MiniAudio's maximum gain, so that a reverb's first send, worked out from these before the mixer gives any, is the one at the listener rather than clamped to 0 with an attenuator.
		{ std::lock_guard<std::mutex> lock(g_tracked_spatializers_mutex); g_tracked_spatializers.insert(this); }
	}
	~audio_spatializer_impl() {
		last_error_kept kept;
		drop_node_holds(static_cast<audio_node*>(this));
		// Out of the set first, which a global panner or attenuator change takes its references from: it takes none once the last one went (see duplicate_if_alive()), so none is rewiring this one as its node goes, nor reaches it once it is out.
		{ std::lock_guard<std::mutex> lock(g_tracked_spatializers_mutex); g_tracked_spatializers.erase(this); }
		// A component the script kept goes on without this spatializer: off the graph first, which waits for the audio thread to stop processing it, then without its pointer back here, so it passes audio through if used again.
		for (spatializer_component_node *component : {panner, attenuator}) {
			if (!component) continue;
			try {
				component->detach_all_output_buses();
			} catch (...) {} // Out of memory taking it off, which a destructor can't throw: left on the graph, where it passes audio through once it forgets this spatializer.
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
		if (placement != prepan && placement != postpan && placement != postattenuate) { // Another took the attachment out of the chain and never put it back, keeping the reverb3d silent.
			g_soundsystem_last_error = MA_INVALID_ARGS;
			return;
		}
		if (new_reverb && new_reverb->get_engine() != get_engine()) { // Another engine's audio thread reads that reverb3d, which two threads can't read at once.
			g_soundsystem_last_error = MA_INVALID_ARGS;
			return;
		}
		// Not a reverb3d whose mixer is this one, or goes into it (see mixer_reaches()). Asked before this spatializer's chain lock is taken: mixer_reaches() takes other spatializers' chain locks, one at a time, so a thread holding this one while another, holding one of those, set a reverb3d sending back here deadlocked with it. The topology lock is held through the change.
		std::lock_guard<std::recursive_mutex> topology(g_audio_topology_mutex);
		mixer* owner = get_mixer();
		if (new_reverb && owner && new_reverb != get_reverb3d() && reverb3d_reaches(new_reverb, [owner](mixer* m) { return m == owner; })) {
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
		if (!claim_node_hold(static_cast<audio_node*>(this), new_reverb)) { // One whose reverb holds this spatializer at any depth, as a chain it is in (see claim_node_hold()).
			g_soundsystem_last_error = MA_INVALID_ARGS;
			return;
		}
		hold_claim claim{static_cast<audio_node*>(this), new_reverb}; // Dropped unless it becomes the reverb3d.
		splitter_node* attachment = new_reverb? new_reverb->create_attachment() : nullptr; // First: one that can't be made, or throws, leaves the sound its old reverb, which was let go of before it.
		if (new_reverb && !attachment) return;
		// The old attachment out of the chain before anything else changes, so that a throw there, as on running out of memory, leaves the old reverb as it was, the new attachment let go of.
		if (reverb_attachment) {
			try {
				remove_node(reverb_attachment);
			} catch (...) {
				if (attachment) attachment->release();
				throw;
			}
		}
		if (reverb) {
			drop_node_hold(static_cast<audio_node*>(this), reverb);
			release_later(reverb);
		}
		if (reverb_attachment) release_later(reverb_attachment);
		reverb = nullptr;
		reverb_attachment = nullptr;
		if (new_reverb) {
			// Kept before it is placed, so that a throw placing it leaves it this spatializer's, let go of as any other, rather than held by nothing.
			new_reverb->duplicate();
			reverb = new_reverb;
			reverb_attachment = attachment;
			reverb_placement = placement;
			claim.kept = true;
			if (attached_mixer && parameters_valid) reverb_attachment->set_output_bus_volume(1, reverb_send_volume(new_reverb));
			position_reverb();
		}
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
		if (g_audio_panners.find(panner_id) == g_audio_panners.end()) { // An id no panner has, refused as set_sound_default_3d_panner() refuses it: it was kept as the one preferred, read back, while another played.
			g_soundsystem_last_error = MA_INVALID_ARGS;
			return;
		}
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
		if (g_audio_attenuators.find(attenuator_id) == g_audio_attenuators.end()) { // As set_panner_by_id().
			g_soundsystem_last_error = MA_INVALID_ARGS;
			return;
		}
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
			// Spatialization off, the mixer plays unattenuated, as at the listener: its send is the reverb's there too, rather than kept at what it was when spatialization went off, loud or nearly silent.
			if (reverb) reverb_attachment->set_output_bus_volume(1, parameters_valid? reverb_send_volume(reverb) : std::min(reverb->get_volume_at(0), max_volume_gain));
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
	// A reference unless the last one already went, its destructor then waiting to take it out of g_tracked_spatializers (see sweep_tracked_spatializers()).
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
};
audio_spatializer* audio_spatializer::create(mixer* mixer, audio_engine* engine) { return new audio_spatializer_impl(mixer, engine); }
// Rewires each spatializer for a panner or attenuator turned on or off, with a reference taken to each under g_tracked_spatializers_mutex and the rewiring done after it: done under it, a spatializer made or destroyed meanwhile, as by a processing callback placing a sound or letting one go, waited for the whole sweep, 60 ms for 700 spatializers. One whose last reference already went is passed over, its destructor taking it out. The references are let go of by swept.
static void sweep_tracked_spatializers(swept_spatializers &swept, bool panner, int id, bool enabled) {
	{
		std::lock_guard<std::mutex> lock(g_tracked_spatializers_mutex);
		swept.taken.reserve(g_tracked_spatializers.size());
		for (audio_spatializer_impl* spatializer : g_tracked_spatializers)
			if (spatializer->duplicate_if_alive()) swept.taken.push_back(spatializer);
	}
	for (audio_spatializer_impl* spatializer : swept.taken) {
		if (panner) spatializer->on_panner_enabled_changed(id, enabled);
		else spatializer->on_attenuator_enabled_changed(id, enabled);
	}
}
swept_spatializers::~swept_spatializers() {
	for (audio_spatializer_impl* spatializer : taken) spatializer->release();
}

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
		{
			// At no farther than max_distance, past which the distance attenuates no more, rather than darkening on for good, and to silence where the basic attenuator holds min_gain.
			const float farthest = params.max_distance > params.min_distance? params.max_distance : params.min_distance, at = params.listener_distance < farthest? params.listener_distance : farthest;
			float absorbed = (params.min_distance > 0? (at > params.min_distance? at - params.min_distance : 0) : at) * params.rolloff;
			if (!std::isfinite(absorbed)) absorbed = std::isnan(absorbed)? 0 : std::numeric_limits<float>::max();
			iplAirAbsorptionCalculate(g_phonon_context, IPLVector3{absorbed, 0, 0}, listenerPos, &airAbsorptionModel, iplEffectParams.airAbsorption);
		}
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
