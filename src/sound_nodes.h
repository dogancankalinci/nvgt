/* sound_nodes.h - audio nodes header
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

#include <functional>
#include <cmath>
#include <exception>
#include <angelscript.h> // asAtomic
#include <miniaudio_phonon.h>
#include <phonon.h>
#include <unordered_map>
#include <unordered_set>
#include <atomic>
#include <vector>
#include <mutex>
#include "sound.h"

// miniaudio's node graph is lock-free for the audio thread that reads it, but its attach/detach mutations assume a single writer. Script threads create and destroy sounds and mixers concurrently, each of which attaches to and detaches from the engine endpoint, so the mutations are serialised here. Recursive because a chain's set_endpoint attaches through its last node.
extern std::recursive_mutex g_node_graph_mutex;
// A group of an engine through which a node of another sample rate goes into one of its nodes, resampled from that rate to the engine's (see audio_node_impl::attach_output_bus()). Made unattached, of the given channels in and out, under the graph lock, as it is let go of.
ma_sound* rate_bridge_create(audio_engine* engine, unsigned int channels, unsigned int sample_rate);
void rate_bridge_destroy(ma_sound* bridge);
class audio_node_impl : public virtual audio_node {
protected:
	ma_node_base* node; // Must be set by subclasses
	audio_engine *engine;
	int refcount;
	std::vector<audio_node*> output_connections; // Owns a reference to whatever each output bus is currently attached to, so an attached node can't be freed out from under the graph.
	// For each output bus going into a node of another sample rate, the group of the destination's engine it goes through (see attach_output_bus()), under the graph lock.
	std::vector<ma_sound*> rate_bridges;
	// The sample rate this node's output runs at, 0 for its engine's: an engine's own, mixed into another, and a data source's, whose node gives the source's frames as they are.
	virtual unsigned int output_sample_rate() const { return is_engine()? (unsigned int)engine->get_sample_rate() : 0; }
	// Lets go of the group an output bus went through, under the graph lock.
	void drop_rate_bridge(unsigned int bus) {
		if (bus >= rate_bridges.size() || !rate_bridges[bus]) return;
		rate_bridge_destroy(rate_bridges[bus]);
		rate_bridges[bus] = nullptr;
	}
	// Each of a destination's engine, which may go once that destination is let go of, so before.
	void drop_rate_bridges() {
		for (unsigned int bus = 0; bus < rate_bridges.size(); bus++) drop_rate_bridge(bus);
	}
public:
	audio_node_impl(ma_node_base *node, audio_engine *engine) : audio_node(), node(node), engine(engine), refcount(1) {
		// A node of a given engine, such as one of the script's engines without a device, needs only what every engine needs; one without an engine goes on the default engine, which init_sound() builds.
		if (!(engine? init_sound_context() : init_sound())) throw std::runtime_error("sound system was not initialized");
		if (!engine) this->engine = acquire_default_engine(); // With the reference this node keeps already taken.
		// Defense in depth: without an engine there is nothing to attach to, and the duplicate() below would dereference null. uninit_sound() can also leave g_audio_engine cleared behind us.
		if (!this->engine) throw std::runtime_error("no audio engine available");
		if (engine && !is_engine()) this->engine->duplicate();
	}
	~audio_node_impl() {
		{
			std::lock_guard<std::recursive_mutex> graph_lock(g_node_graph_mutex);
			drop_rate_bridges();
		}
		for (audio_node *n : output_connections) if (n) n->release();
		if (engine && !is_engine()) engine->release();
	}
	// Whether this node is its engine, which holds no reference on itself. Compared through audio_node, the base both share: a dynamic_cast of the engine to this class gives null while the engine's own constructor is still running this one, so every engine took a reference on itself and was never destroyed.
	bool is_engine() const { return static_cast<const audio_node*>(engine) == static_cast<const audio_node*>(this); }
	void duplicate() { asAtomicInc(refcount); }
	void release() {
		if (asAtomicDec(refcount) < 1)
			delete this;
	}
	audio_engine *get_engine() const { return engine; }
	ma_node_base *get_ma_node() { return node; }
	// What an output bus goes into, with a reference the caller lets go of, or null.
	audio_node* acquire_output_destination(unsigned int bus) const {
		std::lock_guard<std::recursive_mutex> graph_lock(g_node_graph_mutex); // Which output_connections change under.
		audio_node* destination = bus < output_connections.size()? output_connections[bus] : nullptr;
		if (destination) destination->duplicate();
		return destination;
	}
	unsigned int get_input_bus_count() { return node ? ma_node_get_input_bus_count(node) : 0; }
	unsigned int get_output_bus_count() { return node ? ma_node_get_output_bus_count(node) : 0; }
	unsigned int get_input_channels(unsigned int bus) { return node ? ma_node_get_input_channels(node, bus) : 0; }
	unsigned int get_output_channels(unsigned int bus) { return node ? ma_node_get_output_channels(node, bus) : 0; }
	// Whether this node's output goes anywhere, which then reads it on that engine's audio thread.
	bool output_attached() const {
		std::lock_guard<std::recursive_mutex> graph_lock(g_node_graph_mutex); // Which output_connections change under.
		for (audio_node *n : output_connections) if (n) return true;
		return false;
	}
	// Whether an engine is this node's engine, or is mixed into it through engines attached into one another.
	bool feeds_engine(audio_engine *target) const {
		std::lock_guard<std::recursive_mutex> graph_lock(g_node_graph_mutex); // Which output_connections change under.
		for (int depth = 0; target && depth < 64; depth++) {
			if (target == engine) return true;
			auto target_node = dynamic_cast<const audio_node_impl*>(target);
			audio_node *next = target_node && !target_node->output_connections.empty()? target_node->output_connections[0] : nullptr;
			target = next? next->get_engine() : nullptr;
		}
		return false;
	}
	// The node this one was attached to is let go of after the graph lock: letting go can destroy it, and a destructor, such as a spatializer's, takes locks that are taken before the graph lock elsewhere.
	// Whether from is to, or its output reaches to through attachments. Under g_node_graph_mutex, which attachments change under.
	static bool reaches_node(audio_node* from, const audio_node* to) {
		std::vector<audio_node*> todo{from};
		std::unordered_set<audio_node*> seen;
		while (!todo.empty()) {
			audio_node* n = todo.back();
			todo.pop_back();
			if (n == to) return true;
			if (!n || !seen.insert(n).second) continue;
			if (audio_node_impl* impl = dynamic_cast<audio_node_impl*>(n)) todo.insert(todo.end(), impl->output_connections.begin(), impl->output_connections.end());
		}
		return false;
	}
	bool attach_output_bus(unsigned int output_bus, audio_node *destination, unsigned int destination_input_bus) {
		if (!node || !destination) return false;
		unsigned int from = output_sample_rate(), to = destination->get_engine()? (unsigned int)destination->get_engine()->get_sample_rate() : 0; // Before the graph lock, so that no lock a subclass may read its rate under is taken inside it.
		audio_node *previous = nullptr;
		{
			std::lock_guard<std::recursive_mutex> graph_lock(g_node_graph_mutex); 
			// Checked under the graph lock the attach is made under, which feeds_engine() takes too, so that two threads mixing two no-device engines into each other at once can't both pass it before either attached. Only into this node's own engine, whose audio thread alone reads its graph: a node read by two engines' threads at once crashes. An engine itself is the exception, as a no-device engine is mixed into another through its own node, which only that other engine's thread then reads; an engine with a device would be read by its own device thread too, and one fed back into itself, directly or through other engines, would read itself without end.
			if (is_engine()? !(engine->get_flags() & audio_engine::NO_DEVICE) || feeds_engine(destination->get_engine()) : destination->get_engine() != engine) {
				g_soundsystem_last_error = MA_INVALID_ARGS;
				return false;
			}
			// Nor into itself, or into a node whose output reaches this one, as a chain's endpoint set to the chain or one of its own nodes: each attachment holds the node it goes into, so the loop kept every node on it, and their engine with its device, alive for good.
			if (reaches_node(destination, this)) {
				g_soundsystem_last_error = MA_INVALID_ARGS;
				return false;
			}
			// A node's output is read at the rate of the graph it goes into, which doesn't resample, so one of another rate, as a no-device engine of its own rate mixed into another or a decoder's node at its file's rate, played at the ratio of the two rates, too fast or slow and out of tune. It goes through a group of the destination's engine instead, which resamples it from its rate.
			ma_node* target = destination->get_ma_node();
			unsigned int target_bus = destination_input_bus;
			ma_sound* bridge = nullptr;
			if (from && to && from != to) {
				// Of the node's own channels in and out, so that one whose channels differ from the destination's is still refused, as straight into it.
				if (!(bridge = rate_bridge_create(destination->get_engine(), ma_node_get_output_channels(node, output_bus), from))) return false;
				if ((g_soundsystem_last_error = ma_node_attach_output_bus(bridge, 0, target, target_bus)) != MA_SUCCESS) {
					rate_bridge_destroy(bridge);
					return false;
				}
				target = bridge;
				target_bus = 0;
			}
			if ((g_soundsystem_last_error = ma_node_attach_output_bus(node, output_bus, target, target_bus)) != MA_SUCCESS) {
				if (bridge) rate_bridge_destroy(bridge);
				return false;
			}
			if (output_bus >= output_connections.size()) output_connections.resize(output_bus + 1, nullptr);
			if (output_bus >= rate_bridges.size()) rate_bridges.resize(output_bus + 1, nullptr);
			drop_rate_bridge(output_bus); // The one this bus went through before, left without input by the attach.
			rate_bridges[output_bus] = bridge;
			previous = output_connections[output_bus];
			output_connections[output_bus] = destination;
			destination->duplicate();
		}
		if (previous) previous->release();
		return true;
	}
	bool detach_output_bus(unsigned int bus) {
		if (!node) return false;
		audio_node *previous = nullptr;
		{
			std::lock_guard<std::recursive_mutex> graph_lock(g_node_graph_mutex); 
			if ((g_soundsystem_last_error = ma_node_detach_output_bus(node, bus)) != MA_SUCCESS) return false;
			drop_rate_bridge(bus);
			if (bus < output_connections.size()) {
				previous = output_connections[bus];
				output_connections[bus] = nullptr;
			}
		}
		if (previous) previous->release();
		return true;
	}
	bool detach_all_output_buses() {
		if (!node) return false;
		std::vector<audio_node*> previous;
		{
			std::lock_guard<std::recursive_mutex> graph_lock(g_node_graph_mutex); 
			if ((g_soundsystem_last_error = ma_node_detach_all_output_buses(node)) != MA_SUCCESS) return false;
			drop_rate_bridges();
			for (audio_node *&n : output_connections) {
				if (n) previous.push_back(n);
				n = nullptr;
			}
		}
		for (audio_node *n : previous) n->release();
		return true;
	}
	bool set_output_bus_volume(unsigned int bus, float volume) {
		if (!node) return false;
		if (!std::isfinite(volume)) { // A NaN or infinite volume made every sample the bus fed NaN.
			g_soundsystem_last_error = MA_INVALID_ARGS;
			return false;
		}
		return (g_soundsystem_last_error = ma_node_set_output_bus_volume(node, bus, volume)) == MA_SUCCESS;
	}
	float get_output_bus_volume(unsigned int bus) { return node ? ma_node_get_output_bus_volume(node, bus) : 0; }
	bool set_state(ma_node_state state) { return node ? (g_soundsystem_last_error = ma_node_set_state(node, state)) == MA_SUCCESS : false; }
	ma_node_state get_state() { return node ? ma_node_get_state(node) : ma_node_state_stopped; }
	bool set_state_time(ma_node_state state, unsigned long long time) { return node ? (g_soundsystem_last_error = ma_node_set_state_time(node, state, time)) == MA_SUCCESS : false; }
	unsigned long long get_state_time(ma_node_state state) { return node ? ma_node_get_state_time(node, state) : 0; } // As MiniAudio gives for no node, rather than a state, which read as frame 1.
	ma_node_state get_state_by_time(unsigned long long global_time) { return node ? ma_node_get_state_by_time(node, global_time) : ma_node_state_stopped; }
	ma_node_state get_state_by_time_range(unsigned long long global_time_begin, unsigned long long global_time_end) { return node ? ma_node_get_state_by_time_range(node, global_time_begin, global_time_end) : ma_node_state_stopped; }
	unsigned long long get_time() const { return node ? ma_node_get_time(node) : 0; }
	bool set_time(unsigned long long local_time) { return node ? (g_soundsystem_last_error = ma_node_set_time(node, local_time)) == MA_SUCCESS : false; }
};
typedef struct {
	ma_node_base base;
	effect_node* node;
} ma_effect_node;
class effect_node_impl : public audio_node_impl, public virtual effect_node {
	ma_node_vtable vtable;
	public:
	std::unique_ptr<ma_effect_node> n;
	effect_node_impl(audio_engine* e, ma_uint8 input_channel_count, ma_uint8 output_channel_count, ma_uint8 input_bus_count, ma_uint8 output_bus_count, unsigned int flags);
	~effect_node_impl();
	void destroy_node();
	void process(const float** frames_in, unsigned int* frame_count_in, float** frames_out, unsigned int* frame_count_out) override;
	unsigned int required_input_frame_count(unsigned int output_frame_count) const override;
};

class passthrough_node : public virtual audio_node {
	public:
	static passthrough_node* create(audio_engine* engine);
};

// When nodes are added or removed from a node_chain, they are automatically reattached as needed.
class audio_node_chain : public virtual passthrough_node {
public:
	virtual bool attach_output_bus(unsigned int bus_index, audio_node* node, unsigned int input_bus_index) override = 0;
	virtual bool detach_output_bus(unsigned int bus_index) override = 0;
	virtual bool detach_all_output_buses() override = 0;
	virtual bool add_node(audio_node* node, audio_node* after = nullptr, unsigned int input_bus_index = 0) = 0; // input_bus_index is the new node's input bus that the node before it feeds; the chain keeps it through later changes.
	virtual bool add_node_at(audio_node* node, int after = -1, unsigned int input_bus_index = 0) = 0;
	virtual bool remove_node(audio_node* node) = 0;
	virtual bool remove_node_at(unsigned int index) = 0;
	virtual bool clear(bool detach_nodes = true) = 0;
	virtual void set_endpoint(audio_node* endpoint, unsigned int input_bus_index = 0) = 0;
	virtual audio_node* get_endpoint() const = 0;
	virtual audio_node* first() const = 0;
	virtual audio_node* last() const = 0;
	virtual audio_node* operator[](unsigned int index) const = 0;
	virtual int index_of(audio_node* node) const = 0;
	virtual unsigned int get_node_count() const = 0;
	static audio_node_chain* create(audio_node* source = nullptr, audio_node* endpoint = nullptr, audio_engine* engine = nullptr);
};

bool set_global_hrtf(bool enabled);
bool get_global_hrtf();

class phonon_binaural_node : public virtual audio_node {
	public:
	static phonon_binaural_node* create(audio_engine* engine, int channels, int sample_rate, int frame_size = 0);
	virtual void set_direction(float x, float y, float z, float distance) = 0;
	virtual void set_direction_vector(const reactphysics3d::Vector3& direction, float distance) = 0;
	virtual void set_spatial_blend_max_distance(float max_distance) = 0;
};
class splitter_node : public virtual audio_node {
	public:
	static splitter_node* create(audio_engine* engine, int channels);
};
class low_pass_filter_node : public virtual audio_node {
public:
	virtual void set_cutoff_frequency(double freq) = 0;
	virtual double get_cutoff_frequency() const = 0;
	virtual void set_order(unsigned int order) = 0;
	virtual unsigned int get_order() const = 0;
	static low_pass_filter_node* create(double cutoff_frequency, unsigned int order, audio_engine* engine);
};
class high_pass_filter_node : public virtual audio_node {
public:
	virtual void set_cutoff_frequency(double freq) = 0;
	virtual double get_cutoff_frequency() const = 0;
	virtual void set_order(unsigned int order) = 0;
	virtual unsigned int get_order() const = 0;
	static high_pass_filter_node* create(double cutoff_frequency, unsigned int order, audio_engine* engine);
};
class band_pass_filter_node : public virtual audio_node {
public:
	virtual void set_cutoff_frequency(double freq) = 0;
	virtual double get_cutoff_frequency() const = 0;
	virtual void set_order(unsigned int order) = 0;
	virtual unsigned int get_order() const = 0;
	static band_pass_filter_node* create(double cutoff_frequency, unsigned int order, audio_engine* engine);
};
class notch_filter_node : public virtual audio_node {
public:
	virtual void set_q(double q) = 0;
	virtual double get_q() const = 0;
	virtual void set_frequency(double freq) = 0;
	virtual double get_frequency() const = 0;
	static notch_filter_node* create(double q, double frequency, audio_engine* engine);
};
class peak_filter_node : public virtual audio_node {
public:
	virtual void set_gain(double gain) = 0;
	virtual double get_gain() const = 0;
	virtual void set_q(double q) = 0;
	virtual double get_q() const = 0;
	virtual void set_frequency(double freq) = 0;
	virtual double get_frequency() const = 0;
	static peak_filter_node* create(double gain_db, double q, double frequency, audio_engine* engine);
};
class low_shelf_filter_node : public virtual audio_node {
public:
	virtual void set_gain(double gain) = 0;
	virtual double get_gain() const = 0;
	virtual void set_q(double q) = 0;
	virtual double get_q() const = 0;
	virtual void set_frequency(double freq) = 0;
	virtual double get_frequency() const = 0;
	static low_shelf_filter_node* create(double gain_db, double q, double frequency, audio_engine* engine);
};
class high_shelf_filter_node : public virtual audio_node {
public:
	virtual void set_gain(double gain) = 0;
	virtual double get_gain() const = 0;
	virtual void set_q(double q) = 0;
	virtual double get_q() const = 0;
	virtual void set_frequency(double freq) = 0;
	virtual double get_frequency() const = 0;
	static high_shelf_filter_node* create(double gain_db, double q, double frequency, audio_engine* engine);
};
class delay_node : public virtual audio_node {
public:
	virtual void set_wet(float wet) = 0;
	virtual float get_wet() const = 0;
	virtual void set_dry(float dry) = 0;
	virtual float get_dry() const = 0;
	virtual void set_decay(float decay) = 0;
	virtual float get_decay() const = 0;
	static delay_node* create(unsigned int delay_in_frames, float decay, audio_engine* engine);
};
class freeverb_node : public virtual audio_node {
	public:
	virtual void set_room_size(float size) = 0;
	virtual float get_room_size() const = 0;
	virtual void set_damping(float damping) = 0;
	virtual float get_damping() const = 0;
	virtual void set_width(float width) = 0;
	virtual float get_width() const = 0;
	virtual void set_wet(float wet) = 0;
	virtual float get_wet() const = 0;
	virtual void set_dry(float dry) = 0;
	virtual float get_dry() const = 0;
	virtual void set_input_width(float width) = 0;
	virtual float get_input_width() const = 0;
	virtual void set_frozen(bool frozen) = 0;
	virtual bool get_frozen() const = 0;
	static freeverb_node* create(audio_engine* engine);
};
class reverb3d : public virtual passthrough_node {
public:
	virtual void set_reverb(audio_node* verb) = 0;
	virtual audio_node* get_reverb() const = 0;
	virtual void set_mixer(mixer* mix) = 0;
	virtual mixer* get_mixer() const = 0;
	virtual void set_min_volume(float min_volume) = 0;
	virtual float get_min_volume() const = 0;
	virtual void set_max_volume(float max_volume) = 0;
	virtual float get_max_volume() const = 0;
	virtual void set_max_volume_distance(float distance) = 0;
	virtual float get_max_volume_distance() const = 0;
	virtual void set_max_audible_distance(float distance) = 0;
	virtual float get_max_audible_distance() const = 0;
	virtual void set_volume_curve(float volume_curve) = 0;
	virtual float get_volume_curve() const = 0;
	virtual float get_volume_at(float distance) const = 0;
	virtual splitter_node* create_attachment(audio_node* dry_input = nullptr, audio_node* dry_output = nullptr) = 0;
	static reverb3d* create(audio_node* reverb, mixer* destination = nullptr, audio_engine* e = g_audio_engine);
};
class plugin_node : public virtual audio_node {
public:
	virtual audio_plugin_node_interface* get_plugin_interface() const = 0;
	virtual void process(const float** frames_in, unsigned int* frame_count_in, float** frames_out, unsigned int* frame_count_out) = 0;
	// The script type of the plugin's node type this node was made as, 0 when unknown: every plugin's node types are this one class, which a cast tells apart only by this.
	virtual int get_script_type_id() const = 0;
	virtual void set_script_type_id(int type_id) = 0;
	static plugin_node* create(audio_plugin_node_interface* impl, unsigned char input_bus_count, unsigned char output_bus_count, unsigned int flags, audio_engine* engine);
};

enum audio_spatializer_distance_model {
	linear,
	inverse,
	exponential
};
struct audio_spatialization_parameters {
	float listener_x;
	float listener_y;
	float listener_z;
	float listener_direction_x;
	float listener_direction_y;
	float listener_direction_z;
	float listener_distance;
	float sound_x;
	float sound_y;
	float sound_z;
	float min_distance;
	float max_distance;
	float min_volume;
	float max_volume;
	float rolloff;
	float directional_attenuation_factor;
	float cone_volume; // The volume the sound's cone and its listener's give it, which the attenuators clamp to min_volume and max_volume with the distance's (see mixer_impl::get_cone_volume()).
	audio_spatializer_distance_model distance_model;
};

class spatializer_component_node;

class audio_spatializer : public virtual audio_node_chain {
public:
	virtual void set_panner(spatializer_component_node* new_panner) = 0;
	virtual spatializer_component_node* get_panner() const = 0;
	virtual void set_attenuator(spatializer_component_node* new_attenuator) = 0;
	virtual spatializer_component_node* get_attenuator() const = 0;
	virtual void set_panner_by_id(int panner_id) = 0;
	virtual void set_attenuator_by_id(int attenuator_id) = 0;
	virtual int get_current_panner_id() const = 0;
	virtual int get_current_attenuator_id() const = 0;
	virtual int get_preferred_panner_id() const = 0;
	virtual int get_preferred_attenuator_id() const = 0;
	virtual void set_rolloff(float rolloff) = 0;
	virtual float get_rolloff() const = 0;
	virtual void set_directional_attenuation_factor(float factor) = 0;
	virtual float get_directional_attenuation_factor() const = 0;
	virtual void set_reverb3d(reverb3d* new_reverb, audio_spatializer_reverb3d_placement placement = postpan) = 0;
	virtual reverb3d* get_reverb3d() const = 0;
	virtual splitter_node* get_reverb3d_attachment() const = 0;
	virtual audio_spatializer_reverb3d_placement get_reverb3d_placement() const = 0;
	virtual mixer* get_mixer() const = 0;
	virtual bool get_parameters(audio_spatialization_parameters& params) = 0;
	virtual void on_panner_enabled_changed(int panner_id, bool enabled) = 0;
	virtual void on_attenuator_enabled_changed(int attenuator_id, bool enabled) = 0;
	virtual void forget_mixer() = 0; // Its mixer is letting go of it; one the script kept no longer reads that mixer.
	static audio_spatializer* create(mixer* mixer, audio_engine* engine = nullptr);
};

class spatializer_component_node : public virtual effect_node {
public:
	virtual audio_spatializer* get_spatializer() const = 0;
	virtual void forget_spatializer() {} // Its spatializer is going; after this the component passes audio through.
};

class basic_panner : public virtual spatializer_component_node {
public:
	static spatializer_component_node* create(audio_spatializer* spatializer, audio_engine* engine);
};

class phonon_hrtf_panner : public virtual spatializer_component_node {
public:
	static spatializer_component_node* create(audio_spatializer* spatializer, audio_engine* engine);
};

class basic_attenuator : public virtual spatializer_component_node {
public:
	static spatializer_component_node* create(audio_spatializer* spatializer, audio_engine* engine);
};

class phonon_attenuator : public virtual spatializer_component_node {
public:
	static spatializer_component_node* create(audio_spatializer* spatializer, audio_engine* engine);
};

typedef spatializer_component_node* (*spatializer_component_node_factory)(audio_spatializer*, audio_engine*);

struct spatializer_component {
	spatializer_component_node_factory factory = nullptr;
	std::atomic<bool> enabled{false}; // Written under the sweep's lock, read by spatializers made on any thread.
};

int register_audio_panner(spatializer_component_node_factory factory, bool default_enabled = true);
int register_audio_attenuator(spatializer_component_node_factory factory, bool default_enabled = true);
spatializer_component_node* create_audio_panner(int id, audio_spatializer* spatializer, audio_engine* engine);
spatializer_component_node* create_audio_attenuator(int id, audio_spatializer* spatializer, audio_engine* engine);
void sound_set_default_3d_panner(int panner_id);
int sound_get_default_3d_panner();
void sound_set_default_3d_attenuator(int attenuator_id);
int sound_get_default_3d_attenuator();
void set_audio_panner_enabled(int id, bool enabled);
void set_audio_attenuator_enabled(int id, bool enabled);
bool get_audio_panner_enabled(int id);
bool get_audio_attenuator_enabled(int id);
bool sound_set_spatialization(int panner, int attenuator, bool disable_previous = false, bool set_default = true);
// Whether audio from the given mixer reaches a mixer the test is true for, through mixers' parents and the reverb3d each sends to, which goes into its own mixer: a link that would close such a loop is refused, as the loop never reaches the engine, its reverb hears only silence, and the references around it keep it all alive, running on the audio thread for good.
bool mixer_reaches(mixer* from, const std::function<bool(mixer*)>& is_target);
// As mixer_reaches(), from where a reverb3d sends: its mixer and a mixer used as its reverb, which it feeds.
bool reverb3d_reaches(reverb3d* verb, const std::function<bool(mixer*)>& is_target);
// Held by whatever changes the links mixer_reaches() follows (a mixer's parent, its spatializer and the reverb3d that sends to, a reverb3d's mixer) and by the checks that follow them, and taken before any chain, spatialization or graph lock: each link holds a reference to what it points to, so under this nothing a check reaches can be freed, as it was when another thread let go of a mixer the check had just stepped to.
extern std::recursive_mutex g_audio_topology_mutex;
bool reverb_fits(audio_node* verb, audio_node* destination, ma_uint32 channels_in);


extern int g_audio_basic_panner;
extern int g_audio_phonon_hrtf_panner;
extern int g_audio_basic_attenuator;
extern int g_audio_phonon_attenuator;
