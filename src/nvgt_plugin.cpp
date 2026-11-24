/* nvgt_plugin.cpp - code for loading and serializing plugins
 * These are usually loaded with a "#pragma plugin pluginname" in nvgt code, and consist of either a dll file with an nvgt_plugin entry point or a static library.
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

#include <algorithm>
#include <exception>
#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>
#include <Poco/BinaryReader.h>
#include <Poco/BinaryWriter.h>
#include <Poco/Format.h>
#include <Poco/Path.h>
#include <SDL3/SDL.h>
#include "datastreams.h"
#include "nvgt.h"
#include "nvgt_plugin.h"
#include "sound_nodes.h"
#include "UI.h"
#include "xplatform.h"

// Helper functions that are shared with plugins.
void* nvgt_datastream_create(std::ios* stream, const std::string& encoding, int byteorder) { return new datastream(stream, encoding, byteorder); }
std::ios* nvgt_datastream_get_ios(void* stream) { return reinterpret_cast<datastream*>(stream)->get_iostr(); }
#if defined(NVGT_STUB) || defined(NVGT_MOBILE)
// We need a no-op wrapper for nvgt_bundle_shared_library which is only needed on script compilation and thus is not included in stubs or mobile platforms.
void nvgt_bundle_shared_library(const std::string& libname) {}
#endif
#if defined(_WIN32) && defined(_DEBUG)
// Every module linked with the static debug CRT keeps its own list of heap blocks, so memory such as a std::string's buffer that a plugin allocates and NVGT frees, or the reverse, trips a debug heap assertion. Debug plugins find these with GetProcAddress and route their operator new and delete through NVGT's, see nvgt_plugin.h. Release builds don't need this, as the static CRT allocates from the process heap that every module shares.
extern "C" __declspec(dllexport) void* nvgt_debug_operator_new(size_t size, size_t alignment) { return alignment ? ::operator new(size, std::align_val_t(alignment)) : ::operator new(size); }
extern "C" __declspec(dllexport) void nvgt_debug_operator_delete(void* ptr, size_t alignment) { if (alignment) ::operator delete(ptr, std::align_val_t(alignment)); else ::operator delete(ptr); }
#endif
typedef struct {
	nvgt_plugin_entry* e;
	nvgt_plugin_version_func* v;
} static_plugin_vtable;
std::unordered_map<std::string, SDL_SharedObject*> loaded_plugins; // Contains handles to sdl objects.
std::unordered_map<std::string, static_plugin_vtable>* static_plugins = NULL; // Contains pointers to static plugin entry points. This doesn't contain entry points for plugins loaded from a dll, rather those that have been linked statically into the executable produced by a custom build of nvgt. This is a pointer because the map is initialized the first time register_static_plugin is called so that we are not trusting in global initialization order.
std::vector<const char*>* static_plugin_lib_markers = NULL; // Same lifetime rules; see register_static_plugin_libs.
std::vector<nvgt_plugin_shutdown_callback*> plugin_shutdown_callbacks; // Called in reverse registration order by notify_nvgt_plugins_shutdown.

void nvgt_register_shutdown_notification(nvgt_plugin_shutdown_callback* callback) {
	if (!callback || std::find(plugin_shutdown_callbacks.begin(), plugin_shutdown_callbacks.end(), callback) != plugin_shutdown_callbacks.end()) return;
	plugin_shutdown_callbacks.push_back(callback);
}
static std::unordered_map<int, nvgt_raycast_provider_getter*> raycast_provider_types; // Keyed by script type id without handle flags.
void nvgt_register_raycast_provider_type(int type_id, nvgt_raycast_provider_getter* getter) {
	type_id &= ~(asTYPEID_OBJHANDLE | asTYPEID_HANDLETOCONST);
	if (getter) raycast_provider_types[type_id] = getter;
	else raycast_provider_types.erase(type_id);
}
nvgt_raycast_provider* nvgt_get_raycast_provider(void* object, int type_id) { // object is the object itself, as returned by CScriptHandle::GetRef, any handle flags in type_id are ignored.
	if (!object) return nullptr;
	auto it = raycast_provider_types.find(type_id & ~(asTYPEID_OBJHANDLE | asTYPEID_HANDLETOCONST));
	return it == raycast_provider_types.end() ? nullptr : it->second(object);
}
int nvgt_register_audio_panner(nvgt_spatializer_component_factory* factory, bool default_enabled) { return factory ? register_audio_panner(factory, default_enabled) : -1; }
int nvgt_register_audio_attenuator(nvgt_spatializer_component_factory* factory, bool default_enabled, nvgt_audio_attenuation_function* attenuation) { return factory ? register_audio_attenuator(factory, default_enabled, attenuation) : -1; }
float nvgt_get_audio_attenuation(int attenuator_id, const audio_spatialization_parameters* params, float distance) { return params ? get_audio_attenuation(attenuator_id, *params, distance) : 1.0f; }
spatializer_component_node* nvgt_audio_spatializer_component_create(audio_plugin_spatializer_component_interface* impl, audio_spatializer* spatializer, audio_engine* engine, unsigned int input_channels, unsigned int output_channels) { return create_plugin_spatializer_component(impl, spatializer, engine, input_channels, output_channels); }
// The engines nvgt_get_default_audio_engine() gave plugins, each kept with a reference of NVGT's own: a plugin is given the default engine without a reference, as plugins built for this API expect, which another thread setting sound_default_engine could otherwise free before the plugin took one of its own. Giving the plugin a reference instead would have plugins built for that free one they were only lent by an NVGT built before it. Let go of once the engine is no longer the default and was last given out a second before, which no plugin taking its reference at once, as nvgt_plugin.h says, comes near, and the oldest past the eighth whatever their age: kept for good, a replaced engine held its device open, and kept for ten seconds, a script replacing the default many times a second kept hundreds alive, gigabytes of them.
struct plugin_lent_engine {
	audio_engine* engine;
	std::chrono::steady_clock::time_point lent;
};
static std::mutex g_plugin_engines_mutex;
static std::vector<plugin_lent_engine> g_plugin_engines;
static void take_out_lent_engines(audio_engine* current, std::vector<audio_engine*>& let_go) { // Under g_plugin_engines_mutex; the caller lets go of them after it, as freeing an engine closes its device.
	const auto now = std::chrono::steady_clock::now();
	size_t others = 0;
	for (auto it = g_plugin_engines.begin(); it != g_plugin_engines.end();) {
		if (it->engine != current && now - it->lent > std::chrono::seconds(1)) {
			let_go.push_back(it->engine);
			it = g_plugin_engines.erase(it);
		} else {
			if (it->engine != current) others++;
			++it;
		}
	}
	for (auto it = g_plugin_engines.begin(); others > 8 && it != g_plugin_engines.end();) { // Oldest first, as kept in the order given.
		if (it->engine == current) { ++it; continue; }
		let_go.push_back(it->engine);
		it = g_plugin_engines.erase(it);
		others--;
	}
}
// A thread letting go of the engines kept once they are due, running while any that isn't the default is kept: the calls that let go of them otherwise, a plugin's next ask, a default change or a sound made, can be long in coming, or never come, a replaced engine kept meanwhile with its device open. Detached, so that a process ending without uninit_sound() isn't ended by a thread object still joinable; stop_plugin_engine_sweeper() waits for it instead.
static std::condition_variable g_plugin_engines_wake; // Under g_plugin_engines_mutex, as the flags below.
static bool g_plugin_engines_sweeping = false, g_plugin_engines_sweeper_stopped = false;
// When the first kept engine that isn't current is due, under g_plugin_engines_mutex; false if none is kept.
static bool next_lent_engine_due(audio_engine* current, std::chrono::steady_clock::time_point& due) {
	bool any = false;
	for (const plugin_lent_engine& lent : g_plugin_engines) {
		if (lent.engine == current) continue;
		if (!any || lent.lent < due) due = lent.lent;
		any = true;
	}
	due += std::chrono::seconds(1) + std::chrono::milliseconds(1); // Past the second take_out_lent_engines() keeps it.
	return any;
}
static void let_go_of_lent_engines(audio_engine* current, bool sweeper);
static void sweep_plugin_engines() {
	for (;;) {
		let_go_of_lent_engines(current_default_engine_pointer(), true);
		std::unique_lock<std::mutex> lock(g_plugin_engines_mutex);
		std::chrono::steady_clock::time_point due;
		if (!g_plugin_engines_sweeper_stopped && next_lent_engine_due(current_default_engine_pointer(), due)) g_plugin_engines_wake.wait_until(lock, due, [] { return g_plugin_engines_sweeper_stopped; });
		if (g_plugin_engines_sweeper_stopped || !next_lent_engine_due(current_default_engine_pointer(), due)) {
			g_plugin_engines_sweeping = false;
			g_plugin_engines_wake.notify_all(); // Under the lock, so that nothing of this thread runs once stop_plugin_engine_sweeper() goes on.
			return;
		}
	}
}
// Starts the sweeper if an engine that isn't current is kept and none runs, under g_plugin_engines_mutex.
static void start_sweeper_if_due(audio_engine* current) {
	std::chrono::steady_clock::time_point due;
	if (g_plugin_engines_sweeping || g_plugin_engines_sweeper_stopped || !next_lent_engine_due(current, due)) return;
	try {
		std::thread(sweep_plugin_engines).detach();
		g_plugin_engines_sweeping = true;
	} catch (...) {} // No thread to be had: let go of by a later call, as before there was one.
}
static void let_go_of_lent_engines(audio_engine* current, bool sweeper) {
	std::vector<audio_engine*> let_go;
	{
		std::lock_guard<std::mutex> lock(g_plugin_engines_mutex);
		if (g_plugin_engines.empty()) return;
		try {
			let_go.reserve(g_plugin_engines.size());
		} catch (...) {
			return; // Let go of by a later call.
		}
		take_out_lent_engines(current, let_go); // The current default is kept.
		if (!sweeper) start_sweeper_if_due(current);
	}
	for (audio_engine* e : let_go) e->release();
}
void let_go_of_plugin_lent_engines(audio_engine* current) { let_go_of_lent_engines(current, false); }
void stop_plugin_engine_sweeper() {
	std::unique_lock<std::mutex> lock(g_plugin_engines_mutex);
	g_plugin_engines_sweeper_stopped = true;
	g_plugin_engines_wake.notify_all();
	g_plugin_engines_wake.wait(lock, [] { return !g_plugin_engines_sweeping; });
}
audio_engine* nvgt_get_default_audio_engine() {
	audio_engine* engine = nullptr;
	std::vector<audio_engine*> let_go;
	struct letting_go { std::vector<audio_engine*>& engines; ~letting_go() { for (audio_engine* e : engines) e->release(); } } after_lock{let_go}; // Declared before the lock, so run after it.
	try {
		if (!(engine = acquire_default_engine())) return nullptr;
		std::lock_guard<std::mutex> lock(g_plugin_engines_mutex);
		let_go.reserve(g_plugin_engines.size() + 1); // Room made first, so that neither taking them out nor keeping this one can throw midway.
		g_plugin_engines.reserve(g_plugin_engines.size() + 1);
		take_out_lent_engines(engine, let_go);
		auto kept = std::find_if(g_plugin_engines.begin(), g_plugin_engines.end(), [engine](const plugin_lent_engine& lent) { return lent.engine == engine; });
		if (kept != g_plugin_engines.end()) {
			kept->lent = std::chrono::steady_clock::now();
			engine->release(); // Kept already, by the reference taken the first time.
		} else g_plugin_engines.push_back({engine, std::chrono::steady_clock::now()});
		start_sweeper_if_due(current_default_engine_pointer()); // The engine may have stopped being the default since it was taken, when the default change found nothing kept yet to sweep.
		return engine;
	} catch (const std::exception&) { // Not through a plugin, which may not take it; out of memory keeping the engine, the reference just taken let go of.
		if (engine) engine->release();
		return nullptr;
	}
}
reverb3d* nvgt_reverb3d_create_with_handler(reverb3d_attachment_handler* handler, audio_node* reverb, mixer* destination, audio_engine* engine) {
	// reverb3d::create_with_handler() throws for what it refuses (a reverb of another engine, a loop, a reverb in use elsewhere) and frees
	// the handler itself; a plugin only looks for null.
	std::unique_ptr<reverb3d_attachment_handler> owned(handler); // Freed below too, should what comes before it throw.
	audio_engine* default_engine = nullptr; // With a reference, as another thread may change the default meanwhile.
	try {
		if (!engine) engine = default_engine = acquire_default_engine();
		reverb3d* made = reverb3d::create_with_handler(owned.release(), reverb, destination, engine);
		if (default_engine) default_engine->release();
		return made;
	} catch (const std::exception&) {
		if (default_engine) default_engine->release();
		return nullptr;
	}
}
void notify_nvgt_plugins_shutdown() {
	while (!plugin_shutdown_callbacks.empty()) {
		nvgt_plugin_shutdown_callback* callback = plugin_shutdown_callbacks.back();
		plugin_shutdown_callbacks.pop_back();
		callback();
	}
}

bool load_nvgt_plugin(const std::string& name, std::string* errmsg, void* user) {
	nvgt_plugin_entry* entry = NULL;
	nvgt_plugin_version_func* version = NULL;
	SDL_SharedObject* obj = NULL;
	if (loaded_plugins.contains(name)) return true; // plugin already loaded
	if (static_plugins && static_plugins->contains(name)) {
		entry = (*static_plugins)[name].e;
		version = (*static_plugins)[name].v;
	}
	else {
		std::string dllname = name;
		#ifdef _WIN32
		dllname += ".dll";
		#elif defined(__APPLE__)
		dllname += ".dylib";
		#else
		dllname += ".so";
		#endif
		obj = SDL_LoadObject(dllname.c_str());
		if (!obj) obj = SDL_LoadObject(Poco::format("lib%s", dllname).c_str());
		#ifdef __ANDROID__
		// Plugins are shipped as lib<name>.so (the only spelling the package installer extracts) into the same directory the
		// engine's own native library was extracted to; look there by full path in case the bare name is not resolvable.
		if (!obj) {
			std::string main_so = android_get_main_shared_object();
			if (!main_so.empty()) obj = SDL_LoadObject(Poco::Path(main_so).makeParent().setFileName("lib" + dllname).toString().c_str());
		}
		#endif
		#if defined(__APPLE__) && defined(NVGT_MOBILE)
		// dlopen never searches the app bundle for a bare name. The bundler embeds each plugin as <app>/Frameworks/<name>.framework/<name>,
		// the only form of third-party dynamic code iOS accepts; the loose dylib spellings are kept for a developer's ad hoc build.
		if (!obj) {
			Poco::Path frameworks = Poco::Path(Poco::Path::self()).makeParent().pushDirectory("Frameworks");
			obj = SDL_LoadObject(Poco::Path(frameworks).pushDirectory(name + ".framework").setFileName(name).toString().c_str());
			if (!obj) obj = SDL_LoadObject(Poco::Path(frameworks).setFileName(dllname).toString().c_str());
			if (!obj) obj = SDL_LoadObject(Poco::Path(frameworks).setFileName("lib" + dllname).toString().c_str());
		}
		#endif
		if (!obj) return false;
		entry = (nvgt_plugin_entry*)SDL_LoadFunction(obj, "nvgt_plugin");
		version = (nvgt_plugin_version_func*)SDL_LoadFunction(obj, "nvgt_plugin_version");
	}
	if (!version) {
		if (errmsg) *(errmsg) = Poco::format("Failed to determine API version used for plugin %s, the plugin is old or defective.", name);
		return false;
	}
	else if (version() != NVGT_PLUGIN_API_VERSION) {
		if (errmsg) (*errmsg) = Poco::format("Failed API version check for plugin %s, plugin was compiled with API version %d while NVGT is using version %d. A compatible version of the plugin must be used.", name, version(), NVGT_PLUGIN_API_VERSION);
		return false;
	}
	nvgt_plugin_shared* shared = (nvgt_plugin_shared*)malloc(sizeof(nvgt_plugin_shared));
	prepare_plugin_shared(shared, g_ScriptEngine, user);
	if (!entry || !entry(shared)) {
		free(shared);
		if (obj) SDL_UnloadObject(obj);
		return false;
	}
	if (obj) {
		loaded_plugins[name] = obj;
		nvgt_bundle_shared_library(name);
	}
	else loaded_plugins[name] = NULL;
	free(shared);
	return true;
}

bool register_static_plugin(const std::string& name, nvgt_plugin_entry* e, nvgt_plugin_version_func* v) {
	if (!static_plugins) static_plugins = new std::unordered_map<std::string, static_plugin_vtable>;
	static_plugins->insert(std::make_pair(name, static_plugin_vtable {e, v}));
	return true;
}
bool register_static_plugin_libs(const char* marker) {
	if (!static_plugin_lib_markers) static_plugin_lib_markers = new std::vector<const char*>;
	static_plugin_lib_markers->push_back(marker);
	return true;
}
void list_loaded_nvgt_plugins(std::vector<std::string>& output) {
	for (auto kv : loaded_plugins) output.push_back(kv.first);
}

bool read_serialized_nvgt_plugins(Poco::BinaryReader& br, std::vector<std::string>& names) {
	unsigned short count;
	br >> count;
	for (int i = 0; i < count; i++) {
		std::string name;
		br >> name;
		names.push_back(name);
	}
	return br.good();
}

void serialize_nvgt_plugins(Poco::BinaryWriter& bw) {
	unsigned short count = loaded_plugins.size();
	bw << count;
	for (const auto& i : loaded_plugins)
		bw << i.first;
}

void unload_nvgt_plugins() {
	notify_nvgt_plugins_shutdown();
	for (const auto& i : loaded_plugins) {
		if (i.second) SDL_UnloadObject(i.second);
	}
	loaded_plugins.clear();
}
