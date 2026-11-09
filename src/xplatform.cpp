/* xplatform.cpp - code and routines that compile on multiple platforms
 * The intent of this module is to reduce the number of preprocessor platform checks in other parts of NVGT's codebase, and to provide a common place for small bits of platform compatibility code that could otherwise cause clutter.
 * It also contains some function registrations (mostly from SDL3) to ease cross platform development. If a function's effect might dramatically change or even be available on certain platforms it is OK to register it here unless it fits better somewhere else.
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

#include <SDL3/SDL.h>
#ifndef _WIN32
#include <dlfcn.h>
#endif
#include <condition_variable>
#include <mutex>
#include <string>
#include <unordered_set>
#include <vector>
#include <Poco/Clock.h>
#include <Poco/Environment.h>
#include <Poco/File.h>
#include <Poco/Path.h>
#include <Poco/String.h>
#include <Poco/Thread.h>
#include <Poco/Util/Application.h>
#include <obfuscate.h>
#include <angelscript.h>
#include "nvgt.h"
#include "xplatform.h"
#ifdef __APPLE__
#include "apple.h"
#endif

using namespace Poco;

bool running_on_mobile() {
	#if defined(__ANDROID__) || defined(__APPLE__) && TARGET_OS_IPHONE
		return true;
	#else
		return false;
	#endif
}
#ifndef NVGT_STUB
void determine_compile_platform() {
	if (g_platform != "auto") return;
	#ifdef _WIN32
	g_platform = "windows";
	#elif defined(__linux__)
	g_platform = "linux";
	#elif defined(__APPLE__)
	g_platform = "mac"; // Todo: detect difference between IOS and macos (need to look up the correct macros).
	#elif defined(__ANDROID__)
	g_platform = "android";
	#endif
	// else compilation is not supported on this platform.
}
void xplatform_correct_path_to_stubs(Poco::Path& stubpath) {
	#ifdef __APPLE__ // Stub may be in Resources directory of an app bundle.
	if (!File(stubpath).exists() && !icompare(stubpath[stubpath.depth() -2], "MacOS") && !icompare(stubpath[stubpath.depth() -3], "Contents")) stubpath.makeParent().makeParent().pushDirectory("Resources").pushDirectory("stub");
	#endif
}
std::string get_nvgt_lib_directory(const std::string& platform) {
	// The directory containing the libraries for the NVGT currently running is usually just called lib, while all other directories are lib_platform. In any case try to return an absolute path to the libraries given a platform.
	std::string dir;
	bool apple_bundle = File(Path(Path::self()).makeParent().makeParent().pushDirectory("Frameworks").toString()).exists();
	if (platform == "windows") dir = Poco::Environment::isWindows()? "lib" : "lib_windows";
	else if (platform == "mac") dir = Environment::os() == POCO_OS_MAC_OS_X? (apple_bundle? "Frameworks" : "lib") : "lib_mac";
	else if (platform == "linux") dir = Poco::Environment::os() == POCO_OS_LINUX? "lib" : "lib_linux";
	else if (platform == "android") dir = "lib_android";
	else if (platform == "ios") dir = "lib_ios"; // plugin dylibs and the frameworks they need, embedded into the .app by the bundler.
	else return ""; // libs not applicable for this platform.
	Path result(Path::self());
	result.makeParent();
	#ifdef __APPLE__
		if (apple_bundle) {
			result.makeParent();
			if (platform != "mac") result.append("Resources");
		}
	#endif
	result.pushDirectory(dir);
	return result.toString();
}
#else // NVGT_STUB
std::string get_data_location() {
	std::string executable = Poco::Util::Application::instance().commandPath();
	#if defined(__ANDROID__)
	// The payload is packaged as assets/bytecode.bin rather than appended to libgame.so, which is how the multi-ABI android build works. SDL routes a relative path through the asset manager, matching how LoadCompiledExecutable opens the same file.
	return "bytecode.bin";
	#elif defined(__APPLE__)
		#ifndef NVGT_MOBILE
		Path payload_file = Path(Util::Application::instance().commandPath()).makeParent().makeParent().append("Resources/exec");
		#else
		Path payload_file = Path(Util::Application::instance().commandPath()).makeParent().append("exec");
		#endif
		payload_file.makeFile();
		return (Poco::Environment::has("MACOS_BUNDLED_APP") || running_on_mobile()) && File(payload_file).exists()? payload_file.toString() : executable;
	#else
		return executable;
	#endif
}
#endif

#if defined(__APPLE__) || defined(__ANDROID__)
// The following code allows nvgt's compiler to open files sent to it from finder or other android apps. SDL handles the needed event for us, so we just need to snatch it from the event queue before our normal cross platform sdl event handling takes over after the nvgt script has begun executing.
void InputInit(); // Forward declared from input.cpp
void InputDestroy();
std::string event_requested_file() {
	#ifdef __APPLE__
		if (!Poco::Environment::has("MACOS_BUNDLED_APP")) return ""; // This will certainly not happen outside of the app bundle.
	#endif
	InputInit();
	std::string result;
	Poco::Clock timeout;
	bool old_dropfile_state = SDL_EventEnabled(SDL_EVENT_DROP_FILE);
	SDL_SetEventEnabled(SDL_EVENT_DROP_FILE, true);
	while (!timeout.isElapsed(50000)) {
		Poco::Thread::sleep(5);
		SDL_Event e;
		SDL_PumpEvents();
		if (SDL_PeepEvents(&e, 1, SDL_GETEVENT, SDL_EVENT_DROP_FILE, SDL_EVENT_DROP_FILE) < 1) continue;
		result = e.drop.data;
		break;
	}
	SDL_SetEventEnabled(SDL_EVENT_DROP_FILE, old_dropfile_state);
	InputDestroy();
	return result;
}
#endif
#ifdef __ANDROID__
std::string android_get_main_shared_object() {
	std::string p;
	Dl_info inf;
	if (dladdr((void*)android_get_main_shared_object, &inf)) p = inf.dli_fname;
	return p;
}
#endif

#if defined(__APPLE__)
// VoiceOver announcements made from another script thread follow the window's focus, see voice_over_speak().
void lost_window_focus_platform() { voice_over_window_focus_changed(); }
void regained_window_focus_platform() { voice_over_window_focus_changed(); }
#elif !defined(_WIN32)
// Dummy versions of functions that are currently only implemented on windows. If some of these get defined on other platforms, this define can be made more complex to avoid the dummy versions clashing.
void lost_window_focus_platform() {}
void regained_window_focus_platform() {}
#endif

std::string get_font_path(const std::string& name) {
	// If the name already ends in .ttf, treat it as a path directly.
	if (name.size() >= 4 && name.substr(name.size() - 4) == ".ttf") return name;
	// See if name+".ttf" already exists as a relative or absolute path.
	std::string with_ext = name + ".ttf";
	if (File(with_ext).exists()) return with_ext;
	// Search platform system font directories.
	static const char* font_dirs[] = {
		#ifdef _WIN32
		"C:/Windows/Fonts/",
		#elif defined(__APPLE__)
		"/Library/Fonts/",
		"/System/Library/Fonts/",
		"/System/Library/Fonts/Supplemental/",
		#elif defined(__ANDROID__)
		"/system/fonts/",
		"/system/font/",
		#else // Linux and other Unix-likes
		"/usr/share/fonts/truetype/",
		"/usr/share/fonts/",
		"/usr/local/share/fonts/",
		#endif
		nullptr
	};
	for (int i = 0; font_dirs[i]; i++) {
		std::string candidate = std::string(font_dirs[i]) + name + ".ttf";
		if (File(candidate).exists()) return candidate;
	}
	// Couldn't resolve — return name+".ttf" and let the caller handle the error.
	return with_ext;
}

// Anything below this point is function registrations.
// Usually this involves defining no-op versions of functions that are only available on certain platforms, though can sometimes include wrappers as well to get around char* and other things that we can't directly register.
#ifndef SDL_PLATFORM_LINUX
bool SDL_SetLinuxThreadPriority(Sint64 threadID, int priority) { return false; }
bool SDL_SetLinuxThreadPriorityAndPolicy(Sint64 threadID, int priority, int schedPolicy) { return false; }
#endif
#ifndef SDL_PLATFORM_ANDROID
int SDL_GetAndroidSDKVersion() { return -1; }
bool SDL_IsChromebook() { return false; }
bool SDL_IsDeXMode() { return false; }
void SDL_SendAndroidBackButton() {}
bool request_android_permission(const std::string& permission, asIScriptFunction* callback, const std::string& callback_data) {
	if (callback) callback->Release();
	return false;
}
void android_permission_requests_shutdown() {}
bool show_android_toast(const std::string& message, int duration, int gravity, int x_offset, int y_offset) { return false; }
std::string get_directory_appdata() {
	return Path::configHome();
}
std::string get_directory_temp() {
	return Path::temp();
}
#else
// The answer to a request comes on the Java UI thread (SDL calls the callback from nativePermissionResult, out of a list SDL_Quit
// doesn't clear), or at once on the requesting thread when the permission is already granted. It could come after the script had
// ended and the engine was shut down (the user answering late, or Android cancelling the request when the activity finishes), and
// the callback then asked a null g_ScriptEngine for a context and released a function the engine had freed; one answered during the
// shut down ran while the engine was being destroyed. android_permission_requests_shutdown(), called before the engine goes, lets go
// of the callbacks still waiting, aborts the ones running and waits for them; an answer after it only frees the request's data.
struct android_permission_request_callback_data;
struct android_permission_requests_state {
	std::mutex mutex;
	std::condition_variable idle;
	std::unordered_set<android_permission_request_callback_data*> waiting; // With a callback, not answered yet.
	std::unordered_set<asIScriptContext*> executing; // Contexts running a callback now.
	int running = 0; // Callbacks between taking a context and letting go of their function.
	bool engine_gone = false;
};
static android_permission_requests_state& android_permission_requests() {
	static auto* state = new android_permission_requests_state; // Never destroyed: an answer can come during static destruction.
	return *state;
}
struct android_permission_request_callback_data {
	asIScriptFunction* func;
	const bool with_callback; // func can't tell once android_permission_requests_shutdown() has let go of it.
	std::string callback_data;
	Event completed;
	bool was_granted;
	android_permission_request_callback_data(asIScriptFunction* func, const std::string& callback_data) : func(func), with_callback(func != nullptr), callback_data(callback_data), was_granted(false) {}
	void execute(std::string permission, bool granted) {
		was_granted = granted;
		if (!with_callback) {
			completed.set();
			return;
		}
		android_permission_requests_state& state = android_permission_requests();
		asIScriptContext* ctx = nullptr;
		{
			std::lock_guard<std::mutex> lock(state.mutex);
			state.waiting.erase(this);
			if (state.engine_gone) return; // android_permission_requests_shutdown() let go of func.
			state.running++;
			ctx = g_ScriptEngine->RequestContext();
			if (ctx) state.executing.insert(ctx);
		}
		bool prepared = ctx && ctx->Prepare(func) >= 0 && ctx->SetArgObject(0, &permission) >= 0 && ctx->SetArgByte(1, granted) >= 0 && ctx->SetArgObject(2, &callback_data) >= 0;
		if (prepared) {
			std::lock_guard<std::mutex> lock(state.mutex);
			prepared = !state.engine_gone; // An Abort() before Execute() is dropped by Prepare(): don't start one the shut down already asked to stop.
		}
		if (prepared) ctx->Execute();
		if (ctx) {
			{
				std::lock_guard<std::mutex> lock(state.mutex);
				state.executing.erase(ctx);
			}
			g_ScriptEngine->ReturnContext(ctx); // None when the pool couldn't make one, which NVGT's ReturnContextCallback can't take.
		}
		func->Release();
		func = nullptr;
		{
			std::lock_guard<std::mutex> lock(state.mutex);
			state.running--;
		}
		state.idle.notify_all();
		completed.set();
	}
};
void android_permission_request_callback(void* raw_data, const char* permission, bool granted) {
	android_permission_request_callback_data* data = reinterpret_cast<android_permission_request_callback_data*>(raw_data);
	// With a callback nothing waits for the answer, and the request's data was never freed: it is freed here once the callback has run. Without one, request_android_permission waits for the answer and frees it.
	bool has_callback = data->with_callback;
	data->execute(permission, granted);
	if (has_callback) delete data;
}
bool request_android_permission(const std::string& permission, asIScriptFunction* callback, const std::string& callback_data) {
	android_permission_request_callback_data* data = new android_permission_request_callback_data(callback, callback_data);
	android_permission_requests_state& state = android_permission_requests();
	if (callback) {
		bool engine_gone;
		{
			std::lock_guard<std::mutex> lock(state.mutex);
			engine_gone = state.engine_gone;
			if (!engine_gone) state.waiting.insert(data); // Before SDL is asked: the answer can come at once, or on the UI thread before SDL returns.
		}
		if (engine_gone) { // A script destructor run by the engine's shut down: its callback could never run.
			callback->Release();
			delete data;
			return false;
		}
	}
	bool result = SDL_RequestAndroidPermission(permission.c_str(), android_permission_request_callback, data);
	// A request SDL couldn't submit never gets an answer (SDL calls no callback then): the call without a callback waited for one for good, and with one the data and the callback's reference were never let go of.
	if (!result) {
		if (callback) {
			bool released;
			{
				std::lock_guard<std::mutex> lock(state.mutex);
				released = state.waiting.erase(data) == 0; // android_permission_requests_shutdown() let go of it meanwhile.
			}
			if (!released) callback->Release();
		}
		delete data;
		return false;
	}
	if (!callback) {
		data->completed.wait();
		result = data->was_granted;
		delete data;
	}
	return result;
}
void android_permission_requests_shutdown() {
	android_permission_requests_state& state = android_permission_requests();
	std::vector<asIScriptFunction*> callbacks;
	{
		std::lock_guard<std::mutex> lock(state.mutex);
		state.engine_gone = true;
		for (android_permission_request_callback_data* data : state.waiting) {
			callbacks.push_back(data->func);
			data->func = nullptr;
		}
		state.waiting.clear();
		for (asIScriptContext* ctx : state.executing) ctx->Abort();
	}
	for (asIScriptFunction* func : callbacks) func->Release(); // Unlocked: a delegate's object can run a script destructor.
	std::unique_lock<std::mutex> lock(state.mutex);
	state.idle.wait(lock, [&state] { return state.running == 0; });
}
bool show_android_toast(const std::string& message, int duration, int gravity, int x_offset, int y_offset) {
	return SDL_ShowAndroidToast(message.c_str(), duration, gravity, x_offset, y_offset);
}
// SDL gives null when it can't get the path (a Java exception), which made a std::string from a null pointer (a crash): an empty string instead.
std::string get_directory_appdata() {
	const char* path = SDL_GetAndroidInternalStoragePath();
	return path ? path : "";
}
std::string get_directory_temp() {
	const char* path = SDL_GetAndroidCachePath();
	return path ? path : "";
}
#endif
void RegisterXplatform(asIScriptEngine* engine) {
	engine->SetDefaultAccessMask(NVGT_SUBSYSTEM_OS);
	engine->RegisterGlobalFunction("bool set_linux_thread_priority(int64 thread_id, int priority)", asFUNCTION(SDL_SetLinuxThreadPriority), asCALL_CDECL);
	engine->RegisterGlobalFunction("bool set_linux_thread_priority_and_policy(int64 thread_id, int priority, int policy)", asFUNCTION(SDL_SetLinuxThreadPriorityAndPolicy), asCALL_CDECL);
	engine->RegisterGlobalFunction("void android_send_back_button()", asFUNCTION(SDL_SendAndroidBackButton), asCALL_CDECL);
	engine->RegisterFuncdef("void android_permission_request_callback(string permission, bool granted, string user_data)");
	engine->RegisterGlobalFunction("bool android_request_permission(const string&in permission, android_permission_request_callback@ callback = null, const string&in callback_data = \"\")", asFUNCTION(request_android_permission), asCALL_CDECL);
	engine->RegisterGlobalFunction("bool android_show_toast(const string&in message, int duration, int gravity = -1, int x_offset = 0, int y_offset = 0)", asFUNCTION(show_android_toast), asCALL_CDECL);
	engine->SetDefaultAccessMask(NVGT_SUBSYSTEM_GENERAL);
	engine->RegisterGlobalFunction("int get_ANDROID_SDK_VERSION() property", asFUNCTION(SDL_GetAndroidSDKVersion), asCALL_CDECL);
	engine->RegisterGlobalFunction("bool get_system_is_chromebook() property", asFUNCTION(SDL_IsChromebook), asCALL_CDECL);
	engine->RegisterGlobalFunction("bool get_system_is_DeX_mode() property", asFUNCTION(SDL_IsDeXMode), asCALL_CDECL);
	engine->RegisterGlobalFunction("bool get_system_is_tablet() property", asFUNCTION(SDL_IsTablet), asCALL_CDECL);
	//engine->RegisterGlobalFunction("bool get_system_is_tv() property", asFUNCTION(SDL_IsTV), asCALL_CDECL);
	engine->RegisterGlobalFunction(_O("string get_DIRECTORY_APPDATA() property"), asFUNCTION(get_directory_appdata), asCALL_CDECL);
	engine->RegisterGlobalFunction(_O("string get_DIRECTORY_TEMP() property"), asFUNCTION(get_directory_temp), asCALL_CDECL);
	engine->RegisterGlobalFunction("bool get_system_is_mobile() property", asFUNCTION(running_on_mobile), asCALL_CDECL);
}
